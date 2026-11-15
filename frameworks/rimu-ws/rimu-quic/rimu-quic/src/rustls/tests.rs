//! Capture pinned (every key that rustls derives is captured, in the calls that Capture wraps,
//! and equals rustls's own keys, for every suite, level and key update), the sessions of the
//! transport through [`ConnTls`] and the core's key updates, and the settings that refuse
//! resumption and 0-RTT.

use super::{
  ConfigError, KeyMode, RustlsClientConfig, RustlsConfig,
  capture::{Captured, Captures, capture, stray_captures},
  test_support::{CERT_PEM, KEY_PEM, RSA_CERT_PEM, RSA_KEY_PEM},
  tls13_suite,
};
use crate::{
  Cid, CipherSuite, ConnParams, DirectionalKeys, PacketKeys, Space, TransportErrorCode,
  conn_tls::ConnTls,
  initial_keys,
  key_phase::KeyUpdate,
  open_payload, protect, remove_header_protection,
  rng::ChaCha20,
  tls::{KeyMaterial, ServerSessionFactory, TlsAlert},
};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use rustls::quic::{self as rq, HeaderProtectionKey, KeyChange, PacketKey};

const SUITES: [CipherSuite; 3] = CipherSuite::PRIORITY;
const PN_OFFSET: usize = 9;
const SAMPLE_LEN: usize = crate::protection::SAMPLE_LEN;

fn tp(server: bool) -> Vec<u8> {
  let cid = Cid::new(&[1; 8]).unwrap();
  let original = server.then(|| Cid::new(&[2; 8]).unwrap());
  let mut buf = [0; 256];
  let len = ConnParams::default().transport_params(cid, original).encode(&mut buf).unwrap();
  buf[..len].to_vec()
}

fn server_config(mode: KeyMode, suites: &[CipherSuite], cert: &[u8], key: &[u8]) -> RustlsConfig {
  RustlsConfig::builder()
    .cert_chain_pem(cert)
    .private_key_pem(key)
    .cipher_suites(suites)
    .key_mode(mode)
    .build()
    .unwrap()
}

fn client_config(mode: KeyMode) -> RustlsClientConfig {
  RustlsClientConfig::with_mode(mode, b"h3", &SUITES).unwrap()
}

// A 1-RTT packet with an 8-byte destination CID, a 2-byte packet number and `payload_len` bytes.
fn plaintext(payload_len: usize) -> Vec<u8> {
  let mut buf = vec![0u8; PN_OFFSET + 2 + payload_len + 16];
  buf[0] = 0x41;
  for (idx, elem) in buf[1..PN_OFFSET].iter_mut().enumerate() {
    *elem = 0xd0 | idx as u8;
  }
  for (idx, elem) in buf[PN_OFFSET + 2..PN_OFFSET + 2 + payload_len].iter_mut().enumerate() {
    *elem = idx as u8;
  }
  buf
}

fn set_pn(buf: &mut [u8], pn: u64) {
  buf[0] = 0x41;
  buf[PN_OFFSET..PN_OFFSET + 2].copy_from_slice(&(pn as u16).to_be_bytes());
}

fn seal_native(keys: &DirectionalKeys, buf: &mut [u8], pn: u64, payload_len: usize) -> usize {
  set_pn(buf, pn);
  protect(keys, buf, PN_OFFSET, pn, 2, payload_len).unwrap()
}

fn seal_dyn(
  pk: &dyn PacketKey,
  hp: &dyn HeaderProtectionKey,
  buf: &mut [u8],
  pn: u64,
  payload_len: usize,
) -> usize {
  set_pn(buf, pn);
  let header_len = PN_OFFSET + 2;
  let (header, rest) = buf.split_at_mut(header_len);
  let (payload, tag) = rest.split_at_mut(payload_len);
  let tag_value = pk.encrypt_in_place(pn, header, payload).unwrap();
  tag[..16].copy_from_slice(tag_value.as_ref());
  let sample: [u8; SAMPLE_LEN] = buf[PN_OFFSET + 4..PN_OFFSET + 4 + SAMPLE_LEN].try_into().unwrap();
  let (first, rest) = buf.split_at_mut(1);
  hp.encrypt_in_place(&sample, &mut first[0], &mut rest[PN_OFFSET - 1..PN_OFFSET + 1]).unwrap();
  header_len + payload_len + 16
}

fn open_native(keys: &DirectionalKeys, packet: &mut [u8], largest: u64) -> usize {
  let (pn, pn_len, _) =
    remove_header_protection(keys.hp(), packet, PN_OFFSET, Some(largest)).unwrap();
  open_payload(keys.aead(), keys.iv(), packet, PN_OFFSET + pn_len, pn).unwrap().len()
}

fn open_dyn(pk: &dyn PacketKey, hp: &dyn HeaderProtectionKey, packet: &mut [u8], pn: u64) -> usize {
  let sample: [u8; SAMPLE_LEN] =
    packet[PN_OFFSET + 4..PN_OFFSET + 4 + SAMPLE_LEN].try_into().unwrap();
  let (first, rest) = packet.split_at_mut(1);
  hp.decrypt_in_place(&sample, &mut first[0], &mut rest[PN_OFFSET - 1..PN_OFFSET + 3]).unwrap();
  let pn_len = usize::from(packet[0] & 0b11) + 1;
  let (header, payload) = packet.split_at_mut(PN_OFFSET + pn_len);
  pk.decrypt_in_place(pn, header, payload).unwrap().len()
}

fn native_from(captures: &Captures, hp_at: usize, pk_at: usize) -> DirectionalKeys {
  let caps = captures.as_slice();
  let Some(Captured::Hp { suite, key: hk, len: hl }) = caps[hp_at] else { panic!("no hp key") };
  let Some(Captured::Packet { key, len, iv, .. }) = caps[pk_at] else { panic!("no packet key") };
  let material =
    KeyMaterial::new(suite, &key[..usize::from(len)], &iv, Some(&hk[..usize::from(hl)])).unwrap();
  DirectionalKeys::from_material(&material, false).unwrap()
}

fn native_with_hp(captured: Option<Captured>, hp_key: &[u8]) -> DirectionalKeys {
  let Some(Captured::Packet { suite, key, len, iv }) = captured else { panic!("no packet key") };
  let material = KeyMaterial::new(suite, &key[..usize::from(len)], &iv, Some(hp_key)).unwrap();
  DirectionalKeys::from_material(&material, false).unwrap()
}

fn hp_bytes(captured: Option<Captured>) -> Vec<u8> {
  let Some(Captured::Hp { key, len, .. }) = captured else { panic!("no hp key") };
  key[..usize::from(len)].to_vec()
}

/// Seals the same packet with native keys and with rustls's, which must agree byte for byte, and
/// each opens what the other sealed with the peer's keys.
fn assert_same(
  native: &DirectionalKeys,
  pk: &dyn PacketKey,
  hp: &dyn HeaderProtectionKey,
  peer_pk: &dyn PacketKey,
  peer_hp: &dyn HeaderProtectionKey,
  peer_native: &DirectionalKeys,
) {
  for (pn, payload_len) in [(5u64, 37usize), (77, 1200)] {
    let (mut a, mut b) = (plaintext(payload_len), plaintext(payload_len));
    let len = seal_native(native, &mut a, pn, payload_len);
    let len2 = seal_dyn(pk, hp, &mut b, pn, payload_len);
    assert_eq!(len, len2);
    assert_eq!(a, b, "native and rustls protection differ");
    let plain = plaintext(payload_len);
    let mut c = a.clone();
    assert_eq!(open_dyn(peer_pk, peer_hp, &mut c[..len], pn), payload_len);
    assert_eq!(
      c[PN_OFFSET + 2..PN_OFFSET + 2 + payload_len],
      plain[PN_OFFSET + 2..PN_OFFSET + 2 + payload_len]
    );
    assert_eq!(open_native(peer_native, &mut a[..len], pn.saturating_sub(1)), payload_len);
  }
}

struct RawSide {
  changes: Vec<(KeyChange, Captures)>,
}

/// A handshake between a rustls server and client of `mode` with `suite`, driven directly, every
/// `write_hs` under the capture slot.
fn raw_handshake(mode: KeyMode, suite: CipherSuite) -> (RawSide, RawSide) {
  let server_config = server_config(mode, &[suite], CERT_PEM, KEY_PEM);
  let client_config = client_config(mode);
  let server =
    rq::ServerConnection::new(Arc::clone(server_config.rustls_config()), rq::Version::V1, tp(true))
      .unwrap();
  let client = rq::ClientConnection::new(
    Arc::clone(client_config.rustls_config()),
    rq::Version::V1,
    "localhost".try_into().unwrap(),
    tp(false),
  )
  .unwrap();
  let mut conns: [rq::Connection; 2] = [client.into(), server.into()];
  let mut sides = [RawSide { changes: Vec::new() }, RawSide { changes: Vec::new() }];
  for _ in 0..16 {
    let mut progress = false;
    for from in 0..2 {
      loop {
        let mut buf = Vec::new();
        let (change, captures) = capture(|| conns[from].write_hs(&mut buf));
        if !buf.is_empty() {
          let (rslt, read_caps) = capture(|| conns[1 - from].read_hs(&buf));
          rslt.unwrap();
          assert_eq!(read_caps.len, 0, "keys derived by a read_hs");
          progress = true;
        }
        match change {
          Some(elem) => {
            sides[from].changes.push((elem, captures));
            progress = true;
          }
          None => {
            assert_eq!(captures.len, 0, "keys derived by a write_hs without a key change");
            if buf.is_empty() {
              break;
            }
          }
        }
      }
    }
    if !progress {
      break;
    }
  }
  assert!(!conns[0].is_handshaking() && !conns[1].is_handshaking());
  let [client, server] = sides;
  (server, client)
}

fn hex(src: &[u8]) -> Vec<u8> {
  src
    .chunks(2)
    .map(|el| u8::from_str_radix(core::str::from_utf8(el).unwrap(), 16).unwrap())
    .collect()
}

#[test]
fn capture_initial_keys_match_rfc9001_appendix_a() {
  let dcid = hex(b"8394c8f03e515708");
  let suite = tls13_suite(KeyMode::CaptureDelegate, CipherSuite::Aes128GcmSha256).unwrap();
  let (keys, captures) = capture(|| {
    rq::Keys::initial(rq::Version::V1, suite, suite.quic.unwrap(), &dcid, rustls::Side::Server)
  });
  assert_eq!(captures.len, 4);
  assert_eq!(captures.overflow, 0);
  let caps = captures.as_slice();
  // Server first (local), header protection key before packet key
  let Some(Captured::Packet { key, len, iv, .. }) = caps[1] else { panic!() };
  assert_eq!(&key[..usize::from(len)], hex(b"cf3a5331653c364c88f0f379b6067e37"));
  assert_eq!(iv.to_vec(), hex(b"0ac1493ca1905853b0bba03e"));
  assert_eq!(hp_bytes(caps[0]), hex(b"c206b8d9b9f0f37644430b490eeaa314"));
  let Some(Captured::Packet { key, len, iv, .. }) = caps[3] else { panic!() };
  assert_eq!(&key[..usize::from(len)], hex(b"1f369613dd76d5467730efcbe3b1a22d"));
  assert_eq!(iv.to_vec(), hex(b"fa044b2f42a3fd3b46fb255c"));
  assert_eq!(hp_bytes(caps[2]), hex(b"9f50449e04a0e810283a1e9933adedd2"));
  // The level keys of the four records are what the session hands over
  let pair = captures.level_keys().unwrap();
  assert_eq!(pair.local.key(), hex(b"cf3a5331653c364c88f0f379b6067e37"));
  assert_eq!(pair.remote.hp().unwrap(), hex(b"9f50449e04a0e810283a1e9933adedd2"));
  // The captured keys protect as rustls's and as the core's own Initial keys
  let (server, client) = (native_from(&captures, 0, 1), native_from(&captures, 2, 3));
  let core = initial_keys(&dcid, true).unwrap();
  let client_rustls =
    rq::Keys::initial(rq::Version::V1, suite, suite.quic.unwrap(), &dcid, rustls::Side::Client);
  assert_same(
    &server,
    &*keys.local.packet,
    &*keys.local.header,
    &*client_rustls.remote.packet,
    &*client_rustls.remote.header,
    &server,
  );
  assert_same(
    &core.local,
    &*keys.local.packet,
    &*keys.local.header,
    &*client_rustls.remote.packet,
    &*client_rustls.remote.header,
    &core.local,
  );
  let core_client = initial_keys(&dcid, false).unwrap();
  assert_same(
    &client,
    &*client_rustls.local.packet,
    &*client_rustls.local.header,
    &*keys.remote.packet,
    &*keys.remote.header,
    &core_client.local,
  );
}

#[test]
fn capture_yields_every_key_change_and_matches_rustls_for_each_suite() {
  let strays = stray_captures();
  for suite in SUITES {
    let (mut server, mut client) = raw_handshake(KeyMode::CaptureDelegate, suite);
    assert_eq!(server.changes.len(), 2, "{suite:?}");
    assert_eq!(client.changes.len(), 2, "{suite:?}");
    let mut one_rtt = Vec::new();
    for (idx, ((s_change, s_caps), (c_change, c_caps))) in
      server.changes.iter_mut().zip(client.changes.iter_mut()).enumerate()
    {
      assert_eq!((s_caps.len, s_caps.overflow), (4, 0), "{suite:?} {idx}");
      assert_eq!((c_caps.len, c_caps.overflow), (4, 0), "{suite:?} {idx}");
      let (s_keys, c_keys) = match (s_change, c_change) {
        (KeyChange::Handshake { keys: s }, KeyChange::Handshake { keys: c }) if idx == 0 => (s, c),
        (KeyChange::OneRtt { keys: s, .. }, KeyChange::OneRtt { keys: c, .. }) if idx == 1 => {
          (s, c)
        }
        _ => panic!("unexpected key change order"),
      };
      let (s_local, s_remote) = (native_from(s_caps, 0, 1), native_from(s_caps, 2, 3));
      let (c_local, c_remote) = (native_from(c_caps, 0, 1), native_from(c_caps, 2, 3));
      assert_eq!(s_local.suite(), suite);
      assert_same(
        &s_local,
        &*s_keys.local.packet,
        &*s_keys.local.header,
        &*c_keys.remote.packet,
        &*c_keys.remote.header,
        &c_remote,
      );
      assert_same(
        &c_local,
        &*c_keys.local.packet,
        &*c_keys.local.header,
        &*s_keys.remote.packet,
        &*s_keys.remote.header,
        &s_remote,
      );
      if idx == 1 {
        one_rtt.push((hp_bytes(s_caps.as_slice()[0]), hp_bytes(s_caps.as_slice()[2])));
        one_rtt.push((hp_bytes(c_caps.as_slice()[0]), hp_bytes(c_caps.as_slice()[2])));
      }
    }
    // Key updates: three generations, each captured from `next_packet_keys`
    let (
      KeyChange::OneRtt { keys: s_keys, next: s_next },
      KeyChange::OneRtt { keys: c_keys, next: c_next },
    ) = (&mut server.changes[1].0, &mut client.changes[1].0)
    else {
      panic!()
    };
    let (s_hp, c_hp) = (&one_rtt[0], &one_rtt[1]);
    for generation in 1..=3 {
      let (s_set, s_caps) = capture(|| s_next.next_packet_keys());
      let (c_set, c_caps) = capture(|| c_next.next_packet_keys());
      assert_eq!((s_caps.len, c_caps.len), (2, 2), "{suite:?} generation {generation}");
      assert!(s_caps.update_keys().is_ok() && c_caps.update_keys().is_ok());
      let s_local = native_with_hp(s_caps.as_slice()[0], &s_hp.0);
      let c_remote = native_with_hp(c_caps.as_slice()[1], &c_hp.1);
      let c_local = native_with_hp(c_caps.as_slice()[0], &c_hp.0);
      let s_remote = native_with_hp(s_caps.as_slice()[1], &s_hp.1);
      assert_same(
        &s_local,
        &*s_set.local,
        &*s_keys.local.header,
        &*c_set.remote,
        &*c_keys.remote.header,
        &c_remote,
      );
      assert_same(
        &c_local,
        &*c_set.local,
        &*c_keys.local.header,
        &*s_set.remote,
        &*s_keys.remote.header,
        &s_remote,
      );
    }
  }
  assert_eq!(stray_captures(), strays, "keys derived outside of the calls that Capture wraps");
}

// Drives a server and a client session of the transport (`ConnTls`) to the end of the handshake;
// returns the 1-RTT keys of each.
fn conn_handshake(server: &mut ConnTls, client: &mut ConnTls) -> (PacketKeys, PacketKeys) {
  let (mut s_keys, mut c_keys) = (None, None);
  let mut sent = [[0usize; 2]; 2];
  for _ in 0..8 {
    for (space_idx, space) in [Space::Initial, Space::Handshake].into_iter().enumerate() {
      let out = client.output(space)[sent[0][space_idx]..].to_vec();
      sent[0][space_idx] += out.len();
      server.feed(space, &out).unwrap();
      let out = server.output(space)[sent[1][space_idx]..].to_vec();
      sent[1][space_idx] += out.len();
      client.feed(space, &out).unwrap();
    }
    while let Some((space, keys)) = server.poll_keys(true).unwrap() {
      if space == Space::Data {
        s_keys = Some(keys);
      }
    }
    while let Some((space, keys)) = client.poll_keys(true).unwrap() {
      if space == Space::Data {
        c_keys = Some(keys);
      }
    }
    if server.is_complete() && client.is_complete() && s_keys.is_some() && c_keys.is_some() {
      break;
    }
  }
  (s_keys.unwrap(), c_keys.unwrap())
}

/// The sessions of the transport agree on the keys of every generation, the next ones from
/// rustls's `Secrets` through the core's key updates, with the keys that seal and those that open
/// advanced at different times, as the key phase does; the RSA certificate as well.
#[test]
fn sessions_interoperate_and_update_keys() {
  let mut rng = ChaCha20::from_key([3; 32]);
  for (cert, key) in [(CERT_PEM, KEY_PEM), (RSA_CERT_PEM, RSA_KEY_PEM)] {
    for suite in SUITES {
      let config = server_config(KeyMode::Capture, &[suite], cert, key);
      let mut server = ConnTls::new(config.new_session(&tp(true)).unwrap(), &mut rng).unwrap();
      let session = client_config(KeyMode::Capture).new_session("localhost", &tp(false)).unwrap();
      let mut client = ConnTls::new(session, &mut rng).unwrap();
      let (mut s, mut c) = conn_handshake(&mut server, &mut client);
      assert_eq!(s.local.suite(), suite);
      assert_eq!(server.peer_transport_params(), Some(&tp(false)[..]));
      let mut s_up = KeyUpdate::new(server.take_updater().unwrap());
      let mut c_up = KeyUpdate::new(client.take_updater().unwrap());
      for generation in 0..4u64 {
        for (from, to) in [(&c.local, &s.remote), (&s.local, &c.remote)] {
          let mut packet = plaintext(100);
          let len = seal_native(from, &mut packet, 10 + generation, 100);
          assert_eq!(open_native(to, &mut packet[..len], 9 + generation), 100, "{generation}");
        }
        // The remote keys of the server first (prepared), then its local keys
        s.remote = s.remote.next_generation(&s_up.next_for_test(false).unwrap()).unwrap();
        c.local.advance(&c_up.next_for_test(true).unwrap()).unwrap();
        c.remote = c.remote.next_generation(&c_up.next_for_test(false).unwrap()).unwrap();
        s.local.advance(&s_up.next_for_test(true).unwrap()).unwrap();
      }
      // A direction two generations ahead of the other is a broken key phase
      assert!(s_up.next_for_test(true).is_ok());
      assert!(s_up.next_for_test(true).is_err());
    }
  }
}

/// The configuration refuses resumption and 0-RTT: the server sends no session ticket, keeps no
/// session, offers no early data, so a client that would resume and send early data does neither.
#[test]
fn settings_refuse_resumption_and_early_data() {
  let config = server_config(KeyMode::Capture, &SUITES, CERT_PEM, KEY_PEM);
  let inner = config.rustls_config();
  assert_eq!(inner.send_tls13_tickets, 0);
  assert_eq!(inner.max_early_data_size, 0);
  assert!(!inner.send_half_rtt_data);
  assert!(!inner.ticketer.enabled());
  assert!(!inner.session_storage.can_cache());
  assert!(inner.cert_compressors.is_empty() && inner.cert_decompressors.is_empty());
  assert_eq!(inner.alpn_protocols, vec![b"h3".to_vec()]);
  // A client that resumes and sends early data when it can
  let provider = super::provider(KeyMode::Capture, &SUITES);
  let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(super::client::AnyCert))
    .with_no_client_auth();
  client_config.alpn_protocols = vec![b"h3".to_vec()];
  client_config.enable_early_data = true;
  let client_config = Arc::new(client_config);
  for round in 0..2 {
    let server = rq::ServerConnection::new(Arc::clone(inner), rq::Version::V1, tp(true)).unwrap();
    let client = rq::ClientConnection::new(
      Arc::clone(&client_config),
      rq::Version::V1,
      "localhost".try_into().unwrap(),
      tp(false),
    )
    .unwrap();
    assert!(client.zero_rtt_keys().is_none(), "round {round}: 0-RTT keys offered");
    let mut conns: [rq::Connection; 2] = [client.into(), server.into()];
    let mut after_one_rtt = [false; 2];
    for _ in 0..16 {
      let mut progress = false;
      for from in 0..2 {
        loop {
          let mut buf = Vec::new();
          let (change, _caps) = capture(|| conns[from].write_hs(&mut buf));
          if !buf.is_empty() {
            // Nothing (a NewSessionTicket) after the server's 1-RTT keys
            assert!(!(from == 1 && after_one_rtt[1]), "round {round}: post-handshake message");
            conns[1 - from].read_hs(&buf).unwrap();
            progress = true;
          }
          if let Some(KeyChange::OneRtt { .. }) = change {
            after_one_rtt[from] = true;
          }
          if change.is_none() && buf.is_empty() {
            break;
          }
          progress = true;
        }
      }
      if !progress {
        break;
      }
    }
    assert!(!conns[0].is_handshaking() && !conns[1].is_handshaking());
    for conn in &conns {
      assert_eq!(conn.handshake_kind(), Some(rustls::HandshakeKind::Full), "round {round}");
    }
    let rq::Connection::Server(server) = &conns[1] else { panic!() };
    assert!(server.zero_rtt_keys().is_none());
  }
}

/// A session of the transport fails the handshake when the client has no protocol in common:
/// `no_application_protocol` (0x178).
#[test]
fn alpn_mismatch_is_refused_with_no_application_protocol() {
  let mut rng = ChaCha20::from_key([4; 32]);
  let config = server_config(KeyMode::Capture, &SUITES, CERT_PEM, KEY_PEM);
  let mut server = ConnTls::new(config.new_session(&tp(true)).unwrap(), &mut rng).unwrap();
  for alpn in [&b"h2"[..], b""] {
    let client_config = RustlsClientConfig::new(alpn, &SUITES).unwrap();
    let client =
      ConnTls::new(client_config.new_session("localhost", &tp(false)).unwrap(), &mut rng).unwrap();
    let hello = client.output(Space::Initial).to_vec();
    let err = server.feed(Space::Initial, &hello).unwrap_err();
    assert!(
      matches!(err, crate::Error::QuicClose(TransportErrorCode::Crypto(120), _)),
      "{alpn:?}: {err:?}"
    );
    assert_eq!(TransportErrorCode::Crypto(120).code(), 0x178);
    server = ConnTls::new(config.new_session(&tp(true)).unwrap(), &mut rng).unwrap();
  }
}

#[test]
fn builder_refuses_incomplete_configurations() {
  let missing_key = RustlsConfig::builder().cert_chain_pem(CERT_PEM).build();
  assert!(matches!(missing_key, Err(ConfigError::NoPrivateKey)));
  let missing_cert = RustlsConfig::builder().private_key_pem(KEY_PEM).build();
  assert!(matches!(missing_cert, Err(ConfigError::NoCertificate)));
  let no_suite =
    RustlsConfig::builder().cert_chain_pem(CERT_PEM).private_key_pem(KEY_PEM).cipher_suites(&[]);
  assert!(matches!(no_suite.build(), Err(ConfigError::Empty)));
  let mismatch = RustlsConfig::builder().cert_chain_pem(CERT_PEM).private_key_pem(RSA_KEY_PEM);
  assert!(matches!(mismatch.build(), Err(ConfigError::Rustls(_))));
  let garbage = RustlsConfig::builder().cert_chain_pem(b"-----BEGIN CERTIFICATE-----\n!!\n");
  assert!(garbage.private_key_pem(KEY_PEM).build().is_err());
  // DER works as PEM does
  let cert_der: Vec<u8> = {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    CertificateDer::pem_slice_iter(CERT_PEM).next().unwrap().unwrap().to_vec()
  };
  let key_der: Vec<u8> = {
    use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
    PrivatePkcs8KeyDer::from_pem_slice(KEY_PEM).unwrap().secret_pkcs8_der().to_vec()
  };
  let der = RustlsConfig::builder().cert_chain_der(&[&cert_der]).private_key_pkcs8_der(&key_der);
  let factory: Box<dyn ServerSessionFactory> = Box::new(der.build().unwrap());
  assert!(factory.new_session(&tp(true)).is_ok());
  let _ = TlsAlert::INTERNAL_ERROR;
}

/// What a server handshake allocates, counted around the server's calls only (the client's are
/// counted apart), after warm-up handshakes: rustls driven directly, and the session of the
/// transport (`RustlsConfig::new_session` + `ConnTls` + the core's key update state). The
/// allocation tests of the connection and of the endpoint allow `TOTAL` per handshake; this test
/// names rustls's share and pins both, so that a rustls upgrade that changes them is noticed.
/// It also pins what a key update allocates (rustls's `Secrets::next_packet_keys`).
#[cfg_attr(miri, ignore)]
#[test]
fn handshake_allocations_are_pinned() {
  use crate::{
    sync::AtomicU64,
    testing::{
      HANDSHAKE_ALLOCATIONS_ECDSA, HANDSHAKE_ALLOCATIONS_RSA, KEY_UPDATE_ALLOCATIONS,
      RUSTLS_HANDSHAKE_ALLOCATIONS_ECDSA, RUSTLS_HANDSHAKE_ALLOCATIONS_RSA, count_allocations_in,
    },
  };
  use core::sync::atomic::Ordering;
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static RAW: AtomicU64 = AtomicU64::new(0);
  static SESSION: AtomicU64 = AtomicU64::new(0);
  static UPDATE: AtomicU64 = AtomicU64::new(0);
  const ROUNDS: u64 = 16;
  let server_tp = tp(true);
  let client_config = client_config(KeyMode::Capture);
  let mut rng = ChaCha20::from_key([5; 32]);
  let pems = [
    (CERT_PEM, KEY_PEM, RUSTLS_HANDSHAKE_ALLOCATIONS_ECDSA, HANDSHAKE_ALLOCATIONS_ECDSA),
    (RSA_CERT_PEM, RSA_KEY_PEM, RUSTLS_HANDSHAKE_ALLOCATIONS_RSA, HANDSHAKE_ALLOCATIONS_RSA),
  ];
  for (cert, key, rustls_budget, total_budget) in pems {
    let config = server_config(KeyMode::Capture, &SUITES, cert, key);
    // rustls alone: the server connection, fed the client's flights, its output in one buffer
    let raw = |counted: bool| {
      count_allocations_in(&OTHERS);
      let mut client: rq::Connection = rq::ClientConnection::new(
        Arc::clone(client_config.rustls_config()),
        rq::Version::V1,
        "localhost".try_into().unwrap(),
        tp(false),
      )
      .unwrap()
      .into();
      let mut to_server = Vec::with_capacity(4096);
      let mut to_client = Vec::with_capacity(8192);
      let _ = capture(|| while client.write_hs(&mut to_server).is_some() {});
      let enter = || count_allocations_in(if counted { &RAW } else { &OTHERS });
      enter();
      let mut server: rq::Connection = rq::ServerConnection::new(
        Arc::clone(config.rustls_config()),
        rq::Version::V1,
        server_tp.clone(),
      )
      .unwrap()
      .into();
      server.read_hs(&to_server).unwrap();
      let mut changes = Vec::with_capacity(4);
      let mut initial_len = None;
      loop {
        let before = to_client.len();
        let (change, _caps) = capture(|| server.write_hs(&mut to_client));
        let wrote = to_client.len() != before;
        match change {
          Some(elem) => {
            initial_len.get_or_insert(to_client.len());
            changes.push(elem);
          }
          None if !wrote => break,
          None => {}
        }
      }
      count_allocations_in(&OTHERS);
      to_server.clear();
      let (initial, handshake) = to_client.split_at(initial_len.unwrap());
      client.read_hs(initial).unwrap();
      let _ = capture(|| while client.write_hs(&mut to_server).is_some() {});
      client.read_hs(handshake).unwrap();
      let _ = capture(|| while client.write_hs(&mut to_server).is_some() {});
      let _ = capture(|| client.write_hs(&mut to_server));
      enter();
      server.read_hs(&to_server).unwrap();
      assert!(!server.is_handshaking());
      drop(changes);
      drop(server);
      count_allocations_in(&OTHERS);
    };
    // The session of the transport, as a connection drives it
    let session = |counted: bool, rng: &mut ChaCha20| {
      count_allocations_in(&OTHERS);
      let mut client =
        ConnTls::new(client_config.new_session("localhost", &tp(false)).unwrap(), rng).unwrap();
      let hello = client.output(Space::Initial).to_vec();
      let enter = || count_allocations_in(if counted { &SESSION } else { &OTHERS });
      enter();
      let mut server = ConnTls::new(config.new_session(&server_tp).unwrap(), rng).unwrap();
      server.feed(Space::Initial, &hello).unwrap();
      let mut keys = [None, None];
      while let Some((space, elem)) = server.poll_keys(true).unwrap() {
        keys[usize::from(space == Space::Data)] = Some(elem);
      }
      count_allocations_in(&OTHERS);
      let (initial, handshake) =
        (server.output(Space::Initial).to_vec(), server.output(Space::Handshake).to_vec());
      client.feed(Space::Initial, &initial).unwrap();
      while client.poll_keys(true).unwrap().is_some() {}
      client.feed(Space::Handshake, &handshake).unwrap();
      while client.poll_keys(true).unwrap().is_some() {}
      let finished = client.output(Space::Handshake).to_vec();
      enter();
      server.feed(Space::Handshake, &finished).unwrap();
      while let Some((space, elem)) = server.poll_keys(true).unwrap() {
        keys[usize::from(space == Space::Data)] = Some(elem);
      }
      assert!(server.is_complete() && keys[1].is_some());
      let updater = Box::new(KeyUpdate::new(server.take_updater().unwrap()));
      drop(server);
      drop(keys);
      count_allocations_in(&OTHERS);
      drop(client);
      updater
    };
    for _ in 0..4 {
      raw(false);
      drop(session(false, &mut rng));
    }
    let (raw_before, session_before) = (RAW.load(Ordering::SeqCst), SESSION.load(Ordering::SeqCst));
    let mut updaters = Vec::new();
    for _ in 0..ROUNDS {
      raw(true);
      updaters.push(session(true, &mut rng));
    }
    let raw_each = (RAW.load(Ordering::SeqCst) - raw_before) / ROUNDS;
    let session_each = (SESSION.load(Ordering::SeqCst) - session_before) / ROUNDS;
    std::eprintln!(
      "handshake allocations: rustls {raw_each}, session of the transport {session_each}"
    );
    assert_eq!(raw_each, rustls_budget, "rustls's allocations per handshake changed");
    assert_eq!(session_each, total_budget, "the allocations per handshake changed");
    // Key updates: rustls derives both directions at once, and the core keeps the other half
    let mut updater = updaters.pop().unwrap();
    count_allocations_in(&UPDATE);
    let before = UPDATE.load(Ordering::SeqCst);
    for _ in 0..8 {
      drop(updater.next_for_test(true).unwrap());
      drop(updater.next_for_test(false).unwrap());
    }
    let update_each = (UPDATE.load(Ordering::SeqCst) - before) / 8;
    count_allocations_in(&OTHERS);
    std::eprintln!("key update allocations: {update_each}");
    assert_eq!(update_each, KEY_UPDATE_ALLOCATIONS, "the allocations per key update changed");
  }
}

// The offset of the type of every extension of the ClientHello `msg`.
fn extension_types(msg: &[u8]) -> Vec<usize> {
  let mut at = 4 + 34;
  at += 1 + usize::from(msg[at]);
  at += 2 + usize::from(u16::from_be_bytes([msg[at], msg[at + 1]]));
  at += 1 + usize::from(msg[at]);
  let end = at + 2 + usize::from(u16::from_be_bytes([msg[at], msg[at + 1]]));
  at += 2;
  let mut rslt = Vec::new();
  while at < end {
    rslt.push(at);
    at += 4 + usize::from(u16::from_be_bytes([msg[at + 2], msg[at + 3]]));
  }
  rslt
}

/// RFC 9001 section 8.2: a ClientHello without the `quic_transport_parameters` extension of RFC
/// 9001 (0x39) is refused with `missing_extension`, also when it has the one of the drafts
/// (0xffa5), which rustls would take in its place; fed whole or a byte at a time.
#[test]
fn client_hello_with_only_the_draft_transport_parameters_is_refused() {
  let mut client = client_config(KeyMode::Capture).new_session("localhost", &tp(false)).unwrap();
  let mut hello = Vec::new();
  let _change = client.write_handshake(&mut hello).unwrap();
  let config = server_config(KeyMode::Capture, &SUITES, CERT_PEM, KEY_PEM);
  for piece in [hello.len(), 1] {
    let mut server = config.new_session(&tp(true)).unwrap();
    for chunk in hello.chunks(piece) {
      server.read_handshake(chunk).unwrap();
    }
    let mut draft = hello.clone();
    let at = extension_types(&draft)
      .into_iter()
      .find(|el| draft[*el..*el + 2] == [0x00, 0x39])
      .expect("the client sends the extension of RFC 9001");
    draft[at..at + 2].copy_from_slice(&[0xff, 0xa5]);
    let mut server = config.new_session(&tp(true)).unwrap();
    let rslt: Result<(), TlsAlert> =
      draft.chunks(piece).try_for_each(|el| server.read_handshake(el));
    assert_eq!(rslt, Err(TlsAlert::MISSING_EXTENSION), "piece {piece}");
  }
}
