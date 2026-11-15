//! Micro-benchmarks of the per-packet path and of the handshake, for `bench/` (hidden, `__bench`
//! feature): they reach crate-private code. Each function times `iters` operations once and
//! returns nanoseconds per operation; the caller interleaves and repeats them.

use crate::{
  Cid, CipherSuite, ConnParams, DirectionalKeys, FrameReader, HpBatch, Space,
  conn_tls::ConnTls,
  open_payload, protect, protect_deferred,
  protection::{HP_BATCH_LEN, QuicHp, SAMPLE_LEN, material_from_secret},
  remove_header_protection,
  rng::ChaCha20,
  rustls::{RustlsClientConfig, RustlsConfig},
  tls::ServerSessionFactory as _,
};
use alloc::{vec, vec::Vec};
use core::hint::black_box;
use std::time::Instant;

const PN_OFFSET: usize = 9;

/// The 1-RTT keys of `suite` from a fixed secret, with batched header protection if `batched`.
fn keys(suite: CipherSuite, batched: bool) -> DirectionalKeys {
  let secret: Vec<u8> = (0..suite.hash_len()).map(|el| el.wrapping_mul(7)).collect();
  let material = material_from_secret(suite, &secret, true).unwrap();
  DirectionalKeys::from_material(&material, batched).unwrap()
}

fn packet(payload_len: usize) -> Vec<u8> {
  let mut buf = vec![0u8; PN_OFFSET + 2 + payload_len + 16];
  buf[0] = 0x41;
  buf
}

/// Seal + header protection of one 1-RTT packet of `payload_len` bytes (`protect`).
pub fn seal(suite: CipherSuite, payload_len: usize, iters: u64) -> f64 {
  let keys = keys(suite, false);
  let mut buf = packet(payload_len);
  let start = Instant::now();
  for pn in 0..iters {
    buf[0] = 0x41;
    let _ = black_box(protect(&keys, &mut buf, PN_OFFSET, pn, 2, payload_len));
  }
  start.elapsed().as_nanos() as f64 / iters as f64
}

/// Seal with the header protection deferred into batches of eight, as the connection's flush does
/// (`protect_deferred` + `HpBatch::apply`).
pub fn seal_deferred(suite: CipherSuite, payload_len: usize, iters: u64) -> f64 {
  let keys = keys(suite, true);
  let one = PN_OFFSET + 2 + payload_len + 16;
  let mut arena = vec![0u8; one * HP_BATCH_LEN];
  let mut batch = HpBatch::new();
  let start = Instant::now();
  let mut pn = 0;
  while pn < iters {
    for idx in 0..HP_BATCH_LEN {
      let at = idx * one;
      arena[at] = 0x41;
      let _ = black_box(protect_deferred(
        &keys,
        &mut arena[at..at + one],
        (PN_OFFSET, pn, 2, payload_len),
        at,
        &mut batch,
      ));
      pn += 1;
    }
    let _ = black_box(batch.apply(keys.hp(), &mut arena));
  }
  start.elapsed().as_nanos() as f64 / pn as f64
}

/// Remove header protection + open one packet, including a copy of the sealed packet.
pub fn open(suite: CipherSuite, payload_len: usize, iters: u64) -> f64 {
  let keys = keys(suite, false);
  let mut sealed = packet(payload_len);
  let len = protect(&keys, &mut sealed, PN_OFFSET, 7, 2, payload_len).unwrap();
  sealed.truncate(len);
  let mut buf = sealed.clone();
  let start = Instant::now();
  for _ in 0..iters {
    buf.copy_from_slice(&sealed);
    let (pn, pn_len, _) =
      remove_header_protection(keys.hp(), &mut buf, PN_OFFSET, Some(6)).unwrap();
    let _ = black_box(open_payload(keys.aead(), keys.iv(), &mut buf, PN_OFFSET + pn_len, pn));
  }
  start.elapsed().as_nanos() as f64 / iters as f64
}

/// Header protection masks of `packets` samples: batched (AES-NI, eight lanes) if `batched`, else
/// one at a time with the backend's key.
pub fn hp_masks(suite: CipherSuite, packets: usize, batched: bool, iters: u64) -> f64 {
  let key: Vec<u8> = (0..suite.cipher_key_len()).collect();
  let hp =
    QuicHp::with_batches(suite, &key, batched, batched && crate::protection::has_aes_ni()).unwrap();
  let samples: Vec<[u8; SAMPLE_LEN]> = (0..packets).map(|el| [el as u8; SAMPLE_LEN]).collect();
  let mut out = vec![[0u8; 5]; packets];
  let rounds = (iters / packets as u64).max(1);
  let start = Instant::now();
  for _ in 0..rounds {
    if batched {
      for (chunk, dst) in samples.chunks(HP_BATCH_LEN).zip(out.chunks_mut(HP_BATCH_LEN)) {
        let _ = black_box(hp.masks(chunk, dst));
      }
    } else {
      for (sample, dst) in samples.iter().zip(&mut out) {
        *dst = hp.mask(sample).unwrap();
      }
    }
    black_box(&mut out);
  }
  start.elapsed().as_nanos() as f64 / (rounds * packets as u64) as f64
}

/// The payload of a typical 1-RTT packet of a server: an ACK, a MAX_STREAM_DATA and a STREAM frame
/// of `stream_len` bytes; or of many small frames.
pub fn frame_payload(stream_len: usize, small_frames: usize) -> Vec<u8> {
  let mut out = vec![0x02, 0x40, 0x64, 0x05, 0x00, 0x0a, 0x11, 0x04, 0x80, 0x01, 0x00, 0x00];
  for idx in 0..small_frames {
    // PING, MAX_DATA, RESET_STREAM
    out.extend_from_slice(&[
      0x01,
      0x10,
      0x80,
      0x10,
      0x00,
      0x00,
      0x04,
      (idx % 16) as u8 * 4,
      0x00,
      0x05,
    ]);
  }
  if stream_len > 0 {
    // STREAM with offset and length: id 4, offset 1024, length
    out.extend_from_slice(&[0x0e, 0x04, 0x44, 0x00]);
    out.extend_from_slice(&(0x4000u16 | stream_len as u16).to_be_bytes());
    out.extend(core::iter::repeat_n(0x61, stream_len));
  }
  out
}

/// Decodes every frame of `payload` (a 1-RTT payload); returns ns per payload.
pub fn frame_decode(payload: &[u8], iters: u64) -> f64 {
  let start = Instant::now();
  for _ in 0..iters {
    for frame in FrameReader::new(black_box(payload), Space::Data) {
      let _ = black_box(frame.unwrap());
    }
  }
  start.elapsed().as_nanos() as f64 / iters as f64
}

/// The configurations of the handshake benchmark: a server of `cert_pem`/`key_pem` and a client.
pub fn handshake_configs(cert_pem: &[u8], key_pem: &[u8]) -> (RustlsConfig, RustlsClientConfig) {
  let server = RustlsConfig::builder().cert_chain_pem(cert_pem).private_key_pem(key_pem).build();
  let client = RustlsClientConfig::new(b"h3", &CipherSuite::PRIORITY);
  (server.unwrap(), client.unwrap())
}

fn tp(server: bool) -> Vec<u8> {
  let cid = Cid::new(&[1; 8]).unwrap();
  let original = server.then(|| Cid::new(&[2; 8]).unwrap());
  let mut buf = [0; 256];
  let len = ConnParams::default().transport_params(cid, original).encode(&mut buf).unwrap();
  buf[..len].to_vec()
}

/// Server-side cost of `count` handshakes, the client's work not timed: the session of the
/// transport fed the ClientHello and the client's Finished, its keys built; µs per handshake.
pub fn handshake(server: &RustlsConfig, client: &RustlsClientConfig, count: u32) -> f64 {
  let mut rng = ChaCha20::from_key([9; 32]);
  let (server_tp, client_tp) = (tp(true), tp(false));
  let mut timed = core::time::Duration::ZERO;
  for _ in 0..count {
    let mut c =
      ConnTls::new(client.new_session("localhost", &client_tp).unwrap(), &mut rng).unwrap();
    let hello = c.output(Space::Initial).to_vec();
    let start = Instant::now();
    let mut s = ConnTls::new(server.new_session(&server_tp).unwrap(), &mut rng).unwrap();
    s.feed(Space::Initial, &hello).unwrap();
    while black_box(s.poll_keys(true).unwrap()).is_some() {}
    timed += start.elapsed();
    let (initial, handshake) =
      (s.output(Space::Initial).to_vec(), s.output(Space::Handshake).to_vec());
    c.feed(Space::Initial, &initial).unwrap();
    while c.poll_keys(true).unwrap().is_some() {}
    c.feed(Space::Handshake, &handshake).unwrap();
    while c.poll_keys(true).unwrap().is_some() {}
    let finished = c.output(Space::Handshake).to_vec();
    let start = Instant::now();
    s.feed(Space::Handshake, &finished).unwrap();
    while black_box(s.poll_keys(true).unwrap()).is_some() {}
    assert!(s.is_complete());
    drop(black_box(s));
    timed += start.elapsed();
  }
  timed.as_nanos() as f64 / 1000.0 / f64::from(count)
}
