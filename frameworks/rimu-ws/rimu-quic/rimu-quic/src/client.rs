//! The test client (`client` feature): one client connection driven by hand, for the tests and the
//! interop of the layers on the transport (an HTTP/3 server's tests run it against an
//! [`crate::Endpoint`]). It is not a supported client: it trusts any certificate, resumes nothing
//! and sends no early data.
//!
//! Like the endpoint it does no I/O: [`TestClient::flush`] hands out its datagrams and
//! [`TestClient::recv`] takes those of the server, at the times that the caller gives.

use crate::{
  Cid, CipherSuite, ConnCtx, ConnState, DatagramMeta, FlushOutcome, QuicApp, QuicConn, QuicParams,
  TxArena, conn_tls::ConnTls, pools::QuicPools, rng::ChaCha20, rng::Rng as _,
  rustls::RustlsClientConfig,
};
use alloc::{boxed::Box, vec::Vec};
use core::net::SocketAddr;

/// A self-signed ECDSA P-256 certificate for `localhost`, PEM, for test servers.
pub static TEST_CERT_PEM: &[u8] = include_bytes!("../tests/certs/ecdsa-cert.pem");
/// The private key of [`TEST_CERT_PEM`], PEM.
pub static TEST_KEY_PEM: &[u8] = include_bytes!("../tests/certs/ecdsa-key.pem");

// The bytes of the arena of a client
const ARENA_BYTES: usize = 64 * 1500;

/// One client connection and its application `A`: see the [module documentation](self).
///
/// Its pools and arena are its own, so that a test that counts the allocations of a server can
/// leave the client's out.
#[derive(Debug)]
pub struct TestClient<A>
where
  A: QuicApp,
{
  app: A,
  conn: QuicConn<A, true>,
  pools: QuicPools,
  // A train, copied out of the arena for the caller to change
  scratch: Vec<u8>,
  server: SocketAddr,
  tx: TxArena,
}

impl<A> TestClient<A>
where
  A: QuicApp,
{
  /// A client of `app` with the transport parameters of `params` that offers `alpn` (nothing if
  /// empty) to `server`; its connection IDs and TLS randoms come from `rng`. Its first flight
  /// leaves with the first [`Self::flush`].
  #[inline]
  pub fn new(
    app: A,
    params: &QuicParams,
    server: SocketAddr,
    alpn: &[u8],
    rng: &mut ChaCha20,
    now_us: u64,
  ) -> crate::Result<Self> {
    let params = params.conn_params();
    let (mut local, mut original) = ([0; 8], [0; 8]);
    rng.fill_slice(&mut local);
    rng.fill_slice(&mut original);
    let (local, original) = (Cid::new(&local)?, Cid::new(&original)?);
    let mut tp = [0; 256];
    let len = params.transport_params(local, None).encode(&mut tp)?;
    let config = RustlsClientConfig::new(alpn, &CipherSuite::PRIORITY)
      .map_err(|_| crate::Error::ProgrammingError)?;
    let session = config
      .new_session("localhost", tp.get(..len).unwrap_or_default())
      .map_err(|_| crate::Error::ProgrammingError)?;
    let tls = Box::new(ConnTls::new(session, rng)?);
    let mut pools = QuicPools::new();
    let conn = QuicConn::new_client(&params, local, original, server, tls, now_us, &mut pools)?;
    Ok(Self { app, conn, pools, scratch: Vec::new(), server, tx: TxArena::new(ARENA_BYTES)? })
  }

  /// Ends the connection at once, without a CONNECTION_CLOSE (as dropping the client does).
  #[inline]
  pub fn abort(&mut self) {
    self.conn.abort(&mut self.app, &mut self.pools);
  }

  /// The application.
  #[inline]
  pub const fn app(&self) -> &A {
    &self.app
  }

  /// The application, to change.
  #[inline]
  pub const fn app_mut(&mut self) -> &mut A {
    &mut self.app
  }

  /// Closes the connection with the application error `code`; the CONNECTION_CLOSE leaves with
  /// the next flush.
  #[inline]
  pub fn close(&mut self, now_us: u64, code: u64) {
    self.conn.close_app(now_us, code);
  }

  /// Writes what is due into the arena of the client and hands each datagram to `send`, which
  /// may change it (a test that damages packets). Returns `false` if nothing was sent.
  #[inline]
  pub fn flush(&mut self, now_us: u64, mut send: impl FnMut(&mut [u8])) -> bool {
    let mut sent = false;
    loop {
      let full = self.conn.flush(now_us, &mut self.tx, &mut self.app, &mut self.pools)
        == FlushOutcome::ArenaFull;
      loop {
        let Self { scratch, tx, .. } = self;
        let Some((id, segment)) = tx.pending().next().map(|el| {
          scratch.clear();
          scratch.extend_from_slice(el.bytes);
          (el.id, usize::from(el.segment_size.max(1)))
        }) else {
          break;
        };
        tx.mark_submitted(id);
        tx.release(id);
        for datagram in scratch.chunks_mut(segment) {
          sent = true;
          send(datagram);
        }
      }
      if !full {
        return sent;
      }
    }
  }

  /// If the handshake is confirmed and the connection is open.
  #[inline]
  pub fn is_confirmed(&self) -> bool {
    self.conn.state() == ConnState::Confirmed
  }

  /// If the connection is over: closed, or closing or draining.
  #[inline]
  pub fn is_closed(&self) -> bool {
    matches!(self.conn.state(), ConnState::Closing | ConnState::Draining | ConnState::Closed)
  }

  /// If the connection drains: the peer closed it.
  #[inline]
  pub fn is_draining(&self) -> bool {
    self.conn.state() == ConnState::Draining
  }

  /// When [`Self::on_timeout`] is due, if ever.
  #[inline]
  pub fn next_deadline(&self) -> Option<u64> {
    self.conn.next_deadline()
  }

  /// Runs the timers that are due at `now_us`.
  #[inline]
  pub fn on_timeout(&mut self, now_us: u64) {
    self.conn.on_timeout(now_us, &mut self.app, &mut self.pools);
  }

  /// The connection ID that the client sends its packets to: the one it made up for its first
  /// Initial packets, then the one the server chose (whose first byte names its worker).
  #[inline]
  pub fn peer_cid(&self) -> &[u8] {
    self.conn.peer_cid().as_slice()
  }

  /// The CONNECTION_CLOSE that the server sent, once it arrived: (application error, code).
  #[inline]
  pub fn peer_close(&self) -> Option<(bool, u64)> {
    self.conn.peer_close()
  }

  /// Takes `datagram`, which the server sent: its packets are decrypted in place and the
  /// callbacks of the application run.
  #[inline]
  pub fn recv(&mut self, now_us: u64, datagram: &mut [u8]) {
    let meta = DatagramMeta { peer: self.server, local: None, segment_size: None };
    let _rslt = self.conn.recv_datagram(now_us, datagram, meta, &mut self.app, &mut self.pools);
  }

  /// Runs `f` with the application and the context of the connection at `now_us`, as the
  /// application does outside of the callbacks: to open streams and write.
  #[inline]
  pub fn with_ctx<R>(
    &mut self,
    now_us: u64,
    f: impl FnOnce(&mut A, &mut ConnCtx<'_, A::ConnState>) -> R,
  ) -> R {
    let Self { app, conn, pools, .. } = self;
    conn.with_ctx(now_us, pools, |cx| f(app, cx))
  }
}

impl<A> Drop for TestClient<A>
where
  A: QuicApp,
{
  #[inline]
  fn drop(&mut self) {
    self.abort();
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    DatagramMeta, Endpoint, EndpointKeys, QuicParams, StreamId,
    client::TestClient,
    rng::ChaCha20,
    sync::Arc,
    testing::{Behavior, SERVER_ADDR, TestApp, server_tls_config},
  };
  use alloc::vec::Vec;

  // The client of the `client` feature runs a handshake with an endpoint, writes a stream that the
  // server echoes, and reads the close of the server, all through its public interface.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn test_client_talks_to_an_endpoint() {
    let mut rng = ChaCha20::from_key([3; 32]);
    let keys = Arc::new(EndpointKeys::new(&mut rng));
    let params = QuicParams::default();
    let mut endpoint =
      Endpoint::new(params, 0, 1, server_tls_config(), &mut rng, None, keys).unwrap();
    let mut server_app = TestApp { is_server: true, ..TestApp::new(Behavior::Echo) };
    let mut tx = crate::TxArena::new(crate::TxArena::DEFAULT_BYTES).unwrap();
    let mut now_us = 1_000_000;
    let mut client =
      TestClient::new(TestApp::default(), &params, SERVER_ADDR, b"h3", &mut rng, now_us).unwrap();
    let client_addr = crate::testing::CLIENT_ADDR;
    let mut exchange = |client: &mut TestClient<TestApp>,
                        endpoint: &mut Endpoint<TestApp>,
                        server_app: &mut TestApp,
                        now_us: u64| {
      for _ in 0..16 {
        let meta = DatagramMeta { peer: client_addr, local: None, segment_size: None };
        let mut moved = client.flush(now_us, |datagram| {
          let _ = endpoint.recv(now_us, datagram, meta, server_app);
        });
        let _ = endpoint.flush(now_us, &mut tx, server_app);
        let mut out: Vec<(crate::TrainId, Vec<u8>, usize)> = Vec::new();
        for train in tx.pending() {
          out.push((train.id, train.bytes.to_vec(), usize::from(train.segment_size)));
        }
        for (id, mut bytes, segment) in out {
          tx.mark_submitted(id);
          tx.release(id);
          for datagram in bytes.chunks_mut(segment) {
            moved = true;
            client.recv(now_us, datagram);
          }
        }
        if !moved {
          return;
        }
      }
    };
    exchange(&mut client, &mut endpoint, &mut server_app, now_us);
    assert!(client.is_confirmed());
    let id = client
      .with_ctx(now_us, |_, cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"ping", true)?;
        Ok::<StreamId, crate::Error>(id)
      })
      .unwrap();
    exchange(&mut client, &mut endpoint, &mut server_app, now_us);
    let log = &client.app().streams[&id.0];
    assert_eq!((log.data.as_slice(), log.fin), (&b"ping"[..], true));
    assert_eq!(client.peer_close(), None);
    endpoint.begin_shutdown(now_us, &mut server_app);
    now_us += 1_000;
    exchange(&mut client, &mut endpoint, &mut server_app, now_us);
    let code = params.limits().shutdown_app_code;
    assert_eq!(client.peer_close(), Some((true, code)));
    assert!(client.is_draining() && client.is_closed());
    endpoint.abort_all(&mut server_app);
  }

  // The client tells the connection ID that it sends to, the one the server chose: its first byte
  // names the worker of the server (a test of steering reads it).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn peer_cid_names_the_worker_of_the_server() {
    let mut rng = ChaCha20::from_key([5; 32]);
    let keys = Arc::new(EndpointKeys::new(&mut rng));
    let params = QuicParams::default();
    let mut endpoint =
      Endpoint::new(params, 1, 2, server_tls_config(), &mut rng, None, keys).unwrap();
    let mut server_app = TestApp { is_server: true, ..TestApp::new(Behavior::Echo) };
    let mut tx = crate::TxArena::new(crate::TxArena::DEFAULT_BYTES).unwrap();
    let now_us = 1_000_000;
    let mut client =
      TestClient::new(TestApp::default(), &params, SERVER_ADDR, b"h3", &mut rng, now_us).unwrap();
    let original = client.peer_cid().to_vec();
    let meta = DatagramMeta { peer: crate::testing::CLIENT_ADDR, local: None, segment_size: None };
    for _ in 0..16 {
      let _ = client.flush(now_us, |datagram| {
        let _ = endpoint.recv(now_us, datagram, meta, &mut server_app);
      });
      let _ = endpoint.flush(now_us, &mut tx, &mut server_app);
      let out: Vec<(crate::TrainId, Vec<u8>, usize)> =
        tx.pending().map(|el| (el.id, el.bytes.to_vec(), usize::from(el.segment_size))).collect();
      for (id, mut bytes, segment) in out {
        tx.mark_submitted(id);
        tx.release(id);
        for datagram in bytes.chunks_mut(segment) {
          client.recv(now_us, datagram);
        }
      }
    }
    assert!(client.is_confirmed());
    let cid = client.peer_cid();
    assert_ne!(cid, original.as_slice());
    assert_eq!((cid.len(), cid[0]), (8, 1));
    endpoint.abort_all(&mut server_app);
  }
}
