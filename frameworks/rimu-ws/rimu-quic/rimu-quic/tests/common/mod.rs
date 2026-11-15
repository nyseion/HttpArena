//! What the tests of the `uring` driver share: an echo application, a server on a thread, and a
//! client over a standard UDP socket.

#![allow(dead_code, reason = "each test binary uses a part")]

use rimu_quic::{
  ConnCtx, QuicApp, QuicParams, StreamId,
  client::{TEST_CERT_PEM, TEST_KEY_PEM, TestClient},
  rng::ChaCha20,
  rustls::RustlsConfig,
  uring::{AppCounters, Server, ServerParams, ShutdownHandle, Stats, UringApp},
};
use std::{
  collections::BTreeMap,
  net::{SocketAddr, UdpSocket},
  sync::Arc,
  thread::JoinHandle,
  time::{Duration, Instant},
};

/// Every stream a client opens gets its bytes back.
#[derive(Debug, Default)]
pub struct EchoApp {
  pub streams: u64,
  /// Called at the start of each turn of the worker.
  pub on_turn: Option<fn()>,
}

/// The counters of [`EchoApp`].
#[derive(Clone, Copy, Debug, Default)]
pub struct EchoCounters {
  pub streams: u64,
}

impl AppCounters for EchoCounters {
  fn for_each(&self, f: &mut dyn FnMut(&'static str, u64)) {
    f("streams", self.streams);
  }
}

impl QuicApp for EchoApp {
  type ConnState = ();

  fn on_established(&mut self, _: &mut ConnCtx<'_, ()>) -> rimu_quic::Result<()> {
    Ok(())
  }

  fn on_stream_data(
    &mut self,
    cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> rimu_quic::Result<()> {
    if fin {
      self.streams += 1;
    }
    cx.write(id, data, fin)
  }

  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> rimu_quic::Result<()> {
    cx.reset(id, code);
    Ok(())
  }

  fn on_stop_sending(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: StreamId,
    _: u64,
  ) -> rimu_quic::Result<()> {
    Ok(())
  }

  fn on_closed(&mut self, _: &mut ()) {}
}

impl UringApp for EchoApp {
  type Counters = EchoCounters;

  fn start_turn(&mut self, _now_us: u64) {
    if let Some(f) = self.on_turn {
      f();
    }
  }

  fn counters(&self) -> EchoCounters {
    EchoCounters { streams: self.streams }
  }
}

/// A free UDP port on 127.0.0.1.
pub fn free_addr() -> SocketAddr {
  UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// A server running on a thread of its own.
pub struct Running {
  pub shutdown: ShutdownHandle,
  pub stats: Stats<EchoCounters>,
  thread: JoinHandle<std::io::Result<()>>,
}

impl Running {
  /// Waits for the server to return, at most `limit`.
  pub fn join(self, limit: Duration) {
    let started = Instant::now();
    while !self.thread.is_finished() {
      assert!(started.elapsed() < limit, "the server did not stop within {limit:?}");
      std::thread::sleep(Duration::from_millis(10));
    }
    self.thread.join().unwrap().unwrap();
  }
}

/// Starts an echo server with `params`.
pub fn start(params: ServerParams) -> Running {
  start_with(params, None)
}

/// [`start`] whose applications call `on_turn` at each turn.
pub fn start_with(params: ServerParams, on_turn: Option<fn()>) -> Running {
  let tls = RustlsConfig::builder()
    .alpn(&[b"echo"])
    .cert_chain_pem(TEST_CERT_PEM)
    .private_key_pem(TEST_KEY_PEM)
    .build()
    .unwrap();
  let server = Server::<EchoApp>::new(params);
  let shutdown = server.shutdown_handle();
  let stats = server.stats();
  let thread = std::thread::spawn(move || {
    server.run(Arc::new(tls), |_worker| EchoApp { on_turn, ..EchoApp::default() })
  });
  Running { shutdown, stats, thread }
}

/// What a client keeps of its streams.
#[derive(Debug, Default)]
pub struct ClientApp {
  pub streams: BTreeMap<u64, (Vec<u8>, bool)>,
}

impl QuicApp for ClientApp {
  type ConnState = ();

  fn on_established(&mut self, _: &mut ConnCtx<'_, ()>) -> rimu_quic::Result<()> {
    Ok(())
  }

  fn on_stream_data(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> rimu_quic::Result<()> {
    let entry = self.streams.entry(id.0).or_default();
    entry.0.extend_from_slice(data);
    entry.1 |= fin;
    Ok(())
  }

  fn on_stream_reset(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: StreamId,
    _: u64,
  ) -> rimu_quic::Result<()> {
    Ok(())
  }

  fn on_stop_sending(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    _: StreamId,
    _: u64,
  ) -> rimu_quic::Result<()> {
    Ok(())
  }

  fn on_closed(&mut self, _: &mut ()) {}
}

/// A test client over a standard UDP socket.
pub struct Client {
  buf: Vec<u8>,
  conn: TestClient<ClientApp>,
  socket: UdpSocket,
  server: SocketAddr,
  start: Instant,
}

impl Client {
  /// A client whose handshake with the server at `server` is confirmed (within 10 s).
  pub fn connect(server: SocketAddr) -> Self {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let start = Instant::now();
    let mut rng = ChaCha20::from_os().unwrap();
    let conn =
      TestClient::new(ClientApp::default(), &QuicParams::default(), server, b"echo", &mut rng, 1)
        .unwrap();
    let mut this = Self { buf: vec![0; 65_536], conn, socket, server, start };
    this.drive_until(Duration::from_secs(10), |el| el.is_confirmed());
    this
  }

  fn now_us(&self) -> u64 {
    u64::try_from(self.start.elapsed().as_micros()).unwrap().saturating_add(1)
  }

  /// Sends and receives until `done` holds or `limit` passes; returns whether `done` held.
  pub fn drive_until(
    &mut self,
    limit: Duration,
    mut done: impl FnMut(&TestClient<ClientApp>) -> bool,
  ) -> bool {
    let started = Instant::now();
    loop {
      let now_us = self.now_us();
      if self.conn.next_deadline().is_some_and(|el| el <= now_us) {
        self.conn.on_timeout(now_us);
      }
      let Self { conn, socket, server, .. } = self;
      let _sent = conn.flush(now_us, |datagram| {
        let _ = socket.send_to(datagram, *server);
      });
      if done(&self.conn) {
        return true;
      }
      if started.elapsed() >= limit {
        return false;
      }
      let wait = self
        .conn
        .next_deadline()
        .map_or(10_000, |el| el.saturating_sub(self.now_us()))
        .clamp(100, 10_000);
      self.socket.set_read_timeout(Some(Duration::from_micros(wait))).unwrap();
      if let Ok((len, _)) = self.socket.recv_from(&mut self.buf) {
        let now_us = self.now_us();
        let Self { buf, conn, .. } = self;
        conn.recv(now_us, &mut buf[..len]);
      }
    }
  }

  /// Opens a stream, writes `msg` with the FIN and returns what came back on it, within 10 s.
  pub fn echo(&mut self, msg: &[u8]) -> Vec<u8> {
    let now_us = self.now_us();
    let id = self
      .conn
      .with_ctx(now_us, |_, cx| {
        let id = cx.open_bidi()?;
        cx.write(id, msg, true)?;
        Ok::<_, rimu_quic::Error>(id)
      })
      .unwrap();
    let done = self.drive_until(Duration::from_secs(10), |el| {
      el.app().streams.get(&id.0).is_some_and(|stream| stream.1)
    });
    assert!(done, "no answer on stream {}", id.0);
    self.conn.app_mut().streams.remove(&id.0).unwrap().0
  }

  /// Waits at most `limit` for the server to close the connection; its CONNECTION_CLOSE.
  pub fn wait_close(&mut self, limit: Duration) -> Option<(bool, u64)> {
    let _closed = self.drive_until(limit, |el| el.peer_close().is_some());
    self.conn.peer_close()
  }
}
