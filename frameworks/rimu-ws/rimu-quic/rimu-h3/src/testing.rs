//! An in-process HTTP/3 harness for the tests and the fuzz target: the endpoint of one worker whose
//! application is an [`H3Server`], clients of rimu-quic's test client ([`TestClient`]) whose
//! [`ClientApp`] collects what arrives on every stream, a fake network between them and a fake
//! clock ([`H3Net`]), and helpers that write requests and the clients' own streams and read
//! responses and the streams of the server.
//!
//! Each client has an address of its own, from which the tests find its connection on the server
//! (the server records the connections it establishes, by peer address).

use crate::{
  H3ConnState, H3Params, H3Server, H3Settings, Handler, ReqCtx, ReqOutcome, Request,
  frame::{H3FrameTy, decode_frame_header, encode_frame_header},
};
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::AtomicU64;
use rimu_qpack::{DecodeOutcome, Decoder, DecoderConfig, encode_static};
use rimu_quic::{
  ConnCtx, ConnHandle, DatagramMeta, Endpoint, EndpointKeys, QuicApp, QuicParams, StreamId,
  TxArena,
  client::{TEST_CERT_PEM, TEST_KEY_PEM, TestClient},
  rng::ChaCha20,
  rustls::RustlsConfig,
  varint::{decode_varint, encode_varint},
};

/// The address of the server.
pub const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
/// The fields of `GET https://localhost/`.
pub const GET: [(&[u8], &[u8]); 4] =
  [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")];
/// A PRIORITY_UPDATE frame type of RFC 9218, which this implementation does not know.
pub const PRIORITY_UPDATE: u64 = 0xf0700;
/// A PTO of the initial RTT, three times: the closing period.
pub const CLOSING_US: u64 = 3 * (333_000 + 4 * 166_500 + 25_000);

/// Fields, owned.
pub type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// What arrived on a stream of a client.
#[derive(Clone, Debug, Default)]
pub struct StreamLog {
  /// The bytes, in order.
  pub data: Vec<u8>,
  /// If the FIN arrived.
  pub fin: bool,
  /// The length and the FIN of every call: one per STREAM frame that arrived in order.
  pub calls: Vec<(usize, bool)>,
}

/// The application of a client: it collects what arrives on every stream.
#[derive(Clone, Debug, Default)]
pub struct ClientApp {
  /// Calls of `on_closed`.
  pub closed: u32,
  /// A stream whose data it never consumes: it retains it, so that its credit does not come back
  /// to the server.
  pub hold: Option<u64>,
  /// The RESET_STREAM frames that arrived: stream and code.
  pub resets: Vec<(StreamId, u64)>,
  /// The STOP_SENDING frames that arrived: stream and code.
  pub stops: Vec<(StreamId, u64)>,
  /// What arrived, by stream.
  pub streams: BTreeMap<u64, StreamLog>,
}

impl QuicApp for ClientApp {
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
    if self.hold == Some(id.0) {
      // As much as can be retained: the credit of the rest comes back
      return cx.retain(data.len().min(4096));
    }
    let log = self.streams.entry(id.0).or_default();
    log.data.extend_from_slice(data);
    log.fin |= fin;
    log.calls.push((data.len(), fin));
    Ok(())
  }

  fn on_stream_reset(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> rimu_quic::Result<()> {
    self.resets.push((id, code));
    Ok(())
  }

  fn on_stop_sending(
    &mut self,
    _: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> rimu_quic::Result<()> {
    self.stops.push((id, code));
    Ok(())
  }

  fn on_closed(&mut self, _: &mut ()) {
    self.closed = self.closed.wrapping_add(1);
  }
}

/// A request that reached a [`TestHandler`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SeenRequest {
  /// `:authority`.
  pub authority: Vec<u8>,
  /// The body.
  pub body: Vec<u8>,
  /// The fields that are not pseudo-header fields.
  pub fields: Fields,
  /// `:method`.
  pub method: Vec<u8>,
  /// `:path`.
  pub path: Vec<u8>,
  /// `:scheme`.
  pub scheme: Vec<u8>,
  /// The stream.
  pub stream: u64,
}

/// Answers every request with `200`, `content-type: text/plain` and [`Self::body`], except those
/// whose path starts with `/park`, which it parks, and `/err`, which it fails; a parked request is
/// answered with `resumed`.
#[derive(Clone, Debug, Default)]
pub struct TestHandler {
  /// The response body.
  pub body: &'static [u8],
  /// Requests answered or parked.
  pub count: u64,
  /// Requests abandoned while parked: connection and stream.
  pub abandoned: Vec<(ConnHandle, StreamId)>,
  /// Connections closed with parked requests.
  pub conns_closed: Vec<ConnHandle>,
  /// Requests parked, by stream.
  pub parked: Vec<StreamId>,
  /// If requests are kept in [`Self::seen`], which allocates.
  pub record: bool,
  /// Requests resumed.
  pub resumed: u64,
  /// The requests, if [`Self::record`].
  pub seen: Vec<SeenRequest>,
}

impl TestHandler {
  /// Answers with `body` and records the requests.
  pub fn new(body: &'static [u8]) -> Self {
    Self { body, record: true, ..Self::default() }
  }
}

impl Handler for TestHandler {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    self.count = self.count.wrapping_add(1);
    if self.record {
      self.seen.push(SeenRequest {
        authority: req.authority.to_vec(),
        body: req.body.to_vec(),
        fields: req.fields.iter().map(|(name, value)| (name.to_vec(), value.to_vec())).collect(),
        method: req.method.to_vec(),
        path: req.path.to_vec(),
        scheme: req.scheme.to_vec(),
        stream: req.stream.0,
      });
    }
    if req.path.starts_with(b"/park") {
      self.parked.push(req.stream);
      return Ok(ReqOutcome::Parked);
    }
    if req.path.starts_with(b"/err") {
      return Err(crate::Error::Http3(crate::Http3Error::BufferTooSmall));
    }
    cx.respond_fields(&[(b":status", b"200"), (b"content-type", b"text/plain")], self.body)?;
    Ok(ReqOutcome::Responded)
  }

  fn resume(&mut self, cx: &mut ReqCtx<'_, '_>, _stream: StreamId) -> crate::Result<ReqOutcome> {
    self.resumed = self.resumed.wrapping_add(1);
    cx.respond_fields(&[(b":status", b"200")], b"resumed")?;
    Ok(ReqOutcome::Responded)
  }

  fn on_abandoned(&mut self, conn: ConnHandle, stream: StreamId) {
    self.abandoned.push((conn, stream));
  }

  fn on_conn_closed(&mut self, conn: ConnHandle) {
    self.conns_closed.push(conn);
  }
}

/// A response as a client got it.
#[derive(Clone, Debug, Default)]
pub struct Response {
  /// The payloads of the DATA frames.
  pub body: Vec<u8>,
  /// The length and the FIN of every delivery of the stream to the client: one per STREAM frame.
  pub calls: Vec<(usize, bool)>,
  /// The fields of the HEADERS frame, `:status` included.
  pub fields: Fields,
  /// If the FIN arrived.
  pub fin: bool,
  /// The types of the frames, in order.
  pub frames: Vec<u64>,
}

impl Response {
  /// The value of field `name`.
  pub fn field(&self, name: &[u8]) -> Option<&[u8]> {
    self.fields.iter().find(|el| el.0 == name).map(|el| el.1.as_slice())
  }
}

/// A client of an [`H3Net`].
#[derive(Debug)]
pub struct NetClient {
  /// Its address.
  pub addr: SocketAddr,
  /// The connection and its application.
  pub conn: TestClient<ClientApp>,
  /// The datagrams of the server to it are lost.
  pub deaf: bool,
  /// What it sends is lost.
  pub mute: bool,
}

/// Clients and the endpoint of one worker whose application is an [`H3Server`] of `H`, a fake
/// network between them and a fake clock. See the [module documentation](self).
#[derive(Debug)]
pub struct H3Net<H: Handler = TestHandler> {
  /// The application of the worker.
  pub app: H3Server<H>,
  /// The clients.
  pub clients: Vec<NetClient>,
  /// The transport parameters of the clients.
  pub client_params: QuicParams,
  counters: Option<(&'static AtomicU64, &'static AtomicU64)>,
  /// The endpoint of the worker.
  pub endpoint: Endpoint<H3Server<H>>,
  /// The time of the fake clock.
  pub now_us: u64,
  rng: ChaCha20,
  scratch: Vec<u8>,
  tx: TxArena,
}

/// The TLS configuration of the test certificate, offering `h3`.
pub fn server_tls() -> Arc<RustlsConfig> {
  static CONFIG: std::sync::OnceLock<Arc<RustlsConfig>> = std::sync::OnceLock::new();
  Arc::clone(CONFIG.get_or_init(|| {
    #[allow(clippy::unwrap_used, reason = "the test certificate is valid")]
    let config = RustlsConfig::builder()
      .alpn(&[b"h3"])
      .cert_chain_pem(TEST_CERT_PEM)
      .private_key_pem(TEST_KEY_PEM)
      .build()
      .unwrap();
    Arc::new(config)
  }))
}

impl<H: Handler> H3Net<H> {
  /// A server with `quic` and `params` whose requests `handler` answers, and no client.
  pub fn new(quic: QuicParams, params: H3Params, handler: H) -> Self {
    let mut rng = ChaCha20::from_key([7; 32]);
    let keys = Arc::new(EndpointKeys::new(&mut rng));
    #[allow(clippy::unwrap_used, reason = "a test harness")]
    let endpoint = Endpoint::new(quic, 0, 1, server_tls(), &mut rng, None, keys).unwrap();
    let mut app = H3Server::new(handler, params);
    // The record of the connections, which only tests keep, allocates nothing that they count
    app.established.reserve(1 << 14);
    Self {
      app,
      clients: Vec::new(),
      client_params: QuicParams::default(),
      counters: None,
      endpoint,
      now_us: 1_000_000,
      rng,
      scratch: Vec::with_capacity(1 << 17),
      #[allow(clippy::unwrap_used, reason = "a test harness")]
      tx: TxArena::new(TxArena::DEFAULT_BYTES).unwrap(),
    }
  }

  /// Counts the allocations of the calls into the endpoint in the first counter, and the others
  /// in the second one (tests only: the counting allocator of the test build).
  pub fn count(&mut self, counters: (&'static AtomicU64, &'static AtomicU64)) {
    self.counters = Some(counters);
    leave(self.counters);
  }

  /// A new client, whose first flight leaves with the next step. Returns its index.
  pub fn add_client(&mut self) -> usize {
    let idx = self.clients.len();
    let ip = Ipv4Addr::from(0x0a00_0001u32.wrapping_add(u32::try_from(idx).unwrap_or(0)));
    #[allow(clippy::unwrap_used, reason = "a test harness")]
    let conn = TestClient::new(
      ClientApp::default(),
      &self.client_params,
      SERVER_ADDR,
      b"h3",
      &mut self.rng,
      self.now_us,
    )
    .unwrap();
    self.clients.push(NetClient {
      addr: SocketAddr::new(IpAddr::V4(ip), 50_000),
      conn,
      deaf: false,
      mute: false,
    });
    idx
  }

  /// The handle of the connection of client `client` on the server, once it is established.
  pub fn handle(&self, client: usize) -> Option<ConnHandle> {
    let ip = self.clients.get(client)?.addr.ip();
    self.app.established.iter().rev().find(|el| el.0 == ip).map(|el| el.1)
  }

  /// Runs `f` with the HTTP/3 state of the connection of the server with client `client`.
  pub fn server_state<R>(&mut self, client: usize, f: impl FnOnce(&H3ConnState) -> R) -> Option<R> {
    let handle = self.handle(client)?;
    let now_us = self.now_us;
    self.endpoint.with_conn(now_us, handle, &mut self.app, |_, cx| f(cx.state))
  }

  /// Resumes the parked request of stream `id` of client `client` on the server.
  pub fn resume(&mut self, client: usize, id: StreamId) {
    let Some(handle) = self.handle(client) else {
      return;
    };
    let now_us = self.now_us;
    enter(self.counters);
    let _rslt = H3Server::resume_in(&mut self.endpoint, &mut self.app, now_us, handle, id);
    leave(self.counters);
  }

  /// Runs `f` with the context of the connection of client `client`, as its application does
  /// outside of the callbacks.
  pub fn client_ctx<R>(&mut self, client: usize, f: impl FnOnce(&mut ConnCtx<'_, ()>) -> R) -> R {
    let now_us = self.now_us;
    self.clients[client].conn.with_ctx(now_us, |_, cx| f(cx))
  }

  /// Moves the clock forward by `us` and runs the timers that are due.
  pub fn advance(&mut self, us: u64) {
    self.now_us = self.now_us.wrapping_add(us);
    self.run_timers();
  }

  /// Moves the clock to the next timer of a client or of the worker and runs the timers that are
  /// due. Returns `false` if there is none.
  pub fn advance_to_next_event(&mut self) -> bool {
    let clients = self.clients.iter().filter_map(|el| el.conn.next_deadline());
    let Some(next) = clients.chain(self.endpoint.next_deadline()).min() else {
      return false;
    };
    self.now_us = self.now_us.max(next);
    self.run_timers();
    true
  }

  /// Flushes client `client` and returns its datagrams, which do not leave.
  pub fn client_datagrams(&mut self, client: usize) -> Vec<Vec<u8>> {
    let now_us = self.now_us;
    let mut rslt = Vec::new();
    let _ = self.clients[client].conn.flush(now_us, |el| rslt.push(el.to_vec()));
    rslt
  }

  /// Gives `datagram` of client `client` to the endpoint.
  pub fn deliver_to_server(&mut self, client: usize, datagram: &mut [u8]) {
    let peer = self.clients[client].addr;
    let meta = DatagramMeta { peer, local: None, segment_size: None };
    let now_us = self.now_us;
    enter(self.counters);
    let _ = self.endpoint.recv(now_us, datagram, meta, &mut self.app);
    leave(self.counters);
  }

  /// Flushes the endpoint and returns its datagrams with their peers, which do not leave.
  pub fn server_datagrams(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
    let now_us = self.now_us;
    enter(self.counters);
    let _ = self.endpoint.flush(now_us, &mut self.tx, &mut self.app);
    leave(self.counters);
    let mut rslt = Vec::new();
    loop {
      let next = self
        .tx
        .pending()
        .next()
        .map(|el| (el.id, el.peer, el.bytes.to_vec(), usize::from(el.segment_size.max(1))));
      let Some((id, peer, bytes, segment)) = next else {
        break;
      };
      self.tx.mark_submitted(id);
      self.tx.release(id);
      rslt.extend(bytes.chunks(segment).map(|el| (peer, el.to_vec())));
    }
    rslt
  }

  /// Gives `datagram`, from the server, to client `client`.
  pub fn deliver_to_client(&mut self, client: usize, datagram: &mut [u8]) {
    let now_us = self.now_us;
    self.clients[client].conn.recv(now_us, datagram);
  }

  /// Steps until nothing moves anymore, at most `max_steps` times.
  pub fn run_for(&mut self, max_steps: usize) {
    for _ in 0..max_steps {
      if !self.step() {
        return;
      }
    }
    panic!("the net did not settle");
  }

  /// [`Self::run_for`] with 256 steps.
  pub fn run(&mut self) {
    self.run_for(256);
  }

  /// Flushes every client and delivers what it sent, then flushes the worker and delivers what it
  /// sent. Returns `false` if nothing was sent.
  pub fn step(&mut self) -> bool {
    let now_us = self.now_us;
    let mut moved = false;
    let Self { app, clients, counters, endpoint, scratch, tx, .. } = self;
    let counters = *counters;
    for client in clients.iter_mut() {
      let (peer, mute) = (client.addr, client.mute);
      let meta = DatagramMeta { peer, local: None, segment_size: None };
      moved |= client.conn.flush(now_us, |datagram| {
        if !mute {
          enter(counters);
          let _ = endpoint.recv(now_us, datagram, meta, app);
          leave(counters);
        }
      });
    }
    enter(counters);
    let _ = endpoint.flush(now_us, tx, app);
    leave(counters);
    loop {
      let next = tx.pending().next().map(|train| {
        scratch.clear();
        scratch.extend_from_slice(train.bytes);
        (train.id, train.peer, usize::from(train.segment_size.max(1)))
      });
      let Some((id, peer, segment)) = next else {
        break;
      };
      tx.mark_submitted(id);
      tx.release(id);
      moved = true;
      // What goes to an address that no client has anymore is lost
      let Some(client) = clients.iter_mut().find(|el| el.addr == peer && !el.deaf) else {
        continue;
      };
      for datagram in scratch.chunks_mut(segment) {
        client.conn.recv(now_us, datagram);
      }
    }
    moved
  }

  /// Sends `per_client` requests from every client from index `first` on, at most `concurrent`
  /// at once on each, each with its FIN, until every response has its FIN. Returns the responses,
  /// which are dropped.
  pub fn run_requests_from(
    &mut self,
    first: usize,
    per_client: usize,
    concurrent: usize,
    request: &[u8],
  ) -> u64 {
    let clients = self.clients.len().saturating_sub(first);
    let mut opened = vec![0usize; clients];
    let mut pending: Vec<Vec<StreamId>> = vec![Vec::new(); clients];
    let total = (per_client * clients) as u64;
    let mut done = 0u64;
    let mut idle_rounds = 0;
    while done < total {
      for (idx, client) in self.clients.iter_mut().skip(first).enumerate() {
        let list = &mut pending[idx];
        let before = list.len();
        let app = client.conn.app_mut();
        list.retain(|id| match app.streams.get(&id.0) {
          Some(log) if log.fin => {
            let _ = app.streams.remove(&id.0);
            false
          }
          _ => true,
        });
        done += (before - list.len()) as u64;
        while list.len() < concurrent && opened[idx] < per_client {
          let rslt = client.conn.with_ctx(self.now_us, |_, cx| {
            let id = cx.open_bidi()?;
            cx.write(id, request, true)?;
            Ok::<_, rimu_quic::Error>(id)
          });
          match rslt {
            Ok(id) => {
              list.push(id);
              opened[idx] += 1;
            }
            Err(rimu_quic::Error::Quic(rimu_quic::QuicError::StreamsBlocked)) => break,
            Err(err) => panic!("client {idx}, request {}: {err:?}", opened[idx]),
          }
        }
      }
      if done >= total {
        break;
      }
      if self.step() {
        idle_rounds = 0;
      } else {
        idle_rounds += 1;
        assert!(idle_rounds < 64 && self.advance_to_next_event(), "{done} of {total} done");
      }
    }
    done
  }

  fn run_timers(&mut self) {
    let now_us = self.now_us;
    for client in &mut self.clients {
      client.conn.on_timeout(now_us);
    }
    enter(self.counters);
    self.endpoint.on_timeout(now_us, &mut self.app);
    leave(self.counters);
  }
}

impl<H: Handler> Drop for H3Net<H> {
  fn drop(&mut self) {
    for client in &mut self.clients {
      client.conn.abort();
    }
    self.endpoint.abort_all(&mut self.app);
  }
}

/// A server of `params` whose requests `handler` answers, with a client whose handshake is done.
pub fn connected(params: H3Params, handler: TestHandler) -> (H3Net, usize) {
  let mut net = H3Net::new(QuicParams::default(), params, handler);
  let client = net.add_client();
  net.run();
  assert!(net.clients[client].conn.is_confirmed());
  (net, client)
}

/// A frame of type `ty`.
pub fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
  let mut header = [0u8; 16];
  let len = encode_frame_header(H3FrameTy::Unknown(ty), payload.len() as u64, &mut header).unwrap();
  let mut rslt = header[..len].to_vec();
  rslt.extend_from_slice(payload);
  rslt
}

/// A HEADERS frame of `fields`, encoded with the static table.
pub fn headers_frame(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
  let mut section = Vec::new();
  encode_static(fields.iter().copied(), &mut section);
  frame(0x01, &section)
}

/// A DATA frame of `body`.
pub fn data_frame(body: &[u8]) -> Vec<u8> {
  frame(0x00, body)
}

/// A variable-length integer.
pub fn varint(value: u64) -> Vec<u8> {
  let mut buffer = [0u8; 8];
  let len = encode_varint(value, &mut buffer).unwrap();
  buffer[..len].to_vec()
}

/// The control stream of a client: its type and a SETTINGS frame of `settings`.
pub fn control_stream(settings: H3Settings) -> Vec<u8> {
  let mut out = vec![0u8; 64];
  let len = settings.encode(&mut out[1..]).unwrap();
  out.truncate(len + 1);
  out
}

/// The settings of a client that uses no dynamic table.
pub const fn client_settings() -> H3Settings {
  H3Settings { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: None }
}

impl<H: Handler> H3Net<H> {
  /// Opens a request stream of client `client` and writes `bytes` on it, with `fin`.
  pub fn send(&mut self, client: usize, bytes: &[u8], fin: bool) -> StreamId {
    self
      .client_ctx(client, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, bytes, fin)?;
        Ok::<_, rimu_quic::Error>(id)
      })
      .unwrap()
  }

  /// Opens a unidirectional stream of client `client` and writes `bytes` on it, without the FIN.
  pub fn open_uni(&mut self, client: usize, bytes: &[u8]) -> StreamId {
    self
      .client_ctx(client, |cx| {
        let id = cx.open_uni()?;
        cx.write(id, bytes, false)?;
        Ok::<_, rimu_quic::Error>(id)
      })
      .unwrap()
  }

  /// Writes `bytes` on stream `id` of client `client`, with `fin`.
  pub fn write(&mut self, client: usize, id: StreamId, bytes: &[u8], fin: bool) {
    self.client_ctx(client, |cx| cx.write(id, bytes, fin)).unwrap();
  }

  /// Resets stream `id` of client `client` with `code`.
  pub fn reset(&mut self, client: usize, id: StreamId, code: u64) {
    self.client_ctx(client, |cx| cx.reset(id, code));
  }

  /// Asks the server to stop sending on stream `id` of client `client`, with `code`.
  pub fn stop_sending(&mut self, client: usize, id: StreamId, code: u64) {
    self.client_ctx(client, |cx| cx.stop_sending(id, code));
  }

  /// The response of stream `id` as client `client` got it, if anything arrived. Sections that
  /// reference the dynamic table are decoded with the encoder stream of the server.
  pub fn response(&self, client: usize, id: StreamId) -> Option<Response> {
    response_of(self.clients[client].conn.app(), id)
  }

  /// The `:status` of the response of stream `id` of client `client`.
  pub fn status(&self, client: usize, id: StreamId) -> Option<Vec<u8>> {
    self.response(client, id).and_then(|el| el.field(b":status").map(<[u8]>::to_vec))
  }

  /// The unidirectional streams of the server as client `client` got them, by stream: their type
  /// and the bytes that follow it.
  pub fn server_streams(&self, client: usize) -> Vec<(u64, Vec<u8>)> {
    server_streams_of(self.clients[client].conn.app())
  }

  /// The frames of the control stream of the server, as client `client` got them: type and
  /// payload.
  pub fn server_control_frames(&self, client: usize) -> Vec<(u64, Vec<u8>)> {
    let streams = self.server_streams(client);
    let control = &streams.iter().find(|el| el.0 == 0).unwrap().1;
    let mut rslt = Vec::new();
    let mut rest = control.as_slice();
    while let Some((ty, len, header_len)) = decode_frame_header(rest).unwrap() {
      let len = usize::try_from(len).unwrap();
      rslt.push((ty.code(), rest[header_len..header_len + len].to_vec()));
      rest = &rest[header_len + len..];
    }
    rslt
  }

  /// The CONNECTION_CLOSE that client `client` got from the server: (application, code).
  pub fn server_close(&self, client: usize) -> Option<(bool, u64)> {
    self.clients[client].conn.peer_close()
  }

  /// The RESET_STREAM frames that client `client` got: stream and code.
  pub fn resets(&self, client: usize) -> Vec<(u64, u64)> {
    self.clients[client].conn.app().resets.iter().map(|(id, code)| (id.0, *code)).collect()
  }

  /// The STOP_SENDING frames that client `client` got: stream and code.
  pub fn stops(&self, client: usize) -> Vec<(u64, u64)> {
    self.clients[client].conn.app().stops.iter().map(|(id, code)| (id.0, *code)).collect()
  }
}

/// The unidirectional streams of the server that the application `app` of a client got.
pub fn server_streams_of(app: &ClientApp) -> Vec<(u64, Vec<u8>)> {
  app
    .streams
    .iter()
    .filter(|(id, _)| *id & 0b11 == 0b11)
    .filter_map(|(_, log)| {
      let (ty, len) = decode_varint(&log.data)?;
      Some((ty, log.data[len..].to_vec()))
    })
    .collect()
}

/// The response of stream `id` as the application `app` of a client got it, if anything arrived.
pub fn response_of(app: &ClientApp, id: StreamId) -> Option<Response> {
  let log = app.streams.get(&id.0)?;
  let mut rslt = Response { calls: log.calls.clone(), fin: log.fin, ..Response::default() };
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: 64 * 1024,
    blocked_streams: 100,
    memo_sections: 0,
    ..DecoderConfig::default()
  });
  // The encoder stream of the server, its second unidirectional stream: whatever it inserted
  if let Some((_, encoder)) = server_streams_of(app).into_iter().find(|el| el.0 == 0x02) {
    decoder.feed_encoder_stream(&encoder).ok()?;
  }
  let mut rest = log.data.as_slice();
  while let Some((ty, len, header_len)) = decode_frame_header(rest).unwrap() {
    let len = usize::try_from(len).unwrap();
    let Some(payload) = rest.get(header_len..header_len + len) else {
      break;
    };
    rslt.frames.push(ty.code());
    match ty {
      H3FrameTy::Headers => {
        let mut fields = Vec::new();
        let outcome = decoder
          .decode(id.0, payload, |field: rimu_qpack::DecodedField<'_>| {
            fields.push((field.name.to_vec(), field.value.to_vec()));
            Ok::<(), rimu_qpack::Error>(())
          })
          .unwrap();
        assert!(matches!(outcome, DecodeOutcome::Done { .. }), "a response section is blocked");
        rslt.fields = fields;
      }
      H3FrameTy::Data => rslt.body.extend_from_slice(payload),
      _ => {}
    }
    rest = &rest[header_len + len..];
  }
  Some(rslt)
}

fn enter(counters: Option<(&'static AtomicU64, &'static AtomicU64)>) {
  #[cfg(test)]
  if let Some((own, _)) = counters {
    alloc_count::count_allocations_in(own);
  }
  #[cfg(not(test))]
  let _ = counters;
}

fn leave(counters: Option<(&'static AtomicU64, &'static AtomicU64)>) {
  #[cfg(test)]
  if let Some((_, others)) = counters {
    alloc_count::count_allocations_in(others);
  }
  #[cfg(not(test))]
  let _ = counters;
}

/// Allocations made by threads that called [`count_allocations_in`], for tests that pin a path as
/// allocation-free: a counting global allocator over the system allocator.
#[cfg(test)]
#[allow(unsafe_code, reason = "the counting global allocator")]
pub(crate) mod alloc_count {
  use core::{alloc::Layout, cell::Cell, sync::atomic::AtomicU64, sync::atomic::Ordering};

  std::thread_local! {
    static COUNTING: Cell<Option<&'static AtomicU64>> = const { Cell::new(None) };
  }

  /// Counts this thread's allocations in `counter` from now on: a test with its own counter is not
  /// disturbed by the threads of the tests that run alongside.
  pub(crate) fn count_allocations_in(counter: &'static AtomicU64) {
    COUNTING.with(|el| el.set(Some(counter)));
  }

  struct CountingAlloc;

  impl CountingAlloc {
    fn count() {
      if let Some(counter) = COUNTING.try_with(Cell::get).ok().flatten() {
        let _ = counter.fetch_add(1, Ordering::Relaxed);
      }
    }
  }

  // SAFETY: every call is forwarded to the system allocator unchanged.
  unsafe impl core::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
      Self::count();
      // SAFETY: forwarded as is, with the caller's guarantees
      unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
      Self::count();
      // SAFETY: forwarded as is, with the caller's guarantees
      unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
      // SAFETY: forwarded as is, with the caller's guarantees
      unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
      Self::count();
      // SAFETY: forwarded as is, with the caller's guarantees
      unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }
  }

  #[global_allocator]
  static GLOBAL: CountingAlloc = CountingAlloc;
}
