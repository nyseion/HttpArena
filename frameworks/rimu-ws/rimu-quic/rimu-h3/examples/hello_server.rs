//! An HTTP/3 server on a standard UDP socket: every request gets `hello` back, and a POST its own
//! body. One worker, no GSO or GRO: the endpoint is driven by `recv_from`/`send_to`, as
//! rimu-quic's `echo_server` example.
//!
//! `cargo run -p rimu-h3 --example hello_server -- 127.0.0.1:4433 cert.pem key.pem`, then for
//! instance `curl --http3-only -k https://127.0.0.1:4433/`.

use rimu_h3::{Body, H3Params, H3Server, Handler, ReqCtx, ReqOutcome, Request, ResponseFields};
use rimu_quic::{
  DatagramMeta, Endpoint, EndpointKeys, FlushOutcome, QuicParams, TxArena, rng::ChaCha20,
  rustls::RustlsConfig,
};
use std::{net::UdpSocket, sync::Arc, time::Instant};

struct Hello;

impl Handler for Hello {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> rimu_h3::Result<ReqOutcome> {
    let body = if req.method == b"POST" { req.body } else { b"hello\n" };
    cx.respond_with(&ResponseFields::with_type(200, b"text/plain"), Body::Bytes(body))?;
    Ok(ReqOutcome::Responded)
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut args = std::env::args().skip(1);
  let addr = args.next().unwrap_or_else(|| "127.0.0.1:4433".into());
  let cert = std::fs::read(args.next().ok_or("certificate PEM path")?)?;
  let key = std::fs::read(args.next().ok_or("private key PEM path")?)?;
  let tls =
    RustlsConfig::builder().alpn(&[b"h3"]).cert_chain_pem(&cert).private_key_pem(&key).build()?;

  let mut rng = ChaCha20::from_os()?;
  let keys = Arc::new(EndpointKeys::new(&mut rng));
  let mut endpoint = Endpoint::<H3Server<Hello>>::new(
    QuicParams::default(),
    0,
    1,
    Arc::new(tls),
    &mut rng,
    None,
    keys,
  )?;
  // RFC 9110's `date` and `content-length` on top of `:status` and `content-type`
  let mut app = H3Server::new(Hello, H3Params::default().rfc9110_headers(true));
  let mut tx = TxArena::new(TxArena::DEFAULT_BYTES)?;

  let socket = UdpSocket::bind(&addr)?;
  let start = Instant::now();
  let now_us = || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
  let mut buf = vec![0u8; 65_535];
  loop {
    app.refresh_date();
    // Wait for a datagram or the next timer of the endpoint
    let timeout = endpoint.next_deadline().map(|at| at.saturating_sub(now_us()).max(1));
    socket.set_read_timeout(timeout.map(std::time::Duration::from_micros))?;
    match socket.recv_from(&mut buf) {
      Ok((len, peer)) => {
        let meta = DatagramMeta { peer, local: None, segment_size: None };
        // One worker: nothing is ever forwarded
        let _outcome = endpoint.recv(now_us(), &mut buf[..len], meta, &mut app);
      }
      Err(err)
        if matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
      Err(err) => return Err(err.into()),
    }
    endpoint.on_timeout(now_us(), &mut app);
    // Send what the connections wrote, responses with the acknowledgments of their requests
    loop {
      let full = endpoint.flush(now_us(), &mut tx, &mut app) == FlushOutcome::ArenaFull;
      let mut sent = Vec::new();
      for train in tx.pending() {
        for datagram in train.bytes.chunks(usize::from(train.segment_size.max(1))) {
          let _ = socket.send_to(datagram, train.peer);
        }
        sent.push(train.id);
      }
      for id in sent {
        tx.mark_submitted(id);
        tx.release(id);
      }
      if !full {
        break;
      }
    }
  }
}
