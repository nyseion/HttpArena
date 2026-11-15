//! A QUIC echo server on a standard UDP socket: every stream that a client opens gets its own
//! bytes back. One worker, no GSO or GRO: the endpoint is driven by `recv_from`/`send_to`.
//!
//! `cargo run --example echo_server -- 127.0.0.1:4433 cert.pem key.pem` (ALPN `echo`)

use rimu_quic::{
  ConnCtx, DatagramMeta, Endpoint, EndpointKeys, QuicApp, QuicParams, StreamId, TxArena,
  rng::ChaCha20, rustls::RustlsConfig,
};
use std::{net::UdpSocket, sync::Arc, time::Instant};

#[derive(Default)]
struct Echo;

impl QuicApp for Echo {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut args = std::env::args().skip(1);
  let addr = args.next().unwrap_or_else(|| "127.0.0.1:4433".into());
  let cert = std::fs::read(args.next().ok_or("certificate PEM path")?)?;
  let key = std::fs::read(args.next().ok_or("private key PEM path")?)?;
  let tls =
    RustlsConfig::builder().alpn(&[b"echo"]).cert_chain_pem(&cert).private_key_pem(&key).build()?;

  let mut rng = ChaCha20::from_os()?;
  let keys = Arc::new(EndpointKeys::new(&mut rng));
  let mut endpoint =
    Endpoint::<Echo>::new(QuicParams::default(), 0, 1, Arc::new(tls), &mut rng, None, keys)?;
  let mut app = Echo;
  let mut tx = TxArena::new(TxArena::DEFAULT_BYTES)?;

  let socket = UdpSocket::bind(&addr)?;
  let start = Instant::now();
  let now_us = || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
  let mut buf = vec![0u8; 65_535];
  loop {
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
    // Send what the connections wrote: trains of datagrams of `segment_size` bytes each
    loop {
      let full = endpoint.flush(now_us(), &mut tx, &mut app) == rimu_quic::FlushOutcome::ArenaFull;
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
