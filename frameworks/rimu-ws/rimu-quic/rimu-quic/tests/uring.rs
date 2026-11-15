//! The `uring` driver over real sockets: an echo server of one and of four workers (CID steering,
//! placement and forwarding between workers), its graceful shutdown, and its counters. The client
//! is the test client of the `client` feature, driven over a standard UDP socket.

mod common;

use common::{Client, free_addr, start};
use rimu_quic::{
  QuicLimits,
  uring::{Pinning, ServerParams, Stats},
};
use std::time::Duration;

#[test]
fn one_worker_echoes_and_shuts_down() {
  let addr = free_addr();
  let mut params = ServerParams::new(addr);
  params.workers = Some(1);
  params.pin = Pinning::None;
  let server = start(params);
  let mut client = Client::connect(addr);
  for round in 0..32u32 {
    let msg = format!("hello {round}");
    assert_eq!(client.echo(msg.as_bytes()), msg.as_bytes());
  }
  // The worker stores its counters at the end of the turn that answered
  std::thread::sleep(Duration::from_millis(50));
  let stats = server.stats.workers();
  assert_eq!(stats.len(), 1);
  assert_eq!(stats[0].endpoint.conns, 1);
  assert!(stats[0].trains_out > 0 && stats[0].endpoint.datagrams_in > 0);
  assert_eq!(stats[0].app.streams, 32);
  // The shutdown closes the connection with the code of the limits, and the server returns
  server.shutdown.trigger();
  let code = client.wait_close(Duration::from_secs(5));
  assert_eq!(code, Some((true, QuicLimits::default().shutdown_app_code)));
  server.join(Duration::from_secs(10));
}

#[test]
fn four_workers_steer_place_and_forward() {
  let addr = free_addr();
  let mut params = ServerParams::new(addr);
  params.workers = Some(4);
  params.pin = Pinning::None;
  let server = start(params);
  let mut clients: Vec<Client> = (0..24).map(|_| Client::connect(addr)).collect();
  for (idx, client) in clients.iter_mut().enumerate() {
    for round in 0..4 {
      let msg = format!("client {idx} round {round}");
      assert_eq!(client.echo(msg.as_bytes()), msg.as_bytes());
    }
  }
  std::thread::sleep(Duration::from_millis(50));
  let stats = server.stats.workers();
  let conns: Vec<u32> = stats.iter().map(|el| el.endpoint.conns).collect();
  assert_eq!(conns.iter().sum::<u32>(), 24, "{conns:?}");
  // New connections go to the least-loaded worker: every worker has some
  assert!(conns.iter().all(|el| *el >= 3), "{conns:?}");
  assert!(stats.iter().all(|el| el.cid_steering));
  // First Initial packets that the kernel steered elsewhere were handed over
  let forwarded: u64 = stats.iter().map(|el| el.endpoint.forwarded).sum();
  let forwarded_in: u64 = stats.iter().map(|el| el.forwarded_in).sum();
  assert!(forwarded > 0 && forwarded_in >= forwarded, "{forwarded} {forwarded_in}");
  assert_eq!(stats.iter().map(|el| el.forward_dropped).sum::<u64>(), 0);
  assert_eq!(stats.iter().map(|el| el.app.streams).sum::<u64>(), 24 * 4);
  let line = Stats::line(&stats);
  assert!(line.contains(" datagrams_in=") && line.contains(" streams=96"), "{line}");
  server.shutdown.trigger();
  for client in &mut clients {
    assert!(client.wait_close(Duration::from_secs(5)).is_some());
  }
  server.join(Duration::from_secs(10));
}

// A shutdown ends promptly when the client of a connection vanished: the connection is closed at
// once (the echo application does not drain), its closing period ends, and the worker returns.
#[test]
fn shutdown_with_a_vanished_client_ends() {
  let addr = free_addr();
  let mut params = ServerParams::new(addr);
  params.workers = Some(1);
  params.pin = Pinning::None;
  params.drain = Duration::from_millis(200);
  params.linger = Duration::from_millis(300);
  let server = start(params);
  let mut client = Client::connect(addr);
  assert_eq!(client.echo(b"x"), b"x");
  // The client hears nothing more and says nothing more
  drop(client);
  let started = std::time::Instant::now();
  server.shutdown.trigger();
  server.join(Duration::from_secs(10));
  assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

// With generic receive offload the kernel may hand a worker coalesced datagrams, which the
// endpoint splits into their segments; large bodies both ways, on four workers.
#[test]
fn gro_large_echoes_on_four_workers() {
  let addr = free_addr();
  let mut params = ServerParams::new(addr);
  params.workers = Some(4);
  params.pin = Pinning::None;
  params.udp = params.udp.gro(true).recv_buffers(32, 65_536);
  let server = start(params);
  let mut clients: Vec<Client> = (0..4).map(|_| Client::connect(addr)).collect();
  let body: Vec<u8> = (0..300_000u32).map(|el| u8::try_from(el % 251).unwrap()).collect();
  for client in &mut clients {
    assert_eq!(client.echo(&body), body);
  }
  std::thread::sleep(Duration::from_millis(50));
  let stats = server.stats.workers();
  assert_eq!(stats.iter().map(|el| el.endpoint.conns).sum::<u32>(), 4);
  assert_eq!(stats.iter().map(|el| el.datagrams_truncated).sum::<u64>(), 0);
  server.shutdown.trigger();
  for client in &mut clients {
    assert!(client.wait_close(Duration::from_secs(5)).is_some());
  }
  server.join(Duration::from_secs(10));
}
