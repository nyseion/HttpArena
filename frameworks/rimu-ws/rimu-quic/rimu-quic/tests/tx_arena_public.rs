//! The send arena driven from outside the crate, as an I/O layer of its own does: datagrams
//! written with `begin`/`commit`, trains handed out by `pending`, and `max_trains` to size the
//! layer's view of the trains it submitted.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use rimu_quic::TxArena;

#[test]
fn datagrams_written_from_outside_join_one_train() {
  let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
  let mut tx = TxArena::new(64 * 1500).unwrap();
  assert!(tx.max_trains() >= 64);
  for byte in [1u8, 2] {
    let buffer = tx.begin(peer, None, 1200).unwrap();
    buffer.get_mut(..1200).unwrap().fill(byte);
    tx.commit(1200);
  }
  let trains: Vec<_> = tx.pending().map(|el| (el.id, el.bytes.to_vec(), el.segment_size)).collect();
  assert_eq!(trains.len(), 1);
  let (id, bytes, segment_size) = trains.into_iter().next().unwrap();
  assert_eq!(segment_size, 1200);
  assert_eq!(bytes.len(), 2400);
  assert!(bytes[..1200].iter().all(|el| *el == 1) && bytes[1200..].iter().all(|el| *el == 2));
  tx.mark_submitted(id);
  assert_eq!(tx.pending().count(), 0);
  tx.release(id);
  // Every byte is free again
  assert!(tx.begin(peer, None, 64 * 1500 / 2).is_some());
}

#[test]
fn a_full_arena_has_no_room() {
  let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
  let mut tx = TxArena::new(4000).unwrap();
  let _ = tx.begin(peer, None, 4000).unwrap();
  tx.commit(4000);
  assert!(tx.begin(peer, None, 1).is_none());
}
