//! Allocation tests of the `uring` driver, after a warm-up, on the threads of the workers only (a
//! counting global allocator, turned on from inside the turns of the workers while a measurement
//! runs, as rimu-uring's `tests/alloc.rs` does): echo round trips of established connections
//! allocate nothing, on one worker and on two (their inboxes polled at every turn).

mod common;

use common::{Client, free_addr, start_with};
use rimu_quic::uring::{Pinning, ServerParams};
use std::{
  alloc::{GlobalAlloc, Layout, System},
  cell::Cell,
  sync::atomic::{AtomicBool, AtomicU64, Ordering},
  time::Duration,
};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static MEASURE: AtomicBool = AtomicBool::new(false);

std::thread_local! {
  static COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn count() {
  if COUNTING.try_with(Cell::get).unwrap_or(false) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
  }
}

// SAFETY: forwards to `System`, counting on the side
unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    count();
    // SAFETY: the caller's guarantees, passed on
    unsafe { System.alloc(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: the caller's guarantees, passed on
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    count();
    // SAFETY: the caller's guarantees, passed on
    unsafe { System.realloc(ptr, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// At each turn, a worker counts its allocations while a measurement runs.
fn follow() {
  let _ = COUNTING.try_with(|el| el.set(MEASURE.load(Ordering::Relaxed)));
}

// `rounds` echo round trips on each of `clients` connections to a server of `workers` workers,
// after as many to warm up: the allocations of the workers during the second half.
fn steady_state(workers: u8, clients: usize, rounds: usize) -> u64 {
  let addr = free_addr();
  let mut params = ServerParams::new(addr);
  params.workers = Some(workers);
  params.pin = Pinning::None;
  let server = start_with(params, Some(follow));
  let mut conns: Vec<Client> = (0..clients).map(|_| Client::connect(addr)).collect();
  let msg = [7u8; 900];
  let run = |conns: &mut Vec<Client>| {
    for _ in 0..rounds {
      for client in conns.iter_mut() {
        assert_eq!(client.echo(&msg), msg);
      }
    }
  };
  run(&mut conns);
  // A turn or two for every worker to see the flag
  MEASURE.store(true, Ordering::Relaxed);
  std::thread::sleep(Duration::from_millis(20));
  let before = ALLOCS.load(Ordering::Relaxed);
  run(&mut conns);
  let allocations = ALLOCS.load(Ordering::Relaxed) - before;
  // The counter sees the workers: a handshake allocates (rustls, the connection's first use of
  // its pools)
  let before = ALLOCS.load(Ordering::Relaxed);
  conns.push(Client::connect(addr));
  assert!(ALLOCS.load(Ordering::Relaxed) > before, "a handshake was not counted");
  MEASURE.store(false, Ordering::Relaxed);
  server.shutdown.trigger();
  for client in &mut conns {
    let _ = client.wait_close(Duration::from_secs(5));
  }
  server.join(Duration::from_secs(10));
  allocations
}

// One test, so that the measurements never overlap
#[test]
fn echo_round_trips_allocate_nothing_after_warmup() {
  let one = steady_state(1, 4, 256);
  assert_eq!(one, 0, "one worker: {one} allocations for 1024 round trips");
  let two = steady_state(2, 8, 128);
  assert_eq!(two, 0, "two workers: {two} allocations for 1024 round trips");
}
