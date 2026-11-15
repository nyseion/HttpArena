//! The encoder allocates nothing once warm: after one encode of the largest input, encoding it
//! or anything smaller again, in any format, into a vector with room, allocates nothing. Counted
//! by a global allocator; the only test in its binary, so no other test allocates meanwhile.

use rimu_gzip::{Encoder, Format, Level};
use std::{
  alloc::{GlobalAlloc, Layout, System},
  sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// The system allocator, counting allocations and reallocations while `COUNTING` is set.
struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every call is forwarded unchanged to the system allocator; counting has no effect on
// the memory handed out.
unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    if COUNTING.load(Ordering::Relaxed) {
      ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: forwarded with the caller's guarantees.
    unsafe { System.alloc(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: forwarded with the caller's guarantees.
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    if COUNTING.load(Ordering::Relaxed) {
      ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: forwarded with the caller's guarantees.
    unsafe { System.realloc(ptr, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// JSON-like text of `len` bytes.
fn json(len: usize) -> Vec<u8> {
  let mut out = Vec::with_capacity(len + 128);
  let mut i = 0u64;
  while out.len() < len {
    let line = format!(
      "{{\"id\":{i},\"name\":\"Item {i}\",\"price\":{},\"tags\":[\"t{}\",\"sale\"]}},",
      i * 7919 % 10_000,
      i % 13
    );
    out.extend_from_slice(line.as_bytes());
    i += 1;
  }
  out.truncate(len);
  out
}

#[test]
fn zero_allocations_after_warm_up() {
  let big = json(700_000);
  let sizes = [700_000, 100_000, 65_536, 20_000, 4_096, 1_000, 10, 0];
  for level in 0..=9 {
    let mut encoder = Encoder::with_level(Level::new(level).unwrap());
    let mut out = Vec::new();
    for format in [Format::Raw, Format::Zlib, Format::Gzip] {
      out.clear();
      encoder.encode(format, &big, &mut out);
    }
    for &size in &sizes {
      for format in [Format::Raw, Format::Zlib, Format::Gzip] {
        out.clear();
        ALLOCATIONS.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
        encoder.encode(format, &big[..size], &mut out);
        COUNTING.store(false, Ordering::Relaxed);
        let n = ALLOCATIONS.load(Ordering::Relaxed);
        assert_eq!(n, 0, "level {level} {format:?} {size} bytes: {n} allocations");
        assert!(!out.is_empty());
      }
    }
  }
}
