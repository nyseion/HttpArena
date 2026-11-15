//! After a warm-up, a connection's encoder and decoder allocate nothing: inserts, evictions,
//! Duplicates, blocked and unblocked sections, memo replays, acknowledgments and cancellations all
//! reuse the storage that they have.

use rimu_qpack::{
  DecodeOutcome, Decoder, DecoderConfig, Encoder, EncoderConfig, Field, FieldList, InsertPolicy,
};
use std::{
  alloc::{GlobalAlloc, Layout, System},
  cell::Cell,
  fmt::Write,
};

thread_local! {
  static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator with the same arguments; the counter is
// a const-initialized thread local, which does not allocate.
unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    ALLOCATIONS.with(|el| el.set(el.get() + 1));
    // SAFETY: the caller's contract for `alloc` is passed on unchanged.
    unsafe { System.alloc(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: `ptr` was allocated by `System` with `layout`, as `alloc` and `realloc` forward.
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    ALLOCATIONS.with(|el| el.set(el.get() + 1));
    // SAFETY: the caller's contract for `realloc` is passed on unchanged.
    unsafe { System.realloc(ptr, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> u64 {
  ALLOCATIONS.with(Cell::get)
}

struct Connection {
  encoder: Encoder,
  decoder: Decoder,
  section: Vec<u8>,
  wire: Vec<u8>,
  fields: FieldList,
  blocked: u64,
}

impl Connection {
  fn new(capacity: u32, policy: InsertPolicy) -> Self {
    let decoder =
      Decoder::new(DecoderConfig { max_table_capacity: capacity, ..DecoderConfig::default() });
    let mut encoder =
      Encoder::new(EncoderConfig { insert_policy: policy, ..EncoderConfig::default() });
    encoder.set_peer_settings(decoder.settings()).unwrap();
    Self {
      encoder,
      decoder,
      section: Vec::with_capacity(4096),
      wire: Vec::with_capacity(4096),
      fields: FieldList::new(),
      blocked: 0,
    }
  }

  // One exchange; every third one the encoder stream arrives after the section
  fn exchange(&mut self, stream: u64, request: &[Field<'_>], late: bool) {
    self.section.clear();
    self.encoder.encode(stream, request, &mut self.section);
    self.wire.clear();
    self.encoder.drain_encoder_stream(&mut self.wire);
    let mut fed = !late;
    if fed {
      self.decoder.feed_encoder_stream(&self.wire).unwrap();
    }
    if let DecodeOutcome::Blocked { .. } =
      self.decoder.decode_into(stream, &self.section, &mut self.fields).unwrap()
    {
      self.blocked += 1;
      self.decoder.feed_encoder_stream(&self.wire).unwrap();
      fed = true;
      assert_eq!(self.decoder.take_unblocked().next(), Some(stream));
      let outcome = self.decoder.decode_into(stream, &self.section, &mut self.fields).unwrap();
      assert!(matches!(outcome, DecodeOutcome::Done { .. }));
    }
    if !fed {
      self.decoder.feed_encoder_stream(&self.wire).unwrap();
    }
    assert_eq!(self.fields.len(), request.len());
    // A cancelled stream now and then
    if stream % 40 == 36 {
      self.decoder.cancel_stream(stream + 2).unwrap();
    }
    self.wire.clear();
    self.decoder.drain_decoder_stream(&mut self.wire);
    self.encoder.feed_decoder_stream(&self.wire).unwrap();
  }
}

#[test]
fn steady_state_allocates_nothing() {
  const WARM_UP: u64 = 2_000;
  const COUNTED: u64 = 2_000;
  // Field values for every round, built before counting
  let rounds: Vec<(String, String, String)> = (0..WARM_UP + COUNTED)
    .map(|round| {
      let mut path = String::new();
      write!(path, "/items/{}?page={}", round % 37, round % 5).unwrap();
      let trace = format!("{round:016x}");
      let etag = format!("\"{:08x}\"", round % 23);
      (path, trace, etag)
    })
    .collect();
  let mut small = Connection::new(512, InsertPolicy::Always);
  let mut large = Connection::new(4096, InsertPolicy::Repeated);
  // A load generator that repeats one request byte for byte: the memo replays it
  let mut repeat = Connection::new(4096, InsertPolicy::Repeated);
  let mut run = |round: u64| {
    let (path, trace, etag) = &rounds[round as usize];
    let request = [
      Field::new(b":method", b"GET"),
      Field::new(b":scheme", b"https"),
      Field::new(b":authority", b"www.example.com"),
      Field::new(b":path", path.as_bytes()),
      Field::new(
        b"user-agent",
        b"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
      ),
      Field::new(b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
      Field::new(b"accept-encoding", b"gzip, deflate, br"),
      Field::new(b"cookie", b"session=0123456789abcdef; theme=dark"),
      Field::new(b"if-none-match", etag.as_bytes()),
      Field::new(b"x-trace-id", trace.as_bytes()),
    ];
    small.exchange(round * 4, &request, round.is_multiple_of(3));
    large.exchange(round * 4, &request, round % 3 == 1);
    let fixed = [request[0], request[1], request[2], request[4], request[5], request[6]];
    repeat.exchange(round * 4, &fixed, false);
  };
  for round in 0..WARM_UP {
    run(round);
  }
  let before = allocations();
  for round in WARM_UP..WARM_UP + COUNTED {
    run(round);
  }
  let counted = allocations() - before;
  assert_eq!(counted, 0, "allocations in {COUNTED} rounds");
  // The rounds did what they are meant to
  for (name, conn) in [("small", &small), ("large", &large)] {
    let encoder = conn.encoder.stats();
    let decoder = conn.decoder.stats();
    assert!(encoder.inserts > 1_000, "{name}: {encoder:?}");
    assert!(encoder.dynamic_sections > 3_000, "{name}: {encoder:?}");
    assert!(conn.blocked > 100, "{name}: {}", conn.blocked);
    assert!(decoder.sections >= 4_000, "{name}: {decoder:?}");
    if name == "small" {
      assert!(encoder.evictions > 1_000 && encoder.duplicates > 0, "{name}: {encoder:?}");
    }
  }
  assert!(repeat.decoder.stats().memo_hits > 3_000, "{:?}", repeat.decoder.stats());
}
