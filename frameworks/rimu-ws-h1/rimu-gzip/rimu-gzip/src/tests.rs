//! Unit tests of the internals; round trips through other decoders are in `tests/`.

use crate::{
  Encoder, Format, Level, Params, Strategy,
  bits::BitWriter,
  block::BlockType,
  check::check_output,
  huffman::{Scratch, code_lengths},
  tokens::{LEN_XBITS, MAX_MATCH, pack, seq_len},
};
use alloc::vec::Vec;

/// A small xorshift generator: the tests are deterministic.
pub(crate) struct Rng(u64);

impl Rng {
  pub(crate) fn new(seed: u64) -> Self {
    Self(seed | 1)
  }

  pub(crate) fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }

  pub(crate) fn below(&mut self, n: usize) -> usize {
    usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
  }

  pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
    (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
  }
}

/// A JSON array of `items` objects shaped like the HttpArena dataset items.
pub(crate) fn dataset_json(rng: &mut Rng, items: usize) -> Vec<u8> {
  const CATEGORIES: [&str; 6] = ["electronics", "books", "garden", "toys", "sports", "food"];
  const TAGS: [&str; 8] =
    ["new", "sale", "popular", "eco", "premium", "limited", "gift", "classic"];
  let mut out = Vec::from(&b"{\"items\":["[..]);
  for id in 0..items {
    let price = rng.below(10_000);
    let quantity = rng.below(50) + 1;
    let item = alloc::format!(
      "{{\"id\":{id},\"name\":\"Item {id}\",\"category\":\"{}\",\"price\":{price},\"quantity\":{quantity},\
       \"active\":{},\"tags\":[\"{}\",\"{}\"],\"rating\":{{\"score\":{},\"count\":{}}},\"total\":{}}}",
      CATEGORIES[rng.below(CATEGORIES.len())],
      rng.below(2) == 0,
      TAGS[rng.below(TAGS.len())],
      TAGS[rng.below(TAGS.len())],
      rng.below(5) + 1,
      rng.below(1_000),
      price * quantity * 4,
    );
    out.extend_from_slice(item.as_bytes());
    out.push(if id + 1 == items { b']' } else { b',' });
  }
  out.extend_from_slice(alloc::format!(",\"count\":{items}}}").as_bytes());
  out
}

/// Encodes `input` in every format and checks each output; returns the gzip member.
#[track_caller]
fn round_trip(encoder: &mut Encoder, input: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  for format in [Format::Raw, Format::Zlib, Format::Gzip] {
    out.clear();
    encoder.encode(format, input, &mut out);
    check_output(format, input, &out);
  }
  out
}

/// Every level.
fn levels() -> impl Iterator<Item = Level> {
  (0..=9).map(|level| Level::new(level).unwrap())
}

#[test]
fn empty_and_one_byte_inputs_round_trip() {
  for level in levels() {
    let mut encoder = Encoder::with_level(level);
    let _ = round_trip(&mut encoder, b"");
    let _ = round_trip(&mut encoder, b"x");
  }
}

#[test]
fn encode_appends() {
  let mut out = b"abc".to_vec();
  Encoder::new().gzip(b"hello hello hello", &mut out);
  assert_eq!(&out[..3], b"abc");
  check_output(Format::Gzip, b"hello hello hello", &out[3..]);
}

#[test]
fn matches_shrink_json() {
  let mut rng = Rng::new(3);
  let input = dataset_json(&mut rng, 50);
  for level in levels().skip(1) {
    let out = round_trip(&mut Encoder::with_level(level), &input);
    assert!(out.len() * 4 <= input.len(), "{level:?}: {} of {} bytes", out.len(), input.len());
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn skip_acceleration_stays_close_to_the_unaccelerated() {
  // Eight-kilobyte stretches of noise between repeated four-hundred-byte ones: heavy on misses
  // past the first window, where the acceleration applies.
  let mut rng = Rng::new(21);
  let mut input = Vec::new();
  for _ in 0..40 {
    input.extend_from_slice(&rng.bytes(8_000));
    let chunk = rng.bytes(400);
    for _ in 0..6 {
      input.extend_from_slice(&chunk);
    }
  }
  for (strategy, depth, accel) in
    [(Strategy::Fast, 1u16, 12u16), (Strategy::Greedy, 4, 4), (Strategy::LazyOnce, 6, 2)]
  {
    let plain = Params {
      strategy,
      search_depth: depth,
      nice_match: 32,
      good_match: 8,
      max_insert: 258,
      skip_accel: 0,
      len3: true,
      split_blocks: false,
    };
    let quick = Params { skip_accel: accel, ..plain };
    let plain = round_trip(&mut Encoder::with_params(plain), &input).len();
    let quick = round_trip(&mut Encoder::with_params(quick), &input).len();
    assert!(quick * 20 <= plain * 21, "{strategy:?}: {quick} of {plain} bytes");
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn long_runs_encode_in_linear_time() {
  for level in levels().skip(1) {
    let mut encoder = Encoder::with_level(level);
    let _ = round_trip(&mut encoder, &alloc::vec![b'a'; 200_000]);
    let _ = round_trip(&mut encoder, &b"ab".repeat(100_000));
    // The fastest of several encodes, so that a test running beside this one does not decide it
    let fastest = |len: usize, encoder: &mut Encoder| {
      let input = b"ab".repeat(len / 2);
      let mut out = Vec::new();
      (0..5)
        .map(|_| {
          out.clear();
          let begin = std::time::Instant::now();
          encoder.gzip(&input, &mut out);
          begin.elapsed()
        })
        .min()
        .unwrap_or_default()
    };
    let small = fastest(100_000, &mut encoder);
    let large = fastest(2_000_000, &mut encoder);
    // 20 times the input: linear work takes about 20 times as long, quadratic about 400 times
    assert!(large <= small * 60, "{level:?}: {small:?} vs {large:?}");
  }
}

#[test]
fn reuse_across_sizes_has_no_stale_matches() {
  let mut rng = Rng::new(5);
  let big = dataset_json(&mut rng, 600);
  let mid = dataset_json(&mut rng, 25);
  for level in levels() {
    let mut encoder = Encoder::with_level(level);
    let _ = round_trip(&mut encoder, &big);
    let _ = round_trip(&mut encoder, b"tiny input");
    let _ = round_trip(&mut encoder, &mid);
    let _ = round_trip(&mut encoder, &big);
  }
}

#[test]
fn lengths_are_limited_and_complete() {
  let mut scratch = Scratch::new();
  let mut fib = [0u32; 40];
  fib[0] = 1;
  fib[1] = 1;
  for i in 2..fib.len() {
    fib[i] = fib[i - 1].saturating_add(fib[i - 2]);
  }
  let cases: [(&[u32], u8); 6] = [
    (&[5; 30], 15),
    (&fib[..30], 15),
    (&fib[..19], 7),
    (&[0, 0, 9, 0], 15),
    (&[3, 0, 7, 0, 0], 15),
    (&[0, 1, 0, 1000, 1, 0, 0, 2, 1, 1], 7),
  ];
  for (freq, max) in cases {
    let mut lengths = [0u8; 40];
    let _ = code_lengths(freq, max, &mut lengths[..freq.len()], &mut scratch);
    let used: Vec<u8> =
      freq.iter().zip(&lengths).filter(|(f, _)| **f > 0).map(|(_, l)| *l).collect();
    assert!(used.iter().all(|&l| l >= 1 && l <= max), "{freq:?}: {lengths:?}");
    assert!(
      freq.iter().zip(&lengths).all(|(f, l)| (*f == 0) == (*l == 0)),
      "{freq:?}: {lengths:?}"
    );
    if used.len() == 1 {
      assert_eq!(used[0], 1);
    } else {
      let kraft: u64 = used.iter().map(|&l| 1u64 << (15 - u32::from(l))).sum();
      assert_eq!(kraft, 1 << 15, "{freq:?}: {lengths:?}");
    }
  }
}

#[test]
fn seq_len_round_trips_every_packed_length() {
  let mut len = 3;
  for (ls, &xb) in LEN_XBITS.iter().enumerate() {
    for _ in 0..(1 << xb) {
      if len > MAX_MATCH {
        break;
      }
      assert_eq!(seq_len(pack(0, len, ls, 1, 0)), len, "length {len} (symbol {ls})");
      len += 1;
    }
  }
  assert_eq!(len, MAX_MATCH + 1, "every length 3..=258 was covered");
}

#[test]
fn local_flush_writes_bits_lsb_first() {
  let mut out = Vec::new();
  let mut writer = BitWriter::new(&mut out, 8);
  let mut state = writer.local();
  state.put_unflushed(0x65, 8);
  state.put_unflushed(0b10, 2);
  state.flush();
  state.put_unflushed(0x1234, 16);
  state.flush();
  writer.restore(state);
  // The last flush leaves 2 bits, which `finish` pads into a zero byte.
  assert_eq!(writer.finish().as_slice(), &[0x65, 0xd2, 0x48, 0x00]);
}

#[test]
fn block_type_is_the_cheapest() {
  let mut rng = Rng::new(9);
  let mut encoder = Encoder::new();
  let _ = round_trip(&mut encoder, &dataset_json(&mut rng, 25));
  assert_eq!(encoder.last_block_types(), [BlockType::Dynamic]);
  let _ = round_trip(&mut encoder, b"a short text, twenty");
  assert_eq!(encoder.last_block_types(), [BlockType::Fixed]);
  let _ = round_trip(&mut encoder, &rng.bytes(4_000));
  assert_eq!(encoder.last_block_types(), [BlockType::Stored]);
}

#[test]
fn blocks_split_where_the_data_changes() {
  let mut rng = Rng::new(11);
  // JSON, then random bytes, then JSON again: at least three blocks
  let mut input = dataset_json(&mut rng, 200);
  input.extend_from_slice(&rng.bytes(40_000));
  input.extend_from_slice(&dataset_json(&mut rng, 200));
  for level in levels().skip(2) {
    let params = Params { split_blocks: true, ..Params::of_level(level) };
    let mut encoder = Encoder::with_params(params);
    let _ = round_trip(&mut encoder, &input);
    let types = encoder.last_block_types();
    assert!(types.len() >= 3, "{level:?}: {types:?}");
    let mut unsplit = Encoder::with_params(Params { split_blocks: false, ..encoder.params() });
    let whole = round_trip(&mut unsplit, &input);
    let split = round_trip(&mut encoder, &input);
    assert!(split.len() < whole.len(), "{level:?}: {} vs {}", split.len(), whole.len());
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn len3_gating_stays_close_to_the_full_table() {
  // The lazy parsers match from three bytes via a second hash table; without it they match
  // from four, which must still round-trip and cost little on text-like data.
  let mut rng = Rng::new(33);
  // A permutation header pushes the block past 80 distinct literals, where three-byte matches
  // are taken at all; without it the minimum length is already four and the table is unused.
  let mut input: Vec<_> = (0..=255u8).collect();
  for i in (1..input.len()).rev() {
    input.swap(i, rng.below(i + 1));
  }
  input.extend_from_slice(&dataset_json(&mut rng, 400));
  let plain = Params {
    strategy: Strategy::Lazy,
    search_depth: 35,
    nice_match: 65,
    good_match: 258,
    max_insert: 258,
    skip_accel: 0,
    len3: true,
    split_blocks: false,
  };
  let gated = Params { len3: false, ..plain };
  let plain = round_trip(&mut Encoder::with_params(plain), &input).len();
  let gated = round_trip(&mut Encoder::with_params(gated), &input).len();
  assert!(gated * 10 <= plain * 11, "{gated} of {plain} bytes");
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn matches_cross_block_boundaries() {
  // 290 KB of random bytes, then 20 KB of other random bytes twice: blocks end by 300 KB, so the
  // second copy is matched only if matches reach back into the previous block
  let mut rng = Rng::new(12);
  let unique = rng.bytes(20_000);
  let mut input = rng.bytes(290_000);
  input.extend_from_slice(&unique);
  input.extend_from_slice(&unique);
  for level in levels().skip(1) {
    let out = round_trip(&mut Encoder::with_level(level), &input);
    assert!(out.len() < input.len() - 15_000, "{level:?}: {} of {}", out.len(), input.len());
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn random_input_stays_within_bound() {
  let mut rng = Rng::new(8);
  for level in levels() {
    let mut encoder = Encoder::with_level(level);
    for _ in 0..8 {
      let len = rng.below(400_000) + 1;
      let input = rng.bytes(len);
      let out = round_trip(&mut encoder, &input);
      assert!(out.len() >= len, "{len}: {}", out.len());
    }
  }
}

#[cfg_attr(miri, ignore = "slow under Miri; covered natively")]
#[test]
fn check_bytes_accepts_a_seed_corpus() {
  use crate::check::check_bytes;
  let mut rng = Rng::new(10);
  for _ in 0..300 {
    let len = rng.below(12_000);
    check_bytes(&rng.bytes(len));
  }
  for strategy in 0..6u8 {
    for items in [1, 25, 50, 400] {
      let mut data = alloc::vec![4, 0, 32, 0, 8, 0, 4, strategy | 8];
      data.extend_from_slice(&dataset_json(&mut rng, items));
      check_bytes(&data);
    }
  }
  check_bytes(&[]);
  check_bytes(&[0xff; 9]);
}

#[test]
fn strategies_parse_as_documented() {
  // The default is the tuned small-body set of rimu-ws
  let default = Params::default();
  assert_eq!(default.strategy, Strategy::LazyOnce);
  assert_eq!(
    (default.search_depth, default.nice_match, default.good_match, default.max_insert),
    (6, 64, 8, 2)
  );
  assert!(!default.split_blocks);
}

/// Structured random input: runs, random bytes, text and copies from up to 40,000 bytes back.
fn structured(rng: &mut Rng, len: usize) -> Vec<u8> {
  let mut out = Vec::with_capacity(len + 300);
  while out.len() < len {
    match rng.below(5) {
      0 => out.extend(core::iter::repeat_n(rng.next() as u8, rng.below(300) + 1)),
      1 => {
        let n = rng.below(200) + 1;
        out.extend(rng.bytes(n));
      }
      2 => {
        let items = rng.below(3) + 1;
        out.extend_from_slice(&dataset_json(rng, items));
      }
      _ if out.len() > 4 => {
        let back = rng.below(out.len().min(40_000)) + 1;
        let start = out.len() - back;
        for i in 0..rng.below(300) + 3 {
          out.push(out[start + i]);
        }
      }
      _ => out.push(b'x'),
    }
  }
  out.truncate(len);
  out
}

/// A long seeded randomized round trip: random parameters (every strategy, format and knob,
/// through the fuzz target's seed decoding), random structured inputs of up to 200 KB, each
/// output checked by miniz_oxide and libdeflate. `RIMU_GZIP_RANDOM_ITERS` sets the iterations
/// (default 400); `RIMU_GZIP_RANDOM_SEED` the seed.
#[cfg_attr(miri, ignore = "long")]
#[test]
fn seeded_random_round_trips() {
  let env = |name: &str, default: u64| {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
  };
  let mut rng = Rng::new(env("RIMU_GZIP_RANDOM_SEED", 0x5eed));
  let mut decompressor = libdeflater::Decompressor::new();
  let mut out = Vec::new();
  for _ in 0..env("RIMU_GZIP_RANDOM_ITERS", 400) {
    let seed = rng.next().to_le_bytes();
    let (params, format, _) = crate::check::params_of(seed);
    let mut encoder = Encoder::with_params(params);
    for _ in 0..3 {
      let len = match rng.below(4) {
        0 => rng.below(100),
        1 => rng.below(5_000),
        2 => rng.below(70_000),
        _ => rng.below(200_000),
      };
      let input = structured(&mut rng, len);
      out.clear();
      encoder.encode(format, &input, &mut out);
      check_output(format, &input, &out);
      let mut back = alloc::vec![0u8; input.len()];
      let n = match format {
        Format::Raw => decompressor.deflate_decompress(&out, &mut back),
        Format::Zlib => decompressor.zlib_decompress(&out, &mut back),
        Format::Gzip => decompressor.gzip_decompress(&out, &mut back),
      }
      .unwrap_or_else(|e| panic!("{params:?} {format:?} {len}: libdeflate: {e:?}"));
      assert!(n == input.len() && back == input, "{params:?} {format:?} {len}");
    }
  }
}
