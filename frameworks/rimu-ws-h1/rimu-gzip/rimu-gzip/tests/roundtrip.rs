//! Round trips of every format and level through three independent decoders: miniz_oxide,
//! libdeflate (C, through libdeflater) and zlib-rs (through flate2).
//!
//! Inputs: random bytes, repetitive and synthetic text, and, when present, the benchmark corpus
//! (the directory in `RIMU_GZIP_CORPUS`, else `/mnt/nvme1tb/claude-tmp/codec-bench/corpus`), each
//! cut to sizes around the encoder's boundaries (powers of two, the 64 KiB stored-block limit,
//! the 32 KiB window) up to 1 MiB.

use rimu_gzip::{Encoder, Format, Level};
use std::io::Read;

/// The sizes every input is cut to (those it reaches).
const SIZES: &[usize] = &[
  0,
  1,
  2,
  3,
  4,
  5,
  255,
  256,
  1_024,
  4_096,
  9_999,
  10_000,
  32_767,
  32_768,
  32_769,
  65_533,
  65_534,
  65_535,
  65_536,
  65_537,
  100_000,
  300_000,
  305_001,
  1 << 20,
];

/// A small xorshift generator: the tests are deterministic.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }

  fn below(&mut self, n: usize) -> usize {
    (self.next() % n.max(1) as u64) as usize
  }
}

/// Text from a small vocabulary, a little like prose or logs.
fn words(rng: &mut Rng, len: usize) -> Vec<u8> {
  const WORDS: [&str; 16] = [
    "the ",
    "encoder ",
    "matches ",
    "input ",
    "where ",
    "it ",
    "lies, ",
    "with ",
    "state ",
    "sized ",
    "to ",
    "block ",
    "2026-11-13T16:00:00Z ",
    "INFO ",
    "GET /api/items ",
    "\n",
  ];
  let mut out = Vec::with_capacity(len + 32);
  while out.len() < len {
    out.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
    if rng.below(8) == 0 {
      out.extend_from_slice(rng.next().to_string().as_bytes());
    }
  }
  out.truncate(len);
  out
}

/// The named inputs, each at least 1 MiB long where it can be.
fn inputs() -> Vec<(String, Vec<u8>)> {
  let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
  let mut list: Vec<(String, Vec<u8>)> = vec![
    ("random".into(), (0..1 << 20).map(|_| rng.next() as u8).collect()),
    ("zeros".into(), vec![0; 1 << 20]),
    ("ab".into(), b"ab".repeat(1 << 19)),
    ("words".into(), words(&mut rng, 1 << 20)),
  ];
  // Random 1 KiB pieces repeated at random distances, some beyond the window
  let pieces: Vec<Vec<u8>> =
    (0..64).map(|_| (0..1_024).map(|_| rng.next() as u8).collect()).collect();
  let mut repeats = Vec::new();
  while repeats.len() < 1 << 20 {
    repeats.extend_from_slice(&pieces[rng.below(pieces.len())]);
  }
  list.push(("repeats".into(), repeats));
  // Text, random bytes and text again: blocks split
  let mut mixed = words(&mut rng, 200_000);
  mixed.extend((0..100_000).map(|_| rng.next() as u8));
  mixed.extend_from_slice(&words(&mut rng, 200_000));
  list.push(("mixed".into(), mixed));
  let dir = std::env::var("RIMU_GZIP_CORPUS")
    .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/codec-bench/corpus".into());
  if let Ok(entries) = std::fs::read_dir(&dir) {
    let mut files: Vec<_> = entries.map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    files.sort();
    let mut all = Vec::new();
    for path in files {
      let data = std::fs::read(&path).unwrap();
      all.extend_from_slice(&data);
      list.push((path.file_name().unwrap().to_string_lossy().into_owned(), data));
    }
    // Every file in one: 1 MiB and more, with changes of content for the block splitter
    list.push(("corpus-concatenated".into(), all));
  } else {
    eprintln!("corpus not found at {dir}: synthetic inputs only");
  }
  list
}

/// Inflates `out` (in `format`) with every decoder and checks each gives `input`.
#[track_caller]
fn check_all_decoders(format: Format, input: &[u8], out: &[u8], what: &str) {
  assert!(out.len() <= format.bound(input.len()), "{what}: {} > bound", out.len());
  // miniz_oxide
  let miniz = match format {
    Format::Raw => miniz_oxide::inflate::decompress_to_vec(out),
    Format::Zlib => miniz_oxide::inflate::decompress_to_vec_zlib(out),
    Format::Gzip => miniz_oxide::inflate::decompress_to_vec(&out[10..out.len() - 8]),
  }
  .unwrap_or_else(|e| panic!("{what}: miniz_oxide: {e:?}"));
  assert!(miniz == input, "{what}: miniz_oxide inflates to something else");
  // libdeflate
  let mut back = vec![0u8; input.len()];
  let mut d = libdeflater::Decompressor::new();
  let n = match format {
    Format::Raw => d.deflate_decompress(out, &mut back),
    Format::Zlib => d.zlib_decompress(out, &mut back),
    Format::Gzip => d.gzip_decompress(out, &mut back),
  }
  .unwrap_or_else(|e| panic!("{what}: libdeflate: {e:?}"));
  assert!(n == input.len() && back == input, "{what}: libdeflate inflates to something else");
  // zlib-rs, through flate2, which also checks the zlib and gzip trailers
  let mut flate = Vec::with_capacity(input.len());
  match format {
    Format::Raw => flate2::read::DeflateDecoder::new(out).read_to_end(&mut flate),
    Format::Zlib => flate2::read::ZlibDecoder::new(out).read_to_end(&mut flate),
    Format::Gzip => flate2::read::GzDecoder::new(out).read_to_end(&mut flate),
  }
  .unwrap_or_else(|e| panic!("{what}: flate2: {e}"));
  assert!(flate == input, "{what}: flate2 inflates to something else");
}

/// Every level, every format, every input at every size, through every decoder; one encoder per
/// level is reused across all of them.
#[test]
fn every_level_format_and_size_round_trips() {
  let inputs = inputs();
  for level in 0..=9 {
    let mut encoder = Encoder::with_level(Level::new(level).unwrap());
    let mut out = Vec::new();
    for (name, data) in &inputs {
      let mut sizes: Vec<usize> = SIZES.iter().copied().filter(|&s| s <= data.len()).collect();
      sizes.push(data.len());
      sizes.dedup();
      for size in sizes {
        let input = &data[..size];
        for format in [Format::Raw, Format::Zlib, Format::Gzip] {
          out.clear();
          encoder.encode(format, input, &mut out);
          check_all_decoders(
            format,
            input,
            &out,
            &format!("level {level} {format:?} {name} {size}"),
          );
        }
      }
    }
  }
}

/// The output does not depend on what the encoder encoded before, nor on what `out` held.
#[test]
fn output_is_independent_of_history() {
  let inputs = inputs();
  for level in [1, 3, 6, 9] {
    let level = Level::new(level).unwrap();
    for (name, data) in inputs.iter().take(6) {
      let input = &data[..data.len().min(150_000)];
      let mut fresh = Vec::new();
      Encoder::with_level(level).gzip(input, &mut fresh);
      let mut used = Encoder::with_level(level);
      let mut out = b"prefix".to_vec();
      used.gzip(&inputs[0].1, &mut Vec::new());
      used.gzip(input, &mut out);
      assert_eq!(&out[..6], b"prefix");
      assert!(out[6..] == fresh[..], "level {level:?} {name}: output depends on history");
    }
  }
}
