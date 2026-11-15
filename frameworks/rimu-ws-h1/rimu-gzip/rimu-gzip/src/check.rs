//! The encoder over arbitrary bytes, for the fuzz target `round_trip` and its seed tests: the
//! first eight bytes choose the parameters, the format and how the rest splits into one to three
//! inputs, which one encoder encodes in turn. Every output must inflate (with miniz_oxide) to its
//! input, stay within its bound and carry the right framing and checksums.

use crate::{Encoder, Format, Params, Strategy, checksum};
use alloc::vec::Vec;

/// The parameters, format and part count `seed` selects.
pub fn params_of(seed: [u8; 8]) -> (Params, Format, usize) {
  let field = |i: usize| u16::from_le_bytes([seed[i], seed[i + 1]]);
  let strategy = match seed[7] % 6 {
    0 => Strategy::Stored,
    1 => Strategy::Fast,
    2 => Strategy::Greedy,
    3 => Strategy::LazyOnce,
    4 => Strategy::Lazy,
    _ => Strategy::Lazy2,
  };
  let params = Params {
    strategy,
    search_depth: field(0) % 1024 + 1,
    nice_match: field(2) % 258 + 1,
    good_match: field(4) % 258 + 1,
    max_insert: u16::from(seed[6]) % 258 + 1,
    skip_accel: field(4) >> 8 & 0xf,
    len3: seed[6] & 0x80 == 0,
    split_blocks: seed[7] & 0x40 == 0,
  };
  let format = match (seed[7] >> 3) % 3 {
    0 => Format::Raw,
    1 => Format::Zlib,
    _ => Format::Gzip,
  };
  let parts = usize::from(seed[7] >> 7) + usize::from(seed[6] & 1) + 1;
  (params, format, parts)
}

/// See the module documentation. Panics on a broken output.
pub fn check_bytes(data: &[u8]) {
  let (head, rest) = data.split_at(data.len().min(8));
  let mut seed = [0u8; 8];
  seed[..head.len()].copy_from_slice(head);
  let (params, format, parts) = params_of(seed);
  let mut encoder = Encoder::with_params(params);
  let mut out = Vec::new();
  let mut start = 0;
  for part in 0..parts {
    let end = if part + 1 == parts { rest.len() } else { start + (rest.len() - start) / 2 };
    let input = &rest[start..end];
    start = end;
    out.clear();
    encoder.encode(format, input, &mut out);
    check_output(format, input, &out);
  }
}

/// Panics unless `out` is a valid `format` stream of `input` within its bound.
#[track_caller]
pub fn check_output(format: Format, input: &[u8], out: &[u8]) {
  assert!(out.len() <= format.bound(input.len()), "{} > bound of {}", out.len(), input.len());
  let raw = match format {
    Format::Raw => out,
    Format::Zlib => {
      assert_eq!(out[0], 0x78, "zlib CMF");
      assert_eq!(u16::from_be_bytes([out[0], out[1]]) % 31, 0, "zlib FCHECK");
      let n = out.len();
      assert_eq!(out[n - 4..], checksum::adler32(input).to_be_bytes(), "Adler-32");
      &out[2..n - 4]
    }
    Format::Gzip => {
      assert_eq!(out[..4], [0x1f, 0x8b, 8, 0], "gzip header");
      let n = out.len();
      assert_eq!(out[n - 8..n - 4], checksum::crc32(input).to_le_bytes(), "CRC-32");
      assert_eq!(out[n - 4..], (input.len() as u32).to_le_bytes(), "ISIZE");
      &out[10..n - 8]
    }
  };
  let inflated = miniz_oxide::inflate::decompress_to_vec_with_limit(raw, input.len())
    .expect("miniz_oxide inflates the stream");
  assert!(inflated == input, "the stream inflates to something else");
}
