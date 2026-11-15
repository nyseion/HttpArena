//! Writers of encoder instructions and field line representations (RFC 9204 section 4), with
//! every choice explicit, for tests and the model checker.

use crate::{huffman, prefix_int::push_prefix_int};
use alloc::vec::Vec;

/// A prefixed integer.
pub fn int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
  push_prefix_int(out, value, prefix_bits, flags);
}

/// A string literal with a prefix of `prefix_bits` bits: the Huffman bit is the highest of them,
/// the length takes the others. Huffman coded if `huffman`, even when that is longer.
pub fn string(out: &mut Vec<u8>, bytes: &[u8], prefix_bits: u8, flags: u8, huffman: bool) {
  let h_bit = 1u8 << (prefix_bits - 1);
  if huffman {
    let mut coded = Vec::new();
    huffman::encode(bytes, &mut coded);
    int(out, coded.len() as u64, prefix_bits - 1, flags | h_bit);
    out.extend_from_slice(&coded);
  } else {
    int(out, bytes.len() as u64, prefix_bits - 1, flags);
    out.extend_from_slice(bytes);
  }
}

/// Set Dynamic Table Capacity.
pub fn set_capacity(out: &mut Vec<u8>, capacity: u64) {
  int(out, capacity, 5, 0b0010_0000);
}

/// Insert with Name Reference, static or relative to the last insert.
pub fn insert_name_ref(out: &mut Vec<u8>, is_static: bool, idx: u64, value: &[u8], huffman: bool) {
  int(out, idx, 6, if is_static { 0b1100_0000 } else { 0b1000_0000 });
  string(out, value, 8, 0, huffman);
}

/// Insert with Literal Name.
pub fn insert_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8], huffman: bool) {
  string(out, name, 6, 0b0100_0000, huffman);
  string(out, value, 8, 0, huffman);
}

/// Duplicate, relative to the last insert.
pub fn duplicate(out: &mut Vec<u8>, relative: u64) {
  int(out, relative, 5, 0);
}

/// The prefix of a field section (RFC 9204 section 4.5.1) for a table of `max_entries`.
pub fn prefix(out: &mut Vec<u8>, ric: u64, base: u64, max_entries: u64) {
  let encoded = if ric == 0 { 0 } else { ric % (2 * max_entries) + 1 };
  int(out, encoded, 8, 0);
  if base >= ric {
    int(out, base - ric, 7, 0);
  } else {
    int(out, ric - base - 1, 7, 0b1000_0000);
  }
}

/// Indexed Field Line, static or relative to the Base.
pub fn indexed(out: &mut Vec<u8>, is_static: bool, idx: u64) {
  int(out, idx, 6, if is_static { 0b1100_0000 } else { 0b1000_0000 });
}

/// Indexed Field Line with Post-Base Index.
pub fn indexed_post_base(out: &mut Vec<u8>, idx: u64) {
  int(out, idx, 4, 0b0001_0000);
}

/// Literal Field Line with Name Reference, static or relative to the Base.
pub fn name_ref(
  out: &mut Vec<u8>,
  is_static: bool,
  never_indexed: bool,
  idx: u64,
  value: &[u8],
  huffman: bool,
) {
  let flags = 0b0100_0000 | if never_indexed { 0b0010_0000 } else { 0 };
  int(out, idx, 4, flags | if is_static { 0b0001_0000 } else { 0 });
  string(out, value, 8, 0, huffman);
}

/// Literal Field Line with Post-Base Name Reference.
pub fn post_base_name_ref(
  out: &mut Vec<u8>,
  never_indexed: bool,
  idx: u64,
  value: &[u8],
  huffman: bool,
) {
  int(out, idx, 3, if never_indexed { 0b0000_1000 } else { 0 });
  string(out, value, 8, 0, huffman);
}

/// Literal Field Line with Literal Name.
pub fn literal(out: &mut Vec<u8>, never_indexed: bool, name: &[u8], value: &[u8], huffman: bool) {
  string(out, name, 4, 0b0010_0000 | if never_indexed { 0b0001_0000 } else { 0 }, huffman);
  string(out, value, 8, 0, huffman);
}

/// Section Acknowledgment.
pub fn section_ack(out: &mut Vec<u8>, stream: u64) {
  int(out, stream, 7, 0b1000_0000);
}

/// Stream Cancellation.
pub fn stream_cancel(out: &mut Vec<u8>, stream: u64) {
  int(out, stream, 6, 0b0100_0000);
}

/// Insert Count Increment.
pub fn insert_count_increment(out: &mut Vec<u8>, increment: u64) {
  int(out, increment, 6, 0);
}

/// Bytes of a hexadecimal string, spaces ignored.
pub fn hex(text: &str) -> Vec<u8> {
  let digits: Vec<u8> = text.bytes().filter(|el| !el.is_ascii_whitespace()).collect();
  digits
    .chunks(2)
    .map(|pair| {
      let text = core::str::from_utf8(pair).unwrap();
      u8::from_str_radix(text, 16).unwrap()
    })
    .collect()
}
