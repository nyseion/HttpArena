//! Field sections that reference the static table only: no encoder stream, no blocking, no
//! acknowledgments, and the same bytes on every connection.
//!
//! This is what a server wants for responses when it does not want the peer's decoder to block or
//! to track anything: the bytes can be encoded once per route (a pre-encoded response head) and
//! copied into each response, with only the changing lines encoded per response.
//!
//! ```
//! use rimu_qpack::{encode_static, encode_static_line, encode_static_prefix};
//!
//! // Once, at startup: the head that every response of a route shares
//! let mut head = Vec::new();
//! encode_static([(":status", "200"), ("content-type", "text/plain")], &mut head);
//!
//! // Per response: the head, then the lines that change
//! let mut section = head.clone();
//! encode_static_line(b"content-length", b"1234", &mut section);
//! # let mut decoder = rimu_qpack::Decoder::new(Default::default());
//! # let mut fields = rimu_qpack::FieldList::new();
//! # decoder.decode_into(0, &section, &mut fields).unwrap();
//! # assert_eq!(fields.len(), 3);
//! ```

use crate::{
  huffman,
  prefix_int::{encode_prefix_int, push_prefix_int},
  static_table::{find_exact_from, find_name_hashed, name_hash},
};
use alloc::vec::Vec;

/// Appends to `out` the field section of `fields`, in their order, with the static table only.
///
/// The section has a Required Insert Count of 0 and a Base of 0 (RFC 9204 section 4.5.1). A field
/// whose name and value are in the static table is an Indexed Field Line; one whose name only is
/// there a literal with a static name reference; any other a literal with a literal name.
/// Literals are written raw, without Huffman coding: see [`crate::Encoder`] for Huffman.
pub fn encode_static<'a, I, F>(fields: I, out: &mut Vec<u8>)
where
  I: IntoIterator<Item = F>,
  F: Into<crate::Field<'a>>,
{
  encode_static_prefix(out);
  for field in fields {
    let field = field.into();
    encode_static_field(field.name, field.value, field.sensitive, false, out);
  }
}

/// Appends to `out` the prefix of a field section that references no entry of the dynamic table:
/// a Required Insert Count of 0 and a Base of 0, which lines of [`encode_static_line`] follow.
#[inline]
pub fn encode_static_prefix(out: &mut Vec<u8>) {
  out.extend_from_slice(&[0, 0]);
}

/// Appends to `out` the field line of `name` and `value` as [`encode_static`] encodes each field.
/// `name` must be lowercase (RFC 9114 section 4.2).
#[inline]
pub fn encode_static_line(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
  encode_static_field(name, value, false, false, out);
}

/// One field line with static references only; `sensitive` sets the never-indexed bit, `huffman`
/// codes literals when that is shorter.
pub(crate) fn encode_static_field(
  name: &[u8],
  value: &[u8],
  sensitive: bool,
  huffman: bool,
  out: &mut Vec<u8>,
) {
  let n_bit = if sensitive { 0b0010_0000 } else { 0 };
  match find_name_hashed(name, name_hash(name)) {
    Some(first) => match find_exact_from(first, value) {
      // Indexed Field Line, T = 1 (RFC 9204 section 4.5.2): a sensitive field is still sent by
      // index when the static table has it, which reveals nothing
      Some(idx) => push_prefix_int(out, idx.into(), 6, 0b1100_0000),
      None => {
        // Literal Field Line with Name Reference, T = 1 (section 4.5.4)
        push_prefix_int(out, first.into(), 4, 0b0101_0000 | n_bit);
        push_string(out, value, 8, 0, huffman);
      }
    },
    None => {
      // Literal Field Line with Literal Name (section 4.5.6)
      push_string(out, name, 4, 0b0010_0000 | (n_bit >> 1), huffman);
      push_string(out, value, 8, 0, huffman);
    }
  }
}

/// Appends a string literal with a prefix of `prefix_bits` bits whose highest one is the Huffman
/// bit (RFC 9204 section 4.1.2); Huffman coded if `huffman` and that is shorter.
///
/// The string is Huffman coded into `out` past a placeholder header; if the coding is not
/// shorter, both are truncated away and the raw bytes are appended. One pass over the bytes:
/// `encoded_len` first would walk them twice.
#[inline]
pub(crate) fn push_string(
  out: &mut Vec<u8>,
  bytes: &[u8],
  prefix_bits: u8,
  flags: u8,
  huffman: bool,
) {
  let h_bit = 1u8 << (prefix_bits - 1);
  if huffman && !bytes.is_empty() {
    let header = out.len();
    // A placeholder header of the raw length: the longest that a kept coding needs, because a
    // coding is kept only when it is shorter than the raw bytes, and a shorter length never
    // needs a longer prefixed integer
    push_prefix_int(out, bytes.len() as u64, prefix_bits - 1, flags | h_bit);
    let header_len = out.len() - header;
    let coded_len = huffman::encode(bytes, out);
    if coded_len < bytes.len() {
      let mut buffer = [0u8; 10];
      // The header of the coded length: never longer than the placeholder's
      let len = encode_prefix_int(coded_len as u64, prefix_bits - 1, flags | h_bit, &mut buffer)
        .unwrap_or(10);
      debug_assert!(len <= header_len);
      out.copy_within(header + header_len.., header + len);
      out.truncate(out.len() - (header_len - len));
      out[header..header + len].copy_from_slice(&buffer[..len]);
      return;
    }
    out.truncate(header);
  }
  push_prefix_int(out, bytes.len() as u64, prefix_bits - 1, flags);
  out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
  use super::push_string;
  use crate::huffman_code;
  use crate::prefix_int::encode_prefix_int;
  use crate::{DecodeOutcome, Decoder, DecoderConfig, FieldList, encode_static};
  use alloc::{vec, vec::Vec};

  // The huffman path of push_string rewrites a placeholder header in place: the raw length and
  // the coded length must both come out right around the boundary where one needs a longer
  // prefixed integer than the other
  #[test]
  fn push_string_matches_the_independent_encoding() {
    let mut state = 0x5851_f42d_4c95_7f2du64;
    let mut next = move || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    // Ten five-bit symbols: 50 bits coded into 7 bytes, raw 10 needs a two-byte header with a
    // 3-bit prefix while 7 needs one
    let mut cases: Vec<Vec<u8>> = vec![
      b"".to_vec(),
      b"a".to_vec(),
      b"01245789ab".to_vec(),
      b"01245789ab01245789ab".to_vec(),
      b"www.example.com".to_vec(),
      vec![b'x'; 200],
    ];
    for _ in 0..64 {
      let len = (next() % 300) as usize;
      let bytes: Vec<u8> = (0..len).map(|_| (next() % 96 + 32) as u8).collect();
      cases.push(bytes);
    }
    for bytes in &cases {
      for prefix_bits in [4u8, 6, 7, 8] {
        for huffman in [false, true] {
          let mut out = b"before".to_vec();
          push_string(&mut out, bytes, prefix_bits, 0, huffman);
          let mut expected = b"before".to_vec();
          let coded_len = huffman_code::encoded_len(bytes);
          let coded = huffman && !bytes.is_empty() && coded_len < bytes.len();
          let len = if coded { coded_len } else { bytes.len() };
          let h_bit = if coded { 1u8 << (prefix_bits - 1) } else { 0 };
          let mut buffer = [0u8; 10];
          let header = encode_prefix_int(len as u64, prefix_bits - 1, h_bit, &mut buffer).unwrap();
          expected.extend_from_slice(&buffer[..header]);
          if coded {
            huffman_code::encode(bytes, &mut expected);
          } else {
            expected.extend_from_slice(bytes);
          }
          assert_eq!(out, expected, "{bytes:?} {prefix_bits} {huffman}");
        }
      }
    }
  }

  #[test]
  fn encode_static_round_trips_through_decoder() {
    let long = [b'x'; 200];
    let fields: [(&[u8], &[u8]); 10] = [
      // Exact static entries
      (b":status", b"200"),
      (b"content-type", b"text/plain;charset=utf-8"),
      (b"content-encoding", b"br"),
      (b"vary", b"accept-encoding"),
      // An exact entry above the 6-bit prefix (71)
      (b":status", b"500"),
      // Static names with other values, below and above the 4-bit prefix (4 and 92)
      (b"content-length", b"13"),
      (b"server", b"rimu"),
      // A name that is not in the table, with an empty value and with a value of 200 bytes
      (b"x-custom", b""),
      (b"x-custom-long-name", &long),
      (b"date", b"Mon, 09 Nov 2026 08:00:00 GMT"),
    ];
    let mut out = b"before".to_vec();
    encode_static(fields, &mut out);
    // Appended after what was there; RIC 0 and Base 0, then the field lines
    let section = &out[6..];
    assert_eq!(&out[..6], b"before");
    assert_eq!(&section[..7], &[0x00, 0x00, 0xd9, 0xf6, 0xea, 0xfb, 0xff]);
    // 0xff 0x08: 71 = 63 + 8 in a 6-bit prefix; then `content-length: 13` as 0x54 0x02 "13"
    assert_eq!(&section[7..12], &[0x08, 0x54, 0x02, b'1', b'3']);
    // `server: rimu`: 92 = 15 + 77 in a 4-bit prefix, raw value
    assert_eq!(&section[12..19], &[0x5f, 0x4d, 0x04, b'r', b'i', b'm', b'u']);
    // `x-custom` with a literal name: 0x27 is 001, N=0, H=0 and 7 filling the 3-bit prefix; 8 = 7 + 1
    assert_eq!(&section[19..21], &[0x27, 0x01]);

    let mut decoder = Decoder::new(DecoderConfig { max_table_capacity: 0, ..Default::default() });
    let mut decoded = FieldList::new();
    let outcome = decoder.decode_into(0, section, &mut decoded).unwrap();
    assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
    let expected: Vec<_> = fields.iter().map(|(n, v)| crate::Field::new(n, v)).collect();
    assert_eq!(decoded.to_vec(), expected);
    // Nothing to acknowledge
    assert_eq!(decoder.decoder_stream_output(), b"");
  }
}
