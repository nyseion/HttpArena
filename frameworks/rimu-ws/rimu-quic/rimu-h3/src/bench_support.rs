//! Micro-benchmarks of crate-private paths for `bench/` (feature `__bench`, not a public API): the
//! decode of the head of a request (QPACK, the checks of RFC 9114 and the head buffer, with or
//! without rimu-qpack's decode memo) and the encode of the head of its response with the frames
//! that carry it, as a request takes them in [`crate::H3Server`], without the transport.

use crate::{
  conn_state::Budget,
  frame::{H3FrameTy, encode_frame_header},
  request::RequestHead,
  response::{DateLine, ResponseFields, ResponseHeads},
};
use alloc::vec::Vec;
use core::hint::black_box;
use rimu_qpack::{
  DecodedField, Decoder, DecoderConfig, Encoder, EncoderConfig, Field, InsertPolicy, Settings,
  encode_static,
};
use std::time::Instant;

/// The field section of a `GET` of `path` from a browser-like client: the pseudo-header fields
/// and `extra`, encoded with the static table.
#[must_use]
pub fn request_section(path: &[u8], extra: &[(&[u8], &[u8])]) -> Vec<u8> {
  let mut fields: Vec<(&[u8], &[u8])> = alloc::vec![
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", path)
  ];
  fields.extend_from_slice(extra);
  let mut out = Vec::new();
  encode_static(fields, &mut out);
  out
}

/// The head of a request: `section` decoded into the head buffer and checked, `iterations` times.
/// Returns ns per request.
#[must_use]
pub fn decode_request(section: &[u8], memo: bool, iterations: u64) -> f64 {
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: 0,
    blocked_streams: 0,
    memo_sections: if memo { 8 } else { 0 },
    ..DecoderConfig::default()
  });
  let mut head = RequestHead::new();
  let mut budget = Budget::new(1 << 20);
  let start = Instant::now();
  for _ in 0..iterations {
    head.clear();
    let outcome = decoder.decode(0, black_box(section), |field: DecodedField<'_>| {
      head.push(field.name, field.value, field.static_ref, 16_384, &mut budget)
    });
    assert!(outcome.is_ok() && head.check().is_ok());
    let _ = black_box(head.path());
  }
  per(start, iterations)
}

/// What [`encode_response`] puts in the head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Head {
  /// `:status` and `content-type`, kept encoded (the default).
  Lean,
  /// With `date` and `content-length` (RFC 9110).
  Rfc9110,
  /// `:status`, `content-type` and `server`, by rimu-qpack's encoder with a dynamic table that the
  /// peer acknowledged.
  Dynamic,
}

/// The HEADERS and DATA frames of a `200` response of `body`, put together as the server writes
/// them, `iterations` times. Returns ns per response.
#[must_use]
pub fn encode_response(head: Head, body: &[u8], iterations: u64) -> f64 {
  let mut heads = ResponseHeads::new();
  let mut date = DateLine::new();
  date.set(1_794_571_200);
  let mut encoder = Encoder::new(EncoderConfig {
    max_table_capacity: 4096,
    insert_policy: InsertPolicy::Always,
    ..EncoderConfig::default()
  });
  let _ = encoder.set_peer_settings(Settings { max_table_capacity: 4096, blocked_streams: 100 });
  let mut section = Vec::new();
  let mut frame = Vec::new();
  let fields = ResponseFields::with_type(200, b"text/plain");
  let start = Instant::now();
  for _ in 0..iterations {
    let encoded: &[u8] = match head {
      Head::Lean => heads.encode(black_box(&fields), None, None),
      Head::Rfc9110 => heads.encode(black_box(&fields), Some(body.len()), Some(date.line())),
      Head::Dynamic => {
        section.clear();
        let lines = [
          Field::new(b":status", b"200"),
          Field::new(b"content-type", b"text/plain"),
          Field::new(b"server", b"rimu"),
        ];
        encoder.encode(0, lines, &mut section);
        encoder.consume_encoder_stream(usize::MAX);
        // The peer acknowledges at once (a Section Acknowledgment of stream 0): the entries stay
        // referable, nothing piles up
        if encoder.unacknowledged_sections() > 0 {
          let _ = encoder.feed_decoder_stream(&[0x80]);
        }
        &section
      }
    };
    frame.clear();
    push_header(&mut frame, H3FrameTy::Headers, encoded.len());
    frame.extend_from_slice(encoded);
    push_header(&mut frame, H3FrameTy::Data, body.len());
    frame.extend_from_slice(body);
    let _ = black_box(frame.len());
  }
  per(start, iterations)
}

/// A request's head decoded and checked, and its response put together: [`decode_request`] and
/// [`encode_response`] in one loop. Returns ns per request.
#[must_use]
pub fn request_response(section: &[u8], memo: bool, head: Head, iterations: u64) -> f64 {
  // The two halves share no state: their sum, measured apart, is the cost of a request
  decode_request(section, memo, iterations) + encode_response(head, b"hello", iterations)
}

fn push_header(out: &mut Vec<u8>, ty: H3FrameTy, len: usize) {
  let mut header = [0u8; 16];
  let len = encode_frame_header(ty, len as u64, &mut header).unwrap_or(0);
  out.extend_from_slice(header.get(..len).unwrap_or_default());
}

fn per(start: Instant, iterations: u64) -> f64 {
  start.elapsed().as_nanos() as f64 / iterations.max(1) as f64
}
