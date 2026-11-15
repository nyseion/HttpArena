use super::{DecodeOutcome, Decoder, DecoderConfig, decode_required_insert_count};
use crate::{
  DecodedField, Error, ErrorCode, ErrorKind, StaticRef,
  wire::{self, hex},
};
use alloc::{vec, vec::Vec};

type Fields = Vec<(Vec<u8>, Vec<u8>)>;

// RFC 9204 Appendix B, in order
const B2_ENCODER: &str = "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468";
const B2_STREAM_4: &str = "03811011";
const B3_ENCODER: &str = "4a637573746f6d2d6b65790c637573746f6d2d76616c7565";
const B4_ENCODER: &str = "02";
const B4_STREAM_8: &str = "050080c181";
const B5_ENCODER: &str = "810d637573746f6d2d76616c756532";

const DONE_DYNAMIC: DecodeOutcome = DecodeOutcome::Done { referenced_dynamic: true };
const DONE_STATIC: DecodeOutcome = DecodeOutcome::Done { referenced_dynamic: false };

fn new(capacity: u32, blocked: u16) -> Decoder {
  Decoder::new(DecoderConfig {
    max_table_capacity: capacity,
    blocked_streams: blocked,
    memo_sections: 0,
    ..DecoderConfig::default()
  })
}

fn with_memo(capacity: u32, blocked: u16, memo: usize) -> Decoder {
  Decoder::new(DecoderConfig {
    max_table_capacity: capacity,
    blocked_streams: blocked,
    memo_sections: memo,
    ..DecoderConfig::default()
  })
}

fn decode(
  decoder: &mut Decoder,
  stream: u64,
  section: &[u8],
) -> Result<(DecodeOutcome, Fields), Error> {
  let mut fields = Vec::new();
  let outcome = decoder.decode(stream, section, |field: DecodedField<'_>| {
    fields.push((field.name.to_vec(), field.value.to_vec()));
    Ok::<_, Error>(())
  })?;
  Ok((outcome, fields))
}

fn fails<T: core::fmt::Debug>(rslt: Result<T, Error>, code: ErrorCode, kind: ErrorKind) -> bool {
  match rslt {
    Err(err) => err.code() == Some(code) && err.kind() == kind,
    Ok(elem) => panic!("expected {code:?} {kind:?}, got {elem:?}"),
  }
}

fn failed(rslt: Result<(DecodeOutcome, Fields), Error>, kind: ErrorKind) -> bool {
  fails(rslt, ErrorCode::DecompressionFailed, kind)
}

fn refused(rslt: Result<(), Error>, kind: ErrorKind) -> bool {
  fails(rslt, ErrorCode::EncoderStreamError, kind)
}

fn output(decoder: &mut Decoder) -> Vec<u8> {
  let mut out = Vec::new();
  decoder.drain_decoder_stream(&mut out);
  out
}

fn pairs(list: &[(&str, &str)]) -> Fields {
  list.iter().map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec())).collect()
}

fn after_b2() -> Decoder {
  let mut decoder = new(220, 2);
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  assert_eq!(decode(&mut decoder, 4, &hex(B2_STREAM_4)).unwrap().0, DONE_DYNAMIC);
  assert_eq!(output(&mut decoder), [0x84]);
  decoder
}

fn after_b3() -> Decoder {
  let mut decoder = after_b2();
  decoder.feed_encoder_stream(&hex(B3_ENCODER)).unwrap();
  assert_eq!(output(&mut decoder), [0x01]);
  decoder
}

fn after_b4() -> Decoder {
  let mut decoder = after_b3();
  decoder.feed_encoder_stream(&hex(B4_ENCODER)).unwrap();
  assert_eq!(output(&mut decoder), [0x01]);
  decoder
}

#[test]
fn rfc9204_appendix_b1_literal_with_name_reference() {
  let mut decoder = new(220, 0);
  let section = hex("0000510b2f696e6465782e68746d6c");
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap(),
    (DONE_STATIC, pairs(&[(":path", "/index.html")]))
  );
  // Required Insert Count 0: nothing to acknowledge
  assert_eq!(decoder.decoder_stream_output(), b"");
}

#[test]
fn rfc9204_appendix_b2_dynamic_table_and_section_ack() {
  let mut decoder = new(220, 2);
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  assert_eq!(decoder.insert_count(), 2);
  assert_eq!(decoder.size, 106);
  assert_eq!(decoder.capacity, 220);
  // Until a section acknowledges them, the inserts wait for an Insert Count Increment
  assert_eq!(decoder.decoder_stream_output(), [0x02]);
  let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
  assert_eq!(decode(&mut decoder, 4, &hex(B2_STREAM_4)).unwrap(), (DONE_DYNAMIC, expected));
  // The Section Acknowledgment covers them: it replaces the increment (RFC 9204 2.1.4, 4.4.3)
  assert_eq!(output(&mut decoder), [0x84]);
  assert_eq!(decoder.known_received, 2);
  assert_eq!(decoder.decoder_stream_output(), b"");
}

#[test]
fn rfc9204_appendix_b3_speculative_insert() {
  let mut decoder = after_b2();
  // An instruction that is not whole waits for the rest of it
  let encoder = hex(B3_ENCODER);
  let (head, tail) = encoder.split_at(13);
  decoder.feed_encoder_stream(head).unwrap();
  assert_eq!(decoder.insert_count(), 2);
  assert_eq!(decoder.decoder_stream_output(), b"");
  decoder.feed_encoder_stream(tail).unwrap();
  assert_eq!(decoder.insert_count(), 3);
  assert_eq!(decoder.size, 160);
  // Nothing references it: an Insert Count Increment of 1
  assert_eq!(output(&mut decoder), [0x01]);
  assert_eq!(decoder.known_received, 3);
}

#[test]
fn rfc9204_appendix_b4_duplicate_instruction() {
  let mut decoder = after_b3();
  // The section arrives before the duplicate that it references: the stream blocks
  assert_eq!(
    decode(&mut decoder, 8, &hex(B4_STREAM_8)).unwrap(),
    (DecodeOutcome::Blocked { required_insert_count: 4 }, Vec::new())
  );
  assert_eq!(decoder.blocked_streams(), 1);
  // The stream is cancelled before the duplicate arrives
  decoder.cancel_stream(8).unwrap();
  assert_eq!(output(&mut decoder), [0x48]);
  assert_eq!(decoder.blocked_streams(), 0);
  // Duplicate of relative index 2: absolute index 0 again, as absolute index 3
  decoder.feed_encoder_stream(&hex(B4_ENCODER)).unwrap();
  assert_eq!(decoder.insert_count(), 4);
  assert_eq!(decoder.size, 217);
  assert_eq!(output(&mut decoder), [0x01]);
  // The cancelled stream is not reported as unblocked
  assert_eq!(decoder.take_unblocked().count(), 0);
  // The same section, on another stream, now decodes
  let expected =
    pairs(&[(":authority", "www.example.com"), (":path", "/"), ("custom-key", "custom-value")]);
  assert_eq!(decode(&mut decoder, 12, &hex(B4_STREAM_8)).unwrap(), (DONE_DYNAMIC, expected));
  assert_eq!(output(&mut decoder), [0x8c]);
}

#[test]
fn rfc9204_appendix_b5_insert_evicts_the_oldest_entry() {
  let mut decoder = after_b4();
  // custom-key=custom-value2 by the name of relative index 1 (absolute 2): 57 bytes evicted
  decoder.feed_encoder_stream(&hex(B5_ENCODER)).unwrap();
  assert_eq!(decoder.insert_count(), 5);
  assert_eq!(decoder.size, 215);
  assert_eq!(output(&mut decoder), [0x01]);
  // Absolute index 4 decodes; absolute index 0 is gone
  let mut newest = Vec::new();
  wire::prefix(&mut newest, 5, 5, 6);
  wire::indexed(&mut newest, false, 0);
  wire::indexed(&mut newest, false, 3);
  assert_eq!(
    decode(&mut decoder, 16, &newest).unwrap(),
    (DONE_DYNAMIC, pairs(&[("custom-key", "custom-value2"), (":path", "/sample/path")]))
  );
  assert!(failed(decode(&mut decoder, 20, &hex("020080")), ErrorKind::InvalidDynamicIndex));
}

#[test]
fn required_insert_count_wraps_per_rfc9204_section_4_5_1_1() {
  // The example of the RFC: a table of 100 bytes, 10 inserts, an encoded 4
  assert_eq!(decode_required_insert_count(4, 3, 10), Some(9));
  assert_eq!(decode_required_insert_count(0, 3, 10), Some(0));
  assert_eq!(decode_required_insert_count(0, 0, 0), Some(0));
  // Values that no encoder produces
  assert_eq!(decode_required_insert_count(7, 3, 10), None);
  assert_eq!(decode_required_insert_count(1, 0, 0), None);
  assert_eq!(decode_required_insert_count(1, 3, 0), None);
  assert_eq!(decode_required_insert_count(5, 3, 0), None);
  // Every count that an encoder can send, encoded as an encoder does, comes back
  for max_entries in [1u64, 3, 6, 128] {
    for total in 0..200u64 {
      let low = total.saturating_sub(max_entries - 1).max(1);
      for ric in low..=total + max_entries {
        let encoded = ric % (2 * max_entries) + 1;
        assert_eq!(decode_required_insert_count(encoded, max_entries, total), Some(ric));
      }
    }
  }
}

#[test]
fn blocked_stream_resumes_after_insert() {
  let mut decoder = new(4096, 1);
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 4096);
  decoder.feed_encoder_stream(&encoder).unwrap();
  // A section that references the first insert, before it arrives
  let mut section = Vec::new();
  wire::prefix(&mut section, 1, 1, 128);
  wire::indexed(&mut section, false, 0);
  wire::indexed(&mut section, true, 17);
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap(),
    (DecodeOutcome::Blocked { required_insert_count: 1 }, Vec::new())
  );
  // Decoding it again before the insert keeps one blocked stream, not two
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap().0,
    DecodeOutcome::Blocked { required_insert_count: 1 }
  );
  assert_eq!(decoder.blocked_streams(), 1);
  assert_eq!(output(&mut decoder), b"");
  encoder.clear();
  wire::insert_literal(&mut encoder, b"x-key", b"x-value", true);
  decoder.feed_encoder_stream(&encoder).unwrap();
  assert_eq!(decoder.insert_count(), 1);
  // The stream is reported once
  assert_eq!(decoder.take_unblocked().collect::<Vec<_>>(), [0]);
  assert_eq!(decoder.take_unblocked().count(), 0);
  assert_eq!(decoder.blocked_streams(), 0);
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap(),
    (DONE_DYNAMIC, pairs(&[("x-key", "x-value"), (":method", "GET")]))
  );
  // The Section Acknowledgment covers the insert
  assert_eq!(output(&mut decoder), [0x80]);
  // The stream slot is free again
  let mut later = Vec::new();
  wire::prefix(&mut later, 2, 2, 128);
  wire::indexed(&mut later, false, 0);
  assert_eq!(
    decode(&mut decoder, 4, &later).unwrap().0,
    DecodeOutcome::Blocked { required_insert_count: 2 }
  );
}

// Streams blocked on different counts are unblocked in the order that the inserts arrive, not
// the order that they blocked in
#[test]
fn blocked_streams_resolve_out_of_order() {
  let mut decoder = new(4096, 3);
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 4096);
  decoder.feed_encoder_stream(&encoder).unwrap();
  let section = |ric: u64| {
    let mut section = Vec::new();
    wire::prefix(&mut section, ric, 0, 128);
    wire::indexed_post_base(&mut section, ric - 1);
    section
  };
  for (stream, ric) in [(0u64, 3u64), (4, 1), (8, 2)] {
    assert_eq!(
      decode(&mut decoder, stream, &section(ric)).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: ric }
    );
  }
  let insert = |idx: u8| {
    let mut encoder = Vec::new();
    wire::insert_literal(&mut encoder, b"n", &[b'a' + idx], false);
    encoder
  };
  decoder.feed_encoder_stream(&insert(0)).unwrap();
  assert_eq!(decoder.take_unblocked().collect::<Vec<_>>(), [4]);
  assert_eq!(decode(&mut decoder, 4, &section(1)).unwrap().1, pairs(&[("n", "a")]));
  // Two inserts in one call unblock the two remaining streams
  let mut both = insert(1);
  both.extend_from_slice(&insert(2));
  decoder.feed_encoder_stream(&both).unwrap();
  let mut ready: Vec<_> = decoder.take_unblocked().collect();
  ready.sort_unstable();
  assert_eq!(ready, [0, 8]);
  assert_eq!(decode(&mut decoder, 8, &section(2)).unwrap().1, pairs(&[("n", "b")]));
  assert_eq!(decode(&mut decoder, 0, &section(3)).unwrap().1, pairs(&[("n", "c")]));
  assert_eq!(output(&mut decoder), [0x84, 0x88, 0x80]);
  decoder.check_invariants();
}

#[test]
fn blocked_streams_over_limit_is_decompression_failed() {
  let mut section = Vec::new();
  wire::prefix(&mut section, 1, 1, 128);
  wire::indexed(&mut section, false, 0);
  // Two promised: the third fails
  let mut decoder = new(4096, 2);
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap().0,
    DecodeOutcome::Blocked { required_insert_count: 1 }
  );
  assert_eq!(
    decode(&mut decoder, 4, &section).unwrap().0,
    DecodeOutcome::Blocked { required_insert_count: 1 }
  );
  assert!(failed(decode(&mut decoder, 8, &section), ErrorKind::TooManyBlockedStreams));
  // None promised: the first fails
  let mut decoder = new(4096, 0);
  assert!(failed(decode(&mut decoder, 0, &section), ErrorKind::TooManyBlockedStreams));
}

#[test]
fn encoder_stream_errors_per_rfc9204() {
  // A capacity above the advertised one (RFC 9204 4.3.1); the advertised one itself is fine
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 101);
  assert!(refused(new(100, 0).feed_encoder_stream(&encoder), ErrorKind::CapacityAboveMaximum));
  let fresh = || {
    let mut decoder = new(100, 0);
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 100);
    decoder.feed_encoder_stream(&encoder).unwrap();
    decoder
  };
  // An entry larger than the capacity (3.2.2): 40 + 40 + 32 > 100, refused as soon as the lengths
  // are known and before the bytes arrive
  encoder.clear();
  wire::insert_literal(&mut encoder, &[b'a'; 40], &[b'b'; 40], false);
  assert!(refused(fresh().feed_encoder_stream(&encoder), ErrorKind::EntryTooLarge));
  assert!(refused(fresh().feed_encoder_stream(&encoder[..43]), ErrorKind::EntryTooLarge));
  // A Huffman value that decodes past the capacity
  encoder.clear();
  wire::insert_literal(&mut encoder, b"a", &[b'0'; 80], true);
  assert!(refused(fresh().feed_encoder_stream(&encoder), ErrorKind::EntryTooLarge));
  // An index past the static table, references to entries that do not exist (2.2.3)
  encoder.clear();
  wire::insert_name_ref(&mut encoder, true, 99, b"v", false);
  assert!(refused(fresh().feed_encoder_stream(&encoder), ErrorKind::InvalidStaticIndex));
  encoder.clear();
  wire::insert_name_ref(&mut encoder, false, 0, b"v", false);
  assert!(refused(fresh().feed_encoder_stream(&encoder), ErrorKind::InvalidDynamicIndex));
  assert!(refused(fresh().feed_encoder_stream(&[0x00]), ErrorKind::InvalidDynamicIndex));
  // A bad Huffman string: padding of ones longer than 7 bits
  assert!(refused(
    fresh().feed_encoder_stream(&[0xc0 | 5, 0x84, 0xff, 0xff, 0xff, 0xff]),
    ErrorKind::InvalidHuffman
  ));
  // An evicted entry: two entries of 51 bytes do not fit in 100, the second evicts the first
  let mut decoder = fresh();
  encoder.clear();
  wire::insert_literal(&mut encoder, b"aaaaaaaa", b"bbbbbbbbbbb", false);
  wire::insert_literal(&mut encoder, b"cccccccc", b"ddddddddddd", false);
  decoder.feed_encoder_stream(&encoder).unwrap();
  assert_eq!((decoder.insert_count(), decoder.size), (2, 51));
  assert!(refused(decoder.clone().feed_encoder_stream(&[0x01]), ErrorKind::InvalidDynamicIndex));
  // A duplicate of the live one evicts it and still copies it whole
  decoder.feed_encoder_stream(&[0x00]).unwrap();
  let mut section = Vec::new();
  wire::prefix(&mut section, 3, 3, 3);
  wire::indexed(&mut section, false, 0);
  assert_eq!(
    decode(&mut decoder, 0, &section).unwrap(),
    (DONE_DYNAMIC, pairs(&[("cccccccc", "ddddddddddd")]))
  );
  // A prefixed integer above 62 bits (4.1.1): 31 in the 5-bit prefix of Set Dynamic Table
  // Capacity, then nine continuation bytes and one more
  let mut overflow = vec![0x3f];
  overflow.extend_from_slice(&[0xff; 9]);
  overflow.push(0x7f);
  assert!(refused(decoder.feed_encoder_stream(&overflow), ErrorKind::IntegerOverflow));
  // Without a dynamic table nothing can be inserted
  let mut decoder = new(0, 0);
  decoder.feed_encoder_stream(&[0x20]).unwrap();
  assert!(refused(decoder.clone().feed_encoder_stream(&[0x21]), ErrorKind::CapacityAboveMaximum));
  encoder.clear();
  wire::insert_literal(&mut encoder, b"", b"", false);
  assert!(refused(decoder.feed_encoder_stream(&encoder), ErrorKind::EntryTooLarge));
}

// A one-byte Duplicate of a 4 KiB entry copies 4 KiB twice: the bytes copied out of the table are
// bounded by a budget that received bytes refill (64 per byte, at most four capacities)
#[test]
fn duplicate_flood_is_excessive_load() {
  let budget_exceeded =
    |rslt| fails(rslt, ErrorCode::ExcessiveLoad, ErrorKind::EncoderInstructionBudget);
  let mut decoder = new(4096, 0);
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 4096);
  wire::insert_literal(&mut encoder, b"x", &[b'v'; 4031], false);
  decoder.feed_encoder_stream(&encoder).unwrap();
  assert_eq!(decoder.size, 4064);
  // The budget is full (four capacities) after 4 KiB received: four duplicates of 4032 bytes fit,
  // a fifth (with 64 more bytes of budget for its byte) does not
  decoder.feed_encoder_stream(&[0x00; 4]).unwrap();
  assert!(budget_exceeded(decoder.clone().feed_encoder_stream(&[0x00])));
  // Bytes received refill it: 63 bytes of capacity changes are enough for one more duplicate
  let mut refill = Vec::new();
  for _ in 0..21 {
    wire::set_capacity(&mut refill, 4096);
  }
  assert_eq!(refill.len(), 63);
  decoder.feed_encoder_stream(&refill).unwrap();
  decoder.feed_encoder_stream(&[0x00]).unwrap();
  // Dynamic name references count their names
  let mut name_decoder = new(4096, 0);
  encoder.clear();
  wire::set_capacity(&mut encoder, 4096);
  wire::insert_literal(&mut encoder, &[b'n'; 2000], b"", false);
  name_decoder.feed_encoder_stream(&encoder).unwrap();
  let mut name_refs = Vec::new();
  for _ in 0..8 {
    wire::insert_name_ref(&mut name_refs, false, 0, b"", false);
  }
  name_decoder.feed_encoder_stream(&name_refs).unwrap();
  assert!(budget_exceeded(name_decoder.feed_encoder_stream(&name_refs)));
}

// A pooled decoder starts over: no entry, no blocked stream, no pending output, the RFC bytes
// again
#[test]
fn reset_starts_over() {
  let mut decoder = after_b4();
  decoder.feed_encoder_stream(&hex(B5_ENCODER)).unwrap();
  let mut blocked = Vec::new();
  wire::prefix(&mut blocked, 6, 6, 6);
  wire::indexed(&mut blocked, false, 0);
  assert_eq!(
    decode(&mut decoder, 40, &blocked).unwrap().0,
    DecodeOutcome::Blocked { required_insert_count: 6 }
  );
  assert!(!decoder.decoder_stream_output().is_empty());
  let config = *decoder.config();
  let heap = decoder.heap_bytes();
  decoder.reset(DecoderConfig { max_table_capacity: 100, blocked_streams: 1, ..config });
  decoder.reset(config);
  assert_eq!(decoder.heap_bytes(), heap);
  assert_eq!((decoder.insert_count(), decoder.size, decoder.capacity), (0, 0, 0));
  assert_eq!((decoder.entries_len, decoder.blocked_streams()), (0, 0));
  assert_eq!(decoder.decoder_stream_output(), b"");
  decoder.check_invariants();
  // The RFC exchange from the start
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  assert_eq!(decoder.decoder_stream_output(), [0x02]);
  let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
  assert_eq!(decode(&mut decoder, 4, &hex(B2_STREAM_4)).unwrap(), (DONE_DYNAMIC, expected));
  assert_eq!(output(&mut decoder), [0x84]);
  // Larger limits are allowed, with new storage
  decoder.reset(DecoderConfig { max_table_capacity: 4096, blocked_streams: 4, ..config });
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 4096);
  wire::insert_literal(&mut encoder, &[b'a'; 1000], &[b'b'; 3000], false);
  decoder.feed_encoder_stream(&encoder).unwrap();
  decoder.check_invariants();
}

#[test]
fn field_section_errors_per_rfc9204() {
  // A prefix that is not whole
  assert!(failed(decode(&mut after_b2(), 0, &[]), ErrorKind::Truncated));
  assert!(failed(decode(&mut after_b2(), 0, &[0x03]), ErrorKind::Truncated));
  // An encoded Required Insert Count above 2 * MaxEntries (4.5.1.1)
  assert!(failed(decode(&mut after_b2(), 0, &[13, 0x00]), ErrorKind::InvalidRequiredInsertCount));
  // A negative Base (4.5.1.2)
  assert!(failed(decode(&mut after_b2(), 0, &[0x03, 0x82, 0x10]), ErrorKind::InvalidBase));
  // A static index past the table (3.1)
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0xff, 0x24]),
    ErrorKind::InvalidStaticIndex
  ));
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0x5f, 0x54, 0x00]),
    ErrorKind::InvalidStaticIndex
  ));
  // Dynamic references with a Required Insert Count of 0, or at the Required Insert Count (2.2.3)
  assert!(failed(decode(&mut after_b2(), 0, &[0x00, 0x00, 0x80]), ErrorKind::InvalidDynamicIndex));
  assert!(failed(decode(&mut after_b2(), 0, &[0x02, 0x00, 0x10]), ErrorKind::InvalidDynamicIndex));
  assert!(failed(decode(&mut after_b2(), 0, &[0x02, 0x00, 0x81]), ErrorKind::InvalidDynamicIndex));
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x02, 0x80, 0x01, 0x00]),
    ErrorKind::InvalidDynamicIndex
  ));
  // A Required Insert Count larger than the references need (2.1.2)
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x03, 0x00, 0x81]),
    ErrorKind::RequiredInsertCountTooLarge
  ));
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x03, 0x00, 0xd1]),
    ErrorKind::RequiredInsertCountTooLarge
  ));
  // Literals that end early, or whose Huffman string is bad
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x0b, b'/']),
    ErrorKind::Truncated
  ));
  assert!(failed(decode(&mut after_b2(), 0, &[0x00, 0x00, 0x27]), ErrorKind::Truncated));
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x84, 0xff, 0xff, 0xff, 0xff]),
    ErrorKind::InvalidHuffman
  ));
  // A Huffman string with an EOS symbol, and one with padding that is not all ones
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x85, 0x1f, 0xff, 0xff, 0xff, 0xff]),
    ErrorKind::InvalidHuffman
  ));
  assert!(failed(
    decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x81, 0x18]),
    ErrorKind::InvalidHuffman
  ));
  // An integer above 62 bits
  let mut huge = vec![0x00, 0x00, 0xff];
  huge.extend_from_slice(&[0xff; 9]);
  huge.push(0x7f);
  assert!(failed(decode(&mut after_b2(), 0, &huge), ErrorKind::IntegerOverflow));
}

// A sink error stops the decoding and is returned as it is; it is local, and the section is
// acknowledged so that the encoder releases its references
#[test]
fn sink_errors_are_local() {
  #[derive(Debug, PartialEq)]
  enum AppError {
    Qpack(Error),
    TooManyFields,
  }
  impl From<Error> for AppError {
    fn from(error: Error) -> Self {
      Self::Qpack(error)
    }
  }
  let mut decoder = after_b2();
  let mut calls = 0;
  let rslt = decoder.decode(4, &hex(B2_STREAM_4), |_| {
    calls += 1;
    Err(AppError::TooManyFields)
  });
  assert_eq!(rslt, Err(AppError::TooManyFields));
  assert_eq!(calls, 1);
  assert_eq!(output(&mut decoder), [0x84]);
  // QPACK errors convert into the caller's type
  let rslt = decoder.decode(4, &[0x00, 0x00, 0x80], |_| Ok::<_, AppError>(()));
  assert!(
    matches!(rslt, Err(AppError::Qpack(err)) if err.kind() == ErrorKind::InvalidDynamicIndex)
  );
  decoder.check_invariants();
}

#[test]
fn field_section_size_limit() {
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: 220,
    blocked_streams: 2,
    max_field_section_size: Some(32 + 10 + 15 + 32 + 5 + 12),
    ..DecoderConfig::default()
  });
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  // :authority www.example.com and :path /sample/path: exactly the limit
  assert_eq!(decode(&mut decoder, 4, &hex(B2_STREAM_4)).unwrap().0, DONE_DYNAMIC);
  let mut section = Vec::new();
  wire::prefix(&mut section, 2, 2, 6);
  wire::indexed(&mut section, false, 1);
  wire::indexed(&mut section, false, 0);
  wire::indexed(&mut section, true, 17);
  let rslt = decode(&mut decoder, 8, &section);
  assert_eq!(rslt.unwrap_err(), Error::local(ErrorKind::FieldSectionTooLarge));
  // Both sections are acknowledged
  assert_eq!(output(&mut decoder), [0x84, 0x88]);
}

// Each field comes with the static entry that gave its name (and its value, for an Indexed Field
// Line), with none for a literal name or a name of the dynamic table, and with the never-indexed
// bit; a replay of the memo gives the same
#[test]
fn fields_carry_their_static_reference_and_sensitivity() {
  let mut decoder = with_memo(220, 2, 4);
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  let mut section = Vec::new();
  wire::prefix(&mut section, 2, 2, 8);
  wire::indexed(&mut section, true, 17); // :method GET
  wire::name_ref(&mut section, true, false, 1, b"/index", false); // :path, a literal value
  wire::name_ref(&mut section, true, true, 31, b"br", true); // accept-encoding, sensitive
  wire::literal(&mut section, false, b"x-y", b"z", false);
  wire::literal(&mut section, true, b"x-s", b"secret", true);
  wire::indexed(&mut section, false, 0); // dynamic: :path /sample/path
  wire::name_ref(&mut section, false, true, 1, b"x", false); // dynamic name: :authority
  let expected = [
    (&b":method"[..], &b"GET"[..], false, Some(StaticRef { index: 17, with_value: true })),
    (b":path", b"/index", false, Some(StaticRef { index: 1, with_value: false })),
    (b"accept-encoding", b"br", true, Some(StaticRef { index: 31, with_value: false })),
    (b"x-y", b"z", false, None),
    (b"x-s", b"secret", true, None),
    (b":path", b"/sample/path", false, None),
    (b":authority", b"x", true, None),
  ];
  for (round, stream) in [(0, 8u64), (1, 12)] {
    let mut got = Vec::new();
    let outcome = decoder.decode(stream, &section, |field: DecodedField<'_>| {
      got.push((field.name.to_vec(), field.value.to_vec(), field.sensitive, field.static_ref));
      Ok::<_, Error>(())
    });
    assert_eq!(outcome.unwrap(), DONE_DYNAMIC, "round {round}");
    let want: Vec<_> =
      expected.iter().map(|(n, v, s, r)| (n.to_vec(), v.to_vec(), *s, *r)).collect();
    assert_eq!(got, want, "round {round}");
  }
  assert_eq!(decoder.stats().memo_hits, 1);
  assert_eq!(decoder.stats().sections, 2);
}

#[test]
fn huffman_literals_and_post_base_references_decode() {
  let mut decoder = after_b2();
  let mut section = Vec::new();
  // Required Insert Count 2 with a Base of 0: every dynamic reference is post-Base
  wire::prefix(&mut section, 2, 0, 6);
  wire::indexed_post_base(&mut section, 1);
  wire::post_base_name_ref(&mut section, true, 0, b"example.org", true);
  // RFC 7541 C.4.1: "www.example.com" as Huffman, by the static name of index 0
  section.extend_from_slice(&hex("508cf1e3c2e5f23a6ba0ab90f4ff"));
  // RFC 7541 C.4.3: custom-key: custom-value, both Huffman
  section.extend_from_slice(&hex("2f0125a849e95ba97d7f8925a849e95bb8e8b4bf"));
  wire::name_ref(&mut section, true, true, 4, b"0", false);
  wire::literal(&mut section, true, b"x-empty", b"", false);
  let expected = pairs(&[
    (":path", "/sample/path"),
    (":authority", "example.org"),
    (":authority", "www.example.com"),
    ("custom-key", "custom-value"),
    ("content-length", "0"),
    ("x-empty", ""),
  ]);
  assert_eq!(decode(&mut decoder, 4, &section).unwrap(), (DONE_DYNAMIC, expected));
  assert_eq!(output(&mut decoder), [0x84]);
}

// Entries go round a ring of the capacity: those that wrap around its end decode whole, by index,
// by name and duplicated
#[test]
fn entries_that_wrap_the_ring_decode_whole() {
  let mut decoder = new(100, 0);
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 100);
  decoder.feed_encoder_stream(&encoder).unwrap();
  for round in 0..64usize {
    let name = alloc::format!("n{:0w$}", round, w = round % 7 + 1);
    let value = alloc::format!("v{:0w$}", round, w = round % 11 + 1);
    encoder.clear();
    wire::insert_literal(&mut encoder, name.as_bytes(), value.as_bytes(), round % 2 == 0);
    // The same name with another value, then a duplicate of it
    wire::insert_name_ref(&mut encoder, false, 0, b"other", false);
    wire::duplicate(&mut encoder, 0);
    decoder.feed_encoder_stream(&encoder).unwrap();
    let ric = decoder.insert_count();
    let mut section = Vec::new();
    wire::prefix(&mut section, ric, ric, 3);
    wire::indexed(&mut section, false, 0);
    wire::name_ref(&mut section, false, false, 0, value.as_bytes(), false);
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap(),
      (DONE_DYNAMIC, pairs(&[(&name, "other"), (&name, &value)]))
    );
    let _ = output(&mut decoder);
    assert!(decoder.size <= 100);
    decoder.check_invariants();
  }
}

// The encoder stream may arrive one byte at a time
#[test]
fn encoder_stream_byte_by_byte() {
  let mut decoder = new(220, 2);
  for byte in hex(B2_ENCODER).iter().chain(&hex(B3_ENCODER)).chain(&hex(B4_ENCODER)) {
    decoder.feed_encoder_stream(&[*byte]).unwrap();
    decoder.check_invariants();
  }
  assert_eq!(decoder.insert_count(), 4);
  assert_eq!(output(&mut decoder), [0x04]);
}

#[test]
fn decoder_output_backlog_is_bounded() {
  let mut decoder = new(4096, 0);
  let mut stream = 0u64;
  let mut rslt = None;
  for _ in 0..100_000 {
    if let Err(err) = decoder.cancel_stream(stream) {
      rslt = Some(err);
      break;
    }
    assert!(decoder.decoder_stream_output().len() <= 64 * 1024);
    stream += 4;
  }
  assert_eq!(rslt, Some(Error::new(ErrorCode::ExcessiveLoad, ErrorKind::DecoderStreamBacklog)));
  // Written out, it goes on
  let _ = output(&mut decoder);
  decoder.cancel_stream(stream).unwrap();
  // Without a dynamic table there is nothing to cancel (RFC 9204 2.2.2.2)
  let mut decoder = new(0, 0);
  decoder.cancel_stream(4).unwrap();
  assert_eq!(decoder.decoder_stream_output(), b"");
}

// An incomplete instruction waits, bounded by what a valid one can need
#[test]
fn incomplete_instruction_is_bounded() {
  let mut decoder = new(100, 0);
  let mut encoder = Vec::new();
  wire::set_capacity(&mut encoder, 100);
  decoder.feed_encoder_stream(&encoder).unwrap();
  // A Huffman name of 250 bytes may decode to as few as 66 bytes: allowed to wait
  let mut partial = Vec::new();
  wire::int(&mut partial, 250, 5, 0x40 | 0x20);
  partial.extend_from_slice(&[0xfe; 249]);
  decoder.feed_encoder_stream(&partial).unwrap();
  assert_eq!(decoder.insert_count(), 0);
  decoder.check_invariants();
  // More than that is refused by its length
  let mut too_long = Vec::new();
  wire::int(&mut too_long, 500, 5, 0x40 | 0x20);
  assert!(refused(new(100, 0).feed_encoder_stream(&too_long), ErrorKind::EntryTooLarge));
}

#[test]
fn decode_memo_hits_identical_sections() {
  // RFC 9204 B.2: two entries, and a section on stream 4 that references both
  let mut decoder = with_memo(220, 2, 2);
  decoder.feed_encoder_stream(&hex(B2_ENCODER)).unwrap();
  let _ = output(&mut decoder);
  let dynamic = hex(B2_STREAM_4);
  let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
  let hits = |decoder: &Decoder| decoder.stats().memo_hits;
  // Decoded, then replayed; each one is acknowledged on its own stream
  let first = decode(&mut decoder, 4, &dynamic).unwrap();
  assert_eq!(first, (DONE_DYNAMIC, expected.clone()));
  assert_eq!(hits(&decoder), 0);
  assert_eq!(output(&mut decoder), [0x84]);
  let second = decode(&mut decoder, 8, &dynamic).unwrap();
  assert_eq!(second, first);
  assert_eq!(hits(&decoder), 1);
  assert_eq!(output(&mut decoder), [0x88]);
  // A static section (RFC 9204 B.1) is replayed too, and acknowledged by neither
  let fixed = hex("0000510b2f696e6465782e68746d6c");
  let static_expected = (DONE_STATIC, pairs(&[(":path", "/index.html")]));
  assert_eq!(decode(&mut decoder, 12, &fixed).unwrap(), static_expected);
  assert_eq!(decode(&mut decoder, 16, &fixed).unwrap(), static_expected);
  assert_eq!(hits(&decoder), 2);
  assert_eq!(output(&mut decoder), b"");
  // Two entries are kept: a third section replaces the one used least recently (the dynamic one)
  let mut other = Vec::new();
  wire::prefix(&mut other, 0, 0, 6);
  wire::literal(&mut other, false, b"x-a", b"1", true);
  let _ = decode(&mut decoder, 20, &other).unwrap();
  let _ = decode(&mut decoder, 24, &fixed).unwrap();
  assert_eq!(hits(&decoder), 3);
  let _ = decode(&mut decoder, 28, &dynamic).unwrap();
  assert_eq!(hits(&decoder), 3);
  assert_eq!(decoder.memo.kept(), 2);
  let _ = output(&mut decoder);
  // Sections longer than 128 bytes are not kept
  let mut long = Vec::new();
  wire::prefix(&mut long, 0, 0, 6);
  wire::literal(&mut long, false, b"x-long", &[b'v'; 130], false);
  let _ = decode(&mut decoder, 32, &long).unwrap();
  let _ = decode(&mut decoder, 36, &long).unwrap();
  assert_eq!(hits(&decoder), 3);
  // The entries that a kept section references are evicted: the same bytes are decoded again and
  // fail as a decode does (RFC 9204 section 2.2.3), they are not replayed
  let _ = decode(&mut decoder, 40, &dynamic).unwrap();
  assert_eq!(hits(&decoder), 4);
  let _ = output(&mut decoder);
  decoder.feed_encoder_stream(&[0x20]).unwrap();
  assert!(failed(decode(&mut decoder, 44, &dynamic), ErrorKind::InvalidDynamicIndex));
  assert_eq!(hits(&decoder), 4);
  assert_eq!(output(&mut decoder), b"");
}

// A memo replays only for the table that it was filled from: the same decoder reset decodes the
// same bytes and Required Insert Count against its new table
#[test]
fn decode_memo_never_replays_another_table() {
  let ours = hex(B2_ENCODER);
  let mut theirs = Vec::new();
  wire::set_capacity(&mut theirs, 220);
  wire::insert_name_ref(&mut theirs, true, 0, b"other.example", false);
  wire::insert_name_ref(&mut theirs, true, 1, b"/other", false);
  let dynamic = hex(B2_STREAM_4);
  let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
  let other = pairs(&[(":authority", "other.example"), (":path", "/other")]);
  let mut decoder = with_memo(220, 2, 2);
  decoder.feed_encoder_stream(&ours).unwrap();
  let _ = decode(&mut decoder, 4, &dynamic).unwrap();
  assert_eq!(decode(&mut decoder, 8, &dynamic).unwrap().1, expected);
  assert_eq!(decoder.stats().memo_hits, 1);
  // Reset and refilled with other entries at the same absolute indices
  let config = *decoder.config();
  decoder.reset(config);
  decoder.feed_encoder_stream(&theirs).unwrap();
  assert_eq!(decode(&mut decoder, 4, &dynamic).unwrap().1, other);
  assert_eq!(decoder.stats().memo_hits, 0);
  // Reset and refilled, then emptied: the RFC error, not a replay
  decoder.reset(config);
  let mut emptied = theirs.clone();
  wire::set_capacity(&mut emptied, 0);
  decoder.feed_encoder_stream(&emptied).unwrap();
  assert!(failed(decode(&mut decoder, 8, &dynamic), ErrorKind::InvalidDynamicIndex));
}

// A kept section is not replayed while its stream would block: a decoder whose table is behind
// the section blocks the stream as a decode does
#[test]
fn decode_memo_respects_blocked_streams() {
  let mut decoder = with_memo(220, 1, 2);
  let dynamic = hex(B2_STREAM_4);
  assert_eq!(
    decode(&mut decoder, 4, &dynamic).unwrap(),
    (DecodeOutcome::Blocked { required_insert_count: 2 }, Vec::new())
  );
  assert!(failed(decode(&mut decoder, 8, &dynamic), ErrorKind::TooManyBlockedStreams));
  assert_eq!(decoder.stats().memo_hits, 0);
}

#[test]
fn random_tables_match_a_model() {
  let mut state = 0x2545_f491_4f6c_dd1du64;
  let mut data = Vec::new();
  for round in 0..2_000 {
    data.clear();
    for _ in 0..64 + round % 1024 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      data.push(state as u8);
    }
    crate::check::check_model(&data);
  }
  crate::check::check_model(&[0; 4096]);
}

#[test]
fn arbitrary_bytes_do_not_break_the_decoder() {
  let mut state = 0x9e37_79b9_7f4a_7c15u64;
  let mut next = || {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
  };
  let mut data = Vec::new();
  for _ in 0..5_000 {
    data.clear();
    for _ in 0..next() % 512 {
      data.push(next() as u8);
    }
    crate::check::check_decoders(&data);
  }
}

// The same checks over a million inputs: `cargo test --release -- --ignored`
#[test]
#[ignore = "long; run in release with --ignored"]
fn long_random_inputs() {
  let mut state = 0x0bad_5eed_dead_beefu64;
  let mut data = Vec::new();
  for round in 0..1_000_000u64 {
    data.clear();
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    let len = state % 1024;
    for _ in 0..len {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      data.push(state as u8);
    }
    crate::check::check_decoders(&data);
    if round % 4 == 0 {
      crate::check::check_model(&data);
      let _ = crate::check::check_roundtrip(&data);
    }
  }
}
