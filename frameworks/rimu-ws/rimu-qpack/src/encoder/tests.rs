use super::{Encoder, EncoderConfig, InsertPolicy, MAX_TRACKED_SECTIONS};
use crate::{
  DecodeOutcome, Decoder, DecoderConfig, Error, ErrorCode, ErrorKind, Field, FieldList, Settings,
  check, wire,
};
use alloc::{format, vec, vec::Vec};

fn settings(capacity: u64, blocked: u64) -> Settings {
  Settings { max_table_capacity: capacity, blocked_streams: blocked }
}

fn decoder(capacity: u32, blocked: u16) -> Decoder {
  Decoder::new(DecoderConfig {
    max_table_capacity: capacity,
    blocked_streams: blocked,
    ..DecoderConfig::default()
  })
}

fn encoder(config: EncoderConfig, decoder: &Decoder) -> Encoder {
  let mut encoder = Encoder::new(config);
  encoder.set_peer_settings(decoder.settings()).unwrap();
  encoder
}

fn always() -> EncoderConfig {
  EncoderConfig { insert_policy: InsertPolicy::Always, ..EncoderConfig::default() }
}

// Encodes, delivers the encoder stream, decodes, checks the fields and delivers the decoder
// stream back: one exchange of a connection whose streams are in order.
fn exchange(
  encoder: &mut Encoder,
  decoder: &mut Decoder,
  stream: u64,
  fields: &[Field<'_>],
) -> Vec<u8> {
  let mut section = Vec::new();
  encoder.encode(stream, fields, &mut section);
  let mut stream_bytes = Vec::new();
  encoder.drain_encoder_stream(&mut stream_bytes);
  decoder.feed_encoder_stream(&stream_bytes).unwrap();
  let mut decoded = FieldList::new();
  assert!(matches!(
    decoder.decode_into(stream, &section, &mut decoded).unwrap(),
    DecodeOutcome::Done { .. }
  ));
  assert_eq!(decoded.to_vec(), fields);
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  encoder.check_invariants();
  decoder.check_invariants();
  section
}

const REQUEST: [Field<'static>; 6] = [
  Field::new(b":method", b"GET"),
  Field::new(b":scheme", b"https"),
  Field::new(b":authority", b"www.example.com"),
  Field::new(b":path", b"/index.html"),
  Field::new(b"user-agent", b"Mozilla/5.0 rimu"),
  Field::new(b"x-custom", b"value"),
];

#[test]
fn static_only_mode_never_touches_the_dynamic_table() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(EncoderConfig::static_only(), &decoder);
  for stream in 0..4 {
    let section = exchange(&mut encoder, &mut decoder, stream * 4, &REQUEST);
    // Required Insert Count 0, Base 0
    assert_eq!(&section[..2], &[0, 0]);
  }
  assert_eq!(encoder.insert_count(), 0);
  assert_eq!(decoder.insert_count(), 0);
  assert_eq!(decoder.decoder_stream_output(), b"");
  // Before the peer's settings any encoder is static-only
  let mut early = Encoder::new(always());
  let mut section = Vec::new();
  early.encode(0, REQUEST, &mut section);
  assert_eq!(early.encoder_stream_output(), b"");
  assert_eq!(&section[..2], &[0, 0]);
}

#[test]
fn repeated_policy_inserts_on_second_sight_then_references() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(EncoderConfig::default(), &decoder);
  // The capacity is announced
  assert_eq!(encoder.encoder_stream_output(), [0x3f, 0xe1, 0x1f]);
  let first = exchange(&mut encoder, &mut decoder, 0, &REQUEST);
  assert_eq!(encoder.insert_count(), 0);
  assert_eq!(&first[..2], &[0, 0]);
  // Second sight: :authority, :path, user-agent and x-custom go in (the rest is static) and are
  // referenced post-Base
  let second = exchange(&mut encoder, &mut decoder, 4, &REQUEST);
  assert_eq!(encoder.insert_count(), 4);
  assert_eq!(encoder.stats().blocking_sections, 1);
  // Required Insert Count 4 (encoded 5), Base 0: Sign 1, Delta Base 3
  assert_eq!(&second[..2], &[5, 0x83]);
  // Third: by index only, relative to a Base of 4
  let third = exchange(&mut encoder, &mut decoder, 8, &REQUEST);
  assert_eq!(third, [5, 0x00, 0xd1, 0xd7, 0x83, 0x82, 0x81, 0x80]);
  assert_eq!(encoder.unacknowledged_sections(), 0);
  assert_eq!(encoder.known_received_count(), 4);
  // The memo replays the repeats of the third
  let fourth = exchange(&mut encoder, &mut decoder, 12, &REQUEST);
  assert_eq!(fourth, third);
  assert_eq!(decoder.stats().memo_hits, 1);
}

#[test]
fn inserts_use_static_dynamic_and_literal_names() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  let fields = [
    Field::new(b":authority", b"a.example"),
    Field::new(b"x-a", b"1"),
    Field::new(b"x-a", b"2"),
    Field::new(b"x-a", b"1"),
  ];
  let mut section = Vec::new();
  encoder.encode(0, fields, &mut section);
  let mut expected = Vec::new();
  // Static name, literal name, then the name of the entry just inserted (relative index 0)
  wire::insert_name_ref(&mut expected, true, 0, b"a.example", true);
  wire::insert_literal(&mut expected, b"x-a", b"1", false);
  wire::insert_name_ref(&mut expected, false, 0, b"2", false);
  assert_eq!(encoder.encoder_stream_output(), expected);
  // Every line post-Base; the repeat of x-a: 1 references the first insert of it
  assert_eq!(section, [4, 0x82, 0x10, 0x11, 0x12, 0x11]);
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  let mut decoded = FieldList::new();
  decoder.decode_into(0, &section, &mut decoded).unwrap();
  assert_eq!(decoded.to_vec(), fields);
}

#[test]
fn sensitive_fields_are_never_indexed() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  let fields = [
    Field::new(b"authorization", b"Bearer token"),
    Field::new(b"cookie", b"a=b"),
    Field::sensitive(b"x-api-key", b"k3y"),
    Field::sensitive(b":path", b"/secret"),
    Field::new(b"x-plain", b"p"),
  ];
  for stream in 0..3 {
    let mut section = Vec::new();
    encoder.encode(stream * 4, fields, &mut section);
    let mut bytes = Vec::new();
    encoder.drain_encoder_stream(&mut bytes);
    decoder.feed_encoder_stream(&bytes).unwrap();
    let mut sensitive = Vec::new();
    decoder
      .decode(stream * 4, &section, |field: crate::DecodedField<'_>| {
        sensitive.push(field.sensitive);
        Ok::<_, Error>(())
      })
      .unwrap();
    assert_eq!(sensitive, [true, true, true, true, false]);
  }
  // Only x-plain went in
  assert_eq!(encoder.insert_count(), 1);
  // Unless sensitive names may be indexed; fields marked sensitive still are not
  let mut decoder = self::decoder(4096, 100);
  let mut encoder =
    self::encoder(EncoderConfig { index_sensitive_names: true, ..always() }, &decoder);
  exchange(&mut encoder, &mut decoder, 0, &fields);
  assert_eq!(encoder.insert_count(), 3);
}

#[test]
fn blocked_streams_limit_is_respected() {
  // The peer allows one blocked stream
  let mut decoder = decoder(4096, 1);
  let mut encoder = encoder(always(), &decoder);
  let mut sections = Vec::new();
  for stream in [0u64, 4, 8] {
    let mut section = Vec::new();
    let fields = [Field::new(b"x-shared", b"v"), Field::new(b"x-stream", b"s")];
    encoder.encode(stream, fields, &mut section);
    sections.push((stream, section));
    assert!(encoder.blocking_streams() <= 1);
  }
  assert_eq!(encoder.stats().blocking_sections, 1);
  // The decoder sees the sections before the inserts: one blocks, the others decode at once
  let mut decoded = FieldList::new();
  let outcomes: Vec<_> = sections
    .iter()
    .map(|(stream, section)| decoder.decode_into(*stream, section, &mut decoded).unwrap())
    .collect();
  assert!(matches!(outcomes[0], DecodeOutcome::Blocked { .. }));
  assert!(matches!(outcomes[1], DecodeOutcome::Done { referenced_dynamic: false }));
  assert!(matches!(outcomes[2], DecodeOutcome::Done { referenced_dynamic: false }));
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  assert_eq!(decoder.take_unblocked().collect::<Vec<_>>(), [0]);
  decoder.decode_into(0, &sections[0].1, &mut decoded).unwrap();
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  // Everything is acknowledged: references are free again
  assert_eq!(encoder.blocking_streams(), 0);
  let section = exchange(&mut encoder, &mut decoder, 12, &[Field::new(b"x-shared", b"v")]);
  assert_ne!(&section[..2], &[0, 0]);
  encoder.check_invariants();
}

#[test]
fn no_blocking_when_disallowed() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(EncoderConfig { allow_blocking: false, ..always() }, &decoder);
  let mut section = Vec::new();
  encoder.encode(0, REQUEST, &mut section);
  // Inserted, but not referenced before the acknowledgment
  assert!(encoder.insert_count() > 0);
  assert_eq!(&section[..2], &[0, 0]);
  let mut decoded = FieldList::new();
  // Decodes without the encoder stream
  decoder.decode_into(0, &section, &mut decoded).unwrap();
  assert_eq!(decoded.to_vec(), REQUEST);
  // Once the Insert Count Increment arrives, the entries are referenced
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  let section = exchange(&mut encoder, &mut decoder, 4, &REQUEST);
  assert_ne!(&section[..2], &[0, 0]);
  assert_eq!(encoder.stats().blocking_sections, 0);
}

// In a small table, entries that unacknowledged sections reference are never evicted: inserts
// stop until acknowledgments arrive, then resume with evictions
#[test]
fn referenced_entries_are_never_evicted() {
  let mut decoder = decoder(220, 100);
  let mut encoder = encoder(always(), &decoder);
  let mut held = Vec::new();
  for idx in 0..10u8 {
    let value = [b'a' + idx; 20];
    let mut section = Vec::new();
    encoder.encode(u64::from(idx) * 4, [Field::new(b"x-key", &value)], &mut section);
    held.push(section);
    encoder.check_invariants();
  }
  // 220 bytes hold 3 entries of 57 bytes; nothing was acknowledged, so nothing was evicted
  assert_eq!(encoder.insert_count(), 3);
  assert_eq!(encoder.stats().evictions, 0);
  // Deliver everything, decode everything, acknowledge everything
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  let mut decoded = FieldList::new();
  for (idx, section) in held.iter().enumerate() {
    decoder.decode_into(idx as u64 * 4, section, &mut decoded).unwrap();
    assert_eq!(decoded.iter().next().unwrap().value, [b'a' + idx as u8; 20]);
  }
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  assert_eq!(encoder.unacknowledged_sections(), 0);
  // Now inserts evict
  for idx in 10..20u8 {
    let value = [b'a' + idx; 20];
    exchange(&mut encoder, &mut decoder, u64::from(idx) * 4, &[Field::new(b"x-key", &value)]);
  }
  assert!(encoder.stats().evictions > 0);
  assert!(encoder.insert_count() > 3);
}

#[test]
fn capacity_changes() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  assert_eq!(encoder.set_capacity(4097), Err(Error::local(ErrorKind::CapacityAboveMaximum)));
  let mut section = Vec::new();
  encoder.encode(0, REQUEST, &mut section);
  // Unacknowledged entries can not be evicted
  assert_eq!(encoder.set_capacity(0), Err(Error::local(ErrorKind::EntriesInUse)));
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  let mut decoded = FieldList::new();
  decoder.decode_into(0, &section, &mut decoded).unwrap();
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  // Acknowledged and unreferenced: the table can shrink, to nothing
  encoder.set_capacity(100).unwrap();
  assert!(encoder.table_size() <= 100);
  encoder.set_capacity(0).unwrap();
  assert_eq!(encoder.table_len(), 0);
  exchange(&mut encoder, &mut decoder, 4, &REQUEST);
  assert_eq!(decoder.table_capacity(), 0);
  // And grow again
  encoder.set_capacity(1000).unwrap();
  exchange(&mut encoder, &mut decoder, 8, &REQUEST);
  exchange(&mut encoder, &mut decoder, 12, &REQUEST);
  assert_eq!(decoder.table_capacity(), 1000);
  assert!(decoder.table_len() > 0);
  // The settings come once
  assert_eq!(
    encoder.set_peer_settings(settings(10, 1)),
    Err(Error::local(ErrorKind::InvalidConfig))
  );
}

#[test]
fn decoder_stream_errors_per_rfc9204() {
  let error = |kind| Err(Error::new(ErrorCode::DecoderStreamError, kind));
  let fresh = || {
    let mut encoder = Encoder::new(always());
    encoder.set_peer_settings(settings(4096, 100)).unwrap();
    let mut section = Vec::new();
    encoder.encode(0, REQUEST, &mut section);
    encoder
  };
  let mut bytes = Vec::new();
  // A Section Acknowledgment of a stream without unacknowledged sections (4.4.1)
  wire::section_ack(&mut bytes, 4);
  assert_eq!(
    fresh().feed_decoder_stream(&bytes),
    error(ErrorKind::UnexpectedSectionAcknowledgment)
  );
  bytes.clear();
  wire::section_ack(&mut bytes, 0);
  wire::section_ack(&mut bytes, 0);
  assert_eq!(
    fresh().feed_decoder_stream(&bytes),
    error(ErrorKind::UnexpectedSectionAcknowledgment)
  );
  // An Insert Count Increment of zero, or past the inserts (4.4.3)
  assert_eq!(fresh().feed_decoder_stream(&[0x00]), error(ErrorKind::InvalidInsertCountIncrement));
  let inserts = fresh().insert_count();
  bytes.clear();
  wire::insert_count_increment(&mut bytes, inserts + 1);
  assert_eq!(fresh().feed_decoder_stream(&bytes), error(ErrorKind::InvalidInsertCountIncrement));
  bytes.clear();
  wire::insert_count_increment(&mut bytes, inserts);
  wire::insert_count_increment(&mut bytes, 1);
  assert_eq!(fresh().feed_decoder_stream(&bytes), error(ErrorKind::InvalidInsertCountIncrement));
  // An integer above 62 bits
  let mut huge = vec![0x7f];
  huge.extend_from_slice(&[0xff; 9]);
  huge.push(0x7f);
  assert_eq!(fresh().feed_decoder_stream(&huge), error(ErrorKind::IntegerOverflow));
  // Cancelling an unknown stream is fine, and instructions may come one byte at a time
  let mut encoder = fresh();
  bytes.clear();
  wire::stream_cancel(&mut bytes, 1000);
  wire::insert_count_increment(&mut bytes, inserts);
  wire::section_ack(&mut bytes, 0);
  for byte in &bytes {
    encoder.feed_decoder_stream(&[*byte]).unwrap();
  }
  assert_eq!(encoder.known_received_count(), inserts);
  assert_eq!(encoder.unacknowledged_sections(), 0);
  encoder.check_invariants();
}

// A Stream Cancellation releases the references of every section of the stream; a Section
// Acknowledgment acknowledges the earliest section of the stream (headers before trailers)
#[test]
fn cancellations_and_trailers() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  let mut headers = Vec::new();
  let mut trailers = Vec::new();
  encoder.encode(0, REQUEST, &mut headers);
  encoder.encode(0, [Field::new(b"x-checksum", b"abc")], &mut trailers);
  assert_eq!(encoder.unacknowledged_sections(), 2);
  let mut other = Vec::new();
  encoder.encode(4, REQUEST, &mut other);
  assert_eq!(encoder.unacknowledged_sections(), 3);
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  encoder.consume_encoder_stream(usize::MAX);
  let mut decoded = FieldList::new();
  decoder.decode_into(0, &headers, &mut decoded).unwrap();
  decoder.decode_into(0, &trailers, &mut decoded).unwrap();
  assert_eq!(decoded.to_vec(), [Field::new(b"x-checksum", b"abc")]);
  decoder.cancel_stream(4).unwrap();
  let mut back = Vec::new();
  decoder.drain_decoder_stream(&mut back);
  encoder.feed_decoder_stream(&back).unwrap();
  assert_eq!(encoder.unacknowledged_sections(), 0);
  assert_eq!(encoder.known_received_count(), encoder.insert_count());
  encoder.check_invariants();
}

// Entries that are used all the time but get old are duplicated rather than left to block
// inserts
#[test]
fn draining_entries_are_duplicated() {
  let mut decoder = decoder(512, 100);
  let mut encoder = encoder(always(), &decoder);
  for round in 0..200u64 {
    let unique = format!("value-{round}");
    let fields =
      [Field::new(b"x-hot", b"always the same"), Field::new(b"x-unique", unique.as_bytes())];
    exchange(&mut encoder, &mut decoder, round * 4, &fields);
  }
  assert!(encoder.stats().duplicates > 0, "{:?}", encoder.stats());
  assert!(encoder.stats().evictions > 0);
}

// Without acknowledgments, tracking is bounded: past the limit, sections are static-only
#[test]
fn tracked_sections_are_bounded() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  // The entry is inserted and acknowledged first, so that references to it do not block
  exchange(&mut encoder, &mut decoder, 0, &[Field::new(b"x-a", b"b")]);
  assert_eq!(encoder.known_received_count(), 1);
  let mut last = Vec::new();
  for stream in 1..=MAX_TRACKED_SECTIONS as u64 + 10 {
    last.clear();
    encoder.encode(stream * 4, [Field::new(b"x-a", b"b")], &mut last);
  }
  assert_eq!(encoder.unacknowledged_sections(), MAX_TRACKED_SECTIONS);
  assert_eq!(&last[..2], &[0, 0]);
  decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
  let mut decoded = FieldList::new();
  decoder.decode_into(1, &last, &mut decoded).unwrap();
  assert_eq!(decoded.to_vec(), [Field::new(b"x-a", b"b")]);
}

// A section that arrives before the inserts it needs blocks, and decodes once they arrive in
// pieces
#[test]
fn interleaved_streams() {
  let mut decoder = decoder(4096, 100);
  let mut encoder = encoder(always(), &decoder);
  let mut section = Vec::new();
  encoder.encode(0, REQUEST, &mut section);
  let mut decoded = FieldList::new();
  assert!(matches!(
    decoder.decode_into(0, &section, &mut decoded).unwrap(),
    DecodeOutcome::Blocked { .. }
  ));
  let bytes = encoder.encoder_stream_output().to_vec();
  encoder.consume_encoder_stream(usize::MAX);
  for chunk in bytes.chunks(3) {
    decoder.feed_encoder_stream(chunk).unwrap();
  }
  assert_eq!(decoder.take_unblocked().collect::<Vec<_>>(), [0]);
  decoder.decode_into(0, &section, &mut decoded).unwrap();
  assert_eq!(decoded.to_vec(), REQUEST);
}

#[test]
fn random_connections_round_trip() {
  let mut state = 0x5851_f42d_4c95_7f2du64;
  let mut data = Vec::new();
  let mut total = check::RoundtripStats::default();
  for round in 0..10_000 {
    data.clear();
    for _ in 0..32 + round % 2048 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      data.push(state as u8);
    }
    total += crate::check::check_roundtrip(&data);
  }
  // Every feature was exercised, many times
  let check::RoundtripStats {
    sections,
    dynamic_sections,
    blocked_decodes,
    inserts,
    duplicates,
    evictions,
    memo_hits,
    capacity_changes,
    cancellations,
  } = total;
  assert!(sections > 300_000, "{total:?}");
  assert!(dynamic_sections > 50_000, "{total:?}");
  assert!(blocked_decodes > 1_000, "{total:?}");
  assert!(inserts > 10_000, "{total:?}");
  assert!(duplicates > 200, "{total:?}");
  assert!(evictions > 1_000, "{total:?}");
  assert!(memo_hits > 1_000, "{total:?}");
  assert!(capacity_changes.0 > 1_000 && capacity_changes.1 > 100, "{total:?}");
  assert!(cancellations > 1_000, "{total:?}");
}

#[test]
fn random_static_round_trip() {
  let mut state = 0x1234_5678_9abc_def1u64;
  let mut data = Vec::new();
  for round in 0..2_000 {
    data.clear();
    for _ in 0..round % 512 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      data.push(state as u8);
    }
    crate::check::check_static(&data);
  }
}
