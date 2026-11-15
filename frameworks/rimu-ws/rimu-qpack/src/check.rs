//! Checks over arbitrary bytes, for tests and the fuzz targets. Whatever the input, the decoder
//! returns fields or an error of the RFC and never panics, keeps its state within its bounds,
//! gives the same results with and without the memo, and decodes what a conformant encoder (a
//! model, or this crate's [`Encoder`]) writes to what that encoder was given.

use crate::{
  DecodeOutcome, DecodedField, Decoder, DecoderConfig, Encoder, EncoderConfig, Error, ErrorCode,
  ErrorKind, Field, FieldList, InsertPolicy, STATIC_TABLE, encode_static, find_exact,
  prefix_int::decode_prefix_int, wire,
};
use alloc::{collections::VecDeque, format, vec::Vec};

type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// Every check of this module over `data`.
pub fn check_bytes(data: &[u8]) {
  check_decoders(data);
  check_model(data);
  let _ = check_roundtrip(data);
  check_static(data);
}

/// What a run of [`check_roundtrip`] exercised.
#[derive(Clone, Copy, Debug, Default)]
pub struct RoundtripStats {
  /// Sections encoded.
  pub sections: u64,
  /// Sections with dynamic references.
  pub dynamic_sections: u64,
  /// Decodes that blocked.
  pub blocked_decodes: u64,
  /// Inserts, Duplicates included.
  pub inserts: u64,
  /// Duplicates.
  pub duplicates: u64,
  /// Evictions at the encoder.
  pub evictions: u64,
  /// Memo replays.
  pub memo_hits: u64,
  /// Capacity changes made, and refused because entries were in use.
  pub capacity_changes: (u64, u64),
  /// Streams cancelled.
  pub cancellations: u64,
}

impl core::ops::AddAssign for RoundtripStats {
  fn add_assign(&mut self, other: Self) {
    self.sections += other.sections;
    self.dynamic_sections += other.dynamic_sections;
    self.blocked_decodes += other.blocked_decodes;
    self.inserts += other.inserts;
    self.duplicates += other.duplicates;
    self.evictions += other.evictions;
    self.memo_hits += other.memo_hits;
    self.capacity_changes.0 += other.capacity_changes.0;
    self.capacity_changes.1 += other.capacity_changes.1;
    self.cancellations += other.cancellations;
  }
}

/// Reads `data` as the choices of a conformant encoder that writes its instructions by hand: its
/// encoder stream and field sections, fed in pieces and out of order, decode to what it put in,
/// and the decoder stream acknowledges exactly what was inserted.
pub fn check_model(data: &[u8]) {
  let mut input = Input(data);
  let max_capacity = [0u32, 100, 220, 4096][usize::from(input.byte() & 3)];
  let max_entries = u64::from(max_capacity / 32);
  let memo_sections = if input.bit() { 4 } else { 0 };
  let mut decoder = Decoder::new(DecoderConfig {
    max_table_capacity: max_capacity,
    blocked_streams: 4,
    memo_sections,
    ..DecoderConfig::default()
  });
  // The encoder starts with the whole capacity, as one that uses the dynamic table does
  let mut model = Model { capacity: max_capacity.into(), entries: VecDeque::new(), inserted: 0 };
  let mut peer = Peer { cancelled: Vec::new(), known_received: 0, unacknowledged: Vec::new() };
  let mut encoder_stream = Vec::new();
  wire::set_capacity(&mut encoder_stream, max_capacity.into());
  // The copy budget of the decoder, which the model stays within
  let budget_cap = u64::from(max_capacity) * 4;
  let mut budget = budget_cap;
  let mut kept: Vec<(u64, Vec<u64>, Vec<u8>, Fields)> = Vec::new();
  let mut stream = 0u64;
  let mut instruction = Vec::new();
  while !input.0.is_empty() {
    instruction.clear();
    match input.byte() % 10 {
      0 => {
        let capacity = u64::from(input.u16()) % (u64::from(max_capacity) + 1);
        wire::set_capacity(&mut instruction, capacity);
        model.capacity = capacity;
        model.evict_down_to(capacity);
        budget = (budget + 64 * instruction.len() as u64).min(budget_cap);
        encoder_stream.extend_from_slice(&instruction);
      }
      1 | 2 => {
        let (name, value, huffman) = (input.word(), input.word(), input.bit());
        if model.insert(&name, &value) {
          wire::insert_literal(&mut instruction, &name, &value, huffman);
          budget = (budget + 64 * instruction.len() as u64).min(budget_cap);
          encoder_stream.extend_from_slice(&instruction);
        }
      }
      3 => {
        let idx = input.byte() % 99;
        let (value, huffman) = (input.word(), input.bit());
        let name = STATIC_TABLE[usize::from(idx)].0;
        if model.insert(name, &value) {
          wire::insert_name_ref(&mut instruction, true, idx.into(), &value, huffman);
          budget = (budget + 64 * instruction.len() as u64).min(budget_cap);
          encoder_stream.extend_from_slice(&instruction);
        }
      }
      4 | 5 => {
        let Some(relative) = model.pick_relative(&mut input) else {
          continue;
        };
        let duplicate = input.bit();
        let (name, old_value) = model.relative(relative).clone();
        let value = if duplicate { old_value } else { input.word() };
        let to_copy = (name.len() + if duplicate { value.len() } else { 0 }) as u64;
        if duplicate {
          wire::duplicate(&mut instruction, relative);
        } else {
          wire::insert_name_ref(&mut instruction, false, relative, &value, input.bit());
        }
        let available = budget + 64 * instruction.len() as u64;
        if available >= to_copy && model.insert(&name, &value) {
          budget = (available - to_copy).min(budget_cap);
          encoder_stream.extend_from_slice(&instruction);
        }
      }
      6 => {
        // A piece of the encoder stream arrives, maybe in the middle of an instruction
        let len = usize::from(input.byte()).min(encoder_stream.len());
        feed(&mut decoder, &mut encoder_stream, len);
      }
      7 => {
        stream += 4;
        decoder.cancel_stream(stream).unwrap();
        if max_capacity > 0 {
          peer.cancelled.push(stream);
        }
      }
      8 => {
        // A section seen before, repeated byte for byte while it is decodable
        let Some((ric, refs, section, expected)) =
          kept.get(usize::from(input.byte()) % kept.len().max(1)).cloned()
        else {
          continue;
        };
        feed(&mut decoder, &mut encoder_stream, usize::MAX);
        if ric > 0 && ric <= model.inserted.saturating_sub(max_entries) {
          continue;
        }
        stream += 4;
        let rslt = decode(&mut decoder, stream, &section);
        if refs.iter().all(|abs| *abs >= model.oldest()) {
          assert_eq!(
            rslt.unwrap(),
            (DecodeOutcome::Done { referenced_dynamic: ric > 0 }, expected)
          );
          if ric > 0 {
            peer.unacknowledged.push((stream, ric));
          }
        } else {
          let err = rslt.unwrap_err();
          assert_eq!(
            err,
            Error::new(ErrorCode::DecompressionFailed, ErrorKind::InvalidDynamicIndex)
          );
          return;
        }
      }
      _ => {
        let (ric, refs, section, expected) = model.section(&mut input, max_entries);
        stream += 4;
        // Before the inserts that it needs, the stream blocks while the decoder can tell the
        // Required Insert Count apart
        if ric > decoder.insert_count() && ric <= decoder.insert_count() + max_entries {
          let rslt = decode(&mut decoder, stream, &section);
          assert_eq!(
            rslt.unwrap(),
            (DecodeOutcome::Blocked { required_insert_count: ric }, Vec::new())
          );
        }
        feed(&mut decoder, &mut encoder_stream, usize::MAX);
        let rslt = decode(&mut decoder, stream, &section);
        assert_eq!(
          rslt.unwrap(),
          (DecodeOutcome::Done { referenced_dynamic: ric > 0 }, expected.clone())
        );
        if ric > 0 {
          peer.unacknowledged.push((stream, ric));
        }
        if kept.len() < 8 {
          kept.push((ric, refs, section, expected));
        }
      }
    }
    decoder.check_invariants();
    if input.bit() {
      peer.read(&mut decoder);
    }
  }
  feed(&mut decoder, &mut encoder_stream, usize::MAX);
  peer.read(&mut decoder);
  decoder.check_invariants();
  // Every insert is acknowledged, every section and every cancellation was seen
  assert_eq!(peer.known_received, decoder.insert_count());
  assert!(peer.unacknowledged.is_empty());
  assert!(peer.cancelled.is_empty());
}

/// Two decoders, one with a memo, fed the same arbitrary encoder stream and sections: they return
/// the same, their errors are those of the RFC, and their state stays consistent.
pub fn check_decoders(data: &[u8]) {
  let Some((setup, mut rest)) = data.split_first() else {
    return;
  };
  let config = DecoderConfig {
    max_table_capacity: [0u32, 64, 220, 1024][usize::from(setup & 3)],
    blocked_streams: u16::from((setup >> 2) & 3),
    memo_sections: 0,
    max_field_section_size: if setup & 0x10 != 0 { Some(200) } else { None },
    max_pending_decoder_stream: 256,
  };
  let mut plain = Decoder::new(config);
  let mut memoized = Decoder::new(DecoderConfig { memo_sections: 4, ..config });
  let mut sections: Vec<Vec<u8>> = Vec::new();
  while let Some((tag, tail)) = rest.split_first() {
    let (chunk, tail) = tail.split_at(usize::from(tag >> 3).min(tail.len()));
    rest = tail;
    let stream = u64::from(tag >> 5) * 4;
    match tag & 7 {
      0 | 1 => {
        let one = plain.feed_encoder_stream(chunk);
        let other = memoized.feed_encoder_stream(chunk);
        assert_eq!(one, other);
        if let Err(err) = one {
          assert!(
            matches!(err.code(), Some(ErrorCode::EncoderStreamError | ErrorCode::ExcessiveLoad)),
            "{err:?}"
          );
          return;
        }
        assert_eq!(
          plain.take_unblocked().collect::<Vec<_>>(),
          memoized.take_unblocked().collect::<Vec<_>>()
        );
      }
      2 | 3 => {
        let section = match sections.get(usize::from(tag >> 4) % sections.len().max(1)) {
          Some(elem) if tag & 1 == 1 => elem.clone(),
          _ => chunk.to_vec(),
        };
        let one = decode(&mut plain, stream, &section);
        let other = decode(&mut memoized, stream, &section);
        assert_eq!(format!("{one:?}"), format!("{other:?}"));
        assert_eq!(plain.decoder_stream_output(), memoized.decoder_stream_output());
        if let Err(err) = one {
          match err.code() {
            Some(code) => {
              assert!(
                matches!(code, ErrorCode::DecompressionFailed | ErrorCode::ExcessiveLoad),
                "{err:?}"
              );
              return;
            }
            None => assert_eq!(err.kind(), ErrorKind::FieldSectionTooLarge),
          }
        }
        if sections.len() < 8 {
          sections.push(section);
        }
      }
      4 => {
        let one = plain.cancel_stream(stream);
        let other = memoized.cancel_stream(stream);
        assert_eq!(one, other);
        if one.is_err() {
          return;
        }
      }
      5 | 6 => {
        let len = usize::from(tag >> 3);
        plain.consume_decoder_stream(len);
        memoized.consume_decoder_stream(len);
      }
      _ => {
        // A new connection on pooled decoders; the kept sections are tried again
        plain.reset(config);
        memoized.reset(DecoderConfig { memo_sections: 4, ..config });
      }
    }
    assert_eq!(plain.decoder_stream_output(), memoized.decoder_stream_output());
    assert_eq!(plain.insert_count(), memoized.insert_count());
    // Memory stays bounded whatever the input: the table storage, 256 bytes of pending output, an
    // incomplete instruction below 4 capacities, scratch for one field and the memo
    assert!(
      memoized.heap_bytes() <= 16 * 1024 + 8 * config.max_table_capacity as usize,
      "{}",
      memoized.heap_bytes()
    );
    plain.check_invariants();
    memoized.check_invariants();
  }
}

/// This crate's [`Encoder`] and [`Decoder`] over a connection whose streams deliver their bytes
/// late, in pieces and out of order, with cancellations and capacity changes: every section
/// decodes to its fields, no stream blocks beyond the limit, no sensitive field is inserted, and
/// in the end every section and every insert is acknowledged.
pub fn check_roundtrip(data: &[u8]) -> RoundtripStats {
  let mut input = Input(data);
  let config = DecoderConfig {
    max_table_capacity: [0u32, 64, 220, 1024, 4096][usize::from(input.byte() % 5)],
    blocked_streams: [0u16, 1, 2, 100][usize::from(input.byte() % 4)],
    memo_sections: [0usize, 4][usize::from(input.byte() % 2)],
    ..DecoderConfig::default()
  };
  let encoder_config = EncoderConfig {
    max_table_capacity: [0u32, 100, 4096][usize::from(input.byte() % 3)],
    insert_policy: [InsertPolicy::Never, InsertPolicy::Repeated, InsertPolicy::Always]
      [usize::from(input.byte() % 3)],
    allow_blocking: input.bit(),
    huffman: input.bit(),
    index_sensitive_names: input.byte() % 4 == 0,
  };
  let mut decoder = Decoder::new(config);
  let mut encoder = Encoder::new(encoder_config);
  encoder.set_peer_settings(decoder.settings()).unwrap();
  let mut to_decoder = Vec::new();
  let mut to_encoder = Vec::new();
  // Sections not decoded yet, per stream in order: stream, section, fields
  let mut pending: Vec<(u64, Vec<u8>, FieldList)> = Vec::new();
  let mut next_stream = 0u64;
  let mut sensitive: Fields = Vec::new();
  let mut decoded = FieldList::new();
  let mut section = Vec::new();
  let mut steps = 0;
  let mut stats = RoundtripStats::default();
  while !input.0.is_empty() {
    steps += 1;
    match input.byte() % 12 {
      0..=3 => {
        // A field section, on a new stream or as the trailers of a pending one
        let stream = match pending.get(usize::from(input.byte()) % pending.len().max(1)) {
          Some(elem) if input.byte() % 4 == 0 => elem.0,
          _ => {
            next_stream += 4;
            next_stream
          }
        };
        let fields = input.fields();
        for field in &fields {
          if field.sensitive {
            sensitive.push((field.name.to_vec(), field.value.to_vec()));
          }
        }
        section.clear();
        encoder.encode(stream, &fields, &mut section);
        encoder.drain_encoder_stream(&mut to_decoder);
        pending.push((stream, section.clone(), fields.iter().copied().collect()));
      }
      4 | 5 => {
        let len = usize::from(input.byte()).min(to_decoder.len());
        decoder.feed_encoder_stream(&to_decoder[..len]).unwrap();
        let _ = to_decoder.drain(..len);
        let _ = decoder.take_unblocked().count();
      }
      6 => {
        decoder.drain_decoder_stream(&mut to_encoder);
        let len = usize::from(input.byte()).min(to_encoder.len());
        encoder.feed_decoder_stream(&to_encoder[..len]).unwrap();
        let _ = to_encoder.drain(..len);
      }
      7 | 8 => {
        // The first pending section of a stream, picked at random
        let Some(idx) = first_of_stream(&pending, input.byte()) else {
          continue;
        };
        let (stream, bytes, fields) = &pending[idx];
        match decoder.decode_into(*stream, bytes, &mut decoded).unwrap() {
          DecodeOutcome::Done { .. } => {
            same_fields(&decoded, fields);
            let _ = pending.remove(idx);
          }
          DecodeOutcome::Blocked { .. } => stats.blocked_decodes += 1,
        }
      }
      9 => {
        // A stream is reset: its sections are dropped
        let Some(idx) = first_of_stream(&pending, input.byte()) else {
          continue;
        };
        let stream = pending[idx].0;
        pending.retain(|el| el.0 != stream);
        decoder.cancel_stream(stream).unwrap();
        stats.cancellations += 1;
      }
      10 => {
        let capacity = u64::from(input.u16()) % (encoder.max_capacity() + 1);
        match encoder.set_capacity(capacity) {
          Ok(()) => stats.capacity_changes.0 += 1,
          Err(err) => {
            assert_eq!(err, Error::local(ErrorKind::EntriesInUse));
            stats.capacity_changes.1 += 1;
          }
        }
      }
      _ => {
        // Everything in flight arrives
        decoder.feed_encoder_stream(&to_decoder).unwrap();
        to_decoder.clear();
        decoder.drain_decoder_stream(&mut to_encoder);
        encoder.feed_decoder_stream(&to_encoder).unwrap();
        to_encoder.clear();
      }
    }
    assert!(decoder.blocked_streams() <= usize::from(config.blocked_streams));
    for (name, value) in encoder.table_fields() {
      assert!(!sensitive.iter().any(|el| el.0 == name && el.1 == value));
    }
    if steps % 8 == 0 {
      decoder.check_invariants();
      encoder.check_invariants();
    }
  }
  // Everything arrives: every pending section decodes, and is acknowledged
  decoder.feed_encoder_stream(&to_decoder).unwrap();
  let _ = decoder.take_unblocked().count();
  while let Some(idx) = first_of_stream(&pending, 0) {
    let (stream, bytes, fields) = pending.remove(idx);
    let outcome = decoder.decode_into(stream, &bytes, &mut decoded).unwrap();
    assert!(matches!(outcome, DecodeOutcome::Done { .. }));
    same_fields(&decoded, &fields);
  }
  decoder.drain_decoder_stream(&mut to_encoder);
  encoder.feed_decoder_stream(&to_encoder).unwrap();
  decoder.check_invariants();
  encoder.check_invariants();
  assert_eq!(encoder.unacknowledged_sections(), 0);
  assert_eq!(decoder.insert_count(), encoder.insert_count());
  assert_eq!(encoder.known_received_count(), encoder.insert_count());
  assert_eq!(decoder.blocked_streams(), 0);
  let encoded = encoder.stats();
  stats.sections = encoded.sections;
  stats.dynamic_sections = encoded.dynamic_sections;
  stats.inserts = encoded.inserts;
  stats.duplicates = encoded.duplicates;
  stats.evictions = encoded.evictions;
  stats.memo_hits = decoder.stats().memo_hits;
  stats
}

/// Fields of arbitrary bytes go through the static encoder and come back.
pub fn check_static(data: &[u8]) {
  let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
  let mut rest = data;
  while let Some((len, tail)) = rest.split_first() {
    let (name, tail) = tail.split_at(usize::from(len & 15).min(tail.len()));
    let (value, tail) = tail.split_at(usize::from(len >> 4).min(tail.len()));
    fields.push((name, value));
    rest = tail;
  }
  let mut section = Vec::new();
  encode_static(fields.iter().copied(), &mut section);
  let mut decoder =
    Decoder::new(DecoderConfig { max_table_capacity: 0, ..DecoderConfig::default() });
  let (outcome, decoded) = decode(&mut decoder, 0, &section).unwrap();
  assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
  let expected: Fields = fields.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
  assert_eq!(decoded, expected);
  // And through a static-only encoder, with Huffman coding
  let mut encoder = Encoder::new(EncoderConfig::static_only());
  section.clear();
  encoder.encode(0, fields.iter().copied(), &mut section);
  assert_eq!(encoder.encoder_stream_output(), b"");
  assert_eq!(decode(&mut decoder, 0, &section).unwrap().1, expected);
}

fn first_of_stream(pending: &[(u64, Vec<u8>, FieldList)], pick: u8) -> Option<usize> {
  if pending.is_empty() {
    return None;
  }
  let stream = pending[usize::from(pick) % pending.len()].0;
  pending.iter().position(|el| el.0 == stream)
}

fn same_fields(decoded: &FieldList, expected: &FieldList) {
  assert_eq!(decoded.len(), expected.len());
  for (got, want) in decoded.iter().zip(expected) {
    assert_eq!((got.name, got.value), (want.name, want.value));
    // A sensitive field keeps its never-indexed bit, unless the static table has it whole
    if want.sensitive {
      assert!(got.sensitive || find_exact(want.name, want.value).is_some());
    }
  }
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
  // Nothing goes to the sink of a blocked stream
  if matches!(outcome, DecodeOutcome::Blocked { .. }) {
    assert!(fields.is_empty());
  }
  Ok((outcome, fields))
}

// Gives the decoder up to `len` bytes of the encoder stream, which may end in the middle of an
// instruction.
fn feed(decoder: &mut Decoder, encoder_stream: &mut Vec<u8>, len: usize) {
  let len = len.min(encoder_stream.len());
  decoder.feed_encoder_stream(&encoder_stream[..len]).unwrap();
  let _ = encoder_stream.drain(..len);
  let _ = decoder.take_unblocked().count();
}

struct Input<'bytes>(&'bytes [u8]);

impl Input<'_> {
  fn bit(&mut self) -> bool {
    self.byte() & 1 == 1
  }

  fn byte(&mut self) -> u8 {
    let Some((first, rest)) = self.0.split_first() else {
      return 0;
    };
    self.0 = rest;
    *first
  }

  fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  // A field name or value: lower-case letters, digits and a few symbols, 0 to 47 bytes
  fn word(&mut self) -> Vec<u8> {
    let len = usize::from(self.byte() % 48);
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-:/._~ ";
    (0..len).map(|_| alphabet[usize::from(self.byte() % 43)]).collect()
  }

  // A header list of up to 12 fields from a vocabulary, so that fields repeat, with fresh values
  // now and then, sensitive fields, and values too large for small tables
  fn fields(&mut self) -> Vec<Field<'static>> {
    const VOCABULARY: [(&[u8], &[u8]); 24] = [
      (b":method", b"GET"),
      (b":method", b"POST"),
      (b":scheme", b"https"),
      (b":authority", b"www.example.com"),
      (b":authority", b"api.example.com"),
      (b":path", b"/"),
      (b":path", b"/index.html"),
      (b":path", b"/api/v1/items?page=2"),
      (b":status", b"200"),
      (b":status", b"201"),
      (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) rimu/1.0"),
      (b"accept", b"text/html,application/xhtml+xml"),
      (b"accept-encoding", b"gzip, deflate, br"),
      (b"accept-language", b"en-US,en;q=0.9"),
      (b"content-type", b"application/json"),
      (b"content-type", b"text/plain"),
      (b"x-request-id", b"7f3a9c"),
      (b"x-forwarded-for", b"203.0.113.7"),
      (b"cache-control", b"no-cache"),
      (b"x-custom-header", b"some fairly long value that takes room in a small table"),
      (b"cookie", b"session=8c1f2b; theme=dark"),
      (b"authorization", b"Bearer eyJhbGciOiJIUzI1NiJ9"),
      (b"x-empty", b""),
      (b"server", b"rimu"),
    ];
    const FRESH: [&[u8]; 8] = [b"a1", b"b22", b"c333", b"d4444", b"e5", b"f66", b"g777", b"h8888"];
    const LARGE: &[u8] = &[b'L'; 300];
    let count = usize::from(self.byte() % 13);
    (0..count)
      .map(|_| {
        let pick = self.byte();
        match pick % 16 {
          0 => Field::new(b"x-fresh", FRESH[usize::from(self.byte() % 8)]),
          1 => Field::sensitive(b"x-secret", FRESH[usize::from(self.byte() % 8)]),
          2 => Field::new(b"x-large", LARGE),
          _ => {
            let (name, value) = VOCABULARY[usize::from(self.byte()) % VOCABULARY.len()];
            Field::new(name, value)
          }
        }
      })
      .collect()
  }
}

// The dynamic table as the encoder sees it
struct Model {
  capacity: u64,
  entries: VecDeque<(Vec<u8>, Vec<u8>)>,
  inserted: u64,
}

impl Model {
  fn evict_down_to(&mut self, size: u64) {
    while self.size() > size {
      let _ = self.entries.pop_front();
    }
  }

  // Inserts if the entry fits, as a conformant encoder does
  fn insert(&mut self, name: &[u8], value: &[u8]) -> bool {
    let size = (name.len() + value.len()) as u64 + 32;
    if size > self.capacity {
      return false;
    }
    self.evict_down_to(self.capacity - size);
    self.entries.push_back((name.to_vec(), value.to_vec()));
    self.inserted += 1;
    true
  }

  fn oldest(&self) -> u64 {
    self.inserted - self.entries.len() as u64
  }

  fn pick_relative(&self, input: &mut Input<'_>) -> Option<u64> {
    if self.entries.is_empty() {
      return None;
    }
    Some(u64::from(input.byte()) % self.entries.len() as u64)
  }

  fn relative(&self, relative: u64) -> &(Vec<u8>, Vec<u8>) {
    &self.entries[self.entries.len() - 1 - relative as usize]
  }

  fn absolute(&self, abs: u64) -> &(Vec<u8>, Vec<u8>) {
    &self.entries[(abs - self.oldest()) as usize]
  }

  // A field section of up to four field lines of every representation, with its Required Insert
  // Count, the absolute indices that it references and the fields that it decodes to
  fn section(&self, input: &mut Input<'_>, max_entries: u64) -> (u64, Vec<u64>, Vec<u8>, Fields) {
    enum Line {
      Indexed(u64),
      Literal(Vec<u8>, Vec<u8>),
      NameRef(u64, Vec<u8>),
      StaticIndexed(u8),
      StaticNameRef(u8, Vec<u8>),
    }
    let mut lines = Vec::new();
    let mut refs = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..1 + input.byte() % 4 {
      let choice = input.byte() % 5;
      let live = !self.entries.is_empty();
      let abs =
        if live { self.oldest() + u64::from(input.byte()) % self.entries.len() as u64 } else { 0 };
      let line = match choice {
        0 if live => Line::Indexed(abs),
        1 if live => Line::NameRef(abs, input.word()),
        2 => Line::Literal(input.word(), input.word()),
        3 => Line::StaticNameRef(input.byte() % 99, input.word()),
        _ => Line::StaticIndexed(input.byte() % 99),
      };
      match &line {
        Line::Indexed(abs) => {
          refs.push(*abs);
          expected.push(self.absolute(*abs).clone());
        }
        Line::Literal(name, value) => expected.push((name.clone(), value.clone())),
        Line::NameRef(abs, value) => {
          refs.push(*abs);
          expected.push((self.absolute(*abs).0.clone(), value.clone()));
        }
        Line::StaticIndexed(idx) => {
          let (name, value) = STATIC_TABLE[usize::from(*idx)];
          expected.push((name.to_vec(), value.to_vec()));
        }
        Line::StaticNameRef(idx, value) => {
          expected.push((STATIC_TABLE[usize::from(*idx)].0.to_vec(), value.clone()));
        }
      }
      lines.push(line);
    }
    let ric = refs.iter().max().map_or(0, |el| el + 1);
    let base = u64::from(input.byte() % 4) + ric.saturating_sub(u64::from(input.byte() % 4));
    let mut section = Vec::new();
    wire::prefix(&mut section, ric, base, max_entries);
    for line in lines {
      let (never_indexed, huffman) = (input.bit(), input.bit());
      match line {
        Line::Indexed(abs) if abs < base => wire::indexed(&mut section, false, base - 1 - abs),
        Line::Indexed(abs) => wire::indexed_post_base(&mut section, abs - base),
        Line::Literal(name, value) => {
          wire::literal(&mut section, never_indexed, &name, &value, huffman)
        }
        Line::NameRef(abs, value) if abs < base => {
          wire::name_ref(&mut section, false, never_indexed, base - 1 - abs, &value, huffman)
        }
        Line::NameRef(abs, value) => {
          wire::post_base_name_ref(&mut section, never_indexed, abs - base, &value, huffman)
        }
        Line::StaticIndexed(idx) => wire::indexed(&mut section, true, idx.into()),
        Line::StaticNameRef(idx, value) => {
          wire::name_ref(&mut section, true, never_indexed, idx.into(), &value, huffman)
        }
      }
    }
    (ric, refs, section, expected)
  }

  fn size(&self) -> u64 {
    self.entries.iter().map(|(name, value)| (name.len() + value.len()) as u64 + 32).sum()
  }
}

// The encoder side of the decoder stream: what it learns from the instructions
struct Peer {
  cancelled: Vec<u64>,
  known_received: u64,
  unacknowledged: Vec<(u64, u64)>,
}

impl Peer {
  fn read(&mut self, decoder: &mut Decoder) {
    let mut out = Vec::new();
    decoder.drain_decoder_stream(&mut out);
    let mut rest = out.as_slice();
    while let Some(first) = rest.first().copied() {
      let prefix_bits = if first & 0b1000_0000 != 0 { 7 } else { 6 };
      let (value, len) = decode_prefix_int(rest, prefix_bits).unwrap().unwrap();
      rest = &rest[len..];
      if first & 0b1000_0000 != 0 {
        // Section Acknowledgment: of a section of the stream that referenced the dynamic table
        let idx = self.unacknowledged.iter().position(|el| el.0 == value).unwrap();
        let (_, ric) = self.unacknowledged.remove(idx);
        self.known_received = self.known_received.max(ric);
      } else if first & 0b0100_0000 != 0 {
        let idx = self.cancelled.iter().position(|el| *el == value).unwrap();
        let _ = self.cancelled.remove(idx);
      } else {
        // Insert Count Increment: never 0, never past the inserts (RFC 9204 section 4.4.3)
        assert!(value > 0);
        self.known_received += value;
      }
      assert!(self.known_received <= decoder.insert_count());
    }
  }
}
