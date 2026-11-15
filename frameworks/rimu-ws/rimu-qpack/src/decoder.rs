//! The QPACK decoder (RFC 9204): the dynamic table that the peer's encoder stream fills, the field
//! sections of request and push streams, and the instructions of the decoder stream.
//!
//! The table stores names and values in a byte ring of the advertised capacity and their lengths
//! in a ring of capacity / 32 slots, both allocated once by [`Decoder::new`], with a staging
//! buffer of the capacity where an insert is put together before it evicts anything: an insert
//! can name or duplicate an entry that it evicts (RFC 9204 section 3.2.2). An entry may wrap
//! around the end of the byte ring; it is then copied into a scratch buffer when a field section
//! references it. Fields are otherwise given to the caller borrowed from the section, the static
//! table or the ring, without copies.
//!
//! Every length read from the wire is checked against the bytes present before anything is
//! copied or reserved, and Huffman output is bounded by 8/5 of its input. Bytes copied out of the
//! table by Duplicates and dynamic name references, which a one-byte instruction can multiply,
//! come from a budget that each instruction refills by 64 bytes per byte of itself, up to four
//! capacities.

use crate::{
  DecodedField, Error, ErrorKind, Result, Settings,
  decode_memo::DecodeMemo,
  huffman::{self, HuffmanError},
  prefix_int::{decode_prefix_int, push_prefix_int},
  static_table::{STATIC_TABLE, StaticRef},
};
use alloc::vec::Vec;
use core::mem;

/// The bytes that an entry adds to the size of the table on top of its name and value (RFC 9204
/// section 3.2.1).
pub(crate) const ENTRY_OVERHEAD: u64 = 32;
/// Copy budget refilled per encoder-stream byte received.
const COPY_BUDGET_PER_BYTE: u64 = 64;
/// The copy budget holds at most this many advertised capacities.
const COPY_BUDGET_CAPACITIES: u64 = 4;

/// The configuration of a [`Decoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderConfig {
  /// The `SETTINGS_QPACK_MAX_TABLE_CAPACITY` to advertise: the most bytes of dynamic table that
  /// the peer's encoder may use. The decoder allocates about twice this. Default 4096.
  pub max_table_capacity: u32,
  /// The `SETTINGS_QPACK_BLOCKED_STREAMS` to advertise: the most streams that may wait for
  /// inserts at once. Default 100.
  pub blocked_streams: u16,
  /// The number of field sections that the decode memo keeps, 0 to disable it. Default 8.
  pub memo_sections: usize,
  /// The largest field section to accept, counted as RFC 9114 section 4.2.2 does; larger ones
  /// fail with a local [`ErrorKind::FieldSectionTooLarge`]. Default: no limit.
  pub max_field_section_size: Option<u64>,
  /// The most decoder-stream bytes that may wait for [`Decoder::consume_decoder_stream`];
  /// more is an `H3_EXCESSIVE_LOAD`. Default 64 KiB.
  pub max_pending_decoder_stream: usize,
}

impl Default for DecoderConfig {
  #[inline]
  fn default() -> Self {
    Self {
      max_table_capacity: 4096,
      blocked_streams: 100,
      memo_sections: 8,
      max_field_section_size: None,
      max_pending_decoder_stream: 64 * 1024,
    }
  }
}

impl DecoderConfig {
  /// The settings to advertise to the peer.
  #[inline]
  pub const fn settings(&self) -> Settings {
    Settings {
      max_table_capacity: self.max_table_capacity as u64,
      blocked_streams: self.blocked_streams as u64,
    }
  }
}

/// What became of a field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeOutcome {
  /// Every field went to the sink.
  Done {
    /// The section referenced the dynamic table; its Section Acknowledgment is queued.
    referenced_dynamic: bool,
  },
  /// The section needs inserts that did not arrive yet: nothing went to the sink. Keep the
  /// section and decode it again once the stream appears in [`Decoder::take_unblocked`].
  Blocked {
    /// The absolute Required Insert Count of the section.
    required_insert_count: u64,
  },
}

/// Counters of a decoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecoderStats {
  /// Field sections decoded (or replayed), blocked attempts excluded.
  pub sections: u64,
  /// Of [`Self::sections`], those that the decode memo replayed.
  pub memo_hits: u64,
}

/// Where the name and the value of a dynamic table entry are in the byte ring.
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
  name_len: u32,
  start: u32,
  value_len: u32,
}

impl Entry {
  fn size(self) -> u64 {
    u64::from(self.name_len) + u64::from(self.value_len) + ENTRY_OVERHEAD
  }
}

/// The parts of a field section prefix (RFC 9204 section 4.5.1).
#[derive(Clone, Copy, Debug)]
struct Prefix {
  base: u64,
  lines: usize,
  ric: u64,
}

/// A name or a value of a field line: borrowed from the section, the static table or the byte
/// ring, or written into the scratch buffer.
#[derive(Clone, Copy, Debug)]
enum Part<'any> {
  Borrowed(&'any [u8]),
  Scratch(usize, usize),
}

impl<'any> Part<'any> {
  fn get<'rslt>(self, scratch: &'rslt [u8]) -> &'rslt [u8]
  where
    'any: 'rslt,
  {
    match self {
      Self::Borrowed(bytes) => bytes,
      Self::Scratch(start, end) => scratch.get(start..end).unwrap_or_default(),
    }
  }
}

/// Why the decoding of a section stopped.
enum Stop<E> {
  Qpack(Error),
  Sink(E),
}

impl<E> From<Error> for Stop<E> {
  fn from(error: Error) -> Self {
    Self::Qpack(error)
  }
}

/// The QPACK decoder of one HTTP/3 connection.
///
/// Sans-IO: feed it the bytes of the peer's encoder stream with [`Self::feed_encoder_stream`],
/// give it each field section with [`Self::decode`], and write what
/// [`Self::decoder_stream_output`] holds to this side's decoder stream.
#[derive(Clone, Debug)]
pub struct Decoder {
  /// Blocked streams and the Required Insert Count that they wait for.
  blocked: Vec<(u64, u64)>,
  /// The capacity that the encoder set, at most `max_capacity`.
  capacity: u64,
  config: DecoderConfig,
  /// Bytes that may still be copied out of the table.
  copy_budget: u64,
  entries: Vec<Entry>,
  entries_head: usize,
  entries_len: usize,
  insert_count: u64,
  /// The incomplete encoder-stream instruction that waits for its next bytes.
  input: Vec<u8>,
  /// Inserts that the encoder knows of from what was queued on the decoder stream, apart from a
  /// trailing Insert Count Increment.
  known_received: u64,
  max_capacity: u64,
  max_entries: u64,
  memo: DecodeMemo,
  out: Vec<u8>,
  out_start: usize,
  /// The Insert Count Increment at the end of `out`, if it was not written yet: where it starts
  /// and the insert count that it acknowledges. It is rewritten when more is acknowledged.
  pending_increment: Option<(usize, u64)>,
  ring: Vec<u8>,
  ring_head: usize,
  ring_len: usize,
  scratch: Vec<u8>,
  size: u64,
  /// An insert is put together here before it goes into the ring.
  staging: Vec<u8>,
  stats: DecoderStats,
  /// Streams that were blocked and can now be decoded.
  unblocked: Vec<u64>,
}

impl Decoder {
  /// A decoder for `config`. The table storage is allocated here, once: twice the capacity in
  /// bytes and 12 bytes per 32 of capacity.
  pub fn new(config: DecoderConfig) -> Self {
    let mut this = Self {
      blocked: Vec::new(),
      capacity: 0,
      config,
      copy_budget: 0,
      entries: Vec::new(),
      entries_head: 0,
      entries_len: 0,
      insert_count: 0,
      input: Vec::new(),
      known_received: 0,
      max_capacity: 0,
      max_entries: 0,
      memo: DecodeMemo::new(0),
      out: Vec::new(),
      out_start: 0,
      pending_increment: None,
      ring: Vec::new(),
      ring_head: 0,
      ring_len: 0,
      scratch: Vec::new(),
      size: 0,
      staging: Vec::new(),
      stats: DecoderStats::default(),
      unblocked: Vec::new(),
    };
    this.reset(config);
    this
  }

  /// Makes this decoder a new one for `config`, as [`Self::new`] does, in the storage that it has:
  /// nothing is allocated when the new limits are at most those that it had. For pooling
  /// decoders across connections.
  pub fn reset(&mut self, config: DecoderConfig) {
    let ring_len = config.max_table_capacity as usize;
    let max_entries = config.max_table_capacity / 32;
    self.config = config;
    self.blocked.clear();
    self.blocked.reserve(config.blocked_streams.into());
    self.entries.clear();
    self.entries.resize(max_entries as usize, Entry::default());
    self.input.clear();
    self.memo.clear();
    if self.memo.is_enabled() != (config.memo_sections > 0) {
      self.memo = DecodeMemo::new(config.memo_sections);
    }
    self.out.clear();
    // Zeroed: no byte of the previous table stays
    self.ring.clear();
    self.ring.resize(ring_len, 0);
    self.scratch.clear();
    self.staging.clear();
    self.staging.reserve(ring_len);
    self.unblocked.clear();
    self.capacity = 0;
    self.entries_head = 0;
    self.entries_len = 0;
    self.insert_count = 0;
    self.known_received = 0;
    self.max_capacity = config.max_table_capacity.into();
    self.max_entries = max_entries.into();
    self.out_start = 0;
    self.pending_increment = None;
    self.ring_head = 0;
    self.ring_len = 0;
    self.size = 0;
    self.copy_budget = self.max_capacity * COPY_BUDGET_CAPACITIES;
    self.stats = DecoderStats::default();
  }

  /// The configuration of this decoder.
  #[inline]
  pub const fn config(&self) -> &DecoderConfig {
    &self.config
  }

  /// The settings to advertise to the peer.
  #[inline]
  pub const fn settings(&self) -> Settings {
    self.config.settings()
  }

  /// The bytes that the storage of the decoder takes on the heap.
  pub fn heap_bytes(&self) -> usize {
    self.blocked.capacity() * size_of::<(u64, u64)>()
      + self.entries.capacity() * size_of::<Entry>()
      + self.input.capacity()
      + self.out.capacity()
      + self.ring.capacity()
      + self.scratch.capacity()
      + self.staging.capacity()
      + self.unblocked.capacity() * size_of::<u64>()
      + self.memo.heap_bytes()
  }

  /// Inserts and duplications applied so far.
  #[inline]
  pub const fn insert_count(&self) -> u64 {
    self.insert_count
  }

  /// The capacity of the dynamic table that the encoder set.
  #[inline]
  pub const fn table_capacity(&self) -> u64 {
    self.capacity
  }

  /// The size of the dynamic table: names, values and 32 per entry.
  #[inline]
  pub const fn table_size(&self) -> u64 {
    self.size
  }

  /// The number of entries in the dynamic table.
  #[inline]
  pub const fn table_len(&self) -> usize {
    self.entries_len
  }

  /// The number of streams blocked now.
  #[inline]
  pub const fn blocked_streams(&self) -> usize {
    self.blocked.len()
  }

  /// Counters of decoded and replayed sections.
  #[inline]
  pub const fn stats(&self) -> DecoderStats {
    self.stats
  }

  /// Applies the instructions of the peer's encoder stream in `bytes`, which follow those given
  /// before. An instruction that `bytes` does not hold whole is kept until the next call.
  ///
  /// Errors are a `QPACK_ENCODER_STREAM_ERROR`, or an `H3_EXCESSIVE_LOAD` when Duplicates and
  /// dynamic name references copy more out of the table than the instructions received allow:
  /// each instruction adds 64 bytes per byte of itself to a budget of at most four capacities. A
  /// conformant encoder stays far below it. After an error the decoder must not be used again.
  pub fn feed_encoder_stream(&mut self, bytes: &[u8]) -> Result<()> {
    let before = self.insert_count;
    if self.input.is_empty() {
      let consumed = self.apply_instructions(bytes)?;
      self.input.extend_from_slice(&bytes[consumed..]);
    } else {
      let mut input = mem::take(&mut self.input);
      input.extend_from_slice(bytes);
      let rslt = self.apply_instructions(&input);
      let consumed = match rslt {
        Ok(elem) => elem,
        Err(err) => {
          self.input = input;
          return Err(err);
        }
      };
      let _ = input.drain(..consumed);
      self.input = input;
    }
    // A valid incomplete instruction is shorter than its Huffman strings of at most 30 bits per
    // byte of an entry that fits
    if self.input.len() as u64 > self.max_capacity * 4 + 64 {
      return Err(Error::excessive_load(ErrorKind::StreamBacklog));
    }
    if self.insert_count != before {
      let insert_count = self.insert_count;
      let Self { blocked, unblocked, .. } = self;
      blocked.retain(|(stream, ric)| {
        if *ric <= insert_count {
          unblocked.push(*stream);
          false
        } else {
          true
        }
      });
    }
    self.refresh_increment()
  }

  /// Applies the whole instructions at the start of `bytes`; returns the bytes consumed.
  fn apply_instructions(&mut self, bytes: &[u8]) -> Result<usize> {
    let mut consumed = 0usize;
    while consumed < bytes.len() {
      let Some(len) = self.encoder_instruction(&bytes[consumed..])? else {
        break;
      };
      consumed += len;
    }
    Ok(consumed)
  }

  /// The streams that were blocked and whose sections can now be decoded, since the last call.
  #[inline]
  pub fn take_unblocked(&mut self) -> alloc::vec::Drain<'_, u64> {
    self.unblocked.drain(..)
  }

  /// Decodes the field section `section` of stream `stream`, giving each field to `sink` in order.
  ///
  /// A section that references the dynamic table queues its Section Acknowledgment. A section
  /// that needs inserts that did not arrive yet blocks the stream: the caller keeps the section
  /// and decodes it again later (see [`DecodeOutcome::Blocked`]).
  ///
  /// Errors of the section are a `QPACK_DECOMPRESSION_FAILED`. An error of `sink` stops the
  /// decoding and is returned; it and [`ErrorKind::FieldSectionTooLarge`] are local: the section
  /// is acknowledged as if decoded (the encoder can release its references), and the caller
  /// resets the stream or answers it with an error.
  pub fn decode<E, F>(
    &mut self,
    stream: u64,
    section: &[u8],
    mut sink: F,
  ) -> Result<DecodeOutcome, E>
  where
    E: From<Error>,
    F: FnMut(DecodedField<'_>) -> Result<(), E>,
  {
    let prefix = self.prefix(section)?;
    if prefix.ric > self.insert_count {
      return Ok(self.block(stream, prefix.ric)?);
    }
    self.forget_stream(stream);
    self.stats.sections += 1;
    let limit = self.config.max_field_section_size.unwrap_or(u64::MAX);
    let mut total = 0u64;
    let mut checked_sink = |field: DecodedField<'_>| -> Result<(), Stop<E>> {
      total = total.saturating_add(field.name.len() as u64 + field.value.len() as u64 + 32);
      if total > limit {
        return Err(Stop::Qpack(Error::local(ErrorKind::FieldSectionTooLarge)));
      }
      sink(field).map_err(Stop::Sink)
    };
    let oldest_live = self.oldest_live();
    let rslt = if let Some(fields) = self.memo.lookup(prefix.ric, section, oldest_live) {
      self.stats.memo_hits += 1;
      fields.into_iter().try_for_each(|(name, value, static_ref, sensitive)| {
        checked_sink(DecodedField { name, value, sensitive, static_ref })
      })
    } else {
      let mut memo = mem::take(&mut self.memo);
      let mut scratch = mem::take(&mut self.scratch);
      let mut recorder = memo.insert(prefix.ric, section);
      let rslt = self.decode_lines(prefix, section, &mut scratch, &mut |field| {
        if let Some(elem) = &mut recorder {
          elem.push(field.name, field.value, field.static_ref, field.sensitive);
        }
        checked_sink(field)
      });
      if let (Ok(lowest), Some(elem)) = (&rslt, recorder) {
        elem.seal(*lowest);
      }
      self.memo = memo;
      self.scratch = scratch;
      rslt.map(|_| ())
    };
    match rslt {
      Ok(()) => Ok(self.finish(stream, prefix.ric)?),
      Err(Stop::Qpack(err)) if err.code().is_some() => Err(err.into()),
      Err(stop) => {
        let _ = self.finish(stream, prefix.ric)?;
        Err(match stop {
          Stop::Qpack(err) => err.into(),
          Stop::Sink(err) => err,
        })
      }
    }
  }

  /// [`Self::decode`] into a [`crate::FieldList`], which is cleared first.
  pub fn decode_into(
    &mut self,
    stream: u64,
    section: &[u8],
    list: &mut crate::FieldList,
  ) -> Result<DecodeOutcome> {
    list.clear();
    self.decode(stream, section, |field: DecodedField<'_>| {
      list.push(field.as_field());
      Ok(())
    })
  }

  /// Stream `stream` was reset, or its reading abandoned: queues a Stream Cancellation (RFC 9204
  /// section 4.4.2) and forgets the stream if it is blocked. Without a dynamic table nothing is
  /// queued (RFC 9204 section 2.2.2.2).
  pub fn cancel_stream(&mut self, stream: u64) -> Result<()> {
    self.forget_stream(stream);
    if self.max_capacity == 0 {
      return Ok(());
    }
    self.retract_increment();
    self.push_instruction(stream, 6, 0b0100_0000)?;
    self.refresh_increment()
  }

  /// The decoder-stream bytes that wait to be written: Section Acknowledgments, Stream
  /// Cancellations and at most one Insert Count Increment, at the end.
  #[inline]
  pub fn decoder_stream_output(&self) -> &[u8] {
    &self.out[self.out_start..]
  }

  /// `n` bytes of [`Self::decoder_stream_output`] were written.
  pub fn consume_decoder_stream(&mut self, n: usize) {
    let len = self.out.len();
    self.out_start = (self.out_start + n).min(len);
    if let Some((start, acknowledged)) = self.pending_increment
      && self.out_start > start
    {
      self.known_received = acknowledged;
      self.pending_increment = None;
    }
    if self.out_start == len {
      self.out.clear();
      self.out_start = 0;
    } else if self.out_start >= len / 2 {
      let start = self.out_start;
      self.out.copy_within(start.., 0);
      self.out.truncate(len - start);
      if let Some((pending, _)) = &mut self.pending_increment {
        *pending -= start;
      }
      self.out_start = 0;
    }
  }

  /// Appends [`Self::decoder_stream_output`] to `out` and consumes it.
  pub fn drain_decoder_stream(&mut self, out: &mut Vec<u8>) {
    out.extend_from_slice(self.decoder_stream_output());
    self.consume_decoder_stream(usize::MAX);
  }

  // Blocks `stream` on `ric`; a stream that blocks again keeps its slot.
  fn block(&mut self, stream: u64, ric: u64) -> Result<DecodeOutcome> {
    if let Some(elem) = self.blocked.iter_mut().find(|el| el.0 == stream) {
      elem.1 = ric;
    } else {
      if self.blocked.len() >= usize::from(self.config.blocked_streams) {
        return Err(Error::decompression(ErrorKind::TooManyBlockedStreams));
      }
      if let Some(idx) = self.unblocked.iter().position(|el| *el == stream) {
        let _ = self.unblocked.swap_remove(idx);
      }
      self.blocked.push((stream, ric));
    }
    Ok(DecodeOutcome::Blocked { required_insert_count: ric })
  }

  // Copies the referenced part of the byte ring into `scratch` if it wraps around the end.
  fn ring_part<'this>(&'this self, start: usize, len: usize, scratch: &mut Vec<u8>) -> Part<'this> {
    let (first, second) = ring_slices(&self.ring, start, len);
    if second.is_empty() {
      return Part::Borrowed(first);
    }
    let begin = scratch.len();
    scratch.extend_from_slice(first);
    scratch.extend_from_slice(second);
    Part::Scratch(begin, scratch.len())
  }

  // The entry of absolute index `abs`, if it is in the table.
  fn entry(&self, abs: u64) -> Option<Entry> {
    let offset = abs.checked_sub(self.oldest_live())?;
    if abs >= self.insert_count {
      return None;
    }
    // The offset is below the number of entries: the slot wraps at most once
    let slot = self.entries_head + usize::try_from(offset).ok()?;
    let len = self.entries.len();
    self.entries.get(if slot >= len { slot - len } else { slot }).copied()
  }

  // The entry of the absolute index of a reference in a field section, which must be below the
  // Required Insert Count and not evicted.
  fn section_entry(&self, prefix: Prefix, abs: Option<u64>) -> Result<(u64, Entry)> {
    if let Some(abs) = abs
      && abs < prefix.ric
      && let Some(entry) = self.entry(abs)
    {
      return Ok((abs, entry));
    }
    Err(Error::decompression(ErrorKind::InvalidDynamicIndex))
  }

  // Decodes the field lines; returns the lowest absolute index referenced (`u64::MAX` for none).
  fn decode_lines<'this, E>(
    &'this self,
    prefix: Prefix,
    section: &'this [u8],
    scratch: &mut Vec<u8>,
    sink: &mut dyn FnMut(DecodedField<'_>) -> Result<(), Stop<E>>,
  ) -> Result<u64, Stop<E>> {
    let mut lowest = u64::MAX;
    let mut highest = None;
    let mut rest = &section[prefix.lines..];
    while let [first, ..] = rest {
      let first = *first;
      scratch.clear();
      let mut track = |abs: u64| {
        lowest = lowest.min(abs);
        highest = highest.max(Some(abs));
      };
      let mut static_ref = None;
      let mut sensitive = false;
      let (name, value, len) = if first & 0b1000_0000 != 0 {
        // Indexed Field Line (RFC 9204 section 4.5.2)
        let (idx, len) = section_int(rest, 6)?;
        if first & 0b0100_0000 != 0 {
          let (name, value) = static_entry(idx)?;
          static_ref = make_static_ref(idx, true);
          (Part::Borrowed(name), Part::Borrowed(value), len)
        } else {
          let (abs, entry) = self.section_entry(prefix, relative(prefix.base, idx))?;
          track(abs);
          let (name, value) = self.entry_parts(entry, scratch);
          (name, value, len)
        }
      } else if first & 0b0100_0000 != 0 {
        // Literal Field Line with Name Reference (section 4.5.4)
        sensitive = first & 0b0010_0000 != 0;
        let (idx, idx_len) = section_int(rest, 4)?;
        let name = if first & 0b0001_0000 != 0 {
          static_ref = make_static_ref(idx, false);
          Part::Borrowed(static_entry(idx)?.0)
        } else {
          let (abs, entry) = self.section_entry(prefix, relative(prefix.base, idx))?;
          track(abs);
          self.ring_part(entry.start as usize, entry.name_len as usize, scratch)
        };
        let (value, value_len) = section_string(&rest[idx_len..], 8, scratch)?;
        (name, value, idx_len + value_len)
      } else if first & 0b0010_0000 != 0 {
        // Literal Field Line with Literal Name (section 4.5.6)
        sensitive = first & 0b0001_0000 != 0;
        let (name, name_len) = section_string(rest, 4, scratch)?;
        let (value, value_len) = section_string(&rest[name_len..], 8, scratch)?;
        (name, value, name_len + value_len)
      } else if first & 0b0001_0000 != 0 {
        // Indexed Field Line with Post-Base Index (section 4.5.3)
        let (idx, len) = section_int(rest, 4)?;
        let (abs, entry) = self.section_entry(prefix, prefix.base.checked_add(idx))?;
        track(abs);
        let (name, value) = self.entry_parts(entry, scratch);
        (name, value, len)
      } else {
        // Literal Field Line with Post-Base Name Reference (section 4.5.5)
        sensitive = first & 0b0000_1000 != 0;
        let (idx, idx_len) = section_int(rest, 3)?;
        let (abs, entry) = self.section_entry(prefix, prefix.base.checked_add(idx))?;
        track(abs);
        let name = self.ring_part(entry.start as usize, entry.name_len as usize, scratch);
        let (value, value_len) = section_string(&rest[idx_len..], 8, scratch)?;
        (name, value, idx_len + value_len)
      };
      let bytes = scratch.as_slice();
      sink(DecodedField { name: name.get(bytes), value: value.get(bytes), sensitive, static_ref })?;
      rest = &rest[len..];
    }
    // The Required Insert Count must be the one that the references need (section 2.1.2)
    let needed = highest.map_or(0, |el: u64| el + 1);
    if needed != prefix.ric {
      return Err(Error::decompression(ErrorKind::RequiredInsertCountTooLarge).into());
    }
    Ok(lowest)
  }

  // Applies the encoder instruction at the start of `bytes`, if it is whole.
  fn encoder_instruction(&mut self, bytes: &[u8]) -> Result<Option<usize>> {
    let Some(first) = bytes.first().copied() else {
      return Ok(None);
    };
    if first & 0b1000_0000 != 0 {
      // Insert with Name Reference (RFC 9204 section 4.3.2)
      let is_static = first & 0b0100_0000 != 0;
      let Some((idx, idx_len)) = encoder_int(bytes, 6)? else {
        return Ok(None);
      };
      let name_len = if is_static {
        static_name(idx)?.len()
      } else {
        self.encoder_entry(idx)?.name_len as usize
      };
      let Some((value, value_len)) = self.encoder_string(&bytes[idx_len..], 8, name_len)? else {
        return Ok(None);
      };
      self.staging.clear();
      if is_static {
        self.credit_copy_budget(idx_len + value_len);
        self.staging.extend_from_slice(static_name(idx)?);
      } else {
        self.spend_copy_budget(name_len, idx_len + value_len)?;
        let entry = self.encoder_entry(idx)?;
        self.stage_ring(entry.start as usize, entry.name_len as usize);
      }
      self.stage_string(value)?;
      self.insert(name_len)?;
      Ok(Some(idx_len + value_len))
    } else if first & 0b0100_0000 != 0 {
      // Insert with Literal Name (section 4.3.3)
      let Some((name, name_len)) = self.encoder_string(bytes, 6, 0)? else {
        return Ok(None);
      };
      let name_min = string_min_len(name);
      let Some((value, value_len)) = self.encoder_string(&bytes[name_len..], 8, name_min)? else {
        return Ok(None);
      };
      self.credit_copy_budget(name_len + value_len);
      self.staging.clear();
      self.stage_string(name)?;
      let staged_name_len = self.staging.len();
      self.stage_string(value)?;
      self.insert(staged_name_len)?;
      Ok(Some(name_len + value_len))
    } else if first & 0b0010_0000 != 0 {
      // Set Dynamic Table Capacity (section 4.3.1)
      let Some((capacity, len)) = encoder_int(bytes, 5)? else {
        return Ok(None);
      };
      if capacity > self.max_capacity {
        return Err(Error::encoder_stream(ErrorKind::CapacityAboveMaximum));
      }
      self.credit_copy_budget(len);
      self.capacity = capacity;
      self.evict_down_to(capacity);
      Ok(Some(len))
    } else {
      // Duplicate (section 4.3.4)
      let Some((idx, len)) = encoder_int(bytes, 5)? else {
        return Ok(None);
      };
      let entry = self.encoder_entry(idx)?;
      let name_len = entry.name_len as usize;
      let len_copied = name_len + entry.value_len as usize;
      self.spend_copy_budget(len_copied, len)?;
      self.staging.clear();
      self.stage_ring(entry.start as usize, len_copied);
      self.insert(name_len)?;
      Ok(Some(len))
    }
  }

  // The entry of a relative index of the encoder stream, counted back from the last insert.
  fn encoder_entry(&self, idx: u64) -> Result<Entry> {
    if let Some(abs) = relative(self.insert_count, idx)
      && let Some(entry) = self.entry(abs)
    {
      return Ok(entry);
    }
    Err(Error::encoder_stream(ErrorKind::InvalidDynamicIndex))
  }

  // Reads the string literal at the start of `bytes`, if it is whole, after checking that an
  // entry whose other parts take at least `taken` bytes can still hold it.
  fn encoder_string<'bytes>(
    &self,
    bytes: &'bytes [u8],
    prefix_bits: u8,
    taken: usize,
  ) -> Result<Option<(StringLiteral<'bytes>, usize)>> {
    let Some(first) = bytes.first().copied() else {
      return Ok(None);
    };
    let Some((len, header_len)) = encoder_int(bytes, prefix_bits - 1)? else {
      return Ok(None);
    };
    let huffman = first & (1 << (prefix_bits - 1)) != 0;
    let min_len = if huffman { huffman_min_len(len) } else { len };
    let min_size = min_len.saturating_add(taken as u64).saturating_add(ENTRY_OVERHEAD);
    if min_size > self.capacity {
      return Err(Error::encoder_stream(ErrorKind::EntryTooLarge));
    }
    // Below the capacity, a u32
    let len = len as usize;
    let Some(data) = bytes.get(header_len..header_len + len) else {
      return Ok(None);
    };
    Ok(Some((StringLiteral { data, huffman }, header_len + len)))
  }

  // Inserts the entry in `staging`, whose first `name_len` bytes are the name, evicting what it
  // needs (RFC 9204 section 3.2.2).
  fn insert(&mut self, name_len: usize) -> Result<()> {
    let bytes_len = self.staging.len();
    let size = bytes_len as u64 + ENTRY_OVERHEAD;
    if size > self.capacity {
      return Err(Error::encoder_stream(ErrorKind::EntryTooLarge));
    }
    self.evict_down_to(self.capacity - size);
    // The ring has room: what the table holds is at most capacity - size - 32 per entry
    let ring_capacity = self.ring.len();
    let mut tail = self.ring_head + self.ring_len;
    if tail >= ring_capacity {
      tail -= ring_capacity;
    }
    let Self { ring, staging, .. } = self;
    let first_len = bytes_len.min(ring_capacity - tail);
    let (first, second) = staging.split_at(first_len);
    ring[tail..tail + first_len].copy_from_slice(first);
    ring[..second.len()].copy_from_slice(second);
    let entries_cap = self.entries.len();
    // A table holds at most capacity / 32 entries, and `size > capacity` returned above when the
    // capacity is 0
    let mut slot = self.entries_head + self.entries_len;
    if slot >= entries_cap {
      slot -= entries_cap;
    }
    self.entries[slot] = Entry {
      name_len: name_len as u32,
      start: tail as u32,
      value_len: (bytes_len - name_len) as u32,
    };
    self.entries_len += 1;
    self.ring_len += bytes_len;
    self.size += size;
    self.insert_count += 1;
    Ok(())
  }

  // Evicts the oldest entries until the size of the table is at most `size`.
  fn evict_down_to(&mut self, size: u64) {
    let ring_cap = self.ring.len();
    let entries_cap = self.entries.len();
    while self.size > size {
      let entry = self.entries[self.entries_head];
      let bytes_len = entry.name_len as usize + entry.value_len as usize;
      self.ring_head += bytes_len;
      if self.ring_head >= ring_cap {
        self.ring_head -= ring_cap;
      }
      self.ring_len -= bytes_len;
      self.entries_head += 1;
      if self.entries_head >= entries_cap {
        self.entries_head = 0;
      }
      self.entries_len -= 1;
      self.size -= entry.size();
    }
  }

  // The name and the value of `entry`.
  fn entry_parts<'this>(
    &'this self,
    entry: Entry,
    scratch: &mut Vec<u8>,
  ) -> (Part<'this>, Part<'this>) {
    let name_len = entry.name_len as usize;
    let start = entry.start as usize;
    let name = self.ring_part(start, name_len, scratch);
    let value_start = (start + name_len) % self.ring.len();
    let value = self.ring_part(value_start, entry.value_len as usize, scratch);
    (name, value)
  }

  fn finish(&mut self, stream: u64, ric: u64) -> Result<DecodeOutcome> {
    if ric > 0 {
      // Section Acknowledgment (RFC 9204 section 4.4.1)
      self.retract_increment();
      self.push_instruction(stream, 7, 0b1000_0000)?;
      self.known_received = self.known_received.max(ric);
      self.refresh_increment()?;
    }
    Ok(DecodeOutcome::Done { referenced_dynamic: ric > 0 })
  }

  fn forget_stream(&mut self, stream: u64) {
    if let Some(idx) = self.blocked.iter().position(|el| el.0 == stream) {
      let _ = self.blocked.swap_remove(idx);
    }
    if let Some(idx) = self.unblocked.iter().position(|el| *el == stream) {
      let _ = self.unblocked.swap_remove(idx);
    }
  }

  fn oldest_live(&self) -> u64 {
    self.insert_count - self.entries_len as u64
  }

  fn prefix(&self, section: &[u8]) -> Result<Prefix> {
    let (encoded, ric_len) = section_int(section, 8)?;
    let Some(ric) = decode_required_insert_count(encoded, self.max_entries, self.insert_count)
    else {
      return Err(Error::decompression(ErrorKind::InvalidRequiredInsertCount));
    };
    let rest = &section[ric_len..];
    let (delta, delta_len) = section_int(rest, 7)?;
    let base = if rest.first().is_some_and(|el| el & 0b1000_0000 != 0) {
      // A Sign of 1 with Delta Base >= Required Insert Count is a negative Base
      ric.checked_sub(delta).and_then(|el| el.checked_sub(1))
    } else {
      ric.checked_add(delta)
    };
    let Some(base) = base else {
      return Err(Error::decompression(ErrorKind::InvalidBase));
    };
    Ok(Prefix { base, lines: ric_len + delta_len, ric })
  }

  fn push_instruction(&mut self, value: u64, prefix_bits: u8, flags: u8) -> Result<()> {
    if self.out.len() - self.out_start + 10 > self.config.max_pending_decoder_stream {
      return Err(Error::excessive_load(ErrorKind::DecoderStreamBacklog));
    }
    push_prefix_int(&mut self.out, value, prefix_bits, flags);
    Ok(())
  }

  // Queues an Insert Count Increment (RFC 9204 section 4.4.3) for the inserts that nothing queued
  // acknowledges, in place of the one that waits at the end of the output.
  fn refresh_increment(&mut self) -> Result<()> {
    self.retract_increment();
    if self.insert_count > self.known_received {
      let start = self.out.len();
      self.push_instruction(self.insert_count - self.known_received, 6, 0)?;
      self.pending_increment = Some((start, self.insert_count));
    }
    Ok(())
  }

  fn retract_increment(&mut self) {
    if let Some((start, _)) = self.pending_increment.take() {
      self.out.truncate(start);
    }
  }

  // An instruction of `len` bytes that copies `copied` bytes out of the table: its own bytes are
  // credited first.
  fn spend_copy_budget(&mut self, copied: usize, len: usize) -> Result<()> {
    let available = self.copy_budget + len as u64 * COPY_BUDGET_PER_BYTE;
    let Some(budget) = available.checked_sub(copied as u64) else {
      return Err(Error::excessive_load(ErrorKind::EncoderInstructionBudget));
    };
    self.copy_budget = budget.min(self.max_capacity * COPY_BUDGET_CAPACITIES);
    Ok(())
  }

  // An instruction of `len` bytes that copies nothing.
  fn credit_copy_budget(&mut self, len: usize) {
    let available = self.copy_budget + len as u64 * COPY_BUDGET_PER_BYTE;
    self.copy_budget = available.min(self.max_capacity * COPY_BUDGET_CAPACITIES);
  }

  // Appends `len` bytes of the ring at `start` to `staging`.
  fn stage_ring(&mut self, start: usize, len: usize) {
    let (first, second) = ring_slices(&self.ring, start, len);
    self.staging.extend_from_slice(first);
    self.staging.extend_from_slice(second);
  }

  // Appends a string literal of the encoder stream to `staging`, decoded if it is Huffman coded;
  // the entry must still fit in the capacity.
  fn stage_string(&mut self, string: StringLiteral<'_>) -> Result<()> {
    let room =
      (self.capacity.saturating_sub(ENTRY_OVERHEAD) as usize).saturating_sub(self.staging.len());
    if !string.huffman {
      if string.data.len() > room {
        return Err(Error::encoder_stream(ErrorKind::EntryTooLarge));
      }
      self.staging.extend_from_slice(string.data);
      return Ok(());
    }
    huffman::decode(string.data, &mut self.staging, room).map_err(|err| {
      Error::encoder_stream(match err {
        HuffmanError::TooLong => ErrorKind::EntryTooLarge,
        HuffmanError::Invalid => ErrorKind::InvalidHuffman,
      })
    })
  }

  /// Panics if the table, the blocked streams or the decoder-stream output are not consistent.
  #[cfg(any(test, feature = "__check"))]
  #[doc(hidden)]
  pub fn check_invariants(&self) {
    assert!(self.capacity <= self.max_capacity);
    assert!(self.size <= self.capacity);
    assert!(self.entries_len as u64 <= self.max_entries);
    assert!(self.blocked.len() <= usize::from(self.config.blocked_streams));
    assert!(self.blocked.iter().all(|(_, ric)| *ric > self.insert_count));
    assert!(self.oldest_live() <= self.insert_count);
    assert!(self.known_received <= self.insert_count);
    assert!(self.decoder_stream_output().len() <= self.config.max_pending_decoder_stream);
    assert!(self.input.len() as u64 <= self.max_capacity * 4 + 64);
    if let Some((start, acknowledged)) = self.pending_increment {
      assert!(start >= self.out_start && start < self.out.len());
      assert_eq!(acknowledged, self.insert_count);
    } else {
      assert_eq!(self.known_received, self.insert_count);
    }
    // The entries follow each other in the ring from its head, and account for its bytes and the
    // size of the table
    let (mut size, mut bytes, mut next) = (0u64, 0usize, self.ring_head);
    for abs in self.oldest_live()..self.insert_count {
      let entry = self.entry(abs).unwrap();
      assert_eq!(entry.start as usize, next);
      let len = entry.name_len as usize + entry.value_len as usize;
      next = (next + len).checked_rem(self.ring.len()).unwrap_or(0);
      size += entry.size();
      bytes += len;
    }
    assert_eq!(size, self.size);
    assert_eq!(bytes, self.ring_len);
    assert!(self.ring_len <= self.ring.len());
  }
}

/// The absolute Required Insert Count of `encoded` (RFC 9204 section 4.5.1.1), for a table of
/// `max_entries` that had `total_inserts`; `None` for a value that no conformant encoder produces.
pub(crate) fn decode_required_insert_count(
  encoded: u64,
  max_entries: u64,
  total_inserts: u64,
) -> Option<u64> {
  if encoded == 0 {
    return Some(0);
  }
  let full_range = max_entries.checked_mul(2)?;
  if encoded > full_range {
    return None;
  }
  let max_value = total_inserts.checked_add(max_entries)?;
  let max_wrapped = max_value.checked_div(full_range)?.checked_mul(full_range)?;
  let mut ric = max_wrapped.checked_add(encoded)?.checked_sub(1)?;
  if ric > max_value {
    if ric <= full_range {
      return None;
    }
    ric -= full_range;
  }
  if ric == 0 {
    return None;
  }
  Some(ric)
}

/// A string literal of the wire, with its Huffman bit.
#[derive(Clone, Copy, Debug)]
struct StringLiteral<'bytes> {
  data: &'bytes [u8],
  huffman: bool,
}

// A prefixed integer of the encoder stream: `None` if it is not whole.
fn encoder_int(bytes: &[u8], prefix_bits: u8) -> Result<Option<(u64, usize)>> {
  decode_prefix_int(bytes, prefix_bits)
    .map_err(|_err| Error::encoder_stream(ErrorKind::IntegerOverflow))
}

// The fewest bytes that a Huffman string of `len` bytes decodes to: the longest code has 30 bits
// and the padding at most 7.
fn huffman_min_len(len: u64) -> u64 {
  len.saturating_mul(8).saturating_sub(7) / 30
}

// The `len` bytes at `start` of the byte ring, in one or two slices. `start` is below and `len`
// at most the length of the ring, as every entry is: the callers hold entries of the table.
fn ring_slices(ring: &[u8], start: usize, len: usize) -> (&[u8], &[u8]) {
  let first_len = len.min(ring.len() - start);
  (&ring[start..start + first_len], &ring[..len - first_len])
}

// The index `idx` relative to `base`, counted back from it (RFC 9204 section 3.2.5).
fn relative(base: u64, idx: u64) -> Option<u64> {
  base.checked_sub(idx)?.checked_sub(1)
}

// A prefixed integer of a field section, which is whole: one that ends early is an error.
fn section_int(bytes: &[u8], prefix_bits: u8) -> Result<(u64, usize)> {
  match decode_prefix_int(bytes, prefix_bits) {
    Ok(Some(elem)) => Ok(elem),
    Ok(None) => Err(Error::decompression(ErrorKind::Truncated)),
    Err(_err) => Err(Error::decompression(ErrorKind::IntegerOverflow)),
  }
}

// The string literal at the start of `bytes` (RFC 9204 section 4.1.2): raw, it is borrowed;
// Huffman coded, it is decoded at the end of `scratch`, which grows by at most 8/5 of it.
fn section_string<'bytes>(
  bytes: &'bytes [u8],
  prefix_bits: u8,
  scratch: &mut Vec<u8>,
) -> Result<(Part<'bytes>, usize)> {
  let huffman = bytes.first().is_some_and(|el| el & (1 << (prefix_bits - 1)) != 0);
  let (len, header_len) = section_int(bytes, prefix_bits - 1)?;
  let Some(data) =
    usize::try_from(len).ok().and_then(|len| bytes.get(header_len..).and_then(|el| el.get(..len)))
  else {
    return Err(Error::decompression(ErrorKind::Truncated));
  };
  let total = header_len + data.len();
  if !huffman {
    return Ok((Part::Borrowed(data), total));
  }
  let start = scratch.len();
  if huffman::decode(data, scratch, usize::MAX).is_err() {
    return Err(Error::decompression(ErrorKind::InvalidHuffman));
  }
  Ok((Part::Scratch(start, scratch.len()), total))
}

fn static_entry(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
  if let Some(elem) = usize::try_from(idx).ok().and_then(|el| STATIC_TABLE.get(el)) {
    return Ok(*elem);
  }
  Err(Error::decompression(ErrorKind::InvalidStaticIndex))
}

// The reference to static entry `idx`, which `static_entry` checked or checks next.
fn make_static_ref(idx: u64, with_value: bool) -> Option<StaticRef> {
  u8::try_from(idx)
    .ok()
    .filter(|el| usize::from(*el) < STATIC_TABLE.len())
    .map(|index| StaticRef { index, with_value })
}

fn static_name(idx: u64) -> Result<&'static [u8]> {
  if let Some(elem) = usize::try_from(idx).ok().and_then(|el| STATIC_TABLE.get(el)) {
    return Ok(elem.0);
  }
  Err(Error::encoder_stream(ErrorKind::InvalidStaticIndex))
}

// A lower bound of the decoded length of a string literal.
fn string_min_len(string: StringLiteral<'_>) -> usize {
  let len = string.data.len() as u64;
  let min = if string.huffman { huffman_min_len(len) } else { len };
  min as usize
}

#[cfg(test)]
mod tests;
