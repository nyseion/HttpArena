//! The QPACK encoder (RFC 9204), with a dynamic table.
//!
//! # Policy
//!
//! For each field, in order:
//!
//! 1. A name and value in the static table: an Indexed Field Line of the static table.
//! 2. A sensitive field ([`Field::sensitive`], or a name of [`SENSITIVE_NAMES`] unless
//!    [`EncoderConfig::index_sensitive_names`]): never inserted, sent as a literal with the
//!    never-indexed bit, by a static or dynamic name reference when there is one.
//! 3. A name and value in the dynamic table that may be referenced (see below): an Indexed Field
//!    Line. If the entry is draining (among the oldest eighth of the capacity), it is duplicated
//!    first when the table has room, and the duplicate is referenced.
//! 4. Otherwise the field is inserted if the [`InsertPolicy`] allows it, the entry takes at most
//!    three quarters of the capacity and room can be made by evicting evictable entries. The
//!    insert names the field by a static reference, else by the newest dynamic entry with the
//!    name, else literally. The new entry is then referenced if it may be.
//! 5. Otherwise a literal with a static or dynamic name reference, or a literal name.
//!
//! An entry may be referenced if it is not draining and either the decoder acknowledged it (its
//! absolute index is below the Known Received Count) or the section may block: blocking is allowed
//! by [`EncoderConfig::allow_blocking`] and the stream already risks blocking or fewer streams than
//! the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` do.
//!
//! An entry is evictable once the decoder acknowledged it and no unacknowledged field section
//! references it (RFC 9204 section 2.1.1); the encoder never evicts any other, and never inserts
//! when it would have to. Each field section with dynamic references is tracked until its Section
//! Acknowledgment or the stream's cancellation; at most [`MAX_TRACKED_SECTIONS`] are, beyond which
//! sections use the static table and literals only.
//!
//! Strings are Huffman coded when that is shorter ([`EncoderConfig::huffman`]).

use crate::{
  Error, ErrorKind, Field, Result, Settings,
  decoder::ENTRY_OVERHEAD,
  encode_static::{encode_static_field, push_string},
  prefix_int::{decode_prefix_int, push_prefix_int},
  static_table::{find_exact_from, find_name_hashed, name_hash},
};
use alloc::{collections::VecDeque, vec::Vec};
use core::mem;

/// Names that are not inserted into the dynamic table and are sent with the never-indexed bit
/// unless [`EncoderConfig::index_sensitive_names`] is set: credentials and cookies, which an
/// attacker who can inject fields could otherwise recover by watching the compressed size.
pub const SENSITIVE_NAMES: [&[u8]; 4] =
  [b"authorization", b"cookie", b"proxy-authorization", b"set-cookie"];

/// The most field sections with dynamic references that the encoder tracks until they are
/// acknowledged; past it, sections reference the static table only.
pub const MAX_TRACKED_SECTIONS: usize = 4096;

/// Slots of the filter of fields seen once, for [`InsertPolicy::Repeated`].
const SEEN_SLOTS: usize = 1024;

/// Slots of the name index: open addressing by name hash over the newest entry with the name.
const NAME_SLOTS: usize = 1024;
/// The name index slot is empty.
const NO_NAME: u32 = u32::MAX;

/// When the encoder inserts fields into the dynamic table.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum InsertPolicy {
  /// Never: the dynamic table is not used (the static-only mode).
  Never,
  /// A field the second time it is seen (by a 1024-slot hash filter of name and value): values
  /// that change on every message (dates, lengths, ids) do not churn the table.
  #[default]
  Repeated,
  /// Every field that fits and is not sensitive.
  Always,
}

/// The configuration of an [`Encoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncoderConfig {
  /// The most bytes of dynamic table to use; the encoder uses the smaller of this and the peer's
  /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`. 0 is the static-only mode. Default 4096.
  pub max_table_capacity: u32,
  /// When to insert fields. Default [`InsertPolicy::Repeated`].
  pub insert_policy: InsertPolicy,
  /// Whether sections may reference entries that the decoder did not acknowledge yet, which can
  /// block the stream at the decoder (never more streams than the peer allows). Default true.
  pub allow_blocking: bool,
  /// Huffman-code strings when that is shorter. Default true.
  pub huffman: bool,
  /// Index the names of [`SENSITIVE_NAMES`] like any other. Default false.
  pub index_sensitive_names: bool,
}

impl Default for EncoderConfig {
  #[inline]
  fn default() -> Self {
    Self {
      max_table_capacity: 4096,
      insert_policy: InsertPolicy::Repeated,
      allow_blocking: true,
      huffman: true,
      index_sensitive_names: false,
    }
  }
}

impl EncoderConfig {
  /// The static-only mode: no dynamic table, no encoder stream, nothing for the peer's decoder to
  /// block on or acknowledge. Huffman coding stays on.
  #[inline]
  pub fn static_only() -> Self {
    Self { max_table_capacity: 0, insert_policy: InsertPolicy::Never, ..Self::default() }
  }
}

/// Counters of an encoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EncoderStats {
  /// Field sections encoded.
  pub sections: u64,
  /// Field sections that referenced the dynamic table.
  pub dynamic_sections: u64,
  /// Field sections that may block at the decoder.
  pub blocking_sections: u64,
  /// Inserts, duplicates included.
  pub inserts: u64,
  /// Of [`Self::inserts`], the Duplicates.
  pub duplicates: u64,
  /// Entries evicted.
  pub evictions: u64,
}

/// An entry of the dynamic table: its name and value follow each other in the byte ring.
#[derive(Clone, Copy, Debug)]
struct DynEntry {
  hash: u32,
  name_hash: u32,
  name_len: u32,
  /// Unacknowledged field sections that reference the entry, counted per reference.
  refs: u32,
  start: u32,
  value_len: u32,
}

impl DynEntry {
  fn bytes_len(&self) -> usize {
    self.name_len as usize + self.value_len as usize
  }

  fn size(&self) -> u64 {
    self.bytes_len() as u64 + ENTRY_OVERHEAD
  }
}

/// A field section with dynamic references that waits for its acknowledgment.
#[derive(Clone, Debug)]
struct Section {
  refs: Vec<u64>,
  ric: u64,
}

#[derive(Clone, Debug)]
struct StreamSections {
  id: u64,
  sections: VecDeque<Section>,
}

/// What a section may reference, fixed at its start.
#[derive(Clone, Copy, Debug)]
struct SectionCtx {
  base: u64,
  /// The section may reference unacknowledged entries.
  can_block: bool,
  /// The lowest absolute index that may be referenced.
  draining: u64,
  /// The dynamic table may be used.
  dynamic: bool,
}

/// The QPACK encoder of one HTTP/3 connection.
///
/// Sans-IO: give it the peer's settings with [`Self::set_peer_settings`], encode each field
/// section with [`Self::encode`], write what [`Self::encoder_stream_output`] holds to this side's
/// encoder stream (before, or together with, the sections that need it), and feed it the bytes of
/// the peer's decoder stream with [`Self::feed_decoder_stream`]. See the module documentation for
/// the policy.
#[derive(Clone, Debug)]
pub struct Encoder {
  capacity: u64,
  config: EncoderConfig,
  /// The absolute index of the oldest entry.
  dropped: u64,
  entries: VecDeque<DynEntry>,
  /// The count of sections whose Required Insert Count is above the Known Received Count.
  blocking_count: u64,
  /// Open-addressed by name hash: the offset in `entries` of the newest entry with a name, or
  /// `NO_NAME`. Kept consistent by `push_entry` and `evict_down_to`.
  name_index: Vec<u32>,
  free_refs: Vec<Vec<u64>>,
  free_sections: Vec<VecDeque<Section>>,
  input: Vec<u8>,
  insert_count: u64,
  known_received: u64,
  lines: Vec<u8>,
  max_entries: u64,
  out: Vec<u8>,
  out_start: usize,
  peer_blocked: u64,
  peer_max_capacity: u64,
  peer_settings: bool,
  refs: Vec<u64>,
  /// Names and values of the entries, oldest first from `ring_head`, in a ring of the largest
  /// capacity that the encoder may set.
  ring: Vec<u8>,
  ring_head: usize,
  ring_len: usize,
  /// A Duplicate is staged here: the room that it makes may overwrite the entry.
  scratch: Vec<u8>,
  seen: Vec<u32>,
  size: u64,
  stats: EncoderStats,
  streams: Vec<StreamSections>,
  tracked: usize,
}

impl Encoder {
  /// An encoder for `config`. Until [`Self::set_peer_settings`] it uses the static table only, as
  /// the peer's decoder starts with a dynamic table of capacity 0.
  pub fn new(config: EncoderConfig) -> Self {
    Self {
      capacity: 0,
      config,
      dropped: 0,
      entries: VecDeque::new(),
      blocking_count: 0,
      name_index: Vec::new(),
      free_refs: Vec::new(),
      free_sections: Vec::new(),
      input: Vec::new(),
      insert_count: 0,
      known_received: 0,
      lines: Vec::new(),
      max_entries: 0,
      out: Vec::new(),
      out_start: 0,
      peer_blocked: 0,
      peer_max_capacity: 0,
      peer_settings: false,
      refs: Vec::new(),
      ring: Vec::new(),
      ring_head: 0,
      ring_len: 0,
      scratch: Vec::new(),
      seen: Vec::new(),
      size: 0,
      stats: EncoderStats::default(),
      streams: Vec::new(),
      tracked: 0,
    }
  }

  /// The configuration of this encoder.
  #[inline]
  pub const fn config(&self) -> &EncoderConfig {
    &self.config
  }

  /// Counters of what the encoder did.
  #[inline]
  pub const fn stats(&self) -> EncoderStats {
    self.stats
  }

  /// The capacity of the dynamic table in use.
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
  pub fn table_len(&self) -> usize {
    self.entries.len()
  }

  /// Inserts and duplications sent so far.
  #[inline]
  pub const fn insert_count(&self) -> u64 {
    self.insert_count
  }

  /// The inserts that the decoder is known to have received (RFC 9204 section 2.1.4).
  #[inline]
  pub const fn known_received_count(&self) -> u64 {
    self.known_received
  }

  /// Field sections with dynamic references that wait for their acknowledgment.
  #[inline]
  pub const fn unacknowledged_sections(&self) -> usize {
    self.tracked
  }

  /// The number of streams that may be blocked at the decoder now.
  #[inline]
  pub fn blocking_streams(&self) -> usize {
    self.blocking_count as usize
  }

  /// Applies the peer's SETTINGS: the dynamic table capacity becomes the smaller of the peer's
  /// maximum and [`EncoderConfig::max_table_capacity`], announced on the encoder stream with a Set
  /// Dynamic Table Capacity if it is not 0, and the table storage (that many bytes) is allocated.
  /// Called once per connection.
  pub fn set_peer_settings(&mut self, settings: Settings) -> Result<()> {
    if self.peer_settings {
      return Err(Error::local(ErrorKind::InvalidConfig));
    }
    self.peer_settings = true;
    self.peer_max_capacity = settings.max_table_capacity;
    self.peer_blocked = settings.blocked_streams;
    self.max_entries = settings.max_table_capacity / 32;
    let capacity = self.max_capacity();
    if capacity > 0 {
      self.ring.resize(capacity as usize, 0);
      self.set_capacity(capacity)?;
    }
    Ok(())
  }

  /// The largest capacity that the encoder may set: the smaller of the peer's maximum and
  /// [`EncoderConfig::max_table_capacity`], or 0 with [`InsertPolicy::Never`].
  #[inline]
  pub fn max_capacity(&self) -> u64 {
    if self.config.insert_policy == InsertPolicy::Never {
      return 0;
    }
    self.peer_max_capacity.min(self.config.max_table_capacity.into())
  }

  /// Changes the capacity of the dynamic table, with a Set Dynamic Table Capacity on the encoder
  /// stream. Above [`Self::max_capacity`] is an error; so is a lower capacity that would evict
  /// entries that are not evictable yet ([`ErrorKind::EntriesInUse`], local: retry once more is
  /// acknowledged).
  pub fn set_capacity(&mut self, capacity: u64) -> Result<()> {
    if capacity > self.ring.len() as u64 {
      return Err(Error::local(ErrorKind::CapacityAboveMaximum));
    }
    if !self.can_evict_down_to(capacity) {
      return Err(Error::local(ErrorKind::EntriesInUse));
    }
    self.evict_down_to(capacity);
    self.capacity = capacity;
    push_prefix_int(&mut self.out, capacity, 5, 0b0010_0000);
    Ok(())
  }

  /// The encoder-stream bytes that wait to be written.
  #[inline]
  pub fn encoder_stream_output(&self) -> &[u8] {
    &self.out[self.out_start..]
  }

  /// `n` bytes of [`Self::encoder_stream_output`] were written.
  pub fn consume_encoder_stream(&mut self, n: usize) {
    let len = self.out.len();
    self.out_start = (self.out_start + n).min(len);
    if self.out_start == len {
      self.out.clear();
      self.out_start = 0;
    } else if self.out_start >= len / 2 {
      self.out.drain(..self.out_start);
      self.out_start = 0;
    }
  }

  /// Appends [`Self::encoder_stream_output`] to `out` and consumes it.
  pub fn drain_encoder_stream(&mut self, out: &mut Vec<u8>) {
    out.extend_from_slice(self.encoder_stream_output());
    self.consume_encoder_stream(usize::MAX);
  }

  /// Applies the instructions of the peer's decoder stream in `bytes`, which follow those given
  /// before; an incomplete instruction is kept until the next call. Errors are a
  /// `QPACK_DECODER_STREAM_ERROR`; after one the encoder must not be used again.
  pub fn feed_decoder_stream(&mut self, bytes: &[u8]) -> Result<()> {
    if self.input.is_empty() {
      let consumed = self.apply_instructions(bytes)?;
      self.input.extend_from_slice(&bytes[consumed..]);
    } else {
      let mut input = mem::take(&mut self.input);
      input.extend_from_slice(bytes);
      let consumed = self.apply_instructions(&input)?;
      let _ = input.drain(..consumed);
      self.input = input;
    }
    Ok(())
  }

  fn apply_instructions(&mut self, bytes: &[u8]) -> Result<usize> {
    let mut consumed = 0;
    while let Some(&first) = bytes.get(consumed) {
      let prefix_bits = if first & 0x80 != 0 { 7 } else { 6 };
      let Some((value, len)) = decode_prefix_int(&bytes[consumed..], prefix_bits)
        .map_err(|_err| Error::decoder_stream(ErrorKind::IntegerOverflow))?
      else {
        break;
      };
      consumed += len;
      if first & 0x80 != 0 {
        self.on_section_ack(value)?;
      } else if first & 0x40 != 0 {
        self.on_stream_cancel(value);
      } else {
        // Insert Count Increment (RFC 9204 section 4.4.3)
        if value == 0 || value > self.insert_count - self.known_received {
          return Err(Error::decoder_stream(ErrorKind::InvalidInsertCountIncrement));
        }
        self.known_received += value;
        // Sections that it acknowledges may stop blocking their streams
        self.recount_blocking();
      }
    }
    Ok(consumed)
  }

  // Section Acknowledgment (RFC 9204 section 4.4.1): of the earliest unacknowledged section with
  // dynamic references of the stream
  fn on_section_ack(&mut self, stream: u64) -> Result<()> {
    let Some(idx) = self.streams.iter().position(|el| el.id == stream) else {
      return Err(Error::decoder_stream(ErrorKind::UnexpectedSectionAcknowledgment));
    };
    let streams = &mut self.streams[idx];
    let Some(section) = streams.sections.pop_front() else {
      return Err(Error::decoder_stream(ErrorKind::UnexpectedSectionAcknowledgment));
    };
    if streams.sections.is_empty() {
      let streams = self.streams.swap_remove(idx);
      self.free_sections.push(streams.sections);
    }
    self.known_received = self.known_received.max(section.ric);
    self.release(section);
    self.recount_blocking();
    Ok(())
  }

  // Stream Cancellation (RFC 9204 section 4.4.2): every section of the stream is released
  fn on_stream_cancel(&mut self, stream: u64) {
    let Some(idx) = self.streams.iter().position(|el| el.id == stream) else {
      return;
    };
    let mut streams = self.streams.swap_remove(idx);
    while let Some(section) = streams.sections.pop_front() {
      self.release(section);
    }
    self.free_sections.push(streams.sections);
    self.recount_blocking();
  }

  // Streams whose earliest unacknowledged section may block, recounted: the Known Received Count
  // moved or sections were released. Rare, so the scan is fine.
  fn recount_blocking(&mut self) {
    let krc = self.known_received;
    self.blocking_count =
      self.streams.iter().filter(|el| el.sections.iter().any(|sec| sec.ric > krc)).count() as u64;
  }

  fn release(&mut self, mut section: Section) {
    for abs in section.refs.drain(..) {
      // Referenced entries are never evicted, so they are there
      if let Some(entry) =
        abs.checked_sub(self.dropped).and_then(|el| self.entries.get_mut(el as usize))
      {
        entry.refs -= 1;
      }
    }
    self.tracked -= 1;
    self.free_refs.push(section.refs);
  }

  /// Appends to `out` the field section of `fields` for stream `stream_id`, in their order, and
  /// queues the encoder-stream instructions that it needs.
  pub fn encode<'a, I, F>(&mut self, stream_id: u64, fields: I, out: &mut Vec<u8>)
  where
    I: IntoIterator<Item = F>,
    F: Into<Field<'a>>,
  {
    self.stats.sections += 1;
    let dynamic = self.capacity > 0 && self.tracked < MAX_TRACKED_SECTIONS;
    if !dynamic {
      self.encode_static(fields, out);
      return;
    }
    let krc = self.known_received;
    let stream_blocking = self
      .streams
      .iter()
      .find(|el| el.id == stream_id)
      .is_some_and(|el| el.sections.iter().any(|sec| sec.ric > krc));
    let can_block = self.config.allow_blocking
      && (stream_blocking || (self.blocking_streams() as u64) < self.peer_blocked);
    let ctx =
      SectionCtx { base: self.insert_count, can_block, draining: self.draining_index(), dynamic };
    let mut lines = mem::take(&mut self.lines);
    lines.clear();
    self.refs.clear();
    for field in fields {
      self.encode_field(ctx, field.into(), &mut lines);
    }
    let ric = self.refs.iter().max().map_or(0, |el| el + 1);
    if ric == 0 {
      encode_static_prefix_raw(out);
    } else {
      let encoded = ric % (2 * self.max_entries) + 1;
      push_prefix_int(out, encoded, 8, 0);
      if ctx.base >= ric {
        push_prefix_int(out, ctx.base - ric, 7, 0);
      } else {
        push_prefix_int(out, ric - ctx.base - 1, 7, 0b1000_0000);
      }
      let mut refs = self.free_refs.pop().unwrap_or_default();
      refs.clear();
      refs.extend_from_slice(&self.refs);
      let section = Section { refs, ric };
      match self.streams.iter_mut().find(|el| el.id == stream_id) {
        Some(elem) => elem.sections.push_back(section),
        None => {
          let mut sections = self.free_sections.pop().unwrap_or_default();
          sections.push_back(section);
          self.streams.push(StreamSections { id: stream_id, sections });
        }
      }
      self.tracked += 1;
      self.stats.dynamic_sections += 1;
      if ric > krc {
        self.stats.blocking_sections += 1;
        // This stream now blocks (its other sections already counted, if any)
        if !stream_blocking {
          self.blocking_count += 1;
        }
      }
    }
    out.extend_from_slice(&lines);
    self.lines = lines;
  }

  fn encode_static<'a, I, F>(&mut self, fields: I, out: &mut Vec<u8>)
  where
    I: IntoIterator<Item = F>,
    F: Into<Field<'a>>,
  {
    encode_static_prefix_raw(out);
    for field in fields {
      let field = field.into();
      let sensitive = field.sensitive || self.sensitive_name(field.name);
      encode_static_field(field.name, field.value, sensitive, self.config.huffman, out);
    }
  }

  fn sensitive_name(&self, name: &[u8]) -> bool {
    !self.config.index_sensitive_names && SENSITIVE_NAMES.contains(&name)
  }

  fn encode_field(&mut self, ctx: SectionCtx, field: Field<'_>, lines: &mut Vec<u8>) {
    let huffman = self.config.huffman;
    let (name, value) = (field.name, field.value);
    let name_hash = name_hash(name);
    let static_name = find_name_hashed(name, name_hash);
    // 1. The static table has the field
    if let Some(first) = static_name
      && let Some(idx) = find_exact_from(first, value)
    {
      push_prefix_int(lines, idx.into(), 6, 0b1100_0000);
      return;
    }
    let sensitive = field.sensitive || self.sensitive_name(name);
    let hash = value_hash(name_hash, value);
    let (exact, name_match) = self.find(ctx, name, name_hash, value, hash);
    if !sensitive && ctx.dynamic {
      // 3. The dynamic table has the field
      if let Some(abs) = exact {
        if self.usable(ctx, abs) {
          self.reference(abs);
          push_indexed(lines, ctx.base, abs);
          return;
        }
        // A duplicate is not acknowledged yet: only worth it if the section may block
        if abs < ctx.draining && ctx.can_block && self.duplicate(abs) {
          let new_abs = self.insert_count - 1;
          if self.usable(ctx, new_abs) {
            self.reference(new_abs);
            push_indexed(lines, ctx.base, new_abs);
            return;
          }
        }
      } else if self.should_insert(hash) {
        // 4. Insert, then reference
        let size = (name.len() + value.len()) as u64 + ENTRY_OVERHEAD;
        let dynamic_name =
          if static_name.is_none() { self.newest_name(name, name_hash) } else { None };
        if size <= self.capacity / 4 * 3 && self.make_room(size) {
          self.insert(static_name, dynamic_name, field, name_hash, hash);
          let new_abs = self.insert_count - 1;
          if self.usable(ctx, new_abs) {
            self.reference(new_abs);
            push_indexed(lines, ctx.base, new_abs);
            return;
          }
        }
      }
    }
    // 5. A literal, by name reference when there is one
    let n_bit = if sensitive { 0b0010_0000 } else { 0 };
    if let Some(idx) = static_name {
      push_prefix_int(lines, idx.into(), 4, 0b0101_0000 | n_bit);
    } else if let Some(abs) =
      // An insert above may have evicted it
      name_match
        .filter(|el| ctx.dynamic && *el >= self.dropped && self.usable(ctx, *el))
    {
      self.reference(abs);
      if abs < ctx.base {
        push_prefix_int(lines, ctx.base - 1 - abs, 4, 0b0100_0000 | n_bit);
      } else {
        push_prefix_int(lines, abs - ctx.base, 3, n_bit >> 2);
      }
    } else {
      push_string(lines, name, 4, 0b0010_0000 | (n_bit >> 1), huffman);
    }
    push_string(lines, value, 8, 0, huffman);
  }

  // The newest entry with the field, and the newest usable entry with its name. The name index
  // suggests the newest entry with the name; the scan confirms it and finds the exact match.
  fn find(
    &self,
    ctx: SectionCtx,
    name: &[u8],
    name_hash: u32,
    value: &[u8],
    hash: u32,
  ) -> (Option<u64>, Option<u64>) {
    let mut exact = None;
    let mut name_match = None;
    let mut offset = self.indexed_name(name_hash);
    while let Some(idx) = offset {
      let entry = &self.entries[idx as usize];
      offset = if idx > 0 { Some(idx - 1) } else { None };
      if entry.name_hash != name_hash || !self.ring_eq(entry.start as usize, name) {
        continue;
      }
      let abs = self.dropped + idx as u64;
      if exact.is_none()
        && entry.hash == hash
        && entry.value_len as usize == value.len()
        && self.ring_eq(self.wrap(entry.start as usize + name.len()), value)
      {
        exact = Some(abs);
      }
      if name_match.is_none() && self.usable(ctx, abs) {
        name_match = Some(abs);
      }
      if exact.is_some() && name_match.is_some() {
        break;
      }
    }
    (exact, name_match)
  }

  /// The offset that the name index suggests for `name_hash`, if it points at a live entry.
  fn indexed_name(&self, name_hash: u32) -> Option<u32> {
    let idx = *self.name_index.get(Self::name_slot(name_hash))?;
    if idx != NO_NAME && (idx as usize) < self.entries.len() { Some(idx) } else { None }
  }

  // The newest entry with `name`, for a name reference of an insert, which may be to any entry.
  fn newest_name(&self, name: &[u8], name_hash: u32) -> Option<u64> {
    let mut offset = self.indexed_name(name_hash);
    while let Some(idx) = offset {
      let entry = &self.entries[idx as usize];
      offset = if idx > 0 { Some(idx - 1) } else { None };
      if entry.name_hash == name_hash && self.ring_eq(entry.start as usize, name) {
        return Some(self.dropped + idx as u64);
      }
    }
    None
  }

  // If a section of `ctx` may reference the entry of absolute index `abs`.
  fn usable(&self, ctx: SectionCtx, abs: u64) -> bool {
    abs >= ctx.draining && (abs < self.known_received || ctx.can_block)
  }

  fn reference(&mut self, abs: u64) {
    if let Some(entry) = self.entries.get_mut((abs - self.dropped) as usize) {
      entry.refs += 1;
    }
    self.refs.push(abs);
  }

  // The lowest absolute index that new references may use: the entries that make up the oldest
  // eighth of the capacity are left to drain so that they become evictable (RFC 9204 section
  // 2.1.1.1).
  fn draining_index(&self) -> u64 {
    let room = self.capacity - self.size;
    let target = self.capacity / 8;
    let mut abs = self.dropped;
    let mut freed = 0;
    for entry in &self.entries {
      if room + freed >= target {
        break;
      }
      freed += entry.size();
      abs += 1;
    }
    abs
  }

  fn should_insert(&mut self, hash: u32) -> bool {
    // An encoder stream that is not written out stops growing
    if self.out.len() - self.out_start > (self.capacity as usize) * 2 + 1024 {
      return false;
    }
    match self.config.insert_policy {
      InsertPolicy::Never => false,
      InsertPolicy::Always => true,
      InsertPolicy::Repeated => {
        if self.seen.is_empty() {
          self.seen.resize(SEEN_SLOTS, 0);
        }
        // Mixed again, so that the slot does not depend only on the low bits of FNV
        let tag = hash | 1;
        let slot = (hash.wrapping_mul(0x9e37_79b9) >> 22) as usize % SEEN_SLOTS;
        let seen = self.seen[slot] == tag;
        self.seen[slot] = tag;
        seen
      }
    }
  }

  // If entries can be evicted until the table is at most `size`.
  fn can_evict_down_to(&self, size: u64) -> bool {
    let mut table = self.size;
    for (offset, entry) in self.entries.iter().enumerate() {
      if table <= size {
        return true;
      }
      if !self.evictable(offset, entry) {
        return false;
      }
      table -= entry.size();
    }
    table <= size
  }

  fn evictable(&self, offset: usize, entry: &DynEntry) -> bool {
    entry.refs == 0 && self.dropped + (offset as u64) < self.known_received
  }

  fn evict_down_to(&mut self, size: u64) {
    while self.size > size {
      let Some(entry) = self.entries.pop_front() else {
        break;
      };
      self.size -= entry.size();
      self.ring_head = self.wrap(self.ring_head + entry.bytes_len());
      self.ring_len -= entry.bytes_len();
      self.unindex_name(entry.name_hash, 0);
      self.dropped += 1;
      self.stats.evictions += 1;
    }
    self.rebuild_name_index();
  }

  /// Reindexes the entries oldest-to-newest, so each slot holds the newest entry with a name.
  /// Called after evictions, which shift every offset by one.
  fn rebuild_name_index(&mut self) {
    if self.name_index.is_empty() {
      return;
    }
    self.name_index.fill(NO_NAME);
    for (offset, entry) in self.entries.iter().enumerate() {
      let slot = Self::name_slot(entry.name_hash);
      self.name_index[slot] = offset as u32;
    }
  }

  // Evicts what an entry of `size` needs, if that is allowed.
  fn make_room(&mut self, size: u64) -> bool {
    if size > self.capacity || !self.can_evict_down_to(self.capacity - size) {
      return false;
    }
    self.evict_down_to(self.capacity - size);
    true
  }

  // Appends an entry whose name and value are `name` and `value`, room made.
  fn push_entry(&mut self, name: &[u8], value: &[u8], name_hash: u32, hash: u32) {
    // The table holds at most capacity - size - 32 per entry bytes: they fit in the ring
    let start = self.wrap(self.ring_head + self.ring_len);
    self.ring_write(start, name);
    self.ring_write(self.wrap(start + name.len()), value);
    let entry = DynEntry {
      hash,
      name_hash,
      name_len: name.len() as u32,
      refs: 0,
      start: start as u32,
      value_len: value.len() as u32,
    };
    self.ring_len += entry.bytes_len();
    self.size += entry.size();
    self.entries.push_back(entry);
    self.index_name(name_hash, (self.entries.len() - 1) as u32);
    self.insert_count += 1;
    self.stats.inserts += 1;
  }

  /// The slot of `name_hash` in the name index.
  fn name_slot(name_hash: u32) -> usize {
    (name_hash.wrapping_mul(0x9e37_79b9) >> 22) as usize % NAME_SLOTS
  }

  /// Makes `offset` the indexed newest entry for `name_hash`, keeping the previous newest as a
  /// fallback chain of one: a slot holds at most the newest, and `find` falls back to a scan.
  fn index_name(&mut self, name_hash: u32, offset: u32) {
    if self.name_index.is_empty() {
      self.name_index.resize(NAME_SLOTS, NO_NAME);
    }
    let slot = Self::name_slot(name_hash);
    self.name_index[slot] = offset;
  }

  /// Forgets the index slots that point at `offset` (an entry being evicted) or at a stale one.
  fn unindex_name(&mut self, name_hash: u32, offset: u32) {
    if self.name_index.is_empty() {
      return;
    }
    let slot = Self::name_slot(name_hash);
    if self.name_index[slot] == offset {
      self.name_index[slot] = NO_NAME;
    }
  }

  fn wrap(&self, pos: usize) -> usize {
    // pos is at most 2 * ring.len() - 1 in the callers: one conditional subtract, no division
    if pos >= self.ring.len() { pos - self.ring.len() } else { pos }
  }

  // The `len` bytes at `start` of the ring, in one or two slices.
  fn ring_parts(&self, start: usize, len: usize) -> (&[u8], &[u8]) {
    let first_len = len.min(self.ring.len() - start);
    (&self.ring[start..start + first_len], &self.ring[..len - first_len])
  }

  // If the ring holds `bytes` at `start`.
  fn ring_eq(&self, start: usize, bytes: &[u8]) -> bool {
    let (first, second) = self.ring_parts(start, bytes.len());
    first == &bytes[..first.len()] && second == &bytes[first.len()..]
  }

  fn ring_write(&mut self, start: usize, bytes: &[u8]) {
    let first_len = bytes.len().min(self.ring.len() - start);
    self.ring[start..start + first_len].copy_from_slice(&bytes[..first_len]);
    self.ring[..bytes.len() - first_len].copy_from_slice(&bytes[first_len..]);
  }

  // Inserts `field`, room made, by a static or dynamic name reference or a literal name.
  fn insert(
    &mut self,
    static_name: Option<u8>,
    dynamic_name: Option<u64>,
    field: Field<'_>,
    name_hash: u32,
    hash: u32,
  ) {
    let huffman = self.config.huffman;
    if let Some(idx) = static_name {
      // Insert with Name Reference, T = 1 (RFC 9204 section 4.3.2)
      push_prefix_int(&mut self.out, idx.into(), 6, 0b1100_0000);
    } else if let Some(abs) = dynamic_name {
      // Relative to the last insert. The room of this insert may have evicted the entry: the
      // decoder reads the name before it evicts (section 3.2.2)
      push_prefix_int(&mut self.out, self.insert_count - 1 - abs, 6, 0b1000_0000);
    } else {
      // Insert with Literal Name (section 4.3.3)
      push_string(&mut self.out, field.name, 6, 0b0100_0000, huffman);
    }
    push_string(&mut self.out, field.value, 8, 0, huffman);
    self.push_entry(field.name, field.value, name_hash, hash);
  }

  // Duplicates the entry of absolute index `abs` if room can be made (section 4.3.4).
  fn duplicate(&mut self, abs: u64) -> bool {
    let entry = self.entries[(abs - self.dropped) as usize];
    // The room may evict the entry itself (the decoder reads it before it evicts, section
    // 3.2.2), and the new entry overwrite it: it is staged first
    let mut scratch = mem::take(&mut self.scratch);
    scratch.clear();
    let (first, second) = self.ring_parts(entry.start as usize, entry.bytes_len());
    scratch.extend_from_slice(first);
    scratch.extend_from_slice(second);
    if !self.make_room(entry.size()) {
      self.scratch = scratch;
      return false;
    }
    push_prefix_int(&mut self.out, self.insert_count - 1 - abs, 5, 0);
    let (name, value) = scratch.split_at(entry.name_len as usize);
    self.push_entry(name, value, entry.name_hash, entry.hash);
    self.scratch = scratch;
    self.stats.duplicates += 1;
    true
  }

  /// The names and values of the dynamic table, oldest first.
  #[cfg(any(test, feature = "__check"))]
  #[doc(hidden)]
  pub fn table_fields(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
    let read = |start: usize, len: usize| {
      let (first, second) = self.ring_parts(start, len);
      [first, second].concat()
    };
    self
      .entries
      .iter()
      .map(|entry| {
        let start = entry.start as usize;
        let name = read(start, entry.name_len as usize);
        (name, read(self.wrap(start + entry.name_len as usize), entry.value_len as usize))
      })
      .collect()
  }

  /// Panics if the table or the section tracking are not consistent.
  #[cfg(any(test, feature = "__check"))]
  #[doc(hidden)]
  pub fn check_invariants(&self) {
    assert!(self.size <= self.capacity);
    assert!(self.capacity <= self.peer_max_capacity);
    assert!(self.known_received <= self.insert_count);
    assert_eq!(self.dropped + self.entries.len() as u64, self.insert_count);
    assert_eq!(self.size, self.entries.iter().map(DynEntry::size).sum::<u64>());
    assert_eq!(self.ring_len, self.entries.iter().map(DynEntry::bytes_len).sum::<usize>());
    let mut next = self.ring_head;
    for entry in &self.entries {
      assert_eq!(entry.start as usize, next);
      next = self.wrap(next + entry.bytes_len());
    }
    let mut refs = alloc::vec![0u32; self.entries.len()];
    let mut tracked = 0;
    for stream in &self.streams {
      assert!(!stream.sections.is_empty());
      for section in &stream.sections {
        tracked += 1;
        assert!(section.ric > 0 && section.ric <= self.insert_count);
        assert_eq!(section.refs.iter().max().map(|el| el + 1), Some(section.ric));
        for abs in &section.refs {
          refs[(abs - self.dropped) as usize] += 1;
        }
      }
    }
    assert_eq!(tracked, self.tracked);
    for (entry, count) in self.entries.iter().zip(refs) {
      assert_eq!(entry.refs, count);
    }
    assert!(self.blocking_streams() as u64 <= self.peer_blocked);
    assert_eq!(self.blocking_streams() as u64, self.blocking_count);
    // The name index holds, for every entry, the offset of the newest entry with its name
    for (offset, entry) in self.entries.iter().enumerate() {
      let indexed = self.name_index[Self::name_slot(entry.name_hash)];
      if indexed != NO_NAME {
        let newest = self.entries[indexed as usize];
        let found = self.entries.iter().rposition(|el| el.name_hash == entry.name_hash).unwrap();
        assert_eq!(indexed as usize, found, "stale name index for offset {offset}");
        assert!(newest.name_hash == entry.name_hash);
      }
    }
  }
}

fn encode_static_prefix_raw(out: &mut Vec<u8>) {
  out.extend_from_slice(&[0, 0]);
}

// An Indexed Field Line of the dynamic table, relative to the Base or post-Base.
fn push_indexed(lines: &mut Vec<u8>, base: u64, abs: u64) {
  if abs < base {
    push_prefix_int(lines, base - 1 - abs, 6, 0b1000_0000);
  } else {
    push_prefix_int(lines, abs - base, 4, 0b0001_0000);
  }
}

// A hash of name and value, from the hash of the name.
fn value_hash(name_hash: u32, value: &[u8]) -> u32 {
  crate::static_table::hash_bytes(u64::from(name_hash) << 1 | 1, value)
}

#[cfg(test)]
mod tests;
