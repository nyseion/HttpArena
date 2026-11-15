//! Field sections decoded lately, with what they decoded to.
//!
//! Clients repeat requests byte for byte, and so do servers their response heads. A field section
//! decodes to the same fields as long as the dynamic table entries that it references are there:
//! the key is the absolute Required Insert Count with the bytes of the section, and an entry is
//! replayed only while the lowest absolute index that its section referenced is not evicted.
//! Absolute indices are never reused within one table, and the memo belongs to its decoder, which
//! clears it when its table starts over, so a replay always gives what a decode would give. The
//! decoder replays a kept section with the same effects as a decode: the blocked check before and
//! the Section Acknowledgment after.

use crate::static_table::StaticRef;
use alloc::vec::Vec;

/// Longer field sections are not kept: they are rarely repeated and costly to compare.
pub(crate) const MAX_SECTION_LEN: usize = 128;
/// Sections that decode to more bytes of names and values are not kept, which bounds the memory
/// of an entry (a section of 128 bytes can reference 4 KiB entries of the dynamic table).
pub(crate) const MAX_DECODED_LEN: usize = 2048;

/// One field of a kept section: name length, value length, static reference code, sensitive.
type MemoField = (u32, u32, u8, bool);

#[derive(Clone, Debug)]
struct Entry {
  /// Names and values, one after the other.
  bytes: Vec<u8>,
  fields: Vec<MemoField>,
  last_use: u64,
  lowest_dynamic: u64,
  ric: u64,
  section: [u8; MAX_SECTION_LEN],
  /// 0 while the entry holds nothing that can be replayed.
  section_len: u8,
}

impl Entry {
  const fn new() -> Self {
    Self {
      bytes: Vec::new(),
      fields: Vec::new(),
      last_use: 0,
      lowest_dynamic: 0,
      ric: 0,
      section: [0; MAX_SECTION_LEN],
      section_len: 0,
    }
  }

  fn holds(&self, ric: u64, section: &[u8]) -> bool {
    self.section_len != 0
      && self.ric == ric
      && self.section.get(..usize::from(self.section_len)) == Some(section)
  }
}

/// See the module documentation. The entries are allocated on first use.
#[derive(Clone, Debug, Default)]
pub(crate) struct DecodeMemo {
  capacity: usize,
  entries: Vec<Entry>,
  uses: u64,
}

impl DecodeMemo {
  /// A memo of up to `capacity` sections; 0 keeps nothing.
  pub(crate) const fn new(capacity: usize) -> Self {
    Self { capacity, entries: Vec::new(), uses: 0 }
  }

  pub(crate) const fn is_enabled(&self) -> bool {
    self.capacity > 0
  }

  /// The bytes that the kept fields take on the heap.
  pub(crate) fn heap_bytes(&self) -> usize {
    let entries = self.entries.capacity() * size_of::<Entry>();
    self.entries.iter().fold(entries, |acc, el| {
      acc + el.bytes.capacity() + el.fields.capacity() * size_of::<MemoField>()
    })
  }

  /// The sections that can be replayed.
  #[cfg(test)]
  pub(crate) fn kept(&self) -> usize {
    self.entries.iter().filter(|el| el.section_len != 0).count()
  }

  /// Forgets every kept section; the storage stays for the next ones.
  pub(crate) fn clear(&mut self) {
    for entry in &mut self.entries {
      entry.last_use = 0;
      entry.section_len = 0;
    }
    self.uses = 0;
  }

  /// The fields that `section` with the absolute Required Insert Count `ric` decoded to, if it is
  /// kept and the lowest dynamic table entry that it referenced is at or above `oldest_live`.
  pub(crate) fn lookup(
    &mut self,
    ric: u64,
    section: &[u8],
    oldest_live: u64,
  ) -> Option<MemoFields<'_>> {
    if section.len() > MAX_SECTION_LEN || section.is_empty() {
      return None;
    }
    self.uses += 1;
    let uses = self.uses;
    let entry = self.entries.iter_mut().find(|el| el.holds(ric, section))?;
    if entry.lowest_dynamic < oldest_live {
      return None;
    }
    entry.last_use = uses;
    Some(MemoFields { bytes: &entry.bytes, fields: entry.fields.iter() })
  }

  /// Starts keeping `section` with the absolute Required Insert Count `ric`, in place of the entry
  /// that holds the same section or else of the entry used least recently: the fields are pushed
  /// to the recorder as they are decoded, which keeps them once it is sealed. `None` if the
  /// section is too long to be kept or the memo is disabled.
  pub(crate) fn insert(&mut self, ric: u64, section: &[u8]) -> Option<MemoRecorder<'_>> {
    if self.capacity == 0 || section.is_empty() || section.len() > MAX_SECTION_LEN {
      return None;
    }
    let section_len = section.len() as u8;
    let idx = match self.entries.iter().position(|el| el.holds(ric, section)) {
      Some(idx) => idx,
      None if self.entries.len() < self.capacity => {
        self.entries.push(Entry::new());
        self.entries.len() - 1
      }
      None => self.entries.iter().enumerate().min_by_key(|(_, el)| el.last_use)?.0,
    };
    self.uses += 1;
    let entry = self.entries.get_mut(idx)?;
    entry.bytes.clear();
    entry.fields.clear();
    entry.last_use = self.uses;
    entry.ric = ric;
    entry.section[..section.len()].copy_from_slice(section);
    entry.section_len = 0;
    Some(MemoRecorder { entry, section_len, valid: true })
  }
}

/// The fields of a kept section: name, value, static reference and sensitivity.
#[derive(Debug)]
pub(crate) struct MemoFields<'memo> {
  bytes: &'memo [u8],
  fields: core::slice::Iter<'memo, MemoField>,
}

impl<'memo> Iterator for MemoFields<'memo> {
  type Item = (&'memo [u8], &'memo [u8], Option<StaticRef>, bool);

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    let (name_len, value_len, sref, sensitive) = *self.fields.next()?;
    let (name, rest) = self.bytes.split_at_checked(name_len as usize)?;
    let (value, rest) = rest.split_at_checked(value_len as usize)?;
    self.bytes = rest;
    Some((name, value, StaticRef::from_code(sref), sensitive))
  }
}

/// Records the fields of a section that is being decoded, see [`DecodeMemo::insert`]. Dropped
/// without [`Self::seal`], the entry keeps nothing.
#[derive(Debug)]
pub(crate) struct MemoRecorder<'memo> {
  entry: &'memo mut Entry,
  section_len: u8,
  valid: bool,
}

impl MemoRecorder<'_> {
  /// Keeps a decoded field. A section that decodes to more than [`MAX_DECODED_LEN`] bytes is not
  /// kept.
  pub(crate) fn push(
    &mut self,
    name: &[u8],
    value: &[u8],
    sref: Option<StaticRef>,
    sensitive: bool,
  ) {
    if !self.valid {
      return;
    }
    if self.entry.bytes.len() + name.len() + value.len() > MAX_DECODED_LEN {
      self.valid = false;
      return;
    }
    self.entry.bytes.extend_from_slice(name);
    self.entry.bytes.extend_from_slice(value);
    // Both are below MAX_DECODED_LEN
    self.entry.fields.push((
      name.len() as u32,
      value.len() as u32,
      StaticRef::code(sref),
      sensitive,
    ));
  }

  /// Keeps the section, which referenced no dynamic table entry below `lowest_dynamic`
  /// (`u64::MAX` for none).
  pub(crate) fn seal(self, lowest_dynamic: u64) {
    if self.valid {
      self.entry.lowest_dynamic = lowest_dynamic;
      self.entry.section_len = self.section_len;
    }
  }
}
