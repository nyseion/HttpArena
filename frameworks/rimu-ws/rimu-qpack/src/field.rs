//! Field lines: what the encoder takes and the decoder gives, and an owned list of them.

use crate::static_table::StaticRef;
use alloc::vec::Vec;

/// A field line to encode: a name, a value and whether it is sensitive.
///
/// A sensitive field is never inserted into the dynamic table and is sent with the "never
/// indexed" bit (`N`, RFC 9204 section 4.5.4), which tells intermediaries not to index it either.
/// Names must be lowercase (RFC 9114 section 4.2); the codec does not check them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Field<'a> {
  /// The field name.
  pub name: &'a [u8],
  /// The field value.
  pub value: &'a [u8],
  /// Never index this field, here or at intermediaries.
  pub sensitive: bool,
}

impl<'a> Field<'a> {
  /// A field that may be indexed.
  #[inline]
  pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
    Self { name, value, sensitive: false }
  }

  /// A field that must never be indexed.
  #[inline]
  pub const fn sensitive(name: &'a [u8], value: &'a [u8]) -> Self {
    Self { name, value, sensitive: true }
  }

  /// The size of the field as RFC 9114 section 4.2.2 counts it: name, value and 32.
  #[inline]
  pub const fn size(&self) -> u64 {
    self.name.len() as u64 + self.value.len() as u64 + 32
  }
}

impl<'a> From<&Field<'a>> for Field<'a> {
  #[inline]
  fn from(field: &Field<'a>) -> Self {
    *field
  }
}

impl<'a> From<(&'a [u8], &'a [u8])> for Field<'a> {
  #[inline]
  fn from((name, value): (&'a [u8], &'a [u8])) -> Self {
    Self::new(name, value)
  }
}

impl<'a> From<&(&'a [u8], &'a [u8])> for Field<'a> {
  #[inline]
  fn from((name, value): &(&'a [u8], &'a [u8])) -> Self {
    Self::new(name, value)
  }
}

impl<'a> From<&(&'a str, &'a str)> for Field<'a> {
  #[inline]
  fn from((name, value): &(&'a str, &'a str)) -> Self {
    Self::new(name.as_bytes(), value.as_bytes())
  }
}

impl<'a> From<(&'a str, &'a str)> for Field<'a> {
  #[inline]
  fn from((name, value): (&'a str, &'a str)) -> Self {
    Self::new(name.as_bytes(), value.as_bytes())
  }
}

/// A decoded field line, borrowed from the field section, the static table or the decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedField<'a> {
  /// The field name.
  pub name: &'a [u8],
  /// The field value.
  pub value: &'a [u8],
  /// The encoder sent the field with the "never indexed" bit: an intermediary that re-encodes it
  /// must not index it either.
  pub sensitive: bool,
  /// The static table entry that gave the name (and the value, for an Indexed Field Line).
  pub static_ref: Option<StaticRef>,
}

impl<'a> DecodedField<'a> {
  /// The field as an encoder input, keeping its sensitivity.
  #[inline]
  pub const fn as_field(&self) -> Field<'a> {
    Field { name: self.name, value: self.value, sensitive: self.sensitive }
  }
}

/// An owned list of fields in one allocation of bytes and one of lengths.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FieldList {
  bytes: Vec<u8>,
  fields: Vec<(u32, u32, bool)>,
}

impl FieldList {
  /// An empty list, which allocates nothing.
  #[inline]
  pub const fn new() -> Self {
    Self { bytes: Vec::new(), fields: Vec::new() }
  }

  /// Appends a field. Names and values longer than 4 GiB are not supported and panic.
  #[inline]
  pub fn push(&mut self, field: Field<'_>) {
    let name_len = u32::try_from(field.name.len()).expect("field name over 4 GiB");
    let value_len = u32::try_from(field.value.len()).expect("field value over 4 GiB");
    self.bytes.extend_from_slice(field.name);
    self.bytes.extend_from_slice(field.value);
    self.fields.push((name_len, value_len, field.sensitive));
  }

  /// The number of fields.
  #[inline]
  pub fn len(&self) -> usize {
    self.fields.len()
  }

  /// If there is no field.
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.fields.is_empty()
  }

  /// Removes every field and keeps the allocations.
  #[inline]
  pub fn clear(&mut self) {
    self.bytes.clear();
    self.fields.clear();
  }

  /// The fields in order.
  #[inline]
  pub fn iter(&self) -> FieldListIter<'_> {
    FieldListIter { bytes: &self.bytes, fields: self.fields.iter() }
  }

  /// The fields, collected for an encoder call.
  pub fn to_vec(&self) -> Vec<Field<'_>> {
    self.iter().collect()
  }
}

impl<'a> FromIterator<Field<'a>> for FieldList {
  fn from_iter<T: IntoIterator<Item = Field<'a>>>(iter: T) -> Self {
    let mut list = Self::new();
    for field in iter {
      list.push(field);
    }
    list
  }
}

impl<'a> IntoIterator for &'a FieldList {
  type Item = Field<'a>;
  type IntoIter = FieldListIter<'a>;

  #[inline]
  fn into_iter(self) -> Self::IntoIter {
    self.iter()
  }
}

/// The iterator of [`FieldList::iter`].
#[derive(Clone, Debug)]
pub struct FieldListIter<'a> {
  bytes: &'a [u8],
  fields: core::slice::Iter<'a, (u32, u32, bool)>,
}

impl<'a> Iterator for FieldListIter<'a> {
  type Item = Field<'a>;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    let (name_len, value_len, sensitive) = *self.fields.next()?;
    let (name, rest) = self.bytes.split_at(name_len as usize);
    let (value, rest) = rest.split_at(value_len as usize);
    self.bytes = rest;
    Some(Field { name, value, sensitive })
  }

  #[inline]
  fn size_hint(&self) -> (usize, Option<usize>) {
    self.fields.size_hint()
  }
}

impl ExactSizeIterator for FieldListIter<'_> {}
