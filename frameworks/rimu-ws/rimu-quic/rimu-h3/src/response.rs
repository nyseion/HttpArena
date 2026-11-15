//! The field sections of responses, encoded with the static table of QPACK (rimu-qpack's
//! `encode_static_*`): [`ResponseHeads`] and the `date` line of [`DateLine`].
//!
//! The field lines of `:status`, `content-type`, `content-encoding` and `vary` are kept encoded per
//! combination of their values (a few of them per worker, the least recently used replaced, the
//! last one used looked at first, without making its key), the line of `date` once a second;
//! `content-length` and the other fields are encoded per response, in a second pass over the
//! fields that only a response with such fields takes.
//!
//! The default is `:status` and `content-type` only, like the HttpArena HTTP/3 leaders: that is
//! not RFC 9110-compliant, which wants `date` (section 6.6.1) and `content-length` (section 8.6,
//! a SHOULD when the size is known); [`crate::H3Params::rfc9110_headers`] turns both on.

use alloc::vec::Vec;
use rimu_qpack::{encode_static_line, encode_static_prefix};

/// The combinations of the fields of a response that are kept encoded: past them, the least
/// recently used is encoded again for the next one, which allocates when it is longer than the
/// room that block had. A workload with at most this many allocates nothing in the steady state.
const MAX_BLOCKS: usize = 64;
/// The bytes of the values of a combination past which it is encoded per response.
const MAX_BLOCK_KEY: usize = 512;

/// The fields of a response that [`ResponseHeads`] encodes: `:status`, the three fields that are
/// kept encoded with it, and others.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseFields<'a> {
  /// `:status`.
  pub status: u16,
  /// `content-type`, if any.
  pub content_type: Option<&'a [u8]>,
  /// `content-encoding`, if any.
  pub content_encoding: Option<&'a [u8]>,
  /// `vary`, if any.
  pub vary: Option<&'a [u8]>,
  /// Other fields, in order. Fields that HTTP/3 does not send (`connection`, `keep-alive`,
  /// `proxy-connection`, `transfer-encoding`, `upgrade`, RFC 9114 section 4.2) and
  /// `content-length` (written from the body) are left out; names are lowercased.
  pub others: &'a [(&'a [u8], &'a [u8])],
}

impl<'a> ResponseFields<'a> {
  /// `status` and nothing else.
  #[inline]
  pub const fn status(status: u16) -> Self {
    Self { status, content_type: None, content_encoding: None, vary: None, others: &[] }
  }

  /// `status` and `content-type`.
  #[inline]
  pub const fn with_type(status: u16, content_type: &'a [u8]) -> Self {
    Self {
      status,
      content_type: Some(content_type),
      content_encoding: None,
      vary: None,
      others: &[],
    }
  }
}

/// The field lines of `:status`, `content-type`, `content-encoding` and `vary` of a combination of
/// their values.
#[derive(Debug)]
struct Block {
  key: Vec<u8>,
  last_use: u64,
  lines: Vec<u8>,
}

/// What encodes the field sections of the responses of a worker with the static table: the lines
/// of `:status`, `content-type`, `content-encoding` and `vary` kept encoded per combination of their
/// values (64 at most, the least recently used replaced), `date` and `content-length` added per
/// response, the other fields encoded per response.
#[derive(Debug)]
pub struct ResponseHeads {
  blocks: Vec<Block>,
  key: Vec<u8>,
  // The block used last
  last: Option<usize>,
  lower: Vec<u8>,
  section: Vec<u8>,
  uses: u64,
}

impl ResponseHeads {
  /// No combination kept yet.
  #[inline]
  pub const fn new() -> Self {
    Self {
      blocks: Vec::new(),
      key: Vec::new(),
      last: None,
      lower: Vec::new(),
      section: Vec::new(),
      uses: 0,
    }
  }

  /// The field section of a response of `fields`, `content-length` if `length` and the `date`
  /// line `date` (from [`DateLine::line`]) if any.
  #[inline]
  pub fn encode(
    &mut self,
    fields: &ResponseFields<'_>,
    length: Option<usize>,
    date: Option<&[u8]>,
  ) -> &[u8] {
    let [mut content_type, mut content_encoding, mut vary] =
      [fields.content_type, fields.content_encoding, fields.vary];
    // If a field is left for the second pass below
    let mut others = false;
    for (name, value) in fields.others {
      let slot = match known(name) {
        Some(Known::ContentType) => &mut content_type,
        Some(Known::ContentEncoding) => &mut content_encoding,
        Some(Known::Vary) => &mut vary,
        Some(Known::ContentLength | Known::ConnectionSpecific) => continue,
        Some(Known::Date) | None => {
          others = true;
          continue;
        }
      };
      if slot.is_none() {
        *slot = Some(value);
      } else {
        others = true;
      }
    }
    self.section.clear();
    encode_static_prefix(&mut self.section);
    let block_fields = [content_type, content_encoding, vary];
    let idx = self.block(fields.status, block_fields);
    match idx.and_then(|el| self.blocks.get(el)) {
      Some(block) => self.section.extend_from_slice(&block.lines),
      None => write_block(fields.status, block_fields, &mut self.section),
    }
    if let Some(elem) = date {
      self.section.extend_from_slice(elem);
    }
    if let Some(elem) = length {
      let mut digits = [0u8; 20];
      encode_static_line(b"content-length", decimal(elem, &mut digits), &mut self.section);
    }
    if !others {
      return &self.section;
    }
    // The fields given apart win over the same ones in `others`, which go after them
    let mut firsts =
      [fields.content_type.is_none(), fields.content_encoding.is_none(), fields.vary.is_none()];
    for (name, value) in fields.others {
      let first = match known(name) {
        Some(Known::ContentType) => firsts.get_mut(0),
        Some(Known::ContentEncoding) => firsts.get_mut(1),
        Some(Known::Vary) => firsts.get_mut(2),
        // Written above, or not sent over HTTP/3 (RFC 9114 section 4.2)
        Some(Known::ContentLength | Known::ConnectionSpecific) => continue,
        Some(Known::Date) if date.is_some() => continue,
        Some(Known::Date) | None => None,
      };
      if let Some(elem) = first
        && core::mem::replace(elem, false)
      {
        continue;
      }
      let name = if name.iter().any(u8::is_ascii_uppercase) {
        self.lower.clear();
        self.lower.extend_from_slice(name);
        self.lower.make_ascii_lowercase();
        self.lower.as_slice()
      } else {
        name
      };
      encode_static_line(name, value, &mut self.section);
    }
    &self.section
  }

  /// The bytes that the kept combinations and buffers take.
  #[inline]
  pub fn heap_bytes(&self) -> usize {
    self.blocks.iter().fold(self.blocks.capacity().saturating_mul(size_of::<Block>()), |acc, el| {
      acc.saturating_add(el.key.capacity()).saturating_add(el.lines.capacity())
    }) + self.key.capacity()
      + self.lower.capacity()
      + self.section.capacity()
  }

  // The index of the block of `status` and `fields`, encoded now if it was not; `None` for values
  // too long to keep.
  fn block(&mut self, status: u16, fields: [Option<&[u8]>; 3]) -> Option<usize> {
    self.uses = self.uses.wrapping_add(1);
    let values = fields.iter().flatten().map(|el| el.len()).sum::<usize>();
    if values > MAX_BLOCK_KEY {
      return None;
    }
    // The last block used first, then the others, compared without making the key
    let last = self.last.filter(|el| {
      self.blocks.get(*el).is_some_and(|block| key_matches(&block.key, status, fields))
    });
    let found =
      last.or_else(|| self.blocks.iter().position(|el| key_matches(&el.key, status, fields)));
    if let Some(idx) = found {
      if let Some(block) = self.blocks.get_mut(idx) {
        block.last_use = self.uses;
      }
      self.last = Some(idx);
      return Some(idx);
    }
    self.key.clear();
    self.key.extend_from_slice(&status.to_be_bytes());
    for field in fields {
      let len = field.map_or(u16::MAX, |el| u16::try_from(el.len()).unwrap_or(u16::MAX));
      self.key.extend_from_slice(&len.to_be_bytes());
      self.key.extend_from_slice(field.unwrap_or_default());
    }
    let idx = if self.blocks.len() < MAX_BLOCKS {
      self.blocks.push(Block { key: Vec::new(), last_use: 0, lines: Vec::new() });
      self.blocks.len().wrapping_sub(1)
    } else {
      let oldest = self.blocks.iter().enumerate().min_by_key(|el| el.1.last_use).map(|el| el.0);
      oldest.unwrap_or(0)
    };
    let block = self.blocks.get_mut(idx)?;
    block.key.clear();
    block.key.extend_from_slice(&self.key);
    block.lines.clear();
    block.last_use = self.uses;
    write_block(status, fields, &mut block.lines);
    self.last = Some(idx);
    Some(idx)
  }
}

impl Default for ResponseHeads {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// The `date` field line of responses (RFC 9110 section 6.6.1), encoded with the static table
/// again when the second changes.
#[derive(Debug)]
pub struct DateLine {
  line: Vec<u8>,
  secs: u64,
  text: [u8; 29],
}

impl DateLine {
  /// No date yet: [`Self::set`] gives it one.
  #[inline]
  pub const fn new() -> Self {
    Self { line: Vec::new(), secs: u64::MAX, text: [0; 29] }
  }

  /// The encoded field line, empty before the first [`Self::set`].
  #[inline]
  pub fn line(&self) -> &[u8] {
    &self.line
  }

  /// The value, as IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), empty before the first
  /// [`Self::set`].
  #[inline]
  pub fn text(&self) -> &[u8] {
    if self.line.is_empty() { &[] } else { &self.text }
  }

  /// The time is `unix_secs` seconds after the Unix epoch: the line is encoded again if the second
  /// changed.
  #[inline]
  pub fn set(&mut self, unix_secs: u64) {
    if unix_secs == self.secs {
      return;
    }
    self.secs = unix_secs;
    imf_fixdate(unix_secs, &mut self.text);
    self.line.clear();
    encode_static_line(b"date", &self.text, &mut self.line);
  }
}

impl Default for DateLine {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Writes the IMF-fixdate of RFC 9110 section 5.6.7 (`Sun, 06 Nov 1994 08:49:37 GMT`) of
/// `unix_secs`, seconds after the Unix epoch, into `out`.
#[inline]
pub fn imf_fixdate(unix_secs: u64, out: &mut [u8; 29]) {
  const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
  const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
  ];
  let days = unix_secs / 86_400;
  let secs = unix_secs % 86_400;
  // 1 Jan 1970 was a Thursday
  let weekday = DAYS.get(usize::try_from(days % 7).unwrap_or(0)).copied().unwrap_or(b"Thu");
  let (year, month, day) = civil_from_days(days);
  let month = MONTHS.get(usize::from(month.wrapping_sub(1))).copied().unwrap_or(b"Jan");
  let two = |value: u64| [b'0' + (value / 10 % 10) as u8, b'0' + (value % 10) as u8];
  let year = year.min(9999);
  let parts: [&[u8]; 14] = [
    weekday,
    b", ",
    &two(u64::from(day)),
    b" ",
    month,
    b" ",
    &two(year / 100),
    &two(year % 100),
    b" ",
    &two(secs / 3600),
    b":",
    &two(secs / 60 % 60),
    b":",
    &two(secs % 60),
  ];
  let mut at = 0usize;
  for part in parts.iter().chain([&&b" GMT"[..]]) {
    if let Some(dst) = out.get_mut(at..at.wrapping_add(part.len())) {
      dst.copy_from_slice(part);
    }
    at = at.wrapping_add(part.len());
  }
}

// The year, month (1 to 12) and day (1 to 31) of the day `days` after 1 Jan 1970, in the
// proleptic Gregorian calendar: counted in eras of 400 years from 1 Mar 0000, whose years start
// in March so that the leap day ends them.
fn civil_from_days(days: u64) -> (u64, u8, u8) {
  // 1 Mar 0000 to 1 Jan 1970
  let from_era_start = days.wrapping_add(719_468);
  let era = from_era_start / 146_097;
  let day_of_era = from_era_start % 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  // March is 0
  let shifted_month = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
  let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
  let year = year_of_era + era * 400 + u64::from(month <= 2);
  (year, u8::try_from(month).unwrap_or(1), u8::try_from(day).unwrap_or(1))
}

// If `key` is the key of a block of `status` and `fields`: the status, then for each field the
// length of its value (`u16::MAX` for none) and the value, as `ResponseHeads::block` makes it.
fn key_matches(key: &[u8], status: u16, fields: [Option<&[u8]>; 3]) -> bool {
  let Some((head, mut rest)) = key.split_first_chunk::<2>() else {
    return false;
  };
  if *head != status.to_be_bytes() {
    return false;
  }
  for field in fields {
    let Some((len, after)) = rest.split_first_chunk::<2>() else {
      return false;
    };
    let value = field.unwrap_or_default();
    let expected = field.map_or(u16::MAX, |el| u16::try_from(el.len()).unwrap_or(u16::MAX));
    if *len != expected.to_be_bytes() || !after.starts_with(value) {
      return false;
    }
    rest = after.get(value.len()..).unwrap_or_default();
  }
  rest.is_empty()
}

// The fields of a response that the encoder treats apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Known {
  ConnectionSpecific,
  ContentEncoding,
  ContentLength,
  ContentType,
  Date,
  Vary,
}

// By the length of the name first: one comparison at most for most names (ruling T16-a).
pub(crate) fn known(name: &[u8]) -> Option<Known> {
  let is = |known: &[u8]| name.eq_ignore_ascii_case(known);
  match name.len() {
    4 if is(b"vary") => Some(Known::Vary),
    4 if is(b"date") => Some(Known::Date),
    7 if is(b"upgrade") => Some(Known::ConnectionSpecific),
    10 if is(b"connection") || is(b"keep-alive") => Some(Known::ConnectionSpecific),
    12 if is(b"content-type") => Some(Known::ContentType),
    14 if is(b"content-length") => Some(Known::ContentLength),
    16 if is(b"content-encoding") => Some(Known::ContentEncoding),
    16 if is(b"proxy-connection") => Some(Known::ConnectionSpecific),
    17 if is(b"transfer-encoding") => Some(Known::ConnectionSpecific),
    _ => None,
  }
}

// The lines of `:status` and of the fields of a block that are present, in that order.
fn write_block(
  status: u16,
  [content_type, content_encoding, vary]: [Option<&[u8]>; 3],
  out: &mut Vec<u8>,
) {
  let mut digits = [0u8; 20];
  encode_static_line(b":status", decimal(status.into(), &mut digits), out);
  for (name, value) in
    [(&b"content-type"[..], content_type), (b"content-encoding", content_encoding), (b"vary", vary)]
  {
    if let Some(elem) = value {
      encode_static_line(name, elem, out);
    }
  }
}

/// `value` in decimal digits, written at the end of `buffer`.
#[inline]
pub(crate) fn decimal(mut value: usize, buffer: &mut [u8; 20]) -> &[u8] {
  let mut start = buffer.len();
  loop {
    start = start.wrapping_sub(1);
    if let Some(elem) = buffer.get_mut(start) {
      *elem = b'0'.wrapping_add((value % 10) as u8);
    }
    value /= 10;
    if value == 0 || start == 0 {
      break;
    }
  }
  buffer.get(start..).unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use crate::response::{
    DateLine, Known, ResponseFields, ResponseHeads, civil_from_days, decimal, imf_fixdate, known,
  };
  use alloc::{format, vec, vec::Vec};
  use rimu_qpack::{encode_static, encode_static_line};

  fn known_one_by_one(name: &[u8]) -> Option<Known> {
    let lower = name.to_ascii_lowercase();
    match lower.as_slice() {
      b"vary" => Some(Known::Vary),
      b"date" => Some(Known::Date),
      b"upgrade" | b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" => {
        Some(Known::ConnectionSpecific)
      }
      b"content-type" => Some(Known::ContentType),
      b"content-length" => Some(Known::ContentLength),
      b"content-encoding" => Some(Known::ContentEncoding),
      _ => None,
    }
  }

  // Ruling T16-a: the fields treated apart are found by the length of their name first; the result
  // is that of comparing every name, in any case.
  #[test]
  fn known_fields_by_length_match_one_by_one() {
    for name in [
      &b"vary"[..],
      b"Vary",
      b"date",
      b"DATE",
      b"upgrade",
      b"connection",
      b"keep-alive",
      b"content-type",
      b"Content-Type",
      b"content-length",
      b"content-encoding",
      b"proxy-connection",
      b"transfer-encoding",
      b"x-vary",
      b"dat",
      b"content-typo",
      b"server",
      b"",
    ] {
      assert_eq!(known(name), known_one_by_one(name), "{name:?}");
    }
  }

  // The section of a combination, kept encoded or not, is the static encoding of its fields: block
  // lines first, then the others in order, the ones that HTTP/3 does not send left out.
  #[test]
  fn sections_match_the_static_encoding_of_their_fields() {
    let mut heads = ResponseHeads::new();
    let cases: [(ResponseFields<'_>, &[(&[u8], &[u8])]); 5] = [
      (ResponseFields::status(200), &[(b":status", b"200")]),
      (
        ResponseFields::with_type(200, b"text/plain"),
        &[(b":status", b"200"), (b"content-type", b"text/plain")],
      ),
      (
        ResponseFields {
          status: 404,
          others: &[(b"Server", b"rimu"), (b"connection", b"close"), (b"content-length", b"9")],
          ..ResponseFields::with_type(404, b"text/html")
        },
        &[(b":status", b"404"), (b"content-type", b"text/html"), (b"server", b"rimu")],
      ),
      (
        ResponseFields {
          status: 200,
          content_type: None,
          content_encoding: Some(b"br"),
          vary: Some(b"accept-encoding"),
          others: &[(b"content-type", b"text/plai"), (b"date", b"x")],
        },
        &[
          (b":status", b"200"),
          (b"content-type", b"text/plai"),
          (b"content-encoding", b"br"),
          (b"vary", b"accept-encoding"),
          (b"date", b"x"),
        ],
      ),
      // A second content-type is sent as given, after the first
      (
        ResponseFields {
          others: &[(b"content-type", b"b")],
          ..ResponseFields::with_type(200, b"a")
        },
        &[(b":status", b"200"), (b"content-type", b"a"), (b"content-type", b"b")],
      ),
    ];
    for _ in 0..2 {
      for (fields, lines) in &cases {
        let mut expected = Vec::new();
        encode_static(lines.iter().copied(), &mut expected);
        assert_eq!(heads.encode(fields, None, None), expected.as_slice(), "{lines:?}");
      }
    }
  }

  // The section with the `date` line, `content-length` and a combination too long to keep encoded
  // is the static encoding of the fields in that order: block lines, date, content-length, others.
  #[test]
  fn sections_with_date_length_and_long_values_match_the_static_encoding() {
    let mut heads = ResponseHeads::new();
    let mut date = Vec::new();
    encode_static_line(b"date", b"Mon, 09 Nov 2026 12:00:00 GMT", &mut date);
    let long = vec![b't'; 600];
    for content_type in [&b"text/plain"[..], &long] {
      for (length, with_date) in [(None, false), (Some(1234), false), (None, true), (Some(0), true)]
      {
        let fields = ResponseFields {
          others: &[(b"x-a", b"1")],
          ..ResponseFields::with_type(200, content_type)
        };
        let date_line = with_date.then_some(date.as_slice());
        let section = heads.encode(&fields, length, date_line).to_vec();
        let text = length.map(|el| format!("{el}"));
        let mut lines: Vec<(&[u8], &[u8])> =
          vec![(b":status", b"200"), (b"content-type", content_type)];
        if with_date {
          lines.push((b"date", b"Mon, 09 Nov 2026 12:00:00 GMT"));
        }
        if let Some(elem) = &text {
          lines.push((b"content-length", elem.as_bytes()));
        }
        lines.push((b"x-a", b"1"));
        let mut expected = Vec::new();
        encode_static(lines, &mut expected);
        assert_eq!(section, expected);
      }
    }
  }

  // Up to the cap of combinations, a round of responses over all of them encodes nothing again,
  // and the least recently used one goes first past it.
  #[test]
  fn combinations_up_to_the_cap_are_kept_and_the_oldest_goes_first() {
    let mut heads = ResponseHeads::new();
    let types: Vec<Vec<u8>> = (0..64).map(|el| format!("type/{el}").into_bytes()).collect();
    for content_type in &types {
      let _ = heads.encode(&ResponseFields::with_type(200, content_type), None, None);
    }
    let bytes = heads.heap_bytes();
    for _ in 0..3 {
      for content_type in &types {
        let _ = heads.encode(&ResponseFields::with_type(200, content_type), None, None);
      }
    }
    assert_eq!(heads.heap_bytes(), bytes);
    assert_eq!(heads.blocks.len(), 64);
    // One more takes the place of the least recently used, the first one
    let _ = heads.encode(&ResponseFields::with_type(200, b"type/new"), None, None);
    assert_eq!(heads.blocks.len(), 64);
    assert!(!heads.blocks.iter().any(|el| el.key.ends_with(b"type/0\xff\xff\xff\xff")));
  }

  // Decimal digits of every magnitude.
  #[test]
  fn decimals() {
    for value in [0usize, 7, 10, 99, 100, 12_345, usize::MAX] {
      let mut buffer = [0u8; 20];
      assert_eq!(decimal(value, &mut buffer), format!("{value}").as_bytes());
    }
  }

  // RFC 9110 section 5.6.7's example, the epoch, leap days and the end of centuries, against days
  // counted one by one.
  #[test]
  fn imf_fixdates() {
    let mut out = [0u8; 29];
    for (secs, text) in [
      (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
      (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
      (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
      (4_133_980_799, "Fri, 31 Dec 2100 23:59:59 GMT"),
      (1_794_571_200, "Fri, 13 Nov 2026 12:00:00 GMT"),
    ] {
      imf_fixdate(secs, &mut out);
      assert_eq!(core::str::from_utf8(&out).unwrap(), text, "{secs}");
    }
    let (mut year, mut month, mut day) = (1970u64, 1u8, 1u8);
    for days in 0..200_000u64 {
      assert_eq!(civil_from_days(days), (year, month, day), "{days}");
      let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
      let len = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
      };
      day += 1;
      if day > len {
        day = 1;
        month += 1;
        if month > 12 {
          month = 1;
          year += 1;
        }
      }
    }
    let mut line = DateLine::new();
    assert!(line.line().is_empty() && line.text().is_empty());
    line.set(784_111_777);
    let mut expected = Vec::new();
    encode_static_line(b"date", b"Sun, 06 Nov 1994 08:49:37 GMT", &mut expected);
    assert_eq!(line.line(), expected.as_slice());
    assert_eq!(line.text(), b"Sun, 06 Nov 1994 08:49:37 GMT");
  }
}
