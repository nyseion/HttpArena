//! The QPACK static table (RFC 9204 Appendix A), and its lookups by name and by name and value.

/// The 99 entries of RFC 9204 Appendix A, indexed from 0: name and value.
pub static STATIC_TABLE: [(&[u8], &[u8]); 99] = [
  (b":authority", b""),
  (b":path", b"/"),
  (b"age", b"0"),
  (b"content-disposition", b""),
  (b"content-length", b"0"),
  (b"cookie", b""),
  (b"date", b""),
  (b"etag", b""),
  (b"if-modified-since", b""),
  (b"if-none-match", b""),
  (b"last-modified", b""),
  (b"link", b""),
  (b"location", b""),
  (b"referer", b""),
  (b"set-cookie", b""),
  (b":method", b"CONNECT"),
  (b":method", b"DELETE"),
  (b":method", b"GET"),
  (b":method", b"HEAD"),
  (b":method", b"OPTIONS"),
  (b":method", b"POST"),
  (b":method", b"PUT"),
  (b":scheme", b"http"),
  (b":scheme", b"https"),
  (b":status", b"103"),
  (b":status", b"200"),
  (b":status", b"304"),
  (b":status", b"404"),
  (b":status", b"503"),
  (b"accept", b"*/*"),
  (b"accept", b"application/dns-message"),
  (b"accept-encoding", b"gzip, deflate, br"),
  (b"accept-ranges", b"bytes"),
  (b"access-control-allow-headers", b"cache-control"),
  (b"access-control-allow-headers", b"content-type"),
  (b"access-control-allow-origin", b"*"),
  (b"cache-control", b"max-age=0"),
  (b"cache-control", b"max-age=2592000"),
  (b"cache-control", b"max-age=604800"),
  (b"cache-control", b"no-cache"),
  (b"cache-control", b"no-store"),
  (b"cache-control", b"public, max-age=31536000"),
  (b"content-encoding", b"br"),
  (b"content-encoding", b"gzip"),
  (b"content-type", b"application/dns-message"),
  (b"content-type", b"application/javascript"),
  (b"content-type", b"application/json"),
  (b"content-type", b"application/x-www-form-urlencoded"),
  (b"content-type", b"image/gif"),
  (b"content-type", b"image/jpeg"),
  (b"content-type", b"image/png"),
  (b"content-type", b"text/css"),
  (b"content-type", b"text/html; charset=utf-8"),
  (b"content-type", b"text/plain"),
  (b"content-type", b"text/plain;charset=utf-8"),
  (b"range", b"bytes=0-"),
  (b"strict-transport-security", b"max-age=31536000"),
  (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
  (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
  (b"vary", b"accept-encoding"),
  (b"vary", b"origin"),
  (b"x-content-type-options", b"nosniff"),
  (b"x-xss-protection", b"1; mode=block"),
  (b":status", b"100"),
  (b":status", b"204"),
  (b":status", b"206"),
  (b":status", b"302"),
  (b":status", b"400"),
  (b":status", b"403"),
  (b":status", b"421"),
  (b":status", b"425"),
  (b":status", b"500"),
  (b"accept-language", b""),
  (b"access-control-allow-credentials", b"FALSE"),
  (b"access-control-allow-credentials", b"TRUE"),
  (b"access-control-allow-headers", b"*"),
  (b"access-control-allow-methods", b"get"),
  (b"access-control-allow-methods", b"get, post, options"),
  (b"access-control-allow-methods", b"options"),
  (b"access-control-expose-headers", b"content-length"),
  (b"access-control-request-headers", b"content-type"),
  (b"access-control-request-method", b"get"),
  (b"access-control-request-method", b"post"),
  (b"alt-svc", b"clear"),
  (b"authorization", b""),
  (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
  (b"early-data", b"1"),
  (b"expect-ct", b""),
  (b"forwarded", b""),
  (b"if-range", b""),
  (b"origin", b""),
  (b"purpose", b"prefetch"),
  (b"server", b""),
  (b"timing-allow-origin", b"*"),
  (b"upgrade-insecure-requests", b"1"),
  (b"user-agent", b""),
  (b"x-forwarded-for", b""),
  (b"x-frame-options", b"deny"),
  (b"x-frame-options", b"sameorigin"),
];

/// The static table entry that a decoded field came from: its name, and its value too for an
/// Indexed Field Line. A field with a literal name, or a name of the dynamic table, has none.
///
/// It lets a caller classify known fields (`:method`, `:path`, ...) by a byte comparison instead
/// of a name comparison.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StaticRef {
  /// The index of the entry in [`STATIC_TABLE`], below 99.
  pub index: u8,
  /// If the value is the entry's too.
  pub with_value: bool,
}

impl StaticRef {
  /// The reference as one byte, `NONE_CODE` for none.
  pub(crate) const NONE_CODE: u8 = u8::MAX;

  pub(crate) const fn code(this: Option<Self>) -> u8 {
    match this {
      Some(elem) => elem.index | if elem.with_value { 0x80 } else { 0 },
      None => Self::NONE_CODE,
    }
  }

  pub(crate) const fn from_code(code: u8) -> Option<Self> {
    if code == Self::NONE_CODE {
      return None;
    }
    Some(Self { index: code & 0x7f, with_value: code & 0x80 != 0 })
  }
}

const SLOTS: usize = 256;
const NO_ENTRY: u8 = u8::MAX;

/// A hash of a field name, for the lookup table and the encoder's dynamic table.
#[inline]
pub(crate) const fn name_hash(name: &[u8]) -> u32 {
  hash_bytes(0x9e37_79b9_7f4a_7c15, name)
}

/// A multiplicative hash of `bytes` read eight at a time, from `seed`.
#[inline]
pub(crate) const fn hash_bytes(seed: u64, bytes: &[u8]) -> u32 {
  const K: u64 = 0x0000_0100_0000_01b3;
  let mut hash = seed ^ (bytes.len() as u64);
  let mut idx = 0;
  while idx + 8 <= bytes.len() {
    let word = u64::from_le_bytes([
      bytes[idx],
      bytes[idx + 1],
      bytes[idx + 2],
      bytes[idx + 3],
      bytes[idx + 4],
      bytes[idx + 5],
      bytes[idx + 6],
      bytes[idx + 7],
    ]);
    hash = (hash ^ word).wrapping_mul(K).rotate_left(29);
    idx += 8;
  }
  let mut tail = 0u64;
  let mut shift = 0;
  while idx < bytes.len() {
    tail |= (bytes[idx] as u64) << shift;
    shift += 8;
    idx += 1;
  }
  hash = (hash ^ tail).wrapping_mul(K);
  hash ^= hash >> 32;
  hash = hash.wrapping_mul(0x9e37_79b9_7f4a_7c15);
  (hash >> 32) as u32
}

const fn same_bytes(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  let mut idx = 0;
  while idx < a.len() {
    if a[idx] != b[idx] {
      return false;
    }
    idx += 1;
  }
  true
}

/// Open addressing by name hash: the slot holds the lowest index of a name.
const fn build_slots() -> [u8; SLOTS] {
  let mut slots = [NO_ENTRY; SLOTS];
  let mut idx = 0;
  while idx < STATIC_TABLE.len() {
    let name = STATIC_TABLE[idx].0;
    let mut first = 0;
    while !same_bytes(STATIC_TABLE[first].0, name) {
      first += 1;
    }
    if first == idx {
      let mut slot = name_hash(name) as usize % SLOTS;
      while slots[slot] != NO_ENTRY {
        slot = (slot + 1) % SLOTS;
      }
      slots[slot] = idx as u8;
    }
    idx += 1;
  }
  slots
}

/// For each entry, the next entry with the same name.
const fn build_next_same_name() -> [u8; 99] {
  let mut next = [NO_ENTRY; 99];
  let mut idx = 0;
  while idx < STATIC_TABLE.len() {
    let mut other = idx + 1;
    while other < STATIC_TABLE.len() {
      if same_bytes(STATIC_TABLE[other].0, STATIC_TABLE[idx].0) {
        next[idx] = other as u8;
        break;
      }
      other += 1;
    }
    idx += 1;
  }
  next
}

static SLOTS_BY_NAME: [u8; SLOTS] = build_slots();
static NEXT_SAME_NAME: [u8; 99] = build_next_same_name();

/// The lowest index of an entry with `name`, if there is one.
#[inline]
pub fn find_name(name: &[u8]) -> Option<u8> {
  find_name_hashed(name, name_hash(name))
}

#[inline]
pub(crate) fn find_name_hashed(name: &[u8], hash: u32) -> Option<u8> {
  let mut slot = hash as usize % SLOTS;
  loop {
    let idx = SLOTS_BY_NAME[slot];
    if idx == NO_ENTRY {
      return None;
    }
    if STATIC_TABLE[usize::from(idx)].0 == name {
      return Some(idx);
    }
    slot = (slot + 1) % SLOTS;
  }
}

/// The index of the entry with `name` and `value`, if there is one.
#[inline]
pub fn find_exact(name: &[u8], value: &[u8]) -> Option<u8> {
  find_exact_from(find_name(name)?, value)
}

/// The index of the entry with the name of entry `first` and `value`, at or after `first`.
#[inline]
pub(crate) fn find_exact_from(first: u8, value: &[u8]) -> Option<u8> {
  let mut idx = first;
  while idx != NO_ENTRY {
    if STATIC_TABLE[usize::from(idx)].1 == value {
      return Some(idx);
    }
    idx = NEXT_SAME_NAME[usize::from(idx)];
  }
  None
}

#[cfg(test)]
mod tests {
  use super::{STATIC_TABLE, StaticRef, find_exact, find_name};

  #[test]
  fn static_table_has_99_entries_and_known_indices() {
    assert_eq!(STATIC_TABLE.len(), 99);
    // The entries that responses use (spec 5.9)
    assert_eq!(find_exact(b":status", b"200"), Some(25));
    assert_eq!(find_exact(b"content-type", b"text/plain;charset=utf-8"), Some(54));
    assert_eq!(find_exact(b"content-encoding", b"br"), Some(42));
    assert_eq!(find_exact(b"content-encoding", b"gzip"), Some(43));
    assert_eq!(find_exact(b"vary", b"accept-encoding"), Some(59));
    // The two ends and the entries that RFC 9204 prints over several lines
    assert_eq!(STATIC_TABLE.first(), Some(&(&b":authority"[..], &b""[..])));
    assert_eq!(STATIC_TABLE.last(), Some(&(&b"x-frame-options"[..], &b"sameorigin"[..])));
    assert_eq!(find_exact(b"content-type", b"text/html; charset=utf-8"), Some(52));
    assert_eq!(find_exact(b"content-type", b"application/x-www-form-urlencoded"), Some(47));
    assert_eq!(find_exact(b"cache-control", b"public, max-age=31536000"), Some(41));
    assert_eq!(
      find_exact(b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
      Some(58)
    );
    assert_eq!(
      find_exact(
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'"
      ),
      Some(85)
    );
    // The first entry of a name, and names or values that are not there
    assert_eq!(find_name(b":status"), Some(24));
    assert_eq!(find_name(b"content-type"), Some(44));
    assert_eq!(find_name(b"server"), Some(92));
    assert_eq!(find_name(b":authority"), Some(0));
    assert_eq!(find_name(b"x-unknown"), None);
    assert_eq!(find_exact(b":status", b"201"), None);
    assert_eq!(find_exact(b"server", b"rimu"), None);
    // Every index finds itself
    for (idx, (name, value)) in STATIC_TABLE.iter().enumerate() {
      let idx = u8::try_from(idx).unwrap();
      assert_eq!(find_exact(name, value), Some(idx));
      assert!(find_name(name).unwrap() <= idx);
      assert!(name.iter().all(|el| !el.is_ascii_uppercase()), "{idx}");
      // The exact lookup agrees with a linear scan
      let first = STATIC_TABLE.iter().position(|el| el.0 == *name).unwrap();
      assert_eq!(usize::from(find_name(name).unwrap()), first);
    }
    for code in 0..=u8::MAX {
      let sref = StaticRef::from_code(code);
      if code != u8::MAX {
        assert_eq!(StaticRef::code(sref), code);
      }
    }
    assert_eq!(StaticRef::code(None), u8::MAX);
  }
}
