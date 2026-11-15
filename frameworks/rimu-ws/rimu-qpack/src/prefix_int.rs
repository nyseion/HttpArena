//! Prefixed integers (RFC 7541 section 5.1), which QPACK uses unmodified with more prefix sizes
//! (RFC 9204 section 4.1.1).

use alloc::vec::Vec;

/// The largest value that QPACK decodes: 62 bits (RFC 9204 section 4.1.1).
pub(crate) const PREFIX_INT_MAX: u64 = (1 << 62) - 1;

/// The integer could not be read: too large, or encoded longer than such a value needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Overflow;

/// Writes `value` at the start of `out` with a prefix of `prefix_bits` bits (1 to 8). The bits of
/// the first byte above the prefix are those of `flags`.
///
/// Returns the number of written bytes, or `None` if `out` is too small, `value` is larger than
/// [`PREFIX_INT_MAX`] or `prefix_bits` is not in `1..=8`.
#[inline]
pub(crate) fn encode_prefix_int(
  value: u64,
  prefix_bits: u8,
  flags: u8,
  out: &mut [u8],
) -> Option<usize> {
  let mask = prefix_mask(prefix_bits)?;
  if value > PREFIX_INT_MAX {
    return None;
  }
  let (first, rest) = out.split_first_mut()?;
  let flags = flags & !mask;
  if value < u64::from(mask) {
    *first = flags | value as u8;
    return Some(1);
  }
  *first = flags | mask;
  let mut remaining = value - u64::from(mask);
  let mut len = 1usize;
  for byte in rest {
    len += 1;
    let low = (remaining & 0x7f) as u8;
    remaining >>= 7;
    if remaining == 0 {
      *byte = low;
      return Some(len);
    }
    *byte = low | 0x80;
  }
  None
}

/// Appends `value` to `out` with a prefix of `prefix_bits` bits whose upper bits are `flags`.
/// `value` must be at most [`PREFIX_INT_MAX`]: lengths and indices of this crate always are.
#[inline]
pub(crate) fn push_prefix_int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
  let mut buffer = [0u8; 10];
  let len = encode_prefix_int(value.min(PREFIX_INT_MAX), prefix_bits, flags, &mut buffer)
    .unwrap_or_default();
  out.extend_from_slice(buffer.get(..len).unwrap_or_default());
}

/// Reads the integer at the start of `bytes`, whose first byte holds a prefix of `prefix_bits`
/// bits (1 to 8).
///
/// Returns the value and the number of bytes that it takes, or `None` if `bytes` ends before it
/// does.
#[inline]
pub(crate) fn decode_prefix_int(
  bytes: &[u8],
  prefix_bits: u8,
) -> Result<Option<(u64, usize)>, Overflow> {
  let mask = prefix_mask(prefix_bits).ok_or(Overflow)?;
  let Some((first, rest)) = bytes.split_first() else {
    return Ok(None);
  };
  let mut value = u64::from(first & mask);
  if value < u64::from(mask) {
    return Ok(Some((value, 1)));
  }
  let mut shift = 0u32;
  let mut len = 1usize;
  for byte in rest {
    // Nine continuation bytes hold 63 bits: a tenth is never needed
    if shift > 56 {
      return Err(Overflow);
    }
    len += 1;
    // At most 127 << 56 added to at most 2^62 - 1: no overflow
    value += u64::from(byte & 0x7f) << shift;
    if value > PREFIX_INT_MAX {
      return Err(Overflow);
    }
    if byte & 0x80 == 0 {
      return Ok(Some((value, len)));
    }
    shift += 7;
  }
  Ok(None)
}

#[inline]
const fn prefix_mask(prefix_bits: u8) -> Option<u8> {
  if prefix_bits == 0 || prefix_bits > 8 {
    return None;
  }
  Some(u8::MAX >> (8 - prefix_bits))
}

#[cfg(test)]
mod tests {
  use super::*;
  use alloc::vec;

  fn encoded(value: u64, prefix_bits: u8, flags: u8) -> Vec<u8> {
    let mut out = [0u8; 16];
    let len = encode_prefix_int(value, prefix_bits, flags, &mut out).unwrap();
    out[..len].to_vec()
  }

  #[test]
  fn prefix_int_rfc7541_c1_examples() {
    // C.1.1: 10 with a 5-bit prefix; the bits above the prefix are kept and ignored when read
    assert_eq!(encoded(10, 5, 0), [0x0a]);
    assert_eq!(encoded(10, 5, 0b1110_0000), [0xea]);
    assert_eq!(decode_prefix_int(&[0x0a, 0xff], 5).unwrap(), Some((10, 1)));
    assert_eq!(decode_prefix_int(&[0xea], 5).unwrap(), Some((10, 1)));
    // C.1.2: 1337 with a 5-bit prefix
    assert_eq!(encoded(1337, 5, 0), [0x1f, 0x9a, 0x0a]);
    assert_eq!(decode_prefix_int(&[0x1f, 0x9a, 0x0a, 0x00], 5).unwrap(), Some((1337, 3)));
    // C.1.3: 42 starting at an octet boundary
    assert_eq!(encoded(42, 8, 0), [0x2a]);
    assert_eq!(decode_prefix_int(&[0x2a], 8).unwrap(), Some((42, 1)));
    // The value that fills the prefix takes a zero continuation byte
    assert_eq!(encoded(31, 5, 0), [0x1f, 0x00]);
    assert_eq!(decode_prefix_int(&[0x1f, 0x00], 5).unwrap(), Some((31, 2)));
    // Too few bytes, written or read
    assert_eq!(encode_prefix_int(1337, 5, 0, &mut [0u8; 2]), None);
    assert_eq!(encode_prefix_int(1, 5, 0, &mut []), None);
    assert_eq!(decode_prefix_int(&[0x1f, 0x9a], 5).unwrap(), None);
    assert_eq!(decode_prefix_int(&[], 5).unwrap(), None);
    // 62 bits with every prefix, and not one more
    for prefix_bits in 1..=8 {
      let bytes = encoded(PREFIX_INT_MAX, prefix_bits, 0);
      assert_eq!(
        decode_prefix_int(&bytes, prefix_bits).unwrap(),
        Some((PREFIX_INT_MAX, bytes.len()))
      );
      assert_eq!(encode_prefix_int(PREFIX_INT_MAX + 1, prefix_bits, 0, &mut [0u8; 16]), None);
      for value in [0, 1, 126, 127, 128, 255, 256, 16_383, 16_384, 1 << 40] {
        let bytes = encoded(value, prefix_bits, 0);
        assert_eq!(decode_prefix_int(&bytes, prefix_bits).unwrap(), Some((value, bytes.len())));
        let mut pushed = Vec::new();
        push_prefix_int(&mut pushed, value, prefix_bits, 0);
        assert_eq!(pushed, bytes);
      }
    }
    // 2^62 itself, and an encoding longer than any 62-bit value needs
    let mut too_large = vec![0x1f];
    too_large.extend_from_slice(&[0xe1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]);
    assert_eq!(decode_prefix_int(&too_large, 5), Err(Overflow));
    let mut too_long = vec![0x1f];
    too_long.extend_from_slice(&[0x80; 9]);
    too_long.push(0x00);
    assert_eq!(decode_prefix_int(&too_long, 5), Err(Overflow));
    // Prefixes that do not exist
    assert_eq!(encode_prefix_int(1, 0, 0, &mut [0u8; 4]), None);
    assert_eq!(encode_prefix_int(1, 9, 0, &mut [0u8; 4]), None);
    assert!(decode_prefix_int(&[1], 0).is_err());
    assert!(decode_prefix_int(&[1], 9).is_err());
  }
}
