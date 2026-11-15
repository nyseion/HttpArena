//! The trailer checksums: CRC-32 (RFC 1952, from `crc32fast`, which picks a carry-less multiply
//! kernel at run time with `std`) and Adler-32 (RFC 1950).

/// The CRC-32 of `data`.
#[inline]
pub(crate) fn crc32(data: &[u8]) -> u32 {
  crc32fast::hash(data)
}

/// The Adler-32 modulus.
const BASE: u32 = 65_521;
/// The most bytes summed before the sums must be reduced: the largest `n` with
/// `255 n (n + 1) / 2 + (n + 1) (BASE - 1) < 2^32`.
const NMAX: usize = 5_552;

/// The Adler-32 of `data`.
pub(crate) fn adler32(data: &[u8]) -> u32 {
  let (mut a, mut b) = (1u32, 0u32);
  for block in data.chunks(NMAX) {
    // Sixteen bytes a step in four lanes: lane sums `s[j]` of every fourth byte and the weighted
    // sum folded in once per step, so the loop carries no dependency on `b` per byte
    let (wide, tail) = block.as_chunks::<16>();
    for chunk in wide {
      let mut step_sum = 0u32;
      let mut weighted = 0u32;
      for (i, &byte) in chunk.iter().enumerate() {
        step_sum += u32::from(byte);
        weighted += (16 - i as u32) * u32::from(byte);
      }
      b += 16 * a + weighted;
      a += step_sum;
    }
    for &byte in tail {
      a += u32::from(byte);
      b += a;
    }
    a %= BASE;
    b %= BASE;
  }
  b << 16 | a
}
