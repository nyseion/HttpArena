//! The shortest match the lazy parsers take, as libdeflate chooses it: data with few distinct
//! literals (DNA, some logs) makes literals cheap, so short matches do not pay for themselves.

/// The shortest match by number of distinct literals in use; 3 from 80 on.
const BY_LITERALS: [u8; 80] = [
  9, 9, 9, 9, 9, 9, 8, 8, 7, 7, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
];

/// The shortest match for `literals` distinct literals at search depth `depth` (shallow searches
/// rarely find the long matches a high minimum would wait for).
fn choose(literals: usize, depth: u16) -> usize {
  let mut min_len = BY_LITERALS.get(literals).map_or(3, |&len| usize::from(len));
  if depth < 16 {
    min_len = min_len.min(match depth {
      0..5 => 4,
      5..10 => 5,
      _ => 7,
    });
  }
  min_len
}

/// The shortest match for a block starting with `bytes`, from the distinct bytes of its first
/// 4 KiB; 3 below 512 bytes, where the fixed codes are likely.
pub(crate) fn of_bytes(bytes: &[u8], depth: u16) -> usize {
  if bytes.len() < 512 {
    return 3;
  }
  let mut used = [false; 256];
  for &byte in &bytes[..bytes.len().min(4_096)] {
    used[usize::from(byte)] = true;
  }
  choose(used.iter().filter(|&&u| u).count(), depth)
}

/// The shortest match for a block whose literal/length frequencies are `freq`, ignoring literals
/// used less than once per 1,024 literals.
pub(crate) fn of_freq(freq: &[u32], depth: u16) -> usize {
  let literals = &freq[..256];
  let cutoff = literals.iter().sum::<u32>() >> 10;
  choose(literals.iter().filter(|&&f| f > cutoff).count(), depth)
}
