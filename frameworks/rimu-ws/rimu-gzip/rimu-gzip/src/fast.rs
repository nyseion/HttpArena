//! The fastest parser: greedy over a hash table of two-entry buckets (no chains), as in
//! libdeflate's level 1.

use crate::{
  matcher::{Search, load32, match_len_unchecked, prefetch},
  tokens::{MAX_DIST, MAX_MATCH, MIN_MATCH, Tokens},
};
use alloc::vec::Vec;

/// Bits of the hash table's index.
const MAX_BITS: u32 = 15;

/// The hash of a 4-byte word, in [`MAX_BITS`] bits: a constant shift, masked down for smaller
/// tables.
#[inline(always)]
fn hash(word: u32) -> usize {
  (word.wrapping_mul(0x9e37_79b1) >> (32 - MAX_BITS)) as usize
}

/// A hash table of buckets of the last two positions per hash of 4 bytes, stored plus one (0:
/// none) in 32 bits: no rebasing, and the hot loop stays short. Reused; per input only the
/// buckets its hash width uses are cleared.
#[derive(Debug)]
pub(crate) struct FastTable {
  /// Two entries per bucket, the newer first.
  slots: Vec<u32>,
  /// Bits of the bucket index for the current input.
  bits: u32,
}

impl FastTable {
  /// An empty table. Allocates nothing.
  pub(crate) const fn new() -> Self {
    Self { slots: Vec::new(), bits: 8 }
  }

  /// Prepares the table for an input of `n` bytes.
  pub(crate) fn reset(&mut self, n: usize) {
    let bits = (usize::BITS - n.max(1).leading_zeros()).clamp(8, MAX_BITS);
    let size = 2 << bits;
    if self.slots.len() < size {
      self.slots.resize(size, 0);
    }
    self.slots[..size].fill(0);
    self.bits = bits;
  }

  /// Parses `data[pos..]` into `tokens` until `pos` reaches `stop`, and returns the position
  /// reached. Of `search` only the nice length and the
  /// positions inserted per match apply.
  #[inline(never)]
  pub(crate) fn parse(
    &mut self,
    data: &[u8],
    mut pos: usize,
    stop: usize,
    search: &Search,
    tokens: &mut Tokens,
  ) -> usize {
    let n = data.len();
    let slots = &mut self.slots[..2 << self.bits];
    let mask = (1 << self.bits) - 1;
    // Every bucket index `b` below is even and at most `2 * mask`, so `b + 1 < slots.len()`
    assert!(slots.len() == 2 * (mask + 1));
    let last_hashed = (n + 1).saturating_sub(MIN_MATCH);
    let nice = search.nice.clamp(MIN_MATCH, MAX_MATCH);
    let max_insert = search.max_insert;
    let skip_accel = search.skip_accel;
    let mut misses = 0u32;
    // The word at a position below `last_hashed` (the only ones it is called on)
    let word = |pos: usize| {
      debug_assert!(pos < last_hashed);
      // SAFETY: `pos < last_hashed`, so `pos + 4 <= n`.
      unsafe { load32(data, pos) }
    };
    let bucket = |word: u32| 2 * (hash(word) & mask);
    // The table never moves while parsing (it only grows in `reset`), so a raw pointer to it is
    // sound for the loop below.
    let slots_ptr = slots.as_ptr();
    // Warms the bucket line of the position `p` (which must satisfy `p < last_hashed`): the next
    // search, or the first insert of a match taken here, soon touches it.
    let warm = |p: usize| {
      debug_assert!(p < last_hashed);
      // SAFETY: `p < last_hashed`, so `p + 4 <= n`.
      let b = bucket(unsafe { load32(data, p) });
      // SAFETY: `b + 1 < slots.len()`, as asserted above.
      prefetch(unsafe { slots_ptr.add(b) }.cast());
    };
    let mut sink = tokens.sink(stop.saturating_sub(pos) / MIN_MATCH + 1);
    let hashed_stop = stop.min(last_hashed);
    {
      let end = hashed_stop;
      while pos < end {
        // The next search is for `pos + 1` on a miss, and a match taken here inserts from
        // `pos + 1`: either way, warm that bucket's line while this one is searched.
        if pos + 1 < end {
          warm(pos + 1);
        }
        let w = word(pos);
        let b = bucket(w);
        // SAFETY: `b + 1 < slots.len()`, as asserted above.
        let (c0, c1) = unsafe { (*slots.get_unchecked(b), *slots.get_unchecked(b + 1)) };
        // SAFETY: as above.
        unsafe {
          *slots.get_unchecked_mut(b) = (pos + 1) as u32;
          *slots.get_unchecked_mut(b + 1) = c0;
        }
        let max = (n - pos).min(MAX_MATCH);
        let (mut best, mut best_dist) = (0, 0);
        if c0 != 0 && pos - (c0 as usize - 1) <= MAX_DIST {
          let c = c0 as usize - 1;
          if word(c) == w {
            // SAFETY: `c < pos` and `pos + max <= n`; the first 4 bytes agree.
            best = unsafe { match_len_unchecked(data, c, pos, 4, max) };
            best_dist = pos - c;
          }
          if c1 != 0 && best < nice && pos - (c1 as usize - 1) <= MAX_DIST {
            let c = c1 as usize - 1;
            // SAFETY: evaluated only when `4 <= best < max` (a first match is at least 4
            // bytes), so both words end at or before `pos + best + 1 <= pos + max <= n`.
            let worth = word(c) == w
              && (best == 0
                || best < max
                  && unsafe { load32(data, c + best - 3) == load32(data, pos + best - 3) });
            if worth {
              // SAFETY: as for the first candidate.
              let len = unsafe { match_len_unchecked(data, c, pos, 4, max) };
              if len > best {
                best = len;
                best_dist = pos - c;
              }
            }
          }
        }
        if best_dist == 0 {
          sink.literal(data[pos]);
          pos += 1;
          // Skip acceleration: the longer the run of misses, the more positions in a row are
          // taken as literals without a search, as lz4 does. The skipped positions are still
          // inserted, so the table stays complete and a repeated stretch following the noise is
          // found again once the run ends.
          misses = misses.saturating_add(1);
          if skip_accel > 0 && pos >= 32_768 {
            let step =
              (((misses as u64 * skip_accel as u64) >> 6) as usize).min(crate::matcher::MAX_SKIP);
            if step > 0 {
              let skip_end = (pos + step).min(end);
              for q in pos..skip_end {
                // SAFETY: `q < skip_end <= end <= last_hashed`, so `q + 4 <= n`.
                let b = bucket(unsafe { load32(data, q) });
                // SAFETY: `b + 1 < slots.len()`, as asserted above.
                unsafe {
                  let c0 = *slots.get_unchecked(b);
                  *slots.get_unchecked_mut(b) = (q + 1) as u32;
                  *slots.get_unchecked_mut(b + 1) = c0;
                }
                sink.literal(data[q]);
              }
              pos = skip_end;
            }
          }
          continue;
        }
        misses = 0;
        sink.matched(best, best_dist);
        let insert_end = (pos + best).min(pos + 1 + max_insert).min(last_hashed);
        for q in pos + 1..insert_end {
          let b = bucket(word(q));
          // SAFETY: `b + 1 < slots.len()`, as asserted above.
          unsafe {
            *slots.get_unchecked_mut(b + 1) = *slots.get_unchecked(b);
            *slots.get_unchecked_mut(b) = (q + 1) as u32;
          }
        }
        pos += best;
      }
    }
    while pos < stop {
      sink.literal(data[pos]);
      pos += 1;
    }
    sink.finish();
    pos
  }
}
