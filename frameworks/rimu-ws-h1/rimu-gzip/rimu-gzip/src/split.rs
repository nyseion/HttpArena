//! Where to end a block: libdeflate's heuristic. Tokens are tallied into ten coarse observation
//! types (eight for literals by their top two bits and low bit, two for short and long matches);
//! every [`CHECK_BYTES`] bytes, once there are at least 512 of them, the distribution of the newest ones is compared with the block's so
//! far, and a block ends when the sum of absolute differences of the probabilities passes a cutoff
//! that falls as the block grows.

use crate::tokens::{LIT_SYMBOLS, Tokens};

/// Bytes parsed between two looks at the statistics.
pub(crate) const CHECK_BYTES: usize = 2_048;
/// The fewest new observations (symbols) compared with the block's, as in libdeflate: fewer
/// make the comparison noisy and end blocks for nothing.
const MIN_NEW: u32 = 512;

/// What a check of the statistics decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Check {
  /// Too few new observations: they keep accumulating.
  NotReady,
  /// The new observations differ: end the block before them.
  End,
  /// They do not: they are merged into the block's.
  Continue,
}
/// The fewest bytes a block (other than the last) covers, and the fewest left after it.
pub(crate) const MIN_BLOCK: usize = 5_000;
/// Observation types.
const TYPES: usize = 10;
/// The observation type of every literal/length symbol: literals by their top two bits and low
/// bit, matches shorter than 9 bytes (symbols 257..=262), longer matches. End of block: none.
const KIND: [u8; LIT_SYMBOLS] = {
  let mut table = [0; LIT_SYMBOLS];
  let mut sym = 0;
  while sym < LIT_SYMBOLS {
    table[sym] = match sym {
      0..=255 => (((sym >> 5) & 6) | (sym & 1)) as u8,
      256 => TYPES as u8,
      257..=262 => 8,
      _ => 9,
    };
    sym += 1;
  }
  table
};

/// The observations of the current block up to the last check, as totals per type. The tokens'
/// symbol frequencies hold every observation of the block, so the newest ones are their
/// difference: nothing is tallied per token.
#[derive(Debug)]
pub(crate) struct SplitStats {
  /// The block's observations up to the last merge, per type.
  observed: [u32; TYPES],
  /// Their total.
  observed_total: u32,
}

impl SplitStats {
  /// No observations.
  pub(crate) const fn new() -> Self {
    Self { observed: [0; TYPES], observed_total: 0 }
  }

  /// Takes every token of the block so far as observed (at a block's start or a check that did
  /// not end it).
  pub(crate) fn merge(&mut self, tokens: &Tokens) {
    (self.observed, self.observed_total) = tally(tokens);
  }

  /// Whether the observations since the last merge differ enough from the earlier ones of the
  /// block (of `block_len` bytes so far) to end the block before them. They are merged when not.
  pub(crate) fn check(&mut self, tokens: &Tokens, block_len: usize) -> Check {
    let (now, now_total) = tally(tokens);
    if now_total - self.observed_total < MIN_NEW {
      return Check::NotReady;
    }
    if self.observed_total > 0 {
      // Probabilities scaled by both totals, in 64 bits
      let old_total = u64::from(self.observed_total);
      let new_total = u64::from(now_total - self.observed_total);
      let delta: u64 = self
        .observed
        .iter()
        .zip(&now)
        .map(|(&old, &now)| (u64::from(old) * new_total).abs_diff(u64::from(now - old) * old_total))
        .sum();
      let items = old_total + new_total;
      let mut cutoff = new_total * 200 / 512 * old_total;
      // Short blocks pay heavily for their Huffman codes: end one only when clearly worth it
      if block_len < 10_000 && items < 8_192 {
        cutoff += cutoff * (8_192 - items) / 8_192;
      }
      if delta + (block_len as u64 / 4_096) * old_total >= cutoff {
        return Check::End;
      }
    }
    (self.observed, self.observed_total) = (now, now_total);
    Check::Continue
  }
}

/// The observations of every token: totals per type and overall.
fn tally(tokens: &Tokens) -> ([u32; TYPES], u32) {
  let mut sums = [0u32; TYPES + 1];
  for (&freq, &kind) in tokens.lit_freq.iter().zip(&KIND) {
    sums[usize::from(kind)] += freq;
  }
  let mut out = [0; TYPES];
  out.copy_from_slice(&sums[..TYPES]);
  (out, out.iter().sum())
}
