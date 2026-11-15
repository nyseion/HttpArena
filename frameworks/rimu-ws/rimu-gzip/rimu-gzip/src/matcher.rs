//! The hash-chain match finder and the greedy and lazy parsers over it.
//!
//! Positions index the whole input (one segment of it, see `SEGMENT` in the crate root), so a
//! match reaches back across block boundaries up to [`MAX_DIST`] bytes: the 32 KiB sliding window.

use crate::tokens::{MAX_DIST, MAX_MATCH, MIN_MATCH, Tokens};
use alloc::vec::Vec;

/// Greedy parsing: every match found is taken.
pub(crate) const GREEDY: u8 = 0;
/// One step of lazy evaluation: a match is deferred once when the next position starts a longer
/// one, and the longer one is then taken.
pub(crate) const LAZY1: u8 = 1;
/// Lazy evaluation: a match is deferred as long as the next position starts a better one.
pub(crate) const LAZY: u8 = 2;
/// Lazy evaluation looking two positions ahead.
pub(crate) const LAZY2: u8 = 3;

/// The search parameters, prepared for the hot loop.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Search {
  /// Hash chain links tried per position.
  pub(crate) depth: u32,
  /// A match this long ends the search and the lazy step.
  pub(crate) nice: usize,
  /// Past this length the lazy step searches a quarter as deep.
  pub(crate) good: usize,
  /// Longer matches enter only their first positions into the hash chains.
  pub(crate) max_insert: usize,
  /// The shortest match taken (at least [`MIN_MATCH`]).
  pub(crate) min_len: usize,
  /// Skip acceleration: after 64 / this many consecutive misses, every this many misses one more
  /// position is searched without inserting the ones between; 0 for never. See
  /// [`crate::Params::skip_accel`].
  pub(crate) skip_accel: u32,
}

/// Hash chains over the input: `head` holds, per hash of 4 bytes, the last position, `prev` (a
/// ring of up to 32,768 entries, indexed by position) the position before it with the same hash.
/// Positions are stored relative to a base, in 16 bits (see [`Rel`]), so the tables of a large
/// input take 128 KiB. Both are reused; per input only the head entries its hash width uses are
/// cleared, and a `prev` entry is written when its position is inserted, before any chain can
/// lead to it.
#[derive(Debug)]
pub(crate) struct Chains {
  /// Per hash of 4 bytes, the last position.
  head: Vec<u16>,
  /// Per hash of 3 bytes, the last position: length-3 matches for the lazy strategies.
  head3: Vec<u16>,
  /// Per position (a ring), the previous position with the same hash.
  prev: Vec<u16>,
  /// Bits of the hash for the current input.
  bits: u32,
  /// `prev`'s ring size in use, minus one.
  mask: usize,
  /// The base of the stored positions.
  rel: Rel,
}

impl Chains {
  /// Empty chains. Allocates nothing.
  pub(crate) const fn new() -> Self {
    Self {
      head: Vec::new(),
      head3: Vec::new(),
      prev: Vec::new(),
      bits: 8,
      mask: 0,
      rel: Rel::new(),
    }
  }

  /// Prepares the chains for an input of `n` bytes with at most `2^max_bits` hash heads, and the
  /// 3-byte table too when `len3`.
  pub(crate) fn reset(&mut self, n: usize, max_bits: u32, len3: bool) {
    let bits = (usize::BITS - n.max(1).leading_zeros()).clamp(8, max_bits.max(8));
    let size = 1 << bits;
    if self.head.len() < size {
      self.head.resize(size, 0);
    }
    self.head[..size].fill(0);
    if len3 {
      if self.head3.len() < size {
        self.head3.resize(size, 0);
      }
      self.head3[..size].fill(0);
    }
    let ring = n.next_power_of_two().clamp(256, MAX_DIST + 1);
    if self.prev.len() < ring {
      self.prev.resize(ring, 0);
    }
    self.bits = bits;
    self.mask = ring - 1;
    self.rel = Rel::new();
  }

  /// Parses `data[pos..]` into `tokens` with strategy `S` until `pos` reaches `stop`, and returns
  /// the position reached. `BIG` must be set for inputs
  /// of more than 32,768 bytes, the only ones whose tables may need rebasing; `L3` for the lazy
  /// strategies, which also take length-3 matches (as libdeflate's do). Every position before `pos`
  /// must have been parsed by earlier calls since the last [`Self::reset`] for `data`.
  #[inline(never)]
  pub(crate) fn parse<const S: u8, const BIG: bool, const L3: bool>(
    &mut self,
    data: &[u8],
    mut pos: usize,
    stop: usize,
    search: &Search,
    tokens: &mut Tokens,
  ) -> usize {
    let n = data.len();
    debug_assert!(BIG || n <= HALF);
    debug_assert!(!L3 || S >= LAZY);
    let len3 = L3;
    let mut t = Tables::<BIG, L3> {
      head: &mut self.head[..1 << self.bits],
      head3: if len3 { &mut self.head3[..1 << self.bits] } else { &mut [] },
      prev: &mut self.prev[..=self.mask],
      mask: self.mask,
      shift: 32 - self.bits,
      rel: self.rel,
    };
    let Search { depth, nice, good, max_insert, min_len, skip_accel } = *search;
    let mut misses = 0u32;
    let depth = depth.max(1);
    let nice = nice.clamp(MIN_MATCH, MAX_MATCH);
    let max_insert = max_insert.max(1);
    let min_len = min_len.max(if len3 { 3 } else { MIN_MATCH });
    let last_hashed = (n + 1).saturating_sub(MIN_MATCH);
    while pos < stop {
      if pos >= last_hashed {
        tokens.literal(data[pos]);
        pos += 1;
        continue;
      }
      let (len, dist) = t.search(data, pos, depth, nice, min_len - 1);
      if dist == 0 {
        tokens.literal(data[pos]);
        pos += 1;
        // Skip acceleration: the longer the run of misses, the more positions in a row are
        // taken as literals without a search, as lz4 does. The skipped positions are still
        // inserted, so the table stays complete and a repeated stretch following the noise is
        // found again once the run ends.
        misses = misses.saturating_add(1);
        if skip_accel > 0 && pos >= HALF {
          let step = (((misses as u64 * skip_accel as u64) >> 6) as usize).min(MAX_SKIP);
          if step > 0 {
            let end = (pos + step).min(stop).min(last_hashed);
            if end > pos {
              t.insert_run(data, pos, end);
              for &b in &data[pos..end] {
                tokens.literal(b);
              }
              pos = end;
            }
          }
        }
        continue;
      }
      misses = 0;
      match S {
        GREEDY => {
          tokens.matched(len, dist);
          t.insert_match(data, pos + 1, pos + len, len, max_insert, last_hashed);
          pos += len;
        }
        LAZY1 => {
          if len < nice && pos + 1 < last_hashed {
            let next_depth = if len >= good { (depth / 4).max(1) } else { depth };
            let (len2, dist2) = t.search(data, pos + 1, next_depth, nice, len);
            if dist2 != 0 {
              tokens.literal(data[pos]);
              tokens.matched(len2, dist2);
              t.insert_match(data, pos + 2, pos + 1 + len2, len2, max_insert, last_hashed);
              pos += 1 + len2;
              continue;
            }
            tokens.matched(len, dist);
            t.insert_match(data, pos + 2, pos + len, len, max_insert, last_hashed);
            pos += len;
            continue;
          }
          tokens.matched(len, dist);
          t.insert_match(data, pos + 1, pos + len, len, max_insert, last_hashed);
          pos += len;
        }
        _ => {
          let (mut len, mut dist) = (len, dist);
          // Positions below `inserted` are in the chains
          let mut inserted = pos + 1;
          loop {
            if len >= nice || pos + 1 >= last_hashed {
              break;
            }
            let next_depth = if len >= good { depth / 4 } else { depth / 2 }.max(1);
            let (len1, dist1) = t.search(data, pos + 1, next_depth, nice, len - 1);
            inserted = pos + 2;
            if dist1 != 0 && better(len, dist, len1, dist1, 2) {
              tokens.literal(data[pos]);
              pos += 1;
              (len, dist) = (len1, dist1);
              continue;
            }
            if S == LAZY2 && pos + 2 < last_hashed {
              let (len2, dist2) = t.search(data, pos + 2, (depth / 4).max(1), nice, len - 1);
              inserted = pos + 3;
              if dist2 != 0 && better(len, dist, len2, dist2, 6) {
                tokens.literal(data[pos]);
                tokens.literal(data[pos + 1]);
                pos += 2;
                (len, dist) = (len2, dist2);
                continue;
              }
            }
            break;
          }
          tokens.matched(len, dist);
          t.insert_match(data, inserted, pos + len, len, max_insert, last_hashed);
          pos += len;
        }
      }
    }
    self.rel = t.rel;
    pos
  }
}

/// The longest distance of a length-3 match (as libdeflate's lazy parsers): a longer one costs
/// about as many bits as its three literals.
const LEN3_MAX_DIST: usize = 8_192;

/// Half the range of a 16-bit relative position.
pub(crate) const HALF: usize = 32_768;

/// The most consecutive positions the skip acceleration ever leaves unsearched. Unbounded steps
/// (as sirocco and lz4 allow) leap past the start of a repeated stretch after a long run of
/// noise, missing its matches wholesale; this bounds that damage while keeping nearly all of
/// the speed on incompressible data.
pub(crate) const MAX_SKIP: usize = 256;

/// Positions in 16 bits, as libdeflate stores them: a position `pos` is stored as
/// `pos + 32,768 - base`, where `base` is a multiple of 32,768 and `pos - base < 32,768` for the
/// positions being inserted, so stored values are below 65,536; 0 means none. When an insertion
/// reaches `base + 32,768`, every table entry drops by 32,768 (saturating at 0) and `base` grows
/// by as much: entries of the last 32 KiB stay exact, older ones (beyond the window) become 0.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rel {
  /// The multiple of 32,768 positions are stored relative to.
  base: usize,
}

impl Rel {
  /// The relative positions of a new input.
  pub(crate) const fn new() -> Self {
    Self { base: 0 }
  }

  /// Whether the tables must be rebased before `pos` is inserted.
  #[inline(always)]
  pub(crate) fn needs_rebase(self, pos: usize) -> bool {
    pos - self.base >= HALF
  }

  /// Rebases `tables` for an insertion at `pos`.
  #[cold]
  #[inline(never)]
  pub(crate) fn rebase<const N: usize>(&mut self, pos: usize, mut tables: [&mut [u16]; N]) {
    while self.needs_rebase(pos) {
      for table in &mut tables {
        // A plain loop over one slice, which the compiler turns into saturating vector subtracts
        for entry in table.iter_mut() {
          *entry = entry.saturating_sub(HALF as u16);
        }
      }
      self.base += HALF;
    }
  }

  /// The first position past the range the current base can store.
  #[inline(always)]
  pub(crate) fn limit(self) -> usize {
    self.base + HALF
  }

  /// The stored form of `pos`, which must lie in `base..base + 32,768`.
  #[inline(always)]
  pub(crate) fn store(self, pos: usize) -> u16 {
    debug_assert!(pos >= self.base && pos - self.base < HALF);
    (pos + HALF - self.base) as u16
  }

  /// The position stored as `entry` (not 0).
  #[inline(always)]
  pub(crate) fn load(self, entry: u16) -> usize {
    debug_assert!(entry != 0 && usize::from(entry) + self.base >= HALF);
    usize::from(entry) + self.base - HALF
  }
}

/// Whether a match of `len2` bytes `dist2` back, found later, is worth more than the current one
/// by `margin`: four points a byte of length, one a bit of distance (libdeflate's measure).
#[inline(always)]
fn better(len: usize, dist: usize, len2: usize, dist2: usize, margin: i32) -> bool {
  len2 >= len && 4 * (len2 - len) as i32 + dist.ilog2() as i32 - dist2.ilog2() as i32 > margin
}

/// The input's views of the hash tables, for the hot loop.
struct Tables<'tables, const BIG: bool, const L3: bool> {
  /// The 4-byte hash heads in use.
  head: &'tables mut [u16],
  /// As long as `head` with `L3`, else empty.
  head3: &'tables mut [u16],
  /// The chain links, a ring indexed by position.
  prev: &'tables mut [u16],
  /// `prev.len() - 1`.
  mask: usize,
  /// `32 - bits`: the hash shift.
  shift: u32,
  /// The base of the stored positions.
  rel: Rel,
}

impl<const BIG: bool, const L3: bool> Tables<'_, BIG, L3> {
  /// [`Rel::store`]; the base of a small input is always 0.
  #[inline(always)]
  fn store(&self, pos: usize) -> u16 {
    if BIG { self.rel.store(pos) } else { (pos + HALF) as u16 }
  }

  /// [`Rel::load`]; the base of a small input is always 0.
  #[inline(always)]
  fn load(&self, entry: u16) -> usize {
    if BIG { self.rel.load(entry) } else { usize::from(entry) - HALF }
  }

  /// Enters `pos` (with `pos + 4 <= data.len()`, above every position inserted before) into its
  /// hash chain (and the 3-byte table) and returns the chain's previous head and the 3-byte
  /// table's previous entry (stored, 0: none).
  #[inline(always)]
  fn insert(&mut self, data: &[u8], pos: usize) -> (u16, u16) {
    assert!(pos + MIN_MATCH <= data.len());
    if BIG && self.rel.needs_rebase(pos) {
      self.rel.rebase(pos, [&mut *self.head, &mut *self.prev, &mut *self.head3]);
    }
    // SAFETY: just asserted.
    let word = unsafe { load32(data, pos) };
    let h = (word.wrapping_mul(0x9e37_79b1) >> self.shift) as usize;
    debug_assert!(h < self.head.len() && self.mask < self.prev.len());
    let stored = self.store(pos);
    // SAFETY: `h < 2^bits = head.len()` (a 32-bit value shifted right by `32 - bits`), and
    // `pos & mask <= mask < prev.len()` (the tables were sliced so).
    let first = unsafe {
      let slot = self.head.get_unchecked_mut(h);
      let first = *slot;
      *slot = stored;
      *self.prev.get_unchecked_mut(pos & self.mask) = first;
      first
    };
    let mut first3 = 0;
    if L3 {
      let h3 = ((word & 0x00ff_ffff).wrapping_mul(0x9e37_79b1) >> self.shift) as usize;
      // `head3` has as many entries as `head`; the index check is kept (one per insertion)
      first3 = core::mem::replace(&mut self.head3[h3], stored);
    }
    (first, first3)
  }

  /// Inserts the positions `from..to` a match covered (those below `last_hashed`), only the first
  /// `max_insert` of them when the match is longer than that.
  #[inline(always)]
  fn insert_match(
    &mut self,
    data: &[u8],
    from: usize,
    to: usize,
    len: usize,
    max_insert: usize,
    last_hashed: usize,
  ) {
    let end = if len > max_insert { to.min(from + max_insert) } else { to };
    let end = end.min(last_hashed);
    if end <= from + 4 {
      // A few: inline, as the call would cost more than it saves
      for pos in from..end {
        let _ = self.insert(data, pos);
      }
    } else {
      self.insert_run(data, from, end);
    }
  }

  /// Inserts the positions `from..to` (`to + 3 <= data.len()`): a tight loop of its own, out of
  /// line so that the parser's registers do not crowd it, with one rebase check per 32 KiB.
  #[inline(never)]
  fn insert_run(&mut self, data: &[u8], from: usize, to: usize) {
    assert!(to + MIN_MATCH - 1 <= data.len() && self.mask < self.prev.len());
    assert!(!L3 || self.head3.len() == self.head.len());
    let (shift, mask) = (self.shift, self.mask);
    let mut pos = from;
    while pos < to {
      if BIG && self.rel.needs_rebase(pos) {
        self.rel.rebase(pos, [&mut *self.head, &mut *self.prev, &mut *self.head3]);
      }
      let limit = if BIG { to.min(self.rel.limit()) } else { to };
      // Up to `limit`, the stored form of `p` is `p + offset` (16-bit wrapping)
      let offset = self.store(pos).wrapping_sub(pos as u16);
      for p in pos..limit {
        // SAFETY: `p < to`, so `p + 4 <= data.len()`, as asserted.
        let word = unsafe { load32(data, p) };
        let h = (word.wrapping_mul(0x9e37_79b1) >> shift) as usize;
        let stored = (p as u16).wrapping_add(offset);
        // SAFETY: `h < 2^bits = head.len()` (a 32-bit value shifted right by `32 - bits`), and
        // `p & mask <= mask < prev.len()`, as asserted.
        unsafe {
          let first = core::mem::replace(self.head.get_unchecked_mut(h), stored);
          *self.prev.get_unchecked_mut(p & mask) = first;
        }
        if L3 {
          let h3 = ((word & 0x00ff_ffff).wrapping_mul(0x9e37_79b1) >> shift) as usize;
          // SAFETY: `h3 < 2^bits`, and `head3` is as long as `head`, as asserted.
          unsafe { *self.head3.get_unchecked_mut(h3) = stored };
        }
      }
      pos = limit;
    }
  }

  /// [`Self::search_and_insert`], out of line for the deep searches of the lazy strategies: its
  /// chain walk then gets registers of its own instead of sharing the parser's. Shallow searches
  /// (the tuned default) are faster inline.
  #[inline(always)]
  fn search(
    &mut self,
    data: &[u8],
    pos: usize,
    depth: u32,
    nice: usize,
    best: usize,
  ) -> (usize, usize) {
    if L3 {
      self.search_outlined(data, pos, depth, nice, best)
    } else {
      self.search_and_insert(data, pos, depth, nice, best)
    }
  }

  /// See [`Self::search`].
  #[inline(never)]
  fn search_outlined(
    &mut self,
    data: &[u8],
    pos: usize,
    depth: u32,
    nice: usize,
    best: usize,
  ) -> (usize, usize) {
    self.search_and_insert(data, pos, depth, nice, best)
  }

  /// Inserts `pos` (below `last_hashed`) and returns the longest match for it longer than `best`
  /// (at least 2; length 3 only from the 3-byte table, within [`LEN3_MAX_DIST`]) among at most
  /// `depth` earlier positions of its chain within the window: (length, distance), distance 0
  /// when none.
  #[inline(always)]
  fn search_and_insert(
    &mut self,
    data: &[u8],
    pos: usize,
    depth: u32,
    nice: usize,
    best: usize,
  ) -> (usize, usize) {
    let (mut cand, cand3) = self.insert(data, pos);
    // The next search (the parser's next position on a miss, or the lazy step's) is for
    // `pos + 1`: warm that chain head's line while this one is inserted and walked, as
    // sirocco's `next_heads` do.
    if pos + 1 + MIN_MATCH <= data.len() {
      // SAFETY: `pos + 1 + 4 <= data.len()`, as checked.
      let next = unsafe { load32(data, pos + 1) };
      let h = (next.wrapping_mul(0x9e37_79b1) >> self.shift) as usize;
      // SAFETY: `h < 2^bits = head.len()`, as asserted in `insert`.
      prefetch(unsafe { self.head.as_ptr().add(h) }.cast());
    }
    let max = (data.len() - pos).min(MAX_MATCH);
    let (mut best, mut best_dist) = (best, 0);
    debug_assert!(best >= 2);
    if best >= max {
      return (best, 0);
    }
    // SAFETY: `insert` checked `pos + 4 <= data.len()`.
    let first = unsafe { load32(data, pos) };
    if best < 3 && cand3 != 0 {
      let c = self.load(cand3);
      // SAFETY: `c < pos`, so its word ends before `pos + 4 <= data.len()`.
      if pos - c <= LEN3_MAX_DIST && (unsafe { load32(data, c) } ^ first) & 0x00ff_ffff == 0 {
        (best, best_dist) = (3, pos - c);
      }
    }
    // The chains only find matches of 4 bytes and more: compare from there
    // The length a candidate must reach (the chains only find matches of 4 bytes and more)
    let mut floor = best.max(3);
    if floor >= max {
      return (best, best_dist);
    }
    let mut left = depth;
    while cand != 0 && left > 0 {
      let c = self.load(cand);
      let dist = pos - c;
      if dist > MAX_DIST {
        break;
      }
      // SAFETY: `c < pos` and `3 <= floor < max <= data.len() - pos`, so the words at `c`,
      // `pos`, `c + floor - 3` and `pos + floor - 3` all end at or before
      // `pos + floor + 1 <= data.len()`.
      let candidate = unsafe {
        load32(data, c + floor - 3) == load32(data, pos + floor - 3) && load32(data, c) == first
      };
      if candidate {
        // SAFETY: `c < pos` and `pos + max <= data.len()`.
        let len = unsafe { match_len_unchecked(data, c, pos, 4, max) };
        if len > best {
          (best, best_dist, floor) = (len, dist, len);
          if len >= nice || len >= max {
            break;
          }
        }
      }
      // SAFETY: `c & mask <= mask < prev.len()`.
      cand = unsafe { *self.prev.get_unchecked(c & self.mask) };
      left -= 1;
    }
    (best, best_dist)
  }
}

/// The little-endian word at `data[i..i + 4]`.
///
/// # Safety
/// `i + 4 <= data.len()`.
#[inline(always)]
pub(crate) unsafe fn load32(data: &[u8], i: usize) -> u32 {
  debug_assert!(i + 4 <= data.len());
  // SAFETY: the caller guarantees the 4 bytes are in `data`; no alignment is needed.
  u32::from_le(unsafe { data.as_ptr().add(i).cast::<u32>().read_unaligned() })
}

/// Warms the cache line at `addr` for a load soon to come. A pure performance hint: it never
/// faults and reads nothing. sirocco's idea (its `next_heads`): the next position's table entry
/// is fetched while the current position is still being searched, rather than after.
#[inline(always)]
pub(crate) fn prefetch(addr: *const u8) {
  #[cfg(target_arch = "x86_64")]
  {
    // SAFETY: a hint: never faults, and reads nothing.
    unsafe { core::arch::x86_64::_mm_prefetch(addr.cast(), core::arch::x86_64::_MM_HINT_T0) };
  }
  #[cfg(target_arch = "aarch64")]
  {
    // SAFETY: a hint: never faults, and reads nothing.
    unsafe { core::arch::asm!("prfm pldl1keep, [{0}]", in(reg) addr) };
  }
  #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
  {
    let _ = addr;
  }
}

/// The little-endian word at `data[i..i + 8]`.
///
/// # Safety
/// `i + 8 <= data.len()`.
#[inline(always)]
unsafe fn load64(data: &[u8], i: usize) -> u64 {
  debug_assert!(i + 8 <= data.len());
  // SAFETY: the caller guarantees the 8 bytes are in `data`; no alignment is needed.
  u64::from_le(unsafe { data.as_ptr().add(i).cast::<u64>().read_unaligned() })
}

/// How many bytes at `a` and `b` (`a < b`) agree, up to `max`, given that the first `known`
/// (at most `max`) do; eight at a time.
///
/// # Safety
/// `a < b` and `b + max <= data.len()`.
#[inline(always)]
pub(crate) unsafe fn match_len_unchecked(
  data: &[u8],
  a: usize,
  b: usize,
  known: usize,
  max: usize,
) -> usize {
  debug_assert!(a < b && b + max <= data.len() && known <= max);
  let mut len = known;
  while len + 8 <= max {
    // SAFETY: `a + len + 8 < b + len + 8 <= b + max <= data.len()`.
    let diff = unsafe { load64(data, a + len) ^ load64(data, b + len) };
    if diff != 0 {
      return len + (diff.trailing_zeros() / 8) as usize;
    }
    len += 8;
  }
  // SAFETY: as above, every index is below `b + max <= data.len()`.
  while len < max && unsafe { data.get_unchecked(a + len) == data.get_unchecked(b + len) } {
    len += 1;
  }
  len
}
