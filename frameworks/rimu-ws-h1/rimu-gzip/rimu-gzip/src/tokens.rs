//! Literal and match tokens, DEFLATE's length and distance tables, and the symbol statistics of
//! the tokens of one block.

use alloc::vec::Vec;

/// The bytes hashed to find a match, and so the shortest match the matchers find: 3-byte matches
/// rarely pay for their codes.
pub(crate) const MIN_MATCH: usize = 4;
/// DEFLATE's longest match.
pub(crate) const MAX_MATCH: usize = 258;
/// The longest distance the matchers use: one short of DEFLATE's 32,768, so that a hash chain
/// stored in a 32,768-entry ring is never followed into an entry a newer position overwrote.
pub(crate) const MAX_DIST: usize = 32_767;
/// Literal/length symbols in use (0..=285).
pub(crate) const LIT_SYMBOLS: usize = 286;
/// Distance symbols in use (0..=29).
pub(crate) const DIST_SYMBOLS: usize = 30;

/// The first length of every length symbol (minus 257). Padded to 32 entries — the width of a
/// packed sequence's symbol field — with symbol 28's base, so [`seq_len`] can index it without
/// a clamp: the packer never writes a symbol above 28.
pub(crate) const LEN_BASE: [u16; 32] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258, 258, 258, 258,
];
/// The extra bits of every length symbol (minus 257).
pub(crate) const LEN_XBITS: [u8; 29] =
  [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
/// The first distance of every distance symbol.
pub(crate) const DIST_BASE: [u16; 30] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// The extra bits of every distance symbol.
pub(crate) const DIST_XBITS: [u8; 30] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// The length symbol (minus 257) of every match length 0..=258 (0..=2 unused).
pub(crate) const LEN_SYM: [u8; MAX_MATCH + 1] = {
  let mut table = [0; MAX_MATCH + 1];
  let mut sym = 0;
  while sym < 28 {
    let mut len = LEN_BASE[sym] as usize;
    while len < LEN_BASE[sym] as usize + (1 << LEN_XBITS[sym]) && len < MAX_MATCH {
      table[len] = sym as u8;
      len += 1;
    }
    sym += 1;
  }
  table[MAX_MATCH] = 28;
  table
};

/// The distance symbol of `distance - 1` below 256, then of `(distance - 1) >> 7`: past 256 the
/// symbol ranges are 128-aligned.
const DIST_SYM_LO: [u8; 256] = dist_sym_table(false);
/// See [`DIST_SYM_LO`].
const DIST_SYM_HI: [u8; 256] = dist_sym_table(true);

/// The distance symbols of `distance - 1` by its low byte (`hi` false) or by `(distance - 1) >> 7`.
const fn dist_sym_table(hi: bool) -> [u8; 256] {
  let mut table = [0; 256];
  let mut sym = 0;
  while sym < DIST_SYMBOLS {
    let mut d = DIST_BASE[sym] as usize - 1;
    while d < DIST_BASE[sym] as usize - 1 + (1 << DIST_XBITS[sym]) {
      if !hi && d < 256 {
        table[d] = sym as u8;
      } else if hi && d >= 256 {
        table[d >> 7] = sym as u8;
      }
      d += 1;
    }
    sym += 1;
  }
  table
}

/// The distance symbol of `distance` (1..=32,768).
#[inline]
pub(crate) fn dist_sym(distance: usize) -> usize {
  let d = distance - 1;
  // The masks and the clamp cost nothing and drop the bounds checks of the tables indexed
  let sym = if d < 256 { DIST_SYM_LO[d & 0xff] } else { DIST_SYM_HI[(d >> 7) & 0xff] };
  usize::from(sym).min(DIST_SYMBOLS - 1)
}

/// The literals and matches of one block, with the symbol frequencies the block coder needs.
///
/// As in libdeflate, literals are not stored: a sequence is a run of literals (read back from
/// the input when the block is written) followed by a match, packed with the match's symbols and
/// extra bits ready for the writer (see [`pack`]); `pending` literals follow the last sequence.
#[derive(Debug)]
pub(crate) struct Tokens {
  /// The sequences.
  pub(crate) seqs: Vec<u64>,
  /// Literals after the last sequence.
  pub(crate) pending: u32,
  /// Literal/length symbol frequencies.
  pub(crate) lit_freq: [u32; LIT_SYMBOLS],
  /// Distance symbol frequencies.
  pub(crate) dist_freq: [u32; DIST_SYMBOLS],
  /// The extra bits of every length and distance, summed.
  pub(crate) extra_bits: u64,
}

impl Tokens {
  /// No tokens. Allocates nothing.
  pub(crate) const fn new() -> Self {
    Self {
      seqs: Vec::new(),
      pending: 0,
      lit_freq: [0; LIT_SYMBOLS],
      dist_freq: [0; DIST_SYMBOLS],
      extra_bits: 0,
    }
  }

  /// Empties the tokens, keeping the buffer.
  pub(crate) fn clear(&mut self) {
    self.seqs.clear();
    self.pending = 0;
    self.lit_freq = [0; LIT_SYMBOLS];
    self.dist_freq = [0; DIST_SYMBOLS];
    self.extra_bits = 0;
  }

  /// Makes room for the sequences of `len` more bytes (at most one per 4 bytes).
  pub(crate) fn reserve(&mut self, len: usize) {
    self.seqs.reserve(len / MIN_MATCH + 1);
  }

  /// Appends a literal.
  #[inline(always)]
  pub(crate) fn literal(&mut self, byte: u8) {
    self.pending += 1;
    self.lit_freq[usize::from(byte)] += 1;
  }

  /// Appends a match of `len` bytes `distance` back, closing the pending literal run.
  #[inline(always)]
  pub(crate) fn matched(&mut self, len: usize, distance: usize) {
    debug_assert!((3..=MAX_MATCH).contains(&len) && (1..=MAX_DIST).contains(&distance));
    let (ls, ds) = (len_sym(len), dist_sym(distance));
    self.seqs.push(pack(self.pending, len, ls, distance, ds));
    self.pending = 0;
    self.lit_freq[257 + ls] += 1;
    self.dist_freq[ds] += 1;
    self.extra_bits += u64::from(LEN_XBITS[ls]) + u64::from(DIST_XBITS[ds]);
  }

  /// A sink appending to these tokens with room for `room` sequences before it must grow.
  #[inline]
  pub(crate) fn sink(&mut self, room: usize) -> Sink<'_> {
    self.seqs.reserve(room);
    Sink {
      ptr: self.seqs.as_mut_ptr(),
      len: self.seqs.len(),
      cap: self.seqs.capacity(),
      pending: self.pending,
      extra_bits: 0,
      tokens: self,
    }
  }
}

/// Appends tokens for the parsers' hot loops: the buffer's pointer, length and capacity and the
/// pending run live in the sink, so that the stores of sequences and frequencies do not make the
/// compiler reload them. [`Sink::finish`] brings the tokens up to date.
pub(crate) struct Sink<'tokens> {
  /// The sequence buffer.
  ptr: *mut u64,
  /// Sequences in the buffer.
  len: usize,
  /// The buffer's capacity.
  cap: usize,
  /// Literals after the last sequence.
  pending: u32,
  /// Extra bits added since the sink was made.
  extra_bits: u64,
  /// The tokens appended to.
  tokens: &'tokens mut Tokens,
}

impl Sink<'_> {
  /// Makes room for more sequences.
  #[cold]
  #[inline(never)]
  fn grow(&mut self) {
    // SAFETY: the first `self.len` sequences are initialized: the vector's own, or written by
    // `matched`.
    unsafe { self.tokens.seqs.set_len(self.len) };
    self.tokens.seqs.reserve(1024);
    self.ptr = self.tokens.seqs.as_mut_ptr();
    self.cap = self.tokens.seqs.capacity();
  }

  /// Appends a literal.
  #[inline(always)]
  pub(crate) fn literal(&mut self, byte: u8) {
    self.pending += 1;
    self.tokens.lit_freq[usize::from(byte)] += 1;
  }

  /// Appends a match of `len` bytes `distance` back, closing the pending literal run.
  #[inline(always)]
  pub(crate) fn matched(&mut self, len: usize, distance: usize) {
    debug_assert!((3..=MAX_MATCH).contains(&len) && (1..=MAX_DIST).contains(&distance));
    if self.len == self.cap {
      self.grow();
    }
    let (ls, ds) = (len_sym(len), dist_sym(distance));
    // SAFETY: `len < cap`, so the slot is inside the vector's allocation.
    unsafe { self.ptr.add(self.len).write(pack(self.pending, len, ls, distance, ds)) };
    self.len += 1;
    self.pending = 0;
    self.tokens.lit_freq[257 + ls] += 1;
    self.tokens.dist_freq[ds] += 1;
    self.extra_bits += u64::from(LEN_XBITS[ls]) + u64::from(DIST_XBITS[ds]);
  }

  /// Hands the tokens over to the buffer.
  #[inline]
  pub(crate) fn finish(self) {
    // SAFETY: the first `self.len` sequences are initialized, and `len <= cap`.
    unsafe { self.tokens.seqs.set_len(self.len) };
    self.tokens.pending = self.pending;
    self.tokens.extra_bits += self.extra_bits;
  }
}

/// A sequence of `run` literals, then a match of `len` bytes (length symbol `ls`, minus 257)
/// `distance` back (distance symbol `ds`): `run | ls << 32 | len extra << 37 | ds << 42 |
/// distance extra << 47`.
#[inline(always)]
pub(crate) fn pack(run: u32, len: usize, ls: usize, distance: usize, ds: usize) -> u64 {
  let len_extra = (len - usize::from(LEN_BASE[ls])) as u64;
  let dist_extra = (distance - usize::from(DIST_BASE[ds])) as u64;
  u64::from(run) | (ls as u64) << 32 | len_extra << 37 | (ds as u64) << 42 | dist_extra << 47
}

/// The fields of a packed sequence.
pub(crate) struct Seq {
  /// Literals before the match.
  pub(crate) run: usize,
  /// The length symbol, minus 257 (0..=28).
  pub(crate) ls: usize,
  /// The value of the length's extra bits.
  pub(crate) len_extra: u64,
  /// The distance symbol (0..=29).
  pub(crate) ds: usize,
  /// The value of the distance's extra bits.
  pub(crate) dist_extra: u64,
}

/// The fields of a packed sequence.
#[inline(always)]
pub(crate) fn unpack(seq: u64) -> Seq {
  Seq {
    run: (seq as u32) as usize,
    ls: ((seq >> 32) & 31) as usize,
    len_extra: (seq >> 37) & 31,
    ds: ((seq >> 42) & 31) as usize,
    dist_extra: seq >> 47,
  }
}

/// The match length of a packed sequence.
#[inline(always)]
pub(crate) fn seq_len(seq: u64) -> usize {
  usize::from(LEN_BASE[((seq >> 32) & 31) as usize]) + ((seq >> 37) & 31) as usize
}

/// The length symbol (minus 257) of a match length.
#[inline(always)]
pub(crate) fn len_sym(len: usize) -> usize {
  // The clamps cost nothing and drop the bounds checks of the tables indexed
  usize::from(LEN_SYM[len.min(MAX_MATCH)]).min(28)
}
