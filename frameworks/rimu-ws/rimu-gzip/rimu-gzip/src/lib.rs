//! A one-shot DEFLATE (RFC 1951) encoder with zlib (RFC 1950) and gzip (RFC 1952) framing: one
//! input slice in, one complete stream appended to a `Vec<u8>` out.
//!
//! General streaming compressors spend most of their time on a body of a few kilobytes clearing
//! and walking state sized for megabytes. This encoder matches the input where it lies, with
//! state sized to the input and reused, so encoding allocates nothing once its buffers have grown.
//! Matches reach back 32 KiB across block boundaries; from level 4 up, blocks end where the
//! statistics of the symbols change (libdeflate's heuristic); each block is written in whichever
//! of the stored, fixed-code and dynamic-code types costs the fewest bits.
//!
//! ```
//! use rimu_gzip::{Encoder, Level};
//!
//! let body = br#"{"items":[{"id":1,"name":"Item 1"},{"id":2,"name":"Item 2"}]}"#;
//! let mut encoder = Encoder::new(); // the default level; reuse it across bodies
//! let mut out = Vec::new();
//! encoder.gzip(body, &mut out);
//! assert!(out.len() <= rimu_gzip::gzip_bound(body.len()));
//!
//! let mut best = Encoder::with_level(Level::BEST);
//! out.clear();
//! best.zlib(body, &mut out);
//! ```
//!
//! Streaming is out of scope: the whole input must be in one slice.
#![no_std]
#![warn(missing_docs, clippy::missing_docs_in_private_items, clippy::undocumented_unsafe_blocks)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

mod bits;
mod block;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod check;
mod checksum;
mod dynamic;
mod fast;
mod huffman;
mod matcher;
mod min_len;
mod split;
#[cfg(test)]
mod tests;
mod tokens;

use alloc::vec::Vec;
use bits::BitWriter;
use block::{Block, MAX_STORED, write_block, write_fixed, write_stored};
use dynamic::Dynamic;
use fast::FastTable;
use matcher::{Chains, GREEDY, LAZY, LAZY1, LAZY2, Search};
use split::{CHECK_BYTES, Check, MIN_BLOCK, SplitStats};
use tokens::{MAX_MATCH, Tokens};

/// Inputs are matched in independent segments of this many bytes, so that positions fit in 32
/// bits; matches do not cross segment boundaries.
const SEGMENT: usize = 1 << 30;
/// A block ends at the latest once it covers this many bytes (unless fewer than [`MIN_BLOCK`]
/// would be left after it).
const MAX_BLOCK: usize = 300_000;
/// The block length of [`Strategy::Fast`], which does not split blocks by their statistics.
const FAST_BLOCK: usize = 65_535;
/// The minimal gzip header: deflate, no name or time, no flags; XFL and OS follow.
const GZIP_HEADER: [u8; 8] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0];
/// The gzip OS byte: Unix.
const GZIP_OS: u8 = 3;

/// The framing around the DEFLATE stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Format {
  /// The bare DEFLATE stream (RFC 1951).
  Raw,
  /// A zlib stream (RFC 1950): a 2-byte header, the DEFLATE stream, the Adler-32 of the input.
  Zlib,
  /// A gzip member (RFC 1952): a 10-byte header, the DEFLATE stream, the CRC-32 and length of the
  /// input.
  Gzip,
}

impl Format {
  /// The largest output [`Encoder::encode`] can append for `len` input bytes in this format.
  #[inline]
  pub const fn bound(self, len: usize) -> usize {
    let framing = match self {
      Self::Raw => 0,
      Self::Zlib => 2 + 4,
      Self::Gzip => 10 + 8,
    };
    deflate_bound(len).saturating_add(framing)
  }
}

/// The largest raw DEFLATE stream [`Encoder::deflate`] can produce for `len` input bytes: every
/// block stored.
#[inline]
pub const fn deflate_bound(len: usize) -> usize {
  // Every block but the last of each segment covers at least `MIN_BLOCK` bytes, and costs at most
  // its bytes as stored blocks: per stored block at most 3 header bits, 7 of padding and 32 of
  // LEN and NLEN (40 bits for all but the first of a block, which start byte-aligned).
  let segments = if len == 0 { 1 } else { len.div_ceil(SEGMENT) };
  let blocks = len / MIN_BLOCK + segments;
  let stored_blocks = blocks + len / MAX_STORED;
  len.saturating_add((42 * stored_blocks).div_ceil(8))
}

/// The largest zlib stream [`Encoder::zlib`] can produce for `len` input bytes.
#[inline]
pub const fn zlib_bound(len: usize) -> usize {
  Format::Zlib.bound(len)
}

/// The largest gzip member [`Encoder::gzip`] can produce for `len` input bytes.
#[inline]
pub const fn gzip_bound(len: usize) -> usize {
  Format::Gzip.bound(len)
}

/// How the input is parsed into literals and matches.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Strategy {
  /// No matching: the input as stored blocks.
  Stored,
  /// Greedy over a hash table of the last two positions per hash: the fastest. Ignores
  /// `search_depth` and `good_match`, and does not split blocks by their statistics.
  Fast,
  /// Greedy over hash chains: every match found is taken.
  Greedy,
  /// A match is deferred at most once, when the next position starts a longer one (the tuned
  /// small-body default).
  LazyOnce,
  /// A match is deferred as long as the next position starts a clearly better one.
  Lazy,
  /// As [`Strategy::Lazy`], looking two positions ahead.
  Lazy2,
}

/// How hard the encoder searches for matches. [`Level`] names tuned sets; these are the knobs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Params {
  /// How the input is parsed.
  pub strategy: Strategy,
  /// Hash chain links tried per position.
  pub search_depth: u16,
  /// A match this long ends the search and the lazy step.
  pub nice_match: u16,
  /// Past this length the lazy step searches a quarter as deep (else half as deep, or as deep
  /// for [`Strategy::LazyOnce`]).
  pub good_match: u16,
  /// Longer matches enter only their first `max_insert` positions into the tables — the fast
  /// parser's buckets as well as the hash chains.
  pub max_insert: u16,
  /// Skip acceleration: the longer a run of misses, the more matchless positions in a row the
  /// parser steps over — one more per 64 / this many misses, capped at 256 — as lz4 and
  /// sirocco do; but each skipped position is still inserted into the tables without being
  /// searched, so a later repeat of it stays findable. 0 for never. Only past a stream's first
  /// window, where misses are as much the empty tables' as the input's.
  pub skip_accel: u16,
  /// Match from three bytes through a second hash table (the lazy strategies only; the others
  /// always match from four). Costs insert and chain time; sirocco drops it outright.
  pub len3: bool,
  /// End blocks where the statistics of the symbols change (inputs of 10,000 bytes and more;
  /// not with [`Strategy::Fast`]). Levels 4-9 do.
  pub split_blocks: bool,
}

impl Params {
  /// The parameters of `level`.
  #[inline]
  pub const fn of_level(level: Level) -> Self {
    const fn p(
      strategy: Strategy,
      search_depth: u16,
      nice_match: u16,
      good_match: u16,
      max_insert: u16,
      skip_accel: u16,
    ) -> Params {
      // The 3-byte hash table is off: on every corpus class it costs more time than the
      // length-3 matches it finds are worth (their absence even shrinks some outputs, as
      // sirocco also observed when they dropped it); the knob stays for niche inputs.
      Params {
        strategy,
        search_depth,
        nice_match,
        good_match,
        max_insert,
        skip_accel,
        len3: false,
        split_blocks: true,
      }
    }
    match level.0 {
      0 => p(Strategy::Stored, 0, 0, 0, 0, 0),
      // The speed levels do not split blocks: on 64 KB to 1 MB inputs splitting saves 0.1-1% for
      // about 7% more time (and nothing below 10,000 bytes, where it never applies)
      // A fast-level match enters only its start and next two positions into the buckets: the
      // insert loop was a third of level 1's time on repetitive input, for under 1.3% of size
      // (sirocco's level 1 enters none at all). The chain levels keep every position: their
      // matches come from the chains the inserts build.
      1 => Params { split_blocks: false, ..p(Strategy::Fast, 1, 32, 0, 2, 4) },
      2 => Params { split_blocks: false, ..p(Strategy::Greedy, 4, 16, 258, 4, 4) },
      3 => Params { split_blocks: false, ..p(Strategy::LazyOnce, 6, 64, 8, 2, 2) },
      4 => p(Strategy::Lazy, 10, 30, 258, 258, 0),
      5 => p(Strategy::Lazy, 16, 30, 258, 258, 0),
      6 => p(Strategy::Lazy, 35, 65, 258, 258, 0),
      7 => p(Strategy::Lazy, 100, 130, 258, 258, 0),
      8 => p(Strategy::Lazy2, 300, 258, 258, 258, 0),
      _ => p(Strategy::Lazy2, 600, 258, 258, 258, 0),
    }
  }
}

impl Default for Params {
  /// The parameters of [`Level::DEFAULT`].
  #[inline]
  fn default() -> Self {
    Self::of_level(Level::DEFAULT)
  }
}

/// A compression level: 0 (stored) to 9 (smallest, slowest).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Level(u8);

impl Level {
  /// Level 0: no compression, the input as stored blocks.
  pub const NONE: Self = Self(0);
  /// Level 1: greedy over a hash table, no block splitting.
  pub const FASTEST: Self = Self(1);
  /// Level 3, the default: one-step lazy matching with shallow chains (depth 6, nice length 64,
  /// good length 8, two insertions per match), the winner of the json-comp sweep of rimu-ws
  /// (11 Nov 2026) for small JSON bodies; no block splitting.
  pub const DEFAULT: Self = Self(3);
  /// Level 9: lazy matching two positions ahead, deep chains.
  pub const BEST: Self = Self(9);

  /// The level `level`, if it is at most 9.
  #[inline]
  pub const fn new(level: u8) -> Option<Self> {
    if level <= 9 { Some(Self(level)) } else { None }
  }

  /// The level as a number.
  #[inline]
  pub const fn get(self) -> u8 {
    self.0
  }
}

impl Default for Level {
  #[inline]
  fn default() -> Self {
    Self::DEFAULT
  }
}

/// A reusable one-shot encoder. See the crate documentation.
#[derive(Debug)]
pub struct Encoder {
  #[cfg(test)]
  block_types: Vec<block::BlockType>,
  /// The hash chains of the chain parsers.
  chains: Chains,
  /// The codes and header of the current dynamic block.
  dynamic: Dynamic,
  /// The hash table of the fast parser.
  fast: FastTable,
  /// The shortest match the lazy strategies take in the current block.
  min_len: usize,
  /// The parameters.
  params: Params,
  /// The block-split statistics of the current block.
  split: SplitStats,
  /// The tokens of the current block.
  tokens: Tokens,
}

impl Encoder {
  /// An encoder at [`Level::DEFAULT`]. Allocates nothing.
  #[inline]
  pub fn new() -> Self {
    Self::with_params(Params::default())
  }

  /// An encoder at `level`. Allocates nothing.
  #[inline]
  pub fn with_level(level: Level) -> Self {
    Self::with_params(Params::of_level(level))
  }

  /// An encoder with `params`. Allocates nothing.
  #[inline]
  pub fn with_params(params: Params) -> Self {
    Self {
      #[cfg(test)]
      block_types: Vec::new(),
      chains: Chains::new(),
      dynamic: Dynamic::new(),
      fast: FastTable::new(),
      min_len: tokens::MIN_MATCH,
      params,
      split: SplitStats::new(),
      tokens: Tokens::new(),
    }
  }

  /// The parameters of this encoder.
  #[inline]
  pub fn params(&self) -> Params {
    self.params
  }

  /// The block types of the last encode.
  #[cfg(test)]
  pub(crate) fn last_block_types(&self) -> &[block::BlockType] {
    &self.block_types
  }

  /// Appends the raw DEFLATE stream of `input` to `out`. Allocates only to grow `out` (once, to
  /// [`deflate_bound`]) or this encoder's state beyond their high-water marks.
  #[inline]
  pub fn deflate(&mut self, input: &[u8], out: &mut Vec<u8>) {
    self.encode(Format::Raw, input, out);
  }

  /// Appends the zlib stream of `input` to `out`. Allocates as [`Self::deflate`].
  #[inline]
  pub fn zlib(&mut self, input: &[u8], out: &mut Vec<u8>) {
    self.encode(Format::Zlib, input, out);
  }

  /// Appends one complete gzip member for `input` to `out`. Allocates as [`Self::deflate`].
  #[inline]
  pub fn gzip(&mut self, input: &[u8], out: &mut Vec<u8>) {
    self.encode(Format::Gzip, input, out);
  }

  /// Appends `input` encoded in `format` to `out`. Allocates as [`Self::deflate`].
  pub fn encode(&mut self, format: Format, input: &[u8], out: &mut Vec<u8>) {
    #[cfg(test)]
    self.block_types.clear();
    match format {
      Format::Raw => {}
      Format::Zlib => {
        let level: u16 = match self.params.strategy {
          Strategy::Stored | Strategy::Fast => 0,
          Strategy::Greedy => 1,
          Strategy::LazyOnce | Strategy::Lazy => 2,
          Strategy::Lazy2 => 3,
        };
        // CM 8 (deflate), CINFO 7 (32 KiB window), FLEVEL, and FCHECK making it a multiple of 31
        let mut header = 0x7800 | level << 6;
        header += 31 - header % 31;
        out.reserve(Format::Zlib.bound(input.len()));
        out.extend_from_slice(&header.to_be_bytes());
      }
      Format::Gzip => {
        let xfl = match self.params.strategy {
          Strategy::Stored | Strategy::Fast => 4,
          Strategy::Lazy2 => 2,
          _ => 0,
        };
        out.reserve(Format::Gzip.bound(input.len()));
        out.extend_from_slice(&GZIP_HEADER);
        out.extend_from_slice(&[xfl, GZIP_OS]);
      }
    }
    let mut writer = BitWriter::new(out, deflate_bound(input.len()));
    self.deflate_stream(input, &mut writer);
    let out = writer.finish();
    match format {
      Format::Raw => {}
      Format::Zlib => out.extend_from_slice(&checksum::adler32(input).to_be_bytes()),
      Format::Gzip => {
        out.extend_from_slice(&checksum::crc32(input).to_le_bytes());
        out.extend_from_slice(&(input.len() as u32).to_le_bytes());
      }
    }
  }

  /// Writes the DEFLATE stream of `input`.
  fn deflate_stream(&mut self, input: &[u8], writer: &mut BitWriter<'_>) {
    if input.is_empty() {
      self.tokens.clear();
      #[cfg(test)]
      self.block_types.push(block::BlockType::Fixed);
      writer.ensure(16);
      write_fixed(writer, Block { seqs: &[], trailing: 0, bytes: &[] }, true);
      return;
    }
    if self.params.strategy == Strategy::Stored {
      #[cfg(test)]
      self.block_types.push(block::BlockType::Stored);
      write_stored(writer, input, true);
      return;
    }
    let mut segments = input.chunks(SEGMENT).peekable();
    while let Some(segment) = segments.next() {
      self.deflate_segment(segment, segments.peek().is_none(), writer);
    }
  }

  /// Writes the blocks of one segment; `last` marks the final segment.
  fn deflate_segment(&mut self, data: &[u8], last: bool, writer: &mut BitWriter<'_>) {
    let params = self.params;
    let fast = params.strategy == Strategy::Fast;
    let max_block = if fast { FAST_BLOCK } else { MAX_BLOCK };
    let splitting = params.split_blocks && !fast && data.len() >= 2 * MIN_BLOCK;
    if fast {
      self.fast.reset(data.len());
    } else {
      let len3 = matches!(params.strategy, Strategy::Lazy | Strategy::Lazy2) && params.len3;
      self.chains.reset(data.len(), 15, len3);
    }
    let n = data.len();
    // Bytes `block_start..pos` are parsed into `self.tokens`
    let (mut block_start, mut pos) = (0, 0);
    self.tokens.clear();
    while block_start < n {
      let max_end =
        if n - block_start < max_block + MIN_BLOCK { n } else { block_start + max_block };
      self.tokens.reserve(max_end.saturating_sub(pos) + MAX_MATCH);
      if splitting {
        self.split.merge(&self.tokens);
      }
      let adaptive = matches!(params.strategy, Strategy::Lazy | Strategy::Lazy2);
      self.min_len = if adaptive {
        min_len::of_bytes(&data[block_start..max_end], params.search_depth)
      } else {
        tokens::MIN_MATCH
      };
      let mut recalc_at = pos + (n - pos).min(10_000);
      // As libdeflate: parse, and every `CHECK_BYTES` bytes compare the newest symbols with the
      // block's; the block ends where they differ enough
      loop {
        let stop = if splitting { max_end.min(pos + CHECK_BYTES) } else { max_end };
        pos = self.parse(data, pos, stop.min(if adaptive { recalc_at } else { stop }));
        if adaptive && pos >= recalc_at {
          // Again from the literals the block actually uses, every block length so far
          self.min_len = min_len::of_freq(&self.tokens.lit_freq, params.search_depth);
          recalc_at += (n - recalc_at).min(pos - block_start);
        }
        if pos >= max_end
          || splitting
            && pos - block_start >= MIN_BLOCK
            && n - pos >= MIN_BLOCK
            && self.split.check(&self.tokens, pos - block_start) == Check::End
        {
          break;
        }
      }
      let tokens = &mut self.tokens;
      let trailing = core::mem::take(&mut tokens.pending) as usize;
      let block = Block { seqs: &tokens.seqs, trailing, bytes: &data[block_start..pos] };
      let _block_type = write_block(writer, &mut self.dynamic, tokens, block, last && pos == n);
      #[cfg(test)]
      self.block_types.push(_block_type);
      self.tokens.clear();
      block_start = pos;
    }
  }

  /// Parses `data[pos..]` into the tokens until `stop`.
  #[inline]
  fn parse(&mut self, data: &[u8], pos: usize, stop: usize) -> usize {
    let p = &self.params;
    let search = Search {
      depth: p.search_depth.into(),
      nice: p.nice_match.into(),
      good: p.good_match.into(),
      max_insert: p.max_insert.into(),
      min_len: self.min_len,
      skip_accel: p.skip_accel.into(),
    };
    let (chains, tokens) = (&mut self.chains, &mut self.tokens);
    let big = data.len() > matcher::HALF;
    match p.strategy {
      Strategy::Stored => unreachable!("stored inputs are not parsed"),
      Strategy::Fast => self.fast.parse(data, pos, stop, &search, tokens),
      Strategy::Greedy if big => {
        chains.parse::<GREEDY, true, false>(data, pos, stop, &search, tokens)
      }
      Strategy::Greedy => chains.parse::<GREEDY, false, false>(data, pos, stop, &search, tokens),
      Strategy::LazyOnce if big => {
        chains.parse::<LAZY1, true, false>(data, pos, stop, &search, tokens)
      }
      Strategy::LazyOnce => chains.parse::<LAZY1, false, false>(data, pos, stop, &search, tokens),
      Strategy::Lazy if big && p.len3 => {
        chains.parse::<LAZY, true, true>(data, pos, stop, &search, tokens)
      }
      Strategy::Lazy if big => chains.parse::<LAZY, true, false>(data, pos, stop, &search, tokens),
      Strategy::Lazy if p.len3 => {
        chains.parse::<LAZY, false, true>(data, pos, stop, &search, tokens)
      }
      Strategy::Lazy => chains.parse::<LAZY, false, false>(data, pos, stop, &search, tokens),
      Strategy::Lazy2 if big && p.len3 => {
        chains.parse::<LAZY2, true, true>(data, pos, stop, &search, tokens)
      }
      Strategy::Lazy2 if big => {
        chains.parse::<LAZY2, true, false>(data, pos, stop, &search, tokens)
      }
      Strategy::Lazy2 if p.len3 => {
        chains.parse::<LAZY2, false, true>(data, pos, stop, &search, tokens)
      }
      Strategy::Lazy2 => chains.parse::<LAZY2, false, false>(data, pos, stop, &search, tokens),
    }
  }
}

impl Default for Encoder {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
