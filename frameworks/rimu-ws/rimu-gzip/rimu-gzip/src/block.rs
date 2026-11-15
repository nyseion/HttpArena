//! Writing one DEFLATE block (RFC 1951 §3.2.3) in whichever of the stored, fixed-code and
//! dynamic-code types costs the fewest bits.

use crate::{
  bits::BitWriter,
  bits::Local,
  dynamic::Dynamic,
  tokens::{DIST_SYMBOLS, DIST_XBITS, LEN_XBITS, LIT_SYMBOLS, Seq, Tokens, seq_len, unpack},
};

/// The end-of-block symbol.
pub(crate) const END_OF_BLOCK: usize = 256;
/// The most bytes one stored block holds.
pub(crate) const MAX_STORED: usize = 65_535;

/// How a block was coded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockType {
  /// Stored: the bytes as they are.
  Stored,
  /// Coded with the fixed Huffman codes.
  Fixed,
  /// Coded with Huffman codes of its own, sent in its header.
  Dynamic,
}

/// Bits of `len` bytes as stored blocks of at most [`MAX_STORED`] bytes, the first started at bit
/// `position`: each a 3-bit header, padding to a byte, LEN and NLEN, then its bytes.
pub(crate) fn stored_bits(position: u64, len: usize) -> u64 {
  let blocks = len.div_ceil(MAX_STORED).max(1) as u64;
  let after_header = position + 3;
  let first_pad = (8 - after_header % 8) % 8;
  // Every block after the first starts byte-aligned: 3 header bits and 5 of padding
  3 + first_pad + 32 + (blocks - 1) * 40 + 8 * len as u64
}

/// Writes `bytes` as stored blocks of at most [`MAX_STORED`] bytes; `last` marks the final one.
pub(crate) fn write_stored(writer: &mut BitWriter<'_>, bytes: &[u8], last: bool) {
  let mut chunks = bytes.chunks(MAX_STORED).peekable();
  if chunks.peek().is_none() {
    write_stored_one(writer, &[], last);
  }
  while let Some(chunk) = chunks.next() {
    write_stored_one(writer, chunk, last && chunks.peek().is_none());
  }
}

/// One stored block of at most [`MAX_STORED`] bytes.
fn write_stored_one(writer: &mut BitWriter<'_>, chunk: &[u8], last: bool) {
  writer.put(u32::from(last), 3);
  writer.align();
  let len = chunk.len() as u16;
  writer.bytes(&len.to_le_bytes());
  writer.bytes(&(!len).to_le_bytes());
  writer.bytes(chunk);
}

/// The fixed literal/length code (RFC 1951 §3.2.6) of `symbol`: (bit-reversed code, length).
const fn fixed_lit_code(symbol: usize) -> (u16, u8) {
  let (code, len) = match symbol {
    0..=143 => (0x30 + symbol as u16, 8),
    144..=255 => (0x190 + (symbol - 144) as u16, 9),
    256..=279 => ((symbol - 256) as u16, 7),
    _ => (0xc0 + (symbol - 280) as u16, 8),
  };
  (reverse(code, len), len)
}

/// The low `len` bits of `code` in reverse order: Huffman codes go out most significant bit first
/// in an LSB-first stream.
pub(crate) const fn reverse(code: u16, len: u8) -> u16 {
  code.reverse_bits() >> (16 - len as u32)
}

/// Every byte with its bits reversed.
const REVERSED: [u8; 256] = {
  let mut table = [0; 256];
  let mut byte = 0;
  while byte < 256 {
    table[byte] = (byte as u8).reverse_bits();
    byte += 1;
  }
  table
};

/// [`reverse`] by table: x86 has no bit-reverse instruction, and `reverse_bits` on 16 bits
/// becomes a dozen shifts and masks.
#[inline(always)]
pub(crate) fn reverse_fast(code: u16, len: u8) -> u16 {
  let [lo, hi] = code.to_le_bytes();
  let reversed = u16::from(REVERSED[usize::from(lo)]) << 8 | u16::from(REVERSED[usize::from(hi)]);
  reversed >> (16 - u32::from(len))
}

/// The fixed literal/length codes, bit-reversed (of the symbols in use).
const FIXED_LIT_CODE: [u16; LIT_SYMBOLS] = {
  let mut table = [0; LIT_SYMBOLS];
  let mut symbol = 0;
  while symbol < LIT_SYMBOLS {
    table[symbol] = fixed_lit_code(symbol).0;
    symbol += 1;
  }
  table
};
/// The lengths of the fixed literal/length codes (of the symbols in use).
pub(crate) const FIXED_LIT_LEN: [u8; LIT_SYMBOLS] = {
  let mut table = [0; LIT_SYMBOLS];
  let mut symbol = 0;
  while symbol < LIT_SYMBOLS {
    table[symbol] = fixed_lit_code(symbol).1;
    symbol += 1;
  }
  table
};
/// The fixed distance codes, bit-reversed (all 5 bits long).
const FIXED_DIST_CODE: [u16; DIST_SYMBOLS] = {
  let mut table = [0; DIST_SYMBOLS];
  let mut sym = 0;
  while sym < DIST_SYMBOLS {
    table[sym] = reverse(sym as u16, 5);
    sym += 1;
  }
  table
};
/// The lengths of the fixed distance codes.
const FIXED_DIST_LEN: [u8; DIST_SYMBOLS] = [5; DIST_SYMBOLS];

/// Bits of `tokens` as one fixed-code block: header, symbols, extra bits, end of block.
pub(crate) fn fixed_bits(tokens: &Tokens) -> u64 {
  let symbols: u64 = tokens
    .lit_freq
    .iter()
    .enumerate()
    .map(|(sym, &freq)| u64::from(freq) * u64::from(FIXED_LIT_LEN[sym]))
    .sum();
  let distances: u64 = tokens.dist_freq.iter().map(|&freq| u64::from(freq) * 5).sum();
  3 + symbols + distances + tokens.extra_bits + u64::from(FIXED_LIT_LEN[END_OF_BLOCK])
}

/// The tokens of one block: its sequences, the literals after them, and the input bytes they
/// cover.
#[derive(Clone, Copy)]
pub(crate) struct Block<'a> {
  /// The sequences (see [`Tokens`]).
  pub(crate) seqs: &'a [u64],
  /// The literals after the last sequence.
  pub(crate) trailing: usize,
  /// The input bytes the block covers.
  pub(crate) bytes: &'a [u8],
}

/// Writes `block`, whose statistics `tokens` holds, in the cheapest block type; returns that
/// type. `last` marks the final block of the stream.
pub(crate) fn write_block(
  writer: &mut BitWriter<'_>,
  dynamic: &mut Dynamic,
  tokens: &Tokens,
  block: Block<'_>,
  last: bool,
) -> BlockType {
  let stored = stored_bits(writer.position(), block.bytes.len());
  let fixed = fixed_bits(tokens);
  let dynamic_bits = dynamic.plan(tokens);
  if dynamic_bits < fixed && dynamic_bits < stored {
    // The exact size, plus a margin: the token writer then runs without growing the output
    writer.ensure((dynamic_bits / 8) as usize + 16);
    dynamic.write_header(writer, last);
    let d = &*dynamic;
    write_seqs(writer, block, &d.lit_code, &d.lit_len, &d.dist_code, &d.dist_len);
    BlockType::Dynamic
  } else if fixed < stored {
    writer.ensure((fixed / 8) as usize + 16);
    write_fixed(writer, block, last);
    BlockType::Fixed
  } else {
    write_stored(writer, block.bytes, last);
    BlockType::Stored
  }
}

/// One fixed-code block.
pub(crate) fn write_fixed(writer: &mut BitWriter<'_>, block: Block<'_>, last: bool) {
  writer.put(u32::from(last) | (1 << 1), 3);
  write_seqs(writer, block, &FIXED_LIT_CODE, &FIXED_LIT_LEN, &FIXED_DIST_CODE, &FIXED_DIST_LEN);
}

/// The tokens of a block in its codes, then its end of block, from writer state held in locals.
/// A match goes into the accumulator whole (at most 14 + 5 + 15 + 13 bits), literals four at a
/// time (56 bits), each followed by one branch-free flush. Room for the whole block must have
/// been made (each flush asserts it).
#[inline(never)]
fn write_seqs(
  writer: &mut BitWriter<'_>,
  block: Block<'_>,
  lit_code: &[u16; LIT_SYMBOLS],
  lit_len: &[u8; LIT_SYMBOLS],
  dist_code: &[u16; DIST_SYMBOLS],
  dist_len: &[u8; DIST_SYMBOLS],
) {
  // Per length and distance symbol, its code, the code's length, and that plus the extra bits,
  // packed as `code | n << 16 | total << 24`: one 4-byte load per symbol. Codes are at most 15
  // bits and totals at most 28, so both fit.
  let mut len_code = [0u32; 32];
  for (ls, entry) in len_code.iter_mut().enumerate().take(29) {
    let n = u32::from(lit_len[257 + ls]);
    *entry = u32::from(lit_code[257 + ls]) | n << 16 | (n + u32::from(LEN_XBITS[ls])) << 24;
  }
  let mut dist_tab = [0u32; 32];
  for (ds, entry) in dist_tab.iter_mut().enumerate().take(DIST_SYMBOLS) {
    let n = u32::from(dist_len[ds]);
    *entry = u32::from(dist_code[ds]) | n << 16 | (n + u32::from(DIST_XBITS[ds])) << 24;
  }
  writer.ensure(16);
  let mut state = writer.local();
  let w = &mut state;
  // Down to at most 7 bits, so that a whole match fits
  w.flush();
  let bytes = block.bytes;
  let mut p = 0;
  for &seq in block.seqs {
    let Seq { run, ls, len_extra, ds, dist_extra } = unpack(seq);
    write_literals(w, &bytes[p..p + run], lit_code, lit_len);
    p += run + seq_len(seq);
    let e = len_code[ls];
    w.put_unflushed(u64::from(e & 0xFFFF) | len_extra << ((e >> 16) & 0xF), (e >> 24) & 0x1F);
    let e = dist_tab[ds];
    w.put_unflushed(u64::from(e & 0xFFFF) | dist_extra << ((e >> 16) & 0xF), (e >> 24) & 0x1F);
    w.flush();
  }
  write_literals(w, &bytes[p..p + block.trailing], lit_code, lit_len);
  w.put_unflushed(lit_code[END_OF_BLOCK].into(), lit_len[END_OF_BLOCK].into());
  w.flush();
  writer.restore(state);
}

/// Literals in their codes, four between two flushes (literal codes are at most 14 bits long:
/// 56 bits and the at most 7 left by a flush fit in the accumulator). Each quad is shifted into
/// one word by the prefix sums of its code lengths first: three of the four shifts then depend
/// only on their own code, and just one — the accumulator's — is carried between iterations.
#[inline(always)]
fn write_literals(
  w: &mut Local,
  literals: &[u8],
  code: &[u16; LIT_SYMBOLS],
  len: &[u8; LIT_SYMBOLS],
) {
  if literals.is_empty() {
    return;
  }
  let (quads, rest) = literals.as_chunks::<4>();
  for quad in quads {
    let mut word = 0u64;
    let mut at = 0u32;
    for &byte in quad {
      word |= u64::from(code[usize::from(byte)]) << at;
      at += u32::from(len[usize::from(byte)]);
    }
    w.put_unflushed(word, at);
    w.flush();
  }
  if !rest.is_empty() {
    let mut word = 0u64;
    let mut at = 0u32;
    for &byte in rest {
      word |= u64::from(code[usize::from(byte)]) << at;
      at += u32::from(len[usize::from(byte)]);
    }
    w.put_unflushed(word, at);
    w.flush();
  }
}
