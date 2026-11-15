//! The Huffman code of HPACK (RFC 7541 section 5.2 and Appendix B), which QPACK uses for string
//! literals (RFC 9204 section 4.1.2).
//!
//! The encoder packs codes into a 64-bit accumulator and writes 32 bits at a time. The decoder
//! reads four bits at a time through a state table that is built at compile time from the code
//! table: a state is an internal node of the code tree (256 of them for 257 symbols), and each
//! entry of a state gives, for the next four bits, the node reached, the symbol completed on the
//! way if any (at most one: the shortest code has 5 bits), and whether ending the string at the
//! node is valid. The end is valid at the root, or at a node whose path from the root is all ones
//! and at most 7 bits long: padding must be a prefix of EOS shorter than a byte (RFC 7541 section
//! 5.2). Reaching the EOS leaf is an error.

use alloc::vec::Vec;

/// The code of each symbol, most significant bit first, and its length in bits; symbol 256 is
/// EOS. The data of RFC 7541 Appendix B.
pub(crate) static CODES: [(u32, u8); 257] = [
  (0x1ff8, 13),
  (0x7fffd8, 23),
  (0xfffffe2, 28),
  (0xfffffe3, 28),
  (0xfffffe4, 28),
  (0xfffffe5, 28),
  (0xfffffe6, 28),
  (0xfffffe7, 28),
  (0xfffffe8, 28),
  (0xffffea, 24),
  (0x3ffffffc, 30),
  (0xfffffe9, 28),
  (0xfffffea, 28),
  (0x3ffffffd, 30),
  (0xfffffeb, 28),
  (0xfffffec, 28),
  (0xfffffed, 28),
  (0xfffffee, 28),
  (0xfffffef, 28),
  (0xffffff0, 28),
  (0xffffff1, 28),
  (0xffffff2, 28),
  (0x3ffffffe, 30),
  (0xffffff3, 28),
  (0xffffff4, 28),
  (0xffffff5, 28),
  (0xffffff6, 28),
  (0xffffff7, 28),
  (0xffffff8, 28),
  (0xffffff9, 28),
  (0xffffffa, 28),
  (0xffffffb, 28),
  (0x14, 6),
  (0x3f8, 10),
  (0x3f9, 10),
  (0xffa, 12),
  (0x1ff9, 13),
  (0x15, 6),
  (0xf8, 8),
  (0x7fa, 11),
  (0x3fa, 10),
  (0x3fb, 10),
  (0xf9, 8),
  (0x7fb, 11),
  (0xfa, 8),
  (0x16, 6),
  (0x17, 6),
  (0x18, 6),
  (0x0, 5),
  (0x1, 5),
  (0x2, 5),
  (0x19, 6),
  (0x1a, 6),
  (0x1b, 6),
  (0x1c, 6),
  (0x1d, 6),
  (0x1e, 6),
  (0x1f, 6),
  (0x5c, 7),
  (0xfb, 8),
  (0x7ffc, 15),
  (0x20, 6),
  (0xffb, 12),
  (0x3fc, 10),
  (0x1ffa, 13),
  (0x21, 6),
  (0x5d, 7),
  (0x5e, 7),
  (0x5f, 7),
  (0x60, 7),
  (0x61, 7),
  (0x62, 7),
  (0x63, 7),
  (0x64, 7),
  (0x65, 7),
  (0x66, 7),
  (0x67, 7),
  (0x68, 7),
  (0x69, 7),
  (0x6a, 7),
  (0x6b, 7),
  (0x6c, 7),
  (0x6d, 7),
  (0x6e, 7),
  (0x6f, 7),
  (0x70, 7),
  (0x71, 7),
  (0x72, 7),
  (0xfc, 8),
  (0x73, 7),
  (0xfd, 8),
  (0x1ffb, 13),
  (0x7fff0, 19),
  (0x1ffc, 13),
  (0x3ffc, 14),
  (0x22, 6),
  (0x7ffd, 15),
  (0x3, 5),
  (0x23, 6),
  (0x4, 5),
  (0x24, 6),
  (0x5, 5),
  (0x25, 6),
  (0x26, 6),
  (0x27, 6),
  (0x6, 5),
  (0x74, 7),
  (0x75, 7),
  (0x28, 6),
  (0x29, 6),
  (0x2a, 6),
  (0x7, 5),
  (0x2b, 6),
  (0x76, 7),
  (0x2c, 6),
  (0x8, 5),
  (0x9, 5),
  (0x2d, 6),
  (0x77, 7),
  (0x78, 7),
  (0x79, 7),
  (0x7a, 7),
  (0x7b, 7),
  (0x7ffe, 15),
  (0x7fc, 11),
  (0x3ffd, 14),
  (0x1ffd, 13),
  (0xffffffc, 28),
  (0xfffe6, 20),
  (0x3fffd2, 22),
  (0xfffe7, 20),
  (0xfffe8, 20),
  (0x3fffd3, 22),
  (0x3fffd4, 22),
  (0x3fffd5, 22),
  (0x7fffd9, 23),
  (0x3fffd6, 22),
  (0x7fffda, 23),
  (0x7fffdb, 23),
  (0x7fffdc, 23),
  (0x7fffdd, 23),
  (0x7fffde, 23),
  (0xffffeb, 24),
  (0x7fffdf, 23),
  (0xffffec, 24),
  (0xffffed, 24),
  (0x3fffd7, 22),
  (0x7fffe0, 23),
  (0xffffee, 24),
  (0x7fffe1, 23),
  (0x7fffe2, 23),
  (0x7fffe3, 23),
  (0x7fffe4, 23),
  (0x1fffdc, 21),
  (0x3fffd8, 22),
  (0x7fffe5, 23),
  (0x3fffd9, 22),
  (0x7fffe6, 23),
  (0x7fffe7, 23),
  (0xffffef, 24),
  (0x3fffda, 22),
  (0x1fffdd, 21),
  (0xfffe9, 20),
  (0x3fffdb, 22),
  (0x3fffdc, 22),
  (0x7fffe8, 23),
  (0x7fffe9, 23),
  (0x1fffde, 21),
  (0x7fffea, 23),
  (0x3fffdd, 22),
  (0x3fffde, 22),
  (0xfffff0, 24),
  (0x1fffdf, 21),
  (0x3fffdf, 22),
  (0x7fffeb, 23),
  (0x7fffec, 23),
  (0x1fffe0, 21),
  (0x1fffe1, 21),
  (0x3fffe0, 22),
  (0x1fffe2, 21),
  (0x7fffed, 23),
  (0x3fffe1, 22),
  (0x7fffee, 23),
  (0x7fffef, 23),
  (0xfffea, 20),
  (0x3fffe2, 22),
  (0x3fffe3, 22),
  (0x3fffe4, 22),
  (0x7ffff0, 23),
  (0x3fffe5, 22),
  (0x3fffe6, 22),
  (0x7ffff1, 23),
  (0x3ffffe0, 26),
  (0x3ffffe1, 26),
  (0xfffeb, 20),
  (0x7fff1, 19),
  (0x3fffe7, 22),
  (0x7ffff2, 23),
  (0x3fffe8, 22),
  (0x1ffffec, 25),
  (0x3ffffe2, 26),
  (0x3ffffe3, 26),
  (0x3ffffe4, 26),
  (0x7ffffde, 27),
  (0x7ffffdf, 27),
  (0x3ffffe5, 26),
  (0xfffff1, 24),
  (0x1ffffed, 25),
  (0x7fff2, 19),
  (0x1fffe3, 21),
  (0x3ffffe6, 26),
  (0x7ffffe0, 27),
  (0x7ffffe1, 27),
  (0x3ffffe7, 26),
  (0x7ffffe2, 27),
  (0xfffff2, 24),
  (0x1fffe4, 21),
  (0x1fffe5, 21),
  (0x3ffffe8, 26),
  (0x3ffffe9, 26),
  (0xffffffd, 28),
  (0x7ffffe3, 27),
  (0x7ffffe4, 27),
  (0x7ffffe5, 27),
  (0xfffec, 20),
  (0xfffff3, 24),
  (0xfffed, 20),
  (0x1fffe6, 21),
  (0x3fffe9, 22),
  (0x1fffe7, 21),
  (0x1fffe8, 21),
  (0x7ffff3, 23),
  (0x3fffea, 22),
  (0x3fffeb, 22),
  (0x1ffffee, 25),
  (0x1ffffef, 25),
  (0xfffff4, 24),
  (0xfffff5, 24),
  (0x3ffffea, 26),
  (0x7ffff4, 23),
  (0x3ffffeb, 26),
  (0x7ffffe6, 27),
  (0x3ffffec, 26),
  (0x3ffffed, 26),
  (0x7ffffe7, 27),
  (0x7ffffe8, 27),
  (0x7ffffe9, 27),
  (0x7ffffea, 27),
  (0x7ffffeb, 27),
  (0xffffffe, 28),
  (0x7ffffec, 27),
  (0x7ffffed, 27),
  (0x7ffffee, 27),
  (0x7ffffef, 27),
  (0x7fffff0, 27),
  (0x3ffffee, 26),
  (0x3fffffff, 30),
];

/// A child of a tree node that is a leaf: the symbol is in the low 9 bits.
const LEAF: u16 = 0x8000;
const NO_CHILD: u16 = u16::MAX;
const EOS: u16 = 256;

/// Bits of a decoding table entry.
const NEXT_MASK: u32 = 0xff;
const SYMBOL_SHIFT: u32 = 8;
const EMIT: u32 = 1 << 16;
const FAIL: u32 = 1 << 17;
const ACCEPT: u32 = 1 << 18;

/// The code tree: 256 internal nodes with their two children, the depth of each node and whether
/// its path from the root is all ones.
struct Tree {
  children: [[u16; 2]; 256],
  depth: [u8; 256],
  all_ones: [bool; 256],
}

const fn build_tree() -> Tree {
  let mut tree = Tree { children: [[NO_CHILD; 2]; 256], depth: [0; 256], all_ones: [true; 256] };
  let mut count = 1usize;
  let mut symbol = 0usize;
  while symbol < 257 {
    let (code, len) = CODES[symbol];
    let mut node = 0usize;
    let mut bit_idx = len;
    // Every bit but the last leads to an internal node, created if it is not there yet
    while bit_idx > 1 {
      bit_idx -= 1;
      let bit = ((code >> bit_idx) & 1) as usize;
      let child = tree.children[node][bit];
      if child == NO_CHILD {
        assert!(count < 256, "the code is not prefix-free");
        tree.children[node][bit] = count as u16;
        tree.depth[count] = tree.depth[node] + 1;
        tree.all_ones[count] = tree.all_ones[node] && bit == 1;
        node = count;
        count += 1;
      } else {
        assert!(child & LEAF == 0, "the code is not prefix-free");
        node = child as usize;
      }
    }
    let bit = (code & 1) as usize;
    assert!(tree.children[node][bit] == NO_CHILD, "the code is not prefix-free");
    tree.children[node][bit] = LEAF | symbol as u16;
    symbol += 1;
  }
  // A complete code of 257 leaves has 256 internal nodes, each with two children
  assert!(count == 256);
  let mut node = 0;
  while node < 256 {
    assert!(tree.children[node][0] != NO_CHILD && tree.children[node][1] != NO_CHILD);
    node += 1;
  }
  tree
}

const fn build_decode_table() -> [[u32; 16]; 256] {
  let tree = build_tree();
  let mut table = [[0u32; 16]; 256];
  let mut state = 0usize;
  while state < 256 {
    let mut nibble = 0usize;
    while nibble < 16 {
      let mut node = state;
      let mut entry = 0u32;
      let mut bit_idx = 4;
      while bit_idx > 0 {
        bit_idx -= 1;
        let child = tree.children[node][(nibble >> bit_idx) & 1];
        if child & LEAF != 0 {
          let symbol = child & !LEAF;
          if symbol == EOS {
            entry |= FAIL;
            break;
          }
          // The shortest code has 5 bits: four bits complete at most one symbol
          assert!(entry & EMIT == 0);
          entry |= EMIT | ((symbol as u32) << SYMBOL_SHIFT);
          node = 0;
        } else {
          node = child as usize;
        }
      }
      if entry & FAIL == 0 && (node == 0 || (tree.all_ones[node] && tree.depth[node] <= 7)) {
        entry |= ACCEPT;
      }
      table[state][nibble] = entry | node as u32;
      nibble += 1;
    }
    state += 1;
  }
  table
}

/// The decoding state table, see the module documentation.
static DECODE: [[u32; 16]; 256] = build_decode_table();

/// Why a Huffman string could not be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HuffmanError {
  /// An EOS symbol, or padding that is too long or not all ones.
  Invalid,
  /// The output would be longer than allowed.
  TooLong,
}

/// The number of bytes that [`encode`] writes for `src`.
#[inline]
pub(crate) fn encoded_len(src: &[u8]) -> usize {
  let bits = src.iter().fold(0usize, |acc, el| acc + usize::from(CODES[usize::from(*el)].1));
  bits.div_ceil(8)
}

/// Appends the Huffman coding of `src` to `out`, padded with the most significant bits of EOS.
///
/// Returns the number of bytes that the coding takes, the same as [`encoded_len`].
pub(crate) fn encode(src: &[u8], out: &mut Vec<u8>) -> usize {
  out.reserve(src.len());
  let before = out.len();
  let mut acc = 0u64;
  let mut bits = 0u32;
  for byte in src {
    let (code, len) = CODES[usize::from(*byte)];
    // At most 31 bits are pending and a code has at most 30: they fit in 64
    acc = (acc << len) | u64::from(code);
    bits += u32::from(len);
    if bits >= 32 {
      bits -= 32;
      out.extend_from_slice(&((acc >> bits) as u32).to_be_bytes());
    }
  }
  let pad = (8 - bits % 8) % 8;
  acc = (acc << pad) | ((1u64 << pad) - 1);
  bits += pad;
  while bits >= 8 {
    bits -= 8;
    out.push((acc >> bits) as u8);
  }
  out.len() - before
}

/// Appends the decoding of the Huffman string `src` to `out`, which may grow by at most `limit`
/// bytes.
///
/// The output is staged in a small fixed buffer and flushed to `out`, so that no byte of `out`
/// past the real output is ever written: no zeroing pass over the reserved room, which would
/// double the memory traffic of the decode.
pub(crate) fn decode(src: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), HuffmanError> {
  let start = out.len();
  // The shortest code has 5 bits; the slack lets a byte write both of its symbols before the
  // bound is checked
  let bound = (src.len() * 8 / 5).min(limit);
  out.reserve(bound + 2);
  let mut state = 0u8;
  let mut last = ACCEPT;
  let mut n = 0usize;
  // Symbols completed within one block, flushed to `out` when it fills: a byte emits at most
  // two symbols per nibble, so the block holds a little more than a byte's worth
  let mut block = [0u8; 66];
  let mut filled = 0usize;
  let flush = |out: &mut Vec<u8>, block: &[u8; 66], filled: &mut usize| {
    out.extend_from_slice(&block[..*filled]);
    *filled = 0;
  };
  for &byte in src {
    let high = DECODE[usize::from(state)][usize::from(byte >> 4)];
    let low = DECODE[(high & NEXT_MASK) as usize][usize::from(byte & 0x0f)];
    if (high | low) & FAIL != 0 {
      out.truncate(start);
      return Err(HuffmanError::Invalid);
    }
    if filled + 2 > block.len() {
      flush(out, &block, &mut filled);
    }
    block[filled] = (high >> SYMBOL_SHIFT) as u8;
    filled += ((high & EMIT) >> 16) as usize;
    block[filled] = (low >> SYMBOL_SHIFT) as u8;
    filled += ((low & EMIT) >> 16) as usize;
    n += ((high & EMIT) >> 16) as usize + ((low & EMIT) >> 16) as usize;
    if n > bound {
      out.truncate(start);
      return Err(HuffmanError::TooLong);
    }
    state = (low & NEXT_MASK) as u8;
    last = low;
  }
  flush(out, &block, &mut filled);
  if last & ACCEPT == 0 {
    out.truncate(start);
    return Err(HuffmanError::Invalid);
  }
  Ok(())
}

#[cfg(test)]
mod tests;
