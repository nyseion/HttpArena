//! Length-limited Huffman code lengths and canonical codes (RFC 1951 §3.2.2), with fixed-size
//! scratch: no allocation.

use crate::block::reverse_fast;

/// The most symbols any DEFLATE alphabet has (literal/length, with the two unused ones).
const MAX_SYMBOLS: usize = 288;

/// The working arrays of [`code_lengths`], kept between calls so they are not cleared each time:
/// every entry is written before it is read.
#[derive(Debug)]
pub(crate) struct Scratch {
  /// The used symbols, `frequency << 16 | symbol`, sorted.
  leaves: [u64; MAX_SYMBOLS],
  /// The weight of every node: leaves, then internal nodes.
  weight: [u64; 2 * MAX_SYMBOLS],
  /// The internal node above every node.
  parent: [u16; 2 * MAX_SYMBOLS],
  /// The depth of every node.
  depth: [u8; 2 * MAX_SYMBOLS],
}

impl Scratch {
  /// Arrays to be written before they are read. Allocates nothing.
  pub(crate) const fn new() -> Self {
    Self {
      leaves: [0; MAX_SYMBOLS],
      weight: [0; 2 * MAX_SYMBOLS],
      parent: [0; 2 * MAX_SYMBOLS],
      depth: [0; 2 * MAX_SYMBOLS],
    }
  }
}

/// Writes into `out` (as long as `freq`) a code length for every symbol: 0 for unused symbols,
/// 1..=`max_bits` for used ones, forming a complete prefix code; a lone used symbol gets length 1.
/// Returns the number of codes of every length (index 0 unused).
pub(crate) fn code_lengths(
  freq: &[u32],
  max_bits: u8,
  out: &mut [u8],
  scratch: &mut Scratch,
) -> [u16; 16] {
  let Scratch { leaves, weight, parent, depth } = scratch;
  debug_assert!(
    freq.len() <= MAX_SYMBOLS && out.len() == freq.len() && (1..=15).contains(&max_bits)
  );
  out.fill(0);
  // The used symbols sorted by frequency (then symbol), packed for one sort
  let mut n = 0;
  for (sym, &f) in freq.iter().enumerate() {
    if f > 0 {
      leaves[n] = u64::from(f) << 16 | sym as u64;
      n += 1;
    }
  }
  match n {
    0 => return [0; 16],
    1 => {
      out[(leaves[0] & 0xffff) as usize] = 1;
      let mut bl_count = [0; 16];
      bl_count[1] = 1;
      return bl_count;
    }
    _ => {}
  }
  leaves[..n].sort_unstable();
  // Two queues: the sorted leaves and the internal nodes, made in non-decreasing weight order.
  // Nodes 0..n are leaves, n.. internal; `parent` links every node to the internal node above it.
  for (i, leaf) in leaves[..n].iter().enumerate() {
    weight[i] = leaf >> 16;
  }
  let (mut next_leaf, mut next_node, mut nodes) = (0, n, n);
  let pick =
    |next_leaf: &mut usize, next_node: &mut usize, nodes: usize, weight: &[u64]| -> usize {
      if *next_leaf < n && (*next_node >= nodes || weight[*next_leaf] <= weight[*next_node]) {
        *next_leaf += 1;
        *next_leaf - 1
      } else {
        *next_node += 1;
        *next_node - 1
      }
    };
  while nodes < 2 * n - 1 {
    let a = pick(&mut next_leaf, &mut next_node, nodes, weight);
    let b = pick(&mut next_leaf, &mut next_node, nodes, weight);
    weight[nodes] = weight[a] + weight[b];
    parent[a] = nodes as u16;
    parent[b] = nodes as u16;
    nodes += 1;
  }
  // Depths: the root (last node) has depth 0, every node one more than its parent, clamped to
  // `max_bits`. As in zlib (gen_bitlen), every clamped node, internal or leaf, counts as
  // overflow, and the counts are then rebalanced into a complete code.
  let root = nodes - 1;
  depth[root] = 0;
  let mut bl_count = [0u16; 16];
  let mut overflow = 0u32;
  for node in (0..root).rev() {
    let mut d = depth[usize::from(parent[node])] + 1;
    if d > max_bits {
      d = max_bits;
      overflow += 1;
    }
    depth[node] = d;
    if node < n {
      bl_count[usize::from(d)] += 1;
    }
  }
  let max = usize::from(max_bits);
  while overflow > 0 {
    let mut bits = max - 1;
    while bl_count[bits] == 0 {
      bits -= 1;
    }
    bl_count[bits] -= 1;
    bl_count[bits + 1] += 2;
    bl_count[max] -= 1;
    overflow = overflow.saturating_sub(2);
  }
  // The longest lengths go to the least frequent leaves
  let mut leaf = 0;
  for bits in (1..=max).rev() {
    for _ in 0..bl_count[bits] {
      out[(leaves[leaf] & 0xffff) as usize] = bits as u8;
      leaf += 1;
    }
  }
  bl_count
}

/// Canonical codes (bit-reversed, ready for the LSB-first writer) of `lengths`, which have
/// `bl_count[len]` codes of each length (as [`code_lengths`] returns). The codes of unused symbols
/// (length 0) are left as they were: nothing reads them.
pub(crate) fn canonical_codes(lengths: &[u8], mut bl_count: [u16; 16], codes: &mut [u16]) {
  debug_assert!((1..16).all(|b| lengths.iter().filter(|&&l| usize::from(l) == b).count() == usize::from(bl_count[b])));
  bl_count[0] = 0;
  let mut next = [0u16; 16];
  let mut code = 0u16;
  for bits in 1..16 {
    code = (code + bl_count[bits - 1]) << 1;
    next[bits] = code;
  }
  for (code, &len) in codes.iter_mut().zip(lengths) {
    if len > 0 {
      let slot = &mut next[usize::from(len & 15)];
      *code = reverse_fast(*slot, len);
      *slot += 1;
    }
  }
}
