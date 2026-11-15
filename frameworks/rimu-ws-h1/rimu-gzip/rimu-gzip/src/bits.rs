//! DEFLATE's LSB-first bit stream, written into the spare capacity of a byte vector.

use alloc::vec::Vec;

/// Bytes of spare capacity every flush needs: it stores a whole 64-bit word.
const SLACK: usize = 8;

/// Writes DEFLATE's LSB-first bit stream into a byte vector: a 64-bit accumulator flushed four
/// bytes at a time, so a `put` of up to 32 bits never overflows it.
///
/// The vector's pointer, length and capacity live in the writer while it writes, so that the
/// stores of the output do not make the compiler reload them; the vector's length is brought up
/// to date by [`Self::finish`]. The output grows when it must (a cold path), so no caller-side
/// bound is trusted for memory safety.
pub(crate) struct BitWriter<'out> {
  /// The accumulator: bits not yet stored, from the least significant.
  acc: u64,
  /// Bits in the accumulator.
  bits: u32,
  /// The vector's buffer.
  ptr: *mut u8,
  /// Bytes written, counted from the start of the vector's buffer.
  len: usize,
  /// The vector's capacity.
  cap: usize,
  /// The output; its length is brought up to date by `finish` (and `grow`).
  out: &'out mut Vec<u8>,
}

impl<'out> BitWriter<'out> {
  /// A writer appending to `out`, which it first lets grow by at least `reserve` bytes.
  pub(crate) fn new(out: &'out mut Vec<u8>, reserve: usize) -> Self {
    out.reserve(reserve.saturating_add(SLACK));
    Self { acc: 0, bits: 0, ptr: out.as_mut_ptr(), len: out.len(), cap: out.capacity(), out }
  }

  /// Bits written so far, counting those still in the accumulator.
  pub(crate) fn position(&self) -> u64 {
    (self.len as u64).wrapping_mul(8).wrapping_add(self.bits.into())
  }

  /// Makes room for `n` more bytes plus the slack of a flush.
  #[cold]
  #[inline(never)]
  fn grow(&mut self, n: usize) {
    // SAFETY: the first `self.len` bytes of the buffer are initialized: they were either the
    // vector's or written by this writer.
    unsafe { self.out.set_len(self.len) };
    self.out.reserve(n.saturating_add(SLACK));
    self.ptr = self.out.as_mut_ptr();
    self.cap = self.out.capacity();
  }

  /// Appends the low `n` bits of `value` (`n` ≤ 32, higher bits of `value` zero).
  #[inline(always)]
  pub(crate) fn put(&mut self, value: u32, n: u32) {
    debug_assert!(n <= 32 && (n == 32 || value >> n == 0));
    self.acc |= u64::from(value) << self.bits;
    self.bits += n;
    if self.bits >= 32 {
      if self.cap - self.len < SLACK {
        self.grow(SLACK);
      }
      // SAFETY: `len + SLACK <= cap`, so the 8 bytes stored lie in the vector's allocation;
      // `write_unaligned` has no alignment requirement.
      unsafe { self.ptr.add(self.len).cast::<u64>().write_unaligned(self.acc.to_le()) };
      self.len += 4;
      self.acc >>= 32;
      self.bits -= 32;
    }
  }

  /// Makes sure `bytes` more bytes (plus the slack of a flush) fit without growing, for a run of
  /// [`Local::put_unflushed`] and [`Local::flush`] calls writing at most that many.
  #[inline(always)]
  pub(crate) fn ensure(&mut self, bytes: usize) {
    if self.cap - self.len < bytes + SLACK {
      self.grow(bytes);
    }
  }

  /// The writer's state as a value, for a hot loop: kept in locals, it stays in registers, as
  /// the stores of the output cannot alias it. Hand it back with [`Self::restore`].
  #[inline(always)]
  pub(crate) fn local(&self) -> Local {
    Local { acc: self.acc, bits: self.bits, ptr: self.ptr, len: self.len, cap: self.cap }
  }

  /// Takes back the state [`Self::local`] lent.
  #[inline(always)]
  pub(crate) fn restore(&mut self, local: Local) {
    debug_assert!(local.ptr == self.ptr && local.cap == self.cap);
    (self.acc, self.bits, self.len) = (local.acc, local.bits, local.len);
  }

  /// Pads with zero bits to the next byte boundary and moves every whole byte to the output.
  pub(crate) fn align(&mut self) {
    let pad = (8 - self.bits % 8) % 8;
    self.bits += pad;
    if self.cap - self.len < SLACK {
      self.grow(SLACK);
    }
    // SAFETY: as in `put`: `len + SLACK <= cap`.
    unsafe { self.ptr.add(self.len).cast::<u64>().write_unaligned(self.acc.to_le()) };
    self.len += (self.bits / 8) as usize;
    self.acc = 0;
    self.bits = 0;
  }

  /// Bytes appended unaligned to the output; the stream must be byte-aligned.
  pub(crate) fn bytes(&mut self, bytes: &[u8]) {
    debug_assert_eq!(self.bits, 0);
    if self.cap - self.len < bytes.len() + SLACK {
      self.grow(bytes.len());
    }
    // SAFETY: `len + bytes.len() <= cap`; `bytes` is borrowed separately from the vector the
    // writer holds exclusively, so the two do not overlap.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.len), bytes.len()) };
    self.len += bytes.len();
  }

  /// Pads the last byte and returns the output.
  pub(crate) fn finish(mut self) -> &'out mut Vec<u8> {
    self.align();
    // SAFETY: every byte below `self.len` was initialized by the vector or by this writer, and
    // `self.len <= self.cap`.
    unsafe { self.out.set_len(self.len) };
    self.out
  }
}

/// A [`BitWriter`]'s state lent to a hot loop (see [`BitWriter::local`]): it cannot grow the
/// output, so every flush checks its room in debug builds.
pub(crate) struct Local {
  /// The accumulator: bits not yet stored, from the least significant.
  acc: u64,
  /// Bits in the accumulator.
  bits: u32,
  /// The vector's buffer.
  ptr: *mut u8,
  /// Bytes written, counted from the start of the vector's buffer.
  len: usize,
  /// The vector's capacity.
  cap: usize,
}

impl Local {
  /// Adds the low `n` bits of `value` to the accumulator without flushing it: the accumulator
  /// must have room (`bits + n <= 64`).
  #[inline(always)]
  pub(crate) fn put_unflushed(&mut self, value: u64, n: u32) {
    debug_assert!(self.bits + n <= 64 && (n == 64 || value >> n == 0));
    self.acc |= value << self.bits;
    self.bits += n;
  }

  /// Moves the accumulator's whole bytes to the output, leaving at most 7 bits. Room for the
  /// store — 8 bytes, of which `bits / 8` become the output's — must have been made with
  /// [`BitWriter::ensure`]: a whole block of known size gets its room once, so a check on every
  /// flush would only re-verify what the writer already proved, while keeping the capacity in a
  /// register for the whole loop (the spills cost more than the check). Checked in debug builds.
  ///
  /// The accumulator must hold fewer than 64 bits: a full one cannot be shifted out in one step,
  /// and the callers — which always flush down to at most 7 first — never build one.
  #[inline(always)]
  pub(crate) fn flush(&mut self) {
    debug_assert!(self.bits < 64, "a full accumulator cannot be flushed");
    debug_assert!(self.cap - self.len >= SLACK, "BitWriter::ensure was not called");
    // SAFETY: the writer this state came from ensured the whole block fits, with margin for the
    // store's overshoot past the bytes it advances.
    unsafe { self.ptr.add(self.len).cast::<u64>().write_unaligned(self.acc.to_le()) };
    let bytes = self.bits / 8;
    self.len += bytes as usize;
    self.acc >>= bytes * 8;
    self.bits -= bytes * 8;
  }
}
