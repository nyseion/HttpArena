//! A byte array with a length: key material of a size known up to a bound, kept inline.

use crate::crypto::CryptoError;

/// Up to `N` bytes inline, of which the first `len` are used.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ArrayBytes<const N: usize> {
  bytes: [u8; N],
  len: u8,
}

impl<const N: usize> ArrayBytes<N> {
  /// No bytes.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { bytes: [0; N], len: 0 }
  }

  /// `len` zeros; fails past `N`.
  #[inline]
  pub(crate) fn zeroed(len: usize) -> crate::Result<Self> {
    match u8::try_from(len) {
      Ok(elem) if len <= N => Ok(Self { bytes: [0; N], len: elem }),
      _ => {
        core::hint::cold_path();
        Err(CryptoError::InvalidHashLength.into())
      }
    }
  }

  /// A copy of `slice`; fails if it is longer than `N`.
  #[inline]
  pub(crate) fn from_copyable_slice(slice: &[u8]) -> crate::Result<Self> {
    let mut this = Self::zeroed(slice.len())?;
    this.as_slice_mut().copy_from_slice(slice);
    Ok(this)
  }

  /// The bytes in use.
  #[inline]
  pub(crate) fn as_slice(&self) -> &[u8] {
    self.bytes.get(..usize::from(self.len)).unwrap_or_default()
  }

  /// The bytes in use.
  #[inline]
  pub(crate) fn as_slice_mut(&mut self) -> &mut [u8] {
    self.bytes.get_mut(..usize::from(self.len)).unwrap_or_default()
  }

  /// The number of bytes in use.
  #[cfg(test)]
  pub(crate) const fn len(&self) -> u8 {
    self.len
  }

  /// A pointer to the bytes.
  #[cfg(test)]
  pub(crate) const fn as_ptr(&self) -> *const u8 {
    self.bytes.as_ptr()
  }
}

impl<const N: usize> Default for ArrayBytes<N> {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl<const N: usize> core::fmt::Debug for ArrayBytes<N> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("ArrayBytes").field("len", &self.len).finish_non_exhaustive()
  }
}
