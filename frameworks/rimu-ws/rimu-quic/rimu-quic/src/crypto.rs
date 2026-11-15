//! The cryptographic primitives of packet protection: AEAD keys ([`AeadKey`]) and header
//! protection keys ([`HpKey`]) bound to a backend (`ring` or `aws-lc-rs`), whose expanded key
//! schedules wipe themselves when dropped, the HKDF of the key schedule and HMAC-SHA-256.

pub use aead_key::{
  AeadKey, AeadKeyDummy,
  global::{Aes128GcmKeyGlobal, Aes256GcmKeyGlobal, Chacha20Poly1305KeyGlobal},
};
#[cfg(all(target_arch = "x86_64", feature = "std"))]
pub(crate) use hp_key::x86_aesni::{Aes128HpAesNi, Aes256HpAesNi, has_aes_ni};
pub use hp_key::{
  HpKey, HpKeyDummy,
  global::{Aes128HpGlobal, Aes256HpGlobal, Chacha20HpGlobal},
};
pub(crate) use quic_aead::QuicAead;

/// The length of the nonce of the AEADs of TLS 1.3 and QUIC.
pub const AEAD_NONCE_LEN: usize = 12;
/// The length of the authentication tag of the AEADs of TLS 1.3 and QUIC.
pub const AEAD_TAG_LEN: usize = 16;
/// The longest output of the hashes of the supported cipher suites (SHA-384).
pub const MAX_HASH_LEN: usize = 48;

/// A failure of a cryptographic primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
  /// An AES-128-GCM key of the wrong length, or a seal or open that failed (authentication).
  InvalidAes128GcmData,
  /// An AES-256-GCM key of the wrong length, or a seal or open that failed (authentication).
  InvalidAes256GcmData,
  /// A ChaCha20-Poly1305 key of the wrong length, or a seal or open that failed (authentication).
  InvalidChacha20Poly1305Data,
  /// A secret or derived output of the wrong length for its hash.
  InvalidHashLength,
  /// A header protection key of the wrong length, or a mask that could not be computed.
  InvalidHeaderProtection,
  /// The backend has no header protection.
  UnsupportedHeaderProtection,
}

impl core::fmt::Display for CryptoError {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    core::fmt::Debug::fmt(self, f)
  }
}

// A call into a backend that is not compiled in.
#[cold]
#[track_caller]
fn dummy_crypto_call() -> ! {
  panic!("no crypto backend: enable the `ring` or `aws-lc-rs` feature of rimu-quic")
}

/// Overwrites `len` bytes at `ptr` with zeros, with volatile writes that the compiler cannot
/// remove.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
#[inline]
pub(crate) unsafe fn zero_volatile(ptr: *mut u8, len: usize) {
  for idx in 0..len {
    // SAFETY: `idx < len` and the caller guarantees that `len` bytes at `ptr` are writable
    unsafe { core::ptr::write_volatile(ptr.add(idx), 0) };
  }
  core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Drops the value and then overwrites with zeros the bytes it occupied, with volatile writes that
/// the compiler cannot remove, so that a key does not outlive its owner in a slot that is reused.
///
/// Only the bytes of the value itself are overwritten, memory that the value owns elsewhere is
/// left to its own destructor.
///
/// # Safety
///
/// The value must not be used or dropped again.
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
#[inline]
pub(crate) unsafe fn drop_and_zero<T>(value: &mut core::mem::ManuallyDrop<T>) {
  // SAFETY: up to the caller
  unsafe { core::mem::ManuallyDrop::drop(value) };
  // The pointer is taken after the drop so that it is not invalidated by it
  let ptr = core::ptr::from_mut(value).cast::<u8>();
  // SAFETY: `ptr` is the place of `value`, which is still allocated and `size_of::<T>()` long
  // (`ManuallyDrop` has the layout of `T`), and nothing reads it as a `T` again
  unsafe { crate::crypto::zero_volatile(ptr, size_of::<T>()) };
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
macro_rules! common_aead_key_functions {
  () => {
    #[inline]
    fn local_new_key(
      algorithm: &'static Algorithm,
      error: CryptoError,
      key: &[u8],
    ) -> crate::Result<LessSafeKey> {
      match UnboundKey::new(algorithm, key) {
        Ok(elem) => Ok(LessSafeKey::new(elem)),
        Err(_err) => {
          core::hint::cold_path();
          Err(error.into())
        }
      }
    }

    #[inline]
    fn local_open_key<'data>(
      aad: &[u8],
      data: &'data mut [u8],
      error: CryptoError,
      key: &LessSafeKey,
      nonce: [u8; AEAD_NONCE_LEN],
    ) -> crate::Result<&'data mut [u8]> {
      key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(error)
      })
    }

    #[inline]
    fn local_seal_key(
      aad: &[u8],
      data: &mut [u8],
      error: CryptoError,
      key: &LessSafeKey,
      nonce: [u8; AEAD_NONCE_LEN],
    ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
      let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), data)
        .map_err(|_err| {
          core::hint::cold_path();
          crate::Error::from(error)
        })?;
      Ok(tag.as_ref().try_into()?)
    }
  };
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
macro_rules! common_hp_key_functions {
  () => {
    #[inline]
    fn local_new_hp(
      algorithm: &'static Algorithm,
      key: &[u8],
    ) -> crate::Result<HeaderProtectionKey> {
      HeaderProtectionKey::new(algorithm, key).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(CryptoError::InvalidHeaderProtection)
      })
    }

    #[inline]
    fn local_mask_hp(key: &HeaderProtectionKey, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
      key.new_mask(sample).map_err(|_err| {
        core::hint::cold_path();
        crate::Error::from(CryptoError::InvalidHeaderProtection)
      })
    }
  };
}

// Wrappers of the keys that QUIC keeps in pooled connection slots: whatever was expanded from the
// key is dropped and then overwritten when the wrapper is dropped, so the next owner of the slot
// cannot read it.
macro_rules! _create_key_wrappers {
  ($(
    $(#[$meta:meta])*
    $name:ident($ty:ty)
  ),* $(,)?) => {
    $(
      /// A wrapper used to generalize third-party dependencies. The bytes of the key are
      /// overwritten with zeros when it is dropped.
      $(#[$meta])*
      pub struct $name(pub(crate) core::mem::ManuallyDrop<$ty>);

      impl $name {
        /// Takes ownership of an already expanded key.
        #[inline]
        pub(crate) fn from_key(value: $ty) -> Self {
          Self(core::mem::ManuallyDrop::new(value))
        }
      }

      impl Drop for $name {
        #[inline]
        fn drop(&mut self) {
          // SAFETY: the field is only dropped here, and `self` is not used after `drop`
          unsafe { crate::crypto::drop_and_zero(&mut self.0) };
        }
      }

      impl core::fmt::Debug for $name {
        #[inline]
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
          f.write_str(stringify!($name))
        }
      }
    )*
  };
}

#[cfg(feature = "aws-lc-rs")]
_create_key_wrappers!(
  Aes128GcmKeyAlr(aws_lc_rs::aead::LessSafeKey),
  Aes256GcmKeyAlr(aws_lc_rs::aead::LessSafeKey),
  Chacha20Poly1305KeyAlr(aws_lc_rs::aead::LessSafeKey),
  Aes128HpAlr(aws_lc_rs::aead::quic::HeaderProtectionKey),
  Aes256HpAlr(aws_lc_rs::aead::quic::HeaderProtectionKey),
  Chacha20HpAlr(aws_lc_rs::aead::quic::HeaderProtectionKey),
);

#[cfg(feature = "ring")]
_create_key_wrappers!(
  Aes128GcmKeyRing(ring::aead::LessSafeKey),
  Aes256GcmKeyRing(ring::aead::LessSafeKey),
  Chacha20Poly1305KeyRing(ring::aead::LessSafeKey),
  Aes128HpRing(ring::aead::quic::HeaderProtectionKey),
  Aes256HpRing(ring::aead::quic::HeaderProtectionKey),
  Chacha20HpRing(ring::aead::quic::HeaderProtectionKey),
);

mod aead_key;
pub(crate) mod hkdf;
mod hp_key;
mod quic_aead;
