//! HKDF (RFC 5869) with the `HKDF-Expand-Label` of TLS 1.3 (RFC 8446 section 7.1), which QUIC
//! uses for its Initial secrets and its packet protection keys (RFC 9001 section 5), and
//! HMAC-SHA-256, which signs stateless reset tokens.

use crate::{ArrayBytes, crypto::CryptoError};
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs as backend;
#[cfg(feature = "ring")]
use ring as backend;

/// The hash of an HKDF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HkdfHash {
  Sha256,
  Sha384,
}

impl HkdfHash {
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  const fn len(self) -> usize {
    match self {
      Self::Sha256 => 32,
      Self::Sha384 => 48,
    }
  }

  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  fn algorithm(self) -> backend::hkdf::Algorithm {
    match self {
      Self::Sha256 => backend::hkdf::HKDF_SHA256,
      Self::Sha384 => backend::hkdf::HKDF_SHA384,
    }
  }
}

/// A pseudorandom key: a secret ready for `HKDF-Expand`.
pub(crate) struct Prk {
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  inner: backend::hkdf::Prk,
}

impl core::fmt::Debug for Prk {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("Prk")
  }
}

/// `secret`, which is already pseudorandom (a traffic secret), as a [`Prk`].
#[inline]
pub(crate) fn prk_from_secret(hash: HkdfHash, secret: &[u8]) -> crate::Result<Prk> {
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  {
    Ok(Prk { inner: backend::hkdf::Prk::new_less_safe(hash.algorithm(), secret) })
  }
  #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
  {
    let _ = (hash, secret);
    super::dummy_crypto_call()
  }
}

/// `HKDF-Extract(salt, ikm)`; a missing salt is a string of zeros of the length of the hash.
#[inline]
pub(crate) fn extract(hash: HkdfHash, salt: Option<&[u8]>, ikm: &[u8]) -> Prk {
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  {
    let zeros = [0u8; super::MAX_HASH_LEN];
    let salt = salt.unwrap_or_else(|| zeros.get(..hash.len()).unwrap_or_default());
    Prk { inner: backend::hkdf::Salt::new(hash.algorithm(), salt).extract(ikm) }
  }
  #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
  {
    let _ = (hash, salt, ikm);
    super::dummy_crypto_call()
  }
}

// The length that `HKDF-Expand` writes.
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
struct OutLen(usize);

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
impl backend::hkdf::KeyType for OutLen {
  fn len(&self) -> usize {
    self.0
  }
}

// "tls13 " and the longest label of QUIC ("client in", "server in", "quic key", ...).
const MAX_LABEL_LEN: usize = 6 + 16;

/// `HKDF-Expand-Label(prk, label, context, len)` of TLS 1.3: `len` bytes, at most `N`.
#[inline]
pub(crate) fn hkdf_expand_label<const N: usize>(
  context: Option<&[u8]>,
  label: &[u8],
  len: u8,
  prk: &Prk,
) -> crate::Result<ArrayBytes<N>> {
  let context = context.unwrap_or_default();
  let out_len = usize::from(len);
  if out_len > N || label.len() > MAX_LABEL_LEN - 6 || context.len() > usize::from(u8::MAX) {
    core::hint::cold_path();
    return Err(CryptoError::InvalidHashLength.into());
  }
  // struct HkdfLabel { uint16 length; opaque label<7..255>; opaque context<0..255> }
  let full_label_len = 6usize.wrapping_add(label.len());
  let [len_hi, len_lo] = u16::from(len).to_be_bytes();
  let info: [&[u8]; 6] = [
    &[len_hi, len_lo],
    &[u8::try_from(full_label_len).unwrap_or(u8::MAX)],
    b"tls13 ",
    label,
    &[u8::try_from(context.len()).unwrap_or(u8::MAX)],
    context,
  ];
  let mut out = ArrayBytes::<N>::zeroed(out_len)?;
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  {
    let okm = prk.inner.expand(&info, OutLen(out_len)).map_err(|_err| {
      core::hint::cold_path();
      crate::Error::from(CryptoError::InvalidHashLength)
    })?;
    okm.fill(out.as_slice_mut()).map_err(|_err| {
      core::hint::cold_path();
      crate::Error::from(CryptoError::InvalidHashLength)
    })?;
  }
  #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
  {
    let _ = (prk, info);
    super::dummy_crypto_call()
  }
  Ok(out)
}

/// HMAC-SHA-256 (RFC 2104) over the data given to [`HmacSha256::update`].
pub(crate) struct HmacSha256 {
  #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
  ctx: backend::hmac::Context,
}

impl HmacSha256 {
  /// A MAC keyed with `key`.
  #[inline]
  pub(crate) fn from_key(key: &[u8]) -> crate::Result<Self> {
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    {
      let key = backend::hmac::Key::new(backend::hmac::HMAC_SHA256, key);
      Ok(Self { ctx: backend::hmac::Context::with_key(&key) })
    }
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    {
      let _ = key;
      super::dummy_crypto_call()
    }
  }

  /// Adds `data` to the message.
  #[inline]
  pub(crate) fn update(&mut self, data: &[u8]) {
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    self.ctx.update(data);
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    let _ = data;
  }

  /// The MAC of the message.
  #[inline]
  pub(crate) fn finalize(self) -> [u8; 32] {
    let mut out = [0; 32];
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    {
      let tag = self.ctx.sign();
      for (dst, src) in out.iter_mut().zip(tag.as_ref()) {
        *dst = *src;
      }
    }
    out
  }
}
