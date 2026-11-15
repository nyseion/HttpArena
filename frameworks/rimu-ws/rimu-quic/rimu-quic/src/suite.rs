//! The TLS 1.3 cipher suites that QUIC v1 packets are protected with.

use crate::crypto::hkdf::{self, HkdfHash, Prk};

/// A TLS 1.3 cipher suite (RFC 8446 appendix B.4) that QUIC v1 supports (RFC 9001 section 5.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CipherSuite {
  /// `TLS_AES_128_GCM_SHA256`.
  Aes128GcmSha256,
  /// `TLS_AES_256_GCM_SHA384`.
  Aes256GcmSha384,
  /// `TLS_CHACHA20_POLY1305_SHA256`.
  Chacha20Poly1305Sha256,
}

impl CipherSuite {
  /// Every suite, in the order a server prefers them.
  pub const PRIORITY: [Self; 3] =
    [Self::Aes128GcmSha256, Self::Aes256GcmSha384, Self::Chacha20Poly1305Sha256];

  /// The code point of the suite (IANA TLS Cipher Suites registry).
  #[inline]
  pub const fn iana(self) -> u16 {
    match self {
      Self::Aes128GcmSha256 => 0x1301,
      Self::Aes256GcmSha384 => 0x1302,
      Self::Chacha20Poly1305Sha256 => 0x1303,
    }
  }

  /// The suite of the code point `value`, if it is one of the supported ones.
  #[inline]
  pub const fn from_iana(value: u16) -> Option<Self> {
    match value {
      0x1301 => Some(Self::Aes128GcmSha256),
      0x1302 => Some(Self::Aes256GcmSha384),
      0x1303 => Some(Self::Chacha20Poly1305Sha256),
      _ => None,
    }
  }

  /// The length of the AEAD key (and of the header protection key).
  #[inline]
  pub const fn cipher_key_len(self) -> u8 {
    match self {
      Self::Aes128GcmSha256 => 16,
      Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
    }
  }

  /// The length of the output of the hash, and so of the traffic secrets.
  #[inline]
  pub const fn hash_len(self) -> u8 {
    match self {
      Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => 32,
      Self::Aes256GcmSha384 => 48,
    }
  }

  const fn hkdf_hash(self) -> HkdfHash {
    match self {
      Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => HkdfHash::Sha256,
      Self::Aes256GcmSha384 => HkdfHash::Sha384,
    }
  }

  /// `secret`, a traffic secret of this suite, ready for `HKDF-Expand`.
  #[inline]
  pub(crate) fn hkdf_from_prk(self, secret: &[u8]) -> crate::Result<Prk> {
    hkdf::prk_from_secret(self.hkdf_hash(), secret)
  }

  /// `HKDF-Extract(salt, ikm)` with the hash of this suite.
  #[inline]
  pub(crate) fn hkdf_extract(self, salt: Option<&[u8]>, ikm: &[u8]) -> Prk {
    hkdf::extract(self.hkdf_hash(), salt, ikm)
  }
}
