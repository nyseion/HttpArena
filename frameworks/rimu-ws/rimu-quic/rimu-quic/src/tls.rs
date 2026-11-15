//! The interface between the transport and TLS 1.3 (RFC 9001 section 4).
//!
//! The connection talks to TLS through [`CryptoSession`] only, so the core does not depend on any
//! TLS library; the `rustls` feature provides an implementation on rustls's QUIC API
//! ([`crate::rustls`]). A session hands over the **key material** of each encryption level
//! ([`KeyMaterial`]: packet key, IV, header protection key), from which the connection expands its
//! own keys once: the per-packet path calls no TLS code and no `dyn` method.
//!
//! What a session must do:
//!
//! - [`CryptoSession::read_handshake`] takes the CRYPTO data of the peer, in order. The connection
//!   checks the encryption level of the data itself (data at an earlier level than TLS reads is a
//!   PROTOCOL_VIOLATION, at a later level or in 1-RTT packets an `unexpected_message` alert).
//! - [`CryptoSession::write_handshake`] appends what TLS has to send and returns a
//!   [`KeyChange`] when the keys of the next level are ready; the bytes written before a change
//!   belong to the previous level, so the connection calls it until it writes nothing and returns
//!   no change. A server gets the Handshake and the 1-RTT keys from the same ClientHello; the
//!   connection uses the 1-RTT keys only once [`CryptoSession::is_handshaking`] is `false` (RFC
//!   9001 section 5.7).
//! - The 1-RTT change carries a [`KeyUpdater`], which the connection keeps after it drops the
//!   session at the end of the handshake, for key updates (RFC 9001 section 6).
//! - Nothing is sent in 1-RTT CRYPTO frames: a session must not send session tickets (the
//!   connection closes with INTERNAL_ERROR if it writes after the 1-RTT keys). Resumption and
//!   0-RTT are not supported.

use crate::{CipherSuite, crypto::MAX_HASH_LEN, protection::wipe};
use alloc::{boxed::Box, vec::Vec};

/// The longest packet or header protection key (AES-256, ChaCha20).
pub const MAX_KEY_LEN: usize = 32;
/// The length of a packet protection IV.
pub const IV_LEN: usize = 12;

/// A TLS alert (RFC 8446 section 6): a failed handshake closes the connection with the
/// CRYPTO_ERROR `0x100 + alert` (RFC 9001 section 4.8).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsAlert(pub u8);

impl TlsAlert {
  /// `unexpected_message`.
  pub const UNEXPECTED_MESSAGE: Self = Self(10);
  /// `handshake_failure`.
  pub const HANDSHAKE_FAILURE: Self = Self(40);
  /// `internal_error`.
  pub const INTERNAL_ERROR: Self = Self(80);
  /// `missing_extension`.
  pub const MISSING_EXTENSION: Self = Self(109);
  /// `no_application_protocol`.
  pub const NO_APPLICATION_PROTOCOL: Self = Self(120);
}

/// The key material of one direction of an encryption level, as TLS derived it (RFC 9001 section
/// 5.1): the AEAD key, the IV and the header protection key. Wiped when dropped.
pub struct KeyMaterial {
  suite: CipherSuite,
  key: [u8; MAX_KEY_LEN],
  iv: [u8; IV_LEN],
  hp: [u8; MAX_KEY_LEN],
  has_hp: bool,
}

impl KeyMaterial {
  /// Material of `suite`: `key` and, if given, `hp` must have the key length of the suite.
  /// Material of a key update has no header protection key (it does not change, RFC 9001
  /// section 6).
  #[inline]
  pub fn new(
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8; IV_LEN],
    hp: Option<&[u8]>,
  ) -> Result<Self, TlsAlert> {
    let key_len = usize::from(suite.cipher_key_len());
    if key.len() != key_len || hp.is_some_and(|el| el.len() != key_len) {
      return Err(TlsAlert::INTERNAL_ERROR);
    }
    let mut this =
      Self { suite, key: [0; MAX_KEY_LEN], iv: *iv, hp: [0; MAX_KEY_LEN], has_hp: hp.is_some() };
    this.key.get_mut(..key_len).unwrap_or_default().copy_from_slice(key);
    if let Some(elem) = hp {
      this.hp.get_mut(..key_len).unwrap_or_default().copy_from_slice(elem);
    }
    Ok(this)
  }

  /// The cipher suite.
  #[inline]
  pub const fn suite(&self) -> CipherSuite {
    self.suite
  }

  /// The AEAD key.
  #[inline]
  pub fn key(&self) -> &[u8] {
    self.key.get(..usize::from(self.suite.cipher_key_len())).unwrap_or_default()
  }

  /// The IV.
  #[inline]
  pub const fn iv(&self) -> &[u8; IV_LEN] {
    &self.iv
  }

  /// The header protection key, if this is not the material of a key update.
  #[inline]
  pub fn hp(&self) -> Option<&[u8]> {
    if !self.has_hp {
      return None;
    }
    self.hp.get(..usize::from(self.suite.cipher_key_len()))
  }
}

impl core::fmt::Debug for KeyMaterial {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("KeyMaterial").field("suite", &self.suite).finish_non_exhaustive()
  }
}

impl Drop for KeyMaterial {
  #[inline]
  fn drop(&mut self) {
    wipe(&mut self.key);
    wipe(&mut self.iv);
    wipe(&mut self.hp);
  }
}

/// The key material of both directions of an encryption level.
#[derive(Debug)]
pub struct KeyPair {
  /// Protects what this endpoint sends.
  pub local: KeyMaterial,
  /// Opens what this endpoint receives.
  pub remote: KeyMaterial,
}

/// The keys of the next encryption level, ready.
pub enum KeyChange {
  /// The keys of the Handshake packets.
  Handshake {
    /// Both directions.
    keys: KeyPair,
  },
  /// The keys of the 1-RTT packets, and where the keys of the next key phases come from.
  OneRtt {
    /// Both directions.
    keys: KeyPair,
    /// The keys of the key updates.
    updater: Box<dyn KeyUpdater>,
  },
}

impl core::fmt::Debug for KeyChange {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::Handshake { keys } => f.debug_struct("Handshake").field("keys", keys).finish(),
      Self::OneRtt { keys, .. } => f.debug_struct("OneRtt").field("keys", keys).finish(),
    }
  }
}

/// The keys of the next 1-RTT key phase (RFC 9001 section 6).
pub trait KeyUpdater: Send {
  /// The key material of the next key phase, both directions, without header protection keys.
  /// The connection advances its two directions at different times and keeps the other half.
  fn next_keys(&mut self) -> Result<KeyPair, TlsAlert>;
}

/// The TLS 1.3 handshake of a connection, carried in CRYPTO frames.
pub trait CryptoSession: Send {
  /// Takes CRYPTO data of the peer, in order. On failure the connection closes with the alert.
  fn read_handshake(&mut self, data: &[u8]) -> Result<(), TlsAlert>;

  /// Appends to `out` what TLS has to send at the current level, and returns a change when the
  /// keys of the next level are ready (the bytes written so far belong to the level before it).
  fn write_handshake(&mut self, out: &mut Vec<u8>) -> Result<Option<KeyChange>, TlsAlert>;

  /// The raw transport parameters of the peer, once received.
  fn peer_transport_params(&self) -> Option<&[u8]>;

  /// The negotiated application protocol, once known.
  fn alpn(&self) -> Option<&[u8]>;

  /// If the handshake is still under way: `false` once the Finished of the peer is verified.
  fn is_handshaking(&self) -> bool;
}

/// Makes the TLS session of each new server connection.
pub trait ServerSessionFactory: Send + Sync {
  /// A session that sends `local_transport_params`, the encoded transport parameters of the
  /// server, in its `quic_transport_parameters` extension.
  fn new_session(&self, local_transport_params: &[u8]) -> Result<Box<dyn CryptoSession>, TlsAlert>;
}

/// A [`KeyUpdater`] for sessions that expose their 1-RTT traffic secrets: each key phase derives
/// the next secret with the label `quic ku` (RFC 9001 section 6.1), and its key and IV.
pub struct SecretKeyUpdater {
  local: [u8; MAX_HASH_LEN],
  remote: [u8; MAX_HASH_LEN],
  suite: CipherSuite,
}

impl SecretKeyUpdater {
  /// An updater from the current 1-RTT traffic secrets of each direction, of the length of the
  /// hash of `suite`.
  #[inline]
  pub fn new(suite: CipherSuite, local: &[u8], remote: &[u8]) -> Result<Self, TlsAlert> {
    let len = usize::from(suite.hash_len());
    if local.len() != len || remote.len() != len {
      return Err(TlsAlert::INTERNAL_ERROR);
    }
    let mut this = Self { local: [0; MAX_HASH_LEN], remote: [0; MAX_HASH_LEN], suite };
    this.local.get_mut(..len).unwrap_or_default().copy_from_slice(local);
    this.remote.get_mut(..len).unwrap_or_default().copy_from_slice(remote);
    Ok(this)
  }

  fn advance(suite: CipherSuite, secret: &mut [u8; MAX_HASH_LEN]) -> crate::Result<KeyMaterial> {
    let len = usize::from(suite.hash_len());
    let current = secret.get(..len).unwrap_or_default();
    let next = crate::protection::next_secret(suite, current)?;
    secret.get_mut(..len).unwrap_or_default().copy_from_slice(next.as_slice());
    crate::protection::material_from_secret(suite, next.as_slice(), false)
  }
}

impl KeyUpdater for SecretKeyUpdater {
  #[inline]
  fn next_keys(&mut self) -> Result<KeyPair, TlsAlert> {
    let local = Self::advance(self.suite, &mut self.local).map_err(|_| TlsAlert::INTERNAL_ERROR)?;
    let remote =
      Self::advance(self.suite, &mut self.remote).map_err(|_| TlsAlert::INTERNAL_ERROR)?;
    Ok(KeyPair { local, remote })
  }
}

impl core::fmt::Debug for SecretKeyUpdater {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("SecretKeyUpdater").field("suite", &self.suite).finish_non_exhaustive()
  }
}

impl Drop for SecretKeyUpdater {
  #[inline]
  fn drop(&mut self) {
    wipe(&mut self.local);
    wipe(&mut self.remote);
  }
}
