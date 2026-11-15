//! Capture (spike-tls.md): the cipher suites of the provider carry a [`CaptureAlg`] as their
//! `quic::Algorithm`. rustls hands it the bytes of every packet key, IV and header protection key
//! that it derives; it records them in a slot of this thread, armed only around the rustls calls
//! that derive keys (`write_hs`, `Secrets::next_packet_keys`), and gives rustls zero-sized dummy
//! keys (a `Box` of a zero-sized type allocates nothing). The session turns the records into
//! [`KeyMaterial`] right after the call.
//!
//! rustls 0.23 derives keys in `write_hs` (local header key, local packet key, remote header key,
//! remote packet key per key change) and in `next_packet_keys` (local, remote), and nowhere else;
//! the tests pin it. A call that yields anything else fails the handshake instead of using wrong
//! keys.

use crate::{
  CipherSuite,
  protection::{SAMPLE_LEN, wipe},
  tls::{IV_LEN, KeyMaterial, KeyPair, MAX_KEY_LEN, TlsAlert},
};
use alloc::boxed::Box;
use core::cell::RefCell;
use rustls::{
  Error as RlsError,
  crypto::cipher::{AeadKey, Iv},
  quic::{self as rq, HeaderProtectionKey, PacketKey, Tag},
};

/// Key material that rustls handed to a [`CaptureAlg`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum Captured {
  /// A header protection key.
  Hp { suite: CipherSuite, key: [u8; MAX_KEY_LEN], len: u8 },
  /// A packet key and its IV.
  Packet { suite: CipherSuite, key: [u8; MAX_KEY_LEN], len: u8, iv: [u8; IV_LEN] },
}

impl Captured {
  fn wipe(&mut self) {
    match self {
      Self::Hp { key, .. } => wipe(key),
      Self::Packet { key, iv, .. } => {
        wipe(key);
        wipe(iv);
      }
    }
  }
}

const SLOT_LEN: usize = 4;

/// What one rustls call derived, in the order it derived it.
#[derive(Debug)]
pub(crate) struct Captures {
  pub(crate) entries: [Option<Captured>; SLOT_LEN],
  pub(crate) len: usize,
  /// Keys derived past [`SLOT_LEN`]: a broken assumption.
  pub(crate) overflow: usize,
}

impl Captures {
  const fn new() -> Self {
    Self { entries: [None; SLOT_LEN], len: 0, overflow: 0 }
  }

  /// The records, in order.
  #[cfg(test)]
  pub(crate) fn as_slice(&self) -> &[Option<Captured>] {
    self.entries.get(..self.len).unwrap_or_default()
  }

  /// The key pair of a level, from the four records of one key change: local header key, local
  /// packet key, remote header key, remote packet key.
  pub(crate) fn level_keys(&self) -> Result<KeyPair, TlsAlert> {
    let [Some(lh), Some(lp), Some(rh), Some(rp)] = self.entries else {
      return Err(TlsAlert::INTERNAL_ERROR);
    };
    if self.len != 4 || self.overflow != 0 {
      return Err(TlsAlert::INTERNAL_ERROR);
    }
    Ok(KeyPair { local: material(Some(lh), lp)?, remote: material(Some(rh), rp)? })
  }

  /// The key pair of a key update, from the two records of `next_packet_keys`: local, remote.
  pub(crate) fn update_keys(&self) -> Result<KeyPair, TlsAlert> {
    let [Some(lp), Some(rp), None, None] = self.entries else {
      return Err(TlsAlert::INTERNAL_ERROR);
    };
    if self.len != 2 || self.overflow != 0 {
      return Err(TlsAlert::INTERNAL_ERROR);
    }
    Ok(KeyPair { local: material(None, lp)?, remote: material(None, rp)? })
  }
}

impl Drop for Captures {
  fn drop(&mut self) {
    for elem in self.entries.iter_mut().flatten() {
      elem.wipe();
    }
  }
}

fn material(hp: Option<Captured>, packet: Captured) -> Result<KeyMaterial, TlsAlert> {
  let Captured::Packet { suite, key, len, iv } = packet else {
    return Err(TlsAlert::INTERNAL_ERROR);
  };
  let key = key.get(..usize::from(len)).unwrap_or_default();
  match hp {
    None => KeyMaterial::new(suite, key, &iv, None),
    Some(Captured::Hp { suite: hp_suite, key: hp_key, len: hp_len }) if hp_suite == suite => {
      KeyMaterial::new(suite, key, &iv, Some(hp_key.get(..usize::from(hp_len)).unwrap_or_default()))
    }
    Some(_) => Err(TlsAlert::INTERNAL_ERROR),
  }
}

struct Slot {
  armed: bool,
  captures: Captures,
  // Keys derived while the slot was not armed: a broken assumption too
  stray: usize,
}

std::thread_local! {
  static SLOT: RefCell<Slot> =
    const { RefCell::new(Slot { armed: false, captures: Captures::new(), stray: 0 }) };
}

/// Runs `f`, a rustls call, with the slot armed and returns what it derived.
pub(crate) fn capture<R>(f: impl FnOnce() -> R) -> (R, Captures) {
  SLOT.with(|el| {
    let mut slot = el.borrow_mut();
    slot.armed = true;
    slot.captures = Captures::new();
  });
  let rslt = f();
  let captures = SLOT.with(|el| {
    let mut slot = el.borrow_mut();
    slot.armed = false;
    core::mem::replace(&mut slot.captures, Captures::new())
  });
  (rslt, captures)
}

/// Keys derived outside of [`capture`] on this thread since it started.
#[cfg(test)]
pub(crate) fn stray_captures() -> usize {
  SLOT.with(|el| el.borrow().stray)
}

fn record(elem: Captured) {
  SLOT.with(|el| {
    let mut slot = el.borrow_mut();
    if !slot.armed {
      slot.stray = slot.stray.wrapping_add(1);
      return;
    }
    let captures = &mut slot.captures;
    match captures.entries.get_mut(captures.len) {
      Some(dst) => {
        *dst = Some(elem);
        captures.len = captures.len.wrapping_add(1);
      }
      None => captures.overflow = captures.overflow.wrapping_add(1),
    }
  });
}

fn copy_key(bytes: &[u8]) -> ([u8; MAX_KEY_LEN], u8) {
  let mut key = [0; MAX_KEY_LEN];
  let len = bytes.len().min(MAX_KEY_LEN);
  key.get_mut(..len).unwrap_or_default().copy_from_slice(bytes.get(..len).unwrap_or_default());
  (key, u8::try_from(len).unwrap_or(0))
}

/// The `quic::Algorithm` of Capture: records the keys, then gives rustls dummy keys, or, with
/// `delegate` (tests), the keys of the provider's own algorithm.
pub(crate) struct CaptureAlg {
  pub(crate) delegate: bool,
  pub(crate) inner: &'static dyn rq::Algorithm,
  pub(crate) suite: CipherSuite,
}

impl rq::Algorithm for CaptureAlg {
  fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
    let (bytes, len) = copy_key(key.as_ref());
    let mut iv_bytes = [0; IV_LEN];
    for (dst, src) in iv_bytes.iter_mut().zip(iv.as_ref()) {
      *dst = *src;
    }
    record(Captured::Packet { suite: self.suite, key: bytes, len, iv: iv_bytes });
    if self.delegate { self.inner.packet_key(key, iv) } else { Box::new(NullKey) }
  }

  fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
    let (bytes, len) = copy_key(key.as_ref());
    record(Captured::Hp { suite: self.suite, key: bytes, len });
    if self.delegate { self.inner.header_protection_key(key) } else { Box::new(NullKey) }
  }

  fn aead_key_len(&self) -> usize {
    self.inner.aead_key_len()
  }

  fn fips(&self) -> bool {
    self.inner.fips()
  }
}

/// The zero-sized keys that Capture gives rustls, which are never used.
struct NullKey;

impl PacketKey for NullKey {
  fn encrypt_in_place(&self, _: u64, _: &[u8], _: &mut [u8]) -> Result<Tag, RlsError> {
    Err(RlsError::EncryptError)
  }

  fn decrypt_in_place<'a>(&self, _: u64, _: &[u8], _: &'a mut [u8]) -> Result<&'a [u8], RlsError> {
    Err(RlsError::DecryptError)
  }

  fn tag_len(&self) -> usize {
    crate::crypto::AEAD_TAG_LEN
  }

  fn confidentiality_limit(&self) -> u64 {
    0
  }

  fn integrity_limit(&self) -> u64 {
    0
  }
}

impl HeaderProtectionKey for NullKey {
  fn encrypt_in_place(&self, _: &[u8], _: &mut u8, _: &mut [u8]) -> Result<(), RlsError> {
    Err(RlsError::EncryptError)
  }

  fn decrypt_in_place(&self, _: &[u8], _: &mut u8, _: &mut [u8]) -> Result<(), RlsError> {
    Err(RlsError::DecryptError)
  }

  fn sample_len(&self) -> usize {
    SAMPLE_LEN
  }
}
