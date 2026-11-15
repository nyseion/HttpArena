//! The TLS session of a connection as the connection uses it: a [`CryptoSession`] behind the
//! checks and buffers of the in-tree handshake interface.
//!
//! - The encryption level of CRYPTO data is checked here, since sessions take none: data at an
//!   earlier level than TLS reads closes with PROTOCOL_VIOLATION, at a later level or in 1-RTT
//!   packets with the `unexpected_message` alert.
//! - What TLS writes is kept per level ([`ConnTls::output`]); the connection tracks what it sent.
//! - The keys of each level are expanded when the level is reached; those of 1-RTT, which a
//!   server gets with its own Finished, only once the handshake is complete (RFC 9001 section
//!   5.7).

use crate::{
  DirectionalKeys, PacketKeys, QuicError, Space, TransportErrorCode,
  rng::CryptoRng,
  tls::{CryptoSession, KeyChange, KeyPair, KeyUpdater, TlsAlert},
};
use alloc::{boxed::Box, vec::Vec};

const INITIAL_LEVEL: u8 = 0;
const HANDSHAKE_LEVEL: u8 = 1;
const DATA_LEVEL: u8 = 2;

/// The TLS session of a connection.
pub(crate) struct ConnTls {
  failed: bool,
  out_handshake: Vec<u8>,
  out_initial: Vec<u8>,
  pending_data: Option<KeyPair>,
  pending_handshake: Option<KeyPair>,
  read_level: u8,
  seed: [u8; 32],
  session: Box<dyn CryptoSession>,
  updater: Option<Box<dyn KeyUpdater>>,
  write_level: u8,
}

impl core::fmt::Debug for ConnTls {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("ConnTls")
      .field("read_level", &self.read_level)
      .field("write_level", &self.write_level)
      .finish_non_exhaustive()
  }
}

impl ConnTls {
  /// `session`, whose first flight (a client's ClientHello) [`Self::output`] holds at once. The
  /// connection gets a seed of `rng` for its own generator ([`Self::connection_seed`]).
  #[inline]
  pub(crate) fn new<R>(session: Box<dyn CryptoSession>, rng: &mut R) -> crate::Result<Self>
  where
    R: CryptoRng + ?Sized,
  {
    let mut this = Self {
      failed: false,
      out_handshake: Vec::new(),
      out_initial: Vec::new(),
      pending_data: None,
      pending_handshake: None,
      read_level: INITIAL_LEVEL,
      seed: rng.u8_32(),
      session,
      updater: None,
      write_level: INITIAL_LEVEL,
    };
    this.drain_writes()?;
    Ok(this)
  }

  /// A seed for the generator of the connection, given once: zeros after that.
  #[inline]
  pub(crate) fn connection_seed(&mut self) -> crate::Result<[u8; 32]> {
    let seed = self.seed;
    crate::protection::wipe(&mut self.seed);
    Ok(seed)
  }

  /// Takes the CRYPTO data `data` of `space`, in order.
  #[inline]
  pub(crate) fn feed(&mut self, space: Space, data: &[u8]) -> crate::Result<()> {
    if data.is_empty() {
      return Ok(());
    }
    if self.failed {
      return Err(alert(TlsAlert::INTERNAL_ERROR));
    }
    let level = match space {
      Space::Initial => INITIAL_LEVEL,
      Space::Handshake => HANDSHAKE_LEVEL,
      Space::Data => DATA_LEVEL,
    };
    if level < self.read_level {
      self.failed = true;
      return Err(crate::Error::QuicClose(
        TransportErrorCode::ProtocolViolation,
        QuicError::CryptoDataAtWrongLevel,
      ));
    }
    if level > self.read_level || level == DATA_LEVEL {
      self.failed = true;
      return Err(crate::Error::QuicClose(
        TransportErrorCode::Crypto(TlsAlert::UNEXPECTED_MESSAGE.0),
        QuicError::CryptoDataAtWrongLevel,
      ));
    }
    if let Err(err) = self.session.read_handshake(data) {
      self.failed = true;
      return Err(alert(err));
    }
    self.drain_writes()
  }

  /// If the handshake is complete: the Finished of the peer is verified.
  #[inline]
  pub(crate) fn is_complete(&self) -> bool {
    !self.failed && !self.session.is_handshaking()
  }

  /// Everything TLS wrote at the level of `space`, sent or not.
  #[inline]
  pub(crate) fn output(&self, space: Space) -> &[u8] {
    match space {
      Space::Initial => &self.out_initial,
      Space::Handshake => &self.out_handshake,
      Space::Data => &[],
    }
  }

  /// The raw transport parameters of the peer, once received.
  #[inline]
  pub(crate) fn peer_transport_params(&self) -> Option<&[u8]> {
    self.session.peer_transport_params()
  }

  /// The keys of the next level, once they may be used, which must be taken after each
  /// [`Self::feed`]: those of Handshake once the level is reached, those of 1-RTT once the
  /// handshake is complete. The 1-RTT keys have batched header protection if `batched_hp`.
  #[inline]
  pub(crate) fn poll_keys(
    &mut self,
    batched_hp: bool,
  ) -> crate::Result<Option<(Space, PacketKeys)>> {
    if let Some(keys) = self.pending_handshake.take() {
      let local = DirectionalKeys::from_material(&keys.local, false)?;
      let remote = DirectionalKeys::from_material(&keys.remote, false)?;
      return Ok(Some((Space::Handshake, PacketKeys { local, remote })));
    }
    if self.is_complete()
      && let Some(keys) = self.pending_data.take()
    {
      let local = DirectionalKeys::from_material(&keys.local, batched_hp)?;
      let remote = DirectionalKeys::from_material(&keys.remote, batched_hp)?;
      return Ok(Some((Space::Data, PacketKeys { local, remote })));
    }
    Ok(None)
  }

  /// The source of the keys of the 1-RTT key updates, once the 1-RTT keys were given.
  #[inline]
  pub(crate) fn take_updater(&mut self) -> Option<Box<dyn KeyUpdater>> {
    if self.pending_data.is_some() {
      return None;
    }
    self.updater.take()
  }

  // Takes what TLS has to send, at the level it was written at, and the keys of every level
  // change.
  fn drain_writes(&mut self) -> crate::Result<()> {
    loop {
      let mut scratch = Vec::new();
      let buf = match self.write_level {
        INITIAL_LEVEL => &mut self.out_initial,
        HANDSHAKE_LEVEL => &mut self.out_handshake,
        _ => &mut scratch,
      };
      let before = buf.len();
      let change = match self.session.write_handshake(buf) {
        Ok(elem) => elem,
        Err(err) => {
          self.failed = true;
          return Err(alert(err));
        }
      };
      let wrote = buf.len() != before;
      if !scratch.is_empty() {
        // Post-handshake messages (session tickets) are not supported: sessions must not send any
        self.failed = true;
        return Err(alert(TlsAlert::INTERNAL_ERROR));
      }
      match change {
        None => {
          if !wrote {
            return Ok(());
          }
        }
        Some(KeyChange::Handshake { keys }) => {
          if self.write_level != INITIAL_LEVEL {
            self.failed = true;
            return Err(alert(TlsAlert::INTERNAL_ERROR));
          }
          self.pending_handshake = Some(keys);
          self.write_level = HANDSHAKE_LEVEL;
          self.read_level = HANDSHAKE_LEVEL;
        }
        Some(KeyChange::OneRtt { keys, updater }) => {
          if self.write_level != HANDSHAKE_LEVEL {
            self.failed = true;
            return Err(alert(TlsAlert::INTERNAL_ERROR));
          }
          self.pending_data = Some(keys);
          self.updater = Some(updater);
          self.write_level = DATA_LEVEL;
        }
      }
    }
  }
}

fn alert(alert: TlsAlert) -> crate::Error {
  crate::Error::QuicClose(TransportErrorCode::Crypto(alert.0), QuicError::TlsAlert)
}
