//! Key updates of the 1-RTT keys (RFC 9001 section 6): which generation of the keys opens a
//! packet, the second slot of the keys that open packets, when this endpoint updates the keys that
//! seal them, and the confidentiality and integrity limits of the cipher suites (RFC 9001 section
//! 6.6). The connection ([`crate::conn`]) holds a [`KeyPhase`] next to the keys of its 1-RTT
//! space.

use crate::{
  CipherSuite, DirectionalKeys, PacketKeys, QuicError, TransportErrorCode,
  pools::QuicPools,
  tls::{KeyMaterial, KeyUpdater},
};
use alloc::boxed::Box;

// The confidentiality limit of AES-GCM, in packets sealed with one key (RFC 9001 section 6.6)
const AES_GCM_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
// The integrity limits, in packets that fail to open over the connection (RFC 9001 section 6.6)
const AES_GCM_INTEGRITY_LIMIT: u64 = 1 << 52;
const CHACHA20_INTEGRITY_LIMIT: u64 = 1 << 36;
// PTOs between the acknowledgment of a key update and the next one that this endpoint starts
const KEY_UPDATE_WAIT_PTOS: u64 = 4;

/// The second slot of the keys that open 1-RTT packets: the generation before or after the one
/// of the slot of the space during a key update (RFC 9001 section 6, ruling T9-b). It comes from
/// the pools of the worker and goes back, emptied, once the connection is closed.
#[derive(Debug)]
pub(crate) struct KeySlot {
  remote: Option<DirectionalKeys>,
}

// The generation of the 1-RTT keys that opens a packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Generation {
  Current,
  Previous,
  Next,
}

// What the slot that does not hold the current keys that open packets holds
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OtherKeys {
  // Nothing, before the first key update
  None,
  // The previous generation, until `KeyPhase::previous_until_us`
  Previous,
  // The next generation, made before it is needed
  Next,
}

// Key updates of the 1-RTT keys (RFC 9001 section 6). The keys that open packets are in two slots,
// the one of the space and a box from the pools, and which one is current alternates with the key
// phase, so that a flip moves no key (ruling T9-b). The keys that seal packets advance in place.
#[derive(Debug)]
pub(crate) struct KeyPhase {
  // If the current keys that open packets are in `slot`, not in the slot of the space
  pub(crate) current_in_slot: bool,
  // A packet sealed with the current keys was acknowledged: a new update can start, three PTOs
  // after `local_acked_us` if the keys were updated before
  pub(crate) local_acked: bool,
  pub(crate) local_acked_us: u64,
  // The first packet number sealed with the current keys
  pub(crate) local_first_pn: u64,
  // The key phase of the packets that are sent
  pub(crate) local_phase: bool,
  pub(crate) other: OtherKeys,
  pub(crate) previous_until_us: u64,
  // The first packet number that the current keys opened
  pub(crate) remote_first_pn: u64,
  // The key phase of the packets that the current keys open
  pub(crate) remote_phase: bool,
  pub(crate) slot: Option<Box<KeySlot>>,
  // Where the keys of the next generations come from, once the handshake is over
  // (boxed: the connection stays within 4 KiB; one allocation per handshake)
  pub(crate) updater: Option<Box<KeyUpdate>>,
}

/// The key material of the key updates (RFC 9001 section 6): TLS derives both directions of a
/// generation at once, while the connection advances the keys that seal packets and those that
/// open them at different times (at most one generation apart), so the half that is not used yet
/// waits here.
pub(crate) struct KeyUpdate {
  // Generations derived by `source`
  generated: u32,
  // Generations taken by each direction
  local_taken: u32,
  remote_taken: u32,
  // The half of generation `generated` that its direction did not take yet
  pending_local: Option<KeyMaterial>,
  pending_remote: Option<KeyMaterial>,
  source: Box<dyn KeyUpdater>,
}

impl KeyUpdate {
  pub(crate) fn new(source: Box<dyn KeyUpdater>) -> Self {
    Self {
      generated: 0,
      local_taken: 0,
      remote_taken: 0,
      pending_local: None,
      pending_remote: None,
      source,
    }
  }

  // The key material of the next generation of the keys that seal (`local`) or open packets.
  fn next(&mut self, local: bool) -> crate::Result<KeyMaterial> {
    let (taken, other_taken) = if local {
      (self.local_taken, self.remote_taken)
    } else {
      (self.remote_taken, self.local_taken)
    };
    if taken < self.generated {
      let pending = if local { &mut self.pending_local } else { &mut self.pending_remote };
      let Some(material) = pending.take() else {
        return Err(update_failed());
      };
      self.bump(local);
      return Ok(material);
    }
    // The other direction must have taken its half of the generation before a new one is made
    if other_taken < self.generated {
      return Err(update_failed());
    }
    let pair = self.source.next_keys().map_err(|_| update_failed())?;
    self.generated = self.generated.wrapping_add(1);
    self.bump(local);
    if local {
      self.pending_remote = Some(pair.remote);
      Ok(pair.local)
    } else {
      self.pending_local = Some(pair.local);
      Ok(pair.remote)
    }
  }

  /// [`Self::next`], for the tests of the TLS adapters.
  #[cfg(test)]
  pub(crate) fn next_for_test(&mut self, local: bool) -> crate::Result<KeyMaterial> {
    self.next(local)
  }

  fn bump(&mut self, local: bool) {
    if local {
      self.local_taken = self.local_taken.wrapping_add(1);
    } else {
      self.remote_taken = self.remote_taken.wrapping_add(1);
    }
  }
}

impl core::fmt::Debug for KeyUpdate {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("KeyUpdate")
      .field("generated", &self.generated)
      .field("local_taken", &self.local_taken)
      .field("remote_taken", &self.remote_taken)
      .finish_non_exhaustive()
  }
}

fn update_failed() -> crate::Error {
  crate::Error::QuicClose(TransportErrorCode::InternalError, QuicError::TlsSecretsNotTaken)
}

impl KeyPhase {
  pub(crate) const fn new() -> Self {
    Self {
      current_in_slot: false,
      local_acked: false,
      local_acked_us: 0,
      local_first_pn: 0,
      local_phase: false,
      other: OtherKeys::None,
      previous_until_us: 0,
      remote_first_pn: 0,
      remote_phase: false,
      slot: None,
      updater: None,
    }
  }

  // The source of the keys of the next generations, given when the handshake ends.
  pub(crate) fn set_updater(&mut self, source: Box<dyn KeyUpdater>) {
    self.updater = Some(Box::new(KeyUpdate::new(source)));
  }

  fn next_material(&mut self, local: bool) -> crate::Result<KeyMaterial> {
    match self.updater.as_mut() {
      Some(elem) => elem.next(local),
      None => Err(update_failed()),
    }
  }

  // The generation that opens a packet of key phase `phase` and number `pn`, before it is
  // decrypted (RFC 9001 section 6.3, ruling T9-a): the current one for its phase; for the other
  // phase, the previous one below the first packet number of the current phase, if it is still
  // kept, and the next one above the largest packet number received, if it is made: while the
  // previous keys are kept it is not (review J12). Anything else is dropped.
  pub(crate) fn choose(&self, phase: bool, pn: u64, largest: Option<u64>) -> Option<Generation> {
    if phase == self.remote_phase {
      return Some(Generation::Current);
    }
    if pn < self.remote_first_pn {
      return (self.other == OtherKeys::Previous).then_some(Generation::Previous);
    }
    let next = self.other == OtherKeys::Next && largest.is_none_or(|elem| pn > elem);
    next.then_some(Generation::Next)
  }

  // When the previous keys that open packets go, if they are kept.
  pub(crate) fn discard_deadline(&self) -> Option<u64> {
    (self.other == OtherKeys::Previous).then_some(self.previous_until_us)
  }

  // Three PTOs after a flip: the previous keys are dropped in their slot, where the next ones are
  // made (RFC 9001 section 6.5).
  pub(crate) fn discard_previous(
    &mut self,
    keys: Option<&mut PacketKeys>,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    match keys {
      Some(elem) if self.other == OtherKeys::Previous => self.prepare_next(elem, pools),
      _ => Ok(()),
    }
  }

  // Updates the keys that seal packets if `keys` sealed `threshold` packets, the peer follows
  // the current phase and a packet sealed with the current keys was acknowledged, four PTOs of
  // `pto_us` before `now_us` if the keys were updated before (RFC 9001 sections 6.1 and 6.5,
  // review J7): the next packet, `next_pn`, has the new phase. Returns whether it did. The peer
  // keeps its previous keys three of its own PTOs, and makes its next ones only then (review
  // J12): the fourth one leaves room for its PTO to be longer than ours, so that the packets of
  // the update are not dropped.
  pub(crate) fn maybe_initiate(
    &mut self,
    keys: &mut PacketKeys,
    threshold: u64,
    next_pn: u64,
    now_us: u64,
    pto_us: u64,
  ) -> crate::Result<bool> {
    let waited = self.local_first_pn == 0
      || now_us >= self.local_acked_us.saturating_add(pto_us.saturating_mul(KEY_UPDATE_WAIT_PTOS));
    if !self.local_acked
      || !waited
      || self.local_phase != self.remote_phase
      || keys.local.packets_sealed() < threshold
    {
      return Ok(false);
    }
    self.update_local(keys, next_pn)?;
    Ok(true)
  }

  // A packet opened with the next keys: the peer updated its keys (RFC 9001 section 6.2). The
  // previous ones stay three PTOs, and ours follow if they did not lead. Returns whether they
  // followed.
  pub(crate) fn on_peer_update(
    &mut self,
    pn: u64,
    now_us: u64,
    pto_us: u64,
    keys: &mut PacketKeys,
    next_pn: u64,
  ) -> crate::Result<bool> {
    self.current_in_slot = !self.current_in_slot;
    self.remote_phase = !self.remote_phase;
    self.remote_first_pn = pn;
    self.other = OtherKeys::Previous;
    self.previous_until_us = now_us.saturating_add(pto_us.saturating_mul(3));
    if self.local_phase == self.remote_phase {
      return Ok(false);
    }
    self.update_local(keys, next_pn)?;
    Ok(true)
  }

  // Makes the next generation of the keys that open packets in the slot that does not hold the
  // current ones, which drops what it held in place.
  pub(crate) fn prepare_next(
    &mut self,
    keys: &mut PacketKeys,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    if self.other == OtherKeys::Next {
      return Ok(());
    }
    let material = self.next_material(false)?;
    if self.current_in_slot {
      let current = self.slot.as_deref().and_then(|el| el.remote.as_ref());
      let Some(current) = current else {
        return Err(crate::Error::ProgrammingError);
      };
      keys.remote = current.next_generation(&material)?;
    } else {
      let next = keys.remote.next_generation(&material)?;
      let slot = self.slot.get_or_insert_with(|| {
        pools.key_slots.take().unwrap_or_else(|| Box::new(KeySlot { remote: None }))
      });
      slot.remote = Some(next);
    }
    self.other = OtherKeys::Next;
    Ok(())
  }

  // Gives the box back, its keys wiped in place, and starts over.
  pub(crate) fn release(&mut self, pools: &mut QuicPools) {
    if let Some(mut elem) = self.slot.take() {
      elem.remote = None;
      pools.key_slots.give(elem);
    }
    *self = Self::new();
  }

  // The keys of `generation` that open packets.
  pub(crate) fn remote<'keys>(
    &'keys self,
    generation: Generation,
    keys: &'keys PacketKeys,
  ) -> Option<&'keys DirectionalKeys> {
    let in_slot = match generation {
      Generation::Current => self.current_in_slot,
      Generation::Previous | Generation::Next => !self.current_in_slot,
    };
    if in_slot { self.slot.as_deref()?.remote.as_ref() } else { Some(&keys.remote) }
  }

  pub(crate) fn update_local(&mut self, keys: &mut PacketKeys, next_pn: u64) -> crate::Result<()> {
    let material = self.next_material(true)?;
    keys.local.advance(&material)?;
    self.local_phase = !self.local_phase;
    self.local_first_pn = next_pn;
    self.local_acked = false;
    Ok(())
  }
}

// The packets that one key of `suite` seals at most (RFC 9001 section 6.6). ChaCha20 has no
// limit in practice.
pub(crate) const fn confidentiality_limit(suite: CipherSuite) -> u64 {
  match suite {
    CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => AES_GCM_CONFIDENTIALITY_LIMIT,
    CipherSuite::Chacha20Poly1305Sha256 => u64::MAX,
  }
}

// The packets that may fail to open over a connection of `suite` (RFC 9001 section 6.6).
pub(crate) const fn integrity_limit(suite: CipherSuite) -> u64 {
  match suite {
    CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => AES_GCM_INTEGRITY_LIMIT,
    CipherSuite::Chacha20Poly1305Sha256 => CHACHA20_INTEGRITY_LIMIT,
  }
}

/// The packets that one key of 1-RTT packets of `suite` seals before an update starts:
/// `configured`, at most half the confidentiality limit of the suite (2^23 packets for AES-GCM,
/// RFC 9001 section 6.6), which leaves time for the acknowledgment that an update waits for.
#[cfg(test)]
pub(crate) const fn key_update_threshold(suite: CipherSuite, configured: u64) -> u64 {
  threshold_for(confidentiality_limit(suite), configured)
}

// `configured`, at most half of the confidentiality limit `limit`.
pub(crate) const fn threshold_for(limit: u64, configured: u64) -> u64 {
  let half = if limit == u64::MAX { limit } else { limit / 2 };
  if configured < half { configured } else { half }
}
