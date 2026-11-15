//! The random numbers of the transport: connection IDs, stateless reset and Retry token keys,
//! path challenges, the seeds of the hash maps. A ChaCha20 generator (`rand_chacha`), seeded from
//! the operating system (`std`) or by the caller.

use rand_core::{RngCore, SeedableRng};

/// A cryptographically secure generator: ChaCha20 with 20 rounds.
#[derive(Clone, Debug)]
pub struct ChaCha20(rand_chacha::ChaCha20Rng);

impl ChaCha20 {
  /// The generator of the 32-byte seed `key`: the same seed gives the same numbers.
  #[inline]
  pub fn from_key(key: [u8; 32]) -> Self {
    Self(rand_chacha::ChaCha20Rng::from_seed(key))
  }

  /// A generator seeded from the random numbers of the operating system.
  #[cfg(feature = "std")]
  #[inline]
  pub fn from_os() -> crate::Result<Self> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_err| crate::Error::ProgrammingError)?;
    let this = Self::from_key(seed);
    crate::protection::wipe(&mut seed);
    Ok(this)
  }

  /// A generator seeded from `rng`, independent of it from then on.
  #[inline]
  pub fn from_rng<R>(rng: &mut R) -> Self
  where
    R: Rng + ?Sized,
  {
    let mut seed = rng.u8_32();
    let this = Self::from_key(seed);
    crate::protection::wipe(&mut seed);
    this
  }
}

/// What the transport draws from a generator.
pub trait Rng {
  /// Fills `slice` with random bytes.
  fn fill_slice(&mut self, slice: &mut [u8]);

  /// 4 random bytes.
  #[inline]
  fn u8_4(&mut self) -> [u8; 4] {
    let mut out = [0; 4];
    self.fill_slice(&mut out);
    out
  }

  /// 8 random bytes.
  #[inline]
  fn u8_8(&mut self) -> [u8; 8] {
    let mut out = [0; 8];
    self.fill_slice(&mut out);
    out
  }

  /// 16 random bytes.
  #[inline]
  fn u8_16(&mut self) -> [u8; 16] {
    let mut out = [0; 16];
    self.fill_slice(&mut out);
    out
  }

  /// 32 random bytes.
  #[inline]
  fn u8_32(&mut self) -> [u8; 32] {
    let mut out = [0; 32];
    self.fill_slice(&mut out);
    out
  }

  /// A random `u64`.
  #[inline]
  fn next_value(&mut self) -> u64 {
    u64::from_le_bytes(self.u8_8())
  }
}

impl Rng for ChaCha20 {
  #[inline]
  fn fill_slice(&mut self, slice: &mut [u8]) {
    self.0.fill_bytes(slice);
  }
}

/// A generator fit for keys and connection IDs.
pub(crate) use Rng as CryptoRng;

/// A fixed hash state for the hash maps of connection IDs, keyed from `rng` so that peers cannot
/// pick colliding IDs.
#[inline]
pub(crate) fn random_state<R>(rng: &mut R) -> foldhash::fast::FixedState
where
  R: Rng + ?Sized,
{
  foldhash::fast::FixedState::with_seed(rng.next_value())
}
