//! The error type of the crate.

use crate::{QuicError, TransportErrorCode, crypto::CryptoError};

/// The result type of the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Why an operation failed.
///
/// [`Error::Quic`] alone means that the offending packet or element is dropped;
/// [`Error::QuicClose`] that the connection closes with the transport error code it carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
  /// A cryptographic primitive failed: a packet that does not authenticate, or a key of the wrong
  /// length.
  Crypto(CryptoError),
  /// A QUIC element could not be processed and is dropped.
  Quic(QuicError),
  /// The connection must close with the code.
  QuicClose(TransportErrorCode, QuicError),
  /// A value did not fit the type it was converted to.
  Conversion,
  /// A state that correct code never reaches.
  ProgrammingError,
}

impl core::fmt::Display for Error {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::Crypto(el) => write!(f, "crypto: {el}"),
      Self::Quic(el) => write!(f, "QUIC: {el:?}"),
      Self::QuicClose(code, el) => write!(f, "QUIC, closing with {code:?}: {el:?}"),
      Self::Conversion => f.write_str("a value did not fit its type"),
      Self::ProgrammingError => f.write_str("programming error"),
    }
  }
}

impl core::error::Error for Error {}

impl From<CryptoError> for Error {
  #[inline]
  fn from(value: CryptoError) -> Self {
    Self::Crypto(value)
  }
}

impl From<QuicError> for Error {
  #[inline]
  fn from(value: QuicError) -> Self {
    Self::Quic(value)
  }
}

impl From<core::num::TryFromIntError> for Error {
  #[inline]
  fn from(_: core::num::TryFromIntError) -> Self {
    Self::Conversion
  }
}

impl From<core::array::TryFromSliceError> for Error {
  #[inline]
  fn from(_: core::array::TryFromSliceError) -> Self {
    Self::Conversion
  }
}

impl From<core::convert::Infallible> for Error {
  #[inline]
  fn from(value: core::convert::Infallible) -> Self {
    match value {}
  }
}
