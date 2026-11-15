//! The error type: what went wrong, and which HTTP/3 error code the connection must close with.

use core::fmt;

/// The HTTP/3 error code that an [`Error`] requires the connection to be closed with (RFC 9204
/// section 6 and RFC 9114 section 8.1).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
  /// `QPACK_DECOMPRESSION_FAILED` (0x0200): a field section could not be decoded.
  DecompressionFailed,
  /// `QPACK_ENCODER_STREAM_ERROR` (0x0201): an instruction of the peer's encoder stream could not
  /// be applied.
  EncoderStreamError,
  /// `QPACK_DECODER_STREAM_ERROR` (0x0202): an instruction of the peer's decoder stream could not
  /// be applied.
  DecoderStreamError,
  /// `H3_EXCESSIVE_LOAD` (0x0107): the peer makes this side do more work, or keep more state,
  /// than the limits of this crate allow.
  ExcessiveLoad,
}

impl ErrorCode {
  /// The numeric HTTP/3 error code.
  #[inline]
  pub const fn to_u64(self) -> u64 {
    match self {
      Self::DecompressionFailed => 0x0200,
      Self::EncoderStreamError => 0x0201,
      Self::DecoderStreamError => 0x0202,
      Self::ExcessiveLoad => 0x0107,
    }
  }

  /// The name of the code in the RFCs.
  #[inline]
  pub const fn name(self) -> &'static str {
    match self {
      Self::DecompressionFailed => "QPACK_DECOMPRESSION_FAILED",
      Self::EncoderStreamError => "QPACK_ENCODER_STREAM_ERROR",
      Self::DecoderStreamError => "QPACK_DECODER_STREAM_ERROR",
      Self::ExcessiveLoad => "H3_EXCESSIVE_LOAD",
    }
  }
}

/// What went wrong.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
  /// A Set Dynamic Table Capacity instruction asks for more than the advertised maximum (RFC 9204
  /// section 4.3.1), or a local call asks the encoder for more than the peer allows.
  CapacityAboveMaximum,
  /// The decoder-stream instructions that wait to be written grew past their bound: the peer
  /// does not read them.
  DecoderStreamBacklog,
  /// More encoder-stream instructions arrived in one turn, or more bytes were copied out of the
  /// dynamic table, than the decoder's budget allows.
  EncoderInstructionBudget,
  /// The incomplete encoder- or decoder-stream instruction kept for the next bytes grew past
  /// what any valid instruction needs.
  StreamBacklog,
  /// An insert is larger than the capacity of the dynamic table (RFC 9204 section 3.2.2).
  EntryTooLarge,
  /// A field section decodes to more than the configured maximum field section size, counted as
  /// RFC 9114 section 4.2.2 does (name + value + 32 per field).
  FieldSectionTooLarge,
  /// A prefixed integer is larger than 2^62 - 1 (RFC 9204 section 4.1.1), or longer than such a
  /// value needs.
  IntegerOverflow,
  /// The Base of a field section is negative or does not fit in 64 bits (RFC 9204 section
  /// 4.5.1.2).
  InvalidBase,
  /// A reference to a dynamic table entry that was evicted, is not inserted yet or, in a field
  /// section, is at or above the Required Insert Count (RFC 9204 section 2.2.3).
  InvalidDynamicIndex,
  /// A Huffman string has an invalid code, an EOS symbol, or padding that is longer than 7 bits
  /// or not all ones (RFC 7541 section 5.2).
  InvalidHuffman,
  /// An encoded Required Insert Count that no conformant encoder produces (RFC 9204 section
  /// 4.5.1.1).
  InvalidRequiredInsertCount,
  /// An index past the end of the static table (RFC 9204 section 3.1).
  InvalidStaticIndex,
  /// The Required Insert Count of a field section is larger than its references need (RFC 9204
  /// section 2.1.2).
  RequiredInsertCountTooLarge,
  /// A field section or encoder instruction ends in the middle of a representation.
  Truncated,
  /// More streams would be blocked than `SETTINGS_QPACK_BLOCKED_STREAMS` allows (RFC 9204 section
  /// 2.1.2).
  TooManyBlockedStreams,
  /// A Section Acknowledgment for a stream that has no unacknowledged field section with dynamic
  /// references (RFC 9204 section 4.4.1).
  UnexpectedSectionAcknowledgment,
  /// An Insert Count Increment of zero, or one past the inserts that were sent (RFC 9204 section
  /// 4.4.3).
  InvalidInsertCountIncrement,
  /// The dynamic table capacity can not be lowered now: entries that would have to be evicted are
  /// still referenced by unacknowledged field sections, or not acknowledged yet (RFC 9204 section
  /// 4.3.1). A local error; nothing has to be closed.
  EntriesInUse,
  /// A setting or configuration value is out of the supported range. A local error.
  InvalidConfig,
  /// The field-section sink returned this error: decoding stopped. A local error.
  Aborted,
}

/// An error of the codec: its [`ErrorKind`], and the [`ErrorCode`] that the HTTP/3 connection
/// must be closed with, if any.
///
/// Errors without a code are local: a call was refused, no state was corrupted, and the
/// connection can go on.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Error {
  code: Option<ErrorCode>,
  kind: ErrorKind,
}

impl Error {
  /// An error of `kind` that closes the connection with `code`.
  #[inline]
  pub const fn new(code: ErrorCode, kind: ErrorKind) -> Self {
    Self { code: Some(code), kind }
  }

  /// A local error of `kind`.
  #[inline]
  pub const fn local(kind: ErrorKind) -> Self {
    Self { code: None, kind }
  }

  /// The HTTP/3 error code to close the connection with, or `None` for a local error.
  #[inline]
  pub const fn code(&self) -> Option<ErrorCode> {
    self.code
  }

  /// What went wrong.
  #[inline]
  pub const fn kind(&self) -> ErrorKind {
    self.kind
  }

  #[cold]
  pub(crate) const fn decompression(kind: ErrorKind) -> Self {
    Self::new(ErrorCode::DecompressionFailed, kind)
  }

  #[cold]
  pub(crate) const fn encoder_stream(kind: ErrorKind) -> Self {
    Self::new(ErrorCode::EncoderStreamError, kind)
  }

  #[cold]
  pub(crate) const fn decoder_stream(kind: ErrorKind) -> Self {
    Self::new(ErrorCode::DecoderStreamError, kind)
  }

  #[cold]
  pub(crate) const fn excessive_load(kind: ErrorKind) -> Self {
    Self::new(ErrorCode::ExcessiveLoad, kind)
  }
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.code {
      Some(code) => write!(f, "{} ({:?})", code.name(), self.kind),
      None => write!(f, "{:?}", self.kind),
    }
  }
}

impl core::error::Error for Error {}

/// The result type of this crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

// Errors stay two bytes, cheap to return by value
const _: () = assert!(size_of::<Error>() == 2);
