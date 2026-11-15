//! Error types of the HTTP/3 codecs and connection: [`Error`], [`Http3Error`] (why) and
//! [`H3ErrorCode`] (the code that goes on the wire).

use core::fmt;

// The crate-wide `Error` must stay small.
const _: () = {
  assert!(size_of::<H3ErrorCode>() == 1);
  assert!(size_of::<Http3Error>() == 1);
};

/// The result type of the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Why an operation failed.
///
/// [`Error::Http3`] alone means that the element is refused and nothing is closed because of it;
/// [`Error::Http3Close`] that the connection must close with its code. A [`Error::Qpack`] error
/// with a code ([`rimu_qpack::Error::code`]) closes the connection with that code too.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
  /// An HTTP/3 element could not be processed; nothing is closed because of it.
  Http3(Http3Error),
  /// The connection must close with the code.
  Http3Close(H3ErrorCode, Http3Error),
  /// The QPACK decoder or encoder failed.
  Qpack(rimu_qpack::Error),
  /// The QUIC connection refused an operation (a write to a stream that is closed, no stream
  /// left to open).
  Quic(rimu_quic::Error),
}

impl Error {
  /// The HTTP/3 error code that the connection must close with, if it must.
  #[inline]
  pub fn close_code(&self) -> Option<H3ErrorCode> {
    match self {
      Self::Http3Close(code, _) => Some(*code),
      Self::Qpack(err) => err.code().map(H3ErrorCode::from_qpack),
      Self::Http3(_) | Self::Quic(_) => None,
    }
  }
}

impl fmt::Display for Error {
  #[inline]
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Http3(el) => write!(f, "HTTP/3: {el:?}"),
      Self::Http3Close(code, el) => write!(f, "HTTP/3, closing with {code:?}: {el:?}"),
      Self::Qpack(el) => write!(f, "QPACK: {el}"),
      Self::Quic(el) => write!(f, "QUIC: {el}"),
    }
  }
}

impl core::error::Error for Error {}

impl From<Http3Error> for Error {
  #[inline]
  fn from(value: Http3Error) -> Self {
    Self::Http3(value)
  }
}

impl From<rimu_qpack::Error> for Error {
  #[inline]
  fn from(value: rimu_qpack::Error) -> Self {
    Self::Qpack(value)
  }
}

impl From<rimu_quic::Error> for Error {
  #[inline]
  fn from(value: rimu_quic::Error) -> Self {
    Self::Quic(value)
  }
}

impl From<alloc::collections::TryReserveError> for Error {
  #[inline]
  fn from(_: alloc::collections::TryReserveError) -> Self {
    Self::Http3(Http3Error::OutOfMemory)
  }
}

/// Why an HTTP/3 element could not be processed.
///
/// Alone, in [`Error::Http3`], the element is refused and nothing is closed because of it.
/// Together with an [`H3ErrorCode`], in [`Error::Http3Close`], the connection must be closed with
/// that code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Http3Error {
  /// A request handler answered a request that it had already answered, or sent a head twice.
  AlreadyResponded,
  /// An output buffer is too small for what should be written to it.
  BufferTooSmall,
  /// The buffers of the requests of a connection would hold more than
  /// [`crate::H3Params::max_buffered_body_per_conn`]: the request is answered with 413.
  BufferedLimit,
  /// The peer closed or reset one of its control, QPACK encoder or QPACK decoder streams, or asked
  /// for one of ours to stop (with [`H3ErrorCode::ClosedCriticalStream`], RFC 9114 section 6.2.1
  /// and RFC 9204 section 4.2).
  ClosedCriticalStream,
  /// A frame of the control stream other than DATA, HEADERS and PUSH_PROMISE (and other than the
  /// unknown ones, which are skipped) is longer than the 4 KiB that it is read in (with
  /// [`H3ErrorCode::ExcessiveLoad`]).
  ControlFrameTooLarge,
  /// A SETTINGS frame carries the same identifier twice (with [`H3ErrorCode::SettingsError`], RFC
  /// 9114 section 7.2.4).
  DuplicateSetting,
  /// The encoder-stream instructions that wait to be written grew past their bound (16 KiB): the
  /// peer does not read the encoder stream of the server (with [`H3ErrorCode::ExcessiveLoad`]).
  EncoderStreamBacklog,
  /// A field section decodes to more than the advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`, counted
  /// as RFC 9114 section 4.2.2 does: the request is answered with 431.
  FieldSectionTooLarge,
  /// A CANCEL_PUSH above the push identifiers that the client allowed, a MAX_PUSH_ID that lowers
  /// them or a GOAWAY of the client that raises its identifier (with [`H3ErrorCode::IdError`], RFC
  /// 9114 sections 5.2 and 7.2).
  InvalidPushId,
  /// A frame payload ends inside a field or has bytes after its fields (with
  /// [`H3ErrorCode::FrameError`], RFC 9114 section 7.1).
  MalformedFrame,
  /// A request that RFC 9114 section 4.1.2 calls malformed: its stream is reset with
  /// [`H3ErrorCode::MessageError`].
  MalformedRequest,
  /// The first frame of the control stream of the peer is not SETTINGS (with
  /// [`H3ErrorCode::MissingSettings`], RFC 9114 section 6.2.1).
  MissingSettings,
  /// A handler sent DATA before the head of its response.
  NoHead,
  /// A buffer could not grow: the allocator refused.
  OutOfMemory,
  /// A client opened a push stream, which only servers do (with
  /// [`H3ErrorCode::StreamCreationError`], RFC 9114 section 6.2.2).
  PushStreamFromClient,
  /// A frame type that HTTP/2 used and HTTP/3 reserves: 0x02, 0x06, 0x08 or 0x09 (with
  /// [`H3ErrorCode::FrameUnexpected`], RFC 9114 section 7.2.8).
  ReservedFrameType,
  /// A setting identifier that HTTP/2 used and HTTP/3 reserves: 0x02 to 0x05 (with
  /// [`H3ErrorCode::SettingsError`], RFC 9114 section 7.2.4.1).
  ReservedSetting,
  /// The peer opened a second control, QPACK encoder or QPACK decoder stream (with
  /// [`H3ErrorCode::StreamCreationError`], RFC 9114 section 6.2.1 and RFC 9204 section 4.2).
  SecondCriticalStream,
  /// A SETTINGS frame has more parameters than are checked for duplicates (64) (with
  /// [`H3ErrorCode::ExcessiveLoad`]).
  TooManySettings,
  /// A stream ends inside a frame (with [`H3ErrorCode::FrameError`], RFC 9114 section 7.1).
  TruncatedFrame,
  /// The peer does not allow the three unidirectional streams that HTTP/3 opens (with
  /// [`H3ErrorCode::GeneralProtocolError`], RFC 9114 section 6.2).
  UniStreamsBlocked,
  /// A frame that is not allowed on its stream or at its place on it (with
  /// [`H3ErrorCode::FrameUnexpected`], RFC 9114 sections 4.1 and 7.2).
  UnexpectedFrame,
}

/// HTTP/3 error codes (RFC 9114 section 8.1) and QPACK error codes (RFC 9204 section 6), the reason
/// in a `CONNECTION_CLOSE` frame of type `0x1d`, a `RESET_STREAM` or a `STOP_SENDING`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H3ErrorCode {
  /// No error. This is used when the connection or stream needs to be closed, but there is no
  /// error to signal.
  NoError,
  /// Peer violated protocol requirements in a way that does not match a more specific error code
  /// or endpoint declines to use the more specific error code.
  GeneralProtocolError,
  /// An internal error has occurred in the HTTP stack.
  InternalError,
  /// The endpoint detected that its peer created a stream that it will not accept.
  StreamCreationError,
  /// A stream required by the HTTP/3 connection was closed or reset.
  ClosedCriticalStream,
  /// A frame was received that was not permitted in the current state or on the current stream.
  FrameUnexpected,
  /// A frame that fails to satisfy layout requirements or with an invalid size was received.
  FrameError,
  /// The endpoint detected that its peer is exhibiting a behavior that might be generating
  /// excessive load.
  ExcessiveLoad,
  /// A stream ID or push ID was used incorrectly, such as exceeding a limit, reducing a limit, or
  /// being reused.
  IdError,
  /// An endpoint detected an error in the payload of a SETTINGS frame.
  SettingsError,
  /// No SETTINGS frame was received at the beginning of the control stream.
  MissingSettings,
  /// A server rejected a request without performing any application processing.
  RequestRejected,
  /// The request or its response (including pushed response) is cancelled.
  RequestCancelled,
  /// The client's stream terminated without containing a fully formed request.
  RequestIncomplete,
  /// An HTTP message was malformed and cannot be processed.
  MessageError,
  /// The TCP connection established in response to a CONNECT request was reset or abnormally
  /// closed.
  ConnectError,
  /// The requested operation cannot be served over HTTP/3. The peer should retry over HTTP/1.1.
  VersionFallback,
  /// The decoder failed to interpret an encoded field section and is not able to continue
  /// decoding that field section.
  QpackDecompressionFailed,
  /// The decoder failed to interpret an encoder instruction received on the encoder stream.
  QpackEncoderStreamError,
  /// The encoder failed to interpret a decoder instruction received on the decoder stream.
  QpackDecoderStreamError,
}

impl H3ErrorCode {
  /// The value that goes on the wire.
  #[inline]
  pub const fn code(self) -> u64 {
    match self {
      Self::NoError => 0x0100,
      Self::GeneralProtocolError => 0x0101,
      Self::InternalError => 0x0102,
      Self::StreamCreationError => 0x0103,
      Self::ClosedCriticalStream => 0x0104,
      Self::FrameUnexpected => 0x0105,
      Self::FrameError => 0x0106,
      Self::ExcessiveLoad => 0x0107,
      Self::IdError => 0x0108,
      Self::SettingsError => 0x0109,
      Self::MissingSettings => 0x010a,
      Self::RequestRejected => 0x010b,
      Self::RequestCancelled => 0x010c,
      Self::RequestIncomplete => 0x010d,
      Self::MessageError => 0x010e,
      Self::ConnectError => 0x010f,
      Self::VersionFallback => 0x0110,
      Self::QpackDecompressionFailed => 0x0200,
      Self::QpackEncoderStreamError => 0x0201,
      Self::QpackDecoderStreamError => 0x0202,
    }
  }

  /// The code of a value that came from the wire, or `None` if neither RFC defines it (RFC 9114
  /// section 8: an unknown code is treated as [`Self::NoError`]).
  #[inline]
  pub const fn from_code(code: u64) -> Option<Self> {
    Some(match code {
      0x0100 => Self::NoError,
      0x0101 => Self::GeneralProtocolError,
      0x0102 => Self::InternalError,
      0x0103 => Self::StreamCreationError,
      0x0104 => Self::ClosedCriticalStream,
      0x0105 => Self::FrameUnexpected,
      0x0106 => Self::FrameError,
      0x0107 => Self::ExcessiveLoad,
      0x0108 => Self::IdError,
      0x0109 => Self::SettingsError,
      0x010a => Self::MissingSettings,
      0x010b => Self::RequestRejected,
      0x010c => Self::RequestCancelled,
      0x010d => Self::RequestIncomplete,
      0x010e => Self::MessageError,
      0x010f => Self::ConnectError,
      0x0110 => Self::VersionFallback,
      0x0200 => Self::QpackDecompressionFailed,
      0x0201 => Self::QpackEncoderStreamError,
      0x0202 => Self::QpackDecoderStreamError,
      _ => return None,
    })
  }

  /// The code that a QPACK error closes the connection with.
  #[inline]
  pub const fn from_qpack(code: rimu_qpack::ErrorCode) -> Self {
    match code {
      rimu_qpack::ErrorCode::DecompressionFailed => Self::QpackDecompressionFailed,
      rimu_qpack::ErrorCode::EncoderStreamError => Self::QpackEncoderStreamError,
      rimu_qpack::ErrorCode::DecoderStreamError => Self::QpackDecoderStreamError,
      rimu_qpack::ErrorCode::ExcessiveLoad => Self::ExcessiveLoad,
      // A code that a later rimu-qpack adds: the general one
      _ => Self::GeneralProtocolError,
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::{Error, H3ErrorCode};

  #[test]
  fn h3_error_codes_match_rfc9114_section_8_1_and_rfc9204_section_6() {
    let all = [
      (H3ErrorCode::NoError, 0x0100),
      (H3ErrorCode::GeneralProtocolError, 0x0101),
      (H3ErrorCode::InternalError, 0x0102),
      (H3ErrorCode::StreamCreationError, 0x0103),
      (H3ErrorCode::ClosedCriticalStream, 0x0104),
      (H3ErrorCode::FrameUnexpected, 0x0105),
      (H3ErrorCode::FrameError, 0x0106),
      (H3ErrorCode::ExcessiveLoad, 0x0107),
      (H3ErrorCode::IdError, 0x0108),
      (H3ErrorCode::SettingsError, 0x0109),
      (H3ErrorCode::MissingSettings, 0x010a),
      (H3ErrorCode::RequestRejected, 0x010b),
      (H3ErrorCode::RequestCancelled, 0x010c),
      (H3ErrorCode::RequestIncomplete, 0x010d),
      (H3ErrorCode::MessageError, 0x010e),
      (H3ErrorCode::ConnectError, 0x010f),
      (H3ErrorCode::VersionFallback, 0x0110),
      (H3ErrorCode::QpackDecompressionFailed, 0x0200),
      (H3ErrorCode::QpackEncoderStreamError, 0x0201),
      (H3ErrorCode::QpackDecoderStreamError, 0x0202),
    ];
    for (code, value) in all {
      assert_eq!(code.code(), value);
      assert_eq!(H3ErrorCode::from_code(value), Some(code));
    }
    // Unassigned, and the reserved 0x1f * N + 0x21 space
    for unknown in [0x00, 0xff, 0x0111, 0x01ff, 0x0203, 0x21, 0x40, u64::MAX] {
      assert_eq!(H3ErrorCode::from_code(unknown), None);
    }
  }

  // The codes of QPACK errors are the RFC's, and local QPACK errors close nothing.
  #[test]
  fn qpack_errors_close_with_their_codes() {
    use rimu_qpack::{Error as QError, ErrorCode, ErrorKind};
    for (code, value) in [
      (ErrorCode::DecompressionFailed, 0x200),
      (ErrorCode::EncoderStreamError, 0x201),
      (ErrorCode::DecoderStreamError, 0x202),
      (ErrorCode::ExcessiveLoad, 0x107),
    ] {
      let err = Error::from(QError::new(code, ErrorKind::Truncated));
      assert_eq!(err.close_code().map(H3ErrorCode::code), Some(value));
      assert_eq!(H3ErrorCode::from_qpack(code).code(), code.to_u64());
    }
    assert_eq!(Error::from(QError::local(ErrorKind::Aborted)).close_code(), None);
  }
}
