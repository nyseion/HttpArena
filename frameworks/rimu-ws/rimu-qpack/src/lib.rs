//! Sans-IO QPACK (RFC 9204): the field compression of HTTP/3.
//!
//! - [`Decoder`]: a dynamic table up to the advertised capacity, blocked streams with unblock
//!   notifications, the decoder-stream instructions (Section Acknowledgment, Stream Cancellation,
//!   Insert Count Increment), bounded memory and work against a hostile peer, zero-copy fields,
//!   and a memo that replays field sections repeated byte for byte without decoding them again.
//! - [`Encoder`]: a dynamic table with inserts by static or dynamic name reference or literal
//!   name, Duplicates of draining entries, post-base indexing, tracking of unacknowledged
//!   references so that no referenced entry is evicted, and the peer's blocked-streams limit; or
//!   the static-only mode, which never makes the peer block or acknowledge.
//! - [`encode_static`] and friends: static-only sections without an encoder, for pre-encoded
//!   response heads.
//!
//! The crate does no I/O: the caller moves bytes between the codec and the HTTP/3 streams (the
//! peer's encoder stream into [`Decoder::feed_encoder_stream`], [`Decoder::decoder_stream_output`]
//! to this side's decoder stream, and the same for the [`Encoder`]).
//!
//! ```
//! use rimu_qpack::{Decoder, DecoderConfig, Encoder, EncoderConfig, Field, FieldList};
//!
//! let mut decoder = Decoder::new(DecoderConfig::default());
//! let mut encoder = Encoder::new(EncoderConfig::default());
//! // Each side learns the other's SETTINGS
//! encoder.set_peer_settings(decoder.settings()).unwrap();
//!
//! let request = [
//!   Field::new(b":method", b"GET"),
//!   Field::new(b":path", b"/index.html"),
//!   Field::new(b"user-agent", b"example/1.0"),
//!   Field::sensitive(b"authorization", b"Bearer secret"),
//! ];
//! let mut fields = FieldList::new();
//! for stream_id in [0u64, 4, 8] {
//!   let mut section = Vec::new();
//!   encoder.encode(stream_id, request, &mut section);
//!   // Encoder stream: encoder -> decoder
//!   decoder.feed_encoder_stream(encoder.encoder_stream_output()).unwrap();
//!   encoder.consume_encoder_stream(usize::MAX);
//!   // The field section, on the request stream
//!   decoder.decode_into(stream_id, &section, &mut fields).unwrap();
//!   assert_eq!(fields.to_vec(), request);
//!   // Decoder stream: decoder -> encoder
//!   encoder.feed_decoder_stream(decoder.decoder_stream_output()).unwrap();
//!   decoder.consume_decoder_stream(usize::MAX);
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod decode_memo;
mod decoder;
mod encode_static;
mod encoder;
mod error;
mod field;
mod huffman;
mod prefix_int;
mod static_table;

#[cfg(any(test, feature = "__check"))]
#[doc(hidden)]
pub mod check;
#[cfg(any(test, feature = "__check"))]
#[doc(hidden)]
pub mod wire;

pub use decoder::{DecodeOutcome, Decoder, DecoderConfig, DecoderStats};
pub use encode_static::{encode_static, encode_static_line, encode_static_prefix};
pub use encoder::{
  Encoder, EncoderConfig, EncoderStats, InsertPolicy, MAX_TRACKED_SECTIONS, SENSITIVE_NAMES,
};
pub use error::{Error, ErrorCode, ErrorKind, Result};
pub use field::{DecodedField, Field, FieldList, FieldListIter};
pub use static_table::{STATIC_TABLE, StaticRef, find_exact, find_name};

/// The QPACK settings of an HTTP/3 endpoint (RFC 9204 section 5), as sent in its SETTINGS frame.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Settings {
  /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01): the most bytes of dynamic table that the peer's
  /// encoder may use. 0 when absent.
  pub max_table_capacity: u64,
  /// `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07): the most streams that may be blocked at once. 0 when
  /// absent.
  pub blocked_streams: u64,
}

/// Huffman coding of strings (RFC 7541 Appendix B), as QPACK uses it.
pub mod huffman_code {
  use alloc::vec::Vec;

  /// The length of the Huffman coding of `src`.
  #[inline]
  pub fn encoded_len(src: &[u8]) -> usize {
    crate::huffman::encoded_len(src)
  }

  /// Appends the Huffman coding of `src` to `out`.
  #[inline]
  pub fn encode(src: &[u8], out: &mut Vec<u8>) {
    crate::huffman::encode(src, out);
  }

  /// Appends the decoding of the Huffman string `src` to `out`; an error for an invalid string
  /// (bad padding or EOS), and `out` is then as it was.
  #[inline]
  pub fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<(), crate::Error> {
    crate::huffman::decode(src, out, usize::MAX)
      .map_err(|_err| crate::Error::local(crate::ErrorKind::InvalidHuffman))
  }
}
