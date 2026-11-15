//! A sans-I/O HTTP/3 server (RFC 9114) on the QUIC transport of rimu-quic and the QPACK codec of
//! rimu-qpack (RFC 9204).
//!
//! [`H3Server`] is the application of rimu-quic's connections ([`rimu_quic::QuicApp`]): it opens
//! the control and QPACK streams, reads the SETTINGS and the other frames of the peer's control
//! stream, feeds the peer's QPACK streams to the decoder and the encoder, reads requests frame by
//! frame, checks them as RFC 9114 sections 4.1 to 4.3 ask, and hands them to a [`Handler`], which
//! answers through a [`ReqCtx`]: a pre-encoded head and a body copied, sent by reference
//! ([`BodyRef`]) or streamed.
//!
//! Everything here is sans-I/O: a [`rimu_quic::Endpoint`] of `H3Server` is fed datagrams and drained
//! into a send arena by any UDP loop (see `examples/hello_server.rs`).
//!
//! The sections below are what [`H3Server`] does.
//!
//! # Streams
//!
//! Once a connection is established the server opens its control stream, with its SETTINGS
//! (`SETTINGS_QPACK_MAX_TABLE_CAPACITY` and `SETTINGS_QPACK_BLOCKED_STREAMS` of [`H3Params`] and
//! `SETTINGS_MAX_FIELD_SECTION_SIZE`), and its QPACK encoder and decoder streams, and never closes
//! them; nothing GREASE is sent, and the encoder stream carries nothing after its type unless
//! [`H3Params::response_encoder`] gives responses a dynamic table. Of the unidirectional streams of
//! the client, the control stream must start with SETTINGS; its encoder stream feeds the QPACK
//! decoder; its decoder stream feeds the QPACK encoder (with a static-only encoder, only Stream
//! Cancellations are valid on it). Closing or resetting one of them, or asking us to stop one of
//! ours, closes the connection with `H3_CLOSED_CRITICAL_STREAM`; a second one of a type, or a push
//! stream, with `H3_STREAM_CREATION_ERROR`; a stream of an unknown type is asked to stop with
//! `H3_STREAM_CREATION_ERROR`. Unknown frames and settings are skipped, PRIORITY_UPDATE with them;
//! push is never allowed (no MAX_PUSH_ID is sent).
//!
//! # Requests
//!
//! A request stream is read frame by frame as its bytes arrive. A HEADERS frame that arrived whole
//! is decoded where it is; one that is cut is kept by retaining its bytes (up to 4 KiB, which the
//! connection allows), or else in the head buffer of the request (ruling T13-b). DATA payloads are
//! copied into the body of the request, whose credit then comes back to the peer. Once the FIN
//! arrives, the request, checked ([`Request`]), goes to the handler, which answers it at once or
//! parks it ([`ReqOutcome`]) until [`H3Server::resume`]. A field section that needs QPACK inserts
//! that did not arrive waits, with what follows it on its stream, until they do.
//!
//! A handler that takes bodies as they arrive ([`Handler::body_mode`]) gets the request once its
//! head is read, and its DATA payloads through [`Handler::on_body`], without buffering.
//!
//! - A malformed request (RFC 9114 section 4.1.2) gets a stream error, `H3_MESSAGE_ERROR`
//!   (RESET_STREAM and STOP_SENDING); a stream that ends without a head `H3_REQUEST_INCOMPLETE`.
//! - A field section that decodes to more than `SETTINGS_MAX_FIELD_SECTION_SIZE` (or whose
//!   HEADERS frame alone is longer) is answered with 431, a body longer than
//!   [`H3Params::max_request_body`] (or announced so by `content-length`) with 413; the rest of the
//!   request is then not read (STOP_SENDING with `H3_NO_ERROR`, RFC 9114 section 4.1).
//! - Frames out of place (DATA before HEADERS, frames of the control stream) and frames cut by the
//!   FIN are connection errors, `H3_FRAME_UNEXPECTED` and `H3_FRAME_ERROR`.
//!
//! # Responses
//!
//! A response written from a callback leaves with the next flush of the connection, together with
//! the acknowledgment of the request that it answers: a HEADERS frame, a DATA frame and the FIN in
//! one write, which leave in one STREAM frame when they fit in a packet. Heads are pre-encoded with
//! the static table ([`crate::ResponseHeads`]), or encoded with the dynamic table of the encoder of
//! the connection when [`H3Params::response_encoder`] is set; bodies are copied, sent by reference
//! ([`BodyRef`]) or streamed ([`ReqCtx::send_head`], [`ReqCtx::send_data`]).
//!
//! # Shutdown
//!
//! When the endpoint shuts down ([`rimu_quic::QuicApp::on_shutdown`]), the connection sends GOAWAY with the
//! lowest client stream that QUIC did not open, refuses requests from it on with
//! `H3_REQUEST_REJECTED`, and lets the others finish. Once no request is under way, the streams
//! below the GOAWAY that brought no request (opened by a later one, or whose data did not arrive in
//! order) are refused with `H3_REQUEST_REJECTED`, never dropped, and once every answer and refusal
//! is acknowledged the connection closes with `H3_NO_ERROR` (ruling T13-h);
//! [`rimu_quic::QuicLimits::shutdown_grace_ms`] bounds the wait.
//!
//! # Memory
//!
//! The request buffers of a connection hold at most [`H3Params::max_buffered_body_per_conn`]
//! bytes (ruling T13-g); the decoder-stream output is written while that stream has less than
//! 4 KiB unsent, so a peer that gives it no credit meets the bound of the decoder (review V3); the
//! pool keeps boxes within a byte budget, and [`H3Server::trim_idle`] frees it down for an idle
//! worker (review V4). Once warm, a request allocates nothing.
//!
//! # Example
//!
//! ```rust,ignore
//! use rimu_h3::{H3Params, H3Server, Handler, ReqCtx, ReqOutcome, Request, ResponseFields, Body};
//!
//! struct Hello;
//!
//! impl Handler for Hello {
//!   fn on_request(&mut self, cx: &mut ReqCtx<'_, '_>, req: &Request<'_>) -> rimu_h3::Result<ReqOutcome> {
//!     cx.respond_with(&ResponseFields::with_type(200, b"text/plain"), Body::Bytes(b"hello"))?;
//!     Ok(ReqOutcome::Responded)
//!   }
//! }
//!
//! let app = H3Server::new(Hello, H3Params::default());
//! let endpoint = rimu_quic::Endpoint::<H3Server<Hello>>::new(/* ... */);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench_support;
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub mod check;
mod conn_state;
mod error;
pub mod frame;
mod request;
mod response;
mod server;
mod settings;
#[cfg(any(test, feature = "__fuzz"))]
#[doc(hidden)]
pub mod testing;
#[cfg(all(feature = "uring", target_os = "linux"))]
pub mod uring;

pub use conn_state::H3ConnState;
pub use error::{Error, H3ErrorCode, Http3Error, Result};
pub use request::{Fields, Request};
pub use response::{DateLine, ResponseFields, ResponseHeads, imf_fixdate};
pub use rimu_quic::{BodyRef, SharedBytes, StreamId};
pub use server::{Body, BodyMode, H3Params, H3Server, Handler, QpackCounters, ReqCtx, ReqOutcome};
pub use settings::H3Settings;
