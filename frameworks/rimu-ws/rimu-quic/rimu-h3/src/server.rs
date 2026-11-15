//! The HTTP/3 server connection (RFC 9114) as the application of QUIC connections: [`H3Server`].
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
//! When the endpoint shuts down ([`QuicApp::on_shutdown`]), the connection sends GOAWAY with the
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

use crate::{
  BodyRef, H3ErrorCode, H3Settings, Http3Error,
  conn_state::{FrameLeft, H3Conn, H3ConnState, KEEP_SCRATCH, Phase, Req},
  frame::{H3FrameTy, decode_frame_header, encode_frame_header},
  request::{Request, check_trailer},
  response::{DateLine, ResponseFields, ResponseHeads, decimal},
};
use alloc::{boxed::Box, vec::Vec};
use core::{hint::cold_path, net::IpAddr};
use rimu_qpack::{DecodeOutcome, DecodedField, Encoder, EncoderConfig, Field, encode_static};
use rimu_quic::{
  ConnCtx, ConnHandle, Endpoint, QuicApp, QuicError, StreamId,
  varint::{decode_varint, encode_varint, varint_len},
};

/// The bytes that the connection retains for a stream at most (see `ConnCtx::retain`): what is
/// read in one piece without a buffer of its own.
const RETAIN_MAX: usize = 4096;
/// The bytes that the QPACK streams may have unsent before more output waits in the decoder or
/// the encoder (review V3).
const QPACK_UNSENT_MAX: usize = 4096;
/// The encoder-stream bytes that may wait to be written before the peer, which gives our encoder
/// stream no credit, is closed with `H3_EXCESSIVE_LOAD`.
const ENCODER_BACKLOG: usize = 16 * 1024;
/// Boxes of connections that the pool keeps at most.
const MAX_POOLED: usize = 256;
// Room for what follows a blocked field section on its stream, on top of the limits of a request
const STASH_SLACK: u64 = 64 * 1024;
// The types of unidirectional streams (RFC 9114 section 6.2, RFC 9204 section 4.2)
const CONTROL_STREAM: u8 = 0x00;
const PUSH_STREAM: u64 = 0x01;
const ENCODER_STREAM: u8 = 0x02;
const DECODER_STREAM: u8 = 0x03;

/// The settings of the HTTP/3 connections of a server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H3Params {
  /// The advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the bytes of the dynamic table that the
  /// encoders of clients may use.
  ///
  /// Defaults to 0 (no dynamic table), measured on rimu-ws (EC2, 9 Nov 2026): 4096 bytes with 100
  /// blocked streams lost 2.8 % of requests per second on HttpArena baseline-h3 (spread 0.4 %), the
  /// client spending 3 % more CPU per request on its table, for a decode memo hit rate of 100 %
  /// either way; static-h3 was unchanged within its spread.
  pub qpack_max_table_capacity: u32,
  /// The advertised `SETTINGS_QPACK_BLOCKED_STREAMS`.
  ///
  /// Defaults to 0, which goes with no dynamic table.
  pub qpack_blocked_streams: u16,
  /// The advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`, which the field sections of requests are
  /// held to (RFC 9114 section 4.2.2): a request whose head or trailers decode to more is answered
  /// with 431.
  ///
  /// Defaults to 16 KiB.
  pub max_field_section_size: u32,
  /// The largest body of a request that is buffered: a request with a larger one is answered with
  /// 413. Bodies that the handler takes as they arrive ([`BodyMode::Stream`]) are not held to it.
  ///
  /// Defaults to 1 MiB.
  pub max_request_body: u32,
  /// The bytes that the buffers of the requests of a connection (heads, bodies, bytes that wait
  /// for others) may hold at most, counted by their capacity: a request that would need more is
  /// answered with 413, and the others go on (ruling T13-g).
  ///
  /// Defaults to 16 MiB, the receive window of a connection.
  pub max_buffered_body_per_conn: u32,
  /// The QPACK encoder of responses: `None` (the default) encodes heads with the static table only
  /// (pre-encoded, nothing for the client to track), a configuration a dynamic table of at most
  /// its capacity, used once the SETTINGS of the client allow one.
  pub response_encoder: Option<EncoderConfig>,
  /// If responses with content carry `content-length` (RFC 9110 section 8.6: a SHOULD when the size
  /// is known; HTTP/3 frames the content without it). A response to `HEAD` carries it either way.
  /// Defaults to `false`; see [`Self::rfc9110_headers`].
  pub content_length: bool,
  /// If responses carry `date` (RFC 9110 section 6.6.1: an origin server with a clock must send
  /// one), from [`H3Server::set_date`]. Defaults to `false`; see [`Self::rfc9110_headers`].
  pub date: bool,
}

impl H3Params {
  /// Turns on both response fields that RFC 9110 asks of an origin server and the default leaves
  /// out: `date` (section 6.6.1) and `content-length` (section 8.6). The default, `:status` and
  /// `content-type` only, like the HttpArena HTTP/3 leaders, is not RFC 9110-compliant.
  #[inline]
  #[must_use]
  pub const fn rfc9110_headers(mut self, value: bool) -> Self {
    self.content_length = value;
    self.date = value;
    self
  }
}

impl Default for H3Params {
  #[inline]
  fn default() -> Self {
    Self {
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: 16 * 1024,
      max_request_body: 1 << 20,
      max_buffered_body_per_conn: 16 << 20,
      response_encoder: None,
      content_length: false,
      date: false,
    }
  }
}

/// What became of a request that the handler was given.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReqOutcome {
  /// It was answered whole: its response ends with the FIN.
  Responded,
  /// It is answered later, from [`Handler::resume`], or, for a body that the handler takes as it
  /// arrives, from [`Handler::on_body`].
  Parked,
}

/// How the handler takes the body of a request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BodyMode {
  /// Buffered, up to [`H3Params::max_request_body`]: the request goes to the handler once
  /// complete.
  #[default]
  Buffer,
  /// As it arrives: the request goes to the handler once its head is read, with an empty body,
  /// and the payloads of its DATA frames go to [`Handler::on_body`].
  Stream,
}

/// What answers the requests of the connections of an [`H3Server`].
pub trait Handler {
  /// How the body of `req`, whose head was read, is taken. Defaults to [`BodyMode::Buffer`].
  #[inline]
  fn body_mode(&mut self, req: &Request<'_>) -> BodyMode {
    let _req = req;
    BodyMode::Buffer
  }

  /// A request arrived: complete, or its head only for a body taken as it arrives. Answer it now
  /// through `cx` and return [`ReqOutcome::Responded`], or return [`ReqOutcome::Parked`] to answer
  /// it later. `req` is not kept after the call.
  ///
  /// # Errors
  ///
  /// An error resets the stream of the request with `H3_INTERNAL_ERROR`, unless it closes the
  /// connection ([`crate::Error::close_code`]); so does [`ReqOutcome::Responded`] without a whole
  /// answer.
  fn on_request(&mut self, cx: &mut ReqCtx<'_, '_>, req: &Request<'_>)
  -> crate::Result<ReqOutcome>;

  /// The next bytes of the body of the request of `stream`, for [`BodyMode::Stream`]: `fin` says
  /// that the request ends with them (its trailers, if any, were checked and dropped). Once the
  /// request ended, one that is not answered whole is parked.
  ///
  /// # Errors
  ///
  /// As [`Self::on_request`].
  #[inline]
  fn on_body(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    stream: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    let _args = (cx, stream, data, fin);
    Ok(())
  }

  /// The request of `stream`, parked, is resumed ([`H3Server::resume`]): answer it, or park it
  /// again. Called also for a request that the peer abandoned meanwhile, whose answer then fails.
  /// Defaults to parking it again: a handler that never parks never gets this call.
  ///
  /// # Errors
  ///
  /// As [`Self::on_request`].
  #[inline]
  fn resume(&mut self, cx: &mut ReqCtx<'_, '_>, stream: StreamId) -> crate::Result<ReqOutcome> {
    let _args = (cx, stream);
    Ok(ReqOutcome::Parked)
  }

  /// The peer abandoned the request of `stream` of the connection of `conn`, which the handler
  /// held unanswered (RESET_STREAM or STOP_SENDING): nothing will be answered, and what would
  /// answer it can go.
  #[inline]
  fn on_abandoned(&mut self, conn: ConnHandle, stream: StreamId) {
    let _args = (conn, stream);
  }

  /// The connection of `conn` is over: what would answer its held requests can go.
  #[inline]
  fn on_conn_closed(&mut self, conn: ConnHandle) {
    let _conn = conn;
  }

  /// A parked request that is ready to be resumed, if any: a driver calls this at each turn
  /// until it returns `None`, and resumes each with [`H3Server::resume_in`]. `waker` wakes the
  /// driver for another turn, from any thread: a handler whose parked requests wait for work done
  /// elsewhere keeps it, and wakes it once some are ready. Defaults to `None`: a handler whose
  /// driver resumes its requests itself, or that never parks, needs nothing here.
  #[inline]
  fn poll_ready(&mut self, waker: &core::task::Waker) -> Option<(ConnHandle, StreamId)> {
    let _waker = waker;
    None
  }
}

/// A response body.
#[derive(Clone, Debug)]
pub enum Body<'a> {
  /// No content.
  Empty,
  /// Bytes, copied into the stream.
  Bytes(&'a [u8]),
  /// Bytes sent by reference, not copied ([`BodyRef`]).
  Ref(BodyRef),
}

impl Body<'_> {
  fn len(&self) -> usize {
    match self {
      Self::Empty => 0,
      Self::Bytes(bytes) => bytes.len(),
      Self::Ref(body) => usize::try_from(body.len()).unwrap_or(usize::MAX),
    }
  }
}

/// The response buffers of a worker and what encodes the heads of its responses.
#[derive(Debug)]
pub(crate) struct Out {
  date: DateLine,
  fields: Vec<u8>,
  frame: Vec<u8>,
  heads: ResponseHeads,
}

/// What a handler answers a request through.
#[derive(Debug)]
pub struct ReqCtx<'c, 'a> {
  cx: &'c mut ConnCtx<'a, H3ConnState>,
  encoder: &'c mut Encoder,
  head_sent: bool,
  is_head: bool,
  out: &'c mut Out,
  params: &'c H3Params,
  responded: bool,
  stream: StreamId,
}

impl ReqCtx<'_, '_> {
  /// The handle of the connection of the request, which names it from outside of the callbacks
  /// ([`rimu_quic::Endpoint::with_conn`], [`H3Server::resume_in`]).
  #[inline]
  pub const fn conn(&self) -> ConnHandle {
    self.cx.handle()
  }

  /// The time of the call that runs.
  #[inline]
  pub const fn now_us(&self) -> u64 {
    self.cx.now_us()
  }

  /// The address of the peer.
  #[inline]
  pub const fn peer(&self) -> IpAddr {
    self.cx.peer()
  }

  /// The stream of the request.
  #[inline]
  pub const fn stream(&self) -> StreamId {
    self.stream
  }

  /// If the head of the response was written.
  #[inline]
  pub const fn head_sent(&self) -> bool {
    self.head_sent
  }

  /// If the response was written whole, with its FIN.
  #[inline]
  pub const fn responded(&self) -> bool {
    self.responded
  }

  /// The bytes written to the stream of the request that were not sent yet: a handler that streams
  /// a response writes more when this is low.
  #[inline]
  pub fn unsent(&self) -> usize {
    self.cx.unsent_on(self.stream)
  }

  /// Answers with the field section `encoded_headers`, encoded with QPACK by the static table
  /// ([`rimu_qpack::encode_static`], or [`crate::ResponseHeads`]), and `body`: one write of a
  /// HEADERS frame, a DATA frame (if `body` is not empty) and the FIN, which leave in one STREAM
  /// frame when they fit in a packet.
  ///
  /// # Errors
  ///
  /// [`Http3Error::AlreadyResponded`] if the head was written, or what the stream refuses.
  #[inline]
  pub fn respond(&mut self, encoded_headers: &[u8], body: &[u8]) -> crate::Result<()> {
    self.check_no_head()?;
    let rslt = write_response(self.cx, &mut self.out.frame, self.stream, encoded_headers, body);
    keep_small(&mut self.out.frame);
    rslt?;
    self.head_sent = true;
    self.responded = true;
    Ok(())
  }

  /// [`Self::respond`] with a body that is not copied: the HEADERS frame and the header of the
  /// DATA frame are written by copy, then the body by reference, with the FIN.
  ///
  /// # Errors
  ///
  /// As [`Self::respond`].
  #[inline]
  pub fn respond_body(&mut self, encoded_headers: &[u8], body: BodyRef) -> crate::Result<()> {
    self.check_no_head()?;
    let frame = &mut self.out.frame;
    frame.clear();
    push_frame_header(frame, H3FrameTy::Headers, encoded_headers.len())?;
    frame.extend_from_slice(encoded_headers);
    if body.is_empty() {
      self.cx.write(self.stream, frame, true)?;
    } else {
      push_frame_header(frame, H3FrameTy::Data, usize::try_from(body.len()).unwrap_or(usize::MAX))?;
      self.cx.write(self.stream, frame, false)?;
      self.cx.write_body(self.stream, body, true)?;
    }
    keep_small(frame);
    self.head_sent = true;
    self.responded = true;
    Ok(())
  }

  /// [`Self::respond`] with `fields`, encoded with the static table of QPACK, or with the
  /// dynamic table of the connection when [`H3Params::response_encoder`] asks for one. Names must
  /// be lowercase.
  ///
  /// # Errors
  ///
  /// As [`Self::respond`].
  #[inline]
  pub fn respond_fields(&mut self, fields: &[(&[u8], &[u8])], body: &[u8]) -> crate::Result<()> {
    self.check_no_head()?;
    self.encode_fields(fields.iter().map(Field::from));
    let Out { fields: section, frame, .. } = &mut *self.out;
    let rslt = write_response(self.cx, frame, self.stream, section, body);
    keep_small(section);
    keep_small(frame);
    rslt?;
    self.head_sent = true;
    self.responded = true;
    Ok(())
  }

  /// Answers with `fields` and `body`, as RFC 9110 has it for the method of the request: a
  /// response to `HEAD` has the fields that `GET` would get, `content-length` included, and no
  /// content (section 9.3.2); 1xx and 204 have neither content nor `content-length` (section
  /// 8.6), 304 no content and no `content-length` (section 15.4.5). The others carry
  /// `content-length` with [`H3Params::content_length`], and every one `date` with
  /// [`H3Params::date`]. The head is kept encoded per combination of `:status`, `content-type`,
  /// `content-encoding` and `vary` ([`crate::ResponseHeads`]), unless the dynamic table encodes it.
  ///
  /// # Errors
  ///
  /// As [`Self::respond`].
  #[inline]
  pub fn respond_with(&mut self, fields: &ResponseFields<'_>, body: Body<'_>) -> crate::Result<()> {
    let code = fields.status;
    let without_length = (100..200).contains(&code) || code == 204 || code == 304;
    let no_content = without_length || self.is_head;
    let length = if without_length {
      None
    } else if self.is_head || self.params.content_length {
      Some(body.len())
    } else {
      None
    };
    self.send_head_of(fields, length)?;
    let rslt = match body {
      _ if no_content => self.send_data(&[], true),
      Body::Empty => self.send_data(&[], true),
      Body::Bytes(bytes) => self.send_data(bytes, true),
      Body::Ref(body) => self.send_body(body, true),
    };
    if rslt.is_err() {
      self.responded = false;
    }
    rslt
  }

  /// Writes the head of a response of `fields` (see [`Self::respond_with`] for what is added to
  /// it), with `content-length` if `length`; its content follows with [`Self::send_data`] or
  /// [`Self::send_body`], now or later (the handler parks the request meanwhile).
  ///
  /// # Errors
  ///
  /// As [`Self::respond`].
  #[inline]
  pub fn send_head_with(
    &mut self,
    fields: &ResponseFields<'_>,
    length: Option<usize>,
  ) -> crate::Result<()> {
    self.send_head_of(fields, length)
  }

  /// Writes the head of a response, the field section `encoded_headers` (static table), without
  /// the FIN: its content follows with [`Self::send_data`] or [`Self::send_body`].
  ///
  /// # Errors
  ///
  /// As [`Self::respond`].
  #[inline]
  pub fn send_head(&mut self, encoded_headers: &[u8]) -> crate::Result<()> {
    self.check_no_head()?;
    let frame = &mut self.out.frame;
    frame.clear();
    push_frame_header(frame, H3FrameTy::Headers, encoded_headers.len())?;
    frame.extend_from_slice(encoded_headers);
    let rslt = self.cx.write(self.stream, frame, false);
    keep_small(frame);
    rslt?;
    self.head_sent = true;
    Ok(())
  }

  /// Writes `bytes` in a DATA frame (none if empty), copied, and the FIN if `fin`, after the
  /// head.
  ///
  /// # Errors
  ///
  /// [`Http3Error::NoHead`] before the head, [`Http3Error::AlreadyResponded`] after the FIN, or
  /// what the stream refuses.
  #[inline]
  pub fn send_data(&mut self, bytes: &[u8], fin: bool) -> crate::Result<()> {
    self.check_open_body()?;
    if !bytes.is_empty() {
      let mut header = [0u8; 16];
      let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
      let header_len = encode_frame_header(H3FrameTy::Data, len, &mut header)
        .ok_or(crate::Error::Http3(Http3Error::BufferTooSmall))?;
      self.cx.write(self.stream, header.get(..header_len).unwrap_or_default(), false)?;
    }
    self.cx.write(self.stream, bytes, fin)?;
    self.responded |= fin;
    Ok(())
  }

  /// [`Self::send_data`] of a body that is not copied ([`BodyRef`]).
  ///
  /// # Errors
  ///
  /// As [`Self::send_data`].
  #[inline]
  pub fn send_body(&mut self, body: BodyRef, fin: bool) -> crate::Result<()> {
    self.check_open_body()?;
    if body.is_empty() {
      self.cx.write(self.stream, &[], fin)?;
    } else {
      let mut header = [0u8; 16];
      let header_len = encode_frame_header(H3FrameTy::Data, body.len().into(), &mut header)
        .ok_or(crate::Error::Http3(Http3Error::BufferTooSmall))?;
      self.cx.write(self.stream, header.get(..header_len).unwrap_or_default(), false)?;
      self.cx.write_body(self.stream, body, fin)?;
    }
    self.responded |= fin;
    Ok(())
  }

  fn check_no_head(&self) -> crate::Result<()> {
    if self.head_sent {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::AlreadyResponded));
    }
    Ok(())
  }

  fn check_open_body(&self) -> crate::Result<()> {
    if !self.head_sent {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::NoHead));
    }
    if self.responded {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::AlreadyResponded));
    }
    Ok(())
  }

  // `fields` into the section buffer of the worker, by the static table or the dynamic one
  fn encode_fields<'f>(&mut self, fields: impl Iterator<Item = Field<'f>>) {
    let section = &mut self.out.fields;
    section.clear();
    if self.encoder.config().max_table_capacity == 0 {
      encode_static(fields, section);
    } else {
      self.encoder.encode(self.stream.0, fields, section);
    }
  }

  fn send_head_of(
    &mut self,
    fields: &ResponseFields<'_>,
    length: Option<usize>,
  ) -> crate::Result<()> {
    self.check_no_head()?;
    let date = self.params.date.then(|| self.out.date.line()).filter(|el| !el.is_empty());
    if self.encoder.config().max_table_capacity == 0 {
      let section = self.out.heads.encode(fields, length, date);
      let frame = &mut self.out.frame;
      frame.clear();
      push_frame_header(frame, H3FrameTy::Headers, section.len())?;
      frame.extend_from_slice(section);
    } else {
      let mut status = [0u8; 20];
      let mut digits = [0u8; 20];
      let status = decimal(usize::from(fields.status), &mut status);
      let date_text = self.out.date.text();
      let date = date.map(|_| date_text);
      let length = length.map(|el| decimal(el, &mut digits));
      let section = &mut self.out.fields;
      section.clear();
      let firsts = [
        Some(Field::new(b":status", status)),
        fields.content_type.map(|el| Field::new(b"content-type", el)),
        fields.content_encoding.map(|el| Field::new(b"content-encoding", el)),
        fields.vary.map(|el| Field::new(b"vary", el)),
        date.map(|el| Field::new(b"date", el)),
        length.map(|el| Field::new(b"content-length", el)),
      ];
      let others = fields.others.iter().filter(|el| {
        !matches!(
          crate::response::known(el.0),
          Some(crate::response::Known::ConnectionSpecific | crate::response::Known::ContentLength)
        ) && !(date.is_some() && crate::response::known(el.0) == Some(crate::response::Known::Date))
      });
      self.encoder.encode(
        self.stream.0,
        firsts.into_iter().flatten().chain(others.map(Field::from)),
        section,
      );
      let Out { fields: section, frame, .. } = &mut *self.out;
      frame.clear();
      push_frame_header(frame, H3FrameTy::Headers, section.len())?;
      frame.extend_from_slice(section);
      keep_small(section);
    }
    let frame = &mut self.out.frame;
    let rslt = self.cx.write(self.stream, frame, false);
    keep_small(frame);
    rslt?;
    self.head_sent = true;
    Ok(())
  }
}

/// HTTP/3 over the QUIC connections of a worker: their control and QPACK streams, the requests
/// that they carry, read, checked and handed to `handler`, and the pool of their state. See the
/// [crate documentation](crate).
#[derive(Debug)]
pub struct H3Server<H> {
  /// What answers the requests.
  pub handler: H,
  /// The connections established, by peer address, for the tests.
  #[cfg(any(test, feature = "__fuzz"))]
  pub(crate) established: Vec<(IpAddr, ConnHandle)>,
  out: Out,
  params: H3Params,
  #[allow(clippy::vec_box, reason = "boxes go between connections and the pool without a copy")]
  pool: Vec<Box<H3Conn>>,
  // The bytes that the boxes of the pool take
  pool_bytes: usize,
  qpack: QpackCounters,
  // Requests given to the handler
  requests: u64,
  // The streams that inserts unblocked, taken from the decoder
  unblocked: Vec<u64>,
}

/// The field sections of requests that the connections of a worker decoded, and those of them
/// that the decode memo replayed: the hit rate of the memo is their ratio.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QpackCounters {
  /// Field sections decoded, heads and trailers, replays included.
  pub sections: u64,
  /// Of [`Self::sections`], those that the memo replayed.
  pub memo_hits: u64,
}

// What reading the bytes of a request stream came to.
enum Parsed {
  // The request was answered, refused or parked: nothing waits
  Done,
  // The bytes from this offset on wait for the ones that follow them; `true` if they are the start
  // of a frame that fits in what the connection retains (ruling T13-b)
  More(usize, bool),
  // The field section of the HEADERS frame at this offset waits for QPACK inserts
  Blocked(usize),
}

// What decoding a field section came to.
enum Section {
  // The stream goes on
  Read,
  // The request was refused
  Done,
  // The section waits for QPACK inserts
  Blocked,
}

impl<H> H3Server<H>
where
  H: Handler,
{
  /// The bytes that the boxes of the pool take at most (review V4): a box that would pass it is
  /// dropped instead of pooled.
  pub const POOL_BYTES: usize = 4 << 20;
  /// The boxes that [`Self::trim_idle`] keeps at most.
  pub const IDLE_POOLED: usize = 4;
  /// The bytes that the boxes that [`Self::trim_idle`] keeps take at most.
  const IDLE_POOL_BYTES: usize = 512 * 1024;

  /// The connections of a worker, with `params`, whose requests `handler` answers.
  #[inline]
  pub const fn new(handler: H, params: H3Params) -> Self {
    Self {
      handler,
      #[cfg(any(test, feature = "__fuzz"))]
      established: Vec::new(),
      out: Out {
        date: DateLine::new(),
        fields: Vec::new(),
        frame: Vec::new(),
        heads: ResponseHeads::new(),
      },
      params,
      pool: Vec::new(),
      pool_bytes: 0,
      qpack: QpackCounters { sections: 0, memo_hits: 0 },
      requests: 0,
      unblocked: Vec::new(),
    }
  }

  /// The settings of the connections.
  #[inline]
  pub const fn params(&self) -> &H3Params {
    &self.params
  }

  /// See [`QpackCounters`].
  #[inline]
  pub const fn qpack_counters(&self) -> QpackCounters {
    self.qpack
  }

  /// The requests given to the handler ([`Handler::on_request`]).
  #[inline]
  pub const fn requests(&self) -> u64 {
    self.requests
  }

  /// The time, `unix_secs` seconds after the Unix epoch, for the `date` of responses
  /// ([`H3Params::date`]): call it at each turn of the worker (it encodes the line again once a
  /// second).
  #[inline]
  pub fn set_date(&mut self, unix_secs: u64) {
    self.out.date.set(unix_secs);
  }

  /// [`Self::set_date`] from the system clock.
  #[cfg(feature = "std")]
  #[inline]
  pub fn refresh_date(&mut self) {
    let secs = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(0, |el| el.as_secs());
    self.set_date(secs);
  }

  /// Resumes the request of `stream` that the handler holds ([`Handler::resume`]), from the
  /// context of its connection.
  ///
  /// # Errors
  ///
  /// What closes the connection with a transport error, as from a callback.
  #[inline]
  pub fn resume(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    stream: StreamId,
  ) -> rimu_quic::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = self.resume_request(&mut conn, cx, stream);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  /// [`Self::resume`] of the request of `stream` on the connection of `conn` of `endpoint`, whose
  /// application is `app`, at `now_us`: what a driver calls when what a parked request waited for
  /// is there. `None` if the connection is gone.
  #[inline]
  pub fn resume_in(
    endpoint: &mut Endpoint<Self>,
    app: &mut Self,
    now_us: u64,
    conn: ConnHandle,
    stream: StreamId,
  ) -> Option<rimu_quic::Result<()>> {
    endpoint.with_conn(now_us, conn, app, |app, cx| app.resume(cx, stream))
  }

  /// Frees all but a few boxes of the pool, and the response buffers, for a worker that has no
  /// connection (an idle worker).
  #[inline]
  pub fn trim_idle(&mut self) {
    while self.pool.len() > Self::IDLE_POOLED || self.pool_bytes > Self::IDLE_POOL_BYTES {
      let Some(conn) = self.pool.pop() else {
        break;
      };
      self.pool_bytes = self.pool_bytes.saturating_sub(conn.heap_bytes());
    }
    self.out.fields = Vec::new();
    self.out.frame = Vec::new();
    self.unblocked = Vec::new();
  }

  /// The boxes that wait in the pool.
  #[inline]
  pub fn pooled(&self) -> usize {
    self.pool.len()
  }

  /// The bytes that the boxes of the pool take.
  #[inline]
  pub fn pooled_bytes(&self) -> usize {
    self.pool_bytes
  }

  /// The capacity of the response buffers of the worker.
  #[inline]
  pub fn scratch_bytes(&self) -> usize {
    self.out.frame.capacity().saturating_add(self.out.fields.capacity())
  }

  /// If no box of the pool holds state of a connection.
  #[cfg(test)]
  pub(crate) fn pool_is_clear(&self) -> bool {
    self.pool.iter().all(|el| el.is_clear())
  }

  // The context of the request of entry `idx` of `conn`, with its flags
  fn req_ctx<'c, 'a>(
    out: &'c mut Out,
    params: &'c H3Params,
    encoder: &'c mut Encoder,
    cx: &'c mut ConnCtx<'a, H3ConnState>,
    req: &Req,
  ) -> ReqCtx<'c, 'a> {
    ReqCtx {
      cx,
      encoder,
      head_sent: req.head_sent,
      is_head: req.is_head,
      out,
      params,
      responded: req.responded,
      stream: req.id,
    }
  }

  // Calls the handler with request `idx`: complete, or its head for a body taken as it arrives.
  fn dispatch(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<()> {
    let Self { handler, out, params, requests, .. } = self;
    let H3Conn { encoder, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(());
    };
    req.dispatched = true;
    let request = req.request();
    let mut rcx = Self::req_ctx(out, params, encoder, cx, req);
    *requests = requests.wrapping_add(1);
    let outcome = handler.on_request(&mut rcx, &request);
    let (head_sent, responded) = (rcx.head_sent, rcx.responded);
    if let Some(req) = conn.reqs.get_mut(idx) {
      req.head_sent = head_sent;
      req.responded = responded;
    }
    after_handler(conn, cx, idx, outcome)
  }

  // Gives the next bytes of the body of request `idx`, which the handler takes as they arrive.
  // `false` if the request is gone (a stream error).
  fn body_part(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<bool> {
    let Self { handler, out, params, .. } = self;
    let H3Conn { encoder, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(false);
    };
    let id = req.id;
    let mut rcx = Self::req_ctx(out, params, encoder, cx, req);
    let rslt = handler.on_body(&mut rcx, id, data, fin);
    let (head_sent, responded) = (rcx.head_sent, rcx.responded);
    if let Some(req) = conn.reqs.get_mut(idx) {
      req.head_sent = head_sent;
      req.responded = responded;
    }
    match rslt {
      Ok(()) => Ok(true),
      Err(err) if err.close_code().is_some() => Err(err),
      Err(_) => {
        stream_error(conn, cx, idx, H3ErrorCode::InternalError)?;
        Ok(false)
      }
    }
  }

  // The end of request `idx`, all of which arrived.
  fn complete(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<()> {
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(());
    };
    let received =
      if req.streaming { req.received } else { u64::try_from(req.body.len()).unwrap_or(u64::MAX) };
    if req.head.content_length().is_some_and(|el| el != received) {
      return stream_error(conn, cx, idx, H3ErrorCode::MessageError);
    }
    if !req.streaming {
      return self.dispatch(conn, cx, idx);
    }
    if !self.body_part(conn, cx, idx, &[], true)? {
      return Ok(());
    }
    match conn.reqs.get(idx) {
      Some(req) if req.responded => conn.free_req(idx),
      Some(_) => conn.park(idx),
      None => {}
    }
    Ok(())
  }

  // Reads what arrived on request stream `id`.
  fn request_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    let idx = match conn.req_idx(id) {
      Some(elem) => elem,
      None => {
        // After a GOAWAY, what it did not accept is refused (RFC 9114 section 5.2)
        if conn.goaway.is_some_and(|el| id.0 >= el) {
          return reject(conn, cx, id, H3ErrorCode::RequestRejected);
        }
        conn.next_request = conn.next_request.max(id.0.wrapping_add(4));
        conn.take_req(id)?
      }
    };
    let stash_max = self.stash_max();
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(());
    };
    if req.blocked || !req.stash.is_empty() {
      // What arrives behind bytes that wait, waits with them
      if req.stash.len().saturating_add(data.len()) > stash_max {
        return stream_error(conn, cx, idx, H3ErrorCode::ExcessiveLoad);
      }
      if !reserve_in(conn, idx, data.len(), |el| (&mut el.stash, None))? {
        return self.refuse(conn, cx, idx, b"413");
      }
      let Some(req) = conn.reqs.get_mut(idx) else {
        return Ok(());
      };
      req.stash.extend_from_slice(data);
      req.fin |= fin;
      if req.blocked {
        return Ok(());
      }
      return self.read_stash(conn, cx, idx);
    }
    let (pos, blocked) = match self.parse(conn, cx, idx, data, fin)? {
      Parsed::Done => return Ok(()),
      Parsed::More(pos, fits) => (pos, !fits),
      Parsed::Blocked(pos) => (pos, true),
    };
    // Retained bytes come again with the next ones in one block of 4 KiB: what does not fit there
    // whole waits in the head buffer of the request
    let rest = data.get(pos..).unwrap_or_default();
    if !blocked && rest.len() < RETAIN_MAX {
      return Ok(cx.retain(rest.len())?);
    }
    if !reserve_in(conn, idx, rest.len(), |el| (&mut el.stash, None))? {
      return self.refuse(conn, cx, idx, b"413");
    }
    let Some(req) = conn.reqs.get_mut(idx) else {
      return Ok(());
    };
    req.stash.extend_from_slice(rest);
    req.fin = fin;
    Ok(())
  }

  // Reads the frames of request `idx` in `input`, from the frame that the stream is in. `fin`: the
  // stream ends with `input`.
  fn parse(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    input: &[u8],
    fin: bool,
  ) -> crate::Result<Parsed> {
    let max_body = u64::from(self.params.max_request_body);
    let max_section = u64::from(self.params.max_field_section_size);
    let mut fits = true;
    let mut pos = 0usize;
    loop {
      let rest = input.get(pos..).unwrap_or_default();
      let Some(req) = conn.reqs.get_mut(idx) else {
        return Ok(Parsed::Done);
      };
      match req.frame {
        FrameLeft::Data(left) => {
          let take = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
          let chunk = rest.get(..take).unwrap_or_default();
          let left = left.wrapping_sub(u64::try_from(take).unwrap_or(u64::MAX));
          req.frame = if left == 0 { FrameLeft::None } else { FrameLeft::Data(left) };
          req.received = req.received.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
          if req.streaming {
            if !chunk.is_empty() && !self.body_part(conn, cx, idx, chunk, false)? {
              return Ok(Parsed::Done);
            }
          } else {
            if !reserve_in(conn, idx, take, |el| (&mut el.body, el.head.content_length()))? {
              self.refuse(conn, cx, idx, b"413")?;
              return Ok(Parsed::Done);
            }
            let Some(req) = conn.reqs.get_mut(idx) else {
              return Ok(Parsed::Done);
            };
            req.body.extend_from_slice(chunk);
          }
          pos = pos.wrapping_add(take);
          if left > 0 {
            break;
          }
          continue;
        }
        FrameLeft::Skip(left) => {
          let take = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
          pos = pos.wrapping_add(take);
          let left = left.wrapping_sub(u64::try_from(take).unwrap_or(u64::MAX));
          req.frame = if left == 0 { FrameLeft::None } else { FrameLeft::Skip(left) };
          if left > 0 {
            break;
          }
          continue;
        }
        FrameLeft::None => {}
      }
      let Some((ty, len, header_len)) = decode_frame_header(rest)? else {
        break;
      };
      match ty {
        H3FrameTy::Headers => {
          if !matches!(req.phase, Phase::Head | Phase::Body) {
            return Err(unexpected_frame());
          }
          if len > max_section {
            self.refuse(conn, cx, idx, b"431")?;
            return Ok(Parsed::Done);
          }
          let end = usize::try_from(len).ok().and_then(|el| el.checked_add(header_len));
          let Some(section) = end.and_then(|el| rest.get(header_len..el)) else {
            fits = end.is_some_and(|el| el <= RETAIN_MAX);
            break;
          };
          match self.section(conn, cx, idx, section)? {
            Section::Read => {}
            Section::Done => return Ok(Parsed::Done),
            Section::Blocked => return Ok(Parsed::Blocked(pos)),
          }
          pos = pos.wrapping_add(header_len).wrapping_add(section.len());
        }
        H3FrameTy::Data => {
          // DATA before HEADERS, or after the trailers (RFC 9114 section 4.1)
          if req.phase != Phase::Body {
            return Err(unexpected_frame());
          }
          if !req.streaming {
            let body_len = u64::try_from(req.body.len()).unwrap_or(u64::MAX);
            let frame_len = usize::try_from(len).unwrap_or(usize::MAX);
            if body_len.saturating_add(len) > max_body
              || !fits_in(conn, idx, frame_len, |el| &mut el.body)
            {
              self.refuse(conn, cx, idx, b"413")?;
              return Ok(Parsed::Done);
            }
          }
          let Some(req) = conn.reqs.get_mut(idx) else {
            return Ok(Parsed::Done);
          };
          req.frame = if len == 0 { FrameLeft::None } else { FrameLeft::Data(len) };
          pos = pos.wrapping_add(header_len);
        }
        H3FrameTy::Unknown(_) => {
          req.frame = if len == 0 { FrameLeft::None } else { FrameLeft::Skip(len) };
          pos = pos.wrapping_add(header_len);
        }
        H3FrameTy::CancelPush
        | H3FrameTy::Goaway
        | H3FrameTy::MaxPushId
        | H3FrameTy::PushPromise
        | H3FrameTy::Settings => return Err(unexpected_frame()),
      }
    }
    if !fin {
      return Ok(Parsed::More(pos, fits));
    }
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(Parsed::Done);
    };
    if pos < input.len() || req.frame != FrameLeft::None {
      cold_path();
      return Err(close(H3ErrorCode::FrameError, Http3Error::TruncatedFrame));
    }
    match req.phase {
      Phase::Head => stream_error(conn, cx, idx, H3ErrorCode::RequestIncomplete)?,
      Phase::Body | Phase::Trailers => self.complete(conn, cx, idx)?,
      Phase::Free | Phase::Parked => {}
    }
    Ok(Parsed::Done)
  }

  // Reads what waits of request `idx`.
  fn read_stash(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<()> {
    let Some(req) = conn.reqs.get_mut(idx) else {
      return Ok(());
    };
    let mut stash = core::mem::take(&mut req.stash);
    let fin = req.fin;
    let rslt = self.parse(conn, cx, idx, &stash, fin);
    match rslt {
      Ok(Parsed::More(pos, _) | Parsed::Blocked(pos)) => drain_front(&mut stash, pos),
      Ok(Parsed::Done) | Err(_) => stash.clear(),
    }
    // The entry keeps the storage, whether it still holds the request or not; small if not
    if let Some(req) = conn.reqs.get_mut(idx) {
      req.stash = stash;
    }
    conn.trim_free_stash(idx);
    rslt.map(|_| ())
  }

  // Refuses request `idx` with a response of `status` (413 or 431) and stops reading it (RFC 9114
  // section 4.1).
  fn refuse(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    status: &[u8],
  ) -> crate::Result<()> {
    let Some(id) = conn.reqs.get(idx).map(|el| el.id) else {
      return Ok(());
    };
    let Out { fields, frame, .. } = &mut self.out;
    fields.clear();
    encode_static([(&b":status"[..], status)], fields);
    // A stream that the client stopped can not be answered: the stop is what it gets
    let _rslt = write_response(cx, frame, id, fields, &[]);
    keep_small(frame);
    cx.stop_sending(id, H3ErrorCode::NoError.code());
    conn.decoder.cancel_stream(id.0)?;
    conn.free_req(idx);
    Ok(())
  }

  fn resume_request(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    stream: StreamId,
  ) -> crate::Result<()> {
    let idx = conn
      .req_idx(stream)
      .filter(|el| conn.reqs.get(*el).is_some_and(|req| req.dispatched && !req.responded));
    let Self { handler, out, params, .. } = self;
    let H3Conn { encoder, reqs, .. } = &mut *conn;
    // A request that is gone: the handler is told, and its answer fails on the stream
    let gone = Req::gone(stream);
    let req = idx.and_then(|el| reqs.get(el)).unwrap_or(&gone);
    let mut rcx = Self::req_ctx(out, params, encoder, cx, req);
    let outcome = handler.resume(&mut rcx, stream);
    let (head_sent, responded) = (rcx.head_sent, rcx.responded);
    let Some(idx) = idx else {
      return match outcome {
        Err(err) if err.close_code().is_some() => Err(err),
        _ => Ok(()),
      };
    };
    let Some(req) = conn.reqs.get_mut(idx) else {
      return Ok(());
    };
    req.head_sent = head_sent;
    req.responded = responded;
    if req.phase == Phase::Parked {
      return after_handler(conn, cx, idx, outcome);
    }
    // A body that still arrives: the request stays until it ends
    match outcome {
      Err(err) if err.close_code().is_some() => Err(err),
      Err(_) => stream_error(conn, cx, idx, H3ErrorCode::InternalError),
      Ok(ReqOutcome::Responded) if !responded => {
        stream_error(conn, cx, idx, H3ErrorCode::InternalError)
      }
      Ok(_) => Ok(()),
    }
  }

  // The field sections that waited for the inserts that arrived are read, with what followed them.
  fn retry_blocked(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
  ) -> crate::Result<()> {
    let mut unblocked = core::mem::take(&mut self.unblocked);
    unblocked.clear();
    unblocked.extend(conn.decoder.take_unblocked());
    let mut rslt = Ok(());
    for id in unblocked.iter().copied() {
      let Some(idx) = conn.req_idx(StreamId(id)) else {
        continue;
      };
      if let Some(req) = conn.reqs.get_mut(idx) {
        req.blocked = false;
      }
      rslt = self.read_stash(conn, cx, idx);
      if rslt.is_err() {
        break;
      }
    }
    self.unblocked = unblocked;
    rslt
  }

  // Decodes `section`, the payload of a HEADERS frame of request `idx`: its head or its trailers.
  fn section(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    section: &[u8],
  ) -> crate::Result<Section> {
    let max_body = u64::from(self.params.max_request_body);
    let max_section = u64::from(self.params.max_field_section_size);
    if conn.budget.is_tight() {
      // What entries without a request keep goes first (ruling T13-g)
      conn.reclaim();
    }
    let H3Conn { budget, decoder, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(Section::Done);
    };
    let id = req.id;
    let is_head = req.phase == Phase::Head;
    // The fields are checked, and the decoded size counted, as they are decoded: a short section
    // can reference a large entry many times
    let before = decoder.stats();
    let outcome = if is_head {
      req.head.clear();
      let head = &mut req.head;
      decoder.decode(id.0, section, |field: DecodedField<'_>| {
        head.push(field.name, field.value, field.static_ref, max_section, budget)
      })
    } else {
      let mut size = 0u64;
      decoder.decode(id.0, section, |field: DecodedField<'_>| {
        check_trailer(&mut size, field.name, field.value, max_section)
      })
    };
    let after = decoder.stats();
    let qpack = &mut self.qpack;
    qpack.sections = qpack.sections.wrapping_add(after.sections.wrapping_sub(before.sections));
    qpack.memo_hits = qpack.memo_hits.wrapping_add(after.memo_hits.wrapping_sub(before.memo_hits));
    match outcome {
      Ok(DecodeOutcome::Done { .. }) => {}
      Ok(DecodeOutcome::Blocked { .. }) => {
        req.blocked = true;
        return Ok(Section::Blocked);
      }
      Err(crate::Error::Http3(Http3Error::MalformedRequest)) => {
        stream_error(conn, cx, idx, H3ErrorCode::MessageError)?;
        return Ok(Section::Done);
      }
      Err(crate::Error::Http3(Http3Error::FieldSectionTooLarge)) => {
        self.refuse(conn, cx, idx, b"431")?;
        return Ok(Section::Done);
      }
      Err(crate::Error::Http3(Http3Error::BufferedLimit)) => {
        self.refuse(conn, cx, idx, b"413")?;
        return Ok(Section::Done);
      }
      Err(err) => return Err(err),
    }
    if !is_head {
      req.phase = Phase::Trailers;
      return Ok(Section::Read);
    }
    if req.head.check().is_err() {
      stream_error(conn, cx, idx, H3ErrorCode::MessageError)?;
      return Ok(Section::Done);
    }
    req.phase = Phase::Body;
    req.is_head = req.head.method() == b"HEAD";
    let request = req.request();
    if self.handler.body_mode(&request) == BodyMode::Stream {
      if let Some(req) = conn.reqs.get_mut(idx) {
        req.streaming = true;
      }
      return self.dispatch_head(conn, cx, idx);
    }
    // A body that is announced larger than what is allowed, or than what the buffers of the
    // connection can take, is refused before it arrives
    let length = conn.reqs.get(idx).and_then(|el| el.head.content_length());
    let announced = length.map(|el| usize::try_from(el).unwrap_or(usize::MAX)).unwrap_or(0);
    if length.is_some_and(|el| el > max_body) || !fits_in(conn, idx, announced, |el| &mut el.body) {
      self.refuse(conn, cx, idx, b"413")?;
      return Ok(Section::Done);
    }
    Ok(Section::Read)
  }

  // The head of request `idx`, whose body the handler takes as it arrives, goes to the handler.
  fn dispatch_head(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<Section> {
    let Self { handler, out, params, requests, .. } = self;
    let H3Conn { encoder, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(Section::Done);
    };
    req.dispatched = true;
    let request = req.request();
    let mut rcx = Self::req_ctx(out, params, encoder, cx, req);
    *requests = requests.wrapping_add(1);
    let outcome = handler.on_request(&mut rcx, &request);
    let (head_sent, responded) = (rcx.head_sent, rcx.responded);
    if let Some(req) = conn.reqs.get_mut(idx) {
      req.head_sent = head_sent;
      req.responded = responded;
    }
    match outcome {
      Err(err) if err.close_code().is_some() => Err(err),
      Ok(ReqOutcome::Responded) if responded => Ok(Section::Read),
      Ok(ReqOutcome::Parked) => Ok(Section::Read),
      // It failed, or claims an answer that it did not give
      _ => {
        stream_error(conn, cx, idx, H3ErrorCode::InternalError)?;
        Ok(Section::Done)
      }
    }
  }

  // What may wait for a request: its body, its head and its trailers, with room for frame
  // headers and unknown frames.
  fn stash_max(&self) -> usize {
    let params = &self.params;
    let max = u64::from(params.max_request_body)
      .saturating_add(u64::from(params.max_field_section_size).saturating_mul(2))
      .saturating_add(STASH_SLACK);
    usize::try_from(max).unwrap_or(usize::MAX)
  }

  // A box from the pool, cleared when it was pooled, or a new one.
  fn take_conn(&mut self) -> Box<H3Conn> {
    if let Some(conn) = self.pool.pop() {
      self.pool_bytes = self.pool_bytes.saturating_sub(conn.heap_bytes());
      return conn;
    }
    H3Conn::new(&self.params)
  }

  // Reads what arrived on unidirectional stream `id` of the peer.
  fn uni_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    if conn.peer_control == Some(id) {
      return control_data(conn, cx, data, fin);
    }
    if conn.peer_encoder == Some(id) {
      return self.encoder_data(conn, cx, data, fin);
    }
    if conn.peer_decoder == Some(id) {
      return decoder_data(conn, data, fin);
    }
    let Some((ty, len)) = decode_varint(data) else {
      // The type is cut: it comes again with what follows. A stream that ends before it is
      // ignored.
      return if fin { Ok(()) } else { Ok(cx.retain(data.len())?) };
    };
    let slot = match u8::try_from(ty) {
      Ok(CONTROL_STREAM) => &mut conn.peer_control,
      Ok(ENCODER_STREAM) => &mut conn.peer_encoder,
      Ok(DECODER_STREAM) => &mut conn.peer_decoder,
      _ if ty == PUSH_STREAM => {
        return Err(close(H3ErrorCode::StreamCreationError, Http3Error::PushStreamFromClient));
      }
      _ => {
        // RFC 9114 section 6.2: an unknown type is not read
        cx.stop_sending(id, H3ErrorCode::StreamCreationError.code());
        return Ok(());
      }
    };
    if slot.is_some() {
      return Err(close(H3ErrorCode::StreamCreationError, Http3Error::SecondCriticalStream));
    }
    *slot = Some(id);
    self.uni_data(conn, cx, id, data.get(len..).unwrap_or_default(), fin)
  }

  // Reads what arrived on the QPACK encoder stream of the peer: the decoder keeps an instruction
  // that is cut until the rest of it arrives (no longer than four capacities).
  fn encoder_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    if fin {
      return Err(closed_critical_stream());
    }
    let before = conn.decoder.insert_count();
    conn.decoder.feed_encoder_stream(data)?;
    if conn.decoder.insert_count() > before {
      self.retry_blocked(conn, cx)?;
    }
    Ok(())
  }
}

impl<H> QuicApp for H3Server<H>
where
  H: Handler,
{
  type ConnState = H3ConnState;

  #[inline]
  fn on_established(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) -> rimu_quic::Result<()> {
    let mut conn = self.take_conn();
    conn.handle = cx.handle();
    #[cfg(any(test, feature = "__fuzz"))]
    self.established.push((cx.peer(), cx.handle()));
    let rslt = open_streams(&mut conn, cx, &self.params);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stream_data(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> rimu_quic::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = if id.is_uni() {
      self.uni_data(&mut conn, cx, id, data, fin)
    } else if id.is_client_bidi() {
      self.request_data(&mut conn, cx, id, data, fin)
    } else {
      Ok(())
    };
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    _code: u64,
  ) -> rimu_quic::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let held = conn.is_held(id);
    let rslt = reset_by_peer(&mut conn, cx, id);
    if held {
      self.handler.on_abandoned(conn.handle, id);
    }
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stop_sending(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    _code: u64,
  ) -> rimu_quic::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let held = conn.is_held(id);
    let rslt = stopped_by_peer(&mut conn, cx, id);
    if held {
      self.handler.on_abandoned(conn.handle, id);
    }
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_closed(&mut self, state: &mut H3ConnState) {
    let Some(mut conn) = state.conn.take() else {
      return;
    };
    if conn.live > 0 {
      self.handler.on_conn_closed(conn.handle);
    }
    // Cleared now, so that the pool holds no state of a connection (review V5)
    if self.pool.len() >= MAX_POOLED {
      return;
    }
    conn.release(&self.params);
    let bytes = conn.heap_bytes();
    if self.pool_bytes.saturating_add(bytes) <= Self::POOL_BYTES && self.pool.try_reserve(1).is_ok()
    {
      self.pool.push(conn);
      self.pool_bytes = self.pool_bytes.saturating_add(bytes);
    }
  }

  #[inline]
  fn on_flush(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) {
    let Some(mut conn) = cx.state.conn.take() else {
      return;
    };
    let rslt = flush_conn(&mut conn, cx);
    cx.state.conn = Some(conn);
    if let Err(err) = rslt {
      cold_path();
      let code = err.close_code().unwrap_or(H3ErrorCode::InternalError);
      cx.close(code.code(), b"");
    }
  }

  #[inline]
  fn on_shutdown(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) -> bool {
    let Some(conn) = cx.state.conn.as_ref() else {
      return false;
    };
    if conn.goaway.is_some() {
      return true;
    }
    // The lowest client stream that QUIC did not open: the streams below it are answered or
    // refused before the close (RFC 9114 section 5.2, ruling T13-h)
    let (control, id) = (conn.control, conn.next_request.max(cx.next_peer_bidi().0));
    let mut frame = [0u8; 16];
    let len = u64::try_from(varint_len(id)).unwrap_or(u64::MAX);
    let Some(header_len) = encode_frame_header(H3FrameTy::Goaway, len, &mut frame) else {
      return false;
    };
    let Some(id_len) = frame.get_mut(header_len..).and_then(|el| encode_varint(id, el)) else {
      return false;
    };
    let bytes = frame.get(..header_len.wrapping_add(id_len)).unwrap_or_default();
    if cx.write(control, bytes, false).is_err() {
      return false;
    }
    if let Some(conn) = cx.state.conn.as_mut() {
      conn.goaway = Some(id);
    }
    true
  }
}

// What a handler did with request `idx`, which arrived whole.
fn after_handler(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  idx: usize,
  outcome: crate::Result<ReqOutcome>,
) -> crate::Result<()> {
  let responded = conn.reqs.get(idx).is_some_and(|el| el.responded);
  match outcome {
    Err(err) if err.close_code().is_some() => Err(err),
    Ok(ReqOutcome::Parked) if !responded => {
      // What it held is not needed anymore: a parked request keeps small buffers only, which the
      // budget of the connection counts
      conn.park(idx);
      Ok(())
    }
    Ok(_) if responded => {
      conn.free_req(idx);
      Ok(())
    }
    // It failed, or claims an answer that it did not give
    _ => stream_error(conn, cx, idx, H3ErrorCode::InternalError),
  }
}

#[cold]
fn close(code: H3ErrorCode, error: Http3Error) -> crate::Error {
  crate::Error::Http3Close(code, error)
}

#[cold]
fn closed_critical_stream() -> crate::Error {
  close(H3ErrorCode::ClosedCriticalStream, Http3Error::ClosedCriticalStream)
}

// What a callback returns to the transport: a connection error is a close of the application that
// the callback asks for; an error of the transport goes back to it; any other error closes with
// H3_INTERNAL_ERROR.
fn conclude(cx: &mut ConnCtx<'_, H3ConnState>, rslt: crate::Result<()>) -> rimu_quic::Result<()> {
  let Err(err) = rslt else {
    return Ok(());
  };
  cold_path();
  if let Some(code) = err.close_code() {
    cx.close(code.code(), b"");
    return Ok(());
  }
  if let crate::Error::Quic(err) = err {
    return Err(err);
  }
  cx.close(H3ErrorCode::InternalError.code(), b"");
  Ok(())
}

// Reads what arrived on the control stream of the peer: SETTINGS first, then GOAWAY, MAX_PUSH_ID,
// CANCEL_PUSH and unknown frames (RFC 9114 sections 6.2.1 and 7.2).
fn control_data(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  data: &[u8],
  fin: bool,
) -> crate::Result<()> {
  let mut pos = 0usize;
  loop {
    let rest = data.get(pos..).unwrap_or_default();
    if conn.control_skip > 0 {
      let take = usize::try_from(conn.control_skip).unwrap_or(usize::MAX).min(rest.len());
      pos = pos.wrapping_add(take);
      conn.control_skip = conn.control_skip.wrapping_sub(u64::try_from(take).unwrap_or(0));
      if conn.control_skip > 0 {
        break;
      }
      continue;
    }
    let Some((ty, len, header_len)) = decode_frame_header(rest)? else {
      break;
    };
    if conn.settings.is_none() && ty != H3FrameTy::Settings {
      return Err(close(H3ErrorCode::MissingSettings, Http3Error::MissingSettings));
    }
    match ty {
      H3FrameTy::Unknown(_) => {
        conn.control_skip = len;
        pos = pos.wrapping_add(header_len);
        continue;
      }
      H3FrameTy::Data | H3FrameTy::Headers | H3FrameTy::PushPromise => {
        return Err(unexpected_frame());
      }
      H3FrameTy::Settings if conn.settings.is_some() => return Err(unexpected_frame()),
      H3FrameTy::CancelPush | H3FrameTy::Goaway | H3FrameTy::MaxPushId | H3FrameTy::Settings => {}
    }
    let Some(end) = usize::try_from(len)
      .ok()
      .and_then(|el| el.checked_add(header_len))
      .filter(|el| *el <= RETAIN_MAX)
    else {
      return Err(close(H3ErrorCode::ExcessiveLoad, Http3Error::ControlFrameTooLarge));
    };
    let Some(payload) = rest.get(header_len..end) else {
      break;
    };
    match ty {
      H3FrameTy::Settings => {
        let settings = H3Settings::decode(payload)?;
        conn.settings = Some(settings);
        // The dynamic table of responses, if any, within what the peer allows (RFC 9204 section
        // 3.2.3); a static-only encoder ignores them
        conn.encoder.set_peer_settings(rimu_qpack::Settings {
          max_table_capacity: settings.qpack_max_table_capacity,
          blocked_streams: settings.qpack_blocked_streams,
        })?;
      }
      H3FrameTy::Goaway => {
        // The push identifier of a client never grows (RFC 9114 section 5.2)
        let id = single_varint(payload)?;
        if conn.peer_goaway.is_some_and(|el| id > el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
        conn.peer_goaway = Some(id);
      }
      H3FrameTy::MaxPushId => {
        let id = single_varint(payload)?;
        if conn.max_push_id.is_some_and(|el| id < el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
        conn.max_push_id = Some(id);
      }
      H3FrameTy::CancelPush => {
        // Nothing is pushed: only an identifier that the client allowed can be cancelled
        let id = single_varint(payload)?;
        if conn.max_push_id.is_none_or(|el| id > el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
      }
      H3FrameTy::Data | H3FrameTy::Headers | H3FrameTy::PushPromise | H3FrameTy::Unknown(_) => {}
    }
    pos = end.wrapping_add(pos);
  }
  if fin {
    return Err(closed_critical_stream());
  }
  Ok(cx.retain(data.len().wrapping_sub(pos))?)
}

// Reads what arrived on the QPACK decoder stream of the peer into the encoder of responses, which
// keeps an instruction that is cut (RFC 9204 section 4.4). A static-only encoder takes Stream
// Cancellations only: it never references the dynamic table.
fn decoder_data(conn: &mut H3Conn, data: &[u8], fin: bool) -> crate::Result<()> {
  if fin {
    return Err(closed_critical_stream());
  }
  Ok(conn.encoder.feed_decoder_stream(data)?)
}

// Removes the first `n` bytes of `vector`.
fn drain_front(vector: &mut Vec<u8>, n: usize) {
  let len = vector.len();
  let n = n.min(len);
  vector.copy_within(n.., 0);
  vector.truncate(len.wrapping_sub(n));
}

// Writes the decoder-stream and encoder-stream output of the turn, one write each, and, after a
// GOAWAY, closes once every accepted request was answered and its answer sent.
fn flush_conn(conn: &mut H3Conn, cx: &mut ConnCtx<'_, H3ConnState>) -> crate::Result<()> {
  // While the stream has room: what does not fit waits in the decoder, whose bound then closes a
  // connection whose peer gives the stream no credit (review V3)
  let room = QPACK_UNSENT_MAX.saturating_sub(cx.unsent_on(conn.decoder_stream));
  let output = conn.decoder.decoder_stream_output();
  let len = output.len().min(room);
  if let Some(bytes) = output.get(..len).filter(|el| !el.is_empty()) {
    cx.write(conn.decoder_stream, bytes, false)?;
    conn.decoder.consume_decoder_stream(len);
  }
  let room = QPACK_UNSENT_MAX.saturating_sub(cx.unsent_on(conn.encoder_stream));
  let output = conn.encoder.encoder_stream_output();
  if output.len() > ENCODER_BACKLOG {
    return Err(close(H3ErrorCode::ExcessiveLoad, Http3Error::EncoderStreamBacklog));
  }
  let len = output.len().min(room);
  if let Some(bytes) = output.get(..len).filter(|el| !el.is_empty()) {
    cx.write(conn.encoder_stream, bytes, false)?;
    conn.encoder.consume_encoder_stream(len);
  }
  if let Some(goaway) = conn.goaway
    && conn.live == 0
  {
    drain(conn, cx, StreamId(goaway))?;
  }
  Ok(())
}

// A shutdown with no request under way (ruling T13-h): the streams below the GOAWAY that brought
// no request are refused (RFC 9114 section 5.2), and once every answer and refusal is
// acknowledged, and the GOAWAY sent, the connection closes with H3_NO_ERROR.
fn drain(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  below: StreamId,
) -> crate::Result<()> {
  let mut answered = true;
  let mut from = StreamId(0);
  while let Some((id, writable)) = cx.first_unanswered(from, below) {
    // A refusal that finds no room (no stream slot left on the worker and as many refused streams
    // as a connection keeps) is tried again at the next flush, and the grace period of the
    // shutdown bounds the wait: the close stays graceful. Any other error closes the connection.
    if writable {
      match cx.refuse(id, H3ErrorCode::RequestRejected.code()) {
        Ok(()) => conn.decoder.cancel_stream(id.0)?,
        Err(rimu_quic::Error::QuicClose(_, QuicError::PoolExhausted)) => {}
        Err(err) => return Err(err.into()),
      }
    }
    answered = false;
    from = StreamId(id.0.wrapping_add(4));
  }
  if answered && cx.unsent_on(conn.control) == 0 {
    cx.close(H3ErrorCode::NoError.code(), b"");
  }
  Ok(())
}

// Room for `add` more elements in the buffer of request `idx` that `which` picks, with the length
// that it will have if known, within the budget of the connection, what entries without a request
// keep being freed first if needed (ruling T13-g). `false` if the budget does not allow it.
fn reserve_in(
  conn: &mut H3Conn,
  idx: usize,
  add: usize,
  which: fn(&mut Req) -> (&mut Vec<u8>, Option<u64>),
) -> crate::Result<bool> {
  for reclaim in [false, true] {
    if reclaim {
      conn.reclaim();
    }
    let H3Conn { budget, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(false);
    };
    let (buf, hint) = which(req);
    let hint = hint.map(|el| usize::try_from(el).unwrap_or(usize::MAX));
    if budget.grow(buf, add, hint)? {
      return Ok(true);
    }
  }
  Ok(false)
}

// If the buffer of request `idx` that `which` picks can take `add` more elements within the budget
// of the connection, what entries without a request keep being freed first if needed.
fn fits_in(conn: &mut H3Conn, idx: usize, add: usize, which: fn(&mut Req) -> &mut Vec<u8>) -> bool {
  for reclaim in [false, true] {
    if reclaim {
      conn.reclaim();
    }
    let H3Conn { budget, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return false;
    };
    if budget.fits(which(req), add) {
      return true;
    }
  }
  false
}

// Frees a response buffer of the worker that a large response made grow (review V4).
fn keep_small(buf: &mut Vec<u8>) {
  if buf.capacity() > KEEP_SCRATCH {
    *buf = Vec::new();
  }
}

// Opens our control stream, with the SETTINGS of `params`, and our QPACK streams.
fn open_streams(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  params: &H3Params,
) -> crate::Result<()> {
  let settings = H3Settings {
    qpack_max_table_capacity: params.qpack_max_table_capacity.into(),
    qpack_blocked_streams: params.qpack_blocked_streams.into(),
    max_field_section_size: Some(params.max_field_section_size.into()),
  };
  let mut control = [0u8; 64];
  let Some(len) = control.get_mut(1..).and_then(|el| settings.encode(el)) else {
    return Err(crate::Error::Http3(Http3Error::BufferTooSmall));
  };
  conn.control = open_uni(cx)?;
  cx.write(conn.control, control.get(..len.wrapping_add(1)).unwrap_or_default(), false)?;
  conn.encoder_stream = open_uni(cx)?;
  cx.write(conn.encoder_stream, &[ENCODER_STREAM], false)?;
  conn.decoder_stream = open_uni(cx)?;
  cx.write(conn.decoder_stream, &[DECODER_STREAM], false)?;
  Ok(())
}

fn open_uni(cx: &mut ConnCtx<'_, H3ConnState>) -> crate::Result<StreamId> {
  cx.open_uni().map_err(|err| match err {
    rimu_quic::Error::Quic(QuicError::StreamsBlocked) => {
      close(H3ErrorCode::GeneralProtocolError, Http3Error::UniStreamsBlocked)
    }
    _ => err.into(),
  })
}

// Appends the header of a frame of `ty` whose payload has `len` bytes.
fn push_frame_header(out: &mut Vec<u8>, ty: H3FrameTy, len: usize) -> crate::Result<()> {
  let mut header = [0u8; 16];
  let len = u64::try_from(len).unwrap_or(u64::MAX);
  let Some(header_len) = encode_frame_header(ty, len, &mut header) else {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::BufferTooSmall));
  };
  out.extend_from_slice(header.get(..header_len).unwrap_or_default());
  Ok(())
}

// Refuses stream `id`, which has no request: after a GOAWAY.
fn reject(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
  code: H3ErrorCode,
) -> crate::Result<()> {
  cx.reset(id, code.code());
  cx.stop_sending(id, code.code());
  Ok(conn.decoder.cancel_stream(id.0)?)
}

// The peer reset stream `id`.
fn reset_by_peer(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
) -> crate::Result<()> {
  if [conn.peer_control, conn.peer_encoder, conn.peer_decoder].contains(&Some(id)) {
    return Err(closed_critical_stream());
  }
  if !id.is_client_bidi() {
    return Ok(());
  }
  // The request is abandoned, and its references to the dynamic table with it (RFC 9204 section
  // 4.4.2), and so is what would answer it: the sending part is reset, unless it has its FIN (a
  // 413 or 431 that answered already, which a reset could cut) or was reset (a stream error)
  conn.decoder.cancel_stream(id.0)?;
  if let Some(idx) = conn.req_idx(id) {
    conn.free_req(idx);
  }
  if !cx.write_closed(id) {
    cx.reset(id, H3ErrorCode::RequestCancelled.code());
  }
  Ok(())
}

// The payload of a frame that is one variable-length integer.
fn single_varint(payload: &[u8]) -> crate::Result<u64> {
  match decode_varint(payload) {
    Some((value, len)) if len == payload.len() => Ok(value),
    _ => {
      cold_path();
      Err(close(H3ErrorCode::FrameError, Http3Error::MalformedFrame))
    }
  }
}

// The peer asked us to stop sending on stream `id`.
fn stopped_by_peer(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
) -> crate::Result<()> {
  if [conn.control, conn.encoder_stream, conn.decoder_stream].contains(&id) {
    return Err(closed_critical_stream());
  }
  let Some(idx) = conn.req_idx(id) else {
    return Ok(());
  };
  // Nothing will be answered: what is left of the request is not read
  if conn.reqs.get(idx).is_some_and(|el| el.phase != Phase::Parked) {
    cx.stop_sending(id, H3ErrorCode::RequestCancelled.code());
    conn.decoder.cancel_stream(id.0)?;
  }
  conn.free_req(idx);
  Ok(())
}

// A stream error on request `idx` (RFC 9114 section 8): RESET_STREAM and STOP_SENDING with `code`.
fn stream_error(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  idx: usize,
  code: H3ErrorCode,
) -> crate::Result<()> {
  let Some(id) = conn.reqs.get(idx).map(|el| el.id) else {
    return Ok(());
  };
  cx.reset(id, code.code());
  cx.stop_sending(id, code.code());
  conn.decoder.cancel_stream(id.0)?;
  conn.free_req(idx);
  Ok(())
}

#[cold]
fn unexpected_frame() -> crate::Error {
  close(H3ErrorCode::FrameUnexpected, Http3Error::UnexpectedFrame)
}

// A HEADERS frame of `encoded_headers`, a DATA frame of `body` if it is not empty and the FIN, put
// together in `frame` and written once; a body that would grow `frame` past what it keeps goes with
// a write of its own after the frame headers.
fn write_response(
  cx: &mut ConnCtx<'_, H3ConnState>,
  frame: &mut Vec<u8>,
  stream: StreamId,
  encoded_headers: &[u8],
  body: &[u8],
) -> crate::Result<()> {
  frame.clear();
  push_frame_header(frame, H3FrameTy::Headers, encoded_headers.len())?;
  frame.extend_from_slice(encoded_headers);
  if body.is_empty() {
    return Ok(cx.write(stream, frame, true)?);
  }
  push_frame_header(frame, H3FrameTy::Data, body.len())?;
  // A body that would make the buffer grow past what it keeps goes with a write of its own: the
  // stream copies it either way
  if frame.len().saturating_add(body.len()) > KEEP_SCRATCH {
    cx.write(stream, frame, false)?;
    return Ok(cx.write(stream, body, true)?);
  }
  frame.extend_from_slice(body);
  Ok(cx.write(stream, frame, true)?)
}

#[cfg(test)]
mod tests;
