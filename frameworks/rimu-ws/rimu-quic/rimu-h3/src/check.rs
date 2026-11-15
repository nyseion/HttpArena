//! An HTTP/3 server connection driven by generated input, for the fuzzer and for tests.
//!
//! The server is an [`H3Server`] of a handler that answers `200` with a small body, parks the
//! requests to `/park`, fails the ones to `/err` and answers `/big` with 40 KB, on the endpoint of
//! the in-process harness ([`crate::testing::H3Net`]); the client is rimu-quic's test client, whose
//! streams the script writes: the control stream and the QPACK streams of a client, requests
//! (valid ones, with bodies and trailers, and damaged ones), frames of every type and any bytes on
//! the streams of the script, resets and STOP_SENDING frames, resumptions of parked requests, time,
//! and datagrams lost in either direction.
//!
//! Whatever the script is, the server must hold these:
//!
//! - it never panics;
//! - every application close of the connection that it sends has a code of RFC 9114 section 8.1
//!   or RFC 9204 section 6;
//! - if the script was only valid requests, an acceptable control stream, time and round trips,
//!   every request is answered with a complete `200` and the body of the handler, and the
//!   connection is not closed.

use crate::{
  H3Params, H3Settings, Handler, ReqCtx, ReqOutcome, Request,
  frame::{H3FrameTy, decode_frame_header, encode_frame_header},
  testing::{H3Net, response_of},
};
use alloc::{vec, vec::Vec};
use rimu_qpack::encode_static;
use rimu_quic::{QuicParams, StreamId};

const BIG: &[u8] = &[0x61; 40_000];
const BODY: &[u8] = b"hello";
const MAX_ACTIONS: usize = 96;
const MAX_ROUNDS: usize = 64;

/// The bytes of a script.
#[derive(Debug)]
pub struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
  /// The script `bytes`.
  pub const fn new(bytes: &'a [u8]) -> Self {
    Self(bytes)
  }

  /// If nothing is left.
  pub const fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// The next byte, zero once there are none.
  pub fn byte(&mut self) -> u8 {
    match self.0.split_first() {
      Some((first, rest)) => {
        self.0 = rest;
        *first
      }
      None => 0,
    }
  }

  /// The next `len` bytes, or the ones that are left.
  pub fn take(&mut self, len: usize) -> &'a [u8] {
    let (head, rest) = self.0.split_at(len.min(self.0.len()));
    self.0 = rest;
    head
  }

  /// The next byte as a length of at most `modulus - 1`, and then that many bytes.
  pub fn sized(&mut self, modulus: usize) -> &'a [u8] {
    let len = usize::from(self.byte()) % modulus;
    self.take(len)
  }
}

/// Answers as the module says.
#[derive(Debug, Default)]
pub struct FuzzHandler {
  parked: Vec<StreamId>,
}

impl Handler for FuzzHandler {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    if req.path.starts_with(b"/park") {
      self.parked.push(req.stream);
      return Ok(ReqOutcome::Parked);
    }
    if req.path.starts_with(b"/err") {
      return Err(crate::Error::Http3(crate::Http3Error::BufferTooSmall));
    }
    let body = if req.path.starts_with(b"/big") { BIG } else { BODY };
    cx.respond_fields(&[(b":status", b"200"), (b"content-type", b"text/plain")], body)?;
    Ok(ReqOutcome::Responded)
  }

  fn resume(&mut self, cx: &mut ReqCtx<'_, '_>, _: StreamId) -> crate::Result<ReqOutcome> {
    cx.respond_fields(&[(b":status", b"200")], b"resumed")?;
    Ok(ReqOutcome::Responded)
  }
}

type Net = H3Net<FuzzHandler>;

/// A frame of type `ty`.
fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
  let mut header = [0u8; 16];
  let len = encode_frame_header(H3FrameTy::Unknown(ty), payload.len() as u64, &mut header)
    .unwrap_or_default();
  let mut rslt = header.get(..len).unwrap_or_default().to_vec();
  rslt.extend_from_slice(payload);
  rslt
}

fn section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
  let mut out = Vec::new();
  encode_static(fields.iter().copied(), &mut out);
  out
}

/// The fields of a request: valid, or one thing wrong with it, as the byte `kind` says.
fn request_fields(input: &mut Input<'_>, kind: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
  let method: &[u8] = match input.byte() % 6 {
    0..=2 => b"GET",
    3 => b"POST",
    4 => b"CONNECT",
    _ => b"G E T",
  };
  let path: &[u8] = match input.byte() % 6 {
    0..=2 => b"/",
    3 => b"/park",
    4 => b"/err",
    _ => b"/big",
  };
  let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
    (b":method".to_vec(), method.to_vec()),
    (b":scheme".to_vec(), b"https".to_vec()),
    (b":authority".to_vec(), b"localhost".to_vec()),
    (b":path".to_vec(), path.to_vec()),
  ];
  match kind % 16 {
    // A pseudo-header field twice, missing, late or unknown
    1 => fields.push((b":method".to_vec(), b"GET".to_vec())),
    2 => drop(fields.remove(usize::from(input.byte() % 4))),
    3 => fields.insert(2, (b"x-early".to_vec(), b"1".to_vec())),
    4 => fields.push((b":status".to_vec(), b"200".to_vec())),
    // Fields that HTTP/3 forbids
    5 => fields.push((b"connection".to_vec(), b"close".to_vec())),
    6 => fields.push((b"transfer-encoding".to_vec(), b"chunked".to_vec())),
    7 => fields.push((b"te".to_vec(), b"trailers".to_vec())),
    8 => fields.push((b"te".to_vec(), b"gzip".to_vec())),
    9 => fields.push((b"Upper".to_vec(), b"case".to_vec())),
    10 => fields.push((b"content-length".to_vec(), input.sized(6).to_vec())),
    11 => fields.push((input.sized(12).to_vec(), input.sized(12).to_vec())),
    12 => fields.push((b"cookie".to_vec(), vec![b'c'; 200])),
    13 => fields.push((b"x-big".to_vec(), vec![b'b'; 20_000])),
    _ => {}
  }
  fields
}

/// What the client of a script has done that makes the answers of the server unpredictable.
#[derive(Debug, Default)]
struct Plan {
  /// The requests that must be answered: stream, and whether their path is `/big`.
  good: Vec<(StreamId, bool)>,
  /// Something other than valid requests, an acceptable control stream and time.
  noisy: bool,
  /// The control stream of the client, once opened.
  control: Option<StreamId>,
  /// The time that the script let pass.
  elapsed_us: u64,
  /// The streams the script opened.
  streams: Vec<StreamId>,
}

fn open_uni(net: &mut Net, ty: u8, bytes: &[u8]) -> Option<StreamId> {
  net.client_ctx(0, |cx| {
    let id = cx.open_uni().ok()?;
    cx.write(id, &[ty], false).ok()?;
    cx.write(id, bytes, false).ok()?;
    Some(id)
  })
}

fn write(net: &mut Net, id: StreamId, bytes: &[u8], fin: bool) {
  net.client_ctx(0, |cx| {
    let _rslt = cx.write(id, bytes, fin);
  });
}

fn action(net: &mut Net, input: &mut Input<'_>, plan: &mut Plan) {
  match input.byte() % 18 {
    // The control stream, once: acceptable settings or any bytes
    0 => {
      if plan.control.is_none() {
        let valid = !input.byte().is_multiple_of(3);
        let mut payload = vec![0u8; 64];
        let settings = H3Settings {
          qpack_max_table_capacity: u64::from(input.byte() % 2) * 4096,
          qpack_blocked_streams: u64::from(input.byte() % 4),
          max_field_section_size: None,
        };
        let len = settings.encode(&mut payload).unwrap_or(0);
        payload.truncate(len);
        // `encode` writes the whole SETTINGS frame
        let bytes = if valid { payload } else { input.sized(64).to_vec() };
        plan.noisy |= !valid;
        plan.control = open_uni(net, 0, &bytes);
      } else {
        // Frames on the control stream
        let ty = match input.byte() % 6 {
          0 => 7,
          1 => 0xd,
          2 => 3,
          3 => 0x21,
          4 => u64::from(input.byte()),
          _ => 4,
        };
        let bytes = frame(ty, input.sized(16));
        plan.noisy = true;
        if let Some(id) = plan.control {
          write(net, id, &bytes, false);
        }
      }
    }
    // The QPACK streams: instructions of an encoder, or of a decoder
    1 | 2 => {
      plan.noisy = true;
      let (ty, first): (u8, u8) =
        if input.byte().is_multiple_of(2) { (2, 0x20) } else { (3, 0x00) };
      let mut bytes = vec![first | (input.byte() % 32)];
      bytes.extend_from_slice(input.sized(64));
      if let Some(id) = open_uni(net, ty, &bytes) {
        plan.streams.push(id);
      }
    }
    // A request, valid or not
    3..=8 => {
      let kind = if input.byte().is_multiple_of(4) { input.byte() } else { 0 };
      let fields = request_fields(input, kind);
      let refs: Vec<(&[u8], &[u8])> =
        fields.iter().map(|(name, value)| (name.as_slice(), value.as_slice())).collect();
      let mut bytes = frame(1, &section(&refs));
      let method = fields.first().map(|el| el.1.as_slice()).unwrap_or_default();
      let path = fields.get(3).map(|el| el.1.as_slice()).unwrap_or_default();
      let post = method == b"POST";
      let body = input.sized(200).to_vec();
      if post || input.byte().is_multiple_of(8) {
        bytes.extend(frame(0, &body));
      }
      // Trailers
      if input.byte().is_multiple_of(8) {
        bytes.extend(frame(1, &section(&[(b"x-trailer", b"1")])));
        plan.noisy = true;
      }
      let fin = !input.byte().is_multiple_of(16);
      let valid = kind.is_multiple_of(16)
        && method != b"CONNECT"
        && method != b"G E T"
        && path != b"/park"
        && path != b"/err"
        && fin;
      plan.noisy |= !valid;
      let opened = net.client_ctx(0, |cx| {
        let id = cx.open_bidi().ok()?;
        cx.write(id, &bytes, fin).ok()?;
        Some(id)
      });
      if let Some(id) = opened {
        plan.streams.push(id);
        if valid {
          plan.good.push((id, path == b"/big"));
        }
      }
    }
    // Any bytes on a stream of the script, or a frame of any type
    9 | 10 => {
      plan.noisy = true;
      let Some(id) = pick(&plan.streams, input) else {
        return;
      };
      let bytes = if input.byte().is_multiple_of(2) {
        frame(u64::from(input.byte() % 16) | u64::from(input.byte() % 4) << 8, input.sized(48))
      } else {
        input.sized(96).to_vec()
      };
      write(net, id, &bytes, input.byte().is_multiple_of(8));
    }
    // A field section with a reference to the dynamic table, to an encoder that was not told
    11 => {
      plan.noisy = true;
      let mut bytes = vec![input.byte() % 4, input.byte() % 4];
      bytes.extend_from_slice(input.sized(32));
      let bytes = frame(1, &bytes);
      let fin = input.byte().is_multiple_of(2);
      let opened = net.client_ctx(0, |cx| {
        let id = cx.open_bidi().ok()?;
        cx.write(id, &bytes, fin).ok()?;
        Some(id)
      });
      plan.streams.extend(opened);
    }
    // A reset or a STOP_SENDING of a stream of the script
    12 => {
      plan.noisy = true;
      let Some(id) = pick(&plan.streams, input) else {
        return;
      };
      let code = u64::from(input.byte());
      let reset = input.byte().is_multiple_of(2);
      net.client_ctx(0, |cx| {
        if reset {
          cx.reset(id, code);
        } else {
          cx.stop_sending(id, code);
        }
      });
    }
    // The server resumes a parked request
    13 => {
      if let Some(id) = net.app.handler.parked.pop() {
        net.resume(0, id);
      }
    }
    // Round trips as they are
    14 | 15 => settle(net, usize::from(input.byte() % 8) + 1),
    // Time
    16 => {
      let us = match input.byte() % 4 {
        0 => 1_000,
        1 => 25_000,
        2 => 300_000,
        _ => 1_000_000,
      };
      // Quiet for long enough, a connection idles out
      plan.elapsed_us += us;
      if plan.elapsed_us >= 1_000_000 {
        plan.noisy = true;
      }
      net.advance(us);
      settle(net, 4);
    }
    // The datagrams of one step lost, the client's or the server's
    _ => {
      plan.noisy = true;
      let deaf = input.byte().is_multiple_of(2);
      if let Some(client) = net.clients.first_mut() {
        if deaf {
          client.deaf = true;
        } else {
          client.mute = true;
        }
      }
      let _ = net.step();
      if let Some(client) = net.clients.first_mut() {
        client.deaf = false;
        client.mute = false;
      }
    }
  }
}

fn pick(streams: &[StreamId], input: &mut Input<'_>) -> Option<StreamId> {
  let idx = usize::from(input.byte()).checked_rem(streams.len())?;
  streams.get(idx).copied()
}

// Steps at most `rounds` times, until nothing moves.
fn settle(net: &mut Net, rounds: usize) {
  for _ in 0..rounds {
    if !net.step() {
      return;
    }
  }
}

fn check_codes(net: &Net) {
  if let Some((true, code)) = net.server_close(0) {
    assert!(
      (0x100..=0x110).contains(&code) || (0x200..=0x202).contains(&code),
      "the server sent an application CONNECTION_CLOSE with the code {code:#x}"
    );
  }
}

/// Runs `input` as a script against `net`, whose handshake is done, and checks the rules.
fn drive(net: &mut Net, input: &mut Input<'_>, tight: bool) {
  // Limits that a valid request can exceed (413, 431) make the answers unpredictable
  let mut plan = Plan { noisy: tight, ..Plan::default() };
  for _ in 0..MAX_ACTIONS {
    if input.is_empty() {
      break;
    }
    action(net, input, &mut plan);
    check_codes(net);
  }
  settle(net, MAX_ROUNDS);
  check_codes(net);
  if !plan.noisy {
    assert_eq!(net.server_close(0), None, "the server closed on valid requests");
    for (id, big) in &plan.good {
      let Some(rsp) = response_of(net.clients[0].conn.app(), *id) else {
        panic!("no answer to the valid request of stream {}", id.0);
      };
      let want = if *big { BIG } else { BODY };
      assert_eq!(rsp.field(b":status"), Some(&b"200"[..]), "stream {}", id.0);
      assert!(
        rsp.fin && rsp.frames.first() == Some(&1) && rsp.body == want,
        "{:?} {} {}",
        rsp.frames,
        rsp.fin,
        rsp.body.len()
      );
    }
  }
}

/// A server connection that waits for the script: its handshake is done. `true` with it if its
/// limits are tight enough for a valid request to be refused.
fn net_of(input: &mut Input<'_>) -> (Net, bool) {
  let params = H3Params {
    qpack_max_table_capacity: u32::from(input.byte() % 2) * 4096,
    qpack_blocked_streams: u16::from(input.byte() % 4),
    max_field_section_size: if input.byte().is_multiple_of(4) { 256 } else { 16 * 1024 },
    max_request_body: if input.byte().is_multiple_of(4) { 100 } else { 1 << 20 },
    max_buffered_body_per_conn: if input.byte().is_multiple_of(4) { 1000 } else { 16 << 20 },
    ..H3Params::default()
  };
  let tight = params.max_field_section_size < 1024
    || params.max_request_body < 1024
    || params.max_buffered_body_per_conn < 1 << 20;
  let mut net = Net::new(QuicParams::default(), params, FuzzHandler::default());
  let _ = net.add_client();
  settle(&mut net, 16);
  (net, tight)
}

/// Runs the bytes as a script against an HTTP/3 server connection, panicking if it breaks a rule of
/// the module.
#[inline]
pub fn run(data: &[u8]) {
  let mut input = Input::new(data);
  let (mut net, tight) = net_of(&mut input);
  drive(&mut net, &mut input, tight);
}

/// Feeds `data` to a request stream and to the control stream of a fresh server connection as
/// they are, then a request: the server neither panics nor sends a close of a code that HTTP/3
/// does not have, whatever the bytes.
#[inline]
pub fn run_raw(data: &[u8]) {
  let (target, rest) = data.split_first().map_or((0, data), |(first, rest)| (*first, rest));
  let mut net = Net::new(QuicParams::default(), H3Params::default(), FuzzHandler::default());
  let _ = net.add_client();
  settle(&mut net, 16);
  let fin = target & 0x80 != 0;
  let _ = net.client_ctx(0, |cx| {
    let id = match target % 4 {
      0 | 1 => cx.open_bidi().ok()?,
      2 => {
        let id = cx.open_uni().ok()?;
        cx.write(id, &[0x00], false).ok()?;
        id
      }
      _ => cx.open_uni().ok()?,
    };
    for chunk in rest.chunks(usize::from(target % 64) + 1) {
      cx.write(id, chunk, false).ok()?;
    }
    cx.write(id, &[], fin).ok()
  });
  settle(&mut net, MAX_ROUNDS);
  check_codes(&net);
  let get = frame(1, &section(&crate::testing::GET));
  let _ = net.client_ctx(0, |cx| {
    let id = cx.open_bidi().ok()?;
    cx.write(id, &get, true).ok()
  });
  settle(&mut net, MAX_ROUNDS);
  check_codes(&net);
  let _ = decode_frame_header(rest);
}

#[cfg(test)]
mod tests {
  use crate::check::{BODY, Input, drive, net_of, run, run_raw};
  use crate::testing::response_of;
  use alloc::vec::Vec;
  use rimu_quic::StreamId;

  // Rule: a valid request of the script is answered with the answer of the handler and nothing
  // closes the connection; the script reaches the handler through the QUIC connection.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn valid_request_of_a_script_is_answered() {
    // Settings (five bytes); then a GET of `/` with a FIN, and round trips
    let script = [0, 1, 1, 1, 1, 3, 1, 0, 0, 0, 1, 1, 1, 14, 7];
    let mut input = Input::new(&script);
    let (mut net, tight) = net_of(&mut input);
    assert!(!tight);
    assert!(net.clients[0].conn.is_confirmed());
    drive(&mut net, &mut input, tight);
    // The first stream of the client
    let rsp = response_of(net.clients[0].conn.app(), StreamId(0)).unwrap();
    assert_eq!((rsp.frames.as_slice(), rsp.body.as_slice(), rsp.fin), (&[1, 0][..], BODY, true));
    assert_eq!(rsp.field(b":status"), Some(&b"200"[..]));
  }

  // Rule: whatever the script is, the server holds the rules of the module.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn generated_scripts_do_not_break_the_server() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    for round in 0..300u32 {
      let len = usize::try_from(next() % 800).unwrap();
      let mut data: Vec<u8> = (0..len).map(|_| u8::try_from(next() & 0xff).unwrap()).collect();
      if round.is_multiple_of(2) {
        // Requests and round trips
        for (idx, byte) in data.iter_mut().enumerate().skip(5) {
          if idx.is_multiple_of(3) {
            *byte = [3, 14, 4, 0][idx % 4];
          }
        }
      }
      run(&data);
    }
  }

  // Any bytes on a request stream or the control stream break nothing.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn raw_bytes_on_streams_do_not_break_the_server() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..200 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      let len = usize::try_from(state % 300).unwrap();
      let data: Vec<u8> = (0..len).map(|el| (state >> (el % 56)) as u8 ^ el as u8).collect();
      run_raw(&data);
    }
  }
}
