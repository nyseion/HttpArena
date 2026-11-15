use crate::{
  Body, BodyMode, H3ConnState, H3Params, H3Server, H3Settings, Handler, ReqCtx, ReqOutcome,
  Request, ResponseFields,
  testing::{
    CLOSING_US, GET, H3Net, PRIORITY_UPDATE, TestHandler, alloc_count::count_allocations_in,
    client_settings, connected, control_stream, data_frame, frame, headers_frame, varint,
  },
};
use alloc::{format, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use rimu_qpack::{EncoderConfig, InsertPolicy, wire};
use rimu_quic::{BodyRef, QuicLimits, QuicParams, SharedBytes, StreamId};

const OK: &[u8] = b"hello";
// Static table indices (RFC 9204 Appendix A)
const AUTHORITY: u64 = 0;
const PATH_ROOT: u64 = 1;
const METHOD_GET: u64 = 17;
const SCHEME_HTTPS: u64 = 23;
const USER_AGENT: u64 = 95;
/// What a server connection allocates per handshake with rimu-quic's ECDSA test certificate, as
/// rimu-quic documents and pins it (`CONN_HANDSHAKE_ALLOCATIONS`: rustls's share, the adapter's and
/// the transport's): the zero-allocation tests whose windows contain handshakes allow this per
/// handshake, and nothing per request.
const HANDSHAKE_ALLOCATIONS: u64 = if cfg!(feature = "ring") { 87 } else { 103 };

fn dynamic_params() -> H3Params {
  H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, ..H3Params::default() }
}

// The fields of a request of `method` for `path` with `extra` fields.
fn request_fields<'any>(
  method: &'any [u8],
  path: &'any [u8],
  extra: &[(&'any [u8], &'any [u8])],
) -> Vec<(&'any [u8], &'any [u8])> {
  let mut fields: Vec<(&[u8], &[u8])> = vec![
    (b":method", method),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", path),
  ];
  fields.extend_from_slice(extra);
  fields
}

// A HEADERS frame of `GET /path` whose `:authority` is the dynamic entry of absolute index 0, and
// whose other fields are the dynamic entries of `dynamic` (absolute indices).
fn dynamic_request(ric: u64, path: &[u8], dynamic: &[u64]) -> Vec<u8> {
  let mut section = Vec::new();
  wire::prefix(&mut section, ric, ric, 128);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, true, SCHEME_HTTPS);
  wire::indexed(&mut section, false, ric - 1);
  wire::name_ref(&mut section, true, false, PATH_ROOT, path, false);
  for abs in dynamic {
    wire::indexed(&mut section, false, ric - 1 - abs);
  }
  frame(0x01, &section)
}

// The encoder stream of a client: its type and the capacity.
fn encoder_stream(capacity: u64) -> Vec<u8> {
  let mut out = vec![0x02];
  wire::set_capacity(&mut out, capacity);
  out
}

// A POST of `path` that announces `len` bytes of body, with `body`.
fn post(path: &[u8], len: usize, body: &[u8]) -> Vec<u8> {
  let len = format!("{len}");
  let mut request =
    headers_frame(&request_fields(b"POST", path, &[(b"content-length", len.as_bytes())]));
  if !body.is_empty() {
    request.extend_from_slice(&data_frame(body));
  }
  request
}

fn live(net: &mut H3Net, client: usize) -> u32 {
  net.server_state(client, H3ConnState::live_requests).unwrap()
}

fn buffered(net: &mut H3Net, client: usize) -> usize {
  net.server_state(client, H3ConnState::buffered).unwrap()
}

fn shutdown(net: &mut H3Net) {
  let now_us = net.now_us;
  net.endpoint.begin_shutdown(now_us, &mut net.app);
}

fn close_client(net: &mut H3Net, client: usize) {
  let now_us = net.now_us;
  net.clients[client].conn.close(now_us, 0x100);
}

// Brief step 1: a GET is answered with HEADERS, DATA and the FIN in one STREAM frame.
#[cfg_attr(miri, ignore)]
#[test]
fn get_request_answered_with_one_stream_frame() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let id = net.send(client, &headers_frame(&GET), true);
  net.run();
  let rsp = net.response(client, id).unwrap();
  // In order, a STREAM frame is one delivery: the whole response came in one, with its FIN
  assert_eq!(rsp.calls.len(), 1, "{:?}", rsp.calls);
  assert!(rsp.calls[0].1 && rsp.fin);
  assert_eq!(rsp.frames, [0x01, 0x00]);
  assert_eq!(rsp.field(b":status"), Some(&b"200"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!(rsp.body, OK);
  let seen = &net.app.handler.seen;
  assert_eq!(seen.len(), 1);
  assert_eq!(
    (&*seen[0].method, &*seen[0].scheme, &*seen[0].authority, &*seen[0].path),
    (&b"GET"[..], &b"https"[..], &b"localhost"[..], &b"/"[..])
  );
  assert!(seen[0].fields.is_empty() && seen[0].body.is_empty());
  assert_eq!(seen[0].stream, id.0);
  assert_eq!(live(&mut net, client), 0);
  assert_eq!(net.server_close(client), None);
}

// The response leaves with the acknowledgment of the request: the flush of the server that
// follows the request is one datagram, which carries both, and the client has nothing left to wait
// for (no packet of the server comes later for this request).
#[cfg_attr(miri, ignore)]
#[test]
fn response_and_ack_leave_in_one_datagram() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  // Settle the acknowledgments of the handshake first
  for _ in 0..4 {
    net.advance(30_000);
    net.run();
  }
  let id = net.send(client, &headers_frame(&GET), true);
  for mut datagram in net.client_datagrams(client) {
    net.deliver_to_server(client, &mut datagram);
  }
  let mut out = net.server_datagrams();
  assert_eq!(out.len(), 1, "{} datagrams", out.len());
  net.deliver_to_client(client, &mut out[0].1);
  assert!(net.response(client, id).unwrap().fin);
  // The client's next datagram, its acknowledgment, does not make the server send again
  for mut datagram in net.client_datagrams(client) {
    net.deliver_to_server(client, &mut datagram);
  }
  assert!(net.server_datagrams().is_empty());
}

// Brief step 1: both sides send their SETTINGS first on their control streams; the server opens
// its QPACK encoder and decoder streams, on which nothing follows the type until it is needed.
#[cfg_attr(miri, ignore)]
#[test]
fn settings_exchanged_and_qpack_streams_open() {
  let params =
    H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 100, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let ours = H3Settings { max_field_section_size: Some(8192), ..client_settings() };
  let _ = net.open_uni(client, &control_stream(ours));
  net.run();
  let streams = net.server_streams(client);
  assert_eq!(streams.iter().map(|el| el.0).collect::<Vec<_>>(), [0x00, 0x02, 0x03]);
  let expected = H3Settings {
    qpack_max_table_capacity: 4096,
    qpack_blocked_streams: 100,
    max_field_section_size: Some(16 * 1024),
  };
  let mut settings = [0u8; 64];
  let len = expected.encode(&mut settings).unwrap();
  assert_eq!(streams[0].1, &settings[..len]);
  assert!(streams[1].1.is_empty() && streams[2].1.is_empty());
  // Critical streams: never finished
  let logs = &net.clients[client].conn.app().streams;
  assert!(logs.iter().filter(|(id, _)| **id & 0b11 == 0b11).all(|(_, log)| !log.fin));
  assert_eq!(net.server_state(client, H3ConnState::peer_settings).unwrap(), Some(ours));
  assert_eq!(net.server_close(client), None);
}

// Brief step 1: a POST whose body comes in DATA frames over many STREAM frames, which cut frame
// headers and the HEADERS frame (retained bytes), reaches the handler whole.
#[cfg_attr(miri, ignore)]
#[test]
fn post_with_body_reaches_handler() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let body: Vec<u8> = (0..300_000u32).map(|el| (el % 251) as u8).collect();
  let len = format!("{}", body.len());
  let extra: [(&[u8], &[u8]); 2] =
    [(b"content-length", len.as_bytes()), (b"content-type", b"application/octet-stream")];
  let mut request = headers_frame(&request_fields(b"POST", b"/upload", &extra));
  for chunk in body.chunks(100_000) {
    request.extend_from_slice(&data_frame(chunk));
  }
  let id = net.send(client, &request[..7], false);
  net.run();
  let mut at = 7;
  for piece in [5, 1000, 4093, 150_000] {
    let end = (at + piece).min(request.len());
    net.write(client, id, &request[at..end], false);
    net.run();
    at = end;
  }
  assert!(net.app.handler.seen.is_empty());
  net.write(client, id, &request[at..], true);
  net.run_for(1024);
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  let seen = &net.app.handler.seen;
  assert_eq!(seen.len(), 1);
  assert_eq!((&*seen[0].method, &*seen[0].path), (&b"POST"[..], &b"/upload"[..]));
  assert_eq!(
    seen[0].fields,
    extra.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect::<Vec<_>>()
  );
  assert!(seen[0].body == body);
  assert_eq!(live(&mut net, client), 0);
}

// Brief step 1 and ruling T13-f: malformed requests (RFC 9114 sections 4.1.2 and 4.3) are stream
// errors H3_MESSAGE_ERROR; the connection serves on.
#[cfg_attr(miri, ignore)]
#[test]
fn invalid_pseudo_headers_get_h3_message_error() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let get = |extra: &[(&[u8], &[u8])]| headers_frame(&request_fields(b"GET", b"/", extra));
  let mut cl_mismatch = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"5")]));
  cl_mismatch.extend_from_slice(&data_frame(b"abc"));
  let mut pseudo_trailer = get(&[]);
  pseudo_trailer.extend_from_slice(&headers_frame(&[(b":path", b"/x")]));
  let cases: Vec<Vec<u8>> = vec![
    // No :method, no :path, an empty :path
    headers_frame(&[(b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")]),
    headers_frame(&[(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost")]),
    headers_frame(&request_fields(b"GET", b"", &[])),
    // A pseudo-header field that requests do not have, a response one, one twice
    get(&[(b":foo", b"bar")]),
    headers_frame(&[(b":status", b"200"), GET[0], GET[1], GET[2], GET[3]]),
    get(&[(b":method", b"POST")]),
    // A pseudo-header field after a field
    headers_frame(&[GET[0], (b"accept", b"*/*"), GET[1], GET[2], GET[3]]),
    // http without an authority, an authority that the host contradicts, userinfo
    headers_frame(&[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/")]),
    get(&[(b"host", b"example.com")]),
    headers_frame(&[GET[0], GET[1], (b":authority", b"user@localhost"), GET[3]]),
    // CONNECT with :scheme and :path, an invalid method
    headers_frame(&request_fields(b"CONNECT", b"/", &[])),
    headers_frame(&request_fields(b"GE T", b"/", &[])),
    // Fields specific to a connection, a TE that is not "trailers"
    get(&[(b"connection", b"close")]),
    get(&[(b"transfer-encoding", b"chunked")]),
    get(&[(b"te", b"gzip")]),
    // Values that field-content does not allow, a name that is not a token
    get(&[(b"x-bad", b" leading")]),
    get(&[(b"x-bad", b"a\r\nb")]),
    get(&[(b"x bad", b"a")]),
    // A content-length that the body contradicts, or that is not a number
    cl_mismatch,
    get(&[(b"content-length", b"1x")]),
    // A pseudo-header field in the trailers
    pseudo_trailer,
  ];
  for (nth, case) in cases.iter().enumerate() {
    let id = net.send(client, case, true);
    net.run();
    assert!(net.resets(client).contains(&(id.0, 0x10e)), "case {nth}: {:?}", net.resets(client));
    assert_eq!(net.server_close(client), None, "case {nth}");
  }
  assert_eq!(net.app.handler.count, 0);
  assert_eq!(live(&mut net, client), 0);
  // Well formed: answered (TE: trailers is allowed, so is CONNECT without :scheme and :path)
  let id = net.send(client, &get(&[(b"te", b"trailers")]), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  let connect = [(b":method" as &[u8], b"CONNECT" as &[u8]), (b":authority", b"localhost:443")];
  let id = net.send(client, &headers_frame(&connect), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
}

// Brief step 1: field names are lowercase in HTTP/3 (RFC 9114 section 4.2).
#[cfg_attr(miri, ignore)]
#[test]
fn uppercase_header_name_rejected() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"User-Agent", b"curl")]));
  let id = net.send(client, &request, true);
  net.run();
  assert!(net.resets(client).contains(&(id.0, 0x10e)));
  assert_eq!(net.app.handler.count, 0);
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"user-agent", b"curl")]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[0].fields, [(b"user-agent".to_vec(), b"curl".to_vec())]);
}

// Brief step 1: the control stream of the peer is critical (RFC 9114 section 6.2.1).
#[cfg_attr(miri, ignore)]
#[test]
fn closing_control_stream_is_connection_error() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let control = net.open_uni(client, &control_stream(client_settings()));
  net.run();
  assert_eq!(net.server_close(client), None);
  net.write(client, control, b"", true);
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x104)));
  assert!(net.clients[client].conn.is_draining());
}

// Brief step 1 and ruling T13-f: unknown frames on a request stream are skipped, wherever they
// are (RFC 9114 section 9).
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_frame_on_request_stream_ignored() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let mut request = frame(0x21, b"grease");
  request.extend_from_slice(&headers_frame(&request_fields(
    b"POST",
    b"/",
    &[(b"content-length", b"3")],
  )));
  request.extend_from_slice(&frame(0x1f * 7 + 0x21, b""));
  request.extend_from_slice(&data_frame(b"a"));
  request.extend_from_slice(&frame(PRIORITY_UPDATE, b"\x00u=1"));
  request.extend_from_slice(&data_frame(b"bc"));
  request.extend_from_slice(&headers_frame(&[(b"x-trailer", b"t")]));
  request.extend_from_slice(&frame(0x4242, &[7; 300]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[0].body, b"abc");
  assert_eq!(net.server_close(client), None);
}

// Brief step 1 and ruling T13-d: on shutdown the server sends GOAWAY with the first request
// stream that it did not accept, refuses the ones from there on, lets the ones in flight finish
// and then closes with H3_NO_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn goaway_on_shutdown_then_drain() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let _ = net.open_uni(client, &control_stream(client_settings()));
  let parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  assert!(net.response(client, parked).is_none());
  shutdown(&mut net);
  net.run();
  let goaways: Vec<_> =
    net.server_control_frames(client).into_iter().filter(|el| el.0 == 0x07).collect();
  assert_eq!(goaways, [(0x07, varint(parked.0 + 4))]);
  assert_eq!(net.server_close(client), None);
  // From the GOAWAY on: refused, the client asked to stop (it is still sending: no FIN)
  let late = net.send(client, &headers_frame(&GET), false);
  net.run();
  assert!(net.resets(client).contains(&(late.0, 0x10b)));
  assert!(net.stops(client).contains(&(late.0, 0x10b)));
  assert_eq!(net.app.handler.count, 1);
  assert_eq!(net.server_close(client), None);
  // The request in flight is answered, and then the connection closes
  net.resume(client, parked);
  net.run();
  let rsp = net.response(client, parked).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"resumed"[..]));
  assert_eq!(net.server_close(client), Some((true, 0x100)));
  assert!(net.clients[client].conn.is_draining());
  // Only one GOAWAY was ever sent
  let goaways = net.server_control_frames(client).into_iter().filter(|el| el.0 == 0x07).count();
  assert_eq!(goaways, 1);
}

// Ruling T13-d: what has not drained when the grace period ends is closed by the endpoint, with
// the shutdown code.
#[cfg_attr(miri, ignore)]
#[test]
fn shutdown_grace_closes_what_did_not_drain() {
  let limits = QuicLimits { shutdown_app_code: 0x0102, ..QuicLimits::default() };
  let quic = QuicParams::default().set_limits(limits);
  let mut net = H3Net::new(quic, H3Params::default(), TestHandler::new(OK));
  let client = net.add_client();
  net.run();
  let parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  shutdown(&mut net);
  net.run();
  net.advance(1_999_000);
  net.run();
  assert_eq!(net.server_close(client), None);
  assert!(net.response(client, parked).is_none());
  net.advance(1_000);
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x0102)));
}

// Brief step 1: a request that the handler parks is answered once resumed; the others go on
// meanwhile.
#[cfg_attr(miri, ignore)]
#[test]
fn parked_request_resumes() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  assert!(net.response(client, parked).is_none());
  assert_eq!(net.app.handler.parked, [parked]);
  assert_eq!(live(&mut net, client), 1);
  let other = net.send(client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(client, other).as_deref(), Some(&b"200"[..]));
  net.resume(client, parked);
  net.run();
  let rsp = net.response(client, parked).unwrap();
  assert_eq!(rsp.calls.len(), 1);
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"resumed"[..]));
  assert_eq!(net.app.handler.resumed, 1);
  assert_eq!(live(&mut net, client), 0);
}

// Brief step 1 and ruling T13-e: with a dynamic table, a client indexes `:authority` and
// `user-agent`; its instructions may arrive cut, a section may arrive before the inserts it needs
// (blocked, then decoded) and repeated sections replay from the memo.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_dynamic_requests_decode_when_capacity_set() {
  let params =
    H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 100, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let _ = net.open_uni(client, &control_stream(client_settings()));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", true);
  wire::insert_name_ref(&mut encoder, true, USER_AGENT, b"h2load nghttp2/1.66.0", false);
  // The second insert arrives in two pieces
  let cut = encoder.len() - 5;
  let enc = net.open_uni(client, &encoder[..cut]);
  net.run();
  net.write(client, enc, &encoder[cut..], false);
  net.run();
  let request = dynamic_request(2, b"/", &[1]);
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  let seen = net.app.handler.seen[0].clone();
  assert_eq!(seen.authority, b"localhost");
  assert_eq!(seen.fields, [(b"user-agent".to_vec(), b"h2load nghttp2/1.66.0".to_vec())]);
  // The decoder stream of the server: an Insert Count Increment after each piece (the second
  // made of the two inserts and written before the request arrived), then the Section
  // Acknowledgment of the request
  let decoder_out = net.server_streams(client)[2].1.clone();
  assert_eq!(decoder_out, [0x01, 0x01, 0x80 | u8::try_from(id.0).unwrap()]);
  // A section that needs an insert that did not arrive: blocked, then answered once it does
  let blocked = dynamic_request(3, b"/later", &[1, 2]);
  let id = net.send(client, &blocked, true);
  net.run();
  assert!(net.response(client, id).is_none());
  assert_eq!(live(&mut net, client), 1);
  let mut more = Vec::new();
  wire::insert_literal(&mut more, b"x-trace", b"abc", false);
  net.write(client, enc, &more, false);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  let seen = net.app.handler.seen[1].clone();
  assert_eq!(seen.path, b"/later");
  assert_eq!(seen.fields[1], (b"x-trace".to_vec(), b"abc".to_vec()));
  // Repeated byte for byte: replayed
  let hits = net.server_state(client, H3ConnState::memo_hits).unwrap();
  for _ in 0..3 {
    let id = net.send(client, &request, true);
    net.run();
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  }
  assert_eq!(net.server_state(client, H3ConnState::memo_hits).unwrap(), hits + 3);
  assert_eq!(net.app.handler.seen[4].fields, net.app.handler.seen[0].fields);
  assert_eq!(net.server_close(client), None);
}

// RFC 9204 section 2.1.2: a section that would block more streams than the advertised
// SETTINGS_QPACK_BLOCKED_STREAMS is a QPACK_DECOMPRESSION_FAILED; up to it, the blocked streams
// wait and are answered in the order their inserts arrive.
#[cfg_attr(miri, ignore)]
#[test]
fn blocked_streams_up_to_the_limit_then_decompression_failed() {
  let params =
    H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 2, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let enc = net.open_uni(client, &encoder_stream(4096));
  net.run();
  // Two streams wait for the first and the second insert
  let first = net.send(client, &dynamic_request(1, b"/1", &[]), true);
  let second = net.send(client, &dynamic_request(2, b"/2", &[1]), true);
  net.run();
  assert!(net.response(client, first).is_none() && net.response(client, second).is_none());
  assert_eq!(live(&mut net, client), 2);
  let mut insert = Vec::new();
  wire::insert_name_ref(&mut insert, true, AUTHORITY, b"localhost", false);
  net.write(client, enc, &insert, false);
  net.run();
  assert_eq!(net.status(client, first).as_deref(), Some(&b"200"[..]));
  assert!(net.response(client, second).is_none());
  let mut agent = Vec::new();
  wire::insert_name_ref(&mut agent, true, USER_AGENT, b"curl", false);
  net.write(client, enc, &agent, false);
  net.run();
  assert_eq!(net.status(client, second).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[1].fields, [(b"user-agent".to_vec(), b"curl".to_vec())]);
  // Three at once: the third is one too many
  for nth in 3..=5 {
    let _ = net.send(client, &dynamic_request(nth, b"/x", &[nth - 1]), true);
  }
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x200)));
}

// Brief step 1 (spec section 5.4): once warm, a round of clients of 4 x 64 requests each allocates
// in the server only what their handshakes do: a round of the same handshakes without a request
// allocates as much, and at most rimu-quic's documented allowance per handshake. Warm means that
// every pooled connection state has served as many connections as the decode memo has entries (8):
// rimu-qpack's memo takes a new entry, rather than an old one, until it has them all.
#[cfg_attr(miri, ignore)]
#[test]
fn h3_steady_state_allocates_nothing_per_request_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  const CLIENTS: usize = 16;
  const STREAMS: usize = 64;
  const REQUESTS: usize = 4 * STREAMS;
  let handler = TestHandler { record: false, ..TestHandler::new(OK) };
  let mut net = H3Net::new(QuicParams::default(), H3Params::default(), handler);
  net.count((&SERVER, &OTHERS));
  let request = headers_frame(&GET);
  let control = control_stream(client_settings());
  let round = |net: &mut H3Net, requests: usize| {
    let before = SERVER.load(Ordering::Relaxed);
    let first = net.clients.len();
    for _ in 0..CLIENTS {
      let _ = net.add_client();
    }
    net.run();
    for idx in first..first + CLIENTS {
      assert!(net.clients[idx].conn.is_confirmed());
      let _ = net.open_uni(idx, &control);
    }
    let done = net.run_requests_from(first, requests, STREAMS, &request);
    assert_eq!(done, (CLIENTS * requests) as u64);
    for idx in first..first + CLIENTS {
      close_client(net, idx);
    }
    net.run();
    net.advance(CLOSING_US);
    assert_eq!(net.endpoint.stats().conns, 0);
    SERVER.load(Ordering::Relaxed) - before
  };
  for _ in 0..9 {
    let _ = round(&mut net, REQUESTS);
  }
  let handshakes = round(&mut net, 0);
  let with_requests = round(&mut net, REQUESTS);
  assert!(handshakes <= CLIENTS as u64 * HANDSHAKE_ALLOCATIONS, "{handshakes} for {CLIENTS}");
  assert_eq!(
    with_requests,
    handshakes,
    "{} requests allocated {}",
    CLIENTS * REQUESTS,
    with_requests.wrapping_sub(handshakes)
  );
  assert_eq!(net.app.handler.count, (10 * CLIENTS * REQUESTS) as u64);
}

// Task 23b (spec section 5.4): a worker reaches its connection cap with idle HTTP/3 connections
// that hold the unidirectional streams of a real client (control, QPACK encoder and decoder)
// besides the server's three. Every one of them is established and usable, and the next client is
// refused by the connection cap, its first Initial dropped without a reply.
#[cfg_attr(miri, ignore)]
#[test]
fn idle_h3_connections_reach_the_connection_cap() {
  // Below the handshakes from which a client gets a Retry
  const BATCH: usize = 32;
  const CAP: usize = 256;
  let handler = TestHandler { record: false, ..TestHandler::new(OK) };
  let quic = QuicParams::default().set_max_conns_per_worker(CAP as u32);
  let mut net = H3Net::new(quic, H3Params::default(), handler);
  let control = control_stream(client_settings());
  while net.clients.len() < CAP {
    let first = net.clients.len();
    for _ in 0..BATCH {
      let _ = net.add_client();
    }
    net.run();
    for idx in first..first + BATCH {
      assert!(net.clients[idx].conn.is_confirmed(), "client {idx}");
      let _ = net.open_uni(idx, &control);
      let _ = net.open_uni(idx, &[0x02]);
      let _ = net.open_uni(idx, &[0x03]);
    }
    net.run();
  }
  assert_eq!(net.endpoint.stats().conns, CAP as u32);
  for idx in 0..CAP {
    let app = net.clients[idx].conn.app();
    assert!(net.clients[idx].conn.is_confirmed(), "client {idx}");
    assert_eq!((app.resets.len(), app.stops.len()), (0, 0), "client {idx}");
    assert_eq!(net.server_streams(idx).len(), 3, "client {idx}");
    assert_eq!(net.server_close(idx), None, "client {idx}");
  }
  // A request on the first and on the last is served
  let request = headers_frame(&GET);
  for idx in [0, CAP - 1] {
    let id = net.send(idx, &request, true);
    net.run();
    assert_eq!(net.status(idx, id).as_deref(), Some(&b"200"[..]), "client {idx}");
  }
  // One more: the connection cap drops its first Initial, without a reply
  let late = net.add_client();
  let mut initial = net.client_datagrams(late);
  net.deliver_to_server(late, &mut initial[0]);
  assert!(net.server_datagrams().is_empty());
  assert_eq!(net.endpoint.stats().conns, CAP as u32);
}

// Carried from task 13 (ruling T16-a): a response copied whole that is larger than the response
// buffer keeps (16 KiB) leaves its body with a write of its own instead of through that buffer,
// which would be made and freed again for each response; the client gets the same bytes.
#[cfg_attr(miri, ignore)]
#[test]
fn large_copied_responses_allocate_nothing_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  static BODY: [u8; 40_000] = [b'x'; 40_000];
  let handler = TestHandler { record: false, ..TestHandler::new(&BODY) };
  let mut net = H3Net::new(QuicParams::default(), H3Params::default(), handler);
  net.count((&SERVER, &OTHERS));
  let client = net.add_client();
  net.run();
  let _ = net.open_uni(client, &control_stream(client_settings()));
  let request = headers_frame(&GET);
  let get = |net: &mut H3Net| {
    let id = net.send(client, &request, true);
    net.run();
    let rsp = net.response(client, id).unwrap();
    assert!(rsp.fin && rsp.body.iter().all(|el| *el == b'x'));
    assert_eq!((rsp.body.len(), rsp.frames.as_slice()), (BODY.len(), &[0x01, 0x00][..]));
  };
  for _ in 0..4 {
    get(&mut net);
  }
  let before = SERVER.load(Ordering::Relaxed);
  for _ in 0..4 {
    get(&mut net);
  }
  let allocations = SERVER.load(Ordering::Relaxed) - before;
  assert_eq!(allocations, 0, "{allocations} allocations for 4 responses of 40 KB");
}

// Ruling T13-a: the inline state fits in 160 bytes; a box that comes back from the pool has a new
// decoder table and an empty memo, so another connection's fields never replay.
#[cfg_attr(miri, ignore)]
#[test]
fn pooled_state_is_reset_between_connections() {
  assert!(size_of::<H3ConnState>() <= 160, "{}", size_of::<H3ConnState>());
  let mut net = H3Net::new(QuicParams::default(), dynamic_params(), TestHandler::new(OK));
  let conn_with = |net: &mut H3Net, value: &[u8]| {
    let client = net.add_client();
    net.run();
    let mut encoder = encoder_stream(4096);
    wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
    wire::insert_literal(&mut encoder, b"x-token", value, false);
    let _ = net.open_uni(client, &encoder);
    net.run();
    client
  };
  let first = conn_with(&mut net, b"secret-a");
  let request = dynamic_request(2, b"/", &[1]);
  let id = net.send(first, &request, true);
  net.run();
  assert_eq!(net.status(first, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[0].fields, [(b"x-token".to_vec(), b"secret-a".to_vec())]);
  close_client(&mut net, first);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.app.pooled(), 1);
  // The same bytes on the next connection, which takes the same box
  let second = conn_with(&mut net, b"public-b");
  assert_eq!(net.app.pooled(), 0);
  let id = net.send(second, &request, true);
  net.run();
  assert_eq!(net.status(second, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[1].fields, [(b"x-token".to_vec(), b"public-b".to_vec())]);
  assert_eq!(net.server_state(second, H3ConnState::memo_hits).unwrap(), 0);
}

// Ruling T13-b: a HEADERS frame cut over STREAM frames is read whole, by retained bytes up to
// 4 KiB and in the head buffer of the request above; a field section over the limit is answered
// with 431 and a body over the limit with 413, the client being asked to stop with H3_NO_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn split_heads_and_oversized_requests() {
  let params = H3Params { max_request_body: 1000, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let long = vec![b'v'; 6000];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-long", &long)]));
  let id = net.send(client, &request[..2500], false);
  net.run();
  net.write(client, id, &request[2500..5000], false);
  net.run();
  net.write(client, id, &request[5000..], true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[0].fields, [(b"x-long".to_vec(), long.clone())]);
  // 16 KiB counted with 32 bytes per field (RFC 9114 section 4.2.2): the pseudo-header fields take
  // 175, `x-edge` 38 and its value the rest
  let at_limit = vec![b'w'; 16_384 - 175 - 38];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-edge", &at_limit)]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  let over = vec![b'w'; 16_384 - 175 - 38 + 1];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-edge", &over)]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"431"[..]));
  assert!(net.response(client, id).unwrap().fin);
  assert!(net.stops(client).contains(&(id.0, 0x100)));
  // A HEADERS frame whose payload alone is over the limit: 431 before anything is decoded
  let huge = vec![b'h'; 20_000];
  let id =
    net.send(client, &headers_frame(&request_fields(b"GET", b"/", &[(b"x-huge", &huge)])), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"431"[..]));
  // A content-length over the limit: 413 at once; a body that goes past it without one: 413
  let mut request = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"2000")]));
  request.extend_from_slice(&data_frame(&[1; 2000]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"413"[..]));
  assert!(net.stops(client).contains(&(id.0, 0x100)));
  let mut request = headers_frame(&request_fields(b"POST", b"/", &[]));
  request.extend_from_slice(&data_frame(&[1; 600]));
  request.extend_from_slice(&data_frame(&[2; 600]));
  let id = net.send(client, &request, true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"413"[..]));
  assert_eq!(net.app.handler.count, 2);
  // The connection serves on, and keeps nothing of them
  let id = net.send(client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(live(&mut net, client), 0);
  assert_eq!(net.server_close(client), None);
}

// Ruling T13-b: the RESET_STREAM that answers the STOP_SENDING of a 413 or 431 does not reset the
// answer, whose FIN may not be acknowledged yet: here it is lost, and sent again.
#[cfg_attr(miri, ignore)]
#[test]
fn refusal_is_not_cut_by_the_reset_that_answers_it() {
  let params = H3Params { max_request_body: 1000, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let head = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"2000")]));
  let id = net.send(client, &head, false);
  for mut datagram in net.client_datagrams(client) {
    net.deliver_to_server(client, &mut datagram);
  }
  // The 413 and the STOP_SENDING are lost; the client resets its request meanwhile
  assert!(!net.server_datagrams().is_empty());
  net.reset(client, id, 0x10c);
  for mut datagram in net.client_datagrams(client) {
    net.deliver_to_server(client, &mut datagram);
  }
  net.run();
  for _ in 0..16 {
    if net.response(client, id).is_some_and(|el| el.fin) {
      break;
    }
    assert!(net.advance_to_next_event());
    net.run();
  }
  assert!(!net.resets(client).iter().any(|el| el.0 == id.0), "{:?}", net.resets(client));
  let rsp = net.response(client, id).unwrap();
  assert_eq!(rsp.field(b":status"), Some(&b"413"[..]));
  assert!(rsp.fin);
  assert_eq!(net.server_close(client), None);
}

// Ruling T13-b and review focus 4: a POST larger than the stream window completes: credit comes
// back as the body is read.
#[cfg_attr(miri, ignore)]
#[test]
fn post_larger_than_stream_window_completes() {
  let params = H3Params { max_request_body: 2 << 20, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let body: Vec<u8> = (0..(3 << 19) as u32).map(|el| (el % 253) as u8).collect();
  let len = format!("{}", body.len());
  let mut request =
    headers_frame(&request_fields(b"POST", b"/big", &[(b"content-length", len.as_bytes())]));
  request.extend_from_slice(&data_frame(&body));
  let id = net.send(client, &request, true);
  net.run_for(8192);
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert!(net.app.handler.seen[0].body == body);
}

// Ruling T13-c: the decoder stream output of a turn leaves in one write, at the flush.
#[cfg_attr(miri, ignore)]
#[test]
fn decoder_stream_written_once_per_flush() {
  let (mut net, client) = connected(dynamic_params(), TestHandler::new(OK));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _enc = net.open_uni(client, &encoder);
  net.run();
  let decoder_id = 11;
  let calls = net.clients[client].conn.app().streams[&decoder_id].calls.len();
  let request = dynamic_request(1, b"/", &[]);
  // Ten requests in one flush of the client, read in one turn of the server
  let ids: Vec<StreamId> = (0..10).map(|_| net.send(client, &request, true)).collect();
  net.run();
  assert!(ids.iter().all(|id| net.status(client, *id).as_deref() == Some(&b"200"[..])));
  let log = &net.clients[client].conn.app().streams[&decoder_id];
  assert_eq!(log.calls.len(), calls + 1, "{:?}", log.calls);
  // Ten Section Acknowledgments of one byte each
  assert_eq!(log.calls.last().unwrap().0, 10);
}

// The work that encoder instructions make the decoder do is bounded (rimu-qpack's copy budget,
// which replaces the in-tree budget of instructions per turn): Duplicates of a large entry, each one
// byte, copy far more than the bytes that bring them, and a flood of them is an H3_EXCESSIVE_LOAD;
// a few are not.
#[cfg_attr(miri, ignore)]
#[test]
fn duplicate_floods_are_excessive_load() {
  let (mut net, client) = connected(dynamic_params(), TestHandler::new(OK));
  let mut encoder = encoder_stream(4096);
  wire::insert_literal(&mut encoder, b"x-large", &[b'l'; 1800], false);
  let enc = net.open_uni(client, &encoder);
  net.run();
  // A Duplicate of the newest entry evicts the oldest one: the table holds two entries of 1,832
  let mut few = Vec::new();
  for _ in 0..4 {
    wire::duplicate(&mut few, 0);
  }
  net.write(client, enc, &few, false);
  net.run();
  assert_eq!(net.server_close(client), None);
  let mut flood = Vec::new();
  for _ in 0..200 {
    wire::duplicate(&mut flood, 0);
  }
  net.write(client, enc, &flood, false);
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x107)));
}

// Ruling T13-e: an encoder instruction longer than what is retained is kept whole; a request
// stream that is reset while its section is blocked is cancelled on the decoder stream; with no
// dynamic table, an insert is an encoder stream error.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_obligations() {
  let params = H3Params { qpack_max_table_capacity: 16_384, ..dynamic_params() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let long = vec![b'z'; 6000];
  let mut encoder = encoder_stream(16_384);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  wire::insert_literal(&mut encoder, b"x-long", &long, false);
  let enc = net.open_uni(client, &encoder[..2000]);
  net.run();
  for range in [2000..4000, 4000..encoder.len()] {
    net.write(client, enc, &encoder[range], false);
    net.run();
  }
  // 16,384 / 32 = 512 entries: the encoded Required Insert Count wraps at 1,024
  let mut section = Vec::new();
  wire::prefix(&mut section, 2, 2, 512);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, true, SCHEME_HTTPS);
  wire::indexed(&mut section, false, 1);
  wire::indexed(&mut section, true, PATH_ROOT);
  wire::indexed(&mut section, false, 0);
  let id = net.send(client, &frame(0x01, &section), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.app.handler.seen[0].fields, [(b"x-long".to_vec(), long)]);
  // Blocked, then reset by the client: a Stream Cancellation, and nothing kept
  let mut section = Vec::new();
  wire::prefix(&mut section, 3, 3, 512);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, false, 0);
  let blocked = net.send(client, &frame(0x01, &section), false);
  net.run();
  assert_eq!(live(&mut net, client), 1);
  net.reset(client, blocked, 0x10c);
  net.run();
  assert_eq!(live(&mut net, client), 0);
  let decoder_out = net.server_streams(client)[2].1.clone();
  assert_eq!(decoder_out.last(), Some(&(0x40 | u8::try_from(blocked.0).unwrap())));
  assert!(net.resets(client).contains(&(blocked.0, 0x10c)));
  assert_eq!(net.server_close(client), None);
  // No dynamic table: an insert is an error of the encoder stream
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let mut encoder = vec![0x02];
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = net.open_uni(client, &encoder);
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x201)));
}

// Ruling T13-f: what RFC 9114 makes a connection error closes the connection with its code.
#[cfg_attr(miri, ignore)]
#[test]
fn connection_errors_of_rfc_9114() {
  type Case = (&'static str, u64, fn(&mut H3Net, usize));
  let settings = || control_stream(client_settings());
  let cases: [Case; 25] = [
    ("second control stream", 0x103, |net, c| {
      let _ = net.open_uni(c, &control_stream(client_settings()));
      net.run();
      let _ = net.open_uni(c, &control_stream(client_settings()));
    }),
    ("control stream without SETTINGS first", 0x10a, |net, c| {
      let _ = net.open_uni(c, &[&[0x00][..], &frame(0x07, &varint(0))].concat());
    }),
    ("second SETTINGS", 0x105, |net, c| {
      let settings = control_stream(client_settings());
      let _ = net.open_uni(c, &[&settings[..], &settings[1..]].concat());
    }),
    ("DATA on the control stream", 0x105, |net, c| {
      let _ =
        net.open_uni(c, &[&control_stream(client_settings())[..], &data_frame(b"x")].concat());
    }),
    ("HTTP/2 frame type on the control stream", 0x105, |net, c| {
      let _ =
        net.open_uni(c, &[&control_stream(client_settings())[..], &frame(0x06, b"")].concat());
    }),
    ("push stream of a client", 0x103, |net, c| {
      let _ = net.open_uni(c, &[0x01, 0x00]);
    }),
    ("second encoder stream", 0x103, |net, c| {
      let _ = net.open_uni(c, &[0x02]);
      net.run();
      let _ = net.open_uni(c, &[0x02]);
    }),
    ("DATA before HEADERS", 0x105, |net, c| {
      let _ = net.send(c, &[&data_frame(b"x")[..], &headers_frame(&GET)].concat(), true);
    }),
    ("SETTINGS on a request stream", 0x105, |net, c| {
      let _ = net.send(c, &[&headers_frame(&GET)[..], &frame(0x04, b"")].concat(), true);
    }),
    ("HTTP/2 frame type on a request stream", 0x105, |net, c| {
      let _ = net.send(c, &[&frame(0x02, b"")[..], &headers_frame(&GET)].concat(), true);
    }),
    ("DATA after the trailers", 0x105, |net, c| {
      let request = [
        &headers_frame(&request_fields(b"POST", b"/", &[]))[..],
        &headers_frame(&[(b"x-t", b"1")]),
        &data_frame(b"x"),
      ]
      .concat();
      let _ = net.send(c, &request, true);
    }),
    ("frame cut by the FIN", 0x106, |net, c| {
      let _ = net.send(c, &headers_frame(&GET)[..5], true);
    }),
    ("CANCEL_PUSH without MAX_PUSH_ID", 0x108, |net, c| {
      let control = [&control_stream(client_settings())[..], &frame(0x03, &varint(0))].concat();
      let _ = net.open_uni(c, &control);
    }),
    ("MAX_PUSH_ID lowered", 0x108, |net, c| {
      let frames = [&frame(0x0d, &varint(5))[..], &frame(0x0d, &varint(3))].concat();
      let _ = net.open_uni(c, &[&control_stream(client_settings())[..], &frames].concat());
    }),
    ("encoder stream finished", 0x104, |net, c| {
      let id = net.open_uni(c, &[0x02]);
      net.run();
      net.write(c, id, b"", true);
    }),
    ("decoder stream reset", 0x104, |net, c| {
      let id = net.open_uni(c, &[0x03]);
      net.run();
      net.reset(c, id, 0x10c);
    }),
    ("STOP_SENDING on the control stream of the server", 0x104, |net, c| {
      net.stop_sending(c, StreamId(3), 0x100);
    }),
    ("Section Acknowledgment of a static-only encoder", 0x202, |net, c| {
      let _ = net.open_uni(c, &[0x03, 0x80]);
    }),
    // New cases, beyond the in-tree list
    ("Insert Count Increment of a static-only encoder", 0x202, |net, c| {
      let _ = net.open_uni(c, &[0x03, 0x01]);
    }),
    ("GOAWAY of the client that raises its identifier", 0x108, |net, c| {
      let frames = [&frame(0x07, &varint(8))[..], &frame(0x07, &varint(12))].concat();
      let _ = net.open_uni(c, &[&control_stream(client_settings())[..], &frames].concat());
    }),
    ("SETTINGS with an HTTP/2 identifier", 0x109, |net, c| {
      let _ = net.open_uni(c, &[&[0x00][..], &frame(0x04, &[0x02, 0x00])].concat());
    }),
    ("SETTINGS with an identifier twice", 0x109, |net, c| {
      let _ = net.open_uni(c, &[&[0x00][..], &frame(0x04, &[0x01, 0x00, 0x01, 0x00])].concat());
    }),
    ("SETTINGS cut inside a parameter", 0x106, |net, c| {
      let _ = net.open_uni(c, &[&[0x00][..], &frame(0x04, &[0x01])].concat());
    }),
    ("control frame over 4 KiB", 0x107, |net, c| {
      let big = frame(0x07, &[0x40; 5000]);
      let _ = net.open_uni(c, &[&control_stream(client_settings())[..], &big].concat());
    }),
    ("GOAWAY with bytes after its identifier", 0x106, |net, c| {
      let control = [&control_stream(client_settings())[..], &frame(0x07, &[0x00, 0x00])].concat();
      let _ = net.open_uni(c, &control);
    }),
  ];
  let _ = settings;
  for (name, code, case) in cases {
    let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
    case(&mut net, client);
    net.run();
    assert_eq!(net.server_close(client), Some((true, code)), "{name}");
  }
}

// Ruling T13-f: unknown frames, settings and stream types, PRIORITY_UPDATE and the push frames of
// a client that allows pushes are ignored; a request that ends without a head is incomplete.
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_and_ignored_elements() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  // SETTINGS with unknown identifiers (0x21 is GREASE, 0x33 H3_DATAGRAM)
  let mut control = vec![0x00];
  control.extend_from_slice(&frame(0x04, &[0x01, 0x00, 0x21, 0x05, 0x33, 0x01]));
  for elem in [
    frame(PRIORITY_UPDATE, b"\x00u=1"),
    frame(0x21, b""),
    frame(0x0d, &varint(10)),
    frame(0x03, &varint(3)),
    frame(0x07, &varint(8)),
    frame(0x7fff, &[0; 5000]),
  ] {
    control.extend_from_slice(&elem);
  }
  let _ = net.open_uni(client, &control);
  let unknown = net.open_uni(client, &[0x21, 1, 2, 3]);
  net.run();
  assert!(net.stops(client).contains(&(unknown.0, 0x103)));
  let settings = net.server_state(client, H3ConnState::peer_settings).unwrap();
  assert_eq!(settings, Some(client_settings()));
  let id = net.send(client, &frame(0x21, b"x"), true);
  net.run();
  assert!(net.resets(client).contains(&(id.0, 0x10d)));
  let id = net.send(client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.server_close(client), None);
}

// Fix V1 (ruling T13-g): the request buffers of a connection hold at most
// `max_buffered_body_per_conn`: a request that would take more is answered with 413, the others go
// on.
#[cfg_attr(miri, ignore)]
#[test]
fn buffered_requests_are_capped_per_connection() {
  const CAP: usize = 1_000_000;
  let params = H3Params {
    max_buffered_body_per_conn: CAP as u32,
    max_request_body: 600_000,
    ..H3Params::default()
  };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let body: Vec<u8> = (0..400_000u32).map(|el| (el % 249) as u8).collect();
  let first = net.send(client, &post(b"/a", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&mut net, client) <= CAP);
  let second = net.send(client, &post(b"/b", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&mut net, client) <= CAP, "{}", buffered(&mut net, client));
  let third = net.send(client, &post(b"/c", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&mut net, client) <= CAP, "{}", buffered(&mut net, client));
  assert_eq!(net.status(client, third).as_deref(), Some(&b"413"[..]));
  assert!(net.response(client, first).is_none() && net.response(client, second).is_none());
  for id in [first, second] {
    net.write(client, id, b"", true);
  }
  net.run();
  assert_eq!(net.status(client, first).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.status(client, second).as_deref(), Some(&b"200"[..]));
  assert!(net.app.handler.seen.iter().all(|el| el.body == body));
  assert_eq!(net.app.handler.count, 2);
  // What they held is given back: only small buffers stay
  assert!(buffered(&mut net, client) <= 64 * 1024, "{}", buffered(&mut net, client));
  let id = net.send(client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.server_close(client), None);
}

// Fix V1: requests that never finish and the buffers that finished requests leave can not make the
// connection hold more than the cap; what finished requests leave is freed for a large request.
#[cfg_attr(miri, ignore)]
#[test]
fn unfinished_and_finished_requests_cannot_pin_more_than_the_cap() {
  const CAP: usize = 1_000_000;
  let params = H3Params {
    max_buffered_body_per_conn: CAP as u32,
    max_request_body: 600_000,
    ..H3Params::default()
  };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let large: Vec<u8> = vec![7; 300_000];
  for _ in 0..2 {
    let id = net.send(client, &post(b"/done", large.len(), &large), true);
    net.run_for(1024);
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  }
  // Fifty requests that never finish (no FIN), with 15,000 bytes of body each
  let small = vec![3; 15_000];
  let pending: Vec<StreamId> =
    (0..50).map(|_| net.send(client, &post(b"/slow", small.len(), &small), false)).collect();
  net.run_for(1024);
  assert!(buffered(&mut net, client) <= CAP, "{}", buffered(&mut net, client));
  assert!(pending.iter().all(|id| net.response(client, *id).is_none()));
  let id = net.send(client, &post(b"/big", large.len(), &large), true);
  net.run_for(1024);
  assert_eq!(net.status(client, id).as_deref(), Some(&b"413"[..]));
  assert!(buffered(&mut net, client) <= CAP);
  // Once they are abandoned, what they leave makes room again
  for id in &pending {
    net.reset(client, *id, 0x10c);
  }
  net.run();
  assert_eq!(live(&mut net, client), 0);
  let id = net.send(client, &post(b"/big", large.len(), &large), true);
  net.run_for(1024);
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert!(buffered(&mut net, client) <= CAP);
  assert_eq!(net.server_close(client), None);
}

// Fix V2 (ruling T13-h): a graceful close waits until the last response is acknowledged: lost, it
// is sent again first.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_waits_for_the_last_response_to_be_acknowledged() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  shutdown(&mut net);
  net.run();
  net.resume(client, parked);
  // The datagram with the response is lost
  net.clients[client].deaf = true;
  let _ = net.step();
  net.clients[client].deaf = false;
  assert!(net.response(client, parked).is_none());
  for _ in 0..32 {
    if net.server_close(client).is_some() {
      break;
    }
    assert!(net.advance_to_next_event());
    net.run();
  }
  let rsp = net.response(client, parked).unwrap();
  assert_eq!((rsp.fin, rsp.body.as_slice()), (true, &b"resumed"[..]));
  assert_eq!(net.server_close(client), Some((true, 0x100)));
}

// Fix V2 (ruling T13-h): the GOAWAY covers the streams that QUIC opened, and those that brought no
// request by the time the others are answered are refused with H3_REQUEST_REJECTED before the
// close, never dropped: one opened by a later one, one whose data waits for its start.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_refuses_the_streams_it_never_read() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let (implicit, answered, waiting) = net
    .client_ctx(client, |cx| {
      let implicit = cx.open_bidi()?;
      let answered = cx.open_bidi()?;
      cx.write(answered, &headers_frame(&GET), true)?;
      let waiting = cx.open_bidi()?;
      Ok::<_, rimu_quic::Error>((implicit, answered, waiting))
    })
    .unwrap();
  net.run();
  // The start of the third request is lost; what follows arrives and waits for it
  let request = headers_frame(&GET);
  net.write(client, waiting, &request[..5], false);
  let _lost = net.client_datagrams(client);
  net.write(client, waiting, &request[5..], false);
  net.run();
  assert!(net.response(client, waiting).is_none());
  assert_eq!(net.status(client, answered).as_deref(), Some(&b"200"[..]));
  shutdown(&mut net);
  net.run();
  let goaways: Vec<_> =
    net.server_control_frames(client).into_iter().filter(|el| el.0 == 0x07).collect();
  assert_eq!(goaways, [(0x07, varint(waiting.0 + 4))]);
  let resets = net.resets(client);
  assert!(resets.contains(&(implicit.0, 0x10b)), "{resets:?}");
  assert!(resets.contains(&(waiting.0, 0x10b)), "{resets:?}");
  assert_eq!(net.server_close(client), Some((true, 0x100)));
}

// Fix V3: decoder-stream output is written while the stream has little unsent, so a client that
// never gives credit on our decoder stream meets the bound of the decoder (H3_EXCESSIVE_LOAD)
// instead of growing the memory of the server.
#[cfg_attr(miri, ignore)]
#[test]
fn decoder_stream_output_without_credit_is_bounded() {
  let mut net = H3Net::new(QuicParams::default(), dynamic_params(), TestHandler::new(OK));
  net.client_params = QuicParams::default().set_stream_window(256);
  let client = net.add_client();
  // The server's decoder stream: its third unidirectional stream
  net.clients[client].conn.app_mut().hold = Some(11);
  net.run();
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = net.open_uni(client, &encoder);
  net.run();
  let request = dynamic_request(1, b"/", &[]);
  let mut sent = 0;
  while net.server_close(client).is_none() && sent < 12_000 {
    for _ in 0..64 {
      let _ = net.send(client, &request, true);
      sent += 1;
    }
    net.run();
    let logs = &mut net.clients[client].conn.app_mut().streams;
    logs.retain(|id, log| !(log.fin && *id & 0b11 == 0));
  }
  assert_eq!(net.server_close(client), Some((true, 0x107)), "{sent} requests");
}

// Fix V4: an entry keeps small buffers only once its request is done, a pooled box too, the pool
// has a byte budget, an idle trim frees it down, and the response buffer stays small.
#[cfg_attr(miri, ignore)]
#[test]
fn request_buffers_and_the_pool_stay_small() {
  let params = H3Params { max_request_body: 2 << 20, ..H3Params::default() };
  let mut net = H3Net::new(QuicParams::default(), params, TestHandler::new(&[9; 100_000]));
  let mut clients = Vec::new();
  for _ in 0..6 {
    let client = net.add_client();
    net.run();
    let body = vec![5; 500_000];
    let id = net.send(client, &post(b"/up", body.len(), &body), true);
    net.run_for(1024);
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
    let long = vec![b'v'; 10_000];
    let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-long", &long)]));
    let id = net.send(client, &request, true);
    net.run_for(1024);
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
    assert!(buffered(&mut net, client) <= 32 * 1024, "{}", buffered(&mut net, client));
    clients.push(client);
  }
  // The responses of 100,000 bytes went through the response buffer, which stays small
  assert!(net.app.scratch_bytes() <= 32 * 1024);
  for client in clients {
    close_client(&mut net, client);
  }
  net.run();
  net.advance(CLOSING_US);
  let app = &net.app;
  assert_eq!(app.pooled(), 6);
  assert!(app.pooled_bytes() <= 6 * 64 * 1024, "{}", app.pooled_bytes());
  assert!(app.pooled_bytes() <= H3Server::<TestHandler>::POOL_BYTES);
  net.app.trim_idle();
  let app = &net.app;
  assert!(app.pooled() <= H3Server::<TestHandler>::IDLE_POOLED, "{}", app.pooled());
  assert!(app.pooled_bytes() <= 2 << 20);
  assert!(app.scratch_bytes() == 0);
}

// Fix V5: a box that goes back to the pool holds no state of its connection: no dynamic table
// entry, no decoded section, no request.
#[cfg_attr(miri, ignore)]
#[test]
fn pooled_box_holds_no_request_state() {
  let (mut net, client) = connected(dynamic_params(), TestHandler::new(OK));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = net.open_uni(client, &encoder);
  net.run();
  let id = net.send(client, &dynamic_request(1, b"/", &[]), true);
  let _parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  let _unfinished = net.send(client, &post(b"/slow", 100, &[1; 10]), false);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(live(&mut net, client), 2);
  close_client(&mut net, client);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.app.pooled(), 1);
  assert!(net.app.pool_is_clear());
  // The handler heard that the connection of its parked request is gone
  assert_eq!(net.app.handler.conns_closed.len(), 1);
}

// Fix V6: RFC 9114 sections 4.2 and 4.3.1: fields of a connection, `content-length` that
// disagrees with itself, `host` twice or against `:authority`, userinfo in `host` or
// `:authority`: all stream errors H3_MESSAGE_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn authority_host_and_connection_fields_are_message_errors() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let get = |extra: &[(&[u8], &[u8])]| headers_frame(&request_fields(b"GET", b"/", extra));
  let cases: Vec<Vec<u8>> = vec![
    get(&[(b"keep-alive", b"timeout=5")]),
    get(&[(b"proxy-connection", b"keep-alive")]),
    get(&[(b"upgrade", b"websocket")]),
    get(&[(b"content-length", b"5"), (b"content-length", b"6")]),
    // The values disagree and the body has the length of the last one: only the check of the
    // repeated value refuses it
    {
      let fields = [(&b"content-length"[..], &b"6"[..]), (b"content-length", b"5")];
      let mut request = headers_frame(&request_fields(b"POST", b"/", &fields));
      request.extend_from_slice(&data_frame(b"hello"));
      request
    },
    get(&[(b"host", b"localhost"), (b"host", b"localhost")]),
    get(&[(b"host", b"other")]),
    get(&[(b"host", b"user@localhost")]),
    headers_frame(&[
      (b":method", b"GET"),
      (b":scheme", b"http"),
      (b":path", b"/"),
      (b"host", b"u@h"),
    ]),
    headers_frame(&[(b":method", b"CONNECT"), (b":authority", b"user@localhost:443")]),
  ];
  for (nth, case) in cases.iter().enumerate() {
    let id = net.send(client, case, true);
    net.run();
    assert!(net.resets(client).contains(&(id.0, 0x10e)), "case {nth}");
  }
  assert_eq!(net.app.handler.count, 0);
  // The same fields well formed are answered
  let id = net.send(client, &get(&[(b"host", b"localhost"), (b"content-length", b"0")]), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.server_close(client), None);
}

// The types of the long-header packets of a datagram (0 Initial, 2 Handshake), and 4 for a
// short-header packet, which ends it. Header protection hides neither the type nor the length.
fn packet_types(datagram: &[u8]) -> Vec<u8> {
  let mut rslt = Vec::new();
  let mut rest = datagram;
  while let Some(first) = rest.first().copied() {
    if first & 0x80 == 0 {
      rslt.push(4);
      break;
    }
    let ty = (first >> 4) & 0b11;
    rslt.push(ty);
    let dcid_len = usize::from(rest[5]);
    let scid_len = usize::from(rest[6 + dcid_len]);
    let mut at = 7 + dcid_len + scid_len;
    if ty == 0 {
      let (token_len, len) = rimu_quic::varint::decode_varint(&rest[at..]).unwrap();
      at += len + usize::try_from(token_len).unwrap();
    }
    let (length, len) = rimu_quic::varint::decode_varint(&rest[at..]).unwrap();
    at += len + usize::try_from(length).unwrap();
    rest = &rest[at..];
  }
  rslt
}

// Fix V7 (review focus 1): the client's Finished and its first request, coalesced in one
// datagram, are served in that turn: the handler runs on that datagram and the next flush of the
// server carries the response.
#[cfg_attr(miri, ignore)]
#[test]
fn first_request_coalesced_with_finished_is_answered_in_that_turn() {
  let mut net = H3Net::new(QuicParams::default(), H3Params::default(), TestHandler::new(OK));
  let client = net.add_client();
  for mut datagram in net.client_datagrams(client) {
    net.deliver_to_server(client, &mut datagram);
  }
  for (_, mut datagram) in net.server_datagrams() {
    net.deliver_to_client(client, &mut datagram);
  }
  let id = net.send(client, &headers_frame(&GET), true);
  let mut datagrams = net.client_datagrams(client);
  let idx = datagrams
    .iter()
    .position(|el| {
      let types = packet_types(el);
      types.contains(&2) && types.last() == Some(&4)
    })
    .unwrap();
  for datagram in &mut datagrams[..=idx] {
    assert_eq!(net.app.handler.count, 0);
    net.deliver_to_server(client, datagram);
  }
  assert_eq!(net.app.handler.count, 1);
  for (_, mut datagram) in net.server_datagrams() {
    net.deliver_to_client(client, &mut datagram);
  }
  let rsp = net.response(client, id).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.fin), (Some(&b"200"[..]), true));
}

// Fix in passing of task 14: a request that the handler parks keeps small buffers only, so that a
// parked upload does not hold the budget of the connection.
#[cfg_attr(miri, ignore)]
#[test]
fn parked_request_keeps_small_buffers() {
  let params = H3Params { max_request_body: 600_000, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let body = vec![7u8; 500_000];
  let parked = net.send(client, &post(b"/park", body.len(), &body), true);
  net.run_for(1024);
  assert_eq!(net.app.handler.parked, [parked]);
  assert_eq!(net.app.handler.seen[0].body.len(), body.len());
  assert!(buffered(&mut net, client) <= 64 * 1024, "{}", buffered(&mut net, client));
  net.resume(client, parked);
  net.run();
  let rsp = net.response(client, parked).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"resumed"[..]));
}

// Fix in passing of task 14 (a 413 path that no test covered): a head whose decoded fields do not
// fit in the buffer budget of the connection, while its frame fits in what the connection retains,
// is answered with 413.
#[cfg_attr(miri, ignore)]
#[test]
fn head_over_the_buffer_budget_gets_413() {
  let params = H3Params { max_buffered_body_per_conn: 2048, ..H3Params::default() };
  let (mut net, client) = connected(params, TestHandler::new(OK));
  let value = vec![b'a'; 3000];
  let fields = [(&b"x-large"[..], value.as_slice())];
  let id = net.send(client, &headers_frame(&request_fields(b"GET", b"/", &fields)), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"413"[..]));
  assert!(net.stops(client).contains(&(id.0, 0x100)));
  assert_eq!(net.app.handler.count, 0);
  assert_eq!(net.server_close(client), None);
}

// Fix in passing of task 14 (the other 413 path that no test covered): the bytes of a HEADERS frame
// larger than what the connection retains wait in the head buffer of the request, within the
// buffer budget: a first piece that does not fit, or pieces that fit one by one and not together,
// are answered with 413.
#[cfg_attr(miri, ignore)]
#[test]
fn waiting_bytes_over_the_buffer_budget_get_413() {
  for (budget, len) in [(1000u32, 6000usize), (8000, 9600)] {
    let params = H3Params { max_buffered_body_per_conn: budget, ..H3Params::default() };
    let (mut net, client) = connected(params, TestHandler::new(OK));
    let value = vec![b'b'; len];
    let fields = [(&b"x-large"[..], value.as_slice())];
    let id = net.send(client, &headers_frame(&request_fields(b"GET", b"/", &fields)), true);
    net.run();
    assert_eq!(net.status(client, id).as_deref(), Some(&b"413"[..]), "{budget}");
    assert!(net.stops(client).contains(&(id.0, 0x100)), "{budget}");
    assert_eq!(net.app.handler.count, 0);
    assert_eq!(net.server_close(client), None);
  }
}

// Task 18: the defaults are the measured ones; no QPACK dynamic table, the limits of task 13, the
// lean response heads, static-only responses.
#[test]
fn h3_params_defaults_are_the_measured_ones() {
  let params = H3Params::default();
  assert_eq!((params.qpack_max_table_capacity, params.qpack_blocked_streams), (0, 0));
  assert_eq!(params.max_field_section_size, 16 * 1024);
  assert_eq!(params.max_request_body, 1 << 20);
  assert_eq!(params.max_buffered_body_per_conn, 16 << 20);
  assert_eq!((params.content_length, params.date, params.response_encoder), (false, false, None));
  let rfc = params.rfc9110_headers(true);
  assert!(rfc.content_length && rfc.date);
}

// A handler error resets its stream with H3_INTERNAL_ERROR; the connection serves on.
#[cfg_attr(miri, ignore)]
#[test]
fn handler_error_resets_its_stream_only() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let id = net.send(client, &headers_frame(&request_fields(b"GET", b"/err", &[])), true);
  net.run();
  assert!(net.resets(client).contains(&(id.0, 0x102)), "{:?}", net.resets(client));
  let id = net.send(client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(net.server_close(client), None);
}

// Ruling T14-d: a parked request that the client abandons, or whose connection closes, is given up
// by the handler (`on_abandoned`, `on_conn_closed`); a resume that finds it gone is ignored.
#[cfg_attr(miri, ignore)]
#[test]
fn abandoned_and_orphaned_parked_requests_are_dropped() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let parked = net.send(client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  // The client wants no answer anymore (its request went whole: a reset of it would change nothing)
  net.stop_sending(client, parked, 0x10c);
  net.run();
  let handle = net.handle(client).unwrap();
  assert_eq!(net.app.handler.abandoned, [(handle, parked)]);
  assert_eq!(live(&mut net, client), 0);
  // A resume of it now: the handler answers into a stream that is gone, and nothing breaks
  net.resume(client, parked);
  net.run();
  assert_eq!(net.server_close(client), None);
  let _orphan = net.send(client, &headers_frame(&request_fields(b"GET", b"/park2", &[])), true);
  net.run();
  close_client(&mut net, client);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.app.handler.conns_closed, [handle]);
  assert_eq!(net.endpoint.stats().conns, 0);
  // The next client is served
  let next = net.add_client();
  net.run();
  let id = net.send(next, &headers_frame(&GET), true);
  net.run();
  assert_eq!(net.status(next, id).as_deref(), Some(&b"200"[..]));
}

/// Answers through `respond_with`: `/hello` with `hello`, `/no-content` with 204,
/// `/not-modified` with 304, `/ref` with a shared body by reference, others with 404; HEAD as
/// RFC 9110 has it.
#[derive(Debug)]
struct LeanHandler {
  shared: SharedBytes,
}

impl LeanHandler {
  fn new() -> Self {
    Self { shared: SharedBytes::from_slice(&[b'r'; 3000]) }
  }
}

impl Handler for LeanHandler {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    let text = ResponseFields::with_type(200, b"text/plain");
    let others: [(&[u8], &[u8]); 1] = [(b"server", b"rimu")];
    match req.path {
      b"/hello" => {
        cx.respond_with(&ResponseFields { others: &others, ..text }, Body::Bytes(b"hello"))?
      }
      b"/no-content" => cx.respond_with(&ResponseFields::status(204), Body::Empty)?,
      b"/not-modified" => cx.respond_with(&ResponseFields::status(304), Body::Bytes(b"x"))?,
      b"/ref" => {
        let body = BodyRef::try_from(self.shared.clone())?;
        cx.respond_with(&text, Body::Ref(body))?;
      }
      _ => cx.respond_with(&ResponseFields::with_type(404, b"text/plain"), Body::Bytes(b"none"))?,
    }
    Ok(ReqOutcome::Responded)
  }
}

fn lean_net(params: H3Params) -> (H3Net<LeanHandler>, usize) {
  let mut net = H3Net::new(QuicParams::default(), params, LeanHandler::new());
  let client = net.add_client();
  net.run();
  (net, client)
}

fn lean_get(
  net: &mut H3Net<LeanHandler>,
  client: usize,
  method: &[u8],
  path: &[u8],
) -> crate::testing::Response {
  let id = net.send(client, &headers_frame(&request_fields(method, path, &[])), true);
  net.run();
  net.response(client, id).unwrap()
}

// Decision Q2: by default a response carries `:status` and `content-type` (and what the handler
// adds) only: no `date`, no `content-length`, and a response to HEAD keeps `content-length`.
#[cfg_attr(miri, ignore)]
#[test]
fn default_headers_are_status_and_content_type_only() {
  let (mut net, client) = lean_net(H3Params::default());
  let rsp = lean_get(&mut net, client, b"GET", b"/hello");
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"hello"[..]));
  let mut names: Vec<&[u8]> = rsp.fields.iter().map(|el| el.0.as_slice()).collect();
  names.sort_unstable();
  assert_eq!(names, [&b":status"[..], b"content-type", b"server"], "{names:?}");
  let rsp = lean_get(&mut net, client, b"GET", b"/nothing-here");
  assert_eq!(
    (rsp.field(b":status"), rsp.field(b"date"), rsp.field(b"content-length")),
    (Some(&b"404"[..]), None, None)
  );
  let head = lean_get(&mut net, client, b"HEAD", b"/hello");
  assert_eq!((head.field(b"date"), head.field(b"content-length")), (None, Some(&b"5"[..])));
  assert_eq!((head.frames.as_slice(), head.body.as_slice()), (&[0x01][..], &b""[..]));
}

// Decision Q2: `rfc9110_headers(true)` turns on `date` (RFC 9110 section 6.6.1) and
// `content-length` (section 8.6) together; each has a flag of its own.
#[cfg_attr(miri, ignore)]
#[test]
fn rfc9110_flags_add_date_and_content_length() {
  for (content_length, date) in [(true, true), (true, false), (false, true)] {
    let params = H3Params { content_length, date, ..H3Params::default() };
    let (mut net, client) = lean_net(params);
    net.app.set_date(784_111_777);
    let rsp = lean_get(&mut net, client, b"GET", b"/hello");
    assert_eq!(rsp.body, b"hello");
    assert_eq!(rsp.field(b"content-length"), content_length.then_some(&b"5"[..]));
    assert_eq!(rsp.field(b"date"), date.then_some(&b"Sun, 06 Nov 1994 08:49:37 GMT"[..]));
    let head = lean_get(&mut net, client, b"HEAD", b"/hello");
    assert_eq!(head.field(b"content-length"), Some(&b"5"[..]));
  }
}

// Ruling T14-i (RFC 9110 sections 9.3.2, 8.6, 15.3.5 and 15.4.5): a response to HEAD has the fields
// that GET gets, `content-length` included, and no content; 204 has neither content nor
// `content-length`; 304 has no content.
#[cfg_attr(miri, ignore)]
#[test]
fn head_204_and_304_carry_no_content() {
  let (mut net, client) = lean_net(H3Params::default().rfc9110_headers(true));
  let get = lean_get(&mut net, client, b"GET", b"/hello");
  assert_eq!((get.field(b"content-length"), get.body.as_slice()), (Some(&b"5"[..]), &b"hello"[..]));
  let head = lean_get(&mut net, client, b"HEAD", b"/hello");
  assert_eq!(head.field(b":status"), Some(&b"200"[..]));
  assert_eq!(head.field(b"content-length"), Some(&b"5"[..]));
  assert_eq!(head.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!((head.frames.as_slice(), head.body.as_slice()), (&[0x01][..], &b""[..]));
  for (path, code) in [(&b"/no-content"[..], &b"204"[..]), (b"/not-modified", b"304")] {
    for method in [&b"GET"[..], b"HEAD"] {
      let rsp = lean_get(&mut net, client, method, path);
      assert_eq!(rsp.field(b":status"), Some(code));
      assert_eq!(rsp.field(b"content-length"), None);
      assert_eq!((rsp.frames.as_slice(), rsp.body.as_slice()), (&[0x01][..], &b""[..]));
    }
  }
}

// A body by reference leaves without a copy and arrives whole; the shared bytes are released once
// the stream does not need them.
#[cfg_attr(miri, ignore)]
#[test]
fn body_by_reference_arrives_and_is_released() {
  let (mut net, client) = lean_net(H3Params::default());
  for _ in 0..3 {
    let rsp = lean_get(&mut net, client, b"GET", b"/ref");
    assert!(rsp.fin && rsp.body.len() == 3000 && rsp.body.iter().all(|el| *el == b'r'));
  }
  net.advance(100_000);
  net.run();
  // Only the handler's copy is left
  let bytes = net.app.handler.shared.clone();
  drop(net);
  let body = BodyRef::try_from(bytes).unwrap();
  assert_eq!(body.len(), 3000);
}

// Ruling T18-c: the field sections that the worker decoded, and those that its decode memo
// replayed, are counted: the same request eight times on one connection decodes its head once and
// replays it seven times. A connection of its own starts with an empty memo.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_sections_and_memo_hits_are_counted() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let request = headers_frame(&request_fields(b"GET", b"/baseline2?a=1&b=1", &[]));
  for _ in 0..8 {
    let id = net.send(client, &request, true);
    net.run();
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  }
  let counters = net.app.qpack_counters();
  assert_eq!((counters.sections, counters.memo_hits), (8, 7), "{counters:?}");
  let other = net.add_client();
  net.run();
  let id = net.send(other, &request, true);
  net.run();
  assert_eq!(net.status(other, id).as_deref(), Some(&b"200"[..]));
  let counters = net.app.qpack_counters();
  assert_eq!((counters.sections, counters.memo_hits), (9, 7), "{counters:?}");
}

// Ruling T16-a: fields that are all ASCII come out as text without a second check; one with
// obs-text has none as text, and the caller checks them.
#[cfg_attr(miri, ignore)]
#[test]
fn field_values_beyond_ascii_are_checked_once_more() {
  #[derive(Debug, Default)]
  struct Ascii(Vec<Option<usize>>);
  impl Handler for Ascii {
    fn on_request(
      &mut self,
      cx: &mut ReqCtx<'_, '_>,
      req: &Request<'_>,
    ) -> crate::Result<ReqOutcome> {
      self.0.push(req.fields.ascii().map(Iterator::count));
      assert_eq!(req.fields.len(), 1);
      assert!(req.fields.get(b"x-a").is_some() && req.fields.get(b"x-b").is_none());
      cx.respond_fields(&[(b":status", b"200")], b"")?;
      Ok(ReqOutcome::Responded)
    }
  }
  let mut net = H3Net::new(QuicParams::default(), H3Params::default(), Ascii::default());
  let client = net.add_client();
  net.run();
  for value in [&b"plain"[..], "café".as_bytes(), b"caf\xe9"] {
    let id =
      net.send(client, &headers_frame(&request_fields(b"GET", b"/", &[(b"x-a", value)])), true);
    net.run();
    assert_eq!(net.status(client, id).as_deref(), Some(&b"200"[..]));
  }
  assert_eq!(net.app.handler.0, [Some(1), None, None]);
}

/// Takes bodies as they arrive and echoes their length once they end; a request to `/early`
/// is answered at its head, before its body.
#[derive(Debug, Default)]
struct Streamer {
  chunks: Vec<(u64, usize, bool)>,
  heads: u64,
}

impl Handler for Streamer {
  fn body_mode(&mut self, _req: &Request<'_>) -> BodyMode {
    BodyMode::Stream
  }

  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    self.heads += 1;
    assert!(req.body.is_empty());
    if req.path == b"/early" {
      cx.respond_with(&ResponseFields::status(200), Body::Bytes(b"early"))?;
      return Ok(ReqOutcome::Responded);
    }
    Ok(ReqOutcome::Parked)
  }

  fn on_body(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    stream: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    self.chunks.push((stream.0, data.len(), fin));
    if fin && !cx.responded() {
      let total: usize = self.chunks.iter().filter(|el| el.0 == stream.0).map(|el| el.1).sum();
      let text = format!("{total}");
      // A head, then the content in two DATA frames: a response streamed
      cx.send_head_with(&ResponseFields::with_type(200, b"text/plain"), None)?;
      cx.send_data(&text.as_bytes()[..1], false)?;
      cx.send_data(&text.as_bytes()[1..], true)?;
    }
    Ok(())
  }
}

// A handler that takes bodies as they arrive gets the head first and the DATA payloads one by one,
// without buffering and past the limit of buffered bodies; it can answer at the end, by a streamed
// response, or at the head.
#[cfg_attr(miri, ignore)]
#[test]
fn streamed_request_bodies_and_streamed_responses() {
  let params = H3Params { max_request_body: 1000, ..H3Params::default() };
  let mut net = H3Net::new(QuicParams::default(), params, Streamer::default());
  let client = net.add_client();
  net.run();
  let body = vec![9u8; 200_000];
  let mut request =
    headers_frame(&request_fields(b"POST", b"/up", &[(b"content-length", b"200000")]));
  for chunk in body.chunks(50_000) {
    request.extend_from_slice(&data_frame(chunk));
  }
  request.extend_from_slice(&headers_frame(&[(b"x-trailer", b"1")]));
  let id = net.send(client, &request[..100], false);
  net.run();
  assert_eq!(net.app.handler.heads, 1);
  net.write(client, id, &request[100..], true);
  net.run_for(1024);
  let rsp = net.response(client, id).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"200000"[..]));
  assert_eq!(rsp.frames, [0x01, 0x00, 0x00]);
  let chunks: Vec<_> = net.app.handler.chunks.iter().filter(|el| el.0 == id.0).copied().collect();
  assert!(chunks.len() > 4, "{chunks:?}");
  assert_eq!(chunks.last(), Some(&(id.0, 0, true)));
  assert!(net.server_state(client, H3ConnState::buffered).unwrap() <= 16 * 1024);
  // Answered at its head: the body is still read, to its end
  let mut early = headers_frame(&request_fields(b"POST", b"/early", &[]));
  early.extend_from_slice(&data_frame(b"abc"));
  let id = net.send(client, &early, true);
  net.run();
  assert_eq!(net.response(client, id).unwrap().body, b"early");
  assert_eq!(net.app.handler.chunks.last(), Some(&(id.0, 0, true)));
  // A content-length that the body contradicts: a stream error at the end
  let mut wrong = headers_frame(&request_fields(b"POST", b"/up", &[(b"content-length", b"5")]));
  wrong.extend_from_slice(&data_frame(b"abc"));
  let id = net.send(client, &wrong, true);
  net.run();
  assert!(net.resets(client).contains(&(id.0, 0x10e)));
  assert_eq!(net.server_state(client, H3ConnState::live_requests).unwrap(), 0);
  assert_eq!(net.server_close(client), None);
}

/// Answers with fields that the dynamic table of the connection encodes.
#[derive(Debug, Default)]
struct Dynamic;

impl Handler for Dynamic {
  fn on_request(
    &mut self,
    cx: &mut ReqCtx<'_, '_>,
    req: &Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    if req.path == b"/with" {
      let fields = ResponseFields {
        others: &[(b"x-server-token", b"abcdefghijklmnop")],
        ..ResponseFields::with_type(200, b"text/x-dynamic")
      };
      cx.respond_with(&fields, Body::Bytes(b"d"))?;
    } else {
      cx.respond_fields(&[(b":status", b"200"), (b"x-server-token", b"abcdefghijklmnop")], b"f")?;
    }
    Ok(ReqOutcome::Responded)
  }
}

// With `response_encoder`, response heads use the dynamic table once the SETTINGS of the client
// allow one: the inserts go out on the encoder stream of the server, sections reference them once
// the client acknowledged them (no blocking allowed here), the client's Section Acknowledgments
// and Insert Count Increments feed the encoder, and an acknowledgment of nothing is a
// QPACK_DECODER_STREAM_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn dynamic_response_heads() {
  let config = EncoderConfig {
    max_table_capacity: 1024,
    insert_policy: InsertPolicy::Always,
    allow_blocking: false,
    ..EncoderConfig::default()
  };
  let params = H3Params { response_encoder: Some(config), ..H3Params::default() };
  let mut net = H3Net::new(QuicParams::default(), params, Dynamic);
  let client = net.add_client();
  net.run();
  // Before the SETTINGS of the client: static references and literals only
  let get = headers_frame(&request_fields(b"GET", b"/fields", &[]));
  let id = net.send(client, &get, true);
  net.run();
  let rsp = net.response(client, id).unwrap();
  assert_eq!(rsp.field(b"x-server-token"), Some(&b"abcdefghijklmnop"[..]));
  assert!(net.server_streams(client).iter().find(|el| el.0 == 2).unwrap().1.is_empty());
  let settings = H3Settings {
    qpack_max_table_capacity: 4096,
    qpack_blocked_streams: 8,
    max_field_section_size: None,
  };
  let _ = net.open_uni(client, &control_stream(settings));
  net.run();
  for path in [&b"/fields"[..], b"/with"] {
    let id = net.send(client, &headers_frame(&request_fields(b"GET", path, &[])), true);
    net.run();
    let rsp = net.response(client, id).unwrap();
    assert_eq!(rsp.field(b":status"), Some(&b"200"[..]));
    assert_eq!(rsp.field(b"x-server-token"), Some(&b"abcdefghijklmnop"[..]));
  }
  // The encoder stream of the server: Set Dynamic Table Capacity, then inserts
  let encoder = net.server_streams(client).into_iter().find(|el| el.0 == 2).unwrap().1;
  assert_eq!(encoder[0] & 0xe0, 0x20, "{encoder:?}");
  assert!(encoder.len() > 20);
  // The client acknowledges every insert; the next section references the table
  let inserts = {
    let mut decoder = rimu_qpack::Decoder::new(rimu_qpack::DecoderConfig {
      max_table_capacity: 4096,
      ..rimu_qpack::DecoderConfig::default()
    });
    decoder.feed_encoder_stream(&encoder).unwrap();
    decoder.insert_count()
  };
  assert!(inserts > 0);
  let mut decoder_stream = vec![0x03];
  wire::insert_count_increment(&mut decoder_stream, inserts);
  let dec = net.open_uni(client, &decoder_stream);
  net.run();
  let id = net.send(client, &get, true);
  net.run();
  let rsp = net.response(client, id).unwrap();
  assert_eq!(rsp.field(b"x-server-token"), Some(&b"abcdefghijklmnop"[..]));
  let log = &net.clients[client].conn.app().streams[&id.0].data;
  // The HEADERS frame's Required Insert Count is not 0: it references the table
  assert_ne!(log[2], 0, "{log:?}");
  let mut ack = Vec::new();
  wire::section_ack(&mut ack, id.0);
  net.write(client, dec, &ack, false);
  net.run();
  assert_eq!(net.server_close(client), None);
  // The same acknowledgment again: there is no section left to acknowledge
  net.write(client, dec, &ack, false);
  net.run();
  assert_eq!(net.server_close(client), Some((true, 0x202)));
}

// The response heads of `respond_with`, with RFC 9110's fields, and those of a response by
// reference, allocate nothing per request once warm.
#[cfg_attr(miri, ignore)]
#[test]
fn lean_and_rfc9110_heads_allocate_nothing_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  for rfc9110 in [false, true] {
    let mut net = H3Net::new(
      QuicParams::default(),
      H3Params::default().rfc9110_headers(rfc9110),
      LeanHandler::new(),
    );
    net.count((&SERVER, &OTHERS));
    net.app.set_date(1_794_571_200);
    let client = net.add_client();
    net.run();
    let _ = net.open_uni(client, &control_stream(client_settings()));
    let requests: Vec<Vec<u8>> = [&b"/hello"[..], b"/ref", b"/no-content", b"/missing"]
      .iter()
      .map(|path| headers_frame(&request_fields(b"GET", path, &[])))
      .collect();
    let round = |net: &mut H3Net<LeanHandler>| {
      for request in &requests {
        for _ in 0..8 {
          let id = net.send(client, request, true);
          net.run();
          assert!(net.response(client, id).unwrap().fin);
        }
      }
      net.advance(30_000);
      net.run();
    };
    round(&mut net);
    round(&mut net);
    let before = SERVER.load(Ordering::Relaxed);
    round(&mut net);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    assert_eq!(allocations, 0, "{allocations} allocations for 32 responses, rfc9110 {rfc9110}");
  }
  count_allocations_in(&OTHERS);
}

// Task 23b of the in-tree tests: the stream slots of a worker can still run out when clients hold
// whole windows of requests on many connections, since the slots for requests are shared. It fails
// per stream and per connection, with documented codes, and the worker goes on: a request that
// finds no slot is refused with H3_REQUEST_REJECTED (ruling T10-c) while its connection stays
// open, a new connection whose own streams find none is closed with INTERNAL_ERROR, and once slots
// are free again every connection is served.
#[cfg_attr(miri, ignore)]
#[test]
fn exhausted_stream_slots_fail_per_stream_and_connection() {
  let rejected = QuicLimits::default().stream_rejected_app_code;
  let mut net = H3Net::new(QuicParams::default(), H3Params::default(), TestHandler::new(OK));
  let control = control_stream(client_settings());
  let clients = [net.add_client(), net.add_client()];
  net.run();
  for idx in clients {
    let _ = net.open_uni(idx, &control);
    let _ = net.open_uni(idx, &[0x02]);
    let _ = net.open_uni(idx, &[0x03]);
  }
  net.run();
  // Room for a whole window of requests and four more
  assert_eq!(net.endpoint.stream_slots_in_use(), 12);
  net.endpoint.set_stream_slot_cap(12 + 256 + 4);
  let park = headers_frame(&request_fields(b"GET", b"/park", &[]));
  let parked: Vec<StreamId> = (0..256).map(|_| net.send(clients[0], &park, true)).collect();
  net.run();
  let more: Vec<StreamId> = (0..8).map(|_| net.send(clients[1], &park, true)).collect();
  net.run();
  assert_eq!(net.app.handler.parked.len(), 256 + 4);
  // The requests came whole, with their FIN: a RESET_STREAM, and no STOP_SENDING, refuses them
  let refused: Vec<(u64, u64)> = more[4..].iter().map(|el| (el.0, rejected)).collect();
  assert_eq!(net.resets(clients[1]), refused);
  for idx in clients {
    assert!(net.clients[idx].conn.is_confirmed());
    assert_eq!(net.server_close(idx), None);
  }
  // A new connection finds no slot for its own streams
  let late = net.add_client();
  net.run();
  assert_eq!(net.server_close(late), Some((false, 0x01)));
  // Slots free again: the parked requests are answered, then the others are served
  for id in &parked {
    net.resume(clients[0], *id);
  }
  net.run();
  net.advance(100_000);
  net.run();
  assert!(parked.iter().all(|el| net.status(clients[0], *el).as_deref() == Some(&b"200"[..])));
  let request = headers_frame(&GET);
  for idx in clients {
    let id = net.send(idx, &request, true);
    net.run();
    assert_eq!(net.status(idx, id).as_deref(), Some(&b"200"[..]), "client {idx}");
  }
}

// Task 14 of the in-tree tests: a graceful close does not overtake the RESET_STREAM of a stream
// refused for want of a slot (ruling T10-c): lost, the reset is sent again and acknowledged before
// the CONNECTION_CLOSE.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_waits_for_the_reset_of_a_refused_stream() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  let live = net.endpoint.stream_slots_in_use();
  net.endpoint.set_stream_slot_cap(live);
  let refused = net.send(client, &headers_frame(&GET), true);
  // The request arrives and is refused; the refusal is lost
  net.clients[client].deaf = true;
  let _ = net.step();
  net.clients[client].deaf = false;
  assert!(!net.resets(client).contains(&(refused.0, 0x10b)));
  shutdown(&mut net);
  for _ in 0..64 {
    net.run();
    if net.server_close(client).is_some() {
      break;
    }
    assert!(net.advance_to_next_event());
  }
  assert_eq!(net.server_close(client), Some((true, 0x100)));
  assert!(net.resets(client).contains(&(refused.0, 0x10b)), "{:?}", net.resets(client));
}

// Task 14 of the in-tree tests: during a graceful close, a stream that must be refused when the
// worker has no slot left and the connection holds as many refused streams as it can (eight) is
// refused once one of them is done, and the close stays graceful (H3_NO_ERROR, not
// H3_INTERNAL_ERROR).
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_without_room_to_refuse_stays_graceful() {
  let (mut net, client) = connected(H3Params::default(), TestHandler::new(OK));
  // No slot left on the worker, and none free
  let live = net.endpoint.stream_slots_in_use();
  net.endpoint.set_stream_slot_cap(live);
  // The first stream is never sent: the next ones open it on the server. They are refused, and
  // their refusals lost: the connection keeps eight records of refused streams
  let implicit = net.client_ctx(client, |cx| cx.open_bidi()).unwrap();
  net.clients[client].deaf = true;
  let refused: Vec<StreamId> =
    (0..8).map(|_| net.send(client, &headers_frame(&GET), true)).collect();
  let _ = net.step();
  net.clients[client].deaf = false;
  assert_eq!(net.app.handler.count, 0);
  shutdown(&mut net);
  for _ in 0..64 {
    net.run();
    if net.server_close(client).is_some() {
      break;
    }
    assert!(net.advance_to_next_event());
  }
  assert_eq!(net.server_close(client), Some((true, 0x100)));
  let resets = net.resets(client);
  for id in refused.iter().chain([&implicit]) {
    assert!(resets.contains(&(id.0, 0x10b)), "{id:?} {resets:?}");
  }
}
