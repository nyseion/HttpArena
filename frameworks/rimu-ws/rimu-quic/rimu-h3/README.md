# rimu-h3

A sans-I/O HTTP/3 server (RFC 9114) for Rust, on the QUIC transport of
[rimu-quic](../rimu-quic) and the QPACK codec of [rimu-qpack](../../rimu-qpack) (RFC 9204).

Part of the rimu family of performance crates, alongside rimu-ws. Not affiliated with the Rimu
template language (`rimu` on crates.io).

rimu-h3 is the HTTP/3 layer of [rimu-ws](https://github.com/vincentmele/rimu-ws) (first on
HttpArena's static-h3 on EC2) as a standalone crate. `H3Server` is the application of rimu-quic's
connections (`QuicApp`); an `Endpoint<H3Server<_>>` fed datagrams by any UDP loop is a complete
HTTP/3 server. The core does no I/O itself; the `uring` feature runs it on rimu-quic's io_uring
driver as a ready-to-run multi-worker server (`uring::serve`).

## What it covers

- **Connection**: the control stream with SETTINGS (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`,
  `SETTINGS_QPACK_BLOCKED_STREAMS`, `SETTINGS_MAX_FIELD_SECTION_SIZE`), GOAWAY on shutdown with a
  graceful drain (requests under way finish, the streams it never read are refused with
  `H3_REQUEST_REJECTED`, the close waits for every answer to be acknowledged), critical streams,
  unknown frame, setting and stream types ignored, push refused, every connection error of RFC 9114
  with its code.
- **QPACK**: the peer's encoder stream feeds rimu-qpack's `Decoder` (dynamic table, blocked streams
  up to the advertised limit, Section Acknowledgments, Stream Cancellations, Insert Count
  Increments, its bounds against a hostile encoder, and its decode memo, which replays repeated
  request heads without decoding them); responses are encoded with the static table (pre-encoded
  heads, the default) or with rimu-qpack's `Encoder` and a dynamic table (`response_encoder`), fed
  by the peer's decoder stream.
- **Requests**: read frame by frame as they arrive, heads checked as RFC 9114 sections 4.1 to 4.3
  ask (pseudo-header fields, lowercase names, field values, connection-specific fields,
  `content-length`, `host` against `:authority`): a malformed request is a stream error
  `H3_MESSAGE_ERROR`, a head over `SETTINGS_MAX_FIELD_SECTION_SIZE` gets 431, a body over the limit
  413, and the buffers of a connection are held to a budget.
- **Handler**: `Handler::on_request` gets the request head (method, scheme, authority, path, fields
  checked once, read where they were decoded) and the body, buffered (`BodyMode::Buffer`, the
  default) or as it arrives (`BodyMode::Stream`, `Handler::on_body`); it answers at once or parks
  the request and answers later (`H3Server::resume`). `ReqCtx` answers with a pre-encoded head and a
  body copied (`respond`), by reference (`respond_body`, `BodyRef`: no copy), from fields
  (`respond_fields`), with the RFC 9110 rules for HEAD, 1xx, 204 and 304 (`respond_with`), or
  streamed (`send_head`, `send_data`, `send_body`).
- **Lean heads by default**: `:status` and `content-type` (kept encoded per combination of status,
  content type, encoding and `vary`), like the HttpArena HTTP/3 leaders. That is not RFC
  9110-compliant: `H3Params::rfc9110_headers(true)` adds `date` (from `H3Server::set_date`, encoded
  once a second) and `content-length`.
- **Zero allocation per request** after warm-up: pooled connection state (cleared between
  connections), pooled request buffers, the decode memo, response buffers kept small. A response
  written from a callback leaves with the next flush, together with the acknowledgment of the
  request, in one datagram when it fits.

## Example

```rust,ignore
use rimu_h3::{Body, H3Params, H3Server, Handler, ReqCtx, ReqOutcome, Request, ResponseFields};

struct Hello;

impl Handler for Hello {
  fn on_request(&mut self, cx: &mut ReqCtx<'_, '_>, _req: &Request<'_>) -> rimu_h3::Result<ReqOutcome> {
    cx.respond_with(&ResponseFields::with_type(200, b"text/plain"), Body::Bytes(b"hello\n"))?;
    Ok(ReqOutcome::Responded)
  }
}

let mut app = H3Server::new(Hello, H3Params::default());
let mut endpoint = rimu_quic::Endpoint::<H3Server<Hello>>::new(/* QuicParams, worker, TLS (ALPN h3), ... */)?;
// The UDP loop of rimu-quic's README: endpoint.recv(.., &mut app), on_timeout, flush
```

A complete server on a standard UDP socket: `examples/hello_server.rs`
(`cargo run -p rimu-h3 --example hello_server -- 127.0.0.1:4433 cert.pem key.pem`).

## Ready to run on io_uring (`uring`)

```rust,ignore
use rimu_h3::uring::{ServeParams, serve};

let tls = rimu_quic::rustls::RustlsConfig::builder().cert_chain_pem(&cert).private_key_pem(&key).build()?;
// One worker per CPU, each pinned with its own SO_REUSEPORT socket; SIGINT/SIGTERM drain
// (GOAWAY, requests under way finish) and return; SIGUSR1 prints `h3-stats name=value ...`
serve(ServeParams::new("[::]:443".parse()?), rimu_quic::QuicParams::default(), tls, |_worker| Hello)?;
```

`serve` runs an `H3Server` per worker of rimu-quic's `uring::Server` (Linux 6.1 or later):
each turn refreshes the `date` of responses (with `H3Params::date`), resumes the parked requests
that the handler reports ready (`Handler::poll_ready`), and stores the counters (`H3Counters`:
requests, QPACK sections and memo hits). `uring::server` and `uring::run` split it for a caller
that wants the shutdown handle or the counters.

`examples/uring_server.rs` serves `/hello`, `/baseline2?a=..&b=..` (the sum, as HttpArena's
baseline-h3), `/static/*` from a directory loaded at start (one copy per worker, sent by
reference; the `.br`/`.gz` twin chosen by `accept-encoding`, as static-h3) and `POST /echo`:

```sh
cargo build --release -p rimu-h3 --features uring --example uring_server
CERT_DIR=certs STATIC_DIR=static target/release/examples/uring_server '[::]:8443'
```

io_uring rings lock memory: a server of many workers needs more `RLIMIT_MEMLOCK` than a desktop
user's default (`ulimit -l`), and Docker's default seccomp profile blocks io_uring
(`--security-opt seccomp=unconfined`; see `../scripts/server.sh`).

## Features

| feature | default | |
|---|---|---|
| `std` | yes | `H3Server::refresh_date` from the system clock |
| `rustls`, `ring`, `aws-lc-rs` | `rustls`, `ring` | forwarded to rimu-quic |
| `uring` | | `uring::serve` on rimu-quic's io_uring driver (Linux 6.1 or later) |

Without `std` (and `rustls`) the crate is `no_std` + `alloc`.

## Testing

`cargo test -p rimu-h3`: the in-tree HTTP/3 tests of rimu-ws ported onto an in-process harness
(rimu-quic's test client against an `Endpoint<H3Server>`), RFC 9114 connection and stream errors,
QPACK blocked streams end to end, allocation tests, and a connection checker driven by generated
scripts (`check`), also the fuzz targets `h3_conn` and `h3_streams` in `fuzz/`. Benchmarks of the
request decode and response encode: `cargo run --release -p rimu-quic-bench --bin rimu-h3-bench`.

On the `uring` server (`examples/uring_server.rs` in Docker; scripts in `../scripts/`, raw
output in `../bench/results/2026-11-14-*`):

- **h3spec** v0.1.15 (`scripts/h3spec.sh`, 4 workers): 86 examples, 0 failures, 1 pending, the
  0-RTT case (`MUST send PROTOCOL_VIOLATION if CRYPTO in 0-RTT is received`), pending in h3spec
  itself as 0-RTT is refused.
- **Interop** (`scripts/h3-interop.sh`, 4 workers): curl 8.23 (ngtcp2), ngtcp2's client and
  quic-go 0.65, each direct, with 1 % loss, with 5 % loss/reorder/duplication and through a
  rebinding NAT, on IPv4 and IPv6: 24 of 24 cells pass (GET, every static file in br/gzip/identity,
  POST of 1 MiB echoed, 1,000 sequential requests, 64 parallel connections), no STREAM frame of
  acknowledged bytes ever sent again.
- **rimu-soak `h3`** (4 workers and a one-worker instance, steady client 64 × 64 beside the
  abusers): every scenario passes but `qpack_backlog`, whose unterminated encoder-stream integer
  rimu-qpack refuses at once with `QPACK_ENCODER_STREAM_ERROR` (0x0201) where the scenario expects
  the backlog cap's `H3_EXCESSIVE_LOAD` (rimu-ws buffered it to the cap); and `never_read` failed
  once in two full runs (the server closed with `H3_CLOSED_CRITICAL_STREAM`, 0x0104) and passed
  in both full and four lone reruns.

## Benchmarks

**Against rimu-ws's in-tree HTTP/3** (`scripts/h3-ab.sh`; Ryzen 9 5900X, 14 Nov 2026; both
servers in Docker on CPUs 0-5, HttpArena's h2load-h3 on CPUs 6-11 with HttpArena's arguments,
`-t 6`; best of three 5 s runs per server start, six starts per server and profile in two
batches, alternating). The machine was shared and loaded (load average 19-31 in the first batch,
19-276 in the second), so throughput moved by up to 70 % between batches for both servers alike:

| | rimu-ws in-tree | rimu-h3 on `uring` |
|---|---:|---:|
| baseline-h3, best per start (req/s) | 1.64 M, 1.13 M, 1.10 M / 1.19 M, 1.79 M, 1.78 M | 1.74 M, 1.14 M, 1.14 M / 1.86 M, 1.80 M, 1.79 M |
| baseline-h3, server CPU per request, median (µs) | 2.33 / 1.37 | 1.76 / 1.09 |
| static-h3, best per start (req/s) | 165 k, 159 k, 163 k / 284 k, 285 k, 285 k | 164 k, 161 k, 157 k / 284 k, 288 k, 237 k |
| static-h3, server CPU per request, median (µs) | 28.3 / 17.7 | 28.4 / 17.5 |

Throughput is the same within the spread on both profiles (on baseline-h3 the generator is the
limit at about 1.8 M req/s). On baseline-h3 rimu-h3 used about 20-25 % less server CPU per
request in both batches; part of that may be rimu-ws's image, which also runs its HTTP/1.1, h2
and WebSocket runtimes (idle here) in the same container. static-h3 costs the same.

The HTTP/3 work of a request without the transport (`rimu-h3-bench`, 15 interleaved rounds of
200,000, median / min ns; Ryzen 9 5900X, shared machine at load 12–16, `taskset -c 14`, 14 Nov
2026): the decode of the request head (QPACK, the RFC 9114 checks, the head buffer) and the encode
of the response head with its HEADERS and DATA frames.

| | ns |
|---|---:|
| decode, h2load `GET` (40-byte section), no memo / memo | 151 / 92 |
| decode, browser `GET` (285-byte section; the memo keeps sections up to 128 bytes) | 376 |
| encode, lean head (`:status`, `content-type`) | 36 |
| encode, with `date` and `content-length` | 65 |
| encode, dynamic table (rimu-qpack encoder, acknowledged) | 141 |
| request, h2load `GET`, lean head, memo | 128 |

## License

Apache-2.0. See `../docs/provenance.md` for where the code comes from.
