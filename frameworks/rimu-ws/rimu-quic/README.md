# rimu-quic

A sans-I/O QUIC version 1 server transport for Rust, with a multi-worker endpoint and TLS 1.3
through rustls.

Part of the rimu family of performance crates, alongside rimu-ws. Not affiliated with the Rimu
template language (`rimu` on crates.io).

rimu-quic is the QUIC stack of [rimu-ws](https://github.com/vincentmele/rimu-ws) (first on
HttpArena's static-h3 on EC2) as a standalone crate: packets, frames, connections, streams, flow
control, loss recovery, congestion control and the endpoint of a worker, fed datagrams and
drained into a send arena. The core does no I/O itself: any UDP socket drives it, and the `uring`
feature adds a multi-worker server loop on [rimu-uring](../rimu-uring) (io_uring). Its HTTP/3
server layer, rimu-h3, is the other crate of this workspace (`rimu-h3/`), with a ready-to-run
server on that loop.

## What it covers

- **RFC 9000** (transport): long and short headers, every frame type, connection IDs (issued,
  retired, rotated), streams with flow control and stream limits, RESET_STREAM/STOP_SENDING,
  idle timeout, CONNECTION_CLOSE with the closing and draining states, Retry (under load, with
  address-validation tokens), stateless reset, Version Negotiation, NAT rebinding with path
  validation, the anti-amplification limit, PMTU discovery (DPLPMTUD probes).
- **RFC 9001** (TLS): rustls's QUIC API does the handshake (certificates, signatures,
  transcript, ALPN, the `quic_transport_parameters` extension); packet protection with AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305, header protection (AES batched eight at a time with AES-NI),
  key update with the confidentiality and integrity limits.
- **RFC 9002** (recovery): RTT estimation, packet- and time-threshold loss detection, PTO,
  persistent congestion, NewReno with pacing.
- **The endpoint of a worker**: connection IDs that name their worker, a cBPF program for
  `SO_ATTACH_REUSEPORT_CBPF` steering (`steering_cbpf`, Linux), placement of new connections on
  the least-loaded worker (`WorkerLoads`), forwarding of datagrams between workers
  (`RecvOutcome::Forward`), and the abuse limits (handshake floods, frame floods, reset churn,
  reassembly budgets).
- **Zero allocation per packet and per request** after warm-up: pooled connection state,
  in-place packet protection, key schedules expanded once per key and wiped on drop. What rustls
  allocates per handshake is measured and pinned by the tests (78 allocations with ring and an
  ECDSA P-256 certificate, 87 with RSA-2048).

## Not covered (non-goals for 1.0)

A production client (a test client exists behind the `client` feature, for tests and interop),
0-RTT and resumption (refused: the rustls configuration sends no tickets and accepts no early
data), the DATAGRAM extension (RFC 9221), multipath, QUIC v2 (RFC 9369), ECN feedback, congestion
controllers other than NewReno.

## Features

| feature | default | |
|---|---|---|
| `rustls` | yes | TLS through rustls (implies `std`) |
| `ring` | yes | crypto backend of the packet keys and of rustls |
| `aws-lc-rs` | | the other crypto backend |
| `std` | via `rustls` | AES-NI detection for batched header protection, seeding from the OS |
| `diag` | | process-wide counters of the frame-reference pools and sent rings (`diag`) |
| `client` | | the test client's TLS configuration (`rustls::RustlsClientConfig`) |
| `uring` | | the I/O driver on rimu-uring (Linux 6.1 or later): `uring::Server` |

Without `rustls` the core is `no_std` + `alloc`; TLS then comes from any implementation of
`tls::CryptoSession`.

## Driving it with any UDP socket

```rust,ignore
use rimu_quic::{DatagramMeta, Endpoint, EndpointKeys, QuicParams, TxArena, rng::ChaCha20,
  rustls::RustlsConfig};

let tls = RustlsConfig::builder().alpn(&[b"h3"]).cert_chain_pem(&cert).private_key_pem(&key)
  .build()?;
let mut rng = ChaCha20::from_os()?;
let keys = Arc::new(EndpointKeys::new(&mut rng));
// Worker 0 of 1; with several workers, share `keys` and a `WorkerLoads`
let mut endpoint = Endpoint::<MyApp>::new(QuicParams::default(), 0, 1, Arc::new(tls), &mut rng,
  None, keys)?;
let mut tx = TxArena::new(TxArena::DEFAULT_BYTES)?;
loop {
  // 1. Datagrams in (wait at most until `endpoint.next_deadline()`)
  let (len, peer) = socket.recv_from(&mut buf)?;
  let meta = DatagramMeta { peer, local: None, segment_size: None };
  endpoint.recv(now_us(), &mut buf[..len], meta, &mut app);
  // 2. Timers
  endpoint.on_timeout(now_us(), &mut app);
  // 3. Datagrams out: trains of `segment_size`-byte datagrams (one GSO send each, or one by one)
  endpoint.flush(now_us(), &mut tx, &mut app);
  let ids: Vec<_> = tx.pending().map(|train| {
    for datagram in train.bytes.chunks(usize::from(train.segment_size)) {
      socket.send_to(datagram, train.peer)?;
    }
    Ok(train.id)
  }).collect::<io::Result<_>>()?;
  for id in ids { tx.mark_submitted(id); tx.release(id); }
}
```

## The io_uring driver (`uring`)

```rust,ignore
use rimu_quic::uring::{Server, ServerParams, UringApp};

impl UringApp for MyApp { type Counters = (); fn counters(&self) {} }

let mut params = ServerParams::new("[::]:4433".parse()?);
params.handle_signals = true; // SIGINT/SIGTERM drain and stop, SIGUSR1 calls on_stats_signal
let server = Server::<MyApp>::new(params);
let (shutdown, stats) = (server.shutdown_handle(), server.stats());
server.run(Arc::new(tls), |worker| MyApp::new(worker))?;
```

`Server::run` starts one worker per CPU (or `ServerParams::workers`), each an io_uring runtime of
rimu-uring pinned to a core, with its own `SO_REUSEPORT` socket and `Endpoint`. The sockets are
steered by connection ID (`steering_cbpf`, attached by the last worker; without it the kernel's
hash and no balance), new connections go to the least-loaded worker, and datagrams for another
worker are pushed into its inbox (rimu-uring's `UdpInbox`, woken with `IORING_OP_MSG_RING`). A
worker's turn takes every datagram where the kernel put it (GRO datagrams split into their
segments by the endpoint), resumes what the application parked (`UringApp::resume`), runs the
timers, flushes the connections into its `TxArena` and sends each train with one `UDP_SEGMENT`
send; one ring timer waits for the next deadline (pacing included). Nothing in a turn allocates
once warm (`tests/uring_alloc.rs`). The shutdown (`ShutdownHandle::trigger`, or the signals)
drains the connections through the application (`QuicApp::on_shutdown`), then closes and aborts
what is left. Per-worker counters (`uring::Stats`) are updated at each turn. rimu-uring's
`UdpParams` and `Params` (GRO, send slots, zero-copy sends, spinning) are passed through.

The application implements `QuicApp` (stream data, resets, stop-sending, established, closed)
and acts through `ConnCtx` (write, write a shared body by reference with `BodyRef`, reset, stop
sending, open streams, close). A complete echo server: `examples/echo_server.rs`.

## TLS

`tls::CryptoSession` is the whole interface between the transport and TLS. The rustls adapter
(`rustls::RustlsConfig`) gives rustls cipher suites whose QUIC algorithm *captures* the key bytes
rustls derives (`docs/spike-tls.md`); the transport expands them into its own keys, so no packet
goes through rustls and header protection stays batched. A test pins that rustls derives every
key in the calls the capture wraps, for every suite, level and key update.

## Testing

`cargo test` runs the transport's unit tests and model checks (connection and endpoint driven by
generated scripts) with rustls on both sides: 358 tests. `cargo test --features uring,client`
adds the driver's tests over real sockets (one and four workers, steering, placement and
forwarding, shutdown, GRO) and its allocation test (`tests/uring_alloc.rs`), which need a kernel
with io_uring and room in `RLIMIT_MEMLOCK` for a few rings. Fuzz targets for the packet, frame and
transport-parameter decoders, the connection and the endpoint are in `fuzz/` (cargo-fuzz).

## License

Apache-2.0. See `docs/provenance.md` for where the code comes from.
