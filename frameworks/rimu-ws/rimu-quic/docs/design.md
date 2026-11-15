# rimu-quic and rimu-h3 — design, 14 Nov 2026

rimu-ws carries its own QUIC v1 transport (`wtx/src/quic/`, ~30,000 lines with tests) and HTTP/3 layer
(`wtx/src/http3/`, ~6,000 lines without QPACK). They came first on HttpArena's static-h3 on EC2
(+24 % over the next entry) and topped the local HTTP/3 composite. This design turns them into two
standalone Apache-2.0 crates, `rimu-quic` and `rimu-h3`, usable outside rimu-ws, and makes rimu-ws
depend on them afterwards.

## 1. Provenance

Every file under `wtx/src/quic/`, `wtx/src/http3/`, `wtx/src/crypto/aead_key*`,
`wtx/src/crypto/hp_key*` and `wtx/src/misc/shared_bytes.rs` was written in the fork by Vincent Mele;
none existed at upstream `d22e17e0`. They can be relicensed.

What they use from wtx (MPL, not copyable) and its replacement:

| wtx item | used for | replacement |
|---|---|---|
| `tls::{TlsAcceptor, key_schedule, negotiate_client_hello, write_server_flight, …}` through `tls/quic_tls.rs` | the TLS 1.3 handshake | rustls's QUIC API (§4) |
| `tls::{CipherSuite, SkCtx, TlsCtxSk, AlertDescription}` | suite and key context types | the crate's own small types |
| `rng::ChaCha` | connection IDs, tokens, stateless-reset secrets | `rand_chacha` (or `rand_core` + `getrandom`) |
| `collections::{Vector, VectorUsize, ArrayVectorU*}`, `misc::from_utf8_basic` | buffers | `Vec`, arrays, `core::str::from_utf8` |
| `executor::uring_executor/udp.rs` (rimu-ws's I/O) | UDP send/receive | `rimu-uring`'s UDP (GRO, GSO trains, cBPF steering) as an optional driver |

`tls/quic_tls.rs` itself is the user's, but it is a thin adapter over wtx's handshake; it is
rewritten against rustls, not ported. The check used for every copied block is the one in
`~/src/rimu-uring/docs/provenance.md` (exact and near-match search of upstream `d22e17e0`).

## 2. Goals and non-goals

**Goals**
- A sans-I/O QUIC v1 server transport (RFC 9000, 9001, 9002) with everything rimu-ws has today: Retry
  under load, stateless reset, NAT rebinding with path validation, PMTU discovery, key update,
  NewReno with pacing, abuse limits (handshake floods, frame floods, reset churn, reassembly), and
  zero allocation per packet after warm-up.
- The multi-worker endpoint as a first-class feature: connection IDs that name their worker, cBPF
  reuseport steering, first-packet placement on the least-loaded worker, cross-worker forwarding.
- A sans-I/O HTTP/3 server layer (RFC 9114) on rimu-quic and rimu-qpack (RFC 9204).
- An I/O driver on rimu-uring, so `rimu-quic` + `rimu-h3` + `rimu-uring` make a complete
  high-performance HTTP/3 server; the core stays usable with any UDP I/O.
- Performance at least equal to rimu-ws's in-tree stack on its own benchmarks.

**Non-goals for 1.0** (the in-tree stack does not have them either)
- A production client (the in-tree client exists for tests; it stays test-only, behind a feature).
- 0-RTT (refused today), the DATAGRAM extension (RFC 9221), multipath, QUIC v2 (RFC 9369), ECN
  feedback, congestion controllers other than NewReno (the `cc` module keeps a trait so Cubic or BBR
  can be added).

## 3. Crates

```
rimu-quic          sans-I/O transport: packets, frames, connection, streams, recovery, endpoint
  features: rustls (default) — the TLS adapter of §4
            uring             — the rimu-uring driver of §6
            client            — the test client (tests and interop only)
rimu-h3            sans-I/O HTTP/3 server: control/request streams, SETTINGS, GOAWAY, rimu-qpack
  features: uring             — a ready-to-run server loop on rimu-quic's driver
```

Both `#![forbid(unsafe_code)]` except the modules that need it (crypto backends, the uring driver),
each `unsafe` with a `// SAFETY:` comment, as rimu-ws. `no_std` + `alloc` for the cores (the
in-tree code already is), `std` for the driver.

## 4. TLS: rustls's QUIC API, keys built by rimu-quic

The connection core talks to TLS through one trait, so the core never depends on rustls:

```rust
pub trait CryptoSession {
  /// CRYPTO frame data received at `level`, in order.
  fn read_handshake(&mut self, level: Level, data: &[u8]) -> Result<(), TlsAlert>;
  /// Handshake bytes to send; returns a key change when the next level's keys are ready.
  fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<KeyChange>;
  fn peer_transport_params(&self) -> Option<&[u8]>;
  fn alpn(&self) -> Option<&[u8]>;
  fn is_handshaking(&self) -> bool;
  /// The 1-RTT keys of the next key phase (RFC 9001 §6).
  fn next_one_rtt_keys(&mut self) -> KeyPair;
}
```

`KeyChange` and `KeyPair` carry **rimu-quic's own key types** (`AeadKey`, `HpKey` from
`crypto/aead_key` and `crypto/hp_key`), so the hot path keeps what rimu-ws has: AEAD key schedules
expanded once per key, no dynamic dispatch per packet, and header-protection masks computed eight
at a time with AES-NI.

The rustls adapter gets those keys through rustls's own extension point. A rustls `CryptoProvider`
whose TLS 1.3 suites carry a rimu-quic `quic::Algorithm`; rustls hands that algorithm the derived
packet key, IV and header-protection key (`AeadKey`/`Iv` expose their bytes), from which the adapter
builds the native keys. rustls's `KeyChange` returns them as `Box<dyn PacketKey>`, so the adapter
needs the native keys alongside. Two ways, decided by a spike (§8, step 1):

1. **Capture**: the algorithm records each key's bytes in a slot owned by the session (set around
   the `write_hs`/`next_packet_keys` call that derives it), and the adapter builds native keys from
   them and drops rustls's boxes. No per-packet cost; relies on rustls deriving keys inside those
   calls (it does today; a test pins it).
2. **Wrap**: native keys behind rustls's traits, called through `dyn` per packet, header protection
   one sample at a time (rustls's trait has no batch call). Simpler, slower: the spike measures by
   how much on the netbsd/static-h3 benchmarks.

Capture is the target; Wrap is the fallback if rustls changes. Either way rustls does the whole
handshake: certificates, signatures, transcript, resumption policy, ALPN, and the
`quic_transport_parameters` extension. rimu-ws's pooled handshake state (2 pointers inline per
connection, buffers from a per-thread pool) becomes a pooled `rustls::quic::ServerConnection`:
the zero-allocation tests are re-baselined around what rustls allocates per handshake, as they
already allow for ring's RSA signature (the "crypto budget").

Crypto backends of the native keys: those rimu-ws has (`ring`, `aws-lc-rs`, `graviola`, and the
AES-NI header-protection batch), behind features, matching the provider rustls is built with.

## 5. API shape

Unchanged in substance from the in-tree code, which is already sans-I/O:

- `Endpoint` (one per worker): `recv(datagram, from, to, now) -> RecvOutcome` (deliver, forward to
  another worker, or answer statelessly), `handle_timeouts(now)`, `poll_transmit(&mut TxArena)`,
  `next_timeout()`, `WorkerLoads` for placement, `steering_cbpf()` for the reuseport program.
- `Connection` behind the endpoint, reached through the application interface: rimu-ws's
  `QuicApp` callbacks (stream opened, readable, writable, closed) and `ConnCtx` (send on a stream,
  send a body by reference with `BodyRef`, reset, stop sending, close). `QuicApp` becomes a public
  trait; rimu-h3 implements it.
- `QuicParams` / `QuicLimits` for configuration, `TransportParams`, `QuicError` and
  `TransportErrorCode`, `TxArena` (GSO trains), `diag` counters.

rimu-h3: `H3Server` implements `QuicApp`; requests come to a user `Handler` as a head (method,
path, authority, fields as rimu-qpack views) and a body stream; responses go back as a head
(pre-encoded static heads as today, or rimu-qpack's encoder) and a body (owned, borrowed with
`BodyRef`, or streamed). rimu-ws's router and static-file handler stay in rimu-ws and sit on this.

## 6. I/O driver (`uring` feature)

rimu-ws's `executor/uring_executor/udp.rs` path moves onto `rimu-uring`'s `UdpSocket`: multishot
receive with GRO, GSO send trains from `TxArena`, timers from rimu-uring's timer, cBPF steering
(already in rimu-uring), and the cross-worker forwarding. Two items rimu-uring left out need adding
there first (Apache-2.0, written fresh): datagram forwarding between runtimes (`IORING_OP_MSG_RING`)
and zero-copy sends (`SENDMSG_ZC`). A portable tokio driver is a later option, not 1.0.

## 7. Verification

Everything rimu-ws verifies today, ported:
- The in-tree unit and model tests (`conn/check.rs`, `endpoint/check.rs`, `frame_check`,
  `packet_check`, `h3_check`, the endpoint and connection test suites) — adapted, not weakened.
- h3spec (86 passing today; the one pending case stays documented).
- Interop under loss with curl, quic-go and ngtcp2 (`.scripts/h3-interop.sh`), using `udp-impair`
  from rimu-soak for the loss/reorder/rebind profiles.
- rimu-soak's QUIC abuse scenarios (handshake floods, frame floods, reset churn, reassembly).
- Fuzzing: the packet/frame decoders and the connection with arbitrary datagrams
  (`.scripts/fuzz-h3.sh` targets).
- Allocation tests: zero per packet and per request after warm-up; per-handshake allocations
  bounded and documented (rustls's share named).
- Performance gates, on a quiet machine or EC2: baseline-h3 and static-h3 with the HttpArena method,
  rimu-ws on the crates vs rimu-ws in-tree (must be within the in-tree run's spread), and the crates
  vs quinn on the same driver hardware for the README.

## 8. Plan of work (each step its own plan)

1. **Spike (1–2 days):** rustls `CryptoSession` adapter with Capture and Wrap; handshake against
   the in-tree connection core; measure both on the in-tree h3 benchmarks. Decide §4.
2. **rimu-quic core:** move `quic/`, the key modules and `shared_bytes`; replace the wtx types of §1;
   `CryptoSession` + rustls adapter; port the tests. No I/O.
3. **rimu-uring additions:** MSG_RING forwarding and SENDMSG_ZC (in rimu-uring).
4. **rimu-quic `uring` driver**, then **rimu-h3** on rimu-qpack (which replaces `http3/qpack*`).
5. **Verification** of §7 on the crates alone.
6. **rimu-ws on the crates:** h3 server framework and router onto rimu-h3; delete the in-tree
   stack; HttpArena validator, h3spec, interop, A/B (needs Docker or a larger memlock limit — see
   the phase 1 notes).

## 9. Risks

- **rustls key timing** (Capture relies on keys being derived inside specific calls): pinned by a
  test, with Wrap as the fallback.
- **Handshake allocations**: rustls allocates more per handshake than the pooled in-tree handshake;
  connection-churn throughput (handshake floods) may drop. Measured in step 1; mitigations are
  session pooling and keeping Retry under load.
- **Certificate and signature cost** moves from wtx's crypto to rustls's provider: equal when both
  use ring or aws-lc-rs.
- **Size**: ~36,000 lines to move with their tests; steps 2 and 4 are the bulk.

## 10. Decisions

Taken 14 Nov 2026: rustls for TLS, the client test-only for 1.0, rimu-uring as the only driver for
1.0. The spike (`docs/spike-tls.md`) chose **Capture** for §4: captured keys match rustls's own and
RFC 9001 Appendix A in every suite and key generation, and keep the in-tree per-packet path; Wrap
would add 4–5 ns per packet (~1–1.5 % of a 1,200-byte seal). rustls costs +6–8 % per ECDSA
handshake and ~81 allocations each; its ticket, session-cache and early-data defaults must be
turned off to keep resumption and 0-RTT out.

QPACK encoder-stream backlog (14 Nov): rimu-h3 keeps rimu-qpack's answer to an instruction whose
integer never ends, QPACK_ENCODER_STREAM_ERROR (0x0201), rather than rimu-ws's H3_EXCESSIVE_LOAD
after a buffered cap; rimu-soak's `qpack_backlog` accepts either (`--qpack-backlog-codes`).

The options as they were put:

1. **TLS**: rustls (recommended: audited, standard in the ecosystem, and its QUIC API is what quinn
   uses) or a TLS 1.3 handshake written fresh for rimu-quic (no dependency, but a large, security-
   critical new component).
2. **Client**: keep the client test-only for 1.0 (recommended), or make it a supported feature
   (adds 0-RTT/resumption work on the client side and its tests).
3. **Driver**: rimu-uring only for 1.0 (recommended), or also a tokio driver for portability.
