# Provenance

rimu-quic is Apache-2.0. Its transport comes from the author's own QUIC stack in the rimu-ws
fork of wtx; nothing comes from upstream wtx (MPL-2.0).

## What was reused, from where

Source: `~/src/rimu-ws` `main` (`2081c741`), and the rustls spike (`spike/rustls-quic`,
`d2755029`) for its new files. Every source file below has only Vincent Mele in its history
(`git -C ~/src/rimu-ws log --format='%an' -- <path>`) and none exists at upstream `d22e17e0`
(`git -C ~/src/rimu-ws ls-tree d22e17e0 <path>` is empty), checked per path on 14 Nov 2026.

| rimu-quic | rimu-ws source | How |
|---|---|---|
| `src/{app,cc,cid,cid_table,conn,conn/path,conn/check,diag,endpoint,endpoint/check,endpoint/tests,flow,frame,frame_check,key_phase,limits,packet,packet_check,pmtud,pools,quic_error,recovery,recv_tracker,sent,steer,stream,stream/*,testing,timer_wheel,token,transport_params,tx_arena,varint,writer}.rs` | `wtx/src/quic/<same>` | moved; paths `crate::quic::` → `crate::`; generics `RNG`/`TCX` removed; the TLS session is a `Box<ConnTls>` (below); `Vector` → `Vec`; the key update source in `key_phase.rs` is new (`KeyUpdate`); test harnesses on rustls; the four allocation tests re-baselined |
| `src/lib.rs` | `wtx/src/quic.rs` | rewritten (module list, public API) |
| `src/protection.rs` | `wtx/src/quic/crypto.rs` | moved and renamed; `DirectionalKeys` keeps no secret (keys from `KeyMaterial`, `from_parts` from the spike's `crypto.rs` diff); `next_secret`/`material_from_secret` new; tests adapted |
| `src/crypto/aead_key{,/global,/ring,/alr}.rs`, `src/crypto/hp_key{,/global,/ring,/alr,/x86_aesni}.rs` | `wtx/src/crypto/aead_key*`, `wtx/src/crypto/hp_key*` | moved; Graviola and RustCrypto backends left out; features renamed (`ring`, `aws-lc-rs`) |
| `src/crypto/quic_aead.rs` | `wtx/src/tls/traffic_aead.rs` (only Vincent Mele, not upstream) | moved, renamed `QuicAead` |
| `src/crypto.rs`: `drop_and_zero`, the macros `common_aead_key_functions`, `common_hp_key_functions`, `_create_key_wrappers` and their ring/aws-lc-rs instantiations | `wtx/src/crypto.rs` lines 129–137, 234–242, 297–321 and `wtx/src/crypto/macros.rs` lines 42–115, 205–244 | reused: `git blame` attributes exactly these blocks to Vincent Mele in files otherwise upstream's; nothing else of those two files was taken |
| `src/shared_bytes.rs` | `wtx/src/misc/shared_bytes.rs` | moved |
| `src/conn_tls.rs` | the spike's `quic/conn_tls.rs` and `RustlsSession` of `quic/rustls_session.rs` | rewritten on the `CryptoSession` trait: level checks, output per level, 1-RTT hold |
| `src/rustls/{capture,mod,client}.rs` | the spike's `quic/rustls_session.rs` | adapted: capture slot and `CaptureAlg` reused; records become `KeyMaterial`; Wrap left out; the config builder and the session/updater types are new |
| `src/rustls/tests.rs` | the spike's `quic/rustls_spike.rs` | the three correctness tests adapted (Capture pinned, RFC 9001 A.1, sessions with key updates); the resumption/0-RTT, ALPN, builder and allocation tests are new; the measurements left out (see `bench/`) |
| `fuzz/lib/cap_alloc.rs`, `fuzz/fuzz_targets/*.rs` | `wtx-fuzz/lib/cap_alloc.rs` (only Vincent Mele, not upstream), `wtx-fuzz/quic_*.rs` | reused; crate name changed |

## What was not reused, and what replaced it

| wtx item (MPL) | replacement (written for rimu-quic) |
|---|---|
| `tls::{QuicTls, TlsConfig, TlsCtxSk, SkCtx, UnverifiedCtx, key_schedule, next_rng, AlertDescription}` | `tls.rs` (`CryptoSession`, `KeyChange`, `KeyMaterial`, `KeyUpdater`, `SecretKeyUpdater`, `ServerSessionFactory`, `TlsAlert`), the rustls adapter, `conn/path.rs`'s own challenge generator |
| `tls::CipherSuite` | `suite.rs` |
| `tls::key_schedule::hkdf_expand_label`, `crypto::{Hkdf, Hmac}*` | `crypto/hkdf.rs` on ring / aws-lc-rs |
| the rest of `crypto.rs` (`CryptoError`, `dummy_crypto_call`, the constants), `misc::zero_volatile` | `crypto.rs` (new `CryptoError` with the variant names the moved code uses; `zero_volatile` rewritten) |
| `rng::{ChaCha20, CryptoRng, CryptoSeedableRng, Rng, Xorshift64}`, `misc::random_state` | `rng.rs` on `rand_chacha`/`rand_core`/`getrandom` (the method names the moved code calls, bodies new) |
| `collections::{Vector, ArrayVectorCopy}` | `Vec`, `bytes.rs` (`ArrayBytes`) |
| `crate::Error`, `crate::Result` | `error.rs` |
| `hexd!`, `codec::hex_decode` | `hex.rs` |
| `tests::{_count_allocations_in, _PUBLIC_KEY, _SECRET_KEY}` | `testing::alloc_count` (counting allocator), fresh test certificates in `tests/certs/` |
| `sync::{Arc, AtomicU*}` | `sync.rs` (re-exports of `alloc`/`core`) |
| `must_use_itself_doc!` | a literal `#[must_use = "..."]` |

`wtx/src/tls/quic_tls.rs` (the user's) was not ported: rustls replaces the handshake it adapted.

## Checks run

1. Exact-line scan of every `.rs` file of `rimu-quic/`, `fuzz/` and `bench/` (lines of 30+
   characters, trimmed) against every `.rs` file of upstream wtx at `d22e17e0` (extracted copy at
   `/mnt/nvme1tb/claude-tmp/prov/wtx`, 721 files). The common lines are generic: derive lists,
   `fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {`, `pub(crate) const fn
   new() -> Self {`, `return Err(crate::Error::ProgrammingError);`, `use core::sync::atomic::
   Ordering;`, `use alloc::{boxed::Box, vec::Vec};`, `self.len = self.len.wrapping_add(1);`,
   `fn next(&mut self) -> Option<Self::Item> {`, `pub type Result<T> = core::result::Result<T,
   Error>;`, `impl core::error::Error for Error {}`, the AEAD signatures `) -> crate::Result<&'data
   mut [u8]> {` / `) -> crate::Result<[u8; AEAD_TAG_LEN]> {` and a ring/aws-lc-rs import list
   (`AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce,
   UnboundKey,`). Interface-level matches, kept because the moved code uses those names: the three
   constants `AEAD_NONCE_LEN = 12`, `AEAD_TAG_LEN = 16`, `MAX_HASH_LEN = 48`; the `Rng` method
   signatures `fn u8_4/u8_8/u8_16/u8_32(&mut self) -> [u8; N] {`; the variant names
   `CryptoError::InvalidChacha20Poly1305Data` (and siblings) and the cipher suite list
   `[Self::Aes128GcmSha256, Self::Aes256GcmSha384, Self::Chacha20Poly1305Sha256]`. One comment
   line matched — the doc comment `/// A structure that delegates execution to the selected crypto
   backend.` of the user's `aead_key/global.rs` and `hp_key/global.rs`, which repeats upstream's
   `crypto/aead/global.rs`; it was rewritten. No other comment line matches.
2. Near-match scan: every window of three consecutive non-trivial lines (12+ characters),
   whitespace removed and `crate::Result<` normalized on both sides, compared with the same
   windows of upstream: no match.

Script: `/mnt/nvme1tb/claude-tmp/rimu-quic/scripts/prov.py <upstream> <dirs...>` (not committed).

# rimu-h3

rimu-h3 is Apache-2.0. Its HTTP/3 layer comes from the author's own HTTP/3 stack in the rimu-ws
fork of wtx; nothing comes from upstream wtx (MPL-2.0), and QPACK is rimu-qpack's (`e5bbbad`),
which replaces the in-tree `http3/qpack*`.

## What was reused, from where

Source: `~/src/rimu-ws` `main` (`2081c741`). Every source file below has only Vincent Mele in its
history (`git -C ~/src/rimu-ws log --format='%an' -- <path>`) and none exists at upstream
`d22e17e0` (`git -C ~/src/rimu-ws ls-tree d22e17e0 <path>` is empty), checked per path on 14 Nov
2026: `wtx/src/http3.rs`, `wtx/src/http3/{frame,h3_app,h3_check,h3_conn_state,http3_error,
loopback_client,request,settings,testing}.rs`, `wtx/src/http3/h3_app/`,
`wtx/src/http/http3_server_framework.rs` and `wtx/src/http/http3_server_framework/`.

| rimu-h3 | rimu-ws source | How |
|---|---|---|
| `src/frame.rs` | `http3/frame.rs` | moved; varints from rimu-quic's now public `varint` |
| `src/settings.rs` | `http3/settings.rs` | moved; public; `Default` added |
| `src/error.rs` | `http3/http3_error.rs` | `Http3Error` and `H3ErrorCode` moved, the reasons of the in-tree QPACK codec left out (rimu-qpack's `ErrorKind` has them); `NoHead`, `OutOfMemory` and the encoder-stream backlog new; the crate `Error` (Http3, Http3Close, Qpack, Quic), `close_code` and `H3ErrorCode::from_qpack` new |
| `src/request.rs` | `http3/request.rs` | moved; `Vec` for `VectorUsize`, rimu-qpack's `StaticRef`/`STATIC_TABLE`; `Request` and `Fields` public, `Fields::{get,len,is_empty}` new; the `from_utf8_unchecked` of `ascii_fields` replaced by a checked conversion (no `unsafe`) |
| `src/conn_state.rs` | `http3/h3_conn_state.rs` | adapted: the decoder and its memo are rimu-qpack's `Decoder`, which keeps cut encoder instructions and blocked streams itself (`encoder_rx`, `blocked`, `scratch` gone); a rimu-qpack `Encoder` per connection (new); the flags of a request for streamed bodies and responses new; the 4 KiB size check of the transport's connection left to rimu-quic |
| `src/server.rs` | `http3/h3_app.rs` | adapted: `H3App`→`H3Server`, `H3Handler`→`Handler` (public; `body_mode` and `on_body` new), `H3ReqCtx`→`ReqCtx` (`respond_with` from the framework's `RouterHandler::answer`; `send_head*`, `send_data`, `send_body` new); request bodies taken as they arrive new; the peer's decoder stream fed to the encoder; the dynamic table of responses new; the error mapping to rimu-quic's `QuicApp` results new |
| `src/response.rs` | `http/http3_server_framework/router_handler.rs` | `ResponseHead` (`ResponseHeads`), `Block`, `key_matches`, `write_block`, `decimal` moved off wtx's `Headers`/`StatusCode` (fields given as `ResponseFields`); `known` rewritten without wtx's `KnownHeaderName`; `DateLine` adapted; `imf_fixdate` new (wtx's `format_imf_fixdate` not used) |
| `src/testing.rs` | `http3/testing.rs`, rimu-quic's `testing.rs` (`Net`, `TestApp`, the counting allocator) | the helpers, `TestHandler` and `Response` moved; the network rewritten for one endpoint over rimu-quic's `client::TestClient` |
| `src/check.rs` | `http3/h3_check.rs`, `Input` of rimu-quic's `conn/check.rs` | adapted to the harness above (the packet actions of `Duo` replaced by lost datagrams); `run_raw` new |
| `src/server/tests.rs` | `http3/h3_app/tests.rs`, `http/http3_server_framework/tests.rs` | the 38 `h3_app` tests ported (the three that cap the stream slots once rimu-quic's `Endpoint::set_stream_slot_cap` was public), 10 of the framework's (those about HTTP/3, not its router, static files or threads), rewritten for the harness; new tests listed in the README |
| `examples/hello_server.rs` | rimu-quic's `examples/echo_server.rs` | its UDP loop, with an `H3Server` |
| `src/bench_support.rs`, `bench/src/h3.rs` | — (`interleave`/`stats` from `bench/src/main.rs`) | new |
| `fuzz/fuzz_targets/h3_{conn,streams}.rs` | the shape of `fuzz_targets/quic_conn.rs` | new |

`http3/loopback_client.rs` (a client over a real socket for wtx's binaries) was not ported: the
in-process tests use rimu-quic's `TestClient`, and its response parsing is `testing::response_of`.
Of the server framework, only the HTTP/3 parts named above were taken: not its router, routes,
middlewares, `StaticFiles`, HTTP types, worker threads, stats cells or `endpoint_task.rs` (the
io_uring loop, which rimu-quic's `uring` driver replaces: see its section below).

## Checks run

The two scans of the rimu-quic section, over `rimu-h3/`, `bench/src/h3.rs` and
`fuzz/fuzz_targets/` against upstream wtx at `d22e17e0`: the exact lines in common are generic
(`#[derive(...)]` lists, `use alloc::{boxed::Box, vec::Vec};`, `Err(err) => return Err(err.into()),`,
`pub type Result<T> = core::result::Result<T, Error>;`, `impl core::error::Error for Error {}`,
`fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {`, `pub(crate) const fn new() -> Self {`,
`pub(crate) fn clear(&mut self) {`, `let mut rng = ChaCha20::from_key([7; 32]);`); no comment line,
and no window of three non-trivial lines, matches.

# The `uring` driver and rimu-h3's server on it

rimu-quic's `uring` feature (`src/uring.rs`, `src/uring/`) and rimu-h3's (`src/uring.rs`,
`examples/uring_server.rs`) replace rimu-ws's in-tree HTTP/3 server loop. Its logic was read and
adapted; none of its wtx interfaces (`Executor`, `UringUdpSocket`, `HttpRouter`, `TlsCtxSk`, the
`RNG` generics, wtx's `Error`) were carried over: the driver is written against rimu-uring's API
(at `e5254a3`) and rimu-quic's.

Source: `~/src/rimu-ws` (read-only). Every source file below has only Vincent Mele in its history
(`git -C ~/src/rimu-ws log --format='%an' -- <path>`) and none exists at upstream `d22e17e0`
(`git -C ~/src/rimu-ws ls-tree d22e17e0 <path>` is empty), checked per path on 14 Nov 2026:
`wtx/src/http/http3_server_framework.rs`, `wtx/src/http/http3_server_framework/endpoint_task.rs`,
`wtx/src/http/http3_server_framework/router_handler.rs`, `wtx/src/http/static_files.rs`,
`.scripts/h3spec.sh`, `.scripts/h3-interop.sh`, `.scripts/h3-bench.sh`.

| here | rimu-ws source | How |
|---|---|---|
| `rimu-quic/src/uring.rs`: `Startup`, `bind_in_order`, `forward` | `endpoint_task.rs`: `Startup`, `bind_in_order`, `forward` | adapted: rimu-uring's `UdpSocket` and `UdpInbox` (`push` with `RecvMeta` and a tag, its `Result`), `io::Error`; the steering decision passed in as before; the inboxes returned with the socket |
| `rimu-quic/src/uring/worker.rs`: `Task::{turn, arm, idle, receive, store_stats}`, the shutdown linger | `endpoint_task.rs`: `Task::{turn, arm, idle, receive, store_stats}`, `SHUTDOWN_LINGER` | adapted: the turn's order kept (clock once, receive, inbox, resume, timers, shutdown, flush, idle, counters, one ring timer); resuming parked work is the application's (`UringApp::resume`, in-tree `RouterHandler::take_woken`/`prepare_resume`); the shutdown comes from a `ShutdownHandle` instead of wtx's `ShutdownSignal`; the send of the arena's trains (`send_train_with`, release, `writable` when the send slots are busy) is new, as rimu-uring's sockets copy into send slots where rimu-ws's sent from the arena |
| `rimu-quic/src/uring/affinity.rs` | `endpoint_task.rs`: `affinity::allowed`, `cpu_order` | rewritten without `unsafe`: the CPUs from `/proc/self/status` instead of `sched_getaffinity`, pinning by rimu-uring's `Builder::pin_to`; the order (first thread of each physical core, then the others) kept |
| `rimu-quic/src/uring/stats.rs` | `http3_server_framework.rs`: `Http3WorkerStats` | the names of the counters kept (the scripts read them); the structure (a cell per worker behind a `Mutex`, `try_lock` at each turn, `AppCounters`) is new |
| `rimu-quic/src/uring/signals.rs`, `rimu-quic/tests/{uring,uring_alloc}.rs`, `rimu-quic/tests/common/` | — | new |
| `rimu-h3/src/uring.rs` | — (the in-tree loop built an `H3App` with a router handler) | new |
| `rimu-h3/examples/uring_server.rs` | `static_files.rs`: `Accepted::{parse, order}`, `parse_q`; the routes of HttpArena's `rimu-ws` entry (`frameworks/rimu-ws/src/main.rs`, the user's) | the accept-encoding choice adapted (q-values in thousandths, `br` on a tie, `*` for both, q=0 refuses), on bytes; the file map loaded once at start (in-tree: a per-thread cache read lazily and revalidated) and the routes written fresh |
| `scripts/h3spec.sh`, `scripts/h3-interop.sh` | `.scripts/h3spec.sh`, `.scripts/h3-interop.sh` | adapted: the server in Docker (`scripts/server.sh`, new), its counters through `docker kill -s USR1`; the pins, clients, paths, scenarios and checks kept; the client drivers are mounted from rimu-ws unchanged |
| `scripts/h3-ab.sh` | `.scripts/h3-bench.sh` | the h2load invocation, the readiness probe and the rps definition reused; both servers in Docker on the same CPUs, the A/B alternation new |
| `rimu-quic/src/rustls/hello.rs` | — | new (rustls takes the draft transport-parameters extension; the in-tree TLS refused it) |

## Checks run

The two scans of the rimu-quic section over the files above (`.rs` only) against upstream wtx at
`d22e17e0`: the exact lines in common are generic (`#[derive(...)]` lists, `fn fmt(&self, f: &mut
core::fmt::Formatter<'_>) -> core::fmt::Result {`, `pub(crate) const fn new() -> Self {`,
`let mut rslt = Self::default();`, `rslt = rslt.wrapping_add(value);`); the one window of three
lines in common is a `core` import list (`pin::{Pin, pin}, task::{Context, Poll}, time::Duration`).
No comment line matches.
