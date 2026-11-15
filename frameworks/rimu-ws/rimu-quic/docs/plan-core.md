# rimu-quic core — plan (design §8 step 2), 14 Nov 2026

Move rimu-ws's sans-I/O QUIC v1 server transport into the `rimu-quic` crate, replace what it used
from wtx (MPL) per design §1, put TLS behind a `CryptoSession` trait with a rustls adapter
(Capture, spike-tls.md), and port every in-tree test. No I/O driver, no HTTP/3.

Source: `~/src/rimu-ws` `main` (read-only); the spike's new files from `spike/rustls-quic`
(`d2755029`): `quic/rustls_session.rs`, `quic/conn_tls.rs`, `quic/rustls_spike.rs`, and its
`DirectionalKeys::from_parts` in `quic/crypto.rs`.

## 1. Layout

```
Cargo.toml                workspace: rimu-quic, bench (fuzz/ is its own workspace, cargo-fuzz)
rimu-quic/src/
  lib.rs                  was quic.rs: modules, re-exports, DatagramMeta
  error.rs                NEW  crate Error (Quic, QuicClose, Crypto, Tls, Conversion, ProgrammingError)
  rng.rs                  NEW  QuicRng (rand_chacha ChaCha20Rng, seeded by getrandom), fixed hash state
  hex.rs                  NEW  const hex decoder for test vectors (replaces wtx's hexd!/codec)
  shared_bytes.rs         wtx/src/misc/shared_bytes.rs
  crypto/mod.rs           NEW + user's blocks of wtx crypto.rs: constants, key wrapper macro,
                          drop_and_zero; zero_volatile rewritten
  crypto/aead_key{,/*}.rs wtx/src/crypto/aead_key{,/*}  (ring, alr = aws-lc-rs, global)
  crypto/hp_key{,/*}.rs   wtx/src/crypto/hp_key{,/*}    (ring, alr, global, x86_aesni)
  crypto/hkdf.rs          NEW  HKDF-Extract/Expand-Label (RFC 8446 §7.1) and HMAC-SHA-256 on the backend
  suite.rs                NEW  CipherSuite (3 TLS 1.3 suites: key/hash lengths, limits)
  tls.rs                  NEW  CryptoSession, KeyChange, KeyMaterial, KeyPair, KeyUpdater,
                          Level, TlsAlert, ServerSessionFactory; SecretKeyUpdater ("quic ku")
  conn_tls.rs             from the spike's conn_tls.rs/RustlsSession: level checks, output per
                          level, 1-RTT keys held until the handshake completes
  rustls/                 from the spike's rustls_session.rs: CaptureAlg + capture slot,
                          providers, ServerConfigBuilder, server session, test client session
  (every file of wtx/src/quic/** keeps its name and place: app, cc, cid, cid_table, conn{,/path,
   /check}, crypto, diag, endpoint{,/check,/tests}, flow, frame{,_check}, key_phase, limits,
   packet{,_check}, pmtud, pools, quic_error, recovery, recv_tracker, sent, steer, stream{,/*},
   testing, timer_wheel, token, transport_params, tx_arena, varint, writer)
fuzz/                     cargo-fuzz targets
bench/                    seal/open + HP batch, frame decode, handshake
```

## 2. What each wtx dependency becomes

| wtx item | replacement |
|---|---|
| `crate::Error`, `crate::Result` | `rimu_quic::Error` (same variant names for the QUIC ones), `Result` |
| `tls::QuicTls`, `TlsConfig`, `TlsCtxSk`, `SkCtx`, `UnverifiedCtx`, `next_rng` | `Box<dyn CryptoSession>` made by an `Arc<dyn ServerSessionFactory>`; the generic `TCX` goes |
| `tls::CipherSuite`, `AlertDescription` | `suite::CipherSuite`; alerts are `TlsAlert(u8)` constants |
| `tls::TrafficAead` (user's, in `tls/`) | `crypto::QuicAead`, the same enum over `AeadKey`s |
| `tls::key_schedule::hkdf_expand_label`, `CipherSuite::hkdf_*` | `crypto::hkdf` (fresh, on ring / aws-lc-rs) |
| `crypto::{Hmac, HmacSha256Global}` (tokens) | `crypto::hkdf::hmac_sha256` |
| `rng::{ChaCha20, CryptoRng, CryptoSeedableRng, Rng}` | `rng::QuicRng` (`rand_chacha::ChaCha20Rng`); the generic `RNG` goes |
| `misc::random_state` | `rng::hash_state` (foldhash `FixedState` from the RNG) |
| `misc::zero_volatile` | `crypto::zero_volatile` (fresh: volatile byte writes + fence) |
| `collections::{Vector, ArrayVectorCopy}` | `Vec` (boxed slices where fixed) and fixed arrays with a length |
| `sync::{Arc, AtomicU*}` | `alloc::sync::Arc`, `core::sync::atomic` |
| `hexd!` | `hex!` (fresh const decoder) |
| `tests::{_count_allocations_in, _PUBLIC_KEY, _SECRET_KEY}` | `testing::alloc` (fresh counting allocator, also bytes), fresh test certificates (ECDSA P-256, RSA-2048) |

Generics: `QuicConn<A, RNG, TCX, IS_CLIENT>` → `QuicConn<A, IS_CLIENT>`, `Endpoint<A, RNG, TCX>` →
`Endpoint<A>`. The session is called a few times per handshake, so `dyn` costs nothing per packet.

## 3. `CryptoSession` as finally shaped

```rust
pub trait CryptoSession: Send {
  /// CRYPTO data received, in order. Levels are checked by the core (rustls takes none).
  fn read_handshake(&mut self, data: &[u8]) -> Result<(), TlsAlert>;
  /// Handshake bytes to send, appended to `out`; returns a key change when the next level's keys
  /// are ready. Bytes written before a change belong to the previous level.
  fn write_handshake(&mut self, out: &mut Vec<u8>) -> Result<Option<KeyChange>, TlsAlert>;
  fn peer_transport_params(&self) -> Option<&[u8]>;
  fn alpn(&self) -> Option<&[u8]>;
  fn is_handshaking(&self) -> bool;
}
pub enum KeyChange {
  Handshake { keys: KeyPair },
  OneRtt { keys: KeyPair, updater: Box<dyn KeyUpdater> },
}
pub trait KeyUpdater: Send {
  /// The packet keys of the next 1-RTT key phase, both directions (RFC 9001 §6).
  fn next_keys(&mut self) -> Result<KeyPair, TlsAlert>;
}
```

Differences from design §4, and why:
- `KeyPair` carries **key material** (`KeyMaterial`: suite, packet key, IV, header key; wiped on
  drop), not the expanded native keys: the core expands them into its own `DirectionalKeys`
  (deciding batched header protection itself), so the trait needs no crate-private types.
- `read_handshake` takes no level (rustls cannot use one, spike §6); the core's `ConnTls` keeps the
  level checks of the in-tree handshake (earlier level → PROTOCOL_VIOLATION, later level or 1-RTT
  → unexpected_message) and the 1-RTT hold (keys used only once `!is_handshaking()`).
- `next_one_rtt_keys` moves from the session to a `KeyUpdater` handed over with the 1-RTT keys, so
  the connection drops the session (and rustls's ~5 KB of handshake heap) when the handshake ends
  and keeps only rustls's `Secrets` (spike §5). The core keeps the not-yet-used half (local and
  remote advance at different times) in fixed slots. A `SecretKeyUpdater` derives "quic ku" from
  traffic secrets for sessions that expose them (and the RFC 9001 A.5 tests).
- Sessions are made by `ServerSessionFactory::new_session(local_transport_params)`
  (rustls takes the parameters at construction).

## 4. rustls adapter (`rustls` feature, implies `std`)

From the spike: `CaptureAlg` (thread-local slot armed only around `write_hs` and
`Secrets::next_packet_keys`; zero-sized dummy keys to rustls), providers = ring's (or aws-lc-rs's)
three TLS 1.3 suites with `quic` replaced, leaked `'static`. `RustlsConfig::builder()` applies
every required setting: TLS 1.3 only, `alpn_protocols`, `max_early_data_size = 0`,
`send_tls13_tickets = 0`, `send_half_rtt_data = false`, `NoServerSessionStorage`, default
never-ticketer, no certificate compression; certificate chain + key from PEM or DER.
`RustlsServerSession` implements `CryptoSession`; `RustlsUpdater` (`Secrets`) implements
`KeyUpdater`. A capture that breaks the pinned assumptions (count/order) fails the handshake with
INTERNAL_ERROR instead of using wrong keys.

## 5. Test client (`client` feature, test-only)

`QuicConn<_, true>` stays (behind `cfg(any(test, feature = "client"))`), on
`RustlsClientSession` (rustls's `quic::ClientConnection`, any-certificate verifier, ALPN given,
no resumption, no early data). Not a supported client; documented as such.

## 6. Test-porting map

| in-tree | here | notes |
|---|---|---|
| `quic/**` unit tests (`cid`, `cc`, `cid_table`, `packet`, `recovery`, `transport_params`, `app`, `pmtud`, `token`, `flow`, `frame`, `recv_tracker`, `limits`, `tx_arena`, `sent`, `steer`, `timer_wheel`, `pools`, `conn/path`, `crypto`, `varint`, `writer`, `quic_error`, `stream`, `conn`) | same modules | in-tree TLS → rustls both sides |
| `conn/check.rs`, `endpoint/check.rs` (model checks), `frame_check`, `packet_check` | same | client on rustls's client |
| `endpoint/tests.rs`, `testing.rs` helpers | same | server config from fresh test certs |
| `crypto/aead_key.rs`, `hp_key.rs`, `hp_key/x86_aesni.rs` tests (incl. RFC 9001 A vectors) | same | per backend feature |
| spike `rustls_spike.rs` | `rustls/tests.rs` | Capture pinned for 3 suites, key updates, A.1 |
| — | `rustls/tests.rs` | NEW: no tickets, no session storage, 0-RTT refused |
| zero-allocation tests whose window contains handshakes | same | per-handshake allowance measured from rustls (spike ≈81 ECDSA / ≈90 RSA), zero per packet/request kept |

## 7. Verification commands

All with `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/rimu-quic/target`, `-j 4`, after `free -g`
shows ≥ 17 GB available, one cargo job at a time:

```
cargo build -p rimu-quic --no-default-features            # no_std + alloc core (ring)
cargo test  -p rimu-quic                                   # rustls + ring
cargo test  -p rimu-quic --no-default-features --features rustls,aws-lc-rs   # if aws-lc-rs ports
cargo clippy -p rimu-quic --all-targets -- -D warnings
cargo +nightly fuzz run <target> -- -max_total_time=300   # in fuzz/
cargo bench -p rimu-quic-bench
```

## 8. Status (end of step 2)

Done as planned, with these deviations:

- **Backends**: `ring` (default) and `aws-lc-rs` ported (both pass the whole suite); the in-tree
  Graviola (no header protection) and RustCrypto backends were left out.
- **Endpoint API names** stay the in-tree ones: `recv`, `recv_forwarded`, `on_timeout` (design:
  "handle_timeouts"), `flush` (design: "poll_transmit"), `next_deadline` (design:
  "next_timeout").
- **Key updates allocate**: rustls's `Secrets::next_packet_keys` allocates 4 times per key phase
  (both directions), and the connection prepares the next phase when the handshake is confirmed.
  Zero allocation per packet and per request holds; per key update it does not (the in-tree stack
  derived from the secret without allocating). Capturing the traffic secrets through rustls's
  `KeyLog` would remove it; not done.
- **The test client is crate-internal** (`QuicConn<_, true>` for the tests and the fuzz targets);
  the `client` feature only exposes `rustls::RustlsClientConfig`.
- **Fuzzing is not fully deterministic**: rustls draws its own randomness (client random, key
  shares), so a crash found by `quic_conn`/`quic_endpoint` may need a few runs to reproduce.
- **Toolchain**: stable Rust ≥ 1.95 (`core::hint::cold_path`, `cfg_select!`); nightly only for
  cargo-fuzz.
