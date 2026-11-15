# Spike: rustls for rimu-quic's TLS — Capture or Wrap (§8 step 1), 14 Nov 2026

**Decision: Capture.** rustls derives every QUIC key inside the calls Capture wraps (pinned by a
test for all three suites, Initial, Handshake, 1-RTT and key updates); the captured bytes build
the in-tree key types, so the per-packet path *is* the in-tree path. Wrap costs nothing measurable
on the AEAD, but loses batched header protection (about +4–5 ns per 1-RTT packet sent, 1–1.5 % of
sealing a full-size packet) and would put `Box<dyn …>` keys in the connection (allocations on every
key update, no in-place wipe of pooled key slots). Wrap stays the fallback.

**Handshake cost:** a rustls server costs **+6–8 %** CPU per ECDSA P-256 handshake and **+1–2 %**
per RSA-2048 handshake (≈5–10 µs more per handshake) against the in-tree handshake, and makes
**81 allocations / 15.5 KB (ECDSA), 90 / 20.7 KB (RSA)** per handshake where the warm in-tree
server makes **0 (ECDSA) / 9 (RSA, ring's signature)**. Per-packet and per-request zero allocation
is unaffected; per-handshake zero allocation is gone and the allocation tests must be re-baselined.

## 1. What was built

Scratch worktree `~/src/rimu-ws/.claude/worktrees/spike-rustls-quic`, branch `spike/rustls-quic`
(commit `d2755029`, not for merging), rustls 0.23.46 with the ring provider added to the `quic`
feature.

- **`quic/rustls_session.rs`**
  - `CaptureAlg`: a rustls `quic::Algorithm` that copies the bytes of each packet key + IV and
    header-protection key rustls hands it into a thread-local slot, armed only around
    `write_hs` and `Secrets::next_packet_keys`, and gives rustls zero-sized dummy keys (a `Box`
    of a ZST allocates nothing). `CaptureDelegate` hands rustls ring's real keys instead, for
    the tests that compare the two.
  - `WrapAlg`: the native `TrafficAead`/`QuicHp` behind rustls's `PacketKey` and
    `HeaderProtectionKey` (one sample per call, called through `dyn`).
  - Providers: copies of ring's three TLS 1.3 suites with `quic` replaced; server config (ALPN
    `h3`, no tickets, no session storage, no 0-RTT, no half-RTT data, no cert compression) and a
    test client config.
  - `RustlsSession`: the interface `conn.rs` needs from the in-tree `QuicTls` (`feed`,
    `output`, `peer_transport_params`, `alpn`, `is_complete`, `connection_seed`), but yielding
    native `PacketKeys` (`poll_keys`) instead of secrets. Key updates come from rustls's
    `Secrets` (`RustlsNext`, shared by the two directions, which `KeyPhase` advances at
    different times).
- **`quic/conn_tls.rs`**: `ConnTls`, the in-tree `QuicTls` or a boxed `RustlsSession` behind one
  interface; `conn.rs` now calls `poll_keys`. `SPIKE_RUSTLS=server|client|both` switches the test
  harness (`testing.rs`, `conn/check.rs`, `endpoint/check.rs`, the endpoint's server sessions in
  tests) to rustls.
- **`quic/crypto.rs`**: `DirectionalKeys::from_parts` (keys from captured bytes) and a
  `KeySecret` enum (the in-tree traffic secret, or rustls's `Secrets`) in place of the secret
  array; `QuicConn` still passes its ≤ 4 KiB assertion.
- **`quic/rustls_spike.rs`**: the tests below and the ignored measurement tests; `tests.rs`'s
  counting allocator also counts bytes, live bytes and peak.

The connection is integrated with Capture only. Wrap is measured standalone: putting it in the
connection would mean replacing its key types with rustls's boxes, which is the cost being decided.

## 2. Correctness

| test | result |
|---|---|
| `capture_initial_keys_match_rfc9001_appendix_a`: captured Initial key/IV/HP bytes = RFC 9001 A.1; the native keys protect byte-identically to rustls's ring keys and to the in-tree `initial_keys`, both sides | pass |
| `capture_yields_every_key_change_and_matches_rustls_for_each_suite` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305): every `write_hs` key change yields exactly 4 captures in the order local HP, local packet, remote HP, remote packet; every `next_packet_keys` exactly 2 (local, remote); no key is derived outside the wrapped calls; native keys from captures seal byte-identically to rustls's and each opens the other's packets, for Handshake, 1-RTT and three key updates | pass |
| `sessions_interoperate_and_update_keys`: rustls↔rustls, in-tree client↔rustls server, rustls client↔in-tree server, each suite, 4 key generations with local/remote advanced separately | pass |
| `quic::` suites (312 tests), in-tree | 312 pass |
| `quic::`, `SPIKE_RUSTLS=both` (rustls server and client in the in-tree connection core) | 308 pass, 4 fail |
| `quic::`, `SPIKE_RUSTLS=server` (in-tree test client ↔ rustls server) | 308 pass, 4 fail |
| `quic::`, `SPIKE_RUSTLS=client` (rustls client ↔ in-tree server) | 312 pass |
| `http3::` (75 tests, with `_h3-loopback-client`), in-tree / `SPIKE_RUSTLS=both` | 75 / 74 pass, 1 fail |

The five failures are exactly the zero-allocation-after-warm-up tests that include handshakes
(`steady_state_handshake_and_acks_allocate_nothing_after_warmup`,
`endpoint_steady_state_allocates_nothing_after_warmup`,
`handshake_bursts_allocate_nothing_after_warmup`, `lossy_steady_state_allocates_nothing_after_warmup`,
`h3_steady_state_allocates_nothing_after_warmup`): rustls allocates per handshake (§4). Everything
else — handshake, data, loss recovery, Retry, migration, key updates (`peer_key_update_mid_transfer`,
`key_updates_wait_three_ptos_after_the_previous_one`, `previous_keys_open_late_packets…`), ALPN
refusal, 0-RTT dropped, transport-parameter errors — passes with rustls.

## 3. Measurements

**Method.** AMD Ryzen 9 5900X (12 cores/24 threads, frequency scaling on), shared machine with a
load average of 9–15 throughout; one core (`taskset -c 6`), release, default target and
`-C target-cpu=native`, in-process (no sockets). Each benchmark interleaves its variants (the order
rotates every round). Four passes per target, alternating default/native (two of 21 rounds, two of
41 rounds: 124 rounds per variant per target). Packet rounds time 20,000 packets per variant; HP
rounds 20,000 packets; handshake rounds 200 handshakes per variant. Cells are *median of the pass
medians / minimum over all rounds*. Medians move by up to ±30 % between passes (frequency and
neighbours); the minimum is the better guide for small differences, and comparisons are only made
within a pass's interleaving. Raw output: `/mnt/nvme1tb/claude-tmp/spike-rustls/results/`
(`060648`, `060908`), scripts in the spike branch's `.scripts/spike-rustls/`.

Variants: **in-tree** = keys from the in-tree handshake's secrets; **Capture** = keys built from
captured rustls bytes (same types and code as in-tree); **Wrap (dyn)** = native keys through
rustls's traits; **rustls ring (dyn)** = rustls's own ring keys, for reference. Packets are short
headers with an 8-byte DCID and a 2-byte packet number; "64 B ACK" is a 64-byte packet. The seal
column "HP deferred ×8" is the connection's real 1-RTT path (`protect_deferred` + `HpBatch`).

### 3.1 Packet protection per 1-RTT packet

**Seal + header protection, target default** (ns per packet, median / min)

| suite | packet | in-tree `protect` | Capture | Wrap (dyn) | rustls ring (dyn) | in-tree/Capture, HP deferred ×8 |
|---|---|---|---|---|---|---|
| AES-128-GCM | 1,200 B | 352 / 208 | 347 / 216 | 342 / 203 | 357 / 193 | 350 / 204 |
| AES-128-GCM | 1,350 B | 414 / 248 | 409 / 253 | 386 / 243 | 394 / 230 | 391 / 241 |
| AES-128-GCM | 64 B ACK | 178 / 126 | 176 / 127 | 169 / 114 | 177 / 109 | 173 / 116 |
| AES-256-GCM | 1,200 B | 393 / 227 | 387 / 234 | 376 / 209 | 379 / 208 | 389 / 216 |
| AES-256-GCM | 1,350 B | 328 / 272 | 328 / 275 | 308 / 259 | 306 / 254 | 316 / 263 |
| AES-256-GCM | 64 B ACK | 161 / 138 | 160 / 137 | 140 / 119 | 138 / 116 | 145 / 126 |
| ChaCha20-Poly1305 | 1,200 B | 787 / 624 | 778 / 620 | 771 / 610 | 757 / 611 | 775 / 618 |
| ChaCha20-Poly1305 | 1,350 B | 1027 / 705 | 1019 / 702 | 1011 / 697 | 1015 / 683 | 1027 / 700 |
| ChaCha20-Poly1305 | 64 B ACK | 308 / 247 | 311 / 247 | 298 / 233 | 295 / 227 | 310 / 240 |

**Remove header protection + open, target default** (ns per packet incl. a copy of the packet, median / min)

| suite | packet | in-tree | Capture | Wrap (dyn) | rustls ring (dyn) | copy alone |
|---|---|---|---|---|---|---|
| AES-128-GCM | 1,200 B | 373 / 216 | 382 / 216 | 367 / 209 | 379 / 213 | 23 / 14 |
| AES-128-GCM | 1,350 B | 416 / 248 | 413 / 249 | 412 / 243 | 416 / 246 | 25 / 15 |
| AES-128-GCM | 64 B ACK | 178 / 114 | 181 / 114 | 171 / 98 | 184 / 107 | 4 / 2 |
| AES-256-GCM | 1,200 B | 411 / 232 | 415 / 239 | 390 / 223 | 396 / 230 | 25 / 13 |
| AES-256-GCM | 1,350 B | 324 / 267 | 326 / 265 | 318 / 259 | 321 / 262 | 24 / 14 |
| AES-256-GCM | 64 B ACK | 146 / 124 | 147 / 125 | 131 / 110 | 148 / 119 | 3 / 2 |
| ChaCha20-Poly1305 | 1,200 B | 979 / 622 | 961 / 626 | 984 / 603 | 926 / 608 | 25 / 13 |
| ChaCha20-Poly1305 | 1,350 B | 1009 / 711 | 1018 / 717 | 998 / 697 | 1004 / 699 | 24 / 15 |
| ChaCha20-Poly1305 | 64 B ACK | 282 / 247 | 287 / 249 | 272 / 236 | 270 / 237 | 3 / 2 |

**Seal + header protection, target native** (ns per packet, median / min)

| suite | packet | in-tree `protect` | Capture | Wrap (dyn) | rustls ring (dyn) | in-tree/Capture, HP deferred ×8 |
|---|---|---|---|---|---|---|
| AES-128-GCM | 1,200 B | 345 / 256 | 350 / 270 | 337 / 259 | 349 / 269 | 331 / 251 |
| AES-128-GCM | 1,350 B | 396 / 314 | 395 / 295 | 391 / 300 | 393 / 306 | 398 / 302 |
| AES-128-GCM | 64 B ACK | 174 / 139 | 173 / 138 | 157 / 124 | 172 / 134 | 166 / 130 |
| AES-256-GCM | 1,200 B | 379 / 284 | 374 / 295 | 357 / 270 | 363 / 283 | 363 / 279 |
| AES-256-GCM | 1,350 B | 438 / 314 | 437 / 313 | 428 / 317 | 438 / 323 | 436 / 296 |
| AES-256-GCM | 64 B ACK | 195 / 152 | 190 / 153 | 175 / 142 | 190 / 151 | 182 / 142 |
| ChaCha20-Poly1305 | 1,200 B | 980 / 629 | 956 / 632 | 955 / 615 | 919 / 610 | 946 / 622 |
| ChaCha20-Poly1305 | 1,350 B | 1002 / 702 | 988 / 708 | 998 / 687 | 979 / 678 | 1003 / 692 |
| ChaCha20-Poly1305 | 64 B ACK | 347 / 263 | 350 / 272 | 339 / 262 | 330 / 253 | 348 / 266 |

**Remove header protection + open, target native** (ns per packet incl. a copy of the packet, median / min)

| suite | packet | in-tree | Capture | Wrap (dyn) | rustls ring (dyn) | copy alone |
|---|---|---|---|---|---|---|
| AES-128-GCM | 1,200 B | 352 / 221 | 361 / 225 | 360 / 215 | 363 / 278 | 23 / 16 |
| AES-128-GCM | 1,350 B | 416 / 321 | 410 / 316 | 408 / 320 | 419 / 282 | 27 / 17 |
| AES-128-GCM | 64 B ACK | 174 / 122 | 172 / 122 | 161 / 101 | 178 / 116 | 4 / 2 |
| AES-256-GCM | 1,200 B | 397 / 250 | 405 / 292 | 384 / 261 | 399 / 234 | 23 / 16 |
| AES-256-GCM | 1,350 B | 457 / 345 | 449 / 334 | 434 / 343 | 458 / 355 | 25 / 15 |
| AES-256-GCM | 64 B ACK | 188 / 129 | 188 / 129 | 176 / 111 | 192 / 124 | 4 / 3 |
| ChaCha20-Poly1305 | 1,200 B | 936 / 627 | 943 / 626 | 917 / 614 | 902 / 611 | 20 / 15 |
| ChaCha20-Poly1305 | 1,350 B | 1142 / 784 | 1147 / 779 | 1125 / 780 | 1101 / 773 | 26 / 19 |
| ChaCha20-Poly1305 | 64 B ACK | 330 / 243 | 332 / 241 | 321 / 237 | 332 / 234 | 4 / 2 |

Reading: Capture = in-tree, as it must (same code). Wrap's AEAD through `dyn` costs nothing
measurable — the indirect call is ~1 ns against 100–1,000 ns of AEAD; Wrap even comes out a few ns
*lower* than in-tree `protect` on small packets, most likely because its header-protection helper is leaner
(see 3.2), not because of `dyn`. Single-packet seal does not show the batching benefit; 3.2 does.

### 3.2 Header protection over a batch (8–64 packets of 1,200 B)

**Header protection of a batch of 1-RTT packets, target default** (ns per packet, median / min)

| suite | packets | batched (AES-NI, 8 lanes) | one at a time, AES-NI key | one at a time, ring key | Wrap (dyn, one at a time) | rustls ring (dyn) |
|---|---|---|---|---|---|---|
| AES-128-GCM | 8 | 8.3 / 5.3 | 19.1 / 16.5 | 30.3 / 25.9 | 12.8 / 7.0 | 25.0 / 14.6 |
| AES-128-GCM | 16 | 8.4 / 6.0 | 19.6 / 17.0 | 30.8 / 27.2 | 12.7 / 7.7 | 24.9 / 16.6 |
| AES-128-GCM | 32 | 8.5 / 5.8 | 20.0 / 17.5 | 31.3 / 27.6 | 12.9 / 7.6 | 26.2 / 16.7 |
| AES-128-GCM | 64 | 9.0 / 6.0 | 20.4 / 17.2 | 32.0 / 27.4 | 13.4 / 7.8 | 27.1 / 17.5 |
| AES-256-GCM | 8 | 10.3 / 7.0 | 24.1 / 20.8 | 35.3 / 31.0 | 13.5 / 8.6 | 26.8 / 17.7 |
| AES-256-GCM | 16 | 9.1 / 6.7 | 24.6 / 20.5 | 36.3 / 30.3 | 13.2 / 8.6 | 26.4 / 17.2 |
| AES-256-GCM | 32 | 10.7 / 6.7 | 25.2 / 20.1 | 36.9 / 29.5 | 16.4 / 8.1 | 32.8 / 17.8 |
| AES-256-GCM | 64 | 9.1 / 6.6 | 24.2 / 19.6 | 35.9 / 29.1 | 12.9 / 8.1 | 28.5 / 19.1 |
| ChaCha20-Poly1305 | 8 | 129.1 / 86.4 | 131.4 / 94.7 | 132.2 / 94.8 | 127.0 / 89.8 | 121.5 / 87.5 |
| ChaCha20-Poly1305 | 16 | 146.3 / 85.5 | 148.0 / 92.6 | 145.0 / 93.2 | 147.5 / 87.4 | 152.0 / 86.7 |
| ChaCha20-Poly1305 | 32 | 161.7 / 87.6 | 157.7 / 95.6 | 160.2 / 95.2 | 164.3 / 89.3 | 159.7 / 90.0 |
| ChaCha20-Poly1305 | 64 | 160.2 / 87.6 | 160.0 / 95.3 | 159.9 / 95.1 | 159.3 / 90.7 | 163.5 / 93.1 |

**Header protection of a batch of 1-RTT packets, target native** (ns per packet, median / min)

| suite | packets | batched (AES-NI, 8 lanes) | one at a time, AES-NI key | one at a time, ring key | Wrap (dyn, one at a time) | rustls ring (dyn) |
|---|---|---|---|---|---|---|
| AES-128-GCM | 8 | 10.4 / 7.0 | 20.3 / 16.7 | 31.4 / 26.1 | 15.1 / 10.8 | 29.5 / 22.7 |
| AES-128-GCM | 16 | 10.3 / 6.2 | 20.2 / 16.2 | 31.6 / 25.8 | 14.4 / 10.5 | 29.1 / 21.2 |
| AES-128-GCM | 32 | 10.4 / 6.8 | 20.1 / 16.7 | 31.5 / 26.3 | 14.9 / 11.1 | 29.2 / 22.9 |
| AES-128-GCM | 64 | 10.6 / 6.8 | 20.2 / 16.7 | 31.7 / 26.5 | 14.5 / 11.1 | 29.7 / 22.4 |
| AES-256-GCM | 8 | 11.9 / 8.0 | 24.9 / 20.2 | 36.4 / 29.9 | 16.6 / 12.7 | 32.4 / 25.9 |
| AES-256-GCM | 16 | 12.1 / 7.2 | 24.9 / 20.1 | 36.1 / 30.1 | 16.6 / 12.8 | 33.4 / 25.8 |
| AES-256-GCM | 32 | 11.8 / 8.3 | 24.6 / 20.3 | 36.0 / 29.7 | 16.7 / 12.8 | 33.7 / 27.3 |
| AES-256-GCM | 64 | 11.7 / 8.1 | 24.4 / 20.3 | 36.0 / 29.4 | 16.4 / 12.9 | 35.2 / 28.1 |
| ChaCha20-Poly1305 | 8 | 151.4 / 115.8 | 151.2 / 116.7 | 157.5 / 122.1 | 156.2 / 122.2 | 151.1 / 121.0 |
| ChaCha20-Poly1305 | 16 | 152.2 / 112.6 | 147.9 / 106.1 | 149.5 / 111.5 | 152.9 / 111.7 | 154.0 / 93.4 |
| ChaCha20-Poly1305 | 32 | 153.3 / 90.2 | 150.7 / 121.2 | 155.0 / 98.2 | 155.7 / 90.7 | 158.0 / 96.6 |
| ChaCha20-Poly1305 | 64 | 154.5 / 118.7 | 149.8 / 120.4 | 154.3 / 116.7 | 155.8 / 117.9 | 156.8 / 120.8 |

Reading: batching (the connection's 1-RTT send path) is **8.3–9.0 ns/packet** for AES-128
(10.3–10.6 native) against **12.7–13.4** (14.4–15.1) for Wrap's one-at-a-time calls: Wrap adds
**~4–5 ns per 1-RTT packet sent** (AES-256: 9.1–10.7 vs 12.9–16.4; native 11.7–12.1 vs
16.4–16.7). That is ~1–1.5 % of sealing a 1,200 B packet and ~3 % of a 64 B ACK. ChaCha20 does not
batch, so all variants are equal (and ~15× more expensive than AES-NI: ring's ChaCha20 HP).
Side finding: the in-tree one-at-a-time path (`sample` + `QuicHp::mask` + `apply_mask`, used by
`protect`, Initial/Handshake packets and `remove_header_protection` on receive) runs ~7 ns slower
than `WrapHp`'s minimal xor with the *same* AES-NI key (19–20 vs 13 ns) — an optimisation
independent of this decision.

### 3.3 Handshake cost per connection (server side only)

The client is rustls (not metered). Metered: the server session's construction, its handling of
the ClientHello and of the client's Finished, building the native Handshake and 1-RTT keys (both
servers), and dropping the session. Same certificate and key for both servers, ring for both
signatures. Allocations via a counting allocator around the server's calls only, after 20 warm-up
handshakes.

| certificate | server | µs per handshake, default (median / min) | native (median / min) | handshakes/s per core (default median) | allocations | bytes allocated | live heap while waiting for the client's Finished | peak live | left after the handshake |
|---|---|---|---|---|---|---|---|---|---|
| ECDSA P-256 | in-tree `QuicTls` | 117.4 / 79.0 | 109.4 / 80.5 | 8,520 | 0 | 0 | 0 (pooled) | 0 | 0 |
| ECDSA P-256 | rustls | 127.3 / 84.0 | 118.7 / 85.2 | 7,860 | 81 | 15,546 | 5,568 | 7,394 | 256 |
| RSA-2048 | in-tree `QuicTls` | 807.0 / 540.5 | 753.8 / 539.5 | 1,240 | 9 | 1,920 | 0 (pooled) | 1,280 | 0 |
| RSA-2048 | rustls | 820.2 / 545.4 | 763.4 / 544.4 | 1,220 | 90 | 20,749 | 6,205 | 8,935 | 256 |

rustls/in-tree: ECDSA +8.4 % (median) / +6.3 % (min) default, +8.5 % / +5.8 % native; RSA
+1.6 % / +0.9 % default, +1.3 % / +0.9 % native. In absolute terms rustls adds ≈5–10 µs per
handshake (its message framing, state machine and allocations); the signature dominates the rest,
so the gap shrinks with RSA.

### 3.4 Memory per connection

| | in-tree | rustls (spike) |
|---|---|---|
| inline in the connection | 16 B (`QuicTls`: config `Arc` + state box) | 16 B (`ConnTls` is the same size; `Box<RustlsSession>`) |
| per in-flight handshake | pooled state box 2,704 B + pooled reader/writer buffers: a cold first handshake allocates 13 blocks / 5,880 B and leaves 4,480 B in the thread's pool (RSA: 22 / 9,126, 5,364 pooled) | `RustlsSession` 1,840 B (of which `quic::ServerConnection` 1,160 B) boxed, plus rustls's heap: 5.6 KB live between ClientHello and client Finished (6.2 KB RSA), peak 7.4 KB (8.9 KB) |
| after the handshake is confirmed | 0 (state back to the pool; key update from the secret inside `DirectionalKeys`) | 256 B: rustls's `Secrets` for key updates (spike: `Arc<Mutex<…>>`; can be ~200 B inline in the connection's cold state) |
| `DirectionalKeys` | 944 B | 944 B (`KeySecret` replaces the secret array; `QuicConn` ≤ 4 KiB holds) |

## 4. What the handshake cost means

- **Handshake floods.** Per core, ECDSA handshakes drop from ~8.5 k/s to ~7.9 k/s (−8 %); RSA is
  unchanged within 2 %. At flood rates rustls adds ~650 k malloc/free pairs per second per core;
  this spike measured them with the system allocator on one thread, so allocator contention across
  workers is not in these numbers. Retry under load (already in the endpoint) keeps unvalidated
  floods from reaching TLS at all; a per-thread allocator (mimalloc-style) for the workers is the
  next mitigation. rustls has no API to reset a `ServerConnection`, so its state cannot be pooled
  the way the in-tree state box is; only the outer `RustlsSession` box and its output buffers can
  be reused (a few allocations of the 81).
- **Memory under a flood.** Per in-flight handshake rustls holds ~5.6–6.2 KB of heap (+1.8 KB
  box) against the in-tree ~4.5 KB pooled: comparable, bounded by the existing handshake limits.
- **Zero allocation.** Per packet and per request after warm-up: unchanged by construction —
  Capture builds the same key types, and the boxes it hands rustls are zero-sized (the spike's key
  updater uses `Vec`s that allocate once on the first key update; fixed arrays in the crate). The
  five failing tests are the ones whose measured window contains handshakes. Per handshake: no
  longer zero. Re-baseline the five tests in §2 to a per-handshake budget, as design
  §4 anticipated: with rustls 0.23.46 + ring, **≤ 81 allocations / 15.6 KB (ECDSA P-256), ≤ 90 /
  20.8 KB (RSA-2048) per handshake**, rustls's share named, and keep them pinned so a rustls
  upgrade that changes it is noticed.

## 5. Decision: Capture

1. **The assumption holds and is pinned.** rustls 0.23.46 derives every key in `write_hs`
   (`Keys::new` inside `Quic::write_hs`) and `Secrets::next_packet_keys`, in a fixed order, and
   nowhere else; the tests in §2 fail if that changes, for every suite and key generation.
2. **Per packet, Capture is the in-tree stack** (3.1): same types, same batched header protection,
   same pooled, self-wiping key slots, no `dyn`.
3. **Wrap's cost is small but real and structural**: ~4–5 ns per 1-RTT packet (no batch call in
   rustls's trait, 3.2); `Box<dyn PacketKey>`/`Box<dyn HeaderProtectionKey>` in the connection (four
   boxes per level, two more per key update — allocations on key update, against "zero allocation
   after warm-up"); key wiping left to the boxed types; confidentiality-limit counting moved out of
   `DirectionalKeys`. Its AEAD through `dyn` is free, so Wrap remains a cheap fallback (~1 %) if
   rustls ever moves key derivation.

For the crate: build `CryptoSession` (design §4) on this adapter. Hold rustls's `Secrets` in the
connection (or its cold state) instead of the spike's `Arc<Mutex<…>>`, and keep one derived,
not-yet-used half (local and remote advance at different times, `next_packet_keys` derives both);
fixed arrays instead of the spike's `Vec`s in the updater.

## 6. rustls API constraints found

- **Key timing.** Keys are derived in `write_hs`, not `read_hs` (rustls stores secrets during
  `read_hs`, builds keys when `write_hs` returns the `KeyChange`). Arm the capture around
  `write_hs` and `next_packet_keys` only. Order: local HP, local packet, remote HP, remote packet
  per `KeyChange`; local, remote per `next_packet_keys` (no HP: header keys do not change).
- **One call per level.** `write_hs` stops at each key change: call it until it returns nothing;
  bytes written before a `KeyChange` belong to the previous level. A server gets
  `KeyChange::Handshake` and `KeyChange::OneRtt` from the same ClientHello.
- **1-RTT keys come early on a server** (with its own Finished). The adapter holds them until
  `!is_handshaking()` (the client's Finished verified), as the in-tree handshake does (RFC 9001
  §5.7: no 1-RTT processing before the handshake completes); `send_half_rtt_data = false`.
- **`read_hs` takes no encryption level**: rustls cannot tell CRYPTO data at the wrong level. The
  adapter keeps the in-tree checks (earlier level → PROTOCOL_VIOLATION; later level or 1-RTT →
  `unexpected_message`).
- **Key updates** advance both directions in one `next_packet_keys`; the connection's `KeyPhase`
  advances local and remote separately, so the adapter keeps the other half. The `Secrets` must
  live as long as the connection (~200 B).
- **Transport parameters**: given as a `Vec<u8>` to `ServerConnection::new` (so before the
  ClientHello is read: the server's parameters, original DCID and reset token must be known then,
  as today); rustls does not look into either side's parameters, and fails the handshake if the
  peer sends none (`missing_extension`). `quic_transport_parameters()` returns the peer's raw bytes.
- **ALPN**: with `alpn_protocols = ["h3"]`, rustls in QUIC mode refuses a client that offers no
  ALPN or no overlap (`no_application_protocol`, 0x178) — the in-tree tests' expectation.
- **Tickets, resumption, 0-RTT** — the defaults are *not* what the server wants: `ServerConfig`
  sends 2 TLS 1.3 tickets and keeps a 256-entry in-memory session cache. Set
  `send_tls13_tickets = 0` (otherwise NewSessionTicket goes out in 1-RTT CRYPTO frames, which the
  in-tree connection never sends; the adapter errors on any 1-RTT CRYPTO output),
  `session_storage = NoServerSessionStorage`, keep the default never-ticketer, and
  `max_early_data_size = 0` (QUIC requires 0 or `u32::MAX`; 0 never offers early data). With
  those, resumption and 0-RTT are impossible and `zero_rtt_keys()` is `None`; the connection
  still drops 0-RTT packets (`zero_rtt_packet_is_dropped` passes).
- **Errors**: after `read_hs` fails, `alert()` gives the alert for CONNECTION_CLOSE `0x100 + alert`.
- **Providers**: `Tls13CipherSuite` has all-public fields (`common`, `hkdf_provider`, `aead_alg`,
  `quic`) in 0.23.46 (no `protocol_version` field any more); custom suites are leaked `'static`s.
  Disable cert compression explicitly (`cert_compressors`/`cert_decompressors`).
- **`std`**: `quic::{ServerConnection, ClientConnection, Connection}` exist only with rustls's
  `std` feature, so rimu-quic's `rustls` feature implies `std`; the core stays `no_std` + `alloc`.
- **Not resettable**: no way to reuse a `ServerConnection` for the next handshake (see §4).
- Not explored: rustls's `KeyLog` reports the traffic secrets (the in-tree derivation and key
  update could then stay unchanged), but it is a debugging interface, configuration-wide and keyed
  by client random; Capture needs none of that.
