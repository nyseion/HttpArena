# rimu-quic core — micro-benchmarks, 14 Nov 2026

`cargo build --release -p rimu-quic-bench && taskset -c 14 target/release/rimu-quic-bench 21`:
AMD Ryzen 9 5900X, shared machine (load average 14–16), the least busy core, default target,
21 interleaved rounds per table, two passes; cells are median / min over the rounds of a pass.
Same packet shapes as `docs/spike-tls.md` §3 (8-byte DCID, 2-byte packet number; "64 B ACK" is a
64-byte packet).

## Against the spike (`docs/spike-tls.md` §3, "Capture" columns, default target)

| measure | spike (median / min) | here, pass 1 | here, pass 2 |
|---|---|---|---|
| seal + HP, AES-128-GCM 1,200 B | 347 / 216 | 320 / 294 | 250 / 247 |
| seal, HP deferred ×8, AES-128-GCM 1,200 B | 350 / 204 | 289 / 271 | 227 / 223 |
| seal + HP, AES-128-GCM 64 B | 176 / 127 | 168 / 156 | 136 / 134 |
| seal + HP, ChaCha20-Poly1305 1,200 B | 778 / 620 | 774 / 746 | 622 / 612 |
| remove HP + open, AES-128-GCM 1,200 B | 382 / 216 | 299 / 273 | 287 / 231 |
| remove HP + open, AES-256-GCM 1,350 B | 326 / 265 | 338 / 319 | 341 / 335 |
| server handshake, ECDSA P-256, µs | 127.3 / 84.0 | 82.3 / 80.9 | 99.9 / 84.4 |
| server handshake, RSA-2048, µs | 820.2 / 545.4 | 547 / 537 | 682 / 668 |

The per-packet path is the in-tree code (keys built from captured bytes), so it matches the
spike's Capture and in-tree columns within the spread of this machine (the spike saw medians move
±30 % between passes; its minimums are over 124 rounds, these over 21). The handshake minimums
match the spike's rustls server (84 µs ECDSA, 545 µs RSA).

The header-protection table here times the masks alone (`QuicHp::masks` / `mask`), without
taking the sample and applying the mask, so it is not comparable with the spike's §3.2, which
timed the whole header protection: batched AES-128 masks cost 1.8–2.0 ns per packet against
7.5–8.4 ns one at a time (AES-256: 2.8–3.7 against 9.4–12.9); ChaCha20 does not batch.

## Pass 1 (full output)

rimu-quic micro-benchmarks, 21 rounds (median / min)

Seal + header protection, ns per 1-RTT packet

| suite | packet | `protect` | HP deferred ×8 (flush path) |
|---|---|---|---|
| AES-128-GCM | 1,200 B | 320 / 294 | 289 / 271 |
| AES-128-GCM | 1,350 B | 325 / 297 | 304 / 278 |
| AES-128-GCM | 64 B ACK | 168 / 156 | 145 / 136 |
| AES-256-GCM | 1,200 B | 334 / 318 | 308 / 289 |
| AES-256-GCM | 1,350 B | 348 / 330 | 328 / 307 |
| AES-256-GCM | 64 B ACK | 180 / 165 | 151 / 141 |
| ChaCha20-Poly1305 | 1,200 B | 774 / 746 | 766 / 719 |
| ChaCha20-Poly1305 | 1,350 B | 810 / 775 | 820 / 778 |
| ChaCha20-Poly1305 | 64 B ACK | 300 / 285 | 290 / 271 |

Remove header protection + open, ns per 1-RTT packet (incl. a copy)

| suite | packet | open |
|---|---|---|
| AES-128-GCM | 1,200 B | 299 / 273 |
| AES-128-GCM | 1,350 B | 309 / 285 |
| AES-128-GCM | 64 B ACK | 135 / 123 |
| AES-256-GCM | 1,200 B | 324 / 299 |
| AES-256-GCM | 1,350 B | 338 / 319 |
| AES-256-GCM | 64 B ACK | 146 / 135 |
| ChaCha20-Poly1305 | 1,200 B | 795 / 655 |
| ChaCha20-Poly1305 | 1,350 B | 694 / 666 |
| ChaCha20-Poly1305 | 64 B ACK | 229 / 225 |

Header protection of a batch, ns per packet

| suite | packets | batched (AES-NI, 8 lanes) | one at a time, backend key |
|---|---|---|---|
| AES-128-GCM | 8 | 1.9 / 1.8 | 7.8 / 7.6 |
| AES-128-GCM | 16 | 1.8 / 1.8 | 7.6 / 7.6 |
| AES-128-GCM | 32 | 1.8 / 1.8 | 7.5 / 7.5 |
| AES-128-GCM | 64 | 1.7 / 1.7 | 7.6 / 7.3 |
| AES-256-GCM | 8 | 3.0 / 2.9 | 9.8 / 9.3 |
| AES-256-GCM | 16 | 2.9 / 2.8 | 9.5 / 9.4 |
| AES-256-GCM | 32 | 2.8 / 2.8 | 9.4 / 9.3 |
| AES-256-GCM | 64 | 2.8 / 2.8 | 9.5 / 9.4 |
| ChaCha20-Poly1305 | 8 | 80.6 / 79.8 | 83.1 / 81.3 |
| ChaCha20-Poly1305 | 16 | 81.8 / 80.2 | 82.9 / 81.6 |
| ChaCha20-Poly1305 | 32 | 81.9 / 81.0 | 83.2 / 80.7 |
| ChaCha20-Poly1305 | 64 | 81.3 / 80.3 | 82.6 / 81.3 |

Frame decoding, ns per 1-RTT payload

| payload | bytes | decode |
|---|---|---|
| ACK + MAX_STREAM_DATA + STREAM 1,100 B | 1118 | 27.8 / 26.9 |
| ACK + 40 × (PING, MAX_DATA, RESET_STREAM) | 412 | 687 / 670 |

Server handshake cost, µs per handshake (rustls client, not timed)

| certificate | µs per handshake |
|---|---|
| ECDSA P-256 | 82.3 / 80.9 |
| RSA-2048 | 547 / 537 |

## Pass 2 (full output)

rimu-quic micro-benchmarks, 21 rounds (median / min)

Seal + header protection, ns per 1-RTT packet

| suite | packet | `protect` | HP deferred ×8 (flush path) |
|---|---|---|---|
| AES-128-GCM | 1,200 B | 250 / 247 | 227 / 223 |
| AES-128-GCM | 1,350 B | 259 / 253 | 240 / 236 |
| AES-128-GCM | 64 B ACK | 136 / 134 | 114 / 112 |
| AES-256-GCM | 1,200 B | 266 / 261 | 246 / 243 |
| AES-256-GCM | 1,350 B | 282 / 275 | 261 / 257 |
| AES-256-GCM | 64 B ACK | 141 / 138 | 119 / 117 |
| ChaCha20-Poly1305 | 1,200 B | 622 / 612 | 609 / 598 |
| ChaCha20-Poly1305 | 1,350 B | 654 / 644 | 644 / 633 |
| ChaCha20-Poly1305 | 64 B ACK | 257 / 238 | 264 / 231 |

Remove header protection + open, ns per 1-RTT packet (incl. a copy)

| suite | packet | open |
|---|---|---|
| AES-128-GCM | 1,200 B | 287 / 231 |
| AES-128-GCM | 1,350 B | 306 / 304 |
| AES-128-GCM | 64 B ACK | 129 / 126 |
| AES-256-GCM | 1,200 B | 315 / 312 |
| AES-256-GCM | 1,350 B | 341 / 335 |
| AES-256-GCM | 64 B ACK | 143 / 141 |
| ChaCha20-Poly1305 | 1,200 B | 716 / 635 |
| ChaCha20-Poly1305 | 1,350 B | 762 / 710 |
| ChaCha20-Poly1305 | 64 B ACK | 230 / 223 |

Header protection of a batch, ns per packet

| suite | packets | batched (AES-NI, 8 lanes) | one at a time, backend key |
|---|---|---|---|
| AES-128-GCM | 8 | 2.0 / 1.9 | 8.2 / 8.0 |
| AES-128-GCM | 16 | 2.0 / 1.9 | 9.2 / 8.3 |
| AES-128-GCM | 32 | 1.9 / 1.9 | 8.2 / 8.2 |
| AES-128-GCM | 64 | 1.9 / 1.9 | 8.4 / 8.1 |
| AES-256-GCM | 8 | 3.7 / 3.6 | 12.9 / 11.6 |
| AES-256-GCM | 16 | 3.5 / 3.3 | 12.0 / 11.0 |
| AES-256-GCM | 32 | 3.6 / 3.2 | 12.1 / 10.7 |
| AES-256-GCM | 64 | 3.7 / 3.6 | 12.3 / 11.9 |
| ChaCha20-Poly1305 | 8 | 101 / 83 | 97.2 / 83.4 |
| ChaCha20-Poly1305 | 16 | 103 / 100 | 100 / 100 |
| ChaCha20-Poly1305 | 32 | 104 / 102 | 101 / 99 |
| ChaCha20-Poly1305 | 64 | 105 / 102 | 102 / 100 |

Frame decoding, ns per 1-RTT payload

| payload | bytes | decode |
|---|---|---|
| ACK + MAX_STREAM_DATA + STREAM 1,100 B | 1118 | 43.1 / 34.4 |
| ACK + 40 × (PING, MAX_DATA, RESET_STREAM) | 412 | 847 / 709 |

Server handshake cost, µs per handshake (rustls client, not timed)

| certificate | µs per handshake |
|---|---|
| ECDSA P-256 | 99.9 / 84.4 |
| RSA-2048 | 682 / 668 |
