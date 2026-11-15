# rimu-gzip

A one-shot DEFLATE encoder for Rust with raw (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952)
output: one input slice in, one complete stream appended to a `Vec<u8>` out. Fast on small
bodies, close to libdeflate on large ones, allocation-free once warm, `no_std` + `alloc`.

Part of the rimu family of performance crates, alongside rimu-ws. Not affiliated with the Rimu
template language (`rimu` on crates.io).

```rust
use rimu_gzip::{Encoder, Format, Level};

let body: &[u8] = br#"{"items":[{"id":1,"name":"Item 1"}]}"#;
let mut encoder = Encoder::new();               // Level::DEFAULT; keep it and reuse it
let mut out = Vec::new();
encoder.gzip(body, &mut out);                   // appends one gzip member
encoder.zlib(body, &mut out);                   // or a zlib stream
encoder.deflate(body, &mut out);                // or a raw DEFLATE stream
encoder.encode(Format::Gzip, body, &mut out);   // the same, format chosen at run time

let mut small = Encoder::with_level(Level::BEST);     // levels 0..=9
let mut fast = Encoder::with_level(Level::FASTEST);
let worst = rimu_gzip::gzip_bound(body.len());        // also deflate_bound, zlib_bound
```

**Streaming is out of scope**: the whole input must be in one slice and the whole output goes to
one vector. There is no decoder.

## API

| item | what it is |
|---|---|
| `Encoder` | the reusable encoder: `new()`, `with_level(Level)`, `with_params(Params)`; `deflate`, `zlib`, `gzip`, `encode(Format, ..)` append to a `Vec<u8>` |
| `Level` | 0 (stored) to 9; `NONE`, `FASTEST` (1), `DEFAULT` (3), `BEST` (9), `Level::new(n)` |
| `Params` | the knobs behind a level: `strategy`, `search_depth`, `nice_match`, `good_match`, `max_insert`, `skip_accel`, `len3`, `split_blocks`; `Params::of_level` |
| `Strategy` | `Stored`, `Fast`, `Greedy`, `LazyOnce`, `Lazy`, `Lazy2` |
| `Format` | `Raw`, `Zlib`, `Gzip`; `Format::bound(len)` |
| `deflate_bound`, `zlib_bound`, `gzip_bound` | the largest output for `len` input bytes (`const fn`) |

- **Allocation-free once warm.** The encoder's tables and token buffer grow to the largest
  input seen and are reused; `out` is grown once to the bound. After one encode, encoding that
  input or any smaller one, in any format and at the same level, into a vector with room
  allocates nothing (tested with a counting global allocator, `tests/alloc.rs`).
- **Infallible.** The encode methods return nothing; they only panic if the output vector cannot
  grow.
- `no_std` + `alloc`; the default `std` feature only lets `crc32fast` pick its carry-less multiply
  kernel at run time (CRC-32 is the only dependency; Adler-32 is built in).

## Levels

| level | strategy | depth | nice | notes |
|---|---|---|---|---|
| 0 | stored | – | – | stored blocks only |
| 1 | `Fast` | – | 32 | greedy over a hash table of 2-entry buckets (libdeflate level 1's design), inserting only the first two positions of each match, skip acceleration 4 past the first window, 64 KiB blocks, no block splitting |
| 2 | `Greedy` | 4 | 16 | inserts 4 positions per match, skip acceleration 4; no block splitting |
| **3 (default)** | `LazyOnce` | 6 | 64 | the rimu-ws tuned set: one deferral, good length 8, 2 insertions per match, skip acceleration 2; no block splitting |
| 4 | `Lazy` | 10 | 30 | lazy matching as libdeflate's, adaptive minimum length, block splitting (as 5–9); the 3-byte table is off by default (`Params::len3`) |
| 5 | `Lazy` | 16 | 30 | libdeflate level 5's parameters |
| 6 | `Lazy` | 35 | 65 | libdeflate level 6's |
| 7 | `Lazy` | 100 | 130 | libdeflate level 7's |
| 8 | `Lazy2` | 300 | 258 | lazy two positions ahead, libdeflate level 8's |
| 9 | `Lazy2` | 600 | 258 | libdeflate level 9's |

The default stays the set rimu-ws chose for small JSON bodies (its json-comp sweep of 11 Nov
2026): on bodies of a few kilobytes it is faster than any libdeflate level at about the size of
libdeflate 4–6. Levels 1–3 do not split blocks: on 64 KB–1 MB inputs splitting saved 0.1–1 %
there for about 7 % more time (it never applies below 10,000 bytes).

## How it works

- **One slice, state sized to it.** The input is matched where it lies. Hash tables are sized to
  the input (256 to 32,768 heads) and only the part in use is cleared, so a 1 KB body touches a
  few KB of state, not the hundreds of KB a streaming compressor initializes.
- **32 KiB sliding window.** Matches reach back across block boundaries. The hash chains store
  positions in 16 bits relative to a base, as libdeflate does, and are rebased every 32 KiB with
  one vectorized saturating subtract; the level-1 hash table stores 32-bit positions (fewer
  instructions in its hot loop). Inputs are matched in independent 1 GiB segments.
- **Block splitting** (levels 4–9, or `Params::split_blocks`). libdeflate's heuristic: literals
  and matches are tallied into ten coarse types, and every 2 KiB, once at least 512 new symbols arrived, their distribution is compared
  with the block's so far; a block ends where they differ enough (blocks of 5,000 bytes and up,
  at most 300,000). The tallies come from the running symbol frequencies, so nothing is counted
  per token. Each block is written stored, with the fixed codes or with its own codes, whichever
  is fewest bits (sizes computed exactly).
- **Parsers.** A hash-table greedy parser (level 1); greedy, one-step lazy, lazy and lazy2 over
  hash chains. The lazy parsers follow libdeflate: a minimum match length chosen from the
  literal diversity of each block, and the same better-match test. Length-3 matches from a
  separate 3-byte table (`Params::len3`, reaching back 8 KiB) are available but off by default:
  like sirocco, we found the table costs more time than its matches are worth on every corpus
  class. While one position is searched, the table line the next position will need is
  prefetched, hiding that load behind the search.
- **Skip acceleration** (levels 1–3, `Params::skip_accel`, active only past the first 32 KiB
  window). After a run of matchless positions the parser starts stepping over them at a growing
  pace, as lz4 and sirocco do — but each skipped position is still inserted into the table
  without being searched, and the step is capped (at 256), so a long noise run cannot leap past
  the start of a repeated stretch the way an unbounded skip can.
- **Sequences.** As in libdeflate, literals are not stored per token: a sequence is a literal run
  (read back from the input at write time) and a match with its symbols and extra bits packed in
  64 bits. The writer keeps its bit buffer in registers, assembling four literals into one word
  before it enters the accumulator, and flushes once per four literals or per match, branch-free,
  into room reserved from the block's exact size.
- **Small inputs** (up to 32 KiB) run a separate instance of each chain parser without the
  rebase checks; the deep searches of levels 4–9 run out of line so their chain walk keeps its
  values in registers, while the shallow ones of levels 2–3 stay inline.

## Verification

- `tests/roundtrip.rs`: every level, format and size (0, 1–5, 255, 256, 1 KB, 4 KB, 9,999,
  10,000, 32 KiB ± 1, 65,533–65,537, 100 KB, 300,000, 305,001, 1 MiB and whole files) of random
  bytes, zeros, a two-byte pattern, synthetic text, random pieces repeated near and beyond the
  window, text/random/text (block splits), and the benchmark corpus when present (one file at a
  time and all concatenated, 2.5 MB), inflated by **three independent decoders**: miniz_oxide,
  libdeflate (C) and zlib-rs (through flate2, which also checks the zlib and gzip trailers).
  Output does not depend on what the encoder or `out` held before.
- A seeded randomized test (`seeded_random_round_trips`): random parameter sets (every strategy
  and knob, random formats) on random structured inputs up to 200 KB, checked by miniz_oxide and
  libdeflate. 400 iterations by default; `RIMU_GZIP_RANDOM_ITERS=40000` (120,000 encodes) passed.
- A cargo-fuzz target, `cargo +nightly fuzz run round_trip` in `rimu-gzip/`: parameters, format
  and up to three inputs per encoder from the fuzz input; checks bound, framing, checksums and
  the round trip. 40 minutes over three builds during development (about 4.9 million inputs,
  the last 0.9 million on the final code) found nothing.
- `tests/alloc.rs`: zero allocations after warm-up, every level and format.
- `cargo clippy --all-targets -- -D warnings` clean; `// SAFETY:` comments on every unsafe block.

The corpus is not in the repository; point `RIMU_GZIP_CORPUS` at a directory of files to include
it in the round-trip test.

## Benchmarks

`cargo run --release -p bench -- <corpus-dir> [--csv out.csv]` (the `bench` crate of this
workspace; `--gzip` compares gzip members instead of raw streams). Single core, pinned with
`taskset -c 5`, Ryzen 9 5900X, default target (no `target-cpu`), every codec writing **raw
DEFLATE** into a reused buffer; each row is the median of 9 timed batches of 20 ms, and the
best of two full runs. Every output is checked to inflate to its input with libdeflate.
`rimu-ws-old` is the encoder as imported from rimu-ws (vendored in `bench/src/legacy`, one block
per independent 65,534-byte chunk). `sirocco` is srijs/sirocco 0.3, the pure-Rust libdeflate
port. Corpus: `api.json` (957 KB JSON API response), `page.html` (930 KB), `app.js` (200 KB),
`app.log` (114 KB), `license.txt` (16 KB), `source.rs` (238 KB), `random.bin` (1 MB of
incompressible bytes) and `words-shuf.txt` (7.2 MB of words in random order), each cut to every
size class it reaches, plus the whole file.

The machine is shared; these two runs were taken at a load average around 2.5–3, and rows
still move by a few percent between runs. Output sizes are exact; read speeds as ±5 %, and
prefer the ratios between codecs in the same column.

### Geometric means per size class

Cell: output size relative to libdeflate level 6 / MB/s (geometric means over the files that
reach the size).

| codec | 256 B | 1 KB | 4 KB | 16 KB | 64 KB | 256 KB | whole files |
|---|---|---|---|---|---|---|---|
| rimu-0 | 1.43 @ 11362 | 1.95 @ 37389 | 2.51 @ 81217 | 3.19 @ 105189 | 3.51 @ 64874 | 3.71 @ 57012 | 3.91 @ 59586 |
| rimu-1 | 0.996 @ 101 | 1.01 @ 217 | 1.03 @ 342 | 1.07 @ 405 | 1.13 @ 299 | 1.16 @ 351 | 1.15 @ 338 |
| rimu-2 | 0.996 @ 101 | 1.01 @ 215 | 1.03 @ 350 | 1.07 @ 432 | 1.12 @ 259 | 1.15 @ 342 | 1.14 @ 315 |
| rimu-3 | 0.997 @ 101 | 1.01 @ 204 | 1.02 @ 330 | 1.05 @ 399 | 1.08 @ 226 | 1.10 @ 309 | 1.10 @ 275 |
| rimu-4 | 0.996 @ 95 | 0.999 @ 174 | 1.00 @ 246 | 1.01 @ 256 | 1.03 @ 139 | 1.04 @ 140 | 1.03 @ 150 |
| rimu-5 | 0.996 @ 96 | 0.999 @ 173 | 1.00 @ 237 | 1.00 @ 225 | 1.02 @ 125 | 1.03 @ 127 | 1.02 @ 129 |
| rimu-6 | 0.996 @ 96 | 0.999 @ 174 | 1.00 @ 216 | 0.999 @ 172 | 1.00 @ 97 | 1.00 @ 98 | 1.00 @ 100 |
| rimu-7 | 0.996 @ 95 | 0.999 @ 173 | 1.00 @ 205 | 0.995 @ 131 | 0.99 @ 71 | 0.984 @ 71 | 0.986 @ 73 |
| rimu-8 | 0.996 @ 94 | 0.998 @ 165 | 0.998 @ 175 | 0.991 @ 91 | 0.982 @ 44 | 0.974 @ 42 | 0.976 @ 44 |
| rimu-9 | 0.996 @ 95 | 0.998 @ 166 | 0.998 @ 173 | 0.991 @ 86 | 0.98 @ 35 | 0.972 @ 32 | 0.974 @ 35 |
| rimu-ws-old | 0.997 @ 81 | 1.01 @ 181 | 1.02 @ 303 | 1.05 @ 351 | 1.08 @ 198 | 1.14 @ 200 | 1.14 @ 215 |
| libdeflate-1 | 0.997 @ 53 | 1.01 @ 164 | 1.03 @ 357 | 1.07 @ 530 | 1.13 @ 353 | 1.16 @ 339 | 1.15 @ 366 |
| libdeflate-4 | 1.00 @ 41 | 1.00 @ 108 | 1.02 @ 193 | 1.04 @ 220 | 1.05 @ 172 | 1.06 @ 177 | 1.06 @ 179 |
| libdeflate-6 | 1.00 @ 40 | 1.00 @ 101 | 1.00 @ 169 | 1.00 @ 157 | 1.00 @ 117 | 1.00 @ 121 | 1.00 @ 120 |
| libdeflate-9 | 0.999 @ 40 | 0.999 @ 101 | 0.998 @ 149 | 0.991 @ 89 | 0.98 @ 44 | 0.972 @ 42 | 0.974 @ 44 |
| sirocco-1 | 1.00 @ 91 | 1.01 @ 195 | 1.04 @ 307 | 1.08 @ 386 | 1.14 @ 372 | 1.17 @ 520 | 1.18 @ 449 |
| sirocco-4 | 1.00 @ 75 | 1.00 @ 133 | 1.02 @ 171 | 1.05 @ 197 | 1.08 @ 187 | 1.11 @ 266 | 1.10 @ 230 |
| sirocco-6 | 1.00 @ 72 | 1.00 @ 123 | 1.00 @ 149 | 1.01 @ 142 | 1.02 @ 120 | 1.03 @ 127 | 1.02 @ 123 |
| sirocco-8 | 1.00 @ 72 | 1.00 @ 122 | 1.00 @ 143 | 1.00 @ 123 | 1.00 @ 98 | 1.00 @ 104 | 1.00 @ 101 |
| sirocco-9 | 1.00 @ 71 | 1.00 @ 122 | 1.00 @ 139 | 0.998 @ 117 | 0.997 @ 89 | 0.997 @ 95 | 0.997 @ 92 |
| zlib-rs-1 | 1.17 @ 49 | 1.27 @ 153 | 1.33 @ 327 | 1.40 @ 514 | 1.46 @ 348 | 1.48 @ 341 | 1.51 @ 361 |
| zlib-rs-6 | 0.997 @ 27 | 1.00 @ 69 | 1.01 @ 134 | 1.01 @ 133 | 1.02 @ 88 | 1.02 @ 87 | 1.01 @ 89 |
| miniz-1 | 1.01 @ 42 | 1.06 @ 119 | 1.13 @ 250 | 1.24 @ 387 | 1.34 @ 280 | 1.35 @ 324 | 1.40 @ 295 |
| miniz-6 | 0.998 @ 33 | 1.01 @ 76 | 1.01 @ 108 | 1.01 @ 73 | 1.01 @ 48 | 0.996 @ 48 | 0.998 @ 45 |

### Per file (output bytes @ MB/s)

**api.json**

| size | rimu-3 | rimu-ws-old | libdeflate-1 | libdeflate-4 | libdeflate-6 |
|---|---|---|---|---|---|
| 256 B | 167 B @ 110 | 167 B @ 89 | 167 B @ 55 | 170 B @ 42 | 170 B @ 41 |
| 1 KB | 390 B @ 255 | 390 B @ 212 | 391 B @ 174 | 390 B @ 118 | 387 B @ 113 |
| 4 KB | 913 B @ 506 | 913 B @ 456 | 959 B @ 417 | 923 B @ 232 | 889 B @ 202 |
| 16 KB | 2,653 B @ 656 | 2,653 B @ 637 | 3,006 B @ 645 | 2,744 B @ 297 | 2,508 B @ 216 |
| 64 KB | 9,382 B @ 420 | 9,385 B @ 427 | 11,197 B @ 563 | 9,232 B @ 246 | 8,261 B @ 148 |
| 256 KB | 36,158 B @ 392 | 37,548 B @ 384 | 43,608 B @ 528 | 35,557 B @ 246 | 31,318 B @ 142 |
| whole | 133,454 B @ 389 | 140,105 B @ 374 | 162,207 B @ 525 | 131,565 B @ 246 | 115,213 B @ 143 |

**page.html**

| size | rimu-1 | libdeflate-1 | rimu-6 | libdeflate-6 | rimu-9 | libdeflate-9 |
|---|---|---|---|---|---|---|
| 4 KB | 1,494 B @ 346 | 1,493 B @ 350 | 1,456 B @ 245 | 1,456 B @ 189 | 1,452 B @ 232 | 1,455 B @ 180 |
| 64 KB | 15,067 B @ 324 | 15,058 B @ 423 | 13,555 B @ 124 | 13,532 B @ 150 | 13,473 B @ 51 | 13,454 B @ 62 |
| whole | 125,932 B @ 434 | 125,699 B @ 533 | 104,024 B @ 199 | 104,246 B @ 218 | 101,097 B @ 78 | 101,340 B @ 87 |

**source.rs**

| size | rimu-1 | libdeflate-1 | rimu-6 | libdeflate-6 | rimu-9 | libdeflate-9 |
|---|---|---|---|---|---|---|
| 4 KB | 1,914 B @ 291 | 1,911 B @ 341 | 1,888 B @ 194 | 1,890 B @ 158 | 1,885 B @ 172 | 1,887 B @ 148 |
| 64 KB | 20,057 B @ 258 | 20,066 B @ 341 | 17,965 B @ 93 | 18,013 B @ 107 | 17,745 B @ 36 | 17,788 B @ 44 |
| whole | 67,072 B @ 254 | 67,063 B @ 348 | 58,202 B @ 90 | 58,245 B @ 111 | 57,047 B @ 31 | 57,116 B @ 38 |

### Reading the tables

- **Small bodies (≤ 4 KB):** every rimu-gzip level is faster than the libdeflate level of the
  same size: level 3 (the default) runs 2.5–2.7× libdeflate 4 and 6 at about their size, and
  level 1 runs 1.9–2.2× libdeflate 1.
- **The default vs the old encoder:** byte-for-byte the same sizes up to 16 KB (2–3 bytes smaller
  at 64 KB), faster in every size class here, and 4–6 % smaller from 256 KB up (the window
  reaches across the old 64 KB chunks).
- **Against sirocco** (its levels sit elsewhere on the ratio ladder, so compare at matched
  parser settings): rimu-6 (Lazy, depth 35, nice 65) and sirocco-8 (the same parameters) produce
  the same sizes within 0.1 % at the same speed — 100 vs 101 MB/s on whole files. Where the
  ladders do align, rimu is smaller at the same speed: rimu-1 is 3 % smaller than sirocco-1 at
  256 KB (1.16 vs 1.17, and 2–10 % on the individual text files) with the whole-output column at
  1.15 vs 1.18. sirocco-1 is still the faster of the two on large compressible inputs (its skip
  acceleration never inserts the skipped positions, trading that robustness for speed), and
  unbeaten on pure noise (1,700 vs 675 MB/s on `random.bin`) — rimu keeps its skip bounded and
  its tables complete instead. At the top end rimu-9 reaches ratio points sirocco has no level
  for: 0.974 vs 0.997 at level 9's settings, 4.9 % smaller on `words-shuf.txt`.
- **Large inputs, level for level against libdeflate:** levels 6 and 9 produce libdeflate 6 and
  9's sizes (within 0.1 % here) at about 75–85 % of their speed from 16 KB up; level 1 matches
  libdeflate 1's size at 77–94 % of its speed above 4 KB. libdeflate still wins on speed for
  large inputs.

## Limitations

- One-shot only: no streaming, no dictionary, no decoder.
- Above ~4 KB, every level is slower than the libdeflate level of the same size (about 75–94 %
  of its speed, see the tables); below, it is faster.
- No near-optimal parsing: level 9 matches libdeflate level 9, not libdeflate's levels 10–12.
- Matches do not cross 1 GiB segment boundaries (positions are 32-bit within a segment).
- The gzip header is minimal (no name, time or extra fields; OS = Unix).

## License

Apache-2.0. See [LICENSE](LICENSE).
