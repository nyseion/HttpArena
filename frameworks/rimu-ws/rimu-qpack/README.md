# rimu-qpack

Sans-IO QPACK ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204)) field compression for HTTP/3:
a hardened decoder with a replay memo, a dynamic-table encoder, and static-only encoding for
pre-encoded response heads. `no_std` + `alloc`, no `unsafe`, no dependencies.

Part of the rimu family of performance crates, alongside rimu-ws. Not affiliated with the Rimu
template language (`rimu` on crates.io).

Rust's HTTP/3 stacks keep their QPACK code internal (h3 has its own), and the usual standalone
option is C bindings to ls-qpack. This crate is a standalone codec that any QUIC/HTTP/3 stack
(quinn + h3, s2n-quic, quiche users, your own) can drive: it does no I/O, it only turns bytes into
fields and fields into bytes, and it tells you what to write on the QPACK streams.

```rust
use rimu_qpack::{Decoder, DecoderConfig, Encoder, EncoderConfig, Field, FieldList};

let mut decoder = Decoder::new(DecoderConfig::default()); // advertises 4096 / 100 blocked streams
let mut encoder = Encoder::new(EncoderConfig::default());
encoder.set_peer_settings(decoder.settings())?;           // the peer's SETTINGS

let request = [Field::new(b":method", b"GET"), Field::new(b":path", b"/"),
               Field::sensitive(b"authorization", b"Bearer t")];
let mut section = Vec::new();
encoder.encode(0, request, &mut section);                  // HEADERS frame payload
decoder.feed_encoder_stream(encoder.encoder_stream_output())?; // encoder stream
encoder.consume_encoder_stream(usize::MAX);
let mut fields = FieldList::new();
decoder.decode_into(0, &section, &mut fields)?;            // or decode(..) with a zero-copy sink
encoder.feed_decoder_stream(decoder.decoder_stream_output())?; // decoder stream
decoder.consume_decoder_stream(usize::MAX);
```

## API

| | |
|---|---|
| `Decoder::new(DecoderConfig)` | capacity, blocked streams, memo size, max field section size, decoder-stream backlog bound; `settings()` to advertise |
| `Decoder::feed_encoder_stream(&[u8])` | applies the peer's encoder stream; incomplete instructions are kept for the next call |
| `Decoder::decode(stream, section, sink)` | `Done` or `Blocked { required_insert_count }`; the sink gets `DecodedField { name, value, sensitive, static_ref }` borrowed from the section, the static table or the table ring (no copies unless Huffman-coded or wrapping) and may abort with your own error type |
| `Decoder::decode_into(stream, section, &mut FieldList)` | the same into an owned list |
| `Decoder::take_unblocked()` | streams whose blocked sections can now be decoded |
| `Decoder::cancel_stream(stream)` | Stream Cancellation |
| `Decoder::decoder_stream_output()` / `consume_decoder_stream(n)` | Section Acknowledgments, Stream Cancellations and one coalesced Insert Count Increment, to write on the decoder stream |
| `Encoder::new(EncoderConfig)` | max capacity, insert policy, blocking allowed, Huffman, index sensitive names |
| `Encoder::set_peer_settings(Settings)` | capacity = min(peer, config), Set Dynamic Table Capacity queued |
| `Encoder::encode(stream, fields, &mut Vec<u8>)` | appends the field section; queues encoder-stream instructions |
| `Encoder::feed_decoder_stream(&[u8])` | Section Acknowledgment, Stream Cancellation, Insert Count Increment |
| `Encoder::set_capacity(n)` | refuses (locally) to evict entries that are still referenced or unacknowledged |
| `encode_static`, `encode_static_line`, `encode_static_prefix` | static-table-only sections with no encoder state, for pre-encoded response heads |
| `huffman_code::{encode, decode, encoded_len}` | the RFC 7541 Huffman code |

Errors carry an `ErrorKind` and the HTTP/3 code to close the connection with
(`QPACK_DECOMPRESSION_FAILED`, `QPACK_ENCODER_STREAM_ERROR`, `QPACK_DECODER_STREAM_ERROR`,
`H3_EXCESSIVE_LOAD`), or none for local errors (a sink abort, a field section over the configured
size, a capacity change that has to wait).

## Encoder policy

For each field: an exact static match is indexed; a sensitive field (`Field::sensitive`, or
`authorization`, `cookie`, `proxy-authorization`, `set-cookie` unless `index_sensitive_names`) is
never inserted and is sent with the never-indexed bit; an exact dynamic match is indexed if it may
be referenced (draining entries, the oldest eighth of the table, are duplicated first when there is
room); otherwise the field is inserted when the `InsertPolicy` says so (`Repeated`, the default:
the second time a hash filter sees the name and value, so dates and ids do not churn the table;
`Always`; `Never` = static-only mode), named by a static reference, the newest dynamic entry with
the name, or literally, and referenced post-base. Anything else is a literal with a name reference
when there is one. Strings are Huffman-coded when shorter.

An unacknowledged entry may be referenced only if blocking is allowed and the stream already risks
blocking or fewer streams than the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` do. An entry is evicted
only once acknowledged and unreferenced by unacknowledged sections; the encoder never inserts when
it would need to evict anything else. At most 4096 unacknowledged sections are tracked; beyond,
sections are static-only.

## Hardening

The decoder allocates its table storage once (twice the capacity), checks every length against
the bytes present before copying or reserving, bounds Huffman output, keeps an incomplete
encoder-stream instruction only up to what a valid one can need (four capacities), bounds pending
decoder-stream output (64 KiB by default) and limits the bytes that Duplicates and dynamic name
references copy out of the table to 64 per byte of instruction (up to four capacities banked).
Encoder and decoder allocate nothing per field section once warmed up (checked with a counting
allocator).

The **decode memo** keeps the last N field sections (up to 128 bytes, decoding to up to 2 KiB) with
their fields, keyed by the absolute Required Insert Count and the section bytes, and replays one
while the oldest dynamic entry that it referenced is still in the table: load generators and
browsers repeat sections byte for byte, and a replay is a compare and a copy-free iteration
instead of a decode. It is cleared when the table starts over (`reset`), so it never replays
another connection's table.

## Testing and interop

- RFC 9204 Appendix B: every exchange decodes to the RFC's fields with the RFC's decoder-stream
  bytes; RFC 7541 Appendix C Huffman strings encode and decode exactly.
- Huffman: written from the RFC 7541 Appendix B table; checked exhaustively against a
  bit-at-a-time reference decoder for every input of up to two bytes, 200,000 random 3–11 byte
  inputs, every single symbol, 20,000 random round trips, and the padding/EOS error cases.
- Error kinds of RFC 9204 for the decoder (invalid static/dynamic references, Required Insert
  Count errors, negative Base, truncation, integer overflow, bad Huffman, capacity above the
  maximum, entries larger than the table, too many blocked streams) and the encoder (unexpected
  Section Acknowledgment, zero or excessive Insert Count Increment).
- A model checker (a hand-written conformant encoder) and a connection checker (this crate's
  encoder and decoder with delayed, split and reordered streams, out-of-order unblocking,
  trailers, cancellations and capacity changes), each over thousands of seeded random inputs, and
  as libFuzzer targets (`fuzz/`) with a decoder target over arbitrary bytes.
- **qifs** (github.com/qpackers/qifs, the QPACK offline interop corpus): the netbsd QIFs and all
  176 of their encodings by ls-qpack, nghttp3, quinn, proxygen, f5 and qthingey are vendored and
  decode exactly; with `QIFS_DIR` set, the whole qpack-05 corpus (529 files, ~138,000 sections,
  including the Facebook request/response traces) decodes exactly. Those encoders predate RFC
  9204's initial capacity of 0, so a Set Dynamic Table Capacity is fed first when their encoder
  stream lacks one.
- **ls-qpack** (`interop/`, through the `ls-qpack-rs` bindings; needs cmake and libclang):
  ls-qpack's encoder into this decoder, and this encoder into ls-qpack's decoder, over random
  header lists, tables from 0 to 64 KiB, blocked-stream limits and delayed encoder streams. If
  bindgen cannot find the C headers, set e.g.
  `BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/15/include"`.

## Benchmarks

Single core, Ryzen 9 5900X, shared machine (details and caveats in
[`bench-results.md`](bench-results.md)); netbsd browser requests, ns per field section:

| | rimu-qpack | ls-qpack (via ls-qpack-rs) |
|---|---:|---:|
| decode, dynamic table | 453 (97 with memo) | 1770 |
| decode, static table only | 1080 | 3106 |
| encode, dynamic table, steady state | 1494 | 3335 |
| encode, static table only | 894 | 2993 |

The comparison includes the bindings' per-header boxing. `taskset -c 6 cargo bench --bench qpack`;
`cargo bench -p rimu-qpack-interop --bench compare`.

## Status and limitations

- A field section is decoded from one contiguous slice; a blocked section is kept by the caller
  and decoded again when its stream shows up in `take_unblocked()`.
- The encoder never inserts names alone, and finds entries by a linear scan of the table (at
  most capacity / 32 entries); per-stream bookkeeping is linear in the streams with
  unacknowledged sections.
- 0-RTT remembered settings are not modelled: `set_peer_settings` is called once.
- Sensitivity is detected by name for four names only; mark anything else with
  `Field::sensitive`.

## Provenance and license

The decoder, decode memo, static table, static encoder and model checker began in
[rimu-ws](https://github.com/vincentmele/rimu-ws), where this crate's author wrote them for its
HTTP/3 server; they are not taken from wtx. The Huffman code is new for this crate, written from
the code table of RFC 7541. The qifs test vectors in `tests/qifs/` are MIT-licensed (see
`tests/qifs/LICENSE.md`).

Licensed under the [Apache License, Version 2.0](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 license, shall be licensed as above, without any
additional terms or conditions.
