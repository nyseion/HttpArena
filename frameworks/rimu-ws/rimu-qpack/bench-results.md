# Benchmark results

Single core (`taskset -c 6`), AMD Ryzen 9 5900X, default x86-64 build, release profile (fat
LTO). The machine was shared: another build ran at the same time (load average 3 to 14), and runs
differed by up to 40 %. Read the ratios within one table, not the absolute times. Every decoded
section was checked during setup; the benchmarks then decode the same bytes repeatedly.

## After the encoder name index, the division-free rings and the Huffman rework

Same machine, shared (load average 12 to 15), `taskset -c 22`, best of 3 runs of each side of
every A/B: the base at commit `06035cf`, then the changes below. What changed:

- the encoder's dynamic table has a direct-mapped name index (1024 slots by name hash), so
  `find` and `newest_name` walk down from the newest entry with the name instead of scanning
  the whole table; `blocking_streams` is a counter recounted on decoder-stream instructions
  instead of a scan of every tracked section per encode,
- the decoder's and encoder's byte rings and entry rings wrap by a conditional subtract instead
  of a division (`%` by a length that is not a power of two),
- Huffman decoding stages its output in a 66-byte block flushed to the output, instead of
  zeroing the whole upper bound of the output first (`Vec::resize` with 0 for every decoded
  string),
- `push_string` Huffman-codes past a placeholder header of the raw length and rewrites the
  header when the coding is kept, instead of walking the bytes once for `encoded_len` and
  again to encode.

| case | base ns / section | after | |
|---|---:|---:|---:|
| decode netbsd, static table + raw literals | 121.1 | 99.8 | -17.6 % |
| decode netbsd, static table + Huffman literals | 857.6 | 733.0 | -14.5 % |
| decode netbsd, static + Huffman, memo on | 874.0 | 732.8 | -16.2 % |
| decode netbsd, dynamic table, no memo | 210.6 | 145.5 | -30.9 % |
| decode netbsd, dynamic table, memo | 52.9 | 39.4 | -25.5 % |
| decode load-generator request (Huffman), no memo | 245.6 | 212.5 | -13.5 % |
| decode load-generator request (Huffman), memo | 27.4 | 21.1 | -23.0 % |
| encode netbsd, `encode_static` (raw literals) | 277.7 | 246.3 | -11.3 % |
| encode netbsd, static-only `Encoder` (Huffman) | 532.0 | 466.5 | -12.3 % |
| encode netbsd, dynamic `Encoder`, steady state, acknowledged | 888.3 | 586.8 | -33.9 % |
| encode response head, static-only `Encoder` (Huffman) | 165.1 | 163.0 | -1.3 % |
| encode response head, pre-encoded head + 2 lines | 44.6 | 46.3 | +3.8 % |

A hash of a kept section compared before its bytes in the decode memo was tried and reverted:
sections that share a Required Insert Count differ in their first bytes, so the memcmps already
exit early, while the hash walks the whole section on every lookup (the load-generator memo case
was 45 % slower with it).

## rimu-qpack (`cargo bench --bench qpack`, quietest run, load ~3)

Input: the 18 browser requests of `netbsd.qif` (qifs corpus, 318 bytes of names and values per
request on average), a load generator's 5-field request, and 6-field response heads.

## rimu-qpack (`cargo bench --bench qpack`, quietest run, load ~3)

| case | ns / section |
|---|---:|
| decode netbsd, static table + raw literals | 115 |
| decode netbsd, static table + Huffman literals | 723 |
| decode netbsd, static + Huffman, memo on (sections > 128 B, not kept) | 719 |
| decode netbsd, dynamic table (steady state), no memo | 183 |
| decode netbsd, dynamic table, memo | 43 |
| decode load-generator request (Huffman), no memo | 206 |
| decode load-generator request, memo | 22 |
| encode netbsd, `encode_static` (raw literals) | 229 |
| encode netbsd, static-only `Encoder` (Huffman) | 424 |
| encode netbsd, dynamic `Encoder`, steady state, acknowledged | 731 |
| encode response head, static-only `Encoder` (Huffman) | 156 |
| encode response head, pre-encoded head + 2 lines | 43 |

Section bytes for the 18 requests: 4135 static raw, 3258 static Huffman, 263 dynamic (third pass,
after 617 encoder-stream bytes over three passes).

## Against ls-qpack (`cargo bench -p rimu-qpack-interop --bench compare`, median of 3, load ~14)

ls-qpack is the C library through the `ls-qpack-rs` 0.3.3 bindings, whose decoder boxes each
decoded header and keeps a hash map of streams, and whose encoder copies each header into a box:
part of its time is the bindings, not the C code.

| case | ls-qpack | rimu-qpack | ratio |
|---|---:|---:|---:|
| decode sections written by ls-qpack, dynamic table | 1770 | 453 (97 with memo) | 3.9× (18×) |
| decode sections written by ls-qpack, static table only | 3106 | 1080 | 2.9× |
| encode, steady state (dynamic table, acknowledged) | 3335 | 1494 | 2.2× |
| encode, static table only | 2993 | 894 | 3.3× |

Bytes written for the 18 requests three times over (17,208 bytes of names and values):

| encoder | sections | encoder stream |
|---|---:|---:|
| ls-qpack (default options) | 2269 | 150 |
| rimu-qpack, `InsertPolicy::Repeated` | 1379 | 617 |
| rimu-qpack, `InsertPolicy::Always` | 789 | 617 |
