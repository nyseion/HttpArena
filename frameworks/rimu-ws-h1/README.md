# rimu-ws-h1

[rimu-ws](https://github.com/vincentmele/rimu-ws), a fork of [wtx](https://github.com/c410-f3r/wtx),
on its io_uring executor, serving HTTP/1.1 through `Http1ServerFramework`: plaintext on 8080 and
TLS on 8081. The HTTP/2 and WebSocket entry is `rimu-ws`; this one is the HTTP/1.1 server alone.

## Profiles

All eight HTTP/1.1 profiles:

| profile | port | endpoint |
|---|---|---|
| baseline, limited-conn | 8080 | `GET` and `POST /baseline11?a=&b=`: `a + b` plus the body of a POST |
| latency-1m, latency-10k | 8080 | the same, with no spin |
| async | 8080 | `GET /delay/{ms}`: answers `ms` after the delay; more than 5000 ms is a 400 |
| json-comp | 8080 | `GET /json/{count}?m=`, compressed by `Accept-Encoding` |
| json-tls | 8081 (TLS) | `GET /json/{count}?m=`, uncompressed |
| 8gbit | 8081 (TLS) | `POST /echo`: the request body, byte for byte |

`/json` serializes the dataset on every request. On 8080 it also compresses those bytes on every
request, by every `Accept-Encoding` line of the request: **gzip** (zlib level 6) if offered, else
brotli (quality 2), else none. gzip is preferred because, on this dataset, it produces a body about
the size of brotli's at a fraction of the CPU, which wins the size-penalised json-comp score. Every
response carries `Vary: Accept-Encoding`, and a request that refuses identity (`identity;q=0`, or
`*;q=0`) while offering neither gzip nor brotli gets a 406; a `*` with a nonzero `q` offers the
codings not listed, so `identity;q=0, *` is served gzip. Nothing is cached. The TLS `/json` is
never compressed and has no `Vary`.

## I/O path

- **One io_uring per core**, one thread each, every one with its own `SO_REUSEPORT` listener.
  The rings are set up with `SINGLE_ISSUER | DEFER_TASKRUN`.
- **Multishot accept, and multishot recv into a provided buffer ring.**
- **HTTP/1.1:** a hand-written resumable parser reads the request head out of the receive buffer
  and a resumable decoder reads a `Content-Length` or chunked body, so a request split at any byte
  is rebuilt without copying whole. Pipelined requests are answered in order, and handlers are
  synchronous, so a request costs no allocation and no boxed future. The parser is strict: HTTP/1.1
  needs exactly one `Host`, `Transfer-Encoding` is exactly `chunked`, and a bare line feed is not a
  line end.
- **Routing:** a path router with one handler per method (`HEAD` is served by the `GET` route).
  There is no middleware and no `Server` or `Date` header. The query is parsed on every request;
  nothing is cached.
- **Delays:** the driver awaits an io_uring timer, so a delayed request holds no thread, and it
  watches the socket meanwhile: a peer that goes away ends the connection at once. The framework's
  maximum delay is set to 5000 ms, the cap of `/delay/{ms}`, so a delay is never cut.
- **TLS (8081):** user-space TLS 1.3 from the mounted certificate (`/certs/server.crt` and
  `server.key`), ALPN `http/1.1` only. Without a certificate the entry serves 8080 alone.

## Settings

The library defaults, plus what rimu-ws's production guide recommends for clients that speak first:

- `TCP_DEFER_ACCEPT` on the 8080 listener;
- **no spin**: the runtimes sleep as soon as their ring is empty, because the latency profiles
  charge spin to the score. The peer-address lookup is skipped (no handler uses it).

Environment: `DATASET_PATH` (default `/data/dataset.json`) is the dataset `/json` serves,
`CERT_DIR` (default `/certs`) is the directory holding the TLS certificate and key, `server.crt` and
`server.key`, and `ARENA_LOG_ERRORS` prints the errors the server reports to stderr. There are no tuning variables.
The `Date` header is left out, which HTTP/1.1 allows for a server without a clock it can trust.

## Building

The rimu-ws sources are copied into `rimu-ws/` by `local-src.sh` before `docker build`; it also copies
`src/main.rs` and `src/arena_h1/alloc_tests.rs` from the checkout's arena-h1. `cargo test` runs the
server's unit tests and its steady-state allocation tests, which need the arena dataset (`DATASET_PATH`)
and certificate pair (`CERT_DIR`).
