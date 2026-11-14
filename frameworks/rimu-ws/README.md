# rimu-ws

[rimu-ws](https://github.com/vincentmele/rimu-ws), a fork of [wtx](https://github.com/c410-f3r/wtx),
on its io_uring executor. One binary serves:

- **WebSocket echo** on 8080 (`/ws`) through `WebSocketServerFramework`;
- **HTTP/2** through `Http2ServerFramework`: h2c on 8082 and h2 over TLS on 8443, with
  `/baseline2`, `/json/{count}` and `/static/{*file}`;
- **HTTP/3** through `Http3ServerFramework` on UDP 8443, beside h2, with the same router and
  handlers (`/baseline2`, `/static/{*file}` and `/json/{count}`).

## I/O path

- **One io_uring per core**, one thread each, every one with its own `SO_REUSEPORT` listener.
  The rings are set up with `SINGLE_ISSUER | DEFER_TASKRUN`.
- **Multishot accept, and multishot recv into a provided buffer ring.**
- **WebSocket:** frames are unmasked and parsed in the connection's read buffer. Every frame that
  arrived with one read is queued as a header plus a slice of the read buffer, and the whole batch
  goes out with one vectored send.
- **HTTP/2:** a connection decodes a few requests at a time and answers them before decoding the
  next, so their stream slots and buffers are reused while still in cache. Output and read buffers
  of idle connections go back to per-thread pools. TLS records are sealed in user space straight
  into the send buffers. Static files are served from a per-thread cache, with `.br`/`.gz`
  variants chosen by `Accept-Encoding`.
- **HTTP/3:** the rimu crates' QUIC, HTTP/3 and QPACK (rimu-quic, rimu-h3, rimu-qpack; no
  quinn, quiche or nghttp3; QUIC's TLS 1.3 is rustls) driven by rimu-ws's own loop on the same
  io_uring runtimes: one worker per CPU of the container, each with its own `SO_REUSEPORT` UDP
  socket on `[::]:8443` (dual-stack: IPv4 clients are answered from the address they used). A
  request whose handler completes at once is answered in the turn that received it. HTTP/3
  responses carry content-type only, like cnetmod and zix; full RFC 9110 headers via
  `set_rfc9110_headers(true)`. QPACK is static-table only for responses.

## Settings

The library defaults, plus what rimu-ws's production guide (`docs/production.md`) recommends for
this deployment shape (dedicated cores, clients that speak first):

- `TCP_DEFER_ACCEPT` on every listener;
- the WebSocket runtimes spin 20 µs before sleeping, which saves the sleep between the reconnects
  of `echo-ws-limited`, and skip the peer-address lookup. The HTTP/2 runtimes keep the defaults.

There are no tuning environment variables. `CERT_DIR`, `DATASET_PATH` and `STATIC_DIR` locate the
benchmark's files.

## Building

The rimu-ws sources are copied into `rimu-ws/` by `local-src.sh` before `docker build`.
