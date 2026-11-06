# rimu-ws

[rimu-ws](https://github.com/vincentmele/rimu-ws), a fork of [wtx](https://github.com/c410-f3r/wtx),
on its io_uring executor. One binary serves:

- **WebSocket echo** on 8080 (`/ws`) through `WebSocketServerFramework`;
- **HTTP/2** through `Http2ServerFramework`: h2c on 8082 and h2 over TLS on 8443, with
  `/baseline2`, `/json/{count}` and `/static/{*file}`.

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
