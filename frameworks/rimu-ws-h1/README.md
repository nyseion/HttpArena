# rimu-ws-h1

[rimu-ws](https://github.com/vincentmele/rimu-ws), a fork of [wtx](https://github.com/c410-f3r/wtx),
on its io_uring executor, serving HTTP/1.1 on 8080 through `Http1ServerFramework`. The HTTP/2 and
WebSocket entry is `rimu-ws`; this one is the plaintext HTTP/1.1 server alone.

## I/O path

- **One io_uring per core**, one thread each, every one with its own `SO_REUSEPORT` listener.
  The rings are set up with `SINGLE_ISSUER | DEFER_TASKRUN`.
- **Multishot accept, and multishot recv into a provided buffer ring.**
- **HTTP/1.1:** a hand-written resumable parser reads the request head out of the receive buffer
  and a resumable decoder reads a `Content-Length` or chunked body, so a request split at any byte
  is rebuilt without copying whole. Pipelined requests are answered in order, and handlers are
  synchronous, so a request costs no allocation and no boxed future.
- **Routing and middleware:** a path router with one handler per method, and a middleware that
  adds the `server` header. The query is parsed on every request; nothing is cached.

## Settings

The library defaults, plus what rimu-ws's production guide recommends for clients that speak first:

- `TCP_DEFER_ACCEPT` on the listener;
- **no spin**: the runtimes sleep as soon as their ring is empty, because the latency profiles
  charge spin to the score. The peer-address lookup is skipped (no handler uses it).

There are no tuning environment variables. The `Date` header is left out, which HTTP/1.1 allows
for a server without a clock it can trust.

## Building

The rimu-ws sources are copied into `rimu-ws/` by `local-src.sh` before `docker build`.
