# rimu-ws

A WebSocket echo server on [rimu-ws](https://github.com/vincentmele/rimu-ws), a fork of
[wtx](https://github.com/c410-f3r/wtx). It uses the same `WebSocketServerFramework` as the
`wtx-ws` entry, run on the fork's io_uring executor instead of tokio.

## I/O path

- **One io_uring per core**, one thread each, every one with its own `SO_REUSEPORT` listener.
  The rings are set up with `SINGLE_ISSUER | DEFER_TASKRUN`.
- **Multishot accept into direct descriptors**, so a closing connection queues its close on
  the ring instead of making a syscall.
- **Multishot recv into a provided buffer ring.** Frames are unmasked and parsed in the
  connection's read buffer.
- **Echoes are queued, not awaited.** Every frame that arrived with one read is queued as a
  header plus a slice of the read buffer, and the whole batch goes out with one vectored send.
- **No busy-poll.** Each reactor shares its core with an SMT sibling, and a spinning thread
  slows the busy one beside it; `RIMU_SPIN_US` turns it on.

## Knobs

Environment variables, all optional:

| Variable | Default | Meaning |
|---|---|---|
| `RIMU_SPIN_US` | `0` | Busy-poll before sleeping, in µs; `0` turns it off |
| `RIMU_DIRECT` | `16384` | Direct-descriptor table size per ring; `0` uses regular fds |
| `RIMU_RINGS` | `4096,16384` | Submission and completion queue sizes |
| `RIMU_NODELAY` | `1` | `TCP_NODELAY` on accepted sockets |
