//! A ready-to-run HTTP/3 server on rimu-quic's io_uring driver (feature `uring`, Linux 6.1 or
//! later): [`serve`] runs an [`H3Server`] per worker of a [`rimu_quic::uring::Server`].
//!
//! [`H3Server`] is the driver's application ([`UringApp`]): at each turn it refreshes the `date`
//! of responses (if [`H3Params::date`]), resumes the parked requests that its handler says are
//! ready ([`Handler::poll_ready`]), and trims its pool with the endpoint's when the worker is idle.
//! Its counters ([`H3Counters`]) go with the worker's.
//!
//! ```rust,ignore
//! use rimu_h3::{Body, H3Params, Handler, ReqCtx, ReqOutcome, Request, ResponseFields};
//! use rimu_h3::uring::{ServeParams, serve};
//!
//! struct Hello;
//!
//! impl Handler for Hello {
//!   fn on_request(&mut self, cx: &mut ReqCtx<'_, '_>, _: &Request<'_>) -> rimu_h3::Result<ReqOutcome> {
//!     cx.respond_with(&ResponseFields::with_type(200, b"text/plain"), Body::Bytes(b"hello\n"))?;
//!     Ok(ReqOutcome::Responded)
//!   }
//! }
//!
//! let tls = rimu_quic::rustls::RustlsConfig::builder().cert_chain_pem(&cert).private_key_pem(&key).build()?;
//! serve(ServeParams::new("[::]:8443".parse()?), rimu_quic::QuicParams::default(), tls, |_worker| Hello)?;
//! ```

use crate::{H3ErrorCode, H3Params, H3Server, Handler};
use alloc::sync::Arc;
use core::{net::SocketAddr, task::Waker};
use rimu_quic::{
  Endpoint, QuicParams,
  rustls::RustlsConfig,
  uring::{AppCounters, Server, ServerParams, Stats, UringApp, WorkerStats},
};
use std::io::{self, Write as _};

/// The counters of the HTTP/3 layer of a worker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct H3Counters {
  /// Requests given to the handler.
  pub requests: u64,
  /// Field sections of requests decoded, heads and trailers.
  pub qpack_sections: u64,
  /// Of [`Self::qpack_sections`], those that the decode memo replayed.
  pub qpack_memo_hits: u64,
  /// Connection states waiting in the pool.
  pub pooled: u64,
}

impl AppCounters for H3Counters {
  #[inline]
  fn for_each(&self, f: &mut dyn FnMut(&'static str, u64)) {
    f("requests", self.requests);
    f("qpack_sections", self.qpack_sections);
    f("qpack_memo_hits", self.qpack_memo_hits);
    f("h3_pooled", self.pooled);
  }
}

impl<H> UringApp for H3Server<H>
where
  H: Handler,
{
  type Counters = H3Counters;

  #[inline]
  fn start_turn(&mut self, _now_us: u64) {
    if self.params().date {
      self.refresh_date();
    }
  }

  #[inline]
  fn resume(&mut self, endpoint: &mut Endpoint<Self>, now_us: u64, waker: &Waker) {
    while let Some((conn, stream)) = self.handler.poll_ready(waker) {
      // A connection that is gone has nothing to resume; one whose resumption fails is closed
      let _ran = endpoint.with_conn(now_us, conn, self, |app, cx| {
        if app.resume(cx, stream).is_err() {
          cx.close(H3ErrorCode::InternalError.code(), b"");
        }
      });
    }
  }

  #[inline]
  fn trim_idle(&mut self) {
    H3Server::trim_idle(self);
  }

  #[inline]
  fn counters(&self) -> H3Counters {
    let qpack = self.qpack_counters();
    H3Counters {
      requests: self.requests(),
      qpack_sections: qpack.sections,
      qpack_memo_hits: qpack.memo_hits,
      pooled: u64::try_from(self.pooled()).unwrap_or(u64::MAX),
    }
  }
}

/// The settings of [`serve`]: those of the driver and of the HTTP/3 connections.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServeParams {
  /// The driver: address, workers, pinning, sockets, runtimes, drain. Its `quic` is replaced by
  /// the QUIC parameters given to [`serve`], and `handle_signals` is on by default here.
  pub server: ServerParams,
  /// The HTTP/3 connections.
  pub h3: H3Params,
  /// With signals handled, SIGUSR1 prints one line to standard output: `h3-stats ` and every
  /// counter summed over the workers as `name=value` ([`Stats::line`]). Defaults to `true`.
  pub stats_on_usr1: bool,
}

impl ServeParams {
  /// The defaults, serving on `addr`, with SIGINT/SIGTERM (graceful shutdown) and SIGUSR1
  /// (counters) handled.
  #[inline]
  #[must_use]
  pub fn new(addr: SocketAddr) -> Self {
    let mut server = ServerParams::new(addr);
    server.handle_signals = true;
    Self { server, h3: H3Params::default(), stats_on_usr1: true }
  }
}

/// The server of [`serve`] before it runs, for a caller that wants its shutdown handle or its
/// counters ([`Server::shutdown_handle`], [`Server::stats`]); run it with [`run`].
#[inline]
pub fn server<H>(params: &ServeParams, quic: QuicParams) -> Server<H3Server<H>>
where
  H: Handler + 'static,
{
  let mut server_params = params.server.clone();
  server_params.quic = quic;
  let server = Server::new(server_params);
  if params.stats_on_usr1 { server.on_stats_signal(print_stats) } else { server }
}

/// Runs `server` (from [`server`]) with `tls` and the handlers that `make_handler` makes, one per
/// worker on its thread, given the index of the worker, until it shuts down.
///
/// # Errors
///
/// As [`Server::run`].
#[inline]
pub fn run<H, F>(
  server: Server<H3Server<H>>,
  h3: H3Params,
  tls: RustlsConfig,
  make_handler: F,
) -> io::Result<()>
where
  H: Handler + 'static,
  F: Fn(u8) -> H + Sync,
{
  server.run(Arc::new(tls), |worker| H3Server::new(make_handler(worker), h3))
}

/// Serves HTTP/3 with `params`, `quic` and `tls` (whose ALPN must offer `h3`, as
/// [`RustlsConfig::builder`] does by default) until a shutdown: one worker per CPU (or
/// [`ServerParams::workers`]), each answering with a handler that `make_handler` makes on its
/// thread, given the index of the worker. SIGINT or SIGTERM drains the connections (GOAWAY, the
/// requests under way finish) and returns.
///
/// # Errors
///
/// As [`Server::run`].
#[inline]
pub fn serve<H, F>(
  params: ServeParams,
  quic: QuicParams,
  tls: RustlsConfig,
  make_handler: F,
) -> io::Result<()>
where
  H: Handler + 'static,
  F: Fn(u8) -> H + Sync,
{
  run(server(&params, quic), params.h3, tls, make_handler)
}

fn print_stats(workers: &[WorkerStats<H3Counters>]) {
  let line = Stats::line(workers);
  let mut stdout = io::stdout().lock();
  let _rslt = writeln!(stdout, "h3-stats {line}");
  let _rslt = stdout.flush();
}
