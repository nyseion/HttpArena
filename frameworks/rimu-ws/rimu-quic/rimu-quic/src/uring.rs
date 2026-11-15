//! The I/O driver on rimu-uring (feature `uring`, Linux 6.1 or later): a multi-worker QUIC server
//! loop, one io_uring runtime per worker.
//!
//! # Workers
//!
//! [`Server::run`] starts [`ServerParams::workers`] threads with rimu-uring's [`Builder`], each a
//! runtime pinned to a CPU ([`Pinning`]), its own UDP socket of a `SO_REUSEPORT` group bound to
//! [`ServerParams::addr`], its [`Endpoint`] and its application, made on the thread by the factory
//! that `run` is given. The workers bind one after the other, so that the socket of worker `i` is
//! the `i`-th of the group, and the last one attaches the classic BPF program of
//! [`crate::steering_cbpf`], which steers a datagram to the worker that the first byte of its
//! destination connection ID names. If the attach fails, every worker runs with the hash of the
//! kernel instead: CID steering and the balance of new connections are turned off in their
//! [`QuicParams`] (the degraded mode).
//!
//! # Turn
//!
//! A worker is one task that runs in turns, woken by datagrams, by its inbox, by its timer, by a
//! send slot that frees up or by a shutdown. In each turn it reads the clock once, then:
//!
//! 1. calls [`UringApp::start_turn`] (an HTTP/3 server refreshes its `date` there);
//! 2. hands every datagram received since the last turn to [`Endpoint::recv`], in its receive
//!    buffer: a datagram that the kernel coalesced (GRO) is split into its segments by the
//!    endpoint. One that the endpoint returns for another worker ([`crate::RecvOutcome::Forward`]) is
//!    pushed, segment by segment, into that worker's inbox ([`UdpInbox::push`]); a segment that
//!    the inbox refuses is dropped, and [`Endpoint::forward_dropped`] gives back the place that it
//!    took on that worker;
//! 3. hands the datagrams that other workers pushed into its own inbox to
//!    [`Endpoint::recv_forwarded`];
//! 4. calls [`UringApp::resume`], where an application resumes the work that waited (a parked
//!    request) through [`Endpoint::with_conn`];
//! 5. runs the timers that are due ([`Endpoint::on_timeout`]), and begins the shutdown if it was
//!    asked for;
//! 6. flushes every connection that has something to send into its [`crate::TxArena`], and sends each
//!    train of datagrams with one `UDP_SEGMENT` send ([`UdpSocket::send_train_with`], copied into
//!    a send slot of the socket, or sent from it zero-copy with [`UdpParams::zerocopy`]); a full
//!    arena is flushed again once its trains are out, and when every send slot is busy the rest
//!    waits for the next turn, which a free slot wakes;
//! 7. trims its pools once it has had no connection for [`ServerParams::idle_trim_after`], stores
//!    its counters for [`Stats`], and arms one timer of the ring for the next deadline of the
//!    endpoint (pacing included: the pacer's release times are deadlines of the connections).
//!
//! Nothing in a turn allocates once the worker is warm: the datagrams are processed where the
//! kernel put them, the trains are copied into send slots that keep their buffers, the timer is a
//! reused slot of the ring and the counters go into a cell of the worker.
//!
//! # Shutdown
//!
//! [`ShutdownHandle::trigger`] (or SIGINT / SIGTERM with [`ServerParams::handle_signals`]) wakes
//! every worker, which calls [`Endpoint::begin_shutdown`]: new clients are dropped, the
//! application drains its connections (an HTTP/3 server sends GOAWAY and finishes the requests
//! under way) for at most [`ServerParams::drain`], and what is left is closed. A worker ends once
//! it has no connection, or [`ServerParams::linger`] after the drain, and aborts what remains.

mod affinity;
mod signals;
mod stats;
mod worker;

pub use rimu_uring;
pub use stats::{AppCounters, Stats, WorkerStats};

use crate::{
  Endpoint, EndpointKeys, QuicApp, QuicParams, WorkerLoads, rng::ChaCha20,
  tls::ServerSessionFactory,
};
use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, net::SocketAddr, task::Waker, time::Duration};
use rimu_uring::{
  Builder, Params,
  net::{UdpInbox, UdpParams, UdpSocket},
};
use std::{
  io,
  sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
  },
};

/// What the driver calls an application with, besides the callbacks of [`QuicApp`]. Every method
/// has a default but [`Self::counters`] (which an application without counters of its own answers
/// with `()`).
pub trait UringApp: QuicApp + Sized {
  /// The counters of the application, stored with the worker's at each turn ([`Stats`]).
  type Counters: AppCounters;

  /// The start of a turn, at `now_us` on the clock of the endpoint, before any datagram.
  #[inline]
  fn start_turn(&mut self, now_us: u64) {
    let _now_us = now_us;
  }

  /// After the datagrams of the turn and before its timers and flush: resume what waited, through
  /// [`Endpoint::with_conn`]. `waker` wakes the worker for another turn, from any thread.
  #[inline]
  fn resume(&mut self, endpoint: &mut Endpoint<Self>, now_us: u64, waker: &Waker) {
    let _args = (endpoint, now_us, waker);
  }

  /// The worker has had no connection for [`ServerParams::idle_trim_after`]: free what the pools
  /// of the application keep.
  #[inline]
  fn trim_idle(&mut self) {}

  /// The counters of the application now.
  fn counters(&self) -> Self::Counters;
}

/// Where the threads of the workers run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Pinning {
  /// Unpinned.
  None,
  /// Worker `i` on the `i`-th CPU that the process may run on, the first thread of each physical
  /// core first, then the others (cycling if there are more workers). Without the list of CPUs
  /// (no `/proc/self/status`), unpinned.
  #[default]
  Auto,
  /// Worker `i` on the `i`-th of these CPUs, cycling.
  Cores(Vec<usize>),
}

/// The settings of a [`Server`]. [`Self::new`] has the defaults.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerParams {
  /// The address of every socket. `[::]` makes dual-stack sockets that answer IPv4 clients from
  /// the address that they used.
  pub addr: SocketAddr,
  /// The workers, at most 255; `None` for one per CPU that the process may run on.
  pub workers: Option<u8>,
  /// Where the workers run. Defaults to [`Pinning::Auto`].
  pub pin: Pinning,
  /// The settings of the endpoints. The driver turns CID steering and balance off when it can not
  /// steer (see the module documentation), and sets [`crate::QuicLimits::shutdown_grace_ms`]
  /// from [`Self::drain`].
  pub quic: QuicParams,
  /// The settings of the sockets: `reuseport` is always on, and with more than one worker an
  /// inbox is added if it has none (256 slots of 2048 bytes). Defaults to rimu-uring's, with 128
  /// send slots.
  pub udp: UdpParams,
  /// The settings of the runtimes (ring sizes, spinning before sleeping).
  pub runtime: Params,
  /// The bytes of the send arena of a worker ([`crate::TxArena::DEFAULT_BYTES`] by default).
  pub tx_arena_bytes: usize,
  /// How long a shutdown lets the connections drain before they are closed. Defaults to 5 s.
  pub drain: Duration,
  /// How long past the drain a worker waits for its connections to end their closing period
  /// before it aborts them. Defaults to 5 s.
  pub linger: Duration,
  /// A worker trims its pools once it has had no connection for this long. Defaults to 1 s.
  pub idle_trim_after: Duration,
  /// SIGINT and SIGTERM begin the shutdown (a second one aborts at once), SIGUSR1 calls the
  /// callback of [`Server::on_stats_signal`]: the signals are blocked on the thread that calls
  /// [`Server::run`] and on the workers, and taken by a thread of their own. Defaults to `false`.
  pub handle_signals: bool,
}

impl ServerParams {
  /// The defaults, serving on `addr`.
  #[inline]
  #[must_use]
  pub fn new(addr: SocketAddr) -> Self {
    Self {
      addr,
      workers: None,
      pin: Pinning::Auto,
      quic: QuicParams::default(),
      udp: UdpParams::new().send_slots(128),
      runtime: Params::new(),
      tx_arena_bytes: crate::TxArena::DEFAULT_BYTES,
      drain: Duration::from_secs(5),
      linger: Duration::from_secs(5),
      idle_trim_after: Duration::from_secs(1),
      handle_signals: false,
    }
  }
}

/// Stops the workers of a [`Server`] from any thread: see [`Self::trigger`]. Clones share it.
#[derive(Clone, Debug, Default)]
pub struct ShutdownHandle {
  inner: Arc<ShutdownInner>,
}

#[derive(Debug, Default)]
struct ShutdownInner {
  triggered: AtomicBool,
  wakers: Mutex<Vec<Waker>>,
}

impl ShutdownHandle {
  /// Begins the graceful shutdown of every worker (see the module documentation). Once is enough;
  /// later calls do nothing.
  #[inline]
  pub fn trigger(&self) {
    if self.inner.triggered.swap(true, Ordering::AcqRel) {
      return;
    }
    let wakers = self.inner.wakers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for waker in wakers.iter() {
      waker.wake_by_ref();
    }
  }

  /// If [`Self::trigger`] was called.
  #[inline]
  pub fn is_triggered(&self) -> bool {
    self.inner.triggered.load(Ordering::Acquire)
  }

  // Wakes `waker` once the shutdown is triggered; at once if it is.
  fn register(&self, waker: &Waker) {
    let mut wakers = self.inner.wakers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    wakers.push(waker.clone());
    drop(wakers);
    if self.is_triggered() {
      waker.wake_by_ref();
    }
  }
}

/// The callback of SIGUSR1 ([`Server::on_stats_signal`]).
type StatsCallback<C> = Arc<dyn Fn(&[WorkerStats<C>]) + Send + Sync>;

/// A multi-worker QUIC server of the application `A` on io_uring: see the
/// [module documentation](self).
pub struct Server<A>
where
  A: UringApp,
{
  on_stats: Option<StatsCallback<A::Counters>>,
  params: ServerParams,
  shutdown: ShutdownHandle,
  stats: Stats<A::Counters>,
  workers: u8,
  _app: PhantomData<fn() -> A>,
}

impl<A> core::fmt::Debug for Server<A>
where
  A: UringApp,
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Server").field("params", &self.params).field("workers", &self.workers).finish()
  }
}

impl<A> Server<A>
where
  A: UringApp + 'static,
{
  /// A server with `params`, not yet running.
  #[inline]
  #[must_use]
  pub fn new(params: ServerParams) -> Self {
    let workers = params.workers.unwrap_or_else(|| {
      let cpus = std::thread::available_parallelism().map_or(1, core::num::NonZeroUsize::get);
      u8::try_from(cpus).unwrap_or(u8::MAX)
    });
    let workers = workers.max(1);
    Self {
      on_stats: None,
      params,
      shutdown: ShutdownHandle::default(),
      stats: Stats::new(workers),
      workers,
      _app: PhantomData,
    }
  }

  /// The number of workers.
  #[inline]
  pub const fn workers(&self) -> u8 {
    self.workers
  }

  /// A handle that stops the server from any thread.
  #[inline]
  pub fn shutdown_handle(&self) -> ShutdownHandle {
    self.shutdown.clone()
  }

  /// The counters of the workers, which they update at each turn: valid before, during and
  /// after [`Self::run`].
  #[inline]
  pub fn stats(&self) -> Stats<A::Counters> {
    self.stats.clone()
  }

  /// With [`ServerParams::handle_signals`], what SIGUSR1 calls with the counters of every worker.
  #[inline]
  #[must_use]
  pub fn on_stats_signal(
    mut self,
    f: impl Fn(&[WorkerStats<A::Counters>]) + Send + Sync + 'static,
  ) -> Self {
    self.on_stats = Some(Arc::new(f));
    self
  }

  /// Runs the workers until they shut down (see the module documentation); each serves with `tls`
  /// and an application that `make_app` makes on its thread, given the index of the worker.
  ///
  /// # Errors
  ///
  /// The first error of a worker: its runtime, its socket or its endpoint could not be made (the
  /// others then stop too), or rimu-uring could not start a thread.
  pub fn run<F>(self, tls: Arc<dyn ServerSessionFactory>, make_app: F) -> io::Result<()>
  where
    F: Fn(u8) -> A + Sync,
  {
    let Self { on_stats, params, shutdown, stats, workers, .. } = self;
    let mut rng = ChaCha20::from_os().map_err(to_io)?;
    // Once per process: the keys of the stateless packets and the loads of the workers; the
    // generator of each endpoint is derived from the one of the process
    let keys = Arc::new(EndpointKeys::new(&mut rng));
    let loads = Arc::new(WorkerLoads::new(workers));
    let startup = Startup::new(workers);
    let rng = Mutex::new(rng);
    let cores = match &params.pin {
      Pinning::None => Vec::new(),
      Pinning::Auto => affinity::cpu_order().unwrap_or_default(),
      Pinning::Cores(cores) => cores.clone(),
    };
    let mut udp = params.udp.reuseport(true);
    if workers > 1 && udp.inbox_slots == 0 {
      udp = udp.inbox(256, 2048);
    }
    let watcher = if params.handle_signals {
      let stats = stats.clone();
      let on_stats = on_stats.clone();
      Some(signals::Watcher::start(shutdown.clone(), move || {
        if let Some(f) = &on_stats {
          f(&stats.workers());
        }
      })?)
    } else {
      None
    };
    let epoch = std::time::Instant::now();
    let shared = worker::Shared {
      epoch,
      keys,
      loads,
      params: &params,
      rng: &rng,
      shutdown: &shutdown,
      startup: &startup,
      stats: &stats,
      tls: &tls,
      udp,
      workers,
    };
    let builder = Builder::new()
      .threads(usize::from(workers))
      .params(params.runtime)
      .name("rimu-quic")
      .pin_to(cores);
    let outputs = builder.run(|idx| {
      let worker = u8::try_from(idx).unwrap_or(u8::MAX);
      let shared = &shared;
      let make_app = &make_app;
      async move {
        let rslt = worker::run(shared, worker, make_app).await;
        if rslt.is_err() {
          // The others stop too: those still starting at once, the others gracefully
          shared.startup.fail();
          shared.shutdown.trigger();
        }
        rslt
      }
    });
    drop(watcher);
    let mut first = None;
    for rslt in outputs? {
      if let Err(err) = rslt {
        let _ = first.get_or_insert(err);
      }
    }
    first.map_or(Ok(()), Err)
  }
}

/// What the workers of a server share while they start: whose turn it is to bind, the port of the
/// first socket, the inboxes, and whether steering is on.
#[derive(Debug)]
struct Startup {
  failed: AtomicBool,
  inboxes: Mutex<Vec<Option<UdpInbox>>>,
  port: core::sync::atomic::AtomicU16,
  steering: AtomicBool,
  // The workers that bound
  turn: core::sync::atomic::AtomicUsize,
}

impl Startup {
  fn new(workers: u8) -> Self {
    Self {
      failed: AtomicBool::new(false),
      inboxes: Mutex::new((0..workers).map(|_| None).collect()),
      port: core::sync::atomic::AtomicU16::new(0),
      steering: AtomicBool::new(false),
      turn: core::sync::atomic::AtomicUsize::new(0),
    }
  }

  // A worker failed: the others stop waiting for it.
  fn fail(&self) {
    self.failed.store(true, Ordering::Release);
  }

  // Waits until `turn` workers bound; `false` if a worker failed meanwhile.
  fn wait_turn(&self, turn: usize) -> bool {
    while self.turn.load(Ordering::Acquire) < turn {
      if self.failed.load(Ordering::Acquire) {
        return false;
      }
      std::thread::sleep(Duration::from_micros(100));
    }
    true
  }
}

// Binds the socket of worker `worker` of `workers` once the workers before it did, then gives the
// turn to the next one; the last one decides, with `steer`, if steering is on. Returns once every
// worker bound, with the inboxes of all of them; `Ok(None)` if another worker failed meanwhile.
fn bind_in_order(
  startup: &Startup,
  addr: SocketAddr,
  udp: &UdpParams,
  (worker, workers): (u8, u8),
  steer: &dyn Fn(&UdpSocket) -> bool,
) -> io::Result<Option<(UdpSocket, Vec<UdpInbox>, bool)>> {
  let idx = usize::from(worker);
  if !startup.wait_turn(idx) {
    return Ok(None);
  }
  let mut addr = addr;
  // The workers after the first take the port that it was given, for an address of port 0
  if addr.port() == 0 && worker > 0 {
    addr.set_port(startup.port.load(Ordering::Acquire));
  }
  let socket = UdpSocket::bind(addr, udp).inspect_err(|_err| startup.fail())?;
  if worker == 0 {
    startup.port.store(socket.local_addr().port(), Ordering::Release);
  }
  if let Some(elem) =
    startup.inboxes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get_mut(idx)
  {
    *elem = socket.inbox();
  }
  if worker.wrapping_add(1) == workers {
    startup.steering.store(steer(&socket), Ordering::Release);
  }
  let _ = startup.turn.fetch_add(1, Ordering::AcqRel);
  if !startup.wait_turn(usize::from(workers)) {
    return Ok(None);
  }
  let inboxes: Vec<UdpInbox> = startup
    .inboxes
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
    .iter()
    .flatten()
    .cloned()
    .collect();
  Ok(Some((socket, inboxes, startup.steering.load(Ordering::Acquire))))
}

/// Hands `datagram`, which the endpoint returned for `worker`, to the inbox of that worker: a
/// datagram that the kernel coalesced segment by segment, so that each fits a slot of the inbox. A
/// segment that the inbox does not take (full, too long, its socket gone), or that has no worker,
/// is dropped, and the endpoint gives back the place that it took on that worker. Returns the
/// segments dropped.
fn forward<A>(
  endpoint: &mut Endpoint<A>,
  inboxes: &[UdpInbox],
  datagram: &[u8],
  meta: rimu_uring::net::RecvMeta,
  (worker, tag): (u8, u64),
) -> u64
where
  A: QuicApp,
{
  let inbox = inboxes.get(usize::from(worker));
  let push = |chunk: &[u8], meta| inbox.is_some_and(|el| el.push(chunk, meta, tag).is_ok());
  let segment = meta.segment_size.map_or(datagram.len(), usize::from).max(1);
  if datagram.len() <= segment {
    if push(datagram, meta) {
      return 0;
    }
    core::hint::cold_path();
    endpoint.forward_dropped(datagram, worker);
    return 1;
  }
  let meta = rimu_uring::net::RecvMeta::new(meta.peer, meta.local, None);
  let mut dropped = 0;
  for (nth, chunk) in datagram.chunks(segment).enumerate() {
    if nth > 0 {
      endpoint.forward_segment(chunk, worker);
    }
    if !push(chunk, meta) {
      core::hint::cold_path();
      endpoint.forward_dropped(chunk, worker);
      dropped += 1;
    }
  }
  dropped
}

fn to_io(err: crate::Error) -> io::Error {
  io::Error::other(alloc::format!("{err:?}"))
}
