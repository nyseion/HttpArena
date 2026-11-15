//! The task of a worker: its socket, its endpoint and its application, driven in turns on the
//! runtime of its thread (see the documentation of the `uring` module).

use super::{ServerParams, ShutdownHandle, Startup, Stats, UringApp, WorkerStats};
use crate::{
  DatagramMeta, Endpoint, EndpointKeys, FlushOutcome, QuicLimits, RecvOutcome, TxArena,
  WorkerLoads, rng::ChaCha20, steering_cbpf, tls::ServerSessionFactory,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
  future::{Future as _, poll_fn},
  hint::cold_path,
  pin::{Pin, pin},
  task::{Context, Poll},
  time::Duration,
};
use rimu_uring::{
  net::{UdpInbox, UdpParams, UdpSocket},
  time::{Sleep, sleep},
};
use std::{io, sync::Mutex, time::Instant};

/// What every worker of a server is given.
pub(crate) struct Shared<'any, C> {
  /// The clock of the process, which every worker reads its time from.
  pub(crate) epoch: Instant,
  pub(crate) keys: Arc<EndpointKeys>,
  pub(crate) loads: Arc<WorkerLoads>,
  pub(crate) params: &'any ServerParams,
  /// The generator of the process, which the generator of each endpoint is derived from.
  pub(crate) rng: &'any Mutex<ChaCha20>,
  pub(crate) shutdown: &'any ShutdownHandle,
  pub(crate) startup: &'any Startup,
  pub(crate) stats: &'any Stats<C>,
  pub(crate) tls: &'any Arc<dyn ServerSessionFactory>,
  pub(crate) udp: UdpParams,
  pub(crate) workers: u8,
}

/// Runs worker `worker` until its server shut down.
pub(crate) async fn run<A, F>(
  shared: &Shared<'_, A::Counters>,
  worker: u8,
  make_app: &F,
) -> io::Result<()>
where
  A: UringApp,
  F: Fn(u8) -> A,
{
  let Shared { epoch, keys, loads, params, rng, shutdown, startup, stats, tls, udp, workers } =
    shared;
  let quic = params.quic;
  let workers = *workers;
  // The last worker steers the group, whose sockets all bound: a single worker has none to steer
  let steer = |socket: &UdpSocket| {
    if !quic.cid_steering() || workers <= 1 {
      return quic.cid_steering();
    }
    socket.attach_reuseport_cbpf(&steering_cbpf(workers)).is_ok()
  };
  let Some((socket, inboxes, steering)) =
    super::bind_in_order(startup, params.addr, udp, (worker, workers), &steer)?
  else {
    // Another worker failed to start, and reports why
    return Ok(());
  };
  let mut quic = if steering { quic } else { quic.set_cid_steering(false).set_balance(false) };
  let grace_ms = u64::try_from(params.drain.as_millis()).unwrap_or(u64::MAX);
  quic = quic.set_limits(QuicLimits { shutdown_grace_ms: grace_ms, ..*quic.limits() });
  let endpoint = {
    let mut rng = rng.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Endpoint::<A>::new(
      quic,
      worker,
      workers,
      (*tls).clone(),
      &mut *rng,
      Some(loads.clone()),
      keys.clone(),
    )
    .map_err(super::to_io)?
  };
  let tx = TxArena::new(params.tx_arena_bytes).map_err(super::to_io)?;
  let linger = params.drain.saturating_add(params.linger);
  let mut task = Task {
    app: make_app(worker),
    endpoint,
    epoch: *epoch,
    idle_since_us: None,
    idle_trim_us: u64::try_from(params.idle_trim_after.as_micros()).unwrap_or(u64::MAX),
    inboxes,
    linger_us: u64::try_from(linger.as_micros()).unwrap_or(u64::MAX),
    shutdown,
    shutdown_registered: false,
    shutdown_since_us: None,
    sleep: None,
    socket,
    stats,
    submit_errors: 0,
    tally: WorkerStats { cid_steering: steering, ..WorkerStats::default() },
    trimmed: false,
    tx,
    worker,
  };
  poll_fn(|cx| task.turn(cx)).await;
  let Task { app, endpoint, .. } = &mut task;
  endpoint.abort_all(app);
  task.store_stats(true);
  Ok(())
}

/// The state of the task of a worker.
struct Task<'any, A>
where
  A: UringApp,
{
  app: A,
  endpoint: Endpoint<A>,
  epoch: Instant,
  // Since when the worker has had no connection
  idle_since_us: Option<u64>,
  idle_trim_us: u64,
  inboxes: Vec<UdpInbox>,
  // How long a worker that shuts down waits for its connections
  linger_us: u64,
  shutdown: &'any ShutdownHandle,
  shutdown_registered: bool,
  // Since when the endpoint shuts down
  shutdown_since_us: Option<u64>,
  // The timer of the ring, and the time that it was armed for
  sleep: Option<(Sleep, u64)>,
  socket: UdpSocket,
  stats: &'any Stats<A::Counters>,
  // Sends that the socket refused at once
  submit_errors: u64,
  // The counters of the driver, which the turns add to
  tally: WorkerStats<A::Counters>,
  // The pools were trimmed since the worker was last busy
  trimmed: bool,
  tx: TxArena,
  worker: u8,
}

impl<A> Task<'_, A>
where
  A: UringApp,
{
  // The microseconds since the clock of the process started.
  fn now_us(&self) -> u64 {
    u64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(u64::MAX)
  }

  // One turn: see the documentation of the `uring` module. Ready once the worker is done.
  fn turn(&mut self, cx: &mut Context<'_>) -> Poll<()> {
    let now_us = self.now_us();
    self.tally.turns = self.tally.turns.wrapping_add(1);
    if !self.shutdown_registered {
      self.shutdown_registered = true;
      self.shutdown.register(cx.waker());
    }
    self.app.start_turn(now_us);
    self.receive(cx, now_us);
    self.app.resume(&mut self.endpoint, now_us, cx.waker());
    if self.endpoint.next_deadline().is_some_and(|el| el <= now_us) {
      self.endpoint.on_timeout(now_us, &mut self.app);
    }
    if self.shutdown_since_us.is_none() && self.shutdown.is_triggered() {
      cold_path();
      self.endpoint.begin_shutdown(now_us, &mut self.app);
      self.shutdown_since_us = Some(now_us);
    }
    self.flush(cx, now_us);
    self.idle(now_us);
    self.store_stats(false);
    if let Some(since) = self.shutdown_since_us
      && (self.endpoint.stats().conns == 0 || now_us.saturating_sub(since) >= self.linger_us)
    {
      return Poll::Ready(());
    }
    self.arm(cx, now_us);
    Poll::Pending
  }

  // Arms the timer of the ring for the next deadline, unless it is armed for an earlier one, which
  // then fires early and arms it again.
  fn arm(&mut self, cx: &mut Context<'_>, now_us: u64) {
    let idle =
      self.idle_since_us.filter(|_| !self.trimmed).map(|el| el.saturating_add(self.idle_trim_us));
    let shutdown = self.shutdown_since_us.map(|el| el.saturating_add(self.linger_us));
    let Some(deadline) =
      self.endpoint.next_deadline().into_iter().chain(idle).chain(shutdown).min()
    else {
      self.sleep = None;
      return;
    };
    if deadline <= now_us {
      cx.waker().wake_by_ref();
      return;
    }
    // A timer armed for later than now and not later than the deadline stays: it fires early, if
    // at all, and is armed again then. One that is due is replaced.
    if let Some((sleep, at)) = &mut self.sleep
      && *at > now_us
      && *at <= deadline
    {
      if Pin::new(sleep).poll(cx).is_ready() {
        self.sleep = None;
        cx.waker().wake_by_ref();
      }
      return;
    }
    let mut timer = sleep(Duration::from_micros(deadline.wrapping_sub(now_us)));
    if Pin::new(&mut timer).poll(cx).is_ready() {
      self.sleep = None;
      cx.waker().wake_by_ref();
      return;
    }
    self.sleep = Some((timer, deadline));
  }

  // Flushes the connections into the arena and sends its trains; a full arena is flushed again
  // once its trains are out, unless every send slot is busy.
  fn flush(&mut self, cx: &mut Context<'_>, now_us: u64) {
    loop {
      let outcome = self.endpoint.flush(now_us, &mut self.tx, &mut self.app);
      let (sent, all) = self.send(cx);
      if outcome == FlushOutcome::Done || !all || sent == 0 {
        return;
      }
    }
  }

  // Sends the pending trains of the arena, each copied into a send slot of the socket, and gives
  // their space back. Returns the trains sent and whether none is left; with every send slot busy
  // the rest waits for the turn that a free slot wakes.
  fn send(&mut self, cx: &mut Context<'_>) -> (usize, bool) {
    let Self { socket, submit_errors, tally, tx, .. } = self;
    let mut sent = 0usize;
    loop {
      let Some(train) = tx.pending().next() else {
        return (sent, true);
      };
      let id = train.id;
      let segment = train.segment_size.max(1);
      let rslt =
        socket.send_train_with(train.bytes.len(), segment, train.peer, train.local, |dst| {
          dst.copy_from_slice(train.bytes);
        });
      match rslt {
        Ok(true) => tally.trains_out = tally.trains_out.wrapping_add(1),
        Ok(false) => {
          // Every slot is busy: the waker of the turn is woken once one frees up
          tally.send_slot_waits = tally.send_slot_waits.wrapping_add(1);
          let mut writable = pin!(socket.writable());
          if writable.as_mut().poll(cx).is_pending() {
            return (sent, false);
          }
          continue;
        }
        Err(_err) => {
          cold_path();
          *submit_errors = submit_errors.wrapping_add(1);
        }
      }
      tx.mark_submitted(id);
      tx.release(id);
      sent = sent.wrapping_add(1);
    }
  }

  // The pools are trimmed once the worker has had no connection for a while.
  fn idle(&mut self, now_us: u64) {
    if self.endpoint.stats().conns != 0 {
      self.idle_since_us = None;
      self.trimmed = false;
      return;
    }
    let since = *self.idle_since_us.get_or_insert(now_us);
    if self.trimmed || now_us.saturating_sub(since) < self.idle_trim_us {
      return;
    }
    self.endpoint.trim_idle();
    self.app.trim_idle();
    self.trimmed = true;
    self.tally.idle_trims = self.tally.idle_trims.wrapping_add(1);
  }

  // The datagrams of the socket, then those of the inbox.
  fn receive(&mut self, cx: &mut Context<'_>, now_us: u64) {
    let Self { app, endpoint, inboxes, socket, tally, .. } = self;
    let rslt = socket.poll_recv(cx, &mut |datagram, meta| {
      let quic_meta =
        DatagramMeta { peer: meta.peer, local: meta.local, segment_size: meta.segment_size };
      if let RecvOutcome::Forward { worker: to } = endpoint.recv(now_us, datagram, quic_meta, app) {
        let dropped = super::forward(endpoint, inboxes, datagram, meta, (to, now_us));
        tally.forward_dropped = tally.forward_dropped.wrapping_add(dropped);
      }
    });
    if let Poll::Ready(Err(_err)) = rslt {
      cold_path();
      tally.recv_errors = tally.recv_errors.wrapping_add(1);
    }
    if !inboxes.is_empty() {
      let _rslt = socket.poll_forwarded(cx, &mut |datagram, meta, _tag| {
        let quic_meta =
          DatagramMeta { peer: meta.peer, local: meta.local, segment_size: meta.segment_size };
        endpoint.recv_forwarded(now_us, datagram, quic_meta, app);
      });
    }
  }

  // Stores the counters of the worker for the readers of the stats of the server.
  fn store_stats(&mut self, last: bool) {
    let udp = self.socket.stats();
    let tally = &mut self.tally;
    tally.endpoint = self.endpoint.stats();
    tally.recv_buffers_exhausted = udp.recv_buffers_exhausted;
    tally.datagrams_truncated = udp.datagrams_truncated;
    tally.forwarded_in = udp.forwarded_in;
    tally.zc_sends = udp.zc_sends;
    tally.zc_copied = udp.zc_copied;
    tally.zc_fallbacks = udp.zc_fallbacks;
    // The refusals at submission and the failures that the kernel reports at completion
    tally.udp_send_errors = self.submit_errors.wrapping_add(udp.send_errors);
    tally.app = self.app.counters();
    if last {
      self.stats.store_last(self.worker, tally);
    } else {
      self.stats.store(self.worker, tally);
    }
  }
}
