//! The counters of the workers of a [`super::Server`].

use crate::EndpointStats;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

/// The counters of an application, stored with those of its worker ([`super::UringApp::counters`]).
pub trait AppCounters: Clone + Copy + Default + Send + 'static {
  /// Calls `f` with the name and the value of every counter.
  #[inline]
  fn for_each(&self, f: &mut dyn FnMut(&'static str, u64)) {
    let _f = f;
  }
}

impl AppCounters for () {}

/// What a worker counted, as it stored it at the end of its last turn.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct WorkerStats<C> {
  /// The counters of the endpoint.
  pub endpoint: EndpointStats,
  /// If the datagrams of the worker are steered by connection ID, or reach it by the hash of the
  /// kernel (an attach of the steering program that failed, or CID steering off).
  pub cid_steering: bool,
  /// Turns of the worker.
  pub turns: u64,
  /// Sends of trains of datagrams (one `UDP_SEGMENT` send each).
  pub trains_out: u64,
  /// Sends that failed (their packets count as lost).
  pub udp_send_errors: u64,
  /// Times a flush waited for a free send slot.
  pub send_slot_waits: u64,
  /// Receives that failed.
  pub recv_errors: u64,
  /// Times the multishot receive of the socket ran out of buffers.
  pub recv_buffers_exhausted: u64,
  /// Datagrams longer than a receive buffer, dropped.
  pub datagrams_truncated: u64,
  /// Datagrams that other workers forwarded to this one, taken from its inbox.
  pub forwarded_in: u64,
  /// Segments for another worker that its inbox did not take, dropped.
  pub forward_dropped: u64,
  /// Of [`Self::trains_out`], those sent zero-copy.
  pub zc_sends: u64,
  /// Zero-copy sends that the kernel copied after all.
  pub zc_copied: u64,
  /// Times zero-copy was turned off for the socket.
  pub zc_fallbacks: u64,
  /// Times the pools of the worker were trimmed after it had no connection for a while.
  pub idle_trims: u64,
  /// The counters of the application.
  pub app: C,
}

impl<C> WorkerStats<C>
where
  C: AppCounters,
{
  /// Calls `f` with the name and the value of every counter, those of the application last.
  #[inline]
  pub fn for_each(&self, f: &mut dyn FnMut(&'static str, u64)) {
    let e = &self.endpoint;
    for (name, value) in [
      ("conns", u64::from(e.conns)),
      ("half_open", u64::from(e.half_open)),
      ("datagrams_in", e.datagrams_in),
      ("datagrams_out", e.datagrams_out),
      ("packets_out", e.packets_out),
      ("ack_only_out", e.ack_only_out),
      ("fins_out", e.fins_out),
      ("fin_flushes", e.fin_flushes),
      ("fin_flushes_acked", e.fin_flushes_acked),
      ("fin_flushes_ack_owed", e.fin_flushes_ack_owed),
      ("fin_flushes_owed_and_acked", e.fin_flushes_owed_and_acked),
      ("bytes_out", e.bytes_out),
      ("stream_bytes_out", e.stream_bytes_out),
      ("stream_bytes_copied", e.stream_bytes_copied),
      ("pacer_holds", e.pacer_holds),
      ("data_blocked_in", e.data_blocked_in),
      ("stream_data_blocked_in", e.stream_data_blocked_in),
      ("streams_blocked_in", e.streams_blocked_in),
      ("packets_lost", e.packets_lost),
      ("pto_probes", e.pto_probes),
      ("frames_resent", e.frames_resent),
      ("frames_resent_acked", e.frames_resent_acked),
      ("retries", e.retries),
      ("forwarded", e.forwarded),
      ("stateless_resets", e.resets),
      ("cid_steering", u64::from(self.cid_steering)),
      ("turns", self.turns),
      ("trains_out", self.trains_out),
      ("udp_send_errors", self.udp_send_errors),
      ("send_slot_waits", self.send_slot_waits),
      ("recv_errors", self.recv_errors),
      ("recv_buffers_exhausted", self.recv_buffers_exhausted),
      ("datagrams_truncated", self.datagrams_truncated),
      ("forwarded_in", self.forwarded_in),
      ("forward_dropped", self.forward_dropped),
      ("zc_sends", self.zc_sends),
      ("zc_copied", self.zc_copied),
      ("zc_fallbacks", self.zc_fallbacks),
      ("idle_trims", self.idle_trims),
    ] {
      f(name, value);
    }
    self.app.for_each(f);
  }
}

/// The counters of the workers of a server, updated by each worker at the end of its turns and
/// read from any thread. Clones share them.
#[derive(Clone, Debug)]
pub struct Stats<C> {
  cells: Arc<[Mutex<WorkerStats<C>>]>,
}

impl<C> Stats<C>
where
  C: AppCounters,
{
  pub(crate) fn new(workers: u8) -> Self {
    Self { cells: (0..workers).map(|_| Mutex::new(WorkerStats::default())).collect() }
  }

  /// The counters of each worker, by index.
  #[inline]
  pub fn workers(&self) -> Vec<WorkerStats<C>> {
    self.cells.iter().map(|el| *el.lock().unwrap_or_else(PoisonError::into_inner)).collect()
  }

  /// `name=value` for every counter, summed over `workers`, separated by spaces: the line that
  /// a server prints on SIGUSR1, say.
  #[inline]
  pub fn line(workers: &[WorkerStats<C>]) -> String {
    let mut sums: Vec<(&'static str, u64)> = Vec::new();
    for (nth, stats) in workers.iter().enumerate() {
      let mut idx = 0usize;
      stats.for_each(&mut |name, value| {
        if nth == 0 {
          sums.push((name, value));
        } else if let Some(elem) = sums.get_mut(idx) {
          elem.1 = elem.1.wrapping_add(value);
        }
        idx = idx.wrapping_add(1);
      });
    }
    let mut rslt = String::new();
    for (name, value) in sums {
      if !rslt.is_empty() {
        rslt.push(' ');
      }
      let _ = write!(rslt, "{name}={value}");
    }
    rslt
  }

  // Stores the counters of `worker`, unless a reader holds them now (the next turn does).
  pub(crate) fn store(&self, worker: u8, stats: &WorkerStats<C>) {
    if let Some(cell) = self.cells.get(usize::from(worker))
      && let Ok(mut guard) = cell.try_lock()
    {
      *guard = *stats;
    }
  }

  // Stores the counters of `worker`, waiting for a reader: the last store of a worker.
  pub(crate) fn store_last(&self, worker: u8, stats: &WorkerStats<C>) {
    if let Some(cell) = self.cells.get(usize::from(worker)) {
      *cell.lock().unwrap_or_else(PoisonError::into_inner) = *stats;
    }
  }
}
