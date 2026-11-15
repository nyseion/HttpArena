//! SIGINT, SIGTERM and SIGUSR1 for a server ([`super::ServerParams::handle_signals`]): blocked on
//! the thread that runs the server, and so on the workers that it starts, which inherit its mask,
//! and taken with `sigwait` by a thread of their own.

#![allow(unsafe_code, reason = "the signal mask and sigwait through libc")]

use super::ShutdownHandle;
use std::{
  io,
  os::unix::thread::JoinHandleExt as _,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  thread::JoinHandle,
};

/// The thread that takes the signals; dropping it ends the thread and restores the signal mask of
/// the thread that started it.
pub(crate) struct Watcher {
  old_mask: libc::sigset_t,
  stopped: Arc<AtomicBool>,
  thread: Option<JoinHandle<()>>,
}

impl Watcher {
  /// Blocks the signals on this thread and starts the thread that takes them: the first SIGINT or
  /// SIGTERM triggers `shutdown`, the second ends the process; SIGUSR1 calls `on_usr1`.
  pub(crate) fn start(
    shutdown: ShutdownHandle,
    on_usr1: impl Fn() + Send + 'static,
  ) -> io::Result<Self> {
    let set = signal_set();
    // SAFETY: a `sigset_t` is plain data, valid when all zeroes, and is filled by the call
    let mut old_mask: libc::sigset_t = unsafe { core::mem::zeroed() };
    // SAFETY: `set` and `old_mask` are valid for the call, which reads one and writes the other
    let rslt = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut old_mask) };
    if rslt != 0 {
      return Err(io::Error::from_raw_os_error(rslt));
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let thread_stopped = stopped.clone();
    let thread = std::thread::Builder::new().name("rimu-quic-signals".into()).spawn(move || {
      let mut terms = 0u32;
      loop {
        let mut signal: libc::c_int = 0;
        // SAFETY: `set` and `signal` are valid for the call, which waits for one of the signals
        // of `set`, all blocked on this thread (inherited from the thread that started it)
        let rslt = unsafe { libc::sigwait(&raw const set, &raw mut signal) };
        if thread_stopped.load(Ordering::Acquire) {
          return;
        }
        if rslt != 0 {
          continue;
        }
        match signal {
          libc::SIGUSR1 => on_usr1(),
          libc::SIGINT | libc::SIGTERM => {
            terms = terms.wrapping_add(1);
            if terms == 1 {
              shutdown.trigger();
            } else {
              std::process::exit(128 + signal);
            }
          }
          _ => {}
        }
      }
    });
    match thread {
      Ok(thread) => Ok(Self { old_mask, stopped, thread: Some(thread) }),
      Err(err) => {
        restore(&old_mask);
        Err(err)
      }
    }
  }
}

impl Drop for Watcher {
  fn drop(&mut self) {
    self.stopped.store(true, Ordering::Release);
    if let Some(thread) = self.thread.take() {
      // SAFETY: the thread is alive until joined below, and SIGUSR1 is blocked on it, so the
      // signal ends its `sigwait`, after which it sees `stopped` and returns
      let _rslt = unsafe { libc::pthread_kill(thread.as_pthread_t(), libc::SIGUSR1) };
      let _rslt = thread.join();
    }
    restore(&self.old_mask);
  }
}

fn restore(mask: &libc::sigset_t) {
  // SAFETY: `mask` is a valid signal set for the call, which only reads it
  let _rslt = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, mask, core::ptr::null_mut()) };
}

fn signal_set() -> libc::sigset_t {
  // SAFETY: a `sigset_t` is plain data, valid when all zeroes, and `sigemptyset` initializes it
  let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
  // SAFETY: `set` is valid for these calls, which write it, with signals that exist
  unsafe {
    libc::sigemptyset(&raw mut set);
    libc::sigaddset(&raw mut set, libc::SIGINT);
    libc::sigaddset(&raw mut set, libc::SIGTERM);
    libc::sigaddset(&raw mut set, libc::SIGUSR1);
  }
  set
}
