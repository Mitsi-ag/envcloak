//! Signals while the child runs, and after (SPEC §6.1 step 8).
//!
//! - With a controlling terminal, the child stays in this process's group:
//!   the terminal sends its SIGINT and SIGQUIT (Ctrl-C, Ctrl-\) to both,
//!   and this process, which catches them, stays to redact what the child
//!   prints on its way out. SIGTERM and SIGHUP, which are sent to this
//!   process alone, are passed on to the child, and so are a SIGINT or
//!   SIGQUIT that a process sent to this one (`kill`, `timeout
//!   --foreground -s INT`, a harness's `send_signal`): the terminal did not
//!   send those to the child (review T12-1). Which process sent a signal
//!   is what [`envcloak_sys::Relayed`] says: exactly on Linux, and on macOS
//!   for a sender in this session or already gone (see
//!   `envcloak_sys::SignalRelay`).
//! - Without one, the child leads a group of its own, so a signal meant
//!   for this process does not reach it by itself: SIGINT, SIGTERM, SIGHUP
//!   and SIGQUIT are passed on to the child's whole group.
//!
//! The four signals are caught (never ignored, since `exec` would pass an
//! ignored disposition on to the child) from before the child starts until
//! the run returns. A signal is passed on only while the child has not
//! exited: [`ChildState`] is updated after `waitid` sees the exit and
//! before the child is reaped, so its pid, and the group it leads, can
//! never belong to another process when a signal is sent.
//!
//! Once the exit is seen ([`Forwarder::child_exited`] puts a mark among the
//! caught signals), there is nobody to pass a signal on to, and the output
//! may still be waiting for a descendant or a reader: a signal caught
//! after the mark stops the run at once ([`Cutoff::stop_now`]), and the run
//! ends as the signal asks, with 128 plus its number (review T12-2).

use std::io;
use std::sync::Mutex;

use envcloak_sys::{Relayed, SignalRelay};

use crate::pump::Cutoff;

/// The signals the runner catches.
pub(crate) const CAUGHT: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Whether this process has a controlling terminal: `/dev/tty` opens only
/// then.
pub(crate) fn controlling_terminal() -> bool {
    std::fs::File::open("/dev/tty").is_ok()
}

/// Whether, with a controlling terminal, a caught signal is passed on to
/// the child: SIGTERM and SIGHUP always, SIGINT and SIGQUIT only when a
/// process sent them, since the terminal sends its own to the child too.
pub(crate) fn passed_on_with_terminal(sig: i32, by_process: bool) -> bool {
    match sig {
        libc::SIGTERM | libc::SIGHUP => true,
        libc::SIGINT | libc::SIGQUIT => by_process,
        _ => false,
    }
}

/// The child's pid while it may be signalled.
#[derive(Debug)]
pub(crate) struct ChildState {
    pid: Mutex<Option<i32>>,
}

impl ChildState {
    pub(crate) fn running(pid: i32) -> Self {
        ChildState {
            pid: Mutex::new(Some(pid)),
        }
    }

    /// The child has exited and is not reaped yet: no more signals.
    pub(crate) fn exited(&self) {
        *self.pid.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The caught signals, and whether the child shares this process's
/// terminal.
#[derive(Debug)]
pub(crate) struct Forwarder {
    relay: SignalRelay,
    terminal: bool,
}

impl Forwarder {
    pub(crate) fn install(terminal: bool) -> io::Result<Self> {
        Ok(Forwarder {
            relay: SignalRelay::install(&CAUGHT)?,
            terminal,
        })
    }

    /// Passes signals on until [`Forwarder::stop`], and stops the run
    /// (`cutoff`) for one caught after [`Forwarder::child_exited`]. Run on
    /// its own thread.
    pub(crate) fn forward(&self, child: &ChildState, cutoff: &Cutoff) {
        let mut exited = false;
        while let Ok(Some(caught)) = self.relay.next() {
            let (sig, by_process) = match caught {
                Relayed::Mark => {
                    exited = true;
                    continue;
                }
                Relayed::Signal { number, by_process } => (number, by_process),
            };
            if exited {
                cutoff.stop_now(sig);
                continue;
            }
            let pid = child.pid.lock().unwrap_or_else(|e| e.into_inner());
            let Some(pid) = *pid else { continue };
            // A child that is gone by now, or a group already empty, is
            // not an error: there is nothing left to tell.
            let _ = if !self.terminal {
                envcloak_sys::signal_group(pid, sig)
            } else if passed_on_with_terminal(sig, by_process) {
                envcloak_sys::signal_process(pid, sig)
            } else {
                Ok(())
            };
        }
    }

    /// Marks where the child's exit was seen: a signal caught after this
    /// stops the run rather than being passed on, and one caught before it
    /// is passed on while the child is not marked exited. Called before
    /// [`ChildState::exited`], so a signal caught between the two stops the
    /// run instead of being dropped.
    pub(crate) fn child_exited(&self) {
        let _ = self.relay.mark();
    }

    /// Ends [`Forwarder::forward`].
    pub(crate) fn stop(&self) {
        let _ = self.relay.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With a terminal: SIGTERM and SIGHUP are passed on whoever sent
    /// them; SIGINT and SIGQUIT only when a process sent them, never the
    /// terminal's own (which reached the child already).
    #[test]
    fn with_a_terminal_only_what_the_terminal_did_not_send_the_child_is_passed_on() {
        for (sig, by_process, passed) in [
            (libc::SIGTERM, true, true),
            (libc::SIGTERM, false, true),
            (libc::SIGHUP, true, true),
            (libc::SIGHUP, false, true),
            (libc::SIGINT, true, true),
            (libc::SIGINT, false, false),
            (libc::SIGQUIT, true, true),
            (libc::SIGQUIT, false, false),
            (libc::SIGUSR1, true, false),
        ] {
            assert_eq!(
                passed_on_with_terminal(sig, by_process),
                passed,
                "{sig} {by_process}"
            );
        }
    }
}
