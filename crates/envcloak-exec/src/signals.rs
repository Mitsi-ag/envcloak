//! Signals while the child runs (SPEC §6.1 step 8).
//!
//! - With a controlling terminal, the child stays in this process's group:
//!   the terminal sends its SIGINT and SIGQUIT (Ctrl-C, Ctrl-\) to both,
//!   and this process, which catches them, stays to redact what the child
//!   prints on its way out. SIGTERM and SIGHUP, which are sent to this
//!   process alone, are passed on to the child.
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

use std::io;
use std::sync::Mutex;

use envcloak_sys::SignalRelay;

/// The signals the runner catches.
pub(crate) const CAUGHT: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Whether this process has a controlling terminal: `/dev/tty` opens only
/// then.
pub(crate) fn controlling_terminal() -> bool {
    std::fs::File::open("/dev/tty").is_ok()
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

    /// Passes signals on until [`Forwarder::stop`]. Run on its own thread.
    pub(crate) fn forward(&self, child: &ChildState) {
        while let Ok(Some(sig)) = self.relay.next() {
            let pid = child.pid.lock().unwrap_or_else(|e| e.into_inner());
            let Some(pid) = *pid else { continue };
            // A child that is gone by now, or a group already empty, is
            // not an error: there is nothing left to tell.
            let _ = if self.terminal {
                // The terminal sent SIGINT and SIGQUIT to the child itself.
                if sig == libc::SIGTERM || sig == libc::SIGHUP {
                    envcloak_sys::signal_process(pid, sig)
                } else {
                    Ok(())
                }
            } else {
                envcloak_sys::signal_group(pid, sig)
            };
        }
    }

    /// Ends [`Forwarder::forward`].
    pub(crate) fn stop(&self) {
        let _ = self.relay.stop();
    }
}
