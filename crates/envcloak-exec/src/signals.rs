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
//! the run returns, and unblocked on the thread that installs the relay:
//! a mask inherited through `exec` could block them (review R-8). A signal
//! is passed on only while the child has not exited: [`ChildState`] is
//! updated after `waitid` sees the exit and before the child is reaped, so
//! its pid, and the group it leads, can never belong to another process
//! when a signal is sent.
//!
//! Once the exit is seen ([`Forwarder::child_exited`] puts a mark among the
//! caught signals), there is nobody to pass a signal on to, and the output
//! may still be waiting for a descendant or a reader: a signal caught
//! after the mark stops the run at once ([`Cutoff::stop_now`]), and the run
//! ends as the signal asks, with 128 plus its number (review T12-2).
//!
//! The mark refines, and is not the only way to, that stop (review R-9). A
//! signal caught before the mark but read once the child has exited, which
//! would have been passed on, has nobody to go to either, and stops the
//! run too; only the terminal's own SIGINT or SIGQUIT, which reached the
//! child as well, is then left alone. When the mark cannot be written
//! (the relay's pipe full of signals not read yet), every signal read from
//! then on stops the run. A signal that itself finds the pipe full is kept
//! aside by the relay and read here like the others, on its side of the
//! mark (review F-71), so a SIGTERM behind a flood of another signal is
//! not lost.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// What [`Forwarder::forward`] does with a caught signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    /// Send it to the child, or (`group`) to the group the child leads.
    PassOn { pid: i32, group: bool },
    /// Stop the run: the child has exited, and the signal has nobody to
    /// go to.
    Stop,
    /// Nothing: the terminal sent it to the child as well.
    Nothing,
}

/// What to do with signal `sig` (sent by a process when `by_process`),
/// read after the mark of the child's exit when `after_exit`, while the
/// child's pid is `pid` (`None` once it has exited), with or without a
/// controlling `terminal`.
fn act(sig: i32, by_process: bool, terminal: bool, after_exit: bool, pid: Option<i32>) -> Act {
    if after_exit {
        return Act::Stop;
    }
    let passed = !terminal || passed_on_with_terminal(sig, by_process);
    match (pid, passed) {
        (Some(pid), true) => Act::PassOn {
            pid,
            group: !terminal,
        },
        // Caught before the mark, read after the exit: nobody to pass it
        // on to, so it stops the run as one caught after the mark does
        // (review R-9).
        (None, true) => Act::Stop,
        (_, false) => Act::Nothing,
    }
}

/// The caught signals, and whether the child shares this process's
/// terminal.
#[derive(Debug)]
pub(crate) struct Forwarder {
    relay: SignalRelay,
    terminal: bool,
    /// [`Forwarder::child_exited`] could not write its mark: every signal
    /// read from then on counts as caught after the exit.
    mark_lost: AtomicBool,
}

impl Forwarder {
    pub(crate) fn install(terminal: bool) -> io::Result<Self> {
        Ok(Forwarder {
            relay: SignalRelay::install(&CAUGHT)?,
            terminal,
            mark_lost: AtomicBool::new(false),
        })
    }

    /// Passes signals on until [`Forwarder::stop`], and stops the run
    /// (`cutoff`) for one caught after [`Forwarder::child_exited`], or read
    /// once the child has exited when it would have been passed on (see
    /// [`act`]). Run on its own thread.
    pub(crate) fn forward(&self, child: &ChildState, cutoff: &Cutoff) {
        let mut marked = false;
        while let Ok(Some(caught)) = self.relay.next() {
            let (sig, by_process) = match caught {
                Relayed::Mark => {
                    marked = true;
                    continue;
                }
                Relayed::Signal { number, by_process } => (number, by_process),
            };
            let after_exit = marked || self.mark_lost.load(Ordering::SeqCst);
            let pid = child.pid.lock().unwrap_or_else(|e| e.into_inner());
            match act(sig, by_process, self.terminal, after_exit, *pid) {
                // Sent under the lock `ChildState::exited` takes, so the
                // pid is still the child's. A child that is gone by now,
                // or a group already empty, is not an error: there is
                // nothing left to tell.
                Act::PassOn { pid, group: true } => {
                    let _ = envcloak_sys::signal_group(pid, sig);
                }
                Act::PassOn { pid, group: false } => {
                    let _ = envcloak_sys::signal_process(pid, sig);
                }
                Act::Stop => {
                    drop(pid);
                    cutoff.stop_now(sig);
                }
                Act::Nothing => {}
            }
        }
    }

    /// Marks where the child's exit was seen: a signal caught after this
    /// stops the run rather than being passed on. Called before
    /// [`ChildState::exited`], so a signal caught between the two stops the
    /// run instead of being passed to the exited child. When the mark
    /// cannot be written (the relay's pipe stayed full), every signal read
    /// from then on stops the run, so none caught after the exit is lost.
    pub(crate) fn child_exited(&self) {
        if self.relay.mark().is_err() {
            self.mark_lost.store(true, Ordering::SeqCst);
        }
    }

    /// Ends [`Forwarder::forward`]. While the relay's pipe is full (of
    /// signals the forwarding thread has not read yet) the stop cannot be
    /// written, and is tried again as long as `running` says that thread
    /// still runs: it makes the room. Once the thread has ended, or never
    /// started, nothing needs the stop.
    pub(crate) fn stop(&self, mut running: impl FnMut() -> bool) {
        while self.relay.stop().is_err() && running() {}
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    use super::*;

    /// The relay is process-wide, so the tests that install one take
    /// turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// Raises `sig` on this thread more times than a pipe holds bytes, so
    /// the relay's pipe is full after (the handler drops what does not
    /// fit).
    fn flood(sig: i32) {
        for _ in 0..1 << 17 {
            envcloak_sys::testing::signal_this_thread(sig).unwrap();
        }
    }

    /// A child state whose child has exited.
    fn exited() -> ChildState {
        ChildState {
            pid: Mutex::new(None),
        }
    }

    /// Review R-9: what the forwarder does with each signal. Before the
    /// mark with the child running: passed on (to its group without a
    /// terminal), except the terminal's own SIGINT and SIGQUIT. Before the
    /// mark with the child exited: a signal that would have been passed
    /// on stops the run, where it used to be dropped; the terminal's own
    /// is left alone. After the mark: every signal stops the run.
    #[test]
    fn a_signal_the_exited_child_cannot_get_stops_the_run() {
        let (term, int, quit, hup) = (libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP);
        let pass = |pid, group| Act::PassOn { pid, group };
        for (sig, by_process, terminal, after_exit, pid, want) in [
            // Running, no terminal: to the child's group, whoever sent it.
            (int, false, false, false, Some(7), pass(7, true)),
            (term, true, false, false, Some(7), pass(7, true)),
            // Running, on a terminal.
            (term, false, true, false, Some(7), pass(7, false)),
            (hup, false, true, false, Some(7), pass(7, false)),
            (int, true, true, false, Some(7), pass(7, false)),
            (int, false, true, false, Some(7), Act::Nothing),
            (quit, false, true, false, Some(7), Act::Nothing),
            // Exited, not marked yet: what would have been passed on stops.
            (term, true, false, false, None, Act::Stop),
            (int, false, false, false, None, Act::Stop),
            (term, false, true, false, None, Act::Stop),
            (quit, true, true, false, None, Act::Stop),
            (int, false, true, false, None, Act::Nothing),
            // After the mark, whatever the pid says.
            (int, false, true, true, None, Act::Stop),
            (int, false, true, true, Some(7), Act::Stop),
            (term, true, false, true, Some(7), Act::Stop),
        ] {
            assert_eq!(
                act(sig, by_process, terminal, after_exit, pid),
                want,
                "{sig} {by_process} {terminal} {after_exit} {pid:?}"
            );
        }
    }

    /// Review R-9, through a real relay: a SIGTERM caught before any mark
    /// and read once the child has exited stops the run.
    #[test]
    fn a_signal_read_after_the_exit_before_the_mark_stops_the_run() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let cutoff = Cutoff::default();
        envcloak_sys::testing::signal_this_thread(libc::SIGTERM).unwrap();
        forwarder.stop(|| false);
        forwarder.forward(&exited(), &cutoff);
        assert_eq!(cutoff.stopped_by(), Some(libc::SIGTERM));
    }

    /// Review R-9: the mark is written into a pipe full of signals not
    /// read yet, so it cannot be. The loss is recorded, and every signal
    /// read from then on stops the run: here signals read while the pid
    /// is still the child's (between the mark and `ChildState::exited`)
    /// stop the run rather than reach the exited child, which is a live
    /// process here and must not get them.
    #[test]
    fn a_lost_mark_makes_every_later_signal_stop_the_run() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let cutoff = Cutoff::default();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let state = ChildState::running(i32::try_from(child.id()).unwrap());
        flood(libc::SIGHUP);
        forwarder.child_exited();
        let lost = forwarder.mark_lost.load(Ordering::SeqCst);
        std::thread::scope(|s| {
            let forwarding = s.spawn(|| forwarder.forward(&state, &cutoff));
            forwarder.stop(|| !forwarding.is_finished());
        });
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(lost, "the mark went into a full pipe");
        assert_eq!(cutoff.stopped_by(), Some(libc::SIGHUP));
        assert!(alive, "a signal after the lost mark reached the child");
    }

    /// Waits up to 10 seconds for `child` to exit, and returns how it
    /// ended; kills and reaps one still running, and returns `None`.
    fn ended(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::yield_now();
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    /// A child in a group of its own that ignores SIGHUP, so a flood of it
    /// passed on leaves it running, and dies of anything else. Returned
    /// once it says it ignores it.
    fn ignoring_hup() -> std::process::Child {
        use std::io::BufRead;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "trap '' HUP; echo ready; exec /bin/sleep 60"])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        child
    }

    /// Review F-71, through the forwarder: a SIGTERM caught behind a relay
    /// pipe full of SIGHUP (passed on and ignored), with the child still
    /// running, is kept aside by the relay and still reaches the child.
    /// The relay used to drop it, and the child would run on.
    #[test]
    fn a_signal_behind_a_full_pipe_still_reaches_the_running_child() {
        use std::os::unix::process::ExitStatusExt;
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let cutoff = Cutoff::default();
        let mut child = ignoring_hup();
        let state = ChildState::running(i32::try_from(child.id()).unwrap());
        flood(libc::SIGHUP);
        envcloak_sys::testing::signal_this_thread(libc::SIGTERM).unwrap();
        std::thread::scope(|s| {
            let forwarding = s.spawn(|| forwarder.forward(&state, &cutoff));
            forwarder.stop(|| !forwarding.is_finished());
        });
        let status = ended(&mut child);
        assert_eq!(cutoff.stopped_by(), None);
        assert_eq!(
            status.and_then(|s| s.signal()),
            Some(libc::SIGTERM),
            "the SIGTERM behind the full pipe did not reach the child"
        );
    }

    /// Review F-71: a signal kept aside after the mark of the child's
    /// exit (written, not lost) stops the run like any signal after the
    /// mark, and is never passed on, though the pid is still the child's
    /// (between the mark and `ChildState::exited`): it comes after the
    /// mark, as it was caught.
    #[test]
    fn a_signal_kept_after_the_mark_stops_the_run_and_never_reaches_the_child() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let cutoff = Cutoff::default();
        let mut child = ignoring_hup();
        let state = ChildState::running(i32::try_from(child.id()).unwrap());
        forwarder.child_exited();
        assert!(!forwarder.mark_lost.load(Ordering::SeqCst));
        envcloak_sys::testing::keep_as_if_the_relay_was_full(libc::SIGTERM, true);
        forwarder.stop(|| false);
        forwarder.forward(&state, &cutoff);
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(cutoff.stopped_by(), Some(libc::SIGTERM));
        assert!(alive, "a signal kept after the mark reached the child");
    }

    /// Review R-9 (the stop, as the mark): the stop is written into a
    /// pipe full of signals not read yet, so the first try fails. It is
    /// tried again while the forwarding thread runs, which reads the pipe
    /// and makes room, and that thread then ends. It is started only when
    /// the first try has failed, so that try meets a full pipe.
    #[test]
    fn a_stop_into_a_full_pipe_is_tried_again_while_the_forwarder_reads() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let (cutoff, state) = (Cutoff::default(), exited());
        flood(libc::SIGHUP);
        std::thread::scope(|s| {
            let mut forwarding = None;
            forwarder.stop(|| {
                let f = forwarding
                    .get_or_insert_with(|| s.spawn(|| forwarder.forward(&state, &cutoff)));
                !f.is_finished()
            });
            let Some(f) = forwarding else {
                panic!("the stop was given up at the first try");
            };
            let end = Instant::now() + Duration::from_secs(10);
            while !f.is_finished() {
                if Instant::now() > end {
                    // Let the forwarder go, then fail.
                    while forwarder.relay.stop().is_err() {}
                    panic!("the forwarder never saw the stop");
                }
                std::thread::yield_now();
            }
        });
    }

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
