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
//! - A second SIGTERM ends the child at once: from the second SIGTERM this
//!   process gets on, SIGKILL is sent in its place, to the child's group
//!   without a terminal and to the child on one ([`sent_as`]). A child
//!   that ignores SIGTERM would otherwise outlive this process when it is
//!   killed in turn (as `envcloak mcp` does after two SIGTERMs and a
//!   grace), still holding the injected values, in a group nothing else
//!   owns.
//! - Without a terminal, a run that got a SIGTERM leaves nothing of the
//!   child's group behind ([`Forwarder::ends_childs_group`]): a child that
//!   exits on it may leave a descendant in its group that ignores it, and
//!   once the child has exited the runner kills that group (SIGKILL). The
//!   child is reaped only after its output has been read, so it leads the
//!   group until then, and a SIGTERM that comes while that output is read
//!   (it stops the run, below) ends the group the same way, before the
//!   reap. With a terminal the child is in this process's own group, which
//!   this process does not signal: whoever started this process in a
//!   group of its own (as `envcloak mcp` does) ends that group.
//!
//! The four signals are caught (never ignored, since `exec` would pass an
//! ignored disposition on to the child) from before the child starts until
//! the run returns, and unblocked on the thread that installs the relay:
//! a mask inherited through `exec` could block them (review R-8). A signal
//! is passed on only while the child has not exited: [`ChildState`] is
//! updated after `waitid` sees the exit and before the child is reaped, so
//! its pid, and the group it leads, can never belong to another process
//! when a signal is sent; and before passing one on, the forwarder asks
//! the kernel whether the child has exited already
//! ([`envcloak_sys::has_exited`]), so a signal that comes after the exit,
//! before the run has seen it, is never passed to what the child left in
//! its group as if the child still ran: it stops the run (below).
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
//!
//! Once the forwarding thread has ended, [`Forwarder::close`] draws the
//! line before the run's result is chosen: the four get their earlier
//! dispositions back, and one caught after the thread's last read stops
//! the run all the same, so none is caught and then left unread (Codex's
//! review of M2-19, swept from PTY mode); one sent after the line acts as
//! it would without the relay.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use envcloak_sys::{Relayed, SignalRelay};

use crate::pump::Cutoff;

/// The signals the runner catches.
pub(crate) const CAUGHT: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Kills what is left of the group the M1 runner's child `pid` led, once
/// the child has exited and before it is reaped (so the number is still
/// its own; `crate::follow`).
pub(crate) fn end_group(pid: i32) {
    // Listed in security/signal-allowlist.txt.
    #[allow(clippy::disallowed_methods)]
    let _ = envcloak_sys::signal_group(pid, libc::SIGKILL);
}

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

/// What is sent to the child for caught signal `sig`, when this process
/// has already passed `terms_passed` SIGTERMs on: SIGKILL in place of a
/// second SIGTERM and every one after it, `sig` otherwise.
pub(crate) fn sent_as(sig: i32, terms_passed: u32) -> i32 {
    if sig == libc::SIGTERM && terms_passed > 0 {
        libc::SIGKILL
    } else {
        sig
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
    /// A SIGTERM was read.
    term_seen: AtomicBool,
}

impl Forwarder {
    pub(crate) fn install(terminal: bool) -> io::Result<Self> {
        Ok(Forwarder {
            relay: SignalRelay::install(&CAUGHT)?,
            terminal,
            mark_lost: AtomicBool::new(false),
            term_seen: AtomicBool::new(false),
        })
    }

    /// Whether the run must end what is left of the child's group before
    /// it reaps the child: without a terminal (the child leads a group of
    /// its own), once a SIGTERM was read. Asked when the child's exit is
    /// seen (a SIGTERM the child died of was read before it was passed on)
    /// and again once the forwarder has stopped, after the output was read
    /// (every SIGTERM caught before the stop has been read by then).
    pub(crate) fn ends_childs_group(&self) -> bool {
        !self.terminal && self.term_seen.load(Ordering::SeqCst)
    }

    /// Passes signals on until [`Forwarder::stop`], and stops the run
    /// (`cutoff`) for one caught after [`Forwarder::child_exited`], or read
    /// once the child has exited when it would have been passed on (see
    /// [`act`]). Run on its own thread.
    pub(crate) fn forward(&self, child: &ChildState, cutoff: &Cutoff) {
        let mut marked = false;
        let mut terms_passed = 0u32;
        while let Ok(Some(caught)) = self.relay.next() {
            let (sig, by_process) = match caught {
                Relayed::Mark => {
                    marked = true;
                    continue;
                }
                Relayed::Signal { number, by_process } => (number, by_process),
            };
            if sig == libc::SIGTERM {
                self.term_seen.store(true, Ordering::SeqCst);
            }
            let after_exit = marked || self.mark_lost.load(Ordering::SeqCst);
            let pid = child.pid.lock().unwrap_or_else(|e| e.into_inner());
            // A child that has exited, though the run has not marked it yet,
            // is gone all the same: the signal has nobody to go to (review
            // R-9), and is never passed on to what the child left behind.
            let running = pid.filter(|p| !envcloak_sys::has_exited(*p).unwrap_or(false));
            match act(sig, by_process, self.terminal, after_exit, running) {
                // Sent under the lock `ChildState::exited` takes, so the
                // pid is still the child's. A child that is gone by now,
                // or a group already empty, is not an error: there is
                // nothing left to tell.
                Act::PassOn { pid, group } => {
                    let sent = sent_as(sig, terms_passed);
                    if sig == libc::SIGTERM {
                        terms_passed = terms_passed.saturating_add(1);
                    }
                    // The M1 runner's numbers, kept its child's by the lock
                    // above (review R-9); listed in
                    // security/signal-allowlist.txt.
                    #[allow(clippy::disallowed_methods)]
                    let _ = if group {
                        envcloak_sys::signal_group(pid, sent)
                    } else {
                        envcloak_sys::signal_process(pid, sent)
                    };
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

    /// The line drawn before the run's result is chosen, once the
    /// forwarding thread has ended (Codex's review of M2-19, swept from PTY
    /// mode): the caught signals get their dispositions from before the
    /// run back, and one of the four caught after the stop and not read
    /// (while the forwarder ended, or before the child is reaped) stops the
    /// run as any after the exit does; a SIGTERM among them also has the
    /// run end what the child left in its group
    /// ([`Forwarder::ends_childs_group`]). One sent after this acts as it
    /// would without the relay, as it did once the run had returned.
    pub(crate) fn close(&self, cutoff: &Cutoff) {
        self.relay.restore_dispositions();
        while let Ok(Some(caught)) = self.relay.try_next() {
            let Relayed::Signal { number, .. } = caught else {
                continue;
            };
            if CAUGHT.contains(&number) {
                if number == libc::SIGTERM {
                    self.term_seen.store(true, Ordering::SeqCst);
                }
                cutoff.stop_now(number);
            }
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

/// The signals PTY mode catches (`envcloak run --pty`, [`crate::pty`]):
/// the four it forwards, SIGTSTP from another process, SIGCONT (the
/// person's `fg`) and SIGWINCH (the outer terminal resized). With the outer
/// terminal raw, the person's keys reach the command's terminal as bytes,
/// so the outer terminal itself sends the CLI none of them: every SIGINT
/// or SIGQUIT the CLI gets was sent by a process (or by a hangup).
pub(crate) const PTY_CAUGHT: [i32; 7] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGCONT,
    libc::SIGWINCH,
];

/// What PTY mode does with a caught signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtyAct {
    /// Forward it once to the slave's foreground job
    /// (`envcloak_sys::pty::forward_signal`, M2 plan D-35).
    Forward(i32),
    /// SIGKILL to the command's group, through the monitor, in place of a
    /// second SIGTERM (as in pipe mode: a command that ignores SIGTERM
    /// would otherwise outlive the CLI killed in turn).
    Kill,
    /// The command has exited (or its monitor is gone): stop the run at
    /// once, 128 plus this signal (review T12-2).
    Stop(i32),
    /// SIGTSTP from another process: stop the command first
    /// ([`crate::job_control::stop_requested`]).
    Suspend,
    /// SIGCONT: raw mode and the size again.
    Continued,
    /// SIGWINCH: the outer terminal's size to the PTY.
    Resize,
    /// Nothing to do.
    Nothing,
}

/// What PTY mode does with caught signal `sig`, once the command has
/// exited (or its monitor is gone) when `ended`, after `terms_passed`
/// SIGTERMs were forwarded.
pub(crate) fn pty_act(sig: i32, ended: bool, terms_passed: u32) -> PtyAct {
    match sig {
        libc::SIGINT | libc::SIGQUIT | libc::SIGHUP | libc::SIGTERM if ended => PtyAct::Stop(sig),
        libc::SIGTERM if terms_passed > 0 => PtyAct::Kill,
        libc::SIGINT | libc::SIGQUIT | libc::SIGHUP | libc::SIGTERM => PtyAct::Forward(sig),
        libc::SIGTSTP if !ended => PtyAct::Suspend,
        libc::SIGCONT => PtyAct::Continued,
        libc::SIGWINCH if !ended => PtyAct::Resize,
        _ => PtyAct::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    use super::*;

    /// PTY mode: the four are forwarded once each while the command runs,
    /// a second SIGTERM kills the command's group, every one of the four
    /// stops the run once the command has exited; SIGTSTP stops the
    /// command, SIGCONT and SIGWINCH reach the terminal. No signal is ever
    /// turned into SIGSTOP.
    #[test]
    fn pty_mode_forwards_the_four_and_stops_the_run_after_the_exit() {
        let (int, quit, term, hup) = (libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP);
        for sig in [int, quit, term, hup] {
            assert_eq!(pty_act(sig, false, 0), PtyAct::Forward(sig), "{sig}");
            assert_eq!(pty_act(sig, true, 0), PtyAct::Stop(sig), "{sig}");
        }
        assert_eq!(pty_act(int, false, 3), PtyAct::Forward(int));
        assert_eq!(pty_act(term, false, 1), PtyAct::Kill);
        assert_eq!(pty_act(term, true, 1), PtyAct::Stop(term));
        assert_eq!(pty_act(libc::SIGTSTP, false, 0), PtyAct::Suspend);
        assert_eq!(pty_act(libc::SIGTSTP, true, 0), PtyAct::Nothing);
        assert_eq!(pty_act(libc::SIGCONT, false, 0), PtyAct::Continued);
        assert_eq!(pty_act(libc::SIGCONT, true, 0), PtyAct::Continued);
        assert_eq!(pty_act(libc::SIGWINCH, false, 0), PtyAct::Resize);
        assert_eq!(pty_act(libc::SIGWINCH, true, 0), PtyAct::Nothing);
        assert_eq!(pty_act(libc::SIGUSR1, false, 0), PtyAct::Nothing);
        for sig in PTY_CAUGHT {
            for ended in [false, true] {
                assert!(
                    !matches!(pty_act(sig, ended, 0), PtyAct::Forward(libc::SIGSTOP)),
                    "{sig}"
                );
            }
        }
    }

    /// The relay is process-wide, so the tests that install one take
    /// turns.
    static TURN: Mutex<()> = Mutex::new(());

    /// Raises `sig` on this thread more times than a pipe holds bytes, so
    /// the relay's pipe is full after (the handler keeps one that does not
    /// fit aside and merges the repeats).
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
    /// process here and must not get them. A SIGTERM caught after the
    /// lost mark, kept aside by the relay as the pipe is full (review
    /// F-71), stops the run the same way and never reaches the child.
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
        envcloak_sys::testing::signal_this_thread(libc::SIGTERM).unwrap();
        std::thread::scope(|s| {
            let forwarding = s.spawn(|| forwarder.forward(&state, &cutoff));
            forwarder.stop(|| !forwarding.is_finished());
        });
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(lost, "the mark went into a full pipe");
        assert!(
            matches!(cutoff.stopped_by(), Some(libc::SIGHUP | libc::SIGTERM)),
            "{:?}",
            cutoff.stopped_by()
        );
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
        // The SIGHUPs read once the SIGTERM has ended the child have nobody
        // to go to and stop the run (review R-9); the SIGTERM itself went
        // to the child, and never stops it.
        assert!(
            matches!(cutoff.stopped_by(), None | Some(libc::SIGHUP)),
            "{:?}",
            cutoff.stopped_by()
        );
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

    /// Review R-9, for a child that has exited before the run saw it: a
    /// SIGTERM read with no mark yet and the pid still the child's (the
    /// child a zombie, not reaped) has nobody to go to. It stops the run,
    /// as one read after the mark does, and is not passed on to what the
    /// child left in its group (M2-06, round 4: a test that signals once
    /// the child has exited must not depend on how soon the run sees it).
    ///
    /// Mutation checked: the forwarder not asking whether the child has
    /// exited (`has_exited` left out): the SIGTERM is passed on to the
    /// exited child's group, nothing stops the run, and this fails.
    #[test]
    fn a_signal_read_once_the_child_exited_but_before_the_mark_stops_the_run() {
        let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let forwarder = Forwarder::install(false).unwrap();
        let cutoff = Cutoff::default();
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        envcloak_sys::wait_for_exit(pid).unwrap();
        assert!(envcloak_sys::has_exited(pid).unwrap());
        let state = ChildState::running(pid);
        envcloak_sys::testing::signal_this_thread(libc::SIGTERM).unwrap();
        forwarder.stop(|| false);
        forwarder.forward(&state, &cutoff);
        let _ = child.wait();
        assert_eq!(cutoff.stopped_by(), Some(libc::SIGTERM));
        assert!(forwarder.ends_childs_group());
    }

    /// `has_exited` tells a running child from one that exited, and leaves
    /// the exited one unreaped.
    #[test]
    fn has_exited_does_not_wait_or_reap() {
        use std::os::unix::process::ExitStatusExt;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat >/dev/null"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        assert!(!envcloak_sys::has_exited(pid).unwrap());
        drop(child.stdin.take());
        envcloak_sys::wait_for_exit(pid).unwrap();
        assert!(envcloak_sys::has_exited(pid).unwrap());
        assert!(envcloak_sys::has_exited(pid).unwrap(), "it was reaped");
        let status = child.wait().unwrap();
        assert_eq!((status.code(), status.signal()), (Some(0), None));
    }

    /// The first SIGTERM is passed on as it is; every one after it is
    /// SIGKILL. Other signals are passed on as they are, however many
    /// SIGTERMs came before.
    #[test]
    fn a_second_sigterm_is_sent_as_sigkill() {
        assert_eq!(sent_as(libc::SIGTERM, 0), libc::SIGTERM);
        assert_eq!(sent_as(libc::SIGTERM, 1), libc::SIGKILL);
        assert_eq!(sent_as(libc::SIGTERM, 7), libc::SIGKILL);
        for sig in [libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            assert_eq!(sent_as(sig, 0), sig);
            assert_eq!(sent_as(sig, 3), sig);
        }
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
