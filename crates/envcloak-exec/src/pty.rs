//! PTY mode's relay (`envcloak run --pty`; SPEC §6.1 steps 7 and 8, M2
//! plan task M2-19, D-19, D-34, D-35): the command on a pseudo-terminal of
//! its own, under the PTY monitor ([`crate::start_pty`]), and one thread
//! that relays between that terminal and the person's.
//!
//! - **Output.** The PTY's master side carries the command's standard
//!   output and standard error merged, through the slave's line
//!   discipline (which writes each LF as CR LF). Everything read there
//!   goes through one stream of the redactor, which holds the CR LF form of
//!   every value holding LF (`RedactorBuilder::crlf_variants`): `push` on
//!   every read, `flush_idle` after 40 ms without output, so a prompt
//!   without a newline shows at once unless it could start a value, and
//!   `finish` at the end. Only what the redactor releases is written to
//!   the outer terminal; there is no other way out for the command's
//!   bytes, and no fallback to passing them through. A slow reader slows
//!   the command: at most [`OUTPUT_LIMIT`] released bytes wait for it
//!   before the master side is not read, while the command runs. Once it
//!   has exited, the master side is read on whatever the reader does, up
//!   to [`EXIT_READ_LIMIT`] more, far more than a PTY holds, so the PTY
//!   reaches its end however slow the reader, and what was read is then
//!   delivered at the reader's pace (the verifier's review of M2-19).
//! - **Input.** The outer terminal is in raw mode for the run
//!   (`TerminalGuard`), so every key reaches the command's terminal as a
//!   byte: a typed Ctrl-C is a byte the slave's line discipline turns into
//!   one SIGINT for the foreground job, and the CLI sends none of its own.
//!   Keys are read at most [`INPUT_CHUNK`] bytes at a time into a buffer
//!   that is wiped once they are written to the master side, and never
//!   logged; while the command does not take them, no more are read.
//! - **Window size.** The PTY starts with the outer terminal's size; on
//!   SIGWINCH the new size is set on the master side, which sends the
//!   command SIGWINCH.
//! - **Signals.** SIGINT, SIGQUIT, SIGTERM and SIGHUP are forwarded once
//!   each to the slave's actual foreground job, which is a nested shell's
//!   job when one runs (`envcloak_sys::pty::forward_signal`, along D-35's
//!   route for the signal and system). A second SIGTERM is SIGKILL to the
//!   command's group, through the monitor.
//! - **Suspension** ([`crate::job_control`]): the suspend character is
//!   relayed as a byte; when the monitor reports the command stopped, the
//!   CLI flushes, restores the outer terminal, stops its own group, and on
//!   SIGCONT reads the outer terminal's settings again (what the person's
//!   shell left there is what later restores put back, and a control
//!   character the person changed is copied to the PTY), takes raw mode
//!   and the size again, and only then resumes the command. Raw mode that
//!   cannot be taken again resumes nothing: input ends, and the run ends
//!   with [`ExecError::TerminalLost`]. SIGTSTP from another process stops
//!   the command first.
//! - **The end.** The monitor reports the command's exit at once, and the
//!   relay then closes its end of the monitor's channel, so the monitor,
//!   once what the command wrote has been read, reaps the command and
//!   exits: the session ends (`SessionMonitor::end_channel`). The kernel
//!   sends the terminal's foreground group, the command's with whatever it
//!   left in it, SIGHUP; macOS also revokes the terminal for every process
//!   still holding it. Output is read until the end of the stream, and
//!   what was read is then delivered at the reader's pace, however slow;
//!   only while a descendant still holds the slave (on Linux, one that
//!   ignores SIGHUP) [`crate::DRAIN_LIMIT`] (2 seconds) from the exit, the
//!   master side is closed, what the outer terminal does not take at once
//!   is given up, and what the descendant writes later is lost, never
//!   passed through. The master side not at its end by then is that case:
//!   the relay has read on since the exit, and what a PTY no process
//!   holds still has in it is far less than it reads. A SIGINT, SIGQUIT,
//!   SIGTERM or SIGHUP caught after the exit stops the run at once (128
//!   plus its number). The outer terminal gets its settings back
//!   (`TCSAFLUSH`) and the monitor is reaped. Then the four get their
//!   dispositions from before the run back, and one caught before that
//!   and not read yet (during the last write, or while the monitor was
//!   reaped) still decides the result (Codex's review of M2-19): no signal
//!   is caught and then left unread.
//! - **A lost monitor.** When the monitor's channel ends before it
//!   reported an exit (the monitor died: the kernel hangs the session up,
//!   SIGHUP to the command's group), the outer terminal is restored, the
//!   output drained (redacted) until its end or the 2-second cutoff, and
//!   the run fails with `pty_monitor_lost` ([`ExecError::MonitorLost`]).
//!
//! Everything is waited for in one `poll` (`envcloak_sys::wait_any`): the
//! signal relay, the monitor's channel, the master side and the outer
//! terminal. The outer terminal is opened again by its name
//! ([`OuterTerminal::open`]), so the relay's own descriptions of it are
//! non-blocking while the person's shell keeps a blocking one: a write
//! the reader does not take never blocks the relay, which keeps reading
//! the monitor's reports and the signals.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_policy::EnvName;
use envcloak_redact::{Redactor, StreamRedactor};
use envcloak_sys::pty::{MonitorCommand, MonitorEvent, SessionMonitor, forward_signal};
use envcloak_sys::{
    Relayed, SignalRelay, TerminalGuard, TerminalSettings, set_window_size, window_size,
};
use zeroize::{Zeroize, Zeroizing};

use crate::job_control::{self, Halt, Suspension};
use crate::signals::{PTY_CAUGHT, PtyAct, pty_act};
use crate::{ChildExit, DRAIN_LIMIT, ExecError};

/// Bytes read from the master side at a time.
const CHUNK: usize = 64 * 1024;
/// Keys read from the outer terminal at a time, and the most that wait for
/// the command to take them.
pub const INPUT_CHUNK: usize = 4096;
/// Released bytes that may wait for the outer terminal's reader before the
/// master side is no longer read, while the command runs.
pub const OUTPUT_LIMIT: usize = 64 * 1024;
/// How many more released bytes may wait once the command has exited (or
/// its monitor is gone): the master side is read on for them whatever the
/// reader does, so a PTY that no process holds any more reaches its end
/// and what it held is delivered at the reader's pace rather than given up
/// at the cutoff. Far more than a PTY holds with nobody reading it
/// (measured: 1 KiB on macOS 26.4, 12 KiB on Linux 6.12; `pty_relay.rs`
/// checks the system it runs on), so only output a descendant keeps
/// writing after the exit fills it.
pub const EXIT_READ_LIMIT: usize = 1024 * 1024;
/// How long the suspension waits for the outer terminal's reader to take
/// what the command wrote before it stopped.
const FLUSH_WAIT: Duration = Duration::from_secs(2);

/// The person's terminal for a PTY run: where keys come from and where the
/// command's merged output goes. Each side is the terminal opened again by
/// its name (`envcloak_sys::reopen_terminal`), non-blocking, a description
/// of the relay's own.
pub struct OuterTerminal {
    input: File,
    output: File,
}

impl core::fmt::Debug for OuterTerminal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OuterTerminal").finish_non_exhaustive()
    }
}

impl OuterTerminal {
    /// The terminals on `input` (keys; its settings are the ones raw mode
    /// saves and the PTY starts with) and `output` (the command's output),
    /// each opened again for the relay.
    ///
    /// # Errors
    /// [`ExecError::PtyUnavailable`] when either is not a terminal, or one
    /// cannot be opened again: `--pty` never falls back to pipe mode
    /// (SPEC §6.1 step 7).
    pub fn open(input: BorrowedFd<'_>, output: BorrowedFd<'_>) -> Result<Self, ExecError> {
        if !input.is_terminal() || !output.is_terminal() {
            return Err(ExecError::PtyUnavailable);
        }
        let open = |fd| envcloak_sys::reopen_terminal(fd).map_err(|_| ExecError::PtyUnavailable);
        Ok(OuterTerminal {
            input: File::from(open(input)?),
            output: File::from(open(output)?),
        })
    }
}

/// How the relay ended.
enum End {
    /// The command exited with this status (its output read to the end or
    /// to the cutoff).
    Exited(ExitStatus),
    /// A signal caught after the reported exit stopped the run.
    Stopped(i32),
    /// The monitor's channel ended before it reported an exit.
    MonitorLost,
}

/// The master side's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Master {
    /// Read as it comes.
    Open,
    /// Its end was read: no process holds the slave any more.
    Ended,
    /// Closed at the cutoff, or by a signal that stopped the run.
    Cut,
}

/// Runs `argv` on a new PTY under its monitor and relays it to and from
/// `terminal` until it ends: see the module documentation.
pub(crate) fn run(
    argv: &[std::ffi::OsString],
    injected: Vec<(EnvName, SecretBytes)>,
    redactor: &Redactor,
    idle: Duration,
    terminal: OuterTerminal,
) -> Result<ChildExit, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::NoCommand);
    }
    // Caught before the command exists, so one sent just after it starts is
    // forwarded rather than ending this process with the terminal raw.
    let signals = SignalRelay::install(&PTY_CAUGHT).map_err(|e| ExecError::Setup(e.kind()))?;
    let guard =
        TerminalGuard::enter_raw(terminal.input.as_fd()).map_err(|e| ExecError::Setup(e.kind()))?;
    let size = window_size(terminal.input.as_fd()).ok();
    let settings = guard.saved().pty_output();
    let started = crate::start_pty(argv, &injected, size, Some(&settings));
    // The values are in the command's environment now; the redactor holds
    // the only other copies.
    drop(injected);
    let pty = started?;
    envcloak_sys::set_nonblocking(pty.master.as_fd()).map_err(|e| {
        // The command started: it is hung up with its session as the
        // monitor is dropped.
        ExecError::Followed(e.kind())
    })?;
    let mut relay = Relay {
        terminal: &terminal,
        guard: Some(guard),
        raw_wanted: true,
        master: Some(File::from(pty.master)),
        master_state: Master::Open,
        monitor: pty.monitor,
        channel_open: true,
        signals: &signals,
        stream: redactor.stream(),
        idle,
        flush_at: None,
        keys: Zeroizing::new(vec![0u8; INPUT_CHUNK]),
        keys_at: 0,
        keys_len: 0,
        input_open: true,
        out: Vec::with_capacity(CHUNK),
        output_open: true,
        exit: None,
        lost: false,
        deadline: None,
        stopped_by: None,
        broken: None,
        terms: 0,
        read_buf: Zeroizing::new(vec![0u8; CHUNK]),
    };
    // Gate 12: a test build panics here on request, the terminal raw and
    // the command running; the panic hook restores the terminal.
    envcloak_sys::panic_point("exec.pty.relay");
    let ended = relay.relay();
    if matches!(ended, Ok(End::Exited(_))) {
        // A test build stops here on request: the output delivered, the
        // result not chosen yet (M2-19's boundary gate).
        envcloak_sys::pause_point("exec.pty.ended");
    }
    let result = relay.finish(ended);
    let mut signals = signals;
    after_the_boundary(&mut signals, result)
}

/// The line drawn before the run's result is chosen (Codex's review of
/// M2-19): the four signals get their dispositions from before the run
/// back, so one sent from now on acts as it would have without the run's
/// relay, and one caught before and not read yet (while the last output
/// was written, at the cutoff, or while the monitor was reaped: after the
/// exit, every time) stops the run as one read in the loop does, 128 plus
/// its number. The outer terminal is restored already. A failure, or a run
/// a signal stopped already, stays as it is.
fn after_the_boundary(
    signals: &mut SignalRelay,
    result: Result<ChildExit, ExecError>,
) -> Result<ChildExit, ExecError> {
    signals.restore_dispositions();
    let mut late = None;
    while let Ok(Some(caught)) = signals.try_next() {
        if let Relayed::Signal { number, .. } = caught {
            if let PtyAct::Stop(sig) = pty_act(number, true, 0) {
                late.get_or_insert(sig);
            }
        }
    }
    late_result(result, late)
}

fn late_result(
    result: Result<ChildExit, ExecError>,
    late: Option<i32>,
) -> Result<ChildExit, ExecError> {
    match (result, late) {
        (Ok(ChildExit::Code(_) | ChildExit::Signal(_)), Some(sig)) => Ok(ChildExit::Stopped(sig)),
        (result, _) => result,
    }
}

/// The relay's state: see the module documentation.
struct Relay<'a, 'r> {
    terminal: &'a OuterTerminal,
    guard: Option<TerminalGuard>,
    /// The outer terminal should be raw: false once restored for good (a
    /// lost monitor), so a SIGCONT does not make it raw again.
    raw_wanted: bool,
    master: Option<File>,
    master_state: Master,
    monitor: SessionMonitor,
    channel_open: bool,
    signals: &'a SignalRelay,
    stream: StreamRedactor<'r>,
    idle: Duration,
    /// When the redactor's idle flush is due: set by a read, cleared by the
    /// flush.
    flush_at: Option<Instant>,
    /// Keys read and not yet written to the master side: `keys[keys_at ..
    /// keys_len]`. Wiped once written.
    keys: Zeroizing<Vec<u8>>,
    keys_at: usize,
    keys_len: usize,
    input_open: bool,
    /// Released bytes waiting for the outer terminal.
    out: Vec<u8>,
    output_open: bool,
    exit: Option<ExitStatus>,
    lost: bool,
    /// The cutoff: [`DRAIN_LIMIT`] after the exit or the monitor's loss.
    deadline: Option<Instant>,
    stopped_by: Option<i32>,
    /// The outer terminal could not be put back in raw mode for the
    /// command: the run ends ([`ExecError::TerminalLost`]).
    broken: Option<io::ErrorKind>,
    terms: u32,
    read_buf: Zeroizing<Vec<u8>>,
}

impl Relay<'_, '_> {
    /// Whether the command has exited or its monitor is gone.
    fn ended(&self) -> bool {
        self.exit.is_some() || self.lost
    }

    /// How many released bytes may wait for the outer terminal before the
    /// master side is not read: [`OUTPUT_LIMIT`] while the command runs,
    /// and [`EXIT_READ_LIMIT`] more once it has ended, so a PTY no process
    /// holds is read to its end however slow the reader.
    fn read_limit(&self) -> usize {
        if self.ended() {
            OUTPUT_LIMIT + EXIT_READ_LIMIT
        } else {
            OUTPUT_LIMIT
        }
    }

    /// Whether the master side is to be read now.
    fn reading_master(&self) -> bool {
        self.master_state == Master::Open && self.out.len() < self.read_limit()
    }

    /// The loop: until the command has ended and its output is read and
    /// delivered (or cut off), or a signal stops the run.
    fn relay(&mut self) -> Result<End, ExecError> {
        loop {
            if let Some(sig) = self.stopped_by {
                return Ok(signal_end(self.lost, sig));
            }
            if let Some(kind) = self.broken {
                return Err(ExecError::TerminalLost(kind));
            }
            if self.ended() {
                let now = Instant::now();
                // Not at its end 2 seconds after the exit, though read on
                // since: a descendant holds the slave.
                if self.master_state == Master::Open && self.deadline.is_some_and(|d| d <= now) {
                    self.cut();
                }
                let delivered = self.out.is_empty() || !self.output_open;
                if self.master_state == Master::Cut
                    || (self.master_state == Master::Ended && delivered)
                {
                    return Ok(if let Some(status) = self.exit {
                        End::Exited(status)
                    } else {
                        End::MonitorLost
                    });
                }
            }
            self.wait()?;
            self.take_reports();
            self.take_signals();
            if self.stopped_by.is_some() {
                continue;
            }
            self.read_master();
            self.read_keys();
            self.write_keys();
            self.write_out();
            self.idle_flush();
        }
    }

    /// Waits for anything the loop acts on, at most until the idle flush
    /// or the cutoff is due.
    fn wait(&self) -> Result<(), ExecError> {
        let now = Instant::now();
        let due = [
            self.flush_at,
            self.deadline.filter(|_| self.master_state == Master::Open),
        ]
        .into_iter()
        .flatten()
        .min()
        .map(|d| d.saturating_duration_since(now));
        let reading_master = self.reading_master();
        let keys_waiting = self.keys_at < self.keys_len;
        // Passed only when it is read or written: a hang-up is reported
        // whatever is asked, and would wake a loop with nothing to do.
        let master = self
            .master
            .as_ref()
            .map(AsFd::as_fd)
            .filter(|_| reading_master || keys_waiting);
        let fds = [
            (Some(self.signals.ready()), true, false),
            (
                self.monitor.control().filter(|_| self.channel_open),
                true,
                false,
            ),
            (master, reading_master, keys_waiting),
            (
                (self.input_open && !keys_waiting && !self.ended())
                    .then(|| self.terminal.input.as_fd()),
                true,
                false,
            ),
            (
                (self.output_open && !self.out.is_empty()).then(|| self.terminal.output.as_fd()),
                false,
                true,
            ),
        ];
        envcloak_sys::wait_any(&fds, due)
            .map(|_| ())
            .map_err(|e| ExecError::Followed(e.kind()))
    }

    /// The monitor's reports: a stop runs the suspension, an exit starts the
    /// cutoff, the end of the channel without an exit is a lost monitor.
    fn take_reports(&mut self) {
        while self.channel_open {
            match self.monitor.next_event(Some(Duration::ZERO)) {
                Ok(None) => break,
                Ok(Some(MonitorEvent::Stopped(_))) => match job_control::command_stopped(self) {
                    Ok(()) => {}
                    // The monitor gone: its channel's end says so next.
                    Err(Halt::Monitor) => {}
                    // Not resumed, input ended: the run ends.
                    Err(Halt::Raw(e)) => {
                        self.broken.get_or_insert(e.kind());
                        return;
                    }
                },
                Ok(Some(MonitorEvent::Continued)) => {}
                Ok(Some(MonitorEvent::Exited(status))) => {
                    self.exit = Some(status);
                    self.deadline = Some(Instant::now() + DRAIN_LIMIT);
                    self.drop_keys();
                    // A test build's monitor death after the exit's
                    // report: the run still ends with the command's status.
                    self.monitor.kill_point("exec.pty.exited");
                    // The session ends now (the monitor, once what the
                    // command wrote is read, reaps it and exits), so the
                    // PTY closes as soon as nothing else holds it; what
                    // the command left holding it has the 2-second cutoff
                    // (`SessionMonitor::end_channel`).
                    self.monitor.end_channel();
                    self.channel_open = false;
                    envcloak_sys::pause_point("exec.pty.exited");
                    return;
                }
                // The channel ended, or carried something that is not a
                // report: the monitor is gone either way.
                Err(_) => {
                    self.channel_open = false;
                    if self.exit.is_none() {
                        self.monitor_lost();
                    }
                }
            }
        }
    }

    /// The monitor died before it reported an exit: the kernel has hung the
    /// session up. The outer terminal is restored at once, and the output
    /// is drained until its end or the cutoff.
    fn monitor_lost(&mut self) {
        self.lost = true;
        // A test writer can produce its next batch after loss is known,
        // before the drain starts. No pause exists in a release build.
        envcloak_sys::pause_point("exec.pty.monitor-lost");
        self.deadline = Some(Instant::now() + DRAIN_LIMIT);
        self.raw_wanted = false;
        if let Some(g) = self.guard.as_ref() {
            let _ = g.restore();
        }
        self.drop_keys();
    }

    /// The signals caught since the last look.
    fn take_signals(&mut self) {
        while let Ok(Some(caught)) = self.signals.try_next() {
            let Relayed::Signal { number, .. } = caught else {
                continue;
            };
            match pty_act(number, self.ended(), self.terms) {
                PtyAct::Forward(sig) => {
                    if sig == libc::SIGTERM {
                        self.terms = self.terms.saturating_add(1);
                    }
                    if let Some(m) = self.master.as_ref() {
                        // A job gone by now has nothing to be told; the
                        // monitor gone is seen at its channel's end.
                        let _ = forward_signal(&self.monitor, m.as_fd(), sig);
                    }
                }
                PtyAct::Kill => {
                    let _ = self.monitor.send(MonitorCommand::Signal(libc::SIGKILL));
                }
                PtyAct::Stop(sig) => {
                    self.stopped_by.get_or_insert(sig);
                    return;
                }
                PtyAct::Suspend => {
                    let _ = job_control::stop_requested(self);
                }
                PtyAct::Continued => {
                    if self.raw_wanted {
                        // Continued from a stop that was not the relay's
                        // own (SIGSTOP), or once more after it: what the
                        // person's shell left is kept unless still raw.
                        self.refresh_settings();
                        // Before the exit the command reads keys: it never
                        // does so with the outer terminal cooked.
                        if let Err(e) = self.raw_on_sigcont() {
                            if !self.ended() {
                                self.end_input();
                                self.broken.get_or_insert(e.kind());
                                return;
                            }
                        }
                        self.resend_size();
                    }
                }
                PtyAct::Resize => self.resize(),
                PtyAct::Nothing => {}
            }
        }
    }

    /// Raw mode again on a SIGCONT the suspension did not wait for.
    fn raw_on_sigcont(&self) -> io::Result<()> {
        // A test build fails here on request, as a terminal that refuses
        // raw mode would (Codex's review of M2-19).
        envcloak_sys::fail_point("exec.pty.raw-on-sigcont")?;
        self.reenter_raw()
    }

    /// The outer terminal in raw mode again, from the saved settings.
    fn reenter_raw(&self) -> io::Result<()> {
        self.guard
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .reenter_raw()
    }

    /// SIGWINCH: the outer terminal's size to the PTY.
    fn resize(&mut self) {
        let Ok(size) = window_size(self.terminal.input.as_fd()) else {
            return;
        };
        envcloak_sys::pause_point("exec.pty.winch");
        if let Some(m) = self.master.as_ref() {
            let _ = set_window_size(m.as_fd(), size);
        }
    }

    /// Reads what the master side has, through the redactor, until it
    /// would wait, its end, or the read limit ([`Relay::read_limit`]).
    fn read_master(&mut self) {
        while self.reading_master() {
            let Some(mut m) = self.master.as_ref() else {
                return;
            };
            match m.read(&mut self.read_buf[..]) {
                Ok(0) => return self.master_ended(),
                Ok(n) => {
                    let got = self.read_buf.get_mut(..n).unwrap_or_default();
                    self.stream.push(got, &mut self.out);
                    got.zeroize();
                    self.flush_at = Some(Instant::now() + self.idle);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                // EIO: every descriptor on the slave side is closed.
                Err(_) => return self.master_ended(),
            }
        }
    }

    /// The master side's end: no process holds the slave any more. What
    /// the redactor held back is released, redacted.
    fn master_ended(&mut self) {
        self.master_state = Master::Ended;
        self.master = None;
        self.stream.finish(&mut self.out);
        self.flush_at = None;
    }

    /// The cutoff, 2 seconds after the exit with a descendant still holding
    /// the slave: the master side is closed, so what the descendant writes
    /// later is lost; what the redactor held back is released, redacted,
    /// and the outer terminal is given what it takes at once (SPEC §6.1
    /// step 8: a write the reader has not taken by then is given up).
    fn cut(&mut self) {
        self.master_state = Master::Cut;
        self.master = None;
        self.stream.finish(&mut self.out);
        self.flush_at = None;
        self.write_out();
        self.out.clear();
    }

    /// Releases what the redactor held back once the master side has been
    /// quiet for the idle interval.
    fn idle_flush(&mut self) {
        if flush_idle_at(
            Instant::now(),
            &mut self.flush_at,
            &mut self.stream,
            &mut self.out,
        ) {
            self.write_out();
        }
    }

    /// Writes released bytes to the outer terminal as far as it takes them
    /// now. A terminal that fails (hung up) takes nothing more: what the
    /// command writes is still read, and dropped.
    fn write_out(&mut self) {
        let mut done = 0;
        while self.output_open && done < self.out.len() {
            let rest = self.out.get(done..).unwrap_or_default();
            match (&self.terminal.output).write(rest) {
                Ok(0) => self.output_open = false,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => self.output_open = false,
            }
        }
        if self.output_open {
            self.out.drain(..done.min(self.out.len()));
        } else {
            self.out.clear();
        }
    }

    /// Reads keys from the outer terminal while none wait for the command.
    fn read_keys(&mut self) {
        if !self.input_open || self.ended() || self.keys_at < self.keys_len {
            return;
        }
        match (&self.terminal.input).read(&mut self.keys[..]) {
            Ok(0) => self.input_open = false,
            Ok(n) => {
                self.keys_at = 0;
                self.keys_len = n;
                // A test build's monitor death, keys in hand (M2-19's
                // `pty_monitor_lost` gate).
                self.monitor.kill_point("exec.pty.keys");
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            // EIO: the terminal hung up.
            Err(_) => self.input_open = false,
        }
    }

    /// Writes waiting keys to the master side as far as it takes them, and
    /// wipes them once written.
    fn write_keys(&mut self) {
        let Some(mut master) = self.master.as_ref() else {
            return self.drop_keys();
        };
        if let Err(e) = write_keys_to(
            &mut master,
            &mut self.keys,
            &mut self.keys_at,
            self.keys_len,
        ) {
            if e.kind() == io::ErrorKind::WouldBlock {
                return;
            }
        }
        self.drop_keys();
    }

    /// Wipes the key buffer and forgets what it held.
    fn drop_keys(&mut self) {
        discard_keys(&mut self.keys, &mut self.keys_at, &mut self.keys_len);
    }

    /// Ends the run: the outer terminal back as it was, the master side
    /// closed, the monitor's channel closed so it reaps the command, and the
    /// monitor reaped.
    ///
    /// A run stopped by a signal, or broken off by an error, does not wait
    /// for the monitor: it is killed and reaped (the kernel hangs up what
    /// is left of the session), so the run ends at once.
    fn finish(mut self, ended: Result<End, ExecError>) -> Result<ChildExit, ExecError> {
        self.master = None;
        if let Some(g) = self.guard.take() {
            let _ = g.release();
        }
        let Relay { monitor, .. } = self;
        match ended {
            Err(e) => {
                drop(monitor);
                Err(e)
            }
            Ok(End::Stopped(sig)) => {
                drop(monitor);
                Ok(ChildExit::Stopped(sig))
            }
            Ok(End::MonitorLost) => {
                let _ = monitor.finish();
                Err(ExecError::MonitorLost)
            }
            Ok(End::Exited(status)) => {
                monitor
                    .finish()
                    .map_err(|e| ExecError::Followed(e.kind()))?;
                Ok(ChildExit::from(status))
            }
        }
    }
}

impl Suspension for Relay<'_, '_> {
    fn flush_output(&mut self) {
        self.read_master();
        self.stream.flush_idle(&mut self.out);
        self.flush_at = None;
        let end = Instant::now() + FLUSH_WAIT;
        loop {
            self.write_out();
            if self.out.is_empty() || !self.output_open {
                return;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let fds = [(Some(self.terminal.output.as_fd()), false, true)];
            if envcloak_sys::wait_any(&fds, Some(left)).is_err() {
                return;
            }
        }
    }

    fn restore_terminal(&mut self) -> io::Result<()> {
        self.guard
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .restore()
    }

    fn stop_self(&mut self) -> io::Result<()> {
        envcloak_sys::stop_own_job()
    }

    fn refresh_settings(&mut self) {
        let Some(g) = self.guard.as_mut() else {
            return;
        };
        // Unread or still raw: the settings saved before stay.
        let Ok(before) = g.refresh() else {
            return;
        };
        let after = *g.saved();
        let Some(m) = self.master.as_ref() else {
            return;
        };
        // The master side reads and sets the slave's settings.
        if let Ok(now) = TerminalSettings::read(m.as_fd()) {
            let wanted = now.with_changed_control_chars(&before, &after);
            if !wanted.same_as(&now) {
                let _ = wanted.apply(m.as_fd());
            }
        }
    }

    fn enter_raw(&mut self) -> io::Result<()> {
        // A test build fails here on request, as a terminal that refuses
        // raw mode would (Codex's review of M2-19).
        envcloak_sys::fail_point("exec.pty.raw")?;
        self.reenter_raw()
    }

    fn resend_size(&mut self) {
        let (Ok(size), Some(m)) = (
            window_size(self.terminal.input.as_fd()),
            self.master.as_ref(),
        ) else {
            return;
        };
        let _ = set_window_size(m.as_fd(), size);
    }

    fn barrier(&mut self, site: &'static str) {
        envcloak_sys::pause_point(site);
    }

    fn resume(&mut self) -> io::Result<()> {
        self.monitor.send(MonitorCommand::Resume)
    }

    fn suspend(&mut self) -> io::Result<()> {
        self.monitor.send(MonitorCommand::Suspend)
    }

    fn end_input(&mut self) {
        self.input_open = false;
        self.raw_wanted = false;
        self.drop_keys();
    }
}

/// The idle deadline is independent of reader scheduling. An explicit time
/// lets tests exercise the deadline and a subsequent read without sleeps.
fn flush_idle_at(
    now: Instant,
    deadline: &mut Option<Instant>,
    stream: &mut StreamRedactor<'_>,
    out: &mut Vec<u8>,
) -> bool {
    if deadline.is_some_and(|d| d <= now) {
        *deadline = None;
        stream.flush_idle(out);
        true
    } else {
        false
    }
}

/// A signal ends the drain, keeping a monitor loss distinct from an exit.
fn signal_end(lost: bool, sig: i32) -> End {
    if lost {
        End::MonitorLost
    } else {
        End::Stopped(sig)
    }
}

/// Writes as far as the sink takes input, retaining only unsent bytes.
fn write_keys_to(
    writer: &mut impl Write,
    keys: &mut [u8],
    at: &mut usize,
    len: usize,
) -> io::Result<()> {
    while *at < len {
        match writer.write(keys.get(*at..len).unwrap_or_default()) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                let end = at.saturating_add(n).min(len);
                if let Some(sent) = keys.get_mut(*at..end) {
                    sent.zeroize();
                }
                *at = end;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Discards unread input on every end path, including bytes never sent.
fn discard_keys(keys: &mut [u8], at: &mut usize, len: &mut usize) {
    // The slice, not the vector: its length stays INPUT_CHUNK for reuse.
    keys.zeroize();
    *at = 0;
    *len = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_deadline_releases_at_40_ms_and_restarts_after_a_read() {
        let value =
            SecretBytes::copy_from(format!("pending-{:032x}", std::process::id()).as_bytes());
        let slug = envcloak_core::vault::Slug::new("fixture/t").unwrap();
        let (redactor, _) = crate::build_pty_redactor(&[crate::Label {
            slug: &slug,
            value: &value,
            short: crate::ShortPolicy::Refuse,
        }])
        .unwrap();
        let mut stream = redactor.stream();
        let mut out = Vec::new();
        let start = Instant::now();
        let mut deadline = Some(start + crate::IDLE_FLUSH);
        stream.push(b"Prompt: ", &mut out);
        assert!(out.is_empty());
        assert!(!flush_idle_at(
            start + Duration::from_millis(39),
            &mut deadline,
            &mut stream,
            &mut out
        ));
        assert!(out.is_empty());
        assert!(flush_idle_at(
            start + Duration::from_millis(40),
            &mut deadline,
            &mut stream,
            &mut out
        ));
        assert_eq!(out, b"Prompt: ");
        assert!(!flush_idle_at(
            start + Duration::from_millis(80),
            &mut deadline,
            &mut stream,
            &mut out
        ));
        out.clear();
        stream.push(b"Next", &mut out);
        deadline = Some(start + Duration::from_millis(100) + crate::IDLE_FLUSH);
        stream.push(b": ", &mut out);
        deadline.replace(start + Duration::from_millis(120) + crate::IDLE_FLUSH);
        assert!(!flush_idle_at(
            start + Duration::from_millis(140),
            &mut deadline,
            &mut stream,
            &mut out
        ));
        assert!(out.is_empty());
        assert!(flush_idle_at(
            start + Duration::from_millis(160),
            &mut deadline,
            &mut stream,
            &mut out
        ));
        assert_eq!(out, b"Next: ");
    }

    #[test]
    fn a_partial_input_write_wipes_only_sent_bytes_before_backpressure() {
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    self.0.extend_from_slice(&bytes[..2]);
                    Ok(2)
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let original = [0x61, 0xff, 0, 0x1b, 0xe2, 0x82];
        let mut keys = original;
        let mut at = 0;
        let mut sink = Partial(Vec::new());
        let err = write_keys_to(&mut sink, &mut keys, &mut at, original.len()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(sink.0, original[..2]);
        assert_eq!(at, 2);
        assert_eq!(&keys[..2], &[0, 0]);
        assert_eq!(&keys[2..], &original[2..]);
        let mut rest = Vec::new();
        write_keys_to(&mut rest, &mut keys, &mut at, original.len()).unwrap();
        assert_eq!(rest, original[2..]);
        assert_eq!(keys, [0; 6]);
    }

    #[test]
    fn discarding_input_wipes_unsent_bytes_and_resets_both_cursors() {
        for (mut at, mut len) in [(0, 6), (2, 6), (0, 0), (6, 6), (0, 3)] {
            let mut keys = Zeroizing::new(vec![0x61, 0xff, 0, 0x1b, 0xe2, 0x82]);
            keys[..at].zeroize();
            discard_keys(&mut keys, &mut at, &mut len);
            assert_eq!(&keys[..], &[0; 6], "discard retained input");
            assert_eq!((at, len), (0, 0), "discard retained a cursor");
            // The allocation remains writable at its original size.
            keys.copy_from_slice(&[0x62, 0x1a, 0x7f, 0xc3, 0xa9, 0]);
            len = keys.len();
            discard_keys(&mut keys, &mut at, &mut len);
            assert_eq!(&keys[..], &[0; 6]);
            assert_eq!((at, len), (0, 0));
        }
    }

    #[test]
    fn monitor_loss_survives_each_signal_during_the_drain() {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
            assert!(matches!(signal_end(true, sig), End::MonitorLost));
            assert!(matches!(signal_end(false, sig), End::Stopped(s) if s == sig));
        }
    }

    #[test]
    fn monitor_loss_survives_each_signal_at_the_result_boundary() {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
            assert!(matches!(
                late_result(Err(ExecError::MonitorLost), Some(sig)),
                Err(ExecError::MonitorLost)
            ));
            assert!(
                matches!(late_result(Ok(ChildExit::Code(3)), Some(sig)), Ok(ChildExit::Stopped(s)) if s == sig)
            );
            assert!(matches!(
                late_result(
                    Err(ExecError::TerminalLost(io::ErrorKind::Other)),
                    Some(sig)
                ),
                Err(ExecError::TerminalLost(_))
            ));
        }
    }
}
