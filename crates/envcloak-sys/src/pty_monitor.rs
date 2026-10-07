//! The PTY monitor (M2 plan D-35; review F-76): the process that leads the
//! command's session in `envcloak run --pty`, and its control protocol.
//!
//! A command that leads a new session of its own, with its parent outside
//! that session, is an orphaned process group: the suspend character
//! typed on its terminal makes the line discipline send it SIGTSTP, and
//! an orphaned group does not stop on SIGTSTP. So the command never leads
//! the session. [`crate::pty::spawn_session`] forks this monitor, which:
//!
//! 1. blocks every signal and resets every disposition to its default
//!    (the CLI's handlers would write into the CLI's own pipes), starts a
//!    new session (`setsid`), puts the PTY's slave side on descriptors 0,
//!    1 and 2 and the control channel on 3, closes every other descriptor
//!    (or, where it cannot show it did, reports `SetupFailed` and starts
//!    nothing), and takes the slave as its controlling terminal
//!    (`TIOCSCTTY`);
//! 2. ignores the terminal's job-control signals (SIGTTOU, so its own
//!    `tcsetpgrp` works from the background; SIGTTIN, SIGTSTP) and SIGPIPE,
//!    and catches the four signals the CLI forwards (SIGINT, SIGQUIT,
//!    SIGTERM, SIGHUP) to pass them on to the command's group: `TIOCSIG`
//!    signals whatever group is in the foreground, which is the monitor's
//!    own while the command is stopped, so a signal the CLI forwards as the
//!    command stops reaches the monitor, and goes on to the command from
//!    there. A hangup reaches the monitor too, as the session's leader (the
//!    CLI gone), and is passed on the same way. None of them ends the
//!    monitor: it ends when the CLI's end of the control channel closes;
//! 3. forks the command, which makes its own process group
//!    (`setpgid(0, 0)`) the slave's foreground group (`tcsetpgrp`, SIGTTOU
//!    still ignored and every signal blocked), resets every disposition
//!    and its signal mask, closes the control channel, and execs: the
//!    descriptors it starts with are 0, 1 and 2, the slave. The monitor
//!    sets the command's group too, closing the race. The command's parent,
//!    the monitor, is in the same session but another group, so the
//!    command's group is not orphaned and the suspend character stops it;
//! 4. wipes its copy of the strings prepared for the exec (the paths,
//!    argv and the environment with the values), which it needs no more,
//!    reports `Started` (or `ExecFailed` with the `errno` of the last
//!    `execve`, through a close-on-exec pipe) and then loops: it waits on
//!    its own child only, through `waitid` (stops and continues consumed,
//!    an exit observed without reaping and counted only when the record
//!    is an exit, since macOS returns a stop there too), and on the
//!    control channel.
//!
//! In the loop:
//!
//! - **The command stops** (`Stopped(signal)`): the monitor takes the
//!   slave's foreground back for its own group and reports it.
//! - **`Resume`**: the monitor gives the foreground back to the command's
//!   group (`tcsetpgrp`) and only then sends it SIGCONT. Sent the other
//!   way round, a command that resumes inside a read of the terminal finds
//!   itself in the background and stops again on SIGTTIN.
//! - **`Suspend`**: SIGTSTP to the command's group (the CLI got SIGTSTP
//!   from another process, and stops the command before it restores the
//!   outer terminal).
//! - **`Signal(n)`**: `n` to the command's group, the one signal route the
//!   monitor itself has (the job while the command is stopped, or a
//!   signal narrowed, D-35).
//! - **SIGINT, SIGQUIT, SIGTERM or SIGHUP received**: passed on to the
//!   command's group, once each time it arrives (a signal that arrives
//!   twice before the monitor looks is passed on once, as the kernel
//!   merges a pending signal).
//! - **The command continues** (`Continued`) or **exits** (`Exited`): an
//!   exit is observed with `WNOWAIT`, so the command stays unreaped and
//!   its group's number cannot be reused: `Signal(n)` still reaches what
//!   is left of the group. The monitor reports the status at once, so the
//!   CLI's 2-second cutoff for a descendant's output counts from the exit;
//!   then it waits (up to 2 s, inside that cutoff) until the master side
//!   has read what the command wrote, since macOS discards unread output
//!   at the slave's last close, closes its slave descriptors (so the
//!   master sees the end once no descendant holds the slave), and reaps
//!   the command when the CLI closes the channel. The CLI reads the
//!   master while it waits for reports and after the exit's.
//! - **The channel ends** while the command runs (the CLI is gone): SIGHUP
//!   then SIGCONT to the command's group, as a hangup would, and the
//!   monitor waits for the command to exit before it reaps it and exits.
//!
//! Every signal the monitor sends goes to the group of its own unreaped
//! child, through its [`OwnedChild`] handle, which the reap consumes
//! (D-34). The monitor runs in a child of a multi-threaded process,
//! so between `fork` and `_exit` it calls only system calls on the
//! async-signal-safe list (`sigprocmask`, `sigaction`, `setsid`, `fcntl`,
//! `dup2`, `open`, `close`, `ioctl`, `pipe`, `fork`, `setpgid`,
//! `tcsetpgrp`, `getpid`, `read`, `write`, `recv`, `waitid`, `waitpid`,
//! `pselect`, `kill`, `execve`, `_exit`, `clock_gettime`, `nanosleep`,
//! plus the system calls `close_range` and `getdents64` on Linux and
//! `proc_pidinfo` on macOS; its signal handlers only set an atomic): no
//! allocation, no lock, no panic path. A test allocator
//! that aborts in any process but the one that installed it runs a stop,
//! resume and exit cycle through it
//! (`crates/envcloak-sys/tests/pty_topology.rs`). The loop itself is
//! written against [`MonitorOps`], so a recording model checks what it
//! signals and in which order.
//!
//! SIGCHLD and the four relayed signals stay blocked except inside
//! `pselect`, which unblocks them atomically, so a child that changes
//! state, or a signal that arrives, between the monitor's last look and
//! its wait still wakes it. A one-second tick backs that up
//! where a system does not raise SIGCHLD for a continue.
//!
//! **The control protocol.** Fixed frames of [`FRAME`] bytes: a tag, a
//! marker byte, two zero bytes and a little-endian `i32`. Anything else is
//! not a frame: the monitor ignores a command it cannot read, and the CLI
//! treats a report it cannot read as the monitor lost. [`decode_command`]
//! and [`decode_report`] are the only readers.

use std::ffi::c_char;
#[cfg(feature = "testing")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::owned::OwnedChild;

/// The size of every control frame.
pub const FRAME: usize = 8;
/// The second byte of every frame.
const MARK: u8 = 0xec;

/// A report from the monitor to the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// The command started: its pid.
    Started(i32),
    /// The monitor could not set the session up: the `errno`.
    SetupFailed(i32),
    /// No candidate path could be executed: the `errno` of the last
    /// `execve`, or `EACCES` when one was refused for permission.
    ExecFailed(i32),
    /// The command stopped, on this signal.
    Stopped(i32),
    /// The command continued.
    Continued,
    /// The command exited: its raw wait status.
    Exited(i32),
}

/// A command from the CLI to the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Give the command the terminal back, then continue it.
    Resume,
    /// Stop the command (SIGTSTP to its group).
    Suspend,
    /// Send this signal to the command's group.
    Signal(i32),
}

const R_STARTED: u8 = 1;
const R_SETUP_FAILED: u8 = 2;
const R_EXEC_FAILED: u8 = 3;
const R_STOPPED: u8 = 4;
const R_CONTINUED: u8 = 5;
const R_EXITED: u8 = 6;
const C_RESUME: u8 = 0x41;
const C_SUSPEND: u8 = 0x42;
const C_SIGNAL: u8 = 0x43;

/// The signals `Signal(n)` may carry: the four the CLI forwards, and
/// SIGKILL and SIGCONT for its cleanup.
pub fn signal_allowed(sig: i32) -> bool {
    [
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGKILL,
        libc::SIGCONT,
    ]
    .contains(&sig)
}

fn frame(tag: u8, value: i32) -> [u8; FRAME] {
    let v = value.to_le_bytes();
    [tag, MARK, 0, 0, v[0], v[1], v[2], v[3]]
}

fn unframe(bytes: &[u8]) -> Option<(u8, i32)> {
    let b: &[u8; FRAME] = bytes.try_into().ok()?;
    if b[1] != MARK || b[2] != 0 || b[3] != 0 {
        return None;
    }
    Some((b[0], i32::from_le_bytes([b[4], b[5], b[6], b[7]])))
}

/// The frame for `report`.
pub fn encode_report(report: Report) -> [u8; FRAME] {
    match report {
        Report::Started(pid) => frame(R_STARTED, pid),
        Report::SetupFailed(e) => frame(R_SETUP_FAILED, e),
        Report::ExecFailed(e) => frame(R_EXEC_FAILED, e),
        Report::Stopped(sig) => frame(R_STOPPED, sig),
        Report::Continued => frame(R_CONTINUED, 0),
        Report::Exited(status) => frame(R_EXITED, status),
    }
}

/// Reads one report frame; `None` for anything that is not one: a wrong
/// length, marker or padding, an unknown tag, or a value out of range (a
/// pid below 2, an `errno` or signal outside 1 to 127, a continue with a
/// value).
pub fn decode_report(bytes: &[u8]) -> Option<Report> {
    let (tag, v) = unframe(bytes)?;
    let small = (1..=127).contains(&v);
    match tag {
        R_STARTED if v >= 2 => Some(Report::Started(v)),
        R_SETUP_FAILED if small => Some(Report::SetupFailed(v)),
        R_EXEC_FAILED if small => Some(Report::ExecFailed(v)),
        R_STOPPED if small => Some(Report::Stopped(v)),
        R_CONTINUED if v == 0 => Some(Report::Continued),
        R_EXITED if exit_status_valid(v) => Some(Report::Exited(v)),
        _ => None,
    }
}

/// Whether `v` is a wait status for an exit (a code in bits 8 to 15,
/// nothing else) or a death by a signal (1 to 127, with or without the
/// core flag), the only two an exit is reported with.
fn exit_status_valid(v: i32) -> bool {
    let exited = v & !0xff00 == 0;
    let killed = (1..=0x7f).contains(&(v & 0x7f)) && v & !0xff == 0;
    exited || killed
}

/// The frame for `command`.
pub fn encode_command(command: Command) -> [u8; FRAME] {
    match command {
        Command::Resume => frame(C_RESUME, 0),
        Command::Suspend => frame(C_SUSPEND, 0),
        Command::Signal(sig) => frame(C_SIGNAL, sig),
    }
}

/// Reads one command frame; `None` for anything that is not one, and for
/// a signal [`signal_allowed`] does not allow.
pub fn decode_command(bytes: &[u8]) -> Option<Command> {
    let (tag, v) = unframe(bytes)?;
    match tag {
        C_RESUME if v == 0 => Some(Command::Resume),
        C_SUSPEND if v == 0 => Some(Command::Suspend),
        C_SIGNAL if signal_allowed(v) => Some(Command::Signal(v)),
        _ => None,
    }
}

/// A change in the command's state, as `waitid` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildChange {
    Stopped(i32),
    Continued,
    /// The raw wait status; the command is still unreaped.
    Exited(i32),
}

/// What a read of the control channel found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlRead {
    /// This many bytes.
    Data(usize),
    /// The CLI's end is closed.
    End,
    /// Nothing to read now.
    Nothing,
}

/// What the monitor's loop reads and does, so a recording model can stand
/// in for the system in tests. The real one ([`SysOps`]) makes one system
/// call per method and allocates nothing.
pub(crate) trait MonitorOps {
    /// The command's next stop or continue (consumed), or its exit
    /// (observed without reaping); `None` when nothing changed.
    fn child_change(&mut self) -> Option<ChildChange>;
    /// Reads what the control channel holds now into `buf`, without
    /// waiting.
    fn read_control(&mut self, buf: &mut [u8]) -> ControlRead;
    /// Writes one report; false when the channel is gone.
    fn write_control(&mut self, frame: &[u8; FRAME]) -> bool;
    /// Waits until the control channel (when `control` is true) has
    /// something to read, a signal arrives (SIGCHLD), or the tick passes.
    fn wait(&mut self, control: bool);
    /// Makes `pgid` the slave's foreground process group.
    fn set_foreground(&mut self, pgid: i32);
    /// Sends `sig` to the process group `pgid`.
    fn signal_group(&mut self, pgid: i32, sig: i32);
    /// Closes the monitor's descriptors on the slave.
    fn close_terminal(&mut self);
    /// The relayed signals that arrived since the last call, as a set of
    /// bits (`1 << signal`), and forgets them.
    fn received(&mut self) -> u32;
    /// Reaps the command.
    fn reap(&mut self, pid: i32);
}

/// The signals the monitor catches and passes on to the command's group:
/// the four the CLI forwards.
pub(crate) const RELAYED: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

/// The bit [`MonitorOps::received`] sets for `sig`.
pub(crate) fn signal_bit(sig: libc::c_int) -> u32 {
    u32::try_from(sig)
        .ok()
        .and_then(|s| 1u32.checked_shl(s))
        .unwrap_or(0)
}

/// The monitor's loop, from the command's start to its reaping. `me` is
/// the monitor's own process group, `child` the command (which leads its
/// group). Returns the monitor's exit code. Every signal goes to `child`'s
/// group, and none after [`MonitorOps::reap`].
pub(crate) fn run<O: MonitorOps>(ops: &mut O, me: i32, child: i32) -> i32 {
    let mut buf = [0u8; FRAME];
    let mut filled = 0usize;
    let mut control = true;
    let mut exited = false;
    loop {
        while !exited {
            match ops.child_change() {
                None => break,
                Some(ChildChange::Stopped(sig)) => {
                    // Take the terminal back while the command is stopped.
                    ops.set_foreground(me);
                    if control && !ops.write_control(&encode_report(Report::Stopped(sig))) {
                        control = end_of_channel(ops, child, exited);
                    }
                }
                Some(ChildChange::Continued) => {
                    if control && !ops.write_control(&encode_report(Report::Continued)) {
                        control = end_of_channel(ops, child, exited);
                    }
                }
                Some(ChildChange::Exited(status)) => {
                    exited = true;
                    // Reported first, so the CLI's 2-second cutoff for
                    // output still held by a descendant counts from the
                    // exit, and the monitor's wait below for the CLI to
                    // read the command's last output runs inside it rather
                    // than before it (M2-19: one deadline, never two in a
                    // row).
                    if control && !ops.write_control(&encode_report(Report::Exited(status))) {
                        control = false;
                    }
                    ops.close_terminal();
                }
            }
        }
        // A forwarded signal that reached the monitor (its group held the
        // terminal) goes on to the command's group; its leader is
        // unreaped, so the number is still its own after its exit.
        let received = ops.received();
        for sig in RELAYED {
            if received & signal_bit(sig) != 0 {
                ops.signal_group(child, sig);
            }
        }
        if exited && !control {
            ops.reap(child);
            return 0;
        }
        if control {
            let free = buf.get_mut(filled..).unwrap_or_default();
            match ops.read_control(free) {
                ControlRead::Data(n) => {
                    filled = filled.saturating_add(n).min(FRAME);
                    if filled == FRAME {
                        filled = 0;
                        if let Some(command) = decode_command(&buf) {
                            act(ops, command, child, exited);
                        }
                    }
                    continue;
                }
                ControlRead::End => {
                    control = end_of_channel(ops, child, exited);
                    continue;
                }
                ControlRead::Nothing => {}
            }
        }
        ops.wait(control);
    }
}

/// The CLI's end of the channel is gone. A running command is hung up, as
/// the terminal's hangup would; the channel is not read again. Returns
/// the channel's new state (closed).
fn end_of_channel<O: MonitorOps>(ops: &mut O, child: i32, exited: bool) -> bool {
    if !exited {
        ops.signal_group(child, libc::SIGHUP);
        ops.signal_group(child, libc::SIGCONT);
    }
    false
}

fn act<O: MonitorOps>(ops: &mut O, command: Command, child: i32, exited: bool) {
    match command {
        Command::Resume if !exited => {
            // The terminal first, then SIGCONT: continued in the
            // background, a command reading the terminal stops again on
            // SIGTTIN.
            ops.set_foreground(child);
            ops.signal_group(child, libc::SIGCONT);
        }
        Command::Suspend if !exited => ops.signal_group(child, libc::SIGTSTP),
        // The group's leader is unreaped, so its number is still its own
        // even after it exited.
        Command::Signal(sig) => ops.signal_group(child, sig),
        Command::Resume | Command::Suspend => {}
    }
}

/// Everything the forked monitor needs, prepared before the fork (where
/// allocation is allowed): descriptors and C strings.
pub(crate) struct Prepared {
    /// Withhold Started until the owning parent's test kills the monitor.
    /// Read before fork; the monitor never reads environment variables.
    #[cfg(feature = "testing")]
    pub lose_start_report: bool,
    /// The PTY's slave side.
    pub slave: libc::c_int,
    /// The monitor's end of the control channel.
    pub control: libc::c_int,
    /// The paths to try, in order, each NUL-terminated.
    pub programs: *const *const c_char,
    pub program_count: usize,
    /// argv and envp, NULL-terminated arrays of NUL-terminated strings.
    pub argv: *const *const c_char,
    pub envp: *const *const c_char,
}

/// The real system: system calls on the monitor's own descriptors (the
/// slave on 0 to 2, the channel on 3) and its own child.
struct SysOps {
    child: libc::pid_t,
    /// The handle every signal and the reap go through; `None` once reaped.
    owned: Option<OwnedChild>,
}

const CONTROL_FD: libc::c_int = 3;
/// How long the monitor waits before it looks at its child again with
/// nothing else to wake it, in seconds.
const TICK_SECS: libc::time_t = 1;

fn errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// The raw wait status of an exit record (`si_code` and `si_status`), or
/// `None` for a record that is not an exit ([`crate::child::is_exit_record`]):
/// a stop is never read as a death by its signal.
fn exit_status(code: libc::c_int, status: libc::c_int) -> Option<i32> {
    if !crate::child::is_exit_record(code) {
        return None;
    }
    Some(match code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_DUMPED => (status & 0x7f) | 0x80,
        _ => status & 0x7f,
    })
}

/// One `waitid(P_PID, pid, options | WNOHANG)` on the monitor's own child:
/// the record's `si_code` and `si_status`, or `None` when nothing changed
/// (or the call failed). Async-signal-safe; allocates nothing.
fn waitid_now(pid: libc::pid_t, options: libc::c_int) -> Option<(libc::c_int, libc::c_int)> {
    let id = libc::id_t::try_from(pid).ok()?;
    // SAFETY: siginfo_t is plain data; waitid fills it in, and leaves
    // si_pid 0 when nothing changed.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is writable; the child is the caller's own. WNOHANG
    // makes the call return at once.
    let rc = unsafe { libc::waitid(libc::P_PID, id, &mut info, options | libc::WNOHANG) };
    // SAFETY: waitid filled `info` in or left it zeroed; si_pid and
    // si_status are set for a child's state change.
    if rc == 0 && unsafe { info.si_pid() } == pid {
        // SAFETY: as above.
        return Some((info.si_code, unsafe { info.si_status() }));
    }
    None
}

/// How many times [`next_change`] looks again when its exit observer
/// found a record that is not an exit.
const CHANGE_LOOKS: usize = 4;

/// The command's next change, through `waitid` (one call with `WNOHANG`:
/// [`waitid_now`], or a model's): first its next stop or continue,
/// consumed (`WSTOPPED | WCONTINUED`), so each is reported once; else its
/// exit, observed without reaping (`WEXITED | WNOWAIT`), counted only when
/// the record is an exit. macOS returns a stopped child's unconsumed stop
/// to the second call too (measured on macOS 26.4: `CLD_STOPPED`), when
/// the command stopped after the first call looked; read as an exit, the
/// monitor would report a stop as a death by SIGTSTP, close the slave and
/// then block reaping a command that is only stopped (the verifier's
/// review of PR #27). Such a record sends the loop back to the first call,
/// which consumes and reports the stop. Should it still not settle, `None`:
/// the stop's SIGCHLD is pending, so the monitor's wait returns at once
/// and it looks again. Allocates nothing.
pub(crate) fn next_change(
    mut waitid: impl FnMut(libc::c_int) -> Option<(libc::c_int, libc::c_int)>,
) -> Option<ChildChange> {
    for _ in 0..CHANGE_LOOKS {
        match waitid(libc::WSTOPPED | libc::WCONTINUED) {
            Some((libc::CLD_STOPPED | libc::CLD_TRAPPED, sig)) => {
                return Some(ChildChange::Stopped(sig));
            }
            Some((libc::CLD_CONTINUED, _)) => return Some(ChildChange::Continued),
            _ => {}
        }
        let (code, status) = waitid(libc::WEXITED | libc::WNOWAIT)?;
        if let Some(status) = exit_status(code, status) {
            return Some(ChildChange::Exited(status));
        }
    }
    None
}

impl MonitorOps for SysOps {
    fn child_change(&mut self) -> Option<ChildChange> {
        let child = self.child;
        next_change(|options| waitid_now(child, options))
    }

    fn read_control(&mut self, buf: &mut [u8]) -> ControlRead {
        if buf.is_empty() {
            return ControlRead::Nothing;
        }
        loop {
            // SAFETY: `buf` is writable for its length; MSG_DONTWAIT makes
            // this one call not wait.
            let n = unsafe {
                libc::recv(
                    CONTROL_FD,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            match usize::try_from(n) {
                Ok(0) => return ControlRead::End,
                Ok(n) => return ControlRead::Data(n),
                Err(_) => match errno() {
                    libc::EINTR => {}
                    libc::EAGAIN => return ControlRead::Nothing,
                    _ => return ControlRead::End,
                },
            }
        }
    }

    fn write_control(&mut self, frame: &[u8; FRAME]) -> bool {
        let mut done = 0usize;
        while let Some(rest) = frame.get(done..).filter(|r| !r.is_empty()) {
            // SAFETY: `rest` is readable for its length. SIGPIPE is
            // ignored, so a closed channel fails with EPIPE.
            let n = unsafe { libc::write(CONTROL_FD, rest.as_ptr().cast(), rest.len()) };
            match usize::try_from(n) {
                Ok(n) if n > 0 => done = done.saturating_add(n),
                Ok(_) => return false,
                Err(_) if errno() == libc::EINTR => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn wait(&mut self, control: bool) {
        // SAFETY: fd_set is plain data; FD_ZERO initializes it.
        let mut read: libc::fd_set = unsafe { std::mem::zeroed() };
        // SAFETY: `read` is a writable fd_set, and CONTROL_FD is below
        // FD_SETSIZE.
        unsafe {
            libc::FD_ZERO(&mut read);
            if control {
                libc::FD_SET(CONTROL_FD, &mut read);
            }
        }
        let tick = libc::timespec {
            tv_sec: TICK_SECS,
            tv_nsec: 0,
        };
        // SAFETY: sigset_t is plain data; sigemptyset initializes it.
        let mut none: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `none` is writable.
        unsafe { libc::sigemptyset(&mut none) };
        // SAFETY: every pointer is to an initialized local. pselect
        // unblocks SIGCHLD (every signal) for the wait only, atomically,
        // so one that arrived since the last waitid interrupts it at once.
        unsafe {
            libc::pselect(
                CONTROL_FD + 1,
                &mut read,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &tick,
                &none,
            )
        };
    }

    fn set_foreground(&mut self, pgid: i32) {
        // SAFETY: tcsetpgrp on the slave, the monitor's controlling
        // terminal; SIGTTOU is ignored, so it works from the background.
        unsafe { libc::tcsetpgrp(0, pgid) };
    }

    fn signal_group(&mut self, pgid: i32, sig: i32) {
        if let Some(owned) = self.owned.as_ref().filter(|_| pgid == self.child) {
            // The group the monitor's unreaped child leads.
            let _ = owned.signal_group(sig);
        }
    }

    fn close_terminal(&mut self) {
        drain_output();
        for fd in 0..=2 {
            // SAFETY: closes the monitor's own descriptors on the slave.
            unsafe { libc::close(fd) };
        }
    }

    fn reap(&mut self, pid: i32) {
        if let Some(owned) = self.owned.take_if(|_| pid == self.child) {
            let _ = owned.reap();
        }
    }

    fn received(&mut self) -> u32 {
        RECEIVED.swap(0, Ordering::SeqCst)
    }
}

/// How long the monitor waits, at the command's exit, for the master side
/// to read what the command wrote before it closes the slave, in
/// milliseconds.
const DRAIN_LIMIT_MS: libc::time_t = 2000;

/// Waits until the master side has read everything written to the slave
/// (`TIOCOUTQ` on the slave is 0), up to [`DRAIN_LIMIT_MS`]. On macOS the
/// monitor's close of the slave can discard output the master has not
/// read yet (measured: macOS's `/bin/cat`, stopped and continued, writes
/// its last line and exits; a reader that comes to it after the monitor's
/// close finds the terminal ended and the line gone). Linux keeps the
/// bytes readable, and reports 0 here at once. Bounded, and started once
/// the exit is reported, so it runs inside the CLI's own 2-second cutoff
/// rather than before it, and a command whose descendants keep writing
/// never holds the run past that cutoff. Async-signal-safe: `ioctl`,
/// `clock_gettime` and `nanosleep` only.
fn drain_output() {
    let now_ms = || {
        // SAFETY: timespec is plain data; clock_gettime fills it in.
        let mut t: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is writable.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
        t.tv_sec
            .saturating_mul(1000)
            .saturating_add(t.tv_nsec / 1_000_000)
    };
    let start = now_ms();
    loop {
        let mut queued: libc::c_int = 0;
        // SAFETY: TIOCOUTQ writes one int: the bytes written to the
        // terminal and not yet read on the master side.
        if unsafe { libc::ioctl(0, libc::TIOCOUTQ as _, &mut queued) } != 0 || queued <= 0 {
            return;
        }
        if now_ms().saturating_sub(start) >= DRAIN_LIMIT_MS {
            return;
        }
        let pause = libc::timespec {
            tv_sec: 0,
            tv_nsec: 5_000_000,
        };
        // SAFETY: `pause` is initialized; the remainder is not wanted.
        unsafe { libc::nanosleep(&pause, std::ptr::null_mut()) };
    }
}

/// Signals reset in the monitor and the command: every one there is.
#[cfg(target_os = "linux")]
const LAST_SIGNAL: libc::c_int = 64;
#[cfg(not(target_os = "linux"))]
const LAST_SIGNAL: libc::c_int = 31;

extern "C" fn on_child(_sig: libc::c_int) {}

/// The relayed signals that arrived, as bits, until the loop takes them.
static RECEIVED: AtomicU32 = AtomicU32::new(0);

/// Notes a relayed signal for the loop. Async-signal-safe: one lock-free
/// atomic operation.
extern "C" fn on_relayed(sig: libc::c_int) {
    RECEIVED.fetch_or(signal_bit(sig), Ordering::SeqCst);
}

/// Sets `sig`'s disposition to `handler` (`SIG_DFL`, `SIG_IGN` or a
/// function), with no flags: no `SA_RESTART`, so a wait it interrupts
/// returns.
fn disposition(sig: libc::c_int, handler: libc::sighandler_t) {
    // SAFETY: sigaction is plain data; zeroed is an empty mask and no
    // flags.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler;
    // SAFETY: `act` is initialized; a signal that cannot be changed fails
    // without effect.
    unsafe { libc::sigaction(sig, &act, std::ptr::null_mut()) };
}

fn set_mask(how: libc::c_int, all: bool, only: &[libc::c_int]) {
    // SAFETY: sigset_t is plain data, initialized by sigfillset or
    // sigemptyset before use.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is writable; sigprocmask only reads it.
    unsafe {
        if all {
            libc::sigfillset(&mut set);
        } else {
            libc::sigemptyset(&mut set);
        }
        for sig in only {
            libc::sigaddset(&mut set, *sig);
        }
        libc::sigprocmask(how, &set, std::ptr::null_mut());
    }
}

/// Whether a test asked for the primary way of closing descriptors to be
/// passed over (`crate::testing::force_descriptor_fallback`), so the way
/// after it is the one tested. Always false outside the `testing` feature.
fn primary_closing_passed_over() -> bool {
    #[cfg(feature = "testing")]
    {
        crate::testing::DESCRIPTOR_FALLBACK.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "testing"))]
    {
        false
    }
}

/// Closes every descriptor from `low` up, and says so only once it can
/// tell: on Linux `close_range`, and where that fails (before 5.9) the
/// descriptors `/proc/self/fd` lists, read with `getdents64` until a pass
/// finds none; on macOS the descriptors `proc_pidinfo` lists, until a pass
/// finds none. A bound such as `RLIMIT_NOFILE` is never trusted: a
/// descriptor opened before the limit was lowered sits above it (Codex's
/// review of PR #27). `Err(errno)` when no listing could be read: the
/// monitor then refuses to start the command.
fn close_from(low: libc::c_int) -> Result<(), libc::c_int> {
    #[cfg(target_os = "linux")]
    {
        if !primary_closing_passed_over() {
            // SAFETY: close_range closes descriptors and has no other
            // effect.
            let rc = unsafe { libc::syscall(libc::SYS_close_range, low, libc::c_uint::MAX, 0) };
            if rc == 0 {
                return Ok(());
            }
        }
        close_listed_linux(low)
    }
    #[cfg(target_os = "macos")]
    {
        if primary_closing_passed_over() {
            return Err(libc::ENOTSUP);
        }
        close_listed_macos(low)
    }
}

/// Closes the descriptors from `low` up that `/proc/self/fd` lists, pass
/// after pass, until a pass finds none but the listing's own.
/// Async-signal-safe: `open`, `getdents64` and `close`, on a stack buffer.
#[cfg(target_os = "linux")]
fn close_listed_linux(low: libc::c_int) -> Result<(), libc::c_int> {
    const DIR: &[u8] = b"/proc/self/fd\0";
    loop {
        // SAFETY: DIR is NUL-terminated; open has no other effect.
        let dir = unsafe {
            libc::open(
                DIR.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if dir < 0 {
            return Err(errno());
        }
        let mut found = false;
        let mut buf = [0u8; 2048];
        let result = loop {
            // SAFETY: `buf` is writable for its length; getdents64 fills it
            // with whole records.
            let n =
                unsafe { libc::syscall(libc::SYS_getdents64, dir, buf.as_mut_ptr(), buf.len()) };
            let Ok(n) = usize::try_from(n) else {
                break Err(errno());
            };
            if n == 0 {
                break Ok(());
            }
            let mut at = 0usize;
            while let Some(record) = buf.get(at..n) {
                // linux_dirent64: d_ino (8), d_off (8), d_reclen (2),
                // d_type (1), then the NUL-terminated name.
                let Some(len) = record
                    .get(16..18)
                    .map(|b| usize::from(u16::from_ne_bytes([b[0], b[1]])))
                else {
                    break;
                };
                if len == 0 {
                    break;
                }
                let name = record.get(19..len.min(record.len())).unwrap_or_default();
                let mut fd: libc::c_int = 0;
                let mut digits = 0usize;
                for b in name.iter().take_while(|b| **b != 0) {
                    if !b.is_ascii_digit() {
                        digits = 0;
                        break;
                    }
                    fd = fd
                        .saturating_mul(10)
                        .saturating_add(libc::c_int::from(b - b'0'));
                    digits += 1;
                }
                if digits > 0 && fd >= low && fd != dir {
                    found = true;
                    // SAFETY: closes one of this process's descriptors.
                    unsafe { libc::close(fd) };
                }
                at = at.saturating_add(len);
            }
        };
        // SAFETY: the listing's own descriptor.
        unsafe { libc::close(dir) };
        result?;
        if !found {
            return Ok(());
        }
    }
}

/// Closes the descriptors from `low` up that `proc_pidinfo` lists, pass
/// after pass, until a pass finds none. One system call per pass (a loop
/// up to the limit would be a million calls where the limit is a
/// million). Async-signal-safe.
#[cfg(target_os = "macos")]
fn close_listed_macos(low: libc::c_int) -> Result<(), libc::c_int> {
    const ENTRIES: usize = 256;
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let size = libc::c_int::try_from(ENTRIES * entry).unwrap_or(0);
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() };
    loop {
        // SAFETY: proc_fdinfo is plain data.
        let mut list: [libc::proc_fdinfo; ENTRIES] = unsafe { std::mem::zeroed() };
        // SAFETY: `list` is writable for `size` bytes; proc_pidinfo is one
        // system call that fills it with this process's descriptors.
        let bytes = unsafe {
            libc::proc_pidinfo(me, libc::PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast(), size)
        };
        // A process always has descriptors 0 to 3 here: an empty or a
        // failed listing is no listing.
        let Ok(bytes) = usize::try_from(bytes) else {
            return Err(errno());
        };
        if bytes == 0 {
            return Err(libc::EIO);
        }
        let mut found = false;
        for info in list.iter().take(bytes / entry) {
            if info.proc_fd >= low {
                // SAFETY: closes one of this process's descriptors.
                unsafe { libc::close(info.proc_fd) };
                found = true;
            }
        }
        if !found {
            return Ok(());
        }
    }
}

/// Reports a setup failure on the channel (descriptor 3, wherever it is
/// by then) and ends the monitor.
fn fail(e: libc::c_int) -> ! {
    let f = encode_report(Report::SetupFailed(e));
    // SAFETY: writes the frame from a local; the process then ends.
    unsafe {
        libc::write(CONTROL_FD, f.as_ptr().cast(), FRAME);
        libc::_exit(125)
    }
}

/// The monitor, in the child `fork` returned. Never returns.
///
/// # Safety
/// Called only in a new child of `fork`, with `p`'s pointers valid (the
/// fork copied what they point to). Calls only async-signal-safe
/// functions and never allocates.
pub(crate) unsafe fn monitor_main(p: &Prepared) -> ! {
    // 1. No signal arrives while the dispositions change; each is reset,
    //    so none of the CLI's handlers runs here.
    set_mask(libc::SIG_SETMASK, true, &[]);
    for sig in 1..=LAST_SIGNAL {
        if sig != libc::SIGKILL && sig != libc::SIGSTOP {
            disposition(sig, libc::SIG_DFL);
        }
    }
    // 2. A new session, and the descriptors: the slave on 0, 1 and 2, the
    //    channel on 3, nothing else.
    // SAFETY: setsid has no preconditions; a fresh child of fork does not
    // lead a group, so it succeeds.
    let ok = unsafe {
        libc::setsid() >= 0 && {
            let s = libc::fcntl(p.slave, libc::F_DUPFD, 10);
            let c = libc::fcntl(p.control, libc::F_DUPFD, 10);
            s >= 0
                && c >= 0
                && libc::dup2(s, 0) == 0
                && libc::dup2(s, 1) == 1
                && libc::dup2(s, 2) == 2
                && libc::dup2(c, CONTROL_FD) == CONTROL_FD
        }
    };
    if !ok {
        let e = errno();
        // SAFETY: puts the channel on 3 if it can, for the report.
        unsafe { libc::dup2(p.control, CONTROL_FD) };
        fail(e);
    }
    if let Err(e) = close_from(CONTROL_FD + 1) {
        fail(e);
    }
    // SAFETY: F_SETFD on the monitor's own descriptor: the command does not
    // inherit the channel. TIOCSCTTY with 0 takes the slave as the
    // controlling terminal of the session this process leads, stealing
    // none.
    let ok = unsafe {
        libc::fcntl(CONTROL_FD, libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::ioctl(0, libc::TIOCSCTTY as _, 0) == 0
    };
    if !ok {
        fail(errno());
    }
    // 3. What the monitor ignores, what it passes on to the command, and
    //    SIGCHLD to interrupt its wait.
    for sig in [libc::SIGTTOU, libc::SIGTTIN, libc::SIGTSTP, libc::SIGPIPE] {
        disposition(sig, libc::SIG_IGN);
    }
    for sig in RELAYED {
        disposition(
            sig,
            on_relayed as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
    disposition(
        libc::SIGCHLD,
        on_child as extern "C" fn(libc::c_int) as libc::sighandler_t,
    );
    // 4. The exec-error pipe, close-on-exec at both ends.
    let mut pipe = [-1 as libc::c_int; 2];
    // SAFETY: `pipe` has room for two descriptors; F_SETFD on the new
    // descriptors only.
    let ok = unsafe {
        libc::pipe(pipe.as_mut_ptr()) == 0
            && libc::fcntl(pipe[0], libc::F_SETFD, libc::FD_CLOEXEC) == 0
            && libc::fcntl(pipe[1], libc::F_SETFD, libc::FD_CLOEXEC) == 0
    };
    if !ok {
        fail(errno());
    }
    let [err_read, err_write] = pipe;
    // 5. The command.
    // SAFETY: fork in this single-threaded process.
    let child = unsafe { libc::fork() };
    if child < 0 {
        fail(errno());
    }
    if child == 0 {
        // SAFETY: a new child of fork, with `p`'s pointers valid.
        unsafe { command_main(p, err_read, err_write) };
    }
    // SAFETY: setpgid and tcsetpgrp on the monitor's own child and
    // terminal; either may have been done by the child already, and an
    // error then changes nothing.
    unsafe {
        libc::setpgid(child, child);
        libc::tcsetpgrp(0, child);
        libc::close(err_write);
    }
    let mut code = [0u8; 4];
    let mut got = 0usize;
    while got < code.len() {
        let rest = code.get_mut(got..).unwrap_or_default();
        // SAFETY: `rest` is writable for its length.
        let n = unsafe { libc::read(err_read, rest.as_mut_ptr().cast(), rest.len()) };
        match usize::try_from(n) {
            Ok(0) => break,
            Ok(n) => got = got.saturating_add(n),
            Err(_) if errno() == libc::EINTR => {}
            Err(_) => break,
        }
    }
    // SAFETY: the monitor's own descriptor.
    unsafe { libc::close(err_read) };
    // The command has executed, or could not be: the monitor needs none of
    // the strings prepared for it, values included, and wipes its copy now
    // rather than keep it for the session's life.
    // SAFETY: `p`'s pointers are valid in this process's copy of the CLI's
    // memory, the strings NUL-terminated and writable.
    unsafe { wipe_prepared(p) };
    #[cfg(feature = "testing")]
    {
        // SAFETY: as above.
        if !unsafe { prepared_wiped(p) } {
            PREPARED_KEPT.store(true, Ordering::SeqCst);
        }
    }
    let mut ops = SysOps {
        child,
        owned: Some(OwnedChild::from_fork_without_pidfd(child)),
    };
    if got > 0 {
        let e = i32::from_ne_bytes(code);
        ops.reap(child);
        let e = if (1..=127).contains(&e) { e } else { libc::EIO };
        ops.write_control(&encode_report(Report::ExecFailed(e)));
        exit_monitor(0);
    }
    // A channel already gone shows as its end at the loop's first read.
    #[cfg(feature = "testing")]
    let report_started = !p.lose_start_report;
    #[cfg(not(feature = "testing"))]
    let report_started = true;
    if report_started {
        ops.write_control(&encode_report(Report::Started(child)));
    }
    // 6. SIGCHLD and the relayed signals blocked outside pselect;
    //    everything else unblocked.
    set_mask(
        libc::SIG_SETMASK,
        false,
        &[
            libc::SIGCHLD,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGHUP,
        ],
    );
    // SAFETY: getpid has no preconditions; the monitor leads its session,
    // so its pid is its group.
    let me = unsafe { libc::getpid() };
    let code = run(&mut ops, me, child);
    exit_monitor(code)
}

/// The exit code a monitor built with the `testing` feature ends with when
/// a string prepared for the command was still there after
/// [`wipe_prepared`], so a test sees it in [`crate::pty::SessionMonitor::finish`].
#[cfg(feature = "testing")]
pub const PREPARED_KEPT_EXIT: i32 = 86;

/// Set in a monitor built with the `testing` feature when a prepared string
/// was not wiped.
#[cfg(feature = "testing")]
static PREPARED_KEPT: AtomicBool = AtomicBool::new(false);

/// Ends the monitor with `code` (with the `testing` feature,
/// [`PREPARED_KEPT_EXIT`] instead when a prepared string was kept).
fn exit_monitor(code: i32) -> ! {
    #[cfg(feature = "testing")]
    let code = if PREPARED_KEPT.load(Ordering::SeqCst) {
        PREPARED_KEPT_EXIT
    } else {
        code
    };
    // SAFETY: ends the monitor.
    unsafe { libc::_exit(code) }
}

/// Overwrites with zeros every string `p` points to: the candidate paths,
/// argv and envp, the values included. Once the command has executed (or
/// could not be) the monitor needs none of them, and its copy-on-write
/// copy of them would otherwise stay in its memory for the session's life,
/// after the CLI wiped its own (the verifier's review of PR #27). The rest
/// of the monitor's image is the CLI's memory as it was at the fork (see
/// `crate::pty`). Volatile writes, which the compiler keeps;
/// async-signal-safe and allocation-free.
///
/// # Safety
/// `p`'s pointers valid, and each string NUL-terminated and writable (the
/// monitor's copy of buffers the CLI built with `as_mut_ptr`).
unsafe fn wipe_prepared(p: &Prepared) {
    // SAFETY: as the caller promises; each list ends with NULL.
    unsafe {
        wipe_strings(p.programs, p.program_count);
        wipe_strings(p.argv, usize::MAX);
        wipe_strings(p.envp, usize::MAX);
    }
}

/// Wipes the NUL-terminated strings `list` points to, up to `max` of them
/// or its NULL entry, whichever comes first.
///
/// # Safety
/// As [`wipe_prepared`], for `list`.
unsafe fn wipe_strings(list: *const *const c_char, max: usize) {
    for i in 0..max {
        // SAFETY: `list` has a NULL entry at or before `max`, and every
        // entry before it is read here first.
        let s = unsafe { *list.add(i) };
        if s.is_null() {
            return;
        }
        let mut at = s.cast_mut();
        // SAFETY: `at` stays within the string, up to its NUL, which it
        // leaves; the string is writable.
        unsafe {
            while at.read_volatile() != 0 {
                at.write_volatile(0);
                at = at.add(1);
            }
        }
    }
}

/// Whether every string `p` points to starts with a NUL, as
/// [`wipe_prepared`] leaves them (the program's path never does before).
///
/// # Safety
/// As [`wipe_prepared`].
#[cfg(feature = "testing")]
unsafe fn prepared_wiped(p: &Prepared) -> bool {
    let lists = [
        (p.programs, p.program_count),
        (p.argv, usize::MAX),
        (p.envp, usize::MAX),
    ];
    for (list, max) in lists {
        for i in 0..max {
            // SAFETY: as in `wipe_strings`.
            let s = unsafe { *list.add(i) };
            if s.is_null() {
                break;
            }
            // SAFETY: a NUL-terminated string has at least one byte.
            if unsafe { s.read_volatile() } != 0 {
                return false;
            }
        }
    }
    true
}

/// The command, in the child the monitor forked. Never returns.
///
/// # Safety
/// As [`monitor_main`].
unsafe fn command_main(p: &Prepared, err_read: libc::c_int, err_write: libc::c_int) -> ! {
    // Every signal is still blocked (inherited), and SIGTTOU ignored, so
    // taking the foreground from the background works.
    // SAFETY: setpgid, getpid and tcsetpgrp on this process and its
    // controlling terminal (descriptor 0, the slave).
    unsafe {
        libc::setpgid(0, 0);
        libc::tcsetpgrp(0, libc::getpid());
    }
    for sig in 1..=LAST_SIGNAL {
        if sig != libc::SIGKILL && sig != libc::SIGSTOP {
            disposition(sig, libc::SIG_DFL);
        }
    }
    // SAFETY: the monitor's channel and the pipe's read end; the write end
    // is close-on-exec.
    unsafe {
        libc::close(CONTROL_FD);
        libc::close(err_read);
    }
    set_mask(libc::SIG_SETMASK, false, &[]);
    let mut last = libc::ENOENT;
    let mut refused = false;
    for i in 0..p.program_count {
        // SAFETY: `programs` holds `program_count` valid pointers.
        let path = unsafe { *p.programs.add(i) };
        // SAFETY: `path`, `argv` and `envp` are NUL-terminated strings and
        // NULL-terminated arrays prepared before the fork.
        unsafe { libc::execve(path, p.argv, p.envp) };
        last = errno();
        match last {
            libc::EACCES => refused = true,
            libc::ENOENT | libc::ENOTDIR => {}
            _ => break,
        }
    }
    if refused && matches!(last, libc::ENOENT | libc::ENOTDIR) {
        last = libc::EACCES;
    }
    let bytes = last.to_ne_bytes();
    // SAFETY: writes the errno to the pipe the monitor reads, then ends.
    unsafe {
        libc::write(err_write, bytes.as_ptr().cast(), bytes.len());
        libc::_exit(127)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frames_read_back_as_written() {
        for r in [
            Report::Started(4242),
            Report::SetupFailed(libc::EPERM),
            Report::ExecFailed(libc::ENOENT),
            Report::Stopped(libc::SIGTSTP),
            Report::Continued,
            Report::Exited(0),
            Report::Exited(3 << 8),
            Report::Exited(libc::SIGKILL),
            Report::Exited(libc::SIGSEGV | 0x80),
        ] {
            assert_eq!(decode_report(&encode_report(r)), Some(r));
        }
        for c in [
            Command::Resume,
            Command::Suspend,
            Command::Signal(libc::SIGINT),
            Command::Signal(libc::SIGQUIT),
            Command::Signal(libc::SIGTERM),
            Command::Signal(libc::SIGHUP),
            Command::Signal(libc::SIGKILL),
            Command::Signal(libc::SIGCONT),
        ] {
            assert_eq!(decode_command(&encode_command(c)), Some(c));
        }
    }

    #[test]
    fn frames_out_of_range_are_not_frames() {
        assert_eq!(decode_command(&frame(C_SIGNAL, libc::SIGSTOP)), None);
        assert_eq!(decode_command(&frame(C_SIGNAL, libc::SIGUSR1)), None);
        assert_eq!(decode_command(&frame(C_SIGNAL, 0)), None);
        assert_eq!(decode_command(&frame(C_RESUME, 1)), None);
        assert_eq!(decode_command(&frame(R_STARTED, 7)), None);
        assert_eq!(decode_report(&frame(C_RESUME, 0)), None);
        assert_eq!(decode_report(&frame(R_STARTED, 1)), None);
        assert_eq!(decode_report(&frame(R_STOPPED, 0)), None);
        assert_eq!(decode_report(&frame(R_STOPPED, 128)), None);
        assert_eq!(decode_report(&frame(R_CONTINUED, 1)), None);
        assert_eq!(decode_report(&frame(R_EXITED, 0x1_0000)), None);
        assert_eq!(decode_report(&frame(R_EXITED, -1)), None);
        let mut f = encode_report(Report::Continued);
        f[1] = 0;
        assert_eq!(decode_report(&f), None);
        let mut f = encode_command(Command::Resume);
        f[2] = 1;
        assert_eq!(decode_command(&f), None);
        assert_eq!(decode_command(&encode_command(Command::Resume)[..7]), None);
        assert_eq!(decode_report(&[]), None);
    }

    proptest! {
        /// Any bytes: never a panic, and whatever reads as a frame is
        /// written back byte for byte.
        #[test]
        fn any_bytes_read_back_or_are_refused(bytes in proptest::collection::vec(any::<u8>(), 0..16)) {
            if let Some(r) = decode_report(&bytes) {
                prop_assert_eq!(&encode_report(r)[..], &bytes[..]);
            }
            if let Some(c) = decode_command(&bytes) {
                prop_assert_eq!(&encode_command(c)[..], &bytes[..]);
            }
        }
    }

    /// One step of the model: what `child_change` and `read_control`
    /// return next.
    #[derive(Debug, Clone, Copy)]
    enum Step {
        Child(ChildChange),
        Control(Command),
        ControlEnd,
        /// A relayed signal reaches the monitor.
        Received(i32),
    }

    /// What the loop did, in order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Did {
        Report(Report),
        Foreground(i32),
        Signal(i32, i32),
        CloseTerminal,
        Reap(i32),
    }

    struct Model {
        steps: std::collections::VecDeque<Step>,
        pending: Option<[u8; FRAME]>,
        did: Vec<Did>,
        reaped: bool,
        waits: usize,
    }

    impl Model {
        fn new(steps: &[Step]) -> Self {
            Model {
                steps: steps.iter().copied().collect(),
                pending: None,
                did: Vec::new(),
                reaped: false,
                waits: 0,
            }
        }
    }

    impl MonitorOps for Model {
        fn child_change(&mut self) -> Option<ChildChange> {
            // A command half read comes before the steps after it.
            if self.pending.is_some() {
                return None;
            }
            match self.steps.front() {
                Some(Step::Child(c)) => {
                    let c = *c;
                    self.steps.pop_front();
                    Some(c)
                }
                _ => None,
            }
        }
        fn received(&mut self) -> u32 {
            // As for a child's change: a command half read comes first.
            if self.pending.is_some() {
                return 0;
            }
            let mut bits = 0;
            while let Some(Step::Received(sig)) = self.steps.front() {
                bits |= signal_bit(*sig);
                self.steps.pop_front();
            }
            bits
        }
        fn read_control(&mut self, buf: &mut [u8]) -> ControlRead {
            if self.pending.is_none() {
                match self.steps.front() {
                    Some(Step::Control(c)) => {
                        self.pending = Some(encode_command(*c));
                        self.steps.pop_front();
                    }
                    Some(Step::ControlEnd) => {
                        self.steps.pop_front();
                        return ControlRead::End;
                    }
                    _ => return ControlRead::Nothing,
                }
            }
            // Hand the frame over a few bytes at a time.
            let f = self.pending.take().unwrap();
            let (len, n) = (buf.len(), buf.len().min(3));
            buf[..n].copy_from_slice(&f[FRAME - len..FRAME - len + n]);
            if n < len {
                self.pending = Some(f);
            }
            ControlRead::Data(n)
        }
        fn write_control(&mut self, frame: &[u8; FRAME]) -> bool {
            self.did.push(Did::Report(decode_report(frame).unwrap()));
            true
        }
        fn wait(&mut self, _control: bool) {
            self.waits += 1;
            assert!(
                self.waits < 1000,
                "the loop waits for nothing: {:?}",
                self.did
            );
        }
        fn set_foreground(&mut self, pgid: i32) {
            self.did.push(Did::Foreground(pgid));
        }
        fn signal_group(&mut self, pgid: i32, sig: i32) {
            assert!(!self.reaped, "a signal after the reap");
            self.did.push(Did::Signal(pgid, sig));
        }
        fn close_terminal(&mut self) {
            self.did.push(Did::CloseTerminal);
        }
        fn reap(&mut self, pid: i32) {
            self.reaped = true;
            self.did.push(Did::Reap(pid));
        }
    }

    const ME: i32 = 700;
    const CHILD: i32 = 701;

    /// A stop, a resume and an exit: on the stop the monitor takes the
    /// terminal back; on `Resume` it gives the terminal to the command's
    /// group before SIGCONT, which goes only to its unreaped child's
    /// group; the exit closes the slave, is reported, and the command is
    /// reaped only once the CLI closes the channel.
    #[test]
    fn a_resume_gives_the_terminal_back_before_sigcont_to_the_childs_group() {
        let mut m = Model::new(&[
            Step::Child(ChildChange::Stopped(libc::SIGTSTP)),
            Step::Control(Command::Resume),
            Step::Child(ChildChange::Continued),
            Step::Child(ChildChange::Exited(0)),
            Step::ControlEnd,
        ]);
        assert_eq!(run(&mut m, ME, CHILD), 0);
        assert_eq!(
            m.did,
            vec![
                Did::Foreground(ME),
                Did::Report(Report::Stopped(libc::SIGTSTP)),
                Did::Foreground(CHILD),
                Did::Signal(CHILD, libc::SIGCONT),
                Did::Report(Report::Continued),
                Did::Report(Report::Exited(0)),
                Did::CloseTerminal,
                Did::Reap(CHILD),
            ]
        );
    }

    /// Every signal the monitor sends goes to its child's group: a
    /// suspend, a forwarded signal, and one sent after the exit, while the
    /// child is still unreaped. After the reap, nothing (the model fails on
    /// a signal after it).
    #[test]
    fn every_signal_goes_to_the_unreaped_childs_group() {
        let mut m = Model::new(&[
            Step::Control(Command::Suspend),
            Step::Child(ChildChange::Stopped(libc::SIGTSTP)),
            Step::Control(Command::Signal(libc::SIGTERM)),
            Step::Child(ChildChange::Exited(libc::SIGTERM)),
            Step::Control(Command::Signal(libc::SIGKILL)),
            Step::Control(Command::Resume),
            Step::ControlEnd,
        ]);
        assert_eq!(run(&mut m, ME, CHILD), 0);
        let signals: Vec<_> = m
            .did
            .iter()
            .filter_map(|d| match d {
                Did::Signal(g, s) => Some((*g, *s)),
                _ => None,
            })
            .collect();
        assert_eq!(
            signals,
            vec![
                (CHILD, libc::SIGTSTP),
                (CHILD, libc::SIGTERM),
                (CHILD, libc::SIGKILL),
            ],
            "a resume after the exit continues nothing"
        );
        assert_eq!(m.did.last(), Some(&Did::Reap(CHILD)));
    }

    /// The CLI gone while the command runs: the command's group is hung up
    /// and continued, and the monitor reaps it after it exits.
    #[test]
    fn the_end_of_the_channel_hangs_the_command_up() {
        let mut m = Model::new(&[
            Step::ControlEnd,
            Step::Child(ChildChange::Exited(libc::SIGHUP)),
        ]);
        assert_eq!(run(&mut m, ME, CHILD), 0);
        assert_eq!(
            m.did,
            vec![
                Did::Signal(CHILD, libc::SIGHUP),
                Did::Signal(CHILD, libc::SIGCONT),
                Did::CloseTerminal,
                Did::Reap(CHILD),
            ]
        );
    }

    /// A forwarded signal that reaches the monitor (its own group held the
    /// terminal, the command stopped) goes on to the command's group, each
    /// of the four, also after the command's exit and the channel's end
    /// while the command is unreaped (the model fails on a signal after
    /// the reap). Ignore them instead (the monitor before) and the command
    /// never gets them.
    #[test]
    fn a_relayed_signal_goes_on_to_the_childs_group() {
        let mut m = Model::new(&[
            Step::Child(ChildChange::Stopped(libc::SIGTSTP)),
            Step::Received(libc::SIGINT),
            Step::Received(libc::SIGQUIT),
            Step::Control(Command::Resume),
            Step::Received(libc::SIGTERM),
            Step::Child(ChildChange::Exited(libc::SIGTERM)),
            Step::Received(libc::SIGHUP),
            Step::ControlEnd,
            Step::Received(libc::SIGINT),
        ]);
        assert_eq!(run(&mut m, ME, CHILD), 0);
        let signals: Vec<_> = m
            .did
            .iter()
            .filter_map(|d| match d {
                Did::Signal(g, s) => Some((*g, *s)),
                _ => None,
            })
            .collect();
        assert_eq!(
            signals,
            vec![
                (CHILD, libc::SIGINT),
                (CHILD, libc::SIGQUIT),
                (CHILD, libc::SIGCONT),
                (CHILD, libc::SIGTERM),
                (CHILD, libc::SIGHUP),
                (CHILD, libc::SIGINT),
            ],
            "{:?}",
            m.did
        );
        assert_eq!(m.did.last(), Some(&Did::Reap(CHILD)));
        for sig in RELAYED {
            assert_ne!(signal_bit(sig), 0);
        }
        assert_eq!(signal_bit(-1), 0);
        assert_eq!(signal_bit(40), 0);
    }

    /// The loop's schedules with the control frames cut into pieces of
    /// every size from 1 to [`FRAME`] bytes, and reports that fail (the
    /// CLI gone), each against an event order written down separately from
    /// the loop, and each run's record checked by a receipt: every signal
    /// to the command's group and none after the reap, the terminal given
    /// only to the monitor's or the command's group, the slave closed once
    /// and before the reap, exactly one reap and nothing after it. Four
    /// faults put into each passing record (a signal after the reap, one to
    /// another group, a second reap, no reap) must each fail the receipt,
    /// so the receipt can fail. (An independent review oracle, adopted.)
    mod fragmented {
        use super::super::*;
        use std::collections::VecDeque;

        const ME: i32 = 50001;
        const CHILD: i32 = 50002;

        #[derive(Clone)]
        enum Step {
            Child(ChildChange),
            Frame(Vec<u8>),
            End,
        }

        #[derive(Clone, Debug, PartialEq)]
        enum Event {
            Foreground(i32),
            Signal(i32, i32),
            /// The report, and whether its write succeeded.
            Report(Report, bool),
            Close,
            Reap(i32),
        }

        struct Model {
            steps: VecDeque<Step>,
            chunk: usize,
            offset: usize,
            events: Vec<Event>,
            reports: usize,
            /// The report (1-based) whose write fails.
            fail: Option<usize>,
            waits: usize,
        }

        impl MonitorOps for Model {
            fn child_change(&mut self) -> Option<ChildChange> {
                match self.steps.front() {
                    Some(Step::Child(c)) => {
                        let c = *c;
                        self.steps.pop_front();
                        Some(c)
                    }
                    _ => None,
                }
            }
            fn read_control(&mut self, buf: &mut [u8]) -> ControlRead {
                match self.steps.front() {
                    Some(Step::End) => {
                        self.steps.pop_front();
                        ControlRead::End
                    }
                    Some(Step::Frame(f)) => {
                        let n = self.chunk.min(buf.len()).min(f.len() - self.offset);
                        buf[..n].copy_from_slice(&f[self.offset..self.offset + n]);
                        self.offset += n;
                        if self.offset == f.len() {
                            self.steps.pop_front();
                            self.offset = 0;
                        }
                        ControlRead::Data(n)
                    }
                    _ => ControlRead::Nothing,
                }
            }
            fn write_control(&mut self, f: &[u8; FRAME]) -> bool {
                self.reports += 1;
                let ok = self.fail != Some(self.reports);
                self.events
                    .push(Event::Report(decode_report(f).unwrap(), ok));
                ok
            }
            fn wait(&mut self, _: bool) {
                self.waits += 1;
                assert!(
                    self.waits < 4,
                    "a bounded schedule stalled: {:?}",
                    self.events
                );
            }
            fn set_foreground(&mut self, p: i32) {
                self.events.push(Event::Foreground(p));
            }
            fn signal_group(&mut self, p: i32, s: i32) {
                self.events.push(Event::Signal(p, s));
            }
            fn close_terminal(&mut self) {
                self.events.push(Event::Close);
            }
            fn reap(&mut self, p: i32) {
                self.events.push(Event::Reap(p));
            }
            fn received(&mut self) -> u32 {
                0
            }
        }

        fn command(c: Command) -> Step {
            Step::Frame(encode_command(c).to_vec())
        }

        fn receipt_valid(e: &[Event]) -> bool {
            let (mut reaped, mut closed, mut reaps) = (false, false, 0);
            for x in e {
                match x {
                    Event::Signal(p, _) if *p != CHILD || reaped => return false,
                    Event::Foreground(p) if ![ME, CHILD].contains(p) || reaped => return false,
                    Event::Close if closed || reaped => return false,
                    Event::Close => closed = true,
                    Event::Reap(p) => {
                        if *p != CHILD || !closed || reaped {
                            return false;
                        }
                        reaped = true;
                        reaps += 1;
                    }
                    _ => {}
                }
            }
            reaps == 1 && e.last() == Some(&Event::Reap(CHILD))
        }

        #[test]
        fn every_schedule_at_every_fragment_size_keeps_to_its_order_and_receipt() {
            use ChildChange::{Continued, Exited, Stopped};
            use Event::{Close as C, Foreground as F, Reap as P, Report as R, Signal as S};
            let (hup, cont, stop) = (libc::SIGHUP, libc::SIGCONT, libc::SIGTSTP);
            let mut cases: Vec<(Vec<Step>, Option<usize>, Vec<Event>)> = vec![
                // Stop, resume, continue, exit, channel end.
                (
                    vec![
                        Step::Child(Stopped(stop)),
                        command(Command::Resume),
                        Step::Child(Continued),
                        Step::Child(Exited(0)),
                        Step::End,
                    ],
                    None,
                    vec![
                        F(ME),
                        R(Report::Stopped(stop), true),
                        F(CHILD),
                        S(CHILD, cont),
                        R(Report::Continued, true),
                        R(Report::Exited(0), true),
                        C,
                        P(CHILD),
                    ],
                ),
                // The channel ends while the command runs.
                (
                    vec![Step::End, Step::Child(Exited(hup))],
                    None,
                    vec![S(CHILD, hup), S(CHILD, cont), C, P(CHILD)],
                ),
                // The stop's report fails.
                (
                    vec![
                        Step::Child(Stopped(stop)),
                        Step::Child(Exited(hup)),
                        Step::End,
                    ],
                    Some(1),
                    vec![
                        F(ME),
                        R(Report::Stopped(stop), false),
                        S(CHILD, hup),
                        S(CHILD, cont),
                        C,
                        P(CHILD),
                    ],
                ),
                // The continue's report fails.
                (
                    vec![Step::Child(Continued), Step::Child(Exited(hup)), Step::End],
                    Some(1),
                    vec![
                        R(Report::Continued, false),
                        S(CHILD, hup),
                        S(CHILD, cont),
                        C,
                        P(CHILD),
                    ],
                ),
                // The exit's report fails: no signal to an exited leader.
                (
                    vec![Step::Child(Exited(0)), Step::End],
                    Some(1),
                    vec![R(Report::Exited(0), false), C, P(CHILD)],
                ),
                // A whole frame that is not a command.
                (
                    vec![
                        Step::Frame(vec![0; FRAME]),
                        Step::Child(Exited(0)),
                        Step::End,
                    ],
                    None,
                    vec![R(Report::Exited(0), true), C, P(CHILD)],
                ),
                // Half a command, then the channel ends.
                (
                    vec![Step::Frame(vec![0; 2]), Step::End, Step::Child(Exited(hup))],
                    None,
                    vec![S(CHILD, hup), S(CHILD, cont), C, P(CHILD)],
                ),
            ];
            // After the exit: resume and suspend do nothing; the six signals
            // reach the retained leader's group before the reap.
            let mut steps = vec![
                Step::Child(Exited(0)),
                command(Command::Resume),
                command(Command::Suspend),
            ];
            let mut events = vec![R(Report::Exited(0), true), C];
            for sig in [
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTERM,
                hup,
                libc::SIGKILL,
                cont,
            ] {
                steps.push(command(Command::Signal(sig)));
                events.push(S(CHILD, sig));
            }
            steps.push(Step::End);
            events.push(P(CHILD));
            cases.push((steps, None, events));
            let (mut schedules, mut faults) = (0, 0);
            for (steps, fail, expected) in &cases {
                for chunk in 1..=FRAME {
                    let mut model = Model {
                        steps: steps.iter().cloned().collect(),
                        chunk,
                        offset: 0,
                        events: vec![],
                        reports: 0,
                        fail: *fail,
                        waits: 0,
                    };
                    assert_eq!(run(&mut model, ME, CHILD), 0);
                    assert_eq!(&model.events, expected, "chunk {chunk}");
                    assert!(receipt_valid(&model.events), "{:?}", model.events);
                    schedules += 1;
                    let mut late = model.events.clone();
                    late.push(S(CHILD, cont));
                    let mut foreign = model.events.clone();
                    foreign.insert(0, S(ME, cont));
                    let mut twice = model.events.clone();
                    twice.push(P(CHILD));
                    let mut unreaped = model.events.clone();
                    unreaped.pop();
                    for bad in [late, foreign, twice, unreaped] {
                        assert!(!receipt_valid(&bad), "the receipt missed {bad:?}");
                        faults += 1;
                    }
                }
            }
            assert_eq!((cases.len(), schedules, faults), (8, 64, 256));
        }
    }

    #[test]
    fn wait_statuses_read_as_the_kernel_reports_them() {
        use std::os::unix::process::ExitStatusExt;
        let status =
            |code, value| std::process::ExitStatus::from_raw(exit_status(code, value).unwrap());
        let s = status(libc::CLD_EXITED, 3);
        assert_eq!(s.code(), Some(3));
        let s = status(libc::CLD_KILLED, libc::SIGINT);
        assert_eq!(s.signal(), Some(libc::SIGINT));
        let s = status(libc::CLD_DUMPED, libc::SIGABRT);
        assert_eq!((s.signal(), s.core_dumped()), (Some(libc::SIGABRT), true));
        // A stop, a trap or a continue is no exit, whatever its signal.
        for code in [libc::CLD_STOPPED, libc::CLD_TRAPPED, libc::CLD_CONTINUED, 0] {
            assert_eq!(exit_status(code, libc::SIGTSTP), None, "si_code {code}");
        }
    }

    /// The monitor's wipe of the strings prepared for the exec: every byte
    /// of every path, argument and `NAME=value`, up to each list's NULL (the
    /// paths also by their count), is zero after it, and nothing past a
    /// string's NUL is touched. Stop the wipe at a string's first byte, or
    /// skip a list, and it fails.
    #[test]
    fn the_prepared_strings_are_wiped_whole() {
        let mut bufs: Vec<Vec<u8>> = [
            &b"/usr/bin/x"[..],
            b"/bin/x",
            b"x",
            b"--flag",
            b"",
            b"NAME=fixture-value-made-here",
            b"OTHER=1",
        ]
        .iter()
        .map(|b| {
            let mut v = b.to_vec();
            v.push(0);
            v.push(0x5a);
            v
        })
        .collect();
        let lens: Vec<usize> = bufs.iter().map(|b| b.len() - 2).collect();
        let ptrs: Vec<*const c_char> = bufs
            .iter_mut()
            .map(|b| b.as_mut_ptr().cast::<c_char>().cast_const())
            .collect();
        let list = |range: std::ops::Range<usize>| -> Vec<*const c_char> {
            ptrs[range]
                .iter()
                .copied()
                .chain([std::ptr::null()])
                .collect()
        };
        let (programs, argv, envp) = (list(0..2), list(2..5), list(5..7));
        let p = Prepared {
            #[cfg(feature = "testing")]
            lose_start_report: false,
            slave: -1,
            control: -1,
            programs: programs.as_ptr(),
            program_count: 2,
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
        };
        // SAFETY: every pointer is into a live, writable, NUL-terminated
        // buffer of `bufs`, and each list ends with NULL.
        unsafe { wipe_prepared(&p) };
        for (b, len) in bufs.iter().zip(lens) {
            assert!(b[..=len].iter().all(|c| *c == 0), "a string kept a byte");
            assert_eq!(b[len + 1], 0x5a, "the wipe ran past a string's end");
        }
    }

    /// A recorded `waitid`: each call takes the next record of its kind
    /// (the first call's, `WSTOPPED | WCONTINUED`, or the exit observer's,
    /// `WEXITED | WNOWAIT`) and logs which call it was.
    struct Records {
        stops: Vec<Option<(libc::c_int, libc::c_int)>>,
        exits: Vec<Option<(libc::c_int, libc::c_int)>>,
        calls: Vec<&'static str>,
    }

    impl Records {
        fn call(&mut self, options: libc::c_int) -> Option<(libc::c_int, libc::c_int)> {
            let (name, list) = if options & libc::WEXITED != 0 {
                assert_ne!(
                    options & libc::WNOWAIT,
                    0,
                    "the exit observer reaps nothing"
                );
                ("exit", &mut self.exits)
            } else {
                assert_eq!(options & libc::WNOWAIT, 0, "stops are consumed");
                ("stop", &mut self.stops)
            };
            self.calls.push(name);
            if list.is_empty() {
                None
            } else {
                list.remove(0)
            }
        }
    }

    const STOP: Option<(libc::c_int, libc::c_int)> = Some((libc::CLD_STOPPED, libc::SIGTSTP));

    /// The command stops between the monitor's two looks: the first finds
    /// nothing, and the exit observer finds the stop, as macOS's `waitid`
    /// returns it to a call asked for exits only. The monitor looks again
    /// and reports the stop, never an exit (it would read as killed by
    /// SIGTSTP, and the monitor would then close the slave and block
    /// reaping a command that is only stopped). A stop that keeps coming
    /// back to the exit observer alone gives `None` after a bounded number
    /// of looks (SIGCHLD then wakes the loop), never an exit; a real exit
    /// and a plain "nothing" read as before. Count the exit observer's
    /// record as an exit whatever its kind, and the first two fail.
    #[test]
    fn a_stop_the_exit_observer_finds_is_reported_as_a_stop() {
        let mut r = Records {
            stops: vec![None, STOP],
            exits: vec![STOP],
            calls: vec![],
        };
        assert_eq!(
            next_change(|o| r.call(o)),
            Some(ChildChange::Stopped(libc::SIGTSTP))
        );
        assert_eq!(r.calls, ["stop", "exit", "stop"]);
        let mut r = Records {
            stops: vec![],
            exits: vec![STOP; CHANGE_LOOKS],
            calls: vec![],
        };
        assert_eq!(next_change(|o| r.call(o)), None);
        assert_eq!(r.calls.len(), 2 * CHANGE_LOOKS, "{:?}", r.calls);
        let trapped = Some((libc::CLD_TRAPPED, libc::SIGTRAP));
        let continued = Some((libc::CLD_CONTINUED, libc::SIGCONT));
        for odd in [trapped, continued] {
            let mut r = Records {
                stops: vec![],
                exits: vec![odd; CHANGE_LOOKS],
                calls: vec![],
            };
            assert_eq!(next_change(|o| r.call(o)), None, "{odd:?}");
        }
        let mut r = Records {
            stops: vec![],
            exits: vec![Some((libc::CLD_EXITED, 7))],
            calls: vec![],
        };
        assert_eq!(
            next_change(|o| r.call(o)),
            Some(ChildChange::Exited(7 << 8))
        );
        let mut r = Records {
            stops: vec![],
            exits: vec![],
            calls: vec![],
        };
        assert_eq!(next_change(|o| r.call(o)), None);
        assert_eq!(r.calls, ["stop", "exit"]);
        let mut r = Records {
            stops: vec![continued],
            exits: vec![],
            calls: vec![],
        };
        assert_eq!(next_change(|o| r.call(o)), Some(ChildChange::Continued));
    }

    /// Waits, without consuming anything, until this process's own child
    /// `pid` has a stop to report, up to ten seconds.
    fn stopped_unconsumed(pid: libc::pid_t) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < end {
            if waitid_now(pid, libc::WSTOPPED | libc::WNOWAIT).is_some() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
    }

    /// On the real kernel: a child that stopped itself, its stop not yet
    /// consumed, is not an exit to the monitor's exit observer, also when
    /// the first look found nothing (the command stopped in between). On
    /// macOS the exit observer's `waitid` returns that stop
    /// (`CLD_STOPPED`); against the monitor before this check it read as
    /// `Exited` with the stop's signal. The monitor's real looks then
    /// report the stop, the continue and the exit, and nothing reaps the
    /// child before its handle does.
    #[test]
    fn a_stopped_command_is_not_an_exited_one_on_the_real_kernel() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -STOP $$; read line; exit 7"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        assert!(stopped_unconsumed(pid), "the child did not stop");
        let seen_late = next_change(|o| {
            if o & libc::WEXITED != 0 {
                waitid_now(pid, o)
            } else {
                None
            }
        });
        assert!(
            !matches!(seen_late, Some(ChildChange::Exited(_))),
            "a stopped command read as exited: {seen_late:?}"
        );
        assert!(
            stopped_unconsumed(pid),
            "the exit observer consumed the stop"
        );
        assert_eq!(
            next_change(|o| waitid_now(pid, o)),
            Some(ChildChange::Stopped(libc::SIGSTOP))
        );
        assert_eq!(
            next_change(|o| waitid_now(pid, o)),
            None,
            "the stop is reported once"
        );
        crate::signal_process(pid, libc::SIGCONT).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut continued = None;
        while continued.is_none() && std::time::Instant::now() < end {
            continued = next_change(|o| waitid_now(pid, o));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(continued, Some(ChildChange::Continued));
        drop(child.stdin.take());
        let mut exited = None;
        while exited.is_none() && std::time::Instant::now() < end {
            exited = next_change(|o| waitid_now(pid, o));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(exited, Some(ChildChange::Exited(7 << 8)));
        assert_eq!(
            child.wait().unwrap().code(),
            Some(7),
            "the observer left it unreaped"
        );
    }
}
