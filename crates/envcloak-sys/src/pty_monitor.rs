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
//!    1 and 2 and the control channel on 3, closes every other descriptor,
//!    and takes the slave as its controlling terminal (`TIOCSCTTY`);
//! 2. ignores the terminal's job-control and keyboard signals (SIGTTOU, so
//!    its own `tcsetpgrp` works from the background; SIGTTIN, SIGTSTP,
//!    SIGINT, SIGQUIT) and SIGHUP, SIGTERM and SIGPIPE: on macOS `TIOCSIG`
//!    signals whatever group is in the foreground, which is the monitor's
//!    own while the command is stopped, and a hangup reaches it as the
//!    session's leader. It ends when the CLI's end of the control channel
//!    closes instead;
//! 3. forks the command, which makes its own process group
//!    (`setpgid(0, 0)`) the slave's foreground group (`tcsetpgrp`, SIGTTOU
//!    still ignored and every signal blocked), resets every disposition
//!    and its signal mask, closes the control channel, and execs: the
//!    descriptors it starts with are 0, 1 and 2, the slave. The monitor
//!    sets the command's group too, closing the race. The command's parent,
//!    the monitor, is in the same session but another group, so the
//!    command's group is not orphaned and the suspend character stops it;
//! 4. reports `Started` (or `ExecFailed` with the `errno` of the last
//!    `execve`, through a close-on-exec pipe) and then loops: it waits on
//!    its own child only, through `waitid` (stops and continues consumed,
//!    an exit observed without reaping), and on the control channel.
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
//!   monitor itself has (a signal narrowed on a system, D-35).
//! - **The command continues** (`Continued`) or **exits** (`Exited`): an
//!   exit is observed with `WNOWAIT`, so the command stays unreaped and
//!   its group's number cannot be reused: `Signal(n)` still reaches what
//!   is left of the group. The monitor closes its slave descriptors (so
//!   the master sees the end once no descendant holds the slave), reports
//!   the status, and reaps the command when the CLI closes the channel.
//! - **The channel ends** while the command runs (the CLI is gone): SIGHUP
//!   then SIGCONT to the command's group, as a hangup would, and the
//!   monitor waits for the command to exit before it reaps it and exits.
//!
//! Every signal the monitor sends goes to the group of its own unreaped
//! child, through its [`OwnedChild`] handle, which the reap consumes
//! (D-34). The monitor runs in a child of a multi-threaded process,
//! so between `fork` and `_exit` it calls only system calls on the
//! async-signal-safe list (`sigprocmask`, `sigaction`, `setsid`, `fcntl`,
//! `dup2`, `close`, `ioctl`, `pipe`, `fork`, `setpgid`, `tcsetpgrp`,
//! `getpid`, `read`, `write`, `recv`, `waitid`, `waitpid`, `pselect`,
//! `kill`, `execve`, `_exit`, plus `close_range`, `proc_pidinfo` and
//! `getrlimit`): no allocation, no lock, no panic path. A test allocator
//! that aborts in any process but the one that installed it runs a stop,
//! resume and exit cycle through it
//! (`crates/envcloak-sys/tests/pty_topology.rs`). The loop itself is
//! written against [`MonitorOps`], so a recording model checks what it
//! signals and in which order.
//!
//! SIGCHLD stays blocked except inside `pselect`, which unblocks it
//! atomically, so a child that changes state between the monitor's last
//! `waitid` and its wait still wakes it. A one-second tick backs that up
//! where a system does not raise SIGCHLD for a continue.
//!
//! **The control protocol.** Fixed frames of [`FRAME`] bytes: a tag, a
//! marker byte, two zero bytes and a little-endian `i32`. Anything else is
//! not a frame: the monitor ignores a command it cannot read, and the CLI
//! treats a report it cannot read as the monitor lost. [`decode_command`]
//! and [`decode_report`] are the only readers.

use std::ffi::c_char;

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
    /// Reaps the command.
    fn reap(&mut self, pid: i32);
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
                    ops.close_terminal();
                    if control && !ops.write_control(&encode_report(Report::Exited(status))) {
                        control = false;
                    }
                }
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

/// The raw wait status `waitid` describes in `info`, for an exit.
fn wait_status(code: libc::c_int, status: libc::c_int) -> i32 {
    match code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_DUMPED => (status & 0x7f) | 0x80,
        _ => status & 0x7f,
    }
}

impl MonitorOps for SysOps {
    fn child_change(&mut self) -> Option<ChildChange> {
        let id = libc::id_t::try_from(self.child).ok()?;
        // SAFETY: siginfo_t is plain data; waitid fills it in, and leaves
        // si_pid 0 when nothing changed.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is writable; the child is the monitor's own.
        // Stops and continues are consumed, so each is reported once.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG,
            )
        };
        // SAFETY: waitid filled `info` in or left it zeroed; si_pid and
        // si_status are set for a child's state change.
        if rc == 0 && unsafe { info.si_pid() } == self.child {
            // SAFETY: as above.
            let status = unsafe { info.si_status() };
            match info.si_code {
                libc::CLD_STOPPED | libc::CLD_TRAPPED => return Some(ChildChange::Stopped(status)),
                libc::CLD_CONTINUED => return Some(ChildChange::Continued),
                _ => {}
            }
        }
        // SAFETY: as above.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above; WNOWAIT leaves the child unreaped.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // SAFETY: as above.
        if rc == 0 && unsafe { info.si_pid() } == self.child {
            // SAFETY: as above.
            let status = unsafe { info.si_status() };
            return Some(ChildChange::Exited(wait_status(info.si_code, status)));
        }
        None
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
}

/// Signals reset in the monitor and the command: every one there is.
#[cfg(target_os = "linux")]
const LAST_SIGNAL: libc::c_int = 64;
#[cfg(not(target_os = "linux"))]
const LAST_SIGNAL: libc::c_int = 31;

extern "C" fn on_child(_sig: libc::c_int) {}

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

fn set_mask(how: libc::c_int, all: bool, only: Option<libc::c_int>) {
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
        if let Some(sig) = only {
            libc::sigaddset(&mut set, sig);
        }
        libc::sigprocmask(how, &set, std::ptr::null_mut());
    }
}

/// Closes every descriptor from `low` up: `close_range` on Linux; on macOS
/// the descriptors `proc_pidinfo` lists (a loop up to the limit would be a
/// million calls where the limit is a million); a loop up to the limit
/// where neither works.
fn close_from(low: libc::c_int) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range closes descriptors and has no other effect.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, low, libc::c_uint::MAX, 0) };
        if rc == 0 {
            return;
        }
    }
    #[cfg(target_os = "macos")]
    {
        const ENTRIES: usize = 256;
        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        let size = libc::c_int::try_from(ENTRIES * entry).unwrap_or(0);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        loop {
            // SAFETY: proc_fdinfo is plain data.
            let mut list: [libc::proc_fdinfo; ENTRIES] = unsafe { std::mem::zeroed() };
            // SAFETY: `list` is writable for `size` bytes; proc_pidinfo is
            // one system call that fills it with this process's
            // descriptors.
            let bytes = unsafe {
                libc::proc_pidinfo(me, libc::PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast(), size)
            };
            let Ok(bytes) = usize::try_from(bytes) else {
                break;
            };
            if bytes == 0 {
                break;
            }
            let mut closed = false;
            for info in list.iter().take(bytes / entry) {
                if info.proc_fd >= low {
                    // SAFETY: closes one of this process's descriptors.
                    unsafe { libc::close(info.proc_fd) };
                    closed = true;
                }
            }
            if !closed {
                return;
            }
        }
    }
    // SAFETY: rlimit is plain data; getrlimit fills it in.
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: `lim` is writable.
    let top = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        libc::c_int::try_from(lim.rlim_cur.min(1 << 20)).unwrap_or(1 << 20)
    } else {
        1 << 16
    };
    for fd in low..top {
        // SAFETY: closing a descriptor number that may not be open fails
        // with EBADF and has no other effect.
        unsafe { libc::close(fd) };
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
    set_mask(libc::SIG_SETMASK, true, None);
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
    close_from(CONTROL_FD + 1);
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
    // 3. What the monitor ignores, and SIGCHLD to interrupt its wait.
    for sig in [
        libc::SIGTTOU,
        libc::SIGTTIN,
        libc::SIGTSTP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGHUP,
        libc::SIGTERM,
        libc::SIGPIPE,
    ] {
        disposition(sig, libc::SIG_IGN);
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
    let mut ops = SysOps {
        child,
        owned: Some(OwnedChild::from_fork_without_pidfd(child)),
    };
    if got > 0 {
        let e = i32::from_ne_bytes(code);
        ops.reap(child);
        let e = if (1..=127).contains(&e) { e } else { libc::EIO };
        ops.write_control(&encode_report(Report::ExecFailed(e)));
        // SAFETY: ends the monitor.
        unsafe { libc::_exit(0) };
    }
    // A channel already gone shows as its end at the loop's first read.
    ops.write_control(&encode_report(Report::Started(child)));
    // 6. SIGCHLD blocked outside pselect; everything else unblocked.
    set_mask(libc::SIG_SETMASK, false, Some(libc::SIGCHLD));
    // SAFETY: getpid has no preconditions; the monitor leads its session,
    // so its pid is its group.
    let me = unsafe { libc::getpid() };
    let code = run(&mut ops, me, child);
    // SAFETY: ends the monitor.
    unsafe { libc::_exit(code) }
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
    set_mask(libc::SIG_SETMASK, false, None);
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
                Did::CloseTerminal,
                Did::Report(Report::Exited(0)),
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

    #[test]
    fn wait_statuses_read_as_the_kernel_reports_them() {
        use std::os::unix::process::ExitStatusExt;
        let s = std::process::ExitStatus::from_raw(wait_status(libc::CLD_EXITED, 3));
        assert_eq!(s.code(), Some(3));
        let s = std::process::ExitStatus::from_raw(wait_status(libc::CLD_KILLED, libc::SIGINT));
        assert_eq!(s.signal(), Some(libc::SIGINT));
        let s = std::process::ExitStatus::from_raw(wait_status(libc::CLD_DUMPED, libc::SIGABRT));
        assert_eq!((s.signal(), s.core_dumped()), (Some(libc::SIGABRT), true));
    }
}
