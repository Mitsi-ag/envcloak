//! The only EnvCloak crate allowed `unsafe` code (SPEC §4, §5 "Memory
//! hygiene" and "Process hardening").
//!
//! - [`WipingAllocator`]: a global allocator that wipes every block on free
//!   and never reallocates in place. Both binaries install it.
//! - Process hardening: [`harden_process`] turns off core dumps and, on
//!   Linux, makes the process non-dumpable; [`tracer_present`] reports an
//!   attached debugger; [`hardening_status`] reports what took effect.
//! - [`lock_memory`]: best-effort `mlock` (plus `MADV_DONTDUMP` on Linux).
//! - [`restrict_umask`] and [`effective_uid`]: private creation modes, and
//!   the uid a trusted directory must belong to.
//! - [`open_beneath`]: `openat` from a directory handle, never following a
//!   symlink and never blocking on a FIFO; [`list_dir`],
//!   [`open_dir_beneath`], [`create_beneath`], [`create_rw_beneath`],
//!   [`create_dir_beneath`], [`link_beneath`], [`rename_beneath`],
//!   [`exchange_beneath`], [`unlink_beneath`] and [`remove_dir_beneath`]:
//!   the other name operations a scan, `envcloak init` and the file
//!   backups make in a directory they hold open; [`volume_of`]: whether a
//!   directory is on a network volume; and [`open_elsewhere`]: whether
//!   another process has a file open.
//! - [`sync_file`]: durable writes, with `F_FULLFSYNC` on macOS;
//!   [`wait_for_clock_past`]: a file's stamp, once the file system's clock
//!   moved past its last change, shows any change to it.
//! - The daemon's socket and lifecycle: [`peer_identity`] and [`peer_uid`]
//!   (who is on the other end of a Unix socket), [`connect_unix`] (a
//!   client's connection, bounded in time from before the connect),
//!   [`try_lock_exclusive`]
//!   (`flock`), [`TerminationSignals`] (`sigwait` on SIGTERM, SIGINT and
//!   SIGHUP; [`unblock_termination_on_spawn`] keeps that mask from the
//!   children such a process starts, and [`termination_ends_process`] lets
//!   them end a process started with them blocked or ignored), and
//!   [`awake_time`] and [`time_including_sleep`] (the clock pair that shows
//!   the machine slept).
//! - The CLI's secret input: [`SecretInput`] (a terminal with echo off)
//!   and [`inherited_fd`] (a descriptor named by `--passphrase-fd`).
//! - Descriptors a child gets: [`claim_inherited_fd`] (`envcloak run
//!   --status-fd` takes its status channel), [`close_on_exec_above`]
//!   (nothing inherited reaches the command), [`inherit_on_spawn`] (one
//!   descriptor handed to one child) and [`pipe_cloexec`].
//! - Caller evidence: [`proc_info`] and [`proc_argv`] (one process as the
//!   kernel reports it), [`open_exe`] and [`FileKey`] (a descriptor of the
//!   file a process runs, and that file's state, for its SHA-256 on Linux)
//!   and [`ancestry`] (a peer's parent chain, checked again after the
//!   walk); [`process_running`] and [`ProcessWatch`]
//!   (whether a process instance still runs, a zombie being one that does
//!   not; a pidfd on Linux).
//! - The runner (`envcloak run`): [`SignalRelay`] (signals caught and
//!   handed to a thread that passes them on, each with whether a process
//!   sent it, and marks between them), [`wait_for_exit`] and
//!   [`has_exited`] (a child's exit seen without reaping it, so its pid is
//!   not reused while it may still be signalled), [`signal_process`] and [`signal_group`] (`kill`),
//!   [`wait_writable`] (an output descriptor ready for a write),
//!   [`hung_up`] (a pipe no process can write to any more), and
//!   [`Interrupter`] (a thread blocked writing to an output nobody reads,
//!   broken out of the write once the runner gives up on it).
//! - PTY mode (`envcloak run --pty`, M2): [`pty`] (the PTY, its monitor
//!   session, the control channel and signal forwarding),
//!   [`TerminalGuard`] (the outer terminal in raw mode, restored on every
//!   way out) and [`OwnedChild`] and, on Linux, [`owned::OwnedSession`]
//!   (the only processes the PTY path signals).
//! - Probes on the person's machine (`envcloak agents status --probe`,
//!   M2-28): [`new_session_on_spawn`] (a child leading a session of its
//!   own, on a terminal of its own, which the kernel hangs up when the
//!   starter's side of it closes).
//! - Panics (gate 12): [`install_panic_hook`], which both binaries call so
//!   a panic shows its place and never its message, after it puts back a
//!   terminal a [`TerminalGuard`] holds raw; [`panic_point`], where
//!   a test build panics on request; and [`panic_with_input`], behind the
//!   binaries' hidden `internal panic`.
//!
//! Every other crate inherits the workspace's `unsafe_code = "forbid"`, so
//! the compiler rejects unsafe code there and any `allow` of it. This crate
//! repeats the workspace lint tables with `unsafe_code = "deny"`, which
//! `scripts/check-unsafe.sh` keeps in step. Every `unsafe` block and impl
//! here carries a `SAFETY` comment, which clippy checks.
#![allow(unsafe_code)]
#![warn(clippy::undocumented_unsafe_blocks)]

mod alloc;
mod child;
mod clock;
mod dir;
mod fd;
mod fs;
mod fsclock;
mod harden;
mod interrupt;
mod inuse;
mod lockfile;
pub mod owned;
mod panic;
mod peer;
mod perm;
mod proc;
pub mod pty;
mod pty_monitor;
mod relay_io;
mod session;
mod signal;
mod sock;
mod sync;
mod termios;
#[cfg(feature = "testing")]
pub mod testing;
mod tty;
mod watch;

pub use alloc::{SystemBacking, WipingAllocator, wiping_allocator_active};
pub use child::{Relayed, SignalRelay, has_exited, signal_group, signal_process, wait_for_exit};
pub use clock::{awake_time, time_including_sleep};
pub use dir::{
    DirEntryKind, DirEntryName, MAX_DIR_ENTRIES, Volume, create_beneath, create_dir_beneath,
    create_rw_beneath, exchange_beneath, kind_beneath, link_beneath, list_dir, open_dir_beneath,
    read_link_beneath, remove_dir_beneath, rename_beneath, rename_new_beneath, unlink_beneath,
    volume_of,
};
pub use fd::{
    chdir_on_spawn, claim_inherited_fd, cloexec_flag, close_on_exec_above, inherit_on_spawn,
    inherited_fd, pipe_cloexec,
};
pub use fs::open_beneath;
pub use fsclock::wait_for_clock_past;
pub use harden::{
    Hardening, core_dump_limit, disable_core_dumps, harden_process, hardening_report,
    hardening_status, lock_memory, parse_tracer_pid, set_non_dumpable, tracer_present,
};
pub use interrupt::Interrupter;
pub use inuse::{InUse, open_elsewhere};
pub use lockfile::try_lock_exclusive;
pub use owned::OwnedChild;
pub use panic::{
    fail_point, idle_connection_override, install as install_panic_hook, panic_point,
    panic_with_input, pause_point, test_event, test_trace,
};
pub use peer::{
    PeerIdentity, PeerSource, StartTime, boot_id, parse_boot_id, parse_stat_start_time,
    peer_identity, peer_uid, peer_unchanged, process_start_time,
};
pub use perm::{PRIVATE_UMASK, effective_uid, restrict_umask};
pub use proc::{
    AncestryError, Argv, CDHASH_LEN, CodeSignature, ExeIdentity, FileKey, LiveProcesses,
    MAX_ANCESTRY, MAX_ARGV, MAX_ARGV_BYTES, PROCARGS_ALIGN, ProcInfo, ProcessTable, StatFields,
    ancestry, ancestry_in, open_exe, parse_cmdline, parse_proc_stat, parse_procargs2,
    parse_stat_state, parse_status_euid, proc_argv, proc_info, process_running, reaches_top,
    stat_state_exited,
};
pub use relay_io::{Readiness, reopen_terminal, set_nonblocking, wait_any};
pub use session::new_session_on_spawn;
pub use signal::{
    TerminationSignals, TerminationWatch, exit_by_signal, interrupt_ends_process, stop_own_job,
    termination_ends_process, termination_recorded, unblock_termination_on_spawn,
};
pub use sock::connect_unix;
pub use sync::{SyncMethod, sync_file};
pub use termios::{
    TerminalGuard, TerminalSettings, WindowSize, restore_outer_terminal, set_window_size,
    window_size,
};
pub use tty::{SecretInput, hung_up, wait_readable, wait_writable};
pub use watch::ProcessWatch;
