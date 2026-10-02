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
//!   [`open_dir_beneath`], [`create_beneath`], [`link_beneath`],
//!   [`rename_beneath`], [`exchange_beneath`] and [`unlink_beneath`]: the
//!   other name operations a scan and `envcloak init` make in a directory
//!   they hold open; [`volume_of`]: whether a directory is on a network
//!   volume; and [`open_elsewhere`]: whether another process has a file
//!   open.
//! - [`sync_file`]: durable writes, with `F_FULLFSYNC` on macOS.
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
//! - Caller evidence: [`proc_info`] and [`proc_argv`] (one process as the
//!   kernel reports it) and [`ancestry`] (a peer's parent chain, checked
//!   again after the walk).
//! - The runner (`envcloak run`): [`SignalRelay`] (signals caught and
//!   handed to a thread that passes them on, each with whether a process
//!   sent it, and marks between them), [`wait_for_exit`] and
//!   [`has_exited`] (a child's exit seen without reaping it, so its pid is
//!   not reused while it may still be signalled), [`signal_process`] and [`signal_group`] (`kill`),
//!   [`wait_writable`] (an output descriptor ready for a write),
//!   [`hung_up`] (a pipe no process can write to any more), and
//!   [`Interrupter`] (a thread blocked writing to an output nobody reads,
//!   broken out of the write once the runner gives up on it).
//! - Panics (gate 12): [`install_panic_hook`], which both binaries call so
//!   a panic shows its place and never its message; [`panic_point`], where
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
mod harden;
mod interrupt;
mod inuse;
mod lockfile;
mod panic;
mod peer;
mod perm;
mod proc;
mod signal;
mod sock;
mod sync;
#[cfg(feature = "testing")]
pub mod testing;
mod tty;

pub use alloc::{SystemBacking, WipingAllocator, wiping_allocator_active};
pub use child::{Relayed, SignalRelay, has_exited, signal_group, signal_process, wait_for_exit};
pub use clock::{awake_time, time_including_sleep};
pub use dir::{
    DirEntryKind, DirEntryName, MAX_DIR_ENTRIES, Volume, create_beneath, exchange_beneath,
    kind_beneath, link_beneath, list_dir, open_dir_beneath, read_link_beneath, rename_beneath,
    unlink_beneath, volume_of,
};
pub use fd::{cloexec_flag, inherited_fd};
pub use fs::open_beneath;
pub use harden::{
    Hardening, core_dump_limit, disable_core_dumps, harden_process, hardening_report,
    hardening_status, lock_memory, parse_tracer_pid, set_non_dumpable, tracer_present,
};
pub use interrupt::Interrupter;
pub use inuse::{InUse, open_elsewhere};
pub use lockfile::try_lock_exclusive;
pub use panic::{
    idle_connection_override, install as install_panic_hook, panic_point, panic_with_input,
    test_trace,
};
pub use peer::{
    PeerIdentity, PeerSource, StartTime, boot_id, parse_boot_id, parse_stat_start_time,
    peer_identity, peer_uid, peer_unchanged, process_start_time,
};
pub use perm::{PRIVATE_UMASK, effective_uid, restrict_umask};
pub use proc::{
    AncestryError, Argv, CDHASH_LEN, CodeSignature, ExeIdentity, LiveProcesses, MAX_ANCESTRY,
    MAX_ARGV, MAX_ARGV_BYTES, PROCARGS_ALIGN, ProcInfo, ProcessTable, StatFields, ancestry,
    ancestry_in, parse_cmdline, parse_proc_stat, parse_procargs2, parse_status_euid, proc_argv,
    proc_info, reaches_top,
};
pub use signal::{
    TerminationSignals, TerminationWatch, exit_by_signal, interrupt_ends_process,
    termination_ends_process, termination_recorded, unblock_termination_on_spawn,
};
pub use sock::connect_unix;
pub use sync::{SyncMethod, sync_file};
pub use tty::{SecretInput, hung_up, wait_readable, wait_writable};
