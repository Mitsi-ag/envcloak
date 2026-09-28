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
//!   symlink and never blocking on a FIFO.
//! - [`sync_file`]: durable writes, with `F_FULLFSYNC` on macOS.
//! - The daemon's socket and lifecycle: [`peer_identity`] and [`peer_uid`]
//!   (who is on the other end of a Unix socket), [`try_lock_exclusive`]
//!   (`flock`), [`TerminationSignals`] (`sigwait` on SIGTERM, SIGINT and
//!   SIGHUP), and [`awake_time`] and [`time_including_sleep`] (the clock
//!   pair that shows the machine slept).
//! - The CLI's secret input: [`SecretInput`] (a terminal with echo off)
//!   and [`inherited_fd`] (a descriptor named by `--passphrase-fd`).
//! - Caller evidence: [`proc_info`] and [`proc_argv`] (one process as the
//!   kernel reports it) and [`ancestry`] (a peer's parent chain, checked
//!   again after the walk).
//!
//! Every other crate inherits the workspace's `unsafe_code = "forbid"`, so
//! the compiler rejects unsafe code there and any `allow` of it. This crate
//! repeats the workspace lint tables with `unsafe_code = "deny"`, which
//! `scripts/check-unsafe.sh` keeps in step. Every `unsafe` block and impl
//! here carries a `SAFETY` comment, which clippy checks.
#![allow(unsafe_code)]
#![warn(clippy::undocumented_unsafe_blocks)]

mod alloc;
mod clock;
mod fd;
mod fs;
mod harden;
mod lockfile;
mod peer;
mod perm;
mod proc;
mod signal;
mod sync;
#[cfg(feature = "testing")]
pub mod testing;
mod tty;

pub use alloc::{SystemBacking, WipingAllocator, wiping_allocator_active};
pub use clock::{awake_time, time_including_sleep};
pub use fd::{cloexec_flag, inherited_fd};
pub use fs::open_beneath;
pub use harden::{
    Hardening, core_dump_limit, disable_core_dumps, harden_process, hardening_report,
    hardening_status, lock_memory, parse_tracer_pid, set_non_dumpable, tracer_present,
};
pub use lockfile::try_lock_exclusive;
pub use peer::{
    PeerIdentity, PeerSource, StartTime, parse_stat_start_time, peer_identity, peer_uid,
    process_start_time,
};
pub use perm::{PRIVATE_UMASK, effective_uid, restrict_umask};
pub use proc::{
    AncestryError, Argv, CDHASH_LEN, CodeSignature, ExeIdentity, LiveProcesses, MAX_ANCESTRY,
    MAX_ARGV, MAX_ARGV_BYTES, PROCARGS_ALIGN, ProcInfo, ProcessTable, StatFields, ancestry,
    ancestry_in, parse_cmdline, parse_proc_stat, parse_procargs2, parse_status_euid, proc_argv,
    proc_info, reaches_top,
};
pub use signal::{TerminationSignals, TerminationWatch, exit_by_signal, termination_recorded};
pub use sync::{SyncMethod, sync_file};
pub use tty::{SecretInput, wait_readable};
