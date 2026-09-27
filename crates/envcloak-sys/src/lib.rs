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
//!
//! Every other crate inherits the workspace's `unsafe_code = "forbid"`, so
//! the compiler rejects unsafe code there and any `allow` of it. This crate
//! repeats the workspace lint tables with `unsafe_code = "deny"`, which
//! `scripts/check-unsafe.sh` keeps in step. Every `unsafe` block and impl
//! here carries a `SAFETY` comment, which clippy checks.
#![allow(unsafe_code)]
#![warn(clippy::undocumented_unsafe_blocks)]

mod alloc;
mod fs;
mod harden;
mod perm;
#[cfg(feature = "testing")]
pub mod testing;

pub use alloc::{SystemBacking, WipingAllocator, wiping_allocator_active};
pub use fs::open_beneath;
pub use harden::{
    Hardening, core_dump_limit, disable_core_dumps, harden_process, hardening_report,
    hardening_status, lock_memory, parse_tracer_pid, set_non_dumpable, tracer_present,
};
pub use perm::{PRIVATE_UMASK, effective_uid, restrict_umask};
