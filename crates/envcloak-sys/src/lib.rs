//! The only EnvCloak crate allowed `unsafe` code (SPEC §4, §5 "Memory
//! hygiene" and "Process hardening").
//!
//! - [`WipingAllocator`]: a global allocator that wipes every block on free
//!   and never reallocates in place. Both binaries install it.
//! - Process hardening: [`harden_process`] turns off core dumps and, on
//!   Linux, makes the process non-dumpable; [`tracer_present`] reports an
//!   attached debugger; [`hardening_status`] reports what took effect.
//! - [`lock_memory`]: best-effort `mlock` (plus `MADV_DONTDUMP` on Linux).
//!
//! `scripts/check-unsafe.sh` fails the build if any other crate allows
//! `unsafe_code`. Every `unsafe` block and impl here carries a `SAFETY`
//! comment, which clippy checks.
#![allow(unsafe_code)]
#![warn(clippy::undocumented_unsafe_blocks)]

mod alloc;
mod harden;
#[cfg(feature = "testing")]
pub mod testing;

pub use alloc::{SystemBacking, WipingAllocator, wiping_allocator_active};
pub use harden::{
    Hardening, core_dump_limit, disable_core_dumps, harden_process, hardening_report,
    hardening_status, lock_memory, parse_tracer_pid, set_non_dumpable, tracer_present,
};
