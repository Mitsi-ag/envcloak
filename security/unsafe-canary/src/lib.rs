//! A deliberate violation: unsafe code, and every way of allowing it that
//! an earlier review found to slip past a source check, must be rejected by
//! the compiler at the lint levels every workspace crate but envcloak-sys
//! inherits. scripts/check-unsafe-lint.sh writes the module below (it holds
//! lint attributes that scripts/check-unsafe.sh would rightly reject in a
//! committed file), compiles this crate and matches each error against the
//! module's EXPECT markers.
//!
//! Compiled only with `--cfg envcloak_unsafe_canary`, so ordinary workspace
//! builds see an empty crate. The generated files are ignored by git.
#![cfg(envcloak_unsafe_canary)]

// rustfmt would otherwise look for the file, which exists only while the
// script runs.
#[rustfmt::skip]
pub mod generated;
