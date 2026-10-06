//! A deliberate violation: every way this file opens a secret, and every
//! call of `libc::kill` and `libc::killpg` and of EnvCloak's numeric
//! wrappers around them (M2 plan D-34: signals go only through an owned
//! handle), must be reported by clippy's disallowed-methods
//! lint, configured in the root clippy.toml, at the lint levels every
//! workspace crate inherits.
//! scripts/check-expose-lint.sh counts the reports against the
//! EXPECT-DISALLOWED markers. Never add this file to the expose allowlist.
//!
//! Compiled only with `--cfg envcloak_lint_canary`, so ordinary workspace
//! builds, which deny warnings in CI, see an empty crate. The cfg must stay
//! this file's first item and no crate may depend on this one:
//! scripts/check-unsafe.sh exempts this file from its expose_secret rule
//! only on those terms.
#![cfg(envcloak_lint_canary)]

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

pub fn method_call(s: &SecretBox<[u8; 4]>) -> u8 {
    s.expose_secret()[0] // EXPECT-DISALLOWED
}

pub fn path_call(s: &SecretBox<[u8; 4]>) -> u8 {
    ExposeSecret::expose_secret(s)[0] // EXPECT-DISALLOWED
}

pub fn mutable(s: &mut SecretBox<[u8; 4]>) {
    s.expose_secret_mut()[0] = 1; // EXPECT-DISALLOWED
}

/// A wrapper like `envcloak_core::SecretBytes`: calls on it resolve to the
/// same trait method.
#[derive(Debug)]
pub struct Wrapper(SecretBox<[u8; 4]>);

impl ExposeSecret<[u8; 4]> for Wrapper {
    fn expose_secret(&self) -> &[u8; 4] {
        self.0.expose_secret() // EXPECT-DISALLOWED
    }
}

pub fn through_wrapper(w: &Wrapper) -> u8 {
    w.expose_secret()[0] // EXPECT-DISALLOWED
}

pub fn by_reference(v: &[SecretBox<[u8; 4]>]) -> usize {
    v.iter().map(ExposeSecret::expose_secret).count() // EXPECT-DISALLOWED
}

/// A signal by number, which only `envcloak_sys::owned` may send. The
/// canary inherits `unsafe_code = "forbid"`, so it names the functions
/// rather than calling them; the lint reports a path as it reports a call.
pub fn kill_by_number() -> unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int {
    libc::kill // EXPECT-DISALLOWED
}

/// A group signal by number.
pub fn killpg_by_number() -> unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int {
    libc::killpg // EXPECT-DISALLOWED
}

/// EnvCloak's own numeric wrappers, which reach the same `kill` (review:
/// D-34 makes the owned handle the only signalling API).
pub fn signal_process_by_number() -> fn(i32, i32) -> std::io::Result<()> {
    envcloak_sys::signal_process // EXPECT-DISALLOWED
}

/// The group form of the same.
pub fn signal_group_by_number() -> fn(i32, i32) -> std::io::Result<()> {
    envcloak_sys::signal_group // EXPECT-DISALLOWED
}
