//! Test support for EnvCloak. Never published, never a normal dependency of
//! a shipped crate.
//!
//! - [`canaries`]: fixture secret values generated at test time from a seed,
//!   in the shapes the M1 acceptance story uses (SPEC §15.1). Nothing
//!   key-shaped is committed; GitHub push protection is on.
//! - [`encodings`]: every listed encoding of a canary (SPEC §15.2 gate 8):
//!   hex, base64 and base64url whole and embedded at each alignment,
//!   percent and form encodings in both hex cases, and JSON escaping as
//!   common serializers produce it. The encoders here are written
//!   independently of `envcloak-redact`, so they do not share its bugs.
//! - [`assert_no_canary`], [`find`], [`sweep_dir`] and
//!   [`assert_sweep_clean`]: detection. Failure messages, and the `Debug`
//!   and `Display` output of [`Found`] and [`Hit`], name the canary's label
//!   and the encoding, never the value; a path whose names hold a value
//!   prints with `<LABEL>` in their place.
//! - [`probe_canaries`]: arms the allocator probe (gate 11) with canaries.
//! - [`TestHome`]: an isolated HOME and XDG tree under a short `/tmp` path,
//!   and a cleared environment for the processes a test starts, keeping
//!   only the [`DIAGNOSTIC_VARS`] (`RUST_LOG`, `RUST_BACKTRACE`).
//! - [`Daemon`]: an `envcloakd --foreground` child in a [`TestHome`], with
//!   its log collected, killed on drop.
//! - [`assert_fresh`]: refuses a binary of another package in the target
//!   directory that is older than the sources it is built from, which a
//!   scoped `cargo test -p` leaves as it was.
//! - [`crash`]: gate 19's core-dump control and signed copies, shared by
//!   the tests of both binaries.
//! - [`agents`]: the pinned agent hosts (Claude Code, Codex) in isolated
//!   homes ([`agents::AgentHome`]), driven by the scripted model
//!   `envcloak-probe-model` ([`agents::Model`]), and
//!   [`transcripts`]: the stores they write into and their sweep, with raw
//!   counts per store (M2 plan task M2-04).
//! - [`testkit_bin`]: this crate's programs, for the tests of other crates:
//!   `fixture-agent`, the stand-in agent the builtin agent catalog knows,
//!   and `ec-probe`, a caller that connects to a socket after escaping its
//!   process tree in the ways gate 26 lists; refused, as [`assert_fresh`]
//!   refuses, when older than their sources.

pub mod agents;
mod canary;
pub mod crash;
mod daemon;
mod detect;
mod encode;
mod fresh;
mod home;
pub mod transcripts;

pub use canary::{Canary, by_label, canaries, fresh_seed, labels};
pub use daemon::{Daemon, daemon_run_dir, daemon_socket};
pub use detect::{
    Detector, Found, Hit, SweptPath, assert_no_canary, assert_sweep_clean, encodings, find,
    sweep_dir,
};
pub use envcloak_sys::testing::{ProbeAllocator, ProbeMode, ProbeReport, ProbeSession};
pub use fresh::{assert_fresh, stale_source};
pub use home::{DIAGNOSTIC_VARS, TEST_ENV_VARS, TEST_PATH, TestHome};

/// How to build this crate's programs, which a scoped `cargo test -p` of
/// another package does not rebuild.
pub const TESTKIT_BINS: &str = "cargo build -p envcloak-testkit --bins";

/// The path of `name`, one of this crate's programs (`fixture-agent`,
/// `ec-probe`), built next to the running test binary: in the target
/// directory above its `deps/`.
///
/// # Panics
/// When it is not there, or older than a source it is built from (see
/// [`testkit_bin_beside`]).
pub fn testkit_bin(name: &str) -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("no current exe: {e}"));
    testkit_bin_beside(&exe, name)
}

/// [`testkit_bin`] for a test binary at `exe`: `name` in the target
/// directory above `exe`'s `deps/`. It must be as new as every source it
/// is built from ([`assert_fresh`]): `ec-probe` links envcloak-sys, and a
/// scoped run such as `cargo test -p envcloak-policy --test
/// evidence_gates` builds this crate's library but not its programs, so
/// after a change to envcloak-sys it would run the old one (review R-1).
///
/// # Panics
/// When it is not there or is older than a source: `cargo test
/// --workspace` builds it, as does [`TESTKIT_BINS`].
pub fn testkit_bin_beside(exe: &std::path::Path, name: &str) -> std::path::PathBuf {
    let dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .unwrap_or_else(|| panic!("the test binary is not in a target directory"));
    let path = dir.join(name);
    assert!(
        path.is_file(),
        "{} is missing: run the tests with --workspace, or {TESTKIT_BINS}",
        path.display()
    );
    fresh::assert_fresh_or(&path, "envcloak-testkit", TESTKIT_BINS);
    path
}

/// Default probe window: a freed block holding any 12 consecutive bytes of a
/// canary counts as holding it.
pub const PROBE_WINDOW: usize = 12;

/// Arms the allocator probe with every canary's [`Canary::probe_needle`]:
/// the raw value, or its random part where the value has fixed parts. The
/// test binary must install [`ProbeAllocator`] as its global allocator.
pub fn probe_canaries(cs: &[Canary], mode: ProbeMode) -> ProbeSession {
    let needles: Vec<&[u8]> = cs.iter().map(Canary::probe_needle).collect();
    ProbeSession::start(&needles, PROBE_WINDOW, mode)
}
