//! `envcloak signin`, which sets up dev sign-in and its targets (SPEC
//! §6.8): not in this build. It is registered ahead of its tasks (M2b-05
//! and M2b-08; M2 plan D-23), so tasks in two lanes never edit the same
//! dispatcher lines. Until they land, every invocation exits 125 with
//! `not_in_this_build`, whatever its arguments: none is read or echoed, no
//! daemon is asked and nothing is written.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak signin`")
}
