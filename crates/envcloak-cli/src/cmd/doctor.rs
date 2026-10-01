//! `envcloak doctor`, which finds plaintext keys and where they leaked
//! (SPEC §6.5): not in this build. It is registered ahead of its task
//! (M2-14; M2 plan D-23), so tasks in two lanes never edit the same
//! dispatcher lines. Until that task lands, every invocation exits 125 with
//! `not_in_this_build`, whatever its arguments: none is read or echoed, no
//! daemon is asked and nothing is written.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak doctor`")
}
