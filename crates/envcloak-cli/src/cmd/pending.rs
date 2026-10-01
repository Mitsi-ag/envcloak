//! `envcloak pending`, which lists the requests waiting for approval that
//! this terminal may approve (M2 plan D-04): not in this build. It is
//! registered ahead of its task (M2-03; M2 plan D-23), so tasks in two
//! lanes never edit the same dispatcher lines. Until that task lands, every
//! invocation exits 125 with `not_in_this_build`, whatever its arguments:
//! none is read or echoed, no daemon is asked and nothing is written.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak pending`")
}
