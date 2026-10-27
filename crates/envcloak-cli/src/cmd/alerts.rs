//! `envcloak alerts`: spend and renewal alerts and rules (SPEC §8, §14;
//! M4-13). Registered as a stub in M4-01.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak alerts`")
}
