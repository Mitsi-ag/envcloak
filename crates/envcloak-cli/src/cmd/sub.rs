//! `envcloak sub`: subscription records and renewal tracking (SPEC §2a-bis,
//! §8, §14; M4-04). Registered as a stub in M4-01.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak sub`")
}
