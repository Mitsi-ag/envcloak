//! `envcloak card`: payment card records and number/CVV opt-in (SPEC §2a-bis,
//! §8, §14; M4-17). Registered as a stub in M4-01.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak card`")
}
