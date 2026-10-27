//! `envcloak set-class`: item class change (`secret` to `usage_credential`)
//! with grant and standing-approval revocation (SPEC §5, §8, §10b, §14;
//! M4-20). Registered as a stub in M4-01.

use std::process::ExitCode;

pub fn run(_args: &[&str]) -> ExitCode {
    super::not_in_this_build("`envcloak set-class`")
}
