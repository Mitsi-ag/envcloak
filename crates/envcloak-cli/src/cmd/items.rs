//! `envcloak items reclassify`, which changes an item's classification
//! between test and live after a proof (SPEC §10b, the live-key guard):
//! not in this build. It is registered ahead of its task (M2-13; M2 plan
//! D-23), so tasks in two lanes never edit the same dispatcher lines.
//! Until that task lands, it exits 125 with `not_in_this_build`, whatever
//! its arguments: none is read or echoed, no daemon is asked and nothing
//! is written. Any other subcommand is a usage error.

use std::process::ExitCode;

use envcloak_client::fail::usage;

const USAGE: &str = "envcloak items reclassify (not in this build)";

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["reclassify", ..] => super::not_in_this_build("`envcloak items reclassify`"),
        _ => usage(USAGE),
    }
}
