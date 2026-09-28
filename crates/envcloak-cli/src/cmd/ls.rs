//! `envcloak ls [--long] [--json]`: every item's metadata, sorted by slug
//! (SPEC §7: an agent finds a key here, then references it with `envcloak
//! ref`). Never a value. An item's account is personal, so it is asked
//! for, and shown, only with `--long`.

use std::process::ExitCode;

use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::render::print;

const USAGE: &str = "envcloak ls [--long] [--json]";

pub fn run(args: &[&str]) -> ExitCode {
    let (mut long, mut json) = (false, false);
    for arg in args {
        match *arg {
            "--long" | "-l" if !long => long = true,
            "--json" if !json => json = true,
            _ => return usage(USAGE),
        }
    }
    ls(long, json).unwrap_or_else(|f| f.report(FAILURE))
}

fn ls(long: bool, json: bool) -> Result<ExitCode, Failure> {
    let items = connect()?.items_list(long)?;
    print(&items, json);
    Ok(ExitCode::SUCCESS)
}
