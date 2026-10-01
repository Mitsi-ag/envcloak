//! `envcloak lock` (SPEC §5 "Lock"): any client may lock, because locking
//! only tightens. The daemon wipes the vault key and its subkeys.

use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, usage};

pub fn run(args: &[&str]) -> ExitCode {
    if !args.is_empty() {
        return usage("envcloak lock");
    }
    lock().unwrap_or_else(|f| f.report(FAILURE))
}

fn lock() -> Result<ExitCode, Failure> {
    if connect()?.lock()?.was_unlocked {
        println!("Vault locked.");
    } else {
        println!("The vault was not unlocked.");
    }
    Ok(ExitCode::SUCCESS)
}
