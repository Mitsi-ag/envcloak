//! `envcloak backup create [--json]` (SPEC §5, story S11): writes an
//! encrypted backup of the vault to its `backups` directory, and prints
//! where. The daemon writes it from the unlocked vault; nothing in it
//! opens without the Recovery Kit (docs/VAULT.md "Backups"), and no value
//! crosses the socket, so it needs no proof. `envcloak recover --backup
//! <file>` restores the vault from it.

use std::process::ExitCode;

use envcloak_ipc::ClientError;
use envcloak_ipc::proto::ErrorKind;

use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::render::print;

const USAGE_TEXT: &str = "envcloak backup create [--json]";

pub fn run(args: &[&str]) -> ExitCode {
    let json = match args {
        ["create"] => false,
        ["create", "--json"] => true,
        _ => return usage(USAGE_TEXT),
    };
    create(json).unwrap_or_else(|f| f.report(FAILURE))
}

fn create(json: bool) -> Result<ExitCode, Failure> {
    let view = connect()?.backup_create().map_err(|e| match e {
        ClientError::Rpc(r) if r.kind == ErrorKind::BackupFailed => Failure::new(
            "backup_failed",
            "the encrypted backup could not be written; `envcloakd`'s log says why",
        ),
        e => e.into(),
    })?;
    print(&view, json);
    Ok(ExitCode::SUCCESS)
}
