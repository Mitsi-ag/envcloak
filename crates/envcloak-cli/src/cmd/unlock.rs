//! `envcloak unlock [--passphrase-fd N]` (SPEC §5 "Unlock flow" step 5).
//!
//! The daemon is verified first, so no passphrase is asked for when there
//! is no daemon, no vault, or nothing to unlock. The passphrase is read
//! from `/dev/tty` with echo off, or from the descriptor `--passphrase-fd`
//! names; never from argv or the environment. It is then sent once, on a
//! new connection that is verified again, and the daemon runs Argon2id.

use std::process::ExitCode;

use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::VaultState;
use envcloak_ipc::{ClientError, RpcError};

use super::fd_number;
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::tty::{Terminal, read_secret_fd};

const USAGE: &str = "envcloak unlock [--passphrase-fd N]";

pub fn run(args: &[&str]) -> ExitCode {
    let fd = match args {
        [] => None,
        ["--passphrase-fd", n] => match fd_number(n) {
            Some(n) => Some(n),
            None => return usage(USAGE),
        },
        _ => return usage(USAGE),
    };
    unlock(fd).unwrap_or_else(|f| f.report(FAILURE))
}

fn unlock(fd: Option<i32>) -> Result<ExitCode, Failure> {
    let state = connect()?.status()?.vault;
    match state.state {
        VaultState::Unlocked => {
            println!("The vault is already unlocked.");
            return Ok(ExitCode::SUCCESS);
        }
        VaultState::Absent => {
            return Err(ClientError::Rpc(RpcError::new(ErrorKind::NoVault)).into());
        }
        VaultState::Unavailable => {
            let reason = state.unavailable.as_deref().unwrap_or("damaged");
            return Err(ClientError::Rpc(RpcError::with_reason(
                ErrorKind::VaultUnavailable,
                reason,
            ))
            .into());
        }
        VaultState::Locked => {}
    }
    let passphrase = match fd {
        Some(fd) => read_secret_fd(fd)?,
        None => Terminal::open()?.read_secret("Vault passphrase: ")?,
    };
    let unlocked = connect()?.unlock(passphrase)?;
    if unlocked.already {
        println!("The vault is already unlocked.");
    } else {
        println!("Vault unlocked.");
    }
    if unlocked.read_only {
        eprintln!(
            "envcloak: warning: the vault was modified outside EnvCloak or could not be \
             upgraded; it is open read-only"
        );
    }
    Ok(ExitCode::SUCCESS)
}
