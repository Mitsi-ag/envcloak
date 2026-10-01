//! `envcloak unlock [--passphrase-fd N]` (SPEC §5 "Unlock flow" step 5).
//!
//! The daemon is verified first, so no passphrase is asked for when there
//! is no daemon, no vault, or nothing to unlock. The passphrase is read
//! from `/dev/tty` with echo off, or from the descriptor `--passphrase-fd`
//! names; never from argv or the environment, and never under a tracer.
//! It is then sent once, on a new connection that is verified again, with
//! the agent markers this process's environment holds (their names), and
//! the daemon runs Argon2id. An unlock is a proof (SPEC §10b): the daemon
//! refuses it from a process with an agent in its ancestry or without a
//! terminal session, and this command refuses before it reads anything
//! when its environment holds an agent's markers.

use std::process::ExitCode;

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::VaultState;
use envcloak_ipc::{ClientError, RpcError};

use super::fd_number;

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
    refuse_if_traced()?;
    let claims = refuse_if_claimed()?;
    let passphrase = match fd {
        Some(fd) => read_secret_fd(fd)?,
        None => Terminal::open()?.read_secret("Vault passphrase: ")?,
    };
    let unlocked = connect()?.unlock(passphrase, &claims)?;
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
