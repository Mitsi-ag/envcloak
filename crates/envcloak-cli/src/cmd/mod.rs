//! The commands (SPEC §14 M1 list). T7 has `vault create`, `unlock`,
//! `lock`, `status` and `daemon install`; T9 adds `run`'s request step,
//! `approve`, `deny` and `grants`; T10 adds `audit verify`; T11 adds
//! `add`, `ls`, `show`, `ref`, `check`, `rotate` and `rm`; T12 adds `run`'s
//! runner; T13 adds `init`, `import` and `recovery confirm`; T14 adds
//! `backup create` and `recover`; later tasks add the rest.
//!
//! Every M2 and M2b command is registered here, each in its own module,
//! ahead of the task that lands it (M2 plan D-23): `reveal`, `doctor`,
//! `scrub`, `agents`, `hook`, `mcp`, `mcp-bridge`, `standing`, `items`,
//! `login` and `signin`, and `run`'s `--pty`. Until then each exits 125
//! with `not_in_this_build` ([`not_in_this_build`]), reads and echoes no
//! argument, and asks no daemon. M2-03 landed `pending` and `run`'s
//! `--wait` and `--manifest`; M2-06 landed `mcp`; M2-08 landed `hook` and
//! `agents install` and `uninstall`; M2-13 landed `items reclassify`;
//! M2-09 landed `agents status`, and M2-28 its `--probe`.
//!
//! Argument errors never echo an argument: one could be a pasted secret.
//! No command takes a value on the command line (gate 13): values come
//! from a hidden prompt on `/dev/tty` or from standard input (`--stdin`),
//! and a name given there that is shaped like a key or token is refused
//! ([`refuse_value_like`]).

pub mod add;
pub mod agents;
pub mod approve;
pub mod audit;
pub mod backup;
pub mod check;
pub mod daemon;
pub mod doctor;
pub mod grants;
pub mod hook;
pub mod import;
pub mod init;
pub mod items;
pub mod lock;
pub mod login;
pub mod ls;
pub mod mcp;
pub mod mcp_bridge;
pub mod pending;
pub mod recover;
pub mod recovery;
pub mod ref_;
pub mod reveal;
pub mod rm;
pub mod rotate;
pub mod run;
pub mod scrub;
pub mod show;
pub mod signin;
pub mod standing;
pub mod status;
pub mod unlock;
pub mod vault;

use std::process::ExitCode;

use envcloak_client::fail::{Failure, RUN_FAILURE};
use envcloak_client::render::looks_like_value;

/// The token of a command or option that this build registers but does
/// not have yet (M2 plan D-23).
pub const NOT_IN_THIS_BUILD: &str = "not_in_this_build";

/// Reports that `what`, fixed text naming a command or an option, is not
/// in this build, and returns exit 125 (as `run`'s own failures). Nothing
/// else is done: the caller has read no argument, so none can be echoed,
/// and no daemon is asked.
pub fn not_in_this_build(what: &'static str) -> ExitCode {
    Failure::new(
        NOT_IN_THIS_BUILD,
        format!("{what} is not in this build of EnvCloak; nothing was done"),
    )
    .report(RUN_FAILURE)
}

/// Refuses names given on the command line (a slug, a provider, an
/// account, a variable) that are shaped like a key or token rather than a
/// name ([`looks_like_value`]): values are never taken on the command line
/// (gate 13), so one there was most likely pasted by mistake. The argument
/// is not echoed.
pub fn refuse_value_like(names: &[&str]) -> Result<(), Failure> {
    if names.iter().any(|n| looks_like_value(n)) {
        return Err(Failure::new(
            "value_on_argv",
            "an argument is shaped like a key or token, and values are never taken on the \
             command line: type the value at the hidden prompt, or pipe it in with --stdin; if \
             it was a key, rotate it, since your shell history may hold it now",
        ));
    }
    Ok(())
}

/// Fails unless the daemon's vault is unlocked: checked before a command
/// asks for a value or a passphrase, so nothing is typed for nothing.
pub fn require_unlocked(c: &mut envcloak_ipc::Client) -> Result<(), Failure> {
    use envcloak_ipc::proto::ErrorKind;
    use envcloak_ipc::view::VaultState;
    use envcloak_ipc::{ClientError, RpcError};
    let vault = c.status()?.vault;
    let e = match vault.state {
        VaultState::Unlocked => return Ok(()),
        VaultState::Locked => RpcError::new(ErrorKind::VaultLocked),
        VaultState::Absent => RpcError::new(ErrorKind::NoVault),
        VaultState::Unavailable => RpcError::with_reason(
            ErrorKind::VaultUnavailable,
            vault.unavailable.as_deref().unwrap_or("damaged"),
        ),
    };
    Err(ClientError::Rpc(e).into())
}

/// A file descriptor number given on the command line: digits only.
pub fn fd_number(v: &str) -> Option<i32> {
    if v.is_empty() || v.len() > 9 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::fd_number;

    #[test]
    fn descriptor_numbers_are_plain_digits() {
        assert_eq!(fd_number("0"), Some(0));
        assert_eq!(fd_number("3"), Some(3));
        assert_eq!(fd_number("123456789"), Some(123_456_789));
        for bad in ["", "-1", "+3", "3 ", "0x3", "1234567890", "three"] {
            assert_eq!(fd_number(bad), None, "{bad}");
        }
    }
}
