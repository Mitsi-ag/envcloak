//! The commands (SPEC §14 M1 list). T7 has `vault create`, `unlock`,
//! `lock`, `status` and `daemon install`; T9 adds `run`'s request step,
//! `approve`, `deny` and `grants`; T10 adds `audit verify`; T11 adds
//! `add`, `ls`, `show`, `ref`, `check`, `rotate` and `rm`; T12 adds `run`'s
//! runner; T13 adds `init`, `import` and `recovery confirm`; later tasks
//! add the rest.
//!
//! Argument errors never echo an argument: one could be a pasted secret.
//! No command takes a value on the command line (gate 13): values come
//! from a hidden prompt on `/dev/tty` or from standard input (`--stdin`),
//! and a name given there that is shaped like a key or token is refused
//! ([`refuse_value_like`]).

pub mod add;
pub mod approve;
pub mod audit;
pub mod check;
pub mod daemon;
pub mod grants;
pub mod import;
pub mod init;
pub mod lock;
pub mod ls;
pub mod recovery;
pub mod ref_;
pub mod rm;
pub mod rotate;
pub mod run;
pub mod show;
pub mod status;
pub mod unlock;
pub mod vault;

/// The names of the agent markers set in this process's environment
/// (SPEC §10a "caller-asserted"; they only tighten), from the builtin
/// catalog and the user's extensions.
pub fn claims() -> Vec<String> {
    let catalog = match envcloak_core::vault::VaultPaths::for_user() {
        Ok(p) => envcloak_policy::AgentCatalog::load(&p.data_dir),
        Err(_) => envcloak_policy::AgentCatalog::builtin(),
    };
    envcloak_policy::Claims::from_env(&catalog)
        .markers()
        .to_vec()
}

/// This process's claims ([`claims`]), for a command about to read a
/// proof: with any marker set, the daemon refuses the proof (SPEC §10b),
/// so the command refuses first, before it reads the passphrase or shows
/// anything.
pub fn refuse_if_claimed() -> Result<Vec<String>, crate::fail::Failure> {
    let claims = claims();
    if claims.is_empty() {
        Ok(claims)
    } else {
        Err(envcloak_ipc::ClientError::Rpc(envcloak_ipc::RpcError::new(
            envcloak_ipc::proto::ErrorKind::ProofRefused,
        ))
        .into())
    }
}

/// Refuses names given on the command line (a slug, a provider, an
/// account, a variable) that are shaped like a key or token rather than a
/// name ([`crate::render::looks_like_value`]): values are never taken on
/// the command line (gate 13), so one there was most likely pasted by
/// mistake. The argument is not echoed.
pub fn refuse_value_like(names: &[&str]) -> Result<(), crate::fail::Failure> {
    if names.iter().any(|n| crate::render::looks_like_value(n)) {
        return Err(crate::fail::Failure::new(
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
pub fn require_unlocked(c: &mut envcloak_ipc::Client) -> Result<(), crate::fail::Failure> {
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
