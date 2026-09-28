//! The commands (SPEC §14 M1 list). T7 has `vault create`, `unlock`,
//! `lock`, `status` and `daemon install`; T9 adds `run`'s request step,
//! `approve`, `deny` and `grants`; later tasks add the rest.
//!
//! Argument errors never echo an argument: one could be a pasted secret.

pub mod approve;
pub mod daemon;
pub mod grants;
pub mod lock;
pub mod run;
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
