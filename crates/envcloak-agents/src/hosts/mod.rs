//! What the installer writes for each tier-1 host (SPEC §7; M2 plan
//! M2-08): Claude Code ([`claude`]) and Codex ([`codex`]). The other
//! hosts come with M2-24.

pub mod claude;
pub mod codex;

use std::path::Path;

use crate::hook::{Event, Host};

/// The seconds a host gives EnvCloak's hook before it goes on without an
/// answer (both hosts then let the action through: the coverage report
/// says `fails_open_on_timeout`). The handler answers within its own 2 s.
pub const HOOK_TIMEOUT_SECS: u64 = 10;

/// `s` quoted for a POSIX shell, as the hosts run hook commands: as it is
/// when it holds only characters no shell reads, else in single quotes.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+:,=@%".contains(&b))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command a host runs for `event`: `<envcloak> hook --host <id>
/// --event <name>`, with EnvCloak's absolute path.
pub fn hook_command(envcloak: &Path, host: Host, event: Event) -> String {
    format!(
        "{} hook --host {} --event {}",
        shell_quote(&envcloak.to_string_lossy()),
        host.id(),
        event.name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_quoted_for_a_shell() {
        assert_eq!(
            shell_quote("/usr/local/bin/envcloak"),
            "/usr/local/bin/envcloak"
        );
        assert_eq!(
            shell_quote("/Users/a b/bin/envcloak"),
            "'/Users/a b/bin/envcloak'"
        );
        assert_eq!(shell_quote("/x/it's"), "'/x/it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(
            hook_command(Path::new("/b/envcloak"), Host::Codex, Event::PreToolUse),
            "/b/envcloak hook --host codex --event PreToolUse"
        );
    }
}
