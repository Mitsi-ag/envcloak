//! K-01 as measured (M2 plan task M2-04): whether a pinned host's
//! sandboxed shell reaches EnvCloak's daemon, for each sandbox setting
//! `agent_hosts` measures, on each system. The one table that
//! `agent_hosts` asserts its measurements against, that story step S0
//! takes its expected outcome from, and that docs/AGENTS.md ("Host
//! behaviour", "K-01 on Linux") records: a setting the table says does
//! not reach the daemon is `unsupported (sandbox_blocks_socket)` there,
//! and S0 then requires that refusal of its own invocation, not a
//! delivery.

/// The CLI's refusal when the sandbox will not let it look at the
/// daemon's runtime directory (`EPERM`): `envcloak: <this>; nothing was
/// sent to it`, exit 125, before a byte is sent.
pub const RUNTIME_DIR: &str =
    "daemon_unverified: the daemon's runtime directory cannot be accessed";

/// The CLI's refusal when the socket is reached but the sandbox's own pid
/// namespace hides the daemon's pid (the kernel reports 0), which the
/// client requires.
pub const NO_PEER_PID: &str =
    "daemon_unverified: the kernel did not report who is listening on the socket";

/// What Claude Code's Linux sandbox prints when it cannot apply its
/// seccomp filter, inside a user namespace: the command never runs.
pub const SECCOMP_HELPER: &str = "apply-seccomp: write /proc/self/uid_map: Operation not permitted";

/// What the CLI adds to a pre-send `daemon_unverified` message.
pub const NOTHING_SENT: &str = "; nothing was sent to it";

/// The coverage reason a refused setting is reported with (docs/IPC.md,
/// reserved for M2-04).
pub const REASON: &str = "sandbox_blocks_socket";

/// A host's shell, as a setting the person (or M2-08's installer) makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// Claude Code's Bash tool with its sandbox off, its default.
    ClaudeUnsandboxed,
    /// Claude Code's sandbox on (`enabled`, `failIfUnavailable`,
    /// `allowUnsandboxedCommands: false`) with no socket allowance: what
    /// M2-08 leaves on Linux, where it writes none.
    ClaudeSandboxNoAllowance,
    /// The same with `network.allowUnixSockets` naming the socket as the
    /// daemon names it (macOS only).
    ClaudeSandboxAllowGiven,
    /// The same naming the socket's resolved path: what M2-08 writes on
    /// macOS (macOS only).
    ClaudeSandboxAllowResolved,
    /// The same with `network.allowAllUnixSockets` (Linux only).
    ClaudeSandboxAllowAll,
    /// Codex `exec --sandbox read-only`, no network setting.
    CodexReadOnly,
    /// `read-only` with the bounded setting (network access, the network
    /// proxy on, no domain rule, one `unix_sockets` rule for the socket).
    CodexReadOnlyBounded,
    /// `workspace-write`, no network setting: what M2-08 leaves on Linux.
    CodexWorkspaceWrite,
    /// `workspace-write` with `network_access` alone.
    CodexWorkspaceWriteNetwork,
    /// `workspace-write` with the bounded setting: what M2-08 writes on
    /// macOS.
    CodexWorkspaceWriteBounded,
}

/// What a command in that shell gets when it asks for the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// It reaches and verifies the daemon.
    Reaches,
    /// The CLI fails closed with this message, before it sends a byte.
    Refused(&'static str),
    /// The sandbox runs no command at all, and says this.
    NotRun(&'static str),
}

impl Reach {
    /// The receipt a story step or a status line gives for it on `os`: a
    /// refusal there is `unsupported (sandbox_blocks_socket)` where no
    /// documented allowance reaches the daemon ([`unsupported`]), and
    /// otherwise a setting without the allowance M2-08 writes. A sandbox
    /// that runs no command at all never reached the socket: that is a
    /// limit of the environment (Claude Code's seccomp helper inside a
    /// user namespace), not the refusal, and gives no K-01 receipt; the
    /// receipt for that setting rests on its run outside a user namespace,
    /// which CI requires (verifier, low).
    pub fn receipt(self, os: &str) -> String {
        let why = match self {
            Reach::Reaches => return "qualified: reaches the daemon".to_owned(),
            Reach::NotRun(why) => {
                return format!(
                    "no receipt here (an environment limitation: the sandbox runs no command, \
                     so the socket is never tried): {why}; K-01's receipt for this setting is \
                     the run outside a user namespace"
                );
            }
            Reach::Refused(why) => why,
        };
        if unsupported(os) {
            format!("unsupported ({REASON}): the CLI refuses: {why}")
        } else {
            format!("refused without the allowance M2-08 writes on {os}: the CLI refuses: {why}")
        }
    }
}

/// Whether the pinned hosts' sandboxed shells are `unsupported` on `os`:
/// no documented allowance lets them reach the daemon (docs/AGENTS.md,
/// "K-01 on Linux": both hosts on Linux), so M2-08 writes none there.
pub fn unsupported(os: &str) -> bool {
    os == "linux"
}

/// What `shell` gets on `os` (`macos` or `linux`), inside a user
/// namespace (CI's `unshare -rn`) or not; `None` for a setting that does
/// not exist there.
pub fn expected(shell: Shell, os: &str, user_namespace: bool) -> Option<Reach> {
    use Reach::{NotRun, Reaches, Refused};
    use Shell::{
        ClaudeSandboxAllowAll, ClaudeSandboxAllowGiven, ClaudeSandboxAllowResolved,
        ClaudeSandboxNoAllowance, ClaudeUnsandboxed, CodexReadOnly, CodexReadOnlyBounded,
        CodexWorkspaceWrite, CodexWorkspaceWriteBounded, CodexWorkspaceWriteNetwork,
    };
    let linux = match os {
        "macos" => false,
        "linux" => true,
        _ => return None,
    };
    Some(match (shell, linux) {
        (ClaudeUnsandboxed, _) => Reaches,
        (ClaudeSandboxNoAllowance, true) if user_namespace => NotRun(SECCOMP_HELPER),
        (ClaudeSandboxNoAllowance, _) => Refused(RUNTIME_DIR),
        (ClaudeSandboxAllowGiven, false) => Refused(RUNTIME_DIR),
        (ClaudeSandboxAllowResolved, false) => Reaches,
        (ClaudeSandboxAllowAll, true) => Refused(NO_PEER_PID),
        (ClaudeSandboxAllowGiven | ClaudeSandboxAllowResolved, true)
        | (ClaudeSandboxAllowAll, false) => return None,
        (CodexReadOnly | CodexReadOnlyBounded | CodexWorkspaceWrite, _) => Refused(RUNTIME_DIR),
        (CodexWorkspaceWriteNetwork, false) => Reaches,
        (CodexWorkspaceWriteNetwork, true) => Refused(NO_PEER_PID),
        (CodexWorkspaceWriteBounded, false) => Reaches,
        (CodexWorkspaceWriteBounded, true) => Refused(RUNTIME_DIR),
    })
}

/// Whether this process runs in a Linux user namespace other than the
/// initial one (its uid map is not the identity of every uid); false
/// elsewhere.
pub fn user_namespace() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(map) => map.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"],
        Err(e) => panic!("cannot tell whether this runs in a user namespace: {e}"),
    }
}

/// Checks what docs/AGENTS.md records against [`expected`]: every message
/// a refused or never-run setting gives is in its host behaviour table,
/// and its "K-01 on Linux" section names both pinned hosts `unsupported`
/// and the reason token. The matching receipt S0 and `agent_hosts` rest
/// on, so a table that disagrees with the docs fails. The full CLI refusal
/// must also match the published S0 contract in docs/ACCEPTANCE.md.
///
/// # Panics
/// When the docs say otherwise.
pub fn check_documented() {
    let acceptance = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ACCEPTANCE.md"),
    )
    .expect("read docs/ACCEPTANCE.md");
    assert!(
        acceptance.contains(&format!("`envcloak: {RUNTIME_DIR}{NOTHING_SENT}`")),
        "K-01's full pre-send refusal differs from docs/ACCEPTANCE.md"
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/AGENTS.md");
    let docs =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    for message in [RUNTIME_DIR, NO_PEER_PID, SECCOMP_HELPER] {
        assert!(
            docs.contains(message),
            "docs/AGENTS.md does not record {message:?}"
        );
    }
    let section = docs
        .split("**K-01 on Linux.**")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .unwrap_or_else(|| panic!("docs/AGENTS.md has no \"K-01 on Linux\" section"));
    for host in [
        "- Codex: retired, as `unsupported`",
        "- Claude Code: retired, as `unsupported`",
    ] {
        assert!(
            section.contains(host),
            "docs/AGENTS.md's K-01 section lacks {host:?}"
        );
    }
    assert!(
        section.contains(&format!("`{REASON}`")),
        "docs/AGENTS.md's K-01 section does not name `{REASON}`"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_send_refusal_agrees_with_acceptance_contract() {
        check_documented();
    }

    /// Only the CLI's own refusal is K-01's `unsupported` receipt: a
    /// sandbox that ran no command never tried the socket, and its line
    /// says it is an environment limitation, never `sandbox_blocks_socket`
    /// (verifier, low: it printed `unsupported (sandbox_blocks_socket)`).
    #[test]
    fn only_the_cli_s_refusal_is_the_unsupported_receipt() {
        let refused = Reach::Refused(RUNTIME_DIR).receipt("linux");
        assert!(
            refused.starts_with(&format!("unsupported ({REASON})")),
            "{refused}"
        );
        for os in ["linux", "macos"] {
            let not_run = Reach::NotRun(SECCOMP_HELPER).receipt(os);
            assert!(
                !not_run.contains("unsupported") && !not_run.contains(REASON),
                "{not_run}"
            );
            assert!(not_run.contains("environment limitation"), "{not_run}");
        }
        assert!(
            !Reach::Refused(RUNTIME_DIR)
                .receipt("macos")
                .contains(REASON)
        );
    }
}
