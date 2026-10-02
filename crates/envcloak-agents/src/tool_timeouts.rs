//! How long each agent host waits for an MCP tool call, as EnvCloak's
//! installer sets it up, and how long an EnvCloak tool may wait for a
//! person before it answers (M2 plan task M2-06: the default of `envcloak
//! mcp --host <id> --wait-ms`; M2-18's `mcp-bridge` and M2b-10's sign-in
//! tools wait the same way).
//!
//! The cutoffs are M2-04's measurements of the pinned hosts (docs/AGENTS.md
//! "Host behaviour"), under the per-server setting the installer writes
//! (M2-08 writes [`McpHost::tool_timeout`] for each host here):
//!
//! - Claude Code 2.1.280: the `timeout` of its MCP entry is the cutoff (a
//!   70 s call under `"timeout": 60000` was cut off after 60.0 s). Without
//!   one, `-p` showed no cutoff below 70 s; an earlier version measured 10
//!   s (SI-17), so the installer always writes it.
//! - Codex 0.159.2: `tool_timeout_sec` is the cutoff (a 15 s call under
//!   `tool_timeout_sec = 5` was cut off after 5.0 s).
//! - Any other host, or none named: [`UNKNOWN_CUTOFF`], the 10 s Claude
//!   Code cutoff SI-17 measured without a per-server timeout (K-08).
//!
//! A tool waits for a person at most the cutoff less [`MARGIN`], at least
//! [`MIN_WAIT`] and at most [`MAX_WAIT`] ([`default_wait`]): it answers
//! with the pending request before the host gives up on the call.

use std::time::Duration;

/// One host's MCP tool cutoff, as the installer sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpHost {
    /// The host's catalog id (`integrations/agents.toml`), as `--host`
    /// names it.
    pub id: &'static str,
    /// The per-server tool timeout the installer writes for EnvCloak's
    /// server, which the measurements show is the host's cutoff.
    pub tool_timeout: Duration,
}

/// The hosts whose cutoff is known: the tier-1 hosts, whose MCP entries
/// the installer writes with a timeout.
pub const HOSTS: &[McpHost] = &[
    McpHost {
        id: "claude-code",
        tool_timeout: Duration::from_secs(60),
    },
    McpHost {
        id: "codex",
        tool_timeout: Duration::from_secs(60),
    },
];

/// The cutoff assumed for any other host: Claude Code's 10 s without a
/// per-server timeout (SI-17, K-08).
pub const UNKNOWN_CUTOFF: Duration = Duration::from_secs(10);
/// How much sooner than the cutoff a tool answers.
pub const MARGIN: Duration = Duration::from_secs(2);
/// The shortest wait.
pub const MIN_WAIT: Duration = Duration::from_secs(1);
/// The longest wait, whatever the cutoff.
pub const MAX_WAIT: Duration = Duration::from_secs(20);

/// The host `id` names, when its cutoff is known.
pub fn host(id: &str) -> Option<&'static McpHost> {
    HOSTS.iter().find(|h| h.id == id)
}

/// How long `host` waits for an EnvCloak tool call: its installed tool
/// timeout, or [`UNKNOWN_CUTOFF`] for a host not in [`HOSTS`] or none.
pub fn cutoff(host_id: Option<&str>) -> Duration {
    host_id
        .and_then(host)
        .map_or(UNKNOWN_CUTOFF, |h| h.tool_timeout)
}

/// How long a tool may wait for a person under `host`: [`cutoff`] less
/// [`MARGIN`], from [`MIN_WAIT`] to [`MAX_WAIT`].
pub fn default_wait(host_id: Option<&str>) -> Duration {
    cutoff(host_id)
        .saturating_sub(MARGIN)
        .clamp(MIN_WAIT, MAX_WAIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each host's wait ends before its cutoff, by the margin; an unknown
    /// host gets 8 s, below the 10 s cutoff it is assumed to have.
    #[test]
    fn every_wait_ends_before_its_hosts_cutoff() {
        assert_eq!(default_wait(Some("claude-code")), Duration::from_secs(20));
        assert_eq!(default_wait(Some("codex")), Duration::from_secs(20));
        assert_eq!(default_wait(None), Duration::from_secs(8));
        assert_eq!(default_wait(Some("gemini-cli")), Duration::from_secs(8));
        assert_eq!(default_wait(Some("")), Duration::from_secs(8));
        for id in HOSTS
            .iter()
            .map(|h| Some(h.id))
            .chain([None, Some("other")])
        {
            let (wait, cut) = (default_wait(id), cutoff(id));
            assert!(wait + MARGIN <= cut, "{id:?}: {wait:?} against {cut:?}");
            assert!((MIN_WAIT..=MAX_WAIT).contains(&wait), "{id:?}");
        }
        // The ids are unique and are catalog ids.
        let mut ids: Vec<&str> = HOSTS.iter().map(|h| h.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), HOSTS.len());
    }
}
