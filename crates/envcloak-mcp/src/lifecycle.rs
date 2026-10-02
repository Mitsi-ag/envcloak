//! The MCP session's lifecycle: `initialize` with version negotiation,
//! then `notifications/initialized`, after which tools may be listed and
//! called. `ping` is answered at any time.
//!
//! Version negotiation (MCP "Lifecycle"): when the client asks for a
//! version this server supports ([`PROTOCOL_VERSIONS`]), the answer names
//! that version; otherwise it names the latest this server supports, and
//! the client decides whether to go on. The server declares the `tools`
//! capability only: no resources, prompts, logging or sampling, so their
//! methods are unknown here.

use serde_json::{Value, json};

/// The protocol versions this server speaks, latest first.
pub const PROTOCOL_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// What the server tells the host about itself in `initialize`.
pub const INSTRUCTIONS: &str = "EnvCloak keeps API keys out of this conversation: no tool \
     ever returns a key's value. To run a command that needs the project's keys, call \
     run_with_secrets (or run `envcloak run -- <command>` in your shell); its output comes back \
     with every key masked. The first run of a command needs the person's approval in EnvCloak, \
     from a terminal of their own: say so, and never ask them to approve from this session or to \
     paste a key here. list_secrets and project_status show what exists; add_reference binds a \
     key to a variable in envcloak.toml; for a key that does not exist, request_new_secret says \
     what to ask the person to run.";

/// The version to answer for a client that asked for `asked`.
pub fn negotiate(asked: &str) -> &'static str {
    PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| *v == asked)
        .unwrap_or(PROTOCOL_VERSIONS[0])
}

/// The result of `initialize`, for version `version`.
pub fn initialize_result(version: &'static str) -> Value {
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {
            "name": "envcloak",
            "title": "EnvCloak",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": INSTRUCTIONS,
    })
}

/// Where the session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before `initialize`: only `initialize` and `ping` are taken.
    New,
    /// `initialize` was answered. Tools are taken from here on; the
    /// client's `notifications/initialized` is expected but not waited
    /// for, so a host that calls a tool before sending it is served.
    Ready,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_negotiated() {
        assert_eq!(negotiate("2025-11-25"), "2025-11-25");
        assert_eq!(negotiate("2025-06-18"), "2025-06-18");
        for other in ["2024-11-05", "2025-03-26", "", "2099-01-01", "2025-06-18 "] {
            assert_eq!(negotiate(other), "2025-11-25", "{other:?}");
        }
        let r = initialize_result("2025-06-18");
        assert_eq!(r["protocolVersion"], "2025-06-18");
        assert_eq!(r["capabilities"], json!({"tools": {"listChanged": false}}));
        assert_eq!(r["serverInfo"]["name"], "envcloak");
    }
}
