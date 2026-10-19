//! `envcloak mcp-bridge`: client bridges for HTTP and stdio MCP servers and
//! the daemon-started HTTP relay (`--relay`) (SPEC §6.4, §6.6; M2 plan
//! D-04, D-05, D-06, D-18, D-33, D-36; task M2-18).
//!
//! Three modes share this module:
//! - [`Bridge::run_http`] (`bridge::http`): the HTTP client mode started by
//!   an MCP host (`envcloak mcp-bridge --manifest <path> --url <url>
//!   --header-ref <Header>=<slug>[#<field>]... [--wait [<duration>]]`). It
//!   validates the URL and header references, sends `run.request` with its
//!   pipe ends and lifeline over `SCM_RIGHTS`, never receives secret values
//!   (D-36), and forwards MCP JSON-RPC traffic to and from the relay that
//!   `envcloakd` spawns.
//! - [`Bridge::run_stdio`] (`bridge::stdio`): the stdio client mode started
//!   by an MCP host (`envcloak mcp-bridge --stdio --launch <launch-id>`).
//!   It hands its pipe ends and lifeline to `envcloakd`, never receives
//!   secret values, and pumps its standard input and output to and from the
//!   runner (`envcloak run --launch <id>`) that `envcloakd` spawns.
//! - [`Bridge::run_relay`] (`bridge::relay`): the daemon-started HTTP relay
//!   (`envcloak mcp-bridge --relay`). It verifies that `envcloakd` is its
//!   parent (`not_started_by_daemon` otherwise), reads the released header
//!   values and registered origin from the control channel, checks the
//!   provider registry's `allowed_hosts`, builds the response redactor, and
//!   executes MCP Streamable HTTP (`POST` with JSON and `text/event-stream`
//!   SSE responses) over `ureq` + `rustls` with platform certificate
//!   verification and zero redirects.

pub mod handoff;
pub mod http;
pub mod relay;
pub mod sse;
pub mod stdio;

use envcloak_client::fail::Failure;

pub use handoff::{StartedPipes, WaitBudget, default_wait_budget, detected_host_wait};
pub use http::{BridgeUrl, HeaderRef, HttpBridgeConfig, is_loopback_host, run_http};
pub use relay::{PreparedRelay, build_http_agent, prepare_release, redact_json_line, run_relay};
pub use sse::{MAX_SSE_EVENT_BYTES, SseError, SseEvent, SseParser};
pub use stdio::{StdioBridgeConfig, run_stdio};

/// Entry point facade for the three `envcloak mcp-bridge` modes.
#[derive(Debug, Clone, Copy)]
pub struct Bridge;

impl Bridge {
    /// Runs `envcloak mcp-bridge` in HTTP client mode.
    ///
    /// # Errors
    /// As [`run_http`].
    pub fn run_http(config: &HttpBridgeConfig) -> Result<(), Failure> {
        run_http(config)
    }

    /// Runs `envcloak mcp-bridge --stdio --launch <launch-id>`.
    ///
    /// # Errors
    /// As [`run_stdio`].
    pub fn run_stdio(config: &StdioBridgeConfig) -> Result<(), Failure> {
        run_stdio(config)
    }

    /// Runs `envcloak mcp-bridge --relay` (daemon-started only).
    ///
    /// # Errors
    /// As [`run_relay`].
    pub fn run_relay() -> Result<(), Failure> {
        run_relay()
    }
}
