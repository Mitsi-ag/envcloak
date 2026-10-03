//! The M2 acceptance story (M2 plan §4), one module per task that lands a
//! step; M2-26 composes them into the ordered story. The pull-request
//! `gates` job runs this target (§6 trigger table).
//!
//! - [`skeleton`] (M2-04): step S0, each pinned host running `envcloak run
//!   -- ./emit` through a scripted Bash call, the person approving from a
//!   terminal of their own, the rerun, and the sweep.
//! - [`mcp`] (M2-06): steps S7 and S8 through EnvCloak's MCP server, with
//!   the official MCP TypeScript SDK client and with Claude Code.
//! - [`install`] (M2-08): `envcloak agents install` and `uninstall` on
//!   configurations the pinned hosts' own CLIs wrote, and the hosts
//!   loading what it wrote (the hooks' denials, K-01's socket allowance).
#![allow(clippy::unwrap_used)]

mod install;
mod mcp;
mod skeleton;

/// The story runs with the network CI says (`ENVCLOAK_TEST_NETWORK`):
/// loopback only in the `gates` and `agents-e2e` jobs, so the hosts reach
/// nothing but the scripted model and the daemon.
#[test]
fn the_network_is_what_ci_says() {
    envcloak_e2e::check_network();
}
