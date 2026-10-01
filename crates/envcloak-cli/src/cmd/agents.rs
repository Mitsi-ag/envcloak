//! `envcloak agents install | uninstall | status | migrate-mcp`, which
//! teach the agent hosts EnvCloak, report what protects each one and move
//! literal keys out of their MCP configs (SPEC §6.6, §7, §7.1): not in
//! this build. The subcommands are registered ahead of their tasks (M2-08
//! for `install` and `uninstall`, M2-09 and M2-28 for `status`, M2-20 for
//! `migrate-mcp`; M2 plan D-23), so tasks in two lanes never edit the same
//! dispatcher lines. Until each lands, it exits 125 with
//! `not_in_this_build`, whatever its arguments: none is read or echoed, no
//! daemon is asked and nothing is written. Any other subcommand is a usage
//! error.

use std::process::ExitCode;

use envcloak_client::fail::usage;

const USAGE: &str =
    "envcloak agents install | uninstall | status | migrate-mcp (none is in this build)";

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["install", ..] => super::not_in_this_build("`envcloak agents install`"),
        ["uninstall", ..] => super::not_in_this_build("`envcloak agents uninstall`"),
        ["status", ..] => super::not_in_this_build("`envcloak agents status`"),
        ["migrate-mcp", ..] => super::not_in_this_build("`envcloak agents migrate-mcp`"),
        _ => usage(USAGE),
    }
}
