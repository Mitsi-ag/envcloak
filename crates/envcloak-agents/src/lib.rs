//! EnvCloak's agent integrations (SPEC §7).
//!
//! - [`hook`]: the handler the agent hosts' prompt and tool-call hooks run
//!   (`envcloak hook`), and the argv check `run_with_secrets` shares with
//!   it (M2 plan M2-08, D-12, D-22).
//! - [`install`] with [`blocks`], [`jsonedit`], [`writer`], [`hunks`],
//!   [`detect`] and [`hosts`]: `envcloak agents install` and `uninstall`
//!   for Claude Code and Codex (M2-08, D-16).
//! - [`locations`]: the host, version and path catalog, the only place
//!   host paths are named, which emits the scanner's descriptors (D-02);
//!   [`codex_layers`]: Codex's settings as it merges its layers.
//! - [`probe::model`]: the scripted model that the agent hosts are pointed
//!   at when EnvCloak drives them for a coverage probe or a test (M2-04,
//!   D-13), shipped as the program `envcloak-probe-model`.
//! - [`tool_timeouts`]: each host's MCP tool cutoff as the installer sets
//!   it, which bounds how long EnvCloak's MCP tools wait for a person
//!   (M2-06).

pub mod blocks;
pub mod codex_layers;
pub mod detect;
pub mod hook;
pub mod hosts;
pub mod hunks;
pub mod install;
pub mod jsonedit;
pub mod locations;
pub mod probe;
pub mod tool_timeouts;
pub mod writer;
