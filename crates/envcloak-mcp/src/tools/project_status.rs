//! `project_status { project_dir }`: where a project stands with EnvCloak
//! (SPEC §7, D-20), metadata only:
//!
//! - its `envcloak.toml`, each binding and whether it resolves, and its env
//!   files' plaintext keys by count. These come from a child `envcloak
//!   check --json` run in `project_dir` (so the env files are read by the
//!   CLI's own reader, never by this server), killed if it outlives the
//!   wait;
//! - the requests this server's `run_with_secrets` calls opened that are
//!   still pending (an agent is never shown the person's list, SPEC
//!   §10b), and the grants that may cover those calls, whatever their
//!   project ([`covers_this_server`]);
//! - coverage, which is not reported in this build (`envcloak agents
//!   status` has not shipped), and the features that are unavailable,
//!   with the milestone that brings each (R-M2-01).
//!
//! The whole call ends within the server's wait, which is under the host's
//! cutoff: the check and every daemon call share one deadline, and the
//! daemon is asked on one connection bounded by it, so neither a slow
//! check nor a daemon slow to answer each request's state can add a wait
//! of its own.

use std::process::Command;
use std::time::Instant;

use envcloak_client::fail::Failure;
use envcloak_ipc::view::{CheckReport, GrantView};
use envcloak_policy::{
    AgentCatalog, Claims, GrantId, PendingState, ProcessInstance, SubjectEvidence, gather,
};
use envcloak_sys::{PeerIdentity, PeerSource};
use serde_json::{Map, Value, json};

use super::{Ctx, check_keys, object, project_dir, refuse_value_like, req_str, shown, shown_path};
use crate::child::{self, Call, NotRun};
use crate::router::{Annotations, Tool, ToolResult, ToolSchema};

/// The tool's name.
pub const TOOL: &str = "project_status";

/// The features an agent may ask about that this build does not have, and
/// what brings each (R-M2-01: shown as unavailable, never implied).
pub const UNAVAILABLE: &[(&str, Option<&str>, &str)] = &[
    (
        "coverage",
        Some("M2"),
        "`envcloak agents status` is not in this build: no agent surface is reported active",
    ),
    (
        "paste_sheet",
        Some("M3"),
        "adding a key through EnvCloak's app; until then the person runs `envcloak add \
         <provider>` in a terminal of their own (request_new_secret says so)",
    ),
    (
        "usage_summary",
        Some("M4"),
        "spend and usage per key; the tool is not listed before then",
    ),
    (
        "proxy_mode",
        Some("M6"),
        "keys kept out of the command's environment; every run in this build injects them, and \
         the command holds them while it runs",
    ),
    ("reveal", None, "never available over MCP"),
    (
        "doctor",
        None,
        "never available over MCP; the person runs it",
    ),
];

#[derive(Debug)]
pub struct ProjectStatus;

impl Tool for ProjectStatus {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: TOOL,
            title: "Show a project's EnvCloak status",
            description: "Shows where a project stands with EnvCloak, metadata only: its \
                 envcloak.toml and whether each binding resolves, how many plaintext keys its \
                 .env files still hold, the requests this server's run_with_secrets calls left \
                 waiting for the person's approval, the grants for this agent, and which EnvCloak \
                 features are unavailable in this version. Never returns a value.",
            input: object(
                json!({
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path of the project directory.",
                    },
                }),
                &["project_dir"],
            ),
            output: object(
                json!({
                    "project_dir": {"type": "string"},
                    "manifest": {"type": ["string", "null"]},
                    "project_name": {"type": ["string", "null"]},
                    "bindings": {"type": "array"},
                    "bindings_resolved": {"type": "integer"},
                    "bindings_unresolved": {"type": "integer"},
                    "references_unchecked": {"type": ["string", "null"]},
                    "env_files": {"type": "array"},
                    "plaintext_env_lines": {"type": "integer"},
                    "env_files_skipped": {"type": "integer"},
                    "env_scan_error": {"type": ["string", "null"]},
                    "vault": {"type": "string"},
                    "pending_requests": {"type": "array"},
                    "pending_untracked": {"type": "boolean"},
                    "grants": {"type": "array"},
                    "coverage": {"type": "null"},
                    "unavailable": {"type": "array"},
                }),
                &[
                    "project_dir",
                    "manifest",
                    "bindings",
                    "plaintext_env_lines",
                    "vault",
                    "pending_requests",
                    "grants",
                    "coverage",
                    "unavailable",
                ],
            ),
            annotations: Annotations {
                read_only: Some(true),
                open_world: Some(false),
                ..Annotations::default()
            },
        }
    }

    fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
        match status(args, ctx, call) {
            Ok(v) => ToolResult::Ok(v),
            Err(f) => ToolResult::Err(f),
        }
    }
}

/// `envcloak check --json` in `dir`, read; stopped at `deadline`.
fn check(
    dir: &std::path::Path,
    ctx: &Ctx,
    call: &Call,
    deadline: Instant,
) -> Result<CheckReport, Failure> {
    let mut cmd = Command::new(&ctx.exe);
    cmd.args(["check", "--json"]).current_dir(dir);
    let failed = || {
        Failure::new(
            "run_failed",
            "the project's check (`envcloak check --json`) could not be run; nothing was changed",
        )
    };
    let limit = deadline.saturating_duration_since(Instant::now());
    let done = match child::run(cmd, call, Some(limit)) {
        Ok(c) => c,
        Err(NotRun::Cancelled) => {
            return Err(Failure::new("cancelled", "the call was cancelled"));
        }
        Err(NotRun::Spawn) => return Err(failed()),
    };
    if done.timed_out {
        return Err(Failure::new(
            "run_failed",
            "the project's check did not finish within the wait and was stopped",
        ));
    }
    // 0: clean; 1: the report says what is wrong. Anything else, or output
    // that is not one whole report, is a failure. A report kept whole may
    // run past the head into the tail: it is read from both.
    if !matches!(done.code, Some(0 | 1)) || done.cut || done.stdout.left_out() > 0 {
        return Err(failed());
    }
    let mut report = done.stdout.head().to_vec();
    report.extend(done.stdout.tail());
    serde_json::from_slice::<CheckReport>(&report).map_err(|_| failed())
}

/// This server's own evidence, read as the daemon reads a caller's
/// (`envcloak_policy::gather`): its ancestry from the kernel, each process
/// of this user classified with the agent catalog the daemon loads (the
/// builtin entries and the user's extensions), and the agent markers in its
/// environment as its claims. The daemon does not tell a client the
/// evidence it read, so the server reads its own the same way. An
/// `envcloak run` it starts has this chain above it, in the same session
/// with the same terminal and markers, so a grant rooted in that chain
/// covers the run exactly when it covers this process. `None` when it
/// cannot be read: no grant is shown then.
fn own_evidence() -> Option<SubjectEvidence> {
    let pid = i32::try_from(std::process::id()).ok()?;
    let me = PeerIdentity {
        uid: envcloak_sys::effective_uid(),
        pid,
        start_time: envcloak_sys::process_start_time(pid).ok()?,
        pidversion: None,
        // Read from the process table, not a socket; the walk checks the
        // start time again.
        source: PeerSource::PeerCred,
    };
    let catalog = match envcloak_core::vault::VaultPaths::for_user() {
        Ok(p) => AgentCatalog::load(&p.data_dir),
        Err(_) => AgentCatalog::builtin(),
    };
    gather(&me, Claims::from_env(&catalog), &catalog).ok()
}

/// Whether grant `g` may cover this server's `run_with_secrets` calls, by
/// SPEC §10b "Match" rules 3 and 4 as the daemon applies them
/// (`SubjectEvidence::covered_by`): its root is in this server's chain
/// with its start time, no known agent sits between the root and the
/// server unless the root is that agent (the agent barrier), a root above
/// the session is an agent that may be one, and a grant approved for a
/// terminal subject covers only a terminal subject. So a terminal grant
/// rooted at the shell that started the agent is not this agent's. The
/// project, bindings and mode (rules 5 to 7) are each call's, and are not
/// asked here.
fn covers_this_server(me: &SubjectEvidence, g: &GrantView) -> bool {
    if g.root_pid < 1 {
        return false;
    }
    let Ok(start_time) = envcloak_sys::process_start_time(g.root_pid) else {
        return false;
    };
    let root = ProcessInstance {
        pid: g.root_pid,
        start_time,
        pidversion: None,
        exe: None,
    };
    me.covered_by(&root, g.kind)
}

/// A grant id the daemon sent, in its canonical form (26 Crockford base32
/// characters, which [`shown`] would take for a token); one that is not a
/// grant id is not shown.
fn grant_id(id: &str) -> String {
    GrantId::parse(id).map_or_else(
        || envcloak_client::render::HIDDEN.to_owned(),
        |g| g.to_string(),
    )
}

fn grant(g: &GrantView) -> Value {
    json!({
        "id": grant_id(&g.id),
        "label": g.label.as_deref().map(shown),
        "project_dir": shown_path(&g.project_dir),
        "bindings": g.bindings.iter().map(|b| json!({
            "env_name": shown(&b.env_name),
            "slug": shown(&b.slug),
            "live": b.live,
        })).collect::<Vec<_>>(),
        "uses": serde_json::to_value(g.uses).unwrap_or(Value::Null),
        "remaining_secs": g.remaining_secs,
    })
}

fn status(args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
    check_keys(args, &["project_dir"], &["project_dir"])?;
    let given = req_str(args, "project_dir")?;
    refuse_value_like(&[given])?;
    let dir = project_dir(given)?;
    // The wait counts from the call's arrival, the time it waited for a
    // worker included.
    let deadline = call.deadline(ctx.wait);
    let report = check(&dir, ctx, call, deadline)?;

    let mut client = ctx.connect_by(deadline)?;
    let vault = client.status()?.vault.state;
    let me = own_evidence();
    let grants: Vec<Value> = client
        .grants_list()?
        .grants
        .iter()
        .filter(|g| me.as_ref().is_some_and(|me| covers_this_server(me, g)))
        .map(grant)
        .collect();
    // Each request remembered, as it stands now; one that has ended is
    // forgotten.
    let mut pending = Vec::new();
    let mut ended = Vec::new();
    let (seen, missed) = ctx.pending_seen();
    for id in seen {
        let state = client.pending_state(&id)?;
        if state == PendingState::Pending {
            pending.push(json!({"request": id.to_string(), "state": state.word()}));
        } else {
            ended.push(id);
        }
    }
    drop(client);
    ctx.forget_pending(&ended);

    let bindings = report
        .references
        .as_ref()
        .map(|r| &r.bindings[..])
        .unwrap_or(&[]);
    let resolved = bindings.iter().filter(|b| b.status.is_ok()).count();
    let plaintext: usize = report.env_files.iter().map(|f| f.plaintext.len()).sum();
    Ok(json!({
        "project_dir": shown_path(given),
        "manifest": report.manifest.as_deref().map(shown_path),
        "project_name": report
            .references
            .as_ref()
            .and_then(|r| r.project_name.as_deref())
            .map(shown),
        "bindings": bindings.iter().map(|b| json!({
            "profile": b.profile.as_deref().map(shown),
            "env_name": b.env_name.as_deref().map(shown),
            "reference": b.reference.as_deref().map(shown),
            "status": serde_json::to_value(b.status).unwrap_or(Value::Null),
        })).collect::<Vec<_>>(),
        "bindings_resolved": resolved,
        "bindings_unresolved": bindings.len() - resolved,
        "references_unchecked": report
            .references_unchecked()
            .then(|| report.unchecked.as_deref().map(shown))
            .flatten(),
        "env_files": report.env_files.iter().map(|f| json!({
            "file": shown(&f.file),
            "state": serde_json::to_value(f.state).unwrap_or(Value::Null),
            "plaintext_lines": f.plaintext.len(),
        })).collect::<Vec<_>>(),
        "plaintext_env_lines": plaintext,
        "env_files_skipped": report.env_files_skipped,
        "env_scan_error": report.env_scan_error,
        "vault": serde_json::to_value(vault).unwrap_or(Value::Null),
        "pending_requests": pending,
        "pending_untracked": missed,
        "grants": grants,
        "coverage": Value::Null,
        "unavailable": UNAVAILABLE.iter().map(|(feature, milestone, detail)| json!({
            "feature": feature,
            "milestone": milestone,
            "detail": detail,
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;
    use crate::child::{OUTPUT_HEAD, OUTPUT_TAIL};

    /// A stand-in for `envcloak` whose `check --json` prints `report`.
    fn printing(dir: &std::path::Path, report: &[u8]) -> Ctx {
        let file = dir.join("report.json");
        std::fs::write(&file, report).unwrap();
        let exe = dir.join("envcloak");
        std::fs::write(
            &exe,
            format!("#!/bin/sh\nexec /bin/cat '{}'\n", file.display()),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        Ctx::new(exe, None, Duration::from_secs(30))
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// A report of `n` bytes or a little more.
    fn report_of(n: usize) -> CheckReport {
        CheckReport {
            manifest: Some(format!("/{}/envcloak.toml", "p".repeat(n))),
            references: None,
            unchecked: Some(CheckReport::NOTHING_SENT.to_owned()),
            env_files: Vec::new(),
            env_files_skipped: 0,
            env_scan_error: None,
        }
    }

    /// `envcloak check --json`'s report is read whole when it was kept
    /// whole, also when it is longer than the head and runs into the tail;
    /// one longer than the head and tail together, of which bytes were
    /// left out, fails closed.
    ///
    /// Mutation checked: the report read from the head alone: a report
    /// between 64 and 128 KiB fails to parse and this fails.
    #[test]
    fn a_report_past_the_head_is_read_whole_and_one_cut_fails() {
        let dir = tempfile::tempdir().unwrap();
        for n in [10, OUTPUT_HEAD + 1000, OUTPUT_HEAD + OUTPUT_TAIL - 1000] {
            let want = report_of(n);
            let bytes = serde_json::to_vec(&want).unwrap();
            assert!(bytes.len() <= OUTPUT_HEAD + OUTPUT_TAIL);
            let ctx = printing(dir.path(), &bytes);
            let got = check(dir.path(), &ctx, &Call::new(), later()).unwrap();
            assert_eq!(got, want, "{n}");
        }
        let bytes = serde_json::to_vec(&report_of(OUTPUT_HEAD + OUTPUT_TAIL)).unwrap();
        let ctx = printing(dir.path(), &bytes);
        assert_eq!(
            check(dir.path(), &ctx, &Call::new(), later())
                .unwrap_err()
                .token(),
            "run_failed"
        );
    }

    /// Grant ids are shown as they are: they have a token's shape, which
    /// would hide them as names. Anything else in their place is hidden.
    ///
    /// Mutation checked: the id shown as a name (`shown`): every grant id
    /// is the placeholder and this fails.
    #[test]
    fn grant_ids_are_shown_and_anything_else_hidden() {
        for _ in 0..100 {
            let id = GrantId::generate().to_string();
            assert_eq!(grant_id(&id), id);
        }
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for c in &cs {
            assert_eq!(grant_id(c.as_str()), envcloak_client::render::HIDDEN);
        }
        assert_eq!(grant_id(""), envcloak_client::render::HIDDEN);
    }
}
