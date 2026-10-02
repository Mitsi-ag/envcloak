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
//!   §10b), and the grants rooted at a process in this server's own
//!   ancestry, whatever their project;
//! - coverage, which is not reported in this build (`envcloak agents
//!   status` has not shipped), and the features that are unavailable,
//!   with the milestone that brings each (R-M2-01).

use std::process::Command;

use envcloak_client::fail::Failure;
use envcloak_ipc::view::{CheckReport, GrantView};
use envcloak_policy::PendingState;
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

/// `envcloak check --json` in `dir`, read.
fn check(dir: &std::path::Path, ctx: &Ctx, call: &Call) -> Result<CheckReport, Failure> {
    let mut cmd = Command::new(&ctx.exe);
    cmd.args(["check", "--json"]).current_dir(dir);
    let failed = || {
        Failure::new(
            "run_failed",
            "the project's check (`envcloak check --json`) could not be run; nothing was changed",
        )
    };
    let done = match child::run(cmd, call, Some(ctx.wait)) {
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
    // that is not one whole report, is a failure.
    if !matches!(done.code, Some(0 | 1)) || done.cut || done.stdout.left_out() > 0 {
        return Err(failed());
    }
    serde_json::from_slice::<CheckReport>(done.stdout.head()).map_err(|_| failed())
}

/// The process ids of this process and its ancestors.
fn ancestry() -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(mut pid) = i32::try_from(std::process::id()) else {
        return out;
    };
    while pid > 0 && out.len() < envcloak_sys::MAX_ANCESTRY {
        out.push(pid);
        match envcloak_sys::proc_info(pid) {
            Ok(p) if p.ppid != pid => pid = p.ppid,
            _ => break,
        }
    }
    out
}

fn grant(g: &GrantView) -> Value {
    json!({
        "id": shown(&g.id),
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
    let report = check(&dir, ctx, call)?;

    let mut client = ctx.connect()?;
    let vault = client.status()?.vault.state;
    let mine = ancestry();
    let grants: Vec<Value> = client
        .grants_list()?
        .grants
        .iter()
        .filter(|g| mine.contains(&g.root_pid))
        .map(grant)
        .collect();
    drop(client);
    // Each request remembered, as it stands now; one that has ended is
    // forgotten.
    let mut pending = Vec::new();
    let mut ended = Vec::new();
    let (seen, missed) = ctx.pending_seen();
    for id in seen {
        let state = ctx.connect()?.pending_state(&id)?;
        if state == PendingState::Pending {
            pending.push(json!({"request": id.to_string(), "state": state.word()}));
        } else {
            ended.push(id);
        }
    }
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
