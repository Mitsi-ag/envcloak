//! `envcloak grants list [--json]` and `envcloak grants revoke <GRANT> |
//! --all` (SPEC §10b "A grant ends on"): the grants in force, metadata
//! only, and revocation, which any client may do because tightening needs
//! no proof.
//!
//! Every string the daemon sends (an agent's name, a path, a slug) is
//! escaped before it is printed ([`escape_for_display`]): a program
//! running as the user could answer in the daemon's place. The `--json`
//! form prints the daemon's answer as JSON, whose encoding escapes control
//! characters itself.

use std::process::ExitCode;

use envcloak_ipc::view::GrantView;
use envcloak_policy::{GrantId, SubjectKind, Uses, escape_for_display};

use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};

const USAGE: &str = "envcloak grants list [--json]\n       envcloak grants revoke <GRANT> | --all";

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["list"] => list(false),
        ["list", "--json"] => list(true),
        ["revoke", "--all"] => revoke(None),
        ["revoke", id] => match GrantId::parse(id) {
            Some(id) => revoke(Some(id)),
            None => return usage(USAGE),
        },
        _ => return usage(USAGE),
    }
    .unwrap_or_else(|f| f.report(FAILURE))
}

fn list(json: bool) -> Result<ExitCode, Failure> {
    let grants = connect()?.grants_list()?;
    if json {
        println!("{}", serde_json::to_value(&grants).unwrap_or_default());
        return Ok(ExitCode::SUCCESS);
    }
    if grants.grants.is_empty() {
        println!("No grants are in force.");
        return Ok(ExitCode::SUCCESS);
    }
    for g in &grants.grants {
        print_grant(g);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_grant(g: &GrantView) {
    let e = escape_for_display;
    let id = GrantId::parse(&g.id).map_or_else(|| e(&g.id), |id| id.to_string());
    let who = match (g.kind, &g.label) {
        (SubjectKind::Agent, Some(l)) => format!("agent {}", e(l)),
        (SubjectKind::Agent, None) => "an agent".to_owned(),
        (SubjectKind::Terminal, _) => "a terminal session".to_owned(),
        (SubjectKind::Unknown, _) => "a process of unknown origin".to_owned(),
    };
    let uses = match g.uses {
        Uses::Once => "once".to_owned(),
        Uses::Session => format!("session, {} left", words(g.remaining_secs)),
    };
    println!("{id}");
    println!(
        "  for: {who}, rooted at pid {}{}",
        g.root_pid,
        g.root_exe
            .as_deref()
            .map(|x| format!(" ({})", e(x)))
            .unwrap_or_default()
    );
    println!("  project: {}", e(&g.project_dir));
    let bindings: Vec<String> = g
        .bindings
        .iter()
        .map(|b| {
            format!(
                "{}={}{}",
                e(&b.env_name),
                e(&b.slug),
                if b.live { " (live)" } else { "" }
            )
        })
        .collect();
    println!("  bindings: {}", bindings.join(", "));
    println!("  uses: {uses}");
}

/// A duration in words.
fn words(secs: u64) -> String {
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

fn revoke(id: Option<GrantId>) -> Result<ExitCode, Failure> {
    let text = id.map(|id| id.to_string());
    let revoked = connect()?.grants_revoke(text.as_deref())?;
    match revoked.revoked {
        0 => println!("No grant was revoked."),
        1 => println!("Revoked 1 grant."),
        n => println!("Revoked {n} grants."),
    }
    Ok(ExitCode::SUCCESS)
}
