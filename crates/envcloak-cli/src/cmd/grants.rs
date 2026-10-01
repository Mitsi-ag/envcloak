//! `envcloak grants list [--json]` and `envcloak grants revoke <GRANT> |
//! --all` (SPEC §10b "A grant ends on"): the grants in force, metadata
//! only, and revocation, which any client may do because tightening needs
//! no proof.
//!
//! Every string the daemon sends (an agent's name, a path, a slug) is
//! escaped before it is printed ([`escape_for_display`]): a program
//! running as the user could answer in the daemon's place, and an agent
//! names the directories a grant's project is in. The `--json` form
//! prints the daemon's answer through the CLI's one JSON writer
//! ([`envcloak_client::render::json_text`]), which escapes the same characters.

use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, usage};
use envcloak_client::render::json_text;
use envcloak_ipc::view::{GrantView, GrantsView};
use envcloak_policy::{GrantId, SubjectKind, Uses, escape_for_display};

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
    print!("{}", listing(&grants, json));
    Ok(ExitCode::SUCCESS)
}

/// What `grants list` prints for `grants`: JSON through the CLI's one
/// writer ([`json_text`]), or text with every string escaped.
fn listing(grants: &GrantsView, json: bool) -> String {
    if json {
        return format!("{}\n", json_text(grants));
    }
    if grants.grants.is_empty() {
        return "No grants are in force.\n".to_owned();
    }
    grants.grants.iter().map(grant_text).collect()
}

fn grant_text(g: &GrantView) -> String {
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
    let mut o = format!("{id}\n");
    o.push_str(&format!(
        "  for: {who}, rooted at pid {}{}\n",
        g.root_pid,
        g.root_exe
            .as_deref()
            .map(|x| format!(" ({})", e(x)))
            .unwrap_or_default()
    ));
    o.push_str(&format!("  project: {}\n", e(&g.project_dir)));
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
    o.push_str(&format!("  bindings: {}\n", bindings.join(", ")));
    o.push_str(&format!("  uses: {uses}\n"));
    o
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

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::view::GrantBindingView;
    use envcloak_policy::{Mode, display_escaped};

    /// Review T11 open 2 (and T9 open 7): an agent names the directory a
    /// grant's project is in, and JSON's own encoding leaves a C1 control
    /// (U+009B, CSI) or a bidirectional override (U+202E) as it is. Both
    /// forms of `grants list` escape them, the JSON as `\uXXXX`, and the
    /// JSON reads back unchanged.
    #[test]
    fn grants_list_escapes_what_a_terminal_would_act_on() {
        let dir = "/tmp/ecg/acme\u{202e}bew\u{9b}31m";
        let grants = GrantsView {
            grants: vec![GrantView {
                id: "01K5TESTTESTTESTTESTTESTTE".into(),
                kind: SubjectKind::Agent,
                label: Some("Claude\u{202e}Code".into()),
                root_pid: 4242,
                root_exe: Some("/opt/agent\u{9b}31m/bin".into()),
                project_dir: dir.into(),
                bindings: vec![GrantBindingView {
                    env_name: "OPENAI_API_KEY".into(),
                    slug: "openai/acme-web".into(),
                    live: false,
                }],
                mode: Mode::Inject,
                uses: Uses::Session,
                created_secs: 0,
                remaining_secs: 3600,
            }],
        };
        let json = listing(&grants, true);
        assert!(!json.trim_end().chars().any(display_escaped), "{json:?}");
        assert!(
            json.contains(r#""project_dir":"/tmp/ecg/acme\u202ebew\u009b31m""#),
            "{json}"
        );
        let back: GrantsView = serde_json::from_str(&json).unwrap();
        assert_eq!(back.grants[0].project_dir, dir);
        let text = listing(&grants, false);
        assert!(
            !text.chars().any(|c| c != '\n' && display_escaped(c)),
            "{text:?}"
        );
        assert!(
            text.contains("  project: /tmp/ecg/acme\\u{202e}bew\\u{9b}31m\n"),
            "{text}"
        );
    }
}
