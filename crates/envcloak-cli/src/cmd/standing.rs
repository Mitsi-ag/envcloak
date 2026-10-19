//! `envcloak standing ls [--json]`, `envcloak standing rm <ID> | --agent
//! <AGENT> | --project <DIR> | --all [--json]` and `envcloak standing
//! confirm [--passphrase-fd N] [--json]` (SPEC §10b "Standing approvals";
//! M2 plan D-10).
//!
//! - `ls` (`list`) prints the standing approvals in the vault, metadata
//!   only, and warns when standing approvals are paused
//!   (`policy_epoch_unverified`).
//! - `rm` (`revoke`) removes one standing approval by id, by agent, by
//!   project directory, or all of them, bumps the runtime policy epoch
//!   (ending derived session grants) and raises `<data>/policy-epoch`.
//!   Tightening needs no proof. Its output states that restoring older
//!   copies of both the whole vault and `<data>/policy-epoch` brings a
//!   removed record back for the rest of its 30 days, and that a program
//!   running as the user can do so (SPEC §10b).
//! - `confirm` re-seals the policy record over every standing approval in
//!   the vault and updates `<data>/policy-epoch`, with the vault
//!   passphrase as a proof from a terminal subject over a statement
//!   listing every record.

use std::fmt::Write as _;
use std::process::ExitCode;

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use envcloak_client::render::{json_text, print_json};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_ipc::ClientError;
use envcloak_ipc::proto::{ErrorKind, StandingRevokeParams};
use envcloak_ipc::view::{StandingListView, StandingRevokedView, StandingView};
use envcloak_policy::{
    StandingId, confirm_statement_digest, escape_for_display, render_confirm_statement,
};

use super::{fd_number, refuse_value_like};

const USAGE_TEXT: &str = "envcloak standing ls [--json]\n       \
    envcloak standing rm <ID> | --agent <AGENT> | --project <DIR> | --all [--json]\n       \
    envcloak standing confirm [--passphrase-fd N] [--json]";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    List {
        json: bool,
    },
    Revoke {
        params: StandingRevokeParams,
        json: bool,
    },
    Confirm {
        passphrase_fd: Option<i32>,
        json: bool,
    },
}

fn parse(args: &[&str]) -> Result<Option<Action>, Failure> {
    let Some((&sub, rest)) = args.split_first() else {
        return Ok(None);
    };
    match sub {
        "ls" | "list" => match rest {
            [] => Ok(Some(Action::List { json: false })),
            ["--json"] => Ok(Some(Action::List { json: true })),
            _ => Ok(None),
        },
        "rm" | "revoke" => parse_revoke(rest),
        "confirm" => parse_confirm(rest),
        _ => Ok(None),
    }
}

fn parse_revoke(args: &[&str]) -> Result<Option<Action>, Failure> {
    let mut id: Option<String> = None;
    let mut agent: Option<String> = None;
    let mut project: Option<String> = None;
    let mut all = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !json => json = true,
            "--all" if !all && id.is_none() && agent.is_none() && project.is_none() => {
                all = true;
            }
            "--id" if !all && id.is_none() && agent.is_none() && project.is_none() => {
                let Some(&val) = it.next() else {
                    return Ok(None);
                };
                let Some(parsed) = StandingId::parse(val) else {
                    return Ok(None);
                };
                id = Some(parsed.to_string());
            }
            "--agent" if !all && id.is_none() && agent.is_none() && project.is_none() => {
                let Some(&val) = it.next() else {
                    return Ok(None);
                };
                if val.is_empty() || val.starts_with('-') {
                    return Ok(None);
                }
                refuse_value_like(&[val])?;
                agent = Some(val.to_owned());
            }
            "--project" if !all && id.is_none() && agent.is_none() && project.is_none() => {
                let Some(&val) = it.next() else {
                    return Ok(None);
                };
                if val.is_empty() || val.starts_with('-') {
                    return Ok(None);
                }
                refuse_value_like(&[val])?;
                let dir = std::fs::canonicalize(val)
                    .ok()
                    .and_then(|p| p.into_os_string().into_string().ok())
                    .unwrap_or_else(|| val.to_owned());
                project = Some(dir);
            }
            _ if arg.starts_with('-') => return Ok(None),
            _ if !all && id.is_none() && agent.is_none() && project.is_none() => {
                let Some(parsed) = StandingId::parse(arg) else {
                    return Ok(None);
                };
                id = Some(parsed.to_string());
            }
            _ => return Ok(None),
        }
    }
    let selectors = usize::from(id.is_some())
        + usize::from(agent.is_some())
        + usize::from(project.is_some())
        + usize::from(all);
    if selectors != 1 {
        return Ok(None);
    }
    Ok(Some(Action::Revoke {
        params: StandingRevokeParams {
            id,
            agent,
            project,
            all,
        },
        json,
    }))
}

fn parse_confirm(args: &[&str]) -> Result<Option<Action>, Failure> {
    let mut passphrase_fd = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !json => json = true,
            "--passphrase-fd" if passphrase_fd.is_none() => {
                let Some(&val) = it.next() else {
                    return Ok(None);
                };
                let Some(fd) = fd_number(val) else {
                    return Ok(None);
                };
                passphrase_fd = Some(fd);
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(Action::Confirm {
        passphrase_fd,
        json,
    }))
}

pub fn run(args: &[&str]) -> ExitCode {
    if matches!(args, ["--help"] | ["-h"] | ["help"]) {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let action = match parse(args) {
        Ok(Some(a)) => a,
        Ok(None) => return usage(USAGE_TEXT),
        Err(f) => return f.report(USAGE),
    };
    let res = match action {
        Action::List { json } => list(json),
        Action::Revoke { params, json } => revoke(&params, json),
        Action::Confirm {
            passphrase_fd,
            json,
        } => confirm(passphrase_fd, json),
    };
    res.unwrap_or_else(|f| f.report(FAILURE))
}

fn list(json: bool) -> Result<ExitCode, Failure> {
    let v = connect()?.standing_list()?;
    print!("{}", listing(&v, json));
    Ok(ExitCode::SUCCESS)
}

fn listing(v: &StandingListView, json: bool) -> String {
    if json {
        return format!("{}\n", json_text(v));
    }
    let mut out = String::new();
    if v.policy_epoch_unverified {
        let _ = writeln!(
            out,
            "Warning: standing approvals are paused (policy_epoch_unverified: the vault's policy \
             record does not match the daemon's epoch; run `envcloak standing confirm` or \
             `envcloak standing rm --all`)."
        );
    }
    if v.standing.is_empty() {
        out.push_str("No standing approvals are in force.\n");
        return out;
    }
    for s in &v.standing {
        out.push_str(&record_text(s));
    }
    out
}

fn record_text(s: &StandingView) -> String {
    let e = escape_for_display;
    let id = StandingId::parse(&s.id).map_or_else(|| e(&s.id), |id| id.to_string());
    let mut o = format!("{id}\n");
    let _ = writeln!(
        o,
        "  for: agent {} ({}), {}",
        e(&s.agent_name),
        e(&s.agent_id),
        e(&s.identity)
    );
    let _ = writeln!(o, "  project: {}", e(&s.project_dir));
    if let (Some(l), Some(rev)) = (&s.launch, s.revision) {
        let _ = writeln!(o, "  launch: {} revision {rev}", e(l));
    }
    let bindings: Vec<String> = s.bindings.iter().map(|b| e(b)).collect();
    let _ = writeln!(o, "  bindings: {}", bindings.join(", "));
    let _ = writeln!(o, "  expires: {} left", words(s.remaining_secs));
    o
}

fn words(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        if h > 0 {
            format!("{d}d {h}h")
        } else {
            format!("{d}d")
        }
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

fn revoke(params: &StandingRevokeParams, json: bool) -> Result<ExitCode, Failure> {
    let r = connect()?.standing_revoke(params)?;
    if json {
        print_json(&r);
    } else {
        print!("{}", revoked_text(&r));
    }
    Ok(ExitCode::SUCCESS)
}

fn revoked_text(r: &StandingRevokedView) -> String {
    let mut out = String::new();
    match (r.revoked, r.grants_ended) {
        (0, _) => {
            let _ = writeln!(out, "No standing approval was revoked.");
        }
        (1, 0) => {
            let _ = writeln!(out, "Revoked 1 standing approval.");
        }
        (1, 1) => {
            let _ = writeln!(out, "Revoked 1 standing approval (1 derived grant ended).");
        }
        (1, g) => {
            let _ = writeln!(
                out,
                "Revoked 1 standing approval ({g} derived grants ended)."
            );
        }
        (n, 0) => {
            let _ = writeln!(out, "Revoked {n} standing approvals.");
        }
        (n, 1) => {
            let _ = writeln!(
                out,
                "Revoked {n} standing approvals (1 derived grant ended)."
            );
        }
        (n, g) => {
            let _ = writeln!(
                out,
                "Revoked {n} standing approvals ({g} derived grants ended)."
            );
        }
    }
    let _ = writeln!(
        out,
        "Note: the daemon's policy high-water mark in <data>/policy-epoch refuses older vault \
         copies alone, but restoring older copies of both the whole vault and <data>/policy-epoch \
         brings a removed standing approval back for the rest of its 30 days, and a program \
         running as you can do so."
    );
    out
}

fn confirm(passphrase_fd: Option<i32>, json: bool) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims = refuse_if_claimed()?;
    let list = connect()?.standing_list()?;
    let statement = render_confirm_statement(&list.standing);
    let digest = confirm_statement_digest(&list.standing);
    match connect()?.standing_confirm_check(&digest, &claims) {
        Err(ClientError::Rpc(r)) if r.kind == ErrorKind::InvalidParams => {}
        Err(e) => return Err(Failure::from(e)),
        Ok(_) => {
            return Err(Failure::new(
                "protocol_error",
                "the daemon's answer was malformed",
            ));
        }
    }
    let passphrase = match passphrase_fd {
        Some(fd) => {
            if json {
                eprint!("{statement}");
            } else {
                print!("{statement}");
            }
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open()?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to confirm standing approvals: ")?
        }
    };
    let confirmed = connect()?.standing_confirm(&digest, passphrase, &claims)?;
    if json {
        print_json(&confirmed);
    } else {
        match confirmed.records {
            0 => println!(
                "Confirmed 0 standing approvals (policy epoch generation {}).",
                confirmed.generation
            ),
            1 => println!(
                "Confirmed 1 standing approval (policy epoch generation {}).",
                confirmed.generation
            ),
            n => println!(
                "Confirmed {n} standing approvals (policy epoch generation {}).",
                confirmed.generation
            ),
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_policy::display_escaped;

    #[test]
    fn standing_subcommands_parse_and_escape() {
        assert_eq!(parse(&["ls"]).unwrap(), Some(Action::List { json: false }));
        assert_eq!(
            parse(&["list", "--json"]).unwrap(),
            Some(Action::List { json: true })
        );
        let id = "01K5TESTTESTTESTTESTTESTTE";
        assert_eq!(
            parse(&["rm", id]).unwrap(),
            Some(Action::Revoke {
                params: StandingRevokeParams {
                    id: Some(id.into()),
                    agent: None,
                    project: None,
                    all: false,
                },
                json: false,
            })
        );
        assert_eq!(
            parse(&["revoke", "--all", "--json"]).unwrap(),
            Some(Action::Revoke {
                params: StandingRevokeParams {
                    id: None,
                    agent: None,
                    project: None,
                    all: true,
                },
                json: true,
            })
        );
        assert_eq!(
            parse(&["rm", "--agent", "claude-code"]).unwrap(),
            Some(Action::Revoke {
                params: StandingRevokeParams {
                    id: None,
                    agent: Some("claude-code".into()),
                    project: None,
                    all: false,
                },
                json: false,
            })
        );
        assert_eq!(
            parse(&["confirm", "--passphrase-fd", "3", "--json"]).unwrap(),
            Some(Action::Confirm {
                passphrase_fd: Some(3),
                json: true,
            })
        );
        for bad in [
            &[][..],
            &["ls", "extra"],
            &["rm"],
            &["rm", "not-an-id"],
            &["rm", id, "--all"],
            &["rm", "--agent"],
            &["rm", "--project"],
            &["confirm", "--passphrase-fd"],
            &["confirm", "--passphrase-fd", "x"],
        ] {
            assert_eq!(parse(bad).unwrap(), None, "{bad:?}");
        }

        let dir = "/tmp/ecg/acme\u{202e}bew\u{9b}31m";
        let view = StandingListView {
            standing: vec![StandingView {
                id: id.into(),
                agent_id: "claude-code".into(),
                agent_name: "Claude\u{202e}Code".into(),
                identity: "team=TEAMID1234 id=com.anthropic.claude-code".into(),
                project_dir: dir.into(),
                launch: None,
                revision: None,
                bindings: vec!["STRIPE_SECRET_KEY=stripe/acme-test".into()],
                created_secs: 100,
                remaining_secs: 86_400 * 7,
                not_after_secs: 100 + 86_400 * 7,
            }],
            policy_epoch_unverified: true,
        };
        let json = listing(&view, true);
        assert!(!json.trim_end().chars().any(display_escaped), "{json:?}");
        let text = listing(&view, false);
        assert!(
            !text.chars().any(|c| c != '\n' && display_escaped(c)),
            "{text:?}"
        );
        assert!(text.contains("policy_epoch_unverified"), "{text}");

        let rev = revoked_text(&StandingRevokedView {
            revoked: 1,
            grants_ended: 2,
        });
        assert!(
            rev.contains("restoring older copies of both the whole vault and <data>/policy-epoch"),
            "{rev}"
        );
        assert!(rev.contains("a program running as you can do so"), "{rev}");
    }
}
