//! `envcloak pending [--json]` (SPEC §6.1 step 4, §10b; M2 plan D-04): the
//! requests waiting for approval that this terminal may approve, oldest
//! first, with id, age, agent label, project and the bindings' slugs (the
//! first 32, and how many more), so a person can find a request whose id
//! went to an agent host's log. `envcloak approve` shows every binding.
//!
//! The daemon lists them only to a caller whose proof it would accept (a
//! terminal session with no agent in it), and leaves out a request whose
//! requester shares this caller's session or terminal: an approval surface
//! does not show a request to a caller whose proof it would refuse. Anyone
//! else gets an empty list, without being told why, and so the same line
//! as when nothing waits. The CLI sends the names of the agent markers in
//! its environment, which only tighten.
//!
//! Every string the daemon sends (an agent's name, a path, a slug) is
//! escaped before it is printed ([`escape_for_display`]); `--json` prints
//! the answer through the CLI's one JSON writer ([`json_text`]), which
//! escapes the same characters. Nothing is read from the terminal, and
//! nothing is approved here: `envcloak approve <id>` does that.

use std::process::ExitCode;
use std::time::Duration;

use envcloak_client::claims::claims;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, usage};
use envcloak_client::render::json_text;
use envcloak_ipc::view::{PendingListView, PendingView};
use envcloak_policy::{PendingId, SubjectKind, escape_for_display};

const USAGE: &str = "envcloak pending [--json]";

pub fn run(args: &[&str]) -> ExitCode {
    let json = match args {
        [] => false,
        ["--json"] => true,
        ["--help"] | ["-h"] => {
            println!("usage: {USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return usage(USAGE),
    };
    list(json).unwrap_or_else(|f| f.report(FAILURE))
}

fn list(json: bool) -> Result<ExitCode, Failure> {
    let requests = connect()?.pending_list(&claims())?;
    print!("{}", listing(&requests, json));
    Ok(ExitCode::SUCCESS)
}

/// What `pending` prints for `list`: JSON through the CLI's one writer,
/// or text with every string escaped.
fn listing(list: &PendingListView, json: bool) -> String {
    if json {
        return format!("{}\n", json_text(list));
    }
    if list.requests.is_empty() {
        return "No requests are waiting for approval that this terminal may approve.\n".to_owned();
    }
    let mut o: String = list.requests.iter().map(request_text).collect();
    o.push_str(
        "Approve one with `envcloak approve <REQUEST>`, after reading its statement; deny one \
         with `envcloak deny <REQUEST>`.\n",
    );
    o
}

fn request_text(r: &PendingView) -> String {
    let e = escape_for_display;
    let id = PendingId::parse(&r.request).map_or_else(|| e(&r.request), |id| id.to_string());
    let who = match (r.kind, &r.agent) {
        (SubjectKind::Agent, Some(l)) => format!("agent {}", e(l)),
        (SubjectKind::Agent, None) => "an agent".to_owned(),
        (SubjectKind::Terminal, _) => "a terminal session".to_owned(),
        (SubjectKind::Unknown, _) => "a process of unknown origin".to_owned(),
    };
    let bindings: Vec<String> = r.bindings.iter().map(|b| e(b)).collect();
    let mut shown = if bindings.is_empty() {
        "none".to_owned()
    } else {
        bindings.join(", ")
    };
    if r.more_bindings > 0 {
        shown.push_str(&format!(", and {} more", r.more_bindings));
    }
    format!(
        "{id}\n  from: {who}\n  project: {}\n  bindings: {shown}\n  waiting: {} (expires in {})\n",
        e(&r.project),
        words(r.age_secs),
        words(r.expires_in_secs),
    )
}

/// A duration in words.
fn words(secs: u64) -> String {
    let d = Duration::from_secs(secs);
    let (m, s) = (d.as_secs() / 60, d.as_secs() % 60);
    match (m, s) {
        (0, s) => format!("{s}s"),
        (m, 0) => format!("{m}m"),
        (m, s) => format!("{m}m {s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(agent: Option<&str>, project: &str) -> PendingView {
        PendingView {
            request: "ABCDEFGH".to_owned(),
            age_secs: 65,
            expires_in_secs: 535,
            kind: if agent.is_some() {
                SubjectKind::Agent
            } else {
                SubjectKind::Unknown
            },
            agent: agent.map(str::to_owned),
            project: project.to_owned(),
            bindings: vec!["openai/acme-web".to_owned(), "stripe/acme-web".to_owned()],
            more_bindings: 0,
        }
    }

    /// The listing names each request, who asked, the project and the
    /// bindings, escaped; the empty one says the same whatever the reason.
    #[test]
    fn a_listing_is_escaped_and_the_empty_one_says_nothing_of_why() {
        let list = PendingListView {
            requests: vec![
                view(Some("Claude\u{202e}Code"), "/src/acme\n-web"),
                view(None, "/src/other"),
            ],
        };
        let text = listing(&list, false);
        assert!(
            text.starts_with("ABCDEFGH\n  from: agent Claude\\u{202e}Code\n"),
            "{text}"
        );
        assert!(text.contains("  project: /src/acme\\n-web\n"), "{text}");
        assert!(
            text.contains("  bindings: openai/acme-web, stripe/acme-web\n"),
            "{text}"
        );
        assert!(
            text.contains("  waiting: 1m 5s (expires in 8m 55s)\n"),
            "{text}"
        );
        assert!(text.contains("from: a process of unknown origin"), "{text}");
        // Bindings past the ones listed are counted.
        let mut long = view(None, "/src/other");
        long.more_bindings = 1468;
        let text = listing(
            &PendingListView {
                requests: vec![long],
            },
            false,
        );
        assert!(
            text.contains("  bindings: openai/acme-web, stripe/acme-web, and 1468 more\n"),
            "{text}"
        );
        assert!(!text.contains('\u{202e}'), "{text:?}");
        let empty = PendingListView {
            requests: Vec::new(),
        };
        assert_eq!(
            listing(&empty, false),
            "No requests are waiting for approval that this terminal may approve.\n"
        );
        assert_eq!(listing(&empty, true), "{\"requests\":[]}\n");
        let json = listing(&list, true);
        assert!(json.contains("\"request\":\"ABCDEFGH\""), "{json}");
        assert!(!json.contains('\u{202e}'), "{json:?}");
    }
}
