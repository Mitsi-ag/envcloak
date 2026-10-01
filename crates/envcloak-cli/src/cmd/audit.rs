//! `envcloak audit verify [--json]` (SPEC §15.2 gate 33, story S12): the
//! daemon checks the sealed audit log against the head saved in the
//! vault's header, and this prints what it found. Counts, sequence
//! numbers and fixed words only: no entry's contents cross the socket.
//!
//! - The chain checks out: exit 0, with the anchor and any unanchored tail
//!   (the entries after the anchor, whose removal from the end of the log
//!   could not be noticed).
//! - A problem (an entry changed, missing or out of place, a damaged
//!   segment, an anchor the log contradicts, or a log that no longer ends
//!   where the daemon last wrote it): the first one at its sequence
//!   number, and exit 1 with `audit_problem`.
//!
//! The vault must be unlocked: the log's keys come from the vault key.

use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, usage};
use envcloak_ipc::view::{AnchorState, AuditProblemKind, AuditVerifyView};

const USAGE: &str = "envcloak audit verify [--json]";

pub fn run(args: &[&str]) -> ExitCode {
    let json = match args {
        ["verify"] => false,
        ["verify", "--json"] => true,
        _ => return usage(USAGE),
    };
    verify(json).unwrap_or_else(|f| f.report(FAILURE))
}

fn verify(json: bool) -> Result<ExitCode, Failure> {
    let v = connect()?.audit_verify()?;
    let problem = v.first_problem.is_some() || v.live_head_matches == Some(false);
    if json {
        print!("{}", verify_json(&v));
    } else {
        print_human(&v);
    }
    if !problem {
        return Ok(ExitCode::SUCCESS);
    }
    Err(Failure::new(
        "audit_problem",
        match v.first_problem {
            Some(p) => format!(
                "the audit log was changed or damaged; the first problem is at entry {}",
                p.seq
            ),
            None => "the audit log no longer ends where the daemon last wrote it".to_owned(),
        },
    ))
}

/// What `audit verify --json` prints: JSON through the CLI's one writer
/// ([`envcloak_client::render::json_text`]), and a newline.
fn verify_json(v: &AuditVerifyView) -> String {
    format!("{}\n", envcloak_client::render::json_text(v))
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn problem_text(k: AuditProblemKind) -> &'static str {
    match k {
        AuditProblemKind::Altered => "the entry was changed (it does not open)",
        AuditProblemKind::ChainBroken => {
            "the entry does not follow the one before it (changed, replaced or from another log)"
        }
        AuditProblemKind::Missing => "the entry is missing (removed, or the log was cut there)",
        AuditProblemKind::Reordered => "the entry is out of place",
        AuditProblemKind::SegmentDamaged => {
            "a segment of the log is damaged, or belongs to another vault"
        }
        AuditProblemKind::Unreadable => "the log cannot be read as entries from here",
        AuditProblemKind::AnchorMismatch => {
            "the entry is not the one the vault's saved head names (the log was replaced)"
        }
    }
}

fn print_human(v: &AuditVerifyView) {
    println!(
        "audit log: {} in {}, through entry {}",
        plural(v.entries, "entry", "entries"),
        plural(v.segments, "segment", "segments"),
        v.last_seq
    );
    match (v.anchor.state, v.anchor.seq) {
        (AnchorState::None, _) => println!("anchor: none saved in the vault yet"),
        (AnchorState::Matched, Some(seq)) => {
            println!("anchor: entry {seq}, saved in the vault's header, matches the log");
        }
        (AnchorState::Mismatch, Some(seq)) => {
            println!("anchor: entry {seq}, saved in the vault's header, does NOT match the log");
        }
        (AnchorState::Missing, Some(seq)) => {
            println!("anchor: entry {seq}, saved in the vault's header, is NOT in the log");
        }
        _ => println!("anchor: unknown"),
    }
    match &v.first_problem {
        None => println!("check: OK, the chain holds from the first entry to the last"),
        Some(p) => {
            println!(
                "check: PROBLEM at entry {}: {}",
                p.seq,
                problem_text(p.kind)
            );
            if v.problems > 1 {
                println!("problems in all: {}", v.problems);
            }
        }
    }
    if let Some(t) = v.unanchored_tail {
        if t.first == t.last {
            println!(
                "unanchored tail: entry {} was written after the anchor; had entries been \
                 removed from the end of the log after it, that would not show",
                t.first
            );
        } else {
            println!(
                "unanchored tail: entries {} to {} were written after the anchor; had entries \
                 been removed from the end of the log after them, that would not show",
                t.first, t.last
            );
        }
    }
    if v.torn_tail && v.torn_bytes == 0 {
        println!(
            "note: the log ends in an empty segment file, as a crash while a segment is made \
             leaves it; it is removed when the log is next opened"
        );
    } else if v.torn_tail {
        println!(
            "note: the log ends in {} as a crash in the middle of a write leaves them (part of \
             one entry, or of a segment's header): no whole entry is in them and the saved head \
             does not cover them; they are removed when the log is next opened",
            plural(v.torn_bytes, "byte", "bytes")
        );
    }
    if v.live_head_matches == Some(false) {
        println!(
            "PROBLEM: the log no longer ends where the daemon last wrote it: entries were removed \
             while it ran"
        );
    }
    if v.queued > 0 || v.dropped > 0 {
        println!(
            "waiting to be written: {}; lost because the queue was full: {}",
            plural(v.queued, "event", "events"),
            v.dropped
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::view::{AnchorView, AuditProblemView, SeqRange};
    use envcloak_policy::display_escaped;

    /// Every string in `v`, at any depth.
    fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
            _ => {}
        }
    }

    /// Review T11 open 2 (verification): `audit verify --json` prints the
    /// CLI's one JSON form, and a newline. The view holds counts, sequence
    /// numbers and fixed tokens only, so a daemon (or a program answering
    /// in its place) has no free text to put on the screen: every string
    /// printed is one of the protocol's tokens, and it reads back as the
    /// view.
    #[test]
    fn audit_verify_json_is_the_terminal_safe_form_of_fixed_tokens() {
        let v = AuditVerifyView {
            segments: 2,
            entries: 17,
            last_seq: 17,
            first_problem: Some(AuditProblemView {
                seq: 9,
                kind: AuditProblemKind::ChainBroken,
            }),
            problems: 1,
            anchor: AnchorView {
                state: AnchorState::Matched,
                seq: Some(8),
            },
            unanchored_tail: Some(SeqRange { first: 9, last: 17 }),
            torn_tail: false,
            torn_bytes: 0,
            live_head_matches: Some(true),
            queued: 0,
            dropped: 0,
        };
        let text = verify_json(&v);
        assert!(text.ends_with('\n'), "{text:?}");
        assert_eq!(
            text,
            format!("{}\n", envcloak_client::render::json_text(&v))
        );
        assert!(!text.trim_end().chars().any(display_escaped), "{text:?}");
        let back: AuditVerifyView = serde_json::from_str(&text).unwrap();
        assert_eq!(back, v);
        let mut found = Vec::new();
        strings(&serde_json::from_str(&text).unwrap(), &mut found);
        found.sort();
        assert_eq!(found, ["chain_broken", "matched"]);
    }
}
