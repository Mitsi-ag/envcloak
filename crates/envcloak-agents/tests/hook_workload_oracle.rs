//! The hook's decision on large ordinary payloads, with a denial at the
//! start, in the middle or at the end, within the hook's 2 seconds (M2
//! plan M2-08: a 2 MiB payload is decided within the deadline; the CI
//! failure of 8510515, where 131,000 here-documents took 2.14 s).
//!
//! An independent workload matrix (Codex's cycles 351 and 352, adopted
//! with their envelopes): four ordinary families (a command, a reader of
//! an ordinary file, a here-document, a here-document then a command) at
//! four serialized sizes up to the payload limit, each as an ordinary
//! control and with `printenv` at the beginning, the middle and the end,
//! for both hosts. Each row checks the reader's class, the hook's
//! decision, and the time `hook::decide` took. The Codex envelope carries
//! the fields Codex's parser requires (`model`, `turn_id`), and shape
//! controls show that an envelope missing one gets no decision while the
//! full one is decided, so a throughput row can never pass as a payload
//! the parser refused (cycle 351's first matrix did, with an envelope
//! Codex's parser does not take).
//!
//! Mutation checked: the reader skipping the commands after the first
//! hundred (a `classify_all` that stops early): the end positions are
//! allowed and this fails. The previous `self.bodies.iter().filter(...)`
//! per command: the here-document rows take past 2 seconds and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use envcloak_agents::hook::shell::{Class, check_script};
use envcloak_agents::hook::{self, Decision, Event, Host, MAX_PAYLOAD, Reason};
use envcloak_core::SecretBuf;
use serde_json::{Value, json};

fn envelope(host: Host, command: &str) -> Value {
    let mut v = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "fixture",
        "cwd": "/fixture",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    if host == Host::Codex {
        v["model"] = json!("synthetic-model");
        v["turn_id"] = json!("synthetic-turn");
    }
    v
}

fn decide(host: Host, v: &Value) -> (Decision, Duration, usize) {
    let bytes = serde_json::to_vec(v).unwrap();
    let mut buf = SecretBuf::with_capacity(bytes.len());
    buf.extend(&bytes).unwrap();
    let t = Instant::now();
    let d = hook::decide(host, Event::PreToolUse, &buf);
    (d, t.elapsed(), bytes.len())
}

#[test]
fn a_codex_envelope_missing_a_field_gets_no_decision() {
    let base = envelope(Host::Codex, "printenv");
    for key in ["model", "turn_id", "tool_name", "tool_input"] {
        for remove in [true, false] {
            let mut v = base.clone();
            if remove {
                v.as_object_mut().unwrap().remove(key);
            } else {
                v[key] = Value::Null;
            }
            assert_eq!(
                decide(Host::Codex, &v).0,
                Decision::NoDecision,
                "{key} {remove}"
            );
        }
    }
    // Positive controls: the full envelope is decided both ways.
    assert_eq!(
        decide(Host::Codex, &base).0,
        Decision::Deny(Reason::EnvDump)
    );
    assert_eq!(
        decide(Host::Codex, &envelope(Host::Codex, "true")).0,
        Decision::Allow
    );
}

#[test]
fn large_ordinary_payloads_are_decided_within_the_deadline_wherever_the_denial_is() {
    let units = [
        "true\n",
        "cat ordinary\n",
        "cat <<'END'\nordinary\nEND\n",
        "cat <<'END'\nordinary\nEND\ntrue\n",
    ];
    let mut slowest = Duration::ZERO;
    let mut rows = 0;
    for unit in units {
        for budget in [1024, 16384, 262_144, MAX_PAYLOAD - 16384] {
            // A unit's length as JSON, its line breaks escaped.
            let encoded = serde_json::to_string(unit).unwrap().len() - 2;
            let n = budget / encoded;
            for position in 0..4 {
                let place = match position {
                    1 => 0,
                    2 => n / 2,
                    3 => n,
                    _ => usize::MAX,
                };
                let mut script = String::with_capacity(budget + 32);
                for i in 0..=n {
                    if i == place {
                        script.push_str("printenv\n");
                    }
                    if i < n {
                        script.push_str(unit);
                    }
                }
                let (class, want) = if position == 0 {
                    (None, Decision::Allow)
                } else {
                    (Some(Class::EnvDump), Decision::Deny(Reason::EnvDump))
                };
                assert_eq!(check_script(&script), class, "{unit:?} {budget} {position}");
                for host in [Host::ClaudeCode, Host::Codex] {
                    let (got, took, len) = decide(host, &envelope(host, &script));
                    assert!(len <= MAX_PAYLOAD, "{len}");
                    assert_eq!(got, want, "{host:?} {unit:?} {budget} {position}");
                    assert!(
                        took < Duration::from_secs(2),
                        "{host:?} {unit:?} {budget} {position}: {took:?}"
                    );
                    slowest = slowest.max(took);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 128);
    eprintln!("measurement: 128 rows, slowest decision {slowest:?}");
}
