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
//!
//! A second independent matrix (cycle 358, adopted with its controls) does
//! the same for the fail-closed answer: two ordinary families at three
//! sizes up to the payload limit, each as a control and with an
//! unresolved read (a program the reader does not know given `.env`, given
//! `--env-file=.env`, or given a variable holding `.env`) at the start,
//! the middle and the end: 120 rows, 108 asked about on Claude Code and
//! stopped on Codex, 12 allowed, each within the deadline; benign
//! calibrations allowed, `cat .env` denied as the stronger class, a broken
//! envelope given no decision. Mutation checked: `Analyzer::result`
//! answering `None` for an unresolved read (as an allow): every
//! uncertainty row fails.

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

/// The cycle 358 uncertainty matrix (see the module documentation).
#[test]
fn unresolved_reads_are_asked_about_or_stopped_at_every_size_and_place() {
    let want = |host: Host| {
        if host == Host::ClaudeCode {
            Decision::Ask(Reason::Unresolved)
        } else {
            Decision::Deny(Reason::Unresolved)
        }
    };
    let units = ["echo ordinary; ", "cat <<'END'\nordinary\nEND\n"];
    let unresolved = [
        "opaque_reader .env; ",
        "opaque_reader --env-file=.env; ",
        "file=.env; opaque_reader \"$file\"; ",
    ];
    let (mut rows, mut controls, mut unknown) = (0, 0, 0);
    for unit in units {
        for budget in [1024, 65536, MAX_PAYLOAD - 16384] {
            let n = budget / (serde_json::to_string(unit).unwrap().len() - 2);
            for form in 0..=unresolved.len() {
                for position in 0..if form == 0 { 1 } else { 3 } {
                    let at = match position {
                        0 => 0,
                        1 => n / 2,
                        _ => n,
                    };
                    let mut s = String::new();
                    for i in 0..=n {
                        if form > 0 && i == at {
                            s.push_str(unresolved[form - 1]);
                        }
                        if i < n {
                            s.push_str(unit);
                        }
                    }
                    let class = check_script(&s);
                    assert_eq!(
                        class,
                        (form > 0).then_some(Class::Unresolved),
                        "the reader: form {form} at {position}, {budget} bytes"
                    );
                    for host in [Host::ClaudeCode, Host::Codex] {
                        let (got, took, len) = decide(host, &envelope(host, &s));
                        let expected = if form == 0 {
                            Decision::Allow
                        } else {
                            want(host)
                        };
                        assert_eq!(got, expected, "{host:?}: form {form} at {position}");
                        assert!(len <= MAX_PAYLOAD);
                        assert!(took < Duration::from_secs(2), "{host:?}: {took:?}");
                        rows += 1;
                        if form == 0 {
                            controls += 1;
                        } else {
                            unknown += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!((rows, controls, unknown), (120, 12, 108));
    for host in [Host::ClaudeCode, Host::Codex] {
        for benign in [
            "opaque_reader ordinary.txt",
            "opaque_reader --label=ordinary",
            "echo .env",
        ] {
            assert_eq!(check_script(benign), None, "{benign}");
            assert_eq!(decide(host, &envelope(host, benign)).0, Decision::Allow);
        }
        assert_eq!(check_script("cat .env"), Some(Class::EnvFile));
        assert_eq!(
            decide(host, &envelope(host, "cat .env")).0,
            Decision::Deny(Reason::EnvFile)
        );
        let mut broken = envelope(host, "opaque_reader .env");
        broken.as_object_mut().unwrap().remove("tool_name");
        assert_eq!(decide(host, &broken).0, Decision::NoDecision);
    }
}
