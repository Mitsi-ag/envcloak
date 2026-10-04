//! An independent oracle of what a probe counts as its control reaching
//! the model (M2 plan M2-09), adopted from a reviewer's receiver corpus
//! with its positive control: the scripted model's real server, on an
//! owned loopback port, fed by a synthetic Messages client (not a host),
//! one receiver per case, and the probe's evidence functions
//! (`probe::controls`) and the model's own outcome (`Outcome::clean`)
//! read from what it recorded. A connection, a refused token, an unknown
//! route, a malformed body or a capture past its caps is no control; a
//! candidate seen after an accepted control is a leak; only the clean
//! control passes. Every server is stopped, joined and wiped; no request
//! byte, token or marker is printed.
//!
//! A second part checks the inventory: every host's coverage holds exactly
//! one row per surface, whatever its probe results (none, stale, current
//! with surfaces missing), so a host that could not be probed is reported
//! cell by cell, never left out.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

use envcloak_agents::coverage::{
    self, ConfigSet, Observed, Outcome, ProbeRecord, Probed, Sentinel, ServerObserved, State,
    Surface,
};
use envcloak_agents::hook::Host;
use envcloak_agents::probe::controls::{forms, reached, seen};
use envcloak_agents::probe::model::{Handle, Limits, Recorded, Script, Server, Step, Token};
use serde_json::json;
use zeroize::Zeroizing;

/// One owned receiver: the server's thread, its handle and its token.
struct Owned {
    handle: Handle,
    join: Option<JoinHandle<()>>,
    key: Zeroizing<String>,
}

impl Owned {
    fn new(body: usize, records: usize) -> Owned {
        let script = Script {
            steps: vec![Step {
                say: Some("done".into()),
                shell: None,
                tool: None,
                input: None,
                namespace: None,
                after: None,
            }],
            side: None,
        };
        let limits = Limits {
            body,
            total: 65536,
            time: Duration::from_secs(6),
            idle: Duration::from_secs(2),
            connections: 4,
            records,
            meta: 16384,
        };
        let server = Server::bind(script, limits).unwrap();
        let handle = server.handle();
        let key = Zeroizing::new(server.api_key().as_str().to_owned());
        let join = Some(std::thread::spawn(move || server.serve()));
        Owned { handle, join, key }
    }

    /// One Messages request carrying `text`, with the run's token or
    /// another, to `path`, or a malformed body; the status answered.
    fn send(&self, text: &str, valid: bool, path: &str, malformed: bool) -> u16 {
        let body = if malformed {
            Zeroizing::new(b"{broken".to_vec())
        } else {
            Zeroizing::new(
                serde_json::to_vec(&json!({"model": "synthetic", "max_tokens": 32,
                    "messages": [{"role": "user", "content": text}]}))
                .unwrap(),
            )
        };
        let key = if valid {
            self.key.as_str()
        } else {
            "invalid-synthetic-key"
        };
        let head = Zeroizing::new(format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nx-api-key: {key}\r\ncontent-type: \
             application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        ));
        let mut s =
            TcpStream::connect_timeout(&self.handle.addr(), Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(&body).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut reply = Zeroizing::new(Vec::new());
        s.take(65536).read_to_end(&mut reply).unwrap();
        std::str::from_utf8(&reply)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn finish(mut self) -> (Vec<Recorded>, envcloak_agents::probe::model::Outcome) {
        self.handle.stop();
        self.join.take().unwrap().join().unwrap();
        let requests = self.handle.requests();
        let outcome = self.handle.outcome();
        self.handle.wipe();
        assert!(self.handle.requests().is_empty(), "the receiver is wiped");
        (requests, outcome)
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        self.handle.wipe();
    }
}

/// The receiver corpus: each case's capture, read as the probe reads it
/// (the control reached the model in an accepted request, the receiver
/// clean, the candidate seen nowhere), passes only for the clean control.
///
/// Mutations checked (the oracle's own fault functions, run against the
/// product's evidence): `controls::accepted` without its status check
/// (any recorded request counts): the refused-token, unknown-route and
/// malformed cases pass and this fails; `seen` reading bodies only of
/// accepted requests: the candidate after the control is missed and
/// this fails.
#[test]
fn only_the_clean_control_passes() {
    let control = Token::generate().unwrap();
    let candidate = Token::generate().unwrap();
    let candidate_forms = forms(candidate.as_str().as_bytes());
    let cases = [
        "clean_control",
        "empty_capture",
        "bad_auth",
        "wrong_route",
        "malformed_body",
        "candidate_present",
        "record_cap",
        "body_cap",
    ];
    let mut passed = Vec::new();
    for name in cases {
        let owned = Owned::new(
            if name == "body_cap" { 32 } else { 8192 },
            if name == "record_cap" { 1 } else { 16 },
        );
        if name != "empty_capture" {
            owned.send(
                control.as_str(),
                name != "bad_auth",
                if name == "wrong_route" {
                    "/unknown"
                } else {
                    "/v1/messages"
                },
                name == "malformed_body",
            );
            if name == "candidate_present" || name == "record_cap" {
                owned.send(candidate.as_str(), true, "/v1/messages", false);
            }
        }
        let (captured, summary) = owned.finish();
        let ctl = reached(&captured, control.as_str());
        let clean = summary.clean();
        let leaked = seen(&captured, &candidate_forms);
        // The probe's rule: a control that reached the model, a clean
        // run, no candidate.
        if ctl && clean && !leaked {
            passed.push(name);
        }
        match name {
            "bad_auth" => assert!(summary.bad_token > 0 && !ctl),
            "wrong_route" => assert!(summary.unknown > 0 && !ctl),
            "malformed_body" => assert!(summary.malformed > 0 && !ctl),
            "record_cap" | "body_cap" => assert!(!summary.complete()),
            "candidate_present" => assert!(leaked && ctl, "the detector's positive control"),
            "clean_control" => assert!(ctl && clean && !leaked, "the positive control"),
            _ => {}
        }
    }
    assert_eq!(passed, ["clean_control"]);
}

/// Every host's coverage has exactly one row per surface, whatever the
/// probe results it rests on: a host that could not be probed is reported
/// cell by cell, and no partial result fills the cells it lacks.
#[test]
fn every_surface_is_reported_once_whatever_was_probed() {
    let record = |surfaces: &[Surface]| ProbeRecord {
        host: "codex".to_owned(),
        exe_sha256: "e".to_owned(),
        version: "1".to_owned(),
        config_digest: "d".to_owned(),
        os: std::env::consts::OS.to_owned(),
        surfaces: surfaces
            .iter()
            .map(|s| Observed {
                surface: *s,
                outcome: Outcome::Passed,
                persisted: false,
                why: Vec::new(),
            })
            .collect(),
        server: ServerObserved {
            outcome: Outcome::Passed,
            sentinel: Sentinel::Appeared,
            control_denied: true,
        },
        flags: Vec::new(),
    };
    let partial = record(&[Surface::Shell]);
    let full = record(&Surface::ALL);
    for host in [Host::ClaudeCode, Host::Codex] {
        let cs = ConfigSet {
            host: host.id().to_owned(),
            ..ConfigSet::default()
        };
        for probed in [
            Probed::None,
            Probed::Stale,
            Probed::Current(&partial),
            Probed::Current(&full),
        ] {
            let c = coverage::assemble(host, "1", &cs, probed);
            let mut seen: Vec<Surface> = c.surfaces.iter().map(|s| s.surface).collect();
            seen.sort();
            assert_eq!(seen, Surface::ALL, "{host:?} {probed:?}");
            // A cell the record lacks is never passed.
            if let Probed::Current(r) = probed {
                for s in &c.surfaces {
                    if !r.surfaces.iter().any(|o| o.surface == s.surface) {
                        assert_eq!(s.probe, Outcome::Skipped, "{s}");
                        assert_ne!(s.state, State::Active, "{s}");
                    }
                }
            }
        }
    }
}
