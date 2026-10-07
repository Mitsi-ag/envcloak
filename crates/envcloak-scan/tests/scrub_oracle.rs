//! Cycle570 independent fragment-emitter oracle. This adapter sees only
//! normalized public inputs; Python alone retains the expected previews.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::candidates::{Candidate, Encoding, Form, Occurrence, Source};
use envcloak_scan::scrub::{FilePlan, Match, plan, preview};
use envcloak_scan::{FileStamp, source::ConfigFormat};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
fn decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[allow(clippy::disallowed_methods)] // Synthetic preview goes only to the independent checker pipe.
fn adapt(file: &Value) -> Value {
    use secrecy::ExposeSecret;
    let bytes = decode(file["source_hex"].as_str().unwrap());
    let hash = hex(&SecretBytes::copy_from(&bytes).sha256());
    let stamp = FileStamp {
        dev: 1,
        ino: 2,
        size: bytes.len() as u64,
        mtime: 0,
        mtime_nsec: 0,
        ctime: 0,
        ctime_nsec: 0,
        mode: 0o600,
        nlink: 1,
        uid: 1,
    };
    let mut candidates = Vec::new();
    let mut matches = Vec::new();
    let mut unconfirmed = false;
    for (i, o) in file["observations"].as_array().unwrap().iter().enumerate() {
        if o["confirmed"] == false {
            unconfirmed = true;
            continue;
        }
        candidates.push(Candidate {
            id: i as u64,
            value: SecretBytes::copy_from(&[]),
            form: Form::Raw,
            occurrence: Occurrence {
                source: Source {
                    path: "/fixture/events".into(),
                    object: None,
                },
                range: o["start"].as_u64().unwrap_or(u64::MAX)
                    ..o["end"].as_u64().unwrap_or(u64::MAX),
                stamp: if o["source_sha256"] == hash {
                    Some(stamp)
                } else {
                    None
                },
                rewritable: o["rewritable"] == true,
                encoding: if o["mapping"] == "json" {
                    Encoding::Json
                } else {
                    Encoding::Raw
                },
            },
        });
        matches.push(Match {
            candidate: i as u64,
            item: o["item"].as_str().unwrap().into(),
            slug: o["item"].as_str().unwrap().into(),
        });
    }
    let refs: Vec<_> = candidates.iter().collect();
    let mut p = plan(&refs, &matches);
    let mut f = if p.files.is_empty() {
        FilePlan {
            path: "/fixture/events".into(),
            stamp: Some(stamp),
            edits: vec![],
            reasons: vec![],
        }
    } else {
        p.files.remove(0)
    };
    // The wire supplies these scanner-provenance facts. Production uses range
    // mode exclusively and refuses incomplete files before apply as well.
    if file["count_only"] == true {
        f.refuse("count_only");
    }
    if file["complete"] == false {
        f.refuse("incomplete");
    }
    let format = if file["jsonl"] == true {
        ConfigFormat::Jsonl
    } else {
        ConfigFormat::Raw
    };
    let got = if f.reasons.is_empty() {
        preview(&f, &bytes, format)
    } else {
        Err("refused")
    };
    let (status,body,edits)=match got {
        Ok(body) => (if unconfirmed {"partial"} else {"ready"}, hex(body.expose_secret()),
            f.edits.iter().map(|e| json!({"start":e.range.start,"end":e.range.end,"item":e.item,"marker":e.marker(),
                "mapping":if e.encoding==Encoding::Json {"json"} else {"raw"}})).collect::<Vec<_>>()),
        Err(reason) => {if f.reasons.is_empty() {f.refuse(reason);} ("refused",hex(&bytes),vec![])},
    };
    if status != "refused" && unconfirmed {
        f.reasons.push("unconfirmed");
    }
    json!({"id":file["id"],"status":status,"reasons":f.reasons,"edits":edits,"preview_hex":body})
}
#[test]
fn gate37_independent_fragment_oracle_forward_and_reverse() {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/scrub_plan.py");
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "-c",
            r#"
import copy, json, runpy, sys
oracle=runpy.run_path(sys.argv[1])
cases=oracle['make_cases']()
for reverse in (False,True):
    inputs=copy.deepcopy([c['request'] for c in cases])
    if reverse:
        inputs.reverse()
        for c in inputs:
            c['files'].reverse()
            for f in c['files']: f['observations'].reverse()
    print(json.dumps(inputs),flush=True)
    answer=json.loads(sys.stdin.readline())
    result=oracle['assess_set'](cases,answer)
    if result!='ok':
        print('oracle_failed:'+result,file=sys.stderr)
        sys.exit(1)
"#,
        ])
        .arg(script)
        .env_clear()
        .env("HOME", d.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    for _ in 0..2 {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "independent checker stopped");
        let cases: Vec<Value> = serde_json::from_str(&line).unwrap();
        assert_eq!(cases.len(), 15);
        let answers: Vec<_> = cases
            .iter()
            .map(|c| {
                let files: Vec<_> = c["files"].as_array().unwrap().iter().map(adapt).collect();
                let status = if files.iter().all(|f| f["status"] == "ready") {
                    "ready"
                } else if files.iter().all(|f| f["status"] == "refused") {
                    "refused"
                } else {
                    "partial"
                };
                json!({"id":c["id"],"status":status,"files":files})
            })
            .collect();
        writeln!(
            child.stdin.as_mut().unwrap(),
            "{}",
            serde_json::to_string(&answers).unwrap()
        )
        .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "independent checker rejected product preview"
    );
    assert!(
        out.stderr.is_empty(),
        "independent checker emitted diagnostics"
    );
}
