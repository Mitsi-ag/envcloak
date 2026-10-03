//! The host-store sweep (M2 plan task M2-04, D-15, SI-18): every canary
//! planted in every store, in every encoding the sweep lists, is found
//! there, each case on its own (its file, its offset, its encoding);
//! nothing found is ever dropped; a home without canaries is clean; the
//! scripted model's request bodies are swept too.
//!
//! The stores each host must have are listed here again, by hand, from
//! D-15 and what M2-04 saw the pinned hosts write: an independent list,
//! so a store dropped from `transcript_roots` fails its control below.
//!
//! The planted bytes are made here, independently of the sweep's own
//! encoders (L-02): base64 in every alphabet and padding, and embedded in a
//! longer stream, by the `base64` crate; hex with `format!`; the Python
//! `urllib.parse` quoting styles (and `encodeURIComponent`'s set) by
//! `python3` itself; WHATWG form encoding by the `form_urlencoded` crate;
//! JSON by `serde_json` and Python's `json.dumps`, and the escaping styles
//! no tool here writes (Go's, .NET's, PHP's and their combinations) by an
//! escaper written below from the styles' definitions, which those two
//! anchor: the weaker oracle, labelled so. The list of encoding names is
//! written out here too, so an encoding dropped from the sweep fails.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use envcloak_testkit::agents::{Host, Model, ModelReport, ModelRequest};
use envcloak_testkit::transcripts::{
    Hits, HostDirs, OTHER, claude_tmp_dir, host_roots, is_claude_cwd_file, sweep_model,
    sweep_stores, transcript_roots,
};
use envcloak_testkit::{Canary, Hit, TestHome, by_label, canaries, fresh_seed, labels};
use zeroize::Zeroizing;

/// `(store name, file to plant, relative to HOME)`: one file per store.
const CLAUDE: &[(&str, &str)] = &[
    ("claude/projects", ".claude/projects/-tmp-acme/4f0c.jsonl"),
    (
        "claude/projects",
        ".claude/projects/-tmp-acme/4f0c/tool-results/a.txt",
    ),
    (
        "claude/projects",
        ".claude/projects/-tmp-acme/4f0c/subagents/agent-1.jsonl",
    ),
    ("claude/history.jsonl", ".claude/history.jsonl"),
    ("claude/paste-cache", ".claude/paste-cache/9a.txt"),
    ("claude/file-history", ".claude/file-history/4f0c/env@v1"),
    ("claude/backups", ".claude/backups/.claude.json.backup.1"),
    ("claude/sessions", ".claude/sessions/77.json"),
    ("claude/session-env", ".claude/session-env/4f0c/hook-1.sh"),
    (
        "claude/shell-snapshots",
        ".claude/shell-snapshots/snapshot-zsh-1.sh",
    ),
    (
        "claude/telemetry",
        ".claude/telemetry/1p_failed_events.4f0c.json",
    ),
    ("claude/todos", ".claude/todos/4f0c-agent.json"),
    ("claude/debug", ".claude/debug/4f0c.txt"),
    ("claude.json", ".claude.json"),
    ("claude.json backups", ".claude.json.backup.1790853962065"),
];

/// The same for Claude Code's per-user temporary directory
/// (`claude-<uid>` in `CLAUDE_CODE_TMPDIR`, or `/tmp`): a running Bash
/// command's output so far, and an empty task directory.
const CLAUDE_TMP: &[(&str, &str)] = &[
    (
        "claude/tmp",
        "-private-tmp-acme/4f0c-77/tasks/bul83y2dp.output",
    ),
    ("claude/tmp", "-tmp-acme/9a/tasks/b2.output"),
];

/// The same for the working-directory file Claude Code's Bash tool has
/// a command's shell write directly in `CLAUDE_CODE_TMPDIR` (or `/tmp`).
const CLAUDE_CWD: &[(&str, &str)] = &[("claude/cwd", "claude-f2cb-cwd")];

/// The same for Codex, relative to `$CODEX_HOME` (`~/.codex`).
const CODEX: &[(&str, &str)] = &[
    (
        "codex/sessions",
        "sessions/2026/10/01/rollout-2026-10-01T21-26-47-01a0.jsonl",
    ),
    (
        "codex/archived_sessions",
        "archived_sessions/rollout-1.jsonl",
    ),
    ("codex/history.jsonl", "history.jsonl"),
    ("codex/log", "log/codex-tui.log"),
    ("codex/sqlite", "thread_history_1.sqlite-wal"),
    ("codex/sqlite", "state_5.sqlite"),
    ("codex/shell_snapshots", "shell_snapshots/1.sh"),
    ("codex/memories", "memories/1.md"),
];

/// How a `\u` escape spells its hex digits, or no escape.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Esc {
    Raw,
    Lower,
    Upper,
}

impl Esc {
    fn name(self) -> &'static str {
        match self {
            Esc::Raw => "raw",
            Esc::Lower => "lower",
            Esc::Upper => "upper",
        }
    }

    fn unit(self, unit: u16) -> String {
        match self {
            Esc::Upper => format!("\\u{unit:04X}"),
            _ => format!("\\u{unit:04x}"),
        }
    }
}

/// One JSON string-escaping style, as the sweep's list names them.
#[derive(Clone, Copy)]
struct JsonStyle {
    quote_u: bool,
    slash: bool,
    non_ascii: Esc,
    html: Esc,
    extra: Esc,
}

impl JsonStyle {
    fn name(&self) -> String {
        format!(
            "json/quote-{}/slash-{}/non-ascii-{}/html-{}/extra-{}",
            if self.quote_u { "u" } else { "esc" },
            if self.slash { "esc" } else { "raw" },
            self.non_ascii.name(),
            self.html.name(),
            self.extra.name()
        )
    }

    /// Every style, in the sweep's order.
    fn all() -> Vec<JsonStyle> {
        let escs = [Esc::Raw, Esc::Lower, Esc::Upper];
        let mut out = Vec::new();
        for quote_u in [false, true] {
            for slash in [false, true] {
                for non_ascii in escs {
                    for html in escs {
                        for extra in escs {
                            out.push(JsonStyle {
                                quote_u,
                                slash,
                                non_ascii,
                                html,
                                extra,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    /// The body of the JSON string literal for `text` in this style:
    /// each character on its own, from the style's definition.
    fn escape(&self, text: &str) -> String {
        let mut out = String::new();
        for ch in text.chars() {
            let code = u32::from(ch);
            let piece = match ch {
                '"' if self.quote_u => "\\u0022".to_owned(),
                '"' => "\\\"".to_owned(),
                '\\' => "\\\\".to_owned(),
                '/' if self.slash => "\\/".to_owned(),
                '\n' => "\\n".to_owned(),
                '\r' => "\\r".to_owned(),
                '\t' => "\\t".to_owned(),
                '\u{8}' => "\\b".to_owned(),
                '\u{c}' => "\\f".to_owned(),
                _ if code < 0x20 => format!("\\u{code:04x}"),
                '<' | '>' | '&' if self.html != Esc::Raw => self.html.unit(code as u16),
                '\'' | '+' | '`' if self.extra != Esc::Raw => self.extra.unit(code as u16),
                _ if code > 0x7f && self.non_ascii != Esc::Raw => {
                    let mut units = [0u16; 2];
                    ch.encode_utf16(&mut units)
                        .iter()
                        .map(|u| self.non_ascii.unit(*u))
                        .collect()
                }
                _ => ch.to_string(),
            };
            out.push_str(&piece);
        }
        out
    }
}

/// What Python's own encoders make of each text: `quote` with no safe
/// characters (RFC 3986's unreserved set), `quote` with its default `/`,
/// `quote_plus`, `quote` with `encodeURIComponent`'s set, and `json.dumps`
/// with `ensure_ascii`.
fn python_encodings(texts: &[&str]) -> Vec<[String; 5]> {
    let script = "import json, sys, urllib.parse as u\n\
        out = []\n\
        for t in json.load(sys.stdin):\n\
        \x20   out.append([u.quote(t, safe=''), u.quote(t), u.quote_plus(t),\n\
        \x20               u.quote(t, safe=\"-_.!~*'()\"), json.dumps(t, ensure_ascii=True)[1:-1]])\n\
        json.dump(out, sys.stdout)\n";
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("python3 is needed for the encoding oracle: {e}"));
    let input = serde_json::to_vec(texts).unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), &input).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "python3 failed");
    serde_json::from_slice(&out.stdout).unwrap()
}

/// `%XX` escapes with lower-case hex digits.
fn lower_escapes(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let esc = rest.get(at..at + 3).unwrap_or(&rest[at..]);
        out.push_str(&esc.to_ascii_lowercase());
        rest = &rest[at + esc.len()..];
    }
    out.push_str(rest);
    out
}

/// One planted case: a canary, the encoding name the sweep must report,
/// and the bytes to plant. `embedded` bytes are a longer stream's
/// encoding, inside which the canary's encoding is to be found.
struct Case {
    label: String,
    name: String,
    bytes: Vec<u8>,
    embedded: bool,
}

/// Every case for `cs`: each canary in each encoding, with the name the
/// sweep gives an encoding whose bytes equal an earlier one's (its list
/// keeps the first).
fn matrix(cs: &[Canary]) -> Vec<Case> {
    let texts: Vec<&str> = cs.iter().map(Canary::as_str).collect();
    let python = python_encodings(&texts);
    let mut cases = Vec::new();
    for (c, py) in cs.iter().zip(&python) {
        let v = c.value();
        let text = c.as_str();
        // (name, bytes the sweep looks for, bytes to plant, embedded)
        let mut list: Vec<(String, Vec<u8>, Vec<u8>, bool)> = Vec::new();
        let mut plain = |name: &str, bytes: Vec<u8>| {
            list.push((name.to_owned(), bytes.clone(), bytes, false));
        };
        plain("raw", v.to_vec());
        plain(
            "hex-lower",
            v.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into_bytes(),
        );
        plain(
            "hex-upper",
            v.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
                .into_bytes(),
        );
        plain("base64", STANDARD.encode(v).into_bytes());
        plain("base64-nopad", STANDARD_NO_PAD.encode(v).into_bytes());
        plain("base64url", URL_SAFE.encode(v).into_bytes());
        plain("base64url-nopad", URL_SAFE_NO_PAD.encode(v).into_bytes());
        // The canary at each offset (mod 3) of a longer stream, the whole
        // stream encoded: what the sweep looks for is the run of whole
        // 3-byte groups that are the canary's alone.
        for (url, engine, prefix) in [
            (false, &STANDARD, "base64-at-"),
            (true, &URL_SAFE, "base64url-at-"),
        ] {
            for offset in 0..3usize {
                let mut stream = vec![b'#'; offset];
                stream.extend_from_slice(v);
                stream.extend_from_slice(b"##");
                let encoded = engine.encode(&stream).into_bytes();
                let skip = (3 - offset % 3) % 3;
                let whole = (v.len() - skip) / 3 * 3;
                let frag = if url {
                    &URL_SAFE_NO_PAD
                } else {
                    &STANDARD_NO_PAD
                }
                .encode(&v[skip..skip + whole])
                .into_bytes();
                assert!(
                    encoded.windows(frag.len()).any(|w| w == frag.as_slice()),
                    "the stream's encoding holds the canary's groups"
                );
                list.push((format!("{prefix}{offset}"), frag, encoded, true));
            }
        }
        let [quote_rfc, quote, quote_plus, uri_component, json_ascii] = py;
        let form: String = form_urlencoded::byte_serialize(v).collect();
        for (name, upper) in [
            ("percent-rfc3986", quote_rfc),
            ("percent-quote", quote),
            ("percent-quote-plus", quote_plus),
            ("form-urlencoded", &form),
            ("percent-uri-component", uri_component),
        ] {
            list.push((
                format!("{name}-upper"),
                upper.clone().into_bytes(),
                upper.clone().into_bytes(),
                false,
            ));
            let lower = lower_escapes(upper).into_bytes();
            list.push((format!("{name}-lower"), lower.clone(), lower, false));
        }
        // The hand-written escaper, anchored to two real tools.
        let serde = serde_json::to_string(text).unwrap();
        let styles = JsonStyle::all();
        assert_eq!(styles[0].escape(text), serde[1..serde.len() - 1]);
        let ascii = styles
            .iter()
            .find(|s| s.name() == "json/quote-esc/slash-raw/non-ascii-lower/html-raw/extra-raw")
            .unwrap();
        assert_eq!(&ascii.escape(text), json_ascii);
        for style in &styles {
            let bytes = style.escape(text).into_bytes();
            list.push((style.name(), bytes.clone(), bytes, false));
        }
        assert_eq!(list.len(), 7 + 6 + 10 + 108);
        for (i, (name, looked_for, plant, embedded)) in list.iter().enumerate() {
            let first = list[..i]
                .iter()
                .find(|(_, b, _, _)| b == looked_for)
                .map_or(name, |(n, _, _, _)| n);
            cases.push(Case {
                label: c.label.clone(),
                name: first.clone(),
                bytes: plant.clone(),
                embedded: *embedded,
            });
        }
    }
    cases
}

/// Writes every case into `path`, each between line breaks, and returns
/// where each one starts.
fn plant(path: &Path, cases: &[Case]) -> Vec<usize> {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut body = b"{\"type\":\"user\"}\n".to_vec();
    let mut starts = Vec::new();
    for case in cases {
        body.extend_from_slice(b"\n");
        starts.push(body.len());
        body.extend_from_slice(&case.bytes);
        body.extend_from_slice(b"\n");
    }
    std::fs::write(path, body).unwrap();
    starts
}

/// Where the stores are in `home`: as an agent home lays them out, with
/// Claude Code's temporary directory in the home's `tmp/`.
fn dirs(home: &TestHome) -> HostDirs {
    HostDirs {
        home: home.home(),
        codex_home: home.home().join(".codex"),
        claude_tmp: home.root().join("tmp"),
    }
}

fn sweep(host: Host, home: &TestHome, cs: &[Canary]) -> Hits {
    let d = dirs(home);
    Hits {
        stores: sweep_stores(&host_roots(host, &d), &transcript_roots(host, &d), cs),
        model: Vec::new(),
    }
}

/// The URL canary: it has `/`, `"`, `+`, a space and a non-ASCII
/// character, so its encodings differ from its raw bytes.
fn url_canary(cs: &[Canary]) -> Canary {
    by_label(cs, labels::DATABASE_URL).clone()
}

/// Plants every case in every store's file and checks each one on its
/// own: a hit filed under that store, in that file, for that canary, with
/// that encoding, where it was planted.
fn every_store(host: Host, list: &[(&str, &str)], base: impl Fn(&TestHome) -> PathBuf) {
    let cs = canaries(fresh_seed());
    let cases = matrix(&cs);
    let home = TestHome::new();
    let planted: Vec<(&str, PathBuf, Vec<usize>)> = list
        .iter()
        .map(|(store, rel)| {
            let path = base(&home).join(rel);
            let starts = plant(&path, &cases);
            (*store, path, starts)
        })
        .collect();
    let hits = sweep(host, &home, &cs);
    let mut missing = Vec::new();
    for (store, path, starts) in &planted {
        let filed: Vec<&Hit> = hits
            .stores
            .iter()
            .filter(|s| s.store == *store)
            .flat_map(|s| &s.hits)
            .collect();
        for (case, &start) in cases.iter().zip(starts) {
            let end = start + case.bytes.len();
            let found = filed.iter().any(|h| match h {
                Hit::Canary { path: p, found } => {
                    p.raw() == path.as_path()
                        && found.label == case.label
                        && found.encoding == case.name
                        && if case.embedded {
                            (start..end).contains(&found.offset)
                        } else {
                            found.offset == start
                        }
                }
                _ => false,
            });
            if !found {
                missing.push(format!("{store}: {} as {}", case.label, case.name));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} cases not found, first: {:?}",
        missing.len(),
        planted.len() * cases.len(),
        &missing[..missing.len().min(10)]
    );
    for c in &cs {
        assert_eq!(hits.in_store(OTHER, &c.label), 0, "{hits}");
    }
}

#[test]
fn every_canary_planted_in_every_claude_store_is_found_there_in_every_encoding() {
    every_store(Host::ClaudeCode, CLAUDE, TestHome::home);
}

/// Claude Code 2.1.280 streams a Bash command's output to a file under
/// its per-user temporary directory while the command runs (verifier,
/// medium: outside HOME, and in no store list): its control.
#[test]
fn every_canary_planted_in_claude_code_s_temporary_store_is_found_there_in_every_encoding() {
    every_store(Host::ClaudeCode, CLAUDE_TMP, |h| {
        claude_tmp_dir(&h.root().join("tmp"))
    });
}

/// Claude Code 2.1.280's Bash tool has each command's shell write its
/// working directory to `claude-<4 hex>-cwd` beside that directory
/// (verifier, low: outside HOME, and in no store list): its control. A
/// file there of any other name is not the host's.
#[test]
fn every_canary_planted_in_claude_code_s_working_directory_file_is_found_there() {
    every_store(Host::ClaudeCode, CLAUDE_CWD, |h| h.root().join("tmp"));
    for (name, is) in [
        ("claude-f2cb-cwd", true),
        ("claude-0-cwd", true),
        ("claude--cwd", false),
        ("claude-xyz-cwd", false),
        ("claude-f2cb-cwd.tmp", false),
        ("other-f2cb-cwd", false),
    ] {
        assert_eq!(is_claude_cwd_file(name), is, "{name}");
    }
}

#[test]
fn every_canary_planted_in_every_codex_store_is_found_there_in_every_encoding() {
    every_store(Host::Codex, CODEX, |h| h.home().join(".codex"));
}

#[test]
fn a_hit_outside_every_listed_store_is_kept_under_other() {
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let cases: Vec<Case> = matrix(std::slice::from_ref(&c));
    let home = TestHome::new();
    plant(&home.home().join(".claude/plans/new-store.md"), &cases);
    plant(&home.home().join(".codex/new-store/x.json"), &cases);
    // Not the host's: a project beside it in HOME, which the tests sweep
    // with the whole home instead.
    plant(&home.home().join("acme-web/.env.local"), &cases);
    let claude = sweep(Host::ClaudeCode, &home, std::slice::from_ref(&c));
    assert!(claude.in_store(OTHER, &c.label) >= cases.len(), "{claude}");
    let codex = sweep(Host::Codex, &home, std::slice::from_ref(&c));
    assert!(codex.in_store(OTHER, &c.label) >= cases.len(), "{codex}");
    assert!(home.sweep(&cs).len() >= 3 * cases.len());
}

/// `path`'s mode set to `mode` until dropped, then restored.
struct Mode {
    path: PathBuf,
    was: u32,
}

impl Mode {
    fn set(path: &Path, mode: u32) -> Mode {
        use std::os::unix::fs::PermissionsExt as _;
        let was = std::fs::metadata(path).unwrap().permissions().mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        Mode {
            path: path.to_path_buf(),
            was,
        }
    }
}

impl Drop for Mode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.was));
    }
}

/// Whether permissions can keep this process out (not for root).
fn permissions_apply() -> bool {
    if envcloak_sys::effective_uid() == 0 {
        eprintln!("skipped: permissions do not keep root out");
        return false;
    }
    true
}

/// What the sweep cannot look at is reported, never taken for absent
/// (review: `Path::exists` read an error as "not there", so an
/// inaccessible root was skipped and the sweep came back clean; review
/// F-88: Claude Code's file filter dropped an unreadable HOME, so nothing
/// was reported either). Each case has its canary found once access is
/// back, so the same tree is what was hidden.
#[test]
fn what_the_sweep_cannot_read_is_reported_not_skipped() {
    if !permissions_apply() {
        return;
    }
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let one = std::slice::from_ref(&c);
    let found = |host: Host, home: &TestHome| sweep(host, home, one);
    let plant_raw = |path: &Path| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, c.as_str()).unwrap();
    };

    // Codex: $CODEX_HOME itself, and a directory above it that cannot be
    // searched (the root then cannot even be looked at: EACCES, not
    // "not found").
    let home = TestHome::new();
    plant_raw(&home.home().join(".codex/sessions/1.jsonl"));
    for locked in [home.home().join(".codex"), home.home()] {
        let guard = Mode::set(&locked, 0o000);
        let hits = found(Host::Codex, &home);
        assert!(hits.unreadable() >= 1, "{}: {hits}", locked.display());
        drop(guard);
    }
    assert_eq!(
        found(Host::Codex, &home).in_store("codex/sessions", &c.label),
        1
    );

    // Claude Code: HOME (the root), `~/.claude`, and one store.
    let home = TestHome::new();
    plant_raw(&home.home().join(".claude/projects/-tmp/1.jsonl"));
    for locked in [
        home.home(),
        home.home().join(".claude"),
        home.home().join(".claude/projects"),
    ] {
        let guard = Mode::set(&locked, 0o000);
        let hits = found(Host::ClaudeCode, &home);
        assert!(hits.unreadable() >= 1, "{}: {hits}", locked.display());
        assert_eq!(hits.in_store("claude/projects", &c.label), 0);
        drop(guard);
    }
    let hits = found(Host::ClaudeCode, &home);
    assert_eq!(hits.in_store("claude/projects", &c.label), 1, "{hits}");
    assert_eq!(hits.unreadable(), 0, "{hits}");

    // Not the host's: an unreadable project beside it in HOME, which the
    // tests sweep with the whole home instead, is not a host store's.
    let project = home.home().join("acme-web");
    std::fs::create_dir_all(&project).unwrap();
    let guard = Mode::set(&project, 0o000);
    let hits = found(Host::ClaudeCode, &home);
    assert_eq!(hits.unreadable(), 0, "{hits}");
    drop(guard);
}

#[test]
fn the_negative_control_is_clean() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    // The same stores holding everything but a canary: other values of
    // the same shapes, from another seed, in every encoding.
    let others = matrix(&canaries(fresh_seed()));
    for (_, rel) in CLAUDE {
        plant(&home.home().join(rel), &others);
    }
    for (_, rel) in CODEX {
        plant(&home.home().join(".codex").join(rel), &others);
    }
    for (_, rel) in CLAUDE_TMP {
        plant(&claude_tmp_dir(&home.root().join("tmp")).join(rel), &others);
    }
    for (_, rel) in CLAUDE_CWD {
        plant(&home.root().join("tmp").join(rel), &others);
    }
    for host in [Host::ClaudeCode, Host::Codex] {
        let hits = sweep(host, &home, &cs);
        assert_eq!(hits.total(), 0, "{hits}");
        assert_eq!(hits.to_string(), "no hits");
    }
}

#[test]
fn the_harness_s_own_canaries_are_counted_like_any_other() {
    let cs = canaries(fresh_seed());
    let control = Canary::new("POSITIVE_CONTROL", format!("ecctl-{:016x}", fresh_seed()));
    let home = TestHome::new();
    let file = home.home().join(".claude/projects/-tmp/1.jsonl");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, format!("{{\"stdout\":\"{}\"}}\n", control.as_str())).unwrap();
    let mut all = cs.clone();
    all.push(control.clone());
    let hits = sweep(Host::ClaudeCode, &home, &all);
    assert_eq!(
        hits.in_store_as("claude/projects", "POSITIVE_CONTROL", "raw"),
        1,
        "{hits}"
    );
}

#[test]
fn the_model_s_request_bodies_are_swept() {
    let cs = canaries(fresh_seed());
    let c = url_canary(&cs);
    let body = serde_json::json!({"messages": [{"role": "user", "content": [
        {"type": "tool_result", "content": c.as_str()}]}]})
    .to_string();
    let report = ModelReport {
        requests: vec![ModelRequest {
            seq: 3,
            at_ms: 0,
            method: "POST".to_owned(),
            path: "/v1/messages".to_owned(),
            query: None,
            headers: Vec::new(),
            header_values: Vec::new(),
            forward: Zeroizing::new(Vec::new()),
            status: 200,
            answered: true,
            api: Some("messages".to_owned()),
            pick: Some("step 1".to_owned()),
            body: Zeroizing::new(body.into_bytes()),
        }],
        outcome: serde_json::json!({}),
    };
    let hits = sweep_model(&report, &cs);
    // Its JSON encoding as the body holds it, and the value itself with
    // the body's escaping read through.
    let mut at: Vec<(u64, u8, &str)> = hits
        .iter()
        .map(|h| (h.seq, h.found.unescaped, h.found.encoding))
        .collect();
    at.sort_unstable();
    assert_eq!(at.len(), 2, "{hits:?}");
    assert!(
        at[0].0 == 3 && at[0].1 == 0 && at[0].2.starts_with("json/"),
        "{hits:?}"
    );
    assert_eq!(at[1], (3, 1, "raw"), "{hits:?}");
}

/// A host, or a command through the proxy variables that point at the
/// scripted model, can put a value in a request line as well as a body:
/// the path, the query, a method of its own, a header name or value, the
/// host of a tunnel or of a request to forward, and a request to
/// forward's own path, query and body. Each is swept, as the model
/// recorded it, and filed by the part it was in (verifier, low: only
/// bodies were swept, so S0's check that nothing sent to the model holds
/// a value missed these; Codex review, medium: header values, and a
/// request to forward's path, query and body, were not recorded). A
/// control in a body is found too.
#[test]
fn the_model_s_request_lines_are_swept() {
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("curl is needed"));
    let hex = || format!("{:016x}{:016x}", fresh_seed(), fresh_seed());
    let path = Canary::new("PATH_VALUE", format!("ecpath{}", hex()));
    let query = Canary::new("QUERY_VALUE", format!("ecquery{}", hex()));
    let tunnel = Canary::new("TUNNEL_VALUE", format!("ectunnel{}", hex()));
    let forward = Canary::new("FORWARD_VALUE", format!("ecfwd{}", hex()));
    let header = Canary::new("HEADER_VALUE", format!("echdr{}", hex()));
    // A name a host sent in mixed case is recorded and swept as it came
    // (Codex review of M2-04: the record lower-cased it, and the
    // case-sensitive sweep missed it).
    let mixed = Canary::new(
        "HEADER_MIXED_VALUE",
        format!("EcHdr{}", hex().to_uppercase()),
    );
    let value = Canary::new("HEADER_FIELD_VALUE", format!("ecval{}", hex()));
    let body = Canary::new("BODY_VALUE", format!("ecbody{}", hex()));
    let fwd_path = Canary::new("FORWARD_PATH_VALUE", format!("ecfpath{}", hex()));
    let fwd_query = Canary::new("FORWARD_QUERY_VALUE", format!("ecfquery{}", hex()));
    let fwd_body = Canary::new("FORWARD_BODY_VALUE", format!("ecfbody{}", hex()));
    let fwd_header = Canary::new("FORWARD_HEADER_VALUE", format!("ecfhdr{}", hex()));
    // A method is 16 upper-case letters at most.
    let letters: String = hex()
        .bytes()
        .take(14)
        .map(|b| char::from(b'A' + (b % 26)))
        .collect();
    let method = Canary::new("METHOD_VALUE", format!("EC{letters}"));
    let model = Model::start(&serde_json::json!({"steps": [{"say": "done"}]}));
    let (base, key) = (model.base_url(), format!("x-api-key: {}", model.token()));
    let run = |args: &[&str]| {
        let out = Command::new(curl)
            .args(["-s", "-o", "/dev/null", "--max-time", "20"])
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("curl: {e}"));
        drop(out);
    };
    run(&[
        "--path-as-is",
        "-H",
        &key,
        "-H",
        &format!("x-{}: 1", header.as_str()),
        "-H",
        &format!("X-{}: 1", mixed.as_str()),
        "-H",
        &format!("x-leak: {}", value.as_str()),
        &format!("{base}/{}?{}", path.as_str(), query.as_str()),
    ]);
    run(&["-X", method.as_str(), "-H", &key, &format!("{base}/v1/x")]);
    run(&[
        "-p",
        "-x",
        &base,
        &format!("https://{}.example/", tunnel.as_str()),
    ]);
    run(&[
        "-x",
        &base,
        &format!("http://{}.example/", forward.as_str()),
    ]);
    run(&[
        "-x",
        &base,
        "-H",
        &format!("x-leak: {}", fwd_header.as_str()),
        "--data-binary",
        fwd_body.as_str(),
        &format!(
            "http://ec.example/{}?{}",
            fwd_path.as_str(),
            fwd_query.as_str()
        ),
    ]);
    run(&[
        "-H",
        &key,
        "-H",
        "content-type: application/json",
        "--data-binary",
        &format!("{{\"note\": \"{}\"}}", body.as_str()),
        &format!("{base}/v1/x"),
    ]);
    let report = model.finish();
    let cs = [
        path.clone(),
        query.clone(),
        tunnel.clone(),
        forward.clone(),
        header.clone(),
        mixed.clone(),
        value.clone(),
        body.clone(),
        method.clone(),
        fwd_path.clone(),
        fwd_query.clone(),
        fwd_body.clone(),
        fwd_header.clone(),
    ];
    let hits = sweep_model(&report, &cs);
    let parts = |c: &Canary| -> Vec<&str> {
        let mut p: Vec<&str> = hits
            .iter()
            .filter(|h| h.found.label == c.label && h.found.encoding == "raw")
            .map(|h| h.part)
            .collect();
        p.dedup();
        p
    };
    for (c, want) in [
        (&path, &["target"][..]),
        (&query, &["target"]),
        // The host a tunnel names is in its `Host` header too; the host of
        // a request to forward also in its whole target.
        (&tunnel, &["target", "header values"]),
        (&forward, &["target", "forwarded target", "header values"]),
        (&header, &["header names"]),
        (&mixed, &["header names"]),
        (&value, &["header values"]),
        (&method, &["method"]),
        (&body, &["body"]),
        (&fwd_path, &["forwarded target"]),
        (&fwd_query, &["forwarded target"]),
        (&fwd_body, &["body"]),
        (&fwd_header, &["header values"]),
    ] {
        assert_eq!(parts(c), want, "{} in {:?}", c.label, report.requests);
    }
}

/// What a host does with a line a command printed: it keeps it as a JSON
/// string, and Codex keeps a command's result as a JSON string that holds
/// JSON, so each listed encoding is escaped again on its way to a store or
/// to the model (Codex review: a JSON-encoded value escaped a second time
/// matched none of the 131 patterns). Every case of the matrix, printed
/// alone, in each envelope a pinned host writes, built by serde_json and
/// by Python's `json.dumps` (ASCII only, as Python writes JSON by
/// default), is found under its own encoding name: in the stores by the
/// sweep, in the bodies by the model sweep.
#[test]
fn every_encoding_is_found_inside_each_host_and_model_envelope() {
    let cs = canaries(fresh_seed());
    let cases = matrix(&cs);
    let printed: Vec<String> = cases
        .iter()
        .map(|c| String::from_utf8(c.bytes.clone()).unwrap())
        .collect();
    let python = python_history_lines(&printed);
    let home = TestHome::new();
    let h = home.home();
    // (envelope, the host whose stores hold it, file for case i, the
    // file's text)
    type Envelope<'a> = (
        &'a str,
        Host,
        Box<dyn Fn(usize) -> PathBuf + 'a>,
        Box<dyn Fn(usize) -> String + 'a>,
    );
    let envelopes: Vec<Envelope<'_>> = vec![
        (
            "a Claude Code tool result",
            Host::ClaudeCode,
            Box::new(|i| h.join(format!(".claude/projects/-tmp-acme/s/{i}.jsonl"))),
            Box::new(|i| {
                serde_json::json!({"type": "user", "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": printed[i]}]},
                    "toolUseResult": {"stdout": printed[i], "stderr": "", "interrupted": false}})
                .to_string()
            }),
        ),
        (
            "a Codex command result",
            Host::Codex,
            Box::new(|i| h.join(format!(".codex/sessions/2026/10/02/rollout-{i}.jsonl"))),
            Box::new(|i| {
                let output = serde_json::json!({"output": printed[i],
                    "metadata": {"exit_code": 0, "duration_seconds": 0.1}})
                .to_string();
                serde_json::json!({"type": "response_item", "payload":
                    {"type": "function_call_output", "call_id": "call_1", "output": output}})
                .to_string()
            }),
        ),
        (
            "a line Python wrote",
            Host::ClaudeCode,
            Box::new(|i| h.join(format!(".claude/paste-cache/{i}.json"))),
            Box::new(|i| python[i].clone()),
        ),
    ];
    let mut missing = Vec::new();
    for (what, host, file, text) in &envelopes {
        for i in 0..cases.len() {
            let path = file(i);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text(i)).unwrap();
        }
        let hits = sweep(*host, &home, &cs);
        for (i, case) in cases.iter().enumerate() {
            let path = file(i);
            let found = hits
                .stores
                .iter()
                .flat_map(|s| &s.hits)
                .any(|hit| match hit {
                    Hit::Canary { path: p, found } => {
                        p.raw() == path.as_path()
                            && found.label == case.label
                            && found.encoding == case.name
                    }
                    _ => false,
                });
            if !found {
                missing.push(format!("{what}: {} as {}", case.label, case.name));
            }
        }
    }
    // The bodies a host sends its model: Anthropic Messages with the
    // printed line as a tool result, OpenAI Responses with Codex's command
    // result (JSON in a JSON string).
    let bodies = |i: usize| -> [String; 2] {
        let output =
            serde_json::json!({"output": printed[i], "metadata": {"exit_code": 0}}).to_string();
        [
            serde_json::json!({"model": "m", "messages": [{"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": printed[i]}]}]})
            .to_string(),
            serde_json::json!({"model": "m", "input": [
                {"type": "function_call_output", "call_id": "call_1", "output": output}]})
            .to_string(),
        ]
    };
    for (kind, what) in ["an Anthropic Messages body", "an OpenAI Responses body"]
        .into_iter()
        .enumerate()
    {
        let report = ModelReport {
            requests: (0..cases.len())
                .map(|i| ModelRequest {
                    seq: i as u64,
                    at_ms: 0,
                    method: "POST".to_owned(),
                    path: "/v1/x".to_owned(),
                    query: None,
                    headers: Vec::new(),
                    header_values: Vec::new(),
                    forward: Zeroizing::new(Vec::new()),
                    status: 200,
                    answered: true,
                    api: None,
                    pick: None,
                    body: Zeroizing::new(bodies(i)[kind].clone().into_bytes()),
                })
                .collect(),
            outcome: serde_json::json!({}),
        };
        let hits = sweep_model(&report, &cs);
        for (i, case) in cases.iter().enumerate() {
            if !hits.iter().any(|h| {
                h.seq == i as u64 && h.found.label == case.label && h.found.encoding == case.name
            }) {
                missing.push(format!("{what}: {} as {}", case.label, case.name));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} cases not found, first: {:?}",
        missing.len(),
        5 * cases.len(),
        &missing[..missing.len().min(10)]
    );
}

/// What Python's `json.dumps` makes of a Claude Code history line holding
/// each text: ASCII only, every other character as `\u` escapes.
fn python_history_lines(texts: &[String]) -> Vec<String> {
    let script = "import json, sys\n\
        out = [json.dumps({'display': t, 'pastedContents': {}, 'timestamp': 1,\n\
        \x20                  'project': '/tmp/acme'}) for t in json.load(sys.stdin)]\n\
        json.dump(out, sys.stdout)\n";
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("python3 is needed for the envelope oracle: {e}"));
    let input = serde_json::to_vec(texts).unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), &input).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "python3 failed");
    serde_json::from_slice(&out.stdout).unwrap()
}
