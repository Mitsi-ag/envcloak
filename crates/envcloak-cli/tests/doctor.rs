//! Gate 36: real CLI, isolated stores and a real daemon. No output has values.
#![allow(clippy::unwrap_used)]
mod common;
use common::*;
use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};
use serde_json::{Value, json};

struct Fixture {
    home: TestHome,
    daemon: Daemon,
    values: Vec<Canary>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_values(canaries(fresh_seed()))
    }
    fn with_values(mut values: Vec<Canary>) -> Self {
        let home = TestHome::new();
        values.push(Canary::new("unicode", "é".repeat(8)));
        values.push(Canary::new(
            "pq",
            format!("password={}\\\\{}", "a".repeat(7), "b".repeat(7)),
        ));
        // libpq reads the escaped backslash as one character: 16 written,
        // 15 at the server. Cover the scanner's field form as well as raw DSN.
        values.push(Canary::new(
            "pq-field",
            format!("{}\\\\{}", "a".repeat(7), "b".repeat(7)),
        ));
        let kit = RecoveryKit::generate();
        let pass = by_label(&values, labels::VAULT_PASSPHRASE);
        let mut vault = create_vault_with_kit(
            &VaultPaths::under(data_dir(&home)),
            &SecretBytes::copy_from(pass.value()),
            &kit,
            KdfParams::minimum(),
        )
        .unwrap();
        vault
            .transact(|t| {
                for (slug, label, provider) in [
                    ("openai/doctor", labels::OPENAI_API_KEY, Some("openai")),
                    ("short/doctor", labels::SHORT_TOKEN, None),
                    ("unicode/doctor", "unicode", None),
                    ("pq/doctor", "pq", None),
                    ("pq-field/doctor", "pq-field", None),
                ] {
                    let id = t.create_item(NewItem {
                        class: ItemClass::Secret,
                        slug: Slug::new(slug).unwrap(),
                        details: ItemDetails {
                            title: "Doctor fixture".into(),
                            provider: provider.map(str::to_owned),
                            ..ItemDetails::default()
                        },
                    })?;
                    t.add_field(
                        id,
                        FieldName::new("value").unwrap(),
                        SecretBytes::copy_from(by_label(&values, label).value()),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        drop(vault);
        let daemon = start_daemon(&home);
        let outside = outside_dir();
        let pass_file = secret_file(outside.path(), "pass", pass.value());
        assert!(
            run_on_terminal(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &pass_file, true)]
            )
            .status
            .success()
        );
        Self {
            home,
            daemon,
            values,
        }
    }
    fn transcript(&self) -> std::path::PathBuf {
        let path = self
            .home
            .home()
            .join(".claude/projects/fixture/events.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let texts: Vec<_> = [
            labels::OPENAI_API_KEY,
            labels::OPENAI_API_KEY,
            labels::SHORT_TOKEN,
            "unicode",
            "pq",
            labels::GITHUB_TOKEN,
        ]
        .iter()
        .map(|label| std::str::from_utf8(by_label(&self.values, label).value()).unwrap())
        .collect();
        std::fs::write(&path, format!("{}\n", json!({"text": texts}))).unwrap();
        path
    }
    fn doctor(&self, json: bool, agent: bool) -> std::process::Output {
        let mut c = on_terminal_command(
            &self.home,
            if json {
                &["doctor", "--json"]
            } else {
                &["doctor"]
            },
            &[],
        );
        c.env("CLAUDE_CODE_TMPDIR", self.home.root().join("tmp"));
        if agent {
            c.env("ENVCLOAK_FIXTURE_AGENT", "1");
        }
        let out = finish_within(c, std::time::Duration::from_secs(120));
        assert_no_canary(&out.stdout, &self.values);
        assert_no_canary(&out.stderr, &self.values);
        assert_no_canary(self.daemon.log().as_bytes(), &self.values);
        out
    }
}

fn keys(v: &Value, expected: &[&str]) {
    let mut actual: Vec<_> = v.as_object().unwrap().keys().map(String::as_str).collect();
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(actual, expected, "report grammar changed");
}
fn grammar(v: &Value) {
    keys(v, &["items", "unknown", "not_scanned", "incomplete"]);
    for item in v["items"].as_array().unwrap() {
        keys(item, &["slug", "places", "rotate_url"]);
        for place in item["places"].as_array().unwrap() {
            keys(place, &["display_path", "count"]);
            assert!(place["count"].as_u64().unwrap() > 0);
        }
    }
    for item in v["unknown"].as_array().unwrap() {
        keys(item, &["provider", "places"]);
        assert!(item["provider"].is_string());
        for place in item["places"].as_array().unwrap() {
            keys(place, &["display_path", "count"]);
            assert!(place["display_path"].is_string());
            assert!(place["count"].as_u64().unwrap() > 0);
        }
    }
    for note in v["not_scanned"].as_array().unwrap() {
        keys(note, &["display_path", "reason"]);
    }
}
#[test]
fn gate36_report_grammar_floor_exposure_and_output_sweep() {
    // A trailing key character can also be prose punctuation. Its trimmed
    // reading matches the provider pattern but is not the value in the vault.
    // Cover both legal readings deliberately, not only when a seed ends so.
    for suffix in ['A', '-', '_'] {
        report_grammar_with_suffix(suffix);
    }
}

fn report_grammar_with_suffix(suffix: char) {
    let mut values = canaries(fresh_seed());
    let index = values
        .iter()
        .position(|v| v.label == labels::OPENAI_API_KEY)
        .unwrap();
    let mut value = values[index].as_str().to_owned();
    value.pop();
    value.push(suffix);
    values[index] = Canary::new(labels::OPENAI_API_KEY, value);
    let f = Fixture::with_values(values);
    let path = f.transcript();
    let display_path = path.canonicalize().unwrap().to_str().unwrap().to_owned();
    let places = |count| json!([{"display_path": display_path, "count": count}]);
    let mut unknown = vec![json!({"provider": "github", "places": places(1)})];
    if suffix != 'A' {
        unknown.push(json!({"provider": "openai", "places": places(2)}));
    }
    // Positive control: the detector sees actual fixture exposures.
    assert!(!envcloak_testkit::sweep_dir(path.parent().unwrap(), &f.values).is_empty());
    let mut metadata = Value::Null;
    for agent in [false, true] {
        let out = f.doctor(true, agent);
        assert!(out.status.success(), "{}", stderr(&out));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        grammar(&v);
        assert_eq!(v["incomplete"], Value::Null);
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            1,
            "guessable value reported"
        );
        assert_eq!(v["items"][0]["slug"], "openai/doctor");
        assert_eq!(v["items"][0]["places"], places(2));
        assert_eq!(
            v["items"][0]["rotate_url"],
            "https://platform.openai.com/api-keys"
        );
        assert_eq!(v["unknown"], json!(unknown), "suffix {suffix}");
        metadata = v;
    }
    let out = f.doctor(false, false);
    assert!(out.status.success());
    let text = stdout(&out);
    // Check the whole grammar with multiplicity. Two finding sections may
    // legitimately repeat a path/count or the same provider's rotation URL.
    // Mutations: add a line-number field, drop an unknown-provider heading,
    // or duplicate an item heading; each must still fail this exact oracle.
    let mut expected = vec![
        "item openai/doctor".to_owned(),
        format!("  path {display_path} count 2"),
        "rotate https://platform.openai.com/api-keys".to_owned(),
        "unknown github".to_owned(),
        format!("  path {display_path} count 1"),
    ];
    if suffix != 'A' {
        expected.extend([
            "unknown openai".to_owned(),
            format!("  path {display_path} count 2"),
        ]);
    }
    expected.push("rotate https://github.com/settings/tokens".to_owned());
    if suffix != 'A' {
        expected.push("rotate https://platform.openai.com/api-keys".to_owned());
    }
    expected.push("envcloak scrub: encrypted backup before rewriting".to_owned());
    for note in metadata["not_scanned"].as_array().unwrap() {
        expected.push(format!(
            "not_scanned {} {}",
            note["display_path"].as_str().unwrap(),
            note["reason"].as_str().unwrap()
        ));
    }
    expected.push("doctor: complete".to_owned());
    let actual: Vec<_> = text.lines().map(str::to_owned).collect();
    assert_eq!(
        actual, expected,
        "human output exceeds its metadata grammar; suffix {suffix}"
    );
    assert!(text.find("rotate ").unwrap() < text.find("envcloak scrub").unwrap());
    let shown = run(&f.home, &["show", "openai/doctor", "--json"], &[]);
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["exposed"]["sources"], json!(["transcript"]));
}
#[test]
fn incomplete_never_exits_success_and_hostile_paths_are_masked() {
    let f = Fixture::new();
    let root = f.home.home().join(".claude/projects");
    std::fs::create_dir_all(&root).unwrap();
    let name = std::str::from_utf8(by_label(&f.values, labels::OPENAI_API_KEY).value()).unwrap();
    std::os::unix::fs::symlink("missing", root.join(name)).unwrap();
    let out = f.doctor(true, false);
    assert!(
        !out.status.success(),
        "capped or unreadable scans must fail"
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    grammar(&v);
    assert!(v["incomplete"].is_string());
    assert!(!v["not_scanned"].as_array().unwrap().is_empty());
}
#[test]
fn hostile_arguments_are_never_echoed() {
    let h = TestHome::new();
    for args in [
        &["doctor", "--path"][..],
        &["doctor", "--bogus\nvalue"],
        &["doctor", "--git-history=bad"],
    ] {
        let out = run(&h, args, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(!stderr(&out).contains("bogus"));
    }
}
#[test]
fn non_utf8_doctor_arguments_never_start_a_scan() {
    use std::os::unix::ffi::OsStringExt;
    let home = TestHome::new();
    let mut command = cli_command(&home, &["doctor"], &[]);
    command
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .env("CLAUDE_CODE_TMPDIR", home.root().join("tmp"));
    let out = finish_within(command, std::time::Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        stderr(&out),
        "envcloak: an argument is not valid UTF-8, which this build does not take\n"
    );
}

#[test]
fn doctor_is_absent_from_mcp() {
    let h = TestHome::new();
    let outside = outside_dir();
    let input = outside.path().join("rpc");
    std::fs::write(&input, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n").unwrap();
    let out = run(&h, &["mcp"], &[(0, &input, true)]);
    assert!(out.status.success());
    let responses: Vec<Value> = stdout(&out)
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let tools = responses.iter().find(|v| v["id"] == 2).unwrap()["result"]["tools"]
        .as_array()
        .unwrap();
    assert!(!tools.is_empty());
    assert!(!tools.iter().any(|t| t["name"] == "doctor"));
}

#[test]
fn bounded_transcripts_report_incomplete() {
    use std::io::Write;
    let f = Fixture::new();
    let path = f.home.home().join(".claude/projects/large.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(b"{\"text\":\"").unwrap();
    for _ in 0..129 {
        file.write_all(&[b'a'; 65536]).unwrap();
    }
    file.write_all(b"\"}\n").unwrap();
    drop(file);
    let out = f.doctor(true, false);
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    grammar(&v);
    assert!(v["incomplete"].is_string());
    assert!(
        v["not_scanned"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["reason"] == "line_too_large")
    );
}

/// Density envelope from M2-04's pinned host stores (docs/AGENTS.md):
/// 12,700 candidate tokens/MiB. Synthetic repetition, not a copied transcript.
/// 1,996,800 identities repeat in one physical store: below one awake-hour
/// allowance once, above it twice under the same owned fixture-agent root.
#[test]
fn gate36_gib_dedup_and_per_root_awake_hour_budget() {
    use std::io::Write;
    const SIZE: u64 = 1 << 30;
    const DISTINCT: u64 = 1_996_800;
    // The host-density counter counts words. Keep one raw identity per word;
    // punctuation would deliberately add the scanner's contextual alternatives.
    let sample = format!("{{\"text\":\"doctorZ{:016}{}\"}}\n", 0, "z".repeat(47));
    let mut control = envcloak_scan::candidates::Candidates::counted(
        envcloak_scan::candidates::Budget::for_counts(),
    )
    .unwrap();
    let stream = envcloak_scan::transcript::scan_reader(
        &mut std::io::Cursor::new(sample),
        envcloak_scan::source::ConfigFormat::Jsonl,
        Default::default(),
        envcloak_scan::candidates::Budget::for_counts(),
        &mut |c| control.insert(c),
    )
    .unwrap();
    assert!(stream.complete());
    assert_eq!(
        control.entries().len(),
        1,
        "density fixture has extra comparison identities"
    );
    let f = Fixture::new();
    let path = f.home.home().join(".claude/projects/density.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
    let control = json!({"text": std::str::from_utf8(by_label(&f.values, labels::OPENAI_API_KEY).value()).unwrap()}).to_string() + "\n";
    file.write_all(control.as_bytes()).unwrap();
    let mut bytes = control.len() as u64;
    let mut i = 0;
    // Exactly 82 bytes per line: 12,787 tokens/MiB, slightly above measured density.
    while bytes + 82 + 5 <= SIZE {
        let line = format!(
            "{{\"text\":\"doctorZ{:016}{}\"}}\n",
            i % DISTINCT,
            "z".repeat(47)
        );
        assert_eq!(line.len(), 82);
        file.write_all(line.as_bytes()).unwrap();
        bytes += 82;
        i += 1;
    }
    file.write_all(b"null").unwrap();
    file.write_all(&vec![b' '; (SIZE - bytes - 5) as usize])
        .unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();
    drop(file);
    assert_eq!(std::fs::metadata(path).unwrap().len(), SIZE);
    let mut person = on_terminal_command(&f.home, &["doctor", "--json"], &[]);
    person.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(person, std::time::Duration::from_secs(3500));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.success(),
        "one GiB must complete: {}",
        report["incomplete"]
    );
    assert_eq!(report["incomplete"], Value::Null);
    assert_eq!(report["items"][0]["slug"], "openai/doctor");
    // A single long-lived builtin agent owns both children, so their roots agree.
    let agent = envcloak_testkit::testkit_bin("fixture-agent");
    let python = python3();
    let program = r#"import subprocess,sys,json
for expected in [0,1]:
 p=subprocess.run([sys.argv[1],'doctor','--json'],capture_output=True,check=False)
 r=json.loads(p.stdout)
 if p.returncode != expected or r['incomplete'] != (None if expected == 0 else 'limited'):
  sys.exit(3)
print('two_runs_checked')
"#;
    let mut command = on_terminal_program(
        &f.home,
        &[
            &agent,
            std::path::Path::new("--"),
            &python,
            std::path::Path::new("-c"),
            std::path::Path::new(program),
            cli(),
        ],
        &[],
    );
    command.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(command, std::time::Duration::from_secs(7000));
    assert!(
        out.status.success(),
        "same agent root must exhaust its awake-hour budget"
    );
    assert_eq!(stdout(&out).trim(), "two_runs_checked");
}

#[cfg(target_os = "linux")]
#[test]
fn traced_doctor_refuses_before_any_store_open() {
    use envcloak_sys::testing::spawn_traced;
    use std::process::{Command, Stdio};
    let f = Fixture::new();
    let path = f.transcript();
    let file = std::fs::File::open(&path).unwrap();
    let reset = || {
        file.set_times(std::fs::FileTimes::new().set_accessed(std::time::UNIX_EPOCH))
            .unwrap()
    };
    reset();
    assert!(f.doctor(true, false).status.success());
    assert!(
        std::fs::metadata(&path).unwrap().accessed().unwrap() > std::time::UNIX_EPOCH,
        "atime observer has no positive control"
    );
    reset();
    let mut cmd = Command::new(cli());
    f.home
        .apply(&mut cmd)
        .args(["doctor", "--json"])
        .env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = spawn_traced(&mut cmd).unwrap().wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).starts_with("envcloak: traced:"));
    assert!(out.stdout.is_empty());
    assert_eq!(
        std::fs::metadata(&path).unwrap().accessed().unwrap(),
        std::time::UNIX_EPOCH,
        "traced doctor read the store"
    );
}

#[test]
fn explicit_sources_are_required_and_overlaps_count_once() {
    let f = Fixture::new();
    let path = f.transcript();
    let mut c = on_terminal_command(
        &f.home,
        &[
            "doctor",
            "--json",
            "--path",
            path.to_str().unwrap(),
            "--path",
            path.to_str().unwrap(),
        ],
        &[],
    );
    c.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(c, std::time::Duration::from_secs(60));
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["items"][0]["places"][0]["count"], 2);
    let project = f.home.home().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let value = by_label(&f.values, labels::OPENAI_API_KEY).as_str();
    std::fs::write(project.join(".env"), format!("VALUE={value}\n")).unwrap();
    std::fs::write(project.join(".env.example"), format!("VALUE={value}\n")).unwrap();
    let home = project;
    let mut c = on_terminal_command(
        &f.home,
        &["doctor", "--json", "--path", home.to_str().unwrap()],
        &[],
    );
    c.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(c, std::time::Duration::from_secs(60));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{} {}",
        v["incomplete"],
        v["not_scanned"]
    );
    let places = v["items"][0]["places"].as_array().unwrap();
    assert_eq!(
        places
            .iter()
            .map(|p| p["count"].as_u64().unwrap())
            .sum::<u64>(),
        3,
        "a repeated source or template was counted"
    );
    let missing = home.join("missing.jsonl");
    let mut command = cli_command(
        &f.home,
        &["doctor", "--json", "--path", missing.to_str().unwrap()],
        &[],
    );
    command.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(command, std::time::Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["incomplete"].is_string());
}

#[test]
fn a_failed_exposure_write_is_incomplete() {
    let f = Fixture::new();
    f.transcript();
    let barrier = tempfile::tempdir_in("/tmp").unwrap();
    struct Release(std::path::PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.0, b"go");
        }
    }
    let release = Release(barrier.path().join("000.go"));
    let mut command = on_terminal_command(&f.home, &["doctor", "--json"], &[]);
    command
        .env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"))
        .env(envcloak_scan::testing::PAUSE_DIR, barrier.path());
    let worker =
        std::thread::spawn(move || finish_within(command, std::time::Duration::from_secs(120)));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !barrier.path().join("000.doctor_before_mark").exists() {
        assert!(
            !worker.is_finished() && std::time::Instant::now() < deadline,
            "doctor did not reach the marking barrier"
        );
        std::thread::yield_now();
    }
    assert!(run(&f.home, &["lock"], &[]).status.success());
    drop(release);
    let out = worker.join().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["incomplete"], "vault_locked");
    assert_eq!(report["items"][0]["slug"], "openai/doctor");
}

#[test]
fn git_history_is_opt_in_and_marks_exposure() {
    use std::process::Command;
    let f = Fixture::new();
    let project = f.home.home().join("repo");
    std::fs::create_dir_all(&project).unwrap();
    let git = |args: &[&str]| {
        let mut command = Command::new("/usr/bin/git");
        f.home
            .apply(&mut command)
            .current_dir(&project)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        assert!(command.output().unwrap().status.success());
    };
    git(&["init", "-q"]);
    let file = project.join("history.txt");
    std::fs::write(&file, by_label(&f.values, labels::OPENAI_API_KEY).value()).unwrap();
    git(&["add", "history.txt"]);
    git(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
    ]);
    std::fs::remove_file(file).unwrap();
    for history in [false, true] {
        let args = if history {
            vec!["doctor", "--json", "--git-history"]
        } else {
            vec!["doctor", "--json"]
        };
        let mut command = on_terminal_command(&f.home, &args, &[]);
        command
            .current_dir(&project)
            .env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
        let out = finish_within(command, std::time::Duration::from_secs(60));
        assert_no_canary(&out.stdout, &f.values);
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(out.status.success(), "{}", report["incomplete"]);
        assert_eq!(
            report["items"].as_array().unwrap().len(),
            usize::from(history)
        );
    }
    let out = run(&f.home, &["show", "openai/doctor", "--json"], &[]);
    let item: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(item["exposed"]["sources"], json!(["git_history"]));
}

#[test]
fn profiles_provider_configs_backups_and_synced_paths_are_reported() {
    let f = Fixture::new();
    let value = by_label(&f.values, labels::OPENAI_API_KEY).as_str();
    std::fs::write(f.home.home().join(".zshrc"), "source profile-extra\n").unwrap();
    std::fs::write(
        f.home.home().join("profile-extra"),
        format!("export TOKEN='{value}'\n"),
    )
    .unwrap();
    let config = f.home.root().join("config/codexbar/config.json");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        json!({"providers":[{"id":"openai","apiKey":value}]}).to_string(),
    )
    .unwrap();
    let backup = f.home.home().join(".claude.json.backup.1");
    std::fs::write(
        backup,
        json!({"mcpServers":{"fixture":{"env":{"TOKEN":value}}}}).to_string(),
    )
    .unwrap();
    let synced = f.home.home().join("Dropbox/history.jsonl");
    std::fs::create_dir_all(synced.parent().unwrap()).unwrap();
    std::fs::write(&synced, json!({"text":value}).to_string() + "\n").unwrap();
    let mut command = on_terminal_command(
        &f.home,
        &["doctor", "--json", "--path", synced.to_str().unwrap()],
        &[],
    );
    command.env("CLAUDE_CODE_TMPDIR", f.home.root().join("tmp"));
    let out = finish_within(command, std::time::Duration::from_secs(60));
    assert_no_canary(&out.stdout, &f.values);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(out.status.success(), "{}", report["incomplete"]);
    let places = report["items"][0]["places"].as_array().unwrap();
    assert_eq!(
        places
            .iter()
            .map(|p| p["count"].as_u64().unwrap())
            .sum::<u64>(),
        4
    );
    let out = run(&f.home, &["show", "openai/doctor", "--json"], &[]);
    let item: Value = serde_json::from_slice(&out.stdout).unwrap();
    let sources = item["exposed"]["sources"].as_array().unwrap();
    for kind in [
        "shell_profile",
        "agent_config",
        "config_backup",
        "synced_folder",
    ] {
        assert!(sources.contains(&json!(kind)));
    }
}

#[test]
fn a_new_run_recomputes_matches_after_rotation() {
    let f = Fixture::new();
    f.transcript();
    let before = f.doctor(true, false);
    let before: Value = serde_json::from_slice(&before.stdout).unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 1);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&f.values, labels::VAULT_PASSPHRASE).value(),
    );
    let replacement = secret_file(
        files.path(),
        "replacement",
        by_label(&f.values, labels::STRIPE_SECRET_KEY).value(),
    );
    let out = run_on_terminal(
        &f.home,
        &[
            "rotate",
            "openai/doctor",
            "--stdin",
            "--passphrase-fd",
            "3",
            "--json",
        ],
        &[(0, &replacement, true), (3, &pass, true)],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let after = f.doctor(true, false);
    assert!(after.status.success());
    let after: Value = serde_json::from_slice(&after.stdout).unwrap();
    assert!(
        after["items"].as_array().unwrap().is_empty(),
        "old report survived rotation"
    );
    assert!(
        after["unknown"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["provider"] == "openai")
    );
}
