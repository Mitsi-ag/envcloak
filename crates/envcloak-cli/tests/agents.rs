//! `envcloak agents install` and `uninstall` on the built binaries (M2 plan
//! M2-08; gate 38, the installer half), with a real daemon that seals
//! every backup.
//!
//! The hosts here are stand-ins: `claude` and `codex` scripts that answer
//! `--version` as the pinned versions do, and (`claude`) keep
//! `~/.claude.json`'s `mcpServers` for `claude mcp add-json`, `get`,
//! `remove` and `list` as Claude Code 2.1.280 was measured to. They are a
//! weaker oracle than the hosts: crates/envcloak-e2e (`m2_story`,
//! `install.rs`) runs the same install against the real, pinned Claude
//! Code and Codex, on configs their own CLIs wrote, and has them load it.
//!
//! - Install then uninstall gives every file back byte for byte, removes
//!   what install created, and leaves the other MCP server listed;
//!   installing twice equals installing once; uninstall right after
//!   install needs no wait (EnvCloak's own stamp), while a file the person
//!   changed in the last 2 minutes is refused.
//! - A non-UTF-8 `CLAUDE.md`, a 4 MiB `settings.json`, a symlinked
//!   `settings.json` and a hard-linked `config.toml` are refused, reported
//!   and left as they were.
//! - `AGENTS.override.md` present: no write to Codex's `AGENTS.md`.
//! - No socket allowance or broader network setting on Linux, with or
//!   without consent; on macOS, Codex's only with consent, and never a
//!   `domains` rule. Never `excludedCommands`, and no approval setting for
//!   any EnvCloak tool; other servers' settings byte for byte as they were.
//! - Every `envcloak <command>` the instruction block names is shipped,
//!   and the block never names `--ask`.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use common::{
    cli, cli_command, data_dir, finish_within, outside_dir, python3, run_on_terminal, secret_file,
    seed_vault, start_daemon, stderr, stdout,
};
use envcloak_agents::blocks;
use envcloak_agents::hosts::codex::RULES;
use envcloak_core::file_backup_v2::list_file_backups_v2;
use envcloak_core::vault::VaultPaths;
use envcloak_testkit::{
    Canary, Daemon, TEST_PATH, TestHome, assert_no_canary, by_label, canaries, daemon_socket,
    fresh_seed, labels,
};
use serde_json::{Value, json};

/// Claude Code 2.1.280 as the installer uses it: `--version`, and `claude
/// mcp add-json --scope user`, `get`, `remove --scope user` and `list` on
/// `mcpServers` in `~/.claude.json` (or `$CLAUDE_CONFIG_DIR/.claude.json`),
/// which it rewrites whole, as Claude Code does.
const FAKE_CLAUDE: &str = r#"
import json, os, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("2.1.280 (Claude Code)")
    sys.exit(0)
d = os.environ.get("CLAUDE_CONFIG_DIR")
path = os.path.join(d, ".claude.json") if d else os.path.join(os.environ["HOME"], ".claude.json")
def load():
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
def save(v):
    with open(path + ".tmp", "w") as f:
        json.dump(v, f, indent=2)
    os.rename(path + ".tmp", path)
if args[:4] == ["mcp", "add-json", "--scope", "user"] and len(args) == 6:
    v = load()
    servers = v.setdefault("mcpServers", {})
    if args[4] in servers:
        sys.exit("MCP server " + args[4] + " already exists in user config")
    servers[args[4]] = json.loads(args[5])
    save(v)
    sys.exit(0)
if args[:4] == ["mcp", "remove", "--scope", "user"] and len(args) == 5:
    v = load()
    if args[4] not in v.get("mcpServers", {}):
        sys.exit("No user-scoped MCP server found with name: " + args[4])
    del v["mcpServers"][args[4]]
    save(v)
    sys.exit(0)
if args[:2] == ["mcp", "get"] and len(args) == 3:
    sys.exit(0 if args[2] in load().get("mcpServers", {}) else 1)
if args == ["mcp", "list"]:
    for name in load().get("mcpServers", {}):
        print(name)
    sys.exit(0)
sys.exit(2)
"#;

/// Codex 0.159.2's `--version`, and `codex mcp list` from `config.toml`.
const FAKE_CODEX: &str = r#"
import os, sys, tomllib
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 0.159.2")
    sys.exit(0)
if args == ["mcp", "list"]:
    home = os.environ.get("CODEX_HOME") or os.path.join(os.environ["HOME"], ".codex")
    with open(os.path.join(home, "config.toml"), "rb") as f:
        for name in tomllib.load(f).get("mcp_servers", {}):
            print(name)
    sys.exit(0)
sys.exit(2)
"#;

const CLAUDE_MD: &str = "# My rules\n\nUse tabs, not spaces.\n";
const CODEX_AGENTS_MD: &str = "# Codex notes\n\nRun the tests before a commit.\n";
const SETTINGS: &str = r#"{
  "permissions": {
    "allow": [
      "mcp__other__lookup",
      "Bash(npm test)"
    ],
    "deny": [
      "Read(./secrets/**)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/true"
          }
        ]
      }
    ]
  },
  "model": "opus"
}
"#;
const OTHER_SERVER: &str = r#"[mcp_servers.other]
command = "/usr/bin/true"
args = ["serve"]
default_tools_approval_mode = "approve"

[mcp_servers.other.tools.lookup]
approval_mode = "approve"
"#;

fn config_toml() -> String {
    format!("# mine\nmodel = \"gpt-5\"\napproval_policy = \"on-request\"\n\n{OTHER_SERVER}")
}

/// A home with a seeded vault, a daemon that has it unlocked, the two
/// stand-in hosts on `PATH`, and each host's configuration as a person
/// who has used them for a while has it.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    _files: tempfile::TempDir,
    bin: PathBuf,
}

/// Sets `p`'s modification time `ago` back: the host wrote it before the
/// install, not during it.
fn age(p: &Path, ago: Duration) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - ago)
        .unwrap();
}

const OLD: Duration = Duration::from_secs(180);

impl Fixture {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        let bin = home.root().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let py = python3();
        for (name, body) in [("claude", FAKE_CLAUDE), ("codex", FAKE_CODEX)] {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!{}\n{body}", py.display())).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let f = Fixture {
            cs,
            home,
            d,
            _files: files,
            bin,
        };
        f.host_configs();
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.home().join(rel)
    }

    /// Each host's configuration, older than 2 minutes; `~/.claude.json`
    /// made by `claude` itself.
    fn host_configs(&self) {
        std::fs::create_dir_all(self.path(".claude")).unwrap();
        std::fs::create_dir_all(self.path(".codex")).unwrap();
        std::fs::write(self.path(".claude/CLAUDE.md"), CLAUDE_MD).unwrap();
        std::fs::write(self.path(".claude/settings.json"), SETTINGS).unwrap();
        std::fs::write(self.path(".codex/AGENTS.md"), CODEX_AGENTS_MD).unwrap();
        std::fs::write(self.path(".codex/config.toml"), config_toml()).unwrap();
        let out = self.host(
            "claude",
            &[
                "mcp",
                "add-json",
                "--scope",
                "user",
                "other",
                r#"{"command":"/usr/bin/true","args":["serve"]}"#,
            ],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        for p in [
            ".claude/settings.json",
            ".codex/config.toml",
            ".claude.json",
        ] {
            age(&self.path(p), OLD);
        }
    }

    /// A stand-in host's command, in the home.
    fn host(&self, name: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(self.bin.join(name));
        self.home
            .apply(&mut cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        finish_within(cmd, Duration::from_secs(30))
    }

    /// `envcloak agents <args>` in `cwd`, with the stand-ins on `PATH`;
    /// nothing it writes holds a canary.
    fn agents_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut argv = vec!["agents"];
        argv.extend_from_slice(args);
        let mut cmd = cli_command(&self.home, &argv, &[]);
        cmd.env("PATH", format!("{}:{TEST_PATH}", self.bin.display()))
            .current_dir(cwd);
        let out = finish_within(cmd, Duration::from_secs(120));
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    fn agents(&self, args: &[&str]) -> Output {
        self.agents_in(&self.home.home(), args)
    }

    /// `agents <args> --json`: the report, and the exit code.
    fn report(&self, args: &[&str]) -> (Value, i32) {
        let mut a = args.to_vec();
        a.push("--json");
        let out = self.agents(&a);
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("{}{}", stdout(&out), stderr(&out)));
        (v, out.status.code().unwrap())
    }

    fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.path(rel)).unwrap()
    }

    fn json(&self, rel: &str) -> Value {
        serde_json::from_slice(&self.read(rel)).unwrap()
    }

    fn text(&self, rel: &str) -> String {
        String::from_utf8(self.read(rel)).unwrap()
    }

    /// The ids of the backups v2 the daemon holds.
    fn backups(&self) -> Vec<String> {
        list_file_backups_v2(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .iter()
            .map(|b| b.id.to_string())
            .collect()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// The files a person's configuration is made of, as bytes.
const FILES: [&str; 5] = [
    ".claude/CLAUDE.md",
    ".claude/settings.json",
    ".claude.json",
    ".codex/AGENTS.md",
    ".codex/config.toml",
];

/// What install creates.
const CREATED: [&str; 2] = [".codex/hooks.json", ".codex/rules/envcloak.rules"];

/// `(host, path, outcome, reason)` of every change in a report.
fn outcomes(v: &Value) -> Vec<(String, String, String, Value)> {
    let mut out = Vec::new();
    for h in v["hosts"].as_array().unwrap() {
        for c in h["changes"].as_array().unwrap() {
            out.push((
                h["host"].as_str().unwrap().to_owned(),
                c["path"].as_str().unwrap().to_owned(),
                c["outcome"].as_str().unwrap().to_owned(),
                c["reason"].clone(),
            ));
        }
    }
    out
}

fn outcome_of(v: &Value, path: &str) -> (String, Value, Value) {
    for h in v["hosts"].as_array().unwrap() {
        for c in h["changes"].as_array().unwrap() {
            if c["path"] == path {
                return (
                    c["outcome"].as_str().unwrap().to_owned(),
                    c["reason"].clone(),
                    c["backup"].clone(),
                );
            }
        }
    }
    panic!("{path} is not in the report: {v}");
}

fn notes(v: &Value, host: &str) -> Vec<String> {
    v["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["host"] == host)
        .flat_map(|h| h["notes"].as_array().unwrap().iter())
        .map(|n| n["name"].as_str().unwrap().to_owned())
        .collect()
}

fn envcloak_path() -> String {
    std::fs::canonicalize(cli())
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// The `[mcp_servers.envcloak]` table of a config.toml, as text.
fn envcloak_table(toml: &str) -> &str {
    let start = toml.find("[mcp_servers.envcloak]").unwrap();
    let rest = &toml[start + 1..];
    let end = rest.find("\n[").map_or(toml.len(), |e| start + 1 + e + 1);
    &toml[start..end]
}

/// Install, twice, then uninstall at once: the person's files come back
/// byte for byte, what install created is gone, and the other server is
/// still listed by each host. In between, every addition is where SPEC §7
/// puts it and nothing else changed.
///
/// Mutations checked: no backup before `settings.json` is changed (the
/// `back_up` call skipped for it in `writer::try_change`): its report
/// line names no backup and this fails. `Writer::own` always false (no
/// exemption for EnvCloak's own stamp): the uninstall right after the
/// install is refused `recently_changed` for settings.json and
/// config.toml, and this fails.
#[test]
fn install_then_uninstall_gives_every_byte_back() {
    let f = Fixture::new();
    let before: Vec<Vec<u8>> = FILES.iter().map(|p| f.read(p)).collect();
    // Without --yes: the plan, and nothing written.
    let out = f.agents(&["install"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Nothing was changed: run this again with --yes to write it."),
        "{}",
        stdout(&out)
    );
    for (p, b) in FILES.iter().zip(&before) {
        assert_eq!(&f.read(p), b, "{p} changed without --yes");
    }
    assert!(f.backups().is_empty());

    let (v, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["complete"], true, "{v}");
    // A backup before every change of a file that was there.
    let backups = f.backups();
    for p in [
        "~/.claude/CLAUDE.md",
        "~/.claude/settings.json",
        "~/.claude.json",
        "~/.codex/AGENTS.md",
        "~/.codex/config.toml",
    ] {
        let (outcome, _, backup) = outcome_of(&v, p);
        assert_eq!(outcome, "changed", "{p}: {v}");
        let id = backup.as_str().unwrap_or_else(|| panic!("{p} has no backup: {v}"));
        assert!(backups.iter().any(|b| b == id), "{p}: {id} not in {backups:?}");
    }
    assert_eq!(backups.len(), 5, "{backups:?}");
    for p in ["~/.codex/hooks.json", "~/.codex/rules/envcloak.rules"] {
        assert_eq!(outcome_of(&v, p).0, "created", "{p}: {v}");
    }

    let me = envcloak_path();
    // CLAUDE.md and AGENTS.md: the person's text, then the block.
    for (p, mine) in [
        (".claude/CLAUDE.md", CLAUDE_MD),
        (".codex/AGENTS.md", CODEX_AGENTS_MD),
    ] {
        let t = f.text(p);
        assert!(t.starts_with(mine), "{p}: {t}");
        assert!(t.ends_with(&blocks::block()), "{p}: {t}");
    }
    // settings.json: the additions, and the person's entries as they were.
    let s = f.json(".claude/settings.json");
    let mine: Value = serde_json::from_str(SETTINGS).unwrap();
    assert_eq!(s["permissions"]["allow"], mine["permissions"]["allow"]);
    assert_eq!(
        s["permissions"]["deny"],
        json!(["Read(./secrets/**)", "Read(**/.env*)"])
    );
    assert_eq!(s["model"], "opus");
    assert_eq!(s["hooks"]["PreToolUse"][0], mine["hooks"]["PreToolUse"][0]);
    let hook = |event: &str| format!("{me} hook --host claude-code --event {event}");
    for (event, matcher) in [
        ("UserPromptSubmit", None),
        ("PreToolUse", Some("Bash|Read|Grep|Glob|Edit")),
        ("PreToolUse", Some("mcp__.*")),
        ("SessionStart", None),
    ] {
        let found = s["hooks"][event].as_array().unwrap().iter().any(|e| {
            e["hooks"][0]["command"] == hook(event).as_str()
                && e["matcher"].as_str() == matcher
                && e["hooks"][0]["timeout"] == 10
        });
        assert!(found, "{event} {matcher:?}: {s}");
    }
    let data = data_dir(&f.home);
    let files = &s["sandbox"]["credentials"]["files"];
    for d in ["vault", "backups"] {
        let want = json!({"path": data.join(d).to_string_lossy(), "mode": "deny"});
        assert!(files.as_array().unwrap().contains(&want), "{files}");
    }
    let text = f.text(".claude/settings.json");
    assert!(!text.contains("excludedCommands"));
    assert!(!text.contains("mcp__envcloak"), "no approval of an EnvCloak tool");
    // ~/.claude.json: EnvCloak's server as written, the other one as it was.
    let cj = f.json(".claude.json");
    assert_eq!(
        cj["mcpServers"]["envcloak"],
        json!({"command": me, "args": ["mcp", "--host", "claude-code"], "timeout": 60000})
    );
    assert_eq!(
        cj["mcpServers"]["other"],
        json!({"command": "/usr/bin/true", "args": ["serve"]})
    );
    // Codex: hooks, rules and the server; the other server's text as it was.
    let hooks = f.json(".codex/hooks.json");
    for event in ["UserPromptSubmit", "PreToolUse", "SessionStart"] {
        let cmd = format!("{me} hook --host codex --event {event}");
        assert!(
            hooks["hooks"][event]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["hooks"][0]["command"] == cmd.as_str()),
            "{hooks}"
        );
    }
    assert_eq!(f.text(".codex/rules/envcloak.rules"), RULES);
    let toml = f.text(".codex/config.toml");
    assert!(toml.starts_with(&config_toml()), "{toml}");
    let table = envcloak_table(&toml);
    assert!(table.contains(&format!("command = \"{me}\"")), "{table}");
    assert!(table.contains(r#"args = ["mcp", "--host", "codex"]"#), "{table}");
    assert!(table.contains("tool_timeout_sec = 60"), "{table}");
    assert!(!table.contains("approval"), "{table}");
    assert_eq!(
        table.contains("env_vars"),
        cfg!(target_os = "linux"),
        "{table}"
    );
    if cfg!(target_os = "linux") {
        assert!(table.contains("XDG_RUNTIME_DIR"), "{table}");
    }
    // Each host still lists both servers.
    for (host, want) in [("claude", "envcloak\nother"), ("codex", "envcloak\nother")] {
        let out = f.host(host, &["mcp", "list"]);
        let listed = stdout(&out);
        let mut names: Vec<&str> = listed.lines().map(str::trim).collect();
        names.sort_unstable();
        assert_eq!(names.join("\n"), want, "{host}");
    }

    // Twice equals once.
    let after: Vec<Vec<u8>> = FILES.iter().chain(&CREATED).map(|p| f.read(p)).collect();
    let (v2, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 0, "{v2}");
    assert!(
        outcomes(&v2).iter().all(|(_, _, o, _)| o == "unchanged"),
        "{v2}"
    );
    let again: Vec<Vec<u8>> = FILES.iter().chain(&CREATED).map(|p| f.read(p)).collect();
    assert!(after == again, "a second install changed a file");
    assert_eq!(f.backups().len(), 5);

    // Uninstall at once: no 2-minute wait for EnvCloak's own writes.
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(u["complete"], true, "{u}");
    for (p, b) in FILES.iter().zip(&before) {
        assert!(&f.read(p) == b, "{p} is not as it was");
    }
    for p in CREATED {
        assert!(!f.path(p).exists(), "{p} is still there");
    }
    for host in ["claude", "codex"] {
        assert_eq!(stdout(&f.host(host, &["mcp", "list"])).trim(), "other", "{host}");
    }
    // Nothing left to take out.
    let (u2, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u2}");
    assert!(outcomes(&u2).is_empty(), "{u2}");
    f.sweep();
}

/// A person's change after the install is kept: uninstall takes out only
/// EnvCloak's entries, by structure. A host-owned file the person changed
/// in the last 2 minutes is refused, and the rest is still done.
#[test]
fn a_change_made_since_is_kept_and_a_fresh_one_is_waited_for() {
    let f = Fixture::new();
    let (v, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 0, "{v}");
    // The person adds a rule to settings.json and a line to CLAUDE.md.
    let mut s = f.json(".claude/settings.json");
    s["permissions"]["deny"]
        .as_array_mut()
        .unwrap()
        .push(json!("Read(./private/**)"));
    std::fs::write(
        f.path(".claude/settings.json"),
        serde_json::to_vec_pretty(&s).unwrap(),
    )
    .unwrap();
    let md = format!("{}\nMore of mine.\n", f.text(".claude/CLAUDE.md"));
    std::fs::write(f.path(".claude/CLAUDE.md"), &md).unwrap();
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 1, "{u}");
    let (outcome, reason, _) = outcome_of(&u, "~/.claude/settings.json");
    assert_eq!(
        (outcome.as_str(), reason),
        ("refused", json!("recently_changed")),
        "{u}"
    );
    // CLAUDE.md is no host file: its block is taken out, the rest kept.
    assert_eq!(f.text(".claude/CLAUDE.md"), format!("{CLAUDE_MD}\nMore of mine.\n"));
    // Two minutes on, settings.json loses EnvCloak's entries only.
    age(&f.path(".claude/settings.json"), OLD);
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    let s = f.json(".claude/settings.json");
    assert_eq!(
        s["permissions"]["deny"],
        json!(["Read(./secrets/**)", "Read(./private/**)"])
    );
    assert!(!f.text(".claude/settings.json").contains("envcloak"), "{s}");
    assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    assert!(s.get("sandbox").is_none(), "{s}");
    f.sweep();
}

/// Files EnvCloak must not change are reported with the reason and left
/// byte for byte as they were; the other changes are still made, and the
/// command exits 1 with `agents_incomplete`.
///
/// Mutation checked: `read_plain`'s symlink refusal bypassed for the
/// writer (the target's path resolved with `canonicalize` before it is
/// opened, so the edit goes through the link): settings.json's target
/// gains EnvCloak's hooks and this fails.
#[test]
fn files_it_must_not_change_are_reported_and_left_alone() {
    let f = Fixture::new();
    let outside = f.home.root().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    // A non-UTF-8 CLAUDE.md.
    let latin1 = b"# R\xe8gles\n".to_vec();
    std::fs::write(f.path(".claude/CLAUDE.md"), &latin1).unwrap();
    // settings.json a symlink to a file elsewhere.
    let real = outside.join("settings.json");
    std::fs::rename(f.path(".claude/settings.json"), &real).unwrap();
    std::os::unix::fs::symlink(&real, f.path(".claude/settings.json")).unwrap();
    // config.toml with a second hard link.
    std::fs::hard_link(f.path(".codex/config.toml"), outside.join("config.toml")).unwrap();
    // Codex's AGENTS.md of 4 MiB.
    let big = vec![b'a'; 4 * 1024 * 1024];
    std::fs::write(f.path(".codex/AGENTS.md"), &big).unwrap();
    let keep: Vec<Vec<u8>> = [
        f.path(".claude/CLAUDE.md"),
        real.clone(),
        f.path(".codex/config.toml"),
        f.path(".codex/AGENTS.md"),
    ]
    .iter()
    .map(|p| std::fs::read(p).unwrap())
    .collect();

    let out = f.agents(&["install", "--yes"]);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(
        stderr(&out).starts_with("envcloak: agents_incomplete: "),
        "{}",
        stderr(&out)
    );
    let (v, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 1);
    assert_eq!(v["complete"], false);
    for (p, why) in [
        ("~/.claude/CLAUDE.md", "not_utf8"),
        ("~/.claude/settings.json", "symlink"),
        ("~/.codex/config.toml", "hard_linked"),
        ("~/.codex/AGENTS.md", "too_large"),
    ] {
        let (outcome, reason, backup) = outcome_of(&v, p);
        assert_eq!((outcome.as_str(), reason), ("refused", json!(why)), "{p}: {v}");
        assert!(backup.is_null(), "{p}: {v}");
    }
    let now: Vec<Vec<u8>> = [
        f.path(".claude/CLAUDE.md"),
        real,
        f.path(".codex/config.toml"),
        f.path(".codex/AGENTS.md"),
    ]
    .iter()
    .map(|p| std::fs::read(p).unwrap())
    .collect();
    assert!(keep == now, "a refused file changed");
    assert!(
        std::fs::symlink_metadata(f.path(".claude/settings.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // The rest was done: Codex's hooks and rules, Claude Code's server.
    assert_eq!(outcome_of(&v, "~/.codex/hooks.json").0, "unchanged");
    assert!(f.path(".codex/rules/envcloak.rules").exists());
    assert!(f.json(".claude.json")["mcpServers"]["envcloak"].is_object());
    f.sweep();
}

/// A host file changed in the last 2 minutes (the host or the person just
/// wrote it) is refused before any backup.
#[test]
fn a_host_file_written_in_the_last_two_minutes_is_refused() {
    let f = Fixture::new();
    std::fs::write(f.path(".claude/settings.json"), SETTINGS).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 1, "{v}");
    let (outcome, reason, backup) = outcome_of(&v, "~/.claude/settings.json");
    assert_eq!(
        (outcome.as_str(), reason, backup),
        ("refused", json!("recently_changed"), Value::Null),
        "{v}"
    );
    assert_eq!(f.read(".claude/settings.json"), SETTINGS.as_bytes());
    f.sweep();
}

/// Codex reads `AGENTS.override.md` instead of `AGENTS.md`: with one
/// there, `AGENTS.md` is not written and the report says why.
///
/// Mutation checked: the override check removed from `codex_plan`: the
/// block is written into `AGENTS.md` and this fails.
#[test]
fn the_codex_block_is_not_written_beside_an_override() {
    let f = Fixture::new();
    std::fs::write(f.path(".codex/AGENTS.override.md"), "# Override\n").unwrap();
    let (v, code) = f.report(&["install", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert!(notes(&v, "codex").contains(&"override_file".to_owned()), "{v}");
    assert!(
        !outcomes(&v).iter().any(|(_, p, _, _)| p.ends_with("AGENTS.md")),
        "{v}"
    );
    assert_eq!(f.text(".codex/AGENTS.md"), CODEX_AGENTS_MD);
    assert_eq!(f.text(".codex/AGENTS.override.md"), "# Override\n");
    f.sweep();
}

/// K-01 as measured: on Linux no socket allowance or broader network
/// setting for either host, with or without consent, and both report the
/// sandboxed shell unsupported. On macOS, Claude Code's resolved socket in
/// `allowUnixSockets`, and Codex's bounded allowance only with consent:
/// `network_access`, the proxy enabled, one `unix_sockets` rule naming
/// EnvCloak's socket, never a `domains` rule.
///
/// Mutation checked: a `domains` allow rule added to Codex's proxy
/// settings in `hosts::codex::config_settings`: config.toml holds
/// `domains` and this fails.
#[test]
fn socket_allowances_follow_k01() {
    for consent in [false, true] {
        let f = Fixture::new();
        let mut args = vec!["install", "--yes"];
        if consent {
            args.push("--consent-sandbox-sockets");
        }
        let (v, code) = f.report(&args);
        assert_eq!(code, 0, "{v}");
        let settings = f.json(".claude/settings.json");
        let toml = f.text(".codex/config.toml");
        assert!(toml.starts_with(&config_toml()), "{toml}");
        assert!(!toml.contains("domains"), "{toml}");
        for word in ["allowAll", "excludedCommands", "allowNetwork"] {
            assert!(!f.text(".claude/settings.json").contains(word), "{word}");
        }
        if cfg!(target_os = "linux") {
            assert!(settings["sandbox"].get("network").is_none(), "{settings}");
            for word in ["network_access", "network_proxy", "sandbox_workspace_write"] {
                assert!(!toml.contains(word), "{word}: {toml}");
            }
            for host in ["claude-code", "codex"] {
                assert!(
                    notes(&v, host).contains(&"sandbox_blocks_socket".to_owned()),
                    "{host}: {v}"
                );
            }
        } else {
            let socket = daemon_socket(&f.home);
            let resolved = std::fs::canonicalize(socket.parent().unwrap())
                .unwrap()
                .join(socket.file_name().unwrap());
            assert_eq!(
                settings["sandbox"]["network"]["allowUnixSockets"],
                json!([resolved.to_string_lossy()]),
                "{settings}"
            );
            assert_eq!(toml.contains("network_access = true"), consent, "{toml}");
            assert_eq!(toml.contains("[features.network_proxy]"), consent, "{toml}");
            if consent {
                assert!(
                    toml.contains(&format!("\"{}\" = \"allow\"", socket.display())),
                    "{toml}"
                );
                assert_eq!(toml.matches("= \"allow\"").count(), 1, "{toml}");
            } else {
                assert!(notes(&v, "codex").contains(&"consent_needed".to_owned()), "{v}");
            }
        }
        // The person's own settings, as they were.
        assert!(toml.contains(OTHER_SERVER));
        assert!(toml.contains("approval_policy = \"on-request\""));
        let (u, code) = f.report(&["uninstall", "--yes"]);
        assert_eq!(code, 0, "{u}");
        assert_eq!(f.text(".codex/config.toml"), config_toml());
        assert_eq!(f.text(".claude/settings.json"), SETTINGS);
        f.sweep();
    }
}

/// No approval setting for any EnvCloak tool, in either host, and the
/// other server's approval settings byte for byte as they were.
///
/// Mutation checked: `default_tools_approval_mode = "approve"` added to
/// EnvCloak's server in `hosts::codex::config_settings` (a server-wide
/// approval mode): this fails.
#[test]
fn no_approval_setting_is_written_for_envcloak() {
    let f = Fixture::new();
    let (v, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let toml = f.text(".codex/config.toml");
    assert!(!envcloak_table(&toml).contains("approval"), "{toml}");
    assert_eq!(toml.matches("approval_mode").count(), 2, "{toml}");
    assert!(toml.contains(OTHER_SERVER), "{toml}");
    let settings = f.text(".claude/settings.json");
    assert!(!settings.contains("mcp__envcloak"), "{settings}");
    assert!(!settings.contains("\"allow\": [\n      \"mcp__other__lookup\",\n      \"Bash(npm test)\",") );
    let cj = f.json(".claude.json");
    let entry = cj["mcpServers"]["envcloak"].as_object().unwrap();
    let mut keys: Vec<&str> = entry.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["args", "command", "timeout"]);
    f.sweep();
}

/// The project scope (Map C §6): the block goes into `CLAUDE.md` and
/// `AGENTS.md` where they are, a lone `AGENTS.md` gets no `CLAUDE.md`
/// beside it, and a project with neither gets an `AGENTS.md`. Uninstall
/// gives each back.
#[test]
fn the_project_scope_writes_where_the_project_already_keeps_instructions() {
    let f = Fixture::new();
    let root = f.home.root().join("projects");
    let lone = root.join("lone");
    let claude = root.join("claude");
    let both = root.join("both");
    let none = root.join("none");
    for d in [&lone, &claude, &both, &none] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(lone.join("AGENTS.md"), "# Lone\n").unwrap();
    std::fs::write(claude.join("CLAUDE.md"), "# Claude\n").unwrap();
    std::fs::write(both.join("AGENTS.md"), "# A\n").unwrap();
    std::fs::write(both.join("CLAUDE.md"), "# C\n").unwrap();
    for (dir, present, absent) in [
        (&lone, &["AGENTS.md"][..], &["CLAUDE.md", "CLAUDE.local.md"][..]),
        (&claude, &["CLAUDE.md"], &["AGENTS.md"]),
        (&both, &["AGENTS.md", "CLAUDE.md"], &[]),
        (&none, &["AGENTS.md"], &["CLAUDE.md"]),
    ] {
        let before: Vec<Option<Vec<u8>>> = present
            .iter()
            .map(|n| std::fs::read(dir.join(n)).ok())
            .collect();
        let out = f.agents_in(dir, &["install", "--project", "--yes"]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
        for n in present {
            let t = std::fs::read_to_string(dir.join(n)).unwrap();
            assert!(t.ends_with(&blocks::block()), "{}: {t}", dir.join(n).display());
        }
        for n in absent {
            assert!(!dir.join(n).exists(), "{}", dir.join(n).display());
        }
        // The global files are not touched by --project alone.
        assert_eq!(f.text(".claude/CLAUDE.md"), CLAUDE_MD);
        let out = f.agents_in(dir, &["uninstall", "--project", "--yes"]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
        for (n, b) in present.iter().zip(&before) {
            assert_eq!(&std::fs::read(dir.join(n)).ok(), b, "{}", dir.join(n).display());
        }
    }
    f.sweep();
}

/// D-20: every `envcloak <command>` the instruction block names is one
/// this build ships (dispatched, never `not_in_this_build`), the block
/// never names `--ask`, and it is the reviewed text.
///
/// Mutation checked: `envcloak add --ask <provider>` in the block: the
/// snapshot and the `--ask` check fail.
#[test]
fn every_command_the_block_names_is_shipped() {
    let block = blocks::block();
    assert!(!block.contains("--ask"));
    let snapshot = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/instruction-block.md");
    assert_eq!(
        block,
        std::fs::read_to_string(&snapshot).unwrap(),
        "the block is not the reviewed text in {}",
        snapshot.display()
    );
    let named = blocks::commands_named();
    assert_eq!(named, ["run", "ls", "ref", "add", "init"]);
    let home = TestHome::new();
    for cmd in named {
        let mut c = Command::new(cli());
        home.apply(&mut c)
            .args([cmd, "--help"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish_within(c, Duration::from_secs(30));
        assert_ne!(out.status.code(), Some(125), "{cmd}: {}", stderr(&out));
        assert!(!stderr(&out).contains("not_in_this_build"), "{cmd}");
        // Its own usage line (`ls` takes no --help and prints it as a
        // usage error): dispatched to the command, not to a stub.
        let both = format!("{}{}", stdout(&out), stderr(&out));
        assert!(both.contains(&format!("usage: envcloak {cmd} ")), "{cmd}: {both}");
    }
}

/// No argument is echoed: a key-shaped `--agent` is a usage error that
/// does not repeat it.
#[test]
fn arguments_are_never_echoed() {
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    for label in [labels::OPENAI_API_KEY, labels::GITHUB_TOKEN] {
        let v = by_label(&cs, label).as_str();
        for args in [
            vec!["agents", "install", "--agent", v],
            vec!["agents", "uninstall", v],
            vec!["agents", "install", "--yes", v],
        ] {
            let out = finish_within(cli_command(&home, &args, &[]), Duration::from_secs(30));
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert_no_canary(&out.stdout, &cs);
            assert_no_canary(&out.stderr, &cs);
        }
    }
}
