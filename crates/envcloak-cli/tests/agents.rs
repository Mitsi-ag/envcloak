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
use envcloak_agents::hosts::claude::{READ_DENY, TOOL_MATCHER};
use envcloak_agents::hosts::codex::RULES;
use envcloak_core::file_backup_v2::list_file_backups_v2;
use envcloak_core::vault::VaultPaths;
use envcloak_testkit::{
    Canary, Daemon, TEST_PATH, TestHome, assert_no_canary, by_label, canaries, daemon_socket,
    fresh_seed, labels, sweep_dir,
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
        self.host_with(name, args, &[])
    }

    /// A stand-in host's command, in the home, with `env` set too.
    fn host_with(&self, name: &str, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(self.bin.join(name));
        self.home
            .apply(&mut cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        finish_within(cmd, Duration::from_secs(30))
    }

    /// `envcloak agents <args>` in `cwd`, with the stand-ins on `PATH`;
    /// nothing it writes holds a canary.
    fn agents_in(&self, cwd: &Path, args: &[&str]) -> Output {
        self.agents_with(cwd, args, &[])
    }

    /// `envcloak agents <args>` in `cwd`, with `env` set too.
    fn agents_with(&self, cwd: &Path, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut argv = vec!["agents"];
        argv.extend_from_slice(args);
        let mut cmd = cli_command(&self.home, &argv, &[]);
        cmd.env("PATH", format!("{}:{TEST_PATH}", self.bin.display()))
            .current_dir(cwd);
        for (k, v) in env {
            cmd.env(k, v);
        }
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
        self.report_with(args, &[])
    }

    /// `agents <args> --json` with `env` set too.
    fn report_with(&self, args: &[&str], env: &[(&str, &Path)]) -> (Value, i32) {
        let mut a = args.to_vec();
        a.push("--json");
        let out = self.agents_with(&self.home.home(), &a, env);
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
        let id = backup
            .as_str()
            .unwrap_or_else(|| panic!("{p} has no backup: {v}"));
        assert!(
            backups.iter().any(|b| b == id),
            "{p}: {id} not in {backups:?}"
        );
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
        ("PreToolUse", Some(TOOL_MATCHER)),
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
    assert!(
        !text.contains("mcp__envcloak"),
        "no approval of an EnvCloak tool"
    );
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
    assert!(
        table.contains(r#"args = ["mcp", "--host", "codex"]"#),
        "{table}"
    );
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
        assert_eq!(
            stdout(&f.host(host, &["mcp", "list"])).trim(),
            "other",
            "{host}"
        );
    }
    // Nothing left to take out.
    let (u2, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u2}");
    assert!(outcomes(&u2).is_empty(), "{u2}");
    // Installed again at once: the uninstall's writes were EnvCloak's own.
    let (v3, code) = f.report(&["install", "--yes"]);
    assert_eq!(code, 0, "{v3}");
    let (u3, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u3}");
    for (p, b) in FILES.iter().zip(&before) {
        assert!(&f.read(p) == b, "{p} is not as it was after a second round");
    }
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
    assert_eq!(
        f.text(".claude/CLAUDE.md"),
        format!("{CLAUDE_MD}\nMore of mine.\n")
    );
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
        assert_eq!(
            (outcome.as_str(), reason),
            ("refused", json!(why)),
            "{p}: {v}"
        );
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
    assert!(
        notes(&v, "codex").contains(&"override_file".to_owned()),
        "{v}"
    );
    assert!(
        !outcomes(&v)
            .iter()
            .any(|(_, p, _, _)| p.ends_with("AGENTS.md")),
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
                assert!(
                    notes(&v, "codex").contains(&"consent_needed".to_owned()),
                    "{v}"
                );
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
    // With consent, settings of the person's own that the allowance would
    // switch on (a proxy domain rule here) refuse it, and config.toml is
    // left as it was (Codex review). Linux writes no allowance at all.
    let f = Fixture::new();
    let with_domain = format!(
        "{}\n[features.network_proxy.domains]\n\"example.com\" = \"allow\"\n",
        config_toml()
    );
    std::fs::write(f.path(".codex/config.toml"), &with_domain).unwrap();
    age(&f.path(".codex/config.toml"), OLD);
    let (v, code) = f.report(&[
        "install",
        "--agent",
        "codex",
        "--consent-sandbox-sockets",
        "--yes",
    ]);
    if cfg!(target_os = "macos") {
        assert_eq!(code, 1, "{v}");
        let (outcome, reason, _) = outcome_of(&v, "~/.codex/config.toml");
        assert_eq!(
            (outcome.as_str(), reason),
            ("refused", json!("network_settings_present")),
            "{v}"
        );
        assert_eq!(f.text(".codex/config.toml"), with_domain);
    } else {
        assert_eq!(code, 0, "{v}");
        assert!(!f.text(".codex/config.toml").contains("network_access"));
    }
    f.sweep();
}

/// The Codex review: the socket allowance was written for any Codex
/// version, while M2-04 measured that the proxy settings limit command
/// networking to EnvCloak's socket on the pinned one only. On another
/// version, consent writes no allowance: the step is reported as not
/// made, with its reason, and the run exits 1; the MCP server and the
/// hooks are written. On Linux nothing is written either way.
///
/// Mutation checked: `socket_allowance_qualified` answering true: the
/// allowance is written for 0.159.3 and this fails.
#[test]
fn the_socket_allowance_needs_a_codex_it_was_measured_on() {
    let f = Fixture::new();
    let p = f.bin.join("codex");
    std::fs::write(
        &p,
        format!(
            "#!{}\n{}",
            python3().display(),
            FAKE_CODEX.replace("codex-cli 0.159.2", "codex-cli 0.159.3")
        ),
    )
    .unwrap();
    let (v, code) = f.report(&[
        "install",
        "--agent",
        "codex",
        "--consent-sandbox-sockets",
        "--yes",
    ]);
    let toml = f.text(".codex/config.toml");
    assert!(toml.contains("[mcp_servers.envcloak]"), "{toml}");
    for word in ["network_access", "network_proxy", "unix_sockets"] {
        assert!(!toml.contains(word), "{word}: {toml}");
    }
    let withheld = outcomes(&v).into_iter().any(|(h, path, o, r)| {
        h == "codex"
            && path == "~/.codex/config.toml"
            && o == "refused"
            && r == "socket_allowance_unqualified"
    });
    if cfg!(target_os = "macos") {
        assert_eq!(code, 1, "{v}");
        assert!(withheld, "{v}");
        assert_eq!(v["complete"], false, "{v}");
    } else {
        assert_eq!(code, 0, "{v}");
        assert!(!withheld, "{v}");
    }
    f.sweep();
}

/// The verifier's finding: the version gate only stopped new writes. An
/// allowance written with consent for the measured Codex stayed in
/// config.toml after Codex moved to an unmeasured version, while the
/// report said it was not written. A run that does not write it (an
/// unmeasured version, or no consent) takes EnvCloak's allowance out and
/// says so (`socket_allowance_removed`); one whose change of config.toml
/// is refused says it is still there (`socket_allowance_left`). The server
/// stays throughout, and uninstall gives the bytes back. On Linux no
/// allowance is ever written.
///
/// Mutation checked: the stale settings left in place (`undo_in` not
/// called for them in `hosts::codex::apply`): after the upgrade
/// config.toml still holds `network_access`, the proxy and the
/// `unix_sockets` rule, and this fails.
#[test]
fn an_allowance_written_before_goes_when_it_is_not_written_again() {
    let f = Fixture::new();
    let codex = |version: &str| {
        std::fs::write(
            f.bin.join("codex"),
            format!(
                "#!{}\n{}",
                python3().display(),
                FAKE_CODEX.replace("codex-cli 0.159.2", &format!("codex-cli {version}"))
            ),
        )
        .unwrap();
    };
    let before = f.text(".codex/config.toml");
    let has_allowance = |toml: &str| {
        ["network_access", "network_proxy", "unix_sockets"]
            .iter()
            .any(|w| toml.contains(w))
    };
    let install = |consent: bool| {
        let mut a = vec!["install", "--agent", "codex", "--yes"];
        if consent {
            a.push("--consent-sandbox-sockets");
        }
        f.report(&a)
    };
    let (v, code) = install(true);
    assert_eq!(code, 0, "{v}");
    let macos = cfg!(target_os = "macos");
    assert_eq!(has_allowance(&f.text(".codex/config.toml")), macos);
    // Codex upgraded to a version the allowance was not measured on.
    codex("0.159.3");
    let (v, code) = install(true);
    assert_eq!(code, if macos { 1 } else { 0 }, "{v}");
    let toml = f.text(".codex/config.toml");
    assert!(!has_allowance(&toml), "{toml}");
    assert!(toml.contains("[mcp_servers.envcloak]"), "{toml}");
    assert_eq!(
        notes(&v, "codex").contains(&"socket_allowance_removed".to_owned()),
        macos,
        "{v}"
    );
    // Back on the measured version: with consent it is written again;
    // without, taken out again.
    codex("0.159.2");
    let (v, code) = install(true);
    assert_eq!(code, 0, "{v}");
    assert_eq!(has_allowance(&f.text(".codex/config.toml")), macos);
    let (v, code) = install(false);
    assert_eq!(code, 0, "{v}");
    assert!(!has_allowance(&f.text(".codex/config.toml")));
    assert_eq!(
        notes(&v, "codex").contains(&"socket_allowance_removed".to_owned()),
        macos,
        "{v}"
    );
    // Written once more, then a run whose change of config.toml is refused
    // (Codex wrote the file a moment ago): still there, and said so.
    let (v, code) = install(true);
    assert_eq!(code, 0, "{v}");
    let written = f.read(".codex/config.toml");
    std::fs::write(f.path(".codex/config.toml"), &written).unwrap();
    let (v, code) = install(false);
    assert_eq!(f.read(".codex/config.toml"), written);
    if macos {
        assert_eq!(code, 1, "{v}");
        let (outcome, reason, _) = outcome_of(&v, "~/.codex/config.toml");
        assert_eq!(
            (outcome.as_str(), reason),
            ("refused", json!("recently_changed"))
        );
        assert!(
            notes(&v, "codex").contains(&"socket_allowance_left".to_owned()),
            "{v}"
        );
    } else {
        assert_eq!(code, 0, "{v}");
    }
    age(&f.path(".codex/config.toml"), OLD);
    let (u, code) = f.report(&["uninstall", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{u}");
    // Taken out by structure (values were set and taken out on the way):
    // the person's settings and comment stay, nothing of EnvCloak's.
    let toml = f.text(".codex/config.toml");
    assert!(
        !toml.contains("envcloak") && !has_allowance(&toml),
        "{toml}"
    );
    for kept in ["# mine", "model = \"gpt-5\"", "[mcp_servers.other]"] {
        assert!(
            toml.contains(kept) && before.contains(kept),
            "{kept}: {toml}"
        );
    }
    f.sweep();
}

/// The Codex review: `~/.claude.json` reached Claude Code's own `claude mcp`
/// commands without the writer's hard-link rule. With another hard link
/// it is reported and no command that would change it runs, on install
/// and on uninstall; the link keeps its contents. A symlink is refused the
/// same way.
///
/// Mutation checked: the `nlink > 1` refusal taken out of
/// `claude_registered`: `claude mcp add-json` rewrites the file (the stand-in
/// renames over it, as Claude Code does), the outcome is `changed`, and
/// this fails.
#[test]
fn a_linked_claude_json_is_reported_and_left_alone() {
    let f = Fixture::new();
    let outside = f.home.root().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let before = f.read(".claude.json");
    std::fs::hard_link(f.path(".claude.json"), outside.join("claude.json")).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 1, "{v}");
    let (outcome, reason, backup) = outcome_of(&v, "~/.claude.json");
    assert_eq!(
        (outcome.as_str(), reason),
        ("refused", json!("hard_linked")),
        "{v}"
    );
    assert!(backup.is_null(), "{v}");
    assert_eq!(f.read(".claude.json"), before);
    assert_eq!(std::fs::read(outside.join("claude.json")).unwrap(), before);
    // Uninstall leaves it too: EnvCloak registered nothing.
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.read(".claude.json"), before);
    f.sweep();
    // A symlink, to a file elsewhere, the same: refused by the read.
    let f = Fixture::new();
    let outside = f.home.root().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    let real = outside.join("claude.json");
    std::fs::rename(f.path(".claude.json"), &real).unwrap();
    std::os::unix::fs::symlink(&real, f.path(".claude.json")).unwrap();
    let before = std::fs::read(&real).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 1, "{v}");
    let (outcome, reason, _) = outcome_of(&v, "~/.claude.json");
    assert_eq!(
        (outcome.as_str(), reason),
        ("refused", json!("symlink")),
        "{v}"
    );
    assert_eq!(std::fs::read(&real).unwrap(), before);
    assert!(
        std::fs::symlink_metadata(f.path(".claude.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    f.sweep();
}

/// The verifier's finding: `init --agents-note` saved the state before it
/// printed what it changed, so a failing save hid the results. They are
/// printed first, then the failure; `agents install` and `uninstall`
/// the same.
///
/// Mutations checked: the save moved back above the printing in
/// `project_note` (`file.save(&state).map_err(...)?` first), and in
/// `run_install`: nothing is printed and this fails.
#[test]
fn init_agents_note_prints_its_results_before_a_state_failure() {
    let f = Fixture::new();
    let init = |dir: &Path| {
        let mut cmd = cli_command(&f.home, &["init", "--agents-note"], &[]);
        cmd.current_dir(dir);
        let out = finish_within(cmd, Duration::from_secs(120));
        assert_no_canary(&out.stdout, &f.cs);
        assert_no_canary(&out.stderr, &f.cs);
        out
    };
    let first = f.home.root().join("first");
    std::fs::create_dir_all(&first).unwrap();
    let out = init(&first);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    // EnvCloak's state directory can no longer be written.
    let state = data_dir(&f.home).join("agents");
    let mode = |m: u32| {
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(m)).unwrap();
    };
    mode(0o500);
    // As root the directory's mode stops nothing: this needs a user it
    // stops.
    if std::fs::write(state.join("probe"), b"").is_ok() {
        mode(0o700);
        let _ = std::fs::remove_file(state.join("probe"));
        return;
    }
    let second = f.home.root().join("second");
    std::fs::create_dir_all(&second).unwrap();
    std::fs::write(second.join("AGENTS.md"), "# Notes\n").unwrap();
    let out = init(&second);
    // `agents install` and `uninstall` print theirs first too.
    let installed = f.agents(&["install", "--agent", "codex", "--yes"]);
    let uninstalled = f.agents(&["uninstall", "--yes"]);
    mode(0o700);
    for (o, line) in [
        (&installed, "~/.codex/config.toml: refused"),
        (&uninstalled, "nothing of EnvCloak's to take out"),
    ] {
        assert_eq!(o.status.code(), Some(1), "{}{}", stdout(o), stderr(o));
        assert!(stdout(o).contains(line), "{}", stdout(o));
        assert!(
            stderr(o).starts_with("envcloak: agents_incomplete: "),
            "{}",
            stderr(o)
        );
    }
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("Agent note:"), "{text}");
    assert!(text.contains("AGENTS.md: refused"), "{text}");
    assert!(
        stderr(&out).starts_with("envcloak: agents_incomplete: "),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        std::fs::read_to_string(second.join("AGENTS.md")).unwrap(),
        "# Notes\n"
    );
    f.sweep();
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
    assert!(
        !settings
            .contains("\"allow\": [\n      \"mcp__other__lookup\",\n      \"Bash(npm test)\",")
    );
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
        (
            &lone,
            &["AGENTS.md"][..],
            &["CLAUDE.md", "CLAUDE.local.md"][..],
        ),
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
            assert!(
                t.ends_with(&blocks::block()),
                "{}: {t}",
                dir.join(n).display()
            );
        }
        for n in absent {
            assert!(!dir.join(n).exists(), "{}", dir.join(n).display());
        }
        // The global files are not touched by --project alone.
        assert_eq!(f.text(".claude/CLAUDE.md"), CLAUDE_MD);
        let out = f.agents_in(dir, &["uninstall", "--project", "--yes"]);
        assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
        for (n, b) in present.iter().zip(&before) {
            assert_eq!(
                &std::fs::read(dir.join(n)).ok(),
                b,
                "{}",
                dir.join(n).display()
            );
        }
    }
    f.sweep();
}

/// `envcloak init --agents-note` (SPEC §6.4 step 4) writes the project's
/// block as `agents install --project` does: into a lone `AGENTS.md`,
/// with no `CLAUDE.md` beside it; a dry run of `--import` writes nothing.
///
/// Mutation checked: `--agents-note` parsed but `project_note` not called
/// from `init`: `AGENTS.md` has no block and this fails.
#[test]
fn init_agents_note_writes_the_projects_block() {
    let f = Fixture::new();
    let dir = f.home.root().join("noted");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("AGENTS.md"), "# Notes\n").unwrap();
    let init = |args: &[&str]| {
        let mut argv = vec!["init"];
        argv.extend_from_slice(args);
        let mut cmd = cli_command(&f.home, &argv, &[]);
        cmd.current_dir(&dir);
        let out = finish_within(cmd, Duration::from_secs(120));
        assert_no_canary(&out.stdout, &f.cs);
        assert_no_canary(&out.stderr, &f.cs);
        out
    };
    let out = init(&["--import", "--agents-note"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stderr(&out).contains("the agent note was not written"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("AGENTS.md")).unwrap(),
        "# Notes\n"
    );
    let out = init(&["--agents-note"]);
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("Agent note:"), "{}", stdout(&out));
    let t = std::fs::read_to_string(dir.join("AGENTS.md")).unwrap();
    assert_eq!(t, format!("# Notes\n\n{}", blocks::block()));
    assert!(!dir.join("CLAUDE.md").exists());
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
    let snapshot =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/instruction-block.md");
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
        assert!(
            both.contains(&format!("usage: envcloak {cmd} ")),
            "{cmd}: {both}"
        );
    }
}

/// A literal written into a config by the person (Claude Code's `env`
/// block, between two places install edits; a Codex MCP server's `env`
/// table) never reaches EnvCloak's state: `<data>/agents/` is swept after
/// install and after uninstall (lesson L-12; the review's finding that the
/// undo journal kept the text between two edits).
///
/// Mutation checked: `hunks::hunks` keeping one splice of the whole span
/// from the first changed byte to the last, with its old text (the
/// previous `SpliceRecord`): the sweep finds the settings.json literal in
/// state.json and this fails.
#[test]
fn literals_in_the_configs_never_reach_the_state() {
    let f = Fixture::new();
    let seed = || format!("{:016x}{:016x}", fresh_seed(), fresh_seed());
    let lits = [
        Canary::new("SETTINGS_ENV_LITERAL", format!("ecst{}", seed())),
        Canary::new("CODEX_ENV_LITERAL", format!("eccx{}", seed())),
    ];
    let settings = SETTINGS.replacen(
        "  \"hooks\": {",
        &format!(
            "  \"env\": {{\n    \"API_TOKEN\": \"{}\"\n  }},\n  \"hooks\": {{",
            lits[0].as_str()
        ),
        1,
    );
    assert!(settings.contains(lits[0].as_str()));
    std::fs::write(f.path(".claude/settings.json"), &settings).unwrap();
    // On macOS, consent makes two Codex sites too: network_access near the
    // top, the proxy and EnvCloak's server at the end.
    let toml = format!(
        "[sandbox_workspace_write]\nnetwork_access = false\n\n{}\n[mcp_servers.other.env]\nTOKEN = \"{}\"\n",
        config_toml(),
        lits[1].as_str()
    );
    std::fs::write(f.path(".codex/config.toml"), &toml).unwrap();
    for p in [".claude/settings.json", ".codex/config.toml"] {
        age(&f.path(p), OLD);
    }
    let state = data_dir(&f.home).join("agents");
    let swept = |when: &str| {
        let hits = sweep_dir(&state, &lits);
        assert!(
            hits.is_empty(),
            "{when}: {} hit(s) in <data>/agents",
            hits.len()
        );
    };
    let (v, code) = f.report(&["install", "--yes", "--consent-sandbox-sockets"]);
    assert_eq!(code, 0, "{v}");
    assert!(state.join("state.json").exists());
    swept("after install");
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    swept("after uninstall");
    assert_eq!(f.text(".claude/settings.json"), settings);
    assert_eq!(f.text(".codex/config.toml"), toml);
    f.sweep();
}

/// The Codex review: a write stopped part way (the run killed while the
/// new contents were written beside the config) leaves their first bytes
/// under a temporary name, the person's literal key in them, and the next
/// run took only whole copies and then forgot the record. Here a run is
/// stopped so: the part is laid out as `replace_atomically` names it, and
/// the state holds what the stopped run saved before it wrote (the digest
/// of what it would write). The next install, which writes the same
/// contents, removes the part; a file of that shape it cannot tell is
/// its own stays, is named in the report (`leftovers`), and the run exits
/// 1 until it is gone.
///
/// Mutation checked: `Writer::sweep` taking whole copies only (the
/// previous digest check): the part holding the literal stays and this
/// fails.
#[test]
fn what_a_stopped_write_left_beside_a_config_is_removed_or_named() {
    let f = Fixture::new();
    let lit = Canary::new(
        "SETTINGS_ENV_LITERAL",
        format!("ecst{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let settings = SETTINGS.replacen(
        "{\n",
        &format!(
            "{{\n  \"env\": {{\n    \"API_TOKEN\": \"{}\"\n  }},\n",
            lit.as_str()
        ),
        1,
    );
    std::fs::write(f.path(".claude/settings.json"), &settings).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let installed = f.read(".claude/settings.json");
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.text(".claude/settings.json"), settings);
    // The stopped run: the new contents' first bytes, through the literal
    // and into EnvCloak's first insertion, and the state it saved.
    let first = installed
        .iter()
        .zip(settings.as_bytes())
        .position(|(a, b)| a != b)
        .unwrap();
    let lit_at = settings.find(lit.as_str()).unwrap();
    assert!(
        lit_at + lit.as_str().len() < first,
        "the literal comes first"
    );
    let part = f.path(".claude/.settings.json.envcloak-new-00000000000000aa.tmp");
    std::fs::write(&part, &installed[..first + 4]).unwrap();
    let foreign = f.path(".claude/.settings.json.envcloak-new-00000000000000bb.tmp");
    std::fs::write(&foreign, b"{}").unwrap();
    let state_path = data_dir(&f.home).join("agents").join("state.json");
    let mut state: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    let key = envcloak_agents::writer::key(&f.path(".claude/settings.json"));
    state["leftovers"][key.as_str()] = json!([envcloak_agents::install::digest(&installed)]);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert!(
        !part.exists(),
        "the part holding the literal is still there"
    );
    assert!(foreign.exists());
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["complete"], false, "{v}");
    assert_eq!(
        v["leftovers"],
        json!(["~/.claude/.settings.json.envcloak-new-00000000000000bb.tmp"]),
        "{v}"
    );
    // The literal is in the config alone.
    let elsewhere: Vec<String> = sweep_dir(&f.path(".claude"), std::slice::from_ref(&lit))
        .into_iter()
        .filter(|h| {
            !matches!(h, envcloak_testkit::Hit::Canary { path, .. }
                if path.raw() == f.path(".claude/settings.json"))
        })
        .map(|h| h.to_string())
        .collect();
    assert!(elsewhere.is_empty(), "{elsewhere:?}");
    // Once it is gone, nothing is named, and the run is complete.
    std::fs::remove_file(&foreign).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["leftovers"], json!([]), "{v}");
    f.sweep();
}

/// With EnvCloak's plugin enabled, its hooks and MCP server are not
/// installed again (each hook would run twice), but what no plugin
/// carries still is: the deny rule, which also covers `@` file mentions,
/// and the sandbox settings (Codex review). Uninstall gives the bytes
/// back.
///
/// Mutation checked: the plugin's early return in `claude_plan` (the
/// previous code: only the block written): settings.json has no deny rule
/// and this fails.
#[test]
fn a_plugin_install_still_gets_the_protections() {
    let f = Fixture::new();
    let settings = SETTINGS.replacen(
        "  \"model\": \"opus\"",
        "  \"model\": \"opus\",\n  \"enabledPlugins\": {\n    \"envcloak@market\": true\n  }",
        1,
    );
    std::fs::write(f.path(".claude/settings.json"), &settings).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert!(
        notes(&v, "claude-code").contains(&"plugin_enabled".to_owned()),
        "{v}"
    );
    let s = f.json(".claude/settings.json");
    assert!(
        s["permissions"]["deny"]
            .as_array()
            .unwrap()
            .contains(&json!(READ_DENY)),
        "{s}"
    );
    let data = data_dir(&f.home);
    assert!(
        s["sandbox"]["credentials"]["files"]
            .as_array()
            .unwrap()
            .contains(&json!({"path": data.join("vault").to_string_lossy(), "mode": "deny"})),
        "{s}"
    );
    assert_eq!(
        s["sandbox"]["network"]["allowUnixSockets"].is_array(),
        cfg!(target_os = "macos"),
        "{s}"
    );
    assert!(
        !f.text(".claude/settings.json").contains(" hook --host "),
        "{s}"
    );
    assert!(
        f.json(".claude.json")["mcpServers"]
            .get("envcloak")
            .is_none()
    );
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.text(".claude/settings.json"), settings);
    f.sweep();
}

/// Codex's finding: installing directly and then enabling the plugin left
/// both hook sets and both MCP servers, and nothing said so. In either
/// order: the plugin first, then `agents install`, writes neither (no
/// double install, and `agents status` finds none); `agents install`
/// first, then the plugin, is a double install `agents status` refuses
/// (`double_install`, naming both), and the next `agents install` takes
/// out its own hooks and server (`hooks_removed`), the protections kept,
/// after which `agents status` finds none.
///
/// Mutations checked: the hooks recorded before kept when the plan no
/// longer adds them (the stale elements' removal skipped in `edit_for`):
/// the second install leaves them and this fails; the plugin's
/// `ClaudeMcpRemove` step not planned: the server stays and this fails;
/// `double_install` answering `None`: `agents status` exits 125 on the
/// double install and this fails.
#[test]
fn a_double_install_with_the_plugin_is_found_in_either_order() {
    let f = Fixture::new();
    let enable = |text: &str| {
        text.replacen(
            "  \"model\": \"opus\"",
            "  \"model\": \"opus\",\n  \"enabledPlugins\": {\n    \"envcloak@market\": true\n  }",
            1,
        )
    };
    let status = || {
        let out = f.agents(&["status"]);
        (out.status.code().unwrap(), stderr(&out))
    };
    let own_hooks = || {
        f.text(".claude/settings.json")
            .contains(" hook --host claude-code ")
    };
    let own_server = || {
        f.json(".claude.json")["mcpServers"]
            .get("envcloak")
            .is_some()
    };
    let install = || f.report(&["install", "--agent", "claude-code", "--yes"]);
    // The plugin first.
    std::fs::write(f.path(".claude/settings.json"), enable(SETTINGS)).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (v, code) = install();
    assert_eq!(code, 0, "{v}");
    assert!(!own_hooks() && !own_server());
    let (code, err) = status();
    assert_eq!(code, 125, "{err}");
    assert!(err.starts_with("envcloak: not_in_this_build:"), "{err}");
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.text(".claude/settings.json"), enable(SETTINGS));
    // EnvCloak's own install first, then the person enables the plugin.
    std::fs::write(f.path(".claude/settings.json"), SETTINGS).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (v, code) = install();
    assert_eq!(code, 0, "{v}");
    assert!(own_hooks() && own_server());
    let installed = f.text(".claude/settings.json");
    std::fs::write(f.path(".claude/settings.json"), enable(&installed)).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (code, err) = status();
    assert_eq!(code, 1, "{err}");
    assert!(err.starts_with("envcloak: double_install: "), "{err}");
    for named in ["~/.claude/settings.json", "~/.claude.json"] {
        assert!(err.contains(named), "{named}: {err}");
    }
    let (v, code) = install();
    assert_eq!(code, 0, "{v}");
    assert!(
        notes(&v, "claude-code").contains(&"hooks_removed".to_owned()),
        "{v}"
    );
    assert_eq!(outcome_of(&v, "~/.claude.json").0, "removed", "{v}");
    assert!(!own_hooks() && !own_server());
    let s = f.json(".claude/settings.json");
    assert!(
        s["permissions"]["deny"]
            .as_array()
            .unwrap()
            .contains(&json!(READ_DENY)),
        "{s}"
    );
    let (code, err) = status();
    assert_eq!(code, 125, "{err}");
    // Uninstall leaves the person's own: the plugin, their settings.
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.json(".claude/settings.json"), {
        let mut want: Value = serde_json::from_str(SETTINGS).unwrap();
        want["enabledPlugins"] = json!({"envcloak@market": true});
        want
    });
    // The plugin enabled for one project only, EnvCloak's own install in
    // the user's settings: refused, with what only the person can do
    // (install cannot take its own out for one project).
    std::fs::write(f.path(".claude/settings.json"), SETTINGS).unwrap();
    age(&f.path(".claude/settings.json"), OLD);
    let (v, code) = install();
    assert_eq!(code, 0, "{v}");
    let proj = f.path("proj");
    std::fs::create_dir_all(proj.join(".claude")).unwrap();
    std::fs::write(
        proj.join(".claude/settings.local.json"),
        "{\"enabledPlugins\": {\"envcloak@market\": true}}\n",
    )
    .unwrap();
    let out = f.agents_in(&proj, &["status"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.starts_with("envcloak: double_install: "), "{err}");
    assert!(err.contains("~/proj/.claude/settings.local.json"), "{err}");
    assert!(err.contains("for this project only"), "{err}");
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    f.sweep();
}

/// Codex review: EnvCloak's ownership of its MCP registration was keyed by
/// host only. After `CLAUDE_CONFIG_DIR` moved, uninstall took an equal
/// entry the person registered in the new directory's `.claude.json` for
/// EnvCloak's, removed it, and left the one EnvCloak registered. Now a
/// registration is EnvCloak's in the file it was made in only: uninstall
/// leaves the person's, and takes EnvCloak's out of its own file, with
/// Claude Code's command pointed back at it.
///
/// Mutation checked: `unregister_claude_mcp` reading and changing the
/// file `CLAUDE_CONFIG_DIR` names now (`ctx.locations.claude_json()`, the
/// previous reading) instead of the registration's: the person's entry is
/// removed, EnvCloak's stays, and this fails.
#[test]
fn a_registration_is_envcloaks_in_its_own_file_only() {
    let f = Fixture::new();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let entry = f.json(".claude.json")["mcpServers"]["envcloak"].clone();
    assert!(entry.is_object(), "{entry}");
    let alt = f.path("alt-claude");
    std::fs::create_dir(&alt).unwrap();
    let env = [("CLAUDE_CONFIG_DIR", alt.as_path())];
    let out = f.host_with(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "envcloak",
            &entry.to_string(),
        ],
        &env,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let theirs = std::fs::read(alt.join(".claude.json")).unwrap();
    // The listing names the file EnvCloak registered in.
    let out = f.agents_with(
        &f.home.home(),
        &["uninstall", "--agent", "claude-code", "--json"],
        &env,
    );
    let listed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(listed["mcp_servers"], json!(["~/.claude.json"]), "{listed}");
    let (u, code) = f.report_with(&["uninstall", "--agent", "claude-code", "--yes"], &env);
    assert!(
        std::fs::read(alt.join(".claude.json")).unwrap() == theirs,
        "the person's entry was taken for EnvCloak's: {u}"
    );
    assert!(
        f.json(".claude.json")["mcpServers"]
            .get("envcloak")
            .is_none(),
        "EnvCloak's own entry was left: {u}"
    );
    assert_eq!(code, 0, "{u}");
    f.sweep();
}

/// Codex review: in a fresh home `claude mcp add-json` creates
/// `~/.claude.json`, and uninstall took the entry out and left the file.
/// The registration records that it created the file, and what it left:
/// uninstall removes a file still exactly so; one Claude Code wrote its
/// own state into since stays, with only EnvCloak's entry taken out.
///
/// Mutation checked: the file's creation not recorded (`created` always
/// `None` in `try_register`): uninstall leaves `~/.claude.json` and this
/// fails.
#[test]
fn a_claude_json_the_install_created_is_removed_by_uninstall() {
    let f = Fixture::new();
    std::fs::remove_file(f.path(".claude.json")).unwrap();
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(outcome_of(&v, "~/.claude.json").0, "created", "{v}");
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(outcome_of(&u, "~/.claude.json").0, "removed", "{u}");
    assert!(!f.path(".claude.json").exists());
    // Again, and Claude Code writes its own state into it in between.
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let mut state = f.json(".claude.json");
    state["numStartups"] = json!(1);
    std::fs::write(f.path(".claude.json"), state.to_string()).unwrap();
    age(&f.path(".claude.json"), OLD);
    let (u, code) = f.report(&["uninstall", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{u}");
    let left = f.json(".claude.json");
    assert_eq!(left["numStartups"], 1, "{left}");
    assert!(left["mcpServers"].get("envcloak").is_none(), "{left}");
    f.sweep();
}

/// The class of Codex's low finding (what an install created, left after
/// uninstall): in a home with no `~/.codex`, install makes it and
/// `~/.codex/rules`, and creates every file there; uninstall removes the
/// files and then the directories it made, once empty. A directory it
/// made that holds a file of the person's by then stays.
///
/// Mutation checked: the directories `make_dirs` made not recorded (the
/// previous `open_target` making them unrecorded): `~/.codex` is left and
/// this fails.
#[test]
fn the_directories_an_install_made_go_with_it() {
    let f = Fixture::new();
    std::fs::remove_dir_all(f.path(".codex")).unwrap();
    let (v, code) = f.report(&["install", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert!(f.path(".codex/rules/envcloak.rules").exists());
    let (u, code) = f.report(&["uninstall", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert!(!f.path(".codex").exists(), "{u}");
    // Again, with a file of the person's in a directory install made.
    let (v, code) = f.report(&["install", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{v}");
    std::fs::write(f.path(".codex/rules/mine.rules"), b"# mine\n").unwrap();
    let (u, code) = f.report(&["uninstall", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.read(".codex/rules/mine.rules"), b"# mine\n");
    assert!(!f.path(".codex/rules/envcloak.rules").exists());
    f.sweep();
}

/// An MCP server named `envcloak` the person registered themselves, with
/// EnvCloak's very settings, stays theirs: install changes nothing and
/// says so, and uninstall leaves it (Codex review: "removes exactly what
/// was added").
///
/// Mutation checked: the entry claimed when it is equal (the previous
/// `w.state.mcp.insert` before `Outcome::Unchanged`): uninstall removes
/// the person's entry and this fails.
#[test]
fn a_server_the_person_registered_stays_theirs() {
    let f = Fixture::new();
    let entry = json!({
        "command": envcloak_path(),
        "args": ["mcp", "--host", "claude-code"],
        "timeout": 60000,
    });
    let out = f.host(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "envcloak",
            &entry.to_string(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    age(&f.path(".claude.json"), OLD);
    let (v, code) = f.report(&["install", "--agent", "claude-code", "--yes"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(outcome_of(&v, "~/.claude.json").0, "unchanged", "{v}");
    assert!(
        notes(&v, "claude-code").contains(&"mcp_server_yours".to_owned()),
        "{v}"
    );
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    assert_eq!(f.json(".claude.json")["mcpServers"]["envcloak"], entry);
    f.sweep();
}

/// A file that is EnvCloak's whole (Codex's rules) is removed by
/// uninstall, and replaced by install, only while it is exactly what
/// EnvCloak wrote: one the person changed is left and reported (Codex
/// review: uninstall deleted the person's rules).
///
/// Mutations checked: `install::structural` answering `Undo::Remove` for a
/// whole file whatever it holds (the previous code): uninstall deletes the
/// person's rules and this fails. `OwnFile` overwritten whenever EnvCloak
/// has a record of it (the previous `known`): the second install replaces
/// the person's rules and this fails.
#[test]
fn a_rules_file_changed_since_is_left_and_reported() {
    let f = Fixture::new();
    let (v, code) = f.report(&["install", "--agent", "codex", "--yes"]);
    assert_eq!(code, 0, "{v}");
    let mine = format!("{RULES}# mine\n");
    std::fs::write(f.path(".codex/rules/envcloak.rules"), &mine).unwrap();
    // Older than 2 minutes: only the check of its contents keeps it.
    age(&f.path(".codex/rules/envcloak.rules"), OLD);
    let (v, code) = f.report(&["install", "--agent", "codex", "--yes"]);
    assert_eq!(code, 1, "{v}");
    let (outcome, reason, _) = outcome_of(&v, "~/.codex/rules/envcloak.rules");
    assert_eq!(
        (outcome.as_str(), reason),
        ("refused", json!("modified")),
        "{v}"
    );
    assert_eq!(f.text(".codex/rules/envcloak.rules"), mine);
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 1, "{u}");
    let (outcome, reason, _) = outcome_of(&u, "~/.codex/rules/envcloak.rules");
    assert_eq!(
        (outcome.as_str(), reason),
        ("refused", json!("modified")),
        "{u}"
    );
    assert_eq!(f.text(".codex/rules/envcloak.rules"), mine);
    // The rest was taken out.
    assert_eq!(f.text(".codex/config.toml"), config_toml());
    assert!(!f.path(".codex/hooks.json").exists());
    f.sweep();
}

/// The hooks and the MCP entries name EnvCloak by its link on `PATH`
/// (a package manager's, which an upgrade keeps), not by the versioned
/// file it points to, whose path an upgrade removes (a hook whose command
/// is gone fails open on both hosts).
///
/// Mutation checked: `install::stable_exe` not called in `context` (the
/// previous `current_exe().canonicalize()`): the hooks name the built
/// binary's own path and this fails.
#[test]
fn the_hooks_name_envcloak_by_its_link_on_path() {
    let f = Fixture::new();
    let link = f.home.root().join("linked");
    std::fs::create_dir(&link).unwrap();
    std::os::unix::fs::symlink(cli(), link.join("envcloak")).unwrap();
    let mut cmd = cli_command(
        &f.home,
        &["agents", "install", "--agent", "codex", "--yes"],
        &[],
    );
    cmd.env(
        "PATH",
        format!("{}:{}:{TEST_PATH}", link.display(), f.bin.display()),
    );
    let out = finish_within(cmd, Duration::from_secs(120));
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    let hooks = f.text(".codex/hooks.json");
    let want = format!("{} hook --host codex", link.join("envcloak").display());
    assert!(hooks.contains(&want), "{hooks}");
    assert!(!hooks.contains(&envcloak_path()), "{hooks}");
    let (u, code) = f.report(&["uninstall", "--yes"]);
    assert_eq!(code, 0, "{u}");
    f.sweep();
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

/// The Codex review: `agents install` and `uninstall` read the agents'
/// configs, which can hold literal keys, with no tracer check (SPEC §5).
/// Traced from their first instruction, each exits 1 with `traced` before
/// it reads one: no plan and no report is printed, and nothing changes.
/// The control, untraced, prints the plan, which reading the configs
/// makes (`~/.claude/settings.json` is read for the plugin), so only the
/// order of the check refuses the traced runs.
///
/// Mutation checked: the `refuse_if_traced` check taken out of
/// `cmd/agents.rs`: the traced install prints its plan and this fails.
#[cfg(target_os = "linux")]
#[test]
fn linux_traced_agents_commands_read_no_config() {
    use envcloak_sys::testing::spawn_traced;

    let f = Fixture::new();
    std::fs::write(
        f.path(".claude/settings.json"),
        format!(
            "{{\"env\": {{\"OPENAI_API_KEY\": \"{}\"}}}}\n",
            by_label(&f.cs, labels::OPENAI_API_KEY).as_str()
        ),
    )
    .unwrap();
    let before: Vec<Vec<u8>> = FILES.iter().map(|p| f.read(p)).collect();
    let agents = |args: &[&str], traced: bool| -> Output {
        let mut cmd = Command::new(cli());
        f.home
            .apply(&mut cmd)
            .arg("agents")
            .args(args)
            .env("PATH", format!("{}:{TEST_PATH}", f.bin.display()))
            .current_dir(f.home.home())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = if traced {
            spawn_traced(&mut cmd).unwrap()
        } else {
            cmd.spawn().unwrap()
        };
        let out = child.wait_with_output().unwrap();
        assert_no_canary(&out.stdout, &f.cs);
        assert_no_canary(&out.stderr, &f.cs);
        out
    };
    for args in [
        &["install"][..],
        &["install", "--yes"],
        &["uninstall"],
        &["uninstall", "--yes"],
    ] {
        let out = agents(args, true);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).starts_with("envcloak: traced:"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(out.stdout.is_empty(), "{args:?}: {}", stdout(&out));
    }
    let now: Vec<Vec<u8>> = FILES.iter().map(|p| f.read(p)).collect();
    assert_eq!(now, before);
    // The control: untraced, the plan is printed.
    let out = agents(&["install"], false);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("settings.json"), "{}", stdout(&out));
    f.sweep();
}
