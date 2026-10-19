//! Integration tests for Tier-2 and Tier-3 agent host installers, hook payload
//! contracts, product detection, and coverage reporting (M2 plan task M2-24;
//! SPEC §7, §7.1, §7.2, §15.2 Gate 38).
//!
//! Mutations checked:
//! 1. Report Copilot's prompt guard as `active`: `coverage_states_and_reasons_for_tier_2_and_tier_3_hosts` fails.
//! 2. Write `GEMINI.md` regardless of `context.fileName`: `gemini_never_writes_gemini_md_when_context_file_name_names_agents_md` fails.
//! 3. Write both Kimi products' files: `kimi_cli_and_kimi_code_are_told_apart_and_only_detected_product_is_written` fails.
//! 4. Claim `active` for an unprobed host: `coverage_states_and_reasons_for_tier_2_and_tier_3_hosts` fails.
//! 5. Report a not-drivable host without `not_drivable`: `coverage_states_and_reasons_for_tier_2_and_tier_3_hosts` fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_agents::coverage::{
    self, Case, ConfigSet, HookState, Observed, Outcome as ProbeOutcome, ProbeRecord, Probed,
    Reason, Sentinel, ServerObserved, State as CovState, Surface,
};
use envcloak_agents::hook::{self, Decision, Event, Host, Reason as HookReason};
use envcloak_agents::hosts::{kimi, opencode};
use envcloak_agents::install::{self, Context, Options, Report};
use envcloak_agents::locations::Locations;
use envcloak_agents::writer::{Backups, Journal, Outcome, Refusal, State, Writer};
use envcloak_core::secret::SecretBuf;
use serde_json::{Value, json};

#[derive(Default)]
struct Kept;

impl Journal for Kept {
    fn save(&mut self, _: &State) -> Result<(), Refusal> {
        Ok(())
    }
}

impl Backups for Kept {
    fn back_up(&mut self, _: &Path, _: &[u8], _: u32) -> Result<String, Refusal> {
        Ok("synthetic-backup".to_owned())
    }
    fn record(&mut self, _: &str, _: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }
}

struct Fx {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    state: State,
    vars: BTreeMap<String, OsString>,
}

impl Fx {
    fn new() -> Fx {
        let dir = tempfile::Builder::new()
            .prefix("ect2")
            .tempdir_in("/tmp")
            .unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let bin = root.join("bin");
        let proj = root.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(proj.join(".git")).unwrap();
        let envcloak_exe = root.join("envcloak");
        std::fs::write(&envcloak_exe, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&envcloak_exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut vars = BTreeMap::new();
        vars.insert("HOME".to_owned(), home.into_os_string());
        Fx {
            _dir: dir,
            root,
            bin,
            state: State::default(),
            vars,
        }
    }

    fn home(&self) -> PathBuf {
        PathBuf::from(self.vars.get("HOME").unwrap())
    }

    fn proj(&self) -> PathBuf {
        self.root.join("proj")
    }

    fn write_home(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.home().join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, bytes).unwrap();
        age(&p);
        p
    }

    fn write_proj(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.proj().join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, bytes).unwrap();
        age(&p);
        p
    }

    fn add_fake_exe(&self, name: &str, script_body: &str) -> PathBuf {
        let p = self.bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{script_body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn add_all_tier2_and_tier3_exes(&self, kimi_product: kimi::KimiProduct) {
        self.add_fake_exe("cursor-agent", "echo 2026.09.28-64d2043");
        self.add_fake_exe("gemini", "echo 0.62.0");
        self.add_fake_exe("copilot", "echo 'GitHub Copilot CLI 1.0.90.'");
        self.add_fake_exe("opencode", "echo 1.18.34");
        match kimi_product {
            kimi::KimiProduct::Code => {
                self.add_fake_exe("kimi", "# kimi-code wrapper\necho 'kimi-code 2.1.1'");
            }
            kimi::KimiProduct::Cli => {
                self.add_fake_exe("kimi", "# kimi-cli wrapper\necho 'kimi, version 1.36.0'");
            }
        }
        self.add_fake_exe("qwen", "echo 0.24.7");
        self.add_fake_exe("goose", "echo 'goose 1.29.1'");
        self.add_fake_exe("aider", "echo 'aider 0.86.2'");
    }

    fn run(&mut self, hosts: &[Host], global: bool, project: bool, uninstall: bool) -> Report {
        let root = self.root.clone();
        let bin = self.bin.clone();
        let proj = self.proj();
        let vars = self.vars.clone();
        let env = move |k: &str| vars.get(k).cloned();
        let ctx = Context {
            locations: Locations::new(&env)
                .unwrap()
                .with_system_dirs(root.join("etc-codex"), root.join("prefs")),
            envcloak: root.join("envcloak"),
            data_dir: root.join("data"),
            socket: root.join("socket"),
            path: bin.into_os_string(),
            env: &env,
        };
        let opts = Options {
            hosts: hosts.to_vec(),
            global,
            project: project.then_some(proj),
            consent_sockets: false,
        };
        let (mut journal, mut backups) = (Kept, Kept);
        let mut w = Writer {
            state: &mut self.state,
            journal: &mut journal,
            backups: &mut backups,
            now: SystemTime::now(),
        };
        if uninstall {
            install::uninstall(&opts, &mut w)
        } else {
            let plan = install::plan(&ctx, &opts);
            install::apply(&ctx, &plan, &mut w)
        }
    }
}

fn age(p: &Path) {
    let f = std::fs::File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(600))
        .unwrap();
}

#[test]
fn install_and_uninstall_round_trip_for_all_tier_2_and_tier_3_hosts() {
    let mut fx = Fx::new();
    fx.add_all_tier2_and_tier3_exes(kimi::KimiProduct::Code);

    // Pre-populate user configs for each host so we verify byte-for-byte restoration
    // alongside removal of newly created files.
    let pre_existing: Vec<(&str, &[u8])> = vec![
        (
            ".cursor/hooks.json",
            b"{\n  \"version\": 1,\n  \"hooks\": {\n    \"afterFileEdit\": [\n      {\n        \"command\": \"/usr/bin/true\"\n      }\n    ]\n  }\n}\n",
        ),
        (
            ".cursor/mcp.json",
            b"{\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"npx\"\n    }\n  }\n}\n",
        ),
        (
            ".gemini/settings.json",
            b"{\n  \"theme\": \"Dark\",\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"node\"\n    }\n  }\n}\n",
        ),
        (
            ".gemini/GEMINI.md",
            b"# User Gemini Instructions\n\nKeep answers concise.\n",
        ),
        (
            ".copilot/mcp-config.json",
            b"{\n  \"mcpServers\": {\n    \"github\": {\n      \"command\": \"gh\"\n    }\n  }\n}\n",
        ),
        (
            ".config/opencode/opencode.json",
            b"{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"model\": \"anthropic/sonnet\"\n}\n",
        ),
        (
            ".kimi-code/config.toml",
            b"default_model = \"kimi-for-coding\"\n\n[[hooks]]\nevent = \"PostToolUse\"\ncommand = \"/usr/bin/true\"\n",
        ),
        (
            ".kimi-code/mcp.json",
            b"{\n  \"mcpServers\": {\n    \"existing\": {\n      \"command\": \"uvx\"\n    }\n  }\n}\n",
        ),
        (
            ".qwen/settings.json",
            b"{\n  \"general\": {\n    \"vimMode\": true\n  }\n}\n",
        ),
        (
            ".config/goose/config.yaml",
            b"GOOSE_PROVIDER: openai\nextensions:\n  developer:\n    enabled: true\n",
        ),
        (
            ".config/goose/.goosehints",
            b"Always run tests before committing.\n",
        ),
        (
            ".aider.conf.yml",
            b"model: sonnet\nauto-commits: false\n",
        ),
    ];

    for (rel, content) in &pre_existing {
        fx.write_home(rel, content);
    }
    let proj_agents = b"# Project instructions\n";
    fx.write_proj("AGENTS.md", proj_agents);

    let tier2_and_3 = [
        Host::Cursor,
        Host::Gemini,
        Host::Copilot,
        Host::OpenCode,
        Host::Kimi,
        Host::Qwen,
        Host::Goose,
        Host::Aider,
    ];

    // 1. Install globally and in project for all Tier-2 and Tier-3 hosts.
    let r = fx.run(&tier2_and_3, true, true, false);
    assert!(r.complete(), "{r:?}");

    // Verify Cursor files:
    let cursor_hooks: Value =
        serde_json::from_slice(&std::fs::read(fx.home().join(".cursor/hooks.json")).unwrap())
            .unwrap();
    assert_eq!(cursor_hooks["version"], 1);
    for ev in [
        "beforeSubmitPrompt",
        "beforeShellExecution",
        "beforeReadFile",
        "beforeMCPExecution",
        "preToolUse",
        "sessionStart",
    ] {
        assert!(
            cursor_hooks["hooks"][ev].is_array(),
            "missing Cursor event {ev}: {cursor_hooks}"
        );
    }
    let cursor_mcp: Value =
        serde_json::from_slice(&std::fs::read(fx.home().join(".cursor/mcp.json")).unwrap())
            .unwrap();
    assert!(cursor_mcp["mcpServers"]["envcloak"].is_object());
    assert!(cursor_mcp["mcpServers"]["other"].is_object());
    assert!(fx.proj().join(".cursor/rules/envcloak.mdc").exists());

    // Verify Gemini files:
    let gemini_settings: Value =
        serde_json::from_slice(&std::fs::read(fx.home().join(".gemini/settings.json")).unwrap())
            .unwrap();
    for ev in ["BeforeAgent", "BeforeTool", "SessionStart"] {
        assert!(gemini_settings["hooks"][ev].is_array(), "{gemini_settings}");
    }
    assert_eq!(
        gemini_settings["mcpServers"]["envcloak"]["timeout"],
        json!(60000)
    );
    assert!(
        gemini_settings["mcpServers"]["envcloak"]
            .get("trust")
            .is_none(),
        "Gemini MCP entry must never set trust: true"
    );
    assert!(
        std::fs::read_to_string(fx.home().join(".gemini/GEMINI.md"))
            .unwrap()
            .contains("envcloak:begin")
    );

    // Verify Copilot files:
    assert!(
        fx.home()
            .join(".copilot/instructions/envcloak.instructions.md")
            .exists()
    );
    let copilot_hooks: Value = serde_json::from_slice(
        &std::fs::read(fx.home().join(".copilot/hooks/envcloak.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(copilot_hooks["version"], 1);
    assert!(copilot_hooks["hooks"]["preToolUse"].is_array());
    assert!(copilot_hooks["hooks"]["sessionStart"].is_array());
    let copilot_mcp: Value =
        serde_json::from_slice(&std::fs::read(fx.home().join(".copilot/mcp-config.json")).unwrap())
            .unwrap();
    assert_eq!(copilot_mcp["mcpServers"]["envcloak"]["type"], "local");
    assert_eq!(copilot_mcp["mcpServers"]["envcloak"]["tools"], json!(["*"]));

    // Verify OpenCode files:
    assert!(
        std::fs::read_to_string(fx.home().join(".config/opencode/AGENTS.md"))
            .unwrap()
            .contains("envcloak:begin")
    );
    let oc_plugin =
        std::fs::read_to_string(fx.home().join(".config/opencode/plugins/envcloak.js")).unwrap();
    assert!(oc_plugin.contains(opencode::PLUGIN_MARKER));
    let oc_json: Value = serde_json::from_slice(
        &std::fs::read(fx.home().join(".config/opencode/opencode.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(oc_json["mcp"]["envcloak"]["type"], "local");

    // Verify Kimi Code files:
    assert!(
        std::fs::read_to_string(fx.home().join(".kimi-code/AGENTS.md"))
            .unwrap()
            .contains("envcloak:begin")
    );
    let kimi_toml = std::fs::read_to_string(fx.home().join(".kimi-code/config.toml")).unwrap();
    assert!(kimi_toml.contains("hook --host kimi --event PreToolUse"));
    assert!(!fx.home().join(".kimi").exists());

    // Verify Qwen files:
    assert!(
        std::fs::read_to_string(fx.home().join(".qwen/QWEN.md"))
            .unwrap()
            .contains("envcloak:begin")
    );
    let qwen_settings: Value =
        serde_json::from_slice(&std::fs::read(fx.home().join(".qwen/settings.json")).unwrap())
            .unwrap();
    for ev in ["UserPromptSubmit", "PreToolUse", "SessionStart"] {
        assert!(qwen_settings["hooks"][ev].is_array(), "{qwen_settings}");
    }
    assert_eq!(
        qwen_settings["mcpServers"]["envcloak"]["timeout"],
        json!(60000)
    );

    // Verify Goose files (and that config.yaml was NOT modified):
    assert!(
        std::fs::read_to_string(fx.home().join(".config/goose/.goosehints"))
            .unwrap()
            .contains("envcloak:begin")
    );
    assert!(
        fx.home()
            .join(".agents/plugins/envcloak/hooks/hooks.json")
            .exists()
    );
    assert_eq!(
        std::fs::read(fx.home().join(".config/goose/config.yaml")).unwrap(),
        b"GOOSE_PROVIDER: openai\nextensions:\n  developer:\n    enabled: true\n"
    );

    // Verify Aider files:
    assert!(
        std::fs::read_to_string(fx.home().join(".agents/AGENTS.md"))
            .unwrap()
            .contains("envcloak:begin")
    );
    let aider_yml = std::fs::read_to_string(fx.home().join(".aider.conf.yml")).unwrap();
    assert!(aider_yml.contains("# envcloak:begin"));
    assert!(aider_yml.contains(".agents/AGENTS.md"));

    // 2. Second install is completely idempotent (`Outcome::Unchanged` on every step).
    for (rel, _) in &pre_existing {
        age(&fx.home().join(rel));
    }
    let r2 = fx.run(&tier2_and_3, true, true, false);
    assert!(r2.complete(), "{r2:?}");
    for h in &r2.hosts {
        for s in &h.results {
            assert_eq!(
                s.outcome,
                Outcome::Unchanged,
                "expected Unchanged on second install for {:?} {}: {:?}",
                h.host,
                s.path.display(),
                s.outcome
            );
        }
    }

    // 3. Uninstall restores every pre-existing file byte for byte and removes created files.
    let u = fx.run(&tier2_and_3, true, true, true);
    assert!(u.complete(), "{u:?}");
    for (rel, content) in &pre_existing {
        let actual = std::fs::read(fx.home().join(rel)).unwrap();
        assert_eq!(
            actual.as_slice(),
            *content,
            "file {rel} was not restored byte for byte after uninstall"
        );
    }
    assert_eq!(
        std::fs::read(fx.proj().join("AGENTS.md")).unwrap(),
        proj_agents
    );
    for created_rel in [
        ".copilot/instructions/envcloak.instructions.md",
        ".copilot/hooks/envcloak.json",
        ".config/opencode/AGENTS.md",
        ".config/opencode/plugins/envcloak.js",
        ".kimi-code/AGENTS.md",
        ".qwen/QWEN.md",
        ".agents/plugins/envcloak/hooks/hooks.json",
        ".agents/AGENTS.md",
    ] {
        assert!(
            !fx.home().join(created_rel).exists(),
            "created file {created_rel} was not removed on uninstall"
        );
    }
    assert!(!fx.proj().join(".cursor/rules/envcloak.mdc").exists());
    assert!(fx.state.files.is_empty(), "{:?}", fx.state.files);
}

#[test]
fn gemini_never_writes_gemini_md_when_context_file_name_names_agents_md() {
    // String form: `"context": { "fileName": "AGENTS.md" }`
    let mut fx = Fx::new();
    fx.add_fake_exe("gemini", "echo 0.62.0");
    let user_settings = b"{\n  \"context\": {\n    \"fileName\": \"AGENTS.md\"\n  }\n}\n";
    fx.write_home(".gemini/settings.json", user_settings);
    let proj_settings =
        b"{\n  \"context\": {\n    \"fileName\": [\"AGENTS.md\", \"GEMINI.md\"]\n  }\n}\n";
    fx.write_proj(".gemini/settings.json", proj_settings);
    // Even if `<proj>/GEMINI.md` exists on disk, `context.fileName`'s first entry (`AGENTS.md`) wins.
    let pre_proj_gemini = b"# Untouched project GEMINI.md\n";
    fx.write_proj("GEMINI.md", pre_proj_gemini);

    let r = fx.run(&[Host::Gemini], true, true, false);
    assert!(r.complete(), "{r:?}");
    assert!(
        !fx.home().join(".gemini/GEMINI.md").exists(),
        "global GEMINI.md must never be written when context.fileName is AGENTS.md"
    );
    assert!(
        std::fs::read_to_string(fx.home().join(".gemini/AGENTS.md"))
            .unwrap()
            .contains("envcloak:begin")
    );
    assert_eq!(
        std::fs::read(fx.proj().join("GEMINI.md")).unwrap(),
        pre_proj_gemini,
        "project GEMINI.md must not be touched when context.fileName selects AGENTS.md"
    );
    assert!(
        std::fs::read_to_string(fx.proj().join("AGENTS.md"))
            .unwrap()
            .contains("envcloak:begin")
    );

    let u = fx.run(&[Host::Gemini], true, true, true);
    assert!(u.complete(), "{u:?}");
    assert!(!fx.home().join(".gemini/AGENTS.md").exists());
    assert!(!fx.home().join(".gemini/GEMINI.md").exists());
    assert!(!fx.proj().join("AGENTS.md").exists());
    assert_eq!(
        std::fs::read(fx.proj().join("GEMINI.md")).unwrap(),
        pre_proj_gemini
    );

    // Recheck at write time: if settings.json changes context.fileName between plan and apply,
    // apply refuses with `instruction_file_moved`.
    let root = fx.root.clone();
    let bin = fx.bin.clone();
    let vars = fx.vars.clone();
    let env = move |k: &str| vars.get(k).cloned();
    let ctx = Context {
        locations: Locations::new(&env)
            .unwrap()
            .with_system_dirs(root.join("etc-codex"), root.join("prefs")),
        envcloak: root.join("envcloak"),
        data_dir: root.join("data"),
        socket: root.join("socket"),
        path: bin.into_os_string(),
        env: &env,
    };
    let opts = Options {
        hosts: vec![Host::Gemini],
        global: true,
        project: None,
        consent_sockets: false,
    };
    let plan = install::plan(&ctx, &opts);
    // Now change settings.json before apply so context.fileName points to CUSTOM.md.
    fx.write_home(
        ".gemini/settings.json",
        b"{\n  \"context\": {\n    \"fileName\": \"CUSTOM.md\"\n  }\n}\n",
    );
    let (mut journal, mut backups) = (Kept, Kept);
    let mut w = Writer {
        state: &mut fx.state,
        journal: &mut journal,
        backups: &mut backups,
        now: SystemTime::now(),
    };
    let report = install::apply(&ctx, &plan, &mut w);
    assert!(!report.complete(), "{report:?}");
    let inst_step = &report.hosts[0].results[0];
    assert!(
        matches!(&inst_step.outcome, Outcome::Refused(r) if r.name == "instruction_file_moved"),
        "{inst_step:?}"
    );
    assert!(!fx.home().join(".gemini/AGENTS.md").exists());
}

#[test]
fn opencode_claude_fallback_skips_global_agents_md_and_plugin_guards_unmanaged_file() {
    let mut fx = Fx::new();
    fx.add_fake_exe("opencode", "echo 1.18.34");
    fx.write_home(".claude/CLAUDE.md", b"# Claude instructions\n");

    let r = fx.run(&[Host::OpenCode], true, false, false);
    assert!(r.complete(), "{r:?}");
    assert!(
        !fx.home().join(".config/opencode/AGENTS.md").exists(),
        "OpenCode install must not create global AGENTS.md when ~/.claude/CLAUDE.md fallback is active"
    );
    assert!(
        r.hosts[0]
            .notes
            .iter()
            .any(|n| n.name == "opencode_reads_claude_md"),
        "{:?}",
        r.hosts[0].notes
    );
    assert!(
        fx.home()
            .join(".config/opencode/plugins/envcloak.js")
            .exists()
    );

    let u = fx.run(&[Host::OpenCode], true, false, true);
    assert!(u.complete(), "{u:?}");

    // With OPENCODE_DISABLE_CLAUDE_CODE=1, OpenCode does not fall back to ~/.claude/CLAUDE.md,
    // so ~/.config/opencode/AGENTS.md IS created.
    fx.vars
        .insert("OPENCODE_DISABLE_CLAUDE_CODE".to_owned(), "1".into());
    let r = fx.run(&[Host::OpenCode], true, false, false);
    assert!(r.complete(), "{r:?}");
    assert!(
        fx.home().join(".config/opencode/AGENTS.md").exists(),
        "OpenCode install must create global AGENTS.md when OPENCODE_DISABLE_CLAUDE_CODE=1"
    );
    let u = fx.run(&[Host::OpenCode], true, false, true);
    assert!(u.complete(), "{u:?}");

    // 1. Pre-existing unmanaged plugins/envcloak.js is refused with `conflict`.
    let custom_js = b"// user's own plugin\nexport const Custom = async () => ({});\n";
    fx.write_home(".config/opencode/plugins/envcloak.js", custom_js);
    let r = fx.run(&[Host::OpenCode], true, false, false);
    assert!(!r.complete(), "{r:?}");
    let plugin_step = r.hosts[0]
        .results
        .iter()
        .find(|s| s.path.ends_with("envcloak.js"))
        .unwrap();
    assert!(
        matches!(&plugin_step.outcome, Outcome::Refused(refusal) if refusal.name == "conflict"),
        "{plugin_step:?}"
    );
    assert_eq!(
        std::fs::read(fx.home().join(".config/opencode/plugins/envcloak.js")).unwrap(),
        custom_js
    );

    // 2. Installed plugins/envcloak.js that the user later edits is refused with `modified`.
    std::fs::remove_file(fx.home().join(".config/opencode/plugins/envcloak.js")).unwrap();
    let r = fx.run(&[Host::OpenCode], true, false, false);
    assert!(r.complete(), "{r:?}");
    fx.write_home(".config/opencode/plugins/envcloak.js", custom_js);
    let u = fx.run(&[Host::OpenCode], true, false, true);
    assert!(!u.complete(), "{u:?}");
    let plugin_step = u.hosts[0]
        .results
        .iter()
        .find(|s| s.path.ends_with("envcloak.js"))
        .unwrap();
    assert!(
        matches!(&plugin_step.outcome, Outcome::Refused(refusal) if refusal.name == "modified"),
        "{plugin_step:?}"
    );
    assert_eq!(
        std::fs::read(fx.home().join(".config/opencode/plugins/envcloak.js")).unwrap(),
        custom_js
    );
}

#[test]
fn kimi_cli_and_kimi_code_are_told_apart_and_only_detected_product_is_written() {
    // 1. Kimi Code (`~/.kimi-code` only; `~/.kimi` must remain untouched).
    let mut fx_code = Fx::new();
    fx_code.add_all_tier2_and_tier3_exes(kimi::KimiProduct::Code);
    let r = fx_code.run(&[Host::Kimi], true, false, false);
    assert!(r.complete(), "{r:?}");
    assert!(
        r.hosts[0]
            .notes
            .iter()
            .any(|n| n.name == "kimi_product_code"),
        "{:?}",
        r.hosts[0].notes
    );
    assert!(fx_code.home().join(".kimi-code/AGENTS.md").exists());
    assert!(fx_code.home().join(".kimi-code/config.toml").exists());
    assert!(fx_code.home().join(".kimi-code/mcp.json").exists());
    assert!(
        !fx_code.home().join(".kimi").exists(),
        "Kimi Code install must never touch ~/.kimi"
    );
    let u = fx_code.run(&[Host::Kimi], true, false, true);
    assert!(u.complete(), "{u:?}");
    assert!(!fx_code.home().join(".kimi-code").exists());

    // 2. Kimi CLI (`~/.kimi` only; `~/.kimi-code` must remain untouched).
    let mut fx_cli = Fx::new();
    fx_cli.add_all_tier2_and_tier3_exes(kimi::KimiProduct::Cli);
    let r = fx_cli.run(&[Host::Kimi], true, false, false);
    assert!(r.complete(), "{r:?}");
    assert!(
        r.hosts[0]
            .notes
            .iter()
            .any(|n| n.name == "kimi_product_cli"),
        "{:?}",
        r.hosts[0].notes
    );
    assert!(fx_cli.home().join(".kimi/config.toml").exists());
    assert!(fx_cli.home().join(".kimi/mcp.json").exists());
    assert!(
        !fx_cli.home().join(".kimi-code").exists(),
        "Kimi CLI install must never touch ~/.kimi-code"
    );
    let u = fx_cli.run(&[Host::Kimi], true, false, true);
    assert!(u.complete(), "{u:?}");
    assert!(!fx_cli.home().join(".kimi").exists());
}

#[test]
fn payload_contracts_for_tier_2_hosts_and_third_party_import() {
    let secret_str = "sk-proj-synthetic-secret-value-9988776655443322";
    let sb = |v: &Value| {
        let bytes = serde_json::to_vec(v).unwrap();
        let mut b = SecretBuf::with_capacity(bytes.len());
        b.extend(&bytes).unwrap();
        b
    };

    // --- Cursor ---
    // 1. Third-party Claude Code hook import into Cursor: ignored (`NoDecision`).
    let claude_in_cursor = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "env" }
    });
    assert_eq!(
        hook::decide(Host::Cursor, Event::PreToolUseLower, &sb(&claude_in_cursor)),
        Decision::NoDecision
    );
    // 2. Cursor `beforeReadFile`: decides ONLY on `file_path` and never inspects `content`.
    let cursor_read_readme_with_secret_content = json!({
        "conversation_id": "c-1",
        "hook_event_name": "beforeReadFile",
        "file_path": "/workspace/README.md",
        "content": format!("file body holding {secret_str}")
    });
    assert_eq!(
        hook::decide(
            Host::Cursor,
            Event::BeforeReadFile,
            &sb(&cursor_read_readme_with_secret_content),
        ),
        Decision::Allow,
        "Cursor beforeReadFile must decide on path only and never inspect content"
    );
    let cursor_read_env = json!({
        "conversation_id": "c-1",
        "hook_event_name": "beforeReadFile",
        "file_path": "/workspace/.env",
        "content": ""
    });
    let d = hook::decide(Host::Cursor, Event::BeforeReadFile, &sb(&cursor_read_env));
    assert_eq!(d, Decision::Deny(HookReason::EnvFile));
    let ans = hook::answer(Host::Cursor, Event::BeforeReadFile, d);
    assert_eq!(ans.code, hook::BLOCK);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["permission"], "deny");

    // 3. Cursor `beforeShellExecution` denies bare `env` with flat `permission: "deny"`.
    let cursor_shell = json!({
        "hook_event_name": "beforeShellExecution",
        "command": "env"
    });
    let d = hook::decide(
        Host::Cursor,
        Event::BeforeShellExecution,
        &sb(&cursor_shell),
    );
    assert_eq!(d, Decision::Deny(HookReason::EnvDump));
    let ans = hook::answer(Host::Cursor, Event::BeforeShellExecution, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["permission"], "deny");
    assert!(v.get("hookSpecificOutput").is_none());

    // 4. Cursor `sessionStart` context uses `additional_context`.
    let cursor_ctx: Value = serde_json::from_slice(&hook::session_context(
        Host::Cursor,
        &["OPENAI_API_KEY".to_owned()],
    ))
    .unwrap();
    assert!(
        cursor_ctx["additional_context"]
            .as_str()
            .unwrap()
            .contains("OPENAI_API_KEY")
    );

    // --- Copilot CLI ---
    // 1. camelCase + stringified `toolArgs` (`bash`, `write_bash`, `powershell`, `write_powershell`, `view`).
    for (tool, args_str) in [
        ("bash", "{\"command\":\"printenv\"}"),
        ("write_bash", "{\"input\":\"env\\n\"}"),
        ("powershell", "{\"command\":\"Get-ChildItem Env:\"}"),
        ("write_powershell", "{\"input\":\"gci env:\\n\"}"),
        ("view", "{\"path\":\".env\"}"),
    ] {
        let payload = json!({
            "toolName": tool,
            "toolArgs": args_str
        });
        let d = hook::decide(Host::Copilot, Event::PreToolUseLower, &sb(&payload));
        let ans = hook::answer(Host::Copilot, Event::PreToolUseLower, d);
        let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
        assert_eq!(
            v["permissionDecision"], "deny",
            "Copilot {tool} should be denied: {v}"
        );
    }
    // 2. snake_case + object `tool_args`.
    let copilot_snake = json!({
        "tool_name": "edit",
        "tool_args": {
            "path": ".env.production",
            "new_str": "KEY=1"
        }
    });
    let d = hook::decide(Host::Copilot, Event::PreToolUseLower, &sb(&copilot_snake));
    let ans = hook::answer(Host::Copilot, Event::PreToolUseLower, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["permissionDecision"], "deny");
    // 3. Copilot `userPromptSubmitted` has no rejection contract -> `NoDecision`.
    assert_eq!(
        hook::decide(
            Host::Copilot,
            Event::UserPromptSubmit,
            &sb(&json!({"prompt": secret_str})),
        ),
        Decision::NoDecision
    );

    // --- Gemini CLI ---
    let gemini_prompt = json!({
        "hook_event_name": "BeforeAgent",
        "prompt": format!("use {secret_str}")
    });
    let d = hook::decide(Host::Gemini, Event::BeforeAgent, &sb(&gemini_prompt));
    assert_eq!(d, Decision::Deny(HookReason::KeyInPrompt));
    let ans = hook::answer(Host::Gemini, Event::BeforeAgent, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["decision"], "deny");
    let gemini_shell = json!({
        "hook_event_name": "BeforeTool",
        "tool_name": "run_shell_command",
        "tool_input": { "command": "cat .env" }
    });
    let d = hook::decide(Host::Gemini, Event::BeforeTool, &sb(&gemini_shell));
    assert_eq!(d, Decision::Deny(HookReason::EnvFile));

    // --- Kimi ---
    let kimi_shell = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": "cat .env" }
    });
    let d = hook::decide(Host::Kimi, Event::PreToolUse, &sb(&kimi_shell));
    let ans = hook::answer(Host::Kimi, Event::PreToolUse, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");

    // --- OpenCode ---
    let oc_shell = json!({
        "tool": "bash",
        "args": { "command": "printenv" }
    });
    let d = hook::decide(Host::OpenCode, Event::PreToolUse, &sb(&oc_shell));
    let ans = hook::answer(Host::OpenCode, Event::PreToolUse, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["decision"], "deny");

    // --- Qwen Code ---
    let qwen_shell = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "run_shell_command",
        "tool_input": { "command": "printenv" }
    });
    let d = hook::decide(Host::Qwen, Event::PreToolUse, &sb(&qwen_shell));
    let ans = hook::answer(Host::Qwen, Event::PreToolUse, d);
    let v: Value = serde_json::from_slice(&ans.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");

    // --- Goose (doc-derived payload: Goose 1.29.1 does not ship a CLI hook runner) ---
    let goose_doc_derived = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat .env" }
    });
    let d = hook::decide(Host::Goose, Event::PreToolUse, &sb(&goose_doc_derived));
    assert_eq!(d, Decision::Deny(HookReason::EnvFile));
}

#[test]
fn coverage_states_and_reasons_for_tier_2_and_tier_3_hosts() {
    let mut fx = Fx::new();
    fx.add_all_tier2_and_tier3_exes(kimi::KimiProduct::Code);
    let tier2_and_3 = [
        Host::Cursor,
        Host::Gemini,
        Host::Copilot,
        Host::OpenCode,
        Host::Kimi,
        Host::Qwen,
        Host::Goose,
        Host::Aider,
    ];
    let r = fx.run(&tier2_and_3, true, false, false);
    assert!(r.complete(), "{r:?}");

    let vars = fx.vars.clone();
    let env = move |k: &str| vars.get(k).cloned();
    let l = Locations::new(&env)
        .unwrap()
        .with_system_dirs(fx.root.join("etc-codex"), fx.root.join("prefs"));

    // Fake passing probe record to test what happens even if a record exists.
    let all_passed_record = |host: Host| ProbeRecord {
        host: host.id().to_owned(),
        exe_sha256: "deadbeef".to_owned(),
        version: "1.0.0".to_owned(),
        config_digest: "cafebabe".to_owned(),
        os: std::env::consts::OS.to_owned(),
        surfaces: Surface::ALL
            .into_iter()
            .map(|surface| Observed {
                surface,
                outcome: ProbeOutcome::Passed,
                persisted: false,
                why: Vec::new(),
                skipped: Vec::<Case>::new(),
            })
            .collect(),
        server: ServerObserved {
            outcome: ProbeOutcome::Passed,
            sentinel: Sentinel::Appeared,
            control_ran: true,
            allowed_write: true,
            control_denied: true,
        },
        flags: Vec::new(),
    };

    for host in Host::ALL {
        let cs = ConfigSet::read(host, &l, &fx.root.join("managed"), &fx.proj(), &env);

        // Installed Tier-2/3 hosts have their hooks detected as Present on supported surfaces.
        if matches!(host, Host::Cursor | Host::Gemini | Host::Kimi | Host::Qwen) {
            assert_eq!(cs.hooks.prompt, HookState::Present, "{host:?}");
            assert_eq!(cs.hooks.tools, HookState::Present, "{host:?}");
            assert_eq!(cs.hooks.mcp, HookState::Present, "{host:?}");
            assert!(cs.server.registered, "{host:?}");
        } else if matches!(host, Host::Copilot | Host::OpenCode) {
            assert_eq!(cs.hooks.tools, HookState::Present, "{host:?}");
            assert_eq!(cs.hooks.mcp, HookState::Present, "{host:?}");
            assert!(cs.server.registered, "{host:?}");
        } else if host == Host::Goose {
            assert_eq!(cs.hooks.tools, HookState::Present, "{host:?}");
            assert_eq!(cs.hooks.mcp, HookState::Present, "{host:?}");
        }

        // Mutation check 4: An unprobed host (`Probed::None` or `Probed::Stale`) never reads `active`.
        for probed in [Probed::None, Probed::Stale] {
            let cov = coverage::assemble(host, "1.0.0", &cs, probed);
            for s in &cov.surfaces {
                assert_ne!(
                    s.state,
                    CovState::Active,
                    "unprobed host {host:?} surface {:?} must never be Active: {s:?}",
                    s.surface
                );
            }
        }

        // Mutation check 1: Copilot, OpenCode, and Goose PromptToModel and Transcript are
        // ALWAYS Unsupported, even when given a passing ProbeRecord.
        if matches!(host, Host::Copilot | Host::OpenCode | Host::Goose) {
            let rec = all_passed_record(host);
            let cov = coverage::assemble(host, "1.0.0", &cs, Probed::Current(&rec));
            for surf in [Surface::PromptToModel, Surface::Transcript] {
                let st = cov.surfaces.iter().find(|s| s.surface == surf).unwrap();
                assert_eq!(
                    st.state,
                    CovState::Unsupported,
                    "{host:?} {surf:?} must be Unsupported: {st:?}"
                );
            }
        }

        // Mutation check 5: Every non-drivable host (`!is_drivable(host)`: Cursor, Gemini, Goose, Aider)
        // reports `unverified` with `Reason::NotDrivable` (`not_drivable`) on every non-unsupported surface.
        if !coverage::is_drivable(host) {
            let cov = coverage::assemble(host, "1.0.0", &cs, Probed::None);
            for s in &cov.surfaces {
                if s.state != CovState::Unsupported {
                    assert_eq!(
                        s.state,
                        CovState::Unverified,
                        "non-drivable host {host:?} surface {:?} must be Unverified: {s:?}",
                        s.surface
                    );
                    assert!(
                        s.reasons.contains(&Reason::NotDrivable),
                        "non-drivable host {host:?} surface {:?} must carry Reason::NotDrivable: {s:?}",
                        s.surface
                    );
                }
            }
        }
    }
}

#[test]
fn review_round1_regressions_f01_through_f07() {
    let sb = |v: &Value| {
        let bytes = serde_json::to_vec(v).unwrap();
        let mut b = SecretBuf::with_capacity(bytes.len());
        b.extend(&bytes).unwrap();
        b
    };

    // F-04: XDG_CONFIG_HOME redirects OpenCode and Goose config dirs.
    let mut fx = Fx::new();
    let custom_xdg = fx.root.join("custom-xdg");
    fx.vars.insert(
        "XDG_CONFIG_HOME".into(),
        custom_xdg.clone().into_os_string(),
    );
    let vars = fx.vars.clone();
    let env = move |k: &str| vars.get(k).cloned();
    let l = Locations::new(&env).unwrap();
    assert_eq!(l.opencode_config_dir(), custom_xdg.join("opencode"));
    assert_eq!(l.goose_config_dir(), custom_xdg.join("goose"));

    // F-03: Generic `--version` output without product identification is rejected for
    // Kimi, Goose, and Aider, and `named` is false for Cursor/Gemini/Qwen when `--version`
    // prints only a bare version number.
    assert_eq!(
        envcloak_agents::detect::parse_version(Host::Kimi, b"1.2.3\n"),
        None
    );
    assert_eq!(
        envcloak_agents::detect::parse_version(Host::Goose, b"1.2.3\n"),
        None
    );
    assert_eq!(
        envcloak_agents::detect::parse_version(Host::Aider, b"1.2.3\n"),
        None
    );
    let fx_det = Fx::new();
    fx_det.add_fake_exe("cursor-agent", "echo 1.2.3");
    fx_det.add_fake_exe("gemini", "echo 1.2.3");
    fx_det.add_fake_exe("qwen", "echo 1.2.3");
    let vars_det = fx_det.vars.clone();
    let env_det = move |k: &str| vars_det.get(k).cloned();
    for host in [Host::Cursor, Host::Gemini, Host::Qwen] {
        let det = envcloak_agents::detect::detect(host, fx_det.bin.as_os_str(), &env_det).unwrap();
        assert!(
            !det.named,
            "{host:?} with bare version output must have det.named == false"
        );
    }

    // F-02 & F-07: Cursor hook event validation and Grep/Glob/unknown tool fail-closed behavior.
    assert!(Event::PreToolUseLower.valid_for_host(Host::Cursor));
    assert!(Event::SessionStartLower.valid_for_host(Host::Cursor));
    assert!(!Event::PreToolUse.valid_for_host(Host::Cursor));
    assert!(!Event::SessionStart.valid_for_host(Host::Cursor));
    assert_eq!(
        hook::decide(
            Host::Cursor,
            Event::PreToolUse,
            &sb(&json!({"tool_name": "Shell", "tool_input": {"command": "printenv"}}))
        ),
        Decision::NoDecision
    );
    assert_eq!(
        hook::decide(
            Host::Cursor,
            Event::PreToolUseLower,
            &sb(&json!({"tool_name": "Grep", "tool_input": {}}))
        ),
        Decision::NoDecision
    );
    assert_eq!(
        hook::decide(
            Host::Cursor,
            Event::PreToolUseLower,
            &sb(&json!({"tool_name": "CustomTool", "tool_input": {"target": "/workspace/.env"}}))
        ),
        Decision::Deny(HookReason::EnvFile)
    );
    assert_eq!(
        hook::decide(
            Host::Gemini,
            Event::BeforeTool,
            &sb(&json!({"tool_name": "grep_search", "tool_input": {"type": "sh"}}))
        ),
        Decision::Deny(HookReason::EnvFile)
    );
    assert_eq!(
        hook::decide(
            Host::OpenCode,
            Event::PreToolUse,
            &sb(&json!({"tool": "grep", "args": {"type": "all"}}))
        ),
        Decision::Deny(HookReason::EnvFile)
    );

    // F-06: Aider marker validation, path update in place, and refusal on damaged/modified blocks.
    let mut fx_aider = Fx::new();
    fx_aider.add_fake_exe("aider", "echo 'aider 0.86.2'");
    let r = fx_aider.run(&[Host::Aider], true, false, false);
    assert!(r.complete(), "{r:?}");
    let aider_conf = fx_aider.home().join(".aider.conf.yml");
    let body1 = std::fs::read_to_string(&aider_conf).unwrap();
    assert!(body1.contains("AGENTS.md"), "{body1}");

    // When `agents_md` changes, `aider::apply_aider_conf` replaces the block in place.
    let alt_md = fx_aider.home().join("ALT_AGENTS.md");
    let changed = envcloak_agents::hosts::aider::apply_aider_conf(Some(body1.as_bytes()), &alt_md)
        .unwrap()
        .expect("must update when agents_md path changes");
    let body2 = String::from_utf8(changed.bytes).unwrap();
    assert!(
        body2.contains("ALT_AGENTS.md") && !body2.contains("/AGENTS.md"),
        "{body2}"
    );

    // Modifying inside the block causes refusal (`block_modified`) on both install and uninstall.
    let modified = body2.replace("ALT_AGENTS.md", "TAMPERED.md\n  - extra.md");
    let err_install =
        envcloak_agents::hosts::aider::apply_aider_conf(Some(modified.as_bytes()), &alt_md)
            .unwrap_err();
    assert_eq!(err_install.name, "block_modified");
    let err_remove =
        envcloak_agents::hosts::aider::remove_aider_conf(modified.as_bytes(), true).unwrap_err();
    assert_eq!(err_remove.name, "block_modified");

    // Damaging a marker causes refusal (`block_damaged`).
    let damaged_bytes = b"# envcloak:begin\nread:\n  - a\n";
    let err_damaged =
        envcloak_agents::hosts::aider::apply_aider_conf(Some(damaged_bytes), &alt_md).unwrap_err();
    assert_eq!(err_damaged.name, "block_damaged");

    // F-05: Symlinked Gemini settings.json is not followed by resolve_global_instruction_path.
    let fx_sym = Fx::new();
    let real_file = fx_sym.root.join("real-settings.json");
    std::fs::write(&real_file, r#"{"context":{"fileName":"AGENTS.md"}}"#).unwrap();
    let gemini_dir = fx_sym.home().join(".gemini");
    std::fs::create_dir_all(&gemini_dir).unwrap();
    let sym_settings = gemini_dir.join("settings.json");
    std::os::unix::fs::symlink(&real_file, &sym_settings).unwrap();
    assert_eq!(
        envcloak_agents::hosts::gemini::resolve_global_instruction_path(&gemini_dir, &sym_settings),
        gemini_dir.join("GEMINI.md"),
        "symlinked settings.json must not be read by resolve_global_instruction_path"
    );

    // F-01 & F-07: ConfigSet tracks installed hooks/servers in `cs.installed` for Tier-2 hosts,
    // and partial Cursor hooks leave `cs.hooks.tools == HookState::Missing`.
    let mut fx_cov = Fx::new();
    fx_cov.add_all_tier2_and_tier3_exes(kimi::KimiProduct::Code);
    let r_cov = fx_cov.run(
        &[
            Host::Cursor,
            Host::Gemini,
            Host::Copilot,
            Host::OpenCode,
            Host::Kimi,
            Host::Qwen,
        ],
        true,
        false,
        false,
    );
    assert!(r_cov.complete(), "{r_cov:?}");
    let vars_cov = fx_cov.vars.clone();
    let env_cov = move |k: &str| vars_cov.get(k).cloned();
    let l_cov = Locations::new(&env_cov).unwrap();
    for host in [
        Host::Cursor,
        Host::Gemini,
        Host::Copilot,
        Host::OpenCode,
        Host::Kimi,
        Host::Qwen,
    ] {
        let cs = ConfigSet::read(
            host,
            &l_cov,
            &fx_cov.root.join("m"),
            &fx_cov.proj(),
            &env_cov,
        );
        assert!(
            !cs.installed.hooks.is_empty(),
            "{host:?} must populate cs.installed.hooks so config_digest hashes the hook binary"
        );
        assert!(
            !cs.installed.servers.is_empty(),
            "{host:?} must populate cs.installed.servers so config_digest hashes the server binary"
        );
    }

    // Partial Cursor hook installation (missing `beforeShellExecution`, `beforeMCPExecution`, `preToolUse`)
    // must report `HookState::Missing` for `tools` and `mcp`.
    let cursor_hooks_path = l_cov.cursor_hooks();
    let envcloak_exe = fx_cov.root.join("envcloak");
    std::fs::write(
        &cursor_hooks_path,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "hooks": {
                "beforeReadFile": [
                    { "command": format!("'{}' hook --agent cursor --event beforeReadFile", envcloak_exe.display()) }
                ]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let cs_partial = ConfigSet::read(
        Host::Cursor,
        &l_cov,
        &fx_cov.root.join("m"),
        &fx_cov.proj(),
        &env_cov,
    );
    assert_eq!(cs_partial.hooks.tools, HookState::Missing);
    assert_eq!(cs_partial.hooks.mcp, HookState::Missing);
}
