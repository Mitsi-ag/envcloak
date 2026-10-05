//! The degraders read from real configuration files (M2 plan M2-09, D-14;
//! SPEC §7.1: "Degraders are read from the person's real configuration,
//! every switch the host documents included"): each switch, written into
//! the file where its host reads it, gives its token through
//! `ConfigSet::read` and `degraders`, and only its own; a file at a level
//! that cannot be read is taken as switching that level off; EnvCloak's
//! hooks are found where the installer writes them, and a hook whose
//! program is gone is said so. System and managed directories are temporary
//! ones here (`Locations::with_system_dirs`, `claude_managed`).
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use envcloak_agents::coverage::{self, ConfigSet, HookState, Reason, Surface, degraders};
use envcloak_agents::hook::{Event, Host};
use envcloak_agents::hosts::{claude, codex, hook_command};
use envcloak_agents::locations::Locations;
use serde_json::json;

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    system: PathBuf,
    managed_prefs: PathBuf,
    claude_managed: PathBuf,
    envcloak: PathBuf,
}

impl Home {
    fn new() -> Home {
        let dir = tempfile::Builder::new()
            .prefix("ecv")
            .tempdir_in("/tmp")
            .unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let project = home.join("proj");
        for d in [
            home.join(".claude"),
            home.join(".codex"),
            project.join(".claude"),
            root.join("system"),
            root.join("prefs"),
            root.join("claude-managed"),
            root.join("bin"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let envcloak = root.join("bin").join("envcloak");
        std::fs::write(&envcloak, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&envcloak, std::fs::Permissions::from_mode(0o755)).unwrap();
        Home {
            _dir: dir,
            system: root.join("system"),
            managed_prefs: root.join("prefs"),
            claude_managed: root.join("claude-managed"),
            root,
            home,
            project,
            envcloak,
        }
    }

    fn env(&self, extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let mut pairs: Vec<(String, OsString)> =
            vec![("HOME".to_owned(), self.home.clone().into_os_string())];
        pairs.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), OsString::from(v))),
        );
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    fn read(&self, host: Host, extra: &[(&str, &str)]) -> ConfigSet {
        let env = self.env(extra);
        let l = Locations::new(&env)
            .unwrap()
            .with_system_dirs(self.system.clone(), self.managed_prefs.clone());
        ConfigSet::read(host, &l, &self.claude_managed, &self.project, &env)
    }

    fn write(&self, p: &Path, text: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    /// EnvCloak's Claude Code hooks, as the installer writes them, in the
    /// user's settings, with `extra` keys.
    fn claude_installed(&self, extra: serde_json::Value) {
        let mut v = json!({"permissions": {"deny": [claude::READ_DENY]}});
        for (path, value) in claude::hooks_additions(&self.envcloak) {
            let at = v
                .pointer_mut("")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .entry(path[0])
                .or_insert(json!({}));
            let list = at
                .as_object_mut()
                .unwrap()
                .entry(path[1])
                .or_insert(json!([]));
            list.as_array_mut().unwrap().push(value);
        }
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        self.write(&self.home.join(".claude/settings.json"), &v.to_string());
    }

    fn codex_installed(&self) {
        let mut v = json!({});
        for (path, value) in codex::hooks_additions(&self.envcloak) {
            let at = v
                .as_object_mut()
                .unwrap()
                .entry(path[0])
                .or_insert(json!({}));
            let list = at
                .as_object_mut()
                .unwrap()
                .entry(path[1])
                .or_insert(json!([]));
            list.as_array_mut().unwrap().push(value);
        }
        self.write(&self.home.join(".codex/hooks.json"), &v.to_string());
        self.write(
            &self.home.join(".codex/config.toml"),
            "[mcp_servers.envcloak]\ncommand = \"/x/envcloak\"\nargs = [\"mcp\"]\n",
        );
    }
}

/// The reasons a configuration gives beyond the ones every host's always
/// has (the trust gate and the timeout).
fn switched(cs: &ConfigSet) -> Vec<Reason> {
    degraders(cs)
        .into_iter()
        .filter(|r| {
            !matches!(
                r,
                Reason::WorkspaceUntrusted | Reason::HooksUntrusted | Reason::FailsOpenOnTimeout
            )
        })
        .collect()
}

/// Claude Code: `disableAllHooks` at each level (user, project, local,
/// managed and a managed drop-in), managed `allowManagedHooksOnly`, and
/// `CLAUDE_CONFIG_DIR`, each in a file of its own, give their token and
/// only theirs.
///
/// Mutation checked: the local settings not read (the `"local"` level
/// dropped from `read_claude`'s list): `disableAllHooks` there gives no
/// token and this fails.
#[test]
fn every_claude_code_switch_gives_its_token() {
    type Setup = Box<dyn Fn(&Home)>;
    type Case<'a> = (&'a str, Setup, Vec<(&'a str, &'a str)>, Reason);
    let cases: Vec<Case<'_>> = vec![
        (
            "user disableAllHooks",
            Box::new(|h| h.claude_installed(json!({"disableAllHooks": true}))),
            vec![],
            Reason::SwitchedOffUser,
        ),
        (
            "project disableAllHooks",
            Box::new(|h| {
                h.claude_installed(json!({}));
                h.write(
                    &h.project.join(".claude/settings.json"),
                    r#"{"disableAllHooks": true}"#,
                );
            }),
            vec![],
            Reason::SwitchedOffProject,
        ),
        (
            "local disableAllHooks",
            Box::new(|h| {
                h.claude_installed(json!({}));
                h.write(
                    &h.project.join(".claude/settings.local.json"),
                    r#"{"disableAllHooks": true}"#,
                );
            }),
            vec![],
            Reason::SwitchedOffLocal,
        ),
        (
            "managed disableAllHooks",
            Box::new(|h| {
                h.claude_installed(json!({}));
                h.write(
                    &h.claude_managed.join("managed-settings.json"),
                    r#"{"disableAllHooks": true}"#,
                );
            }),
            vec![],
            Reason::SwitchedOffManaged,
        ),
        (
            "managed drop-in disableAllHooks",
            Box::new(|h| {
                h.claude_installed(json!({}));
                h.write(
                    &h.claude_managed.join("managed-settings.d/10-policy.json"),
                    r#"{"disableAllHooks": true}"#,
                );
            }),
            vec![],
            Reason::SwitchedOffManaged,
        ),
        (
            "managed allowManagedHooksOnly",
            Box::new(|h| {
                h.claude_installed(json!({}));
                h.write(
                    &h.claude_managed.join("managed-settings.json"),
                    r#"{"allowManagedHooksOnly": true}"#,
                );
            }),
            vec![],
            Reason::ManagedOnly,
        ),
        (
            "CLAUDE_CONFIG_DIR",
            Box::new(|h| {
                h.claude_installed(json!({}));
                std::fs::create_dir_all(h.root.join("cfg")).unwrap();
                std::fs::copy(
                    h.home.join(".claude/settings.json"),
                    h.root.join("cfg/settings.json"),
                )
                .unwrap();
            }),
            vec![("CLAUDE_CONFIG_DIR", "/CFG")],
            Reason::ConfigDirMoved,
        ),
    ];
    for (name, setup, env, want) in cases {
        let h = Home::new();
        // The control: installed, nothing switched off.
        h.claude_installed(json!({}));
        let base = h.read(Host::ClaudeCode, &[]);
        assert_eq!(switched(&base), [], "{name}: the control");
        assert_eq!(base.hooks.prompt, HookState::Present, "{name}");
        assert_eq!(base.hooks.tools, HookState::Present, "{name}");
        assert_eq!(base.hooks.mcp, HookState::Present, "{name}");
        assert!(base.read_deny);
        setup(&h);
        let cfg = h.root.join("cfg");
        let env: Vec<(&str, &str)> = env
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    if *v == "/CFG" {
                        cfg.to_str().unwrap()
                    } else {
                        *v
                    },
                )
            })
            .collect();
        let cs = h.read(Host::ClaudeCode, &env);
        assert_eq!(switched(&cs), [want], "{name}");
    }
}

/// A project setting of `false` does not hide a user `true`: the switch
/// at the user level is still reported (a session in another project
/// reads it), and an unreadable settings file reads as switched off at its
/// level, its hooks unknown.
#[test]
fn claude_code_switches_are_read_conservatively() {
    let h = Home::new();
    h.claude_installed(json!({"disableAllHooks": true}));
    h.write(
        &h.project.join(".claude/settings.json"),
        r#"{"disableAllHooks": false}"#,
    );
    assert_eq!(
        switched(&h.read(Host::ClaudeCode, &[])),
        [Reason::SwitchedOffUser]
    );
    let h = Home::new();
    h.claude_installed(json!({}));
    h.write(&h.project.join(".claude/settings.local.json"), "{not json");
    assert_eq!(
        switched(&h.read(Host::ClaudeCode, &[])),
        [Reason::SwitchedOffLocal]
    );
    // Hooks a managed file holds are kept by `allowManagedHooksOnly`.
    let h = Home::new();
    let mut managed = json!({"allowManagedHooksOnly": true});
    for (path, value) in claude::hooks_additions(&h.envcloak) {
        let list = managed
            .as_object_mut()
            .unwrap()
            .entry(path[0])
            .or_insert(json!({}))
            .as_object_mut()
            .unwrap()
            .entry(path[1])
            .or_insert(json!([]));
        list.as_array_mut().unwrap().push(value);
    }
    h.write(
        &h.claude_managed.join("managed-settings.json"),
        &managed.to_string(),
    );
    let cs = h.read(Host::ClaudeCode, &[]);
    assert!(cs.managed_hooks.prompt && cs.managed_hooks.tools && cs.managed_hooks.mcp);
    assert_eq!(switched(&cs), []);
    // A managed file holding the prompt hook alone keeps it alone: the
    // file, shell and MCP hooks in the user's settings are stopped by
    // `allowManagedHooksOnly` (Codex review: one managed hook kept them
    // all).
    let h = Home::new();
    h.claude_installed(json!({}));
    let mut managed = json!({"allowManagedHooksOnly": true});
    for (path, value) in claude::hooks_additions(&h.envcloak) {
        if path[1] != "UserPromptSubmit" {
            continue;
        }
        managed
            .as_object_mut()
            .unwrap()
            .entry(path[0])
            .or_insert(json!({}))
            .as_object_mut()
            .unwrap()
            .entry(path[1])
            .or_insert(json!([]))
            .as_array_mut()
            .unwrap()
            .push(value);
    }
    h.write(
        &h.claude_managed.join("managed-settings.json"),
        &managed.to_string(),
    );
    let cs = h.read(Host::ClaudeCode, &[]);
    assert!(cs.managed_hooks.prompt, "{:?}", cs.managed_hooks);
    assert!(
        !cs.managed_hooks.tools && !cs.managed_hooks.mcp,
        "{:?}",
        cs.managed_hooks
    );
    for surface in Surface::ALL {
        let on = coverage::degraders_for(&cs, surface).contains(&Reason::ManagedOnly);
        assert_eq!(
            on,
            matches!(surface, Surface::FileRead | Surface::Shell | Surface::Mcp),
            "{surface:?}"
        );
    }
}

/// Codex: hook trust (always, until it is observable), `[features] hooks =
/// false` in the user's, a project's and a managed layer, and
/// `allow_managed_hooks_only` in `requirements.toml`, and
/// `AGENTS.override.md`, each give their token.
///
/// Mutation checked: the project layers not read (the loop over the
/// project's directories dropped): `hooks = false` there gives no token
/// and this fails.
#[test]
fn every_codex_switch_gives_its_token() {
    let h = Home::new();
    h.codex_installed();
    let base = h.read(Host::Codex, &[]);
    assert_eq!(switched(&base), []);
    assert!(degraders(&base).contains(&Reason::HooksUntrusted));
    assert_eq!(base.hooks.prompt, HookState::Present);
    assert_eq!(base.hooks.tools, HookState::Present);
    assert_eq!(base.hooks.mcp, HookState::Present);
    assert!(base.server.registered);
    assert_eq!(base.server.run_with_secrets_approved, Some(false));
    type Setup = Box<dyn Fn(&Home)>;
    let cases: Vec<(&str, Setup, Reason)> = vec![
        (
            "user hooks = false",
            Box::new(|h| {
                let p = h.home.join(".codex/config.toml");
                let t = std::fs::read_to_string(&p).unwrap();
                h.write(&p, &format!("[features]\nhooks = false\n\n{t}"));
            }),
            Reason::SwitchedOffUser,
        ),
        (
            "project hooks = false",
            Box::new(|h| {
                h.write(
                    &h.project.join(".codex/config.toml"),
                    "[features]\nhooks = false\n",
                );
            }),
            Reason::SwitchedOffProject,
        ),
        (
            "managed hooks = false",
            Box::new(|h| {
                h.write(
                    &h.system.join("managed_config.toml"),
                    "[features]\nhooks = false\n",
                );
            }),
            Reason::SwitchedOffManaged,
        ),
        (
            "allow_managed_hooks_only",
            Box::new(|h| {
                h.write(
                    &h.system.join("requirements.toml"),
                    "allow_managed_hooks_only = true\n",
                );
            }),
            Reason::ManagedOnly,
        ),
        (
            "AGENTS.override.md",
            Box::new(|h| h.write(&h.home.join(".codex/AGENTS.override.md"), "# mine\n")),
            Reason::OverrideFile,
        ),
    ];
    for (name, setup, want) in cases {
        let h = Home::new();
        h.codex_installed();
        setup(&h);
        assert_eq!(switched(&h.read(Host::Codex, &[])), [want], "{name}");
    }
}

/// EnvCloak's hooks found or not: none written gives `Missing`; one whose
/// program is gone gives `CommandMissing` (a hook that fails, and lets the
/// action through); the person's approval of `run_with_secrets` is read
/// per tool, over the server's default.
#[test]
fn hooks_and_approvals_are_read_as_written() {
    let h = Home::new();
    let cs = h.read(Host::ClaudeCode, &[]);
    assert_eq!(cs.hooks.prompt, HookState::Missing);
    assert!(!cs.server.registered);
    let gone = h.root.join("gone/envcloak");
    let hooks = json!({"hooks": {"UserPromptSubmit": [{"hooks": [{
        "type": "command",
        "command": hook_command(&gone, Host::ClaudeCode, Event::UserPromptSubmit),
    }]}]}});
    h.write(&h.home.join(".claude/settings.json"), &hooks.to_string());
    assert_eq!(
        h.read(Host::ClaudeCode, &[]).hooks.prompt,
        HookState::CommandMissing
    );
    // Allowed by the person in Claude Code's own settings.
    h.claude_installed(json!({"permissions": {"allow": ["mcp__envcloak__run_with_secrets"]}}));
    h.write(
        &h.home.join(".claude.json"),
        r#"{"mcpServers": {"envcloak": {"command": "/x/envcloak"}}}"#,
    );
    let cs = h.read(Host::ClaudeCode, &[]);
    assert!(cs.server.registered);
    assert_eq!(cs.server.run_with_secrets_approved, Some(true));
    // Codex: a server default of `approve` with the tool set to `prompt`
    // is not approved; the tool set to `approve` is.
    let h = Home::new();
    h.codex_installed();
    let p = h.home.join(".codex/config.toml");
    let t = std::fs::read_to_string(&p).unwrap();
    h.write(
        &p,
        &format!(
            "{t}default_tools_approval_mode = \"approve\"\n\n\
             [mcp_servers.envcloak.tools.run_with_secrets]\napproval_mode = \"prompt\"\n"
        ),
    );
    assert_eq!(
        h.read(Host::Codex, &[]).server.run_with_secrets_approved,
        Some(false)
    );
    let t = std::fs::read_to_string(&p).unwrap();
    h.write(
        &p,
        &t.replace("approval_mode = \"prompt\"", "approval_mode = \"approve\""),
    );
    assert_eq!(
        h.read(Host::Codex, &[]).server.run_with_secrets_approved,
        Some(true)
    );
}

/// Codex's sandbox mode and the approval of `run_with_secrets` are read
/// from its merged layers, as Codex merges them, not from the user's file
/// alone (Codex review of M2-09): a higher layer's value wins; a project
/// layer, which Codex reads only for a trusted project, and a profile
/// file, which only a session that names it reads, count both ways, so
/// the shell is sandboxed when any reading has it, and the approval is
/// not known when the readings disagree.
///
/// Mutation checked: the merge without the managed layer (`stack.push(&
/// managed)` dropped): the managed `prompt` over the user's `approve`
/// reads callable and this fails.
#[test]
fn codex_coverage_follows_its_merged_layers() {
    const APPROVE: &str =
        "[mcp_servers.envcloak.tools.run_with_secrets]\napproval_mode = \"approve\"\n";
    const PROMPT: &str =
        "[mcp_servers.envcloak.tools.run_with_secrets]\napproval_mode = \"prompt\"\n";
    let base = "[mcp_servers.envcloak]\ncommand = \"/x/envcloak\"\nargs = [\"mcp\"]\n";
    type Setup = Box<dyn Fn(&Home)>;
    let user = |extra: &'static str| -> Setup {
        Box::new(move |h: &Home| {
            h.write(
                &h.home.join(".codex/config.toml"),
                &format!("{extra}{base}"),
            );
        })
    };
    let cases: Vec<(&str, Vec<Setup>, Option<bool>, bool)> = vec![
        ("the user's approval", vec![user(APPROVE)], Some(true), true),
        (
            "a managed prompt over the user's approval",
            vec![
                user(APPROVE),
                Box::new(|h| h.write(&h.system.join("managed_config.toml"), PROMPT)),
            ],
            Some(false),
            true,
        ),
        (
            "a project's approval, which an untrusted project does not give",
            vec![
                user(""),
                Box::new(|h| h.write(&h.project.join(".codex/config.toml"), APPROVE)),
            ],
            None,
            true,
        ),
        (
            "the system's approval under the user's",
            vec![
                user(""),
                Box::new(|h| h.write(&h.system.join("config.toml"), APPROVE)),
            ],
            Some(true),
            true,
        ),
        (
            "the user's full access",
            vec![user("sandbox_mode = \"danger-full-access\"\n")],
            Some(false),
            false,
        ),
        (
            "a project's sandbox over the user's full access",
            vec![
                user("sandbox_mode = \"danger-full-access\"\n"),
                Box::new(|h| {
                    h.write(
                        &h.project.join(".codex/config.toml"),
                        "sandbox_mode = \"workspace-write\"\n",
                    );
                }),
            ],
            Some(false),
            true,
        ),
        (
            "a profile's sandbox over the user's full access",
            vec![
                user("sandbox_mode = \"danger-full-access\"\n"),
                Box::new(|h| {
                    h.write(
                        &h.home.join(".codex/work.config.toml"),
                        "sandbox_mode = \"read-only\"\n",
                    );
                }),
            ],
            Some(false),
            true,
        ),
        (
            "managed full access over the user's sandbox",
            vec![
                user("sandbox_mode = \"workspace-write\"\n"),
                Box::new(|h| {
                    h.write(
                        &h.system.join("managed_config.toml"),
                        "sandbox_mode = \"danger-full-access\"\n",
                    );
                }),
            ],
            Some(false),
            false,
        ),
        (
            "requirements that do not allow full access",
            vec![
                user("sandbox_mode = \"danger-full-access\"\n"),
                Box::new(|h| {
                    h.write(
                        &h.system.join("requirements.toml"),
                        "allowed_sandbox_modes = [\"read-only\", \"workspace-write\"]\n",
                    );
                }),
            ],
            Some(false),
            true,
        ),
    ];
    for (name, setup, approved, sandboxed) in cases {
        let h = Home::new();
        for s in &setup {
            s(&h);
        }
        let cs = h.read(Host::Codex, &[]);
        assert!(cs.server.registered, "{name}");
        assert_eq!(cs.server.run_with_secrets_approved, approved, "{name}");
        assert_eq!(cs.sandboxed_shell, sandboxed, "{name}");
    }
}

/// A Codex layer EnvCloak cannot read (a macOS device profile for Codex,
/// an organization's settings sent with the account) is taken as
/// switching the hooks off from above, the shell as sandboxed and the
/// server's approval as not known; neither there, none of that (the
/// control). The verifier's finding: a device profile gave no token.
///
/// Mutation checked: the device profiles not looked for
/// (`codex_managed_preferences` not read in `read_codex`): the profile
/// gives no `switched_off_managed` and this fails.
#[test]
fn codex_layers_out_of_sight_read_conservatively() {
    let h = Home::new();
    h.codex_installed();
    h.write(
        &h.home.join(".codex/config.toml"),
        "sandbox_mode = \"danger-full-access\"\n[mcp_servers.envcloak]\ncommand = \"/x\"\n\
         [mcp_servers.envcloak.tools.run_with_secrets]\napproval_mode = \"approve\"\n",
    );
    let clear = h.read(Host::Codex, &[]);
    assert_eq!(switched(&clear), []);
    assert!(!clear.sandboxed_shell);
    assert_eq!(clear.server.run_with_secrets_approved, Some(true));
    for (name, file) in [
        (
            "a device profile",
            h.managed_prefs.join("com.openai.codex.plist"),
        ),
        (
            "a user's device profile",
            h.managed_prefs
                .join("someone")
                .join("com.openai.codex.plist"),
        ),
        (
            "an organization's settings",
            h.home.join(".codex/cloud-config-bundle-cache.json"),
        ),
    ] {
        h.write(&file, "opaque");
        let cs = h.read(Host::Codex, &[]);
        assert_eq!(switched(&cs), [Reason::SwitchedOffManaged], "{name}");
        assert!(cs.sandboxed_shell, "{name}");
        assert_eq!(cs.server.run_with_secrets_approved, None, "{name}");
        std::fs::remove_file(&file).unwrap();
        assert_eq!(switched(&h.read(Host::Codex, &[])), [], "{name}: removed");
    }
}

/// The probe context's fingerprint follows what a probe's result depends
/// on that the summarized facts do not show (Codex F-132): a hook's
/// timeout, the bytes of the program a hook runs, the `envcloak` build,
/// another setting in a file the host reads, Codex's rules; each change
/// gives another fingerprint, and putting it back gives the first again
/// (the control). A hook program that is there but cannot be read leaves
/// no fingerprint at all.
///
/// Mutation checked: the configuration files' bytes left out of the
/// context (`Context::note` keeping no SHA-256): the timeout's change
/// leaves the fingerprint as it was and this fails.
#[test]
fn the_fingerprint_follows_what_a_result_depends_on() {
    let h = Home::new();
    let build = h.root.join("bin").join("envcloak-build");
    h.write(&build, "build one");
    h.claude_installed(json!({}));
    h.codex_installed();
    let settings = h.home.join(".claude/settings.json");
    let hooks = h.home.join(".codex/hooks.json");
    let fp = |host: Host| h.read(host, &[]).fingerprint(&build).unwrap();
    for host in [Host::ClaudeCode, Host::Codex] {
        let first = fp(host);
        assert_eq!(fp(host), first, "{host:?}: read twice");
        let facts = h.read(host, &[]);
        // A hook's timeout: the facts the same, the fingerprint not.
        let file = if host == Host::ClaudeCode {
            &settings
        } else {
            &hooks
        };
        let installed = std::fs::read_to_string(file).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&installed).unwrap();
        for groups in v["hooks"].as_object_mut().unwrap().values_mut() {
            for g in groups.as_array_mut().unwrap() {
                for hk in g["hooks"].as_array_mut().unwrap() {
                    hk["timeout"] = json!(0.001);
                }
            }
        }
        h.write(file, &v.to_string());
        let mut after = h.read(host, &[]);
        after.context = facts.context.clone();
        assert_eq!(after, facts, "{host:?}: the facts changed with the timeout");
        assert_ne!(fp(host), first, "{host:?}: the timeout");
        h.write(file, &installed);
        assert_eq!(fp(host), first, "{host:?}: the timeout put back");
        // The program the hooks run, at the same path.
        let program = std::fs::read(&h.envcloak).unwrap();
        h.write(&h.envcloak, "#!/bin/sh\nexit 0\n");
        assert_ne!(fp(host), first, "{host:?}: the hook program");
        std::fs::write(&h.envcloak, &program).unwrap();
        assert_eq!(fp(host), first, "{host:?}: the hook program put back");
        // The envcloak build.
        h.write(&build, "build two");
        assert_ne!(fp(host), first, "{host:?}: the build");
        h.write(&build, "build one");
        assert_eq!(fp(host), first, "{host:?}: the build put back");
    }
    // Another setting in Claude Code's settings, and a rule of Codex's.
    let first = fp(Host::ClaudeCode);
    let installed = std::fs::read_to_string(&settings).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&installed).unwrap();
    v["env"] = json!({"EXAMPLE_SETTING": "1"});
    h.write(&settings, &v.to_string());
    assert_ne!(fp(Host::ClaudeCode), first, "another setting");
    h.write(&settings, &installed);
    let first = fp(Host::Codex);
    let rules = h.home.join(".codex/rules/mine.rules");
    h.write(
        &rules,
        "prefix_rule(pattern=[\"cat\"], decision=\"forbidden\")\n",
    );
    assert_ne!(fp(Host::Codex), first, "a rule");
    std::fs::remove_file(&rules).unwrap();
    assert_eq!(fp(Host::Codex), first, "the rule taken out");
    // A hook program that cannot be read: no fingerprint.
    std::fs::set_permissions(&h.envcloak, std::fs::Permissions::from_mode(0o111)).unwrap();
    let unreadable = h.read(Host::ClaudeCode, &[]);
    std::fs::set_permissions(&h.envcloak, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!unreadable.context.complete);
    assert_eq!(unreadable.fingerprint(&build), None);
}
