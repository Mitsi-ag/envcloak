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
        self.read_in(host, &self.project, extra)
    }

    /// The configuration of a session whose working directory is `cwd`.
    fn read_in(&self, host: Host, cwd: &Path, extra: &[(&str, &str)]) -> ConfigSet {
        let env = self.env(extra);
        let l = Locations::new(&env)
            .unwrap()
            .with_system_dirs(self.system.clone(), self.managed_prefs.clone());
        ConfigSet::read(host, &l, &self.claude_managed, cwd, &env)
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
        // What EnvCloak installed, as `ConfigSet::shape` reads it, follows
        // the change too; the rest of the facts do not.
        assert_ne!(
            after.installed, facts.installed,
            "{host:?}: the timeout: the installed entries"
        );
        after.context = facts.context.clone();
        after.installed = facts.installed.clone();
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

/// Claude Code's registration of EnvCloak's server is part of the probe
/// context (the verifier's and Codex's round-2 finding, F-132's residual:
/// `.claude.json` was read for the server's presence alone, so a changed
/// command, arguments or timeout left a result current): each change of
/// the user-scope entry, of a local-scope entry or of the person's
/// settings about the server there, of a `.mcp.json` from the working
/// directory up, and an organization's `managed-mcp.json`, gives another
/// fingerprint, the result kept for the first stale, and putting it back
/// the first again, the result current, after a reload too. What Claude
/// Code writes there for itself on every run (measured on 2.1.280: it
/// creates the file in a fresh home, with its own state) changes nothing:
/// the probe's own runs leave the context as it was (a whole-file digest,
/// Codex cycle418's, would make every result stale after its first run).
/// No value of the registration is kept.
///
/// Mutation checked: the registration left out of the context (the
/// `cs.context.parts.push` in `read_claude` dropped): the command's change
/// leaves the fingerprint as it was and this fails.
#[test]
fn claude_registration_changes_make_a_result_stale() {
    use coverage::{Cache, Outcome, ProbeRecord, Probed, Sentinel, ServerObserved};
    let h = Home::new();
    h.claude_installed(json!({}));
    let path = h.home.join(".claude.json");
    let entry = json!({
        "type": "stdio",
        "command": "/fixture/program-a",
        "args": ["mcp", "--host", "claude-code"],
        "env": {"FIXTURE_ONLY": "fixture-environment-a"},
        "timeout": 60000,
    });
    let file = |entry: &serde_json::Value, extra: serde_json::Value| {
        let mut v = json!({"mcpServers": {"envcloak": entry.clone()}});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v.to_string()
    };
    h.write(&path, &file(&entry, json!({})));
    let first = h.read(Host::ClaudeCode, &[]);
    assert!(first.server.registered);
    let digest = first.fingerprint(&h.envcloak).unwrap();
    let cache_path = h.root.join("data").join("coverage.json");
    let mut cache = Cache::default();
    cache.put(ProbeRecord {
        host: Host::ClaudeCode.id().to_owned(),
        exe_sha256: "e".repeat(64),
        version: "2.1.280".to_owned(),
        config_digest: digest.clone(),
        os: std::env::consts::OS.to_owned(),
        surfaces: Vec::new(),
        server: ServerObserved {
            outcome: Outcome::Passed,
            sentinel: Sentinel::Appeared,
            control_ran: true,
            allowed_write: true,
            control_denied: true,
        },
        flags: Vec::new(),
    });
    cache.store(&cache_path).unwrap();
    let current = || {
        let fp = h
            .read(Host::ClaudeCode, &[])
            .fingerprint(&h.envcloak)
            .unwrap_or_default();
        matches!(
            Cache::load(&cache_path).probed("claude-code", &"e".repeat(64), "2.1.280", &fp),
            Probed::Current(_)
        )
    };
    assert!(current(), "the context it was kept for");
    // The entry's every part, the facts the same.
    for (name, k, changed) in [
        ("the command", "command", json!("/fixture/program-b")),
        ("the arguments", "args", json!(["mcp"])),
        (
            "an environment value",
            "env",
            json!({"FIXTURE_ONLY": "fixture-environment-b"}),
        ),
        ("the timeout", "timeout", json!(1)),
        ("the type", "type", json!("http")),
    ] {
        let mut e = entry.clone();
        e[k] = changed;
        h.write(&path, &file(&e, json!({})));
        let mut after = h.read(Host::ClaudeCode, &[]);
        assert!(!current(), "{name}: still current");
        // What EnvCloak installed, as `ConfigSet::shape` reads it, follows
        // the change too; the rest of the facts do not.
        assert_ne!(
            after.installed, first.installed,
            "{name}: the installed entries"
        );
        after.context = first.context.clone();
        after.installed = first.installed.clone();
        assert_eq!(after, first, "{name}: the facts changed");
        h.write(&path, &file(&entry, json!({})));
        assert!(current(), "{name} put back");
    }
    // Claude Code's own bookkeeping, as its runs write it: no change.
    let cwd = std::fs::canonicalize(&h.project).unwrap();
    h.write(
        &path,
        &file(
            &entry,
            json!({
                "numStartups": 7,
                "firstStartTime": "2026-10-05T00:00:00Z",
                "projects": {cwd.to_string_lossy(): {"lastSessionId": "x", "allowedTools": []}},
            }),
        ),
    );
    assert!(current(), "Claude Code's own state moved the fingerprint");
    // A local-scope entry and the person's settings about the server for
    // the working directory, and for a folder above it.
    for (name, part) in [
        (
            "a local-scope entry",
            json!({"mcpServers": {"envcloak": {"command": "/x"}}}),
        ),
        (
            "the server disabled",
            json!({"disabledMcpServers": ["envcloak"]}),
        ),
        (
            "project servers allowed",
            json!({"enableAllProjectMcpServers": true}),
        ),
        (
            "the project's server enabled",
            json!({"enabledMcpjsonServers": ["envcloak"]}),
        ),
    ] {
        for key in [cwd.clone(), cwd.parent().unwrap().to_path_buf()] {
            h.write(
                &path,
                &file(
                    &entry,
                    json!({"projects": {key.to_string_lossy(): part.clone()}}),
                ),
            );
            assert!(!current(), "{name} at {}: still current", key.display());
            h.write(&path, &file(&entry, json!({})));
            assert!(current(), "{name} taken out");
        }
    }
    // Another project's entry: nothing to do with this directory.
    h.write(
        &path,
        &file(
            &entry,
            json!({"projects": {"/elsewhere": {"mcpServers": {"envcloak": {"command": "/x"}}}}}),
        ),
    );
    assert!(current(), "another directory's entry");
    h.write(&path, &file(&entry, json!({})));
    // A `.mcp.json` in the working directory and in a folder above it,
    // and an organization's `managed-mcp.json`.
    for mcp in [
        h.project.join(".mcp.json"),
        h.home.join(".mcp.json"),
        h.claude_managed.join("managed-mcp.json"),
    ] {
        h.write(
            &mcp,
            r#"{"mcpServers": {"envcloak": {"command": "/fixture/y"}}}"#,
        );
        assert!(!current(), "{}: still current", mcp.display());
        std::fs::remove_file(&mcp).unwrap();
        assert!(current(), "{} taken out", mcp.display());
    }
    // No value of the registration is kept.
    let kept = serde_json::to_string(&h.read(Host::ClaudeCode, &[]).context).unwrap();
    for literal in ["/fixture/program-a", "fixture-environment-a"] {
        assert!(!kept.contains(literal), "{literal}");
    }
}

/// A registration only in a `.mcp.json` or a local-scope entry is a
/// registration; a `.claude.json` that is there but cannot be read, or is
/// not JSON, leaves the context incomplete (no result is current), and
/// absent or holding nothing about EnvCloak, the same context.
#[test]
fn claude_registrations_are_found_in_every_scope() {
    let h = Home::new();
    h.claude_installed(json!({}));
    let absent = h.read(Host::ClaudeCode, &[]);
    assert!(!absent.server.registered);
    let fp = absent.fingerprint(&h.envcloak).unwrap();
    let path = h.home.join(".claude.json");
    h.write(&path, r#"{"userID": "fixture", "projects": {}}"#);
    assert_eq!(
        h.read(Host::ClaudeCode, &[]).fingerprint(&h.envcloak),
        Some(fp.clone())
    );
    let cwd = std::fs::canonicalize(&h.project).unwrap();
    h.write(
        &path,
        &json!({"projects": {cwd.to_string_lossy(): {"mcpServers": {"envcloak": {"command": "/x"}}}}})
            .to_string(),
    );
    assert!(h.read(Host::ClaudeCode, &[]).server.registered);
    std::fs::remove_file(&path).unwrap();
    h.write(
        &h.project.join(".mcp.json"),
        r#"{"mcpServers": {"envcloak": {"command": "/x"}}}"#,
    );
    assert!(h.read(Host::ClaudeCode, &[]).server.registered);
    std::fs::remove_file(h.project.join(".mcp.json")).unwrap();
    for (name, body) in [("not JSON", "{not json"), ("unreadable", "{}")] {
        h.write(&path, body);
        if name == "unreadable" {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let cs = h.read(Host::ClaudeCode, &[]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!cs.context.complete, "{name}");
        assert_eq!(cs.fingerprint(&h.envcloak), None, "{name}");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            h.read(Host::ClaudeCode, &[]).fingerprint(&h.envcloak),
            Some(fp.clone()),
            "{name}: taken out"
        );
    }
}

/// How Claude Code lets an agent call `run_with_secrets` follows the
/// permission mode its settings give and the rules naming the tool, as
/// the pinned 2.1.280 does (measured, `-p`): `bypassPermissions` runs it
/// with no rule; a `deny` or an `ask` rule stops it in every mode;
/// `default`, `manual`, `acceptEdits` and `dontAsk` run it with an
/// `allow` rule only; `plan`, `auto`, an unknown mode, bypass switched off
/// and an organization's `managed-mcp.json` are not known; the highest
/// level that sets the mode decides (the verifier's round-2 finding:
/// `defaultMode` was never read, and bypass read as needing approval).
///
/// Mutation checked: `defaultMode` not read (`mode[i] = Some(..)`
/// dropped): bypass reads `Some(false)` and this fails.
#[test]
fn claude_code_approval_follows_its_permission_mode() {
    const TOOL: &str = "mcp__envcloak__run_with_secrets";
    let cases: Vec<(
        &str,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<bool>,
    )> = vec![
        ("no setting", json!({}), None, Some(false)),
        ("allowed", json!({"allow": [TOOL]}), None, Some(true)),
        (
            "bypass",
            json!({"defaultMode": "bypassPermissions"}),
            None,
            Some(true),
        ),
        (
            "bypass, denied",
            json!({"defaultMode": "bypassPermissions", "deny": [TOOL]}),
            None,
            Some(false),
        ),
        (
            "bypass, asked",
            json!({"defaultMode": "bypassPermissions", "ask": ["mcp__envcloak__*"]}),
            None,
            Some(false),
        ),
        (
            "allowed, asked",
            json!({"allow": [TOOL], "ask": [TOOL]}),
            None,
            Some(false),
        ),
        (
            "manual",
            json!({"defaultMode": "manual"}),
            None,
            Some(false),
        ),
        (
            "manual, allowed",
            json!({"defaultMode": "manual", "allow": [TOOL]}),
            None,
            Some(true),
        ),
        (
            "accept edits",
            json!({"defaultMode": "acceptEdits"}),
            None,
            Some(false),
        ),
        (
            "don't ask, allowed",
            json!({"defaultMode": "dontAsk", "allow": ["mcp__envcloak"]}),
            None,
            Some(true),
        ),
        ("plan", json!({"defaultMode": "plan"}), None, None),
        ("auto", json!({"defaultMode": "auto"}), None, None),
        ("unknown", json!({"defaultMode": "someday"}), None, None),
        (
            "bypass switched off",
            json!({"defaultMode": "bypassPermissions", "disableBypassPermissionsMode": "disable"}),
            None,
            None,
        ),
        (
            "bypass for the user, default for the project",
            json!({"defaultMode": "bypassPermissions"}),
            Some(json!({"defaultMode": "default"})),
            Some(false),
        ),
        (
            "default for the user, bypass for the project",
            json!({"defaultMode": "default"}),
            Some(json!({"defaultMode": "bypassPermissions"})),
            Some(true),
        ),
    ];
    for (name, user, project, want) in cases {
        let h = Home::new();
        h.claude_installed(json!({"permissions": user}));
        if let Some(p) = project {
            h.write(
                &h.project.join(".claude/settings.json"),
                &json!({"permissions": p}).to_string(),
            );
        }
        h.write(
            &h.home.join(".claude.json"),
            r#"{"mcpServers": {"envcloak": {"command": "/x/envcloak"}}}"#,
        );
        let cs = h.read(Host::ClaudeCode, &[]);
        assert!(cs.server.registered, "{name}");
        assert_eq!(cs.server.run_with_secrets_approved, want, "{name}");
        // An organization's servers file: not known.
        h.write(&h.claude_managed.join("managed-mcp.json"), "{}");
        assert_eq!(
            h.read(Host::ClaudeCode, &[])
                .server
                .run_with_secrets_approved,
            None,
            "{name}: managed-mcp.json"
        );
    }
}

/// Claude Code's settings are read for the working directory, as the
/// pinned 2.1.280 reads them (measured): the project's settings there
/// only, never a folder above it's; the local settings there and at the
/// git root above it (Codex review of M2-09: the nearest manifest's
/// directory was read instead).
///
/// Mutation checked: the git root's local settings not read (the
/// `git_root` push dropped in `read_claude`): `disableAllHooks` there,
/// for a session in a folder below, gives no token and this fails.
#[test]
fn claude_code_settings_are_read_for_the_working_directory() {
    let off = r#"{"disableAllHooks": true}"#;
    let h = Home::new();
    h.claude_installed(json!({}));
    let sub = h.project.join("sub");
    std::fs::create_dir_all(sub.join(".claude")).unwrap();
    std::fs::create_dir_all(h.project.join(".git")).unwrap();
    let in_sub = || switched(&h.read_in(Host::ClaudeCode, &sub, &[]));
    assert_eq!(in_sub(), []);
    for (file, want) in [
        (
            sub.join(".claude/settings.json"),
            vec![Reason::SwitchedOffProject],
        ),
        (
            sub.join(".claude/settings.local.json"),
            vec![Reason::SwitchedOffLocal],
        ),
        // The git root's local settings: read from below it.
        (
            h.project.join(".claude/settings.local.json"),
            vec![Reason::SwitchedOffLocal],
        ),
        // A folder above's project settings: not read.
        (h.project.join(".claude/settings.json"), vec![]),
    ] {
        h.write(&file, off);
        assert_eq!(in_sub(), want, "{}", file.display());
        std::fs::remove_file(&file).unwrap();
    }
    // With no git root, a folder above's local settings are not read.
    std::fs::remove_dir(h.project.join(".git")).unwrap();
    h.write(&h.project.join(".claude/settings.local.json"), off);
    assert_eq!(in_sub(), []);
}

/// Codex runs the hooks of a trusted project's `.codex/hooks.json`, from
/// the project root down (measured on 0.159.2): each is in the probe
/// context, and a prompt hook there, or in the user's file, that is not
/// EnvCloak's is said so; EnvCloak's own hooks alone are not (the
/// control). Claude Code's settings likewise; and a deny rule for its
/// file tools other than EnvCloak's `Read(**/.env*)`.
///
/// Mutation checked: the project hook files not read (`hook_files` left
/// with the system file alone): the project's prompt hook gives no
/// `foreign_prompt_hook` and this fails.
#[test]
fn hooks_and_rules_not_envcloaks_are_said_so() {
    let other = json!({"hooks": {"UserPromptSubmit": [{"hooks": [
        {"type": "command", "command": "/usr/bin/true"}
    ]}]}})
    .to_string();
    let h = Home::new();
    h.codex_installed();
    let base = h.read(Host::Codex, &[]);
    assert!(!base.foreign_prompt_hook);
    let fp = base.fingerprint(&h.envcloak).unwrap();
    for file in [
        h.project.join(".codex/hooks.json"),
        h.system.join("hooks.json"),
    ] {
        h.write(&file, &other);
        let cs = h.read(Host::Codex, &[]);
        assert!(cs.foreign_prompt_hook, "{}", file.display());
        assert_ne!(
            cs.fingerprint(&h.envcloak),
            Some(fp.clone()),
            "{}",
            file.display()
        );
        assert_eq!(cs.hooks, base.hooks, "{}", file.display());
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            h.read(Host::Codex, &[]).fingerprint(&h.envcloak),
            Some(fp.clone())
        );
    }
    // In the user's own hook file, beside EnvCloak's.
    let user = h.home.join(".codex/hooks.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&user).unwrap()).unwrap();
    v["hooks"]["UserPromptSubmit"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hooks": [{"type": "command", "command": "/usr/bin/true"}]}));
    h.write(&user, &v.to_string());
    assert!(h.read(Host::Codex, &[]).foreign_prompt_hook);
    // Claude Code: EnvCloak's hooks and deny rule alone, then others.
    let h = Home::new();
    h.claude_installed(json!({}));
    let cs = h.read(Host::ClaudeCode, &[]);
    assert!(!cs.foreign_prompt_hook && !cs.foreign_read_deny && cs.read_deny);
    h.write(&h.project.join(".claude/settings.local.json"), &other);
    assert!(h.read(Host::ClaudeCode, &[]).foreign_prompt_hook);
    std::fs::remove_file(h.project.join(".claude/settings.local.json")).unwrap();
    for rule in ["Read(./.env)", "Read", "Read(//**/secrets/**)"] {
        h.write(
            &h.project.join(".claude/settings.json"),
            &json!({"permissions": {"deny": [rule]}}).to_string(),
        );
        assert!(h.read(Host::ClaudeCode, &[]).foreign_read_deny, "{rule}");
    }
    h.write(
        &h.project.join(".claude/settings.json"),
        &json!({"permissions": {"deny": ["Bash(rm:*)", "WebFetch"]}}).to_string(),
    );
    assert!(!h.read(Host::ClaudeCode, &[]).foreign_read_deny);
}

/// A configuration file the host reads that is there but cannot be read
/// leaves the context incomplete: what it holds could change unseen, so no
/// result is current while it cannot be read (Codex cycle418).
///
/// Mutation checked: `Context::note` without `self.complete = false`: the
/// unreadable settings file still gives a fingerprint and this fails.
#[test]
fn a_settings_file_that_cannot_be_read_leaves_no_fingerprint() {
    let h = Home::new();
    h.claude_installed(json!({}));
    let fp = h.read(Host::ClaudeCode, &[]).fingerprint(&h.envcloak);
    assert!(fp.is_some());
    let settings = h.home.join(".claude/settings.json");
    std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o000)).unwrap();
    let cs = h.read(Host::ClaudeCode, &[]);
    std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!cs.context.complete);
    assert_eq!(cs.fingerprint(&h.envcloak), None);
    assert_eq!(h.read(Host::ClaudeCode, &[]).fingerprint(&h.envcloak), fp);
}

/// A `UserPromptSubmit` hook another program wrote inline in any Codex
/// layer's `[hooks]` (Codex runs those as it runs `hooks.json`'s: M2-04
/// measured it), a plugin a layer enables (whose `plugin.json` hooks
/// EnvCloak does not read), a layer that cannot be read and one EnvCloak
/// cannot read (a device profile) may each give the block Codex reports,
/// which names no hook: each is said so (the verifier's round-3 finding:
/// only JSON hook files were read, so a block an inline hook gave counted
/// as EnvCloak's). EnvCloak's own command written inline, and a plugin
/// switched off, are not (the controls); each change moves the
/// fingerprint, and taking it out gives the first again. Claude Code: a
/// plugin other than EnvCloak's enabled is said so too.
///
/// Mutation checked: the layers' own hooks not read (`cs.foreign_prompt_hook
/// |= unseen || layers().any(..)` in `read_codex` dropped): the user's
/// inline hook gives no `foreign_prompt_hook` and this fails.
#[test]
fn prompt_hooks_in_every_codex_layer_are_said_so() {
    const INLINE: &str = "[[hooks.UserPromptSubmit]]\n\
                          hooks = [{ type = \"command\", command = \"/usr/bin/true\" }]\n";
    let h = Home::new();
    h.codex_installed();
    let base = h.read(Host::Codex, &[]);
    assert!(!base.foreign_prompt_hook, "the control: EnvCloak's alone");
    let fp = base.fingerprint(&h.envcloak).unwrap();
    let user = h.home.join(".codex/config.toml");
    let installed = std::fs::read_to_string(&user).unwrap();
    let ours = format!(
        "[[hooks.UserPromptSubmit]]\nhooks = [{{ type = \"command\", command = {} }}]\n",
        toml_quote(&hook_command(
            &h.envcloak,
            Host::Codex,
            Event::UserPromptSubmit
        ))
    );
    let cases: Vec<(&str, PathBuf, String, bool)> = vec![
        (
            "the user's",
            user.clone(),
            format!("{installed}{INLINE}"),
            true,
        ),
        (
            "EnvCloak's own, inline",
            user.clone(),
            format!("{installed}{ours}"),
            false,
        ),
        (
            "a plugin enabled",
            user.clone(),
            format!("{installed}[plugins.\"other@market\"]\nenabled = true\n"),
            true,
        ),
        (
            "a plugin with no switch",
            user.clone(),
            format!("{installed}[plugins.\"other@market\"]\n"),
            true,
        ),
        (
            "a plugin switched off",
            user.clone(),
            format!("{installed}[plugins.\"other@market\"]\nenabled = false\n"),
            false,
        ),
        (
            "the system's",
            h.system.join("config.toml"),
            INLINE.to_owned(),
            true,
        ),
        (
            "a profile's",
            h.home.join(".codex/work.config.toml"),
            INLINE.to_owned(),
            true,
        ),
        (
            "a project's",
            h.project.join(".codex/config.toml"),
            INLINE.to_owned(),
            true,
        ),
        (
            "the managed layer's",
            h.system.join("managed_config.toml"),
            INLINE.to_owned(),
            true,
        ),
        (
            "the requirements'",
            h.system.join("requirements.toml"),
            INLINE.to_owned(),
            true,
        ),
        (
            "a layer that is not TOML",
            h.project.join(".codex/config.toml"),
            "[not toml".to_owned(),
            true,
        ),
        (
            "a device profile",
            h.managed_prefs.join("com.openai.codex.plist"),
            "opaque".to_owned(),
            true,
        ),
    ];
    for (name, file, text, foreign) in cases {
        let before = std::fs::read_to_string(&file).ok();
        h.write(&file, &text);
        let cs = h.read(Host::Codex, &[]);
        assert_eq!(cs.foreign_prompt_hook, foreign, "{name}");
        assert_ne!(cs.fingerprint(&h.envcloak), Some(fp.clone()), "{name}");
        match before {
            Some(b) => h.write(&file, &b),
            None => std::fs::remove_file(&file).unwrap(),
        }
        let back = h.read(Host::Codex, &[]);
        assert!(!back.foreign_prompt_hook, "{name}: taken out");
        assert_eq!(back.fingerprint(&h.envcloak), Some(fp.clone()), "{name}");
    }
    // Claude Code: another plugin enabled; EnvCloak's own is not another's.
    let h = Home::new();
    h.claude_installed(json!({"enabledPlugins": {"envcloak@envcloak": false}}));
    assert!(!h.read(Host::ClaudeCode, &[]).foreign_prompt_hook);
    h.claude_installed(json!({"enabledPlugins": {"other@market": true}}));
    assert!(h.read(Host::ClaudeCode, &[]).foreign_prompt_hook);
}

/// `s` as a TOML basic string.
fn toml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// EnvCloak's Claude Code plugin, installed as Claude Code records it:
/// enabled in the user's settings, its install in
/// `plugins/installed_plugins.json`, its hooks, server and manifest there,
/// and `envcloak` on `PATH`. The install's folder.
fn plugin_install(h: &Home) -> PathBuf {
    h.claude_installed(json!({"enabledPlugins": {"envcloak@envcloak": true}}));
    let dir = h.root.join("plugin-install");
    h.write(
        &dir.join("hooks/hooks.json"),
        r#"{"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "envcloak hook --host claude-code --event UserPromptSubmit"}]}]}}"#,
    );
    h.write(
        &dir.join(".mcp.json"),
        r#"{"mcpServers": {"envcloak": {"command": "envcloak", "args": ["mcp"]}}}"#,
    );
    h.write(
        &dir.join(".claude-plugin/plugin.json"),
        r#"{"name": "envcloak", "version": "1.0.0"}"#,
    );
    h.write(
        &h.home.join(".claude/plugins/installed_plugins.json"),
        &json!({"version": 2, "plugins": {"envcloak@envcloak": [
            {"scope": "user", "installPath": dir.to_string_lossy()}
        ]}})
        .to_string(),
    );
    dir
}

/// The part of the probe context EnvCloak's Claude Code plugin gives (the
/// verifier's round-3 finding: no test covered it, so dropping it, or its
/// incompleteness, failed nothing): a change to the plugin's hooks, its
/// server's file, its manifest, Claude Code's record of the install or the
/// `envcloak` it finds on `PATH` makes a result kept for the first stale,
/// and putting it back makes it current again; with no record of the
/// install, a record without the plugin or without its folder, its hooks
/// file gone, or no `envcloak` on `PATH`, there is no fingerprint at all.
///
/// Mutations checked: the `plugin_context` call in `read_claude` dropped:
/// the plugin's hooks change and the fingerprint stays, and this fails;
/// `if !found { ctx.complete = false; }` dropped: with no record of the
/// install a fingerprint is given, and this fails.
#[test]
fn the_plugin_context_makes_a_result_stale() {
    let h = Home::new();
    let dir = plugin_install(&h);
    let bin = h.root.join("bin");
    let path = [("PATH", bin.to_str().unwrap())];
    let fp = || h.read(Host::ClaudeCode, &path).fingerprint(&h.envcloak);
    let first = fp();
    assert!(first.is_some(), "the plugin install wholly identified");
    let cs = h.read(Host::ClaudeCode, &path);
    assert!(cs.server.registered);
    assert_eq!(cs.hooks.prompt, HookState::Present);
    let record = h.home.join(".claude/plugins/installed_plugins.json");
    for (name, file) in [
        ("the plugin's hooks", dir.join("hooks/hooks.json")),
        ("the plugin's server", dir.join(".mcp.json")),
        (
            "the plugin's manifest",
            dir.join(".claude-plugin/plugin.json"),
        ),
        ("the record of the install", record.clone()),
        ("the envcloak on PATH", h.envcloak.clone()),
    ] {
        let kept = std::fs::read(&file).unwrap();
        let mut changed = kept.clone();
        changed.extend_from_slice(b"\n");
        std::fs::write(&file, &changed).unwrap();
        assert_ne!(fp(), first, "{name}: still current");
        std::fs::write(&file, &kept).unwrap();
        assert_eq!(fp(), first, "{name}: put back");
    }
    // Not wholly identified: no fingerprint.
    let kept = std::fs::read(&record).unwrap();
    for (name, text) in [
        ("no record of the install", None),
        (
            "a record without the plugin",
            Some(json!({"version": 2, "plugins": {"other@market": [{"installPath": "/x"}]}})),
        ),
        (
            "a record without its folder",
            Some(json!({"version": 2, "plugins": {"envcloak@envcloak": [{"scope": "user"}]}})),
        ),
    ] {
        match text {
            None => std::fs::remove_file(&record).unwrap(),
            Some(v) => h.write(&record, &v.to_string()),
        }
        assert_eq!(fp(), None, "{name}");
        std::fs::write(&record, &kept).unwrap();
        assert_eq!(fp(), first, "{name}: put back");
    }
    let hooks = dir.join("hooks/hooks.json");
    let kept = std::fs::read(&hooks).unwrap();
    std::fs::remove_file(&hooks).unwrap();
    assert_eq!(fp(), None, "the plugin's hooks gone");
    std::fs::write(&hooks, &kept).unwrap();
    assert_eq!(fp(), first);
    let elsewhere = h.root.join("no-envcloak-here");
    std::fs::create_dir_all(&elsewhere).unwrap();
    assert_eq!(
        h.read(Host::ClaudeCode, &[("PATH", elsewhere.to_str().unwrap())])
            .fingerprint(&h.envcloak),
        None,
        "no envcloak on PATH"
    );
}

/// Each part of the probe context a result rests on, on both hosts: a
/// change to it makes the fingerprint another, and taking the change back
/// gives the first (the class of the verifier's and Codex's round-3
/// findings: a part a result depends on left out, so a cached result read
/// current). The files of every layer and level each host reads, the hook
/// files, the registrations, Codex's rules, and the environment that
/// places the stores (Codex's round-3 review: `CLAUDE_CODE_TMPDIR`,
/// `TMPDIR` and `CODEX_SQLITE_HOME` moved what the transcript probe has to
/// read, and a result stayed current).
///
/// Mutation checked: the stores left out of the context (the
/// `cs.context.store` loop over the catalog's stores in `read_codex`
/// dropped): `CODEX_SQLITE_HOME` and `TMPDIR` leave the fingerprint as it
/// was and this fails.
#[test]
fn every_part_of_the_probe_context_makes_a_result_stale() {
    let h = Home::new();
    h.claude_installed(json!({}));
    h.codex_installed();
    std::fs::create_dir_all(h.project.join(".git")).unwrap();
    let sub = h.project.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let fp = |host: Host, env: &[(&str, &str)]| {
        h.read_in(host, &sub, env).fingerprint(&h.envcloak).unwrap()
    };
    let claude_files = [
        h.home.join(".claude/settings.json"),
        sub.join(".claude/settings.json"),
        sub.join(".claude/settings.local.json"),
        h.project.join(".claude/settings.local.json"),
        h.claude_managed.join("managed-settings.json"),
        h.claude_managed.join("managed-settings.d/10-policy.json"),
        sub.join(".mcp.json"),
        h.home.join(".mcp.json"),
        h.claude_managed.join("managed-mcp.json"),
    ];
    let codex_files = [
        h.system.join("config.toml"),
        h.home.join(".codex/config.toml"),
        h.home.join(".codex/work.config.toml"),
        sub.join(".codex/config.toml"),
        h.project.join(".codex/config.toml"),
        h.system.join("managed_config.toml"),
        h.system.join("requirements.toml"),
        h.home.join(".codex/hooks.json"),
        sub.join(".codex/hooks.json"),
        h.system.join("hooks.json"),
        h.home.join(".codex/rules/mine.rules"),
        h.managed_prefs.join("com.openai.codex.plist"),
        h.home.join(".codex/cloud-config-bundle-cache.json"),
    ];
    for (host, files) in [
        (Host::ClaudeCode, &claude_files[..]),
        (Host::Codex, &codex_files[..]),
    ] {
        let first = fp(host, &[]);
        for file in files {
            let kept = std::fs::read(file).ok();
            let mut text = kept.clone().unwrap_or_default();
            // Valid in its format, as a person's edit is.
            text.extend_from_slice(match file.extension().and_then(|e| e.to_str()) {
                Some("json") if kept.is_some() => b" ",
                Some("json") => b"{}",
                Some("toml") => b"\n# another setting\n",
                _ => b"\n",
            });
            h.write(file, std::str::from_utf8(&text).unwrap());
            assert_ne!(fp(host, &[]), first, "{host:?}: {}", file.display());
            match kept {
                Some(k) => std::fs::write(file, k).unwrap(),
                None => std::fs::remove_file(file).unwrap(),
            }
            assert_eq!(
                fp(host, &[]),
                first,
                "{host:?}: {} put back",
                file.display()
            );
        }
    }
    // Claude Code's registration of EnvCloak's server.
    let first = fp(Host::ClaudeCode, &[]);
    h.write(
        &h.home.join(".claude.json"),
        r#"{"mcpServers": {"envcloak": {"command": "/x"}}}"#,
    );
    assert_ne!(fp(Host::ClaudeCode, &[]), first, "the registration");
    std::fs::remove_file(h.home.join(".claude.json")).unwrap();
    assert_eq!(fp(Host::ClaudeCode, &[]), first);
    // The environment that places the stores.
    let a = h.root.join("a");
    let b = h.root.join("b");
    for (host, var) in [
        (Host::ClaudeCode, "CLAUDE_CODE_TMPDIR"),
        (Host::Codex, "TMPDIR"),
        (Host::Codex, "CODEX_SQLITE_HOME"),
    ] {
        let at_a = fp(host, &[(var, a.to_str().unwrap())]);
        assert_eq!(at_a, fp(host, &[(var, a.to_str().unwrap())]), "{var}");
        assert_ne!(at_a, fp(host, &[(var, b.to_str().unwrap())]), "{var}");
        assert_ne!(at_a, fp(host, &[]), "{var} unset");
    }
}

/// The stores the transcript probe sweeps are where the host's environment
/// and every layer of its settings put them (Codex's round-3 review: a
/// store a layer other than the user's moved was never swept, and the
/// sweep still read whole): Codex's `log_dir` and `sqlite_home` in each
/// layer (a relative path from the layer's folder, `~/` from the home),
/// `CODEX_SQLITE_HOME`, `TMPDIR` (its hook outputs), Claude Code's
/// `CLAUDE_CODE_TMPDIR`. A blocked prompt kept in each is found by a sweep
/// of the context's stores; a file there the sweep cannot read whole makes
/// it incomplete; a layer that cannot be read, one EnvCloak cannot read, or
/// a move to what is not a path leaves the stores not known.
///
/// Mutation checked: only the user's layer's moves read (the `for layer in
/// layers()` loop over the stores taking `[&user]`): the project's
/// `log_dir` is not swept and this fails.
#[test]
fn the_stores_follow_every_layer_and_the_environment() {
    use envcloak_agents::probe::controls::{SWEEP_FILE_CAP, forms, key_shaped, sweep};
    let generated = key_shaped().unwrap();
    let token_text: &str = generated.as_str();
    let token = forms(token_text.as_bytes());
    let h = Home::new();
    h.codex_installed();
    let base = h.read(Host::Codex, &[]);
    assert!(base.context.stores_known, "the control");
    let moved = |name: &str| h.root.join("moved").join(name);
    let env_sqlite = moved("env-sqlite");
    let tmp = moved("tmp");
    let env = [
        ("CODEX_SQLITE_HOME", env_sqlite.to_str().unwrap()),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    // Each layer moves a store of its own.
    let layers: Vec<(PathBuf, String, PathBuf, &str)> = vec![
        (
            h.system.join("config.toml"),
            format!(
                "log_dir = {}\n",
                toml_quote(moved("system-log").to_str().unwrap())
            ),
            moved("system-log"),
            "session.log",
        ),
        (
            h.home.join(".codex/work.config.toml"),
            "sqlite_home = \"profile-sqlite\"\n".to_owned(),
            h.home.join(".codex/profile-sqlite"),
            "state_5.sqlite",
        ),
        (
            h.project.join(".codex/config.toml"),
            "log_dir = \"logs\"\n".to_owned(),
            h.project.join(".codex/logs"),
            "codex-tui.log",
        ),
        (
            h.system.join("managed_config.toml"),
            "sqlite_home = \"~/managed-sqlite\"\n".to_owned(),
            h.home.join("managed-sqlite"),
            "logs_2.sqlite",
        ),
    ];
    for (file, text, _, _) in &layers {
        h.write(file, text);
    }
    let cs = h.read(Host::Codex, &env);
    assert!(cs.context.stores_known);
    let mut stores: Vec<(PathBuf, &str)> = layers
        .iter()
        .map(|(_, _, dir, f)| (dir.clone(), *f))
        .collect();
    stores.push((env_sqlite.clone(), "state_5.sqlite"));
    stores.push((tmp.join("hook_outputs"), "out.txt"));
    for (dir, file) in &stores {
        assert!(
            cs.context
                .stores
                .iter()
                .any(|s| Path::new(&s.path) == dir.as_path()),
            "{} is not among the stores",
            dir.display()
        );
        // A blocked prompt kept there is found by the sweep.
        h.write(&dir.join(file), &format!("x {token_text} y"));
        let s = sweep(&cs.context.sweep_roots(), &[&token]);
        assert!(s.found[0], "{}", dir.display());
        assert!(s.complete, "{}", dir.display());
        std::fs::remove_file(dir.join(file)).unwrap();
        assert!(!sweep(&cs.context.sweep_roots(), &[&token]).found[0]);
    }
    // A file in a moved store the sweep cannot read whole.
    let large = h.project.join(".codex/logs/large.log");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(SWEEP_FILE_CAP + 1)
        .unwrap();
    assert!(!sweep(&cs.context.sweep_roots(), &[&token]).complete);
    std::fs::remove_file(&large).unwrap();
    assert!(sweep(&cs.context.sweep_roots(), &[&token]).complete);
    // What leaves the stores not known.
    let project = h.project.join(".codex/config.toml");
    for (name, file, text) in [
        ("a layer that is not TOML", project.clone(), "[not toml"),
        (
            "a move to what is not a path",
            project.clone(),
            "log_dir = 3\n",
        ),
        (
            "a move to an empty path",
            project.clone(),
            "sqlite_home = \"\"\n",
        ),
        (
            "a device profile",
            h.managed_prefs.join("com.openai.codex.plist"),
            "opaque",
        ),
    ] {
        let kept = std::fs::read_to_string(&file).ok();
        h.write(&file, text);
        assert!(!h.read(Host::Codex, &env).context.stores_known, "{name}");
        match kept {
            Some(k) => h.write(&file, &k),
            None => std::fs::remove_file(&file).unwrap(),
        }
        assert!(h.read(Host::Codex, &env).context.stores_known, "{name}");
    }
    // Claude Code: its temporary directory, where its environment puts it;
    // no setting moves a store, so they are known.
    let h = Home::new();
    h.claude_installed(json!({}));
    let claude_tmp = h.root.join("claude-tmp");
    let cs = h.read(
        Host::ClaudeCode,
        &[("CLAUDE_CODE_TMPDIR", claude_tmp.to_str().unwrap())],
    );
    assert!(cs.context.stores_known);
    h.write(&claude_tmp.join("claude-0-cwd"), token_text);
    assert!(sweep(&cs.context.sweep_roots(), &[&token]).found[0]);
    // Another temporary directory (never the machine's own `/tmp`, whose
    // files are not this test's): the kept prompt is not among its stores.
    let other_tmp = h.root.join("other-tmp");
    std::fs::create_dir_all(&other_tmp).unwrap();
    let elsewhere = h.read(
        Host::ClaudeCode,
        &[("CLAUDE_CODE_TMPDIR", other_tmp.to_str().unwrap())],
    );
    assert!(
        elsewhere
            .context
            .stores
            .iter()
            .all(|s| Path::new(&s.path).starts_with(&h.root)),
        "{:?}",
        elsewhere.context.stores
    );
    assert!(!sweep(&elsewhere.context.sweep_roots(), &[&token]).found[0]);
}

/// How the host lets an agent call `run_with_secrets` follows every switch
/// that takes EnvCloak's server or its tool away (Codex's round-3 review:
/// `callable` rested on the registration and the approval alone): Claude
/// Code's `disabledMcpServers` for the directory or a folder above, a
/// project's server rejected (`disabledMcpjsonServers`) or not approved,
/// an organization's `deniedMcpServers` naming it or `allowedMcpServers`
/// leaving it out, and the plugin's server, which a rule for
/// `mcp__envcloak__` does not name; Codex's `enabled = false`, an
/// `enabled_tools` without it and a `disabled_tools` with it, the highest
/// layer's. Each refused one reads `needs_host_approval` in the report,
/// never `callable`; a list matched by command, or layers a session may
/// read either way that disagree, are not known (`listed`).
///
/// Mutations checked: `claude_availability` without the `disabled` check:
/// the server switched off reads callable and this fails; `codex_merge`
/// without its `off` (the approval kept whatever the lists say): the tool
/// left out of `enabled_tools` reads callable and this fails.
#[test]
fn availability_follows_what_switches_the_server_or_its_tool_off() {
    use coverage::{Availability, Probed, assemble};
    const TOOL: &str = "mcp__envcloak__run_with_secrets";
    const MCP: &str = r#"{"mcpServers": {"envcloak": {"command": "/x/envcloak"}}}"#;
    let availability = |cs: &ConfigSet, host: Host| {
        assemble(host, "1.0.0", cs, Probed::None)
            .envcloak_server
            .map(|l| l.availability)
    };
    type Setup = Box<dyn Fn(&Home)>;
    let user_server = |h: &Home| h.write(&h.home.join(".claude.json"), MCP);
    let project_server = |h: &Home| h.write(&h.project.join(".mcp.json"), MCP);
    let managed = |h: &Home, text: &str| {
        h.write(&h.claude_managed.join("managed-settings.json"), text);
    };
    let local = |h: &Home, text: &str| {
        h.write(&h.project.join(".claude/settings.local.json"), text);
    };
    let claude: Vec<(&str, Setup, Option<bool>)> = vec![
        (
            "registered and allowed",
            Box::new(move |h| user_server(h)),
            Some(true),
        ),
        (
            "switched off for the directory",
            Box::new(move |h| {
                let cwd = std::fs::canonicalize(&h.project).unwrap();
                h.write(
                    &h.home.join(".claude.json"),
                    &json!({"mcpServers": {"envcloak": {"command": "/x/envcloak"}},
                        "projects": {cwd.to_string_lossy(): {"disabledMcpServers": ["envcloak"]}}})
                    .to_string(),
                );
            }),
            Some(false),
        ),
        (
            "switched off for a folder above",
            Box::new(move |h| {
                h.write(
                    &h.home.join(".claude.json"),
                    &json!({"mcpServers": {"envcloak": {"command": "/x/envcloak"}},
                        "projects": {h.home.to_string_lossy(): {"disabledMcpServers": ["envcloak"]}}})
                    .to_string(),
                );
            }),
            Some(false),
        ),
        (
            "a project's server, not approved",
            Box::new(move |h| project_server(h)),
            Some(false),
        ),
        (
            "a project's server, approved by name",
            Box::new(move |h| {
                project_server(h);
                local(h, r#"{"enabledMcpjsonServers": ["envcloak"]}"#);
            }),
            Some(true),
        ),
        (
            "a project's server, all approved",
            Box::new(move |h| {
                project_server(h);
                local(h, r#"{"enableAllProjectMcpServers": true}"#);
            }),
            Some(true),
        ),
        (
            "a project's server, approved and rejected",
            Box::new(move |h| {
                project_server(h);
                local(
                    h,
                    r#"{"enableAllProjectMcpServers": true, "disabledMcpjsonServers": ["envcloak"]}"#,
                );
            }),
            Some(false),
        ),
        (
            "an organization's denial by name",
            Box::new(move |h| {
                user_server(h);
                managed(h, r#"{"deniedMcpServers": [{"serverName": "envcloak"}]}"#);
            }),
            Some(false),
        ),
        (
            "an organization's allow list without it",
            Box::new(move |h| {
                user_server(h);
                managed(h, r#"{"allowedMcpServers": [{"serverName": "github"}]}"#);
            }),
            Some(false),
        ),
        (
            "an organization's allow list with it",
            Box::new(move |h| {
                user_server(h);
                managed(
                    h,
                    r#"{"allowedMcpServers": [{"serverName": "envcloak"}, {"serverCommand": ["x"]}]}"#,
                );
            }),
            Some(true),
        ),
        (
            "an organization's denial by command",
            Box::new(move |h| {
                user_server(h);
                managed(
                    h,
                    r#"{"deniedMcpServers": [{"serverCommand": ["/x/envcloak"]}]}"#,
                );
            }),
            None,
        ),
        (
            "an organization's denial of another by name",
            Box::new(move |h| {
                user_server(h);
                managed(h, r#"{"deniedMcpServers": [{"serverName": "github"}]}"#);
            }),
            Some(true),
        ),
    ];
    for (name, setup, want) in claude {
        let h = Home::new();
        h.claude_installed(json!({"permissions": {"allow": [TOOL]}}));
        setup(&h);
        let cs = h.read(Host::ClaudeCode, &[]);
        assert!(cs.server.registered, "{name}");
        assert_eq!(cs.server.run_with_secrets_approved, want, "{name}");
        let shown = match want {
            Some(true) => Availability::Callable,
            Some(false) => Availability::NeedsHostApproval,
            None => Availability::Listed,
        };
        assert_eq!(availability(&cs, Host::ClaudeCode), Some(shown), "{name}");
    }
    // The plugin's server: a rule for `mcp__envcloak__` does not name it;
    // bypass runs it with no rule; switched off, it is off.
    let h = Home::new();
    plugin_install(&h);
    let bin = h.root.join("bin");
    let path = [("PATH", bin.to_str().unwrap())];
    let approved = || {
        h.read(Host::ClaudeCode, &path)
            .server
            .run_with_secrets_approved
    };
    h.claude_installed(json!({"enabledPlugins": {"envcloak@envcloak": true},
        "permissions": {"allow": [TOOL]}}));
    assert_eq!(
        approved(),
        Some(false),
        "the plugin's server, a rule for another name"
    );
    h.claude_installed(json!({"enabledPlugins": {"envcloak@envcloak": true},
        "permissions": {"defaultMode": "bypassPermissions"}}));
    assert_eq!(approved(), Some(true), "the plugin's server, bypass");
    let cwd = std::fs::canonicalize(&h.project).unwrap();
    h.write(
        &h.home.join(".claude.json"),
        &json!({"projects": {cwd.to_string_lossy(): {"disabledMcpServers": ["plugin:envcloak:envcloak"]}}})
            .to_string(),
    );
    assert_eq!(approved(), Some(false), "the plugin's server switched off");
    // Codex.
    const APPROVE: &str =
        "\n[mcp_servers.envcloak.tools.run_with_secrets]\napproval_mode = \"approve\"\n";
    const SERVER: &str = "[mcp_servers.envcloak]\ncommand = \"/x/envcloak\"\n";
    type CodexCase<'a> = (&'a str, String, Option<(&'a str, &'a str)>, Option<bool>);
    let codex: Vec<CodexCase<'_>> = vec![
        ("approved", format!("{SERVER}{APPROVE}"), None, Some(true)),
        (
            "switched off",
            format!("{SERVER}enabled = false\n{APPROVE}"),
            None,
            Some(false),
        ),
        (
            "switched on",
            format!("{SERVER}enabled = true\n{APPROVE}"),
            None,
            Some(true),
        ),
        (
            "a list of tools without it",
            format!("{SERVER}enabled_tools = [\"list_secrets\"]\n{APPROVE}"),
            None,
            Some(false),
        ),
        (
            "a list of tools with it",
            format!("{SERVER}enabled_tools = [\"run_with_secrets\"]\n{APPROVE}"),
            None,
            Some(true),
        ),
        (
            "a list of hidden tools with it",
            format!("{SERVER}disabled_tools = [\"run_with_secrets\"]\n{APPROVE}"),
            None,
            Some(false),
        ),
        (
            "a list of hidden tools without it",
            format!("{SERVER}disabled_tools = [\"list_secrets\"]\n{APPROVE}"),
            None,
            Some(true),
        ),
        (
            "a list that is not of names",
            format!("{SERVER}enabled_tools = [1]\n{APPROVE}"),
            None,
            Some(false),
        ),
        (
            "switched off by the managed layer",
            format!("{SERVER}{APPROVE}"),
            Some((
                "managed_config.toml",
                "[mcp_servers.envcloak]\nenabled = false\n",
            )),
            Some(false),
        ),
        (
            "switched off by the system layer, under the user's switch on",
            format!("{SERVER}enabled = true\n{APPROVE}"),
            Some(("config.toml", "[mcp_servers.envcloak]\nenabled = false\n")),
            Some(true),
        ),
    ];
    for (name, user, system, want) in codex {
        let h = Home::new();
        h.codex_installed();
        h.write(&h.home.join(".codex/config.toml"), &user);
        if let Some((file, text)) = system {
            h.write(&h.system.join(file), text);
        }
        let cs = h.read(Host::Codex, &[]);
        assert!(cs.server.registered, "{name}");
        assert_eq!(cs.server.run_with_secrets_approved, want, "{name}");
        if want == Some(false) {
            assert_eq!(
                availability(&cs, Host::Codex),
                Some(Availability::NeedsHostApproval),
                "{name}"
            );
        }
    }
    // A project's switch, which a session reads only in a trusted
    // project: the readings disagree, so not known.
    let h = Home::new();
    h.codex_installed();
    h.write(
        &h.home.join(".codex/config.toml"),
        &format!("{SERVER}{APPROVE}"),
    );
    h.write(
        &h.project.join(".codex/config.toml"),
        "[mcp_servers.envcloak]\nenabled_tools = []\n",
    );
    assert_eq!(
        h.read(Host::Codex, &[]).server.run_with_secrets_approved,
        None
    );
}
