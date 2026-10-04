//! Codex review, round 7 (medium): a project's uninstall ignored
//! `--agent`. Every project file was recorded under `project`, and
//! uninstall took out every record of the directory, so uninstalling
//! Codex also took out the block Claude Code was installed to read.
//!
//! EnvCloak's record of a project file now keeps the hosts its block was
//! installed for, and uninstall for some hosts takes a block out only
//! once none of them is left. Through the public API, with a project's
//! own files:
//!
//! - a `CLAUDE.md` (Claude Code's) and an `AGENTS.md` (Codex's): Codex's
//!   uninstall gives `AGENTS.md` back byte for byte and leaves the block
//!   in `CLAUDE.md`; Claude Code's then gives that back;
//! - a lone `AGENTS.md`, which both read: Codex's uninstall keeps the
//!   block and says Claude Code still reads it, and the dry run says the
//!   same (`project_shares`); Claude Code's then takes it out;
//! - installed for Claude Code alone: Codex's uninstall does not touch
//!   it; installed for Claude Code, then for Codex in a second run: both
//!   are kept as readers;
//! - a record made before readers were kept (none listed) counts every
//!   host: one host's uninstall keeps the block.
//!
//! Mutations checked: `project_shares` answering every file of the
//! directory with no host left (as before): Codex's uninstall takes out
//! Claude Code's block and this fails; no host left for any file the
//! selected hosts share: the dry run says the shared block goes, and this
//! fails; the hosts not recorded at install (`add_readers` not called):
//! Codex's uninstall touches the block installed for Claude Code alone,
//! and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_agents::hook::Host;
use envcloak_agents::install::{self, Context, Options, Report};
use envcloak_agents::locations::Locations;
use envcloak_agents::writer::{Backups, Journal, Outcome, Refusal, State, Writer};

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
    state: State,
}

const CLAUDE: &[u8] = b"# Claude notes\n\nUse the tests.\n";
const AGENTS: &[u8] = b"# Agent notes\n\nKeep it small.\n";

impl Fx {
    fn new(files: &[(&str, &[u8])]) -> Fx {
        let dir = tempfile::Builder::new()
            .prefix("ecph")
            .tempdir_in("/tmp")
            .unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("home/.codex")).unwrap();
        std::fs::create_dir_all(root.join("home/.claude")).unwrap();
        std::fs::create_dir_all(root.join("proj/.git")).unwrap();
        for (name, bytes) in files {
            let p = root.join("proj").join(name);
            std::fs::write(&p, bytes).unwrap();
            // Written ten minutes ago, as a person's file would be.
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(600))
                .unwrap();
        }
        Fx {
            _dir: dir,
            root,
            state: State::default(),
        }
    }

    fn proj(&self, name: &str) -> PathBuf {
        self.root.join("proj").join(name)
    }

    fn run(&mut self, hosts: &[Host], uninstall: bool) -> Report {
        let home = self.root.join("home").into_os_string();
        let env = move |k: &str| (k == "HOME").then(|| home.clone());
        let ctx = Context {
            locations: Locations::new(&env)
                .unwrap()
                .with_system_dirs(self.root.join("etc-codex"), self.root.join("prefs")),
            envcloak: self.root.join("envcloak"),
            data_dir: self.root.join("data"),
            socket: self.root.join("socket"),
            path: OsString::new(),
            env: &env,
        };
        let opts = Options {
            hosts: hosts.to_vec(),
            global: false,
            project: Some(self.root.join("proj")),
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

    fn holds_block(&self, name: &str) -> bool {
        String::from_utf8(std::fs::read(self.proj(name)).unwrap())
            .unwrap()
            .contains("envcloak")
    }

    fn scope(&self) -> String {
        self.root.join("proj").to_string_lossy().into_owned()
    }
}

/// The outcomes a report's project part holds, by file name.
fn outcomes(r: &Report) -> Vec<(String, &'static str)> {
    r.project
        .as_ref()
        .unwrap()
        .results
        .iter()
        .map(|s| {
            let name = s.path.file_name().unwrap().to_string_lossy().into_owned();
            let o = match &s.outcome {
                Outcome::Unchanged => "kept",
                Outcome::Changed { .. } => "changed",
                Outcome::Removed { .. } => "removed",
                Outcome::Partial { .. } => "partial",
                Outcome::Refused(_) => "refused",
            };
            (name, o)
        })
        .collect()
}

#[test]
fn a_projects_block_stays_while_a_host_it_was_installed_for_is_left() {
    let both = [Host::ClaudeCode, Host::Codex];

    // Each host its own file.
    let mut fx = Fx::new(&[("CLAUDE.md", CLAUDE), ("AGENTS.md", AGENTS)]);
    let r = fx.run(&both, false);
    assert!(r.complete(), "{r:?}");
    assert!(fx.holds_block("CLAUDE.md") && fx.holds_block("AGENTS.md"));
    let r = fx.run(&[Host::Codex], true);
    assert!(r.complete(), "{r:?}");
    assert_eq!(std::fs::read(fx.proj("AGENTS.md")).unwrap(), AGENTS);
    assert!(
        fx.holds_block("CLAUDE.md"),
        "Claude Code's block was taken out"
    );
    let r = fx.run(&[Host::ClaudeCode], true);
    assert!(r.complete(), "{r:?}");
    assert_eq!(std::fs::read(fx.proj("CLAUDE.md")).unwrap(), CLAUDE);
    assert!(fx.state.files.is_empty(), "{:?}", fx.state.files);

    // One file both read.
    let mut fx = Fx::new(&[("AGENTS.md", AGENTS)]);
    let r = fx.run(&both, false);
    assert!(r.complete(), "{r:?}");
    let shares = install::project_shares(&fx.state, &fx.scope(), &[Host::Codex]);
    assert_eq!(shares.len(), 1, "{shares:?}");
    assert_eq!(shares[0].1, ["claude-code"], "the dry run: {shares:?}");
    let r = fx.run(&[Host::Codex], true);
    assert!(r.complete(), "{r:?}");
    assert_eq!(outcomes(&r), [("AGENTS.md".to_owned(), "kept")]);
    let what = &r.project.as_ref().unwrap().results[0].what;
    assert!(what.contains("Claude Code"), "{what}");
    assert!(
        fx.holds_block("AGENTS.md"),
        "the shared block was taken out"
    );
    let r = fx.run(&[Host::ClaudeCode], true);
    assert!(r.complete(), "{r:?}");
    assert_eq!(std::fs::read(fx.proj("AGENTS.md")).unwrap(), AGENTS);

    // Installed for Claude Code alone, then for Codex too.
    let mut fx = Fx::new(&[("AGENTS.md", AGENTS)]);
    fx.run(&[Host::ClaudeCode], false);
    let r = fx.run(&[Host::Codex], true);
    assert!(outcomes(&r).is_empty(), "{r:?}");
    assert!(fx.holds_block("AGENTS.md"));
    fx.run(&[Host::Codex], false);
    let readers: Vec<&Vec<String>> = fx.state.files.values().map(|r| &r.readers).collect();
    assert_eq!(
        readers,
        [&vec!["claude-code".to_owned(), "codex".to_owned()]]
    );
    fx.run(&[Host::ClaudeCode], true);
    assert!(fx.holds_block("AGENTS.md"), "Codex's block was taken out");
    fx.run(&[Host::Codex], true);
    assert_eq!(std::fs::read(fx.proj("AGENTS.md")).unwrap(), AGENTS);

    // A record made before readers were kept: every host.
    let mut fx = Fx::new(&[("AGENTS.md", AGENTS)]);
    fx.run(&[Host::Codex], false);
    for r in fx.state.files.values_mut() {
        r.readers.clear();
    }
    let r = fx.run(&[Host::Codex], true);
    assert_eq!(outcomes(&r), [("AGENTS.md".to_owned(), "kept")]);
    assert!(fx.holds_block("AGENTS.md"));
    fx.run(&[Host::ClaudeCode], true);
    assert_eq!(std::fs::read(fx.proj("AGENTS.md")).unwrap(), AGENTS);
}
