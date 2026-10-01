//! The stores an agent host writes what it saw into, and their sweep (M2
//! plan task M2-04; decision D-15, gate 41, SI-18).
//!
//! [`transcript_roots`] lists, per host, every store D-15 names that can
//! hold a pasted or printed value, and the ones M2-04 saw the pinned
//! versions write besides (docs/ACCEPTANCE.md, "Host stores"). A sweep
//! ([`sweep_stores`]) reads the host's whole directory once with
//! [`crate::sweep_dir`], for every canary and every listed encoding, and
//! files each hit in the host's files under the store that holds it; a
//! hit in none of them is kept under [`OTHER`], never dropped. Counts are
//! raw: nothing is filtered, the harness's own canaries included, so a
//! positive control (a canary a scripted turn prints) is counted like
//! anything else. The scripted model's request bodies are swept too
//! ([`sweep_model`]): what a host sent its model is what a real model
//! would have seen. Both read through up to
//! [`crate::detect::JSON_LEVELS`] levels of JSON string escaping, since a
//! host keeps what a command printed as a JSON string, sometimes inside
//! another, and a value escaped again matches none of its listed
//! encodings as stored.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::agents::{AgentHome, Host, ModelReport};
use crate::canary::Canary;
use crate::detect::{Detector, Found, Hit, sweep_dir};

/// Where a hit outside every listed store of a host is filed.
pub const OTHER: &str = "other";

/// What a store holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// Conversation transcripts.
    Transcript,
    /// Prompt history.
    History,
    /// Pasted text kept aside.
    PasteCache,
    /// Copies of files the host edited.
    FileHistory,
    /// Backups of the host's own configuration.
    Backup,
    /// Logs.
    Log,
    /// SQLite databases.
    Database,
    /// Anything else the host keeps per session.
    Session,
    /// The host's own configuration.
    Config,
    /// Files the host deletes once it is done with them (what a running
    /// command printed so far); a host stopped half way leaves them.
    Transient,
}

/// How a store's files are recognised under its root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A directory, everything below it.
    Dir,
    /// One file.
    File,
    /// Files directly in the root whose names contain the text.
    Named(&'static str),
}

/// One store of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    /// The host's catalog id.
    pub host: &'static str,
    /// A short, stable name, such as `claude/projects`.
    pub name: &'static str,
    /// Where it is in this home.
    pub path: PathBuf,
    pub shape: Shape,
    pub kind: StoreKind,
    /// `D-15`, or `observed` for one M2-04 saw the pinned version write.
    pub source: &'static str,
}

impl Store {
    fn holds(&self, file: &Path) -> bool {
        match self.shape {
            Shape::Dir => file.starts_with(&self.path),
            Shape::File => file == self.path,
            Shape::Named(part) => {
                file.parent() == Some(self.path.as_path())
                    && file
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().contains(part))
            }
        }
    }
}

/// Where a host's stores are in one home: `HOME`, `$CODEX_HOME`, and the
/// directory Claude Code makes its per-user temporary directory in
/// (`CLAUDE_CODE_TMPDIR`, `/tmp` when unset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirs {
    pub home: PathBuf,
    pub codex_home: PathBuf,
    pub claude_tmp: PathBuf,
}

/// Claude Code's per-user temporary directory under `tmp`:
/// `claude-<uid>`, which 2.1.280 makes in `CLAUDE_CODE_TMPDIR`, or in
/// `/tmp` without it (it does not read `TMPDIR` for this).
pub fn claude_tmp_dir(tmp: &Path) -> PathBuf {
    tmp.join(format!("claude-{}", envcloak_sys::effective_uid()))
}

/// What a sweep of `host` reads: each directory, and which files under
/// it are the host's. Claude Code keeps `~/.claude/` and, beside it in
/// `HOME`, `.claude.json` and its backups, and its per-user temporary
/// directory ([`claude_tmp_dir`]); Codex keeps `$CODEX_HOME`. Anything
/// else in `HOME` (a project, a fixture) is not a host store; the tests
/// sweep the whole home separately.
pub fn host_roots(host: Host, dirs: &HostDirs) -> Vec<(PathBuf, HostFiles)> {
    match host {
        Host::ClaudeCode => vec![
            (
                dirs.home.clone(),
                HostFiles::Claude {
                    home: dirs.home.clone(),
                },
            ),
            (claude_tmp_dir(&dirs.claude_tmp), HostFiles::All),
        ],
        Host::Codex => vec![(dirs.codex_home.clone(), HostFiles::All)],
    }
}

/// Which files under a host's root are the host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFiles {
    /// Every file.
    All,
    /// `<home>/.claude/` and `<home>/.claude.json*`.
    Claude { home: PathBuf },
}

impl HostFiles {
    fn has(&self, file: &Path) -> bool {
        match self {
            HostFiles::All => true,
            HostFiles::Claude { home } => {
                file.starts_with(home.join(".claude"))
                    || (file.parent() == Some(home.as_path())
                        && file
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with(".claude.json")))
            }
        }
    }
}

/// Every store of `host` in the home `dirs` names.
pub fn transcript_roots(host: Host, dirs: &HostDirs) -> Vec<Store> {
    use Shape::{Dir, File, Named};
    use StoreKind::{
        Backup, Config, Database, FileHistory, History, Log, PasteCache, Session, Transcript,
        Transient,
    };
    let (home, codex_home) = (dirs.home.as_path(), dirs.codex_home.as_path());
    let claude = home.join(".claude");
    let s = |name, path: PathBuf, shape, kind, source| Store {
        host: host.id(),
        name,
        path,
        shape,
        kind,
        source,
    };
    match host {
        Host::ClaudeCode => vec![
            // D-15: transcripts (tool-results/, subagents/, orphaned and
            // superseded files included), history, pastes, file history,
            // backups.
            s(
                "claude/projects",
                claude.join("projects"),
                Dir,
                Transcript,
                "D-15",
            ),
            s(
                "claude/history.jsonl",
                claude.join("history.jsonl"),
                File,
                History,
                "D-15",
            ),
            s(
                "claude/paste-cache",
                claude.join("paste-cache"),
                Dir,
                PasteCache,
                "D-15",
            ),
            s(
                "claude/file-history",
                claude.join("file-history"),
                Dir,
                FileHistory,
                "D-15",
            ),
            s(
                "claude/backups",
                claude.join("backups"),
                Dir,
                Backup,
                "D-15",
            ),
            // Written by 2.1.280 in M2-04's runs.
            s(
                "claude/sessions",
                claude.join("sessions"),
                Dir,
                Session,
                "observed",
            ),
            s(
                "claude/session-env",
                claude.join("session-env"),
                Dir,
                Session,
                "observed",
            ),
            s(
                "claude/shell-snapshots",
                claude.join("shell-snapshots"),
                Dir,
                Session,
                "observed",
            ),
            s(
                "claude/telemetry",
                claude.join("telemetry"),
                Dir,
                Log,
                "observed",
            ),
            s(
                "claude/todos",
                claude.join("todos"),
                Dir,
                Session,
                "observed",
            ),
            s("claude/debug", claude.join("debug"), Dir, Log, "observed"),
            s(
                "claude.json",
                home.join(".claude.json"),
                File,
                Config,
                "observed",
            ),
            s(
                "claude.json backups",
                home.to_path_buf(),
                Named(".claude.json.backup"),
                Backup,
                "observed",
            ),
            // Outside HOME: what a Bash command has printed so far, in
            // `claude-<uid>/<project>/<session>/tasks/<id>.output`, deleted
            // when the command ends; the directories stay.
            s(
                "claude/tmp",
                claude_tmp_dir(&dirs.claude_tmp),
                Dir,
                Transient,
                "observed",
            ),
        ],
        Host::Codex => vec![
            // D-15: sessions, archived sessions, history, logs.
            s(
                "codex/sessions",
                codex_home.join("sessions"),
                Dir,
                Transcript,
                "D-15",
            ),
            s(
                "codex/archived_sessions",
                codex_home.join("archived_sessions"),
                Dir,
                Transcript,
                "D-15",
            ),
            s(
                "codex/history.jsonl",
                codex_home.join("history.jsonl"),
                File,
                History,
                "D-15",
            ),
            s("codex/log", codex_home.join("log"), Dir, Log, "D-15"),
            // Written by 0.159.2 in M2-04's runs: its SQLite stores (a
            // command's output reaches thread_history_1.sqlite), shell
            // snapshots and memories.
            s(
                "codex/sqlite",
                codex_home.to_path_buf(),
                Named(".sqlite"),
                Database,
                "observed",
            ),
            s(
                "codex/shell_snapshots",
                codex_home.join("shell_snapshots"),
                Dir,
                Session,
                "observed",
            ),
            s(
                "codex/memories",
                codex_home.join("memories"),
                Dir,
                Session,
                "observed",
            ),
        ],
    }
}

/// The hits of one store, raw.
#[derive(Debug, Clone)]
pub struct StoreHits {
    /// The store's name, or [`OTHER`].
    pub store: String,
    pub hits: Vec<Hit>,
}

/// One canary occurrence in a body the scripted model recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelHit {
    /// The request's number in the run.
    pub seq: u64,
    pub found: Found,
}

/// A whole sweep: the host's stores, and the model's request bodies.
#[derive(Debug, Clone, Default)]
pub struct Hits {
    pub stores: Vec<StoreHits>,
    pub model: Vec<ModelHit>,
}

/// An encoding's name as a count shows it: with the levels of JSON
/// escaping read through to find it, when any.
fn shown_encoding(f: &Found) -> String {
    if f.unescaped == 0 {
        f.encoding.to_owned()
    } else {
        format!("{} (JSON-unescaped {}x)", f.encoding, f.unescaped)
    }
}

fn found(hit: &Hit) -> Option<&Found> {
    match hit {
        Hit::Canary { found, .. } | Hit::Name { found, .. } | Hit::LinkTarget { found, .. } => {
            Some(found)
        }
        Hit::Unreadable { .. } => None,
    }
}

fn path_of(hit: &Hit) -> &Path {
    match hit {
        Hit::Canary { path, .. }
        | Hit::Name { path, .. }
        | Hit::LinkTarget { path, .. }
        | Hit::Unreadable { path, .. } => path.raw(),
    }
}

impl Hits {
    /// Hits of the canary labelled `label`, in the store named `store`
    /// (or [`OTHER`]).
    pub fn in_store(&self, store: &str, label: &str) -> usize {
        self.stores
            .iter()
            .filter(|s| s.store == store)
            .flat_map(|s| &s.hits)
            .filter_map(found)
            .filter(|f| f.label == label)
            .count()
    }

    /// Hits of `label` in the store named `store` with the encoding
    /// named `encoding` ([`crate::encodings`]).
    pub fn in_store_as(&self, store: &str, label: &str, encoding: &str) -> usize {
        self.stores
            .iter()
            .filter(|s| s.store == store)
            .flat_map(|s| &s.hits)
            .filter_map(found)
            .filter(|f| f.label == label && f.encoding == encoding)
            .count()
    }

    /// Hits of `label` in the model's request bodies.
    pub fn in_model(&self, label: &str) -> usize {
        self.model.iter().filter(|h| h.found.label == label).count()
    }

    /// Every hit, unreadable files included, in stores and bodies.
    pub fn total(&self) -> usize {
        self.stores.iter().map(|s| s.hits.len()).sum::<usize>() + self.model.len()
    }
}

impl fmt::Display for Hits {
    /// Raw counts per store, canary and encoding; never a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut counts: std::collections::BTreeMap<(String, String, String), usize> =
            std::collections::BTreeMap::new();
        for s in &self.stores {
            for h in &s.hits {
                let (label, enc) = match found(h) {
                    Some(x) => (x.label.clone(), shown_encoding(x)),
                    None => ("<unreadable>".to_owned(), String::new()),
                };
                *counts.entry((s.store.clone(), label, enc)).or_default() += 1;
            }
        }
        for h in &self.model {
            *counts
                .entry((
                    "model request bodies".to_owned(),
                    h.found.label.clone(),
                    shown_encoding(&h.found),
                ))
                .or_default() += 1;
        }
        if counts.is_empty() {
            return f.write_str("no hits");
        }
        for ((store, label, enc), n) in counts {
            writeln!(f, "{store}: {label} as {enc}: {n}")?;
        }
        Ok(())
    }
}

/// Sweeps each of `roots` whole for `cs` and files every hit in one of
/// the host's files under the first of `stores` that holds it, or under
/// [`OTHER`].
pub fn sweep_stores(
    roots: &[(PathBuf, HostFiles)],
    stores: &[Store],
    cs: &[Canary],
) -> Vec<StoreHits> {
    let mut out: Vec<StoreHits> = stores
        .iter()
        .map(|s| StoreHits {
            store: s.name.to_owned(),
            hits: Vec::new(),
        })
        .collect();
    out.push(StoreHits {
        store: OTHER.to_owned(),
        hits: Vec::new(),
    });
    for (root, files) in roots {
        if !root.exists() {
            continue;
        }
        for hit in sweep_dir(root, cs) {
            let path = path_of(&hit);
            if !files.has(path) {
                continue;
            }
            let at = stores
                .iter()
                .position(|s| s.holds(path))
                .unwrap_or(stores.len());
            out[at].hits.push(hit);
        }
    }
    out
}

/// Every canary occurrence in the bodies the model recorded.
pub fn sweep_model(report: &ModelReport, cs: &[Canary]) -> Vec<ModelHit> {
    let detector = Detector::new(cs);
    report
        .requests
        .iter()
        .flat_map(|r| {
            detector
                .find(&r.body)
                .into_iter()
                .map(move |found| ModelHit { seq: r.seq, found })
        })
        .collect()
}

/// The sweeps of one agent home.
#[derive(Debug)]
pub struct Sweep;

impl Sweep {
    /// Sweeps `home`'s host stores (and the rest of the host's
    /// directories) for `cs`, and the bodies of `models`.
    pub fn host_stores(home: &AgentHome, cs: &[Canary], models: &[&ModelReport]) -> Hits {
        let dirs = home.host_dirs();
        Hits {
            stores: sweep_stores(
                &host_roots(home.host, &dirs),
                &transcript_roots(home.host, &dirs),
                cs,
            ),
            model: models.iter().flat_map(|m| sweep_model(m, cs)).collect(),
        }
    }
}
