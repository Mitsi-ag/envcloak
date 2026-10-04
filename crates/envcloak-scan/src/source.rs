//! What a scanner reads, named by whoever knows where it is (M2 plan D-02,
//! F-75): neutral descriptors the scanner owns, so the host catalog
//! (`envcloak_agents::locations`) can emit them and the scanner can read
//! them without either crate depending on the other's types. The crate
//! graph stays one-way: `agents -> scan`, never back.
//!
//! A [`ConfigSource`] names a file or a directory, how its contents are
//! encoded, what kind of store it is and a display label. It holds no
//! contents and no host type: the label is text such as "Claude Code user
//! config".

use std::path::PathBuf;

/// How a source's contents are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFormat {
    /// One JSON document.
    Json,
    /// One TOML document.
    Toml,
    /// One YAML document (reported, not rewritten, in M2).
    Yaml,
    /// One JSON value per line.
    Jsonl,
    /// A directory of JSONL and plain text files (Claude Code's
    /// `projects/`: transcripts beside the text of long tool results),
    /// each file read by its name: `.jsonl` as JSONL, any other as text.
    Mixed,
    /// Bytes with no structure the scanner reads (pasted text, snapshots).
    Raw,
}

/// What kind of store a source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// An agent's MCP server configuration (or a settings file that can
    /// carry one).
    McpConfig,
    /// A copy the host keeps of its own configuration (Claude Code's
    /// `~/.claude/backups/`).
    HostBackup,
    /// Conversation transcripts.
    Transcript,
    /// The host's prompt history.
    History,
    /// Pasted text the host keeps apart from the transcript.
    PasteCache,
    /// The host's snapshots of files it edited.
    FileHistory,
    /// A database the scanner does not read in M2 ("not scanned
    /// (database)").
    Database,
    /// What the host keeps for a session besides its transcript: its
    /// environment, shell snapshots, plans, to-do lists, memories.
    Session,
    /// The host's own logs (debug output, telemetry).
    Log,
    /// What the host keeps outside its directory while it runs: a
    /// command's output so far, images, a scratchpad, hook output.
    Temporary,
    /// A store of an agent's own credentials (its provider keys, its MCP
    /// servers' secrets: Copilot CLI's `mcp-secrets/`, OpenCode's
    /// `auth.json`), which is reported as manual and never rewritten
    /// (SPEC §6.6).
    Credentials,
}

/// One place a scanner reads: a file, or a directory whose files of
/// [`ConfigSource::format`] it reads. Display data only, never contents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigSource {
    /// Absolute path of the file or directory.
    pub path: PathBuf,
    pub format: ConfigFormat,
    pub source_kind: SourceKind,
    /// What to call it in a report, such as "Claude Code user config".
    pub label: String,
    /// With a directory `path`: only the files directly in it whose names
    /// hold this (a host's files kept among others, such as Claude Code's
    /// `.claude.json.backup.<time>` beside `.claude.json`). `None`: the
    /// file, or every file under the directory.
    pub names: Option<String>,
}
