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
}
