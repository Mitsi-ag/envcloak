//! The approval statement (SPEC §10a "Bounds and display", §10b "Approval
//! proofs"; gates 23 and 31): what an approval surface shows, and what
//! the proof approves.
//!
//! A pending request crosses the socket as a [`PendingDescriptor`]:
//! metadata only, every field a number, a fixed token or a string the
//! renderer escapes. From it and the approver's [`ApprovalOptions`]:
//!
//! - [`canonical_statement`] is an unambiguous byte encoding of every
//!   field, the full command line included. [`statement_digest`], its
//!   SHA-256, is what the approver sends with the passphrase, and the
//!   daemon compares it against the digest of its own pending request
//!   with the same options: a statement that differs from the pending
//!   request is rejected (gate 23). The daemon nonce in it binds the
//!   statement to one request of one daemon.
//! - [`render_statement`] is the text a person reads. Argv renders as a
//!   list, with control characters, bidirectional overrides and zero-width
//!   characters shown as escapes ([`escape_for_display`]), and the list is
//!   cut at [`RENDER_LIMIT`] bytes with a `(N more bytes)` marker. What
//!   the passphrase approves is the canonical statement, which always
//!   covers the full argv, and the rendering says so where it cuts.
//!
//! Every string the daemon sends (paths, slugs, an agent's name, argv) goes
//! through the escaper before it reaches a terminal: a program running as
//! the user could answer in the daemon's place (SPEC §1.1), and a command
//! line is the caller's to choose.

use core::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::effective::SubjectKind;
use crate::grants::{ApprovalOptions, Uses};
use crate::manifest::Mode;

/// Rendered argv beyond this many bytes is cut, with a marker.
pub const RENDER_LIMIT: usize = 2048;

/// A pending request as an approval surface receives it (SPEC §10b
/// `{request_id, daemon_nonce, subject evidence, project, bindings, mode,
/// ttl, live flags, new project, first use, argv}`). Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDescriptor {
    /// The request id: 8 Crockford base32 characters.
    pub request: String,
    /// The daemon nonce, 32 bytes as 64 hex characters.
    pub nonce: String,
    /// When the request was opened, Unix seconds.
    pub created_secs: u64,
    /// Seconds after `created_secs` at which it expires.
    pub expires_in_secs: u64,
    pub subject: SubjectSummary,
    pub project: ProjectSummary,
    pub bindings: Vec<BindingSummary>,
    pub mode: Mode,
    /// The command line, as display text.
    pub argv: Vec<String>,
}

/// The caller, as the daemon classified it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectSummary {
    pub kind: SubjectKind,
    /// The agent's display name, when one is involved.
    pub label: Option<String>,
    /// The process that connected.
    pub caller_pid: i32,
    /// The instance a grant would be rooted at.
    pub root: ProcessSummary,
}

/// A process instance, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSummary {
    pub pid: i32,
    /// The kernel's start time, as `envcloak_sys::StartTime::raw`.
    pub start_time: u64,
    /// Its executable's path as the kernel reports it, when known.
    pub exe: Option<String>,
}

/// The project, as the daemon opened it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSummary {
    /// The canonical directory.
    pub dir: String,
    /// The manifest's path.
    pub manifest: String,
    /// SHA-256 of the manifest, as 64 hex characters.
    pub manifest_sha256: String,
    /// The vault has no record of this project yet (SPEC §6.4
    /// "Adoption").
    pub new_project: bool,
}

/// One binding the request asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSummary {
    pub env_name: String,
    /// The item's slug, for display; the id is what the grant records.
    pub slug: String,
    /// The item id, as a ULID.
    pub item: String,
    /// The field id, as a ULID.
    pub field: String,
    pub field_name: String,
    /// `test`, `live` or `unknown`.
    pub classification: String,
    /// No adopted project uses the item yet (SPEC §6.4).
    pub first_use: bool,
    /// A session grant in force for this process tree and project covered
    /// this binding when the request was made: the request asks again
    /// only because of the others (SPEC §10b "prompts for the
    /// difference"). The new grant holds it too, for its own uses and
    /// length.
    pub granted: bool,
}

/// Appends length-prefixed fields: unambiguous whatever the strings hold.
struct Enc(Vec<u8>);

impl Enc {
    fn str(&mut self, s: &str) -> &mut Self {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(&s.as_bytes()[..len as usize]);
        self
    }

    fn num(&mut self, n: u64) -> &mut Self {
        self.str(&n.to_string())
    }

    fn flag(&mut self, b: bool) -> &mut Self {
        self.str(if b { "1" } else { "0" })
    }

    fn count(&mut self, n: usize) -> &mut Self {
        self.num(u64::try_from(n).unwrap_or(u64::MAX))
    }
}

/// The word for a subject kind.
fn kind_word(k: SubjectKind) -> &'static str {
    match k {
        SubjectKind::Agent => "agent",
        SubjectKind::Terminal => "terminal",
        SubjectKind::Unknown => "unknown",
    }
}

/// The word for a mode.
fn mode_word(m: Mode) -> &'static str {
    match m {
        Mode::Inject => "inject",
        Mode::Proxy => "proxy",
    }
}

/// The word for how a grant is used.
fn uses_word(u: Uses) -> &'static str {
    match u {
        Uses::Once => "once",
        Uses::Session => "session",
    }
}

/// The canonical encoding of the statement: every field of `p` and `o`,
/// length-prefixed, the full argv included. See the module documentation.
pub fn canonical_statement(p: &PendingDescriptor, o: &ApprovalOptions) -> Vec<u8> {
    let mut e = Enc(Vec::with_capacity(512));
    e.0.extend_from_slice(b"envcloak-statement/1\n");
    e.str(&p.request)
        .str(&p.nonce)
        .num(p.created_secs)
        .num(p.expires_in_secs)
        .str(kind_word(p.subject.kind))
        .str(p.subject.label.as_deref().unwrap_or(""))
        .flag(p.subject.label.is_some())
        .num(i64::from(p.subject.caller_pid).unsigned_abs())
        .num(i64::from(p.subject.root.pid).unsigned_abs())
        .num(p.subject.root.start_time)
        .str(p.subject.root.exe.as_deref().unwrap_or(""))
        .flag(p.subject.root.exe.is_some())
        .str(&p.project.dir)
        .str(&p.project.manifest)
        .str(&p.project.manifest_sha256)
        .flag(p.project.new_project)
        .count(p.bindings.len());
    for b in &p.bindings {
        e.str(&b.env_name)
            .str(&b.slug)
            .str(&b.item)
            .str(&b.field)
            .str(&b.field_name)
            .str(&b.classification)
            .flag(b.first_use)
            .flag(b.granted);
    }
    e.str(mode_word(p.mode)).count(p.argv.len());
    for a in &p.argv {
        e.str(a);
    }
    e.str(uses_word(o.uses)).num(o.ttl_secs).count(o.live.len());
    for l in &o.live {
        e.str(l.as_str());
    }
    e.0
}

/// SHA-256 of [`canonical_statement`].
pub fn statement_digest(p: &PendingDescriptor, o: &ApprovalOptions) -> [u8; 32] {
    Sha256::digest(canonical_statement(p, o)).into()
}

/// Whether `c` is invisible or changes the direction or layout of what
/// follows: bidirectional controls, zero-width and joining characters,
/// line and paragraph separators, tags and other format characters.
fn is_invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if c.is_control() || is_invisible(c) => {
            // Cannot fail: writing to a String.
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
        c => out.push(c),
    }
}

/// `s` with every control character, bidirectional override, zero-width
/// or other invisible character, and backslash, shown as an escape
/// (`\n`, `\r`, `\t`, `\\`, `\u{202e}`), so it can be printed on a
/// terminal as it is.
pub fn escape_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_escaped(&mut out, c);
    }
    out
}

/// A duration in words: `1h 30m`, `45m`, `20s`.
fn duration_words(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let mut parts = Vec::new();
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
}

/// The argv list, cut at [`RENDER_LIMIT`] bytes on a character boundary
/// with a marker counting the rendered bytes not shown.
fn render_argv(argv: &[String]) -> String {
    let mut full = String::new();
    for (i, a) in argv.iter().enumerate() {
        // Cannot fail: writing to a String.
        let _ = writeln!(full, "    [{i}] {}", escape_for_display(a));
    }
    if full.len() <= RENDER_LIMIT {
        return full;
    }
    let mut cut = RENDER_LIMIT;
    while !full.is_char_boundary(cut) {
        cut -= 1;
    }
    let hidden = full.len() - cut;
    full.truncate(cut);
    // Cannot fail: writing to a String.
    let _ = write!(
        full,
        "\n    ({hidden} more bytes)\n    The passphrase approves the full command line, the part not shown included.\n"
    );
    full
}

/// One binding as the statement shows it, with its notes.
fn binding_line(b: &BindingSummary, o: &ApprovalOptions) -> String {
    let e = escape_for_display;
    let mut notes = vec![format!("{} key", e(&b.classification))];
    if b.first_use {
        notes.push("first use: no project uses this item yet".to_owned());
    }
    if o.live.iter().any(|l| l.as_str() == b.env_name) {
        notes.push("live: allowed by you".to_owned());
    }
    format!(
        "    {} = {}#{}  ({})\n",
        e(&b.env_name),
        e(&b.slug),
        e(&b.field_name),
        notes.join(", ")
    )
}

/// The statement as a person reads it. Every string from the request is
/// escaped; argv is a list, cut with a marker past [`RENDER_LIMIT`]. The
/// bindings no grant in force covers come first.
pub fn render_statement(p: &PendingDescriptor, o: &ApprovalOptions) -> String {
    let e = escape_for_display;
    let mut t = String::with_capacity(1024);
    let _ = writeln!(t, "Approval request {}", e(&p.request));
    let who = match (&p.subject.kind, &p.subject.label) {
        (SubjectKind::Agent, Some(l)) => format!("agent {} ", e(l)),
        (SubjectKind::Agent, None) => "an agent ".to_owned(),
        (SubjectKind::Terminal, _) => "a terminal session ".to_owned(),
        (SubjectKind::Unknown, _) => "a process of unknown origin ".to_owned(),
    };
    let _ = writeln!(
        t,
        "  requested by: {who}(caller pid {}), rooted at pid {} started at {}{}",
        p.subject.caller_pid,
        p.subject.root.pid,
        p.subject.root.start_time,
        p.subject
            .root
            .exe
            .as_deref()
            .map(|x| format!(", {}", e(x)))
            .unwrap_or_default()
    );
    let _ = writeln!(
        t,
        "  project: {}{}",
        e(&p.project.dir),
        if p.project.new_project {
            " (new project: the vault has no record of it)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        t,
        "  manifest: {} sha256 {}",
        e(&p.project.manifest),
        e(&p.project.manifest_sha256)
    );
    // The difference first: what no grant in force covers. The bindings
    // a grant already covered follow, under a heading that says this grant
    // holds them too, for its own uses and length: the statement shows
    // all the new grant will hold.
    let (new, granted): (Vec<&BindingSummary>, Vec<&BindingSummary>) =
        p.bindings.iter().partition(|b| !b.granted);
    if granted.is_empty() {
        let _ = writeln!(t, "  bindings ({} mode):", mode_word(p.mode));
    } else {
        let _ = writeln!(
            t,
            "  bindings no grant covers yet ({} mode), which this asks for:",
            mode_word(p.mode)
        );
    }
    for b in &new {
        t.push_str(&binding_line(b, o));
    }
    if !granted.is_empty() {
        let _ = writeln!(
            t,
            "  also held by this grant (a grant for this process tree and project covered \
             them when this was asked):"
        );
        for b in &granted {
            t.push_str(&binding_line(b, o));
        }
    }
    let _ = writeln!(t, "  command ({} arguments):", p.argv.len());
    t.push_str(&render_argv(&p.argv));
    match o.uses {
        Uses::Once => {
            let _ = writeln!(
                t,
                "  grant: once, for the next matching request within {}",
                duration_words(o.ttl_secs)
            );
        }
        Uses::Session => {
            let _ = writeln!(
                t,
                "  grant: every request from this process tree for {}",
                duration_words(o.ttl_secs)
            );
        }
    }
    t.push_str("The passphrase you enter approves exactly this, and nothing else.\n");
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_words() {
        assert_eq!(duration_words(3600), "1h");
        assert_eq!(duration_words(5400), "1h 30m");
        assert_eq!(duration_words(45 * 60), "45m");
        assert_eq!(duration_words(20), "20s");
        assert_eq!(duration_words(0), "0s");
        assert_eq!(duration_words(3661), "1h 1m 1s");
    }
}
