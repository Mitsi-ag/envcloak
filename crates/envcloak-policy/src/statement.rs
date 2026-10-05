//! The approval statement (SPEC §10a "Bounds and display", §10b "Approval
//! proofs"; gates 23 and 31): what an approval surface shows, and what
//! the proof approves.
//!
//! A pending request crosses the socket as a [`PendingDescriptor`]:
//! metadata only, every field a number, a fixed token or a string the
//! renderer escapes. From it and the approver's [`ApprovalOptions`]:
//!
//! - [`canonical_statement`] is an unambiguous byte encoding of every
//!   field, the full command line included, under the domain
//!   [`STATEMENT_DOMAIN`] (`envcloak-statement/2`: the bindings'
//!   classifications, the live ticks and the proposed test items; a
//!   version 1 digest never equals one). [`statement_digest`], its
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
//! **The live-key guard** (SPEC §10b, M2 plan D-11). An agent or unknown
//! subject ([`live_guarded`]) receives a live-classified binding only when
//! the approval ticks it (`--live NAME`): [`unticked_live`] names the live
//! bindings an approval leaves unticked, and an approval with any creates
//! no grant (`live_not_ticked`). When the same provider has a
//! test-classified item, the statement proposes it, before the bindings
//! and their ticks, with how to bind it in the live one's place for the
//! layer the live binding came from (the `envcloak ref --manifest` line,
//! naming the request's manifest, for its `[env]` or a profile's table,
//! the `--ref` or the env file's line otherwise: [`Proposal::advice`]);
//! the daemon never substitutes an item. A proposal is not approved, so a
//! name of one shaped like a key is not shown ([`HIDDEN`]), and a proposed
//! item is not vouched for: any caller can add a test item, or tighten
//! one to live. The daemon builds the classifications and the proposals
//! from the vault when it shows the statement and again when it takes the
//! approval (L-09), so a statement read before either changed is a
//! `statement_mismatch`, the change an agent's included.
//!
//! Every string the daemon sends (paths, slugs, an agent's name, argv) goes
//! through the escaper before it reaches a terminal: a program running as
//! the user could answer in the daemon's place (SPEC §1.1), and a command
//! line is the caller's to choose.

use core::fmt::Write as _;

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{Classification, FieldName, ItemMeta, Slug};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::effective::SubjectKind;
use crate::grants::{ApprovalOptions, BoundRef, Uses};
use crate::manifest::{BindingSource, Mode};
use crate::names::value_shaped;

/// Rendered argv beyond this many bytes is cut, with a marker.
pub const RENDER_LIMIT: usize = 2048;

/// The first line of every canonical statement (docs/IPC.md "Statement
/// domains"). Version 1 had no proposals; its digests are refused since
/// (none equals a version 2 digest).
pub const STATEMENT_DOMAIN: &[u8] = b"envcloak-statement/2\n";

/// What is shown in place of a proposed name shaped like a key or token
/// (a value pasted where a name belongs, or a name a program answering in
/// the daemon's place chose): the same words every metadata command
/// prints in its place.
pub const HIDDEN: &str = "[not shown: looks like a key or token]";

/// A pending request as an approval surface receives it (SPEC §10b
/// `{request_id, daemon_nonce, subject evidence, project, bindings, mode,
/// ttl, live flags, new project, first use, argv}`, and the test items
/// proposed in place of live ones). Metadata only.
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
    /// The same provider's test items, proposed for live bindings
    /// ([`proposals`]), in the order of the bindings.
    pub proposals: Vec<Proposal>,
    pub mode: Mode,
    /// The command line, as display text.
    pub argv: Vec<String>,
    /// For a managed MCP server's project (SPEC §6.6): its record as the
    /// adoption statement shows it. Absent for every other project, whose
    /// canonical statement is byte for byte what it was before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedSummary>,
}

/// A managed MCP server's record, as an approval surface shows it (SPEC
/// §6.4 "Adoption", §6.6): whether "written by migrate-mcp on this device"
/// or "registered by an agent or unknown process", the registered launch
/// and revision a grant for it covers, its class and binding strength, or
/// a bridge's origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSummary {
    /// `<agent>/<server>`.
    pub name: String,
    pub written_by_migrate_mcp: bool,
    /// The registered launch, 26 Crockford base32 characters, and its
    /// revision; absent for a bridged server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// A test item proposed in place of a live one (SPEC §10b "Live-key
/// guard"): for the variable `env_name`, bound to the live item
/// `live_slug`, the same provider's test item `test_slug` (with the same
/// account label, when both have one). The daemon never substitutes it:
/// the person, or the agent, binds it as [`Proposal::advice`] says, for
/// the layer `source` the live binding came from, and asks again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub env_name: String,
    pub live_slug: String,
    pub test_slug: String,
    /// The test item's field to bind, when it has several: the one named
    /// as the live binding's field is. `None` when it has one.
    pub test_field: Option<String>,
    /// Where the live binding came from, which says how the test item is
    /// bound in its place.
    pub source: BindingSource,
}

impl Proposal {
    /// The reference that binds the test item: `<slug>`, or
    /// `<slug>#<field>` for an item of several fields.
    pub fn reference(&self) -> String {
        match &self.test_field {
            Some(f) => format!("{}#{f}", self.test_slug),
            None => self.test_slug.clone(),
        }
    }

    /// How to bind the test item in the live one's place, for the layer
    /// the live binding came from, so that the next request binds the test
    /// item (resolution: a later layer replaces an earlier one, so the
    /// change goes where the live binding is):
    ///
    /// - the manifest's `[env]`: run `envcloak ref --manifest <manifest>
    ///   NAME=<test>`;
    /// - a profile's `[env.<profile>]`: run `envcloak ref --manifest
    ///   <manifest> --profile <profile> NAME=<test>`;
    /// - the `--env-file`: set its line `<n>` to `NAME=envcloak://<test>`;
    /// - a `--ref`: give `--ref NAME=<test>` in place of the `--ref` for
    ///   `NAME`.
    ///
    /// `manifest` is the path of the request's manifest, which the edit
    /// names: `envcloak ref` alone edits the manifest nearest the directory
    /// it runs in, and the terminal that follows the advice can be anywhere
    /// (`run --manifest`, a person's own terminal). It is one shell word
    /// ([`shell_word`]), so a path with spaces or a quote, or one a program
    /// answering in the daemon's place chose, is that one argument. A path
    /// holding a character the display escapes cannot be shown as the word
    /// it is: the advice names its directory instead.
    ///
    /// Every name is escaped, and one that `looks_like_value` takes for a
    /// key or token is [`HIDDEN`] (a proposal is not approved, so nothing
    /// the person approves is hidden by this).
    pub fn advice(&self, manifest: &str, looks_like_value: &dyn Fn(&str) -> bool) -> String {
        if let Some(line) = self.command_line_advice(looks_like_value) {
            return line;
        }
        let name = shown_name(&self.env_name, looks_like_value);
        let reference = self.shown_reference(looks_like_value);
        let profile = match &self.source {
            BindingSource::Profile { profile } => {
                format!(" --profile {}", shown_name(profile, looks_like_value))
            }
            _ => String::new(),
        };
        match shell_word(manifest) {
            Some(m) => format!("run `envcloak ref --manifest {m}{profile} {name}={reference}`"),
            None => format!(
                "run `envcloak ref{profile} {name}={reference}` in the directory of the manifest \
                 {}",
                escape_for_display(manifest)
            ),
        }
    }

    /// How to bind the test item when the live binding came from the
    /// run's own command line, which names no manifest: the `--env-file`'s
    /// line, or another `--ref` ([`Proposal::advice`]). `None` for a
    /// binding of the manifest (`[env]` or a profile), which an edit of
    /// the manifest replaces.
    pub fn command_line_advice(&self, looks_like_value: &dyn Fn(&str) -> bool) -> Option<String> {
        let name = shown_name(&self.env_name, looks_like_value);
        let reference = self.shown_reference(looks_like_value);
        match &self.source {
            BindingSource::Env | BindingSource::Profile { .. } => None,
            BindingSource::EnvFile { line } => Some(format!(
                "set line {line} of the --env-file to `{name}=envcloak://{reference}`"
            )),
            BindingSource::Ref => Some(format!(
                "give `--ref {name}={reference}` in place of the --ref for {name}"
            )),
        }
    }

    /// [`Proposal::reference`] as it may be shown: escaped, each of the slug
    /// and the field [`HIDDEN`] when `looks_like_value` takes it for a key.
    pub fn shown_reference(&self, looks_like_value: &dyn Fn(&str) -> bool) -> String {
        let slug = shown_name(&self.test_slug, looks_like_value);
        match &self.test_field {
            Some(f) => format!("{slug}#{}", shown_name(f, looks_like_value)),
            None => slug,
        }
    }

    /// Whether every name has the shape the daemon gives it: a variable
    /// name, two slugs, a field name and a well-formed layer. A program
    /// answering in the daemon's place could send anything (SPEC §1.1); a
    /// client shows no proposal that fails this.
    pub fn well_formed(&self) -> bool {
        crate::names::EnvName::new(&self.env_name).is_ok()
            && Slug::new(&self.live_slug).is_ok()
            && Slug::new(&self.test_slug).is_ok()
            && self
                .test_field
                .as_deref()
                .is_none_or(|f| FieldName::new(f).is_ok())
            && self.source.well_formed()
    }
}

/// A name from a request or a proposal as it may be shown: escaped
/// ([`escape_for_display`]), or [`HIDDEN`] when `looks_like_value` takes it
/// for a key or token.
pub fn shown_name(s: &str, looks_like_value: &dyn Fn(&str) -> bool) -> String {
    if looks_like_value(s) {
        HIDDEN.to_owned()
    } else {
        escape_for_display(s)
    }
}

/// `s` as one word of a POSIX shell command line, when it can be shown as
/// that word: as it is when every character is one a shell takes as
/// itself (letters, digits and `/._-+=:,@%`), else in single quotes, a `'`
/// in it written `'\''`. Quoted, nothing in it is expanded or run, so a
/// path a program chose (one answering in the daemon's place, SPEC §1.1)
/// is that one argument when the line is pasted. `None` when it is empty
/// or holds a character [`escape_for_display`] escapes (a control or an
/// invisible one): shown escaped, it would no longer be the same word.
pub fn shell_word(s: &str) -> Option<String> {
    if s.is_empty() || s.chars().any(display_escaped) {
        return None;
    }
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-+=:,@%".contains(&b))
    {
        return Some(s.to_owned());
    }
    Some(format!("'{}'", s.replace('\'', "'\\''")))
}

/// Whether the live-key guard applies to a request from a subject of kind
/// `k`: agent and unknown subjects (SPEC §10b; an unknown subject's
/// evidence is missing, and missing evidence takes the tighter rule).
pub fn live_guarded(k: SubjectKind) -> bool {
    match k {
        SubjectKind::Agent | SubjectKind::Unknown => true,
        SubjectKind::Terminal => false,
    }
}

/// The variables of `p`'s live-classified bindings that `o` does not tick,
/// in the order of the bindings, when the guard applies to its subject
/// ([`live_guarded`]); none otherwise. An approval that leaves any is
/// refused `live_not_ticked` and creates no grant. Read from the
/// statement, so the daemon and an approval surface decide from the same
/// classifications: the ones the daemon built from the vault when it sent
/// the statement, and again when it takes the approval.
pub fn unticked_live<'a>(p: &'a PendingDescriptor, o: &ApprovalOptions) -> Vec<&'a str> {
    if !live_guarded(p.subject.kind) {
        return Vec::new();
    }
    p.bindings
        .iter()
        .filter(|b| b.classification == LIVE && !ticked(o, &b.env_name))
        .map(|b| b.env_name.as_str())
        .collect()
}

/// The word of a live classification in a statement.
const LIVE: &str = "live";

/// Whether `o` ticks the variable `env_name`.
fn ticked(o: &ApprovalOptions, env_name: &str) -> bool {
    o.live.iter().any(|l| l.as_str() == env_name)
}

/// The test items to propose for `bindings` (SPEC §10b "Live-key
/// guard"), from `items`, the vault's metadata now: for each binding whose
/// item is a live-classified secret of a known provider, the same
/// provider's test-classified secret item (not the same item; never a
/// live or an unknown one, which SPEC §10b says is not a test key), with
/// the same account label when both have one, that a reference can bind
/// unambiguously (its one field, or the field named as the binding's).
/// One per binding, the first by: an account label equal to the live
/// item's, then slug; with the layer the binding came from. A binding
/// whose item is gone, or of no provider, has none.
pub fn proposals(bindings: &[BoundRef], items: &[ItemMeta]) -> Vec<Proposal> {
    let mut out = Vec::new();
    for b in bindings {
        let Some(live) = items.iter().find(|m| m.id == b.binding.item) else {
            continue;
        };
        if live.class != ItemClass::Secret || live.details.classification != Classification::Live {
            continue;
        }
        let Some(provider) = live.details.provider.as_deref() else {
            continue;
        };
        let live_label = live.details.account.label.as_deref();
        let best = items
            .iter()
            .filter(|m| {
                m.id != live.id
                    && m.class == ItemClass::Secret
                    && m.details.classification == Classification::Test
                    && m.details.provider.as_deref() == Some(provider)
                    && match (live_label, m.details.account.label.as_deref()) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    }
            })
            .filter_map(|m| {
                let field = match m.fields.as_slice() {
                    [_] => None,
                    fields => Some(
                        fields
                            .iter()
                            .find(|f| f.name == b.field_name)?
                            .name
                            .as_str()
                            .to_owned(),
                    ),
                };
                let same_label =
                    live_label.is_some() && live_label == m.details.account.label.as_deref();
                Some((!same_label, m.slug.as_str(), field))
            })
            .min_by(|x, y| (x.0, x.1).cmp(&(y.0, y.1)));
        if let Some((_, test_slug, test_field)) = best {
            out.push(Proposal {
                env_name: b.binding.env_name.as_str().to_owned(),
                live_slug: live.slug.as_str().to_owned(),
                test_slug: test_slug.to_owned(),
                test_field,
                source: b.source.clone(),
            });
        }
    }
    out
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

    /// A signed number, in decimal with its sign (F-81): `-5` and `5`
    /// render differently, so they encode differently. A positive one
    /// encodes as [`Enc::num`] encodes it.
    fn signed(&mut self, n: i64) -> &mut Self {
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

/// The canonical encoding of the statement: [`STATEMENT_DOMAIN`], then
/// every field of `p` and `o`, length-prefixed, the full argv included,
/// the proposals after the bindings. See the module documentation and
/// docs/GRANTS.md "Canonical encoding".
pub fn canonical_statement(p: &PendingDescriptor, o: &ApprovalOptions) -> Vec<u8> {
    let mut e = Enc(Vec::with_capacity(512));
    e.0.extend_from_slice(STATEMENT_DOMAIN);
    e.str(&p.request)
        .str(&p.nonce)
        .num(p.created_secs)
        .num(p.expires_in_secs)
        .str(kind_word(p.subject.kind))
        .str(p.subject.label.as_deref().unwrap_or(""))
        .flag(p.subject.label.is_some())
        .signed(i64::from(p.subject.caller_pid))
        .signed(i64::from(p.subject.root.pid))
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
    e.count(p.proposals.len());
    for x in &p.proposals {
        e.str(&x.env_name)
            .str(&x.live_slug)
            .str(&x.test_slug)
            .str(x.test_field.as_deref().unwrap_or(""))
            .flag(x.test_field.is_some());
        // The layer's word, then what that layer has: a profile's name, an
        // env file's line, or nothing.
        match &x.source {
            BindingSource::Env => e.str("env"),
            BindingSource::Profile { profile } => e.str("profile").str(profile),
            BindingSource::EnvFile { line } => e.str("env_file").num(u64::from(*line)),
            BindingSource::Ref => e.str("ref"),
        };
    }
    e.str(mode_word(p.mode)).count(p.argv.len());
    for a in &p.argv {
        e.str(a);
    }
    e.str(uses_word(o.uses)).num(o.ttl_secs).count(o.live.len());
    for l in &o.live {
        e.str(l.as_str());
    }
    // A managed server's record last, and only for one: every field
    // before it is self-delimiting, so a statement with it never encodes
    // as one without it, and every other statement is unchanged.
    if let Some(m) = &p.managed {
        e.str("managed")
            .str(&m.name)
            .flag(m.written_by_migrate_mcp)
            .str(m.launch.as_deref().unwrap_or(""))
            .flag(m.launch.is_some())
            .num(m.revision.unwrap_or(0))
            .flag(m.revision.is_some())
            .str(m.class.as_deref().unwrap_or(""))
            .str(m.strength.as_deref().unwrap_or(""))
            .str(m.origin.as_deref().unwrap_or(""))
            .flag(m.origin.is_some());
    }
    e.0
}

/// SHA-256 of [`canonical_statement`].
pub fn statement_digest(p: &PendingDescriptor, o: &ApprovalOptions) -> [u8; 32] {
    Sha256::digest(canonical_statement(p, o)).into()
}

/// Whether `c` is invisible or changes the direction or layout of what
/// follows: every format character (Unicode's `Cf`: bidirectional
/// controls, zero-width and joining characters, the soft hyphen, tags,
/// Arabic and Egyptian format marks), line and paragraph separators
/// (`Zl`, `Zp`), variation selectors, and fillers that show as blank.
/// Control characters (`Cc`) are `char::is_control`. Display escapes these
/// ([`escape_for_display`]), and a manifest's project name refuses them.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
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
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE0FFF
    )
}

/// Whether [`escape_for_display`] shows `c` as an escape because a
/// terminal would act on it or not show it: a control character (`Cc`,
/// the C1 controls and DEL included) or an invisible one
/// ([`is_invisible`]). The backslash, which it escapes too, is not one.
pub fn display_escaped(c: char) -> bool {
    c.is_control() || is_invisible(c)
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if display_escaped(c) => {
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

/// One binding as the statement shows it, with its notes. `guarded`: the
/// live-key guard applies to the request ([`live_guarded`]).
fn binding_line(b: &BindingSummary, o: &ApprovalOptions, guarded: bool) -> String {
    let e = escape_for_display;
    let mut notes = vec![format!("{} key", e(&b.classification))];
    if b.first_use {
        notes.push("first use: no project uses this item yet".to_owned());
    }
    if ticked(o, &b.env_name) {
        notes.push("live: allowed by you".to_owned());
    } else if guarded && b.classification == LIVE {
        notes.push(format!(
            "live: not allowed by you, so this approval is refused unless you add --live {}",
            e(&b.env_name)
        ));
    }
    format!(
        "    {} = {}#{}  ({})\n",
        e(&b.env_name),
        e(&b.slug),
        e(&b.field_name),
        notes.join(", ")
    )
}

/// The statement as a person reads it ([`render_statement_with`]), a
/// proposed name hidden when it is shaped like a generated key
/// ([`value_shaped`]).
pub fn render_statement(p: &PendingDescriptor, o: &ApprovalOptions) -> String {
    render_statement_with(p, o, &value_shaped)
}

/// The statement as a person reads it. Every string from the request is
/// escaped; argv is a list, cut with a marker past [`RENDER_LIMIT`]. The
/// test items proposed come first, each name [`HIDDEN`] where
/// `looks_like_value` takes it for a key or token (a proposal is not
/// approved; the bindings, which are, are shown whole), then the bindings
/// no grant in force covers. When the live-key guard refuses the approval
/// as it stands, the statement says so, and that nothing is approved.
pub fn render_statement_with(
    p: &PendingDescriptor,
    o: &ApprovalOptions,
    looks_like_value: &dyn Fn(&str) -> bool,
) -> String {
    let e = escape_for_display;
    let hide = |s: &str| shown_name(s, looks_like_value);
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
    if let Some(m) = &p.managed {
        let _ = writeln!(
            t,
            "  managed MCP server {}: {}",
            e(&m.name),
            if m.written_by_migrate_mcp {
                "written by migrate-mcp on this device"
            } else {
                "registered by an agent or unknown process"
            }
        );
        if let (Some(l), Some(r)) = (&m.launch, m.revision) {
            let _ = writeln!(
                t,
                "    its registered launch {} revision {r} ({}, {}): this approval covers that \
                 revision only",
                e(l),
                e(m.class.as_deref().unwrap_or("")),
                e(m.strength.as_deref().unwrap_or(""))
            );
        }
        if let Some(o) = &m.origin {
            let _ = writeln!(
                t,
                "    its origin {}: the relay sends the header there only",
                e(o)
            );
        }
        let agent = match (&p.subject.kind, &p.subject.label) {
            (SubjectKind::Agent, Some(l)) => e(l),
            _ => "the agent".to_owned(),
        };
        let _ = writeln!(t, "    {}", crate::managed::residual_sentence(&agent));
    }
    // The test items first, before the live bindings and their ticks
    // (SPEC §10b "Live-key guard"): each with the line that binds it. The
    // daemon never swaps one in.
    if !p.proposals.is_empty() {
        let _ = writeln!(
            t,
            "  test keys of the same provider, proposed instead of live ones (EnvCloak never \
             swaps them in: bind one, then run the command again):"
        );
        for x in &p.proposals {
            let _ = writeln!(
                t,
                "    {}: the test key {}, not the live key {}",
                hide(&x.env_name),
                x.shown_reference(looks_like_value),
                hide(&x.live_slug)
            );
            let _ = writeln!(
                t,
                "      to bind it: {}",
                x.advice(&p.project.manifest, looks_like_value)
            );
        }
    }
    let guarded = live_guarded(p.subject.kind);
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
        t.push_str(&binding_line(b, o, guarded));
    }
    if !granted.is_empty() {
        let _ = writeln!(
            t,
            "  also held by this grant (a grant for this process tree and project covered \
             them when this was asked):"
        );
        for b in &granted {
            t.push_str(&binding_line(b, o, guarded));
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
    let unticked = unticked_live(p, o);
    if unticked.is_empty() {
        t.push_str("The passphrase you enter approves exactly this, and nothing else.\n");
        return t;
    }
    let flags: Vec<String> = unticked
        .iter()
        .map(|n| format!("--live {}", e(n)))
        .collect();
    let _ = writeln!(
        t,
        "  live keys: {} gets a live key only where you tick it, and this approval leaves {} \
         unticked, so it creates no grant (live_not_ticked). Approve again with {}{}.",
        who.trim_end(),
        unticked.len(),
        flags.join(" "),
        proposed_for(p, &unticked)
            .map(|names| format!(", or bind the test key proposed above for {names}"))
            .unwrap_or_default()
    );
    t.push_str(
        "Nothing is approved: no passphrase is asked for an approval that leaves a live key \
         unticked.\n",
    );
    t
}

/// The variables among `unticked` that a proposal names, escaped and
/// joined with commas, or `None` when no proposal names any: the test keys
/// a refusal of an approval that leaves them unticked can point to.
pub fn proposed_for(p: &PendingDescriptor, unticked: &[&str]) -> Option<String> {
    let names: Vec<String> = unticked
        .iter()
        .filter(|n| p.proposals.iter().any(|x| x.env_name == **n))
        .map(|n| escape_for_display(n))
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
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
