//! How the metadata commands print what they found (SPEC §4.4: metadata
//! only; T11 output discipline).
//!
//! Every command's output is a type of `envcloak_ipc::view`, rendered as
//! text for a person ([`Render::human`]) or as JSON (`--json`,
//! [`Render::json`]). [`Render`] is implemented only for those types, which
//! cannot hold a value (`envcloak_ipc::view::View`), so no rendering path
//! has one to print.
//!
//! Every string came from the daemon or a file, both of which the user
//! does not fully control: a program running as the user could answer in
//! the daemon's place, and an agent can write the manifest. So text is
//! escaped before it is printed ([`shown`]: control characters, bidi
//! overrides and invisible characters become visible escapes), and a name
//! shaped like a key rather than a name is not printed at all, in the text
//! or in the JSON ([`HIDDEN`] takes its place), since it is most likely a
//! value pasted in its place. JSON is written through one writer
//! ([`json_text`]) that escapes, as `\uXXXX`, every character the text
//! escapes (C1 controls such as U+009B, DEL, bidirectional controls such
//! as U+202E, zero-width characters, tags), in paths too: serde_json alone
//! escapes only U+0000 to U+001F, the quote and the backslash, and an
//! agent chooses these characters through file and directory names. Two
//! kinds of string are not names: the ids the daemon makes,
//! which are shaped like tokens and kept when they have an id's shape
//! ([`shown_id`]), and paths, which are only escaped ([`shown_path`]).
//!
//! Accounts are personal: `ls` shows them only with `--long` (the daemon
//! sends them only then), and `show` always.

use std::fmt::Write as _;

use envcloak_ipc::view::{
    AddedView, BackupView, CheckReport, ClassificationView, DeleteReport, EntryStatus,
    EnvFileState, EnvFileView, FileBackupCreatorView, FileChange, ImportItemView, ImportReport,
    InitReport, ItemClassView, ItemView, ItemsView, LengthClass, RecoveredView,
    RecoveryConfirmedView, RefChange, RefEditView, RefStatus, RemovedView, RotatedView, SkipReason,
    TargetView, UndoReport, View,
};
use envcloak_policy::{Proposal, display_escaped, escape_for_display, shown_name, value_shaped};

/// The most env files `envcloak check` reads in a directory, the first by
/// name; the rest are counted as not read, and the report says so.
pub const MAX_ENV_FILES: usize = 64;

/// What a command prints: text for a person, or JSON. Implemented only for
/// `envcloak_ipc::view` types.
pub trait Render: View {
    /// The text a person reads, ending in a newline.
    fn human(&self) -> String;

    /// The JSON form, as the daemon's answer carries it, with the names the
    /// text hides replaced by [`HIDDEN`] ([`hide_names`]).
    fn json(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        hide_names(&mut v, None);
        v
    }
}

/// The JSON keys whose strings are paths, shown whole ([`shown_path`]).
const PATH_KEYS: [&str; 6] = [
    "manifest",
    "project_dir",
    "root",
    "dir",
    "path",
    "file_name",
];

/// Replaces with [`HIDDEN`] every string of `v` that the text would hide:
/// a name that looks like a value, or an `id` that is not an id's shape.
/// Paths ([`PATH_KEYS`]) stay. A `backup` is an undo's id or a vault
/// backup's file name, as the text shows it: kept when it is either, and
/// hidden only when it looks like a value (verifier review of M2-02: `rm
/// --json` hid the file name `envcloak recover --backup` needs). `key` is
/// the key `v` is under; the items of an array are under the array's key.
fn hide_names(v: &mut serde_json::Value, key: Option<&str>) {
    match v {
        serde_json::Value::String(s) => {
            let keep = match key {
                Some("id") => shown_id(s) == *s,
                Some("backup") => shown_id(s) == *s || !looks_like_value(s),
                Some(k) if PATH_KEYS.contains(&k) => true,
                _ => !looks_like_value(s),
            };
            if !keep {
                HIDDEN.clone_into(s);
            }
        }
        serde_json::Value::Array(a) => {
            for x in a {
                hide_names(x, key);
            }
        }
        serde_json::Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                hide_names(x, Some(k));
            }
        }
        _ => {}
    }
}

/// Prints `v` on standard output, as JSON when `json` ([`json_text`]).
pub fn print(v: &impl Render, json: bool) {
    if json {
        print_json(&v.json());
    } else {
        print!("{}", v.human());
    }
}

/// serde_json's compact form, with every character a terminal would act
/// on or not show ([`display_escaped`]: C1 controls, DEL, bidirectional
/// controls, zero-width characters, tags) written as a `\uXXXX` escape (a
/// surrogate pair above U+FFFF), as serde_json writes U+0000 to U+001F.
/// Parsed back, the JSON is unchanged.
#[derive(Debug)]
struct TerminalSafe;

impl serde_json::ser::Formatter for TerminalSafe {
    fn write_string_fragment<W>(&mut self, w: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            if !display_escaped(c) {
                continue;
            }
            w.write_all(&fragment.as_bytes()[start..i])?;
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                write!(w, "\\u{u:04x}")?;
            }
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
}

/// `v` as the JSON every `--json` prints: compact, with
/// [`TerminalSafe`]'s escapes. `null` if it cannot be written, which a
/// view never causes.
pub fn json_text<T: serde::Serialize + ?Sized>(v: &T) -> String {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, TerminalSafe);
    if v.serialize(&mut ser).is_err() {
        return "null".to_owned();
    }
    String::from_utf8(out).unwrap_or_else(|_| "null".to_owned())
}

/// Prints `v` on standard output as [`json_text`], and a newline.
pub fn print_json<T: serde::Serialize + ?Sized>(v: &T) {
    println!("{}", json_text(v));
}

/// What is printed in place of a name that looks like a value: the words
/// an approval statement shows in place of a proposed name too.
pub use envcloak_policy::HIDDEN;

/// The provider registry compiled into this build, loaded once. `None`
/// when it did not load; names are then checked by their shape alone.
pub fn registry() -> Option<&'static envcloak_providers::Registry> {
    static REGISTRY: std::sync::OnceLock<Option<envcloak_providers::Registry>> =
        std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| envcloak_providers::load_embedded().ok())
        .as_ref()
}

/// Whether `s` looks like a key or token rather than a name: shaped like
/// a generated key ([`value_shaped`]), or holding a word that a provider's
/// key pattern matches whole. A word is a run of letters, digits, `_` and
/// `-` (and, tried again, `.`, `+`, `/`, `=` and `~`), as the audit log's
/// masking takes it (`envcloak_providers::Registry::mask_keys`): a key
/// glued to other letters is not a word of its own.
pub fn looks_like_value(s: &str) -> bool {
    value_shaped(s) || registry().is_some_and(|r| r.mask_keys(s) != s)
}

/// `s` as it may be printed: escaped, or [`HIDDEN`] when it looks like a
/// value.
pub fn shown(s: &str) -> String {
    if looks_like_value(s) {
        HIDDEN.to_owned()
    } else {
        escape_for_display(s)
    }
}

/// A test item proposed in place of a live one (SPEC §10b "Live-key
/// guard"), as the `approval_required` text of `envcloak run` and
/// `envcloak mcp` names it: the variable, the live item, the test item and
/// `how`, how to bind it in the live one's place ([`Proposal::advice`] for
/// the run's manifest, or the MCP tool's own words), then `then`. Every
/// name is escaped, and one that looks like a key or token
/// ([`looks_like_value`]) is [`HIDDEN`]: the daemon's answer is the only
/// source of these names, and a program can answer in its place (SPEC
/// §1.1).
pub fn proposal_text(x: &Proposal, how: &str, then: &str) -> String {
    let hide = |s: &str| shown_name(s, &looks_like_value);
    format!(
        "{} is bound to the live key {}: to use the test key {} instead, {how}, and {then}",
        hide(&x.env_name),
        hide(&x.live_slug),
        x.shown_reference(&looks_like_value),
    )
}

/// Whether every name of `x` is one that is shown (none looks like a key
/// or token, [`looks_like_value`]): a record that carries names unmasked
/// (the run's status record) carries only such a proposal.
pub fn proposal_shown_whole(x: &Proposal) -> bool {
    let names = [
        Some(x.env_name.as_str()),
        Some(x.live_slug.as_str()),
        Some(x.test_slug.as_str()),
        x.test_field.as_deref(),
        match &x.source {
            envcloak_policy::BindingSource::Profile { profile } => Some(profile.as_str()),
            _ => None,
        },
    ];
    !names.into_iter().flatten().any(looks_like_value)
}

/// A path as it may be printed: escaped only. A path is not a name in
/// whose place a value gets pasted, and a directory named like a hash (a
/// git worktree, a CI checkout, `/nix/store`) is common: hiding the path
/// would hide which file was meant.
fn shown_path(s: &str) -> String {
    escape_for_display(s)
}

/// An id the daemon made (26 Crockford base32 characters) as it may be
/// printed. Ids are shaped like tokens, so [`shown`] would hide them; one
/// that is not an id's shape is hidden instead.
fn shown_id(s: &str) -> String {
    let crockford = |b: u8| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b));
    if s.len() == 26 && s.bytes().all(crockford) {
        s.to_owned()
    } else {
        HIDDEN.to_owned()
    }
}

/// An optional name as it may be printed, `-` when absent.
fn shown_or_dash(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_owned(), shown)
}

/// Days since 1970-01-01 as a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// Unix seconds as `YYYY-MM-DD`, UTC.
pub fn date(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn time(secs: u64) -> String {
    let s = secs % 86_400;
    format!(
        "{} {:02}:{:02}:{:02} UTC",
        date(secs),
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

fn class_word(c: ItemClassView) -> &'static str {
    match c {
        ItemClassView::Secret => "secret",
        ItemClassView::Card => "card",
        ItemClassView::IssuerCredential => "issuer credential",
        ItemClassView::Login => "login",
        ItemClassView::Other => "unknown class",
    }
}

fn kind_word(c: ClassificationView) -> &'static str {
    match c {
        ClassificationView::Test => "test key",
        ClassificationView::Live => "live key",
        ClassificationView::Unknown => "not classified",
    }
}

/// `openai (test key)`, or the classification alone.
fn provider_and_kind(i: &ItemView) -> String {
    match i.provider.as_deref() {
        Some(p) => format!("{} ({})", shown(p), kind_word(i.classification)),
        None => kind_word(i.classification).to_owned(),
    }
}

/// `OpenAI; openai, test key`: an item in a statement.
fn described(i: &ItemView) -> String {
    let kind = match i.provider.as_deref() {
        Some(p) => format!("{}, {}", shown(p), kind_word(i.classification)),
        None => kind_word(i.classification).to_owned(),
    };
    format!("{}; {kind}", shown(&i.title))
}

/// Words for why the references were not checked.
fn unchecked_text(token: &str) -> String {
    match token {
        "no_manifest" => "there is no envcloak.toml".to_owned(),
        "daemon_unavailable" => "the EnvCloak daemon is not running".to_owned(),
        "daemon_unverified" => "the daemon could not be verified".to_owned(),
        "vault_locked" => "the vault is locked; run `envcloak unlock`".to_owned(),
        "no_vault" => "there is no vault yet".to_owned(),
        other => shown(other),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The account in one line: the email, then the label and org in
/// parentheses.
fn account_line(i: &ItemView) -> Option<String> {
    let a = i.account.as_ref()?;
    let mut parts = Vec::new();
    if let Some(e) = &a.email {
        parts.push(shown(e));
    }
    let mut extra = Vec::new();
    if let Some(l) = &a.label {
        extra.push(format!("label {}", shown(l)));
    }
    if let Some(o) = &a.org_id {
        extra.push(format!("org {}", shown(o)));
    }
    if !extra.is_empty() {
        parts.push(format!("({})", extra.join(", ")));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// Lays out rows in columns two spaces apart, the last column unpadded.
fn columns(rows: &[Vec<String>]) -> String {
    let n = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..n)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for r in rows {
        let mut line = String::new();
        for (c, cell) in r.iter().enumerate() {
            if c + 1 == r.len() {
                line.push_str(cell);
            } else {
                let pad = widths[c].saturating_sub(cell.chars().count());
                line.push_str(cell);
                line.push_str(&" ".repeat(pad + 2));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

impl Render for ItemsView {
    fn human(&self) -> String {
        if self.items.is_empty() {
            return "The vault has no items yet. Add one with `envcloak add`.\n".to_owned();
        }
        let long = self.items.iter().any(|i| i.account.is_some());
        // Only when an item's value was found outside the vault.
        let exposed = self.items.iter().any(|i| i.exposed.is_some());
        let mut header = vec!["SLUG", "PROVIDER", "KIND", "FIELDS", "UPDATED"];
        if long {
            header.extend(["ENV", "ACCOUNT", "TITLE"]);
        }
        if exposed {
            header.push("NOTE");
        }
        let mut rows = vec![header.into_iter().map(str::to_owned).collect::<Vec<_>>()];
        for i in &self.items {
            let fields: Vec<String> = i.fields.iter().map(|f| shown(&f.name)).collect();
            let mut row = vec![
                shown(&i.slug),
                shown_or_dash(i.provider.as_deref()),
                i.classification.as_str().to_owned(),
                fields.join(","),
                date(i.updated_secs),
            ];
            if long {
                row.push(shown_or_dash(i.env_hint.as_deref()));
                row.push(account_line(i).unwrap_or_else(|| "-".to_owned()));
                row.push(shown(&i.title));
            }
            if exposed {
                row.push(if i.exposed.is_some() {
                    "exposed: rotate".to_owned()
                } else {
                    "-".to_owned()
                });
            }
            rows.push(row);
        }
        columns(&rows)
    }
}

impl Render for ItemView {
    fn human(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "{}", shown(&self.slug));
        let _ = writeln!(o, "  title: {}", shown(&self.title));
        let _ = writeln!(o, "  id: {}", shown_id(&self.id));
        if self.class != ItemClassView::Secret {
            let _ = writeln!(o, "  class: {}", class_word(self.class));
        }
        let _ = writeln!(o, "  provider: {}", shown_or_dash(self.provider.as_deref()));
        let _ = writeln!(o, "  kind: {}", kind_word(self.classification));
        if let Some(x) = &self.exposed {
            let places: Vec<&str> = x.sources.iter().map(|k| k.words()).collect();
            // The mark stays until every value from before it is replaced.
            let each = if self.fields.len() > 1 {
                " each of its fields"
            } else {
                ""
            };
            let _ = writeln!(
                o,
                "  exposed: rotate (found in {}; {}; marked {}): its value is known outside the \
                 vault, so replace it at the provider, then `envcloak rotate`{each}",
                places.join(", "),
                plural(x.count, "place", "places"),
                date(x.since_secs)
            );
        }
        if let Some(e) = &self.env_hint {
            let _ = writeln!(o, "  usual variable: {}", shown(e));
        }
        let _ = writeln!(
            o,
            "  short values: {}",
            if self.allow_short {
                "allowed (values of 8 to 15 bytes may be injected)"
            } else {
                "not allowed"
            }
        );
        if let Some(a) = account_line(self) {
            let _ = writeln!(o, "  account: {a}");
        }
        let _ = writeln!(o, "  fields:");
        for f in &self.fields {
            let _ = writeln!(
                o,
                "    {}: set {}, {} kept",
                shown(&f.name),
                time(f.updated_secs),
                plural(u64::from(f.prior_count), "prior value", "prior values")
            );
        }
        let _ = writeln!(o, "  created: {}", time(self.created_secs));
        let _ = writeln!(o, "  updated: {}", time(self.updated_secs));
        if let Some(t) = self.rotated_secs {
            let _ = writeln!(o, "  rotated: {}", time(t));
        }
        if let Some(t) = self.expires_secs {
            let _ = writeln!(o, "  expires: {}", time(t));
        }
        if let Some(d) = &self.detail {
            if let Some(t) = d.last_used_secs {
                let _ = writeln!(o, "  last used: {}", time(t));
            }
            if !d.allowed_hosts.is_empty() {
                let hosts: Vec<String> = d.allowed_hosts.iter().map(|h| shown(h)).collect();
                let _ = writeln!(o, "  allowed hosts: {}", hosts.join(", "));
            }
            if !d.tags.is_empty() {
                let tags: Vec<String> = d.tags.iter().map(|t| shown(t)).collect();
                let _ = writeln!(o, "  tags: {}", tags.join(", "));
            }
            let links = [
                ("docs", &d.links.docs),
                ("billing", &d.links.billing),
                ("keys page", &d.links.keys_page),
                ("dashboard", &d.links.dashboard),
            ];
            for (name, link) in links {
                if let Some(l) = link {
                    let _ = writeln!(o, "  {name}: {}", shown(l));
                }
            }
            if let Some(n) = &d.notes {
                let _ = writeln!(o, "  notes: {}", shown(n));
            }
        }
        o
    }
}

/// What the length bucket means for `envcloak run`, when it is worth
/// saying.
fn length_note(length: LengthClass, allow_short: bool) -> Option<&'static str> {
    match (length, allow_short) {
        (LengthClass::Ok, _) => None,
        (LengthClass::Short, true) => Some(
            "the value is 8 to 15 bytes long: `envcloak run` injects it because the item allows \
             short values, and warns that redaction may miss some of its encodings",
        ),
        (LengthClass::Short, false) => Some(
            "the value is 8 to 15 bytes long: `envcloak run` refuses to inject it unless the \
             item allows short values (`envcloak add --allow-short`)",
        ),
        (LengthClass::TooShort, _) => {
            Some("the value is under 8 bytes long: `envcloak run` never injects it")
        }
    }
}

impl Render for AddedView {
    fn human(&self) -> String {
        let i = &self.item;
        let mut o = String::new();
        let _ = writeln!(o, "Added {}.", shown(&i.slug));
        let _ = writeln!(o, "  provider: {}", provider_and_kind(i));
        let _ = writeln!(o, "  field: {}", shown(&self.field));
        if let Some(a) = account_line(i) {
            let _ = writeln!(o, "  account: {a}");
        }
        if let Some(d) = &self.detected {
            let _ = writeln!(o, "note: the value is shaped like a {} key", shown(d));
        }
        if self.ambiguous {
            let _ = writeln!(
                o,
                "note: the value matches the key patterns of several providers; name one with \
                 `envcloak add <provider>`"
            );
        }
        if let Some(n) = length_note(self.length, i.allow_short) {
            let _ = writeln!(o, "warning: {n}");
        }
        let var = i.env_hint.as_deref().unwrap_or("NAME");
        let _ = writeln!(
            o,
            "Reference it in a project with: envcloak ref {}={}",
            shown(var),
            shown(&i.slug)
        );
        o
    }
}

impl Render for RotatedView {
    fn human(&self) -> String {
        let mut o = format!(
            "Rotated {}#{}: the new value is in place, and {} kept.\n",
            shown(&self.slug),
            shown(&self.field),
            plural(
                u64::from(self.prior_count),
                "prior value is",
                "prior values are"
            )
        );
        if let Some(from) = self.reclassified_from {
            let _ = writeln!(
                o,
                "Reclassified from {} to {} by the new value: {} that bound the item ended, so \
                 its runs need a new approval.",
                from.as_str(),
                self.classification.as_str(),
                plural(self.grants_ended, "grant", "grants")
            );
        }
        if let Some(n) = length_note(self.length, true) {
            let _ = writeln!(o, "note: {n}");
        }
        o
    }
}

impl Render for RemovedView {
    fn human(&self) -> String {
        let mut o = format!("Removed {} from the vault.\n", shown(&self.slug));
        let _ = writeln!(
            o,
            "  backup: {} in the vault's backups directory; `envcloak recover --backup <file>` \
             brings the item back",
            shown(&self.backup)
        );
        let _ = writeln!(o, "  grants that bound it and ended: {}", self.grants_ended);
        o
    }
}

/// The words for a reference that does not resolve.
pub fn status_text(s: RefStatus) -> &'static str {
    match s {
        RefStatus::Ok => "ok",
        RefStatus::UnknownItem => "no item has that slug",
        RefStatus::UnknownField => "the item has no field of that name",
        RefStatus::AmbiguousField => "the item has several fields: name one with <slug>#<field>",
        RefStatus::NoField => "the item has no fields",
        RefStatus::CardReference => "a card is never bound to a variable",
        RefStatus::IssuerCredentialReference => "an issuer credential is never bound to a variable",
        RefStatus::UnknownItemClass => "the item is of a class that cannot be bound",
        RefStatus::LoginReference => {
            "a login's field is never bound to a variable: only a sign-in opens it"
        }
        RefStatus::InvalidReference => "not NAME=<slug>[#field]",
        RefStatus::LooksLikeValue => {
            "shaped like a key or token rather than a name, so not shown: was a value pasted here?"
        }
        RefStatus::Unchecked => "not checked: the daemon could not be asked",
    }
}

fn env_file_state(f: &EnvFileView) -> String {
    match f.state {
        EnvFileState::Read => {
            if f.plaintext.is_empty() {
                "no key-shaped values".to_owned()
            } else {
                format!(
                    "{} in plaintext",
                    plural(
                        u64::try_from(f.plaintext.len()).unwrap_or(u64::MAX),
                        "key",
                        "keys"
                    )
                )
            }
        }
        EnvFileState::Invalid => format!(
            "not read: {}",
            f.error
                .as_deref()
                .map_or_else(|| "it does not parse".to_owned(), shown)
        ),
        EnvFileState::Symlink => "skipped: a symlink, which is never followed".to_owned(),
        EnvFileState::NotRegular => "skipped: not a regular file".to_owned(),
        EnvFileState::NotOwned => "skipped: owned by another user".to_owned(),
        EnvFileState::TooLarge => "skipped: larger than 1 MiB".to_owned(),
        EnvFileState::Unreadable => "skipped: it could not be read".to_owned(),
    }
}

impl Render for CheckReport {
    fn human(&self) -> String {
        let mut o = String::new();
        // References the daemon answered do not resolve, and references
        // it was not asked about: two different things to say.
        let mut missing = 0u64;
        let mut not_checked = 0u64;
        match &self.manifest {
            Some(m) => {
                let name = self
                    .references
                    .as_ref()
                    .and_then(|r| r.project_name.as_deref())
                    .map(|n| format!(" (project {})", shown(n)))
                    .unwrap_or_default();
                let _ = writeln!(o, "manifest: {}{name}", shown_path(m));
            }
            None => {
                let _ = writeln!(o, "manifest: none in this directory or above it");
            }
        }
        match (&self.references, &self.unchecked) {
            (Some(r), _) => {
                // The header is the manifest's bindings: with no manifest
                // there are none to list, and "none" would read as no
                // reference at all above an env file's checked ones
                // (review R-16).
                if r.bindings.is_empty() {
                    if self.manifest.is_some() {
                        let _ = writeln!(o, "references: none");
                    }
                } else {
                    let _ = writeln!(o, "references:");
                }
                for b in &r.bindings {
                    let place = b
                        .profile
                        .as_deref()
                        .map_or_else(|| "[env]".to_owned(), |p| format!("[env.{}]", shown(p)));
                    let binding = match (&b.env_name, &b.reference) {
                        (Some(n), Some(r)) => format!("{} = {}", shown(n), shown(r)),
                        _ => HIDDEN.to_owned(),
                    };
                    if b.status.is_ok() {
                        let _ = writeln!(o, "  ok       {place} {binding}");
                    } else {
                        missing += 1;
                        let _ =
                            writeln!(o, "  MISSING  {place} {binding}: {}", status_text(b.status));
                    }
                }
            }
            (None, Some(why)) => {
                let _ = writeln!(o, "references: not checked: {}", unchecked_text(why));
            }
            (None, None) => {}
        }
        let mut plaintext = 0u64;
        let scan_error = self.env_scan_error.as_deref().map(scan_error_text);
        match (self.env_files.is_empty(), scan_error) {
            (true, Some(why)) => {
                let _ = writeln!(o, "env files: {why}");
            }
            (true, None) => {
                let _ = writeln!(o, "env files: none");
            }
            (false, _) => {
                let _ = writeln!(o, "env files:");
            }
        }
        for f in &self.env_files {
            let _ = writeln!(o, "  {}: {}", shown(&f.file), env_file_state(f));
            if let Some(line) = f.error_line {
                let _ = writeln!(o, "    at line {line}");
            }
            for p in &f.plaintext {
                plaintext += 1;
                let name = shown_or_dash(p.env_name.as_deref());
                let provider = p
                    .provider
                    .as_deref()
                    .map(|p| format!(" ({} key)", shown(p)))
                    .unwrap_or_default();
                let _ = writeln!(o, "    line {}: {name}{provider}", p.line);
            }
            for r in &f.references {
                let binding = match (&r.env_name, &r.reference) {
                    (Some(n), Some(rf)) => format!("{} = envcloak://{}", shown(n), shown(rf)),
                    _ => HIDDEN.to_owned(),
                };
                if r.status.is_ok() {
                    let _ = writeln!(o, "    line {}: ok       {binding}", r.line);
                } else if r.status == RefStatus::Unchecked {
                    not_checked += 1;
                    let _ = writeln!(o, "    line {}: not checked  {binding}", r.line);
                } else {
                    missing += 1;
                    let _ = writeln!(
                        o,
                        "    line {}: MISSING  {binding}: {}",
                        r.line,
                        status_text(r.status)
                    );
                }
            }
        }
        if self.env_files_skipped > 0 {
            let _ = writeln!(
                o,
                "  {} not read: at most {MAX_ENV_FILES} are checked, the first by name",
                plural(
                    self.env_files_skipped,
                    "more env file was",
                    "more env files were"
                )
            );
        }
        if let (false, Some(why)) = (self.env_files.is_empty(), scan_error) {
            let _ = writeln!(o, "  {why}");
        }
        if self.clean() {
            let _ = writeln!(o, "result: ok");
        } else {
            let mut parts = Vec::new();
            if missing > 0 {
                parts.push(plural(
                    missing,
                    "reference does not resolve",
                    "references do not resolve",
                ));
            }
            if plaintext > 0 {
                parts.push(format!(
                    "{} in env files: move them into the vault with `envcloak add`, and \
                     rotate any that were shared",
                    plural(plaintext, "plaintext key", "plaintext keys")
                ));
            }
            if self.references_unchecked() {
                parts.push("the references were not checked".to_owned());
            } else if not_checked > 0 {
                parts.push(plural(
                    not_checked,
                    "reference was not checked",
                    "references were not checked",
                ));
            }
            let unread = self
                .env_files
                .iter()
                .filter(|f| f.state != EnvFileState::Read)
                .count();
            let unread = u64::try_from(unread)
                .unwrap_or(u64::MAX)
                .saturating_add(self.env_files_skipped);
            if unread > 0 {
                parts.push(plural(
                    unread,
                    "env file was not read",
                    "env files were not read",
                ));
            }
            if self.env_scan_error.is_some() {
                parts.push(
                    "the env-file check is incomplete: the project directory could not be \
                     listed in full; make it readable and run the check again"
                        .to_owned(),
                );
            }
            let _ = writeln!(o, "result: {}", parts.join("; "));
        }
        o
    }
}

/// Words for a [`CheckReport`]'s `env_scan_error`.
fn scan_error_text(token: &str) -> &'static str {
    match token {
        CheckReport::DIRECTORY_UNREADABLE => {
            "the project directory could not be listed, so its env files were not read"
        }
        CheckReport::LISTING_FAILED => {
            "the listing of the project directory broke off; more env files may not have been read"
        }
        _ => "the project directory could not be listed in full",
    }
}

impl Render for RefEditView {
    fn human(&self) -> String {
        let place = self
            .profile
            .as_deref()
            .map_or_else(|| "[env]".to_owned(), |p| format!("[env.{}]", shown(p)));
        let binding = format!("{} = {}", shown(&self.env_name), shown(&self.reference));
        let manifest = shown_path(&self.manifest);
        let mut o = match self.change {
            RefChange::Added => format!("Added {binding} to {place} in {manifest}.\n"),
            RefChange::Replaced => format!(
                "Set {binding} in {place} in {manifest} (it was {}).\n",
                shown_or_dash(self.previous.as_deref())
            ),
            RefChange::Unchanged => {
                format!("{binding} is already in {place} in {manifest}; nothing changed.\n")
            }
        };
        if self.resolves != RefStatus::Ok {
            let _ = writeln!(
                o,
                "warning: the reference does not resolve yet: {}",
                status_text(self.resolves)
            );
        }
        o
    }
}

/// The statement `rotate` shows before it asks for the passphrase.
pub fn rotate_statement(t: &TargetView) -> String {
    let i = &t.item;
    let field = t.field.as_deref().unwrap_or("");
    let prior = i
        .fields
        .iter()
        .find(|f| f.name == field)
        .map_or(0, |f| f.prior_count);
    let mut o = format!(
        "Rotate {}#{} ({}).\n",
        shown(&i.slug),
        shown(field),
        described(i)
    );
    let _ = writeln!(
        o,
        "  The current value becomes the newest prior value; the vault keeps 3 at most ({} now).",
        prior
    );
    let _ = writeln!(
        o,
        "  Grants that bind this item stay in force: {}, unless the new value is classified \
         otherwise (test, live), which ends them.",
        t.grants
    );
    o
}

/// The statement `rm` shows before it asks for the passphrase.
pub fn remove_statement(t: &TargetView) -> String {
    let i = &t.item;
    let fields: Vec<String> = i.fields.iter().map(|f| shown(&f.name)).collect();
    let mut o = format!(
        "Remove {} ({}) and its values from the vault.\n",
        shown(&i.slug),
        described(i)
    );
    let _ = writeln!(o, "  fields: {}", fields.join(", "));
    let _ = writeln!(
        o,
        "  An encrypted backup of the vault is written first, so `envcloak recover --backup \
         <file>` can bring it back."
    );
    let _ = writeln!(o, "  Grants that bind this item end: {}.", t.grants);
    o
}

/// Why an env-file entry was left out, in words.
fn skip_text(r: SkipReason) -> &'static str {
    match r {
        SkipReason::Empty => "left out: empty",
        SkipReason::TooShort => "left out: under 8 bytes, so not a secret to inject",
        SkipReason::NotSecret => "left out: configuration, not a secret",
        SkipReason::Interpolated => "left out: it interpolates another variable",
        SkipReason::Reference => "an envcloak:// reference already",
        SkipReason::LooksLikeValue => "left out: its name is shaped like a key",
        SkipReason::TooLarge => "left out: over 64 KiB",
        SkipReason::NulByte => "left out: it holds a NUL byte",
        SkipReason::Guessable => {
            "left out: short enough to guess, so only a person at a terminal with no agent \
             imports it or has it matched against the vault"
        }
    }
}

fn change_text(c: FileChange) -> &'static str {
    match c {
        FileChange::Created => "created",
        FileChange::Updated => "updated",
        FileChange::Unchanged => "unchanged",
        FileChange::Refused => {
            "left alone: a symlink, a hard link, not valid, or it changed while it was edited"
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Words for a reason token of the scan, the deletion or an undo.
fn path_reason(token: &str) -> String {
    let words = match token {
        "symlink" => "a symlink, which is never followed",
        "not_regular" => "not a regular file (a FIFO, socket, device or directory)",
        "not_owned" => "owned by another user",
        "too_large" => "larger than 1 MiB, so it was not read",
        "unreadable" => "permission denied",
        "not_found" => "not found",
        "changed" => "it changed since it was read",
        "mount_point" => "on another volume, which a scan never enters",
        "too_many_entries" => "a directory with too many entries to scan",
        "too_deep" => "deeper than a scan goes",
        "not_a_profile_name" => "the part after .env. makes no profile name",
        "leftover" => {
            "left by an interrupted change of an env file, and may hold plaintext: look at it, \
             then delete it"
        }
        "not_utf8" => "its path is not UTF-8",
        "hard_linked" => "it has another hard link, so it is never deleted",
        "invalid" => "it does not parse, so it cannot be checked",
        "recently_changed" => "modified in the last 2 minutes, so it may be in use",
        "open_elsewhere" => "another program has it open",
        "unchecked" => "whether another program has it open could not be checked, so it was kept",
        "moved_aside" => {
            "another program saved over it, or wrote into its new file, while it was changed; \
             that file was kept under this name, and nothing was removed"
        }
        "not_removed" => {
            "its file was changed, but this old copy, which may hold plaintext, could not be \
             removed: look at it, then delete it"
        }
        "aside_changed" => {
            "its file was changed, but another program changed the old copy under this name, or \
             put its own file there, meanwhile, so it was kept as it is: it may be that program's"
        }
        "exists" => "a file is there that is not what the deletion left, and is left as it is",
        "swap_unsupported" => {
            "its file system cannot swap two names in one step, so it was left as it is rather \
             than renamed over unchecked"
        }
        "deleted_since" => {
            "the deletion rewrote it and it was deleted since, so it is left deleted: writing it \
             back would bring back what was deleted"
        }
        "unrecorded" => {
            "the backup does not record what the deletion left of it, so only the recovery form \
             --unrecorded writes it back, where it is missing"
        }
        "restored" => "restored",
        "unchanged" => "there already, as it was",
        "no_directory" => "its directory is gone",
        "invalid_path" => "not a path it could be written to",
        "not_env_file" => "not an env file's name, so it was not written",
        "elsewhere" => "not in this project's directory: run `envcloak init --undo` in its own",
        other => return shown(other),
    };
    words.to_owned()
}

/// One item of an import, in a line.
fn item_line(i: &ImportItemView) -> String {
    let mut parts = vec![if i.existing {
        "in the vault already".to_owned()
    } else {
        "new".to_owned()
    }];
    if let Some(p) = &i.provider {
        parts.push(shown(p));
    }
    parts.push(kind_word(i.classification).to_owned());
    match i.length {
        LengthClass::Short => {
            parts.push("8 to 15 bytes: injected only with allow_short".to_owned())
        }
        LengthClass::TooShort => parts.push("under 8 bytes".to_owned()),
        LengthClass::Ok => {}
    }
    if i.projects > 1 {
        parts.push(format!("shared by {} projects", i.projects));
    }
    let mut line = format!("{}  ({})", shown(&i.reference), parts.join(", "));
    if i.holders.len() > 1 {
        let all: Vec<String> = i.holders.iter().map(|h| shown(h)).collect();
        let _ = write!(
            line,
            "\n      the same value is held by {} items: {} (duplicate owners)",
            i.holders.len(),
            all.join(", ")
        );
    }
    line
}

impl Render for ImportReport {
    fn human(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(
            o,
            "Scanned {}{}",
            shown_path(&self.root),
            if self.committed {
                ""
            } else {
                " (dry run: nothing was imported or written)"
            }
        );
        if self.projects.iter().all(|p| p.files.is_empty()) {
            let _ = writeln!(o, "No env files were found.");
        }
        for p in &self.projects {
            let _ = writeln!(o, "\nproject {} ({})", shown(&p.name), shown_path(&p.dir));
            for f in &p.files {
                let mut about = Vec::new();
                if let Some(pr) = &f.profile {
                    about.push(format!("profile {}", shown(pr)));
                }
                if f.template {
                    about.push("template: names only".to_owned());
                }
                if f.hard_linked {
                    about.push("hard linked: never modified".to_owned());
                }
                let about = if about.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", about.join(", "))
                };
                let _ = writeln!(o, "  {}{about}", shown(&f.file));
                if let (Some(line), Some(e)) = (f.error_line, &f.error) {
                    let _ = writeln!(o, "    not read: line {line}: {}", shown(e));
                }
                let mut rows = Vec::new();
                for e in &f.entries {
                    let name = shown_or_dash(e.name.as_deref());
                    let fate = if f.template {
                        "name only".to_owned()
                    } else if let Some(r) = e.skipped {
                        skip_text(r).to_owned()
                    } else if let Some(i) = e
                        .item
                        .and_then(|i| usize::try_from(i).ok())
                        .and_then(|i| self.items.get(i))
                    {
                        format!("-> {}", shown(&i.reference))
                    } else {
                        "found".to_owned()
                    };
                    rows.push(vec![format!("    line {}", e.line), name, fate]);
                }
                o.push_str(&columns(&rows));
            }
            if let Some(c) = p.manifest {
                let _ = writeln!(o, "  envcloak.toml: {}", change_text(c));
            }
            for c in &p.conflicts {
                let _ = writeln!(
                    o,
                    "    {} is bound to another item there already, and was left as it is",
                    shown(c)
                );
            }
            if let Some(c) = p.gitignore {
                let _ = writeln!(o, "  .gitignore: {}", change_text(c));
            }
            if let Some(ok) = p.resolves {
                let _ = writeln!(
                    o,
                    "  references: {}",
                    if ok {
                        "every one resolves"
                    } else {
                        "some do not resolve; run `envcloak check`"
                    }
                );
            }
        }
        if !self.items.is_empty() {
            let _ = writeln!(o, "\nitems:");
            for i in &self.items {
                let _ = writeln!(o, "  {}", item_line(i));
            }
        }
        if !self.skipped.is_empty() {
            let _ = writeln!(o, "\nnot read:");
            for s in &self.skipped {
                let _ = writeln!(o, "  {}: {}", shown_path(&s.path), path_reason(&s.reason));
            }
        }
        o
    }
}

impl Render for DeleteReport {
    fn human(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "Delete plaintext in {}", shown_path(&self.project_dir));
        if let Some(c) = self.gitignore.filter(|c| *c != FileChange::Unchanged) {
            let _ = writeln!(o, "  .gitignore: {}", change_text(c));
        }
        let v = &self.verify;
        if !v.files.is_empty() {
            let _ = writeln!(
                o,
                "  Recovery Kit confirmed: {}\n  every reference resolves: {}",
                yes_no(v.recovery_confirmed),
                yes_no(v.resolves)
            );
        }
        for f in &v.files {
            let _ = writeln!(
                o,
                "  {}: {}",
                shown(&f.file),
                if f.covered {
                    "every secret it holds is in the vault"
                } else {
                    "NOT every secret it holds is in the vault"
                }
            );
            for e in &f.entries {
                let name = shown_or_dash(e.name.as_deref());
                let text = match e.status {
                    EntryStatus::Stored => continue,
                    EntryStatus::LeftOut => format!(
                        "{} ({}): stays in the file",
                        name,
                        e.skipped.map_or("left out", skip_text)
                    ),
                    EntryStatus::NotStored => {
                        format!("{name}: not in the vault where envcloak.toml binds it")
                    }
                };
                let _ = writeln!(o, "    line {}: {text}", e.line);
            }
        }
        if let Some(b) = &self.backup {
            let _ = writeln!(
                o,
                "  encrypted backup: {}\n  undo with `envcloak init --undo {}` (kept 7 days)",
                shown_id(b),
                shown_id(b)
            );
        }
        let names = |v: &[String]| v.iter().map(|p| shown_path(p)).collect::<Vec<_>>();
        if !self.removed.is_empty() {
            let _ = writeln!(o, "  deleted: {}", names(&self.removed).join(", "));
        }
        if !self.rewritten.is_empty() {
            let _ = writeln!(
                o,
                "  rewritten to hold only the entries not in the vault: {}",
                names(&self.rewritten).join(", ")
            );
        }
        if !self.removed.is_empty() || !self.rewritten.is_empty() {
            let _ = writeln!(
                o,
                "  If these files were ever committed to git, synced or copied, the keys they \
                 held are exposed there: rotate them."
            );
        }
        if !self.unchanged.is_empty() {
            let _ = writeln!(
                o,
                "  left as they are, since the vault holds none of their entries: {}",
                names(&self.unchanged).join(", ")
            );
        }
        for k in &self.kept {
            let _ = writeln!(
                o,
                "  kept {}: {}",
                shown_path(&k.path),
                path_reason(&k.reason)
            );
        }
        for s in &self.skipped {
            let _ = writeln!(
                o,
                "  not considered {}: {}",
                shown_path(&s.path),
                path_reason(&s.reason)
            );
        }
        if v.files.is_empty() && self.removed.is_empty() && self.rewritten.is_empty() {
            let _ = writeln!(o, "  no env file to delete");
        }
        o
    }
}

impl Render for InitReport {
    fn human(&self) -> String {
        let mut o = self.import.as_ref().map(Render::human).unwrap_or_default();
        if let Some(d) = &self.delete {
            if !o.is_empty() {
                o.push('\n');
            }
            o.push_str(&d.human());
        }
        o
    }
}

/// Who made a file backup, as the daemon sealed it, in words: for the
/// statement `init --undo` shows before the passphrase and for its
/// report. `None` is a backup that does not record it (one an earlier
/// EnvCloak made).
pub fn made_by(c: Option<&FileBackupCreatorView>) -> String {
    match c {
        None => "made before EnvCloak recorded who makes a backup".to_owned(),
        Some(c) => match (c.kind.as_str(), c.agent.as_deref()) {
            ("terminal", _) => "made from a terminal".to_owned(),
            ("agent", Some(a)) => format!("made by an agent ({}), not by you", shown(a)),
            ("agent", None) => "made by an agent, not by you".to_owned(),
            (_, Some(a)) => format!(
                "made by a process EnvCloak could not identify ({}), not by you",
                shown(a)
            ),
            _ => "made by a process EnvCloak could not identify, not by you".to_owned(),
        },
    }
}

impl Render for UndoReport {
    fn human(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "Backup {}", shown_id(&self.backup));
        let _ = writeln!(o, "  {}", made_by(self.creator.as_ref()));
        for f in &self.files {
            let _ = writeln!(o, "  {}: {}", shown_path(&f.path), path_reason(&f.state));
        }
        o
    }
}

impl Render for BackupView {
    fn human(&self) -> String {
        let mut o = format!("Backup written: {}\n", shown_path(&self.path));
        let _ = writeln!(
            o,
            "  items: {}; size: {} bytes; made {}",
            self.items,
            self.bytes,
            time(self.created_secs)
        );
        let _ = writeln!(
            o,
            "  It opens only with the Recovery Kit: `envcloak recover --backup <file>` restores \
             the vault from it."
        );
        o
    }
}

impl Render for RecoveredView {
    fn human(&self) -> String {
        let mut o = if self.locked {
            format!(
                "Vault restored from the backup made {}, then locked: a lock request, sleep or \
                 stop came while it was restored. Run `envcloak unlock` with the new passphrase.\n",
                time(self.backup_created_secs)
            )
        } else {
            format!(
                "Vault restored from the backup made {} and unlocked.\n",
                time(self.backup_created_secs)
            )
        };
        let _ = writeln!(o, "  items: {}", self.items);
        let _ = writeln!(
            o,
            "  passphrase: the new one you gave; the Recovery Kit is unchanged, and confirmed"
        );
        if self.replaced > 0 {
            let _ = writeln!(
                o,
                "  the vault it replaced is kept beside it, as vault/replaced-<time>.db; delete \
                 it once you no longer need it"
            );
        }
        let _ = writeln!(o, "  grants: none; every run needs a new approval");
        o
    }
}

impl Render for RecoveryConfirmedView {
    fn human(&self) -> String {
        if self.already {
            "The Recovery Kit was confirmed already; it still opens the vault.\n".to_owned()
        } else {
            "Recovery Kit confirmed: it opens the vault. Keep it offline.\n".to_owned()
        }
    }
}

impl Render for envcloak_ipc::view::RefUnsetView {
    fn human(&self) -> String {
        let place = self
            .profile
            .as_deref()
            .map_or_else(|| "[env]".to_owned(), |p| format!("[env.{}]", shown(p)));
        format!("Removed {} from {place}.\n", shown(&self.env_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::view::{
        AccountView, CheckBindingView, CheckView, EnvRefView, ExposedView, ExposureSourceView,
        FieldView, ItemDetailView, LinksView, PlaintextView,
    };

    const T0: u64 = 1_790_000_000;

    /// What `init --delete-plaintext` reports a file kept for, or a file
    /// left under a temporary name after its file was changed, has words
    /// of its own, never the token alone; and a file another program
    /// changed or put under that name is never called the old copy to
    /// delete (verifier, M2-05 round 11).
    #[test]
    fn what_a_deletion_keeps_has_words() {
        for token in [
            "changed",
            "hard_linked",
            "recently_changed",
            "open_elsewhere",
            "unchecked",
            "moved_aside",
            "not_removed",
            "aside_changed",
        ] {
            assert_ne!(path_reason(token), shown(token), "{token}");
        }
        assert!(path_reason("not_removed").contains("delete it"));
        assert!(!path_reason("aside_changed").contains("delete"));
        assert!(!path_reason("moved_aside").contains("delete"));
    }

    /// An item as the daemon describes one, at `detail`: 0 summary, 1 with
    /// the account, 2 with everything.
    pub(crate) fn item(slug: &str, detail: u8) -> ItemView {
        ItemView {
            id: "01K5TESTTESTTESTTESTTESTTE".into(),
            slug: slug.into(),
            class: ItemClassView::Secret,
            title: "OpenAI".into(),
            provider: Some("openai".into()),
            classification: ClassificationView::Test,
            env_hint: Some("OPENAI_API_KEY".into()),
            allow_short: false,
            fields: vec![FieldView {
                name: "value".into(),
                prior_count: 1,
                created_secs: T0,
                updated_secs: T0 + 3600,
            }],
            created_secs: T0,
            updated_secs: T0 + 3600,
            rotated_secs: Some(T0 + 3600),
            expires_secs: None,
            last_used_secs: None,
            account: (detail >= 1).then(|| AccountView {
                email: Some("you@work.example".into()),
                label: None,
                org_id: Some("org-acme".into()),
            }),
            detail: (detail >= 2).then(|| ItemDetailView {
                allowed_hosts: vec!["api.openai.com".into()],
                tags: vec![],
                links: LinksView {
                    docs: Some("https://platform.openai.com/docs".into()),
                    billing: None,
                    keys_page: Some("https://platform.openai.com/api-keys".into()),
                    dashboard: None,
                },
                last_used_secs: None,
                notes: None,
            }),
            exposed: None,
        }
    }

    /// Compares `got` with the snapshot `want`, showing both on a mismatch
    /// (the fixtures hold no value).
    fn snap(got: impl AsRef<str>, want: &str) {
        assert_eq!(got.as_ref(), want);
    }

    /// Every rendered output, text and JSON, is exactly its snapshot: names,
    /// counts, times and fixed words, and no value anywhere.
    #[test]
    fn every_output_matches_its_snapshot() {
        let ls = ItemsView {
            items: vec![item("openai/acme-web", 0), item("openai/acme-web-2", 0)],
        };
        let long = ItemsView {
            items: vec![item("openai/acme-web", 1)],
        };
        snap(
            ls.human(),
            r#"SLUG               PROVIDER  KIND  FIELDS  UPDATED
openai/acme-web    openai    test  value   2026-09-21
openai/acme-web-2  openai    test  value   2026-09-21
"#,
        );
        snap(
            ls.json().to_string(),
            r#"{"items":[{"allow_short":false,"class":"secret","classification":"test","created_secs":1790000000,"env_hint":"OPENAI_API_KEY","expires_secs":null,"fields":[{"created_secs":1790000000,"name":"value","prior_count":1,"updated_secs":1790003600}],"id":"01K5TESTTESTTESTTESTTESTTE","provider":"openai","rotated_secs":1790003600,"slug":"openai/acme-web","title":"OpenAI","updated_secs":1790003600},{"allow_short":false,"class":"secret","classification":"test","created_secs":1790000000,"env_hint":"OPENAI_API_KEY","expires_secs":null,"fields":[{"created_secs":1790000000,"name":"value","prior_count":1,"updated_secs":1790003600}],"id":"01K5TESTTESTTESTTESTTESTTE","provider":"openai","rotated_secs":1790003600,"slug":"openai/acme-web-2","title":"OpenAI","updated_secs":1790003600}]}"#,
        );
        snap(
            long.human(),
            r#"SLUG             PROVIDER  KIND  FIELDS  UPDATED     ENV             ACCOUNT                          TITLE
openai/acme-web  openai    test  value   2026-09-21  OPENAI_API_KEY  you@work.example (org org-acme)  OpenAI
"#,
        );
        // An item found outside the vault: a note in `ls`, a line in
        // `show`, its record in JSON.
        let mut found = item("openai/acme-web", 2);
        found.exposed = Some(ExposedView {
            since_secs: T0,
            sources: vec![
                ExposureSourceView::Transcript,
                ExposureSourceView::GitHistory,
            ],
            count: 3,
        });
        let mut found_summary = item("openai/acme-web", 0);
        found_summary.exposed.clone_from(&found.exposed);
        snap(
            ItemsView {
                items: vec![found_summary, item("openai/acme-web-2", 0)],
            }
            .human(),
            r#"SLUG               PROVIDER  KIND  FIELDS  UPDATED     NOTE
openai/acme-web    openai    test  value   2026-09-21  exposed: rotate
openai/acme-web-2  openai    test  value   2026-09-21  -
"#,
        );
        snap(
            found.human(),
            r#"openai/acme-web
  title: OpenAI
  id: 01K5TESTTESTTESTTESTTESTTE
  provider: openai
  kind: test key
  exposed: rotate (found in agent transcripts, git history; 3 places; marked 2026-09-21): its value is known outside the vault, so replace it at the provider, then `envcloak rotate`
  usual variable: OPENAI_API_KEY
  short values: not allowed
  account: you@work.example (org org-acme)
  fields:
    value: set 2026-09-21 15:13:20 UTC, 1 prior value kept
  created: 2026-09-21 14:13:20 UTC
  updated: 2026-09-21 15:13:20 UTC
  rotated: 2026-09-21 15:13:20 UTC
  allowed hosts: api.openai.com
  docs: https://platform.openai.com/docs
  keys page: https://platform.openai.com/api-keys
"#,
        );
        assert!(
            found
                .json()
                .to_string()
                .contains(r#""exposed":{"count":3,"since_secs":1790000000,"sources":["transcript","git_history"]}"#)
        );
        // An item of several fields is told to rotate each: the mark stays
        // until every value from before it is replaced.
        let mut two = found.clone();
        let mut second = two.fields[0].clone();
        second.name = "secondary".into();
        two.fields.push(second);
        assert!(two.human().contains(
            "so replace it at the provider, then `envcloak rotate` each of its fields\n"
        ));
        snap(
            ItemsView { items: vec![] }.human(),
            r#"The vault has no items yet. Add one with `envcloak add`.
"#,
        );
        snap(
            item("openai/acme-web", 2).human(),
            r#"openai/acme-web
  title: OpenAI
  id: 01K5TESTTESTTESTTESTTESTTE
  provider: openai
  kind: test key
  usual variable: OPENAI_API_KEY
  short values: not allowed
  account: you@work.example (org org-acme)
  fields:
    value: set 2026-09-21 15:13:20 UTC, 1 prior value kept
  created: 2026-09-21 14:13:20 UTC
  updated: 2026-09-21 15:13:20 UTC
  rotated: 2026-09-21 15:13:20 UTC
  allowed hosts: api.openai.com
  docs: https://platform.openai.com/docs
  keys page: https://platform.openai.com/api-keys
"#,
        );
        snap(
            item("openai/acme-web", 2).json().to_string(),
            r#"{"account":{"email":"you@work.example","label":null,"org_id":"org-acme"},"allow_short":false,"class":"secret","classification":"test","created_secs":1790000000,"detail":{"allowed_hosts":["api.openai.com"],"last_used_secs":null,"links":{"billing":null,"dashboard":null,"docs":"https://platform.openai.com/docs","keys_page":"https://platform.openai.com/api-keys"},"notes":null,"tags":[]},"env_hint":"OPENAI_API_KEY","expires_secs":null,"fields":[{"created_secs":1790000000,"name":"value","prior_count":1,"updated_secs":1790003600}],"id":"01K5TESTTESTTESTTESTTESTTE","provider":"openai","rotated_secs":1790003600,"slug":"openai/acme-web","title":"OpenAI","updated_secs":1790003600}"#,
        );
        let added = AddedView {
            item: item("openai", 1),
            field: "value".into(),
            detected: None,
            ambiguous: false,
            length: LengthClass::Ok,
        };
        snap(
            added.human(),
            r#"Added openai.
  provider: openai (test key)
  field: value
  account: you@work.example (org org-acme)
Reference it in a project with: envcloak ref OPENAI_API_KEY=openai
"#,
        );
        let short = AddedView {
            detected: Some("deepseek".into()),
            ambiguous: true,
            length: LengthClass::Short,
            ..added.clone()
        };
        snap(
            short.human(),
            r#"Added openai.
  provider: openai (test key)
  field: value
  account: you@work.example (org org-acme)
note: the value is shaped like a deepseek key
note: the value matches the key patterns of several providers; name one with `envcloak add <provider>`
warning: the value is 8 to 15 bytes long: `envcloak run` refuses to inject it unless the item allows short values (`envcloak add --allow-short`)
Reference it in a project with: envcloak ref OPENAI_API_KEY=openai
"#,
        );
        let rotated = RotatedView {
            slug: "openai/acme-web".into(),
            field: "value".into(),
            prior_count: 1,
            length: LengthClass::Ok,
            classification: ClassificationView::Test,
            reclassified_from: None,
            grants_ended: 0,
        };
        snap(
            rotated.human(),
            r#"Rotated openai/acme-web#value: the new value is in place, and 1 prior value is kept.
"#,
        );
        // Review F-47: the new value is classified otherwise.
        let reclassified = RotatedView {
            classification: ClassificationView::Live,
            reclassified_from: Some(ClassificationView::Test),
            grants_ended: 1,
            ..rotated.clone()
        };
        snap(
            reclassified.human(),
            r#"Rotated openai/acme-web#value: the new value is in place, and 1 prior value is kept.
Reclassified from test to live by the new value: 1 grant that bound the item ended, so its runs need a new approval.
"#,
        );
        let removed = RemovedView {
            slug: "openai/acme-web".into(),
            grants_ended: 1,
            backup: "vault-20260929T120000Z-0123456789abcdef.ecbackup".into(),
        };
        snap(
            removed.human(),
            r#"Removed openai/acme-web from the vault.
  backup: vault-20260929T120000Z-0123456789abcdef.ecbackup in the vault's backups directory; `envcloak recover --backup <file>` brings the item back
  grants that bound it and ended: 1
"#,
        );
        // The JSON names the same file, which `envcloak recover --backup`
        // takes (verifier review of M2-02: it was hidden as an id).
        assert_eq!(
            removed.json()["backup"],
            "vault-20260929T120000Z-0123456789abcdef.ecbackup"
        );
        let target = TargetView {
            item: item("openai/acme-web", 1),
            field: Some("value".into()),
            grants: 1,
        };
        snap(
            rotate_statement(&target),
            r#"Rotate openai/acme-web#value (OpenAI; openai, test key).
  The current value becomes the newest prior value; the vault keeps 3 at most (1 now).
  Grants that bind this item stay in force: 1, unless the new value is classified otherwise (test, live), which ends them.
"#,
        );
        snap(
            remove_statement(&target),
            r#"Remove openai/acme-web (OpenAI; openai, test key) and its values from the vault.
  fields: value
  An encrypted backup of the vault is written first, so `envcloak recover --backup <file>` can bring it back.
  Grants that bind this item end: 1.
"#,
        );
        let check = CheckReport {
            manifest: Some("/src/acme-web/envcloak.toml".into()),
            references: Some(CheckView {
                project_dir: Some("/src/acme-web".into()),
                project_name: Some("acme-web".into()),
                bindings: vec![
                    CheckBindingView {
                        profile: None,
                        env_name: Some("OPENAI_API_KEY".into()),
                        reference: Some("openai/acme-web".into()),
                        status: RefStatus::Ok,
                    },
                    CheckBindingView {
                        profile: Some("short".into()),
                        env_name: Some("SHORT_TOKEN".into()),
                        reference: Some("short/acme-web".into()),
                        status: RefStatus::UnknownItem,
                    },
                    CheckBindingView {
                        profile: None,
                        env_name: None,
                        reference: None,
                        status: RefStatus::LooksLikeValue,
                    },
                ],
                refs: vec![RefStatus::Ok],
            }),
            unchecked: None,
            env_files: vec![
                EnvFileView {
                    file: ".env".into(),
                    state: EnvFileState::Read,
                    error_line: None,
                    error: None,
                    plaintext: vec![PlaintextView {
                        line: 2,
                        env_name: Some("GITHUB_TOKEN".into()),
                        provider: Some("github".into()),
                    }],
                    references: vec![EnvRefView {
                        line: 3,
                        env_name: Some("OPENAI_API_KEY".into()),
                        reference: Some("openai/acme-web".into()),
                        status: RefStatus::Ok,
                    }],
                },
                EnvFileView {
                    file: ".env.link".into(),
                    state: EnvFileState::Symlink,
                    error_line: None,
                    error: None,
                    plaintext: vec![],
                    references: vec![],
                },
            ],
            env_files_skipped: 0,
            env_scan_error: None,
        };
        snap(
            check.human(),
            r#"manifest: /src/acme-web/envcloak.toml (project acme-web)
references:
  ok       [env] OPENAI_API_KEY = openai/acme-web
  MISSING  [env.short] SHORT_TOKEN = short/acme-web: no item has that slug
  MISSING  [env] [not shown: looks like a key or token]: shaped like a key or token rather than a name, so not shown: was a value pasted here?
env files:
  .env: 1 key in plaintext
    line 2: GITHUB_TOKEN (github key)
    line 3: ok       OPENAI_API_KEY = envcloak://openai/acme-web
  .env.link: skipped: a symlink, which is never followed
result: 2 references do not resolve; 1 plaintext key in env files: move them into the vault with `envcloak add`, and rotate any that were shared; 1 env file was not read
"#,
        );
        snap(
            check.json().to_string(),
            r#"{"env_files":[{"error":null,"error_line":null,"file":".env","plaintext":[{"env_name":"GITHUB_TOKEN","line":2,"provider":"github"}],"references":[{"env_name":"OPENAI_API_KEY","line":3,"reference":"openai/acme-web","status":"ok"}],"state":"read"},{"error":null,"error_line":null,"file":".env.link","plaintext":[],"references":[],"state":"symlink"}],"env_files_skipped":0,"env_scan_error":null,"manifest":"/src/acme-web/envcloak.toml","references":{"bindings":[{"env_name":"OPENAI_API_KEY","profile":null,"reference":"openai/acme-web","status":"ok"},{"env_name":"SHORT_TOKEN","profile":"short","reference":"short/acme-web","status":"unknown_item"},{"env_name":null,"profile":null,"reference":null,"status":"looks_like_value"}],"project_dir":"/src/acme-web","project_name":"acme-web","refs":["ok"]},"unchecked":null}"#,
        );
        let clean = CheckReport {
            references: Some(CheckView {
                bindings: vec![],
                refs: vec![],
                project_dir: None,
                project_name: None,
            }),
            env_files: vec![],
            ..check.clone()
        };
        snap(
            clean.human(),
            r#"manifest: /src/acme-web/envcloak.toml
references: none
env files: none
result: ok
"#,
        );
        let unchecked = CheckReport {
            references: None,
            unchecked: Some("vault_locked".into()),
            env_files: vec![],
            ..check.clone()
        };
        snap(
            unchecked.human(),
            r#"manifest: /src/acme-web/envcloak.toml
references: not checked: the vault is locked; run `envcloak unlock`
env files: none
result: the references were not checked
"#,
        );
        // Review T11 open 1: the env files' references were not checked,
        // which is not the same as not resolving.
        let env_refs = |status| EnvFileView {
            file: ".env".into(),
            state: EnvFileState::Read,
            error_line: None,
            error: None,
            plaintext: vec![],
            references: vec![EnvRefView {
                line: 3,
                env_name: Some("OPENAI_API_KEY".into()),
                reference: Some("openai/acme-web".into()),
                status,
            }],
        };
        let locked = CheckReport {
            env_files: vec![env_refs(RefStatus::Unchecked)],
            ..unchecked.clone()
        };
        assert!(!locked.clean());
        snap(
            locked.human(),
            r#"manifest: /src/acme-web/envcloak.toml
references: not checked: the vault is locked; run `envcloak unlock`
env files:
  .env: no key-shaped values
    line 3: not checked  OPENAI_API_KEY = envcloak://openai/acme-web
result: the references were not checked
"#,
        );
        // No manifest: the env files' references were sent, and resolve.
        let no_manifest = CheckReport {
            manifest: None,
            references: Some(CheckView {
                project_dir: None,
                project_name: None,
                bindings: vec![],
                refs: vec![RefStatus::Ok],
            }),
            unchecked: None,
            env_files: vec![env_refs(RefStatus::Ok)],
            env_files_skipped: 0,
            env_scan_error: None,
        };
        assert!(no_manifest.clean());
        // Review R-16: no "references: none" there, which would read as
        // no reference at all above the env file's checked one.
        snap(
            no_manifest.human(),
            r#"manifest: none in this directory or above it
env files:
  .env: no key-shaped values
    line 3: ok       OPENAI_API_KEY = envcloak://openai/acme-web
result: ok
"#,
        );
        // Nothing to send: no manifest, no reference.
        let nothing = CheckReport {
            manifest: None,
            references: None,
            unchecked: Some(CheckReport::NOTHING_SENT.into()),
            env_files: vec![],
            env_files_skipped: 0,
            env_scan_error: None,
        };
        assert!(nothing.clean());
        // F-48: env files past the bound were not read.
        let over = CheckReport {
            env_files_skipped: 2,
            ..nothing.clone()
        };
        assert!(!over.clean());
        snap(
            over.human(),
            r#"manifest: none in this directory or above it
references: not checked: there is no envcloak.toml
env files: none
  2 more env files were not read: at most 64 are checked, the first by name
result: 2 env files were not read
"#,
        );
        assert_eq!(over.json()["env_files_skipped"], 2);
        // The F-48 follow-up: a directory that could not be listed is not
        // an empty one, and a listing that broke off leaves files unread.
        let unlisted = CheckReport {
            env_scan_error: Some(CheckReport::DIRECTORY_UNREADABLE.into()),
            ..nothing.clone()
        };
        assert!(!unlisted.clean());
        snap(
            unlisted.human(),
            r#"manifest: none in this directory or above it
references: not checked: there is no envcloak.toml
env files: the project directory could not be listed, so its env files were not read
result: the env-file check is incomplete: the project directory could not be listed in full; make it readable and run the check again
"#,
        );
        assert_eq!(unlisted.json()["env_scan_error"], "directory_unreadable");
        let broke_off = CheckReport {
            env_scan_error: Some(CheckReport::LISTING_FAILED.into()),
            env_files: vec![env_refs(RefStatus::Ok)],
            ..no_manifest.clone()
        };
        assert!(!broke_off.clean());
        snap(
            broke_off.human(),
            r#"manifest: none in this directory or above it
env files:
  .env: no key-shaped values
    line 3: ok       OPENAI_API_KEY = envcloak://openai/acme-web
  the listing of the project directory broke off; more env files may not have been read
result: the env-file check is incomplete: the project directory could not be listed in full; make it readable and run the check again
"#,
        );
        // A daemon that answered for fewer references than were sent.
        let short_answer = CheckReport {
            env_files: vec![env_refs(RefStatus::Unchecked)],
            ..no_manifest
        };
        assert!(!short_answer.clean());
        assert!(
            short_answer
                .human()
                .ends_with("result: 1 reference was not checked\n"),
            "{}",
            short_answer.human()
        );
        let edit = RefEditView {
            manifest: "/src/acme-web/envcloak.toml".into(),
            profile: None,
            env_name: "GITHUB_TOKEN".into(),
            reference: "github/acme-web".into(),
            change: RefChange::Added,
            previous: None,
            resolves: RefStatus::Ok,
        };
        snap(
            edit.human(),
            r#"Added GITHUB_TOKEN = github/acme-web to [env] in /src/acme-web/envcloak.toml.
"#,
        );
        let replaced = RefEditView {
            profile: Some("short".into()),
            change: RefChange::Replaced,
            previous: Some("github/old".into()),
            resolves: RefStatus::UnknownItem,
            ..edit.clone()
        };
        snap(
            replaced.human(),
            r#"Set GITHUB_TOKEN = github/acme-web in [env.short] in /src/acme-web/envcloak.toml (it was github/old).
warning: the reference does not resolve yet: no item has that slug
"#,
        );
        let same = RefEditView {
            change: RefChange::Unchanged,
            ..edit
        };
        snap(
            same.human(),
            r#"GITHUB_TOKEN = github/acme-web is already in [env] in /src/acme-web/envcloak.toml; nothing changed.
"#,
        );
    }

    /// Strings from the daemon or a file are escaped, and a name shaped like
    /// a key is not printed at all, as text or as JSON: a canary pasted
    /// into any name of any view never reaches either form, and no raw
    /// control character reaches the text.
    #[test]
    fn names_are_escaped_and_key_shaped_ones_hidden() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for c in &cs {
            if matches!(
                c.label.as_str(),
                envcloak_testkit::labels::VAULT_PASSPHRASE
                    | envcloak_testkit::labels::SHORT_TOKEN
                    | envcloak_testkit::labels::DATABASE_URL
            ) {
                // Word-like values are not key-shaped; they never reach a
                // name through EnvCloak (the daemon refuses them as names
                // only by their shape), so they are not checked here.
                continue;
            }
            let v = c.as_str();
            let mut i = item(v, 2);
            i.title = format!("title\u{1b}[31m {v}");
            i.provider = Some(v.to_owned());
            i.env_hint = Some(v.to_owned());
            i.fields[0].name = v.to_owned();
            if let Some(a) = i.account.as_mut() {
                a.email = Some(v.to_owned());
                // A bidirectional override and a C1 control (CSI), which
                // JSON's own encoding leaves as they are.
                a.label = Some("rtl\u{202e}txet\u{9b}31m".to_owned());
            }
            if let Some(d) = i.detail.as_mut() {
                d.tags = vec![v.to_owned()];
                d.notes = Some(format!("see {v}"));
            }
            let target = TargetView {
                item: i.clone(),
                field: Some(v.to_owned()),
                grants: 0,
            };
            let items = ItemsView {
                items: vec![i.clone()],
            };
            let added = AddedView {
                item: i.clone(),
                field: v.to_owned(),
                detected: Some(v.to_owned()),
                ambiguous: false,
                length: LengthClass::Ok,
            };
            let rotated = RotatedView {
                slug: v.to_owned(),
                field: v.to_owned(),
                prior_count: 1,
                length: LengthClass::Ok,
                classification: ClassificationView::Live,
                reclassified_from: Some(ClassificationView::Test),
                grants_ended: 1,
            };
            let removed = RemovedView {
                slug: v.to_owned(),
                grants_ended: 1,
                backup: v.to_owned(),
            };
            let check = canary_check(v);
            let edit = RefEditView {
                manifest: "/src/acme-web/envcloak.toml".into(),
                profile: Some(v.to_owned()),
                env_name: v.to_owned(),
                reference: v.to_owned(),
                change: RefChange::Replaced,
                previous: Some(v.to_owned()),
                resolves: RefStatus::Ok,
            };
            let texts = [
                i.human(),
                items.human(),
                rotate_statement(&target),
                remove_statement(&target),
                added.human(),
                rotated.human(),
                removed.human(),
                check.human(),
                edit.human(),
            ];
            for t in &texts {
                envcloak_testkit::assert_no_canary(t.as_bytes(), &cs);
                assert!(!t.chars().any(|c| c != '\n' && display_escaped(c)), "{t}");
                assert!(t.contains(HIDDEN), "{t}");
            }
            assert!(
                texts[0].contains("rtl\\u{202e}txet\\u{9b}31m"),
                "{}",
                texts[0]
            );
            // The JSON of every view hides the same names.
            let jsons = [
                i.json(),
                items.json(),
                added.json(),
                rotated.json(),
                removed.json(),
                check.json(),
                edit.json(),
            ];
            for j in &jsons {
                // As `--json` prints it: every character the text escapes
                // is a \u escape, and the JSON reads back unchanged.
                let t = json_text(j);
                envcloak_testkit::assert_no_canary(t.as_bytes(), &cs);
                assert!(t.contains(HIDDEN), "{t}");
                assert!(!t.chars().any(display_escaped), "{t:?}");
                assert_eq!(&serde_json::from_str::<serde_json::Value>(&t).unwrap(), j);
            }
            let item_json = json_text(&jsons[0]);
            assert!(
                item_json.contains(r#""rtl\u202etxet\u009b31m""#),
                "{item_json}"
            );
            assert_eq!(jsons[6]["previous"], HIDDEN);
            assert_eq!(jsons[5]["env_files"][0]["file"], HIDDEN);
            assert_eq!(jsons[5]["references"]["project_name"], HIDDEN);
            // Ids and paths are not names: they stay.
            assert_eq!(jsons[0]["id"], "01K5TESTTESTTESTTESTTESTTE");
            assert_eq!(jsons[6]["manifest"], "/src/acme-web/envcloak.toml");
            assert_eq!(jsons[5]["references"]["project_dir"], "/src/acme-web");
        }
    }

    /// A check report with `v` in every name: the project name, profiles,
    /// variables, references, env file names, providers and error texts.
    fn canary_check(v: &str) -> CheckReport {
        CheckReport {
            manifest: Some("/src/acme-web/envcloak.toml".into()),
            references: Some(CheckView {
                project_dir: Some("/src/acme-web".into()),
                project_name: Some(v.to_owned()),
                bindings: vec![CheckBindingView {
                    profile: Some(v.to_owned()),
                    env_name: Some(v.to_owned()),
                    reference: Some(v.to_owned()),
                    status: RefStatus::UnknownItem,
                }],
                refs: vec![RefStatus::Ok],
            }),
            unchecked: Some(v.to_owned()),
            env_files: vec![
                EnvFileView {
                    file: v.to_owned(),
                    state: EnvFileState::Read,
                    error_line: None,
                    error: None,
                    plaintext: vec![PlaintextView {
                        line: 2,
                        env_name: Some(v.to_owned()),
                        provider: Some(v.to_owned()),
                    }],
                    references: vec![EnvRefView {
                        line: 3,
                        env_name: Some(v.to_owned()),
                        reference: Some(v.to_owned()),
                        status: RefStatus::UnknownItem,
                    }],
                },
                EnvFileView {
                    file: ".env".into(),
                    state: EnvFileState::Invalid,
                    error_line: Some(1),
                    error: Some(v.to_owned()),
                    plaintext: vec![],
                    references: vec![],
                },
            ],
            env_files_skipped: 0,
            env_scan_error: None,
        }
    }

    /// Paths are shown whole, only escaped, even with a directory named like
    /// a hash (a git worktree, a CI checkout, `/nix/store`), so the user
    /// sees which file was edited or checked. The ids the daemon makes are
    /// kept in JSON as in text, and anything else in an id's place is
    /// hidden.
    #[test]
    fn paths_and_ids_are_shown_whole() {
        let hash: String = (0..28)
            .map(|i| char::from(b"0123456789abcdef"[(i * 7 + 3) % 16]))
            .collect();
        assert!(looks_like_value(&hash));
        let dir = format!("/tmp/ecrv/{hash}/proj");
        let manifest = format!("{dir}/envcloak.toml");
        let edit = RefEditView {
            manifest: manifest.clone(),
            profile: None,
            env_name: "B".into(),
            reference: "c/d".into(),
            change: RefChange::Added,
            previous: None,
            resolves: RefStatus::Ok,
        };
        assert_eq!(
            edit.human(),
            format!("Added B = c/d to [env] in {manifest}.\n")
        );
        assert_eq!(edit.json()["manifest"], manifest.as_str());
        let check = CheckReport {
            manifest: Some(manifest.clone()),
            references: Some(CheckView {
                project_dir: Some(dir.clone()),
                project_name: None,
                bindings: vec![],
                refs: vec![],
            }),
            unchecked: None,
            env_files: vec![],
            env_files_skipped: 0,
            env_scan_error: None,
        };
        assert!(
            check
                .human()
                .starts_with(&format!("manifest: {manifest}\n")),
            "{}",
            check.human()
        );
        let j = check.json();
        assert_eq!(j["manifest"], manifest.as_str());
        assert_eq!(j["references"]["project_dir"], dir.as_str());
        // A path is still escaped, in the text and in the JSON: an agent
        // names directories, and JSON's own encoding leaves a C1 control
        // (U+009B, CSI) or a bidirectional override (U+202E) as it is.
        let odd_dir = format!("/tmp/ecrv/{hash}/a\u{1b}[31m\u{202e}b\u{9b}31m");
        let odd = RefEditView {
            manifest: format!("{odd_dir}/envcloak.toml"),
            ..edit
        };
        let t = odd.human();
        assert!(!t.chars().any(|c| c != '\n' && display_escaped(c)), "{t:?}");
        assert!(t.contains("\\u{202e}b\\u{9b}31m"), "{t}");
        let odd_check = CheckReport {
            manifest: Some(odd.manifest.clone()),
            references: Some(CheckView {
                project_dir: Some(odd_dir.clone()),
                project_name: None,
                bindings: vec![],
                refs: vec![],
            }),
            ..check
        };
        for j in [odd.json(), odd_check.json()] {
            let t = json_text(&j);
            assert!(!t.chars().any(display_escaped), "{t:?}");
            assert!(t.contains(r"\u001b[31m\u202eb\u009b31m"), "{t}");
            assert_eq!(serde_json::from_str::<serde_json::Value>(&t).unwrap(), j);
        }
        assert_eq!(
            odd_check.json()["references"]["project_dir"],
            odd_dir.as_str()
        );

        let i = item("openai/acme-web", 0);
        assert_eq!(i.json()["id"], "01K5TESTTESTTESTTESTTESTTE");
        for bad in [hash.as_str(), "not an id", "01K5TESTTESTTESTTESTTESTTEX"] {
            let mut j = i.clone();
            j.id = bad.to_owned();
            assert_eq!(j.json()["id"], HIDDEN, "{bad}");
            assert!(j.human().contains(&format!("id: {HIDDEN}")), "{bad}");
        }
    }

    /// Gate 10 through the CLI: a value two items hold is reported with
    /// both, in the text and in the JSON.
    #[test]
    fn duplicate_owners_are_named_each() {
        let item = |holders: &[&str]| ImportItemView {
            slug: "openai/acme-web".into(),
            field: "value".into(),
            reference: "openai/acme-web".into(),
            existing: true,
            provider: Some("openai".into()),
            classification: ClassificationView::Live,
            length: LengthClass::Ok,
            holders: holders.iter().map(|h| (*h).to_owned()).collect(),
            entries: 1,
            projects: 1,
        };
        let one = item_line(&item(&["openai/acme-web"]));
        assert!(!one.contains("duplicate owners"), "{one}");
        let two = item_line(&item(&["openai/acme-web", "openai/copy"]));
        assert!(
            two.contains(
                "the same value is held by 2 items: openai/acme-web, openai/copy (duplicate \
                 owners)"
            ),
            "{two}"
        );
        let report = ImportReport {
            root: "/x".into(),
            committed: false,
            projects: Vec::new(),
            items: vec![item(&["openai/acme-web", "openai/copy"])],
            skipped: Vec::new(),
        };
        assert!(report.human().contains("(duplicate owners)"));
        assert_eq!(
            report.json()["items"][0]["holders"],
            serde_json::json!(["openai/acme-web", "openai/copy"])
        );
    }

    #[test]
    fn dates_are_civil_utc() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(time(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(time(1_790_000_000), "2026-09-21 14:13:20 UTC");
        assert_eq!(date(4_102_444_799), "2099-12-31");
    }
}
