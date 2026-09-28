//! The project manifest, `envcloak.toml` (SPEC §5 "Project manifest"), and
//! resolving the bindings a run asks for (SPEC §6.1 step 2).
//!
//! The manifest lives in the repo, where agents can edit it, so it is
//! untrusted input:
//! - Its `[policy]` can only tighten ([`crate::effective_policy`]).
//!   `agents = "allow"` fails to parse, as does any key or value this
//!   module does not know.
//! - It is capped at [`Manifest::MAX_LEN`] bytes and must be UTF-8.
//! - Errors are value-free: a [`ManifestErrorKind`] and a line number. The
//!   TOML library's own messages quote the source and are never passed on,
//!   so a value pasted into a manifest by mistake is never echoed.
//!
//! Grammar (docs/MANIFEST.md has the full text):
//! - `[project]`: `name`, display text only.
//! - `[env]`: the default profile. Each key is an environment variable
//!   ([`EnvName`]); each value a reference, as a string `"<slug>[#field]"`
//!   or an inline table `{ ref = "<slug>", field = "<field>" }`.
//! - `[env.<profile>]`: a profile ([`ProfileName`]), which inherits `[env]`
//!   and replaces or adds bindings. A standard (or dotted) table under
//!   `env` is a profile; an inline table is a binding. Profiles do not nest.
//! - `[policy]`: `agents` (`"approve"` or `"deny"`), `redact` (a boolean)
//!   and `mode` (`"proxy"` or `"inject"`).

use std::collections::{BTreeMap, BTreeSet};

use envcloak_core::vault::FieldName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml_edit::{Document, InlineTable, Item, TableLike, Value};

use crate::envfile::EnvFileNames;
use crate::names::{Binding, EnvName, ProfileName, Reference};

/// Whether a manifest lets agent subjects ask for approval at all.
/// Ordered by strictness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentsPolicy {
    /// Agents may request, and every request needs an approval (SPEC §10b).
    #[default]
    Approve,
    /// Agent requests are refused without a pending request.
    Deny,
}

/// How values reach a command. Ordered by strictness: proxy mode keeps the
/// real value out of the child (SPEC §6.2, M6). On the wire it is
/// `inject` or `proxy`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Values in the child's environment (SPEC §6.1).
    #[default]
    Inject,
    /// Placeholder tokens and the local proxy (SPEC §6.2).
    Proxy,
}

/// The manifest's `[policy]`, as written. It can only tighten the vault's
/// policy for the project; [`crate::effective_policy`] combines the two.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ManifestPolicy {
    /// [`AgentsPolicy::Approve`] when absent.
    pub agents: AgentsPolicy,
    /// `false` is ignored for agent subjects, and for any subject it never
    /// turns off what the vault turned on.
    pub redact: Option<bool>,
    /// `inject` never loosens a vault policy of proxy.
    pub mode: Option<Mode>,
}

/// A parsed `envcloak.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `[project] name`: display text only.
    pub project_name: Option<String>,
    /// The default profile, `[env]`, sorted by variable name.
    pub env: Vec<Binding>,
    /// Each `[env.<profile>]` as written: only the bindings it replaces or
    /// adds, sorted by variable name. [`resolve`] merges it over `env`.
    pub profiles: BTreeMap<ProfileName, Vec<Binding>>,
    pub policy: ManifestPolicy,
    /// SHA-256 of the bytes parsed. A comment changes it and nothing else;
    /// grants record it (SPEC §10b).
    pub sha256: [u8; 32],
}

impl Manifest {
    /// The file name the CLI looks for and the daemon opens.
    pub const FILE_NAME: &'static str = "envcloak.toml";
    /// The largest manifest accepted, in bytes.
    pub const MAX_LEN: usize = 64 * 1024;
}

/// Where in the input an error is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A line of the manifest, from 1.
    Manifest { line: u32 },
    /// The `--ref` argument at this index, from 0.
    Ref { index: usize },
    /// A line of the `--env-file` file, from 1.
    EnvFile { line: u32 },
}

impl core::fmt::Display for Origin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Origin::Manifest { line } => write!(f, "envcloak.toml line {line}"),
            Origin::Ref { index } => write!(f, "--ref argument {}", index.saturating_add(1)),
            Origin::EnvFile { line } => write!(f, "env file line {line}"),
        }
    }
}

/// What is wrong with a manifest, a `--ref`, a resolution or the path a
/// manifest was opened from. Every message is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ManifestErrorKind {
    TooLarge,
    NotUtf8,
    /// Not TOML.
    Syntax,
    /// TOML defines a key twice, including two spellings of one key.
    DuplicateKey,
    UnknownKey,
    WrongType,
    InvalidEnvName,
    InvalidProfileName,
    /// A table below `[env.<profile>]`.
    NestedProfile,
    InvalidReference,
    InvalidProjectName,
    /// `agents = "allow"`: a manifest cannot loosen policy (gate 17).
    LoosePolicy,
    InvalidPolicy,
    /// `--profile` names a profile the manifest does not have.
    UnknownProfile,
    /// `--ref` and `--env-file` name one variable twice between them.
    DuplicateEnvName,
    /// Not an absolute path to a file named `envcloak.toml`.
    InvalidPath,
    NotFound,
    /// `envcloak.toml` is a symlink (SPEC §5: refused).
    SymlinkedManifest,
    NotRegularFile,
    /// Owned by another user.
    NotOwned,
    /// The directory's path named another directory by the time it was
    /// checked again.
    DirectoryChanged,
    /// Another I/O error.
    Io(std::io::ErrorKind),
}

impl ManifestErrorKind {
    /// The stable token, for the daemon's error reasons.
    pub fn token(self) -> &'static str {
        use ManifestErrorKind as K;
        match self {
            K::TooLarge => "too_large",
            K::NotUtf8 => "not_utf8",
            K::Syntax => "syntax",
            K::DuplicateKey => "duplicate_key",
            K::UnknownKey => "unknown_key",
            K::WrongType => "wrong_type",
            K::InvalidEnvName => "invalid_env_name",
            K::InvalidProfileName => "invalid_profile_name",
            K::NestedProfile => "nested_profile",
            K::InvalidReference => "invalid_reference",
            K::InvalidProjectName => "invalid_project_name",
            K::LoosePolicy => "loose_policy",
            K::InvalidPolicy => "invalid_policy",
            K::UnknownProfile => "unknown_profile",
            K::DuplicateEnvName => "duplicate_env_name",
            K::InvalidPath => "invalid_path",
            K::NotFound => "not_found",
            K::SymlinkedManifest => "symlinked_manifest",
            K::NotRegularFile => "not_regular_file",
            K::NotOwned => "not_owned",
            K::DirectoryChanged => "directory_changed",
            K::Io(_) => "io",
        }
    }

    fn message(self) -> &'static str {
        use ManifestErrorKind as K;
        match self {
            K::TooLarge => "the manifest is larger than 64 KiB",
            K::NotUtf8 => "the manifest is not UTF-8",
            K::Syntax => "not valid TOML",
            K::DuplicateKey => "a key is defined twice",
            K::UnknownKey => "unknown key",
            K::WrongType => "a value has the wrong type",
            K::InvalidEnvName => {
                "invalid variable name: expected an ASCII letter or _, then letters, digits or _ \
                 (at most 128 bytes)"
            }
            K::InvalidProfileName => {
                "invalid profile name: expected a lowercase letter or digit, then those, _ or - \
                 (at most 64 bytes)"
            }
            K::NestedProfile => "profiles do not nest: [env.<profile>] holds bindings only",
            K::InvalidReference => {
                "invalid reference: expected \"<slug>[#field]\" or { ref = \"<slug>\", field = \
                 \"<field>\" }"
            }
            K::InvalidProjectName => {
                "invalid project name: 1 to 128 bytes, without control or invisible characters"
            }
            K::LoosePolicy => {
                "agents = \"allow\" is not accepted: a manifest can only tighten policy \
                 (approve | deny)"
            }
            K::InvalidPolicy => {
                "invalid [policy] value: agents is approve or deny, mode is proxy or inject"
            }
            K::UnknownProfile => "the manifest has no such profile",
            K::DuplicateEnvName => "the variable is bound twice by --ref and --env-file",
            K::InvalidPath => "not an absolute path to a file named envcloak.toml",
            K::NotFound => "no envcloak.toml there",
            K::SymlinkedManifest => "envcloak.toml is a symlink, which is refused",
            K::NotRegularFile => "envcloak.toml is not a regular file",
            K::NotOwned => "envcloak.toml is owned by another user",
            K::DirectoryChanged => "the project directory changed while it was opened",
            K::Io(_) => "cannot read the manifest",
        }
    }
}

/// A manifest, `--ref` or resolution error: a kind and where it is, never
/// the text that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestError {
    kind: ManifestErrorKind,
    origin: Option<Origin>,
}

impl ManifestError {
    pub fn kind(&self) -> ManifestErrorKind {
        self.kind
    }

    pub fn origin(&self) -> Option<Origin> {
        self.origin
    }

    /// The same error at `origin`.
    pub fn at(self, origin: Origin) -> Self {
        ManifestError {
            origin: Some(origin),
            ..self
        }
    }

    /// The stable token `envcloak run` prints (SPEC §6.1 step 9): the
    /// bindings a run asked for beyond the manifest (`--profile`, `--ref`,
    /// `--env-file`) cannot be resolved, or else the manifest is invalid.
    pub fn token(&self) -> &'static str {
        match (self.kind, self.origin) {
            (ManifestErrorKind::UnknownProfile | ManifestErrorKind::DuplicateEnvName, _)
            | (_, Some(Origin::Ref { .. } | Origin::EnvFile { .. })) => "binding_unresolved",
            _ => "manifest_invalid",
        }
    }
}

impl From<ManifestErrorKind> for ManifestError {
    fn from(kind: ManifestErrorKind) -> Self {
        ManifestError { kind, origin: None }
    }
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(o) = self.origin {
            write!(f, "{o}: ")?;
        }
        f.write_str(self.kind.message())?;
        if let ManifestErrorKind::Io(k) = self.kind {
            write!(f, " ({k})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ManifestError {}

/// Line numbers for byte offsets into the manifest.
struct Lines<'a>(&'a [u8]);

impl Lines<'_> {
    fn at(&self, offset: usize) -> u32 {
        let end = offset.min(self.0.len());
        let n = self.0[..end].iter().filter(|&&b| b == b'\n').count();
        u32::try_from(n).unwrap_or(u32::MAX).saturating_add(1)
    }

    /// The line of `key` in `table`, if the parser recorded its place.
    fn key(&self, table: &dyn TableLike, key: &str) -> Option<u32> {
        let span = table.key(key)?.span()?;
        Some(self.at(span.start))
    }

    fn err(&self, kind: ManifestErrorKind, line: Option<u32>) -> ManifestError {
        placed(kind.into(), line)
    }
}

fn placed(e: ManifestError, line: Option<u32>) -> ManifestError {
    match line {
        Some(line) => e.at(Origin::Manifest { line }),
        None => e,
    }
}

/// Parses a manifest. See the module documentation for the grammar and the
/// rules.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    if bytes.len() > Manifest::MAX_LEN {
        return Err(ManifestErrorKind::TooLarge.into());
    }
    let lines = Lines(bytes);
    let text = std::str::from_utf8(bytes)
        .map_err(|e| lines.err(ManifestErrorKind::NotUtf8, Some(lines.at(e.valid_up_to()))))?;
    let doc = Document::parse(text).map_err(|e| {
        // Classified by its fixed description; the message itself quotes
        // the source and is dropped.
        let kind = if e.message().starts_with("duplicate key") {
            ManifestErrorKind::DuplicateKey
        } else {
            ManifestErrorKind::Syntax
        };
        lines.err(kind, e.span().map(|s| lines.at(s.start)))
    })?;
    let mut m = Manifest {
        project_name: None,
        env: Vec::new(),
        profiles: BTreeMap::new(),
        policy: ManifestPolicy::default(),
        sha256: Sha256::digest(bytes).into(),
    };
    let root = doc.as_table();
    for (key, item) in root.iter() {
        let line = lines.key(root, key);
        match key {
            "project" => m.project_name = project(&lines, item, line)?,
            "env" => env(&lines, item, line, &mut m)?,
            "policy" => m.policy = policy(&lines, item, line)?,
            _ => return Err(lines.err(ManifestErrorKind::UnknownKey, line)),
        }
    }
    m.env.sort();
    Ok(m)
}

fn table<'a>(
    lines: &Lines<'_>,
    item: &'a Item,
    line: Option<u32>,
) -> Result<&'a dyn TableLike, ManifestError> {
    item.as_table_like()
        .ok_or_else(|| lines.err(ManifestErrorKind::WrongType, line))
}

fn project(
    lines: &Lines<'_>,
    item: &Item,
    line: Option<u32>,
) -> Result<Option<String>, ManifestError> {
    let t = table(lines, item, line)?;
    let mut name = None;
    for (key, v) in t.iter() {
        let line = lines.key(t, key);
        if key != "name" {
            return Err(lines.err(ManifestErrorKind::UnknownKey, line));
        }
        let s = v
            .as_str()
            .ok_or_else(|| lines.err(ManifestErrorKind::WrongType, line))?;
        if !valid_project_name(s) {
            return Err(lines.err(ManifestErrorKind::InvalidProjectName, line));
        }
        name = Some(s.to_owned());
    }
    Ok(name)
}

/// 1 to 128 bytes, with no control characters and none of the invisible
/// ones an approval screen could be spoofed with (bidirectional controls,
/// zero-width characters, the byte-order mark).
pub(crate) fn valid_project_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
        })
}

fn env(
    lines: &Lines<'_>,
    item: &Item,
    line: Option<u32>,
    m: &mut Manifest,
) -> Result<(), ManifestError> {
    let t = table(lines, item, line)?;
    for (key, v) in t.iter() {
        let line = lines.key(t, key);
        let Item::Table(p) = v else {
            m.env.push(binding(lines, key, v, line)?);
            continue;
        };
        let name = ProfileName::new(key).map_err(|e| placed(e, line))?;
        let mut list = Vec::new();
        for (key, v) in p.iter() {
            let line = lines.key(p, key);
            if matches!(v, Item::Table(_)) {
                return Err(lines.err(ManifestErrorKind::NestedProfile, line));
            }
            list.push(binding(lines, key, v, line)?);
        }
        list.sort();
        m.profiles.insert(name, list);
    }
    Ok(())
}

fn binding(
    lines: &Lines<'_>,
    key: &str,
    item: &Item,
    line: Option<u32>,
) -> Result<Binding, ManifestError> {
    let env_name = EnvName::new(key).map_err(|e| placed(e, line))?;
    let reference = match item {
        Item::Value(Value::String(s)) => {
            Reference::parse(s.value()).map_err(|e| placed(e, line))?
        }
        Item::Value(Value::InlineTable(t)) => table_reference(lines, t, line)?,
        _ => return Err(lines.err(ManifestErrorKind::WrongType, line)),
    };
    Ok(Binding {
        env_name,
        reference,
    })
}

/// `{ ref = "<slug>", field = "<field>" }`: `ref` is a slug alone, and
/// `field` is optional.
fn table_reference(
    lines: &Lines<'_>,
    t: &InlineTable,
    line: Option<u32>,
) -> Result<Reference, ManifestError> {
    let invalid = || lines.err(ManifestErrorKind::InvalidReference, line);
    let mut slug = None;
    let mut field = None;
    for (key, v) in t.iter() {
        let at = lines.key(t, key).or(line);
        let s = match key {
            "ref" => &mut slug,
            "field" => &mut field,
            _ => return Err(lines.err(ManifestErrorKind::UnknownKey, at)),
        };
        *s = Some(
            v.as_str()
                .ok_or_else(|| lines.err(ManifestErrorKind::WrongType, at))?,
        );
    }
    let slug = slug.filter(|s| !s.contains('#')).ok_or_else(invalid)?;
    let r = Reference::parse(slug).map_err(|_| invalid())?;
    let field = field
        .map(FieldName::new)
        .transpose()
        .map_err(|_| invalid())?;
    Ok(Reference {
        slug: r.slug,
        field,
    })
}

fn policy(
    lines: &Lines<'_>,
    item: &Item,
    line: Option<u32>,
) -> Result<ManifestPolicy, ManifestError> {
    let t = table(lines, item, line)?;
    let mut p = ManifestPolicy::default();
    for (key, v) in t.iter() {
        let line = lines.key(t, key);
        let wrong = || lines.err(ManifestErrorKind::WrongType, line);
        let invalid = || lines.err(ManifestErrorKind::InvalidPolicy, line);
        match key {
            "agents" => {
                p.agents = match v.as_str().ok_or_else(wrong)? {
                    "approve" => AgentsPolicy::Approve,
                    "deny" => AgentsPolicy::Deny,
                    s if s.eq_ignore_ascii_case("allow") => {
                        return Err(lines.err(ManifestErrorKind::LoosePolicy, line));
                    }
                    _ => return Err(invalid()),
                }
            }
            "redact" => p.redact = Some(v.as_bool().ok_or_else(wrong)?),
            "mode" => {
                p.mode = Some(match v.as_str().ok_or_else(wrong)? {
                    "inject" => Mode::Inject,
                    "proxy" => Mode::Proxy,
                    _ => return Err(invalid()),
                })
            }
            _ => return Err(lines.err(ManifestErrorKind::UnknownKey, line)),
        }
    }
    Ok(p)
}

/// The bindings a run asks for, sorted by variable name.
///
/// Later layers replace earlier ones, variable by variable:
/// 1. the manifest's `[env]`;
/// 2. `profile`'s `[env.<profile>]`, which must exist;
/// 3. the explicit bindings: `env`'s references and `refs`. They must not
///    name one variable twice between them
///    ([`ManifestErrorKind::DuplicateEnvName`], at the later one). An
///    ordinary variable in `env` is set from the file, so it removes the
///    manifest's binding of that name.
///
/// A binding that changes here is a new binding for the grant check
/// (SPEC §10b "Match"), which compares variable, item and field.
pub fn resolve(
    m: &Manifest,
    profile: Option<&ProfileName>,
    refs: &[Binding],
    env: Option<&EnvFileNames>,
) -> Result<Vec<Binding>, ManifestError> {
    let mut out: BTreeMap<&EnvName, &Reference> =
        m.env.iter().map(|b| (&b.env_name, &b.reference)).collect();
    if let Some(p) = profile {
        let over = m
            .profiles
            .get(p)
            .ok_or(ManifestError::from(ManifestErrorKind::UnknownProfile))?;
        out.extend(over.iter().map(|b| (&b.env_name, &b.reference)));
    }
    let mut explicit = BTreeSet::new();
    let mut claim = |name: &EnvName, origin: Origin| {
        if explicit.insert(name.clone()) {
            Ok(())
        } else {
            Err(ManifestError::from(ManifestErrorKind::DuplicateEnvName).at(origin))
        }
    };
    if let Some(env) = env {
        for r in &env.refs {
            claim(&r.binding.env_name, Origin::EnvFile { line: r.line })?;
            out.insert(&r.binding.env_name, &r.binding.reference);
        }
        for p in &env.plain {
            claim(&p.name, Origin::EnvFile { line: p.line })?;
            out.remove(&p.name);
        }
    }
    for (index, b) in refs.iter().enumerate() {
        claim(&b.env_name, Origin::Ref { index })?;
        out.insert(&b.env_name, &b.reference);
    }
    Ok(out
        .into_iter()
        .map(|(n, r)| Binding {
            env_name: n.clone(),
            reference: r.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let e = ManifestError::from(ManifestErrorKind::InvalidReference);
        assert_eq!(e.token(), "manifest_invalid");
        assert_eq!(
            e.at(Origin::Manifest { line: 2 }).token(),
            "manifest_invalid"
        );
        assert_eq!(e.at(Origin::Ref { index: 0 }).token(), "binding_unresolved");
        assert_eq!(
            e.at(Origin::EnvFile { line: 1 }).token(),
            "binding_unresolved"
        );
        for k in [
            ManifestErrorKind::UnknownProfile,
            ManifestErrorKind::DuplicateEnvName,
        ] {
            assert_eq!(ManifestError::from(k).token(), "binding_unresolved");
        }
        for k in [
            ManifestErrorKind::SymlinkedManifest,
            ManifestErrorKind::LoosePolicy,
            ManifestErrorKind::Io(std::io::ErrorKind::PermissionDenied),
        ] {
            assert_eq!(ManifestError::from(k).token(), "manifest_invalid");
        }
    }

    #[test]
    fn messages_name_the_place() {
        let e = ManifestError::from(ManifestErrorKind::UnknownKey).at(Origin::Manifest { line: 7 });
        assert_eq!(e.to_string(), "envcloak.toml line 7: unknown key");
        let e =
            ManifestError::from(ManifestErrorKind::DuplicateEnvName).at(Origin::Ref { index: 1 });
        assert_eq!(
            e.to_string(),
            "--ref argument 2: the variable is bound twice by --ref and --env-file"
        );
        let e = ManifestError::from(ManifestErrorKind::Io(std::io::ErrorKind::PermissionDenied));
        assert!(
            e.to_string().starts_with("cannot read the manifest ("),
            "{e}"
        );
    }

    #[test]
    fn line_numbers() {
        let l = Lines(b"a\nb\n\nc");
        assert_eq!(
            [l.at(0), l.at(1), l.at(2), l.at(4), l.at(5), l.at(99)],
            [1, 1, 2, 3, 4, 4]
        );
    }
}
