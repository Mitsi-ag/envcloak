//! Import and the deletion of plaintext after it (SPEC §6.4, gates 10 and
//! 16): `import.plan`, `import.commit`, `import.verify`, `files.backup`,
//! `files.restore` and `recovery.confirm`.
//!
//! The CLI scans and parses env files (so a macOS privacy prompt names the
//! terminal, not the daemon) and sends each entry's value to this verified
//! daemon, which alone holds the key to compare values and seal them:
//! - Each value is sorted: a secret to keep, or left where it is for a
//!   fixed reason ([`SkipReason`]): empty, under 8 bytes (never injected,
//!   so a port or a flag), a name shaped like a key (a value pasted in its
//!   place), over the field cap, or configuration: no provider's key
//!   pattern matches, the name holds no word that says secret
//!   ([`SECRET_WORDS`]), and the value is neither a URL with a password
//!   nor shaped like a generated key.
//! - Secrets are grouped by keyed hash ([`Vault::value_key`]): the same
//!   value in two files, or two repos, becomes one item that both
//!   manifests reference. A value some items hold already binds to the
//!   first of them by slug, and when several hold it, every one is
//!   reported (gate 10: duplicate owners).
//! - A new item is named after its provider, or its variable, and its
//!   project: `openai/acme-web`, `database-url/acme-web`, with the profile
//!   added for a profile's file (`short-token/acme-web-short`) and a
//!   number when the slug is taken. A project or profile name shaped like
//!   a key (a directory named by a hash) is never kept: it is
//!   [`SAFE_PROJECT`] instead, or left out, and no slug shaped like a key
//!   is made. Its provider, classification, links and hosts are detected
//!   from the value, as `add` detects them.
//! - The plan's digest covers every entry's fate, every item and each
//!   value's keyed hash; `import.commit` works the plan out again under
//!   the same lock it writes under, and refuses unless the digest is the
//!   one the person was shown.
//!
//! `import.verify` answers the delete gate: whether each secret a file
//! holds is in the vault where the manifest (opened here, not sent) binds
//! its variable, whether every reference resolves, and whether the
//! Recovery Kit is confirmed. `files.backup` writes the encrypted backup
//! a deletion needs first, and purges backups over 7 days old.
//!
//! Comparing a value with the vault tells the caller whether the vault
//! holds it, so it is guarded as SPEC §6.5 guards doctor's matching:
//! - A value short enough to guess ([`guessable`]: under 16 bytes, and no
//!   provider's key pattern matches it) is imported and compared only for
//!   a person: a terminal subject with no agent by any evidence, as a
//!   proof requires. For any other caller it is left where it is
//!   ([`SkipReason::Guessable`]) by the plan and by `import.verify`,
//!   whether the vault holds it or not.
//! - Each subject root may have [`MAX_VALUE_CHECKS`] values compared in
//!   [`CHECK_WINDOW`] of awake time (`import.plan`, `import.commit` and
//!   `import.verify` count), and more are refused (`too_many_checks`).
//! - Each `import.plan`, `import.commit` and `import.verify` is audited
//!   with the count of values compared (kind `import`, outcome `checked`),
//!   and a refusal too.
//!
//! `files.restore` and `recovery.confirm` are proofs, as `rotate` is: the
//! caller must be a terminal subject with no agent by any evidence, the
//! attempt limiter must admit the attempt, and the passphrase (or the
//! kit) must open its envelope, checked with the vault taken out of the
//! slot while Argon2id runs. `files.restore` is the one other method that
//! hands plaintext to a client: it gives back the files the person asked
//! to put back (`envcloak init --undo`), and like a covered run's
//! delivery, only after its audit entry is written durably
//! (`audit_failed` otherwise).
//!
//! Nothing here answers with a value except `files.restore`, and no error
//! repeats text a client sent.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{CryptoErrorKind, ItemClass};
use envcloak_core::file_backup::{BackupFile, FileBackupId, purge_file_backups};
use envcloak_core::vault::{
    Classification, FieldName, ItemDetails, ItemMeta, MAX_FIELD, NewItem, Slug, ValueKey, Vault,
    VaultError, VaultErrorKind,
};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_ipc::proto::{
    ErrorKind, FilesBackupParams, FilesRestoreParams, ImportCommitParams, ImportParams,
    RecoveryConfirmParams, RestoredFile, RestoredFiles, VerifyParams,
};
use envcloak_ipc::view::{
    ClassificationView, EntryStatus, FileBackupView, ImportEntryView, ImportItemView,
    ImportPlanView, LengthClass, RecoveryConfirmedView, SkipReason, VerifyEntryView,
    VerifyFileView, VerifyView,
};
use envcloak_ipc::{RpcError, WireSecret};
use envcloak_policy::{
    Binding, EnvName, ManifestError, ProcessInstance, ProfileName, SubjectEvidence, bind_items,
    load_project, resolve,
};
use envcloak_providers::shaped_like_secret;
use envcloak_sys::PeerIdentity;
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::{DEFAULT_FIELD, DEFAULT_SLUG, looks_like_value};
use crate::requests::{evidence, refuse_unless_prover, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{State, vault_reason};

/// Entries one import takes at most.
pub const MAX_ENTRIES: usize = 10_000;
/// Projects one import takes at most.
pub const MAX_PROJECTS: usize = 1_000;
/// Words of a variable's name (split at `_`) that say it holds a secret.
pub const SECRET_WORDS: [&str; 21] = [
    "KEY",
    "KEYS",
    "APIKEY",
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWORDS",
    "PASSWD",
    "PASS",
    "PWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "CREDS",
    "PRIVATE",
    "SALT",
    "SIGNATURE",
    "SESSION",
    "DSN",
];
/// Values of fewer characters than this that no provider's key pattern
/// matches are short enough to guess (SPEC §6.4, §6.5): compared with the
/// vault only for a person.
pub const GUESSABLE_BELOW: usize = 16;
/// Values one subject root may have compared with the vault within
/// [`CHECK_WINDOW`]: an `import --scan` of the largest request (plan,
/// commit and a verify) three times over.
pub const MAX_VALUE_CHECKS: usize = 100_000;
/// The window [`MAX_VALUE_CHECKS`] counts in, in awake time.
pub const CHECK_WINDOW: Duration = Duration::from_secs(3600);
/// Subject roots counted at once; a new root beyond it takes the place of
/// the one whose window started first.
pub const MAX_CHECKING_ROOTS: usize = 4096;
/// The project part of new items' slugs when the project's name is shaped
/// like a key.
pub const SAFE_PROJECT: &str = "project";
/// Numbered slugs tried for a new item (`<base>/<project>-2`, ...).
const SLUG_TRIES: usize = 99;
/// The longest project part of a new item's slug.
const MAX_PROJECT_PART: usize = 60;

fn invalid() -> RpcError {
    RpcError::new(ErrorKind::InvalidParams)
}

/// Whether a variable's name says it holds a secret.
fn secret_name(name: &str) -> bool {
    name.split('_')
        .any(|w| SECRET_WORDS.iter().any(|s| s.eq_ignore_ascii_case(w)))
}

/// Whether `value` is short enough to guess: under [`GUESSABLE_BELOW`]
/// characters, and no provider's key pattern matches it. UTF-8 is counted
/// in characters, not bytes, so an eight-letter password in a script of
/// two-byte letters is short too; a value that is not UTF-8 is counted as
/// short as any encoding could make it, four bytes a character.
fn guessable(shared: &Shared, value: &SecretBytes) -> bool {
    let short = match value.utf8_chars() {
        Some(chars) => chars < GUESSABLE_BELOW,
        None => value.len() < GUESSABLE_BELOW * 4,
    };
    short
        && !shared
            .registry
            .as_ref()
            .is_some_and(|r| !r.detect(value, None).candidates.is_empty())
}

/// Values compared with the vault, per subject root, in the current
/// window of each.
#[derive(Debug, Default)]
pub(crate) struct ValueChecks {
    /// Each root, when its window started (awake time) and how many values
    /// it has had compared since.
    by_root: HashMap<ProcessInstance, (Duration, usize)>,
}

impl ValueChecks {
    /// Counts `n` values compared for `root` at `awake`; false (and
    /// nothing counted) when that would pass [`MAX_VALUE_CHECKS`] in the
    /// root's window. A call that compares nothing is admitted and not
    /// counted, so it takes no place in the table. With
    /// [`MAX_CHECKING_ROOTS`] roots counted, a new root takes the place of
    /// the one whose window started first: that only forgets a count, so
    /// no caller, however many roots it makes, can have another refused.
    pub(crate) fn admit(&mut self, root: &ProcessInstance, n: usize, awake: Duration) -> bool {
        self.by_root
            .retain(|_, (start, _)| awake.saturating_sub(*start) < CHECK_WINDOW);
        if n == 0 {
            return true;
        }
        if !self.by_root.contains_key(root) && self.by_root.len() >= MAX_CHECKING_ROOTS {
            let oldest = self
                .by_root
                .iter()
                .min_by_key(|(_, (start, _))| *start)
                .map(|(r, _)| r.clone());
            if let Some(r) = oldest {
                self.by_root.remove(&r);
            }
        }
        let (_, count) = self.by_root.entry(root.clone()).or_insert((awake, 0));
        match count.checked_add(n) {
            Some(total) if total <= MAX_VALUE_CHECKS => {
                *count = total;
                true
            }
            _ => false,
        }
    }
}

/// Who asks to compare values: whether the caller is a person, to whom
/// guessable values are compared too, and its evidence.
struct Asker {
    evidence: SubjectEvidence,
    person: bool,
}

/// Reads who asks, admits the values `count` says are compared for them
/// (given whether they are a person), and audits the call (`method`) with
/// that count, or the refusal.
fn ask(
    shared: &Shared,
    peer: &PeerIdentity,
    claims: &[String],
    method: &'static str,
    count: impl FnOnce(bool) -> usize,
) -> Result<Asker, RpcError> {
    let evidence = evidence(shared, peer, claims)?;
    let person = evidence.proof_refusal().is_none();
    let n = count(person);
    let now = now_of(&shared.clocks);
    let admitted = locked(&shared.value_checks).admit(&evidence.root(), n, now.awake);
    shared.audit(AuditEvent::ValuesChecked {
        pid: peer.pid,
        subject: subject_summary(peer, &evidence),
        method,
        values: n,
        refused: !admitted,
    });
    if !admitted {
        return Err(RpcError::new(ErrorKind::TooManyChecks));
    }
    Ok(Asker { evidence, person })
}

/// Whether the value of the variable `name` is compared with the vault
/// for this caller: a secret, and not short enough to guess unless the
/// caller is a person. The reason it is left out otherwise.
fn compare(
    shared: &Shared,
    name: &str,
    value: &SecretBytes,
    person: bool,
) -> Result<(), SkipReason> {
    classify(shared, name, value)?;
    if !person && guessable(shared, value) {
        return Err(SkipReason::Guessable);
    }
    Ok(())
}

/// Whether `value`, read from the variable `name`, is a secret an import
/// keeps; the reason it is left out otherwise.
fn classify(shared: &Shared, name: &str, value: &SecretBytes) -> Result<(), SkipReason> {
    if value.is_empty() {
        return Err(SkipReason::Empty);
    }
    if value.contains_byte(0) {
        return Err(SkipReason::NulByte);
    }
    if value.len() > MAX_FIELD {
        return Err(SkipReason::TooLarge);
    }
    if looks_like_value(shared, name) {
        return Err(SkipReason::LooksLikeValue);
    }
    if LengthClass::of(value.len()) == LengthClass::TooShort {
        return Err(SkipReason::TooShort);
    }
    let by_pattern = shared
        .registry
        .as_ref()
        .is_some_and(|r| !r.detect(value, Some(name)).candidates.is_empty());
    if by_pattern || secret_name(name) || shaped_like_secret(value) {
        Ok(())
    } else {
        Err(SkipReason::NotSecret)
    }
}

/// One checked entry.
struct Entry {
    project: usize,
    profile: Option<ProfileName>,
    name: EnvName,
    value: SecretBytes,
}

/// A checked [`ImportParams`]: project names and entries.
struct Input {
    projects: Vec<Slug>,
    entries: Vec<Entry>,
}

fn check_input(shared: &Shared, p: ImportParams) -> Result<(Input, Vec<String>), RpcError> {
    if p.projects.len() > MAX_PROJECTS || p.entries.len() > MAX_ENTRIES {
        return Err(invalid());
    }
    let mut projects = Vec::with_capacity(p.projects.len());
    for pr in &p.projects {
        // One slug part: new items are named `<base>/<project>`.
        if !Path::new(&pr.dir).is_absolute() || pr.name.contains('/') {
            return Err(invalid());
        }
        let name = if looks_like_value(shared, &pr.name) {
            SAFE_PROJECT
        } else {
            pr.name.as_str()
        };
        projects.push(Slug::new(name).map_err(|_| invalid())?);
    }
    let mut entries = Vec::with_capacity(p.entries.len());
    for e in p.entries {
        let project = usize::try_from(e.project).map_err(|_| invalid())?;
        if project >= projects.len() {
            return Err(invalid());
        }
        let profile = e
            .profile
            .as_deref()
            .map(ProfileName::new)
            .transpose()
            .map_err(|_| invalid())?;
        entries.push(Entry {
            project,
            profile,
            name: EnvName::new(&e.name).map_err(|_| invalid())?,
            value: e.value.into_inner(),
        });
    }
    Ok((Input { projects, entries }, p.claims))
}

/// What becomes of one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    Skip(SkipReason),
    Item(usize),
}

/// One item of a plan.
struct PlannedItem {
    key: ValueKey,
    /// The entry whose value it gets.
    first: usize,
    slug: Slug,
    field: FieldName,
    reference: String,
    /// Items that held the value before, by slug; bound to the first.
    holders: Vec<Slug>,
    /// For a new item: what it is made with.
    details: Option<ItemDetails>,
    provider: Option<String>,
    classification: Classification,
    length: LengthClass,
    entries: u32,
    projects: BTreeSet<usize>,
}

struct Plan {
    fates: Vec<Fate>,
    items: Vec<PlannedItem>,
    digest: [u8; 32],
}

/// A slug part from a variable's name: `DATABASE_URL` is `database-url`.
fn name_base(name: &EnvName) -> String {
    let mut s: String = name
        .as_str()
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    while s.starts_with('-') {
        s.remove(0);
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.is_empty() {
        DEFAULT_SLUG.to_owned()
    } else {
        s
    }
}

/// The first free slug of `base/project[-profile]`, then numbered, that is
/// not shaped like a key. A profile shaped like a key is left out.
fn new_slug(
    shared: &Shared,
    v: &Vault,
    taken: &BTreeSet<Slug>,
    base: &str,
    project: &Slug,
    profile: Option<&ProfileName>,
) -> Result<Slug, RpcError> {
    let mut part = project.as_str().to_owned();
    if let Some(p) = profile.filter(|p| !looks_like_value(shared, p.as_str())) {
        part.push('-');
        part.push_str(p.as_str());
    }
    part.truncate(MAX_PROJECT_PART);
    while part.ends_with(['-', '.', '_']) {
        part.pop();
    }
    let mut base = base.to_owned();
    base.truncate(MAX_PROJECT_PART);
    while base.ends_with(['-', '.', '_']) {
        base.pop();
    }
    (1..=SLUG_TRIES)
        .map(|n| {
            if n == 1 {
                format!("{base}/{part}")
            } else {
                format!("{base}/{part}-{n}")
            }
        })
        .filter_map(|s| Slug::new(&s).ok())
        .filter(|s| !looks_like_value(shared, s.as_str()))
        .find(|s| v.find(s).is_none() && !taken.contains(s))
        .ok_or_else(|| RpcError::with_reason(ErrorKind::InvalidItem, "no_free_slug"))
}

/// The secret items of `v` holding `value`, by slug, with the field.
fn holders<'v>(v: &'v Vault, value: &SecretBytes) -> Vec<(&'v ItemMeta, FieldName)> {
    let fields = v.find_by_value(value);
    let mut out: Vec<(&ItemMeta, FieldName)> = v
        .items()
        .iter()
        .filter(|m| m.class == ItemClass::Secret)
        .filter_map(|m| {
            m.fields
                .iter()
                .find(|f| fields.contains(&f.id))
                .map(|f| (m, f.name.clone()))
        })
        .collect();
    out.sort_by(|a, b| a.0.slug.cmp(&b.0.slug));
    out
}

fn reference(m: &ItemMeta, field: &FieldName) -> String {
    if m.fields.len() == 1 {
        m.slug.as_str().to_owned()
    } else {
        format!("{}#{}", m.slug, field)
    }
}

/// How many of `input`'s values are compared with the vault for a person
/// or not.
fn compared(shared: &Shared, input: &Input, person: bool) -> usize {
    input
        .entries
        .iter()
        .filter(|e| compare(shared, e.name.as_str(), &e.value, person).is_ok())
        .count()
}

/// Works out the plan, for a person or not ([`Asker::person`]). See the
/// module documentation.
fn plan(shared: &Shared, v: &Vault, input: &Input, person: bool) -> Result<Plan, RpcError> {
    let mut fates = Vec::with_capacity(input.entries.len());
    let mut items: Vec<PlannedItem> = Vec::new();
    let mut by_key: BTreeMap<ValueKey, usize> = BTreeMap::new();
    let mut taken = BTreeSet::new();
    for (i, e) in input.entries.iter().enumerate() {
        if let Err(r) = compare(shared, e.name.as_str(), &e.value, person) {
            fates.push(Fate::Skip(r));
            continue;
        }
        let key = v.value_key(&e.value);
        let at = match by_key.get(&key) {
            Some(&at) => at,
            None => {
                let item = new_item(shared, v, &mut taken, input, i, key)?;
                items.push(item);
                by_key.insert(key, items.len() - 1);
                items.len() - 1
            }
        };
        items[at].entries += 1;
        items[at].projects.insert(e.project);
        fates.push(Fate::Item(at));
    }
    let digest = digest(&fates, &items);
    Ok(Plan {
        fates,
        items,
        digest,
    })
}

fn new_item(
    shared: &Shared,
    v: &Vault,
    taken: &mut BTreeSet<Slug>,
    input: &Input,
    first: usize,
    key: ValueKey,
) -> Result<PlannedItem, RpcError> {
    let e = &input.entries[first];
    let length = LengthClass::of(e.value.len());
    let found = holders(v, &e.value);
    if let Some((m, field)) = found.first() {
        return Ok(PlannedItem {
            key,
            first,
            slug: m.slug.clone(),
            reference: reference(m, field),
            field: field.clone(),
            holders: found.iter().map(|(m, _)| m.slug.clone()).collect(),
            details: None,
            provider: m.details.provider.clone(),
            classification: m.details.classification,
            length,
            entries: 0,
            projects: BTreeSet::new(),
        });
    }
    let mut details = ItemDetails {
        env_hint: Some(e.name.as_str().to_owned()),
        ..ItemDetails::default()
    };
    let mut provider = None;
    if let Some(r) = shared.registry.as_ref() {
        let d = r.detect(&e.value, Some(e.name.as_str()));
        r.prefill(&d, &mut details);
        provider = d.provider.map(|p| p.as_str().to_owned());
    }
    let base = provider.clone().unwrap_or_else(|| name_base(&e.name));
    let slug = new_slug(
        shared,
        v,
        taken,
        &base,
        &input.projects[e.project],
        e.profile.as_ref(),
    )?;
    taken.insert(slug.clone());
    slug.as_str().clone_into(&mut details.title);
    let classification = details.classification;
    Ok(PlannedItem {
        key,
        first,
        reference: slug.as_str().to_owned(),
        slug,
        field: FieldName::new(DEFAULT_FIELD).map_err(|_| RpcError::new(ErrorKind::Internal))?,
        holders: Vec::new(),
        details: Some(details),
        provider,
        classification,
        length,
        entries: 0,
        projects: BTreeSet::new(),
    })
}

/// SHA-256 over every entry's fate and every item, value keys included:
/// the same plan of the same values gives the same digest.
fn digest(fates: &[Fate], items: &[PlannedItem]) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut put = |b: &[u8]| {
        h.update(u64::try_from(b.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(b);
    };
    put(b"envcloak/v1/import-plan");
    for f in fates {
        match f {
            Fate::Skip(r) => put(r.token().as_bytes()),
            Fate::Item(i) => put(&u64::try_from(*i).unwrap_or(u64::MAX).to_be_bytes()),
        }
    }
    for i in items {
        put(i.key.as_bytes());
        put(i.slug.as_str().as_bytes());
        put(i.reference.as_bytes());
        put(&[u8::from(i.details.is_none())]);
        for s in &i.holders {
            put(s.as_str().as_bytes());
        }
        put(i.provider.as_deref().unwrap_or("").as_bytes());
    }
    h.finalize().into()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(2 * b.len()), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn view(p: &Plan) -> ImportPlanView {
    ImportPlanView {
        digest: hex(&p.digest),
        entries: p
            .fates
            .iter()
            .map(|f| match f {
                Fate::Skip(r) => ImportEntryView {
                    item: None,
                    skipped: Some(*r),
                },
                Fate::Item(i) => ImportEntryView {
                    item: u32::try_from(*i).ok(),
                    skipped: None,
                },
            })
            .collect(),
        items: p
            .items
            .iter()
            .map(|i| ImportItemView {
                slug: i.slug.as_str().to_owned(),
                field: i.field.as_str().to_owned(),
                reference: i.reference.clone(),
                existing: i.details.is_none(),
                provider: i.provider.clone(),
                classification: ClassificationView::from(i.classification),
                length: i.length,
                holders: i.holders.iter().map(|s| s.as_str().to_owned()).collect(),
                entries: i.entries,
                projects: u32::try_from(i.projects.len()).unwrap_or(u32::MAX),
            })
            .collect(),
    }
}

/// `import.plan`.
pub fn import_plan(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ImportParams,
) -> Result<ImportPlanView, RpcError> {
    let (input, claims) = check_input(shared, p)?;
    refuse_if_traced()?;
    locked(&shared.state).unlocked()?;
    let asker = ask(shared, peer, &claims, "import.plan", |person| {
        compared(shared, &input, person)
    })?;
    let s = locked(&shared.state);
    let v = s.unlocked()?;
    Ok(view(&plan(shared, v, &input, asker.person)?))
}

/// `import.commit`.
pub fn import_commit(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ImportCommitParams,
) -> Result<ImportPlanView, RpcError> {
    let wanted = p.digest;
    let (mut input, claims) = check_input(shared, p.import)?;
    refuse_if_traced()?;
    locked(&shared.state).unlocked()?;
    let Asker {
        evidence: caller,
        person,
    } = ask(shared, peer, &claims, "import.commit", |person| {
        compared(shared, &input, person)
    })?;
    let mut s = locked(&shared.state);
    let plan = plan(shared, s.unlocked()?, &input, person)?;
    if hex(&plan.digest) != wanted {
        return Err(RpcError::new(ErrorKind::PlanChanged));
    }
    let mut new = Vec::new();
    for i in &plan.items {
        if let Some(details) = &i.details {
            let value = std::mem::replace(
                &mut input.entries[i.first].value,
                SecretBytes::copy_from(&[]),
            );
            new.push((
                NewItem {
                    class: ItemClass::Secret,
                    slug: i.slug.clone(),
                    details: details.clone(),
                },
                i.field.clone(),
                value,
            ));
        }
    }
    let reused = plan.items.len() - new.len();
    let v = s.unlocked_mut()?;
    let created = v
        .transact(|t| {
            let mut out = Vec::with_capacity(new.len());
            for (item, field, value) in new {
                let slug = item.slug.clone();
                let id = t.create_item(item)?;
                t.add_field(id, field, value)?;
                out.push((id, slug));
            }
            Ok(out)
        })
        .map_err(|e| write_error(&e))?;
    s.audit(AuditEvent::Imported {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        created,
        reused,
    });
    Ok(view(&plan))
}

fn write_error(e: &VaultError) -> RpcError {
    match e.kind() {
        VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
            RpcError::new(ErrorKind::VaultTampered)
        }
        VaultErrorKind::DuplicateSlug => RpcError::new(ErrorKind::PlanChanged),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

fn manifest_error(e: &ManifestError) -> RpcError {
    RpcError::with_reason(ErrorKind::ManifestInvalid, e.kind().token())
}

/// `import.verify`. The manifest is opened here, as `run.request` opens
/// it; nothing the client sent about its contents is used.
pub fn import_verify(
    shared: &Shared,
    peer: &PeerIdentity,
    p: VerifyParams,
) -> Result<VerifyView, RpcError> {
    let path = Path::new(&p.manifest);
    if !path.is_absolute() {
        return Err(RpcError::with_reason(
            ErrorKind::ManifestInvalid,
            "invalid_path",
        ));
    }
    let project = load_project(path).map_err(|e| manifest_error(&e))?;
    let m = &project.manifest;
    refuse_if_traced()?;
    locked(&shared.state).unlocked()?;
    let asker = ask(shared, peer, &p.claims, "import.verify", |person| {
        p.files
            .iter()
            .flat_map(|f| f.entries.iter())
            .filter(|e| {
                EnvName::new(&e.name).is_ok_and(|name| {
                    compare(shared, name.as_str(), e.value.as_secret(), person).is_ok()
                })
            })
            .count()
    })?;
    let s = locked(&shared.state);
    let v = s.unlocked()?;
    let items = v.items();
    let recovery_confirmed = v
        .recovery_confirmed()
        .map_err(|_| RpcError::new(ErrorKind::VaultTampered))?;
    let mut resolves = bind_items(&m.env, items).is_ok();
    for profile in m.profiles.keys() {
        let all = resolve(m, Some(profile), &[], None).map_err(|e| manifest_error(&e))?;
        resolves &= bind_items(&all, items).is_ok();
    }
    let mut files = Vec::with_capacity(p.files.len());
    for f in p.files {
        let profile = f
            .profile
            .as_deref()
            .map(ProfileName::new)
            .transpose()
            .map_err(|_| invalid())?;
        // A profile the manifest does not name binds as `[env]` does: its
        // values were all the default profile's.
        let profile = profile.filter(|p| m.profiles.contains_key(p));
        let bindings = resolve(m, profile.as_ref(), &[], None).map_err(|e| manifest_error(&e))?;
        let mut entries = Vec::with_capacity(f.entries.len());
        for e in f.entries {
            let name = EnvName::new(&e.name).map_err(|_| invalid())?;
            let value = e.value.into_inner();
            let (status, skipped) = match compare(shared, name.as_str(), &value, asker.person) {
                Err(r) => (EntryStatus::LeftOut, Some(r)),
                Ok(()) => (stored(v, &bindings, &name, &value), None),
            };
            entries.push(VerifyEntryView {
                line: e.line,
                name: (!looks_like_value(shared, name.as_str())).then(|| name.as_str().to_owned()),
                status,
                skipped,
            });
        }
        files.push(VerifyFileView {
            file: f.file,
            covered: entries.iter().all(|e| e.status != EntryStatus::NotStored),
            entries,
        });
    }
    Ok(VerifyView {
        recovery_confirmed,
        resolves,
        files,
    })
}

/// Whether the item `bindings` binds `name` to holds `value` now.
fn stored(v: &Vault, bindings: &[Binding], name: &EnvName, value: &SecretBytes) -> EntryStatus {
    let Some(b) = bindings.iter().find(|b| b.env_name == *name) else {
        return EntryStatus::NotStored;
    };
    match bind_items(std::slice::from_ref(b), v.items()) {
        Ok(bound)
            if bound
                .iter()
                .all(|x| v.find_by_value(value).contains(&x.field)) =>
        {
            EntryStatus::Stored
        }
        _ => EntryStatus::NotStored,
    }
}

/// `files.backup`.
pub fn files_backup(
    shared: &Shared,
    peer: &PeerIdentity,
    p: FilesBackupParams,
) -> Result<FileBackupView, RpcError> {
    let mut files = Vec::with_capacity(p.files.len());
    for f in p.files {
        if !Path::new(&f.path).is_absolute() || f.path.contains('\0') {
            return Err(invalid());
        }
        files.push(BackupFile {
            path: f.path,
            mode: f.mode & 0o7777,
            content: f.content.into_inner(),
        });
    }
    refuse_if_traced()?;
    let caller = evidence(shared, peer, &p.claims)?;
    let mut s = locked(&shared.state);
    let v = s.unlocked()?;
    let info = v.backup_files(&files).map_err(|e| match e.kind() {
        VaultErrorKind::InvalidRecord => invalid(),
        VaultErrorKind::Tampered | VaultErrorKind::ReadOnly => {
            RpcError::new(ErrorKind::VaultTampered)
        }
        k => {
            log_line!(
                "envcloakd: a file backup could not be written ({}); nothing was deleted",
                vault_reason(k)
            );
            RpcError::new(ErrorKind::FilesBackupFailed)
        }
    })?;
    let now = now_of(&shared.clocks);
    let secs = now
        .wall
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Err(e) = purge_file_backups(v.paths(), secs) {
        log_line!(
            "envcloakd: old file backups could not be removed ({})",
            vault_reason(e.kind())
        );
    }
    let id = info.id.to_string();
    s.audit(AuditEvent::FilesBackedUp {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        backup: id.clone(),
        files: info.files,
    });
    Ok(FileBackupView {
        id,
        files: u32::try_from(info.files).unwrap_or(u32::MAX),
        file_name: info
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    })
}

/// A proof by `check`, run on the vault taken out of its slot (see the
/// module documentation). On success, returns the caller's evidence with
/// the state lock held and the vault back in its slot.
fn prove<'s>(
    shared: &'s Shared,
    peer: &PeerIdentity,
    method: &'static str,
    kind: AuditKind,
    claims: &[String],
    check: impl FnOnce(&Vault) -> Result<(), VaultError>,
) -> Result<(std::sync::MutexGuard<'s, State>, SubjectEvidence), RpcError> {
    refuse_if_traced()?;
    let caller = evidence(shared, peer, claims)?;
    refuse_unless_prover(shared, peer, &caller, method)?;
    let _gate = locked(&shared.proof_gate);
    let (vault, generation) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        s.begin_proof()?
    };
    let verified = check(&vault);
    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let back = s.finish_proof(generation, vault);
    match verified {
        Ok(()) => {
            s.limiter().succeeded();
            back?;
            Ok((s, caller))
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::ProofFailed {
                pid: peer.pid,
                kind,
            });
            back?;
            Err(RpcError::new(ErrorKind::WrongPassphrase))
        }
        Err(e) => {
            back?;
            Err(RpcError::with_reason(
                ErrorKind::VaultUnavailable,
                vault_reason(e.kind()),
            ))
        }
    }
}

/// `files.restore`.
pub fn files_restore(
    shared: &Shared,
    peer: &PeerIdentity,
    p: FilesRestoreParams,
) -> Result<RestoredFiles, RpcError> {
    let pass = p.passphrase.into_inner();
    let id = FileBackupId::parse(&p.backup).ok_or(RpcError::new(ErrorKind::NoSuchBackup))?;
    let (mut s, caller) = prove(
        shared,
        peer,
        "files.restore",
        AuditKind::FilesRestore,
        &p.claims,
        |v| v.verify_passphrase(&pass),
    )?;
    drop(pass);
    let files = s
        .unlocked()?
        .open_file_backup(&id)
        .map_err(|e| match e.kind() {
            VaultErrorKind::NotFound => RpcError::new(ErrorKind::NoSuchBackup),
            VaultErrorKind::Tampered | VaultErrorKind::ReadOnly => {
                RpcError::new(ErrorKind::VaultTampered)
            }
            _ => RpcError::new(ErrorKind::FilesBackupFailed),
        })?;
    // A delivery: its entry is on disk before any byte is released (SPEC
    // §3 principle 4, gate 33); when it cannot be written, the files read
    // are dropped, and wiped, and the call is refused.
    let entry = AuditEvent::FilesRestored {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        backup: id.to_string(),
        files: files.len(),
    };
    if !s.audit_delivery(entry) {
        drop(files);
        return Err(RpcError::new(ErrorKind::AuditFailed));
    }
    Ok(RestoredFiles {
        files: files
            .into_iter()
            .map(|f| RestoredFile {
                path: f.path,
                mode: f.mode,
                content: WireSecret::new(f.content),
            })
            .collect(),
    })
}

/// `recovery.confirm`.
pub fn recovery_confirm(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RecoveryConfirmParams,
) -> Result<RecoveryConfirmedView, RpcError> {
    let text = p.recovery_kit.into_inner();
    let kit = RecoveryKit::parse(&text).map_err(|_| RpcError::new(ErrorKind::WrongPassphrase))?;
    drop(text);
    let (mut s, caller) = prove(
        shared,
        peer,
        "recovery.confirm",
        AuditKind::RecoveryConfirm,
        &p.claims,
        |v| v.verify_recovery_kit(&kit),
    )?;
    drop(kit);
    let v = s.unlocked_mut()?;
    let already = v
        .recovery_confirmed()
        .map_err(|_| RpcError::new(ErrorKind::VaultTampered))?;
    if !already {
        v.transact(|t| {
            t.set_recovery_confirmed(true);
            Ok(())
        })
        .map_err(|e| write_error(&e))?;
    }
    s.audit(AuditEvent::RecoveryConfirmed {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        already,
    });
    Ok(RecoveryConfirmedView { already })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_words_are_whole_words_of_the_name() {
        for yes in [
            "OPENAI_API_KEY",
            "SHORT_TOKEN",
            "JWT_SECRET",
            "DB_PASSWORD",
            "db_pass",
            "SENTRY_DSN",
            "APIKEY",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(secret_name(yes), "{yes}");
        }
        for no in [
            "PORT",
            "NODE_ENV",
            "DATABASE_URL",
            "MONKEYS",
            "PASSPORT_ID",
            "KEYBOARD_LAYOUT",
            "TOKENIZER",
        ] {
            assert!(!secret_name(no), "{no}");
        }
    }

    fn inst(pid: i32) -> ProcessInstance {
        ProcessInstance {
            pid,
            start_time: envcloak_sys::StartTime::from_raw(7),
            pidversion: None,
            exe: None,
        }
    }

    #[test]
    fn value_checks_are_counted_per_root_in_a_window() {
        let mut b = ValueChecks::default();
        let (one, two) = (inst(10), inst(20));
        let t0 = Duration::from_secs(1000);
        assert!(b.admit(&one, MAX_VALUE_CHECKS - 1, t0));
        assert!(b.admit(&one, 1, t0));
        // Full: refused, and nothing counted.
        assert!(!b.admit(&one, 1, t0));
        assert!(!b.admit(&one, usize::MAX, t0));
        assert!(b.admit(&one, 0, t0));
        // Another root has its own count.
        assert!(b.admit(&two, MAX_VALUE_CHECKS, t0));
        // The window ends an hour of awake time after its first count.
        assert!(!b.admit(&one, 1, t0 + CHECK_WINDOW - Duration::from_secs(1)));
        assert!(b.admit(&one, 1, t0 + CHECK_WINDOW));
        // At most MAX_CHECKING_ROOTS roots at once: a full table refuses
        // no one, and forgets the root whose window started first.
        let mut b = ValueChecks::default();
        let roots = i32::try_from(MAX_CHECKING_ROOTS).unwrap();
        assert!(b.admit(&inst(100), MAX_VALUE_CHECKS, t0));
        for pid in 1..roots {
            assert!(b.admit(&inst(pid + 100), 1, t0 + Duration::from_secs(1)));
        }
        assert_eq!(b.by_root.len(), MAX_CHECKING_ROOTS);
        assert!(!b.admit(&inst(100), 1, t0 + Duration::from_secs(1)));
        assert!(b.admit(&inst(1), 1, t0 + Duration::from_secs(2)));
        assert_eq!(b.by_root.len(), MAX_CHECKING_ROOTS);
        assert!(!b.by_root.contains_key(&inst(100)));
        assert!(b.by_root.contains_key(&inst(101)));
        // A root still counted keeps its count.
        assert!(b.admit(
            &inst(101),
            MAX_VALUE_CHECKS - 1,
            t0 + Duration::from_secs(2)
        ));
        assert!(!b.admit(&inst(101), 1, t0 + Duration::from_secs(2)));
    }

    /// Calls that compare nothing take no place: any number of roots
    /// making them leaves every other root's calls admitted.
    #[test]
    fn calls_that_compare_nothing_take_no_place() {
        let mut b = ValueChecks::default();
        let t0 = Duration::from_secs(1000);
        for pid in 0..i32::try_from(MAX_CHECKING_ROOTS * 2).unwrap() {
            assert!(b.admit(&inst(pid + 100), 0, t0));
        }
        assert!(b.by_root.is_empty());
        assert!(b.admit(&inst(1), 1, t0));
        assert_eq!(b.by_root.len(), 1);
    }

    #[test]
    fn slug_bases_come_from_variable_names() {
        let base = |s: &str| name_base(&EnvName::new(s).unwrap());
        assert_eq!(base("DATABASE_URL"), "database-url");
        assert_eq!(base("_LEADING"), "leading");
        assert_eq!(base("TRAILING_"), "trailing");
        assert_eq!(base("___"), DEFAULT_SLUG);
    }
}
