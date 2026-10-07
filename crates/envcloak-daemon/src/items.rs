//! The item methods (SPEC §5 "Items", §6.3, §10b "Writes that need a
//! proof"): `items.list`, `items.show`, `items.check`, `items.add`,
//! `items.target`, `items.rotate`, `items.remove`, `items.reclassify` and
//! `items.mark_exposed`.
//!
//! What they send back is metadata only (`envcloak_ipc::view`): no method
//! here answers with a value, and none records one. Names a client sent
//! (a slug, a provider, an account, a variable) are checked before they
//! are used and never repeated in an error; an audit entry names the item
//! the vault resolved, by id and slug, never the text a client sent.
//!
//! - `items.add` needs no proof: nothing is bound to a new item yet. It
//!   refuses names shaped like a value ([`envcloak_policy::value_shaped`]
//!   or a provider's key pattern), since values are never taken on the
//!   command line (gate 13) and a pasted key would otherwise be kept, and
//!   shown, as a name. The provider and classification are detected from
//!   the value (SPEC §6.3) and pre-fill the item's links and hosts.
//! - `items.rotate` and `items.remove` are proofs, as `approve` is: the
//!   caller must be a terminal subject with no agent by any evidence, the
//!   attempt limiter must admit the attempt, and the passphrase must open
//!   the vault's passphrase envelope, checked with the vault taken out of
//!   the slot while Argon2id runs. A rotation keeps the old value as the
//!   newest of three prior values, and grants that bind the item stay
//!   (SPEC §10b), unless the new value changes the item's classification:
//!   it is detected as `items.add` detects it, stored in the same
//!   transaction as the value, and a change (test to live, say) ends the
//!   grants and pending requests that bind the item. A rotation also
//!   clears the item's "exposed: rotate" mark when it leaves the item
//!   holding no value the mark covers (the values the item held at each
//!   mark, by keyed hash, `Exposure::covered`): a rotation to the same
//!   value, to a value another field holds or held at a mark, or of one
//!   field of several while another still holds a covered value, leaves
//!   the mark. A removal writes an encrypted backup of the vault first,
//!   which keeps the item's values (`envcloak recover` restores it), then
//!   deletes the item and ends the grants and pending requests that bind
//!   it. When the backup cannot be written, nothing is removed. A write
//!   that passed its proof and then changed nothing (the vault locked
//!   while Argon2id ran, the backup or the write failed) is audited as
//!   failed, with that reason, as a wrong passphrase is.
//! - `items.target` shows what a rotation or removal would change, and is
//!   served only to a caller that may give a proof, like `pending.get`.
//! - `items.reclassify` sets a secret item's classification by hand (SPEC
//!   §10b "Live-key guard"). Towards `live` tightens (an agent then needs
//!   a tick for it), so any caller may, with no proof. Towards `test` or
//!   `unknown` loosens, so it is a proof as a rotation is, with the item's
//!   id from `items.target`. Either change is written with the time it
//!   happened (`classification_changed_at`) and ends the grants and
//!   pending requests that bind the item, as a rotation that reclassifies
//!   does; pending requests whose statements proposed the item read
//!   differently from then on, so a statement read before is
//!   `statement_mismatch`. A classification the item has already changes
//!   nothing. Every call that reaches the vault is audited (kind
//!   `reclassify`), with the change and the grants it ended.
//! - `items.mark_exposed` marks items "exposed: rotate" (SPEC §6.4, §6.5):
//!   their values were found outside the vault, in the kinds of place it
//!   names. Marking only tightens, so any caller may, with no proof; each
//!   call is audited. A mark that names only kinds an item is marked for
//!   already, on an item whose every value its mark covers, writes nothing,
//!   so a doctor run repeated changes nothing it marked; one on an item
//!   holding a value set since is written, and its mark covers that value
//!   too. Only `secret` items are marked: an id that names no
//!   secret item (one removed meanwhile, a card's, a login's) is counted
//!   as missing, never an error for the rest.
//!
//! Every write is refused on a vault that failed its integrity check.

use std::path::Path;

use envcloak_core::SecretBytes;
use envcloak_core::audit::{AuditKind, SubjectSummary};
use envcloak_core::crypto::{CryptoErrorKind, ItemClass};
use envcloak_core::vault::{
    Account, Classification, ExposureSource, FieldId, FieldName, ItemDetails, ItemId, ItemMeta,
    MAX_FIELD, NewItem, Slug, Vault, VaultError, VaultErrorKind,
};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{
    AddParams, CheckParams, ErrorKind, ListParams, MAX_MARKED, MarkExposedParams, ReclassifyParams,
    RemoveParams, RotateParams, SlugParams, TargetParams,
};
use envcloak_ipc::view::{
    AddedView, CheckBindingView, CheckView, ClassificationView, ItemDetail, ItemView, ItemsView,
    LengthClass, MarkedView, ReclassifiedView, RefStatus, RemovedView, RotatedView, TargetView,
};
use envcloak_policy::{
    BindErrorKind, Binding, Claims, EnvName, ManifestError, SubjectEvidence, bind_items,
    load_project, value_shaped,
};
use envcloak_sys::PeerIdentity;

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::requests::{evidence, refuse_unless_prover, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{backup_reason, vault_reason};

/// The field a new item's value goes in when none is named.
pub const DEFAULT_FIELD: &str = "value";
/// The slug a new item gets when neither it nor a provider is known.
pub const DEFAULT_SLUG: &str = "secret";
/// How many numbered slugs (`openai-2`, `openai-3`, ...) are tried.
const SLUG_TRIES: usize = 99;
/// The longest account an item keeps, in bytes.
pub const MAX_ACCOUNT: usize = 254;

fn no_such(reason: &str) -> RpcError {
    RpcError::with_reason(ErrorKind::NoSuchItem, reason)
}

fn invalid(reason: &str) -> RpcError {
    RpcError::with_reason(ErrorKind::InvalidItem, reason)
}

/// Whether a name a client sent looks like a value: shaped like a
/// generated key, or matched whole by a provider's key pattern.
pub(crate) fn looks_like_value(shared: &Shared, s: &str) -> bool {
    value_shaped(s)
        || shared
            .registry
            .as_ref()
            .is_some_and(|r| r.mask_keys(s) != s)
}

/// A vault error from a write, as the protocol reports it.
fn write_error(e: &VaultError) -> RpcError {
    match e.kind() {
        VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
            RpcError::new(ErrorKind::VaultTampered)
        }
        VaultErrorKind::DuplicateSlug => RpcError::new(ErrorKind::ItemExists),
        VaultErrorKind::UnknownItem => no_such("unknown_item"),
        VaultErrorKind::UnknownField => no_such("unknown_field"),
        VaultErrorKind::TooLarge => invalid("value_too_large"),
        VaultErrorKind::InvalidValue => invalid("empty_value"),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

/// Checks a new value: not empty, no NUL byte (no environment can carry
/// one), and within the vault's 64 KiB field cap.
fn check_value(v: &SecretBytes) -> Result<(), RpcError> {
    if v.is_empty() {
        return Err(invalid("empty_value"));
    }
    if v.len() > MAX_FIELD {
        return Err(invalid("value_too_large"));
    }
    if v.contains_byte(0) {
        return Err(invalid("nul_byte"));
    }
    Ok(())
}

/// `items.list`.
pub fn list(shared: &Shared, p: ListParams) -> Result<ItemsView, RpcError> {
    let s = locked(&shared.state);
    let detail = if p.long {
        ItemDetail::Long
    } else {
        ItemDetail::Summary
    };
    Ok(ItemsView {
        items: s
            .unlocked()?
            .items()
            .iter()
            .map(|m| ItemView::from_meta(m, detail))
            .collect(),
    })
}

/// The item a client named by slug. A malformed slug names nothing.
fn find<'v>(v: &'v Vault, slug: &str) -> Result<&'v ItemMeta, RpcError> {
    let slug = Slug::new(slug).map_err(|_| no_such("unknown_item"))?;
    v.find(&slug).ok_or_else(|| no_such("unknown_item"))
}

/// `items.show`.
pub fn show(shared: &Shared, p: SlugParams) -> Result<ItemView, RpcError> {
    let s = locked(&shared.state);
    let m = find(s.unlocked()?, &p.slug)?;
    Ok(ItemView::from_meta(m, ItemDetail::Full))
}

fn status_of(k: BindErrorKind) -> RefStatus {
    match k {
        BindErrorKind::UnknownItem => RefStatus::UnknownItem,
        BindErrorKind::UnknownField => RefStatus::UnknownField,
        BindErrorKind::AmbiguousField => RefStatus::AmbiguousField,
        BindErrorKind::NoField => RefStatus::NoField,
        BindErrorKind::CardReference => RefStatus::CardReference,
        BindErrorKind::IssuerCredentialReference => RefStatus::IssuerCredentialReference,
        BindErrorKind::LoginReference => RefStatus::LoginReference,
        _ => RefStatus::UnknownItemClass,
    }
}

/// Whether `b` resolves to a field of a secret item in `items`.
fn resolves(b: &Binding, items: &[ItemMeta]) -> RefStatus {
    match bind_items(std::slice::from_ref(b), items) {
        Ok(_) => RefStatus::Ok,
        Err(e) => status_of(e.kind()),
    }
}

/// `items.check`. The manifest is opened here, as `run.request` opens it;
/// nothing the client sent about its contents is used.
pub fn check(shared: &Shared, p: CheckParams) -> Result<CheckView, RpcError> {
    let project = match &p.manifest {
        Some(m) => {
            let path = Path::new(m);
            if !path.is_absolute() {
                return Err(RpcError::with_reason(
                    ErrorKind::ManifestInvalid,
                    "invalid_path",
                ));
            }
            Some(load_project(path).map_err(|e: ManifestError| {
                RpcError::with_reason(ErrorKind::ManifestInvalid, e.kind().token())
            })?)
        }
        None => None,
    };
    let s = locked(&shared.state);
    let items = s.unlocked()?.items();
    let view = |profile: Option<&str>, b: &Binding| {
        let name = b.env_name.as_str();
        let reference = b.reference.to_string();
        let hidden = looks_like_value(shared, name) || looks_like_value(shared, &reference);
        CheckBindingView {
            profile: profile.map(str::to_owned),
            env_name: (!hidden).then(|| name.to_owned()),
            reference: (!hidden).then_some(reference),
            status: if hidden {
                RefStatus::LooksLikeValue
            } else {
                resolves(b, items)
            },
        }
    };
    let mut bindings = Vec::new();
    let (mut project_dir, mut project_name) = (None, None);
    if let Some(project) = &project {
        let m = &project.manifest;
        bindings.extend(m.env.iter().map(|b| view(None, b)));
        for (profile, list) in &m.profiles {
            bindings.extend(list.iter().map(|b| view(Some(profile.as_str()), b)));
        }
        project_dir = Some(
            project
                .identity
                .canonical_dir
                .to_string_lossy()
                .into_owned(),
        );
        project_name.clone_from(&m.project_name);
    }
    let refs = p
        .refs
        .iter()
        .map(|r| {
            if looks_like_value(shared, r) {
                return RefStatus::LooksLikeValue;
            }
            match Binding::parse_arg(r) {
                Ok(b) => resolves(&b, items),
                Err(_) => RefStatus::InvalidReference,
            }
        })
        .collect();
    Ok(CheckView {
        project_dir,
        project_name,
        bindings,
        refs,
    })
}

/// Text a person gave as an account: 1 to [`MAX_ACCOUNT`] bytes, with no
/// blanks, control characters, or invisible characters that could spoof
/// what a terminal shows.
fn valid_account(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ACCOUNT
        && !s.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
        })
}

/// A checked [`AddParams`], without the value.
struct NewNames {
    slug: Option<Slug>,
    provider: Option<String>,
    field: FieldName,
    account: Option<String>,
    env_hint: Option<EnvName>,
}

fn check_names(shared: &Shared, p: &AddParams) -> Result<NewNames, RpcError> {
    let named = [
        p.slug.as_deref(),
        p.provider.as_deref(),
        p.field.as_deref(),
        p.account.as_deref(),
        p.env_hint.as_deref(),
    ];
    if named
        .into_iter()
        .flatten()
        .any(|s| looks_like_value(shared, s))
    {
        return Err(invalid("looks_like_value"));
    }
    let slug = p
        .slug
        .as_deref()
        .map(Slug::new)
        .transpose()
        .map_err(|_| invalid("invalid_slug"))?;
    let provider = match p.provider.as_deref() {
        None => None,
        Some(id) => {
            let known = shared.registry.as_ref().and_then(|r| r.get(id));
            Some(
                known
                    .ok_or_else(|| invalid("unknown_provider"))?
                    .id
                    .to_string(),
            )
        }
    };
    let field = FieldName::new(p.field.as_deref().unwrap_or(DEFAULT_FIELD))
        .map_err(|_| invalid("invalid_field"))?;
    let account = match p.account.as_deref() {
        Some(a) if !valid_account(a) => return Err(invalid("invalid_account")),
        a => a.map(str::to_owned),
    };
    let env_hint = p
        .env_hint
        .as_deref()
        .map(EnvName::new)
        .transpose()
        .map_err(|_| invalid("invalid_env_name"))?;
    Ok(NewNames {
        slug,
        provider,
        field,
        account,
        env_hint,
    })
}

/// The first of `base`, `base-2`, ... `base-99` that no item has.
fn free_slug(v: &Vault, base: &str) -> Result<Slug, RpcError> {
    (1..=SLUG_TRIES)
        .map(|n| {
            if n == 1 {
                base.to_owned()
            } else {
                format!("{base}-{n}")
            }
        })
        .filter_map(|s| Slug::new(&s).ok())
        .find(|s| v.find(s).is_none())
        .ok_or_else(|| invalid("no_free_slug"))
}

/// `items.add`. See the module documentation.
pub fn add(shared: &Shared, peer: &PeerIdentity, p: AddParams) -> Result<AddedView, RpcError> {
    let names = check_names(shared, &p)?;
    let value = p.value.into_inner();
    refuse_if_traced()?;
    check_value(&value)?;
    let caller = evidence(shared, peer, &p.claims)?;

    let mut details = ItemDetails {
        provider: names.provider.clone(),
        account: Account {
            email: names.account,
            ..Account::default()
        },
        env_hint: names.env_hint.as_ref().map(|e| e.as_str().to_owned()),
        allow_short: p.allow_short,
        ..ItemDetails::default()
    };
    let hint = names.env_hint.as_ref().map(EnvName::as_str);
    let (detected, ambiguous) = match shared.registry.as_ref() {
        Some(r) => {
            let d = r.detect(&value, hint);
            r.prefill(&d, &mut details);
            let found = d.provider.as_ref().map(|id| id.as_str().to_owned());
            // Worth saying only when the item does not carry it.
            let differs = found.is_some() && found != details.provider;
            (
                found.filter(|_| differs),
                d.ambiguous && details.provider.is_none(),
            )
        }
        None => (None, false),
    };
    let length = LengthClass::of(value.len());

    let mut s = locked(&shared.state);
    let v = s.unlocked_mut()?;
    let slug = match names.slug {
        Some(slug) => {
            if v.find(&slug).is_some() {
                return Err(RpcError::new(ErrorKind::ItemExists));
            }
            slug
        }
        None => free_slug(v, details.provider.as_deref().unwrap_or(DEFAULT_SLUG))?,
    };
    if details.title.is_empty() {
        details.title = slug.as_str().to_owned();
    }
    let field = names.field;
    let new = NewItem {
        class: ItemClass::Secret,
        slug: slug.clone(),
        details,
    };
    let id = v
        .transact(|t| {
            let id = t.create_item(new)?;
            t.add_field(id, field.clone(), value)?;
            Ok(id)
        })
        .map_err(|e| write_error(&e))?;
    let item = v
        .item(id)
        .map(|m| ItemView::from_meta(m, ItemDetail::Long))
        .ok_or(RpcError::new(ErrorKind::Internal))?;
    s.audit(AuditEvent::Added {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        item: id,
        slug,
    });
    Ok(AddedView {
        item,
        field: field.as_str().to_owned(),
        detected,
        ambiguous,
        length,
    })
}

/// What a rotation or removal changes: the item, and the field a rotation
/// replaces when one is named or the item has only one.
pub(crate) struct Target {
    pub(crate) item: ItemId,
    pub(crate) slug: Slug,
    pub(crate) field: Option<(FieldId, FieldName)>,
}

/// Resolves `slug` (and `field`) to a secret item of `v`. With `expect`,
/// the item's id must be that one: the slug may name another item by now.
pub(crate) fn target(
    v: &Vault,
    slug: &str,
    field: Option<&str>,
    expect: Option<&str>,
) -> Result<Target, RpcError> {
    let m = find(v, slug)?;
    if m.class != ItemClass::Secret {
        return Err(no_such("unknown_item_class"));
    }
    if expect.is_some_and(|id| id != m.id.to_string()) {
        return Err(no_such("item_changed"));
    }
    let field = match field {
        Some(name) => {
            let name = FieldName::new(name).map_err(|_| no_such("unknown_field"))?;
            let f = m
                .fields
                .iter()
                .find(|f| f.name == name)
                .ok_or_else(|| no_such("unknown_field"))?;
            Some((f.id, f.name.clone()))
        }
        None => match m.fields.as_slice() {
            [only] => Some((only.id, only.name.clone())),
            _ => None,
        },
    };
    Ok(Target {
        item: m.id,
        slug: m.slug.clone(),
        field,
    })
}

/// `items.target`: for a caller that may give a proof only.
/// This preflight also refuses a live agent request's terminal, so a
/// reveal never asks for its passphrase on that requester's surface.
pub fn target_view(
    shared: &Shared,
    peer: &PeerIdentity,
    p: TargetParams,
) -> Result<TargetView, RpcError> {
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover(shared, peer, &caller, "items.target")?;
    let mut s = locked(&shared.state);
    refuse_item_prover(
        &mut s,
        peer,
        &caller,
        &now_of(&shared.clocks),
        "items.target",
    )?;
    let v = s.unlocked()?;
    let t = target(v, &p.slug, p.field.as_deref(), None)?;
    let item = v
        .item(t.item)
        .map(|m| ItemView::from_meta(m, ItemDetail::Long))
        .ok_or(RpcError::new(ErrorKind::Internal))?;
    let grants = s.grants().binding_item(t.item);
    Ok(TargetView {
        item,
        field: t.field.map(|(_, name)| name.as_str().to_owned()),
        grants: u64::try_from(grants).unwrap_or(u64::MAX),
    })
}

/// Proof surfaces for an item have no request id. Refuse an overlap with
/// any live pending nonterminal requester, using the same independently
/// computed origin boundary as `approve` (T9-3, F-70).
pub(crate) fn refuse_item_prover(
    s: &mut crate::state::State,
    peer: &PeerIdentity,
    caller: &SubjectEvidence,
    now: &envcloak_policy::Now,
    method: &'static str,
) -> Result<(), RpcError> {
    let refusal = caller.proof_refusal().or_else(|| {
        s.grants()
            .pending_all(now)
            .find_map(|p| caller.approval_refusal(&p.request.subject, &crate::requests::alive))
    });
    if let Some(r) = refusal {
        s.audit(AuditEvent::ProofRefused {
            pid: peer.pid,
            method,
            reason: r.token(),
        });
        return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
    }
    Ok(())
}

/// Which proof-gated write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Write {
    Rotate,
    Remove,
    /// Towards `test` or `unknown` only: towards `live` takes no proof.
    Reclassify,
    #[cfg(target_os = "linux")]
    Reveal,
}

impl Write {
    fn method(self) -> &'static str {
        match self {
            Write::Rotate => "items.rotate",
            Write::Remove => "items.remove",
            Write::Reclassify => "items.reclassify",
            #[cfg(target_os = "linux")]
            Write::Reveal => "items.reveal",
        }
    }

    fn kind(self) -> AuditKind {
        match self {
            Write::Rotate => AuditKind::Rotate,
            Write::Remove => AuditKind::Remove,
            Write::Reclassify => AuditKind::Reclassify,
            #[cfg(target_os = "linux")]
            Write::Reveal => AuditKind::Reveal,
        }
    }
}

/// A proof that passed, for the write it allows: the state lock, held
/// since the vault came back to its slot, the caller's evidence, and the
/// target as it was resolved before Argon2id ran (the write resolves it
/// again under this lock).
pub(crate) struct Proven<'s> {
    pub(crate) s: std::sync::MutexGuard<'s, crate::state::State>,
    pub(crate) caller: SubjectEvidence,
    pub(crate) target: Target,
}

impl Proven<'_> {
    /// Records that the write this proof allowed changed nothing, for
    /// `e`'s reason (SPEC §3 principle 4: a proof that passed is audited
    /// whatever follows), and returns `e`.
    pub(crate) fn aborted(&mut self, peer: &PeerIdentity, write: Write, e: RpcError) -> RpcError {
        self.s.audit(AuditEvent::ItemWriteFailed {
            pid: peer.pid,
            subject: subject_summary(peer, &self.caller),
            write: write.kind(),
            item: self.target.item,
            slug: self.target.slug.clone(),
            reason: e.reason.unwrap_or_else(|| e.kind.token()),
        });
        e
    }
}

/// The proof for a rotation or removal (see the module documentation).
/// On success, returns the [`Proven`] write with the state lock held and
/// the vault back in its slot. A proof that passes when the vault cannot
/// come back (a lock arrived while Argon2id ran) is audited as an aborted
/// write.
pub(crate) fn prove<'s>(
    shared: &'s Shared,
    peer: &PeerIdentity,
    write: Write,
    claims: &[String],
    pass: SecretBytes,
    resolve: &dyn Fn(&Vault) -> Result<Target, RpcError>,
) -> Result<Proven<'s>, RpcError> {
    refuse_if_traced()?;
    let caller = evidence(shared, peer, claims)?;
    refuse_unless_prover(shared, peer, &caller, write.method())?;
    let _gate = locked(&shared.proof_gate);
    let (vault, generation, t) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        #[cfg(target_os = "linux")]
        if write == Write::Reveal {
            refuse_item_prover(&mut s, peer, &caller, &now, write.method())?;
        }
        // Everything but the passphrase is checked before Argon2id runs.
        let t = resolve(s.unlocked()?)?;
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        let (v, g) = s.begin_proof()?;
        (v, g, t)
    };
    #[cfg(target_os = "linux")]
    if write == Write::Reveal {
        // A test-only barrier after admission, while the state lock is free.
        envcloak_sys::pause_point("reveal.proof.verifying");
    }
    let verified = vault.verify_passphrase(&pass);
    drop(pass);
    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let back = s.finish_proof(generation, vault);
    match verified {
        Ok(()) => {
            s.limiter().succeeded();
            let mut proven = Proven {
                s,
                caller,
                target: t,
            };
            match back {
                Ok(()) => Ok(proven),
                Err(e) => Err(proven.aborted(peer, write, e)),
            }
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::ItemProofFailed {
                pid: peer.pid,
                write: write.kind(),
                item: t.item,
                slug: t.slug,
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

/// `items.rotate`. See the module documentation.
pub fn rotate(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RotateParams,
) -> Result<RotatedView, RpcError> {
    let value = p.value.into_inner();
    let pass = p.passphrase.into_inner();
    check_value(&value)?;
    let resolve = |v: &Vault| {
        let t = target(v, &p.slug, p.field.as_deref(), Some(&p.item))?;
        if t.field.is_none() {
            return Err(no_such("ambiguous_field"));
        }
        Ok(t)
    };
    let mut proven = prove(shared, peer, Write::Rotate, &p.claims, pass, &resolve)?;
    let length = LengthClass::of(value.len());
    let written = (|| {
        let v = proven.s.unlocked_mut()?;
        let t = resolve(v)?;
        let (field, name) = t.field.clone().ok_or(RpcError::new(ErrorKind::Internal))?;
        let meta = v.item(t.item).ok_or(RpcError::new(ErrorKind::Internal))?;
        let before = meta.details.classification;
        // The item's only value decides its classification, as it did at
        // `items.add`; an item of several fields keeps its own.
        let after = match meta.fields.as_slice() {
            [_] => detected_class(shared, &meta.details, &value).unwrap_or(before),
            _ => before,
        };
        let details = (after != before).then(|| ItemDetails {
            classification: after,
            ..meta.details.clone()
        });
        // The value, the classification and the mark change together, or
        // none of them. The mark is cleared only when the item, with its
        // new value, holds no value the mark covers, read by the vault
        // from the values the transaction leaves (`Exposure::covered`):
        // the same value written again, a covered value moved to another
        // field or set back keeps it.
        v.transact(|txn| {
            txn.set_value(field, value)?;
            if let Some(details) = details {
                txn.update_item(t.item, details)?;
            }
            txn.clear_exposure_if_replaced(t.item)?;
            Ok(())
        })
        .map_err(|e| write_error(&e))?;
        let prior_count = v
            .item(t.item)
            .and_then(|m| m.fields.iter().find(|f| f.id == field))
            .map(|f| f.prior_count)
            .ok_or(RpcError::new(ErrorKind::Internal))?;
        Ok((t, name, prior_count, before, after))
    })();
    let (t, name, prior_count, before, after) = match written {
        Ok(w) => w,
        Err(e) => return Err(proven.aborted(peer, Write::Rotate, e)),
    };
    // A reclassification ends the grants and pending requests that bind
    // the item (SPEC §10b); an ordinary rotation keeps them.
    let reclassified = after != before;
    let grants = if reclassified {
        proven.s.grants().on_item_reclassified(t.item)
    } else {
        0
    };
    let token = |c| ClassificationView::from(c).as_str();
    let subject = subject_summary(peer, &proven.caller);
    proven.s.audit(AuditEvent::Rotated {
        pid: peer.pid,
        subject,
        item: t.item,
        slug: t.slug.clone(),
        prior_count,
        reclassified: reclassified.then(|| (token(before), token(after))),
        grants,
    });
    Ok(RotatedView {
        slug: t.slug.as_str().to_owned(),
        field: name.as_str().to_owned(),
        prior_count,
        length,
        classification: ClassificationView::from(after),
        reclassified_from: reclassified.then(|| ClassificationView::from(before)),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
    })
}

/// `items.reclassify`. See the module documentation. The request is
/// checked whole before anything is read: towards `live` with neither a
/// passphrase nor an item id, towards `test` or `unknown` with both
/// (`invalid_params` otherwise, nothing audited).
pub fn reclassify(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ReclassifyParams,
) -> Result<ReclassifiedView, RpcError> {
    let to = match p.to {
        ClassificationView::Live => Classification::Live,
        ClassificationView::Test => Classification::Test,
        ClassificationView::Unknown => Classification::Unknown,
    };
    match (to, p.passphrase, p.item) {
        (Classification::Live, None, None) => without_proof(shared, peer, &p.slug, &p.claims, to),
        (Classification::Test | Classification::Unknown, Some(pass), Some(item)) => loosen(
            shared,
            peer,
            &p.slug,
            &item,
            to,
            &p.claims,
            pass.into_inner(),
        ),
        // A passphrase sent where none is taken is dropped, and wiped,
        // unread.
        _ => Err(RpcError::new(ErrorKind::InvalidParams)),
    }
}

/// Sets `slug`'s item to `to` with no proof: only ever to live, which
/// tightens, for any caller (SPEC §10b). A change ends the grants and
/// pending requests that bind the item. Audited, a classification the item
/// had already too.
fn without_proof(
    shared: &Shared,
    peer: &PeerIdentity,
    slug: &str,
    claims: &[String],
    to: Classification,
) -> Result<ReclassifiedView, RpcError> {
    let caller = evidence(shared, peer, claims)?;
    let mut s = locked(&shared.state);
    let v = s.unlocked_mut()?;
    let t = target(v, slug, None, None)?;
    let before = set_classification(v, t.item, to)?;
    Ok(reclassified(
        &mut s,
        peer,
        subject_summary(peer, &caller),
        &t,
        before,
        to,
    ))
}

/// Sets the item `slug` names, which must still be `item`, to `to`
/// (`test` or `unknown`): a loosening, so a proof, as a rotation is (see
/// [`prove`]).
fn loosen(
    shared: &Shared,
    peer: &PeerIdentity,
    slug: &str,
    item: &str,
    to: Classification,
    claims: &[String],
    pass: SecretBytes,
) -> Result<ReclassifiedView, RpcError> {
    let resolve = |v: &Vault| target(v, slug, None, Some(item));
    let mut proven = prove(shared, peer, Write::Reclassify, claims, pass, &resolve)?;
    let written = (|| {
        let v = proven.s.unlocked_mut()?;
        let t = resolve(v)?;
        let before = set_classification(v, t.item, to)?;
        Ok((t, before))
    })();
    let (t, before) = match written {
        Ok(w) => w,
        Err(e) => return Err(proven.aborted(peer, Write::Reclassify, e)),
    };
    let subject = subject_summary(peer, &proven.caller);
    Ok(reclassified(&mut proven.s, peer, subject, &t, before, to))
}

/// Writes `to` as `item`'s classification, unless it has it already (the
/// vault records when it changed); returns the classification before.
fn set_classification(
    v: &mut Vault,
    item: ItemId,
    to: Classification,
) -> Result<Classification, RpcError> {
    let meta = v.item(item).ok_or(RpcError::new(ErrorKind::Internal))?;
    let before = meta.details.classification;
    if before != to {
        let details = ItemDetails {
            classification: to,
            ..meta.details.clone()
        };
        v.transact(|txn| txn.update_item(item, details))
            .map_err(|e| write_error(&e))?;
    }
    Ok(before)
}

/// After a reclassification of `t`'s item from `before` to `to`: a change
/// ends the grants and pending requests that bind the item (SPEC §10b "A
/// grant ends on"), as a rotation that reclassifies does; the call is
/// audited; the answer says what changed.
fn reclassified(
    s: &mut crate::state::State,
    peer: &PeerIdentity,
    subject: SubjectSummary,
    t: &Target,
    before: Classification,
    to: Classification,
) -> ReclassifiedView {
    let changed = before != to;
    let grants = if changed {
        s.grants().on_item_reclassified(t.item)
    } else {
        0
    };
    let token = |c| ClassificationView::from(c).as_str();
    s.audit(AuditEvent::Reclassified {
        pid: peer.pid,
        subject,
        item: t.item,
        slug: t.slug.clone(),
        from: token(before),
        to: token(to),
        grants,
    });
    ReclassifiedView {
        slug: t.slug.as_str().to_owned(),
        classification: ClassificationView::from(to),
        reclassified_from: changed.then(|| ClassificationView::from(before)),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
    }
}

/// Whether `s` is shaped like an item's id: 26 Crockford base32
/// characters, as `ItemId`'s `Display` writes it.
fn id_shaped(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

/// `items.mark_exposed`. See the module documentation. The request is
/// checked whole before anything is read or written: 1 to [`MAX_MARKED`]
/// items, each named once by an id of the right shape, with at least one
/// kind of place and a count of at least 1, and claims that are markers
/// (`invalid_params` otherwise, nothing audited). Every call past those
/// checks writes one audit entry: outcome `marked`, with the items marked,
/// or the token of the error it was refused with (`evidence`,
/// `vault_locked`, a write's), with none marked.
pub fn mark_exposed(
    shared: &Shared,
    peer: &PeerIdentity,
    p: MarkExposedParams,
) -> Result<MarkedView, RpcError> {
    if p.items.is_empty() || p.items.len() > MAX_MARKED {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    let mut named = std::collections::HashSet::with_capacity(p.items.len());
    for e in &p.items {
        if !id_shaped(&e.item)
            || !named.insert(e.item.as_str())
            || e.sources.is_empty()
            || e.count == 0
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
    }
    Claims::from_markers(&p.claims).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    let mut subject = None;
    let done = mark(shared, peer, &p, &mut subject);
    let (outcome, marked, already, missing) = match &done {
        Ok(m) => ("marked", m.marked.clone(), m.already, m.missing),
        Err(e) => (e.kind.token(), Vec::new(), 0, 0),
    };
    shared.audit(AuditEvent::MarkedExposed {
        pid: peer.pid,
        subject: subject.unwrap_or_else(|| SubjectSummary {
            pid: peer.pid,
            ..SubjectSummary::default()
        }),
        marked,
        already,
        missing,
        outcome,
    });
    let m = done?;
    Ok(MarkedView {
        marked: u32::try_from(m.marked.len()).unwrap_or(u32::MAX),
        already: u32::try_from(m.already).unwrap_or(u32::MAX),
        missing: u32::try_from(m.missing).unwrap_or(u32::MAX),
    })
}

/// What one `items.mark_exposed` did.
struct Marked {
    marked: Vec<(ItemId, Slug)>,
    already: usize,
    missing: usize,
}

/// The marks of a checked `items.mark_exposed` request, written; the
/// caller's subject in `subject` once its evidence was read.
fn mark(
    shared: &Shared,
    peer: &PeerIdentity,
    p: &MarkExposedParams,
    subject: &mut Option<SubjectSummary>,
) -> Result<Marked, RpcError> {
    let caller = evidence(shared, peer, &p.claims)?;
    *subject = Some(subject_summary(peer, &caller));
    let mut s = locked(&shared.state);
    let v = s.unlocked_mut()?;
    // Only a `secret` item is marked (R-M2-34): a card's or a login's id
    // is counted as naming no item, as `scan.match` never answers one, and
    // a rotation, which alone clears a mark, takes secrets only.
    let by_id: std::collections::HashMap<String, &ItemMeta> = v
        .items()
        .iter()
        .filter(|m| m.class == ItemClass::Secret)
        .map(|m| (m.id.to_string(), m))
        .collect();
    let (mut marks, mut already, mut missing) = (Vec::new(), 0usize, 0usize);
    for e in &p.items {
        let Some(m) = by_id.get(&e.item) else {
            missing += 1;
            continue;
        };
        let sources: Vec<ExposureSource> = e.sources.iter().map(|k| (*k).into()).collect();
        // Marked for every kind named already, and the mark covers every
        // value the item holds: nothing to write. A mark that does not
        // cover a value set since (a field replaced after it) is written,
        // and covers it then (`Txn::mark_exposed`).
        let known = m
            .exposure
            .as_ref()
            .is_some_and(|x| sources.iter().all(|k| x.sources.contains(k)));
        if known && m.rotate_recommended && v.exposure_covers(m.id) {
            already += 1;
        } else {
            marks.push((m.id, m.slug.clone(), sources, e.count));
        }
    }
    if !marks.is_empty() {
        v.transact(|t| {
            for (id, _, sources, count) in &marks {
                t.mark_exposed(*id, sources, *count)?;
            }
            Ok(())
        })
        .map_err(|e| write_error(&e))?;
    }
    Ok(Marked {
        marked: marks.into_iter().map(|(id, slug, ..)| (id, slug)).collect(),
        already,
        missing,
    })
}

/// The classification the registry gives `value` in an item with
/// `details`, as `items.add` gives a new item's (SPEC §6.3): detected with
/// the item's variable to break ties, and taken only when the item names
/// no provider or the provider detected; otherwise unknown. `None` with
/// no registry, when nothing can be detected. In M1 every classification
/// comes from a detection (no command sets one by hand), so the item's
/// classification follows its value.
fn detected_class(
    shared: &Shared,
    details: &ItemDetails,
    value: &SecretBytes,
) -> Option<Classification> {
    let r = shared.registry.as_ref()?;
    let d = r.detect(value, details.env_hint.as_deref());
    let mut probe = ItemDetails {
        provider: details.provider.clone(),
        ..ItemDetails::default()
    };
    r.prefill(&d, &mut probe);
    Some(probe.classification)
}

/// `items.remove`. See the module documentation.
pub fn remove(
    shared: &Shared,
    peer: &PeerIdentity,
    p: RemoveParams,
) -> Result<RemovedView, RpcError> {
    let pass = p.passphrase.into_inner();
    let resolve = |v: &Vault| target(v, &p.slug, None, Some(&p.item));
    let mut proven = prove(shared, peer, Write::Remove, &p.claims, pass, &resolve)?;
    let written = (|| {
        let v = proven.s.unlocked_mut()?;
        let t = resolve(v)?;
        // The backup keeps the item's values; without it nothing is removed.
        let backup = v.create_backup().map_err(|e| {
            log_line!(
                "envcloakd: the backup before a removal could not be written ({}); nothing was \
                 removed",
                backup_reason(e.kind())
            );
            RpcError::new(ErrorKind::BackupFailed)
        })?;
        v.transact(|txn| txn.delete_item(t.item))
            .map_err(|e| write_error(&e))?;
        Ok((t, backup))
    })();
    let (t, backup) = match written {
        Ok(w) => w,
        Err(e) => return Err(proven.aborted(peer, Write::Remove, e)),
    };
    let grants = proven.s.grants().on_item_removed(t.item);
    let subject = subject_summary(peer, &proven.caller);
    proven.s.audit(AuditEvent::Removed {
        pid: peer.pid,
        subject,
        item: t.item,
        slug: t.slug.clone(),
        grants,
    });
    Ok(RemovedView {
        slug: t.slug.as_str().to_owned(),
        grants_ended: u64::try_from(grants).unwrap_or(u64::MAX),
        backup: backup
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_text_without_blanks_or_invisible_characters() {
        for ok in ["you@work.com", "team-billing", "\u{e9}quipe@example.fr"] {
            assert!(valid_account(ok), "{ok}");
        }
        let long = "a".repeat(MAX_ACCOUNT + 1);
        for bad in [
            "",
            "two words",
            "tab\there",
            "line\nbreak",
            "bell\u{7}",
            "rtl\u{202e}moc.krow",
            "zero\u{200b}width",
            long.as_str(),
        ] {
            assert!(!valid_account(bad), "{bad:?}");
        }
    }

    #[test]
    fn length_classes_follow_the_injection_rules() {
        assert_eq!(LengthClass::of(1), LengthClass::TooShort);
        assert_eq!(LengthClass::of(7), LengthClass::TooShort);
        assert_eq!(LengthClass::of(8), LengthClass::Short);
        assert_eq!(LengthClass::of(15), LengthClass::Short);
        assert_eq!(LengthClass::of(16), LengthClass::Ok);
    }

    #[test]
    fn values_are_checked_before_they_are_stored() {
        assert!(check_value(&SecretBytes::copy_from(b"a value")).is_ok());
        let reason = |v: &[u8]| check_value(&SecretBytes::copy_from(v)).unwrap_err().reason;
        assert_eq!(reason(b""), Some("empty_value"));
        assert_eq!(reason(b"nul\0inside"), Some("nul_byte"));
        assert_eq!(reason(&vec![b'a'; MAX_FIELD + 1]), Some("value_too_large"));
        assert!(check_value(&SecretBytes::copy_from(&vec![b'a'; MAX_FIELD])).is_ok());
    }
}
