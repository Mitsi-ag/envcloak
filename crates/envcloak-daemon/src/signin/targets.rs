//! Sign-in target management (`signin.target.add`, `signin.target.edit`,
//! `signin.target.remove`, `signin.target.list`): proof-gated writes to
//! `policies.sealed` (`PolicyRecord::SignInTarget`, kind `4`), origin
//! validation via `envcloak_signin::origin::parse_registered`, revision
//! tracking on edits, and immediate reconciliation of `OperationStore`
//! (SPEC §6.8, §10b, task M2b-05).

use std::path::Path;
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{CryptoErrorKind, ItemClass};
use envcloak_core::vault::{
    AdapterRef as VaultAdapterRef, Classification, CookieScope as VaultCookieScope,
    IdentityCheck as VaultIdentityCheck, IdentityCheckKind as VaultIdentityCheckKind, ItemId,
    ItemMeta, LoginTier, PolicyId, PolicyRecord, SessionFormat as VaultSessionFormat, SignInTarget,
    Slug, StorageScope as VaultStorageScope, TransferScope as VaultTransferScope, Vault,
    VaultErrorKind,
};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{
    ErrorKind, SigninTargetAddParams, SigninTargetEditParams, SigninTargetListParams,
    SigninTargetRemoveParams,
};
use envcloak_ipc::view::{
    AdapterRefView, CookieScopeView, IdentityCheckKindView, IdentityCheckView, LoginTierView,
    SessionFormatView, SigninTargetListView, SigninTargetRemovedView, SigninTargetView,
    StorageScopeView,
};
use envcloak_policy::{SubjectEvidence, load_project};
use envcloak_signin::origin::parse_registered;
use envcloak_signin::{
    Account, AdapterId, CheckKind, CookieDomain, CookiePartition, CookiePath, DeclaredCookie,
    DeclaredStorage, Environment, Host, HostName, IdentityCheck as SignInIdentityCheck, Label,
    MAX_APPROVAL, MAX_SESSION_LIFETIME, Origin, Site, SortedSet, Target, TargetId, Tier,
    TransferScope as SignInTransferScope,
};
use envcloak_sys::PeerIdentity;
use sha2::{Digest, Sha256};

use crate::audit::AuditEvent;
use crate::clock::now_of;
use crate::items::refuse_item_prover;
use crate::lock::Reading;
use crate::requests::{
    evidence, manifest_error, refuse_unless_prover_beside_pending, requester_terminal_in,
    subject_summary,
};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::vault_reason;

/// Parsed, validated representation of a stored [`SignInTarget`] record.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ParsedTarget {
    pub policy_id: PolicyId,
    pub name: String,
    pub login_item: ItemId,
    pub login_slug: Option<Slug>,
    pub account_label: Label,
    pub tenant_label: Option<Label>,
    pub role_label: Label,
    pub app_origins: SortedSet<Origin>,
    pub credential_origins: SortedSet<Origin>,
    pub identity_provider_origins: SortedSet<Origin>,
    pub callback_origins: SortedSet<Origin>,
    pub target: Target,
    pub tier: LoginTier,
    pub session_format: VaultSessionFormat,
    pub approval_lifetime: Duration,
    pub session_lifetime: Duration,
    pub revocation: Option<String>,
    pub adapter_view: Option<AdapterRefView>,
    pub shared_loopback_cookie_jar: bool,
}

impl ParsedTarget {
    pub fn build_account(&self, login_rev: u64, class: Classification) -> Account {
        let environment = match class {
            Classification::Test => Environment::Test,
            Classification::Unknown | Classification::Live => Environment::Live,
        };
        Account {
            login_item: self.login_item,
            authorization_revision: login_rev,
            account: self.account_label.clone(),
            tenant: self.tenant_label.clone(),
            role: self.role_label.clone(),
            environment,
        }
    }
}

fn invalid_target(reason: &'static str) -> RpcError {
    RpcError::with_reason(ErrorKind::InvalidParams, reason)
}

fn no_such_target() -> RpcError {
    RpcError::with_reason(ErrorKind::NoSuchItem, "unknown_target")
}

pub(crate) fn tier_to_vault(t: LoginTierView) -> LoginTier {
    match t {
        LoginTierView::Dev => LoginTier::Dev,
        LoginTierView::Each => LoginTier::Each,
        LoginTierView::NeverAgent => LoginTier::NeverAgent,
    }
}

pub(crate) fn tier_from_vault(t: LoginTier) -> LoginTierView {
    match t {
        LoginTier::Dev => LoginTierView::Dev,
        LoginTier::Each => LoginTierView::Each,
        LoginTier::NeverAgent => LoginTierView::NeverAgent,
    }
}

#[allow(dead_code)]
pub(crate) fn tier_from_signin(t: Tier) -> LoginTierView {
    match t {
        Tier::Dev => LoginTierView::Dev,
        Tier::Each => LoginTierView::Each,
    }
}

pub(crate) fn format_to_vault(f: SessionFormatView) -> VaultSessionFormat {
    match f {
        SessionFormatView::Cookies => VaultSessionFormat::Cookies,
        SessionFormatView::Storage => VaultSessionFormat::Storage,
        SessionFormatView::CookiesAndStorage => VaultSessionFormat::CookiesAndStorage,
    }
}

pub(crate) fn format_from_vault(f: VaultSessionFormat) -> SessionFormatView {
    match f {
        VaultSessionFormat::Cookies => SessionFormatView::Cookies,
        VaultSessionFormat::Storage => SessionFormatView::Storage,
        VaultSessionFormat::CookiesAndStorage => SessionFormatView::CookiesAndStorage,
    }
}

fn check_kind_to_vault(k: IdentityCheckKindView) -> VaultIdentityCheckKind {
    match k {
        IdentityCheckKindView::Endpoint => VaultIdentityCheckKind::Endpoint,
        IdentityCheckKindView::Element => VaultIdentityCheckKind::Element,
    }
}

fn check_kind_from_vault(k: VaultIdentityCheckKind) -> IdentityCheckKindView {
    match k {
        VaultIdentityCheckKind::Endpoint => IdentityCheckKindView::Endpoint,
        VaultIdentityCheckKind::Element => IdentityCheckKindView::Element,
    }
}

fn check_kind_to_signin(k: VaultIdentityCheckKind) -> CheckKind {
    match k {
        VaultIdentityCheckKind::Endpoint => CheckKind::Endpoint,
        VaultIdentityCheckKind::Element => CheckKind::Element,
    }
}

fn valid_target_name(name: &str) -> bool {
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    first_ok
        && name.len() <= 128
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')
        })
}

fn adapter_id_of(adapter: Option<&VaultAdapterRef>) -> (AdapterId, u64) {
    match adapter {
        None => (AdapterId::from_bytes([0u8; 16]), 0),
        Some(a) => {
            let mut h = Sha256::new();
            h.update(b"envcloak-signin-adapter/1\n");
            h.update((a.id.len() as u32).to_be_bytes());
            h.update(a.id.as_bytes());
            h.update((a.version.len() as u32).to_be_bytes());
            h.update(a.version.as_bytes());
            let digest: [u8; 32] = h.finalize().into();
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            (AdapterId::from_bytes(bytes), 1)
        }
    }
}

fn validate_manifest_opt(manifest: Option<&str>) -> Result<(), RpcError> {
    if let Some(m) = manifest {
        let p = Path::new(m);
        if !p.is_absolute() {
            return Err(RpcError::with_reason(
                ErrorKind::ManifestInvalid,
                "invalid_path",
            ));
        }
        load_project(p).map_err(manifest_error)?;
    }
    Ok(())
}

fn parse_origin_set(raw: &[String]) -> Result<(SortedSet<Origin>, Vec<String>), RpcError> {
    let mut parsed = Vec::with_capacity(raw.len());
    for s in raw {
        let origin = parse_registered(s).map_err(|_| invalid_target("invalid_origin"))?;
        parsed.push(origin);
    }
    let set = SortedSet::new(parsed).map_err(|_| invalid_target("invalid_origin_set"))?;
    let canonical = set.iter().map(ToString::to_string).collect();
    Ok((set, canonical))
}

fn parse_site(raw: &str) -> Result<(Site, String), RpcError> {
    let origin = parse_registered(raw).map_err(|_| invalid_target("invalid_origin"))?;
    if origin.port() != origin.scheme().default_port() {
        return Err(invalid_target("partition_site_has_port"));
    }
    let site = Site {
        scheme: origin.scheme(),
        host: origin.host().clone(),
    };
    let text = format!("{}://{}", site.scheme.as_str(), site.host);
    Ok((site, text))
}

fn parse_cookie_scopes(
    raw: &[CookieScopeView],
) -> Result<(SortedSet<DeclaredCookie>, Vec<VaultCookieScope>), RpcError> {
    let mut cookies = Vec::with_capacity(raw.len());
    for c in raw {
        let name = Label::new(&c.name).map_err(|_| invalid_target("invalid_cookie_name"))?;
        let path = CookiePath::new(&c.path).map_err(|_| invalid_target("invalid_cookie_path"))?;
        let domain = match (c.host_only, c.domain.strip_prefix('.')) {
            (Some(true), Some(_)) => return Err(invalid_target("invalid_cookie_domain")),
            (Some(false), Some(rest)) | (None, Some(rest)) => {
                let hn =
                    HostName::new(rest).map_err(|_| invalid_target("invalid_cookie_domain"))?;
                CookieDomain::Domain(hn)
            }
            (Some(false), None) => {
                let hn = HostName::new(&c.domain)
                    .map_err(|_| invalid_target("invalid_cookie_domain"))?;
                CookieDomain::Domain(hn)
            }
            (Some(true) | None, None) => {
                let h =
                    Host::parse(&c.domain).map_err(|_| invalid_target("invalid_cookie_domain"))?;
                CookieDomain::HostOnly(h)
            }
        };
        let partition = match &c.partition_top_site {
            None => {
                if c.cross_site_ancestor {
                    return Err(invalid_target("invalid_cookie_partition"));
                }
                CookiePartition::Unpartitioned
            }
            Some(site_str) => {
                let (site, _) = parse_site(site_str)?;
                CookiePartition::Partitioned {
                    site,
                    cross_site_ancestor: c.cross_site_ancestor,
                }
            }
        };
        cookies.push(DeclaredCookie {
            name,
            domain,
            path,
            partition,
        });
    }
    let set = SortedSet::new(cookies).map_err(|_| invalid_target("invalid_cookie_set"))?;
    let vault_cookies = set.iter().map(encode_vault_cookie).collect();
    Ok((set, vault_cookies))
}

fn encode_vault_cookie(c: &DeclaredCookie) -> VaultCookieScope {
    let base_domain = match &c.domain {
        CookieDomain::HostOnly(h) => h.to_string(),
        CookieDomain::Domain(hn) => format!(".{}", hn.as_str()),
    };
    let domain = match &c.partition {
        CookiePartition::Unpartitioned => base_domain,
        CookiePartition::Partitioned {
            site,
            cross_site_ancestor: false,
        } => format!("{base_domain}@{}://{}", site.scheme.as_str(), site.host),
        CookiePartition::Partitioned {
            site,
            cross_site_ancestor: true,
        } => format!("{base_domain}@+{}://{}", site.scheme.as_str(), site.host),
    };
    VaultCookieScope {
        name: c.name.as_str().to_owned(),
        domain,
        path: c.path.as_str().to_owned(),
    }
}

pub(crate) fn decode_vault_cookie(
    c: &VaultCookieScope,
) -> Result<(DeclaredCookie, CookieScopeView), RpcError> {
    let name = Label::new(&c.name).map_err(|_| invalid_target("invalid_cookie_name"))?;
    let path = CookiePath::new(&c.path).map_err(|_| invalid_target("invalid_cookie_path"))?;
    let (dom_str, part_str) = match c.domain.split_once('@') {
        Some((d, p)) => (d, Some(p)),
        None => (c.domain.as_str(), None),
    };
    let (domain, domain_view, host_only) = if let Some(rest) = dom_str.strip_prefix('.') {
        let hn = HostName::new(rest).map_err(|_| invalid_target("invalid_cookie_domain"))?;
        let view = hn.as_str().to_owned();
        (CookieDomain::Domain(hn), view, Some(false))
    } else {
        let h = Host::parse(dom_str).map_err(|_| invalid_target("invalid_cookie_domain"))?;
        let view = h.to_string();
        (CookieDomain::HostOnly(h), view, Some(true))
    };
    let (partition, partition_top_site, cross_site_ancestor) = match part_str {
        None => (CookiePartition::Unpartitioned, None, false),
        Some(p) => {
            let (ancestor, site_str) = match p.strip_prefix('+') {
                Some(rest) => (true, rest),
                None => (false, p),
            };
            let (site, site_text) = parse_site(site_str)?;
            (
                CookiePartition::Partitioned {
                    site,
                    cross_site_ancestor: ancestor,
                },
                Some(site_text),
                ancestor,
            )
        }
    };
    let view = CookieScopeView {
        name: name.as_str().to_owned(),
        domain: domain_view,
        path: path.as_str().to_owned(),
        host_only,
        partition_top_site,
        cross_site_ancestor,
    };
    let declared = DeclaredCookie {
        name,
        domain,
        path,
        partition,
    };
    Ok((declared, view))
}

fn parse_storage_scopes(
    raw: &[StorageScopeView],
) -> Result<(SortedSet<DeclaredStorage>, Vec<VaultStorageScope>), RpcError> {
    let mut items = Vec::with_capacity(raw.len());
    for s in raw {
        let origin = parse_registered(&s.origin).map_err(|_| invalid_target("invalid_origin"))?;
        let key = Label::new(&s.key).map_err(|_| invalid_target("invalid_storage_key"))?;
        items.push(DeclaredStorage { origin, key });
    }
    let set = SortedSet::new(items).map_err(|_| invalid_target("invalid_storage_set"))?;
    let vault_storage = set
        .iter()
        .map(|s| VaultStorageScope {
            origin: s.origin.to_string(),
            key: s.key.as_str().to_owned(),
        })
        .collect();
    Ok((set, vault_storage))
}

pub(crate) fn decode_vault_storage(
    s: &VaultStorageScope,
) -> Result<(DeclaredStorage, StorageScopeView), RpcError> {
    let origin = parse_registered(&s.origin).map_err(|_| invalid_target("invalid_origin"))?;
    let key = Label::new(&s.key).map_err(|_| invalid_target("invalid_storage_key"))?;
    let view = StorageScopeView {
        origin: origin.to_string(),
        key: key.as_str().to_owned(),
    };
    let declared = DeclaredStorage { origin, key };
    Ok((declared, view))
}

fn has_shared_loopback_cookie_jar(
    app_origins: &SortedSet<Origin>,
    cookies: &SortedSet<DeclaredCookie>,
) -> bool {
    if cookies.is_empty() {
        return false;
    }
    app_origins.iter().any(|o| o.host().is_loopback())
        || cookies.iter().any(|c| match &c.domain {
            CookieDomain::HostOnly(h) => h.is_loopback(),
            CookieDomain::Domain(hn) => hn.as_str().ends_with(".localhost"),
        })
}

/// Resolves a login item reference (`slug` or 26-char ULID `ItemId`) in `v`.
pub(crate) fn resolve_login_item<'v>(
    v: &'v Vault,
    reference: &str,
) -> Result<&'v ItemMeta, RpcError> {
    if let Ok(slug) = Slug::new(reference)
        && let Some(item) = v.find(&slug)
    {
        if item.class != ItemClass::Login {
            return Err(invalid_target("not_a_login_item"));
        }
        return Ok(item);
    }
    for item in v.items() {
        if item.id.to_string() == reference {
            if item.class != ItemClass::Login {
                return Err(invalid_target("not_a_login_item"));
            }
            return Ok(item);
        }
    }
    Err(RpcError::with_reason(
        ErrorKind::NoSuchItem,
        "unknown_login_item",
    ))
}

/// Converts a stored [`SignInTarget`] policy record into a validated
/// [`ParsedTarget`] and [`SigninTargetView`].
pub(crate) fn target_from_vault(
    v: &Vault,
    id: PolicyId,
    record: &SignInTarget,
    ended_operations: u64,
    revoked_authorizations: u64,
) -> Result<(ParsedTarget, SigninTargetView), RpcError> {
    if !valid_target_name(&record.name) {
        return Err(invalid_target("invalid_target_name"));
    }
    let (app_origins, app_view) = parse_origin_set(&record.app_origins)?;
    let (credential_origins, cred_view) = parse_origin_set(&record.credential_origins)?;
    if credential_origins.is_empty() {
        return Err(invalid_target("no_credential_origin"));
    }
    let (idp_origins, idp_view) = parse_origin_set(&record.identity_provider_origins)?;
    let (cb_origins, cb_view) = parse_origin_set(&record.callback_origins)?;

    let locator = Label::new(&record.identity_check.locator)
        .map_err(|_| invalid_target("invalid_identity_check"))?;
    let account_label = Label::new(&record.identity_check.account)
        .map_err(|_| invalid_target("invalid_account"))?;
    let tenant_label = match &record.identity_check.tenant {
        Some(t) => Some(Label::new(t).map_err(|_| invalid_target("invalid_tenant"))?),
        None => None,
    };
    let role_label =
        Label::new(&record.identity_check.role).map_err(|_| invalid_target("invalid_role"))?;

    let ic_view = IdentityCheckView {
        kind: check_kind_from_vault(record.identity_check.kind),
        locator: locator.as_str().to_owned(),
        account: account_label.as_str().to_owned(),
        tenant: tenant_label.as_ref().map(|t| t.as_str().to_owned()),
        role: role_label.as_str().to_owned(),
    };
    let signin_ic = SignInIdentityCheck {
        kind: check_kind_to_signin(record.identity_check.kind),
        locator,
    };

    let mut cookie_vec = Vec::with_capacity(record.transfer.cookies.len());
    let mut cookies_view = Vec::with_capacity(record.transfer.cookies.len());
    for c in &record.transfer.cookies {
        let (dc, vc) = decode_vault_cookie(c)?;
        cookie_vec.push(dc);
        cookies_view.push(vc);
    }
    let cookies = SortedSet::new(cookie_vec).map_err(|_| invalid_target("invalid_cookie_set"))?;

    let mut storage_vec = Vec::with_capacity(record.transfer.storage.len());
    let mut storage_view = Vec::with_capacity(record.transfer.storage.len());
    for s in &record.transfer.storage {
        let (ds, vs) = decode_vault_storage(s)?;
        storage_vec.push(ds);
        storage_view.push(vs);
    }
    let storage = SortedSet::new(storage_vec).map_err(|_| invalid_target("invalid_storage_set"))?;

    match record.transfer.format {
        VaultSessionFormat::Cookies if cookies.is_empty() || !storage.is_empty() => {
            return Err(invalid_target("transfer_format_mismatch"));
        }
        VaultSessionFormat::Storage if storage.is_empty() || !cookies.is_empty() => {
            return Err(invalid_target("transfer_format_mismatch"));
        }
        VaultSessionFormat::CookiesAndStorage if cookies.is_empty() && storage.is_empty() => {
            return Err(invalid_target("transfer_format_mismatch"));
        }
        _ => {}
    }

    let approval_lifetime = Duration::from_secs(record.approval_lifetime);
    let session_lifetime = Duration::from_secs(record.session_lifetime);
    if approval_lifetime.is_zero()
        || approval_lifetime > MAX_APPROVAL
        || session_lifetime.is_zero()
        || session_lifetime > MAX_SESSION_LIFETIME
    {
        return Err(invalid_target("invalid_lifetime"));
    }

    if let Some(ref rev) = record.revocation {
        let _ = Label::new(rev).map_err(|_| invalid_target("invalid_revocation"))?;
    }

    let adapter_view = match &record.adapter {
        None => None,
        Some(a) => {
            let id_lbl = Label::new(&a.id).map_err(|_| invalid_target("invalid_adapter"))?;
            let ver_lbl = Label::new(&a.version).map_err(|_| invalid_target("invalid_adapter"))?;
            Some(AdapterRefView {
                id: id_lbl.as_str().to_owned(),
                version: ver_lbl.as_str().to_owned(),
            })
        }
    };
    let (adapter_id, adapter_rev_base) = adapter_id_of(record.adapter.as_ref());
    let adapter_revision = if adapter_rev_base == 0 {
        0
    } else {
        record.revision.max(1)
    };

    let shared_loopback_cookie_jar = has_shared_loopback_cookie_jar(&app_origins, &cookies);
    let login_meta = v.item(record.login);
    let login_slug = login_meta.map(|m| m.slug.clone());

    let target = Target {
        id: TargetId::from_bytes(*id.as_bytes()),
        revision: record.revision,
        adapter: adapter_id,
        adapter_revision,
        entry_origins: credential_origins.clone(),
        identity_check: signin_ic,
        transfer: SignInTransferScope { cookies, storage },
    };

    let view = SigninTargetView {
        id: id.to_string(),
        name: record.name.clone(),
        login_item: record.login.to_string(),
        login_slug: login_slug.as_ref().map(|s| s.as_str().to_owned()),
        revision: record.revision,
        app_origins: app_view,
        credential_origins: cred_view,
        identity_provider_origins: idp_view,
        callback_origins: cb_view,
        identity_check: ic_view,
        cookies: cookies_view,
        storage: storage_view,
        session_format: format_from_vault(record.transfer.format),
        tier: tier_from_vault(record.tier),
        adapter: adapter_view.clone(),
        approval_lifetime_secs: record.approval_lifetime,
        session_lifetime_secs: record.session_lifetime,
        revocation: record.revocation.clone(),
        shared_loopback_cookie_jar,
        ended_operations,
        revoked_authorizations,
    };

    let parsed = ParsedTarget {
        policy_id: id,
        name: record.name.clone(),
        login_item: record.login,
        login_slug,
        account_label,
        tenant_label,
        role_label,
        app_origins,
        credential_origins,
        identity_provider_origins: idp_origins,
        callback_origins: cb_origins,
        target,
        tier: record.tier,
        session_format: record.transfer.format,
        approval_lifetime,
        session_lifetime,
        revocation: record.revocation.clone(),
        adapter_view,
        shared_loopback_cookie_jar,
    };
    Ok((parsed, view))
}

/// Looks up a sign-in target by name and optional role in the unlocked vault.
pub(crate) fn find_target_by_name_and_role(
    v: &Vault,
    name: &str,
    role: Option<&str>,
) -> Result<Option<(PolicyId, SignInTarget)>, RpcError> {
    let policies = v
        .policies()
        .map_err(|e| RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind())))?;
    let mut matches = Vec::new();
    for (id, rec) in policies {
        if let PolicyRecord::SignInTarget(t) = rec
            && t.name == name
            && role.is_none_or(|r| t.identity_check.role == r)
        {
            matches.push((id, t.clone()));
        }
    }
    if matches.len() > 1 && role.is_none() {
        return Err(invalid_target("ambiguous_target_role"));
    }
    Ok(matches.into_iter().next())
}

/// Looks up a sign-in target by [`TargetId`] in the unlocked vault.
pub(crate) fn find_target_by_id(v: &Vault, id: TargetId) -> Result<Option<ParsedTarget>, RpcError> {
    let pid = PolicyId::from_bytes(*id.as_bytes());
    let policies = v
        .policies()
        .map_err(|e| RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind())))?;
    for (rec_id, rec) in policies {
        if rec_id == pid
            && let PolicyRecord::SignInTarget(t) = rec
        {
            let (parsed, _) = target_from_vault(v, rec_id, t, 0, 0)?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn build_vault_target(
    v: &Vault,
    id: PolicyId,
    name: &str,
    login: ItemId,
    revision: u64,
    app_origins: &[String],
    credential_origins: &[String],
    identity_provider_origins: &[String],
    callback_origins: &[String],
    identity_check: &IdentityCheckView,
    cookies: &[CookieScopeView],
    storage: &[StorageScopeView],
    session_format: SessionFormatView,
    tier: LoginTierView,
    adapter: Option<&AdapterRefView>,
    approval_lifetime_secs: u64,
    session_lifetime_secs: u64,
    revocation: Option<&str>,
) -> Result<(SignInTarget, SigninTargetView), RpcError> {
    if !valid_target_name(name) {
        return Err(invalid_target("invalid_target_name"));
    }
    let (_, app_canonical) = parse_origin_set(app_origins)?;
    let (_, cred_canonical) = parse_origin_set(credential_origins)?;
    let (_, idp_canonical) = parse_origin_set(identity_provider_origins)?;
    let (_, cb_canonical) = parse_origin_set(callback_origins)?;
    let (_, vault_cookies) = parse_cookie_scopes(cookies)?;
    let (_, vault_storage) = parse_storage_scopes(storage)?;

    let vault_ic = VaultIdentityCheck {
        kind: check_kind_to_vault(identity_check.kind),
        locator: identity_check.locator.clone(),
        account: identity_check.account.clone(),
        tenant: identity_check.tenant.clone(),
        role: identity_check.role.clone(),
    };
    let vault_adapter = adapter.map(|a| VaultAdapterRef {
        id: a.id.clone(),
        version: a.version.clone(),
    });

    let record = SignInTarget {
        name: name.to_owned(),
        login,
        revision,
        app_origins: app_canonical,
        credential_origins: cred_canonical,
        identity_provider_origins: idp_canonical,
        callback_origins: cb_canonical,
        identity_check: vault_ic,
        transfer: VaultTransferScope {
            cookies: vault_cookies,
            storage: vault_storage,
            format: format_to_vault(session_format),
        },
        tier: tier_to_vault(tier),
        adapter: vault_adapter,
        approval_lifetime: approval_lifetime_secs,
        session_lifetime: session_lifetime_secs,
        revocation: revocation.map(str::to_owned),
    };
    PolicyRecord::SignInTarget(record.clone())
        .check()
        .map_err(|_| invalid_target("invalid_target_record"))?;
    let (_, view) = target_from_vault(v, id, &record, 0, 0)?;
    Ok((record, view))
}

#[allow(clippy::too_many_arguments)]
fn verify_target_proof<T>(
    shared: &Shared,
    peer: &PeerIdentity,
    method: &'static str,
    target_name: Option<String>,
    claims: &[String],
    passphrase: Option<SecretBytes>,
    precheck: impl Fn(&Vault) -> Result<T, RpcError>,
    commit: impl FnOnce(
        &mut crate::state::State,
        &SubjectEvidence,
        T,
    ) -> Result<SigninTargetOutcome, RpcError>,
) -> Result<SigninTargetOutcome, RpcError> {
    refuse_if_traced()?;
    let caller = evidence(shared, peer, claims)?;
    refuse_unless_prover_beside_pending(shared, peer, &caller, method)?;

    let Some(pass) = passphrase else {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        refuse_item_prover(&mut s, peer, &caller, &now, method)?;
        if let Some(r) = requester_terminal_in(&mut s, &caller, &now) {
            s.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method,
                reason: r.token(),
            });
            return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
        }
        let v = s.unlocked()?;
        let _ = precheck(v)?;
        return Err(invalid_target("passphrase_required"));
    };

    let _gate = locked(&shared.proof_gate);
    let (vault, generation) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        refuse_item_prover(&mut s, peer, &caller, &now, method)?;
        if let Some(r) = requester_terminal_in(&mut s, &caller, &now) {
            s.audit(AuditEvent::ProofRefused {
                pid: peer.pid,
                method,
                reason: r.token(),
            });
            return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
        }
        let _ = precheck(s.unlocked()?)?;
        s.limiter()
            .check(&now)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        s.begin_proof()?
    };

    let verified = vault.verify_passphrase(&pass);
    drop(pass);

    let mut s = locked(&shared.state);
    let now = now_of(&shared.clocks);
    let back = s.finish_proof(generation, vault);
    match verified {
        Ok(()) => {
            s.limiter().succeeded();
            back?;
            let caller = evidence(shared, peer, claims)?;
            refuse_item_prover(&mut s, peer, &caller, &now, method)?;
            if let Some(r) = requester_terminal_in(&mut s, &caller, &now) {
                s.audit(AuditEvent::ProofRefused {
                    pid: peer.pid,
                    method,
                    reason: r.token(),
                });
                return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
            }
            let prepared = precheck(s.unlocked()?)?;
            let out = commit(&mut s, &caller, prepared)?;
            s.touch(Reading::now(&shared.clocks));
            Ok(out)
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::SigninTarget {
                pid: peer.pid,
                subject: subject_summary(peer, &caller),
                outcome: "wrong_passphrase",
                method,
                target: target_name,
                item: None,
                revision: None,
                reason: Some("wrong_passphrase"),
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

#[allow(clippy::large_enum_variant)]
enum SigninTargetOutcome {
    Target(SigninTargetView),
    Removed(SigninTargetRemovedView),
}

/// `signin.target.add`.
pub fn add(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninTargetAddParams,
) -> Result<SigninTargetView, RpcError> {
    validate_manifest_opt(p.manifest.as_deref())?;
    let policy_id = PolicyId::generate();
    let pass = p.passphrase.map(|w| w.into_inner());
    let outcome = verify_target_proof(
        shared,
        peer,
        "signin.target.add",
        Some(p.name.clone()),
        &p.claims,
        pass,
        |v| {
            if find_target_by_name_and_role(v, &p.name, Some(&p.identity_check.role))?.is_some() {
                return Err(RpcError::new(ErrorKind::ItemExists));
            }
            let login_meta = resolve_login_item(v, &p.login)?.clone();
            let (record, view) = build_vault_target(
                v,
                policy_id,
                &p.name,
                login_meta.id,
                1,
                &p.app_origins,
                &p.credential_origins,
                &p.identity_provider_origins,
                &p.callback_origins,
                &p.identity_check,
                &p.cookies,
                &p.storage,
                p.session_format,
                p.tier,
                p.adapter.as_ref(),
                p.approval_lifetime_secs,
                p.session_lifetime_secs,
                p.revocation.as_deref(),
            )?;
            Ok((login_meta, record, view))
        },
        |s, caller, (login_meta, record, view)| {
            {
                let v = s.unlocked_mut()?;
                v.transact(|txn| {
                    txn.put_policy(policy_id, &PolicyRecord::SignInTarget(record.clone()))
                })
                .map_err(|e| crate::items::write_error(&e))?;
            }
            s.audit(AuditEvent::SigninTarget {
                pid: peer.pid,
                subject: subject_summary(peer, caller),
                outcome: "added",
                method: "signin.target.add",
                target: Some(p.name.clone()),
                item: Some((login_meta.id, login_meta.slug)),
                revision: Some(1),
                reason: None,
            });
            Ok(SigninTargetOutcome::Target(view))
        },
    )?;
    match outcome {
        SigninTargetOutcome::Target(v) => Ok(v),
        SigninTargetOutcome::Removed(_) => Err(RpcError::new(ErrorKind::Internal)),
    }
}

/// `signin.target.edit`.
pub fn edit(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninTargetEditParams,
) -> Result<SigninTargetView, RpcError> {
    validate_manifest_opt(p.manifest.as_deref())?;
    let pass = p.passphrase.map(|w| w.into_inner());
    let outcome = verify_target_proof(
        shared,
        peer,
        "signin.target.edit",
        Some(p.name.clone()),
        &p.claims,
        pass,
        |v| {
            let (id, existing) = match p.role.as_deref() {
                Some(r) => find_target_by_name_and_role(v, &p.name, Some(r))?,
                None => match find_target_by_name_and_role(v, &p.name, None) {
                    Ok(found) => found,
                    Err(e) => {
                        if let Some(ic) = &p.identity_check {
                            find_target_by_name_and_role(v, &p.name, Some(&ic.role))?
                        } else {
                            return Err(e);
                        }
                    }
                },
            }
            .ok_or_else(no_such_target)?;
            let (_, existing_view) = target_from_vault(v, id, &existing, 0, 0)?;
            let next_rev = existing
                .revision
                .checked_add(1)
                .ok_or_else(|| invalid_target("revision_overflow"))?;

            let login_meta = match p.login.as_deref() {
                Some(l) => resolve_login_item(v, l)?.clone(),
                None => v
                    .item(existing.login)
                    .filter(|m| m.class == ItemClass::Login)
                    .ok_or_else(|| {
                        RpcError::with_reason(ErrorKind::NoSuchItem, "unknown_login_item")
                    })?
                    .clone(),
            };

            let app_origins = p
                .app_origins
                .as_deref()
                .unwrap_or(&existing_view.app_origins);
            let cred_origins = p
                .credential_origins
                .as_deref()
                .unwrap_or(&existing_view.credential_origins);
            let idp_origins = p
                .identity_provider_origins
                .as_deref()
                .unwrap_or(&existing_view.identity_provider_origins);
            let cb_origins = p
                .callback_origins
                .as_deref()
                .unwrap_or(&existing_view.callback_origins);
            let ic = p
                .identity_check
                .as_ref()
                .unwrap_or(&existing_view.identity_check);
            let cookies = p.cookies.as_deref().unwrap_or(&existing_view.cookies);
            let storage = p.storage.as_deref().unwrap_or(&existing_view.storage);
            let session_format = p.session_format.unwrap_or(existing_view.session_format);
            let tier = p.tier.unwrap_or(existing_view.tier);
            let approval_lifetime_secs = p
                .approval_lifetime_secs
                .unwrap_or(existing_view.approval_lifetime_secs);
            let session_lifetime_secs = p
                .session_lifetime_secs
                .unwrap_or(existing_view.session_lifetime_secs);
            let revocation = match &p.revocation {
                Some(r) => r.as_deref(),
                None => existing_view.revocation.as_deref(),
            };
            let adapter = match &p.adapter {
                Some(a) => a.as_ref(),
                None => existing_view.adapter.as_ref(),
            };

            let (updated, view) = build_vault_target(
                v,
                id,
                &p.name,
                login_meta.id,
                next_rev,
                app_origins,
                cred_origins,
                idp_origins,
                cb_origins,
                ic,
                cookies,
                storage,
                session_format,
                tier,
                adapter,
                approval_lifetime_secs,
                session_lifetime_secs,
                revocation,
            )?;
            Ok((id, login_meta, updated, view))
        },
        |s, caller, (id, login_meta, updated, mut view)| {
            let rev = updated.revision;
            {
                let v = s.unlocked_mut()?;
                v.transact(|txn| txn.put_policy(id, &PolicyRecord::SignInTarget(updated)))
                    .map_err(|e| crate::items::write_error(&e))?;
            }
            let (ended_ops, revoked_auths) = s.signin_reconcile_counts(shared);
            view.ended_operations = u64::try_from(ended_ops).unwrap_or(u64::MAX);
            view.revoked_authorizations = u64::try_from(revoked_auths).unwrap_or(u64::MAX);
            s.audit(AuditEvent::SigninTarget {
                pid: peer.pid,
                subject: subject_summary(peer, caller),
                outcome: "edited",
                method: "signin.target.edit",
                target: Some(p.name.clone()),
                item: Some((login_meta.id, login_meta.slug)),
                revision: Some(rev),
                reason: None,
            });
            Ok(SigninTargetOutcome::Target(view))
        },
    )?;
    match outcome {
        SigninTargetOutcome::Target(v) => Ok(v),
        SigninTargetOutcome::Removed(_) => Err(RpcError::new(ErrorKind::Internal)),
    }
}

/// `signin.target.remove`.
pub fn remove(
    shared: &Shared,
    peer: &PeerIdentity,
    p: SigninTargetRemoveParams,
) -> Result<SigninTargetRemovedView, RpcError> {
    validate_manifest_opt(p.manifest.as_deref())?;
    let pass = p.passphrase.map(|w| w.into_inner());
    let outcome = verify_target_proof(
        shared,
        peer,
        "signin.target.remove",
        Some(p.name.clone()),
        &p.claims,
        pass,
        |v| {
            let policies = v.policies().map_err(|e| {
                RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind()))
            })?;
            let mut to_remove = Vec::new();
            for (id, rec) in policies {
                if let PolicyRecord::SignInTarget(t) = rec
                    && t.name == p.name
                    && p.role.as_deref().is_none_or(|r| t.identity_check.role == r)
                {
                    let item = v.item(t.login).map(|m| (m.id, m.slug.clone()));
                    to_remove.push((id, t.revision, item));
                }
            }
            if to_remove.is_empty() {
                return Err(no_such_target());
            }
            Ok(to_remove)
        },
        |s, caller, to_remove| {
            let removed_count = to_remove.len();
            let first_rev = to_remove.first().map(|(_, r, _)| *r);
            let first_item = to_remove.first().and_then(|(_, _, i)| i.clone());
            {
                let v = s.unlocked_mut()?;
                v.transact(|txn| {
                    for (id, _, _) in &to_remove {
                        txn.delete_policy(*id)?;
                    }
                    Ok(())
                })
                .map_err(|e| crate::items::write_error(&e))?;
            }
            let (ended_ops, revoked_auths) = s.signin_reconcile_counts(shared);
            s.audit(AuditEvent::SigninTarget {
                pid: peer.pid,
                subject: subject_summary(peer, caller),
                outcome: "removed",
                method: "signin.target.remove",
                target: Some(p.name.clone()),
                item: first_item,
                revision: first_rev,
                reason: None,
            });
            Ok(SigninTargetOutcome::Removed(SigninTargetRemovedView {
                removed: u64::try_from(removed_count).unwrap_or(u64::MAX),
                ended_operations: u64::try_from(ended_ops).unwrap_or(u64::MAX),
                revoked_authorizations: u64::try_from(revoked_auths).unwrap_or(u64::MAX),
            }))
        },
    )?;
    match outcome {
        SigninTargetOutcome::Removed(v) => Ok(v),
        SigninTargetOutcome::Target(_) => Err(RpcError::new(ErrorKind::Internal)),
    }
}

/// `signin.target.list`.
pub fn list(shared: &Shared, p: SigninTargetListParams) -> Result<SigninTargetListView, RpcError> {
    validate_manifest_opt(p.manifest.as_deref())?;
    let s = locked(&shared.state);
    let v = s.unlocked()?;
    let policies = v
        .policies()
        .map_err(|e| RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(e.kind())))?;
    let mut targets = Vec::new();
    for (id, rec) in policies {
        if let PolicyRecord::SignInTarget(t) = rec {
            let (_, view) = target_from_vault(v, id, t, 0, 0)?;
            targets.push(view);
        }
    }
    targets.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.identity_check.role.cmp(&b.identity_check.role))
    });
    Ok(SigninTargetListView { targets })
}
