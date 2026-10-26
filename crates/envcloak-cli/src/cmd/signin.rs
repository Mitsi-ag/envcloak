//! `envcloak signin target add|edit|rm|ls` (SPEC §6.8, M2b-05) and
//! `envcloak signin setup` (M2b-08).
//!
//! - `target add`, `target edit` and `target rm` require a passphrase proof
//!   from a terminal session with no agent in it (binding a login item to
//!   origins is what makes the credential usable there).
//! - `target ls` lists registered sign-in targets (metadata only).
//! - `setup` verifies the pinned sign-in browser runtime (Node,
//!   `@playwright/mcp` + `playwright-core`, and Chrome for Testing).

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use envcloak_client::render::{json_text, print_json};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_core::vault::{DEFAULT_LOGIN_SESSION_LIFETIME_SECS, MAX_LOGIN_SESSION_LIFETIME_SECS};
use envcloak_ipc::proto::{
    ErrorKind, SigninTargetAddParams, SigninTargetEditParams, SigninTargetRemoveParams,
};
use envcloak_ipc::view::{
    AdapterRefView, CookieScopeView, IdentityCheckKindView, IdentityCheckView, LoginTierView,
    SessionFormatView, SigninTargetListView, SigninTargetRemovedView, SigninTargetView,
    StorageScopeView,
};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_policy::escape_for_display;
use envcloak_signin::MAX_APPROVAL;

use super::{fd_number, refuse_value_like};

const DEFAULT_SIGNIN_APPROVAL_LIFETIME_SECS: u64 = 8 * 3600;
const MAX_SIGNIN_APPROVAL_LIFETIME_SECS: u64 = MAX_APPROVAL.as_secs();

const USAGE_TEXT: &str = "envcloak signin target add <name> --login <slug> \
    --credential-origin <url>... --identity-check endpoint|element <locator> \
    --account <acct> [--tenant <tenant>] --role <role> [--app-origin <url>]... \
    [--idp-origin <url>]... [--callback-origin <url>]... [--cookie <name>@<domain><path>]... \
    [--storage <origin>#<key>]... [--format cookies|storage|cookies-and-storage] \
    [--tier dev|each|never-agent] [--adapter <id>@<version>] [--approval-lifetime <dur>] \
    [--session-lifetime <dur>] [--revocation <endpoint>] [--manifest <path>] \
    [--passphrase-fd N] [--json]\n       \
    envcloak signin target edit <name> [--role <role>] [--login <slug>] \
    [--credential-origin <url>]... [--identity-check endpoint|element <locator>] \
    [--account <acct>] [--tenant <tenant> | --no-tenant] [--new-role <role>] \
    [--app-origin <url>]... [--clear-app-origins] [--idp-origin <url>]... \
    [--clear-idp-origins] [--callback-origin <url>]... [--clear-callback-origins] \
    [--cookie <name>@<domain><path>]... [--clear-cookies] [--storage <origin>#<key>]... \
    [--clear-storage] [--format cookies|storage|cookies-and-storage] \
    [--tier dev|each|never-agent] [--adapter <id>@<version> | --no-adapter] \
    [--approval-lifetime <dur>] [--session-lifetime <dur>] \
    [--revocation <endpoint> | --no-revocation] [--manifest <path>] \
    [--passphrase-fd N] [--json]\n       \
    envcloak signin target rm <name> [--role <role>] [--manifest <path>] \
    [--passphrase-fd N] [--json]\n       \
    envcloak signin target ls [--json]\n       \
    envcloak signin setup [--versions <path>] [--json]";

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Action {
    Add {
        params: SigninTargetAddParams,
        passphrase_fd: Option<i32>,
        json: bool,
    },
    Edit {
        params: Box<SigninTargetEditParams>,
        partial_ic: PartialIdentityCheck,
        passphrase_fd: Option<i32>,
        json: bool,
    },
    Remove {
        params: SigninTargetRemoveParams,
        passphrase_fd: Option<i32>,
        json: bool,
    },
    List {
        json: bool,
    },
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PartialIdentityCheck {
    kind_locator: Option<(IdentityCheckKindView, String)>,
    account: Option<String>,
    tenant: Option<Option<String>>,
    new_role: Option<String>,
}

impl PartialIdentityCheck {
    fn is_any(&self) -> bool {
        self.kind_locator.is_some()
            || self.account.is_some()
            || self.tenant.is_some()
            || self.new_role.is_some()
    }
}

fn parse_duration_secs(s: &str, max_secs: u64) -> Option<u64> {
    let (digits, factor) = if let Some(d) = s.strip_suffix('s') {
        (d, 1u64)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60u64)
    } else {
        (s.strip_suffix('h')?, 3600u64)
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(factor)?;
    (1..=max_secs).contains(&secs).then_some(secs)
}

fn parse_tier(s: &str) -> Option<LoginTierView> {
    match s {
        "dev" => Some(LoginTierView::Dev),
        "each" => Some(LoginTierView::Each),
        "never-agent" => Some(LoginTierView::NeverAgent),
        _ => None,
    }
}

fn parse_format(s: &str) -> Option<SessionFormatView> {
    match s {
        "cookies" => Some(SessionFormatView::Cookies),
        "storage" => Some(SessionFormatView::Storage),
        "cookies-and-storage" => Some(SessionFormatView::CookiesAndStorage),
        _ => None,
    }
}

fn parse_check_kind(s: &str) -> Option<IdentityCheckKindView> {
    match s {
        "endpoint" => Some(IdentityCheckKindView::Endpoint),
        "element" => Some(IdentityCheckKindView::Element),
        _ => None,
    }
}

fn parse_adapter(s: &str) -> Option<AdapterRefView> {
    let (id, version) = s.split_once('@')?;
    if id.is_empty() || version.is_empty() {
        return None;
    }
    Some(AdapterRefView {
        id: id.to_owned(),
        version: version.to_owned(),
    })
}

/// Parses `<name>@<domain><path>[@[+]<partition_site>]`.
fn parse_cookie_spec(s: &str) -> Option<CookieScopeView> {
    let (name, rest) = s.split_once('@')?;
    if name.is_empty() {
        return None;
    }
    let (domain_and_path, partition_raw) = match rest.split_once('@') {
        Some((dp, part)) => (dp, Some(part)),
        None => (rest, None),
    };
    let slash = domain_and_path.find('/')?;
    let raw_domain = &domain_and_path[..slash];
    let path = &domain_and_path[slash..];
    if raw_domain.is_empty() || path.is_empty() {
        return None;
    }
    let (domain, host_only) = if let Some(stripped) = raw_domain.strip_prefix('.') {
        if stripped.is_empty() {
            return None;
        }
        (stripped.to_owned(), Some(false))
    } else {
        (raw_domain.to_owned(), Some(true))
    };
    let (partition_top_site, cross_site_ancestor) = match partition_raw {
        None => (None, false),
        Some(p) => {
            let (anc, site) = match p.strip_prefix('+') {
                Some(r) => (true, r),
                None => (false, p),
            };
            if site.is_empty() {
                return None;
            }
            (Some(site.to_owned()), anc)
        }
    };
    Some(CookieScopeView {
        name: name.to_owned(),
        domain,
        path: path.to_owned(),
        host_only,
        partition_top_site,
        cross_site_ancestor,
    })
}

/// Parses `<origin>#<key>`.
fn parse_storage_spec(s: &str) -> Option<StorageScopeView> {
    let (origin, key) = s.split_once('#')?;
    if origin.is_empty() || key.is_empty() {
        return None;
    }
    Some(StorageScopeView {
        origin: origin.to_owned(),
        key: key.to_owned(),
    })
}

fn resolve_manifest_arg(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let p = Path::new(raw);
    if p.is_absolute() {
        return Some(raw.to_owned());
    }
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(p))
        .and_then(|full| full.into_os_string().into_string().ok())
}

fn parse(args: &[&str]) -> Result<Option<Action>, Failure> {
    let Some((&first, rest)) = args.split_first() else {
        return Ok(None);
    };
    if first != "target" {
        return Ok(None);
    }
    let Some((&sub, tail)) = rest.split_first() else {
        return Ok(None);
    };
    match sub {
        "ls" | "list" => match tail {
            [] => Ok(Some(Action::List { json: false })),
            ["--json"] => Ok(Some(Action::List { json: true })),
            _ => Ok(None),
        },
        "add" => parse_add(tail),
        "edit" => parse_edit(tail),
        "rm" | "remove" => parse_remove(tail),
        _ => Ok(None),
    }
}

fn parse_add(args: &[&str]) -> Result<Option<Action>, Failure> {
    let Some((&name, rest)) = args.split_first() else {
        return Ok(None);
    };
    if name.is_empty() || name.starts_with('-') {
        return Ok(None);
    }
    refuse_value_like(&[name])?;

    let mut login: Option<String> = None;
    let mut app_origins = Vec::new();
    let mut credential_origins = Vec::new();
    let mut idp_origins = Vec::new();
    let mut callback_origins = Vec::new();
    let mut check_kind_locator: Option<(IdentityCheckKindView, String)> = None;
    let mut account: Option<String> = None;
    let mut tenant: Option<String> = None;
    let mut role: Option<String> = None;
    let mut cookies = Vec::new();
    let mut storage = Vec::new();
    let mut session_format: Option<SessionFormatView> = None;
    let mut tier: Option<LoginTierView> = None;
    let mut adapter: Option<AdapterRefView> = None;
    let mut approval_lifetime_secs: Option<u64> = None;
    let mut session_lifetime_secs: Option<u64> = None;
    let mut revocation: Option<String> = None;
    let mut manifest: Option<String> = None;
    let mut passphrase_fd: Option<i32> = None;
    let mut json = false;

    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        match flag {
            "--login" if login.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                login = Some(v.to_owned());
            }
            "--app-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                app_origins.push(v.to_owned());
            }
            "--credential-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                credential_origins.push(v.to_owned());
            }
            "--idp-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                idp_origins.push(v.to_owned());
            }
            "--callback-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                callback_origins.push(v.to_owned());
            }
            "--identity-check" if check_kind_locator.is_none() => {
                let Some(&k_raw) = it.next() else {
                    return Ok(None);
                };
                let Some(&loc) = it.next() else {
                    return Ok(None);
                };
                let Some(k) = parse_check_kind(k_raw) else {
                    return Ok(None);
                };
                refuse_value_like(&[loc])?;
                check_kind_locator = Some((k, loc.to_owned()));
            }
            "--account" if account.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                account = Some(v.to_owned());
            }
            "--tenant" if tenant.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                tenant = Some(v.to_owned());
            }
            "--role" if role.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                role = Some(v.to_owned());
            }
            "--cookie" => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(c) = parse_cookie_spec(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[c.name.as_str()])?;
                cookies.push(c);
            }
            "--storage" => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(s) = parse_storage_spec(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[s.key.as_str()])?;
                storage.push(s);
            }
            "--format" if session_format.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(f) = parse_format(v) else {
                    return Ok(None);
                };
                session_format = Some(f);
            }
            "--tier" if tier.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(t) = parse_tier(v) else {
                    return Ok(None);
                };
                tier = Some(t);
            }
            "--adapter" if adapter.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(a) = parse_adapter(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[a.id.as_str(), a.version.as_str()])?;
                adapter = Some(a);
            }
            "--approval-lifetime" if approval_lifetime_secs.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(secs) = parse_duration_secs(v, MAX_SIGNIN_APPROVAL_LIFETIME_SECS) else {
                    return Ok(None);
                };
                approval_lifetime_secs = Some(secs);
            }
            "--session-lifetime" if session_lifetime_secs.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(secs) = parse_duration_secs(v, MAX_LOGIN_SESSION_LIFETIME_SECS) else {
                    return Ok(None);
                };
                session_lifetime_secs = Some(secs);
            }
            "--revocation" if revocation.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                revocation = Some(v.to_owned());
            }
            "--manifest" if manifest.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(m) = resolve_manifest_arg(v) else {
                    return Ok(None);
                };
                manifest = Some(m);
            }
            "--passphrase-fd" if passphrase_fd.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(fd) = fd_number(v) else {
                    return Ok(None);
                };
                passphrase_fd = Some(fd);
            }
            "--json" if !json => json = true,
            _ => return Ok(None),
        }
    }

    let Some(login) = login else { return Ok(None) };
    if credential_origins.is_empty() {
        return Ok(None);
    }
    let Some((kind, locator)) = check_kind_locator else {
        return Ok(None);
    };
    let Some(account) = account else {
        return Ok(None);
    };
    let Some(role) = role else { return Ok(None) };

    let inferred_format = match (cookies.is_empty(), storage.is_empty()) {
        (false, true) => SessionFormatView::Cookies,
        (true, false) => SessionFormatView::Storage,
        (false, false) => SessionFormatView::CookiesAndStorage,
        (true, true) => SessionFormatView::Cookies,
    };

    Ok(Some(Action::Add {
        params: SigninTargetAddParams {
            name: name.to_owned(),
            login,
            app_origins,
            credential_origins,
            identity_provider_origins: idp_origins,
            callback_origins,
            identity_check: IdentityCheckView {
                kind,
                locator,
                account,
                tenant,
                role,
            },
            cookies,
            storage,
            session_format: session_format.unwrap_or(inferred_format),
            tier: tier.unwrap_or(LoginTierView::Each),
            adapter,
            approval_lifetime_secs: approval_lifetime_secs
                .unwrap_or(DEFAULT_SIGNIN_APPROVAL_LIFETIME_SECS),
            session_lifetime_secs: session_lifetime_secs
                .unwrap_or(DEFAULT_LOGIN_SESSION_LIFETIME_SECS),
            revocation,
            manifest,
            passphrase: None,
            claims: Vec::new(),
        },
        passphrase_fd,
        json,
    }))
}

fn parse_edit(args: &[&str]) -> Result<Option<Action>, Failure> {
    let Some((&name, rest)) = args.split_first() else {
        return Ok(None);
    };
    if name.is_empty() || name.starts_with('-') {
        return Ok(None);
    }
    refuse_value_like(&[name])?;

    let mut role: Option<String> = None;
    let mut login: Option<String> = None;
    let mut app_origins: Option<Vec<String>> = None;
    let mut credential_origins: Option<Vec<String>> = None;
    let mut idp_origins: Option<Vec<String>> = None;
    let mut callback_origins: Option<Vec<String>> = None;
    let mut partial_ic = PartialIdentityCheck::default();
    let mut cookies: Option<Vec<CookieScopeView>> = None;
    let mut storage: Option<Vec<StorageScopeView>> = None;
    let mut session_format: Option<SessionFormatView> = None;
    let mut tier: Option<LoginTierView> = None;
    let mut adapter: Option<Option<AdapterRefView>> = None;
    let mut approval_lifetime_secs: Option<u64> = None;
    let mut session_lifetime_secs: Option<u64> = None;
    let mut revocation: Option<Option<String>> = None;
    let mut manifest: Option<String> = None;
    let mut passphrase_fd: Option<i32> = None;
    let mut json = false;

    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        match flag {
            "--role" if role.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                role = Some(v.to_owned());
            }
            "--login" if login.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                login = Some(v.to_owned());
            }
            "--app-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                app_origins.get_or_insert_with(Vec::new).push(v.to_owned());
            }
            "--clear-app-origins" if app_origins.is_none() => {
                app_origins = Some(Vec::new());
            }
            "--credential-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                credential_origins
                    .get_or_insert_with(Vec::new)
                    .push(v.to_owned());
            }
            "--idp-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                idp_origins.get_or_insert_with(Vec::new).push(v.to_owned());
            }
            "--clear-idp-origins" if idp_origins.is_none() => {
                idp_origins = Some(Vec::new());
            }
            "--callback-origin" => {
                let Some(&v) = it.next() else { return Ok(None) };
                callback_origins
                    .get_or_insert_with(Vec::new)
                    .push(v.to_owned());
            }
            "--clear-callback-origins" if callback_origins.is_none() => {
                callback_origins = Some(Vec::new());
            }
            "--identity-check" if partial_ic.kind_locator.is_none() => {
                let Some(&k_raw) = it.next() else {
                    return Ok(None);
                };
                let Some(&loc) = it.next() else {
                    return Ok(None);
                };
                let Some(k) = parse_check_kind(k_raw) else {
                    return Ok(None);
                };
                refuse_value_like(&[loc])?;
                partial_ic.kind_locator = Some((k, loc.to_owned()));
            }
            "--account" if partial_ic.account.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                partial_ic.account = Some(v.to_owned());
            }
            "--tenant" if partial_ic.tenant.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                partial_ic.tenant = Some(Some(v.to_owned()));
            }
            "--no-tenant" if partial_ic.tenant.is_none() => {
                partial_ic.tenant = Some(None);
            }
            "--new-role" if partial_ic.new_role.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                partial_ic.new_role = Some(v.to_owned());
            }
            "--cookie" => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(c) = parse_cookie_spec(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[c.name.as_str()])?;
                cookies.get_or_insert_with(Vec::new).push(c);
            }
            "--clear-cookies" if cookies.is_none() => {
                cookies = Some(Vec::new());
            }
            "--storage" => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(s) = parse_storage_spec(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[s.key.as_str()])?;
                storage.get_or_insert_with(Vec::new).push(s);
            }
            "--clear-storage" if storage.is_none() => {
                storage = Some(Vec::new());
            }
            "--format" if session_format.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(f) = parse_format(v) else {
                    return Ok(None);
                };
                session_format = Some(f);
            }
            "--tier" if tier.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(t) = parse_tier(v) else {
                    return Ok(None);
                };
                tier = Some(t);
            }
            "--adapter" if adapter.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(a) = parse_adapter(v) else {
                    return Ok(None);
                };
                refuse_value_like(&[a.id.as_str(), a.version.as_str()])?;
                adapter = Some(Some(a));
            }
            "--no-adapter" if adapter.is_none() => {
                adapter = Some(None);
            }
            "--approval-lifetime" if approval_lifetime_secs.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(secs) = parse_duration_secs(v, MAX_SIGNIN_APPROVAL_LIFETIME_SECS) else {
                    return Ok(None);
                };
                approval_lifetime_secs = Some(secs);
            }
            "--session-lifetime" if session_lifetime_secs.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(secs) = parse_duration_secs(v, MAX_LOGIN_SESSION_LIFETIME_SECS) else {
                    return Ok(None);
                };
                session_lifetime_secs = Some(secs);
            }
            "--revocation" if revocation.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                revocation = Some(Some(v.to_owned()));
            }
            "--no-revocation" if revocation.is_none() => {
                revocation = Some(None);
            }
            "--manifest" if manifest.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(m) = resolve_manifest_arg(v) else {
                    return Ok(None);
                };
                manifest = Some(m);
            }
            "--passphrase-fd" if passphrase_fd.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(fd) = fd_number(v) else {
                    return Ok(None);
                };
                passphrase_fd = Some(fd);
            }
            "--json" if !json => json = true,
            _ => return Ok(None),
        }
    }

    let has_any_edit = login.is_some()
        || app_origins.is_some()
        || credential_origins.is_some()
        || idp_origins.is_some()
        || callback_origins.is_some()
        || partial_ic.is_any()
        || cookies.is_some()
        || storage.is_some()
        || session_format.is_some()
        || tier.is_some()
        || adapter.is_some()
        || approval_lifetime_secs.is_some()
        || session_lifetime_secs.is_some()
        || revocation.is_some();
    if !has_any_edit {
        return Ok(None);
    }

    Ok(Some(Action::Edit {
        params: Box::new(SigninTargetEditParams {
            name: name.to_owned(),
            role,
            login,
            app_origins,
            credential_origins,
            identity_provider_origins: idp_origins,
            callback_origins,
            identity_check: None,
            cookies,
            storage,
            session_format,
            tier,
            adapter,
            approval_lifetime_secs,
            session_lifetime_secs,
            revocation,
            manifest,
            passphrase: None,
            claims: Vec::new(),
        }),
        partial_ic,
        passphrase_fd,
        json,
    }))
}

fn parse_remove(args: &[&str]) -> Result<Option<Action>, Failure> {
    let Some((&name, rest)) = args.split_first() else {
        return Ok(None);
    };
    if name.is_empty() || name.starts_with('-') {
        return Ok(None);
    }
    refuse_value_like(&[name])?;

    let mut role: Option<String> = None;
    let mut manifest: Option<String> = None;
    let mut passphrase_fd: Option<i32> = None;
    let mut json = false;

    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        match flag {
            "--role" if role.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                refuse_value_like(&[v])?;
                role = Some(v.to_owned());
            }
            "--manifest" if manifest.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(m) = resolve_manifest_arg(v) else {
                    return Ok(None);
                };
                manifest = Some(m);
            }
            "--passphrase-fd" if passphrase_fd.is_none() => {
                let Some(&v) = it.next() else { return Ok(None) };
                let Some(fd) = fd_number(v) else {
                    return Ok(None);
                };
                passphrase_fd = Some(fd);
            }
            "--json" if !json => json = true,
            _ => return Ok(None),
        }
    }

    Ok(Some(Action::Remove {
        params: SigninTargetRemoveParams {
            name: name.to_owned(),
            role,
            manifest,
            passphrase: None,
            claims: Vec::new(),
        },
        passphrase_fd,
        json,
    }))
}

pub fn run(args: &[&str]) -> ExitCode {
    if let Some(rest) = args.strip_prefix(&["setup"]) {
        return run_setup(rest);
    }
    if matches!(
        args,
        ["--help"] | ["-h"] | ["help"] | ["target", "--help"] | ["target", "-h"]
    ) {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let action = match parse(args) {
        Ok(Some(a)) => a,
        Ok(None) => return usage(USAGE_TEXT),
        Err(f) => return f.report(USAGE),
    };
    let res = match action {
        Action::Add {
            params,
            passphrase_fd,
            json,
        } => target_add(params, passphrase_fd, json),
        Action::Edit {
            params,
            partial_ic,
            passphrase_fd,
            json,
        } => target_edit(*params, partial_ic, passphrase_fd, json),
        Action::Remove {
            params,
            passphrase_fd,
            json,
        } => target_remove(params, passphrase_fd, json),
        Action::List { json } => target_list(json),
    };
    res.unwrap_or_else(|f| f.report(FAILURE))
}

fn run_setup(args: &[&str]) -> ExitCode {
    if matches!(args, ["--help"] | ["-h"]) {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let mut json = false;
    let mut versions_path: Option<std::path::PathBuf> = None;
    let mut it = args.iter();
    while let Some(&flag) = it.next() {
        match flag {
            "--json" if !json => json = true,
            "--versions" if versions_path.is_none() => {
                let Some(&v) = it.next() else {
                    return usage(USAGE_TEXT);
                };
                versions_path = Some(std::path::PathBuf::from(v));
            }
            _ => return usage(USAGE_TEXT),
        }
    }
    if let Err(f) = refuse_if_traced() {
        return f.report(FAILURE);
    }
    let vpath = versions_path.unwrap_or_else(envcloak_mcp::browser::browser_versions_path);
    match envcloak_mcp::browser::resolve_browser_runtime(&vpath) {
        Ok(rt) => {
            if json {
                println!(
                    "{{\"status\":\"ready\",\"node_version\":{},\"helper_version\":{},\"playwright_version\":{},\"chrome_version\":{},\"chrome_revision\":{}}}",
                    json_text(&rt.pins.node_version),
                    json_text(&rt.pins.helper_version),
                    json_text(&rt.pins.playwright_version),
                    json_text(&rt.pins.chrome_version),
                    json_text(&rt.pins.chrome_revision),
                );
            } else {
                println!(
                    "sign-in browser runtime verified (node {}, @playwright/mcp {}, Chrome for Testing {} r{})",
                    escape_for_display(&rt.pins.node_version),
                    escape_for_display(&rt.pins.helper_version),
                    escape_for_display(&rt.pins.chrome_version),
                    escape_for_display(&rt.pins.chrome_revision),
                );
            }
            ExitCode::SUCCESS
        }
        Err(why) => Failure::new("check_failed", why).report(FAILURE),
    }
}

fn read_proof_passphrase(
    passphrase_fd: Option<i32>,
    prompt: &str,
) -> Result<envcloak_core::SecretBytes, Failure> {
    match passphrase_fd {
        Some(fd) => Ok(read_secret_fd(fd)?),
        None => {
            let mut t = Terminal::open()?;
            Ok(t.read_secret(prompt)?)
        }
    }
}

fn expect_passphrase_required<T>(res: Result<T, ClientError>) -> Result<(), Failure> {
    match res {
        Err(ClientError::Rpc(r)) if r.kind == ErrorKind::InvalidParams => Ok(()),
        Err(e) => Err(Failure::from(e)),
        Ok(_) => Err(Failure::new(
            "protocol_error",
            "the daemon's answer was malformed",
        )),
    }
}

fn target_add(
    mut params: SigninTargetAddParams,
    passphrase_fd: Option<i32>,
    json: bool,
) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    params.claims = refuse_if_claimed()?;
    expect_passphrase_required(connect()?.signin_target_add(&params))?;
    let pass = read_proof_passphrase(
        passphrase_fd,
        "Vault passphrase to register sign-in target: ",
    )?;
    params.passphrase = Some(WireSecret::new(pass));
    let view = connect()?.signin_target_add(&params)?;
    if json {
        print_json(&view);
    } else {
        print!("{}", format_target("Added", &view));
    }
    Ok(ExitCode::SUCCESS)
}

fn target_edit(
    mut params: SigninTargetEditParams,
    partial_ic: PartialIdentityCheck,
    passphrase_fd: Option<i32>,
    json: bool,
) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    params.claims = refuse_if_claimed()?;
    if partial_ic.is_any() {
        let list = connect()?.signin_target_list(params.manifest.as_deref())?;
        let matches: Vec<&SigninTargetView> = list
            .targets
            .iter()
            .filter(|t| {
                t.name == params.name
                    && params
                        .role
                        .as_deref()
                        .is_none_or(|r| t.identity_check.role == r)
            })
            .collect();
        if let [existing] = matches.as_slice() {
            let (kind, locator) = partial_ic.kind_locator.unwrap_or_else(|| {
                (
                    existing.identity_check.kind,
                    existing.identity_check.locator.clone(),
                )
            });
            let account = partial_ic
                .account
                .unwrap_or_else(|| existing.identity_check.account.clone());
            let tenant = partial_ic
                .tenant
                .unwrap_or_else(|| existing.identity_check.tenant.clone());
            let role = partial_ic
                .new_role
                .unwrap_or_else(|| existing.identity_check.role.clone());
            params.identity_check = Some(IdentityCheckView {
                kind,
                locator,
                account,
                tenant,
                role,
            });
        } else if let (Some((kind, locator)), Some(account), Some(role)) = (
            partial_ic.kind_locator,
            partial_ic.account,
            partial_ic.new_role.or_else(|| params.role.clone()),
        ) {
            params.identity_check = Some(IdentityCheckView {
                kind,
                locator,
                account,
                tenant: partial_ic.tenant.flatten(),
                role,
            });
        }
    }
    expect_passphrase_required(connect()?.signin_target_edit(&params))?;
    let pass = read_proof_passphrase(passphrase_fd, "Vault passphrase to edit sign-in target: ")?;
    params.passphrase = Some(WireSecret::new(pass));
    let view = connect()?.signin_target_edit(&params)?;
    if json {
        print_json(&view);
    } else {
        print!("{}", format_target("Edited", &view));
    }
    Ok(ExitCode::SUCCESS)
}

fn target_remove(
    mut params: SigninTargetRemoveParams,
    passphrase_fd: Option<i32>,
    json: bool,
) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    params.claims = refuse_if_claimed()?;
    expect_passphrase_required(connect()?.signin_target_remove(&params))?;
    let pass = read_proof_passphrase(passphrase_fd, "Vault passphrase to remove sign-in target: ")?;
    params.passphrase = Some(WireSecret::new(pass));
    let view = connect()?.signin_target_remove(&params)?;
    if json {
        print_json(&view);
    } else {
        print!(
            "{}",
            format_removed(&params.name, params.role.as_deref(), &view)
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn target_list(json: bool) -> Result<ExitCode, Failure> {
    let view = connect()?.signin_target_list(None)?;
    print!("{}", format_list(&view, json));
    Ok(ExitCode::SUCCESS)
}

fn format_target(verb: &str, t: &SigninTargetView) -> String {
    let e = escape_for_display;
    let mut o = String::new();
    let login = t.login_slug.as_deref().map_or_else(|| e(&t.login_item), e);
    let _ = writeln!(
        o,
        "{verb} sign-in target {} (role {}, revision {}).",
        e(&t.name),
        e(&t.identity_check.role),
        t.revision
    );
    let _ = writeln!(o, "  id: {}", e(&t.id));
    let _ = writeln!(o, "  login: {login}");
    let _ = writeln!(o, "  tier: {}", t.tier.as_str());
    let creds: Vec<String> = t.credential_origins.iter().map(|u| e(u)).collect();
    let _ = writeln!(o, "  credential origins: {}", creds.join(", "));
    if !t.app_origins.is_empty() {
        let apps: Vec<String> = t.app_origins.iter().map(|u| e(u)).collect();
        let _ = writeln!(o, "  app origins: {}", apps.join(", "));
    }
    let tenant = t
        .identity_check
        .tenant
        .as_deref()
        .map_or_else(|| "none".to_owned(), e);
    let _ = writeln!(
        o,
        "  identity check: {} {} (account {}, tenant {}, role {})",
        t.identity_check.kind.as_str(),
        e(&t.identity_check.locator),
        e(&t.identity_check.account),
        tenant,
        e(&t.identity_check.role)
    );
    let _ = writeln!(o, "  session format: {}", t.session_format.as_str());
    if t.shared_loopback_cookie_jar {
        let _ = writeln!(
            o,
            "  note: cookies on a loopback host are shared across every port on that host"
        );
    }
    if t.ended_operations > 0 || t.revoked_authorizations > 0 {
        let _ = writeln!(
            o,
            "  reconciled: {} operations ended, {} authorizations revoked",
            t.ended_operations, t.revoked_authorizations
        );
    }
    o
}

fn format_removed(name: &str, role: Option<&str>, r: &SigninTargetRemovedView) -> String {
    let e = escape_for_display;
    match role {
        Some(role) => format!(
            "Removed sign-in target {} (role {}): {} operations ended, {} authorizations revoked.\n",
            e(name),
            e(role),
            r.ended_operations,
            r.revoked_authorizations
        ),
        None => format!(
            "Removed sign-in target {}: {} operations ended, {} authorizations revoked.\n",
            e(name),
            r.ended_operations,
            r.revoked_authorizations
        ),
    }
}

fn format_list(list: &SigninTargetListView, json: bool) -> String {
    if json {
        return format!("{}\n", json_text(list));
    }
    if list.targets.is_empty() {
        return "No sign-in targets are registered.\n".to_owned();
    }
    let mut o = String::new();
    for t in &list.targets {
        o.push_str(&format_target("Target", t));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_commands_parse_and_refuse_invalid_inputs() {
        let a = parse(&[
            "target",
            "add",
            "acme/local",
            "--login",
            "acme/editor",
            "--credential-origin",
            "http://127.0.0.1:4100",
            "--app-origin",
            "http://127.0.0.1:4100",
            "--identity-check",
            "endpoint",
            "/api/whoami",
            "--account",
            "dev@acme.test",
            "--tenant",
            "acme-dev",
            "--role",
            "editor",
            "--cookie",
            "sid@127.0.0.1/",
            "--tier",
            "dev",
            "--approval-lifetime",
            "4h",
            "--session-lifetime",
            "1h",
            "--passphrase-fd",
            "3",
            "--json",
        ])
        .unwrap()
        .unwrap();
        match a {
            Action::Add {
                params,
                passphrase_fd,
                json,
            } => {
                assert_eq!(params.name, "acme/local");
                assert_eq!(params.login, "acme/editor");
                assert_eq!(params.credential_origins, vec!["http://127.0.0.1:4100"]);
                assert_eq!(params.cookies.len(), 1);
                assert_eq!(params.cookies[0].name, "sid");
                assert_eq!(params.cookies[0].host_only, Some(true));
                assert_eq!(params.tier, LoginTierView::Dev);
                assert_eq!(passphrase_fd, Some(3));
                assert!(json);
            }
            other => panic!("unexpected action: {other:?}"),
        }

        assert!(matches!(
            parse(&["target", "ls", "--json"]).unwrap(),
            Some(Action::List { json: true })
        ));
        assert!(parse(&["target"]).unwrap().is_none());
        assert!(parse(&["target", "add", "acme/local"]).unwrap().is_none());
        assert!(parse(&["target", "edit", "acme/local"]).unwrap().is_none());
    }
}
