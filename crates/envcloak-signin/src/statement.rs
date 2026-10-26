//! The sign-in approval statement (SPEC §6.8 "Approval"; R-M2b-14):
//! `envcloak-signin-statement/1`.
//!
//! A statement wraps one [`SignInScope`] for one operation: the scope, the
//! request id, a fresh daemon nonce, creation and expiry, the options the
//! approver chose (`once`, or `dev` with a window and an attempt budget)
//! and the one recipient-context id reserved for the operation. Its
//! canonical encoding ([`SignInStatement::canonical`], docs/GRANTS.md
//! "Sign-in scope and statement") is the line
//! `envcloak-signin-statement/1\n`, then numbered, length-prefixed fields
//! as in the scope's encoding: 1 the scope's whole encoding, 2 the request
//! id, 3 the nonce, 4 and 5 creation and expiry in Unix seconds (8 bytes
//! each), 6 the options (`1` for once; `2`, the window in seconds as 8
//! bytes and the attempts as 1 byte for dev), 7 the context id (8 bytes).
//! [`SignInStatement::digest`] is its SHA-256, which the approver's proof
//! names.
//!
//! The nonce and the reserved context belong to the statement, never to
//! the scope: [`SignInStatement::lookup_fingerprint`] is the scope's
//! fingerprint alone, so a retry finds its operation whatever nonce the
//! daemon drew for it (SI-07).

use std::fmt::{self, Write as _};
use std::time::Duration;

use envcloak_core::vault::ItemId;
use envcloak_policy::{SubjectKind, SubjectSummary, escape_for_display};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scope::{
    Account, AdapterId, CheckKind, CookieDomain, CookiePartition, CookiePath, DaemonInstance,
    DeclaredCookie, DeclaredStorage, Delivery, DeliveryMode, Environment, Epochs, Fields,
    Fingerprint, Host, HostName, IdentityCheck, Instance, Label, Limits, MAX_APPROVAL,
    MAX_DEV_ATTEMPTS, Origin, ProjectScope, Scheme, SignInScope, Site, SortedSet, Target, TargetId,
    Tier, TransferScope, decode_hex, format_ipv6_whatwg, hex,
};

/// The first line of every sign-in statement (docs/IPC.md "Statement
/// domains").
pub const STATEMENT_DOMAIN: &[u8] = b"envcloak-signin-statement/1\n";
/// The attempt budget a `dev` approval offers unless the person picks
/// another (plan M2b-01).
pub const DEFAULT_DEV_ATTEMPTS: u8 = 3;

/// An operation's request id: 16 random bytes the daemon draws. Opaque and
/// never bearer authority: status and cancel answer only the owner root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 16]);

impl RequestId {
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        RequestId(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse(s: &str) -> Option<Self> {
        decode_hex::<16>(s).map(RequestId)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", hex(&self.0))
    }
}

/// A fresh daemon nonce: 32 random bytes, one per operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Nonce(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(s: &str) -> Option<Self> {
        decode_hex::<32>(s).map(Nonce)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", hex(&self.0))
    }
}

/// The recipient-context id reserved for one operation, after the retry
/// lookup and only for a new operation (SPEC §6.8 "Approval").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(u64);

impl ContextId {
    pub const fn new(n: u64) -> Self {
        ContextId(n)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

/// What the approver chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Options {
    /// One authentication attempt (one password submission and at most
    /// two one-time codes).
    Once,
    /// A rolling window of at most 24 hours from the approval with a
    /// budget of attempts, for this exact scope (SPEC §6.8 `dev`).
    Dev { window: Duration, attempts: u8 },
}

/// Why options were refused. Fixed and value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionsError {
    /// `dev` for a scope whose tier is `each`.
    NotDev,
    /// A window that is zero, not whole seconds, over 24 hours or over the
    /// scope's approval limit.
    Window,
    /// Attempts outside 1 to 5 or over the scope's limit.
    Attempts,
}

impl Options {
    /// The `dev` options offered by default for `limits`: its whole
    /// approval window and [`DEFAULT_DEV_ATTEMPTS`], or fewer if the scope
    /// allows fewer. `Once` for an `each` scope.
    pub fn default_for(limits: &Limits) -> Options {
        match limits.tier() {
            Tier::Each => Options::Once,
            Tier::Dev => Options::Dev {
                window: limits.approval(),
                attempts: DEFAULT_DEV_ATTEMPTS.min(limits.attempts()),
            },
        }
    }

    /// Whether the scope's limits allow these options: `once` always;
    /// `dev` only for a `dev` scope, with a window of whole seconds within
    /// its approval limit and at most 24 hours, and 1 to 5 attempts within
    /// its attempt limit.
    pub fn allowed_by(&self, limits: &Limits) -> Result<(), OptionsError> {
        match *self {
            Options::Once => Ok(()),
            Options::Dev { window, attempts } => {
                if limits.tier() != Tier::Dev {
                    return Err(OptionsError::NotDev);
                }
                if window.is_zero()
                    || window.subsec_nanos() != 0
                    || window > MAX_APPROVAL
                    || window > limits.approval()
                {
                    return Err(OptionsError::Window);
                }
                if attempts == 0 || attempts > MAX_DEV_ATTEMPTS || attempts > limits.attempts() {
                    return Err(OptionsError::Attempts);
                }
                Ok(())
            }
        }
    }

    fn encode(&self) -> Vec<u8> {
        match *self {
            Options::Once => vec![1],
            Options::Dev { window, attempts } => {
                let mut v = Vec::with_capacity(10);
                v.push(2);
                v.extend_from_slice(&window.as_secs().to_be_bytes());
                v.push(attempts);
                v
            }
        }
    }
}

/// One sign-in approval statement. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignInStatement {
    pub scope: SignInScope,
    pub request: RequestId,
    pub nonce: Nonce,
    /// When the operation was opened, Unix seconds.
    pub created_unix: u64,
    /// When its pending statement expires, Unix seconds.
    pub expires_unix: u64,
    pub options: Options,
    pub context: ContextId,
}

impl SignInStatement {
    /// The canonical encoding. See the module documentation.
    pub fn canonical(&self) -> Vec<u8> {
        let SignInStatement {
            scope,
            request,
            nonce,
            created_unix,
            expires_unix,
            options,
            context,
        } = self;
        let mut e = Fields::new(STATEMENT_DOMAIN);
        e.field(1, &scope.encode());
        e.field(2, request.as_bytes());
        e.field(3, nonce.as_bytes());
        e.field(4, &created_unix.to_be_bytes());
        e.field(5, &expires_unix.to_be_bytes());
        e.field(6, &options.encode());
        e.field(7, &context.get().to_be_bytes());
        e.0
    }

    /// SHA-256 of [`SignInStatement::canonical`]: what a proof approves.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical()).into()
    }

    /// The key a retry is looked up by: the scope's fingerprint, without
    /// the nonce or the reserved context.
    pub fn lookup_fingerprint(&self) -> Fingerprint {
        self.scope.fingerprint()
    }
}

/// Wire form of `options.dev` in `approve` (docs/IPC.md): a sign-in `dev`
/// authorization's window in seconds and attempt budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInDevOptions {
    pub window_secs: u64,
    pub attempts: u8,
}

impl SignInDevOptions {
    pub fn to_options(self) -> Options {
        Options::Dev {
            window: Duration::from_secs(self.window_secs),
            attempts: self.attempts,
        }
    }
}

/// Wire summary of an [`Origin`] in [`SignInPendingDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginSummary {
    pub scheme: String,
    pub host_kind: String,
    pub host: String,
    pub port: u16,
}

impl OriginSummary {
    pub fn from_origin(o: &Origin) -> Self {
        let (host_kind, host) = encode_host(o.host());
        OriginSummary {
            scheme: o.scheme().as_str().to_owned(),
            host_kind,
            host,
            port: o.port(),
        }
    }

    pub fn to_origin(&self) -> Option<Origin> {
        let scheme = parse_scheme(&self.scheme)?;
        let host = decode_host(&self.host_kind, &self.host)?;
        Origin::new(scheme, host, self.port).ok()
    }
}

fn parse_scheme(s: &str) -> Option<Scheme> {
    match s {
        "http" => Some(Scheme::Http),
        "https" => Some(Scheme::Https),
        _ => None,
    }
}

fn encode_host(h: &Host) -> (String, String) {
    match h {
        Host::Name(n) => ("name".to_owned(), n.as_str().to_owned()),
        Host::V4([a, b, c, d]) => ("v4".to_owned(), format!("{a}.{b}.{c}.{d}")),
        Host::V6(octets) => ("v6".to_owned(), format_ipv6_whatwg(octets)),
    }
}

fn decode_host(kind: &str, s: &str) -> Option<Host> {
    match kind {
        "name" => HostName::new(s).ok().map(Host::Name),
        "v4" => {
            let addr: std::net::Ipv4Addr = s.parse().ok()?;
            Some(Host::V4(addr.octets()))
        }
        "v6" => {
            let addr: std::net::Ipv6Addr = s.parse().ok()?;
            Some(Host::V6(addr.octets()))
        }
        _ => None,
    }
}

/// Wire summary of a [`CookiePartition`] in [`CookieSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CookiePartitionSummary {
    pub scheme: String,
    pub host_kind: String,
    pub host: String,
    pub cross_site_ancestor: bool,
}

/// Wire summary of a [`DeclaredCookie`] in [`SignInPendingDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CookieSummary {
    pub name: String,
    pub domain_kind: String,
    pub domain_host_kind: String,
    pub domain: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<CookiePartitionSummary>,
}

impl CookieSummary {
    pub fn from_cookie(c: &DeclaredCookie) -> Self {
        let (domain_kind, domain_host_kind, domain) = match &c.domain {
            CookieDomain::HostOnly(h) => {
                let (hk, hs) = encode_host(h);
                ("host_only".to_owned(), hk, hs)
            }
            CookieDomain::Domain(n) => (
                "domain".to_owned(),
                "name".to_owned(),
                n.as_str().to_owned(),
            ),
        };
        let partition = match &c.partition {
            CookiePartition::Unpartitioned => None,
            CookiePartition::Partitioned {
                site,
                cross_site_ancestor,
            } => {
                let (hk, hs) = encode_host(&site.host);
                Some(CookiePartitionSummary {
                    scheme: site.scheme.as_str().to_owned(),
                    host_kind: hk,
                    host: hs,
                    cross_site_ancestor: *cross_site_ancestor,
                })
            }
        };
        CookieSummary {
            name: c.name.as_str().to_owned(),
            domain_kind,
            domain_host_kind,
            domain,
            path: c.path.as_str().to_owned(),
            partition,
        }
    }

    pub fn to_cookie(&self) -> Option<DeclaredCookie> {
        let name = Label::new(&self.name).ok()?;
        let domain = match self.domain_kind.as_str() {
            "host_only" => {
                CookieDomain::HostOnly(decode_host(&self.domain_host_kind, &self.domain)?)
            }
            "domain" if self.domain_host_kind == "name" => {
                CookieDomain::Domain(HostName::new(&self.domain).ok()?)
            }
            _ => return None,
        };
        let path = CookiePath::new(&self.path).ok()?;
        let partition = match &self.partition {
            None => CookiePartition::Unpartitioned,
            Some(p) => CookiePartition::Partitioned {
                site: Site {
                    scheme: parse_scheme(&p.scheme)?,
                    host: decode_host(&p.host_kind, &p.host)?,
                },
                cross_site_ancestor: p.cross_site_ancestor,
            },
        };
        Some(DeclaredCookie {
            name,
            domain,
            path,
            partition,
        })
    }
}

/// Wire summary of a [`DeclaredStorage`] in [`SignInPendingDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSummary {
    pub origin: OriginSummary,
    pub key: String,
}

impl StorageSummary {
    pub fn from_storage(s: &DeclaredStorage) -> Self {
        StorageSummary {
            origin: OriginSummary::from_origin(&s.origin),
            key: s.key.as_str().to_owned(),
        }
    }

    pub fn to_storage(&self) -> Option<DeclaredStorage> {
        Some(DeclaredStorage {
            origin: self.origin.to_origin()?,
            key: Label::new(&self.key).ok()?,
        })
    }
}

/// A pending sign-in operation as `pending.get` delivers it to an approval
/// surface (SPEC §6.8, §10b; M2b-05). Carries every field of the
/// [`SignInStatement`]'s scope and envelope plus display metadata (`subject`,
/// `login_slug`, `target_slug`) so the client reconstructs the exact
/// [`SignInStatement`] and renders the receipt from the same validated
/// fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInPendingDescriptor {
    /// Request id (16 bytes as 32 lowercase hex characters).
    pub request: String,
    /// Daemon nonce (32 bytes as 64 lowercase hex characters).
    pub nonce: String,
    /// Creation time, Unix seconds.
    pub created_unix: u64,
    /// Pending expiry time, Unix seconds.
    pub expires_unix: u64,
    /// Reserved recipient-context id.
    pub context: u64,
    /// Caller subject summary for display.
    pub subject: SubjectSummary,
    /// SHA-256 of the caller's gathered evidence (64 hex chars).
    pub subject_evidence_sha256: String,
    /// Project canonical directory (UTF-8 lossy for display; exact bytes in `project_dir_hex`).
    pub project_dir: String,
    /// Project canonical directory bytes as lowercase hex.
    pub project_dir_hex: String,
    pub project_dev: u64,
    pub project_ino: u64,
    /// SHA-256 of the effective sign-in configuration (64 hex chars).
    pub project_config_sha256: String,
    /// Login item slug for display.
    pub login_slug: String,
    /// Login item id (ULID).
    pub login_item: String,
    pub authorization_revision: u64,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub role: String,
    /// `"test"` or `"live"`.
    pub environment: String,
    /// Target slug for display.
    pub target_slug: String,
    /// Target id (32 hex chars).
    pub target_id: String,
    pub target_revision: u64,
    /// Adapter id (32 hex chars).
    pub adapter_id: String,
    pub adapter_revision: u64,
    pub entry_origins: Vec<OriginSummary>,
    /// `"endpoint"` or `"element"`.
    pub check_kind: String,
    pub check_locator: String,
    pub cookies: Vec<CookieSummary>,
    pub storage: Vec<StorageSummary>,
    pub requester_pid: i32,
    pub requester_start_time: u64,
    pub browser_generation: u64,
    /// `"each"` or `"dev"`.
    pub tier: String,
    pub max_attempts: u8,
    pub approval_secs: u64,
    pub attempt_timeout_secs: u64,
    pub session_lifetime_secs: u64,
    /// Daemon instance (32 hex chars).
    pub daemon_instance: String,
    pub vault_epoch: u64,
    pub policy_epoch: u64,
}

impl SignInPendingDescriptor {
    /// Builds a descriptor from a [`SignInStatement`] and its display
    /// metadata.
    pub fn from_statement(
        stmt: &SignInStatement,
        subject: SubjectSummary,
        login_slug: String,
        target_slug: String,
    ) -> Self {
        let s = &stmt.scope;
        let p = s.project();
        let a = s.account();
        let t = s.target();
        let d = s.delivery();
        let l = s.limits();
        let e = s.epochs();
        SignInPendingDescriptor {
            request: stmt.request.to_string(),
            nonce: stmt.nonce.to_string(),
            created_unix: stmt.created_unix,
            expires_unix: stmt.expires_unix,
            context: stmt.context.get(),
            subject,
            subject_evidence_sha256: hex(&s.subject().evidence),
            project_dir: String::from_utf8_lossy(&p.dir).into_owned(),
            project_dir_hex: hex(&p.dir),
            project_dev: p.dev,
            project_ino: p.ino,
            project_config_sha256: hex(&p.config),
            login_slug,
            login_item: a.login_item.to_string(),
            authorization_revision: a.authorization_revision,
            account: a.account.as_str().to_owned(),
            tenant: a.tenant.as_ref().map(|x| x.as_str().to_owned()),
            role: a.role.as_str().to_owned(),
            environment: match a.environment {
                Environment::Test => "test".to_owned(),
                Environment::Live => "live".to_owned(),
            },
            target_slug,
            target_id: t.id.to_string(),
            target_revision: t.revision,
            adapter_id: t.adapter.to_string(),
            adapter_revision: t.adapter_revision,
            entry_origins: t
                .entry_origins
                .iter()
                .map(OriginSummary::from_origin)
                .collect(),
            check_kind: match t.identity_check.kind {
                CheckKind::Endpoint => "endpoint".to_owned(),
                CheckKind::Element => "element".to_owned(),
            },
            check_locator: t.identity_check.locator.as_str().to_owned(),
            cookies: t
                .transfer
                .cookies
                .iter()
                .map(CookieSummary::from_cookie)
                .collect(),
            storage: t
                .transfer
                .storage
                .iter()
                .map(StorageSummary::from_storage)
                .collect(),
            requester_pid: d.requester.pid,
            requester_start_time: d.requester.start_time,
            browser_generation: d.browser,
            tier: match l.tier() {
                Tier::Each => "each".to_owned(),
                Tier::Dev => "dev".to_owned(),
            },
            max_attempts: l.attempts(),
            approval_secs: l.approval().as_secs(),
            attempt_timeout_secs: l.attempt_timeout().as_secs(),
            session_lifetime_secs: l.session_lifetime().as_secs(),
            daemon_instance: e.daemon.to_string(),
            vault_epoch: e.vault,
            policy_epoch: e.policy,
        }
    }

    /// Reconstructs the validated [`SignInScope`] from this descriptor.
    pub fn to_scope(&self) -> Option<SignInScope> {
        let evidence = decode_hex::<32>(&self.subject_evidence_sha256)?;
        let dir = decode_hex_vec(&self.project_dir_hex)?;
        if self.project_dir != String::from_utf8_lossy(&dir) {
            return None;
        }
        let config = decode_hex::<32>(&self.project_config_sha256)?;
        let login_item = envcloak_policy::GrantId::parse(&self.login_item)
            .map(|g| ItemId::from_bytes(*g.as_bytes()))
            .or_else(|| decode_hex::<16>(&self.login_item).map(ItemId::from_bytes))?;
        let account = Label::new(&self.account).ok()?;
        let tenant = match &self.tenant {
            Some(t) => Some(Label::new(t).ok()?),
            None => None,
        };
        let role = Label::new(&self.role).ok()?;
        let environment = match self.environment.as_str() {
            "test" => Environment::Test,
            "live" => Environment::Live,
            _ => return None,
        };
        let target_id = TargetId::parse(&self.target_id)?;
        let adapter_id = AdapterId::parse(&self.adapter_id)?;
        let mut origins = Vec::with_capacity(self.entry_origins.len());
        for o in &self.entry_origins {
            origins.push(o.to_origin()?);
        }
        let entry_origins = SortedSet::new(origins).ok()?;
        let check_kind = match self.check_kind.as_str() {
            "endpoint" => CheckKind::Endpoint,
            "element" => CheckKind::Element,
            _ => return None,
        };
        let check_locator = Label::new(&self.check_locator).ok()?;
        let mut cookies = Vec::with_capacity(self.cookies.len());
        for c in &self.cookies {
            cookies.push(c.to_cookie()?);
        }
        let cookies = SortedSet::new(cookies).ok()?;
        let mut storage = Vec::with_capacity(self.storage.len());
        for s in &self.storage {
            storage.push(s.to_storage()?);
        }
        let storage = SortedSet::new(storage).ok()?;
        let tier = match self.tier.as_str() {
            "each" => Tier::Each,
            "dev" => Tier::Dev,
            _ => return None,
        };
        let limits = Limits::new(
            tier,
            self.max_attempts,
            Duration::from_secs(self.approval_secs),
            Duration::from_secs(self.attempt_timeout_secs),
            Duration::from_secs(self.session_lifetime_secs),
        )
        .ok()?;
        let daemon = DaemonInstance::parse(&self.daemon_instance)?;
        SignInScope::new(
             crate::scope::Subject {
                root: Instance {
                    pid: self.subject.root.pid,
                    start_time: self.subject.root.start_time,
                },
                evidence,
            },
            ProjectScope {
                dir,
                dev: self.project_dev,
                ino: self.project_ino,
                config,
            },
            Account {
                login_item,
                authorization_revision: self.authorization_revision,
                account,
                tenant,
                role,
                environment,
            },
            Target {
                id: target_id,
                revision: self.target_revision,
                adapter: adapter_id,
                adapter_revision: self.adapter_revision,
                entry_origins,
                identity_check: IdentityCheck {
                    kind: check_kind,
                    locator: check_locator,
                },
                transfer: TransferScope { cookies, storage },
            },
            Delivery {
                mode: DeliveryMode::BrowserSession,
                requester: Instance {
                    pid: self.requester_pid,
                    start_time: self.requester_start_time,
                },
                browser: self.browser_generation,
            },
            limits,
            Epochs {
                daemon,
                vault: self.vault_epoch,
                policy: self.policy_epoch,
            },
        )
        .ok()
    }

    /// Reconstructs the [`SignInStatement`] for `options`.
    pub fn to_statement(&self, options: Options) -> Option<SignInStatement> {
        let scope = self.to_scope()?;
        let request = RequestId::parse(&self.request)?;
        let nonce = Nonce::parse(&self.nonce)?;
        Some(SignInStatement {
            scope,
            request,
            nonce,
            created_unix: self.created_unix,
            expires_unix: self.expires_unix,
            options,
            context: ContextId::new(self.context),
        })
    }
}

fn decode_hex_vec(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?);
    }
    Some(out)
}

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

fn has_loopback_host(scope: &SignInScope) -> bool {
    let is_lb = |h: &Host| match h {
        Host::Name(n) => n.as_str() == "localhost" || n.as_str().ends_with(".localhost"),
        _ => h.is_loopback(),
    };
    scope.target().entry_origins.iter().any(|o| is_lb(o.host()))
        || scope.target().transfer.cookies.iter().any(|c| match &c.domain {
            CookieDomain::HostOnly(h) => is_lb(h),
            CookieDomain::Domain(n) => {
                n.as_str() == "localhost" || n.as_str().ends_with(".localhost")
            }
        })
        || scope
            .target()
            .transfer
            .storage
            .iter()
            .any(|s| is_lb(s.origin.host()))
}

/// Renders the human-facing sign-in receipt and computes the statement
/// digest over the reconstructed [`SignInStatement`] (SPEC §6.8, §10b;
/// R-M2b-01, R-M2b-14, R-M2b-30, R-M2b-48). Every string from the
/// descriptor goes through [`escape_for_display`].
pub fn render_signin_statement(
    d: &SignInPendingDescriptor,
    options: Option<Options>,
) -> Option<(String, Options, [u8; 32])> {
    let scope = d.to_scope()?;
    let chosen = options.unwrap_or_else(|| Options::default_for(scope.limits()));
    let stmt = d.to_statement(chosen)?;
    let digest = stmt.digest();
    let e = escape_for_display;
    let mut t = String::with_capacity(1024);
    let _ = writeln!(t, "Sign-in approval request {}", e(&d.request));
    let who = match (&d.subject.kind, &d.subject.label) {
        (SubjectKind::Agent, Some(l)) => format!("agent {} ", e(l)),
        (SubjectKind::Agent, None) => "an agent ".to_owned(),
        (SubjectKind::Terminal, _) => "a terminal session ".to_owned(),
        (SubjectKind::Unknown, _) => "a process of unknown origin ".to_owned(),
    };
    let _ = writeln!(
        t,
        "  requested by: {who}(caller pid {}), rooted at pid {} started at {}{}",
        d.subject.caller_pid,
        d.subject.root.pid,
        d.subject.root.start_time,
        d.subject
            .root
            .exe
            .as_deref()
            .map(|x| format!(", {}", e(x)))
            .unwrap_or_default()
    );
    let _ = writeln!(
        t,
        "  project: {} (config sha256 {})",
        e(&d.project_dir),
        e(&d.project_config_sha256)
    );
    let _ = writeln!(
        t,
        "  target: {} (id {}, revision {}, adapter {} revision {})",
        e(&d.target_slug),
        e(&d.target_id),
        d.target_revision,
        e(&d.adapter_id),
        d.adapter_revision
    );
    let _ = writeln!(
        t,
        "  account: {} (login item {}, id {}, revision {}, {} identity)",
        e(scope.account().account.as_str()),
        e(&d.login_slug),
        scope.account().login_item,
        scope.account().authorization_revision,
        match scope.account().environment {
            Environment::Test => "test",
            Environment::Live => "live",
        }
    );
    let _ = writeln!(
        t,
        "  tenant: {}",
        scope
            .account()
            .tenant
            .as_ref()
            .map_or_else(|| "none".to_owned(), |x| e(x.as_str()))
    );
    let _ = writeln!(t, "  role: {}", e(scope.account().role.as_str()));
    let _ = writeln!(
        t,
        "  browser: browser_session_delivery to recipient pid {} started at {}, browser generation {}, reserved context {}",
        scope.delivery().requester.pid,
        scope.delivery().requester.start_time,
        scope.delivery().browser,
        stmt.context.get()
    );
    let origins: Vec<String> = scope
        .target()
        .entry_origins
        .iter()
        .map(|o| e(&o.to_string()))
        .collect();
    let _ = writeln!(t, "  credential-entry origins: {}", origins.join(", "));
    let _ = writeln!(
        t,
        "  identity check: {} {} (only after the account, tenant and role are verified in the receiving context)",
        match scope.target().identity_check.kind {
            CheckKind::Endpoint => "endpoint",
            CheckKind::Element => "element",
        },
        e(scope.target().identity_check.locator.as_str())
    );
    let _ = writeln!(t, "  delivery allows:");
    if scope.target().transfer.cookies.is_empty() {
        let _ = writeln!(t, "    cookies: none");
    } else {
        for c in scope.target().transfer.cookies.iter() {
            let dom = match &c.domain {
                CookieDomain::HostOnly(h) => format!("host-only {}", e(&h.to_string())),
                CookieDomain::Domain(n) => format!("domain .{}", e(n.as_str())),
            };
            let part = match &c.partition {
                CookiePartition::Unpartitioned => "unpartitioned".to_owned(),
                CookiePartition::Partitioned {
                    site,
                    cross_site_ancestor,
                } => format!(
                    "partitioned {}://{} (cross_site_ancestor={cross_site_ancestor})",
                    site.scheme.as_str(),
                    e(&site.host.to_string())
                ),
            };
            let _ = writeln!(
                t,
                "    cookie {} ({dom}, path {}, {part})",
                e(c.name.as_str()),
                e(c.path.as_str())
            );
        }
    }
    if scope.target().transfer.storage.is_empty() {
        let _ = writeln!(t, "    local storage: none");
    } else {
        for s in scope.target().transfer.storage.iter() {
            let _ = writeln!(
                t,
                "    local storage {} key {}",
                e(&s.origin.to_string()),
                e(s.key.as_str())
            );
        }
    }
    let _ = writeln!(
        t,
        "    Delivered to this agent's browser only after the account, tenant and role are verified in the receiving context. The browser can use and export the session."
    );
    if has_loopback_host(&scope) {
        let _ = writeln!(
            t,
            "    Cookies are scoped by host/domain and path, not by port: cookies for this hostname can also reach services on its other ports, including by background requests."
        );
    }
    match chosen {
        Options::Once => {
            let _ = writeln!(
                t,
                "  attempt budget: once, 1 authentication attempt (at most 1 password submission and 2 one-time codes)"
            );
            let _ = writeln!(
                t,
                "  lifetimes: approval window {}, per-attempt timeout {}, broker-managed session lifetime {}",
                duration_words(scope.limits().approval().as_secs()),
                duration_words(scope.limits().attempt_timeout().as_secs()),
                duration_words(scope.limits().session_lifetime().as_secs())
            );
        }
        Options::Dev { window, attempts } => {
            let _ = writeln!(
                t,
                "  attempt budget: dev, {attempts} authentication attempt(s) within {} (each attempt: at most 1 password submission and 2 one-time codes)",
                duration_words(window.as_secs())
            );
            let _ = writeln!(
                t,
                "  lifetimes: approval window {}, per-attempt timeout {}, broker-managed session lifetime {}",
                duration_words(window.as_secs()),
                duration_words(scope.limits().attempt_timeout().as_secs()),
                duration_words(scope.limits().session_lifetime().as_secs())
            );
        }
    }
    let _ = writeln!(
        t,
        "  teardown: ending EnvCloak access clears this browser; server session expiry: unknown; server revocation: unknown"
    );
    t.push_str("The passphrase you enter approves exactly this, and nothing else.\n");
    Some((t, chosen, digest))
}
