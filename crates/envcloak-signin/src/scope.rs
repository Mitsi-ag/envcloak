//! The sign-in scope (SPEC §6.8 "Sign-in scope"; R-M2b-11, R-M2b-12): what
//! one sign-in request asks for, resolved by the daemon before any pending
//! state exists, and never changed afterwards.
//!
//! A [`SignInScope`] holds the subject (its verified root instance and a
//! digest of its evidence), the project (canonical directory, device and
//! inode, and a digest of the effective sign-in configuration), the
//! account (login item id and authorization revision; expected account,
//! tenant and exact role; test or live), the target and adapter (ids and
//! revisions, the parsed credential-entry origins, the identity check and
//! the transfer scope), the delivery (`browser_session_delivery`, the
//! requesting process instance that is to receive the browser tools, and
//! the recipient browser instance's generation), the limits (attempt kind
//! and count, approval duration, per-attempt timeout, maximum session
//! lifetime) and the daemon, vault and policy epochs.
//!
//! **No secret in it.** Every leaf is one of this crate's plain value
//! types (ids, numbers, digests, ASCII hosts and validated labels), and the
//! scope derives `Clone`, `Eq`, `Ord` and `Hash`, none of which
//! `secrecy`'s wrappers or `envcloak_core::SecretBytes` implement, so no
//! field can hold one; no credential is hashed into it either (the
//! evidence and configuration digests are of metadata).
//!
//! **Encoding** ([`SignInScope::encode`]), which docs/GRANTS.md "Sign-in
//! scope and statement" sets out byte for byte: the line
//! `envcloak-signin-scope/1\n`, then each field as a 2-byte big-endian
//! field number, a 4-byte big-endian length and its value, in field-number
//! order. Values are typed, never display text or JSON: integers as
//! fixed-width big-endian, ids and digests as their bytes, enumerations as
//! one byte, and composite values as length-prefixed parts. A set is a
//! 4-byte count, then each element length-prefixed, in ascending order of
//! the element's bytes; a set given with a duplicate is refused
//! ([`ScopeError::Duplicate`]), so the order a caller lists things in
//! never changes the encoding. [`SignInScope::fingerprint`] is SHA-256 of
//! the encoding: the lookup key for retries (SPEC §6.8 "Retries"), which
//! the statement's nonce and reserved recipient context are not part of
//! (SI-07).

use std::fmt;
use std::time::Duration;

use envcloak_core::vault::ItemId;
use envcloak_policy::{ProcessInstance, ProjectIdentity, display_escaped};
use sha2::{Digest, Sha256};

/// The first line of every scope encoding.
pub const SCOPE_DOMAIN: &[u8] = b"envcloak-signin-scope/1\n";
/// The longest label (an account, tenant, role, cookie name, storage key
/// or identity-check locator), in bytes.
pub const MAX_LABEL: usize = 256;
/// The longest host name, in bytes (RFC 1035).
pub const MAX_HOST: usize = 253;
/// The most elements in one set.
pub const MAX_SET: usize = 64;
/// The longest approval window (SPEC §6.8 `dev`: "up to 24 hours").
pub const MAX_APPROVAL: Duration = Duration::from_secs(24 * 3600);
/// The longest per-attempt timeout.
pub const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3600);
/// The longest session EnvCloak manages after delivery.
pub const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// The most attempts one `dev` authorization may hold (plan M2b-01).
pub const MAX_DEV_ATTEMPTS: u8 = 5;

/// Why a scope part was refused. Fixed and value-free: never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeError {
    /// An empty label.
    EmptyLabel,
    /// A label over [`MAX_LABEL`] bytes.
    LabelTooLong,
    /// A label with a control, invisible or direction-changing character.
    LabelCharacter,
    /// A host name that is not lowercase ASCII letters, digits and `-` in
    /// dot-separated labels of 1 to 63 bytes, or whose last label the URL
    /// standard reads as a number (all digits, or `0x` and hex digits: an
    /// address written as a name).
    Host,
    /// `http` for a host other than `127.0.0.1`, `::1` or a `*.localhost`
    /// name.
    Scheme,
    /// Port 0.
    Port,
    /// A set given with the same element twice.
    Duplicate,
    /// A set over [`MAX_SET`] elements.
    TooMany,
    /// A target without a credential-entry origin.
    NoOrigin,
    /// A duration that is zero, not whole seconds, or over its maximum.
    Duration,
    /// An attempt count outside its tier's range: exactly 1 for `each`,
    /// 1 to [`MAX_DEV_ATTEMPTS`] for `dev`.
    Attempts,
    /// A `dev` tier for a live identity (SPEC §6.8: `dev` is for test
    /// identities only).
    LiveDev,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScopeError::EmptyLabel => "empty label",
            ScopeError::LabelTooLong => "label too long",
            ScopeError::LabelCharacter => "label with a control or invisible character",
            ScopeError::Host => "host not in the registered form",
            ScopeError::Scheme => "http only for a loopback host",
            ScopeError::Port => "port 0",
            ScopeError::Duplicate => "a set holds an element twice",
            ScopeError::TooMany => "a set holds too many elements",
            ScopeError::NoOrigin => "no credential-entry origin",
            ScopeError::Duration => "a duration out of range",
            ScopeError::Attempts => "an attempt count out of range",
            ScopeError::LiveDev => "dev tier for a live identity",
        })
    }
}

impl std::error::Error for ScopeError {}

/// A process instance: its pid and the kernel's start time
/// (`envcloak_sys::StartTime::raw`), which together name one process for
/// its life. An identification, never a code identity (plan D-31, D-36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instance {
    pub pid: i32,
    pub start_time: u64,
}

impl From<&ProcessInstance> for Instance {
    fn from(p: &ProcessInstance) -> Self {
        Instance {
            pid: p.pid,
            start_time: p.start_time.raw(),
        }
    }
}

macro_rules! id16 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(b: [u8; 16]) -> Self {
                $name(b)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

id16!(
    /// The daemon instance: 16 random bytes drawn when the daemon starts.
    /// A daemon restart ends every grant and every retry (SPEC §6.8).
    DaemonInstance
);
id16!(
    /// A registered sign-in target.
    TargetId
);
id16!(
    /// A target's adapter: its login form or its test-session endpoint.
    AdapterId
);

/// The epochs a scope was resolved in (SPEC §10b): the daemon instance,
/// the vault epoch and the policy epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epochs {
    pub daemon: DaemonInstance,
    pub vault: u64,
    pub policy: u64,
}

/// SHA-256 of a scope's encoding: the retry lookup key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", hex(&self.0))
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Cannot fail: writing to a String.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Text that names something: an account, a tenant, a role, a cookie
/// name, a storage key, an identity-check locator. 1 to [`MAX_LABEL`]
/// bytes of UTF-8 with no character a terminal would act on or hide
/// (`envcloak_policy::display_escaped`), compared byte for byte: a role
/// has no ordering and no case folding (SPEC §10b). It holds what a
/// registration or an agent's request gave, so its `Debug` shows only its
/// length (L-12).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({} bytes)", self.0.len())
    }
}

impl Label {
    pub fn new(s: &str) -> Result<Self, ScopeError> {
        if s.is_empty() {
            return Err(ScopeError::EmptyLabel);
        }
        if s.len() > MAX_LABEL {
            return Err(ScopeError::LabelTooLong);
        }
        if s.chars().any(display_escaped) {
            return Err(ScopeError::LabelCharacter);
        }
        Ok(Label(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A host name in the form the browser serializes it (plan D-26), checked
/// by [`HostName::new`], the only way to make one: so a [`Host`], an
/// [`Origin`] or a declared cookie never holds a name that was not
/// checked. Its `Debug` shows only its length (L-12).
///
/// ```
/// use envcloak_signin::{Host, HostName, Origin, Scheme};
/// let name = HostName::new("app.localhost").unwrap();
/// let host = Host::Name(name);
/// assert!(Origin::new(Scheme::Http, host, 3000).is_ok());
/// assert!(HostName::new("App.localhost").is_err());
/// ```
///
/// Nothing else makes one: not the tuple constructor,
///
/// ```compile_fail
/// let _ = envcloak_signin::HostName(String::from("App.localhost"));
/// ```
///
/// not a [`Host`] from a string,
///
/// ```compile_fail
/// let _ = envcloak_signin::Host::Name(String::from("App.localhost"));
/// ```
///
/// and not an [`Origin`] built field by field.
///
/// ```compile_fail
/// use envcloak_signin::{Host, Origin, Scheme};
/// let _ = Origin { scheme: Scheme::Http, host: Host::V4([10, 0, 0, 1]), port: 0 };
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// A host name: dot-separated labels of 1 to 63 bytes, each of
    /// lowercase ASCII letters, digits and `-`, not starting or ending
    /// with `-`; at most [`MAX_HOST`] bytes; no trailing dot; and a last
    /// label that the URL standard does not read as a number (all digits,
    /// or `0x` and hex digits: "ends in a number", where the browser parses
    /// the host as an IPv4 address and refuses the URL), so an address is
    /// never read as a name and every name is one the browser serializes
    /// as itself.
    pub fn new(s: &str) -> Result<Self, ScopeError> {
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        let number = |l: &str| {
            l.bytes().all(|b| b.is_ascii_digit())
                || l.strip_prefix("0x")
                    .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
        };
        let ok = !s.is_empty()
            && s.len() <= MAX_HOST
            && s.split('.').all(label_ok)
            && !s.rsplit('.').next().is_some_and(number);
        if ok {
            Ok(HostName(s.to_owned()))
        } else {
            Err(ScopeError::Host)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostName({} bytes)", self.0.len())
    }
}

/// A host as the browser serializes it (plan D-26): a checked
/// [`HostName`] (lowercase ASCII, a punycode A-label written as it is),
/// or an IP address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    Name(HostName),
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Host {
    /// A host name, checked by [`HostName::new`].
    pub fn name(s: &str) -> Result<Self, ScopeError> {
        HostName::new(s).map(Host::Name)
    }

    /// Whether `http` may be registered for it (SPEC §6.8): `127.0.0.1`,
    /// `::1` or a name under `localhost`.
    pub fn is_loopback(&self) -> bool {
        match self {
            Host::V4(a) => *a == [127, 0, 0, 1],
            Host::V6(a) => *a == std::net::Ipv6Addr::LOCALHOST.octets(),
            Host::Name(n) => n.0.ends_with(".localhost"),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Host::Name(n) => {
                lp(out, &[1]);
                lp(out, n.0.as_bytes());
            }
            Host::V4(a) => {
                lp(out, &[4]);
                lp(out, a);
            }
            Host::V6(a) => {
                lp(out, &[6]);
                lp(out, a);
            }
        }
    }
}

/// An origin's scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    Http,
    Https,
}

/// An exact origin (plan D-26): scheme, host and port, compared byte for
/// byte. `http` only for a loopback host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    scheme: Scheme,
    host: Host,
    port: u16,
}

impl Origin {
    pub fn new(scheme: Scheme, host: Host, port: u16) -> Result<Self, ScopeError> {
        if port == 0 {
            return Err(ScopeError::Port);
        }
        if scheme == Scheme::Http && !host.is_loopback() {
            return Err(ScopeError::Scheme);
        }
        Ok(Origin { scheme, host, port })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A value that can be an element of a [`SortedSet`]: it has one byte
/// encoding, which orders the set and tells duplicates apart.
pub trait Element: Clone {
    #[doc(hidden)]
    fn element(&self, out: &mut Vec<u8>);
}

impl Element for Origin {
    fn element(&self, out: &mut Vec<u8>) {
        lp(
            out,
            &[match self.scheme {
                Scheme::Http => 1,
                Scheme::Https => 2,
            }],
        );
        let mut h = Vec::new();
        self.host.encode(&mut h);
        lp(out, &h);
        lp(out, &self.port.to_be_bytes());
    }
}

/// A cookie the target declares for transfer: its host and name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclaredCookie {
    pub host: Host,
    pub name: Label,
}

impl Element for DeclaredCookie {
    fn element(&self, out: &mut Vec<u8>) {
        let mut h = Vec::new();
        self.host.encode(&mut h);
        lp(out, &h);
        lp(out, self.name.as_str().as_bytes());
    }
}

/// A storage key the target declares for transfer: its origin and key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclaredStorage {
    pub origin: Origin,
    pub key: Label,
}

impl Element for DeclaredStorage {
    fn element(&self, out: &mut Vec<u8>) {
        let mut o = Vec::new();
        self.origin.element(&mut o);
        lp(out, &o);
        lp(out, self.key.as_str().as_bytes());
    }
}

/// A set: sorted by each element's encoding, without duplicates, at most
/// [`MAX_SET`] elements.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedSet<T>(Vec<T>);

impl<T: Element> SortedSet<T> {
    /// The set of `items`, in whatever order they come; a duplicate is
    /// refused, never dropped.
    pub fn new(items: Vec<T>) -> Result<Self, ScopeError> {
        if items.len() > MAX_SET {
            return Err(ScopeError::TooMany);
        }
        let mut keyed: Vec<(Vec<u8>, T)> = items
            .into_iter()
            .map(|t| {
                let mut b = Vec::new();
                t.element(&mut b);
                (b, t)
            })
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(ScopeError::Duplicate);
        }
        Ok(SortedSet(keyed.into_iter().map(|(_, t)| t).collect()))
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&count(self.0.len()).to_be_bytes());
        for t in &self.0 {
            let mut b = Vec::new();
            t.element(&mut b);
            lp(&mut out, &b);
        }
        out
    }
}

/// The subject: the verified root process instance the grant would be
/// rooted at (the owner of the operation), and SHA-256 of the evidence the
/// daemon gathered for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject {
    pub root: Instance,
    pub evidence: [u8; 32],
}

/// The project: its canonical directory (bytes), the directory's device
/// and inode, and SHA-256 of the effective sign-in configuration. Its
/// `Debug` shows the directory's length, never the path (L-12).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectScope {
    pub dir: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
    pub config: [u8; 32],
}

impl fmt::Debug for ProjectScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectScope")
            .field("dir", &format_args!("{} bytes", self.dir.len()))
            .field("dev", &self.dev)
            .field("ino", &self.ino)
            .field("config", &format_args!("{}", hex(&self.config)))
            .finish()
    }
}

impl ProjectScope {
    /// The project as `envcloak_policy::project_identity` opened it.
    pub fn new(identity: &ProjectIdentity, config: [u8; 32]) -> Self {
        use std::os::unix::ffi::OsStrExt as _;
        ProjectScope {
            dir: identity.canonical_dir.as_os_str().as_bytes().to_vec(),
            dev: identity.dev,
            ino: identity.ino,
            config,
        }
    }
}

/// Whether the login is a test identity or a live one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Environment {
    Test,
    Live,
}

/// The account: the login item and its authorization revision (which
/// changes when the password or TOTP enrollment is replaced, or when the
/// origins, identity check, account, tenant or role mapping, transfer
/// scope or adapter behaviour change), and the exact identity expected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Account {
    pub login_item: ItemId,
    pub authorization_revision: u64,
    pub account: Label,
    pub tenant: Option<Label>,
    pub role: Label,
    pub environment: Environment,
}

/// How the identity check finds the signed-in identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckKind {
    /// An app endpoint that names the account, tenant and role.
    Endpoint,
    /// A page element that names them.
    Element,
}

/// The target's declared identity check (SPEC §6.8 "Identity check").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityCheck {
    pub kind: CheckKind,
    pub locator: Label,
}

/// The declared state that may move into the recipient context (SPEC
/// §6.8 "Delivery"): cookies and storage keys, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferScope {
    pub cookies: SortedSet<DeclaredCookie>,
    pub storage: SortedSet<DeclaredStorage>,
}

/// The target and its adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target {
    pub id: TargetId,
    pub revision: u64,
    pub adapter: AdapterId,
    pub adapter_revision: u64,
    pub entry_origins: SortedSet<Origin>,
    pub identity_check: IdentityCheck,
    pub transfer: TransferScope,
}

/// How the session is delivered: into a fresh recipient context served
/// by EnvCloak's browser tools (the only mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliveryMode {
    BrowserSession,
}

/// The delivery: the mode, the requesting process instance that is to
/// receive the browser tools (plan D-31: an `envcloak mcp` instance, so a
/// sibling instance in the same root has a different scope), and the
/// generation of the managed browser instance, which a replacement
/// changes even if its name stays (SI-07).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delivery {
    pub mode: DeliveryMode,
    pub requester: Instance,
    pub browser: u64,
}

/// The approval tier (SPEC §6.8 "Approval"). `never-agent` targets never
/// get a scope: the daemon refuses them before resolving one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// One proof per sign-in.
    Each,
    /// One proof opens a bounded window of attempts.
    Dev,
}

/// The limits the request carries: the tier and its attempt count, the
/// longest approval window, the per-attempt timeout and the longest
/// session EnvCloak manages after delivery. Whole seconds. The daemon
/// resolves the approval window already clamped by the subject's limits
/// (SPEC §10b "Lifetimes": 24 hours for a known agent root, 12 for a
/// terminal or unknown one); root exit, lock and the epochs end an
/// authorization before it, in the operation store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Limits {
    tier: Tier,
    attempts: u8,
    approval: Duration,
    attempt_timeout: Duration,
    session_lifetime: Duration,
}

fn whole(d: Duration, max: Duration) -> Result<Duration, ScopeError> {
    if d.is_zero() || d.subsec_nanos() != 0 || d > max {
        Err(ScopeError::Duration)
    } else {
        Ok(d)
    }
}

impl Limits {
    pub fn new(
        tier: Tier,
        attempts: u8,
        approval: Duration,
        attempt_timeout: Duration,
        session_lifetime: Duration,
    ) -> Result<Self, ScopeError> {
        let attempts_ok = match tier {
            Tier::Each => attempts == 1,
            Tier::Dev => (1..=MAX_DEV_ATTEMPTS).contains(&attempts),
        };
        if !attempts_ok {
            return Err(ScopeError::Attempts);
        }
        Ok(Limits {
            tier,
            attempts,
            approval: whole(approval, MAX_APPROVAL)?,
            attempt_timeout: whole(attempt_timeout, MAX_ATTEMPT_TIMEOUT)?,
            session_lifetime: whole(session_lifetime, MAX_SESSION_LIFETIME)?,
        })
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn approval(&self) -> Duration {
        self.approval
    }

    pub fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }

    pub fn session_lifetime(&self) -> Duration {
        self.session_lifetime
    }
}

/// One immutable sign-in scope. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignInScope {
    subject: Subject,
    project: ProjectScope,
    account: Account,
    target: Target,
    delivery: Delivery,
    limits: Limits,
    epochs: Epochs,
}

impl SignInScope {
    /// A scope from its parts. Refused: a target with no credential-entry
    /// origin, and the `dev` tier for a live identity.
    pub fn new(
        subject: Subject,
        project: ProjectScope,
        account: Account,
        target: Target,
        delivery: Delivery,
        limits: Limits,
        epochs: Epochs,
    ) -> Result<Self, ScopeError> {
        if target.entry_origins.is_empty() {
            return Err(ScopeError::NoOrigin);
        }
        if limits.tier == Tier::Dev && account.environment == Environment::Live {
            return Err(ScopeError::LiveDev);
        }
        Ok(SignInScope {
            subject,
            project,
            account,
            target,
            delivery,
            limits,
            epochs,
        })
    }

    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn delivery(&self) -> &Delivery {
        &self.delivery
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn epochs(&self) -> &Epochs {
        &self.epochs
    }

    /// The operation's owner: the subject's root instance (SPEC §6.8
    /// "Retries": lookups, status and cancel are within the owner root).
    pub fn owner(&self) -> Instance {
        self.subject.root
    }

    /// The canonical encoding. See the module documentation.
    pub fn encode(&self) -> Vec<u8> {
        // Every field is named here, so a field added to a part and not
        // encoded does not compile.
        let SignInScope {
            subject: Subject { root, evidence },
            project:
                ProjectScope {
                    dir,
                    dev,
                    ino,
                    config,
                },
            account:
                Account {
                    login_item,
                    authorization_revision,
                    account,
                    tenant,
                    role,
                    environment,
                },
            target:
                Target {
                    id,
                    revision,
                    adapter,
                    adapter_revision,
                    entry_origins,
                    identity_check: IdentityCheck { kind, locator },
                    transfer: TransferScope { cookies, storage },
                },
            delivery:
                Delivery {
                    mode,
                    requester,
                    browser,
                },
            limits:
                Limits {
                    tier,
                    attempts,
                    approval,
                    attempt_timeout,
                    session_lifetime,
                },
            epochs:
                Epochs {
                    daemon,
                    vault,
                    policy,
                },
        } = self;
        let mut e = Fields::new(SCOPE_DOMAIN);
        e.field(1, &instance(root));
        e.field(2, evidence);
        e.field(3, dir);
        e.field(4, &dev.to_be_bytes());
        e.field(5, &ino.to_be_bytes());
        e.field(6, config);
        e.field(7, login_item.as_bytes());
        e.field(8, &authorization_revision.to_be_bytes());
        e.field(9, account.as_str().as_bytes());
        e.field(
            10,
            &optional(tenant.as_ref().map(|t| t.as_str().as_bytes())),
        );
        e.field(11, role.as_str().as_bytes());
        e.field(
            12,
            &[match environment {
                Environment::Test => 1,
                Environment::Live => 2,
            }],
        );
        e.field(13, id.as_bytes());
        e.field(14, &revision.to_be_bytes());
        e.field(15, adapter.as_bytes());
        e.field(16, &adapter_revision.to_be_bytes());
        e.field(17, &entry_origins.encode());
        let mut check = Vec::new();
        lp(
            &mut check,
            &[match kind {
                CheckKind::Endpoint => 1,
                CheckKind::Element => 2,
            }],
        );
        lp(&mut check, locator.as_str().as_bytes());
        e.field(18, &check);
        e.field(19, &cookies.encode());
        e.field(20, &storage.encode());
        e.field(
            21,
            &[match mode {
                DeliveryMode::BrowserSession => 1,
            }],
        );
        e.field(22, &instance(requester));
        e.field(23, &browser.to_be_bytes());
        e.field(
            24,
            &[match tier {
                Tier::Each => 1,
                Tier::Dev => 2,
            }],
        );
        e.field(25, &[*attempts]);
        e.field(26, &approval.as_secs().to_be_bytes());
        e.field(27, &attempt_timeout.as_secs().to_be_bytes());
        e.field(28, &session_lifetime.as_secs().to_be_bytes());
        e.field(29, daemon.as_bytes());
        e.field(30, &vault.to_be_bytes());
        e.field(31, &policy.to_be_bytes());
        e.0
    }

    /// SHA-256 of [`SignInScope::encode`].
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(Sha256::digest(self.encode()).into())
    }
}

/// An instance: the pid as a 4-byte big-endian two's complement number,
/// then the start time as 8 bytes.
fn instance(i: &Instance) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&i.pid.to_be_bytes());
    v.extend_from_slice(&i.start_time.to_be_bytes());
    v
}

/// An optional value: `0`, or `1` and the value.
fn optional(v: Option<&[u8]>) -> Vec<u8> {
    match v {
        None => vec![0],
        Some(b) => {
            let mut out = Vec::with_capacity(b.len() + 1);
            out.push(1);
            out.extend_from_slice(b);
            out
        }
    }
}

/// A length that fits in 4 bytes: every value is bounded far below it.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Appends `bytes` with its 4-byte big-endian length.
pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&count(bytes.len()).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A domain line, then numbered, length-prefixed fields.
pub(crate) struct Fields(pub(crate) Vec<u8>);

impl Fields {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut v = Vec::with_capacity(512);
        v.extend_from_slice(domain);
        Fields(v)
    }

    pub(crate) fn field(&mut self, number: u16, value: &[u8]) {
        self.0.extend_from_slice(&number.to_be_bytes());
        lp(&mut self.0, value);
    }
}
