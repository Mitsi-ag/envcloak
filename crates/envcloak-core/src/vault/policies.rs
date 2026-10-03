//! Typed, versioned policy records (plan decision D-08, task M2-07): what
//! `policies.sealed` holds from schema version 2 on.
//!
//! Every record is `kind(1) version(1)` and then the body of that kind's
//! version. Three kinds exist, each at version 1 (docs/VAULT.md "Policy
//! records"): a standing approval (D-10, M2-15), a sign-in target (M2b-05)
//! and a managed MCP server with its registered launch or bridged origin
//! (D-05, D-33, M2-27). A later change to one of them is a new version of
//! that record, read beside the old one, never a schema migration. A kind
//! or a version this build does not know, a record that does not decode
//! whole, or one that breaks its kind's bounds is refused like tampering
//! (the row is not served and the vault opens read-only), never read as
//! an empty or default record: a policy row that loosened a decision when
//! it could not be read would be a way around it.
//!
//! The set of standing approvals carries a generation and a digest of the
//! set, [`StandingSetHeader`], in the sealed header: every transaction
//! that adds, changes or removes a standing approval moves the generation
//! by one and recomputes the digest, and unlock recomputes the digest from
//! the rows and refuses a header that does not match it. M2-15 compares
//! both with the policy-epoch sidecar outside the vault (D-10's
//! selective-revoke transaction).

use std::collections::BTreeMap;

use crate::crypto::{Keyring, Purpose, keyed_hash};

use super::codec::{Dec, Enc};
use super::error::{VaultError, VaultErrorKind};
use super::items::{FieldId, ItemId, LoginTier, PolicyId};

/// The kind of a policy record: its first byte. Part of the vault format
/// (docs/VAULT.md "Reserved for M2 and M2b"): never renumber or reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PolicyKind {
    StandingApproval = 1,
    /// A [`SignInTarget`] (named as docs/VAULT.md reserves it).
    SigninTarget = 2,
    ManagedServer = 3,
}

impl PolicyKind {
    /// The record version this build writes for each kind.
    fn version(self) -> u8 {
        match self {
            PolicyKind::StandingApproval | PolicyKind::SigninTarget | PolicyKind::ManagedServer => {
                1
            }
        }
    }
}

/// The longest text a policy record holds in one field, in bytes.
pub const MAX_TEXT: usize = 4096;
/// The most entries one list of a policy record holds.
pub const MAX_LIST: usize = 256;
/// The most executable digests a Linux standing approval keeps (M2-15: a
/// later proven approval adds one, and a full set is refused, never
/// evicted).
pub const MAX_DIGESTS: usize = 4;
/// The longest signature the reserved slot holds, in bytes.
pub const MAX_SIGNATURE: usize = 1024;

/// A policy record (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRecord {
    StandingApproval(StandingApproval),
    SignInTarget(SignInTarget),
    ManagedServer(ManagedServer),
}

/// How a standing approval was proven. Part of the record: never
/// renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProofKind {
    /// A passphrase from a terminal subject.
    Passphrase = 1,
}

/// The code identity a standing approval is keyed to (D-10, L-14): never
/// a path or a name a program can copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeIdentity {
    /// macOS: the code signature's Team ID and signing identifier.
    MacSignature { team: String, identifier: String },
    /// Linux: the SHA-256 of the executable, read through a descriptor
    /// (D-09); 1 to [`MAX_DIGESTS`] of them.
    LinuxSha256 { digests: Vec<[u8; 32]> },
}

/// A project directory as the daemon identified it: its canonical path
/// (bytes, as the file system names it), device and inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectIdentity {
    pub canonical_dir: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
}

/// A registered launch and its revision, which a standing approval for a
/// managed project is bound to (D-33, CR-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LaunchRef {
    pub launch_id: [u8; 16],
    pub revision: u64,
}

/// One binding a standing approval covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingBinding {
    pub env_name: String,
    pub item: ItemId,
    pub field: FieldId,
}

/// A standing approval (D-10; the fields M2-15 lists), version 1. Its id
/// is the policy row's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingApproval {
    /// The agent catalog id of the agent it was created for.
    pub agent_id: String,
    pub code_identity: CodeIdentity,
    pub project: ProjectIdentity,
    /// For a managed project: the registered launch and revision.
    pub launch: Option<LaunchRef>,
    /// 1 to [`MAX_LIST`] bindings.
    pub bindings: Vec<StandingBinding>,
    /// Unix seconds.
    pub created: u64,
    /// Unix seconds, after `created`.
    pub not_after: u64,
    pub proof_kind: ProofKind,
    /// Reserved for the signature M5 adds before records are replicated;
    /// `None` in M2.
    pub signature: Option<Vec<u8>>,
}

/// What the identity check of a sign-in target reads (SPEC §6.8 "Identity
/// check"). Part of the record: never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdentityCheckKind {
    /// An app endpoint.
    Endpoint = 1,
    /// A page element.
    Element = 2,
}

/// A sign-in target's identity check and the account, tenant and role it
/// must name. Its `Debug` shows the kind and the texts' lengths only.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityCheck {
    pub kind: IdentityCheckKind,
    /// The endpoint's path or the element's selector.
    pub locator: String,
    pub account: String,
    pub tenant: Option<String>,
    pub role: String,
}

/// One cookie a target's session moves as (SPEC §6.8 "Delivery").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieScope {
    pub name: String,
    pub domain: String,
    pub path: String,
}

/// One storage key a target's session moves as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageScope {
    pub origin: String,
    pub key: String,
}

/// The form a target's session takes. Part of the record: never
/// renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionFormat {
    Cookies = 1,
    Storage = 2,
    CookiesAndStorage = 3,
}

/// What a target's delivery moves, and nothing else. Its `Debug` shows
/// how many cookies and storage keys, and the format.
#[derive(Clone, PartialEq, Eq)]
pub struct TransferScope {
    pub cookies: Vec<CookieScope>,
    pub storage: Vec<StorageScope>,
    pub format: SessionFormat,
}

/// A test-session adapter's id and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRef {
    pub id: String,
    pub version: String,
}

/// A sign-in target (SPEC §6.8; M2b-05 registers and checks them), record
/// version 1. Origins are kept as the person registered them, in ASCII;
/// M2b-05's parser (D-26) decides what is accepted. Its `Debug` shows its
/// name, ids, numbers and how many of each list, never a text the person
/// registered (L-12).
#[derive(Clone, PartialEq, Eq)]
pub struct SignInTarget {
    /// The name requests use for it.
    pub name: String,
    /// The login item it signs in with.
    pub login: ItemId,
    /// The authorization revision: moved by every edit (R-M2b-17).
    pub revision: u64,
    /// 1 to [`MAX_LIST`] origins.
    pub app_origins: Vec<String>,
    /// 1 to [`MAX_LIST`] origins.
    pub credential_origins: Vec<String>,
    pub identity_provider_origins: Vec<String>,
    pub callback_origins: Vec<String>,
    pub identity_check: IdentityCheck,
    pub transfer: TransferScope,
    pub tier: LoginTier,
    pub adapter: Option<AdapterRef>,
    /// The longest a `dev` authorization lasts, in seconds.
    pub approval_lifetime: u64,
    /// The longest a session it signs in may be kept, in seconds.
    pub session_lifetime: u64,
    /// The app's revocation call, when it declares one.
    pub revocation: Option<String>,
}

/// Who registered a managed server, as the daemon classed the caller.
/// Part of the record: never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SubjectKindRecord {
    Terminal = 1,
    Agent = 2,
    Unknown = 3,
}

/// A registered launch's class (D-33). Part of the record: never
/// renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LaunchClass {
    /// A Mach-O or ELF executable.
    Native = 1,
    /// An interpreter with an absolute entry file, or a `#!` file.
    Script = 2,
    /// `npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx` or `pipx run`.
    PackageRunner = 3,
}

/// How firmly a registered launch is bound to its image (D-33). Part of
/// the record: never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BindingStrength {
    /// The launched image is the checked one; standing-capable.
    Bound = 1,
    /// Checked before launch, not bound; no standing approvals.
    CheckedAtRest = 2,
}

/// The identity of an executable or entry file's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeDigest {
    /// Linux, and any entry file: SHA-256 read through a descriptor.
    Sha256([u8; 32]),
    /// macOS: the code directory hash (20 or 32 bytes), with the Team ID
    /// and signing identifier when Developer ID signed.
    CdHash {
        cdhash: Vec<u8>,
        team: Option<String>,
        identifier: Option<String>,
    },
}

/// A file as registered: its absolute path (bytes), device, inode and
/// contents' identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub path: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
    pub digest: CodeDigest,
}

/// A directory as registered: its canonical path (bytes), device and
/// inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirIdentity {
    pub path: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
}

/// A registered launch's environment, besides the runner's fixed
/// passthrough list (D-33): the recorded `PATH`, the declared non-secret
/// variables and the names of the injected bindings. Never a value of a
/// binding. Its `Debug` shows names only: a declared variable's value came
/// from a host config, where literal keys sit.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchEnv {
    pub path_env: Vec<u8>,
    pub vars: Vec<(String, String)>,
    pub binding_names: Vec<String>,
}

/// The declaration `migrate-mcp` gave, exactly as given (CR-2), which
/// `migrate-mcp --update` re-resolves. Its `Debug` shows how many
/// arguments and the variables' names: what a host config gave may hold a
/// literal key (`--api-key=<key>` in argv, a value in env) that extraction
/// missed.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchDecl {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub path_env: Option<String>,
}

/// A managed stdio server's registered launch (D-33). Its `Debug` shows
/// argv by count and its environment and declaration as theirs do.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredLaunch {
    pub launch_id: [u8; 16],
    pub revision: u64,
    pub class: LaunchClass,
    pub executable: FileIdentity,
    /// 1 to [`MAX_LIST`] arguments, `argv[0]` first.
    pub argv: Vec<Vec<u8>>,
    pub cwd: DirIdentity,
    pub env: LaunchEnv,
    /// A `script` launch's entry file.
    pub entry: Option<FileIdentity>,
    pub strength: BindingStrength,
    pub declaration: LaunchDecl,
}

/// How a managed server is reached. Its `Debug` shows a bridge's header
/// names and its origin's length.
#[derive(Clone, PartialEq, Eq)]
pub enum ManagedTransport {
    Stdio(Box<RegisteredLaunch>),
    /// An HTTP server reached through `mcp-bridge` (D-18): its exact
    /// origin and the header names the relay inserts.
    Bridge {
        origin: String,
        header_names: Vec<String>,
    },
}

/// A managed MCP server (D-05), version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedServer {
    /// `<agent>/<server>`.
    pub name: String,
    /// The managed project directory.
    pub project: ProjectIdentity,
    pub transport: ManagedTransport,
    pub registered_by: SubjectKindRecord,
    /// "Written by migrate-mcp on this device".
    pub written_by_migrate_mcp: bool,
}

/// A text or byte string a person or a host config gave, as the policy
/// records' `Debug` shows it: its length, never its bytes (L-12).
struct Elided(usize);

impl core::fmt::Debug for Elided {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

fn elided(b: &(impl AsRef<[u8]> + ?Sized)) -> Elided {
    Elided(b.as_ref().len())
}

/// The names of `(name, value)` pairs, for a `Debug` that shows no value.
fn names(pairs: &[(String, String)]) -> Vec<&str> {
    pairs.iter().map(|(n, _)| n.as_str()).collect()
}

impl core::fmt::Debug for IdentityCheck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityCheck")
            .field("kind", &self.kind)
            .field("locator", &elided(&self.locator))
            .field("account", &elided(&self.account))
            .field("tenant", &self.tenant.as_ref().map(elided))
            .field("role", &elided(&self.role))
            .finish()
    }
}

impl core::fmt::Debug for TransferScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransferScope")
            .field("cookies", &self.cookies.len())
            .field("storage", &self.storage.len())
            .field("format", &self.format)
            .finish()
    }
}

impl core::fmt::Debug for SignInTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignInTarget")
            .field("name", &self.name)
            .field("login", &self.login)
            .field("revision", &self.revision)
            .field("app_origins", &self.app_origins.len())
            .field("credential_origins", &self.credential_origins.len())
            .field(
                "identity_provider_origins",
                &self.identity_provider_origins.len(),
            )
            .field("callback_origins", &self.callback_origins.len())
            .field("identity_check", &self.identity_check)
            .field("transfer", &self.transfer)
            .field("tier", &self.tier)
            .field("adapter", &self.adapter)
            .field("approval_lifetime", &self.approval_lifetime)
            .field("session_lifetime", &self.session_lifetime)
            .field("revocation", &self.revocation.as_ref().map(elided))
            .finish()
    }
}

impl core::fmt::Debug for LaunchEnv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LaunchEnv")
            .field("path_env", &elided(&self.path_env))
            .field("vars", &names(&self.vars))
            .field("binding_names", &self.binding_names)
            .finish()
    }
}

impl core::fmt::Debug for LaunchDecl {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LaunchDecl")
            .field("argv", &self.argv.len())
            .field("cwd", &self.cwd.as_ref().map(elided))
            .field("env", &names(&self.env))
            .field("path_env", &self.path_env.as_ref().map(elided))
            .finish()
    }
}

impl core::fmt::Debug for RegisteredLaunch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredLaunch")
            .field("launch_id", &self.launch_id)
            .field("revision", &self.revision)
            .field("class", &self.class)
            .field("executable", &self.executable)
            .field("argv", &self.argv.len())
            .field("cwd", &self.cwd)
            .field("env", &self.env)
            .field("entry", &self.entry)
            .field("strength", &self.strength)
            .field("declaration", &self.declaration)
            .finish()
    }
}

impl core::fmt::Debug for ManagedTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ManagedTransport::Stdio(l) => f.debug_tuple("Stdio").field(l).finish(),
            ManagedTransport::Bridge {
                origin,
                header_names,
            } => f
                .debug_struct("Bridge")
                .field("origin", &elided(origin))
                .field("header_names", header_names)
                .finish(),
        }
    }
}

/// The standing-policy set's header (D-10): its generation, moved by one
/// by every transaction that changes the set, and a keyed digest of the
/// set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StandingSetHeader {
    pub generation: u64,
    pub set_digest: [u8; 32],
}

/// The keyed-hash domain of [`StandingSetHeader::set_digest`].
pub(crate) const STANDING_SET_DOMAIN: &str = "envcloak/v2/standing-set";

/// The set digest of the standing approvals among `policies`: keyed
/// BLAKE3 under the `index` subkey, in its own domain, over each one's id
/// and record, in id order (`id(16) len(4) record`).
pub(crate) fn standing_set_digest<'a>(
    keys: &Keyring,
    policies: impl Iterator<Item = (&'a PolicyId, &'a PolicyRecord)>,
) -> [u8; 32] {
    let mut sorted: BTreeMap<PolicyId, Vec<u8>> = BTreeMap::new();
    for (id, r) in policies {
        if matches!(r, PolicyRecord::StandingApproval(_)) {
            sorted.insert(*id, r.encode());
        }
    }
    let mut buf = Vec::new();
    for (id, record) in sorted {
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(
            &u32::try_from(record.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        buf.extend_from_slice(&record);
    }
    keyed_hash(keys.key(Purpose::Index), STANDING_SET_DOMAIN, &buf)
}

fn invalid() -> VaultError {
    VaultErrorKind::InvalidRecord.into()
}

fn corrupt() -> VaultError {
    VaultErrorKind::Corrupt.into()
}

/// Text of 1 to [`MAX_TEXT`] bytes.
fn text_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TEXT
}

fn bytes_ok(b: &[u8]) -> bool {
    !b.is_empty() && b.len() <= MAX_TEXT
}

fn opt_text_ok(s: Option<&String>) -> bool {
    s.is_none_or(|s| text_ok(s))
}

fn list_ok<T>(l: &[T], min: usize, ok: impl Fn(&T) -> bool) -> bool {
    l.len() >= min && l.len() <= MAX_LIST && l.iter().all(ok)
}

fn pair_ok(p: &(String, String)) -> bool {
    text_ok(&p.0) && p.1.len() <= MAX_TEXT
}

impl PolicyRecord {
    pub fn kind(&self) -> PolicyKind {
        match self {
            PolicyRecord::StandingApproval(_) => PolicyKind::StandingApproval,
            PolicyRecord::SignInTarget(_) => PolicyKind::SigninTarget,
            PolicyRecord::ManagedServer(_) => PolicyKind::ManagedServer,
        }
    }

    /// Whether the record keeps its kind's bounds: the text and list caps,
    /// the counts that must not be empty, and `not_after` after `created`.
    fn in_bounds(&self) -> bool {
        match self {
            PolicyRecord::StandingApproval(s) => s.in_bounds(),
            PolicyRecord::SignInTarget(t) => t.in_bounds(),
            PolicyRecord::ManagedServer(m) => m.in_bounds(),
        }
    }

    /// Fails with [`VaultErrorKind::InvalidRecord`] when the record breaks
    /// its kind's bounds.
    pub fn check(&self) -> Result<(), VaultError> {
        if self.in_bounds() {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    /// `kind(1) version(1) body`.
    pub fn encode(&self) -> Vec<u8> {
        let kind = self.kind();
        let mut e = Enc::new();
        e.u8(kind as u8).u8(kind.version());
        match self {
            PolicyRecord::StandingApproval(s) => s.encode(&mut e),
            PolicyRecord::SignInTarget(t) => t.encode(&mut e),
            PolicyRecord::ManagedServer(m) => m.encode(&mut e),
        }
        e.finish()
    }

    /// Decodes [`PolicyRecord::encode`]'s output. An unknown kind or
    /// version, trailing bytes, or a record out of its kind's bounds is
    /// [`VaultErrorKind::Corrupt`]: never an empty or default record.
    pub fn decode(b: &[u8]) -> Result<Self, VaultError> {
        let mut d = Dec::new(b);
        let kind = d.u8()?;
        let version = d.u8()?;
        let record = match (kind, version) {
            (1, 1) => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?),
            (2, 1) => PolicyRecord::SignInTarget(SignInTarget::decode(&mut d)?),
            (3, 1) => PolicyRecord::ManagedServer(ManagedServer::decode(&mut d)?),
            _ => return Err(corrupt()),
        };
        d.end()?;
        if !record.in_bounds() {
            return Err(corrupt());
        }
        Ok(record)
    }
}

fn id16(d: &mut Dec<'_>) -> Result<[u8; 16], VaultError> {
    d.array()
}

fn enc_project(e: &mut Enc, p: &ProjectIdentity) {
    e.bytes(&p.canonical_dir).u64(p.dev).u64(p.ino);
}

fn dec_project(d: &mut Dec<'_>) -> Result<ProjectIdentity, VaultError> {
    Ok(ProjectIdentity {
        canonical_dir: d.bytes()?.to_vec(),
        dev: d.u64()?,
        ino: d.u64()?,
    })
}

fn project_ok(p: &ProjectIdentity) -> bool {
    bytes_ok(&p.canonical_dir)
}

/// A list of text: `count(4)` then each.
fn enc_texts(e: &mut Enc, l: &[String]) {
    e.count(l.len());
    for s in l {
        e.str(s);
    }
}

fn dec_texts(d: &mut Dec<'_>) -> Result<Vec<String>, VaultError> {
    let n = d.count(4, MAX_LIST)?;
    (0..n).map(|_| d.string()).collect()
}

fn enc_pairs(e: &mut Enc, l: &[(String, String)]) {
    e.count(l.len());
    for (k, v) in l {
        e.str(k).str(v);
    }
}

fn dec_pairs(d: &mut Dec<'_>) -> Result<Vec<(String, String)>, VaultError> {
    let n = d.count(8, MAX_LIST)?;
    (0..n).map(|_| Ok((d.string()?, d.string()?))).collect()
}

fn dec_tier(b: u8) -> Result<LoginTier, VaultError> {
    match b {
        1 => Ok(LoginTier::Dev),
        2 => Ok(LoginTier::Each),
        3 => Ok(LoginTier::NeverAgent),
        _ => Err(corrupt()),
    }
}

impl StandingApproval {
    fn in_bounds(&self) -> bool {
        let identity = match &self.code_identity {
            CodeIdentity::MacSignature { team, identifier } => text_ok(team) && text_ok(identifier),
            CodeIdentity::LinuxSha256 { digests } => {
                !digests.is_empty()
                    && digests.len() <= MAX_DIGESTS
                    && digests
                        .iter()
                        .enumerate()
                        .all(|(i, d)| !digests[..i].contains(d))
            }
        };
        text_ok(&self.agent_id)
            && identity
            && project_ok(&self.project)
            && list_ok(&self.bindings, 1, |b| text_ok(&b.env_name))
            && self.not_after > self.created
            && self
                .signature
                .as_ref()
                .is_none_or(|s| !s.is_empty() && s.len() <= MAX_SIGNATURE)
    }

    fn encode(&self, e: &mut Enc) {
        e.str(&self.agent_id);
        match &self.code_identity {
            CodeIdentity::MacSignature { team, identifier } => {
                e.u8(1).str(team).str(identifier);
            }
            CodeIdentity::LinuxSha256 { digests } => {
                e.u8(2).count(digests.len());
                for d in digests {
                    e.raw(d);
                }
            }
        }
        enc_project(e, &self.project);
        match &self.launch {
            None => {
                e.u8(0);
            }
            Some(l) => {
                e.u8(1).raw(&l.launch_id).u64(l.revision);
            }
        }
        e.count(self.bindings.len());
        for b in &self.bindings {
            e.str(&b.env_name)
                .raw(b.item.as_bytes())
                .raw(b.field.as_bytes());
        }
        e.u64(self.created)
            .u64(self.not_after)
            .u8(self.proof_kind as u8)
            .opt_bytes(self.signature.as_deref());
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let agent_id = d.string()?;
        let code_identity = match d.u8()? {
            1 => CodeIdentity::MacSignature {
                team: d.string()?,
                identifier: d.string()?,
            },
            2 => {
                let n = d.count(32, MAX_DIGESTS)?;
                CodeIdentity::LinuxSha256 {
                    digests: (0..n).map(|_| d.array()).collect::<Result<_, _>>()?,
                }
            }
            _ => return Err(corrupt()),
        };
        let project = dec_project(d)?;
        let launch = if d.bool()? {
            Some(LaunchRef {
                launch_id: id16(d)?,
                revision: d.u64()?,
            })
        } else {
            None
        };
        let n = d.count(36, MAX_LIST)?;
        let mut bindings = Vec::with_capacity(n);
        for _ in 0..n {
            bindings.push(StandingBinding {
                env_name: d.string()?,
                item: ItemId::from_bytes(id16(d)?),
                field: FieldId::from_bytes(id16(d)?),
            });
        }
        let created = d.u64()?;
        let not_after = d.u64()?;
        let proof_kind = match d.u8()? {
            1 => ProofKind::Passphrase,
            _ => return Err(corrupt()),
        };
        let signature = d.opt_bytes()?.map(<[u8]>::to_vec);
        Ok(StandingApproval {
            agent_id,
            code_identity,
            project,
            launch,
            bindings,
            created,
            not_after,
            proof_kind,
            signature,
        })
    }
}

impl SignInTarget {
    fn in_bounds(&self) -> bool {
        let check = &self.identity_check;
        text_ok(&self.name)
            && list_ok(&self.app_origins, 1, |o| text_ok(o))
            && list_ok(&self.credential_origins, 1, |o| text_ok(o))
            && list_ok(&self.identity_provider_origins, 0, |o| text_ok(o))
            && list_ok(&self.callback_origins, 0, |o| text_ok(o))
            && text_ok(&check.locator)
            && text_ok(&check.account)
            && opt_text_ok(check.tenant.as_ref())
            && text_ok(&check.role)
            && list_ok(&self.transfer.cookies, 0, |c| {
                text_ok(&c.name) && text_ok(&c.domain) && text_ok(&c.path)
            })
            && list_ok(&self.transfer.storage, 0, |s| {
                text_ok(&s.origin) && text_ok(&s.key)
            })
            && self
                .adapter
                .as_ref()
                .is_none_or(|a| text_ok(&a.id) && text_ok(&a.version))
            && opt_text_ok(self.revocation.as_ref())
    }

    fn encode(&self, e: &mut Enc) {
        e.str(&self.name)
            .raw(self.login.as_bytes())
            .u64(self.revision);
        for list in [
            &self.app_origins,
            &self.credential_origins,
            &self.identity_provider_origins,
            &self.callback_origins,
        ] {
            enc_texts(e, list);
        }
        let c = &self.identity_check;
        e.u8(c.kind as u8)
            .str(&c.locator)
            .str(&c.account)
            .opt_str(c.tenant.as_deref())
            .str(&c.role);
        e.count(self.transfer.cookies.len());
        for c in &self.transfer.cookies {
            e.str(&c.name).str(&c.domain).str(&c.path);
        }
        e.count(self.transfer.storage.len());
        for s in &self.transfer.storage {
            e.str(&s.origin).str(&s.key);
        }
        e.u8(self.transfer.format as u8).u8(self.tier as u8);
        match &self.adapter {
            None => {
                e.u8(0);
            }
            Some(a) => {
                e.u8(1).str(&a.id).str(&a.version);
            }
        }
        e.u64(self.approval_lifetime)
            .u64(self.session_lifetime)
            .opt_str(self.revocation.as_deref());
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let name = d.string()?;
        let login = ItemId::from_bytes(id16(d)?);
        let revision = d.u64()?;
        let app_origins = dec_texts(d)?;
        let credential_origins = dec_texts(d)?;
        let identity_provider_origins = dec_texts(d)?;
        let callback_origins = dec_texts(d)?;
        let kind = match d.u8()? {
            1 => IdentityCheckKind::Endpoint,
            2 => IdentityCheckKind::Element,
            _ => return Err(corrupt()),
        };
        let identity_check = IdentityCheck {
            kind,
            locator: d.string()?,
            account: d.string()?,
            tenant: d.opt_string()?,
            role: d.string()?,
        };
        let n = d.count(12, MAX_LIST)?;
        let mut cookies = Vec::with_capacity(n);
        for _ in 0..n {
            cookies.push(CookieScope {
                name: d.string()?,
                domain: d.string()?,
                path: d.string()?,
            });
        }
        let n = d.count(8, MAX_LIST)?;
        let mut storage = Vec::with_capacity(n);
        for _ in 0..n {
            storage.push(StorageScope {
                origin: d.string()?,
                key: d.string()?,
            });
        }
        let format = match d.u8()? {
            1 => SessionFormat::Cookies,
            2 => SessionFormat::Storage,
            3 => SessionFormat::CookiesAndStorage,
            _ => return Err(corrupt()),
        };
        let tier = dec_tier(d.u8()?)?;
        let adapter = if d.bool()? {
            Some(AdapterRef {
                id: d.string()?,
                version: d.string()?,
            })
        } else {
            None
        };
        Ok(SignInTarget {
            name,
            login,
            revision,
            app_origins,
            credential_origins,
            identity_provider_origins,
            callback_origins,
            identity_check,
            transfer: TransferScope {
                cookies,
                storage,
                format,
            },
            tier,
            adapter,
            approval_lifetime: d.u64()?,
            session_lifetime: d.u64()?,
            revocation: d.opt_string()?,
        })
    }
}

fn enc_digest(e: &mut Enc, c: &CodeDigest) {
    match c {
        CodeDigest::Sha256(h) => {
            e.u8(1).raw(h);
        }
        CodeDigest::CdHash {
            cdhash,
            team,
            identifier,
        } => {
            e.u8(2)
                .bytes(cdhash)
                .opt_str(team.as_deref())
                .opt_str(identifier.as_deref());
        }
    }
}

fn dec_digest(d: &mut Dec<'_>) -> Result<CodeDigest, VaultError> {
    match d.u8()? {
        1 => Ok(CodeDigest::Sha256(d.array()?)),
        2 => Ok(CodeDigest::CdHash {
            cdhash: d.bytes()?.to_vec(),
            team: d.opt_string()?,
            identifier: d.opt_string()?,
        }),
        _ => Err(corrupt()),
    }
}

fn digest_ok(c: &CodeDigest) -> bool {
    match c {
        CodeDigest::Sha256(_) => true,
        CodeDigest::CdHash {
            cdhash,
            team,
            identifier,
        } => {
            matches!(cdhash.len(), 20 | 32)
                && opt_text_ok(team.as_ref())
                && opt_text_ok(identifier.as_ref())
        }
    }
}

fn enc_file(e: &mut Enc, f: &FileIdentity) {
    e.bytes(&f.path).u64(f.dev).u64(f.ino);
    enc_digest(e, &f.digest);
}

fn dec_file(d: &mut Dec<'_>) -> Result<FileIdentity, VaultError> {
    Ok(FileIdentity {
        path: d.bytes()?.to_vec(),
        dev: d.u64()?,
        ino: d.u64()?,
        digest: dec_digest(d)?,
    })
}

fn file_ok(f: &FileIdentity) -> bool {
    bytes_ok(&f.path) && digest_ok(&f.digest)
}

impl RegisteredLaunch {
    fn in_bounds(&self) -> bool {
        let env = &self.env;
        let decl = &self.declaration;
        file_ok(&self.executable)
            && list_ok(&self.argv, 1, |a| a.len() <= MAX_TEXT)
            && bytes_ok(&self.cwd.path)
            && env.path_env.len() <= MAX_TEXT
            && list_ok(&env.vars, 0, pair_ok)
            && list_ok(&env.binding_names, 0, |n| text_ok(n))
            && self.entry.as_ref().is_none_or(file_ok)
            // Only a script names an entry file, and it must.
            && self.entry.is_some() == (self.class == LaunchClass::Script)
            && list_ok(&decl.argv, 1, |a| a.len() <= MAX_TEXT)
            && opt_text_ok(decl.cwd.as_ref())
            && list_ok(&decl.env, 0, pair_ok)
            && decl.path_env.as_ref().is_none_or(|p| p.len() <= MAX_TEXT)
    }

    fn encode(&self, e: &mut Enc) {
        e.raw(&self.launch_id)
            .u64(self.revision)
            .u8(self.class as u8);
        enc_file(e, &self.executable);
        e.count(self.argv.len());
        for a in &self.argv {
            e.bytes(a);
        }
        e.bytes(&self.cwd.path).u64(self.cwd.dev).u64(self.cwd.ino);
        e.bytes(&self.env.path_env);
        enc_pairs(e, &self.env.vars);
        enc_texts(e, &self.env.binding_names);
        match &self.entry {
            None => {
                e.u8(0);
            }
            Some(f) => {
                e.u8(1);
                enc_file(e, f);
            }
        }
        e.u8(self.strength as u8);
        let decl = &self.declaration;
        enc_texts(e, &decl.argv);
        e.opt_str(decl.cwd.as_deref());
        enc_pairs(e, &decl.env);
        e.opt_str(decl.path_env.as_deref());
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let launch_id = id16(d)?;
        let revision = d.u64()?;
        let class = match d.u8()? {
            1 => LaunchClass::Native,
            2 => LaunchClass::Script,
            3 => LaunchClass::PackageRunner,
            _ => return Err(corrupt()),
        };
        let executable = dec_file(d)?;
        let n = d.count(4, MAX_LIST)?;
        let argv = (0..n)
            .map(|_| d.bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let cwd = DirIdentity {
            path: d.bytes()?.to_vec(),
            dev: d.u64()?,
            ino: d.u64()?,
        };
        let env = LaunchEnv {
            path_env: d.bytes()?.to_vec(),
            vars: dec_pairs(d)?,
            binding_names: dec_texts(d)?,
        };
        let entry = if d.bool()? { Some(dec_file(d)?) } else { None };
        let strength = match d.u8()? {
            1 => BindingStrength::Bound,
            2 => BindingStrength::CheckedAtRest,
            _ => return Err(corrupt()),
        };
        let declaration = LaunchDecl {
            argv: dec_texts(d)?,
            cwd: d.opt_string()?,
            env: dec_pairs(d)?,
            path_env: d.opt_string()?,
        };
        Ok(RegisteredLaunch {
            launch_id,
            revision,
            class,
            executable,
            argv,
            cwd,
            env,
            entry,
            strength,
            declaration,
        })
    }
}

impl ManagedServer {
    fn in_bounds(&self) -> bool {
        let transport = match &self.transport {
            ManagedTransport::Stdio(l) => l.in_bounds(),
            ManagedTransport::Bridge {
                origin,
                header_names,
            } => text_ok(origin) && list_ok(header_names, 0, |h| text_ok(h)),
        };
        text_ok(&self.name) && project_ok(&self.project) && transport
    }

    fn encode(&self, e: &mut Enc) {
        e.str(&self.name);
        enc_project(e, &self.project);
        match &self.transport {
            ManagedTransport::Stdio(l) => {
                e.u8(1);
                l.encode(e);
            }
            ManagedTransport::Bridge {
                origin,
                header_names,
            } => {
                e.u8(2).str(origin);
                enc_texts(e, header_names);
            }
        }
        e.u8(self.registered_by as u8)
            .bool(self.written_by_migrate_mcp);
    }

    fn decode(d: &mut Dec<'_>) -> Result<Self, VaultError> {
        let name = d.string()?;
        let project = dec_project(d)?;
        let transport = match d.u8()? {
            1 => ManagedTransport::Stdio(Box::new(RegisteredLaunch::decode(d)?)),
            2 => ManagedTransport::Bridge {
                origin: d.string()?,
                header_names: dec_texts(d)?,
            },
            _ => return Err(corrupt()),
        };
        let registered_by = match d.u8()? {
            1 => SubjectKindRecord::Terminal,
            2 => SubjectKindRecord::Agent,
            3 => SubjectKindRecord::Unknown,
            _ => return Err(corrupt()),
        };
        Ok(ManagedServer {
            name,
            project,
            transport,
            registered_by,
            written_by_migrate_mcp: d.bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        Argon2id, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk, wrap_vmk_with,
    };
    use crate::secret::SecretBytes;
    use crate::vault::{INITIAL_EPOCH, Integrity, LockedVault, TamperKind, Vault, VaultPaths};

    fn standing(signature: Option<Vec<u8>>, launch: bool, mac: bool) -> PolicyRecord {
        PolicyRecord::StandingApproval(StandingApproval {
            agent_id: "claude-code".into(),
            code_identity: if mac {
                CodeIdentity::MacSignature {
                    team: "TEAMID1234".into(),
                    identifier: "com.example.agent".into(),
                }
            } else {
                CodeIdentity::LinuxSha256 {
                    digests: vec![[1; 32], [2; 32], [3; 32], [4; 32]],
                }
            },
            project: ProjectIdentity {
                canonical_dir: b"/src/acme \xff web".to_vec(),
                dev: u64::MAX,
                ino: 0,
            },
            launch: launch.then_some(LaunchRef {
                launch_id: [9; 16],
                revision: 7,
            }),
            bindings: vec![
                StandingBinding {
                    env_name: "OPENAI_API_KEY".into(),
                    item: ItemId::from_bytes([5; 16]),
                    field: FieldId::from_bytes([6; 16]),
                },
                StandingBinding {
                    env_name: "\u{e9}".into(),
                    item: ItemId::from_bytes([7; 16]),
                    field: FieldId::from_bytes([8; 16]),
                },
            ],
            created: 10,
            not_after: 11,
            proof_kind: ProofKind::Passphrase,
            signature,
        })
    }

    fn target(full: bool) -> PolicyRecord {
        PolicyRecord::SignInTarget(SignInTarget {
            name: "fixture".into(),
            login: ItemId::from_bytes([1; 16]),
            revision: 3,
            app_origins: vec!["http://127.0.0.1:4000".into()],
            credential_origins: vec!["http://127.0.0.1:4000".into()],
            identity_provider_origins: if full {
                vec!["https://idp.example.test".into()]
            } else {
                Vec::new()
            },
            callback_origins: if full {
                vec!["http://127.0.0.1:4000".into(), "http://[::1]:4000".into()]
            } else {
                Vec::new()
            },
            identity_check: IdentityCheck {
                kind: if full {
                    IdentityCheckKind::Element
                } else {
                    IdentityCheckKind::Endpoint
                },
                locator: "/api/whoami".into(),
                account: "editor@example.test".into(),
                tenant: full.then(|| "acme".into()),
                role: "editor".into(),
            },
            transfer: TransferScope {
                cookies: vec![CookieScope {
                    name: "session".into(),
                    domain: "127.0.0.1".into(),
                    path: "/".into(),
                }],
                storage: if full {
                    vec![StorageScope {
                        origin: "http://127.0.0.1:4000".into(),
                        key: "token".into(),
                    }]
                } else {
                    Vec::new()
                },
                format: if full {
                    SessionFormat::CookiesAndStorage
                } else {
                    SessionFormat::Cookies
                },
            },
            tier: if full {
                LoginTier::Each
            } else {
                LoginTier::Dev
            },
            adapter: full.then(|| AdapterRef {
                id: "envcloak-test-session".into(),
                version: "1".into(),
            }),
            approval_lifetime: 86_400,
            session_lifetime: 3_600,
            revocation: full.then(|| "/__envcloak/revoke".into()),
        })
    }

    fn launch(class: LaunchClass, mac: bool) -> RegisteredLaunch {
        let digest = if mac {
            CodeDigest::CdHash {
                cdhash: vec![4; 20],
                team: Some("TEAMID1234".into()),
                identifier: None,
            }
        } else {
            CodeDigest::Sha256([4; 32])
        };
        RegisteredLaunch {
            launch_id: [2; 16],
            revision: 1,
            class,
            executable: FileIdentity {
                path: b"/usr/bin/node".to_vec(),
                dev: 1,
                ino: 2,
                digest,
            },
            argv: vec![
                b"node".to_vec(),
                b"/srv/server.js".to_vec(),
                b"\xff".to_vec(),
            ],
            cwd: DirIdentity {
                path: b"/srv".to_vec(),
                dev: 1,
                ino: 3,
            },
            env: LaunchEnv {
                path_env: b"/usr/bin".to_vec(),
                vars: vec![("NODE_ENV".into(), String::new())],
                binding_names: vec!["API_KEY".into()],
            },
            entry: (class == LaunchClass::Script).then(|| FileIdentity {
                path: b"/srv/server.js".to_vec(),
                dev: 1,
                ino: 4,
                digest: CodeDigest::Sha256([5; 32]),
            }),
            strength: if class == LaunchClass::Native {
                BindingStrength::Bound
            } else {
                BindingStrength::CheckedAtRest
            },
            declaration: LaunchDecl {
                argv: vec!["node".into(), "/srv/server.js".into()],
                cwd: Some("/srv".into()),
                env: vec![("NODE_ENV".into(), "production".into())],
                path_env: None,
            },
        }
    }

    fn managed(t: ManagedTransport) -> PolicyRecord {
        PolicyRecord::ManagedServer(ManagedServer {
            name: "codex/files".into(),
            project: ProjectIdentity {
                canonical_dir: b"/data/mcp/codex-files".to_vec(),
                dev: 1,
                ino: 9,
            },
            transport: t,
            registered_by: SubjectKindRecord::Terminal,
            written_by_migrate_mcp: false,
        })
    }

    fn every_record() -> Vec<PolicyRecord> {
        vec![
            standing(None, false, false),
            standing(Some(vec![1; 64]), true, true),
            target(false),
            target(true),
            managed(ManagedTransport::Stdio(Box::new(launch(
                LaunchClass::Native,
                false,
            )))),
            managed(ManagedTransport::Stdio(Box::new(launch(
                LaunchClass::Script,
                true,
            )))),
            managed(ManagedTransport::Stdio(Box::new(launch(
                LaunchClass::PackageRunner,
                false,
            )))),
            managed(ManagedTransport::Bridge {
                origin: "https://mcp.example.test".into(),
                header_names: vec!["Authorization".into()],
            }),
        ]
    }

    /// Every policy record's `Debug` is value-free (L-12): a text or byte
    /// string a person or a host config gave (argv, a variable's value, the
    /// declaration as `migrate-mcp` gave it, an origin, the identity
    /// check's account and the rest a target registers) shows as its
    /// length, neither as text nor as the list of its bytes; names show.
    /// The positive controls: each canary is in the record's encoding, so
    /// the record holds it, and the names are in its `Debug`.
    ///
    /// Mutations checked: the derived `Debug` given back to `LaunchDecl`,
    /// to `LaunchEnv`, to `RegisteredLaunch`, to `ManagedTransport` and to
    /// `SignInTarget`: a canary shows, and this fails for each.
    #[test]
    fn debug_shows_no_text_a_person_or_a_host_config_gave() {
        let c = |slot: &str| format!("debug-canary-{slot}");
        // Text, and the list of its bytes as a derived `Debug` of a byte
        // string prints it.
        let shows = |debug: &str, canary: &str| {
            let bytes = format!("{:?}", canary.as_bytes());
            debug.contains(canary) || debug.contains(&bytes[1..bytes.len() - 1])
        };
        let mut l = launch(LaunchClass::Script, false);
        l.argv.push(c("argv").into_bytes());
        l.env.path_env = c("path-env").into_bytes();
        l.env.vars.push(("NODE_OPTIONS_NAME".into(), c("var")));
        l.declaration = LaunchDecl {
            argv: vec!["node".into(), c("decl-argv")],
            cwd: Some(c("decl-cwd")),
            env: vec![("TOKEN_NAME".into(), c("decl-env"))],
            path_env: Some(c("decl-path")),
        };
        let stdio = managed(ManagedTransport::Stdio(Box::new(l)));
        let bridge = managed(ManagedTransport::Bridge {
            origin: c("origin"),
            header_names: vec!["Authorization".into()],
        });
        let PolicyRecord::SignInTarget(mut t) = target(true) else {
            unreachable!()
        };
        t.app_origins.push(c("app-origin"));
        t.credential_origins.push(c("credential-origin"));
        t.identity_provider_origins.push(c("idp-origin"));
        t.callback_origins.push(c("callback-origin"));
        t.identity_check = IdentityCheck {
            kind: IdentityCheckKind::Endpoint,
            locator: c("locator"),
            account: c("account"),
            tenant: Some(c("tenant")),
            role: c("role"),
        };
        t.transfer.cookies.push(CookieScope {
            name: c("cookie-name"),
            domain: c("cookie-domain"),
            path: c("cookie-path"),
        });
        t.transfer.storage.push(StorageScope {
            origin: c("storage-origin"),
            key: c("storage-key"),
        });
        t.revocation = Some(c("revocation"));
        let target = PolicyRecord::SignInTarget(t);
        let cases: [(&PolicyRecord, &[&str], &[&str]); 3] = [
            (
                &stdio,
                &[
                    "argv",
                    "path-env",
                    "var",
                    "decl-argv",
                    "decl-cwd",
                    "decl-env",
                    "decl-path",
                ],
                &["NODE_OPTIONS_NAME", "TOKEN_NAME", "API_KEY", "codex/files"],
            ),
            (&bridge, &["origin"], &["Authorization", "codex/files"]),
            (
                &target,
                &[
                    "app-origin",
                    "credential-origin",
                    "idp-origin",
                    "callback-origin",
                    "locator",
                    "account",
                    "tenant",
                    "role",
                    "cookie-name",
                    "cookie-domain",
                    "cookie-path",
                    "storage-origin",
                    "storage-key",
                    "revocation",
                ],
                &["fixture", "envcloak-test-session"],
            ),
        ];
        for (r, slots, names) in cases {
            let encoded = r.encode();
            for debug in [format!("{r:?}"), format!("{r:#?}")] {
                for slot in slots {
                    let canary = c(slot);
                    assert!(
                        encoded
                            .windows(canary.len())
                            .any(|w| w == canary.as_bytes()),
                        "the record does not hold {slot}"
                    );
                    assert!(!shows(&debug, &canary), "Debug shows {slot}: {debug}");
                }
                for name in names {
                    assert!(debug.contains(name), "Debug lacks {name}: {debug}");
                }
            }
        }
    }

    #[test]
    fn every_kind_round_trips_and_starts_with_its_kind_and_version() {
        for r in every_record() {
            r.check().unwrap();
            let b = r.encode();
            assert_eq!(b[0], r.kind() as u8);
            assert_eq!(b[1], 1, "version 1 of every kind");
            assert_eq!(PolicyRecord::decode(&b).unwrap(), r);
        }
        assert_eq!(
            [
                PolicyKind::StandingApproval as u8,
                PolicyKind::SigninTarget as u8,
                PolicyKind::ManagedServer as u8
            ],
            [1, 2, 3],
            "docs/VAULT.md's reserved numbers"
        );
    }

    /// Every record cut short, or with a byte more, fails to decode; no
    /// prefix of a record decodes as some other record.
    #[test]
    fn a_record_decodes_whole_or_not_at_all() {
        for r in every_record() {
            let b = r.encode();
            for n in 0..b.len() {
                assert_eq!(
                    PolicyRecord::decode(&b[..n]).unwrap_err().kind(),
                    VaultErrorKind::Corrupt,
                    "{:?} cut at {n}",
                    r.kind()
                );
            }
            let mut more = b.clone();
            more.push(0);
            assert!(PolicyRecord::decode(&more).is_err());
        }
    }

    /// A tag or kind byte this build does not know is refused wherever it
    /// sits: the record's kind and version, and every enum inside.
    #[test]
    fn unknown_kinds_versions_and_tags_are_refused() {
        for r in every_record() {
            let b = r.encode();
            for (at, bad) in [(0, 0), (0, 4), (0, 255), (1, 0), (1, 2)] {
                let mut x = b.clone();
                x[at] = bad;
                assert!(
                    PolicyRecord::decode(&x).is_err(),
                    "{:?} [{at}]={bad}",
                    r.kind()
                );
            }
        }
        // Every single-byte change either fails or decodes to a record in
        // bounds; none panics. Both happen (the counts), so neither half
        // of the check is empty.
        let (mut accepted, mut refused) = (0u32, 0u32);
        for r in every_record() {
            let b = r.encode();
            for at in 0..b.len() {
                for bad in [0u8, 1, 2, 3, 4, 0x7f, 0xff] {
                    let mut x = b.clone();
                    x[at] = bad;
                    if let Ok(d) = PolicyRecord::decode(&x) {
                        d.check().unwrap();
                        accepted += 1;
                    } else {
                        refused += 1;
                    }
                }
            }
        }
        assert!(accepted > 0 && refused > 0, "{accepted} {refused}");
    }

    /// Random bytes behind each kind and version, and random records'
    /// tails: decoding never panics, and anything it accepts is in bounds
    /// and encodes back to the same bytes (one form per record).
    #[test]
    fn random_bytes_never_decode_into_something_else() {
        let mut state: u64 = 0x6d32_2d30_375f_7076;
        let mut next = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let records = every_record();
        let mut accepted = 0u32;
        for round in 0..20_000u32 {
            let b: Vec<u8> = if round % 2 == 0 {
                let len = (next() % 200) as usize;
                let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if b.len() >= 2 {
                    b[0] = 1 + (round / 2 % 3) as u8;
                    b[1] = 1;
                }
                b
            } else {
                let r = &records[(next() as usize) % records.len()];
                let mut b = r.encode();
                let at = (next() as usize) % b.len();
                for x in &mut b[at..] {
                    *x = next() as u8;
                }
                b
            };
            if let Ok(r) = PolicyRecord::decode(&b) {
                r.check().unwrap();
                assert_eq!(r.encode(), b);
                accepted += 1;
            }
        }
        // Some inputs decode, so the round trip above was checked.
        assert!(accepted > 0);
    }

    #[test]
    fn records_out_of_bounds_are_refused_both_ways() {
        let mut cases: Vec<PolicyRecord> = Vec::new();
        let mut s = |f: &dyn Fn(&mut StandingApproval)| {
            let mut r = standing(None, false, false);
            if let PolicyRecord::StandingApproval(x) = &mut r {
                f(x);
            }
            cases.push(r);
        };
        s(&|x| x.bindings.clear());
        s(&|x| x.not_after = x.created);
        s(&|x| x.agent_id.clear());
        s(&|x| x.agent_id = "a".repeat(MAX_TEXT + 1));
        s(&|x| x.project.canonical_dir.clear());
        s(&|x| x.signature = Some(Vec::new()));
        s(&|x| x.signature = Some(vec![0; MAX_SIGNATURE + 1]));
        s(&|x| {
            x.code_identity = CodeIdentity::LinuxSha256 {
                digests: Vec::new(),
            }
        });
        s(&|x| {
            x.code_identity = CodeIdentity::LinuxSha256 {
                digests: vec![[0; 32]; MAX_DIGESTS + 1],
            }
        });
        s(&|x| {
            x.code_identity = CodeIdentity::LinuxSha256 {
                digests: vec![[0; 32], [0; 32]],
            }
        });
        s(&|x| x.bindings = (0..=MAX_LIST).map(|_| x.bindings[0].clone()).collect());
        let mut t = target(true);
        if let PolicyRecord::SignInTarget(x) = &mut t {
            x.app_origins.clear();
        }
        cases.push(t);
        let mut t = target(true);
        if let PolicyRecord::SignInTarget(x) = &mut t {
            x.identity_check.tenant = Some(String::new());
        }
        cases.push(t);
        for (class, entry) in [(LaunchClass::Script, false), (LaunchClass::Native, true)] {
            let mut l = launch(class, false);
            if entry {
                l.entry = launch(LaunchClass::Script, false).entry;
            } else {
                l.entry = None;
            }
            cases.push(managed(ManagedTransport::Stdio(Box::new(l))));
        }
        let mut l = launch(LaunchClass::Native, true);
        l.executable.digest = CodeDigest::CdHash {
            cdhash: vec![0; 19],
            team: None,
            identifier: None,
        };
        cases.push(managed(ManagedTransport::Stdio(Box::new(l))));
        let mut l = launch(LaunchClass::Native, false);
        l.argv.clear();
        cases.push(managed(ManagedTransport::Stdio(Box::new(l))));
        cases.push(managed(ManagedTransport::Bridge {
            origin: String::new(),
            header_names: Vec::new(),
        }));
        for r in cases {
            assert_eq!(
                r.check().unwrap_err().kind(),
                VaultErrorKind::InvalidRecord,
                "{r:?}"
            );
            assert_eq!(
                PolicyRecord::decode(&r.encode()).unwrap_err().kind(),
                VaultErrorKind::Corrupt,
                "{r:?}"
            );
        }
    }

    fn vault() -> (tempfile::TempDir, VaultPaths, Vec<u8>, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let raw = vmk.export_for_testing();
        let env = wrap_vmk_with(
            &vmk,
            &SecretBytes::copy_from(b"unit test passphrase"),
            UnlockerKind::Passphrase,
            &EnvelopeCtx {
                vault_id,
                unlocker_id: UnlockerId::generate(),
                epoch: INITIAL_EPOCH,
            },
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();
        let v = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();
        (dir, paths, raw, v)
    }

    /// The standing set's digest in the header must be the one the rows
    /// give: a header sealed over another set (written here by this
    /// process with the key, as only a holder of the key could) makes the
    /// vault read-only at the next unlock.
    #[test]
    fn a_header_whose_standing_digest_is_not_the_sets_is_refused() {
        let (_d, paths, raw, mut v) = vault();
        v.transact(|t| {
            t.put_policy(
                crate::vault::PolicyId::generate(),
                &standing(None, false, false),
            )
        })
        .unwrap();
        // A write that does not touch the set commits the header as it is
        // in memory: here with another digest.
        v.state.header.standing_set.set_digest[0] ^= 1;
        v.transact(|t| {
            t.bump_policy_epoch();
            Ok(())
        })
        .unwrap();
        drop(v);
        let v = LockedVault::open(&paths)
            .unwrap()
            .unlock(Vmk::import_for_testing(&raw).unwrap())
            .map_err(|(_, e)| e)
            .unwrap();
        assert_eq!(
            v.integrity(),
            Integrity::Tampered(TamperKind::RowInconsistent)
        );
        assert!(v.standing_set().is_err());
    }
}
