//! Standing approvals (SPEC §10b "Standing approvals"; M2 plan D-10,
//! task M2-15): persistent, test-key-only approvals keyed to a builtin
//! agent's kernel-verified code identity and one project (plus the
//! registered launch revision when the project is a managed MCP server's),
//! for at most [`MAX_STANDING_TTL`] (30 days).
//!
//! A standing approval is created only from a live pending request of an
//! agent subject with a passphrase proof from a terminal subject. When a
//! request arrives with no covering in-memory grant, [`StandingStore`]
//! checks whether an unexpired standing record covers it, and on a match
//! mints a standard `session` grant in [`crate::GrantStore`] rooted at the
//! current agent process instance with TTL
//! `min(DEFAULT_TTL, MAX_AGENT_TTL, not_after - now)`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envcloak_core::vault::{
    Classification, CodeIdentity, ItemMeta, LaunchRef, MAX_DIGESTS, PolicyId, PolicyRecord,
    StandingApproval, StandingBinding, Vault, VaultError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agents::AgentCatalog;
use crate::effective::SubjectKind;
use crate::evidence::SubjectEvidence;
use crate::grants::{
    AccessRequest, ApprovalOptions, ApprovalProof, DEFAULT_TTL, GrantId, GrantStore, MAX_AGENT_TTL,
    ManagedRequest, Now, OptionsError, ProofKind, Uses,
};
use crate::ids;
use crate::manifest::Mode;
use crate::project::{MANIFEST_NAME, ProjectIdentity};
use crate::statement::{StandingSummary, escape_for_display};

/// The longest standing approval: 30 days (SPEC §10b).
pub const MAX_STANDING_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// Domain prefix for `envcloak standing confirm` digests.
pub const STANDING_CONFIRM_DOMAIN: &[u8] = b"envcloak-standing-confirm/1\n";

/// Pinned Linux release SHA-256 digests (`integrations/agents-digests.toml`).
pub const AGENTS_DIGESTS_TOML: &str = r#"# EnvCloak pinned Linux agent executable SHA-256 digests (SPEC §10b, M2-15).
#
# On Linux, where an agent's code identity is the SHA-256 of `/proc/<pid>/exe`,
# `--standing` checks whether the digest matches a release recorded here. An
# unrecognized digest is still eligible when its path lies within the agent's
# catalog `install_trees`, with an explicit warning line above the passphrase
# prompt.

schema_version = 1

[[agents]]
id = "claude-code"

[[agents.releases]]
version = "2.1.280"
arch = "x86_64-linux"
sha256 = "1e08503dbdf3c2cb0d706d32f3408277388d1c76ef108673e8fe42c1b322925b"

[[agents]]
id = "codex"

[[agents.releases]]
version = "0.159.2"
arch = "x86_64-linux"
sha256 = "1748767b230ebfc3d4ab7e4e254920d0c0ad9691fd8c11f190e7d44511a4a92e"

[[agents]]
id = "copilot-cli"

[[agents.releases]]
version = "1.0.90"
arch = "x86_64-linux"
sha256 = "be17b42705ca17490098d7b87f293300d72a094d125b6bb2b2557dc4a0a4f8a8"

[[agents]]
id = "opencode"

[[agents.releases]]
version = "1.18.34"
arch = "x86_64-linux"
sha256 = "9ca0b9953d49997601655e54f846a3efa464f237e47c6f1b04716d0f2e64c4c2"

[[agents]]
id = "cursor-cli"

[[agents.releases]]
version = "2026.09.28-64d2043"
arch = "x86_64-linux"
sha256 = "2ccc9a8e167797641448b5e5c936f006ba137a2555f117f38c5eb76a5238a233"
"#;

/// Returns the recognized release version in `integrations/agents-digests.toml`
/// when `sha256` matches a pinned release of `agent_id`, or `None` for an
/// unrecognized build.
pub fn recognized_release(agent_id: &str, sha256: &[u8; 32]) -> Option<String> {
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if *sha256 == [0u8; 32] {
        return None;
    }
    let want = hex(sha256);
    if want.eq_ignore_ascii_case(EMPTY_SHA256) {
        return None;
    }
    let doc = toml_edit::Document::parse(AGENTS_DIGESTS_TOML).ok()?;
    if doc.get("schema_version")?.as_integer()? != 1 {
        return None;
    }
    let agents = doc.get("agents")?.as_array_of_tables()?;
    for agent in agents {
        if agent.get("id")?.as_str()? != agent_id {
            continue;
        }
        let releases = agent.get("releases")?.as_array_of_tables()?;
        for release in releases {
            let digest = release.get("sha256")?.as_str()?;
            if digest.eq_ignore_ascii_case(&want) {
                return Some(release.get("version")?.as_str()?.to_owned());
            }
        }
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A standing approval's identifier: a ULID, shown as 26 Crockford base32
/// characters (matching its [`PolicyId`] in the vault).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StandingId(PolicyId);

impl StandingId {
    /// Generates a new random standing id.
    pub fn generate() -> Self {
        StandingId(PolicyId::generate())
    }

    /// Parses the 26-character Crockford base32 form.
    pub fn parse(s: &str) -> Option<Self> {
        let mut b = [0u8; 16];
        ids::decode(s, 26, &mut b)?;
        Some(StandingId(PolicyId::from_bytes(b)))
    }

    /// Wraps a vault [`PolicyId`].
    pub fn from_policy_id(id: PolicyId) -> Self {
        StandingId(id)
    }

    /// The underlying vault [`PolicyId`].
    pub fn policy_id(self) -> PolicyId {
        self.0
    }

    /// The raw 16-byte ULID.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl core::fmt::Display for StandingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&ids::encode(self.0.as_bytes(), 26))
    }
}

impl core::fmt::Debug for StandingId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StandingId({self})")
    }
}

/// A standing approval record (SPEC §10b, M2 plan D-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingRecord {
    pub id: StandingId,
    pub agent_id: String,
    pub code_identity: CodeIdentity,
    pub project: ProjectIdentity,
    pub launch: Option<LaunchRef>,
    pub bindings: Vec<StandingBinding>,
    pub created: SystemTime,
    pub not_after: SystemTime,
    pub proof_kind: ProofKind,
    pub signature: Option<Vec<u8>>,
}

impl StandingRecord {
    /// Converts a sealed vault [`StandingApproval`] row into a [`StandingRecord`].
    pub fn from_vault(id: PolicyId, a: &StandingApproval) -> Self {
        let canonical_dir = PathBuf::from(OsStr::from_bytes(&a.project.canonical_dir));
        let manifest_path = canonical_dir.join(MANIFEST_NAME);
        StandingRecord {
            id: StandingId(id),
            agent_id: a.agent_id.clone(),
            code_identity: a.code_identity.clone(),
            project: ProjectIdentity {
                canonical_dir,
                manifest_path,
                dev: a.project.dev,
                ino: a.project.ino,
            },
            launch: a.launch,
            bindings: a.bindings.clone(),
            created: UNIX_EPOCH + Duration::from_secs(a.created),
            not_after: UNIX_EPOCH + Duration::from_secs(a.not_after),
            proof_kind: match a.proof_kind {
                envcloak_core::vault::ProofKind::Passphrase => ProofKind::Passphrase,
            },
            signature: a.signature.clone(),
        }
    }

    /// Converts this [`StandingRecord`] into its sealed vault form.
    pub fn to_vault(&self) -> (PolicyId, StandingApproval) {
        let created = self
            .created
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let not_after = self
            .not_after
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .max(created.saturating_add(1));
        (
            self.id.0,
            StandingApproval {
                agent_id: self.agent_id.clone(),
                code_identity: self.code_identity.clone(),
                project: envcloak_core::vault::ProjectIdentity {
                    canonical_dir: self.project.canonical_dir.as_os_str().as_bytes().to_vec(),
                    dev: self.project.dev,
                    ino: self.project.ino,
                },
                launch: self.launch,
                bindings: self.bindings.clone(),
                created,
                not_after,
                proof_kind: match self.proof_kind {
                    ProofKind::Passphrase | ProofKind::SecureEnclave { .. } => {
                        envcloak_core::vault::ProofKind::Passphrase
                    }
                },
                signature: self.signature.clone(),
            },
        )
    }

    /// Remaining wall-clock duration before `not_after`.
    pub fn remaining(&self, now: SystemTime) -> Duration {
        self.not_after.duration_since(now).unwrap_or_default()
    }

    /// Whether the record has expired at `now`.
    pub fn expired(&self, now: SystemTime) -> bool {
        now >= self.not_after
    }

    /// Formats the code identity for display and confirmation statements.
    pub fn display_identity(&self) -> String {
        match &self.code_identity {
            CodeIdentity::MacSignature { team, identifier } => {
                format!("macos:{team}:{identifier}")
            }
            CodeIdentity::LinuxSha256 { digests } => {
                let list: Vec<String> = digests
                    .iter()
                    .map(|d| format!("sha256:{}", hex(d)))
                    .collect();
                list.join(",")
            }
        }
    }

    /// Summary of this standing record at `now`, resolving item ids to slugs
    /// where present in `items`.
    pub fn summary(
        &self,
        now: SystemTime,
        catalog: &AgentCatalog,
        items: &[ItemMeta],
    ) -> StandingRecordSummary {
        let agent_name = catalog
            .name(&self.agent_id)
            .unwrap_or(&self.agent_id)
            .to_owned();
        let bindings = self
            .bindings
            .iter()
            .map(|b| {
                if let Some(m) = items.iter().find(|m| m.id == b.item) {
                    let field_name = m
                        .fields
                        .iter()
                        .find(|f| f.id == b.field)
                        .map(|f| f.name.as_str())
                        .unwrap_or("value");
                    if field_name != "value" {
                        format!("{}={}#{field_name}", b.env_name, m.slug)
                    } else {
                        format!("{}={}", b.env_name, m.slug)
                    }
                } else {
                    format!("{}={}", b.env_name, b.item)
                }
            })
            .collect();
        let created_secs = self
            .created
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let not_after_secs = self
            .not_after
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        StandingRecordSummary {
            id: self.id.to_string(),
            agent_id: self.agent_id.clone(),
            agent_name,
            identity: self.display_identity(),
            project_dir: self.project.canonical_dir.to_string_lossy().into_owned(),
            launch: self.launch.map(|l| ids::encode(&l.launch_id, 26)),
            revision: self.launch.map(|l| l.revision),
            bindings,
            created_secs,
            remaining_secs: self.remaining(now).as_secs(),
            not_after_secs,
        }
    }
}

/// Why a standing approval cannot be created or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandingError {
    /// Caller/requester is not a builtin executable/signature-matched agent,
    /// or has a code-selecting environment variable (`identity_not_standing_capable`).
    IdentityNotStandingCapable,
    /// Linux agent executable is outside the agent's catalog `install_trees`
    /// (`identity_outside_install_tree`).
    IdentityOutsideInstallTree,
    /// Managed MCP project launch is not `BindingStrength::Bound`
    /// (`launch_not_standing_capable`).
    LaunchNotStandingCapable,
    /// Policy epoch sidecar is unverified (`policy_epoch_unverified`).
    PolicyEpochUnverified,
    /// Options are invalid (`--standing` > 30d, 0s, combined with `--once` or `--live`,
    /// or binding a `Live` or `Unknown` item).
    InvalidOptions(OptionsError),
}

/// Which standing approvals to revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandingRevokeSelector {
    Id(StandingId),
    All,
}

/// Checks whether `subject` is eligible for a standing approval and returns
/// its `(agent_id, CodeIdentity)`.
pub fn extract_code_identity(
    subject: &SubjectEvidence,
    catalog: &AgentCatalog,
    home: Option<&Path>,
) -> Result<(String, CodeIdentity), StandingError> {
    if subject.kind() != SubjectKind::Agent {
        return Err(StandingError::IdentityNotStandingCapable);
    }
    let Some((idx, label)) = subject.nearest_agent() else {
        return Err(StandingError::IdentityNotStandingCapable);
    };
    if idx != subject.root_index()
        || !label.may_root_above_session()
        || subject.nearest_agent_env_selects_code()
    {
        return Err(StandingError::IdentityNotStandingCapable);
    }
    let Some(exe) = subject
        .chain()
        .get(idx)
        .and_then(|a| a.instance.exe.as_ref())
    else {
        return Err(StandingError::IdentityNotStandingCapable);
    };
    if let Some(sig) = &exe.signature {
        let Some(team) = &sig.team_id else {
            return Err(StandingError::IdentityNotStandingCapable);
        };
        if !catalog.has_builtin_signature(&label.id, team, &sig.identifier) {
            return Err(StandingError::IdentityNotStandingCapable);
        }
        return Ok((
            label.id.clone(),
            CodeIdentity::MacSignature {
                team: team.clone(),
                identifier: sig.identifier.clone(),
            },
        ));
    }
    if let Some(sha256) = exe.sha256 {
        if !catalog.within_install_tree(&label.id, &exe.path, home) {
            return Err(StandingError::IdentityOutsideInstallTree);
        }
        return Ok((
            label.id.clone(),
            CodeIdentity::LinuxSha256 {
                digests: vec![sha256],
            },
        ));
    }
    Err(StandingError::IdentityNotStandingCapable)
}

/// Checks whether `r`'s managed-project launch (if any) is eligible for a
/// standing approval (`BindingStrength::Bound` stdio launch only).
pub fn extract_launch(r: &AccessRequest) -> Result<Option<LaunchRef>, StandingError> {
    match &r.managed {
        None => Ok(None),
        Some(m) => {
            if m.origin.is_some() || m.strength != Some("bound") {
                return Err(StandingError::LaunchNotStandingCapable);
            }
            let Some(launch) = m.launch else {
                return Err(StandingError::LaunchNotStandingCapable);
            };
            Ok(Some(launch))
        }
    }
}

/// Verifies that every binding of `r` is currently `Classification::Test` in
/// `items`, and returns the standing bindings.
pub fn check_test_bindings(
    r: &AccessRequest,
    items: &[ItemMeta],
) -> Result<Vec<StandingBinding>, StandingError> {
    if r.bindings.is_empty() {
        return Err(StandingError::InvalidOptions(OptionsError::StandingInvalid));
    }
    let mut out = Vec::with_capacity(r.bindings.len());
    for b in &r.bindings {
        let Some(item) = items.iter().find(|m| m.id == b.binding.item) else {
            return Err(StandingError::InvalidOptions(OptionsError::StandingInvalid));
        };
        if item.details.classification != Classification::Test {
            return Err(StandingError::InvalidOptions(OptionsError::StandingNotTest));
        }
        out.push(StandingBinding {
            env_name: b.binding.env_name.as_str().to_owned(),
            item: b.binding.item,
            field: b.binding.field,
        });
    }
    Ok(out)
}

fn code_identity_matches(
    identity: &CodeIdentity,
    agent_id: &str,
    exe: &envcloak_sys::ExeIdentity,
    catalog: &AgentCatalog,
) -> bool {
    match identity {
        CodeIdentity::MacSignature { team, identifier } => {
            exe.signature.as_ref().is_some_and(|sig| {
                sig.team_id.as_deref() == Some(team.as_str())
                    && sig.identifier == *identifier
                    && catalog.has_builtin_signature(agent_id, team, identifier)
            })
        }
        CodeIdentity::LinuxSha256 { digests } => exe.sha256.is_some_and(|d| digests.contains(&d)),
    }
}

impl StandingRecord {
    /// Recomputes whether every item bound by this standing record still
    /// exists in `items` and has `Classification::Test` (SPEC §10b).
    pub fn items_are_test(&self, items: &[ItemMeta]) -> bool {
        !self.bindings.is_empty()
            && self.bindings.iter().all(|sb| {
                items
                    .iter()
                    .find(|m| m.id == sb.item)
                    .is_some_and(|m| m.details.classification == Classification::Test)
            })
    }

    /// Whether this record's launch binding matches `launch` (both launch id
    /// and revision).
    pub fn launch_matches(&self, launch: Option<LaunchRef>) -> bool {
        match (self.launch, launch) {
            (None, None) => true,
            (Some(a), Some(b)) => a.launch_id == b.launch_id && a.revision == b.revision,
            _ => false,
        }
    }
}

fn bindings_covered_and_test(rec: &StandingRecord, r: &AccessRequest, items: &[ItemMeta]) -> bool {
    rec.items_are_test(items)
        && !r.bindings.is_empty()
        && r.bindings.iter().all(|b| {
            let is_test = items
                .iter()
                .find(|m| m.id == b.binding.item)
                .is_some_and(|m| m.details.classification == Classification::Test);
            is_test
                && rec.bindings.iter().any(|sb| {
                    sb.env_name == b.binding.env_name.as_str()
                        && sb.item == b.binding.item
                        && sb.field == b.binding.field
                })
        })
}

/// Builds the [`StandingSummary`] for a pending request's descriptor.
pub fn describe_standing(
    r: &AccessRequest,
    appends_to: Option<StandingId>,
) -> Option<StandingSummary> {
    let (idx, label) = r.subject.nearest_agent()?;
    if idx != r.subject.root_index() || !label.may_root_above_session() {
        return None;
    }
    let exe = r.subject.chain().get(idx)?.instance.exe.as_ref()?;
    let linux_sha256 = exe.sha256.map(|d| hex(&d));
    let recognized_release = exe.sha256.and_then(|d| recognized_release(&label.id, &d));
    Some(StandingSummary {
        exe: exe.path.to_string_lossy().into_owned(),
        linux_sha256,
        recognized_release,
        appends_to: appends_to.map(|id| id.to_string()),
    })
}

/// The daemon's standing-approval store, loaded from `policies.sealed` at
/// unlock and kept in sync with write-through vault transactions.
#[derive(Debug, Clone, Default)]
pub struct StandingStore {
    records: BTreeMap<StandingId, StandingRecord>,
}

impl StandingStore {
    /// An empty standing store.
    pub fn new() -> Self {
        StandingStore {
            records: BTreeMap::new(),
        }
    }

    /// Loads all standing approvals from an unlocked [`Vault`].
    pub fn from_vault(vault: &Vault) -> Result<Self, VaultError> {
        let mut records = BTreeMap::new();
        for (id, record) in vault.policies()? {
            if let PolicyRecord::StandingApproval(a) = record {
                let sr = StandingRecord::from_vault(id, a);
                records.insert(sr.id, sr);
            }
        }
        Ok(StandingStore { records })
    }

    /// Inserts or replaces a standing record in memory.
    pub fn insert(&mut self, record: StandingRecord) {
        self.records.insert(record.id, record);
    }

    /// Removes a standing record by id.
    pub fn remove(&mut self, id: StandingId) -> Option<StandingRecord> {
        self.records.remove(&id)
    }

    /// Clears all standing records in memory.
    pub fn clear(&mut self) -> usize {
        let n = self.records.len();
        self.records.clear();
        n
    }

    /// All standing records in id order.
    pub fn all_records(&self) -> impl Iterator<Item = &StandingRecord> {
        self.records.values()
    }

    /// Unexpired standing records at `now`, in id order.
    pub fn records(&self, now: SystemTime) -> impl Iterator<Item = &StandingRecord> {
        self.records.values().filter(move |r| !r.expired(now))
    }

    /// Record `id`, if present.
    pub fn get(&self, id: StandingId) -> Option<&StandingRecord> {
        self.records.get(&id)
    }

    /// Number of unexpired standing records at `now`.
    pub fn len(&self, now: SystemTime) -> usize {
        self.records(now).count()
    }

    /// Whether there are no unexpired standing records at `now`.
    pub fn is_empty(&self, now: SystemTime) -> bool {
        self.len(now) == 0
    }

    /// On Linux, after an agent self-updates to a new binary digest within
    /// its install tree, finds the existing unexpired standing record for
    /// the same `(agent_id, project, launch, bindings)` whose digest list
    /// can be updated in place (SPEC §10b).
    pub fn self_update_target(
        &self,
        r: &AccessRequest,
        catalog: &AgentCatalog,
        home: Option<&Path>,
        now: SystemTime,
        items: &[ItemMeta],
    ) -> Option<StandingId> {
        if matches!(r.mode, Mode::SignIn(_)) {
            return None;
        }
        let (agent_id, CodeIdentity::LinuxSha256 { digests }) =
            extract_code_identity(&r.subject, catalog, home).ok()?
        else {
            return None;
        };
        let new_digest = *digests.first()?;
        let launch = extract_launch(r).ok()?;
        let _ = check_test_bindings(r, items).ok()?;
        self.records
            .values()
            .find(|rec| {
                !rec.expired(now)
                    && rec.agent_id == agent_id
                    && rec.project == r.project
                    && rec.launch_matches(launch)
                    && bindings_covered_and_test(rec, r, items)
                    && matches!(
                        &rec.code_identity,
                        CodeIdentity::LinuxSha256 { digests }
                            if !digests.contains(&new_digest) && digests.len() < MAX_DIGESTS
                    )
            })
            .map(|rec| rec.id)
    }

    /// Validates that `r` and `opts` can create (or self-update in place) a
    /// standing approval at `now`, and builds the resulting [`StandingRecord`].
    #[allow(clippy::too_many_arguments)]
    pub fn build_record(
        &self,
        r: &AccessRequest,
        opts: &ApprovalOptions,
        proof: Option<&ApprovalProof>,
        catalog: &AgentCatalog,
        home: Option<&Path>,
        now: SystemTime,
        items: &[ItemMeta],
    ) -> Result<StandingRecord, StandingError> {
        if let Some(p) = proof
            && p.is_refused()
        {
            return Err(StandingError::IdentityNotStandingCapable);
        }
        let Some(standing_ttl) = opts.standing else {
            return Err(StandingError::InvalidOptions(OptionsError::StandingInvalid));
        };
        if standing_ttl.is_zero() || standing_ttl.subsec_nanos() != 0 {
            return Err(StandingError::InvalidOptions(OptionsError::TtlZero));
        }
        if standing_ttl > MAX_STANDING_TTL {
            return Err(StandingError::InvalidOptions(OptionsError::TtlTooLong));
        }
        if opts.uses != Uses::Session
            || !opts.live.is_empty()
            || matches!(r.mode, Mode::SignIn(_))
        {
            return Err(StandingError::InvalidOptions(OptionsError::StandingInvalid));
        }
        // Check launch and bindings and identity.
        let launch = extract_launch(r)?;
        let bindings = check_test_bindings(r, items)?;
        let (agent_id, code_identity) = extract_code_identity(&r.subject, catalog, home)?;

        if let CodeIdentity::LinuxSha256 { ref digests } = code_identity
            && let Some(&new_digest) = digests.first()
        {
            if let Some(existing_id) = self.self_update_target(r, catalog, home, now, items)
                && let Some(existing) = self.records.get(&existing_id)
            {
                let mut updated = existing.clone();
                if let CodeIdentity::LinuxSha256 { ref mut digests } = updated.code_identity {
                    digests.push(new_digest);
                }
                updated.not_after = now + standing_ttl;
                return Ok(updated);
            }
            // If an existing record for the same (agent_id, project, launch, bindings)
            // already has MAX_DIGESTS digests and does not contain new_digest, refuse
            // rather than evicting or silently creating a duplicate.
            let full = self.records.values().any(|rec| {
                !rec.expired(now)
                    && rec.agent_id == agent_id
                    && rec.project == r.project
                    && rec.launch_matches(launch)
                    && bindings_covered_and_test(rec, r, items)
                    && matches!(
                        &rec.code_identity,
                        CodeIdentity::LinuxSha256 { digests }
                            if !digests.contains(&new_digest) && digests.len() >= MAX_DIGESTS
                    )
            });
            if full {
                return Err(StandingError::InvalidOptions(OptionsError::StandingInvalid));
            }
        }

        let id = loop {
            let id = StandingId::generate();
            if !self.records.contains_key(&id) {
                break id;
            }
        };
        Ok(StandingRecord {
            id,
            agent_id,
            code_identity,
            project: r.project.clone(),
            launch,
            bindings,
            created: now,
            not_after: now + standing_ttl,
            proof_kind: proof.map_or(ProofKind::Passphrase, |p| p.kind),
            signature: None,
        })
    }

    /// Standing records whose bound items are no longer all `Classification::Test`
    /// in `items` (reclassified to `Live` or `Unknown`, or removed).
    pub fn invalid_for_items(&self, items: &[ItemMeta]) -> Vec<StandingId> {
        self.records
            .values()
            .filter(|rec| !rec.items_are_test(items))
            .map(|rec| rec.id)
            .collect()
    }

    /// Standing records bound to `launch_id` whose launch revision no longer
    /// matches `current`.
    pub fn invalid_for_launch(
        &self,
        launch_id: &[u8; 16],
        current: Option<LaunchRef>,
    ) -> Vec<StandingId> {
        self.records
            .values()
            .filter(|rec| {
                rec.launch.is_some_and(|l| &l.launch_id == launch_id)
                    && !rec.launch_matches(current)
            })
            .map(|rec| rec.id)
            .collect()
    }

    /// Finds an unexpired standing record covering `r`, if any.
    pub fn find_matching(
        &self,
        r: &AccessRequest,
        subject: &SubjectEvidence,
        launch: Option<LaunchRef>,
        now: SystemTime,
        items: &[ItemMeta],
        catalog: &AgentCatalog,
    ) -> Option<&StandingRecord> {
        if subject.kind() != SubjectKind::Agent || matches!(r.mode, Mode::SignIn(_)) {
            return None;
        }
        let (idx, label) = subject.nearest_agent()?;
        if idx != subject.root_index()
            || !label.may_root_above_session()
            || subject.nearest_agent_env_selects_code()
        {
            return None;
        }
        let exe = subject.chain().get(idx)?.instance.exe.as_ref()?;
        match &r.managed {
            Some(m) => {
                if m.origin.is_some()
                    || m.strength != Some("bound")
                    || m.launch != launch
                    || launch.is_none()
                {
                    return None;
                }
            }
            None => {
                if launch.is_some() {
                    return None;
                }
            }
        }
        self.records.values().find(|rec| {
            !rec.expired(now)
                && rec.agent_id == label.id
                && code_identity_matches(&rec.code_identity, &label.id, exe, catalog)
                && rec.project == r.project
                && rec.launch_matches(launch)
                && bindings_covered_and_test(rec, r, items)
        })
    }

    /// Checks whether a standing approval covers `r`, and if so, mints a
    /// `session` grant in `grants` rooted at `subject.root()` with TTL
    /// `min(DEFAULT_TTL, MAX_AGENT_TTL, not_after - now)` and returns the
    /// `(StandingId, GrantId)` pair.
    #[allow(clippy::too_many_arguments)]
    pub fn match_request(
        &self,
        r: &AccessRequest,
        subject: &SubjectEvidence,
        launch: Option<LaunchRef>,
        now: &Now,
        items: &[ItemMeta],
        catalog: &AgentCatalog,
        grants: &mut GrantStore,
    ) -> Option<(StandingId, GrantId)> {
        let rec = self.find_matching(r, subject, launch, now.wall, items, catalog)?;
        let ttl = DEFAULT_TTL.min(MAX_AGENT_TTL).min(rec.remaining(now.wall));
        let standing_items = rec.bindings.iter().map(|b| b.item).collect();
        let grant_id = grants.mint_from_standing_items(r, ttl, now, standing_items)?;
        Some((rec.id, grant_id))
    }

    /// Whether any unexpired standing record could cover `r` if the policy
    /// epoch were verified (used when `EpochState::Unverified` to refuse
    /// `policy_epoch_unverified`).
    pub fn would_match(
        &self,
        r: &AccessRequest,
        now: SystemTime,
        items: &[ItemMeta],
        catalog: &AgentCatalog,
    ) -> bool {
        let launch = ManagedRequest::launch(r);
        self.find_matching(r, &r.subject, launch, now, items, catalog)
            .is_some()
    }
}

/// Summary of one standing approval for `standing.list` and `standing.confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingRecordSummary {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub identity: String,
    pub project_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    pub bindings: Vec<String>,
    pub created_secs: u64,
    pub remaining_secs: u64,
    pub not_after_secs: u64,
}

/// Canonical byte encoding of the standing-approval set for
/// `envcloak standing confirm`.
pub fn canonical_confirm_statement(records: &[StandingRecordSummary]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(STANDING_CONFIRM_DOMAIN);
    let mut push = |s: &str| {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&s.as_bytes()[..len as usize]);
    };
    push(&records.len().to_string());
    for r in records {
        push(&r.id);
        push(&r.agent_id);
        push(&r.agent_name);
        push(&r.identity);
        push(&r.project_dir);
        push(r.launch.as_deref().unwrap_or(""));
        push(if r.launch.is_some() { "1" } else { "0" });
        push(&r.revision.unwrap_or(0).to_string());
        push(if r.revision.is_some() { "1" } else { "0" });
        push(&r.bindings.len().to_string());
        for b in &r.bindings {
            push(b);
        }
        push(&r.created_secs.to_string());
        push(&r.not_after_secs.to_string());
    }
    out
}

/// SHA-256 of [`canonical_confirm_statement`].
pub fn confirm_statement_digest(records: &[StandingRecordSummary]) -> [u8; 32] {
    Sha256::digest(canonical_confirm_statement(records)).into()
}

/// Renders the confirmation statement shown by `envcloak standing confirm`.
pub fn render_confirm_statement(records: &[StandingRecordSummary]) -> String {
    use core::fmt::Write as _;
    let e = escape_for_display;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Confirm standing approvals (policy epoch sidecar is missing or behind the vault):"
    );
    if records.is_empty() {
        let _ = writeln!(out, "  (no standing approvals in the vault)");
    } else {
        for r in records {
            let _ = writeln!(out, "  {}", e(&r.id));
            let _ = writeln!(
                out,
                "    agent: {} ({}), {}",
                e(&r.agent_name),
                e(&r.agent_id),
                e(&r.identity)
            );
            let _ = writeln!(out, "    project: {}", e(&r.project_dir));
            if let (Some(l), Some(rev)) = (&r.launch, r.revision) {
                let _ = writeln!(out, "    launch: {} revision {rev}", e(l));
            }
            let bindings: Vec<String> = r.bindings.iter().map(|b| e(b)).collect();
            let _ = writeln!(out, "    bindings: {}", bindings.join(", "));
        }
    }
    out.push_str(
        "The passphrase you enter confirms these standing approvals and restores the policy-epoch sidecar.\n",
    );
    out
}
