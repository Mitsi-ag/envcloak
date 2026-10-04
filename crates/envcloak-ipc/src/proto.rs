//! Messages: JSON-RPC 2.0 over [`Frame`]s (SPEC §4.3, §4.4; the format is
//! in docs/IPC.md).
//!
//! - A request is `{"jsonrpc":"2.0","id":N,"method":"...","params":{...}}`
//!   and gets exactly one response with the same `id`: `result`, or
//!   `error` with a numeric `code`, a fixed `message`, and `data.kind`, a
//!   stable token (with `data.reason` for some kinds). Notifications and
//!   batches are not used.
//! - Each method is a [`Method`] type naming its parameters and result, so
//!   a client cannot read one method's result as another's.
//! - Methods named `app.*` belong to the `app` role (SPEC §4.3). Before the
//!   macOS app (M3) no peer has that role: the daemon rejects them with
//!   [`ErrorKind::RoleDenied`] and audits the attempt.
//! - Parsing never copies a string out of the frame except the fixed
//!   tokens of an error. Unknown fields are refused. Errors are
//!   [`RpcError`]s built from fixed tokens: a client never shows text it
//!   received, and the daemon never shows what a client sent.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use envcloak_policy::{
    ApprovalOptions, Binding, EnvFileNames, EnvFileRef, EnvName, ManifestError, PendingDescriptor,
    PlainName,
};

use crate::frame::{DecodeError, Frame, FrameError};
use crate::view::{
    AddedView, ApprovedView, AuditVerifyView, BackupBegunView, BackupCommittedView, BackupListView,
    BackupPutView, BackupResultView, BackupView, CheckView, CreatedView, DecisionView, DeniedView,
    FileBackupCreatorView, FileBackupView, GrantsView, ImportPlanView, ItemView, ItemsView,
    LockedView, PendingListView, PendingStateView, RecoveredView, RecoveryConfirmedView,
    RemovedView, RestoreFileView, RestoreLeaseView, RevokedView, RotatedView, ScanMatchView,
    StatusView, TargetView, UnlockedView, VerifyView,
};
use crate::wire_secret::WireSecret;

/// The protocol version string every message carries.
pub const JSONRPC: &str = "2.0";

/// A method: its name, its parameters and its result.
pub trait Method {
    const NAME: &'static str;
    type Params: Serialize + for<'de> Deserialize<'de>;
    type Output: Serialize + for<'de> Deserialize<'de>;
}

/// Parameters of a method that takes none: `{}`, or no `params` at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// `status`: the daemon, its vault and its lock. Metadata only.
#[derive(Debug)]
pub struct Status;

impl Method for Status {
    const NAME: &'static str = "status";
    type Params = NoParams;
    type Output = StatusView;
}

/// `vault.create`: creates the vault and leaves it unlocked, or locked
/// when a lock arrived while Argon2id ran ([`CreatedView::locked`]).
#[derive(Debug)]
pub struct VaultCreate;

impl Method for VaultCreate {
    const NAME: &'static str = "vault.create";
    type Params = VaultCreateParams;
    type Output = CreatedView;
}

/// The passphrase and the Recovery Kit the client generated and showed,
/// and the Argon2id memory for both envelopes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultCreateParams {
    pub passphrase: WireSecret,
    /// The kit as the user wrote it down (`RecoveryKit::to_display`).
    pub recovery_kit: WireSecret,
    /// Argon2id memory in KiB, 64 MiB to 4 GiB; the default (256 MiB) when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_memory_kib: Option<u32>,
}

/// `unlock`: unlocks with the passphrase. A proof: refused from a caller
/// that is not a terminal subject (an agent by any evidence, or no
/// terminal session; SPEC §10b), and counted by the attempt limiter.
#[derive(Debug)]
pub struct Unlock;

impl Method for Unlock {
    const NAME: &'static str = "unlock";
    type Params = UnlockParams;
    type Output = UnlockedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockParams {
    pub passphrase: WireSecret,
    /// Agent marker names set in the caller's environment, never values
    /// (SPEC §10a "caller-asserted"; they only tighten).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `lock`: locks. Locking only tightens, so it needs no proof.
#[derive(Debug)]
pub struct Lock;

impl Method for Lock {
    const NAME: &'static str = "lock";
    type Params = NoParams;
    type Output = LockedView;
}

/// `run.request`: the decision for a run (SPEC §6.1 steps 2 to 5, §10b):
/// covered by a grant, pending an approval, or denied. A covered request
/// is a delivery: its answer carries the value of each binding, sent only
/// after the request's audit entry is on disk.
#[derive(Debug)]
pub struct RunRequest;

impl Method for RunRequest {
    const NAME: &'static str = "run.request";
    type Params = RunRequestParams;
    type Output = RunAnswer;
}

/// What `run.request` answers: the decision, and with a covered one the
/// values of the run's bindings, one per variable, in the order the daemon
/// resolved them. Values cross only here, and only to a client that has
/// verified the daemon (SPEC §4.4).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAnswer {
    pub decision: DecisionView,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<ReleasedValue>,
}

impl RunAnswer {
    /// A decision that releases nothing.
    pub fn decided(decision: DecisionView) -> Self {
        RunAnswer {
            decision,
            values: Vec::new(),
        }
    }

    /// Whether the answer has the shape a daemon sends: values only with a
    /// covered decision, each under a variable name and a slug of the
    /// right shape, no variable twice, and no value empty or holding a
    /// NUL byte. A program answering in the daemon's place could send
    /// anything (SPEC §1.1); a client uses no answer that fails this.
    pub fn well_formed(&self) -> bool {
        if !self.values.is_empty() && !matches!(self.decision, DecisionView::Covered { .. }) {
            return false;
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.values.len());
        for v in &self.values {
            let value = v.value.as_secret();
            if EnvName::new(&v.env_name).is_err()
                || envcloak_core::vault::Slug::new(&v.slug).is_err()
                || value.is_empty()
                || value.contains_byte(0)
                || names.contains(&v.env_name.as_str())
            {
                return false;
            }
            names.push(&v.env_name);
        }
        true
    }
}

/// One binding's value, released to a covered run.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasedValue {
    /// The variable the value is set in.
    pub env_name: String,
    /// The item's slug, which labels the value in redacted output.
    pub slug: String,
    /// The item takes values of 8 to 15 bytes (SPEC §6.1 step 6).
    pub allow_short: bool,
    pub value: WireSecret,
}

/// What `envcloak run` sends: the manifest it found, the bindings it asks
/// for beyond the manifest, the command line as display text, and the
/// agent markers set in its environment (their names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequestParams {
    /// The absolute path of `envcloak.toml`. The daemon opens it itself.
    pub manifest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// `--ref NAME=<slug>[#field]` arguments, in order.
    #[serde(default)]
    pub refs: Vec<String>,
    /// `--env-file`: its references and the names of its ordinary
    /// variables. Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<EnvFileParams>,
    /// The command and its arguments. Display only.
    pub argv: Vec<String>,
    /// Marker names, never values (SPEC §10a "caller-asserted").
    #[serde(default)]
    pub claims: Vec<String>,
}

/// What `envcloak run` sends of an `--env-file` (SPEC §6.1 step 2): what
/// the daemon needs to resolve the run's bindings, and nothing else. An
/// ordinary variable's value stays with the CLI, which sets it for the
/// command.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFileParams {
    /// Each `NAME=envcloak://<slug>[#field]` entry, as `NAME=<slug>[#field]`
    /// with its line, in file order.
    #[serde(default)]
    pub refs: Vec<EnvFileLine>,
    /// The name of each ordinary variable, with its line, in file order.
    #[serde(default)]
    pub plain: Vec<EnvFileLine>,
}

/// One entry of an [`EnvFileParams`]: its line, from 1, and its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFileLine {
    pub line: u32,
    pub text: String,
}

impl From<&EnvFileNames> for EnvFileParams {
    fn from(n: &EnvFileNames) -> Self {
        EnvFileParams {
            refs: n
                .refs
                .iter()
                .map(|r| EnvFileLine {
                    line: r.line,
                    text: format!("{}={}", r.binding.env_name, r.binding.reference),
                })
                .collect(),
            plain: n
                .plain
                .iter()
                .map(|p| EnvFileLine {
                    line: p.line,
                    text: p.name.to_string(),
                })
                .collect(),
        }
    }
}

impl EnvFileParams {
    /// The names a client sent, checked as the CLI checked them.
    ///
    /// # Errors
    /// A reference that is not `NAME=<slug>[#field]`, or a name that is not
    /// a variable name. The error names the kind, never the text.
    pub fn names(&self) -> Result<EnvFileNames, ManifestError> {
        Ok(EnvFileNames {
            refs: self
                .refs
                .iter()
                .map(|r| {
                    Ok(EnvFileRef {
                        line: r.line,
                        binding: Binding::parse_arg(&r.text)?,
                    })
                })
                .collect::<Result<_, ManifestError>>()?,
            plain: self
                .plain
                .iter()
                .map(|p| {
                    Ok(PlainName {
                        line: p.line,
                        name: EnvName::new(&p.text)?,
                    })
                })
                .collect::<Result<_, ManifestError>>()?,
        })
    }
}

/// `pending.get`: what an approval surface shows for a pending request.
/// Metadata only. Served only to a caller that may give a proof (SPEC
/// §10b), so `envcloak approve` run where no proof is taken fails before
/// it shows the statement or asks for the passphrase.
#[derive(Debug)]
pub struct PendingGet;

impl Method for PendingGet {
    const NAME: &'static str = "pending.get";
    type Params = PendingGetParams;
    type Output = PendingDescriptor;
}

/// A pending request's id, and the caller's claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingGetParams {
    /// 8 Crockford base32 characters.
    pub request: String,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// A pending request's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestParams {
    /// 8 Crockford base32 characters.
    pub request: String,
}

/// `pending.state`: how a pending request stands (SPEC §6.1 step 4, M2
/// plan D-04), answered at once: `pending`, `approved`, `denied`,
/// `expired` or `unknown`. Told only to a caller whose kernel-verified
/// chain holds the request's root instance; anyone else gets `unknown`, as
/// for an id no request has. Each poll counts against the caller's root's
/// limit ([`ErrorKind::Busy`] beyond it). It opens no pending request and
/// writes no audit entry; `envcloak run --wait` asks it on fresh
/// connections and never holds one open while it waits.
#[derive(Debug)]
pub struct PendingPoll;

impl Method for PendingPoll {
    const NAME: &'static str = "pending.state";
    type Params = PendingStateParams;
    type Output = PendingStateView;
}

/// A pending request's id. No claims: the answer goes by the caller's
/// kernel-verified chain alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStateParams {
    /// 8 Crockford base32 characters.
    pub request: String,
}

/// `pending.list`: the requests waiting for approval that the caller may
/// approve (`envcloak pending`). Metadata only. A caller whose proof the
/// daemon would refuse (SPEC §10b) gets an empty list, without being told
/// why, and a request is left out for a caller in its requester's session
/// or on its terminal: an approval surface does not show a request to a
/// caller whose proof it would refuse.
#[derive(Debug)]
pub struct PendingList;

impl Method for PendingList {
    const NAME: &'static str = "pending.list";
    type Params = PendingListParams;
    type Output = PendingListView;
}

/// The caller's claims.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingListParams {
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `approve`: creates a grant from a pending request with the passphrase
/// as the proof (SPEC §10b "Approval proofs").
#[derive(Debug)]
pub struct Approve;

impl Method for Approve {
    const NAME: &'static str = "approve";
    type Params = ApproveParams;
    type Output = ApprovedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveParams {
    pub request: String,
    pub options: ApprovalOptions,
    /// SHA-256 of the canonical statement the approver read, as 64 hex
    /// characters (`envcloak_policy::statement_digest`).
    pub digest: String,
    pub passphrase: WireSecret,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `deny`: refuses a pending request. Tightening needs no proof.
#[derive(Debug)]
pub struct Deny;

impl Method for Deny {
    const NAME: &'static str = "deny";
    type Params = RequestParams;
    type Output = DeniedView;
}

/// `grants.list`: the grants in force. Metadata only.
#[derive(Debug)]
pub struct GrantsList;

impl Method for GrantsList {
    const NAME: &'static str = "grants.list";
    type Params = NoParams;
    type Output = GrantsView;
}

/// `grants.revoke`: ends one grant or all. Tightening needs no proof.
#[derive(Debug)]
pub struct GrantsRevoke;

impl Method for GrantsRevoke {
    const NAME: &'static str = "grants.revoke";
    type Params = RevokeParams;
    type Output = RevokedView;
}

/// One grant by id, or every grant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeParams {
    /// 26 Crockford base32 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(default)]
    pub all: bool,
}

/// `audit.verify`: checks the audit log against the head saved in the
/// vault's header (SPEC §15.2 gate 33). Counts and sequence numbers only;
/// no entry's contents cross.
#[derive(Debug)]
pub struct AuditVerify;

impl Method for AuditVerify {
    const NAME: &'static str = "audit.verify";
    type Params = NoParams;
    type Output = AuditVerifyView;
}

/// `items.list`: every item's metadata, sorted by slug (`envcloak ls`).
/// Never a value. The account an item belongs to is personal, so it is
/// sent only when asked for (`ls --long`).
#[derive(Debug)]
pub struct ItemsList;

impl Method for ItemsList {
    const NAME: &'static str = "items.list";
    type Params = ListParams;
    type Output = ItemsView;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// Include each item's account.
    #[serde(default)]
    pub long: bool,
}

/// `items.show`: one item's metadata, its account and links included
/// (`envcloak show`). Never a value.
#[derive(Debug)]
pub struct ItemsShow;

impl Method for ItemsShow {
    const NAME: &'static str = "items.show";
    type Params = SlugParams;
    type Output = ItemView;
}

/// An item by its slug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlugParams {
    pub slug: String,
}

/// `items.check`: whether references resolve to the vault's items
/// (`envcloak check`): every binding of the manifest the daemon opens
/// itself, in `[env]` and in each profile, and each reference in `refs`
/// (an env file's, which the CLI read). Metadata only.
#[derive(Debug)]
pub struct ItemsCheck;

impl Method for ItemsCheck {
    const NAME: &'static str = "items.check";
    type Params = CheckParams;
    type Output = CheckView;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckParams {
    /// The absolute path of `envcloak.toml`, when there is one. The daemon
    /// opens it itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    /// `NAME=<slug>[#field]` references, answered in order.
    #[serde(default)]
    pub refs: Vec<String>,
}

/// `items.add`: a new secret item with one field holding `value` (SPEC
/// §6.3). Adding needs no proof: nothing is bound to a new item yet
/// (SPEC §10b "Writes that need a proof").
#[derive(Debug)]
pub struct ItemsAdd;

impl Method for ItemsAdd {
    const NAME: &'static str = "items.add";
    type Params = AddParams;
    type Output = AddedView;
}

/// What `envcloak add` sends: names the person gave, and the value.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddParams {
    /// The slug; derived from the provider when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// A provider registry id; detected from the value when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The field's name; `value` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Who owns or pays for the key, such as an email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The variable the value usually goes in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_hint: Option<String>,
    /// Values of 8 to 15 bytes may be injected (SPEC §6.1).
    #[serde(default)]
    pub allow_short: bool,
    pub value: WireSecret,
    /// As [`UnlockParams::claims`], for the audit entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `items.target`: the item a `rotate` or `rm` would change, for the
/// statement the person reads before giving the passphrase. Served only
/// to a caller that may give a proof (SPEC §10b), so where none is taken
/// the command stops before it asks for anything.
#[derive(Debug)]
pub struct ItemsTarget;

impl Method for ItemsTarget {
    const NAME: &'static str = "items.target";
    type Params = TargetParams;
    type Output = TargetView;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetParams {
    pub slug: String,
    /// The field, when the item has several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `items.rotate`: replaces a field's value, keeping the old one as the
/// newest of up to three prior values. A proof: the passphrase, from a
/// terminal subject (SPEC §10b). Grants that bind the item stay.
#[derive(Debug)]
pub struct ItemsRotate;

impl Method for ItemsRotate {
    const NAME: &'static str = "items.rotate";
    type Params = RotateParams;
    type Output = RotatedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateParams {
    pub slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The item's id from [`TargetView`]: the rotation is refused when the
    /// slug names another item by now.
    pub item: String,
    pub value: WireSecret,
    pub passphrase: WireSecret,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `items.remove`: deletes an item, after an encrypted backup of the
/// vault that keeps its values. A proof, as [`ItemsRotate`]. Grants and
/// pending requests that bind the item end.
#[derive(Debug)]
pub struct ItemsRemove;

impl Method for ItemsRemove {
    const NAME: &'static str = "items.remove";
    type Params = RemoveParams;
    type Output = RemovedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveParams {
    pub slug: String,
    /// As [`RotateParams::item`].
    pub item: String,
    pub passphrase: WireSecret,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `import.plan`: what importing these env-file entries would do (SPEC
/// §6.4, `envcloak init --import` and `envcloak import --scan`): which
/// are secrets, which items the vault holds with the same value already,
/// which new items would be made and under what slugs, and which values
/// more than one item holds (gate 10). Nothing is written. The daemon
/// compares values by keyed hash; the CLI has no key.
#[derive(Debug)]
pub struct ImportPlan;

impl Method for ImportPlan {
    const NAME: &'static str = "import.plan";
    type Params = ImportParams;
    type Output = ImportPlanView;
}

/// `import.commit`: the import `import.plan` described, in one vault
/// transaction. Refused with [`ErrorKind::PlanChanged`] unless the plan,
/// worked out again now, is the one with `digest`: the person approved
/// that one. Importing needs no proof, as `items.add` needs none.
#[derive(Debug)]
pub struct ImportCommit;

impl Method for ImportCommit {
    const NAME: &'static str = "import.commit";
    type Params = ImportCommitParams;
    type Output = ImportPlanView;
}

/// The entries of the env files an import read: each with its value.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportParams {
    /// The directories the entries come from.
    pub projects: Vec<ImportProject>,
    pub entries: Vec<ImportEntry>,
    /// As [`UnlockParams::claims`], for the audit entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// A directory an import read env files in: where its manifest goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportProject {
    /// Its absolute path. Display text, and where the CLI writes.
    pub dir: String,
    /// The name new items are given under (`openai/<name>`): one slug
    /// part.
    pub name: String,
}

/// One `NAME=value` entry of an env file, a shell profile, an agent's MCP
/// config, the AWS files or a vendor's export.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportEntry {
    /// Where the entry's item belongs: a project, or the machine.
    pub scope: ImportScope,
    /// The file: relative to the project's directory, or for a machine
    /// entry its display path. Display text only.
    pub file: String,
    pub line: u32,
    /// The profile the file is for; `None` for `[env]`. A machine entry
    /// has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub name: String,
    pub value: WireSecret,
}

/// Where an imported entry's item belongs (SPEC §6.4, M2 plan M2-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportScope {
    /// A project: the index of its directory in [`ImportParams::projects`].
    /// A new item is named `<provider or variable>/<project>`.
    Project(u32),
    /// The machine: a value found outside any project (a shell profile, an
    /// agent's MCP config, the AWS files, a vendor's export). A new item
    /// is named `<provider or variable>/<label>`, numbered when taken, and
    /// no project is adopted for it.
    Machine(MachineScope),
}

/// A machine-scope entry's source and label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineScope {
    pub source: MachineSource,
    /// One slug part that names where the value was found
    /// (`secrets-sh`, `mcp-claude-code-fixture-stdio`). One shaped like a
    /// key is never kept: the daemon names the item `<base>/machine`.
    pub label: String,
}

/// Where a machine-scope entry was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineSource {
    /// A shell profile or a file one sources.
    Profile,
    /// An agent's MCP server config.
    McpConfig,
    /// The AWS shared credentials or config file.
    Aws,
    /// A vendor's export (1Password, Bitwarden, Doppler, Infisical,
    /// Vercel).
    Export,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCommitParams {
    pub import: ImportParams,
    /// [`ImportPlanView::digest`] of the plan shown.
    pub digest: String,
}

/// `import.verify`: whether plaintext env files may be deleted (SPEC §6.4
/// "Deleting plaintext after import", gate 16): whether every secret each
/// file holds is in the vault where the manifest binds its variable,
/// whether every reference of the manifest resolves, and whether the
/// Recovery Kit is confirmed. The daemon opens the manifest itself.
#[derive(Debug)]
pub struct ImportVerify;

impl Method for ImportVerify {
    const NAME: &'static str = "import.verify";
    type Params = VerifyParams;
    type Output = VerifyView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyParams {
    /// The absolute path of `envcloak.toml`.
    pub manifest: String,
    pub files: Vec<VerifyFile>,
    /// As [`UnlockParams::claims`]: who asks decides which values the
    /// daemon compares (IMPORT.md "Who may compare values").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// One env file whose deletion is asked about: its entries with values.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyFile {
    /// Relative to the manifest's directory.
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub entries: Vec<VerifyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEntry {
    pub line: u32,
    pub name: String,
    pub value: WireSecret,
}

/// `scan.match`: candidate tokens a scan found (doctor, scrub, the
/// first-run import, `migrate-mcp`), compared with the vault's `secret`
/// items by keyed hash in the daemon (SPEC §6.4, §6.5; M2 plan D-32). The
/// daemon applies its purpose's rules before comparing: no caller is told
/// whether the vault holds a value short enough to guess unless it may
/// give a proof and the purpose is `import`, and comparisons count against
/// the subject root's two budgets. Candidates are wiped once compared and
/// never stored, logged or audited; the answer names items, never values.
#[derive(Debug)]
pub struct ScanMatch;

impl Method for ScanMatch {
    const NAME: &'static str = "scan.match";
    type Params = ScanMatchParams;
    type Output = ScanMatchView;
}

/// Candidates a call compares at most. With one item holding each, its
/// answer fits in a frame (docs/IPC.md "scan.match").
pub const MAX_SCAN_CANDIDATES: usize = 4096;
/// The largest candidate value, in bytes.
pub const MAX_CANDIDATE: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanMatchParams {
    /// At most [`MAX_SCAN_CANDIDATES`], each id once.
    pub candidates: Vec<ScanCandidate>,
    /// Where the candidates were read, recorded in the audit entry.
    pub source_kind: ScanSource,
    /// What the comparison is for: required, and it decides which
    /// candidates are compared.
    pub purpose: ScanPurpose,
    /// As [`UnlockParams::claims`]: who asks decides which values the
    /// daemon compares.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// One candidate: the caller's id for it, its value and how it was read.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCandidate {
    pub id: u32,
    /// 1 to [`MAX_CANDIDATE`] bytes. A password-form candidate is the
    /// password as its server reads it (escapes decoded).
    pub value: WireSecret,
    pub form: CandidateForm,
}

/// How a candidate was read: a token as it stands, or the password of a
/// URL, of Go's MySQL DSN or of a connection string's `password=` field,
/// which the daemon counts as that form's server reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateForm {
    Raw,
    UrlPassword,
    DsnPassword,
    ConnPassword,
}

/// What a `scan.match` is for (M2 plan D-32). `import` (the first-run
/// scan, `migrate-mcp`) follows the import rules: a value short enough to
/// guess is compared only for a caller that may give a proof. `doctor` and
/// `scrub` compare only values that cannot be guessed (16 characters as a
/// server reads them, or a provider's key pattern), for every caller, so
/// doctor never reports a short value and scrub never rewrites one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPurpose {
    Import,
    Doctor,
    Scrub,
}

impl ScanPurpose {
    /// The purpose as its audit entry records it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ScanPurpose::Import => "import",
            ScanPurpose::Doctor => "doctor",
            ScanPurpose::Scrub => "scrub",
        }
    }
}

/// The kind of place a `scan.match` call's candidates were read: one of
/// the places an item is marked exposed for, the two first-run import
/// sources that are not, or `mixed` for a batch drawn from several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSource {
    EnvFile,
    ShellProfile,
    AgentConfig,
    ConfigBackup,
    Transcript,
    GitHistory,
    SyncedFolder,
    Aws,
    Export,
    Mixed,
}

impl ScanSource {
    /// The source as its audit entry records it.
    pub const fn as_str(self) -> &'static str {
        match self {
            ScanSource::EnvFile => "env_file",
            ScanSource::ShellProfile => "shell_profile",
            ScanSource::AgentConfig => "agent_config",
            ScanSource::ConfigBackup => "config_backup",
            ScanSource::Transcript => "transcript",
            ScanSource::GitHistory => "git_history",
            ScanSource::SyncedFolder => "synced_folder",
            ScanSource::Aws => "aws",
            ScanSource::Export => "export",
            ScanSource::Mixed => "mixed",
        }
    }
}

/// `files.backup`: an encrypted backup of files about to be deleted (SPEC
/// §6.4 "Backups"), under a key of its own wrapped under the `backup`
/// subkey. Answered once it is on disk.
#[derive(Debug)]
pub struct FilesBackup;

impl Method for FilesBackup {
    const NAME: &'static str = "files.backup";
    type Params = FilesBackupParams;
    type Output = FileBackupView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesBackupParams {
    pub files: Vec<BackupFileParams>,
    /// As [`UnlockParams::claims`], for the audit entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// One file's bytes, where it was, and what the deletion leaves of it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFileParams {
    /// Its absolute path.
    pub path: String,
    /// Its permission bits.
    pub mode: u32,
    pub content: WireSecret,
    /// What the deletion leaves of it, which the backup records so that
    /// `init --undo` writes it back only over exactly that (F-78).
    pub left: FileLeft,
}

/// What a deletion leaves of a file (F-78): `"removed"`, or
/// `{"rewritten": "<the SHA-256 of what is left, 64 lower-case hex>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileLeft {
    Removed,
    Rewritten(String),
}

/// `files.show`: what a file backup is, from its sealed manifest, for
/// the statement `envcloak init --undo` shows before the passphrase (SPEC
/// §6.4: the restore statement names the creator): who made it, and each
/// file's path and what the deletion left of it. Metadata only, for a
/// caller that may give a proof, as `files.restore` is.
#[derive(Debug)]
pub struct FilesShow;

impl Method for FilesShow {
    const NAME: &'static str = "files.show";
    type Params = FilesShowParams;
    type Output = FilesShown;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesShowParams {
    /// The backup's id: 26 Crockford base32 characters.
    pub backup: String,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// What `files.show` answers: [`RestoredFiles`] without the files' modes
/// and bytes, so it fits in a frame whenever the restore's answer does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesShown {
    /// As [`RestoredFiles::creator`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<FileBackupCreatorView>,
    pub files: Vec<ShownFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShownFile {
    pub path: String,
    /// As [`RestoredFile::left`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<FileLeft>,
}

/// `files.restore`: the files of a backup, byte for byte, for `envcloak
/// init --undo`, which writes them back. It hands plaintext to the
/// client, so it is a proof: the passphrase, from a terminal subject
/// (SPEC §10b), as `items.rotate` is. Before the passphrase is looked at,
/// as `backup.v2.open_restore` refuses one (SPEC §6.4): a backup that
/// does not record what the deletion left of a file, or who made it,
/// comes back only with `unrecorded` (the recovery form), and one an
/// agent or an unknown process made, or that does not record who made
/// it, only with `created_by_agent_ticked`.
#[derive(Debug)]
pub struct FilesRestore;

impl Method for FilesRestore {
    const NAME: &'static str = "files.restore";
    type Params = FilesRestoreParams;
    type Output = RestoredFiles;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesRestoreParams {
    /// The backup's id: 26 Crockford base32 characters.
    pub backup: String,
    pub passphrase: WireSecret,
    /// The person ticked `--created-by-agent`: the backup may be one an
    /// agent or an unknown process made.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub created_by_agent_ticked: bool,
    /// The recovery form `--unrecorded`: the backup may not record what
    /// the deletion left, so the client writes back only a file that is
    /// missing.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub unrecorded: bool,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// What `files.restore` answers: who made the backup, and each file with
/// its bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredFiles {
    /// Who made the backup, as the daemon sealed it; none for a backup
    /// made before that was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<FileBackupCreatorView>,
    pub files: Vec<RestoredFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredFile {
    pub path: String,
    pub mode: u32,
    pub content: WireSecret,
    /// What the deletion left of it, as its backup recorded; none for a
    /// backup made before that was recorded, which then writes back only
    /// a file that is missing, and only with `unrecorded` (F-78).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<FileLeft>,
}

/// `recovery.confirm`: records that the person holds the Recovery Kit
/// (SPEC §6.4: plaintext is deleted only once it is confirmed), after
/// checking the kit they typed opens the vault. A proof, like `unlock`:
/// taken only from a terminal subject and counted by the attempt limiter.
#[derive(Debug)]
pub struct RecoveryConfirm;

impl Method for RecoveryConfirm {
    const NAME: &'static str = "recovery.confirm";
    type Params = RecoveryConfirmParams;
    type Output = RecoveryConfirmedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfirmParams {
    /// The kit as the user wrote it down.
    pub recovery_kit: WireSecret,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `backup.create`: writes an encrypted backup of the unlocked vault to
/// its `backups` directory (VAULT.md "Backups"). No value crosses and none
/// is written in the clear: the backup opens only with the Recovery Kit.
/// It needs no proof.
#[derive(Debug)]
pub struct BackupCreate;

impl Method for BackupCreate {
    const NAME: &'static str = "backup.create";
    type Params = NoParams;
    type Output = BackupView;
}

/// `vault.recover`: replaces the vault with the one an encrypted backup
/// holds, opened with the Recovery Kit, under a new passphrase, and leaves
/// it unlocked (SPEC §15.1 step 11). A proof, like `unlock`, with the kit:
/// taken only from a terminal subject and counted by the attempt limiter.
/// A vault that was unlocked is locked first, which ends every grant.
#[derive(Debug)]
pub struct VaultRecover;

impl Method for VaultRecover {
    const NAME: &'static str = "vault.recover";
    type Params = RecoverParams;
    type Output = RecoveredView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverParams {
    /// The backup file's absolute path. The daemon opens it itself, never
    /// through a symlink in its last component, and only a regular file.
    pub backup: String,
    /// The kit as the user wrote it down.
    pub recovery_kit: WireSecret,
    /// The vault's passphrase from now on.
    pub new_passphrase: WireSecret,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `backup.v2.begin`: starts a file backup v2 (M2 plan D-07; docs/IPC.md
/// "Backups v2") of files under the allowed roots, and records the
/// caller's process instance as its creator. Only that instance may add
/// chunks, commit and record results. Who made the backup (the subject's
/// kind, evidence and agent) is read from the kernel and sealed by the
/// daemon: there is no field for it, and a request that sends one is
/// `invalid_params`.
#[derive(Debug)]
pub struct BackupBegin;

impl Method for BackupBegin {
    const NAME: &'static str = "backup.v2.begin";
    type Params = BackupBeginParams;
    type Output = BackupBegunView;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBeginParams {
    /// `init`, `scrub`, `agents` or `migrate`.
    pub purpose: String,
    pub files: Vec<BackupPlanFile>,
    /// As [`UnlockParams::claims`]: they only tighten the creator's kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// One file a backup v2 will hold, as declared at its start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPlanFile {
    /// Its absolute path, under an allowed root. Display text, and where a
    /// restore writes it back.
    pub path: String,
    pub size: u64,
    /// Its permission bits.
    pub mode: u32,
}

/// `backup.v2.put`: the next chunk of the next file, from the backup's
/// creator only.
#[derive(Debug)]
pub struct BackupPut;

impl Method for BackupPut {
    const NAME: &'static str = "backup.v2.put";
    type Params = BackupPutParams;
    type Output = BackupPutView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPutParams {
    /// The backup's id from `backup.v2.begin`.
    pub id: String,
    /// The file's index in the begin's `files`.
    pub file: u32,
    /// The chunk's index in its file.
    pub chunk: u32,
    /// Exactly the chunk's bytes: [`BackupBegunView::chunk_size`] for
    /// every chunk but a file's last, the rest for its last.
    pub data: WireSecret,
}

/// `backup.v2.commit`: seals the backup's metadata and puts it in place;
/// from then on its contents never change. From the creator only.
#[derive(Debug)]
pub struct BackupCommit;

impl Method for BackupCommit {
    const NAME: &'static str = "backup.v2.commit";
    type Params = BackupIdParams;
    type Output = BackupCommittedView;
}

/// A backup v2's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupIdParams {
    /// 26 Crockford base32 characters.
    pub id: String,
}

/// `backup.v2.record_result`: what the change left in one file (its
/// SHA-256), once per file, from the creator only, while it lives.
#[derive(Debug)]
pub struct BackupRecordResult;

impl Method for BackupRecordResult {
    const NAME: &'static str = "backup.v2.record_result";
    type Params = BackupResultParams;
    type Output = BackupResultView;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupResultParams {
    pub id: String,
    pub file: u32,
    /// 64 lowercase hex characters.
    pub sha256_after: String,
}

/// `backup.v2.open_restore`: one passphrase proof, from a terminal
/// subject, opens a restore lease on a committed backup v2, bound to the
/// backup, the caller's process instance and its terminal. A backup an
/// agent or an unknown process made opens only with
/// `created_by_agent_ticked`, and one whose results are not all recorded
/// only with `unrecorded`; both are refused before the passphrase is
/// looked at. The lease's audit entry is on disk before the lease is
/// issued, so before the first chunk.
#[derive(Debug)]
pub struct BackupOpenRestore;

impl Method for BackupOpenRestore {
    const NAME: &'static str = "backup.v2.open_restore";
    type Params = OpenRestoreParams;
    type Output = RestoreLeaseView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRestoreParams {
    pub id: String,
    pub passphrase: WireSecret,
    /// The person ticked `--created-by-agent`.
    #[serde(default)]
    pub created_by_agent_ticked: bool,
    /// The recovery-only form `--unrecorded`.
    #[serde(default)]
    pub unrecorded: bool,
    /// As [`UnlockParams::claims`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
}

/// `backup.v2.read`: one chunk of a backup under its restore lease, on
/// any connection of the lease's process. A delivery: plaintext goes only
/// to the process instance the lease is bound to, on its terminal.
#[derive(Debug)]
pub struct BackupRead;

impl Method for BackupRead {
    const NAME: &'static str = "backup.v2.read";
    type Params = BackupReadParams;
    type Output = BackupChunk;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReadParams {
    /// 26 Crockford base32 characters, from `backup.v2.open_restore`.
    pub lease: String,
    pub file: u32,
    pub chunk: u32,
}

/// One chunk of a file, read under a restore lease.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupChunk {
    pub data: WireSecret,
    /// The file's last chunk.
    #[serde(rename = "final")]
    pub last: bool,
    /// With a file's first chunk: where the file goes and what it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<RestoreFileView>,
}

/// `backup.v2.list`: the committed backups v2, newest first, with their
/// creator, purpose and state. Metadata only, to any caller.
#[derive(Debug)]
pub struct BackupList;

impl Method for BackupList {
    const NAME: &'static str = "backup.v2.list";
    type Params = NoParams;
    type Output = BackupListView;
}

/// The client-role methods this daemon serves.
pub const CLIENT_METHODS: [&str; 37] = [
    Status::NAME,
    VaultCreate::NAME,
    Unlock::NAME,
    Lock::NAME,
    RunRequest::NAME,
    PendingGet::NAME,
    PendingPoll::NAME,
    PendingList::NAME,
    Approve::NAME,
    Deny::NAME,
    GrantsList::NAME,
    GrantsRevoke::NAME,
    AuditVerify::NAME,
    ItemsList::NAME,
    ItemsShow::NAME,
    ItemsCheck::NAME,
    ItemsAdd::NAME,
    ItemsTarget::NAME,
    ItemsRotate::NAME,
    ItemsRemove::NAME,
    ImportPlan::NAME,
    ImportCommit::NAME,
    ImportVerify::NAME,
    ScanMatch::NAME,
    FilesBackup::NAME,
    FilesShow::NAME,
    FilesRestore::NAME,
    RecoveryConfirm::NAME,
    BackupCreate::NAME,
    VaultRecover::NAME,
    BackupBegin::NAME,
    BackupPut::NAME,
    BackupCommit::NAME,
    BackupRecordResult::NAME,
    BackupOpenRestore::NAME,
    BackupRead::NAME,
    BackupList::NAME,
];

/// The `app`-role methods (SPEC §4.3): Secure Enclave unlock, signed
/// approval, policy, reveal, the paste sheet, devices and registry
/// overrides. Any other `app.` name is an app method too.
pub const APP_METHODS: [&str; 8] = [
    "app.unlock",
    "app.approve",
    "app.policy.set",
    "app.reveal",
    "app.paste",
    "app.device.add",
    "app.device.remove",
    "app.registry.override",
];

/// The roles a peer can have (SPEC §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Any same-uid peer.
    Client,
    /// The signed macOS app (M3). No peer has it before then.
    App,
}

/// The role a method needs: [`Role::App`] for every `app.` name.
pub fn required_role(method: &str) -> Role {
    if method.starts_with("app.") {
        Role::App
    } else {
        Role::Client
    }
}

/// A method name that is safe to log: the name itself when it is one of
/// [`CLIENT_METHODS`] or [`APP_METHODS`], a fixed placeholder otherwise.
/// A name a client sent can hold anything, a pasted value included.
pub fn loggable_method(method: &str) -> &'static str {
    CLIENT_METHODS
        .iter()
        .chain(APP_METHODS.iter())
        .find(|m| **m == method)
        .copied()
        .unwrap_or(if method.starts_with("app.") {
            "app.(unknown)"
        } else {
            "(unknown)"
        })
}

/// What went wrong, as a stable token (`data.kind`) and a JSON-RPC code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The frame is not JSON.
    ParseError,
    /// The JSON is not a request.
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    /// The method belongs to the `app` role.
    RoleDenied,
    VaultLocked,
    /// No vault exists yet.
    NoVault,
    /// `vault create` found a vault already there.
    VaultExists,
    /// The one error for a wrong passphrase or a damaged unlocker.
    WrongPassphrase,
    /// A new passphrase breaks the rules; `reason` says which.
    PassphraseRejected,
    /// Argon2id parameters out of bounds.
    KdfParams,
    /// Another unlock or `vault create` is running.
    Busy,
    /// A tracer is attached to the daemon, so it will not handle values.
    Traced,
    /// The vault file could not be opened; `reason` says why.
    VaultUnavailable,
    /// The request did not fit in a frame.
    FrameTooLarge,
    /// The caller's ancestry could not be read; `reason` says why.
    Evidence,
    /// The manifest, or the path it was opened from; `reason` says what.
    ManifestInvalid,
    /// A binding the run asked for could not be bound; `reason` says why.
    BindingUnresolved,
    /// The effective policy refuses agent requests for this project.
    PolicyDenied,
    /// The effective mode is proxy, which this build does not have.
    ModeUnsupported,
    /// No pending request has the id, or it expired.
    NoSuchRequest,
    /// The statement digest is not the pending request's with these
    /// options.
    StatementMismatch,
    /// A proof from a caller with an agent in its evidence.
    ProofRefused,
    /// The attempt limiter refused this attempt; `envcloak status` shows
    /// the wait.
    TooManyAttempts,
    /// The vault failed its integrity check: no grant is evaluated from
    /// it, and no proof taken.
    VaultTampered,
    /// The grant store is full.
    TooManyGrants,
    /// The approval options are out of bounds; `reason` says how.
    InvalidOptions,
    /// The audit log could not be read.
    AuditUnavailable,
    /// No item has the slug, or it has no such field; `reason` says which.
    NoSuchItem,
    /// An item with the slug exists already.
    ItemExists,
    /// A new item's names or a new value are not accepted; `reason` says
    /// what.
    InvalidItem,
    /// The encrypted backup `rm` writes first could not be written, so
    /// nothing was removed.
    BackupFailed,
    /// The import worked out now is not the plan shown.
    PlanChanged,
    /// No file backup has the id, or it was purged.
    NoSuchBackup,
    /// A file backup could not be written, or could not be read back.
    FilesBackupFailed,
    /// The caller's process tree had as many values compared with the
    /// vault as an hour allows (`import.plan`, `import.commit`,
    /// `import.verify`); or, with the reason `limited`, a `scan.match`
    /// whose budget for its candidates was spent before it compared any.
    TooManyChecks,
    /// A delivery's audit entry could not be written, so nothing was
    /// released (`files.restore`).
    AuditFailed,
    /// The file named for `vault.recover` is not a readable vault backup:
    /// missing, not a regular file, altered, cut short, or of a newer
    /// format.
    BackupUnusable,
    /// A `run.request` over a pending cap (SPEC §10a): no request was
    /// opened and nothing refused; `reason` names the cap. A waiter asks
    /// again with backoff.
    TooManyPending,
    /// A backup v2 call from another process instance than the one that
    /// began the backup: nothing changed, and no metadata is returned.
    NotBackupOwner,
    /// A backup v2 restore refused before the passphrase was looked at;
    /// `reason` is `created_by_agent` (an agent or unknown process made it
    /// and `--created-by-agent` was not ticked) or `result_unrecorded`
    /// (EnvCloak does not know what the change left, and `--unrecorded`
    /// was not given).
    RestoreRefused,
    /// No restore lease has the id for this process on this terminal: it
    /// never did, or it ended.
    NoSuchLease,
    /// The backup v2 is committed: it takes no more chunks, and each
    /// file's result is recorded once.
    BackupFrozen,
    /// A reference to a login's field (SPEC §6.8): `run`, `ref` and every
    /// resolver refuse it; only a sign-in opens a login's fields.
    LoginReference,
    Internal,
}

impl ErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [ErrorKind; 45] = [
        ErrorKind::ParseError,
        ErrorKind::InvalidRequest,
        ErrorKind::MethodNotFound,
        ErrorKind::InvalidParams,
        ErrorKind::RoleDenied,
        ErrorKind::VaultLocked,
        ErrorKind::NoVault,
        ErrorKind::VaultExists,
        ErrorKind::WrongPassphrase,
        ErrorKind::PassphraseRejected,
        ErrorKind::KdfParams,
        ErrorKind::Busy,
        ErrorKind::Traced,
        ErrorKind::VaultUnavailable,
        ErrorKind::FrameTooLarge,
        ErrorKind::Evidence,
        ErrorKind::ManifestInvalid,
        ErrorKind::BindingUnresolved,
        ErrorKind::PolicyDenied,
        ErrorKind::ModeUnsupported,
        ErrorKind::NoSuchRequest,
        ErrorKind::StatementMismatch,
        ErrorKind::ProofRefused,
        ErrorKind::TooManyAttempts,
        ErrorKind::VaultTampered,
        ErrorKind::TooManyGrants,
        ErrorKind::InvalidOptions,
        ErrorKind::AuditUnavailable,
        ErrorKind::NoSuchItem,
        ErrorKind::ItemExists,
        ErrorKind::InvalidItem,
        ErrorKind::BackupFailed,
        ErrorKind::PlanChanged,
        ErrorKind::NoSuchBackup,
        ErrorKind::FilesBackupFailed,
        ErrorKind::TooManyChecks,
        ErrorKind::AuditFailed,
        ErrorKind::BackupUnusable,
        ErrorKind::TooManyPending,
        ErrorKind::NotBackupOwner,
        ErrorKind::RestoreRefused,
        ErrorKind::NoSuchLease,
        ErrorKind::BackupFrozen,
        ErrorKind::LoginReference,
        ErrorKind::Internal,
    ];

    /// The JSON-RPC error code.
    pub fn code(self) -> i32 {
        match self {
            ErrorKind::ParseError => -32700,
            ErrorKind::InvalidRequest => -32600,
            ErrorKind::MethodNotFound => -32601,
            ErrorKind::InvalidParams => -32602,
            ErrorKind::RoleDenied => -32001,
            ErrorKind::VaultLocked => -32002,
            ErrorKind::NoVault => -32003,
            ErrorKind::VaultExists => -32004,
            ErrorKind::WrongPassphrase => -32005,
            ErrorKind::PassphraseRejected => -32006,
            ErrorKind::KdfParams => -32007,
            ErrorKind::Busy => -32008,
            ErrorKind::Traced => -32009,
            ErrorKind::VaultUnavailable => -32010,
            ErrorKind::FrameTooLarge => -32011,
            ErrorKind::Evidence => -32012,
            ErrorKind::ManifestInvalid => -32013,
            ErrorKind::BindingUnresolved => -32014,
            ErrorKind::PolicyDenied => -32015,
            ErrorKind::ModeUnsupported => -32016,
            ErrorKind::NoSuchRequest => -32017,
            ErrorKind::StatementMismatch => -32018,
            ErrorKind::ProofRefused => -32019,
            ErrorKind::TooManyAttempts => -32020,
            ErrorKind::VaultTampered => -32021,
            ErrorKind::TooManyGrants => -32022,
            ErrorKind::InvalidOptions => -32023,
            ErrorKind::AuditUnavailable => -32024,
            ErrorKind::NoSuchItem => -32025,
            ErrorKind::ItemExists => -32026,
            ErrorKind::InvalidItem => -32027,
            ErrorKind::BackupFailed => -32028,
            ErrorKind::PlanChanged => -32029,
            ErrorKind::NoSuchBackup => -32030,
            ErrorKind::FilesBackupFailed => -32031,
            ErrorKind::TooManyChecks => -32032,
            ErrorKind::AuditFailed => -32033,
            ErrorKind::BackupUnusable => -32034,
            ErrorKind::TooManyPending => -32035,
            ErrorKind::NotBackupOwner => -32036,
            ErrorKind::RestoreRefused => -32048,
            ErrorKind::NoSuchLease => -32049,
            ErrorKind::BackupFrozen => -32050,
            ErrorKind::LoginReference => -32037,
            ErrorKind::Internal => -32099,
        }
    }

    /// The stable token, printed by the CLI as `envcloak: <token>: ...`.
    pub fn token(self) -> &'static str {
        match self {
            ErrorKind::ParseError => "parse_error",
            ErrorKind::InvalidRequest => "invalid_request",
            ErrorKind::MethodNotFound => "method_not_found",
            ErrorKind::InvalidParams => "invalid_params",
            ErrorKind::RoleDenied => "role_denied",
            ErrorKind::VaultLocked => "vault_locked",
            ErrorKind::NoVault => "no_vault",
            ErrorKind::VaultExists => "vault_exists",
            ErrorKind::WrongPassphrase => "wrong_passphrase",
            ErrorKind::PassphraseRejected => "passphrase_rejected",
            ErrorKind::KdfParams => "kdf_params",
            ErrorKind::Busy => "busy",
            ErrorKind::Traced => "traced",
            ErrorKind::VaultUnavailable => "vault_unavailable",
            ErrorKind::FrameTooLarge => "frame_too_large",
            ErrorKind::Evidence => "evidence",
            ErrorKind::ManifestInvalid => "manifest_invalid",
            ErrorKind::BindingUnresolved => "binding_unresolved",
            ErrorKind::PolicyDenied => "policy_denied",
            ErrorKind::ModeUnsupported => "mode_unsupported",
            ErrorKind::NoSuchRequest => "no_such_request",
            ErrorKind::StatementMismatch => "statement_mismatch",
            ErrorKind::ProofRefused => "proof_refused",
            ErrorKind::TooManyAttempts => "too_many_attempts",
            ErrorKind::VaultTampered => "vault_tampered",
            ErrorKind::TooManyGrants => "too_many_grants",
            ErrorKind::InvalidOptions => "invalid_options",
            ErrorKind::AuditUnavailable => "audit_unavailable",
            ErrorKind::NoSuchItem => "no_such_item",
            ErrorKind::ItemExists => "item_exists",
            ErrorKind::InvalidItem => "invalid_item",
            ErrorKind::BackupFailed => "backup_failed",
            ErrorKind::PlanChanged => "plan_changed",
            ErrorKind::NoSuchBackup => "no_such_backup",
            ErrorKind::FilesBackupFailed => "files_backup_failed",
            ErrorKind::TooManyChecks => "too_many_checks",
            ErrorKind::AuditFailed => "audit_failed",
            ErrorKind::BackupUnusable => "backup_unusable",
            ErrorKind::TooManyPending => "too_many_pending",
            ErrorKind::NotBackupOwner => "not_backup_owner",
            ErrorKind::RestoreRefused => "restore_refused",
            ErrorKind::NoSuchLease => "no_such_lease",
            ErrorKind::BackupFrozen => "backup_frozen",
            ErrorKind::LoginReference => "login_reference",
            ErrorKind::Internal => "internal",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            ErrorKind::ParseError => "the request is not valid JSON",
            ErrorKind::InvalidRequest => "the request is not a JSON-RPC 2.0 request",
            ErrorKind::MethodNotFound => "no such method",
            ErrorKind::InvalidParams => "the request's parameters are missing or malformed",
            ErrorKind::RoleDenied => {
                "this method needs the EnvCloak app; a command-line client cannot call it"
            }
            ErrorKind::VaultLocked => "the vault is locked; run `envcloak unlock`",
            ErrorKind::NoVault => "there is no vault yet; run `envcloak vault create`",
            ErrorKind::VaultExists => "a vault already exists",
            ErrorKind::WrongPassphrase => {
                "wrong passphrase or Recovery Kit, or the unlocker envelope is damaged"
            }
            ErrorKind::PassphraseRejected => "the passphrase does not meet the rules",
            ErrorKind::KdfParams => "key derivation memory must be between 64 MiB and 4 GiB",
            ErrorKind::Busy => {
                "the daemon is busy (an unlock or a vault creation is in progress, or this process \
                 tree asked too often); try again"
            }
            ErrorKind::Traced => {
                "a debugger or tracer is attached to the daemon, so it will not handle secrets"
            }
            ErrorKind::VaultUnavailable => "the vault could not be opened",
            ErrorKind::FrameTooLarge => {
                "the request, or the answer its values would make, exceeds the 1 MiB frame limit"
            }
            ErrorKind::Evidence => "the caller's ancestry could not be read",
            ErrorKind::ManifestInvalid => "the project manifest is invalid or could not be opened",
            ErrorKind::BindingUnresolved => "a binding the run asked for could not be resolved",
            ErrorKind::PolicyDenied => "the policy for this project refuses requests from agents",
            ErrorKind::ModeUnsupported => {
                "the policy requires proxy mode, which this build does not have yet"
            }
            ErrorKind::NoSuchRequest => "no pending request has that id, or it expired",
            ErrorKind::StatementMismatch => {
                "the statement approved is not the pending request's; nothing was approved"
            }
            ErrorKind::ProofRefused => {
                "a proof is taken only in a terminal session with no agent in it: not from a \
                 process with an agent in its ancestry, agent markers in its environment or a \
                 lost ancestry, nor from one without a controlling terminal (a service \
                 manager's job, setsid); run this in a terminal you control"
            }
            ErrorKind::TooManyAttempts => {
                "too many failed passphrase attempts; `envcloak status` shows the wait"
            }
            ErrorKind::VaultTampered => {
                "the vault was modified outside EnvCloak, so no grant is evaluated from it"
            }
            ErrorKind::TooManyGrants => "too many grants are in force; revoke some first",
            ErrorKind::InvalidOptions => "the approval options are out of bounds",
            ErrorKind::AuditUnavailable => "the audit log could not be read",
            ErrorKind::NoSuchItem => "the vault has no such item or field",
            ErrorKind::ItemExists => "an item with that slug already exists",
            ErrorKind::InvalidItem => "the item's names or value are not accepted",
            ErrorKind::BackupFailed => {
                "an encrypted backup of the vault could not be written (before a removal, \
                 nothing was removed)"
            }
            ErrorKind::PlanChanged => {
                "what the import would do changed since it was shown (the vault or the files \
                 changed); nothing was imported, run it again"
            }
            ErrorKind::NoSuchBackup => {
                "no file backup has that id, or it is over 7 days old and was removed"
            }
            ErrorKind::FilesBackupFailed => {
                "the encrypted backup of the files could not be written or read; nothing was \
                 deleted or restored"
            }
            ErrorKind::TooManyChecks => {
                "this process tree has had as many values compared with the vault as an hour \
                 allows; try again later"
            }
            ErrorKind::AuditFailed => {
                "the audit entry could not be written, so nothing was released; check the \
                 audit log's directory (`envcloak status`)"
            }
            ErrorKind::BackupUnusable => {
                "that file is not a vault backup this build can read: it is missing, not a \
                 regular file, altered or cut short, or of a newer format; nothing was restored"
            }
            ErrorKind::TooManyPending => {
                "too many requests are waiting for approval, so this one was not opened; approve \
                 or deny one (`envcloak pending` lists them), or ask again later"
            }
            ErrorKind::NotBackupOwner => {
                "only the process that began this backup may add to it, commit it or record its \
                 result; nothing was changed"
            }
            ErrorKind::RestoreRefused => {
                "this backup is restored only with an explicit option; nothing was restored"
            }
            ErrorKind::NoSuchLease => {
                "no restore lease is open for this process and terminal (it ended when its process \
                 exited, the vault locked, it sat idle for 60 seconds or the daemon restarted); \
                 open the restore again"
            }
            ErrorKind::BackupFrozen => {
                "the backup is committed: it takes no more chunks, and each file's result is \
                 recorded once; nothing was changed"
            }
            ErrorKind::LoginReference => {
                "a reference names a login's field, which is never bound to a variable: only a \
                 sign-in opens a login, after the person approves it in EnvCloak"
            }
            ErrorKind::Internal => "the daemon failed",
        }
    }

    /// The kind with this token.
    pub fn from_token(token: &str) -> Option<ErrorKind> {
        ErrorKind::ALL.into_iter().find(|k| k.token() == token)
    }
}

/// The detail tokens an error may carry in `data.reason`: why a passphrase
/// was rejected, why the vault could not be opened, why the caller's
/// ancestry could not be read, what is wrong with a manifest or a binding,
/// what is wrong with approval options, and what is wrong with an item.
/// A slice, so a lane that adds a token changes no count (review R-7):
/// each token is unique and listed in docs/IPC.md's "Reasons" table,
/// which lists nothing else (review R-21), and each an error carries has
/// its words in the CLI (tests in both crates check it).
pub const REASONS: &[&str] = &[
    // Passphrase rules (envcloak_core::PassphraseRejected).
    "not_text",
    "control_character",
    "too_short",
    "common",
    // The vault file.
    "busy",
    "damaged",
    "unsupported_version",
    "permissions",
    "disk_full",
    "storage",
    "io",
    "migration",
    // Caller evidence (envcloak_policy::EvidenceError).
    "caller_gone",
    "ancestry_changed",
    "ancestry_hidden",
    "ancestry_unreadable",
    "caller_is_init",
    // The manifest (envcloak_policy::ManifestErrorKind).
    "too_large",
    "not_utf8",
    "syntax",
    "duplicate_key",
    "unknown_key",
    "wrong_type",
    "invalid_env_name",
    "invalid_profile_name",
    "nested_profile",
    "invalid_reference",
    "invalid_project_name",
    "loose_policy",
    "invalid_policy",
    "unknown_profile",
    "duplicate_env_name",
    "invalid_path",
    "not_found",
    "symlinked_manifest",
    "not_regular_file",
    "not_owned",
    "directory_changed",
    // Bindings (envcloak_policy::BindErrorKind).
    "unknown_item",
    "unknown_field",
    "ambiguous_field",
    "no_field",
    "card_reference",
    "issuer_credential_reference",
    "unknown_item_class",
    // Approval options (envcloak_policy::OptionsError).
    "ttl_zero",
    "ttl_too_long",
    "live_not_bound",
    // Denied decisions (envcloak_policy::DenyReason), in results.
    "repeated",
    "root_denied",
    "denials_full",
    "audit_failed",
    // The pending cap a `run.request` met (envcloak_policy::PendingCap),
    // for `too_many_pending`.
    "pending_per_root",
    "pending_total",
    // Items (`items.*`): what is wrong with a name or a value, and a
    // target that changed. `unknown_item`, `unknown_field`,
    // `ambiguous_field`, `no_field`, `unknown_item_class` and
    // `invalid_env_name` are above.
    "item_changed",
    "invalid_slug",
    "invalid_field",
    "unknown_provider",
    "invalid_account",
    "looks_like_value",
    "empty_value",
    "nul_byte",
    "value_too_large",
    "no_free_slug",
    // A proof refused (`proof_refused`) because the approver shares a
    // session or a terminal with the request's own chain.
    "requester_terminal",
    // A backup v2 restore refused before the proof (`restore_refused`).
    "result_unrecorded",
    "created_by_agent",
    // A backup the vault wrote that its name did not hold once published
    // (`files_backup_failed`).
    "substituted",
    // A comparison budget of the caller's subject root stopped `scan.match`
    // before it compared anything (`too_many_checks`).
    "limited",
];

/// An error response. Built from fixed tokens only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RpcError {
    pub kind: ErrorKind,
    /// One of [`REASONS`], for [`ErrorKind::PassphraseRejected`],
    /// [`ErrorKind::VaultUnavailable`], [`ErrorKind::Evidence`],
    /// [`ErrorKind::ManifestInvalid`], [`ErrorKind::BindingUnresolved`],
    /// [`ErrorKind::InvalidOptions`], [`ErrorKind::NoSuchItem`],
    /// [`ErrorKind::InvalidItem`], [`ErrorKind::ProofRefused`]
    /// (`requester_terminal` only), [`ErrorKind::TooManyChecks`] (`limited`
    /// only, from `scan.match`), [`ErrorKind::TooManyPending`],
    /// [`ErrorKind::RestoreRefused`] and [`ErrorKind::FilesBackupFailed`]
    /// (`too_large`, a backup v2 over its caps, and `substituted`, a
    /// backup replaced under its name, or cut or written into, before it
    /// was checked in place).
    pub reason: Option<&'static str>,
}

impl RpcError {
    pub const fn new(kind: ErrorKind) -> Self {
        RpcError { kind, reason: None }
    }

    /// The error with a reason; one not in [`REASONS`] is dropped.
    pub fn with_reason(kind: ErrorKind, reason: &str) -> Self {
        RpcError {
            kind,
            reason: REASONS.iter().find(|r| **r == reason).copied(),
        }
    }
}

impl From<ErrorKind> for RpcError {
    fn from(kind: ErrorKind) -> Self {
        RpcError::new(kind)
    }
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())?;
        if let Some(r) = self.reason {
            write!(f, " ({r})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RpcError {}

#[derive(Serialize)]
struct OutRequest<'a, P> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: &'a P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

#[derive(Serialize)]
struct OutResult<'a, T> {
    jsonrpc: &'static str,
    id: u64,
    result: &'a T,
}

#[derive(Serialize)]
struct OutError {
    jsonrpc: &'static str,
    id: Option<u64>,
    error: OutErrorBody,
}

#[derive(Serialize)]
struct OutErrorBody {
    code: i32,
    message: &'static str,
    data: OutErrorData,
}

#[derive(Serialize)]
struct OutErrorData {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InResponse<'a> {
    jsonrpc: &'a str,
    id: Option<u64>,
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
    #[serde(default)]
    error: Option<InErrorBody>,
}

#[derive(Deserialize)]
struct InErrorBody {
    #[allow(dead_code)] // Read for the shape; the kind decides.
    code: i64,
    // Never shown: the client prints its own message for the kind.
    #[allow(dead_code)]
    message: IgnoredAny,
    #[serde(default)]
    data: Option<InErrorData>,
}

#[derive(Deserialize)]
struct InErrorData {
    kind: String,
    #[serde(default)]
    reason: Option<String>,
}

/// A request frame for method `M`.
///
/// # Errors
/// [`FrameError::TooLarge`] when the request does not fit in a frame.
pub fn request_frame<M: Method>(id: u64, params: &M::Params) -> Result<Frame, FrameError> {
    Frame::encode(&OutRequest {
        jsonrpc: JSONRPC,
        id,
        method: M::NAME,
        params,
    })
}

/// A request as the daemon receives it: the method name and parameters
/// still in the frame. Its `Debug` shows the id and a loggable method
/// name only; the parameters may hold a value.
pub struct IncomingRequest<'a> {
    pub id: u64,
    /// As the client sent it. Log it only through [`loggable_method`].
    pub method: &'a str,
    params: Option<&'a RawValue>,
}

impl core::fmt::Debug for IncomingRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("id", &self.id)
            .field("method", &loggable_method(self.method))
            .finish_non_exhaustive()
    }
}

impl<'a> IncomingRequest<'a> {
    /// Parses a request frame. On failure, the error to answer with and
    /// the request id when it could be read.
    pub fn parse(frame: &'a Frame) -> Result<Self, RpcError> {
        let req: InRequest<'a> = frame.decode().map_err(|e| match e {
            DecodeError::Syntax | DecodeError::Eof => RpcError::new(ErrorKind::ParseError),
            DecodeError::Data => RpcError::new(ErrorKind::InvalidRequest),
        })?;
        if req.jsonrpc != JSONRPC {
            return Err(RpcError::new(ErrorKind::InvalidRequest));
        }
        Ok(IncomingRequest {
            id: req.id,
            method: req.method,
            params: req.params,
        })
    }

    /// The parameters as `P`. Absent parameters read as `{}`.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidParams`] when they do not match `P`.
    pub fn params<P: Deserialize<'a>>(&self) -> Result<P, RpcError> {
        let raw = self.params.map_or("{}", RawValue::get);
        serde_json::from_str(raw).map_err(|_| RpcError::new(ErrorKind::InvalidParams))
    }
}

/// The success response to request `id`.
///
/// # Errors
/// [`FrameError::TooLarge`] when the result does not fit in a frame.
pub fn result_frame<T: Serialize>(id: u64, result: &T) -> Result<Frame, FrameError> {
    Frame::encode(&OutResult {
        jsonrpc: JSONRPC,
        id,
        result,
    })
}

/// The error response to request `id`, or to an unreadable request
/// (`None`).
///
/// # Errors
/// Only if a fixed error object could not be serialized.
pub fn error_frame(id: Option<u64>, e: &RpcError) -> Result<Frame, FrameError> {
    Frame::encode(&OutError {
        jsonrpc: JSONRPC,
        id,
        error: OutErrorBody {
            code: e.kind.code(),
            message: e.kind.message(),
            data: OutErrorData {
                kind: e.kind.token(),
                reason: e.reason,
            },
        },
    })
}

/// Why a response could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// The daemon answered with an error.
    Rpc(RpcError),
    /// The response is malformed, answers another request, or holds an
    /// error kind this client does not know.
    Protocol,
}

/// Reads the response to request `id` as `T`.
///
/// # Errors
/// [`ResponseError::Rpc`] for an error response, and
/// [`ResponseError::Protocol`] for anything else that is not a result of
/// type `T` for request `id`.
pub fn parse_response<'a, T: Deserialize<'a>>(
    frame: &'a Frame,
    id: u64,
) -> Result<T, ResponseError> {
    let resp: InResponse<'a> = frame.decode().map_err(|_| ResponseError::Protocol)?;
    if resp.jsonrpc != JSONRPC {
        return Err(ResponseError::Protocol);
    }
    match (resp.result, resp.error) {
        (Some(result), None) if resp.id == Some(id) => {
            serde_json::from_str(result.get()).map_err(|_| ResponseError::Protocol)
        }
        (None, Some(err)) if resp.id.is_none_or(|got| got == id) => {
            let data = err.data.ok_or(ResponseError::Protocol)?;
            let kind = ErrorKind::from_token(&data.kind).ok_or(ResponseError::Protocol)?;
            let e = match data.reason {
                Some(r) => RpcError::with_reason(kind, &r),
                None => RpcError::new(kind),
            };
            Err(ResponseError::Rpc(e))
        }
        _ => Err(ResponseError::Protocol),
    }
}
