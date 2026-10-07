//! Managed MCP servers (SPEC §6.6; M2 plan D-05, D-18, D-33, D-36, CR-2;
//! task M2-27): their records, the methods that write them, and the check
//! every `run.request` against a managed project passes before a grant is
//! consulted.
//!
//! **Records.** A `ManagedServer` policy record (docs/VAULT.md "Policy
//! records", kind 3) names a managed project by its identity (canonical
//! directory, device and inode) and how its server is reached: a stdio
//! server's registered launch ([`crate::launch_check`]) or a bridged HTTP
//! server's origin and header names. One record per project and per name:
//! registering again replaces the record of that name or that project, a
//! stdio launch keeping its launch id with the next revision.
//!
//! **The methods.** `managed.register`, `managed.unregister` and
//! `managed.update` take a passphrase proof, only from a caller that may
//! give one (a terminal subject with no agent by any evidence, sharing no
//! session or terminal with a waiting agent's request,
//! [`crate::requests::refuse_unless_prover_beside_pending`]); the declaration is resolved
//! before the proof, so a refused one costs no Argon2id run. Each change
//! is audited `managed_register` with counts and digest prefixes, never an
//! argument, a variable's value or a path inside the launch. No method
//! returns a launch description beyond the receipt's display: the runner
//! receives the launch on its control channel. `managed.update_plan`
//! answers only a caller whose proof would be accepted (the `pending.list`
//! rule), and builds the statement from the declaration stored in the
//! record, never from a host config (CR-2).
//!
//! **The request check** ([`check_request`]): a `run.request` whose
//! project has a record, found by the manifest it names or by the launch
//! id it names, must name the record's launch (stdio) or its origin and
//! header names with bindings that carry the origin's digest (bridge), and
//! hand over its pipe ends and a lifeline; otherwise it is
//! `managed_command_mismatch`. A stdio launch is then checked by the
//! daemon ([`crate::launch_check::check`]): `managed_launch_changed` or
//! `runner_unavailable`. Each refusal is audited `managed_launch` and
//! answered before any pending request exists, so no grant is consulted.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use envcloak_core::audit::{ProjectSummary, SubjectSummary};
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{
    CodeDigest, LaunchDecl, ManagedServer, ManagedTransport, PolicyId, PolicyRecord,
    ProjectIdentity, RegisteredLaunch, SubjectKindRecord, Vault, VaultErrorKind,
};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{
    BridgeDecl, ErrorKind, ManagedRegisterParams, ManagedServerDecl, ManagedUnregisterParams,
    ManagedUpdateParams, ManagedUpdatePlanParams, RunRequestParams,
};
use envcloak_ipc::view::{
    LaunchDeclarationView, LaunchReceiptView, ManagedRegisteredView, ManagedUnregisteredView,
    ManagedUpdatePlanView, ManagedUpdatedView, UpdateStatementView,
};
use envcloak_policy::managed::{
    ArgvClass, apply_changes, bridge_binding_suffix, bridge_headers, class_word, classify_argv,
    launch_digest, launch_id_text, new_launch_id, parse_launch_id, receipt_sentences,
    residual_sentence, strength_word, update_digest,
};
use envcloak_policy::{ManagedRequest, Project, SubjectEvidence, SubjectKind, load_project};
use envcloak_sys::PeerIdentity;

use crate::audit::{AuditEvent, ManagedCounts};
use crate::clock::now_of;
use crate::launch_check::{self, CheckError, CheckedLaunch, ResolveError};
use crate::requests::{
    evidence, manifest_error, proof_refusal_beside_pending, refuse_unless_prover_beside_pending,
    requester_terminal_in, subject_summary,
};
use crate::server::{Shared, locked, refuse_if_traced};
use crate::state::{State, vault_reason};

/// The longest `<agent>/<server>` name, in bytes.
const MAX_NAME: usize = 256;
/// The most header names a bridged server's record holds.
const MAX_HEADERS: usize = 32;

/// Whether `name` is `<agent>/<server>`: two non-empty parts of printable
/// ASCII without spaces, one `/` between them.
fn valid_name(name: &str) -> bool {
    let Some((agent, server)) = name.split_once('/') else {
        return false;
    };
    let part = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
    name.len() <= MAX_NAME && part(agent) && part(server)
}

/// Whether `origin` is an origin: `https://` or `http://`, a host of
/// letters, digits, `.`, `-` and `:` (a port or an IPv6 literal in
/// brackets), and nothing after it: no user, path, query or fragment.
fn valid_origin(origin: &str) -> bool {
    let Some(host) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    origin.len() <= 2048
        && !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Whether `h` is an HTTP header name (RFC 9110 `token`).
fn valid_header(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 128
        && h.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn invalid(reason: &'static str) -> RpcError {
    RpcError::with_reason(ErrorKind::InvalidParams, reason)
}

/// A policy project identity from a request's.
fn record_project(p: &envcloak_policy::ProjectIdentity) -> ProjectIdentity {
    ProjectIdentity {
        canonical_dir: p.canonical_dir.as_os_str().as_bytes().to_vec(),
        dev: p.dev,
        ino: p.ino,
    }
}

fn project_summary(p: &Project) -> ProjectSummary {
    ProjectSummary {
        dir: p.identity.canonical_dir.to_string_lossy().into_owned(),
        manifest_sha256: p.manifest.sha256,
        approved_sha256: None,
    }
}

/// The vault's managed records. A vault whose policy rows cannot be served
/// (tampered, or not migrated) refuses: a record that cannot be read must
/// not loosen a decision.
fn records(vault: &Vault) -> Result<Vec<(PolicyId, ManagedServer)>, RpcError> {
    let rows = vault.policies().map_err(|e| match e.kind() {
        VaultErrorKind::Tampered => RpcError::new(ErrorKind::VaultTampered),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    })?;
    Ok(rows
        .filter_map(|(id, r)| match r {
            PolicyRecord::ManagedServer(m) => Some((id, m.clone())),
            _ => None,
        })
        .collect())
}

/// The record of the project `project`, if any.
pub(crate) fn by_project(
    vault: &Vault,
    project: &envcloak_policy::ProjectIdentity,
) -> Result<Option<(PolicyId, ManagedServer)>, RpcError> {
    let want = record_project(project);
    Ok(records(vault)?.into_iter().find(|(_, m)| m.project == want))
}

/// The record whose stdio launch is `launch_id`, if any.
pub(crate) fn by_launch(
    vault: &Vault,
    launch_id: &[u8; 16],
) -> Result<Option<(PolicyId, ManagedServer)>, RpcError> {
    Ok(records(vault)?.into_iter().find(
        |(_, m)| matches!(&m.transport, ManagedTransport::Stdio(l) if &l.launch_id == launch_id),
    ))
}

/// A digest's display: `sha256:<hex>` or `cdhash:<hex>`.
fn identity_text(d: &CodeDigest) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    match d {
        CodeDigest::Sha256(h) => format!("sha256:{}", hex(h)),
        CodeDigest::CdHash { cdhash, .. } => format!("cdhash:{}", hex(cdhash)),
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A stdio launch's receipt (D-33): what was registered and what its
/// strength binds.
pub(crate) fn launch_receipt(name: &str, l: &RegisteredLaunch) -> LaunchReceiptView {
    let agent = name.split('/').next().unwrap_or(name);
    let runner = match classify_argv(&l.declaration.argv) {
        Ok(ArgvClass::PackageRunner { label }) => Some(label),
        _ => None,
    };
    let mut sentences = receipt_sentences(l.class, l.strength, runner.as_deref());
    sentences.push(residual_sentence(agent));
    let mut env_names: Vec<String> = vec!["PATH".to_owned()];
    env_names.extend(l.env.vars.iter().map(|(n, _)| n.clone()));
    LaunchReceiptView {
        server: name.to_owned(),
        transport: "stdio".to_owned(),
        class: Some(class_word(l.class).to_owned()),
        strength: Some(strength_word(l.strength).to_owned()),
        executable: Some(lossy(&l.executable.path)),
        identity: Some(identity_text(&l.executable.digest)),
        entry: l.entry.as_ref().map(|e| lossy(&e.path)),
        entry_identity: l.entry.as_ref().map(|e| identity_text(&e.digest)),
        cwd: Some(lossy(&l.cwd.path)),
        env_names,
        bindings: l.env.binding_names.clone(),
        origin: None,
        header_names: Vec::new(),
        sentences,
    }
}

/// A bridged server's receipt.
fn bridge_receipt(
    name: &str,
    origin: &str,
    header_names: &[String],
    bindings: Vec<String>,
) -> LaunchReceiptView {
    let agent = name.split('/').next().unwrap_or(name);
    LaunchReceiptView {
        server: name.to_owned(),
        transport: "bridge".to_owned(),
        class: None,
        strength: None,
        executable: None,
        identity: None,
        entry: None,
        entry_identity: None,
        cwd: None,
        env_names: Vec::new(),
        bindings,
        origin: Some(origin.to_owned()),
        header_names: header_names.to_vec(),
        sentences: vec![
            "the header values go only to this origin, inserted by EnvCloak's relay; an edited \
             origin is a new binding, which asks for approval"
                .to_owned(),
            residual_sentence(agent),
        ],
    }
}

fn counts(l: &RegisteredLaunch) -> ManagedCounts {
    let d = launch_digest(l);
    ManagedCounts {
        revision: l.revision,
        arguments: l.argv.len(),
        variables: l.env.vars.len(),
        bindings: l.env.binding_names.len(),
        digest_prefix: u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]),
    }
}

/// The binding names of a managed project's manifest: its default
/// profile's variables.
fn binding_names(p: &Project) -> Vec<String> {
    p.manifest
        .env
        .iter()
        .map(|b| b.env_name.as_str().to_owned())
        .collect()
}

/// Whether every binding of the manifest carries `origin`'s digest
/// ([`bridge_binding_suffix`], D-18).
fn bindings_carry_origin<'a>(names: impl IntoIterator<Item = &'a str>, origin: &str) -> bool {
    let suffix = bridge_binding_suffix(origin);
    let mut any = false;
    for n in names {
        any = true;
        if !n.ends_with(&suffix) {
            return false;
        }
    }
    any
}

/// Takes a passphrase proof from `caller` (already found a prover), with
/// the attempt limiter, as `approve` does: the state, locked, with the
/// vault back in its slot, when the passphrase is the vault's. A wrong one
/// is audited with `outcome` `wrong_passphrase`.
fn prove<'s>(
    shared: &'s Shared,
    peer: &PeerIdentity,
    who: &SubjectSummary,
    caller: &SubjectEvidence,
    method: &'static str,
    pass: envcloak_core::SecretBytes,
) -> Result<std::sync::MutexGuard<'s, State>, RpcError> {
    let _gate = locked(&shared.proof_gate);
    let (vault, generation) = {
        let mut s = locked(&shared.state);
        let now = now_of(&shared.clocks);
        s.unlocked()?;
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
            // A waiting agent's request that shares this caller's terminal,
            // made while the passphrase was read, refuses it as one made
            // before did ([`refuse_unless_prover_beside_pending`]).
            if let Some(r) = requester_terminal_in(&mut s, caller, &now) {
                s.audit(AuditEvent::ProofRefused {
                    pid: peer.pid,
                    method,
                    reason: r.token(),
                });
                return Err(RpcError::with_reason(ErrorKind::ProofRefused, r.token()));
            }
            Ok(s)
        }
        Err(e) if e.kind() == VaultErrorKind::Crypto(CryptoErrorKind::Unlock) => {
            s.limiter().failed(&now);
            s.audit(AuditEvent::ManagedRegistered {
                pid: peer.pid,
                subject: who.clone(),
                outcome: "wrong_passphrase",
                launch: None,
                project: None,
                counts: None,
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

fn write_error(e: &envcloak_core::vault::VaultError) -> RpcError {
    match e.kind() {
        VaultErrorKind::ReadOnly | VaultErrorKind::Tampered => {
            RpcError::new(ErrorKind::VaultTampered)
        }
        VaultErrorKind::TooLarge => invalid("too_large"),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

/// A resolution failure, audited as the refusal of a registration or an
/// update.
fn resolve_refused(
    shared: &Shared,
    peer: &PeerIdentity,
    who: &SubjectSummary,
    project: Option<ProjectSummary>,
    e: ResolveError,
) -> RpcError {
    let err = e.rpc();
    shared.audit(AuditEvent::ManagedRegistered {
        pid: peer.pid,
        subject: who.clone(),
        outcome: err.reason.unwrap_or_else(|| err.kind.token()),
        launch: None,
        project,
        counts: None,
    });
    err
}

/// Gate 13 in the daemon, behind the client's own refusal: a declaration
/// whose argument, variable value, working directory or `PATH` looks like
/// a key is refused `invalid_params` (`key_shaped`) and audited, before
/// anything of it is resolved or stored. A key in a launch would sit in
/// the record, on the server's argv (where `ps` shows it) and in the
/// receipt; it belongs in the vault, bound by the managed manifest.
fn refuse_key_shaped(
    shared: &Shared,
    peer: &PeerIdentity,
    who: &SubjectSummary,
    d: &LaunchDecl,
) -> Result<(), RpcError> {
    let texts = d
        .argv
        .iter()
        .chain(d.env.iter().map(|(_, v)| v))
        .chain(d.cwd.iter())
        .chain(d.path_env.iter());
    refuse_key_shaped_texts(shared, peer, who, texts.map(String::as_str))
}

/// [`refuse_key_shaped`] for any texts of a declaration (a bridged
/// server's origin and header names too).
fn refuse_key_shaped_texts<'t>(
    shared: &Shared,
    peer: &PeerIdentity,
    who: &SubjectSummary,
    mut texts: impl Iterator<Item = &'t str>,
) -> Result<(), RpcError> {
    if texts.any(|t| crate::items::looks_like_value(shared, t)) {
        shared.audit(AuditEvent::ManagedRegistered {
            pid: peer.pid,
            subject: who.clone(),
            outcome: "key_shaped",
            launch: None,
            project: None,
            counts: None,
        });
        return Err(invalid("key_shaped"));
    }
    Ok(())
}

/// `managed.register`. See the module documentation.
pub fn register(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ManagedRegisterParams,
) -> Result<ManagedRegisteredView, RpcError> {
    refuse_if_traced()?;
    let pass = p.passphrase.into_inner();
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover_beside_pending(shared, peer, &caller, "managed.register")?;
    if !valid_name(&p.name) {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    let manifest = Path::new(&p.manifest);
    if !manifest.is_absolute() {
        return Err(invalid("invalid_path"));
    }
    let project = load_project(manifest).map_err(manifest_error)?;
    let names = binding_names(&project);
    let who = subject_summary(peer, &caller);
    let summary = project_summary(&project);
    let identity = record_project(&project.identity);
    // The launch id: the one the record of this name has, for the next
    // revision, so the host config's `--launch <id>` stays right; a new one
    // otherwise.
    let prior = {
        let s = locked(&shared.state);
        let vault = s.unlocked()?;
        records(vault)?
            .into_iter()
            .find(|(_, m)| m.name == p.name)
            .and_then(|(_, m)| match m.transport {
                ManagedTransport::Stdio(l) => Some((l.launch_id, l.revision)),
                ManagedTransport::Bridge { .. } => None,
            })
    };
    let transport = match &p.server {
        ManagedServerDecl::Stdio { launch } => {
            let decl = LaunchDecl::from(launch);
            refuse_key_shaped(shared, peer, &who, &decl)?;
            let (id, revision) = prior.map_or_else(|| (new_launch_id(), 1), |(id, r)| (id, r + 1));
            // Resolved and identified outside the state lock: hashing a
            // large executable never holds it.
            let l = launch_check::resolve(
                &decl,
                &project.identity.canonical_dir,
                names.clone(),
                id,
                revision,
            )
            .map_err(|e| resolve_refused(shared, peer, &who, Some(summary.clone()), e))?;
            ManagedTransport::Stdio(Box::new(l))
        }
        ManagedServerDecl::Bridge {
            origin,
            header_names,
        } => {
            refuse_key_shaped_texts(
                shared,
                peer,
                &who,
                std::iter::once(origin.as_str()).chain(header_names.iter().map(String::as_str)),
            )?;
            if !valid_origin(origin) {
                return Err(RpcError::new(ErrorKind::InvalidParams));
            }
            if header_names.is_empty()
                || header_names.len() > MAX_HEADERS
                || !header_names.iter().all(|h| valid_header(h))
            {
                return Err(RpcError::new(ErrorKind::InvalidParams));
            }
            if !bindings_carry_origin(names.iter().map(String::as_str), origin) {
                return Err(RpcError::new(ErrorKind::InvalidParams));
            }
            // Each header has its one binding (its name and the origin's
            // digest), and the manifest binds exactly those: the relay is
            // told which value goes in which header, and no binding goes
            // in none.
            let Some(headers) = bridge_headers(header_names, origin) else {
                return Err(invalid("invalid_header"));
            };
            if !same_names(headers.iter().map(|(_, b)| b.as_str()), names.iter()) {
                return Err(invalid("header_bindings"));
            }
            ManagedTransport::Bridge {
                origin: origin.clone(),
                header_names: header_names.clone(),
            }
        }
    };
    let receipt = match &transport {
        ManagedTransport::Stdio(l) => launch_receipt(&p.name, l),
        ManagedTransport::Bridge {
            origin,
            header_names,
        } => bridge_receipt(&p.name, origin, header_names, names.clone()),
    };
    let record = ManagedServer {
        name: p.name.clone(),
        project: identity,
        transport,
        registered_by: match caller.kind() {
            SubjectKind::Terminal => SubjectKindRecord::Terminal,
            SubjectKind::Agent => SubjectKindRecord::Agent,
            SubjectKind::Unknown => SubjectKindRecord::Unknown,
        },
        // Only a proof from a terminal subject writes a record, which is
        // what `migrate-mcp` sends on this device.
        written_by_migrate_mcp: true,
    };
    let mut record = record;
    // A test stops here, after the resolution and before the proof and
    // the commit.
    envcloak_sys::pause_point("managed.register_resolved");
    let mut s = prove(shared, peer, &who, &caller, "managed.register", pass)?;
    let vault = s.unlocked_mut()?;
    // The launch id and revision are taken from the record of this name as
    // it is now, under the lock the commit holds: a registration or an
    // update that committed since the declaration was resolved is the
    // predecessor, so no two launches share a revision, and none goes back.
    if let ManagedTransport::Stdio(l) = &mut record.transport {
        let current = records(vault)?
            .into_iter()
            .find(|(_, m)| m.name == record.name)
            .and_then(|(_, m)| match m.transport {
                ManagedTransport::Stdio(c) => Some((c.launch_id, c.revision)),
                ManagedTransport::Bridge { .. } => None,
            });
        // Without a stdio record of this name now, a new launch id: never
        // the first revision of one an earlier record had.
        let (id, revision) = current.map_or_else(|| (new_launch_id(), 1), |(id, r)| (id, r + 1));
        l.launch_id = id;
        l.revision = revision;
    }
    // The record of this name or this project is replaced: one record per
    // project and per name. Its id stays that of the record of this name.
    let replaced: Vec<(PolicyId, ManagedServer)> = records(vault)?
        .into_iter()
        .filter(|(_, m)| m.name == record.name || m.project == record.project)
        .collect();
    let id = replaced
        .iter()
        .find(|(_, m)| m.name == record.name)
        .map_or_else(PolicyId::generate, |(id, _)| *id);
    vault
        .transact(|txn| {
            for (old, _) in &replaced {
                txn.delete_policy(*old)?;
            }
            txn.put_policy(id, &PolicyRecord::ManagedServer(record.clone()))
        })
        .map_err(|e| write_error(&e))?;
    let (launch, revision, launch_counts) = match &record.transport {
        ManagedTransport::Stdio(l) => (
            Some(launch_id_text(&l.launch_id)),
            Some(l.revision),
            Some(counts(l)),
        ),
        ManagedTransport::Bridge { .. } => (None, None, None),
    };
    s.audit(AuditEvent::ManagedRegistered {
        pid: peer.pid,
        subject: who,
        outcome: if replaced.is_empty() {
            "registered"
        } else {
            "replaced"
        },
        launch: launch.clone(),
        project: Some(summary),
        counts: launch_counts,
    });
    Ok(ManagedRegisteredView {
        id: id.to_string(),
        launch,
        revision,
        receipt,
    })
}

/// `managed.unregister`, by the record's id or its name.
pub fn unregister(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ManagedUnregisterParams,
) -> Result<ManagedUnregisteredView, RpcError> {
    refuse_if_traced()?;
    let pass = p.passphrase.into_inner();
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover_beside_pending(shared, peer, &caller, "managed.unregister")?;
    let who = subject_summary(peer, &caller);
    let found = |vault: &Vault| -> Result<Option<(PolicyId, ManagedServer)>, RpcError> {
        Ok(records(vault)?
            .into_iter()
            .find(|(id, m)| id.to_string() == p.id || m.name == p.id))
    };
    {
        let s = locked(&shared.state);
        if found(s.unlocked()?)?.is_none() {
            return Ok(ManagedUnregisteredView { removed: false });
        }
    }
    let mut s = prove(shared, peer, &who, &caller, "managed.unregister", pass)?;
    let vault = s.unlocked_mut()?;
    let Some((id, record)) = found(vault)? else {
        return Ok(ManagedUnregisteredView { removed: false });
    };
    vault
        .transact(|txn| txn.delete_policy(id))
        .map_err(|e| write_error(&e))?;
    let launch = match &record.transport {
        ManagedTransport::Stdio(l) => Some(launch_id_text(&l.launch_id)),
        ManagedTransport::Bridge { .. } => None,
    };
    s.audit(AuditEvent::ManagedRegistered {
        pid: peer.pid,
        subject: who,
        outcome: "removed",
        launch,
        project: None,
        counts: None,
    });
    Ok(ManagedUnregisteredView { removed: true })
}

/// An update as planned: the record, its launch now, and the launch the
/// update makes (the next revision, resolved from the stored declaration
/// with the changes applied).
struct Plan {
    id: PolicyId,
    record: ManagedServer,
    old: RegisteredLaunch,
    new: RegisteredLaunch,
}

impl Plan {
    fn digest(&self) -> [u8; 32] {
        update_digest(&self.old.launch_id, &self.old, &self.new)
    }
}

/// The plan of an update of launch `launch` with `changes`, or `None` when
/// no record has that launch. Reads the record under the state lock and
/// resolves outside it.
fn plan(
    shared: &Shared,
    launch: &[u8; 16],
    changes: &envcloak_policy::managed::LaunchChanges,
    key_shaped: impl FnOnce(&LaunchDecl) -> Result<(), RpcError>,
) -> Result<Option<Result<Plan, ResolveError>>, RpcError> {
    let found = {
        let s = locked(&shared.state);
        by_launch(s.unlocked()?, launch)?
    };
    let Some((id, record)) = found else {
        return Ok(None);
    };
    let ManagedTransport::Stdio(old) = &record.transport else {
        return Ok(None);
    };
    let old = (**old).clone();
    let decl = match apply_changes(&old.declaration, changes) {
        Ok(d) => d,
        Err(e) => return Ok(Some(Err(ResolveError::Decl(e)))),
    };
    key_shaped(&decl)?;
    let dir = PathBuf::from(std::ffi::OsStr::from_bytes(&record.project.canonical_dir));
    let new = match launch_check::resolve(
        &decl,
        &dir,
        old.env.binding_names.clone(),
        old.launch_id,
        old.revision + 1,
    ) {
        Ok(l) => l,
        Err(e) => return Ok(Some(Err(e))),
    };
    Ok(Some(Ok(Plan {
        id,
        record,
        old,
        new,
    })))
}

/// A declaration as an update statement shows it.
fn declaration_view(d: &LaunchDecl) -> LaunchDeclarationView {
    LaunchDeclarationView {
        argv: d.argv.clone(),
        cwd: d.cwd.clone(),
        env: d.env.clone(),
        path_env: d.path_env.clone(),
    }
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// `managed.update_plan`. See the module documentation.
pub fn update_plan(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ManagedUpdatePlanParams,
) -> Result<ManagedUpdatePlanView, RpcError> {
    let launch = parse_launch_id(&p.launch).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &p.claims)?;
    // The `pending.list` rule: nothing for a caller whose proof would be
    // refused, and no reason why.
    if proof_refusal_beside_pending(shared, &caller).is_some() {
        return Ok(ManagedUpdatePlanView { statement: None });
    }
    let who = subject_summary(peer, &caller);
    let plan = match plan(shared, &launch, &p.changes, |d| {
        refuse_key_shaped(shared, peer, &who, d)
    })? {
        None => return Ok(ManagedUpdatePlanView { statement: None }),
        Some(Err(e)) => {
            return Err(resolve_refused(shared, peer, &who, None, e));
        }
        Some(Ok(plan)) => plan,
    };
    envcloak_sys::pause_point("managed.update_plan_resolved");
    // Resolution reads and hashes files outside the lock. A requester may
    // have reached this terminal meanwhile; publish no declaration to it.
    let mut s = locked(&shared.state);
    if caller.proof_refusal().is_some()
        || requester_terminal_in(&mut s, &caller, &now_of(&shared.clocks)).is_some()
    {
        return Ok(ManagedUpdatePlanView { statement: None });
    }
    Ok(ManagedUpdatePlanView {
        statement: Some(UpdateStatementView {
            launch: launch_id_text(&launch),
            revision: plan.old.revision,
            old: launch_receipt(&plan.record.name, &plan.old),
            new: launch_receipt(&plan.record.name, &plan.new),
            old_declaration: declaration_view(&plan.old.declaration),
            new_declaration: declaration_view(&plan.new.declaration),
            digest: hex(&plan.digest()),
        }),
    })
}

/// `managed.update`. See the module documentation.
pub fn update(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ManagedUpdateParams,
) -> Result<ManagedUpdatedView, RpcError> {
    refuse_if_traced()?;
    let pass = p.passphrase.into_inner();
    let launch = parse_launch_id(&p.launch).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let digest =
        crate::requests::digest_of(&p.digest).ok_or(RpcError::new(ErrorKind::InvalidParams))?;
    let caller = evidence(shared, peer, &p.claims)?;
    refuse_unless_prover_beside_pending(shared, peer, &caller, "managed.update")?;
    let who = subject_summary(peer, &caller);
    // The plan made again: anything changed since the statement was shown
    // is another digest.
    let plan = match plan(shared, &launch, &p.changes, |d| {
        refuse_key_shaped(shared, peer, &who, d)
    })? {
        None => return Err(RpcError::new(ErrorKind::StatementMismatch)),
        Some(Err(e)) => return Err(resolve_refused(shared, peer, &who, None, e)),
        Some(Ok(plan)) => plan,
    };
    if plan.digest() != digest {
        return Err(RpcError::new(ErrorKind::StatementMismatch));
    }
    let mut s = prove(shared, peer, &who, &caller, "managed.update", pass)?;
    let vault = s.unlocked_mut()?;
    // The record must still be the one planned from.
    match by_launch(vault, &launch)? {
        Some((id, r)) if id == plan.id && r == plan.record => {}
        _ => return Err(RpcError::new(ErrorKind::StatementMismatch)),
    }
    let record = ManagedServer {
        transport: ManagedTransport::Stdio(Box::new(plan.new.clone())),
        ..plan.record.clone()
    };
    vault
        .transact(|txn| txn.put_policy(plan.id, &PolicyRecord::ManagedServer(record)))
        .map_err(|e| write_error(&e))?;
    s.audit(AuditEvent::ManagedRegistered {
        pid: peer.pid,
        subject: who,
        outcome: "updated",
        launch: Some(launch_id_text(&launch)),
        project: None,
        counts: Some(counts(&plan.new)),
    });
    Ok(ManagedUpdatedView {
        revision: plan.new.revision,
        receipt: launch_receipt(&plan.record.name, &plan.new),
    })
}

/// A managed request that passed [`check_request`].
pub(crate) enum Checked {
    /// A stdio server's launch, checked: how the runner runs it.
    Stdio {
        launch: Box<RegisteredLaunch>,
        checked: CheckedLaunch,
    },
    /// A bridged server: its origin, and each header with the binding
    /// it carries ([`bridge_headers`]).
    Bridge {
        origin: String,
        headers: Vec<(String, String)>,
    },
}

/// Whether `a` and `b` name the same bindings: each once, in any order.
fn same_names<'a>(
    a: impl IntoIterator<Item = &'a str>,
    b: impl IntoIterator<Item = impl AsRef<str>>,
) -> bool {
    let mut a: Vec<&str> = a.into_iter().collect();
    let mut b: Vec<String> = b.into_iter().map(|n| n.as_ref().to_owned()).collect();
    a.sort_unstable();
    b.sort_unstable();
    let distinct = a.windows(2).all(|w| w[0] != w[1]);
    distinct && a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| *x == y.as_str())
}

/// What a request against a managed project carries into the grant
/// store: the record's mark and the launch revision checked.
pub(crate) fn managed_request(record: &ManagedServer) -> ManagedRequest {
    let (launch, class, strength, origin) = match &record.transport {
        ManagedTransport::Stdio(l) => (
            Some(envcloak_core::vault::LaunchRef {
                launch_id: l.launch_id,
                revision: l.revision,
            }),
            Some(class_word(l.class)),
            Some(strength_word(l.strength)),
            None,
        ),
        ManagedTransport::Bridge { origin, .. } => (None, None, None, Some(origin.clone())),
    };
    ManagedRequest {
        launch,
        name: record.name.clone(),
        written_by_migrate_mcp: record.written_by_migrate_mcp,
        registered_by: match record.registered_by {
            SubjectKindRecord::Terminal => SubjectKind::Terminal,
            SubjectKindRecord::Agent => SubjectKind::Agent,
            SubjectKindRecord::Unknown => SubjectKind::Unknown,
        },
        class,
        strength,
        origin,
    }
}

/// Audits a managed request's refusal (`managed_launch`) and returns it.
#[allow(clippy::too_many_arguments)]
fn refused(
    shared: &Shared,
    peer: &PeerIdentity,
    subject: &SubjectEvidence,
    project: &Project,
    record: Option<&ManagedServer>,
    kind: ErrorKind,
    change: Option<CheckError>,
) -> RpcError {
    let (launch, revision) = match record.map(|r| &r.transport) {
        Some(ManagedTransport::Stdio(l)) => (Some(launch_id_text(&l.launch_id)), Some(l.revision)),
        _ => (None, None),
    };
    let (part, old, new) = match change {
        Some(CheckError::Changed { part, old, new }) => (Some(part.name()), Some(old), new),
        _ => (None, None, None),
    };
    shared.audit(AuditEvent::ManagedLaunch {
        pid: peer.pid,
        subject: subject_summary(peer, subject),
        outcome: kind.token(),
        part,
        launch,
        project: Some(project_summary(project)),
        revision,
        old,
        new,
    });
    RpcError::new(kind)
}

/// The request check (see the module documentation): for a project with a
/// record, the request must name its launch or its bridge and hand over
/// its descriptors, and a stdio launch must pass the daemon's own check.
/// `Ok(None)` for a project without a record, whose request must name no
/// launch or bridge. `requested` is the names of the bindings the request
/// resolves to (its profile, references and env file applied): a bridged
/// server's origin digest is checked on each of them, not on the
/// manifest's defaults only. Called without the state lock held, so the
/// launch check (which may copy and hash a large executable) never holds
/// it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_request(
    shared: &Shared,
    peer: &PeerIdentity,
    subject: &SubjectEvidence,
    project: &Project,
    record: Option<&ManagedServer>,
    p: &RunRequestParams,
    has_fds: bool,
    requested: &[&str],
) -> Result<Option<Checked>, RpcError> {
    let mismatch = || {
        refused(
            shared,
            peer,
            subject,
            project,
            record,
            ErrorKind::ManagedCommandMismatch,
            None,
        )
    };
    let Some(record) = record else {
        if p.launch.is_some() || p.bridge.is_some() {
            return Err(mismatch());
        }
        return Ok(None);
    };
    if !has_fds {
        return Err(mismatch());
    }
    match &record.transport {
        ManagedTransport::Stdio(l) => {
            let named = p.launch.as_deref().and_then(parse_launch_id);
            if named != Some(l.launch_id) || p.bridge.is_some() {
                return Err(mismatch());
            }
            // A test stops here, before the daemon's own check.
            envcloak_sys::pause_point("launch.before_check");
            match launch_check::check(l) {
                Ok(checked) => Ok(Some(Checked::Stdio {
                    launch: l.clone(),
                    checked,
                })),
                Err(e @ CheckError::Changed { .. }) => Err(refused(
                    shared,
                    peer,
                    subject,
                    project,
                    Some(record),
                    ErrorKind::ManagedLaunchChanged,
                    Some(e),
                )),
                Err(CheckError::RunnerUnavailable) => Err(refused(
                    shared,
                    peer,
                    subject,
                    project,
                    Some(record),
                    ErrorKind::RunnerUnavailable,
                    None,
                )),
            }
        }
        ManagedTransport::Bridge {
            origin,
            header_names,
        } => {
            let declared = BridgeDecl {
                origin: origin.clone(),
                header_names: header_names.clone(),
            };
            // Every binding the request resolves to, whatever layer chose
            // it: a profile, a reference or an env file can name bindings
            // the manifest's defaults do not.
            // The request resolves to exactly the bindings of the record's
            // headers, whatever layer chose them.
            if p.launch.is_some()
                || p.bridge.as_ref() != Some(&declared)
                || !bindings_carry_origin(requested.iter().copied(), origin)
            {
                return Err(mismatch());
            }
            let Some(headers) = bridge_headers(header_names, origin)
                .filter(|h| same_names(h.iter().map(|(_, b)| b.as_str()), requested.iter()))
            else {
                return Err(mismatch());
            };
            Ok(Some(Checked::Bridge {
                origin: origin.clone(),
                headers,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_origins_and_headers_are_checked() {
        assert!(valid_name("claude-code/github"));
        for bad in ["", "a", "a/", "/b", "a/b/c", "a b/c", &"x".repeat(300)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_origin("https://api.example.test"));
        assert!(valid_origin("http://127.0.0.1:8080"));
        for bad in [
            "https://",
            "ftp://a.test",
            "https://a.test/path",
            "https://user@a.test",
            "https://a.test?q",
            "a.test",
        ] {
            assert!(!valid_origin(bad), "{bad:?}");
        }
        assert!(valid_header("Authorization"));
        assert!(valid_header("X-Api-Key"));
        assert!(!valid_header("Bad Header"));
        assert!(!valid_header(""));
    }

    /// D-18: every binding of a bridged server's manifest must carry its
    /// origin's digest; an edited origin is another suffix.
    #[test]
    fn bindings_carry_their_origin() {
        let s = bridge_binding_suffix("https://api.example.test");
        let good = format!("API_KEY{s}");
        assert!(bindings_carry_origin(
            [good.as_str()],
            "https://api.example.test"
        ));
        assert!(!bindings_carry_origin(
            [good.as_str()],
            "https://api.example.test:444"
        ));
        assert!(!bindings_carry_origin(
            ["API_KEY"],
            "https://api.example.test"
        ));
        assert!(!bindings_carry_origin([], "https://api.example.test"));
    }
}
