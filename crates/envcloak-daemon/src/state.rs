//! The vault slot and its lock state machine (SPEC §5 "Lock", "Unlock
//! flow").
//!
//! The daemon holds at most one open vault file, in one of these states:
//! - [`Slot::Absent`]: there is no vault yet;
//! - [`Slot::Locked`]: the file is open and its lock held, with no key;
//! - [`Slot::Unlocked`]: the VMK and subkeys are in memory;
//! - [`Slot::Busy`]: an unlock or `vault create` has taken the file out to
//!   run Argon2id without holding the state lock;
//! - [`Slot::Unavailable`]: the file exists but could not be opened.
//!
//! Locking drops the [`Vault`], whose VMK, subkeys and decrypted metadata
//! are wiped as they are freed, and keeps the file open. Every lock bumps
//! a generation number; an unlock that started under an older generation
//! (a lock request, sleep or stop arrived while Argon2id ran) finishes
//! locked. A `vault create` in that case still creates the vault, whose
//! Recovery Kit the client has already shown, and leaves it locked; its
//! answer says so. Idle time does not count against an unlock in progress:
//! it applies only to an unlocked vault.
//!
//! The grants ([`envcloak_policy::GrantStore`]) and the passphrase attempt
//! limiter live here too, under the same mutex: a `once` grant is decided
//! and consumed under it, and a lock for any reason drops every grant and
//! pending request (SPEC §5 "Lock"). A proof (`approve`) takes the
//! unlocked vault out ([`State::begin_proof`]) to run Argon2id, as an
//! unlock does; other requests see [`Slot::Busy`] meanwhile, and a lock
//! that arrives wins.
//!
//! The audit log ([`crate::audit::AuditLog`]) lives here too: its writer
//! is opened from the vault when it unlocks and closed, with its keys,
//! when it locks. The head is saved in the vault's sealed header at lock
//! (and so at stop, which locks), and every 15 minutes or 100 entries
//! ([`State::audit_tick`]); a save that fails is tried again (see
//! [`crate::audit::AuditLog`]). A delivery's entry is written durably
//! before the request is answered, or the request is denied
//! ([`State::audit_delivery`]).
//!
//! Every method here runs with the daemon's state mutex held and returns
//! quickly; Argon2id runs between a `begin_*` and its `finish_*`, outside
//! the mutex.

use std::time::Duration;

use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{
    AuditHead, FieldId, Integrity, LockedVault, Vault, VaultError, VaultErrorKind, VaultPaths,
};
use envcloak_core::{PassphraseRejected, RestoreReport, SecretBytes};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::{
    ApprovalsView, AuditStatusView, AuditVerifyView, CreatedView, DaemonView,
    Integrity as IntegrityView, LockReason, LockView, RecoveredView, StatusView, UnlockedView,
    VaultState, VaultView,
};
use envcloak_policy::{AttemptLimiter, GrantId, GrantStore, Now, ProcessInstance};

use crate::audit::{AuditEvent, AuditLog, RequestAudit};
use crate::clock::{Clocks, now_of};
use crate::crowded::Crowded;
use crate::lock::{LockTimer, Reading};

/// The vault as the daemon holds it.
pub enum Slot {
    Absent,
    Locked(LockedVault),
    /// Boxed: a vault holds its keys and metadata inline.
    Unlocked(Box<Vault>),
    Busy,
    Unavailable(&'static str),
}

impl core::fmt::Debug for Slot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Slot::Absent => "Absent",
            Slot::Locked(_) => "Locked",
            Slot::Unlocked(_) => "Unlocked",
            Slot::Busy => "Busy",
            Slot::Unavailable(_) => "Unavailable",
        })
    }
}

/// Why [`State::deliver`] released nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The vault is not unlocked and verified, or a value could not be
    /// read.
    Refused(RpcError),
    /// The answer the values make could not be built: too large for one
    /// frame (F-77). Nothing was recorded or released.
    Unsendable(RpcError),
    /// The grant was no longer in force once the answer was built: it ran
    /// out while the values were read and framed (F-77). Nothing was
    /// recorded or released.
    Lapsed,
    /// The delivery's audit entry could not be written.
    AuditFailed,
}

/// What `begin_unlock` found.
#[derive(Debug)]
pub enum BeginUnlock {
    /// Already unlocked; nothing to check.
    Already(UnlockedView),
    /// The locked file, taken out of the slot, and the generation to
    /// finish under.
    Proceed(LockedVault, u64),
}

/// How the audit log's head is saved in the vault's header.
type SaveHead = fn(&mut Vault, AuditHead) -> Result<(), VaultError>;

/// The daemon's vault state.
#[derive(Debug)]
pub struct State {
    slot: Slot,
    paths: VaultPaths,
    timer: LockTimer,
    last_reason: Option<LockReason>,
    generation: u64,
    failed_unlocks: u32,
    grants: GrantStore,
    limiter: AttemptLimiter,
    audit: AuditLog,
    /// The head of a log closed while a proof had the vault out: saved in
    /// the header when the vault comes back ([`State::finish_proof`]).
    unsaved_head: Option<AuditHead>,
    /// [`Vault::save_audit_head`]; tests put a failing one in its place.
    save_head: SaveHead,
    /// `too_many_pending` answers counted, not yet written
    /// ([`crate::crowded`]).
    crowded: Crowded,
    /// Backups v2 in progress and restore leases ([`crate::backups`]).
    backups: crate::backups::Registry,
}

impl State {
    /// Opens the vault at `paths` if there is one, locked.
    pub fn open(paths: VaultPaths, idle_limit: Duration, now: Reading) -> Self {
        State {
            slot: probe(&paths),
            paths,
            timer: LockTimer::new(idle_limit, now),
            last_reason: None,
            generation: 0,
            failed_unlocks: 0,
            grants: GrantStore::new(),
            limiter: AttemptLimiter::new(),
            audit: AuditLog::default(),
            unsaved_head: None,
            save_head: Vault::save_audit_head,
            crowded: Crowded::default(),
            backups: crate::backups::Registry::default(),
        }
    }

    #[cfg(test)]
    pub fn slot(&self) -> &Slot {
        &self.slot
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    /// The grants and pending requests.
    pub fn grants(&mut self) -> &mut GrantStore {
        &mut self.grants
    }

    /// Backups v2 in progress and restore leases.
    pub fn backups(&mut self) -> &mut crate::backups::Registry {
        &mut self.backups
    }

    /// The passphrase attempt limiter, shared by every proof.
    pub fn limiter(&mut self) -> &mut AttemptLimiter {
        &mut self.limiter
    }

    /// The unlocked vault, for a request that reads its metadata under the
    /// state lock.
    ///
    /// # Errors
    /// [`ErrorKind::VaultLocked`], [`ErrorKind::NoVault`],
    /// [`ErrorKind::Busy`] or [`ErrorKind::VaultUnavailable`] when it is
    /// not unlocked, and [`ErrorKind::VaultTampered`] when it failed its
    /// integrity check: no grant is evaluated from such a vault, and no
    /// proof taken.
    pub fn unlocked(&self) -> Result<&Vault, RpcError> {
        match &self.slot {
            Slot::Unlocked(v) if v.integrity() == Integrity::Ok => Ok(v),
            Slot::Unlocked(_) => Err(RpcError::new(ErrorKind::VaultTampered)),
            Slot::Locked(_) => Err(RpcError::new(ErrorKind::VaultLocked)),
            Slot::Absent => Err(RpcError::new(ErrorKind::NoVault)),
            Slot::Busy => Err(RpcError::new(ErrorKind::Busy)),
            Slot::Unavailable(r) => Err(RpcError::with_reason(ErrorKind::VaultUnavailable, r)),
        }
    }

    /// Refuses (`vault_tampered`) while the open vault has failed its
    /// integrity check, whatever else a request needs: nothing is shown
    /// for a person to approve from a vault no proof can be taken for.
    ///
    /// # Errors
    /// [`ErrorKind::VaultTampered`].
    pub fn refuse_if_tampered(&self) -> Result<(), RpcError> {
        match &self.slot {
            Slot::Unlocked(v) if v.integrity() != Integrity::Ok => {
                Err(RpcError::new(ErrorKind::VaultTampered))
            }
            _ => Ok(()),
        }
    }

    /// The unlocked vault, for a request that writes to it under the state
    /// lock (`items.add`, and `items.rotate` and `items.remove` once their
    /// proof has passed).
    ///
    /// # Errors
    /// As [`State::unlocked`].
    pub fn unlocked_mut(&mut self) -> Result<&mut Vault, RpcError> {
        self.unlocked()?;
        match &mut self.slot {
            Slot::Unlocked(v) => Ok(v),
            _ => Err(RpcError::new(ErrorKind::Internal)),
        }
    }

    /// Records activity at `now`: a covered request or an approval keeps
    /// the vault from locking idle.
    pub fn touch(&mut self, now: Reading) {
        self.timer.touch(now);
    }

    /// Starts a proof: takes the unlocked vault out of the slot for the
    /// caller to run Argon2id on, and the generation to finish under. The
    /// vault must be unlocked and verified.
    ///
    /// # Errors
    /// As [`State::unlocked`].
    pub fn begin_proof(&mut self) -> Result<(Box<Vault>, u64), RpcError> {
        self.unlocked()?;
        match std::mem::replace(&mut self.slot, Slot::Busy) {
            Slot::Unlocked(v) => Ok((v, self.generation)),
            other => {
                self.slot = other;
                Err(RpcError::new(ErrorKind::Internal))
            }
        }
    }

    /// Finishes a proof begun under `generation`: puts the vault back, or
    /// locks it when a lock arrived meanwhile.
    ///
    /// # Errors
    /// [`ErrorKind::VaultLocked`] when a lock arrived meanwhile.
    pub fn finish_proof(&mut self, generation: u64, vault: Box<Vault>) -> Result<(), RpcError> {
        if generation == self.generation {
            self.slot = Slot::Unlocked(vault);
            Ok(())
        } else {
            let mut vault = vault;
            if let Some(head) = self.unsaved_head.take() {
                save_at_lock(self.save_head, &mut vault, head);
            }
            self.slot = Slot::Locked((*vault).lock());
            Err(RpcError::new(ErrorKind::VaultLocked))
        }
    }

    /// Runs the sleep and idle checks at `now`. Returns the reason when it
    /// locked the vault.
    pub fn observe(&mut self, now: Reading) -> Option<LockReason> {
        let reason = self.timer.observe(now)?;
        if reason == LockReason::Idle && !matches!(self.slot, Slot::Unlocked(_)) {
            return None;
        }
        self.lock(reason).then_some(reason)
    }

    /// Locks for `reason`. Returns whether a vault was unlocked. An unlock
    /// in progress finishes locked, unless the reason is idle time.
    pub fn lock(&mut self, reason: LockReason) -> bool {
        // The `too_many_pending` answers still counted are written while
        // the log is open (crate::crowded).
        for e in self.crowded.drain() {
            self.audit(AuditEvent::Request(Box::new(e)));
        }
        // Whatever the slot holds, a lock ends every grant and pending
        // request (SPEC §5 "Lock"), every backup v2 in progress and every
        // restore lease.
        self.grants.on_lock();
        self.backups.on_lock();
        let recorded = matches!(self.slot, Slot::Unlocked(_))
            || (matches!(self.slot, Slot::Busy) && reason != LockReason::Idle);
        if recorded {
            self.audit(AuditEvent::Locked { reason });
        }
        match std::mem::replace(&mut self.slot, Slot::Absent) {
            Slot::Unlocked(mut v) => {
                // The log's keys go with the vault's; its head is saved
                // in the header first.
                if let Some(head) = self.audit.close() {
                    save_at_lock(self.save_head, &mut v, head);
                }
                // Dropping the Vault wipes the VMK, the subkeys and the
                // decrypted metadata; the file stays open and locked.
                self.slot = Slot::Locked((*v).lock());
                self.generation += 1;
                self.last_reason = Some(reason);
                true
            }
            Slot::Busy => {
                self.slot = Slot::Busy;
                if reason != LockReason::Idle {
                    // A proof has the vault out: the head is saved when it
                    // comes back locked.
                    if let Some(head) = self.audit.close() {
                        self.unsaved_head = Some(head);
                    }
                    self.generation += 1;
                    self.last_reason = Some(reason);
                }
                false
            }
            other => {
                self.slot = other;
                false
            }
        }
    }

    /// Starts an unlock: takes the locked file out of the slot.
    pub fn begin_unlock(&mut self) -> Result<BeginUnlock, RpcError> {
        match std::mem::replace(&mut self.slot, Slot::Busy) {
            Slot::Locked(v) => Ok(BeginUnlock::Proceed(v, self.generation)),
            Slot::Unlocked(v) => {
                let view = unlocked_view(&v, true);
                self.slot = Slot::Unlocked(v);
                Ok(BeginUnlock::Already(view))
            }
            other => {
                let e = match &other {
                    Slot::Absent => RpcError::new(ErrorKind::NoVault),
                    Slot::Busy => RpcError::new(ErrorKind::Busy),
                    Slot::Unavailable(r) => RpcError::with_reason(ErrorKind::VaultUnavailable, r),
                    Slot::Locked(_) | Slot::Unlocked(_) => RpcError::new(ErrorKind::Internal),
                };
                self.slot = other;
                Err(e)
            }
        }
    }

    /// Finishes an unlock begun under `generation` with Argon2id's result.
    pub fn finish_unlock(
        &mut self,
        generation: u64,
        now: Reading,
        result: Result<Vault, (LockedVault, VaultError)>,
    ) -> Result<UnlockedView, RpcError> {
        match result {
            Ok(v) if generation == self.generation => {
                let view = unlocked_view(&v, false);
                self.start_grants(&v);
                self.slot = Slot::Unlocked(Box::new(v));
                self.timer.touch(now);
                self.audit_open();
                Ok(view)
            }
            Ok(v) => {
                // Locked while Argon2id ran.
                self.slot = Slot::Locked(v.lock());
                Err(RpcError::new(ErrorKind::VaultLocked))
            }
            Err((locked, e)) => {
                self.slot = Slot::Locked(locked);
                let e = unlock_error(e.kind());
                if e.kind == ErrorKind::WrongPassphrase {
                    self.failed_unlocks = self.failed_unlocks.saturating_add(1);
                }
                Err(e)
            }
        }
    }

    /// An unlocked vault: the grant store starts empty at its epochs.
    fn start_grants(&mut self, v: &Vault) {
        self.grants.on_lock();
        let policy_epoch = v.header().map(|h| h.policy_epoch).unwrap_or(0);
        self.grants.set_epochs(v.epoch(), policy_epoch);
    }

    /// Starts `vault create`: there must be no vault.
    pub fn begin_create(&mut self) -> Result<u64, RpcError> {
        match &self.slot {
            Slot::Absent => {
                self.slot = Slot::Busy;
                Ok(self.generation)
            }
            Slot::Locked(_) | Slot::Unlocked(_) => Err(RpcError::new(ErrorKind::VaultExists)),
            Slot::Busy => Err(RpcError::new(ErrorKind::Busy)),
            Slot::Unavailable(r) => Err(RpcError::with_reason(ErrorKind::VaultUnavailable, r)),
        }
    }

    /// Finishes `vault create` begun under `generation`. A vault created
    /// after a lock arrived is kept, locked: it exists under the passphrase
    /// and the kit the client sent, so the answer is a success that says it
    /// is locked, never an error that would make the kit look void.
    pub fn finish_create(
        &mut self,
        generation: u64,
        now: Reading,
        result: Result<Vault, VaultError>,
    ) -> Result<CreatedView, RpcError> {
        match result {
            Ok(v) if generation == self.generation => {
                let view = created_view(&v, false);
                self.start_grants(&v);
                self.slot = Slot::Unlocked(Box::new(v));
                self.timer.touch(now);
                self.audit_open();
                Ok(view)
            }
            Ok(v) => {
                let view = created_view(&v, true);
                self.slot = Slot::Locked(v.lock());
                Ok(view)
            }
            Err(e) => {
                // Whatever the failure left on disk decides the slot.
                self.slot = probe(&self.paths);
                Err(create_error(e.kind()))
            }
        }
    }

    /// Starts `vault.recover`: closes the vault file, so the restore can
    /// take its lock, and leaves the slot busy. A vault that was unlocked
    /// is locked first, which ends every grant and pending request and
    /// saves the audit log's head. Returns the generation to finish under,
    /// and whether a vault was unlocked.
    ///
    /// # Errors
    /// [`ErrorKind::Busy`] while an unlock, a creation, a proof or another
    /// restore runs.
    pub fn begin_recover(&mut self) -> Result<(u64, bool), RpcError> {
        if matches!(self.slot, Slot::Busy) {
            return Err(RpcError::new(ErrorKind::Busy));
        }
        let was_unlocked = self.lock(LockReason::Restore);
        // Dropping the locked file closes it and releases its lock.
        self.slot = Slot::Busy;
        Ok((self.generation, was_unlocked))
    }

    /// Finishes `vault.recover` begun under `generation` with the
    /// restore's result. A restored vault is unlocked, or kept locked when
    /// a lock arrived meanwhile: it is the vault on disk either way, under
    /// the new passphrase, so the answer is a success that says so. After a
    /// failure the slot holds whatever is on disk: the old vault (the
    /// restore changes nothing before the new file is ready), or none.
    pub fn finish_recover(
        &mut self,
        generation: u64,
        now: Reading,
        result: Result<(Vault, RestoreReport), VaultError>,
    ) -> Result<RecoveredView, RpcError> {
        match result {
            Ok((v, report)) => {
                let locked = generation != self.generation;
                let view = RecoveredView {
                    items: u64::try_from(report.items).unwrap_or(u64::MAX),
                    backup_created_secs: report.backup_created_at,
                    replaced: u64::try_from(report.replaced.len()).unwrap_or(u64::MAX),
                    locked,
                };
                if locked {
                    self.slot = Slot::Locked(v.lock());
                } else {
                    self.start_grants(&v);
                    self.slot = Slot::Unlocked(Box::new(v));
                    self.timer.touch(now);
                    self.audit_open();
                }
                Ok(view)
            }
            Err(e) => {
                self.slot = probe(&self.paths);
                Err(crate::backup::recover_error(e.kind()))
            }
        }
    }

    /// The vault, lock and approvals parts of `status`.
    pub fn status(&self, now: Reading, at: &Now, daemon: DaemonView) -> StatusView {
        let (state, integrity, read_only, unavailable) = match &self.slot {
            Slot::Absent => (VaultState::Absent, None, false, None),
            Slot::Locked(_) | Slot::Busy => (VaultState::Locked, None, false, None),
            Slot::Unlocked(v) => {
                let u = unlocked_view(v, false);
                (VaultState::Unlocked, Some(u.integrity), u.read_only, None)
            }
            Slot::Unavailable(r) => (VaultState::Unavailable, None, false, Some((*r).to_owned())),
        };
        let unlocked = matches!(self.slot, Slot::Unlocked(_));
        let (queued, dropped) = self.audit.backlog();
        StatusView {
            daemon,
            audit: AuditStatusView {
                open: self.audit.is_open(),
                head_seq: self.audit.head().map(|h| h.seq),
                unanchored: self.audit.unanchored(),
                anchor_failed: self.audit.anchor_failed(),
                queued,
                dropped,
            },
            vault: VaultView {
                state,
                integrity,
                read_only,
                unavailable,
                busy: matches!(self.slot, Slot::Busy),
                failed_unlocks: self.failed_unlocks,
            },
            lock: LockView {
                last_reason: self.last_reason,
                idle_limit_secs: self.timer.idle_limit().as_secs(),
                idle_remaining_secs: unlocked.then(|| self.timer.idle_remaining(now).as_secs()),
            },
            approvals: self.approvals(at),
        }
    }

    /// Records `e` in the audit log (and its line on standard error):
    /// written now when the log is open, queued otherwise (see
    /// [`crate::audit::AuditLog`]).
    pub fn audit(&mut self, e: AuditEvent) {
        if let Some(line) = e.line() {
            log_line!("{line}");
        }
        self.audit_open();
        self.audit.record(e.record());
        self.anchor_if_due(None);
    }

    /// Writes a delivery's entry durably, before anything is released
    /// (SPEC §6.1 step 5, gate 33). Returns false when it could not be
    /// written: the request must then be denied, and nothing released.
    pub fn audit_delivery(&mut self, e: AuditEvent) -> bool {
        self.audit_open();
        let written = Self::write_delivery(&mut self.audit, e);
        if written {
            self.anchor_if_due(None);
        }
        written
    }

    /// The durable append alone, so a provisional project transaction can
    /// roll back on failure. Anchoring waits until that transaction ends.
    fn write_delivery(audit: &mut AuditLog, e: AuditEvent) -> bool {
        match audit.write_now(&e.record()) {
            Ok(_) => {
                if let Some(line) = e.line() {
                    log_line!("{line}");
                }
                true
            }
            Err(err) => {
                log_line!(
                    "envcloakd: audit: a delivery's entry could not be written ({}); the request \
                     is denied",
                    err.kind().token()
                );
                false
            }
        }
    }

    /// A covered request's delivery under `grant` (SPEC §6.1 step 5, gate
    /// 33): reads the value of each field from the verified vault, builds
    /// the answer from them with `answer` (the frame that will be sent, so
    /// an answer too large for one is known before anything is committed,
    /// F-77), asks whether `grant` is still in force on `clocks` read then
    /// and with its root still running as `alive` tells (the reads and the
    /// framing come after the decision, and a grant that ran out, or whose
    /// root exited, meanwhile covers nothing: F-77, SPEC §10b), then
    /// stages any project adoption in a vault transaction, rechecks the
    /// grant, writes the delivery's entry durably, commits the adoption,
    /// and only then gives the answer out. A lapse or audit failure rolls
    /// back the staged adoption, including a previous record's last seen.
    /// The answer is the only way to a release, so no value leaves
    /// the daemon before its entry is on disk. The caller holds the state
    /// lock from its decision to its use of the grant, so nothing else in
    /// the daemon ends the grant meanwhile; only time and the root's exit
    /// do, and the tick's sweep, which removes a grant whose root exited,
    /// waits for that lock.
    ///
    /// # Errors
    /// [`Delivery::Refused`] when the vault is not unlocked and verified,
    /// or a value cannot be read (a vault that turns out changed on disk
    /// is marked tampered by the read, and releases nothing more), or the
    /// project transaction fails. A failed commit after the audit append
    /// can leave an audit entry for the covered attempt, never an answer
    /// or a committed adoption. [`Delivery::Unsendable`] with `answer`'s error,
    /// and [`Delivery::Lapsed`] when the grant is no longer in force, which
    /// then sweeps the grants as the tick does (a grant whose root exited
    /// is removed, so the request decided again is not covered by it);
    /// nothing is recorded then either, and the answer is dropped, and
    /// wiped. [`Delivery::AuditFailed`] when the entry could not be
    /// written; the answer is dropped, and wiped.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver<T>(
        &mut self,
        grant: GrantId,
        clocks: &dyn Clocks,
        alive: &dyn Fn(&ProcessInstance) -> bool,
        e: AuditEvent,
        fields: &[FieldId],
        project: Option<envcloak_core::vault::ProjectRecord>,
        answer: impl FnOnce(Vec<SecretBytes>) -> Result<T, RpcError>,
    ) -> Result<T, Delivery> {
        let vault = self.unlocked().map_err(Delivery::Refused)?;
        let values = fields
            .iter()
            .map(|f| vault.read_value(*f))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                Delivery::Refused(match e.kind() {
                    VaultErrorKind::Tampered => RpcError::new(ErrorKind::VaultTampered),
                    k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
                })
            })?;
        if vault.integrity() != Integrity::Ok {
            return Err(Delivery::Refused(RpcError::new(ErrorKind::VaultTampered)));
        }
        let answer = answer(values).map_err(Delivery::Unsendable)?;
        let now = now_of(clocks);
        if !self.grants.in_force(grant, &now, alive) {
            self.grants.sweep(&now, alive);
            return Err(Delivery::Lapsed);
        }
        if let Some(mut project) = project {
            project.last_seen = now
                .wall
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Delivery::Refused(RpcError::new(ErrorKind::Internal)))?
                .as_secs();
            self.audit_open();
            let Slot::Unlocked(vault) = &mut self.slot else {
                return Err(Delivery::Refused(RpcError::new(ErrorKind::VaultLocked)));
            };
            let grants = &mut self.grants;
            let audit = &mut self.audit;
            let mut refusal = None;
            let result = vault.transact(|t| {
                t.upsert_project(project)?;
                // No project state is published yet. Recheck after staging,
                // then audit before committing or releasing the answer.
                let now = now_of(clocks);
                if !grants.in_force(grant, &now, alive) {
                    grants.sweep(&now, alive);
                    refusal = Some(Delivery::Lapsed);
                } else if !Self::write_delivery(audit, e) {
                    refusal = Some(Delivery::AuditFailed);
                }
                if refusal.is_some() {
                    // Interrupt the vault transaction; the caller receives
                    // the precise refusal below, never this rollback marker.
                    return Err(VaultErrorKind::Io(std::io::ErrorKind::Interrupted).into());
                }
                Ok(())
            });
            // Saving the log head also writes the vault, so it cannot run
            // inside the adoption transaction. It is independent of adoption.
            self.anchor_if_due(None);
            result.map_err(|e| {
                refusal.unwrap_or_else(|| {
                    Delivery::Refused(RpcError::with_reason(
                        ErrorKind::VaultUnavailable,
                        vault_reason(e.kind()),
                    ))
                })
            })?;
        } else if !self.audit_delivery(e) {
            return Err(Delivery::AuditFailed);
        }
        Ok(answer)
    }

    /// A `too_many_pending` answer to the request with fingerprint `key`
    /// at awake time `awake`: written now, with the answers it stands for,
    /// or counted toward a later entry ([`crate::crowded`]).
    pub fn audit_crowded(&mut self, key: [u8; 32], e: RequestAudit, awake: Duration) {
        if let Some(e) = self.crowded.answer(key, e, awake) {
            self.audit(AuditEvent::Request(Box::new(e)));
        }
    }

    /// The tick's part: writes the `too_many_pending` answers counted for
    /// a minute ([`crate::crowded`]); saves the head when 15 minutes
    /// passed awake with entries not yet anchored, or tries again after a
    /// save that failed.
    pub fn audit_tick(&mut self, now: Reading) {
        for e in self.crowded.due(now.awake) {
            self.audit(AuditEvent::Request(Box::new(e)));
        }
        self.anchor_if_due(Some(now.awake));
    }

    /// Opens the log's writer when the vault is unlocked and it is not
    /// open yet (after an unlock, or after the log's directory was
    /// unusable).
    fn audit_open(&mut self) {
        if let Slot::Unlocked(v) = &self.slot {
            self.audit.open(v);
        }
    }

    /// Saves the head in the header when a save is due and the vault is
    /// here to take it. A failure is reported once, until a save succeeds
    /// again; the entries stay counted and a tick tries again.
    fn anchor_if_due(&mut self, awake: Option<Duration>) {
        let Slot::Unlocked(v) = &mut self.slot else {
            return;
        };
        let Some(head) = self.audit.anchor_due(awake) else {
            return;
        };
        let saved = (self.save_head)(v, head);
        if self.audit.anchor_saved(saved.is_ok(), awake) {
            match saved {
                Err(e) => log_line!(
                    "envcloakd: warning: the audit log's head could not be saved in the vault \
                     ({}); it is tried again",
                    vault_reason(e.kind())
                ),
                Ok(()) => log_line!("envcloakd: the audit log's head was saved in the vault again"),
            }
        }
    }

    /// `audit.verify`: the log checked against the head saved in the
    /// header, and whether it still ends where this daemon last wrote it.
    ///
    /// # Errors
    /// As [`State::unlocked`], and [`ErrorKind::AuditUnavailable`] when
    /// the log's directory cannot be read.
    pub fn audit_verify(&mut self) -> Result<AuditVerifyView, RpcError> {
        let report = self
            .unlocked()?
            .verify_audit()
            .map_err(|_| RpcError::new(ErrorKind::AuditUnavailable))?;
        let mut view = AuditVerifyView::from(&report);
        view.live_head_matches = self.audit.head().map(|h| (h.seq, h.mac) == report.head);
        (view.queued, view.dropped) = self.audit.backlog();
        Ok(view)
    }

    /// The grants, pending requests and limiter parts of `status`.
    pub fn approvals(&self, at: &Now) -> ApprovalsView {
        let (grants, pending) = self.grants.counts(at);
        ApprovalsView {
            grants: u32::try_from(grants).unwrap_or(u32::MAX),
            pending: u32::try_from(pending).unwrap_or(u32::MAX),
            proof_failures: self.limiter.failures(),
            proof_wait_secs: self.limiter.wait_remaining(at).as_secs(),
        }
    }
}

/// Saves the audit head in `v`'s header as the vault locks. A failure (a
/// vault that failed its integrity check is read-only) is reported, and the
/// entries stay in the unanchored tail: the next unlock counts them and
/// saves the head when a save is due.
fn save_at_lock(save: SaveHead, v: &mut Vault, head: AuditHead) {
    if let Err(e) = save(v, head) {
        log_line!(
            "envcloakd: warning: the audit log's head could not be saved in the vault ({}); it \
             is tried again after the next unlock",
            vault_reason(e.kind())
        );
    }
}

/// The slot for whatever is at `paths` now.
fn probe(paths: &VaultPaths) -> Slot {
    match LockedVault::open(paths) {
        Ok(v) => Slot::Locked(v),
        Err(e) if e.kind() == VaultErrorKind::NotFound => Slot::Absent,
        Err(e) => Slot::Unavailable(vault_reason(e.kind())),
    }
}

fn created_view(v: &Vault, locked: bool) -> CreatedView {
    let u = unlocked_view(v, false);
    CreatedView {
        locked,
        integrity: u.integrity,
        read_only: u.read_only,
    }
}

fn unlocked_view(v: &Vault, already: bool) -> UnlockedView {
    let integrity = match v.integrity() {
        Integrity::Ok => IntegrityView::Ok,
        _ => IntegrityView::Tampered,
    };
    UnlockedView {
        integrity,
        read_only: integrity != IntegrityView::Ok || v.migration_error().is_some(),
        already,
    }
}

/// Why a vault file could not be used, as a token from
/// [`envcloak_ipc::proto::REASONS`].
pub fn vault_reason(k: VaultErrorKind) -> &'static str {
    match k {
        VaultErrorKind::Busy => "busy",
        VaultErrorKind::UnsupportedVersion => "unsupported_version",
        VaultErrorKind::Path(_) => "permissions",
        VaultErrorKind::DiskFull => "disk_full",
        VaultErrorKind::Storage(_) => "storage",
        VaultErrorKind::Io(_) => "io",
        VaultErrorKind::Migration => "migration",
        _ => "damaged",
    }
}

/// Why a backup could not be written, for a log line: [`vault_reason`],
/// or `substituted` for a file the vault wrote that its name did not hold
/// once linked, or that did not hold exactly the bytes written (something
/// replaced, cut or wrote into it inside the vault's directory), which is
/// not damage.
pub fn backup_reason(k: VaultErrorKind) -> &'static str {
    match k {
        VaultErrorKind::Substituted => "substituted",
        k => vault_reason(k),
    }
}

/// An unlock failure. A wrong passphrase and a damaged or missing
/// passphrase envelope give the one generic error (gate 3).
fn unlock_error(k: VaultErrorKind) -> RpcError {
    match k {
        VaultErrorKind::Crypto(_) | VaultErrorKind::NoPassphrase => {
            RpcError::new(ErrorKind::WrongPassphrase)
        }
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

/// A `vault create` failure.
pub fn create_error(k: VaultErrorKind) -> RpcError {
    match k {
        VaultErrorKind::AlreadyExists => RpcError::new(ErrorKind::VaultExists),
        VaultErrorKind::Passphrase(r) => passphrase_error(r),
        VaultErrorKind::Crypto(CryptoErrorKind::KdfParams) => RpcError::new(ErrorKind::KdfParams),
        k => RpcError::with_reason(ErrorKind::VaultUnavailable, vault_reason(k)),
    }
}

/// A passphrase that breaks the rules, with the rule as its reason.
pub fn passphrase_error(r: PassphraseRejected) -> RpcError {
    let reason = match r {
        PassphraseRejected::NotText => "not_text",
        PassphraseRejected::ControlCharacter => "control_character",
        PassphraseRejected::TooShort => "too_short",
        PassphraseRejected::Common => "common",
        _ => return RpcError::new(ErrorKind::PassphraseRejected),
    };
    RpcError::with_reason(ErrorKind::PassphraseRejected, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clocks, FakeClocks};
    use envcloak_core::crypto::KdfParams;
    use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};

    /// A vault backup that something replaced under its name is logged as
    /// that, not as damage (verifier, M2-05 round 9).
    #[test]
    fn a_substituted_backup_is_logged_as_substituted() {
        assert_eq!(backup_reason(VaultErrorKind::Substituted), "substituted");
        assert_eq!(backup_reason(VaultErrorKind::DiskFull), "disk_full");
        assert_eq!(vault_reason(VaultErrorKind::Substituted), "damaged");
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: VaultPaths,
        clocks: FakeClocks,
    }

    const PASS: &[u8] = b"a passphrase long enough to pass";

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        Fixture {
            _dir: dir,
            paths,
            clocks: FakeClocks::new(),
        }
    }

    fn now(c: &dyn Clocks) -> Reading {
        Reading::now(c)
    }

    fn at(c: &dyn Clocks) -> Now {
        crate::clock::now_of(c)
    }

    fn daemon_view() -> DaemonView {
        DaemonView {
            version: "test".into(),
            pid: 1,
            hardening: envcloak_sys::hardening_status().into(),
            runtime_dir_fallback: false,
        }
    }

    fn create(f: &Fixture, s: &mut State) {
        let generation = s.begin_create().unwrap();
        let v = create_vault_with_kit(
            &f.paths,
            &SecretBytes::copy_from(PASS),
            &RecoveryKit::generate(),
            KdfParams::minimum(),
        );
        s.finish_create(generation, now(&f.clocks), v).unwrap();
    }

    fn unlock(f: &Fixture, s: &mut State, pass: &[u8]) -> Result<UnlockedView, RpcError> {
        match s.begin_unlock()? {
            BeginUnlock::Already(v) => Ok(v),
            BeginUnlock::Proceed(locked, generation) => {
                let r = locked.unlock_with_passphrase(&SecretBytes::copy_from(pass));
                s.finish_unlock(generation, now(&f.clocks), r)
            }
        }
    }

    #[test]
    fn create_unlock_and_lock() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        assert!(matches!(s.slot(), Slot::Absent));
        assert_eq!(
            unlock(&f, &mut s, PASS).unwrap_err().kind,
            ErrorKind::NoVault
        );
        create(&f, &mut s);
        assert!(matches!(s.slot(), Slot::Unlocked(_)));
        assert_eq!(s.begin_create().unwrap_err().kind, ErrorKind::VaultExists);
        assert!(unlock(&f, &mut s, PASS).unwrap().already);

        assert!(s.lock(LockReason::Request));
        assert!(!s.lock(LockReason::Request));
        assert!(matches!(s.slot(), Slot::Locked(_)));
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!(st.vault.state, VaultState::Locked);
        assert_eq!(st.lock.last_reason, Some(LockReason::Request));
        assert_eq!(st.lock.idle_remaining_secs, None);

        let e = unlock(&f, &mut s, b"not the passphrase at all").unwrap_err();
        assert_eq!(e.kind, ErrorKind::WrongPassphrase);
        assert!(matches!(s.slot(), Slot::Locked(_)));
        assert_eq!(
            s.status(now(&f.clocks), &at(&f.clocks), daemon_view())
                .vault
                .failed_unlocks,
            1
        );
        let v = unlock(&f, &mut s, PASS).unwrap();
        assert!(!v.already);
        assert_eq!(v.integrity, IntegrityView::Ok);
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!(st.vault.state, VaultState::Unlocked);
        assert_eq!(st.lock.idle_remaining_secs, Some(8 * 3600));
    }

    /// The idle lock, driven through injected clocks.
    #[test]
    fn idle_time_locks_an_unlocked_vault() {
        let f = fixture();
        let idle = Duration::from_secs(600);
        let mut s = State::open(f.paths.clone(), idle, now(&f.clocks));
        create(&f, &mut s);
        for _ in 0..599 {
            f.clocks.run(Duration::from_secs(1));
            assert_eq!(s.observe(now(&f.clocks)), None);
        }
        f.clocks.run(Duration::from_secs(1));
        assert_eq!(s.observe(now(&f.clocks)), Some(LockReason::Idle));
        assert!(matches!(s.slot(), Slot::Locked(_)));
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!(st.lock.last_reason, Some(LockReason::Idle));
        // Locked already: later ticks report nothing.
        f.clocks.run(Duration::from_secs(1));
        assert_eq!(s.observe(now(&f.clocks)), None);

        // An unlock starts the idle time again.
        unlock(&f, &mut s, PASS).unwrap();
        f.clocks.run(Duration::from_secs(599));
        assert_eq!(s.observe(now(&f.clocks)), None);
    }

    /// Sleep detection, driven through injected clocks.
    #[test]
    fn sleep_locks_an_unlocked_vault() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        f.clocks.run(Duration::from_secs(1));
        assert_eq!(s.observe(now(&f.clocks)), None);
        f.clocks.sleep(Duration::from_secs(3600));
        assert_eq!(s.observe(now(&f.clocks)), Some(LockReason::Sleep));
        assert!(matches!(s.slot(), Slot::Locked(_)));
        assert_eq!(
            s.status(now(&f.clocks), &at(&f.clocks), daemon_view())
                .lock
                .last_reason,
            Some(LockReason::Sleep)
        );
    }

    /// A process in a terminal session: pid, start time, session.
    fn ancestor(pid: i32, sid: i32) -> envcloak_policy::Ancestor {
        envcloak_policy::Ancestor {
            instance: envcloak_policy::ProcessInstance {
                pid,
                start_time: envcloak_sys::StartTime::from_raw(10 * u64::from(pid.unsigned_abs())),
                pidversion: None,
                exe: None,
            },
            sid: Some(sid),
            terminal: None,
            agent: None,
        }
    }

    /// A request from a terminal session (envcloak 90 <- zsh 70, the
    /// session leader <- login 60 <- launchd 1) for `env` bound to a new
    /// item.
    fn request(env: &str) -> envcloak_policy::AccessRequest {
        use envcloak_core::vault::{Classification, FieldId, FieldName, ItemId, Slug};
        use envcloak_policy::{
            AccessRequest, BoundBinding, BoundRef, ChainEnd, Claims, EnvName, Mode,
            ProjectIdentity, SubjectEvidence,
        };
        let subject = SubjectEvidence::from_chain(
            vec![
                ancestor(90, 70),
                ancestor(70, 70),
                ancestor(60, 60),
                ancestor(1, 1),
            ],
            ChainEnd::Top,
            true,
            Claims::none(),
            None,
        )
        .unwrap();
        AccessRequest {
            subject,
            project: ProjectIdentity {
                canonical_dir: "/src/acme-web".into(),
                dev: 1,
                ino: 100,
                manifest_path: "/src/acme-web/envcloak.toml".into(),
            },
            manifest_sha256: [7u8; 32],
            bindings: vec![BoundRef {
                binding: BoundBinding {
                    env_name: EnvName::new(env).unwrap(),
                    item: ItemId::generate(),
                    field: FieldId::generate(),
                    classification: Classification::Test,
                },
                slug: Slug::new("openai/acme-web").unwrap(),
                field_name: FieldName::new("value").unwrap(),
                first_use: false,
                source: envcloak_policy::BindingSource::Env,
            }],
            mode: Mode::Inject,
            argv_display: vec!["./emit".to_owned()],
            new_project: false,
        }
    }

    /// Gate 29: a lock for any reason ends every grant and pending
    /// request: idle time, sleep and a signal as well as a request. The
    /// grant here lasts 8 hours and the request 10 minutes awake, so
    /// neither expires on its own in these steps.
    #[test]
    fn every_lock_ends_grants_and_pending_requests() {
        use envcloak_policy::{
            ApprovalOptions, ApprovalProof, DEFAULT_TTL, Decision, ProofKind, Uses,
            statement_digest,
        };
        let idle = Duration::from_secs(120);
        for reason in [
            LockReason::Idle,
            LockReason::Sleep,
            LockReason::Signal,
            LockReason::Request,
        ] {
            let f = fixture();
            let mut s = State::open(f.paths.clone(), idle, now(&f.clocks));
            create(&f, &mut s);
            let t = at(&f.clocks);
            let first = request("OPENAI_API_KEY");
            let Decision::Pending(approved) = s.grants().decide(first.clone(), &t) else {
                panic!("expected a pending request");
            };
            let opts = ApprovalOptions {
                uses: Uses::Session,
                ttl_secs: DEFAULT_TTL.as_secs(),
                live: Vec::new(),
            };
            let vault = metas(&first);
            let digest = statement_digest(
                &s.grants()
                    .pending_descriptor(&approved, &t, &vault)
                    .unwrap(),
                &opts,
            );
            let proof = ApprovalProof {
                approver: first.subject.clone(),
                kind: ProofKind::Passphrase,
            };
            let g = s
                .grants()
                .approve(&approved, proof, opts, digest, &t, &vault)
                .unwrap();
            // Another item: the grant does not cover it.
            let Decision::Pending(waiting) = s.grants().decide(request("GITHUB_TOKEN"), &t) else {
                panic!("expected a pending request");
            };
            let counts = |s: &State, t: &Now| {
                let a = s.approvals(t);
                (a.grants, a.pending)
            };
            assert_eq!(counts(&s, &t), (1, 1), "{reason:?}");

            // Just short of the idle limit nothing locks, and both are
            // still there.
            f.clocks.run(idle - Duration::from_secs(1));
            assert_eq!(s.observe(now(&f.clocks)), None);
            let t = at(&f.clocks);
            assert_eq!(counts(&s, &t), (1, 1), "{reason:?}");
            assert_eq!(s.grants().decide(first.clone(), &t), Decision::Covered(g));
            match reason {
                LockReason::Idle => {
                    f.clocks.run(Duration::from_secs(1));
                    assert_eq!(s.observe(now(&f.clocks)), Some(LockReason::Idle));
                }
                LockReason::Sleep => {
                    f.clocks.sleep(Duration::from_secs(3600));
                    assert_eq!(s.observe(now(&f.clocks)), Some(LockReason::Sleep));
                }
                // A restore locks through `begin_recover`, tested below.
                LockReason::Signal | LockReason::Request | LockReason::Restore => {
                    assert!(s.lock(reason));
                }
            }
            let t = at(&f.clocks);
            assert!(matches!(s.slot(), Slot::Locked(_)), "{reason:?}");
            assert_eq!(counts(&s, &t), (0, 0), "{reason:?}");
            assert!(s.grants().grant(g).is_none(), "{reason:?}");
            assert!(s.grants().pending(&waiting, &t).is_none(), "{reason:?}");
            // Unlocked again, the store starts empty: the request the
            // grant covered is pending again.
            unlock(&f, &mut s, PASS).unwrap();
            let t = at(&f.clocks);
            assert!(
                matches!(s.grants().decide(first, &t), Decision::Pending(_)),
                "{reason:?}"
            );
        }
    }

    /// `vault.recover`'s slot handling: an unlocked vault is locked first
    /// (its pending requests end) and its file closed, so the restore can
    /// take the vault's lock; the slot is busy meanwhile. A restore that
    /// succeeds is unlocked, or locked when a lock arrived meanwhile; one
    /// that fails leaves the slot with what is on disk.
    #[test]
    fn a_restore_locks_first_and_leaves_what_is_on_disk() {
        use envcloak_policy::Decision;
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        let generation = s.begin_create().unwrap();
        let kit = RecoveryKit::generate();
        let v = create_vault_with_kit(
            &f.paths,
            &SecretBytes::copy_from(PASS),
            &kit,
            KdfParams::minimum(),
        );
        s.finish_create(generation, now(&f.clocks), v).unwrap();
        let backup = s.unlocked().unwrap().create_backup().unwrap().path;
        let t = at(&f.clocks);
        assert!(matches!(
            s.grants().decide(request("OPENAI_API_KEY"), &t),
            Decision::Pending(_)
        ));
        assert_eq!(s.approvals(&t).pending, 1);
        let new_pass = SecretBytes::copy_from(b"another passphrase, long enough");

        // A wrong kit: the vault was locked and closed first, and is the
        // old one, locked, afterwards.
        let (generation, was_unlocked) = s.begin_recover().unwrap();
        assert!(was_unlocked);
        assert!(matches!(s.slot(), Slot::Busy));
        assert_eq!(s.approvals(&t).pending, 0);
        assert_eq!(s.begin_recover().unwrap_err().kind, ErrorKind::Busy);
        assert_eq!(s.begin_unlock().unwrap_err().kind, ErrorKind::Busy);
        let r =
            envcloak_core::restore_backup(&f.paths, &backup, &RecoveryKit::generate(), &new_pass);
        let e = s.finish_recover(generation, now(&f.clocks), r).unwrap_err();
        assert_eq!(e.kind, ErrorKind::WrongPassphrase);
        assert!(matches!(s.slot(), Slot::Locked(_)));
        // The lock was the restore's, not a request nobody made.
        assert_eq!(s.last_reason, Some(LockReason::Restore));

        // The right kit: the restored vault is unlocked, under the new
        // passphrase.
        let (generation, was_unlocked) = s.begin_recover().unwrap();
        assert!(!was_unlocked);
        let r = envcloak_core::restore_backup(&f.paths, &backup, &kit, &new_pass);
        let view = s.finish_recover(generation, now(&f.clocks), r).unwrap();
        assert!(!view.locked);
        assert_eq!(view.replaced, 1);
        assert!(matches!(s.slot(), Slot::Unlocked(_)));
        s.lock(LockReason::Request);
        assert_eq!(
            unlock(&f, &mut s, PASS).unwrap_err().kind,
            ErrorKind::WrongPassphrase
        );
        unlock(&f, &mut s, b"another passphrase, long enough").unwrap();

        // A lock while it ran: restored, and locked.
        let (generation, _) = s.begin_recover().unwrap();
        assert!(!s.lock(LockReason::Signal));
        let r = envcloak_core::restore_backup(&f.paths, &backup, &kit, &new_pass);
        let view = s.finish_recover(generation, now(&f.clocks), r).unwrap();
        assert!(view.locked);
        assert!(matches!(s.slot(), Slot::Locked(_)));

        // A file that is not a backup: refused, and the vault is there.
        let (generation, _) = s.begin_recover().unwrap();
        let bogus = f.paths.data_dir.join("bogus.ecbackup");
        std::fs::write(&bogus, b"not a backup").unwrap();
        let r = envcloak_core::restore_backup(&f.paths, &bogus, &kit, &new_pass);
        let e = s.finish_recover(generation, now(&f.clocks), r).unwrap_err();
        assert_eq!(e.kind, ErrorKind::BackupUnusable);
        assert!(matches!(s.slot(), Slot::Locked(_)));
    }

    /// A lock that arrives while Argon2id runs wins: the unlock finishes
    /// locked. Idle time does not.
    #[test]
    fn a_lock_during_an_unlock_wins() {
        let f = fixture();
        let idle = Duration::from_secs(600);
        let mut s = State::open(f.paths.clone(), idle, now(&f.clocks));
        create(&f, &mut s);
        s.lock(LockReason::Request);

        for reason in [LockReason::Request, LockReason::Sleep, LockReason::Signal] {
            let BeginUnlock::Proceed(locked, generation) = s.begin_unlock().unwrap() else {
                panic!("expected to proceed");
            };
            assert_eq!(s.begin_unlock().unwrap_err().kind, ErrorKind::Busy);
            assert!(!s.lock(reason));
            let r = locked.unlock_with_passphrase(&SecretBytes::copy_from(PASS));
            let e = s.finish_unlock(generation, now(&f.clocks), r).unwrap_err();
            assert_eq!(e.kind, ErrorKind::VaultLocked, "{reason:?}");
            assert!(matches!(s.slot(), Slot::Locked(_)));
        }

        // Idle time passing during an unlock does not lock it.
        f.clocks.run(Duration::from_secs(10_000));
        let BeginUnlock::Proceed(locked, generation) = s.begin_unlock().unwrap() else {
            panic!("expected to proceed");
        };
        assert_eq!(s.observe(now(&f.clocks)), None);
        let r = locked.unlock_with_passphrase(&SecretBytes::copy_from(PASS));
        s.finish_unlock(generation, now(&f.clocks), r).unwrap();
        assert!(matches!(s.slot(), Slot::Unlocked(_)));
        assert_eq!(s.observe(now(&f.clocks)), None);
    }

    /// A lock that arrives while `vault create` runs Argon2id does not undo
    /// the creation: the vault exists under the passphrase and kit sent,
    /// the answer says it was created and then locked, and both unlock it.
    #[test]
    fn a_lock_during_create_leaves_the_vault_created_and_locked() {
        for reason in [LockReason::Request, LockReason::Sleep, LockReason::Signal] {
            let f = fixture();
            let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
            let generation = s.begin_create().unwrap();
            assert!(!s.lock(reason));
            let kit = RecoveryKit::generate();
            let v = create_vault_with_kit(
                &f.paths,
                &SecretBytes::copy_from(PASS),
                &kit,
                KdfParams::minimum(),
            );
            let created = s.finish_create(generation, now(&f.clocks), v).unwrap();
            assert!(created.locked, "{reason:?}");
            assert_eq!(created.integrity, IntegrityView::Ok);
            assert!(matches!(s.slot(), Slot::Locked(_)));
            let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
            assert_eq!(st.vault.state, VaultState::Locked);
            assert_eq!(st.lock.last_reason, Some(reason));
            assert!(!unlock(&f, &mut s, PASS).unwrap().already);
            s.lock(LockReason::Request);
            let BeginUnlock::Proceed(locked, generation) = s.begin_unlock().unwrap() else {
                panic!("expected to proceed");
            };
            let r = locked.unlock_with_kit(&kit);
            s.finish_unlock(generation, now(&f.clocks), r).unwrap();
        }
        // Idle time passing during a create does not lock it.
        let f = fixture();
        let mut s = State::open(f.paths.clone(), Duration::from_secs(60), now(&f.clocks));
        let generation = s.begin_create().unwrap();
        f.clocks.run(Duration::from_secs(600));
        assert_eq!(s.observe(now(&f.clocks)), None);
        let v = create_vault_with_kit(
            &f.paths,
            &SecretBytes::copy_from(PASS),
            &RecoveryKit::generate(),
            KdfParams::minimum(),
        );
        assert!(
            !s.finish_create(generation, now(&f.clocks), v)
                .unwrap()
                .locked
        );
        assert!(matches!(s.slot(), Slot::Unlocked(_)));
    }

    #[test]
    fn create_errors_map_to_fixed_kinds() {
        assert_eq!(
            create_error(VaultErrorKind::AlreadyExists).kind,
            ErrorKind::VaultExists
        );
        let e = create_error(VaultErrorKind::Passphrase(PassphraseRejected::TooShort));
        assert_eq!(e.kind, ErrorKind::PassphraseRejected);
        assert_eq!(e.reason, Some("too_short"));
        for r in PassphraseRejected::ALL {
            assert!(passphrase_error(r).reason.is_some(), "{r:?}");
        }
        assert_eq!(
            create_error(VaultErrorKind::Crypto(CryptoErrorKind::KdfParams)).kind,
            ErrorKind::KdfParams
        );
        let e = create_error(VaultErrorKind::Busy);
        assert_eq!(
            (e.kind, e.reason),
            (ErrorKind::VaultUnavailable, Some("busy"))
        );
    }

    /// The head saved in the unlocked vault's header.
    fn saved_head(s: &State) -> Option<u64> {
        match s.slot() {
            Slot::Unlocked(v) => v.header().unwrap().audit_head.map(|h| h.seq),
            other => panic!("expected an unlocked vault, got {other:?}"),
        }
    }

    /// The log's entries, as the unlocked vault reads them.
    fn entries(s: &State) -> Vec<(u64, String, String)> {
        match s.slot() {
            Slot::Unlocked(v) => {
                let (entries, report) = v.read_audit().unwrap();
                assert!(report.ok(), "{report:?}");
                entries
                    .into_iter()
                    .map(|e| {
                        (
                            e.seq,
                            e.record.kind.token().to_owned(),
                            e.record.decision.outcome,
                        )
                    })
                    .collect()
            }
            other => panic!("expected an unlocked vault, got {other:?}"),
        }
    }

    fn revoked() -> AuditEvent {
        AuditEvent::Revoked { pid: 1, count: 0 }
    }

    /// SPEC T10 acceptance: the head is saved in the sealed header every
    /// 100 entries, after 15 minutes awake with entries not yet saved (the
    /// window starts at the first tick that sees one), and at lock.
    #[test]
    fn the_head_is_saved_every_100_entries_every_15_minutes_and_at_lock() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        for _ in 0..99 {
            s.audit(revoked());
        }
        assert_eq!(saved_head(&s), None);
        s.audit(revoked());
        assert_eq!(saved_head(&s), Some(100));

        for _ in 0..5 {
            s.audit(revoked());
        }
        s.audit_tick(now(&f.clocks));
        f.clocks
            .run(crate::audit::ANCHOR_INTERVAL - Duration::from_secs(1));
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), Some(100));
        f.clocks.run(Duration::from_secs(1));
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), Some(105));
        // Nothing new: later ticks save nothing.
        f.clocks.run(crate::audit::ANCHOR_INTERVAL * 2);
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), Some(105));

        s.audit(revoked());
        s.audit(revoked());
        assert!(s.lock(LockReason::Request));
        unlock(&f, &mut s, PASS).unwrap();
        // The two entries and the lock's own, 108, were saved at lock.
        assert_eq!(saved_head(&s), Some(108));
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!((st.audit.unanchored, st.audit.anchor_failed), (0, false));
        let log = entries(&s);
        assert_eq!(log.len(), 108);
        assert_eq!(
            log.last().unwrap(),
            &(108, "lock".to_owned(), "locked".to_owned())
        );
    }

    /// Saves nothing and counts the tries: storage that refuses the write.
    fn failing_save(_: &mut Vault, _: AuditHead) -> Result<(), VaultError> {
        FAILED_SAVES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(VaultErrorKind::Storage(13).into())
    }
    static FAILED_SAVES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn failed_saves() -> u32 {
        FAILED_SAVES.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Codex F-45: a save of the head that fails is not counted as done.
    /// Status still counts the entries and says the save failed; events do
    /// not try again on their own (a read-only vault would fail each one),
    /// but ticks do, with no new event, after 30 seconds awake and then
    /// waits that double up to 15 minutes; once storage takes the write the
    /// head is saved and status is back to normal.
    #[test]
    fn a_failed_save_of_the_head_is_tried_again_until_it_is_saved() {
        use crate::audit::{ANCHOR_EVERY, ANCHOR_INTERVAL, ANCHOR_RETRY_FIRST};
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        let audit = |s: &State| {
            s.status(now(&f.clocks), &at(&f.clocks), daemon_view())
                .audit
        };
        for _ in 0..10 {
            s.audit(revoked());
        }
        s.save_head = failing_save;
        s.audit_tick(now(&f.clocks));
        f.clocks.run(ANCHOR_INTERVAL);
        s.audit_tick(now(&f.clocks));
        assert_eq!(failed_saves(), 1);
        assert_eq!(saved_head(&s), None);
        let st = audit(&s);
        assert_eq!((st.unanchored, st.anchor_failed), (10, true));

        // Events, even past 100 of them, do not try again.
        for _ in 0..ANCHOR_EVERY {
            s.audit(revoked());
        }
        assert_eq!(failed_saves(), 1);
        assert_eq!(audit(&s).unanchored, 10 + ANCHOR_EVERY);

        // Ticks do: after 30 seconds, then 60, 120, ... up to 15 minutes.
        let mut wait = ANCHOR_RETRY_FIRST;
        for tries in 2..=8 {
            f.clocks.run(wait - Duration::from_secs(1));
            s.audit_tick(now(&f.clocks));
            assert_eq!(failed_saves(), tries - 1, "{wait:?}");
            f.clocks.run(Duration::from_secs(1));
            s.audit_tick(now(&f.clocks));
            assert_eq!(failed_saves(), tries, "{wait:?}");
            wait = (wait * 2).min(ANCHOR_INTERVAL);
        }
        assert_eq!(wait, ANCHOR_INTERVAL);

        // Storage takes writes again; no event comes.
        s.save_head = Vault::save_audit_head;
        f.clocks.run(wait - Duration::from_secs(1));
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), None);
        f.clocks.run(Duration::from_secs(1));
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), Some(10 + ANCHOR_EVERY));
        let st = audit(&s);
        assert_eq!((st.unanchored, st.anchor_failed), (0, false));
        assert_eq!(failed_saves(), 8);

        // Saves are due as before: after 100 entries.
        for _ in 0..ANCHOR_EVERY {
            s.audit(revoked());
        }
        assert_eq!(saved_head(&s), Some(10 + 2 * ANCHOR_EVERY));
    }

    /// A save of the head that fails at lock leaves its entries after the
    /// saved head. The next unlock counts them from the log, and saves the
    /// head when a save is due.
    #[test]
    fn entries_a_failed_save_at_lock_left_are_counted_and_saved_after_unlock() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        for _ in 0..3 {
            s.audit(revoked());
        }
        assert!(s.lock(LockReason::Request));
        unlock(&f, &mut s, PASS).unwrap();
        assert_eq!(saved_head(&s), Some(4));
        s.audit(revoked());

        s.save_head = |_, _| Err(VaultErrorKind::Storage(13).into());
        assert!(s.lock(LockReason::Request));
        s.save_head = Vault::save_audit_head;
        unlock(&f, &mut s, PASS).unwrap();
        assert_eq!(saved_head(&s), Some(4));
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!(st.audit.head_seq, Some(6));
        assert_eq!((st.audit.unanchored, st.audit.anchor_failed), (2, false));
        s.audit_tick(now(&f.clocks));
        f.clocks.run(crate::audit::ANCHOR_INTERVAL);
        s.audit_tick(now(&f.clocks));
        assert_eq!(saved_head(&s), Some(6));
        let st = s.status(now(&f.clocks), &at(&f.clocks), daemon_view());
        assert_eq!(st.audit.unanchored, 0);
    }

    /// A lock that arrives while a proof has the vault out still writes
    /// its entry and closes the log at once (its keys go); the head is saved
    /// when the proof hands the vault back, locked.
    #[test]
    fn a_lock_during_a_proof_saves_the_head_when_the_vault_comes_back() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        s.audit(revoked());
        let (vault, generation) = s.begin_proof().unwrap();
        assert!(!s.lock(LockReason::Request));
        assert!(!s.audit.is_open());
        assert_eq!(
            s.finish_proof(generation, vault).unwrap_err().kind,
            ErrorKind::VaultLocked
        );
        unlock(&f, &mut s, PASS).unwrap();
        assert_eq!(saved_head(&s), Some(2));
        assert_eq!(
            entries(&s),
            vec![
                (1, "revoke".into(), "revoked".into()),
                (2, "lock".into(), "locked".into()),
            ]
        );
    }

    /// Events while the vault is locked wait in memory and are written at
    /// the next unlock, after the lock's entry; a delivery that cannot be
    /// written is refused, and ordinary events wait until the log can be
    /// written again.
    #[test]
    fn events_wait_while_the_log_cannot_be_written() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        s.audit(revoked());
        s.lock(LockReason::Request);
        s.audit(AuditEvent::UnlockFailed { pid: 2 });
        assert_eq!(s.audit.backlog(), (1, 0));
        unlock(&f, &mut s, PASS).unwrap();
        assert_eq!(s.audit.backlog(), (0, 0));
        assert_eq!(
            entries(&s),
            vec![
                (1, "revoke".into(), "revoked".into()),
                (2, "lock".into(), "locked".into()),
                (3, "unlock".into(), "failed".into()),
            ]
        );

        // The log's directory replaced by a file: a delivery is refused,
        // and an event waits.
        let dir = &f.paths.audit_dir;
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::write(dir, b"in the way").unwrap();
        let delivery = || {
            AuditEvent::Request(Box::new(crate::audit::RequestAudit {
                pid: 3,
                decision: "covered",
                request_id: None,
                grant_id: None,
                reason: None,
                subject: Default::default(),
                project: None,
                items: Vec::new(),
                argv: Vec::new(),
                count: None,
            }))
        };
        // The segment is gone and no new one can be made.
        assert!(!s.audit_delivery(delivery()));
        s.audit(AuditEvent::Revoked { pid: 4, count: 1 });
        assert_eq!(s.audit.backlog(), (1, 0));
        std::fs::remove_file(dir).unwrap();
        assert!(s.audit_delivery(delivery()));
        assert_eq!(s.audit.backlog(), (0, 0));
        match s.slot() {
            Slot::Unlocked(v) => {
                let (entries, report) = v.read_audit().unwrap();
                // The removed segment held entries 1 to 3.
                assert_eq!(report.first_problem.map(|p| p.seq), Some(1), "{report:?}");
                let got: Vec<(u64, &str)> = entries
                    .iter()
                    .map(|e| (e.seq, e.record.decision.outcome.as_str()))
                    .collect();
                assert_eq!(got, vec![(4, "revoked"), (5, "covered")]);
            }
            other => panic!("{other:?}"),
        }
    }

    /// `value` in a new item `slug` of `s`'s vault: its field.
    fn stored_value(s: &mut State, slug: &str, value: &[u8]) -> FieldId {
        use envcloak_core::crypto::ItemClass;
        use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug};
        s.unlocked_mut()
            .unwrap()
            .transact(|t| {
                let id = t.create_item(NewItem {
                    class: ItemClass::Secret,
                    slug: Slug::new(slug).unwrap(),
                    details: ItemDetails::default(),
                })?;
                t.add_field(
                    id,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(value),
                )
            })
            .unwrap()
    }

    /// A grant of `opts` for `r`, approved now, as its requester (a
    /// terminal session).
    fn granted(
        f: &Fixture,
        s: &mut State,
        r: envcloak_policy::AccessRequest,
        opts: envcloak_policy::ApprovalOptions,
    ) -> GrantId {
        use envcloak_policy::{ApprovalProof, Decision, ProofKind, statement_digest};
        let t = at(&f.clocks);
        let Decision::Pending(id) = s.grants().decide(r.clone(), &t) else {
            panic!("expected a pending request");
        };
        let vault = metas(&r);
        let digest = statement_digest(
            &s.grants().pending_descriptor(&id, &t, &vault).unwrap(),
            &opts,
        );
        let proof = ApprovalProof {
            approver: r.subject,
            kind: ProofKind::Passphrase,
        };
        s.grants()
            .approve(&id, proof, opts, digest, &t, &vault)
            .unwrap()
    }

    /// The vault's metadata for the items `r` binds: one secret with one
    /// field each, classified as `r` read it.
    fn metas(r: &envcloak_policy::AccessRequest) -> Vec<envcloak_core::vault::ItemMeta> {
        use envcloak_core::crypto::ItemClass;
        use envcloak_core::vault::{FieldKind, FieldMeta, ItemDetails, ItemMeta};
        r.bindings
            .iter()
            .map(|b| ItemMeta {
                id: b.binding.item,
                class: ItemClass::Secret,
                slug: b.slug.clone(),
                details: ItemDetails {
                    classification: b.binding.classification,
                    ..ItemDetails::default()
                },
                created_at: 0,
                updated_at: 0,
                fields: vec![FieldMeta {
                    id: b.binding.field,
                    name: b.field_name.clone(),
                    kind: FieldKind::Value,
                    prior_count: 0,
                    created_at: 0,
                    updated_at: 0,
                }],
                classification_changed_at: None,
                exposure: None,
                rotate_recommended: false,
                login: None,
            })
            .collect()
    }

    /// Every process is still running: what `alive` says when no root
    /// exited.
    fn running(_: &ProcessInstance) -> bool {
        true
    }

    /// A covered request's delivery entry.
    fn delivery(pid: i32) -> AuditEvent {
        AuditEvent::Request(Box::new(crate::audit::RequestAudit {
            pid,
            decision: "covered",
            request_id: None,
            grant_id: None,
            reason: None,
            subject: Default::default(),
            project: None,
            items: Vec::new(),
            argv: Vec::new(),
            count: None,
        }))
    }

    const VALUE: &[u8] = b"a value of forty bytes, made for this..";

    fn project_record(key: &[u8], revision: u8) -> envcloak_core::vault::ProjectRecord {
        use envcloak_core::vault::{ProjectBinding, ProjectKey, ProjectRecord};
        ProjectRecord {
            key: ProjectKey::new(key).unwrap(),
            display_path: format!("/fixture/{revision}"),
            manifest_sha256: [revision; 32],
            bindings: vec![ProjectBinding {
                env_name: "BOUND".into(),
                reference: format!("ordinary/{revision}"),
            }],
            last_seen: u64::from(revision),
        }
    }

    fn project_index(
        s: &State,
    ) -> std::collections::BTreeMap<
        envcloak_core::vault::ProjectId,
        envcloak_core::vault::ProjectRecord,
    > {
        s.unlocked()
            .unwrap()
            .projects()
            .unwrap()
            .map(|(id, p)| (id, p.clone()))
            .collect()
    }

    fn project_audit_failure(refresh: bool) {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        let field = stored_value(&mut s, "a/b", VALUE);
        s.unlocked_mut()
            .unwrap()
            .transact(|t| {
                t.upsert_project(project_record(b"unrelated", 1))?;
                if refresh {
                    t.upsert_project(project_record(b"target", 2))?;
                }
                Ok(())
            })
            .unwrap();
        let before = project_index(&s);
        let g = granted(
            &f,
            &mut s,
            request("OPENAI_API_KEY"),
            envcloak_policy::ApprovalOptions::once(Duration::from_secs(600)),
        );
        let dir = &f.paths.audit_dir;
        let held = dir.with_extension("held");
        std::fs::rename(dir, &held).unwrap();
        std::fs::write(dir, b"in the way").unwrap();
        let result = s.deliver(
            g,
            &f.clocks,
            &running,
            delivery(1),
            &[field],
            Some(project_record(b"target", 3)),
            Ok,
        );
        assert!(matches!(result, Err(Delivery::AuditFailed)));
        assert_eq!(project_index(&s), before, "failed audit changed adoption");
        assert!(s.grants().in_force(g, &at(&f.clocks), &running));
        std::fs::remove_file(dir).unwrap();
        std::fs::rename(&held, dir).unwrap();
        // Verify the persisted rows too, including their ids and every field.
        s.lock(LockReason::Request);
        unlock(&f, &mut s, PASS).unwrap();
        assert_eq!(project_index(&s), before);
        // The exact same project record is writable once the audit recovers.
        let g = granted(
            &f,
            &mut s,
            request("OPENAI_API_KEY"),
            envcloak_policy::ApprovalOptions::once(Duration::from_secs(600)),
        );
        let audit_before = entries(&s).len();
        let values = s
            .deliver(
                g,
                &f.clocks,
                &running,
                delivery(2),
                &[field],
                Some(project_record(b"target", 3)),
                Ok,
            )
            .unwrap();
        assert!(values[0].ct_eq(VALUE));
        assert_eq!(entries(&s).len(), audit_before + 1);
        let after = project_index(&s);
        let mut expected = project_record(b"target", 3);
        expected.last_seen = f
            .clocks
            .wall()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(after.values().any(|p| *p == expected));
        assert_eq!(after.len(), 2);
        assert!(after.iter().any(|(id, p)| before.get(id) == Some(p)));
    }

    #[test]
    fn project_audit_failure_does_not_adopt() {
        project_audit_failure(false);
    }

    #[test]
    fn project_audit_failure_does_not_refresh() {
        project_audit_failure(true);
    }

    fn project_lapse(refresh: bool) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CheckpointClocks<'a> {
            base: &'a FakeClocks,
            reads: AtomicUsize,
            case: &'static str,
        }
        impl Clocks for CheckpointClocks<'_> {
            fn wall(&self) -> std::time::SystemTime {
                // The second reading is after the project's provisional write.
                if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
                    let ttl = Duration::from_secs(60);
                    match self.case {
                        "wall" => self.base.sleep(ttl),
                        "awake" => {
                            let wall = self.base.wall();
                            self.base.run(ttl);
                            self.base.set_wall(wall);
                        }
                        _ => {}
                    }
                }
                self.base.wall()
            }
            fn awake(&self) -> Duration {
                self.base.awake()
            }
            fn including_sleep(&self) -> Duration {
                self.base.including_sleep()
            }
        }
        for case in ["live", "wall", "awake", "root"] {
            let f = fixture();
            let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
            create(&f, &mut s);
            let field = stored_value(&mut s, "a/b", VALUE);
            s.unlocked_mut()
                .unwrap()
                .transact(|t| {
                    t.upsert_project(project_record(b"unrelated", 1))?;
                    if refresh {
                        t.upsert_project(project_record(b"target", 2))?;
                    }
                    Ok(())
                })
                .unwrap();
            let before = project_index(&s);
            let audit_before = entries(&s).len();
            let g = granted(
                &f,
                &mut s,
                request("OPENAI_API_KEY"),
                envcloak_policy::ApprovalOptions::once(Duration::from_secs(60)),
            );
            let clocks = CheckpointClocks {
                base: &f.clocks,
                reads: AtomicUsize::new(0),
                case,
            };
            let alive_reads = std::cell::Cell::new(0);
            let alive = |_: &ProcessInstance| {
                alive_reads.set(alive_reads.get() + 1);
                case != "root" || alive_reads.get() == 1
            };
            let result = s.deliver(
                g,
                &clocks,
                &alive,
                delivery(1),
                &[field],
                Some(project_record(b"target", 3)),
                Ok,
            );
            assert_eq!(clocks.reads.load(Ordering::SeqCst), 2, "{case}");
            if case == "live" {
                assert!(result.unwrap()[0].ct_eq(VALUE));
                assert_ne!(project_index(&s), before);
                assert_eq!(entries(&s).len(), audit_before + 1);
            } else {
                assert!(matches!(result, Err(Delivery::Lapsed)), "{case}");
                assert_eq!(
                    project_index(&s),
                    before,
                    "{case}: failed run changed adoption"
                );
                assert_eq!(entries(&s).len(), audit_before, "{case}");
                assert!(s.grants().grant(g).is_none(), "{case}: grant not swept");
                s.lock(LockReason::Request);
                unlock(&f, &mut s, PASS).unwrap();
                assert_eq!(project_index(&s), before, "{case}: persisted adoption");
            }
        }
    }

    #[test]
    fn project_lapse_does_not_adopt() {
        project_lapse(false);
    }

    #[test]
    fn project_lapse_does_not_refresh() {
        project_lapse(true);
    }

    #[test]
    fn project_adoption_failure_releases_nothing_and_keeps_the_index() {
        use envcloak_core::vault::{ProjectKey, ProjectRecord};
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        let field = stored_value(&mut s, "a/b", VALUE);
        let g = granted(
            &f,
            &mut s,
            request("OPENAI_API_KEY"),
            envcloak_policy::ApprovalOptions::session(Duration::from_secs(600)),
        );
        let record = ProjectRecord {
            key: ProjectKey::new(b"project").unwrap(),
            display_path: "/fixture".into(),
            manifest_sha256: [0; 32],
            bindings: vec![],
            last_seen: 0,
        };
        s.deliver(
            g,
            &f.clocks,
            &running,
            delivery(1),
            &[field],
            Some(record.clone()),
            |_| Ok(()),
        )
        .unwrap();
        let before: Vec<_> = s
            .unlocked()
            .unwrap()
            .projects()
            .unwrap()
            .map(|(id, p)| (id, p.clone()))
            .collect();
        assert_eq!(before.len(), 1);
        assert!(before[0].1.last_seen > 0);
        let audit_before = entries(&s).len();
        let mut too_large = record;
        too_large.display_path = "x".repeat(65536);
        let result = s.deliver(
            g,
            &f.clocks,
            &running,
            delivery(2),
            &[field],
            Some(too_large),
            |_| Ok(()),
        );
        assert_eq!(
            result,
            Err(Delivery::Refused(RpcError::with_reason(
                ErrorKind::VaultUnavailable,
                "damaged",
            )))
        );
        assert_eq!(entries(&s).len(), audit_before);
        let after: Vec<_> = s
            .unlocked()
            .unwrap()
            .projects()
            .unwrap()
            .map(|(id, p)| (id, p.clone()))
            .collect();
        assert_eq!(before, after);
        assert!(s.grants().in_force(g, &at(&f.clocks), &running));
    }

    /// Gate 33's release order, at the one place values are released
    /// from: `deliver` gives values out only after the delivery's entry
    /// reads back from the log on disk, and when the entry cannot be
    /// written it gives none. On a locked vault it reads nothing.
    #[test]
    fn values_are_released_only_after_their_entry_is_on_disk() {
        let f = fixture();
        let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
        create(&f, &mut s);
        let field = stored_value(&mut s, "a/b", VALUE);
        let g = granted(
            &f,
            &mut s,
            request("OPENAI_API_KEY"),
            envcloak_policy::ApprovalOptions::session(Duration::from_secs(600)),
        );
        let c = &f.clocks;

        let values = s
            .deliver(g, c, &running, delivery(1), &[field], None, Ok)
            .unwrap();
        // The values exist: the entry is already in the log's files.
        assert_eq!(
            entries(&s).last().map(|e| e.2.clone()),
            Some("covered".into())
        );
        assert!(values[0].ct_eq(VALUE));

        // An answer that cannot be built (too large for a frame, F-77):
        // nothing recorded, and its error given back.
        let before = entries(&s).len();
        let too_large = RpcError::new(ErrorKind::FrameTooLarge);
        assert_eq!(
            s.deliver(
                g,
                c,
                &running,
                delivery(5),
                &[field],
                None,
                |_| Err::<(), _>(too_large)
            )
            .unwrap_err(),
            Delivery::Unsendable(too_large)
        );
        assert_eq!(entries(&s).len(), before);

        // No entry can be written: no values.
        let dir = &f.paths.audit_dir;
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::write(dir, b"in the way").unwrap();
        assert_eq!(
            s.deliver(g, c, &running, delivery(2), &[field], None, Ok)
                .unwrap_err(),
            Delivery::AuditFailed
        );
        std::fs::remove_file(dir).unwrap();
        assert_eq!(
            s.deliver(g, c, &running, delivery(3), &[field], None, Ok)
                .unwrap()
                .len(),
            1
        );

        // Locked: refused before anything is read or written.
        s.lock(LockReason::Request);
        assert_eq!(
            s.deliver(g, c, &running, delivery(4), &[field], None, Ok)
                .unwrap_err(),
            Delivery::Refused(RpcError::new(ErrorKind::VaultLocked))
        );
    }

    /// F-77, expiry before commit: the values are read and the answer
    /// framed after the decision, and a grant that runs out meanwhile
    /// commits nothing. Each case is a `once` grant of 60 seconds, decided
    /// on and then delivered while the preparation (the `answer` closure
    /// here, where the daemon reads the values and frames them) moves the
    /// injected clocks on:
    /// - to a second before the deadline: delivered, and its entry written
    ///   (the control);
    /// - to the deadline on both clocks;
    /// - to the wall clock's deadline alone (the machine slept: time awake
    ///   stands still);
    /// - to the awake deadline alone (the wall clock set back as far):
    ///
    /// the last three are [`Delivery::Lapsed`]: no entry, and no value
    /// given out. The decision the grant was found by is taken before the
    /// clocks move, so these cases fail against a check on its clocks.
    ///
    /// Mutations: no check after the answer is built, or one on clocks
    /// read before it (the three lapsed cases are delivered); a check of
    /// the wall clock alone (the awake case is delivered).
    #[test]
    fn a_grant_that_runs_out_while_its_answer_is_prepared_commits_nothing() {
        /// Moves the clocks as a preparation taking that long would.
        type Prepare = fn(&FakeClocks, Duration);
        let ttl = Duration::from_secs(60);
        let cases: [(&str, Prepare, bool); 4] = [
            (
                "a second short",
                |c, ttl| c.run(ttl - Duration::from_secs(1)),
                true,
            ),
            ("both deadlines", |c, ttl| c.run(ttl), false),
            ("asleep: the wall deadline", |c, ttl| c.sleep(ttl), false),
            (
                "the awake deadline, the wall clock set back",
                |c, ttl| {
                    let wall = c.wall();
                    c.run(ttl);
                    c.set_wall(wall);
                },
                false,
            ),
        ];
        for (case, prepare, delivered) in cases {
            let f = fixture();
            let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
            create(&f, &mut s);
            let field = stored_value(&mut s, "a/b", VALUE);
            let r = request("OPENAI_API_KEY");
            let g = granted(
                &f,
                &mut s,
                r.clone(),
                envcloak_policy::ApprovalOptions::once(ttl),
            );
            // The decision, on the clocks before the preparation.
            assert_eq!(
                s.grants().decide(r, &at(&f.clocks)),
                envcloak_policy::Decision::Covered(g),
                "{case}"
            );
            let before = entries(&s).len();
            let mut prepared = false;
            let got = s.deliver(
                g,
                &f.clocks,
                &running,
                delivery(1),
                &[field],
                None,
                |values| {
                    prepare(&f.clocks, ttl);
                    prepared = true;
                    Ok(values)
                },
            );
            assert!(prepared, "{case}: the answer was not built");
            if delivered {
                let values = got.unwrap_or_else(|e| panic!("{case}: {e:?}"));
                assert!(values[0].ct_eq(VALUE), "{case}: not the item's value");
                assert_eq!(entries(&s).len(), before + 1, "{case}");
            } else {
                assert!(
                    matches!(got, Err(Delivery::Lapsed)),
                    "{case}: delivered, or refused otherwise: {:?}",
                    got.map(|v| v.len())
                );
                assert_eq!(entries(&s).len(), before, "{case}: an entry was written");
            }
        }
    }

    /// SPEC §10b, a grant never outlives its root, before commit (Codex's
    /// review of F-77): a `once` grant covers a request, and its root
    /// exits while the answer is prepared (the `answer` closure here,
    /// where the daemon reads the values and frames them; `alive` then
    /// says the grant's root is gone). The delivery commits nothing:
    /// [`Delivery::Lapsed`], no entry, no value given out, and the grant
    /// is gone, so the request decided again is pending, not covered by
    /// it. The control: the same delivery with the root running is
    /// delivered and its entry written.
    ///
    /// Mutations: `in_force` without the root (delivered); the lapse
    /// without the sweep (the grant stays, and covers the request decided
    /// again).
    #[test]
    fn a_grant_whose_root_exits_while_its_answer_is_prepared_commits_nothing() {
        use std::cell::Cell;
        for exits in [false, true] {
            let f = fixture();
            let mut s = State::open(f.paths.clone(), crate::lock::DEFAULT_IDLE, now(&f.clocks));
            create(&f, &mut s);
            let field = stored_value(&mut s, "a/b", VALUE);
            let r = request("OPENAI_API_KEY");
            let root = r.subject.root();
            let g = granted(
                &f,
                &mut s,
                r.clone(),
                envcloak_policy::ApprovalOptions::once(Duration::from_secs(600)),
            );
            assert_eq!(
                s.grants().decide(r.clone(), &at(&f.clocks)),
                envcloak_policy::Decision::Covered(g)
            );
            let exited = Cell::new(false);
            let alive = |p: &ProcessInstance| !(exited.get() && *p == root);
            let before = entries(&s).len();
            let got = s.deliver(
                g,
                &f.clocks,
                &alive,
                delivery(1),
                &[field],
                None,
                |values| {
                    exited.set(exits);
                    Ok(values)
                },
            );
            if exits {
                assert!(
                    matches!(got, Err(Delivery::Lapsed)),
                    "delivered, or refused otherwise: {:?}",
                    got.map(|v| v.len())
                );
                assert_eq!(entries(&s).len(), before, "an entry was written");
                assert!(s.grants().grant(g).is_none(), "the grant outlived its root");
                assert!(matches!(
                    s.grants().decide(r, &at(&f.clocks)),
                    envcloak_policy::Decision::Pending(_)
                ));
            } else {
                let values = got.unwrap_or_else(|e| panic!("the control: {e:?}"));
                assert!(values[0].ct_eq(VALUE));
                assert_eq!(entries(&s).len(), before + 1);
            }
        }
    }
}
