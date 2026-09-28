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
//! Every method here runs with the daemon's state mutex held and returns
//! quickly; Argon2id runs between a `begin_*` and its `finish_*`, outside
//! the mutex.

use std::time::Duration;

use envcloak_core::PassphraseRejected;
use envcloak_core::crypto::CryptoErrorKind;
use envcloak_core::vault::{Integrity, LockedVault, Vault, VaultError, VaultErrorKind, VaultPaths};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::{
    ApprovalsView, CreatedView, DaemonView, Integrity as IntegrityView, LockReason, LockView,
    StatusView, UnlockedView, VaultState, VaultView,
};
use envcloak_policy::{AttemptLimiter, GrantStore, Now};

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

/// What `begin_unlock` found.
#[derive(Debug)]
pub enum BeginUnlock {
    /// Already unlocked; nothing to check.
    Already(UnlockedView),
    /// The locked file, taken out of the slot, and the generation to
    /// finish under.
    Proceed(LockedVault, u64),
}

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
        // Whatever the slot holds, a lock ends every grant and pending
        // request (SPEC §5 "Lock").
        self.grants.on_lock();
        match std::mem::replace(&mut self.slot, Slot::Absent) {
            Slot::Unlocked(v) => {
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
        StatusView {
            daemon,
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
}
