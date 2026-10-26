//! Daemon TOTP engine: per-account attempt serialization, no-reuse step
//! memory, post-restart refusal of the startup step and its predecessor,
//! last-3-second step boundary wait, `AttemptLease`-bound seed access, and
//! durable audit callback before returning a [`Code`] (SPEC §6.8,
//! R-M2b-18 to R-M2b-20).
#![allow(clippy::disallowed_methods)]
#![allow(dead_code)] // Sign-in worker (M2b-09) wires TotpState::next_code and read_field.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::vault::{AttemptLease, FieldKind, ItemId, LoginValue, Vault, VaultErrorKind};
use envcloak_signin::totp::{
    Code, TotpParams, code, refused_after_start, seconds_left, step_at, too_late_in_step,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    AccountMismatch,
    LeaseStale,
    VaultLocked,
    NoTotpEnrolled,
    InvalidParams,
    TooLateInStep,
    RefusedAfterStart { step: u64 },
    StepAlreadyUsed { step: u64 },
    AuditFailed,
    Vault(VaultErrorKind),
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TotpError::AccountMismatch => f.write_str("account_mismatch"),
            TotpError::LeaseStale => f.write_str("lease_stale"),
            TotpError::VaultLocked => f.write_str("vault_locked"),
            TotpError::NoTotpEnrolled => f.write_str("no_totp_enrolled"),
            TotpError::InvalidParams => f.write_str("invalid_totp_params"),
            TotpError::TooLateInStep => f.write_str("too_late_in_step"),
            TotpError::RefusedAfterStart { .. } => f.write_str("refused_after_start"),
            TotpError::StepAlreadyUsed { .. } => f.write_str("step_already_used"),
            TotpError::AuditFailed => f.write_str("audit_failed"),
            TotpError::Vault(k) => f.write_str(k.message()),
        }
    }
}

impl std::error::Error for TotpError {}

#[derive(Debug, Default)]
struct AccountSlot {
    in_use: bool,
    last_submitted_step: Option<u64>,
    min_revision: u64,
}

#[derive(Debug, Default)]
struct AccountEntry {
    slot: Mutex<AccountSlot>,
    cv: Condvar,
}

/// Guard proving exclusive per-account attempt ownership for a login item.
#[derive(Debug)]
pub struct AttemptGuard {
    item: ItemId,
    entry: Arc<AccountEntry>,
}

impl AttemptGuard {
    pub fn item(&self) -> ItemId {
        self.item
    }
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        let mut slot = self
            .entry
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        slot.in_use = false;
        self.entry.cv.notify_one();
    }
}

/// Per-daemon TOTP state across login accounts.
#[derive(Debug)]
pub struct TotpState {
    start_unix: u64,
    generation: AtomicU64,
    accounts: Mutex<BTreeMap<ItemId, Arc<AccountEntry>>>,
}

impl TotpState {
    /// Creates fresh TOTP state at daemon startup timestamp `start_unix`.
    pub fn after_start(start_unix: u64) -> Self {
        TotpState {
            start_unix,
            generation: AtomicU64::new(1),
            accounts: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn start_unix(&self) -> u64 {
        self.start_unix
    }

    /// Invalidates active `AttemptLease`s across a vault lock, unlock, or
    /// backup recovery by advancing the lock generation and resetting
    /// per-account `min_revision` to `0` while preserving `last_submitted_step`.
    pub fn on_lock(&self) {
        let map = self.accounts.lock().unwrap_or_else(PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::SeqCst);
        for entry in map.values() {
            let mut slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
            slot.min_revision = 0;
        }
    }

    fn entry_for(&self, item: ItemId) -> Arc<AccountEntry> {
        let mut map = self.accounts.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            map.entry(item)
                .or_insert_with(|| Arc::new(AccountEntry::default())),
        )
    }

    /// Acquires the per-account serialization guard for `item`, waiting if
    /// another attempt on the same account is currently active.
    pub fn acquire_account(&self, item: ItemId) -> AttemptGuard {
        let entry = self.entry_for(item);
        let mut slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
        while slot.in_use {
            slot = entry.cv.wait(slot).unwrap_or_else(PoisonError::into_inner);
        }
        slot.in_use = true;
        drop(slot);
        AttemptGuard { item, entry }
    }

    /// Attempts to acquire the per-account serialization guard without
    /// blocking.
    pub fn try_acquire_account(&self, item: ItemId) -> Option<AttemptGuard> {
        let entry = self.entry_for(item);
        let mut slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.in_use {
            return None;
        }
        slot.in_use = true;
        drop(slot);
        Some(AttemptGuard { item, entry })
    }

    /// Issues a vault `AttemptLease` bound to `item`'s current authorization
    /// revision and this `TotpState`'s current unlock/lock generation.
    pub fn issue_lease(&self, vault: &Vault, item: ItemId) -> Result<AttemptLease, TotpError> {
        let entry = self.entry_for(item);
        let slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = self.generation.load(Ordering::SeqCst);
        let lease = vault
            .issue_attempt_lease(item)
            .map_err(map_vault_err)?
            .with_generation(generation);
        if lease.revision() < slot.min_revision {
            return Err(TotpError::LeaseStale);
        }
        Ok(lease)
    }

    /// Opens a non-TOTP login field (`Username`, `Password`, `AdapterKey`)
    /// inside an active `AttemptGuard` and `AttemptLease`.
    pub fn read_field(
        &self,
        guard: &AttemptGuard,
        lease: &AttemptLease,
        vault: &Vault,
        kind: FieldKind,
    ) -> Result<SecretBytes, TotpError> {
        if guard.item != lease.item() {
            return Err(TotpError::AccountMismatch);
        }
        {
            let slot = guard
                .entry
                .slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !slot.in_use {
                return Err(TotpError::AccountMismatch);
            }
            if lease.generation() != self.generation.load(Ordering::SeqCst)
                || lease.revision() < slot.min_revision
            {
                return Err(TotpError::LeaseStale);
            }
        }
        match vault
            .login_fields()
            .open(lease, kind)
            .map_err(map_vault_err)?
        {
            LoginValue::Text(b) => Ok(b),
            LoginValue::Totp(_) => Err(TotpError::InvalidParams),
        }
    }

    /// Records that `item`'s login credentials were replaced, bumping its
    /// minimum valid authorization revision to `new_revision`.
    pub fn on_login_replaced(&self, item: ItemId, new_revision: u64) {
        let entry = self.entry_for(item);
        let mut slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.min_revision = slot.min_revision.max(new_revision);
    }

    /// Last submitted step for `item`, if any.
    pub fn last_submitted_step(&self, item: ItemId) -> Option<u64> {
        let entry = self.entry_for(item);
        let slot = entry.slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.last_submitted_step
    }

    /// Generates the next one-time code for `lease`'s login item inside the
    /// active `guard`, waiting for a fresh step when in the last 3 seconds of
    /// a step, when in the startup step or its predecessor, or when the
    /// current step was already submitted for this account, and writing the
    /// durable audit callback before returning the [`Code`].
    pub fn next_code(
        &self,
        guard: &AttemptGuard,
        lease: &AttemptLease,
        vault: &Vault,
        clock: &mut dyn FnMut() -> u64,
        sleep: &mut dyn FnMut(Duration),
        audit: &mut dyn FnMut(u64) -> bool,
    ) -> Result<(Code, u64), TotpError> {
        self.next_code_with_vault(
            guard,
            lease,
            &mut |f| {
                f(vault);
                true
            },
            clock,
            sleep,
            audit,
        )
    }

    /// Generates the next one-time code for `lease`'s login item using a
    /// scoped `with_vault` callback so the daemon's state mutex is never held
    /// across `sleep` or `audit` callbacks.
    #[allow(clippy::type_complexity)]
    pub fn next_code_with_vault(
        &self,
        guard: &AttemptGuard,
        lease: &AttemptLease,
        with_vault: &mut dyn FnMut(&mut dyn FnMut(&Vault)) -> bool,
        clock: &mut dyn FnMut() -> u64,
        sleep: &mut dyn FnMut(Duration),
        audit: &mut dyn FnMut(u64) -> bool,
    ) -> Result<(Code, u64), TotpError> {
        if guard.item != lease.item() {
            return Err(TotpError::AccountMismatch);
        }
        loop {
            let last_submitted = {
                let slot = guard
                    .entry
                    .slot
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if !slot.in_use {
                    return Err(TotpError::AccountMismatch);
                }
                if lease.generation() != self.generation.load(Ordering::SeqCst)
                    || lease.revision() < slot.min_revision
                {
                    return Err(TotpError::LeaseStale);
                }
                slot.last_submitted_step
            };

            let mut opened: Option<Result<LoginValue, TotpError>> = None;
            let vault_ok = with_vault(&mut |vault| {
                opened = Some(
                    vault
                        .login_fields()
                        .open(lease, FieldKind::TotpSeed)
                        .map_err(map_vault_err),
                );
            });
            if !vault_ok {
                return Err(TotpError::VaultLocked);
            }
            let enrollment = match opened.ok_or(TotpError::VaultLocked)?? {
                LoginValue::Totp(e) => e,
                LoginValue::Text(_) => return Err(TotpError::NoTotpEnrolled),
            };
            let params = TotpParams::from_vault_params(enrollment.params)
                .map_err(|_| TotpError::InvalidParams)?;
            let period = params.period();

            let now_secs = clock();
            if too_late_in_step(now_secs, period) {
                let wait = seconds_left(now_secs, period).max(1);
                sleep(Duration::from_secs(wait));
                if clock() <= now_secs {
                    return Err(TotpError::TooLateInStep);
                }
                continue;
            }

            let step = step_at(now_secs, period);
            let refused = refused_after_start(self.start_unix, period);
            if step == refused[0] || step == refused[1] {
                let target_step = refused[0].saturating_add(1);
                let target_unix = target_step.saturating_mul(period.seconds());
                let wait = target_unix.saturating_sub(now_secs).max(1);
                sleep(Duration::from_secs(wait));
                if clock() <= now_secs {
                    return Err(TotpError::RefusedAfterStart { step });
                }
                continue;
            }

            if let Some(last) = last_submitted
                && step <= last
            {
                let target_step = last.saturating_add(1);
                let target_unix = target_step.saturating_mul(period.seconds());
                let wait = target_unix.saturating_sub(now_secs).max(1);
                sleep(Duration::from_secs(wait));
                if clock() <= now_secs {
                    return Err(TotpError::StepAlreadyUsed { step });
                }
                continue;
            }

            if !audit(step) {
                return Err(TotpError::AuditFailed);
            }

            // Re-verify lease freshness after any wait/audit before releasing the code.
            {
                let slot = guard
                    .entry
                    .slot
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if !slot.in_use {
                    return Err(TotpError::AccountMismatch);
                }
                if lease.generation() != self.generation.load(Ordering::SeqCst)
                    || lease.revision() < slot.min_revision
                {
                    return Err(TotpError::LeaseStale);
                }
            }

            let generated = code(&enrollment.seed, params, step);
            {
                let mut slot = guard
                    .entry
                    .slot
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                slot.last_submitted_step = Some(step);
            }
            return Ok((generated, step));
        }
    }
}

fn map_vault_err(e: envcloak_core::vault::VaultError) -> TotpError {
    match e.kind() {
        VaultErrorKind::LeaseStale => TotpError::LeaseStale,
        VaultErrorKind::UnknownField => TotpError::NoTotpEnrolled,
        other => TotpError::Vault(other),
    }
}

/// Copies a UTF-8 [`SecretBytes`] field into a [`zeroize::Zeroizing<String>`]
/// for transmission over the private daemon-to-driver control pipe.
#[allow(clippy::disallowed_methods)]
pub fn secret_to_zeroizing_utf8(
    secret: &SecretBytes,
) -> Result<zeroize::Zeroizing<String>, TotpError> {
    use secrecy::ExposeSecret;
    let s = std::str::from_utf8(secret.expose_secret()).map_err(|_| TotpError::InvalidParams)?;
    Ok(zeroize::Zeroizing::new(s.to_owned()))
}

/// Copies a generated [`Code`] into a [`zeroize::Zeroizing<String>`] for
/// transmission over the private daemon-to-driver control pipe.
#[allow(clippy::disallowed_methods)]
pub fn code_to_zeroizing_utf8(code: &Code) -> Result<zeroize::Zeroizing<String>, TotpError> {
    secret_to_zeroizing_utf8(code.as_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use envcloak_core::crypto::{
        Argon2id, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk, wrap_vmk_with,
    };
    use envcloak_core::vault::{
        INITIAL_EPOCH, ItemDetails, LoginFieldValue, LoginMeta, LoginTier, NewLogin, Slug,
        TotpAlgorithm, TotpEnrollment, TotpParams as VaultTotpParams, VaultPaths,
    };
    use envcloak_signin::totp::count_code_matches;

    const RFC_SEED_20: &[u8] = b"12345678901234567890";

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let env = wrap_vmk_with(
            &vmk,
            &SecretBytes::copy_from(b"unit test passphrase for totp engine"),
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
        (dir, v)
    }

    fn enroll_login(v: &mut Vault, slug: &str, digits: u8, period: u32) -> ItemId {
        v.transact(|t| {
            t.create_login(NewLogin {
                slug: Slug::new(slug).unwrap(),
                details: ItemDetails::default(),
                meta: LoginMeta {
                    tier: LoginTier::Dev,
                    session_lifetime: 3600,
                },
                username: SecretBytes::copy_from(b"editor@example.test"),
                password: SecretBytes::copy_from(b"synthetic-login-password-fixture"),
                totp: Some(TotpEnrollment {
                    params: VaultTotpParams::new(TotpAlgorithm::Sha1, digits, period).unwrap(),
                    seed: SecretBytes::copy_from(RFC_SEED_20),
                }),
                adapter_key: Some(SecretBytes::copy_from(b"synthetic-adapter-key-fixture")),
            })
        })
        .unwrap()
    }

    #[test]
    fn per_account_serialization_blocks_same_account_and_allows_distinct_accounts() {
        let state = Arc::new(TotpState::after_start(0));
        let item_a = ItemId::generate();
        let item_b = ItemId::generate();

        let guard_a1 = state.acquire_account(item_a);
        assert_eq!(guard_a1.item(), item_a);
        assert!(state.try_acquire_account(item_a).is_none());

        // A distinct account acquires immediately in parallel.
        let guard_b = state
            .try_acquire_account(item_b)
            .expect("distinct account must not block");
        assert_eq!(guard_b.item(), item_b);
        drop(guard_b);

        let started = Arc::new(Barrier::new(2));
        let acquired = Arc::new(AtomicUsize::new(0));
        let state_bg = Arc::clone(&state);
        let started_bg = Arc::clone(&started);
        let acquired_bg = Arc::clone(&acquired);

        let handle = thread::spawn(move || {
            started_bg.wait();
            let _guard_a2 = state_bg.acquire_account(item_a);
            acquired_bg.store(1, Ordering::SeqCst);
        });

        started.wait();
        // Give the background thread a moment to park on the condvar while guard_a1 is held.
        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            acquired.load(Ordering::SeqCst),
            0,
            "second attempt on the same account must wait while first guard is held"
        );

        drop(guard_a1);
        handle.join().unwrap();
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn last_three_seconds_waits_for_next_step_and_refuses_if_clock_stalls() {
        let (_dir, mut v) = test_vault();
        let item = enroll_login(&mut v, "acme/editor", 8, 30);
        // Start at unix 0 (refused steps [0, 0]); step 2 is [60..89], step 3 is [90..119].
        let state = TotpState::after_start(0);
        let guard = state.acquire_account(item);
        let lease = state.issue_lease(&v, item).unwrap();

        // At t = 88 (2 seconds left in step 2, inside the last 3 seconds), if clock stalls:
        let mut stalled_clock = || 88u64;
        let mut sleeps = Vec::new();
        let mut record_sleep = |d: Duration| sleeps.push(d);
        let mut audit_ok = |_step: u64| true;
        let err = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut stalled_clock,
                &mut record_sleep,
                &mut audit_ok,
            )
            .unwrap_err();
        assert_eq!(err, TotpError::TooLateInStep);
        assert_eq!(sleeps, vec![Duration::from_secs(2)]);
        assert_eq!(state.last_submitted_step(item), None);

        // At t = 87 (3 seconds left in step 2: T-3s boundary), clock advances on sleep by wait_secs:
        let now = std::cell::Cell::new(87u64);
        let mut waited = Vec::new();
        let mut audited_steps = Vec::new();
        let (c3, step) = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut || now.get(),
                &mut |d: Duration| {
                    waited.push(d);
                    now.set(now.get() + d.as_secs());
                },
                &mut |s: u64| {
                    audited_steps.push(s);
                    true
                },
            )
            .unwrap();
        assert_eq!(waited, vec![Duration::from_secs(3)]);
        assert_eq!(now.get(), 90);
        assert_eq!(step, 3);
        assert_eq!(audited_steps, vec![3]);
        let expected_step_3 = code(
            &SecretBytes::copy_from(RFC_SEED_20),
            TotpParams::new(envcloak_signin::totp::Algorithm::Sha1, 8, 30).unwrap(),
            3,
        );
        assert!(c3.as_secret().ct_eq_secret(expected_step_3.as_secret()));

        // At T+1s of the next step (t = 121, step 4), no boundary wait is needed.
        now.set(121);
        waited.clear();
        let (_c4, step4) = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut || now.get(),
                &mut |d: Duration| {
                    waited.push(d);
                    now.set(now.get() + d.as_secs());
                },
                &mut |s: u64| {
                    audited_steps.push(s);
                    true
                },
            )
            .unwrap();
        assert!(waited.is_empty());
        assert_eq!(step4, 4);
    }

    #[test]
    fn submitted_step_is_never_reused_for_same_account() {
        let (_dir, mut v) = test_vault();
        let item = enroll_login(&mut v, "acme/editor", 6, 30);
        let state = TotpState::after_start(0);
        let guard = state.acquire_account(item);
        let lease = state.issue_lease(&v, item).unwrap();

        let now = std::cell::Cell::new(95u64); // step 3
        let mut sleeps = Vec::new();

        let (c_first, step_first) = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut || now.get(),
                &mut |d: Duration| {
                    sleeps.push(d);
                    now.set(now.get() + d.as_secs());
                },
                &mut |_step: u64| true,
            )
            .unwrap();
        assert_eq!(step_first, 3);
        assert!(sleeps.is_empty());
        assert_eq!(state.last_submitted_step(item), Some(3));

        // Still in step 3 (t = 100): if clock stalls, returns StepAlreadyUsed { step: 3 }.
        let mut stalled_sleeps = Vec::new();
        let err = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut || 100u64,
                &mut |d: Duration| stalled_sleeps.push(d),
                &mut |_step: u64| true,
            )
            .unwrap_err();
        assert_eq!(err, TotpError::StepAlreadyUsed { step: 3 });
        assert_eq!(stalled_sleeps, vec![Duration::from_secs(20)]);

        // With advancing clock at t = 100, waits 20s for step 4 (t = 120) and returns step 4's code.
        now.set(100);
        let (c_second, step_second) = state
            .next_code(
                &guard,
                &lease,
                &v,
                &mut || now.get(),
                &mut |d: Duration| {
                    sleeps.push(d);
                    now.set(now.get() + d.as_secs());
                },
                &mut |_step: u64| true,
            )
            .unwrap();
        assert_eq!(sleeps, vec![Duration::from_secs(20)]);
        assert_eq!(step_second, 4);
        assert!(!c_first.as_secret().ct_eq_secret(c_second.as_secret()));
    }

    #[test]
    fn after_start_refuses_startup_step_and_predecessor_across_restart() {
        let (_dir, mut v) = test_vault();
        let item = enroll_login(&mut v, "acme/editor", 6, 30);

        // Before restart: code submitted at step 10 (t = 305).
        let state_before = TotpState::after_start(0);
        let g1 = state_before.acquire_account(item);
        let lease = state_before.issue_lease(&v, item).unwrap();
        let (code_s10, s10) = state_before
            .next_code(&g1, &lease, &v, &mut || 305, &mut |_| {}, &mut |_| true)
            .unwrap();
        assert_eq!(s10, 10);
        drop(g1);

        // Daemon restarts at t = 310 (still step 10). Refused steps are [10, 9].
        let state_restarted = TotpState::after_start(310);
        assert_eq!(state_restarted.start_unix(), 310);
        let g2 = state_restarted.acquire_account(item);

        // Stalled clock at step 9 (t = 280) or step 10 (t = 312) is refused.
        let err_s9 = state_restarted
            .next_code(&g2, &lease, &v, &mut || 280, &mut |_| {}, &mut |_| true)
            .unwrap_err();
        assert_eq!(err_s9, TotpError::RefusedAfterStart { step: 9 });

        let err_s10 = state_restarted
            .next_code(&g2, &lease, &v, &mut || 312, &mut |_| {}, &mut |_| true)
            .unwrap_err();
        assert_eq!(err_s10, TotpError::RefusedAfterStart { step: 10 });

        // Advancing clock from t = 312 sleeps 18s to t = 330 (step 11) and yields step 11's code.
        let now = std::cell::Cell::new(312u64);
        let mut sleeps = Vec::new();
        let (code_s11, s11) = state_restarted
            .next_code(
                &g2,
                &lease,
                &v,
                &mut || now.get(),
                &mut |d| {
                    sleeps.push(d);
                    now.set(now.get() + d.as_secs());
                },
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(sleeps, vec![Duration::from_secs(18)]);
        assert_eq!(s11, 11);
        assert!(!code_s10.as_secret().ct_eq_secret(code_s11.as_secret()));
    }

    #[test]
    fn durable_audit_failure_aborts_before_returning_code_or_recording_step() {
        let (_dir, mut v) = test_vault();
        let item = enroll_login(&mut v, "acme/editor", 6, 30);
        let state = TotpState::after_start(0);
        let guard = state.acquire_account(item);
        let lease = state.issue_lease(&v, item).unwrap();

        let err = state
            .next_code(&guard, &lease, &v, &mut || 95, &mut |_| {}, &mut |_| false)
            .unwrap_err();
        assert_eq!(err, TotpError::AuditFailed);
        assert_eq!(state.last_submitted_step(item), None);

        // Since step 3 was not recorded as submitted, a retry with working audit succeeds at step 3.
        let (_code, step) = state
            .next_code(&guard, &lease, &v, &mut || 95, &mut |_| {}, &mut |_| true)
            .unwrap();
        assert_eq!(step, 3);
        assert_eq!(state.last_submitted_step(item), Some(3));
    }

    #[test]
    fn login_field_replacement_invalidates_attempt_lease_and_totp_state_revision() {
        let (_dir, mut v) = test_vault();
        let item = enroll_login(&mut v, "acme/editor", 6, 30);
        let state = TotpState::after_start(0);
        let guard = state.acquire_account(item);
        let lease_v1 = state.issue_lease(&v, item).unwrap();
        assert_eq!(lease_v1.revision(), 1);

        let user = state
            .read_field(&guard, &lease_v1, &v, FieldKind::Username)
            .unwrap();
        assert!(user.ct_eq(b"editor@example.test"));
        let pass = state
            .read_field(&guard, &lease_v1, &v, FieldKind::Password)
            .unwrap();
        assert!(pass.ct_eq(b"synthetic-login-password-fixture"));

        // Rotate password in the vault and notify TotpState.
        v.transact(|t| {
            t.replace_login_field(
                item,
                LoginFieldValue::Password(SecretBytes::copy_from(b"rotated-login-password-v2")),
            )
        })
        .unwrap();
        let rev_v2 = v.login_revision(item).unwrap();
        assert_eq!(rev_v2, 2);
        state.on_login_replaced(item, rev_v2);

        // Old lease is rejected by both read_field and next_code.
        assert_eq!(
            state
                .read_field(&guard, &lease_v1, &v, FieldKind::Password)
                .unwrap_err(),
            TotpError::LeaseStale
        );
        assert_eq!(
            state
                .next_code(&guard, &lease_v1, &v, &mut || 95, &mut |_| {}, &mut |_| {
                    true
                })
                .unwrap_err(),
            TotpError::LeaseStale
        );

        // Even if TotpState's min_revision moves ahead before a vault read, issue_lease and
        // next_code reject any lease below min_revision.
        let lease_v2 = state.issue_lease(&v, item).unwrap();
        assert_eq!(lease_v2.revision(), 2);
        let new_pass = state
            .read_field(&guard, &lease_v2, &v, FieldKind::Password)
            .unwrap();
        assert!(new_pass.ct_eq(b"rotated-login-password-v2"));

        state.on_login_replaced(item, 3);
        assert_eq!(
            state
                .next_code(&guard, &lease_v2, &v, &mut || 95, &mut |_| {}, &mut |_| {
                    true
                })
                .unwrap_err(),
            TotpError::LeaseStale
        );
    }

    #[test]
    fn on_lock_invalidates_pre_lock_lease_resets_min_revision_and_preserves_submitted_step() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let kit = envcloak_core::RecoveryKit::generate();
        let pass = SecretBytes::copy_from(b"unit test passphrase for totp engine");
        let mut v = envcloak_core::create_vault_with_kit(&paths, &pass, &kit, KdfParams::minimum())
            .unwrap();
        let item = enroll_login(&mut v, "acme/editor", 6, 30);
        let state = TotpState::after_start(0);
        let guard = state.acquire_account(item);

        // Take a backup at revision 1 before rotating.
        let backup = v.create_backup().unwrap().path;

        // Issue a lease at revision 1 and submit step 3 (t = 95).
        let lease_pre_lock = state.issue_lease(&v, item).unwrap();
        assert_eq!(lease_pre_lock.revision(), 1);
        let (_code_s3, s3) = state
            .next_code(
                &guard,
                &lease_pre_lock,
                &v,
                &mut || 95,
                &mut |_| {},
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(s3, 3);
        assert_eq!(state.last_submitted_step(item), Some(3));

        // 1. Lock/unlock at the same revision 1: pre-lock lease is invalidated by on_lock.
        state.on_lock();
        assert_eq!(
            state
                .read_field(&guard, &lease_pre_lock, &v, FieldKind::Password)
                .unwrap_err(),
            TotpError::LeaseStale
        );
        assert_eq!(
            state
                .next_code(
                    &guard,
                    &lease_pre_lock,
                    &v,
                    &mut || 125,
                    &mut |_| {},
                    &mut |_| true,
                )
                .unwrap_err(),
            TotpError::LeaseStale
        );
        // Step 3 remains recorded as submitted across on_lock.
        assert_eq!(state.last_submitted_step(item), Some(3));

        // 2. Rotate login password to revision 2 and record min_revision = 2 in TotpState.
        v.transact(|t| {
            t.replace_login_field(
                item,
                LoginFieldValue::Password(SecretBytes::copy_from(b"rotated-login-password-v2")),
            )
        })
        .unwrap();
        assert_eq!(v.login_revision(item), Some(2));
        state.on_login_replaced(item, 2);

        // 3. Restore backup from revision 1 (`vault.recover` calls `on_lock` during
        // `begin_recover` and `start_grants`).
        drop(v);
        state.on_lock();
        let (restored, _report) =
            envcloak_core::restore_backup(&paths, &backup, &kit, &pass).unwrap();
        assert_eq!(restored.login_revision(item), Some(1));
        state.on_lock();

        // Restored login item at revision 1 is not wedged by the pre-recover min_revision = 2.
        let lease_restored = state.issue_lease(&restored, item).unwrap();
        assert_eq!(lease_restored.revision(), 1);
        let restored_pw = state
            .read_field(&guard, &lease_restored, &restored, FieldKind::Password)
            .unwrap();
        assert!(restored_pw.ct_eq(b"synthetic-login-password-fixture"));

        // Step 3 replay protection is still preserved after backup recovery.
        assert_eq!(
            state
                .next_code(
                    &guard,
                    &lease_restored,
                    &restored,
                    &mut || 100,
                    &mut |_| {},
                    &mut |_| true,
                )
                .unwrap_err(),
            TotpError::StepAlreadyUsed { step: 3 }
        );
        let (_code_s4, s4) = state
            .next_code(
                &guard,
                &lease_restored,
                &restored,
                &mut || 125,
                &mut |_| {},
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(s4, 4);
    }

    #[test]
    fn bounded_output_code_search_finds_planted_code_and_confirms_zero_leaks() {
        let (_dir, mut v) = test_vault();
        let item6 = enroll_login(&mut v, "acme/six", 6, 30);
        let item8 = enroll_login(&mut v, "acme/eight", 8, 30);
        let state = TotpState::after_start(0);

        let g6 = state.acquire_account(item6);
        let l6 = state.issue_lease(&v, item6).unwrap();
        let (code6, step6) = state
            .next_code(&g6, &l6, &v, &mut || 95, &mut |_| {}, &mut |_| true)
            .unwrap();
        assert_eq!(step6, 3);

        let g8 = state.acquire_account(item8);
        let l8 = state.issue_lease(&v, item8).unwrap();
        let (code8, step8) = state
            .next_code(&g8, &l8, &v, &mut || 95, &mut |_| {}, &mut |_| true)
            .unwrap();
        assert_eq!(step8, 3);

        let bounded_outputs = [
            format!("{code6:?}"),
            format!("{code6}"),
            format!("{code8:?}"),
            format!("{code8}"),
            format!("{g6:?}"),
            format!("{l6:?}"),
            format!("{state:?}"),
            format!("{:?}", TotpError::StepAlreadyUsed { step: 3 }),
            format!("{}", TotpError::StepAlreadyUsed { step: 3 }),
            r#"{"tool":"signin","status":"ok","item":"acme/six"}"#.to_owned(),
            "envcloakd: audit: login replaced id=01J000 field=totp revision=2 pid=42".to_owned(),
            "mcp-stderr: navigation completed status=200".to_owned(),
        ];
        for sample in &bounded_outputs {
            assert_eq!(
                count_code_matches(sample.as_bytes(), &code6),
                0,
                "6-digit code leaked in bounded output: {sample}"
            );
            assert_eq!(
                count_code_matches(sample.as_bytes(), &code8),
                0,
                "8-digit code leaked in bounded output: {sample}"
            );
        }

        // Positive control: RFC 6238 SHA-1 seed "12345678901234567890" at period=30, step=3 (t=95):
        // Verify that planting the exact 6-digit code inside bounded outputs is detected, while
        // adjacent digits (7-digit number) do not false-match.
        for candidate in 0..1_000_000u32 {
            let text = format!("{candidate:06}");
            if code6.as_secret().ct_eq(text.as_bytes()) {
                let planted = format!(r#"{{"error":"unexpected code {text} in response"}}"#);
                assert_eq!(count_code_matches(planted.as_bytes(), &code6), 1);
                let neighbor = format!("request_id={text}9");
                assert_eq!(count_code_matches(neighbor.as_bytes(), &code6), 0);
                return;
            }
        }
        panic!("6-digit code must match one of 000000..=999999");
    }
}
