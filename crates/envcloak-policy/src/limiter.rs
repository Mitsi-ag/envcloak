//! The passphrase attempt limiter (SPEC §10b "Passphrase attempts"; gate
//! 32). Failed proofs share one limiter, whatever method took them:
//! `unlock`, `approve`, and from T11 `rotate`, `rm` and `recover`.
//!
//! The first [`FREE_ATTEMPTS`] failures cost nothing. After them, each
//! further attempt must wait: [`FIRST_WAIT`] after the fifth failure, twice
//! as long after each failure beyond it, up to [`MAX_WAIT`]. An attempt
//! that comes early is refused without a passphrase being checked, so
//! Argon2id runs only for attempts the limiter admits. A success clears
//! the count. The wait counts time awake, so a machine asleep does not
//! serve it; [`crate::Now`] carries that clock.

use std::time::Duration;

use crate::grants::Now;

/// Failures before any wait.
pub const FREE_ATTEMPTS: u32 = 5;
/// The wait after the fifth failure.
pub const FIRST_WAIT: Duration = Duration::from_secs(30);
/// The longest wait.
pub const MAX_WAIT: Duration = Duration::from_secs(3600);

/// One limiter for every passphrase-proven method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptLimiter {
    failures: u32,
    /// Awake time before which no attempt is admitted.
    not_before: Option<Duration>,
}

impl AttemptLimiter {
    pub fn new() -> Self {
        AttemptLimiter::default()
    }

    /// Failures since the last success.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Whether an attempt may be checked now, or else how long it must
    /// still wait.
    ///
    /// # Errors
    /// The remaining wait.
    pub fn check(&self, now: &Now) -> Result<(), Duration> {
        match self.not_before {
            Some(t) if t > now.awake => Err(t - now.awake),
            _ => Ok(()),
        }
    }

    /// The remaining wait, or zero.
    pub fn wait_remaining(&self, now: &Now) -> Duration {
        self.check(now).err().unwrap_or_default()
    }

    /// Records a failed attempt at `now`.
    pub fn failed(&mut self, now: &Now) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= FREE_ATTEMPTS {
            let doublings = self.failures - FREE_ATTEMPTS;
            let wait = FIRST_WAIT
                .checked_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
                .unwrap_or(MAX_WAIT)
                .min(MAX_WAIT);
            self.not_before = Some(now.awake + wait);
        }
    }

    /// Records a successful attempt: the count and the wait are cleared.
    pub fn succeeded(&mut self) {
        self.failures = 0;
        self.not_before = None;
    }
}
