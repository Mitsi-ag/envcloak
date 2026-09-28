//! When the vault locks by itself (SPEC §5 "Lock"): after the machine
//! slept, and after the idle limit.
//!
//! [`LockTimer::observe`] runs on a one-second tick and before every
//! request. It compares how far each clock moved since the last
//! observation: when time including sleep ran more than [`SLEEP_GAP`] ahead
//! of time awake, the machine slept. Deltas since the last observation,
//! not totals since start, so the clocks' small independent drift never
//! adds up to a false sleep. The idle limit counts time awake since the
//! last activity, and the machine sleeping locks anyway.
//!
//! Activity is a request that used the vault key: `unlock` and
//! `vault create` in M1, and every value release from T12 on. `status` and
//! `lock` are not activity, so polling the daemon never keeps the vault
//! open.

use std::time::Duration;

use envcloak_ipc::view::LockReason;

use crate::clock::Clocks;

/// Divergence between the two clocks that means the machine slept.
pub const SLEEP_GAP: Duration = Duration::from_secs(5);
/// The default idle limit: 8 hours.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(8 * 3600);
/// The largest idle limit: 24 hours.
pub const MAX_IDLE: Duration = Duration::from_secs(24 * 3600);
/// The smallest idle limit: 1 minute.
pub const MIN_IDLE: Duration = Duration::from_secs(60);

/// One reading of the clock pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub awake: Duration,
    pub including_sleep: Duration,
}

impl Reading {
    pub fn now(c: &dyn Clocks) -> Self {
        Reading {
            awake: c.awake(),
            including_sleep: c.including_sleep(),
        }
    }
}

/// The sleep and idle detector.
#[derive(Debug, Clone)]
pub struct LockTimer {
    idle_limit: Duration,
    last: Reading,
    last_activity: Duration,
}

impl LockTimer {
    /// A timer starting at `now`, locking after `idle_limit` of awake time
    /// without activity.
    pub fn new(idle_limit: Duration, now: Reading) -> Self {
        LockTimer {
            idle_limit,
            last: now,
            last_activity: now.awake,
        }
    }

    pub fn idle_limit(&self) -> Duration {
        self.idle_limit
    }

    /// Records activity at `now`: the idle limit starts again.
    pub fn touch(&mut self, now: Reading) {
        self.last_activity = now.awake;
    }

    /// Awake time left before the idle lock.
    pub fn idle_remaining(&self, now: Reading) -> Duration {
        let idle = now.awake.saturating_sub(self.last_activity);
        self.idle_limit.saturating_sub(idle)
    }

    /// Takes a reading and says whether the vault must lock: the machine
    /// slept since the last reading, or the idle limit passed. A clock
    /// that went backwards (it cannot, but a failed read gives zero) reads
    /// as no time passing.
    pub fn observe(&mut self, now: Reading) -> Option<LockReason> {
        let awake = now.awake.saturating_sub(self.last.awake);
        let total = now
            .including_sleep
            .saturating_sub(self.last.including_sleep);
        self.last = Reading {
            awake: now.awake.max(self.last.awake),
            including_sleep: now.including_sleep.max(self.last.including_sleep),
        };
        if total.saturating_sub(awake) > SLEEP_GAP {
            return Some(LockReason::Sleep);
        }
        if now.awake.saturating_sub(self.last_activity) >= self.idle_limit {
            return Some(LockReason::Idle);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClocks;

    fn timer(c: &FakeClocks, idle: Duration) -> LockTimer {
        LockTimer::new(idle, Reading::now(c))
    }

    #[test]
    fn a_running_machine_does_not_look_asleep() {
        let c = FakeClocks::new();
        let mut t = timer(&c, DEFAULT_IDLE);
        for _ in 0..100 {
            c.run(Duration::from_secs(1));
            assert_eq!(t.observe(Reading::now(&c)), None);
        }
        // A long gap between observations while awake (a stalled tick) is
        // not sleep either.
        c.run(Duration::from_secs(600));
        assert_eq!(t.observe(Reading::now(&c)), None);
    }

    #[test]
    fn sleep_longer_than_the_gap_locks() {
        let c = FakeClocks::new();
        let mut t = timer(&c, DEFAULT_IDLE);
        c.run(Duration::from_secs(1));
        c.sleep(Duration::from_secs(6));
        assert_eq!(t.observe(Reading::now(&c)), Some(LockReason::Sleep));
        // Measured from the last reading: the next tick is clean.
        c.run(Duration::from_secs(1));
        assert_eq!(t.observe(Reading::now(&c)), None);
    }

    #[test]
    fn a_short_divergence_is_noise() {
        let c = FakeClocks::new();
        let mut t = timer(&c, DEFAULT_IDLE);
        c.run(Duration::from_secs(1));
        c.sleep(SLEEP_GAP);
        assert_eq!(t.observe(Reading::now(&c)), None);
        // Divergence does not accumulate across readings.
        for _ in 0..10 {
            c.run(Duration::from_secs(1));
            c.sleep(Duration::from_secs(4));
            assert_eq!(t.observe(Reading::now(&c)), None);
        }
    }

    #[test]
    fn idle_counts_awake_time_since_the_last_activity() {
        let c = FakeClocks::new();
        let mut t = timer(&c, Duration::from_secs(3600));
        c.run(Duration::from_secs(3599));
        assert_eq!(t.observe(Reading::now(&c)), None);
        assert_eq!(t.idle_remaining(Reading::now(&c)), Duration::from_secs(1));
        t.touch(Reading::now(&c));
        c.run(Duration::from_secs(3599));
        assert_eq!(t.observe(Reading::now(&c)), None);
        c.run(Duration::from_secs(1));
        assert_eq!(t.observe(Reading::now(&c)), Some(LockReason::Idle));
        assert_eq!(t.idle_remaining(Reading::now(&c)), Duration::ZERO);
    }

    #[test]
    fn clocks_that_go_backwards_are_no_time() {
        let mut t = LockTimer::new(
            DEFAULT_IDLE,
            Reading {
                awake: Duration::from_secs(100),
                including_sleep: Duration::from_secs(100),
            },
        );
        let zero = Reading {
            awake: Duration::ZERO,
            including_sleep: Duration::ZERO,
        };
        assert_eq!(t.observe(zero), None);
        // A later good reading is measured from the highest seen.
        let later = Reading {
            awake: Duration::from_secs(101),
            including_sleep: Duration::from_secs(120),
        };
        assert_eq!(t.observe(later), Some(LockReason::Sleep));
    }
}
