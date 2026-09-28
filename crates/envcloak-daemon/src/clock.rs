//! The daemon's clocks (SPEC §5 "Lock").
//!
//! Rust's `Instant` does not say whether it counts time asleep, so lock
//! decisions read an explicit pair: time awake, which stops while the
//! machine sleeps, and time including sleep. [`Clocks`] is a trait so tests
//! can drive both, and the wall clock, by hand.

use std::time::{Duration, SystemTime};

/// The clocks lock decisions read.
pub trait Clocks: Send + Sync {
    /// The wall clock, UTC. Grant deadlines (T9) read it.
    #[allow(dead_code)]
    fn wall(&self) -> SystemTime;
    /// Time awake: macOS `CLOCK_UPTIME_RAW`, Linux `CLOCK_MONOTONIC`.
    fn awake(&self) -> Duration;
    /// Time including sleep: macOS `CLOCK_MONOTONIC_RAW`, Linux
    /// `CLOCK_BOOTTIME`.
    fn including_sleep(&self) -> Duration;
}

/// The kernel's clocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClocks;

impl Clocks for SystemClocks {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn awake(&self) -> Duration {
        // The kernel always has these clocks; a failure reads as zero, which
        // an observation treats as a clock that did not advance.
        envcloak_sys::awake_time().unwrap_or_default()
    }

    fn including_sleep(&self) -> Duration {
        envcloak_sys::time_including_sleep().unwrap_or_default()
    }
}

/// Clocks a test moves by hand.
#[cfg(test)]
#[derive(Debug)]
pub struct FakeClocks {
    inner: std::sync::Mutex<(SystemTime, Duration, Duration)>,
}

#[cfg(test)]
impl FakeClocks {
    pub fn new() -> Self {
        FakeClocks {
            inner: std::sync::Mutex::new((
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                Duration::from_secs(1000),
                Duration::from_secs(1000),
            )),
        }
    }

    /// The machine runs for `d`: every clock advances by it.
    pub fn run(&self, d: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 += d;
        g.1 += d;
        g.2 += d;
    }

    /// The machine sleeps for `d`: the wall clock and time including sleep
    /// advance; time awake does not.
    pub fn sleep(&self, d: Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 += d;
        g.2 += d;
    }
}

#[cfg(test)]
impl Clocks for FakeClocks {
    fn wall(&self) -> SystemTime {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    fn awake(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    fn including_sleep(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).2
    }
}
