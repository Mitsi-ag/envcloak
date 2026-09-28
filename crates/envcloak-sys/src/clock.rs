//! The two clocks the daemon compares to notice that the machine slept
//! (SPEC §5 "Lock").
//!
//! Rust's `Instant` does not say whether it counts time asleep, so the
//! daemon reads each clock explicitly:
//!
//! | | [`awake_time`] (stops while asleep) | [`time_including_sleep`] |
//! |---|---|---|
//! | macOS | `CLOCK_UPTIME_RAW` | `CLOCK_MONOTONIC` |
//! | Linux | `CLOCK_MONOTONIC` | `CLOCK_BOOTTIME` |
//!
//! Both are monotonic. When the second advances further than the first
//! between two readings, the machine slept for the difference.

use std::io;
use std::time::Duration;

/// Time the machine has been awake: it stops while the machine sleeps.
///
/// # Errors
/// When the kernel does not provide the clock.
pub fn awake_time() -> io::Result<Duration> {
    #[cfg(target_os = "macos")]
    {
        read_clock(libc::CLOCK_UPTIME_RAW)
    }
    #[cfg(not(target_os = "macos"))]
    {
        read_clock(libc::CLOCK_MONOTONIC)
    }
}

/// Time since boot, including time asleep.
///
/// # Errors
/// When the kernel does not provide the clock.
pub fn time_including_sleep() -> io::Result<Duration> {
    #[cfg(target_os = "macos")]
    {
        read_clock(libc::CLOCK_MONOTONIC)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        read_clock(libc::CLOCK_BOOTTIME)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    {
        read_clock(libc::CLOCK_MONOTONIC)
    }
}

pub(crate) fn read_clock(id: libc::clockid_t) -> io::Result<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a writable timespec that outlives the call.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let secs = u64::try_from(ts.tv_sec).map_err(|_| io::Error::other("a negative clock"))?;
    let nanos = u32::try_from(ts.tv_nsec).map_err(|_| io::Error::other("a malformed clock"))?;
    if nanos >= 1_000_000_000 {
        return Err(io::Error::other("a malformed clock"));
    }
    Ok(Duration::new(secs, nanos))
}
