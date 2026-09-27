//! Process hardening (SPEC §5 "Process hardening", gate 19).
//!
//! - Core dumps off: `RLIMIT_CORE` soft and hard limits set to 0, so neither
//!   the process nor a child it spawns can turn them back on.
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)`. The kernel then refuses same-uid
//!   `ptrace` attaches and reads of `/proc/<pid>/mem` and `environ`, and never
//!   writes a core, not even through a `core_pattern` pipe helper (which
//!   ignores `RLIMIT_CORE`).
//! - macOS: debugger protection comes from the hardened runtime without
//!   `get-task-allow` on signed builds; [`Hardening::hardened_runtime`]
//!   reports it from the kernel's code-signing flags.
//! - [`tracer_present`] tells a caller to refuse to handle values when a
//!   tracer is already attached.

use std::io;

/// What the running process is protected by. Every field is read back from
/// the kernel, so a failed hardening call shows up here as `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// The soft `RLIMIT_CORE` limit is 0.
    pub core_dumps_off: bool,
    /// Linux: `PR_GET_DUMPABLE` returns 0. Always false elsewhere, where
    /// there is no such flag.
    pub non_dumpable: bool,
    /// macOS: the code signature has the hardened runtime and no
    /// `get-task-allow`. `None` on other systems.
    pub hardened_runtime: Option<bool>,
}

/// Sets the soft and hard `RLIMIT_CORE` limits to 0. Lowering the hard limit
/// cannot be undone by an unprivileged process, and children inherit it.
pub fn disable_core_dumps() -> io::Result<()> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The current `RLIMIT_CORE` limits as `(soft, hard)`. `RLIM_INFINITY`
/// reads as `u64::MAX`.
pub fn core_dump_limit() -> io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit that outlives the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((lim.rlim_cur, lim.rlim_max))
}

/// Linux: `prctl(PR_SET_DUMPABLE, 0)`. A no-op on other systems.
pub fn set_non_dumpable() -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let off: libc::c_ulong = 0;
        let zero: libc::c_ulong = 0;
        // SAFETY: PR_SET_DUMPABLE takes one integer argument; the unused
        // trailing arguments are passed as zero.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, zero, zero, zero) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn dumpable_flag() -> io::Result<i32> {
    let zero: libc::c_ulong = 0;
    // SAFETY: PR_GET_DUMPABLE takes no arguments and returns the flag.
    let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, zero, zero, zero, zero) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// Parses the `TracerPid` field of a Linux `/proc/<pid>/status` file.
/// Returns `None` when the field is missing or malformed.
pub fn parse_tracer_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|rest| rest.trim().parse().ok())
}

/// Whether a debugger or other tracer is attached to this process right now.
///
/// Linux reads `TracerPid` for every thread under `/proc/self/task`, since
/// ptrace attaches to threads and `/proc/self/status` shows only the main
/// one. macOS reads the kernel's traced flag with
/// `proc_pidinfo(PROC_PIDTBSDINFO)`, the same flag Apple's QA1361 reads
/// through `sysctl` as `P_TRACED`. This is defense in depth: on Linux,
/// non-dumpable blocks new attaches, and on signed macOS builds the hardened
/// runtime does.
pub fn tracer_present() -> io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_traced()
    }
    #[cfg(target_os = "macos")]
    {
        macos::traced()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_traced() -> io::Result<bool> {
    let tracer_of = |status: &str| {
        parse_tracer_pid(status).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no TracerPid field in a status file",
            )
        })
    };
    let mut threads = 0usize;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let status = match std::fs::read_to_string(entry?.path().join("status")) {
            Ok(s) => s,
            // The thread exited between listing and reading.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if tracer_of(&status)? != 0 {
            return Ok(true);
        }
        threads += 1;
    }
    if threads == 0 {
        // Every listed thread vanished; the main thread cannot have.
        return Ok(tracer_of(&std::fs::read_to_string("/proc/self/status")?)? != 0);
    }
    Ok(false)
}

/// Locks `region` into RAM with `mlock` and, on Linux, excludes its pages
/// from core dumps with `MADV_DONTDUMP` (macOS has no equivalent). Best
/// effort: callers treat an error as non-fatal. The Linux `RLIMIT_MEMLOCK`
/// default can be as small as 64 KiB, so keep locked regions to a page.
/// The lock covers whole pages and stays until they are unmapped.
pub fn lock_memory(region: &mut [u8]) -> io::Result<()> {
    if region.is_empty() {
        return Ok(());
    }
    let ptr = region.as_mut_ptr();
    let len = region.len();
    // SAFETY: `ptr..ptr+len` is a live, writable region borrowed for the
    // duration of the call; mlock does not access its contents.
    let locked = if unsafe { libc::mlock(ptr.cast(), len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let advised = {
        let page = page_size();
        let start = ptr.wrapping_sub(ptr.addr() % page);
        let span = (ptr.addr() - start.addr() + len).div_ceil(page) * page;
        // SAFETY: madvise only changes dump flags of the pages covering the
        // borrowed region; `start` is page-aligned as madvise requires.
        if unsafe { libc::madvise(start.cast(), span, libc::MADV_DONTDUMP) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let advised = Ok(());
    locked.and(advised)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|s| s.is_power_of_two())
        .unwrap_or(4096)
}

/// Reads back what protects this process. See [`Hardening`].
pub fn hardening_status() -> Hardening {
    let core_dumps_off = matches!(core_dump_limit(), Ok((0, _)));
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let non_dumpable = matches!(dumpable_flag(), Ok(0));
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let non_dumpable = false;
    #[cfg(target_os = "macos")]
    let hardened_runtime = Some(macos::hardened_runtime());
    #[cfg(not(target_os = "macos"))]
    let hardened_runtime = None;
    Hardening {
        core_dumps_off,
        non_dumpable,
        hardened_runtime,
    }
}

/// Applies the hardening every EnvCloak binary performs first thing in
/// `main`, and reads back the result. Failures are not fatal here: the
/// returned [`Hardening`] (and `envcloak status`) shows what took effect, and
/// value paths decide whether to refuse.
pub fn harden_process() -> Hardening {
    let _ = disable_core_dumps();
    let _ = set_non_dumpable();
    hardening_status()
}

/// A value-free, line-oriented description of this process's hardening:
/// `key=value` lines for diagnostics and tests.
pub fn hardening_report() -> String {
    let h = hardening_status();
    let limit = match core_dump_limit() {
        Ok((soft, hard)) => format!("{}/{}", show_limit(soft), show_limit(hard)),
        Err(_) => "unknown".to_owned(),
    };
    let runtime = match h.hardened_runtime {
        Some(v) => v.to_string(),
        None => "n/a".to_owned(),
    };
    let tracer = match tracer_present() {
        Ok(v) => v.to_string(),
        Err(_) => "unknown".to_owned(),
    };
    format!(
        "core_dumps_off={}\nrlimit_core={limit}\nnon_dumpable={}\nhardened_runtime={runtime}\ntracer_present={tracer}\nwiping_allocator={}\n",
        h.core_dumps_off,
        h.non_dumpable,
        crate::wiping_allocator_active(),
    )
}

fn show_limit(v: u64) -> String {
    if v == libc::RLIM_INFINITY {
        "unlimited".to_owned()
    } else {
        v.to_string()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;

    // Declared in the kernel's <sys/codesign.h>; exported by libSystem.
    unsafe extern "C" {
        fn csops(
            pid: libc::pid_t,
            ops: libc::c_uint,
            useraddr: *mut libc::c_void,
            usersize: libc::size_t,
        ) -> libc::c_int;
    }

    const CS_OPS_STATUS: libc::c_uint = 0;
    const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
    const CS_RUNTIME: u32 = 0x0001_0000;
    /// <sys/proc_info.h>: "process currently being traced".
    const PROC_FLAG_TRACED: u32 = 2;

    pub(super) fn hardened_runtime() -> bool {
        let mut flags: u32 = 0;
        // SAFETY: CS_OPS_STATUS writes one u32 into `flags`, whose size we
        // pass; getpid has no preconditions.
        let rc = unsafe {
            csops(
                libc::getpid(),
                CS_OPS_STATUS,
                (&raw mut flags).cast(),
                size_of::<u32>(),
            )
        };
        rc == 0 && flags & CS_RUNTIME != 0 && flags & CS_GET_TASK_ALLOW == 0
    }

    pub(super) fn traced() -> io::Result<bool> {
        // SAFETY: proc_bsdinfo is plain old data; all zeros is valid.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` is writable for `size` bytes; getpid has no
        // preconditions.
        let n = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if n != size {
            return Err(io::Error::last_os_error());
        }
        Ok(info.pbi_flags & PROC_FLAG_TRACED != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_tracer_pid;

    const STATUS: &str = "Name:\tenvcloak\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4242\nPPid:\t4100\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";

    #[test]
    fn untraced_status_parses_to_zero() {
        assert_eq!(parse_tracer_pid(STATUS), Some(0));
    }

    #[test]
    fn traced_status_parses_to_the_tracer_pid() {
        let traced = STATUS.replace("TracerPid:\t0", "TracerPid:\t31337");
        assert_eq!(parse_tracer_pid(&traced), Some(31337));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(parse_tracer_pid("TracerPid:   77  \n"), Some(77));
        assert_eq!(parse_tracer_pid("TracerPid:\t9"), Some(9));
    }

    #[test]
    fn first_field_wins() {
        assert_eq!(parse_tracer_pid("TracerPid:\t5\nTracerPid:\t0\n"), Some(5));
    }

    #[test]
    fn missing_or_malformed_fields_are_none() {
        assert_eq!(parse_tracer_pid(""), None);
        assert_eq!(parse_tracer_pid("Name:\tx\nPid:\t1\n"), None);
        assert_eq!(parse_tracer_pid("TracerPid:\n"), None);
        assert_eq!(parse_tracer_pid("TracerPid:\t-1\n"), None);
        assert_eq!(parse_tracer_pid("TracerPid:\tabc\n"), None);
        assert_eq!(parse_tracer_pid("TracerPid:\t99999999999\n"), None);
        // The field name must start the line.
        assert_eq!(parse_tracer_pid("XTracerPid:\t3\n"), None);
    }
}
