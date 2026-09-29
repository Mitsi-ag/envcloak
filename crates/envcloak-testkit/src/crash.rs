//! Helpers for gate 19's crash and code-signing checks (SPEC §5 "Process
//! hardening"), shared by the tests of both binaries.
//!
//! The positive core-dump control deliberately crashes a process, so it
//! runs only where core files go to a known directory: set
//! `ENVCLOAK_TEST_CORE_DIR` to a directory the kernel writes `core.<pid>`
//! files into (Linux `kernel.core_pattern`, macOS `kern.corefile`; CI does
//! this on both). macOS writes a core only for a process signed with
//! `get-task-allow`, so there the control and the program under test are
//! copies signed with it ([`signed_copy`]).

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::process::ExitStatus;

/// Shell prefix that raises the core limit as far as the hard limit
/// allows. Use it only in [`crate::TestHome::apply`]'s cleared environment.
pub const RAISE_CORE_LIMIT: &str =
    "ulimit -c unlimited 2>/dev/null || ulimit -c \"$(ulimit -H -c)\" 2>/dev/null; ";

/// The directory the kernel writes `core.<pid>` files into, when the
/// environment names one (see the module documentation).
///
/// # Panics
/// When `ENVCLOAK_TEST_CORE_DIR` is set but the kernel is not configured
/// to write there.
pub fn core_dump_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("ENVCLOAK_TEST_CORE_DIR")?);
    assert!(dir.is_dir(), "ENVCLOAK_TEST_CORE_DIR is not a directory");
    #[cfg(target_os = "linux")]
    {
        let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_default();
        assert!(
            Path::new(pattern.trim()).starts_with(&dir),
            "ENVCLOAK_TEST_CORE_DIR is set, but kernel.core_pattern is {pattern:?}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let sysctl = |name: &str| {
            let out = Command::new("/usr/sbin/sysctl")
                .args(["-n", name])
                .output()
                .unwrap_or_else(|e| panic!("sysctl {name}: {e}"));
            assert!(out.status.success(), "sysctl {name}: {out:?}");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        assert_eq!(
            sysctl("kern.coredump"),
            "1",
            "ENVCLOAK_TEST_CORE_DIR is set, but kern.coredump is off"
        );
        let pattern = sysctl("kern.corefile");
        assert_eq!(
            Path::new(&pattern),
            dir.join("core.%P"),
            "ENVCLOAK_TEST_CORE_DIR is set, but kern.corefile is {pattern:?}"
        );
    }
    Some(dir)
}

/// Core files a crash of `pid` could have left: `core` or `core.*` in
/// `cwd`, `/cores/core.<pid>` (macOS), and `core.<pid>` in `dumps`. A file
/// with that name can be older than the crash (an earlier process had the
/// same pid): take a [`CoreFiles`] snapshot before the process starts to
/// tell.
pub fn core_files(cwd: &Path, dumps: Option<&Path>, pid: i32) -> Vec<PathBuf> {
    cores_of(cwd, &pid_dirs(dumps), pid)
}

/// The directories a kernel writes `core.<pid>` files into: macOS's
/// `/cores`, and `dumps`.
fn pid_dirs(dumps: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/cores")];
    dirs.extend(dumps.map(Path::to_path_buf));
    dirs
}

/// `core` or `core.*` in `cwd`, and `core.<pid>` in each of `dirs`.
fn cores_of(cwd: &Path, dirs: &[PathBuf], pid: i32) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(cwd)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| is_core_name(&e.path()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    found.extend(
        dirs.iter()
            .map(|d| d.join(format!("core.{pid}")))
            .filter(|p| p.exists()),
    );
    found
}

/// Whether a file's name is `core` or starts with `core.`.
fn is_core_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "core" || n.starts_with("core."))
}

/// What identifies a file's contents at one moment: device, inode, size
/// and modification time.
type Stamp = (u64, u64, u64, i64, i64);

fn stamp(path: &Path) -> Option<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec()))
}

/// Every file a crash could leave as a core ([`core_files`] of any pid),
/// as it was at one moment. Take it before the process that is to crash
/// is started; [`CoreFiles::left`] then names only the files of that pid
/// made or changed since, so a `core.<pid>` an earlier process with the
/// same pid left is not blamed on it (review finding F-60), while one the
/// kernel wrote over is.
#[derive(Debug)]
pub struct CoreFiles {
    cwd: PathBuf,
    /// Where `core.<pid>` files are looked for (see [`pid_dirs`]).
    dirs: Vec<PathBuf>,
    before: Vec<(PathBuf, Stamp)>,
}

impl CoreFiles {
    pub fn before(cwd: &Path, dumps: Option<&Path>) -> Self {
        Self::before_in(cwd, pid_dirs(dumps))
    }

    /// [`CoreFiles::before`], with `core.<pid>` files looked for in `dirs`
    /// alone. The unit tests pass directories of their own, so what the
    /// host's `/cores` holds is not counted (review finding F-63).
    fn before_in(cwd: &Path, dirs: Vec<PathBuf>) -> Self {
        let before = std::iter::once(cwd)
            .chain(dirs.iter().map(PathBuf::as_path))
            .filter_map(|d| std::fs::read_dir(d).ok())
            .flat_map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()))
            .filter(|p| is_core_name(p))
            .filter_map(|p| stamp(&p).map(|s| (p, s)))
            .collect();
        CoreFiles {
            cwd: cwd.to_path_buf(),
            dirs,
            before,
        }
    }

    /// The files a crash of `pid` could have left ([`core_files`]) that
    /// are new or changed since the snapshot.
    pub fn left(&self, pid: i32) -> Vec<PathBuf> {
        cores_of(&self.cwd, &self.dirs, pid)
            .into_iter()
            .filter(|p| {
                let now = stamp(p);
                now.is_none() || !self.before.iter().any(|(q, s)| q == p && Some(*s) == now)
            })
            .collect()
    }

    /// How many core files there were at the snapshot, which
    /// [`CoreFiles::left`] does not count unless they changed.
    pub fn stale(&self) -> usize {
        self.before.len()
    }
}

/// Signal number and core-dump flag of an exit status.
pub trait StatusExt {
    fn signal_number(&self) -> Option<i32>;
    fn core_dumped_flag(&self) -> bool;
}

impl StatusExt for ExitStatus {
    fn signal_number(&self) -> Option<i32> {
        std::os::unix::process::ExitStatusExt::signal(self)
    }

    fn core_dumped_flag(&self) -> bool {
        std::os::unix::process::ExitStatusExt::core_dumped(self)
    }
}

/// Entitlements that let a debugger attach to the process (and, on macOS,
/// let it dump core).
#[cfg(target_os = "macos")]
const GET_TASK_ALLOW: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>\n";

/// Copies `program` to `dir/name` and signs the copy ad hoc, with the
/// hardened runtime if `runtime`, and with `get-task-allow` if
/// `debuggable`. Checks with `codesign --display` that the signature says
/// exactly that, starts the copy once (see [`FIRST_START_LIMIT`]), and
/// returns it.
///
/// # Panics
/// When copying or signing fails, the signature says otherwise, or the
/// first start does not end in time.
#[cfg(target_os = "macos")]
pub fn signed_copy(
    program: &Path,
    dir: &Path,
    name: &str,
    runtime: bool,
    debuggable: bool,
) -> PathBuf {
    let copy = dir.join(name);
    if let Err(e) = std::fs::copy(program, &copy) {
        panic!("copying {}: {e}", program.display());
    }
    let mut cmd = Command::new("codesign");
    cmd.args(["--force", "--sign", "-"]);
    if runtime {
        cmd.args(["--options", "runtime"]);
    }
    if debuggable {
        let plist = dir.join(format!("{name}.entitlements"));
        if let Err(e) = std::fs::write(&plist, GET_TASK_ALLOW) {
            panic!("writing entitlements: {e}");
        }
        cmd.arg("--entitlements").arg(plist);
    }
    let signed = cmd
        .arg(&copy)
        .output()
        .unwrap_or_else(|e| panic!("codesign: {e}"));
    assert!(signed.status.success(), "codesign failed: {signed:?}");
    let shown = Command::new("codesign")
        .args(["--display", "--verbose=2", "--entitlements", "-"])
        .arg(&copy)
        .output()
        .unwrap_or_else(|e| panic!("codesign --display: {e}"));
    assert!(shown.status.success(), "{shown:?}");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
    let runtime_flag = text
        .lines()
        .filter(|l| l.starts_with("CodeDirectory "))
        .any(|l| {
            l.split_whitespace()
                .find_map(|w| w.strip_prefix("flags="))
                .is_some_and(|f| f.contains("runtime"))
        });
    assert_eq!(runtime_flag, runtime, "{text}");
    assert_eq!(
        text.contains("com.apple.security.get-task-allow"),
        debuggable,
        "{text}"
    );
    first_start(&copy, dir, FIRST_START_LIMIT);
    copy
}

/// How long the first start of a copy signed a moment ago may take.
///
/// Before a new executable first runs, macOS has the system's execution
/// policy service look at it; until then the process waits at
/// `_dyld_start` and runs none of its code. On a loaded machine that
/// service can take minutes to get to it: behind a queue of new
/// executables, one start of such a copy waited over seven minutes, and a
/// review run whose held CLI had 30 seconds to say it was ready failed
/// (review finding F-60). The bound only keeps a stalled service from
/// hanging the suite.
#[cfg(target_os = "macos")]
pub const FIRST_START_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);

/// Starts `copy` once, with an argument no program here accepts, and waits
/// for it to exit, so the system's check of the new executable happens in
/// this step of its own and not inside a timed step of a test. Later
/// starts of the same copy are not checked again.
///
/// # Panics
/// When it has not exited within `limit`, naming the step. It is killed
/// first.
#[cfg(target_os = "macos")]
fn first_start(copy: &Path, dir: &Path, limit: std::time::Duration) {
    use std::process::Stdio;
    use std::time::Instant;

    let started = Instant::now();
    let mut child = Command::new(copy)
        .arg("--envcloak-first-start")
        .env_clear()
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("step `first start`: {}: {e}", copy.display()));
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < limit => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "step `first start`: {} had not started and exited after {:?} ({other:?}): \
                     the system's check of new executables is stalled",
                    copy.display(),
                    started.elapsed()
                );
            }
        }
    }
    if started.elapsed() > std::time::Duration::from_secs(5) {
        eprintln!(
            "the first start of {} took {:?}",
            copy.display(),
            started.elapsed()
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::CoreFiles;
    use crate::home::TestHome;

    /// Review finding F-60: a `core.<pid>` an earlier process with the same
    /// pid left is not this crash's; one written over, or new, is. The
    /// snapshot looks only in the test's own directories (review finding
    /// F-63: a Mac keeps old cores in `/cores`), one of which stands in for
    /// `/cores` and already holds cores of other processes.
    #[test]
    fn core_files_left_counts_only_files_made_or_changed_since() {
        let home = TestHome::new();
        let cwd = home.home();
        let tmp = home.root().join("tmp");
        let (dumps, cores_dir) = (tmp.join("dumps"), tmp.join("cores"));
        for d in [&dumps, &cores_dir] {
            std::fs::create_dir(d).unwrap();
        }
        let pid = 4242;
        let stale = dumps.join(format!("core.{pid}"));
        std::fs::write(&stale, b"an older process's core").unwrap();
        let unrelated = [
            cores_dir.join("core"),
            cores_dir.join("core.4343"),
            cores_dir.join(format!("core.{pid}")),
        ];
        for u in &unrelated {
            std::fs::write(u, b"another process's core").unwrap();
        }
        std::fs::write(cores_dir.join("not-a-core"), b"z").unwrap();
        let cores = CoreFiles::before_in(&cwd, vec![cores_dir.clone(), dumps.clone()]);
        assert_eq!(cores.stale(), 1 + unrelated.len(), "{cores:?}");
        assert!(cores.left(pid).is_empty(), "{:?}", cores.left(pid));

        // Written over by the crash: counted, like a new file.
        std::fs::write(&stale, b"this crash's core, longer than before").unwrap();
        std::fs::write(cwd.join("core"), b"x").unwrap();
        let mut left = cores.left(pid);
        left.sort();
        assert_eq!(left, [cwd.join("core"), stale.clone()]);
        // Another pid's file is not this crash's.
        std::fs::write(dumps.join("core.4343"), b"y").unwrap();
        assert_eq!(cores.left(pid).len(), 2);
        // Nor is one in the stand-in for /cores that nothing changed.
        std::fs::write(cores_dir.join("core.4343"), b"another crash").unwrap();
        assert_eq!(cores.left(pid).len(), 2);
        // One of this pid's written over there is.
        std::fs::write(&unrelated[2], b"this crash's core, written over").unwrap();
        let mut left = cores.left(pid);
        left.sort();
        assert_eq!(left, [cwd.join("core"), unrelated[2].clone(), stale]);
    }

    /// A first start that never ends fails its own step, named, within its
    /// bound, and leaves nothing running.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_first_start_that_never_ends_fails_its_step() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let home = TestHome::new();
        let dir = home.root().join("tmp");
        let marker = dir.join("pid");
        let script = dir.join("stalls");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nexec sleep 600\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        let (s, d) = (script.clone(), dir.clone());
        std::thread::spawn(move || {
            let r = std::panic::catch_unwind(|| {
                super::first_start(&s, &d, Duration::from_secs(1));
            });
            let _ = tx.send(r.err().and_then(|e| e.downcast_ref::<String>().cloned()));
        });
        let message = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the first start step did not end within its bound")
            .expect("a first start that never ends passed");
        assert!(message.starts_with("step `first start`:"), "{message}");
        assert!(started.elapsed() < Duration::from_secs(20));
        // The start was killed and reaped before the step failed. If the
        // script got as far as saying its pid, that process is gone; if
        // not, it never will (it is new to the system too, so under load
        // it may not have run a line within the bound).
        if let Ok(pid) = std::fs::read_to_string(&marker) {
            let pid: i32 = pid.trim().parse().unwrap();
            assert!(
                envcloak_sys::signal_process(pid, 0).is_err(),
                "the stalled start is still running"
            );
        }
    }
}
