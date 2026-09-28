//! Review finding F-38: what a process's rewritten argument area hands
//! over, and where it goes. Neither kernel keeps a boundary between a
//! process's arguments and its environment that the process cannot move
//! (see the `proc` module documentation):
//!
//! - macOS reads environment strings as arguments once a process removed
//!   the NULs between its arguments, as the positive controls here show;
//! - Linux reads no more than the kernel's record of the argument area, so
//!   it never does, even when the NUL that ends the area is gone too (the
//!   kernel would then run on into the environment, as a control shows).
//!
//! Either way the arguments are held in an `Argv`: neither `ProcInfo`'s
//! `Debug` nor an error shows them, and no block freed after the read
//! holds them. This binary installs the inspection allocator and checks
//! that with the global allocator's own wipe turned off
//! (`ProbeMode::Unwiped`), so only `proc_argv`'s own wiping counts.
//!
//! The children are `python3`, which rewrites its own argument area
//! through `ctypes`, and `node`, whose `process.title` rewrites it over a
//! short command line. Each runs with a cleared environment whose first
//! variable holds a marker made at run time.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use envcloak_sys::testing::{ProbeAllocator, ProbeMode, ProbeSession};
use envcloak_sys::{Argv, proc_argv, proc_info};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

const WINDOW: usize = 12;

/// The marker's variable. Variables are passed in name order, so it is the
/// first environment string (the fillers follow, then `PATH`).
const MARKER_VAR: &str = "ECQ_ARGV_MARKER";

/// A marker distinct per call site and run: lowercase letters and digits.
fn marker(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("ecqenv{tag}{}x{nanos:x}", std::process::id())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A child, killed and reaped on drop, that printed `ready <pid>`.
struct Ready {
    child: Child,
    pid: i32,
}

impl Ready {
    fn start(cmd: &mut Command, marker: &str) -> Self {
        cmd.env_clear()
            .env(MARKER_VAR, marker)
            .env("ECQ_FILL_1", "1")
            .env("ECQ_FILL_2", "2")
            .env("ECQ_FILL_3", "3")
            .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let pid = line
            .trim()
            .strip_prefix("ready ")
            .unwrap_or_else(|| panic!("unexpected: {line:?}"))
            .parse()
            .unwrap();
        Ready { child, pid }
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `pid`'s arguments into a `ProcInfo` under an armed probe, shows
/// it every way the daemon can, and drops it. Returns whether the marker
/// was among the arguments. Asserts that no output shows the marker and
/// that no block freed meanwhile held it.
fn read_and_drop(pid: i32, marker: &str, what: &str) -> bool {
    let session = ProbeSession::start(&[marker.as_bytes()], WINDOW, ProbeMode::Unwiped);
    let mut info = proc_info(pid).unwrap();
    let (found, shown) = match proc_argv(pid) {
        Ok(argv) => {
            let found = argv
                .iter()
                .any(|a| contains(a.as_encoded_bytes(), marker.as_bytes()));
            let shown = format!("{argv:?}");
            info.argv = Some(argv);
            (found, shown + &format!("{info:?}"))
        }
        Err(e) => (false, format!("{e} {e:?}")),
    };
    let count = info.argv.as_ref().map(Argv::len);
    drop(info);
    let report = session.finish();
    assert!(
        !shown.contains(marker),
        "{what}: the output shows the environment marker"
    );
    assert!(count.is_some(), "{what}: the arguments were not read");
    assert_eq!(
        report.released_with_needle, 0,
        "{what}: a block freed after the read held the environment marker: {report:?}"
    );
    found
}

/// Removes the NULs between its own arguments (`separators`), or those
/// and the one that ends the argument area (`all`), then prints `ready`.
/// macOS: the area runs from `argv[0]` to the end of the last argument, as
/// `_NSGetArgv` finds them. Linux: `stat` fields 48 and 49.
const PY_REWRITE: &str = r#"import ctypes, os, sys
mode = sys.argv[1]
if sys.platform == 'darwin':
    libc = ctypes.CDLL(None)
    libc._NSGetArgc.restype = ctypes.POINTER(ctypes.c_int)
    libc._NSGetArgv.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
    argc = libc._NSGetArgc()[0]
    argv = libc._NSGetArgv()[0]
    start = argv[0]
    end = argv[argc - 1] + len(ctypes.string_at(argv[argc - 1])) + 1
else:
    stat = open('/proc/self/stat', 'rb').read()
    fields = stat[stat.rindex(b')') + 2:].split()
    start, end = int(fields[48 - 3]), int(fields[49 - 3])
area = bytearray(ctypes.string_at(start, end - start))
keep = 1 if mode == 'separators' else 0
for i in range(len(area) - keep):
    if area[i] == 0:
        area[i] = 0x20
ctypes.memmove(start, bytes(area), len(area))
print('ready %d' % os.getpid(), flush=True)
sys.stdin.read()
"#;

#[test]
fn a_rewritten_argument_area_is_held_wiped_and_never_shown() {
    for mode in ["separators", "all"] {
        let m = marker(&mode[..1]);
        let child = Ready::start(Command::new("python3").args(["-c", PY_REWRITE, mode]), &m);
        if cfg!(target_os = "linux") && mode == "all" {
            // The kernel takes the missing NUL for `setproctitle` and runs
            // on into the environment: this is what the bound is for.
            let raw = std::fs::read(format!("/proc/{}/cmdline", child.pid)).unwrap();
            assert!(
                contains(&raw, m.as_bytes()),
                "the kernel no longer reads past the argument area"
            );
        }
        let found = read_and_drop(child.pid, &m, mode);
        if cfg!(target_os = "macos") {
            // Nothing marks where the arguments end.
            assert!(found, "{mode}: macOS read no environment string");
        } else {
            assert!(!found, "{mode}: Linux read past the argument area");
        }
    }
}

/// The absolute path of `node`, found on this process's `PATH`. In CI it
/// must be there; elsewhere the test is skipped without it.
fn node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .map(|d| d.join("node"))
        .find(|p| p.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os("CI").is_none(),
            "node is needed on PATH in CI"
        );
        eprintln!("skipped: no node on PATH");
    }
    found
}

/// The review's case: an ordinary program. libuv writes node's
/// `process.title` over the argument area, cut to fit, and leaves one NUL
/// at its end, so on macOS the second argument is read from the
/// environment.
#[test]
fn node_with_a_long_process_title() {
    let Some(node) = node() else {
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("ecq")
        .tempdir_in("/tmp")
        .unwrap();
    let script = dir.path().join("t.js");
    std::fs::write(
        &script,
        r#"process.title = "a-long-descriptive-process-title-".repeat(8);
console.log("ready " + process.pid);
process.stdin.resume();
process.stdin.on("end", () => process.exit(0));
"#,
    )
    .unwrap();
    let m = marker("n");
    let child = Ready::start(Command::new(node).arg(&script), &m);
    let found = read_and_drop(child.pid, &m, "node");
    if cfg!(target_os = "macos") {
        assert!(found, "macOS read no environment string");
    } else {
        assert!(!found, "Linux read past the argument area");
    }
}
