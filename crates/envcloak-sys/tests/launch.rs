//! The day-one measurements of M2 task M2-27, kept as tests (M2 plan
//! M2-27 "Spike first"; D-33, D-36): on macOS, a child started suspended
//! runs no instruction until it is resumed, is killed through its handle
//! without running one, and reports the code directory hash the static
//! reading of its file gives, as `codesign` (an independent tool) gives
//! it; on Linux, a sealed copy is what runs whatever happens to the file
//! after the copy was made.
#![allow(clippy::unwrap_used)]

use std::os::fd::AsFd;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use envcloak_sys::launch::{Program, Session, Spawn, spawn};

#[cfg(target_os = "macos")]
fn wait_for(path: &Path, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

/// A shell that writes `marker` as its first act: a witness of whether
/// any of its code ran.
#[cfg(target_os = "macos")]
fn marker_shell(marker: &Path) -> Vec<u8> {
    format!("echo ran > '{}'", marker.display()).into_bytes()
}

/// macOS: a suspended child writes nothing until it is resumed, and once
/// it is, it runs; a suspended child killed through its handle never
/// runs. Its cdhash, read from the kernel while it is suspended, is the
/// one the static reading of `/bin/sh` gives and the one `codesign`
/// prints.
#[cfg(target_os = "macos")]
#[test]
fn a_suspended_child_runs_only_once_resumed_and_reports_its_cdhash() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let script = marker_shell(&marker);
    let start = || {
        spawn(&Spawn {
            program: Program::Path(b"/bin/sh"),
            argv: &[b"sh", b"-c", &script],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: true,
        })
        .unwrap()
    };

    // Killed while suspended: nothing ran.
    let child = start();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "a suspended child ran");
    let status = child.kill_and_reap().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
    assert!(
        !wait_for(&marker, Duration::from_millis(300)),
        "a killed suspended child ran"
    );

    // Resumed: it runs. Its cdhash first, while it is suspended.
    let child = start();
    let pid = i32::try_from(child.id()).unwrap();
    let kernel = envcloak_sys::proc_info(pid)
        .unwrap()
        .exe
        .and_then(|e| e.signature)
        .and_then(|s| s.cdhash)
        .expect("the kernel reports a suspended child's cdhash");
    let file = std::fs::File::open("/bin/sh").unwrap();
    let cd = envcloak_sys::codesign::code_directory(&file)
        .unwrap()
        .expect("/bin/sh is signed");
    assert_eq!(cd.hash_type, 2, "/bin/sh's best code directory is SHA-256");
    let digest = Sha256::digest(cd.cdhash_input());
    assert_eq!(
        &digest[..20],
        &kernel[..],
        "static and kernel cdhash differ"
    );
    // The independent oracle: codesign's own reading of the file.
    let out = std::process::Command::new("/usr/bin/codesign")
        .args(["-dvvv", "/bin/sh"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    let printed = text
        .lines()
        .find_map(|l| l.strip_prefix("CDHash="))
        .expect("codesign prints CDHash=");
    let hex: String = kernel.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(printed, hex, "codesign and the kernel disagree");
    assert!(!marker.exists());
    child.resume().unwrap();
    assert!(
        wait_for(&marker, Duration::from_secs(10)),
        "a resumed child did not run"
    );
    assert!(child.reap().unwrap().success());
}

/// Linux: the sealed copy runs as it was when copied, after the file it
/// came from is rewritten in place (the source's inode changed, which the
/// test checks happened) and after another file is renamed over it; and a
/// copy of a file that changes while it is read holds what was read.
#[cfg(target_os = "linux")]
#[test]
fn a_sealed_copy_runs_the_copied_image_whatever_the_file_becomes() {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use envcloak_sys::launch::SealedImage;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prog");
    // A native program is what a sealed copy is for; /bin/true and
    // /bin/false stand in for two builds: the copy is of `true`.
    std::fs::copy("/bin/true", &path).unwrap();
    let src = std::fs::File::open(&path).unwrap();
    let image = SealedImage::copy_from(src.as_fd(), 512 << 20).unwrap();
    let ino = std::fs::metadata(&path).unwrap().ino();
    // Rewritten in place with another build: the same inode, new bytes.
    let other = std::fs::read("/bin/false").unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.write_all(&other).unwrap();
    drop(f);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino);
    assert_eq!(std::fs::read(&path).unwrap(), other, "the rewrite happened");
    let run = |image: &SealedImage| {
        spawn(&Spawn {
            program: Program::Descriptor(image.as_fd()),
            argv: &[b"prog"],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap()
        .reap()
        .unwrap()
        .code()
    };
    assert_eq!(run(&image), Some(0), "the copy ran the rewritten file");
    // The file moved away and another put in its place: the copy still
    // runs `true`.
    std::fs::rename(&path, dir.path().join("moved")).unwrap();
    std::fs::copy("/bin/false", &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run(&image), Some(0));
    // The control: the source file, run by its path, is `false` now.
    let by_path = spawn(&Spawn {
        program: Program::Path(path.as_os_str().as_encoded_bytes()),
        argv: &[b"prog"],
        env: &[],
        fds: &[],
        cwd: None,
        session: Session::Group,
        suspended: false,
    })
    .unwrap()
    .reap()
    .unwrap()
    .code();
    assert_eq!(by_path, Some(1), "the control: the file itself changed");
}

/// The precondition of D-36 on Linux (CR-1): a process that made itself
/// non-dumpable, as EnvCloak's CLI and bridge do first thing
/// (`envcloak_sys::harden_process`), hides its executable from another
/// process of the same user (`/proc/<pid>/exe` refuses both `readlink`
/// and `open`), while one that did not is readable. So no release can rest
/// on reading a requester's executable. Both are copies of this test
/// binary, one hardened ([`hardened_helper`]) and one not.
#[cfg(target_os = "linux")]
#[test]
fn a_hardened_process_hides_its_executable_and_a_control_does_not() {
    use std::io::BufRead;

    let start = |harden: &str| {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hardened_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ENVCLOAK_TEST_HARDEN_HELPER", harden)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while out.read_line(&mut line).unwrap() > 0 && !line.contains("helper ready") {
            line.clear();
        }
        assert!(line.contains("helper ready"), "the helper did not start");
        (child, out)
    };
    let probe = |pid: u32| -> (Result<(), Option<i32>>, Result<(), Option<i32>>) {
        let link = std::fs::read_link(format!("/proc/{pid}/exe"));
        let open = std::fs::File::open(format!("/proc/{pid}/exe"));
        (
            link.map(|_| ()).map_err(|e| e.raw_os_error()),
            open.map(|_| ()).map_err(|e| e.raw_os_error()),
        )
    };
    let (mut hardened, _h) = start("hardened");
    let (mut control, _c) = start("control");
    let (link, open) = probe(hardened.id());
    let (clink, copen) = probe(control.id());
    let _ = hardened.kill();
    let _ = hardened.wait();
    let _ = control.kill();
    let _ = control.wait();
    let refused = |e: &Result<(), Option<i32>>| matches!(e, Err(Some(libc::EACCES | libc::EPERM)));
    assert!(
        refused(&link),
        "readlink of a hardened process's exe: {link:?}"
    );
    assert!(refused(&open), "open of a hardened process's exe: {open:?}");
    assert!(
        clink.is_ok() && copen.is_ok(),
        "the control is readable: {clink:?} {copen:?}"
    );
}

/// Not a test of its own: with `ENVCLOAK_TEST_HARDEN_HELPER` set, the copy
/// of this binary [`a_hardened_process_hides_its_executable_and_a_control_does_not`]
/// starts makes itself non-dumpable (`hardened`) or not (`control`), says
/// so, and waits to be killed.
#[test]
fn hardened_helper() {
    let Ok(mode) = std::env::var("ENVCLOAK_TEST_HARDEN_HELPER") else {
        return;
    };
    if mode == "hardened" {
        let _ = envcloak_sys::harden_process();
    }
    println!("helper ready");
    std::thread::sleep(std::time::Duration::from_secs(60));
}

/// D-34: stopping the group of a child that has already exited (unreaped,
/// so its group's number is still its own) is no error, on both systems,
/// though macOS answers `EPERM` to `killpg` of a group whose members are
/// all zombies; a member the child left in its group is stopped. The
/// runner stops a server's group whether or not the server exited first,
/// so a server that exits on its own must not read as a failed run.
///
/// Mutation checked: `stop_group` quiet on `ESRCH` only (as before): on
/// macOS the stop of the exited child's group fails with `EPERM`, and this
/// fails.
#[test]
fn stopping_an_exited_childs_group_is_no_error() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("left");
    let script = format!(
        "sleep 60 </dev/null >/dev/null 2>&1 & echo $! > '{}'; exit 0",
        pidfile.display()
    );
    let start = |line: &str| {
        spawn(&Spawn {
            program: Program::Path(b"/bin/sh"),
            argv: &[b"sh", b"-c", line.as_bytes()],
            env: &[],
            fds: &[],
            cwd: None,
            session: Session::Group,
            suspended: false,
        })
        .unwrap()
    };
    // Alone in its group.
    let child = start("exit 0");
    child.wait_exit().unwrap();
    assert!(child.stop_group(std::time::Duration::from_secs(5)).unwrap());
    assert_eq!(child.reap().unwrap().code(), Some(0));
    // With a member it left behind: stopped too.
    let child = start(&script);
    child.wait_exit().unwrap();
    let left: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        envcloak_sys::proc_info(left).is_ok(),
        "the member is not running"
    );
    assert!(child.stop_group(std::time::Duration::from_secs(5)).unwrap());
    assert_eq!(child.reap().unwrap().code(), Some(0));
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while envcloak_sys::proc_info(left).is_ok_and(|p| p.comm == "sleep") {
        assert!(
            std::time::Instant::now() < end,
            "the member outlived the stop"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Every descriptor that is not handed over is closed in the child, also
/// below the highest number handed over, and a directory descriptor
/// numbered as a target is still the directory the child starts in. Run
/// in a copy of this binary ([`launch_isolation_helper`]) started by a
/// shell that leaves its descriptor 5 open without close-on-exec, so the
/// numbers are known: the helper hands over only a pipe at 7 (a sparse
/// mapping, with 5 below it), then a pipe at the number its directory's
/// descriptor has.
///
/// Mutations checked (Linux, in a container): the child closing only from
/// above its own descriptors up (`close_from(keep_to + 1)`, the previous
/// rule): the child has 0, 1, 2 and 5 open beside 7, and this fails; the
/// child changing directory through the directory's unmoved number: the
/// pipe filled that number first, the start fails, and this fails. On
/// macOS the directory's descriptor is moved above the targets too, but
/// macOS 26.4 already changes to the directory the parent named (measured:
/// with that move removed this still passes); the move stays because the
/// order of file actions is not documented, and this test holds the
/// guarantee there.
#[test]
fn only_handed_descriptors_reach_the_child_and_the_directory_survives_a_collision() {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "exec 5</dev/null; exec \"$0\" --exact launch_isolation_helper --nocapture \
             --test-threads=1",
            exe.to_str().unwrap(),
        ])
        .env("ENVCLOAK_TEST_LAUNCH_HELPER", "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The positive control: the helper's own descriptor 5 is open, so a
    // child that kept it would show it.
    assert!(text.contains("helper fd5 open\n"), "{text}");
    assert!(text.contains("child fds: 7\n"), "{text}");
    assert!(text.contains("child cwd ok\n"), "{text}");
}

/// Not a test of its own: with `ENVCLOAK_TEST_LAUNCH_HELPER` set, the copy
/// of this binary
/// [`only_handed_descriptors_reach_the_child_and_the_directory_survives_a_collision`]
/// starts.
#[test]
fn launch_isolation_helper() {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    if std::env::var_os("ENVCLOAK_TEST_LAUNCH_HELPER").is_none() {
        return;
    }
    if std::path::Path::new("/dev/fd/5").exists() {
        println!("helper fd5 open");
    }
    // A sparse mapping: only 7, with the inherited 5 below it.
    let (r, w) = std::io::pipe().unwrap();
    let child = spawn(&Spawn {
        program: Program::Path(b"/bin/sh"),
        argv: &[
            b"sh",
            b"-c",
            b"open=''; for n in 0 1 2 3 4 5 6 7 8 9; do \
              if [ -e /dev/fd/$n ]; then open=\"$open $n\"; fi; done; \
              echo \"child fds:$open\" >&7",
        ],
        env: &[],
        fds: &[(w.as_fd(), 7)],
        cwd: None,
        session: Session::Group,
        suspended: false,
    })
    .unwrap();
    drop(w);
    let mut got = String::new();
    std::fs::File::from(std::os::fd::OwnedFd::from(r))
        .read_to_string(&mut got)
        .unwrap();
    assert!(child.reap().unwrap().success());
    print!("{got}");
    // The directory's descriptor numbered as a target.
    let dir = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(dir.path()).unwrap();
    let d = std::fs::File::open(&canonical).unwrap();
    let at = d.as_raw_fd();
    assert!(at <= envcloak_sys::launch::MAX_TARGET_FD, "{at}");
    let (r, w) = std::io::pipe().unwrap();
    let line = format!("pwd -P >&{at}");
    let child = spawn(&Spawn {
        program: Program::Path(b"/bin/sh"),
        argv: &[b"sh", b"-c", line.as_bytes()],
        env: &[],
        fds: &[(w.as_fd(), at)],
        cwd: Some(d.as_fd()),
        session: Session::Group,
        suspended: false,
    })
    .unwrap();
    drop(w);
    let mut got = String::new();
    std::fs::File::from(std::os::fd::OwnedFd::from(r))
        .read_to_string(&mut got)
        .unwrap();
    assert!(child.reap().unwrap().success());
    if got.trim_end() == canonical.to_str().unwrap() {
        println!("child cwd ok");
    }
}
