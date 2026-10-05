//! Descriptors named by number (SPEC §5 "Unlockers": the Recovery Kit is
//! written only to the terminal or to a file descriptor the user named;
//! "Unlock flow": the passphrase comes from stdin or another descriptor
//! only with an explicit `--passphrase-fd`).

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A new descriptor for the open file that the inherited descriptor `n`
/// refers to, made with `fcntl` and `F_DUPFD_CLOEXEC`, so it has the
/// close-on-exec flag. The original stays open and untouched; dropping the
/// copy closes only the copy.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a negative number, and `EBADF`
/// when `n` is not an open descriptor.
pub fn inherited_fd(n: i32) -> io::Result<OwnedFd> {
    if n < 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // The copy gets a number above the standard streams.
    // SAFETY: fcntl on any integer only reports EBADF for one that is not
    // open; F_DUPFD_CLOEXEC creates a new descriptor this process owns.
    let fd = unsafe { libc::fcntl(n, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether `fd` has the close-on-exec flag set.
///
/// # Errors
/// When `fcntl` fails.
pub fn cloexec_flag(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: F_GETFD only reads the descriptor's flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}

/// The inherited descriptor `n` (3 or more), for this process to write
/// to, with no program it starts ever holding it: `envcloak run
/// --status-fd N` takes its status channel so before it starts anything.
/// The close-on-exec flag is set on `n` itself, and the result is a copy
/// of it made with `F_DUPFD_CLOEXEC` ([`inherited_fd`]), which this
/// process owns alone; `n` stays open, closed on exec, until the process
/// exits. A safe function cannot take ownership of a number something
/// else may own (a `File` the caller holds, say): two owners would each
/// close it, the second closing whatever reused the number (Codex review
/// of M2-RES1). Setting the flag changes no ownership.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a number under 3 (the standard
/// streams are never taken), and `EBADF` when `n` is not open.
pub fn claim_inherited_fd(n: i32) -> io::Result<OwnedFd> {
    if n < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: fcntl on any integer only reports EBADF for one that is not
    // open; F_GETFD reads its flags.
    let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above; F_SETFD changes only this descriptor's flags, and
    // no handle in this process gains or loses ownership.
    if unsafe { libc::fcntl(n, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    inherited_fd(n)
}

/// A new pipe, both ends close-on-exec: `(read, write)`. On Linux the
/// flag is set as the pipe is made (`pipe2`); elsewhere just after, so a
/// caller that starts children on other threads holds its own lock across
/// this and its spawns, as `envcloak mcp` does.
///
/// # Errors
/// When `pipe` or `fcntl` fails (out of descriptors).
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: `fds` is a writable array of two ints, as pipe2 requires.
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    // SAFETY: `fds` is a writable array of two ints, as pipe requires.
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just made by the kernel and nothing
    // else owns them.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    for fd in [&read, &write] {
        // SAFETY: F_SETFD on a descriptor owned here.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

/// Where this process's open descriptors are listed: one entry, named by
/// its number, for each (on Linux a link to `/proc/self/fd`).
const FD_DIR: &str = "/dev/fd";

/// Sets the close-on-exec flag on every descriptor of this process above
/// `min`, so that no program it starts from here on inherits one it did
/// not hand over itself (the standard streams a spawn sets up are not
/// touched). Returns how many had the flag off. The open descriptors are
/// read from `/dev/fd`, which lists every one, whatever its number.
///
/// # Errors
/// When the descriptors cannot all be listed: `/dev/fd` cannot be read,
/// one of its entries cannot be, or one is not a descriptor number. A
/// sweep that cannot see every descriptor fails rather than leave one
/// open on exec (Codex review of M2-RES1: it then tried the numbers up to
/// the soft `RLIMIT_NOFILE`, at most 65,536, and reported success, while a
/// descriptor above a limit lowered after it was opened stayed open).
/// Also when a descriptor's flags cannot be read or set, other than one
/// closed meanwhile (the listing's own).
pub fn close_on_exec_above(min: i32) -> io::Result<usize> {
    // A test build can make the listing fail here, as an unreadable
    // `/dev/fd` would.
    let listed = crate::fail_point("sys.fd.listing")
        .and_then(|()| open_fds_in(std::path::Path::new(FD_DIR)));
    close_on_exec_listed(listed?.into_iter().filter(|n| *n > min))
}

/// The descriptor numbers listed in `dir`, every entry read or an error.
fn open_fds_in(dir: &std::path::Path) -> io::Result<Vec<i32>> {
    let mut numbers = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let n = name
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|n| *n >= 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an entry of the descriptor listing is not a descriptor number",
                )
            })?;
        numbers.push(n);
    }
    Ok(numbers)
}

/// Sets the close-on-exec flag on each of `numbers` that is open: see
/// [`close_on_exec_above`].
fn close_on_exec_listed(numbers: impl Iterator<Item = i32>) -> io::Result<usize> {
    let mut changed = 0;
    for n in numbers {
        // SAFETY: F_GETFD on any integer only reads flags or reports EBADF.
        let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
        if flags < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(e);
        }
        if flags & libc::FD_CLOEXEC != 0 {
            continue;
        }
        // SAFETY: F_SETFD changes only this open descriptor's flags; no
        // handle in this process gains or loses ownership.
        if unsafe { libc::fcntl(n, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        changed += 1;
    }
    Ok(changed)
}

/// Makes `cmd`'s child have the open file `fd` refers to now at `fd`'s
/// number when it starts its program, and no other child started
/// meanwhile get it. `cmd` keeps its own copy, made now with
/// `F_DUPFD_CLOEXEC` and closed with `cmd`; in the child only, after the
/// fork, `dup2` puts that copy at `fd`'s number without the close-on-exec
/// flag. So the child gets this file whatever becomes of the number here
/// before the spawn: a hook that cleared the flag on the number itself
/// used it after the borrow ended, and would have handed the child
/// whatever descriptor reused it (the class of Codex's review of
/// M2-RES1). The caller passes the number to the child (`envcloak run
/// --status-fd N`). `cmd` holds its copy until it is dropped: a reader
/// waiting for the end of the file waits for that too.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a standard stream's number, which
/// the spawn sets up itself; and when the copy cannot be made.
pub fn inherit_on_spawn(cmd: &mut std::process::Command, fd: BorrowedFd<'_>) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let n = fd.as_raw_fd();
    if n < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let copy = inherited_fd(n)?;
    let keep = move || {
        let m = copy.as_raw_fd();
        if m == n {
            // SAFETY: F_GETFD and F_SETFD on `copy`, open in the child (the
            // fork copied it); fcntl is async-signal-safe.
            let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
            // SAFETY: as above.
            if flags < 0 || unsafe { libc::fcntl(n, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        // SAFETY: dup2 from `copy`, open in the child, onto `n`, closing in
        // the child only whatever had that number there; the new
        // descriptor has no close-on-exec flag. dup2 is async-signal-safe,
        // and nothing here allocates or takes a lock.
        if unsafe { libc::dup2(m, n) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: the closure runs in the child after the fork and before its
    // program starts, where a child forked from a threaded parent may call
    // only async-signal-safe functions: it calls `dup2` or `fcntl` on
    // descriptors the fork copied, and `last_os_error` only reads errno.
    unsafe { cmd.pre_exec(keep) };
    Ok(())
}

/// Sets a child's working directory from an owned copy of an open directory.
/// A path rename or descriptor reuse before spawn cannot redirect the child.
///
/// # Errors
/// The descriptor cannot be copied. A non-directory is refused at spawn.
pub fn chdir_on_spawn(cmd: &mut std::process::Command, dir: &std::fs::File) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let copy = inherited_fd(dir.as_raw_fd())?;
    // SAFETY: the closure owns the copied descriptor until exec. fchdir is
    // async-signal-safe, and last_os_error only reads errno. Nothing here
    // allocates, locks, or changes the parent's working directory.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fchdir(copy.as_raw_fd()) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// Clears the close-on-exec flag on `fd`, as an inherited descriptor
    /// arrives.
    fn inheritable(fd: BorrowedFd<'_>) {
        // SAFETY: F_GETFD and F_SETFD on a descriptor the test owns.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        // SAFETY: as above.
        let r = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        assert_eq!(r, 0);
    }

    /// Held by each test that sweeps the process's descriptors, clears a
    /// flag and reads it back, or starts a child: a sweep sets the flag on
    /// every other test's descriptors too, and a child started while
    /// another test's descriptor has the flag cleared would hold it.
    static SWEEPING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn sweeping() -> std::sync::MutexGuard<'static, ()> {
        SWEEPING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every descriptor above the floor gets the flag, and those at or
    /// under it keep theirs.
    ///
    /// Mutation checked: the sweep taking no number from the listing: the
    /// inheritable pipe keeps its flag off and this fails.
    #[test]
    fn every_descriptor_above_the_floor_is_closed_on_exec() {
        let _sweeping = sweeping();
        let (r, w) = pipe_cloexec().unwrap();
        inheritable(r.as_fd());
        inheritable(w.as_fd());
        let (low, high) = if r.as_fd().as_raw_fd() < w.as_fd().as_raw_fd() {
            (r.as_fd(), w.as_fd())
        } else {
            (w.as_fd(), r.as_fd())
        };
        // At the floor and under it: untouched.
        close_on_exec_above(high.as_raw_fd()).unwrap();
        assert!(!cloexec_flag(high).unwrap());
        assert!(!cloexec_flag(low).unwrap());
        assert!(close_on_exec_above(low.as_raw_fd() - 1).unwrap() >= 2);
        assert!(cloexec_flag(high).unwrap());
        assert!(cloexec_flag(low).unwrap());
    }

    /// A sweep that cannot list every descriptor fails, whatever it could
    /// have tried: a listing that cannot be read, and one with an entry
    /// that is not a descriptor number, are errors, never a guess at the
    /// numbers (Codex review of M2-RES1).
    ///
    /// Mutation checked: an unreadable listing replaced by the numbers up
    /// to the soft limit, at most 65,536, as before: the sweep reports
    /// success and this fails.
    #[test]
    fn a_sweep_that_cannot_list_the_descriptors_fails() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_fds_in(&dir.path().join("missing")).is_err());
        std::fs::write(dir.path().join("3"), b"").unwrap();
        assert_eq!(open_fds_in(dir.path()).unwrap(), vec![3]);
        std::fs::write(dir.path().join("not-a-number"), b"").unwrap();
        assert_eq!(
            open_fds_in(dir.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// A descriptor above the soft `RLIMIT_NOFILE`, opened before the
    /// limit was lowered, is found by the listing and closed on exec: the
    /// numbers up to the limit, which the sweep once fell back to, would
    /// miss it. Skipped (with a line) where the hard limit is too low to
    /// open one so high.
    ///
    /// Mutation checked: the sweep taking the numbers up to the soft limit
    /// in place of the listing: the high descriptor keeps its flag off and
    /// this fails.
    #[test]
    fn a_descriptor_above_the_soft_limit_is_closed_on_exec() {
        const HIGH: i32 = 6000;
        let _sweeping = sweeping();
        // SAFETY: rlimit is plain data, for which all zeros is valid.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: a valid resource and a writable rlimit.
        let got = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) };
        assert_eq!(got, 0);
        let need = libc::rlim_t::try_from(HIGH).unwrap() + 1;
        if lim.rlim_max < need {
            eprintln!("skipped: the hard RLIMIT_NOFILE is under {need}");
            return;
        }
        let set = |cur: libc::rlim_t| {
            let l = libc::rlimit {
                rlim_cur: cur,
                rlim_max: lim.rlim_max,
            };
            // SAFETY: a valid resource and an rlimit within the hard limit.
            let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const l) };
            assert_eq!(set, 0);
        };
        set(lim.rlim_cur.max(need));
        let (_r, w) = pipe_cloexec().unwrap();
        // SAFETY: dup2 onto a number no other test uses; the copy is owned
        // below and closed with it.
        let n = unsafe { libc::dup2(w.as_raw_fd(), HIGH) };
        assert_eq!(n, HIGH);
        // SAFETY: `HIGH` was just made by dup2 and nothing else owns it.
        let high = unsafe { OwnedFd::from_raw_fd(HIGH) };
        inheritable(high.as_fd());
        // The limit back under the descriptor, as a parent that lowered it
        // after opening the descriptor leaves it.
        set(lim
            .rlim_cur
            .min(libc::rlim_t::try_from(HIGH).unwrap() - 1000));
        assert!(!cloexec_flag(high.as_fd()).unwrap());
        // Above every other descriptor this process has: only `HIGH`.
        let swept = close_on_exec_above(HIGH - 1);
        set(lim.rlim_cur);
        assert_eq!(swept.unwrap(), 1);
        assert!(cloexec_flag(high.as_fd()).unwrap());
    }

    /// A claimed descriptor is a copy this process owns alone, both it and
    /// the inherited number closed on exec: dropping the copy leaves the
    /// number open for whatever else owns it (Codex review of M2-RES1: the
    /// claim took ownership of the number itself, so a safe caller holding
    /// it as a `File` had two owners, and the first drop closed the
    /// other's descriptor). A standard stream's number and one that is not
    /// open are refused.
    ///
    /// Mutation checked: the claim taking `n` itself as its result, as
    /// before (`OwnedFd::from_raw_fd(n)`): dropping it closes the pipe's
    /// only write end, the reader sees its end and this fails.
    #[test]
    fn a_claimed_descriptor_is_a_copy_and_both_close_on_exec() {
        let _sweeping = sweeping();
        let (r, w) = pipe_cloexec().unwrap();
        inheritable(w.as_fd());
        // The caller's own handle on the number, as a `File`; never closed
        // twice, whatever the claim does.
        let held = std::mem::ManuallyDrop::new(std::fs::File::from(w));
        let n = held.as_raw_fd();
        let claimed = claim_inherited_fd(n).unwrap();
        assert_ne!(claimed.as_raw_fd(), n);
        assert!(cloexec_flag(claimed.as_fd()).unwrap());
        drop(claimed);
        // The number is still open, its flag set, and still the pipe's
        // write end: the reader has no end of input yet.
        let mut reader = std::fs::File::from(r);
        // SAFETY: F_GETFL and F_SETFL on the read end this test owns.
        let fl = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above.
        let set = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK) };
        assert_eq!(set, 0);
        let mut buf = [0u8; 1];
        let pending = std::io::Read::read(&mut reader, &mut buf);
        assert_eq!(
            pending.map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock),
            "the inherited number was closed with the copy"
        );
        assert!(cloexec_flag(held.as_fd()).unwrap());
        drop(std::mem::ManuallyDrop::into_inner(held));
        assert_eq!(std::io::Read::read(&mut reader, &mut buf).unwrap(), 0);
        assert_eq!(
            claim_inherited_fd(2).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // A number no descriptor has (another test may reuse `n` by now).
        assert_eq!(
            claim_inherited_fd(1 << 20).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    /// A child keeps the descriptor it is handed, at its number, while
    /// this process's copy keeps its flag; without the hand-over the child
    /// has nothing there; and when the number is closed here and given to
    /// another file before the spawn, the child still gets the file it was
    /// handed, never the other.
    ///
    /// Mutations checked: the hook not clearing the flag: the child's write
    /// fails and this fails. The hook clearing the flag on the number in
    /// the child, as before, in place of its own copy: the child writes
    /// into the file that reused the number and this fails.
    #[test]
    fn a_child_keeps_the_descriptor_it_is_handed() {
        let _sweeping = sweeping();
        for handed in [true, false] {
            let (r, w) = pipe_cloexec().unwrap();
            let n = w.as_fd().as_raw_fd();
            let mut cmd = std::process::Command::new("/bin/sh");
            cmd.arg("-c")
                .arg(format!("echo kept >&{n}"))
                .stderr(std::process::Stdio::null());
            if handed {
                inherit_on_spawn(&mut cmd, w.as_fd()).unwrap();
            }
            let status = cmd.status().unwrap();
            assert!(cloexec_flag(w.as_fd()).unwrap());
            // `cmd` holds its copy of the write end until it goes.
            drop(cmd);
            drop(w);
            let mut got = String::new();
            std::io::Read::read_to_string(&mut std::fs::File::from(r), &mut got).unwrap();
            assert_eq!(status.success(), handed, "handed {handed}");
            assert_eq!(got, if handed { "kept\n" } else { "" }, "handed {handed}");
        }
        // The number closed here, and given to another file, before the
        // spawn: the child still gets the file it was handed there.
        let (r, w) = pipe_cloexec().unwrap();
        let n = w.as_fd().as_raw_fd();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("echo kept >&{n}"))
            .stderr(std::process::Stdio::null());
        inherit_on_spawn(&mut cmd, w.as_fd()).unwrap();
        drop(w);
        // SAFETY: dup2 of this test's own read end onto the number just
        // closed; the copy is owned below.
        assert_eq!(unsafe { libc::dup2(r.as_raw_fd(), n) }, n);
        // SAFETY: `n` was just made by dup2 and nothing else owns it.
        let reused = unsafe { OwnedFd::from_raw_fd(n) };
        inheritable(reused.as_fd());
        let status = cmd.status().unwrap();
        drop(cmd);
        drop(reused);
        let mut got = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::from(r), &mut got).unwrap();
        assert!(status.success());
        assert_eq!(got, "kept\n", "the child got what reused the number");
        let mut cmd = std::process::Command::new("/bin/sh");
        assert_eq!(
            inherit_on_spawn(&mut cmd, std::io::stderr().as_fd())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
