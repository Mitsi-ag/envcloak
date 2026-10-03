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

/// Takes the inherited descriptor `n` (3 or more) as this process's own,
/// with the close-on-exec flag set on it first, so that no program this
/// process starts inherits it: `envcloak run --status-fd N` takes its
/// status channel so before it starts anything. Unlike [`inherited_fd`]
/// no copy is made, and `n` itself is closed when the result is dropped.
/// Nothing else in the process may own `n`: the caller takes it before it
/// opens anything.
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
    // SAFETY: as above; F_SETFD changes only this descriptor's flags.
    if unsafe { libc::fcntl(n, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `n` is open, and the caller owns no other handle to it (see
    // above), so the result is its only owner.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
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

/// The most descriptor numbers [`close_on_exec_above`] tries when it
/// cannot list `/dev/fd`.
pub const MAX_SWEEP: libc::rlim_t = 1 << 16;

/// Sets the close-on-exec flag on every descriptor of this process above
/// `min`, so that no program it starts from here on inherits one it did
/// not hand over itself (the standard streams a spawn sets up are not
/// touched). Returns how many had the flag off. The open descriptors are
/// read from `/dev/fd`; where that cannot be listed, every number up to
/// the soft `RLIMIT_NOFILE`, at most [`MAX_SWEEP`], is tried.
///
/// # Errors
/// When a descriptor's flags cannot be read or set, other than one closed
/// meanwhile (the listing's own).
pub fn close_on_exec_above(min: i32) -> io::Result<usize> {
    let numbers: Vec<i32> = match std::fs::read_dir("/dev/fd") {
        Ok(dir) => dir
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
            .filter(|n| *n > min)
            .collect(),
        Err(_) => {
            // SAFETY: rlimit is plain data, for which all zeros is valid.
            let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
            // SAFETY: a valid resource and a writable rlimit.
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let top = i32::try_from(lim.rlim_cur.min(MAX_SWEEP)).unwrap_or(i32::MAX);
            (min.saturating_add(1)..top).collect()
        }
    };
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

/// Makes `cmd`'s child keep `fd`, at the same number, when it starts its
/// program: the close-on-exec flag is cleared on that number in the child
/// only, after the fork, so this process's copy keeps the flag and no
/// other child started meanwhile gets the descriptor. The caller keeps
/// `fd` open until the spawn returns, and passes its number to the child
/// (`envcloak run --status-fd N`).
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a standard stream's number, which
/// the spawn sets up itself.
pub fn inherit_on_spawn(cmd: &mut std::process::Command, fd: BorrowedFd<'_>) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    let n = fd.as_raw_fd();
    if n < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let keep = move || {
        // SAFETY: F_GETFD and F_SETFD on a number open in the child (the
        // fork copied it); fcntl is async-signal-safe, and nothing here
        // allocates or takes a lock.
        let flags = unsafe { libc::fcntl(n, libc::F_GETFD) };
        // SAFETY: as above.
        if flags < 0 || unsafe { libc::fcntl(n, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: the closure runs in the child after the fork and before its
    // program starts, where a child forked from a threaded parent may call
    // only async-signal-safe functions: it calls `fcntl` twice on a number
    // copied before the fork, and `last_os_error` only reads errno.
    unsafe { cmd.pre_exec(keep) };
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

    /// Every descriptor above the floor gets the flag, and those at or
    /// under it keep theirs.
    ///
    /// Mutation checked: the sweep taking no number from the listing: the
    /// inheritable pipe keeps its flag off and this fails.
    #[test]
    fn every_descriptor_above_the_floor_is_closed_on_exec() {
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

    /// A claimed descriptor gets the flag and is closed with its owner; a
    /// standard stream's number and one that is not open are refused.
    #[test]
    fn a_claimed_descriptor_is_closed_on_exec_and_owned() {
        use std::os::fd::IntoRawFd;
        let (r, w) = pipe_cloexec().unwrap();
        inheritable(w.as_fd());
        let n = w.into_raw_fd();
        let owned = claim_inherited_fd(n).unwrap();
        assert!(cloexec_flag(owned.as_fd()).unwrap());
        drop(owned);
        // Its only owner is gone: the reader sees the end at once.
        let mut buf = [0u8; 1];
        assert_eq!(
            std::io::Read::read(&mut std::fs::File::from(r), &mut buf).unwrap(),
            0
        );
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
    /// has nothing there.
    ///
    /// Mutation checked: the hook not clearing the flag: the child's write
    /// fails and this fails.
    #[test]
    fn a_child_keeps_the_descriptor_it_is_handed() {
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
            drop(w);
            let mut got = String::new();
            std::io::Read::read_to_string(&mut std::fs::File::from(r), &mut got).unwrap();
            assert_eq!(status.success(), handed, "handed {handed}");
            assert_eq!(got, if handed { "kept\n" } else { "" }, "handed {handed}");
        }
        let mut cmd = std::process::Command::new("/bin/sh");
        assert_eq!(
            inherit_on_spawn(&mut cmd, std::io::stderr().as_fd())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
