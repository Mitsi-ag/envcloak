//! The descriptors of `envcloak run --pty`'s relay (SPEC §6.1 steps 7 and
//! 8; M2 plan task M2-19): the outer terminal, the PTY's master side, the
//! monitor's control channel and the signal relay, waited on together by
//! one thread.
//!
//! - [`reopen_terminal`]: the outer terminal opened again by its name, so
//!   the relay has a description of its own that it may make
//!   non-blocking. The descriptor it inherited shares its description
//!   (and so its `O_NONBLOCK` flag) with the person's shell, which reads
//!   the terminal again whenever the run is suspended or ends: a flag set
//!   there would make the shell's reads fail with `EAGAIN`.
//! - [`set_nonblocking`]: for a descriptor the relay owns alone (the
//!   PTY's master side).
//! - [`wait_any`]: `poll` on several descriptors at once.

use std::ffi::c_char;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// Opens the terminal `fd` is on again, by the name `ttyname_r` gives it,
/// with a description of its own: read and write, non-blocking,
/// close-on-exec, and never as this process's controlling terminal
/// (`O_NOCTTY`). The descriptor opened is checked to be the same terminal
/// (a character device with the same device number), so a name that came
/// to point elsewhere meanwhile is refused.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when `fd` is not a terminal or the name
/// opened is another device; `ttyname_r`'s, `open`'s and `fstat`'s errors.
pub fn reopen_terminal(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let mut name = [0 as c_char; 256];
    // SAFETY: `name` is writable for its length; ttyname_r writes a
    // NUL-terminated path into it, or fails without effect.
    let rc = unsafe { libc::ttyname_r(fd.as_raw_fd(), name.as_mut_ptr(), name.len()) };
    if rc != 0 {
        return Err(if rc == libc::ENOTTY {
            io::ErrorKind::InvalidInput.into()
        } else {
            io::Error::from_raw_os_error(rc)
        });
    }
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    // SAFETY: `name` holds a NUL-terminated path.
    let opened = unsafe { libc::open(name.as_ptr(), flags) };
    if opened < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open just created `opened`; nothing else owns it.
    let opened = unsafe { OwnedFd::from_raw_fd(opened) };
    let (was, now) = (device_of(fd.as_raw_fd())?, device_of(opened.as_raw_fd())?);
    if was.is_none() || was != now {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(opened)
}

/// The device number of the character device `fd` is open on, or `None`
/// for anything else.
fn device_of(fd: libc::c_int) -> io::Result<Option<libc::dev_t>> {
    // SAFETY: stat is plain data; fstat fills it in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is writable; on a closed descriptor fstat fails.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.st_mode & libc::S_IFMT == libc::S_IFCHR).then_some(st.st_rdev))
}

/// Sets `O_NONBLOCK` on `fd`'s description: a read with nothing to read,
/// and a write with no room, fail with [`io::ErrorKind::WouldBlock`]
/// rather than wait. Only for a description this process holds alone.
///
/// # Errors
/// `fcntl`'s errors.
pub fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_GETFL reads the description's flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL with the flags just read plus O_NONBLOCK.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a descriptor showed to [`wait_any`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Readiness {
    /// It can be read without waiting (data, or the end of it).
    pub readable: bool,
    /// It can be written without waiting.
    pub writable: bool,
    /// Its other side is gone (`POLLHUP`): a terminal hung up, a channel
    /// whose peer closed, a PTY master whose slave side no process holds.
    pub hung_up: bool,
    /// An error is pending on it, or it is not open (`POLLERR`,
    /// `POLLNVAL`).
    pub failed: bool,
}

impl Readiness {
    /// Whether anything at all was shown.
    pub fn any(&self) -> bool {
        self.readable || self.writable || self.hung_up || self.failed
    }
}

/// Waits at most `timeout` (`None`: until something happens) for one of
/// `fds` to be ready: each entry is a descriptor (or `None`, which is
/// passed over) and whether it is waited for to read and to write; a hang
/// up or an error is reported beside what was asked (Linux reports them
/// also to an entry that asks for nothing; macOS may not, so an entry
/// that must see its other side go asks to read). Returns what each
/// showed, in order. A signal handled meanwhile (`EINTR`) ends the wait
/// with nothing shown, so a caller that reads its signals after each wait
/// sees them at once. A timeout under a millisecond waits a whole one,
/// so a caller looping until a deadline does not spin.
///
/// # Errors
/// `poll`'s errors other than `EINTR`.
pub fn wait_any(
    fds: &[(Option<BorrowedFd<'_>>, bool, bool)],
    timeout: Option<Duration>,
) -> io::Result<Vec<Readiness>> {
    let mut polled: Vec<libc::pollfd> = fds
        .iter()
        .map(|(fd, read, write)| libc::pollfd {
            fd: fd.map_or(-1, |f| f.as_raw_fd()),
            events: (if *read { libc::POLLIN } else { 0 })
                | (if *write { libc::POLLOUT } else { 0 }),
            revents: 0,
        })
        .collect();
    let ms = match timeout {
        None => -1,
        Some(t) => {
            let whole = t.as_millis() + u128::from(t.subsec_nanos() % 1_000_000 != 0);
            libc::c_int::try_from(whole).unwrap_or(libc::c_int::MAX)
        }
    };
    let n = libc::nfds_t::try_from(polled.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `polled` holds `n` initialized pollfds; a negative descriptor
    // is ignored by poll, and the others stay open for the call.
    let rc = unsafe { libc::poll(polled.as_mut_ptr(), n, ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
        return Ok(vec![Readiness::default(); polled.len()]);
    }
    Ok(polled
        .iter()
        .map(|p| Readiness {
            readable: p.revents & libc::POLLIN != 0,
            writable: p.revents & libc::POLLOUT != 0,
            hung_up: p.revents & libc::POLLHUP != 0,
            failed: p.revents & (libc::POLLERR | libc::POLLNVAL) != 0,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn a_descriptor_that_is_not_a_terminal_is_not_reopened() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            reopen_terminal(f.as_fd()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_pty_is_reopened_as_itself_and_non_blocking() {
        let pty = crate::pty::open_pty(None, None).unwrap();
        let again = reopen_terminal(pty.slave.as_fd()).unwrap();
        assert_eq!(
            device_of(again.as_raw_fd()).unwrap(),
            device_of(pty.slave.as_raw_fd()).unwrap()
        );
        // Its own description: non-blocking there, and only there.
        // SAFETY: F_GETFL reads a descriptor's flags.
        let (mine, theirs) = unsafe {
            (
                libc::fcntl(again.as_raw_fd(), libc::F_GETFL),
                libc::fcntl(pty.slave.as_raw_fd(), libc::F_GETFL),
            )
        };
        assert_ne!(mine & libc::O_NONBLOCK, 0);
        assert_eq!(theirs & libc::O_NONBLOCK, 0);
        let mut buf = [0u8; 8];
        let mut f = std::fs::File::from(again);
        let read = std::io::Read::read(&mut f, &mut buf);
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn wait_any_reports_each_descriptor_and_passes_over_none() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let shown = wait_any(
            &[(Some(a.as_fd()), true, false), (None, true, true)],
            Some(Duration::from_millis(1)),
        )
        .unwrap();
        assert_eq!(shown, vec![Readiness::default(); 2]);
        std::io::Write::write_all(&mut &b, b"x").unwrap();
        let shown = wait_any(&[(Some(a.as_fd()), true, true)], None).unwrap();
        assert!(shown[0].readable && shown[0].writable, "{shown:?}");
        // The other end gone: shown to a reader, as the end of the stream
        // or a hang-up (macOS reports a socket's hang-up only to a wait
        // that asks for something; measured on macOS 26.4).
        let mut buf = [0u8; 8];
        std::io::Read::read(&mut &a, &mut buf).unwrap();
        drop(b);
        let shown = wait_any(
            &[(Some(a.as_fd()), true, false)],
            Some(Duration::from_secs(20)),
        )
        .unwrap();
        assert!(shown[0].readable || shown[0].hung_up, "{shown:?}");
    }
}
