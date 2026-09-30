//! Terminal settings for typing a secret (SPEC §5 "Unlock flow": the
//! passphrase is read from `/dev/tty` with echo off).
//!
//! [`SecretInput::begin`] turns off echo, line editing, signal characters
//! and extended input processing on a terminal, so each keystroke reaches
//! the reader as a byte and nothing is shown. The reader handles Enter,
//! Backspace and Ctrl-C itself: with signal characters off, Ctrl-C is a
//! byte rather than a signal that would kill the process and leave the
//! terminal without echo. Input typed before the prompt is discarded. The
//! saved settings come back when the [`SecretInput`] is dropped, and input
//! still unread then is discarded too (`TCSAFLUSH`): it was typed with
//! echo off, so it may be the rest of a secret, and once echo is back on it
//! would show on the terminal and reach the next program to read it,
//! usually the shell. An entry that ends before Enter (Ctrl-C, Ctrl-D, a
//! secret too long) first calls [`SecretInput::discard_until_quiet`], so
//! the rest of a paste still arriving is discarded as well.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

/// A terminal in secret-input mode. Restores the previous settings on
/// drop.
pub struct SecretInput<'a> {
    fd: BorrowedFd<'a>,
    saved: libc::termios,
}

impl core::fmt::Debug for SecretInput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretInput").finish_non_exhaustive()
    }
}

fn get(fd: BorrowedFd<'_>) -> io::Result<libc::termios> {
    // SAFETY: termios is plain data; tcgetattr fills it in.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is a writable termios; the descriptor stays open.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(t)
}

fn set(fd: BorrowedFd<'_>, how: libc::c_int, t: &libc::termios) -> io::Result<()> {
    loop {
        // SAFETY: `t` is an initialized termios; the descriptor stays open.
        if unsafe { libc::tcsetattr(fd.as_raw_fd(), how, t) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

impl<'a> SecretInput<'a> {
    /// Puts the terminal `tty` into secret-input mode: no echo, no line
    /// editing, no signal characters, one byte per read, and pending input
    /// discarded.
    ///
    /// # Errors
    /// When `tty` is not a terminal or its settings cannot be changed.
    pub fn begin(tty: BorrowedFd<'a>) -> io::Result<Self> {
        let saved = get(tty)?;
        let mut raw = saved;
        raw.c_lflag &= !(libc::ECHO
            | libc::ECHOE
            | libc::ECHOK
            | libc::ECHONL
            | libc::ICANON
            | libc::ISIG
            | libc::IEXTEN);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        set(tty, libc::TCSAFLUSH, &raw)?;
        Ok(SecretInput { fd: tty, saved })
    }

    /// Whether the terminal's echo flag is off now, read back from the
    /// kernel.
    ///
    /// # Errors
    /// When the settings cannot be read.
    pub fn echo_off(&self) -> io::Result<bool> {
        Ok(get(self.fd)?.c_lflag & libc::ECHO == 0)
    }

    /// Reads and discards input until none has arrived for `quiet`
    /// (rounded up to tenths of a second, at most 25.5 seconds), or until
    /// `limit` has passed. The bytes read are wiped. Returns how many were
    /// discarded. For an entry that ends before Enter: what follows a
    /// Ctrl-C, or the rest of a paste over the length limit, which may still
    /// be arriving when the reader stops.
    ///
    /// # Errors
    /// When the terminal's settings cannot be changed, or reading fails for
    /// another reason than the terminal hanging up.
    pub fn discard_until_quiet(&self, quiet: Duration, limit: Duration) -> io::Result<usize> {
        let mut t = get(self.fd)?;
        let tenths = quiet.as_millis().div_ceil(100).clamp(1, 255);
        t.c_cc[libc::VMIN] = 0;
        t.c_cc[libc::VTIME] = libc::cc_t::try_from(tenths).unwrap_or(libc::cc_t::MAX);
        set(self.fd, libc::TCSANOW, &t)?;
        let end = Instant::now() + limit;
        let mut buf = [0u8; 256];
        let mut discarded = 0usize;
        let result = loop {
            if Instant::now() >= end {
                break Ok(discarded);
            }
            // SAFETY: `buf` is writable for its length; the descriptor stays
            // open for the call.
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            match usize::try_from(n) {
                // Quiet for the whole timer, or the terminal hung up.
                Ok(0) => break Ok(discarded),
                Ok(n) => discarded = discarded.saturating_add(n),
                Err(_) => {
                    let err = io::Error::last_os_error();
                    match err.kind() {
                        io::ErrorKind::Interrupted => {}
                        _ if err.raw_os_error() == Some(libc::EIO) => break Ok(discarded),
                        _ => break Err(err),
                    }
                }
            }
        };
        buf.zeroize();
        result
    }
}

/// Waits at most `timeout` for `fd` to have input to read, or to have hung
/// up. Returns whether it has. A signal handled meanwhile ends the wait
/// with an error of kind [`io::ErrorKind::Interrupted`].
///
/// A reader that must notice a signal recorded by a handler waits in
/// short steps with this rather than blocking in `read`: a signal that
/// arrives after the reader last looked and before `read` blocks
/// interrupts nothing, and the read would wait for a key.
///
/// # Errors
/// When `poll` fails, `EINTR` included.
pub fn wait_readable(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `p` is one initialized pollfd, and the descriptor stays open
    // for the call.
    let rc = unsafe { libc::poll(&mut p, 1, ms) };
    match rc {
        0 => Ok(false),
        n if n > 0 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Whether nothing can write to `fd` any more: every write end of the
/// pipe, or the socket's peer, is closed (`POLLHUP`), even while data
/// written before is still unread. The runner uses it to tell a pipe that
/// only has output left to deliver from one a descendant still holds.
///
/// # Errors
/// When `poll` fails, `EINTR` included.
pub fn hung_up(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `p` is one initialized pollfd, and the descriptor stays open
    // for the call; a zero timeout only looks.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(p.revents & libc::POLLHUP != 0)
}

/// Waits at most `timeout` for `fd` to accept a write without blocking, or
/// to have failed (the reader gone). Returns whether it has: the runner
/// uses it when its output descriptor was left non-blocking by whoever
/// opened it. A signal handled meanwhile ends the wait with an error of
/// kind [`io::ErrorKind::Interrupted`].
///
/// # Errors
/// When `poll` fails, `EINTR` included.
pub fn wait_writable(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `p` is one initialized pollfd, and the descriptor stays open
    // for the call.
    let rc = unsafe { libc::poll(&mut p, 1, ms) };
    match rc {
        0 => Ok(false),
        n if n > 0 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

impl Drop for SecretInput<'_> {
    fn drop(&mut self) {
        // TCSAFLUSH: input not read yet is discarded, not left for the next
        // reader with echo back on.
        let _ = set(self.fd, libc::TCSAFLUSH, &self.saved);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::{hung_up, wait_readable};

    #[test]
    fn waits_for_input_or_a_hang_up() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(!wait_readable(a.as_fd(), Duration::from_millis(50)).unwrap());
        assert!(start.elapsed() >= Duration::from_millis(40));
        b.write_all(b"x").unwrap();
        assert!(wait_readable(a.as_fd(), Duration::from_secs(5)).unwrap());
        let (c, d) = UnixStream::pair().unwrap();
        drop(d);
        assert!(wait_readable(c.as_fd(), Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn a_closed_writer_is_seen_while_data_is_unread() {
        let (a, mut b) = UnixStream::pair().unwrap();
        assert!(!hung_up(a.as_fd()).unwrap());
        b.write_all(b"x").unwrap();
        assert!(!hung_up(a.as_fd()).unwrap());
        drop(b);
        assert!(hung_up(a.as_fd()).unwrap());

        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors pipe returns.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe just created both descriptors, and nothing else owns
        // them.
        let (r, w) = unsafe {
            use std::os::fd::FromRawFd;
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        };
        (&w).write_all(b"x").unwrap();
        assert!(!hung_up(r.as_fd()).unwrap());
        let w2 = w.try_clone().unwrap();
        drop(w);
        assert!(
            !hung_up(r.as_fd()).unwrap(),
            "a second writer holds the pipe"
        );
        drop(w2);
        assert!(hung_up(r.as_fd()).unwrap());
    }
}
