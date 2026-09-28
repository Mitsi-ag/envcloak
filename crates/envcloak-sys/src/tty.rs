//! Terminal settings for typing a secret (SPEC §5 "Unlock flow": the
//! passphrase is read from `/dev/tty` with echo off).
//!
//! [`SecretInput::begin`] turns off echo, line editing, signal characters
//! and extended input processing on a terminal, so each keystroke reaches
//! the reader as a byte and nothing is shown. The reader handles Enter,
//! Backspace and Ctrl-C itself: with signal characters off, Ctrl-C is a
//! byte rather than a signal that would kill the process and leave the
//! terminal without echo. Input typed before the prompt is discarded. The
//! saved settings come back when the [`SecretInput`] is dropped.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

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
}

impl Drop for SecretInput<'_> {
    fn drop(&mut self) {
        let _ = set(self.fd, libc::TCSANOW, &self.saved);
    }
}
