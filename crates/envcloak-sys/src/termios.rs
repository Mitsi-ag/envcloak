//! The person's own terminal while `envcloak run --pty` runs (SPEC §6.1
//! step 8; M2 plan D-35, lesson L-13).
//!
//! [`TerminalGuard::enter_raw`] saves the outer terminal's settings and
//! puts it into raw mode, so every key reaches the command's terminal as a
//! byte: Ctrl-C, Ctrl-Z and Ctrl-\ are then the command's terminal's to
//! act on, not the outer one's. The saved settings come back with
//! `TCSAFLUSH` on every way out, so input typed meanwhile and not read is
//! discarded rather than left for the shell with echo back on:
//!
//! - when the guard is dropped (a normal exit, or an error returned);
//! - from the panic hook ([`crate::install_panic_hook`]), which calls
//!   [`restore_outer_terminal`] before anything else. Release builds abort
//!   on a panic (`panic = "abort"`), so no destructor runs there: the hook
//!   is the only restore on that path;
//! - on the signal paths: the CLI catches SIGTERM and SIGHUP and ends
//!   through the guard's drop, and for a stop (the command suspended,
//!   SIGTSTP) [`TerminalGuard::restore`] puts the settings back before the
//!   process stops and [`TerminalGuard::reenter_raw`] takes raw mode again
//!   after SIGCONT. [`restore_outer_terminal`] is async-signal-safe
//!   (`tcsetattr` and atomics only), for a path that cannot run ordinary
//!   code.
//!
//! The guard keeps its own copy of the terminal's descriptor, so the
//! number the panic hook restores through stays open for as long as the
//! guard is registered. One guard is registered at a time.
//!
//! [`TerminalSettings`] are the settings themselves: the PTY's slave side
//! starts with the outer terminal's (`crate::pty::open_pty`), so a
//! remapped or disabled suspend character carries over. [`window_size`]
//! and [`set_window_size`] read and set a terminal's size.

use std::cell::UnsafeCell;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

/// A terminal's settings (`struct termios`), read with
/// [`TerminalSettings::read`].
#[derive(Clone, Copy)]
pub struct TerminalSettings(pub(crate) libc::termios);

impl core::fmt::Debug for TerminalSettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TerminalSettings")
            .field("raw", &self.is_raw())
            .field("echo", &self.echo())
            .field("suspend_char", &self.suspend_char())
            .finish_non_exhaustive()
    }
}

impl TerminalSettings {
    /// The settings of the terminal `fd` now.
    ///
    /// # Errors
    /// When `fd` is not a terminal (`ENOTTY`) or cannot be read.
    pub fn read(fd: BorrowedFd<'_>) -> io::Result<Self> {
        get(fd.as_raw_fd()).map(TerminalSettings)
    }

    /// Writes these settings to the terminal `fd` at once (`TCSANOW`).
    ///
    /// # Errors
    /// When `fd` is not a terminal or the settings cannot be changed.
    pub fn apply(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        set(fd.as_raw_fd(), libc::TCSANOW, &self.0)
    }

    /// The same settings in raw mode (`cfmakeraw`): no echo, no line
    /// editing, no signal characters, no output processing, eight-bit
    /// bytes, and one byte per read.
    pub fn raw(&self) -> Self {
        let mut t = self.0;
        // SAFETY: `t` is an initialized termios; cfmakeraw only changes its
        // flags and control characters.
        unsafe { libc::cfmakeraw(&mut t) };
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        TerminalSettings(t)
    }

    /// Whether these settings are raw: no line editing, no echo and no
    /// signal characters.
    pub fn is_raw(&self) -> bool {
        self.0.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG) == 0
    }

    /// Whether echo is on.
    pub fn echo(&self) -> bool {
        self.0.c_lflag & libc::ECHO != 0
    }

    /// Whether signal characters are on (`ISIG`).
    pub fn signal_chars(&self) -> bool {
        self.0.c_lflag & libc::ISIG != 0
    }

    /// The suspend character (`VSUSP`), or `None` when it is disabled.
    pub fn suspend_char(&self) -> Option<u8> {
        let c = self.0.c_cc[libc::VSUSP];
        (c != disabled_char()).then_some(c)
    }

    /// The interrupt character (`VINTR`), or `None` when it is disabled.
    pub fn interrupt_char(&self) -> Option<u8> {
        let c = self.0.c_cc[libc::VINTR];
        (c != disabled_char()).then_some(c)
    }

    /// The end-of-file character (`VEOF`), or `None` when it is disabled.
    pub fn eof_char(&self) -> Option<u8> {
        let c = self.0.c_cc[libc::VEOF];
        (c != disabled_char()).then_some(c)
    }

    /// The same settings with echo on or off.
    pub fn with_echo(&self, on: bool) -> Self {
        let mut t = self.0;
        if on {
            t.c_lflag |= libc::ECHO;
        } else {
            t.c_lflag &= !libc::ECHO;
        }
        TerminalSettings(t)
    }

    /// The same settings with the suspend character `c`, or none.
    pub fn with_suspend_char(&self, c: Option<u8>) -> Self {
        let mut t = self.0;
        t.c_cc[libc::VSUSP] = c.unwrap_or_else(disabled_char);
        TerminalSettings(t)
    }

    /// Whether two settings are the same: every flag, control character
    /// and speed (what `stty -g` prints).
    pub fn same_as(&self, other: &Self) -> bool {
        let (a, b) = (&self.0, &other.0);
        a.c_iflag == b.c_iflag
            && a.c_oflag == b.c_oflag
            && a.c_cflag == b.c_cflag
            && a.c_lflag == b.c_lflag
            && a.c_cc == b.c_cc
            // SAFETY: both are initialized termios values; the speed
            // getters only read them.
            && unsafe { libc::cfgetispeed(a) == libc::cfgetispeed(b) }
            // SAFETY: as above.
            && unsafe { libc::cfgetospeed(a) == libc::cfgetospeed(b) }
    }
}

/// The value that disables a control character (`_POSIX_VDISABLE`): 0 on
/// Linux, 0xff on macOS.
fn disabled_char() -> libc::cc_t {
    #[cfg(target_os = "macos")]
    {
        0xff
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

pub(crate) fn get(fd: libc::c_int) -> io::Result<libc::termios> {
    // SAFETY: termios is plain data; tcgetattr fills it in.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is a writable termios; tcgetattr fails without effect on
    // a descriptor that is not an open terminal.
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(t)
}

pub(crate) fn set(fd: libc::c_int, how: libc::c_int, t: &libc::termios) -> io::Result<()> {
    loop {
        // SAFETY: `t` is an initialized termios; tcsetattr fails without
        // effect on a descriptor that is not an open terminal.
        if unsafe { libc::tcsetattr(fd, how, t) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// A terminal's size: rows and columns, and the pixel size some terminals
/// also report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

impl WindowSize {
    pub(crate) fn to_raw(self) -> libc::winsize {
        libc::winsize {
            ws_row: self.rows,
            ws_col: self.cols,
            ws_xpixel: self.x_pixels,
            ws_ypixel: self.y_pixels,
        }
    }
}

/// The size of the terminal `fd` (`TIOCGWINSZ`).
///
/// # Errors
/// When `fd` is not a terminal.
pub fn window_size(fd: BorrowedFd<'_>) -> io::Result<WindowSize> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one winsize into `ws`, which is writable.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ as _, &mut ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
        x_pixels: ws.ws_xpixel,
        y_pixels: ws.ws_ypixel,
    })
}

/// Sets the size of the terminal `fd` (`TIOCSWINSZ`). On a PTY's master
/// side this is the slave side's size, and the kernel sends SIGWINCH to
/// the slave's foreground process group when it changes.
///
/// # Errors
/// When `fd` is not a terminal.
pub fn set_window_size(fd: BorrowedFd<'_>, size: WindowSize) -> io::Result<()> {
    let ws = size.to_raw();
    // SAFETY: TIOCSWINSZ reads one winsize from `ws`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The registered settings, for [`restore_outer_terminal`]: written by
/// the one thread that registers a guard before [`STATE`] says they are
/// there, and only read after.
struct SavedSlot(UnsafeCell<MaybeUninit<libc::termios>>);

// SAFETY: the slot is written only while STATE is EMPTY (by the thread
// registering a guard, which first moves STATE from EMPTY to WRITING), and
// read only after STATE was seen READY, which the writer stores with
// Release after its write.
unsafe impl Sync for SavedSlot {}

static SAVED: SavedSlot = SavedSlot(UnsafeCell::new(MaybeUninit::uninit()));
/// The descriptor the registered guard holds, -1 for none.
static SAVED_FD: AtomicI32 = AtomicI32::new(-1);
static STATE: AtomicU8 = AtomicU8::new(EMPTY);
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

fn register(fd: libc::c_int, saved: &libc::termios) -> io::Result<()> {
    if STATE
        .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a terminal guard is already registered",
        ));
    }
    // SAFETY: STATE is WRITING, so no other thread writes the slot, and no
    // reader reads it until STATE is READY.
    unsafe { (*SAVED.0.get()).write(*saved) };
    SAVED_FD.store(fd, Ordering::Release);
    STATE.store(READY, Ordering::Release);
    Ok(())
}

fn unregister() {
    if STATE
        .compare_exchange(READY, WRITING, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        SAVED_FD.store(-1, Ordering::Release);
        STATE.store(EMPTY, Ordering::Release);
    }
}

/// Puts the registered guard's saved settings back on its terminal with
/// `TCSAFLUSH`, and returns whether it did. Async-signal-safe: it reads
/// atomics and the saved settings and calls `tcsetattr`, which POSIX lists
/// as safe in a signal handler. The panic hook calls it first, so a
/// release build, which aborts on a panic without running destructors,
/// still leaves the terminal as it found it. The guard stays registered:
/// its drop restores again, which changes nothing.
pub fn restore_outer_terminal() -> bool {
    if STATE.load(Ordering::Acquire) != READY {
        return false;
    }
    let fd = SAVED_FD.load(Ordering::Acquire);
    if fd < 0 {
        return false;
    }
    // SAFETY: STATE was READY, so the slot holds the settings the
    // registering thread wrote before it stored READY.
    let saved = unsafe { (*SAVED.0.get()).assume_init() };
    loop {
        // SAFETY: `saved` is an initialized termios; on a descriptor that
        // is not a terminal tcsetattr fails without effect.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) } == 0 {
            return true;
        }
        // EINTR only: retry. Anything else: give up.
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
        }
    }
}

/// The outer terminal in raw mode for as long as the guard lives. See the
/// module documentation for when the saved settings come back.
pub struct TerminalGuard {
    fd: OwnedFd,
    saved: TerminalSettings,
}

impl core::fmt::Debug for TerminalGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TerminalGuard").finish_non_exhaustive()
    }
}

impl TerminalGuard {
    /// Saves the settings of the terminal `fd`, registers them for
    /// [`restore_outer_terminal`] and puts the terminal into raw mode
    /// (`TCSANOW`, so input typed ahead for the command is kept).
    ///
    /// # Errors
    /// When `fd` is not a terminal, its settings cannot be changed, or
    /// another guard is registered ([`io::ErrorKind::AlreadyExists`]).
    pub fn enter_raw(fd: BorrowedFd<'_>) -> io::Result<Self> {
        // A copy of its own: the registered number stays open while the
        // guard lives, whatever the caller does with `fd`.
        // SAFETY: F_DUPFD_CLOEXEC creates a new descriptor this process
        // owns, or fails without effect.
        let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `copy` was just created and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(copy) };
        let saved = TerminalSettings(get(fd.as_raw_fd())?);
        register(fd.as_raw_fd(), &saved.0)?;
        let guard = TerminalGuard { fd, saved };
        set(guard.fd.as_raw_fd(), libc::TCSANOW, &saved.raw().0)?;
        Ok(guard)
    }

    /// The settings the terminal had before raw mode, which the PTY's
    /// slave side starts with.
    pub fn saved(&self) -> &TerminalSettings {
        &self.saved
    }

    /// The guarded terminal.
    pub fn terminal(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Puts the saved settings back with `TCSAFLUSH` (for a stop: the
    /// person's shell gets its terminal as it was, and what was typed and
    /// not read is discarded).
    ///
    /// # Errors
    /// When the settings cannot be changed.
    pub fn restore(&self) -> io::Result<()> {
        set(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.saved.0)
    }

    /// Takes raw mode again after [`TerminalGuard::restore`] (after
    /// SIGCONT).
    ///
    /// # Errors
    /// When the settings cannot be changed.
    pub fn reenter_raw(&self) -> io::Result<()> {
        set(self.fd.as_raw_fd(), libc::TCSANOW, &self.saved.raw().0)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // TCSAFLUSH: input not read yet is discarded, not left for the
        // next reader with echo back on.
        let _ = set(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.saved.0);
        unregister();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_that_is_not_a_terminal_is_refused() {
        let file = tempfile::tempfile().unwrap();
        let err = TerminalGuard::enter_raw(file.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTTY), "{err}");
        assert!(!restore_outer_terminal(), "nothing is registered");
        assert!(TerminalSettings::read(file.as_fd()).is_err());
        assert!(window_size(file.as_fd()).is_err());
    }
}
