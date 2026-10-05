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
//!   after SIGCONT, from the settings [`TerminalGuard::refresh`] read again
//!   once the person's shell has had the terminal (a `stty` change made
//!   meanwhile is what later restores put back; review of M2-19, L-09).
//!   [`restore_outer_terminal`] is async-signal-safe
//!   (`tcsetattr` and atomics only), for a path that cannot run ordinary
//!   code.
//!
//! The guard keeps its own copy of the terminal's descriptor, so the
//! number the panic hook restores through stays open for as long as the
//! guard is registered. One guard is registered at a time. A restore on
//! another thread holds the registration while it runs: a guard dropped
//! meanwhile waits for it before its descriptor closes, and no new guard
//! registers over settings being read. The panic hook's restore is final
//! for the guard: a switch to raw mode already under way finishes first,
//! and the restore comes after it; one asked for after it is refused
//! (Codex's review of PR #27: a raw switch on one thread could otherwise
//! land after the hook's restore on another, and the process abort with
//! the terminal raw). [`TerminalGuard::release`] ends a guard and reports
//! whether the restore worked; a drop restores without reporting.
//!
//! [`TerminalSettings`] are the settings themselves: the PTY's slave side
//! starts with the outer terminal's (`crate::pty::open_pty`), so a
//! remapped or disabled suspend character carries over. [`window_size`]
//! and [`set_window_size`] read and set a terminal's size.

use std::cell::UnsafeCell;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

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

    /// These settings with every control character that differs between
    /// `old` and `new` set to `new`'s (the interrupt, quit, suspend, erase,
    /// kill and end-of-file characters and the others), and every other
    /// left as it is; `VMIN` and `VTIME`, which share the array but time a
    /// read, never change. For the command's terminal once the person has
    /// changed theirs while the command was stopped (`stty susp ^X`): the
    /// change reaches the command, and what the command set for itself
    /// stays.
    pub fn with_changed_control_chars(&self, old: &Self, new: &Self) -> Self {
        let mut t = self.0;
        for (i, (was, now)) in old.0.c_cc.iter().zip(new.0.c_cc.iter()).enumerate() {
            if was != now && i != libc::VMIN && i != libc::VTIME {
                if let Some(c) = t.c_cc.get_mut(i) {
                    *c = *now;
                }
            }
        }
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

/// The registered guard's terminal and saved settings, for
/// [`restore_outer_terminal`], which a panic hook or a signal path calls
/// from any thread while other threads may drop the guard and register a
/// new one. A reader announces itself in `state` before it reads and
/// leaves after its `tcsetattr`; retiring the slot first shuts readers
/// out, then waits for those inside to leave, so the settings are never
/// written while one reads them and the guard's descriptor is closed only
/// once no reader can use its number (review cycle 365). Lock-free and
/// allocation-free on the reading side, so async-signal-safe.
struct Slot {
    /// The phase in the top two bits, the readers inside below.
    state: AtomicU32,
    fd: AtomicI32,
    saved: UnsafeCell<MaybeUninit<libc::termios>>,
    /// The final restore has begun for this registration: raw mode is
    /// refused from then on.
    fatal: AtomicBool,
    /// Switches to raw mode under way.
    raw_switches: AtomicU32,
}

const READERS: u32 = (1 << 30) - 1;
const PHASE: u32 = !READERS;
/// Nothing registered.
const EMPTY: u32 = 0;
/// A guard is writing its settings in; no reader enters.
const WRITING: u32 = 1 << 30;
/// Registered: readers may enter.
const READY: u32 = 2 << 30;
/// Being unregistered: no reader enters; the ones inside finish.
const RETIRING: u32 = 3 << 30;

// SAFETY: `saved` and `fd` are written only by the thread that moved
// `state` to WRITING (from EMPTY, or from READY with no reader inside, a
// compare-exchange that fails while one is), before it stores READY with
// Release; they are read only by a reader that entered with an Acquire
// compare-exchange from READY, and the phase leaves READY (for RETIRING,
// then EMPTY, or for WRITING) only once every reader inside has left with
// a Release decrement, which the leaving phase's thread observes with
// Acquire before the slot can be written again.
unsafe impl Sync for Slot {}

impl Slot {
    const fn new() -> Self {
        Slot {
            state: AtomicU32::new(EMPTY),
            fd: AtomicI32::new(-1),
            saved: UnsafeCell::new(MaybeUninit::uninit()),
            fatal: AtomicBool::new(false),
            raw_switches: AtomicU32::new(0),
        }
    }

    fn register(&self, fd: libc::c_int, saved: &libc::termios) -> io::Result<()> {
        if self
            .state
            .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a terminal guard is already registered",
            ));
        }
        // SAFETY: the phase is WRITING, which this thread set: no other
        // thread writes the slot, and no reader is inside or can enter.
        unsafe { (*self.saved.get()).write(*saved) };
        self.fd.store(fd, Ordering::Relaxed);
        self.fatal.store(false, Ordering::SeqCst);
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    /// Writes `saved` over the registered settings, for a guard that read
    /// its terminal's settings again ([`TerminalGuard::refresh`]): waits
    /// until no reader is inside (each runs one `tcsetattr`), then holds
    /// the slot, so no reader enters, while it writes. The registration's
    /// descriptor and its final restore's mark are kept.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] when nothing is registered or the slot
    /// is being retired; nothing is written then.
    fn replace(&self, saved: &libc::termios) -> io::Result<()> {
        loop {
            match self.state.compare_exchange_weak(
                READY,
                WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                // A reader inside (or a spurious failure): its tcsetattr
                // ends soon.
                Err(now) if now & PHASE == READY => std::thread::yield_now(),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no terminal guard is registered",
                    ));
                }
            }
        }
        // SAFETY: the phase is WRITING, which this thread set from READY
        // with no reader inside: no other thread writes the slot, and no
        // reader is inside or can enter until READY is stored below.
        unsafe { (*self.saved.get()).write(*saved) };
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    /// Runs `switch`, a change of the registered terminal to raw mode,
    /// unless the final restore has begun, which then waits for it to end
    /// before it restores. Announcing the switch and reading `fatal`, and
    /// setting `fatal` and reading the switches under way, are each
    /// sequentially consistent, so one of the two sees the other: either
    /// the switch is refused, or the restore waits for it.
    fn raw_switch(&self, switch: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        self.raw_switches.fetch_add(1, Ordering::SeqCst);
        let result = if self.fatal.load(Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the terminal was restored for the process's end; raw mode is refused",
            ))
        } else {
            switch()
        };
        self.raw_switches.fetch_sub(1, Ordering::SeqCst);
        result
    }

    /// The final restore: marks the registration so no switch to raw mode
    /// starts after it, waits for one under way to end (up to
    /// [`SWITCH_WAIT_MS`], in case it is this very thread's, interrupted),
    /// then runs `restore` on the registered descriptor and settings with
    /// the slot held. `None` when nothing is registered.
    fn final_restore<R>(
        &self,
        restore: impl FnOnce(libc::c_int, &libc::termios) -> R,
    ) -> Option<R> {
        self.read(|fd, saved| {
            self.fatal.store(true, Ordering::SeqCst);
            let start = monotonic_ms();
            while self.raw_switches.load(Ordering::SeqCst) != 0
                && monotonic_ms().saturating_sub(start) < SWITCH_WAIT_MS
            {
                std::thread::yield_now();
            }
            restore(fd, saved)
        })
    }

    /// Runs `f` on the registered descriptor and settings, with the slot
    /// held so it is neither retired nor rewritten meanwhile; `None` when
    /// nothing is registered or the slot is being retired.
    fn read<R>(&self, f: impl FnOnce(libc::c_int, &libc::termios) -> R) -> Option<R> {
        let mut now = self.state.load(Ordering::Acquire);
        loop {
            if now & PHASE != READY || now & READERS == READERS {
                return None;
            }
            match self.state.compare_exchange_weak(
                now,
                now + 1,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(seen) => now = seen,
            }
        }
        let fd = self.fd.load(Ordering::Relaxed);
        // SAFETY: this reader entered while the phase was READY, so the
        // registering thread's write happened before (Release/Acquire),
        // and no write can happen until this reader leaves below.
        let saved = unsafe { (*self.saved.get()).assume_init_ref() };
        let result = f(fd, saved);
        self.state.fetch_sub(1, Ordering::Release);
        Some(result)
    }

    /// Unregisters: no new reader enters, and this returns once every
    /// reader inside has left. Then the caller may close the descriptor.
    fn unregister(&self) {
        let mut now = self.state.load(Ordering::Acquire);
        loop {
            if now & PHASE != READY {
                return;
            }
            let retiring = (now & READERS) | RETIRING;
            match self.state.compare_exchange_weak(
                now,
                retiring,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(seen) => now = seen,
            }
        }
        // A reader inside runs one tcsetattr; it cannot be this thread
        // (no guard is dropped from inside a restore).
        while self.state.load(Ordering::Acquire) & READERS != 0 {
            std::thread::yield_now();
        }
        self.fd.store(-1, Ordering::Relaxed);
        self.state.store(EMPTY, Ordering::Release);
    }

    #[cfg(test)]
    fn phase(&self) -> u32 {
        self.state.load(Ordering::Acquire) & PHASE
    }
}

static SLOT: Slot = Slot::new();

/// How long the final restore waits for a switch to raw mode under way,
/// in milliseconds: a switch is one `tcsetattr`.
const SWITCH_WAIT_MS: libc::time_t = 1000;

/// The monotonic clock in milliseconds. Async-signal-safe
/// (`clock_gettime`).
fn monotonic_ms() -> libc::time_t {
    // SAFETY: timespec is plain data; clock_gettime fills it in.
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is writable.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec
        .saturating_mul(1000)
        .saturating_add(t.tv_nsec / 1_000_000)
}

/// Puts the registered guard's saved settings back on its terminal with
/// `TCSAFLUSH`, for the process's end, and returns whether it did. It is
/// final for the guard: a switch to raw mode under way on another thread
/// ends first and this restore comes after it, and the guard's later
/// switches to raw mode (`TerminalGuard::reenter_raw`) are refused. Only
/// the panic hook, and a path that ends the process, calls it; a stop
/// uses [`TerminalGuard::restore`]. Async-signal-safe: it reads and
/// writes atomics, reads the saved settings and the monotonic clock, and
/// calls `tcsetattr`, which POSIX lists as safe in a signal handler; and
/// it holds the slot while it does, so a guard dropped meanwhile on
/// another thread waits for it before it closes the descriptor. The panic
/// hook calls it first, so a release build, which aborts on a panic
/// without running destructors, still leaves the terminal as it found it.
/// The guard stays registered: its drop restores again, which changes
/// nothing.
pub fn restore_outer_terminal() -> bool {
    SLOT.final_restore(|fd, saved| {
        if fd < 0 {
            return false;
        }
        loop {
            // SAFETY: `saved` is an initialized termios; on a descriptor
            // that is not a terminal tcsetattr fails without effect.
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, saved) } == 0 {
                return true;
            }
            // EINTR only: retry. Anything else: give up.
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return false;
            }
        }
    })
    .unwrap_or(false)
}

/// The outer terminal in raw mode for as long as the guard lives. See the
/// module documentation for when the saved settings come back.
pub struct TerminalGuard {
    fd: OwnedFd,
    saved: TerminalSettings,
    /// [`TerminalGuard::release`] restored already; the drop only
    /// unregisters.
    released: bool,
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
        SLOT.register(fd.as_raw_fd(), &saved.0)?;
        let guard = TerminalGuard {
            fd,
            saved,
            released: false,
        };
        let raw = saved.raw();
        SLOT.raw_switch(|| set(guard.fd.as_raw_fd(), libc::TCSANOW, &raw.0))?;
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

    /// Reads the terminal's settings again and keeps them as the saved
    /// ones, for after a stop: the person's shell had the terminal
    /// meanwhile, and may have changed it (`stty susp ^X`, `stty -echo`).
    /// Every later restore, the panic hook's included, puts these back, and
    /// raw mode is made from them. Settings that are raw themselves (no
    /// line editing, no echo and no signal characters,
    /// [`TerminalSettings::is_raw`]: the terminal as this guard left it,
    /// which a shell that does not take a stopped job's terminal back
    /// leaves so) are not kept, so the terminal is never restored raw.
    /// Returns the settings saved before, which are still the saved ones
    /// when nothing was kept.
    ///
    /// # Errors
    /// When the settings cannot be read, or the guard is not registered
    /// (never once it lives); nothing changes then.
    pub fn refresh(&mut self) -> io::Result<TerminalSettings> {
        let before = self.saved;
        let now = TerminalSettings(get(self.fd.as_raw_fd())?);
        if now.is_raw() {
            return Ok(before);
        }
        SLOT.replace(&now.0)?;
        self.saved = now;
        Ok(before)
    }

    /// Takes raw mode again after [`TerminalGuard::restore`] (after
    /// SIGCONT).
    ///
    /// # Errors
    /// When the settings cannot be changed; [`io::ErrorKind::Interrupted`]
    /// once [`restore_outer_terminal`] has restored the terminal for the
    /// process's end.
    pub fn reenter_raw(&self) -> io::Result<()> {
        let raw = self.saved.raw();
        SLOT.raw_switch(|| set(self.fd.as_raw_fd(), libc::TCSANOW, &raw.0))
    }

    /// Ends the guard on a way out that can still report: puts the saved
    /// settings back with `TCSAFLUSH`, unregisters and closes, and says
    /// whether the restore worked (a drop cannot; it restores all the
    /// same and ignores the result).
    ///
    /// # Errors
    /// When the settings cannot be put back.
    pub fn release(mut self) -> io::Result<()> {
        let result = set(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.saved.0);
        self.released = true;
        result
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if !self.released {
            // TCSAFLUSH: input not read yet is discarded, not left for the
            // next reader with echo back on.
            let _ = set(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.saved.0);
        }
        // Waits for a restore running on another thread (the panic hook)
        // before the descriptor closes after this.
        SLOT.unregister();
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

    fn settings(tag: libc::tcflag_t) -> libc::termios {
        // SAFETY: termios is plain data.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        t.c_iflag = tag;
        t
    }

    /// A reader inside the slot (the panic hook on another thread, in its
    /// `tcsetattr`) holds off both the guard's unregistering, so its
    /// descriptor is not closed under the reader, and a new registration,
    /// so the settings it reads are not rewritten under it: the reader
    /// reads the slot again at its end and finds what it read at its
    /// start. Let `unregister` return without waiting for readers and the
    /// new registration lands while the reader is inside.
    #[test]
    fn a_reader_inside_holds_off_unregistering_and_a_new_registration() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let slot: &'static Slot = Box::leak(Box::new(Slot::new()));
        slot.register(100, &settings(100)).unwrap();
        let (inside_tx, inside) = mpsc::channel();
        let (go, go_rx) = mpsc::channel::<()>();
        let reader = std::thread::spawn(move || {
            slot.read(|fd, t| {
                inside_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                // What the slot holds now, read the way the next reader
                // would.
                // SAFETY: test-only peek, made while this reader holds the
                // slot.
                let now = unsafe { (*slot.saved.get()).assume_init_ref() };
                (fd, t.c_iflag, slot.fd.load(Ordering::Relaxed), now.c_iflag)
            })
        });
        inside.recv().unwrap();
        let done = Box::leak(Box::new(AtomicBool::new(false)));
        let done_ref: &'static AtomicBool = done;
        let dropper = std::thread::spawn(move || {
            slot.unregister();
            done_ref.store(true, Ordering::Release);
        });
        let end = Instant::now() + Duration::from_secs(10);
        while slot.phase() == READY {
            assert!(Instant::now() < end, "unregister never started");
            std::thread::yield_now();
        }
        // While the reader is inside: no new registration, and the
        // unregistering thread has not returned. A bounded wait proves the
        // second: without the wait for readers it returns at once.
        let watch = Instant::now() + Duration::from_millis(300);
        while Instant::now() < watch {
            assert!(
                slot.register(200, &settings(200)).is_err(),
                "a new guard registered while a restore was reading the slot"
            );
            assert!(
                !done.load(Ordering::Acquire),
                "the guard was unregistered (and its descriptor free to close) while a \
                 restore was using it"
            );
            std::thread::yield_now();
        }
        go.send(()).unwrap();
        let (fd, read, fd_after, read_after) = reader.join().unwrap().unwrap();
        assert_eq!((fd, read), (100, 100));
        assert_eq!(
            (fd_after, read_after),
            (100, 100),
            "rewritten under the reader"
        );
        dropper.join().unwrap();
        assert!(done.load(Ordering::Acquire));
        assert!(
            slot.read(|_, _| ()).is_none(),
            "nothing registered after it"
        );
        slot.register(200, &settings(200)).unwrap();
        assert_eq!(slot.read(|fd, t| (fd, t.c_iflag)), Some((200, 200)));
    }

    /// The final restore and a switch to raw mode on two threads (Codex's
    /// review of PR #27): a switch under way when the final restore begins
    /// ends first, and the restore lands after it, so the terminal is left
    /// restored; a switch asked for after the final restore is refused and
    /// changes nothing; a new registration takes raw mode again. Here the
    /// terminal is a record of what was written to it, last write last.
    /// Let the restore run without waiting for the switch, or the switch
    /// run without looking at the mark, and the terminal is left raw.
    #[test]
    fn a_raw_switch_never_lands_after_the_final_restore() {
        use std::sync::mpsc;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        let slot: &'static Slot = Box::leak(Box::new(Slot::new()));
        slot.register(7, &settings(7)).unwrap();
        let terminal = Arc::new(Mutex::new(Vec::<&str>::new()));
        let (inside_tx, inside) = mpsc::channel();
        let (go, go_rx) = mpsc::channel::<()>();
        let t = Arc::clone(&terminal);
        let switcher = std::thread::spawn(move || {
            slot.raw_switch(|| {
                inside_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                t.lock().unwrap().push("raw");
                Ok(())
            })
        });
        inside.recv().unwrap();
        let t = Arc::clone(&terminal);
        let restorer = std::thread::spawn(move || {
            slot.final_restore(|fd, saved| {
                assert_eq!((fd, saved.c_iflag), (7, 7));
                t.lock().unwrap().push("restored");
            })
        });
        // The restore waits while the switch is under way (it would return
        // at once without the wait).
        let watch = Instant::now() + Duration::from_millis(300);
        while Instant::now() < watch {
            assert!(
                !restorer.is_finished(),
                "the final restore did not wait for the switch under way"
            );
            std::thread::yield_now();
        }
        go.send(()).unwrap();
        switcher.join().unwrap().unwrap();
        assert_eq!(restorer.join().unwrap(), Some(()));
        assert_eq!(*terminal.lock().unwrap(), vec!["raw", "restored"]);
        // After it: refused, and nothing written.
        let refused = slot.raw_switch(|| {
            terminal.lock().unwrap().push("raw");
            Ok(())
        });
        assert_eq!(
            refused.unwrap_err().kind(),
            io::ErrorKind::Interrupted,
            "a switch after the final restore"
        );
        assert_eq!(*terminal.lock().unwrap().last().unwrap(), "restored");
        // A new registration starts unmarked.
        slot.unregister();
        slot.register(8, &settings(8)).unwrap();
        slot.raw_switch(|| Ok(())).unwrap();
    }

    /// What the person changed among the control characters reaches the
    /// command's terminal, and nothing else does: a character the command
    /// set for itself stays, and `VMIN` and `VTIME` never change, even when
    /// the person's differ. Let every character be copied and the
    /// command's own end-of-file character and its read timing are lost.
    #[test]
    fn only_the_control_characters_the_person_changed_are_copied() {
        // SAFETY: termios is plain data; zeroed is a valid value.
        let base: libc::termios = unsafe { std::mem::zeroed() };
        let mut old = base;
        old.c_cc[libc::VSUSP] = 0x1a;
        old.c_cc[libc::VINTR] = 0x03;
        old.c_cc[libc::VMIN] = 1;
        let mut new = old;
        new.c_cc[libc::VSUSP] = 0x18;
        new.c_cc[libc::VINTR] = disabled_char();
        new.c_cc[libc::VMIN] = 9;
        new.c_cc[libc::VTIME] = 9;
        let mut command = old;
        command.c_cc[libc::VEOF] = 0x01;
        command.c_cc[libc::VMIN] = 0;
        let got = TerminalSettings(command)
            .with_changed_control_chars(&TerminalSettings(old), &TerminalSettings(new));
        assert_eq!(got.suspend_char(), Some(0x18));
        assert_eq!(got.interrupt_char(), None);
        assert_eq!(got.eof_char(), Some(0x01), "the command's own");
        assert_eq!(got.0.c_cc[libc::VMIN], 0, "VMIN");
        assert_eq!(got.0.c_cc[libc::VTIME], 0, "VTIME");
        // Nothing changed, nothing copied.
        let same = TerminalSettings(command)
            .with_changed_control_chars(&TerminalSettings(old), &TerminalSettings(old));
        assert!(same.same_as(&TerminalSettings(command)));
    }

    /// A guard's settings read again replace the registered ones the panic
    /// hook restores, once no reader is inside, and keep the final
    /// restore's mark; with nothing registered nothing is written. Let
    /// `replace` write without waiting for a reader and the reader finds
    /// its settings rewritten under it.
    #[test]
    fn a_replace_waits_for_a_reader_inside_and_keeps_the_mark() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let slot: &'static Slot = Box::leak(Box::new(Slot::new()));
        assert_eq!(
            slot.replace(&settings(1)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        slot.register(5, &settings(5)).unwrap();
        let (inside_tx, inside) = mpsc::channel();
        let (go, go_rx) = mpsc::channel::<()>();
        let reader = std::thread::spawn(move || {
            slot.read(|fd, t| {
                inside_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                // SAFETY: test-only peek, made while this reader holds the
                // slot.
                let now = unsafe { (*slot.saved.get()).assume_init_ref() };
                (fd, t.c_iflag, now.c_iflag)
            })
        });
        inside.recv().unwrap();
        let replacer = std::thread::spawn(move || slot.replace(&settings(6)));
        let watch = Instant::now() + Duration::from_millis(300);
        while Instant::now() < watch {
            assert!(
                !replacer.is_finished(),
                "the settings were replaced while a restore was reading them"
            );
            std::thread::yield_now();
        }
        go.send(()).unwrap();
        assert_eq!(reader.join().unwrap(), Some((5, 5, 5)));
        replacer.join().unwrap().unwrap();
        assert_eq!(slot.read(|fd, t| (fd, t.c_iflag)), Some((5, 6)));
        // The final restore's mark survives a replace.
        assert_eq!(slot.final_restore(|_, t| t.c_iflag), Some(6));
        slot.replace(&settings(7)).unwrap();
        assert_eq!(
            slot.raw_switch(|| Ok(())).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        slot.unregister();
        assert!(slot.replace(&settings(8)).is_err());
    }

    /// Teardown and re-registration racing readers: each guard registers a
    /// descriptor number and settings that carry the same tag, and every
    /// read sees a matching pair (never one guard's number with another's
    /// settings, never a torn value).
    #[test]
    fn readers_racing_teardown_and_reregistration_see_whole_registrations() {
        use std::sync::atomic::AtomicBool;
        let slot: &'static Slot = Box::leak(Box::new(Slot::new()));
        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                std::thread::spawn(move || {
                    let mut seen = 0usize;
                    while !stop.load(Ordering::Relaxed) {
                        if let Some((fd, tag)) = slot.read(|fd, t| (fd, t.c_iflag)) {
                            assert_eq!(libc::tcflag_t::try_from(fd).unwrap(), tag);
                            seen += 1;
                        }
                    }
                    seen
                })
            })
            .collect();
        for tag in 3..20_000 {
            slot.register(tag, &settings(libc::tcflag_t::try_from(tag).unwrap()))
                .unwrap();
            slot.unregister();
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().unwrap();
        }
    }
}
