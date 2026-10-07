//! Reading a secret from a person (SPEC §5 "Unlock flow"): from `/dev/tty`
//! with echo off, never from argv or the environment, and from another
//! descriptor only when the user names it with `--passphrase-fd`.
//!
//! The terminal is put in secret-input mode (`envcloak_sys::SecretInput`):
//! no echo, no line editing and no signal characters, with input typed
//! before the prompt discarded. This reader handles the keys itself: Enter
//! ends the secret, Backspace removes the last character (a whole UTF-8
//! character), Ctrl-U clears it, Ctrl-C cancels, and Ctrl-D on an empty
//! line ends input. Bytes go one at a time into a fixed-size
//! [`SecretBuf`], wiped on drop. The terminal's settings come back when
//! reading ends, however it ends, and input not read by then is discarded
//! rather than left for the next program on the terminal (the shell, which
//! would show and run it). When reading ends before Enter, the rest of a
//! paste still arriving is read and discarded first.
//!
//! A `SIGTERM`, `SIGINT` or `SIGHUP` sent to the process while it reads is
//! recorded by a [`envcloak_sys::TerminationWatch`] instead of ending the
//! process on the spot: the reader, which waits for input in short steps
//! ([`envcloak_sys::wait_readable`]) and looks for a record between them,
//! stops, the terminal's settings come back, and only then does the
//! process end by that signal, as it would have without the watch. A
//! signal that arrives just before a read would interrupt nothing, so the
//! reader never blocks in `read` itself. `SIGKILL` cannot be caught; a terminal left in
//! secret-input mode by it is restored by the next `reset` or `stty sane`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::fail::Failure;

/// The longest secret read, in bytes.
pub const MAX_SECRET: usize = 1024;

/// When secret entry ends before Enter, input is discarded until none has
/// arrived for this long, and for at most [`DISCARD_LIMIT`].
const DISCARD_QUIET: Duration = Duration::from_millis(200);
const DISCARD_LIMIT: Duration = Duration::from_secs(3);

/// How long the reader waits for a key before it looks for a recorded
/// termination signal again.
const SIGNAL_CHECK: Duration = Duration::from_millis(100);

/// Why no secret was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    /// There is no controlling terminal.
    NoTerminal,
    /// Ctrl-C.
    Cancelled,
    /// End of input before any character.
    Empty,
    /// More than [`MAX_SECRET`] bytes.
    TooLong,
    /// The descriptor named by `--passphrase-fd` is not open.
    BadFd,
    /// A termination signal arrived while reading; the process ends by it
    /// once the terminal is restored.
    Terminated(i32),
    /// Reading or writing failed.
    Io,
    /// `--stdin` was given, but standard input is a terminal.
    StdinIsTerminal,
    /// The value holds a NUL byte, which no environment variable can carry.
    NulByte,
}

impl From<InputError> for Failure {
    fn from(e: InputError) -> Self {
        match e {
            InputError::NoTerminal => Failure::new(
                "no_terminal",
                "there is no terminal to type the passphrase on; pass it on a descriptor with \
                 --passphrase-fd",
            ),
            InputError::Cancelled => Failure::new("cancelled", "cancelled"),
            InputError::Empty => Failure::new("no_input", "nothing was entered"),
            InputError::TooLong => Failure::new(
                "input_too_long",
                "the input is too long: 1024 bytes when typed, 64 KiB with --stdin",
            ),
            InputError::BadFd => Failure::new(
                "bad_fd",
                "the file descriptor named on the command line is not open",
            ),
            InputError::Io => Failure::new("io", "reading the input failed"),
            InputError::Terminated(_) => Failure::new("terminated", "stopped by a signal"),
            InputError::StdinIsTerminal => Failure::new(
                "stdin_is_terminal",
                "--stdin reads a pipe, and standard input is a terminal, where typing is shown; \
                 leave out --stdin to type the value at a hidden prompt",
            ),
            InputError::NulByte => Failure::new(
                "invalid_value",
                "the value holds a NUL byte, which no environment variable can carry",
            ),
        }
    }
}

/// The controlling terminal, `/dev/tty`.
#[derive(Debug)]
pub struct Terminal {
    file: File,
}

impl Terminal {
    /// Opens `/dev/tty`.
    pub fn open() -> Result<Terminal, InputError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            // Opening the terminal must not make it the controlling one.
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")
            .map(|file| Terminal { file })
            .map_err(|_| InputError::NoTerminal)
    }

    /// Writes `text` to the terminal.
    pub fn say(&mut self, text: &str) -> Result<(), InputError> {
        self.file
            .write_all(text.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|_| InputError::Io)
    }

    /// Writes a proven reveal value only to this open controlling
    /// terminal. Never formats it or falls back to another descriptor.
    #[allow(clippy::disallowed_methods)] // Proven reveal, directly to /dev/tty.
    pub fn write_secret(&mut self, value: &SecretBytes) -> Result<(), InputError> {
        self.file
            .write_all(value.expose_secret())
            .and_then(|()| self.file.flush())
            .map_err(|_| InputError::Io)
    }

    /// Turns echo off, shows `prompt` and reads a secret. Echo goes off
    /// before the prompt appears, so nothing typed after it is echoed or
    /// discarded.
    pub fn read_secret(&mut self, prompt: &str) -> Result<SecretBytes, InputError> {
        // Installed before the terminal changes, so no signal can end the
        // process between the two without the settings coming back.
        let watch = envcloak_sys::TerminationWatch::install().map_err(|_| InputError::Io)?;
        let result = {
            let mode = envcloak_sys::SecretInput::begin(self.file.as_fd())
                .map_err(|_| InputError::NoTerminal)?;
            let r = (&self.file)
                .write_all(prompt.as_bytes())
                .map_err(|_| InputError::Io)
                .and_then(|()| read_keys(&self.file));
            if r.is_err() {
                // What follows a Ctrl-C, or the rest of a long paste, never
                // reaches the next reader. Dropping `mode` then discards
                // anything left.
                let _ = mode.discard_until_quiet(DISCARD_QUIET, DISCARD_LIMIT);
            }
            drop(mode);
            r
        };
        let _ = self.say("\n");
        // A signal that arrived after the last read completed is honoured
        // too: the terminal is restored either way.
        let terminated = match (&result, watch.recorded()) {
            (Err(InputError::Terminated(sig)), _) => Some(*sig),
            (_, Some(sig)) => Some(sig),
            _ => None,
        };
        if let Some(sig) = terminated {
            drop(result);
            drop(watch);
            envcloak_sys::exit_by_signal(sig);
        }
        result
    }
}

/// Reads keystrokes until Enter.
fn read_keys(mut tty: &File) -> Result<SecretBytes, InputError> {
    let mut buf = SecretBuf::with_capacity(MAX_SECRET);
    // Byte lengths of the characters typed so far, for Backspace. Not
    // secret: they say how long each character is, not which it is.
    let mut chars: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    loop {
        // A signal that arrives before `read` blocks interrupts nothing,
        // so the read would wait for a key: wait for input in short steps
        // instead, looking for a recorded signal between them.
        loop {
            if let Some(sig) = envcloak_sys::termination_recorded() {
                return Err(InputError::Terminated(sig));
            }
            match envcloak_sys::wait_readable(tty.as_fd(), SIGNAL_CHECK) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(InputError::Io),
            }
        }
        match tty.read(&mut b) {
            // The terminal hung up.
            Ok(0) => return Err(InputError::Io),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if let Some(sig) = envcloak_sys::termination_recorded() {
                    return Err(InputError::Terminated(sig));
                }
                continue;
            }
            Err(_) => return Err(InputError::Io),
        }
        match b[0] {
            b'\r' | b'\n' => break,
            0x03 => return Err(InputError::Cancelled),
            0x04 if buf.is_empty() => return Err(InputError::Empty),
            0x04 => {}
            0x7f | 0x08 => {
                if let Some(n) = chars.pop() {
                    buf.truncate(buf.len() - usize::from(n));
                }
            }
            0x15 => {
                buf.clear();
                chars.clear();
            }
            byte => {
                buf.extend(&b).map_err(|_| InputError::TooLong)?;
                match chars.last_mut() {
                    // A UTF-8 continuation byte belongs to the character
                    // before it.
                    Some(n) if byte & 0xC0 == 0x80 => *n = n.saturating_add(1),
                    _ => chars.push(1),
                }
            }
        }
    }
    b.zeroize();
    Ok(buf.freeze())
}

/// The largest value `--stdin` takes: the vault's 64 KiB field cap.
pub const MAX_VALUE: usize = envcloak_core::vault::MAX_FIELD;

/// Reads a value from standard input for `--stdin` (SPEC §6.3): all of it,
/// up to end of input, less one line ending at the very end (`\n` or
/// `\r\n`), so `echo "$KEY" |` and `printf %s "$KEY" |` give the same value.
/// The bytes go through a wiped buffer on the stack into a [`SecretBuf`]
/// with room for [`MAX_VALUE`] and a line ending; a NUL byte is refused.
/// Standard input that is a terminal is refused too: what is typed there
/// is echoed, so `--stdin` is for pipes, and a person types the value at
/// the hidden prompt instead.
pub fn read_stdin_value() -> Result<SecretBytes, InputError> {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(InputError::StdinIsTerminal);
    }
    read_value_from(&mut stdin.lock())
}

/// As [`read_stdin_value`], from `r`.
pub fn read_value_from(r: &mut impl Read) -> Result<SecretBytes, InputError> {
    // Room for a value at the cap and its line ending; more than that does
    // not fit, and a value over the cap is refused below.
    let mut buf = SecretBuf::with_capacity(MAX_VALUE + 2);
    let mut chunk = zeroize::Zeroizing::new([0u8; 512]);
    // The last two bytes read, to take a line ending off the end.
    let mut tail = zeroize::Zeroizing::new([0u8; 2]);
    loop {
        match r.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => {
                let part = chunk.get(..n).ok_or(InputError::Io)?;
                if part.contains(&0) {
                    return Err(InputError::NulByte);
                }
                buf.extend(part).map_err(|_| InputError::TooLong)?;
                match part {
                    [.., a, b] => *tail = [*a, *b],
                    [b] => *tail = [tail[1], *b],
                    [] => {}
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(InputError::Io),
        }
    }
    let len = buf.len();
    if len >= 2 && *tail == *b"\r\n" {
        buf.truncate(len - 2);
    } else if len >= 1 && tail[1] == b'\n' {
        buf.truncate(len - 1);
    }
    if buf.len() > MAX_VALUE {
        return Err(InputError::TooLong);
    }
    if buf.is_empty() {
        return Err(InputError::Empty);
    }
    Ok(buf.freeze())
}

/// Reads one line from the inherited descriptor `fd`, without its line
/// ending, one byte at a time so nothing past the line is consumed.
pub fn read_secret_fd(fd: i32) -> Result<SecretBytes, InputError> {
    let mut file = File::from(envcloak_sys::inherited_fd(fd).map_err(|_| InputError::BadFd)?);
    let mut buf = SecretBuf::with_capacity(MAX_SECRET);
    let mut b = [0u8; 1];
    let mut cr = false;
    loop {
        match file.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(InputError::Io),
        }
        if b[0] == b'\n' {
            break;
        }
        if cr {
            buf.extend(b"\r").map_err(|_| InputError::TooLong)?;
        }
        cr = b[0] == b'\r';
        if !cr {
            buf.extend(&b).map_err(|_| InputError::TooLong)?;
        }
    }
    b.zeroize();
    if buf.is_empty() {
        return Err(InputError::Empty);
    }
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_reveal_write_failure_is_an_error() {
        let (writer, reader) = UnixStream::pair().unwrap();
        let mut terminal = Terminal {
            file: File::from(OwnedFd::from(writer)),
        };
        drop(reader);
        let value = SecretBytes::copy_from(b"synthetic reveal value");
        assert_eq!(terminal.write_secret(&value), Err(InputError::Io));
    }

    /// Reads `input` in pieces of `step` bytes, as a pipe delivers it.
    struct Pieces<'a> {
        input: &'a [u8],
        step: usize,
    }

    impl Read for Pieces<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.input.len());
            buf[..n].copy_from_slice(&self.input[..n]);
            self.input = &self.input[n..];
            Ok(n)
        }
    }

    fn read_value(input: &[u8], step: usize) -> Result<SecretBytes, InputError> {
        read_value_from(&mut Pieces { input, step })
    }

    /// `--stdin` takes the whole input less one line ending at the very
    /// end, however the pipe splits it; NUL bytes, empty input and more
    /// than 64 KiB are refused.
    #[test]
    fn stdin_values_lose_one_final_line_ending() {
        for step in [1, 2, 3, 512, 4096] {
            for (input, want) in [
                (&b"value"[..], &b"value"[..]),
                (b"value\n", b"value"),
                (b"value\r\n", b"value"),
                (b"value\n\n", b"value\n"),
                (b"two\nlines\n", b"two\nlines"),
                (b"cr\r", b"cr\r"),
                (b"x\n", b"x"),
                (b"\r\nx", b"\r\nx"),
            ] {
                let got = read_value(input, step).unwrap();
                assert!(got.ct_eq(want), "{input:?} in pieces of {step}");
            }
            for (input, err) in [
                (&b""[..], InputError::Empty),
                (b"\n", InputError::Empty),
                (b"\r\n", InputError::Empty),
                (b"nul\0inside", InputError::NulByte),
            ] {
                assert_eq!(read_value(input, step).unwrap_err(), err, "{input:?}");
            }
        }
        let full = vec![b'a'; MAX_VALUE];
        assert_eq!(read_value(&full, 4096).unwrap().len(), MAX_VALUE);
        let mut with_newline = full.clone();
        with_newline.push(b'\n');
        assert_eq!(read_value(&with_newline, 4096).unwrap().len(), MAX_VALUE);
        let mut crlf = full.clone();
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(read_value(&crlf, 4096).unwrap().len(), MAX_VALUE);
        for extra in [&b"a"[..], b"a\n", b"ab", b"abc\n"] {
            let mut over = full.clone();
            over.extend_from_slice(extra);
            assert_eq!(read_value(&over, 4096).unwrap_err(), InputError::TooLong);
        }
    }

    /// A termination signal that arrives after the prompt and before the
    /// read blocks still ends the entry, without a key being pressed: the
    /// reader does not sit in a read the signal never interrupted.
    #[test]
    fn a_signal_before_the_read_still_ends_the_entry() {
        let (a, b) = UnixStream::pair().unwrap();
        let input = File::from(OwnedFd::from(a));
        let watch = envcloak_sys::TerminationWatch::install().unwrap();
        envcloak_sys::testing::signal_this_thread(libc::SIGTERM).unwrap();
        assert_eq!(watch.recorded(), Some(libc::SIGTERM));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_keys(&input).map(|_| ()));
        });
        let got = rx.recv_timeout(Duration::from_secs(5));
        drop(watch);
        assert_eq!(got, Ok(Err(InputError::Terminated(libc::SIGTERM))));
        // The other end was open all along: only the signal ended the read.
        drop(b);
    }
}
