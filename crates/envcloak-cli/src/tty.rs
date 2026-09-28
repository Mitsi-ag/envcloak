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
//! reading ends, however it ends.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;

use envcloak_core::{SecretBuf, SecretBytes};
use zeroize::Zeroize;

use crate::fail::Failure;

/// The longest secret read, in bytes.
pub const MAX_SECRET: usize = 1024;

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
    /// Reading or writing failed.
    Io,
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
            InputError::Empty => Failure::new("no_input", "no passphrase was given"),
            InputError::TooLong => Failure::new("input_too_long", "the input is over 1024 bytes"),
            InputError::BadFd => Failure::new(
                "bad_fd",
                "the file descriptor named on the command line is not open",
            ),
            InputError::Io => Failure::new("io", "reading the passphrase failed"),
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

    /// Turns echo off, shows `prompt` and reads a secret. Echo goes off
    /// before the prompt appears, so nothing typed after it is echoed or
    /// discarded.
    pub fn read_secret(&mut self, prompt: &str) -> Result<SecretBytes, InputError> {
        let result = {
            let mode = envcloak_sys::SecretInput::begin(self.file.as_fd())
                .map_err(|_| InputError::NoTerminal)?;
            let r = (&self.file)
                .write_all(prompt.as_bytes())
                .map_err(|_| InputError::Io)
                .and_then(|()| read_keys(&self.file));
            drop(mode);
            r
        };
        self.say("\n")?;
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
        match tty.read(&mut b) {
            // The terminal hung up.
            Ok(0) => return Err(InputError::Io),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
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
