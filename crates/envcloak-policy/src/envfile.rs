//! `--env-file` files (SPEC §6.1): dotenv-style files in which a value of
//! the form `envcloak://<slug>[#field]` is a reference. Every other line is
//! an ordinary variable that the runner sets from the file.
//!
//! An env file can hold real values, so this parser is written for them:
//! - It reads the caller's [`SecretBytes`] in place and copies a value only
//!   into a [`SecretBuf`] sized for it, which becomes the variable's
//!   [`SecretBytes`] or is wiped. Nothing else holds a value.
//! - Errors are an [`EnvFileErrorKind`] and a line number, never text from
//!   the file. (A dotenv library's errors print the line.)
//!
//! Grammar, per line (docs/MANIFEST.md has the full text):
//! - Blank lines and lines starting with `#` are skipped. A byte-order mark
//!   before the first line is skipped. Lines end in LF or CRLF.
//! - `[export ]NAME=value`, with blanks allowed around `=`. `NAME` is an
//!   [`EnvName`]; each may appear once.
//! - Unquoted values end at the line's end or at a `#` that follows a
//!   blank, and lose surrounding blanks.
//! - `'single'` quotes are literal. `"double"` quotes decode `\n`, `\r`,
//!   `\t`, `\\`, `\"` and `\'`, and keep any other backslash as written.
//!   Quoted values may span lines (CRLF inside becomes LF); after the
//!   closing quote only blanks and a comment may follow. There is no
//!   variable expansion.
//! - A value may not contain a NUL byte, which no environment can carry.
//! - A value that starts with `envcloak://` must be a whole reference.

use std::collections::BTreeSet;

use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;

use crate::names::{Binding, EnvName, Reference};

/// The largest env file accepted, in bytes (SPEC §6.4: 1 MiB for dotenv
/// files).
pub const MAX_ENV_FILE: usize = 1024 * 1024;

/// The scheme of a reference in an env file.
pub const REFERENCE_SCHEME: &str = "envcloak://";

/// A parsed env file: its references and its ordinary variables, each in
/// file order. Names are unique across both.
#[derive(Debug, Default)]
pub struct EnvFileRefs {
    pub refs: Vec<EnvFileRef>,
    pub plain: Vec<PlainVar>,
}

/// `NAME=envcloak://<slug>[#field]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileRef {
    /// The line the entry starts on, from 1.
    pub line: u32,
    pub binding: Binding,
}

/// An ordinary variable, set from the file as written.
#[derive(Debug)]
pub struct PlainVar {
    /// The line the entry starts on, from 1.
    pub line: u32,
    pub name: EnvName,
    pub value: SecretBytes,
}

/// What a run's resolution needs of an env file, and all the daemon is
/// sent of it (SPEC §6.1 step 2): its references and the names of its
/// ordinary variables, each with its line. Never a value: an ordinary
/// variable's value stays with `envcloak run`, which sets it for the
/// command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvFileNames {
    pub refs: Vec<EnvFileRef>,
    pub plain: Vec<PlainName>,
}

/// An ordinary variable's name and line, without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainName {
    /// The line the entry starts on, from 1.
    pub line: u32,
    pub name: EnvName,
}

impl EnvFileRefs {
    /// The file's references and the names of its ordinary variables,
    /// without their values.
    pub fn names(&self) -> EnvFileNames {
        EnvFileNames {
            refs: self.refs.clone(),
            plain: self
                .plain
                .iter()
                .map(|p| PlainName {
                    line: p.line,
                    name: p.name.clone(),
                })
                .collect(),
        }
    }
}

/// What is wrong with an env file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EnvFileErrorKind {
    TooLarge,
    /// The line is not `NAME=...`: no `=`.
    MissingEquals,
    /// The text before `=` is not a variable name.
    InvalidName,
    UnterminatedQuote,
    /// Text after a quoted value's closing quote.
    TrailingCharacters,
    NulByte,
    /// A value starting with `envcloak://` that is not a reference.
    InvalidReference,
    /// A variable set twice.
    DuplicateName,
}

impl EnvFileErrorKind {
    fn message(self) -> &'static str {
        use EnvFileErrorKind as K;
        match self {
            K::TooLarge => "the env file is larger than 1 MiB",
            K::MissingEquals => "expected NAME=value",
            K::InvalidName => {
                "invalid variable name: expected an ASCII letter or _, then letters, digits or _"
            }
            K::UnterminatedQuote => "a quoted value is not closed",
            K::TrailingCharacters => "unexpected text after a quoted value",
            K::NulByte => "a value contains a NUL byte",
            K::InvalidReference => "invalid reference: expected envcloak://<slug>[#field]",
            K::DuplicateName => "the variable is set twice",
        }
    }
}

/// An env-file error: a kind and a line, never text from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvFileError {
    line: u32,
    kind: EnvFileErrorKind,
}

impl EnvFileError {
    pub fn kind(&self) -> EnvFileErrorKind {
        self.kind
    }

    /// The line, from 1; 0 when the error is about the whole file.
    pub fn line(&self) -> u32 {
        self.line
    }

    /// The kind's fixed message, without the line.
    pub fn message(&self) -> &'static str {
        self.kind.message()
    }

    /// The stable token `envcloak run` prints (SPEC §6.1 step 9).
    pub fn token(&self) -> &'static str {
        "binding_unresolved"
    }
}

impl core::fmt::Display for EnvFileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.line != 0 {
            write!(f, "env file line {}: ", self.line)?;
        }
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for EnvFileError {}

fn err(line: u32, kind: EnvFileErrorKind) -> EnvFileError {
    EnvFileError { line, kind }
}

/// Parses an env file. See the module documentation.
pub fn parse_env_file_refs(bytes: &SecretBytes) -> Result<EnvFileRefs, EnvFileError> {
    #[allow(clippy::disallowed_methods)] // Parsed in place; values are copied only into SecretBuf.
    let b = bytes.expose_secret();
    if b.len() > MAX_ENV_FILE {
        return Err(err(0, EnvFileErrorKind::TooLarge));
    }
    let mut c = Cursor { b, pos: 0, line: 1 };
    if b.starts_with(b"\xef\xbb\xbf") {
        c.pos = 3;
    }
    let mut out = EnvFileRefs::default();
    let mut names = BTreeSet::new();
    loop {
        c.skip_blanks();
        match c.peek() {
            None => break,
            Some(b'\n') => {
                c.newline();
                continue;
            }
            Some(b'\r') if c.peek_at(1) == Some(b'\n') => {
                c.pos += 1;
                continue;
            }
            Some(b'#') => {
                c.skip_to_eol();
                continue;
            }
            Some(_) => {}
        }
        let line = c.line;
        let name = c.name(line)?;
        if !names.insert(name.clone()) {
            return Err(err(line, EnvFileErrorKind::DuplicateName));
        }
        let value = c.value(line)?;
        c.end_of_line()?;
        #[allow(clippy::disallowed_methods)] // Checks the scheme; a reference is not a secret.
        let text = value.expose_secret();
        if let Some(rest) = text.strip_prefix(REFERENCE_SCHEME.as_bytes()) {
            let reference = std::str::from_utf8(rest)
                .ok()
                .and_then(|s| Reference::parse(s).ok())
                .ok_or(err(line, EnvFileErrorKind::InvalidReference))?;
            out.refs.push(EnvFileRef {
                line,
                binding: Binding {
                    env_name: name,
                    reference,
                },
            });
        } else {
            out.plain.push(PlainVar {
                line,
                name,
                value: value.freeze(),
            });
        }
    }
    Ok(out)
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
    line: u32,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.b.get(self.pos.saturating_add(n)).copied()
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Consumes a line feed.
    fn newline(&mut self) {
        self.pos += 1;
        self.line = self.line.saturating_add(1);
    }

    /// The index of the next line feed, or the end.
    fn eol(&self) -> usize {
        self.b[self.pos..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(self.b.len(), |i| self.pos + i)
    }

    fn skip_to_eol(&mut self) {
        self.pos = self.eol();
    }

    /// `[export ]NAME` and the `=` after it.
    fn name(&mut self, line: u32) -> Result<EnvName, EnvFileError> {
        if self.b[self.pos..].starts_with(b"export")
            && matches!(self.peek_at(6), Some(b' ' | b'\t'))
        {
            self.pos += 6;
            self.skip_blanks();
        }
        let start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_') {
            self.pos += 1;
        }
        let raw = &self.b[start..self.pos];
        let after = self.pos;
        self.skip_blanks();
        if self.peek() != Some(b'=') {
            // Other characters in the name, or no `=` on the line.
            let rest = &self.b[after..self.eol()];
            let kind = if rest.contains(&b'=') {
                EnvFileErrorKind::InvalidName
            } else {
                EnvFileErrorKind::MissingEquals
            };
            return Err(err(line, kind));
        }
        self.pos += 1;
        self.skip_blanks();
        EnvName::from_bytes(raw).map_err(|_| err(line, EnvFileErrorKind::InvalidName))
    }

    fn value(&mut self, line: u32) -> Result<SecretBuf, EnvFileError> {
        match self.peek() {
            Some(q @ (b'"' | b'\'')) => self.quoted(q, line),
            _ => self.unquoted(line),
        }
    }

    fn unquoted(&mut self, line: u32) -> Result<SecretBuf, EnvFileError> {
        let start = self.pos;
        let eol = self.eol();
        // A comment starts at a `#` after a blank (the blank may be the one
        // after `=`).
        let mut end = (start..eol)
            .find(|&i| self.b[i] == b'#' && i > 0 && matches!(self.b[i - 1], b' ' | b'\t'))
            .unwrap_or(eol);
        while end > start && matches!(self.b[end - 1], b' ' | b'\t' | b'\r') {
            end -= 1;
        }
        let raw = &self.b[start..end];
        if raw.contains(&0) {
            return Err(err(line, EnvFileErrorKind::NulByte));
        }
        let mut v = SecretBuf::with_capacity(raw.len());
        push(&mut v, raw, line)?;
        self.pos = eol;
        Ok(v)
    }

    fn quoted(&mut self, q: u8, line: u32) -> Result<SecretBuf, EnvFileError> {
        let start = self.pos + 1;
        // Find the closing quote before copying anything.
        let mut i = start;
        let close = loop {
            match self.b.get(i) {
                None => return Err(err(line, EnvFileErrorKind::UnterminatedQuote)),
                Some(&c) if c == q => break i,
                Some(b'\\') if q == b'"' => i += 2,
                Some(_) => i += 1,
            }
        };
        let raw = &self.b[start..close];
        let mut v = SecretBuf::with_capacity(raw.len());
        let mut j = 0;
        while let Some(&c) = raw.get(j) {
            let (out, used): (&[u8], usize) = match (c, raw.get(j + 1)) {
                (0, _) => return Err(err(line, EnvFileErrorKind::NulByte)),
                (b'\r', Some(b'\n')) => (b"\n", 2),
                (b'\\', Some(&e)) if q == b'"' => match e {
                    b'n' => (b"\n", 2),
                    b'r' => (b"\r", 2),
                    b't' => (b"\t", 2),
                    b'\\' => (b"\\", 2),
                    b'"' => (b"\"", 2),
                    b'\'' => (b"'", 2),
                    _ => (b"\\", 1),
                },
                _ => (&raw[j..=j], 1),
            };
            push(&mut v, out, line)?;
            j += used;
        }
        let lines = raw.iter().filter(|&&c| c == b'\n').count();
        self.line = self
            .line
            .saturating_add(u32::try_from(lines).unwrap_or(u32::MAX));
        self.pos = close + 1;
        Ok(v)
    }

    /// After a value: blanks, an optional comment, then the line's end.
    fn end_of_line(&mut self) -> Result<(), EnvFileError> {
        self.skip_blanks();
        if self.peek() == Some(b'#') {
            self.skip_to_eol();
        }
        if self.peek() == Some(b'\r') && self.peek_at(1) == Some(b'\n') {
            self.pos += 1;
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.newline();
                Ok(())
            }
            Some(_) => Err(err(self.line, EnvFileErrorKind::TrailingCharacters)),
        }
    }
}

/// Appends to a buffer sized for the whole raw value, which decoding never
/// outgrows.
fn push(v: &mut SecretBuf, b: &[u8], line: u32) -> Result<(), EnvFileError> {
    v.extend(b)
        .map_err(|_| err(line, EnvFileErrorKind::TooLarge))
}
