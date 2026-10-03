//! Dotenv files as `envcloak init` and `envcloak import` read them (SPEC
//! §6.4). Not a dotenv library: `dotenvy`'s errors print the offending
//! line, which can hold a value, and dotenv libraries expand variables.
//!
//! The file is a [`SecretBytes`] the caller read, parsed in place. Each
//! value is copied once, into a [`SecretBuf`] sized for it, which becomes
//! the entry's [`SecretBytes`] or is wiped; nothing else holds a value.
//! Errors are a [`DotenvErrorKind`] and a line number, never text from the
//! file.
//!
//! Grammar, per line:
//! - Blank lines and lines whose first non-blank character is `#` are
//!   skipped. A byte-order mark before the first line is skipped. Lines
//!   end in LF or CRLF; a lone CR is a character of the value.
//! - `[export ]NAME=value`, with blanks allowed around `=`. `NAME` is an
//!   [`EnvName`] (ASCII); each may appear once in a file.
//! - An unquoted value ends at the line's end, or at a `#` that follows a
//!   blank, and loses the blanks around it.
//! - `'single'` and `` `backtick` `` quotes are literal. `"double"` quotes
//!   decode `\n`, `\r`, `\t`, `\\`, `\"` and `\'`, and keep any other
//!   backslash as written. Quoted values may span lines (a CRLF inside
//!   becomes LF); after the closing quote only blanks and a comment may
//!   follow.
//! - Nothing is expanded. A value that is not single-quoted and holds a
//!   `$` followed by a letter, a digit, `_`, `{` or `(` interpolates
//!   another variable (or runs a command) in the tools that read it:
//!   dotenv-expand, docker compose, godotenv and Ruby's dotenv expand
//!   `$NAME` as well as `${NAME}`. It is an [`EntryKind::Template`]: its
//!   text is not the value a program sees, and import leaves it where it
//!   is.
//! - A value starting with `envcloak://` must be a whole reference,
//!   [`EntryKind::Reference`].
//! - A value may not hold a NUL byte, which no environment can carry.
//! - Values are bytes: they need not be UTF-8.
//!
//! Each entry records its [`DotenvEntry::span`]: the bytes of its whole
//! lines. [`without_entries`] takes entries out of a file by their spans,
//! leaving every other byte as it was (`envcloak init --delete-plaintext`
//! keeps the entries it did not import), and [`trimmed_from`] tells
//! whether a file is another with some of its entries taken out that way
//! (gate 16's test asks it of what a killed deletion left). `envcloak init
//! --undo` does not: it puts a file back only when it is exactly what the
//! deletion left, by the SHA-256 the backup recorded (F-78).

use std::collections::BTreeSet;
use std::ops::Range;

use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_policy::{EnvName, REFERENCE_SCHEME, Reference};
use secrecy::ExposeSecret;

/// The largest dotenv file read, in bytes (SPEC §6.4: 1 MiB for dotenv and
/// profile files).
pub const MAX_DOTENV: usize = 1024 * 1024;

/// What an entry's value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A value as written.
    Plain,
    /// `envcloak://<slug>[#field]`: a reference, not a value.
    Reference(Reference),
    /// Interpolates another variable (`$NAME`, `${NAME}`) or runs a
    /// command (`$(...)`), which is never done.
    Template,
}

/// One `NAME=value` line (or lines, for a quoted multi-line value).
#[derive(Debug)]
pub struct DotenvEntry {
    /// The line the entry starts on, from 1.
    pub line: u32,
    pub name: EnvName,
    /// The value as decoded; the reference's text for a reference.
    pub value: SecretBytes,
    pub kind: EntryKind,
    /// The bytes of the file the entry is written in: from the start of
    /// its first line to the end of its last, the line ending included.
    pub span: Range<usize>,
}

/// What is wrong with a dotenv file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DotenvErrorKind {
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

impl DotenvErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [DotenvErrorKind; 8] = [
        DotenvErrorKind::TooLarge,
        DotenvErrorKind::MissingEquals,
        DotenvErrorKind::InvalidName,
        DotenvErrorKind::UnterminatedQuote,
        DotenvErrorKind::TrailingCharacters,
        DotenvErrorKind::NulByte,
        DotenvErrorKind::InvalidReference,
        DotenvErrorKind::DuplicateName,
    ];

    /// The fixed message.
    pub fn message(self) -> &'static str {
        use DotenvErrorKind as K;
        match self {
            K::TooLarge => "the file is larger than 1 MiB",
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

    /// A stable token for reports.
    pub fn token(self) -> &'static str {
        use DotenvErrorKind as K;
        match self {
            K::TooLarge => "too_large",
            K::MissingEquals => "missing_equals",
            K::InvalidName => "invalid_name",
            K::UnterminatedQuote => "unterminated_quote",
            K::TrailingCharacters => "trailing_characters",
            K::NulByte => "nul_byte",
            K::InvalidReference => "invalid_reference",
            K::DuplicateName => "duplicate_name",
        }
    }
}

/// A dotenv error: a kind and a line, never text from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DotenvError {
    line: u32,
    kind: DotenvErrorKind,
}

impl DotenvError {
    pub fn kind(&self) -> DotenvErrorKind {
        self.kind
    }

    /// The line, from 1; 0 when the error is about the whole file.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl core::fmt::Display for DotenvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.line != 0 {
            write!(f, "line {}: ", self.line)?;
        }
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for DotenvError {}

fn err(line: u32, kind: DotenvErrorKind) -> DotenvError {
    DotenvError { line, kind }
}

/// Parses a dotenv file. See the module documentation.
pub fn parse_dotenv(bytes: &SecretBytes) -> Result<Vec<DotenvEntry>, DotenvError> {
    #[allow(clippy::disallowed_methods)] // Parsed in place; values are copied only into SecretBuf.
    let b = bytes.expose_secret();
    if b.len() > MAX_DOTENV {
        return Err(err(0, DotenvErrorKind::TooLarge));
    }
    let mut c = Cursor {
        b,
        pos: 0,
        line: 1,
        line_start: 0,
    };
    if b.starts_with(b"\xef\xbb\xbf") {
        c.pos = 3;
        c.line_start = 3;
    }
    let mut out = Vec::new();
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
        let start = c.line_start;
        let name = c.name(line)?;
        if !names.insert(name.clone()) {
            return Err(err(line, DotenvErrorKind::DuplicateName));
        }
        let (value, quote) = c.value(line)?;
        c.end_of_line()?;
        let kind = classify(&value, quote, line)?;
        out.push(DotenvEntry {
            line,
            name,
            value: value.freeze(),
            kind,
            span: start..c.pos,
        });
    }
    Ok(out)
}

/// The entry's kind, from its decoded value and how it was quoted.
fn classify(value: &SecretBuf, quote: Option<u8>, line: u32) -> Result<EntryKind, DotenvError> {
    #[allow(clippy::disallowed_methods)] // Looks for the scheme and `${`; nothing is copied.
    let text = value.expose_secret();
    if let Some(rest) = text.strip_prefix(REFERENCE_SCHEME.as_bytes()) {
        let reference = std::str::from_utf8(rest)
            .ok()
            .and_then(|s| Reference::parse(s).ok())
            .ok_or(err(line, DotenvErrorKind::InvalidReference))?;
        return Ok(EntryKind::Reference(reference));
    }
    let expands = |w: &[u8]| {
        w[0] == b'$' && (w[1].is_ascii_alphanumeric() || matches!(w[1], b'_' | b'{' | b'('))
    };
    if quote != Some(b'\'') && text.windows(2).any(expands) {
        return Ok(EntryKind::Template);
    }
    Ok(EntryKind::Plain)
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
    line: u32,
    /// Where the line being read starts.
    line_start: usize,
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
        self.line_start = self.pos;
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
    fn name(&mut self, line: u32) -> Result<EnvName, DotenvError> {
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
                DotenvErrorKind::InvalidName
            } else {
                DotenvErrorKind::MissingEquals
            };
            return Err(err(line, kind));
        }
        self.pos += 1;
        self.skip_blanks();
        EnvName::from_bytes(raw).map_err(|_| err(line, DotenvErrorKind::InvalidName))
    }

    /// The value, and the quote it was written in.
    fn value(&mut self, line: u32) -> Result<(SecretBuf, Option<u8>), DotenvError> {
        match self.peek() {
            Some(q @ (b'"' | b'\'' | b'`')) => Ok((self.quoted(q, line)?, Some(q))),
            _ => Ok((self.unquoted(line)?, None)),
        }
    }

    fn unquoted(&mut self, line: u32) -> Result<SecretBuf, DotenvError> {
        let start = self.pos;
        let eol = self.eol();
        // A comment starts at a `#` after a blank (the blank may be the one
        // after `=`); `A=#x` is the value `#x`.
        let mut end = (start..eol)
            .find(|&i| self.b[i] == b'#' && i > 0 && matches!(self.b[i - 1], b' ' | b'\t'))
            .unwrap_or(eol);
        while end > start && matches!(self.b[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        // The CR of a CRLF ending, then any blanks before it.
        if end == eol && end > start && self.b[end - 1] == b'\r' {
            end -= 1;
            while end > start && matches!(self.b[end - 1], b' ' | b'\t') {
                end -= 1;
            }
        }
        let raw = &self.b[start..end];
        if raw.contains(&0) {
            return Err(err(line, DotenvErrorKind::NulByte));
        }
        let mut v = SecretBuf::with_capacity(raw.len());
        push(&mut v, raw, line)?;
        self.pos = eol;
        Ok(v)
    }

    fn quoted(&mut self, q: u8, line: u32) -> Result<SecretBuf, DotenvError> {
        let start = self.pos + 1;
        // Find the closing quote before copying anything.
        let mut i = start;
        let close = loop {
            match self.b.get(i) {
                None => return Err(err(line, DotenvErrorKind::UnterminatedQuote)),
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
                (0, _) => return Err(err(line, DotenvErrorKind::NulByte)),
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
    fn end_of_line(&mut self) -> Result<(), DotenvError> {
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
            Some(_) => Err(err(self.line, DotenvErrorKind::TrailingCharacters)),
        }
    }
}

/// Appends to a buffer sized for the whole raw value, which decoding never
/// outgrows.
fn push(v: &mut SecretBuf, b: &[u8], line: u32) -> Result<(), DotenvError> {
    v.extend(b)
        .map_err(|_| err(line, DotenvErrorKind::TooLarge))
}

/// `bytes` with the byte ranges `spans` taken out (entries' spans, from a
/// parse of `bytes`), every other byte as it was, in a buffer that is
/// wiped when dropped. A span outside `bytes` is ignored.
pub fn without_entries(bytes: &SecretBytes, spans: &[Range<usize>]) -> SecretBytes {
    #[allow(clippy::disallowed_methods)] // Copied only into a SecretBuf.
    let b = bytes.expose_secret();
    let mut cut: Vec<&Range<usize>> = spans
        .iter()
        .filter(|r| r.start <= r.end && r.end <= b.len())
        .collect();
    cut.sort_by_key(|r| r.start);
    let mut out = SecretBuf::with_capacity(b.len());
    let mut at = 0;
    for r in cut {
        if r.start > at {
            // Sized for the whole file, which the pieces never outgrow.
            let _ = out.extend(&b[at..r.start]);
        }
        at = at.max(r.end);
    }
    if at < b.len() {
        let _ = out.extend(&b[at..]);
    }
    out.freeze()
}

/// Whether `now` is `original` with some of its entries taken out whole
/// ([`without_entries`]) and nothing else changed: what `envcloak init
/// --delete-plaintext` leaves of a file it rewrites. `false` when either
/// does not parse, or when no entry is gone.
pub fn trimmed_from(original: &SecretBytes, now: &SecretBytes) -> bool {
    let (Ok(was), Ok(is)) = (parse_dotenv(original), parse_dotenv(now)) else {
        return false;
    };
    let kept: BTreeSet<&EnvName> = is.iter().map(|e| &e.name).collect();
    let gone: Vec<Range<usize>> = was
        .iter()
        .filter(|e| !kept.contains(&e.name))
        .map(|e| e.span.clone())
        .collect();
    !gone.is_empty() && without_entries(original, &gone).ct_eq_secret(now)
}
