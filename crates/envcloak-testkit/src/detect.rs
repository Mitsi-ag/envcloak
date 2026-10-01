//! Finding canaries and their encodings in bytes, files and directories.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use envcloak_sys::{
    DirEntryKind, MAX_DIR_ENTRIES, kind_beneath, list_dir, open_beneath, open_dir_beneath,
    read_link_beneath,
};

use crate::canary::Canary;
use crate::encode::{self, PERCENT_STYLES};

/// Every listed encoding of a canary (SPEC §15.2 gate 8), as
/// `(encoding name, bytes)`, raw value first. Encodings that come out
/// byte-identical to an earlier one are listed once, under the first name.
pub fn encodings(c: &Canary) -> Vec<(&'static str, Vec<u8>)> {
    let v = c.value();
    let mut out: Vec<(&'static str, Vec<u8>)> = vec![
        ("raw", v.to_vec()),
        ("hex-lower", encode::hex(v, false)),
        ("hex-upper", encode::hex(v, true)),
        ("base64", encode::base64(v, false, true)),
        ("base64-nopad", encode::base64(v, false, false)),
        ("base64url", encode::base64(v, true, true)),
        ("base64url-nopad", encode::base64(v, true, false)),
    ];
    const EMBEDDED: [[&str; 3]; 2] = [
        ["base64-at-0", "base64-at-1", "base64-at-2"],
        ["base64url-at-0", "base64url-at-1", "base64url-at-2"],
    ];
    for (url, names) in [false, true].into_iter().zip(EMBEDDED) {
        for (offset, name) in names.into_iter().enumerate() {
            if let Some(frag) = encode::base64_embedded(v, offset, url) {
                out.push((name, frag));
            }
        }
    }
    for style in &PERCENT_STYLES {
        out.push((style.name_upper, encode::percent(v, style, true)));
        out.push((style.name_lower, encode::percent(v, style, false)));
    }
    let text = c.as_str();
    for (style, name) in encode::json_styles() {
        out.push((name, encode::json(text, style).into_bytes()));
    }

    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    out.retain(|(_, bytes)| seen.insert(bytes.clone()));
    out
}

/// One canary occurrence. Holds no value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The canary's label.
    pub label: String,
    /// Which encoding matched, as named by [`encodings`].
    pub encoding: &'static str,
    /// Byte offset of the match: in the bytes as stored when `unescaped`
    /// is 0, else in those bytes with that many levels of JSON string
    /// escaping read through.
    pub offset: usize,
    /// How many levels of JSON string escaping were read through to find
    /// it (see [`JSON_LEVELS`]): 0 for the bytes as stored.
    pub unescaped: u8,
}

/// How many levels of JSON string escaping the detector reads through, on
/// top of the encodings [`encodings`] lists. A host keeps what a command
/// printed as a JSON string (a transcript line, a request body), and
/// output that was JSON already, or a JSON string that holds JSON (Codex
/// keeps a command's result as one), is escaped again at each level: a
/// value with a `"`, a `\` or a non-ASCII character in it then matches
/// none of its listed encodings byte for byte. So every haystack is also
/// read with one level of escaping undone, then two, up to this many, and
/// an occurrence counts at a level only where it covers a character that
/// level decoded (one that covers none was there, and was counted, a
/// level up). Undoing a level decodes each `\"`, `\\`, `\/`, `\b`, `\f`,
/// `\n`, `\r`, `\t` and `\uXXXX` (a surrogate pair as one character)
/// wherever it is, and leaves any other backslash as it is: bytes outside
/// JSON strings hold no escapes, so string boundaries need not be known,
/// and an escape in a file that is not JSON is read the conservative way.
pub const JSON_LEVELS: u8 = 4;

/// A path reported by [`sweep_dir`]. Its `Debug` and `Display` show the
/// path with every component below the sweep root that holds a canary
/// replaced by `<LABEL>`, so hits can go into failure messages. [`raw`]
/// gives the real path, which may hold a value: compare it, never print it.
///
/// [`raw`]: SweptPath::raw
#[derive(Clone, PartialEq, Eq)]
pub struct SweptPath {
    raw: PathBuf,
    shown: String,
}

impl SweptPath {
    /// The real path. It may hold a value; do not print it.
    pub fn raw(&self) -> &Path {
        &self.raw
    }

    /// The printable form (see the type documentation).
    pub fn shown(&self) -> &str {
        &self.shown
    }
}

impl PartialEq<PathBuf> for SweptPath {
    fn eq(&self, other: &PathBuf) -> bool {
        self.raw == *other
    }
}

impl PartialEq<Path> for SweptPath {
    fn eq(&self, other: &Path) -> bool {
        self.raw == other
    }
}

impl fmt::Debug for SweptPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.shown, f)
    }
}

impl fmt::Display for SweptPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.shown)
    }
}

/// One finding of [`sweep_dir`]. Holds no value bytes, and its `Debug` and
/// `Display` never print one: paths are [`SweptPath`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hit {
    /// A canary, or one of its encodings, inside a file.
    Canary { path: SweptPath, found: Found },
    /// A canary in the name of a file, directory, symlink or other entry,
    /// or spread over the names of it and its parents (an encoding with a
    /// `/` in it). `found.offset` counts from the start of the path below
    /// the sweep root.
    Name { path: SweptPath, found: Found },
    /// A canary in the target of the symlink at `path`, which the sweep
    /// does not follow.
    LinkTarget { path: SweptPath, found: Found },
    /// A file or directory the sweep could not read, so it cannot vouch for
    /// it. Make it readable before sweeping, or remove it.
    Unreadable {
        path: SweptPath,
        kind: std::io::ErrorKind,
    },
}

impl fmt::Display for Found {
    /// `LABEL as ENCODING at offset N`, and how many levels of JSON
    /// escaping were read through, when any; never a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} as {} at offset {}",
            self.label, self.encoding, self.offset
        )?;
        if self.unescaped > 0 {
            write!(f, " (JSON-unescaped {}x)", self.unescaped)?;
        }
        Ok(())
    }
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let found = |f: &mut fmt::Formatter<'_>, x: &Found| write!(f, "{x}");
        match self {
            Hit::Canary { path, found: x } => {
                found(f, x)?;
                write!(f, " in the contents of {path}")
            }
            Hit::Name { path, found: x } => {
                found(f, x)?;
                write!(f, " in the path {path}")
            }
            Hit::LinkTarget { path, found: x } => {
                found(f, x)?;
                write!(f, " in the target of the symlink {path}")
            }
            Hit::Unreadable { path, kind } => write!(f, "could not read {path}: {kind:?}"),
        }
    }
}

/// A compiled matcher for a set of canaries and all their encodings. Build
/// one to scan many haystacks.
pub struct Detector {
    matcher: AhoCorasick,
    /// Per pattern: canary index and encoding name.
    meta: Vec<(usize, &'static str)>,
    labels: Vec<String>,
    /// The length of the longest pattern.
    longest: usize,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("labels", &self.labels)
            .field("patterns", &self.meta.len())
            .finish()
    }
}

impl Detector {
    /// # Panics
    /// When the matcher cannot be built (it can always be built for the
    /// canaries this crate generates).
    pub fn new(cs: &[Canary]) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut meta = Vec::new();
        for (i, c) in cs.iter().enumerate() {
            for (name, bytes) in encodings(c) {
                patterns.push(bytes);
                meta.push((i, name));
            }
        }
        // A contiguous NFA builds fast, which matters more here than search
        // speed: tests build a detector per assertion.
        let matcher = match AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&patterns)
        {
            Ok(m) => m,
            Err(_) => panic!("canary matcher could not be built"),
        };
        Detector {
            matcher,
            meta,
            labels: cs.iter().map(|c| c.label.clone()).collect(),
            longest: patterns.iter().map(Vec::len).max().unwrap_or(0),
        }
    }

    /// Every occurrence of every canary encoding in `haystack`, including
    /// overlapping ones: those in the bytes as they are, in order of their
    /// end offset, then those found with one level of JSON string escaping
    /// read through, and so on up to [`JSON_LEVELS`].
    pub fn find(&self, haystack: &[u8]) -> Vec<Found> {
        let mut reader = haystack;
        self.find_streaming(&mut reader, haystack.len())
            .unwrap_or_else(|_| unreachable!("reading a slice cannot fail"))
    }

    /// As [`Detector::find`] over everything `reader` yields, reading at
    /// most `chunk` bytes at a time. Only the last chunk and the tail of the
    /// one before it (one byte short of the longest pattern) are held, at
    /// each level of unescaping, so a file of any size costs a fixed amount
    /// of memory. Occurrences come out exactly as [`Detector::find`] would
    /// report them for the whole input: each once, by level and then in
    /// order of end offset, with offsets from the start of their level.
    fn find_streaming(&self, reader: &mut dyn Read, chunk: usize) -> io::Result<Vec<Found>> {
        let keep = self.longest.saturating_sub(1);
        let mut piece = vec![0u8; chunk.max(1)];
        let mut levels: Vec<Level> = (0..=JSON_LEVELS).map(Level::new).collect();
        let mut decoded = Vec::new();
        let mut escaped = Vec::new();
        loop {
            let n = match reader.read(&mut piece) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let mut input = piece[..n].to_vec();
            let mut from_escape = vec![false; n];
            for at in 0..levels.len() {
                levels[at].push(self, &input, &from_escape, keep);
                if at + 1 < levels.len() {
                    decoded.clear();
                    escaped.clear();
                    levels[at + 1]
                        .unescape
                        .feed(&input, false, &mut decoded, &mut escaped);
                    std::mem::swap(&mut input, &mut decoded);
                    std::mem::swap(&mut from_escape, &mut escaped);
                }
            }
        }
        // An escape cut off by the end of the input is no escape: what each
        // level still holds is read as it is, through the levels below it.
        for at in 1..levels.len() {
            let mut input = Vec::new();
            let mut from_escape = Vec::new();
            levels[at]
                .unescape
                .feed(&[], true, &mut input, &mut from_escape);
            for below in at..levels.len() {
                levels[below].push(self, &input, &from_escape, keep);
                if below + 1 < levels.len() {
                    decoded.clear();
                    escaped.clear();
                    levels[below + 1]
                        .unescape
                        .feed(&input, false, &mut decoded, &mut escaped);
                    std::mem::swap(&mut input, &mut decoded);
                    std::mem::swap(&mut from_escape, &mut escaped);
                }
            }
        }
        Ok(levels.into_iter().flat_map(|l| l.found).collect())
    }

    /// As [`Detector::find`], with the end offset of each occurrence.
    fn find_ending(&self, haystack: &[u8]) -> Vec<(Found, usize)> {
        self.matcher
            .find_overlapping_iter(haystack)
            .map(|m| {
                let (canary, encoding) = self.meta[m.pattern().as_usize()];
                let found = Found {
                    label: self.labels[canary].clone(),
                    encoding,
                    offset: m.start(),
                    unescaped: 0,
                };
                (found, m.end())
            })
            .collect()
    }

    /// `path` as [`SweptPath`] shows it: `root`, then each component below
    /// it with every canary occurrence replaced by `<LABEL>`. If the result
    /// still holds one (spread over components), everything below the root
    /// is replaced.
    fn swept_path(&self, root: &Path, path: &Path) -> SweptPath {
        let shown = match path.strip_prefix(root) {
            Ok(rel) => {
                let mut shown = root.display().to_string();
                for part in rel.components() {
                    shown.push('/');
                    shown.push_str(&self.redact_name(part.as_os_str().as_bytes()));
                }
                if self.find(shown.as_bytes()).is_empty() {
                    shown
                } else {
                    format!("{}/<redacted>", root.display())
                }
            }
            Err(_) => String::from("<outside the sweep root>"),
        };
        SweptPath {
            raw: path.to_path_buf(),
            shown,
        }
    }

    /// Panics if `haystack` holds any canary. The message names labels,
    /// encodings and offsets, never a value.
    pub fn assert_absent(&self, haystack: &[u8]) {
        let found = self.find(haystack);
        if found.is_empty() {
            return;
        }
        let shown: Vec<String> = found.iter().take(8).map(ToString::to_string).collect();
        panic!(
            "canary leak: {} occurrence(s): {}{}",
            found.len(),
            shown.join("; "),
            if found.len() > shown.len() {
                "; ..."
            } else {
                ""
            }
        );
    }

    /// `name` with each run of overlapping canary occurrences replaced by
    /// `<LABEL>` (labels joined with `+`).
    fn redact_name(&self, name: &[u8]) -> String {
        let mut spans: Vec<(usize, usize, String)> = self
            .find_ending(name)
            .into_iter()
            .map(|(f, end)| (f.offset, end, f.label))
            .collect();
        spans.sort_unstable();
        let mut out = String::new();
        let mut at = 0;
        let mut i = 0;
        while i < spans.len() {
            let start = spans[i].0;
            let mut end = spans[i].1;
            let mut labels = Vec::new();
            while i < spans.len() && spans[i].0 < end {
                end = end.max(spans[i].1);
                labels.push(spans[i].2.clone());
                i += 1;
            }
            labels.sort_unstable();
            labels.dedup();
            out.push_str(&String::from_utf8_lossy(&name[at..start]));
            out.push('<');
            out.push_str(&labels.join("+"));
            out.push('>');
            at = end;
        }
        out.push_str(&String::from_utf8_lossy(&name[at..]));
        out
    }
}

/// One level of a streamed search: the bytes with `level` levels of JSON
/// string escaping read through, as they arrive.
struct Level {
    level: u8,
    /// Undoes one more level of escaping: from the level above to this
    /// one (unused at level 0).
    unescape: Unescape,
    /// The tail carried from earlier pieces, then the new bytes.
    window: Vec<u8>,
    /// Per byte of `window`: whether an escape at this level made it.
    escaped: Vec<bool>,
    /// The offset in this level's stream of `window[0]`.
    base: usize,
    found: Vec<Found>,
}

impl Level {
    fn new(level: u8) -> Level {
        Level {
            level,
            unescape: Unescape::default(),
            window: Vec::new(),
            escaped: Vec::new(),
            base: 0,
            found: Vec::new(),
        }
    }

    /// Takes the next bytes of this level's stream and records the
    /// occurrences that end in them. Above level 0, only an occurrence
    /// that covers a byte an escape made counts: one that covers none is
    /// the same bytes, in the same order, as one level up, where it was
    /// counted.
    fn push(&mut self, detector: &Detector, bytes: &[u8], from_escape: &[bool], keep: usize) {
        // Occurrences that end in the carried tail were reported with the
        // piece they end in; one that ends in the new bytes starts no
        // earlier than the tail, which is one byte short of the longest
        // pattern.
        let carried = self.window.len();
        self.window.extend_from_slice(bytes);
        self.escaped.extend_from_slice(from_escape);
        if self.level == 0 || self.escaped.contains(&true) {
            for (mut f, end) in detector.find_ending(&self.window) {
                let start = f.offset;
                if end > carried && (self.level == 0 || self.escaped[start..end].contains(&true)) {
                    f.offset += self.base;
                    f.unescaped = self.level;
                    self.found.push(f);
                }
            }
        }
        if self.window.len() > keep {
            let drop = self.window.len() - keep;
            self.window.drain(..drop);
            self.escaped.drain(..drop);
            self.base += drop;
        }
    }
}

/// One level of JSON string unescaping over a stream that arrives in
/// pieces (see [`JSON_LEVELS`]). An escape cut off at the end of a piece
/// is held until the next one completes it, so the output does not depend
/// on where the pieces end.
#[derive(Default)]
struct Unescape {
    held: Vec<u8>,
}

/// What a backslash starts.
enum Escape {
    /// A whole escape: the UTF-8 bytes it stands for, and its length.
    Whole([u8; 4], usize, usize),
    /// Possibly an escape, cut off by the end of the input.
    Short,
    /// Not an escape: the backslash stands for itself.
    Not,
}

fn hex4(s: &[u8]) -> Option<u32> {
    if s.len() != 4 || !s.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::str::from_utf8(s)
        .ok()
        .and_then(|t| u32::from_str_radix(t, 16).ok())
}

/// The escape at the start of `s`, which starts with a backslash.
fn escape_at(s: &[u8]) -> Escape {
    let one = |b: u8| Escape::Whole([b, 0, 0, 0], 1, 2);
    let Some(&kind) = s.get(1) else {
        return Escape::Short;
    };
    match kind {
        b'"' | b'\\' | b'/' => return one(kind),
        b'b' => return one(0x08),
        b'f' => return one(0x0c),
        b'n' => return one(b'\n'),
        b'r' => return one(b'\r'),
        b't' => return one(b'\t'),
        b'u' => {}
        _ => return Escape::Not,
    }
    // `\uXXXX`, or a high surrogate's and a low one's: 6 or 12 bytes.
    let digits = &s[2..s.len().min(6)];
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Escape::Not;
    }
    let Some(unit) = hex4(digits) else {
        return Escape::Short;
    };
    let (ch, len) = match unit {
        0xd800..=0xdbff => {
            let rest = &s[6..s.len().min(12)];
            let expected = rest.iter().enumerate().all(|(i, &b)| match i {
                0 => b == b'\\',
                1 => b == b'u',
                _ => b.is_ascii_hexdigit(),
            });
            if !expected {
                return Escape::Not;
            }
            match hex4(rest.get(2..).unwrap_or(&[])) {
                None => return Escape::Short,
                Some(low @ 0xdc00..=0xdfff) => (
                    char::from_u32(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)),
                    12,
                ),
                Some(_) => return Escape::Not,
            }
        }
        _ => (char::from_u32(unit), 6),
    };
    let Some(ch) = ch else {
        // A lone low surrogate.
        return Escape::Not;
    };
    let mut bytes = [0u8; 4];
    let n = ch.encode_utf8(&mut bytes).len();
    Escape::Whole(bytes, n, len)
}

impl Unescape {
    /// Appends `input` (after what was held) to `out` with one level of
    /// escaping undone, and to `from_escape` whether an escape made each
    /// byte. An escape cut off at the end is held, unless `last`, when it
    /// is read as no escape.
    fn feed(&mut self, input: &[u8], last: bool, out: &mut Vec<u8>, from_escape: &mut Vec<bool>) {
        let data: Vec<u8> = if self.held.is_empty() {
            input.to_vec()
        } else {
            let mut d = std::mem::take(&mut self.held);
            d.extend_from_slice(input);
            d
        };
        let mut i = 0;
        while i < data.len() {
            if data[i] != b'\\' {
                // Up to the next backslash, as it is.
                let run = data[i..]
                    .iter()
                    .position(|&b| b == b'\\')
                    .unwrap_or(data.len() - i);
                out.extend_from_slice(&data[i..i + run]);
                from_escape.extend(std::iter::repeat_n(false, run));
                i += run;
                continue;
            }
            match escape_at(&data[i..]) {
                Escape::Whole(bytes, n, len) => {
                    out.extend_from_slice(&bytes[..n]);
                    from_escape.extend(std::iter::repeat_n(true, n));
                    i += len;
                }
                Escape::Short if !last => {
                    self.held = data[i..].to_vec();
                    return;
                }
                Escape::Short | Escape::Not => {
                    out.push(b'\\');
                    from_escape.push(false);
                    i += 1;
                }
            }
        }
    }
}

/// Every occurrence of any canary encoding in `haystack`.
pub fn find(haystack: &[u8], cs: &[Canary]) -> Vec<Found> {
    Detector::new(cs).find(haystack)
}

/// Panics if `haystack` holds any canary in any listed encoding. The message
/// names the label and encoding, never the value.
pub fn assert_no_canary(haystack: &[u8], cs: &[Canary]) {
    Detector::new(cs).assert_absent(haystack);
}

/// Bytes [`sweep_dir`] reads from a file at a time.
const SWEEP_CHUNK: usize = 64 * 1024;

/// `file`, if it is a regular file: its type is checked on the open
/// descriptor, so an entry replaced after the sweep looked at it is
/// refused rather than read.
fn regular(file: File) -> io::Result<File> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("no longer a regular file"));
    }
    Ok(file)
}

/// Opens `path` for reading only if it is a regular file: without
/// following a symlink in its last component and without blocking on a
/// FIFO. For the sweep root only; below it, entries are opened relative
/// to their directory's descriptor.
fn open_regular(path: &Path) -> io::Result<File> {
    regular(
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)?,
    )
}

/// Every canary occurrence in the regular file at `path`, read in
/// [`SWEEP_CHUNK`] pieces. See [`open_regular`].
fn scan_file(detector: &Detector, path: &Path) -> io::Result<Vec<Found>> {
    let mut file = open_regular(path)?;
    detector.find_streaming(&mut file, SWEEP_CHUNK)
}

/// An entry the sweep will look at: its name in the directory `parent`,
/// held open, and its path for reports.
struct Queued {
    parent: Rc<File>,
    name: OsString,
    kind: DirEntryKind,
    path: PathBuf,
}

/// What opening the sweep root found.
enum Root {
    Dir(File),
    /// Not a directory (a symlink, a file or something else), or gone: it
    /// is looked at by path, as the one entry of the sweep.
    Other,
}

/// Opens `root` as a directory without following a symlink in its last
/// component (the caller chose its path; the components above it are the
/// caller's).
fn open_root(root: &Path) -> io::Result<Root> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
    {
        Ok(dir) => Ok(Root::Dir(dir)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => Ok(Root::Other),
        Err(e) => Err(e),
    }
}

/// Scans everything under `dir` for canaries: the contents of every regular
/// file, the path of every entry below `dir` (so a canary in a name, or
/// spread over nested names, is found), and the target of every symlink.
/// Symlinks are not followed, and the contents of FIFOs, sockets and
/// devices are not read, so a sweep never hangs or leaves the tree.
///
/// That holds for a tree that changes while the sweep runs, as a daemon
/// still writing might change it. The sweep opens `dir` once, without
/// following a symlink in its place, and from then on works through
/// descriptors, never through paths: it lists each directory through its
/// own descriptor, and opens each entry relative to its directory's
/// descriptor without following a symlink or blocking (review finding
/// F-19). So when `dir`, or any directory below it, is renamed or replaced
/// by a symlink midway, what the sweep reads is still the tree it opened,
/// and a symlink put where it had seen a file or directory is refused. A
/// file must still be a regular file once open. Anything that fails those
/// checks, or cannot be read, is reported as [`Hit::Unreadable`]. Files
/// are read in fixed-size pieces, so a large file costs no more memory
/// than a small one. Hits print without values; [`assert_sweep_clean`]
/// panics with them.
pub fn sweep_dir(dir: &Path, cs: &[Canary]) -> Vec<Hit> {
    sweep(dir, cs, &mut |_| {})
}

/// [`sweep_dir`], calling `before` with each entry's path just before the
/// entry is opened: the tests change the tree there.
fn sweep(dir: &Path, cs: &[Canary], before: &mut dyn FnMut(&Path)) -> Vec<Hit> {
    let detector = Detector::new(cs);
    let shown = |p: &Path| detector.swept_path(dir, p);
    let mut hits = Vec::new();
    let unreadable = |hits: &mut Vec<Hit>, p: &Path, e: &io::Error| {
        hits.push(Hit::Unreadable {
            path: shown(p),
            kind: e.kind(),
        });
    };
    let root = match open_root(dir) {
        Ok(Root::Dir(d)) => d,
        Ok(Root::Other) => {
            sweep_root_entry(&detector, dir, &mut hits);
            return hits;
        }
        Err(e) => {
            unreadable(&mut hits, dir, &e);
            return hits;
        }
    };
    let mut stack: Vec<Queued> = Vec::new();
    queue_children(root, dir, &mut stack, &mut hits, &shown);
    while let Some(q) = stack.pop() {
        // The root's own name was chosen by the caller. Below it, each
        // occurrence is reported once, at the deepest entry it reaches.
        if let Ok(rel) = q.path.strip_prefix(dir) {
            let rel = rel.as_os_str().as_bytes();
            let name_start = rel.len().saturating_sub(q.name.as_bytes().len());
            for (found, end) in detector.find_ending(rel) {
                if end > name_start {
                    hits.push(Hit::Name {
                        path: shown(&q.path),
                        found,
                    });
                }
            }
        }
        before(&q.path);
        let kind = match q.kind {
            DirEntryKind::Unknown => match kind_beneath(&q.parent, &q.name) {
                Ok(k) => k,
                Err(e) => {
                    unreadable(&mut hits, &q.path, &e);
                    continue;
                }
            },
            k => k,
        };
        match kind {
            DirEntryKind::Dir => match open_dir_beneath(&q.parent, &q.name) {
                Ok(sub) => queue_children(sub, &q.path, &mut stack, &mut hits, &shown),
                Err(e) => unreadable(&mut hits, &q.path, &e),
            },
            DirEntryKind::Symlink => match read_link_beneath(&q.parent, &q.name) {
                Ok(target) => {
                    for found in detector.find(target.as_bytes()) {
                        hits.push(Hit::LinkTarget {
                            path: shown(&q.path),
                            found,
                        });
                    }
                }
                Err(e) => unreadable(&mut hits, &q.path, &e),
            },
            DirEntryKind::File => {
                let found = open_beneath(&q.parent, &q.name)
                    .and_then(regular)
                    .and_then(|mut f| detector.find_streaming(&mut f, SWEEP_CHUNK));
                match found {
                    Ok(found) => {
                        for found in found {
                            hits.push(Hit::Canary {
                                path: shown(&q.path),
                                found,
                            });
                        }
                    }
                    Err(e) => unreadable(&mut hits, &q.path, &e),
                }
            }
            DirEntryKind::Other | DirEntryKind::Unknown => {}
        }
    }
    hits
}

/// Lists `dir` through its descriptor and queues its entries, in name
/// order, above everything already queued. The entries share the
/// descriptor, which stays open until the last of them is looked at.
fn queue_children(
    dir: File,
    path: &Path,
    stack: &mut Vec<Queued>,
    hits: &mut Vec<Hit>,
    shown: &dyn Fn(&Path) -> SweptPath,
) {
    let mut entries = match list_dir(&dir, MAX_DIR_ENTRIES) {
        Ok(e) => e,
        Err(e) => {
            hits.push(Hit::Unreadable {
                path: shown(path),
                kind: e.kind(),
            });
            return;
        }
    };
    let parent = Rc::new(dir);
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    // Popped from the end: in name order.
    for e in entries.into_iter().rev() {
        stack.push(Queued {
            parent: Rc::clone(&parent),
            path: path.join(&e.name),
            name: e.name,
            kind: e.kind,
        });
    }
}

/// The sweep root when it is not a directory: a symlink's target, a
/// regular file's contents, nothing for anything else.
fn sweep_root_entry(detector: &Detector, root: &Path, hits: &mut Vec<Hit>) {
    let shown = |p: &Path| detector.swept_path(root, p);
    let meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) => {
            hits.push(Hit::Unreadable {
                path: shown(root),
                kind: e.kind(),
            });
            return;
        }
    };
    let found = if meta.file_type().is_symlink() {
        std::fs::read_link(root).map(|target| {
            detector
                .find(target.as_os_str().as_bytes())
                .into_iter()
                .map(|found| Hit::LinkTarget {
                    path: shown(root),
                    found,
                })
                .collect()
        })
    } else if meta.is_file() {
        scan_file(detector, root).map(|found| {
            found
                .into_iter()
                .map(|found| Hit::Canary {
                    path: shown(root),
                    found,
                })
                .collect()
        })
    } else {
        Ok(Vec::new())
    };
    match found {
        Ok(found) => hits.extend(found),
        Err(e) => hits.push(Hit::Unreadable {
            path: shown(root),
            kind: e.kind(),
        }),
    }
}

/// Panics if [`sweep_dir`] finds anything under `dir`. The message lists
/// the hits as [`Hit`]'s `Display` prints them: labels, encodings and paths
/// with value-bearing names replaced, never a value.
pub fn assert_sweep_clean(dir: &Path, cs: &[Canary]) {
    let hits = sweep_dir(dir, cs);
    if hits.is_empty() {
        return;
    }
    let shown: Vec<String> = hits.iter().take(16).map(ToString::to_string).collect();
    panic!(
        "canary sweep: {} hit(s):\n  {}{}",
        hits.len(),
        shown.join("\n  "),
        if hits.len() > shown.len() {
            "\n  ..."
        } else {
            ""
        }
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{self, Read};
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    use std::path::Path;

    use super::{Detector, Found, Hit, encodings, scan_file, sweep};
    use crate::canary::{by_label, canaries, fresh_seed, labels};
    use crate::home::TestHome;

    /// Hands out at most `step` bytes per read, and fails every third read
    /// with `Interrupted`, which the reader must retry.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
        calls: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls % 3 == 0 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    /// Every encoding of every canary, some back to back and some apart,
    /// so occurrences overlap, touch and straddle any chunk boundary.
    fn haystack() -> (Detector, Vec<u8>) {
        let cs = canaries(fresh_seed());
        let mut hay = Vec::new();
        for (i, c) in cs.iter().enumerate() {
            for (j, (_, bytes)) in encodings(c).into_iter().enumerate() {
                hay.extend(std::iter::repeat_n(b'~', (i * 7 + j * 3) % 11));
                hay.extend_from_slice(&bytes);
            }
        }
        (Detector::new(&cs), hay)
    }

    #[test]
    fn streaming_finds_what_a_whole_input_search_finds() {
        let (detector, hay) = haystack();
        let whole: Vec<Found> = detector.find(&hay);
        assert!(whole.len() > 100, "{}", whole.len());
        for chunk in [1, 2, 3, 5, 7, 16, 61, 4096, hay.len() + 1] {
            for step in [1, 3, 64, usize::MAX] {
                let mut reader = Trickle {
                    data: &hay,
                    step,
                    calls: 0,
                };
                let streamed = detector.find_streaming(&mut reader, chunk).unwrap();
                assert!(
                    streamed == whole,
                    "chunk {chunk}, step {step}: {} occurrences streamed, {} in the whole input",
                    streamed.len(),
                    whole.len()
                );
            }
        }
    }

    /// One level of unescaping, the input handed over `piece` bytes at a
    /// time.
    fn unescaped(input: &[u8], piece: usize) -> (Vec<u8>, Vec<bool>) {
        let mut u = super::Unescape::default();
        let (mut out, mut flags) = (Vec::new(), Vec::new());
        for p in input.chunks(piece.max(1)) {
            u.feed(p, false, &mut out, &mut flags);
        }
        u.feed(&[], true, &mut out, &mut flags);
        (out, flags)
    }

    /// Each JSON escape is undone, a surrogate pair as one character, and
    /// anything that is not an escape (a lone surrogate, an unknown letter,
    /// an escape cut off by the end) is left as it is; the result does not
    /// depend on where the pieces end.
    #[test]
    fn one_level_of_json_escaping_is_undone_whatever_the_pieces() {
        let cases: &[(&[u8], &[u8])] = &[
            (br#"a\"b\\c\/d\b\f\n\r\t"#, b"a\"b\\c/d\x08\x0c\n\r\t"),
            (br"\u00e9\u00C9\u0022", "\u{e9}\u{c9}\"".as_bytes()),
            (br"\ud83d\ude00!", "\u{1f600}!".as_bytes()),
            (br"\ue000", "\u{e000}".as_bytes()),
            (br"\ud83dx \ude00 \ud83d\u0041", br"\ud83dx \ude00 \ud83dA"),
            (br"\x \u12g4 \", br"\x \u12g4 \"),
            (br"\u00", br"\u00"),
            (br"\ud83d\ude0", br"\ud83d\ude0"),
            (br"\\\\u0041", br"\\u0041"),
        ];
        for (input, want) in cases {
            for piece in [1, 2, 3, 5, 7, input.len()] {
                let (out, flags) = unescaped(input, piece);
                assert_eq!(
                    out,
                    *want,
                    "{:?} in pieces of {piece}",
                    String::from_utf8_lossy(input)
                );
                assert_eq!(flags.len(), out.len());
            }
        }
        // Which bytes an escape made.
        let (out, flags) = unescaped(br#"x\"y\u00e9"#, 2);
        assert_eq!(out, "x\"y\u{e9}".as_bytes());
        assert_eq!(flags, [false, true, false, true, true]);
    }

    /// A value a command printed as JSON, kept by a host as a JSON string,
    /// inside a JSON string that holds JSON (Codex keeps a command's result
    /// as one): none of its listed encodings is in the bytes as stored, and
    /// each level of escaping read through finds the value again.
    #[test]
    fn a_value_escaped_again_by_each_envelope_is_found_through_them() {
        let cs = canaries(fresh_seed());
        let c = by_label(&cs, labels::DATABASE_URL);
        let detector = Detector::new(&cs);
        let printed = serde_json::json!({ "DATABASE_URL": c.as_str() }).to_string();
        let kept = serde_json::json!({ "type": "tool_result", "content": printed }).to_string();
        let output = serde_json::json!({ "output": kept }).to_string();
        let line =
            serde_json::json!({ "type": "function_call_output", "output": output }).to_string();
        for (level, hay) in [(0u8, &printed), (1, &kept), (2, &output), (3, &line)] {
            let found = detector.find(hay.as_bytes());
            let mut at: Vec<(u8, &str)> = found
                .iter()
                .filter(|f| f.label == c.label)
                .map(|f| (f.unescaped, f.encoding))
                .collect();
            at.sort_unstable();
            at.dedup();
            // The JSON encoding at this level, and the raw value one level
            // further in.
            assert!(
                at.iter()
                    .any(|(l, e)| *l == level && e.starts_with("json/")),
                "level {level}: {at:?}"
            );
            assert!(
                at.iter().any(|(l, e)| *l == level + 1 && *e == "raw"),
                "level {level}: {at:?}"
            );
            assert!(
                at.iter().all(|(l, _)| *l >= level),
                "found less escaped than it is: {at:?}"
            );
        }
        // Past the last level read through, it is not found: the limit is
        // real, and stated.
        let mut deeper = line;
        for _ in 0..super::JSON_LEVELS {
            deeper = serde_json::Value::String(deeper).to_string();
        }
        assert!(
            !detector
                .find(deeper.as_bytes())
                .iter()
                .any(|f| f.label == c.label),
            "found past JSON_LEVELS"
        );
    }

    /// An occurrence that covers no byte an escape made is counted once, at
    /// the level where it is: a clean JSON line does not count again.
    #[test]
    fn an_occurrence_with_no_escape_in_it_is_counted_once() {
        let cs = canaries(fresh_seed());
        let c = by_label(&cs, labels::GITHUB_TOKEN);
        let detector = Detector::new(&cs);
        let line = format!(
            "{{\"note\":\"a \\\"quoted\\\" word\",\"t\":\"{}\"}}",
            c.as_str()
        );
        let found: Vec<Found> = detector
            .find(line.as_bytes())
            .into_iter()
            .filter(|f| f.label == c.label)
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].encoding, found[0].unescaped), ("raw", 0));
    }

    /// Runs `f` on another thread and gives up after ten seconds, so a
    /// scan that blocks fails the test instead of hanging it.
    fn within_ten_seconds<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the scan blocked")
    }

    /// What the sweep meets when a file it saw as regular is replaced
    /// before it opens it.
    #[test]
    fn a_file_swapped_for_a_fifo_or_symlink_is_refused() {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let root = home.home();

        let fifo = root.join("fifo");
        let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(made.success());
        let detector = Detector::new(&cs);
        let result = within_ten_seconds(move || scan_file(&detector, &fifo).map(|_| ()));
        assert!(result.is_err(), "a FIFO was scanned");

        let outside = TestHome::new();
        let secret = outside.root().join("secret.txt");
        std::fs::write(&secret, cs[0].value()).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let detector = Detector::new(&cs);
        assert!(
            scan_file(&detector, &link).is_err(),
            "a symlink was followed"
        );

        // Control: the same file, opened where it is, is scanned.
        let found = scan_file(&detector, &secret).unwrap();
        assert!(
            found
                .iter()
                .any(|f| f.label == cs[0].label && f.offset == 0)
        );
    }

    /// Where the sweep and the tree meet in the F-19 regressions: a tree
    /// holding one canary in its later file, a separate tree outside it
    /// holding another under the same name, and which of the two a sweep
    /// found.
    struct Swap {
        cs: Vec<crate::canary::Canary>,
        home: TestHome,
        outside: TestHome,
    }

    impl Swap {
        fn new() -> Swap {
            let cs = canaries(fresh_seed());
            let (home, outside) = (TestHome::new(), TestHome::new());
            std::fs::write(
                outside.home().join("later.txt"),
                by_label(&cs, labels::GITHUB_TOKEN).value(),
            )
            .unwrap();
            Swap { cs, home, outside }
        }

        /// Fills `dir` (under the sweep root) with a clean first file and a
        /// later one holding the inside canary.
        fn fill(&self, dir: &Path) {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("first.txt"), b"nothing here").unwrap();
            std::fs::write(
                dir.join("later.txt"),
                by_label(&self.cs, labels::STRIPE_SECRET_KEY).value(),
            )
            .unwrap();
        }

        /// Renames `dir` aside and puts a symlink to the outside tree in its
        /// place.
        fn replace_with_link(&self, dir: &Path) {
            let mut aside = dir.as_os_str().to_owned();
            aside.push(".moved");
            std::fs::rename(dir, &aside).unwrap();
            std::os::unix::fs::symlink(self.outside.home(), dir).unwrap();
        }

        /// The labels of the canaries found in file contents.
        fn contents(hits: &[Hit]) -> Vec<String> {
            let mut v: Vec<String> = hits
                .iter()
                .filter_map(|h| match h {
                    Hit::Canary { found, .. } => Some(found.label.clone()),
                    _ => None,
                })
                .collect();
            v.sort();
            v.dedup();
            v
        }
    }

    /// Review finding F-19 (Codex's regression): a directory below the
    /// root is listed, and before its later child is opened it is renamed
    /// and replaced by a symlink to another tree. The child is still read
    /// in the directory the sweep listed, never through the new symlink.
    #[test]
    fn queued_child_does_not_follow_replaced_ancestor() {
        let s = Swap::new();
        let root = s.home.home();
        let sub = root.join("sub");
        s.fill(&sub);
        let later = sub.join("later.txt");
        let mut swapped = false;
        let hits = sweep(&root, &s.cs, &mut |p| {
            if p == later && !swapped {
                s.replace_with_link(&sub);
                swapped = true;
            }
        });
        assert!(swapped, "the sweep never reached the later file");
        assert_eq!(
            Swap::contents(&hits),
            [labels::STRIPE_SECRET_KEY],
            "{hits:?}"
        );
        assert_eq!(hits.len(), found_count(&hits), "{hits:?}");
    }

    /// The same with the sweep root itself swapped for a symlink after the
    /// sweep opened it.
    #[test]
    fn queued_child_does_not_follow_a_replaced_root() {
        let s = Swap::new();
        let root = s.home.home();
        s.fill(&root);
        let later = root.join("later.txt");
        let mut swapped = false;
        let hits = sweep(&root, &s.cs, &mut |p| {
            if p == later && !swapped {
                s.replace_with_link(&root);
                swapped = true;
            }
        });
        assert!(swapped, "the sweep never reached the later file");
        assert_eq!(
            Swap::contents(&hits),
            [labels::STRIPE_SECRET_KEY],
            "{hits:?}"
        );
        assert_eq!(hits.len(), found_count(&hits), "{hits:?}");
    }

    /// A directory replaced by a symlink after its parent was listed and
    /// before it is opened is refused, not listed through the link.
    #[test]
    fn a_directory_swapped_for_a_symlink_before_it_is_opened_is_refused() {
        let s = Swap::new();
        let root = s.home.home();
        let sub = root.join("sub");
        s.fill(&sub);
        let mut swapped = false;
        let hits = sweep(&root, &s.cs, &mut |p| {
            if p == sub && !swapped {
                s.replace_with_link(&sub);
                swapped = true;
            }
        });
        assert!(swapped, "the sweep never reached the directory");
        assert!(Swap::contents(&hits).is_empty(), "{hits:?}");
        assert!(
            matches!(hits.as_slice(), [Hit::Unreadable { path, .. }] if path == &sub),
            "{hits:?}"
        );
    }

    /// The number of hits that are canary finds.
    fn found_count(hits: &[Hit]) -> usize {
        hits.iter()
            .filter(|h| matches!(h, Hit::Canary { .. }))
            .count()
    }
}
