//! Finding canaries and their encodings in bytes, files and directories.

use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

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
    /// Byte offset of the match.
    pub offset: usize,
}

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

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let found = |f: &mut fmt::Formatter<'_>, x: &Found| {
            write!(f, "{} as {} at offset {}", x.label, x.encoding, x.offset)
        };
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
    /// overlapping ones, in order of their end offset.
    pub fn find(&self, haystack: &[u8]) -> Vec<Found> {
        self.find_ending(haystack)
            .into_iter()
            .map(|(f, _)| f)
            .collect()
    }

    /// As [`Detector::find`] over everything `reader` yields, reading at
    /// most `chunk` bytes at a time. Only the last chunk and the tail of the
    /// one before it (one byte short of the longest pattern) are held, so a
    /// file of any size costs a fixed amount of memory. Occurrences come out
    /// exactly as [`Detector::find`] would report them for the whole input:
    /// each once, in order of end offset, with offsets from the start.
    fn find_streaming(&self, reader: &mut dyn Read, chunk: usize) -> io::Result<Vec<Found>> {
        let keep = self.longest.saturating_sub(1);
        let mut piece = vec![0u8; chunk.max(1)];
        let mut window: Vec<u8> = Vec::with_capacity(keep + piece.len());
        // The input offset of window[0].
        let mut base = 0usize;
        let mut found = Vec::new();
        loop {
            let n = match reader.read(&mut piece) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            // Occurrences that end in the carried tail were reported with
            // the chunk they end in; one that ends in the new bytes starts
            // no earlier than the tail, which is one byte short of the
            // longest pattern.
            let carried = window.len();
            window.extend_from_slice(&piece[..n]);
            for (mut f, end) in self.find_ending(&window) {
                if end > carried {
                    f.offset += base;
                    found.push(f);
                }
            }
            if window.len() > keep {
                let drop = window.len() - keep;
                window.drain(..drop);
                base += drop;
            }
        }
        Ok(found)
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
        let shown: Vec<String> = found
            .iter()
            .take(8)
            .map(|f| format!("{} as {} at offset {}", f.label, f.encoding, f.offset))
            .collect();
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

/// Opens `path` for reading only if it is a regular file: without
/// following a symlink in its last component, without blocking on a FIFO,
/// and with the type checked again on the open descriptor, so an entry
/// replaced after the sweep looked at it is refused rather than followed
/// or waited on.
fn open_regular(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("no longer a regular file"));
    }
    Ok(file)
}

/// Every canary occurrence in the regular file at `path`, read in
/// [`SWEEP_CHUNK`] pieces. See [`open_regular`].
fn scan_file(detector: &Detector, path: &Path) -> io::Result<Vec<Found>> {
    let mut file = open_regular(path)?;
    detector.find_streaming(&mut file, SWEEP_CHUNK)
}

/// Whether `path` is still the directory `before` described: same device
/// and inode, not replaced by a symlink or anything else.
fn same_dir(path: &Path, before: &std::fs::Metadata) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|now| now.is_dir() && now.dev() == before.dev() && now.ino() == before.ino())
}

/// Scans everything under `dir` for canaries: the contents of every regular
/// file, the path of every entry below `dir` (so a canary in a name, or
/// spread over nested names, is found), and the target of every symlink.
/// Symlinks are not followed, and the contents of FIFOs, sockets and
/// devices are not read, so a sweep never hangs or leaves the tree. That
/// holds for entries that change while the sweep runs, as a daemon still
/// writing might make them: a file is opened without following a symlink
/// or blocking and must still be a regular file once open, and a directory
/// counts only if it is the same directory after it was listed. Anything
/// that fails those checks, or cannot be read, is reported as
/// [`Hit::Unreadable`]. Files are read in fixed-size pieces, so a large
/// file costs no more memory than a small one. Hits print without values;
/// [`assert_sweep_clean`] panics with them.
pub fn sweep_dir(dir: &Path, cs: &[Canary]) -> Vec<Hit> {
    let detector = Detector::new(cs);
    let shown = |p: &Path| detector.swept_path(dir, p);
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        // The root's own name was chosen by the caller. Below it, each
        // occurrence is reported once, at the deepest entry it reaches.
        if let (Ok(rel), Some(name)) = (path.strip_prefix(dir), path.file_name())
            && path != dir
        {
            let rel = rel.as_os_str().as_bytes();
            let name_start = rel.len().saturating_sub(name.as_bytes().len());
            for (found, end) in detector.find_ending(rel) {
                if end > name_start {
                    hits.push(Hit::Name {
                        path: shown(&path),
                        found,
                    });
                }
            }
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                hits.push(Hit::Unreadable {
                    path: shown(&path),
                    kind: e.kind(),
                });
                continue;
            }
        };
        if meta.is_dir() {
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    let mut children = Vec::new();
                    for entry in entries {
                        match entry {
                            Ok(e) => children.push(e.path()),
                            Err(e) => hits.push(Hit::Unreadable {
                                path: shown(&path),
                                kind: e.kind(),
                            }),
                        }
                    }
                    // Listed through a symlink swapped in after the check
                    // above: the names are not this tree's.
                    if !same_dir(&path, &meta) {
                        hits.push(Hit::Unreadable {
                            path: shown(&path),
                            kind: io::ErrorKind::Other,
                        });
                        continue;
                    }
                    children.sort();
                    stack.extend(children.into_iter().rev());
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path: shown(&path),
                    kind: e.kind(),
                }),
            }
        } else if meta.file_type().is_symlink() {
            match std::fs::read_link(&path) {
                Ok(target) => {
                    for found in detector.find(target.as_os_str().as_bytes()) {
                        hits.push(Hit::LinkTarget {
                            path: shown(&path),
                            found,
                        });
                    }
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path: shown(&path),
                    kind: e.kind(),
                }),
            }
        } else if meta.is_file() {
            match scan_file(&detector, &path) {
                Ok(found) => {
                    for found in found {
                        hits.push(Hit::Canary {
                            path: shown(&path),
                            found,
                        });
                    }
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path: shown(&path),
                    kind: e.kind(),
                }),
            }
        }
    }
    hits
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

    use super::{Detector, Found, encodings, same_dir, scan_file};
    use crate::canary::{canaries, fresh_seed};
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

    #[test]
    fn a_directory_counts_only_while_it_is_the_same_directory() {
        let home = TestHome::new();
        let dir = home.home().join("d");
        let moved = home.home().join("moved");
        std::fs::create_dir(&dir).unwrap();
        let before = std::fs::symlink_metadata(&dir).unwrap();
        assert!(same_dir(&dir, &before));

        // Moved away and replaced by a symlink to it: listing `dir` would
        // follow the link.
        std::fs::rename(&dir, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &dir).unwrap();
        assert!(!same_dir(&dir, &before));

        // Replaced by another directory. The original still exists, so its
        // inode cannot be handed out again.
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        assert!(!same_dir(&dir, &before));

        // The original, back in place, is the same directory.
        std::fs::remove_dir(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
        assert!(same_dir(&dir, &before));
    }
}
