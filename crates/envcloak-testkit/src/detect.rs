//! Finding canaries and their encodings in bytes, files and directories.

use std::collections::HashSet;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
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

/// Scans everything under `dir` for canaries: the contents of every regular
/// file, the path of every entry below `dir` (so a canary in a name, or
/// spread over nested names, is found), and the target of every symlink.
/// Symlinks are not followed, and the contents of FIFOs, sockets and
/// devices are not read, so a sweep never hangs or leaves the tree.
/// Anything unreadable is reported as [`Hit::Unreadable`]. Hits print
/// without values; [`assert_sweep_clean`] panics with them.
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
            match std::fs::read(&path) {
                Ok(bytes) => {
                    for found in detector.find(&bytes) {
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
