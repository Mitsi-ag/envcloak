//! Finding canaries and their encodings in bytes, files and directories.

use std::collections::HashSet;
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

/// One finding of [`sweep_dir`]. Holds no value bytes, but a `path` whose
/// name holds a canary does: do not print the path of a [`Hit::Name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hit {
    /// A canary, or one of its encodings, inside a file.
    Canary { path: PathBuf, found: Found },
    /// A canary in the name (the last component of `path`) of a file,
    /// directory, symlink or other entry.
    Name { path: PathBuf, found: Found },
    /// A canary in the target of the symlink at `path`, which the sweep
    /// does not follow.
    LinkTarget { path: PathBuf, found: Found },
    /// A file or directory the sweep could not read, so it cannot vouch for
    /// it. Make it readable before sweeping, or remove it.
    Unreadable {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
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
        self.matcher
            .find_overlapping_iter(haystack)
            .map(|m| {
                let (canary, encoding) = self.meta[m.pattern().as_usize()];
                Found {
                    label: self.labels[canary].clone(),
                    encoding,
                    offset: m.start(),
                }
            })
            .collect()
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
/// file, the name of every entry below `dir`, and the target of every
/// symlink. Symlinks are not followed, and the contents of FIFOs, sockets
/// and devices are not read, so a sweep never hangs or leaves the tree.
/// Anything unreadable is reported as [`Hit::Unreadable`].
pub fn sweep_dir(dir: &Path, cs: &[Canary]) -> Vec<Hit> {
    let detector = Detector::new(cs);
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        // The root's own name was chosen by the caller.
        if let Some(name) = path.file_name().filter(|_| path != dir) {
            for found in detector.find(name.as_bytes()) {
                hits.push(Hit::Name {
                    path: path.clone(),
                    found,
                });
            }
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                hits.push(Hit::Unreadable {
                    path,
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
                                path: path.clone(),
                                kind: e.kind(),
                            }),
                        }
                    }
                    children.sort();
                    stack.extend(children.into_iter().rev());
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path,
                    kind: e.kind(),
                }),
            }
        } else if meta.file_type().is_symlink() {
            match std::fs::read_link(&path) {
                Ok(target) => {
                    for found in detector.find(target.as_os_str().as_bytes()) {
                        hits.push(Hit::LinkTarget {
                            path: path.clone(),
                            found,
                        });
                    }
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path,
                    kind: e.kind(),
                }),
            }
        } else if meta.is_file() {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    for found in detector.find(&bytes) {
                        hits.push(Hit::Canary {
                            path: path.clone(),
                            found,
                        });
                    }
                }
                Err(e) => hits.push(Hit::Unreadable {
                    path,
                    kind: e.kind(),
                }),
            }
        }
    }
    hits
}
