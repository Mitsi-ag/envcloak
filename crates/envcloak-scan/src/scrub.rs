//! Confirmed byte ranges, conservative per-file planning and bounded previews.
//! Matches come only from the daemon. Counts and unsupported readings confer
//! no rewrite authority; conflicting spans refuse the affected file.
use crate::FileStamp;
use crate::candidates::{Candidate, Encoding};
use crate::source::ConfigFormat;
use envcloak_core::SecretBytes;
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::ops::Range;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct Match {
    pub candidate: u64,
    pub item: String,
    pub slug: String,
}
impl std::fmt::Debug for Match {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Match(..)")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Edit {
    pub range: Range<u64>,
    pub item: String,
    pub slug: String,
    pub encoding: Encoding,
}
impl std::fmt::Debug for Edit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Edit(..)")
    }
}
impl Edit {
    pub fn marker(&self) -> String {
        format!("[envcloak:redacted:{}]", self.slug)
    }
}
pub struct FilePlan {
    pub path: PathBuf,
    pub stamp: Option<FileStamp>,
    pub edits: Vec<Edit>,
    pub reasons: Vec<&'static str>,
}
impl std::fmt::Debug for FilePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FilePlan(..)")
    }
}
#[derive(Debug)]
pub struct ScrubPlan {
    pub files: Vec<FilePlan>,
}
impl ScrubPlan {
    pub fn complete(&self) -> bool {
        self.files.iter().all(|f| f.reasons.is_empty())
    }
}
impl FilePlan {
    pub fn refuse(&mut self, reason: &'static str) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}
pub fn plan(candidates: &[&Candidate], matches: &[Match]) -> ScrubPlan {
    let mut files: BTreeMap<PathBuf, FilePlan> = BTreeMap::new();
    let mut matched: BTreeMap<u64, Vec<&Match>> = BTreeMap::new();
    for m in matches {
        matched.entry(m.candidate).or_default().push(m);
    }
    for c in candidates {
        let Some(associations) = matched.get(&c.id) else {
            continue;
        };
        let o = &c.occurrence;
        let f = files
            .entry(o.source.path.clone())
            .or_insert_with(|| FilePlan {
                path: o.source.path.clone(),
                stamp: o.stamp,
                edits: Vec::new(),
                reasons: Vec::new(),
            });
        if o.stamp.is_none() || o.stamp != f.stamp {
            f.refuse("binding");
        }
        if !o.rewritable || o.source.object.is_some() {
            f.refuse("unsupported");
        }
        if o.range.start >= o.range.end || f.stamp.is_some_and(|s| o.range.end > s.size) {
            f.refuse("bounds");
        }
        for m in associations {
            // Marker text must be valid inside a JSON string, with no controls.
            if m.slug.is_empty()
                || m.slug.len() > 128
                || !m
                    .slug
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
            {
                f.refuse("invalid_slug");
                continue;
            }
            f.edits.push(Edit {
                range: o.range.clone(),
                item: m.item.clone(),
                slug: m.slug.clone(),
                encoding: o.encoding,
            });
        }
    }
    for f in files.values_mut() {
        f.edits.sort_by(|a, b| {
            (a.range.start, a.range.end, &a.item, &a.slug).cmp(&(
                b.range.start,
                b.range.end,
                &b.item,
                &b.slug,
            ))
        });
        f.edits.dedup();
        if f.edits
            .windows(2)
            .any(|w| w[0].range.end > w[1].range.start)
        {
            f.refuse("overlap");
        }
    }
    ScrubPlan {
        files: files.into_values().collect(),
    }
}

/// In-memory oracle seam. No filesystem changes or daemon calls.
pub fn preview(
    plan: &FilePlan,
    bytes: &[u8],
    format: ConfigFormat,
) -> Result<SecretBytes, &'static str> {
    let mut out = Zeroizing::new(Vec::new());
    rewrite(plan, &mut std::io::Cursor::new(bytes), &mut *out, format)?;
    Ok(SecretBytes::copy_from(&out))
}

/// Stream a complete, immutable source into a writer. JSON and JSONL are
/// checked before each rewritten document is written. Other formats are raw.
pub fn rewrite(
    plan: &FilePlan,
    input: &mut dyn Read,
    output: &mut dyn Write,
    format: ConfigFormat,
) -> Result<(), &'static str> {
    if !plan.reasons.is_empty() {
        return Err("refused");
    }
    let stamp = plan.stamp.ok_or("binding")?;
    if matches!(format, ConfigFormat::Json | ConfigFormat::Jsonl) {
        let mut reader = WipingReader {
            input,
            buffer: Zeroizing::new([0; 8192]),
            start: 0,
            end: 0,
        };
        let mut base = 0u64;
        let mut next = 0;
        let mut line = Zeroizing::new(Vec::with_capacity(crate::transcript::MAX_LINE + 1));
        loop {
            line.as_mut_slice().zeroize();
            line.clear();
            if format == ConfigFormat::Json {
                reader
                    .by_ref()
                    .take(crate::transcript::MAX_LINE as u64 + 1)
                    .read_to_end(&mut line)
                    .map_err(|_| "unreadable")?;
            } else {
                reader
                    .by_ref()
                    .take(crate::transcript::MAX_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                    .map_err(|_| "unreadable")?;
            }
            if line.is_empty() {
                break;
            }
            if line.len() > crate::transcript::MAX_LINE {
                return Err("line_too_large");
            }
            let end = base.checked_add(line.len() as u64).ok_or("bounds")?;
            let first = next;
            while next < plan.edits.len() && plan.edits[next].range.start < end {
                next += 1;
            }
            let capacity = line
                .len()
                .checked_add(
                    plan.edits[first..next]
                        .iter()
                        .map(|e| e.marker().len())
                        .sum::<usize>(),
                )
                .ok_or("bounds")?;
            let mut rewritten = Zeroizing::new(Vec::with_capacity(capacity));
            rewrite_slice(&line, base, &plan.edits[first..next], &mut rewritten)?;
            if line.iter().any(|b| !b.is_ascii_whitespace()) {
                crate::json::parse(&line).map_err(|_| "invalid_json")?;
                crate::json::parse(&rewritten).map_err(|_| "invalid_json")?;
            }
            output.write_all(&rewritten).map_err(|_| "write_failed")?;
            base = end;
        }
        if base != stamp.size || next != plan.edits.len() {
            return Err("binding");
        }
    } else {
        let mut position = 0;
        for edit in &plan.edits {
            if edit.range.start < position || edit.range.end > stamp.size {
                return Err("bounds");
            }
            copy_exact(input, output, edit.range.start - position)?;
            copy_exact(
                input,
                &mut std::io::sink(),
                edit.range.end - edit.range.start,
            )?;
            output
                .write_all(edit.marker().as_bytes())
                .map_err(|_| "write_failed")?;
            position = edit.range.end;
        }
        copy_exact(input, output, stamp.size - position)?;
        let mut extra = [0];
        if input.read(&mut extra).map_err(|_| "unreadable")? != 0 {
            return Err("binding");
        }
    }
    Ok(())
}
fn copy_exact(
    input: &mut dyn Read,
    output: &mut dyn Write,
    mut size: u64,
) -> Result<(), &'static str> {
    let mut buf = Zeroizing::new([0u8; 65536]);
    while size > 0 {
        let len = size.min(buf.len() as u64) as usize;
        input.read_exact(&mut buf[..len]).map_err(|_| "binding")?;
        output.write_all(&buf[..len]).map_err(|_| "write_failed")?;
        size -= len as u64;
    }
    Ok(())
}
fn rewrite_slice(
    bytes: &[u8],
    base: u64,
    edits: &[Edit],
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_text")?;
    let mut pos = 0;
    for e in edits {
        let a = usize::try_from(e.range.start.checked_sub(base).ok_or("bounds")?)
            .map_err(|_| "bounds")?;
        let b = usize::try_from(e.range.end.checked_sub(base).ok_or("bounds")?)
            .map_err(|_| "bounds")?;
        if a < pos
            || a >= b
            || b > bytes.len()
            || !text.is_char_boundary(a)
            || !text.is_char_boundary(b)
        {
            return Err("bounds");
        }
        // Both endpoints must lie on decoded JSON-string character boundaries.
        if !json_boundary(bytes, a) || !json_boundary(bytes, b) {
            return Err("bounds");
        }
        out.extend_from_slice(&bytes[pos..a]);
        out.extend_from_slice(e.marker().as_bytes());
        pos = b;
    }
    out.extend_from_slice(&bytes[pos..]);
    Ok(())
}
fn json_boundary(bytes: &[u8], at: usize) -> bool {
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        if in_string && i == at {
            return true;
        }
        match bytes[i] {
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'\\' if in_string => {
                i += if bytes.get(i + 1) == Some(&b'u') {
                    6
                } else {
                    2
                };
            }
            _ => i += 1,
        }
        if i > at {
            return false;
        }
    }
    false
}

/// A source opened without following links, retained through validation,
/// backup and replacement. The caller must commit its encrypted backup first.
pub struct OpenFile {
    root: crate::ScanRoot,
    rel: PathBuf,
    file: std::fs::File,
    stamp: FileStamp,
}
impl std::fmt::Debug for OpenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenFile(..)")
    }
}
impl OpenFile {
    pub fn open(plan: &FilePlan) -> Result<Self, &'static str> {
        if !plan.reasons.is_empty() {
            return Err("refused");
        }
        let stamp = plan.stamp.ok_or("binding")?;
        let (root, rel, file, actual) = open_source(&plan.path)?;
        if actual != stamp {
            return Err("changed");
        }
        crate::atomic::check_modifiable(&root, &rel, &stamp).map_err(|e| e.token())?;
        Ok(Self {
            root,
            rel,
            file,
            stamp,
        })
    }
    pub fn reader(&mut self) -> Result<&mut std::fs::File, &'static str> {
        use std::io::Seek;
        self.check()?;
        self.file.rewind().map_err(|_| "unreadable")?;
        Ok(&mut self.file)
    }
    pub fn check(&self) -> Result<(), &'static str> {
        if FileStamp::of(&self.file.metadata().map_err(|_| "unreadable")?) != self.stamp {
            return Err("changed");
        }
        crate::atomic::check_modifiable(&self.root, &self.rel, &self.stamp).map_err(|e| e.token())
    }
    pub fn validate(&mut self, plan: &FilePlan, format: ConfigFormat) -> Result<(), &'static str> {
        rewrite(plan, self.reader()?, &mut std::io::sink(), format)?;
        self.check()
    }
    pub fn apply(
        &mut self,
        plan: &FilePlan,
        format: ConfigFormat,
    ) -> Result<[u8; 32], &'static str> {
        use std::io::Seek;
        self.check()?;
        self.file.rewind().map_err(|_| "unreadable")?;
        let file = &mut self.file;
        let mut cause = None;
        let result = crate::atomic::scrub_stream(
            &self.root,
            &self.rel,
            &self.stamp,
            &mut |w| {
                rewrite(plan, file, w, format).map_err(|reason| {
                    cause = Some(reason);
                    crate::ModifyErrorKind::Changed
                })
            },
            &mut |at| match at {
                crate::Inside::Staged => crate::pause_point("scrub_staged"),
                crate::Inside::Checked => crate::pause_point("scrub_checked"),
                crate::Inside::Swapped => crate::pause_point("scrub_renamed"),
                _ => (),
            },
        );
        result.map_err(|e| cause.unwrap_or(e.kind.token()))
    }
}
fn open_source(
    path: &std::path::Path,
) -> Result<(crate::ScanRoot, PathBuf, std::fs::File, FileStamp), &'static str> {
    let parent = path.parent().ok_or("invalid_path")?;
    let root = crate::sources::absolute_root(parent).map_err(|e| e.token())?;
    let rel = PathBuf::from(path.file_name().ok_or("invalid_path")?);
    let (dir, name) = root.open_parent(&rel).map_err(|e| e.token())?;
    let (file, m) = crate::root::open_file(&dir, &name, usize::MAX).map_err(|e| e.token())?;
    let stamp = FileStamp::of(&m);
    if stamp.dev != root.dev() {
        return Err("mount_point");
    }
    if stamp.nlink != 1 {
        return Err("hard_linked");
    }
    Ok((root, rel, file, stamp))
}
/// Digest for explicit unrecorded recovery. It is checked again by restore.
pub fn current_digest(path: &std::path::Path) -> Result<[u8; 32], &'static str> {
    let (root, rel, mut file, stamp) = open_source(path)?;
    let (dir, _) = root.open_parent(&rel).map_err(|e| e.token())?;
    crate::atomic::digest_of(&mut file, &stamp, &dir).map_err(|e| e.token())
}

/// Discover possible restore leftovers beside selected files, including missing
/// leaves, without reading any contents. A name never grants cleanup authority.
pub fn inspect_leftovers(sources: &[crate::source::ConfigSource]) -> crate::candidates::ScanReport {
    let mut report = crate::candidates::ScanReport::default();
    crate::sources::walk_sources(
        sources,
        crate::candidates::Budget::default(),
        &mut report,
        |_, _, _, _, _, _| {},
    );
    report
}

// BufReader's ordinary allocation would retain plaintext. This bounded buffer
// is wiped on every refill and on every exit, including a read failure.
struct WipingReader<'a> {
    input: &'a mut dyn Read,
    buffer: Zeroizing<[u8; 8192]>,
    start: usize,
    end: usize,
}
impl BufRead for WipingReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.start == self.end {
            self.buffer.zeroize();
            self.end = self.input.read(&mut *self.buffer)?;
            self.start = 0;
        }
        Ok(&self.buffer[self.start..self.end])
    }
    fn consume(&mut self, n: usize) {
        self.start += n.min(self.end - self.start);
    }
}
impl Read for WipingReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self.fill_buf()?;
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        self.consume(n);
        Ok(n)
    }
}
