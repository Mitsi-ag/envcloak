//! Per-run limits and keyed de-duplication. No hash or value is report data.
use crate::FileStamp;
use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Literal,
    Template,
    Manual,
}

/// Parser output. Names and values are untrusted, and never Debug output.
#[derive(Debug)]
pub struct Found {
    pub name: SecretBytes,
    pub value: Option<SecretBytes>,
    pub disposition: Disposition,
    /// True only for a schema-level include directive, never a binding name.
    pub env_file: bool,
    pub range: Range<u64>,
    pub single_complete_line: bool,
    pub source: Source,
    pub stamp: Option<FileStamp>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Source {
    pub path: PathBuf,
    pub object: Option<String>,
}
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Source(..)")
    }
}
impl Default for Source {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            object: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub source: Source,
    pub reason: &'static str,
}

#[derive(Default)]
pub struct ScanReport {
    pub findings: Vec<Found>,
    pub issues: Vec<Issue>,
    /// Existing stores deliberately outside this scanner's coverage.
    /// These notes do not make an otherwise successful scan incomplete.
    pub notes: Vec<Issue>,
    pub leftovers: Vec<Leftover>,
    /// The effective format used by transcript discovery for each opened file.
    /// Consumers must not infer a different grammar from its extension or parent.
    pub transcript_formats: std::collections::BTreeMap<PathBuf, crate::source::ConfigFormat>,
    pub files: u64,
    /// Budget charged: successful bytes, or the allowance of a failed config read.
    pub bytes: u64,
}
impl std::fmt::Debug for ScanReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanReport")
            .field("findings", &self.findings.len())
            .field("issues", &self.issues.len())
            .field("notes", &self.notes.len())
            .field("leftovers", &self.leftovers.len())
            .field("transcript_formats", &self.transcript_formats.len())
            .field("files", &self.files)
            .field("bytes", &self.bytes)
            .finish()
    }
}
impl ScanReport {
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
    pub(crate) fn issue(&mut self, path: impl Into<PathBuf>, reason: &'static str) {
        let path = path.into();
        if self
            .issues
            .iter()
            .any(|i| i.reason == reason && i.source.path == path)
        {
            return;
        }
        self.issues.push(Issue {
            source: Source { path, object: None },
            reason,
        });
    }
    pub(crate) fn append(&mut self, mut other: Self) {
        self.findings.append(&mut other.findings);
        for issue in other.issues {
            if !self.issues.contains(&issue) {
                self.issues.push(issue);
            }
        }
        self.notes.append(&mut other.notes);
        self.leftovers.append(&mut other.leftovers);
        self.transcript_formats
            .append(&mut other.transcript_formats);
        self.files += other.files;
        self.bytes += other.bytes;
    }
}

/// A name-shaped candidate, never proof of ownership or permission to remove.
#[derive(Debug)]
pub struct Leftover {
    pub source: Source,
    pub inspection: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub bytes: u64,
    pub candidates: usize,
    /// Maximum emissions accepted, independent of retention mode.
    pub occurrences: usize,
    /// Maximum retained ranges, or (candidate, source) pairs in count mode.
    pub retained: usize,
    pub files: usize,
    pub objects: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            bytes: 1 << 30,
            candidates: 2_000_000,
            occurrences: 4_000_000,
            retained: 4_000_000,
            files: 10_000,
            objects: 100_000,
        }
    }
}

impl Budget {
    /// Count-only callers allow repeated readings without retaining each range.
    /// At two readings per token this covers the measured 12,700 tokens/MiB
    /// through the 1 GiB byte limit; distinct candidates remain independently bounded.
    pub fn for_counts() -> Self {
        Self {
            occurrences: 128_000_000,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form {
    Raw,
    UrlPassword,
    DsnPassword,
    ConnPassword,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Raw,
    Json,
    Base64,
    Hex,
    Percent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub source: Source,
    /// Raw file range. For JSON, this covers the token's escape sequences.
    pub range: Range<u64>,
    pub encoding: Encoding,
    pub stamp: Option<FileStamp>,
    /// False for a decoded run that needs a structured rewrite, or git data.
    pub rewritable: bool,
}

#[derive(Debug)]
pub struct Candidate {
    pub id: u64,
    pub value: SecretBytes,
    pub form: Form,
    pub occurrence: Occurrence,
}

#[derive(Debug)]
pub struct DistinctCandidate {
    pub id: u64,
    pub value: SecretBytes,
    pub form: Form,
    /// Populated by `Candidates::new`, empty in count-only mode.
    pub occurrences: Vec<Occurrence>,
    /// Populated by `Candidates::counted`, without ranges or rewrite authority.
    /// A Git object is a separate source from another object at the same path.
    pub counts: HashMap<Source, u64>,
}

/// Kept until the scan finishes. Keyed hashes are local, never persisted.
pub struct Candidates {
    key: [u8; 32],
    index: HashMap<[u8; 32], usize>,
    entries: Vec<DistinctCandidate>,
    budget: Budget,
    occurrences: usize,
    retained: usize,
    count_only: bool,
    limited: bool,
}
impl std::fmt::Debug for Candidates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidates")
            .field("distinct", &self.entries.len())
            .field("limited", &self.limited)
            .finish()
    }
}
impl Drop for Candidates {
    fn drop(&mut self) {
        self.key.zeroize();
        // Drain before freeing the table. Values are owned wiping buffers.
        for (mut digest, _) in self.index.drain() {
            digest.zeroize();
        }
    }
}
impl Candidates {
    pub fn new(budget: Budget) -> std::io::Result<Self> {
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| std::io::ErrorKind::Other)?;
        Ok(Self {
            key,
            index: HashMap::new(),
            entries: Vec::new(),
            budget,
            occurrences: 0,
            retained: 0,
            count_only: false,
            limited: false,
        })
    }
    /// Aggregate per candidate and file/object for doctor; retain no ranges.
    /// Use the same `Budget::for_counts()` for the stream and this collector.
    pub fn counted(budget: Budget) -> std::io::Result<Self> {
        let mut result = Self::new(budget)?;
        result.count_only = true;
        Ok(result)
    }
    pub fn entries(&self) -> &[DistinctCandidate] {
        &self.entries
    }
    /// Transfer wiping values to a bounded matching caller, then wipe the index.
    pub fn into_entries(mut self) -> Vec<DistinctCandidate> {
        std::mem::take(&mut self.entries)
    }
    pub fn limited(&self) -> bool {
        self.limited
    }
    /// False means incomplete; already accepted occurrences remain available.
    pub fn insert(&mut self, c: Candidate) -> bool {
        if self.limited || self.occurrences >= self.budget.occurrences {
            self.limited = true;
            return false;
        }
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(&[c.form as u8]);
        #[allow(clippy::disallowed_methods)]
        hasher.update(c.value.expose_secret());
        let digest = *hasher.finalize().as_bytes();
        let existing = self.index.get(&digest).copied();
        let new_record = !self.count_only
            || existing.is_none_or(|i| !self.entries[i].counts.contains_key(&c.occurrence.source));
        if (new_record && self.retained >= self.budget.retained)
            || (existing.is_none() && self.entries.len() >= self.budget.candidates)
        {
            self.limited = true;
            return false;
        }
        let i = if let Some(i) = existing {
            i
        } else {
            let id = self.entries.len();
            self.index.insert(digest, id);
            self.entries.push(DistinctCandidate {
                id: id as u64,
                value: c.value,
                form: c.form,
                occurrences: Vec::new(),
                counts: HashMap::new(),
            });
            id
        };
        if self.count_only {
            *self.entries[i]
                .counts
                .entry(c.occurrence.source)
                .or_default() += 1;
        } else {
            self.entries[i].occurrences.push(c.occurrence);
        }
        self.retained += usize::from(new_record);
        self.occurrences += 1;
        true
    }
}
