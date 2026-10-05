//! Per-run limits and keyed de-duplication. No hash or value is report data.
use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;
use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;
use zeroize::Zeroize;
use crate::FileStamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition { Literal, Template, Manual }

/// Parser output. Names and values are untrusted, and never Debug output.
#[derive(Debug)]
pub struct Found {
    pub name: SecretBytes,
    pub value: Option<SecretBytes>,
    pub disposition: Disposition,
    pub range: Range<u64>,
    pub single_complete_line: bool,
    pub source: Source,
    pub stamp: Option<FileStamp>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Source { pub path: PathBuf }
impl std::fmt::Debug for Source {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { f.write_str("Source(..)") }
}
impl Default for Source { fn default()->Self { Self { path: PathBuf::new() } } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue { pub source: Source, pub reason: &'static str }

#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Found>,
    pub issues: Vec<Issue>,
    pub leftovers: Vec<Leftover>,
    pub files: u64,
    pub bytes: u64,
}
impl ScanReport {
    pub fn complete(&self)->bool { self.issues.is_empty() }
    pub(crate) fn issue(&mut self,path: impl Into<PathBuf>,reason:&'static str) {
        self.issues.push(Issue { source: Source { path:path.into() },reason });
    }
    pub(crate) fn append(&mut self,mut other:Self) {
        self.findings.append(&mut other.findings); self.issues.append(&mut other.issues);
        self.leftovers.append(&mut other.leftovers); self.files+=other.files; self.bytes+=other.bytes;
    }
}

/// A name-shaped candidate, never proof of ownership or permission to remove.
#[derive(Debug)]
pub struct Leftover { pub source: Source, pub inspection: &'static str }

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub bytes: u64,
    pub candidates: usize,
    pub occurrences: usize,
    pub files: usize,
    pub objects: usize,
}
impl Default for Budget {
    fn default()->Self { Self { bytes:1<<30,candidates:2_000_000,occurrences:4_000_000,files:10_000,objects:100_000 } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form { Raw, UrlPassword, DsnPassword, ConnPassword }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding { Raw, Json, Base64, Hex, Percent }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub source: Source,
    /// Raw file range. For JSON, this covers the token's escape sequences.
    pub range: Range<u64>,
    pub encoding: Encoding,
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
    pub occurrences: Vec<Occurrence>,
}

/// Kept until the scan finishes. Keyed hashes are local, never persisted.
pub struct Candidates {
    key: [u8;32],
    index: HashMap<[u8;32],usize>,
    entries: Vec<DistinctCandidate>,
    budget: Budget,
    occurrences: usize,
    limited: bool,
}
impl std::fmt::Debug for Candidates {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("Candidates").field("distinct",&self.entries.len()).field("limited",&self.limited).finish()
    }
}
impl Drop for Candidates {
    fn drop(&mut self) {
        self.key.zeroize();
        // Drain before freeing the table. Values are owned wiping buffers.
        for (mut digest,_) in self.index.drain() { digest.zeroize(); }
    }
}
impl Candidates {
    pub fn new(budget:Budget)->std::io::Result<Self> {
        let mut key=[0;32];
        getrandom::fill(&mut key).map_err(|_|std::io::ErrorKind::Other)?;
        Ok(Self { key,index:HashMap::new(),entries:Vec::new(),budget,occurrences:0,limited:false })
    }
    pub fn entries(&self)->&[DistinctCandidate] { &self.entries }
    pub fn limited(&self)->bool { self.limited }
    /// False means incomplete; already accepted occurrences remain available.
    pub fn insert(&mut self,c:Candidate)->bool {
        if self.limited || self.occurrences>=self.budget.occurrences { self.limited=true; return false; }
        let mut hasher=blake3::Hasher::new_keyed(&self.key);
        hasher.update(&[c.form as u8]);
        #[allow(clippy::disallowed_methods)]
        hasher.update(c.value.expose_secret());
        let digest=*hasher.finalize().as_bytes();
        if let Some(&i)=self.index.get(&digest) {
            self.entries[i].occurrences.push(c.occurrence);
        } else {
            if self.entries.len()>=self.budget.candidates { self.limited=true; return false; }
            let id=self.entries.len();
            self.index.insert(digest,id);
            self.entries.push(DistinctCandidate {id:id as u64,value:c.value,form:c.form,occurrences:vec![c.occurrence]});
        }
        self.occurrences+=1;
        true
    }
}
