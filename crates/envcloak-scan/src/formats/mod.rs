//! Explicit export profiles. Input streams, records and the unpublished batch
//! are bounded; callbacks run only after the complete document validates.
use crate::json::Node;
use envcloak_core::{SecretBuf, SecretBytes};
use std::io::Read;

mod bitwarden;
mod doppler;
mod infisical;
mod onepassword_csv;
mod stream;

pub const MAX_INPUT: usize = 16 << 20;
pub const MAX_FIELD: usize = 64 << 10;
pub const MAX_RECORD: usize = 256 << 10;
pub const MAX_RECORDS: usize = 10_000;
pub const MAX_ENTRIES: usize = 1_024;
pub const MAX_VALUES: usize = 256 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    BitwardenJson,
    OnePasswordCsv,
    DopplerJson,
    InfisicalJson,
    AwsCredentials,
    Dotenv,
}
impl Kind {
    pub const ALL: [Self; 6] = [
        Self::BitwardenJson,
        Self::OnePasswordCsv,
        Self::DopplerJson,
        Self::InfisicalJson,
        Self::AwsCredentials,
        Self::Dotenv,
    ];
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.token() == text)
    }
    pub fn token(self) -> &'static str {
        match self {
            Self::BitwardenJson => "bitwarden-json",
            Self::OnePasswordCsv => "1password-csv",
            Self::DopplerJson => "doppler-json",
            Self::InfisicalJson => "infisical-json",
            Self::AwsCredentials => "aws-credentials",
            Self::Dotenv => "dotenv",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    Invalid,
    Shape,
    Limit,
    Read,
}
impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid export syntax",
            Self::Shape => "unsupported export shape",
            Self::Limit => "export limit reached",
            Self::Read => "export read failed",
        })
    }
}
impl std::error::Error for FormatError {}
#[derive(Debug)]
pub struct Entry {
    pub record: u32,
    pub name: SecretBytes,
    pub value: SecretBytes,
}
impl Entry {
    /// Safe environment metadata for the shared importer. Values and labels
    /// shaped like credentials never become report names.
    #[allow(clippy::disallowed_methods)]
    pub fn env_name(&self) -> Option<String> {
        let text = std::str::from_utf8(secrecy::ExposeSecret::expose_secret(&self.name)).ok()?;
        if !valid_name(&self.name) || envcloak_policy::value_shaped(text) {
            return None;
        }
        Some(text.to_owned())
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FormatReport {
    pub records: usize,
    pub candidates: usize,
    /// Unsupported records or credential fields. These are not item counts.
    pub unsupported: usize,
    /// Fields that require an explicit name mapping or are templates/references.
    pub manual: usize,
}
#[derive(Default)]
struct Batch {
    report: FormatReport,
    entries: Vec<Entry>,
    bytes: usize,
}
impl Batch {
    fn record(&mut self) -> Result<(), FormatError> {
        if self.report.records == MAX_RECORDS {
            return Err(FormatError::Limit);
        }
        self.report.records += 1;
        Ok(())
    }
    fn add(&mut self, name: SecretBytes, value: SecretBytes) -> Result<(), FormatError> {
        if name.len() > 128 || name.is_empty() {
            self.report.manual += 1;
            return Ok(());
        }
        if self.entries.len() == MAX_ENTRIES
            || value.len() > MAX_FIELD
            || self.bytes + value.len() > MAX_VALUES
        {
            return Err(FormatError::Limit);
        }
        if !valid_name(&name) {
            self.report.manual += 1;
            return Ok(());
        }
        self.bytes += value.len();
        self.entries.push(Entry {
            record: self.report.records as u32,
            name,
            value,
        });
        Ok(())
    }
}
#[allow(clippy::disallowed_methods)] // Inspect a candidate name, never print it.
fn valid_name(name: &SecretBytes) -> bool {
    std::str::from_utf8(secrecy::ExposeSecret::expose_secret(name))
        .ok()
        .is_some_and(|s| envcloak_policy::EnvName::new(s).is_ok())
}
fn text(node: Node) -> Result<SecretBytes, FormatError> {
    if let Node::Text(t) = node {
        Ok(t.value)
    } else {
        Err(FormatError::Shape)
    }
}
fn object(node: Node) -> Result<Vec<(crate::json::Text, Node)>, FormatError> {
    if let Node::Object(fields) = node {
        Ok(fields)
    } else {
        Err(FormatError::Shape)
    }
}
fn take(fields: &mut Vec<(crate::json::Text, Node)>, name: &[u8]) -> Option<Node> {
    let i = fields.iter().position(|(k, _)| k.value.ct_eq(name))?;
    Some(fields.remove(i).1)
}
fn scalar(node: &Node, bytes: &[u8]) -> bool {
    matches!(node,Node::Scalar(v) if v.ct_eq(bytes))
}
fn optional_text(node: Option<Node>) -> Result<Option<SecretBytes>, FormatError> {
    match node {
        None => Ok(None),
        Some(n) if scalar(&n, b"null") => Ok(None),
        Some(n) => text(n).map(Some),
    }
}
/// No callback occurs on error, even for a valid prefix followed by bad input.
/// The callback owns wiping storage. No I/O other than reading is performed.
pub fn parse(
    kind: Kind,
    reader: impl Read,
    emit: &mut impl FnMut(Entry),
) -> Result<FormatReport, FormatError> {
    let mut input = stream::Input::new(reader);
    let mut batch = Batch::default();
    match kind {
        Kind::DopplerJson => doppler::parse(&mut input, &mut batch)?,
        Kind::InfisicalJson => infisical::parse(&mut input, &mut batch)?,
        Kind::BitwardenJson => bitwarden::parse(&mut input, &mut batch)?,
        Kind::OnePasswordCsv => onepassword_csv::parse(&mut input, &mut batch)?,
        Kind::Dotenv | Kind::AwsCredentials => legacy(kind, &mut input, &mut batch)?,
    }
    input.space()?;
    if input.peek()?.is_some() {
        return Err(FormatError::Invalid);
    }
    batch.report.candidates = batch.entries.len();
    for entry in batch.entries {
        emit(entry);
    }
    Ok(batch.report)
}
fn legacy(
    kind: Kind,
    input: &mut stream::Input<impl Read>,
    batch: &mut Batch,
) -> Result<(), FormatError> {
    let mut bytes = SecretBuf::with_capacity(4096);
    while let Some(b) = input.next()? {
        stream::append(&mut bytes, &[b], crate::MAX_DOTENV)?;
    }
    let bytes = bytes.freeze();
    if kind == Kind::Dotenv {
        for entry in crate::parse_dotenv(&bytes).map_err(|_| FormatError::Invalid)? {
            batch.record()?;
            if entry.kind == crate::EntryKind::Plain {
                batch.add(
                    SecretBytes::copy_from(entry.name.as_str().as_bytes()),
                    entry.value,
                )?;
            } else {
                batch.report.manual += 1;
            }
        }
    } else {
        let report = crate::aws::parse_aws(&bytes);
        if !report.complete() {
            return Err(FormatError::Invalid);
        }
        for found in report.findings {
            batch.record()?;
            batch.add(found.name, found.value.ok_or(FormatError::Invalid)?)?;
        }
    }
    Ok(())
}
/// Read only the held regular file, checking its identity after streaming.
pub fn parse_file(
    kind: Kind,
    root: &crate::ScanRoot,
    rel: &std::path::Path,
    emit: &mut impl FnMut(Entry),
) -> Result<FormatReport, FormatError> {
    let (dir, name) = root.open_parent(rel).map_err(|_| FormatError::Read)?;
    let (mut file, meta) =
        crate::root::open_file(&dir, &name, MAX_INPUT).map_err(|_| FormatError::Read)?;
    let before = crate::FileStamp::of(&meta);
    let mut staged = Vec::new();
    let report = parse(kind, &mut file, &mut |e| staged.push(e))?;
    let after = file.metadata().map_err(|_| FormatError::Read)?;
    if before != crate::FileStamp::of(&after) {
        return Err(FormatError::Read);
    }
    for entry in staged {
        emit(entry);
    }
    Ok(report)
}
