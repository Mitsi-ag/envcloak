//! Streaming token extraction, with raw-file spans retained across JSON escapes.
use crate::ScanError;
use crate::candidates::{Budget, Candidate, Encoding, Form, Issue, Occurrence, Source};
use crate::source::ConfigFormat;
use base64::Engine;
use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;
use std::fs::File;
use std::io::Read;
use zeroize::Zeroizing;

pub const MAX_LINE: usize = 8 * 1024 * 1024;
pub const MAX_CANDIDATE: usize = 4096;
#[derive(Debug, Default)]
pub struct StreamReport {
    pub bytes: u64,
    pub candidates: u64,
    pub not_scanned: u64,
    pub issues: Vec<Issue>,
}
impl StreamReport {
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
    pub(crate) fn issue(&mut self, source: &Source, reason: &'static str) {
        if !self
            .issues
            .iter()
            .any(|i| i.reason == reason && i.source == *source)
        {
            self.issues.push(Issue {
                source: source.clone(),
                reason,
            });
        }
    }
}

/// The caller opens the file through the scanner's no-follow rules.
pub fn stream_candidates(
    file: &mut File,
    emit: &mut impl FnMut(Candidate),
) -> Result<StreamReport, ScanError> {
    scan_reader(
        file,
        ConfigFormat::Jsonl,
        Source::default(),
        Budget::default(),
        &mut |c| {
            emit(c);
            true
        },
    )
}

/// `emit` returning false stops the run visibly, preserving accepted ranges.
#[allow(clippy::disallowed_methods)] // Bounded buffers exposed only to token parsing.
pub fn scan_reader(
    reader: &mut impl Read,
    format: ConfigFormat,
    source: Source,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> Result<StreamReport, ScanError> {
    let mut report = StreamReport::default();
    let json = format == ConfigFormat::Jsonl;
    let cap = if json { MAX_LINE } else { MAX_CANDIDATE };
    let mut buffer = SecretBuf::with_capacity(cap.min(8192));
    let mut chunk = Zeroizing::new([0u8; 32768]);
    let mut start = 0u64;
    let mut skipped = false;
    let mut stopped = false;
    let mut exhausted = false;
    loop {
        let remaining = budget.bytes.saturating_sub(report.bytes);
        if remaining == 0 {
            exhausted = true;
            report.issue(&source, "byte_budget");
            break;
        }
        let want = remaining.min(chunk.len() as u64) as usize;
        let n = match reader.read(&mut chunk[..want]) {
            Ok(n) => n,
            Err(_) => {
                stopped = true;
                report.issue(&source, "unreadable");
                break;
            }
        };
        if n == 0 {
            break;
        }
        let chunk_start = report.bytes;
        report.bytes += n as u64;
        for (i, &b) in chunk[..n].iter().enumerate() {
            let boundary = if json { b == b'\n' } else { delimiter(b) };
            if boundary {
                if !skipped && !buffer.is_empty() {
                    if json {
                        stopped = !json_line(
                            buffer.expose_secret(),
                            start,
                            &source,
                            &mut report,
                            budget,
                            emit,
                        );
                    } else {
                        stopped = !token(
                            buffer.expose_secret(),
                            start,
                            None,
                            &source,
                            Encoding::Raw,
                            &mut report,
                            budget,
                            emit,
                        );
                    }
                }
                buffer.clear();
                skipped = false;
                start = chunk_start + i as u64 + 1;
                if stopped {
                    break;
                }
            } else if !skipped {
                if buffer.len() == cap {
                    report.not_scanned += 1;
                    report.issue(
                        &source,
                        if json {
                            "line_too_large"
                        } else {
                            "token_too_large"
                        },
                    );
                    buffer.clear();
                    skipped = true;
                } else {
                    if buffer.len() == buffer.capacity() {
                        buffer.grow((buffer.capacity() * 2).min(cap));
                    }
                    let _ = buffer.extend(&[b]);
                }
            }
        }
        if stopped {
            break;
        }
    }
    if !stopped && !exhausted && !skipped && !buffer.is_empty() {
        if json {
            json_line(
                buffer.expose_secret(),
                start,
                &source,
                &mut report,
                budget,
                emit,
            );
        } else {
            token(
                buffer.expose_secret(),
                start,
                None,
                &source,
                Encoding::Raw,
                &mut report,
                budget,
                emit,
            );
        }
    }
    Ok(report)
}
fn delimiter(b: u8) -> bool {
    b.is_ascii_whitespace()
        || b < 32
        || matches!(
            b,
            b'"' | b'\'' | b',' | b'{' | b'}' | b'[' | b']' | b';' | b'<' | b'>'
        )
}
fn json_line(
    bytes: &[u8],
    base: u64,
    source: &Source,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    let node = match crate::json::parse(bytes) {
        Ok(n) => n,
        Err(()) => {
            report.not_scanned += 1;
            report.issue(source, "invalid_json");
            return true;
        }
    };
    json_tokens(&node, base, source, report, budget, emit)
}
#[allow(clippy::disallowed_methods)] // JSON parser strings are wiping buffers.
fn json_tokens(
    node: &crate::json::Node,
    base: u64,
    source: &Source,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    match node {
        crate::json::Node::Text(t) => {
            let bytes = t.value.expose_secret();
            let mut start = 0;
            for i in 0..=bytes.len() {
                if i == bytes.len() || delimiter(bytes[i]) {
                    if i > start
                        && !token(
                            &bytes[start..i],
                            base,
                            Some(&t.offsets[start..=i]),
                            source,
                            Encoding::Json,
                            report,
                            budget,
                            emit,
                        )
                    {
                        return false;
                    }
                    start = i + 1;
                }
            }
        }
        crate::json::Node::Object(fields) => {
            for (key, v) in fields {
                if !text_tokens(key, base, source, report, budget, emit)
                    || !json_tokens(v, base, source, report, budget, emit)
                {
                    return false;
                }
            }
        }
        crate::json::Node::Array(values) => {
            for v in values {
                if !json_tokens(v, base, source, report, budget, emit) {
                    return false;
                }
            }
        }
        crate::json::Node::Scalar => {}
    }
    true
}
#[allow(clippy::disallowed_methods)]
fn text_tokens(
    t: &crate::json::Text,
    base: u64,
    source: &Source,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    let bytes = t.value.expose_secret();
    let mut start = 0;
    for i in 0..=bytes.len() {
        if i == bytes.len() || delimiter(bytes[i]) {
            if i > start
                && !token(
                    &bytes[start..i],
                    base,
                    Some(&t.offsets[start..=i]),
                    source,
                    Encoding::Json,
                    report,
                    budget,
                    emit,
                )
            {
                return false;
            }
            start = i + 1;
        }
    }
    true
}
#[allow(clippy::too_many_arguments)]
fn token(
    bytes: &[u8],
    base: u64,
    map: Option<&[usize]>,
    source: &Source,
    encoding: Encoding,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    token_reading(
        bytes, base, map, source, encoding, report, budget, emit, true,
    )
}
#[allow(clippy::too_many_arguments)]
fn token_reading(
    bytes: &[u8],
    base: u64,
    map: Option<&[usize]>,
    source: &Source,
    encoding: Encoding,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
    assignment: bool,
) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        report.not_scanned += 1;
        report.issue(source, "invalid_text");
        return true;
    };
    if bytes.len() > MAX_CANDIDATE {
        report.not_scanned += 1;
        report.issue(source, "token_too_large");
        return true;
    }
    // An assignment includes its RHS as a second token without losing a
    // padded base64 run. The whole reading stays, for URL/DSN filtering.
    if let Some(eq) = bytes.iter().position(|b| *b == b'=') {
        if assignment
            && eq + 1 < bytes.len()
            && bytes[..eq]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            let next = map.map(|m| &m[eq + 1..]);
            if !token_reading(
                &bytes[eq + 1..],
                if map.is_some() {
                    base
                } else {
                    base + eq as u64 + 1
                },
                next,
                source,
                encoding,
                report,
                budget,
                emit,
                false,
            ) {
                return false;
            }
        }
    }
    if text.chars().count() < 16 {
        return true;
    }
    let range = if let Some(m) = map {
        base + m[0] as u64..base + m[m.len() - 1] as u64
    } else {
        base..base + bytes.len() as u64
    };
    let occurrence = Occurrence {
        source: source.clone(),
        range,
        encoding,
        stamp: None,
        rewritable: true,
    };
    if !send(
        SecretBytes::copy_from(bytes),
        occurrence.clone(),
        report,
        budget,
        emit,
    ) {
        return false;
    }
    for (value, form) in decoded(bytes) {
        let mut at = occurrence.clone();
        at.encoding = form;
        at.rewritable = false;
        if !decoded_tokens(&value, &at, report, budget, emit)
            || !send(value, at, report, budget, emit)
        {
            return false;
        }
    }
    true
}
#[allow(clippy::disallowed_methods)] // Tokens inside an encoded run retain its whole raw span.
fn decoded_tokens(
    value: &SecretBytes,
    at: &Occurrence,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    let bytes = value.expose_secret();
    let mut start = 0;
    for end in 0..=bytes.len() {
        if end == bytes.len() || delimiter(bytes[end]) {
            if (start != 0 || end != bytes.len()) && end > start {
                let part = &bytes[start..end];
                if std::str::from_utf8(part).is_ok_and(|s| s.chars().count() >= 16)
                    && !send(
                        SecretBytes::copy_from(part),
                        at.clone(),
                        report,
                        budget,
                        emit,
                    )
                {
                    return false;
                }
            }
            start = end + 1;
        }
    }
    true
}

fn send(
    value: SecretBytes,
    occurrence: Occurrence,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    if report.candidates >= budget.occurrences as u64 {
        report.issue(&occurrence.source, "occurrence_budget");
        return false;
    }
    let source = occurrence.source.clone();
    let id = report.candidates;
    report.candidates += 1;
    if !emit(Candidate {
        id,
        value,
        form: Form::Raw,
        occurrence,
    }) {
        report.issue(&source, "candidate_budget");
        return false;
    }
    true
}
fn decoded(bytes: &[u8]) -> Vec<(SecretBytes, Encoding)> {
    let mut out = Vec::new();
    if bytes.len() % 2 == 0 && bytes.iter().all(|b| crate::json::hex(*b).is_some()) {
        let mut b = SecretBuf::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            let _ = b.extend(&[(crate::json::hex(pair[0]).unwrap_or(0) << 4)
                | crate::json::hex(pair[1]).unwrap_or(0)]);
        }
        out.push((b.freeze(), Encoding::Hex));
    }
    if bytes.contains(&b'%') {
        let mut b = SecretBuf::with_capacity(bytes.len());
        let mut i = 0;
        let mut valid = true;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if let Some(pair) = bytes.get(i + 1..i + 3) {
                    if let (Some(a), Some(c)) =
                        (crate::json::hex(pair[0]), crate::json::hex(pair[1]))
                    {
                        let _ = b.extend(&[(a << 4) | c]);
                        i += 3;
                        continue;
                    }
                }
                valid = false;
                break;
            }
            let _ = b.extend(&bytes[i..i + 1]);
            i += 1;
        }
        if valid {
            out.push((b.freeze(), Encoding::Percent));
        }
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        let mut b = Zeroizing::new(vec![0; bytes.len()]);
        if let Ok(n) = engine.decode_slice(bytes, &mut b) {
            out.push((SecretBytes::copy_from(&b[..n]), Encoding::Base64));
            break;
        }
    }
    out
}

/// Scan only the catalog's approved files and directories. File stamps travel
/// with occurrences; changed files report incomplete and are never rewritten.
pub fn scan_transcript_sources(
    sources: &[crate::source::ConfigSource],
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> Result<crate::candidates::ScanReport, ScanError> {
    let mut report = crate::candidates::ScanReport::default();
    let mut occurrences = 0usize;
    let mut stopped = false;
    crate::sources::walk_sources(sources, budget, &mut report, |root, rel, source, report| {
        if stopped {
            return;
        }
        let path = root.path().join(rel);
        let opened = root
            .open_parent(rel)
            .and_then(|(d, n)| crate::root::open_file(&d, &n, usize::MAX));
        let (mut file, metadata) = match opened {
            Ok(v) => v,
            Err(e) => {
                report.issue(path, e.token());
                return;
            }
        };
        let stamp = crate::FileStamp::of(&metadata);
        if stamp.dev != root.dev() {
            report.issue(path, "mount_point");
            return;
        }
        let format = match source.format {
            ConfigFormat::Mixed => {
                if rel.extension().is_some_and(|s| s == "jsonl") {
                    ConfigFormat::Jsonl
                } else {
                    ConfigFormat::Raw
                }
            }
            f => f,
        };
        let remaining = Budget {
            bytes: budget.bytes.saturating_sub(report.bytes),
            occurrences: budget.occurrences.saturating_sub(occurrences),
            ..budget
        };
        match scan_reader(
            &mut file,
            format,
            Source {
                path: path.clone(),
                object: None,
            },
            remaining,
            &mut |mut c| {
                c.occurrence.stamp = Some(stamp);
                c.occurrence.rewritable &= stamp.nlink == 1;
                let accepted = emit(c);
                if !accepted {
                    stopped = true;
                }
                accepted
            },
        ) {
            Ok(part) => {
                report.files += 1;
                report.bytes += part.bytes;
                occurrences += part.candidates as usize;
                report.issues.extend(part.issues);
            }
            Err(_) => report.issue(&path, "unreadable"),
        }
        match file.metadata() {
            Ok(after) if crate::FileStamp::of(&after) == stamp => {}
            _ => report.issue(path, "changed"),
        }
    });
    Ok(report)
}
