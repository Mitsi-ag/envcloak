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
    let json = matches!(format, ConfigFormat::Json | ConfigFormat::Jsonl);
    let cap = match format {
        ConfigFormat::Json => crate::MAX_DOTENV,
        ConfigFormat::Jsonl => MAX_LINE,
        _ => MAX_CANDIDATE,
    };
    let mut buffer = SecretBuf::with_capacity(cap.min(8192));
    let mut chunk = Zeroizing::new([0u8; 32768]);
    let mut start = 0u64;
    let mut skipped = false;
    let mut stopped = false;
    let mut exhausted = false;
    let mut utf8 = Utf8Boundary::default();
    loop {
        let remaining = budget.bytes.saturating_sub(report.bytes);
        if remaining == 0 {
            exhausted = true;
            report.issue(&source, "byte_budget");
            break;
        }
        let allowance = if format == ConfigFormat::Json {
            remaining.min((cap as u64 + 1).saturating_sub(report.bytes))
        } else {
            remaining
        };
        let want = allowance.min(chunk.len() as u64) as usize;
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
            let boundary = if json {
                format == ConfigFormat::Jsonl && b == b'\n'
            } else {
                delimiter(b)
            };
            let (before, discard) = if json { (false, false) } else { utf8.step(b) };
            if before {
                report.not_scanned += 1;
                report.issue(&source, "invalid_text");
            }
            if boundary || before {
                if !skipped && !buffer.is_empty() {
                    if json {
                        stopped = !json_line(
                            buffer.expose_secret(),
                            start,
                            &source,
                            format,
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
                start = chunk_start + i as u64 + u64::from(boundary || discard);
                if stopped {
                    break;
                }
            }
            if !boundary && !discard && !skipped {
                if buffer.len() == cap {
                    report.not_scanned += 1;
                    report.issue(
                        &source,
                        if format == ConfigFormat::Json {
                            "too_large"
                        } else if json {
                            "line_too_large"
                        } else {
                            "token_too_large"
                        },
                    );
                    buffer.clear();
                    skipped = true;
                    if format == ConfigFormat::Json {
                        stopped = true;
                        break;
                    }
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
                format,
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
// Keep UTF-8 state across read chunks. Invalid bytes separate raw text before
// the token cap is applied, so a long binary run cannot swallow later text.
#[derive(Default)]
struct Utf8Boundary {
    remaining: u8,
    lower: u8,
    upper: u8,
}
impl Utf8Boundary {
    // (flush before this byte, discard this byte). An ASCII byte interrupting
    // a sequence starts the next text run and must not be discarded.
    fn step(&mut self, b: u8) -> (bool, bool) {
        let interrupted = self.remaining > 0;
        if interrupted && (self.lower..=self.upper).contains(&b) {
            self.remaining -= 1;
            self.lower = 0x80;
            self.upper = 0xbf;
            return (false, false);
        }
        self.remaining = 0;
        self.lower = 0x80;
        self.upper = 0xbf;
        match b {
            0..=0x7f => {}
            0xc2..=0xdf => self.remaining = 1,
            0xe0..=0xef => {
                self.remaining = 2;
                if b == 0xe0 {
                    self.lower = 0xa0;
                }
                if b == 0xed {
                    self.upper = 0x9f;
                }
            }
            0xf0..=0xf4 => {
                self.remaining = 3;
                if b == 0xf0 {
                    self.lower = 0x90;
                }
                if b == 0xf4 {
                    self.upper = 0x8f;
                }
            }
            _ => return (true, true),
        }
        (interrupted, false)
    }
}

fn delimiter(b: u8) -> bool {
    b.is_ascii_whitespace() || b < 32
}
fn json_line(
    bytes: &[u8],
    base: u64,
    source: &Source,
    format: ConfigFormat,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    let node = match crate::json::parse(bytes) {
        Ok(n) => n,
        Err(()) => {
            report.not_scanned += 1;
            report.issue(source, "invalid_json");
            // Damaged documents and lines still get a raw scan. Keep the parse issue
            // visible and never charge these already-read bytes a second time.
            let mut accepted = true;
            if matches!(format, ConfigFormat::Json | ConfigFormat::Jsonl) {
                let mut fallback: &mut dyn FnMut(Candidate) -> bool = &mut |mut c| {
                    c.occurrence.range.start += base;
                    c.occurrence.range.end += base;
                    accepted = emit(c);
                    accepted
                };
                if let Ok(part) = scan_reader(
                    &mut std::io::Cursor::new(bytes),
                    ConfigFormat::Raw,
                    source.clone(),
                    Budget {
                        bytes: bytes.len() as u64 + 1,
                        occurrences: budget
                            .occurrences
                            .saturating_sub(report.candidates as usize),
                        ..budget
                    },
                    &mut fallback,
                ) {
                    accepted &= !part
                        .issues
                        .iter()
                        .any(|i| matches!(i.reason, "occurrence_budget" | "candidate_budget"));
                    report.candidates += part.candidates;
                    report.not_scanned += part.not_scanned;
                    for issue in part.issues {
                        report.issue(&issue.source, issue.reason);
                    }
                }
            }
            return accepted;
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
            if !text_tokens(t, base, source, report, budget, emit) {
                return false;
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
    if bytes.len() <= MAX_CANDIDATE && bytes.iter().any(|b| delimiter(*b)) {
        return token(
            bytes,
            base,
            Some(&t.offsets),
            source,
            Encoding::Json,
            report,
            budget,
            emit,
        );
    }
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
    if bytes.len() > MAX_CANDIDATE {
        report.not_scanned += 1;
        report.issue(source, "token_too_large");
        return true;
    }
    let mut at = 0;
    while at < bytes.len() {
        let (end, skip) = match std::str::from_utf8(&bytes[at..]) {
            Ok(_) => (bytes.len(), 0),
            Err(e) => {
                report.not_scanned += 1;
                report.issue(source, "invalid_text");
                let end = at + e.valid_up_to();
                (end, e.error_len().unwrap_or(bytes.len() - end))
            }
        };
        let (ranges, limited) = crate::token_readings::ranges(&bytes[at..end]);
        if limited {
            report.not_scanned += 1;
            report.issue(source, "reading_budget");
        }
        for (r, form) in ranges {
            let a = at + r.start;
            let b = at + r.end;
            let range = if let Some(m) = map {
                base + m[a] as u64..base + m[b] as u64
            } else {
                base + a as u64..base + b as u64
            };
            let occurrence = Occurrence {
                source: source.clone(),
                range,
                encoding,
                stamp: None,
                rewritable: true,
            };
            if !send(
                SecretBytes::copy_from(&bytes[a..b]),
                occurrence.clone(),
                form,
                report,
                budget,
                emit,
            ) {
                return false;
            }
            for (value, encoding) in decoded(&bytes[a..b]) {
                let mut encoded = occurrence.clone();
                encoded.encoding = encoding;
                encoded.rewritable = false;
                if !decoded_tokens(&value, &encoded, form, report, budget, emit) {
                    return false;
                }
            }
        }
        if skip == 0 {
            break;
        }
        at = end + skip;
    }
    true
}
#[allow(clippy::disallowed_methods)] // Decoded readings retain the whole encoded source range.
fn decoded_tokens(
    value: &SecretBytes,
    at: &Occurrence,
    form: Form,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    let bytes = value.expose_secret();
    // An incidental base64 decoding of ordinary text is not an input error.
    if std::str::from_utf8(bytes).is_err() {
        return true;
    }
    let (ranges, limited) = crate::token_readings::ranges(bytes);
    if limited {
        report.not_scanned += 1;
        report.issue(&at.source, "reading_budget");
    }
    for (r, reading_form) in ranges {
        let form = if reading_form == Form::Raw {
            form
        } else {
            reading_form
        };
        // Only the complete decoded spelling authorizes replacing its source
        // span. A token inside a longer encoded run remains detection-only.
        let mut occurrence = at.clone();
        occurrence.rewritable = r.start == 0 && r.end == bytes.len();
        if !send(
            SecretBytes::copy_from(&bytes[r]),
            occurrence,
            form,
            report,
            budget,
            emit,
        ) {
            return false;
        }
    }
    true
}

fn send(
    value: SecretBytes,
    occurrence: Occurrence,
    form: Form,
    report: &mut StreamReport,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> bool {
    if !value.utf8_chars().is_some_and(|n| n >= 16) {
        return true;
    }
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
        form,
        occurrence,
    }) {
        report.issue(&source, "candidate_budget");
        return false;
    }
    true
}
fn decoded(bytes: &[u8]) -> Vec<(SecretBytes, Encoding)> {
    let mut out = Vec::new();
    // Decode bounded spellings, not an entire message with several spellings.
    // Otherwise a percent escape anywhere could claim unrelated text's range.
    if bytes.iter().any(u8::is_ascii_whitespace) {
        return out;
    }
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
    let mut ordered = sources.to_vec();
    // Known structured stores win over broader raw catalog coverage. One
    // reader per leaf preserves physical counts without retaining every range.
    ordered.sort_by_key(|s| match s.format {
        ConfigFormat::Json => 0,
        ConfigFormat::Jsonl => 1,
        ConfigFormat::Mixed => 2,
        _ => 3,
    });
    let mut scanned = std::collections::HashMap::new();
    crate::sources::walk_sources(
        &ordered,
        budget,
        &mut report,
        |root, rel, source, opened, _attempts, report| {
            let path = root.path().join(rel);
            let format = crate::sources::effective_format(rel, source.format);
            if let Some(previous) = scanned.get(&path) {
                if *previous != format && matches!(format, ConfigFormat::Json | ConfigFormat::Jsonl)
                {
                    report.issue(path, "conflicting_formats");
                }
                return;
            }
            scanned.insert(path, format);
            scan_file(
                root,
                rel,
                source,
                opened,
                budget,
                report,
                &mut occurrences,
                &mut stopped,
                emit,
            );
        },
    );
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn scan_file(
    root: &crate::ScanRoot,
    rel: &std::path::Path,
    source: &crate::source::ConfigSource,
    opened: (File, std::fs::Metadata),
    budget: Budget,
    report: &mut crate::candidates::ScanReport,
    occurrences: &mut usize,
    stopped: &mut bool,
    emit: &mut impl FnMut(Candidate) -> bool,
) {
    if *stopped {
        return;
    }
    let path = root.path().join(rel);
    let cap = if source.format == ConfigFormat::Json {
        crate::MAX_DOTENV
    } else {
        usize::MAX
    };
    let (mut file, metadata) = opened;
    if metadata.len() > cap as u64 {
        report.issue(path, "too_large");
        return;
    }
    let stamp = crate::FileStamp::of(&metadata);
    if stamp.dev != root.dev() {
        report.issue(path, "mount_point");
        return;
    }
    let format = crate::sources::effective_format(rel, source.format);
    let remaining = Budget {
        bytes: budget.bytes.saturating_sub(report.bytes),
        occurrences: budget.occurrences.saturating_sub(*occurrences),
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
                *stopped = true;
            }
            accepted
        },
    ) {
        Ok(part) => {
            report.files += 1;
            report.bytes += part.bytes;
            *occurrences += part.candidates as usize;
            report.issues.extend(part.issues);
        }
        Err(_) => report.issue(&path, "unreadable"),
    }
    match file.metadata() {
        Ok(after) if crate::FileStamp::of(&after) == stamp => {}
        _ => report.issue(path, "changed"),
    }
}

#[cfg(test)]
mod device_tests {
    use super::*;

    #[test]
    fn transcript_reads_the_discovered_handle_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        let path = d.path().join("store");
        let value = b"fixtureZheldTranscriptValue";
        std::fs::write(&path, value).expect("write");
        let stamp = crate::FileStamp::of(&std::fs::metadata(&path).expect("metadata"));
        let source = crate::source::ConfigSource {
            path: path.clone(),
            format: ConfigFormat::Raw,
            source_kind: crate::source::SourceKind::Transcript,
            label: "fixture".into(),
            names: None,
        };
        let mut report = crate::candidates::ScanReport::default();
        let mut found = false;
        crate::sources::walk_sources(
            &[source],
            Budget::default(),
            &mut report,
            |root, rel, source, opened, _attempts, report| {
                // The callback is a deterministic barrier after discovery's
                // open. Reopening this path must fail, while the held file
                // remains readable and its original stamp must be retained.
                std::fs::rename(&path, d.path().join("held")).expect("rename");
                std::fs::write(&path, b"replacement").expect("replace");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
                    .expect("permissions");
                scan_file(
                    root,
                    rel,
                    source,
                    opened,
                    Budget::default(),
                    report,
                    &mut 0,
                    &mut false,
                    &mut |c| {
                        assert!(c.value.ct_eq(value));
                        assert_eq!(c.occurrence.stamp, Some(stamp));
                        found = true;
                        true
                    },
                );
            },
        );
        assert!(found, "reader reopened the path instead of its held file");
        assert_eq!(report.files, 1);
        assert_eq!(report.bytes, value.len() as u64);
        assert!(!report.issues.iter().any(|i| i.reason == "unreadable"));
    }

    #[test]
    fn transcript_leaf_mount_is_refused_at_the_actual_read() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        std::fs::write(d.path().join("store"), b"fixtureZtranscriptDeviceValue").expect("write");
        let mut root = crate::open_root(d.path()).expect("root");
        let source = crate::source::ConfigSource {
            path: d.path().join("store"),
            format: ConfigFormat::Raw,
            source_kind: crate::source::SourceKind::Transcript,
            label: "fixture".into(),
            names: None,
        };
        for mounted in [false, true] {
            if mounted {
                root.model_other_device();
            }
            let mut report = crate::candidates::ScanReport::default();
            let mut found = false;
            scan_file(
                &root,
                std::path::Path::new("store"),
                &source,
                crate::root::open_file(root.dir(), std::ffi::OsStr::new("store"), usize::MAX)
                    .expect("open"),
                Budget::default(),
                &mut report,
                &mut 0,
                &mut false,
                &mut |c| {
                    found |= c.value.ct_eq(b"fixtureZtranscriptDeviceValue");
                    true
                },
            );
            assert_eq!(found, !mounted);
            assert_eq!(report.complete(), !mounted);
            if mounted {
                assert_eq!(report.bytes, 0);
                assert!(report.issues.iter().any(|i| i.reason == "mount_point"));
            }
        }
    }
}
