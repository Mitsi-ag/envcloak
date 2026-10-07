//! AWS shared INI files, keys only. Never runs credential_process or SSO.
use crate::candidates::{Disposition, Found, ScanReport, Source};
use crate::{MAX_DOTENV, ScanErrorKind, ScanRoot, read_capped};
use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;
use std::collections::HashSet;
use std::path::Path;

/// Parse the literal scalar keys written by `aws configure set`.
/// Duplicate fields and multiline values make the entire file manual.
#[allow(clippy::disallowed_methods)] // Bounded INI input to wiping values.
pub fn parse_aws(input: &SecretBytes) -> ScanReport {
    let mut report = ScanReport::default();
    if input.len() > MAX_DOTENV {
        report.issue("", "too_large");
        return report;
    }
    let Ok(text) = std::str::from_utf8(input.expose_secret()) else {
        report.issue("", "invalid_text");
        return report;
    };
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        report.issue("", "invalid_text");
        return report;
    }
    let mut section = None;
    let mut sections = HashSet::new();
    let mut seen = HashSet::new();
    let mut offset = 0;
    let mut prior_key = false;
    for raw in text.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if prior_key && raw.starts_with(char::is_whitespace) {
            report.issue("", "multiline_aws_value");
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            section = Some(&line[1..line.len() - 1]);
            if !sections.insert(section) {
                report.issue("", "duplicate_aws_section");
            }
            prior_key = false;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            report.issue("", "unsupported_aws_syntax");
            continue;
        };
        prior_key = true;
        let key = key.trim();
        let name = [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ]
        .into_iter()
        .find(|name| key.eq_ignore_ascii_case(name));
        let Some(name) = name else {
            continue;
        };
        let Some(section) = section else {
            report.issue("", "unsupported_aws_syntax");
            continue;
        };
        if !seen.insert((section, name)) {
            report.issue("", "duplicate_aws_key");
        }
        report.findings.push(Found {
            name: SecretBytes::copy_from(name.as_bytes()),
            value: Some(SecretBytes::copy_from(value.trim().as_bytes())),
            disposition: Disposition::Literal,
            env_file: false,
            range: start as u64..offset as u64,
            single_complete_line: true,
            source: Source::default(),
            stamp: None,
        });
    }
    if !report.complete() {
        for f in &mut report.findings {
            f.value = None;
            f.disposition = Disposition::Manual;
            f.single_complete_line = false;
        }
    }
    report
}

/// Conventional files beneath an explicitly held home/root, never overrides
/// from the caller's AWS environment and never a symlink or special file.
pub fn scan_aws(root: &ScanRoot) -> ScanReport {
    let mut report = ScanReport::default();
    for name in [".aws/credentials", ".aws/config"] {
        crate::sources::inspect_optional_siblings(root, Path::new(name), &mut report);
        let (bytes, stamp) = match read_capped(root, Path::new(name), MAX_DOTENV) {
            Ok(read) => read,
            Err(e) => {
                if e.kind != ScanErrorKind::NotFound {
                    report.issue(root.path().join(name), e.kind.token());
                }
                continue;
            }
        };
        let mut part = parse_aws(&bytes);
        part.files = 1;
        part.bytes = bytes.len() as u64;
        for f in &mut part.findings {
            f.source.path = root.path().join(name);
            f.stamp = Some(stamp);
            f.single_complete_line &= stamp.nlink == 1;
        }
        for issue in &mut part.issues {
            issue.source.path = root.path().join(name);
        }
        if stamp.nlink > 1 {
            part.issue(root.path().join(name), "hard_link");
        }
        report.append(part);
    }
    report
}
