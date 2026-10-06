//! Host-neutral config readers. Paths and host versions belong to the caller.
//! Unsupported syntax produces an incomplete report; reference values stay names-only.
use crate::candidates::{Budget, Disposition, Found, ScanReport, Source};
use crate::json::{Node, Text};
use crate::source::{ConfigFormat, ConfigSource};
use crate::{MAX_DOTENV, ScanError, parse_dotenv, read_capped};
use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;
use std::path::{Component, Path};

#[allow(clippy::disallowed_methods)] // Bounded config parsing, fixed errors only.
pub fn parse_config(bytes: &SecretBytes, format: ConfigFormat) -> ScanReport {
    parse_config_limited(bytes, format, Budget::default())
}
#[allow(clippy::disallowed_methods)]
fn parse_config_limited(bytes: &SecretBytes, format: ConfigFormat, budget: Budget) -> ScanReport {
    let mut report = ScanReport::default();
    if bytes.len() > MAX_DOTENV {
        report.issue("", "too_large");
        return report;
    }
    match format {
        ConfigFormat::Json => match crate::json::parse(bytes.expose_secret()) {
            Ok(node) => json(&node, false, &mut report, budget),
            Err(()) => report.issue("", "invalid_json"),
        },
        ConfigFormat::Toml => {
            let Ok(text) = std::str::from_utf8(bytes.expose_secret()) else {
                report.issue("", "invalid_text");
                return report;
            };
            // toml_edit's transient parsing allocations are covered by the
            // binary's mandatory wiping allocator, including failure paths.
            match toml_edit::Document::parse(text) {
                Ok(doc) => toml_table(doc.as_table(), false, &mut report, budget),
                Err(_) => report.issue("", "invalid_toml"),
            }
        }
        _ => report.issue("", "unsupported_format"),
    }
    report
}
fn room(report: &mut ScanReport, budget: Budget, path: &Path) -> bool {
    let reason = if report.findings.len() >= budget.candidates {
        "candidate_budget"
    } else if report.findings.len() >= budget.occurrences {
        "occurrence_budget"
    } else {
        return true;
    };
    if !report
        .issues
        .iter()
        .any(|i| i.reason == reason && i.source.path == path)
    {
        report.issue(path, reason);
    }
    false
}
fn reference(value: &[u8]) -> Disposition {
    if value.starts_with(b"envcloak://") {
        return Disposition::Template;
    }
    let mut tail = value;
    let mut found = false;
    while let Some(at) = tail.windows(2).position(|w| w == b"${") {
        tail = &tail[at + 2..];
        let Some(end) = tail.iter().position(|b| *b == b'}') else {
            return Disposition::Manual;
        };
        let body = &tail[..end];
        let n = body
            .iter()
            .position(|b| !b.is_ascii_alphanumeric() && *b != b'_')
            .unwrap_or(body.len());
        if n == 0
            || !body[0].is_ascii_alphabetic() && body[0] != b'_'
            || !(n == body.len() || body[n..].starts_with(b":-"))
            || body.contains(&b'{')
        {
            return Disposition::Manual;
        }
        found = true;
        tail = &tail[end + 1..];
    }
    if found {
        Disposition::Template
    } else {
        Disposition::Literal
    }
}
fn push(
    report: &mut ScanReport,
    name: &[u8],
    value: &[u8],
    range: std::ops::Range<u64>,
    budget: Budget,
) -> bool {
    if !room(report, budget, Path::new("")) {
        return false;
    }
    let disposition = reference(value);
    if disposition == Disposition::Manual {
        report.issue("", "unsupported_reference");
    }
    report.findings.push(Found {
        name: SecretBytes::copy_from(name),
        value: (disposition == Disposition::Literal).then(|| SecretBytes::copy_from(value)),
        disposition,
        env_file: false,
        range,
        single_complete_line: false,
        source: Source::default(),
        stamp: None,
    });
    true
}
#[allow(clippy::disallowed_methods)]
fn field(report: &mut ScanReport, k: &Text, v: &Text, budget: Budget) -> bool {
    push(
        report,
        k.value.expose_secret(),
        v.value.expose_secret(),
        v.range.start as u64..v.range.end as u64,
        budget,
    )
}
fn json(node: &Node, servers: bool, report: &mut ScanReport, budget: Budget) {
    if let Some(fields) = node.object() {
        for (k, v) in fields {
            if !room(report, budget, Path::new("")) {
                return;
            }
            if k.value.ct_eq(b"mcpServers")
                || k.value.ct_eq(b"mcp_servers")
                || k.value.ct_eq(b"mcp")
                || k.value.ct_eq(b"servers")
            {
                if let Some(entries) = v.object() {
                    for (_, server) in entries {
                        if server.object().is_some() {
                            json(server, true, report, budget);
                        } else {
                            report.issue("", "invalid_server");
                        }
                    }
                } else {
                    report.issue("", "invalid_servers");
                }
            } else if (servers || k.value.ct_eq(b"env"))
                && (k.value.ct_eq(b"env")
                    || k.value.ct_eq(b"environment")
                    || k.value.ct_eq(b"headers")
                    || k.value.ct_eq(b"http_headers")
                    || k.value.ct_eq(b"auth"))
            {
                if let Some(entries) = v.object() {
                    for (name, value) in entries {
                        if let Some(t) = value.text() {
                            field(report, name, t, budget);
                        } else {
                            report.issue("", "non_string_binding");
                        }
                    }
                } else {
                    report.issue("", "invalid_bindings");
                }
            } else if [b"apiKey".as_slice(), b"cookieHeader", b"token"]
                .iter()
                .any(|name| k.value.ct_eq(name))
            {
                if let Some(t) = v.text() {
                    field(report, k, t, budget);
                } else {
                    report.issue("", "non_string_binding");
                }
            } else if servers && k.value.ct_eq(b"envFile") {
                if let Some(t) = v.text() {
                    if field(report, k, t, budget) {
                        if let Some(f) = report.findings.last_mut() {
                            f.env_file = true;
                        }
                    }
                } else {
                    report.issue("", "invalid_env_file");
                }
            } else if servers && k.value.ct_eq(b"args") {
                // Migration decides which arguments match a provider pattern;
                // preserve the values but never offer an argv rewrite.
                if let Node::Array(args) = v {
                    for arg in args {
                        if let Some(t) = arg.text() {
                            if field(report, k, t, budget) {
                                if let Some(f) = report.findings.last_mut() {
                                    f.disposition = Disposition::Manual;
                                }
                            }
                        } else {
                            report.issue("", "invalid_argument");
                        }
                    }
                } else {
                    report.issue("", "invalid_arguments");
                }
            } else {
                json(v, servers, report, budget);
            }
        }
    } else if let Node::Array(values) = node {
        for value in values {
            json(value, servers, report, budget);
        }
    }
}
fn toml_table(
    table: &dyn toml_edit::TableLike,
    servers: bool,
    report: &mut ScanReport,
    budget: Budget,
) {
    for (key, item) in table.iter() {
        if !room(report, budget, Path::new("")) {
            return;
        }
        if matches!(key, "mcp_servers" | "mcpServers" | "mcp" | "servers") {
            if let Some(entries) = item.as_table_like() {
                for (_, server) in entries.iter() {
                    if let Some(t) = server.as_table_like() {
                        toml_table(t, true, report, budget);
                    } else {
                        report.issue("", "invalid_server");
                    }
                }
            } else {
                report.issue("", "invalid_servers");
            }
        } else if (servers || key == "env")
            && matches!(
                key,
                "env" | "environment" | "headers" | "http_headers" | "auth"
            )
        {
            if let Some(entries) = item.as_table_like() {
                for (name, value) in entries.iter() {
                    if let Some(v) = value.as_str() {
                        let span = value.span().unwrap_or(0..0);
                        push(
                            report,
                            name.as_bytes(),
                            v.as_bytes(),
                            span.start as u64..span.end as u64,
                            budget,
                        );
                    } else {
                        report.issue("", "non_string_binding");
                    }
                }
            } else {
                report.issue("", "invalid_bindings");
            }
        } else if servers && key == "envFile" {
            if let Some(v) = item.as_str() {
                let span = item.span().unwrap_or(0..0);
                if push(
                    report,
                    b"envFile",
                    v.as_bytes(),
                    span.start as u64..span.end as u64,
                    budget,
                ) {
                    if let Some(f) = report.findings.last_mut() {
                        f.env_file = true;
                    }
                }
            } else {
                report.issue("", "invalid_env_file");
            }
        } else if servers && key == "args" {
            if let Some(args) = item.as_array() {
                for arg in args.iter() {
                    if let Some(v) = arg.as_str() {
                        let span = arg.span().unwrap_or(0..0);
                        if push(
                            report,
                            b"args",
                            v.as_bytes(),
                            span.start as u64..span.end as u64,
                            budget,
                        ) {
                            if let Some(f) = report.findings.last_mut() {
                                f.disposition = Disposition::Manual;
                            }
                        }
                    } else {
                        report.issue("", "invalid_argument");
                    }
                }
            } else {
                report.issue("", "invalid_arguments");
            }
        } else if let Some(t) = item.as_table_like() {
            toml_table(t, servers, report, budget);
        }
    }
}

pub fn scan_config_sources(sources: &[ConfigSource]) -> Result<ScanReport, ScanError> {
    scan_config_sources_with_budget(sources, Budget::default())
}
pub fn scan_config_sources_with_budget(
    sources: &[ConfigSource],
    budget: Budget,
) -> Result<ScanReport, ScanError> {
    let mut report = ScanReport::default();
    let mut attempted = std::collections::HashSet::new();
    let mut failed = std::collections::HashSet::new();
    crate::sources::walk_sources(sources, budget, &mut report, |root, rel, source, report| {
        if failed.contains(&root.path().join(rel))
            || !admit_file(
                root.path().join(rel),
                Reader::Config(source.format),
                budget,
                &mut attempted,
                report,
            )
        {
            return;
        }
        let remaining = budget.bytes.saturating_sub(report.bytes);
        let (bytes, stamp) = match read_capped(root, rel, MAX_DOTENV.min(remaining as usize)) {
            Ok(v) => v,
            Err(e) => {
                failed.insert(root.path().join(rel));
                // A failed read may have consumed bytes before the error.
                // Reserve its whole allowance so repeated failures stay bounded.
                if matches!(
                    e.kind,
                    crate::ScanErrorKind::Changed | crate::ScanErrorKind::Io(_)
                ) {
                    report.bytes += remaining.min(MAX_DOTENV as u64);
                }
                report.issue(
                    root.path().join(rel),
                    if remaining < MAX_DOTENV as u64 {
                        "byte_budget"
                    } else {
                        e.kind.token()
                    },
                );
                return;
            }
        };
        report.files += 1;
        report.bytes += bytes.len() as u64;
        let mut parsed = parse_config_limited(
            &bytes,
            source.format,
            Budget {
                candidates: budget.candidates.saturating_sub(report.findings.len()),
                occurrences: budget.occurrences.saturating_sub(report.findings.len()),
                ..budget
            },
        );
        for f in &mut parsed.findings {
            f.source.path = root.path().join(rel);
            f.stamp = Some(stamp);
        }
        for i in &mut parsed.issues {
            i.source.path = root.path().join(rel);
        }
        let mut includes = Vec::new();
        parsed.findings.retain(|f| {
            if f.env_file {
                if let Some(v) = &f.value {
                    #[allow(clippy::disallowed_methods)]
                    includes.push(SecretBytes::copy_from(v.expose_secret()));
                    false
                } else {
                    true
                }
            } else {
                true
            }
        });
        for f in &parsed.findings {
            if f.env_file && f.value.is_none() {
                report.issue(root.path().join(rel), "unread_env_file");
            }
        }
        report.append(parsed);
        for included in includes {
            #[allow(clippy::disallowed_methods)]
            let text = std::str::from_utf8(included.expose_secret());
            let Ok(text) = text else {
                report.issue(root.path().join(rel), "invalid_env_file");
                continue;
            };
            let path = Path::new(text);
            let path = if path.is_absolute() {
                match path.strip_prefix(root.path()) {
                    Ok(p) => p.to_path_buf(),
                    Err(_) => {
                        report.issue(root.path().join(rel), "env_file_outside_root");
                        continue;
                    }
                }
            } else {
                rel.parent().unwrap_or(Path::new("")).join(path)
            };
            if !path.components().all(|c| matches!(c, Component::Normal(_))) {
                report.issue(root.path().join(rel), "env_file_outside_root");
                continue;
            }
            if crate::sources::omitted_path(sources, &root.path().join(&path)) {
                report.issue(root.path().join(&path), "unread_env_file");
                continue;
            }
            if failed.contains(&root.path().join(&path)) {
                continue;
            }
            if attempted.len() >= budget.files
                && !attempted.contains(&(root.path().join(&path), Reader::Dotenv))
            {
                report.issue(root.path().join(rel), "file_budget");
                break;
            }
            if !admit_file(
                root.path().join(&path),
                Reader::Dotenv,
                budget,
                &mut attempted,
                report,
            ) {
                continue;
            }
            let remain = budget.bytes.saturating_sub(report.bytes);
            match read_capped(root, &path, MAX_DOTENV.min(remain as usize)) {
                Ok((b, stamp)) => {
                    if stamp.nlink > 1 {
                        report.issue(root.path().join(&path), "hard_link");
                    }
                    report.files += 1;
                    report.bytes += b.len() as u64;
                    match parse_dotenv(&b) {
                        Ok(entries) => {
                            for e in entries {
                                if !room(report, budget, &root.path().join(&path)) {
                                    break;
                                }
                                let template = e.kind != crate::EntryKind::Plain
                                    || path.file_name().and_then(crate::dotenv_kind)
                                        == Some(Ok(crate::FileKind::Template));
                                report.findings.push(Found {
                                    name: SecretBytes::copy_from(e.name.as_str().as_bytes()),
                                    value: if template { None } else { Some(e.value) },
                                    disposition: if template {
                                        Disposition::Template
                                    } else {
                                        Disposition::Literal
                                    },
                                    env_file: false,
                                    range: e.span.start as u64..e.span.end as u64,
                                    single_complete_line: false,
                                    source: Source {
                                        path: root.path().join(&path),
                                        object: None,
                                    },
                                    stamp: Some(stamp),
                                });
                            }
                        }
                        Err(_) => report.issue(root.path().join(&path), "invalid_dotenv"),
                    }
                }
                Err(e) => {
                    failed.insert(root.path().join(&path));
                    if matches!(
                        e.kind,
                        crate::ScanErrorKind::Changed | crate::ScanErrorKind::Io(_)
                    ) {
                        report.bytes += remain.min(MAX_DOTENV as u64);
                    }
                    report.issue(root.path().join(&path), e.kind.token());
                }
            }
        }
    });
    Ok(report)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Reader {
    Config(ConfigFormat),
    Dotenv,
}

// Charge every distinct attempted file, including failures, before opening it.
// Shared by catalog configs and their envFile includes for the whole run.
fn admit_file(
    path: std::path::PathBuf,
    reader: Reader,
    budget: Budget,
    attempted: &mut std::collections::HashSet<(std::path::PathBuf, Reader)>,
    report: &mut ScanReport,
) -> bool {
    let key = (path, reader);
    if attempted.contains(&key) {
        return false;
    }
    if attempted.len() >= budget.files {
        report.issue(key.0, "file_budget");
        return false;
    }
    attempted.insert(key);
    true
}
