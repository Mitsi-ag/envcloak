//! Host-neutral config readers. Paths and host versions belong to the caller.
//! Unsupported syntax and credential stores always produce an incomplete report.
use crate::candidates::{Budget, Disposition, Found, ScanReport, Source};
use crate::json::{Node, Text};
use crate::source::{ConfigFormat, ConfigSource};
use crate::{MAX_DOTENV, ScanError, parse_dotenv, read_capped};
use envcloak_core::SecretBytes;
use secrecy::ExposeSecret;
use std::path::{Component, Path};

#[allow(clippy::disallowed_methods)] // Bounded config parsing, fixed errors only.
pub fn parse_config(bytes: &SecretBytes, format: ConfigFormat) -> ScanReport {
    let mut report = ScanReport::default();
    if bytes.len() > MAX_DOTENV {
        report.issue("", "too_large");
        return report;
    }
    match format {
        ConfigFormat::Json => match crate::json::parse(bytes.expose_secret()) {
            Ok(node) => json(&node, false, &mut report),
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
                Ok(doc) => toml_table(doc.as_table(), false, &mut report),
                Err(_) => report.issue("", "invalid_toml"),
            }
        }
        _ => report.issue("", "unsupported_format"),
    }
    report
}
fn push(report: &mut ScanReport, name: &[u8], value: &[u8], range: std::ops::Range<u64>) {
    let template = value.contains(&b'$') || value.starts_with(b"envcloak://");
    report.findings.push(Found {
        name: SecretBytes::copy_from(name),
        value: if template {
            None
        } else {
            Some(SecretBytes::copy_from(value))
        },
        disposition: if template {
            Disposition::Template
        } else {
            Disposition::Literal
        },
        range,
        single_complete_line: false,
        source: Source::default(),
        stamp: None,
    });
}
#[allow(clippy::disallowed_methods)]
fn field(report: &mut ScanReport, k: &Text, v: &Text) {
    push(
        report,
        k.value.expose_secret(),
        v.value.expose_secret(),
        v.range.start as u64..v.range.end as u64,
    );
}
fn json(node: &Node, servers: bool, report: &mut ScanReport) {
    if let Some(fields) = node.object() {
        for (k, v) in fields {
            if k.value.ct_eq(b"mcpServers")
                || k.value.ct_eq(b"mcp_servers")
                || k.value.ct_eq(b"mcp")
            {
                if let Some(entries) = v.object() {
                    for (_, server) in entries {
                        json(server, true, report);
                    }
                } else {
                    report.issue("", "invalid_servers");
                }
            } else if servers
                && (k.value.ct_eq(b"env")
                    || k.value.ct_eq(b"environment")
                    || k.value.ct_eq(b"headers")
                    || k.value.ct_eq(b"http_headers")
                    || k.value.ct_eq(b"auth"))
            {
                if let Some(entries) = v.object() {
                    for (name, value) in entries {
                        if let Some(t) = value.text() {
                            field(report, name, t);
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
                    field(report, k, t);
                }
            } else if servers && k.value.ct_eq(b"envFile") {
                if let Some(t) = v.text() {
                    field(report, k, t);
                } else {
                    report.issue("", "invalid_env_file");
                }
            } else if servers && k.value.ct_eq(b"args") {
                // Migration decides which arguments match a provider pattern;
                // preserve the values but never offer an argv rewrite.
                if let Node::Array(args) = v {
                    for arg in args {
                        if let Some(t) = arg.text() {
                            field(report, k, t);
                            if let Some(f) = report.findings.last_mut() {
                                f.disposition = Disposition::Manual;
                            }
                        }
                    }
                }
            } else {
                json(v, servers, report);
            }
        }
    } else if let Node::Array(values) = node {
        for value in values {
            json(value, servers, report);
        }
    }
}
fn toml_table(table: &dyn toml_edit::TableLike, servers: bool, report: &mut ScanReport) {
    for (key, item) in table.iter() {
        if matches!(key, "mcp_servers" | "mcpServers" | "mcp") {
            if let Some(entries) = item.as_table_like() {
                for (_, server) in entries.iter() {
                    if let Some(t) = server.as_table_like() {
                        toml_table(t, true, report);
                    } else {
                        report.issue("", "invalid_server");
                    }
                }
            } else {
                report.issue("", "invalid_servers");
            }
        } else if servers
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
                push(
                    report,
                    b"envFile",
                    v.as_bytes(),
                    span.start as u64..span.end as u64,
                );
            } else {
                report.issue("", "invalid_env_file");
            }
        } else if let Some(t) = item.as_table_like() {
            toml_table(t, servers, report);
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
    crate::sources::walk_sources(sources, budget, &mut report, |root, rel, source, report| {
        if report.files >= budget.files as u64 {
            report.issue(root.path().join(rel), "file_budget");
            return;
        }
        let remaining = budget.bytes.saturating_sub(report.bytes);
        let (bytes, stamp) = match read_capped(root, rel, MAX_DOTENV.min(remaining as usize)) {
            Ok(v) => v,
            Err(e) => {
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
        let mut parsed = parse_config(&bytes, source.format);
        for f in &mut parsed.findings {
            f.source.path = root.path().join(rel);
            f.stamp = Some(stamp);
        }
        for i in &mut parsed.issues {
            i.source.path = root.path().join(rel);
        }
        let mut includes = Vec::new();
        parsed.findings.retain(|f| {
            if f.name.ct_eq(b"envFile") {
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
            if report.files >= budget.files as u64 {
                report.issue(root.path().join(path), "file_budget");
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
                                let template = e.kind != crate::EntryKind::Plain;
                                report.findings.push(Found {
                                    name: SecretBytes::copy_from(e.name.as_str().as_bytes()),
                                    value: if template { None } else { Some(e.value) },
                                    disposition: if template {
                                        Disposition::Template
                                    } else {
                                        Disposition::Literal
                                    },
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
