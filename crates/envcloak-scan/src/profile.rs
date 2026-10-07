//! A conservative, non-executing profile reader. Unsupported shell constructs
//! are reported. Literal decoding and whole-line removal are separate facts.
use crate::candidates::{Disposition, Found, ScanReport, Source};
use crate::{MAX_DOTENV, ScanError, ScanRoot, read_capped};
use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Posix,
    Fish,
}
const PROFILES: [&str; 7] = [
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".config/fish/config.fish",
];

fn blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}
// Shell token separators are blanks (space or tab), not arbitrary Unicode
// whitespace. Requiring a separator also keeps command-name prefixes intact.
fn command_arg<'a>(text: &'a [u8], command: &[u8]) -> Option<&'a [u8]> {
    let rest = text.strip_prefix(command)?;
    if !rest.first().is_some_and(|b| blank(*b)) {
        return None;
    }
    let start = rest.iter().position(|b| !blank(*b)).unwrap_or(rest.len());
    Some(&rest[start..])
}
fn name_end(b: &[u8]) -> usize {
    if !b
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
    {
        return 0;
    }
    b.iter()
        .position(|c| !c.is_ascii_alphanumeric() && *c != b'_')
        .unwrap_or(b.len())
}

/// Parse one bounded file. No expansions, subprocesses or filesystem access.
#[allow(clippy::disallowed_methods)] // In-place parsing into wiping buffers.
pub fn parse_profile(input: &SecretBytes, shell: Shell) -> ScanReport {
    parse(input.expose_secret(), shell).0
}

struct Include {
    path: SecretBytes,
    expand_home: bool,
}

fn parse(bytes: &[u8], shell: Shell) -> (ScanReport, Vec<Include>) {
    let mut report = ScanReport::default();
    let mut includes = Vec::new();
    if bytes.len() > MAX_DOTENV {
        report.issue("", "too_large");
        return (report, includes);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        report.issue("", "invalid_text");
        return (report, includes);
    }
    let mut offset = 0;
    // A multiline/continued construct is consumed as one logical line. It
    // can never acquire whole-physical-line removal eligibility.
    while offset < bytes.len() {
        let start = offset;
        let mut q = 0;
        let mut escaped = false;
        let mut comment = false;
        while offset < bytes.len() {
            let b = bytes[offset];
            if comment {
                if b == b'\n' {
                    break;
                }
            } else if escaped {
                escaped = false;
            } else if b == b'\\' && q != b'\'' {
                escaped = true;
            } else if q != 0 {
                if b == q {
                    q = 0;
                }
            } else if matches!(b, b'\'' | b'"') {
                q = b;
            } else if b == b'#' && (offset == start || blank(bytes[offset - 1])) {
                comment = true;
            } else if b == b'\n' {
                break;
            }
            offset += 1;
        }
        let end = offset;
        offset = (offset + 1).min(bytes.len());
        let line = &bytes[start..end];
        let trim = line.iter().position(|b| !blank(*b)).unwrap_or(line.len());
        let mut text = &line[trim..];
        if text.is_empty() || text[0] == b'#' {
            continue;
        }
        if let Some(path) = command_arg(text, b"source").or_else(|| command_arg(text, b".")) {
            match source_path(path) {
                Some(included) => includes.push(included),
                None => report.issue("", "source_not_literal"),
            }
            continue;
        }
        let exported = if let Some(rest) = command_arg(text, b"export") {
            text = rest;
            true
        } else {
            false
        };
        let fish = shell == Shell::Fish;
        if fish {
            if let Some(rest) = command_arg(text, b"set").and_then(|args| {
                [b"-x".as_slice(), b"-gx", b"-Ux", b"-xg", b"-xU"]
                    .iter()
                    .find_map(|option| command_arg(args, option))
            }) {
                text = rest;
            } else {
                report.issue("", "unsupported_syntax");
                continue;
            }
        }
        let n = name_end(text);
        if n == 0
            || (!fish && text.get(n) != Some(&b'='))
            || (fish && !text.get(n).is_some_and(|b| blank(*b)))
        {
            report.issue("", "unsupported_syntax");
            continue;
        }
        let name = &text[..n];
        let mut rhs = &text[n + 1..];
        if fish {
            while rhs.first().is_some_and(|b| blank(*b)) {
                rhs = &rhs[1..];
            }
        }
        let (value, used, unsupported) = word(rhs, fish, exported, false);
        let template = rhs[..used].contains(&b'$') || rhs[..used].contains(&b'`');
        let tail = &rhs[used..];
        let tail = tail
            .iter()
            .position(|b| !blank(*b))
            .map(|p| &tail[p..])
            .unwrap_or(b"");
        let complete_tail = tail.is_empty() || tail.starts_with(b"#");
        let complex = !complete_tail;
        let disposition = if unsupported || q != 0 || escaped || complex {
            Disposition::Manual
        } else if template {
            Disposition::Template
        } else {
            Disposition::Literal
        };
        if disposition == Disposition::Manual {
            report.issue("", "unsupported_syntax");
        }
        let single =
            disposition == Disposition::Literal && !line.contains(&b'\n') && !line.contains(&b'\r');
        report.findings.push(Found {
            name: SecretBytes::copy_from(name),
            value: if disposition == Disposition::Literal {
                Some(value)
            } else {
                None
            },
            disposition,
            env_file: false,
            range: start as u64..offset as u64,
            single_complete_line: single,
            source: Source::default(),
            stamp: None,
        });
    }
    if !report.complete() {
        for f in &mut report.findings {
            f.single_complete_line = false;
        }
    }
    (report, includes)
}

fn word(bytes: &[u8], fish: bool, exported: bool, home_prefix: bool) -> (SecretBytes, usize, bool) {
    let mut out = SecretBuf::with_capacity(bytes.len());
    let mut q = 0;
    let mut i = 0;
    let mut unsupported = false;
    while i < bytes.len() {
        let b = bytes[i];
        if fish && b == b'\\' {
            unsupported = true;
        }
        if q == 0 && (blank(b) || matches!(b, b';' | b'&' | b'|' | b'<' | b'>')) {
            break;
        }
        if q == 0 && matches!(b, b'\'' | b'"') {
            q = b;
            i += 1;
            continue;
        }
        if q != 0 && b == q {
            q = 0;
            i += 1;
            continue;
        }
        if q == 0
            && ((b == b'~' && !(home_prefix && i == 0))
                || matches!(b, b'(' | b')')
                || (exported && matches!(b, b'{' | b'}'))
                || (fish && matches!(b, b'*' | b'?' | b'{' | b'}')))
        {
            unsupported = true;
        }
        if b == b'\\' && (q != b'\'' || fish) {
            let Some(&next) = bytes.get(i + 1) else {
                unsupported = true;
                break;
            };
            if q == 0
                || (!fish && q == b'"' && matches!(next, b'$' | b'`' | b'"' | b'\\' | b'\n'))
                || (fish && matches!(next, b'\\' | b'\''))
            {
                if next != b'\n' {
                    let _ = out.extend(&[next]);
                }
                i += 2;
                continue;
            }
            if fish {
                unsupported = true;
            }
        }
        let _ = out.extend(&[b]);
        i += 1;
    }
    (out.freeze(), i, unsupported || q != 0)
}

// Expand only a leading unquoted ~ or $HOME (also double quoted), never a
// dollar inside single quotes. The decoded path still must stay in the root.
fn source_path(raw: &[u8]) -> Option<Include> {
    let raw = &raw[raw.iter().position(|b| !blank(*b)).unwrap_or(raw.len())..];
    let expand_home =
        raw.starts_with(b"~/") || raw.starts_with(b"$HOME/") || raw.starts_with(b"\"$HOME/");
    let (v, n, bad) = word(raw, false, false, raw.starts_with(b"~/"));
    if bad {
        return None;
    }
    let tail = &raw[n..];
    let tail = &tail[tail.iter().position(|b| !blank(*b)).unwrap_or(tail.len())..];
    if !tail.is_empty() && !tail.starts_with(b"#") {
        return None;
    }
    #[allow(clippy::disallowed_methods)]
    let p = v.expose_secret();
    let rest = if expand_home {
        p.strip_prefix(b"$HOME/")
            .or_else(|| p.strip_prefix(b"~/"))
            .unwrap_or(p)
    } else {
        p
    };
    if rest
        .iter()
        .any(|b| matches!(b, b'$' | b'`' | b'\n' | b'\r'))
    {
        return None;
    }
    Some(Include {
        path: v,
        expand_home,
    })
}

pub fn scan_profiles(root: &ScanRoot) -> Result<ScanReport, ScanError> {
    scan_profiles_selected(root, &|_| true)
}

/// Consult the caller before opening each conventional or sourced file.
/// The path is absolute and still opened through the held root.
pub fn scan_profiles_selected(
    root: &ScanRoot,
    allow: &dyn Fn(&Path) -> bool,
) -> Result<ScanReport, ScanError> {
    let mut report = ScanReport::default();
    let mut seen = HashMap::new();
    for name in PROFILES {
        visit(
            root,
            Path::new(name),
            if name.ends_with(".fish") {
                Shell::Fish
            } else {
                Shell::Posix
            },
            0,
            true,
            &mut seen,
            &mut report,
            allow,
        );
    }
    Ok(report)
}
#[allow(clippy::too_many_arguments)]
fn visit(
    root: &ScanRoot,
    rel: &Path,
    shell: Shell,
    depth: usize,
    optional: bool,
    seen: &mut HashMap<PathBuf, Option<crate::ScanErrorKind>>,
    report: &mut ScanReport,
    allow: &dyn Fn(&Path) -> bool,
) {
    if depth > 4 {
        report.issue(rel, "too_deep");
        return;
    }
    if let Some(failure) = seen.get(rel) {
        if let Some(kind) = failure.filter(|_| !optional) {
            report.issue(rel, kind.token());
        }
        return;
    }
    if seen.len() >= 64 {
        report.issue(rel, "too_many_files");
        return;
    }
    seen.insert(rel.to_path_buf(), None);
    if !allow(&root.path().join(rel)) {
        report.issue(root.path().join(rel), "volume_opt_in");
        return;
    }
    crate::sources::inspect_optional_siblings(root, rel, report);
    if rel
        .file_name()
        .is_some_and(crate::sources::restore_leftover_name)
    {
        crate::sources::leftover(root, rel, report);
        return;
    }
    // Missing conventional profiles are not an incomplete scan. A missing
    // explicit source is. Unsafe existing profiles are always reported.
    let (bytes, stamp) = match read_capped(root, rel, MAX_DOTENV) {
        Ok(x) => x,
        Err(e) => {
            seen.insert(rel.to_path_buf(), Some(e.kind));
            if !optional || e.kind != crate::ScanErrorKind::NotFound {
                report.issue(rel, e.kind.token());
            }
            return;
        }
    };
    #[allow(clippy::disallowed_methods)]
    let (mut part, includes) = parse(bytes.expose_secret(), shell);
    part.files = 1;
    part.bytes = bytes.len() as u64;
    for f in &mut part.findings {
        f.source.path = root.path().join(rel);
        f.stamp = Some(stamp);
        if stamp.nlink > 1 {
            f.single_complete_line = false;
        }
    }
    for i in &mut part.issues {
        i.source.path = root.path().join(rel);
    }
    if stamp.nlink > 1 {
        part.issue(root.path().join(rel), "hard_link");
    }
    report.append(part);
    for included in includes {
        #[allow(clippy::disallowed_methods)]
        let bytes = included.path.expose_secret();
        let Ok(text) = std::str::from_utf8(bytes) else {
            report.issue(rel, "source_not_literal");
            continue;
        };
        let path = if let Some(rest) = text
            .strip_prefix("$HOME/")
            .or_else(|| text.strip_prefix("~/"))
            .filter(|_| included.expand_home)
        {
            PathBuf::from(rest)
        } else if Path::new(text).is_absolute() {
            match Path::new(text).strip_prefix(root.path()) {
                Ok(p) => p.to_path_buf(),
                Err(_) => {
                    report.issue(rel, "source_outside_root");
                    continue;
                }
            }
        } else {
            PathBuf::from(text)
        };
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            report.issue(rel, "source_outside_root");
            continue;
        }
        if seen.len() >= 64 && !seen.contains_key(&path) {
            report.issue(rel, "too_many_files");
            break;
        }
        visit(root, &path, shell, depth + 1, false, seen, report, allow);
    }
}

#[cfg(test)]
mod attempt_tests {
    use super::*;

    #[test]
    fn failed_profile_read_is_not_retried_in_same_run() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        let root = crate::open_root(d.path()).expect("root");
        let mut seen = HashMap::new();
        let mut report = ScanReport::default();
        visit(
            &root,
            Path::new("missing"),
            Shell::Posix,
            0,
            false,
            &mut seen,
            &mut report,
            &|_| true,
        );
        std::fs::write(d.path().join("missing"), b"A=fixtureZlaterCreatedValue\n").expect("write");
        visit(
            &root,
            Path::new("missing"),
            Shell::Posix,
            0,
            false,
            &mut seen,
            &mut report,
            &|_| true,
        );
        assert!(report.findings.is_empty());
        assert!(!report.complete());
        // A fresh scan recomputes state and can read the new file.
        let mut fresh = ScanReport::default();
        visit(
            &root,
            Path::new("missing"),
            Shell::Posix,
            0,
            false,
            &mut HashMap::new(),
            &mut fresh,
            &|_| true,
        );
        assert!(fresh.complete());
        assert_eq!(fresh.findings.len(), 1);
    }
}
