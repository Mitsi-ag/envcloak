//! First-run cleanup transforms. Authority and the four deletion conditions
//! are checked by the CLI against the daemon before using atomic replacement.
use crate::candidates::{Disposition, Found};
use envcloak_core::vault::Slug;
use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;

/// Comment out proven, complete physical assignment lines. Selection carries
/// only parser indices and daemon-produced slugs. Every other byte survives.
#[allow(clippy::disallowed_methods)] // Copy retained spans into wiping storage.
pub fn comment_assignments(
    input: &SecretBytes,
    findings: &[Found],
    selected: &[(usize, &str)],
) -> Result<SecretBytes, &'static str> {
    let bytes = input.expose_secret();
    let mut changes = Vec::new();
    for &(index, slug) in selected {
        let f = findings.get(index).ok_or("invalid_selection")?;
        if f.disposition != Disposition::Literal || !f.single_complete_line {
            return Err("manual_assignment");
        }
        if Slug::new(slug).is_err() {
            return Err("invalid_reference");
        }
        let start = usize::try_from(f.range.start).map_err(|_| "invalid_range")?;
        let end = usize::try_from(f.range.end).map_err(|_| "invalid_range")?;
        let line = bytes.get(start..end).ok_or("invalid_range")?;
        if start == end || (start > 0 && bytes[start - 1] != b'\n') {
            return Err("invalid_range");
        }
        changes.push((start, end, slug, line.ends_with(b"\n")));
    }
    changes.sort_by_key(|c| c.0);
    let extra: usize = changes.iter().map(|c| c.2.len() + 40).sum();
    let mut out = SecretBuf::with_capacity(bytes.len().saturating_add(extra));
    let mut cursor = 0;
    for (start, end, slug, newline) in changes {
        if start < cursor {
            return Err("overlapping_assignment");
        }
        out.extend(&bytes[cursor..start]).map_err(|_| "too_large")?;
        out.extend(format!("# envcloak: {slug}; use envcloak run").as_bytes())
            .map_err(|_| "too_large")?;
        if newline {
            out.extend(b"\n").map_err(|_| "too_large")?;
        }
        cursor = end;
    }
    out.extend(&bytes[cursor..]).map_err(|_| "too_large")?;
    Ok(out.freeze())
}
