//! M2-26 README and compatibility matrix verification against
//! `integrations/compat/matrix.toml` and `docs/SPEC.md` §1.1.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

const AMENDED_INTRO_SENTENCE: &str = "In inject mode, EnvCloak keeps keys out of files, configs and what reaches the model, but the command you approve holds the key while it runs, and a key pasted into some agents can persist in their local history until `envcloak scrub` (§7.1).";

const UNAMENDED_CLAIMS: &[&str] = &[
    "keeps keys out of files, prompts, configs and transcripts",
    "keeps keys out of files, configs and transcripts",
    "keeps secrets out of transcripts",
    "never reaches transcripts",
];

const GUARANTEE_ROWS: &[(&str, &str)] = &[
    (
        "Secret out of `.env` files, git, shell history, agent configs",
        "Yes",
    ),
    (
        "Secret out of agent context & transcripts",
        "envcloak scrub",
    ),
    (
        "Secret out of command output shown to the agent",
        "Best-effort",
    ),
    (
        "Secret out of the child process's memory & `/proc/<pid>/environ`",
        "**No**",
    ),
    ("Bound to allowed HTTP hosts & methods", "**No**"),
    ("Per-request audit & instant revocation mid-run", "**No**"),
    (
        "Works with any tool or SDK",
        "**Every** CLI, SDK, database driver and binary",
    ),
];

#[derive(Debug, Clone)]
struct MatrixSurface {
    state: String,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct MatrixHost {
    host: String,
    version: String,
    os: String,
    surfaces: BTreeMap<String, MatrixSurface>,
    server_state: String,
    server_reasons: Vec<String>,
    server_sentinel: String,
}

fn parse_surface_line(line: &str) -> Result<MatrixSurface, String> {
    let (state, rest) = line
        .split_once(" (")
        .ok_or_else(|| format!("malformed surface line: {line:?}"))?;
    let inner = rest.trim_end_matches(')');
    let reasons = if let Some((r_part, _)) = inner.split_once("; ") {
        r_part
            .split(',')
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    Ok(MatrixSurface {
        state: state.trim().to_owned(),
        reasons,
    })
}

fn parse_server_line(line: &str) -> Result<(String, Vec<String>, String), String> {
    let (before_paren, in_paren) = line
        .split_once(" (")
        .ok_or_else(|| format!("malformed envcloak_server line: {line:?}"))?;
    let parts: Vec<String> = before_paren
        .split(';')
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let state = parts
        .first()
        .cloned()
        .ok_or_else(|| "missing server state".to_owned())?;
    let sentinel = if in_paren.contains("sentinel appeared") {
        "appeared".to_owned()
    } else {
        "missing".to_owned()
    };
    Ok((state, parts, sentinel))
}

fn parse_matrix(matrix_toml: &str) -> Result<Vec<MatrixHost>, String> {
    let doc: toml_edit::DocumentMut = matrix_toml
        .parse()
        .map_err(|e| format!("parse matrix.toml: {e}"))?;
    let hosts = doc
        .get("host")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(|| "matrix.toml has no [[host]] array".to_owned())?;
    let mut out = Vec::new();
    for entry in hosts {
        let host = entry
            .get("id")
            .or_else(|| entry.get("host"))
            .and_then(toml_edit::Item::as_str)
            .ok_or("missing host id")?
            .to_owned();
        let version = entry
            .get("version")
            .and_then(toml_edit::Item::as_str)
            .ok_or("missing version")?
            .to_owned();
        for os_key in ["macos", "linux"] {
            let Some(os_tbl) = entry.get(os_key).and_then(toml_edit::Item::as_table_like) else {
                continue;
            };
            let mut surfaces = BTreeMap::new();
            for surf_name in [
                "prompt_to_model",
                "transcript",
                "file_read",
                "shell",
                "mcp",
                "output",
            ] {
                let line = os_tbl
                    .get(surf_name)
                    .and_then(toml_edit::Item::as_str)
                    .ok_or_else(|| format!("missing {surf_name} on {host} {os_key}"))?;
                surfaces.insert(surf_name.to_owned(), parse_surface_line(line)?);
            }
            let srv_line = os_tbl
                .get("envcloak_server")
                .and_then(toml_edit::Item::as_str)
                .ok_or_else(|| format!("missing envcloak_server on {host} {os_key}"))?;
            let (server_state, server_reasons, server_sentinel) = parse_server_line(srv_line)?;
            out.push(MatrixHost {
                host: host.clone(),
                version: version.clone(),
                os: os_key.to_owned(),
                surfaces,
                server_state,
                server_reasons,
                server_sentinel,
            });
        }
    }
    Ok(out)
}

fn flat_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn markdown_cells(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    Some(
        trimmed[1..trimmed.len() - 1]
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect(),
    )
}

pub fn verify_docs_against_matrix(
    readme: &str,
    compat: &str,
    installers: &str,
    mcp_doc: &str,
    matrix_toml: &str,
) -> Result<(), String> {
    let matrix = parse_matrix(matrix_toml)?;
    if matrix.is_empty() {
        return Err("matrix.toml held zero [[host]] entries".to_owned());
    }

    let flat_readme = flat_ws(readme);
    let lower_readme = flat_readme.to_ascii_lowercase();

    // 1. Check that no unamended or unsupported transcript claim appears in README.md.
    for forbidden in UNAMENDED_CLAIMS {
        if lower_readme.contains(&forbidden.to_ascii_lowercase()) {
            return Err(format!(
                "README.md contains unamended or unsupported claim: {forbidden:?}"
            ));
        }
    }

    // 2. Check the M2-01 amended §1.1 sentence verbatim.
    if !flat_readme.contains(&flat_ws(AMENDED_INTRO_SENTENCE)) {
        return Err("README.md is missing the M2-01 amended §1.1 inject-mode sentence".to_owned());
    }

    // 3. Check that `run_with_secrets` running outside the host's sandbox is stated in README.md and docs/MCP.md.
    if !flat_readme.contains("Commands it starts run outside the agent host's sandbox")
        && !flat_readme.contains("commands it starts run outside the agent host's sandbox")
    {
        return Err(
            "README.md does not state that commands started by run_with_secrets run outside the agent host's sandbox"
                .to_owned(),
        );
    }
    let flat_mcp = flat_ws(mcp_doc);
    if !flat_mcp.contains("outside the host's sandbox")
        && !flat_mcp.contains("outside the agent host's sandbox")
    {
        return Err(
            "docs/MCP.md does not state that commands started by run_with_secrets run outside the host's sandbox"
                .to_owned(),
        );
    }

    // 4. Parse the §1.1 guarantees table in README.md and verify every row + unavailable markers.
    let mut guarantee_header_seen = false;
    let mut found_rows: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    for line in readme.lines() {
        let Some(cells) = markdown_cells(line) else {
            continue;
        };
        if cells.len() == 4 && cells[0] == "Guarantee" {
            if !cells[1].to_ascii_lowercase().contains("unavailable")
                || !cells[3].to_ascii_lowercase().contains("unavailable")
            {
                return Err(
                    "README.md guarantees table header must mark Proxy mode (M6+) and Sign-in mode (M2b+) as unavailable in this build"
                        .to_owned(),
                );
            }
            guarantee_header_seen = true;
            continue;
        }
        if guarantee_header_seen && cells.len() == 4 {
            if cells[0].starts_with("---") {
                continue;
            }
            found_rows.insert(
                cells[0].clone(),
                (cells[1].clone(), cells[2].clone(), cells[3].clone()),
            );
        } else if guarantee_header_seen && !line.trim().starts_with('|') {
            break;
        }
    }
    if !guarantee_header_seen {
        return Err("README.md is missing the §1.1 guarantees table".to_owned());
    }
    for (row_name, expected_inject_substr) in GUARANTEE_ROWS {
        let Some((proxy_cell, inject_cell, signin_cell)) = found_rows.get(*row_name) else {
            return Err(format!(
                "README.md guarantees table is missing row {row_name:?}"
            ));
        };
        if !proxy_cell.to_ascii_lowercase().contains("unavailable") {
            return Err(format!(
                "README.md guarantees row {row_name:?} Proxy column does not mark M6 as unavailable: {proxy_cell:?}"
            ));
        }
        if !signin_cell.to_ascii_lowercase().contains("unavailable") {
            return Err(format!(
                "README.md guarantees row {row_name:?} Sign-in column does not mark M2b as unavailable: {signin_cell:?}"
            ));
        }
        if !inject_cell.contains(expected_inject_substr) {
            return Err(format!(
                "README.md guarantees row {row_name:?} Inject column {inject_cell:?} does not contain {expected_inject_substr:?}"
            ));
        }
    }

    // If any host in matrix.toml has `transcript.state == "unsupported"`, the transcript guarantee row
    // in Inject mode must explicitly note persisted blocked prompts and `envcloak scrub`.
    let any_transcript_unsupported = matrix.iter().any(|h| {
        h.surfaces
            .get("transcript")
            .map(|s| s.state == "unsupported")
            .unwrap_or(false)
    });
    if any_transcript_unsupported {
        let (_, inject_transcript, _) = &found_rows["Secret out of agent context & transcripts"];
        if !inject_transcript.contains("persists blocked prompts")
            || !inject_transcript.contains("envcloak scrub")
        {
            return Err(
                "matrix.toml has a host with transcript = unsupported, so README.md's transcript row must qualify inject mode with persisted blocked prompts and `envcloak scrub`"
                    .to_owned(),
            );
        }
    }

    // 5. Parse the Agent coverage table in README.md and compare every cell with matrix.toml.
    let surface_cols = [
        "prompt_to_model",
        "transcript",
        "file_read",
        "shell",
        "mcp",
        "output",
    ];
    let mut cov_header_seen = false;
    let mut cov_rows: Vec<Vec<String>> = Vec::new();
    for line in readme.lines() {
        let Some(cells) = markdown_cells(line) else {
            if cov_header_seen && !line.trim().starts_with('|') {
                break;
            }
            continue;
        };
        if cells.len() == 10 && cells[0] == "Host" && cells[1] == "Version" && cells[2] == "OS" {
            cov_header_seen = true;
            continue;
        }
        if cov_header_seen && cells.len() == 10 {
            if cells[0].starts_with("---") {
                continue;
            }
            cov_rows.push(cells);
        }
    }
    if !cov_header_seen || cov_rows.is_empty() {
        return Err("README.md is missing the Agent coverage table".to_owned());
    }

    for entry in &matrix {
        let matching_row = cov_rows.iter().find(|r| {
            r[0].trim_matches('`') == entry.host
                && r[1].trim_matches('`') == entry.version
                && r[2]
                    .split(',')
                    .map(|s| s.trim().trim_matches('`'))
                    .any(|os| os == entry.os)
        });
        let Some(row) = matching_row else {
            return Err(format!(
                "README.md coverage table has no row for {} {} on {}",
                entry.host, entry.version, entry.os
            ));
        };
        for (idx, surf_name) in surface_cols.iter().enumerate() {
            let cell = &row[3 + idx];
            let m_surf = entry
                .surfaces
                .get(*surf_name)
                .ok_or_else(|| format!("matrix missing surface {surf_name}"))?;
            let expected_state = format!("`{}`", m_surf.state);
            if !cell.starts_with(&expected_state) {
                return Err(format!(
                    "README.md coverage claim mismatch for {} {} ({}) surface {}: README has {:?}, matrix.toml has state {:?}",
                    entry.host, entry.version, entry.os, surf_name, cell, m_surf.state
                ));
            }
            for reason in &m_surf.reasons {
                if !cell.contains(reason.as_str()) {
                    return Err(format!(
                        "README.md coverage claim for {} {} ({}) surface {} omits reason {:?}: {:?}",
                        entry.host, entry.version, entry.os, surf_name, reason, cell
                    ));
                }
            }
        }
        let srv_cell = &row[9];
        for reason in &entry.server_reasons {
            if !srv_cell.contains(reason.as_str()) {
                return Err(format!(
                    "README.md envcloak_server cell for {} {} ({}) omits {:?}: {:?}",
                    entry.host, entry.version, entry.os, reason, srv_cell
                ));
            }
        }
    }

    // Check that Tier 2 & Tier 3 row is present and claims only `unverified` (`not_probed`), never `active`.
    let tier2_row = cov_rows
        .iter()
        .find(|r| r[0].contains("Tier 2"))
        .ok_or_else(|| "README.md coverage table is missing Tier 2 & Tier 3 row".to_owned())?;
    for cell in &tier2_row[3..9] {
        if !cell.contains("`unverified`")
            || !cell.contains("`not_probed`")
            || cell.contains("`active`")
        {
            return Err(format!(
                "README.md Tier 2 & Tier 3 coverage cell must be `unverified` (`not_probed`) and never `active`: {cell:?}"
            ));
        }
    }

    // 6. Verify docs/COMPAT.md and docs/INSTALLERS.md agree with matrix.toml.
    let flat_compat = flat_ws(compat);
    let flat_installers = flat_ws(installers);
    for entry in &matrix {
        if !flat_compat.contains(&entry.version) || !flat_installers.contains(&entry.version) {
            return Err(format!(
                "docs/COMPAT.md or docs/INSTALLERS.md is missing pinned version {} for {}",
                entry.version, entry.host
            ));
        }
        assert_eq!(entry.server_state, "needs_host_approval");
        assert_eq!(entry.server_sentinel, "appeared");
    }
    if !flat_compat.contains("persists_blocked_prompt")
        || !flat_compat.contains("sandbox_blocks_socket")
        || !flat_compat.contains("outside_host_sandbox")
        || !flat_compat.contains("not reliably used")
    {
        return Err(
            "docs/COMPAT.md is missing required matrix reasons or the real-model release rule"
                .to_owned(),
        );
    }

    // 7. No em dashes in README.md or docs/COMPAT.md.
    if readme.contains('\u{2014}') {
        return Err("README.md contains an em dash (U+2014)".to_owned());
    }
    if compat.contains('\u{2014}') {
        return Err("docs/COMPAT.md contains an em dash (U+2014)".to_owned());
    }

    Ok(())
}

#[test]
fn readme_and_compat_match_probe_matrix() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let compat = std::fs::read_to_string(root.join("docs/COMPAT.md")).expect("read docs/COMPAT.md");
    let installers =
        std::fs::read_to_string(root.join("docs/INSTALLERS.md")).expect("read docs/INSTALLERS.md");
    let mcp_doc = std::fs::read_to_string(root.join("docs/MCP.md")).expect("read docs/MCP.md");
    let matrix_toml = std::fs::read_to_string(root.join("integrations/compat/matrix.toml"))
        .expect("read integrations/compat/matrix.toml");

    verify_docs_against_matrix(&readme, &compat, &installers, &mcp_doc, &matrix_toml)
        .unwrap_or_else(|e| panic!("README / COMPAT matrix check failed: {e}"));

    // Negative controls (also exercising Mutation Check 8):
    // 1. Putting the unamended §1.1 sentence back into README.md must fail.
    let unamended = readme.replace(
        AMENDED_INTRO_SENTENCE,
        "In inject mode, EnvCloak keeps keys out of files, prompts, configs and transcripts, though the child process holds the key in memory while it runs.",
    );
    assert!(
        verify_docs_against_matrix(&unamended, &compat, &installers, &mcp_doc, &matrix_toml)
            .is_err(),
        "unamended §1.1 sentence in README.md must be rejected"
    );

    // 2. Claiming Claude Code's transcript surface is `active` or `degraded` instead of `unsupported` must fail.
    let bad_transcript = readme.replace("`unsupported` (`persists_blocked_prompt`)", "`active`");
    assert!(
        verify_docs_against_matrix(
            &bad_transcript,
            &compat,
            &installers,
            &mcp_doc,
            &matrix_toml
        )
        .is_err(),
        "claiming Claude Code transcript surface is active must be rejected"
    );

    // 3. Claiming Claude Code's prompt_to_model is `active` must fail.
    let bad_prompt = readme.replacen(
        "`degraded` (`fails_open_on_timeout`, `workspace_untrusted`)",
        "`active`",
        1,
    );
    assert!(
        verify_docs_against_matrix(&bad_prompt, &compat, &installers, &mcp_doc, &matrix_toml)
            .is_err(),
        "claiming Claude Code prompt_to_model is active must be rejected"
    );
}
