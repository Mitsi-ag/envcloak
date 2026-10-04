//! Gate 22 through M3 (M3 plan R-M3-41, task M3-01). docs/IPC.md's
//! "App-role methods" says that gate 22 keeps holding and that each task
//! that lands an app method adds its name to `APP_METHODS`, which the
//! gate's test, crates/envcloak-daemon/tests/roles.rs, calls one by one
//! from a client peer. This test holds the three to that: the paragraph
//! names the gate, its test, `APP_METHODS` and this file; roles.rs calls
//! every name in `APP_METHODS` and wants `role_denied` for each; every
//! name in `APP_METHODS` has a row in the `app_method` reservations table;
//! and every `landed` row's method is in `APP_METHODS`, so no app method
//! reaches a peer without the gate's test calling it from a client.
//! Each rule is also shown to refuse a copy of the texts changed one way.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const IPC: &str = "docs/IPC.md";
const PROTO: &str = "crates/envcloak-ipc/src/proto.rs";
const ROLES: &str = "crates/envcloak-daemon/tests/roles.rs";

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap()
}

/// The paragraph of IPC.md's "App-role methods" that begins "From M3".
fn m3_paragraph(ipc: &str) -> Option<&str> {
    let section = ipc.find("\n## App-role methods\n")?;
    let rest = &ipc[section..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    rest[..end].split("\n\n").find(|p| p.starts_with("From M3"))
}

/// The names in `pub const APP_METHODS: [&str; N] = [...]`, or None when
/// the list cannot be read as string literals alone.
fn app_methods(proto: &str) -> Option<Vec<String>> {
    let start = proto.find("pub const APP_METHODS: [&str; ")?;
    let open = start + proto[start..].find("= [")? + 3;
    let close = open + proto[open..].find("];")?;
    let mut names = Vec::new();
    for item in proto[open..close].split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let name = item.strip_prefix('"')?.strip_suffix('"')?;
        names.push(name.to_owned());
    }
    Some(names)
}

/// (method, status) of every row of every `app_method` table in IPC.md.
fn app_method_rows(ipc: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut at = 0;
    while let Some(i) = ipc[at..].find("<!-- reservations:app_method -->") {
        let open = at + i;
        let close = open + ipc[open..].find("<!-- /reservations -->").unwrap();
        for line in ipc[open..close].lines().skip(3) {
            let cells: Vec<&str> = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            let name = cells[0].trim_matches('`').to_owned();
            rows.push((name, cells[2].to_owned()));
        }
        at = close;
    }
    rows
}

/// What breaks the rules above in these texts.
fn problems(ipc: &str, proto: &str, roles: &str) -> Vec<String> {
    let mut out = Vec::new();
    match m3_paragraph(ipc) {
        None => out.push("IPC.md's \"App-role methods\" has no paragraph from M3".to_owned()),
        Some(p) => {
            for want in [
                "gate 22 (SPEC §15.2) keeps holding through M3",
                "`APP_METHODS` in `crates/envcloak-ipc/src/proto.rs`",
                "`crates/envcloak-daemon/tests/roles.rs`",
                "`crates/envcloak-testkit/tests/app_role_gate.rs`",
            ] {
                if !p.contains(want) {
                    out.push(format!("IPC.md's app-role paragraph does not say {want}"));
                }
            }
        }
    }
    for want in [
        "use envcloak_ipc::proto::APP_METHODS;",
        "let mut methods: Vec<&str> = APP_METHODS.to_vec();",
        "assert_eq!(error_kind(&r), \"role_denied\", \"{m}\");",
    ] {
        if !roles.contains(want) {
            out.push(format!("roles.rs does not hold {want:?}"));
        }
    }
    let Some(listed) = app_methods(proto) else {
        out.push("proto.rs has no `APP_METHODS` of string literals".to_owned());
        return out;
    };
    let rows = app_method_rows(ipc);
    if rows.is_empty() {
        out.push("IPC.md has no `app_method` rows".to_owned());
    }
    for name in &listed {
        if !rows.iter().any(|(n, _)| n == name) {
            out.push(format!(
                "`{name}` is in APP_METHODS but no app_method row has it"
            ));
        }
    }
    for (name, status) in &rows {
        if status == "landed" && !listed.contains(name) {
            out.push(format!(
                "`{name}` is landed but APP_METHODS lacks it, so gate 22's test never calls it"
            ));
        }
    }
    out
}

/// The tree keeps the three in step.
///
/// Mutation checked: the gate-22 sentence cut from IPC.md's app-role
/// paragraph (the review's probe P6, which every check passed): this test
/// fails.
#[test]
fn the_tree_keeps_gate_22_over_every_app_method() {
    assert_eq!(
        problems(&read(IPC), &read(PROTO), &read(ROLES)),
        Vec::<String>::new()
    );
}

/// Each rule refuses a copy changed one way: a landed app method missing
/// from `APP_METHODS` (a probe row, so the case holds as tasks land theirs), a name in `APP_METHODS` with no row, a paragraph
/// without the gate, and a roles.rs that no longer calls the list.
///
/// Mutation checked: the landed-row rule removed from `problems`: the
/// first case passes, and this test fails.
#[test]
fn each_rule_refuses_a_copy_changed_one_way() {
    let (ipc, proto, roles) = (read(IPC), read(PROTO), read(ROLES));
    // A probe row, so the case holds whatever the real rows' statuses.
    let table = ipc.find("<!-- reservations:app_method -->").unwrap();
    let close = table + ipc[table..].find("<!-- /reservations -->").unwrap();
    let landed = format!(
        "{}| `app.zz_probe` | M3-16 | landed | a probe row |\n{}",
        &ipc[..close],
        &ipc[close..]
    );
    assert_eq!(
        problems(&landed, &proto, &roles),
        vec![
            "`app.zz_probe` is landed but APP_METHODS lacks it, so gate 22's test never calls it"
                .to_owned()
        ]
    );
    let unlisted = ipc.replacen(
        "| `app.paste` | M3-14 |",
        "| `app.paste_value` | M3-14 |",
        1,
    );
    assert_ne!(unlisted, ipc);
    assert_eq!(
        problems(&unlisted, &proto, &roles),
        vec!["`app.paste` is in APP_METHODS but no app_method row has it".to_owned()]
    );
    let silent = ipc.replacen(
        "gate 22 (SPEC §15.2) keeps holding through M3",
        "the role check keeps holding through M3",
        1,
    );
    assert_ne!(silent, ipc);
    assert_eq!(problems(&silent, &proto, &roles).len(), 1);
    let unused = roles.replacen("APP_METHODS.to_vec()", "vec![\"app.unlock\"]", 1);
    assert_ne!(unused, roles);
    assert_eq!(problems(&ipc, &proto, &unused).len(), 1);
}
