//! Gate 22 through M3 (M3 plan R-M3-41, task M3-01). docs/IPC.md's
//! "App-role methods" says that gate 22 keeps holding and that each task
//! that lands an app method adds its name to `APP_METHODS`, which the
//! gate's test, crates/envcloak-daemon/tests/roles.rs, calls one by one
//! from a client peer. This test holds the three to that: the paragraph
//! names the gate, its test, `APP_METHODS`, this file and the evidence
//! rule of SPEC §10b; roles.rs calls every name in `APP_METHODS` and wants
//! `role_denied` for each; every name in `APP_METHODS` has a row in the
//! `app_method` reservations table; and every app method that is built,
//! read two ways, is in `APP_METHODS`, so no app method reaches a peer
//! without the gate's test calling it from a client: each row whose status
//! is not `reserved` (`landed`, `reuse`, or any status a later change
//! adds), and each `const NAME` starting with `app.` in envcloak-ipc's
//! sources, whatever its row says. Each rule is also shown to refuse a
//! copy of the texts changed one way.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const IPC: &str = "docs/IPC.md";
const PROTO: &str = "crates/envcloak-ipc/src/proto.rs";
const IPC_SRC: &str = "crates/envcloak-ipc/src";
const ROLES: &str = "crates/envcloak-daemon/tests/roles.rs";

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap()
}

/// Every Rust file under `dir`, in a fixed order, as one text.
fn sources(dir: &Path) -> String {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
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

/// The value of every `const NAME` whose statement holds a string literal
/// starting with `app.`: the app methods the code declares, read apart
/// from the reservation script's reader.
fn code_app_methods(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = code[at..].find("const NAME") {
        let start = at + i;
        let end = start + code[start..].find(';').unwrap_or(code.len() - start);
        let stmt = &code[start..end];
        if let Some(q) = stmt.find("\"app.") {
            let rest = &stmt[q + 1..];
            if let Some(close) = rest.find('"') {
                out.push(rest[..close].to_owned());
            }
        }
        at = end;
    }
    out
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

/// What breaks the rules above in these texts; `code` is envcloak-ipc's
/// sources.
fn problems(ipc: &str, proto: &str, code: &str, roles: &str) -> Vec<String> {
    let mut out = Vec::new();
    match m3_paragraph(ipc) {
        None => out.push("IPC.md's \"App-role methods\" has no paragraph from M3".to_owned()),
        Some(p) => {
            for want in [
                "gate 22 (SPEC §15.2) keeps holding through M3",
                "`APP_METHODS` in `crates/envcloak-ipc/src/proto.rs`",
                "`crates/envcloak-daemon/tests/roles.rs`",
                "`crates/envcloak-testkit/tests/app_role_gate.rs`",
                "every `app.` request but `app.lock` is answered `proof_refused` and audited before anything else is done",
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
    // Every status but `reserved` says the code holds the method: `landed`
    // and `reuse`, and any status added later, so a new one fails closed.
    for (name, status) in &rows {
        if status != "reserved" && !listed.contains(name) {
            out.push(format!(
                "`{name}` is {status} but APP_METHODS lacks it, so gate 22's test never calls it"
            ));
        }
    }
    for name in code_app_methods(code) {
        if !listed.contains(&name) {
            out.push(format!(
                "the code declares `{name}` but APP_METHODS lacks it, so gate 22's test never calls it"
            ));
        }
    }
    out
}

fn tree() -> (String, String, String, String) {
    (
        read(IPC),
        read(PROTO),
        sources(&repo_root().join(IPC_SRC)),
        read(ROLES),
    )
}

/// The tree keeps the three in step.
///
/// Mutation checked: the gate-22 sentence cut from IPC.md's app-role
/// paragraph (the review's probe P6, which every check passed): this test
/// fails.
#[test]
fn the_tree_keeps_gate_22_over_every_app_method() {
    let (ipc, proto, code, roles) = tree();
    assert!(
        code.contains("const NAME: &'static str = \"status\";"),
        "the sources were read"
    );
    assert_eq!(problems(&ipc, &proto, &code, &roles), Vec::<String>::new());
}

/// Adds `row` as the last row of IPC.md's first `app_method` table.
fn with_row(ipc: &str, row: &str) -> String {
    let table = ipc.find("<!-- reservations:app_method -->").unwrap();
    let close = table + ipc[table..].find("<!-- /reservations -->").unwrap();
    format!("{}{row}\n{}", &ipc[..close], &ipc[close..])
}

/// Each rule refuses a copy changed one way: an app method built but
/// missing from `APP_METHODS`, by a `landed` or a `reuse` row (probe rows,
/// so the cases hold as tasks land theirs) and by the code alone, a name in
/// `APP_METHODS` with no row, a paragraph without the gate or without the
/// evidence rule, and a roles.rs that no longer calls the list.
///
/// Mutation checked: the status rule written `status == "landed"`, as in
/// round two (Codex's probe, a `reuse` app method outside the gate): the
/// `reuse` case passes, and this test fails. And the code rule removed
/// from `problems`: the code-only case passes, and this test fails.
#[test]
fn each_rule_refuses_a_copy_changed_one_way() {
    let (ipc, proto, code, roles) = tree();
    for status in ["landed", "reuse"] {
        let built = with_row(
            &ipc,
            &format!("| `app.zz_probe` | M3-16 | {status} | a probe row |"),
        );
        assert_eq!(
            problems(&built, &proto, &code, &roles),
            vec![format!(
                "`app.zz_probe` is {status} but APP_METHODS lacks it, so gate 22's test never calls it"
            )],
            "{status}"
        );
    }
    // A reserved probe row is not built yet, and passes.
    let reserved = with_row(&ipc, "| `app.zz_probe` | M3-16 | reserved | a probe row |");
    assert_eq!(
        problems(&reserved, &proto, &code, &roles),
        Vec::<String>::new()
    );
    // The code declares an app method that APP_METHODS lacks, whatever its
    // row says.
    let declared = format!(
        "{code}\nimpl Method for ZzProbe {{\n    const NAME: &'static str = \"app.zz_probe\";\n}}\n"
    );
    assert_eq!(
        problems(&reserved, &proto, &declared, &roles),
        vec![
            "the code declares `app.zz_probe` but APP_METHODS lacks it, so gate 22's test never calls it"
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
        problems(&unlisted, &proto, &code, &roles),
        vec!["`app.paste` is in APP_METHODS but no app_method row has it".to_owned()]
    );
    let silent = ipc.replacen(
        "gate 22 (SPEC §15.2) keeps holding through M3",
        "the role check keeps holding through M3",
        1,
    );
    assert_ne!(silent, ipc);
    assert_eq!(problems(&silent, &proto, &code, &roles).len(), 1);
    let any_evidence = ipc.replacen(
        "every `app.` request but `app.lock` is answered `proof_refused`",
        "every `app.` request is answered",
        1,
    );
    assert_ne!(any_evidence, ipc);
    assert_eq!(problems(&any_evidence, &proto, &code, &roles).len(), 1);
    let unused = roles.replacen("APP_METHODS.to_vec()", "vec![\"app.unlock\"]", 1);
    assert_ne!(unused, roles);
    assert_eq!(problems(&ipc, &proto, &code, &unused).len(), 1);
}
