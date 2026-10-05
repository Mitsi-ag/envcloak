//! `scripts/check-reservations.py` on the M3 reservations (M3 plan, task
//! M3-01), on the real tree and on copies of the files it reads, each
//! changed one way. The M3 rows are read under their own heading as one
//! table with M2's per registry: a number or name taken in both fails, a
//! row under the other milestone's heading fails, the M3 task and join ids
//! are known and no other, app-role methods and unlocker kinds are read
//! from the code, every row the M3 plan lists is reserved whatever its
//! status, and no M3 name is one another registry holds. The decoders that
//! read a stored unlocker kind, item class or policy kind back are read
//! too: a second number for one entry fails, and so does a declared entry
//! the decoder does not read back, but the one the script names as never
//! stored; and `AuditKind::ALL` and `ErrorKind::ALL`, which their decoders
//! search, must name every variant once. The tests hold whatever status
//! the real rows have by then, so an M3 task that lands its rows changes
//! nothing here. The M2 and M2b cases are in check_reservations.rs; these
//! are in a file of their own so that lanes appending tests to either do
//! not edit one file's end.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SCRIPT: &str = "scripts/check-reservations.py";
const VAULT: &str = "docs/VAULT.md";
const IPC: &str = "docs/IPC.md";
const BASELINE: &str = "scripts/check-reservations-baseline.txt";
const PROTO: &str = "crates/envcloak-ipc/src/proto.rs";
const POLICIES: &str = "crates/envcloak-core/src/vault/policies.rs";
const RECORD: &str = "crates/envcloak-core/src/audit/record.rs";

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &dest);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// A copy of what the script reads (the two documents, the baseline, the
/// workspace's manifest, and every crate's `src/`, manifest and build
/// script), under a fresh test home.
fn fixture() -> TestHome {
    let t = TestHome::new();
    let root = t.home();
    for rel in [IPC, VAULT, BASELINE, "Cargo.toml"] {
        let dest = root.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(rel), dest).unwrap();
    }
    for entry in std::fs::read_dir(repo_root().join("crates")).unwrap() {
        let entry = entry.unwrap();
        let src = entry.path().join("src");
        if src.is_dir() {
            let dest = root.join("crates").join(entry.file_name());
            copy_dir(&src, &dest.join("src"));
            for file in ["Cargo.toml", "build.rs"] {
                if entry.path().join(file).is_file() {
                    std::fs::copy(entry.path().join(file), dest.join(file)).unwrap();
                }
            }
        }
    }
    t
}

/// Replaces the one occurrence of `from` in `rel` with `to`.
fn edit(t: &TestHome, rel: &str, from: &str, to: &str) {
    let path = t.home().join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {rel}");
    std::fs::write(path, text.replacen(from, to, 1)).unwrap();
}

fn run(root: &Path) -> Output {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    t.apply(&mut cmd)
        .arg(repo_root().join(SCRIPT))
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

fn assert_passes(root: &Path) {
    let out = run(root);
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("check-reservations: ok"));
}

fn assert_fails(t: &TestHome, expect_in_message: &str) {
    let out = run(&t.home());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "expected a failure: {stderr}");
    assert!(
        stderr.contains(expect_in_message),
        "expected {expect_in_message:?} in: {stderr}"
    );
}

/// Appends a method `name` to the copy of proto.rs.
fn add_method(t: &TestHome, name: &str) {
    let path = t.home().join(PROTO);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{text}\npub struct Added;\n\nimpl Method for Added {{\n    const NAME: &'static str = \"{name}\";\n    type Params = NoParams;\n    type Output = LockedView;\n}}\n"
        ),
    )
    .unwrap();
}

#[test]
fn the_real_tree_passes() {
    assert_passes(&repo_root());
}

const ENVELOPE: &str = "crates/envcloak-core/src/crypto/envelope.rs";
const STATE: &str = "crates/envcloak-core/src/vault/state.rs";
const AAD: &str = "crates/envcloak-core/src/crypto/aad.rs";
const M3: &str = "\n## Reserved for M3\n";

/// The part of a document's text under its "## Reserved for M3" heading,
/// up to the next `## ` heading or the end.
fn m3_section_of(text: &str) -> &str {
    let start = text.find(M3).unwrap() + 1;
    let rest = &text[start..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

/// Adds `row` as the last row of the `registry` table under "Reserved for
/// M3" in `doc` of the copy, whatever rows that table holds by then.
fn add_m3_row(t: &TestHome, doc: &str, registry: &str, row: &str) {
    let path = t.home().join(doc);
    let text = std::fs::read_to_string(&path).unwrap();
    let section = text.find(M3).unwrap();
    let marker = format!("<!-- reservations:{registry} -->");
    let open = section + text[section..].find(&marker).unwrap();
    let close = open + text[open..].find("<!-- /reservations -->").unwrap();
    std::fs::write(
        &path,
        format!("{}{row}\n{}", &text[..close], &text[close..]),
    )
    .unwrap();
}

/// Every row task M3-01 reserves, by the cells before its status: its
/// name (and number, or method), and the lane-C task the M3 plan builds it
/// in. The status is left to the script, which checks it against the code,
/// so a task that lands its row changes nothing here (review: a test that
/// pinned `reserved` would refuse every M3 task's landing).
const M3_ROWS: &[(&str, &str)] = &[
    (IPC, "| `signature_invalid` | -32051 | M3-09 |"),
    (IPC, "| `unlock_failed` | -32052 | M3-08 |"),
    (IPC, "| `no_unlocker` | -32053 | M3-08 |"),
    (IPC, "| `ask_closed` | -32054 | M3-14 |"),
    (IPC, "| `last_unlocker` | -32055 | M3-14 |"),
    (IPC, "| `statement_mismatch` | -32018 | M3-14 |"),
    (IPC, "| `proof_refused` | -32019 | M3-08 |"),
    (IPC, "| `code_identity` | M3-07 |"),
    (IPC, "| `rolled_back` | M3-16 |"),
    (IPC, "| `keychain_anchor_missing` | M3-16 |"),
    (IPC, "| `projects.list` | M3-04 |"),
    (IPC, "| `items.ask` | M3-14 |"),
    (IPC, "| `items.ask_state` | M3-14 |"),
    (IPC, "| `reveal.request` | M3-14 |"),
    (IPC, "| `app.pending.list` | M3-09 |"),
    (IPC, "| `app.pending.get` | M3-09 |"),
    (IPC, "| `app.approve` | M3-09 |"),
    (IPC, "| `app.unlocker.enroll.begin` | M3-08 |"),
    (IPC, "| `app.unlocker.enroll` | M3-08 |"),
    (IPC, "| `app.unlocker.add` | M3-14 |"),
    (IPC, "| `app.unlocker.remove` | M3-14 |"),
    (IPC, "| `app.unlock.begin` | M3-08 |"),
    (IPC, "| `app.unlock` | M3-08 |"),
    (IPC, "| `app.items.target` | M3-14 |"),
    (IPC, "| `app.items.rotate` | M3-14 |"),
    (IPC, "| `app.items.remove` | M3-14 |"),
    (IPC, "| `app.reveal.begin` | M3-14 |"),
    (IPC, "| `app.reveal` | M3-14 |"),
    (IPC, "| `app.paste.begin` | M3-14 |"),
    (IPC, "| `app.paste.inspect` | M3-14 |"),
    (IPC, "| `app.paste` | M3-14 |"),
    (IPC, "| `app.asks.list` | M3-14 |"),
    (IPC, "| `app.asks.decline` | M3-14 |"),
    (IPC, "| `app.audit.list` | M3-16 |"),
    (IPC, "| `app.lock` | M3-16 |"),
    (IPC, "| `app.policy.set` | spare |"),
    (IPC, "| `app.registry.override` | spare |"),
    (IPC, "| `app.device.add` | M5 |"),
    (IPC, "| `app.device.remove` | M5 |"),
    (IPC, "| `status` | `vault.keychain_anchor` | M3-16 |"),
    (IPC, "| `status` | `app_requests` | M3-14 |"),
    (IPC, "| `status` | `lock.reason=screen_lock` | M3-16 |"),
    (IPC, "| `status` | `lock.reason=session_resign` | M3-16 |"),
    (IPC, "| `binding_absent` | M3-04 |"),
    (IPC, "| `declined` | M3-19 |"),
    (IPC, "| `expired` | M3-19 |"),
    (IPC, "| `envcloak-unlocker-statement/1` | M3-08 |"),
    (IPC, "| `envcloak-write-statement/1` | M3-14 |"),
    (IPC, "| `envcloak-reveal-statement/1` | M3-14 |"),
    (VAULT, "| 46 | `unlocker_add` | M3-08 |"),
    (VAULT, "| 47 | `unlocker_remove` | M3-14 |"),
    (VAULT, "| 48 | `reveal_app` | M3-14 |"),
    (VAULT, "| 49 | `ask` | M3-14 |"),
    (VAULT, "| 50 | `keychain_anchor_mismatch` | M3-16 |"),
    (VAULT, "| 3 | `secure_enclave` | M3-08 |"),
];

/// Rows the M3 plan names that M3-01 does not reserve, with the reason in
/// IPC.md's "Reserved for M3": `daemon.identity` is the CLI's own output
/// since M1, the keychain anchor's names say `keychain`, apart from the
/// audit log's `anchor_mismatch`, and run approvals are
/// `envcloak-statement/2` since M2-13 (its row is M2-13's, and version 1
/// digests are refused).
const NOT_M3_ROWS: &[(&str, &str)] = &[
    (IPC, "| `status` | `daemon.identity` |"),
    (IPC, "| `envcloak-statement/1` |"),
    (IPC, "| `envcloak-statement/2` |"),
    (IPC, "| `status` | `vault.anchor` |"),
    (IPC, "| `anchor_missing` |"),
    (VAULT, "| 50 | `anchor_mismatch` |"),
];

/// `text` with the status of the row under "Reserved for M3" that starts
/// with `lead` set to `status`, whatever it was: tests set a status rather
/// than assume one, so they hold as tasks land their rows (review: a
/// replacement of `| reserved |` changed nothing once the row landed).
fn with_status(text: &str, lead: &str, status: &str) -> String {
    let section = text.find(M3).unwrap();
    let at = section + text[section..].find(&format!("\n{lead}")).unwrap() + 1;
    let end = at + text[at..].find('\n').unwrap();
    let rest = &text[at + lead.len()..end];
    let cell = 1 + rest[1..].find('|').unwrap();
    format!(
        "{}{lead} {status} {}{}",
        &text[..at],
        &rest[cell..],
        &text[end..]
    )
}

/// What is wrong with the M3 rows of these two documents' texts.
fn m3_row_problems(ipc: &str, vault: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let section = |doc: &str| m3_section_of(if doc == IPC { ipc } else { vault }).to_owned();
    for (doc, lead) in M3_ROWS {
        let text = section(doc);
        let rows: Vec<&str> = text.lines().filter(|l| l.starts_with(lead)).collect();
        if rows.len() != 1 {
            problems.push(format!(
                "{lead} is under {doc}'s heading {} times",
                rows.len()
            ));
            continue;
        }
        let status = rows[0][lead.len()..].trim_start();
        if !["reserved |", "landed |", "reuse |"]
            .iter()
            .any(|s| status.starts_with(s))
        {
            problems.push(format!("{lead} has no status"));
        }
    }
    for (doc, lead) in NOT_M3_ROWS {
        if section(doc).lines().any(|l| l.starts_with(lead)) {
            problems.push(format!("{lead} is a row under {doc}'s heading"));
        }
    }
    problems
}

/// Every name and number the M3 plan's task M3-01 lists is reserved under
/// "Reserved for M3", with the lane-C task the plan builds it in: methods
/// (client and app role), fields, error kinds from -32051, reasons, exit
/// tokens, statement domains, audit kinds from 46 and unlocker kind 3. A
/// row whose status a later task changes still counts, and the names this
/// task left out on purpose stay out.
///
/// Mutation checked: the `app.lock` row deleted from docs/IPC.md: the
/// script still passes (it does not know the plan), and this test fails.
/// And the rows matched with their status, as the first round did: the
/// copy with `projects.list` landed fails, and this test fails. And, from
/// round three, the test made to replace `| reserved |` as round two did
/// (Codex's finding): with the row landed first, as M3-04 will, it fails.
#[test]
fn every_row_the_m3_plan_reserves_is_under_its_heading() {
    let read = |doc: &str| std::fs::read_to_string(repo_root().join(doc)).unwrap();
    let (ipc, vault) = (read(IPC), read(VAULT));
    assert_eq!(m3_row_problems(&ipc, &vault), Vec::<String>::new());
    // A task landing a row changes its status alone, from any status the
    // row has by then.
    let lead = "| `projects.list` | M3-04 |";
    for first in ["reserved", "landed"] {
        let base = with_status(&ipc, lead, first);
        for status in ["reserved", "landed", "reuse"] {
            let changed = with_status(&base, lead, status);
            assert!(
                changed.contains(&format!("\n{lead} {status} | ")),
                "{status}"
            );
            assert_eq!(m3_row_problems(&changed, &vault), Vec::<String>::new());
        }
        let unknown = with_status(&base, lead, "pending");
        assert_eq!(
            m3_row_problems(&unknown, &vault),
            vec![format!("{lead} has no status")]
        );
    }
    // A row renamed away, or put back under a plan name left out, is not.
    let gone = ipc.replacen("| `app.lock` | M3-16 |", "| `app.lock_screen` | M3-16 |", 1);
    assert_ne!(gone, ipc);
    assert!(
        m3_row_problems(&gone, &vault)
            .iter()
            .any(|p| p.contains("`app.lock` | M3-16 |"))
    );
    let back = vault.replacen(
        "| 50 | `keychain_anchor_mismatch` |",
        "| 50 | `anchor_mismatch` |",
        1,
    );
    assert_ne!(back, vault);
    assert_eq!(m3_row_problems(&ipc, &back).len(), 2);
}

/// What each registry's tables (in both documents and both sections) and
/// the baseline name: (registry, name, status, whether the row is under
/// "Reserved for M3"). A baseline line has the status `baseline`.
fn registry_names(ipc: &str, vault: &str, baseline: &str) -> Vec<(String, String, String, bool)> {
    let mut out = Vec::new();
    for text in [ipc, vault] {
        let m3_at = text.find(M3).unwrap_or(text.len());
        let mut at = 0;
        while let Some(i) = text[at..].find("<!-- reservations:") {
            let open = at + i;
            let reg_end = open + text[open..].find(" -->").unwrap();
            let reg = &text[open + "<!-- reservations:".len()..reg_end];
            let close = open + text[open..].find("<!-- /reservations -->").unwrap();
            for line in text[reg_end..close].lines().skip(3) {
                let cells: Vec<&str> = line
                    .trim()
                    .trim_matches('|')
                    .split('|')
                    .map(str::trim)
                    .collect();
                let ticked: Vec<&str> = cells
                    .iter()
                    .filter(|c| c.len() > 2 && c.starts_with('`') && c.ends_with('`'))
                    .map(|c| &c[1..c.len() - 1])
                    .collect();
                let name = if reg == "field" || reg == "control_message" {
                    ticked[1]
                } else {
                    ticked[0]
                };
                let status = cells[cells.len() - 2];
                out.push((
                    reg.to_owned(),
                    name.to_owned(),
                    status.to_owned(),
                    open > m3_at,
                ));
            }
            at = close;
        }
    }
    for line in baseline.lines() {
        let words: Vec<&str> = line.split('#').next().unwrap().split_whitespace().collect();
        if words.len() >= 2 {
            out.push((
                words[0].to_owned(),
                words[1].to_owned(),
                "baseline".to_owned(),
                false,
            ));
        }
    }
    out
}

/// Names an M3 row may share with another registry because the two mean
/// one thing; a reviewer adds a pair here only after agreeing so. Empty.
const M3_SHARED: &[(&str, &str)] = &[];

/// The M3 rows, `reserved` or `landed`, whose name another registry
/// already holds. A `reuse` row names an entry its own registry already
/// has, so it brings no name of its own.
fn m3_names_held_elsewhere(ipc: &str, vault: &str, baseline: &str) -> Vec<String> {
    let all = registry_names(ipc, vault, baseline);
    let mut problems = Vec::new();
    for (reg, name, status, in_m3) in &all {
        if !in_m3 || status == "reuse" || M3_SHARED.contains(&(reg.as_str(), name.as_str())) {
            continue;
        }
        for (other, other_name, other_status, _) in &all {
            if other != reg && other_name == name {
                problems.push(format!(
                    "`{reg}` `{name}` is also `{other}` ({other_status})"
                ));
            }
        }
    }
    problems
}

/// No name an M3 row reserves is one another registry already holds, in
/// its tables or in the baseline (review: audit kind 50 was reserved as
/// `anchor_mismatch`, which `audit.verify` and the CLI already use for the
/// audit log's saved head, not the keychain anchor). The tree holds none;
/// the round-one name put back is found.
///
/// The rule holds once the row has landed (Codex's finding: the test read
/// `reserved` rows alone, so M3-16 landing kind 50 would have let the old
/// name back in unseen).
///
/// Mutation checked: the comparison made within one registry only
/// (`other == reg`): the round-one name passes, and this test fails. And
/// the rows read when `reserved` alone, as in round two: the landed case
/// passes, and this test fails.
#[test]
fn no_m3_reserved_name_is_another_registrys() {
    let read = |rel: &str| std::fs::read_to_string(repo_root().join(rel)).unwrap();
    let (ipc, vault, baseline) = (read(IPC), read(VAULT), read(BASELINE));
    assert!(
        registry_names(&ipc, &vault, &baseline)
            .iter()
            .any(|(reg, name, _, m3)| reg == "audit_kind"
                && name == "keychain_anchor_mismatch"
                && *m3),
        "the reader finds the M3 rows"
    );
    assert_eq!(
        m3_names_held_elsewhere(&ipc, &vault, &baseline),
        Vec::<String>::new()
    );
    let lead = "| 50 | `keychain_anchor_mismatch` | M3-16 |";
    for status in ["reserved", "landed"] {
        let back = with_status(&vault, lead, status).replacen(
            "| 50 | `keychain_anchor_mismatch` |",
            "| 50 | `anchor_mismatch` |",
            1,
        );
        assert!(back.contains(&format!("| 50 | `anchor_mismatch` | M3-16 | {status} |")));
        assert_eq!(
            m3_names_held_elsewhere(&ipc, &back, &baseline),
            vec!["`audit_kind` `anchor_mismatch` is also `exit_token` (baseline)".to_owned()],
            "{status}"
        );
    }
}

/// A number or name is taken once across both headings: the M3 plan's
/// mutation (-32051 reserved twice) fails within its own section and
/// across the two, and so do an audit kind and a method name.
///
/// Mutation checked: check_rows starting a fresh set of names and numbers
/// for each section: the three cases across the two sections pass, and
/// this test fails.
#[test]
fn a_number_or_name_reserved_in_both_sections_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `unlock_failed` | -32052 |",
        "| `unlock_failed` | -32051 |",
    );
    assert_fails(
        &t,
        "`error_kind`: number -32051 is reserved twice (`signature_invalid` and `unlock_failed`)",
    );
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `request_conflict` | -32047 |",
        "| `request_conflict` | -32051 |",
    );
    assert_fails(
        &t,
        "`error_kind`: number -32051 is reserved twice (`request_conflict` and `signature_invalid`)",
    );
    let t = fixture();
    edit(
        &t,
        VAULT,
        "| 45 | `signin_cleanup` |",
        "| 46 | `signin_cleanup` |",
    );
    assert_fails(
        &t,
        "`audit_kind`: number 46 is reserved twice (`signin_cleanup` and `unlocker_add`)",
    );
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `items.ask` | M3-14 |",
        "| `scan.match` | M3-14 |",
    );
    assert_fails(&t, "`method`: `scan.match` is reserved twice");
}

/// The script knows the M3 plan's tasks, `M3-01` to `M3-21`, and its joins,
/// `M3-J1` to `M3-J6`, and no other `M3-` id: the plan's mutation (a row
/// for `M3-99`) fails. Each id is given a row of its own, added to the
/// table, so the test holds however the real rows change.
///
/// Mutation checked: TASKS taking any `M3-` id (`M3-%02d` for 1 to 99):
/// `M3-22` and `M3-99` pass, and this test fails.
#[test]
fn every_m3_task_and_join_is_known_and_no_other_m3_id() {
    let ids: Vec<String> = (1..=21)
        .map(|n| format!("M3-{n:02}"))
        .chain((1..=6).map(|n| format!("M3-J{n}")))
        .collect();
    let t = fixture();
    for (i, id) in ids.iter().enumerate() {
        add_m3_row(
            &t,
            IPC,
            "exit_token",
            &format!("| `zz_probe_{i}` | {id} | reserved | a probe row |"),
        );
    }
    assert_passes(&t.home());

    let t = fixture();
    let bad = ["M3-00", "M3-22", "M3-99", "M3-J0", "M3-J7", "M3-1"];
    for (i, id) in bad.iter().enumerate() {
        add_m3_row(
            &t,
            IPC,
            "exit_token",
            &format!("| `zz_bad_{i}` | {id} | reserved | a probe row |"),
        );
    }
    let out = run(&t.home());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    for id in bad {
        let why = format!("names '{id}', which is not an M2, M2b or M3 task");
        assert!(stderr.contains(&why), "expected {why:?} in: {stderr}");
    }
}

/// A row of an M3 task belongs under "Reserved for M3" and a row of an M2
/// or M2b task under "Reserved for M2 and M2b"; a bare later milestone
/// must come after the section's own.
///
/// Mutation checked: check_rows without the section rule: each case
/// passes, and this test fails.
#[test]
fn a_row_under_the_other_milestones_heading_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `items.reclassify` | M2-13 |",
        "| `items.reclassify` | M3-14 |",
    );
    assert_fails(
        &t,
        "`items.reclassify` is M3-14's, so its row belongs under \"Reserved for M3\", not \"Reserved for M2 and M2b\"",
    );
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `projects.list` | M3-04 |",
        "| `projects.list` | M2-11 |",
    );
    assert_fails(
        &t,
        "`projects.list` is M2-11's, so its row belongs under \"Reserved for M2 and M2b\", not \"Reserved for M3\"",
    );
    let t = fixture();
    edit(
        &t,
        VAULT,
        "| 3 | `secure_enclave` | M3-08 |",
        "| 3 | `secure_enclave` | M3 |",
    );
    assert_fails(
        &t,
        "`secure_enclave` names M3, which is not a milestone after the one \"Reserved for M3\" reserves for",
    );
}

/// Each heading holds a registry's table once, and a table outside the two
/// headings is refused.
///
/// Mutation checked: read_tables keyed by the table alone (a second table
/// under one heading merged in): the first case passes, and this test
/// fails.
#[test]
fn a_table_twice_under_one_heading_or_under_another_heading_fails() {
    let block = "\n<!-- reservations:reason -->\n| Token | Task | Status | Use |\n|---|---|---|---|\n| `spare_reason` | spare | reserved | kept free |\n<!-- /reservations -->\n";
    let t = fixture();
    let path = t.home().join(IPC);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}{block}")).unwrap();
    assert_fails(
        &t,
        "the `reason` table appears twice under \"Reserved for M3\"",
    );
    let t = fixture();
    let path = t.home().join(IPC);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}\n## Reserved for M4\n{block}")).unwrap();
    assert_fails(
        &t,
        "the `reason` table is under \"Reserved for M4\", not one of the headings",
    );
}

/// App-role methods have their own table: an `app.` name in the client
/// table, and a client name in the app table, are malformed.
///
/// Mutation checked: the client table's grammar taking any method name
/// (METHOD, as before M3-01): the first case passes, and this test fails.
#[test]
fn an_app_method_in_the_client_table_or_the_reverse_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `reveal.request` | M3-14 |",
        "| `app.reveal.request` | M3-14 |",
    );
    assert_fails(
        &t,
        "`method`: `app.reveal.request` is not a well-formed name for this table",
    );
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `app.asks.decline` | M3-14 |",
        "| `asks.decline` | M3-14 |",
    );
    assert_fails(
        &t,
        "`app_method`: `asks.decline` is not a well-formed name for this table",
    );
}

/// The app-role methods are read from the code: an `impl Method` named
/// like a `reserved` row fails, and passes once the row is `landed`; an
/// app method no row reserves fails, and so does a `landed` row the code
/// lacks. The client table does not count an app method. The probe row is
/// added for the test, so it holds whatever the real rows' statuses.
///
/// Mutation checked: no reader for `app_method` (`code=None`): a reserved
/// row the code has passes, and this test fails. And code_methods keeping
/// `app.` names: the landed probe fails the client table, and this test
/// fails.
#[test]
fn app_methods_are_read_from_the_code() {
    let row = |status: &str| format!("| `app.zz_probe` | M3-16 | {status} | a probe row |");
    let t = fixture();
    add_m3_row(&t, IPC, "app_method", &row("reserved"));
    add_method(&t, "app.zz_probe");
    assert_fails(
        &t,
        "`app_method`: `app.zz_probe` is reserved, but the code already has it",
    );
    let t = fixture();
    add_m3_row(&t, IPC, "app_method", &row("landed"));
    add_method(&t, "app.zz_probe");
    assert_passes(&t.home());
    let t = fixture();
    add_method(&t, "app.zz_unreserved");
    assert_fails(
        &t,
        &format!(
            "`app_method`: the code has `app.zz_unreserved` ({PROTO}), which no `landed` row reserves"
        ),
    );
    let t = fixture();
    add_m3_row(&t, IPC, "app_method", &row("landed"));
    assert_fails(
        &t,
        "`app.zz_probe` is `landed`, but the code has no such entry",
    );
}

/// Adds `variant = number` to the copy's `UnlockerKind` and the arm
/// `arm => Some(UnlockerKind::<variant>)` to `UnlockerKind::from_byte`, at
/// the top of each, so the edit holds whatever kinds the enum has by then.
fn add_unlocker_kind(t: &TestHome, variant: &str, number: u32, arm: u32) {
    edit(
        t,
        ENVELOPE,
        "pub enum UnlockerKind {\n",
        &format!("pub enum UnlockerKind {{\n    {variant} = {number},\n"),
    );
    add_unlocker_arm(t, &format!("{arm} => Some(UnlockerKind::{variant})"));
}

/// Adds `arm` as the first arm of the copy's `UnlockerKind::from_byte`.
fn add_unlocker_arm(t: &TestHome, arm: &str) {
    edit(
        t,
        ENVELOPE,
        "        match b {\n",
        &format!("        match b {{\n            {arm},\n"),
    );
}

/// The unlocker kinds are read from `UnlockerKind`: M1's two from the
/// baseline, a kind reserved until the code has it, and a kind no row
/// reserves refused. The probe kind (9) is added for the test, so it holds
/// once M3-08 lands `secure_enclave`.
///
/// Mutation checked: no reader for `unlocker_kind` (`code=None`): the
/// tree itself fails (its baseline lines name a registry without a
/// reader), a reserved kind the code has is not refused as such, and this
/// test fails.
#[test]
fn unlocker_kinds_are_read_from_the_code() {
    let row = |status: &str| format!("| 9 | `zz_probe` | M3-08 | {status} | a probe row |");
    let t = fixture();
    add_m3_row(&t, VAULT, "unlocker_kind", &row("reserved"));
    add_unlocker_kind(&t, "ZzProbe", 9, 9);
    assert_fails(
        &t,
        "`unlocker_kind`: `zz_probe` is reserved, but the code already has it",
    );
    let t = fixture();
    add_m3_row(&t, VAULT, "unlocker_kind", &row("landed"));
    add_unlocker_kind(&t, "ZzProbe", 9, 9);
    assert_passes(&t.home());
    let t = fixture();
    add_unlocker_kind(&t, "ZzProbe", 9, 9);
    assert_fails(
        &t,
        "the code has `zz_probe` = 9 in the reserved range with no `landed` row",
    );
    let t = fixture();
    edit(&t, BASELINE, "unlocker_kind recovery_kit 2\n", "");
    assert_fails(
        &t,
        "`unlocker_kind`: the code has `recovery_kit` = 2, which no `landed` row reserves",
    );
}

/// `UnlockerKind::from_byte`, which reads a stored kind back, is read too
/// and must name, for each number, the kind that number declares: a second
/// number for one kind (the review's probe, `3 => Passphrase`), a kind
/// read under a number other than its own, a number read twice and an arm
/// the reader cannot read each fail, and the probe kind read under its own
/// number passes.
///
/// Mutation checked: code_unlocker_kinds without the decoder (the
/// declaration alone, as in round one): the probe's `3 => Passphrase`
/// passes, and this test fails.
#[test]
fn the_unlocker_kind_decoder_is_the_declarations_inverse() {
    let t = fixture();
    add_unlocker_arm(&t, "3 => Some(UnlockerKind::Passphrase)");
    assert_fails(
        &t,
        "`UnlockerKind::from_byte` reads 3 as `UnlockerKind::Passphrase`, whose number is 1: one entry with two numbers",
    );
    let t = fixture();
    add_m3_row(
        &t,
        VAULT,
        "unlocker_kind",
        "| 9 | `zz_probe` | M3-08 | landed | a probe row |",
    );
    add_unlocker_kind(&t, "ZzProbe", 9, 8);
    assert_fails(
        &t,
        "`UnlockerKind::from_byte` reads 8 as `UnlockerKind::ZzProbe`, whose number is 9",
    );
    let t = fixture();
    add_unlocker_arm(&t, "1 => Some(UnlockerKind::Passphrase)");
    assert_fails(&t, "`UnlockerKind::from_byte` reads 1 twice");
    let t = fixture();
    add_unlocker_arm(&t, "n if n == 3 => Some(UnlockerKind::Passphrase)");
    assert_fails(
        &t,
        "`UnlockerKind::from_byte` has an arm the reader cannot read",
    );
    let t = fixture();
    add_unlocker_arm(&t, "0x3 => Some(Self::Passphrase)");
    assert_fails(
        &t,
        "reads 3 as `UnlockerKind::Passphrase`, whose number is 1",
    );
}

/// The same class in the registries the script read before M3: the item
/// class decoder (`item_class_from`, vault/state.rs) and the policy record
/// decoder (`PolicyRecord::decode` through `PolicyRecord::kind`) are read,
/// so a second number for one class or kind fails, as does a record that
/// `kind` maps to another kind's number, and an arm the reader cannot read.
///
/// Mutation checked: code_item_classes and code_policy_kinds reading the
/// declarations alone (`tags("ItemClass")` and `numbered_variants`): each
/// case passes, and this test fails.
#[test]
fn the_item_class_and_policy_kind_decoders_are_read() {
    let t = fixture();
    edit(
        &t,
        STATE,
        "    match v {\n",
        "    match v {\n        5 => Some(ItemClass::Secret),\n",
    );
    assert_fails(
        &t,
        "`fn item_class_from` reads 5 as `ItemClass::Secret`, whose number is 1",
    );
    let t = fixture();
    edit(
        &t,
        POLICIES,
        "        let record = match (kind, version) {\n",
        "        let record = match (kind, version) {\n            (4, 1) => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?),\n",
    );
    assert_fails(
        &t,
        "`PolicyRecord::decode` reads 4 as `PolicyKind::StandingApproval`, whose number is 1",
    );
    let t = fixture();
    edit(
        &t,
        POLICIES,
        "PolicyRecord::SignInTarget(_) => PolicyKind::SigninTarget",
        "PolicyRecord::SignInTarget(_) => PolicyKind::StandingApproval",
    );
    assert_fails(
        &t,
        "`PolicyRecord::decode` reads 2 as `PolicyKind::StandingApproval`, whose number is 1",
    );
    let t = fixture();
    edit(
        &t,
        POLICIES,
        "        let record = match (kind, version) {\n",
        "        let record = match (kind, version) {\n            (k, 1) if k == 4 => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?),\n",
    );
    assert_fails(
        &t,
        "`PolicyRecord::decode` has an arm the reader cannot read",
    );
}

/// A field nested with dots (`vault.keychain_anchor` in `status`) is read,
/// and a malformed one is refused.
///
/// Mutation checked: FIELD taking any text: the empty component passes,
/// and this test fails.
#[test]
fn a_dotted_field_is_read_and_a_malformed_one_fails() {
    assert_passes(&fixture().home());
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `status` | `vault.keychain_anchor` |",
        "| `status` | `vault..keychain_anchor` |",
    );
    assert_fails(
        &t,
        "`vault..keychain_anchor` is not a well-formed name for this table",
    );
}

/// The M3 plan's code-owned paths (task M3-01): the macOS app, its build
/// and signing scripts, and the pinned requirements, beside the two
/// checks whose tables the M3 tasks take their rows from, and the SPEC,
/// whose edits the SPEC check leaves to a code owner's review for the
/// paraphrases it misses (round three's verifier: no line named it).
///
/// Mutations checked: the `/apps/macos/` line removed from
/// .github/CODEOWNERS; separately the `/docs/SPEC.md` line removed: this
/// test fails for each.
#[test]
fn codeowners_name_an_owner_for_the_m3_paths() {
    let text = std::fs::read_to_string(repo_root().join(".github/CODEOWNERS")).unwrap();
    let owned: Vec<(&str, usize)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut words = l.split_whitespace();
            let pattern = words.next().unwrap();
            (pattern, words.filter(|w| w.starts_with('@')).count())
        })
        .collect();
    for want in [
        "/apps/macos/",
        "/scripts/macos/",
        "/crates/envcloak-sys/src/peer_code.rs",
        "/crates/envcloak-sys/src/peer_code/",
        "/scripts/check-reservations.py",
        "/scripts/check-reservations-baseline.txt",
        "/scripts/check-spec-decisions.py",
        "/docs/SPEC.md",
    ] {
        assert!(
            owned.iter().any(|(p, owners)| *p == want && *owners > 0),
            "CODEOWNERS names no owner for {want}"
        );
    }
}

/// Every variant a decoder's enum declares is read back by it (Codex's
/// finding: `UnlockerKind::from_byte` without the Recovery Kit's arm
/// passed, though the vault could then not read that unlocker back): the
/// unlocker kind, item class and policy kind decoders each fail with an
/// arm taken out, and a kind declared with no arm fails too.
///
/// Mutation checked: check_inverse without its last rule (the variants
/// it reads no number as): each case passes, and this test fails.
#[test]
fn every_declared_entry_is_read_back_by_its_decoder() {
    let t = fixture();
    edit(
        &t,
        ENVELOPE,
        "            2 => Some(UnlockerKind::RecoveryKit),\n",
        "",
    );
    assert_fails(
        &t,
        "`UnlockerKind::from_byte` reads no number as `UnlockerKind::RecoveryKit` (2)",
    );
    let t = fixture();
    edit(&t, STATE, "        1 => Some(ItemClass::Secret),\n", "");
    assert_fails(
        &t,
        "`fn item_class_from` reads no number as `ItemClass::Secret` (1)",
    );
    let t = fixture();
    edit(
        &t,
        POLICIES,
        "            (3, 1) => PolicyRecord::ManagedServer(ManagedServer::decode(&mut d)?),\n",
        "",
    );
    assert_fails(
        &t,
        "`PolicyRecord::decode` reads no number as `PolicyKind::ManagedServer` (3)",
    );
    let t = fixture();
    add_m3_row(
        &t,
        VAULT,
        "unlocker_kind",
        "| 9 | `zz_probe` | M3-08 | landed | a probe row |",
    );
    edit(
        &t,
        ENVELOPE,
        "pub enum UnlockerKind {\n",
        "pub enum UnlockerKind {\n    ZzProbe = 9,\n",
    );
    assert_fails(
        &t,
        "`UnlockerKind::from_byte` reads no number as `UnlockerKind::ZzProbe` (9)",
    );
}

/// The one entry the script names as never stored, `ItemClass::None` (the
/// class of a row that is not an item), must not be read back either, and
/// a name there that the enum no longer declares fails, so the exception
/// cannot outlive its entry.
///
/// Mutation checked: check_inverse without the rule for an arm that reads
/// a never-stored entry: the first case passes, and this test fails.
#[test]
fn an_entry_never_stored_is_not_read_back() {
    let t = fixture();
    edit(
        &t,
        STATE,
        "    match v {\n",
        "    match v {\n        0 => Some(ItemClass::None),\n",
    );
    assert_fails(
        &t,
        "`fn item_class_from` reads 0 as `ItemClass::None`, which is never stored",
    );
    let t = fixture();
    edit(&t, AAD, "    None = 0,\n", "    Nothing = 0,\n");
    assert_fails(
        &t,
        "the script's NOT_DECODED names `ItemClass::None`, which `ItemClass` does not declare",
    );
}

/// `AuditKind::ALL` and `ErrorKind::ALL`, which `AuditKind::from_u8` and
/// `ErrorKind::from_token` search, name every variant once: a variant left
/// out (written, then refused when read back), one named twice and an
/// entry the reader cannot read each fail.
///
/// Mutation checked: the `check_all_list` calls taken out of
/// code_audit_kinds and code_error_kinds: each case passes, and this test
/// fails.
#[test]
fn the_all_lists_name_every_variant_once() {
    let t = fixture();
    edit(&t, RECORD, "        AuditKind::Recover,\n", "");
    assert_fails(
        &t,
        "`AuditKind::ALL` leaves out `AuditKind::Recover`, which the code would then not read back",
    );
    let t = fixture();
    edit(
        &t,
        RECORD,
        "        AuditKind::Recover,\n",
        "        AuditKind::Recover,\n        AuditKind::Run,\n",
    );
    assert_fails(&t, "`AuditKind::ALL` entry `Run` appears twice");
    let t = fixture();
    edit(
        &t,
        RECORD,
        "        AuditKind::Recover,\n",
        "        AuditKind::Recover,\n        AuditKind::ALL[0],\n",
    );
    assert_fails(&t, "`AuditKind::ALL` holds an entry the reader cannot read");
    let t = fixture();
    edit(&t, PROTO, "        ErrorKind::LoginReference,\n", "");
    assert_fails(
        &t,
        "`ErrorKind::ALL` leaves out `ErrorKind::LoginReference`, which the code would then not read back",
    );
}

const ITEMS: &str = "crates/envcloak-core/src/vault/items.rs";
const SCHEMA: &str = "crates/envcloak-core/src/vault/schema.rs";

/// A decoder's arm that no input reaches fails (Codex's review of round
/// three: a guard was read as any text, so `2 if false` passed while the
/// vault could no longer read a Recovery Kit back). The one guard the
/// script takes is a schema condition it checks: `schema >= <constant>`
/// with the decoder's own `schema: u16` and a constant between 1 and
/// CURRENT_SCHEMA. A guard of another form, a constant above the schema
/// the code writes, a guard parameter the decoder lacks, and an arm a
/// `#[cfg]` takes out each fail; the tree's `4 if schema >=
/// RECORDS_V2_FROM` passes.
///
/// Mutations checked: some_arms taking any guard, as in round three (the
/// first three cases pass); schema_guards without its range rule (the
/// two constant cases pass); each fails this test.
#[test]
fn a_decoder_arm_no_input_reaches_fails() {
    assert_passes(&fixture().home());
    for (rel, from, to, expect) in [
        (
            ENVELOPE,
            "            2 => Some(UnlockerKind::RecoveryKit),\n",
            "            2 if false => Some(UnlockerKind::RecoveryKit),\n",
            "`UnlockerKind::from_byte` guards an arm with `if false`, which the reader does not take",
        ),
        (
            STATE,
            "        4 if schema >= RECORDS_V2_FROM => Some(ItemClass::Login),\n",
            "        4 if schema >= 99 => Some(ItemClass::Login),\n",
            "`fn item_class_from` guards an arm with `if schema >= 99`, which the reader does not take",
        ),
        (
            STATE,
            "        4 if schema >= RECORDS_V2_FROM => Some(ItemClass::Login),\n",
            "        4 if schema >= RECORDS_V2_FROM && v < 0 => Some(ItemClass::Login),\n",
            "`fn item_class_from` guards an arm with `if schema >= RECORDS_V2_FROM && v < 0`",
        ),
        (
            ITEMS,
            "pub(crate) const RECORDS_V2_FROM: u16 = 2;",
            "pub(crate) const RECORDS_V2_FROM: u16 = 3;",
            "`RECORDS_V2_FROM` is 3, which is not between 1 and CURRENT_SCHEMA (2)",
        ),
        (
            SCHEMA,
            "pub const CURRENT_SCHEMA: u16 = 2;",
            "pub const CURRENT_SCHEMA: u16 = 1;",
            "`RECORDS_V2_FROM` is 2, which is not between 1 and CURRENT_SCHEMA (1)",
        ),
        (
            STATE,
            "fn item_class_from(v: i64, schema: u16)",
            "fn item_class_from(v: i64, schema: u32)",
            "`fn item_class_from` has no parameter `schema: u16`",
        ),
        (
            ENVELOPE,
            "            2 => Some(UnlockerKind::RecoveryKit),\n",
            "            #[cfg(any())]\n            2 => Some(UnlockerKind::RecoveryKit),\n",
            "`UnlockerKind::from_byte` has an arm the reader cannot read (`#[cfg(any())] 2",
        ),
    ] {
        let t = fixture();
        edit(&t, rel, from, to);
        assert_fails(&t, expect);
    }
}

/// A decoder that changes its input before its `match`, or its value
/// after it, fails (Codex's review of round three: the reader ignored the
/// matched expression, so a decoder that transformed its input passed
/// while it read every entry under another number). Each decoder the
/// script reads is held to `match <input> { .. }` alone: a changed
/// scrutinee, a statement before the `match` and code after it fail, for
/// the unlocker kind, item class and policy decoders and for
/// `PolicyRecord::kind`.
///
/// Mutation checked: match_arms without its scrutinee rule and its rule
/// for what stands around the `match` (round three's reader): every case
/// passes, and this test fails.
#[test]
fn a_decoder_that_changes_its_input_or_its_value_fails() {
    for (rel, from, to, expect) in [
        (
            ENVELOPE,
            "        match b {\n",
            "        match b.wrapping_sub(1) {\n",
            "`UnlockerKind::from_byte` matches on `b.wrapping_sub(1)`, not on `b`",
        ),
        (
            ENVELOPE,
            "        match b {\n",
            "        let b = b ^ 3;\n        match b {\n",
            "`UnlockerKind::from_byte` is not `match b { .. }` alone (it has `let b = b ^ 3;` before",
        ),
        (
            STATE,
            "    match v {\n",
            "    match v - 1 {\n",
            "`fn item_class_from` matches on `v - 1`, not on `v`",
        ),
        (
            STATE,
            "    match v {\n",
            "    let found = match v {\n",
            "`fn item_class_from` is not `match v { .. }` alone (it has `let found =` before",
        ),
        (
            POLICIES,
            "        let record = match (kind, version) {\n",
            "        let record = match (version, kind) {\n",
            "`PolicyRecord::decode` matches on `(version, kind)`, not on `(kind, version)`",
        ),
        (
            POLICIES,
            "        let record = match (kind, version) {\n",
            "        let record = match (kind ^ 1, version) {\n",
            "`PolicyRecord::decode` matches on `(kind ^ 1, version)`, not on `(kind, version)`",
        ),
        (
            POLICIES,
            "    pub fn kind(&self) -> PolicyKind {\n        match self {\n",
            "    pub fn kind(&self) -> PolicyKind {\n        match &PolicyRecord::Probe {\n",
            "`PolicyRecord::kind` matches on `&PolicyRecord::Probe`, not on `self`",
        ),
    ] {
        let t = fixture();
        edit(&t, rel, from, to);
        assert_fails(&t, expect);
    }
}

/// `PolicyRecord::decode` reads the kind and then the version as the
/// record's first two bytes, refuses a pair it does not know as corrupt
/// and gives the record its `match` made: the two reads swapped, a
/// fallback arm that makes a record, an arm whose record is changed after
/// it is made, and a different record given back each fail.
///
/// Mutation checked: code_policy_kinds with DECODE_BEFORE and DECODE_AFTER
/// empty, the fallback arm's value and the arm's record read as round
/// three read them: the cases pass, and this test fails.
#[test]
fn the_policy_decoder_reads_its_bytes_in_order_and_refuses_what_it_does_not_know() {
    for (from, to, expect) in [
        (
            "        let kind = d.u8()?;\n        let version = d.u8()?;\n",
            "        let version = d.u8()?;\n        let kind = d.u8()?;\n",
            "`PolicyRecord::decode` is not `let mut d = Dec::new(b); let kind = d.u8()?; let version = d.u8()?; let record = match (kind, version) { .. }",
        ),
        (
            "            _ => return Err(corrupt()),\n        };\n        d.end()?;\n",
            "            _ => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?),\n        };\n        d.end()?;\n",
            "`PolicyRecord::decode` does not end with `_ => return Err(corrupt())`",
        ),
        (
            "            (1, 1) => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?),\n",
            "            (1, 1) => PolicyRecord::StandingApproval(StandingApproval::decode(&mut d)?).probe(),\n",
            "`PolicyRecord::decode` has an arm the reader cannot read (`(1, 1) => PolicyRecord::StandingApproval(",
        ),
        (
            "        Ok(record)\n    }\n}\n",
            "        Ok(PolicyRecord::probe(record))\n    }\n}\n",
            "and `; d.end()?; if !record.in_bounds() { return Err(corrupt()); } Ok(PolicyRecord::probe(record))` after it",
        ),
    ] {
        let t = fixture();
        edit(&t, POLICIES, from, to);
        assert_fails(&t, expect);
    }
}

/// `AuditKind::from_u8` and `ErrorKind::from_token` are read as the
/// searches of `ALL` they are, and `ALL` as the list the code builds: a
/// search that changes its input, adds a condition or takes another
/// parameter fails, and so does an entry of `ALL` behind a `#[cfg]`,
/// which takes it out of the list (rustc compiles it so) though the
/// reader counted it (round three read `ALL` with attributes blanked and
/// the searches not at all).
///
/// Mutations checked: the check_all_search calls taken out (the first
/// four cases pass); check_all_list reading entries with attributes
/// blanked, as in round three (the last case passes); each fails this
/// test.
#[test]
fn the_all_searches_and_lists_are_read_as_the_code_builds_them() {
    for (rel, from, to, expect) in [
        (
            RECORD,
            "AuditKind::ALL.into_iter().find(|k| *k as u8 == v)",
            "AuditKind::ALL.into_iter().find(|k| *k as u8 == v.wrapping_add(1))",
            "`AuditKind::from_u8` is `AuditKind::ALL.into_iter().find(|k| *k as u8 == v.wrapping_add(1))`",
        ),
        (
            RECORD,
            "AuditKind::ALL.into_iter().find(|k| *k as u8 == v)",
            "AuditKind::ALL.into_iter().find(|k| *k as u8 == v && *k != AuditKind::Recover)",
            "`AuditKind::from_u8` is `AuditKind::ALL.into_iter().find(|k| *k as u8 == v && *k != AuditKind::Recover)`",
        ),
        (
            PROTO,
            "ErrorKind::ALL.into_iter().find(|k| k.token() == token)",
            "ErrorKind::ALL.into_iter().find(|k| k.token() == token.trim_start_matches('x'))",
            "`ErrorKind::from_token` is `ErrorKind::ALL.into_iter().find(|k| k.token() == token.trim_start_matches('x'))`",
        ),
        (
            PROTO,
            "pub fn from_token(token: &str) -> Option<ErrorKind> {",
            "pub fn from_token(token: &str, _probe: bool) -> Option<ErrorKind> {",
            "`ErrorKind::from_token` is not `fn from_token(token: &str) -> Option<ErrorKind>`",
        ),
        (
            RECORD,
            "        AuditKind::Recover,\n",
            "        #[cfg(any())]\n        AuditKind::Recover,\n",
            "`AuditKind::ALL` holds an entry the reader cannot read (`#[cfg(any())] AuditKind::Recover`)",
        ),
    ] {
        let t = fixture();
        edit(&t, rel, from, to);
        assert_fails(&t, expect);
    }
}

/// `fn token` and `fn code`, whose values the registries take and
/// `ErrorKind::from_token` searches, are read whole: an arm behind a
/// `#[cfg]` is not counted (the variant has no arm the reader reads), an
/// arm the reader cannot read fails even when every variant has one (a
/// wildcard that would give a value the reader never sees), and so does
/// a `match` on something other than `self`.
///
/// Mutation checked: enum_arms as in round three (a search for arms in
/// the bodies of every `fn token`): every case passes, and this test
/// fails.
#[test]
fn a_token_or_code_arm_the_reader_does_not_read_fails() {
    for (rel, from, to, expect) in [
        (
            RECORD,
            "            AuditKind::Recover => \"recover\",\n",
            "            #[cfg(any())]\n            AuditKind::Recover => \"recover\",\n            _ => \"recover\",\n",
            "`fn token` has no `AuditKind::<variant> => <value>` arm the reader can read for Recover",
        ),
        (
            RECORD,
            "            AuditKind::Recover => \"recover\",\n",
            "            AuditKind::Recover => \"recover\",\n            _ => \"zz_probe\",\n",
            "`fn token` has an arm the reader cannot read (`_ => \"zz_probe\"`)",
        ),
        (
            PROTO,
            "ErrorKind::Internal => -32099,",
            "ErrorKind::Internal => -32099,\n            _ => -32098,",
            "`fn code` has an arm the reader cannot read (`_ => -32098`)",
        ),
        (
            RECORD,
            "    pub const fn token(self) -> &'static str {\n        match self {\n",
            "    pub const fn token(self) -> &'static str {\n        match AuditKind::Run {\n",
            "`AuditKind::token` matches on `AuditKind::Run`, not on `self`",
        ),
    ] {
        let t = fixture();
        edit(&t, rel, from, to);
        assert_fails(&t, expect);
    }
}

const INVERSE_MODEL: &str = "crates/envcloak-testkit/tests/oracles/check_inverse_model.py";

/// `check_inverse` agrees with an independent model of its rule
/// (tests/oracles/check_inverse_model.py): over every list of up to three
/// (number, variant) pairs for five declarations, 21,845 cases, it passes
/// exactly the lists that are the declaration's pairs as a multiset, less
/// the never-stored entries, which must be declared. The model's 11
/// positive controls must pass, and no verdict may differ.
///
/// Mutations checked: check_inverse without its missing-variant rule;
/// separately without its never-stored rule; separately with the
/// number-twice rule taken out: the model reports a disagreement for
/// each, and this test fails.
#[test]
fn check_inverse_agrees_with_an_independent_model() {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    let out = t
        .apply(&mut cmd)
        .arg(repo_root().join(INVERSE_MODEL))
        .arg(repo_root().join(SCRIPT))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the model disagrees: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        stdout.trim(),
        r#"{"cases": 21845, "positive_controls": 11, "rejected": 21834, "mismatches": 0}"#
    );
}
