//! `scripts/check-reservations.py` (plan decision D-23, task M2-01) on the
//! real tree and on copies of the files it reads, each changed one way: it
//! accepts the tree as it is and an entry landed as reserved, and refuses a
//! number or name taken twice, a malformed row, an unknown task or status, a
//! missing table, a code source it cannot read, and each disagreement
//! between a table and the code.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every file the script reads, relative to the root, apart from the CLI's
/// source directory.
const FILES: [&str; 7] = [
    "docs/IPC.md",
    "docs/VAULT.md",
    "crates/envcloak-core/src/audit/record.rs",
    "crates/envcloak-core/src/crypto/aad.rs",
    "crates/envcloak-ipc/src/proto.rs",
    "crates/envcloak-ipc/src/client.rs",
    "crates/envcloak-policy/src/statement.rs",
];
const CLI_SRC: &str = "crates/envcloak-cli/src";

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

/// A copy of the files the script reads, under a fresh test home.
fn fixture() -> TestHome {
    let t = TestHome::new();
    let root = t.home();
    for rel in FILES {
        let dest = root.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(rel), dest).unwrap();
    }
    copy_dir(&repo_root().join(CLI_SRC), &root.join(CLI_SRC));
    t
}

/// Replaces the one occurrence of `from` in `rel` with `to`.
fn edit(t: &TestHome, rel: &str, from: &str, to: &str) {
    let path = t.home().join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {rel}");
    std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
}

fn run(root: &Path) -> Output {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    t.apply(&mut cmd)
        .arg(repo_root().join("scripts/check-reservations.py"))
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

const VAULT: &str = "docs/VAULT.md";
const IPC: &str = "docs/IPC.md";
const RECORD: &str = "crates/envcloak-core/src/audit/record.rs";

/// Adds an `AuditKind` variant and its token to the copy of record.rs.
fn add_audit_kind(t: &TestHome, variant: &str, number: u32, token: &str) {
    edit(
        t,
        RECORD,
        "    Recover = 21,\n}",
        &format!("    Recover = 21,\n    {variant} = {number},\n}}"),
    );
    edit(
        t,
        RECORD,
        "AuditKind::Run => \"run\",",
        &format!("AuditKind::Run => \"run\",\n            AuditKind::{variant} => \"{token}\","),
    );
}

#[test]
fn the_real_tree_passes() {
    assert_passes(&repo_root());
}

#[test]
fn a_copy_of_the_files_it_reads_passes() {
    assert_passes(&fixture().home());
}

#[test]
fn an_audit_kind_number_reserved_twice_fails() {
    let t = fixture();
    edit(&t, VAULT, "| 23 | `scan_match` |", "| 22 | `scan_match` |");
    assert_fails(
        &t,
        "`audit_kind`: number 22 is reserved twice (`reveal` and `scan_match`)",
    );
}

#[test]
fn an_error_code_reserved_twice_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `request_conflict` | -32047 |",
        "| `request_conflict` | -32035 |",
    );
    assert_fails(&t, "`error_kind`: number -32035 is reserved twice");
}

#[test]
fn a_name_reserved_twice_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `items.mark_exposed` | M2-11 |",
        "| `scan.match` | M2-11 |",
    );
    assert_fails(&t, "`method`: `scan.match` is reserved twice");
}

#[test]
fn coverage_states_reasons_and_outcomes_share_one_namespace() {
    let t = fixture();
    edit(&t, IPC, "| `skipped` | outcome |", "| `active` | outcome |");
    assert_fails(&t, "`coverage`: `active` is reserved twice");
}

#[test]
fn a_control_message_twice_on_one_channel_fails() {
    // `Stopped` is on two channels in the real table; on one it is a clash.
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `pty_monitor` | `Continued` |",
        "| `pty_monitor` | `Stopped` |",
    );
    assert_fails(&t, "`pty_monitor Stopped` is reserved twice");
}

#[test]
fn a_number_outside_the_reserved_range_fails() {
    let t = fixture();
    edit(&t, VAULT, "| 22 | `reveal` |", "| 21 | `reveal` |");
    assert_fails(
        &t,
        "`reveal` takes 21, outside the reserved range 22 to 255",
    );
}

#[test]
fn a_reserved_entry_the_code_already_has_fails() {
    let t = fixture();
    add_audit_kind(&t, "Reveal", 22, "reveal");
    assert_fails(&t, "`reveal` is reserved, but the code already has it");
}

#[test]
fn a_reserved_number_the_code_gives_another_entry_fails() {
    let t = fixture();
    add_audit_kind(&t, "Probe", 22, "probe");
    assert_fails(&t, "`reveal` reserves 22, which the code gives to `probe`");
}

#[test]
fn a_code_entry_in_the_reserved_range_without_a_landed_row_fails() {
    let t = fixture();
    add_audit_kind(&t, "Probe", 46, "probe");
    assert_fails(
        &t,
        "the code has `probe` = 46 in the reserved range with no `landed` row",
    );
}

#[test]
fn an_entry_landed_as_reserved_passes() {
    let t = fixture();
    add_audit_kind(&t, "Reveal", 22, "reveal");
    edit(
        &t,
        VAULT,
        "| 22 | `reveal` | M2-21 | reserved |",
        "| 22 | `reveal` | M2-21 | landed |",
    );
    assert_passes(&t.home());
}

#[test]
fn a_landed_row_the_code_lacks_fails() {
    let t = fixture();
    edit(
        &t,
        VAULT,
        "| 22 | `reveal` | M2-21 | reserved |",
        "| 22 | `reveal` | M2-21 | landed |",
    );
    assert_fails(&t, "`reveal` is `landed`, but the code has no such entry");
}

#[test]
fn a_landed_row_with_another_number_than_the_code_fails() {
    let t = fixture();
    add_audit_kind(&t, "Reveal", 47, "reveal");
    edit(
        &t,
        VAULT,
        "| 22 | `reveal` | M2-21 | reserved |",
        "| 22 | `reveal` | M2-21 | landed |",
    );
    assert_fails(&t, "`reveal` is 22 here and 47 in the code");
}

#[test]
fn a_reuse_row_the_code_lacks_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `value_on_argv` | M2-18 | reuse |",
        "| `value_in_argv` | M2-18 | reuse |",
    );
    assert_fails(
        &t,
        "`value_in_argv` is `reuse`, but the code has no such entry",
    );
}

#[test]
fn a_reserved_reason_the_code_already_has_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `limited` | M2-11 | reserved |",
        "| `requester_terminal` | M2-11 | reserved |",
    );
    assert_fails(
        &t,
        "`requester_terminal` is reserved, but the code already has it",
    );
}

#[test]
fn an_unknown_task_or_status_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `pending.state` | M2-03 |",
        "| `pending.state` | M2-29 |",
    );
    assert_fails(&t, "names 'M2-29', which is not an M2 or M2b task");
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `pending.state` | M2-03 | reserved |",
        "| `pending.state` | M2-03 | taken |",
    );
    assert_fails(&t, "`pending.state` has status 'taken'");
}

#[test]
fn a_malformed_name_or_row_fails() {
    let t = fixture();
    edit(&t, IPC, "| `live_not_ticked` |", "| `Live_not_ticked` |");
    assert_fails(
        &t,
        "`Live_not_ticked` is not a well-formed name for this table",
    );
    let t = fixture();
    edit(&t, IPC, "| `live_not_ticked` |", "| live_not_ticked |");
    assert_fails(&t, "'live_not_ticked' is not one backticked name");
    let t = fixture();
    edit(
        &t,
        VAULT,
        "| 4 | `login` | M2-07 | reserved |",
        "| four | `login` | M2-07 | reserved |",
    );
    assert_fails(&t, "`login` has number 'four', not an integer");
}

#[test]
fn a_missing_table_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "<!-- reservations:mcp_tool -->",
        "<!-- tools, no longer reserved -->",
    );
    assert_fails(&t, "the `mcp_tool` reservations table is missing");
}

#[test]
fn a_code_source_it_cannot_read_fails() {
    let t = fixture();
    edit(&t, RECORD, "pub enum AuditKind {", "pub enum AuditKinds {");
    assert_fails(&t, "has no `pub enum AuditKind`");
}
