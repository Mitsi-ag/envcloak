//! `scripts/check-reservations.py` (plan decision D-23, task M2-01) on the
//! real tree and on copies of the files it reads, each changed one way: it
//! accepts the tree as it is and an entry landed as reserved, and refuses a
//! number or name taken twice (in one table, across the tables printed as
//! `envcloak: <token>`, and in the code itself), a malformed row, an
//! unknown task or status, a missing table, a code source it cannot read,
//! each disagreement between a table and the code, wherever in the
//! workspace's sources the code holds the entry, a code entry that neither
//! a `landed` row nor the baseline of M1's entries accounts for, and a
//! baseline that is missing, malformed or no longer what the code holds.
//! Its readers take every form Rust gives a declaration (hexadecimal and
//! other integer literals, `Self::` arms, raw strings, escapes, `&str`
//! with or without `'static`, a method in any file of the protocol crate)
//! and refuse any they cannot read (an implicit or computed discriminant,
//! a tuple variant, a variant without an arm, a `const NAME` or a reason
//! that is not one string literal), never skipping one.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SCRIPT: &str = "scripts/check-reservations.py";

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

/// A copy of what the script reads (the two documents, the baseline and
/// every crate's `src/`), under a fresh test home.
fn fixture() -> TestHome {
    let t = TestHome::new();
    let root = t.home();
    for rel in ["docs/IPC.md", "docs/VAULT.md", BASELINE] {
        let dest = root.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(rel), dest).unwrap();
    }
    for entry in std::fs::read_dir(repo_root().join("crates")).unwrap() {
        let entry = entry.unwrap();
        let src = entry.path().join("src");
        if src.is_dir() {
            copy_dir(
                &src,
                &root.join("crates").join(entry.file_name()).join("src"),
            );
        }
    }
    t
}

/// Writes `text` as a new Rust file at `rel` in the copy.
fn add_file(t: &TestHome, rel: &str, text: &str) {
    let path = t.home().join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    assert!(!path.exists(), "{rel} exists");
    std::fs::write(path, text).unwrap();
}

/// Replaces the one occurrence of `from` in `rel` with `to`.
fn edit(t: &TestHome, rel: &str, from: &str, to: &str) {
    let path = t.home().join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {rel}");
    std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
}

fn run_script(script: &Path, root: &Path) -> Output {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    t.apply(&mut cmd)
        .arg(script)
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

fn run(root: &Path) -> Output {
    run_script(&repo_root().join(SCRIPT), root)
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
const BASELINE: &str = "scripts/check-reservations-baseline.txt";
const RECORD: &str = "crates/envcloak-core/src/audit/record.rs";

/// Adds an `AuditKind` variant and its token to the copy of record.rs.
fn add_audit_kind(t: &TestHome, variant: &str, number: u32, token: &str) {
    edit(
        t,
        RECORD,
        "    Recover = 21,\n",
        &format!("    Recover = 21,\n    {variant} = {number},\n"),
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
        "| `signin.status` | M2b-05 |",
        "| `signin.status` | M2-29 |",
    );
    assert_fails(&t, "names 'M2-29', which is not an M2 or M2b task");
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `signin.status` | M2b-05 | reserved |",
        "| `signin.status` | M2b-05 | taken |",
    );
    assert_fails(&t, "`signin.status` has status 'taken'");
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

const PROTO: &str = "crates/envcloak-ipc/src/proto.rs";

/// Points the `incomplete` row of the failure-token table at `token`.
fn reserve_exit_token(t: &TestHome, token: &str) {
    edit(
        t,
        IPC,
        "| `incomplete` | M2-14 | reserved |",
        &format!("| `{token}` | M2-14 | reserved |"),
    );
}

#[test]
fn a_failure_token_returned_by_another_crates_token_method_counts() {
    // envcloak-exec's `ExecError::token`, which `run` prints through
    // `Failure::new(e.token(), ...)`.
    let t = fixture();
    reserve_exit_token(&t, "command_not_executable");
    assert_fails(
        &t,
        "`command_not_executable` is reserved, but the code already has it (crates/envcloak-exec/src/lib.rs)",
    );
}

#[test]
fn a_failure_token_through_a_helper_function_counts() {
    // `envcloak daemon` reports through `failure(token, message)`.
    let t = fixture();
    reserve_exit_token(&t, "service_manager");
    assert_fails(
        &t,
        "`service_manager` is reserved, but the code already has it (crates/envcloak-cli/src/cmd/daemon.rs)",
    );
}

/// A new file in a crate other than the CLI's (`envcloak-client`, which
/// holds the CLI's reusable modules since M2-02).
const CLIENT_STUB: &str = "crates/envcloak-client/src/stub.rs";

#[test]
fn a_failure_token_written_as_a_constant_in_another_crate_counts() {
    // `incomplete` is still `reserved` (M2-14), so a constant that holds it
    // in another crate is a clash until its task marks the row `landed`.
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "/// The token of a job that did not finish.\n\
         pub const INCOMPLETE: &str = \"incomplete\";\n\
         \n\
         pub fn stopped() -> Failure {\n    \
             Failure::new(\n        \
                 crate::stub::INCOMPLETE,\n        \
                 \"the job did not finish\",\n    \
             )\n\
         }\n",
    );
    assert_fails(
        &t,
        &format!("`incomplete` is reserved, but the code already has it ({CLIENT_STUB})"),
    );
    // The task that lands it marks the row `landed`, and then it passes.
    edit(
        &t,
        IPC,
        "| `incomplete` | M2-14 | reserved |",
        "| `incomplete` | M2-14 | landed |",
    );
    assert_passes(&t.home());
}

#[test]
fn the_failure_token_m2_02_landed_is_marked_landed() {
    // M2-02 prints `not_in_this_build` through a constant in the CLI's
    // `cmd` module; a `reserved` row for it is a clash.
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `not_in_this_build` | M2-02 | landed |",
        "| `not_in_this_build` | M2-02 | reserved |",
    );
    assert_fails(
        &t,
        "`not_in_this_build` is reserved, but the code already has it (crates/envcloak-cli/src/cmd/mod.rs)",
    );
}

#[test]
fn a_failure_token_in_a_field_or_a_token_method_counts() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "const APP: &'static str = \"app_required\";\n\
         pub fn a() -> Failure { Failure { token: \"pty_unavailable\", message: \"\".into() } }\n\
         impl E { pub fn token(&self) -> &'static str { match self { E::A => APP, E::B => \"pty_monitor_lost\" } } }\n",
    );
    for token in ["pty_unavailable", "pty_monitor_lost", "app_required"] {
        assert_fails(
            &t,
            &format!("`{token}` is reserved, but the code already has it ({CLIENT_STUB})"),
        );
    }
}

#[test]
fn a_token_printed_directly_as_envcloak_token_counts() {
    // `envcloak run` prints its coverage gaps with `eprintln!("envcloak:
    // coverage: ...")`, and `envcloak unlock` a warning the same way.
    let t = fixture();
    reserve_exit_token(&t, "coverage");
    assert_fails(
        &t,
        "`coverage` is reserved, but the code already has it (crates/envcloak-cli/src/cmd/run.rs)",
    );
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `limited` | M2-11 | reserved |",
        "| `warning` | M2-11 | reserved |",
    );
    assert_fails(
        &t,
        "`reason`: `warning` is reserved here, but the code already uses it in `exit_token` (crates/envcloak-cli/src/cmd/unlock.rs)",
    );
    // A new line in another crate, through `format!`.
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn stopped() -> String {\n    \
             format!(\"envcloak: incomplete: {} files not read\", 3)\n\
         }\n",
    );
    assert_fails(
        &t,
        &format!("`incomplete` is reserved, but the code already has it ({CLIENT_STUB})"),
    );
}

#[test]
fn text_that_only_mentions_envcloak_is_not_a_printed_token() {
    // Not a `envcloak: <token>:` prefix: two words, no colon after the
    // word, or the prefix inside the text. (A placeholder where the token
    // goes is read: `a_token_printed_from_a_placeholder_is_read_or_refused`.)
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn a() { eprintln!(\"envcloak: pty unavailable: no terminal\"); }\n\
         pub fn b() { eprintln!(\"envcloak: app_required because\"); }\n\
         pub fn c() -> String { format!(\"[envcloak: incomplete: cut]\") }\n",
    );
    assert_passes(&t.home());
}

#[test]
fn a_token_in_a_comment_a_string_or_a_test_module_does_not_count() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "// Failure::new(\"app_required\", \"\")\n\
         /* token: \"pty_unavailable\" */\n\
         const TEXT: &str = \"Failure::new(\\\"pty_monitor_lost\\\", x)\";\n\
         #[cfg(test)]\n\
         mod tests {\n    \
             fn t() { let _ = Failure::new(\"not_in_this_build\", \"\"); }\n\
         }\n",
    );
    assert_passes(&t.home());
}

#[test]
fn a_name_reserved_in_two_printed_tables_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `limited` | M2-11 | reserved |",
        "| `incomplete` | M2-11 | reserved |",
    );
    assert_fails(
        &t,
        "`incomplete` is reserved in both `reason` and `exit_token`",
    );
}

#[test]
fn a_reserved_name_the_code_uses_in_another_printed_table_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `waiting_for_approval` | M2b-10 | reserved |",
        "| `vault_locked` | M2b-10 | reserved |",
    );
    assert_fails(
        &t,
        "`signin_token`: `vault_locked` is reserved here, but the code already uses it in `error_kind` (code -32002)",
    );
}

#[test]
fn a_name_the_shared_list_names_with_both_tables_passes() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `limited` | M2-11 | reserved |",
        "| `incomplete` | M2-11 | reserved |",
    );
    let script = t.home().join("check.py");
    let text = std::fs::read_to_string(repo_root().join(SCRIPT)).unwrap();
    assert_eq!(text.matches("\nSHARED = {}\n").count(), 1);
    std::fs::write(
        &script,
        text.replacen(
            "\nSHARED = {}\n",
            "\nSHARED = {\"incomplete\": (\"reason\", \"exit_token\")}\n",
            1,
        ),
    )
    .unwrap();
    let out = run_script(&script, &t.home());
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn two_audit_kinds_with_one_token_fail() {
    // Codex's case: 22 and 46 both `reveal`, only 22 registered.
    let t = fixture();
    add_audit_kind(&t, "Reveal", 22, "reveal");
    add_audit_kind(&t, "RevealAgain", 46, "reveal");
    edit(
        &t,
        VAULT,
        "| 22 | `reveal` | M2-21 | reserved |",
        "| 22 | `reveal` | M2-21 | landed |",
    );
    assert_fails(
        &t,
        "`fn token` gives `reveal` to more than one `AuditKind` variant (RevealAgain, Reveal)",
    );
}

#[test]
fn two_audit_kinds_with_one_number_fail() {
    let t = fixture();
    add_audit_kind(&t, "Probe", 21, "probe");
    assert_fails(
        &t,
        "`AuditKind` gives 21 to more than one variant (Recover, Probe)",
    );
}

#[test]
fn two_error_kinds_with_one_code_fail() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => -32099,",
        "ErrorKind::Internal => -32034,",
    );
    assert_fails(
        &t,
        "`fn code` gives `-32034` to more than one `ErrorKind` variant (BackupUnusable, Internal)",
    );
}

#[test]
fn two_error_kinds_with_one_token_fail() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => \"internal\",",
        "ErrorKind::Internal => \"busy\",",
    );
    assert_fails(
        &t,
        "`fn token` gives `busy` to more than one `ErrorKind` variant (Busy, Internal)",
    );
}

#[test]
fn a_reason_or_a_method_twice_in_the_code_fails() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    \"not_text\",\n",
        "    \"not_text\",\n    \"common\",\n",
    );
    assert_fails(&t, "reason `common` appears twice");
    let t = fixture();
    edit(
        &t,
        PROTO,
        "const NAME: &'static str = \"lock\";",
        "const NAME: &'static str = \"unlock\";",
    );
    assert_fails(&t, "method name `unlock` appears twice");
}

// --- Code entries no row accounts for (D-23: reserved before use) ---------

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
fn an_unreserved_method_in_the_code_fails() {
    // Codex's case: a method no row reserves.
    let t = fixture();
    add_method(&t, "pending.peek");
    assert_fails(
        &t,
        &format!(
            "`method`: the code has `pending.peek` ({PROTO}), which no `landed` row reserves and {BASELINE} does not hold"
        ),
    );
}

#[test]
fn a_method_landed_as_reserved_passes() {
    let t = fixture();
    add_method(&t, "signin.status");
    edit(
        &t,
        IPC,
        "| `signin.status` | M2b-05 | reserved |",
        "| `signin.status` | M2b-05 | landed |",
    );
    assert_passes(&t.home());
}

#[test]
fn an_unreserved_reason_in_the_code_fails() {
    // Codex's case: a reason no row reserves.
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    \"not_text\",\n",
        "    \"not_text\",\n    \"new_m2_reason\",\n",
    );
    assert_fails(
        &t,
        &format!(
            "`reason`: the code has `new_m2_reason` ({PROTO}), which no `landed` row reserves and {BASELINE} does not hold"
        ),
    );
}

#[test]
fn an_unreserved_failure_token_in_the_code_fails() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn gone() -> Failure { Failure::new(\"brand_new_failure\", \"gone\") }\n",
    );
    assert_fails(
        &t,
        &format!(
            "`exit_token`: the code has `brand_new_failure` ({CLIENT_STUB}), which no `landed` row reserves"
        ),
    );
}

#[test]
fn an_unreserved_error_kind_outside_the_reserved_range_fails() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    Internal,\n}",
        "    Internal,\n    Fresh,\n}",
    );
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => -32099,",
        "ErrorKind::Internal => -32099,\n            ErrorKind::Fresh => -32000,",
    );
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => \"internal\",",
        "ErrorKind::Internal => \"internal\",\n            ErrorKind::Fresh => \"fresh\",",
    );
    assert_fails(
        &t,
        &format!(
            "`error_kind`: the code has `fresh` = -32000, which no `landed` row reserves and {BASELINE} does not hold"
        ),
    );
}

#[test]
fn an_unreserved_statement_domain_in_the_code_fails() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub const DOMAIN: &[u8] = b\"envcloak-probe-statement/1\\n\";\n",
    );
    assert_fails(
        &t,
        &format!(
            "`statement_domain`: the code has `envcloak-probe-statement/1` ({CLIENT_STUB}), which no `landed` row reserves"
        ),
    );
}

#[test]
fn a_baseline_entry_the_code_no_longer_holds_fails() {
    // Gone from the code.
    let t = fixture();
    edit(&t, BASELINE, "\nmethod lock\n", "\nmethod lock_all\n");
    assert_fails(
        &t,
        &format!("{BASELINE} holds `method lock_all`, but the code has no such entry"),
    );
    assert_fails(&t, "`method`: the code has `lock` (");
    // Renumbered in the code.
    let t = fixture();
    edit(&t, RECORD, "    Recover = 21,\n", "    Recover = 99,\n");
    assert_fails(
        &t,
        &format!("{BASELINE} holds `audit_kind recover` = 21, but the code has it as 99"),
    );
    assert_fails(
        &t,
        "the code has `recover` = 99 in the reserved range with no `landed` row",
    );
}

#[test]
fn a_missing_or_malformed_baseline_fails() {
    let t = fixture();
    std::fs::remove_file(t.home().join(BASELINE)).unwrap();
    assert_fails(&t, &format!("{BASELINE} could not be read"));
    let t = fixture();
    edit(&t, BASELINE, "\nmethod lock\n", "\nmethod\n");
    assert_fails(&t, "not `method <name>`");
    let t = fixture();
    edit(
        &t,
        BASELINE,
        "\naudit_kind run 1\n",
        "\naudit_kind run one\n",
    );
    assert_fails(&t, "not `audit_kind <name> <number>`");
    let t = fixture();
    edit(
        &t,
        BASELINE,
        "\nmethod lock\n",
        "\nmethod lock\nmethod lock\n",
    );
    assert_fails(&t, "`method lock` is listed twice");
    let t = fixture();
    edit(
        &t,
        BASELINE,
        "\nmethod lock\n",
        "\nmethod lock\ncoverage active\n",
    );
    assert_fails(
        &t,
        "`coverage` is not a registry whose code this script reads",
    );
}

// --- Readers that read every declaration or refuse it (Codex, PR #14) -----

const AAD: &str = "crates/envcloak-core/src/crypto/aad.rs";

/// Adds the line `variant` (as written, with its comma) to `AuditKind` and,
/// when `token` is given, its arm in `fn token`.
fn add_audit_variant(t: &TestHome, variant: &str, token: Option<(&str, &str)>) {
    edit(
        t,
        RECORD,
        "    Recover = 21,\n",
        &format!("    Recover = 21,\n    {variant}\n"),
    );
    if let Some((name, token)) = token {
        edit(
            t,
            RECORD,
            "AuditKind::Run => \"run\",",
            &format!("AuditKind::Run => \"run\",\n            AuditKind::{name} => \"{token}\","),
        );
    }
}

#[test]
fn an_audit_kind_with_a_hexadecimal_number_is_read() {
    // Codex's case: `Login = 0x04` was skipped, so neither the number it
    // shares with `Revoke` nor its missing row was seen.
    let t = fixture();
    add_audit_variant(&t, "Login = 0x04,", Some(("Login", "login")));
    assert_fails(
        &t,
        "`AuditKind` gives 4 to more than one variant (Revoke, Login)",
    );
    let t = fixture();
    add_audit_variant(&t, "Login = 0x16,", Some(("Login", "login")));
    assert_fails(
        &t,
        "the code has `login` = 22 in the reserved range with no `landed` row",
    );
    // Read as the number it is: 22 in any of Rust's forms lands `reveal`.
    for number in ["0x16", "0o26", "0b1_0110", "2_2", "22u8"] {
        let t = fixture();
        add_audit_variant(
            &t,
            &format!("Reveal = {number},"),
            Some(("Reveal", "reveal")),
        );
        edit(
            &t,
            VAULT,
            "| 22 | `reveal` | M2-21 | reserved |",
            "| 22 | `reveal` | M2-21 | landed |",
        );
        assert_passes(&t.home());
    }
}

#[test]
fn a_numbered_variant_without_its_number_fails() {
    // Codex's case: an implicit `Login` was skipped. Every variant of a
    // numbered registry is written with its number.
    let t = fixture();
    add_audit_variant(&t, "Login,", Some(("Login", "login")));
    assert_fails(
        &t,
        "`AuditKind::Login` has no explicit number: every `AuditKind` variant is written `Login = <number>`",
    );
    let t = fixture();
    edit(
        &t,
        AAD,
        "    FileBackupV2 = 10,\n}",
        "    FileBackupV2 = 10,\n    Login,\n}",
    );
    assert_fails(&t, "`TableTag::Login` has no explicit number");
}

#[test]
fn a_variant_the_reader_cannot_read_fails() {
    let t = fixture();
    add_audit_variant(&t, "Login = 21 + 1,", Some(("Login", "login")));
    assert_fails(
        &t,
        "`AuditKind::Login = 21 + 1` is not an integer literal the reader can read",
    );
    let t = fixture();
    add_audit_variant(&t, "Login(u8),", Some(("Login", "login")));
    assert_fails(
        &t,
        "`AuditKind` has a variant the reader cannot read (`Login(u8)`)",
    );
    // Attributes and doc comments on a variant are not part of it.
    let t = fixture();
    add_audit_variant(
        &t,
        "/// Revealed.\n    #[doc = \"x, y\"]\n    Reveal = 22,",
        Some(("Reveal", "reveal")),
    );
    edit(
        &t,
        VAULT,
        "| 22 | `reveal` | M2-21 | reserved |",
        "| 22 | `reveal` | M2-21 | landed |",
    );
    assert_passes(&t.home());
}

#[test]
fn a_variant_without_a_token_arm_the_reader_can_read_fails() {
    // A variant whose arm is missing, or written in a form the reader does
    // not take, is named, never left out of the registry.
    let t = fixture();
    add_audit_variant(&t, "Login = 46,", None);
    assert_fails(
        &t,
        "`fn token` has no `AuditKind::<variant> => <value>` arm the reader can read for Login",
    );
    let t = fixture();
    add_audit_variant(&t, "Login = 46,", Some(("Login", "Login")));
    assert_fails(&t, "the reader can read for Login");
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    Internal,\n}",
        "    Internal,\n    Fresh,\n}",
    );
    assert_fails(
        &t,
        "`fn code` has no `ErrorKind::<variant> => <value>` arm the reader can read for Fresh",
    );
}

#[test]
fn an_error_kind_arm_written_with_self_counts() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    Internal,\n}",
        "    Internal,\n    Fresh,\n}",
    );
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => -32099,",
        "ErrorKind::Internal => -32099,\n            Self::Fresh => -32_000,",
    );
    edit(
        &t,
        PROTO,
        "ErrorKind::Internal => \"internal\",",
        "ErrorKind::Internal => \"internal\",\n            Self::Fresh => \"fresh\",",
    );
    assert_fails(
        &t,
        "`error_kind`: the code has `fresh` = -32000, which no `landed` row reserves",
    );
}

/// Appends a method to the copy of proto.rs, its `NAME` written `decl`.
fn add_method_decl(t: &TestHome, decl: &str) {
    let path = t.home().join(PROTO);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{text}\npub struct Added;\n\nimpl Method for Added {{\n    {decl}\n    type Params = NoParams;\n    type Output = LockedView;\n}}\n"
        ),
    )
    .unwrap();
}

#[test]
fn a_method_named_by_a_raw_string_counts() {
    // Codex's case: `const NAME: &'static str = r"pending.state";` was
    // skipped. A raw string, `&str` without `'static` and an escape are
    // each read as the name they hold.
    for decl in [
        "const NAME: &'static str = r\"pending.peek\";",
        "const NAME: &'static str = r#\"pending.peek\"#;",
        "const NAME: &str = \"pending.peek\";",
        "const NAME : & 'static str=\"pending\\x2epeek\";",
    ] {
        let t = fixture();
        add_method_decl(&t, decl);
        assert_fails(
            &t,
            &format!(
                "`method`: the code has `pending.peek` ({PROTO}), which no `landed` row reserves"
            ),
        );
    }
    let t = fixture();
    add_method_decl(&t, "const NAME: &'static str = r\"signin.status\";");
    edit(
        &t,
        IPC,
        "| `signin.status` | M2b-05 | reserved |",
        "| `signin.status` | M2b-05 | landed |",
    );
    assert_passes(&t.home());
}

#[test]
fn a_method_name_the_reader_cannot_read_fails() {
    for (decl, message) in [
        (
            "const NAME: &'static str = concat!(\"pending\", \".peek\");",
            "a method's `const NAME` whose value is not one string literal",
        ),
        (
            "const NAME: &'static str = Lock::NAME;",
            "a method's `const NAME` whose value is not one string literal",
        ),
        (
            "const NAME: &'static [u8] = b\"pending.peek\";",
            "a `const NAME` the reader cannot read",
        ),
        (
            "const NAME: &'static str = \"Pending.Peek\";",
            "method name 'Pending.Peek' is not a well-formed method name",
        ),
    ] {
        let t = fixture();
        add_method_decl(&t, decl);
        assert_fails(&t, message);
    }
    // A method in another file of the protocol crate is read too.
    let t = fixture();
    add_file(
        &t,
        "crates/envcloak-ipc/src/added.rs",
        "impl crate::proto::Method for Added {\n    const NAME: &'static str = r\"pending.peek\";\n}\n",
    );
    assert_fails(
        &t,
        "`method`: the code has `pending.peek` (crates/envcloak-ipc/src/added.rs)",
    );
    // A `const NAME` outside an `impl Method for` block, or a block with
    // none the reader can read, is named.
    let t = fixture();
    add_file(
        &t,
        "crates/envcloak-ipc/src/added.rs",
        "impl Added {\n    const NAME: &'static str = \"pending.peek\";\n}\n",
    );
    assert_fails(&t, "a `const NAME` outside an `impl Method for` block");
    let t = fixture();
    add_file(
        &t,
        "crates/envcloak-ipc/src/added.rs",
        "impl Method for Added {\n    type Params = NoParams;\n}\n",
    );
    assert_fails(
        &t,
        "an `impl Method for` block with 0 `const NAME` the reader can read, not one",
    );
}

#[test]
fn a_reason_in_a_raw_string_counts_and_one_the_reader_cannot_read_fails() {
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    \"not_text\",\n",
        "    \"not_text\",\n    r\"new_m2_reason\",\n",
    );
    assert_fails(
        &t,
        "`reason`: the code has `new_m2_reason` (crates/envcloak-ipc/src/proto.rs), which no `landed` row reserves",
    );
    let t = fixture();
    edit(
        &t,
        PROTO,
        "    \"not_text\",\n",
        "    \"not_text\",\n    NEW_REASON,\n",
    );
    assert_fails(
        &t,
        "REASONS holds an entry that is not one string literal (`NEW_REASON`)",
    );
}

#[test]
fn a_failure_token_in_a_raw_string_or_with_an_escape_counts() {
    for text in [
        "pub fn gone() -> Failure { Failure::new(r\"brand_new_failure\", \"gone\") }\n",
        "const GONE: &'static str = r#\"brand_new_failure\"#;\npub fn gone() -> Failure { Failure::new(GONE, \"gone\") }\n",
        "pub fn gone() -> Failure { Failure::new(\"brand\\x5fnew\\u{5f}failure\", \"gone\") }\n",
        "pub fn gone() -> Report { Report { token: r\"brand_new_failure\" } }\n",
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, text);
        assert_fails(
            &t,
            &format!(
                "`exit_token`: the code has `brand_new_failure` ({CLIENT_STUB}), which no `landed` row reserves"
            ),
        );
    }
}

/// An arm whose value goes on past its literal is refused, never read as
/// the literal (review M2R-1): `-32602 + 1` is `MethodNotFound`'s code,
/// and `"invalid_params".split_at(8).1` is `params`, yet the reader took
/// the leading literal of each and passed.
///
/// Mutation checked: the reader taking the leading literal as before (no
/// check of what follows it): both copies pass and this fails.
#[test]
fn an_arm_whose_value_goes_on_past_its_literal_fails() {
    for (from, to, expect) in [
        (
            "ErrorKind::InvalidParams => -32602,",
            "ErrorKind::InvalidParams => -32602 + 1,",
            "`fn code` gives `ErrorKind::InvalidParams` an expression the reader cannot read (`-32602 + 1",
        ),
        (
            "ErrorKind::InvalidParams => \"invalid_params\",",
            "ErrorKind::InvalidParams => \"invalid_params\".split_at(8).1,",
            "`fn token` gives `ErrorKind::InvalidParams` an expression the reader cannot read (`\"invalid_params\".split_at(8).1",
        ),
    ] {
        let t = fixture();
        edit(&t, PROTO, from, to);
        assert_fails(&t, expect);
    }
    // The same arm with only its literal, a comment or the match's end
    // after it, passes.
    let t = fixture();
    edit(
        &t,
        PROTO,
        "ErrorKind::InvalidParams => -32602,",
        "ErrorKind::InvalidParams => -32602, // the JSON-RPC code",
    );
    assert_passes(&t.home());
}

/// Failure tokens in the forms the reader skipped (review M2R-2, M2R-3):
/// `concat!` of literals is read joined, an inline `const` block and each
/// branch of a conditional by their literals, and `Fail::new` (the
/// client's public alias of `Failure`) and an alias of it made with
/// `use ... as` or `type` like `Failure::new`. A reserved token in any of
/// them is refused, and so is an unreserved one.
///
/// Mutation checked: the reader taking only `Failure::new` and only a
/// lone literal or constant as before: each copy passes and this fails.
#[test]
fn failure_tokens_in_every_form_the_code_can_write_count() {
    for body in [
        "pub fn a() -> Failure { Failure::new(concat!(\"pty_\", \"unavailable\"), \"refused\") }\n",
        "pub fn a() -> Failure { Failure::new(const { \"pty_unavailable\" }, \"refused\") }\n",
        "pub fn a() -> Failure { Failure::new(if true { \"io\" } else { \"pty_unavailable\" }, \"x\") }\n",
        "pub fn a() -> crate::Fail { crate::Fail::new(\"pty_unavailable\", \"refused\") }\n",
        "pub fn a() -> Fail { envcloak_client::Fail::new(\"pty_unavailable\", \"refused\") }\n",
        "use crate::fail::Failure as Oops;\npub fn a() -> Oops { Oops::new(\"pty_unavailable\", \"x\") }\n",
        "type Bad = crate::Fail;\npub fn a() -> Bad { Bad::new(\"pty_unavailable\", \"x\") }\n",
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(
            &t,
            &format!("`pty_unavailable` is reserved, but the code already has it ({CLIENT_STUB})"),
        );
    }
    for body in [
        "pub fn a() -> Failure { Failure::new(concat!(\"zz_\", \"unreserved\"), \"x\") }\n",
        "pub fn a() -> crate::Fail { crate::Fail::new(\"zz_unreserved\", \"x\") }\n",
        "pub fn a() -> Failure { Failure::new(if true { \"io\" } else { \"zz_unreserved\" }, \"x\") }\n",
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(
            &t,
            &format!(
                "`exit_token`: the code has `zz_unreserved` ({CLIENT_STUB}), which no `landed` row reserves"
            ),
        );
    }
}

/// A token argument the reader cannot read is refused, never skipped: a
/// local variable, a constant it does not know, `concat!` of anything but
/// literals, and another macro. The enclosing function's own `token`
/// parameter and another value's `.token()` are read where their values
/// are (the helper's callers, the `fn token` bodies), and pass.
#[test]
fn a_failure_token_the_reader_cannot_read_fails() {
    for (body, expect) in [
        (
            "pub fn a(t: &'static str) -> Failure { Failure::new(t, \"x\") }\n",
            "a failure token the reader cannot read (`t`)",
        ),
        (
            "pub fn a() -> Failure { Failure::new(UNKNOWN_TOKEN, \"x\") }\n",
            "a failure token names `UNKNOWN_TOKEN`, which is no `&str` constant the reader knows",
        ),
        (
            "pub fn a(x: &'static str) -> Failure { Failure::new(concat!(\"pty_\", x), \"x\") }\n",
            "a failure token in `concat!` of something other than string literals",
        ),
        (
            "pub fn a() -> Failure { Failure::new(stringify!(pty_unavailable), \"x\") }\n",
            "a macro other than `concat!` of literals",
        ),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, expect);
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn stub_refuse(token: &'static str) -> Failure { Failure::new(token, \"x\") }\n\
         pub fn stub_again(e: &crate::fail::Failure) -> Failure { Failure::new(e.token(), \"x\") }\n",
    );
    assert_passes(&t.home());
}

/// A table with no code reader takes no `landed` row (review M2R-7): the
/// row would be accepted with no code behind it.
///
/// Mutation checked: `landed` accepted in such a table as before: the
/// copy passes and this fails.
#[test]
fn a_landed_row_in_a_table_without_a_reader_fails() {
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `active` | state | M2-09 | reserved |",
        "| `active` | state | M2-09 | landed |",
    );
    assert_fails(
        &t,
        "`coverage`: `active` is `landed`, but this table has no code reader to check it against: add its reader first",
    );
}

/// A failure token is accounted for only by a row of a table whose tokens
/// the failure-token reader takes (the printed tables and the audit
/// kinds), never by a row of an unrelated table (review M2R-7): an MCP
/// tool's name is not a failure token's reservation.
///
/// Mutation checked: `elsewhere` taking every table's rows as before: the
/// copy passes and this fails.
#[test]
fn a_failure_token_covered_only_by_an_unrelated_table_fails() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn a() -> Failure { Failure::new(\"list_secrets\", \"x\") }\n",
    );
    assert_fails(
        &t,
        &format!(
            "`exit_token`: the code has `list_secrets` ({CLIENT_STUB}), which no `landed` row reserves"
        ),
    );
}

/// The reserved token and an unreserved one, refused as a clash and as a
/// token no `landed` row reserves.
fn assert_counted(body: &str, file: &str) {
    for (token, expect) in [
        (
            "pty_unavailable",
            format!("`pty_unavailable` is reserved, but the code already has it ({file})"),
        ),
        (
            "zz_unreserved",
            format!(
                "`exit_token`: the code has `zz_unreserved` ({file}), which no `landed` row reserves"
            ),
        ),
    ] {
        let t = fixture();
        if file == CLIENT_STUB {
            add_file(&t, file, &body.replace("TOKEN", token));
        } else {
            let path = t.home().join(file);
            let mut text = std::fs::read_to_string(&path).unwrap();
            text.push_str(&body.replace("TOKEN", token));
            std::fs::write(&path, text).unwrap();
        }
        assert_fails(&t, &expect);
    }
}

/// A token handed on through a `token` parameter in any position is read
/// at the helper's callers, in that position (review of M2-RES1: a
/// `token` second parameter was exempt in the helper's body, but its
/// callers were read only at their first argument, so a reserved or
/// unreserved token passed there was never seen). The verifier's
/// reproduction appended to `envcloak check`, and Codex's in the client.
///
/// Mutation checked: helpers taken only with `token` first and read at
/// the first argument, the exemption kept for any function with a `token`
/// parameter (as before): each copy passes and this fails.
#[test]
fn a_token_handed_on_from_any_parameter_position_is_read_at_the_callers() {
    assert_counted(
        "\nfn zz_a(code: u8, token: &'static str) -> ExitCode { Failure::new(token, \"x\").report(code) }\n\
         fn zz_b() -> ExitCode { zz_a(125, \"TOKEN\") }\n",
        "crates/envcloak-cli/src/cmd/check.rs",
    );
    assert_counted(
        "pub fn zz_a(code: u8, token: crate::fail::ExitToken) -> Failure { let _ = code; Failure::new(token, \"x\") }\n\
         pub fn zz_b() -> Failure { zz_a(1, \"TOKEN\") }\n",
        CLIENT_STUB,
    );
    // Through an alias of `&'static str`, and through a second helper.
    assert_counted(
        "pub type Tok = &'static str;\n\
         pub fn zz_a(code: u8, token: Tok) -> Failure { let _ = code; zz_c(token) }\n\
         fn zz_c(token: &'static str) -> Failure { Failure::new(token, \"x\") }\n\
         pub fn zz_b() -> Failure { zz_a(1, \"TOKEN\") }\n",
        CLIENT_STUB,
    );
}

/// A `Failure` struct literal's `token` is read as an argument is: each
/// branch of a conditional, `concat!` joined, and one the reader cannot
/// read refused (review of M2-RES1: the field reader skipped any value
/// that was not one literal or constant). The verifier's reproductions,
/// appended to `envcloak check`.
///
/// Mutation checked: a struct literal's `token` read as the other
/// structs' fields are (a literal or a constant, anything else skipped):
/// the copies pass and this fails.
#[test]
fn a_failure_literal_token_is_read_in_every_form_or_refused() {
    let check = "crates/envcloak-cli/src/cmd/check.rs";
    assert_counted(
        "\nfn zz_c(flag: bool) -> Failure { Failure { token: if flag { \"io\" } else { \"TOKEN\" }, message: \"x\".into() } }\n",
        check,
    );
    assert_counted(
        "\nfn zz_d() -> Failure { Failure { token: concat!(\"\", \"TOKEN\"), message: \"x\".into() } }\n",
        check,
    );
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn a() -> Failure { let token = \"pty_unavailable\"; Failure { token, message: \"x\".into() } }\n",
    );
    assert_fails(&t, "a failure token the reader cannot read (`token`)");
}

/// A helper's `token` is only ever handed on as a failure token: rebound
/// by a `let`, a closure or a pattern, a value the callers did not pass
/// could reach a failure. A method's `token` parameter is not read at its
/// callers, so a method cannot hand one on.
///
/// Mutation checked: the check of a helper's other uses of `token`
/// removed: each copy passes and this fails.
#[test]
fn a_helpers_token_used_other_than_handed_on_fails() {
    for body in [
        "pub fn zz_h(token: &'static str) -> Failure { let token = \"pty_unavailable\"; Failure::new(token, \"x\") }\n",
        "pub fn zz_h(token: &'static str) -> Failure { let f = |token| Failure::new(token, \"x\"); f(\"pty_unavailable\") }\n",
        "pub fn zz_h(token: &'static str, o: Option<&'static str>) -> Failure { if let Some(token) = o { return Failure::new(token, \"x\"); } Failure::new(token, \"y\") }\n",
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(
            &t,
            "`zz_h`'s `token` is used other than handed on as a failure token",
        );
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub struct S;\nimpl S { pub fn f(&self, token: &'static str) -> Failure { Failure::new(token, \"x\") } }\n",
    );
    assert_fails(&t, "a failure token the reader cannot read (`token`)");
}

/// A private helper is visible in its module's children too, in other
/// files: its calls there, by a path (`super::name`) or after a `use`, are
/// read, and a function pointer to it through a glob import is refused. A
/// local of the same name in a file that does not import it is not the
/// helper, and passes.
///
/// Mutation checked: a private helper's calls read in its own file only:
/// the child's call is not read, the copy passes and this fails.
#[test]
fn a_private_helpers_calls_in_its_modules_children_are_read() {
    let parent = "crates/envcloak-client/src/zzmod/mod.rs";
    let child = "crates/envcloak-client/src/zzmod/child.rs";
    let helper = "fn zz_h(token: &'static str) -> crate::fail::Failure { crate::fail::Failure::new(token, \"x\") }\nmod child;\n";
    for (body, expect) in [
        (
            "pub fn g() -> crate::fail::Failure { super::zz_h(\"pty_unavailable\") }\n",
            format!("`pty_unavailable` is reserved, but the code already has it ({child})"),
        ),
        (
            "use super::zz_h;\npub fn g() -> crate::fail::Failure { zz_h(\"pty_unavailable\") }\n",
            format!("`pty_unavailable` is reserved, but the code already has it ({child})"),
        ),
        (
            "use super::*;\npub fn g() -> Option<crate::fail::Failure> { Some(\"pty_unavailable\").map(zz_h) }\n",
            "the token helper `zz_h` is used other than called by name".to_owned(),
        ),
    ] {
        let t = fixture();
        add_file(&t, parent, helper);
        add_file(&t, child, body);
        assert_fails(&t, &expect);
    }
    let t = fixture();
    add_file(&t, parent, helper);
    add_file(
        &t,
        child,
        "pub fn g(f: &crate::fail::Failure) { let zz_h = f; let _ = zz_h.token(); }\n",
    );
    assert_passes(&t.home());
}

/// `Failure::new` and a token helper are read at their calls, so naming
/// either any other way (a function pointer, an alias made with `use ...
/// as`) is refused: the tokens handed to it would not be read.
///
/// Mutation checked: mentions other than calls skipped: each copy passes
/// and this fails.
#[test]
fn a_token_helper_or_failure_new_named_other_than_called_fails() {
    for (body, expect) in [
        (
            "pub fn zz_h(token: &'static str) -> Failure { Failure::new(token, \"x\") }\n\
             pub fn zz_g() -> Option<Failure> { Some(\"pty_unavailable\").map(zz_h) }\n",
            "the token helper `zz_h` is used other than called by name",
        ),
        (
            "pub fn zz_h(token: &'static str) -> Failure { Failure::new(token, \"x\") }\n\
             mod inner { use super::zz_h as other; pub fn g() -> crate::fail::Failure { other(\"pty_unavailable\") } }\n",
            "the token helper `zz_h` is used other than called by name",
        ),
        (
            "pub fn zz_g() -> Failure { let f = Failure::new; f(\"pty_unavailable\", \"x\") }\n",
            "`Failure::new` is used other than called",
        ),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, expect);
    }
    // Called by a path, or with a turbofish, it is read.
    assert_counted(
        "impl Failure { pub fn zz_x() -> Self { Self::new(\"TOKEN\", \"x\") } }\n",
        CLIENT_STUB,
    );
    assert_counted(
        "pub fn zz_g() -> Failure { <Failure>::new(\"TOKEN\", \"x\") }\n",
        CLIENT_STUB,
    );
}

const FAIL: &str = "crates/envcloak-client/src/fail.rs";

/// `Failure` is defined once, in fail.rs, with a private `token` that
/// file never changes after the failure is made; otherwise code anywhere
/// could set a token where the reader does not look.
///
/// Mutation checked: `check_failure_struct` not called: each copy passes
/// and this fails.
#[test]
fn a_failures_token_is_set_only_where_it_is_made() {
    let t = fixture();
    edit(
        &t,
        FAIL,
        "    token: ExitToken,\n",
        "    pub token: ExitToken,\n",
    );
    assert_fails(&t, "`Failure`'s `token` field is public");
    for change in [
        "impl Failure { pub fn zz(&mut self) { self.token = \"pty_unavailable\"; } }\n",
        "impl Failure { pub fn zz(&mut self) { let _ = std::mem::replace(&mut self.token, \"pty_unavailable\"); } }\n",
    ] {
        let t = fixture();
        let path = t.home().join(FAIL);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(change);
        std::fs::write(&path, text).unwrap();
        assert_fails(&t, "`Failure`'s token is changed after it is made");
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub struct Failure { pub token: &'static str }\n",
    );
    assert_fails(&t, "`Failure` must be defined once");
}

/// A `fn token` that returns a static string is read for every value it
/// can have, so another value's `.token()` hides none: one returning a
/// field, or an index, is refused. One that lends its receiver's own
/// field (`-> &str`, `&self.field`) lives no longer than the receiver and
/// is no failure token; it passes.
///
/// Mutation checked: `fn token` bodies read for their string literals
/// only, as before: the copies pass and this fails.
#[test]
fn a_token_method_the_reader_cannot_read_fails() {
    for (body, expect) in [
        (
            "pub struct E { name: &'static str }\n\
             impl E { pub fn token(&self) -> &'static str { self.name } }\n",
            "a failure token the reader cannot read (`self.name`)",
        ),
        (
            "pub enum K { A }\nconst NAMES: [&str; 1] = [\"pty_unavailable\"];\n\
             impl K { pub fn token(self) -> crate::fail::ExitToken { match self { K::A => NAMES[0] } } }\n",
            "a failure token the reader cannot read (`NAMES[0]`)",
        ),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, expect);
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub struct M { key: String }\nimpl M { pub fn token(&self) -> &str { &self.key } }\n",
    );
    assert_passes(&t.home());
}

/// A placeholder where the token goes prints its argument as one: it is
/// read as a token argument (a failure's `.token()` passes), and a
/// variable is refused. A usage line, `envcloak: {why}`, prints a message
/// from its file's `fn parse`, whose every `<token>:` start counts; one
/// whose message comes from anywhere else is refused.
///
/// Mutation checked: lines starting `envcloak: {` skipped, as before: the
/// copies pass and this fails.
#[test]
fn a_token_printed_from_a_placeholder_is_read_or_refused() {
    for (body, expect) in [
        (
            "pub fn d(t: &str) { eprintln!(\"envcloak: {t}: x\"); }\n",
            "a line printed as `envcloak: {t}:` takes its token from a variable",
        ),
        (
            "pub fn d() { let why = \"pty_unavailable: x\"; eprintln!(\"envcloak: {why}\"); }\n",
            "a usage line `envcloak: {why}` whose message the reader cannot trace",
        ),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, expect);
    }
    assert_counted(
        "pub fn d() { eprintln!(\"envcloak: {}: x\", \"TOKEN\"); }\n",
        CLIENT_STUB,
    );
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn d(f: &Failure) { eprintln!(\"envcloak: {}: x\", f.token()); }\n",
    );
    assert_passes(&t.home());
    // A usage message of `envcloak add` starting with a token.
    let t = fixture();
    edit(
        &t,
        "crates/envcloak-cli/src/cmd/add.rs",
        "Err(\"unknown or repeated option\")",
        "Err(\"pty_unavailable: unknown or repeated option\")",
    );
    assert_fails(
        &t,
        "`pty_unavailable` is reserved, but the code already has it (crates/envcloak-cli/src/cmd/add.rs)",
    );
}

/// An `if` or a `match` is read by every branch, and one whose branch the
/// reader cannot read is refused (review of M2-RES1: an expression was
/// counted by whatever literals it held, so a variable beside a literal
/// went unread).
///
/// Mutation checked: any other expression counted by its literals and
/// constants, as before: the variable copy passes and this fails.
#[test]
fn a_conditional_with_a_branch_the_reader_cannot_read_fails() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn zz_g(c: bool, t: &'static str) -> Failure { Failure::new(if c { \"io\" } else { t }, \"x\") }\n",
    );
    assert_fails(&t, "a failure token the reader cannot read (`t`)");
    assert_counted(
        "pub fn zz_g(k: u8) -> Failure { Failure::new(match k { 1 => \"io\", _ => \"TOKEN\" }, \"x\") }\n",
        CLIENT_STUB,
    );
}
