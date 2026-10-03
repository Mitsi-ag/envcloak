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

/// A copy of what the script reads (the two documents, the baseline, the
/// workspace's manifest, and every crate's `src/`, manifest and build
/// script), under a fresh test home.
fn fixture() -> TestHome {
    let t = TestHome::new();
    let root = t.home();
    for rel in ["docs/IPC.md", "docs/VAULT.md", BASELINE, "Cargo.toml"] {
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
    // Not a `envcloak: <token>:` line: two words, no colon after the
    // word, or a placeholder inside a line that no colon follows. (A
    // placeholder where the token goes is read:
    // `a_token_printed_from_a_placeholder_is_read_or_refused`; and
    // `envcloak: <token>:` anywhere in a string counts, since a slice of
    // it prints it: `a_line_made_at_compile_time_is_read_or_refused`.)
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn a() { eprintln!(\"envcloak: pty unavailable: no terminal\"); }\n\
         pub fn b() { eprintln!(\"envcloak: app_required because\"); }\n\
         pub fn c() -> String { format!(\"[envcloak: {} incomplete: cut]\", 3) }\n",
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
            "`concat!` of something other than literals",
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
/// field, or an index, is refused. A method named `token` that returns
/// anything else is refused too (Codex review of M2-RES1: one lending
/// its receiver's field, `-> &str`, was passed over, so a `.token()`
/// printed as `envcloak: {}:` printed a value nobody read): a `.token()`
/// cannot be told from a failure's, so every method of that name is read.
/// A free function named `token` is not what `.token()` calls, and
/// passes.
///
/// Mutations checked: `fn token` bodies read for their string literals
/// only, as before: the first copies pass and this fails. The check of a
/// `token` method's return type removed: the lending method, printed,
/// passes and this fails.
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
    for (body, ret) in [
        (
            "pub struct M { key: String }\nimpl M { pub fn token(&self) -> &str { &self.key } }\n\
             pub fn d(m: &M) { eprintln!(\"envcloak: {}: x\", m.token()); }\n",
            "`&str`",
        ),
        (
            "pub struct M { key: String }\nimpl M { pub fn token(&self) -> String { self.key.clone() } }\n",
            "`String`",
        ),
        ("pub trait ZzT { fn token(&self) -> &str; }\n", "`&str`"),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(
            &t,
            &format!("a method `token` returns {ret}, not a static string"),
        );
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn token(b: &[u8]) -> String { String::from_utf8_lossy(b).into_owned() }\n",
    );
    assert_passes(&t.home());
}

/// A placeholder where the token goes prints its argument as one: it is
/// read as a token argument (a failure's `.token()` passes), and a
/// variable is refused. A usage line, `envcloak: {why}`, prints a message
/// from its file's `fn parse`, whose every `<token>:` start counts; one
/// whose message comes from anywhere else is refused.
///
/// Mutations checked: lines starting `envcloak: {` skipped, as before: the
/// copies pass and this fails. A usage line taken whenever its function
/// binds the name with `Err(..)` and calls `parse` anywhere: another
/// call's message passes and this fails.
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
        // In a function that calls `parse`, but printing another call's
        // message.
        (
            "fn parse(a: &[&str]) -> Result<(), &'static str> { let _ = a; Err(\"bad option\") }\n\
             fn other() -> Result<(), &'static str> { Err(\"pty_unavailable: x\") }\n\
             pub fn run(a: &[&str]) { let _ = parse(a); match other() { Ok(()) => {}, Err(why) => eprintln!(\"envcloak: {why}\") } }\n",
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

/// Appends `text` to the copy of `rel`.
fn append_to(t: &TestHome, rel: &str, text: &str) {
    let path = t.home().join(rel);
    let mut old = std::fs::read_to_string(&path).unwrap();
    old.push_str(text);
    std::fs::write(&path, old).unwrap();
}

/// fail.rs names `Failure`'s token only where the reader has read it or
/// knows it changes nothing (verifier review of M2-RES1: a destructuring
/// `let Failure { token, .. } = &mut f; *token = t;` changed a made
/// failure's token unseen, so `from_parts("pty_unavailable")` passed).
/// Every way to reach the field is refused: a pattern that binds it
/// (against `&mut`, with `ref mut`, `token: ref mut`, in an `if let`), an
/// assignment through a parenthesized place, `clone_from`, a macro that
/// assigns it, and another struct with a `token` field in fail.rs, whose
/// field would pass for `Failure`'s.
///
/// Mutation checked: `check_fail_rs_tokens` not called: the copies
/// refused by it pass and this fails.
#[test]
fn fail_rs_names_a_failures_token_only_where_it_is_read() {
    let t = fixture();
    append_to(
        &t,
        FAIL,
        "impl Failure { pub fn from_parts(t: ExitToken) -> Self { let mut f = Failure::new(\"run_failed\", \"\"); \
         let Failure { token, .. } = &mut f; *token = t; f } }\n",
    );
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn g() -> crate::fail::Failure { crate::fail::Failure::from_parts(\"pty_unavailable\") }\n",
    );
    let named = "`Failure`'s `token` is named where the reader cannot tell it is not changed";
    assert_fails(&t, named);
    for change in [
        "impl Failure { pub fn zz(&mut self) { let Failure { ref mut token, .. } = *self; *token = \"pty_unavailable\"; } }\n",
        "impl Failure { pub fn zz(&mut self) { let Failure { token: ref mut x, .. } = *self; *x = \"pty_unavailable\"; } }\n",
        "impl Failure { pub fn zz(&mut self) { if let Failure { token, .. } = self { *token = \"pty_unavailable\"; } } }\n",
        "impl Failure { pub fn zz(&mut self) { (self.token) = \"pty_unavailable\"; } }\n",
        "impl Failure { pub fn zz(&mut self) { self.token.clone_from(&\"pty_unavailable\"); } }\n",
        "macro_rules! zz_set { ($f:expr) => { let Failure { token, .. } = $f; *token = \"pty_unavailable\"; }; }\n\
         impl Failure { pub fn zz(&mut self) { zz_set!(self); } }\n",
        "struct Zz { token: &'static str }\n\
         pub fn zz(t: &'static str) { let z = Zz { token: t }; eprintln!(\"envcloak: {}: x\", z.token); }\n",
    ] {
        let t = fixture();
        append_to(&t, FAIL, change);
        assert_fails(&t, named);
    }
}

/// `Failure` can be made no way the reader does not read: a derive or an
/// attribute that would make one (`Default`, a deserializer, one added
/// under `cfg_attr`) is refused, and so is a module of fail.rs in another
/// file, which could reach the private field.
///
/// Mutations checked: the attribute check removed: the `Default` copy
/// passes and this fails. The check of fail.rs's modules removed: the
/// child module's assignment is not seen, the copy passes and this
/// fails.
#[test]
fn a_failure_is_made_no_way_the_reader_does_not_read() {
    for (derive, expect) in [
        (
            "#[derive(Debug, Clone, PartialEq, Eq, Default)]",
            "`Failure` derives `Default`",
        ),
        (
            "#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]",
            "`Failure` derives `serde::Deserialize`",
        ),
        (
            "#[derive(Debug, Clone, PartialEq, Eq)]\n#[cfg_attr(test, derive(Default))]",
            "`Failure` carries `#[cfg_attr(test, derive(Default))]`",
        ),
    ] {
        let t = fixture();
        edit(
            &t,
            FAIL,
            "#[derive(Debug, Clone, PartialEq, Eq)]\npub struct Failure",
            &format!("{derive}\npub struct Failure"),
        );
        assert_fails(&t, expect);
    }
    let t = fixture();
    append_to(&t, FAIL, "mod zz_child;\n");
    add_file(
        &t,
        "crates/envcloak-client/src/fail/zz_child.rs",
        "impl super::Failure { pub fn zz(&mut self) { self.token = \"pty_unavailable\"; } }\n",
    );
    assert_fails(&t, "fail.rs declares a module in another file");
}

/// A raw identifier names what the plain one does: `Failure::r#new` is
/// read as `Failure::new`, and `self.r#token = ..` in fail.rs is refused
/// as `self.token = ..` is.
///
/// Mutation checked: raw identifiers left as written: `r#new` is not
/// read, the reserved token passes and this fails.
#[test]
fn a_raw_identifier_is_read_as_its_name() {
    assert_counted(
        "pub fn zz_g() -> Failure { Failure::r#new(\"TOKEN\", \"x\") }\n",
        CLIENT_STUB,
    );
    let t = fixture();
    append_to(
        &t,
        FAIL,
        "impl Failure { pub fn zz(&mut self) { self.r#token = \"pty_unavailable\"; } }\n",
    );
    assert_fails(&t, "`Failure`'s token is changed after it is made");
}

const RUN_RS: &str = "crates/envcloak-cli/src/cmd/run.rs";
const ADD_RS: &str = "crates/envcloak-cli/src/cmd/add.rs";

/// Every message `fn parse` can give a usage line, `envcloak: {why}`, is
/// read as a token argument (verifier review of M2-RES1: `concat!`, a
/// constant and a helper's `ParseError::Usage("pty_unavailable: ...")`
/// each printed `envcloak: pty_unavailable: ...` and passed). A message
/// from `concat!` or a constant counts; one from a helper, a `?` on a
/// helper's result, a `From` that makes its own message (in run.rs or in
/// another file) or a last expression other than `Ok`/`Err` is refused.
///
/// Mutation checked: `parse_errors` not called (only the strings written
/// in `fn parse` read, as before): the constant and refused copies pass
/// and this fails.
#[test]
fn every_message_fn_parse_can_give_is_read() {
    let grace = "return Err(\"--wait-grace needs --wait\".into());";
    let reserved = format!("`pty_unavailable` is reserved, but the code already has it ({RUN_RS})");
    for (to, extra, expect) in [
        (
            "return Err(concat!(\"pty_unavailable\", \": no terminal\").into());",
            "",
            reserved.as_str(),
        ),
        (
            "return Err(ZZ_WHY.into());",
            "const ZZ_WHY: &str = \"pty_unavailable: no terminal\";\n",
            reserved.as_str(),
        ),
        (
            "return Err(zz_why());",
            "fn zz_why() -> ParseError { ParseError::Usage(\"pty_unavailable: no terminal\") }\n",
            "`fn parse` gives an error the reader cannot read",
        ),
        (
            "zz_check()?;",
            "fn zz_check() -> Result<(), &'static str> { Err(\"pty_unavailable: x\") }\n",
            "`fn parse` has a `?` whose error the reader cannot read",
        ),
    ] {
        let t = fixture();
        edit(&t, RUN_RS, grace, to);
        append_to(&t, RUN_RS, extra);
        assert_fails(&t, expect);
    }
    let t = fixture();
    edit(
        &t,
        RUN_RS,
        "        ParseError::Usage(why)\n",
        "        let _ = why;\n        ParseError::Usage(\"pty_unavailable: x\")\n",
    );
    assert_fails(
        &t,
        "a `From` for `ParseError`, the error of `fn parse`, that does not hand its value to a variant unchanged",
    );
    let t = fixture();
    append_to(
        &t,
        "crates/envcloak-cli/src/main.rs",
        "impl From<u8> for crate::cmd::run::ParseError { fn from(_: u8) -> Self { Self::Usage(\"pty_unavailable: x\") } }\n",
    );
    assert_fails(&t, &format!("the error of `fn parse`, outside {RUN_RS}"));
    let t = fixture();
    edit(
        &t,
        ADD_RS,
        "    Ok(a)\n}\n\npub fn run",
        "    zz(a)\n}\n\nfn zz(a: AddArgs) -> Result<AddArgs, &'static str> { let _ = a; Err(\"pty_unavailable: x\") }\n\npub fn run",
    );
    assert_fails(
        &t,
        "`fn parse` ends with something other than `Ok(..)` or `Err(..)`",
    );
    let t = fixture();
    edit(
        &t,
        ADD_RS,
        ".ok_or(\"an option needs a name after it\")?",
        ".ok_or(ZZ_WHY)?",
    );
    append_to(&t, ADD_RS, "const ZZ_WHY: &str = \"pty_unavailable: x\";\n");
    assert_fails(
        &t,
        &format!("`pty_unavailable` is reserved, but the code already has it ({ADD_RS})"),
    );
}

/// A line made at compile time is read wherever its text is, or refused
/// (verifier review of M2-RES1: `eprintln!(concat!("envcloak: ",
/// "pty_unavailable", ": x"))` passed). `concat!` in any brackets is read
/// joined; a literal holding the line anywhere counts (a slice of it
/// prints it), with any white space after `envcloak:`; a placeholder
/// after a newline takes the argument its place among the placeholders
/// gives. Text the reader cannot see is refused:
/// `stringify!` of `envcloak`, `include_str!`, `env!` of a variable other
/// than Cargo's own, and `concat!` of anything but literals.
///
/// Mutations checked: `concat!` values left out of the strings read: the
/// first two copies pass and this fails. `envcloak: <token>:` matched at
/// the start of a string only: the slice passes and this fails. One
/// space only after `envcloak:`: the tab passes and this fails.
/// Placeholders read only at the start of a string: the newline copy
/// passes and this fails. The unreadable macros not refused: those copies
/// pass and this fails.
#[test]
fn a_line_made_at_compile_time_is_read_or_refused() {
    for body in [
        "pub fn zz_d() { eprintln!(concat!(\"envcloak: \", \"TOKEN\", \": x\")); }\n",
        "pub fn zz_d() { eprintln!(concat![\"envcloak: \", \"TOKEN\", \": x\"]); }\n",
        "const ZZ_L: &str = \"(envcloak: TOKEN: x\";\npub fn zz_d() { eprintln!(\"{}\", &ZZ_L[1..]); }\n",
        "pub fn zz_d() { eprintln!(\"{}\\nenvcloak: {}: x\", 1, \"TOKEN\"); }\n",
        "pub fn zz_d() { eprintln!(\"envcloak:\\tTOKEN: x\"); }\n",
    ] {
        assert_counted(body, CLIENT_STUB);
    }
    for (body, expect) in [
        (
            "pub fn zz_d(a: u8, t: &str) { eprintln!(\"{}\\nenvcloak: {}: x\", a, t); }\n",
            "a failure token the reader cannot read (`t`)",
        ),
        (
            "pub fn zz_d(t: &str) { eprintln!(concat!(\"envcloak: {}\", \": x\"), t); }\n",
            "a failure token the reader cannot read (`t`)",
        ),
        (
            "pub fn zz_d() { eprintln!(stringify!(envcloak: pty_unavailable: x)); }\n",
            "`stringify!` of text that holds `envcloak`",
        ),
        (
            "pub fn zz_d() { eprintln!(include_str!(\"zz.txt\")); }\n",
            "`include_str!` brings in text from another file",
        ),
        (
            "pub fn zz_d() { eprintln!(env!(\"ZZ_LINE\")); }\n",
            "`env!` of a variable other than Cargo's own package variables",
        ),
        (
            "pub fn zz_d() { eprintln!(concat!(env!(\"CARGO_PKG_NAME\"), \": pty_unavailable: x\")); }\n",
            "`concat!` of something other than literals",
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
        "pub fn zz_d(a: u8, f: &Failure) { eprintln!(\"{}\\nenvcloak: {}: x\", a, f.token()); }\n",
    );
    assert_passes(&t.home());
}

/// A constant or a static is read by its whole value (Codex review of
/// M2-RES1: `"approval_required".split_at(9).1` was read by its leading
/// literal, though it is `required`). One the reader cannot read, or a
/// mutable static, is refused where it is named as a token; a static and
/// a constant naming another are read. A name in capitals is a
/// constant's: a lint override that would let a local be named so (and
/// read as a constant of that name in another module), in the sources or
/// a manifest, is refused, and so is a build script that sets a variable
/// for `env!`.
///
/// Mutations checked: a constant read by its leading literal, and
/// statics left unread, as before: the `split_at` copy passes, the
/// static is refused for another reason, and this fails. The lint,
/// manifest and build-script checks removed: each copy passes and this
/// fails.
#[test]
fn a_constant_is_read_by_its_whole_value() {
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "const ZZ_T: &str = \"approval_required\".split_at(9).1;\n\
         pub fn zz_a() -> Failure { Failure::new(ZZ_T, \"x\") }\n",
    );
    assert_fails(
        &t,
        "a failure token names `ZZ_T`, whose value the reader cannot read",
    );
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "static mut ZZ_T: &str = \"io\";\npub fn zz_a() -> Failure { Failure::new(ZZ_T, \"x\") }\n",
    );
    assert_fails(&t, "a failure token names `ZZ_T`, a mutable static");
    assert_counted(
        "static ZZ_T: &str = \"TOKEN\";\npub fn zz_a() -> Failure { Failure::new(ZZ_T, \"x\") }\n",
        CLIENT_STUB,
    );
    assert_counted(
        "const ZZ_A: &str = ZZ_B;\nconst ZZ_B: &str = \"TOKEN\";\n\
         pub fn zz_a() -> Failure { Failure::new(ZZ_A, \"x\") }\n",
        CLIENT_STUB,
    );
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "mod zz_m { pub const ZZ_T: &str = \"io\"; }\n\
         #[allow(non_snake_case)]\npub fn zz_a() -> Failure { let ZZ_T = \"pty_unavailable\"; Failure::new(ZZ_T, \"x\") }\n",
    );
    assert_fails(&t, "`non_snake_case` is allowed");
    let t = fixture();
    append_to(
        &t,
        "crates/envcloak-client/Cargo.toml",
        "\n[package.metadata.zz]\nnonstandard_style = \"allow\"\n",
    );
    assert_fails(
        &t,
        "crates/envcloak-client/Cargo.toml sets `nonstandard_style`",
    );
    let t = fixture();
    add_file(
        &t,
        "crates/envcloak-client/build.rs",
        "fn main() { println!(\"cargo:rustc-env=ZZ_LINE=x\"); }\n",
    );
    assert_fails(
        &t,
        "crates/envcloak-client/build.rs sets an environment variable for `env!`",
    );
}

/// `Failure` named any way Rust allows is read as `Failure` (Codex review
/// of M2-RES1: `use Failure as failure; failure::new(..)` passed, the
/// alias reader taking capitalized names only): an alias in lower case,
/// a generic alias called with a turbofish, an alias in parentheses, and
/// a lower-case alias of `ExitToken` on a helper's parameter. A type
/// alias that names `Failure` some other way is refused.
///
/// Mutation checked: aliases read only when capitalized, as before: the
/// lower-case copies pass and this fails.
#[test]
fn an_alias_of_failure_in_any_form_is_read() {
    for body in [
        "use crate::fail::Failure as failure;\npub fn zz_a() -> failure { failure::new(\"TOKEN\", \"x\") }\n",
        "type ZzF<'a> = crate::fail::Failure;\npub fn zz_a() -> ZzF<'static> { ZzF::<'static>::new(\"TOKEN\", \"x\") }\n",
        "type ZzF = (crate::fail::Failure);\npub fn zz_a() -> ZzF { ZzF::new(\"TOKEN\", \"x\") }\n",
        "use crate::fail::ExitToken as tok;\n\
         pub fn zz_h(token: tok) -> Failure { Failure::new(token, \"x\") }\n\
         pub fn zz_g() -> Failure { zz_h(\"TOKEN\") }\n",
    ] {
        assert_counted(body, CLIENT_STUB);
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub trait ZzT { type A; }\nimpl ZzT for u8 { type A = crate::fail::Failure; }\ntype ZzF = <u8 as ZzT>::A;\n",
    );
    assert_fails(
        &t,
        "the type alias `ZzF` names `Failure` in a form the reader cannot read",
    );
}

/// The other readers take a value whole too: an MCP tool's `const TOOL`
/// that goes on past its literal is refused, a statement domain made with
/// `concat!` is read joined, and a `fn` named by a macro (which could be a
/// `fn token` the reader does not see) is refused.
///
/// Mutations checked: `const TOOL` read by its leading literal: the copy
/// passes and this fails. `concat!` left out of the statement-domain
/// reader: the domain is not seen and this fails. The macro `fn` check
/// removed: the copy passes and this fails.
#[test]
fn every_reader_takes_a_value_whole() {
    let t = fixture();
    edit(
        &t,
        "crates/envcloak-mcp/src/tools/list_secrets.rs",
        "const TOOL: &str = \"list_secrets\";",
        "const TOOL: &str = \"list_secrets\".split_at(4).1;",
    );
    assert_fails(&t, "`const TOOL` is not one string literal");
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub const ZZ_D: &str = concat!(\"envcloak-zz\", \"statement/1\");\n",
    );
    assert_fails(&t, "the code has `envcloak-zzstatement/1`");
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "macro_rules! zz_m { ($n:ident) => { pub fn $n(&self) -> &'static str { \"x\" } }; }\n\
         pub struct ZzS;\nimpl ZzS { zz_m!(token); }\n",
    );
    assert_fails(
        &t,
        "a `fn`, `const` or `static` named by a macro's metavariable",
    );
}

/// What `fn parse` is, and what it may call, is read as narrowly: a
/// method named `parse` is not the free `parse(..)` a usage line's match
/// calls (an imported one, whose messages are not read, is refused); a
/// macro in `fn parse` could give an error unseen, and is refused; and a
/// conversion a macro makes for a type it is given could be one into the
/// error, and is refused.
///
/// Mutations checked: methods taken for `fn parse`: the method's message
/// is read in place of the imported function's, the copy passes and this
/// fails. The macro check in `fn parse` removed: the macro's hidden
/// `return Err(..)` passes and this fails. The check of conversions made
/// by a macro removed: the copy passes and this fails.
#[test]
fn fn_parse_is_read_as_narrowly_as_a_token() {
    let t = fixture();
    add_file(
        &t,
        "crates/envcloak-client/src/zz_other.rs",
        "pub fn parse(a: &[&str]) -> Result<(), &'static str> { let _ = a; Err(ZZ_WHY) }\n\
         const ZZ_WHY: &str = \"pty_unavailable: x\";\n",
    );
    add_file(
        &t,
        CLIENT_STUB,
        "use crate::zz_other::parse;\npub struct Zz;\n\
         impl Zz { pub fn parse(a: &[&str]) -> Result<(), &'static str> { let _ = a; Err(\"bad option\") } }\n\
         pub fn zz_run(a: &[&str]) { match parse(a) { Ok(()) => {}, Err(why) => eprintln!(\"envcloak: {why}\") } }\n",
    );
    assert_fails(
        &t,
        "a usage line `envcloak: {why}` whose message the reader cannot trace",
    );
    let t = fixture();
    edit(
        &t,
        ADD_RS,
        "            return Err(\"an option is given twice\");",
        "            zz_bail!();",
    );
    append_to(
        &t,
        ADD_RS,
        "macro_rules! zz_bail { () => { return Err(zz_why()) }; }\nfn zz_why() -> &'static str { \"pty_unavailable: x\" }\n",
    );
    assert_fails(&t, "`fn parse` calls a macro (`zz_bail!(`)");
    let t = fixture();
    append_to(
        &t,
        RUN_RS,
        "macro_rules! zz_conv { ($t:ty) => { impl From<u8> for $t { fn from(_: u8) -> Self { ParseError::Usage(\"pty_unavailable: x\") } } }; }\n\
         zz_conv!(ParseError);\n",
    );
    assert_fails(&t, "a conversion a macro makes for a type it is given");
}

/// A directory of a crate's sources that cannot be listed is an error,
/// never one with nothing in it (`os.walk` skips it unless told). Where
/// this process can list a directory of mode 0 anyway (as root), the case
/// cannot be made and is skipped with a line.
///
/// Mutations checked: `os.walk` without `onerror`, as before, in the
/// failure-token reader, and in the statement-domain reader: each skips
/// the directory, its line is missing and this fails.
#[test]
fn a_source_directory_that_cannot_be_listed_fails() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = fixture();
    let dir = t.home().join("crates/envcloak-client/src/zz_hidden");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("mod.rs"),
        "pub fn zz() -> crate::fail::Failure { crate::fail::Failure::new(\"pty_unavailable\", \"x\") }\n",
    )
    .unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&dir).is_ok() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!(
            "a_source_directory_that_cannot_be_listed_fails: a directory of mode 0 lists here (root); skipped"
        );
        return;
    }
    let out = run(&t.home());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "expected a failure: {stderr}");
    for reader in ["`exit_token`", "`statement_domain`"] {
        assert!(
            stderr
                .lines()
                .any(|l| l.contains(reader) && l.contains("zz_hidden could not be listed")),
            "{reader}: {stderr}"
        );
    }
}

/// Unsupported code tokens are refused before the ASCII source readers
/// run. Text in comments/literals and omitted test modules stays supported.
#[test]
fn non_ascii_code_is_refused_without_rejecting_unicode_text() {
    for body in [
        r#"use crate::fail::Failure as Φ; pub fn make()->Φ { Φ::new("pty_unavailable", "") }"#,
        r#"type Φ=crate::fail::Failure; pub fn make()->Φ { Φ::new("pty_unavailable", "") }"#,
        r#"use crate::fail::Failure as AliasΦ; pub fn make()->AliasΦ { AliasΦ::new("pty_unavailable", "") }"#,
        r#"type AliasΦ=crate::fail::Failure; pub fn make()->AliasΦ { AliasΦ::new("pty_unavailable", "") }"#,
        r#"mod δοκιμή { pub use crate::fail::Failure; } pub fn make()->δοκιμή::Failure { δοκιμή::Failure::new("pty_unavailable", "") }"#,
        r#"use crate::fail::Failure as r#Φ; pub fn make()->r#Φ { r#Φ::new("pty_unavailable", "") }"#,
        r#"type é=crate::fail::Failure;"#,
        r#"type é=crate::fail::Failure;"#,
        r#"pub fn borrowed<'α>(value: &'α str)->&'α str { value }"#,
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, "unsupported non-ASCII Rust code");
    }
    for body in [
        r#"// Φ aliases remain text here.
        /* δοκιμή /* Φ */ */
        pub fn text()->&'static str { "Φ δοκιμή" }"#,
        r###"pub const TEXT: &str = r##"Φ δοκιμή"##; pub const LETTER: char = 'Φ';"###,
        r#"#[doc = "Φ"] pub fn make()->crate::fail::Failure { crate::fail::Failure::new("daemon_unavailable", "Φ") }"#,
        r#"#[cfg(test)] mod tests { type Φ=crate::fail::Failure; fn make()->Φ { Φ::new("pty_unavailable", "") } }"#,
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_passes(&t.home());
    }
}

const STATUS_RS: &str = "crates/envcloak-cli/src/cmd/status.rs";

/// `Failure::new` is read however the path before `new` is written
/// (verifier review of M2-RES1: `::envcloak_client::fail::Failure::new`,
/// `::envcloak_client::Fail::new`, `<::envcloak_client::fail::Failure>::new`
/// and `<Self>::new` in an `impl Failure` compiled and passed, reserved,
/// unreserved and run-time tokens alike, since the constructor was matched
/// by a pattern anchored at its start). Every `::new` is now read back to
/// the type it is called on: a leading `::`, a qualified path, `return`
/// before one, a turbofish, `Self` in an implementation of a trait for
/// `Failure`. A type the reader cannot tell is refused: a macro's
/// metavariable (`$t::new`, `<$t>::new`), a type a macro makes, and a
/// trait's `new` for `Failure` (`<Failure as T>::new`); so are a run-time
/// token and a function pointer however the path is written.
///
/// Mutation checked: the constructor matched forward from its start, as
/// in round 3 (`(?<![\w:])` before the path): the leading-`::` and
/// `<Self>` copies pass and this fails.
#[test]
fn a_constructor_is_read_however_its_path_is_written() {
    for body in [
        "\npub fn zz() -> envcloak_client::Failure { ::envcloak_client::fail::Failure::new(\"TOKEN\", \"x\") }\n",
        "\npub fn zz() -> envcloak_client::Failure { ::envcloak_client::Fail::new(\"TOKEN\", \"x\") }\n",
        "\npub fn zz() -> envcloak_client::Failure { <::envcloak_client::fail::Failure>::new(\"TOKEN\", \"x\") }\n",
        "\npub fn zz() -> envcloak_client::Failure { return <envcloak_client::Fail>::new(\"TOKEN\", \"x\"); }\n",
    ] {
        assert_counted(body, STATUS_RS);
    }
    for body in [
        "impl crate::fail::Failure { pub fn zz() -> Self { <Self>::new(\"TOKEN\", \"x\") } }\n",
        "pub trait ZzMk { fn mk() -> Self; }\n\
         impl ZzMk for ::std::string::String { fn mk() -> Self { Self::new() } }\n\
         impl ZzMk for crate::fail::Failure { fn mk() -> Self { <Self>::new(\"TOKEN\", \"x\") } }\n",
        "pub fn zz() -> std::collections::BTreeMap::<[u8; 2], u8> { let _ = crate::fail::Failure::new(\"TOKEN\", \"x\"); std::collections::BTreeMap::<[u8; 2], u8>::new() }\n",
    ] {
        assert_counted(body, CLIENT_STUB);
    }
    for (file, body, expect) in [
        (
            STATUS_RS,
            "\npub fn zz(t: &'static str) -> envcloak_client::Failure { ::envcloak_client::fail::Failure::new(t, \"x\") }\n",
            "a failure token the reader cannot read (`t`)",
        ),
        (
            STATUS_RS,
            "\npub fn zz() -> Option<envcloak_client::Failure> { Some(\"pty_unavailable\").map(|t| (t, \"x\")).map(|(t, m)| (::envcloak_client::Fail::new)(t, m)) }\n",
            "`Fail::new` is used other than called",
        ),
        (
            CLIENT_STUB,
            "macro_rules! zz_mk { ($t:ty) => { <$t>::new(\"pty_unavailable\", \"x\") }; }\n\
             pub fn zz() -> crate::fail::Failure { zz_mk!(crate::fail::Failure) }\n",
            "`$t::new` is called on a macro's metavariable",
        ),
        (
            CLIENT_STUB,
            "macro_rules! zz_mk { ($t:ident) => { $t::new(\"pty_unavailable\", \"x\") }; }\n\
             pub fn zz() -> crate::fail::Failure { use crate::fail::Failure; zz_mk!(Failure) }\n",
            "`$t::new` is called on a macro's metavariable",
        ),
        (
            CLIENT_STUB,
            "macro_rules! zz_ty { () => { crate::fail::Failure }; }\n\
             pub fn zz() -> crate::fail::Failure { <zz_ty!()>::new(\"pty_unavailable\", \"x\") }\n",
            "`<zz_ty!()>::new` is called on a type the reader cannot read",
        ),
        (
            CLIENT_STUB,
            "pub trait ZzNew { fn new(a: u8) -> Self; }\n\
             impl ZzNew for crate::fail::Failure { fn new(a: u8) -> Self { let _ = a; crate::fail::Failure::new(\"io\", \"x\") } }\n\
             pub fn zz() -> crate::fail::Failure { <crate::fail::Failure as ZzNew>::new(1) }\n",
            "`<Failure as ..>::new` calls a trait's `new` for `Failure`",
        ),
    ] {
        let t = fixture();
        if file == CLIENT_STUB {
            add_file(&t, file, body);
        } else {
            append_to(&t, file, body);
        }
        assert_fails(&t, expect);
    }
}

/// A function a trait declares or implements is called without its name
/// (`.into()` and `?` call `From::from`, a generic `T::new` a trait's
/// `new`), so its callers cannot be read: one that takes a `token` to
/// hand on is refused, `Failure`'s own `new` in fail.rs only where it is
/// inherent.
///
/// Mutation checked: the check of functions in traits removed: `from`
/// becomes a helper whose `.into()` callers are never read (the copy
/// fails only elsewhere, without this message), and a trait's `new` for
/// `Failure` in fail.rs is taken for `Failure::new`, its generic callers
/// unread: this fails.
#[test]
fn a_function_a_trait_calls_unnamed_takes_no_token() {
    for (file, body, name) in [
        (
            CLIENT_STUB,
            "impl From<&'static str> for crate::fail::Failure { fn from(token: &'static str) -> Self { Self::new(token, \"x\") } }\n\
             pub fn zz() -> crate::fail::Failure { \"pty_unavailable\".into() }\n",
            "from",
        ),
        (
            FAIL,
            "pub trait ZzCtor { fn new(token: ExitToken) -> Self; }\n\
             impl ZzCtor for Failure { fn new(token: ExitToken) -> Self { Failure::new(token, \"x\") } }\n\
             pub fn zz<T: ZzCtor>() -> T { T::new(\"pty_unavailable\") }\n",
            "new",
        ),
        (
            CLIENT_STUB,
            "pub trait ZzMk { fn mk(token: &'static str) -> crate::fail::Failure { crate::fail::Failure::new(token, \"x\") } }\n",
            "mk",
        ),
    ] {
        let t = fixture();
        if file == CLIENT_STUB {
            add_file(&t, file, body);
        } else {
            append_to(&t, file, body);
        }
        assert_fails(
            &t,
            &format!(
                "`fn {name}` takes a `token` to hand on inside a trait or a trait's implementation"
            ),
        );
    }
}

/// A name or a type a macro gives could be `Failure` under a name the
/// reader never sees: an import built from a metavariable (`use $p as
/// Q;`, `use .. Failure as $n;`), a type alias named by one or of one, a
/// type alias of a type a macro makes, and a constant named by one. They
/// are refused; an import through `$crate` is read.
///
/// Mutations checked: the checks of imports and type aliases built by
/// macros removed: the copies pass and this fails. `const` and `static`
/// left out of the metavariable-named items: the constant copy passes and
/// this fails.
#[test]
fn a_name_or_type_a_macro_gives_is_refused() {
    for (body, expect) in [
        (
            "macro_rules! zz_imp { ($n:ident) => { use crate::fail::Failure as $n; }; }\nzz_imp!(Q);\n\
             pub fn zz() -> Q { Q::new(\"pty_unavailable\", \"x\") }\n",
            "an import built from a macro's metavariable",
        ),
        (
            "macro_rules! zz_imp { ($p:path) => { use $p as Q; }; }\nzz_imp!(crate::fail::Failure);\n\
             pub fn zz() -> Q { Q::new(\"pty_unavailable\", \"x\") }\n",
            "an import built from a macro's metavariable",
        ),
        (
            "macro_rules! zz_al { ($t:ty) => { type Q = $t; }; }\nzz_al!(crate::fail::Failure);\n\
             pub fn zz() -> Q { Q::new(\"pty_unavailable\", \"x\") }\n",
            "the type alias `Q` is of a type a macro gives (`$t`)",
        ),
        (
            "macro_rules! zz_ty { () => { crate::fail::Failure }; }\ntype Q = zz_ty!();\n\
             pub fn zz() -> Q { Q::new(\"pty_unavailable\", \"x\") }\n",
            "the type alias `Q` is of a type a macro gives (`zz_ty!()`)",
        ),
        (
            "macro_rules! zz_al { ($n:ident) => { type $n = crate::fail::Failure; }; }\nzz_al!(Q);\n\
             pub fn zz() -> Q { Q::new(\"pty_unavailable\", \"x\") }\n",
            "a type alias named by a macro's metavariable",
        ),
        (
            "pub const ZZ_T: &str = \"io\";\n\
             mod zz_m { macro_rules! zz_c { ($n:ident) => { const $n: &str = \"pty_unavailable\"; }; }\n\
             zz_c!(ZZ_T); pub fn zz() -> crate::fail::Failure { crate::fail::Failure::new(ZZ_T, \"x\") } }\n",
            "a `fn`, `const` or `static` named by a macro's metavariable",
        ),
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, expect);
    }
    assert_counted(
        "macro_rules! zz_imp { () => { use $crate::fail::Failure as Qz; }; }\nzz_imp!();\n\
         pub fn zz() -> Qz { Qz::new(\"TOKEN\", \"x\") }\n",
        CLIENT_STUB,
    );
}

/// The compiler reads no Rust for a crate that the reader does not
/// (verifier review of M2-RES1: a `#[path]` module in another directory,
/// and a source directory that is a symbolic link, compiled and passed,
/// since the walk never reached their files). Refused: a `#[path]`
/// attribute (also under `cfg_attr`), a symbolic link under a `src/`
/// (to a directory or a file), a library or binary target whose file is
/// outside `src/`, a path dependency outside `crates/`, and a workspace
/// member outside `crates/` other than the canaries. Each is refused by
/// both readers that walk the sources.
///
/// Mutations checked: `#[path]` not refused: the first copy passes the
/// failure-token reader, and the statement-domain reader too, and this
/// fails. Symbolic links to directories left to `os.walk`, which passes
/// over them: the linked directory passes and this fails. The manifest
/// checks not called: the target, dependency and member copies pass and
/// this fails.
#[test]
fn the_compiler_reads_no_rust_the_reader_does_not() {
    let hidden = "pub fn h() -> envcloak_client::Failure { envcloak_client::Failure::new(\"pty_unavailable\", \"x\") }\n";
    for attr in [
        "#[path = \"../../gen/hidden.rs\"]",
        "#[cfg_attr(unix, path = \"../../gen/hidden.rs\")]",
    ] {
        let t = fixture();
        append_to(&t, STATUS_RS, &format!("\n{attr}\nmod hidden;\n"));
        add_file(&t, "crates/envcloak-cli/gen/hidden.rs", hidden);
        let out = run(&t.home());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{attr}: {stderr}");
        for reader in ["`exit_token`", "`statement_domain`"] {
            assert!(
                stderr.lines().any(|l| l.contains(reader)
                    && l.contains(
                        "a `#[path]` attribute compiles a file the reader does not walk to"
                    )),
                "{reader}, {attr}: {stderr}"
            );
        }
    }
    for (link, target, real) in [
        (
            "crates/envcloak-cli/src/linked",
            "../realmod",
            "crates/envcloak-cli/realmod/mod.rs",
        ),
        (
            "crates/envcloak-cli/src/linked.rs",
            "../realmod.rs",
            "crates/envcloak-cli/realmod.rs",
        ),
    ] {
        let t = fixture();
        add_file(&t, real, hidden);
        append_to(&t, "crates/envcloak-cli/src/main.rs", "mod linked;\n");
        std::os::unix::fs::symlink(target, t.home().join(link)).unwrap();
        let out = run(&t.home());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{link}: {stderr}");
        for reader in ["`exit_token`", "`statement_domain`"] {
            assert!(
                stderr.lines().any(
                    |l| l.contains(reader) && l.contains(&format!("{link} is a symbolic link"))
                ),
                "{reader}, {link}: {stderr}"
            );
        }
    }
    for (rel, text, expect) in [
        (
            "crates/envcloak-cli/Cargo.toml",
            "\n[lib]\npath = \"gen/lib.rs\"\n",
            "a target's file outside the crate's src/ (`gen/lib.rs`)",
        ),
        (
            "crates/envcloak-cli/Cargo.toml",
            "\n[[bin]]\nname = \"zz\"\npath = \"../envcloak-core/gen/zz.rs\"\n",
            "a target's file outside the crate's src/ (`../envcloak-core/gen/zz.rs`)",
        ),
        (
            "crates/envcloak-cli/Cargo.toml",
            "\n[target.'cfg(unix)'.dependencies]\nzz = { path = \"../../vendor/zz\" }\n",
            "a path outside crates/ (`../../vendor/zz`)",
        ),
    ] {
        let t = fixture();
        append_to(&t, rel, text);
        assert_fails(&t, expect);
    }
    let t = fixture();
    edit(
        &t,
        "Cargo.toml",
        "members = [\"crates/*\",",
        "members = [\"crates/*\", \"vendor/zz\",",
    );
    assert_fails(&t, "the workspace member `vendor/zz` is outside crates/");
}

/// The statement-domain reader reads every Rust file under `crates/`,
/// tests included, and refuses what it would not see: a domain in a file
/// `include_bytes!` brings in is read; `include!`, an `include_str!` of a
/// file outside the repository, `env!` of a variable Cargo does not set,
/// and a `#[path]` module are refused. Cargo's own variables
/// (`CARGO_BIN_EXE_<name>`, `CARGO_TARGET_TMPDIR`), which tests use,
/// pass.
///
/// Mutation checked: the text `include_bytes!` brings in left unread: the
/// domain in it is not seen and this fails.
#[test]
fn the_statement_domain_reader_reads_what_tests_bring_in() {
    let test_rs = "crates/envcloak-core/tests/zz_domain.rs";
    let t = fixture();
    add_file(
        &t,
        test_rs,
        "pub const D: &[u8] = include_bytes!(\"zz.bin\");\n",
    );
    // Made here, so this file's own literals name no domain.
    add_file(
        &t,
        "crates/envcloak-core/tests/zz.bin",
        &format!("envcloak-zz{}/1\n", "statement"),
    );
    assert_fails(&t, "the code has `envcloak-zzstatement/1`");
    for (body, expect) in [
        (
            "include!(\"zz.in\");\n",
            "`include!` brings in text from another file",
        ),
        (
            "pub const D: &str = include_str!(\"../../../../zz.txt\");\n",
            "of a file outside the repository",
        ),
        (
            "pub const D: &str = env!(\"ZZ_DOMAIN\");\n",
            "`env!` of a variable other than",
        ),
        (
            "#[path = \"../../zz.rs\"]\nmod zz;\n",
            "a `#[path]` attribute",
        ),
    ] {
        let t = fixture();
        add_file(&t, test_rs, body);
        assert_fails(&t, expect);
    }
    let t = fixture();
    add_file(
        &t,
        test_rs,
        "pub const A: &str = env!(\"CARGO_BIN_EXE_envcloak\");\npub const B: &str = env!(\"CARGO_TARGET_TMPDIR\");\n",
    );
    assert_passes(&t.home());
}

/// A placeholder right after `envcloak:` prints its value where a token
/// goes, with or without white space before it: padding (`{:>16}`) or the
/// value itself can give the space (verifier review of M2-RES1:
/// `envcloak:{:>16}: x` printed `envcloak:  pty_unavailable: x` and
/// passed). It is read, its value counted without the white space around
/// it; a value printed mid-line, not followed by `:`, counts by the token
/// it starts with when the reader can read it. A token put together from
/// pieces (`{}{}:`, `pty_{}:`) or a colon a value brings after `envcloak`
/// (`envcloak{}`) is refused. A count printed mid-line passes.
///
/// Mutation checked: placeholders read only after `envcloak:` and white
/// space, as before: the padded copy passes and this fails.
#[test]
fn a_placeholder_right_after_envcloak_is_read() {
    for body in [
        "pub fn d() { eprintln!(\"envcloak:{:>16}: x\", \"TOKEN\"); }\n",
        "pub fn d() { eprintln!(\"envcloak:{}: x\", \" TOKEN\"); }\n",
        "pub fn d() { eprintln!(\"! envcloak: {}\", \"TOKEN: x\"); }\n",
    ] {
        assert_counted(body, CLIENT_STUB);
    }
    for body in [
        "pub fn d() { eprintln!(\"envcloak: {}{}: x\", \"pty_\", \"unavailable\"); }\n",
        "pub fn d() { eprintln!(\"envcloak: pty_{}: x\", \"unavailable\"); }\n",
        "pub fn d() { eprintln!(\"envcloak{} x\", \": pty_unavailable:\"); }\n",
    ] {
        let t = fixture();
        add_file(&t, CLIENT_STUB, body);
        assert_fails(&t, "comes in pieces");
    }
    let t = fixture();
    add_file(
        &t,
        CLIENT_STUB,
        "pub fn d(n: usize) { eprintln!(\"[envcloak: {} bytes cut]\", n); }\n",
    );
    assert_passes(&t.home());
}
