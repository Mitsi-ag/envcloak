//! `scripts/check-spec-decisions.py` (plan task M2-01) on the real SPEC and
//! on copies of it, each changed one way: it accepts SPEC v0.4, rewrapped
//! or not, and refuses the wording v0.4 replaced (gate b12 and the §6.8
//! worker sentence, F-74; the real-model release rule), wrapped or not, a
//! release that rests on EnvCloak's own `envcloak` executable or binary or
//! on any other reading of the requester's code (CR-1), a missing or
//! weakened tool allowlist or per-call grant check (D-30, D-31), a decision
//! whose edit is gone, a decided sentence twice, an em dash and an older
//! version. With `--pr-files` it refuses a SPEC pull request that changes
//! any file but docs/SPEC.md.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SPEC: &str = "docs/SPEC.md";

/// The b12 gate of v0.3.1, which v0.4 replaced.
const OLD_B12: &str = "After an attempt, and across lock, expiry and daemon restart, no trust, refresh or session state from the worker remains usable.";
/// The start of the b12 gate of v0.4.
const NEW_B12: &str = "After an attempt, and across lock, expiry and daemon restart, EnvCloak retains no reusable worker-owned trust";
/// The §6.8 worker sentence of v0.3.1.
const OLD_WORKER: &str =
    "In M2b no trust, refresh or session state from the worker outlives the attempt.";
/// The start of its v0.4 replacement.
const NEW_WORKER: &str = "In M2b, after an attempt EnvCloak retains no reusable worker-owned trust, refresh or session state: the worker process, its profile and its control channel end with the attempt.";

fn fixture() -> TestHome {
    let t = TestHome::new();
    let dest = t.home().join(SPEC);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::copy(repo_root().join(SPEC), dest).unwrap();
    t
}

fn spec(t: &TestHome) -> String {
    std::fs::read_to_string(t.home().join(SPEC)).unwrap()
}

/// Replaces the one occurrence of `from` in the copy with `to`.
fn edit(t: &TestHome, from: &str, to: &str) {
    let text = spec(t);
    assert_eq!(text.matches(from).count(), 1, "{from:?}");
    std::fs::write(t.home().join(SPEC), text.replacen(from, to, 1)).unwrap();
}

fn run(root: &Path, extra: &[&str]) -> Output {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    t.apply(&mut cmd)
        .arg(repo_root().join("scripts/check-spec-decisions.py"))
        .arg("--root")
        .arg(root)
        .args(extra)
        .output()
        .unwrap()
}

fn assert_passes(root: &Path, extra: &[&str]) {
    let out = run(root, extra);
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("check-spec-decisions: ok"));
}

fn assert_fails(root: &Path, extra: &[&str], expect_in_message: &str) {
    let out = run(root, extra);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "expected a failure: {stderr}");
    assert!(
        stderr.contains(expect_in_message),
        "expected {expect_in_message:?} in: {stderr}"
    );
}

#[test]
fn the_real_spec_passes() {
    assert_passes(&repo_root(), &[]);
}

#[test]
fn a_copy_of_the_spec_passes() {
    assert_passes(&fixture().home(), &[]);
}

#[test]
fn the_old_b12_sentence_fails() {
    let t = fixture();
    let text = spec(&t);
    let start = text.find(NEW_B12).unwrap();
    let end = start + text[start..].find('\n').unwrap();
    let changed = format!("{}{}{}", &text[..start], OLD_B12, &text[end..]);
    std::fs::write(t.home().join(SPEC), changed).unwrap();
    assert_fails(&t.home(), &[], "the SPEC still holds the old gate b12");
    assert_fails(&t.home(), &[], "gate b12 (F-74): found 0 times");
}

#[test]
fn the_old_worker_sentence_fails() {
    let t = fixture();
    edit(&t, NEW_WORKER, OLD_WORKER);
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the old §6.8 worker sentence",
    );
}

#[test]
fn a_release_resting_on_envcloaks_own_executable_fails() {
    let t = fixture();
    edit(
        &t,
        "A covered request's values are never returned to the requesting process:",
        "The requesting process must be one whose code comes from EnvCloak's own `envcloak` executable, and a covered request's values are never returned to the requesting process:",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds a release that rests on EnvCloak's own `envcloak` executable",
    );
    assert_fails(
        &t.home(),
        &[],
        "§10b rule 6 for managed projects (CR-1): found 0 times",
    );
}

#[test]
fn a_decision_whose_edit_is_gone_fails() {
    let t = fixture();
    let text = spec(&t).replace("`pty_unavailable`", "`pty_missing`");
    std::fs::write(t.home().join(SPEC), text).unwrap();
    assert_fails(&t.home(), &[], "D-19: the SPEC lacks '`pty_unavailable`'");
}

#[test]
fn a_decided_sentence_twice_fails() {
    let t = fixture();
    let sentence = "The daemon sends a value or captured session state to a process other than an `envcloak run` in inject mode only when it started that process itself: EnvCloak's runner for a managed server, its HTTP relay for a bridged server, and its browser supervisor for a sign-in operation, each over an inherited pipe.";
    edit(&t, sentence, &format!("{sentence} {sentence}"));
    assert_fails(
        &t.home(),
        &[],
        "§4.4 daemon-started recipients (CR-1): found 2 times",
    );
}

#[test]
fn an_em_dash_fails() {
    let t = fixture();
    edit(
        &t,
        "## 2. The problem",
        "## 2. The problem \u{2014} and why it matters",
    );
    assert_fails(&t.home(), &[], "the SPEC still holds an em dash");
}

#[test]
fn an_older_spec_version_fails() {
    let t = fixture();
    edit(&t, "Status: draft v0.4 ", "Status: draft v0.3.1 ");
    assert_fails(&t.home(), &[], "the status line does not say draft v0.4");
}

/// The §4.4 sentence on daemon-started recipients (CR-1).
const DAEMON_STARTED: &str = "The daemon sends a value or captured session state to a process other than an `envcloak run` in inject mode only when it started that process itself: EnvCloak's runner for a managed server, its HTTP relay for a bridged server, and its browser supervisor for a sign-in operation, each over an inherited pipe.";

/// §6.8's grant check on every browser tool call (D-31).
const PER_CALL_CHECK: &str = "The supervisor checks the grant with the daemon on every tool call, not only when a context is first handed over.";

#[test]
fn the_old_b12_sentence_wrapped_over_two_lines_fails() {
    let t = fixture();
    let text = spec(&t);
    let start = text.find(NEW_B12).unwrap();
    let end = start + text[start..].find('\n').unwrap();
    let wrapped = OLD_B12.replacen(" session state", "\n  session state", 1);
    let changed = format!("{}{}{}", &text[..start], wrapped, &text[end..]);
    std::fs::write(t.home().join(SPEC), changed).unwrap();
    assert_fails(&t.home(), &[], "the SPEC still holds the old gate b12");
}

#[test]
fn a_decided_sentence_wrapped_over_two_lines_passes() {
    let t = fixture();
    edit(
        &t,
        DAEMON_STARTED,
        &DAEMON_STARTED.replacen(" captured session", "\n  captured session", 1),
    );
    assert_passes(&t.home(), &[]);
}

#[test]
fn a_release_resting_on_envcloaks_own_binary_fails() {
    let t = fixture();
    edit(
        &t,
        DAEMON_STARTED,
        &format!(
            "{DAEMON_STARTED} The requesting process must be EnvCloak's own `envcloak` binary."
        ),
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds a release that rests on EnvCloak's own `envcloak` executable or binary",
    );
}

#[test]
fn a_release_resting_on_the_requesters_code_fails() {
    for wording in [
        "The requester's binary must match the anchor.",
        "A value is released when the requesting process's code identity matches EnvCloak's.",
        "The caller's executable is checked first, and the value goes only if the client code is EnvCloak's.",
    ] {
        let t = fixture();
        edit(&t, DAEMON_STARTED, &format!("{DAEMON_STARTED} {wording}"));
        assert_fails(
            &t.home(),
            &[],
            "the SPEC still holds a release that rests on the requester's code (CR-1)",
        );
    }
}

#[test]
fn the_grant_check_on_every_tool_call_removed_fails() {
    let t = fixture();
    edit(&t, &format!(" {PER_CALL_CHECK}"), "");
    assert_fails(
        &t.home(),
        &[],
        "§6.8 grant check on every tool call (D-31): found 0 times",
    );
    let t = fixture();
    edit(
        &t,
        PER_CALL_CHECK,
        "The supervisor checks the grant with the daemon when a context is first handed over.",
    );
    assert_fails(
        &t.home(),
        &[],
        "§6.8 grant check on every tool call (D-31): found 0 times",
    );
}

#[test]
fn a_wider_tool_allowlist_fails() {
    let t = fixture();
    edit(
        &t,
        "; no tool that runs code in the helper process, uploads a local file, installs a browser or belongs to an optional capability group;",
        ";",
    );
    assert_fails(&t.home(), &[], "§6.8 tool allowlist (D-30): found 0 times");
}

#[test]
fn the_old_real_model_release_rule_fails() {
    let t = fixture();
    let text = spec(&t);
    let start = text
        .find("Before a milestone is released, each tier-1 host makes at least 20 real-model runs")
        .unwrap();
    let end = start + text[start..].find('\n').unwrap();
    let old = "a milestone is released only when, over at least 20 real-model runs per tier-1 host, the host used EnvCloak instead of reading `.env` or typing a password in at least 80% of runs with no fixture found in any run; a host below that is published as \"not reliably used\" in the compatibility matrix.";
    let changed = format!("{}{}{}", &text[..start], old, &text[end..]);
    std::fs::write(t.home().join(SPEC), changed).unwrap();
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the old gate 41 release rule",
    );
    assert_fails(
        &t.home(),
        &[],
        "D-13: the SPEC lacks 'A fixture found in any of those runs holds the release'",
    );
}

fn git(t: &TestHome, repo: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    let out = t
        .apply(&mut cmd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with a base commit holding the real SPEC and an IPC.md, a
/// branch `spec` that changes the SPEC alone, and a branch `mixed` that
/// changes it and IPC.md.
fn pr_repo() -> TestHome {
    let t = fixture();
    let repo = t.home();
    std::fs::write(repo.join("docs/IPC.md"), "# protocol\n").unwrap();
    git(&t, &repo, &["init", "-q", "-b", "base"]);
    git(&t, &repo, &["add", "docs"]);
    git(&t, &repo, &["commit", "-q", "-m", "base"]);
    git(&t, &repo, &["checkout", "-q", "-b", "spec"]);
    let text = spec(&t);
    std::fs::write(repo.join(SPEC), format!("{text}\nA new paragraph.\n")).unwrap();
    git(&t, &repo, &["commit", "-q", "-a", "-m", "spec"]);
    git(&t, &repo, &["checkout", "-q", "-b", "mixed"]);
    std::fs::write(repo.join("docs/IPC.md"), "# protocol, changed\n").unwrap();
    git(&t, &repo, &["commit", "-q", "-a", "-m", "mixed"]);
    t
}

#[test]
fn a_spec_pull_request_that_changes_the_spec_alone_passes() {
    let t = pr_repo();
    assert_passes(&t.home(), &["--pr-files", "base", "spec"]);
}

#[test]
fn a_spec_pull_request_that_changes_another_file_fails() {
    let t = pr_repo();
    assert_fails(
        &t.home(),
        &["--pr-files", "base", "mixed"],
        "the SPEC pull request changes docs/IPC.md, docs/SPEC.md, not docs/SPEC.md alone",
    );
    assert_fails(
        &t.home(),
        &["--pr-files", "base", "no-such-branch"],
        "git diff base...no-such-branch failed",
    );
}
