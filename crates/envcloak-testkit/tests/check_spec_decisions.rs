//! `scripts/check-spec-decisions.py` (plan task M2-01) on the real SPEC and
//! on copies of it, each changed one way: it accepts SPEC v0.4, rewrapped
//! or not, and refuses the wording v0.4 replaced (gate b12 and the §6.8
//! worker sentence, F-74; the real-model release rule; the descriptor exec
//! of a bound Linux launch), wrapped or not and in any letter case, a
//! release that rests on EnvCloak's own `envcloak` executable or binary or
//! on any other reading of the requester's code, in the reviewers' other
//! words too (CR-1), a missing or weakened tool allowlist or per-call grant
//! check (D-30, D-31), a missing or weakened standing-approval clause
//! (D-10, D-11) or launch-binding clause (D-33, D-36, gate 39), including
//! what a bound launch does not bind, where a sealed copy cannot run and
//! where the sign-in driver starts from, a decision whose edit is gone, a
//! decided sentence twice, an em dash and an older version. With
//! `--pr-files` it refuses a SPEC pull request that changes any file but
//! docs/SPEC.md.
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

// --- Replaced wording in any letter case ----------------------------------

#[test]
fn the_old_b12_sentence_capitalized_as_a_new_bullet_fails() {
    // The verifier's case: the old gate as a bullet of its own, its first
    // word capitalized, beside the new b12.
    let t = fixture();
    let text = spec(&t);
    let start = text.find(NEW_B12).unwrap();
    let end = start + text[start..].find('\n').unwrap();
    let changed = format!(
        "{}\n- No trust, refresh or session state from the worker remains usable.{}",
        &text[..end],
        &text[end..]
    );
    std::fs::write(t.home().join(SPEC), changed).unwrap();
    assert_fails(&t.home(), &[], "the SPEC still holds the old gate b12");
}

#[test]
fn the_old_worker_sentence_without_its_lead_fails() {
    let t = fixture();
    edit(
        &t,
        NEW_WORKER,
        &format!(
            "{NEW_WORKER} No trust, refresh or session state from the worker outlives the attempt."
        ),
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the old §6.8 worker sentence",
    );
}

// --- Security clauses (Codex review of PR #14) ----------------------------

/// §10b: which agent identities a standing approval can name (D-10).
const STANDING_IDENTITY: &str = "Only a builtin catalog match on the executable path or code signature qualifies; an agent launched by an interpreter, recognized only by a user extension, or asserted by its name or markers is refused (`identity_not_standing_capable`).";
/// §10b: which keys a standing approval can cover (D-10, D-11).
const STANDING_KEYS: &str = "It covers test-classified keys only; live keys, and keys classified `unknown`, are never standing.";
/// §6.6: a bound Linux launch runs the sealed copy it checked (D-33).
const LINUX_SEALED: &str = "A file can be rewritten in place after any check of it, so on Linux a `bound` launch never runs from its file: the daemon copies the executable, through the descriptor it checked, into a sealed in-memory file (a memfd sealed against writing, growing and shrinking), computes the identity over that sealed copy and compares it with the record, and the runner executes the copy (`execveat`), so the bytes that run are the bytes that were hashed, whatever happens to the file afterwards.";
/// §6.6: macOS checks the suspended child before it runs (D-33).
const MACOS_SUSPENDED: &str = "On macOS the runner starts the checked path suspended, the daemon compares the suspended child's code directory hash with the record, and the child runs only if they match.";
/// §6.6: the daemon's own modes run from a sealed copy (D-36).
const DAEMON_COPY: &str = "On Linux the daemon starts them from a sealed in-memory copy of that `envcloak`, made and hashed once when the daemon starts, so a change to the file after the daemon started never reaches a process that receives a value, and an upgraded `envcloak` takes effect when the daemon restarts;";
/// Gate 39: only the registered launch, as checked, receives the key.
const GATE_39_LAUNCH: &str = "Only a managed server's registered launch receives its key: a launch whose executable was replaced is refused, and a `bound` launch whose executable is rewritten in place after the daemon's last check runs the checked image, never the rewritten one.";

/// Each clause removed, then each weakened one way, fails with its name.
fn assert_each_change_fails(name: &str, clause: &str, weakened: &[(&str, &str)]) {
    let t = fixture();
    edit(&t, &format!(" {clause}"), "");
    assert_fails(&t.home(), &[], &format!("{name}: found 0 times"));
    for (from, to) in weakened {
        assert_eq!(clause.matches(from).count(), 1, "{from:?}");
        let t = fixture();
        edit(&t, clause, &clause.replacen(from, to, 1));
        assert_fails(&t.home(), &[], &format!("{name}: found 0 times"));
    }
}

#[test]
fn a_standing_approval_for_interpreter_extension_or_asserted_agents_fails() {
    // Codex's case: the identity rule removed; and each excluded kind of
    // match let back in.
    assert_each_change_fails(
        "§10b standing identity (D-10)",
        STANDING_IDENTITY,
        &[
            ("an agent launched by an interpreter, ", ""),
            (" recognized only by a user extension, or", ""),
            (", or asserted by its name or markers", ""),
            (
                "executable path or code signature",
                "executable path, name or code signature",
            ),
        ],
    );
}

#[test]
fn a_standing_approval_for_live_or_unknown_keys_or_other_subjects_fails() {
    assert_each_change_fails(
        "§10b standing keys (D-10, D-11)",
        STANDING_KEYS,
        &[(
            "live keys, and keys classified `unknown`, are",
            "live keys are",
        )],
    );
    assert_each_change_fails(
        "§10b standing subjects (D-10)",
        "A standing approval never covers a terminal or unknown subject.",
        &[(" or unknown", "")],
    );
}

#[test]
fn a_bound_linux_launch_that_runs_from_its_file_fails() {
    // Codex's case: Linux's binding of what runs to what was checked
    // removed; and the descriptor exec that a rewrite in place can beat.
    assert_each_change_fails(
        "§6.6 Linux runs the sealed copy it checked (D-33)",
        LINUX_SEALED,
        &[
            ("never runs from its file", "runs from its file"),
            (
                " (a memfd sealed against writing, growing and shrinking)",
                "",
            ),
            (
                "computes the identity over that sealed copy",
                "computes the identity over the file",
            ),
        ],
    );
    let t = fixture();
    edit(
        &t,
        LINUX_SEALED,
        "What runs is the file: on Linux the runner executes the very descriptor the daemon checked (`execveat`), after re-reading its stamp.",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the file's own descriptor as the binding of a bound Linux launch (D-33)",
    );
}

#[test]
fn a_macos_launch_that_runs_unchecked_fails() {
    assert_each_change_fails(
        "§6.6 macOS checks the suspended child (D-33)",
        MACOS_SUSPENDED,
        &[
            (", and the child runs only if they match", ""),
            (" suspended,", ","),
        ],
    );
}

#[test]
fn a_launch_bound_or_standing_without_the_check_fails() {
    assert_each_change_fails(
        "§6.6 nothing else is bound (D-33)",
        "A launch that cannot run this way is not `bound`.",
        &[("is not `bound`", "is `bound`")],
    );
    assert_each_change_fails(
        "§6.6 only bound launches are standing (D-33)",
        "Only `bound` launches can have standing approvals (§10b).",
        &[("Only `bound` launches", "Launches")],
    );
}

#[test]
fn the_daemons_own_modes_run_from_the_file_fails() {
    assert_each_change_fails(
        "§6.6 the daemon's own modes run from a sealed copy (D-36)",
        DAEMON_COPY,
        &[("never reaches", "reaches")],
    );
}

#[test]
fn gate_39_without_its_launch_binding_fails() {
    assert_each_change_fails(
        "gate 39 launch binding (D-33)",
        GATE_39_LAUNCH,
        &[(
            "runs the checked image, never the rewritten one",
            "is refused when the change is seen",
        )],
    );
}

// --- Review of PR #14, round 3 --------------------------------------------

#[test]
fn a_release_resting_on_the_requesters_code_in_other_words_fails() {
    // The verifier's paraphrases, each outside rule 6: EnvCloak's own
    // `envcloak` without backticks, the bridge's code signature, the peer
    // being the `envcloak` binary, and the requester's executable SHA-256;
    // and `envcloak mcp`'s cdhash.
    for (wording, name) in [
        (
            "The bridge's executable must be EnvCloak's own envcloak executable.",
            "a release that rests on EnvCloak's own `envcloak` executable or binary (CR-1)",
        ),
        (
            "The values go to the bridge only when the bridge's code signature equals the one EnvCloak ships.",
            "a release that rests on the requester's code (CR-1)",
        ),
        (
            "The values go only if the peer process is the envcloak binary installed beside envcloakd.",
            "a release that rests on the requester being EnvCloak's `envcloak` (CR-1)",
        ),
        (
            "The values go only to a requester whose executable SHA-256 equals the anchor.",
            "a release that rests on the requester's code (CR-1)",
        ),
        (
            "The values go only when `envcloak mcp`'s cdhash matches the anchor's.",
            "a release that rests on the requester's code (CR-1)",
        ),
    ] {
        let t = fixture();
        edit(&t, DAEMON_STARTED, &format!("{DAEMON_STARTED} {wording}"));
        assert_fails(&t.home(), &[], &format!("the SPEC still holds {name}"));
    }
}

/// §6.6: what a `bound` launch does not bind (D-33).
const MAIN_EXECUTABLE_ONLY: &str = "A `bound` launch binds the server's main executable only, not the dynamic loader, the shared libraries it loads or anything they load, so a program running as you that can write those files (as in a Homebrew or Linuxbrew prefix) can change what the server runs; the launch receipt says so.";
/// §6.6: a program that cannot run from the copy is not run from its file.
const NEVER_FROM_FILE: &str = "A program that reads its own path only while it runs (through `/proc/self/exe`) cannot be recognised before it starts: from the copy it may fail to start, and it is then never started from its file instead.";
/// §6.6: where a sealed memfd cannot be executed, no managed servers.
const NO_SEALED_EXEC: &str = "On a system whose kernel or security policy refuses to execute a sealed memfd (for example `vm.memfd_noexec=2`), the daemon cannot start its own runner or relay either (below), so managed servers are unavailable there: a request for one is refused with `runner_unavailable`, and the server is reported as manual.";
/// §6.8: where the sign-in reaper and driver are started from.
const DRIVER_START: &str = "The daemon starts the reaper and the driver from its own executable as it was when the daemon started, never from a path it reads again: on Linux from a sealed in-memory copy of `envcloakd` made then, as it starts its own modes of `envcloak` (§6.6); on macOS from a suspended start whose code directory hash must equal its own.";

#[test]
fn a_bound_launch_claimed_to_bind_its_libraries_fails() {
    assert_each_change_fails(
        "§6.6 a bound launch binds the main executable only (D-33)",
        MAIN_EXECUTABLE_ONLY,
        &[
            (
                " only, not the dynamic loader, the shared libraries it loads or anything they load",
                "",
            ),
            ("; the launch receipt says so", ""),
        ],
    );
}

#[test]
fn a_launch_that_fails_from_the_copy_run_from_its_file_fails() {
    assert_each_change_fails(
        "§6.6 never started from its file instead (D-33)",
        NEVER_FROM_FILE,
        &[(
            "it is then never started from its file instead",
            "it is then started from its file instead",
        )],
    );
}

#[test]
fn a_fallback_where_a_sealed_copy_cannot_run_fails() {
    // The verifier's case: the old text promised a `checked_at_rest`
    // fallback on such a system, where the runner itself cannot start.
    assert_each_change_fails(
        "§6.6 no sealed copy, no managed servers (D-36)",
        NO_SEALED_EXEC,
        &[(
            "so managed servers are unavailable there: a request for one is refused with `runner_unavailable`, and the server is reported as manual",
            "so its launches are `checked_at_rest`",
        )],
    );
}

#[test]
fn a_sign_in_driver_started_from_a_path_read_again_fails() {
    assert_each_change_fails(
        "§6.8 the reaper and driver start from the daemon's own executable (D-25, D-36)",
        DRIVER_START,
        &[
            (", never from a path it reads again", ""),
            (
                "from a sealed in-memory copy of `envcloakd` made then",
                "from the `envcloakd` file",
            ),
        ],
    );
}
