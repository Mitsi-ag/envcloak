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
//! decided sentence twice, an em dash and an older version. From SPEC
//! v0.4.1 (task M3-01) it also refuses the M3 wording v0.4.1 replaced (the
//! macOS 14 floor, a screen lock any program could report, the old §4.4
//! app list) and a missing or weakened M3 clause (§4.4's new crossings, the
//! app role's conditions, the signed proof and the first unlocker). With
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
    edit(&t, "Status: draft v0.4.1 ", "Status: draft v0.4 ");
    assert_fails(&t.home(), &[], "the status line does not say draft v0.4.1");
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

// --- M2-RES1 (residuals of M2-01) ------------------------------------------

/// The end of §10b rule 6, after which the review added its paraphrases.
const RULE_6_END: &str = "A launch whose code EnvCloak can check only at rest (interpreter scripts, package runners) gets once and session approvals, never standing approvals.";

/// The review's paraphrases of a release resting on the requester's code
/// (M2R-4), each added after rule 6 of a copy: each passed before.
///
/// Mutation checked: the four paraphrase patterns removed and `RESTS_ON`
/// without `satisfies` and `hashes to`, as before: every copy passes and
/// this fails.
#[test]
fn a_release_resting_on_the_requesters_code_in_the_reviews_paraphrases_fails() {
    for (wording, name) in [
        (
            "The daemon releases the values only to a bridge signed by EnvCloak's Developer ID.",
            "a release that rests on who signed the requester (CR-1)",
        ),
        (
            "Values go to the requesting process only when its executable hashes to the envcloak release digest.",
            "a release that rests on the requester's code, named later in the sentence (CR-1)",
        ),
        (
            "The daemon checks that the client process runs the envcloak binary before it releases a value.",
            "a release that rests on the requester running the `envcloak` binary (CR-1)",
        ),
        (
            "The values go only if /proc/<pid>/exe of the peer is the installed envcloak.",
            "a release that rests on the requester's `/proc/<pid>/exe` (CR-1)",
        ),
        (
            "Values are released to an mcp-bridge whose code signature satisfies EnvCloak's designated requirement.",
            "a release that rests on the requester's code (CR-1)",
        ),
    ] {
        let t = fixture();
        edit(&t, RULE_6_END, &format!("{RULE_6_END} {wording}"));
        assert_fails(&t.home(), &[], &format!("the SPEC still holds {name}"));
    }
}

/// The SPEC wording items of M2-RES1, each required: the relay's host rule
/// as D-18 has it (M2R-5), dev sign-in unavailable without a sealed copy
/// (M2R-6), and reclassifying towards `test` or `unknown` as a proven
/// write in §4.3 and §10b (M2R-8). The old relay wording is refused.
#[test]
fn the_m2_res1_wording_is_required() {
    let t = fixture();
    edit(
        &t,
        "sends it, when the provider is known, only to a host within that provider's `allowed_hosts`,",
        "requires a known provider's `allowed_hosts`,",
    );
    assert_fails(
        &t.home(),
        &[],
        "§6.6 the relay's host rule (D-18): found 0 times",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the relay requiring a known provider for any HTTP server (D-18)",
    );
    for (sentence, name) in [
        (
            " Where that sealed copy cannot be made or executed (for example under `vm.memfd_noexec=2`, as for managed servers in §6.6), dev sign-in is unavailable: a sign-in request is refused with `runner_unavailable`, and `envcloak agents status` and the sign-in tool's result say so.",
            "§6.8 no sealed copy, no dev sign-in (D-36)",
        ),
        (
            ", and reclassifying an item towards `test` or `unknown` (§10b)",
            "§4.3 reclassification is passphrase-proven (M2-13)",
        ),
        (
            ";\n- reclassifying an item towards `test` or `unknown` (M2), which loosens the live-key guard and, towards `test`, what a standing approval can cover.",
            "§10b reclassification needs a proof (M2-13)",
        ),
    ] {
        let t = fixture();
        edit(
            &t,
            sentence,
            if sentence.starts_with(';') { "." } else { "" },
        );
        assert_fails(&t.home(), &[], &format!("{name}: found 0 times"));
    }
}

// --- SPEC v0.4.1, the M3 build decisions (M3 plan, task M3-01) ------------

/// §4.4's app-to-daemon crossings in v0.4.1.
const APP_TO_DAEMON: &str = "App to daemon: one HPKE-sealed VMK per unlock; the two public keys (`unlock` and `approve`) of a new Secure Enclave unlocker; signed approval, write, unlocker, reveal, policy and device statements; values typed into the paste sheet and replacement values, each sealed to a daemon ephemeral key.";
/// §4.4's app-to-daemon crossings in v0.4, before M3-01.
const OLD_APP_TO_DAEMON: &str = "App to daemon: one HPKE-sealed VMK per unlock; signed approval, policy, device and reveal statements; values typed into the paste sheet, sealed to a daemon ephemeral key.";
/// §4.4's daemon-to-app crossings in v0.4.1.
const DAEMON_TO_APP: &str = "Daemon to app: envelopes (ciphertext); approval request descriptors (metadata only); audit entries (metadata only, with command lines masked as the audit log keeps them); the paste and reveal requests the CLI filed (`envcloak add --ask`, `envcloak reveal`), metadata only, with the requester's evidence; reveal values sealed to an app ephemeral key after a signed reveal statement.";

/// The plan's mutation: §4.4's list left without the new crossings (the
/// v0.4 bullet put back, or the daemon-to-app additions dropped) fails the
/// wording check, and so does each new crossing removed or weakened.
///
/// Mutation checked: the two §4.4 entries dropped from REQUIRED and the
/// old list from FORBIDDEN: the v0.4 bullet passes, and this test fails.
#[test]
fn a_44_list_without_the_new_crossings_fails() {
    let t = fixture();
    edit(&t, APP_TO_DAEMON, OLD_APP_TO_DAEMON);
    assert_fails(&t.home(), &[], "§4.4 app to daemon (M3-01): found 0 times");
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the old app-to-daemon list (M3-01)",
    );
    assert_each_change_fails(
        "§4.4 app to daemon (M3-01)",
        APP_TO_DAEMON,
        &[
            (
                " the two public keys (`unlock` and `approve`) of a new Secure Enclave unlocker;",
                "",
            ),
            (" write, unlocker,", ""),
            (" and replacement values, each", ""),
        ],
    );
    assert_each_change_fails(
        "§4.4 daemon to app (M3-01)",
        DAEMON_TO_APP,
        &[
            (
                " audit entries (metadata only, with command lines masked as the audit log keeps them);",
                "",
            ),
            (
                " the paste and reveal requests the CLI filed (`envcloak add --ask`, `envcloak reveal`), metadata only, with the requester's evidence;",
                "",
            ),
        ],
    );
}

/// §12's floor is macOS 26 (D3-04), and "macOS 14" is gone from the SPEC.
///
/// Mutation checked: the "macOS 14" pattern dropped from FORBIDDEN: the
/// second case passes, and this test fails.
#[test]
fn the_macos_14_floor_fails() {
    let t = fixture();
    edit(
        &t,
        "SwiftUI, macOS 26 or later, Swift 6.",
        "SwiftUI, macOS 14 or later, Swift 6.",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the macOS 14 floor (D3-04)",
    );
    assert_fails(
        &t.home(),
        &[],
        "§12 the macOS 26 floor (D3-04): found 0 times",
    );
    assert_fails(&t.home(), &[], "D3-04: the SPEC lacks");
    let t = fixture();
    edit(
        &t,
        "Secure Enclave and LocalAuthentication are used from Swift in the app.",
        "Secure Enclave and LocalAuthentication are used from Swift in the app, on macOS 14 and later.",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the macOS 14 floor (D3-04)",
    );
}

/// D3-06's conditions on the app's peer, its verdict per connection, and a
/// peer that fails them kept a client peer (gate 22), each required whole.
///
/// Mutation checked: the three §4.3 entries dropped from REQUIRED: a
/// weakened clause passes, and this test fails.
#[test]
fn the_app_roles_conditions_are_required() {
    assert_each_change_fails(
        "§4.3 the app role's runtime conditions (D3-06)",
        "The peer must also run with the hardened runtime flag and carry neither `com.apple.security.get-task-allow` nor any of the hardened runtime's exception entitlements (`com.apple.security.cs.allow-jit`, `allow-unsigned-executable-memory`, `allow-dyld-environment-variables`, `disable-library-validation`, `disable-executable-page-protection` and `debugger`), since each of them lets another process run code inside the signed app.",
        &[
            ("run with the hardened runtime flag and ", ""),
            (" `allow-dyld-environment-variables`,", ""),
            ("neither `com.apple.security.get-task-allow` nor ", ""),
        ],
    );
    assert_each_change_fails(
        "§4.3 the app role's verdict per connection (D3-06)",
        "The daemon takes this verdict at the connection's first `app` request and keeps it for that connection alone, which it closes unanswered once another process sends on it",
        &[("for that connection alone", "for that process")],
    );
    assert_each_change_fails(
        "§4.3 a peer that fails is a client peer (D3-06, gate 22)",
        "From M3, a peer that does not meet every condition of the `app` role is a client peer, and its `app` requests are rejected and audited the same way (gate 22).",
        &[("every condition", "the requirement")],
    );
}

/// The signed form of a proof (an enrolled key, over the statement the
/// daemon rebuilds), the first unlocker approved with the passphrase, and
/// which caller gives which proof, each required whole; the v0.4 rule that
/// took every proof from a terminal subject is refused.
///
/// Mutation checked: the three §10b entries dropped from REQUIRED: a
/// weakened clause passes, and this test fails.
#[test]
fn the_signed_proof_and_the_first_unlocker_are_required() {
    assert_each_change_fails(
        "§10b the signed form of a proof (D3-10)",
        "From the `app` role (§4.3, M3): a P-256 ECDSA signature by the `approve` key of a Secure Enclave unlocker enrolled in the vault, over the SHA-256 digest of the canonical statement as a prehash, sent as the 64-byte raw `r || s`; the daemon rebuilds the statement from its own record, verifies the signature with that unlocker's public key, and refuses a key that is not enrolled or was removed.",
        &[
            (" enrolled in the vault", ""),
            (
                "the daemon rebuilds the statement from its own record, ",
                "",
            ),
            (
                ", and refuses a key that is not enrolled or was removed",
                "",
            ),
        ],
    );
    assert_each_change_fails(
        "§10b the first unlocker approved with the passphrase (D3-08)",
        "The first Secure Enclave unlocker is approved with the passphrase, since until it exists the app has no key to sign with: the app asks for it, and the person runs `envcloak approve <id>` in a terminal and reads an `envcloak-unlocker-statement/1` that names the unlocker's label, the SHA-256 fingerprints of both its public keys, and the Team ID and signing identifier the daemon verified for the app.",
        &[
            ("approved with the passphrase", "approved in the app"),
            (
                ", and the Team ID and signing identifier the daemon verified for the app",
                "",
            ),
        ],
    );
    let t = fixture();
    edit(
        &t,
        "The daemon takes a passphrase or Recovery Kit proof (approve, unlock, rotate, remove, reveal, recover) only from a terminal subject (Subject kind, above), and a signed proof only from the `app` role, and refuses a passphrase or Recovery Kit proof from every other caller",
        "The daemon takes a proof (approve, unlock, rotate, remove, reveal, recover) only from a terminal subject (Subject kind, above), and refuses it from every other caller",
    );
    assert_fails(
        &t.home(),
        &[],
        "§10b which caller gives which proof (D3-10): found 0 times",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds a proof taken only from a terminal subject, with no signed form (D3-10)",
    );
}

/// §5's screen lock is reported through the app role (D3-11); the v0.4
/// bullet is refused. And a decision whose edit is gone fails (D3-10).
///
/// Mutation checked: the old screen-lock bullet dropped from FORBIDDEN and
/// D3-11's phrase changed to the old bullet's: the first case passes, and
/// this test fails.
#[test]
fn the_old_screen_lock_bullet_and_a_lost_m3_edit_fail() {
    let t = fixture();
    edit(
        &t,
        "screen lock (reported by the app through the app role, so no other program can record a screen lock in the audit log);",
        "screen lock (reported by the app);",
    );
    assert_fails(
        &t.home(),
        &[],
        "the SPEC still holds the screen lock any program could report (D3-11)",
    );
    assert_fails(&t.home(), &[], "D3-11: the SPEC lacks");
    let t = fixture();
    let text = spec(&t).replace("`envcloak-write-statement/1`", "`envcloak-write/1`");
    std::fs::write(t.home().join(SPEC), text).unwrap();
    assert_fails(
        &t.home(),
        &[],
        "D3-10: the SPEC lacks '`envcloak-write-statement/1`'",
    );
}
