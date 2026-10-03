//! An independent oracle for the hook's reading of search globs (M2 plan
//! M2-08; the verifier's finding F119 on `Grep`'s `glob`): ripgrep
//! itself, run on a directory holding one empty file, says whether a
//! glob picks that file out, and the hook must stop a `Grep` call with
//! that glob exactly when the file is an env file the glob picks out.
//!
//! - Character classes spelling env files' names (eight profile names,
//!   each plain, under `**/` and as a brace alternative), with
//!   ordinary-name classes as the negative controls: adopted from the
//!   cycle 321 glob-class oracle.
//! - Globs Claude Code 2.1.280's `Grep` splits before ripgrep reads them
//!   (on white space, then on commas in a piece without both braces; each
//!   piece one `--glob`, the search `--hidden`), the split written here
//!   from the pinned binary's Grep implementation, not from the hook's.
//! - ripgrep's own `--type-list`: every built-in type with a glob that
//!   may pick out an env file is one the hook reads as such
//!   (`RG_ENV_TYPES`), and the other way round.
//!
//! ripgrep is not part of the build: without it on `PATH` the test says
//! so and passes, unless `ENVCLOAK_TEST_REQUIRE_RG` is set (CI sets it,
//! and installs ripgrep). Only empty files in a temporary directory are
//! made; nothing else is read.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_agents::hook::shell::{RG_ENV_TYPES, glob_may_name_env_file};
use envcloak_agents::hook::{Decision, Event, Host, Reason, decide, names_env_file};
use envcloak_core::SecretBuf;
use serde_json::json;

/// ripgrep on `PATH`, or `None` (and the test passes) when it is not
/// there and not required.
fn rg() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("rg"))
            .find(|c| c.is_file())
    });
    match found {
        Some(p) => Some(p),
        None if std::env::var_os("ENVCLOAK_TEST_REQUIRE_RG").is_some() => {
            panic!("ripgrep is not on PATH, and ENVCLOAK_TEST_REQUIRE_RG is set")
        }
        None => {
            eprintln!("grep_glob_oracle: skipped: ripgrep is not on PATH");
            None
        }
    }
}

/// Claude Code 2.1.280's split of a Grep `glob` (its Grep implementation:
/// `r.split(/\s+/)`, then each piece that does not include both `{` and
/// `}` split on `,`, empty pieces dropped).
fn host_split(glob: &str) -> Vec<String> {
    let mut out = Vec::new();
    for piece in glob.split(char::is_whitespace) {
        if piece.contains('{') && piece.contains('}') {
            out.push(piece.to_owned());
        } else {
            out.extend(piece.split(',').map(str::to_owned));
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

/// Whether ripgrep, given `glob` as Claude Code gives it, lists the empty
/// file `witness`.
fn rg_lists(rg: &Path, glob: &str, witness: &str) -> bool {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(witness), b"").unwrap();
    let mut cmd = Command::new(rg);
    cmd.current_dir(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .args(["--files", "--hidden", "--no-ignore", "--no-config"]);
    for g in host_split(glob) {
        cmd.arg("--glob").arg(g);
    }
    cmd.arg(".");
    let out = cmd.output().unwrap();
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "rg failed on {glob:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).lines().count() == 1
}

fn grep(glob: &str) -> Decision {
    let p = json!({
        "session_id": "s", "transcript_path": "/t", "cwd": "/w",
        "hook_event_name": "PreToolUse", "permission_mode": "default",
        "tool_name": "Grep", "tool_input": {"pattern": "K", "glob": glob},
        "tool_use_id": "u",
    });
    let bytes = serde_json::to_vec(&p).unwrap();
    let mut b = SecretBuf::with_capacity(bytes.len());
    b.extend(&bytes).unwrap();
    decide(Host::ClaudeCode, Event::PreToolUse, &b)
}

/// Each character of `name` as a class of its own: `[.][e][n][v]`.
fn classes(name: &str) -> String {
    name.chars().map(|c| format!("[{c}]")).collect()
}

/// Mutations checked: classes read as text (`class` in the hook's glob
/// reader answering `None`, the previous reading): the class cases are
/// allowed while ripgrep lists their witness, and this fails; the Grep
/// glob judged whole (the hook calling `glob_may_name_env_file` on it):
/// the split cases are allowed, and this fails.
#[test]
fn the_hook_stops_exactly_the_globs_ripgrep_reads_an_env_file_with() {
    let Some(rg) = rg() else {
        return;
    };
    let deny = Decision::Deny(Reason::EnvFile);
    let mut cases: Vec<(String, String, bool)> = Vec::new();
    let prefix: String = [46_u8, 101, 110, 118].into_iter().map(char::from).collect();
    for n in 0..8 {
        let witness = format!("{prefix}.q{n}");
        assert!(names_env_file(&witness), "{witness}");
        let quoted = classes(&witness);
        for pattern in [
            quoted.clone(),
            format!("**/{quoted}"),
            format!("{{*.rs,{quoted}}}"),
        ] {
            cases.push((pattern, witness.clone(), true));
        }
        // The literal glob, a positive control of the oracle itself.
        cases.push((witness.clone(), witness.clone(), true));
        // Ordinary names spelled the same way pick out no env file.
        cases.push((classes(&format!("unit{n}.rs")), witness.clone(), false));
    }
    // The pieces Claude Code makes of one glob.
    for (glob, witness) in [
        (".env.local src/*.rs", ".env.local"),
        ("README.md,.env", ".env"),
        (".env,config/app.yaml", ".env"),
        (".env* src/**", ".env.local"),
        (".env x", ".env"),
        ("a.rs\t.env.ci", ".env.ci"),
    ] {
        cases.push((glob.to_owned(), witness.to_owned(), true));
    }
    // A template holds names only: picked out, and let through.
    cases.push((".env.example".to_owned(), ".env.example".to_owned(), true));
    cases.push((classes(".env.example"), ".env.example".to_owned(), true));
    let mut wrong = Vec::new();
    for (glob, witness, listed_by_design) in &cases {
        // The oracle's own check: ripgrep lists the witness exactly for
        // the cases built to pick it out.
        let listed = rg_lists(&rg, glob, witness);
        assert_eq!(
            listed, *listed_by_design,
            "ripgrep and the case disagree on {glob:?} for {witness:?}"
        );
        let want = if listed && names_env_file(witness) {
            deny
        } else {
            Decision::Allow
        };
        if grep(glob) != want {
            wrong.push(format!("{glob:?} ({witness}): want {want:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "the hook disagrees with ripgrep: {wrong:#?}"
    );
}

/// ripgrep's built-in file types against `RG_ENV_TYPES`: a type with a
/// glob that may pick out an env file is one the hook stops a `--type`
/// (and Grep's `type`) for, and each one it stops for has such a glob.
///
/// Mutation checked: `sh` taken out of `RG_ENV_TYPES`: this fails.
#[test]
fn ripgreps_own_types_that_hold_env_files_are_the_hooks() {
    let Some(rg) = rg() else {
        return;
    };
    let out = Command::new(&rg)
        .args(["--no-config", "--type-list"])
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success());
    let list = String::from_utf8(out.stdout).unwrap();
    let mut env_types: Vec<String> = Vec::new();
    for line in list.lines() {
        let Some((name, globs)) = line.split_once(": ") else {
            continue;
        };
        if globs.split(", ").any(glob_may_name_env_file) {
            env_types.push(name.to_owned());
        }
    }
    // The positive control: `sh` holds `.env`.
    assert!(env_types.iter().any(|t| t == "sh"), "{env_types:?}");
    let listed: Vec<&str> = RG_ENV_TYPES
        .iter()
        .copied()
        .filter(|t| *t != "all")
        .collect();
    let mut found: Vec<&str> = env_types.iter().map(String::as_str).collect();
    found.sort_unstable();
    assert_eq!(found, listed, "ripgrep's types that hold env files");
}
