//! An independent oracle for the hook's reading of search globs and types
//! (M2 plan M2-08; the verifier's finding F119 on `Grep`'s `glob` and its
//! follow-ups): ripgrep itself, run on a directory holding empty files,
//! says which files a glob or a type picks out, and the hook is checked
//! against that.
//!
//! - Globs: for each case below, the hook stops a `Grep` call with the
//!   glob exactly when ripgrep picks out the case's file and that file is
//!   an env file. The cases: character classes spelling env files' names
//!   (eight profile names, each plain, under `**/` and as a brace
//!   alternative), with ordinary-name classes as the negative controls
//!   (adopted from the cycle 321 glob-class oracle); a `/` inside a class
//!   and a class that matches the separator (Codex's cycle 326 class/path
//!   cases, and the verifier's `**[/].env` and `sub[/].env`, their files in
//!   a subdirectory), with ordinary and template files picked out the same
//!   way as controls; and globs Claude Code 2.1.280's `Grep` splits before
//!   ripgrep reads them (on white space, then on commas in a piece without
//!   both braces; each piece one `--glob`, the search `--hidden`), the
//!   split written here from the pinned binary's Grep implementation, not
//!   from the hook's.
//! - Types: every type of the installed ripgrep is asked, by name, which of
//!   a directory's files it picks out; each type that picks out an env file
//!   is one the hook stops (`RG_ENV_TYPES`), `all` picks one out whenever a
//!   type does, and each other type the hook stops picks one out in this
//!   ripgrep or is recorded as one of another version's (ripgrep 15's `sh`
//!   holds `.env`, 14.1.0's does not). Types a command defines with
//!   `--type-add` (Codex's cycle 327 type oracle): a definition that picks
//!   out an env file, its own glob or an included type's, is stopped.
//!
//! ripgrep is not part of the build: without it on `PATH` the test says
//! so and passes, unless `ENVCLOAK_TEST_REQUIRE_RG` is set (CI sets it,
//! and installs ripgrep). Only empty files in temporary directories are
//! made; nothing else is read.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_agents::hook::shell::{Class, RG_ENV_TYPES, check_script};
use envcloak_agents::hook::{Decision, Event, Host, Reason, decide, decide_argv, names_env_file};
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

/// `.env`, made at run time (never a literal name in the tree).
fn env_prefix() -> String {
    [46_u8, 101, 110, 118].into_iter().map(char::from).collect()
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

/// ripgrep run in a fresh directory holding the empty files `files`
/// (paths relative to it, a subdirectory made where one is named), with
/// `args`: the files it lists, relative and without `./`.
fn rg_files(rg: &Path, files: &[&str], args: &[String]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    for f in files {
        let p = dir.path().join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"").unwrap();
    }
    let out = Command::new(rg)
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .args(["--files", "--hidden", "--no-ignore", "--no-config"])
        .args(args)
        .arg(".")
        .output()
        .unwrap();
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "rg failed on {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_start_matches("./").to_owned())
        .collect()
}

/// Whether ripgrep, given `glob` as Claude Code gives it, lists the empty
/// file `witness` (a relative path).
fn rg_lists(rg: &Path, glob: &str, witness: &str) -> bool {
    let mut args = Vec::new();
    for g in host_split(glob) {
        args.push("--glob".to_owned());
        args.push(g);
    }
    let listed = rg_files(rg, &[witness], &args);
    listed.iter().any(|l| l == witness)
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
/// the split cases are allowed, and this fails; the last component taken
/// at the raw last `/` (the previous `rposition` split in
/// `word_may_name_env_file`): the class/path cases are allowed, and this
/// fails.
#[test]
fn the_hook_stops_exactly_the_globs_ripgrep_reads_an_env_file_with() {
    let Some(rg) = rg() else {
        return;
    };
    let deny = Decision::Deny(Reason::EnvFile);
    let prefix = env_prefix();
    let mut cases: Vec<(String, String, bool)> = Vec::new();
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
    // A `/` inside a class, and a class that matches the separator: the
    // name after it is still read (Codex's cycle 326 cases; the
    // verifier's, with their files in a subdirectory).
    let profile = format!("{prefix}.oracle-profile");
    let nested = format!("sub/{prefix}");
    for (glob, witness) in [
        ("[/.]env*", &profile),
        ("[.-/]env*", &profile),
        ("[./]e[n]v*", &profile),
        ("[/.][e][n][v]*", &profile),
        ("[/\\.]env*", &profile),
        ("[.\\/]env*", &profile),
        ("**[/].env", &nested),
        ("sub[/].env", &nested),
        ("sub[!a].env", &nested),
        ("sub[.-0].env", &nested),
    ] {
        cases.push((glob.to_owned(), witness.clone(), true));
    }
    // Their controls: an ordinary file and a template picked out the same
    // way (listed, and let through), and a class that leaves the name's
    // first byte out (not listed).
    cases.push(("sub[/]x.rs".to_owned(), "sub/x.rs".to_owned(), true));
    cases.push((
        "sub[/].env.example".to_owned(),
        format!("sub/{prefix}.example"),
        true,
    ));
    cases.push(("src/[a-c]*.rs".to_owned(), "src/b.rs".to_owned(), true));
    cases.push(("[/]env*".to_owned(), profile.clone(), false));
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

/// The installed ripgrep's major version.
fn rg_major(rg: &Path) -> (u32, String) {
    let out = Command::new(rg)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let major = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse().ok())
        .unwrap();
    (major, line)
}

/// The verifier's low finding: the type check asked the hook's own glob
/// reader which types hold env files, so a reader that wrongly said none
/// would have found none and passed. ripgrep is asked instead: every
/// built-in type of the installed ripgrep, by name, on a directory holding
/// env files and a control file. Each type that picks out an env file must
/// be one the hook stops (`RG_ENV_TYPES`); `all` must pick one out exactly
/// when a type does; and each other type the hook stops must pick one out
/// in this ripgrep, unless this ripgrep is older than 15, where `sh` holds
/// no env file (Ubuntu 24.04's 14.1.0, measured in CI): the list is the
/// union of the versions, and this prints what the installed one has.
///
/// Mutations checked: `sh` taken out of `RG_ENV_TYPES`: this fails with
/// ripgrep 15.1.0 (a type picks out `.env` and the hook lets it through);
/// a type added to `RG_ENV_TYPES` that holds no env file (`rust`): this
/// fails (the other direction).
#[test]
fn ripgreps_own_types_that_hold_env_files_are_the_hooks() {
    let Some(rg) = rg() else {
        return;
    };
    let (major, version) = rg_major(&rg);
    let out = Command::new(&rg)
        .args(["--no-config", "--type-list"])
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success());
    let list = String::from_utf8(out.stdout).unwrap();
    let prefix = env_prefix();
    let env_files = [
        prefix.clone(),
        format!("{prefix}.local"),
        format!("{prefix}.production"),
        format!("sub/{prefix}"),
    ];
    let mut files: Vec<&str> = env_files.iter().map(String::as_str).collect();
    files.extend(["main.rs", "notes.txt"]);
    let picks = |t: &str| rg_files(&rg, &files, &["--type".to_owned(), t.to_owned()]);
    let mut env_types: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for line in list.lines() {
        let Some((name, _)) = line.split_once(": ") else {
            continue;
        };
        names.push(name.to_owned());
        if picks(name).iter().any(|f| names_env_file(f)) {
            env_types.push(name.to_owned());
        }
    }
    // The positive control: ripgrep was asked, and answered by type
    // (`rust` picks out `main.rs` and nothing else).
    assert!(names.len() > 50, "ripgrep's type list was not read");
    assert_eq!(picks("rust"), vec!["main.rs".to_owned()]);
    let missed: Vec<&String> = env_types
        .iter()
        .filter(|t| !RG_ENV_TYPES.contains(&t.as_str()))
        .collect();
    assert!(
        missed.is_empty(),
        "ripgrep's types that pick out env files and the hook lets through: {missed:?}"
    );
    // `all`, every type at once, picks out an env file exactly when a
    // type does.
    let all = picks("all").iter().any(|f| names_env_file(f));
    assert_eq!(all, !env_types.is_empty(), "{version}: `all`");
    // The other direction: each type the hook stops picks out an env file
    // here, or is another version's.
    for t in RG_ENV_TYPES.iter().filter(|t| **t != "all") {
        assert!(
            names.iter().any(|n| n == t),
            "{version}: the hook names a type ripgrep does not have: {t}"
        );
        assert!(
            env_types.iter().any(|e| e == t) || major < 15,
            "{version}: the hook stops {t}, which picks out no env file here"
        );
    }
    println!("measurement: {version}: types picking out env files: {env_types:?}");
}

/// Codex's cycle 327 type oracle: a type a command defines with
/// `--type-add` picks out the files its globs, or the types it includes,
/// pick out. For each definition, ripgrep is asked which files `--type`
/// with it lists, and the hook (the shell reader and the `run_with_secrets`
/// argv check) must stop the command whenever an env file is among them;
/// the controls pick out only ordinary files and are let through. ripgrep
/// 15's `sh` holds `.env`, so there `include:sh` picks one out (asserted);
/// with an older ripgrep the hook stops it all the same (the union).
///
/// Mutation checked: `rg_type_add_may_name_env_file` answering false for
/// `include:` (the previous reading, which took the included types for
/// globs): the `include:sh` definitions are let through, and this fails
/// with ripgrep 15.
#[test]
fn types_a_command_defines_are_read_as_ripgrep_reads_them() {
    let Some(rg) = rg() else {
        return;
    };
    let (major, version) = rg_major(&rg);
    let prefix = env_prefix();
    let files = [prefix.as_str(), "ordinary.rs", "ordinary.json"];
    let own = format!("guard:{prefix}*");
    let definitions: [(&str, bool); 7] = [
        ("guard:include:sh", true),
        ("guard:include:sh,rust", true),
        ("guard:include:rust,sh", true),
        (own.as_str(), true),
        ("guard:include:rust", false),
        ("guard:include:json", false),
        ("guard:include:rust,json", false),
    ];
    for (definition, holds_env) in definitions {
        let args = [
            "--type-add".to_owned(),
            definition.to_owned(),
            "--type".to_owned(),
            "guard".to_owned(),
        ];
        let listed = rg_files(&rg, &files, &args);
        let env = listed.iter().any(|f| names_env_file(f));
        let ordinary = listed.iter().any(|f| !names_env_file(f));
        if holds_env && major >= 15 || definition == own {
            assert!(env, "{version}: {definition}: no env file listed");
        }
        if !holds_env {
            assert!(!env && ordinary, "{version}: {definition}: {listed:?}");
        }
        let argv = [
            "rg",
            "--type-add",
            definition,
            "--type",
            "guard",
            "KEY",
            ".",
        ];
        let script = argv.join(" ");
        let (by_argv, by_script) = (decide_argv(&argv), check_script(&script));
        if env || holds_env {
            assert_eq!(
                by_argv,
                Decision::Deny(Reason::EnvFile),
                "{version}: {definition}"
            );
            assert_eq!(by_script, Some(Class::EnvFile), "{version}: {definition}");
        } else {
            assert_eq!(by_argv, Decision::Allow, "{version}: {definition}");
            assert_eq!(by_script, None, "{version}: {definition}");
        }
    }
}
