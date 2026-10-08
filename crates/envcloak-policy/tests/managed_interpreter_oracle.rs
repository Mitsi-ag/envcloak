//! Real interpreter entry selection, independent of the policy tables.
//! Run with scripts/check-managed-oracles.sh and the pinned runtimes named
//! there. Fixtures print fixed words only and use an isolated HOME.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_policy::managed::{ArgvClass, CodeSelecting, DeclError, classify_argv};
use envcloak_testkit::agents::run_capped;
use sha2::{Digest, Sha256};

fn runtime(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).expect("pinned oracle path required"));
    assert!(path.is_absolute());
    let digest: String = Sha256::digest(std::fs::read(&path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    eprintln!("{variable} sha256={digest}");
    path
}

fn run(bin: &Path, home: &Path, args: &[String], extra: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CACHE_HOME", home)
        .env("TMPDIR", home)
        .current_dir(home)
        .args(args)
        .envs(extra.iter().copied());
    let result = run_capped(cmd, Duration::from_secs(20), 8192).unwrap();
    assert!(
        result.in_time && result.complete && !result.over_cap,
        "{result:?}"
    );
    assert!(
        result.output.status.success(),
        "{}",
        String::from_utf8_lossy(&result.output.stderr)
    );
    String::from_utf8(result.output.stdout).unwrap()
}

fn refused(bin: &str, options: &[String], entry: &str) {
    let argv = [
        vec![bin.to_owned()],
        options.to_vec(),
        vec![entry.to_owned()],
    ]
    .concat();
    assert_eq!(
        classify_argv(&argv),
        Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
    );
}

#[test]
#[ignore = "requires PHP 8.4.5; run scripts/check-managed-oracles.sh"]
fn php_attached_file_selects_the_actual_entry() {
    let php = runtime("ENVCLOAK_PHP_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    assert!(run(&php, h, &["-n".into(), "-v".into()], &[]).starts_with("PHP 8.4.5 "));
    let entry = h.join("entry.php");
    let selected = h.join("selected.php");
    std::fs::write(&entry, "<?php echo 'entry';").unwrap();
    std::fs::write(&selected, "<?php echo 'selected';").unwrap();
    let e = entry.to_str().unwrap();
    assert_eq!(run(&php, h, &["-n".into(), e.into()], &[]), "entry");
    assert_eq!(
        classify_argv(&["php".into(), "-n".into(), e.into()]),
        Ok(ArgvClass::Interpreter { entry: 2 })
    );
    for options in [
        vec!["-n".into(), format!("-f{}", selected.display())],
        vec![format!("-nf{}", selected.display())],
    ] {
        let args = [options.clone(), vec![e.into()]].concat();
        assert_eq!(run(&php, h, &args, &[]), "selected");
        refused("php", &options, e);
    }
}

#[test]
#[ignore = "requires debug CPython 3.14.0; run scripts/check-managed-oracles.sh"]
fn python_attached_options_can_import_before_the_entry() {
    let python = runtime("ENVCLOAK_PYTHON_DEBUG_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    let entry = h.join("entry.py");
    std::fs::write(&entry, "print('entry')\n").unwrap();
    std::fs::write(
        h.join("observer.py"),
        "print('prelude')\nclass Notice(Warning): pass\n",
    )
    .unwrap();
    let extra = [("PYTHONPATH", h.to_str().unwrap())];
    let version = run(
        &python,
        h,
        &[
            "-c".into(),
            "import sys; print(sys.version_info[:3]); print(hasattr(sys, 'gettotalrefcount'))"
                .into(),
        ],
        &[],
    );
    assert_eq!(version, "(3, 14, 0)\nTrue\n");
    let e = entry.to_str().unwrap();
    assert_eq!(
        run(&python, h, &["-Xdev".into(), e.into()], &extra),
        "entry\n"
    );
    for option in [
        "-Xpresite=observer",
        "-uXpresite=observer",
        "-Wignore::observer.Notice",
    ] {
        let options = vec![option.to_owned()];
        assert_eq!(
            run(&python, h, &[option.into(), e.into()], &extra),
            "prelude\nentry\n"
        );
        refused("python3.14d", &options, e);
    }
}

#[test]
#[ignore = "requires npm 11.19.0; run scripts/check-managed-oracles.sh"]
fn npm_configuration_names_match_without_case() {
    let npm = runtime("ENVCLOAK_NPM_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    let path = format!("{}:/usr/bin:/bin", npm.parent().unwrap().display());
    let user = h.join("user");
    let global = h.join("global");
    std::fs::write(&user, b"").unwrap();
    std::fs::write(&global, b"").unwrap();
    let base = [
        ("PATH", path.as_str()),
        ("NPM_CONFIG_UPDATE_NOTIFIER", "false"),
        ("NPM_CONFIG_USERCONFIG", user.to_str().unwrap()),
        ("NPM_CONFIG_GLOBALCONFIG", global.to_str().unwrap()),
    ];
    assert_eq!(run(&npm, h, &["--version".into()], &base), "11.19.0\n");
    let args = vec![
        "--userconfig".into(),
        user.to_str().unwrap().into(),
        "--globalconfig".into(),
        global.to_str().unwrap().into(),
        "config".into(),
        "get".into(),
        "script-shell".into(),
    ];
    assert_eq!(run(&npm, h, &args, &base), "null\n");
    for name in [
        "npm_config_script_shell",
        "NPM_CONFIG_SCRIPT_SHELL",
        "NpM_cOnFiG_sCrIpT_ShElL",
    ] {
        let mut extra = base.to_vec();
        extra.push((name, "/fixture/shell"));
        assert_eq!(run(&npm, h, &args, &extra), "/fixture/shell\n");
        assert!(envcloak_policy::managed::is_code_selecting(name), "{name}");
    }
}

/// The environment spellings must obey the same code-loading policy as
/// their corresponding attached options. Mutation: omit both names from
/// the environment refusal predicate.
#[test]
#[ignore = "requires debug CPython 3.14.0; run scripts/check-managed-oracles.sh"]
fn python_startup_environment_cannot_select_unchecked_code() {
    use envcloak_core::vault::LaunchDecl;
    use envcloak_policy::managed::{
        LaunchChanges, apply_changes, check_declaration, launch_environment,
    };
    let python = runtime("ENVCLOAK_PYTHON_DEBUG_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    let entry = h.join("entry.py");
    std::fs::write(&entry, "print('entry')\n").unwrap();
    std::fs::write(
        h.join("observer.py"),
        "print('prelude')\nclass Notice(Warning): pass\n",
    )
    .unwrap();
    let args = vec![entry.to_str().unwrap().to_owned()];
    let base = [("PYTHONPATH", h.to_str().unwrap())];
    assert_eq!(run(&python, h, &args, &base), "entry\n");
    let declared = LaunchDecl {
        argv: vec!["python3.14d".into(), args[0].clone()],
        cwd: None,
        env: Vec::new(),
        path_env: None,
    };
    assert!(check_declaration(&declared).is_ok());
    for (name, value) in [
        ("PYTHON_PRESITE", "observer"),
        ("PYTHONWARNINGS", "ignore::observer.Notice"),
    ] {
        let mut extra = base.to_vec();
        extra.push((name, value));
        assert_eq!(run(&python, h, &args, &extra), "prelude\nentry\n");
        let mut d = declared.clone();
        d.env.push((name.into(), value.into()));
        let refusal = Err(DeclError::CodeSelecting(CodeSelecting::Variable));
        assert_eq!(check_declaration(&d), refusal, "{name}");
        let changes = LaunchChanges {
            set_env: d.env.clone(),
            ..LaunchChanges::default()
        };
        assert!(matches!(
            apply_changes(&declared, &changes),
            Err(DeclError::CodeSelecting(CodeSelecting::Variable))
        ));
        let environment = launch_environment(
            [(name.as_bytes(), value.as_bytes())],
            b"/bin",
            &d.env,
            &[(name, value.as_bytes())],
        );
        assert!(environment.iter().all(|(n, _)| n != name.as_bytes()));
    }
}

/// A real login shell loads a private startup file before the entry.
/// Mutation: keep --login in BOOLEAN_LONG instead of CODE_LOADING_LONG.
#[test]
fn bash_login_startup_is_refused_for_declarations_updates_and_shebangs() {
    use envcloak_core::vault::LaunchDecl;
    use envcloak_policy::managed::{LaunchChanges, apply_changes, check_declaration, shebang_argv};
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    let bash = Path::new("/bin/bash");
    let entry = h.join("entry.sh");
    std::fs::write(&entry, "printf 'entry\\n'\n").unwrap();
    std::fs::write(h.join(".bash_profile"), "printf 'startup\\n'\n").unwrap();
    let e = entry.to_str().unwrap();
    assert_eq!(run(bash, h, &[e.into()], &[]), "entry\n");
    let base = LaunchDecl {
        argv: vec!["/bin/bash".into(), e.into()],
        cwd: None,
        env: vec![],
        path_env: None,
    };
    assert!(check_declaration(&base).is_ok());
    for option in ["--login", "-l", "-lx"] {
        assert_eq!(
            run(bash, h, &[option.into(), e.into()], &[]),
            "startup\nentry\n"
        );
        let argv = vec!["/bin/bash".into(), option.into(), e.into()];
        let declaration = LaunchDecl {
            argv: argv.clone(),
            ..base.clone()
        };
        assert_eq!(
            check_declaration(&declaration),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
        assert!(matches!(
            apply_changes(
                &base,
                &LaunchChanges {
                    argv: Some(argv),
                    ..LaunchChanges::default()
                }
            ),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        ));
        assert_eq!(
            shebang_argv("/bin/bash", Some(option), e, &[], "/bin/bash"),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
    }
}

/// A real LuaJIT loads a `jit.*` module through its search path, whose
/// first entry is `./?.lua`, before the entry file runs: `-jv` loads
/// `jit.v` and `-b` loads `jit.bcsave` from the working directory. Each
/// such form is refused for a declaration, an update and a `#!` line; the
/// benign entry, `-v` and `-O3` beside the same modules run only the entry
/// and register (the controls). Mutation: drop the `harmless_short` check,
/// refusing only listed letters (the previous rule): `-jv` registers.
#[test]
#[ignore = "requires the pinned LuaJIT 2.1; run scripts/check-managed-oracles.sh"]
fn luajit_module_options_load_code_before_the_entry() {
    use envcloak_core::vault::LaunchDecl;
    use envcloak_policy::managed::{LaunchChanges, apply_changes, check_declaration, shebang_argv};
    let luajit = runtime("ENVCLOAK_LUAJIT_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    assert!(run(&luajit, h, &["-v".into()], &[]).starts_with("LuaJIT 2.1."));
    let modules = h.join("jit");
    std::fs::create_dir(&modules).unwrap();
    for module in ["v", "bcsave"] {
        std::fs::write(
            modules.join(format!("{module}.lua")),
            "io.write('prelude\\n')\nreturn { start = function() end }\n",
        )
        .unwrap();
    }
    let entry = h.join("entry.lua");
    std::fs::write(&entry, "io.write('entry\\n')\n").unwrap();
    let e = entry.to_str().unwrap();
    let base = LaunchDecl {
        argv: vec!["luajit".into(), e.into()],
        cwd: Some(h.to_str().unwrap().into()),
        env: vec![],
        path_env: None,
    };
    // The benign controls: the same working directory and modules.
    assert_eq!(run(&luajit, h, &[e.into()], &[]), "entry\n");
    assert!(check_declaration(&base).is_ok());
    assert!(run(&luajit, h, &["-v".into(), e.into()], &[]).ends_with("\nentry\n"));
    assert_eq!(run(&luajit, h, &["-O3".into(), e.into()], &[]), "entry\n");
    for option in ["-v", "-O3"] {
        assert_eq!(
            classify_argv(&["luajit".into(), option.into(), e.into()]),
            Ok(ArgvClass::Interpreter { entry: 2 })
        );
    }
    for (option, output) in [("-jv", "prelude\nentry\n"), ("-b", "prelude\n")] {
        assert_eq!(run(&luajit, h, &[option.into(), e.into()], &[]), output);
        refused("luajit", &[option.to_owned()], e);
        let argv = vec!["luajit".into(), option.into(), e.into()];
        let refusal = Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption));
        assert_eq!(
            check_declaration(&LaunchDecl {
                argv: argv.clone(),
                ..base.clone()
            }),
            refusal
        );
        assert!(matches!(
            apply_changes(
                &base,
                &LaunchChanges {
                    argv: Some(argv),
                    ..LaunchChanges::default()
                }
            ),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        ));
        let path = luajit.to_str().unwrap();
        assert_eq!(
            shebang_argv(path, Some(option), e, &[], path),
            Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
    }
}

/// A real Ruby reads a short value after `-W` (one digit, or a whole
/// `:category`) and after `-K` (one encoding letter), then reads the rest
/// of the cluster as more options: `-We`, `-W1e` and `-KUe` run the code
/// after them, `-Wr` and `-WI.` load a file from the working directory
/// before the entry. Each form is refused for a declaration, an update
/// and a `#!` line. The controls (`-W2`, `-w`, `-W0`, `-W:no-deprecated`,
/// `-KU`) run only the entry and register. Mutation: ruby's `W` and `K`
/// returning `Ok` at their letter without checking the rest of the
/// cluster (the previous `attached_short` rule): `-We...` registers.
#[test]
#[ignore = "requires the pinned Ruby 3.4.7; run scripts/check-managed-oracles.sh"]
fn ruby_short_values_read_the_rest_of_the_cluster_as_options() {
    use envcloak_core::vault::LaunchDecl;
    use envcloak_policy::managed::{LaunchChanges, apply_changes, check_declaration, shebang_argv};
    let ruby = runtime("ENVCLOAK_RUBY_ORACLE");
    let home = tempfile::Builder::new()
        .prefix("eco")
        .tempdir_in("/tmp")
        .unwrap();
    let h = home.path();
    assert!(run(&ruby, h, &["-v".into()], &[]).starts_with("ruby 3.4.7 "));
    std::fs::write(h.join("evil.rb"), "print \"prelude\\n\"\n").unwrap();
    let entry = h.join("entry.rb");
    std::fs::write(&entry, "print \"entry\\n\"\n").unwrap();
    let e = entry.to_str().unwrap();
    let base = LaunchDecl {
        argv: vec!["ruby".into(), e.into()],
        cwd: Some(h.to_str().unwrap().into()),
        env: vec![],
        path_env: None,
    };
    // The benign controls: the same working directory and files.
    assert_eq!(run(&ruby, h, &[e.into()], &[]), "entry\n");
    assert!(check_declaration(&base).is_ok());
    for option in ["-W2", "-w", "-W0", "-W:no-deprecated", "-KU", "-W1KU"] {
        assert_eq!(
            run(&ruby, h, &[option.into(), e.into()], &[]),
            "entry\n",
            "{option}"
        );
        assert_eq!(
            classify_argv(&["ruby".into(), option.into(), e.into()]),
            Ok(ArgvClass::Interpreter { entry: 2 }),
            "{option}"
        );
    }
    let refusal = DeclError::CodeSelecting(CodeSelecting::InterpreterOption);
    for (options, output) in [
        (&["-Weprint(\"injected\\n\")"][..], "injected\n"),
        (&["-W1eprint(\"injected\\n\")"], "injected\n"),
        (&["-KUeprint(\"injected\\n\")"], "injected\n"),
        (&["-Wr./evil"], "prelude\nentry\n"),
        (&["-WI.", "-Wrevil"], "prelude\nentry\n"),
    ] {
        let options: Vec<String> = options.iter().map(|o| (*o).to_owned()).collect();
        let args = [options.clone(), vec![e.to_owned()]].concat();
        assert_eq!(run(&ruby, h, &args, &[]), output, "{options:?}");
        refused("ruby", &options, e);
        let argv = [vec!["ruby".to_owned()], args].concat();
        assert_eq!(
            check_declaration(&LaunchDecl {
                argv: argv.clone(),
                ..base.clone()
            }),
            Err(refusal),
            "{options:?}"
        );
        assert!(
            matches!(
                apply_changes(
                    &base,
                    &LaunchChanges {
                        argv: Some(argv),
                        ..LaunchChanges::default()
                    }
                ),
                Err(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
            ),
            "{options:?}"
        );
        let path = ruby.to_str().unwrap();
        // A `#!` line carries one option: the first one's form.
        assert_eq!(
            shebang_argv(path, Some(options[0].as_str()), e, &[], path),
            Err(refusal),
            "{options:?}"
        );
    }
}
