//! The agent catalog (SPEC §10a; docs/AGENTS.md): the builtin file is
//! integrations/agents.toml byte for byte and loads; the ways real agents
//! are installed and run are classified, and ordinary programs are not;
//! user extensions only add, and an unsafe or malformed one is skipped and
//! reported without echoing its contents.
#![allow(clippy::unwrap_used)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use envcloak_policy::{
    AGENTS_DIR, AgentCatalog, CatalogErrorKind, CatalogSource, Claims, ClaimsError,
    MAX_EXTENSION_FILES, MatchBasis,
};
use envcloak_sys::{Argv, CodeSignature, ExeIdentity, ProcInfo, StartTime};

fn proc_with(exe: Option<&str>, comm: &str, argv: Option<&[&str]>) -> ProcInfo {
    ProcInfo {
        pid: 4242,
        ppid: 1,
        start_time: StartTime::from_raw(1),
        uid: 501,
        sid: Some(4242),
        controlling_tty: Some(0x1_0003),
        comm: OsString::from(comm),
        exe: exe.map(|p| ExeIdentity {
            path: PathBuf::from(p),
            file: None,
            sha256: None,
            signature: None,
        }),
        argv: argv.map(Argv::new),
    }
}

fn exe(path: &str) -> ProcInfo {
    let comm = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().chars().take(15).collect::<String>())
        .unwrap_or_default();
    proc_with(Some(path), &comm, None)
}

fn signed(path: &str, identifier: &str, team: Option<&str>) -> ProcInfo {
    let mut p = exe(path);
    p.exe.as_mut().unwrap().signature = Some(CodeSignature {
        identifier: identifier.to_owned(),
        team_id: team.map(str::to_owned),
        cdhash: None,
    });
    p
}

fn id_of(cat: &AgentCatalog, p: &ProcInfo) -> Option<String> {
    cat.classify(p).map(|l| l.id)
}

#[test]
fn the_builtin_catalog_is_integrations_agents_toml() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../integrations/agents.toml");
    let on_disk = std::fs::read_to_string(path).unwrap();
    assert!(
        AgentCatalog::builtin_source() == on_disk,
        "integrations/agents.toml differs from its compiled copy: run python3 scripts/gen-agents.py"
    );
}

/// SPEC §10a: the catalog and the code that roots grants with it need a
/// code owner's review, as the provider registry does.
#[test]
fn codeowners_cover_the_catalog_and_the_evidence() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/CODEOWNERS");
    let text = std::fs::read_to_string(path).unwrap();
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
        "/integrations/agents.toml",
        "/crates/envcloak-policy/src/agents_builtin.rs",
        "/crates/envcloak-policy/src/agents.rs",
        "/crates/envcloak-policy/src/evidence.rs",
        "/crates/envcloak-sys/src/proc/",
        "/scripts/gen-agents.py",
        "/crates/envcloak-daemon/src/exe_hash.rs",
    ] {
        assert!(
            owned.iter().any(|(p, owners)| *p == want && *owners > 0),
            "CODEOWNERS names no owner for {want}"
        );
    }
}

#[test]
fn the_builtin_catalog_loads_with_its_agents_named() {
    let cat = AgentCatalog::builtin();
    assert_eq!(
        cat.ids().collect::<Vec<_>>(),
        ["claude-code", "codex", "fixture"]
    );
    assert!(cat.problems().is_empty());
    for (marker, id, name) in [
        ("CLAUDECODE", "claude-code", "Claude Code"),
        ("CODEX_THREAD_ID", "codex", "Codex"),
        (
            "ENVCLOAK_FIXTURE_AGENT",
            "fixture",
            "EnvCloak test fixture agent",
        ),
    ] {
        let l = cat.agent_for_marker(marker).unwrap();
        assert_eq!((l.id.as_str(), l.name.as_str()), (id, name));
        assert_eq!(l.source, CatalogSource::Builtin);
    }
    assert!(cat.agent_for_marker("PATH").is_none());
}

#[test]
fn claude_code_is_recognized_however_it_is_installed() {
    let cat = AgentCatalog::builtin();
    let claude = Some("claude-code".to_owned());
    // The native build, run through ~/.local/bin/claude or directly.
    assert_eq!(
        id_of(&cat, &exe("/home/u/.local/share/claude/versions/2.1.112")),
        claude
    );
    // npm's native binary.
    assert_eq!(
        id_of(
            &cat,
            &exe("/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
        ),
        claude
    );
    // The older npm build under node, directly or through its shebang.
    for argv in [
        &[
            "node",
            "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
            "--resume",
        ][..],
        &["/usr/bin/node", "--no-warnings", "/usr/local/bin/claude"][..],
        &[
            "node",
            "--max-old-space-size=4096",
            "/opt/homebrew/bin/claude",
            "-p",
            "x",
        ][..],
    ] {
        let p = proc_with(Some("/usr/bin/node"), "node", Some(argv));
        assert!(cat.needs_argv(&p));
        assert_eq!(id_of(&cat, &p), claude, "{argv:?}");
    }
    // Retitled (node's process.title): argv[0] alone.
    assert_eq!(
        id_of(
            &cat,
            &proc_with(Some("/usr/bin/node"), "node", Some(&["claude"]))
        ),
        claude
    );
    // A renamed copy is still Anthropic's signature on macOS, but not an
    // ad hoc one that borrows the identifier.
    assert_eq!(
        id_of(
            &cat,
            &signed(
                "/tmp/x/renamed",
                "com.anthropic.claude-code",
                Some("Q6L2SF6YDW")
            )
        ),
        claude
    );
    assert_eq!(
        id_of(
            &cat,
            &signed("/tmp/x/renamed", "com.anthropic.claude-code", None)
        ),
        None
    );
    assert_eq!(
        id_of(
            &cat,
            &signed(
                "/tmp/x/renamed",
                "com.anthropic.claude-code",
                Some("AAAAAAAAAA")
            )
        ),
        None
    );
}

#[test]
fn codex_is_recognized_however_it_is_installed() {
    let cat = AgentCatalog::builtin();
    let codex = Some("codex".to_owned());
    for path in [
        "/opt/homebrew/bin/codex",
        "/usr/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex/codex",
    ] {
        assert_eq!(id_of(&cat, &exe(path)), codex, "{path}");
    }
    // npm's launcher under node.
    let p = proc_with(
        Some("/usr/bin/node"),
        "node",
        Some(&["node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"]),
    );
    assert_eq!(id_of(&cat, &p), codex);
    // Linux: a non-dumpable codex hides its exe; its command name and
    // argv[0] remain.
    let hidden = proc_with(None, "codex", Some(&["/opt/x/codex", "exec"]));
    assert!(cat.needs_argv(&hidden));
    assert_eq!(id_of(&cat, &hidden), codex);
    let hidden = proc_with(None, "x", Some(&["/opt/vendor/codex"]));
    assert_eq!(id_of(&cat, &hidden), codex);
    assert_eq!(
        id_of(&cat, &signed("/tmp/renamed", "codex", Some("2DC432GLL2"))),
        codex
    );
}

#[test]
fn the_fixture_agent_is_recognized_by_its_file_name_only() {
    let cat = AgentCatalog::builtin();
    assert_eq!(
        id_of(&cat, &exe("/work/target/debug/fixture-agent")),
        Some("fixture".to_owned())
    );
    for other in [
        "/work/target/debug/fixture-agent-2",
        "/work/target/debug/xfixture-agent",
        "/work/fixture-agent/bin/run",
    ] {
        assert_eq!(id_of(&cat, &exe(other)), None, "{other}");
    }
}

#[test]
fn ordinary_programs_are_not_agents() {
    let cat = AgentCatalog::builtin();
    for path in [
        "/bin/zsh",
        "/bin/bash",
        "/usr/bin/login",
        "/sbin/launchd",
        "/lib/systemd/systemd",
        "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        // The desktop app: another name, another case.
        "/Applications/Claude.app/Contents/MacOS/Claude",
        "/usr/local/bin/claude-helper",
        "/usr/bin/python3",
    ] {
        let p = exe(path);
        assert_eq!(id_of(&cat, &p), None, "{path}");
        assert!(!cat.needs_argv(&p), "{path}");
    }
    // An interpreter running something else, or whose arguments were not
    // read.
    let p = proc_with(
        Some("/usr/bin/node"),
        "node",
        Some(&["node", "/srv/app/server.js", "--port", "8080"]),
    );
    assert_eq!(id_of(&cat, &p), None);
    let p = proc_with(Some("/usr/bin/node"), "node", None);
    assert_eq!(id_of(&cat, &p), None);
    // An Apple platform binary.
    assert_eq!(
        id_of(&cat, &signed("/bin/zsh", "com.apple.zsh", None)),
        None
    );
}

/// A data directory with a private `agents.d`.
fn data_dir() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("eca")
        .tempdir_in("/tmp")
        .unwrap();
    let dir = root.path().join(AGENTS_DIR);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    (root, dir)
}

fn write(dir: &Path, name: &str, text: &str) {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_missing_agents_dir_is_the_builtin_catalog() {
    let root = tempfile::tempdir().unwrap();
    let cat = AgentCatalog::load(root.path());
    assert!(cat.problems().is_empty());
    assert_eq!(cat.ids().count(), 3);
}

#[test]
fn extensions_add_agents_patterns_and_interpreters() {
    let (root, dir) = data_dir();
    write(
        &dir,
        "aider.toml",
        r#"interpreters = ["python3"]

[[agent]]
id = "aider"
name = "Aider"
executables = ["aider"]
scripts = ["aider"]
markers = ["AIDER_SESSION"]
"#,
    );
    write(
        &dir,
        "more-claude.toml",
        r#"[[agent]]
id = "claude-code"
executables = ["my-claude"]
"#,
    );
    // Not read: another extension, and a hidden file.
    write(
        &dir,
        "notes.txt",
        "[[agent]]\nid = \"x\"\nname = \"X\"\nexecutables = [\"zsh\"]\n",
    );
    write(
        &dir,
        ".hidden.toml",
        "[[agent]]\nid = \"y\"\nname = \"Y\"\nexecutables = [\"bash\"]\n",
    );
    let cat = AgentCatalog::load(root.path());
    assert!(cat.problems().is_empty(), "{:?}", cat.problems());
    assert_eq!(
        cat.ids().collect::<Vec<_>>(),
        ["claude-code", "codex", "fixture", "aider"]
    );

    let l = cat.classify(&exe("/usr/local/bin/aider")).unwrap();
    assert_eq!((l.id.as_str(), l.name.as_str()), ("aider", "Aider"));
    assert_eq!(l.source, CatalogSource::Extension);
    let py = proc_with(
        Some("/usr/bin/python3"),
        "python3",
        Some(&["python3", "/home/u/.local/bin/aider", "--yes"]),
    );
    assert!(cat.needs_argv(&py));
    assert_eq!(cat.classify(&py).unwrap().id, "aider");

    // Builtin entries still match as builtin; the added pattern matches
    // as an extension.
    let l = cat.classify(&exe("/opt/claude/versions/9.9.9")).unwrap();
    assert_eq!(
        (l.id.as_str(), l.source),
        ("claude-code", CatalogSource::Builtin)
    );
    let l = cat.classify(&exe("/opt/bin/my-claude")).unwrap();
    assert_eq!(
        (l.id.as_str(), l.source),
        ("claude-code", CatalogSource::Extension)
    );
    assert_eq!(cat.agent_for_marker("AIDER_SESSION").unwrap().id, "aider");
    assert_eq!(id_of(&cat, &exe("/bin/zsh")), None);
    assert_eq!(id_of(&cat, &exe("/bin/bash")), None);
}

/// An agent's product is its id unless its entry names one; an extension
/// that names a product for an existing agent leaves it, as it leaves its
/// name. Only the builtin catalog says where an agent's own installers
/// put it: an extension that lists install trees is skipped and reported,
/// and so is a product that is not an id.
#[test]
fn products_and_install_trees_come_from_the_builtin_catalog() {
    let (root, dir) = data_dir();
    write(
        &dir,
        "a.toml",
        "[[agent]]\nid = \"aider\"\nname = \"Aider\"\nproduct = \"aider-chat\"\n\
         executables = [\"aider\"]\n\n[[agent]]\nid = \"codex\"\nproduct = \"other\"\n\
         executables = [\"codex-nightly\"]\n\n[[agent]]\nid = \"goose\"\nname = \"Goose\"\n\
         executables = [\"goose-agent\"]\n",
    );
    write(
        &dir,
        "b.toml",
        "[[agent]]\nid = \"claude-code\"\nexecutables = [\"cc\"]\n\
         install_trees = [\"/tmp\"]\n",
    );
    write(
        &dir,
        "c.toml",
        "[[agent]]\nid = \"x\"\nname = \"X\"\nexecutables = [\"x\"]\nproduct = \"Not An Id\"\n",
    );
    let cat = AgentCatalog::load(root.path());
    assert_eq!(cat.product("aider"), Some("aider-chat"));
    assert_eq!(cat.product("goose"), Some("goose"));
    assert_eq!(cat.product("codex"), Some("codex"));
    assert_eq!(cat.product("nothing"), None);
    let l = cat.classify(&exe("/usr/local/bin/codex-nightly")).unwrap();
    assert_eq!((l.id.as_str(), l.product.as_str()), ("codex", "codex"));
    assert_eq!(
        cat.classify(&exe("/usr/local/bin/aider")).unwrap().product,
        "aider-chat"
    );
    let problems: Vec<(String, CatalogErrorKind, Option<u32>)> = cat
        .problems()
        .iter()
        .map(|p| {
            (
                p.file.to_string_lossy().into_owned(),
                p.error.kind(),
                p.error.line(),
            )
        })
        .collect();
    assert_eq!(
        problems,
        [
            ("b.toml".to_owned(), CatalogErrorKind::BuiltinOnly, Some(1)),
            ("c.toml".to_owned(), CatalogErrorKind::InvalidId, Some(5)),
        ]
    );
    assert_eq!(id_of(&cat, &exe("/usr/bin/cc")), None, "b.toml was skipped");
    assert!(!cat.within_install_tree(
        "claude-code",
        Path::new("/tmp/claude"),
        Some(Path::new("/home/u"))
    ));
    assert!(!cat.within_install_tree("aider", Path::new("/usr/local/bin/aider"), None));
}

#[test]
fn an_extension_cannot_take_anything_away() {
    let (root, dir) = data_dir();
    // Redefining codex with nothing is refused; codex keeps matching.
    write(
        &dir,
        "a.toml",
        "[[agent]]\nid = \"codex\"\nname = \"Not codex\"\n",
    );
    // Renaming a builtin agent does nothing.
    write(
        &dir,
        "b.toml",
        "[[agent]]\nid = \"claude-code\"\nname = \"Renamed\"\nmarkers = [\"X_MARK\"]\n",
    );
    let cat = AgentCatalog::load(root.path());
    let problems: Vec<_> = cat
        .problems()
        .iter()
        .map(|p| (p.file.to_str().unwrap(), p.error.kind()))
        .collect();
    assert_eq!(problems, [("a.toml", CatalogErrorKind::EmptyAgent)]);
    assert_eq!(
        id_of(&cat, &exe("/opt/homebrew/bin/codex")),
        Some("codex".to_owned())
    );
    let l = cat.classify(&exe("/usr/local/bin/claude")).unwrap();
    assert_eq!(l.name, "Claude Code");
    assert_eq!(cat.agent_for_marker("X_MARK").unwrap().name, "Claude Code");
}

/// Review finding F-36: arguments read only because an extension names an
/// interpreter are not builtin evidence. A match on them, even against a
/// builtin pattern, is an extension match, whether on `argv[0]` or on a
/// script under a builtin interpreter's name.
#[test]
fn arguments_read_for_an_extension_interpreter_are_extension_evidence() {
    let (root, dir) = data_dir();
    write(&dir, "holder.toml", "interpreters = [\"review-holder\"]\n");
    let cat = AgentCatalog::load(root.path());
    assert!(cat.problems().is_empty(), "{:?}", cat.problems());
    let builtin = AgentCatalog::builtin();
    for (argv, id) in [
        (&["codex", "serve"][..], "codex"),
        (
            &["node", "/opt/x/@anthropic-ai/claude-code/cli.js"][..],
            "claude-code",
        ),
        (
            &["/usr/bin/node", "/usr/local/bin/claude"][..],
            "claude-code",
        ),
    ] {
        let p = proc_with(
            Some("/opt/tools/review-holder"),
            "review-holder",
            Some(argv),
        );
        // The builtin catalog neither reads nor uses these arguments.
        assert!(!builtin.needs_argv(&p), "{argv:?}");
        assert_eq!(builtin.classify(&p), None, "{argv:?}");
        // With the extension, they are read, and what matches is labeled
        // an extension match.
        assert!(cat.needs_argv(&p), "{argv:?}");
        let l = cat.classify(&p).unwrap();
        assert_eq!(
            (l.id.as_str(), l.source),
            (id, CatalogSource::Extension),
            "{argv:?}"
        );
    }
    // The builtin reasons to read arguments still give builtin matches: a
    // builtin interpreter, and a hidden executable.
    let node = proc_with(
        Some("/usr/bin/node"),
        "node",
        Some(&["node", "/opt/x/@anthropic-ai/claude-code/cli.js"]),
    );
    let l = cat.classify(&node).unwrap();
    assert_eq!(
        (l.id.as_str(), l.source),
        ("claude-code", CatalogSource::Builtin)
    );
    let hidden = proc_with(None, "x", Some(&["/opt/vendor/codex"]));
    let l = cat.classify(&hidden).unwrap();
    assert_eq!((l.id.as_str(), l.source), ("codex", CatalogSource::Builtin));
}

/// Review finding F-37: what a process says about itself (`argv[0]`, its
/// script, its command name) is caller-asserted (SPEC §10a). A match on it
/// is labeled [`MatchBasis::Asserted`] and may not root a grant above the
/// caller's session; a builtin match on the executable's path or its
/// signature is [`MatchBasis::Executable`] and may.
#[test]
fn what_a_process_says_about_itself_is_asserted() {
    let cat = AgentCatalog::builtin();
    let basis = |p: &ProcInfo| {
        let l = cat.classify(p).unwrap();
        let wide = l.may_root_above_session();
        (l.id, l.source, l.basis, wide)
    };
    let by_exe = |id: &str| {
        (
            id.to_owned(),
            CatalogSource::Builtin,
            MatchBasis::Executable,
            true,
        )
    };
    let said = |id: &str| {
        (
            id.to_owned(),
            CatalogSource::Builtin,
            MatchBasis::Asserted,
            false,
        )
    };
    for path in [
        "/home/u/.local/share/claude/versions/2.1.112",
        "/opt/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
    ] {
        assert_eq!(basis(&exe(path)), by_exe("claude-code"), "{path}");
    }
    assert_eq!(basis(&exe("/opt/homebrew/bin/codex")), by_exe("codex"));
    assert_eq!(
        basis(&signed(
            "/tmp/x/renamed",
            "com.anthropic.claude-code",
            Some("Q6L2SF6YDW")
        )),
        by_exe("claude-code")
    );
    // The executable unchanged, the process's own word changed.
    for (p, id) in [
        // argv[0] under a builtin interpreter (node's process.title).
        (
            proc_with(Some("/usr/bin/node"), "node", Some(&["codex"])),
            "codex",
        ),
        // A script it names.
        (
            proc_with(
                Some("/usr/bin/node"),
                "node",
                Some(&["node", "/opt/x/@anthropic-ai/claude-code/cli.js"]),
            ),
            "claude-code",
        ),
        // Linux: a command name set by prctl, or by a link named `claude`.
        (
            proc_with(Some("/usr/bin/tmux"), "claude", None),
            "claude-code",
        ),
        // A hidden executable: argv[0] and the command name stand in.
        (proc_with(None, "codex", Some(&["x"])), "codex"),
        (proc_with(None, "x", Some(&["/opt/vendor/codex"])), "codex"),
    ] {
        assert_eq!(basis(&p), said(id), "{p:?}");
    }
    // The executable wins over what the process says: Codex by its path,
    // though its command name says Claude Code.
    assert_eq!(
        basis(&proc_with(Some("/opt/homebrew/bin/codex"), "claude", None)),
        by_exe("codex")
    );
    // A marker is a claim.
    assert_eq!(
        cat.agent_for_marker("CLAUDECODE").unwrap().basis,
        MatchBasis::Asserted
    );

    // An extension's executable match roots nothing above the session
    // either.
    let (root, dir) = data_dir();
    write(
        &dir,
        "a.toml",
        "[[agent]]\nid = \"aider\"\nname = \"Aider\"\nexecutables = [\"aider\"]\n",
    );
    let cat = AgentCatalog::load(root.path());
    let l = cat.classify(&exe("/usr/local/bin/aider")).unwrap();
    assert_eq!(
        (l.source, l.basis),
        (CatalogSource::Extension, MatchBasis::Executable)
    );
    assert!(!l.may_root_above_session());
}

#[test]
fn malformed_extensions_are_skipped_and_reported_by_kind_and_line() {
    let (root, dir) = data_dir();
    // A value that must never be echoed back, generated at run time.
    let secretish = format!("tok{:x}{:x}", std::process::id(), 0x5eed_u32);
    let cases: &[(&str, String, CatalogErrorKind, Option<u32>)] = &[
        ("syntax.toml", format!("[[agent]]\nid = {secretish}\n"), CatalogErrorKind::Syntax, Some(2)),
        ("unknown.toml", format!("[[agent]]\nid = \"a\"\nname = \"A\"\n{secretish} = 1\n"), CatalogErrorKind::UnknownKey, Some(4)),
        ("wildcard.toml", "[[agent]]\nid = \"b\"\nname = \"B\"\nexecutables = [\"*\"]\n".to_owned(), CatalogErrorKind::InvalidPattern, Some(4)),
        ("absolute.toml", "[[agent]]\nid = \"c\"\nname = \"C\"\nexecutables = [\"/usr/bin/c\"]\n".to_owned(), CatalogErrorKind::InvalidPattern, Some(4)),
        ("unnamed.toml", "[[agent]]\nid = \"new-agent\"\nexecutables = [\"new-agent\"]\n".to_owned(), CatalogErrorKind::MissingKey, Some(1)),
        ("noid.toml", "[[agent]]\nname = \"N\"\nexecutables = [\"n\"]\n".to_owned(), CatalogErrorKind::MissingKey, Some(1)),
        ("badid.toml", "[[agent]]\nid = \"Bad_Id\"\nname = \"B\"\nexecutables = [\"b\"]\n".to_owned(), CatalogErrorKind::InvalidId, Some(2)),
        ("dup.toml", "[[agent]]\nid = \"d\"\nname = \"D\"\nexecutables = [\"d\"]\n[[agent]]\nid = \"d\"\nname = \"D\"\nexecutables = [\"e\"]\n".to_owned(), CatalogErrorKind::DuplicateId, Some(5)),
        ("marker.toml", "[[agent]]\nid = \"m\"\nname = \"M\"\nmarkers = [\"1BAD\"]\n".to_owned(), CatalogErrorKind::InvalidMarker, Some(4)),
        ("sig.toml", "[[agent]]\nid = \"s\"\nname = \"S\"\nsignatures = [{ identifier = \"s\", team = \"short\" }]\n".to_owned(), CatalogErrorKind::InvalidSignature, Some(4)),
        ("interp.toml", "interpreters = [\"/usr/bin/node\"]\n".to_owned(), CatalogErrorKind::InvalidInterpreter, Some(1)),
        ("name.toml", "[[agent]]\nid = \"n2\"\nname = \"a\u{202e}b\"\nexecutables = [\"n2\"]\n".to_owned(), CatalogErrorKind::InvalidName, Some(3)),
        ("inline.toml", "agent = [{ id = \"i\", name = \"I\", executables = [\"i\"] }]\n".to_owned(), CatalogErrorKind::WrongType, Some(1)),
    ];
    for (name, text, _, _) in cases {
        write(&dir, name, text);
    }
    write(&dir, "big.toml", &format!("# {}\n", "x".repeat(64 * 1024)));
    let cat = AgentCatalog::load(root.path());
    for (name, _, kind, line) in cases {
        let p = cat
            .problems()
            .iter()
            .find(|p| p.file == *name)
            .unwrap_or_else(|| panic!("{name} was not reported"));
        assert_eq!(p.error.kind(), *kind, "{name}: {}", p.error);
        assert_eq!(p.error.line(), *line, "{name}: {}", p.error);
        let shown = format!("{} {:?}", p.error, p);
        assert!(!shown.contains(&secretish), "{name} echoed its contents");
    }
    let big = cat
        .problems()
        .iter()
        .find(|p| p.file == "big.toml")
        .unwrap();
    assert_eq!(big.error.kind(), CatalogErrorKind::TooLarge);
    // Nothing from the bad files was added.
    assert_eq!(cat.ids().count(), 3);
}

#[test]
fn unsafe_files_and_directories_are_refused() {
    let (root, dir) = data_dir();
    let good = "[[agent]]\nid = \"g\"\nname = \"G\"\nexecutables = [\"g-agent\"]\n";
    write(&dir, "writable.toml", good);
    std::fs::set_permissions(
        dir.join("writable.toml"),
        std::fs::Permissions::from_mode(0o620),
    )
    .unwrap();
    let outside = root.path().join("outside.toml");
    std::fs::write(&outside, good).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("link.toml")).unwrap();
    std::fs::create_dir(dir.join("adir.toml")).unwrap();
    let cat = AgentCatalog::load(root.path());
    let mut problems: Vec<_> = cat
        .problems()
        .iter()
        .map(|p| (p.file.to_str().unwrap().to_owned(), p.error.kind()))
        .collect();
    problems.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        problems,
        [
            ("adir.toml".to_owned(), CatalogErrorKind::NotRegularFile),
            ("link.toml".to_owned(), CatalogErrorKind::Symlink),
            ("writable.toml".to_owned(), CatalogErrorKind::Writable),
        ]
    );
    assert_eq!(id_of(&cat, &exe("/x/g-agent")), None);

    // A group-writable agents.d is not read at all.
    write(&dir, "ok.toml", good);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let cat = AgentCatalog::load(root.path());
    assert_eq!(cat.problems().len(), 1);
    assert_eq!(cat.problems()[0].file, AGENTS_DIR);
    assert_eq!(
        cat.problems()[0].error.kind(),
        CatalogErrorKind::UnsafeDirectory
    );
    assert_eq!(id_of(&cat, &exe("/x/g-agent")), None);

    // Nor is a symlinked one.
    let other = tempfile::Builder::new()
        .prefix("eca")
        .tempdir_in("/tmp")
        .unwrap();
    let real = other.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    write(&real, "ok.toml", good);
    std::os::unix::fs::symlink(&real, other.path().join(AGENTS_DIR)).unwrap();
    let cat = AgentCatalog::load(other.path());
    assert_eq!(
        cat.problems()[0].error.kind(),
        CatalogErrorKind::UnsafeDirectory
    );
    assert_eq!(id_of(&cat, &exe("/x/g-agent")), None);
}

#[test]
fn at_most_sixteen_extension_files_are_read() {
    let (root, dir) = data_dir();
    for i in 0..MAX_EXTENSION_FILES + 2 {
        write(
            &dir,
            &format!("{i:02}.toml"),
            &format!("[[agent]]\nid = \"a{i}\"\nname = \"A{i}\"\nexecutables = [\"agent-{i}\"]\n"),
        );
    }
    let cat = AgentCatalog::load(root.path());
    assert_eq!(cat.ids().count(), 3 + MAX_EXTENSION_FILES);
    let skipped: Vec<_> = cat.problems().iter().map(|p| p.file.clone()).collect();
    assert_eq!(skipped, ["16.toml", "17.toml"]);
    assert!(
        cat.problems()
            .iter()
            .all(|p| p.error.kind() == CatalogErrorKind::TooMany)
    );
}

#[test]
fn the_cli_claims_only_catalog_markers_by_name() {
    let cat = AgentCatalog::builtin();
    let names = [
        "PATH",
        "CODEX_THREAD_ID",
        "CLAUDECODE",
        "HOME",
        "CLAUDECODE",
    ]
    .map(OsString::from);
    let c = Claims::from_vars(names, &cat);
    assert_eq!(c.markers(), ["CLAUDECODE", "CODEX_THREAD_ID"]);
    assert!(c.claims_agent());
    assert!(!Claims::from_vars([OsString::from("PATH")], &cat).claims_agent());
    assert!(!Claims::none().claims_agent());
}

#[test]
fn claims_from_the_wire_are_checked() {
    let c = Claims::from_markers(["CLAUDECODE", "SOME_OTHER_AGENT", "CLAUDECODE"]).unwrap();
    assert_eq!(c.markers(), ["CLAUDECODE", "SOME_OTHER_AGENT"]);
    assert_eq!(
        Claims::from_markers(["not a name"]).unwrap_err(),
        ClaimsError::InvalidMarker
    );
    assert_eq!(
        Claims::from_markers([""]).unwrap_err(),
        ClaimsError::InvalidMarker
    );
    let many: Vec<String> = (0..=Claims::MAX_MARKERS).map(|i| format!("M{i}")).collect();
    assert_eq!(
        Claims::from_markers(&many).unwrap_err(),
        ClaimsError::TooMany
    );
    assert!(Claims::from_markers(&many[..Claims::MAX_MARKERS]).is_ok());
}
