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

/// The builtin catalog's agents, in its order.
const BUILTIN: [&str; 11] = [
    "claude-code",
    "codex",
    "cursor",
    "gemini-cli",
    "copilot-cli",
    "opencode",
    "kimi",
    "qwen-code",
    "goose",
    "aider",
    "fixture",
];

fn builtin_ids() -> Vec<&'static str> {
    BUILTIN.to_vec()
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
    assert_eq!(cat.ids().collect::<Vec<_>>(), builtin_ids());
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

/// What a fixture should classify as: an agent id and the basis of the
/// match, or nothing.
type Want = Option<(&'static str, MatchBasis)>;

const BY_EXE: MatchBasis = MatchBasis::Executable;
const SAID: MatchBasis = MatchBasis::Asserted;

/// `node` running `args` (`argv[0]` first).
fn node(args: &[&str]) -> ProcInfo {
    proc_with(Some("/usr/local/bin/node"), "node", Some(args))
}

/// Every agent the M2 catalog adds (M2 plan task M2-10), and Claude Code's
/// additions, as their documented installs and M2-04's pinned hosts run
/// them (positive fixtures: executables by path, scripts under node, the
/// names a process gives itself), and the same files under other names or
/// in other places (negative fixtures: no match, so nothing rooted above
/// the caller's session). Each match's basis decides whether it may root
/// a grant there: only a builtin match on the executable's path or
/// signature does, never one on a script, `argv[0]` or a command name
/// (review finding F-37). Each label carries its product.
#[test]
fn every_new_entry_has_positive_and_negative_fixtures() {
    let cat = AgentCatalog::builtin();
    let home = "/home/u";
    let v = "2026.09.28-64d2043";
    let cursor_dir = format!("{home}/.local/share/cursor-agent/versions/{v}");
    let mut cases: Vec<(String, ProcInfo, Want)> = vec![
        // Claude Code: npm's launcher with install scripts off.
        (
            "claude cli-wrapper".into(),
            node(&[
                "node",
                "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli-wrapper.cjs",
            ]),
            Some(("claude-code", SAID)),
        ),
        // Cursor CLI: its own node in its versions directory running its
        // index.js (`exec -a` gives node the link's name), and that
        // index.js under any node: by its script only. Its node runs any
        // script, so it is never Cursor by its path.
        (
            "cursor node".into(),
            proc_with(
                Some(&format!("{cursor_dir}/node")),
                "node",
                Some(&[
                    &format!("{home}/.local/bin/agent"),
                    "--use-system-ca",
                    &format!("{cursor_dir}/index.js"),
                ]),
            ),
            Some(("cursor", SAID)),
        ),
        (
            "cursor's node running another script".into(),
            proc_with(
                Some(&format!("{cursor_dir}/node")),
                "node",
                Some(&["node", "/tmp/evil.js"]),
            ),
            None,
        ),
        (
            "cursor's node, its arguments not read".into(),
            proc_with(Some(&format!("{cursor_dir}/node")), "node", None),
            None,
        ),
        (
            "cursor index.js".into(),
            node(&["node", &format!("{cursor_dir}/index.js")]),
            Some(("cursor", SAID)),
        ),
        // Not Cursor: node elsewhere, its links, its files elsewhere, and
        // the Node.js Foundation's signature that its node carries.
        ("node elsewhere".into(), exe("/usr/local/bin/node"), None),
        (
            "agent link".into(),
            exe(&format!("{home}/.local/bin/agent")),
            None,
        ),
        (
            "cursor files outside versions".into(),
            exe(&format!("{home}/.local/share/cursor-agent/{v}/node")),
            None,
        ),
        (
            "index.js elsewhere".into(),
            node(&["node", "/srv/app/index.js"]),
            None,
        ),
        (
            "Node.js Foundation signature".into(),
            signed(&format!("{cursor_dir}/node2"), "node", Some("HX7739G8FX")),
            None,
        ),
        // Gemini CLI: its bundle under node, or its `gemini` link.
        (
            "gemini bundle".into(),
            node(&[
                "node",
                "--no-warnings=DEP0040",
                "/usr/local/lib/node_modules/@google/gemini-cli/bundle/gemini.js",
            ]),
            Some(("gemini-cli", SAID)),
        ),
        (
            "gemini link".into(),
            node(&["node", "/usr/local/bin/gemini", "-p", "x"]),
            Some(("gemini-cli", SAID)),
        ),
        // No executable is Gemini CLI by its name alone.
        ("gemini binary".into(), exe("/usr/local/bin/gemini"), None),
        (
            "another bundle".into(),
            node(&["node", "/srv/gemini-cli/bundle/gemini.js"]),
            None,
        ),
        // Copilot CLI: the platform binary of npm's packages (on Linux its
        // command name is its main thread's) and its signature, by its
        // executable; the install script's binary, whose path the AWS
        // Copilot CLI shares, by its name only; and npm's launcher.
        (
            "copilot platform binary".into(),
            proc_with(
                Some(
                    "/usr/local/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot",
                ),
                "MainThread",
                None,
            ),
            Some(("copilot-cli", BY_EXE)),
        ),
        (
            "copilot macOS platform binary".into(),
            exe(
                "/opt/homebrew/lib/node_modules/@github/copilot/node_modules/@github/copilot-darwin-arm64/copilot",
            ),
            Some(("copilot-cli", BY_EXE)),
        ),
        (
            "copilot by its signature".into(),
            signed("/Users/u/bin/gh-copilot", "copilot", Some("VEKTX9H2N7")),
            Some(("copilot-cli", BY_EXE)),
        ),
        (
            "copilot's identifier, another team".into(),
            signed("/Users/u/bin/gh-copilot", "copilot", Some("ABCDE12345")),
            None,
        ),
        (
            "copilot install script".into(),
            exe(&format!("{home}/.local/bin/copilot")),
            Some(("copilot-cli", SAID)),
        ),
        (
            "AWS Copilot CLI, by the same name".into(),
            exe("/usr/local/bin/copilot"),
            Some(("copilot-cli", SAID)),
        ),
        (
            "another package's copilot".into(),
            exe("/usr/local/lib/node_modules/@aws/copilot-linux-x64/copilot"),
            Some(("copilot-cli", SAID)),
        ),
        (
            "copilot npm-loader".into(),
            node(&[
                "node",
                "/usr/local/lib/node_modules/@github/copilot/npm-loader.js",
            ]),
            Some(("copilot-cli", SAID)),
        ),
        (
            "copilot link".into(),
            node(&["node", "/usr/local/bin/copilot"]),
            Some(("copilot-cli", SAID)),
        ),
        (
            "copilot renamed".into(),
            exe("/usr/local/bin/copilot-x"),
            None,
        ),
        (
            "another npm-loader".into(),
            node(&["node", "/srv/npm-loader.js"]),
            None,
        ),
        // OpenCode: the native binary, from npm or its install script.
        (
            "opencode platform binary".into(),
            exe(
                "/usr/local/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64/bin/opencode",
            ),
            Some(("opencode", BY_EXE)),
        ),
        (
            "opencode install script".into(),
            exe(&format!("{home}/.opencode/bin/opencode")),
            Some(("opencode", BY_EXE)),
        ),
        (
            "opencode by its signature".into(),
            signed("/Users/u/bin/oc", "opencode", Some("5NZ4Q7NXJ4")),
            Some(("opencode", BY_EXE)),
        ),
        (
            "opencode renamed".into(),
            exe("/usr/local/bin/opencoder"),
            None,
        ),
        // Kimi: Kimi Code's binary; npm's Kimi Code, which renames its
        // node process and its arguments; its main.mjs; kimi-cli's
        // Python script, by its command name on Linux.
        (
            "kimi binary".into(),
            exe(&format!("{home}/.kimi-code/bin/kimi")),
            Some(("kimi", BY_EXE)),
        ),
        (
            "kimi-code retitled".into(),
            proc_with(
                Some("/usr/local/bin/node"),
                "kimi-code",
                Some(&["kimi-code"]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-code main.mjs".into(),
            node(&[
                "node",
                "/usr/local/lib/node_modules/@moonshot-ai/kimi-code/dist/main.mjs",
            ]),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli script".into(),
            proc_with(Some("/usr/bin/python3.12"), "kimi", None),
            Some(("kimi", SAID)),
        ),
        // kimi-cli under Python: its `kimi` and `kimi-cli` scripts, and
        // the title setproctitle gives it (`Kimi Code`, over its
        // arguments, and on Linux its command name too), on each system.
        (
            "kimi-cli under python".into(),
            proc_with(
                Some(
                    "/home/u/.local/share/uv/python/cpython-3.12.11-linux-x86_64-gnu/bin/python3.12",
                ),
                "python3.12",
                Some(&[
                    "/home/u/.local/share/uv/tools/kimi-cli/bin/python",
                    "/home/u/.local/bin/kimi",
                ]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli's second script".into(),
            proc_with(
                Some("/usr/bin/python3"),
                "python3",
                Some(&["python3", "/home/u/.local/bin/kimi-cli", "--yolo"]),
            ),
            Some(("kimi", SAID)),
        ),
        // A Python or a node by a version the interpreters list does not
        // name is still an interpreter (`python3.9`, `node22`): its script
        // is read. A name that only starts like one is not.
        (
            "kimi-cli under a Python the list does not name".into(),
            proc_with(
                Some("/usr/bin/python3.9"),
                "python3.9",
                Some(&["python3.9", "/home/u/.local/bin/kimi"]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "Gemini CLI under a versioned node".into(),
            proc_with(
                Some("/opt/node22/bin/node22"),
                "node22",
                Some(&[
                    "node22",
                    "/usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js",
                ]),
            ),
            Some(("gemini-cli", SAID)),
        ),
        (
            "a name that only starts like an interpreter".into(),
            proc_with(
                Some("/usr/local/bin/nodemon"),
                "nodemon",
                Some(&[
                    "nodemon",
                    "/usr/lib/node_modules/@google/gemini-cli/bundle/gemini.js",
                ]),
            ),
            None,
        ),
        (
            "kimi-cli titled, Linux".into(),
            proc_with(
                Some("/usr/bin/python3.13"),
                "Kimi Code",
                Some(&["Kimi Code"]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli titled, Linux, arguments not read".into(),
            proc_with(Some("/usr/bin/python3.13"), "Kimi Code", None),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli titled, macOS framework Python".into(),
            proc_with(
                Some(
                    "/opt/homebrew/Cellar/python@3.13/3.13.5/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python",
                ),
                "Python",
                Some(&["Kimi Code", "", ""]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli background worker, its command name cut".into(),
            proc_with(Some("/usr/bin/python3.12"), "kimi-code-bg-wo", None),
            Some(("kimi", SAID)),
        ),
        (
            "kimi-cli web worker, macOS".into(),
            proc_with(
                Some("/usr/local/bin/python3.12"),
                "python3.12",
                Some(&["kimi-code-worker"]),
            ),
            Some(("kimi", SAID)),
        ),
        (
            "a file named as a title is still only a name".into(),
            exe("/opt/Kimi Code"),
            Some(("kimi", SAID)),
        ),
        ("kimi renamed".into(), exe("/usr/local/bin/kimi2"), None),
        (
            "another title".into(),
            proc_with(Some("/usr/bin/python3.12"), "Kimi", Some(&["Kimi"])),
            None,
        ),
        (
            "a short command name is not a cut one".into(),
            proc_with(Some("/usr/bin/python3.12"), "kimi-code-bg", None),
            None,
        ),
        (
            "python running another script".into(),
            proc_with(
                Some("/usr/bin/python3.12"),
                "python3.12",
                Some(&["python3", "/srv/kimi_tools.py"]),
            ),
            None,
        ),
        (
            "another main.mjs".into(),
            node(&["node", "/srv/dist/main.mjs"]),
            None,
        ),
        // An executable removed or renamed over while it runs (an agent, or
        // node, that updated itself): Linux adds ` (deleted)` to its path,
        // and the process still runs the file the path named.
        (
            "claude updated while it runs".into(),
            exe(&format!(
                "{home}/.local/share/claude/versions/2.1.280 (deleted)"
            )),
            Some(("claude-code", BY_EXE)),
        ),
        (
            "opencode updated while it runs".into(),
            exe(&format!("{home}/.opencode/bin/opencode (deleted)")),
            Some(("opencode", BY_EXE)),
        ),
        (
            "node updated while it runs Gemini CLI".into(),
            proc_with(
                Some("/usr/local/bin/node (deleted)"),
                "node",
                Some(&[
                    "node",
                    "/usr/local/lib/node_modules/@google/gemini-cli/bundle/gemini.js",
                ]),
            ),
            Some(("gemini-cli", SAID)),
        ),
        (
            "only the kernel's suffix is taken off".into(),
            exe("/usr/local/bin/codex (deleted)x"),
            None,
        ),
        // Qwen Code: its entry script under node, or its `qwen` link.
        (
            "qwen entry".into(),
            node(&[
                "node",
                "/usr/local/lib/node_modules/@qwen-code/qwen-code/cli-entry.js",
            ]),
            Some(("qwen-code", SAID)),
        ),
        (
            "qwen link".into(),
            node(&["node", "/usr/local/bin/qwen"]),
            Some(("qwen-code", SAID)),
        ),
        ("qwen binary".into(), exe("/usr/local/bin/qwen"), None),
        (
            "another cli-entry".into(),
            node(&["node", "/srv/qwen-code/cli-entry.js"]),
            None,
        ),
        // Goose: its one binary, wherever its install script, a package
        // manager or its desktop app put it, by its name only (pressly's
        // database migration tool is a `goose` too). Its macOS build is
        // signed ad hoc: no signature names it.
        (
            "goose install script".into(),
            exe(&format!("{home}/.local/bin/goose")),
            Some(("goose", SAID)),
        ),
        (
            "goose elsewhere".into(),
            exe("/opt/homebrew/bin/goose"),
            Some(("goose", SAID)),
        ),
        (
            "goose in its desktop app".into(),
            proc_with(
                Some("/Applications/Goose.app/Contents/Resources/bin/goose"),
                "goose",
                Some(&[
                    "/Applications/Goose.app/Contents/Resources/bin/goose",
                    "serve",
                ]),
            ),
            Some(("goose", SAID)),
        ),
        (
            "goose signed ad hoc".into(),
            signed(
                &format!("{home}/.local/bin/goose"),
                "goose-37a4aa07b5b08d24",
                None,
            ),
            Some(("goose", SAID)),
        ),
        (
            "goose by its command name, its executable hidden".into(),
            proc_with(None, "goose", None),
            Some(("goose", SAID)),
        ),
        (
            "goose renamed".into(),
            exe("/usr/local/bin/goose-cli"),
            None,
        ),
        ("goosed".into(), exe("/usr/local/bin/goosed"), None),
        (
            "a script called goose under node".into(),
            node(&["node", "/srv/goose"]),
            None,
        ),
        // Aider: its console script under the Python of the tool
        // environment uv, pipx or aider-install made, or `python -m aider`.
        (
            "aider under uv's Python".into(),
            proc_with(
                Some(
                    "/home/u/.local/share/uv/python/cpython-3.12.11-linux-x86_64-gnu/bin/python3.12",
                ),
                "python3.12",
                Some(&[
                    "/home/u/.local/share/uv/tools/aider-chat/bin/python",
                    "/home/u/.local/bin/aider",
                    "--model",
                    "x",
                ]),
            ),
            Some(("aider", SAID)),
        ),
        (
            "aider under pipx's Python".into(),
            proc_with(
                Some("/usr/bin/python3.11"),
                "python3.11",
                Some(&[
                    "/home/u/.local/share/pipx/venvs/aider-chat/bin/python",
                    "/home/u/.local/share/pipx/venvs/aider-chat/bin/aider",
                ]),
            ),
            Some(("aider", SAID)),
        ),
        (
            "python -m aider".into(),
            proc_with(
                Some("/usr/bin/python3"),
                "python3",
                Some(&["python3", "-m", "aider", "--yes-always"]),
            ),
            Some(("aider", SAID)),
        ),
        // Not Aider: a program by that name (it is a Python script), its
        // installer, another script.
        ("an aider binary".into(), exe("/usr/local/bin/aider"), None),
        (
            "aider-install".into(),
            proc_with(
                Some("/usr/bin/python3"),
                "python3",
                Some(&["python3", "/home/u/.local/bin/aider-install"]),
            ),
            None,
        ),
        (
            "another python script".into(),
            proc_with(
                Some("/usr/bin/python3"),
                "python3",
                Some(&["python3", "/srv/aider_tools.py"]),
            ),
            None,
        ),
    ];
    let products = [
        ("claude-code", "claude-code"),
        ("cursor", "cursor"),
        ("gemini-cli", "gemini-cli"),
        ("copilot-cli", "copilot-cli"),
        ("opencode", "opencode"),
        ("kimi", "kimi"),
        ("qwen-code", "qwen-code"),
        ("goose", "goose"),
        ("aider", "aider"),
    ];
    for (what, p, want) in cases.drain(..) {
        let got = cat.classify(&p);
        let shown = got.as_ref().map(|l| (l.id.as_str(), l.basis));
        assert_eq!(shown, want, "{what}");
        if let Some(l) = got {
            assert_eq!(l.source, CatalogSource::Builtin, "{what}");
            assert_eq!(l.may_root_above_session(), l.basis == BY_EXE, "{what}");
            let product = products.iter().find(|(id, _)| *id == l.id).unwrap().1;
            assert_eq!(l.product, product, "{what}");
        }
    }
    // Markers from the agents' documentation are claims.
    for (marker, id) in [
        ("CLAUDE_CODE_CHILD_SESSION", "claude-code"),
        ("CURSOR_AGENT", "cursor"),
        ("CURSOR_SANDBOX", "cursor"),
        ("GEMINI_CLI", "gemini-cli"),
        ("GOOSE_TERMINAL", "goose"),
    ] {
        let l = cat.agent_for_marker(marker).unwrap();
        assert_eq!((l.id.as_str(), l.basis), (id, SAID), "{marker}");
        assert!(!l.may_root_above_session());
    }
    // `AGENT`, which Goose documents for every agent to set, is no marker.
    assert!(cat.agent_for_marker("AGENT").is_none());
    assert_eq!(cat.product("fixture"), Some("fixture"));
}

/// Install trees (M2 plan D-10): an agent's executable is in one when its
/// documented installer put it there; the same file anywhere else, and an
/// agent with no tree, is not.
#[test]
fn install_trees_name_where_each_agents_installers_put_it() {
    let cat = AgentCatalog::builtin();
    let home = Some(Path::new("/home/u"));
    let inside = [
        (
            "claude-code",
            "/home/u/.local/share/claude/versions/2.1.280",
        ),
        (
            "claude-code",
            "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
        ),
        (
            "claude-code",
            "/usr/lib/node_modules/@anthropic-ai/claude-code/node_modules/@anthropic-ai/claude-code-linux-x64/claude",
        ),
        (
            "codex",
            "/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex/codex",
        ),
        (
            "copilot-cli",
            "/usr/local/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot",
        ),
        ("opencode", "/home/u/.opencode/bin/opencode"),
        (
            "opencode",
            "/usr/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64/bin/opencode",
        ),
    ];
    for (id, path) in inside {
        assert!(
            cat.within_install_tree(id, Path::new(path), home),
            "{id} {path}"
        );
    }
    let outside = [
        ("claude-code", "/tmp/x/claude"),
        ("claude-code", "/home/u/.local/bin/claude"),
        (
            "claude-code",
            "/home/v/.local/share/claude/versions/2.1.280",
        ),
        ("claude-code", "/home/u/.local/share/claude/versions"),
        ("codex", "/home/u/bin/codex"),
        // Cursor is known by its script only: no tree.
        ("cursor", "/home/u/.local/bin/agent"),
        (
            "cursor",
            "/home/u/.local/share/cursor-agent/versions/2026.09.28-64d2043/node",
        ),
        // The install script's directories hold any program by that name
        // (the AWS Copilot CLI's too): no tree.
        ("copilot-cli", "/home/u/.local/bin/copilot"),
        ("copilot-cli", "/usr/local/bin/copilot"),
        ("copilot-cli", "/home/u/.local/bin/opencode/../copilot"),
        ("opencode", "/home/u/.local/bin/opencode"),
        // No Kimi Code build is pinned and measured: no tree.
        ("kimi", "/home/u/.kimi-code/bin/kimi"),
        ("kimi", "/home/u/.kimi/bin/kimi"),
        (
            "gemini-cli",
            "/usr/local/lib/node_modules/@google/gemini-cli/bundle/gemini.js",
        ),
        ("qwen-code", "/usr/local/bin/qwen"),
        // Goose is known by its name only, Aider by its script: no tree.
        ("goose", "/home/u/.local/bin/goose"),
        ("goose", "/usr/local/bin/goose"),
        ("aider", "/home/u/.local/bin/aider"),
        ("fixture", "/work/target/debug/fixture-agent"),
        ("no-such-agent", "/usr/local/bin/copilot"),
    ];
    for (id, path) in outside {
        assert!(
            !cat.within_install_tree(id, Path::new(path), home),
            "{id} {path}"
        );
    }
    // Another agent's tree is not this one's.
    assert!(!cat.within_install_tree("opencode", Path::new("/home/u/.local/bin/opencode"), home));
    assert!(!cat.within_install_tree(
        "claude-code",
        Path::new("/home/u/.kimi-code/bin/claude"),
        home
    ));
}

/// What makes an agent's own executable run other code, as measured on
/// its pinned builds (agent_hosts' `code_selecting_env_is_measured` checks
/// each on both systems): `BUN_OPTIONS` for Claude Code's native build and
/// `BUN_BE_BUN` for OpenCode's, nothing for Codex's or Copilot CLI's;
/// nothing is known for an agent with no executable identity or an
/// unknown id. Standing approvals read it (SPEC §10b).
#[test]
fn code_selecting_env_comes_from_the_builtin_catalog() {
    let cat = AgentCatalog::builtin();
    let measured: Vec<(&str, Vec<&str>)> = builtin_ids()
        .into_iter()
        .map(|id| {
            (
                id,
                cat.code_selecting_env(id)
                    .iter()
                    .map(String::as_str)
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        measured,
        [
            ("claude-code", vec!["BUN_OPTIONS"]),
            ("codex", vec![]),
            ("cursor", vec![]),
            ("gemini-cli", vec![]),
            ("copilot-cli", vec![]),
            ("opencode", vec!["BUN_BE_BUN"]),
            ("kimi", vec![]),
            ("qwen-code", vec![]),
            ("goose", vec![]),
            ("aider", vec![]),
            ("fixture", vec![]),
        ]
    );
    assert!(cat.code_selecting_env("no-such-agent").is_empty());
}

/// The rule standing approvals apply (SPEC §10b): a variable selects code
/// in an agent's process when it is a dynamic loader's (`LD_*`, `DYLD_*`),
/// for every agent and an unknown one alike, measured or not (verifier
/// review: `DYLD_INSERT_LIBRARIES` runs a library in OpenCode's macOS
/// build, which its `code_selecting_env` never listed, and `LD_PRELOAD`
/// in any dynamically linked Linux build), or one its entry lists. Nothing
/// else, and names compare whole and by case. Mutation checked: dropping
/// the `DYLD_` prefix, or the loader prefixes altogether, fails this test.
#[test]
fn a_loader_variable_selects_code_in_every_agent() {
    let cat = AgentCatalog::builtin();
    let mut ids = builtin_ids();
    ids.push("no-such-agent");
    for id in ids {
        for var in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
        ] {
            assert!(cat.env_selects_code(id, var.as_bytes()), "{id} {var}");
        }
        for var in [
            "LD",
            "DYLD",
            "OLD_PRELOAD",
            "ld_preload",
            "XDYLD_INSERT_LIBRARIES",
            "PATH",
            "HOME",
            "",
        ] {
            assert!(!cat.env_selects_code(id, var.as_bytes()), "{id} {var}");
        }
        for var in ["BUN_OPTIONS", "BUN_BE_BUN", "NODE_OPTIONS"] {
            assert_eq!(
                cat.env_selects_code(id, var.as_bytes()),
                cat.code_selecting_env(id).iter().any(|v| v == var),
                "{id} {var}"
            );
        }
    }
    assert!(cat.env_selects_code("claude-code", b"BUN_OPTIONS"));
    assert!(cat.env_selects_code("opencode", b"BUN_BE_BUN"));
    assert!(!cat.env_selects_code("opencode", b"BUN_BE_BUN_"));
    assert!(!cat.env_selects_code("codex", b"BUN_OPTIONS"));
}

/// Cursor's process is the node it ships, which runs any script: Cursor is
/// never matched by that node's path, so it roots no grant above a
/// command's session, has no install tree and no signature, and the node
/// it ships, running another script, is no agent at all.
#[test]
fn a_runtime_is_never_an_agents_identity() {
    let cat = AgentCatalog::builtin();
    let dir = "/home/u/.local/share/cursor-agent/versions/2026.09.28-64d2043";
    let cursor = proc_with(
        Some(&format!("{dir}/node")),
        "node",
        Some(&["/home/u/.local/bin/agent", &format!("{dir}/index.js")]),
    );
    let l = cat.classify(&cursor).unwrap();
    assert_eq!((l.id.as_str(), l.basis), ("cursor", MatchBasis::Asserted));
    assert!(!l.may_root_above_session());
    assert!(!cat.within_install_tree(
        "cursor",
        Path::new(&format!("{dir}/node")),
        Some(Path::new("/home/u"))
    ));
    let mut signed_node = signed(&format!("{dir}/node"), "node", Some("HX7739G8FX"));
    signed_node.argv = Some(Argv::new(["node", "/tmp/x.js"]));
    assert_eq!(id_of(&cat, &signed_node), None);
    // Interpreters are never matched by path or signature.
    for path in [
        "/usr/local/bin/node",
        "/usr/bin/python3.12",
        "/opt/bun/bin/bun",
    ] {
        assert_eq!(id_of(&cat, &exe(path)), None, "{path}");
    }
}

/// Codex review (medium): an interpreter placed where an agent's
/// `executables` pattern takes any name (`claude/versions/*`) is still an
/// interpreter. Its path matches no pattern: it is read by its script, as
/// an interpreter anywhere is (Claude Code's `cli.js` under it is Claude
/// Code on an asserted basis, which roots no grant above the session;
/// another script under it is no agent), and it is in no install tree.
/// So is one by a versioned name, an ABI-suffixed one, and one an
/// extension's wildcard takes in. The agent's own build at the same place
/// is still its executable. Mutation checked: letting a wildcard match an
/// interpreter's path fails this test (and the root-confinement tests in
/// tests/evidence.rs and tests/evidence_gates.rs); leaving interpreters in
/// install trees fails it too.
#[test]
fn an_interpreter_at_an_agents_path_is_no_identity() {
    let cat = AgentCatalog::builtin();
    let home = Some(Path::new("/home/u"));
    let versions = "/home/u/.local/share/claude/versions";
    let cli = "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js";
    for name in [
        "node",
        "node22",
        "bun",
        "python3.14t",
        "python3.13td",
        "Python",
    ] {
        let path = format!("{versions}/{name}");
        assert_eq!(id_of(&cat, &exe(&path)), None, "{path}");
        let running = proc_with(Some(&path), name, Some(&[name, "/tmp/x.js"]));
        assert_eq!(id_of(&cat, &running), None, "{path}");
        let claude = proc_with(Some(&path), name, Some(&[name, cli]));
        let l = cat.classify(&claude).unwrap();
        assert_eq!(
            (l.id.as_str(), l.basis),
            ("claude-code", MatchBasis::Asserted),
            "{path}"
        );
        assert!(!l.may_root_above_session(), "{path}");
        for id in ["claude-code", "opencode", "copilot-cli", "codex"] {
            assert!(
                !cat.within_install_tree(id, Path::new(&path), home),
                "{id} {path}"
            );
        }
        // Linux's mark of a removed file changes nothing.
        let deleted = format!("{path} (deleted)");
        assert_eq!(id_of(&cat, &exe(&deleted)), None, "{deleted}");
        assert!(!cat.within_install_tree("claude-code", Path::new(&deleted), home));
    }
    for (id, path) in [
        ("opencode", "/home/u/.opencode/bin/bun"),
        (
            "claude-code",
            "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/node",
        ),
        (
            "copilot-cli",
            "/usr/lib/node_modules/@github/copilot/node_modules/.bin/node",
        ),
    ] {
        assert!(
            !cat.within_install_tree(id, Path::new(path), home),
            "{id} {path}"
        );
    }
    // The control: the agent's own build there is its executable, in its
    // tree.
    let own = format!("{versions}/2.1.280");
    let l = cat.classify(&exe(&own)).unwrap();
    assert_eq!(
        (l.id.as_str(), l.basis),
        ("claude-code", MatchBasis::Executable)
    );
    assert!(l.may_root_above_session());
    assert!(cat.within_install_tree("claude-code", Path::new(&own), home));
    // An extension's wildcard takes in no interpreter either, builtin or
    // its own.
    let (root, dir) = data_dir();
    write(
        &dir,
        "a.toml",
        "interpreters = [\"ruby\"]\n[[agent]]\nid = \"tool\"\nname = \"Tool\"\nexecutables = [\"tool/bin/*\"]\n",
    );
    let ext = AgentCatalog::load(root.path());
    assert!(ext.problems().is_empty());
    for name in ["node", "python3.14t", "ruby", "ruby3.3"] {
        let path = format!("/opt/tool/bin/{name}");
        assert_eq!(id_of(&ext, &exe(&path)), None, "{path}");
    }
    let l = ext.classify(&exe("/opt/tool/bin/tool")).unwrap();
    assert_eq!(
        (l.id.as_str(), l.source, l.basis),
        ("tool", CatalogSource::Extension, MatchBasis::Executable)
    );
}

/// `names` are names, never an identity: a match on one is asserted, from
/// the executable's file name, `argv[0]` or the command name (cut to the
/// length the kernel keeps), and an extension may add them. Each name is
/// 1 to 64 bytes without `/` or control characters.
#[test]
fn names_are_asserted_and_checked() {
    let (root, dir) = data_dir();
    write(
        &dir,
        "a.toml",
        "[[agent]]\nid = \"pairbot\"\nname = \"Pairbot\"\nnames = [\"pairbot\", \"Pairbot Chat Assistant 1\"]\n",
    );
    for (file, names) in [
        ("b.toml", "[\"a/b\"]"),
        ("c.toml", "[\"\"]"),
        ("d.toml", "[\"a\\u0007b\"]"),
        ("e.toml", "[\"..\"]"),
    ] {
        write(
            &dir,
            file,
            &format!(
                "[[agent]]\nid = \"x{}\"\nname = \"X\"\nnames = {names}\n",
                &file[..1]
            ),
        );
    }
    write(
        &dir,
        "f.toml",
        &format!(
            "[[agent]]\nid = \"xf\"\nname = \"X\"\nnames = [\"{}\"]\n",
            "a".repeat(65)
        ),
    );
    let cat = AgentCatalog::load(root.path());
    let kinds: Vec<(String, CatalogErrorKind)> = cat
        .problems()
        .iter()
        .map(|p| (p.file.to_string_lossy().into_owned(), p.error.kind()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("b.toml".to_owned(), CatalogErrorKind::InvalidAgentName),
            ("c.toml".to_owned(), CatalogErrorKind::InvalidAgentName),
            ("d.toml".to_owned(), CatalogErrorKind::InvalidAgentName),
            ("e.toml".to_owned(), CatalogErrorKind::InvalidAgentName),
            ("f.toml".to_owned(), CatalogErrorKind::InvalidAgentName),
        ]
    );
    for p in [
        exe("/usr/local/bin/pairbot"),
        proc_with(
            Some("/usr/bin/python3"),
            "python3",
            Some(&["/x/pairbot", "--yes"]),
        ),
        proc_with(Some("/usr/bin/python3"), "Pairbot Chat As", None),
    ] {
        let l = cat.classify(&p).unwrap();
        assert_eq!(
            (l.id.as_str(), l.source, l.basis),
            ("pairbot", CatalogSource::Extension, MatchBasis::Asserted),
            "{p:?}"
        );
    }
    assert_eq!(
        id_of(&cat, &proc_with(Some("/usr/bin/python3"), "Pairbot", None)),
        None
    );
}

/// Only the builtin catalog records what makes an agent's executable run
/// other code: an extension that lists `code_selecting_env` is skipped and
/// reported, like one with install trees.
#[test]
fn code_selecting_env_is_the_builtin_catalogs_alone() {
    let (root, dir) = data_dir();
    write(
        &dir,
        "a.toml",
        "[[agent]]\nid = \"opencode\"\nexecutables = [\"oc\"]\ncode_selecting_env = [\"NODE_OPTIONS\"]\n",
    );
    write(
        &dir,
        "b.toml",
        "[[agent]]\nid = \"y\"\nname = \"Y\"\nexecutables = [\"y\"]\ncode_selecting_env = [\"1BAD\"]\n",
    );
    let cat = AgentCatalog::load(root.path());
    let kinds: Vec<(String, CatalogErrorKind)> = cat
        .problems()
        .iter()
        .map(|p| (p.file.to_string_lossy().into_owned(), p.error.kind()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("a.toml".to_owned(), CatalogErrorKind::BuiltinOnly),
            ("b.toml".to_owned(), CatalogErrorKind::InvalidMarker),
        ]
    );
    assert_eq!(cat.code_selecting_env("opencode"), ["BUN_BE_BUN"]);
    assert_eq!(id_of(&cat, &exe("/usr/bin/oc")), None, "a.toml was skipped");
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
    ] {
        let p = exe(path);
        assert_eq!(id_of(&cat, &p), None, "{path}");
        assert!(!cat.needs_argv(&p), "{path}");
    }
    // Python is an interpreter (kimi-cli runs under it): its arguments are
    // read, and a script that is no agent's is no agent.
    let p = exe("/usr/bin/python3");
    assert!(cat.needs_argv(&p));
    assert_eq!(id_of(&cat, &p), None);
    let p = proc_with(
        Some("/usr/bin/python3.12"),
        "python3.12",
        Some(&["python3", "/srv/manage.py", "runserver"]),
    );
    assert_eq!(id_of(&cat, &p), None);
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
    assert_eq!(cat.ids().count(), builtin_ids().len());
}

#[test]
fn extensions_add_agents_patterns_and_interpreters() {
    let (root, dir) = data_dir();
    write(
        &dir,
        "pairbot.toml",
        r#"interpreters = ["python3"]

[[agent]]
id = "pairbot"
name = "Pairbot"
executables = ["pairbot"]
scripts = ["pairbot"]
markers = ["PAIRBOT_SESSION"]
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
    let mut want = builtin_ids();
    want.push("pairbot");
    assert_eq!(cat.ids().collect::<Vec<_>>(), want);

    let l = cat.classify(&exe("/usr/local/bin/pairbot")).unwrap();
    assert_eq!((l.id.as_str(), l.name.as_str()), ("pairbot", "Pairbot"));
    assert_eq!(l.source, CatalogSource::Extension);
    let py = proc_with(
        Some("/usr/bin/python3"),
        "python3",
        Some(&["python3", "/home/u/.local/bin/pairbot", "--yes"]),
    );
    assert!(cat.needs_argv(&py));
    assert_eq!(cat.classify(&py).unwrap().id, "pairbot");

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
    assert_eq!(
        cat.agent_for_marker("PAIRBOT_SESSION").unwrap().id,
        "pairbot"
    );
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
        "[[agent]]\nid = \"pairbot\"\nname = \"Pairbot\"\nproduct = \"pairbot-chat\"\n\
         executables = [\"pairbot\"]\n\n[[agent]]\nid = \"codex\"\nproduct = \"other\"\n\
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
    assert_eq!(cat.product("pairbot"), Some("pairbot-chat"));
    assert_eq!(cat.product("goose"), Some("goose"));
    assert_eq!(cat.product("codex"), Some("codex"));
    assert_eq!(cat.product("nothing"), None);
    let l = cat.classify(&exe("/usr/local/bin/codex-nightly")).unwrap();
    assert_eq!((l.id.as_str(), l.product.as_str()), ("codex", "codex"));
    assert_eq!(
        cat.classify(&exe("/usr/local/bin/pairbot"))
            .unwrap()
            .product,
        "pairbot-chat"
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
    assert!(!cat.within_install_tree("pairbot", Path::new("/usr/local/bin/pairbot"), None));
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
        "[[agent]]\nid = \"pairbot\"\nname = \"Pairbot\"\nexecutables = [\"pairbot\"]\n",
    );
    let cat = AgentCatalog::load(root.path());
    let l = cat.classify(&exe("/usr/local/bin/pairbot")).unwrap();
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
    assert_eq!(cat.ids().count(), builtin_ids().len());
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
    assert_eq!(cat.ids().count(), builtin_ids().len() + MAX_EXTENSION_FILES);
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
