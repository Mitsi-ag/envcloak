//! End-to-end and integration tests for `envcloak agents migrate-mcp` and
//! `envcloak agents migrate-mcp --update` (SPEC §6.6; M2 plan D-02, D-05,
//! D-16, D-17, D-18, D-33, CR-2; task M2-20; gates 13, 39).
//!
//! Cursor, Gemini, Copilot, Kimi, and OpenCode modules are tested here on
//! doc-derived fixtures (labelled the weaker oracle; M2-24 repeats them on
//! configs the CI-installed hosts wrote).
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use common::{
    approve_ticking, cli, cli_command, data_dir, finish_within, on_terminal_command, outside_dir,
    python3, run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_core::file_backup_v2::list_file_backups_v2;
use envcloak_core::vault::VaultPaths;
use envcloak_testkit::{
    Canary, Daemon, TEST_PATH, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
    sweep_dir, testkit_bin,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FAKE_CLAUDE: &str = r#"
import json, os, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("2.1.280 (Claude Code)")
    sys.exit(0)
d = os.environ.get("CLAUDE_CONFIG_DIR")
path = os.path.join(d, ".claude.json") if d else os.path.join(os.environ["HOME"], ".claude.json")
def load():
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
def save(v):
    with open(path + ".tmp", "w") as f:
        json.dump(v, f, indent=2)
    os.rename(path + ".tmp", path)
if args[:4] == ["mcp", "add-json", "--scope", "user"] and len(args) == 6:
    v = load()
    servers = v.setdefault("mcpServers", {})
    if args[4] in servers:
        sys.exit("MCP server " + args[4] + " already exists in user config")
    servers[args[4]] = json.loads(args[5])
    save(v)
    sys.exit(0)
if args[:4] == ["mcp", "remove", "--scope", "user"] and len(args) == 5:
    v = load()
    if args[4] not in v.get("mcpServers", {}):
        sys.exit("No user-scoped MCP server found with name: " + args[4])
    del v["mcpServers"][args[4]]
    save(v)
    sys.exit(0)
if args[:2] == ["mcp", "get"] and len(args) == 3:
    sys.exit(0 if args[2] in load().get("mcpServers", {}) else 1)
if args == ["mcp", "list"]:
    for name in load().get("mcpServers", {}):
        print(name)
    sys.exit(0)
sys.exit(2)
"#;

const FAKE_CODEX: &str = r#"
import os, sys, tomllib
args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 0.159.2")
    sys.exit(0)
if args == ["mcp", "list"]:
    home = os.environ.get("CODEX_HOME") or os.path.join(os.environ["HOME"], ".codex")
    with open(os.path.join(home, "config.toml"), "rb") as f:
        for name in tomllib.load(f).get("mcp_servers", {}):
            print(name)
    sys.exit(0)
sys.exit(2)
"#;

const OLD: Duration = Duration::from_secs(180);

fn age(p: &Path, ago: Duration) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - ago)
        .unwrap();
}

fn sha256_file(p: &Path) -> [u8; 32] {
    Sha256::digest(std::fs::read(p).unwrap()).into()
}

struct MigrateWorld {
    cs: Vec<Canary>,
    home: TestHome,
    daemon: Daemon,
    files: tempfile::TempDir,
    pass_file: PathBuf,
    bin: PathBuf,
}

impl MigrateWorld {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        cs.push(Canary::new(
            "CUSTOM_BRIDGE_HEADER",
            format!("Bearer mcp-custom-alpha-{seed_a:016x}-secret"),
        ));
        cs.push(Canary::new(
            "CUSTOM_BRIDGE_ENV",
            format!("mcp-custom-beta-{seed_b:016x}-token"),
        ));

        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        cs.push(kit);
        let daemon = start_daemon(&home);
        let files = outside_dir();
        let pass_file = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = run_on_terminal(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass_file, true)],
        );
        assert!(out.status.success(), "{}", stderr(&out));

        let bin = home.root().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let py = python3();
        for (name, body) in [("claude", FAKE_CLAUDE), ("codex", FAKE_CODEX)] {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!{}\n{body}", py.display())).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let npx = bin.join("npx");
        std::fs::write(&npx, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&npx, std::fs::Permissions::from_mode(0o755)).unwrap();

        std::fs::create_dir_all(home.home().join(".claude")).unwrap();
        std::fs::create_dir_all(home.home().join(".codex")).unwrap();

        Self {
            cs,
            home,
            daemon,
            files,
            pass_file,
            bin,
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.home().join(rel)
    }

    fn value(&self, label: &str) -> &str {
        by_label(&self.cs, label).as_str()
    }

    fn path_env(&self) -> String {
        format!("{}:{TEST_PATH}", self.bin.display())
    }

    fn host(&self, name: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(self.bin.join(name));
        self.home
            .apply(&mut cmd)
            .env("PATH", self.path_env())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        finish_within(cmd, Duration::from_secs(30))
    }

    fn run_terminal(&self, args: &[&str]) -> Output {
        let mut cmd = on_terminal_command(&self.home, args, &[(3, &self.pass_file, true)]);
        cmd.env("PATH", self.path_env());
        let out = finish_within(cmd, Duration::from_secs(60));
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    fn run_detached(&self, args: &[&str]) -> Output {
        let mut cmd = cli_command(&self.home, args, &[]);
        cmd.env("PATH", self.path_env());
        let out = finish_within(cmd, Duration::from_secs(60));
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        out
    }

    fn spawn_agent_bridge(&self, args: &[&str]) -> Child {
        let mut cmd = Command::new(testkit_bin("fixture-agent"));
        self.home
            .apply(&mut cmd)
            .env("PATH", self.path_env())
            .arg("--")
            .arg(cli())
            .args(args)
            .current_dir(self.home.home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.spawn().unwrap()
    }

    fn call_stdio_launch(
        &self,
        launch_id: &str,
        approve_flags: Option<&[&str]>,
    ) -> (Output, Value) {
        let mut args = vec!["mcp-bridge", "--stdio", "--launch", launch_id];
        if approve_flags.is_some() {
            args.extend_from_slice(&["--wait", "30s"]);
        }
        let mut child = self.spawn_agent_bridge(&args);
        let mut child_stdin = child.stdin.take().unwrap();
        let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
        let mut child_stderr = BufReader::new(child.stderr.take().unwrap());

        if let Some(flags) = approve_flags {
            let mut pending_line = String::new();
            child_stderr.read_line(&mut pending_line).unwrap();
            assert!(
                pending_line.contains("approval_required"),
                "expected approval_required on stderr: {pending_line}"
            );
            let req_id = pending_line
                .split("request=")
                .nth(1)
                .and_then(|s| s.get(..8))
                .unwrap()
                .to_owned();
            let app = approve_ticking(&self.home, &req_id, flags, &self.pass_file);
            assert!(
                app.status.success(),
                "approve {req_id} failed: {}\n{}",
                stdout(&app),
                stderr(&app)
            );
            writeln!(
                child_stdin,
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call"}}"#
            )
            .unwrap();
            child_stdin.flush().unwrap();
            let mut reply_line = String::new();
            child_stdout.read_line(&mut reply_line).unwrap();
            drop(child_stdin);
            let mut stderr_bytes = Vec::new();
            let _ = child_stderr.read_to_end(&mut stderr_bytes);
            let status = child.wait().unwrap();
            let stdout_bytes = reply_line.into_bytes();
            assert_no_canary(&stdout_bytes, &self.cs);
            assert_no_canary(&stderr_bytes, &self.cs);
            let reply = serde_json::from_slice(&stdout_bytes).unwrap_or(Value::Null);
            let out = Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            };
            return (out, reply);
        }

        drop(child_stdin);
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let _ = child_stdout.read_to_end(&mut stdout_bytes);
        let _ = child_stderr.read_to_end(&mut stderr_bytes);
        let status = child.wait().unwrap();
        assert_no_canary(&stdout_bytes, &self.cs);
        assert_no_canary(&stderr_bytes, &self.cs);
        let out = Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        };
        let reply = if out.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
        };
        (out, reply)
    }

    fn compile_native_mcp_server(&self, name: &str, version_tag: u32, env_var: &str) -> PathBuf {
        let src = self.files.path().join(format!("{name}_{version_tag}.c"));
        let bin = self.home.root().join(name);
        let tmp_bin = self.files.path().join(format!("{name}_{version_tag}.bin"));
        let code = format!(
            r#"#include <stdio.h>
#include <stdlib.h>
int main(void) {{
    char buf[1024];
    const char *v = getenv({env_var:?});
    int present = (v != NULL && v[0] != '\0');
    while (fgets(buf, sizeof(buf), stdin) != NULL) {{
        printf("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"present\":%s,\"version\":{version_tag}}}}}\n",
               present ? "true" : "false");
        fflush(stdout);
    }}
    return 0;
}}
"#
        );
        std::fs::write(&src, code).unwrap();
        let st = Command::new("/usr/bin/cc")
            .args(["-O1", "-o"])
            .arg(&tmp_bin)
            .arg(&src)
            .status()
            .expect("cc compile native mcp server");
        assert!(st.success(), "cc failed");
        std::fs::copy(&tmp_bin, &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    fn sweep(&self) {
        assert_no_canary(&self.daemon.log_bytes(), &self.cs);
        assert!(
            sweep_dir(&data_dir(&self.home).join("backups"), &self.cs).is_empty(),
            "encrypted-backup exposure detected"
        );
        self.home.assert_clean(&self.cs);
    }
}

/// Gate 39: Claude Code (`claude mcp add-json`), Codex (`config.toml`), stdio
/// and HTTP bridge servers (including a server with both a header and an `env`
/// secret), launch classes (`native`/`bound`, `script`/`checked_at_rest`,
/// `package_runner`/`checked_at_rest`), standing approval eligibility on
/// `bound` + `test` keys, `claude mcp list` and `codex mcp list` parsing,
/// tool execution after approval, and `--undo` byte-for-byte restore.
#[test]
fn gate39_claude_and_codex_migration_classes_receipts_standing_and_undo() {
    let w = MigrateWorld::new();
    let native_bin = w.compile_native_mcp_server("native-mcp", 1, "STRIPE_KEY");
    let script_py = w.home.root().join("script_mcp.py");
    std::fs::write(
        &script_py,
        concat!(
            "import json, os, sys\n",
            "for line in sys.stdin:\n",
            "    msg = json.loads(line)\n",
            "    has_key = bool(os.environ.get('OPENAI_API_KEY'))\n",
            "    mode = os.environ.get('MODE', '')\n",
            "    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg.get('id'),'result':{'present':has_key,'mode':mode}}) + '\\n')\n",
            "    sys.stdout.flush()\n",
        ),
    )
    .unwrap();

    let stripe_test = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();
    let github_tok = w.value(labels::GITHUB_TOKEN).to_owned();
    let bridge_hdr = w.value("CUSTOM_BRIDGE_HEADER").to_owned();
    let bridge_env = w.value("CUSTOM_BRIDGE_ENV").to_owned();

    // 1. Add a native server (bound + test key) and an HTTP bridge server (with BOTH
    //    headers and env secret) via `claude mcp add-json`.
    let claude_native_payload = json!({
        "command": native_bin.to_str().unwrap(),
        "args": ["--port", "9100"],
        "env": {
            "STRIPE_KEY": stripe_test,
        }
    });
    let out = w.host(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "stripe-native",
            &claude_native_payload.to_string(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let claude_http_payload = json!({
        "url": "https://mcp.example.com/v1/sse",
        "headers": {
            "Authorization": bridge_hdr,
        },
        "env": {
            "EXTRA_BRIDGE_TOKEN": bridge_env,
        }
    });
    let out = w.host(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "remote-http",
            &claude_http_payload.to_string(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    // 2. Write Codex `config.toml` with a `script` server and a `package_runner` (`npx`) server.
    let py = python3();
    let codex_before = format!(
        r#"model = "gpt-5"

[mcp_servers.py_srv]
command = {:?}
args = [{:?}]
env = {{ OPENAI_API_KEY = {:?}, MODE = "initial" }}

[mcp_servers.npx_srv]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-everything"]
env = {{ GITHUB_TOKEN = {:?} }}
"#,
        py.to_str().unwrap(),
        script_py.to_str().unwrap(),
        openai_live,
        github_tok,
    );
    std::fs::write(w.path(".codex/config.toml"), &codex_before).unwrap();

    age(&w.path(".claude.json"), OLD);
    age(&w.path(".codex/config.toml"), OLD);

    let claude_bytes_before = std::fs::read(w.path(".claude.json")).unwrap();
    let codex_bytes_before = std::fs::read(w.path(".codex/config.toml")).unwrap();

    // 3. Dry run changes no byte on disk.
    let dry = w.run_detached(&["agents", "migrate-mcp", "--dry-run", "--json"]);
    assert!(dry.status.success(), "{}", stderr(&dry));
    assert_eq!(
        std::fs::read(w.path(".claude.json")).unwrap(),
        claude_bytes_before
    );
    assert_eq!(
        std::fs::read(w.path(".codex/config.toml")).unwrap(),
        codex_bytes_before
    );

    // 4. Apply migration with `--yes --passphrase-fd 3`.
    let mig_out = w.run_terminal(&["agents", "migrate-mcp", "--yes", "--passphrase-fd", "3"]);
    assert!(
        mig_out.status.success(),
        "migrate-mcp failed: {}\n{}",
        stdout(&mig_out),
        stderr(&mig_out)
    );
    let mig_text = stdout(&mig_out);
    assert!(mig_text.contains("envcloak pending"), "{mig_text}");
    assert!(
        mig_text.contains(
            "`claude-code/stripe-native` is `bound` and binds only `test`-classified items"
        ),
        "expected standing suggestion for native bound test server: {mig_text}"
    );
    assert!(
        !mig_text.contains("`codex/npx_srv` is `bound`"),
        "package_runner must never be suggested for --standing: {mig_text}"
    );
    assert!(
        !mig_text.contains("`codex/py_srv` is `bound`"),
        "script must never be suggested for --standing: {mig_text}"
    );
    assert!(
        mig_text.contains("the guarantee covers the server's main executable only, not its dynamic loader, the shared libraries it loads or anything they load"),
        "expected dynamic loader / shared libraries sentence in receipt: {mig_text}"
    );
    assert!(
        mig_text.contains("only this server's exact command can receive its key, but any program claude-code runs can start that command and read the key from its environment"),
        "expected D-05 residual sentence in receipt: {mig_text}"
    );
    assert!(
        mig_text.contains(
            "checked_at_rest: EnvCloak checks the interpreter and the entry script before launch"
        ),
        "expected script receipt sentence: {mig_text}"
    );
    assert!(
        mig_text.contains("checked_at_rest: the code that runs is chosen by npx at launch; to pin it, install the package and register its entry file"),
        "expected package_runner receipt sentence: {mig_text}"
    );
    assert!(
        mig_text.contains("codex startup_timeout_sec set to 60"),
        "expected Codex startup_timeout_sec raise with --yes consent: {mig_text}"
    );

    // 5. Sweep all files in HOME and backups for every canary encoding!
    w.sweep();

    // 6. Verify `claude mcp list` and `codex mcp list` parse the rewritten configs.
    let claude_list = w.host("claude", &["mcp", "list"]);
    assert!(claude_list.status.success(), "{}", stderr(&claude_list));
    assert!(stdout(&claude_list).contains("stripe-native"));
    assert!(stdout(&claude_list).contains("remote-http"));

    let codex_list = w.host("codex", &["mcp", "list"]);
    assert!(codex_list.status.success(), "{}", stderr(&codex_list));
    assert!(stdout(&codex_list).contains("py_srv"));
    assert!(stdout(&codex_list).contains("npx_srv"));

    // 7. Verify rewritten entries hold only `mcp-bridge` and no original argv or env.
    let claude_after: Value =
        serde_json::from_slice(&std::fs::read(w.path(".claude.json")).unwrap()).unwrap();
    let native_entry = &claude_after["mcpServers"]["stripe-native"];
    assert!(native_entry.get("env").is_none(), "{native_entry}");
    let native_args: Vec<&str> = native_entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(native_args[..3], ["mcp-bridge", "--stdio", "--launch"]);
    assert_eq!(native_args.len(), 4);
    let native_launch_id = native_args[3].to_owned();

    let http_entry = &claude_after["mcpServers"]["remote-http"];
    assert!(http_entry.get("headers").is_none(), "{http_entry}");
    assert!(http_entry.get("env").is_none(), "{http_entry}");
    let http_args: Vec<&str> = http_entry["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(http_args[0], "mcp-bridge");
    assert!(http_args.contains(&"--manifest"));
    assert!(http_args.contains(&"--url"));
    assert!(http_args.contains(&"--header"));

    let codex_after_str = std::fs::read_to_string(w.path(".codex/config.toml")).unwrap();
    assert!(
        !codex_after_str.contains("script_mcp.py"),
        "{codex_after_str}"
    );
    assert!(
        !codex_after_str.contains("server-everything"),
        "{codex_after_str}"
    );
    assert!(
        codex_after_str.contains("startup_timeout_sec = 60"),
        "{codex_after_str}"
    );
    let py_launch_id =
        envcloak_agents::migrate::lookup_launch_id(&data_dir(&w.home), "codex/py_srv").unwrap();
    assert!(
        codex_after_str.contains(&format!(
            "args = [\"mcp-bridge\", \"--stdio\", \"--launch\", {py_launch_id:?}]"
        )),
        "{codex_after_str}"
    );

    // 8. Run the rewritten stdio servers and verify approval and tool execution!
    let (out1, reply1) = w.call_stdio_launch(&native_launch_id, Some(&[]));
    assert!(out1.status.success(), "{}", stderr(&out1));
    assert_eq!(reply1["result"]["present"], true);
    assert_eq!(reply1["result"]["version"], 1);

    // Run `codex/py_srv` (`script` class) with a session approval.
    let (out3, reply3) = w.call_stdio_launch(&py_launch_id, Some(&[]));
    assert!(out3.status.success(), "{}", stderr(&out3));
    assert_eq!(reply3["result"]["present"], true);
    assert_eq!(reply3["result"]["mode"], "initial");

    // 9. Undo restores byte-for-byte with one passphrase and unregisters the servers.
    let backups = list_file_backups_v2(&VaultPaths::under(data_dir(&w.home))).unwrap();
    let backup_id = backups.last().unwrap().id.to_string();

    let undo_out = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--undo",
        &backup_id,
        "--passphrase-fd",
        "3",
    ]);
    assert!(
        undo_out.status.success(),
        "undo failed: {}\n{}",
        stdout(&undo_out),
        stderr(&undo_out)
    );
    assert_eq!(
        std::fs::read(w.path(".claude.json")).unwrap(),
        claude_bytes_before,
        "~/.claude.json must be restored byte for byte"
    );
    assert_eq!(
        std::fs::read(w.path(".codex/config.toml")).unwrap(),
        codex_bytes_before,
        "~/.codex/config.toml must be restored byte for byte"
    );

    // After undo, the launch id is unregistered (`managed_command_mismatch`).
    let (unreg_out, _) = w.call_stdio_launch(&native_launch_id, None);
    assert!(!unreg_out.status.success());
    assert!(
        stderr(&unreg_out).contains("managed_command_mismatch"),
        "{}",
        stderr(&unreg_out)
    );
}

/// CR-2: `--update` against the actual rewritten config:
/// - Never reads a declaration from the host config (which holds only `mcp-bridge --stdio --launch <id>`).
/// - Replacing the fixture's executable causes `managed_launch_changed` on the next launch.
/// - `--update claude-code/<server>` with no changes shows old and new identity from the stored
///   declaration, bumps revision, leaves both host config files byte-identical (SHA-256 before
///   and after), and the next launch succeeds.
/// - `--update claude-code/<server> --cwd <dir> --env MODE=fast --unset-env DEBUG -- <python3> /abs/server2.py`
///   shows each change, the new class `script` and its receipt, leaves host configs byte-identical,
///   and the next launch runs the new argv in the new directory.
/// - `--update` with `--env OPENAI_API_KEY=<key-shaped>` is refused before any daemon contact
///   with "add it with `envcloak add` and bind it in the managed manifest" and no value in output.
/// - `--update` for an unmigrated server names `migrate-mcp`.
#[test]
fn gate39_cr2_update_against_rewritten_configs_and_refusals() {
    let w = MigrateWorld::new();
    let native_bin = w.compile_native_mcp_server("updatable-mcp", 1, "STRIPE_KEY");
    let stripe_test = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();

    let claude_payload = json!({
        "command": native_bin.to_str().unwrap(),
        "args": ["--port", "9200"],
        "env": {
            "STRIPE_KEY": stripe_test,
            "DEBUG": "1",
        }
    });
    let out = w.host(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "updatable",
            &claude_payload.to_string(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let codex_toml = format!(
        r#"[mcp_servers.codex_srv]
command = {:?}
args = ["--port", "9201"]
env = {{ STRIPE_KEY = {:?} }}
"#,
        native_bin.to_str().unwrap(),
        stripe_test,
    );
    std::fs::write(w.path(".codex/config.toml"), &codex_toml).unwrap();
    age(&w.path(".claude.json"), OLD);
    age(&w.path(".codex/config.toml"), OLD);

    let mig = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--yes",
        "--passphrase-fd",
        "3",
        "--json",
    ]);
    assert!(mig.status.success(), "{}", stderr(&mig));
    let mig_json: Value = serde_json::from_slice(&mig.stdout).unwrap();
    let claude_srv = mig_json["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["agent"] == "claude-code" && s["server"] == "updatable")
        .unwrap();
    let launch_id = claude_srv["launch_id"].as_str().unwrap().to_owned();
    let old_identity = claude_srv["receipt"]["identity"]
        .as_str()
        .unwrap()
        .to_owned();

    let claude_sha_before = sha256_file(&w.path(".claude.json"));
    let codex_sha_before = sha256_file(&w.path(".codex/config.toml"));

    // 1. Replace the native binary with version 2 -> next call is refused `managed_launch_changed`.
    w.compile_native_mcp_server("updatable-mcp", 2, "STRIPE_KEY");
    let (changed_out, _) = w.call_stdio_launch(&launch_id, None);
    assert!(!changed_out.status.success());
    assert!(
        stderr(&changed_out).contains("managed_launch_changed"),
        "expected managed_launch_changed: {}",
        stderr(&changed_out)
    );

    // 2. `--update claude-code/updatable` with no changes re-resolves from stored declaration,
    //    shows old and new identity, bumps revision 1 -> 2, and leaves both host configs byte-identical.
    let upd1 = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--update",
        "claude-code/updatable",
        "--passphrase-fd",
        "3",
    ]);
    assert!(
        upd1.status.success(),
        "update failed: {}\n{}",
        stdout(&upd1),
        stderr(&upd1)
    );
    let upd1_text = stdout(&upd1);
    assert!(upd1_text.contains("revision 1 -> 2"), "{upd1_text}");
    assert!(
        upd1_text.contains(&old_identity),
        "expected old identity in statement: {upd1_text}"
    );
    assert!(upd1_text.contains("class: native (bound)"), "{upd1_text}");

    assert_eq!(
        sha256_file(&w.path(".claude.json")),
        claude_sha_before,
        "--update must not touch ~/.claude.json"
    );
    assert_eq!(
        sha256_file(&w.path(".codex/config.toml")),
        codex_sha_before,
        "--update must not touch ~/.codex/config.toml"
    );

    // Next launch succeeds and runs version 2!
    let (ok_out, ok_reply) = w.call_stdio_launch(&launch_id, Some(&[]));
    assert!(ok_out.status.success(), "{}", stderr(&ok_out));
    assert_eq!(ok_reply["result"]["present"], true);
    assert_eq!(ok_reply["result"]["version"], 2);

    // 3. `--update claude-code/updatable --cwd <dir> --env MODE=fast --unset-env DEBUG -- <python3> /abs/server2.py`
    let new_cwd = w.home.root().join("updated-cwd");
    std::fs::create_dir_all(&new_cwd).unwrap();
    let new_cwd_canon = std::fs::canonicalize(&new_cwd).unwrap();
    let server2_py = new_cwd_canon.join("server2.py");
    std::fs::write(
        &server2_py,
        concat!(
            "import json, os, sys\n",
            "for line in sys.stdin:\n",
            "    msg = json.loads(line)\n",
            "    res = {\n",
            "        'present': bool(os.environ.get('STRIPE_KEY')),\n",
            "        'mode': os.environ.get('MODE'),\n",
            "        'debug_unset': 'DEBUG' not in os.environ,\n",
            "        'cwd': os.path.realpath(os.getcwd()),\n",
            "    }\n",
            "    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg.get('id'),'result':res}) + '\\n')\n",
            "    sys.stdout.flush()\n",
        ),
    )
    .unwrap();

    let py = python3();
    let upd2 = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--update",
        "claude-code/updatable",
        "--cwd",
        new_cwd_canon.to_str().unwrap(),
        "--env",
        "MODE=fast",
        "--unset-env",
        "DEBUG",
        "--passphrase-fd",
        "3",
        "--",
        py.to_str().unwrap(),
        server2_py.to_str().unwrap(),
    ]);
    assert!(
        upd2.status.success(),
        "update 2 failed: {}\n{}",
        stdout(&upd2),
        stderr(&upd2)
    );
    let upd2_text = stdout(&upd2);
    assert!(upd2_text.contains("revision 2 -> 3"), "{upd2_text}");
    assert!(upd2_text.contains("MODE=fast"), "{upd2_text}");
    assert!(
        upd2_text.contains("new class: script (checked_at_rest)"),
        "{upd2_text}"
    );
    assert_eq!(sha256_file(&w.path(".claude.json")), claude_sha_before);
    assert_eq!(sha256_file(&w.path(".codex/config.toml")), codex_sha_before);

    let (ok2_out, ok2_reply) = w.call_stdio_launch(&launch_id, Some(&[]));
    assert!(ok2_out.status.success(), "{}", stderr(&ok2_out));
    assert_eq!(ok2_reply["result"]["present"], true);
    assert_eq!(ok2_reply["result"]["mode"], "fast");
    assert_eq!(ok2_reply["result"]["debug_unset"], true);
    assert_eq!(
        ok2_reply["result"]["cwd"].as_str().unwrap(),
        new_cwd_canon.to_str().unwrap()
    );

    // 4. `--update` for an unmigrated server names `migrate-mcp`.
    let unmig = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--update",
        "claude-code/does-not-exist",
        "--passphrase-fd",
        "3",
    ]);
    assert!(!unmig.status.success());
    assert!(
        stderr(&unmig).contains("envcloak agents migrate-mcp"),
        "expected unmigrated server error to name migrate-mcp: {}",
        stderr(&unmig)
    );

    // 5. Gate 13: `--update` with key-shaped `--env` or argv is refused BEFORE any daemon
    //    contact (verified by pointing `XDG_RUNTIME_DIR` / `HOME` at a nonexistent socket or
    //    checking exit 2 `value_on_argv`), with the exact guidance message and zero canary leak.
    let env_kv = format!("OPENAI_API_KEY={openai_live}");
    let mut bad_cmd = cli_command(
        &w.home,
        &[
            "agents",
            "migrate-mcp",
            "--update",
            "claude-code/updatable",
            "--env",
            &env_kv,
        ],
        &[],
    );
    // Point runtime dir at an empty dir with no daemon socket so any socket contact would fail
    // with `daemon_unreachable` instead of `value_on_argv`.
    let no_sock_dir = w.files.path().join("no-daemon-sock");
    std::fs::create_dir_all(&no_sock_dir).unwrap();
    bad_cmd.env("XDG_RUNTIME_DIR", &no_sock_dir);
    let bad_out = finish_within(bad_cmd, Duration::from_secs(30));
    assert_no_canary(&bad_out.stdout, &w.cs);
    assert_no_canary(&bad_out.stderr, &w.cs);
    assert_eq!(bad_out.status.code(), Some(2), "{}", stderr(&bad_out));
    assert!(
        stderr(&bad_out).starts_with("envcloak: value_on_argv: ")
            && stderr(&bad_out)
                .contains("add it with `envcloak add` and bind it in the managed manifest"),
        "unexpected stderr: {}",
        stderr(&bad_out)
    );

    w.sweep();
}

/// `agents install` then `migrate-mcp` run back to back with no wait and no
/// backdated mtimes succeed (a file EnvCloak itself wrote and nobody changed
/// since is exempt from the 2-minute rule).
#[test]
fn gate39_install_then_migrate_mcp_back_to_back_without_waiting() {
    let w = MigrateWorld::new();
    let stripe_test = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();
    let native_bin = w.compile_native_mcp_server("back-to-back-mcp", 1, "STRIPE_KEY");

    let claude_payload = json!({
        "command": native_bin.to_str().unwrap(),
        "args": [],
        "env": {
            "STRIPE_KEY": stripe_test,
        }
    });
    let out = w.host(
        "claude",
        &[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "b2b-claude",
            &claude_payload.to_string(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    let codex_toml = format!(
        r#"model = "gpt-5"

[mcp_servers.b2b_codex]
command = {:?}
args = []
env = {{ OPENAI_API_KEY = {:?} }}
"#,
        native_bin.to_str().unwrap(),
        openai_live,
    );
    std::fs::write(w.path(".codex/config.toml"), &codex_toml).unwrap();
    std::fs::write(w.path(".claude/settings.json"), "{}\n").unwrap();

    // Age the initial pre-install files once, as a user's existing config is.
    age(&w.path(".claude.json"), OLD);
    age(&w.path(".claude/settings.json"), OLD);
    age(&w.path(".codex/config.toml"), OLD);

    // Run `agents install --yes` (which rewrites `.claude.json` via `claude mcp` and
    // `.codex/config.toml` directly, leaving both with fresh mtimes = now!).
    let inst = w.run_detached(&["agents", "install", "--yes"]);
    assert!(
        inst.status.success(),
        "agents install failed: {}\n{}",
        stdout(&inst),
        stderr(&inst)
    );

    // Immediately run `agents migrate-mcp --yes` with NO wait and NO backdated mtimes!
    let mig = w.run_terminal(&["agents", "migrate-mcp", "--yes", "--passphrase-fd", "3"]);
    assert!(
        mig.status.success(),
        "back-to-back migrate-mcp failed: {}\n{}",
        stdout(&mig),
        stderr(&mig)
    );
    w.sweep();
}

/// `kill -9` between backup and rename (pause point `migrate_mcp_backed_up`)
/// leaves the original or the migrated file, never a partial/truncated file,
/// and backups hold ciphertext only.
#[test]
fn gate39_kill_at_pause_point_leaves_whole_file_and_ciphertext_backup() {
    let w = MigrateWorld::new();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();
    let native_bin = w.compile_native_mcp_server("crash-mcp", 1, "OPENAI_API_KEY");

    let codex_before = format!(
        r#"model = "gpt-5"

[mcp_servers.crash_srv]
command = {:?}
args = []
env = {{ OPENAI_API_KEY = {:?} }}
"#,
        native_bin.to_str().unwrap(),
        openai_live,
    );
    let codex_path = w.path(".codex/config.toml");
    std::fs::write(&codex_path, &codex_before).unwrap();
    age(&codex_path, OLD);

    let pause_dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut cmd = on_terminal_command(
        &w.home,
        &["agents", "migrate-mcp", "--yes", "--passphrase-fd", "3"],
        &[(3, &w.pass_file, true)],
    );
    cmd.env("PATH", w.path_env());
    cmd.env("ENVCLOAK_TEST_PAUSE_DIR", pause_dir.path());
    let mut child = cmd.spawn().unwrap();

    let until = Instant::now() + Duration::from_secs(60);
    loop {
        if std::fs::read_dir(pause_dir.path()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .contains("migrate_mcp_backed_up")
        }) {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "migrate-mcp exited before pause"
        );
        assert!(Instant::now() < until, "timed out waiting for pause point");
        std::thread::sleep(Duration::from_millis(10));
    }

    // Backups directory must hold ciphertext only (zero canary matches).
    assert!(
        sweep_dir(&data_dir(&w.home).join("backups"), &w.cs).is_empty(),
        "backup plaintext exposure at pause point"
    );

    // Kill the process with SIGKILL.
    let _ = child.kill();
    let _ = child.wait();

    // Config file on disk must be the whole original file (since pause was before rename).
    let on_disk = std::fs::read_to_string(&codex_path).unwrap();
    assert_eq!(on_disk, codex_before);
}

/// Refusals and manual reporting:
/// - Running host (config file open in another process) is refused.
/// - JSONC (comments / trailing commas) is reported manual (`jsonc_unsupported`) and exits non-zero.
/// - Key-shaped literal in `args` is reported manual (`secret_in_args`) and never moved into argv.
/// - Goose YAML file, Copilot `mcp-secrets/`, OpenCode `auth.json` are each reported manual and exit non-zero.
/// - Server with `NODE_OPTIONS` in `env` is reported manual (`code_selecting_env`) and exits non-zero.
/// - D-17 helper opt-ins are reported unavailable until M9.
#[test]
fn gate39_refusals_running_host_jsonc_args_manual_stores_and_code_selecting() {
    let w = MigrateWorld::new();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();
    let stripe_test = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let github_tok = w.value(labels::GITHUB_TOKEN).to_owned();
    let native_bin = w.compile_native_mcp_server("refusal-mcp", 1, "STRIPE_KEY");

    // 1. Running host (file held open by another process) is refused.
    let codex_path = w.path(".codex/config.toml");
    std::fs::write(
        &codex_path,
        format!(
            "[mcp_servers.open_srv]\ncommand = {:?}\nargs = []\nenv = {{ STRIPE_KEY = {:?} }}\n",
            native_bin.to_str().unwrap(),
            stripe_test
        ),
    )
    .unwrap();
    age(&codex_path, OLD);

    let mut holder = Command::new(python3())
        .args([
            "-c",
            "import sys, time\nf = open(sys.argv[1], 'r')\nsys.stdout.write('ready\\n')\nsys.stdout.flush()\ntime.sleep(30)\n",
        ])
        .arg(&codex_path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready_line = String::new();
    BufReader::new(holder.stdout.take().unwrap())
        .read_line(&mut ready_line)
        .unwrap();
    assert_eq!(ready_line.trim(), "ready");

    let open_out = w.run_terminal(&["agents", "migrate-mcp", "--yes", "--passphrase-fd", "3"]);
    let _ = holder.kill();
    let _ = holder.wait();
    assert!(!open_out.status.success());
    assert!(
        stderr(&open_out).contains("open in another process"),
        "expected open in another process refusal: {}",
        stderr(&open_out)
    );
    std::fs::remove_file(&codex_path).unwrap();

    // 2. JSONC config, `args` literal, `NODE_OPTIONS`, Goose YAML, Copilot `mcp-secrets/`,
    //    OpenCode `auth.json`, and D-17 `headersHelper` opt-in.
    std::fs::create_dir_all(w.path(".cursor")).unwrap();
    std::fs::write(
        w.path(".cursor/mcp.json"),
        "// JSONC comment\n{\n  \"mcpServers\": {}\n}\n",
    )
    .unwrap();
    age(&w.path(".cursor/mcp.json"), OLD);

    let mcp_json = json!({
        "mcpServers": {
            "args-leak": {
                "command": native_bin.to_str().unwrap(),
                "args": [format!("--api-key={openai_live}")],
            },
            "code-sel": {
                "command": native_bin.to_str().unwrap(),
                "args": [],
                "env": {
                    "STRIPE_KEY": stripe_test,
                    "NODE_OPTIONS": "--require /tmp/preload.js",
                }
            },
            "helper-optin": {
                "url": "https://mcp.example.com/v1",
                "headersHelper": "/usr/local/bin/get-headers",
            }
        }
    });
    std::fs::write(w.path(".mcp.json"), mcp_json.to_string()).unwrap();
    age(&w.path(".mcp.json"), OLD);

    let goose_dir = w.home.root().join("config/goose");
    std::fs::create_dir_all(&goose_dir).unwrap();
    std::fs::write(
        goose_dir.join("config.yaml"),
        format!("extensions:\n  my_ext:\n    envs:\n      GITHUB_TOKEN: {github_tok}\n"),
    )
    .unwrap();
    age(&goose_dir.join("config.yaml"), OLD);

    let copilot_secrets = w.path(".copilot/mcp-secrets");
    std::fs::create_dir_all(&copilot_secrets).unwrap();
    std::fs::write(copilot_secrets.join("tok"), format!("{github_tok}\n")).unwrap();
    age(&copilot_secrets.join("tok"), OLD);

    let opencode_share = w.home.root().join("data/opencode");
    std::fs::create_dir_all(&opencode_share).unwrap();
    std::fs::write(
        opencode_share.join("auth.json"),
        json!({"openai": {"key": openai_live}}).to_string(),
    )
    .unwrap();
    age(&opencode_share.join("auth.json"), OLD);

    let man_out = w.run_detached(&["agents", "migrate-mcp", "--yes", "--json"]);
    assert!(
        !man_out.status.success(),
        "migrate-mcp must exit non-zero when manual items remain"
    );
    assert!(
        stderr(&man_out).contains("envcloak: incomplete:"),
        "expected incomplete error token: {}",
        stderr(&man_out)
    );
    let report: Value = serde_json::from_slice(&man_out.stdout).unwrap();
    assert_eq!(report["complete"], false);
    let items = report["manual_items"].as_array().unwrap();
    let reasons: Vec<&str> = items
        .iter()
        .map(|m| m["reason"].as_str().unwrap())
        .collect();
    for expected in [
        "invalid_json",
        "secret_in_args",
        "code_selecting_env",
        "unsupported_format",
        "manual_credentials",
    ] {
        assert!(
            reasons.contains(&expected),
            "missing manual reason `{expected}` in {reasons:?}"
        );
    }
    assert!(
        items
            .iter()
            .any(|m| m["agent"] == "goose" && m["reason"] == "unsupported_format"),
        "missing goose YAML manual item in {items:?}"
    );
    assert!(
        items
            .iter()
            .any(|m| m["agent"] == "copilot" && m["reason"] == "manual_credentials"),
        "missing copilot mcp-secrets manual item in {items:?}"
    );
    assert!(
        items
            .iter()
            .any(|m| m["agent"] == "opencode" && m["reason"] == "manual_credentials"),
        "missing opencode auth.json manual item in {items:?}"
    );
    let opt_ins: Vec<&str> = report["unavailable_opt_ins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["opt_in"].as_str().unwrap())
        .collect();
    assert!(opt_ins.contains(&"headersHelper"), "{opt_ins:?}");
}

/// Doc-derived fixtures (weaker oracle; M2-24 repeats on CI-installed host configs)
/// for Cursor (`~/.cursor/mcp.json` + `envFile`), Gemini (`~/.gemini/settings.json`),
/// Copilot (`~/.copilot/mcp-config.json`), Kimi (`~/.kimi/mcp.json`), OpenCode
/// (`~/.config/opencode/opencode.json`), and shared `.mcp.json` (which marks both
/// `claude-code` and `copilot` for re-probe) plus `~/.claude/backups/` note.
#[test]
fn gate39_doc_derived_fixtures_for_cursor_gemini_copilot_kimi_opencode_and_shared_mcp_json() {
    let w = MigrateWorld::new();
    let stripe_test = w.value(labels::STRIPE_SECRET_KEY).to_owned();
    let openai_live = w.value(labels::OPENAI_API_KEY).to_owned();
    let github_tok = w.value(labels::GITHUB_TOKEN).to_owned();
    let bridge_hdr = w.value("CUSTOM_BRIDGE_HEADER").to_owned();
    let native_bin = w.compile_native_mcp_server("tier2-mcp", 1, "STRIPE_KEY");

    // 1. Cursor `~/.cursor/mcp.json` with an `envFile` target.
    std::fs::create_dir_all(w.path(".cursor")).unwrap();
    let cursor_env_file = w.path(".cursor/mcp.env");
    std::fs::write(&cursor_env_file, format!("OPENAI_API_KEY={openai_live}\n")).unwrap();
    age(&cursor_env_file, OLD);
    std::fs::write(
        w.path(".cursor/mcp.json"),
        json!({
            "mcpServers": {
                "cur-srv": {
                    "command": native_bin.to_str().unwrap(),
                    "args": [],
                    "envFile": "mcp.env",
                    "env": {
                        "STRIPE_KEY": stripe_test,
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // 2. Gemini `~/.gemini/settings.json` with `headers` and `${EXISTING}` preserved.
    std::fs::create_dir_all(w.path(".gemini")).unwrap();
    std::fs::write(
        w.path(".gemini/settings.json"),
        json!({
            "theme": "dark",
            "mcpServers": {
                "gem-http": {
                    "httpUrl": "https://mcp.example.com/gemini",
                    "headers": {
                        "Authorization": bridge_hdr,
                    }
                },
                "gem-interpolated": {
                    "command": native_bin.to_str().unwrap(),
                    "args": [],
                    "env": {
                        "STRIPE_KEY": "${STRIPE_KEY}",
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // 3. Copilot `~/.copilot/mcp-config.json`.
    std::fs::create_dir_all(w.path(".copilot")).unwrap();
    std::fs::write(
        w.path(".copilot/mcp-config.json"),
        json!({
            "mcpServers": {
                "cop-srv": {
                    "command": native_bin.to_str().unwrap(),
                    "args": [],
                    "env": {
                        "GITHUB_TOKEN": github_tok,
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // 4. Kimi `~/.kimi/mcp.json` with `auth` token.
    std::fs::create_dir_all(w.path(".kimi")).unwrap();
    std::fs::write(
        w.path(".kimi/mcp.json"),
        json!({
            "mcpServers": {
                "kimi-srv": {
                    "url": "https://mcp.example.com/kimi",
                    "auth": {
                        "token": bridge_hdr,
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // 5. OpenCode `$XDG_CONFIG_HOME/opencode/opencode.json` with `mcp` (`command` array + `environment`).
    let oc_dir = w.home.root().join("config/opencode");
    std::fs::create_dir_all(&oc_dir).unwrap();
    let oc_cfg = oc_dir.join("opencode.json");
    std::fs::write(
        &oc_cfg,
        json!({
            "mcp": {
                "oc-local": {
                    "type": "local",
                    "command": [native_bin.to_str().unwrap(), "--port", "9300"],
                    "environment": {
                        "STRIPE_KEY": stripe_test,
                    }
                },
                "oc-remote": {
                    "type": "remote",
                    "url": "https://mcp.example.com/opencode",
                    "headers": {
                        "Authorization": bridge_hdr,
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    age(&oc_cfg, OLD);

    // 6. Shared `.mcp.json` and `~/.claude/backups/` directory.
    std::fs::write(
        w.path(".mcp.json"),
        json!({
            "mcpServers": {
                "shared-srv": {
                    "command": native_bin.to_str().unwrap(),
                    "args": [],
                    "env": {
                        "STRIPE_KEY": stripe_test,
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    std::fs::create_dir_all(w.path(".claude/backups")).unwrap();

    for rel in [
        ".cursor/mcp.json",
        ".gemini/settings.json",
        ".copilot/mcp-config.json",
        ".kimi/mcp.json",
        ".mcp.json",
    ] {
        age(&w.path(rel), OLD);
    }

    let mig = w.run_terminal(&[
        "agents",
        "migrate-mcp",
        "--yes",
        "--passphrase-fd",
        "3",
        "--json",
    ]);
    assert!(
        mig.status.success(),
        "tier2 migrate failed: {}\n{}",
        stdout(&mig),
        stderr(&mig)
    );
    let report: Value = serde_json::from_slice(&mig.stdout).unwrap();
    assert_eq!(report["complete"], true, "{report}");
    assert_eq!(
        report["reprobe_agents"],
        json!(["claude-code", "copilot"]),
        "shared .mcp.json rewrite must mark claude-code and copilot for re-probe"
    );
    assert!(
        report["claude_backups_note"]
            .as_str()
            .unwrap()
            .contains("envcloak scrub"),
        "expected ~/.claude/backups/ scrub note: {report}"
    );

    // Remove the external `.cursor/mcp.env` file before sweeping `w.home` so we sweep all
    // rewritten config files for every canary encoding.
    std::fs::remove_file(&cursor_env_file).unwrap();
    w.sweep();

    // Verify OpenCode `command` array and Gemini `${STRIPE_KEY}` interpolation preservation.
    let oc_after: Value = serde_json::from_slice(&std::fs::read(&oc_cfg).unwrap()).unwrap();
    assert_eq!(oc_after["mcp"]["oc-local"]["type"], "local");
    assert!(oc_after["mcp"]["oc-local"].get("environment").is_none());
    let oc_cmd = oc_after["mcp"]["oc-local"]["command"].as_array().unwrap();
    assert_eq!(oc_cmd[1], "mcp-bridge");
    assert_eq!(oc_cmd[2], "--stdio");
    assert_eq!(oc_cmd[3], "--launch");

    let gem_after: Value =
        serde_json::from_slice(&std::fs::read(w.path(".gemini/settings.json")).unwrap()).unwrap();
    assert_eq!(
        gem_after["mcpServers"]["gem-interpolated"]["env"]["STRIPE_KEY"], "${STRIPE_KEY}",
        "existing interpolation must not be treated as a literal secret"
    );
}
