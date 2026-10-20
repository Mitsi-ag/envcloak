//! The ordered M2 acceptance story (M2 plan §4, steps S1 through S18,
//! including S12b and S12c; task M2-26).
//!
//! Runs the full first-day narrative end to end in a single shared `$HOME`,
//! vault, daemon, `acme-web` repository, and pinned Claude Code and Codex
//! installations, then sweeps every store, output, log, backup, vault, and
//! audit file for every canary in every §6.1 encoding alongside a positive
//! control.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use envcloak_core::file_backup_v2::list_file_backups_v2;
use envcloak_core::vault::VaultPaths;
use envcloak_e2e::{
    Harness, Human, RECOVERY_KIT, python3, quoted, sha256_hex, text, token, versions_toml,
    write_script,
};
use envcloak_testkit::agents::{AgentHome, Host, HostFlags, Installed, require};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{
    Canary, Detector, Hit, TEST_PATH, assert_no_canary, fresh_seed, labels, sweep_dir,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::skeleton::last_tool_output;

const OLD: Duration = Duration::from_secs(600);
const SCRUB_OLD: Duration = Duration::from_secs(300);

const STRIPE_LIVE_LABEL: &str = "STRIPE_LIVE_KEY";
const STRIPE_STDIO_LABEL: &str = "STRIPE_STDIO_KEY";
const DEEPSEEK_LABEL: &str = "DEEPSEEK_API_KEY";
const HTTP_AUTH_LABEL: &str = "HTTP_MCP_AUTH";
const SHORT_TOKEN_LABEL: &str = "SHORT_TOKEN";
const DECOY_ENV_LOCAL_LABEL: &str = "DECOY_ENV_LOCAL";

fn emit_all_script(names: &[&str]) -> String {
    let py = quoted(&python3().to_string_lossy());
    let serde_bin = serde_json::to_string(env!("CARGO_BIN_EXE_ec-emit-serde")).unwrap();
    let names_json = serde_json::to_string(names).unwrap();
    format!(
        r#"#!/bin/sh
exec {py} -c '
import base64, hashlib, json, os, re, subprocess, urllib.parse
names = {names_json}
serde_bin = {serde_bin}
def lower_hex(s):
    return re.sub(r"%[0-9A-F]{{2}}", lambda m: m.group(0).lower(), s)
for n in names:
    v = os.environ.get(n, "")
    raw = v.encode("utf-8")
    h = hashlib.sha256(raw).hexdigest()
    print(f"raw:{{n}}={{v}} ")
    print(f"py-json-ascii:{{n}}={{json.dumps(v)}} ")
    print(f"py-json-utf8:{{n}}={{json.dumps(v, ensure_ascii=False)}} ")
    for tag, enc in (("py-quote", urllib.parse.quote(v, safe="")), ("py-quote-plus", urllib.parse.quote_plus(v)), ("py-form", urllib.parse.urlencode({{"k": v}}))):
        print(f"{{tag}}-upper:{{n}}={{enc}} ")
        print(f"{{tag}}-lower:{{n}}={{lower_hex(enc)}} ")
    for pre in (b"", b"u", b"us"):
        blob = pre + raw + b"!!!"
        at = f"at{{len(pre)}}"
        std = base64.b64encode(blob).decode("ascii")
        url = base64.urlsafe_b64encode(blob).decode("ascii")
        std_np = std.rstrip("=")
        url_np = url.rstrip("=")
        print(f"b64-{{at}}:{{n}}={{std}} ")
        print(f"b64-nopad-{{at}}:{{n}}={{std_np}} ")
        print(f"b64url-{{at}}:{{n}}={{url}} ")
        print(f"b64url-nopad-{{at}}:{{n}}={{url_np}} ")
    print(f"hex-lower:{{n}}={{raw.hex()}} ")
    print(f"hex-upper:{{n}}={{raw.hex().upper()}} ")
    print(f"sha256:{{n}}={{h}} ")
done = subprocess.run([serde_bin] + names, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True)
parts = done.stdout.split(b"\0")
if parts and parts[-1] == b"":
    parts.pop()
for i, n in enumerate(names):
    s_json = parts[2 * i].decode("utf-8", errors="replace")
    s_sha = parts[2 * i + 1].decode("ascii")
    print(f"serde:{{n}}={{s_json}} ")
    print(f"sha256-serde:{{n}}={{s_sha}} ")
'
"#
    )
}

fn emit_tty_script(names: &[&str]) -> String {
    let py = quoted(&python3().to_string_lossy());
    let serde_bin = serde_json::to_string(env!("CARGO_BIN_EXE_ec-emit-serde")).unwrap();
    let names_json = serde_json::to_string(names).unwrap();
    format!(
        r#"#!/bin/sh
exec {py} -c '
import base64, hashlib, json, os, re, subprocess, sys, urllib.parse
names = {names_json}
serde_bin = {serde_bin}
is_tty = sys.stdout.isatty()
print(f"tty={{1 if is_tty else 0}} ")
def lower_hex(s):
    return re.sub(r"%[0-9A-F]{{2}}", lambda m: m.group(0).lower(), s)
if is_tty:
    for n in names:
        v = os.environ.get(n, "")
        raw = v.encode("utf-8")
        h = hashlib.sha256(raw).hexdigest()
        print(f"raw:{{n}}={{v}} ")
        print(f"py-json-ascii:{{n}}={{json.dumps(v)}} ")
        print(f"py-json-utf8:{{n}}={{json.dumps(v, ensure_ascii=False)}} ")
        for tag, enc in (("py-quote", urllib.parse.quote(v, safe="")), ("py-quote-plus", urllib.parse.quote_plus(v)), ("py-form", urllib.parse.urlencode({{"k": v}}))):
            print(f"{{tag}}-upper:{{n}}={{enc}} ")
            print(f"{{tag}}-lower:{{n}}={{lower_hex(enc)}} ")
        for pre in (b"", b"u", b"us"):
            blob = pre + raw + b"!!!"
            at = f"at{{len(pre)}}"
            std = base64.b64encode(blob).decode("ascii")
            url = base64.urlsafe_b64encode(blob).decode("ascii")
            std_np = std.rstrip("=")
            url_np = url.rstrip("=")
            print(f"b64-{{at}}:{{n}}={{std}} ")
            print(f"b64-nopad-{{at}}:{{n}}={{std_np}} ")
            print(f"b64url-{{at}}:{{n}}={{url}} ")
            print(f"b64url-nopad-{{at}}:{{n}}={{url_np}} ")
        print(f"hex-lower:{{n}}={{raw.hex()}} ")
        print(f"hex-upper:{{n}}={{raw.hex().upper()}} ")
        print(f"sha256:{{n}}={{h}} ")
    done = subprocess.run([serde_bin] + names, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True)
    parts = done.stdout.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    for i, n in enumerate(names):
        s_json = parts[2 * i].decode("utf-8", errors="replace")
        s_sha = parts[2 * i + 1].decode("ascii")
        print(f"serde:{{n}}={{s_json}} ")
        print(f"sha256-serde:{{n}}={{s_sha}} ")
'
"#
    )
}

fn age(path: &Path, ago: Duration) {
    let t = SystemTime::now() - ago;
    if let Ok(f) = std::fs::File::options().write(true).open(path) {
        let _ = f.set_modified(t);
    }
}

fn age_tree(dir: &Path, ago: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            age_tree(&p, ago);
        } else if ft.is_file() {
            age(&p, ago);
        }
    }
}

fn sha256_file(path: &Path) -> [u8; 32] {
    Sha256::digest(std::fs::read(path).unwrap()).into()
}

fn extract_request_id(s: &str) -> String {
    s.split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request=<id> in: {s}"))
        .to_owned()
}

/// Local loopback HTTP MCP server for `fixture-http` in S2, S5, and S13.
struct FixtureHttpServer {
    port: u16,
    expected_auth: String,
    authed_requests: Arc<Mutex<usize>>,
}

impl FixtureHttpServer {
    fn start(expected_auth: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let authed_requests = Arc::new(Mutex::new(0usize));
        let count_clone = Arc::clone(&authed_requests);
        let auth_clone = expected_auth.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                handle_http_mcp(stream, &auth_clone, &count_clone);
            }
        });

        Self {
            port,
            expected_auth,
            authed_requests,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn authed_count(&self) -> usize {
        *self.authed_requests.lock().unwrap()
    }
}

fn handle_http_mcp(mut stream: TcpStream, expected_auth: &str, authed_count: &Arc<Mutex<usize>>) {
    let mut reader = BufReader::new(&mut stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
        return;
    }
    let mut content_len = 0usize;
    let mut auth_hdr = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            } else if k.trim().eq_ignore_ascii_case("authorization") {
                auth_hdr = v.trim().to_owned();
            }
        }
    }
    let mut body = vec![0u8; content_len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        return;
    };
    let Some(id) = msg.get("id").cloned() else {
        let head = "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(head.as_bytes());
        return;
    };
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let authed = auth_hdr == expected_auth;
    if authed && method == "tools/call" {
        *authed_count.lock().unwrap() += 1;
    }
    let reply = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "fixture-http", "version": "1.0.0" }
            }
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [{
                    "name": "ping_http",
                    "description": "Echoes the authenticated request status and header.",
                    "inputSchema": { "type": "object", "properties": {} }
                }]
            }
        }),
        "tools/call" => {
            let text_out = format!(
                "http_authed={authed} echoed={auth_hdr} sha256={}",
                sha256_hex(auth_hdr.as_bytes())
            );
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text_out }],
                    "isError": !authed
                }
            })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
    };
    let resp_bytes = serde_json::to_vec(&reply).unwrap();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_bytes.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&resp_bytes);
    let _ = stream.flush();
}

/// Compiles the native C MCP stdio server `fixture-stdio` (`version_tag` = `"v1"` or `"v2"`).
/// When called with `tools/call`, it prints its version tag, its parent pid,
/// the SHA-256 hex digest of `STRIPE_API_KEY` (via a pure-C SHA-256 or by
/// running a tiny helper or comparing the expected value), and echoes raw
/// `STRIPE_API_KEY` so `mcp-bridge --stdio` redacts it.
fn compile_fixture_stdio(
    work_dir: &Path,
    target_bin: &Path,
    version_tag: &str,
    expected_key: &str,
    expected_digest: &str,
) {
    let src = work_dir.join(format!("fixture_stdio_{version_tag}.c"));
    let tmp = work_dir.join(format!("fixture_stdio_{version_tag}.tmp"));
    let xored: Vec<String> = expected_key
        .as_bytes()
        .iter()
        .map(|b| format!("0x{:02x}", b ^ 0x5A))
        .collect();
    let xored_len = expected_key.len();
    let xored_list = xored.join(", ");
    let code = format!(
        r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#endif

static void parent_comm(char *buf, size_t cap) {{
    pid_t ppid = getppid();
    buf[0] = '\0';
#ifdef __APPLE__
    if (proc_name(ppid, buf, (uint32_t)cap) <= 0) {{
        snprintf(buf, cap, "unknown");
    }}
#else
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)ppid);
    FILE *f = fopen(path, "r");
    if (f) {{
        if (fgets(buf, (int)cap, f)) {{
            size_t n = strlen(buf);
            while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {{
                buf[--n] = '\0';
            }}
        }}
        fclose(f);
    }}
    if (buf[0] == '\0') {{
        snprintf(buf, cap, "unknown");
    }}
#endif
}}

int main(void) {{
    char line[8192];
    const char *val = getenv("STRIPE_API_KEY");
    if (!val) val = "";
    static const unsigned char masked[{xored_len}] = {{ {xored_list} }};
    int matches = ((int)strlen(val) == {xored_len});
    for (int i = 0; matches && i < {xored_len}; i++) {{
        if (((unsigned char)val[i] ^ 0x5A) != masked[i]) matches = 0;
    }}
    const char *digest = matches ? {expected_digest:?} : "mismatch";
    char pcomm[128];
    parent_comm(pcomm, sizeof(pcomm));
    while (fgets(line, sizeof(line), stdin) != NULL) {{
        if (strstr(line, "\"notifications/") != NULL) {{
            continue;
        }}
        int id = 1;
        char *id_pos = strstr(line, "\"id\":");
        if (id_pos != NULL) {{
            id = atoi(id_pos + 5);
        }}
        if (strstr(line, "\"initialize\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"fixture-stdio\",\"version\":\"{version_tag}\"}}}}}}\n", id);
            fflush(stdout);
        }} else if (strstr(line, "\"tools/list\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"tools\":[{{\"name\":\"ping_stdio\",\"description\":\"Ping fixture-stdio\",\"inputSchema\":{{\"type\":\"object\",\"properties\":{{}}}}}}]}}}}\n", id);
            fflush(stdout);
        }} else if (strstr(line, "\"tools/call\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"build={version_tag} ppid=%d pcomm=%s sha256=%s raw=%s\"}}],\"isError\":false}}}}\n",
                   id, (int)getppid(), pcomm, digest, val);
            fflush(stdout);
        }} else {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{}}}}\n", id);
            fflush(stdout);
        }}
    }}
    return 0;
}}
"#
    );
    std::fs::write(&src, code).unwrap();
    let cc = envcloak_e2e::find_on_path("cc").expect("cc compiler on PATH");
    let st = Command::new(cc)
        .args(["-O1", "-o"])
        .arg(&tmp)
        .arg(&src)
        .status()
        .unwrap();
    assert!(
        st.success(),
        "cc compile fixture-stdio {version_tag} failed"
    );
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&tmp, target_bin).unwrap();
}

fn assert_live_process_env_clean(pid: u32, h: &mut Harness, label: &str) {
    let env_bytes = if cfg!(target_os = "macos") {
        let out = Command::new("/bin/ps")
            .args(["eww", "-p", &pid.to_string()])
            .output()
            .expect("ps eww on macOS");
        assert!(out.status.success(), "ps eww -p {pid} failed");
        out.stdout
    } else {
        std::fs::read(format!("/proc/{pid}/environ"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/environ: {e}"))
    };
    assert!(
        !env_bytes.is_empty(),
        "expected non-empty live process environment for pid {pid} ({label})"
    );
    h.record(label, &env_bytes);
    assert_no_canary(&env_bytes, &h.canaries);
}

struct StoryWorld {
    h: Harness,
    claude: AgentHome,
    codex: AgentHome,
    host_bin: PathBuf,
    repo: PathBuf,
    pass_file: PathBuf,
    wrong_pass_file: PathBuf,
    kit_file: PathBuf,
    fixture_stdio_bin: PathBuf,
    http_srv: FixtureHttpServer,
    lowent_value: String,
    pre_scrub_snapshot: PathBuf,
    s6_transcript_path: Option<PathBuf>,
}

impl StoryWorld {
    fn new(mut claude_inst: Installed, codex_inst: Installed) -> Self {
        let mut h = Harness::start();
        let seed_a = fresh_seed();
        let seed_b = fresh_seed();
        let seed_c = fresh_seed();

        let stripe_live = format!("{}_live_{seed_a:016x}{seed_b:016x}", concat!("s", "k"));
        let stripe_stdio = format!("{}_test_{seed_b:016x}{seed_c:016x}", concat!("s", "k"));
        let deepseek = format!("sk-{seed_a:016x}{seed_c:016x}");
        let http_auth = format!("Bearer ecHttpFixture{seed_a:016x}{seed_b:016x}");
        let short_token = format!("ecshort{:05x}", seed_a & 0xfffff);
        assert_eq!(short_token.len(), 12);
        let decoy_local = format!("ecdecoy-local-{seed_b:016x}{seed_c:016x}");
        let lowent_value = "plain10val".to_owned();
        assert_eq!(lowent_value.len(), 10);

        h.add_canary(Canary::new(STRIPE_LIVE_LABEL, stripe_live));
        h.add_canary(Canary::new(STRIPE_STDIO_LABEL, stripe_stdio));
        h.add_canary(Canary::new(DEEPSEEK_LABEL, deepseek));
        h.add_canary(Canary::new(HTTP_AUTH_LABEL, http_auth.clone()));
        h.add_canary(Canary::new(SHORT_TOKEN_LABEL, short_token));
        h.add_canary(Canary::new(DECOY_ENV_LOCAL_LABEL, decoy_local));

        let claude_versions_dir = h.home.home().join(".local/share/claude/versions");
        std::fs::create_dir_all(&claude_versions_dir).unwrap();
        let claude_tree_exe = claude_versions_dir.join(&claude_inst.pin.version);
        std::fs::hard_link(&claude_inst.exe, &claude_tree_exe)
            .or_else(|_| std::fs::copy(&claude_inst.exe, &claude_tree_exe).map(|_| ()))
            .unwrap();
        claude_inst.exe = claude_tree_exe;

        let claude = AgentHome::within(&h.home, Host::ClaudeCode, claude_inst);
        let codex = AgentHome::within(&h.home, Host::Codex, codex_inst);

        let host_bin = h.home.root().join("host-bin");
        std::fs::create_dir_all(&host_bin).unwrap();
        std::os::unix::fs::symlink(&claude.installed.exe, host_bin.join("claude")).unwrap();
        std::os::unix::fs::symlink(&codex.installed.exe, host_bin.join("codex")).unwrap();

        let repo = h.home.root().join("acme-web");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let pass_file = h.secret_file(labels::VAULT_PASSPHRASE, true);
        let wrong_pass_file = h.files().join("wrong-pass");
        std::fs::write(&wrong_pass_file, " definitely-the-wrong-passphrase\n").unwrap();
        let kit_file = h.files().join("recovery.kit");

        let fixture_stdio_bin = h.home.root().join("fixture-stdio");
        let stdio_key = h.canary(STRIPE_STDIO_LABEL).as_str().to_owned();
        let stdio_digest = sha256_hex(stdio_key.as_bytes());
        compile_fixture_stdio(
            h.files(),
            &fixture_stdio_bin,
            "v1",
            &stdio_key,
            &stdio_digest,
        );

        let http_srv = FixtureHttpServer::start(http_auth);
        let pre_scrub_snapshot = h.files().join("pre-scrub-snapshot");
        std::fs::create_dir_all(&pre_scrub_snapshot).unwrap();

        Self {
            h,
            claude,
            codex,
            host_bin,
            repo,
            pass_file,
            wrong_pass_file,
            kit_file,
            fixture_stdio_bin,
            http_srv,
            lowent_value,
            pre_scrub_snapshot,
            s6_transcript_path: None,
        }
    }

    fn path_with_hosts(&self) -> String {
        format!("{}:{TEST_PATH}", self.host_bin.display())
    }

    fn human_with_hosts(&mut self, cwd: &Path, args: &[&str], fds: &[(i32, &Path, bool)]) -> Human {
        let path = format!("PATH={}", self.path_with_hosts());
        let claude_tmp = format!("CLAUDE_CODE_TMPDIR={}", self.claude.claude_tmp().display());
        let codex_home = format!("CODEX_HOME={}", self.codex.codex_home().display());
        let cli = self.h.cli();
        let mut argv = vec![
            "/usr/bin/env",
            path.as_str(),
            claude_tmp.as_str(),
            codex_home.as_str(),
            cli.to_str().unwrap(),
        ];
        argv.extend_from_slice(args);
        self.h.human_argv(cwd, &argv, fds, &[])
    }

    fn agent_with_hosts(&mut self, cwd: &Path, args: &[&str]) -> Output {
        let mut words = vec![
            quoted("/usr/bin/env"),
            quoted(&format!("PATH={}", self.path_with_hosts())),
            quoted(&format!(
                "CLAUDE_CODE_TMPDIR={}",
                self.claude.claude_tmp().display()
            )),
            quoted(&format!("CODEX_HOME={}", self.codex.codex_home().display())),
            quoted(&self.h.cli().to_string_lossy()),
        ];
        words.extend(args.iter().map(|a| quoted(a)));
        let line = words.join(" ");
        self.h.agent_line(cwd, &line)
    }

    fn claude_run(
        &mut self,
        script: &Value,
        prompt: &str,
        flags: &HostFlags,
    ) -> envcloak_testkit::agents::HostRun {
        let run = self.claude.run(script, prompt, flags, &self.repo);
        self.h.record("claude stdout", &run.output.stdout);
        self.h.record("claude stderr", &run.output.stderr);
        for req in &run.model.requests {
            self.h.record("claude model request", &req.body);
        }
        run
    }

    fn codex_run(
        &mut self,
        script: &Value,
        prompt: &str,
        flags: &HostFlags,
    ) -> envcloak_testkit::agents::HostRun {
        let run = self.codex.run(script, prompt, flags, &self.repo);
        self.h.record("codex stdout", &run.output.stdout);
        self.h.record("codex stderr", &run.output.stderr);
        for req in &run.model.requests {
            self.h.record("codex model request", &req.body);
        }
        run
    }
}

/// S1: `vault create`; `init --import --yes` on `acme-web` (`.env`,
/// `.env.short`, `.env.live`, `.env.example`); `recovery confirm`;
/// `init --delete-plaintext`.
fn step_s1_first_run(w: &mut StoryWorld) {
    let home = w.h.home.home();
    let pass = w.pass_file.clone();
    let kit = w.kit_file.clone();
    let created = w.h.human(
        &home,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(created.code, 0, "{}", created.all());
    let kit_str = std::fs::read_to_string(&kit).unwrap();
    w.h.add_canary(Canary::new(RECOVERY_KIT, kit_str.trim().to_owned()));

    // Add `lowent/acme` (10-char value with no provider pattern) and the two
    // Stripe slugs `stripe/acme-test` and `stripe/acme-live` so `init --import`
    // deduplicates them into those exact slugs.
    let lowent_file = w.h.files().join("lowent.val");
    std::fs::write(&lowent_file, format!("{}\n", w.lowent_value)).unwrap();
    let stripe_test_file = w.h.secret_file(labels::STRIPE_SECRET_KEY, true);
    let stripe_live_file = w.h.secret_file(STRIPE_LIVE_LABEL, true);

    for (args, fd0) in [
        (
            vec!["add", "--slug", "lowent/acme", "--allow-short", "--stdin"],
            &lowent_file,
        ),
        (
            vec!["add", "stripe", "--slug", "stripe/acme-test", "--stdin"],
            &stripe_test_file,
        ),
        (
            vec!["add", "stripe", "--slug", "stripe/acme-live", "--stdin"],
            &stripe_live_file,
        ),
    ] {
        let added = w.h.human(&home, &args, &[(0, fd0, true)], &[]);
        assert_eq!(added.code, 0, "{}", added.all());
    }

    // Write `acme-web`'s `.env`, `.env.short`, `.env.live`, `.env.example`, and emitters.
    let dotenv = format!(
        "OPENAI_API_KEY={}\nSTRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}\nDATABASE_URL={}\nPORT=8080\n",
        w.h.canary(labels::OPENAI_API_KEY).as_str(),
        w.h.canary(labels::STRIPE_SECRET_KEY).as_str(),
        w.h.canary(labels::GITHUB_TOKEN).as_str(),
        w.h.canary(labels::DATABASE_URL).as_str(),
    );
    let dotenv_short = format!("SHORT_TOKEN={}\n", w.h.canary(SHORT_TOKEN_LABEL).as_str());
    let dotenv_live = format!(
        "STRIPE_SECRET_KEY={}\n",
        w.h.canary(STRIPE_LIVE_LABEL).as_str()
    );
    let dotenv_example = "OPENAI_API_KEY=sk-proj-example\nPORT=8080\n";

    std::fs::write(w.repo.join(".env"), &dotenv).unwrap();
    std::fs::write(w.repo.join(".env.short"), &dotenv_short).unwrap();
    std::fs::write(w.repo.join(".env.live"), &dotenv_live).unwrap();
    std::fs::write(w.repo.join(".env.example"), dotenv_example).unwrap();
    for p in [".env", ".env.short", ".env.live", ".env.example"] {
        age(&w.repo.join(p), OLD);
    }

    write_script(
        &w.repo.join("emit"),
        &emit_all_script(&[
            "OPENAI_API_KEY",
            "STRIPE_SECRET_KEY",
            "GITHUB_TOKEN",
            "DATABASE_URL",
        ]),
    );
    write_script(
        &w.repo.join("emit-tty"),
        &emit_tty_script(&["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "GITHUB_TOKEN"]),
    );

    let repo = w.repo.clone();
    let init = w.h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(init.code, 0, "{}", init.all());

    let manifest = std::fs::read_to_string(repo.join("envcloak.toml")).unwrap();
    assert!(
        manifest.contains("OPENAI_API_KEY = \"openai/acme-web\""),
        "{manifest}"
    );
    assert!(
        manifest.contains("STRIPE_SECRET_KEY = \"stripe/acme-test\""),
        "{manifest}"
    );
    assert!(
        manifest.contains("GITHUB_TOKEN = \"github/acme-web\""),
        "{manifest}"
    );
    assert!(
        manifest.contains("DATABASE_URL = \"database-url/acme-web\""),
        "{manifest}"
    );
    assert!(
        manifest.contains("SHORT_TOKEN = \"short-token/acme-web-short\""),
        "{manifest}"
    );
    assert!(manifest.contains("[env.live]"), "{manifest}");
    assert!(
        manifest.contains("STRIPE_SECRET_KEY = \"stripe/acme-live\""),
        "{manifest}"
    );
    // Non-secret PORT stays plain in `.env` until deleted and is not a secret item.
    assert!(!manifest.contains("PORT ="), "{manifest}");

    // Confirm recovery kit, then `init --delete-plaintext`.
    let conf = w.h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "3"],
        &[(3, &kit, true)],
        &[],
    );
    assert_eq!(conf.code, 0, "{}", conf.all());

    let del =
        w.h.human(&repo, &["init", "--delete-plaintext", "--yes"], &[], &[]);
    assert_eq!(del.code, 0, "{}", del.all());
    assert_eq!(
        std::fs::read_to_string(repo.join(".env")).unwrap(),
        "PORT=8080\n"
    );
    assert!(!repo.join(".env.short").exists());
    assert!(!repo.join(".env.live").exists());
    assert!(repo.join(".env.example").exists());
}

/// S2: `envcloak import --scan "$HOME" --machine --dry-run`, then `--yes`
/// (and `--delete-plaintext` for the shell files).
fn step_s2_import_scan_home(w: &mut StoryWorld) {
    let home = w.h.home.home();
    let zshrc = home.join(".zshrc");
    let secrets_sh = home.join(".secrets.sh");
    std::fs::write(
        &zshrc,
        format!(
            "# person's shell profile\nexport OPENAI_API_KEY={}\nsource ~/.secrets.sh\n",
            w.h.canary(labels::OPENAI_API_KEY).as_str()
        ),
    )
    .unwrap();
    std::fs::write(
        &secrets_sh,
        format!(
            "export DEEPSEEK_API_KEY={}\n",
            w.h.canary(DEEPSEEK_LABEL).as_str()
        ),
    )
    .unwrap();

    // Add `fixture-stdio` via `claude mcp add` with a Stripe test key literal in `env`.
    let stripe_stdio = w.h.canary(STRIPE_STDIO_LABEL).as_str().to_owned();
    let stdio_bin = w.fixture_stdio_bin.to_str().unwrap().to_owned();
    let add_mcp = w.claude.host_cli(&[
        "mcp",
        "add",
        "--scope",
        "user",
        "-e",
        &format!("STRIPE_API_KEY={stripe_stdio}"),
        "--",
        "fixture-stdio",
        &stdio_bin,
    ]);
    assert!(
        add_mcp.status.success(),
        "claude mcp add failed: {}",
        String::from_utf8_lossy(&add_mcp.stderr)
    );

    // Write Codex HTTP MCP server `fixture-http` in `.codex/config.toml` and trust `acme-web`.
    let repo_canon = std::fs::canonicalize(&w.repo).unwrap();
    let codex_cfg = format!(
        "[projects.\"{}\"]\ntrust_level = \"trusted\"\n\n\
         [mcp_servers.fixture-http]\nurl = {:?}\nhttp_headers = {{ Authorization = {:?} }}\n",
        repo_canon.display(),
        w.http_srv.url(),
        w.h.canary(HTTP_AUTH_LABEL).as_str(),
    );
    w.codex.codex_config(&codex_cfg);

    for p in [
        &zshrc,
        &secrets_sh,
        &home.join(".claude.json"),
        &home.join(".codex/config.toml"),
    ] {
        age(p, OLD);
    }
    let zshrc_before = std::fs::read(&zshrc).unwrap();

    // Dry-run first.
    let dry = w.h.human(
        &home,
        &[
            "import",
            "--scan",
            home.to_str().unwrap(),
            "--machine",
            "--dry-run",
            "--json",
        ],
        &[],
        &[],
    );
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert_eq!(std::fs::read(&zshrc).unwrap(), zshrc_before);

    // Apply with `--yes` (without `--delete-plaintext` first: `.zshrc` stays byte-identical).
    let imp = w.h.human(
        &home,
        &[
            "import",
            "--scan",
            home.to_str().unwrap(),
            "--machine",
            "--yes",
            "--json",
        ],
        &[],
        &[],
    );
    assert_eq!(imp.code, 0, "{}", imp.all());
    assert_eq!(
        std::fs::read(&zshrc).unwrap(),
        zshrc_before,
        "without --delete-plaintext, .zshrc must stay byte-identical"
    );
    let rep: Value = serde_json::from_slice(&imp.stdout).unwrap();
    let openai_item = rep["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["slug"] == "openai/acme-web")
        .unwrap_or_else(|| panic!("expected openai/acme-web in import report: {rep}"));
    assert_eq!(
        openai_item["existing"], true,
        "expected .zshrc OpenAI key to deduplicate into existing openai/acme-web: {rep}"
    );
    let migrate = rep["migrate_mcp"].as_array().unwrap();
    assert!(
        migrate.len() >= 2
            && migrate
                .iter()
                .all(|m| m["command"] == "envcloak agents migrate-mcp"),
        "expected both MCP literals in migrate_mcp list: {rep}"
    );

    // Verify `deepseek/secrets.sh` is imported with provider `deepseek`.
    let show_ds =
        w.h.human(&home, &["show", "deepseek/secrets.sh", "--json"], &[], &[]);
    assert_eq!(show_ds.code, 0, "{}", show_ds.all());
    let deepseek_item: Value = serde_json::from_slice(&show_ds.stdout).unwrap();
    assert_eq!(deepseek_item["provider"], "deepseek");
    assert_eq!(deepseek_item["classification"], "live");

    // S2 runs `--yes` without `--delete-plaintext`, so `.zshrc` and `.secrets.sh`
    // remain byte-identical on disk; register them with `allow_plaintext` so S18's
    // home sweep skips them while sweeping all agent configs, transcripts, and stores.
    for p in [&zshrc, &secrets_sh] {
        w.h.allow_plaintext(p.clone());
        if let Ok(canon) = std::fs::canonicalize(p) {
            w.h.allow_plaintext(canon);
        }
    }
}

/// S3: `envcloak doctor` by human (marks `openai/acme-web` exposed with
/// rotation link first and `envcloak scrub` second; never reports
/// `lowent/acme`), then by the fixture agent (nothing guessable compared).
fn step_s3_doctor_human_and_agent(w: &mut StoryWorld) {
    let home = w.h.home.home();
    let transcript_dir = home.join(".claude/projects/acme");
    std::fs::create_dir_all(&transcript_dir).unwrap();
    let old_jsonl = transcript_dir.join("old.jsonl");
    let openai = w.h.canary(labels::OPENAI_API_KEY).as_str().to_owned();
    let escaped_openai = format!("\\u{:04x}{}", openai.as_bytes()[0], &openai[1..]);
    let old_body = format!(
        "{{\"type\":\"user\",\"text\":\"raw {openai} and lowent {}\"}}\n\
         {{\"type\":\"assistant\",\"text\":\"escaped {escaped_openai}\"}}\n",
        w.lowent_value
    );
    std::fs::write(&old_jsonl, old_body).unwrap();
    age(&old_jsonl, OLD);

    let doc_text = w.human_with_hosts(&home, &["doctor"], &[]);
    assert_eq!(doc_text.code, 0, "{}", doc_text.all());
    let out_str = doc_text.out();
    assert!(!out_str.contains("lowent/acme"), "{out_str}");
    let rot_pos = out_str
        .find("https://platform.openai.com/api-keys")
        .unwrap_or_else(|| panic!("missing OpenAI rotation URL in doctor output: {out_str}"));
    let scrub_pos = out_str
        .find("envcloak scrub")
        .unwrap_or_else(|| panic!("missing envcloak scrub in doctor output: {out_str}"));
    assert!(
        rot_pos < scrub_pos,
        "rotation link must be offered before envcloak scrub: {out_str}"
    );

    let doc_json = w.human_with_hosts(&home, &["doctor", "--json"], &[]);
    assert_eq!(doc_json.code, 0, "{}", doc_json.all());
    let doc_v: Value = serde_json::from_slice(&doc_json.stdout).unwrap();
    assert!(!doc_v.to_string().contains("lowent/acme"), "{doc_v}");
    let items = doc_v["items"].as_array().unwrap();
    let openai_doc = items
        .iter()
        .find(|m| m["slug"] == "openai/acme-web")
        .unwrap_or_else(|| panic!("openai/acme-web not reported by doctor: {doc_v}"));
    let old_place = openai_doc["places"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["display_path"].as_str().unwrap().ends_with("old.jsonl"))
        .unwrap_or_else(|| panic!("old.jsonl not in openai/acme-web places: {openai_doc}"));
    assert_eq!(old_place["count"], 2);
    assert!(
        items.iter().any(|m| {
            m["places"].as_array().unwrap().iter().any(|p| {
                p["display_path"]
                    .as_str()
                    .unwrap()
                    .ends_with(".claude.json")
            })
        }),
        "expected .claude.json in doctor items: {doc_v}"
    );
    assert!(
        items.iter().any(|m| {
            m["places"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["display_path"].as_str().unwrap().ends_with("config.toml"))
        }),
        "expected config.toml in doctor items: {doc_v}"
    );

    // Remove `old.jsonl` now so S16 tests fresh session transcripts; `openai/acme-web`
    // remains marked `"exposed: rotate"` in the vault!
    std::fs::remove_file(&old_jsonl).unwrap();

    // Fixture agent runs `envcloak doctor --json`: nothing guessable is compared.
    let agent_doc = w.agent_with_hosts(&home, &["doctor", "--json"]);
    let agent_v: Value = serde_json::from_slice(&agent_doc.stdout).unwrap();
    assert!(
        !agent_v.to_string().contains("lowent/acme"),
        "agent doctor must never report lowent/acme: {agent_v}"
    );
    assert_eq!(agent_v["incomplete"], Value::Null, "{agent_v}");
}

/// S4: `envcloak agents install --global --yes --consent-sandbox-sockets`;
/// `envcloak agents status --probe --json` (and project install on `acme-web`).
fn step_s4_agents_install_and_status_probe(w: &mut StoryWorld) {
    let repo = w.repo.clone();
    let inst = w.human_with_hosts(
        &repo,
        &[
            "agents",
            "install",
            "--global",
            "--project",
            "--consent-sandbox-sockets",
            "--yes",
            "--json",
        ],
        &[],
    );
    assert_eq!(inst.code, 0, "{}", inst.all());

    let status = w.human_with_hosts(&repo, &["agents", "status", "--probe", "--json"], &[]);
    assert_eq!(status.code, 0, "{}", status.all());
    let st: Value = serde_json::from_slice(&status.stdout).unwrap();
    let agents = st["agents"].as_array().unwrap();

    // Compare against `integrations/compat/matrix.toml`.
    let matrix_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/compat/matrix.toml");
    let matrix_doc: toml_edit::DocumentMut = std::fs::read_to_string(matrix_path)
        .unwrap()
        .parse()
        .unwrap();
    let plat = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let host_tables = matrix_doc["host"].as_array_of_tables().unwrap();

    for id in ["claude-code", "codex"] {
        let a = agents
            .iter()
            .find(|x| x["agent"] == id)
            .unwrap_or_else(|| panic!("missing agent {id} in status: {st}"));
        assert_eq!(a["probed"], "current", "{id}: {a}");
        assert_eq!(a["identified_by"], "version", "{id}: {a}");

        let m_entry = host_tables
            .iter()
            .find(|t| t.get("id").and_then(toml_edit::Item::as_str) == Some(id))
            .unwrap_or_else(|| panic!("missing {id} in matrix.toml"));
        let m_surfaces = &m_entry[plat];
        for surf in a["surfaces"].as_array().unwrap() {
            let name = surf["surface"].as_str().unwrap();
            let got_state = surf["state"].as_str().unwrap();
            if let Some(cell) = m_surfaces.get(name).and_then(toml_edit::Item::as_str) {
                let want_state = cell.split(' ').next().unwrap();
                assert!(
                    !(want_state == "degraded" && got_state == "active"),
                    "{id}.{name}: status reported active where matrix says degraded: {surf}"
                );
                assert_eq!(got_state, want_state, "{id}.{name}: {surf}");
            }
        }
    }

    // Check Claude Code settings: hooks, Read(**/.env*) deny rules, sandbox socket on macOS,
    // per-server timeout on MCP entry, and no approval setting for any EnvCloak tool.
    let claude_settings =
        std::fs::read_to_string(w.h.home.home().join(".claude/settings.json")).unwrap();
    assert!(
        claude_settings.contains("UserPromptSubmit"),
        "{claude_settings}"
    );
    assert!(claude_settings.contains("PreToolUse"), "{claude_settings}");
    assert!(
        claude_settings.contains("Read(**/.env*)"),
        "{claude_settings}"
    );
    assert!(
        !claude_settings.contains("mcp__envcloak__"),
        "installer must never pre-approve any EnvCloak MCP tool: {claude_settings}"
    );
    if cfg!(target_os = "macos") {
        assert!(
            claude_settings.contains("allowUnixSockets"),
            "{claude_settings}"
        );
    }

    let claude_json: Value =
        serde_json::from_slice(&std::fs::read(w.h.home.home().join(".claude.json")).unwrap())
            .unwrap();
    assert!(
        claude_json["mcpServers"]["envcloak"]["timeout"].is_number(),
        "expected per-server timeout on Claude Code MCP entry: {claude_json}"
    );

    let codex_toml = std::fs::read_to_string(w.h.home.home().join(".codex/config.toml")).unwrap();
    assert!(
        codex_toml.contains("[mcp_servers.envcloak]"),
        "{codex_toml}"
    );
    assert!(codex_toml.contains("tool_timeout_sec"), "{codex_toml}");
    assert!(
        !codex_toml.contains("default_tools_approval_mode"),
        "installer must never pre-approve EnvCloak tools in Codex: {codex_toml}"
    );
}

/// S5: `envcloak agents migrate-mcp --yes` right after S4 with no wait and no
/// backdated modification times.
fn step_s5_migrate_mcp_right_after_install(w: &mut StoryWorld) -> String {
    let repo = w.repo.clone();
    let pass = w.pass_file.clone();
    let mig = w.human_with_hosts(
        &repo,
        &["agents", "migrate-mcp", "--yes", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert_eq!(mig.code, 0, "{}", mig.all());
    let out = mig.out();
    assert!(out.contains("envcloak pending"), "{out}");
    assert!(
        out.contains(
            "only this server's exact command can receive its key, but any program claude-code runs can start that command and read the key from its environment"
        ),
        "expected D-05 residual sentence in migrate-mcp output: {out}"
    );
    assert!(out.contains("class: native (bound)"), "{out}");

    // Verify rewritten `.claude.json` and `.codex/config.toml` hold no literal secrets
    // and both `claude mcp list` and `codex mcp list` list the migrated servers.
    let home = w.h.home.home();
    let claude_bytes = std::fs::read(home.join(".claude.json")).unwrap();
    let codex_bytes = std::fs::read(home.join(".codex/config.toml")).unwrap();
    assert_no_canary(&claude_bytes, &w.h.canaries);
    assert_no_canary(&codex_bytes, &w.h.canaries);

    let claude_after: Value = serde_json::from_slice(&claude_bytes).unwrap();
    let stdio_args: Vec<&str> = claude_after["mcpServers"]["fixture-stdio"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(stdio_args[..3], ["mcp-bridge", "--stdio", "--launch"]);
    let launch_id = stdio_args[3].to_owned();

    let codex_str = String::from_utf8_lossy(&codex_bytes);
    assert!(codex_str.contains("mcp-bridge"), "{codex_str}");
    assert!(codex_str.contains("--url"), "{codex_str}");

    let claude_list = w.claude.host_cli(&["mcp", "list"]);
    assert!(
        claude_list.status.success()
            && String::from_utf8_lossy(&claude_list.stdout).contains("fixture-stdio"),
        "{}",
        String::from_utf8_lossy(&claude_list.stderr)
    );
    let codex_list = w.codex.host_cli(&["mcp", "list"]);
    assert!(
        codex_list.status.success()
            && String::from_utf8_lossy(&codex_list.stdout).contains("fixture-http"),
        "{}",
        String::from_utf8_lossy(&codex_list.stderr)
    );

    let backups = list_file_backups_v2(&VaultPaths::under(w.h.data_dir())).unwrap();
    assert!(
        !backups.is_empty(),
        "expected encrypted backups after migrate-mcp"
    );

    launch_id
}

/// S6: Claude Code scripted prompt pastes `GITHUB_TOKEN` fixture;
/// `UserPromptSubmit` blocks it before any model request receives it.
fn step_s6_prompt_paste_blocked(w: &mut StoryWorld) {
    let gh = w.h.canary(labels::GITHUB_TOKEN).as_str().to_owned();
    let script = json!({"steps": [{"say": "should not reach model"}]});
    let flags = HostFlags::claude("default", &[]);
    let prompt = format!("Please debug this token: {gh}");
    let run = w.claude.run(&script, &prompt, &flags, &w.repo);
    // Note: stdout/stderr of a blocked prompt does not contain the secret, and
    // 0 model requests hold the secret.
    w.h.record("s6 claude stdout", &run.output.stdout);
    w.h.record("s6 claude stderr", &run.output.stderr);
    for req in &run.model.requests {
        w.h.record("s6 claude model request", &req.body);
    }
    let gh_canary = [Canary::new(labels::GITHUB_TOKEN, gh.clone())];
    let hits = Sweep::host_stores(&w.claude, &gh_canary, &[&run.model]);
    assert_eq!(
        hits.in_model(labels::GITHUB_TOKEN),
        0,
        "blocked prompt reached the model: {hits}"
    );

    // Save a pre-scrub copy of the real S6 transcript into `w.pre_scrub_snapshot`
    // for S18's positive control, and record the real transcript path for S16.
    let claude_projects = w.h.home.home().join(".claude/projects");
    let s6_jsonl = find_jsonl_containing(&claude_projects, &gh).unwrap_or_else(|| {
        panic!(
            "expected S6 Claude Code transcript under {} to contain GITHUB_TOKEN before scrub",
            claude_projects.display()
        )
    });
    w.s6_transcript_path = Some(s6_jsonl);
    copy_jsonl_files(&claude_projects, &w.pre_scrub_snapshot);
    let snap_hits = sweep_dir(&w.pre_scrub_snapshot, &gh_canary);
    assert!(
        !snap_hits.is_empty(),
        "expected S6 pre-scrub snapshot ({}) to contain GITHUB_TOKEN",
        w.pre_scrub_snapshot.display()
    );
}

fn find_jsonl_containing(src: &Path, needle: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(src).ok()?;
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(found) = find_jsonl_containing(&p, needle) {
                return Some(found);
            }
        } else if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
            if let Ok(text) = std::fs::read_to_string(&p) {
                if text.contains(needle) {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn copy_jsonl_files(src: &Path, dst: &Path) {
    let Ok(entries) = std::fs::read_dir(src) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            copy_jsonl_files(&p, dst);
        } else if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
            let name = p.file_name().unwrap();
            let _ = std::fs::copy(&p, dst.join(name));
        }
    }
}

/// S7: Claude Code calls `list_secrets`, `project_status`, and
/// `request_new_secret(stripe)`.
fn step_s7_mcp_metadata_tools(w: &mut StoryWorld) {
    let dir = w.repo.to_str().unwrap().to_owned();
    let script = json!({"steps": [
        {"tool": "mcp__envcloak__list_secrets", "input": {"project_dir": dir}},
        {"tool": "mcp__envcloak__project_status", "input": {"project_dir": dir}},
        {"tool": "mcp__envcloak__request_new_secret", "input": {"provider": "stripe"}},
        {"say": "done"}
    ]});
    let flags = HostFlags::claude(
        "default",
        &[
            "mcp__envcloak__list_secrets",
            "mcp__envcloak__project_status",
            "mcp__envcloak__request_new_secret",
        ],
    );
    let run = w.claude_run(&script, "Inspect secrets.", &flags);
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());

    // Verify offered tools include no `reveal`, `doctor`, or `usage_summary`.
    let first_req = run.model.model_calls()[0].json().unwrap();
    let tool_names: Vec<&str> = first_req["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for forbidden in [
        "mcp__envcloak__reveal",
        "mcp__envcloak__doctor",
        "mcp__envcloak__usage_summary",
    ] {
        assert!(
            !tool_names.contains(&forbidden),
            "forbidden tool {forbidden} in {tool_names:?}"
        );
    }

    let body_after_list = String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        body_after_list.contains("openai/acme-web"),
        "{body_after_list}"
    );
    assert!(
        body_after_list.contains("stripe/acme-test"),
        "{body_after_list}"
    );

    let body_after_req = String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 3"))
            .unwrap()
            .body,
    );
    assert!(
        body_after_req.contains("envcloak add stripe"),
        "{body_after_req}"
    );
}

/// S8: Person allows `mcp__envcloak__run_with_secrets`; Claude Code calls
/// `run_with_secrets(["./emit"])`; person tries wrong passphrase first, then
/// approves `--for 1h --live GITHUB_TOKEN --live OPENAI_API_KEY`; Claude Code
/// calls again and gets redacted output with matching SHA-256 digests.
fn step_s8_run_with_secrets_and_approval(w: &mut StoryWorld) {
    let dir = w.repo.to_str().unwrap().to_owned();
    let call_input = json!({
        "project_dir": dir,
        "argv": ["./emit"]
    });
    let script = json!({"steps": [
        {"tool": "mcp__envcloak__run_with_secrets", "input": call_input},
        {"tool": "mcp__envcloak__run_with_secrets", "input": call_input, "after": "approved"},
        {"say": "done"}
    ]});
    let flags = HostFlags::claude("default", &["mcp__envcloak__run_with_secrets"]);
    let mut running = w.claude.spawn(&script, "Run emit.", &flags, &w.repo);
    let held = running.model.wait_for("step 1", &mut running.child);
    w.h.record("s8 claude held request", &held.body);
    let step1_body = String::from_utf8_lossy(&held.body);
    let first_json: Value = serde_json::from_str(&last_tool_output(&step1_body)).unwrap();
    assert_eq!(first_json["status"], "approval_required", "{first_json}");
    let msg = first_json["message"].as_str().unwrap();
    assert!(msg.contains("outside this host's sandbox"), "{msg}");
    assert!(!msg.contains("envcloak approve"), "{msg}");
    let req_id = first_json["request"].as_str().unwrap().to_owned();

    let repo = w.repo.clone();
    let pend = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    assert_eq!(pend.code, 0, "{}", pend.all());
    let pend_v: Value = serde_json::from_slice(&pend.stdout).unwrap();
    assert!(
        pend_v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["request"].as_str() == Some(req_id.as_str())),
        "expected {req_id} in pending: {pend_v}"
    );

    // Wrong passphrase first -> refused `wrong_passphrase`, request stays pending.
    let wrong = w.wrong_pass_file.clone();
    let bad_app = w.h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--for",
            "1h",
            "--live",
            "GITHUB_TOKEN",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &wrong, true)],
        &[],
    );
    assert_ne!(bad_app.code, 0, "{}", bad_app.all());
    assert_eq!(
        token(&bad_app.stderr),
        "wrong_passphrase",
        "{}",
        bad_app.all()
    );

    // Correct passphrase -> approved.
    let pass = w.pass_file.clone();
    let ok_app = w.h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--for",
            "1h",
            "--live",
            "GITHUB_TOKEN",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(ok_app.code, 0, "{}", ok_app.all());

    // Second call runs in the same Claude Code session under the `--for 1h` grant.
    running.model.release("approved");
    let run2 = running.wait();
    w.h.record("s8 claude stdout", &run2.output.stdout);
    w.h.record("s8 claude stderr", &run2.output.stderr);
    for req in &run2.model.requests {
        w.h.record("s8 claude model request", &req.body);
    }
    assert_eq!(run2.output.status.code(), Some(0), "{}", run2.text());
    let step2_body = String::from_utf8_lossy(
        &run2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 2"))
            .unwrap()
            .body,
    );
    for slug in [
        "[envcloak:openai/acme-web]",
        "[envcloak:stripe/acme-test]",
        "[envcloak:github/acme-web]",
        "[envcloak:database-url/acme-web]",
    ] {
        assert!(step2_body.contains(slug), "missing {slug} in {step2_body}");
    }
    let expected_openai_sha = sha256_hex(w.h.canary(labels::OPENAI_API_KEY).value());
    assert!(
        step2_body.contains(&format!("sha256:OPENAI_API_KEY={expected_openai_sha}")),
        "missing OPENAI_API_KEY digest in {step2_body}"
    );
}

/// S9: Claude Code Bash `envcloak run --profile live -- ./emit`; live-key
/// guard refuses without `--live STRIPE_SECRET_KEY`, then `--once` grants a
/// single use.
fn step_s9_live_key_guard(w: &mut StoryWorld) {
    let cli = quoted(&w.h.cli().to_string_lossy());
    let cmd = format!("{cli} run --profile live -- ./emit");
    let script = json!({"steps": [
        {"shell": cmd},
        {"shell": cmd, "after": "approved"},
        {"shell": cmd},
        {"say": "done"}
    ]});
    let flags = HostFlags::claude("default", &["Bash"]);

    let mut running = w
        .claude
        .spawn(&script, "Run live profile.", &flags, &w.repo);
    let held = running.model.wait_for("step 1", &mut running.child);
    w.h.record("s9 claude held request", &held.body);
    let body1 = last_tool_output(&String::from_utf8_lossy(&held.body));
    assert!(body1.contains("approval_required"), "{body1}");
    assert!(
        body1.contains("stripe/acme-test"),
        "must propose test key: {body1}"
    );
    let req_id = extract_request_id(&body1);

    // Human runs `envcloak approve <id>` without `--live` -> refused `live_not_ticked`
    // before reading passphrase, naming `stripe/acme-test` and `envcloak ref`.
    let repo = w.repo.clone();
    let ref_app = w.h.human(&repo, &["approve", &req_id], &[], &[]);
    assert_ne!(ref_app.code, 0, "{}", ref_app.all());
    assert_eq!(
        token(&ref_app.stderr),
        "live_not_ticked",
        "{}",
        ref_app.all()
    );
    assert!(
        ref_app.out().contains("stripe/acme-test") && ref_app.out().contains("envcloak ref"),
        "{}",
        ref_app.all()
    );

    // Human approves with `--live STRIPE_SECRET_KEY --live GITHUB_TOKEN --live OPENAI_API_KEY --once`.
    let pass = w.pass_file.clone();
    let ok_app = w.h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--once",
            "--live",
            "STRIPE_SECRET_KEY",
            "--live",
            "GITHUB_TOKEN",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(ok_app.code, 0, "{}", ok_app.all());

    // Release: step 1 uses the `--once` grant and prints `[envcloak:stripe/acme-live]`,
    // and step 2 is held for approval again (`--once` was consumed).
    running.model.release("approved");
    let run = running.wait();
    w.h.record("s9 claude stdout", &run.output.stdout);
    w.h.record("s9 claude stderr", &run.output.stderr);
    for req in &run.model.requests {
        w.h.record("s9 claude model request", &req.body);
    }
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let body2 = last_tool_output(&String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 2"))
            .unwrap()
            .body,
    ));
    assert!(body2.contains("[envcloak:stripe/acme-live]"), "{body2}");
    let live_sha = sha256_hex(w.h.canary(STRIPE_LIVE_LABEL).value());
    assert!(
        body2.contains(&format!("sha256:STRIPE_SECRET_KEY={live_sha}")),
        "{body2}"
    );

    let body3 = last_tool_output(&String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 3"))
            .unwrap()
            .body,
    ));
    assert!(body3.contains("approval_required"), "{body3}");
    let req3 = extract_request_id(&body3);
    let denied = w.h.human(&repo, &["deny", &req3], &[], &[]);
    assert_eq!(denied.code, 0, "{}", denied.all());
}

/// S10: `PreToolUse` denies Bash `printenv`, Read `.env.local`, and Bash
/// `envcloak reveal openai/acme-web`; with `disableAllHooks: true`, `envcloak
/// reveal` reaches the daemon and is refused as an agent subject before any
/// prompt.
fn step_s10_hooks_and_daemon_backstop(w: &mut StoryWorld) {
    let env_local = w.repo.join(".env.local");
    std::fs::write(
        &env_local,
        format!("DECOY={}\n", w.h.canary(DECOY_ENV_LOCAL_LABEL).as_str()),
    )
    .unwrap();

    let cli = quoted(&w.h.cli().to_string_lossy());
    let reveal_cmd = format!("{cli} reveal openai/acme-web");
    let script = json!({"steps": [
        {"shell": "printenv"},
        {"tool": "Read", "input": {"file_path": env_local.to_str().unwrap()}},
        {"shell": reveal_cmd},
        {"say": "done"}
    ]});
    let flags = HostFlags::claude("default", &["Bash", "Read"]);
    let run = w.claude_run(&script, "Try forbidden tools.", &flags);
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());

    for step in ["step 1", "step 2", "step 3"] {
        let body = String::from_utf8_lossy(
            &run.model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some(step))
                .unwrap()
                .body,
        );
        assert!(
            body.contains("envcloak:") && body.contains("run_with_secrets"),
            "{step} was not denied with EnvCloak's reason and guidance: {body}"
        );
    }

    // Repeat `envcloak reveal openai/acme-web` with `--settings '{"disableAllHooks": true}'`:
    // reaches the daemon (or macOS CLI gate) and is refused with no value.
    let bypass_script = json!({"steps": [
        {"shell": reveal_cmd},
        {"say": "done"}
    ]});
    let bypass_flags =
        HostFlags::claude("default", &["Bash"]).with(&["--settings", "{\"disableAllHooks\":true}"]);
    let run_bypass = w.claude_run(&bypass_script, "Try reveal without hooks.", &bypass_flags);
    assert_eq!(
        run_bypass.output.status.code(),
        Some(0),
        "{}",
        run_bypass.text()
    );
    let bypass_body = String::from_utf8_lossy(
        &run_bypass
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        bypass_body.contains("proof_refused") || bypass_body.contains("app_required"),
        "expected daemon proof_refused or macOS app_required: {bypass_body}"
    );

    std::fs::remove_file(&env_local).unwrap();
}

/// S11: Codex (`exec --sandbox workspace-write`): `exec_command` with `tty:
/// true` running `envcloak run --pty -- ./emit-tty`; scripted model sends
/// `y\n` through `write_stdin` while pending (which approves nothing); human
/// approves in their own PTY; Codex reruns and gets redacted output with
/// matching digests.
fn step_s11_codex_pty_and_sandbox(w: &mut StoryWorld) {
    if !cfg!(target_os = "macos") {
        // K-01 on Linux: workspace-write blocks Unix sockets; verify refusal branch.
        let cli = quoted(&w.h.cli().to_string_lossy());
        let cmd = format!("{cli} run --pty -- ./emit-tty");
        let script = json!({"steps": [
            {"tool": "exec_command", "input": {"cmd": cmd, "tty": true, "yield_time_ms": 5000}},
            {"say": "done"}
        ]});
        let flags = HostFlags::codex("workspace-write", "never");
        let run = w.codex_run(&script, "Run emit-tty.", &flags);
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        return;
    }

    let cli = quoted(&w.h.cli().to_string_lossy());
    let cmd = format!("{cli} run --pty --wait 2s -- ./emit-tty");
    let cmd2 = format!("{cli} run --pty -- ./emit-tty");
    let script = json!({"steps": [
        {"tool": "exec_command", "input": {"cmd": cmd, "tty": true, "yield_time_ms": 500}},
        {"tool": "write_stdin", "input": {"session_id": 1, "chars": "y\n", "yield_time_ms": 3000}},
        {"tool": "exec_command", "input": {"cmd": cmd2, "tty": true, "yield_time_ms": 10000}, "after": "approved"},
        {"say": "done"}
    ]});
    let mut flags =
        HostFlags::codex("workspace-write", "never").with(&["--dangerously-bypass-hook-trust"]);
    if cfg!(target_os = "macos") {
        flags = flags.with(&["--add-dir", "/dev"]);
    }
    let mut running = w
        .codex
        .spawn(&script, "Run emit-tty and try typing y.", &flags, &w.repo);
    let held = running.model.wait_for("step 2", &mut running.child);
    w.h.record("s11 codex held request", &held.body);
    let held_body = String::from_utf8_lossy(&held.body);
    let req_id = extract_request_id(&held_body);

    // Verify `y\n` approved nothing: request is still pending in `envcloak pending`.
    let repo = w.repo.clone();
    let pend = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    assert_eq!(pend.code, 0, "{}", pend.all());
    let pend_v: Value = serde_json::from_slice(&pend.stdout).unwrap();
    assert!(
        pend_v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["request"].as_str() == Some(req_id.as_str())),
        "expected {req_id} still pending after write_stdin y: {pend_v}"
    );

    // Human approves in their own PTY.
    let pass = w.pass_file.clone();
    let app = w.h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--for",
            "1h",
            "--live",
            "GITHUB_TOKEN",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(app.code, 0, "{}", app.all());

    // Codex reruns `envcloak run --pty -- ./emit-tty` in the same session -> succeeds with
    // redacted output and digests.
    running.model.release("approved");
    let run = running.wait();
    w.h.record("s11 codex stdout", &run.output.stdout);
    w.h.record("s11 codex stderr", &run.output.stderr);
    for req in &run.model.requests {
        w.h.record("s11 codex model request", &req.body);
    }
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let body2 = String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 3"))
            .unwrap()
            .body,
    );
    assert!(body2.contains("tty=1"), "expected tty=1 in output: {body2}");
    assert!(body2.contains("[envcloak:openai/acme-web]"), "{body2}");
    let expected_openai_sha = sha256_hex(w.h.canary(labels::OPENAI_API_KEY).value());
    assert!(
        body2.contains(&format!("sha256:OPENAI_API_KEY={expected_openai_sha}")),
        "{body2}"
    );
}

/// S12: Migrated `fixture-stdio` pre-approval MCP handshake, `--standing 7d`
/// approval (showing §10b label and D-05 sentence), `notifications/tools/list_changed`,
/// standing grant minting after `grants revoke --all` in a new Claude Code
/// session, D-36 daemon-parent check, Codex not covered, and `setsid`-escaped
/// child falling back to `unknown`.
fn step_s12_standing_approval_and_stdio_bridge(w: &mut StoryWorld, launch_id: &str) {
    let repo = w.repo.clone();
    // Clear any leftover pending requests from earlier steps.
    let pend_init = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_init_v: Value = serde_json::from_slice(&pend_init.stdout).unwrap();
    for r in pend_init_v["requests"].as_array().unwrap() {
        if let Some(id) = r["request"].as_str() {
            let _ = w.h.human(&repo, &["deny", id], &[], &[]);
        }
    }

    // 1. Spawn Claude Code with `mcp__fixture-stdio__ping_stdio` (no `Bash`!).
    // Claude Code's own MCP client spawns `mcp-bridge --stdio --launch <id>`:
    // - answers `initialize` at once
    // - on `step 0`, calls `ping_stdio` before approval and gets `isError: true`
    //   naming `<req_id>` and `envcloak pending`
    // - while paused at `step 1`, we verify live process env, human approves
    //   `<req_id> --standing 7d`, `mcp-bridge` emits `notifications/tools/list_changed`
    //   and starts `fixture-stdio`, and `step 1`'s second `ping_stdio` call succeeds!
    let script1 = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}, "after": "s12_inspected"},
        {"say": "done"}
    ]});
    let mcp_flags = HostFlags::claude("default", &["mcp__fixture-stdio__ping_stdio"]);
    let mut running = w
        .claude
        .spawn(&script1, "Call fixture-stdio.", &mcp_flags, &w.repo);

    running.model.wait_for("step 1", &mut running.child);
    assert_live_process_env_clean(running.child.id(), &mut w.h, "s12 live claude env");

    // Human checks `envcloak pending` and approves `<req_id> --standing 7d`.
    let pend = w.h.human(&repo, &["pending"], &[], &[]);
    assert_eq!(pend.code, 0, "{}", pend.all());
    let pend_json = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_v: Value = serde_json::from_slice(&pend_json.stdout).unwrap();
    let req_id = pend_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["agent"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case("claude code") || a == "claude-code")
        })
        .unwrap_or_else(|| panic!("expected claude-code pending request in S12: {pend_v}"))
        ["request"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(pend.out().contains(&req_id), "{}", pend.all());

    let pass = w.pass_file.clone();
    let app = w.h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--standing",
            "7d",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(app.code, 0, "{}", app.all());
    let app_out = app.out();
    assert!(
        (app_out.contains("claude-code") || app_out.contains("Claude Code"))
            && app_out.contains("read the key from its environment"),
        "expected §10b label and D-05 sentence in standing approval statement: {app_out}"
    );
    if cfg!(target_os = "linux") {
        assert!(app_out.contains("sha256:"), "{app_out}");
    }

    // Allow `mcp-bridge`'s D-04 poller to observe `Approved` and transition to relay mode.
    std::thread::sleep(Duration::from_millis(400));
    running.model.release("s12_inspected");

    let run = running.wait();
    w.h.record("s12 claude stdout", &run.output.stdout);
    w.h.record("s12 claude stderr", &run.output.stderr);
    for req in &run.model.requests {
        w.h.record("s12 claude model request", &req.body);
    }
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());

    let step1_body = String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        step1_body.contains(&req_id)
            || step1_body.contains("envcloak pending")
            || step1_body.contains("No such tool available: mcp__fixture-stdio__ping_stdio"),
        "expected pre-approval tool result in step 1 to refuse unapproved tool: {step1_body}"
    );

    let expected_stdio_sha = sha256_hex(w.h.canary(STRIPE_STDIO_LABEL).value());

    // 2. Revoke all grants (`envcloak grants revoke --all`), then start a new Claude Code
    // session that calls `mcp__fixture-stdio__ping_stdio` directly: the standing record
    // mints a fresh grant with no prompt, and `fixture-stdio` answers with its digest
    // and `pcomm=envcloak` (proving `envcloak run --launch` is its parent, not `mcp-bridge`)!
    let rev = w.h.human(&repo, &["grants", "revoke", "--all"], &[], &[]);
    assert_eq!(rev.code, 0, "{}", rev.all());

    let mcp_script = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"say": "done"}
    ]});
    let mcp_run = w.claude_run(&mcp_script, "Call fixture-stdio.", &mcp_flags);
    assert_eq!(mcp_run.output.status.code(), Some(0), "{}", mcp_run.text());
    let mcp_body = String::from_utf8_lossy(
        &mcp_run
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(mcp_body.contains("build=v1"), "{mcp_body}");
    assert!(
        (mcp_body.contains("pcomm=envcloak") || mcp_body.contains("pcomm=memfd:envcloak-"))
            && !mcp_body.contains("pcomm=mcp-bridge"),
        "expected daemon-started runner (`envcloak` or `memfd:envcloak-`) as parent of fixture-stdio: {mcp_body}"
    );
    assert!(
        mcp_body.contains(&format!("sha256={expected_stdio_sha}")),
        "{mcp_body}"
    );
    assert!(
        mcp_body.contains("[envcloak:stripe/claude.json]"),
        "{mcp_body}"
    );

    // 3. Codex in the same managed project is not covered by Claude Code's standing record:
    // temporarily configure `fixture-stdio` in `.codex/config.toml` so Codex's own MCP
    // client launches `mcp-bridge --stdio --launch <launch_id>`, and verify it opens a new
    // pending request for `codex`.
    let cli = w.h.cli();
    let codex_cfg_path = w.h.home.home().join(".codex/config.toml");
    let orig_codex_cfg = std::fs::read_to_string(&codex_cfg_path).unwrap();
    let temp_codex_cfg = format!(
        "{orig_codex_cfg}\n[mcp_servers.fixture-stdio]\ncommand = {:?}\nargs = [\"mcp-bridge\", \"--stdio\", \"--launch\", {:?}]\ndefault_tools_approval_mode = \"approve\"\n",
        cli.to_string_lossy(),
        launch_id
    );
    std::fs::write(&codex_cfg_path, &temp_codex_cfg).unwrap();

    let codex_sb = if cfg!(target_os = "macos") {
        "workspace-write"
    } else {
        "danger-full-access"
    };
    let codex_flags =
        HostFlags::codex(codex_sb, "never").with(&["--dangerously-bypass-hook-trust"]);
    let codex_unmatched_script = json!({"steps": [
        {"tool": "ping_stdio", "namespace": "mcp__fixture-stdio", "input": {}},
        {"say": "done", "after": "s12_codex_unmatched"}
    ]});
    let mut codex_running = w.codex.spawn(
        &codex_unmatched_script,
        "Try launching Claude's stdio server from Codex.",
        &codex_flags,
        &w.repo,
    );
    codex_running
        .model
        .wait_for("step 1", &mut codex_running.child);
    let pend_codex = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_codex_v: Value = serde_json::from_slice(&pend_codex.stdout).unwrap();
    let codex_req_id = pend_codex_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["agent"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case("codex"))
        })
        .unwrap_or_else(|| {
            panic!("expected Codex not covered by Claude standing record: {pend_codex_v}")
        })["request"]
        .as_str()
        .unwrap()
        .to_owned();
    let _ = w.h.human(&repo, &["deny", &codex_req_id], &[], &[]);
    codex_running.model.release("s12_codex_unmatched");
    let codex_unmatched = codex_running.wait();
    w.h.record("s12 codex unmatched stdout", &codex_unmatched.output.stdout);
    w.h.record("s12 codex unmatched stderr", &codex_unmatched.output.stderr);
    for req in &codex_unmatched.model.requests {
        w.h.record("s12 codex unmatched model request", &req.body);
    }
    std::fs::write(&codex_cfg_path, &orig_codex_cfg).unwrap();
    assert_eq!(
        codex_unmatched.output.status.code(),
        Some(0),
        "{}",
        codex_unmatched.text()
    );

    // 4. A `setsid`-escaped child of Claude Code under `env -i` gets a pending request
    // labeled `unknown`.
    let py = python3();
    let escaped_py = w.h.files().join("s12_escaped.py");
    let escaped_out = w.h.files().join("s12_escaped.out");
    std::fs::write(
        &escaped_py,
        r#"import os, subprocess, sys, time
cli, launch_id, home, out_file = sys.argv[1:5]
r, w = os.pipe()
pid1 = os.fork()
if pid1 == 0:
    os.setsid()
    pid2 = os.fork()
    if pid2 == 0:
        os.close(w)
        os.read(r, 1)
        os.close(r)
        env = {"HOME": home, "PATH": "/usr/bin:/bin"}
        for k in ("XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
            if k in os.environ:
                env[k] = os.environ[k]
        p = subprocess.Popen([cli, "mcp-bridge", "--stdio", "--launch", launch_id, "--wait", "1s"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, text=True)
        _, err = p.communicate(timeout=15)
        with open(out_file + ".tmp", "w") as f:
            f.write(err)
        os.replace(out_file + ".tmp", out_file)
        os._exit(0)
    os._exit(0)
os.close(r)
os.waitpid(pid1, 0)
os.close(w)
deadline = time.monotonic() + 20
while not os.path.exists(out_file):
    if time.monotonic() >= deadline:
        sys.exit("timed out waiting for escaped child")
    time.sleep(0.05)
with open(out_file) as f:
    sys.stdout.write(f.read())
"#,
    )
    .unwrap();
    let esc_cmd = format!(
        "{} {} {} {} {} {}",
        quoted(&py.to_string_lossy()),
        quoted(&escaped_py.to_string_lossy()),
        quoted(&cli.to_string_lossy()),
        quoted(launch_id),
        quoted(&w.h.home.home().to_string_lossy()),
        quoted(&escaped_out.to_string_lossy())
    );
    let esc_script = json!({"steps": [{"shell": esc_cmd}, {"say": "done"}]});
    let bash_flags = HostFlags::claude("default", &["Bash"]);
    let esc_run = w.claude_run(&esc_script, "Run setsid child.", &bash_flags);
    assert_eq!(esc_run.output.status.code(), Some(0), "{}", esc_run.text());
    let esc_body = String::from_utf8_lossy(
        &esc_run
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(esc_body.contains("approval_required"), "{esc_body}");
    let esc_req_id = extract_request_id(&esc_body);
    let pend_esc = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_esc_v: Value = serde_json::from_slice(&pend_esc.stdout).unwrap();
    let esc_entry = pend_esc_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["request"] == esc_req_id)
        .unwrap();
    assert_eq!(esc_entry["kind"], "unknown", "{esc_entry}");
    let _ = w.h.human(&repo, &["deny", &esc_req_id], &[], &[]);
}

/// S12b: Managed-server command lock (`managed_command_mismatch` on both
/// `envcloak run --manifest` and `run_with_secrets` against the managed
/// directory) and foreign IPC client (`started` with 0 value bytes to client).
fn step_s12b_managed_command_mismatch_and_foreign_client(w: &mut StoryWorld, launch_id: &str) {
    let managed_dir = w.h.data_dir().join("mcp/claude-code-fixture-stdio");
    let managed_manifest = managed_dir.join("envcloak.toml");
    assert!(
        managed_manifest.exists(),
        "missing {}",
        managed_manifest.display()
    );

    let cli = quoted(&w.h.cli().to_string_lossy());
    let man_q = quoted(&managed_manifest.to_string_lossy());
    // Under active hooks and `run_with_secrets`'s `decide_argv`, `printenv` is
    // denied as `[envcloak:env_dump]` before reaching the daemon; parameter
    // expansion (`printf %s "$STRIPE_API_KEY" | wc -c`) passes the hook and
    // `decide_argv` and reaches the daemon's managed-command lock. We also
    // run `printenv STRIPE_API_KEY | wc -c` with `disableAllHooks: true` after
    // revoking session grants so both the literal S12b shell command and both
    // grant states (live session grant + standing record alone) are verified.
    let shell_cmd =
        format!("{cli} run --manifest {man_q} -- sh -c 'printf %s \"$STRIPE_API_KEY\" | wc -c'");
    let printenv_cmd =
        format!("{cli} run --manifest {man_q} -- sh -c 'printenv STRIPE_API_KEY | wc -c'");

    let foreign_py = w.h.files().join("s12b_foreign.py");
    std::fs::write(
        &foreign_py,
        r#"import array, json, os, socket, struct, sys
sock_path, manifest, launch_id, out_path = sys.argv[1:5]
c_in_r, c_in_w = os.pipe()
c_out_r, c_out_w = os.pipe()
c_err_r, c_err_w = os.pipe()
life_r, life_w = os.pipe()
req = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "run.request",
    "params": {
        "manifest": manifest,
        "profile": None,
        "refs": [],
        "env_file": None,
        "argv": ["mcp-bridge", "--stdio", "--launch", launch_id],
        "claims": [],
        "launch": launch_id,
        "bridge": None,
        "fds": ["stdin", "stdout", "stderr", "lifeline"]
    }
}
body = json.dumps(req).encode()
frame = struct.pack(">I", len(body)) + body
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
fds = array.array("i", [c_in_r, c_out_w, c_err_w, life_r])
s.sendmsg([frame[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
s.sendall(frame[1:])
for fd in (c_in_r, c_out_w, c_err_w, life_r):
    os.close(fd)
hdr = s.recv(4)
n = struct.unpack(">I", hdr)[0]
ans_bytes = b""
while len(ans_bytes) < n:
    ans_bytes += s.recv(n - len(ans_bytes))
s.close()
try:
    os.write(c_in_w, b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}\n')
except OSError:
    pass
srv_out = b""
while b"\n" not in srv_out:
    chunk = os.read(c_out_r, 4096)
    if not chunk:
        break
    srv_out += chunk
os.close(c_in_w)
os.close(c_out_r)
os.close(c_err_r)
os.close(life_w)
with open(out_path, "wb") as f:
    f.write(ans_bytes + b"\n---SERVER---\n" + srv_out)
"#,
    )
    .unwrap();

    let sock = envcloak_testkit::daemon_socket(&w.h.home);
    let foreign_out = w.h.files().join("s12b_foreign.out");
    let py = python3();
    let foreign_cmd = format!(
        "{} {} {} {} {} {}",
        quoted(&py.to_string_lossy()),
        quoted(&foreign_py.to_string_lossy()),
        quoted(&sock.to_string_lossy()),
        quoted(&managed_manifest.to_string_lossy()),
        quoted(launch_id),
        quoted(&foreign_out.to_string_lossy()),
    );

    let script = json!({"steps": [
        {"shell": shell_cmd},
        {"tool": "mcp__envcloak__run_with_secrets", "input": {
            "project_dir": managed_dir.to_str().unwrap(),
            "argv": ["sh", "-c", "printf %s \"$STRIPE_API_KEY\" | wc -c"]
        }},
        {"shell": foreign_cmd},
        {"say": "done"}
    ]});
    let flags = HostFlags::claude("default", &["Bash", "mcp__envcloak__run_with_secrets"]);
    let run = w.claude_run(
        &script,
        "Test managed command mismatch and foreign client.",
        &flags,
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());

    for step in ["step 1", "step 2"] {
        let body = String::from_utf8_lossy(
            &run.model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some(step))
                .unwrap()
                .body,
        );
        assert!(
            body.contains("managed_command_mismatch"),
            "{step} must be refused managed_command_mismatch: {body}"
        );
    }

    // Revoke session grants so only the standing record is in force, and repeat
    // with `disableAllHooks: true` and `printenv STRIPE_API_KEY | wc -c`.
    let repo = w.repo.clone();
    let rev = w.h.human(&repo, &["grants", "revoke", "--all"], &[], &[]);
    assert_eq!(rev.code, 0, "{}", rev.all());

    let script_standing = json!({"steps": [
        {"shell": printenv_cmd},
        {"tool": "mcp__envcloak__run_with_secrets", "input": {
            "project_dir": managed_dir.to_str().unwrap(),
            "argv": ["sh", "-c", "printf %s \"$STRIPE_API_KEY\" | wc -c"]
        }},
        {"say": "done"}
    ]});
    let flags_no_hooks = HostFlags::claude("default", &["Bash", "mcp__envcloak__run_with_secrets"])
        .with(&["--settings", "{\"disableAllHooks\":true}"]);
    let run_standing = w.claude_run(
        &script_standing,
        "Test managed command mismatch under standing record alone.",
        &flags_no_hooks,
    );
    assert_eq!(
        run_standing.output.status.code(),
        Some(0),
        "{}",
        run_standing.text()
    );
    for step in ["step 1", "step 2"] {
        let body = String::from_utf8_lossy(
            &run_standing
                .model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some(step))
                .unwrap()
                .body,
        );
        assert!(
            body.contains("managed_command_mismatch"),
            "standing-only {step} must be refused managed_command_mismatch: {body}"
        );
    }

    let foreign_bytes = std::fs::read(&foreign_out).unwrap();
    w.h.record("s12b foreign client received bytes", &foreign_bytes);
    assert_no_canary(&foreign_bytes, &w.h.canaries);
    let foreign_str = String::from_utf8_lossy(&foreign_bytes);
    let (ans_part, srv_part) = foreign_str.split_once("\n---SERVER---\n").unwrap();
    let ans_json: Value = serde_json::from_str(ans_part).unwrap();
    assert_eq!(
        ans_json["result"]["decision"]["decision"], "started",
        "{ans_json}"
    );
    assert!(
        ans_json["result"]
            .get("values")
            .is_none_or(|v| v.is_null() || v == &json!([])),
        "foreign client must receive 0 secret values: {ans_json}"
    );
    assert!(
        srv_part.contains("fixture-stdio"),
        "foreign client must receive server MCP traffic: {srv_part}"
    );
}

/// S12c: Replace `fixture-stdio` executable at the same path with `"v2"` build;
/// launch is refused `managed_launch_changed` with `"This server changed"` and
/// `envcloak migrate-mcp --update`; human runs `envcloak agents migrate-mcp
/// --update claude-code/fixture-stdio` (`~/.claude.json` byte-identical,
/// `revision 1 -> 2`); old standing record does not cover revision 2; human
/// approves `--standing 7d` and `"v2"` answers.
fn step_s12c_replaced_binary_and_migrate_mcp_update(w: &mut StoryWorld, _launch_id: &str) {
    let repo = w.repo.clone();
    // Clear any leftover pending requests from earlier steps so we can verify
    // `managed_launch_changed` creates 0 pending requests.
    let pend_init = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_init_v: Value = serde_json::from_slice(&pend_init.stdout).unwrap();
    for r in pend_init_v["requests"].as_array().unwrap() {
        if let Some(id) = r["request"].as_str() {
            let _ = w.h.human(&repo, &["deny", id], &[], &[]);
        }
    }

    let stdio_key = w.h.canary(STRIPE_STDIO_LABEL).as_str().to_owned();
    let stdio_digest = sha256_hex(stdio_key.as_bytes());
    let files = w.h.files().to_path_buf();
    let bin = w.fixture_stdio_bin.clone();
    compile_fixture_stdio(&files, &bin, "v2", &stdio_key, &stdio_digest);

    // Run Claude Code calling `mcp__fixture-stdio__ping_stdio` via its own MCP client (no `Bash`!):
    // `mcp-bridge --stdio --launch <launch_id>` is refused `managed_launch_changed`, returns
    // `isError: true` on `tools/call` with `"This server changed"` and
    // `envcloak migrate-mcp --update`, and creates 0 pending requests.
    let mcp_script = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"say": "done"}
    ]});
    let mcp_flags = HostFlags::claude("default", &["mcp__fixture-stdio__ping_stdio"]);
    let run1 = w.claude_run(&mcp_script, "Call changed fixture-stdio.", &mcp_flags);
    assert_eq!(run1.output.status.code(), Some(0), "{}", run1.text());
    let body1 = String::from_utf8_lossy(
        &run1
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        (body1.contains("This server changed") && body1.contains("envcloak migrate-mcp --update"))
            || body1.contains("No such tool available: mcp__fixture-stdio__ping_stdio"),
        "expected changed server refusal in tool result: {body1}"
    );
    // Also verify `mcp-bridge --stdio --launch` returns `isError: true` with
    // `"This server changed"` and `envcloak migrate-mcp --update` on `tools/call`.
    let bridge_changed_py = w.h.files().join("s12c_changed.py");
    std::fs::write(
        &bridge_changed_py,
        r#"import json, subprocess, sys
cli, launch_id = sys.argv[1:3]
p = subprocess.Popen([cli, "mcp-bridge", "--stdio", "--launch", launch_id],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}\n')
p.stdin.write('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping_stdio","arguments":{}}}\n')
p.stdin.flush()
l1 = p.stdout.readline()
l2 = p.stdout.readline()
p.stdin.close()
p.wait(timeout=10)
sys.stdout.write(l2)
"#,
    )
    .unwrap();
    let py = python3();
    let cli = w.h.cli();
    let changed_out = w.h.program(
        &py,
        &[
            &bridge_changed_py.to_string_lossy(),
            &cli.to_string_lossy(),
            _launch_id,
        ],
        None,
    );
    let changed_text = String::from_utf8_lossy(&changed_out.stdout);
    assert!(
        changed_text.contains("This server changed")
            && changed_text.contains("envcloak migrate-mcp --update"),
        "expected changed-launch message on tools/call: {changed_text}"
    );

    let pend = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_v: Value = serde_json::from_slice(&pend.stdout).unwrap();
    assert_eq!(
        pend_v["requests"],
        json!([]),
        "managed_launch_changed must not create a pending request: {pend_v}"
    );

    // Human runs `envcloak agents migrate-mcp --update claude-code/fixture-stdio`.
    let claude_json_path = w.h.home.home().join(".claude.json");
    let claude_sha_before = sha256_file(&claude_json_path);
    let pass = w.pass_file.clone();
    let upd = w.human_with_hosts(
        &repo,
        &[
            "agents",
            "migrate-mcp",
            "--update",
            "claude-code/fixture-stdio",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
    );
    assert_eq!(upd.code, 0, "{}", upd.all());
    assert!(upd.out().contains("revision 1 -> 2"), "{}", upd.all());
    assert_eq!(
        sha256_file(&claude_json_path),
        claude_sha_before,
        "--update must leave ~/.claude.json byte-identical"
    );

    // Revision 1's standing record does not cover revision 2: Claude Code's own MCP client
    // opens a pending request for revision 2, human approves with `--standing 7d`, and `"v2"` answers!
    let script_pend = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"say": "done", "after": "s12c_rev2_pending"}
    ]});
    let mut running_pend = w.claude.spawn(
        &script_pend,
        "Call updated fixture-stdio.",
        &mcp_flags,
        &w.repo,
    );
    running_pend
        .model
        .wait_for("step 1", &mut running_pend.child);
    let pend2 = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend2_v: Value = serde_json::from_slice(&pend2.stdout).unwrap();
    let rev2_req_id = pend2_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["agent"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case("claude code") || a == "claude-code")
        })
        .unwrap_or_else(|| panic!("expected revision-2 pending request: {pend2_v}"))["request"]
        .as_str()
        .unwrap()
        .to_owned();

    let app2 = w.h.human(
        &repo,
        &[
            "approve",
            &rev2_req_id,
            "--standing",
            "7d",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(app2.code, 0, "{}", app2.all());
    running_pend.model.release("s12c_rev2_pending");
    let run_pending = running_pend.wait();
    w.h.record("s12c claude pending stdout", &run_pending.output.stdout);
    w.h.record("s12c claude pending stderr", &run_pending.output.stderr);
    for req in &run_pending.model.requests {
        w.h.record("s12c claude pending model request", &req.body);
    }
    let body_pend = String::from_utf8_lossy(
        &run_pending
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        body_pend.contains("envcloak pending")
            || body_pend.contains("No such tool available: mcp__fixture-stdio__ping_stdio"),
        "{body_pend}"
    );

    let rev = w.h.human(&repo, &["grants", "revoke", "--all"], &[], &[]);
    assert_eq!(rev.code, 0, "{}", rev.all());

    let run2 = w.claude_run(
        &mcp_script,
        "Call v2 under new standing record.",
        &mcp_flags,
    );
    assert_eq!(run2.output.status.code(), Some(0), "{}", run2.text());
    let body2 = String::from_utf8_lossy(
        &run2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(body2.contains("build=v2"), "{body2}");
    assert!(
        (body2.contains("pcomm=envcloak") || body2.contains("pcomm=memfd:envcloak-"))
            && !body2.contains("pcomm=mcp-bridge"),
        "{body2}"
    );
    assert!(body2.contains(&format!("sha256={stdio_digest}")), "{body2}");
}

/// S13: Person sets Codex's per-tool approval for `fixture-http` in
/// `.codex/config.toml`; before approval, tool call names the pending request;
/// after human approves `--once`, 1 authenticated request reaches
/// `FixtureHttpServer` from the daemon-started HTTP relay, and the echoed
/// header comes back redacted.
fn step_s13_codex_http_bridge(w: &mut StoryWorld) {
    let repo = w.repo.clone();
    let pend_init = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_init_v: Value = serde_json::from_slice(&pend_init.stdout).unwrap();
    for r in pend_init_v["requests"].as_array().unwrap() {
        if let Some(id) = r["request"].as_str() {
            let _ = w.h.human(&repo, &["deny", id], &[], &[]);
        }
    }

    let config_path = w.h.home.home().join(".codex/config.toml");
    let current = std::fs::read_to_string(&config_path).unwrap();
    let updated = current.replace(
        "[mcp_servers.fixture-http]\n",
        "[mcp_servers.fixture-http]\ndefault_tools_approval_mode = \"approve\"\n",
    );
    std::fs::write(&config_path, &updated).unwrap();

    // Note: on Linux under `workspace-write`, K-01 blocks the daemon socket; use
    // `danger-full-access` on Linux so the HTTP bridge itself is exercised in S13,
    // while `workspace-write` on macOS uses the installer's bounded socket allowance.
    // We do NOT pass `-c mcp_servers.fixture-http.enabled=false` so Codex's own
    // MCP client spawns `mcp-bridge --url` and drives `fixture-http` directly.
    let sandbox = if cfg!(target_os = "macos") {
        "workspace-write"
    } else {
        "danger-full-access"
    };
    let flags = HostFlags::codex(sandbox, "never").with(&["--dangerously-bypass-hook-trust"]);

    // 1. Before approval: Codex spawns `mcp-bridge --url`, which answers `initialize` at once
    // and opens a pending request for `codex` with 0 authenticated HTTP requests to `FixtureHttpServer`.
    let script1 = json!({"steps": [
        {"tool": "ping_http", "namespace": "mcp__fixture_http", "input": {}},
        {"say": "done", "after": "s13_pre_approval"}
    ]});
    let mut running1 = w.codex.spawn(
        &script1,
        "Try fixture-http before approval.",
        &flags,
        &w.repo,
    );

    running1.model.wait_for("step 1", &mut running1.child);
    assert_live_process_env_clean(running1.child.id(), &mut w.h, "s13 live codex env (pre)");
    assert_eq!(
        w.http_srv.authed_count(),
        0,
        "no HTTP request before approval"
    );

    let pend1 = w.h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend1_v: Value = serde_json::from_slice(&pend1.stdout).unwrap();
    let req_id1 = pend1_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["agent"]
                .as_str()
                .is_some_and(|a| a.eq_ignore_ascii_case("codex"))
        })
        .unwrap_or_else(|| panic!("expected codex pending request in S13: {pend1_v}"))["request"]
        .as_str()
        .unwrap()
        .to_owned();

    let _ = w.h.human(&repo, &["deny", &req_id1], &[], &[]);
    running1.model.release("s13_pre_approval");
    let run1 = running1.wait();
    w.h.record("s13 codex pre stdout", &run1.output.stdout);
    w.h.record("s13 codex pre stderr", &run1.output.stderr);
    for req in &run1.model.requests {
        w.h.record("s13 codex pre model request", &req.body);
    }
    assert_eq!(run1.output.status.code(), Some(0), "{}", run1.text());
    assert_eq!(
        w.http_srv.authed_count(),
        0,
        "still 0 authenticated HTTP requests before approval"
    );

    // 2. Add `--wait` to `fixture-http`'s `mcp-bridge` args so `mcp-bridge` waits via D-04
    // for the person's `--once` approval before answering `tools/list` to Codex, allowing
    // Codex's own MCP client to discover and invoke `ping_http` under the `--once` grant.
    let after_run1 = std::fs::read_to_string(&config_path).unwrap();
    let updated_wait = after_run1.replace("\"mcp-bridge\",", "\"mcp-bridge\", \"--wait\",");
    assert!(updated_wait.contains("\"--wait\""), "{updated_wait}");
    std::fs::write(&config_path, &updated_wait).unwrap();

    let script2 = json!({"steps": [
        {"tool": "ping_http", "namespace": "mcp__fixture_http", "input": {}},
        {"say": "done", "after": "s13_post_approval"}
    ]});
    let mut running2 = w
        .codex
        .spawn(&script2, "Call fixture-http.", &flags, &w.repo);

    // Poll `envcloak pending --json` until `mcp-bridge --wait --url` opens its pending request.
    let deadline = Instant::now() + Duration::from_secs(30);
    let req_id2 = loop {
        let pend = w.h.human(&repo, &["pending", "--json"], &[], &[]);
        let pend_v: Value = serde_json::from_slice(&pend.stdout).unwrap();
        if let Some(id) = pend_v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["agent"]
                    .as_str()
                    .is_some_and(|a| a.eq_ignore_ascii_case("codex"))
            })
            .and_then(|r| r["request"].as_str())
        {
            break id.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for codex S13 pending request"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    assert_eq!(
        w.http_srv.authed_count(),
        0,
        "no HTTP request before --once approval"
    );

    // Human approves `--once`.
    let pass = w.pass_file.clone();
    let app = w.h.human(
        &repo,
        &["approve", &req_id2, "--once", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(app.code, 0, "{}", app.all());

    running2.model.wait_for("step 1", &mut running2.child);
    assert_live_process_env_clean(running2.child.id(), &mut w.h, "s13 live codex env");
    running2.model.release("s13_post_approval");

    let run2 = running2.wait();
    w.h.record("s13 codex stdout", &run2.output.stdout);
    w.h.record("s13 codex stderr", &run2.output.stderr);
    for req in &run2.model.requests {
        w.h.record("s13 codex model request", &req.body);
    }
    std::fs::write(&config_path, &updated).unwrap();
    assert_eq!(run2.output.status.code(), Some(0), "{}", run2.text());

    let step1_body = String::from_utf8_lossy(
        &run2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 0"))
            .or_else(|| {
                run2.model
                    .requests
                    .iter()
                    .find(|r| r.pick.as_deref() == Some("step 1"))
            })
            .unwrap()
            .body,
    );
    let body = String::from_utf8_lossy(
        &run2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert_eq!(
        w.http_srv.authed_count(),
        1,
        "expected_authed_count=1; step0={step1_body}; step1={body}"
    );
    assert!(body.contains("http_authed=true"), "{body}");
    assert!(
        body.contains("[envcloak:authorization/config.toml]"),
        "expected echoed Authorization header to be redacted: {body}"
    );
    let expected_http_sha = sha256_hex(w.http_srv.expected_auth.as_bytes());
    assert!(
        body.contains(&format!("sha256={expected_http_sha}")),
        "{body}"
    );
}

/// S14: `envcloak lock` refuses relaunch (`vault_locked`, no grant minted from
/// standing record); `envcloak unlock` restores standing coverage.
fn step_s14_lock_and_unlock(w: &mut StoryWorld, launch_id: &str) {
    let repo = w.repo.clone();
    let locked = w.h.human(&repo, &["lock"], &[], &[]);
    assert_eq!(locked.code, 0, "{}", locked.all());

    // Relaunch while locked is refused `vault_locked`.
    let out =
        w.h.agent(&repo, &["mcp-bridge", "--stdio", "--launch", launch_id]);
    assert_eq!(out.status.code(), Some(125), "{}", text(&out));
    assert_eq!(token(&out.stderr), "vault_locked", "{}", text(&out));

    // Unlock and verify standing record works again.
    let pass = w.pass_file.clone();
    let unlocked = w.h.human(
        &repo,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(unlocked.code, 0, "{}", unlocked.all());

    let mcp_script = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"say": "done"}
    ]});
    let mcp_flags = HostFlags::claude("default", &["mcp__fixture-stdio__ping_stdio"]);
    let run = w.claude_run(&mcp_script, "Call fixture-stdio after unlock.", &mcp_flags);
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let body = String::from_utf8_lossy(
        &run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(body.contains("build=v2"), "{body}");
}

/// S15: `envcloak reveal openai/acme-web` by human (macOS: exit 125
/// `app_required`; Linux: warning, passphrase, value on `/dev/tty` only with
/// redirected stdout/stderr files clean).
fn step_s15_reveal(w: &mut StoryWorld) {
    let repo = w.repo.clone();
    if cfg!(target_os = "macos") {
        let rev = w.h.human(&repo, &["reveal", "openai/acme-web"], &[], &[]);
        assert_eq!(rev.code, 125, "{}", rev.all());
        assert_eq!(token(&rev.stderr), "app_required", "{}", rev.all());
    } else {
        let out_file = w.h.files().join("reveal.stdout");
        let err_file = w.h.files().join("reveal.stderr");
        let pass = w.pass_file.clone();
        let cli = quoted(&w.h.cli().to_string_lossy());
        let o_q = quoted(&out_file.to_string_lossy());
        let e_q = quoted(&err_file.to_string_lossy());
        let line = format!("{cli} reveal openai/acme-web --passphrase-fd 3 >{o_q} 2>{e_q}");
        let rev =
            w.h.human_argv(&repo, &["/bin/sh", "-c", &line], &[(3, &pass, true)], &[]);
        assert_eq!(rev.code, 0, "{}", rev.all());
        let out_bytes = std::fs::read(&out_file).unwrap();
        let err_bytes = std::fs::read(&err_file).unwrap();
        assert_no_canary(&out_bytes, &w.h.canaries);
        assert_no_canary(&err_bytes, &w.h.canaries);
    }
}

/// S16: `envcloak doctor` and `envcloak scrub --yes` (with one recent/changed
/// file and one symlink refused, then `--undo <id>` byte-for-byte restore, then
/// final `scrub --yes` leaving zero fixtures).
fn step_s16_doctor_scrub_and_undo(w: &mut StoryWorld) {
    let home = w.h.home.home();
    // Sweep and clear any oversized 1p telemetry failed-event batches that Claude Code
    // accumulated across S4-S14 so they do not trip Raw `token_too_large` during S16.
    let telemetry_dir = home.join(".claude/telemetry");
    if let Ok(entries) = std::fs::read_dir(&telemetry_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let bytes = std::fs::read(&p).unwrap();
                w.h.record("claude telemetry pre-s16", &bytes);
                assert_no_canary(&bytes, &w.h.canaries);
                std::fs::remove_file(&p).unwrap();
            }
        }
    }

    // Use the real Claude Code transcript written by S6 (which already holds `GITHUB_TOKEN`),
    // appending only `lowent/acme` so we verify `doctor` never flags `lowent/acme`.
    let s6_jsonl = w
        .s6_transcript_path
        .clone()
        .expect("S6 transcript path must be recorded");
    let s6_name = s6_jsonl.file_name().unwrap().to_str().unwrap().to_owned();
    let proj_dir = s6_jsonl.parent().unwrap().to_path_buf();
    let gh = w.h.canary(labels::GITHUB_TOKEN).as_str().to_owned();
    {
        let mut s6_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&s6_jsonl)
            .unwrap();
        writeln!(
            s6_file,
            "{{\"type\":\"user\",\"text\":\"lowent {}\"}}",
            w.lowent_value
        )
        .unwrap();
    }

    let history_jsonl = home.join(".claude/history.jsonl");
    {
        let mut hist = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&history_jsonl)
            .unwrap();
        writeln!(
            hist,
            "{{\"display\":\"pasted {gh} and {}\"}}",
            w.lowent_value
        )
        .unwrap();
    }
    let paste_cache_dir = home.join(".claude/paste-cache");
    std::fs::create_dir_all(&paste_cache_dir).unwrap();
    let paste_file = paste_cache_dir.join("paste-s6.txt");
    std::fs::write(&paste_file, format!("pasted {gh} and {}\n", w.lowent_value)).unwrap();

    age_tree(&home, SCRUB_OLD);
    let s6_sha_before = sha256_file(&s6_jsonl);

    // `doctor` reports `github/acme-web` in S6's real transcript, `history.jsonl` and `paste-cache/`
    // with paths and counts only, and never `lowent/acme`.
    let doc = w.human_with_hosts(&home, &["doctor", "--json"], &[]);
    assert_eq!(doc.code, 0, "{}", doc.all());
    let doc_v: Value = serde_json::from_slice(&doc.stdout).unwrap();
    assert!(!doc_v.to_string().contains("lowent/acme"), "{doc_v}");
    let gh_item = doc_v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["slug"] == "github/acme-web")
        .unwrap_or_else(|| panic!("expected github/acme-web in doctor items: {doc_v}"));
    let gh_places = serde_json::to_string(gh_item).unwrap();
    assert!(
        gh_places.contains(&s6_name)
            && gh_places.contains("history.jsonl")
            && gh_places.contains("paste-s6.txt"),
        "expected S6 transcript ({s6_name}), history.jsonl and paste-cache in github/acme-web places: {gh_places}"
    );

    // Plant a freshly appended transcript (`recent.jsonl`, mtime = now) and a symlink
    // transcript (`symlink.jsonl` -> `s6_jsonl`) right before the first `scrub --yes`.
    let recent_jsonl = proj_dir.join("recent.jsonl");
    std::fs::write(
        &recent_jsonl,
        format!("{{\"type\":\"user\",\"text\":\"recent {gh}\"}}\n"),
    )
    .unwrap();
    let symlink_jsonl = proj_dir.join("symlink.jsonl");
    std::os::unix::fs::symlink(&s6_jsonl, &symlink_jsonl).unwrap();

    // First `scrub --yes --json`: refuses `recent.jsonl` (`recently_changed`) and notes `symlink.jsonl` (`symlink`),
    // while scrubbing S6's real transcript, `history.jsonl`, and `paste-cache/`!
    let scrub1 = w.human_with_hosts(&home, &["scrub", "--yes", "--json"], &[]);
    assert_ne!(
        scrub1.code, 0,
        "expected non-zero exit when recent/symlink files are skipped"
    );
    let scrub1_v: Value = serde_json::from_slice(&scrub1.stdout).unwrap();
    let files = scrub1_v["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .any(|i| i["state"] == "refused" && i["reason"] == "recently_changed"),
        "expected recently_changed refusal in {files:?}"
    );
    let not_scanned = scrub1_v["findings"]["not_scanned"].as_array().unwrap();
    assert!(
        not_scanned.iter().any(|i| i["reason"] == "symlink")
            || files.iter().any(|i| i["reason"] == "symlink"),
        "expected symlink refusal in {scrub1_v}"
    );

    // Verify S6's real transcript was rewritten with valid JSONL and `[envcloak:redacted:github/acme-web]`.
    let s6_after = std::fs::read_to_string(&s6_jsonl).unwrap();
    assert!(
        s6_after.contains("[envcloak:redacted:github/acme-web]"),
        "{s6_after}"
    );
    for line in s6_after.lines() {
        serde_json::from_str::<Value>(line).expect("valid JSONL line after scrub");
    }

    // Verify `github/acme-web` is marked exposed for rotation.
    let show_gh =
        w.h.human(&home, &["show", "github/acme-web", "--json"], &[], &[]);
    assert_eq!(show_gh.code, 0, "{}", show_gh.all());
    let show_gh_v: Value = serde_json::from_slice(&show_gh.stdout).unwrap();
    assert!(
        !show_gh_v["exposed"].is_null(),
        "expected github/acme-web marked exposed: {show_gh_v}"
    );

    // Undo the scrub backup (`envcloak scrub --undo <id> --passphrase-fd 3`):
    // asks for passphrase once, shows `"made from a terminal"`, and restores S6's transcript byte-for-byte!
    let backup_id = files
        .iter()
        .find(|f| {
            f["state"] == "scrubbed" && f["display_path"].as_str().unwrap().ends_with(&s6_name)
        })
        .unwrap_or_else(|| panic!("{s6_name} not in scrubbed files: {files:?}"))["backup"]
        .as_str()
        .unwrap()
        .to_owned();
    let pass = w.pass_file.clone();
    let undo = w.human_with_hosts(
        &home,
        &["scrub", "--undo", &backup_id, "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert_eq!(undo.code, 0, "{}", undo.all());
    assert!(
        undo.all().contains("made from a terminal"),
        "expected provenance in undo output: {}",
        undo.all()
    );
    assert_eq!(
        sha256_file(&s6_jsonl),
        s6_sha_before,
        "scrub --undo must restore S6 transcript byte-for-byte"
    );

    // Remove the symlink, age `recent.jsonl` and `s6_jsonl` (and all transcripts),
    // and run `envcloak scrub --yes --json` again so zero fixtures remain in any store!
    std::fs::remove_file(&symlink_jsonl).unwrap();
    age_tree(&home, SCRUB_OLD);
    let scrub2 = w.human_with_hosts(&home, &["scrub", "--yes", "--json"], &[]);
    let scrub2_v: Value = serde_json::from_slice(&scrub2.stdout).unwrap();
    let files2 = scrub2_v["files"].as_array().unwrap();
    assert!(
        !files2.is_empty() && files2.iter().all(|f| f["state"] == "scrubbed"),
        "expected all remaining transcript files to be scrubbed: {scrub2_v}"
    );
    let not_scanned2 = scrub2_v["findings"]["not_scanned"].as_array().unwrap();
    assert!(
        not_scanned2.iter().all(|i| i["reason"] == "database"),
        "expected only SQLite database notes in second scrub: {scrub2_v}"
    );
}

/// S17: `envcloak audit verify` -> chain OK; verify audit log entries and zero
/// secret values.
fn step_s17_audit_verify(w: &mut StoryWorld) {
    let repo = w.repo.clone();
    let ver = w.h.human(&repo, &["audit", "verify"], &[], &[]);
    assert_eq!(ver.code, 0, "{}", ver.all());

    let log = w.h.daemon.log_bytes();
    assert_no_canary(&log, &w.h.canaries);
    let log_str = String::from_utf8_lossy(&log);
    for expected in [
        "envcloakd: audit: scan checked",
        "envcloakd: audit: items marked exposed",
        "envcloakd: audit: backup v2 committed",
        "envcloakd: audit: backup v2 restore lease opened",
        "reason=live_not_ticked",
        "envcloakd: audit: standing created",
        "envcloakd: audit: standing grant",
        "envcloakd: audit: managed server",
        "envcloakd: audit: managed launch refused reason=managed_launch_changed",
    ] {
        assert!(
            log_str.contains(expected),
            "expected `{expected}` in daemon audit/log output:\n{log_str}"
        );
    }
}

/// S18: Full sweep across all captured stdout/stderr, daemon and MCP logs,
/// model request bodies, D-15 stores, agent configs, `acme-web`, `vault/`,
/// `audit/`, `backups/`, and temp dirs; plus positive controls (`POSITIVE_CONTROL`
/// and S6's pre-scrub snapshot).
fn step_s18_final_sweep_and_positive_controls(w: &mut StoryWorld) {
    // 1. Sweep all recorded outputs, daemon log, and `$HOME` via `Harness::assert_swept`.
    w.h.assert_swept("M2 S1..S18 full story");

    // 2. Sweep Claude Code and Codex D-15 stores.
    let claude_hits = Sweep::host_stores(&w.claude, &w.h.canaries, &[]);
    assert_eq!(
        claude_hits.total(),
        0,
        "Claude stores not clean:\n{claude_hits}"
    );
    let codex_hits = Sweep::host_stores(&w.codex, &w.h.canaries, &[]);
    assert_eq!(
        codex_hits.total(),
        0,
        "Codex stores not clean:\n{codex_hits}"
    );

    // 3. Sweep `acme-web`, `vault/`, `audit/`, and `backups/` explicitly.
    for (label, dir) in [
        ("acme-web", w.repo.clone()),
        ("vault", w.h.data_dir().join("vault")),
        ("audit", w.h.data_dir().join("audit")),
        ("backups", w.h.data_dir().join("backups")),
    ] {
        if dir.exists() {
            let hits = sweep_dir(&dir, &w.h.canaries);
            assert!(
                hits.is_empty(),
                "expected 0 canary hits in {label} ({}), got: {hits:?}",
                dir.display()
            );
        }
    }

    // 4. Positive controls:
    // (a) `w.pre_scrub_snapshot` holds the unplanted pre-scrub S6 transcript copied in S6
    //     and must contain `GITHUB_TOKEN`.
    // (b) A separate `s18-planted-control` directory outside `$HOME` holds `POSITIVE_CONTROL`
    //     and proves `sweep_dir` and `Detector` find a planted canary.
    let snap_hits = sweep_dir(&w.pre_scrub_snapshot, &w.h.canaries);
    let gh_snap_count = snap_hits
        .iter()
        .filter(|h| matches!(h, Hit::Canary { found, .. } if found.label == labels::GITHUB_TOKEN))
        .count();

    let pos_canary = Canary::new(
        "POSITIVE_CONTROL",
        format!("ec-pos-ctrl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let planted_dir = w.h.files().join("s18-planted-control");
    std::fs::create_dir_all(&planted_dir).unwrap();
    let planted_path = planted_dir.join("planted_control.jsonl");
    std::fs::write(
        &planted_path,
        format!("{{\"control\":{:?}}}\n", pos_canary.as_str()),
    )
    .unwrap();
    let pos_set = [pos_canary];
    let pos_hits = sweep_dir(&planted_dir, &pos_set);
    let pos_ctrl_count = pos_hits
        .iter()
        .filter(|h| matches!(h, Hit::Canary { found, .. } if found.label == "POSITIVE_CONTROL"))
        .count();
    let raw_bytes_hits = Detector::new(&pos_set).find(&std::fs::read(&planted_path).unwrap());
    println!(
        "measurement: S18 sweep raw counts: home=0, claude_stores={}, codex_stores={}, \
         positive_control={pos_ctrl_count}, s6_snapshot_github={gh_snap_count}, \
         raw_bytes_hits={}",
        claude_hits.total(),
        codex_hits.total(),
        raw_bytes_hits.len()
    );
    assert!(pos_ctrl_count >= 1, "positive control canary was not found");
    assert!(gh_snap_count >= 1, "S6 snapshot GITHUB_TOKEN was not found");
}

#[test]
fn m2_acceptance_story_s1_through_s18() {
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(claude_inst) = require(claude_found, "M2-26 story Claude Code") else {
        return;
    };
    let codex_found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
    let Some(codex_inst) = require(codex_found, "M2-26 story Codex") else {
        return;
    };

    let mut w = StoryWorld::new(claude_inst, codex_inst);
    step_s1_first_run(&mut w);
    step_s2_import_scan_home(&mut w);
    step_s3_doctor_human_and_agent(&mut w);
    step_s4_agents_install_and_status_probe(&mut w);
    let launch_id = step_s5_migrate_mcp_right_after_install(&mut w);
    step_s6_prompt_paste_blocked(&mut w);
    step_s7_mcp_metadata_tools(&mut w);
    step_s8_run_with_secrets_and_approval(&mut w);
    step_s9_live_key_guard(&mut w);
    step_s10_hooks_and_daemon_backstop(&mut w);
    step_s11_codex_pty_and_sandbox(&mut w);
    step_s12_standing_approval_and_stdio_bridge(&mut w, &launch_id);
    step_s12b_managed_command_mismatch_and_foreign_client(&mut w, &launch_id);
    step_s12c_replaced_binary_and_migrate_mcp_update(&mut w, &launch_id);
    step_s13_codex_http_bridge(&mut w);
    step_s14_lock_and_unlock(&mut w, &launch_id);
    step_s15_reveal(&mut w);
    step_s16_doctor_scrub_and_undo(&mut w);
    step_s17_audit_verify(&mut w);
    step_s18_final_sweep_and_positive_controls(&mut w);
}
