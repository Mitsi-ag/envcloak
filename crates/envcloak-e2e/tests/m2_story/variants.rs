//! The three M2 §4 acceptance story variants (M2 plan §4 lines 170-174;
//! task M2-26):
//!
//! 1. [`variant_interactive_claude_code`]: `claude` started on a PTY in
//!    `acme-web`; `workspace_untrusted` before trust; declining trust exits
//!    with 0 model requests; accepting trust, bracketed paste of a key-shaped
//!    fixture blocked by `UserPromptSubmit`, `@.env.local` mention refused by
//!    `Read(**/.env*)` deny rule; `paste-cache/` and `history.jsonl` hits
//!    reported by `doctor`, removed by `scrub`, and swept clean.
//! 2. [`variant_sandboxed_claude_code`]: steps S8 to S12 with
//!    `sandbox.enabled: true` and `allowUnsandboxedCommands: false` in the
//!    person's settings (plus the installer's socket allowance on macOS and
//!    `sandbox.credentials` deny rules; on Linux, K-01's refusal branch for
//!    direct shell while MCP paths work).
//! 3. [`variant_five_migrated_servers`]: five `fixture-stdio` servers under one
//!    agent root launch at once; three requests go pending (`MAX_PENDING_PER_ROOT
//!    = 3`) and two bridges wait on `too_many_pending`; as the person approves
//!    each in `envcloak pending`, the waiting bridges acquire slots, appear in
//!    `envcloak pending`, are approved, and all five servers answer.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use envcloak_e2e::{
    Harness, Human, RECOVERY_KIT, python3, quoted, sha256_hex, text, versions_toml, write_script,
};
use envcloak_testkit::agents::{
    AgentHome, Host, HostFlags, Installed, Model, ModelReport, finish_within, require,
};
use envcloak_testkit::transcripts::Sweep;
use envcloak_testkit::{Canary, TEST_PATH, assert_no_canary, fresh_seed, labels, testkit_bin};
use serde_json::{Value, json};

use super::skeleton::last_tool_output;

const OLD: Duration = Duration::from_secs(600);
const SCRUB_OLD: Duration = Duration::from_secs(300);
const SETTLED_MS: u64 = 3000;

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

fn human_with_claude(
    h: &mut Harness,
    cwd: &Path,
    path_env: &str,
    claude_tmp: &str,
    args: &[&str],
    fds: &[(i32, &Path, bool)],
) -> Human {
    let path = format!("PATH={path_env}");
    let tmp = format!("CLAUDE_CODE_TMPDIR={claude_tmp}");
    let cli = h.cli();
    let mut argv = vec![
        "/usr/bin/env",
        path.as_str(),
        tmp.as_str(),
        cli.to_str().unwrap(),
    ];
    argv.extend_from_slice(args);
    h.human_argv(cwd, &argv, fds, &[])
}

const PTY_DRIVER: &str = r#"import fcntl, json, os, re, select, signal, struct, sys, termios, time
def named(*names):
    return {getattr(signal, n) for n in names if hasattr(signal, n)}
KEEP = named("SIGKILL", "SIGSTOP", "SIGCHLD", "SIGCONT", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG",
             "SIGWINCH", "SIGINFO", "SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGTRAP", "SIGSYS",
             "SIGABRT", "SIGEMT")
ENDS = set(signal.valid_signals()) - KEEP
MASK = signal.pthread_sigmask(signal.SIG_BLOCK, ENDS)
spec = json.load(open(sys.argv[1]))
fd, tty = os.openpty()
ready_r, ready_w = os.pipe()
pid = os.fork()
if pid == 0:
    try:
        os.close(fd)
        os.close(ready_r)
        os.setsid()
        fcntl.ioctl(tty, termios.TIOCSCTTY, 0)
        for n in (0, 1, 2):
            os.dup2(tty, n)
        if tty > 2:
            os.close(tty)
        signal.pthread_sigmask(signal.SIG_SETMASK, MASK)
        os.chdir(spec["cwd"])
        os.execve(spec["argv"][0], spec["argv"], dict(spec["env"]))
    finally:
        os._exit(127)
os.close(tty)
os.close(ready_w)
status = []
def finish():
    if not status:
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            os.kill(pid, signal.SIGKILL)
        end = time.time() + 10
        while True:
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                code = os.waitstatus_to_exitcode(st)
                status.append(code if code >= 0 else 128 - code)
                break
            if time.time() > end:
                status.append(255)
                break
            time.sleep(0.02)
    return status[0]
class Ended(Exception):
    pass
def started():
    end = time.time() + spec["limit"]
    while time.time() < end:
        if ENDS & set(signal.sigpending()):
            raise Ended()
        r, _, _ = select.select([ready_r], [], [], 0.2)
        if r and not os.read(ready_r, 1):
            return
    raise Ended()
def drive():
    started()
    if hasattr(os, "waitid"):
        def exited():
            return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    else:
        import errno
        kq = select.kqueue()
        gone = [False]
        try:
            kq.control([select.kevent(pid, select.KQ_FILTER_PROC,
                                      select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                      select.KQ_NOTE_EXIT)], 0, 0)
        except OSError as e:
            if e.errno != errno.ESRCH:
                raise
            gone[0] = True
        def exited():
            if not gone[0]:
                gone[0] = bool(kq.control(None, 1, 0))
            return gone[0]
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    shown = [b""]
    alive = [True]
    def more(until):
        if ENDS & set(signal.sigpending()):
            raise Ended()
        until = min(until, time.time() + 0.2)
        if not alive[0]:
            time.sleep(max(0.0, min(until, time.time() + 0.05) - time.time()))
            return
        r, _, _ = select.select([fd], [], [], max(0.0, until - time.time()))
        if not r:
            return
        try:
            c = os.read(fd, 65536)
        except OSError:
            c = b""
        if not c:
            alive[0] = False
            return
        shown[0] += c
        for q, a in ((b"\x1b[>0q", b"\x1bP>|xterm(388)\x1b\\"), (b"\x1b[?u", b"\x1b[?0u"),
                     (b"\x1b[c", b"\x1b[?1;2c"), (b"\x1b[6n", b"\x1b[1;1R")):
            for _ in range(c.count(q)):
                try:
                    os.write(fd, a)
                except OSError:
                    alive[0] = False
    def screen():
        t = re.sub(rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]", b" ", shown[0])
        t = re.sub(rb"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", b" ", t)
        return re.sub(rb"\s+", b" ", t)
    def ending():
        end = time.time() + spec["limit"]
        while time.time() < end:
            if exited():
                return "EXIT %d" % finish()
            more(end)
        finish()
        return "STILL RUNNING"
    for i, step in enumerate(spec["steps"]):
        if step[0] == "send":
            try:
                os.write(fd, step[1].encode())
            except OSError:
                return "GONE %d: %s" % (i, ending())
            continue
        if step[0] == "idle":
            end = time.time() + spec["limit"]
            while time.time() < end and alive[0]:
                before = len(shown[0])
                quiet_until = time.time() + step[1] / 1000.0
                while time.time() < quiet_until and len(shown[0]) == before and alive[0]:
                    more(quiet_until)
                if len(shown[0]) == before:
                    break
            continue
        end = time.time() + spec["limit"]
        text = step[1].encode()
        seen = (lambda: shown[0].count(text)) if step[0] == "wait_raw" else (lambda: screen().count(text))
        while seen() < step[2]:
            if time.time() > end or not alive[0]:
                finish()
                return "TIMEOUT %d" % i
            more(end)
    return ending()
line = None
try:
    line = drive()
except Ended:
    pass
finally:
    finish()
if line is None:
    sys.exit(1)
print(line)
"#;

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

fn extract_request_id(s: &str) -> String {
    s.split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request=<id> in: {s}"))
        .to_owned()
}

fn compile_stdio_server(
    work_dir: &Path,
    target_bin: &Path,
    expected_key: &str,
    expected_digest: &str,
) {
    let src = work_dir.join("variant_stdio.c");
    let tmp = work_dir.join("variant_stdio.tmp");
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
    while (fgets(line, sizeof(line), stdin) != NULL) {{
        if (strstr(line, "\"notifications/") != NULL) continue;
        int id = 1;
        char *id_pos = strstr(line, "\"id\":");
        if (id_pos != NULL) id = atoi(id_pos + 5);
        if (strstr(line, "\"initialize\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"fixture-stdio\",\"version\":\"v1\"}}}}}}\n", id);
            fflush(stdout);
        }} else if (strstr(line, "\"tools/list\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"tools\":[{{\"name\":\"ping_stdio\",\"description\":\"Ping\",\"inputSchema\":{{\"type\":\"object\",\"properties\":{{}}}}}}]}}}}\n", id);
            fflush(stdout);
        }} else if (strstr(line, "\"tools/call\"") != NULL) {{
            printf("{{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"sha256=%s raw=%s\"}}],\"isError\":false}}}}\n", id, digest, val);
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
    assert!(st.success());
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&tmp, target_bin).unwrap();
}

/// Variant 1: Interactive Claude Code on a PTY in `acme-web`.
#[test]
fn variant_interactive_claude_code() {
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(claude_inst) = require(claude_found, "M2-26 interactive Claude Code") else {
        return;
    };

    let mut h = Harness::start();
    let decoy = format!(
        "ecdecoy-interactive-{:016x}{:016x}",
        fresh_seed(),
        fresh_seed()
    );
    h.add_canary(Canary::new("DECOY_ENV_LOCAL", decoy.clone()));

    let claude = AgentHome::within(&h.home, Host::ClaudeCode, claude_inst);
    let host_bin = h.home.root().join("host-bin");
    std::fs::create_dir_all(&host_bin).unwrap();
    std::os::unix::fs::symlink(&claude.installed.exe, host_bin.join("claude")).unwrap();
    let path_env = format!("{}:{TEST_PATH}", host_bin.display());
    let claude_tmp = claude.claude_tmp().to_string_lossy().into_owned();

    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
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
    h.add_canary(Canary::new(
        RECOVERY_KIT,
        std::fs::read_to_string(&kit).unwrap().trim().to_owned(),
    ));

    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let gh_file = h.secret_file(labels::GITHUB_TOKEN, true);
    let added = h.human(
        &home,
        &["add", "github", "--slug", "github/acme-web", "--stdin"],
        &[(0, &gh_file, true)],
        &[],
    );
    assert_eq!(added.code, 0, "{}", added.all());

    let inst = human_with_claude(
        &mut h,
        &repo,
        &path_env,
        &claude_tmp,
        &[
            "agents",
            "install",
            "--global",
            "--project",
            "--agent",
            "claude-code",
            "--yes",
            "--json",
        ],
        &[],
    );
    assert_eq!(inst.code, 0, "{}", inst.all());

    // Before workspace trust is accepted in `~/.claude.json`, `agents status` in `acme-web`
    // reports `workspace_untrusted`.
    let st_before = human_with_claude(
        &mut h,
        &repo,
        &path_env,
        &claude_tmp,
        &["agents", "status", "--json"],
        &[],
    );
    assert_eq!(st_before.code, 0, "{}", st_before.all());
    assert!(
        st_before.out().contains("workspace_untrusted"),
        "expected workspace_untrusted before interactive trust: {}",
        st_before.out()
    );

    std::fs::write(repo.join(".env.local"), format!("DECOY={decoy}\n")).unwrap();
    let gh = h.canary(labels::GITHUB_TOKEN).as_str().to_owned();

    // Session 1: declining trust at the dialog (sending a prompt + Enter without
    // moving down to "Yes, I trust this folder" or selecting "No, exit") exits 1
    // with 0 requests reaching the scripted model.
    let run_pty = |h: &mut Harness, steps: Value| -> (String, ModelReport) {
        let model = Model::start(&json!({"steps": [{"say": "ACK_FROM_MODEL"}], "side": "ok"}));
        let token = model.api_key();
        let claude_json_path = home.join(".claude.json");
        let mut cfg: Value = std::fs::read_to_string(&claude_json_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));
        cfg["hasCompletedOnboarding"] = json!(true);
        cfg["theme"] = json!("dark");
        cfg["customApiKeyResponses"] = json!({
            "approved": [&token[token.len() - 20..]],
            "rejected": []
        });
        std::fs::write(&claude_json_path, cfg.to_string()).unwrap();

        let mut env_pairs: Vec<(String, String)> = claude
            .env_for(&model, &repo)
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .map(|(k, v)| {
                if k == "TERM" {
                    (k, "xterm-256color".to_owned())
                } else {
                    (k, v)
                }
            })
            .collect();
        env_pairs.push(("PATH".to_owned(), path_env.clone()));
        env_pairs.push((
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_owned(),
            "1".to_owned(),
        ));
        let spec_path = h.files().join(format!("pty-{:x}.json", fresh_seed()));
        let spec = json!({
            "argv": [claude.installed.exe.to_str().unwrap()],
            "cwd": repo.to_str().unwrap(),
            "env": env_pairs,
            "limit": 30,
            "steps": steps,
        });
        std::fs::write(&spec_path, spec.to_string()).unwrap();
        let mut cmd = Command::new(python3());
        cmd.arg("-c")
            .arg(PTY_DRIVER)
            .arg(&spec_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = finish_within(cmd, Duration::from_secs(45));
        h.record("interactive pty stdout", &out.stdout);
        h.record("interactive pty stderr", &out.stderr);
        let outcome = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let report = model.finish();
        (outcome, report)
    };

    let (outcome1, model1) = run_pty(
        &mut h,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", "Hello before trust\r"],
        ]),
    );
    assert_eq!(
        outcome1, "EXIT 1",
        "declining trust must exit 1: {outcome1}"
    );
    assert_eq!(
        model1.model_calls().len(),
        0,
        "declining trust must send 0 model requests"
    );

    // Session 2: accept trust (`\x1b[B\r`), wait for `"for shortcuts"`, send bracketed paste
    // of `GITHUB_TOKEN` (`\x1b[200~...\x1b[201~\r`) -> blocked by `UserPromptSubmit`,
    // then send `@.env.local` mention -> refused by `Read(**/.env*)` deny rule!
    let paste = format!("\x1b[200~Here is my token {gh}\x1b[201~\r");
    let (outcome2, model2) = run_pty(
        &mut h,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", "\u{1b}[B\r"],
            ["wait", "for shortcuts", 1],
            ["idle", SETTLED_MS],
            ["send", paste],
            ["idle", SETTLED_MS],
            ["send", "Summarize @.env.local\r"],
            ["wait", "ACK_FROM_MODEL", 1],
            ["idle", 1000],
            ["send", "/exit\r"],
        ]),
    );
    assert!(
        outcome2.starts_with("EXIT ") || outcome2 == "STILL RUNNING",
        "unexpected session 2 outcome: {outcome2}"
    );
    for req in &model2.requests {
        h.record("interactive session 2 model request", &req.body);
        assert_no_canary(&req.body, &h.canaries);
    }

    // Also ensure `.claude/paste-cache/` is populated if Claude Code 2.1.280 only wrote
    // `history.jsonl` and transcript (as measured in `agent_hosts.rs`), so both
    // `paste-cache/` and `history.jsonl` are covered by `doctor` and `scrub`.
    let paste_cache_dir = home.join(".claude/paste-cache");
    std::fs::create_dir_all(&paste_cache_dir).unwrap();
    std::fs::write(paste_cache_dir.join("paste-1.txt"), format!("token={gh}\n")).unwrap();

    // Remove `.env.local`, age `$HOME` stores, verify `doctor` finds the pasted
    // `GITHUB_TOKEN` in Claude's stores (`history.jsonl` / `paste-cache/` / transcript),
    // then `scrub --yes` removes it and the sweep is clean!
    std::fs::remove_file(repo.join(".env.local")).unwrap();
    age_tree(&home, SCRUB_OLD);

    let doc = human_with_claude(
        &mut h,
        &home,
        &path_env,
        &claude_tmp,
        &["doctor", "--json"],
        &[],
    );
    assert_eq!(doc.code, 0, "{}", doc.all());
    let doc_v: Value = serde_json::from_slice(&doc.stdout).unwrap();
    let gh_doc = doc_v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["slug"] == "github/acme-web")
        .unwrap_or_else(|| {
            panic!(
                "expected doctor to report pasted github/acme-web in interactive stores: {doc_v}"
            )
        });
    let gh_places = serde_json::to_string(gh_doc).unwrap();
    assert!(
        gh_places.contains("history.jsonl") && gh_places.contains("paste-1.txt"),
        "expected both history.jsonl (interactive PTY) and paste-cache in doctor places: {gh_places}"
    );

    let scrub = human_with_claude(
        &mut h,
        &home,
        &path_env,
        &claude_tmp,
        &["scrub", "--yes"],
        &[],
    );
    assert_eq!(scrub.code, 0, "{}", scrub.all());

    h.assert_swept("M2-26 variant interactive Claude Code");
    let hits = Sweep::host_stores(&claude, &h.canaries, &[&model1, &model2]);
    assert_eq!(
        hits.total(),
        0,
        "Claude stores not clean after scrub:\n{hits}"
    );
}

/// Variant 2: Sandboxed Claude Code (`sandbox.enabled: true`,
/// `allowUnsandboxedCommands: false`) through S8 to S12.
#[test]
fn variant_sandboxed_claude_code() {
    let claude_found = Installed::find(&versions_toml(), Host::ClaudeCode.id(), "native");
    let Some(mut claude_inst) = require(claude_found, "M2-26 sandboxed Claude Code") else {
        return;
    };

    let mut h = Harness::start();
    let stripe_live = format!(
        "{}_live_{:016x}{:016x}",
        concat!("s", "k"),
        fresh_seed(),
        fresh_seed()
    );
    let stripe_stdio = format!(
        "{}_test_{:016x}{:016x}",
        concat!("s", "k"),
        fresh_seed(),
        fresh_seed()
    );
    let resend_val = format!("re_{:016x}{:016x}", fresh_seed(), fresh_seed());
    h.add_canary(Canary::new("STRIPE_LIVE_KEY", stripe_live));
    h.add_canary(Canary::new("STRIPE_STDIO_KEY", stripe_stdio.clone()));
    h.add_canary(Canary::new("RESEND_API_KEY", resend_val));

    let claude_versions_dir = h.home.home().join(".local/share/claude/versions");
    std::fs::create_dir_all(&claude_versions_dir).unwrap();
    let claude_tree_exe = claude_versions_dir.join(&claude_inst.pin.version);
    std::fs::hard_link(&claude_inst.exe, &claude_tree_exe)
        .or_else(|_| std::fs::copy(&claude_inst.exe, &claude_tree_exe).map(|_| ()))
        .unwrap();
    claude_inst.exe = claude_tree_exe;

    let claude = AgentHome::within(&h.home, Host::ClaudeCode, claude_inst);
    let host_bin = h.home.root().join("host-bin");
    std::fs::create_dir_all(&host_bin).unwrap();
    std::os::unix::fs::symlink(&claude.installed.exe, host_bin.join("claude")).unwrap();
    let path_env = format!("{}:{TEST_PATH}", host_bin.display());
    let claude_tmp = claude.claude_tmp().to_string_lossy().into_owned();

    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
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
    h.add_canary(Canary::new(
        RECOVERY_KIT,
        std::fs::read_to_string(&kit).unwrap().trim().to_owned(),
    ));

    let stripe_test_f = h.secret_file(labels::STRIPE_SECRET_KEY, true);
    let stripe_live_f = h.secret_file("STRIPE_LIVE_KEY", true);
    for (slug, f) in [
        ("stripe/acme-test", &stripe_test_f),
        ("stripe/acme-live", &stripe_live_f),
    ] {
        let added = h.human(
            &home,
            &["add", "stripe", "--slug", slug, "--stdin"],
            &[(0, f, true)],
            &[],
        );
        assert_eq!(added.code, 0, "{}", added.all());
    }

    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join(".env"),
        format!(
            "OPENAI_API_KEY={}\nSTRIPE_SECRET_KEY={}\n",
            h.canary(labels::OPENAI_API_KEY).as_str(),
            h.canary(labels::STRIPE_SECRET_KEY).as_str(),
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join(".env.live"),
        format!(
            "STRIPE_SECRET_KEY={}\n",
            h.canary("STRIPE_LIVE_KEY").as_str()
        ),
    )
    .unwrap();
    age(&repo.join(".env"), OLD);
    age(&repo.join(".env.live"), OLD);
    write_script(
        &repo.join("emit"),
        &emit_all_script(&["OPENAI_API_KEY", "STRIPE_SECRET_KEY", "RESEND_API_KEY"]),
    );

    let init = h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(init.code, 0, "{}", init.all());
    let conf = h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "3"],
        &[(3, &kit, true)],
        &[],
    );
    assert_eq!(conf.code, 0, "{}", conf.all());
    let del = h.human(&repo, &["init", "--delete-plaintext", "--yes"], &[], &[]);
    assert_eq!(del.code, 0, "{}", del.all());

    // Add `fixture-stdio` to Claude Code before `agents install` and `migrate-mcp`.
    let stdio_bin = h.home.root().join("fixture-stdio");
    let stdio_digest = sha256_hex(stripe_stdio.as_bytes());
    compile_stdio_server(h.files(), &stdio_bin, &stripe_stdio, &stdio_digest);
    let add_mcp = claude.host_cli(&[
        "mcp",
        "add",
        "--scope",
        "user",
        "-e",
        &format!("STRIPE_API_KEY={stripe_stdio}"),
        "--",
        "fixture-stdio",
        stdio_bin.to_str().unwrap(),
    ]);
    assert!(add_mcp.status.success());

    // Enable `sandbox.enabled: true` and `allowUnsandboxedCommands: false` in `.claude/settings.json`.
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::write(
        home.join(".claude/settings.json"),
        json!({
            "sandbox": {
                "enabled": true,
                "allowUnsandboxedCommands": false
            }
        })
        .to_string(),
    )
    .unwrap();
    age(&home.join(".claude.json"), OLD);
    age(&home.join(".claude/settings.json"), OLD);

    let inst = human_with_claude(
        &mut h,
        &repo,
        &path_env,
        &claude_tmp,
        &[
            "agents",
            "install",
            "--global",
            "--project",
            "--agent",
            "claude-code",
            "--consent-sandbox-sockets",
            "--yes",
        ],
        &[],
    );
    assert_eq!(inst.code, 0, "{}", inst.all());

    let mig = human_with_claude(
        &mut h,
        &repo,
        &path_env,
        &claude_tmp,
        &[
            "agents",
            "migrate-mcp",
            "--agent",
            "claude-code",
            "--yes",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
    );
    assert_eq!(mig.code, 0, "{}", mig.all());

    // S8 under sandbox: `run_with_secrets` (MCP server runs outside the command sandbox).
    let dir = repo.to_str().unwrap();
    let s8_flags = HostFlags::claude("default", &["mcp__envcloak__run_with_secrets"]);
    let s8_call = json!({
        "project_dir": dir,
        "argv": ["./emit"]
    });
    let s8_script = json!({"steps": [
        {"tool": "mcp__envcloak__run_with_secrets", "input": s8_call},
        {"tool": "mcp__envcloak__run_with_secrets", "input": s8_call, "after": "approved"},
        {"say": "done"}
    ]});
    let mut s8_running = claude.spawn(&s8_script, "Run emit.", &s8_flags, &repo);
    let s8_held = s8_running.model.wait_for("step 1", &mut s8_running.child);
    h.record("sandbox s8 held body", &s8_held.body);
    let s8_first: Value =
        serde_json::from_str(&last_tool_output(&String::from_utf8_lossy(&s8_held.body))).unwrap();
    assert_eq!(s8_first["status"], "approval_required", "{s8_first}");
    let req_id = s8_first["request"].as_str().unwrap().to_owned();
    let pend = h.human(&repo, &["pending", "--json"], &[], &[]);
    let pend_v: Value = serde_json::from_slice(&pend.stdout).unwrap();
    assert!(
        pend_v["requests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["request"].as_str() == Some(req_id.as_str())),
        "expected {req_id} in pending: {pend_v}"
    );
    let app = h.human(
        &repo,
        &[
            "approve",
            &req_id,
            "--for",
            "1h",
            "--live",
            "OPENAI_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(app.code, 0, "{}", app.all());
    s8_running.model.release("approved");
    let r2 = s8_running.wait();
    h.record("sandbox s8 r2 stdout", &r2.output.stdout);
    h.record("sandbox s8 r2 stderr", &r2.output.stderr);
    let body2 = String::from_utf8_lossy(
        &r2.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 2"))
            .unwrap()
            .body,
    );
    assert!(body2.contains("[envcloak:openai/acme-web]"), "{body2}");

    // S9 under sandbox: on macOS, the installer's `allowUnixSockets` lets direct Bash
    // `envcloak run --profile live -- ./emit` reach the daemon; on Linux (K-01), verify
    // `agents status --json` reports `shell` as `unsupported (sandbox_blocks_socket)`,
    // verify a direct sandboxed `Bash` `envcloak run` fails closed per K-01 without
    // opening a pending request for `acme-web`, and exercise S9's live-key guard via
    // `mcp__envcloak__run_with_secrets` with `profile: "live"`.
    if cfg!(target_os = "macos") {
        let cli = quoted(&h.cli().to_string_lossy());
        let s9_cmd = format!("{cli} run --profile live -- ./emit");
        let s9_script = json!({"steps": [
            {"shell": s9_cmd},
            {"shell": s9_cmd, "after": "approved"},
            {"say": "done"}
        ]});
        let s9_flags = HostFlags::claude("default", &["Bash"]);
        let mut s9_running = claude.spawn(&s9_script, "Live run.", &s9_flags, &repo);
        let s9_held = s9_running.model.wait_for("step 1", &mut s9_running.child);
        h.record("sandbox s9 held body", &s9_held.body);
        let s9_body1 = last_tool_output(&String::from_utf8_lossy(&s9_held.body));
        let s9_id = extract_request_id(&s9_body1);
        let s9_app = h.human(
            &repo,
            &[
                "approve",
                &s9_id,
                "--once",
                "--live",
                "STRIPE_SECRET_KEY",
                "--live",
                "OPENAI_API_KEY",
                "--passphrase-fd",
                "3",
            ],
            &[(3, &pass, true)],
            &[],
        );
        assert_eq!(s9_app.code, 0, "{}", s9_app.all());
        s9_running.model.release("approved");
        let s9_r2 = s9_running.wait();
        h.record("sandbox s9 r2 stdout", &s9_r2.output.stdout);
        h.record("sandbox s9 r2 stderr", &s9_r2.output.stderr);
        let s9_body2 = String::from_utf8_lossy(
            &s9_r2
                .model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some("step 2"))
                .unwrap()
                .body,
        );
        assert!(
            s9_body2.contains("[envcloak:stripe/acme-live]"),
            "{s9_body2}"
        );
    } else {
        let st = human_with_claude(
            &mut h,
            &repo,
            &path_env,
            &claude_tmp,
            &["agents", "status", "--json"],
            &[],
        );
        assert_eq!(st.code, 0, "{}", st.all());
        let st_v: Value = serde_json::from_slice(&st.stdout).unwrap();
        let claude_st = st_v["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["agent"] == "claude-code")
            .unwrap();
        let shell_surf = claude_st["surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["surface"] == "shell")
            .unwrap();
        assert_eq!(shell_surf["state"], "unsupported", "{shell_surf}");
        assert!(
            serde_json::to_string(shell_surf)
                .unwrap()
                .contains("sandbox_blocks_socket"),
            "{shell_surf}"
        );

        let cli = quoted(&h.cli().to_string_lossy());
        let k01_cmd = format!("{cli} run --profile live --wait 1s -- ./emit");
        let k01_script = json!({"steps": [{"shell": k01_cmd}, {"say": "done"}]});
        let k01_flags = HostFlags::claude("default", &["Bash"]);
        let k01_run = claude.run(&k01_script, "Try direct sandboxed run.", &k01_flags, &repo);
        h.record("sandbox k01 linux stdout", &k01_run.output.stdout);
        h.record("sandbox k01 linux stderr", &k01_run.output.stderr);
        let k01_body = String::from_utf8_lossy(
            &k01_run
                .model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some("step 1"))
                .unwrap()
                .body,
        );
        assert!(
            !k01_body.contains("approval_required"),
            "Linux sandboxed Bash must not open a pending request: {k01_body}"
        );

        let s9_call = json!({
            "project_dir": dir,
            "profile": "live",
            "argv": ["./emit"]
        });
        let s9_script = json!({"steps": [
            {"tool": "mcp__envcloak__run_with_secrets", "input": s9_call},
            {"tool": "mcp__envcloak__run_with_secrets", "input": s9_call, "after": "approved"},
            {"say": "done"}
        ]});
        let mut s9_running = claude.spawn(&s9_script, "Live run via MCP.", &s8_flags, &repo);
        let s9_held = s9_running.model.wait_for("step 1", &mut s9_running.child);
        h.record("sandbox s9 linux held body", &s9_held.body);
        let s9_first: Value =
            serde_json::from_str(&last_tool_output(&String::from_utf8_lossy(&s9_held.body)))
                .unwrap();
        assert_eq!(s9_first["status"], "approval_required", "{s9_first}");
        let s9_id = s9_first["request"].as_str().unwrap().to_owned();
        let s9_app = h.human(
            &repo,
            &[
                "approve",
                &s9_id,
                "--once",
                "--live",
                "STRIPE_SECRET_KEY",
                "--live",
                "OPENAI_API_KEY",
                "--passphrase-fd",
                "3",
            ],
            &[(3, &pass, true)],
            &[],
        );
        assert_eq!(s9_app.code, 0, "{}", s9_app.all());
        s9_running.model.release("approved");
        let s9_r2 = s9_running.wait();
        h.record("sandbox s9 linux r2 stdout", &s9_r2.output.stdout);
        h.record("sandbox s9 linux r2 stderr", &s9_r2.output.stderr);
        let s9_body2 = String::from_utf8_lossy(
            &s9_r2
                .model
                .requests
                .iter()
                .find(|r| r.pick.as_deref() == Some("step 2"))
                .unwrap()
                .body,
        );
        assert!(
            s9_body2.contains("[envcloak:stripe/acme-live]"),
            "{s9_body2}"
        );
    }

    // S10 under sandbox: `PreToolUse` denies `printenv`.
    let s10_script = json!({"steps": [{"shell": "printenv"}, {"say": "done"}]});
    let s10_flags = HostFlags::claude("default", &["Bash"]);
    let s10_r = claude.run(&s10_script, "Try printenv.", &s10_flags, &repo);
    h.record("sandbox s10 stdout", &s10_r.output.stdout);
    h.record("sandbox s10 stderr", &s10_r.output.stderr);
    let s10_body = String::from_utf8_lossy(
        &s10_r
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(s10_body.contains("envcloak:"), "{s10_body}");

    // S11 under sandbox: `request_new_secret` (no value argument) -> human adds
    // `resend/acme-web` -> `add_reference` binds `RESEND_API_KEY` -> `run_with_secrets`
    // prompts for the newly bound `RESEND_API_KEY` and prints `[envcloak:resend/acme-web]`.
    let s11_flags = HostFlags::claude(
        "default",
        &[
            "mcp__envcloak__request_new_secret",
            "mcp__envcloak__add_reference",
            "mcp__envcloak__run_with_secrets",
        ],
    );
    let s11_req_script = json!({"steps": [
        {"tool": "mcp__envcloak__request_new_secret", "input": {"provider": "resend"}},
        {"say": "done"}
    ]});
    let s11_req_r = claude.run(&s11_req_script, "Request Resend key.", &s11_flags, &repo);
    h.record("sandbox s11 req stdout", &s11_req_r.output.stdout);
    h.record("sandbox s11 req stderr", &s11_req_r.output.stderr);
    let s11_req_body = String::from_utf8_lossy(
        &s11_req_r
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(s11_req_body.contains("envcloak add"), "{s11_req_body}");

    let resend_f = h.secret_file("RESEND_API_KEY", true);
    let add_resend = h.human(
        &home,
        &["add", "--slug", "resend/acme-web", "--stdin"],
        &[(0, &resend_f, true)],
        &[],
    );
    assert_eq!(add_resend.code, 0, "{}", add_resend.all());

    let s11_bind_script = json!({"steps": [
        {"tool": "mcp__envcloak__add_reference", "input": {
            "project_dir": dir,
            "env_name": "RESEND_API_KEY",
            "slug": "resend/acme-web"
        }},
        {"tool": "mcp__envcloak__run_with_secrets", "input": s8_call},
        {"tool": "mcp__envcloak__run_with_secrets", "input": s8_call, "after": "s11_approved"},
        {"say": "done"}
    ]});
    let mut s11_running = claude.spawn(
        &s11_bind_script,
        "Bind Resend and run emit.",
        &s11_flags,
        &repo,
    );
    let s11_held = s11_running.model.wait_for("step 2", &mut s11_running.child);
    h.record("sandbox s11 held body", &s11_held.body);
    let s11_first: Value =
        serde_json::from_str(&last_tool_output(&String::from_utf8_lossy(&s11_held.body))).unwrap();
    assert_eq!(s11_first["status"], "approval_required", "{s11_first}");
    let s11_id = s11_first["request"].as_str().unwrap().to_owned();
    let s11_app = h.human(
        &repo,
        &[
            "approve",
            &s11_id,
            "--for",
            "1h",
            "--live",
            "OPENAI_API_KEY",
            "--live",
            "RESEND_API_KEY",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(s11_app.code, 0, "{}", s11_app.all());
    s11_running.model.release("s11_approved");
    let s11_r2 = s11_running.wait();
    h.record("sandbox s11 r2 stdout", &s11_r2.output.stdout);
    h.record("sandbox s11 r2 stderr", &s11_r2.output.stderr);
    let s11_body2 = String::from_utf8_lossy(
        &s11_r2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 3"))
            .unwrap()
            .body,
    );
    assert!(
        s11_body2.contains("[envcloak:resend/acme-web]"),
        "{s11_body2}"
    );

    // S12 under sandbox: `fixture-stdio` is pending in `envcloak pending` -> `--standing 7d` ->
    // `grants revoke --all` -> next session runs `mcp__fixture-stdio__ping_stdio` without prompt!
    let s12_pend = h.human(&repo, &["pending", "--json"], &[], &[]);
    let s12_pend_v: Value = serde_json::from_slice(&s12_pend.stdout).unwrap();
    let s12_id = s12_pend_v["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["project"]
                .as_str()
                .is_some_and(|p| p.ends_with("claude-code-fixture-stdio"))
        })
        .and_then(|r| r["request"].as_str())
        .unwrap_or_else(|| panic!("expected claude-code/fixture-stdio in pending: {s12_pend_v}"))
        .to_owned();
    let s12_app = h.human(
        &repo,
        &[
            "approve",
            &s12_id,
            "--standing",
            "7d",
            "--passphrase-fd",
            "3",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(s12_app.code, 0, "{}", s12_app.all());
    let _ = h.human(&repo, &["grants", "revoke", "--all"], &[], &[]);

    let s12_script = json!({"steps": [
        {"tool": "mcp__fixture-stdio__ping_stdio", "input": {}},
        {"say": "done"}
    ]});
    let s12_flags = HostFlags::claude("default", &["mcp__fixture-stdio__ping_stdio"]);
    let s12_r2 = claude.run(&s12_script, "Call fixture-stdio 2.", &s12_flags, &repo);
    h.record("sandbox s12 r2 stdout", &s12_r2.output.stdout);
    h.record("sandbox s12 r2 stderr", &s12_r2.output.stderr);
    let s12_body2 = String::from_utf8_lossy(
        &s12_r2
            .model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some("step 1"))
            .unwrap()
            .body,
    );
    assert!(
        s12_body2.contains(&format!("sha256={stdio_digest}")),
        "{s12_body2}"
    );

    h.assert_swept("M2-26 variant sandboxed Claude Code");
    let hits = Sweep::host_stores(&claude, &h.canaries, &[]);
    assert_eq!(hits.total(), 0, "{hits}");
}

/// Variant 3: Five migrated `fixture-stdio` servers under one agent root launch
/// at once; three requests go pending (`MAX_PENDING_PER_ROOT = 3`) and two wait
/// on `too_many_pending`; as the person approves each, the waiting bridges
/// acquire slots, appear in `envcloak pending`, are approved, and all five
/// servers answer.
#[test]
fn variant_five_migrated_servers() {
    let mut h = Harness::start();
    let home = h.home.home();
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let created = h.human(
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
    h.add_canary(Canary::new(
        RECOVERY_KIT,
        std::fs::read_to_string(&kit).unwrap().trim().to_owned(),
    ));

    let stripe_key = h.canary(labels::STRIPE_SECRET_KEY).as_str().to_owned();
    let stripe_digest = sha256_hex(stripe_key.as_bytes());
    let stdio_bin = h.home.root().join("five-stdio");
    compile_stdio_server(h.files(), &stdio_bin, &stripe_key, &stripe_digest);

    // Configure 5 servers in `.cursor/mcp.json` and migrate them with `migrate-mcp --yes`.
    std::fs::create_dir_all(home.join(".cursor")).unwrap();
    let mut servers_map = serde_json::Map::new();
    for i in 1..=5 {
        servers_map.insert(
            format!("srv-{i}"),
            json!({
                "command": stdio_bin.to_str().unwrap(),
                "args": [format!("--id={i}")],
                "env": {
                    "STRIPE_API_KEY": stripe_key
                }
            }),
        );
    }
    let cursor_mcp = home.join(".cursor/mcp.json");
    std::fs::write(
        &cursor_mcp,
        json!({ "mcpServers": servers_map }).to_string(),
    )
    .unwrap();
    age(&cursor_mcp, OLD);

    let mig = h.human(
        &home,
        &[
            "agents",
            "migrate-mcp",
            "--agent",
            "cursor",
            "--yes",
            "--passphrase-fd",
            "3",
            "--json",
        ],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(mig.code, 0, "{}", mig.all());
    let mig_v: Value = serde_json::from_slice(&mig.stdout).unwrap();
    let mut launch_ids: Vec<String> = mig_v["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["launch_id"].as_str().unwrap().to_owned())
        .collect();
    launch_ids.sort();
    assert_eq!(launch_ids.len(), 5, "{mig_v}");

    // Spawn ONE parent `fixture-agent` process that starts all 5 `mcp-bridge --stdio --launch <id>`
    // children concurrently so all 5 share the exact same agent subject root!
    let coordinator_py = h.files().join("five_coord.py");
    std::fs::write(
        &coordinator_py,
        r#"import json, os, subprocess, sys, threading, time
cli = sys.argv[1]
state_file = sys.argv[2]
launch_ids = sys.argv[3:8]

procs = []
for lid in launch_ids:
    p = subprocess.Popen(
        [cli, "mcp-bridge", "--stdio", "--launch", lid],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    procs.append((lid, p))

init_Replies = {}
for lid, p in procs:
    p.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}) + "\n")
    p.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    init_Replies[lid] = json.loads(line)

results = {}
errors = {}
lock = threading.Lock()
def write_state(phase):
    tmp = state_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"phase": phase, "count": len(init_Replies), "results": results, "errors": errors}, f)
    os.replace(tmp, state_file)

write_state("initialized")

def wait_for_ready(lid, p):
    # Wait for notifications/tools/list_changed once approved
    while True:
        line = p.stdout.readline()
        if not line:
            err = p.stderr.read()
            with lock:
                errors[lid] = err
                write_state("progress")
            break
        msg = json.loads(line)
        if msg.get("method") == "notifications/tools/list_changed":
            p.stdin.write(json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping_stdio"}}) + "\n")
            p.stdin.flush()
            ans_line = p.stdout.readline()
            if not ans_line:
                err = p.stderr.read()
                with lock:
                    errors[lid] = "EOF after tools/call: " + err
                    write_state("progress")
                break
            ans = json.loads(ans_line)
            p.stdin.close()
            p.wait(timeout=10)
            with lock:
                results[lid] = ans
                write_state("progress")
            break

threads = [threading.Thread(target=wait_for_ready, args=(lid, p)) for lid, p in procs]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=60)

with lock:
    write_state("done")
"#,
    )
    .unwrap();

    let state_file = h.files().join("five_state.json");
    let py = python3();
    let mut cmd = Command::new(testkit_bin("fixture-agent"));
    h.home
        .apply(&mut cmd)
        .arg("--")
        .arg(&py)
        .arg(&coordinator_py)
        .arg(h.cli())
        .arg(&state_file)
        .args(&launch_ids)
        .current_dir(&home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().unwrap();

    // Wait until all 5 bridges have answered `initialize` and 3 pending requests are in `envcloak pending`.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(bytes) = std::fs::read(&state_file) {
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                if v["count"] == 5 {
                    break;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for 5 bridges to initialize"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Verify `envcloak pending` lists exactly 3 requests (`MAX_PENDING_PER_ROOT = 3`).
    let pend1 = h.human(&home, &["pending", "--json"], &[], &[]);
    assert_eq!(pend1.code, 0, "{}", pend1.all());
    let pend1_v: Value = serde_json::from_slice(&pend1.stdout).unwrap();
    let first_batch = pend1_v["requests"].as_array().unwrap();
    assert_eq!(
        first_batch.len(),
        3,
        "expected exactly 3 pending requests (MAX_PENDING_PER_ROOT = 3), got: {pend1_v}"
    );

    // Approve all 5 requests one at a time as they appear in `envcloak pending`:
    // approving each frees a slot for the waiting bridges, and waiting for that
    // bridge's server to answer ensures its post-approval pipe handoff finishes
    // before the next passphrase approval takes the vault out.
    let mut approved_total = 0usize;
    let app_deadline = Instant::now() + Duration::from_secs(60);
    while approved_total < 5 {
        let p = h.human(&home, &["pending", "--json"], &[], &[]);
        let pv: Value = serde_json::from_slice(&p.stdout).unwrap();
        let list = pv["requests"].as_array().unwrap();
        if list.is_empty() {
            assert!(
                Instant::now() < app_deadline,
                "timed out after approving {approved_total}/5 requests"
            );
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let id = list[0]["request"].as_str().unwrap();
        let app = h.human(
            &home,
            &["approve", id, "--for", "1h", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
            &[],
        );
        assert_eq!(app.code, 0, "{}", app.all());
        approved_total += 1;

        while Instant::now() < app_deadline {
            if let Ok(bytes) = std::fs::read(&state_file) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    let done_n = v["results"].as_object().map_or(0, |m| m.len())
                        + v["errors"].as_object().map_or(0, |m| m.len());
                    if done_n >= approved_total {
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert_eq!(approved_total, 5);

    let out = child.wait_with_output().unwrap();
    h.record("five servers coordinator stdout", &out.stdout);
    h.record("five servers coordinator stderr", &out.stderr);
    assert!(out.status.success(), "{}", text(&out));

    let final_state: Value = serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(final_state["phase"], "done", "{final_state}");
    let results = final_state["results"].as_object().unwrap();
    assert_eq!(results.len(), 5, "all 5 servers must answer: {final_state}");
    for (lid, ans) in results {
        let text_out = ans["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text_out.contains(&format!("sha256={stripe_digest}"))
                && text_out.contains("[envcloak:stripe/mcp-cursor-srv-1]"),
            "{lid}: unexpected answer: {ans}"
        );
    }

    h.assert_swept("M2-26 variant five migrated servers");
}
