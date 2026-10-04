//! The pinned agent hosts against the scripted model (M2 plan task M2-04,
//! D-13, R-M2-66, R-M2-78, R-M2-88): the stub answers scripted turns to
//! Claude Code and Codex; a canary a scripted turn prints with plain
//! `printf` is found in the tool result the host sent its model and in
//! that host's transcript (the positive control); a run with no canary
//! leaves none anywhere (the negative control). A command that prints a
//! canary names it in two pieces, so only what it printed can hold it
//! whole.
//!
//! Each host runs in an isolated home with a cleared environment, its
//! flags pinned per run (D-13), and `HTTPS_PROXY` pointed at the model,
//! which refuses and records every tunnel. A host that is not installed
//! (scripts/install-agent-hosts.py) skips its test with a line on
//! standard error, unless ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS is set, as in
//! CI's agent jobs.
//!
//! Lines starting `measurement:` are what docs/AGENTS.md's host behaviour
//! table and docs/ACCEPTANCE.md record; CI prints them on both systems.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use envcloak_agents::probe::model::{QUALIFIED, SERVER};
use envcloak_e2e::k01::{self, Reach, Shell};
use envcloak_e2e::{bin_dir, versions_toml};
use envcloak_testkit::agents::{
    AgentHome, Host, HostFlags, HostRun, Installed, pins, reports_version, require,
};
use envcloak_testkit::transcripts::{OTHER, Sweep};
use envcloak_testkit::{Canary, by_label, canaries, fresh_seed, labels};
use serde_json::json;

fn host(h: Host, variant: &str, test: &str) -> Option<AgentHome> {
    let found = Installed::find(&versions_toml(), h.id(), variant);
    require(found, test).map(|i| AgentHome::start(h, i))
}

/// The hosts run with the network CI says (`ENVCLOAK_TEST_NETWORK`):
/// loopback only, on both systems, so a host's direct connection
/// anywhere, past the proxy the scripted model records, fails; and open
/// in the step before, so that failure is the isolation's (review).
#[test]
fn the_network_is_what_ci_says() {
    envcloak_e2e::check_network();
}

/// One entry point of each way to resolve a name that the isolation
/// leaves open on macOS, written out here from the frameworks' headers,
/// apart from the guard's own table ([`envcloak_e2e::OPEN_RESOLVERS`]),
/// so an entry left out of that table fails its control (Codex review of
/// M2-RES1: the controls were built from the table itself):
/// Network.framework's connections and resolver configuration, libdnssd's
/// XPC lookup, CFNetwork's host lookup, its socket streams to a named
/// host and its two HTTP streams, and URLSession's and NSURLConnection's
/// classes. The guard's unit test in `network.rs` writes the same names.
const OPEN_RESOLVER_ENTRY_POINTS: [&str; 10] = [
    "_nw_connection_create",
    "_nw_resolver_config_create_https",
    "_dnssd_getaddrinfo_create",
    "_CFHostStartInfoResolution",
    "_CFStreamCreatePairWithSocketToHost",
    "_CFStreamCreatePairWithSocketToCFHost",
    "_CFReadStreamCreateForHTTPRequest",
    "_CFReadStreamCreateForStreamedHTTPRequest",
    "_OBJC_CLASS_$_NSURLSession",
    "_OBJC_CLASS_$_NSURLConnection",
];

/// A Mach-O file that imports every one of [`OPEN_RESOLVER_ENTRY_POINTS`]
/// by that very name, built with the system's C compiler (each symbol
/// left for the loader to find, so no framework need be linked): the
/// guard's positive control, one per entry point. Its directory goes with
/// the result.
fn importer_of_every_open_resolver() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::fmt::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let mut c = String::new();
    for (i, sym) in OPEN_RESOLVER_ENTRY_POINTS.iter().enumerate() {
        writeln!(c, "extern char s{i} __asm__(\"{sym}\");").unwrap();
    }
    c.push_str("int main(void) { volatile const void *p[] = {");
    for i in 0..OPEN_RESOLVER_ENTRY_POINTS.len() {
        write!(c, "&s{i}, ").unwrap();
    }
    c.push_str("0}; return p[0] == 0; }\n");
    let src = dir.path().join("imports.c");
    std::fs::write(&src, c).unwrap();
    let out = dir.path().join("imports");
    let built = std::process::Command::new("/usr/bin/cc")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .arg("-Wl,-undefined,dynamic_lookup")
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "the positive control could not be built: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    (dir, out)
}

/// What the loopback-only isolation leaves open on macOS (verifier review
/// of M2-04): the resolver's XPC service, which Network.framework (and
/// URLSession on it) and `dnssd_getaddrinfo` use, and which no file access
/// control can deny, and CFNetwork's own lookups, not shown refused. No
/// executable or library of a pinned host's tree, nor the Node.js that
/// runs a script host, imports any of their entry points
/// ([`envcloak_e2e::OPEN_RESOLVERS`]): a check of static imports only,
/// which a framework loaded at run time (`dlopen`) passes unseen
/// (docs/ACCEPTANCE.md). The positive controls: a program built here that
/// imports every entry is found by each, and `/usr/bin/nscurl`, a client
/// on URLSession and Network.framework, by its URLSession class and its
/// connection calls. On Linux the check does not apply: there is no such
/// API, and systemd-resolved's sockets are stated uncovered in
/// docs/ACCEPTANCE.md.
///
/// Mutations checked: the guard matching no import (`filter` never
/// true): the controls are not found and this fails. Each entry left out
/// of the guard in turn (URLSession's class, as the verifier of M2-RES1
/// found, among them): its entry point, written out here apart from the
/// guard's table, is not found and this fails.
#[test]
fn no_pinned_host_imports_a_resolver_the_isolation_leaves_open() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "no_pinned_host_imports_a_resolver_the_isolation_leaves_open: macOS only (Linux has no \
             such API)"
        );
        return;
    }
    let (_dir, importer) = importer_of_every_open_resolver();
    let hits = envcloak_e2e::open_resolver_imports(&importer).unwrap();
    for entry in OPEN_RESOLVER_ENTRY_POINTS {
        assert!(
            hits.iter().any(|(_, sym)| sym == entry),
            "the guard does not find {entry} in a program that imports it: {hits:?}"
        );
    }
    let control = envcloak_e2e::open_resolver_imports(Path::new("/usr/bin/nscurl")).unwrap();
    for wanted in ["_OBJC_CLASS_$_NSURLSession", "_nw_connection_"] {
        assert!(
            control.iter().any(|(_, sym)| sym.starts_with(wanted)),
            "the positive control, /usr/bin/nscurl, is not found by {wanted}: {control:?}"
        );
    }
    for pin in pins(&versions_toml()) {
        let found = Installed::find(&versions_toml(), &pin.id, &pin.variant);
        let label = format!("{}/{}", pin.id, pin.variant);
        // A tier-1 host is required where CI says so; a tier-2 host is
        // checked when it is installed.
        let installed = if pin.tier == 1 {
            require(found, &format!("open resolver imports ({label})"))
        } else {
            found.ok()
        };
        let Some(i) = installed else {
            continue;
        };
        let mut hits = envcloak_e2e::open_resolver_imports(&i.dir).unwrap();
        if let Some((node, _)) = &i.interpreter {
            hits.extend(envcloak_e2e::open_resolver_imports(node).unwrap());
        }
        assert!(hits.is_empty(), "{label} imports {hits:?}");
        println!(
            "measurement: open resolver imports host={label} version={} os={}: none",
            pin.version,
            os()
        );
    }
}

/// The guard reads every Mach-O format `nm` reads, and never takes a file
/// it cannot read as clean (Codex review of M2-RES1: a fat file with
/// 64-bit offsets was skipped as not Mach-O, and so was a file that could
/// not be opened). The positive controls: the program that imports every
/// entry, made fat with 32-bit and with 64-bit offsets (`lipo -create`,
/// `-fat64`), is found by each entry in each form; and a tree holding a
/// copy of it that cannot be read is an error. As root, a file of mode 0
/// opens anyway, and that case is skipped with a line.
///
/// Mutations checked: `FAT_MAGIC_64` left out of the magic numbers: the
/// 64-bit fat control is skipped and this fails. A file that cannot be
/// opened taken as not Mach-O: the tree passes as clean and this fails.
#[test]
fn the_resolver_guard_reads_every_mach_o_form_and_every_file() {
    if !cfg!(target_os = "macos") {
        eprintln!("the_resolver_guard_reads_every_mach_o_form_and_every_file: macOS only");
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let (dir, importer) = importer_of_every_open_resolver();
    for (name, flags) in [("fat32", &[][..]), ("fat64", &["-fat64"][..])] {
        let out = dir.path().join(name);
        let made = std::process::Command::new("/usr/bin/lipo")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-create")
            .args(flags)
            .arg(&importer)
            .arg("-output")
            .arg(&out)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "lipo {name}: {}",
            String::from_utf8_lossy(&made.stderr)
        );
        let magic = std::fs::read(&out).unwrap()[..4].to_vec();
        let want: &[u8] = if name == "fat64" {
            &[0xca, 0xfe, 0xba, 0xbf]
        } else {
            &[0xca, 0xfe, 0xba, 0xbe]
        };
        assert_eq!(magic, want, "{name}");
        let hits = envcloak_e2e::open_resolver_imports(&out).unwrap();
        for entry in OPEN_RESOLVER_ENTRY_POINTS {
            assert!(
                hits.iter().any(|(_, sym)| sym == entry),
                "the guard does not find {entry} in the {name} control: {hits:?}"
            );
        }
    }
    let tree = tempfile::tempdir().unwrap();
    let hidden = tree.path().join("hidden");
    std::fs::copy(&importer, &hidden).unwrap();
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&hidden).is_ok() {
        eprintln!(
            "the_resolver_guard_reads_every_mach_o_form_and_every_file: a file of mode 0 opens here (root); its case is skipped"
        );
        return;
    }
    let refused = envcloak_e2e::open_resolver_imports(tree.path());
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        refused.as_ref().is_err_and(|e| e.contains("hidden")),
        "a tree holding a file the guard cannot read passed: {refused:?}"
    );
}

/// The flags every run here pins (D-13): Claude Code `-p` in the default
/// permission mode with Bash allowed; Codex `exec` in its workspace-write
/// sandbox with approval policy `never`. Never a bypass mode.
fn flags(h: Host) -> HostFlags {
    match h {
        Host::ClaudeCode => HostFlags::claude("default", &["Bash"]),
        Host::Codex => HostFlags::codex("workspace-write", "never"),
    }
}

/// The store a host keeps its transcripts in.
fn transcript_store(h: Host) -> &'static str {
    match h {
        Host::ClaudeCode => "claude/projects",
        Host::Codex => "codex/sessions",
    }
}

fn os() -> &'static str {
    std::env::consts::OS
}

fn measure(a: &AgentHome, what: &str, value: impl std::fmt::Display) {
    println!(
        "measurement: {what} host={} version={} os={}: {value}",
        a.installed.pin.id,
        a.installed.pin.version,
        os()
    );
}

/// A command that prints each of `values` on a line of its own, each
/// named in two pieces: the command's own text never holds one whole, so
/// a whole one anywhere is what the command printed.
fn print_split(values: &[&str]) -> String {
    values
        .iter()
        .map(|v| {
            let mid = v.len() / 2;
            let (a, b) = v.split_at(
                v.char_indices()
                    .map(|(i, _)| i)
                    .find(|&i| i >= mid)
                    .unwrap_or(mid),
            );
            format!(
                "printf '%s%s\\n' {} {}",
                envcloak_e2e::quoted(a),
                envcloak_e2e::quoted(b)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Linux: whether this process runs in a user namespace (CI's
/// `unshare -rn`) or outside one; empty elsewhere. Sandbox rows say which.
fn namespace() -> &'static str {
    if !cfg!(target_os = "linux") {
        return "";
    }
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(map) if map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"] => {
            " (outside a user namespace)"
        }
        Ok(_) => " (in a user namespace)",
        Err(_) => " (user namespace unknown)",
    }
}

/// The body of the request the script answered with `pick`.
fn body_of(run: &HostRun, pick: &str) -> String {
    let r = run
        .model
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some(pick))
        .unwrap_or_else(|| panic!("no request for {pick}: {:?}", run.model.requests));
    String::from_utf8_lossy(&r.body).into_owned()
}

#[test]
fn the_qualified_table_is_the_pinned_tier_1_hosts() {
    let mut pinned: Vec<(String, String)> = pins(&versions_toml())
        .into_iter()
        .filter(|p| p.tier == 1)
        .map(|p| (p.id, p.version))
        .collect();
    pinned.sort();
    pinned.dedup();
    let mut qualified: Vec<(String, String)> = QUALIFIED
        .iter()
        .map(|q| (q.host.to_owned(), q.version.to_owned()))
        .collect();
    qualified.sort();
    assert_eq!(pinned, qualified);
}

#[test]
fn the_scripted_model_is_never_linked_into_envcloak_or_envcloakd() {
    let contains = |p: &Path| {
        let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
        bytes.windows(SERVER.len()).any(|w| w == SERVER.as_bytes())
    };
    let bins = bin_dir();
    for name in ["envcloak", "envcloakd"] {
        assert!(
            !contains(&bins.join(name)),
            "{name} holds the scripted model"
        );
    }
    // The positive control: the model's own program holds it.
    let model = envcloak_testkit::agents::probe_model_exe();
    assert!(contains(&model), "the sentinel is not where it must be");
}

fn scripted_turns(h: Host, variant: &str) {
    let Some(a) = host(h, variant, "scripted_turns") else {
        return;
    };
    let marker = format!("ecturn-{:016x}", fresh_seed());
    let script = json!({"steps": [
        {"say": "running the step", "shell": print_split(&[&marker])},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Run the scripted step.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert!(
        String::from_utf8_lossy(&run.output.stdout).contains("done"),
        "{}",
        run.text()
    );
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    let picks: Vec<&str> = run
        .model
        .model_calls()
        .iter()
        .filter_map(|r| r.pick.as_deref())
        .collect();
    assert_eq!(picks, ["step 0", "step 1"], "{:?}", run.model.requests);
    // The host ran the command and sent its output back.
    assert!(
        last_tool_output(&body_of(&run, "step 1")).contains(&marker),
        "{}",
        run.text()
    );
    // As a diagnostic shows a request a host sent (no value, whatever it
    // put in a request line): endpoints and host names, else lengths.
    measure(
        &a,
        "model endpoints",
        run.model.shown_model_endpoints().join(", "),
    );
    measure(&a, "tunnels refused", run.model.shown_connects().join(", "));
    measure(&a, "seconds", run.elapsed.as_secs_f32());
}

#[test]
fn claude_code_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "native");
}

#[test]
fn claude_code_from_npm_is_served_scripted_turns() {
    scripted_turns(Host::ClaudeCode, "npm");
}

#[test]
fn codex_is_served_scripted_turns() {
    scripted_turns(Host::Codex, "native");
}

/// Claude Code from npm with install scripts off: `node cli-wrapper.cjs`
/// is the entry, and the native binary its child (F-37's
/// interpreter-launched layout, which M2-10 classifies on an asserted
/// basis). Served like the native build, and the shell tool's ancestry,
/// nearest first up to the test, is recorded: the command's shell, the
/// native binary, Node.
#[test]
fn claude_code_through_node_is_served_scripted_turns_and_its_layout_recorded() {
    scripted_turns(Host::ClaudeCode, "npm-wrapper");
    let Some(a) = host(Host::ClaudeCode, "npm-wrapper", "npm_wrapper_layout") else {
        return;
    };
    let probe = format!(
        "p=$$; printf '%s%s' 'ANC' 'ESTRY['; while [ \"$p\" != {test} ] && [ \"$p\" -gt 1 ]; do \
         printf '%s,' \"$(basename \"$(ps -o comm= -p \"$p\")\")\"; \
         p=$(ps -o ppid= -p \"$p\" | tr -d ' '); done; printf '%s%s' ']' 'END'",
        test = std::process::id()
    );
    let script = json!({"steps": [{"shell": probe}, {"say": "done"}]});
    let run = a.run(
        &script,
        "Show the ancestry.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let text = last_tool_output(&body_of(&run, "step 1"));
    let start = text.rfind("ANCESTRY[").map(|i| i + 9).unwrap_or(0);
    let end = text[start..].find("]END").map_or(start, |i| start + i);
    let chain: Vec<&str> = text[start..end]
        .split(',')
        .filter(|s| !s.is_empty())
        .collect();
    measure(&a, "shell tool ancestry, nearest first", chain.join(" <- "));
    let node = chain.iter().position(|n| *n == "node");
    let native = chain.iter().position(|n| *n == "claude");
    assert!(
        matches!((native, node), (Some(c), Some(n)) if c < n),
        "the native binary is not a child of node: {chain:?}"
    );
}

/// A canary printed by a scripted turn with plain `echo` must be found in
/// the host's transcript store and in the model's request bodies: the
/// sweep's positive control (L-01, SI-18). Raw counts per store are
/// printed for docs/ACCEPTANCE.md.
fn positive_control(h: Host) {
    let Some(a) = host(h, "native", "positive_control") else {
        return;
    };
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    // A key-shaped one too, printed the same way: whether a host keeps a
    // key it saw printed, raw.
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).clone();
    let script = json!({"steps": [
        {"shell": print_split(&[control.as_str(), key.as_str()])},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print the two lines.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "exit code");
    assert!(run.model.clean(), "{:?}", run.model.outcome);
    // The command named it in two pieces: whole, it is what the command
    // printed, and the tool result the host sent holds it.
    assert!(
        last_tool_output(&body_of(&run, "step 1")).contains(control.as_str()),
        "the printed control is not in the tool result the host sent its model"
    );
    let all = [control.clone(), key.clone()];
    let hits = Sweep::host_stores(&a, &all, &[&run.model]);
    print!(
        "measurement: store hits host={} os={}:\n{hits}",
        a.installed.pin.id,
        os()
    );
    let store = transcript_store(h);
    assert!(
        hits.in_store_as(store, "POSITIVE_CONTROL", "raw") >= 1,
        "the positive control is not in {store}:\n{hits}"
    );
    assert!(
        hits.in_model("POSITIVE_CONTROL") >= 1,
        "the positive control is not in the model's request bodies:\n{hits}"
    );
    measure(
        &a,
        "printed key kept raw in the transcript",
        hits.in_store_as(store, &key.label, "raw"),
    );
    // Every hit outside the listed stores is reported, never dropped: a
    // new store shows up here first.
    measure(
        &a,
        "control hits outside the listed stores",
        hits.in_store(OTHER, "POSITIVE_CONTROL"),
    );
}

#[test]
fn claude_code_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::ClaudeCode);
}

#[test]
fn codex_keeps_what_a_scripted_turn_prints() {
    positive_control(Host::Codex);
}

/// Claude Code 2.1.280 writes what a Bash command prints, while it runs,
/// to `claude-<uid>/<project>/<session>/tasks/<id>.output` in its per-user
/// temporary directory, outside `HOME`, and deletes the file when the
/// command ends (verifier, medium: in no store list, so the sweep never
/// looked there; a host killed mid-command leaves it). A control the
/// command prints is found there while the command waits on a barrier
/// file, and the directory is the one `CLAUDE_CODE_TMPDIR` names in the
/// home: nothing is kept in `/tmp/claude-<uid>/` (checked after the run).
#[test]
fn claude_code_keeps_a_running_command_s_output_in_its_temporary_store() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_temporary_store") else {
        return;
    };
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecrun-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let release = a.root().join("release");
    // Where the Bash tool has the shell write its working directory when
    // the command ends: the last word of the shell's own arguments
    // (`... && pwd -P >| <file>`, verifier, low).
    let shell = format!(
        "{}; printf '%s%s%s%s\\n' 'CWD' 'FILE[' \"$(ps -ww -o args= -p $$ | awk '{{print $NF}}')\" ']END'; {}",
        print_split(&[control.as_str()]),
        barrier(&release, a.root(), 1200)
    );
    let script = json!({"steps": [{"shell": shell}, {"say": "done"}]});
    let running = a.spawn(
        &script,
        "Run the step.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    let cs = [control.clone()];
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let while_running = loop {
        let hits = Sweep::host_stores(&a, &cs, &[]);
        if hits.in_store("claude/tmp", &control.label) > 0 {
            break hits;
        }
        assert!(
            std::time::Instant::now() < end,
            "the running command's output never reached claude/tmp:\n{hits}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    std::fs::write(&release, b"").unwrap();
    let run = running.wait();
    a.check_pinned();
    a.check_isolated();
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert!(
        last_tool_output(&body_of(&run, "step 1"))
            .split_whitespace()
            .any(|w| w == "released"),
        "the command did not end by its release"
    );
    let after = Sweep::host_stores(&a, &cs, &[&run.model]);
    let said = last_tool_output(&body_of(&run, "step 1"));
    let cwd_file = said
        .split("CWDFILE[")
        .nth(1)
        .and_then(|r| r.split("]END").next())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| panic!("the shell's arguments were not shown: {said}"));
    // As docs/AGENTS.md records: directly in CLAUDE_CODE_TMPDIR (which
    // the harness keeps apart from TMPDIR), named as the sweep's
    // `claude/cwd` store expects, and gone once the host has read it.
    let name = cwd_file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let left = std::fs::symlink_metadata(&cwd_file).is_ok();
    measure(
        &a,
        "the Bash tool's working-directory file",
        format!(
            "in {} ({name}); there after the command: {left}",
            if cwd_file.parent() == Some(a.claude_tmp().as_path()) {
                "CLAUDE_CODE_TMPDIR"
            } else {
                "neither CLAUDE_CODE_TMPDIR nor where it was seen"
            },
        ),
    );
    assert_eq!(
        cwd_file.parent(),
        Some(a.claude_tmp().as_path()),
        "the working-directory file is not in CLAUDE_CODE_TMPDIR"
    );
    assert!(
        envcloak_testkit::transcripts::is_claude_cwd_file(&name),
        "{name}"
    );
    assert!(
        !left,
        "the working-directory file was left after the command"
    );
    measure(
        &a,
        "a running Bash command's printed output in claude/tmp",
        format!(
            "while it runs: {} hit(s); after it ended: {}",
            while_running.in_store("claude/tmp", &control.label),
            after.in_store("claude/tmp", &control.label)
        ),
    );
}

/// A command that waits until `release` exists, and prints `released`;
/// it also ends on its own, printing `unreleased`, once `root` is gone or
/// after `ticks` tenths of a second (verifier, low: Claude Code 2.1.280
/// runs a Bash command in a process group of its own, which the harness's
/// group kill does not reach and D-34 forbids signalling by number, so a
/// wait with no end of its own outlived a failed test, polling forever).
fn barrier(release: &Path, root: &Path, ticks: u32) -> String {
    let q = |p: &Path| envcloak_e2e::quoted(p.to_str().unwrap());
    format!(
        "i=0; while [ ! -e {r} ] && [ -d {d} ] && [ $i -lt {ticks} ]; do sleep 0.1; i=$((i+1)); \
         done; if [ -e {r} ]; then echo released; else echo unreleased; fi",
        r = q(release),
        d = q(root),
    )
}

/// The barrier ends on its own: when released, when its root is gone,
/// and at its bound, each well within the time a wait without an end
/// would take (here 600 tenths of a second).
#[test]
fn the_barrier_a_host_s_command_waits_on_ends_on_its_own() {
    let run = |setup: &dyn Fn(&Path, &Path), ticks: u32| {
        let home = envcloak_testkit::TestHome::new();
        let root = home.root().join("root");
        std::fs::create_dir(&root).unwrap();
        let release = root.join("release");
        let start = std::time::Instant::now();
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(barrier(&release, &root, ticks))
            .env_clear()
            .env("PATH", envcloak_testkit::TEST_PATH)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        setup(&release, &root);
        let end = start + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                let mut out = String::new();
                std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out).unwrap();
                return out;
            }
            if std::time::Instant::now() > end {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the barrier did not end within 30 s");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };
    let released = run(&|release, _| std::fs::write(release, b"").unwrap(), 600);
    assert_eq!(released, "released\n");
    let gone = run(&|_, root| std::fs::remove_dir(root).unwrap(), 600);
    assert_eq!(gone, "unreleased\n");
    let bounded = run(&|_, _| {}, 10);
    assert_eq!(bounded, "unreleased\n");
}

/// A run that never sees a canary leaves none anywhere: not in the host's
/// stores, not in the rest of the home, not in what it sent its model.
fn negative_control(h: Host) {
    let Some(a) = host(h, "native", "negative_control") else {
        return;
    };
    let cs = canaries(fresh_seed());
    let script = json!({"steps": [
        {"shell": "echo nothing secret here"},
        {"say": "done"},
    ]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let hits = Sweep::host_stores(&a, &cs, &[&run.model]);
    assert_eq!(hits.total(), 0, "{hits}");
    let home = a.test_home().unwrap();
    assert!(home.sweep(&cs).is_empty(), "the home holds a canary");
}

#[test]
fn claude_code_negative_control_is_clean() {
    negative_control(Host::ClaudeCode);
}

#[test]
fn codex_negative_control_is_clean() {
    negative_control(Host::Codex);
}

/// Every file a host wrote in its home, by path relative to `HOME`
/// (names only), for the store list in docs/ACCEPTANCE.md.
fn files_written(a: &AgentHome) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap_or(&p).display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    let home = a.home_dir();
    walk(&home, &home, &mut out);
    out.sort();
    out
}

fn stores_written(h: Host) {
    let Some(a) = host(h, "native", "stores_written") else {
        return;
    };
    let script = json!({"steps": [{"shell": "echo stores"}, {"say": "done"}]});
    let run = a.run(&script, "Print a line.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    // Collapse ids so the list reads as shapes.
    // The skills Codex unpacks at every start are its own files, not a
    // store of what it saw.
    let shapes: Vec<String> = files_written(&a)
        .into_iter()
        .filter(|f| !f.starts_with(".codex/skills/.system/") && !f.starts_with(".codex/tmp/arg0/"))
        .map(|f| {
            f.split('/')
                .map(|part| {
                    if part.chars().filter(char::is_ascii_hexdigit).count() >= 8 {
                        "<id>".to_owned()
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    measure(&a, "files written", shapes.join(", "));
}

#[test]
fn claude_code_stores() {
    stores_written(Host::ClaudeCode);
}

#[test]
fn codex_stores() {
    stores_written(Host::Codex);
}

// ---------------------------------------------------------------------
// Measurements for docs/AGENTS.md "Host behaviour" (M2-04): each prints
// `measurement:` lines and asserts only what it must for the next tasks.
// ---------------------------------------------------------------------

/// What the host sent back for a call: the body of the request the
/// script answered with `pick` (the turn after the call).
fn after_call(run: &HostRun, pick: &str) -> String {
    body_of(run, pick)
}

/// The value printed after `key` (`KEY<value>`), up to a space, a quote
/// or a backslash, in `text`; the last such.
fn printed(text: &str, key: &str) -> Option<String> {
    let at = text.rfind(key)? + key.len();
    let value: String = text[at..]
        .chars()
        .take_while(|c| !matches!(c, ' ' | '"' | '\\' | '\n'))
        .collect();
    Some(value)
}

/// What a command run by the shell tool has for a terminal: whether each
/// standard stream is one (`[ -t fd ]`), whether it has a controlling
/// terminal (it can open `/dev/tty`, which only a process with one can),
/// and that terminal's name as `ps` gives it. Not `tty`, which reports on
/// standard input alone (verifier, medium: a command whose input is
/// redirected has a controlling terminal `tty` cannot see). The keys are
/// built at run time, so the command's own text never matches them.
const TTY_PROBE: &str = "for fd in 0 1 2; do if [ -t $fd ]; then t=T; else t=N; fi; \
     printf '%s%s%s ' FD $fd $t; done; \
     if (: </dev/tty) 2>/dev/null; then t=Y; else t=N; fi; printf '%s%s ' CTTY $t; \
     t=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' '); printf '%s%s ' TTYNAME \"${t:-none}\"";

/// [`TTY_PROBE`]'s answer in `output`, as `stdin=.. stdout=.. stderr=..
/// controlling-terminal=.. (name)`; `None` when a part of it is missing.
fn tty_shown(output: &str) -> Option<String> {
    let get = |k: &str| printed(output, k).filter(|v| !v.is_empty());
    Some(format!(
        "stdin={} stdout={} stderr={} controlling-terminal={} ({})",
        get("FD0")?,
        get("FD1")?,
        get("FD2")?,
        get("CTTY")?,
        get("TTYNAME")?
    ))
}

/// The probe itself, with no host: under a pseudo-terminal of its own with
/// standard input from `/dev/null`, it reports a controlling terminal and
/// a standard input that is not a terminal; in a new session with no
/// terminal, no controlling terminal. A probe that read the controlling
/// terminal from standard input (`tty`) fails the first.
#[test]
fn the_terminal_probe_reads_the_controlling_terminal_not_standard_input() {
    let driver = "import os, pty, sys\n\
        probe = sys.argv[2]\n\
        if sys.argv[1] == 'pty':\n\
        \x20   pid, fd = pty.fork()\n\
        \x20   if pid == 0:\n\
        \x20       null = os.open('/dev/null', os.O_RDONLY)\n\
        \x20       os.dup2(null, 0)\n\
        \x20       os.execv('/bin/sh', ['/bin/sh', '-c', probe])\n\
        \x20   out = b''\n\
        \x20   while True:\n\
        \x20       try:\n\
        \x20           c = os.read(fd, 4096)\n\
        \x20       except OSError:\n\
        \x20           break\n\
        \x20       if not c:\n\
        \x20           break\n\
        \x20       out += c\n\
        \x20   os.waitpid(pid, 0)\n\
        \x20   sys.stdout.write(out.decode())\n\
        else:\n\
        \x20   os.setsid()\n\
        \x20   os.execv('/bin/sh', ['/bin/sh', '-c', probe])\n";
    let run = |mode: &str| {
        let out = std::process::Command::new(envcloak_e2e::python3())
            .args(["-c", driver, mode, TTY_PROBE])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        tty_shown(&text).unwrap_or_else(|| panic!("the probe printed {text:?}"))
    };
    let in_terminal = run("pty");
    assert!(
        in_terminal.starts_with("stdin=N stdout=T stderr=T controlling-terminal=Y"),
        "{in_terminal}"
    );
    let detached = run("setsid");
    assert!(
        detached.starts_with("stdin=N stdout=N stderr=N controlling-terminal=N"),
        "{detached}"
    );
}

/// Whether the shell tool's standard streams are terminals and whether it
/// has a controlling terminal ([`TTY_PROBE`]), as the harness runs a host
/// here: `-p` or `exec`, standard input from `/dev/null`, in a session of
/// its own with no terminal (M2-17 and M2-19 depend on it; the interactive
/// case is in [`claude_code_interactive_trust_and_paste`]).
fn tty_in_the_shell_tool(h: Host) {
    let Some(a) = host(h, "native", "tty_in_the_shell_tool") else {
        return;
    };
    let script = json!({"steps": [{"shell": TTY_PROBE}, {"say": "done"}]});
    let run = a.run(&script, "Check the terminal.", &flags(h), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let output = last_tool_output(&after_call(&run, "step 1"));
    let shown = tty_shown(&output).unwrap_or_else(|| panic!("the probe printed {output:?}"));
    measure(
        &a,
        "shell tool terminal, no terminal for the host (T=tty, N=not)",
        &shown,
    );
    // docs/AGENTS.md, both hosts and systems (Codex review, medium: only
    // printed). The probe's control is
    // the_terminal_probe_reads_the_controlling_terminal_not_standard_input.
    assert!(
        shown.starts_with(NO_TERMINAL),
        "the shell tool's command has a terminal: {shown}"
    );
}

#[test]
fn claude_code_shell_tool_terminal() {
    tty_in_the_shell_tool(Host::ClaudeCode);
}

#[test]
fn codex_shell_tool_terminal() {
    tty_in_the_shell_tool(Host::Codex);
}

/// The names (never the values) of the variables the shell tool's
/// commands get: the host's markers, and whether the model credential
/// the host was given reaches them.
fn environment_in_the_shell_tool(h: Host) {
    let Some(a) = host(h, "native", "environment_in_the_shell_tool") else {
        return;
    };
    // Quoted: an unquoted `[` is a pattern to zsh, Codex's and macOS's
    // shell. The keys are built at run time, so the command never matches.
    let probe = "printf '%s%s' 'NAM' 'ES['; env | cut -d= -f1 | sort | tr '\\n' ' '; \
                 printf '%s%s' ']' 'END'";
    let script = json!({"steps": [{"shell": probe}, {"say": "done"}]});
    let run = a.run(
        &script,
        "List the variable names.",
        &flags(h),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let text = after_call(&run, "step 1");
    let start = text.rfind("NAMES[").map(|i| i + 6).unwrap_or(0);
    let end = text[start..]
        .find("]END")
        .map(|i| start + i)
        .unwrap_or(start);
    let names: Vec<&str> = text[start..end].split_whitespace().collect();
    assert!(!names.is_empty(), "no names printed");
    let markers: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| {
            ["CLAUDE", "CODEX", "AGENT", "SANDBOX", "PROXY", "ENTRYPOINT"]
                .iter()
                .any(|m| n.contains(m))
        })
        .collect();
    measure(&a, "shell tool marker variables", markers.join(" "));
    let credential = match h {
        Host::ClaudeCode => "ANTHROPIC_API_KEY",
        Host::Codex => "EC_MODEL_TOKEN",
    };
    measure(
        &a,
        &format!("shell tool gets the model credential ({credential})"),
        names.contains(&credential),
    );
    // docs/AGENTS.md (Codex review, medium: only printed): every marker
    // it lists for this host and system is there (M2-10 matches on them),
    // and the model credential reaches commands (the inject-mode limit).
    let documented: &[&str] = match h {
        Host::ClaudeCode => &[
            "AI_AGENT",
            "CLAUDECODE",
            "CLAUDE_CODE_ENTRYPOINT",
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_CODE_CHILD_SESSION",
            "CLAUDE_CODE_EXECPATH",
            "CLAUDE_CODE_MESSAGING_SOCKET",
            "CLAUDE_CODE_MESSAGING_TOKEN",
            "CLAUDE_CODE_SESSION_ATTENDED",
            "CLAUDE_EFFORT",
            "CLAUDE_PID",
        ],
        Host::Codex if cfg!(target_os = "macos") => &[
            "CODEX_CI",
            "CODEX_HOME",
            "CODEX_SANDBOX",
            "CODEX_SANDBOX_NETWORK_DISABLED",
            "CODEX_SESSION_ID",
            "CODEX_THREAD_ID",
            "CODEX_VERSION",
        ],
        Host::Codex => &[
            "CODEX_CI",
            "CODEX_HOME",
            "CODEX_SANDBOX_NETWORK_DISABLED",
            "CODEX_SESSION_ID",
            "CODEX_THREAD_ID",
            "CODEX_VERSION",
        ],
    };
    let missing: Vec<&&str> = documented.iter().filter(|m| !names.contains(m)).collect();
    assert!(
        missing.is_empty(),
        "documented markers missing: {missing:?}"
    );
    assert!(
        names.contains(&credential),
        "{credential} no longer reaches commands"
    );
}

#[test]
fn claude_code_shell_tool_environment() {
    environment_in_the_shell_tool(Host::ClaudeCode);
}

#[test]
fn codex_shell_tool_environment() {
    environment_in_the_shell_tool(Host::Codex);
}

fn fixture_mcp() -> std::path::PathBuf {
    envcloak_testkit::testkit_bin("ec-mcp-fixture")
}

/// The milliseconds between the model's answer to `call` (the tool call)
/// and the host's next request (`next`): how long the host waited.
fn waited(run: &HostRun, call: &str, next: &str) -> u64 {
    let at = |p: &str| {
        run.model
            .requests
            .iter()
            .find(|r| r.pick.as_deref() == Some(p))
            .map(|r| r.at_ms)
            .unwrap_or_else(|| panic!("no request for {p}"))
    };
    at(next).saturating_sub(at(call))
}

/// Claude Code and an MCP server it starts (registered with its own CLI,
/// `claude mcp add-json`, as the installer will): the server's ancestry
/// and environment names, and the tool-call cutoff under `-p` without and
/// with a per-server `timeout` of 60 s (Map C §8 item 1, K-08, SI-17),
/// which sets M2-06's `--wait-ms` default: calls of 30 s and 70 s, so the
/// cutoff is seen where it falls inside 70 s, and otherwise 70 s is the
/// lower bound recorded.
#[test]
fn claude_code_mcp_server_and_tool_cutoff() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_mcp") else {
        return;
    };
    let server = fixture_mcp();
    let register = |timeout: Option<u64>| {
        let _ = a.host_cli(&["mcp", "remove", "--scope", "user", "fixture"]);
        let mut entry = json!({"command": server.to_str().unwrap(), "args": []});
        if let Some(t) = timeout {
            entry["timeout"] = json!(t);
        }
        let out = a.host_cli(&[
            "mcp",
            "add-json",
            "--scope",
            "user",
            "fixture",
            &entry.to_string(),
        ]);
        assert!(
            out.status.success(),
            "claude mcp add-json: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let tools = HostFlags::claude("default", &["mcp__fixture__whoami", "mcp__fixture__wait"]);

    register(None);
    let whoami = json!({"steps": [{"tool": "mcp__fixture__whoami", "input": {}}, {"say": "done"}]});
    // A call made before Claude Code has connected the new server gets an
    // error instead of an answer: tried up to three times, and what the
    // earlier tries got is recorded with the answer.
    let mut earlier = Vec::new();
    let text = loop {
        let run = a.run(&whoami, "Who is the server?", &tools, &a.home_dir());
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let text = after_call(&run, "step 1");
        if text.contains("ancestry=") {
            break text;
        }
        // The fixture's answers hold names only; an error is the host's.
        let got: String = last_tool_output(&text).chars().take(160).collect();
        earlier.push(got);
        assert!(
            earlier.len() < 3,
            "the whoami call was never answered: {earlier:?}"
        );
    };
    let at = text.rfind("ancestry=").unwrap_or(0) + 9;
    let ancestry = text[at..]
        .split(['"', '\\'])
        .next()
        .unwrap_or("")
        .to_owned();
    measure(&a, "MCP server ancestry", &ancestry);
    if !earlier.is_empty() {
        measure(
            &a,
            "MCP call before the answer, tries",
            format!("{earlier:?}"),
        );
    }
    let env = printed(&text, "env=").unwrap_or_default();
    let markers: Vec<&str> = env
        .split(',')
        .filter(|n| {
            ["CLAUDE", "AGENT", "ENTRYPOINT", "ANTHROPIC"]
                .iter()
                .any(|m| n.contains(m))
        })
        .collect();
    measure(&a, "MCP server marker variables", markers.join(" "));

    for timeout in [None, Some(60_000)] {
        register(timeout);
        for call_ms in [30_000u64, 70_000] {
            let wait = json!({"steps": [
                {"tool": "mcp__fixture__wait", "input": {"ms": call_ms}},
                {"say": "done"},
            ]});
            let run = a.run(&wait, "Wait.", &tools, &a.home_dir());
            assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
            let after = after_call(&run, "step 1");
            let answered = after.contains(&format!("waited {call_ms}"));
            let ms = waited(&run, "step 0", "step 1");
            let setting = match timeout {
                None => "no per-server timeout".to_owned(),
                Some(t) => format!("per-server timeout {t} ms"),
            };
            measure(
                &a,
                &format!("MCP tool call of {} s under -p, {setting}", call_ms / 1000),
                format!(
                    "{} after {:.1} s",
                    if answered { "answered" } else { "cut off" },
                    ms as f64 / 1000.0
                ),
            );
            // What docs/AGENTS.md records, asserted (review: a
            // measurement only printed cannot fail): with no per-server
            // timeout both calls are answered, each after its own length;
            // with one of 60 s the 30 s call is answered and the 70 s call
            // cut off after 60 s, give or take the host's own turn.
            match (timeout, answered) {
                (Some(t), false) if call_ms > t => assert!(
                    (t.saturating_sub(500)..t + 6_000).contains(&ms),
                    "the {call_ms} ms call was cut off after {ms} ms, not at the {t} ms timeout"
                ),
                (_, true) if timeout.is_none_or(|t| call_ms < t) => assert!(
                    ms + 500 >= call_ms,
                    "the {call_ms} ms call was answered after {ms} ms"
                ),
                _ => panic!(
                    "the {call_ms} ms call under {setting} was {} after {ms} ms",
                    if answered { "answered" } else { "cut off" }
                ),
            }
        }
    }
}

/// Codex and an MCP server registered with its own CLI (`codex mcp add
/// fixture -- <command>`, which writes `[mcp_servers.fixture]` with the
/// command), plus the two keys that CLI cannot set, as the person's
/// settings (M2-08's installer writes the same): how its tools are
/// offered (a `mcp__fixture` namespace in 0.159.2), whether a call runs
/// under `exec` with approval policy `never` for each per-server
/// `default_tools_approval_mode` (SI-17; the meaning of `auto`), the
/// server's ancestry, and the cutoff `tool_timeout_sec` sets.
#[test]
fn codex_mcp_server_approval_modes_and_tool_cutoff() {
    let Some(mut a) = host(Host::Codex, "native", "codex_mcp") else {
        return;
    };
    let server = fixture_mcp();
    let added = a.host_cli(&["mcp", "add", "fixture", "--", server.to_str().unwrap()]);
    assert!(
        added.status.success(),
        "codex mcp add: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    // What the CLI wrote (a path is the same string in TOML and JSON).
    let written = std::fs::read_to_string(a.codex_home().join("config.toml")).unwrap();
    assert!(
        written.contains("[mcp_servers.fixture]")
            && written.contains(&format!("command = {}", json!(server.to_str().unwrap()))),
        "{written}"
    );
    let config = |mode: Option<&str>, timeout: u64| {
        let mut t = format!("[mcp_servers.fixture]\ntool_timeout_sec = {timeout}\n");
        if let Some(m) = mode {
            t.push_str(&format!("default_tools_approval_mode = \"{m}\"\n"));
        }
        t
    };
    let whoami = json!({"steps": [
        {"tool": "whoami", "namespace": "mcp__fixture", "input": {}},
        {"say": "done"},
    ]});
    let mut ran_with = Vec::new();
    for mode in [None, Some("auto"), Some("prompt"), Some("approve")] {
        a.codex_config(&config(mode, 60));
        let run = a.run(
            &whoami,
            "Who is the server?",
            &flags(Host::Codex),
            &a.home_dir(),
        );
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        if mode.is_none() {
            let offered = run
                .model
                .model_calls()
                .first()
                .and_then(|r| r.json())
                .map(|b| {
                    b["tools"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|t| t["name"] == "mcp__fixture")
                        .map(|t| format!("{} {}", t["type"], t["name"]))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            measure(&a, "MCP tools offered as", offered);
        }
        let text = after_call(&run, "step 1");
        let ran = text.contains("ancestry=");
        measure(
            &a,
            &format!(
                "MCP call under exec, approval never, default_tools_approval_mode {}",
                mode.unwrap_or("unset")
            ),
            if ran { "ran" } else { "refused" },
        );
        if ran {
            ran_with.push(mode);
            let at = text.rfind("ancestry=").unwrap_or(0) + 9;
            let ancestry = text[at..].split(['"', '\\']).next().unwrap_or("");
            measure(&a, "MCP server ancestry", ancestry);
        }
    }
    // Under `exec` with approval policy `never`, only `approve` lets the
    // call run: unset, `auto` and `prompt` are refused (review: a
    // test that only required `approve` to run passed whatever the others
    // did).
    assert_eq!(
        ran_with,
        [Some("approve")],
        "the approval modes that let the call run"
    );
    // The cutoff: a 15 s call under tool_timeout_sec = 5.
    a.codex_config(&config(Some("approve"), 5));
    let wait = json!({"steps": [
        {"tool": "wait", "namespace": "mcp__fixture", "input": {"ms": 15000}},
        {"say": "done"},
    ]});
    let run = a.run(&wait, "Wait.", &flags(Host::Codex), &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let answered = after_call(&run, "step 1").contains("waited 15000");
    let ms = waited(&run, "step 0", "step 1");
    measure(
        &a,
        "MCP tool call of 15 s, tool_timeout_sec = 5",
        format!(
            "{} after {:.1} s",
            if answered { "answered" } else { "cut off" },
            ms as f64 / 1000.0
        ),
    );
    // The setting is the cutoff: cut off after 5 s, give or take the
    // host's own turn, never answered after 15 s (review: printed
    // only, it could not fail).
    assert!(
        !answered,
        "a 15 s call was answered under tool_timeout_sec = 5"
    );
    assert!(
        (4_500..10_000).contains(&ms),
        "the 15 s call was cut off after {ms} ms, not at tool_timeout_sec = 5"
    );
}

/// A hook command that saves every payload it gets under `dir`, named by
/// its event, and blocks a prompt holding `BLOCK-ME-NOW` (exit 2, the
/// documented block for both hosts) and sleeps 10 s on one holding
/// `SLOW-HOOK`.
fn hook_command(dir: &Path) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("hook.sh");
    envcloak_e2e::write_script(
        &path,
        &format!(
            "#!/bin/sh\nevent=\"$1\"\nf='{}'/\"$event\".$$.json\ncat > \"$f\"\n\
             case \"$event\" in UserPromptSubmit)\n\
             if grep -q SLOW-HOOK \"$f\"; then sleep 10; fi\n\
             if grep -q BLOCK-ME-NOW \"$f\"; then echo 'blocked by the fixture hook' >&2; exit 2; fi;;\n\
             esac\nexit 0\n",
            dir.display()
        ),
    );
    path
}

/// The payloads the hook saved for `event`, newest last.
fn payloads(dir: &Path, event: &str) -> Vec<serde_json::Value> {
    let mut found: Vec<(std::time::SystemTime, serde_json::Value)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("{event}."))
        })
        .filter_map(|e| {
            let at = e.metadata().ok()?.modified().ok()?;
            let v = serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
            Some((at, v))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, v)| v).collect()
}

/// A payload with what differs from run to run (ids, paths, times)
/// replaced by fixed placeholders, keeping every key and value type, so
/// it can be compared with the fixture M2-08's parsers test against.
fn normalized(v: &serde_json::Value, home: &Path) -> serde_json::Value {
    use serde_json::Value;
    let home = home.to_string_lossy().into_owned();
    let private = format!("/private{home}");
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| {
                    let v = match (k.as_str(), v) {
                        (
                            "session_id" | "turn_id" | "tool_use_id" | "agent_id",
                            Value::String(_),
                        ) => {
                            json!("<id>")
                        }
                        _ => normalized(v, Path::new(&home)),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(a) => {
            Value::Array(a.iter().map(|x| normalized(x, Path::new(&home))).collect())
        }
        Value::String(s) => {
            // Claude Code names a project's transcript directory after its
            // path, with `/` and `.` as `-`.
            let encoded = |p: &str| p.replace(['/', '.'], "-");
            let s = s
                .replace(&private, "<home>")
                .replace(&home, "<home>")
                .replace(&encoded(&private), "<home-as-directory-name>")
                .replace(&encoded(&home), "<home-as-directory-name>");
            // Session files are named by id, and Codex's sit under dated
            // directories.
            let s = s
                .split('/')
                .map(|part| {
                    if part.chars().filter(char::is_ascii_hexdigit).count() >= 16 {
                        "<id>".to_owned()
                    } else if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                        "<n>".to_owned()
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            Value::String(s)
        }
        other => other.clone(),
    }
}

/// Compares `got` with the fixture `name` of `host` (written instead when
/// ENVCLOAK_TEST_WRITE_FIXTURES is set, by a maintainer pinning a new
/// version): the real payloads, with synthetic content, that M2-08's hook
/// parsers test against.
fn payload_fixture(a: &AgentHome, name: &str, got: &serde_json::Value) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hook-payloads")
        .join(format!(
            "{}-{}",
            a.installed.pin.id, a.installed.pin.version
        ));
    let path = dir.join(format!("{name}.json"));
    let text = format!("{}\n", serde_json::to_string_pretty(got).unwrap());
    if std::env::var_os("ENVCLOAK_TEST_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(text, want, "{} drifted from {}", name, path.display());
}

/// Claude Code's hooks under `-p`: the real `UserPromptSubmit` and
/// `PreToolUse` payloads (fixtures for M2-08), and whether a prompt a hook
/// blocks still reaches `history.jsonl` or the transcript (K-14, R-M2-85),
/// and the model.
#[test]
fn claude_code_hooks_and_blocked_prompt_persistence() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_hooks") else {
        return;
    };
    let dir = a.root().join("hook-payloads");
    let hook = hook_command(&dir);
    let command = |event: &str| format!("{} {event}", hook.display());
    // The person's settings: two hooks in the user settings file.
    let settings = json!({"hooks": {
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": command("UserPromptSubmit")}]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command("PreToolUse")}]}],
    }});
    std::fs::create_dir_all(a.home_dir().join(".claude")).unwrap();
    std::fs::write(
        a.home_dir().join(".claude/settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .unwrap();
    let script = json!({"steps": [{"shell": "echo hook-check"}, {"say": "done"}]});
    let run = a.run(
        &script,
        "List the files here.",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    for event in ["UserPromptSubmit", "PreToolUse"] {
        let got = payloads(&dir, event);
        assert!(!got.is_empty(), "no {event} payload");
        payload_fixture(&a, event, &normalized(&got[got.len() - 1], &a.home_dir()));
    }

    let control = Canary::new(
        "BLOCKED_PROMPT",
        format!("ecblk-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let blocked = format!("BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt was not blocked"}]});
    let run = a.run(&script, &blocked, &flags(Host::ClaudeCode), &a.home_dir());
    let hits = Sweep::host_stores(&a, std::slice::from_ref(&control), &[&run.model]);
    print!(
        "measurement: blocked prompt hits host=claude-code os={}:\n{hits}",
        os()
    );
    measure(
        &a,
        "blocked prompt: exit code",
        format!("{:?}", run.output.status.code()),
    );
    measure(
        &a,
        "blocked prompt: model requests",
        run.model.model_calls().len(),
    );
    measure(
        &a,
        "blocked prompt: in history.jsonl",
        hits.in_store("claude/history.jsonl", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in transcripts",
        hits.in_store("claude/projects", &control.label),
    );
    // The positive control: a prompt the same hook lets through, with a
    // canary of its own, in the same home.
    let passed = Canary::new(
        "PASSED_PROMPT",
        format!("ecok-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let script = json!({"steps": [{"say": "the prompt went through"}]});
    let ok = a.run(
        &script,
        &format!("Echo {}", passed.as_str()),
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(ok.output.status.code(), Some(0), "{}", ok.text());
    let both = [control.clone(), passed.clone()];
    let hits = Sweep::host_stores(&a, &both, &[&run.model, &ok.model]);
    measure(
        &a,
        "a prompt the hook lets through: kept in",
        stores_holding(&hits, &passed.label),
    );
    // docs/AGENTS.md (Codex review, medium: only printed): exit 0, never
    // sent to the model, kept in the transcript; and not in
    // history.jsonl, which `-p` does not write at all (the prompt let
    // through is not there either: that absence says nothing about the
    // hook). By a sweep that read everything, and that finds the prompt
    // let through in the model's requests and the transcript.
    assert_eq!(hits.unreadable(), 0, "{hits}");
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert_eq!(
        hits.in_model(&control.label),
        0,
        "a blocked prompt reached the model"
    );
    assert!(
        run.model.model_calls().is_empty(),
        "the model was called for a blocked prompt"
    );
    assert!(hits.in_model(&passed.label) > 0, "{hits}");
    assert!(
        hits.in_store("claude/projects", &passed.label) > 0,
        "the prompt let through is not in the transcript:\n{hits}"
    );
    for label in [&passed.label, &control.label] {
        assert_eq!(
            hits.in_store("claude/history.jsonl", label),
            0,
            "{label} is in history.jsonl, which -p was measured not to write:\n{hits}"
        );
    }
    assert!(
        hits.in_store("claude/projects", &control.label) > 0,
        "a blocked prompt is no longer kept in the transcript (K-14):\n{hits}"
    );
}

/// Codex's hooks under `exec`: whether they run untrusted, the real
/// payloads (fixtures for M2-08), a blocked prompt's persistence and
/// whether it reaches the model, and what a hook that outlives its
/// `timeout` does (Map C §8 item 3).
#[test]
fn codex_hooks_trust_blocked_prompt_and_timeout() {
    let Some(mut a) = host(Host::Codex, "native", "codex_hooks") else {
        return;
    };
    let dir = a.root().join("hook-payloads");
    let hook = hook_command(&dir);
    let hooks = |timeout: u64| {
        format!(
            "[[hooks.UserPromptSubmit]]\nhooks = [{{ type = \"command\", command = {}, timeout = {timeout} }}]\n\
             [[hooks.PreToolUse]]\nhooks = [{{ type = \"command\", command = {}, timeout = {timeout} }}]\n",
            json!(format!("{} UserPromptSubmit", hook.display())),
            json!(format!("{} PreToolUse", hook.display())),
        )
    };
    a.codex_config(&hooks(30));
    let script = json!({"steps": [{"shell": "echo hook-check"}, {"say": "done"}]});
    // Untrusted, as a fresh install leaves them.
    let run = a.run(
        &script,
        "List the files here.",
        &flags(Host::Codex),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let untrusted_ran = !payloads(&dir, "UserPromptSubmit").is_empty();
    measure(&a, "hooks run without trust (no bypass)", untrusted_ran);
    // docs/AGENTS.md: untrusted hooks do not run (`hooks_untrusted`); the
    // trusted run below, whose payloads are asserted, is the control.
    assert!(!untrusted_ran, "Codex ran hooks it was never told to trust");
    // Trust bypassed, in this probe home only (D-13).
    let trusted = flags(Host::Codex).with(&["--dangerously-bypass-hook-trust"]);
    let run = a.run(&script, "List the files here.", &trusted, &a.home_dir());
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    for event in ["UserPromptSubmit", "PreToolUse"] {
        let got = payloads(&dir, event);
        assert!(!got.is_empty(), "no {event} payload");
        payload_fixture(&a, event, &normalized(&got[got.len() - 1], &a.home_dir()));
    }

    let control = Canary::new(
        "BLOCKED_PROMPT",
        format!("ecblk-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let blocked = format!("BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt was not blocked"}]});
    let run = a.run(&script, &blocked, &trusted, &a.home_dir());
    let hits = Sweep::host_stores(&a, std::slice::from_ref(&control), &[&run.model]);
    print!(
        "measurement: blocked prompt hits host=codex os={}:\n{hits}",
        os()
    );
    measure(
        &a,
        "blocked prompt: exit code",
        format!("{:?}", run.output.status.code()),
    );
    measure(
        &a,
        "blocked prompt: model requests",
        run.model.model_calls().len(),
    );
    measure(
        &a,
        "blocked prompt: in history.jsonl",
        hits.in_store("codex/history.jsonl", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in sessions",
        hits.in_store("codex/sessions", &control.label),
    );
    measure(
        &a,
        "blocked prompt: in SQLite stores",
        hits.in_store("codex/sqlite", &control.label),
    );
    // The positive control: a prompt the same trusted hook lets through,
    // with a canary of its own.
    let passed = Canary::new(
        "PASSED_PROMPT",
        format!("ecok-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let ok_script = json!({"steps": [{"say": "the prompt went through"}]});
    let ok = a.run(
        &ok_script,
        &format!("Echo {}", passed.as_str()),
        &trusted,
        &a.home_dir(),
    );
    assert_eq!(ok.output.status.code(), Some(0), "{}", ok.text());
    let both = [control.clone(), passed.clone()];
    let hits = Sweep::host_stores(&a, &both, &[&run.model, &ok.model]);
    measure(
        &a,
        "a prompt the hook lets through: kept in",
        stores_holding(&hits, &passed.label),
    );
    // docs/AGENTS.md (Codex review, medium: only printed): exit 0, never
    // sent to the model, in no store; by a sweep that read everything and
    // finds the prompt let through in the model's requests and the
    // session transcript (`exec` writes no history.jsonl for either).
    assert_eq!(hits.unreadable(), 0, "{hits}");
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    assert_eq!(
        hits.in_model(&control.label),
        0,
        "a blocked prompt reached the model"
    );
    assert!(
        run.model.model_calls().is_empty(),
        "the model was called for a blocked prompt"
    );
    assert!(hits.in_model(&passed.label) > 0, "{hits}");
    assert!(
        hits.in_store("codex/sessions", &passed.label) > 0,
        "the prompt let through is not in codex/sessions:\n{hits}"
    );
    assert_eq!(
        hits.stores
            .iter()
            .map(|s| hits.in_store(&s.store, &control.label))
            .sum::<usize>(),
        0,
        "a blocked prompt was kept:\n{hits}"
    );

    // A hook slower than its timeout: does the prompt go on (fail open)?
    a.codex_config(&hooks(2));
    let slow = format!("SLOW-HOOK BLOCK-ME-NOW {}", control.as_str());
    let script = json!({"steps": [{"say": "the prompt went on"}]});
    let before = payloads(&dir, "UserPromptSubmit").len();
    let run = a.run(&script, &slow, &trusted, &a.home_dir());
    measure(
        &a,
        "hook past its 2 s timeout, prompt it would block",
        format!(
            "{} (exit {:?}, {:.1} s)",
            if run.model.model_calls().is_empty() {
                "blocked"
            } else {
                "went on (fails open)"
            },
            run.output.status.code(),
            run.elapsed.as_secs_f32()
        ),
    );
    // docs/AGENTS.md: the prompt goes on (`fails_open_on_timeout`); the
    // same hook within its timeout blocked it above.
    assert!(
        !run.model.model_calls().is_empty(),
        "a hook past its timeout blocked the prompt: Codex no longer fails open"
    );
    // And it went on because the hook ran past its timeout, not because
    // the hook let it through or never ran (verifier, low: a hook that
    // exited at once passed): this prompt's own payload is new in the
    // hook's directory, and the run took at least the 2 s timeout and
    // ended well before the hook's 10 s sleep would have.
    let fresh = payloads(&dir, "UserPromptSubmit");
    assert!(
        fresh[before.min(fresh.len())..]
            .iter()
            .any(|p| p.to_string().contains("SLOW-HOOK")),
        "the hook never got the slow prompt"
    );
    assert!(
        run.elapsed >= std::time::Duration::from_secs(2),
        "the run took {:?}, less than the hook's timeout: the hook did not run past it",
        run.elapsed
    );
    assert!(
        run.elapsed < std::time::Duration::from_secs(8),
        "the run took {:?}: Codex waited for the hook beyond its timeout",
        run.elapsed
    );
}

/// Whether Claude Code expands an `@` mention under `-p` (M2-09's `@.env`
/// probe depends on it).
#[test]
fn claude_code_at_mentions_under_print() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_at_mentions") else {
        return;
    };
    let marker = format!("ecreadme-{:016x}", fresh_seed());
    std::fs::write(a.home_dir().join("README.md"), format!("{marker}\n")).unwrap();
    let script = json!({"steps": [{"say": "done"}]});
    let run = a.run(
        &script,
        "Summarize @README.md",
        &flags(Host::ClaudeCode),
        &a.home_dir(),
    );
    assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
    let first = after_call(&run, "step 0");
    measure(&a, "@ mention expanded under -p", first.contains(&marker));
    // docs/AGENTS.md: expanded, so M2-09's `@.env` probe runs under -p.
    assert!(
        first.contains(&marker),
        "@README.md was not expanded under -p"
    );
}

/// `envcloakd --foreground` in `a`'s home, by absolute path.
fn daemon_in(a: &AgentHome) -> envcloak_testkit::Daemon {
    let home = a.test_home().unwrap();
    let mut cmd = std::process::Command::new(bin_dir().join("envcloakd"));
    home.apply(&mut cmd);
    envcloak_testkit::Daemon::start_command(cmd, &[])
}

/// What `envcloak status` printed inside the host's shell tool, and the
/// uid the command ran as there, with keys built at run time so the
/// command's text never matches.
fn status_probe() -> String {
    format!(
        "printf '%s%s%s%s' 'UI' 'D[' \"$(id -u)\" ']'; \
         printf '%s%s' 'REA' 'CH['; {} status 2>&1 | tr '\\n' ' ' | cut -c1-600; printf '%s%s' ']' 'END'",
        envcloak_e2e::quoted(bin_dir().join("envcloak").to_str().unwrap())
    )
}

/// The text of the last tool result in a request body (Anthropic
/// Messages or OpenAI Responses), on one line.
fn last_tool_output(body: &str) -> String {
    last_tool_text(body)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The text of the last tool result in a request body, as the host sent
/// it (parts joined by line breaks).
fn last_tool_text(body: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let mut out = String::new();
    // A string, a list of text parts, or anything else whole, as JSON.
    let text = |c: &serde_json::Value| match c {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    for m in v["messages"].as_array().into_iter().flatten() {
        for c in m["content"].as_array().into_iter().flatten() {
            if c["type"] == "tool_result" {
                out = text(&c["content"]);
            }
        }
    }
    for item in v["input"].as_array().into_iter().flatten() {
        if item["type"] == "function_call_output" {
            out = text(&item["output"]);
        }
    }
    out
}

/// Whether the status probe reached the daemon, and if not, why: the
/// failure token and its fixed message, the uid inside the sandbox and
/// the test's own; when the probe printed nothing, the start of what the
/// command printed instead.
fn reach(text: &str) -> String {
    let inside: String = text
        .rfind("UID[")
        .map(|i| {
            text[i + 4..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect()
        })
        .unwrap_or_else(|| "?".to_owned());
    let Some(start) = text.rfind("REACH[").map(|i| i + 6) else {
        let said: String = last_tool_output(text).chars().take(300).collect();
        return format!("no output (the command did not run: {said:?})");
    };
    let end = text[start..]
        .find("]END")
        .map(|i| start + i)
        .unwrap_or(start);
    let line = &text[start..end];
    if line.starts_with("daemon: running") {
        "reaches the daemon".to_owned()
    } else if line.is_empty() {
        "no output".to_owned()
    } else {
        // `daemon: not running` or `not verified`, and the failure token
        // with its fixed message.
        let first = line.split("cli hardening").next().unwrap_or(line).trim();
        let why: String = line
            .split("envcloak: ")
            .nth(1)
            // `cut` ends the line, which the request body escapes.
            .map_or("?", |r| r.trim().trim_end_matches("\\n").trim_end())
            .chars()
            .take(200)
            .collect();
        format!(
            "does not ({first}; {why}; uid {inside} inside, {} outside)",
            own_uid()
        )
    }
}

/// The test's own uid, from `id -u`.
fn own_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|_| "?".to_owned())
}

/// Whether `envcloak status` reaches the daemon from Claude Code's Bash
/// sandbox (K-01): off; on with no socket allowance; on with
/// `allowUnixSockets` naming EnvCloak's socket (macOS) or
/// `allowAllUnixSockets` (Linux). `failIfUnavailable` makes a sandbox
/// that cannot start (Linux without bubblewrap) show as such.
#[test]
fn claude_code_sandbox_reaches_the_socket() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_sandbox") else {
        return;
    };
    let _daemon = daemon_in(&a);
    let socket = envcloak_testkit::daemon_socket(a.test_home().unwrap());
    let base = json!({"enabled": true, "failIfUnavailable": true,
                      "autoAllowBashIfSandboxed": true, "allowUnsandboxedCommands": false});
    // macOS resolves /tmp to /private/tmp before the sandbox compares a
    // path: the socket as the daemon names it, and resolved.
    let resolved = std::fs::canonicalize(&socket).unwrap();
    let mut given = base.clone();
    given["network"] = json!({"allowUnixSockets": [socket.to_str().unwrap()]});
    let mut allowed = base.clone();
    if cfg!(target_os = "macos") {
        allowed["network"] = json!({"allowUnixSockets": [resolved.to_str().unwrap()]});
    } else {
        allowed["network"] = json!({"allowAllUnixSockets": true});
    }
    let script = json!({"steps": [{"shell": status_probe()}, {"say": "done"}]});
    let mut cases = vec![
        ("sandbox off", Shell::ClaudeUnsandboxed, None),
        (
            "sandbox on, no socket allowance",
            Shell::ClaudeSandboxNoAllowance,
            Some(base),
        ),
    ];
    if cfg!(target_os = "macos") {
        cases.push((
            "sandbox on, allowUnixSockets [the socket's path as given]",
            Shell::ClaudeSandboxAllowGiven,
            Some(given),
        ));
        cases.push((
            "sandbox on, allowUnixSockets [the socket's resolved path]",
            Shell::ClaudeSandboxAllowResolved,
            Some(allowed),
        ));
    } else {
        cases.push((
            "sandbox on, allowAllUnixSockets",
            Shell::ClaudeSandboxAllowAll,
            Some(allowed),
        ));
    }
    for (name, shell, sandbox) in cases {
        let settings = match sandbox {
            Some(s) => json!({"sandbox": s}),
            None => json!({}),
        };
        std::fs::create_dir_all(a.home_dir().join(".claude")).unwrap();
        std::fs::write(
            a.home_dir().join(".claude/settings.json"),
            settings.to_string(),
        )
        .unwrap();
        let run = a.run(
            &script,
            "Check the daemon.",
            &flags(Host::ClaudeCode),
            &a.home_dir(),
        );
        let result = if run.output.status.code() == Some(0) {
            reach(&after_call(&run, "step 1"))
        } else {
            format!("the host did not run (exit {:?})", run.output.status.code())
        };
        measure(
            &a,
            &format!("envcloak status, {name}{}", namespace()),
            &result,
        );
        assert_reach(shell, &result);
    }
}

/// Checks a status probe's result ([`reach`]) against K-01's table
/// (`envcloak_e2e::k01`, which docs/AGENTS.md records): the measurement
/// is asserted, not only printed (Codex review, medium).
fn assert_reach(shell: Shell, result: &str) {
    let want = k01::expected(shell, os(), k01::user_namespace())
        .unwrap_or_else(|| panic!("{shell:?} is not a setting on {}", os()));
    let ok = match want {
        Reach::Reaches => result == "reaches the daemon",
        Reach::Refused(why) => result.starts_with("does not (") && result.contains(why),
        Reach::NotRun(why) => result.contains("the command did not run") && result.contains(why),
    };
    assert!(
        ok,
        "{shell:?}{}: measured {result:?}, K-01's table says {}",
        namespace(),
        want.receipt(os())
    );
}

/// What a sandboxed command tries besides EnvCloak's socket, as a Python
/// program (keys built at run time, so the command's text never matches
/// them). `raw`: a loopback TCP listener, another Unix socket and a raw
/// connection to a non-loopback address (TEST-NET-1, which nothing
/// answers: a sandbox that let it out shows `timeout`). `https` and
/// `http`: a request through whatever proxy the command's environment
/// names (Codex's own, under its network proxy), each in a command of its
/// own, since Codex fails a whole command whose request its proxy blocks.
/// Each prints `<KEY>OK` or `<KEY>NO <why>`, one word; `PXY` lists the
/// command's proxy variables with the host and port each names.
const EGRESS: &str = r#"import errno, os, re, socket, sys, urllib.error, urllib.request
mode, port, other = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def say(key, verdict, why=""):
    print(key + "%s" % verdict, re.sub(r"[^A-Za-z0-9._-]", "_", str(why))[:80])
def raw(key, family, addr):
    # A socket the sandbox will not even let be made counts as refused.
    s = None
    try:
        s = socket.socket(family)
        s.settimeout(5)
        s.connect(addr)
        say(key, "OK")
    except socket.timeout:
        say(key, "NO", "timeout")
    except OSError as e:
        say(key, "NO", errno.errorcode.get(e.errno, e.errno))
    finally:
        if s is not None:
            s.close()
if mode == "raw":
    raw("TCP", socket.AF_INET, ("127.0.0.1", port))
    raw("UNIX", socket.AF_UNIX, other)
    raw("EXT", socket.AF_INET, ("192.0.2.1", 443))
    proxies = sorted("%s=%s" % (k, re.sub(r"^[a-z0-9]+://", "", v)) for k, v in os.environ.items() if "proxy" in k.lower())
    print("PXY", re.sub(r"[^A-Za-z0-9._:=,-]", "_", ",".join(proxies) or "none")[:400])
for key, url in (("PRXS", "https://example.com/"), ("PRXH", "http://example.com/")):
    if mode != url.split(":")[0]:
        continue
    try:
        # Within the 10 s Codex waits before it returns a command's
        # output so far.
        r = urllib.request.urlopen(url, timeout=5)
        say(key, "OK", r.status)
    except urllib.error.HTTPError as e:
        say(key, "NO", "http-%d" % e.code)
    except Exception as e:
        t = re.search(r"Tunnel connection failed: (\d+)", str(e))
        say(key, "NO", "tunnel-" + t.group(1) if t else type(getattr(e, "reason", e)).__name__ + "-" + str(getattr(e, "reason", e))[:60])
"#;

/// Whether `envcloak status` reaches the daemon from Codex's sandbox
/// (K-01) in `read-only` (the `exec` default) and `workspace-write`, each
/// with no network setting and with the bounded setting (network access,
/// the network proxy on, no domain rule and one `unix_sockets` allow rule
/// for EnvCloak's socket), and `workspace-write` with network access
/// alone; and what else a command can reach there ([`EGRESS`]). Under the
/// bounded setting in `workspace-write` (what M2-08 would write) nothing
/// else may be reachable: on macOS a raw connection anywhere is refused by
/// the sandbox itself (`EPERM`), and on both systems both proxied
/// requests are refused by Codex itself (its proxy's "Network access to
/// ... was blocked", naming its rule, a 403 from it, or `EPERM` for the
/// socket), never by a network that is not there, and never reach the
/// scripted model's proxy.
#[test]
fn codex_sandbox_reaches_the_socket_and_nothing_else() {
    let Some(mut a) = host(Host::Codex, "native", "codex_sandbox") else {
        return;
    };
    let _daemon = daemon_in(&a);
    let socket = envcloak_testkit::daemon_socket(a.test_home().unwrap());
    // Something else to reach: a loopback TCP listener and a Unix socket.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let other = a.root().join("other.sock");
    let _unix = std::os::unix::net::UnixListener::bind(&other).unwrap();
    let probe = a.root().join("egress.py");
    std::fs::write(&probe, EGRESS).unwrap();
    let egress = |mode: &str| {
        format!(
            "python3 {} {mode} {port} {}",
            envcloak_e2e::quoted(probe.to_str().unwrap()),
            envcloak_e2e::quoted(other.to_str().unwrap())
        )
    };
    let bounded = format!(
        "[sandbox_workspace_write]\nnetwork_access = true\n\
         [features.network_proxy]\nenabled = true\n\
         [features.network_proxy.unix_sockets]\n{} = \"allow\"\n",
        json!(socket.to_str().unwrap())
    );
    for (name, shell, sandbox, config) in [
        (
            "read-only",
            Shell::CodexReadOnly,
            "read-only",
            String::new(),
        ),
        (
            "read-only, network_access, proxy with one unix_sockets rule",
            Shell::CodexReadOnlyBounded,
            "read-only",
            bounded.clone(),
        ),
        (
            "workspace-write",
            Shell::CodexWorkspaceWrite,
            "workspace-write",
            String::new(),
        ),
        (
            "workspace-write, network_access",
            Shell::CodexWorkspaceWriteNetwork,
            "workspace-write",
            "[sandbox_workspace_write]\nnetwork_access = true\n".to_owned(),
        ),
        (
            "workspace-write, network_access, proxy with one unix_sockets rule",
            Shell::CodexWorkspaceWriteBounded,
            "workspace-write",
            bounded.clone(),
        ),
    ] {
        a.codex_config(&config);
        let script = json!({"steps": [
            {"shell": format!("{}; {}", status_probe(), egress("raw"))},
            // With the probe's exit status, as `RC<n>`, built at run time.
            {"shell": format!("{}; printf '%s%s\\n' 'R' \"C$?\"", egress("https"))},
            {"shell": format!("{}; printf '%s%s\\n' 'R' \"C$?\"", egress("http"))},
            {"say": "done"},
        ]});
        let run = a.run(
            &script,
            "Check the daemon.",
            &HostFlags::codex(sandbox, "never"),
            &a.home_dir(),
        );
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        let text = after_call(&run, "step 1");
        let label = format!("{name}{}", namespace());
        let reached = reach(&text);
        measure(&a, &format!("envcloak status, {label}"), &reached);
        assert_reach(shell, &reached);
        // Each proxied request's result is in the next turn's request.
        let proxied = [
            ("PRXS", after_call(&run, "step 2")),
            ("PRXH", after_call(&run, "step 3")),
        ];
        let seen = |key: &str| {
            // The raw probe's keys are in the request after its command;
            // each proxied one's in the request after its own, read from
            // that command's tool result.
            let (body, out) = match proxied.iter().find(|(k, _)| *k == key) {
                Some((_, body)) => (body.as_str(), last_tool_output(body)),
                None => (text.as_str(), text.clone()),
            };
            if let Some(e) = printed(&out, &format!("{key}OK ")) {
                format!("reached ({e})")
            } else if let Some(e) = printed(&out, &format!("{key}NO ")) {
                format!("refused ({e})")
            } else if let Some(why) = out
                .split_once("was blocked: ")
                .filter(|(before, _)| before.contains("Network access to"))
                .map(|(_, why)| why)
            {
                // Codex failed the whole command: its proxy blocked the
                // request, and says by which rule (macOS: the domain is
                // not on the allowlist; Linux CI, whose namespaces resolve
                // no name: local or private addresses).
                let why: String = why
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '/'))
                    .collect();
                format!("refused (codex-proxy: {})", why.trim())
            } else {
                // What the command's tool result said instead (Python's own
                // error, or the host's words), and the types of the last
                // items the request ends with, for the record: no value.
                let said: String = out
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(300)
                    .collect();
                let types = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["input"].as_array().cloned())
                    .map(|items| {
                        items
                            .iter()
                            .rev()
                            .take(4)
                            .map(|i| i["type"].as_str().unwrap_or("?").to_owned())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let rc = printed(&out, "RC").unwrap_or_else(|| "?".to_owned());
                format!("not tried (tool result {said:?}; exit {rc}; last items {types})")
            }
        };
        let proxies = printed(&text, "PXY ").unwrap_or_else(|| "?".to_owned());
        measure(
            &a,
            &format!("other egress, {label}"),
            format!(
                "loopback TCP {}, another Unix socket {}, a non-loopback address {}, \
                 HTTPS through the command's proxy {}, HTTP {}; the command's proxy \
                 variables {proxies}, the scripted model at {}",
                seen("TCP"),
                seen("UNIX"),
                seen("EXT"),
                seen("PRXS"),
                seen("PRXH"),
                run.model_url.trim_start_matches("http://")
            ),
        );
        if sandbox == "workspace-write" && name.contains("unix_sockets") {
            for key in ["TCP", "UNIX", "EXT", "PRXS", "PRXH"] {
                assert!(
                    seen(key).starts_with("refused"),
                    "the bounded setting lets a command reach {key}: {}",
                    seen(key)
                );
            }
            if cfg!(target_os = "macos") {
                assert!(
                    matches!(seen("EXT").as_str(), "refused (EPERM)" | "refused (EACCES)"),
                    "a non-loopback connection was not refused by the sandbox: {}",
                    seen("EXT")
                );
            }
            // Refused by Codex itself: its proxy, by its rules (no domain
            // is allowed), or its sandbox, which will not let the socket
            // be made (EPERM); never by a network that is missing (CI's
            // Linux namespace has none, so ECONNREFUSED, ENETUNREACH or a
            // timeout prove nothing there).
            for key in ["PRXS", "PRXH"] {
                let got = seen(key);
                assert!(
                    matches!(got.as_str(), "refused (tunnel-403)" | "refused (http-403)")
                        || got.starts_with("refused (codex-proxy: ")
                        || got.starts_with("refused (PermissionError"),
                    "{key} was not refused by Codex: {got}"
                );
            }
            // Every request that reached the scripted model was read: a
            // proxy request in any form is recorded (an HTTP/1.0 tunnel, a
            // request to forward), so the check below can fail.
            assert_eq!(
                run.model.outcome["malformed"].as_u64(),
                Some(0),
                "{:?}",
                run.model.outcome
            );
            assert!(
                !run.model
                    .connects()
                    .iter()
                    .any(|c| c.starts_with("example.com")),
                "a sandboxed command reached the scripted model's proxy"
            );
        }
    }
}

/// Drives a program on a pseudo-terminal of its own (40 rows, 120
/// columns), as a person in a terminal window. argv[1] is a JSON spec:
/// `argv`, `env`, `cwd`, `limit` and `steps`, each one of
/// - `["wait", text, n]`: until the screen has shown `text` `n` times;
/// - `["wait_raw", bytes, n]`: until the program has written `bytes` `n`
///   times;
/// - `["idle", ms]`: until it has written nothing for `ms` milliseconds;
/// - `["send", text]`: types `text`.
///
/// It answers the queries a terminal answers. Its last line is the
/// outcome: `EXIT <n>`, the program's exit code (or 128 plus its signal);
/// `TIMEOUT <step>` when a wait runs out; `STILL RUNNING` when the program
/// has not exited `limit` seconds after the last step; `GONE <step>: `
/// and one of those when the program's terminal had closed by the time a
/// `send` step typed into it. The screen is never printed: it can hold
/// what was pasted. On a timeout it is written to `screen`, for
/// diagnosis, once the program has been ended; a write that fails is
/// noted on standard error and changes nothing else.
///
/// The program leads a session and a process group of its own, outside
/// the driver's, so the harness's group kill does not reach it: the
/// driver ends that group itself, with one cleanup set up as soon as the
/// program is forked and run on every way out of the driver (the outcomes
/// above, a signal to the driver that would end it, such as the harness's
/// limit (`SIGTERM`) or a hangup, and any error, such as a write to a
/// terminal the program has closed). It kills
/// the group while the program that leads it is still unreaped, so the
/// group's id cannot have been reused, and then reaps the program (D-34);
/// what the program left running in its group (a process that ignores the
/// hangup when the terminal closes) goes with it. The driver forks the
/// program itself (a pseudo-terminal, then `fork`; the child makes its
/// session, takes the terminal and starts the program) and waits, before
/// anything else, until the child has made its session and started the
/// program (a close-on-exec pipe the child holds until then ends): until
/// it has, the group does not exist, and a kill of it would reach nothing
/// (Codex review of M2-04, medium: the driver could return from the fork,
/// take a signal and find no group, then wait for the program without
/// end). A signal that comes during that wait, or any time the group
/// cannot be signalled, ends the program directly, by its pid, which is
/// the driver's unreaped child; the program is then reaped within 10
/// seconds, never waited for without a bound. A `hold` path in the spec
/// (tests only) makes the child open it for writing, write `x` there and
/// wait before it makes its session. The program's exit is
/// seen without reaping it, with `waitid(WNOWAIT)`, or a kqueue exit note
/// where Python has no `waitid` (macOS before 3.13). Every signal whose
/// default action ends a process (`SIGTERM`, the harness's, and `SIGHUP`,
/// `SIGINT`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2`, `SIGALRM` and the rest)
/// stays blocked in the driver and is read between waits (every 0.2 s at
/// most), so none interrupts the cleanup or skips it; the driver then
/// exits 1. The program gets the signal mask the driver started with.
/// Only `SIGKILL`, or a signal a fault raises (`SIGSEGV`, `SIGBUS`,
/// `SIGFPE`, `SIGILL`, `SIGTRAP`, `SIGSYS`, `SIGABRT`, and `SIGEMT` where
/// there is one), to the driver itself skips the cleanup (verifier, low:
/// only `SIGTERM` was blocked, and a `SIGHUP` left the program's group
/// running).
const PTY_DRIVER: &str = r#"import fcntl, json, os, re, select, signal, struct, sys, termios, time
def named(*names):
    return {getattr(signal, n) for n in names if hasattr(signal, n)}
# Signals that do not end a process, and those a fault raises.
KEEP = named("SIGKILL", "SIGSTOP", "SIGCHLD", "SIGCONT", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG",
             "SIGWINCH", "SIGINFO", "SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGTRAP", "SIGSYS",
             "SIGABRT", "SIGEMT")
ENDS = set(signal.valid_signals()) - KEEP
assert named("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT", "SIGUSR1", "SIGALRM") <= ENDS
MASK = signal.pthread_sigmask(signal.SIG_BLOCK, ENDS)
spec = json.load(open(sys.argv[1]))
fd, tty = os.openpty()
# Held by the child until it starts the program (close-on-exec), after it
# made its session; `hold` (tests only) keeps it waiting before that.
ready_r, ready_w = os.pipe()
hold_r, hold_w = os.pipe()
pid = os.fork()
if pid == 0:
    try:
        os.close(fd)
        os.close(ready_r)
        os.close(hold_w)
        if spec.get("hold"):
            h = os.open(spec["hold"], os.O_WRONLY)
            os.write(h, b"x")
            os.read(hold_r, 1)
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
os.close(hold_r)
status = []
def finish():
    # The one cleanup, run once. Once the program leads its group (it made
    # its session) and while it is unreaped (until here), the group's id
    # is its own: the group is killed, then the program reaped. Until it
    # has made its session there is no such group: the program, the
    # driver's unreaped child, is killed directly then. It is reaped
    # within 10 s, or reported. Its exit code, or 128 plus its signal.
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
                print("the program was not reaped within 10 s", file=sys.stderr)
                status.append(255)
                break
            time.sleep(0.02)
    return status[0]
class Ended(Exception):
    pass
def started():
    # Until the child has made its session and started the program (or
    # failed to): the end of the pipe it held. A signal that would end the
    # driver ends the wait.
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
    # Whether the program has exited, seen without reaping it.
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
        # What the program writes until `until`, 0.2 s at most, so a
        # signal that would end the driver is seen soon; once its terminal
        # has closed, a pause.
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
        # Answer the queries a terminal answers: the version (XTVERSION),
        # the keyboard protocol, the device attributes, the cursor position.
        for q, a in ((b"\x1b[>0q", b"\x1bP>|xterm(388)\x1b\\"), (b"\x1b[?u", b"\x1b[?0u"),
                     (b"\x1b[c", b"\x1b[?1;2c"), (b"\x1b[6n", b"\x1b[1;1R")):
            for _ in range(c.count(q)):
                try:
                    os.write(fd, a)
                except OSError:
                    alive[0] = False
    def screen():
        # What a person reads: escape sequences (cursor moves stand in for
        # spaces) as spaces, runs of white space as one.
        t = re.sub(rb"\x1b\[[0-9;?<>=]*[ -/]*[@-~]", b" ", shown[0])
        t = re.sub(rb"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", b" ", t)
        return re.sub(rb"\s+", b" ", t)
    def ending():
        # The program's exit within the limit, or it is still running (and
        # then ended with its group).
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
                # Its terminal has closed: the program is gone, or going.
                return "GONE %d: %s" % (i, ending())
            continue
        if step[0] == "idle":
            # Until the program has written nothing for step[1] ms.
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
                if spec.get("screen"):
                    try:
                        with open(spec["screen"], "wb") as f:
                            f.write(screen())
                    except OSError as e:
                        print("the screen was not written: %s" % e.strerror, file=sys.stderr)
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

/// Claude Code 2.1.280 draws the trust dialog before it takes keys, and
/// shows nothing when it starts to: keys sent at once go to a dialog that
/// is then replaced, and an Enter reads as "No, exit". The screen staying
/// unchanged for this long is when the dialog has been seen to take them.
const SETTLED_MS: u64 = 3000;

/// Runs Claude Code interactively in `a`'s home against `model`, with
/// `args` (its flags, pinned per run), driven by `steps`; the driver's
/// last line.
fn interactive_claude(
    a: &AgentHome,
    model: &envcloak_testkit::agents::Model,
    cwd: &Path,
    args: &[&str],
    limit: u64,
    steps: serde_json::Value,
) -> String {
    let env: Vec<(String, String)> = a
        .env_for(model, cwd)
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
    let mut argv = vec![a.installed.exe.to_str().unwrap()];
    argv.extend_from_slice(args);
    let spec = json!({
        "argv": argv,
        "env": env,
        "cwd": cwd.to_str().unwrap(),
        "limit": limit,
        // What the screen showed when a wait ran out, for diagnosis: a
        // file in the test's root, outside HOME, swept with the home.
        "screen": a.root().join("pty-screen.txt").to_str().unwrap(),
        "steps": steps,
    });
    let spec_path = a.root().join("pty-spec.json");
    std::fs::write(&spec_path, spec.to_string()).unwrap();
    let mut cmd = std::process::Command::new(envcloak_e2e::python3());
    cmd.arg("-c")
        .arg(PTY_DRIVER)
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = envcloak_testkit::agents::finish_within(cmd, std::time::Duration::from_secs(600));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .to_owned()
}

/// What the pseudo-terminal driver returned for a program, once nothing
/// the program started is left: the program is `/bin/sh` running
/// `body`, with descriptor 3 open on a FIFO the test reads, which reads to
/// its end only when every process holding it has gone. Each body leaves
/// a process that ignores the hangup the closing terminal sends and holds
/// the FIFO for 90 s. `None` when the harness had to stop the driver at
/// `harness_limit` (a SIGTERM to its group, then SIGKILL 2 s later).
///
/// # Panics
/// When something still holds the FIFO 10 s after the driver returned.
fn pty_driver_leaves_nothing(
    body: &str,
    steps: serde_json::Value,
    limit: u64,
    screen: Option<&str>,
    harness_limit: std::time::Duration,
) -> Option<std::process::Output> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let home = envcloak_testkit::TestHome::new();
    let fifo = home.root().join("held");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let program = home.root().join("program.sh");
    std::fs::write(
        &program,
        format!(
            "exec 3>{}\nprintf x >&3\n{body}",
            envcloak_e2e::quoted(fifo.to_str().unwrap())
        ),
    )
    .unwrap();
    let mut spec = json!({
        "argv": ["/bin/sh", program.to_str().unwrap()],
        "env": [["PATH", "/usr/bin:/bin"]],
        "cwd": home.root().to_str().unwrap(),
        "limit": limit,
        "steps": steps,
    });
    if let Some(name) = screen {
        spec["screen"] = json!(home.root().join(name).to_str().unwrap());
    }
    let spec_path = home.root().join("pty-spec.json");
    std::fs::write(&spec_path, spec.to_string()).unwrap();
    let mut cmd = std::process::Command::new(envcloak_e2e::python3());
    cmd.arg("-c")
        .arg(PTY_DRIVER)
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        envcloak_testkit::agents::finish_within(cmd, harness_limit)
    }))
    .ok();
    let mut got = Vec::new();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut chunk = [0u8; 16];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < end,
                    "a process the program started still holds the FIFO after the driver \
                     returned ({:?})",
                    out.as_ref()
                        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => panic!("read the FIFO: {e}"),
        }
    }
    assert_eq!(got, b"x", "the program never started what it leaves behind");
    out
}

/// The driver's last line.
fn last_line(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .to_owned()
}

/// A program that keeps running, with a process it started that ignores
/// the hangup; `ready` once it has started it.
const RUNS_ON: &str = "(trap '' HUP; exec sleep 90) &\nprintf 'ready\\n'\nexec sleep 90\n";

/// The pseudo-terminal driver ends what its program leaves behind (Codex
/// review, medium: the program leads a session of its own, the harness's
/// group kill does not reach it, and the driver reaped it at once and
/// never killed its group). The program starts a process that ignores the
/// hangup, then exits.
#[test]
fn the_pty_driver_ends_what_its_program_leaves_running() {
    let out = pty_driver_leaves_nothing(
        "(trap '' HUP; exec sleep 90) &\nexit 0\n",
        json!([]),
        30,
        None,
        std::time::Duration::from_secs(60),
    )
    .expect("the driver did not finish");
    assert_eq!(last_line(&out), "EXIT 0");
}

/// A wait that runs out ends the program and what it started first, and
/// only then writes the screen for diagnosis: a write that fails (its
/// directory is missing) changes nothing else (review F-87: the write came
/// before the cleanup, and its error skipped it).
#[test]
fn the_pty_driver_ends_the_program_before_a_diagnostic_write_that_fails() {
    let out = pty_driver_leaves_nothing(
        RUNS_ON,
        json!([["wait", "ready", 1], ["wait", "never shown", 1]]),
        2,
        Some("missing/screen.txt"),
        std::time::Duration::from_secs(60),
    )
    .expect("the driver did not finish");
    assert_eq!(last_line(&out), "TIMEOUT 1");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("the screen was not written"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Keys typed after the program has exited (as when a host quits at its
/// trust dialog) go to a terminal that is closed. macOS reports that to
/// the write (`EIO`), and the driver says so, with the program's exit;
/// Linux (CI) takes the keys into the terminal's buffer, and the exit is
/// seen after the steps as usual. Either way the driver ends what the
/// program left running (review F-87: on macOS the error ended the driver
/// with a traceback before any cleanup). The process left behind holds
/// no terminal, so the terminal closes when the program exits.
#[test]
fn the_pty_driver_ends_what_is_left_when_a_key_is_sent_after_the_program_exited() {
    let out = pty_driver_leaves_nothing(
        "(trap '' HUP; exec sleep 90 <&- >&- 2>&-) &\nprintf 'bye\\n'\nexit 0\n",
        json!([["wait", "bye", 1], ["idle", 2000], ["send", "y\r"]]),
        30,
        None,
        std::time::Duration::from_secs(60),
    )
    .expect("the driver did not finish");
    let last = last_line(&out);
    if cfg!(target_os = "macos") {
        assert_eq!(last, "GONE 2: EXIT 0");
    } else {
        assert!(
            matches!(last.as_str(), "GONE 2: EXIT 0" | "EXIT 0"),
            "{last}"
        );
    }
}

/// Any error in the driver (here a malformed step) still ends the
/// program's group and reaps the program before the driver exits (review
/// F-87: no cleanup surrounded the driver as a whole).
#[test]
fn the_pty_driver_ends_the_program_on_an_error_of_its_own() {
    let out = pty_driver_leaves_nothing(
        RUNS_ON,
        json!([["wait", "ready", 1], ["wait"]]),
        30,
        None,
        std::time::Duration::from_secs(60),
    )
    .expect("the driver did not finish");
    assert_eq!(out.status.code(), Some(1));
    let last = last_line(&out);
    assert!(
        !last.starts_with("EXIT") && !last.starts_with("TIMEOUT"),
        "{last}"
    );
}

/// A signal that comes before the program has made its session ends it
/// all the same (Codex review of M2-04, medium: the driver could take the
/// signal while the group did not exist yet, find nothing to kill, and
/// then wait for the program without end; 9 runs in 12 missed it with the
/// child paused at its start). The child is held before its session
/// (`hold`), holding the test's FIFO; the driver, the test's own
/// unreaped child, gets `SIGTERM`, ends the child by its pid and exits 1
/// through its cleanup, and the FIFO's last writer is gone.
///
/// Mutation checked: the cleanup as it was (the group kill alone, its
/// error ignored, then a wait without a bound): the driver waits for the
/// held child for ever and this fails at its 30-second bound.
#[test]
fn the_pty_driver_ends_a_program_signalled_before_its_session_exists() {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let home = envcloak_testkit::TestHome::new();
    let fifo = home.root().join("held");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let spec = json!({
        "argv": ["/bin/sh", "-c", "exec sleep 90"],
        "env": [["PATH", "/usr/bin:/bin"]],
        "cwd": home.root().to_str().unwrap(),
        "limit": 120,
        "steps": [["wait", "never shown", 1]],
        "hold": fifo.to_str().unwrap(),
    });
    let spec_path = home.root().join("pty-spec.json");
    std::fs::write(&spec_path, spec.to_string()).unwrap();
    let mut cmd = std::process::Command::new(envcloak_e2e::python3());
    cmd.arg("-c")
        .arg(PTY_DRIVER)
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut driver = envcloak_testkit::agents::GroupChild::spawn(&mut cmd).unwrap();
    // `x` once the child is held, before its session; then the end, once
    // the child is gone.
    let mut got = Vec::new();
    let mut chunk = [0u8; 16];
    let mut read_until = |done: &dyn Fn(&[u8], bool) -> bool, what: &str| {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match reader.read(&mut chunk) {
                Ok(0) if done(&got, true) => return,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("read the FIFO: {e}"),
            }
            if done(&got, false) {
                return;
            }
            assert!(std::time::Instant::now() < end, "{what}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    };
    read_until(
        &|g, _| g == b"x",
        "the child was not held before its session",
    );
    driver.signal(libc::SIGTERM);
    let status = driver.end_within(std::time::Duration::from_secs(30));
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(1),
        "the driver did not end through its cleanup ({status:?})"
    );
    read_until(
        &|_, ended| ended,
        "the held child still holds the FIFO after the driver exited",
    );
    assert_eq!(got, b"x");
}

/// The harness's limit (a SIGTERM to the driver's group) ends the program
/// and what it started too, before the harness's SIGKILL 2 s later.
#[test]
fn the_pty_driver_ends_the_program_on_the_harness_s_limit() {
    let out = pty_driver_leaves_nothing(
        RUNS_ON,
        json!([["wait", "ready", 1], ["wait", "never shown", 1]]),
        60,
        None,
        std::time::Duration::from_secs(3),
    );
    assert!(out.is_none(), "the driver finished before its limit");
}

/// Each signal that would end the driver, not only the harness's
/// `SIGTERM`, ends the program and what it started before the driver
/// exits 1 (verifier, low: a `SIGHUP` to the driver ended it with the
/// program's group still running). The program starts a process that
/// ignores the hangup and holds the FIFO, says so on the FIFO, and waits;
/// then the driver, the test's own unreaped child, gets the signal.
#[test]
fn the_pty_driver_ends_the_program_on_any_signal_that_would_end_it() {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    for sig in [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGALRM,
        libc::SIGTERM,
    ] {
        let home = envcloak_testkit::TestHome::new();
        let fifo = home.root().join("held");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let program = home.root().join("program.sh");
        std::fs::write(
            &program,
            format!(
                "exec 3>{}\nprintf x >&3\n(trap '' HUP; printf r >&3; exec sleep 90) &\n\
                 exec sleep 90\n",
                envcloak_e2e::quoted(fifo.to_str().unwrap())
            ),
        )
        .unwrap();
        let spec = json!({
            "argv": ["/bin/sh", program.to_str().unwrap()],
            "env": [["PATH", "/usr/bin:/bin"]],
            "cwd": home.root().to_str().unwrap(),
            "limit": 120,
            "steps": [["wait", "never shown", 1]],
        });
        let spec_path = home.root().join("pty-spec.json");
        std::fs::write(&spec_path, spec.to_string()).unwrap();
        let mut cmd = std::process::Command::new(envcloak_e2e::python3());
        cmd.arg("-c")
            .arg(PTY_DRIVER)
            .arg(&spec_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut driver = envcloak_testkit::agents::GroupChild::spawn(&mut cmd).unwrap();
        // The FIFO, read until the program has started what it leaves
        // behind (`x`, then `r`; before the program opens it, a read finds
        // no writer and ends at once, which says nothing yet), then to its
        // end once the driver has gone, which it reaches only when nothing
        // holds it any more.
        let mut got = Vec::new();
        let mut read_until = |started: bool, what: &str| {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut chunk = [0u8; 16];
            loop {
                if !started && got == b"xr" {
                    return;
                }
                match reader.read(&mut chunk) {
                    Ok(0) if started => return,
                    Ok(n) => got.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("read the FIFO: {e}"),
                }
                assert!(std::time::Instant::now() < end, "signal {sig}: {what}");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        read_until(false, "the program did not start what it leaves behind");
        driver.signal(sig);
        let status = driver.end_within(std::time::Duration::from_secs(30));
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(1),
            "signal {sig}: the driver did not end through its cleanup ({status:?})"
        );
        read_until(
            true,
            "a process the program started still holds the FIFO after the driver exited",
        );
        assert_eq!(got, b"xr", "signal {sig}");
    }
}

/// One interactive Claude Code session through a pseudo-terminal (D-13,
/// review row 25): whether a prompt can be submitted before the workspace
/// trust dialog is answered, and which stores a real paste reaches
/// (`paste-cache/`, `history.jsonl`, the transcript), for a short paste
/// and a long one. The person's settings: onboarding done and the
/// harness's key approved, in `~/.claude.json`, labelled so.
#[test]
fn claude_code_interactive_trust_and_paste() {
    let Some(a) = host(Host::ClaudeCode, "native", "claude_code_interactive") else {
        return;
    };
    let project = a.root().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let script = json!({"steps": [{"say": "reply received"}], "side": "ok"});
    let approve_key = |model: &envcloak_testkit::agents::Model| {
        // Settings the person made, so the session opens at the trust
        // dialog: onboarding done, the key in ANTHROPIC_API_KEY approved.
        let token = model.api_key();
        let cfg = json!({"hasCompletedOnboarding": true, "theme": "dark",
                         "customApiKeyResponses": {"approved": [&token[token.len() - 20..]], "rejected": []}});
        std::fs::write(a.home_dir().join(".claude.json"), cfg.to_string()).unwrap();
    };

    // Before the trust dialog is answered: type a prompt and Enter.
    let before = Canary::new("BEFORE_TRUST", format!("ecpre-{:016x}", fresh_seed()));
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &[],
        30,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", format!("{}\r", before.as_str())],
        ]),
    );
    let report = model.finish();
    let early = Sweep::host_stores(&a, std::slice::from_ref(&before), &[&report]);
    let reached = early.in_model(&before.label) > 0;
    measure(
        &a,
        "interactive: prompt typed before the trust dialog is answered",
        format!(
            "{} ({end}); model requests {}; kept in {}",
            if reached {
                "reached the model"
            } else {
                "never reached the model"
            },
            report.model_calls().len(),
            stores_holding(&early, &before.label)
        ),
    );
    // As docs/AGENTS.md records for the pinned version (Codex review,
    // medium: only printed): Enter at the dialog answers its default, "No,
    // exit", and the prompt reaches neither the model nor any store. The
    // sweep is complete, and the pastes below, which do reach the model
    // and the stores, are its positive control.
    assert!(!reached, "a prompt typed before trust reached the model");
    assert!(
        report.model_calls().is_empty(),
        "the model was called before trust: {:?}",
        report.requests
    );
    assert_eq!(
        end, "EXIT 1",
        "the trust dialog did not end the session on Enter"
    );
    assert_eq!(early.unreadable(), 0, "{early}");
    assert_eq!(
        early.stores.iter().map(|s| s.hits.len()).sum::<usize>(),
        0,
        "a prompt typed before trust was kept:\n{early}"
    );

    // Trust accepted with the documented keys, then two pastes.
    let short = Canary::new(
        "PASTE_SHORT",
        format!("ecpaste-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let long_value = format!("eclong-{:016x}{:016x}", fresh_seed(), fresh_seed());
    let long = Canary::new("PASTE_LONG", long_value.clone());
    let long_text: String = (0..40)
        .map(|i| {
            if i == 20 {
                format!("{long_value}\n")
            } else {
                format!("line {i} of a long paste\n")
            }
        })
        .collect();
    // A project of its own: the first session's is left as it ended.
    let project = a.root().join("project-2");
    std::fs::create_dir_all(&project).unwrap();
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &[],
        120,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            // Down to "Yes" and Enter, in one write.
            ["send", "\u{1b}[B\r"],
            ["wait", "for shortcuts", 1],
            // A bracketed paste and Enter, as a terminal sends them.
            [
                "send",
                format!("\u{1b}[200~{}\u{1b}[201~\r", short.as_str())
            ],
            ["wait", "reply received", 1],
            ["send", format!("\u{1b}[200~{long_text}\u{1b}[201~\r")],
            ["wait", "reply received", 2],
            ["send", "/exit\r"],
        ]),
    );
    let report = model.finish();
    assert!(end.starts_with("EXIT"), "the session did not end: {end}");
    let cs = [short.clone(), long.clone()];
    let hits = Sweep::host_stores(&a, &cs, &[&report]);
    print!(
        "measurement: interactive paste hits host=claude-code os={}:\n{hits}",
        os()
    );
    for c in &cs {
        measure(
            &a,
            &format!(
                "interactive: a {} paste is kept in",
                if c.label == "PASTE_SHORT" {
                    "one-line"
                } else {
                    "40-line"
                }
            ),
            stores_holding(&hits, &c.label),
        );
    }
    // As docs/AGENTS.md records (Codex review, medium: only printed):
    // each paste reaches the model, and is kept in history.jsonl and the
    // transcript, and not in paste-cache/, by a sweep that read
    // everything; a control planted in paste-cache/ afterwards is found
    // there, so "not in paste-cache/" is the sweep's finding.
    assert_eq!(hits.unreadable(), 0, "{hits}");
    for c in &cs {
        assert!(
            hits.in_model(&c.label) > 0,
            "{} never reached the model",
            c.label
        );
        for store in ["claude/history.jsonl", "claude/projects"] {
            assert!(
                hits.in_store(store, &c.label) > 0,
                "{} is not in {store}:\n{hits}",
                c.label
            );
        }
        assert_eq!(hits.in_store("claude/paste-cache", &c.label), 0, "{hits}");
    }
    let planted = Canary::new(
        "PASTE_CACHE_CONTROL",
        format!("eccache-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let cache = a.home_dir().join(".claude/paste-cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("ec-control.txt"), planted.as_str()).unwrap();
    let control = Sweep::host_stores(&a, std::slice::from_ref(&planted), &[]);
    assert!(
        control.in_store("claude/paste-cache", &planted.label) > 0,
        "a control planted in paste-cache/ was not found there:\n{control}"
    );
    std::fs::remove_file(cache.join("ec-control.txt")).unwrap();

    // The Bash tool in an interactive session, the host on a terminal of
    // its own (the flags pinned: default permission mode, Bash allowed):
    // what a command it runs has for a terminal (TTY_PROBE).
    let project = a.root().join("project-3");
    std::fs::create_dir_all(&project).unwrap();
    let script = json!({"steps": [{"shell": TTY_PROBE}, {"say": "probe done"}], "side": "ok"});
    let model = envcloak_testkit::agents::Model::start(&script);
    approve_key(&model);
    let end = interactive_claude(
        &a,
        &model,
        &project,
        &["--permission-mode", "default", "--allowedTools", "Bash"],
        120,
        json!([
            ["wait", "trust this folder", 1],
            ["idle", SETTLED_MS],
            ["send", "\u{1b}[B\r"],
            ["wait", "for shortcuts", 1],
            ["send", "Check the terminal.\r"],
            ["wait", "probe done", 1],
            ["send", "/exit\r"],
        ]),
    );
    let report = model.finish();
    a.check_pinned();
    a.check_isolated();
    assert!(end.starts_with("EXIT"), "the session did not end: {end}");
    let after = report
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 1"))
        .map(|r| last_tool_output(&String::from_utf8_lossy(&r.body)))
        .unwrap_or_else(|| panic!("no request after the probe: {:?}", report.requests));
    let shown = tty_shown(&after).unwrap_or_else(|| panic!("the probe printed {after:?}"));
    measure(
        &a,
        "interactive: shell tool terminal, the host on a terminal (T=tty, N=not)",
        &shown,
    );
    // docs/AGENTS.md: no terminal on any stream and no controlling one,
    // though the host has one (the probe's control:
    // the_terminal_probe_reads_the_controlling_terminal_not_standard_input).
    assert!(
        shown.starts_with(NO_TERMINAL),
        "the Bash tool's command has a terminal: {shown}"
    );
}

/// [`TTY_PROBE`] in a command with no terminal on any stream and no
/// controlling terminal.
const NO_TERMINAL: &str = "stdin=N stdout=N stderr=N controlling-terminal=N";

/// The stores in `hits` holding `label`, by name, or `none`.
fn stores_holding(hits: &envcloak_testkit::transcripts::Hits, label: &str) -> String {
    let stores: Vec<&str> = hits
        .stores
        .iter()
        .filter(|s| hits.in_store(&s.store, label) > 0)
        .map(|s| s.store.as_str())
        .collect();
    if stores.is_empty() {
        "none".to_owned()
    } else {
        stores.join(", ")
    }
}

// ---------------------------------------------------------------------
// Tier 2 (M2-04's spike, Codex review: drivability was read from the
// documentation only). Each tier-2 host, with its documented base-URL
// setting pointed at the scripted model in an isolated home: which
// endpoints it calls; for the drivable ones, whether the scripted model's
// call to its shell tool starts a command, and what that command's
// ancestry is (the executable, interpreter and script layout M2-10
// classifies). Flags are pinned per host; no host runs in a bypass mode.
// ---------------------------------------------------------------------

/// What the probe command prints: a marker, then each ancestor up to four
/// levels, nearest first, as `ANC <comm> | <args, cut>`. The keys are
/// built at run time, so the command's own text never holds them whole.
const ANCESTRY_PROBE: &str = "printf '%s%s\\n' 'MARK' 'ER-ran'; p=$$; i=0; \
     while [ \"$p\" -gt 1 ] && [ $i -lt 4 ]; do \
     printf '%s %s | %s\\n' 'AN''C' \"$(ps -o comm= -p \"$p\")\" \"$(ps -o args= -p \"$p\" | cut -c1-400)\"; \
     p=$(ps -o ppid= -p \"$p\" | tr -d ' '); i=$((i+1)); done";

/// One tier-2 host run: the scripted model's report, the host's output
/// and the host as installed.
struct Tier2Run {
    report: envcloak_testkit::agents::ModelReport,
    output: std::process::Output,
}

/// Runs the tier-2 host `id`/`variant` in a fresh home against a scripted
/// model: the probe through its shell tool `shell` (the tool's name and
/// the rest of its input), or one plain reply when it has none. `setup`
/// writes the host's settings into the home and adds its arguments and
/// variables. Every proxy variable points at the model, which refuses and
/// records every tunnel.
fn tier_2(
    id: &str,
    variant: &str,
    shell: Option<(&str, serde_json::Value)>,
    setup: impl FnOnce(
        &envcloak_testkit::TestHome,
        &envcloak_testkit::agents::Model,
        &mut std::process::Command,
    ),
) -> Option<Tier2Run> {
    let found = Installed::find(&versions_toml(), id, variant);
    let installed = require(found, &format!("tier 2 ({id})"))?;
    let home = envcloak_testkit::TestHome::new();
    let project = home.root().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let script = match &shell {
        Some((tool, extra)) => {
            let mut input = extra.clone();
            // The ancestry probe, unless the caller gives its own command
            // (the catalog's tests, `catalog.rs`).
            if input.get("command").is_none() {
                input["command"] = json!(ANCESTRY_PROBE);
            }
            json!({"steps": [{"tool": tool, "input": input}, {"say": "probe done"}], "side": "ok"})
        }
        None => json!({"steps": [{"say": "scripted reply"}], "side": "ok"}),
    };
    let model = envcloak_testkit::agents::Model::start(&script);
    let mut cmd = installed.command();
    cmd.env_clear().envs(home.vars());
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        cmd.env(k, model.base_url());
    }
    for k in ["NO_PROXY", "no_proxy"] {
        cmd.env(k, "127.0.0.1,localhost");
    }
    setup(&home, &model, &mut cmd);
    cmd.current_dir(&project)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // The run's own environment, for the version check after it.
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = cmd
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned())))
        .collect();
    let output = envcloak_testkit::agents::finish_within(cmd, envcloak_testkit::agents::RUN_LIMIT);
    let report = model.finish();
    if let Err(why) = installed.verify() {
        panic!("the host changed during the run: {why}");
    }
    // As for the tier-1 hosts (`AgentHome::check_pinned`): after the run,
    // in the same isolated environment and directory, the host still
    // reports the pinned version, so an update it made of itself (a new
    // build beside the pinned file, a version the files do not show)
    // fails the test (Codex review, low).
    let mut version = installed.command();
    version
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .arg("--version")
        .current_dir(&project)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let shown =
        envcloak_testkit::agents::finish_within(version, std::time::Duration::from_secs(120));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
    assert!(
        reports_version(&said, &installed.pin.version),
        "{id} --version says {:?} after the run, pinned {}",
        said.chars().take(300).collect::<String>(),
        installed.pin.version
    );
    let label = format!("{id}/{variant} {}", installed.pin.version);
    println!(
        "measurement: tier 2 host={label} os={}: endpoints {}; tunnels refused {}; outcome {}",
        os(),
        report.shown_model_endpoints().join(", "),
        report.shown_connects().join(", "),
        report.outcome
    );
    Some(Tier2Run { report, output })
}

/// The probe's answer in the request after the shell call: the marker,
/// and the ancestry as `comm (args)` entries, nearest first, the shell
/// itself left out (its arguments are the probe).
fn tier_2_probe(run: &Tier2Run) -> (bool, Vec<String>) {
    let Some(r) = run
        .report
        .requests
        .iter()
        .find(|r| r.pick.as_deref() == Some("step 1"))
    else {
        return (false, Vec::new());
    };
    let text = last_tool_text(&String::from_utf8_lossy(&r.body));
    let ran = text.contains("MARKER-ran");
    let lines: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("ANC "))
        .collect();
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_owned();
    // The shell, by name; then its ancestors up to this test.
    let shell = lines
        .first()
        .map(|l| base(l.split_once(" | ").map_or(*l, |(c, _)| c)));
    let chain = shell
        .into_iter()
        .chain(lines.iter().skip(1).map(|l| {
            let (comm, args) = l.split_once(" | ").unwrap_or((l, ""));
            // The program and, when it is an interpreter, its script.
            let mut words = args.split_whitespace();
            let program = words.next().map(base).unwrap_or_default();
            let script = words
                .next()
                .filter(|w| w.ends_with(".js") || w.ends_with(".mjs") || w.ends_with(".cjs"))
                .map(base);
            match script {
                Some(script) => format!("{} ({program} {script})", base(comm)),
                None => format!("{} ({program})", base(comm)),
            }
        }))
        .take_while(|c| !c.starts_with("agent_hosts"))
        .collect();
    (ran, chain)
}

/// A drivable tier-2 host: it spoke Anthropic Messages to the scripted
/// model, its shell tool ran the probe, the command's shell and its
/// nearest ancestors are `expected`, by name, in order (the shell first),
/// and the run was whole: the model's run clean (no unknown endpoint, no
/// unscripted or unanswered request, nothing refused or cut short), every
/// model call answered, and the host exited 0.
fn tier_2_drivable(id: &str, run: &Tier2Run, expected: &[&str]) {
    let (ran, chain) = tier_2_probe(run);
    println!(
        "measurement: tier 2 host={id} os={}: shell tool ran the command: {ran}; its ancestry, \
         nearest first: {}",
        os(),
        chain.join(" <- ")
    );
    if let Some(why) = not_drivable(run, expected) {
        panic!("{id}: {why}");
    }
}

/// Why `run` does not show a drivable host ([`tier_2_drivable`]), if it
/// does not. Every check, the run's completeness included, so protocol
/// drift after a successful tool turn fails loudly (Codex review, medium:
/// an unknown endpoint, an unanswered final reply or a host failure after
/// the marker still passed).
fn not_drivable(run: &Tier2Run, expected: &[&str]) -> Option<String> {
    if !run
        .report
        .model_endpoints()
        .iter()
        .any(|e| e == "POST /v1/messages")
    {
        return Some(format!(
            "it did not speak Anthropic Messages to the scripted model: {:?}",
            run.report.requests
        ));
    }
    let (ran, chain) = tier_2_probe(run);
    if !ran {
        return Some(format!(
            "its shell tool did not run the command; stdout {:?}",
            String::from_utf8_lossy(&run.output.stdout)
        ));
    }
    for (i, want) in expected.iter().enumerate() {
        if !chain.get(i).is_some_and(|c| c.contains(want)) {
            return Some(format!("ancestor {i} is not {want}: {chain:?}"));
        }
    }
    if !run.report.clean() {
        return Some(format!(
            "the scripted model's run is not clean: {}; {:?}",
            run.report.outcome, run.report.requests
        ));
    }
    if let Some(r) = run.report.model_calls().into_iter().find(|r| !r.answered) {
        return Some(format!("a model call was never answered: {r:?}"));
    }
    if run.output.status.code() != Some(0) {
        return Some(format!(
            "the host exited {:?}; stderr {:?}",
            run.output.status.code(),
            String::from_utf8_lossy(&run.output.stderr)
        ));
    }
    None
}

/// The drivability check fails a run that is incomplete or failed after
/// a successful tool turn, not only one without it. A synthetic run with
/// the marker, the ancestry and a clean model run passes (the control);
/// each change below, made after the tool turn, fails it (Codex review,
/// medium).
#[test]
fn a_tier_2_run_incomplete_or_failed_after_its_tool_turn_is_not_drivable() {
    use envcloak_testkit::agents::{ModelReport, ModelRequest};
    use std::os::unix::process::ExitStatusExt as _;
    let call = |seq: u64, pick: &str, body: serde_json::Value| ModelRequest {
        seq,
        at_ms: 0,
        method: "POST".to_owned(),
        path: "/v1/messages".to_owned(),
        query: None,
        headers: Vec::new(),
        header_values: Vec::new(),
        forward: Vec::new().into(),
        status: 200,
        answered: true,
        api: Some("messages".to_owned()),
        pick: Some(pick.to_owned()),
        body: body.to_string().into_bytes().into(),
    };
    let result = "MARKER-ran\nANC sh | sh -c printf\nANC node | /c/node /c/cli-entry.js\n";
    let outcome = json!({"bad_peer": 0, "bad_token": 0, "busy": 0, "connect": 1,
        "exhausted": 0, "incomplete": [], "malformed": 0, "mismatch": 0,
        "unanswered": 0, "unknown": 0});
    let good = || Tier2Run {
        report: ModelReport {
            requests: vec![
                call(
                    1,
                    "step 0",
                    json!({"messages": [{"role": "user", "content": "go"}]}),
                ),
                call(
                    2,
                    "step 1",
                    json!({"messages": [{"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "t", "content": result}]}]}),
                ),
            ],
            outcome: outcome.clone(),
        },
        output: std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"probe done\n".to_vec(),
            stderr: Vec::new(),
        },
    };
    let expected = ["sh", "node (node cli-entry.js)"];
    assert_eq!(not_drivable(&good(), &expected), None);
    let mut failed: Vec<(&str, Tier2Run)> = Vec::new();
    // An endpoint the model does not serve, after the tool turn.
    let mut run = good();
    run.report.requests.push(ModelRequest {
        path: "/v1/messages/count_tokens".to_owned(),
        status: 404,
        api: None,
        pick: None,
        ..call(3, "", json!({}))
    });
    run.report.outcome["unknown"] = json!(1);
    failed.push(("an unknown endpoint", run));
    // A request past the script (the host wanted another turn).
    let mut run = good();
    run.report.requests.push(call(3, "exhausted", json!({})));
    run.report.outcome["exhausted"] = json!(1);
    failed.push(("a request past the script", run));
    // The final reply never sent whole, by the outcome and by the record.
    let mut run = good();
    run.report.outcome["unanswered"] = json!(1);
    failed.push(("an unanswered reply (outcome)", run));
    let mut run = good();
    run.report.requests[1].answered = false;
    failed.push(("an unanswered reply (record)", run));
    // The run cut short.
    let mut run = good();
    run.report.outcome["incomplete"] = json!(["time_limit"]);
    failed.push(("an incomplete run", run));
    // The host failing after the marker.
    let mut run = good();
    run.output.status = std::process::ExitStatus::from_raw(1 << 8);
    failed.push(("a host exit of 1", run));
    let mut run = good();
    run.output.status = std::process::ExitStatus::from_raw(libc::SIGKILL);
    failed.push(("a host killed by a signal", run));
    for (what, run) in &failed {
        assert!(
            not_drivable(run, &expected).is_some(),
            "{what} passed as drivable"
        );
    }
}

/// Qwen Code: `modelProviders.anthropic` in `~/.qwen/settings.json`, the
/// key by `envKey`; `-p`'s positional prompt in the default approval mode
/// with the shell tool allowed by name (headless runs deny it otherwise).
#[test]
fn tier_2_qwen_code_against_the_scripted_model() {
    let Some(run) = tier_2(
        "qwen-code",
        "npm",
        Some(("run_shell_command", json!({"description": "probe"}))),
        |home, model, cmd| {
            let dir = home.home().join(".qwen");
            std::fs::create_dir_all(&dir).unwrap();
            let settings = json!({
                "modelProviders": {"anthropic": [{"id": "ec-scripted", "name": "ec",
                    "envKey": "EC_MODEL_TOKEN", "baseUrl": model.base_url()}]},
                "model": {"name": "ec-scripted"},
                "security": {"auth": {"selectedType": "anthropic"}},
            });
            std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.api_key()).args([
                "Run the probe.",
                "--approval-mode",
                "default",
                "--allowed-tools",
                "run_shell_command",
            ]);
        },
    ) else {
        return;
    };
    tier_2_drivable("qwen-code", &run, &["sh", "node (node cli-entry.js)"]);
}

/// Kimi Code: an `anthropic` provider in `$KIMI_CODE_HOME/config.toml`
/// (`~/.kimi-code`), the key by `api_key_env`; `-p`.
#[test]
fn tier_2_kimi_code_against_the_scripted_model() {
    let Some(run) = tier_2(
        "kimi-code",
        "npm",
        Some(("Bash", json!({}))),
        |home, model, cmd| {
            let dir = home.home().join(".kimi-code");
            std::fs::create_dir_all(&dir).unwrap();
            let config = format!(
                "default_model = \"ec\"\n\n[providers.ec]\ntype = \"anthropic\"\n\
                 base_url = {}\napi_key_env = \"EC_MODEL_TOKEN\"\n\n[models.ec]\n\
                 provider = \"ec\"\nmodel = \"ec-scripted\"\nmax_context_size = 200000\n",
                json!(model.base_url())
            );
            std::fs::write(dir.join("config.toml"), config).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.api_key())
                .env("KIMI_CODE_HOME", &dir)
                .args(["-p", "Run the probe."]);
        },
    ) else {
        return;
    };
    // Node, which names its process `kimi-code` (its arguments too).
    tier_2_drivable("kimi-code", &run, &["sh", "kimi-code"]);
}

/// OpenCode: a provider in `~/.config/opencode/opencode.json` on the
/// bundled `@ai-sdk/anthropic`, the key from the environment; `run`.
#[test]
fn tier_2_opencode_against_the_scripted_model() {
    let Some(run) = tier_2(
        "opencode",
        "native",
        Some(("bash", json!({"description": "probe"}))),
        |home, model, cmd| {
            let dir = home.root().join("config").join("opencode");
            std::fs::create_dir_all(&dir).unwrap();
            let config = json!({
                "provider": {"ec": {"npm": "@ai-sdk/anthropic", "name": "ec",
                    "options": {"baseURL": format!("{}/v1", model.base_url()),
                                "apiKey": "{env:EC_MODEL_TOKEN}"},
                    "models": {"ec-scripted": {"name": "ec-scripted"}}}},
                "model": "ec/ec-scripted",
                "autoupdate": false,
                "share": "disabled",
            });
            std::fs::write(dir.join("opencode.json"), config.to_string()).unwrap();
            cmd.env("EC_MODEL_TOKEN", model.api_key())
                .args(["run", "Run the probe."]);
        },
    ) else {
        return;
    };
    tier_2_drivable("opencode", &run, &["sh", "opencode (opencode)"]);
}

/// Copilot CLI: `COPILOT_PROVIDER_BASE_URL` with
/// `COPILOT_PROVIDER_TYPE=anthropic`, offline, updates off; `-p` with the
/// shell tool allowed (`--allow-tool=shell`, not every tool).
#[test]
fn tier_2_copilot_cli_against_the_scripted_model() {
    let Some(run) = tier_2(
        "copilot-cli",
        "npm",
        Some(("bash", json!({"description": "probe", "mode": "sync"}))),
        |_, model, cmd| {
            cmd.env("COPILOT_OFFLINE", "true")
                .env("COPILOT_AUTO_UPDATE", "false")
                .env("COPILOT_PROVIDER_BASE_URL", model.base_url())
                .env("COPILOT_PROVIDER_TYPE", "anthropic")
                .env("COPILOT_PROVIDER_API_KEY", model.api_key())
                .env("COPILOT_MODEL", "ec-scripted")
                .args(["-p", "Run the probe.", "--allow-tool=shell"]);
        },
    ) else {
        return;
    };
    // `node npm-loader.js` starts the platform package's binary (pinned
    // as `starts`), which runs the command. Matched by its program: on
    // Linux its process name is its main thread's (`MainThread`).
    tier_2_drivable(
        "copilot-cli",
        &run,
        &["sh", "(copilot)", "node (node npm-loader.js)"],
    );
}

/// Gemini CLI: `GOOGLE_GEMINI_BASE_URL` with a Gemini API key. It speaks
/// the Gemini API, not one of the scripted model's two protocols: not
/// drivable, measured.
#[test]
fn tier_2_gemini_cli_speaks_neither_protocol() {
    let Some(run) = tier_2("gemini-cli", "npm", None, |home, model, cmd| {
        let dir = home.home().join(".gemini");
        std::fs::create_dir_all(&dir).unwrap();
        let settings = json!({"security": {"auth": {"selectedType": "gemini-api-key"}},
                              "general": {"disableAutoUpdate": true}});
        std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
        cmd.env("GOOGLE_GEMINI_BASE_URL", model.base_url())
            .env("GEMINI_API_KEY", model.api_key())
            .args(["-p", "Say hello.", "--skip-trust"]);
    }) else {
        return;
    };
    assert!(
        run.report.model_calls().is_empty(),
        "Gemini CLI spoke a protocol the scripted model serves: {:?}",
        run.report.requests
    );
    assert!(
        run.report
            .requests
            .iter()
            .any(|r| r.path.starts_with("/v1beta/models/")),
        "Gemini CLI did not reach the base URL: {:?}",
        run.report.requests
    );
}

/// Cursor CLI: no documented base-URL setting; with every proxy variable
/// at the scripted model, all it tries is a tunnel to its own servers.
/// Not drivable, measured ([`cursor_stopped_at_its_tunnel`]).
#[test]
fn tier_2_cursor_cli_has_no_base_url() {
    let Some(run) = tier_2("cursor-cli", "native", None, |_, model, cmd| {
        cmd.env("CURSOR_API_KEY", model.api_key())
            .args(["-p", "Say hello."]);
    }) else {
        return;
    };
    if let Err(why) = cursor_stopped_at_its_tunnel(&run) {
        panic!("Cursor CLI's run is not the measurement: {why}");
    }
}

/// Where Cursor CLI reaches for its model, as a tunnel through the proxy.
const CURSOR_API: &str = "api2.cursor.sh:443";

/// What Cursor CLI says when it stops on the refused tunnel.
const CURSOR_STOPS: &str = "Failed to reach the Cursor API";

/// Whether a Cursor CLI run is what docs/ACCEPTANCE.md records for it:
/// the scripted model's run complete and clean, nothing served, every
/// request it recorded a tunnel to [`CURSOR_API`], refused (403) with the
/// reply sent, at least one, and the host stopping on it, saying
/// [`CURSOR_STOPS`], with an exit code that is not 0. A run with no
/// traffic, one that failed some other way (another message, a signal, a
/// success), or an incomplete record is not that measurement (Codex
/// review, low: only "no request to the model itself" was checked, which
/// a host that never started passed). Why not, naming no request target.
fn cursor_stopped_at_its_tunnel(run: &Tier2Run) -> Result<(), String> {
    let report = &run.report;
    if !report.clean() {
        return Err(format!(
            "the scripted model's run is not clean: {}",
            report.outcome
        ));
    }
    if !report.model_endpoints().is_empty() {
        return Err("it reached the scripted model itself".to_owned());
    }
    let tunnels = report
        .requests
        .iter()
        .filter(|r| {
            r.api.as_deref() == Some("connect")
                && r.path == CURSOR_API
                && r.status == 403
                && r.answered
        })
        .count();
    if tunnels == 0 {
        return Err(format!("no refused tunnel to {CURSOR_API}"));
    }
    if tunnels != report.requests.len()
        || report.outcome["connect"].as_u64() != Some(tunnels as u64)
    {
        return Err(format!(
            "{} request(s) other than a refused tunnel to {CURSOR_API}",
            report.requests.len() - tunnels
        ));
    }
    match run.output.status.code() {
        Some(code) if code != 0 => {}
        other => return Err(format!("it did not stop with a failure: exit {other:?}")),
    }
    let said = [&run.output.stdout, &run.output.stderr]
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .concat();
    if !said.contains(CURSOR_STOPS) {
        return Err(format!(
            "it did not stop on the refused tunnel (no {CURSOR_STOPS:?})"
        ));
    }
    Ok(())
}

/// The Cursor check takes only the measured run: a refused tunnel to its
/// API, then the host stopping on it. The control passes; a run with no
/// traffic, one stopped by another failure or a signal, one that
/// succeeded, an incomplete or unclean record, a tunnel elsewhere or one
/// besides, and a request to the model itself all fail (Codex review,
/// low).
#[test]
fn cursor_s_measurement_is_its_refused_tunnel_and_nothing_else() {
    use envcloak_testkit::agents::{ModelReport, ModelRequest};
    use std::os::unix::process::ExitStatusExt as _;
    let tunnel = |seq: u64, path: &str| ModelRequest {
        seq,
        at_ms: 0,
        method: "CONNECT".to_owned(),
        path: path.to_owned(),
        query: None,
        headers: Vec::new(),
        header_values: Vec::new(),
        forward: Vec::new().into(),
        status: 403,
        answered: true,
        api: Some("connect".to_owned()),
        pick: None,
        body: Vec::new().into(),
    };
    let outcome = json!({"bad_peer": 0, "bad_token": 0, "busy": 0, "connect": 1,
        "exhausted": 0, "incomplete": [], "malformed": 0, "mismatch": 0,
        "unanswered": 0, "unknown": 0});
    let good = || Tier2Run {
        report: ModelReport {
            requests: vec![tunnel(1, CURSOR_API)],
            outcome: outcome.clone(),
        },
        output: std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: format!("Error: {CURSOR_STOPS}\n").into_bytes(),
        },
    };
    assert_eq!(cursor_stopped_at_its_tunnel(&good()), Ok(()));
    let mut failed: Vec<(&str, Tier2Run)> = Vec::new();
    let mut run = good();
    run.report.requests.clear();
    run.report.outcome["connect"] = json!(0);
    failed.push(("no traffic, the same failure", run));
    let mut run = good();
    run.output.stderr = b"Segmentation fault\n".to_vec();
    failed.push(("an unrelated failure", run));
    let mut run = good();
    run.output.status = std::process::ExitStatus::from_raw(libc::SIGKILL);
    failed.push(("killed by a signal", run));
    let mut run = good();
    run.output.status = std::process::ExitStatus::from_raw(0);
    failed.push(("a success", run));
    let mut run = good();
    run.report.outcome["incomplete"] = json!(["time_limit"]);
    failed.push(("an incomplete record", run));
    let mut run = good();
    run.report.outcome["malformed"] = json!(1);
    failed.push(("a malformed request", run));
    let mut run = good();
    run.report.requests[0].answered = false;
    failed.push(("a refusal never sent", run));
    let mut run = good();
    run.report.requests[0] = tunnel(1, "elsewhere.example:443");
    failed.push(("a tunnel elsewhere", run));
    let mut run = good();
    run.report.requests.push(tunnel(2, "elsewhere.example:443"));
    run.report.outcome["connect"] = json!(2);
    failed.push(("a tunnel besides", run));
    let mut run = good();
    run.report.outcome["connect"] = json!(2);
    failed.push(("a tunnel the record lacks", run));
    let mut run = good();
    run.report.requests.push(ModelRequest {
        method: "POST".to_owned(),
        path: "/v1/messages".to_owned(),
        status: 200,
        api: Some("messages".to_owned()),
        pick: Some("step 0".to_owned()),
        ..tunnel(2, "")
    });
    failed.push(("a request to the model itself", run));
    for (what, run) in &failed {
        assert!(
            cursor_stopped_at_its_tunnel(run).is_err(),
            "{what} passed as the measurement"
        );
    }
}

// ---------------------------------------------------------------------
// The agent catalog against these hosts (M2 plan task M2-10).
// ---------------------------------------------------------------------

mod catalog {
    //! The agent catalog against the pinned hosts (M2 plan task M2-10;
    //! gates 23 and 25; risk K-03). The catalog's patterns rest on these
    //! layouts (integrations/agents.toml), so each is checked on the real
    //! install M2-04's cache holds:
    //!
    //! - every tier-2 host, started on a pseudo-terminal of its own and left
    //!   waiting for input, classifies as its catalog entry when its running
    //!   processes are read as the daemon reads an ancestor (its executable,
    //!   and its arguments where the catalog needs them), with the basis that
    //!   decides whether it may root a grant above a caller's session; Cursor
    //!   CLI in the layout its installer makes, which M2-04's cache does not;
    //! - a command Codex starts with `tty: true` (on a pseudo-terminal of its
    //!   own, in a session it leads) under `env -i` is an agent subject rooted
    //!   at Codex: a grant for its terminal does not cover it, and its proofs
    //!   are refused;
    //! - for each tier-2 host M2-04 found drivable, a command its shell tool
    //!   starts on a pseudo-terminal of its own (the shape of Gemini CLI's
    //!   `node-pty`), under `env -i`, is an agent subject labeled with the
    //!   host's entry, and its proofs are refused;
    //! - and from each such pseudo-terminal (Codex's `tty: true` and every
    //!   drivable host's, and the test fixture agent's), real proofs reach a
    //!   real daemon and are refused there ([`ProofTarget`]): `envcloak
    //!   approve` for an agent's pending request and `envcloak unlock` of
    //!   the locked vault, each with the vault's passphrase on a
    //!   descriptor. Nothing is approved or unlocked, no grant exists and
    //!   the agent's run gets no value; the same proofs from a person's
    //!   terminal are then taken, and the run gets its value (the control).
    //!
    //! The caller is `ec-probe`, which connects to a socket this test listens
    //! on, as the CLI connects to the daemon, and stays until it is closed;
    //! the test gathers its evidence there with the builtin catalog, as the
    //! daemon does (`envcloak_policy::gather`). Lines starting `measurement:`
    //! feed docs/AGENTS.md.

    use std::os::fd::AsFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use envcloak_e2e::{Harness, RECOVERY_KIT, python3, quoted, text, token, versions_toml};
    use envcloak_policy::{
        AgentCatalog, AgentLabel, Claims, MatchBasis, ProofRefusal, SubjectEvidence, SubjectKind,
        gather,
    };
    use envcloak_testkit::agents::{AgentHome, GroupChild, Host, HostFlags, Installed, require};
    use envcloak_testkit::{Canary, TestHome, labels, testkit_bin};
    use serde_json::json;

    use super::{os, tier_2};

    /// Runs argv[1:] as the leader of a new session on a new
    /// pseudo-terminal (120 columns, 40 rows), reading and dropping what it
    /// prints. Once it has printed something and then nothing for two
    /// seconds (it drew its screen and waits for input), prints `QUIET` on
    /// standard output, once. When this driver's standard input closes, kills
    /// that session's process group while its leader is unreaped, then reaps
    /// it.
    const PTY_HOLD: &str = r#"import fcntl, os, pty, select, signal, struct, sys, termios, time
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
seen, last, told = False, time.monotonic(), False
while True:
    r, _, _ = select.select([fd, 0], [], [], 0.2)
    if fd in r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if not data:
            break
        seen, last = True, time.monotonic()
    if 0 in r and not os.read(0, 4096):
        break
    if seen and not told and time.monotonic() - last >= 2:
        sys.stdout.write("QUIET\n")
        sys.stdout.flush()
        told = True
try:
    os.killpg(pid, signal.SIGKILL)
except OSError:
    pass
os.waitpid(pid, 0)
"#;

    /// Runs argv[1:] as the leader of a new session on a new pseudo-terminal
    /// until it ends, dropping what it prints, as `node-pty` and Codex's
    /// `tty: true` start a command; exits with its status.
    const PTY_ONCE: &str = r#"import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:
        break
    if not data:
        break
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status) & 255)
"#;

    /// A socket this test listens on, in a short temporary directory, and the
    /// evidence of each caller that connects to it.
    struct Listener {
        _home: TestHome,
        sock: PathBuf,
        l: UnixListener,
    }

    impl Listener {
        fn new() -> Self {
            let home = TestHome::new();
            let sock = home.root().join("e.sock");
            let l = UnixListener::bind(&sock).unwrap();
            l.set_nonblocking(true).unwrap();
            Listener {
                _home: home,
                sock,
                l,
            }
        }

        /// The evidence of the next caller, gathered while it is connected, or
        /// why there is none within `limit`. The connection is then closed,
        /// which lets the caller exit.
        fn next_within(&self, limit: Duration) -> Result<SubjectEvidence, String> {
            let end = Instant::now() + limit;
            let s: UnixStream = loop {
                match self.l.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= end {
                            return Err(format!("no caller connected within {limit:?}"));
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => return Err(format!("accept: {e}")),
                }
            };
            s.set_nonblocking(false).map_err(|e| e.to_string())?;
            let peer = envcloak_sys::peer_identity(s.as_fd()).map_err(|e| e.to_string())?;
            gather(&peer, Claims::none(), &AgentCatalog::builtin()).map_err(|e| e.to_string())
        }
    }

    /// The line of the script a host's shell tool runs (`sh
    /// ./ec-pty-probe.sh`, in the directory the host works in, so the
    /// command names no path a host would ask about) that runs `ec-probe
    /// <socket>` under `env -i`, leading a session of its own on a new
    /// pseudo-terminal.
    fn probe_on_its_own_pty(sock: &Path) -> String {
        let probe = testkit_bin("ec-probe");
        let line = [
            quoted(&python3().to_string_lossy()),
            "-c".to_owned(),
            quoted(PTY_ONCE),
            "/usr/bin/env".to_owned(),
            "-i".to_owned(),
            quoted(&probe.to_string_lossy()),
            quoted(&sock.to_string_lossy()),
        ]
        .join(" ");
        format!("{line}\n")
    }

    /// The script's name, in the host's working directory.
    const PTY_SCRIPT: &str = "ec-pty-probe.sh";

    /// How long a line the daemon wrote may take to reach its collected log.
    const LOG_LIMIT: Duration = Duration::from_secs(10);

    /// A daemon with an unlocked vault, a project (the canary
    /// `OPENAI_API_KEY` imported from its `.env`) and the test fixture
    /// agent's pending request (its `run -- ./emit`): what a command on an
    /// agent's pseudo-terminal tries to prove itself to (gate 23 at the
    /// daemon, Codex review). The proofs it tries are valid ones: the
    /// vault's passphrase, on a descriptor.
    pub(super) struct ProofTarget {
        h: Harness,
        repo: PathBuf,
        id: String,
        pass: PathBuf,
        /// Where the attempts write their output and status.
        dir: PathBuf,
    }

    impl ProofTarget {
        pub(super) fn new() -> Self {
            let mut h = Harness::start();
            let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
            let kit = h.files().join("kit");
            let home = h.home.home();
            let made = h.human(
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
            assert_eq!(made.code, 0, "{}", made.all());
            let kit_text = std::fs::read_to_string(&kit).unwrap();
            h.add_canary(Canary::new(RECOVERY_KIT, kit_text.trim_end().to_owned()));
            let repo = h.home.root().join("acme-web");
            std::fs::create_dir_all(&repo).unwrap();
            let env = format!(
                "OPENAI_API_KEY={}\n",
                h.canary(labels::OPENAI_API_KEY).as_str()
            );
            std::fs::write(repo.join(".env"), env).unwrap();
            h.allow_plaintext(repo.join(".env"));
            let imported = h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
            assert_eq!(imported.code, 0, "{}", imported.all());
            envcloak_e2e::write_script(&repo.join("emit"), "#!/bin/sh\necho started\n");
            let run = h.agent(&repo, &["run", "--", "./emit"]);
            assert_eq!(run.status.code(), Some(125), "{}", text(&run));
            assert_eq!(token(&run.stderr), "approval_required", "{}", text(&run));
            let err = String::from_utf8_lossy(&run.stderr).into_owned();
            let id = err
                .split("request=")
                .nth(1)
                .and_then(|r| r.get(..8))
                .unwrap_or_else(|| panic!("no request id: {err}"))
                .to_owned();
            let dir = h.files().join("attempts");
            std::fs::create_dir_all(&dir).unwrap();
            ProofTarget {
                h,
                repo,
                id,
                pass,
                dir,
            }
        }

        /// The shell commands a command on an agent's pseudo-terminal runs,
        /// under `env -i` with only this daemon's home, each writing its
        /// output and status beside the others: `envcloak approve <id> --for
        /// 1h` for the pending request, with the vault's passphrase on
        /// descriptor 3; `envcloak lock`, which needs no proof; then
        /// `envcloak unlock`, with the passphrase on descriptor 3.
        pub(super) fn attempts(&self) -> String {
            let env = self
                .h
                .home
                .vars()
                .iter()
                .map(|(k, v)| format!("{k}={}", quoted(&v.to_string_lossy())))
                .collect::<Vec<_>>()
                .join(" ");
            let cli = quoted(&self.h.cli().to_string_lossy());
            let pass = quoted(&self.pass.to_string_lossy());
            let one = |name: &str, args: &str| {
                let at =
                    |ext: &str| quoted(&self.dir.join(format!("{name}.{ext}")).to_string_lossy());
                format!(
                    "/usr/bin/env -i {env} {cli} {args} >{} 2>{}; echo $? >{}",
                    at("out"),
                    at("err"),
                    at("code")
                )
            };
            let proof = format!("--passphrase-fd 3 3<{pass}");
            [
                one("approve", &format!("approve {} --for 1h {proof}", self.id)),
                one("lock", "lock"),
                one("unlock", &format!("unlock {proof}")),
            ]
            .join("; ")
        }

        /// [`ProofTarget::attempts`] as a line a host's shell tool runs: on
        /// a pseudo-terminal of its own, `sh` leading its session there.
        pub(super) fn attempts_on_own_pty(&self) -> String {
            [
                quoted(&python3().to_string_lossy()),
                "-c".to_owned(),
                quoted(PTY_ONCE),
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                quoted(&self.attempts()),
            ]
            .join(" ")
        }

        /// Both proofs were refused as an agent's, and nothing came of them:
        /// no approval in the daemon's audit, no grant, the vault still
        /// locked (the lock between them ran), the agent's run given
        /// nothing. Then the control: the same passphrase from a person's
        /// terminal unlocks the vault and approves the agent's request (its
        /// new one: the lock ended the first), and the run gets its value.
        /// Prints the measurement.
        pub(super) fn assert_refused_then_taken(mut self, host: &str) {
            let read = |dir: &Path, name: &str, ext: &str| {
                std::fs::read(dir.join(format!("{name}.{ext}"))).unwrap_or_default()
            };
            let dir = self.dir.clone();
            assert_eq!(
                String::from_utf8_lossy(&read(&dir, "lock", "code")).trim(),
                "0",
                "{host}: the lock between the proofs: {}",
                String::from_utf8_lossy(&read(&dir, "lock", "err"))
            );
            for name in ["approve", "unlock"] {
                let (out, err) = (read(&dir, name, "out"), read(&dir, name, "err"));
                self.h.record(&format!("{host}: {name} (stdout)"), &out);
                self.h.record(&format!("{host}: {name} (stderr)"), &err);
                let code = String::from_utf8_lossy(&read(&dir, name, "code"))
                    .trim()
                    .to_owned();
                println!(
                    "measurement: catalog host={host} os={}: `envcloak {name}` with the \
                     passphrase from its pseudo-terminal: exit {code}, {}",
                    os(),
                    token(&err)
                );
                assert!(
                    !code.is_empty() && code != "0",
                    "{host}: {name} ran or was taken: {code:?} {}",
                    String::from_utf8_lossy(&err)
                );
                assert_eq!(
                    token(&err),
                    "proof_refused",
                    "{host}: {name}: {}",
                    String::from_utf8_lossy(&err)
                );
            }
            let mut log = String::new();
            for method in ["pending.get", "unlock"] {
                log = self.h.expect_log(
                    &format!("envcloakd: audit: proof refused method={method} reason=agent"),
                    LOG_LIMIT,
                );
            }
            assert!(
                !log.contains("envcloakd: audit: approved request="),
                "{host}: {log}"
            );
            let grants = self.h.agent(&self.repo, &["grants", "list", "--json"]);
            assert_eq!(grants.status.code(), Some(0), "{}", text(&grants));
            let g: serde_json::Value = serde_json::from_slice(&grants.stdout).unwrap();
            assert_eq!(g["grants"], json!([]), "{host}: {g}");
            let st = self.h.agent(&self.repo, &["status", "--json"]);
            let st: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap();
            assert_eq!(st["vault"]["state"], "locked", "{host}: {st}");
            let run = self.h.agent(&self.repo, &["run", "--", "./emit"]);
            assert_ne!(run.status.code(), Some(0), "{host}: {}", text(&run));
            assert!(run.stdout.is_empty(), "{host}: {}", text(&run));
            // The control, from a person's terminal.
            let home = self.h.home.home();
            let unlocked = self.h.human(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &self.pass, true)],
                &[],
            );
            assert_eq!(unlocked.code, 0, "{host}: {}", unlocked.all());
            let again = self.h.agent(&self.repo, &["run", "--", "./emit"]);
            assert_eq!(
                token(&again.stderr),
                "approval_required",
                "{}",
                text(&again)
            );
            let err = String::from_utf8_lossy(&again.stderr).into_owned();
            let id = err
                .split("request=")
                .nth(1)
                .and_then(|r| r.get(..8))
                .unwrap_or_else(|| panic!("no request id: {err}"))
                .to_owned();
            let typed = format!("{}\r", self.h.canary(labels::VAULT_PASSPHRASE).as_str());
            let repo = self.repo.clone();
            let approved = self.h.human(
                &repo,
                &["approve", &id, "--for", "1h"],
                &[],
                &[("Vault passphrase to approve this: ", &typed)],
            );
            assert_eq!(approved.code, 0, "{host}: {}", approved.all());
            let run = self.h.agent(&self.repo, &["run", "--", "./emit"]);
            assert_eq!(run.status.code(), Some(0), "{host}: {}", text(&run));
            assert_eq!(String::from_utf8_lossy(&run.stdout), "started\n");
            self.h.assert_swept(host);
        }
    }

    /// Checks the evidence of a command `id`'s host started on a
    /// pseudo-terminal of its own: it leads its session there, with no marker,
    /// and is an agent subject labeled `id` at the nearest agent, its basis
    /// `basis`; a grant for its terminal (rooted at its session's leader, for
    /// a terminal subject) does not cover it, and its proofs are refused.
    /// Prints the measurement.
    fn assert_pty_command_is_an_agent(
        e: &SubjectEvidence,
        host: &str,
        id: &str,
        basis: MatchBasis,
    ) {
        let (n, label) = e
            .nearest_agent()
            .unwrap_or_else(|| panic!("{host}: no agent in the command's ancestry: {e:?}"));
        println!(
            "measurement: catalog host={host} os={}: a command on its own pseudo-terminal: kind {:?}, \
         nearest agent {} ({:?}) at {n}, root at {}, terminal {}, proof refusal {:?}",
            os(),
            e.kind(),
            label.id,
            label.basis,
            e.root_index(),
            e.terminal(),
            e.proof_refusal().map(ProofRefusal::token)
        );
        assert!(e.terminal(), "{host}: no controlling terminal: {e:?}");
        let leader = e.session_leader().expect("its session's leader");
        assert!(leader.same(e.caller()), "{host}: {e:?}");
        assert!(e.claims().markers().is_empty());
        assert_eq!((label.id.as_str(), label.basis), (id, basis), "{host}");
        assert_eq!(e.kind(), SubjectKind::Agent, "{host}");
        assert!(!e.covered_by(leader, SubjectKind::Terminal), "{host}");
        assert!(!e.covered_by(&e.root(), SubjectKind::Terminal), "{host}");
        assert_eq!(e.proof_refusal(), Some(ProofRefusal::Agent), "{host}");
    }

    /// Gate 23 and 25 (risk K-03): Codex's `tty: true` starts a command on a
    /// pseudo-terminal of its own. Under `env -i`, with no sandbox in the way
    /// of the socket (`danger-full-access`; the classification, not the
    /// sandbox, is measured here), the command is an agent subject rooted at
    /// the pinned `codex` binary, above its session.
    #[test]
    fn a_codex_tty_true_command_is_an_agent() {
        let found = Installed::find(&versions_toml(), Host::Codex.id(), "native");
        let Some(installed) = require(found, "a_codex_tty_true_command_is_an_agent") else {
            return;
        };
        let target = ProofTarget::new();
        let a = AgentHome::start(Host::Codex, installed);
        let l = Listener::new();
        let probe = testkit_bin("ec-probe");
        let cmd = format!(
            "/usr/bin/env -i {} {}",
            quoted(&probe.to_string_lossy()),
            quoted(&l.sock.to_string_lossy())
        );
        let script = json!({"steps": [
            {"tool": "exec_command", "input": {"cmd": cmd, "tty": true, "yield_time_ms": 30000}},
            {"tool": "exec_command",
             "input": {"cmd": target.attempts(), "tty": true, "yield_time_ms": 60000}},
            {"say": "done"}
        ]});
        let running = a.spawn(
            &script,
            "Run the probe.",
            &HostFlags::codex("danger-full-access", "never"),
            &a.home_dir(),
        );
        let e = l.next_within(Duration::from_secs(240));
        let run = running.wait();
        let e = e.unwrap_or_else(|why| panic!("{why}; the host said {}", run.text()));
        assert_pty_command_is_an_agent(&e, "codex", "codex", MatchBasis::Executable);
        // Rooted at the pinned binary itself, the host's own process.
        let root = e.root();
        let exe = root.exe.as_ref().expect("the root's executable");
        assert_eq!(exe.path.file_name().unwrap(), "codex", "{e:?}");
        assert!(e.root_index() > 0);
        assert_eq!(run.output.status.code(), Some(0), "{}", run.text());
        a.check_pinned();
        target.assert_refused_then_taken("codex");
    }

    /// One drivable tier-2 host's shell tool runs [`probe_on_its_own_pty`],
    /// then `target`'s proofs on a pseudo-terminal of their own
    /// ([`ProofTarget::attempts_on_own_pty`]); the probe's evidence is
    /// gathered while the host runs, the proofs' outcome checked after it.
    fn drivable_pty_command(
        id: &str,
        variant: &str,
        tool: &str,
        input: serde_json::Value,
        setup: impl FnOnce(
            &envcloak_testkit::TestHome,
            &envcloak_testkit::agents::Model,
            &mut std::process::Command,
        ),
    ) -> Option<SubjectEvidence> {
        pinned(id, variant, id)?;
        let target = ProofTarget::new();
        let l = Listener::new();
        let mut input = input;
        input["command"] = json!(format!("sh ./{PTY_SCRIPT}"));
        let script = format!(
            "{}{}\n",
            probe_on_its_own_pty(&l.sock),
            target.attempts_on_own_pty()
        );
        let setup = |home: &envcloak_testkit::TestHome,
                     model: &envcloak_testkit::agents::Model,
                     cmd: &mut std::process::Command| {
            std::fs::write(home.root().join("project").join(PTY_SCRIPT), &script).unwrap();
            setup(home, model, cmd);
        };
        let (tx, rx) = mpsc::channel();
        let run = std::thread::scope(|scope| {
            scope.spawn(|| {
                let _ = tx.send(l.next_within(Duration::from_secs(240)));
            });
            tier_2(id, variant, Some((tool, input)), setup)
        });
        let run = run?;
        let e = rx.recv().unwrap();
        let e = e.unwrap_or_else(|why| {
            panic!(
                "{id}: {why}; the host said {}",
                String::from_utf8_lossy(&run.output.stdout)
            )
        });
        target.assert_refused_then_taken(id);
        Some(e)
    }

    /// Gates 23 and 25 for Qwen Code (drivable, M2-04): node runs its entry
    /// script, so it is known by that script, and roots no grant above the
    /// command's session.
    #[test]
    fn a_qwen_code_command_on_its_own_pty_is_an_agent() {
        let Some(e) = drivable_pty_command(
            "qwen-code",
            "npm",
            "run_shell_command",
            json!({"description": "probe"}),
            |home, model, cmd| {
                let dir = home.home().join(".qwen");
                std::fs::create_dir_all(&dir).unwrap();
                let settings = json!({
                    "modelProviders": {"anthropic": [{"id": "ec-scripted", "name": "ec",
                        "envKey": "EC_MODEL_TOKEN", "baseUrl": model.base_url()}]},
                    "model": {"name": "ec-scripted"},
                    "security": {"auth": {"selectedType": "anthropic"}},
                });
                std::fs::write(dir.join("settings.json"), settings.to_string()).unwrap();
                cmd.env("EC_MODEL_TOKEN", model.api_key()).args([
                    "Run the probe.",
                    "--approval-mode",
                    "default",
                    "--allowed-tools",
                    "run_shell_command",
                ]);
            },
        ) else {
            return;
        };
        assert_pty_command_is_an_agent(&e, "qwen-code", "qwen-code", MatchBasis::Asserted);
    }

    /// Gates 23 and 25 for Kimi Code (drivable): node renames its process to
    /// `kimi-code`, which the `kimi` entry knows.
    #[test]
    fn a_kimi_code_command_on_its_own_pty_is_an_agent() {
        let Some(e) =
            drivable_pty_command("kimi-code", "npm", "Bash", json!({}), |home, model, cmd| {
                let dir = home.home().join(".kimi-code");
                std::fs::create_dir_all(&dir).unwrap();
                let config = format!(
                    "default_model = \"ec\"\n\n[providers.ec]\ntype = \"anthropic\"\n\
                 base_url = {}\napi_key_env = \"EC_MODEL_TOKEN\"\n\n[models.ec]\n\
                 provider = \"ec\"\nmodel = \"ec-scripted\"\nmax_context_size = 200000\n",
                    json!(model.base_url())
                );
                std::fs::write(dir.join("config.toml"), config).unwrap();
                cmd.env("EC_MODEL_TOKEN", model.api_key())
                    .env("KIMI_CODE_HOME", &dir)
                    .args(["-p", "Run the probe."]);
            })
        else {
            return;
        };
        assert_pty_command_is_an_agent(&e, "kimi-code", "kimi", MatchBasis::Asserted);
    }

    /// Gates 23 and 25 for OpenCode (drivable): its native binary, known by
    /// its path, roots the grant above the command's session.
    #[test]
    fn an_opencode_command_on_its_own_pty_is_an_agent() {
        let Some(e) = drivable_pty_command(
            "opencode",
            "native",
            "bash",
            json!({"description": "probe"}),
            |home, model, cmd| {
                let dir = home.root().join("config").join("opencode");
                std::fs::create_dir_all(&dir).unwrap();
                let config = json!({
                    "provider": {"ec": {"npm": "@ai-sdk/anthropic", "name": "ec",
                        "options": {"baseURL": format!("{}/v1", model.base_url()),
                                    "apiKey": "{env:EC_MODEL_TOKEN}"},
                        "models": {"ec-scripted": {"name": "ec-scripted"}}}},
                    "model": "ec/ec-scripted",
                    "autoupdate": false,
                    "share": "disabled",
                });
                std::fs::write(dir.join("opencode.json"), config.to_string()).unwrap();
                cmd.env("EC_MODEL_TOKEN", model.api_key())
                    .args(["run", "Run the probe."]);
            },
        ) else {
            return;
        };
        assert_pty_command_is_an_agent(&e, "opencode", "opencode", MatchBasis::Executable);
        let root = e.root();
        let exe = root.exe.as_ref().expect("the root's executable");
        assert_eq!(exe.path.file_name().unwrap(), "opencode", "{e:?}");
    }

    /// Gates 23 and 25 for Copilot CLI (drivable): `node npm-loader.js`
    /// starts the platform binary, which runs the command and is known by its
    /// path.
    #[test]
    fn a_copilot_cli_command_on_its_own_pty_is_an_agent() {
        let Some(e) = drivable_pty_command(
            "copilot-cli",
            "npm",
            "bash",
            json!({"description": "probe", "mode": "sync"}),
            |_, model, cmd| {
                cmd.env("COPILOT_OFFLINE", "true")
                    .env("COPILOT_AUTO_UPDATE", "false")
                    .env("COPILOT_PROVIDER_BASE_URL", model.base_url())
                    .env("COPILOT_PROVIDER_TYPE", "anthropic")
                    .env("COPILOT_PROVIDER_API_KEY", model.api_key())
                    .env("COPILOT_MODEL", "ec-scripted")
                    .args(["-p", "Run the probe.", "--allow-tool=shell"]);
            },
        ) else {
            return;
        };
        assert_pty_command_is_an_agent(&e, "copilot-cli", "copilot-cli", MatchBasis::Executable);
        let root = e.root();
        let exe = root.exe.as_ref().expect("the root's executable");
        assert_eq!(exe.path.file_name().unwrap(), "copilot", "{e:?}");
    }

    /// What the daemon would make of process `pid` as an ancestor of a caller
    /// of this uid: read as `gather` reads it (its executable, and its
    /// arguments where the catalog needs them), then classified.
    fn classify_running(cat: &AgentCatalog, pid: i32) -> Option<AgentLabel> {
        let mut p = envcloak_sys::proc_info(pid).ok()?;
        if p.uid != envcloak_sys::effective_uid() {
            return None;
        }
        if cat.needs_argv(&p) {
            p.argv = envcloak_sys::proc_argv(pid).ok();
        }
        cat.classify(&p)
    }

    /// Process `root` and its descendants, from `ps`.
    fn tree(root: i32) -> Vec<i32> {
        let out = Command::new("ps")
            .args(["-A", "-o", "pid=,ppid="])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        let pairs: Vec<(i32, i32)> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                Some((w.next()?.parse().ok()?, w.next()?.parse().ok()?))
            })
            .collect();
        let mut found = vec![root];
        let mut i = 0;
        while i < found.len() {
            let parent = found[i];
            found.extend(
                pairs
                    .iter()
                    .filter(|(_, pp)| *pp == parent)
                    .map(|(p, _)| *p),
            );
            i += 1;
        }
        found
    }

    /// The file name of the executable process `pid` runs.
    fn exe_name(pid: i32) -> Option<String> {
        let p = envcloak_sys::proc_info(pid).ok()?;
        let exe = p.exe?;
        Some(exe.path.file_name()?.to_string_lossy().into_owned())
    }

    /// Starts `argv` on a pseudo-terminal of its own in `home`, with the
    /// variables of `home` and nothing else from this process, waits (up to
    /// 120 seconds) until it waits for input ([`PTY_HOLD`]'s `QUIET`), then
    /// reads its processes as the daemon reads ancestors: those whose
    /// executable's file name is a key of `want` must be there, each key at
    /// least once, and each must classify as its value, an entry id and a
    /// basis. Prints what it found, then ends the tree; panics when the host
    /// never waited for input or a process did not classify so.
    fn running_classifies(
        host: &str,
        home: &TestHome,
        argv: &[&std::ffi::OsStr],
        want: &[(&str, &str, MatchBasis)],
    ) {
        let cat = AgentCatalog::builtin();
        let mut cmd = Command::new(python3());
        cmd.arg("-c").arg(PTY_HOLD).args(argv);
        cmd.env_clear()
            .envs(home.vars())
            .env("DISABLE_AUTOUPDATER", "1")
            .current_dir(home.home())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Nothing leaves loopback: a proxy that refuses every connection.
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            cmd.env(k, "http://127.0.0.1:9");
        }
        let mut driver = GroupChild::spawn(&mut cmd).unwrap();
        let stdin = driver.take_stdin();
        let stdout = driver.take_stdout().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stdout).lines() {
                if tx.send(line.unwrap_or_default()).is_err() {
                    break;
                }
            }
        });
        let quiet = rx
            .recv_timeout(Duration::from_secs(120))
            .is_ok_and(|l| l == "QUIET");
        let driver_pid = i32::try_from(driver.id()).unwrap();
        let mut seen: Vec<String> = Vec::new();
        let mut good = quiet;
        let mut present = vec![false; want.len()];
        for pid in tree(driver_pid).into_iter().skip(1) {
            let Some(name) = exe_name(pid) else {
                continue;
            };
            let got = classify_running(&cat, pid);
            seen.push(format!(
                "{name}: {:?}",
                got.as_ref().map(|l| (l.id.as_str(), l.basis))
            ));
            if let Some(k) = want.iter().position(|(n, _, _)| *n == name) {
                present[k] = true;
                let (_, id, basis) = want[k];
                if got.as_ref().map(|l| (l.id.as_str(), l.basis)) != Some((id, basis)) {
                    good = false;
                }
            }
        }
        let shown = seen.join("; ");
        println!(
            "measurement: catalog host={host} os={}: waiting for input: {quiet}; its running \
         processes read as ancestors: {shown}",
            os()
        );
        drop(stdin);
        let _ = driver.end_within(Duration::from_secs(30));
        assert!(quiet, "{host}: it never waited for input");
        assert!(
            good && present.iter().all(|p| *p),
            "{host}: its processes did not classify as {want:?} while it waited for input: {shown}"
        );
    }

    /// The pinned host `id`/`variant`, or `None` when it is not installed
    /// (a skip, except in CI).
    fn pinned(id: &str, variant: &str, test: &str) -> Option<Installed> {
        require(Installed::find(&versions_toml(), id, variant), test)
    }

    /// The pinned host's command line: its interpreter, if any, then its
    /// entry.
    fn argv_of(i: &Installed) -> Vec<PathBuf> {
        match &i.interpreter {
            Some((node, _)) => vec![node.clone(), i.exe.clone()],
            None => vec![i.exe.clone()],
        }
    }

    fn os_strs(v: &[PathBuf]) -> Vec<&std::ffi::OsStr> {
        v.iter().map(|p| p.as_os_str()).collect()
    }

    /// Gemini CLI (tier 2, not drivable): node runs its bundle, and relaunches
    /// it in a child node with more memory; both are Gemini CLI by their
    /// script.
    #[test]
    fn gemini_cli_running_is_its_entry() {
        let Some(i) = pinned("gemini-cli", "npm", "gemini_cli_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let argv = argv_of(&i);
        running_classifies(
            "gemini-cli",
            &home,
            &os_strs(&argv),
            &[("node", "gemini-cli", MatchBasis::Asserted)],
        );
    }

    /// Copilot CLI: `node npm-loader.js`, by its script, and the platform
    /// binary it starts, by its path.
    #[test]
    fn copilot_cli_running_is_its_entry() {
        let Some(i) = pinned("copilot-cli", "npm", "copilot_cli_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let argv = argv_of(&i);
        running_classifies(
            "copilot-cli",
            &home,
            &os_strs(&argv),
            &[
                ("node", "copilot-cli", MatchBasis::Asserted),
                ("copilot", "copilot-cli", MatchBasis::Executable),
            ],
        );
    }

    /// OpenCode: the native binary, by its path.
    #[test]
    fn opencode_running_is_its_entry() {
        let Some(i) = pinned("opencode", "native", "opencode_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let argv = argv_of(&i);
        running_classifies(
            "opencode",
            &home,
            &os_strs(&argv),
            &[("opencode", "opencode", MatchBasis::Executable)],
        );
    }

    /// Kimi Code: node, which renames its process and overwrites its own
    /// arguments with `kimi-code`.
    #[test]
    fn kimi_code_running_is_its_entry() {
        let Some(i) = pinned("kimi-code", "npm", "kimi_code_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let argv = argv_of(&i);
        running_classifies(
            "kimi-code",
            &home,
            &os_strs(&argv),
            &[("node", "kimi", MatchBasis::Asserted)],
        );
    }

    /// Qwen Code: node runs its entry script.
    #[test]
    fn qwen_code_running_is_its_entry() {
        let Some(i) = pinned("qwen-code", "npm", "qwen_code_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let argv = argv_of(&i);
        running_classifies(
            "qwen-code",
            &home,
            &os_strs(&argv),
            &[("node", "qwen-code", MatchBasis::Asserted)],
        );
    }

    /// Cursor CLI, in the layout its installer makes (https://cursor.com/
    /// install): `~/.local/share/cursor-agent/versions/<version>/` holding its
    /// own node, its `cursor-agent` script and its index.js. M2-04's cache
    /// keeps the package as downloaded, so the test lays the version out in
    /// the home: the script and node copied (the kernel names a process after
    /// the file it runs, not a link to it), the rest linked. The script runs
    /// node on index.js, `argv[0]` set to the script's path; node is Cursor by
    /// its script, asserted: the node it ships runs any script, so it is no
    /// identity (it roots no grant above a session, and lies in no install
    /// tree).
    #[test]
    fn cursor_cli_running_is_its_entry() {
        let Some(i) = pinned("cursor-cli", "native", "cursor_cli_running_is_its_entry") else {
            return;
        };
        let home = TestHome::new();
        let version = home
            .home()
            .join(".local/share/cursor-agent/versions")
            .join(&i.pin.version);
        std::fs::create_dir_all(&version).unwrap();
        for entry in std::fs::read_dir(&i.dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let to = version.join(&name);
            if name == "cursor-agent" || name == "node" {
                std::fs::copy(entry.path(), &to).unwrap();
            } else {
                std::os::unix::fs::symlink(entry.path(), &to).unwrap();
            }
        }
        let node = version.join("node");
        assert!(
            !AgentCatalog::builtin().within_install_tree("cursor", &node, Some(&home.home())),
            "{node:?}"
        );
        let script = version.join("cursor-agent");
        running_classifies(
            "cursor-cli",
            &home,
            &[script.as_os_str()],
            &[("node", "cursor", MatchBasis::Asserted)],
        );
    }

    /// Gate 23 at the daemon, with no host installed: the test fixture
    /// agent's shell runs [`ProofTarget::attempts_on_own_pty`], the shape
    /// of a command `node-pty` or `tty: true` starts. The daemon refuses
    /// both proofs as an agent's; a person's terminal then gives them.
    /// Mutation checked (run outside any agent's tree): removing the
    /// fixture agent's executable pattern fails this test (the proofs are
    /// taken).
    #[test]
    fn a_proof_from_an_agents_own_pty_is_refused_by_the_daemon() {
        let mut target = ProofTarget::new();
        let line = target.attempts_on_own_pty();
        let repo = target.repo.clone();
        let out = target.h.agent_line(&repo, &line);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        target.assert_refused_then_taken("fixture");
    }

    /// The catalog's `code_selecting_env` against the pinned builds (M2-10
    /// review): for every entry with an executable identity (an install
    /// tree or a signature, what a standing approval could name), its
    /// pinned native executable is run with each variable known to make a
    /// Bun or Node executable run a file it is given (`BUN_OPTIONS
    /// =--preload=`, `BUN_BE_BUN=1` with the file as its argument,
    /// `NODE_OPTIONS=--require=`), the file writing a marker. The variables
    /// whose marker appears are the entry's `code_selecting_env`, no more
    /// and no fewer, on each system. Mutation checked: removing
    /// `BUN_OPTIONS` from Claude Code's entry, or adding `NODE_OPTIONS` to
    /// Copilot CLI's, fails this test.
    #[test]
    fn code_selecting_env_is_measured() {
        let cat = AgentCatalog::builtin();
        let home = TestHome::new();
        let pinned_exe = |id: &str, variant: &str| -> Option<PathBuf> {
            let i = pinned(id, variant, "code_selecting_env_is_measured")?;
            Some(match &i.pin.starts {
                Some((path, _)) => i.dir.join(path),
                None => i.exe.clone(),
            })
        };
        let entries = [
            ("claude-code", "native"),
            ("codex", "native"),
            ("opencode", "native"),
            ("copilot-cli", "npm"),
        ];
        // Every entry an identity could name is measured here.
        let src = AgentCatalog::builtin_source();
        for id in cat.ids() {
            let identity = entry_has(src, id, "install_trees") || entry_has(src, id, "signatures");
            assert_eq!(
                identity,
                entries.iter().any(|(e, _)| *e == id),
                "{id}: an entry with an install tree or a signature is measured here"
            );
        }
        let marker_dir = home.root().join("m");
        std::fs::create_dir_all(&marker_dir).unwrap();
        for (id, variant) in entries {
            let Some(exe) = pinned_exe(id, variant) else {
                return;
            };
            let mut ran = Vec::new();
            for var in ["BUN_OPTIONS", "BUN_BE_BUN", "NODE_OPTIONS"] {
                let marker = marker_dir.join(format!("{id}-{var}"));
                let file = marker_dir.join(format!("{id}-{var}.js"));
                std::fs::write(
                    &file,
                    format!(
                        "require(\"fs\").writeFileSync({}, \"ran\");\n",
                        json!(marker.to_string_lossy())
                    ),
                )
                .unwrap();
                let mut cmd = Command::new(&exe);
                cmd.env_clear()
                    .envs(home.vars())
                    .env("DISABLE_AUTOUPDATER", "1")
                    .env("COPILOT_AUTO_UPDATE", "false")
                    .current_dir(home.home())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                    cmd.env(k, "http://127.0.0.1:9");
                }
                match var {
                    "BUN_OPTIONS" => {
                        cmd.env(var, format!("--preload={}", file.display()))
                            .arg("--version");
                    }
                    "BUN_BE_BUN" => {
                        cmd.env(var, "1").arg(&file);
                    }
                    _ => {
                        cmd.env(var, format!("--require={}", file.display()))
                            .arg("--version");
                    }
                }
                let mut child = GroupChild::spawn(&mut cmd).unwrap();
                let _ = child.end_within(Duration::from_secs(30));
                if marker.exists() {
                    ran.push(var);
                }
            }
            let want: Vec<&str> = cat
                .code_selecting_env(id)
                .iter()
                .map(String::as_str)
                .collect();
            println!(
                "measurement: catalog code_selecting_env os={} {id}: {ran:?}",
                os()
            );
            assert_eq!(ran, want, "{id} ({})", exe.display());
        }
    }

    /// Whether `id`'s `[[agent]]` table in the catalog text `src` sets
    /// `key`.
    fn entry_has(src: &str, id: &str, key: &str) -> bool {
        src.split("[[agent]]")
            .find(|t| t.contains(&format!("\nid = \"{id}\"\n")))
            .is_some_and(|t| t.lines().any(|l| l.starts_with(&format!("{key} ="))))
    }
}
