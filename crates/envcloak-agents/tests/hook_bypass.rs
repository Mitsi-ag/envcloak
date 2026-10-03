//! The hook handler against what agents write (M2 plan M2-08; lessons L-02,
//! L-06, L-15):
//!
//! - the payloads the pinned Claude Code and Codex sent their hooks
//!   (captured by M2-04 in crates/envcloak-e2e/tests/fixtures/
//!   hook-payloads/), loaded as bytes and changed only where a test puts a
//!   command or a prompt;
//! - a bypass corpus of ways to read an env file, print the environment or
//!   run `envcloak reveal` and `approve` (quoting, escapes, `${IFS}`, split
//!   words, wrappers such as `command env` and `busybox env`, here-documents,
//!   substitutions, globs): the commands the hook lets through must be
//!   exactly the ones docs/INSTALLERS.md lists in "What the hook does not
//!   see", an honesty table;
//! - hostile and fuzzed input: no panic, a bounded time, the same answer
//!   twice, and no answer that holds the payload's text.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use envcloak_agents::hook::shell::{Class, check_script};
use envcloak_agents::hook::{
    Answer, Decision, Event, Host, MAX_PAYLOAD, Reason, answer, decide, decide_argv,
};
use envcloak_core::SecretBuf;
use proptest::prelude::*;
use serde_json::{Value, json};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn buf(bytes: &[u8]) -> SecretBuf {
    let mut b = SecretBuf::with_capacity(bytes.len());
    b.extend(bytes).unwrap();
    b
}

/// A captured payload of the pinned `host` for `event`.
fn captured(host: Host, event: &str) -> Value {
    let dir = match host {
        Host::ClaudeCode => "claude-code-2.1.280",
        Host::Codex => "codex-0.159.2",
    };
    let p = repo()
        .join("crates/envcloak-e2e/tests/fixtures/hook-payloads")
        .join(dir)
        .join(format!("{event}.json"));
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

fn with_command(host: Host, command: &str) -> Vec<u8> {
    let mut p = captured(host, "PreToolUse");
    p["tool_input"]["command"] = Value::from(command);
    serde_json::to_vec(&p).unwrap()
}

fn with_prompt(host: Host, prompt: &str) -> Vec<u8> {
    let mut p = captured(host, "UserPromptSubmit");
    p["prompt"] = Value::from(prompt);
    serde_json::to_vec(&p).unwrap()
}

/// A key-shaped token made at run time (never a literal in the tree).
fn token(seed: u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut x = seed | 1;
    (0..40)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(ALPHABET[usize::try_from(x % 57).unwrap()])
        })
        .collect()
}

#[test]
fn the_captured_payloads_are_read_and_decided() {
    for host in [Host::ClaudeCode, Host::Codex] {
        // As captured: `echo hook-check` and a benign prompt.
        for (event, e) in [
            ("PreToolUse", Event::PreToolUse),
            ("UserPromptSubmit", Event::UserPromptSubmit),
        ] {
            let raw = serde_json::to_vec(&captured(host, event)).unwrap();
            assert_eq!(
                decide(host, e, &buf(&raw)),
                Decision::Allow,
                "{host:?} {event}"
            );
            // The other host's handler gets no decision from it.
            let other = if host == Host::Codex {
                Host::ClaudeCode
            } else {
                Host::Codex
            };
            assert_eq!(
                decide(other, e, &buf(&raw)),
                Decision::NoDecision,
                "{host:?} {event} to {other:?}"
            );
        }
        assert_eq!(
            decide(
                host,
                Event::PreToolUse,
                &buf(&with_command(host, "printenv"))
            ),
            Decision::Deny(Reason::EnvDump)
        );
        assert_eq!(
            decide(
                host,
                Event::PreToolUse,
                &buf(&with_command(host, "cat .env.local"))
            ),
            Decision::Deny(Reason::EnvFile)
        );
        let key = token(42);
        assert_eq!(
            decide(
                host,
                Event::UserPromptSubmit,
                &buf(&with_prompt(host, &format!("here: {key}")))
            ),
            Decision::Deny(Reason::KeyInPrompt)
        );
        // A key split across two pastes, neither part key-shaped alone,
        // is read whole.
        let (a, b) = key.split_at(20);
        for part in [a, b] {
            assert_eq!(
                decide(
                    host,
                    Event::UserPromptSubmit,
                    &buf(&with_prompt(host, part))
                ),
                Decision::Allow
            );
        }
        let pasted = format!(
            "use this\n<pasted_content id=\"1\">\n{a}\n</pasted_content id=\"1\">\n\
             <pasted_content id=\"2\">\n{b}\n</pasted_content id=\"2\">"
        );
        assert_eq!(
            decide(
                host,
                Event::UserPromptSubmit,
                &buf(&with_prompt(host, &pasted))
            ),
            Decision::Deny(Reason::KeyInPrompt)
        );
    }
}

/// No answer holds what the payload held: the prompt's key, a command's
/// words.
#[test]
fn answers_never_echo_the_payload() {
    let key = token(7);
    for host in [Host::ClaudeCode, Host::Codex] {
        let cases = [
            (
                Event::UserPromptSubmit,
                with_prompt(host, &format!("x {key} y")),
            ),
            (
                Event::PreToolUse,
                with_command(host, &format!("cat .env # {key}")),
            ),
        ];
        for (event, payload) in cases {
            let d = decide(host, event, &buf(&payload));
            assert!(matches!(d, Decision::Deny(_)), "{d:?}");
            let Answer { stdout, stderr, .. } = answer(host, event, d);
            for out in [&stdout, &stderr] {
                let text = String::from_utf8_lossy(out);
                assert!(!text.contains(&key), "{text}");
                assert!(!text.contains(&key[..16]), "{text}");
            }
        }
    }
}

/// Every way past the hook the corpus tries, and what the hook makes of
/// it: a class it stops, or `None` for a command it lets through.
const CORPUS: &[(&str, Option<Class>)] = &[
    // Quoting and escapes.
    ("ca\"t\" .env", Some(Class::EnvFile)),
    ("'cat' '.env'", Some(Class::EnvFile)),
    ("cat '.e'nv", Some(Class::EnvFile)),
    ("c\\at .env", Some(Class::EnvFile)),
    ("cat \\.env", Some(Class::EnvFile)),
    ("$'\\x63\\x61\\x74' .env", Some(Class::EnvFile)),
    ("cat $'\\056env'", Some(Class::EnvFile)),
    // ${IFS}, brace expansion and split words.
    ("cat${IFS}.env", Some(Class::Ambiguous)),
    ("{cat,.env}", Some(Class::EnvFile)),
    ("ca\\\nt .env", Some(Class::EnvFile)),
    ("pr\"\"intenv", Some(Class::EnvDump)),
    // Wrappers.
    ("command env", Some(Class::EnvDump)),
    ("busybox env", Some(Class::EnvDump)),
    ("exec env", Some(Class::EnvDump)),
    ("nohup env", Some(Class::EnvDump)),
    ("/usr/bin/env", Some(Class::EnvDump)),
    ("\\env", Some(Class::EnvDump)),
    ("sudo -E env", Some(Class::EnvDump)),
    ("timeout 1 env", Some(Class::EnvDump)),
    ("env -i", Some(Class::EnvDump)),
    ("env -S 'printenv'", Some(Class::EnvDump)),
    ("watch -n 1 printenv", Some(Class::EnvDump)),
    ("nice -n 5 cat .env", Some(Class::EnvFile)),
    ("xargs -a .env echo", Some(Class::EnvFile)),
    ("dd if=.env", Some(Class::EnvFile)),
    // Here-documents and here-strings.
    ("bash <<'X'\nprintenv\nX", Some(Class::EnvDump)),
    ("cat <<X\n$(printenv)\nX", Some(Class::EnvDump)),
    ("sh <<< printenv", Some(Class::EnvDump)),
    // Subshells and substitutions.
    ("(printenv)", Some(Class::EnvDump)),
    ("echo $(printenv)", Some(Class::EnvDump)),
    ("echo `printenv`", Some(Class::EnvDump)),
    ("x=$(cat .env)", Some(Class::EnvFile)),
    ("diff <(cat .env) /dev/null", Some(Class::EnvFile)),
    ("echo $(< .env)", Some(Class::EnvFile)),
    // eval and shells.
    ("eval printenv", Some(Class::EnvDump)),
    ("eval \"cat .env\"", Some(Class::EnvFile)),
    ("sh -c 'printenv'", Some(Class::EnvDump)),
    ("bash -lc \"cat .env\"", Some(Class::EnvFile)),
    ("zsh -c printenv", Some(Class::EnvDump)),
    // Globs.
    ("cat .en*", Some(Class::EnvFile)),
    ("cat ./.e?v", Some(Class::EnvFile)),
    ("cat .[e]nv", Some(Class::EnvFile)),
    ("head -n 3 */.env.local", Some(Class::EnvFile)),
    // Redirections.
    ("cat < .env", Some(Class::EnvFile)),
    ("read -r x < .env", Some(Class::EnvFile)),
    (
        "while read l; do echo \"$l\"; done < .env",
        Some(Class::EnvFile),
    ),
    // find -exec.
    ("find . -name '.env*' -exec cat {} +", Some(Class::EnvFile)),
    // A process's environment.
    ("cat /proc/self/environ", Some(Class::EnvDump)),
    ("cat /proc/$$/environ", Some(Class::EnvDump)),
    ("ps eww $$", Some(Class::EnvDump)),
    ("export -p", Some(Class::EnvDump)),
    ("declare -x", Some(Class::EnvDump)),
    ("set", Some(Class::EnvDump)),
    ("typeset -x", Some(Class::EnvDump)),
    // envcloak reveal and approve.
    ("command envcloak approve REQUEST", Some(Class::Approve)),
    (
        "sh -c 'envcloak reveal openai/project'",
        Some(Class::Reveal),
    ),
    ("f() { envcloak approve REQUEST; }; f", Some(Class::Approve)),
    // A command named by a variable.
    ("$c .env", Some(Class::Ambiguous)),
    // Case: macOS's file system opens `.ENV` as `.env` and finds `CAT`
    // as `cat` by default, so names are read in one case.
    ("cat .ENV", Some(Class::EnvFile)),
    ("CAT .env", Some(Class::EnvFile)),
    ("PrintEnv", Some(Class::EnvDump)),
    ("source .Env.Local", Some(Class::EnvFile)),
    // More programs that run a command.
    ("script -q /dev/null printenv", Some(Class::EnvDump)),
    ("script -c printenv /dev/null", Some(Class::EnvDump)),
    ("strace -f printenv", Some(Class::EnvDump)),
    ("ltrace -o log cat .env", Some(Class::EnvFile)),
    ("flock /tmp/l printenv", Some(Class::EnvDump)),
    ("flock -w 5 /tmp/l -c 'cat .env'", Some(Class::EnvFile)),
    ("npx printenv", Some(Class::EnvDump)),
    ("npm exec -- printenv", Some(Class::EnvDump)),
    ("npx -c 'cat .env'", Some(Class::EnvFile)),
    ("uv run printenv", Some(Class::EnvDump)),
    ("uv run --with httpx printenv", Some(Class::EnvDump)),
    ("poetry run cat .env", Some(Class::EnvFile)),
    ("direnv exec . printenv", Some(Class::EnvDump)),
    ("mise exec -- printenv", Some(Class::EnvDump)),
    ("bundle exec printenv", Some(Class::EnvDump)),
    ("arch -arm64 printenv", Some(Class::EnvDump)),
    ("taskset 0x1 printenv", Some(Class::EnvDump)),
    ("chronic printenv", Some(Class::EnvDump)),
    // EnvCloak's own wrapper, whose command has the project's keys in its
    // environment (the verifier's finding).
    ("envcloak run -- printenv", Some(Class::EnvDump)),
    ("envcloak run --profile dev -- env", Some(Class::EnvDump)),
    (
        "envcloak run --ref A=openai/x -- cat .env",
        Some(Class::EnvFile),
    ),
    ("envcloak run -- sh -c 'export -p'", Some(Class::EnvDump)),
    ("envcloak run $SEP printenv", Some(Class::Ambiguous)),
    ("envcloak run -- sh -c 'echo $OPENAI_API_KEY'", None),
    // Options whose value picks the files a search reads (Codex review:
    // they were skipped as ordinary values), in every form.
    ("rg -g '.env*' KEY", Some(Class::EnvFile)),
    ("rg --glob=.env KEY .", Some(Class::EnvFile)),
    ("rg --glob=.env* KEY", Some(Class::EnvFile)),
    ("rg -g.env.local KEY", Some(Class::EnvFile)),
    ("rg --iglob '[.]E[N]V' KEY", Some(Class::EnvFile)),
    ("rg -t sh KEY", Some(Class::EnvFile)),
    ("rg --type=all KEY", Some(Class::EnvFile)),
    ("rg -tsh KEY", Some(Class::EnvFile)),
    ("rg --type-add 'x:.env*' -t x KEY", Some(Class::EnvFile)),
    ("grep -r --include=.env KEY .", Some(Class::EnvFile)),
    ("grep -r --include '*.env' KEY .", Some(Class::EnvFile)),
    ("ag -G '[.]env' KEY", Some(Class::EnvFile)),
    ("rg -g '!.env*' -g '*.rs' KEY", None),
    // find's wildcards and classes match a leading `.`.
    ("find . -name '[.]env' -exec cat {} +", Some(Class::EnvFile)),
    ("find . -name '*env' -exec cat {} \\;", Some(Class::EnvFile)),
    (
        "find . -regex '.*/[.]e[n]v' -exec cat {} +",
        Some(Class::EnvFile),
    ),
    ("find . -regex '.*\\.e.v' -exec cat {} +", None),
    // What the hook lets through (docs/INSTALLERS.md, "What the hook does
    // not see").
    ("f=.env; cat \"$f\"", None),
    ("for f in .env*; do cat \"$f\"; done", None),
    ("cat $(echo .env)", None),
    ("echo $OPENAI_API_KEY", None),
    ("ls -a | grep '^.env' | xargs cat", None),
    ("python3 -c 'print(open(\".env\").read())'", None),
    ("node -e 'console.log(process.env)'", None),
    ("bash script.sh", None),
    ("printf 'cat .env' | sh", None),
    ("cp .env notes.txt && cat notes.txt", None),
    ("ln -s .env x && cat x", None),
    ("git show HEAD:.env", None),
    ("iconv -f utf-8 -t utf-8 .env", None),
    ("grep -r KEY .", None),
    ("shopt -s dotglob; cat *", None),
    ("e", None),
    ("cd /proc/self && cat environ", None),
    ("dbus-run-session printenv", None),
    ("parallel ::: printenv", None),
];

/// The examples in docs/INSTALLERS.md's "What the hook does not see".
fn documented_misses() -> Vec<String> {
    let doc = std::fs::read_to_string(repo().join("docs/INSTALLERS.md")).unwrap();
    let start = doc.find("<!-- hook-misses:begin -->").unwrap();
    let end = doc.find("<!-- /hook-misses -->").unwrap();
    let mut out = Vec::new();
    for line in doc[start..end].lines().filter(|l| l.starts_with("| ")) {
        let cells: Vec<&str> = line.split(" | ").collect();
        let Some(example) = cells.get(1) else {
            continue;
        };
        let mut rest = *example;
        while let Some(a) = rest.find('`') {
            let Some(b) = rest[a + 1..].find('`') else {
                break;
            };
            out.push(rest[a + 1..a + 1 + b].replace("\\|", "|"));
            rest = &rest[a + 1 + b + 1..];
        }
    }
    out
}

#[test]
fn the_corpus_misses_exactly_what_the_honesty_table_lists() {
    for (cmd, want) in CORPUS {
        assert_eq!(check_script(cmd), *want, "{cmd:?}");
    }
    let mut missed: Vec<String> = CORPUS
        .iter()
        .filter(|(_, c)| c.is_none())
        .map(|(cmd, _)| (*cmd).to_owned())
        .collect();
    let mut listed = documented_misses();
    missed.sort();
    listed.sort();
    assert_eq!(
        missed, listed,
        "the commands the hook lets through are not the ones docs/INSTALLERS.md lists"
    );
}

/// The Codex review's finding: here-documents are matched to their
/// commands once each, so a payload of many is read in one pass, well
/// within the hook's 2 seconds, and decided.
///
/// Mutation checked: `classify_all` filtering every body for every
/// command again (the previous `self.bodies.iter().filter(...)`): this
/// takes far longer than 2 seconds and fails.
#[test]
fn many_here_documents_are_read_in_one_pass() {
    for host in [Host::ClaudeCode, Host::Codex] {
        let unit = "cat <<A\nx\nA\n";
        // Each unit takes 16 bytes as JSON (its line breaks escaped).
        let cmd = unit.repeat((MAX_PAYLOAD - 8192) / 16);
        let payload = with_command(host, &cmd);
        assert!(payload.len() <= MAX_PAYLOAD, "{}", payload.len());
        let t = Instant::now();
        let d = decide(host, Event::PreToolUse, &buf(&payload));
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "{host:?}: {:?}",
            t.elapsed()
        );
        assert_eq!(d, Decision::Allow, "{host:?}");
    }
}

/// Claude Code 2.1.280's `Monitor` reaches the hook as a `PreToolUse` of
/// the captured shape, its `command` a shell script: it gets the shell
/// command's decision.
#[test]
fn monitor_gets_the_shell_commands_decision() {
    let mut p = captured(Host::ClaudeCode, "PreToolUse");
    p["tool_name"] = json!("Monitor");
    for (command, want) in [
        ("printenv", Decision::Deny(Reason::EnvDump)),
        ("tail -f .env.local", Decision::Deny(Reason::EnvFile)),
        ("tail -f app.log", Decision::Allow),
    ] {
        p["tool_input"] = json!({"description": "watch", "timeout_ms": 60000, "command": command});
        let raw = serde_json::to_vec(&p).unwrap();
        assert_eq!(
            decide(Host::ClaudeCode, Event::PreToolUse, &buf(&raw)),
            want,
            "{command}"
        );
    }
}

#[test]
fn run_with_secrets_argv_gets_the_hooks_decision() {
    assert_eq!(decide_argv(&["printenv"]), Decision::Deny(Reason::EnvDump));
    assert_eq!(
        decide_argv(&["cat", ".env"]),
        Decision::Deny(Reason::EnvFile)
    );
    assert_eq!(
        decide_argv(&["sh", "-c", "envcloak approve X"]),
        Decision::Deny(Reason::Approve)
    );
    assert_eq!(decide_argv(&["npm", "test"]), Decision::Allow);
}

#[test]
fn hostile_payloads_get_no_decision_or_a_refusal_and_are_quick() {
    let host = Host::ClaudeCode;
    for bad in [
        &b""[..],
        b"\xff\xfe\xfd",
        b"[]",
        b"null",
        b"{\"hook_event_name\": \"PreToolUse\"}",
        b"{\"hook_event_name\": 3}",
        b"\x00\x01\x02",
        b"{\"a\": \"\\ud800\"}",
    ] {
        for e in [
            Event::PreToolUse,
            Event::UserPromptSubmit,
            Event::SessionStart,
        ] {
            assert_eq!(decide(host, e, &buf(bad)), Decision::NoDecision, "{bad:?}");
        }
    }
    // Over the cap: refused, unread.
    let mut big = SecretBuf::with_capacity(MAX_PAYLOAD + 1);
    big.extend(&vec![b' '; MAX_PAYLOAD + 1]).unwrap();
    assert_eq!(
        decide(host, Event::PreToolUse, &big),
        Decision::Deny(Reason::Unchecked)
    );
    // A command of the whole cap, of each kind of byte the reader treats
    // specially: answered within 2 seconds.
    for unit in [
        "$(",
        "'",
        "\"",
        "`",
        "{a,b}",
        "{",
        "{1..2}",
        "\\",
        "<<X\n",
        "a",
        ";",
        "$x",
        "${",
        "${x:-\"",
        "$((",
        "$\"",
        "\"$(",
        "a=(",
        "[[ ",
        "( ",
        "{ ",
        "case x in x) ",
        "<(",
        "|",
        "command ",
        "env ",
        "sudo ",
        "eval ",
        "sh -c ",
        "f() ",
        "for x in ",
    ] {
        let mut cmd = String::new();
        while cmd.len() + unit.len() < MAX_PAYLOAD - 1024 {
            cmd.push_str(unit);
        }
        let payload = with_command(host, &cmd);
        let t = Instant::now();
        let d = decide(host, Event::PreToolUse, &buf(&payload));
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "{unit:?}: {:?}",
            t.elapsed()
        );
        assert!(
            matches!(d, Decision::Allow | Decision::Deny(_)),
            "{unit:?}: {d:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any text: no panic, and the same answer twice (a hook fired twice
    /// agrees with itself).
    #[test]
    fn any_command_text_gets_one_answer(s in "[ -~\\n\\t]{0,200}") {
        let a = check_script(&s);
        prop_assert_eq!(a, check_script(&s));
    }

    /// Text made of the shell's own characters, where the reader's rules
    /// meet.
    #[test]
    fn shell_shaped_text_never_panics(parts in proptest::collection::vec(
        prop_oneof![
            Just("$("), Just(")"), Just("`"), Just("'"), Just("\""), Just("\\"),
            Just("{"), Just("}"), Just(","), Just("<<"), Just("<"), Just(">"),
            Just("|"), Just("&"), Just(";"), Just("\n"), Just(" "), Just("cat"),
            Just(".env"), Just("env"), Just("printenv"), Just("eval"), Just("sh -c"),
            Just("EOF"), Just("$x"), Just("${"), Just("*"), Just("["), Just("]"),
            Just("case"), Just("in"), Just("esac"), Just("(("), Just("for"), Just("do"),
            Just("done"), Just("[["), Just("]]"), Just("function"), Just("=")
        ],
        0..60,
    )) {
        let s: String = parts.concat();
        let a = check_script(&s);
        prop_assert_eq!(a, check_script(&s));
    }

    /// Any payload bytes: no panic, the same decision twice.
    #[test]
    fn any_payload_bytes_get_one_decision(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        for host in [Host::ClaudeCode, Host::Codex] {
            for e in [Event::PreToolUse, Event::UserPromptSubmit, Event::SessionStart] {
                let a = decide(host, e, &buf(&bytes));
                prop_assert_eq!(a, decide(host, e, &buf(&bytes)));
            }
        }
    }

    /// Any command in a real payload: one decision, the same twice.
    #[test]
    fn any_command_in_a_captured_payload(s in "\\PC{0,120}") {
        for host in [Host::ClaudeCode, Host::Codex] {
            let p = with_command(host, &s);
            let a = decide(host, Event::PreToolUse, &buf(&p));
            prop_assert!(!matches!(a, Decision::NoDecision));
            prop_assert_eq!(a, decide(host, Event::PreToolUse, &buf(&p)));
        }
    }
}

#[test]
fn a_json_tool_input_of_every_shape_is_walked() {
    let mut p = captured(Host::ClaudeCode, "PreToolUse");
    p["tool_name"] = json!("mcp__fs__read");
    p["tool_input"] = json!({"a": [1, {"b": [null, true, "/w/.env.production"]}]});
    let raw = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        decide(Host::ClaudeCode, Event::PreToolUse, &buf(&raw)),
        Decision::Deny(Reason::EnvFile)
    );
    p["tool_input"] = json!({"query": "how do .env files work"});
    let raw = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        decide(Host::ClaudeCode, Event::PreToolUse, &buf(&raw)),
        Decision::Allow
    );
}
