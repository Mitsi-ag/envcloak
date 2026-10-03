//! EnvCloak's hook handler (SPEC §7, §7.2 rule 3; M2 plan M2-08, D-12):
//! what `envcloak hook --host <id> --event <name>` decides for a host's
//! prompt and tool-call hooks, and the same check `run_with_secrets`
//! applies to its argv (D-22).
//!
//! Decisions are pure functions of the payload ([`decide`]): a pasted key
//! is found by registry patterns and key shape ([`prompt`]), a command by
//! what it runs ([`shell`]), a file by its name. Nothing is compared with
//! the vault and nothing is sent anywhere, so the same payload always
//! gets the same answer, however often a host fires the hook. Every
//! denial carries EnvCloak's fixed marker, `[envcloak:<reason>]`, and says
//! what to do instead; none echoes what it matched. Hooks prevent
//! accidents; enforcement is the proof, the grants and the manifest
//! (SPEC §7.2 rule 4, T-14).
//!
//! A payload that is not the one `--host` and `--event` name (the wrong
//! event, a field of the wrong type, another host's shape, JSON that does
//! not parse) gets no decision ([`Decision::NoDecision`]): the handler
//! says so on standard error and exits 1, which both hosts read as a
//! hook error that blocks nothing (Map C §3 item 1: a Claude-format hook
//! another host imports must not answer in a shape that host misreads).

pub mod claude;
pub mod codex;
mod payload;
pub mod prompt;
pub mod shell;

use envcloak_core::SecretBuf;
use serde_json::{Map, Value};

use payload::Parsed;

use shell::Class;

/// The hosts the handler answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Host {
    ClaudeCode,
    Codex,
}

impl Host {
    /// The catalog id `--host` takes.
    pub fn id(self) -> &'static str {
        match self {
            Host::ClaudeCode => "claude-code",
            Host::Codex => "codex",
        }
    }

    pub fn from_id(id: &str) -> Option<Host> {
        match id {
            "claude-code" => Some(Host::ClaudeCode),
            "codex" => Some(Host::Codex),
            _ => None,
        }
    }
}

/// The hook events the handler answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    UserPromptSubmit,
    PreToolUse,
    SessionStart,
}

impl Event {
    /// The event's name, as the hosts write it.
    pub fn name(self) -> &'static str {
        match self {
            Event::UserPromptSubmit => "UserPromptSubmit",
            Event::PreToolUse => "PreToolUse",
            Event::SessionStart => "SessionStart",
        }
    }

    pub fn from_name(name: &str) -> Option<Event> {
        match name {
            "UserPromptSubmit" => Some(Event::UserPromptSubmit),
            "PreToolUse" => Some(Event::PreToolUse),
            "SessionStart" => Some(Event::SessionStart),
            _ => None,
        }
    }
}

/// Why the handler stopped a prompt or a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The prompt holds something shaped like a key.
    KeyInPrompt,
    /// The tool call reads an env file.
    EnvFile,
    /// The tool call prints the environment.
    EnvDump,
    /// `envcloak reveal` from an agent.
    Reveal,
    /// `envcloak approve` from an agent.
    Approve,
    /// What the command reads or runs could not be told.
    Ambiguous,
    /// The payload was larger than the handler reads, or did not arrive in
    /// time, so it was not checked.
    Unchecked,
}

impl Reason {
    /// Every reason, for the tests.
    pub const ALL: [Reason; 7] = [
        Reason::KeyInPrompt,
        Reason::EnvFile,
        Reason::EnvDump,
        Reason::Reveal,
        Reason::Approve,
        Reason::Ambiguous,
        Reason::Unchecked,
    ];

    /// The name in the marker, `[envcloak:<name>]`.
    pub fn name(self) -> &'static str {
        match self {
            Reason::KeyInPrompt => "key_in_prompt",
            Reason::EnvFile => "env_file",
            Reason::EnvDump => "env_dump",
            Reason::Reveal => "reveal",
            Reason::Approve => "approve",
            Reason::Ambiguous => "ambiguous",
            Reason::Unchecked => "unchecked",
        }
    }

    /// The fixed message: the marker, what was stopped, what to do
    /// instead, and that the hook is accident prevention. Never anything
    /// from the payload.
    pub fn message(self) -> &'static str {
        match self {
            Reason::KeyInPrompt => {
                "[envcloak:key_in_prompt] EnvCloak stopped this prompt before it reached the \
                 model: it holds something shaped like a key or token, which is not shown here. \
                 To give an agent a key, add it to EnvCloak in your own terminal with `envcloak \
                 add <provider>`; commands then get it through `envcloak run`. If it was a real \
                 key, rotate it: the prompt text may still be in this host's local history."
            }
            Reason::EnvFile => {
                "[envcloak:env_file] EnvCloak's hook stopped this: it reads a .env file, whose \
                 values would reach the model. Run the command that needs them as `envcloak run \
                 -- <command>`, and use `envcloak ls` to see which keys exist (names only). This \
                 hook prevents accidents; it is not a security boundary."
            }
            Reason::EnvDump => {
                "[envcloak:env_dump] EnvCloak's hook stopped this: it prints environment \
                 variables, which can hold keys. Run a command that needs a key as `envcloak run \
                 -- <command>`, and use `envcloak ls` to see which keys exist (names only). This \
                 hook prevents accidents; it is not a security boundary."
            }
            Reason::Reveal => {
                "[envcloak:reveal] EnvCloak's hook stopped this: `envcloak reveal` shows a value \
                 only to the person, in their own terminal, and an agent's request is refused. \
                 Run the command that needs the key as `envcloak run -- <command>`. This hook \
                 prevents accidents; it is not a security boundary."
            }
            Reason::Approve => {
                "[envcloak:approve] EnvCloak's hook stopped this: approvals come from the person, \
                 in a terminal of their own, and one from an agent's session is refused. Ask \
                 them to run `envcloak pending` and approve the request there. This hook \
                 prevents accidents; it is not a security boundary."
            }
            Reason::Ambiguous => {
                "[envcloak:ambiguous] EnvCloak's hook stopped this: it could not tell what the \
                 command reads or runs (an unfinished quote or substitution, a command named by \
                 a variable, or text run by eval or sh -c that it cannot see). Write the command \
                 out plainly; if it needs keys, run it as `envcloak run -- <command>`. This hook \
                 prevents accidents; it is not a security boundary."
            }
            Reason::Unchecked => {
                "[envcloak:unchecked] EnvCloak's hook stopped this: the request was larger than \
                 the hook reads (2 MiB) or did not arrive within its 2 second limit, so it could \
                 not be checked. This hook prevents accidents; it is not a security boundary."
            }
        }
    }

    fn of(class: Class) -> Reason {
        match class {
            Class::EnvFile => Reason::EnvFile,
            Class::EnvDump => Reason::EnvDump,
            Class::Reveal => Reason::Reveal,
            Class::Approve => Reason::Approve,
            Class::Ambiguous => Reason::Ambiguous,
        }
    }
}

/// What the handler answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Let it through: no output.
    Allow,
    /// Stop it, with this reason.
    Deny(Reason),
    /// The payload is not the one the hook was set up for.
    NoDecision,
}

/// The most bytes of a payload the handler reads (2 MiB). A larger one is
/// [`Reason::Unchecked`].
pub const MAX_PAYLOAD: usize = 2 * 1024 * 1024;

/// What the handler decides for `payload` from `host`'s `event`: a pure
/// function of the bytes. `SessionStart` decides nothing (its context is
/// added by the command, [`session_context`]).
pub fn decide(host: Host, event: Event, payload: &SecretBuf) -> Decision {
    let p = match payload::parse(host, event, payload) {
        Parsed::TooLarge => return Decision::Deny(Reason::Unchecked),
        Parsed::Unfit => return Decision::NoDecision,
        Parsed::Fits(p) => p,
    };
    match event {
        Event::SessionStart => Decision::Allow,
        Event::UserPromptSubmit => match p.get("prompt").and_then(Value::as_str) {
            Some(text) if prompt::holds_key(text) => Decision::Deny(Reason::KeyInPrompt),
            Some(_) => Decision::Allow,
            None => Decision::NoDecision,
        },
        Event::PreToolUse => {
            let (Some(tool), Some(Value::Object(input))) = (
                p.get("tool_name").and_then(Value::as_str),
                p.get("tool_input"),
            ) else {
                return Decision::NoDecision;
            };
            tool_call(host, tool, input)
        }
    }
}

/// The decision for one tool call.
fn tool_call(host: Host, tool: &str, input: &Map<String, Value>) -> Decision {
    let deny_if = |c: Option<Class>| c.map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)));
    match tool {
        "Bash" => match input.get("command").and_then(Value::as_str) {
            Some(cmd) => deny_if(shell::check_script(cmd)),
            None => Decision::NoDecision,
        },
        "Read" | "Edit" | "Write" | "NotebookEdit" if host == Host::ClaudeCode => {
            match input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
                .and_then(Value::as_str)
            {
                Some(path) if tool != "Write" && names_env_file(path) => {
                    Decision::Deny(Reason::EnvFile)
                }
                Some(_) => Decision::Allow,
                None => Decision::NoDecision,
            }
        }
        "Grep" if host == Host::ClaudeCode => {
            let path = input.get("path").and_then(Value::as_str);
            let glob = input.get("glob").and_then(Value::as_str);
            if path.is_some_and(names_env_file) || glob.is_some_and(glob_matches_env_file) {
                Decision::Deny(Reason::EnvFile)
            } else {
                Decision::Allow
            }
        }
        "mcp__envcloak__run_with_secrets" => match input.get("argv") {
            Some(Value::Array(argv)) => {
                let words: Option<Vec<&str>> = argv.iter().map(Value::as_str).collect();
                match words {
                    Some(w) => decide_argv(&w),
                    // The server refuses an argv that is not strings.
                    None => Decision::Allow,
                }
            }
            _ => Decision::Allow,
        },
        t if t.starts_with("mcp__") => {
            if strings_name_env_file(&Value::Object(input.clone()), 0) {
                Decision::Deny(Reason::EnvFile)
            } else {
                Decision::Allow
            }
        }
        _ => Decision::Allow,
    }
}

/// The check `run_with_secrets` applies to its argv before it asks the
/// daemon anything (D-22), and the hook to `mcp__envcloak__run_with_secrets`:
/// the classes the `PreToolUse` hook denies in a shell command.
pub fn decide_argv<S: AsRef<std::ffi::OsStr>>(argv: &[S]) -> Decision {
    shell::check_argv(argv).map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)))
}

/// Whether a path names an env file (by its last component).
pub fn names_env_file(path: &str) -> bool {
    shell::check_argv(&["cat", path]) == Some(Class::EnvFile)
}

/// Whether a search glob (Claude Code's `Grep` tool's `glob`) could match
/// an env file, `*` matching a leading dot as search tools have it.
fn glob_matches_env_file(glob: &str) -> bool {
    let last = glob.rsplit('/').next().unwrap_or(glob);
    [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
    ]
    .iter()
    .any(|name| shell_glob(last.as_bytes(), name.as_bytes()))
}

fn shell_glob(pat: &[u8], name: &[u8]) -> bool {
    // `{a,b}` alternatives first.
    if let (Some(open), Some(close)) = (
        pat.iter().position(|&b| b == b'{'),
        pat.iter().position(|&b| b == b'}'),
    ) {
        if open < close {
            return pat[open + 1..close].split(|&b| b == b',').any(|alt| {
                let mut p = pat[..open].to_vec();
                p.extend_from_slice(alt);
                p.extend_from_slice(&pat[close + 1..]);
                shell_glob(&p, name)
            });
        }
    }
    shell::glob_matches(pat, name)
}

/// Whether any string in a tool's input, at any depth, names an env file.
fn strings_name_env_file(v: &Value, depth: usize) -> bool {
    if depth > 64 {
        return true;
    }
    match v {
        Value::String(s) => names_env_file(s),
        Value::Array(a) => a.iter().any(|x| strings_name_env_file(x, depth + 1)),
        Value::Object(o) => o.values().any(|x| strings_name_env_file(x, depth + 1)),
        _ => false,
    }
}

/// What the handler writes and how it exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: u8,
}

/// The exit status that stops the action on both hosts.
pub const BLOCK: u8 = 2;
/// The exit status of a hook error that stops nothing (no decision).
pub const NO_DECISION: u8 = 1;

/// The handler's answer to `decision` for `host`'s `event`: nothing for
/// [`Decision::Allow`]; for a denial, the host's JSON shape on standard
/// output, the message on standard error and exit 2, which stops the
/// action on both hosts even where the JSON is not read (SPEC §7, the
/// hosts' hook documentation). [`Decision::NoDecision`] is written by the
/// command, which says why on standard error.
pub fn answer(host: Host, event: Event, decision: Decision) -> Answer {
    let Decision::Deny(reason) = decision else {
        return Answer {
            stdout: Vec::new(),
            stderr: Vec::new(),
            code: if decision == Decision::NoDecision {
                NO_DECISION
            } else {
                0
            },
        };
    };
    let json = match host {
        Host::ClaudeCode => claude::deny(event, reason.message()),
        Host::Codex => codex::deny(event, reason.message()),
    };
    let mut stdout = serde_json::to_vec(&json).unwrap_or_default();
    stdout.push(b'\n');
    let mut stderr = reason.message().as_bytes().to_vec();
    stderr.push(b'\n');
    Answer {
        stdout,
        stderr,
        code: BLOCK,
    }
}

/// The context a `SessionStart` hook adds, as the host's JSON: the names
/// (never values) of the variables the project's manifest binds, and the
/// one-line usage rule.
pub fn session_context(host: Host, names: &[String]) -> Vec<u8> {
    let text = format!(
        "EnvCloak holds this project's keys: its envcloak.toml binds {}. Run anything that \
         needs them as `envcloak run -- <command>`; never read .env files or print environment \
         variables.",
        names.join(", ")
    );
    let json = match host {
        Host::ClaudeCode => claude::context(&text),
        Host::Codex => codex::context(&text),
    };
    let mut out = serde_json::to_vec(&json).unwrap_or_default();
    out.push(b'\n');
    out
}

/// The `cwd` of a payload that fits, for `SessionStart`'s manifest
/// lookup. `None` when there is none or the payload does not fit.
pub fn payload_cwd(host: Host, event: Event, payload: &SecretBuf) -> Option<String> {
    let Parsed::Fits(p) = payload::parse(host, event, payload) else {
        return None;
    };
    p.get("cwd")
        .and_then(Value::as_str)
        .filter(|c| c.starts_with('/'))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(v: &Value) -> SecretBuf {
        let bytes = serde_json::to_vec(v).unwrap_or_default();
        let mut b = SecretBuf::with_capacity(bytes.len());
        b.extend(&bytes).unwrap_or(());
        b
    }

    fn claude_pre(tool: &str, input: Value) -> Value {
        serde_json::json!({
            "session_id": "s", "transcript_path": "/t", "cwd": "/w",
            "hook_event_name": "PreToolUse", "permission_mode": "default",
            "tool_name": tool, "tool_input": input, "tool_use_id": "u",
        })
    }

    #[test]
    fn every_message_carries_its_marker_and_names_shipped_commands() {
        for r in Reason::ALL {
            let m = r.message();
            assert!(m.starts_with(&format!("[envcloak:{}] ", r.name())), "{r:?}");
            assert!(!m.contains("--ask"), "{r:?}");
        }
    }

    #[test]
    fn claude_tool_calls() {
        let d = |tool: &str, input: Value| {
            decide(
                Host::ClaudeCode,
                Event::PreToolUse,
                &buf(&claude_pre(tool, input)),
            )
        };
        assert_eq!(
            d("Bash", serde_json::json!({"command": "printenv"})),
            Decision::Deny(Reason::EnvDump)
        );
        assert_eq!(
            d("Read", serde_json::json!({"file_path": "/w/.env.local"})),
            Decision::Deny(Reason::EnvFile)
        );
        assert_eq!(
            d("Read", serde_json::json!({"file_path": "/w/.env.example"})),
            Decision::Allow
        );
        assert_eq!(
            d(
                "Edit",
                serde_json::json!({"file_path": "/w/.env", "old_string": "a", "new_string": "b"})
            ),
            Decision::Deny(Reason::EnvFile)
        );
        assert_eq!(
            d(
                "Grep",
                serde_json::json!({"pattern": "KEY", "glob": ".env*"})
            ),
            Decision::Deny(Reason::EnvFile)
        );
        assert_eq!(
            d(
                "Grep",
                serde_json::json!({"pattern": "KEY", "glob": "*.rs"})
            ),
            Decision::Allow
        );
        assert_eq!(
            d("Glob", serde_json::json!({"pattern": "**/.env*"})),
            Decision::Allow
        );
        assert_eq!(
            d(
                "mcp__envcloak__run_with_secrets",
                serde_json::json!({"project_dir": "/w", "argv": ["cat", ".env"]})
            ),
            Decision::Deny(Reason::EnvFile)
        );
        assert_eq!(
            d(
                "mcp__fs__read_file",
                serde_json::json!({"args": {"path": "/w/.env"}})
            ),
            Decision::Deny(Reason::EnvFile)
        );
        assert_eq!(d("Bash", serde_json::json!({})), Decision::NoDecision);
    }

    #[test]
    fn a_payload_of_another_shape_gets_no_decision() {
        let mut p = claude_pre("Bash", serde_json::json!({"command": "printenv"}));
        // The wrong event.
        assert_eq!(
            decide(Host::ClaudeCode, Event::UserPromptSubmit, &buf(&p)),
            Decision::NoDecision
        );
        // Codex's shape to the Claude Code handler, and the other way.
        p["turn_id"] = Value::from("t");
        assert_eq!(
            decide(Host::ClaudeCode, Event::PreToolUse, &buf(&p)),
            Decision::NoDecision
        );
        let codex = serde_json::json!({
            "session_id": "s", "transcript_path": null, "cwd": "/w",
            "hook_event_name": "PreToolUse", "model": "m", "permission_mode": "default",
            "turn_id": "t", "tool_name": "Bash", "tool_input": {"command": "printenv"},
            "tool_use_id": "u",
        });
        assert_eq!(
            decide(Host::Codex, Event::PreToolUse, &buf(&codex)),
            Decision::Deny(Reason::EnvDump)
        );
        let mut no_turn = codex.clone();
        if let Some(o) = no_turn.as_object_mut() {
            o.remove("turn_id");
        }
        assert_eq!(
            decide(Host::Codex, Event::PreToolUse, &buf(&no_turn)),
            Decision::NoDecision
        );
        let mut b = SecretBuf::with_capacity(4);
        b.extend(b"{\"a\"").unwrap_or(());
        assert_eq!(
            decide(Host::Codex, Event::PreToolUse, &b),
            Decision::NoDecision
        );
    }

    #[test]
    fn answers_block_with_exit_2_and_the_host_shape() {
        let a = answer(
            Host::ClaudeCode,
            Event::UserPromptSubmit,
            Decision::Deny(Reason::KeyInPrompt),
        );
        assert_eq!(a.code, BLOCK);
        let v: Value = serde_json::from_slice(&a.stdout).unwrap_or(Value::Null);
        assert_eq!(v["decision"], "block");
        assert_eq!(v["hookSpecificOutput"]["suppressOriginalPrompt"], true);
        let a = answer(
            Host::Codex,
            Event::PreToolUse,
            Decision::Deny(Reason::EnvFile),
        );
        let v: Value = serde_json::from_slice(&a.stdout).unwrap_or(Value::Null);
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(String::from_utf8_lossy(&a.stderr).starts_with("[envcloak:env_file]"));
        let a = answer(Host::Codex, Event::PreToolUse, Decision::Allow);
        assert_eq!((a.stdout.len(), a.stderr.len(), a.code), (0, 0, 0));
    }
}
