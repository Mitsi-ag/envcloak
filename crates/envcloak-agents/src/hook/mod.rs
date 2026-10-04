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
    /// Every event, in the order the hosts' hook files list them.
    pub const ALL: [Event; 3] = [
        Event::UserPromptSubmit,
        Event::PreToolUse,
        Event::SessionStart,
    ];

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
    /// What a command that reads files or the environment reads was not
    /// resolved ([`Class::Unresolved`]): the person is asked (Claude Code),
    /// or the call stopped (Codex).
    Unresolved,
    /// The payload was larger than the handler reads, or did not arrive in
    /// time, so it was not checked.
    Unchecked,
    /// A debugger or tracer is attached to the handler, which therefore
    /// read nothing (SPEC §5: no secret is read under a tracer, and a
    /// prompt can hold one).
    Traced,
}

impl Reason {
    /// Every reason, for the tests.
    pub const ALL: [Reason; 9] = [
        Reason::KeyInPrompt,
        Reason::EnvFile,
        Reason::EnvDump,
        Reason::Reveal,
        Reason::Approve,
        Reason::Ambiguous,
        Reason::Unresolved,
        Reason::Unchecked,
        Reason::Traced,
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
            Reason::Unresolved => "unresolved",
            Reason::Unchecked => "unchecked",
            Reason::Traced => "traced",
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
            Reason::Unresolved => {
                "[envcloak:unresolved] EnvCloak's hook could not tell what this command reads: a \
                 file name or a command only known when it runs, a glob read under shell options \
                 that change what it matches, zsh's =command, or a program it does not know \
                 running a command that reads files. It is not let through unchecked: if it \
                 would read a .env file or print environment variables, do not run it; write the \
                 file names out plainly, and run anything that needs keys as `envcloak run -- \
                 <command>`. This hook prevents accidents; it is not a security boundary."
            }
            Reason::Unchecked => {
                "[envcloak:unchecked] EnvCloak's hook stopped this: the request was larger than \
                 the hook reads (2 MiB) or did not arrive within its 2 second limit, so it could \
                 not be checked. This hook prevents accidents; it is not a security boundary."
            }
            Reason::Traced => {
                "[envcloak:traced] EnvCloak's hook stopped this: a debugger or tracer is attached \
                 to the hook, so it did not read the request, which could hold a key. Run the agent \
                 without the tracer. This hook prevents accidents; it is not a security boundary."
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
            Class::Unresolved => Reason::Unresolved,
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
    /// Ask the person before it runs, with this reason (Claude Code's
    /// `permissionDecision: "ask"`). Never answered to Codex, which runs a
    /// call its hook asks about (Codex's cycle178 measurement): there it
    /// is a [`Decision::Deny`].
    Ask(Reason),
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

/// The decision for one tool call. Every channel a class can come
/// through is read for it (a deny class enforced on one tool only is a
/// miss on the others): a command, as a shell reads it ([`shell`]), for
/// `Bash` and `Monitor` (whose `command` is a shell script, Claude Code
/// 2.1.280's `sdk-tools.d.ts`); a path, for the file tools and every
/// string of an MCP tool's input, an MCP resource's URI and the input of
/// the tools that read a local file to send it on
/// ([`shell::path_class`]: env files and `/proc/<pid>/environ`); a search
/// glob, as Claude Code splits it, and a search's file type
/// ([`shell::grep_tool_glob_may_name_env_file`], [`shell::RG_ENV_TYPES`]);
/// and the argv of `run_with_secrets` ([`decide_argv`]).
fn tool_call(host: Host, tool: &str, input: &Map<String, Value>) -> Decision {
    let deny_if = |c: Option<Class>| c.map_or(Decision::Allow, |c| for_host(host, c));
    let claude = host == Host::ClaudeCode;
    match tool {
        "Bash" => match input.get("command").and_then(Value::as_str) {
            Some(cmd) => deny_if(shell::check_script(cmd)),
            None => Decision::NoDecision,
        },
        "Monitor" if claude => match input.get("command") {
            Some(Value::String(cmd)) => deny_if(shell::check_script(cmd)),
            // A WebSocket to watch, which runs nothing.
            None if input.contains_key("ws") => Decision::Allow,
            _ => Decision::NoDecision,
        },
        "Read" | "Edit" | "NotebookEdit" if claude => {
            match input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
                .and_then(Value::as_str)
            {
                Some(path) => deny_if(shell::path_class(path)),
                None => Decision::NoDecision,
            }
        }
        "Grep" if claude => {
            let path = input.get("path").and_then(Value::as_str);
            let glob = input.get("glob").and_then(Value::as_str);
            let kind = input.get("type").and_then(Value::as_str);
            match path.and_then(shell::path_class) {
                Some(c) => Decision::Deny(Reason::of(c)),
                // The glob as Claude Code splits it into ripgrep's
                // `--glob`s, and the `type` it passes as `--type`.
                None if glob.is_some_and(shell::grep_tool_glob_may_name_env_file)
                    || kind.is_some_and(|t| {
                        shell::RG_ENV_TYPES.contains(&t.to_ascii_lowercase().as_str())
                    }) =>
                {
                    Decision::Deny(Reason::EnvFile)
                }
                None => Decision::Allow,
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
        // An MCP resource, or a directory of them, by its URI; and the
        // tools that read a local file named anywhere in their input to
        // send it on (Artifact's `file_path` and `file_paths`, Projects'
        // `local_path`, Workflow's `scriptPath`, ClaudeDesign's
        // `arguments`), read as an MCP tool's arguments are.
        "ReadMcpResourceTool"
        | "ReadMcpResourceDirTool"
        | "Artifact"
        | "Projects"
        | "Workflow"
        | "ClaudeDesign"
            if claude =>
        {
            deny_if(strings_class(input.values(), 0))
        }
        t if t.starts_with("mcp__") => deny_if(strings_class(input.values(), 0)),
        _ => Decision::Allow,
    }
}

/// The answer to a tool call of class `class` from `host`: a denial, or for
/// [`Class::Unresolved`] a question to the person where the host stops a
/// call until they answer (Claude Code), and a denial where it does not
/// (Codex runs a call its hook asks about: never a silent allow).
fn for_host(host: Host, class: Class) -> Decision {
    match (class, host) {
        (Class::Unresolved, Host::ClaudeCode) => Decision::Ask(Reason::Unresolved),
        (c, _) => Decision::Deny(Reason::of(c)),
    }
}

/// The check `run_with_secrets` applies to its argv before it asks the
/// daemon anything (D-22), and the hook to `mcp__envcloak__run_with_secrets`:
/// the classes the `PreToolUse` hook denies in a shell command, and the
/// ones it asks about (the server has no one to ask, so it refuses).
pub fn decide_argv<S: AsRef<std::ffi::OsStr>>(argv: &[S]) -> Decision {
    shell::check_argv(argv).map_or(Decision::Allow, |c| Decision::Deny(Reason::of(c)))
}

/// Whether a path names an env file (by its last component, in any case).
pub fn names_env_file(path: &str) -> bool {
    shell::path_class(path) == Some(Class::EnvFile)
}

/// The class of the first string in a tool's input, at any depth, that
/// names an env file or a process's environment.
fn strings_class<'a>(values: impl Iterator<Item = &'a Value>, depth: usize) -> Option<Class> {
    for v in values {
        let c = match v {
            _ if depth > 64 => Some(Class::Ambiguous),
            Value::String(s) => shell::path_class(s),
            Value::Array(a) => strings_class(a.iter(), depth + 1),
            Value::Object(o) => strings_class(o.values(), depth + 1),
            _ => None,
        };
        if c.is_some() {
            return c;
        }
    }
    None
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
    if let (Decision::Ask(reason), Host::ClaudeCode, Event::PreToolUse) = (decision, host, event) {
        let mut stdout = serde_json::to_vec(&claude::ask(reason.message())).unwrap_or_default();
        stdout.push(b'\n');
        return Answer {
            stdout,
            stderr: Vec::new(),
            code: 0,
        };
    }
    let decision = match decision {
        // Anywhere else a question is not asked: it is a denial.
        Decision::Ask(r) => Decision::Deny(r),
        d => d,
    };
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

    /// Every channel a class can come through gets the same check: a
    /// command in `Monitor` as in `Bash` (Claude Code 2.1.280's Monitor
    /// runs a shell command), a process's environment through a file tool,
    /// a search glob or an MCP tool as through `cat`, an env file of any
    /// profile or case through a `Grep` glob, an MCP resource's URI as an
    /// MCP tool's arguments.
    ///
    /// Mutations checked: the `Monitor` arm taken out of `tool_call`
    /// (`Monitor {command: "printenv"}` allowed); `shell::path_class`
    /// without its `/proc/<pid>/environ` answer (the env-dump class for
    /// Bash only, as before); `glob_may_name_env_file` back to the five
    /// sample names (`.env.staging` allowed); the `ReadMcpResourceTool` arm
    /// taken out. This round: the Grep glob judged whole, without the
    /// host's split (`README.md,.env` allowed); classes read as text (the
    /// previous `glob_may_name_env_file`: `[.]e[n]v` allowed); Grep's
    /// `type` not read; the `Artifact`, `Projects` and `Workflow` arms
    /// taken out. Each fails this.
    #[test]
    fn every_channel_a_class_comes_through_is_read() {
        let d = |tool: &str, input: Value| {
            decide(
                Host::ClaudeCode,
                Event::PreToolUse,
                &buf(&claude_pre(tool, input)),
            )
        };
        let j = |v: Value| v;
        let env_dump = Decision::Deny(Reason::EnvDump);
        let env_file = Decision::Deny(Reason::EnvFile);
        for (tool, input, want) in [
            (
                "Monitor",
                j(
                    serde_json::json!({"description": "d", "timeout_ms": 1000, "command": "printenv"}),
                ),
                env_dump,
            ),
            (
                "Monitor",
                j(
                    serde_json::json!({"description": "d", "timeout_ms": 1000, "command": "tail -f .env"}),
                ),
                env_file,
            ),
            (
                "Monitor",
                j(
                    serde_json::json!({"description": "d", "timeout_ms": 1000, "command": "tail -f app.log"}),
                ),
                Decision::Allow,
            ),
            (
                "Monitor",
                j(
                    serde_json::json!({"description": "d", "timeout_ms": 1000, "ws": {"url": "ws://x"}}),
                ),
                Decision::Allow,
            ),
            (
                "Monitor",
                j(serde_json::json!({"description": "d", "timeout_ms": 1000, "command": 3})),
                Decision::NoDecision,
            ),
            (
                "Read",
                serde_json::json!({"file_path": "/proc/self/environ"}),
                env_dump,
            ),
            (
                "Read",
                serde_json::json!({"file_path": "/proc/1/environ"}),
                env_dump,
            ),
            (
                "Read",
                serde_json::json!({"file_path": "/w/.ENV"}),
                env_file,
            ),
            (
                "Read",
                serde_json::json!({"file_path": "/w/.env.staging"}),
                env_file,
            ),
            (
                "Read",
                serde_json::json!({"file_path": "/w/.env.Example"}),
                Decision::Allow,
            ),
            (
                "Grep",
                serde_json::json!({"pattern": "K", "path": "/proc/42/environ"}),
                env_dump,
            ),
            (
                "mcp__fs__read_file",
                serde_json::json!({"path": "/proc/self/environ"}),
                env_dump,
            ),
            (
                "ReadMcpResourceTool",
                serde_json::json!({"server": "fs", "uri": "file:///w/.env.local"}),
                env_file,
            ),
            (
                "ReadMcpResourceTool",
                serde_json::json!({"server": "fs", "uri": "file:///proc/self/environ"}),
                env_dump,
            ),
            (
                "ReadMcpResourceTool",
                serde_json::json!({"server": "fs", "uri": "file:///w/README.md"}),
                Decision::Allow,
            ),
            // The tools of the pinned version that read a local file to
            // send it on, or a directory of resources (the verifier's
            // finding: they were not in the matcher, nor read).
            (
                "ReadMcpResourceDirTool",
                serde_json::json!({"server": "fs", "uri": "file:///proc/self/environ"}),
                env_dump,
            ),
            (
                "NotebookEdit",
                serde_json::json!({"notebook_path": "/w/.env", "new_source": "x"}),
                env_file,
            ),
            (
                "Artifact",
                serde_json::json!({"action": "upload_asset", "url": "u", "file_path": "/w/.env.local"}),
                env_file,
            ),
            (
                "Artifact",
                serde_json::json!({"action": "upload_asset", "url": "u", "file_paths": ["/w/a.png", "/w/.env"]}),
                env_file,
            ),
            (
                "Artifact",
                serde_json::json!({"file_path": "/w/page.html"}),
                Decision::Allow,
            ),
            (
                "Projects",
                serde_json::json!({"method": "project_write", "local_path": "/w/.ENV"}),
                env_file,
            ),
            (
                "Workflow",
                serde_json::json!({"scriptPath": "/w/.env.staging"}),
                env_file,
            ),
            (
                "ClaudeDesign",
                serde_json::json!({"operation": "upload", "arguments": {"file": "/proc/1/environ"}}),
                env_dump,
            ),
            (
                "Write",
                serde_json::json!({"file_path": "/w/.env.example", "content": "A="}),
                Decision::Allow,
            ),
            // Grep's `type` is ripgrep's `--type`: `sh` holds `.env`.
            (
                "Grep",
                serde_json::json!({"pattern": "K", "type": "sh"}),
                env_file,
            ),
            (
                "Grep",
                serde_json::json!({"pattern": "K", "type": "ALL"}),
                env_file,
            ),
            (
                "Grep",
                serde_json::json!({"pattern": "K", "type": "rust"}),
                Decision::Allow,
            ),
        ] {
            assert_eq!(d(tool, input.clone()), want, "{tool} {input}");
        }
        // Every tool the hook reads is in the installer's matcher.
        for tool in [
            "Bash",
            "Monitor",
            "Read",
            "Edit",
            "NotebookEdit",
            "Grep",
            "Glob",
            "ReadMcpResourceTool",
            "ReadMcpResourceDirTool",
            "Artifact",
            "Projects",
            "Workflow",
            "ClaudeDesign",
        ] {
            assert!(
                crate::hosts::claude::TOOL_MATCHER
                    .split('|')
                    .any(|t| t == tool),
                "{tool}"
            );
        }
        for glob in [
            ".env*",
            ".env.staging",
            ".env.prod",
            ".env.ci",
            "**/.env.preview",
            "{.env.stage,x}",
            "*.{env,txt}",
            "*.env",
            "*env*",
            "[.]env",
            ".E*",
            "src/.e?v",
            // Classes are sets (F119), and Claude Code splits the glob on
            // white space and commas before ripgrep reads it.
            "[.]e[n]v",
            "[.]e[n]v*",
            "**/[.][e][n][v].staging",
            "{*.rs,[.]env.ci}",
            ".env.local src/*.rs",
            "README.md,.env",
            ".env,config/app.yaml",
            ".env* src/**",
            ".env x",
        ] {
            assert_eq!(
                d("Grep", serde_json::json!({"pattern": "K", "glob": glob})),
                env_file,
                "{glob}"
            );
        }
        for glob in [
            "*.rs",
            "*.{ts,tsx}",
            "*",
            "!.env*",
            "src/**/*.py",
            ".env.example",
            "[u]nit.rs",
            "*.rs src/**/*.ts",
            "README.md,docs/*.md",
        ] {
            assert_eq!(
                d("Grep", serde_json::json!({"pattern": "K", "glob": glob})),
                Decision::Allow,
                "{glob}"
            );
        }
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

    /// The orchestrator's finding, fail closed: a command whose reads are
    /// not resolved is put to the person in Claude Code (`ask`, exit 0, the
    /// reason shown) and stopped in Codex, which runs a call its hook asks
    /// about (Codex's cycle178 measurement); the MCP server, with no one to
    /// ask, refuses it.
    ///
    /// Mutation checked: `for_host` answering `Ask` to Codex too: Codex's
    /// decision is not a denial and this fails.
    #[test]
    fn an_unresolved_read_is_asked_about_or_stopped_never_let_through() {
        let cmd = "f=a.txt; cat \"$f\"";
        let claude = decide(
            Host::ClaudeCode,
            Event::PreToolUse,
            &buf(&claude_pre("Bash", serde_json::json!({"command": cmd}))),
        );
        assert_eq!(claude, Decision::Ask(Reason::Unresolved));
        let a = answer(Host::ClaudeCode, Event::PreToolUse, claude);
        assert_eq!(a.code, 0);
        let v: Value = serde_json::from_slice(&a.stdout).unwrap_or(Value::Null);
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(
            v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .is_some_and(|r| r.starts_with("[envcloak:unresolved]"))
        );
        let codex = serde_json::json!({
            "session_id": "s", "transcript_path": null, "cwd": "/w",
            "hook_event_name": "PreToolUse", "model": "m", "turn_id": "t",
            "permission_mode": "default", "tool_name": "Bash",
            "tool_input": {"command": cmd}, "tool_use_id": "u",
        });
        let d = decide(Host::Codex, Event::PreToolUse, &buf(&codex));
        assert_eq!(d, Decision::Deny(Reason::Unresolved));
        assert_eq!(answer(Host::Codex, Event::PreToolUse, d).code, BLOCK);
        // An `Ask` reaching Codex's answer anyway is a denial there.
        let a = answer(
            Host::Codex,
            Event::PreToolUse,
            Decision::Ask(Reason::Unresolved),
        );
        assert_eq!(a.code, BLOCK);
        assert_eq!(
            decide_argv(&["sh", "-c", cmd]),
            Decision::Deny(Reason::Unresolved)
        );
    }
}
