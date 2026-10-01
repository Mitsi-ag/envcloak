//! The script a run replays: one assistant turn per step, each a text, a
//! shell command, a named tool call, or a text followed by one call.
//!
//! The step a request gets is the number of tool calls already in the
//! conversation it carries, so a retried request gets the same step and
//! no state is kept between requests. A step that only says something ends
//! the conversation. A request that offers no tools (a host's side call,
//! such as a title) gets the `side` text and no step.

use std::fmt;

use serde::Deserialize;
use serde_json::Value;

/// The most bytes a script may take, as JSON.
pub const MAX_SCRIPT: usize = 1024 * 1024;
/// The most steps a script may hold.
pub const MAX_STEPS: usize = 256;

/// A run's script. `Debug` shows its shape, never its text: a probe's
/// script can carry a canary on purpose (a positive control).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    /// The assistant turns, in order.
    pub steps: Vec<Step>,
    /// The reply to a request that offers no tools.
    #[serde(default)]
    pub side: Option<String>,
}

/// One assistant turn.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Text said before any call, or alone.
    #[serde(default)]
    pub say: Option<String>,
    /// A command for the host's own shell tool: `Bash` under Anthropic
    /// Messages, `exec_command` (or the older `shell`) under OpenAI
    /// Responses, whichever the request offers.
    #[serde(default)]
    pub shell: Option<String>,
    /// A tool called by name with [`Step::input`], for tools the host
    /// names itself (an MCP server's, a file read).
    #[serde(default)]
    pub tool: Option<String>,
    /// The arguments of [`Step::tool`], a JSON object.
    #[serde(default)]
    pub input: Option<Value>,
    /// The namespace of [`Step::tool`], for OpenAI Responses hosts that
    /// offer tools in one (Codex 0.159.2 offers an MCP server's tools as
    /// the namespace `mcp__<server>`). Anthropic Messages has none: such a
    /// step is a mismatch there.
    #[serde(default)]
    pub namespace: Option<String>,
    /// A barrier: the reply to this step is held until the run is told
    /// `release <name>` (see [`super::Handle::release`]), so a test can act
    /// between two turns (a person approving a request) without timing.
    #[serde(default)]
    pub after: Option<String>,
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Script")
            .field("steps", &self.steps)
            .field("side", &self.side.as_ref().map(|_| "<text>"))
            .finish()
    }
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match (&self.shell, &self.tool) {
            (Some(_), _) => "shell",
            (None, Some(_)) => "tool",
            (None, None) => "say",
        };
        f.debug_struct("Step")
            .field("kind", &kind)
            .field("says", &self.say.is_some())
            .field("after", &self.after)
            .finish()
    }
}

/// Why a script was refused. Fixed text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    /// Longer than [`MAX_SCRIPT`].
    TooLarge,
    /// Not the JSON shape above (unknown fields included).
    Shape,
    /// No steps, or more than [`MAX_STEPS`].
    Steps,
    /// A step with neither text nor a call, or with both a shell command
    /// and a named tool.
    Step,
    /// A named tool's input that is not a JSON object, or an input or a
    /// namespace without a named tool.
    Input,
    /// A barrier name that is not 1 to 64 letters, digits, `-` or `_`.
    Barrier,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScriptError::TooLarge => "the script is longer than 1 MiB",
            ScriptError::Shape => "the script is not a JSON object of steps and side",
            ScriptError::Steps => "the script needs 1 to 256 steps",
            ScriptError::Step => "a step needs text or one call, and at most one call",
            ScriptError::Input => {
                "a tool's input must be a JSON object, and only a tool has an input or a namespace"
            }
            ScriptError::Barrier => "a barrier is named with 1 to 64 letters, digits, - or _",
        })
    }
}

impl Script {
    /// Reads a script from JSON.
    ///
    /// # Errors
    /// [`ScriptError`], naming the rule broken and nothing of the input.
    pub fn parse(json: &[u8]) -> Result<Script, ScriptError> {
        if json.len() > MAX_SCRIPT {
            return Err(ScriptError::TooLarge);
        }
        let script: Script = serde_json::from_slice(json).map_err(|_| ScriptError::Shape)?;
        if script.steps.is_empty() || script.steps.len() > MAX_STEPS {
            return Err(ScriptError::Steps);
        }
        for step in &script.steps {
            let calls = usize::from(step.shell.is_some()) + usize::from(step.tool.is_some());
            if calls > 1 || (calls == 0 && step.say.is_none()) {
                return Err(ScriptError::Step);
            }
            match (&step.tool, &step.input) {
                (Some(_), Some(Value::Object(_))) | (Some(_), None) | (None, None) => {}
                _ => return Err(ScriptError::Input),
            }
            if step.namespace.is_some() && step.tool.is_none() {
                return Err(ScriptError::Input);
            }
            if step.after.as_deref().is_some_and(|b| !barrier_name(b)) {
                return Err(ScriptError::Barrier);
            }
        }
        Ok(script)
    }

    /// The step for a conversation that already holds `calls` tool calls.
    pub fn step(&self, calls: usize) -> Option<&Step> {
        self.steps.get(calls)
    }
}

/// Whether `name` can name a barrier: 1 to 64 ASCII letters, digits, `-`
/// or `_`.
pub fn barrier_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Step {
    /// Whether this step calls a tool (and so the conversation goes on).
    pub fn calls(&self) -> bool {
        self.shell.is_some() || self.tool.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_are_checked() {
        let ok = br#"{"steps":[{"shell":"echo hi"},{"say":"done"}],"side":"ok"}"#;
        let s = Script::parse(ok).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.steps.len(), 2);
        assert!(s.step(0).is_some_and(Step::calls));
        assert!(s.step(1).is_some_and(|s| !s.calls()));
        assert!(s.step(2).is_none());
        let shown = format!("{s:?}");
        assert!(
            !shown.contains("echo") && !shown.contains("done"),
            "{shown}"
        );

        let refused: &[(&[u8], ScriptError)] = &[
            (br#"{"steps":[]}"#, ScriptError::Steps),
            (br#"{"steps":[{}]}"#, ScriptError::Step),
            (
                br#"{"steps":[{"shell":"a","tool":"b"}]}"#,
                ScriptError::Step,
            ),
            (
                br#"{"steps":[{"tool":"b","input":[1]}]}"#,
                ScriptError::Input,
            ),
            (br#"{"steps":[{"say":"a","input":{}}]}"#, ScriptError::Input),
            (
                br#"{"steps":[{"say":"a","namespace":"x"}]}"#,
                ScriptError::Input,
            ),
            (br#"{"steps":[{"say":"a","extra":1}]}"#, ScriptError::Shape),
            (br#"{"steps":[{"say":"a"}],"more":1}"#, ScriptError::Shape),
            (
                br#"{"steps":[{"say":"a","after":"no space"}]}"#,
                ScriptError::Barrier,
            ),
            (
                br#"{"steps":[{"say":"a","after":""}]}"#,
                ScriptError::Barrier,
            ),
            (b"\xff", ScriptError::Shape),
        ];
        for (input, want) in refused {
            assert_eq!(Script::parse(input).err(), Some(*want));
        }
        let many = format!(r#"{{"steps":[{}]}}"#, vec![r#"{"say":"a"}"#; 257].join(","));
        assert_eq!(
            Script::parse(many.as_bytes()).err(),
            Some(ScriptError::Steps)
        );
        let big = vec![b' '; MAX_SCRIPT + 1];
        assert_eq!(Script::parse(&big).err(), Some(ScriptError::TooLarge));
    }
}
