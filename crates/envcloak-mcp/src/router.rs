//! Which tools the server lists and dispatches.
//!
//! A tool is registered listed ([`Router::register`]) or not
//! ([`Router::register_unlisted`]); a backend serves every tool whose name
//! starts with its prefix that it lists itself ([`Router::register_backend`],
//! the seam M2b's sign-in tools and browser backend plug into). The router
//! dispatches only what `tools/list` shows: a `tools/call` naming a tool
//! that is registered but not listed gets the same unknown-tool error as a
//! name nothing has, so an unlisted tool cannot be reached by guessing its
//! name (M2b-06 relies on it).

use serde_json::{Map, Value, json};

use crate::child::Call;
use crate::tools::Ctx;

/// A tool's annotations (MCP `ToolAnnotations`): hints a host may use to
/// decide whether to ask the person, never a guarantee. `None` leaves a
/// hint out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Annotations {
    pub read_only: Option<bool>,
    pub destructive: Option<bool>,
    pub idempotent: Option<bool>,
    pub open_world: Option<bool>,
}

impl Annotations {
    fn to_json(self) -> Value {
        let mut m = Map::new();
        let mut put = |k: &str, v: Option<bool>| {
            if let Some(v) = v {
                m.insert(k.to_owned(), Value::Bool(v));
            }
        };
        put("readOnlyHint", self.read_only);
        put("destructiveHint", self.destructive);
        put("idempotentHint", self.idempotent);
        put("openWorldHint", self.open_world);
        Value::Object(m)
    }
}

/// What `tools/list` shows of a tool.
#[derive(Debug, Clone)]
pub struct ToolSchema {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// A JSON Schema object; `additionalProperties` is false.
    pub input: Value,
    /// The JSON Schema of `structuredContent`.
    pub output: Value,
    pub annotations: Annotations,
}

impl ToolSchema {
    /// The tool as `tools/list` shows it.
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input,
            "outputSchema": self.output,
            "annotations": self.annotations.to_json(),
        })
    }
}

/// A tool's answer: a result, or a failure with a fixed token and fixed
/// text ([`envcloak_client::fail::Failure`], the CLI's own failures).
#[derive(Debug, Clone)]
pub enum ToolResult {
    Ok(Value),
    Err(envcloak_client::fail::Failure),
}

impl ToolResult {
    /// The `tools/call` result: a result's JSON as `structuredContent` and
    /// as text; a failure as text only (`{"error": <token>, "message":
    /// <text>}`), with `isError`.
    pub fn to_json(&self) -> Value {
        match self {
            ToolResult::Ok(v) => json!({
                "content": [{"type": "text", "text": v.to_string()}],
                "structuredContent": v,
                "isError": false,
            }),
            ToolResult::Err(f) => {
                let text = json!({"error": f.token, "message": f.message}).to_string();
                json!({"content": [{"type": "text", "text": text}], "isError": true})
            }
        }
    }
}

impl From<envcloak_client::fail::Failure> for ToolResult {
    fn from(f: envcloak_client::fail::Failure) -> Self {
        ToolResult::Err(f)
    }
}

/// A tool.
pub trait Tool: Send + Sync {
    fn schema(&self) -> ToolSchema;
    /// Runs the tool with the call's `arguments` (an empty object when
    /// none were sent). `call` says whether the host cancelled it, and
    /// owns the child the tool starts.
    fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult;
}

/// A set of tools served under one name prefix.
pub trait Backend: Send + Sync {
    /// The tools it lists now; each name starts with its prefix.
    fn tools(&self) -> Vec<ToolSchema>;
    /// Runs `name`, which it listed.
    fn call(&self, name: &str, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult;
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The name, or the prefix, is taken or overlaps one taken.
    Taken,
}

struct Entry {
    name: &'static str,
    tool: Box<dyn Tool>,
    listed: bool,
}

/// What a listed tool name leads to.
pub enum Target<'a> {
    Tool(&'a dyn Tool),
    Backend(&'a dyn Backend),
}

impl std::fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Target::Tool(_) => "Target::Tool",
            Target::Backend(_) => "Target::Backend",
        })
    }
}

/// The tools of a server.
#[derive(Default)]
pub struct Router {
    tools: Vec<Entry>,
    backends: Vec<(&'static str, Box<dyn Backend>)>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tools: Vec<(&str, bool)> = self.tools.iter().map(|e| (e.name, e.listed)).collect();
        let prefixes: Vec<&str> = self.backends.iter().map(|(p, _)| *p).collect();
        f.debug_struct("Router")
            .field("tools", &tools)
            .field("backends", &prefixes)
            .finish()
    }
}

impl Router {
    pub fn new() -> Router {
        Router::default()
    }

    fn taken(&self, name: &str) -> bool {
        self.tools.iter().any(|e| e.name == name)
            || self.backends.iter().any(|(p, _)| name.starts_with(p))
    }

    fn add(&mut self, tool: Box<dyn Tool>, listed: bool) -> Result<(), RegisterError> {
        let name = tool.schema().name;
        if self.taken(name) {
            return Err(RegisterError::Taken);
        }
        self.tools.push(Entry { name, tool, listed });
        Ok(())
    }

    /// Registers `tool`, listed.
    ///
    /// # Errors
    /// [`RegisterError::Taken`] when its name is taken.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<(), RegisterError> {
        self.add(tool, true)
    }

    /// Registers `tool` without listing it: it is not shown, and a call to
    /// it is answered as a call to no tool.
    ///
    /// # Errors
    /// [`RegisterError::Taken`] when its name is taken.
    pub fn register_unlisted(&mut self, tool: Box<dyn Tool>) -> Result<(), RegisterError> {
        self.add(tool, false)
    }

    /// Registers `backend` for the tools whose names start with `prefix`.
    ///
    /// # Errors
    /// [`RegisterError::Taken`] when a tool's name or another prefix
    /// overlaps it.
    pub fn register_backend(
        &mut self,
        prefix: &'static str,
        backend: Box<dyn Backend>,
    ) -> Result<(), RegisterError> {
        let overlaps = prefix.is_empty()
            || self.tools.iter().any(|e| e.name.starts_with(prefix))
            || self
                .backends
                .iter()
                .any(|(p, _)| p.starts_with(prefix) || prefix.starts_with(p));
        if overlaps {
            return Err(RegisterError::Taken);
        }
        self.backends.push((prefix, backend));
        Ok(())
    }

    /// What `tools/list` shows: the listed tools in the order registered,
    /// then each backend's.
    pub fn list(&self) -> Vec<ToolSchema> {
        let mut out: Vec<ToolSchema> = self
            .tools
            .iter()
            .filter(|e| e.listed)
            .map(|e| e.tool.schema())
            .collect();
        for (prefix, b) in &self.backends {
            out.extend(b.tools().into_iter().filter(|s| s.name.starts_with(prefix)));
        }
        out
    }

    /// The listed tool `name`, if any.
    pub fn route(&self, name: &str) -> Option<Target<'_>> {
        if let Some(e) = self.tools.iter().find(|e| e.name == name) {
            return e.listed.then_some(Target::Tool(e.tool.as_ref()));
        }
        let (prefix, b) = self.backends.iter().find(|(p, _)| name.starts_with(p))?;
        let listed = b
            .tools()
            .iter()
            .any(|s| s.name == name && s.name.starts_with(prefix));
        listed.then_some(Target::Backend(b.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Named(&'static str);

    impl Tool for Named {
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: self.0,
                title: "t",
                description: "d",
                input: json!({"type": "object", "additionalProperties": false}),
                output: json!({"type": "object"}),
                annotations: Annotations::default(),
            }
        }

        fn call(&self, _: &Map<String, Value>, _: &Ctx, _: &Call) -> ToolResult {
            ToolResult::Ok(json!({}))
        }
    }

    struct Browser;

    impl Backend for Browser {
        fn tools(&self) -> Vec<ToolSchema> {
            // A backend can only list names under its prefix.
            vec![Named("browser_click").schema(), Named("elsewhere").schema()]
        }

        fn call(&self, _: &str, _: &Map<String, Value>, _: &Ctx, _: &Call) -> ToolResult {
            ToolResult::Ok(json!({}))
        }
    }

    #[test]
    fn only_listed_tools_are_shown_and_reached() {
        let mut r = Router::new();
        r.register(Box::new(Named("listed"))).unwrap();
        r.register_unlisted(Box::new(Named("hidden"))).unwrap();
        assert_eq!(
            r.register(Box::new(Named("listed"))),
            Err(RegisterError::Taken)
        );
        r.register_backend("browser_", Box::new(Browser)).unwrap();
        assert_eq!(
            r.register_backend("browser", Box::new(Browser)).err(),
            Some(RegisterError::Taken)
        );
        assert_eq!(
            r.register(Box::new(Named("browser_x"))),
            Err(RegisterError::Taken)
        );
        let names: Vec<&str> = r.list().iter().map(|s| s.name).collect();
        assert_eq!(names, ["listed", "browser_click"]);
        assert!(matches!(r.route("listed"), Some(Target::Tool(_))));
        assert!(matches!(r.route("browser_click"), Some(Target::Backend(_))));
        // Registered but unlisted, unlisted by its backend, or nothing:
        // the same answer.
        for name in ["hidden", "browser_type", "elsewhere", "nothing", ""] {
            assert!(r.route(name).is_none(), "{name}");
        }
    }

    #[test]
    fn results_carry_structured_content_and_failures_text_only() {
        let ok = ToolResult::Ok(json!({"a": 1})).to_json();
        assert_eq!(ok["structuredContent"], json!({"a": 1}));
        assert_eq!(ok["content"][0]["text"], "{\"a\":1}");
        assert_eq!(ok["isError"], false);
        let err = ToolResult::Err(envcloak_client::fail::Failure::new("busy", "later")).to_json();
        assert_eq!(err["isError"], true);
        assert!(err.get("structuredContent").is_none());
        let text: Value =
            serde_json::from_str(err["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, json!({"error": "busy", "message": "later"}));
    }
}
