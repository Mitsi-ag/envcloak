//! D-30 hosted browser tool allowlist and argument sanitizer for `envcloak mcp`.
//!
//! Only the 19 safe navigation, inspection, and interaction tools from
//! `@playwright/mcp` are exposed to the host agent. Dangerous tools
//! (`browser_run_code`, `browser_run_code_unsafe`, `browser_file_upload`,
//! `browser_pdf_save`, tracing tools, etc.), filesystem path arguments
//! (`filename`, `path`, `outputPath`, `savePath`), and non-`http(s)` navigation
//! schemes (`file:`, `javascript:`, `data:`, `chrome:`, `about:`) are refused
//! at the supervisor and relay boundary before reaching the browser helper.

use serde_json::{Map, Value, json};

/// Exact D-30 allowlist of hosted browser tools exposed by `envcloak mcp`.
pub const ALLOWED_BROWSER_TOOLS: &[&str] = &[
    "browser_click",
    "browser_close",
    "browser_console_messages",
    "browser_drag",
    "browser_evaluate",
    "browser_fill_form",
    "browser_handle_dialog",
    "browser_hover",
    "browser_navigate",
    "browser_navigate_back",
    "browser_network_requests",
    "browser_press_key",
    "browser_resize",
    "browser_select_option",
    "browser_snapshot",
    "browser_tabs",
    "browser_take_screenshot",
    "browser_type",
    "browser_wait_for",
];

/// Known `@playwright/mcp` tools explicitly excluded by D-30.
pub const EXCLUDED_BROWSER_TOOLS: &[&str] = &[
    "browser_drop",
    "browser_emulate_media",
    "browser_file_upload",
    "browser_find",
    "browser_install",
    "browser_network_request",
    "browser_pdf_save",
    "browser_run_code",
    "browser_run_code_unsafe",
    "browser_start_tracing",
    "browser_stop_tracing",
];

/// Argument keys stripped from every allowed tool's `inputSchema` and refused
/// at `tools/call` time so no browser tool can read or write arbitrary host paths.
pub const FORBIDDEN_PATH_ARGS: &[&str] = &[
    "filename",
    "outputPath",
    "output_path",
    "path",
    "paths",
    "savePath",
    "save_path",
];

/// Refusal reason returned when a disallowed tool, path argument, or URL scheme is called.
pub const TOOL_NOT_ALLOWED: &str = "tool_not_allowed";

/// D-30 hosted browser tool filter and admission check.
#[derive(Debug, Default, Clone, Copy)]
pub struct ToolAllowlist;

impl ToolAllowlist {
    /// Returns whether `tool_name` is in [`ALLOWED_BROWSER_TOOLS`].
    #[must_use]
    pub fn is_allowed_tool(tool_name: &str) -> bool {
        ALLOWED_BROWSER_TOOLS.contains(&tool_name)
    }

    /// Returns whether `tool_name` looks like any browser tool (`browser_*`).
    #[must_use]
    pub fn is_browser_tool_name(tool_name: &str) -> bool {
        tool_name.starts_with("browser_")
    }

    /// Filters a raw `tools/list` array from `@playwright/mcp` down to
    /// [`ALLOWED_BROWSER_TOOLS`] and strips [`FORBIDDEN_PATH_ARGS`] from each
    /// tool's `inputSchema.properties` and `inputSchema.required`.
    #[must_use]
    pub fn list(raw_tools: &[Value]) -> Vec<Value> {
        let mut out = Vec::new();
        for tool in raw_tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !Self::is_allowed_tool(name) {
                continue;
            }
            let mut sanitized = tool.clone();
            if let Some(schema) = sanitized
                .get_mut("inputSchema")
                .and_then(Value::as_object_mut)
            {
                if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                    for forbidden in FORBIDDEN_PATH_ARGS {
                        props.remove(*forbidden);
                    }
                }
                if let Some(req) = schema.get_mut("required").and_then(Value::as_array_mut) {
                    req.retain(|v| v.as_str().is_none_or(|s| !FORBIDDEN_PATH_ARGS.contains(&s)));
                }
            }
            out.push(sanitized);
        }
        out
    }

    /// Checks whether a `tools/call` invocation for `tool_name` with `arguments`
    /// is permitted by D-30.
    ///
    /// # Errors
    /// Returns `Err("tool_not_allowed")` if the tool name is not in
    /// [`ALLOWED_BROWSER_TOOLS`], if `arguments` is not a JSON object, if any
    /// forbidden path argument is present, or if a navigation URL is not valid
    /// `http://` or `https://` without userinfo.
    pub fn admit(tool_name: &str, arguments: &Value) -> Result<(), &'static str> {
        if !Self::is_allowed_tool(tool_name) {
            return Err(TOOL_NOT_ALLOWED);
        }
        let Some(obj) = arguments.as_object() else {
            if arguments.is_null() {
                if tool_name == "browser_navigate" {
                    return Err(TOOL_NOT_ALLOWED);
                }
                return Ok(());
            }
            return Err(TOOL_NOT_ALLOWED);
        };
        if Self::has_forbidden_key(obj) {
            return Err(TOOL_NOT_ALLOWED);
        }
        if tool_name == "browser_navigate" {
            let Some(url) = obj.get("url").and_then(Value::as_str) else {
                return Err(TOOL_NOT_ALLOWED);
            };
            if !Self::is_allowed_http_url(url) {
                return Err(TOOL_NOT_ALLOWED);
            }
        } else if tool_name == "browser_tabs" {
            if let Some(url_val) = obj.get("url") {
                let Some(url) = url_val.as_str() else {
                    return Err(TOOL_NOT_ALLOWED);
                };
                if !Self::is_allowed_http_url(url) {
                    return Err(TOOL_NOT_ALLOWED);
                }
            }
        }
        Ok(())
    }

    fn has_forbidden_key(obj: &Map<String, Value>) -> bool {
        for (k, v) in obj {
            if FORBIDDEN_PATH_ARGS.contains(&k.as_str()) {
                return true;
            }
            if Self::value_has_forbidden_key(v) {
                return true;
            }
        }
        false
    }

    fn value_has_forbidden_key(val: &Value) -> bool {
        match val {
            Value::Object(map) => Self::has_forbidden_key(map),
            Value::Array(items) => items.iter().any(Self::value_has_forbidden_key),
            _ => false,
        }
    }

    /// Validates that `url` is an `http://` or `https://` URL with a non-empty
    /// authority, no userinfo (`@`), and no ASCII control or whitespace bytes.
    #[must_use]
    pub fn is_allowed_http_url(url: &str) -> bool {
        let trimmed = url.trim();
        if trimmed.is_empty() || trimmed != url {
            return false;
        }
        if url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return false;
        }
        let rest = if let Some(r) = Self::strip_ascii_case_prefix(url, "http://") {
            r
        } else if let Some(r) = Self::strip_ascii_case_prefix(url, "https://") {
            r
        } else {
            return false;
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return false;
        }
        true
    }

    fn strip_ascii_case_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if s.len() < prefix.len() {
            return None;
        }
        let (head, tail) = s.split_at(prefix.len());
        if head.eq_ignore_ascii_case(prefix) {
            Some(tail)
        } else {
            None
        }
    }

    /// Returns static sanitized schemas for the 19 [`ALLOWED_BROWSER_TOOLS`] when
    /// no live helper has been queried yet.
    #[must_use]
    pub fn static_schemas() -> Vec<Value> {
        ALLOWED_BROWSER_TOOLS
            .iter()
            .map(|&name| {
                let props = match name {
                    "browser_navigate" => json!({
                        "url": { "type": "string", "description": "HTTP(S) URL to navigate to" }
                    }),
                    "browser_tabs" => json!({
                        "action": { "type": "string", "description": "Tab operation" },
                        "index": { "type": "integer", "description": "Tab index" },
                        "url": { "type": "string", "description": "Optional HTTP(S) URL for a new tab" }
                    }),
                    "browser_evaluate" => json!({
                        "function": { "type": "string", "description": "JavaScript function expression" },
                        "element": { "type": "string", "description": "Optional element description" },
                        "ref": { "type": "string", "description": "Optional element reference" }
                    }),
                    "browser_click" | "browser_hover" => json!({
                        "element": { "type": "string", "description": "Element description" },
                        "ref": { "type": "string", "description": "Element reference" }
                    }),
                    "browser_type" => json!({
                        "element": { "type": "string", "description": "Element description" },
                        "ref": { "type": "string", "description": "Element reference" },
                        "text": { "type": "string", "description": "Text to type" },
                        "submit": { "type": "boolean", "description": "Whether to submit after typing" }
                    }),
                    _ => json!({}),
                };
                json!({
                    "name": name,
                    "description": format!("Hosted Playwright browser tool ({name})"),
                    "inputSchema": {
                        "type": "object",
                        "properties": props,
                    }
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_admits_only_nineteen_tools_and_blocks_forbidden_args_and_schemes() {
        assert_eq!(ALLOWED_BROWSER_TOOLS.len(), 19);
        assert_eq!(
            ToolAllowlist::admit(
                "browser_navigate",
                &json!({ "url": "https://acme.localhost:8443/dashboard" })
            ),
            Ok(())
        );
        assert_eq!(
            ToolAllowlist::admit("browser_run_code_unsafe", &json!({})),
            Err(TOOL_NOT_ALLOWED)
        );
        for key in FORBIDDEN_PATH_ARGS {
            let mut m = Map::new();
            m.insert((*key).to_owned(), json!("/tmp/leak.png"));
            assert_eq!(
                ToolAllowlist::admit("browser_take_screenshot", &Value::Object(m)),
                Err(TOOL_NOT_ALLOWED)
            );
        }
        for bad_url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "chrome://settings",
            "about:blank",
            "https://user:pass@acme.localhost/login",
        ] {
            assert_eq!(
                ToolAllowlist::admit("browser_navigate", &json!({ "url": bad_url })),
                Err(TOOL_NOT_ALLOWED)
            );
        }
    }
}
