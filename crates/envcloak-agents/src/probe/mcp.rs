//! The probe's MCP server, shipped as its own binary `envcloak-probe-mcp`
//! (a `[[bin]]` of this crate, never linked into `envcloak` or
//! `envcloakd`), which `envcloak agents status --probe` registers with the
//! host in the probe home for the MCP surface (M2 plan M2-28, gate 38 on
//! the person's machine; the verifier's and Codex's reviews: with no such
//! server shipped, that surface was never probed outside CI).
//!
//! A stdio MCP server: one JSON-RPC message per line on its input and its
//! output (`initialize`, `ping`, `tools/list`, `tools/call`; notifications
//! are read and not answered; any other request is `-32601`). Two tools,
//! the MCP probe's (`super::run`):
//!
//! - `echo {text, more}`: the two joined, the probe's control (a marker
//!   sent in two pieces comes back whole only from a call that ran);
//! - `read_file {path}`: the first 64 KiB of a file in the server's
//!   working directory (the probe's project), the call EnvCloak's hook must
//!   deny for `.env`. `path` must be one name in that directory: an
//!   absolute path, a `/`, `.` or `..`, a link, or anything but a regular
//!   file is refused, so the server reads nothing outside the probe's
//!   project, whoever calls it.
//!
//! It holds no value of EnvCloak's: what `read_file` returns is the probe
//! project's fixture, which the hook is there to stop.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, Read as _, Write};

use serde_json::{Value, json};

/// The protocol versions it answers with, newest first.
pub const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// The most of a file `read_file` returns.
pub const MAX_READ: u64 = 64 * 1024;
/// The longest input line read; a longer one ends the session.
pub const MAX_LINE: u64 = 1024 * 1024;

/// What `read_file` answers when it reads nothing.
pub const NOT_READ: &str = "the file could not be read";

/// Serves `input` to `output` until the input ends (or a line is longer
/// than [`MAX_LINE`]), `read_file` reading from `dir`.
///
/// # Errors
/// Writing to `output`.
pub fn serve(input: &mut impl BufRead, output: &mut impl Write, dir: &File) -> std::io::Result<()> {
    loop {
        let mut line = Vec::new();
        let n = input
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 || (line.len() as u64 > MAX_LINE && !line.ends_with(b"\n")) {
            return Ok(());
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        if let Some(reply) = answer(&msg, dir) {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
}

/// The reply to one message, or `None` for a notification.
pub fn answer(msg: &Value, dir: &File) -> Option<Value> {
    let id = msg.get("id")?.clone();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => {
            let asked = msg["params"]["protocolVersion"].as_str().unwrap_or("");
            let version = if VERSIONS.contains(&asked) {
                asked
            } else {
                VERSIONS[0]
            };
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "envcloak-probe-mcp", "version": env!("CARGO_PKG_VERSION")},
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": [
            {"name": "echo", "description": "Answers its two texts joined.",
             "inputSchema": {"type": "object",
                             "properties": {"text": {"type": "string"},
                                            "more": {"type": "string"}},
                             "required": ["text"], "additionalProperties": false}},
            {"name": "read_file", "description": "Answers a file's contents.",
             "inputSchema": {"type": "object",
                             "properties": {"path": {"type": "string"}},
                             "required": ["path"], "additionalProperties": false}},
        ]}),
        "tools/call" => {
            let args = &msg["params"]["arguments"];
            let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("");
            let (text, error) = match msg["params"]["name"].as_str().unwrap_or("") {
                "echo" => (format!("{}{}", s("text"), s("more")), false),
                "read_file" => (read_file(dir, s("path")), false),
                _ => ("no such tool".to_owned(), true),
            };
            json!({"content": [{"type": "text", "text": text}], "isError": error})
        }
        _ => {
            return Some(json!({"jsonrpc": "2.0", "id": id,
                               "error": {"code": -32601, "message": "method not found"}}));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// The first [`MAX_READ`] bytes of the regular file `name` in `dir`, as
/// text, or [`NOT_READ`]: `name` is one component, opened beneath `dir`
/// without following a link (`envcloak_sys::open_beneath`).
pub fn read_file(dir: &File, name: &str) -> String {
    let Ok(f) = envcloak_sys::open_beneath(dir, OsStr::new(name)) else {
        return NOT_READ.to_owned();
    };
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return NOT_READ.to_owned();
    }
    let mut out = Vec::new();
    match f.take(MAX_READ).read_to_end(&mut out) {
        Ok(_) => String::from_utf8_lossy(&out).into_owned(),
        Err(_) => NOT_READ.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(dir: &File, name: &str, args: Value) -> (String, bool) {
        let r = answer(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": args}}),
            dir,
        )
        .unwrap_or_default();
        (
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            r["result"]["isError"].as_bool().unwrap_or(true),
        )
    }

    /// The two tools answer as the MCP probe needs, and `read_file` reads
    /// one regular file in its directory and nothing else. Mutation
    /// checked: `read_file` opening `name` by path from its working
    /// directory (following links, taking `..` and absolute paths), the
    /// test run in the project as the server is: the link's read returns
    /// the outside file and this fails.
    #[test]
    fn the_probe_server_answers_its_tools_and_reads_only_its_directory() {
        let root = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(project.join(".env"), "PROBE=fixture\n").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(root.path().join("outside"), "outside\n").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(root.path().join("outside"), project.join("link"))
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(project.join("sub")).unwrap_or_else(|e| panic!("{e}"));
        let dir = File::open(&project).unwrap_or_else(|e| panic!("{e}"));

        assert_eq!(
            call(&dir, "echo", json!({"text": "ab", "more": "cd"})),
            ("abcd".to_owned(), false)
        );
        assert_eq!(
            call(&dir, "read_file", json!({"path": ".env"})),
            ("PROBE=fixture\n".to_owned(), false)
        );
        let outside = root.path().join("outside");
        for path in [
            "link",
            "../outside",
            outside.to_str().unwrap_or(""),
            "sub",
            "missing",
            "",
            ".",
            "..",
        ] {
            assert_eq!(
                call(&dir, "read_file", json!({"path": path})).0,
                NOT_READ,
                "{path}"
            );
        }
        assert!(call(&dir, "other", json!({})).1);

        // Over the wire: initialize, a notification, the tool list.
        let input = [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
        ]
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>();
        let mut out = Vec::new();
        serve(&mut input.as_bytes(), &mut out, &dir).unwrap_or_else(|e| panic!("{e}"));
        let replies: Vec<Value> = out
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap_or_default())
            .collect();
        assert_eq!(replies.len(), 3, "{replies:?}");
        assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
        let tools: Vec<&str> = replies[1]["result"]["tools"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t["name"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(tools, ["echo", "read_file"]);
        assert_eq!(replies[2]["error"]["code"], -32601);
    }
}
