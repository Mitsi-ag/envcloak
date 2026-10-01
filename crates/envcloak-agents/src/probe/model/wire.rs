//! The two wire protocols the scripted model speaks, as far as the pinned
//! hosts use them (M2 plan task M2-04, recorded in docs/ACCEPTANCE.md):
//!
//! - Anthropic Messages, `POST /v1/messages` (Claude Code adds
//!   `?beta=true`): the server-sent events `message_start`,
//!   `content_block_start`, `content_block_delta` (`text_delta`,
//!   `input_json_delta`), `content_block_stop`, `message_delta` and
//!   `message_stop`, or one JSON message when the request does not ask to
//!   stream;
//! - OpenAI Responses, `POST /v1/responses`: `response.created`,
//!   `response.in_progress`, per output item `response.output_item.added`,
//!   its content or argument events and `response.output_item.done`, then
//!   `response.completed`. The set is the one Codex 0.159.2 handles or
//!   ignores by name (`codex-rs/codex-api/src/sse/responses.rs`,
//!   `process_responses_event`), and `response.completed` carries the `id`
//!   and `usage` fields its `ResponseCompleted` requires.
//!
//! The step a request gets is chosen from the conversation it carries
//! ([`super::script`]); the reply is built whole, then sent with a
//! `Content-Length`.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::script::{Script, Step};

/// Which API a request was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Anthropic Messages.
    Messages,
    /// OpenAI Responses.
    Responses,
}

impl Api {
    /// The name recorded for it.
    pub fn name(self) -> &'static str {
        match self {
            Api::Messages => "messages",
            Api::Responses => "responses",
        }
    }
}

/// What the script gave a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// Step `n` (from 0).
    Step(usize),
    /// The side reply: the request offered no tools.
    Side,
    /// The conversation holds more calls than the script has steps.
    Exhausted,
    /// The step calls the shell and the request offers no shell tool.
    Mismatch,
}

impl Pick {
    /// The name recorded for it.
    pub fn name(self) -> String {
        match self {
            Pick::Step(n) => format!("step {n}"),
            Pick::Side => "side".to_owned(),
            Pick::Exhausted => "exhausted".to_owned(),
            Pick::Mismatch => "mismatch".to_owned(),
        }
    }
}

/// A reply body and its media type.
#[derive(Debug)]
pub struct Reply {
    pub content_type: &'static str,
    pub body: Zeroizing<Vec<u8>>,
}

/// A request body that is not the shape its API requires. Fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyError(pub &'static str);

/// What the step amounts to for one request, once the shell is resolved.
struct Turn {
    say: Option<String>,
    call: Option<Call>,
}

/// One tool call: its name, arguments and, for Responses, namespace.
struct Call {
    name: String,
    input: Value,
    namespace: Option<String>,
}

const EXHAUSTED: &str = "envcloak-probe-model: the script has no step for this request";
const MISMATCH: &str = "envcloak-probe-model: the request offers no shell tool";
const SIDE: &str = "ok";
/// The model every reply names. Never the request's: no reply echoes what
/// a request held.
const MODEL: &str = "ec-scripted";

/// The names of the tools a request offers.
fn offered(body: &Value) -> Vec<&str> {
    body.get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

fn offers_tools(body: &Value) -> bool {
    body.get("tools")
        .and_then(Value::as_array)
        .is_some_and(|t| !t.is_empty())
}

/// The turn a step makes for `api`, given the tools the request offers.
fn turn(step: &Step, api: Api, tools: &[&str]) -> Result<Turn, Pick> {
    let call = |name: &str, input: Value| Call {
        name: name.to_owned(),
        input,
        namespace: None,
    };
    let call = match (&step.shell, &step.tool) {
        (Some(cmd), _) => Some(match api {
            Api::Messages if tools.contains(&"Bash") => call(
                "Bash",
                json!({"command": cmd, "description": "scripted step"}),
            ),
            // Codex returns what a command printed so far after
            // `yield_time_ms` (10 s by default, 30 s at most) and expects the
            // model to poll; the longest wait keeps a scripted command whole.
            Api::Responses if tools.contains(&"exec_command") => {
                call("exec_command", json!({"cmd": cmd, "yield_time_ms": 30000}))
            }
            Api::Responses if tools.contains(&"shell") => {
                call("shell", json!({"command": ["bash", "-lc", cmd]}))
            }
            _ => return Err(Pick::Mismatch),
        }),
        (None, Some(name)) => {
            if api == Api::Messages && step.namespace.is_some() {
                return Err(Pick::Mismatch);
            }
            Some(Call {
                name: name.clone(),
                input: step.input.clone().unwrap_or_else(|| json!({})),
                namespace: step.namespace.clone(),
            })
        }
        (None, None) => None,
    };
    Ok(Turn {
        say: step.say.clone(),
        call,
    })
}

/// Picks the step for `body` and the turn it makes.
fn pick(body: &Value, api: Api, script: &Script, calls: usize) -> (Pick, Turn) {
    let text = |t: &str| Turn {
        say: Some(t.to_owned()),
        call: None,
    };
    if !offers_tools(body) {
        let side = script.side.as_deref().unwrap_or(SIDE);
        return (Pick::Side, text(side));
    }
    let Some(step) = script.step(calls) else {
        return (Pick::Exhausted, text(EXHAUSTED));
    };
    match turn(step, api, &offered(body)) {
        Ok(t) => (Pick::Step(calls), t),
        Err(p) => (p, text(MISMATCH)),
    }
}

/// Tool calls already in an Anthropic conversation: `tool_use` blocks of
/// assistant messages.
fn messages_calls(body: &Value) -> Result<usize, BodyError> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Err(BodyError("messages"));
    };
    Ok(messages
        .iter()
        .filter(|m| m.get("role").and_then(Value::as_str) == Some("assistant"))
        .filter_map(|m| m.get("content").and_then(Value::as_array))
        .flatten()
        .filter(|c| c.get("type").and_then(Value::as_str) == Some("tool_use"))
        .count())
}

/// Tool calls already in a Responses conversation: call items of `input`.
fn responses_calls(body: &Value) -> Result<usize, BodyError> {
    match body.get("input") {
        Some(Value::Array(items)) => Ok(items
            .iter()
            .filter(|i| {
                matches!(
                    i.get("type").and_then(Value::as_str),
                    Some("function_call" | "custom_tool_call" | "local_shell_call")
                )
            })
            .count()),
        Some(Value::String(_)) => Ok(0),
        _ => Err(BodyError("input")),
    }
}

fn sse(events: &[(&str, Value)]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for (name, data) in events {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"\ndata: ");
        // Serializing a Value into a Vec cannot fail.
        let _ = serde_json::to_writer(&mut *out, data);
        out.extend_from_slice(b"\n\n");
    }
    out
}

fn json_body(v: &Value) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    let _ = serde_json::to_writer(&mut *out, v);
    out
}

/// The reply to an Anthropic Messages request.
///
/// # Errors
/// [`BodyError`] when the body is not a Messages request.
pub fn messages(body: &Value, script: &Script, id: u64) -> Result<(Pick, Reply), BodyError> {
    if !body.is_object() {
        return Err(BodyError("not an object"));
    }
    let calls = messages_calls(body)?;
    let (pick, turn) = pick(body, Api::Messages, script, calls);
    let model = MODEL;
    let message_id = format!("msg_ecprobe{id:08}");
    let usage = json!({"input_tokens": 1, "output_tokens": 1});
    let mut content = Vec::new();
    if let Some(text) = &turn.say {
        content.push(json!({"type": "text", "text": text}));
    }
    if let Some(call) = &turn.call {
        content.push(json!({
            "type": "tool_use",
            "id": format!("toolu_ecprobe{id:08}"),
            "name": call.name,
            "input": call.input,
        }));
    }
    let stop = if turn.call.is_some() {
        "tool_use"
    } else {
        "end_turn"
    };
    if body.get("stream").and_then(Value::as_bool) != Some(true) {
        let message = json!({
            "id": message_id, "type": "message", "role": "assistant", "model": model,
            "content": content, "stop_reason": stop, "stop_sequence": null, "usage": usage,
        });
        return Ok((
            pick,
            Reply {
                content_type: "application/json",
                body: json_body(&message),
            },
        ));
    }
    let mut events = vec![(
        "message_start",
        json!({"type": "message_start", "message": {
            "id": message_id, "type": "message", "role": "assistant", "model": model,
            "content": [], "stop_reason": null, "stop_sequence": null, "usage": usage,
        }}),
    )];
    for (index, block) in content.iter().enumerate() {
        let (start, delta) = match block.get("type").and_then(Value::as_str) {
            Some("tool_use") => {
                let mut start = block.clone();
                start["input"] = json!({});
                let partial = serde_json::to_string(&block["input"]).unwrap_or_default();
                (
                    start,
                    json!({"type": "input_json_delta", "partial_json": partial}),
                )
            }
            _ => (
                json!({"type": "text", "text": ""}),
                json!({"type": "text_delta", "text": block["text"]}),
            ),
        };
        events.push((
            "content_block_start",
            json!({"type": "content_block_start", "index": index, "content_block": start}),
        ));
        events.push((
            "content_block_delta",
            json!({"type": "content_block_delta", "index": index, "delta": delta}),
        ));
        events.push((
            "content_block_stop",
            json!({"type": "content_block_stop", "index": index}),
        ));
    }
    events.push((
        "message_delta",
        json!({"type": "message_delta",
               "delta": {"stop_reason": stop, "stop_sequence": null},
               "usage": {"output_tokens": 1}}),
    ));
    events.push(("message_stop", json!({"type": "message_stop"})));
    Ok((
        pick,
        Reply {
            content_type: "text/event-stream",
            body: sse(&events),
        },
    ))
}

/// The reply to an OpenAI Responses request.
///
/// # Errors
/// [`BodyError`] when the body is not a Responses request.
pub fn responses(body: &Value, script: &Script, id: u64) -> Result<(Pick, Reply), BodyError> {
    if !body.is_object() {
        return Err(BodyError("not an object"));
    }
    let calls = responses_calls(body)?;
    let (pick, turn) = pick(body, Api::Responses, script, calls);
    let response_id = format!("resp_ecprobe{id:08}");
    let mut items = Vec::new();
    if let Some(text) = &turn.say {
        items.push(json!({
            "type": "message", "id": format!("msg_ecprobe{id:08}"), "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }));
    }
    if let Some(call) = &turn.call {
        let arguments = serde_json::to_string(&call.input).unwrap_or_default();
        let mut item = json!({
            "type": "function_call", "id": format!("fc_ecprobe{id:08}"), "status": "completed",
            "call_id": format!("call_ecprobe{id:08}"), "name": call.name, "arguments": arguments,
        });
        if let Some(ns) = &call.namespace {
            item["namespace"] = json!(ns);
        }
        items.push(item);
    }
    let usage = json!({
        "input_tokens": 1, "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": 2,
    });
    let response = |status: &str, output: &[Value]| {
        json!({"id": response_id, "object": "response", "status": status,
               "model": MODEL,
               "output": output, "usage": usage})
    };
    if body.get("stream").and_then(Value::as_bool) != Some(true) {
        return Ok((
            pick,
            Reply {
                content_type: "application/json",
                body: json_body(&response("completed", &items)),
            },
        ));
    }
    let mut seq = 0u64;
    let mut events: Vec<(&str, Value)> = Vec::new();
    let mut push = |name: &'static str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(seq);
        seq += 1;
        events.push((name, data));
    };
    push(
        "response.created",
        json!({"response": response("in_progress", &[])}),
    );
    push(
        "response.in_progress",
        json!({"response": response("in_progress", &[])}),
    );
    for (index, item) in items.iter().enumerate() {
        let mut added = item.clone();
        added["status"] = json!("in_progress");
        let item_id = item["id"].clone();
        if item["type"] == "message" {
            added["content"] = json!([]);
            push(
                "response.output_item.added",
                json!({"output_index": index, "item": added}),
            );
            let text = item["content"][0]["text"].clone();
            let part = |t: Value| json!({"type": "output_text", "text": t, "annotations": []});
            push(
                "response.content_part.added",
                json!({"output_index": index, "item_id": item_id, "content_index": 0,
                       "part": part(json!(""))}),
            );
            push(
                "response.output_text.delta",
                json!({"output_index": index, "item_id": item_id, "content_index": 0,
                       "delta": text}),
            );
            push(
                "response.output_text.done",
                json!({"output_index": index, "item_id": item_id, "content_index": 0,
                       "text": text}),
            );
            push(
                "response.content_part.done",
                json!({"output_index": index, "item_id": item_id, "content_index": 0,
                       "part": part(text.clone())}),
            );
        } else {
            added["arguments"] = json!("");
            push(
                "response.output_item.added",
                json!({"output_index": index, "item": added}),
            );
            push(
                "response.function_call_arguments.delta",
                json!({"output_index": index, "item_id": item_id, "delta": item["arguments"]}),
            );
            push(
                "response.function_call_arguments.done",
                json!({"output_index": index, "item_id": item_id,
                       "arguments": item["arguments"]}),
            );
        }
        push(
            "response.output_item.done",
            json!({"output_index": index, "item": item}),
        );
    }
    push(
        "response.completed",
        json!({"response": response("completed", &items)}),
    );
    Ok((
        pick,
        Reply {
            content_type: "text/event-stream",
            body: sse(&events),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script() -> Script {
        Script::parse(
            br#"{"steps":[{"say":"first","shell":"echo one"},
                          {"tool":"mcp__x__y","input":{"a":1}},
                          {"say":"done"}]}"#,
        )
        .unwrap_or_else(|e| panic!("{e}"))
    }

    fn events(body: &[u8]) -> Vec<(String, Value)> {
        let text = String::from_utf8_lossy(body);
        text.split("\n\n")
            .filter(|b| !b.is_empty())
            .map(|b| {
                let mut lines = b.lines();
                let name = lines.next().and_then(|l| l.strip_prefix("event: "));
                let data = lines.next().and_then(|l| l.strip_prefix("data: "));
                let data: Value = serde_json::from_str(data.unwrap_or("")).unwrap_or(Value::Null);
                (name.unwrap_or("").to_owned(), data)
            })
            .collect()
    }

    #[test]
    fn messages_steps_follow_the_conversation() {
        let s = script();
        let tools = json!([{"name": "Bash"}, {"name": "Read"}]);
        let first = json!({"model": "m", "stream": true, "tools": tools, "messages": [
            {"role": "user", "content": "hi"}]});
        let (pick, reply) = messages(&first, &s, 1).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pick, Pick::Step(0));
        let ev = events(&reply.body);
        let names: Vec<&str> = ev.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert_eq!(ev[4].1["content_block"]["name"], "Bash");
        let input: Value =
            serde_json::from_str(ev[5].1["delta"]["partial_json"].as_str().unwrap_or(""))
                .unwrap_or(Value::Null);
        assert_eq!(input["command"], "echo one");
        assert_eq!(ev[7].1["delta"]["stop_reason"], "tool_use");

        let second = json!({"stream": false, "tools": tools, "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "text", "text": "x"},
                                              {"type": "tool_use", "id": "a", "name": "Bash", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "one"}]}]});
        let (pick, reply) = messages(&second, &s, 2).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pick, Pick::Step(1));
        let msg: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        assert_eq!(msg["content"][0]["name"], "mcp__x__y");
        assert_eq!(msg["content"][0]["input"]["a"], 1);

        let side = json!({"messages": [{"role": "user", "content": "title?"}]});
        assert_eq!(messages(&side, &s, 3).map(|r| r.0), Ok(Pick::Side));
        let no_shell = json!({"tools": [{"name": "Read"}], "messages": []});
        assert_eq!(messages(&no_shell, &s, 4).map(|r| r.0), Ok(Pick::Mismatch));
        let calls: Vec<Value> = (0..3)
            .map(|_| json!({"role": "assistant", "content": [{"type": "tool_use"}]}))
            .collect();
        let past = json!({"tools": tools, "messages": calls});
        assert_eq!(messages(&past, &s, 5).map(|r| r.0), Ok(Pick::Exhausted));
        assert_eq!(
            messages(&json!({"tools": tools}), &s, 6).err(),
            Some(BodyError("messages"))
        );
        assert_eq!(
            messages(&json!([1]), &s, 7).err(),
            Some(BodyError("not an object"))
        );
    }

    #[test]
    fn a_namespaced_tool_is_called_in_its_namespace_under_responses_only() {
        let s = Script::parse(
            br#"{"steps":[{"tool":"whoami","namespace":"mcp__fixture","input":{}}]}"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let body = json!({"stream": false, "tools": [{"type": "namespace", "name": "mcp__fixture"}],
                          "input": []});
        let (pick, reply) = responses(&body, &s, 1).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pick, Pick::Step(0));
        let out: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        assert_eq!(out["output"][0]["name"], "whoami");
        assert_eq!(out["output"][0]["namespace"], "mcp__fixture");
        let body = json!({"tools": [{"name": "Bash"}], "messages": []});
        assert_eq!(messages(&body, &s, 2).map(|r| r.0), Ok(Pick::Mismatch));
    }

    #[test]
    fn responses_events_are_the_codex_set() {
        let s = script();
        let tools = json!([{"type": "function", "name": "exec_command"}]);
        let first = json!({"model": "m", "stream": true, "tools": tools, "input": [
            {"type": "message", "role": "user", "content": []}]});
        let (pick, reply) = responses(&first, &s, 1).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(pick, Pick::Step(0));
        let ev = events(&reply.body);
        // Every event is one Codex 0.159.2 handles or ignores by name.
        const KNOWN: [&str; 11] = [
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "response.output_item.done",
            "response.completed",
        ];
        for (name, data) in &ev {
            assert!(KNOWN.contains(&name.as_str()), "{name}");
            assert_eq!(data["type"], name.as_str());
        }
        let done: Vec<&Value> = ev
            .iter()
            .filter(|(n, _)| n == "response.output_item.done")
            .map(|(_, d)| &d["item"])
            .collect();
        assert_eq!(done.len(), 2);
        assert_eq!(done[0]["content"][0]["text"], "first");
        assert_eq!(done[1]["name"], "exec_command");
        let args: Value = serde_json::from_str(done[1]["arguments"].as_str().unwrap_or(""))
            .unwrap_or(Value::Null);
        assert_eq!(args["cmd"], "echo one");
        let completed = &ev[ev.len() - 1].1["response"];
        assert!(completed["id"].is_string());
        for field in ["input_tokens", "output_tokens", "total_tokens"] {
            assert!(completed["usage"][field].is_i64(), "{field}");
        }

        let older = json!({"tools": [{"name": "shell"}], "input": []});
        let (_, reply) = responses(&older, &s, 2).unwrap_or_else(|e| panic!("{e:?}"));
        let out: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        let args: Value =
            serde_json::from_str(out["output"][1]["arguments"].as_str().unwrap_or(""))
                .unwrap_or(Value::Null);
        assert_eq!(args["command"], json!(["bash", "-lc", "echo one"]));

        let after = json!({"tools": tools, "input": [
            {"type": "function_call"}, {"type": "function_call_output"}]});
        assert_eq!(responses(&after, &s, 3).map(|r| r.0), Ok(Pick::Step(1)));
        assert_eq!(
            responses(&json!({"tools": tools, "input": "hi"}), &s, 4).map(|r| r.0),
            Ok(Pick::Step(0))
        );
        assert_eq!(
            responses(&json!({"tools": tools, "input": 3}), &s, 5).err(),
            Some(BodyError("input"))
        );
    }
}
