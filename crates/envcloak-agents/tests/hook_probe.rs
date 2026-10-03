//! Gate 11 (SPEC §15.2) for the hook's decision (lesson L-12; the review's
//! finding that the parsed payload and the prompt check's copies were left
//! in unwiped memory): deciding a prompt or a tool call that holds a key
//! frees no block that still holds it.
//!
//! - With the allocator's own wipe off (`ProbeMode::Unwiped`), for prompts
//!   and MCP tool calls whose strings need no JSON escape: what the hook's
//!   own code copies (the parsed object's strings and keys, the prompt
//!   check's copies, the bytes a path or an MCP argument is read as for its
//!   class) it wipes itself.
//! - With the wipe the `envcloak` binary's allocator does on every free
//!   (`ProbeMode::Wiping`, `envcloak_sys::WipingAllocator`, which
//!   crates/envcloak-cli/src/main.rs installs), for every payload: what is
//!   not the hook's own to wipe (serde_json's scratch buffer for an escaped
//!   string, the blocks a growing buffer of the command reader outgrows)
//!   leaves nothing either.
//!
//! One test, so no other test's allocations run while the probe is armed.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use envcloak_agents::hook::{Decision, Event, Host, decide};
use envcloak_core::SecretBuf;
use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};
use serde_json::{Value, json};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn captured(host: Host, event: &str) -> Value {
    let dir = match host {
        Host::ClaudeCode => "claude-code-2.1.280",
        Host::Codex => "codex-0.159.2",
    };
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../envcloak-e2e/tests/fixtures/hook-payloads")
        .join(dir)
        .join(format!("{event}.json"));
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

fn buf(v: &Value) -> SecretBuf {
    let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(v).unwrap());
    let mut b = SecretBuf::with_capacity(bytes.len());
    b.extend(&bytes).unwrap();
    zeroize::Zeroize::zeroize(&mut *bytes);
    b
}

/// Mutations checked: `payload::Wiped`'s `Drop` taken out (the parsed
/// object dropped as serde_json leaves it, as before): the unwiped run
/// finds the key in freed blocks and this fails. `shell::plain` returning
/// a plain `Vec` again: the MCP argument's bytes are freed unwiped and
/// this fails.
#[test]
fn deciding_leaves_no_key_in_freed_memory() {
    let cs = canaries(fresh_seed());

    // Negative control: the probe is armed and sees a plain copy.
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(
        by_label(&cs, labels::OPENAI_API_KEY).value().to_vec(),
    ));
    assert!(session.finish().released_with_needle >= 1);

    // Payloads are built before the probe is armed.
    let key = by_label(&cs, labels::OPENAI_API_KEY).as_str().to_owned();
    let token = by_label(&cs, labels::GITHUB_TOKEN).as_str().to_owned();
    let mut plain: Vec<(Host, Event, SecretBuf)> = Vec::new();
    let mut escaped: Vec<(Host, Event, SecretBuf)> = Vec::new();
    for host in [Host::ClaudeCode, Host::Codex] {
        let mut p = captured(host, "UserPromptSubmit");
        p["prompt"] = json!(format!("deploy with {key} please"));
        plain.push((host, Event::UserPromptSubmit, buf(&p)));
        p["prompt"] = json!(format!("use {token} for the repo"));
        plain.push((host, Event::UserPromptSubmit, buf(&p)));
        let (a, b) = key.split_at(key.len() / 2);
        p["prompt"] = json!(format!(
            "<pasted_content id=\"1\">\n{a}\n</pasted_content id=\"1\">\n<pasted_content \
             id=\"2\">\n{b}\n</pasted_content id=\"2\">"
        ));
        escaped.push((host, Event::UserPromptSubmit, buf(&p)));
        let mut t = captured(host, "PreToolUse");
        t["tool_name"] = json!("mcp__x__call");
        t["tool_input"] = json!({"token": key, "nested": [{"value": token}]});
        plain.push((host, Event::PreToolUse, buf(&t)));
        t["tool_name"] = json!("Bash");
        t["tool_input"] = json!({"command": format!("cat <<A\n{key}\nA\necho \"{token}\"")});
        escaped.push((host, Event::PreToolUse, buf(&t)));
    }

    for (mode, set) in [
        (ProbeMode::Unwiped, &plain),
        (ProbeMode::Wiping, &plain),
        (ProbeMode::Wiping, &escaped),
    ] {
        let session = probe_canaries(&cs, mode);
        let mut decided = 0;
        for (host, event, payload) in set {
            let d = decide(*host, *event, payload);
            assert_ne!(d, Decision::NoDecision, "{host:?} {event:?}");
            decided += 1;
        }
        let report = session.finish();
        assert_eq!(decided, set.len());
        assert!(report.freed > 0, "{mode:?} {report:?}");
        assert_eq!(report.released_with_needle, 0, "{mode:?} {report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{mode:?} {report:?}");
        }
    }
}
