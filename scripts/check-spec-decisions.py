#!/usr/bin/env python3
"""Checks that docs/SPEC.md carries the M2 and M2b build decisions as the
SPEC v0.4 pull request wrote them (plan task M2-01), and the M3 build
decisions as SPEC v0.4.1 wrote them (M3 plan task M3-01).

- Every decision D-01 to D-36 of the M2 plan is listed once below, in order,
  either as an edit, with phrases its SPEC edit wrote, or as "no edit", with
  where the decision lives instead. Each phrase of an edit must be in the
  SPEC.
- The sentences the plan fixed word for word are in the SPEC exactly once:
  the §1.1 inject-mode sentence, the §6.8 worker sentences and gate b12
  (review F-74), §10b rule 6 for managed projects and §4.4's sentence on
  daemon-started recipients (review CR-1), the §6.1 PTY signals paragraph
  (F-76, CR-4), and gates 38 and 39 as narrowed.
- So are the sentences that carry a decision's security property on their
  own: the browser supervisor's tool allowlist (D-30) and its grant check
  on every tool call (D-31); which identities, keys and subjects a
  standing approval can cover (D-10, D-11); how a bound launch runs what
  was checked, from a sealed copy on Linux and after a code directory
  check on macOS, and that nothing else is bound or standing-capable
  (D-33); what a bound launch does not bind (its libraries), and that a
  program that cannot run from the sealed copy is never run from its file
  instead (D-33); the sealed copy the daemon starts its own modes from,
  and that managed servers are unavailable where it cannot be executed
  (D-36); the daemon's own executable as the only source of the sign-in
  reaper and driver (D-25, D-36); and gate 39's launch binding. Since
  M2-RES1 also: the HTTP relay's host rule as D-18 has it (a known
  provider's `allowed_hosts` bound the host; an unknown provider's server
  is not refused for it), dev sign-in unavailable where the sealed copy is
  (D-36), and reclassifying an item towards `test` or `unknown` as a
  passphrase-proven write in §4.3 and §10b.
- The wording they replaced is gone, in any letter case, and nothing makes
  a release depend on the requesting process's code: not on EnvCloak's own
  `envcloak` (backticked or not), not on the requester, caller, client,
  peer, bridge or `envcloak mcp` being the `envcloak` binary, and not on
  their executable, binary, code, signature, hash, SHA-256, cdhash, Team
  ID or signing identifier matching anything, nor on the requester being
  signed by anyone, its executable hashing to anything, its code
  signature satisfying a requirement, it running the `envcloak` binary,
  or `/proc/<pid>/exe` of it being anything. The daemon cannot identify a
  hardened client's code on Linux (CR-1). These patterns catch the
  wordings reviewers wrote, and the paraphrases a review found passing
  (M2R-4); one they still miss is left to code-owner review of SPEC edits
  (.github/CODEOWNERS names docs/SPEC.md from task M3-01), which `main`'s
  branch protection must require (plan §3). Until it does, that review is
  not enforced, and such a sentence passes this check.
- Every decision D3-01 to D3-18 of the M3 plan is listed once, in order,
  in the same way (SPEC v0.4.1, task M3-01). D3-15 says the SPEC changes
  only on its fallback; the dependency trial's measurement (hpke 0.14
  compiles `zeroize_derive` on every target, X25519 `curve25519-dalek-
  derive` on x86_64) corrected §11, so it is an edit. The sentences that
  carry an M3 decision's security property are in the SPEC exactly once:
  the app role's runtime conditions and its verdict per connection, a peer
  that fails them kept a client peer (D3-06, gate 22), the app role's
  methods (the unlockers it removes, never the Recovery Kit's or the last
  daily one) and the client's reveal request, every §4.4 crossing of the
  app with its request metadata named whole (the plan's wording check: a
  list left without the new crossings fails) and the app's calls of
  client methods, the app's sealed reveal named as the one exception to
  the one-rule bullet and that bullet's last clause scoped to client
  processes, the unlockers the app removes (§5) and "Touch ID only" held
  by removing the earlier unlocker (§12), screen lock and a session
  switch reported through the app role, no client able to report them
  and a program that can post the app's signal able to, §6.7's reveal
  domain and who `envcloak reveal` files for, the signed form of a proof,
  its statement domains and the first unlocker approved with the
  passphrase (D3-08, D3-10), a passphrase proof only from a terminal
  subject and a signed one or a Secure Enclave unlock only from the app
  role, every app request but `app.lock` refused from an app an agent
  started (so no Touch ID prompt appears), the honest limit of that
  evidence, gate 23 and §10a's orphan rule scoped to passphrase and
  Recovery Kit proofs, and the macOS 26 floor (D3-04). The wording they
  replaced is gone: the macOS 14 floor, the screen lock any program
  could report and the claim that no other program can, the proof taken
  only from a terminal subject, the old app-role and app-to-daemon lists
  and request metadata, the app's client calls as a closed list, an
  unlocker statement the app signs, the passphrase-only removal that
  left "Touch ID only" to the keychain, a refusal of signed proofs
  alone, gate 23 and §10a over every proof, and a release clause that
  covers the app.
- The status line says v0.4.1, and the file holds no em dash.

Runs of whitespace, line breaks included, count as one space in the SPEC
and in every phrase, so rewrapping a sentence neither hides nor breaks it.

With `--pr-files BASE HEAD`, it also checks that the SPEC pull request
(`git diff --name-only BASE...HEAD`) changes docs/SPEC.md and nothing else.

Usage: scripts/check-spec-decisions.py [--root <dir>] [--pr-files BASE HEAD]
Prints "check-spec-decisions: ok" and exits 0, or names every problem on
stderr and exits 1.
"""

import os
import re
import subprocess
import sys

SPEC = "docs/SPEC.md"

# The plan's decisions: ("edit", phrases the SPEC must hold) or
# ("no edit", where the decision is carried instead).
DECISIONS = [
    ("D-01", "edit", ["hand-written on `serde_json` (§11)", "a hand-written MCP server (newline-delimited JSON-RPC on `serde_json`"]),
    ("D-02", "edit", ["envcloak-client     the CLI's reusable client modules", "The crate graph is one-way"]),
    ("D-03", "edit", ["`run_with_secrets` starts a child `envcloak run`", "Commands it starts run outside the agent host's sandbox"]),
    ("D-04", "edit", ["`envcloak pending [--json]`", "It never holds a connection open while it waits"]),
    ("D-05", "edit", ["`envcloak run --launch <id>` (started by the daemon only; §6.6)", "written by migrate-mcp on this device", "managed project directory"]),
    ("D-06", "edit", ["candidate tokens from `doctor`, `scrub`, `migrate-mcp` and machine scans", "Daemon to a process it started itself"]),
    ("D-07", "edit", ["seals into each backup who created it"]),
    ("D-08", "no edit", "docs/VAULT.md: the one vault migration, schema version 2 (M2-07)"),
    ("D-09", "no edit", "SPEC §6.1 step 3 already schedules the Linux executable SHA-256 for M2"),
    ("D-10", "edit", ["Approval signing key without a Secure Enclave (M5)", "`identity_outside_install_tree`", "`policy_epoch_unverified`"]),
    ("D-11", "edit", ["`live_not_ticked`", "`envcloak-statement/2`"]),
    ("D-12", "no edit", "SPEC §7.2 rule 3 already keeps hook decisions local and deterministic"),
    ("D-13", "edit", ["run against a local scripted model", "A fixture found in any of those runs holds the release"]),
    ("D-14", "edit", ["`fails_open_on_timeout`", "**Tier 2,", "Documented capabilities as of 2026-10-01"]),
    ("D-15", "edit", ["`paste-cache/`, `file-history/` and `~/.claude/backups/`"]),
    ("D-16", "no edit", "installer practice, in docs/INSTALLERS.md (M2-08)"),
    ("D-17", "edit", ["`http_headers_helper` and `env_http_headers`"]),
    ("D-18", "edit", ["`envcloak mcp-bridge --relay`", "The URL's exact origin is part of the binding's identity"]),
    ("D-19", "edit", ["`pty_unavailable`", "the CR LF form of every value that contains LF"]),
    ("D-20", "edit", ["`app_required`", "ask the person to run `envcloak add <provider>` in their own terminal", "listed from M4"]),
    ("D-21", "edit", ["1Password's 1PUX format comes later"]),
    ("D-22", "edit", ["Host approval is set per tool, never per server", "`destructiveHint`"]),
    ("D-23", "no edit", "docs/IPC.md and docs/VAULT.md hold the reservations (M2-01)"),
    ("D-24", "edit", ["envcloak-signin     pure sign-in contract", "envcloak-browser    sign-in driver"]),
    ("D-25", "edit", ["`envcloakd --signin-driver`", "each attempt's sign-in driver (`envcloakd --signin-driver`) receives a login's username and password from the daemon, one step at a time"]),
    ("D-26", "edit", ["Origins are registered in ASCII only", "no `url` or `idna` crate"]),
    ("D-27", "edit", ["`handoff_required`", "A CAPTCHA or other handoff state stops the attempt"]),
    ("D-28", "no edit", "docs/SIGNIN-ADAPTER.md (M2b-06)"),
    ("D-29", "no edit", "packaging and pinning, in docs/SIGNIN.md (M2b-02, M2b-08)"),
    ("D-30", "edit", ["The supervisor serves a fixed tool allowlist"]),
    ("D-31", "edit", ["`envcloak mcp --browser-supervisor`", "the requesting process instance that is to receive the browser tools"]),
    ("D-32", "edit", ["a short value is neither found nor removed"]),
    ("D-33", "edit", ["registered launch", "`code_selecting_env`", "`checked_at_rest`", "`envcloak agents migrate-mcp --update <agent>/<server> [--cwd <dir>]", "a sealed in-memory file"]),
    ("D-34", "edit", ["`cleanup_unconfirmed`", "EnvCloak signals only processes it owns"]),
    ("D-35", "edit", ["whose leader is EnvCloak's PTY monitor", "`pty_monitor_lost`"]),
    ("D-36", "edit", ["Daemon-started modes of `envcloak`", "no release depends on identifying the requesting process's code", "a sealed in-memory copy of that `envcloak`"]),
]

# The M3 plan's decisions, in the same form (SPEC v0.4.1, task M3-01).
M3_DECISIONS = [
    ("D3-01", "no edit", "M3 plan §1.1's order; SPEC §4.2 and §12 already say an unsigned build reports the daemon identity unverified"),
    ("D3-02", "no edit", "the lane rules of the M3 plan (§1.2, §5) and .github/CODEOWNERS"),
    ("D3-03", "no edit", "docs/APP.md: the Swift client and its cross-language vectors (M3-03)"),
    ("D3-04", "edit", ["SwiftUI, macOS 26 or later, Swift 6."]),
    ("D3-05", "no edit", "docs/APP.md: the signing tiers; SPEC §12 already separates M3 from M7"),
    ("D3-06", "edit", [
        '`identifier "ai.envcloak.app" and anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`',
        "The peer must also run with the hardened runtime flag",
        "`allow-dyld-environment-variables`",
        "keeps it for that connection alone",
        "against the daemon's pinned requirement and the runtime conditions of §4.3",
    ]),
    ("D3-07", "no edit", "SPEC §4.1 already allows the CLI's LaunchAgent by absolute path; docs/APP.md"),
    ("D3-08", "edit", [
        "The first Secure Enclave unlocker is approved with the passphrase",
        "the two public keys (`unlock` and `approve`) of a new Secure Enclave unlocker",
    ]),
    ("D3-09", "no edit", "docs/IPC.md \"Framing\": no client waits for a person on an open connection"),
    ("D3-10", "edit", [
        "`envcloak-unlocker-statement/1`",
        "`envcloak-write-statement/1`",
        "`envcloak-reveal-statement/1`",
        "sent as the 64-byte raw `r || s`",
    ]),
    ("D3-11", "edit", ["reported by the app through the app role, so no client can report either through the socket"]),
    ("D3-12", "no edit", "docs/APP.md and docs/VAULT.md: the anchor store (M3-16)"),
    ("D3-13", "no edit", "SPEC §6.4 already keeps machine scans out of the daemon and the app"),
    ("D3-14", "no edit", "SPEC §5 already shows the Recovery Kit only on the terminal"),
    ("D3-15", "edit", [
        "it compiles the proc-macro crate `zeroize_derive` on every target",
        "compiles `curve25519-dalek-derive` on x86_64",
    ]),
    ("D3-16", "no edit", "SPEC §1.1 already shows an unshipped feature as unavailable"),
    ("D3-17", "no edit", "docs/IPC.md \"Reserved for M3\": the `projects.list` row (Q3-04)"),
    ("D3-18", "no edit", "docs/APP.md: the founder build"),
]

REQUIRED = {
    "§1.1 inject-mode sentence": (
        "In inject mode, EnvCloak keeps keys out of files, configs and what reaches the model, "
        "but the command you approve holds the key while it runs, and a key pasted into some "
        "agents can persist in their local history until `envcloak scrub` (§7.1)"
    ),
    "§6.8 worker sentences (F-74)": (
        "In M2b, after an attempt EnvCloak retains no reusable worker-owned trust, refresh or "
        "session state: the worker process, its profile and its control channel end with the "
        "attempt. Deliberately delivered application state follows the delivery and "
        "stop-outcomes contract below."
    ),
    "gate b12 (F-74)": (
        "After an attempt, and across lock, expiry and daemon restart, EnvCloak retains no "
        "reusable worker-owned trust, refresh or session state: no worker process, profile "
        "directory or control channel remains, and no captured state is held outside a "
        "published recipient context. Deliberately delivered application state follows the "
        "delivery and stop-outcomes contract (§6.8) and is tested by the boundary-honesty and "
        "stop-outcome gates; this gate does not require the app to reject a delivered session."
    ),
    "§10b rule 6 for managed projects (CR-1)": (
        "For a managed project (§6.6), a request is covered only when it names the project's "
        "registered launch (or, for a bridged HTTP server, its registered origin and header "
        "names), and the daemon's check of that launch passes before any pending request or "
        "grant lookup: the executable, its identity, the working directory and, for a script, "
        "the entry file must equal what was registered with a proof. A covered request's values "
        "are never returned to the requesting process: the daemon starts EnvCloak's own runner "
        "(or HTTP relay), which receives them and starts the checked executable with the "
        "registered argv, working directory and environment, never the caller's. A grant or "
        "standing approval covers only the launch revision it was made for. A changed launch is "
        "refused and must be re-registered by the person. A launch whose code EnvCloak can check "
        "only at rest (interpreter scripts, package runners) gets once and session approvals, "
        "never standing approvals."
    ),
    "§4.4 daemon-started recipients (CR-1)": (
        "The daemon sends a value or captured session state to a process other than an "
        "`envcloak run` in inject mode only when it started that process itself: EnvCloak's "
        "runner for a managed server, its HTTP relay for a bridged server, and its browser "
        "supervisor for a sign-in operation, each over an inherited pipe."
    ),
    "§6.1 PTY signals (F-76, CR-4)": (
        "In PTY mode the command runs as the foreground process group of a new session whose "
        "leader is EnvCloak's PTY monitor. Typing the terminal's suspend character stops the "
        "command, restores your terminal and suspends `envcloak run` in your shell; `fg` "
        "resumes both. A nested shell keeps its own job control, and a raw-mode program that "
        "reads the suspend character itself keeps doing so. SIGINT, SIGQUIT, SIGTERM and SIGHUP "
        "sent to `envcloak run` by another process reach the terminal's foreground job, the job "
        "a nested shell is running included, as the terminal's own keys would; where a system "
        "cannot deliver one of them that way, `envcloak run --pty` documents it and sends that "
        "signal to the command's own process group."
    ),
    "gate 38, first bullet": (
        "Activation and denial probes run in an isolated HOME for each agent whose host the "
        "scripted model can drive in CI (Claude Code and Codex, and any tier-2 host the "
        "drivability check of §7.1 qualifies); every other agent reports each surface "
        "`unverified` with a reason token and never `active`."
    ),
    "§6.8 tool allowlist (D-30)": (
        "The supervisor serves a fixed tool allowlist, the same for listing and calling: the "
        "page-interaction tools, with every `filename` or output-path argument removed from their "
        "schemas and refused if sent; no tool that runs code in the helper process, uploads a "
        "local file, installs a browser or belongs to an optional capability group; and "
        "navigation to any scheme other than `http` and `https` refused."
    ),
    "§6.8 grant check on every tool call (D-31)": (
        "The supervisor checks the grant with the daemon on every tool call, not only when a "
        "context is first handed over."
    ),
    "gate 39": (
        "No literal secret remains in the MCP server entries of the covered agents' JSON and "
        "TOML configs (Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI, Kimi, OpenCode); "
        "YAML configs, key-shaped `args` literals and stores that hold an agent's own "
        "credentials are reported as manual and the command exits non-zero."
    ),
    "gate 39 launch binding (D-33)": (
        "Only a managed server's registered launch receives its key: a launch whose executable "
        "was replaced is refused, and a `bound` launch whose executable is rewritten in place "
        "after the daemon's last check runs the checked image, never the rewritten one."
    ),
    "§10b standing identity (D-10)": (
        "The identity is the kernel's view of that request's nearest agent, never a path or "
        "name a program can copy: on macOS its code signature (Team ID and signing "
        "identifier), on Linux the SHA-256 of its executable. Only a builtin catalog match on "
        "the executable path or code signature qualifies; an agent launched by an interpreter, "
        "recognized only by a user extension, or asserted by its name or markers is refused "
        "(`identity_not_standing_capable`)."
    ),
    "§10b standing keys (D-10, D-11)": (
        "It covers test-classified keys only; live keys, and keys classified `unknown`, are "
        "never standing."
    ),
    "§10b standing subjects (D-10)": (
        "A standing approval never covers a terminal or unknown subject."
    ),
    "§6.6 Linux runs the sealed copy it checked (D-33)": (
        "A file can be rewritten in place after any check of it, so on Linux a `bound` launch "
        "never runs from its file: the daemon copies the executable, through the descriptor it "
        "checked, into a sealed in-memory file (a memfd sealed against writing, growing and "
        "shrinking), computes the identity over that sealed copy and compares it with the "
        "record, and the runner executes the copy (`execveat`), so the bytes that run are the "
        "bytes that were hashed, whatever happens to the file afterwards."
    ),
    "§6.6 macOS checks the suspended child (D-33)": (
        "On macOS the runner starts the checked path suspended, the daemon compares the "
        "suspended child's code directory hash with the record, and the child runs only if "
        "they match."
    ),
    "§6.6 nothing else is bound (D-33)": (
        "A launch that cannot run this way is not `bound`."
    ),
    "§6.6 only bound launches are standing (D-33)": (
        "Only `bound` launches can have standing approvals (§10b)."
    ),
    "§6.6 the daemon's own modes run from a sealed copy (D-36)": (
        "On Linux the daemon starts them from a sealed in-memory copy of that `envcloak`, made "
        "and hashed once when the daemon starts, so a change to the file after the daemon "
        "started never reaches a process that receives a value, and an upgraded `envcloak` "
        "takes effect when the daemon restarts; on macOS from a suspended start whose code "
        "directory hash must equal the one the daemon read when it started."
    ),
    "§6.6 a bound launch binds the main executable only (D-33)": (
        "A `bound` launch binds the server's main executable only, not the dynamic loader, the "
        "shared libraries it loads or anything they load, so a program running as you that can "
        "write those files (as in a Homebrew or Linuxbrew prefix) can change what the server "
        "runs; the launch receipt says so."
    ),
    "§6.6 never started from its file instead (D-33)": (
        "A program that reads its own path only while it runs (through `/proc/self/exe`) cannot "
        "be recognised before it starts: from the copy it may fail to start, and it is then "
        "never started from its file instead."
    ),
    "§6.6 no sealed copy, no managed servers (D-36)": (
        "On a system whose kernel or security policy refuses to execute a sealed memfd (for "
        "example `vm.memfd_noexec=2`), the daemon cannot start its own runner or relay either "
        "(below), so managed servers are unavailable there: a request for one is refused with "
        "`runner_unavailable`, and the server is reported as manual."
    ),
    "§6.6 the relay's host rule (D-18)": (
        "sends it, when the provider is known, only to a host within that provider's "
        "`allowed_hosts`"
    ),
    "§6.8 no sealed copy, no dev sign-in (D-36)": (
        "Where that sealed copy cannot be made or executed (for example under "
        "`vm.memfd_noexec=2`, as for managed servers in §6.6), dev sign-in is unavailable: a "
        "sign-in request is refused with `runner_unavailable`, and `envcloak agents status` and "
        "the sign-in tool's result say so."
    ),
    "§4.3 reclassification is passphrase-proven (M2-13)": (
        "and reclassifying an item towards `test` or `unknown` (§10b)"
    ),
    "§10b reclassification needs a proof (M2-13)": (
        "reclassifying an item towards `test` or `unknown` (M2), which loosens the live-key guard "
        "and, towards `test`, what a standing approval can cover."
    ),
    "§4.3 the app role's runtime conditions (D3-06)": (
        "The peer must also run with the hardened runtime flag and carry neither "
        "`com.apple.security.get-task-allow` nor any of the hardened runtime's exception "
        "entitlements (`com.apple.security.cs.allow-jit`, `allow-unsigned-executable-memory`, "
        "`allow-dyld-environment-variables`, `disable-library-validation`, "
        "`disable-executable-page-protection` and `debugger`), since each of them lets another "
        "process run code inside the signed app."
    ),
    "§4.3 the app role's verdict per connection (D3-06)": (
        "The daemon takes this verdict at the connection's first `app` request and keeps it for "
        "that connection alone, which it closes unanswered once another process sends on it"
    ),
    "§4.3 a peer that fails is a client peer (D3-06, gate 22)": (
        "From M3, a peer that does not meet every condition of the `app` role is a client peer, "
        "and its `app` requests are rejected and audited the same way (gate 22)."
    ),
    "§4.3 the app role's methods (D3-08, M3-01)": (
        "Its methods are: unlock with the Secure Enclave; enrolling and removing Secure Enclave "
        "unlockers, and removing the passphrase unlocker, never the Recovery Kit's and never the "
        "last daily unlocker (§5); the list of pending requests, and approval with a "
        "signature; replacing and removing an item with a signature; reveal; paste-sheet ingest, "
        "and answering the keys `envcloak add --ask` asks for (§6.3); the audit log's entries; and "
        "lock with a reason (§5 \"Lock\")."
    ),
    "§4.3 the client's ask and reveal request (M3-01)": (
        "`request_new_secret` (from M3, the ask `envcloak add --ask` files for the app's paste "
        "sheet, and its state, §6.3), the reveal request `envcloak reveal` files for the app on "
        "macOS (M3, §6.7),"
    ),
    "§4.4 app to daemon (M3-01)": (
        "App to daemon: one HPKE-sealed VMK per unlock; the two public keys (`unlock` and "
        "`approve`) of a new Secure Enclave unlocker; signed approval, write, reveal, policy and "
        "device statements; values typed into the paste sheet and replacement values, each sealed "
        "to a daemon ephemeral key; the app's ephemeral public key for a sealed reveal; and request "
        "metadata, never a value or a proof (the claims every request carries, request, ask and "
        "unlocker ids, an unlocker's label, an approval's options, the lock reason, slugs and fields, "
        "a new item's provider, account and environment hint, and the audit log's filters)."
    ),
    "§4.4 daemon to app (M3-01)": (
        "Daemon to app: envelopes (ciphertext); approval request descriptors (metadata only); "
        "audit entries (metadata only, with command lines masked as the audit log keeps them); "
        "the paste and reveal requests the CLI filed (`envcloak add --ask`, `envcloak reveal`), "
        "metadata only, with the requester's evidence; other metadata: daemon ephemeral public "
        "keys, challenges and nonces, ids and outcomes (a grant's id and expiry, an enrolment's "
        "result, a new item's slug, the grants a write ended), and item metadata (slug, fields, "
        "bindings, grants, the count "
        "of prior values and the classification); the paste sheet's reading of a staged value "
        "(provider, class, length class, suggested slug and variable), never the value; reveal "
        "values sealed to an app ephemeral key after a signed reveal statement."
    ),
    "§4.4 the app's calls of client methods (M3-01)": (
        "The app's calls of client-role methods (such as `status`, the listing methods, `deny`, "
        "`grants.revoke`, `lock` and, before the `app` role exists, `items.add`) cross as a "
        "client's, under the two client bullets below."
    ),
    "§4.4 the app's sealed reveal, the one rule's exception (M3-01)": (
        "from the reveal values the `app` role receives sealed after a signed reveal statement "
        "(above),"
    ),
    "§4.4 no release to a client process rests on its code (M3-01)": (
        "and for a client process no release depends on identifying the requesting process's "
        "code: the daemon cannot read a hardened client's executable on Linux. The `app` role's "
        "sealed reveal, the one release to a peer chosen by its code signature, exists on macOS "
        "alone (§4.3)."
    ),
    "§5 screen lock and a session switch through the app role (D3-11)": (
        "screen lock, and a switch to another user's login session (each reported by the app "
        "through the app role, so no client can report either through the socket; the app hears "
        "of each from the system, and a program running as you that can post the signal the app "
        "listens for, which docs/APP.md names, can make it report one: the vault then locks early "
        "under that reason);"
    ),
    "§5 the unlockers the app removes (M3-01)": (
        "The app removes an unlocker only under a signed `envcloak-write-statement/1` (§10b): the "
        "passphrase unlocker or a Secure Enclave unlocker, never the Recovery Kit's, and never one "
        "whose removal would leave the vault without a daily unlocker (the passphrase or a Secure "
        "Enclave unlocker). Removing a Secure Enclave unlocker deletes its envelope and its "
        "`approve` public key from the vault, so the daemon takes neither of its keys again, "
        "whatever the keychain still holds."
    ),
    "§12 \"Touch ID only\" removes the earlier unlocker (M3-01)": (
        "An optional \"Touch ID only\" setting uses `biometryCurrentSet` on Macs with Touch ID: the "
        "app enrols a Secure Enclave unlocker whose keys require it and removes the earlier one "
        "(§5), so the daemon no longer takes the earlier keys, which accept the login password."
    ),
    "§6.7 the reveal statement's domain (D3-10)": (
        "The app shows the value after a signed reveal statement (Secure Enclave, reuse 0; domain "
        "`envcloak-reveal-statement/1`, §10b)"
    ),
    "§6.7 who `envcloak reveal` files a request for (M3-01)": (
        "On macOS, `envcloak reveal` files a request for the app only from a terminal subject: "
        "an agent, unknown or terminal-less caller gets `proof_refused`, and nothing is filed."
    ),
    "§10b the statement domains (D3-10)": (
        "Each statement starts with its domain: `envcloak-statement/1` for run approvals "
        "(`envcloak-statement/2` once the live-key guard lands), `envcloak-unlocker-statement/1` "
        "for adding a Secure Enclave unlocker with the passphrase in a terminal, "
        "`envcloak-write-statement/1` for replacing or removing an item, adding or removing a "
        "Secure Enclave unlocker and removing the passphrase unlocker in the app, and "
        "`envcloak-reveal-statement/1` for a reveal in the app (§6.7)."
    ),
    "§10b an app an agent started takes no proof and shows no prompt (M3-01)": (
        "From an `app` peer whose evidence names an agent (a known agent in its ancestry or agent "
        "markers in its claims, as when an agent runs the app's executable itself) or whose chain "
        "is cut at the walk's depth limit, it takes no signed proof and no Secure Enclave unlock: "
        "it refuses every `app` request of that peer but `app.lock` (`proof_refused`, audited) "
        "before answering anything, so `app.unlock.begin` sends no envelope, the pending list "
        "shows no request and no Touch ID prompt appears; `app.lock` is answered, since locking "
        "only tightens. The conditions only a terminal subject meets (a controlling terminal, an "
        "ancestry that reaches its session leader) are not asked of the app, which launchd "
        "starts."
    ),
    "§10b the honest limit of an app peer's evidence (M3-01)": (
        "An `app` peer's evidence names an agent only when the agent runs the app's executable "
        "itself. An agent that starts the app through LaunchServices (`open -a`), or whose app "
        "outlives it and is reparented to launchd, leaves evidence that names no agent; there the "
        "guard is user presence on the Secure Enclave key (Touch ID, or the login password) for "
        "the statement the app renders, and such an agent can still make a prompt appear."
    ),
    "gate 23 which proofs need a terminal session (M3-01)": (
        "Passphrase and Recovery Kit proofs from an agent-descended caller are refused, and so are "
        "those from a caller without a terminal session (a service manager's job, `setsid`). "
        "Signed proofs and Secure Enclave unlocks are taken only from the `app` role, which "
        "launchd starts, and never from an `app` peer whose evidence names an agent or whose "
        "chain is cut at the walk's depth limit (M3)."
    ),
    "§10a an orphan's passphrase and Recovery Kit proofs (M3-01)": (
        "it is not a terminal subject and its passphrase and Recovery Kit proofs are refused (the "
        "app, which launchd starts, gives signed proofs under §10b's own rule)."
    ),
    "§10b the signed form of a proof (D3-10)": (
        "From the `app` role (§4.3, M3): a P-256 ECDSA signature by the `approve` key of a Secure "
        "Enclave unlocker enrolled in the vault, over the SHA-256 digest of the canonical statement "
        "as a prehash, sent as the 64-byte raw `r || s`; the daemon rebuilds the statement from its "
        "own record, verifies the signature with that unlocker's public key, and refuses a key that "
        "is not enrolled or was removed."
    ),
    "§10b the first unlocker approved with the passphrase (D3-08)": (
        "The first Secure Enclave unlocker is approved with the passphrase, since until it exists "
        "the app has no key to sign with: the app asks for it, and the person runs `envcloak "
        "approve <id>` in a terminal and reads an `envcloak-unlocker-statement/1` that names the "
        "unlocker's label, the SHA-256 fingerprints of both its public keys, and the Team ID and "
        "signing identifier the daemon verified for the app."
    ),
    "§10b which caller gives which proof (D3-10)": (
        "The daemon takes a passphrase or Recovery Kit proof (approve, unlock, rotate, remove, "
        "reveal, recover) only from a terminal subject (Subject kind, above), and a signed proof "
        "or a Secure Enclave unlock only from the `app` role, and refuses a passphrase or Recovery "
        "Kit proof from every other caller"
    ),
    "§12 the macOS 26 floor (D3-04)": "SwiftUI, macOS 26 or later, Swift 6.",
    "§6.8 the reaper and driver start from the daemon's own executable (D-25, D-36)": (
        "The daemon starts the reaper and the driver from its own executable as it was when the "
        "daemon started, never from a path it reads again: on Linux from a sealed in-memory copy "
        "of `envcloakd` made then, as it starts its own modes of `envcloak` (§6.6); on macOS from "
        "a suspended start whose code directory hash must equal its own."
    ),
}

# The parts of the CR-1 patterns below: who asks for a release, what of its
# code a check would read, and the verbs that make a release rest on it.
REQUESTER = (
    r"(?:requester|requesting (?:process|client)|caller|calling process|client|"
    r"connecting process|peer(?: process)?|bridge|`?mcp-bridge`?|`?envcloak mcp`?)"
)
CODE = (
    r"(?:(?:executable|binary|program|code)"
    r"(?: (?:identity|signature|hash|sha-256|cdhash|code directory hash|team id|signing identifier))?"
    r"|code directory hash|signature|hash|sha-256|cdhash|team id|signing identifier)"
)
RESTS_ON = (
    r"(?:is|are|must|matches|match|equals|equal|comes from|come from|has to|"
    r"satisfies|satisfy|meets|meet|hashes to|hash to|verifies|verify)"
)

# What v0.4 replaced, as regular expressions over the SPEC with its
# whitespace collapsed, matched in any letter case; a plain phrase is
# escaped.
FORBIDDEN = {
    "the old gate b12": re.escape("no trust, refresh or session state from the worker remains usable"),
    "the old §6.8 worker sentence": re.escape("no trust, refresh or session state from the worker outlives the attempt"),
    "the file's own descriptor as the binding of a bound Linux launch (D-33)": re.escape("the runner executes the very descriptor the daemon checked"),
    "a release that rests on EnvCloak's own `envcloak` executable or binary (CR-1)": r"\bown `?envcloak\b",
    "a release that rests on the requester's code (CR-1)": (
        r"\b%s(?:'s|\u2019s| whose)?(?: own)? %s %s\b" % (REQUESTER, CODE, RESTS_ON)
    ),
    "a release that rests on the requester being EnvCloak's `envcloak` (CR-1)": (
        r"\b%s (?:is|must be|matches|equals|has to be|comes from) "
        r"(?:the |an? |envcloak's |envcloak\u2019s )?(?:own )?`?envcloak`?(?:'s)? "
        r"(?:binary|executable|program|code|command)\b" % REQUESTER
    ),
    "a release that rests on the requester's executable identity (CR-1)": re.escape("executable identity is EnvCloak's"),
    # The paraphrases a review found passing (M2R-4).
    "a release that rests on who signed the requester (CR-1)": (
        r"\b%s(?: process)?(?: that is| which is)? (?:signed|notari[sz]ed) (?:by|with)\b" % REQUESTER
    ),
    "a release that rests on the requester's code, named later in the sentence (CR-1)": (
        r"\b%s\b[^.;:]{0,160}?\b(?:its|their) %s %s\b" % (REQUESTER, CODE, RESTS_ON)
    ),
    "a release that rests on the requester running the `envcloak` binary (CR-1)": (
        r"\b%s(?: process)? (?:runs|is running|executes) (?:the |an? |envcloak's |envcloak\u2019s )?"
        r"(?:own |installed |released? )?`?envcloak`? (?:binary|executable|program|release)\b" % REQUESTER
    ),
    "a release that rests on the requester's `/proc/<pid>/exe` (CR-1)": (
        r"/proc/\S+/exe (?:of|for) (?:the |a |an |its )?%s" % REQUESTER
    ),
    "the old §1.1 inject-mode claim": re.escape("keeps keys out of files, prompts, configs and transcripts"),
    "the relay requiring a known provider for any HTTP server (D-18)": re.escape("requires a known provider's `allowed_hosts`"),
    "`rmcp` as the MCP library": re.escape("`rmcp` 3.x (pinned)"),
    "the old stdio rewrite form": re.escape("`args: [\"run\", \"--ref\""),
    "the old instruction 3": re.escape("`envcloak add <provider> --ask` so the user pastes it into the app"),
    "the server-wide Codex approval offer": re.escape("offer to set Codex's per-server MCP approval mode for EnvCloak only"),
    "IDNA normalisation of origins": re.escape("after URL parsing and IDNA normalisation"),
    "the M2b handoff pause": re.escape("(the app, or a terminal the person controls)"),
    "the old gate 38 bullet": re.escape("Activation and denial probes run for each agent in an isolated HOME, and coverage"),
    "the old gate 39": re.escape("No literal secret remains in any agent config."),
    "the old gate 41 release rule": re.escape("a host below that is published as"),
    # What v0.4.1 replaced (M3 plan, task M3-01).
    "the macOS 14 floor (D3-04)": r"\bmacOS 14\b",
    "the screen lock any program could report (D3-11)": re.escape("screen lock (reported by the app);"),
    "a proof taken only from a terminal subject, with no signed form (D3-10)": re.escape(
        "The daemon takes a proof (approve, unlock, rotate, remove, reveal, recover) only from a terminal subject"
    ),
    "the old app-to-daemon list (M3-01)": re.escape(
        "signed approval, policy, device and reveal statements; values typed into the paste sheet, sealed"
    ),
    "the old app-role list (M3-01)": re.escape(
        "Its methods are: unlock with the Secure Enclave, approve with a signature, policy.set"
    ),
    "an unlocker statement the app signs (M3-01)": r"\bsigned (?:[a-z]+, )*unlocker\b",
    "the passphrase-only removal, which left \"Touch ID only\" to the keychain (M3-01)": re.escape(
        "enrolling Secure Enclave unlockers, and removing the passphrase unlocker (§5)"
    ),
    "the claim that no other program can report a screen lock (M3-01)": re.escape(
        "so no other program can record either in the audit log"
    ),
    "the old request metadata, which left out what the rows send (M3-01)": re.escape(
        "and request metadata (request, ask and unlocker ids"
    ),
    "the app's client calls as a closed list (M3-01)": re.escape(
        "client-role methods (`status`, the listing methods and,"
    ),
    "a refusal of signed proofs alone, with the Secure Enclave unlock outside it (M3-01)": re.escape(
        "It refuses a signed proof from an `app` peer whose evidence names an agent"
    ),
    "gate 23's terminal rule over every proof (M3-01)": re.escape(
        "Proofs from an agent-descended caller are refused, and so are proofs from a caller without"
    ),
    "§10a's orphan rule over every proof (M3-01)": re.escape(
        "fails closed: it is not a terminal subject and its proofs are refused"
    ),
    "a release clause that covers the app (M3-01)": re.escape(
        "receives any of them, and no release depends on identifying"
    ),
    "an em dash": "\u2014",
}

STATUS = "Status: draft v0.4.1 "

problems = []


def fail(msg):
    problems.append(msg)


def flat(text):
    """`text` with every run of whitespace, line breaks included, as one
    space."""
    return re.sub(r"\s+", " ", text)


def check_spec(text):
    if not text.startswith("# EnvCloak: product and architecture spec\n\n" + STATUS):
        fail("the status line does not say draft v0.4.1")
    text = flat(text)
    ids = [d[0] for d in DECISIONS]
    expected = ["D-%02d" % n for n in range(1, 37)]
    if ids != expected:
        fail("the decision list is not D-01 to D-36, each once and in order")
    m3_ids = [d[0] for d in M3_DECISIONS]
    if m3_ids != ["D3-%02d" % n for n in range(1, 19)]:
        fail("the M3 decision list is not D3-01 to D3-18, each once and in order")
    for did, kind, what in DECISIONS + M3_DECISIONS:
        if kind == "edit":
            if not what:
                fail("%s is an edit with no phrase to check" % did)
            for phrase in what:
                if flat(phrase) not in text:
                    fail("%s: the SPEC lacks %r" % (did, phrase))
        elif kind == "no edit":
            if not isinstance(what, str) or not what.strip():
                fail("%s is \"no edit\" without saying where it is carried" % did)
        else:
            fail("%s: %r is neither \"edit\" nor \"no edit\"" % (did, kind))
    for name, sentence in REQUIRED.items():
        n = text.count(flat(sentence))
        if n != 1:
            fail("%s: found %d times, not once word for word" % (name, n))
    for name, pattern in FORBIDDEN.items():
        if re.search(pattern, text, re.IGNORECASE):
            fail("the SPEC still holds %s" % name)


def check_pr_files(root, base, head):
    try:
        out = subprocess.run(
            ["git", "-C", root, "diff", "--name-only", "%s...%s" % (base, head)],
            capture_output=True, check=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        fail("git diff %s...%s failed" % (base, head))
        return
    files = [f for f in out.split("\n") if f]
    if files != [SPEC]:
        fail("the SPEC pull request changes %s, not docs/SPEC.md alone" % (", ".join(files) or "nothing"))


def main(argv):
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    args = argv[1:]
    pr = None
    while args:
        if args[0] == "--root" and len(args) >= 2:
            root, args = args[1], args[2:]
        elif args[0] == "--pr-files" and len(args) >= 3:
            pr, args = (args[1], args[2]), args[3:]
        else:
            sys.exit("usage: scripts/check-spec-decisions.py [--root <dir>] [--pr-files BASE HEAD]")
    try:
        with open(os.path.join(root, SPEC), encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        fail("%s could not be read as UTF-8" % SPEC)
        text = None
    if text is not None:
        check_spec(text)
    if pr:
        check_pr_files(root, *pr)
    if problems:
        for p in problems:
            print("check-spec-decisions: " + p, file=sys.stderr)
        return 1
    print("check-spec-decisions: ok (%d decisions, %d sentences)" % (len(DECISIONS) + len(M3_DECISIONS), len(REQUIRED)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
