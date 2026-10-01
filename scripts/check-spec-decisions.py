#!/usr/bin/env python3
"""Checks that docs/SPEC.md carries the M2 and M2b build decisions as the
SPEC v0.4 pull request wrote them (plan task M2-01).

- Every decision D-01 to D-36 of the M2 plan is listed once below, in order,
  either as an edit, with phrases its SPEC edit wrote, or as "no edit", with
  where the decision lives instead. Each phrase of an edit must be in the
  SPEC.
- The sentences the plan fixed word for word are in the SPEC exactly once:
  the §1.1 inject-mode sentence, the §6.8 worker sentences and gate b12
  (review F-74), §10b rule 6 for managed projects and §4.4's sentence on
  daemon-started recipients (review CR-1), the §6.1 PTY signals paragraph
  (F-76, CR-4), and gates 38 and 39 as narrowed.
- The wording they replaced is gone, and nothing makes a release depend on
  EnvCloak's own `envcloak` executable: the daemon cannot identify a
  hardened client's code on Linux (CR-1).
- The status line says v0.4, and the file holds no em dash.

With `--pr-files BASE HEAD`, it also checks that the SPEC pull request
(`git diff --name-only BASE...HEAD`) changes docs/SPEC.md and nothing else.

Usage: scripts/check-spec-decisions.py [--root <dir>] [--pr-files BASE HEAD]
Prints "check-spec-decisions: ok" and exits 0, or names every problem on
stderr and exits 1.
"""

import os
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
    ("D-13", "edit", ["run against a local scripted model"]),
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
    ("D-25", "edit", ["`envcloakd --signin-driver`"]),
    ("D-26", "edit", ["Origins are registered in ASCII only", "no `url` or `idna` crate"]),
    ("D-27", "edit", ["`handoff_required`", "A CAPTCHA or other handoff state stops the attempt"]),
    ("D-28", "no edit", "docs/SIGNIN-ADAPTER.md (M2b-06)"),
    ("D-29", "no edit", "packaging and pinning, in docs/SIGNIN.md (M2b-02, M2b-08)"),
    ("D-30", "edit", ["The supervisor serves a fixed tool allowlist"]),
    ("D-31", "edit", ["`envcloak mcp --browser-supervisor`", "the requesting process instance that is to receive the browser tools"]),
    ("D-32", "edit", ["a short value is neither found nor removed"]),
    ("D-33", "edit", ["registered launch", "`code_selecting_env`", "`checked_at_rest`", "`envcloak agents migrate-mcp --update <agent>/<server> [--cwd <dir>]"]),
    ("D-34", "edit", ["`cleanup_unconfirmed`", "EnvCloak signals only processes it owns"]),
    ("D-35", "edit", ["whose leader is EnvCloak's PTY monitor", "`pty_monitor_lost`"]),
    ("D-36", "edit", ["Daemon-started modes of `envcloak`", "no release depends on identifying the requesting process's code"]),
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
    "gate 39": (
        "No literal secret remains in the MCP server entries of the covered agents' JSON and "
        "TOML configs (Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI, Kimi, OpenCode); "
        "YAML configs, key-shaped `args` literals and stores that hold an agent's own "
        "credentials are reported as manual and the command exits non-zero."
    ),
}

FORBIDDEN = {
    "the old gate b12": "no trust, refresh or session state from the worker remains usable",
    "the old §6.8 worker sentence": "In M2b no trust, refresh or session state from the worker outlives the attempt",
    "a release that rests on EnvCloak's own `envcloak` executable (CR-1)": "own `envcloak` executable",
    "a release that rests on the requester's executable identity (CR-1)": "executable identity is EnvCloak's",
    "the old §1.1 inject-mode claim": "keeps keys out of files, prompts, configs and transcripts",
    "`rmcp` as the MCP library": "`rmcp` 3.x (pinned)",
    "the old stdio rewrite form": "`args: [\"run\", \"--ref\"",
    "the old instruction 3": "`envcloak add <provider> --ask` so the user pastes it into the app",
    "the server-wide Codex approval offer": "offer to set Codex's per-server MCP approval mode for EnvCloak only",
    "IDNA normalisation of origins": "after URL parsing and IDNA normalisation",
    "the M2b handoff pause": "(the app, or a terminal the person controls)",
    "the old gate 38 bullet": "Activation and denial probes run for each agent in an isolated HOME, and coverage",
    "the old gate 39": "No literal secret remains in any agent config.",
    "an em dash": "—",
}

STATUS = "Status: draft v0.4 "

problems = []


def fail(msg):
    problems.append(msg)


def check_spec(text):
    if not text.startswith("# EnvCloak: product and architecture spec\n\n" + STATUS):
        fail("the status line does not say draft v0.4")
    ids = [d[0] for d in DECISIONS]
    expected = ["D-%02d" % n for n in range(1, 37)]
    if ids != expected:
        fail("the decision list is not D-01 to D-36, each once and in order")
    for did, kind, what in DECISIONS:
        if kind == "edit":
            if not what:
                fail("%s is an edit with no phrase to check" % did)
            for phrase in what:
                if phrase not in text:
                    fail("%s: the SPEC lacks %r" % (did, phrase))
        elif kind == "no edit":
            if not isinstance(what, str) or not what.strip():
                fail("%s is \"no edit\" without saying where it is carried" % did)
        else:
            fail("%s: %r is neither \"edit\" nor \"no edit\"" % (did, kind))
    for name, sentence in REQUIRED.items():
        n = text.count(sentence)
        if n != 1:
            fail("%s: found %d times, not once word for word" % (name, n))
    for name, phrase in FORBIDDEN.items():
        if phrase in text:
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
    print("check-spec-decisions: ok (%d decisions, %d sentences)" % (len(DECISIONS), len(REQUIRED)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
