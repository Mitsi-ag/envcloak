#!/usr/bin/env python3
"""Which of CI's M2 agent jobs a pull request needs (M2 plan §6, task M2-04).

Reads the paths a pull request changes, one per line, on standard input,
and prints `gates=true|false` and `agents=true|false` for $GITHUB_OUTPUT:

- `gates` (the story steps in crates/envcloak-e2e/tests/m2_story/ with the
  pinned hosts) runs when anything they build or drive changes: any crate,
  the workspace manifests and lockfile, the host pins and installer, or
  this workflow. A product change that breaks a story is seen on its pull
  request, not first on main (K-16).
- `agents` (`agents-e2e`: crates/envcloak-e2e/tests/agent_hosts.rs) runs
  when envcloak-agents, envcloak-mcp or integrations/ change, as the plan's
  table says, and when the harness itself does: the e2e crate's helpers,
  host tests, fixtures and pins, envcloak-testkit (the agent harness, the
  sweep and the scripted model's wrapper), the workspace manifests and
  lockfile, the installer and this workflow.

`--self-test` checks representative paths against both answers and exits
non-zero on any difference; CI runs it before using the answers.
"""

import re
import sys

HARNESS = [
    r"^crates/envcloak-e2e/",
    r"^crates/envcloak-testkit/",
    r"^Cargo\.(toml|lock)$",
    r"^rust-toolchain\.toml$",
    r"^scripts/install-agent-hosts\.py$",
    r"^scripts/ci-paths\.py$",
    r"^\.github/workflows/ci\.yml$",
]
GATES = HARNESS + [r"^crates/"]
AGENTS = HARNESS + [
    r"^crates/envcloak-agents/",
    r"^crates/envcloak-mcp/",
    r"^integrations/",
]


def needs(paths, patterns):
    rules = [re.compile(p) for p in patterns]
    return any(rule.search(p) for p in paths for rule in rules)


def answers(paths):
    return {"gates": needs(paths, GATES), "agents": needs(paths, AGENTS)}


# (path, gates, agents)
CASES = [
    ("crates/envcloak-e2e/tests/agent_hosts.rs", True, True),
    ("crates/envcloak-e2e/tests/fixtures/hook-payloads/codex-0.159.2/PreToolUse.json", True, True),
    ("crates/envcloak-e2e/src/lib.rs", True, True),
    ("crates/envcloak-e2e/Cargo.toml", True, True),
    ("crates/envcloak-e2e/agents/versions.toml", True, True),
    ("crates/envcloak-e2e/agents/npm/claude-code/package-lock.json", True, True),
    ("crates/envcloak-e2e/tests/m2_story/skeleton.rs", True, True),
    ("crates/envcloak-e2e/tests/m2b_story/main.rs", True, True),
    ("crates/envcloak-testkit/src/agents.rs", True, True),
    ("crates/envcloak-testkit/src/home.rs", True, True),
    ("crates/envcloak-testkit/src/bin/ec-mcp-fixture.rs", True, True),
    ("crates/envcloak-testkit/Cargo.toml", True, True),
    ("Cargo.lock", True, True),
    ("Cargo.toml", True, True),
    ("scripts/install-agent-hosts.py", True, True),
    ("scripts/ci-paths.py", True, True),
    (".github/workflows/ci.yml", True, True),
    ("crates/envcloak-agents/src/probe/model/server.rs", True, True),
    ("crates/envcloak-mcp/src/lib.rs", True, True),
    ("integrations/agents.toml", False, True),
    ("crates/envcloak-cli/src/cmd/run.rs", True, False),
    ("crates/envcloak-daemon/src/audit.rs", True, False),
    ("crates/envcloak-sys/src/peer.rs", True, False),
    ("docs/AGENTS.md", False, False),
    ("README.md", False, False),
    ("scripts/check-unsafe.sh", False, False),
]


def self_test():
    bad = 0
    for path, gates, agents in CASES:
        got = answers([path])
        if got != {"gates": gates, "agents": agents}:
            print("ci-paths: %s: gates=%s agents=%s, want gates=%s agents=%s"
                  % (path, got["gates"], got["agents"], gates, agents), file=sys.stderr)
            bad += 1
    if answers([]) != {"gates": False, "agents": False}:
        print("ci-paths: no changed path must need nothing", file=sys.stderr)
        bad += 1
    print("ci-paths: self-test %s (%d cases)" % ("failed" if bad else "ok", len(CASES)))
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    paths = [line.strip() for line in sys.stdin if line.strip()]
    for job, need in answers(paths).items():
        print("%s=%s" % (job, "true" if need else "false"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
