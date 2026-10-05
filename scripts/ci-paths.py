#!/usr/bin/env python3
"""Which of CI's path-filtered jobs a pull request needs (M2 plan §6, task
M2-04; M3 plan §5 rule 8, task M3-02).

Reads the paths a pull request changes, one per line, on standard input,
and prints `gates=true|false`, `agents=true|false` and `app=true|false`
for $GITHUB_OUTPUT:

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
- `app` (`macos-app`, the macOS app; M3 plan §5 rule 8, task M3-02) runs
  when the app or its scripts change (apps/macos/, scripts/macos/), when
  the daemon side the app talks to does (envcloak-ipc, envcloak-daemon,
  envcloak-sys, envcloak-core, and the CLI's `ref`, `add`, `approve` and
  `status` commands), when the brand files the app links do
  (assets/brand/), when the documents its tests read do (docs/APP.md's
  token table, docs/BRAND.md), and when check-sources.sh, this script or
  the workflow do.

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
APP = [
    r"^apps/macos/",
    r"^scripts/macos/",
    r"^crates/envcloak-(?:ipc|daemon|sys|core)/",
    r"^crates/envcloak-cli/src/cmd/(?:ref_|add|approve[^/]*|status)\.rs$",
    r"^assets/brand/",
    r"^docs/(?:APP|BRAND)\.md$",
    r"^scripts/check-sources\.sh$",
    r"^scripts/ci-paths\.py$",
    r"^\.github/workflows/ci\.yml$",
]


def needs(paths, patterns):
    rules = [re.compile(p) for p in patterns]
    return any(rule.search(p) for p in paths for rule in rules)


def answers(paths):
    return {"gates": needs(paths, GATES), "agents": needs(paths, AGENTS), "app": needs(paths, APP)}


# (path, gates, agents)
CASES = [
    ("crates/envcloak-e2e/tests/agent_hosts.rs", True, True),
    ("crates/envcloak-e2e/tests/fixtures/hook-payloads/codex-0.159.2/PreToolUse.json", True, True),
    ("crates/envcloak-e2e/src/lib.rs", True, True),
    ("crates/envcloak-e2e/Cargo.toml", True, True),
    ("crates/envcloak-e2e/agents/versions.toml", True, True),
    ("crates/envcloak-e2e/agents/npm/claude-code/package-lock.json", True, True),
    ("crates/envcloak-e2e/mcp-client/package-lock.json", True, True),
    ("crates/envcloak-e2e/mcp-client/client.mjs", True, True),
    ("crates/envcloak-e2e/tests/m2_story/mcp.rs", True, True),
    ("crates/envcloak-cli/src/cmd/mcp.rs", True, False),
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


# (path, app)
APP_CASES = [
    ("apps/macos/EnvCloak/App/EnvCloakApp.swift", True),
    ("apps/macos/EnvCloak.xcodeproj/project.pbxproj", True),
    ("apps/macos/Packages/EnvCloakDesign/Sources/EnvCloakDesign/Tokens.swift", True),
    ("scripts/macos/build-app.sh", True),
    ("scripts/macos/tests/test_sign_check.py", True),
    ("crates/envcloak-ipc/src/proto.rs", True),
    ("crates/envcloak-daemon/src/server.rs", True),
    ("crates/envcloak-sys/src/peer.rs", True),
    ("crates/envcloak-core/src/vault/items.rs", True),
    ("crates/envcloak-cli/src/cmd/ref_.rs", True),
    ("crates/envcloak-cli/src/cmd/add.rs", True),
    ("crates/envcloak-cli/src/cmd/approve.rs", True),
    ("crates/envcloak-cli/src/cmd/approve_unlocker.rs", True),
    ("crates/envcloak-cli/src/cmd/status.rs", True),
    ("assets/brand/motion/swiftui/EnvCloakMotion.swift", True),
    ("assets/brand/icon/EnvCloak.icon/icon.json", True),
    ("docs/APP.md", True),
    ("docs/BRAND.md", True),
    ("scripts/check-sources.sh", True),
    ("scripts/ci-paths.py", True),
    (".github/workflows/ci.yml", True),
    ("crates/envcloak-cli/src/cmd/run.rs", False),
    ("crates/envcloak-cli/src/cmd/addendum/x.rs", False),
    ("crates/envcloak-cli/tests/add.rs", False),
    ("crates/envcloak-agents/src/lib.rs", False),
    ("crates/envcloak-e2e/tests/agent_hosts.rs", False),
    ("docs/SPEC.md", False),
    ("scripts/check-unsafe.sh", False),
    ("apps/linux/README.md", False),
    ("Cargo.lock", False),
]


def self_test():
    bad = 0
    for path, gates, agents in CASES:
        got = answers([path])
        if (got["gates"], got["agents"]) != (gates, agents):
            print("ci-paths: %s: gates=%s agents=%s, want gates=%s agents=%s"
                  % (path, got["gates"], got["agents"], gates, agents), file=sys.stderr)
            bad += 1
    for path, app in APP_CASES:
        got = answers([path])["app"]
        if got != app:
            print("ci-paths: %s: app=%s, want app=%s" % (path, got, app), file=sys.stderr)
            bad += 1
    if answers([]) != {"gates": False, "agents": False, "app": False}:
        print("ci-paths: no changed path must need nothing", file=sys.stderr)
        bad += 1
    print("ci-paths: self-test %s (%d cases)" % ("failed" if bad else "ok", len(CASES) + len(APP_CASES)))
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
