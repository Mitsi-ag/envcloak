#!/usr/bin/env python3
"""The workspace's crate graph is one-way (M2 plan D-02, F-75).

Reads the dependencies every workspace package declares, from
`cargo metadata --format-version 1 --no-deps` (no resolution, so a
dependency cycle Cargo would refuse is still read and named here), and
fails on:

- a normal or build dependency of one workspace package on another that
  ALLOWED below does not list, optional and target-specific ones included,
  however the dependency is renamed. Dev-dependencies are not checked: a
  test may use any crate without the shipped code depending on it;
- a cycle among those dependencies;
- a FORBIDDEN edge, named with the reason it is forbidden. FORBIDDEN and
  ALLOWED must not overlap, so allowing a forbidden edge means editing both,
  and this check fails until then; nor may ALLOWED itself hold a cycle.

A new edge is a plan change, reviewed as one (D-02): never a table edit
inside a feature task. The table holds today's edges and the planned ones
of the M2 plan's M2-02 task. `cli -> *` is every workspace crate but the
daemon, the test-only crates and the canaries.

Usage: scripts/check-crate-graph.py [workspace-root]
Runs `$CARGO` (else `cargo`) with the root's Cargo.toml. Exits 0 with one
`ok` line, or 1 with one line per problem on standard error.
"""

import json
import os
import subprocess
import sys

# A package's short name: the CLI's package is `envcloak` and the daemon's
# `envcloakd`; every other package drops its `envcloak-` prefix.
SPECIAL = {"envcloak": "cli", "envcloakd": "daemon"}

# Crates that never ship: the test kit, the end-to-end story and the two
# lint canaries (which scripts/check-unsafe.sh also keeps out of every
# manifest).
TEST_ONLY = {"testkit", "e2e", "lint-canary", "unsafe-canary"}

# Every normal or build edge a workspace crate may have to another.
ALLOWED = {
    "sys": set(),
    "core": {"sys"},
    "policy": {"core", "sys"},
    "redact": set(),
    "providers": {"core"},
    "ipc": {"core", "policy", "sys"},
    "exec": {"core", "policy", "redact", "sys"},
    "scan": {"core", "policy", "redact", "sys"},
    # render.rs reads the provider registry to keep key-shaped names out
    # of what it prints.
    "client": {"core", "ipc", "policy", "providers", "sys"},
    "agents": {"client", "scan", "ipc", "core", "policy", "sys"},
    "mcp": {"client", "agents", "ipc", "core", "policy", "redact", "sys"},
    "signin": {"core", "policy"},
    "browser": {"signin", "sys"},
    "daemon": {"core", "ipc", "policy", "providers", "redact", "sys", "signin", "browser"},
    "cli": {"*"},
    "proxy": set(),
    "sync": set(),
    "testkit": {"sys"},
    "e2e": {"testkit"},
    "lint-canary": set(),
    "unsafe-canary": set(),
}

# What `cli -> *` leaves out.
CLI_NEVER = {"daemon", "cli"} | TEST_ONLY

SCANNER = (
    "the scanner never depends on the agent catalog, the MCP server, the client or the "
    "CLI: they build scan-owned ConfigSource descriptors and call it"
)
CLIENT = (
    "the client is the base the agent catalog and the MCP server build on, and never "
    "depends on them or on the scanner"
)
FORBIDDEN = {
    ("scan", "agents"): SCANNER,
    ("scan", "mcp"): SCANNER,
    ("scan", "client"): SCANNER,
    ("scan", "cli"): SCANNER,
    ("client", "agents"): CLIENT,
    ("client", "mcp"): CLIENT,
    ("client", "scan"): CLIENT,
}


def short(name):
    if name in SPECIAL:
        return SPECIAL[name]
    if name.startswith("envcloak-"):
        return name[len("envcloak-"):]
    return name


def allowed(src, dst):
    targets = ALLOWED.get(src)
    if targets is None:
        return False
    if "*" in targets:
        return dst not in CLI_NEVER
    return dst in targets


def metadata(root):
    cargo = os.environ.get("CARGO", "cargo")
    cmd = [
        cargo,
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--manifest-path",
        os.path.join(root, "Cargo.toml"),
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, check=False)
    except OSError as e:
        return None, "cannot run %s: %s" % (cargo, e)
    if out.returncode != 0:
        return None, "cargo metadata failed: %s" % out.stderr.decode("utf-8", "replace").strip()
    try:
        return json.loads(out.stdout), None
    except ValueError as e:
        return None, "cargo metadata printed no JSON: %s" % e


def edges_of(meta):
    """{(src, dst): [how]} for every normal or build dependency of one
    workspace package on another, by short name."""
    members = set(meta.get("workspace_members") or [])
    packages = [p for p in meta.get("packages") or [] if p.get("id") in members]
    names = {p["name"] for p in packages}
    edges = {}
    for p in packages:
        src = short(p["name"])
        for d in p.get("dependencies") or []:
            if d.get("kind") == "dev":
                continue
            if d.get("name") not in names:
                continue
            how = d.get("kind") or "normal"
            if d.get("target"):
                how += " for " + d["target"]
            if d.get("optional"):
                how += ", optional"
            if d.get("rename"):
                how += ", as " + d["rename"]
            edges.setdefault((src, short(d["name"])), []).append(how)
    return {short(n) for n in names}, edges


def cycles(nodes, edges):
    """The cycles among `edges`, each as its path, starting from its least
    node, once each."""
    out = {}
    succ = {n: sorted({b for (a, b) in edges if a == n}) for n in nodes}
    state = {}

    def visit(n, path):
        state[n] = "open"
        path.append(n)
        for m in succ.get(n, []):
            if state.get(m) == "open":
                loop = path[path.index(m):]
                k = loop.index(min(loop))
                loop = loop[k:] + loop[:k]
                out[tuple(loop)] = loop + [loop[0]]
            elif m not in state:
                visit(m, path)
        path.pop()
        state[n] = "done"

    for n in sorted(nodes):
        if n not in state:
            visit(n, [])
    return [out[k] for k in sorted(out)]


def main(argv):
    if len(argv) > 2:
        print("usage: scripts/check-crate-graph.py [workspace-root]", file=sys.stderr)
        return 2
    root = argv[1] if len(argv) == 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    problems = []
    for (src, dst), why in sorted(FORBIDDEN.items()):
        if allowed(src, dst):
            problems.append("the table allows the forbidden edge %s -> %s (%s)" % (src, dst, why))
    table = {(a, b) for a, bs in ALLOWED.items() for b in bs if b != "*"}
    for loop in cycles(set(ALLOWED), table):
        problems.append("the allowed-edge table has a cycle: %s" % " -> ".join(loop))
    meta, err = metadata(root)
    if err:
        problems.append(err)
    else:
        nodes, edges = edges_of(meta)
        for (src, dst), how in sorted(edges.items()):
            kinds = "; ".join(sorted(set(how)))
            if (src, dst) in FORBIDDEN:
                problems.append(
                    "%s -> %s (%s) is forbidden: %s (D-02, F-75)" % (src, dst, kinds, FORBIDDEN[(src, dst)])
                )
            elif not allowed(src, dst):
                problems.append(
                    "%s -> %s (%s) is not in the allowed-edge table: a new edge is a plan change "
                    "(D-02), not a table edit inside a feature task" % (src, dst, kinds)
                )
        for loop in cycles(nodes, edges):
            problems.append("dependency cycle: %s" % " -> ".join(loop))
    if problems:
        for p in problems:
            print("check-crate-graph: " + p, file=sys.stderr)
        return 1
    print("check-crate-graph: ok (%d edges among %d crates)" % (len(edges), len(nodes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
