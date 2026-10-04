"""Lists, per candidate and target, the crates the trial crate compiles
(normal and build edges), the proc-macro crates among them and the build
scripts, from `cargo metadata --filter-platform`."""
import json
import os
import sys

PLATFORMS = ("aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu")

base = sys.argv[1]
for name in sorted(os.listdir(base)):
    if not os.path.isdir(os.path.join(base, name)):
        continue
    for plat in PLATFORMS:
        p = os.path.join(base, name, "meta-%s.json" % plat)
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            print(name, plat, "no metadata")
            continue
        with open(p) as f:
            m = json.load(f)
        pk = {x["id"]: x for x in m["packages"]}
        nodes = {n["id"]: n for n in m["resolve"]["nodes"]}
        root = [i for i in pk if pk[i]["name"] == "envcloak-deptrial"][0]
        seen, stack = set(), [root]
        while stack:
            i = stack.pop()
            if i in seen:
                continue
            seen.add(i)
            for d in nodes[i]["deps"]:
                kinds = {k["kind"] for k in d["dep_kinds"]}
                if kinds & {None, "build"}:
                    stack.append(d["pkg"])
        pms = sorted("%s %s" % (pk[i]["name"], pk[i]["version"]) for i in seen
                     if any("proc-macro" in t["kind"] for t in pk[i]["targets"]))
        bs = sorted(pk[i]["name"] for i in seen
                    if any("custom-build" in t["kind"] for t in pk[i]["targets"]))
        print("%-20s %-26s crates=%3d proc-macros=%s; build-scripts=%s" % (
            name, plat, len(seen) - 1, ", ".join(pms) or "none", ", ".join(bs) or "none"))
