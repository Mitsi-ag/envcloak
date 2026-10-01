import json
import os

base = "trial"
for name in sorted(os.listdir(base)):
    for plat in ("mac", "linux"):
        p = os.path.join(base, name, f"meta-{plat}.json")
        if not os.path.exists(p) or os.path.getsize(p) == 0:
            print(name, plat, "no metadata")
            continue
        m = json.load(open(p))
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
        pms = sorted(
            f"{pk[i]['name']} {pk[i]['version']}"
            for i in seen
            if any("proc-macro" in t["kind"] for t in pk[i]["targets"])
        )
        bs = sorted(
            pk[i]["name"]
            for i in seen
            if any("custom-build" in t["kind"] for t in pk[i]["targets"])
        )
        print(
            f"{name:26} {plat:5} crates={len(seen) - 1:3} "
            f"proc-macros={', '.join(pms) or 'none'}; build-scripts={', '.join(bs) or 'none'}"
        )
