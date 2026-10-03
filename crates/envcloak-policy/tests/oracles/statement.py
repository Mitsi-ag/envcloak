"""An independent encoder of the approval statement, for tests/statement.rs.

It follows docs/GRANTS.md "Canonical encoding": the bytes
`envcloak-statement/1\\n`, then every field of the descriptor and of the
options, each as a 4-byte big-endian length followed by its bytes, lists
preceded by their count, numbers as decimal strings (a pid with its sign),
booleans as `1` or `0`. It shares no code with the crate.

Reads a JSON array of {"descriptor": ..., "options": ...} on standard
input, as the crate serializes them, and writes a JSON array with, for
each, the statement in hex: `signed`, the format as it is, and `legacy`,
the encoding before F-81, which wrote each pid's absolute value. The
legacy encoding is the positive control: it gives a pid and its negative
the same bytes, which the crate must not.
"""

import json
import sys


def frame(b):
    return len(b).to_bytes(4, "big") + b


def text(s):
    return frame(s.encode("utf-8"))


def num(n):
    return text(str(n))


def flag(b):
    return text("1" if b else "0")


def encode(d, o, pid):
    s = d["subject"]
    root = s["root"]
    p = d["project"]
    out = bytearray(b"envcloak-statement/1\n")
    out += text(d["request"]) + text(d["nonce"])
    out += num(d["created_secs"]) + num(d["expires_in_secs"])
    out += text(s["kind"])
    out += text(s["label"] if s["label"] is not None else "")
    out += flag(s["label"] is not None)
    out += pid(s["caller_pid"]) + pid(root["pid"]) + num(root["start_time"])
    out += text(root["exe"] if root["exe"] is not None else "")
    out += flag(root["exe"] is not None)
    out += text(p["dir"]) + text(p["manifest"]) + text(p["manifest_sha256"])
    out += flag(p["new_project"])
    out += num(len(d["bindings"]))
    for b in d["bindings"]:
        for k in ("env_name", "slug", "item", "field", "field_name", "classification"):
            out += text(b[k])
        out += flag(b["first_use"]) + flag(b["granted"])
    out += text(d["mode"]) + num(len(d["argv"]))
    for a in d["argv"]:
        out += text(a)
    out += text(o["uses"]) + num(o["ttl_secs"]) + num(len(o["live"]))
    for name in o["live"]:
        out += text(name)
    return bytes(out)


def main():
    cases = json.load(sys.stdin)
    out = []
    for c in cases:
        d, o = c["descriptor"], c["options"]
        out.append(
            {
                "signed": encode(d, o, num).hex(),
                "legacy": encode(d, o, lambda n: num(abs(n))).hex(),
            }
        )
    json.dump(out, sys.stdout)


main()
