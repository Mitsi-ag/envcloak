"""An independent encoder of the approval statement, for tests/statement.rs.

It follows docs/GRANTS.md "Canonical encoding": the bytes
`envcloak-statement/2\\n`, then every field of the descriptor and of the
options, each as a 4-byte big-endian length followed by its bytes, lists
preceded by their count, numbers as decimal strings (a pid with its sign),
booleans as `1` or `0`, an optional string as the string (empty when
absent) and then whether it is there; the proposed test items come after
the bindings, each as its variable, live slug, test slug and optional
field, then the layer its live binding came from: the word `env`,
`profile` with the profile's name, `env_file` with the line, or `ref`. It
shares no code with the crate.

Reads a JSON array of {"descriptor": ..., "options": ...} on standard
input, as the crate serializes them, and writes a JSON array with, for
each, the statement in hex:

- `signed`: the format as it is (version 2);
- `legacy`: version 2 with each pid's absolute value, as the encoding was
  before F-81, which gives a pid and its negative the same bytes; the
  crate must not (a positive control);
- `v1`: version 1, the format before M2-13, which had no proposals: the
  crate's digests must never equal it (version 1 digests are refused
  after the upgrade), and two descriptors that differ in their proposals
  alone encode alike in it (a positive control that the proposals are
  what version 2 adds);
- `unsourced`: version 2 without the proposals' layers: two descriptors
  whose proposals differ in their layer alone encode alike in it (a
  positive control that the layer, which the advice the statement shows
  follows, is under the digest).
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


def optional(s):
    return text(s if s is not None else "") + flag(s is not None)


def layer(source):
    kind = source["layer"]
    if kind == "env" and len(source) == 1:
        return text("env")
    if kind == "profile" and set(source) == {"layer", "profile"}:
        return text("profile") + text(source["profile"])
    if kind == "env_file" and set(source) == {"layer", "line"}:
        return text("env_file") + num(source["line"])
    if kind == "ref" and len(source) == 1:
        return text("ref")
    raise ValueError("unknown layer %r" % (source,))


def encode(d, o, pid, version, sourced=True):
    s = d["subject"]
    root = s["root"]
    p = d["project"]
    out = bytearray(b"envcloak-statement/%d\n" % version)
    out += text(d["request"]) + text(d["nonce"])
    out += num(d["created_secs"]) + num(d["expires_in_secs"])
    out += text(s["kind"])
    out += optional(s["label"])
    out += pid(s["caller_pid"]) + pid(root["pid"]) + num(root["start_time"])
    out += optional(root["exe"])
    out += text(p["dir"]) + text(p["manifest"]) + text(p["manifest_sha256"])
    out += flag(p["new_project"])
    out += num(len(d["bindings"]))
    for b in d["bindings"]:
        for k in ("env_name", "slug", "item", "field", "field_name", "classification"):
            out += text(b[k])
        out += flag(b["first_use"]) + flag(b["granted"])
    if version >= 2:
        out += num(len(d["proposals"]))
        for x in d["proposals"]:
            out += text(x["env_name"]) + text(x["live_slug"]) + text(x["test_slug"])
            out += optional(x["test_field"])
            if sourced:
                out += layer(x["source"])
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
                "signed": encode(d, o, num, 2).hex(),
                "legacy": encode(d, o, lambda n: num(abs(n)), 2).hex(),
                "v1": encode(d, o, num, 1).hex(),
                "unsourced": encode(d, o, num, 2, sourced=False).hex(),
            }
        )
    json.dump(out, sys.stdout)


main()
