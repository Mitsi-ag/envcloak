"""An independent encoder of the sign-in scope and statement, for
tests/encoding.rs.

It follows docs/GRANTS.md "Sign-in scope and statement": the line
`envcloak-signin-scope/1\\n`, then each field as a 2-byte big-endian field
number, a 4-byte big-endian length and its value, in field-number order;
integers fixed-width big-endian, ids and digests as bytes, enumerations as
one byte, composite values as parts each preceded by its 4-byte length,
and sets as a 4-byte count and length-prefixed elements in ascending
order of the element's bytes, with duplicates refused. The statement is
the line `envcloak-signin-statement/1\\n` and fields 1 to 7. It shares no
code with the crate.

Reads a JSON array of cases on standard input, each a scope and a
statement described field by field, with every set in the order the test
listed it, and writes a JSON array with, for each: `scope` and
`statement` in hex (or `duplicate` if a set holds an element twice), and
`unsorted`, the scope with its sets left in the order given. The unsorted
encoding is the positive control: it differs from the crate wherever the
test listed a set out of order.
"""

import json
import struct
import sys


class Duplicate(Exception):
    pass


def lp(b):
    return struct.pack(">I", len(b)) + b


def u64(n):
    return struct.pack(">Q", n)


def instance(i):
    return struct.pack(">i", i["pid"]) + u64(i["start_time"])


def text(s):
    return s.encode("utf-8")


def host(h):
    if "name" in h:
        return lp(b"\x01") + lp(text(h["name"]))
    if "v4" in h:
        return lp(b"\x04") + lp(bytes(h["v4"]))
    return lp(b"\x06") + lp(bytes.fromhex(h["v6"]))


def origin(o):
    scheme = {"http": b"\x01", "https": b"\x02"}[o["scheme"]]
    return lp(scheme) + lp(host(o["host"])) + lp(struct.pack(">H", o["port"]))


def cookie(c):
    return lp(host(c["host"])) + lp(text(c["name"]))


def storage(s):
    return lp(origin(s["origin"])) + lp(text(s["key"]))


def encode_set(items, element, ordered):
    elems = [element(x) for x in items]
    if ordered:
        elems.sort()
        for a, b in zip(elems, elems[1:]):
            if a == b:
                raise Duplicate()
    out = struct.pack(">I", len(elems))
    for e in elems:
        out += lp(e)
    return out


def fields(domain, values):
    out = bytearray(domain)
    for number, value in values:
        out += struct.pack(">H", number) + lp(value)
    return bytes(out)


def scope(s, ordered=True):
    sub, proj, acc, tgt, dlv, lim, ep = (
        s["subject"],
        s["project"],
        s["account"],
        s["target"],
        s["delivery"],
        s["limits"],
        s["epochs"],
    )
    tenant = b"\x00" if acc["tenant"] is None else b"\x01" + text(acc["tenant"])
    check_kind = {"endpoint": b"\x01", "element": b"\x02"}[tgt["identity_check"]["kind"]]
    return fields(
        b"envcloak-signin-scope/1\n",
        [
            (1, instance(sub["root"])),
            (2, bytes.fromhex(sub["evidence"])),
            (3, bytes.fromhex(proj["dir"])),
            (4, u64(proj["dev"])),
            (5, u64(proj["ino"])),
            (6, bytes.fromhex(proj["config"])),
            (7, bytes.fromhex(acc["login_item"])),
            (8, u64(acc["authorization_revision"])),
            (9, text(acc["account"])),
            (10, tenant),
            (11, text(acc["role"])),
            (12, {"test": b"\x01", "live": b"\x02"}[acc["environment"]]),
            (13, bytes.fromhex(tgt["id"])),
            (14, u64(tgt["revision"])),
            (15, bytes.fromhex(tgt["adapter"])),
            (16, u64(tgt["adapter_revision"])),
            (17, encode_set(tgt["entry_origins"], origin, ordered)),
            (18, lp(check_kind) + lp(text(tgt["identity_check"]["locator"]))),
            (19, encode_set(tgt["cookies"], cookie, ordered)),
            (20, encode_set(tgt["storage"], storage, ordered)),
            (21, b"\x01"),
            (22, instance(dlv["requester"])),
            (23, u64(dlv["browser"])),
            (24, {"each": b"\x01", "dev": b"\x02"}[lim["tier"]]),
            (25, bytes([lim["attempts"]])),
            (26, u64(lim["approval"])),
            (27, u64(lim["attempt_timeout"])),
            (28, u64(lim["session_lifetime"])),
            (29, bytes.fromhex(ep["daemon"])),
            (30, u64(ep["vault"])),
            (31, u64(ep["policy"])),
        ],
    )


def statement(st, scope_bytes):
    opts = st["options"]
    if opts == "once":
        o = b"\x01"
    else:
        o = b"\x02" + u64(opts["window"]) + bytes([opts["attempts"]])
    return fields(
        b"envcloak-signin-statement/1\n",
        [
            (1, scope_bytes),
            (2, bytes.fromhex(st["request"])),
            (3, bytes.fromhex(st["nonce"])),
            (4, u64(st["created"])),
            (5, u64(st["expires"])),
            (6, o),
            (7, u64(st["context"])),
        ],
    )


def main():
    out = []
    for case in json.load(sys.stdin):
        try:
            s = scope(case["scope"])
        except Duplicate:
            out.append({"duplicate": True})
            continue
        out.append(
            {
                "scope": s.hex(),
                "statement": statement(case["statement"], s).hex(),
                "unsorted": scope(case["scope"], ordered=False).hex(),
            }
        )
    json.dump(out, sys.stdout)


main()
