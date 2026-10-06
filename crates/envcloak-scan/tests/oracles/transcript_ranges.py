"""Cycle432 generator with a portable owned /tmp guard and value-free errors.

The Rust adapter checks scanner ranges only. Scrub previews are not qualified.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import stat
import tempfile
import urllib.parse

VERSION = "envcloak-transcript-range-oracle-v1"
MARKER = "[envcloak:redacted:oracle-item]"
GUARD_FAILURES = ("bundle_location", "bundle_name", "bundle_owner", "bundle_mode",
                  "bundle_nonempty", "bundle_marker")


def failure_code(error):
    # Only guard-owned codes may leave the process, never exception text.
    if type(error) is ValueError and len(error.args) == 1:
        code = error.args[0]
        if isinstance(code, str) and code in GUARD_FAILURES:
            return code
    return "internal"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n")


def guard(root, empty=False):
    root = Path(root)
    if root.is_symlink() or root.resolve().parent != Path("/tmp").resolve():
        raise ValueError("bundle_location")
    if not root.name.startswith("ec-codex-transcript-oracle-"):
        raise ValueError("bundle_name")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("bundle_owner")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("bundle_mode")
    if empty and any(root.iterdir()):
        raise ValueError("bundle_nonempty")
    if not empty and (root / "owner").read_text() != VERSION:
        raise ValueError("bundle_marker")
    return root


def spelling(value, form):
    data = value.encode("utf-8")
    if form == "raw":
        return value
    if form == "base64":
        encoded = base64.b64encode(data).decode("ascii")
        assert base64.b64decode(encoded, validate=True) == data
        return encoded
    if form == "hex":
        encoded = data.hex()
        assert bytes.fromhex(encoded) == data
        return encoded
    encoded = "".join("%%%02X" % byte for byte in data)
    assert urllib.parse.unquote_to_bytes(encoded) == data
    return encoded


def escaped(text, style):
    # Values are deliberately ASCII; Unicode lives in unrelated prefix text.
    if style == "plain":
        return json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8")
    parts = []
    for index, char in enumerate(text):
        use_escape = (style == "unicode" or (style == "mixed" and index % 2 == 0)
                      or (style == "edges" and index in (0, len(text) - 1)))
        if use_escape:
            parts.append(("\\u%04x" % ord(char)).encode("ascii"))
        else:
            parts.append(json.dumps(char)[1:-1].encode("ascii"))
    return b"".join(parts)


def line(parts, unicode_prefix, ending):
    context = "context \u2022 \U0001f680" if unicode_prefix else "context"
    start = (b'{ "context": ' + json.dumps(context, ensure_ascii=False).encode("utf-8")
             + b', "message": "')
    original = bytearray(start)
    wanted = bytearray(start)
    ranges = []
    decoded = []
    for index, (value, form, style) in enumerate(parts):
        separator = b"prefix " if index == 0 else b" between "
        original.extend(separator)
        wanted.extend(separator)
        rendered = spelling(value, form)
        raw = escaped(rendered, style)
        begin = len(original)
        original.extend(raw)
        ranges.append({"digest": digest(value.encode()), "form": form,
                       "start": begin, "end": len(original)})
        wanted.extend(MARKER.encode())
        decoded.append(separator.decode() + rendered)
    tail = b' suffix", "keep": 3 }' + ending
    original.extend(tail)
    wanted.extend(tail)
    # Independent JSON decoder checks the generator; offsets were recorded
    # during emission, never reconstructed with find() or a product parser.
    before = json.loads(original)
    after = json.loads(wanted)
    assert before == {"context": context, "message": "".join(decoded) + " suffix", "keep": 3}
    assert after == {"context": context, "message": "prefix " + " between ".join([MARKER] * len(parts)) + " suffix", "keep": 3}
    return bytes(original), bytes(wanted), ranges


def generate(root):
    root = guard(root, empty=True)
    (root / "owner").write_text(VERSION)
    cases = []
    requests = []

    def add(label, parts, prefix=False, ending=b"\n", repeats=1):
        case_id = "case-%02d" % len(cases)
        original, wanted, spans = line(parts, prefix, ending)
        occurrences = []
        for i in range(repeats):
            offset = i * len(original)
            occurrences.extend(dict(s, start=s["start"] + offset, end=s["end"] + offset) for s in spans)
        source = case_id + ".jsonl"
        expected = case_id + ".expected"
        (root / source).write_bytes(original * repeats)
        (root / expected).write_bytes(wanted * repeats)
        identities = sorted({s["digest"] for s in occurrences})
        cases.append({"id": case_id, "label": label, "input": source, "expected": expected,
                      "occurrences": occurrences, "count": len(occurrences),
                      "distinct": len(identities), "complete": True})
        requests.append({"id": case_id, "input": source,
                         "matches": [{"digest": d, "slug": "oracle-item"} for d in identities]})

    for form in ["raw", "base64", "hex", "percent"]:
        for style in ["plain", "unicode", "mixed", "edges"]:
            for prefix in [False, True]:
                value = secrets.token_hex(12)
                add("form-style-prefix", [(value, form, style)] * 2, prefix,
                    b"\r\n" if prefix else b"\n")
    value = secrets.token_hex(12)
    add("cross-form-dedup", [(value, form, style)
                            for form in ["raw", "base64", "hex", "percent"]
                            for style in ["plain", "unicode"]], True)
    first, second = secrets.token_hex(12), secrets.token_hex(12)
    add("two-identities", [(first, "raw", "mixed"), (second, "raw", "unicode"),
                            (first, "percent", "plain"), (second, "hex", "mixed")], True)
    for width in [23, 25]:
        value = secrets.token_hex(13)[:width]
        add("base64-padding", [(value, "base64", "plain"),
                               (value, "base64", "unicode")], True)
    add("repeated-100000", [(secrets.token_hex(12), "raw", "plain")], True, repeats=100000)
    dump(root / "requests.json", {"version": VERSION, "cases": requests})
    dump(root / "expected.json", {"version": VERSION, "cases": cases})
    assert len(cases) == 37
    return cases


if __name__ == "__main__":
    import sys
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        cases = generate(Path(sys.argv[1]))
        print(json.dumps({"cases": len(cases), "ranges": sum(c["count"] for c in cases)}))
    except Exception as error:
        print("oracle_failed:" + failure_code(error), file=sys.stderr)
        sys.exit(1)
