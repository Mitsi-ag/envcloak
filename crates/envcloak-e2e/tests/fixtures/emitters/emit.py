"""The fixture story's command, `./emit` in acme-web (SPEC §15.1 steps 5, 6
and 8; gate 8 through the whole of `envcloak run`).

It takes the values from its own environment, as any command `envcloak run`
starts does, puts each through every serializer gate 8 names, and writes
every result on standard output and standard error at once:

- here, Python: `json.dumps` with `ensure_ascii` true and false, `quote` and
  `quote_plus` in upper and lower hex, form encoding, standard and URL-safe
  base64, padded and unpadded, with the value at byte offsets 0, 1 and 2 of
  a longer payload, and lower and upper hex;
- Node's `JSON.stringify` (emit.js), Go's `encoding/json` (emit.go), .NET's
  `System.Text.Json` (Emit.cs), PHP's `json_encode` (emit.php) and
  `serde_json` (`ec-emit-serde`, a program of the envcloak-e2e crate): each
  runtime the configuration names prints, for each variable, its JSON
  string and the SHA-256 of the value, NUL after each.

Each result is written whole, then again in pieces: for the variables the
mode splits fully, at every byte boundary, with a pause longer than the
runner's idle flush (40 ms) after each byte; for the others, at three
boundaries with the same pause. The full mode ends with bytes that are not
UTF-8 around halves of a value. Last come the digests, one line per runtime
and variable: `sha256 <runtime> <NAME> <hex>`, which the test compares with
the fixtures'.

Every line of a result starts with a frame naming it (`<W|` whole, `<B|` in
pieces), so the test can tell that each went through. Nothing here prints a
value except as a serializer's result inside its frame, and no error holds
one.

Usage: emit.py --config FILE [--quick | --digests-only | --oracle]

The configuration (JSON, written by the test) names the variables
(`names`), the ones the full mode splits at every byte (`split`), the pause
in milliseconds (`pause_ms`), and the runtimes (`runtimes`: each a tag and
a command, to which the names are appended).

- full (no flag): every result, split as above, then the malformed tail;
- `--quick`: every result, split at three boundaries only;
- `--digests-only`: the digests only;
- `--oracle`: for the test itself, run outside EnvCloak: every result as
  `<NAME>/<tag> NUL <result> NUL` on standard output, and nothing else. The
  test loads these bytes as the fixtures to look for (the F-9 lesson: what
  a serializer produces is taken from the serializer).
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse


def lower_hex(s):
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), s)


def python_results(name, raw):
    text = raw.decode("utf-8")
    out = [
        ("raw", raw),
        ("py-json-ascii", json.dumps(text).encode()),
        ("py-json-utf8", json.dumps(text, ensure_ascii=False).encode("utf-8")),
    ]
    for tag, encoded in (
        ("py-quote", urllib.parse.quote(text)),
        ("py-quote-plus", urllib.parse.quote_plus(text)),
        ("py-form", urllib.parse.urlencode({"k": text})),
    ):
        out.append((tag + "-upper", encoded.encode()))
        out.append((tag + "-lower", lower_hex(encoded).encode()))
    for pre in (b"", b"u", b"us"):
        blob = pre + raw + b"!!!"
        at = "at%d" % len(pre)
        std = base64.b64encode(blob)
        url = base64.urlsafe_b64encode(blob)
        out += [
            ("b64-" + at, std),
            ("b64-nopad-" + at, std.rstrip(b"=")),
            ("b64url-" + at, url),
            ("b64url-nopad-" + at, url.rstrip(b"=")),
        ]
    out.append(("hex-lower", raw.hex().encode()))
    out.append(("hex-upper", raw.hex().upper().encode()))
    return [("%s/%s" % (name, tag), p) for tag, p in out]


def runtime_results(tag, command, names):
    """What one runtime printed: a JSON string and a digest per name."""
    done = subprocess.run(
        command + names, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=False
    )
    if done.returncode != 0:
        sys.exit("emit.py: the %s serializer failed with code %d" % (tag, done.returncode))
    parts = done.stdout.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) != 2 * len(names):
        sys.exit("emit.py: %s printed %d parts for %d names" % (tag, len(parts), len(names)))
    results = [("%s/%s" % (n, tag), parts[2 * i]) for i, n in enumerate(names)]
    digests = [(tag, n, parts[2 * i + 1].decode("ascii")) for i, n in enumerate(names)]
    return results, digests


def cuts(n, every):
    """Where a result of n bytes is cut: every boundary, or three."""
    if n < 2:
        return []
    if every:
        return list(range(1, n))
    return sorted({max(1, n // 4), max(1, n // 2), max(1, n - 1)})


def emit(fd, results, full_names, pause):
    for label, p in results:
        os.write(fd, ("<W|%s=" % label).encode() + p + b"\n")
        name = label.split("/", 1)[0]
        at = 0
        os.write(fd, ("<B|%s=" % label).encode())
        for cut in cuts(len(p), name in full_names):
            os.write(fd, p[at:cut])
            at = cut
            time.sleep(pause)
        os.write(fd, p[at:] + b"\n")


def main():
    args = sys.argv[1:]
    mode = "full"
    config = None
    while args:
        a = args.pop(0)
        if a == "--config":
            config = args.pop(0)
        elif a in ("--quick", "--digests-only", "--oracle"):
            mode = a[2:]
        else:
            sys.exit("emit.py: unknown argument")
    with open(config) as f:
        cfg = json.load(f)
    names = cfg["names"]
    pause = cfg.get("pause_ms", 45) / 1000.0

    results, digests, used = [], [], ["python"]
    for n in names:
        raw = os.environb[n.encode()]
        results += python_results(n, raw)
        digests.append(("python", n, hashlib.sha256(raw).hexdigest()))
    for tag, command in cfg["runtimes"]:
        r, d = runtime_results(tag, command, names)
        results += r
        digests += d
        used.append(tag)

    if mode == "oracle":
        out = sys.stdout.buffer
        for label, p in results:
            out.write(label.encode() + b"\0" + p + b"\0")
        out.flush()
        return

    os.write(2, ("SERIALIZERS %s RESULTS %d\n" % (",".join(used), len(results))).encode())
    if mode != "digests-only":
        full_names = set(cfg["split"]) if mode == "full" else set()
        threads = [
            threading.Thread(target=emit, args=(fd, results[i::2], full_names, pause))
            for i, fd in ((0, 1), (1, 2))
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    if mode == "full":
        first = os.environb[names[0].encode()]
        half = len(first) // 2
        os.write(1, b"M:\xff\xfe\xc3(\xe2\x82" + first[:half] + b"\xf0\x9f\n")
        os.write(2, b"M:\xc0\xaf\xed\xa0\x80" + first[half:] + b"\xc3\n")
    for tag, n, hexdigest in digests:
        os.write(1, ("sha256 %s %s %s\n" % (tag, n, hexdigest)).encode())
    os.write(2, b"DONE\n")


main()
