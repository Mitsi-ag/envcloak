"""The command gate 8 runs under envcloak-exec's runner (SPEC §15.2 gate 8).

It takes the values from its own environment, as a command `envcloak run`
starts does, serializes each with real serializers, and writes every result
on standard output and standard error at once: first whole, then one byte at
a time with a pause after each byte, so the runner's redactor sees the value
split at every byte boundary with an idle flush between the pieces. Then
comes the tail: `eof` ends the output, `malformed` writes bytes that are not
UTF-8 first, and `sigterm` writes the first half of a value and waits for
the signal that ends it. So that it never outlives its test, that wait also
ends when the file `--stop` names appears, or after `--deadline` seconds,
and says which in the file `--ended` names (`stopped` or `deadline`).

Serializers: Python's `json.dumps` (ASCII and UTF-8), `quote` and
`quote_plus` (upper and lower hex), form encoding, standard and URL-safe
base64 (padded and unpadded, the value at byte offsets 0, 1 and 2 of a
longer payload), and lower and upper hex; Node's `JSON.stringify`, PHP's
`json_encode` and a Go program's `encoding/json`, each when its path is
given; and payloads read from standard input and from fixture directories
(serde_json's, and the recorded output of .NET, Go, Node, Python and Ruby).

Usage:
  emit.py --names A,B [--pause-ms N] [--tail eof|malformed|sigterm]
          [--whole-only] [--node PATH] [--php PATH] [--go PATH]
          [--stdin] [--fixtures DIR]...
          [--stop PATH --ended PATH --deadline SECONDS]

Every line it writes starts with a frame naming the payload, so the test
can tell that each one went through. It never writes a value on its own
line without its frame, and it never prints one in an error.
"""

import base64
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


def python_payloads(name, raw, whole_only):
    text = raw.decode("utf-8")
    out = [
        ("raw", raw),
        ("py-json-ascii", json.dumps(text).encode()),
        ("py-json-utf8", json.dumps(text, ensure_ascii=False).encode("utf-8")),
    ]
    for label, encoded in (
        ("py-quote", urllib.parse.quote(text)),
        ("py-quote-plus", urllib.parse.quote_plus(text)),
        ("py-form", urllib.parse.urlencode({"k": text})),
    ):
        out.append((label + "-upper", encoded.encode()))
        out.append((label + "-lower", lower_hex(encoded).encode()))
    prefixes = [b""] if whole_only else [b"", b"u", b"us"]
    suffix = b"" if whole_only else b"!!!"
    for pre in prefixes:
        blob = pre + raw + suffix
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
    return [("%s/%s" % (name, label), p) for label, p in out]


def runtime_payloads(tag, argv, names):
    """JSON strings a runtime printed, NUL-separated, one per name."""
    done = subprocess.run(argv + names, stdout=subprocess.PIPE, check=True)
    parts = done.stdout.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) != len(names):
        sys.exit("emit.py: %s printed %d payloads for %d names" % (tag, len(parts), len(names)))
    return [("%s/%s" % (n, tag), p) for n, p in zip(names, parts)]


NODE = "const n = process.argv.slice(1); for (const x of n) process.stdout.write(JSON.stringify(process.env[x]) + '\\0');"
PHP = 'foreach (array_slice($argv, 1) as $x) { echo json_encode(getenv($x)), "\\0"; }'


def emit(fd, payloads, pause):
    for name, p in payloads:
        frame = ("<W|%s=" % name).encode()
        os.write(fd, frame + p + b"\n")
        os.write(fd, ("<B|%s=" % name).encode())
        for i in range(len(p)):
            os.write(fd, p[i : i + 1])
            time.sleep(pause)
        os.write(fd, b"\n")


def main():
    args = sys.argv[1:]
    opts = {"--pause-ms": "2", "--tail": "eof"}
    fixtures, flags = [], set()
    while args:
        a = args.pop(0)
        if a in ("--whole-only", "--stdin"):
            flags.add(a)
        elif a == "--fixtures":
            fixtures.append(args.pop(0))
        else:
            opts[a] = args.pop(0)
    names = [n for n in opts["--names"].split(",") if n]
    pause = int(opts["--pause-ms"]) / 1000.0
    whole_only = "--whole-only" in flags

    payloads, used = [], ["python"]
    for n in names:
        payloads += python_payloads(n, os.environb[n.encode()], whole_only)
    for tag, key, argv in (
        ("node", "--node", ["-e", NODE]),
        ("php", "--php", ["-r", PHP, "--"]),
        ("go", "--go", []),
    ):
        if key in opts:
            payloads += runtime_payloads(tag, [opts[key]] + argv, names)
            used.append(tag)
    if "--stdin" in flags:
        parts = sys.stdin.buffer.read().split(b"\0")
        for i, p in enumerate(x for x in parts if x):
            payloads.append(("stdin/%d" % i, p))
        used.append("stdin")
    for d in fixtures:
        for f in sorted(os.listdir(d)):
            with open(os.path.join(d, f), "rb") as fh:
                payloads.append(("fixture/" + f, fh.read()))
        used.append("fixtures")
    os.write(2, ("SERIALIZERS %s PAYLOADS %d\n" % (",".join(used), len(payloads))).encode())

    threads = [
        threading.Thread(target=emit, args=(fd, payloads[i::2], pause))
        for i, fd in ((0, 1), (1, 2))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    tail = opts["--tail"]
    first = os.environb[names[0].encode()]
    if tail == "malformed":
        os.write(1, b"M:\xff\xfe\xc3(\xe2\x82" + first[: len(first) // 2] + b"\xf0\x9f\n")
        os.write(2, b"M:\xc0\xaf\xed\xa0\x80\n")
        os.write(1, b"END\n")
    elif tail == "sigterm":
        os.write(1, b"H:" + first[: len(first) // 2])
        os.write(2, b"READY\n")
        end = time.monotonic() + float(opts["--deadline"])
        while not os.path.exists(opts["--stop"]):
            if time.monotonic() > end:
                with open(opts["--ended"], "a") as f:
                    f.write("deadline\n")
                sys.exit(124)
            time.sleep(0.05)
        with open(opts["--ended"], "a") as f:
            f.write("stopped\n")
        sys.exit(0)
    os.write(2, b"DONE\n")


main()
