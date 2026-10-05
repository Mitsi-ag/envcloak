"""The command gate 8 runs under envcloak-exec's runner (SPEC §15.2 gate 8).

It takes the values from its own environment, as a command `envcloak run`
starts does, serializes each with real serializers, and writes every result
on standard output and standard error at once: first whole, then one byte at
a time with a pause after each byte, so the runner's redactor sees the value
split at every byte boundary with an idle flush between the pieces. Then
comes the tail: `eof` ends the output, `malformed` writes bytes that are not
UTF-8 first, and `sigterm` writes the first half of a value and waits for
the signal that ends it. So that it never outlives its test, that wait also
ends when the file `--stop` names appears, when the directory that file
would be in is gone (the test's home, removed as the test ended), or after
`--deadline` seconds, and says which in the file `--ended` names
(`stopped`, `gone` or `deadline`), unless that file's directory is gone too.

Serializers: Python's `json.dumps` (ASCII and UTF-8), `quote` and
`quote_plus` (upper and lower hex), form encoding, standard and URL-safe
base64 (padded and unpadded, the value at byte offsets 0, 1 and 2 of a
longer payload), and lower and upper hex; Node's `JSON.stringify`, PHP's
`json_encode` and a Go program's `encoding/json`, each when its path is
given; and payloads read from standard input and from fixture directories
(serde_json's, and the recorded output of .NET, Go, Node, Python and Ruby).

Usage:
  emit.py --names A,B [--pause-ms N] [--tail eof|malformed|sigterm]
          [--whole-only] [--merged] [--node PATH] [--php PATH] [--go PATH]
          [--stdin] [--fixtures DIR]...
          [--stop PATH --ended PATH --deadline SECONDS]

With `--merged` (PTY mode, where standard output and standard error are one
terminal), each payload is written whole and then split while the other
stream waits, so the streams still alternate but a value's bytes are never
interleaved with the other stream's on the one terminal.

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


class NoLock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def emit(fd, payloads, pause, lock):
    for name, p in payloads:
        with lock:
            frame = ("<W|%s=" % name).encode()
            os.write(fd, frame + p + b"\n")
            os.write(fd, ("<B|%s=" % name).encode())
            for i in range(len(p)):
                os.write(fd, p[i : i + 1])
                time.sleep(pause)
            os.write(fd, b"\n")


def record(path, how):
    """Appends `how` to the record at `path`, if its directory is there."""
    try:
        with open(path, "a") as f:
            f.write(how + "\n")
    except OSError:
        pass


def main():
    args = sys.argv[1:]
    opts = {"--pause-ms": "2", "--tail": "eof"}
    fixtures, flags = [], set()
    while args:
        a = args.pop(0)
        if a in ("--whole-only", "--stdin", "--merged"):
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

    lock = threading.Lock() if "--merged" in flags else NoLock()
    threads = [
        threading.Thread(target=emit, args=(fd, payloads[i::2], pause, lock))
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
        stop = opts["--stop"]
        life = os.path.dirname(stop)
        end = time.monotonic() + float(opts["--deadline"])
        while os.path.isdir(life) and not os.path.exists(stop):
            if time.monotonic() > end:
                record(opts["--ended"], "deadline")
                sys.exit(124)
            time.sleep(0.05)
        record(opts["--ended"], "stopped" if os.path.exists(stop) else "gone")
        sys.exit(0)
    os.write(2, b"DONE\n")


main()
