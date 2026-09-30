#!/usr/bin/env python3
"""Regenerates passwords.txt: libpq keyword/value connection strings and
how many characters libpq itself decodes their password to (review F-65).

Each password is written into a connection string the way libpq's keyword
form escapes it (a backslash before a backslash, a quote or whitespace,
or before every byte; quoted or not; with each kind of whitespace libpq
takes around `=`), then parsed with libpq's own PQconninfoParse, which
reads the options without looking up defaults or connecting. The line is
kept only when libpq gives back exactly the password written: the test
then compares EnvCloak's count with libpq's.

The passwords are synthetic, drawn from a fixed seed, and short: nothing
is shaped like a key. Run it with libpq installed and commit the output:

    python3 crates/envcloak-providers/tests/fixtures/libpq/generate.py

LIBPQ names the library; otherwise `pg_config --libdir` finds it.

Each line of passwords.txt is `<chars> <exact|at-most> <string>`: libpq's
password has <chars> characters, and EnvCloak counts exactly that
(`exact`) or no more (`at-most`: a reading stops at a `;`, a quote or
escaped whitespace, which libpq reads on past). The string is written
with every byte but printable ASCII other than `%` as `%XX`.
"""

import ctypes
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def libpq():
    path = os.environ.get("LIBPQ")
    if not path:
        libdir = subprocess.run(
            ["pg_config", "--libdir"], check=True, capture_output=True, text=True
        ).stdout.strip()
        name = "libpq.dylib" if sys.platform == "darwin" else "libpq.so"
        path = os.path.join(libdir, name)
    lib = ctypes.CDLL(path)

    class Option(ctypes.Structure):
        _fields_ = [
            ("keyword", ctypes.c_char_p),
            ("envvar", ctypes.c_char_p),
            ("compiled", ctypes.c_char_p),
            ("val", ctypes.c_char_p),
            ("label", ctypes.c_char_p),
            ("dispchar", ctypes.c_char_p),
            ("dispsize", ctypes.c_int),
        ]

    lib.PQconninfoParse.restype = ctypes.POINTER(Option)
    lib.PQconninfoParse.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
    lib.PQconninfoFree.argtypes = [ctypes.POINTER(Option)]
    lib.PQconninfoFree.restype = None
    lib.PQfreemem.argtypes = [ctypes.c_void_p]

    def password(conninfo: bytes):
        err = ctypes.c_char_p()
        opts = lib.PQconninfoParse(conninfo, ctypes.byref(err))
        if not opts:
            raise ValueError("libpq refused a generated connection string")
        try:
            i = 0
            while opts[i].keyword is not None:
                if opts[i].keyword == b"password":
                    return opts[i].val
                i += 1
            return None
        finally:
            lib.PQconninfoFree(opts)

    return password


BASE = "abcdefghijklmnopqrstuvwxyz0123456789"
SPECIALS = ["\\", "'", " ", "\t", "é", "€", ";", "&", "%", "=", '"', "{", "}", "@", ":"]
# Characters with which EnvCloak's reading of the password stops early or
# takes another reading, and so may count fewer characters than libpq.
INEXACT = set(" \t'\";&%{}@:")
SPACES = ["", " ", "\t", "\n", "\x0b", "\x0c", "\r"]


def passwords(rng):
    out = []
    # Review F-65's case: 15 characters with one backslash, and the
    # 16-character control.
    for n in (15, 16):
        left = n // 2
        body = "".join(rng.choice(BASE) for _ in range(n - 1))
        out.append(body[:left] + "\\" + body[left:])
    for n in (8, 15, 16):
        for special in SPECIALS:
            body = [rng.choice(BASE) for _ in range(n - 1)]
            body.insert(rng.randrange(n), special)
            out.append("".join(body))
        for _ in range(3):
            body = [rng.choice(BASE) for _ in range(n - 3)]
            for _ in range(3):
                body.insert(rng.randrange(len(body) + 1), rng.choice(SPECIALS))
            out.append("".join(body))
    return out


def escaped(p, every):
    if every:
        return "".join("\\" + ch for ch in p)
    return "".join("\\" + ch if ch in "\\' \t\n\x0b\x0c\r" else ch for ch in p)


def quoted(p, every):
    if every:
        return "'" + "".join("\\" + ch for ch in p) + "'"
    return "'" + "".join("\\" + ch if ch in "\\'" else ch for ch in p) + "'"


def written(raw):
    return "".join(
        chr(b) if 0x21 <= b <= 0x7E and b != 0x25 else f"%{b:02X}" for b in raw
    )


def main():
    parse = libpq()
    rng = random.Random(0x6C69_6270_71)
    lines = []
    for k, p in enumerate(passwords(rng)):
        forms = [
            ("unquoted", escaped(p, False)),
            ("unquoted, every byte escaped", escaped(p, True)),
            ("quoted", quoted(p, False)),
            ("quoted, every byte escaped", quoted(p, True)),
        ]
        for name, e in forms:
            # Every kind of whitespace around `=` for F-65's two passwords.
            spaces = SPACES if k < 2 else [""]
            for sp in spaces:
                sep = sp if sp else " "
                for text in (
                    f"host=db.internal{sep}port=5432 user=app password{sp}={sp}{e}{sep}dbname=app",
                    f"password{sp}={sp}{e}",
                ):
                    raw = text.encode("utf-8")
                    got = parse(raw)
                    if got != p.encode("utf-8"):
                        raise SystemExit(f"libpq read another password from a {name} form")
                    exact = not (set(p) & INEXACT)
                    lines.append(f"{len(p)} {'exact' if exact else 'at-most'} {written(raw)}")
    with open(os.path.join(HERE, "passwords.txt"), "w", newline="\n") as f:
        f.write("# Generated by generate.py with libpq's PQconninfoParse; do not edit.\n")
        f.write("# <libpq's password characters> <exact|at-most> <connection string, %XX>\n")
        for line in lines:
            f.write(line + "\n")
    print(f"{len(lines)} connection strings")


if __name__ == "__main__":
    main()
