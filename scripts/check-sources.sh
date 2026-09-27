#!/usr/bin/env bash
# Proves that the compiler reads no Rust code that scripts/check-unsafe.sh
# has not read (SPEC §5, "Memory hygiene"). check-unsafe.sh reads source
# text, so it can only guess at `#[path]` and `include!` from their
# spelling, and a macro can build either from pieces no text check sees
# (`m!(path "x.txt")` expanding to `#[path = "x.txt"] mod m;`, say). A file
# compiled that way could carry `#![allow(clippy::disallowed_methods)]` and
# open secrets outside security/expose-allowlist.txt. So this script asks
# the compiler instead:
#
# 1. It runs `cargo check` in the two configurations CI lints with clippy:
#    every workspace target in the dev profile, and the shipped binaries
#    (the default members in the release profile, without test-only
#    features). For each workspace compilation unit it reads the dep-info
#    file rustc writes, which lists every file the compiler read, and fails
#    unless each one is a Rust file check-unsafe.sh scans. That catches
#    `#[path]`, `include!`, `include_str!` and `include_bytes!` however they
#    are spelled or generated. check-unsafe.sh forbids the `clippy` cfg, so
#    clippy compiles the same files `cargo check` does.
# 2. Every proc-macro crate compiled for the workspace must be listed in
#    security/proc-macro-allowlist.txt (and every entry must still be a
#    proc-macro package in the dependency graph). A proc-macro can build
#    `disallowed_methods` or `include` from pieces, so each one needs
#    review. check-unsafe.sh already forbids proc-macro crates in the
#    workspace itself.
#
# Configurations CI does not build (other targets or features) are covered
# only by check-unsafe.sh's text checks.
#
# Usage: scripts/check-sources.sh [workspace-root]
# Runs $CARGO (default: cargo) with the caller's environment, so it checks
# the configuration CI's clippy steps lint when run with the same RUSTFLAGS.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${1:-$here/..}" && pwd -P)"
cd "$root"

scanned="$(mktemp "${TMPDIR:-/tmp}/check-sources.XXXXXX")"
trap 'rm -f "$scanned"' EXIT
bash "$here/check-unsafe.sh" --list-rust "$root" >"$scanned"

python3 - "$root" "$scanned" <<'PY'
import json, os, re, subprocess, sys

root, scanned_list = sys.argv[1], sys.argv[2]
CARGO = os.environ.get("CARGO") or "cargo"
ALLOWLIST = "security/proc-macro-allowlist.txt"
RUNS = (
    ("dev profile, every workspace target", ["check", "--workspace", "--all-targets"]),
    ("release profile, shipped binaries", ["check", "--release"]),
)

problems = []


def fail(msg):
    problems.append(msg)


def real(path):
    return os.path.realpath(os.path.join(root, path))


def shown(path):
    rel = os.path.relpath(path, root)
    return path if rel.startswith("..") else rel


with open(scanned_list) as f:
    scanned = {real(line.rstrip("\n")) for line in f if line.strip()}


def cargo(args):
    proc = subprocess.run(
        [CARGO, *args, "--locked", "--message-format=json"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    messages = []
    for line in proc.stdout.splitlines():
        try:
            messages.append(json.loads(line))
        except ValueError:
            continue
    if proc.returncode != 0:
        for m in messages:
            rendered = (m.get("message") or {}).get("rendered")
            if m.get("reason") == "compiler-message" and rendered:
                sys.stderr.write(rendered)
        sys.stderr.write(proc.stderr.decode(errors="replace"))
        sys.exit("check-sources: cargo %s failed" % " ".join(args))
    return messages


# A dep-info rule is "target: prerequisite ..." with spaces in paths escaped
# as "\ ". The output files are the targets of rules with prerequisites;
# every file read appears as a prerequisite and as a rule of its own.
RULE = re.compile(r"((?:[^\\:]|\\.)+):(?: (.*))?$")
WORD = re.compile(r"(?:[^\\ ]|\\.)+")


def unescape(word):
    return re.sub(r"\\(.)", r"\1", word)


def dep_info(path):
    read = set()
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            m = RULE.match(line)
            if not m:
                fail("%s: cannot read this dep-info line: %r" % (shown(path), line))
                continue
            if m.group(2):
                read.update(unescape(w) for w in WORD.findall(m.group(2)))
            else:
                read.add(unescape(m.group(1)))
    return read


def dep_info_file(filenames):
    """rustc writes deps/<stem>.d beside deps/lib<stem>.rmeta."""
    for name in filenames:
        base, _ = os.path.splitext(os.path.basename(name))
        for stem in (base[3:] if base.startswith("lib") else None, base):
            if stem:
                candidate = os.path.join(os.path.dirname(name), stem + ".d")
                if os.path.isfile(candidate):
                    return candidate
    return None


meta = json.loads(
    subprocess.run(
        [CARGO, "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
)
members = set(meta["workspace_members"])
package_name = {p["id"]: p["name"] for p in meta["packages"]}
proc_macro_packages = {
    p["name"]
    for p in meta["packages"]
    if any("proc-macro" in t["kind"] for t in p["targets"])
}

compiled_proc_macros = set()
reported = set()
for label, args in RUNS:
    units = 0
    for m in cargo(args):
        if m.get("reason") != "compiler-artifact":
            continue
        target = m["target"]
        if m["package_id"] not in members:
            if "proc-macro" in target["kind"]:
                compiled_proc_macros.add(package_name.get(m["package_id"], target["name"]))
            continue
        units += 1
        unit = "%s (%s %s, %s)" % (target["name"], "/".join(target["kind"]), "test" if m["profile"]["test"] else "build", label)
        d = dep_info_file(m.get("filenames") or [])
        if d is None:
            fail("%s: rustc wrote no dep-info file, so its sources cannot be checked" % unit)
            continue
        for path in sorted(dep_info(d)):
            full = real(path)
            if full in scanned:
                continue
            key = (target["name"], full)
            if key in reported:
                continue
            reported.add(key)
            fail(
                "%s: compiled %s, which scripts/check-unsafe.sh does not read "
                "(only tracked or unignored .rs files are checked; #[path], include! "
                "and include_str! may not reach anything else)" % (unit, shown(full))
            )
    if units == 0:
        fail("%s: cargo reported no workspace units, so nothing was checked" % label)

allowed = set()
try:
    with open(os.path.join(root, ALLOWLIST)) as f:
        for line in f:
            entry = line.split("#", 1)[0].strip()
            if entry:
                allowed.add(entry)
except OSError:
    fail("%s is missing" % ALLOWLIST)

for name in sorted(compiled_proc_macros - allowed):
    fail(
        "the proc-macro crate %s is compiled for the workspace but not listed in %s "
        "(a proc-macro can generate lint attributes and includes no source check sees)"
        % (name, ALLOWLIST)
    )
for name in sorted(allowed):
    if name not in proc_macro_packages:
        fail("%s: %s is not a proc-macro package in the dependency graph" % (ALLOWLIST, name))

for msg in problems:
    print("check-sources: " + msg, file=sys.stderr)
if problems:
    sys.exit(1)
print("check-sources: ok")
PY
