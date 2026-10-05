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
# Code compiled only for other targets or features is not in this list,
# and clippy does not lint it either. There check-unsafe.sh's text checks
# stand alone: they refuse the expose_secret names outside the allowlist in
# any cfg, and every lint attribute, #[path], include! and clippy cfg they
# can see, but not what a macro assembles from pieces.
#
#
# 3. With `--swift`, the macOS app instead (M3 plan §5 rule 7, task M3-02):
#    after an xcodebuild of apps/macos, every Swift file the compiler was
#    given (the build's *.SwiftFileList files) must be one
#    scripts/macos/check-swift.sh reads, or one of the two files the build
#    generates for a package with resources (SwiftPM's
#    resource_bundle_accessor.swift and Xcode's GeneratedAssetSymbols.swift,
#    in the build's own DerivedSources/). So a Swift file referenced from
#    outside apps/macos, linked in from elsewhere or written by a build phase
#    is refused. What each target is comes from what its linker wrote (a
#    .xctest bundle is a test bundle; a prelinked object in Build/Products
#    or a file in an app ships), never from its name: one that ships may
#    compile only files check-swift.sh holds to the product rules, so a test
#    file compiled into the app, or into any library linked into it, is
#    refused. What was linked is read from each target's link list, output
#    file map and the linker's own record of every file it read
#    (ld -dependency_info), all required: each object must be one the
#    output file map assigns to a Swift file of the target, another
#    target's prelinked object or, in a test bundle, the host app; and every
#    other file the linker read must be a Swift module, the macOS SDK, the
#    toolchain's runtime or, in a test bundle, XCTest. So an object compiled
#    from C, Objective-C or assembly and a library from a flag or a search
#    path are refused, and check-swift.sh's rules hold for everything linked
#    into the app. (check-swift.sh also refuses such sources and settings in
#    the tree.) The generated accessor's Debug-only environment override
#    never ships: scripts/macos/sign-check.sh refuses an artifact that holds
#    it. scripts/macos/check_compiled_swift.py does the comparison.
#
# Usage: scripts/check-sources.sh [workspace-root]
#        scripts/check-sources.sh --swift <xcodebuild derived data> [workspace-root]
# Runs $CARGO (default: cargo) with the caller's environment, so it checks
# the configuration CI's clippy steps lint when run with the same RUSTFLAGS.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

# make_listing NAME: makes this run's listing file and sets $listed to it.
# It is named $TMPDIR/NAME.<pid>.<run>.<random>, <run> drawn once from
# /dev/urandom, and the exit trap removes every such name of this run (not
# an earlier run's of the same pid), so it goes however the script stops:
# the four signals leave through that trap (bash runs no EXIT trap on
# SIGQUIT or SIGPIPE, measured with 3.2 and 5.3), and a name made in the
# instant before it reached a variable is removed too.
make_listing() {
  local candidate
  run_token="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  case "$run_token" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *)
      echo "check-sources: cannot read a run token from /dev/urandom" >&2
      exit 1
      ;;
  esac
  prefix="${TMPDIR:-/tmp}"
  prefix="${prefix%/}/$1.$$.$run_token"
  trap 'rm -f "$prefix".*' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 131' QUIT
  trap 'exit 143' TERM
  trap '' PIPE
  listed=""
  for _ in 1 2 3 4 5 6 7 8; do
    candidate="$prefix.$RANDOM$RANDOM"
    if (set -C && : >"$candidate") 2>/dev/null; then
      listed="$candidate"
      break
    fi
  done
  [ -n "$listed" ] || {
    echo "check-sources: cannot make a listing named $prefix.*" >&2
    exit 1
  }
}

if [ "${1:-}" = "--swift" ]; then
  [ $# -ge 2 ] || {
    echo "usage: scripts/check-sources.sh --swift <xcodebuild derived data> [workspace-root]" >&2
    exit 2
  }
  derived="$(cd "$2" && pwd -P)"
  root="$(cd "${3:-$here/..}" && pwd -P)"
  make_listing check-sources-swift
  bash "$here/macos/check-swift.sh" --list-swift --root "$root" >"$listed"
  python3 "$here/macos/check_compiled_swift.py" "$derived" "$listed"
  exit 0
fi

root="$(cd "${1:-$here/..}" && pwd -P)"
cd "$root"

make_listing check-sources
scanned="$listed"
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
