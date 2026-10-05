#!/usr/bin/env python3
"""The Swift half of scripts/check-sources.sh (`--swift`): every Swift file
an xcodebuild of apps/macos compiled is one scripts/macos/check-swift.sh
reads, with the class check-swift.sh gave it, or a file the build itself
generates for a package with resources; and everything the linker read for
a target is accounted for.

Usage: check_compiled_swift.py <derived data> <check-swift.sh --list-swift output>

Each target that compiles Swift leaves four files side by side under
Build/Intermediates.noindex, each named for the target, and all four are
required (a target missing any of them is a finding, so a partial record
never passes):
- <T>.SwiftFileList: the Swift files xcodebuild handed to swiftc;
- <T>-OutputFileMap.json: the object swiftc wrote for each of them;
- <T>.LinkFileList: the objects xcodebuild handed to the linker;
- <T>_dependency_info.dat: the linker's own record (ld -dependency_info)
  of the one file it wrote and every file it read, whether it came from
  the file list, a library search, a framework or a flag.

What a target is comes from what its linker wrote, never from its name: an
output inside a `.xctest` bundle is a test bundle; a prelinked object
`Build/Products/<config>/<name>.o` (how a local package's library reaches
the app) and an executable or dylib inside a `.app` ship; any other output
is a finding. A target that ships may compile only files check-swift.sh
holds to the product rules, so a test file compiled into the app, or into a
library linked into it whatever the library is called, fails here even
though check-swift.sh lets test files print and read the environment. The
generated files allowed are SwiftPM's resource_bundle_accessor.swift and
Xcode's GeneratedAssetSymbols.swift, and only where the build writes them:
a DerivedSources/ directory inside this derived data.

What is linked: each entry of a target's link list is an object its output
file map assigns to one of its Swift files, another target's prelinked
object, or, in a test bundle only, the host app's executable or dylib.
Each file the linker read is one of those, the link list itself, a Swift
module (`.swiftmodule`, read for debug information, and checked to be one
by its first bytes), a file of the macOS SDK (System/Library, usr/lib) or
of the toolchain's runtime (usr/lib/swift, usr/lib/clang) under the
developer directory (DEVELOPER_DIR, else `xcode-select -p`), or, in a test
bundle only, XCTest (the platform's Developer/Library and Developer/usr/lib)
and the host app inside Build/Products. So an object compiled from C,
Objective-C or assembly, a library from a search path or a flag, and a
test bundle linked into anything fail, and so does a target that links but
compiles no Swift.
"""

import json
import os
import subprocess
import sys

GENERATED = {"resource_bundle_accessor.swift", "GeneratedAssetSymbols.swift"}
SUFFIX = ".SwiftFileList"
LINK_SUFFIX = ".LinkFileList"
MAP_SUFFIX = "-OutputFileMap.json"
DEP_SUFFIX = "_dependency_info.dat"
# The first bytes of a serialized Swift module.
SWIFTMODULE_MAGIC = b"\xe2\x9c\xa8\x0e"


def read_list(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.rstrip("\n")]


def dependency_info(path):
    """ld's -dependency_info record: (output paths, input paths). Each
    record is a kind byte and a NUL-terminated path: 0x00 the linker's
    version (first, once), 0x10 a file it read, 0x11 one it looked for and
    did not find, 0x40 a file it wrote. Anything else raises ValueError."""
    with open(path, "rb") as f:
        data = f.read()
    outputs, inputs = [], []
    pos = 0
    versions = 0
    while pos < len(data):
        kind = data[pos]
        end = data.find(b"\0", pos + 1)
        if end < 0:
            raise ValueError("a record without its end at byte %d" % pos)
        text = data[pos + 1 : end].decode("utf-8", "surrogateescape")
        if kind == 0x00:
            if pos != 0:
                raise ValueError("a second version record")
            versions += 1
        elif kind == 0x10:
            inputs.append(text)
        elif kind == 0x40:
            outputs.append(text)
        elif kind != 0x11:
            raise ValueError("a record of kind 0x%02x" % kind)
        pos = end + 1
    if versions != 1:
        raise ValueError("no version record")
    return outputs, inputs


def developer_dir():
    """The developer directory the build used: DEVELOPER_DIR, else what
    xcode-select names; None if neither gives one."""
    d = os.environ.get("DEVELOPER_DIR", "")
    if not d:
        try:
            d = subprocess.run(["xcode-select", "-p"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout.decode().strip()
        except (OSError, subprocess.CalledProcessError):
            return None
    if os.path.isdir(os.path.join(d, "Contents", "Developer")):
        d = os.path.join(d, "Contents", "Developer")
    return os.path.realpath(d) if os.path.isdir(d) else None


def external_roots(dev):
    """(roots any target may read, roots only a test bundle may read), each
    a real path that ends with a separator."""
    def real(*parts):
        return os.path.realpath(os.path.join(*parts)) + os.sep

    platform = os.path.join(dev, "Platforms", "MacOSX.platform", "Developer")
    shipping = []
    sdks = os.path.join(platform, "SDKs")
    for name in sorted(os.listdir(sdks)) if os.path.isdir(sdks) else []:
        if name.startswith("MacOSX") and name.endswith(".sdk"):
            shipping += [real(sdks, name, "System", "Library"), real(sdks, name, "usr", "lib")]
    chains = os.path.join(dev, "Toolchains")
    for name in sorted(os.listdir(chains)) if os.path.isdir(chains) else []:
        if name.endswith(".xctoolchain"):
            shipping += [real(chains, name, "usr", "lib", "swift"), real(chains, name, "usr", "lib", "clang")]
    tests = [real(platform, "Library"), real(platform, "usr", "lib")]
    return sorted(set(shipping)), tests


def inside(path, root):
    return (path + os.sep).startswith(root + os.sep)


def output_kind(derived, out):
    """"test", "object" or "app" for a linker output, from where it is; None
    for anything else."""
    real = os.path.realpath(out)
    if not inside(real, derived):
        return None
    rel = os.path.relpath(real, derived).split(os.sep)
    if len(rel) < 4 or rel[:2] != ["Build", "Products"]:
        return None
    if any(p.endswith(".xctest") for p in rel[3:-1]):
        return "test"
    if len(rel) == 4 and rel[3].endswith(".o"):
        return "object"
    if any(p.endswith(".app") for p in rel[3:-1]):
        return "app"
    return None


class Target:
    def __init__(self, derived, base):
        self.base = base  # <dir>/<T>
        self.name = os.path.basename(base)
        self.where = os.path.relpath(base, derived)
        self.output = None
        self.kind = None
        self.own = set()
        self.links = []
        self.inputs = []


def read_target(derived, base, problems):
    """A target's four files, or None (with the problem) when one is
    missing or unreadable."""
    t = Target(derived, base)
    missing = [s for s in (LINK_SUFFIX, MAP_SUFFIX, DEP_SUFFIX) if not os.path.isfile(base + s)]
    if missing:
        problems.append("%s compiles Swift but the build left no %s beside its Swift file list, so what it linked was not checked" % (t.where, " or ".join(t.name + s for s in missing)))
        return None
    try:
        with open(base + MAP_SUFFIX, encoding="utf-8") as f:
            omap = json.load(f)
        if not isinstance(omap, dict) or not all(isinstance(v, dict) for v in omap.values()):
            raise ValueError("not a map of maps")
        outputs, t.inputs = dependency_info(base + DEP_SUFFIX)
    except (OSError, ValueError) as e:
        problems.append("%s: its output file map or linker record cannot be read (%s)" % (t.where, e))
        return None
    if len(outputs) != 1:
        problems.append("%s: the linker recorded %d outputs, not one" % (t.where, len(outputs)))
        return None
    t.output = os.path.realpath(outputs[0])
    t.kind = output_kind(derived, outputs[0])
    if t.kind is None:
        problems.append("%s links %s, which is not a test bundle, a prelinked object in Build/Products or a file in an app" % (t.where, outputs[0]))
        return None
    files = {os.path.realpath(p) for p in read_list(base + SUFFIX)}
    mapped = {os.path.realpath(k) for k in omap if k}
    if mapped != files:
        problems.append("%s: its output file map does not name the files its Swift file list does" % t.where)
        return None
    for key, entry in omap.items():
        obj = entry.get("object")
        if key and not obj:
            problems.append("%s: its output file map gives %s no object" % (t.where, key))
            return None
        if obj:
            t.own.add(os.path.realpath(obj))
    t.links = [os.path.realpath(p) for p in read_list(base + LINK_SUFFIX)]
    return t


def check_links(derived, targets, problems, dev):
    """Each object a target links, and each file its linker read, is
    accounted for. Returns the number of link list entries checked."""
    outputs = {t.output: t for t in targets}
    if dev is None:
        problems.append("no developer directory (DEVELOPER_DIR or xcode-select -p), so the files the linker read cannot be placed")
        shipping_roots, test_roots = [], []
    else:
        shipping_roots, test_roots = external_roots(dev)
    linked = 0
    for t in targets:
        test = t.kind == "test"
        for real in t.links:
            linked += 1
            if real in t.own:
                continue
            other = outputs.get(real)
            if other is not None and other is not t and (other.kind == "object" or (test and other.kind == "app")):
                continue
            if os.path.dirname(real) == os.path.dirname(t.base):
                problems.append("%s links %s, which no Swift file %s compiled made" % (t.where, os.path.basename(real), t.name))
            elif other is not None and other.kind == "test":
                problems.append("%s links %s, a test bundle" % (t.where, real))
            else:
                problems.append("%s links %s, which is not an object this build compiled from Swift" % (t.where, real))
        allowed = set(t.links) | {os.path.realpath(t.base + LINK_SUFFIX)}
        for path in t.inputs:
            real = os.path.realpath(path)
            if real in allowed:
                continue
            if inside(real, derived):
                if real.endswith(".swiftmodule"):
                    if not is_swift_module(real):
                        problems.append("the linker read %s for %s, which is named a Swift module but is not one" % (path, t.name))
                    continue
                rel = os.path.relpath(real, derived).split(os.sep)
                if test and rel[:2] == ["Build", "Products"] and any(p.endswith(".app") for p in rel[3:-1]):
                    continue
                problems.append("the linker read %s for %s, which is not in its link list" % (path, t.name))
                continue
            if any(real.startswith(r) for r in shipping_roots) or (test and any(real.startswith(r) for r in test_roots)):
                continue
            problems.append(
                "the linker read %s for %s, which is not from the macOS SDK or the toolchain under %s%s"
                % (path, t.name, dev, "" if test else " (XCTest only in a test bundle)")
            )
    return linked


def is_swift_module(path):
    try:
        with open(path, "rb") as f:
            return os.path.isfile(path) and f.read(4) == SWIFTMODULE_MAGIC
    except OSError:
        return False


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    derived = os.path.realpath(argv[1])
    scanned = {}
    problems = []
    with open(argv[2], encoding="utf-8", errors="surrogateescape") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            cls, sep, path = line.partition(" ")
            if not sep or cls not in ("product", "test") or not path:
                problems.append("line %d of the check-swift.sh listing is not `<product|test> <path>`" % n)
                continue
            scanned[os.path.realpath(path)] = cls
    lists, others = [], []
    for dirpath, _, filenames in os.walk(os.path.join(derived, "Build", "Intermediates.noindex")):
        for n in filenames:
            if n.endswith(SUFFIX):
                lists.append(os.path.join(dirpath, n)[: -len(SUFFIX)])
            elif n.endswith((LINK_SUFFIX, DEP_SUFFIX)):
                others.append(os.path.join(dirpath, n))
    bases = set(lists)
    for path in sorted(others):
        base = path[: -len(LINK_SUFFIX)] if path.endswith(LINK_SUFFIX) else path[: -len(DEP_SUFFIX)]
        if base not in bases:
            problems.append("%s links objects for %s, which compiles no Swift file this check reads" % (os.path.relpath(path, derived), os.path.basename(base)))
    targets = []
    for base in sorted(lists):
        t = read_target(derived, base, problems)
        if t is not None:
            targets.append(t)
    kinds = {t.base: t.kind for t in targets}
    compiled = generated = 0
    for base in sorted(lists):
        name = os.path.basename(base)
        where = os.path.relpath(base + SUFFIX, derived)
        # A target whose record could not be read is held to the product
        # rules: only a test bundle's linker output lets it compile tests.
        ships = kinds.get(base) != "test"
        for path in read_list(base + SUFFIX):
            compiled += 1
            real = os.path.realpath(path)
            if real in scanned:
                if ships and scanned[real] != "product":
                    problems.append("%s compiles %s into %s, which ships, but check-swift.sh reads it as a test file" % (where, path, name))
                continue
            inside_dd = inside(real, derived)
            if inside_dd and os.path.basename(real) in GENERATED and os.path.basename(os.path.dirname(real)) == "DerivedSources":
                generated += 1
                continue
            problems.append("%s compiles %s, which scripts/macos/check-swift.sh does not read" % (where, path))
    if not lists or compiled == 0:
        problems.append("no Swift file list under %s, so nothing was checked (build the app first)" % derived)
    linked = check_links(derived, targets, problems, developer_dir())
    if not scanned:
        problems.append("check-swift.sh listed no Swift file")
    for p in problems:
        print("check-sources: " + p, file=sys.stderr)
    if problems:
        return 1
    print(
        "check-sources: ok (%d targets: %s; %d compiled files: %d that check-swift.sh reads, %d generated package accessors;"
        " %d linked objects, each from them; every file the linker read accounted for)"
        % (
            len(targets),
            ", ".join("%s (%s)" % (t.name, "test bundle" if t.kind == "test" else "ships") for t in targets),
            compiled,
            compiled - generated,
            generated,
            linked,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
