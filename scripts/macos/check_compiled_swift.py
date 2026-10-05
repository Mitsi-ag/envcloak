#!/usr/bin/env python3
"""The Swift half of scripts/check-sources.sh (`--swift`): every Swift file
an xcodebuild of apps/macos compiled is one scripts/macos/check-swift.sh
reads, with the class check-swift.sh gave it, or a file the build itself
generates for a package with resources.

Usage: check_compiled_swift.py <derived data> <check-swift.sh --list-swift output>

The compiler's inputs come from the build's *.SwiftFileList files, one path
per line, which xcodebuild hands to swiftc; each list is named for the
target (the Swift module) it compiles. A target whose name ends in `Tests`
is a test target and may compile test and product files; every other
target ships (the app, the packages' libraries, and any target a later task
adds) and may compile only files check-swift.sh holds to the product rules,
so a test file compiled into a shipping target fails here even though
check-swift.sh lets test files print and read the environment. The
generated files allowed are SwiftPM's resource_bundle_accessor.swift and
Xcode's GeneratedAssetSymbols.swift, and only where the build writes them:
a DerivedSources/ directory inside this derived data.

What is linked is checked the same way, from the build's *.LinkFileList
files (the object files xcodebuild hands to the linker, one list per
target, beside that target's Swift file list): every object is one the
target compiled from a Swift file in its list (`<name>.o` for
`<name>.swift`; a basename two of its files share may carry a suffix), the
prelinked object of another target in this build that has its own lists
(`Build/Products/<config>/<target>.o`, how a local package's library
reaches the app), or, in a test target only, the host app's Debug dylib. So
an object compiled from C, Objective-C or assembly, which no Swift file
list names, fails, and so does a target that links objects but compiles no
Swift.
"""

import os
import sys

GENERATED = {"resource_bundle_accessor.swift", "GeneratedAssetSymbols.swift"}
SUFFIX = ".SwiftFileList"
LINK_SUFFIX = ".LinkFileList"


def read_list(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.rstrip("\n")]


def check_links(derived, link_lists, swift_lists, problems):
    """Each object a target links was compiled from Swift this build read."""
    targets = {os.path.basename(fl)[: -len(SUFFIX)] for fl in swift_lists}
    objects = 0
    for ll in sorted(link_lists):
        target = os.path.basename(ll)[: -len(LINK_SUFFIX)]
        where = os.path.relpath(ll, derived)
        sibling = ll[: -len(LINK_SUFFIX)] + SUFFIX
        if sibling not in swift_lists:
            problems.append("%s links objects for %s, which compiles no Swift file this check reads" % (where, target))
            continue
        stems = [os.path.splitext(os.path.basename(p))[0] for p in read_list(sibling)]
        shared = {s for s in stems if stems.count(s) > 1}
        own = 0
        for obj in read_list(ll):
            objects += 1
            real = os.path.realpath(obj)
            inside = (real + os.sep).startswith(derived + os.sep)
            name = os.path.basename(obj)
            stem, ext = os.path.splitext(name)
            if os.path.dirname(os.path.realpath(obj)) == os.path.dirname(os.path.realpath(ll)):
                own += 1
                if ext == ".o" and (stem in stems or any(stem.startswith(s + "-") for s in shared)):
                    continue
                problems.append("%s links %s, which no Swift file %s compiled made" % (where, name, target))
                continue
            rel = os.path.relpath(real, derived).split(os.sep) if inside else []
            if inside and len(rel) == 4 and rel[:2] == ["Build", "Products"] and ext == ".o" and stem in targets:
                continue
            if inside and target.endswith("Tests") and name.endswith(".debug.dylib") and rel[:2] == ["Build", "Products"] and any(r.endswith(".app") for r in rel):
                continue
            problems.append("%s links %s, which is not an object this build compiled from Swift" % (where, obj))
        if own != len(stems):
            problems.append("%s links %d object(s) of its own for the %d Swift file(s) %s compiled" % (where, own, len(stems), target))
    return objects


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
    lists = []
    link_lists = []
    for dirpath, _, filenames in os.walk(os.path.join(derived, "Build", "Intermediates.noindex")):
        lists.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(SUFFIX))
        link_lists.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(LINK_SUFFIX))
    compiled = generated = 0
    targets = set()
    for fl in sorted(lists):
        target = os.path.basename(fl)[: -len(SUFFIX)]
        targets.add(target)
        ships = not target.endswith("Tests")
        with open(fl, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                path = line.rstrip("\n")
                if not path:
                    continue
                compiled += 1
                real = os.path.realpath(path)
                where = os.path.relpath(fl, derived)
                if real in scanned:
                    if ships and scanned[real] != "product":
                        problems.append(
                            "%s compiles %s into %s, which ships, but check-swift.sh reads it as a test file" % (where, path, target)
                        )
                    continue
                inside = (real + os.sep).startswith(derived + os.sep)
                if inside and os.path.basename(real) in GENERATED and os.path.basename(os.path.dirname(real)) == "DerivedSources":
                    generated += 1
                    continue
                problems.append("%s compiles %s, which scripts/macos/check-swift.sh does not read" % (where, path))
    if not lists or compiled == 0:
        problems.append("no Swift file list under %s, so nothing was checked (build the app first)" % derived)
    linked = check_links(derived, link_lists, set(lists), problems)
    if lists and not link_lists:
        problems.append("no link file list under %s, so what was linked was not checked" % derived)
    if not scanned:
        problems.append("check-swift.sh listed no Swift file")
    for p in problems:
        print("check-sources: " + p, file=sys.stderr)
    if problems:
        return 1
    print(
        "check-sources: ok (%d Swift file lists for %s; %d compiled files: %d that check-swift.sh reads, %d generated package accessors; %d linked objects, each from them)"
        % (len(lists), ", ".join(sorted(targets)), compiled, compiled - generated, generated, linked)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
