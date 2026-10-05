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
"""

import os
import sys

GENERATED = {"resource_bundle_accessor.swift", "GeneratedAssetSymbols.swift"}
SUFFIX = ".SwiftFileList"


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
    for dirpath, _, filenames in os.walk(os.path.join(derived, "Build", "Intermediates.noindex")):
        lists.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(SUFFIX))
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
    if not scanned:
        problems.append("check-swift.sh listed no Swift file")
    for p in problems:
        print("check-sources: " + p, file=sys.stderr)
    if problems:
        return 1
    print(
        "check-sources: ok (%d Swift file lists for %s; %d compiled files: %d that check-swift.sh reads, %d generated package accessors)"
        % (len(lists), ", ".join(sorted(targets)), compiled, compiled - generated, generated)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
