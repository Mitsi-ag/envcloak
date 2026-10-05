#!/usr/bin/env python3
"""The Swift half of scripts/check-sources.sh (`--swift`): every Swift file
an xcodebuild of apps/macos compiled is one scripts/macos/check-swift.sh
reads, or a file the build itself generates for a package with resources.

Usage: check_compiled_swift.py <derived data> <file listing what check-swift.sh reads>

The compiler's inputs come from the build's *.SwiftFileList files, one path
per line, which xcodebuild hands to swiftc. The generated files allowed are
SwiftPM's resource_bundle_accessor.swift and Xcode's
GeneratedAssetSymbols.swift, and only where the build writes them: a
DerivedSources/ directory inside this derived data.
"""

import os
import sys

GENERATED = {"resource_bundle_accessor.swift", "GeneratedAssetSymbols.swift"}


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    derived = os.path.realpath(argv[1])
    with open(argv[2], encoding="utf-8", errors="surrogateescape") as f:
        scanned = {os.path.realpath(line.rstrip("\n")) for line in f if line.strip()}
    problems = []
    lists = []
    for dirpath, _, filenames in os.walk(os.path.join(derived, "Build", "Intermediates.noindex")):
        lists.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(".SwiftFileList"))
    compiled = generated = 0
    for fl in sorted(lists):
        with open(fl, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                path = line.rstrip("\n")
                if not path:
                    continue
                compiled += 1
                real = os.path.realpath(path)
                if real in scanned:
                    continue
                inside = (real + os.sep).startswith(derived + os.sep)
                if inside and os.path.basename(real) in GENERATED and os.path.basename(os.path.dirname(real)) == "DerivedSources":
                    generated += 1
                    continue
                problems.append(
                    "%s compiles %s, which scripts/macos/check-swift.sh does not read" % (os.path.relpath(fl, derived), path)
                )
    if not lists or compiled == 0:
        problems.append("no Swift file list under %s, so nothing was checked (build the app first)" % derived)
    if not scanned:
        problems.append("check-swift.sh listed no Swift file")
    for p in problems:
        print("check-sources: " + p, file=sys.stderr)
    if problems:
        return 1
    print(
        "check-sources: ok (%d Swift file lists, %d compiled files: %d that check-swift.sh reads, %d generated package accessors)"
        % (len(lists), compiled, compiled - generated, generated)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
