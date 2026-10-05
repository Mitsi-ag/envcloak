#!/usr/bin/env python3
"""Tests for scripts/check-sources.sh --swift (scripts/macos/
check_compiled_swift.py): every Swift file a build compiled is one
scripts/macos/check-swift.sh reads, and a target that ships compiles only
files check-swift.sh holds to the product rules.

Each case writes a derived-data tree shaped as xcodebuild writes it (one
<Target>.SwiftFileList per target under Build/Intermediates.noindex) and a
check-swift.sh listing, under a short temporary directory, and changes one
thing from a tree that passes. With --derived-data DIR, the real build
there is checked as well, and once more with a test file added to the
app's own list, which must fail.

Usage: python3 scripts/macos/tests/test_check_sources_swift.py [--derived-data DIR]
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CHECK_SOURCES = os.path.join(ROOT, "scripts", "check-sources.sh")
COMPARE = os.path.join(ROOT, "scripts", "macos", "check_compiled_swift.py")
REAL = {"derived": None}


def run(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode() + p.stderr.decode()


class Fixture:
    def __init__(self, base):
        self.dir = tempfile.mkdtemp(prefix="eccc", dir=base)
        self.derived = os.path.join(self.dir, "dd")
        self.src = os.path.join(self.dir, "src")
        self.product = self.source("App.swift")
        self.kit = self.source("Client.swift")
        self.test = self.source("AppTests.swift")
        self.accessor = os.path.join(self.derived, "Build/Intermediates.noindex/EnvCloakDesign.build/Debug/EnvCloakDesign.build/DerivedSources/resource_bundle_accessor.swift")
        self.touch(self.accessor)
        self.listing = {self.product: "product", self.kit: "product", self.test: "test"}
        self.lists = {"EnvCloak": [self.product], "EnvCloakKit": [self.kit], "EnvCloakTests": [self.test, self.product], "EnvCloakDesign": [self.accessor]}

    def source(self, name):
        path = os.path.join(self.src, name)
        self.touch(path)
        return os.path.realpath(path)

    @staticmethod
    def touch(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("// x\n")

    def check(self):
        for target, files in self.lists.items():
            fl = os.path.join(self.derived, "Build/Intermediates.noindex/X.build/Debug/%s.build/Objects-normal/arm64/%s.SwiftFileList" % (target, target))
            os.makedirs(os.path.dirname(fl), exist_ok=True)
            with open(fl, "w") as f:
                f.write("".join(p + "\n" for p in files))
        listing = os.path.join(self.dir, "listing")
        with open(listing, "w") as f:
            f.write("".join("%s %s\n" % (cls, path) for path, cls in self.listing.items()))
        return run([sys.executable, COMPARE, self.derived, listing])


class CompiledSources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="eccc", dir="/tmp")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    def refused(self, fx, needle):
        code, out = fx.check()
        self.assertEqual(code, 1, out)
        self.assertIn(needle, out)

    def test_a_build_of_read_files_passes(self):
        code, out = Fixture(self.base).check()
        self.assertEqual(code, 0, out)
        self.assertIn("4 Swift file lists", out)

    def test_a_test_file_compiled_into_the_app_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloak"].append(fx.test)
        self.refused(fx, "into EnvCloak, which ships, but check-swift.sh reads it as a test file")

    def test_a_test_file_compiled_into_a_new_target_is_refused(self):
        # A target nobody classified ships unless its name says Tests.
        fx = Fixture(self.base)
        fx.lists["EnvCloakKitTestSupport"] = [fx.test]
        self.refused(fx, "into EnvCloakKitTestSupport, which ships")

    def test_a_file_check_swift_does_not_read_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloak"].append(fx.source("Elsewhere.swift"))
        self.refused(fx, "which scripts/macos/check-swift.sh does not read")

    def test_a_generated_accessor_outside_derived_sources_is_refused(self):
        fx = Fixture(self.base)
        stray = os.path.join(fx.derived, "Build/Intermediates.noindex/Other/resource_bundle_accessor.swift")
        fx.touch(stray)
        fx.lists["EnvCloak"].append(stray)
        self.refused(fx, "which scripts/macos/check-swift.sh does not read")

    def test_no_build_is_refused(self):
        fx = Fixture(self.base)
        fx.lists = {}
        self.refused(fx, "no Swift file list")

    def test_a_listing_without_classes_is_refused(self):
        fx = Fixture(self.base)
        listing = os.path.join(fx.dir, "bare")
        with open(listing, "w") as f:
            f.write(fx.product + "\n")
        fx.check()
        code, out = run([sys.executable, COMPARE, fx.derived, listing])
        self.assertEqual(code, 1, out)
        self.assertIn("is not `<product|test> <path>`", out)


class RealBuild(unittest.TestCase):
    """The build given with --derived-data; without it these are reported
    as skipped, never as passed."""

    def setUp(self):
        if not REAL["derived"]:
            self.skipTest("no derived data given (--derived-data)")

    def test_the_build_passes(self):
        code, out = run(["bash", CHECK_SOURCES, "--swift", REAL["derived"]])
        self.assertEqual(code, 0, out)

    def test_the_build_with_a_test_file_in_the_app_fails(self):
        lists = []
        for dirpath, _, names in os.walk(os.path.join(REAL["derived"], "Build", "Intermediates.noindex")):
            lists.extend(os.path.join(dirpath, n) for n in names if n == "EnvCloak.SwiftFileList")
        self.assertTrue(lists, "the build has no EnvCloak.SwiftFileList")
        test_file = os.path.realpath(os.path.join(ROOT, "apps/macos/EnvCloakTests/LaunchTests.swift"))
        with tempfile.TemporaryDirectory(prefix="eccc", dir="/tmp") as copy:
            dd = os.path.join(copy, "dd")
            for fl in lists + [p for p in self.all_lists() if p not in lists]:
                dest = os.path.join(dd, os.path.relpath(fl, REAL["derived"]))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy(fl, dest)
                if fl in lists:
                    with open(dest, "a") as f:
                        f.write(test_file + "\n")
            code, out = run(["bash", CHECK_SOURCES, "--swift", dd])
            self.assertEqual(code, 1, out)
            self.assertIn("reads it as a test file", out)

    def all_lists(self):
        out = []
        for dirpath, _, names in os.walk(os.path.join(REAL["derived"], "Build", "Intermediates.noindex")):
            out.extend(os.path.join(dirpath, n) for n in names if n.endswith(".SwiftFileList"))
        return out


def main():
    args = sys.argv[1:]
    if args[:1] == ["--derived-data"] and len(args) >= 2:
        REAL["derived"] = os.path.abspath(args[1])
        args = args[2:]
    prog = unittest.main(argv=[sys.argv[0]] + args, exit=False, verbosity=2)
    result = prog.result
    if REAL["derived"] and result.skipped:
        print("test_check_sources_swift: derived data was given but %d test(s) were skipped" % len(result.skipped), file=sys.stderr)
        sys.exit(1)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
