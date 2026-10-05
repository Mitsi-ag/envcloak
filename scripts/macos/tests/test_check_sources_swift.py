#!/usr/bin/env python3
"""Tests for scripts/check-sources.sh --swift (scripts/macos/
check_compiled_swift.py): every Swift file a build compiled is one
scripts/macos/check-swift.sh reads, and a target that ships compiles only
files check-swift.sh holds to the product rules.

Each case writes a derived-data tree shaped as xcodebuild writes it (a
<Target>.SwiftFileList and a <Target>.LinkFileList per target under
Build/Intermediates.noindex) and a check-swift.sh listing, under a short
temporary directory, and changes one thing from a tree that passes. With
--derived-data DIR, the real build there is checked as well, once more
with a test file added to the app's own Swift list, and once more with an
object no Swift file made (a C file's) added to the app's link list; both
must fail.

Usage: python3 scripts/macos/tests/test_check_sources_swift.py [--derived-data DIR]
"""

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
        # Linked beyond each target's own objects: the packages' prelinked
        # objects into the app, the host app's Debug dylib into its tests.
        self.extra_links = {
            "EnvCloak": [self.product_object("EnvCloakKit"), self.product_object("EnvCloakDesign")],
            "EnvCloakTests": [os.path.join(self.derived, "Build/Products/Debug/EnvCloak.app/Contents/MacOS/EnvCloakApp.debug.dylib")],
        }
        self.unlisted_links = {}

    def product_object(self, target):
        return os.path.join(self.derived, "Build/Products/Debug/%s.o" % target)

    def objects_dir(self, target):
        return os.path.join(self.derived, "Build/Intermediates.noindex/X.build/Debug/%s.build/Objects-normal/arm64" % target)

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
            objects = self.objects_dir(target)
            fl = os.path.join(objects, "%s.SwiftFileList" % target)
            os.makedirs(objects, exist_ok=True)
            with open(fl, "w") as f:
                f.write("".join(p + "\n" for p in files))
            links = [os.path.join(objects, os.path.splitext(os.path.basename(p))[0] + ".o") for p in files] + self.extra_links.get(target, [])
            with open(os.path.join(objects, "%s.LinkFileList" % target), "w") as f:
                f.write("".join(p + "\n" for p in links))
        for target, links in self.unlisted_links.items():
            objects = self.objects_dir(target)
            os.makedirs(objects, exist_ok=True)
            with open(os.path.join(objects, "%s.LinkFileList" % target), "w") as f:
                f.write("".join(p + "\n" for p in links))
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

    def test_an_object_no_swift_file_made_is_refused(self):
        # A C or Objective-C file compiled into the app.
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(os.path.join(fx.objects_dir("EnvCloak"), "shim.o"))
        self.refused(fx, "links shim.o, which no Swift file EnvCloak compiled made")

    def test_an_object_replacing_a_swift_one_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloakKit"].append(fx.source("Extra.swift"))
        fx.listing[fx.lists["EnvCloakKit"][-1]] = "product"
        fx.check()
        ll = os.path.join(fx.objects_dir("EnvCloakKit"), "EnvCloakKit.LinkFileList")
        with open(ll, "w") as f:
            f.write(os.path.join(fx.objects_dir("EnvCloakKit"), "Client.o") + "\n" + os.path.join(fx.objects_dir("EnvCloakKit"), "shim.o") + "\n")
        listing = os.path.join(fx.dir, "listing")
        code, out = run([sys.executable, COMPARE, fx.derived, listing])
        self.assertEqual(code, 1, out)
        self.assertIn("links shim.o", out)

    def test_a_target_that_links_but_compiles_no_swift_is_refused(self):
        fx = Fixture(self.base)
        fx.unlisted_links["CShim"] = [os.path.join(fx.objects_dir("CShim"), "shim.o")]
        self.refused(fx, "links objects for CShim, which compiles no Swift file this check reads")

    def test_a_prelinked_object_of_no_target_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(fx.product_object("Analytics"))
        self.refused(fx, "which is not an object this build compiled from Swift")

    def test_a_debug_dylib_in_a_shipping_target_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(fx.extra_links["EnvCloakTests"][0])
        self.refused(fx, "which is not an object this build compiled from Swift")

    def test_a_link_list_from_outside_the_build_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(os.path.join(fx.dir, "elsewhere", "EnvCloakKit.o"))
        self.refused(fx, "which is not an object this build compiled from Swift")

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


def child_setup():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGPIPE):
        signal.signal(sig, signal.SIG_DFL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Stopped(unittest.TestCase):
    """check-sources.sh --swift leaves no listing behind however it stops:
    the comparison is held by a stand-in python3 (the real one runs
    check-swift.sh's listing) while a signal goes to its process group."""

    def test_a_stopped_check_leaves_no_listing(self):
        base = tempfile.mkdtemp(prefix="eccc", dir="/tmp")
        try:
            fx = Fixture(base)
            fx.check()
            stubs = os.path.join(base, "stubs")
            tmp = os.path.join(base, "tmp")
            os.makedirs(stubs)
            os.makedirs(tmp)
            held = os.path.join(base, "held")
            with open(os.path.join(stubs, "python3"), "w") as f:
                f.write(
                    "#!/bin/bash\n"
                    'case "$1" in *check_compiled_swift.py) : >"%s"; while :; do /bin/sleep 0.05; done ;; esac\n'
                    'exec "%s" "$@"\n' % (held, sys.executable)
                )
            os.chmod(os.path.join(stubs, "python3"), 0o755)
            env = {"PATH": stubs + ":/usr/bin:/bin", "TMPDIR": tmp, "HOME": base, "LC_ALL": "C"}
            for name in ("HUP", "INT", "QUIT", "TERM"):
                with self.subTest(signal=name):
                    if os.path.exists(held):
                        os.unlink(held)
                    p = subprocess.Popen(
                        ["/bin/bash", CHECK_SOURCES, "--swift", fx.derived, ROOT],
                        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, preexec_fn=child_setup,
                    )
                    deadline = time.monotonic() + 60
                    while not os.path.exists(held) and p.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(os.path.exists(held), "the comparison never ran")
                    self.assertEqual(len([n for n in os.listdir(tmp) if n.startswith("check-sources-swift.")]), 1, "no listing while it ran")
                    os.killpg(p.pid, getattr(signal, "SIG" + name))
                    try:
                        status = p.wait(timeout=30)
                    finally:
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except OSError:
                            # Gone (ESRCH), or only a zombie waiting to be
                            # reaped, which macOS answers with EPERM.
                            pass
                    self.assertNotEqual(status, 0)
                    self.assertEqual([n for n in os.listdir(tmp) if n.startswith("check-sources-swift.")], [], "the listing was left behind")
        finally:
            shutil.rmtree(base, ignore_errors=True)


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

    def test_the_build_with_a_c_object_in_the_app_fails(self):
        links = [p for p in self.all_lists((".LinkFileList",)) if os.path.basename(p) == "EnvCloak.LinkFileList"]
        self.assertTrue(links, "the build has no EnvCloak.LinkFileList")
        with tempfile.TemporaryDirectory(prefix="eccc", dir="/tmp") as copy:
            dd = os.path.join(copy, "dd")
            for fl in self.all_lists((".SwiftFileList", ".LinkFileList")):
                dest = os.path.join(dd, os.path.relpath(fl, REAL["derived"]))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(fl) as f:
                    text = f.read().replace(REAL["derived"].rstrip("/") + "/", dd + "/")
                if fl in links:
                    text += os.path.join(os.path.dirname(dest), "shim.o") + "\n"
                with open(dest, "w") as f:
                    f.write(text)
            code, out = run(["bash", CHECK_SOURCES, "--swift", dd])
            self.assertEqual(code, 1, out)
            self.assertIn("links shim.o, which no Swift file EnvCloak compiled made", out)

    def all_lists(self, suffixes=(".SwiftFileList",)):
        out = []
        for dirpath, _, names in os.walk(os.path.join(REAL["derived"], "Build", "Intermediates.noindex")):
            out.extend(os.path.join(dirpath, n) for n in names if n.endswith(suffixes))
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
