#!/usr/bin/env python3
"""Tests for scripts/check-sources.sh --swift (scripts/macos/
check_compiled_swift.py): every Swift file a build compiled is one
scripts/macos/check-swift.sh reads; a target that ships, which the linker's
output says and the target's name never does, compiles only files
check-swift.sh holds to the product rules; and every file the linker read
is accounted for.

Each case writes a derived-data tree shaped as xcodebuild writes it (per
target under Build/Intermediates.noindex: <T>.SwiftFileList,
<T>-OutputFileMap.json, <T>.LinkFileList and the linker's
<T>_dependency_info.dat in its binary form), a stand-in developer
directory holding the SDK, toolchain and XCTest files the linker reads, and
a check-swift.sh listing, under a short temporary directory, and changes
one thing from a tree that passes. With --derived-data DIR, the real build
there is checked as well, and then a clone of it (APFS clones, so no space
is copied) with one thing changed in its records: a test file added to the
app's Swift list, an object no Swift file made added to the app's link list
(as a C file's would be), a library from outside the SDK in what the
app's linker read, and the app's link record removed; each must fail.

Usage: python3 scripts/macos/tests/test_check_sources_swift.py [--derived-data DIR]
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True

from procgroup import Group  # noqa: E402 (after the bytecode switch)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CHECK_SOURCES = os.path.join(ROOT, "scripts", "check-sources.sh")
COMPARE = os.path.join(ROOT, "scripts", "macos", "check_compiled_swift.py")
REAL = {"derived": None}
SWIFTMODULE_MAGIC = b"\xe2\x9c\xa8\x0e"


def run(args, env=None):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return p.returncode, p.stdout.decode() + p.stderr.decode()


def dependency_info(output, inputs, extra=b""):
    """The linker's record as ld writes it: a version record, then each
    file read (0x10) and the file written (0x40)."""
    data = b"\x00@(#)PROGRAM:ld PROJECT:stand-in\n\x00"
    data += b"".join(b"\x10" + p.encode() + b"\x00" for p in inputs)
    data += b"\x11/nowhere/libmissing.tbd\x00"
    data += b"\x40" + output.encode() + b"\x00"
    return data + extra


class Fixture:
    """A build that passes: the app (EnvCloak) linking the two packages'
    prelinked objects, and a hosted test bundle (EnvCloakTests) linking the
    app's Debug dylib. Each attribute is one of the records' parts; a case
    changes one, then calls check()."""

    def __init__(self, base):
        self.dir = tempfile.mkdtemp(prefix="eccc", dir=base)
        self.derived = os.path.join(self.dir, "dd")
        self.src = os.path.join(self.dir, "src")
        self.dev = os.path.join(self.dir, "Xcode.app", "Contents", "Developer")
        platform = os.path.join(self.dev, "Platforms", "MacOSX.platform", "Developer")
        self.sdk_files = [
            os.path.join(platform, "SDKs", "MacOSX.sdk", "usr", "lib", "libSystem.tbd"),
            os.path.join(platform, "SDKs", "MacOSX.sdk", "System", "Library", "Frameworks", "Foundation.framework", "Foundation.tbd"),
            os.path.join(self.dev, "Toolchains", "XcodeDefault.xctoolchain", "usr", "lib", "swift", "macosx", "libswiftCompatibility56.a"),
        ]
        self.xctest = os.path.join(platform, "Library", "Frameworks", "XCTest.framework", "XCTest")
        for path in self.sdk_files + [self.xctest]:
            self.touch(path)
        os.symlink("MacOSX.sdk", os.path.join(platform, "SDKs", "MacOSX26.5.sdk"))
        self.product = self.source("App.swift")
        self.kit = self.source("Client.swift")
        self.test = self.source("AppTests.swift")
        self.accessor = os.path.join(self.derived, "Build/Intermediates.noindex/EnvCloakDesign.build/Debug/EnvCloakDesign.build/DerivedSources/resource_bundle_accessor.swift")
        self.touch(self.accessor)
        self.listing = {self.product: "product", self.kit: "product", self.test: "test"}
        self.lists = {"EnvCloak": [self.product], "EnvCloakKit": [self.kit], "EnvCloakTests": [self.test], "EnvCloakDesign": [self.accessor]}
        app = "Build/Products/Debug/EnvCloak.app/Contents/MacOS/"
        self.outputs = {
            "EnvCloak": self.at(app + "EnvCloakApp.debug.dylib"),
            "EnvCloakTests": self.at("Build/Products/Debug/EnvCloak.app/Contents/PlugIns/EnvCloakTests.xctest/Contents/MacOS/EnvCloakTests"),
        }
        # Linked beyond each target's own objects: the packages' prelinked
        # objects into the app, the host app's Debug dylib into its tests.
        self.extra_links = {
            "EnvCloak": [self.product_object("EnvCloakKit"), self.product_object("EnvCloakDesign")],
            "EnvCloakTests": [self.outputs["EnvCloak"]],
        }
        # Read by the linker beyond the link list: the SDK and the
        # toolchain, a module for debug information, and in the test bundle
        # XCTest and the host app's executable.
        self.extra_inputs = {"EnvCloakTests": [self.xctest, self.at(app + "EnvCloakApp")]}
        # Per target, the object each Swift file compiles to (default: its
        # stem's .o beside the lists).
        self.objects = {}
        self.missing = set()  # (target, suffix) not to write
        self.unlisted_links = {}
        self.unlisted_deps = {}
        self.env = dict(os.environ, DEVELOPER_DIR=self.dev)

    def at(self, rel):
        return os.path.join(self.derived, rel)

    def product_object(self, target):
        return self.at("Build/Products/Debug/%s.o" % target)

    def objects_dir(self, target):
        return self.at("Build/Intermediates.noindex/X.build/Debug/%s.build/Objects-normal/arm64" % target)

    def output(self, target):
        return self.outputs.get(target, self.product_object(target))

    def object(self, target, path):
        return self.objects.get(target, {}).get(path, os.path.join(self.objects_dir(target), os.path.splitext(os.path.basename(path))[0] + ".o"))

    def source(self, name):
        path = os.path.join(self.src, name)
        self.touch(path)
        return os.path.realpath(path)

    @staticmethod
    def touch(path, data=b"// x\n"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def write(self, target, suffix, data):
        if (target, suffix) not in self.missing:
            self.touch(os.path.join(self.objects_dir(target), target + suffix), data)

    def check(self):
        for target, files in self.lists.items():
            objects = self.objects_dir(target)
            module = os.path.join(objects, target + ".swiftmodule")
            self.touch(module, SWIFTMODULE_MAGIC + b"\x01\x08")
            omap = {"": {"swift-dependencies": os.path.join(objects, target + "-primary.swiftdeps")}}
            omap.update({p: {"object": self.object(target, p)} for p in files})
            links = [self.object(target, p) for p in files] + self.extra_links.get(target, [])
            inputs = [os.path.join(objects, target + ".LinkFileList"), module] + links + self.sdk_files + self.extra_inputs.get(target, [])
            self.write(target, ".SwiftFileList", "".join(p + "\n" for p in files).encode())
            self.write(target, "-OutputFileMap.json", json.dumps(omap).encode())
            self.write(target, ".LinkFileList", "".join(p + "\n" for p in links).encode())
            self.write(target, "_dependency_info.dat", dependency_info(self.output(target), inputs))
        for target, links in self.unlisted_links.items():
            self.touch(os.path.join(self.objects_dir(target), target + ".LinkFileList"), "".join(p + "\n" for p in links).encode())
        for target, data in self.unlisted_deps.items():
            self.touch(os.path.join(self.objects_dir(target), target + "_dependency_info.dat"), data)
        listing = os.path.join(self.dir, "listing")
        with open(listing, "w") as f:
            f.write("".join("%s %s\n" % (cls, path) for path, cls in self.listing.items()))
        return run([sys.executable, COMPARE, self.derived, listing], env=self.env)


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
        self.assertIn("4 targets: EnvCloak (ships), EnvCloakDesign (ships), EnvCloakKit (ships), EnvCloakTests (test bundle)", out)

    # ---------------------------------------------------- what is compiled

    def test_a_test_file_compiled_into_the_app_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloak"].append(fx.test)
        self.refused(fx, "into EnvCloak, which ships, but check-swift.sh reads it as a test file")

    def test_a_test_file_compiled_into_a_new_target_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloakKitTestSupport"] = [fx.test]
        self.refused(fx, "into EnvCloakKitTestSupport, which ships")

    def test_a_library_named_for_tests_linked_into_the_app_ships(self):
        # A library target whose name ends in Tests is still a library: its
        # prelinked object goes into the app, so a test file in it is
        # refused (the name once exempted it).
        fx = Fixture(self.base)
        fx.lists["AnalyticsTests"] = [fx.test]
        fx.extra_links["EnvCloak"].append(fx.product_object("AnalyticsTests"))
        self.refused(fx, "into AnalyticsTests, which ships, but check-swift.sh reads it as a test file")

    def test_a_test_bundle_is_known_by_its_output_not_its_name(self):
        # Positive control for the line above: a target with any name whose
        # linker wrote a .xctest bundle may compile test files.
        fx = Fixture(self.base)
        fx.lists["Probe"] = [fx.test]
        fx.outputs["Probe"] = fx.at("Build/Products/Debug/Probe.xctest/Contents/MacOS/Probe")
        fx.extra_inputs["Probe"] = [fx.xctest]
        code, out = fx.check()
        self.assertEqual(code, 0, out)
        self.assertIn("Probe (test bundle)", out)

    def test_a_test_bundle_linked_into_the_app_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(fx.outputs["EnvCloakTests"])
        self.refused(fx, "a test bundle")

    def test_an_output_of_another_kind_is_refused(self):
        fx = Fixture(self.base)
        fx.outputs["EnvCloakKit"] = fx.at("Build/Products/Debug/EnvCloakKit.framework/Versions/A/EnvCloakKit")
        self.refused(fx, "which is not a test bundle, a prelinked object in Build/Products or a file in an app")

    def test_a_file_check_swift_does_not_read_is_refused(self):
        fx = Fixture(self.base)
        fx.lists["EnvCloak"].append(fx.source("Elsewhere.swift"))
        self.refused(fx, "which scripts/macos/check-swift.sh does not read")

    def test_a_generated_accessor_outside_derived_sources_is_refused(self):
        fx = Fixture(self.base)
        stray = fx.at("Build/Intermediates.noindex/Other/resource_bundle_accessor.swift")
        fx.touch(stray)
        fx.lists["EnvCloak"].append(stray)
        self.refused(fx, "which scripts/macos/check-swift.sh does not read")

    # ------------------------------------------------------- what is linked

    def test_an_object_no_swift_file_made_is_refused(self):
        # A C or Objective-C file compiled into the app.
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(os.path.join(fx.objects_dir("EnvCloak"), "shim.o"))
        self.refused(fx, "links shim.o, which no Swift file EnvCloak compiled made")

    def test_an_object_beside_two_files_of_one_name_is_refused(self):
        # Two Swift files share a name; a third object whose name starts
        # with it rides along. The output file map names each file's own
        # object, so the extra one is refused.
        fx = Fixture(self.base)
        second = os.path.realpath(fx.source("sub/App.swift"))
        fx.listing[second] = "product"
        fx.lists["EnvCloak"].append(second)
        fx.objects["EnvCloak"] = {second: os.path.join(fx.objects_dir("EnvCloak"), "App-1.o")}
        fx.extra_links["EnvCloak"].append(os.path.join(fx.objects_dir("EnvCloak"), "App-shim.o"))
        self.refused(fx, "links App-shim.o, which no Swift file EnvCloak compiled made")

    def test_an_object_replacing_a_swift_one_is_refused(self):
        fx = Fixture(self.base)
        extra = fx.source("Extra.swift")
        fx.lists["EnvCloakKit"].append(extra)
        fx.listing[extra] = "product"
        fx.objects["EnvCloakKit"] = {extra: os.path.join(fx.objects_dir("EnvCloakKit"), "Extra.o")}
        fx.extra_links["EnvCloakKit"] = [os.path.join(fx.objects_dir("EnvCloakKit"), "shim.o")]
        self.refused(fx, "links shim.o")

    def test_a_target_that_links_but_compiles_no_swift_is_refused(self):
        fx = Fixture(self.base)
        fx.unlisted_links["CShim"] = [os.path.join(fx.objects_dir("CShim"), "shim.o")]
        self.refused(fx, "links objects for CShim, which compiles no Swift file this check reads")

    def test_a_link_record_with_no_swift_list_is_refused(self):
        fx = Fixture(self.base)
        fx.unlisted_deps["CShim"] = dependency_info(fx.product_object("CShim"), [])
        self.refused(fx, "links objects for CShim, which compiles no Swift file this check reads")

    def test_a_prelinked_object_of_no_target_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(fx.product_object("Analytics"))
        self.refused(fx, "which is not an object this build compiled from Swift")

    def test_a_debug_dylib_in_a_shipping_target_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloakKit"] = [fx.outputs["EnvCloak"]]
        self.refused(fx, "which is not an object this build compiled from Swift")

    def test_a_link_list_from_outside_the_build_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_links["EnvCloak"].append(os.path.join(fx.dir, "elsewhere", "EnvCloakKit.o"))
        self.refused(fx, "which is not an object this build compiled from Swift")

    def test_each_record_of_a_target_is_required(self):
        # A partial record never passes: without its link list nothing it
        # linked would be checked.
        for suffix in (".LinkFileList", "-OutputFileMap.json", "_dependency_info.dat"):
            with self.subTest(missing=suffix):
                fx = Fixture(self.base)
                fx.missing.add(("EnvCloak", suffix))
                self.refused(fx, "compiles Swift but the build left no EnvCloak%s" % suffix)

    def test_a_map_that_names_other_files_is_refused(self):
        fx = Fixture(self.base)
        fx.objects["EnvCloak"] = {}
        fx.check()
        path = os.path.join(fx.objects_dir("EnvCloak"), "EnvCloak-OutputFileMap.json")
        with open(path, "w") as f:
            json.dump({fx.kit: {"object": os.path.join(fx.objects_dir("EnvCloak"), "App.o")}}, f)
        code, out = run([sys.executable, COMPARE, fx.derived, os.path.join(fx.dir, "listing")], env=fx.env)
        self.assertEqual(code, 1, out)
        self.assertIn("its output file map does not name the files its Swift file list does", out)

    def test_a_map_that_gives_a_file_no_object_is_refused(self):
        # Without its object, what the file compiled to could not be told
        # from any other object in the link list.
        fx = Fixture(self.base)
        fx.check()
        path = os.path.join(fx.objects_dir("EnvCloak"), "EnvCloak-OutputFileMap.json")
        with open(path, "w") as f:
            json.dump({fx.product: {"swift-dependencies": os.path.join(fx.objects_dir("EnvCloak"), "App.swiftdeps")}}, f)
        code, out = run([sys.executable, COMPARE, fx.derived, os.path.join(fx.dir, "listing")], env=fx.env)
        self.assertEqual(code, 1, out)
        self.assertIn("its output file map gives %s no object" % fx.product, out)

    # ------------------------------------------- what the linker read

    def test_a_library_from_outside_the_sdk_is_refused(self):
        # A library a flag or a search path hands the linker is in no link
        # list; the linker's record names it.
        fx = Fixture(self.base)
        lib = os.path.join(fx.dir, "vendor", "libanalytics.a")
        fx.touch(lib)
        fx.extra_inputs["EnvCloak"] = [lib]
        self.refused(fx, "the linker read %s for EnvCloak, which is not from the macOS SDK or the toolchain" % lib)

    def test_a_library_inside_the_build_but_in_no_link_list_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_inputs["EnvCloak"] = [fx.at("Build/Products/Debug/libsdk.a")]
        self.refused(fx, "which is not in its link list")

    def test_xctest_in_a_shipping_target_is_refused(self):
        fx = Fixture(self.base)
        fx.extra_inputs["EnvCloak"] = [fx.xctest]
        self.refused(fx, "the linker read %s for EnvCloak" % fx.xctest)

    def test_a_path_that_leaves_the_sdk_is_refused(self):
        fx = Fixture(self.base)
        lib = os.path.join(fx.dir, "vendor", "libanalytics.a")
        fx.touch(lib)
        here = os.path.dirname(fx.sdk_files[0])
        escaped = os.path.join(here, os.path.relpath(lib, here))
        self.assertTrue(escaped.startswith(here + "/.."), escaped)
        self.assertEqual(os.path.realpath(escaped), os.path.realpath(lib))
        fx.extra_inputs["EnvCloak"] = [escaped]
        self.refused(fx, "which is not from the macOS SDK or the toolchain")

    def test_an_object_named_as_a_swift_module_is_refused(self):
        fx = Fixture(self.base)
        fake = fx.at("Build/Products/Debug/Shim.swiftmodule")
        fx.touch(fake, b"\xcf\xfa\xed\xfe" + bytes(28))
        fx.extra_inputs["EnvCloak"] = [fake]
        self.refused(fx, "which is named a Swift module but is not one")

    def test_a_link_record_it_cannot_read_is_refused(self):
        for name, data in (("two outputs", lambda fx: dependency_info(fx.output("EnvCloak"), [], b"\x40/tmp/second\x00")), ("an unknown record", lambda fx: dependency_info(fx.output("EnvCloak"), [], b"\x20x\x00")), ("a cut record", lambda fx: dependency_info(fx.output("EnvCloak"), [])[:-1]), ("no version", lambda fx: dependency_info(fx.output("EnvCloak"), [])[1:])):
            with self.subTest(record=name):
                fx = Fixture(self.base)
                fx.missing.add(("EnvCloak", "_dependency_info.dat"))
                fx.unlisted_deps["EnvCloak"] = data(fx)
                code, out = fx.check()
                self.assertEqual(code, 1, out)
                self.assertTrue("cannot be read" in out or "not one" in out, out)

    def test_no_developer_directory_is_refused(self):
        fx = Fixture(self.base)
        fx.env["DEVELOPER_DIR"] = os.path.join(fx.dir, "nowhere")
        self.refused(fx, "no developer directory")

    # ------------------------------------------------------------- inputs

    def test_no_build_is_refused(self):
        fx = Fixture(self.base)
        fx.lists = {}
        self.refused(fx, "no Swift file list")

    def test_an_empty_listing_is_refused(self):
        # A check-swift.sh that listed nothing is a broken listing, said as
        # such, whatever else the build shows.
        fx = Fixture(self.base)
        fx.listing = {}
        self.refused(fx, "check-swift.sh listed no Swift file")

    def test_a_listing_without_classes_is_refused(self):
        fx = Fixture(self.base)
        listing = os.path.join(fx.dir, "bare")
        with open(listing, "w") as f:
            f.write(fx.product + "\n")
        fx.check()
        code, out = run([sys.executable, COMPARE, fx.derived, listing], env=fx.env)
        self.assertEqual(code, 1, out)
        self.assertIn("is not `<product|test> <path>`", out)


# The stand-in python3 that holds the comparison: it marks that it holds,
# then polls until it is stopped, giving up after a bound; with HEARTBEAT
# set it appends a byte there on each poll, so a test can see from outside
# whether it still runs.
HOLDING_PYTHON = """#!/bin/bash
case "$1" in
  *check_compiled_swift.py)
    : >"%(held)s"
    n=0
    while [ "$n" -lt 4000 ]; do
      [ -z "${HEARTBEAT:-}" ] || printf . >>"$HEARTBEAT"
      /bin/sleep 0.05
      n=$((n + 1))
    done
    exit 99 ;;
esac
exec "%(python)s" "$@"
"""


# The stand-in cargo the Rust check runs ($CARGO), which holds the same way.
HOLDING_CARGO = """#!/bin/bash
: >"%(held)s"
n=0
while [ "$n" -lt 4000 ]; do
  [ -z "${HEARTBEAT:-}" ] || printf . >>"$HEARTBEAT"
  /bin/sleep 0.05
  n=$((n + 1))
done
exit 99
"""


class Stopped(unittest.TestCase):
    """check-sources.sh leaves no listing behind however it stops, in both
    of its modes: with --swift the comparison is held by a stand-in python3
    (the real one runs check-swift.sh's listing), and the Rust check is
    held by a stand-in cargo, while a signal goes to the script's process
    group. A listing an earlier run of the same pid kept is not this run's
    to remove. However a case ends, every process of its group is ended and
    confirmed gone (procgroup.py)."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="eccc", dir="/tmp")
        self.fx = Fixture(self.base)
        self.fx.check()
        stubs = os.path.join(self.base, "stubs")
        self.tmp = os.path.join(self.base, "tmp")
        os.makedirs(stubs)
        os.makedirs(self.tmp)
        self.held = os.path.join(self.base, "held")
        with open(os.path.join(stubs, "python3"), "w") as f:
            f.write(HOLDING_PYTHON % {"held": self.held, "python": sys.executable})
        os.chmod(os.path.join(stubs, "python3"), 0o755)
        self.cargo = os.path.join(stubs, "cargo")
        with open(self.cargo, "w") as f:
            f.write(HOLDING_CARGO % {"held": self.held})
        os.chmod(self.cargo, 0o755)
        self.env = {"PATH": stubs + ":/usr/bin:/bin", "TMPDIR": self.tmp, "HOME": self.base, "LC_ALL": "C"}
        self.groups = []

    def tearDown(self):
        # A net for a case whose own cleanup was taken out (the mutation
        # the early-failure case is checked against); close is idempotent.
        try:
            for g in self.groups:
                g.close()
        finally:
            shutil.rmtree(self.base, ignore_errors=True)

    def listings(self, rust=False):
        prefix = "check-sources." if rust else "check-sources-swift."
        return sorted(n for n in os.listdir(self.tmp) if n.startswith(prefix))

    def stop_once(self, name, early=None, rust=False, **env):
        """Runs the check until the comparison (or, with rust, cargo) holds,
        signals its group, and returns its status. With `early`, raises
        that once it holds instead, as a failed assertion would."""
        if os.path.exists(self.held):
            os.unlink(self.held)
        if rust:
            args = ["/bin/bash", CHECK_SOURCES, ROOT]
            env = dict(env, CARGO=self.cargo)
        else:
            args = ["/bin/bash", CHECK_SOURCES, "--swift", self.fx.derived, ROOT]
        g = Group(args, env=dict(self.env, **env), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.groups.append(g)
        kept = None
        try:
            deadline = time.monotonic() + 180
            while not os.path.exists(self.held) and not g.ended() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(os.path.exists(self.held), "the comparison never ran")
            self.assertTrue(g.live(), "nothing was running in the check's group")
            if early is not None:
                raise early()
            self.assertEqual(len(self.listings(rust)), 1, "no listing while it ran")
            # A listing an earlier run of this pid left: the stop must not
            # remove it.
            kept = os.path.join(self.tmp, "%s%d.earlier" % ("check-sources." if rust else "check-sources-swift.", g.pgid))
            with open(kept, "w") as f:
                f.write("kept\n")
            g.signal(getattr(signal, "SIG" + name))
            self.assertTrue(g.wait_ended(180), "the check did not end\n" + g.ps())
        finally:
            status = g.close()
        self.assertEqual(self.listings(rust), [os.path.basename(kept)], "this run's listing was left behind, or an earlier one removed")
        os.unlink(kept)
        return status

    def test_a_stopped_check_leaves_no_listing(self):
        for name in ("HUP", "INT", "QUIT", "TERM"):
            with self.subTest(signal=name):
                self.assertNotEqual(self.stop_once(name), 0)

    def test_a_stopped_rust_check_leaves_no_listing(self):
        # The same listing in the Rust check, which before this round was a
        # mktemp name removed only by the exit trap (so SIGQUIT left it).
        for name in ("HUP", "INT", "QUIT", "TERM"):
            with self.subTest(signal=name):
                self.assertNotEqual(self.stop_once(name, rust=True), 0)

    def test_a_case_that_fails_early_leaves_no_process_running(self):
        # A case that fails while the stand-in holds still ends it: nothing
        # polls on after the case.
        class Early(Exception):
            pass

        heartbeat = os.path.join(self.base, "beat")
        with self.assertRaises(Early):
            self.stop_once("TERM", early=Early, HEARTBEAT=heartbeat)
        before = os.path.getsize(heartbeat)
        time.sleep(1.0)
        self.assertEqual(os.path.getsize(heartbeat), before, "the stand-in still polls after the case ended")
        self.assertIsNotNone(self.groups[-1].status, "the check was not reaped")


class RealBuild(unittest.TestCase):
    """The build given with --derived-data; without it these are reported
    as skipped, never as passed. Each refusal changes one thing in an APFS
    clone of the build (cp -c: no file data is copied), with every path in
    its records moved to the clone."""

    RECORDS = (".SwiftFileList", ".LinkFileList", "-OutputFileMap.json", "_dependency_info.dat")

    def setUp(self):
        if not REAL["derived"]:
            self.skipTest("no derived data given (--derived-data)")

    def test_the_build_passes(self):
        code, out = run(["bash", CHECK_SOURCES, "--swift", REAL["derived"]])
        self.assertEqual(code, 0, out)

    def clone(self, copy):
        """Clones the build into copy/dd and moves its records' paths there;
        returns (the clone, the base path of the app target's records)."""
        dd = os.path.join(copy, "dd")
        subprocess.run(["/bin/cp", "-cR", REAL["derived"], dd], check=True)
        olds = sorted({REAL["derived"].rstrip("/"), os.path.realpath(REAL["derived"])}, key=len, reverse=True)
        bases = []
        for dirpath, _, names in os.walk(os.path.join(dd, "Build", "Intermediates.noindex")):
            for n in names:
                if n.endswith(self.RECORDS):
                    path = os.path.join(dirpath, n)
                    with open(path, "rb") as f:
                        data = f.read()
                    for old in olds:
                        data = data.replace(old.encode() + b"/", dd.encode() + b"/")
                    with open(path, "wb") as f:
                        f.write(data)
                if n == "EnvCloak.SwiftFileList":
                    bases.append(os.path.join(dirpath, n)[: -len(".SwiftFileList")])
        self.assertEqual(len(bases), 1, "the build has no single EnvCloak target: %s" % bases)
        code, out = run(["bash", CHECK_SOURCES, "--swift", dd])
        self.assertEqual(code, 0, "the unchanged clone does not pass\n" + out)
        return dd, bases[0]

    def refused(self, change, needle):
        with tempfile.TemporaryDirectory(prefix="eccc", dir="/tmp") as copy:
            dd, app = self.clone(copy)
            change(dd, app)
            code, out = run(["bash", CHECK_SOURCES, "--swift", dd])
            self.assertEqual(code, 1, out)
            self.assertIn(needle, out)

    def test_the_build_with_a_test_file_in_the_app_fails(self):
        test_file = os.path.realpath(os.path.join(ROOT, "apps/macos/EnvCloakTests/LaunchTests.swift"))

        def change(dd, app):
            with open(app + ".SwiftFileList", "a") as f:
                f.write(test_file + "\n")

        self.refused(change, "reads it as a test file")

    def test_the_build_with_a_c_object_in_the_app_fails(self):
        def change(dd, app):
            with open(app + ".LinkFileList", "a") as f:
                f.write(os.path.join(os.path.dirname(app), "shim.o") + "\n")

        self.refused(change, "links shim.o, which no Swift file EnvCloak compiled made")

    def test_the_build_with_a_library_from_outside_the_sdk_fails(self):
        def change(dd, app):
            lib = os.path.join(os.path.dirname(dd), "vendor", "libanalytics.a")
            os.makedirs(os.path.dirname(lib))
            with open(lib, "wb") as f:
                f.write(b"!<arch>\n")
            with open(app + "_dependency_info.dat", "ab") as f:
                f.write(b"\x10" + lib.encode() + b"\x00")

        self.refused(change, "libanalytics.a for EnvCloak, which is not from the macOS SDK or the toolchain")

    def test_the_build_without_the_apps_link_list_fails(self):
        def change(dd, app):
            os.unlink(app + ".LinkFileList")

        self.refused(change, "compiles Swift but the build left no EnvCloak.LinkFileList")


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
