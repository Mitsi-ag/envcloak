#!/usr/bin/env python3
"""Tests for scripts/macos/sign-check.sh (gate 19 for the bundle; M3 plan
D3-05, D3-06), on bundles built here from tiny programs and signed with
the real codesign, and, with --app, on a built EnvCloak.app.

Every refusal case changes one property of a bundle that passes. Before a
refusal counts, an independent reader (oracles/codesign_facts.swift, the
Security framework's SecStaticCode, where sign-check reads codesign's text)
confirms the fixture really has the property, so a fixture that went wrong
cannot pass a refusal test by accident; and on the passing bundle and the
built app the two readers must agree on every executable's identifier,
flags, runtime bit and entitlement keys.

Usage: python3 scripts/macos/tests/test_sign_check.py [--app path/to/EnvCloak.app]
Fixtures live under a short temporary directory that is removed afterwards.
"""

import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(SCRIPTS))
SIGN_CHECK = os.path.join(SCRIPTS, "sign-check.sh")
LAUNCH_AGENT = os.path.join(ROOT, "apps/macos/Support/LaunchAgents/ai.envcloak.agent.plist")
APP_EXE = "Contents/MacOS/EnvCloakApp"
CLI_EXE = "Contents/MacOS/envcloak"
HELPER = "Contents/Helpers/EnvCloakAgent.app"
DAEMON_EXE = HELPER + "/Contents/MacOS/envcloakd"
EXCEPTIONS = (
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.debugger",
)

def run(args, **kw):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


class Workspace:
    """Compiled programs and the oracle, shared by every case."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="ecsc", dir="/tmp")
        src = os.path.join(self.dir, "main.c")
        with open(src, "w") as f:
            f.write("int main(void) { return 0; }\n")
        debug_src = os.path.join(self.dir, "debug.c")
        with open(debug_src, "w") as f:
            # The name SwiftPM's Debug-only resource override reads, built
            # from pieces so this file holds no copy of it.
            f.write('#include <stdlib.h>\nint main(void) { return getenv("PACKAGE_RESOURCE" "_BUNDLE_PATH") != 0; }\n')
        self.native = os.path.join(self.dir, "native")
        self.x86 = os.path.join(self.dir, "x86")
        self.debug = os.path.join(self.dir, "debug")
        for out, arch, source in ((self.native, None, src), (self.x86, "x86_64", src), (self.debug, None, debug_src)):
            cmd = ["cc", "-O0", "-o", out, source]
            if arch:
                cmd[1:1] = ["-arch", arch]
            p = run(cmd)
            if p.returncode != 0:
                raise RuntimeError("cc failed: %s" % p.stderr.decode())
        self.oracle = os.path.join(self.dir, "codesign_facts")
        p = run(["swiftc", "-O", "-o", self.oracle, os.path.join(HERE, "oracles", "codesign_facts.swift")])
        if p.returncode != 0:
            raise RuntimeError("swiftc failed: %s" % p.stderr.decode())
        self.count = 0

    def close(self):
        shutil.rmtree(self.dir)

    def entitlements(self, keys):
        self.count += 1
        path = os.path.join(self.dir, "e%d.entitlements" % self.count)
        with open(path, "wb") as f:
            plistlib.dump(dict(keys), f)
        return path

    def facts(self, paths):
        p = run([self.oracle] + list(paths))
        if p.returncode != 0:
            raise RuntimeError("oracle failed: %s" % p.stderr.decode())
        return json.loads(p.stdout)


WS = None


def write_plist(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        plistlib.dump(data, f)


class Bundle:
    """A bundle with the real layout, built from the compiled program."""

    def __init__(self, cli_arch="native", app_exe=APP_EXE, app_prog=None):
        WS.count += 1
        self.root = os.path.join(WS.dir, "b%d" % WS.count)
        self.app = os.path.join(self.root, "EnvCloak.app")
        for rel, prog in ((app_exe, app_prog or WS.native), (CLI_EXE, WS.x86 if cli_arch == "x86" else WS.native), (DAEMON_EXE, WS.native)):
            os.makedirs(os.path.dirname(self.path(rel)), exist_ok=True)
            shutil.copy(prog, self.path(rel))
            os.chmod(self.path(rel), 0o755)
        write_plist(
            self.path("Contents/Info.plist"),
            {
                "CFBundleIdentifier": "ai.envcloak.app",
                "CFBundleExecutable": os.path.basename(app_exe),
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": "0.0.0",
            },
        )
        write_plist(
            self.path(HELPER + "/Contents/Info.plist"),
            {
                "CFBundleIdentifier": "ai.envcloak.agent",
                "CFBundleExecutable": "envcloakd",
                "CFBundlePackageType": "APPL",
                "LSBackgroundOnly": True,
            },
        )
        os.makedirs(self.path("Contents/Library/LaunchAgents"))
        shutil.copy(LAUNCH_AGENT, self.path("Contents/Library/LaunchAgents/ai.envcloak.agent.plist"))
        os.makedirs(self.path("Contents/Resources"))
        with open(self.path("Contents/Resources/notes.txt"), "w") as f:
            f.write("a resource\n")

    def path(self, rel):
        return os.path.join(self.app, rel)

    def codesign(self, target, identifier=None, runtime=True, entitlements=None):
        cmd = ["codesign", "--force", "--sign", "-", "--timestamp=none"]
        if runtime:
            cmd += ["--options", "runtime"]
        if identifier:
            cmd += ["--identifier", identifier]
        if entitlements is not None:
            cmd += ["--entitlements", WS.entitlements(entitlements)]
        p = run(cmd + [target])
        if p.returncode != 0:
            raise RuntimeError("codesign failed: %s" % p.stderr.decode())

    def sign(self, helper=None, cli=None, app=None, skip=()):
        """Signs inside out; each of helper, cli and app is a dict of
        codesign options overriding the good defaults."""
        if "helper" not in skip:
            self.codesign(self.path(HELPER), **dict({"identifier": "ai.envcloak.agent", "entitlements": {}}, **(helper or {})))
        if "cli" not in skip:
            self.codesign(self.path(CLI_EXE), **dict({"identifier": "ai.envcloak.cli", "entitlements": {}}, **(cli or {})))
        if "app" not in skip:
            self.codesign(self.app, **dict({"identifier": "ai.envcloak.app", "entitlements": {}}, **(app or {})))
        return self

    def check(self, facts=False):
        args = [SIGN_CHECK] + (["--facts"] if facts else []) + [self.app]
        return run(args)

    def oracle(self, rel):
        target = self.app if rel == APP_EXE else (self.path(HELPER) if rel == DAEMON_EXE else self.path(rel))
        return WS.facts([target])[target]


class SignCheck(unittest.TestCase):
    def refused(self, bundle, needle):
        p = bundle.check()
        err = p.stderr.decode()
        self.assertEqual(p.returncode, 1, "sign-check passed a bundle it must refuse:\n" + err)
        self.assertIn(needle, err)
        return err

    def test_a_good_bundle_passes_and_both_readers_agree(self):
        b = Bundle().sign()
        p = b.check(facts=True)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        ours = json.loads(p.stdout)
        for rel in (APP_EXE, CLI_EXE, DAEMON_EXE):
            theirs = b.oracle(rel)
            self.assertTrue(theirs["valid"], theirs)
            self.assertTrue(theirs["runtime"])
            self.assertEqual(ours[rel]["identifier"], theirs["identifier"])
            self.assertEqual(ours[rel]["flags"], theirs["flags"])
            self.assertEqual(ours[rel]["runtime"], theirs["runtime"])
            self.assertEqual(ours[rel]["entitlements"], theirs["entitlements"])

    def test_the_cli_signed_without_the_runtime_is_refused(self):
        b = Bundle().sign(cli={"runtime": False})
        self.assertFalse(b.oracle(CLI_EXE)["runtime"])
        self.refused(b, "Contents/MacOS/envcloak: signed without the hardened runtime")

    def test_the_helper_and_the_app_without_the_runtime_are_refused(self):
        b = Bundle().sign(helper={"runtime": False})
        self.assertFalse(b.oracle(DAEMON_EXE)["runtime"])
        self.refused(b, DAEMON_EXE + ": signed without the hardened runtime")
        b = Bundle().sign(app={"runtime": False})
        self.assertFalse(b.oracle(APP_EXE)["runtime"])
        self.refused(b, APP_EXE + ": signed without the hardened runtime")

    def test_get_task_allow_on_the_app_is_refused(self):
        b = Bundle().sign(app={"entitlements": {"com.apple.security.get-task-allow": True}})
        self.assertIn("com.apple.security.get-task-allow", b.oracle(APP_EXE)["entitlements"])
        self.refused(b, APP_EXE + ": carries the entitlement com.apple.security.get-task-allow")

    def test_each_runtime_exception_on_each_executable_is_refused(self):
        for key in EXCEPTIONS:
            for part, rel in (("helper", DAEMON_EXE), ("cli", CLI_EXE), ("app", APP_EXE)):
                with self.subTest(key=key, part=part):
                    b = Bundle().sign(**{part: {"entitlements": {key: True}}})
                    self.assertIn(key, b.oracle(rel)["entitlements"])
                    self.refused(b, "%s: carries the entitlement %s" % (rel, key))

    def test_a_forbidden_key_set_to_false_is_still_refused(self):
        b = Bundle().sign(cli={"entitlements": {"com.apple.security.get-task-allow": False}})
        self.assertIn("com.apple.security.get-task-allow", b.oracle(CLI_EXE)["entitlements"])
        self.refused(b, CLI_EXE + ": carries the entitlement com.apple.security.get-task-allow")

    def test_a_temporary_exception_is_refused(self):
        key = "com.apple.security.temporary-exception.files.absolute-path.read-only"
        b = Bundle().sign(app={"entitlements": {key: ["/"]}})
        self.assertIn(key, b.oracle(APP_EXE)["entitlements"])
        self.refused(b, "carries the entitlement " + key)

    def test_an_unsigned_cli_is_refused(self):
        b = Bundle().sign(skip=("cli",))
        # cc's output carries only the linker's signature: no runtime bit.
        self.assertFalse(b.oracle(CLI_EXE)["runtime"])
        err = self.refused(b, CLI_EXE)
        self.assertTrue("not signed" in err or "without the hardened runtime" in err or "signed as" in err, err)

    def test_the_cli_with_another_identifier_is_refused(self):
        b = Bundle().sign(cli={"identifier": "envcloak"})
        self.assertEqual(b.oracle(CLI_EXE)["identifier"], "envcloak")
        self.refused(b, CLI_EXE + ": signed as 'envcloak', not ai.envcloak.cli")

    def test_an_extra_executable_is_refused_whatever_its_name(self):
        b = Bundle()
        shutil.copy(WS.native, b.path("Contents/Resources/notes.png"))
        b.sign()
        self.refused(b, "Contents/Resources/notes.png: an executable the bundle must not hold")

    def test_an_executable_script_is_refused(self):
        b = Bundle()
        path = b.path("Contents/Resources/run.sh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o755)
        b.sign()
        self.refused(b, "Contents/Resources/run.sh: an executable the bundle must not hold")

    def test_a_missing_cli_is_refused(self):
        b = Bundle()
        os.remove(b.path(CLI_EXE))
        b.sign(skip=("cli",))
        self.refused(b, CLI_EXE + ": missing")

    def test_a_symbolic_link_is_refused(self):
        b = Bundle()
        os.symlink("/bin/sh", b.path("Contents/Resources/shell"))
        b.sign()
        self.refused(b, "Contents/Resources/shell: a symbolic link in the bundle")

    def test_an_inner_change_after_the_outer_signature_is_refused(self):
        # The app signed before its CLI, the order SPEC §12 forbids: the
        # app's seal holds the CLI as it was (the linker's signature), and
        # signing the CLI afterwards changes it.
        b = Bundle().sign(skip=("cli",))
        b.codesign(b.path(CLI_EXE), identifier="ai.envcloak.cli", entitlements={})
        self.assertTrue(b.oracle(CLI_EXE)["runtime"])
        self.assertFalse(WS.facts([b.app])[b.app]["valid"])
        self.refused(b, "the bundle does not verify")

    def test_a_side_door_in_an_info_plist_is_refused(self):
        for rel in ("Contents/Info.plist", HELPER + "/Contents/Info.plist"):
            with self.subTest(plist=rel):
                b = Bundle()
                with open(b.path(rel), "rb") as f:
                    info = plistlib.load(f)
                info["CFBundleURLTypes"] = [{"CFBundleURLSchemes": ["envcloak"]}]
                write_plist(b.path(rel), info)
                b.sign()
                self.refused(b, rel + ": holds CFBundleURLTypes")

    def test_a_helper_that_is_not_background_only_is_refused(self):
        b = Bundle()
        rel = HELPER + "/Contents/Info.plist"
        with open(b.path(rel), "rb") as f:
            info = plistlib.load(f)
        del info["LSBackgroundOnly"]
        write_plist(b.path(rel), info)
        b.sign()
        self.refused(b, "the helper is not background-only")

    def test_a_launch_agent_that_starts_something_else_is_refused(self):
        b = Bundle()
        rel = "Contents/Library/LaunchAgents/ai.envcloak.agent.plist"
        with open(b.path(rel), "rb") as f:
            agent = plistlib.load(f)
        agent["BundleProgram"] = "Contents/MacOS/envcloak"
        write_plist(b.path(rel), agent)
        b.sign()
        self.refused(b, "BundleProgram is not the helper's envcloakd")

    def test_an_app_executable_named_like_the_cli_is_refused(self):
        # `EnvCloak` and `envcloak` are one file on a case-insensitive
        # volume: the CLI copied in last replaces the app.
        b = Bundle(app_exe="Contents/MacOS/EnvCloak").sign()
        names = os.listdir(b.path("Contents/MacOS"))
        self.assertEqual(len(names), 1 if os.path.exists(b.path("Contents/MacOS/ENVCLOAK")) else 2, names)
        self.refused(b, "Contents/Info.plist: not ai.envcloak.app with the executable EnvCloakApp")

    def test_a_debug_resource_override_in_the_app_is_refused(self):
        b = Bundle(app_prog=WS.debug).sign()
        self.refused(b, APP_EXE + ": holds PACKAGE_RESOURCE_BUNDLE_PATH")

    def test_mixed_architectures_are_refused(self):
        b = Bundle(cli_arch="x86").sign()
        self.refused(b, "the executables are built for different architectures")


class CaseClashes(unittest.TestCase):
    """Names that differ only in case cannot both exist on this Mac's
    case-insensitive volume, so the rule is checked on names directly: a
    bundle built on a case-sensitive volume could hold both."""

    def test_names_that_differ_only_in_case_clash(self):
        sys.path.insert(0, SCRIPTS)
        try:
            import sign_check
        finally:
            sys.path.pop(0)
        self.assertEqual(sign_check.case_clashes(["EnvCloak", "envcloak", "envcloakd"]), [["EnvCloak", "envcloak"]])
        self.assertEqual(sign_check.case_clashes(["EnvCloakApp", "envcloak"]), [])
        self.assertEqual(sign_check.case_clashes(["Info.plist", "info.PLIST", "PkgInfo"]), [["Info.plist", "info.PLIST"]])


class BuiltApp(unittest.TestCase):
    """The app scripts/macos/build-app.sh built, given with --app; without
    it these are reported as skipped, never as passed."""

    def setUp(self):
        if not os.environ.get("ENVCLOAK_TEST_BUILT_APP"):
            self.skipTest("no built app given (--app)")

    def test_the_built_app_passes_and_both_readers_agree(self):
        app = os.environ["ENVCLOAK_TEST_BUILT_APP"]
        p = run([SIGN_CHECK, "--facts", app])
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        ours = json.loads(p.stdout)
        self.assertEqual(sorted(ours), sorted([APP_EXE, CLI_EXE, DAEMON_EXE]))
        targets = {APP_EXE: app, CLI_EXE: os.path.join(app, CLI_EXE), DAEMON_EXE: os.path.join(app, HELPER)}
        theirs = WS.facts(targets.values())
        for rel, target in targets.items():
            with self.subTest(executable=rel):
                self.assertTrue(theirs[target]["valid"], theirs[target])
                self.assertTrue(theirs[target]["runtime"])
                for field in ("identifier", "flags", "runtime", "entitlements"):
                    self.assertEqual(ours[rel][field], theirs[target][field], field)

    def test_the_kernel_runs_the_bundled_cli_hardened(self):
        # A third reader: the CLI's own report of the kernel's code-signing
        # flags for its running process (csops, envcloak-sys).
        app = os.environ["ENVCLOAK_TEST_BUILT_APP"]
        p = run([os.path.join(app, CLI_EXE), "internal", "hardening"], env={"PATH": "/usr/bin:/bin", "HOME": WS.dir})
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn("hardened_runtime=true", p.stdout.decode().splitlines())


def main():
    global WS
    args = sys.argv[1:]
    if args[:1] == ["--app"] and len(args) >= 2:
        os.environ["ENVCLOAK_TEST_BUILT_APP"] = os.path.abspath(args[1])
        args = args[2:]
    WS = Workspace()
    try:
        prog = unittest.main(argv=[sys.argv[0]] + args, exit=False, verbosity=2)
    finally:
        WS.close()
    result = prog.result
    if os.environ.get("ENVCLOAK_TEST_BUILT_APP") and result.skipped:
        print("test_sign_check: a built app was given but %d test(s) were skipped" % len(result.skipped), file=sys.stderr)
        sys.exit(1)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
