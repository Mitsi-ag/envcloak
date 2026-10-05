#!/usr/bin/env python3
"""sign_check.py's decisions on modeled platform answers (gate 19's policy,
an independent check beside test_sign_check.py's native one).

Each case runs the real checker's main() on a small bundle made here: the
three executables (a Mach-O header and nothing else), the app's and the
helper's Info.plist, and the LaunchAgent from apps/macos/Support/. The
checker's `run`, the only way it starts codesign or lipo, is replaced by
answers modeled on what `codesign --display --verbose=4`, `codesign
--display --entitlements - --xml`, `lipo -archs` and `codesign --verify`
print, and starting any program fails the case. Each case loads a fresh
copy of the module, so no problem carries over from the one before.

Positive controls (arm64, x86_64, a build key Xcode adds) must pass. Each
refusal changes one answer or one file and must fail with its own message:
for each of the three executables, no hardened runtime flag, two
architectures, a forbidden entitlement present with the value false, and an
entitlement no tier signs; then one executable built for another
architecture, a code directory with no flags, entitlements that are not a
property list, and a boolean in the LaunchAgent or the helper's Info.plist
written as an integer. Every case also checks that the checker asked
exactly its ten questions: one signature display, one entitlement read and
one architecture read per executable, and one verification of the bundle.

Usage: python3 scripts/macos/tests/test_sign_check_policy.py
"""

import contextlib
import importlib.util
import io
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CHECKER = os.path.join(ROOT, "scripts", "macos", "sign_check.py")
AGENT_SOURCE = os.path.join(ROOT, "apps", "macos", "Support", "LaunchAgents", "ai.envcloak.agent.plist")

RELS = [
    "Contents/MacOS/EnvCloakApp",
    "Contents/MacOS/envcloak",
    "Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd",
]
IDENTIFIERS = ["ai.envcloak.app", "ai.envcloak.cli", "ai.envcloak.agent"]
ROLE_MUTATIONS = {
    "no-runtime": "without the hardened runtime",
    "two-architectures": "one architecture until M7",
    "forbidden-false": "carries the entitlement com.apple.security.get-task-allow",
    "unknown-entitlement": "which no tier signs yet",
}
OTHER_MUTATIONS = {
    "mixed-architectures": (1, "different architectures"),
    "no-flags": (2, "no code directory flags"),
    "entitlements-not-a-plist": (0, "entitlements are not a property list"),
    "agent-boolean-as-integer": (None, "KeepAlive is not what the agent's plist sets"),
    "helper-boolean-as-integer": (None, "the helper is not background-only"),
}


def load_checker(n):
    spec = importlib.util.spec_from_file_location("sign_check_case_%d" % n, CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Policy(unittest.TestCase):
    count = 0

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="ecsp", dir="/tmp")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def bundle(self, mutation):
        app = os.path.join(tempfile.mkdtemp(dir=self.base), "Model.app")
        for rel in RELS:
            path = os.path.join(app, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(bytes.fromhex("cffaedfe") + bytes(28))
            os.chmod(path, 0o600)
        info = {"CFBundleIdentifier": IDENTIFIERS[0], "CFBundleExecutable": "EnvCloakApp"}
        helper = {"CFBundleIdentifier": IDENTIFIERS[2], "CFBundleExecutable": "envcloakd", "LSBackgroundOnly": True}
        with open(AGENT_SOURCE, "rb") as f:
            agent = plistlib.load(f)
        if mutation == "agent-boolean-as-integer":
            agent["KeepAlive"]["SuccessfulExit"] = 0
        if mutation == "helper-boolean-as-integer":
            helper["LSBackgroundOnly"] = 1
        if mutation == "build-key":
            info["DTSDKName"] = "macosx26.0"
        for rel, body in (
            ("Contents/Info.plist", info),
            ("Contents/Helpers/EnvCloakAgent.app/Contents/Info.plist", helper),
            ("Contents/Library/LaunchAgents/ai.envcloak.agent.plist", agent),
        ):
            path = os.path.join(app, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                plistlib.dump(body, f)
        return app

    def run_case(self, mutation=None, role=None, arch="arm64"):
        """Returns (exit, standard error, the questions asked)."""
        Policy.count += 1
        checker = load_checker(Policy.count)
        self.assertEqual(dict(zip(RELS, IDENTIFIERS)), checker.EXECUTABLES)
        app = self.bundle(mutation)
        asked = []

        def answer(args):
            target = args[-1]
            if args[:5] == ["codesign", "--verify", "--strict", "--deep", "--verbose=2"]:
                self.assertEqual(target, app)
                asked.append(("verify", None))
                return 0, b"", b""
            index = RELS.index(os.path.relpath(target, app))
            if args[:3] == ["codesign", "--display", "--verbose=4"]:
                asked.append(("display", index))
                lines = ["Identifier=" + IDENTIFIERS[index]]
                if not (mutation == "no-flags" and index == role):
                    flags = "0x0" if mutation == "no-runtime" and index == role else "0x10000"
                    lines.append("CodeDirectory v=20500 size=1 flags=%s(runtime) hashes=1+0 location=embedded" % flags)
                return 0, b"", ("\n".join(lines) + "\n").encode()
            if args[:5] == ["codesign", "--display", "--entitlements", "-", "--xml"]:
                asked.append(("entitlements", index))
                if index == role and mutation == "entitlements-not-a-plist":
                    return 0, b"\0", b""
                body = {}
                if index == role and mutation == "forbidden-false":
                    body = {"com.apple.security.get-task-allow": False}
                if index == role and mutation == "unknown-entitlement":
                    body = {"com.apple.security.app-sandbox": True}
                return 0, plistlib.dumps(body), b""
            if args[:2] == ["lipo", "-archs"]:
                asked.append(("archs", index))
                archs = arch
                if index == role and mutation == "two-architectures":
                    archs = "arm64 x86_64"
                if index == role and mutation == "mixed-architectures":
                    archs = "x86_64" if arch == "arm64" else "arm64"
                return 0, archs.encode(), b""
            raise AssertionError("a question the model has no answer for: %r" % (args,))

        def no_program(*args, **kwargs):
            raise AssertionError("a program was started: %r" % (args,))

        checker.run = answer
        out, err = io.StringIO(), io.StringIO()
        saved = subprocess.Popen
        subprocess.Popen = no_program
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = checker.main(["sign-check", app])
        finally:
            subprocess.Popen = saved
        self.assertEqual(sum(1 for q in asked if q[0] == "verify"), 1, asked)
        for index in range(3):
            self.assertEqual(sorted(q[0] for q in asked if q[1] == index), ["archs", "display", "entitlements"], asked)
        self.assertEqual(len(asked), 10, asked)
        return code, err.getvalue()

    def test_positive_controls_pass(self):
        for mutation, arch in ((None, "arm64"), (None, "x86_64"), ("build-key", "arm64")):
            with self.subTest(mutation=mutation, arch=arch):
                code, err = self.run_case(mutation, arch=arch)
                self.assertEqual(code, 0, err)
                self.assertIn("sign-check: ok", err)

    def test_each_executable_is_judged_on_its_own(self):
        for mutation, message in sorted(ROLE_MUTATIONS.items()):
            for role in range(3):
                with self.subTest(mutation=mutation, executable=RELS[role]):
                    code, err = self.run_case(mutation, role)
                    self.assertEqual(code, 1, err)
                    self.assertIn(RELS[role] + ": ", err)
                    self.assertIn(message, err)

    def test_bundle_wide_refusals(self):
        for mutation, (role, message) in sorted(OTHER_MUTATIONS.items()):
            with self.subTest(mutation=mutation):
                code, err = self.run_case(mutation, role)
                self.assertEqual(code, 1, err)
                self.assertIn(message, err)

    def test_the_passing_bundle_still_passes_after_the_refusals(self):
        # Fresh module state: nothing a refused case recorded carries over.
        self.run_case("no-runtime", 0)
        code, err = self.run_case()
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
