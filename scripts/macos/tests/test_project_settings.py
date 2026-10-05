#!/usr/bin/env python3
"""The Xcode project's settings, as xcodebuild resolves them for each
target and configuration (docs/APP.md "Toolchain and floor"; M3 plan
D3-04, D3-05): Swift 6 with complete strict concurrency and warnings as
errors, macOS 26, the hardened runtime on what ships, no base entitlements
in Release, and the bundle identifiers and executable names the layout
names.

Usage: python3 scripts/macos/tests/test_project_settings.py
"""

import json
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PROJECT = os.path.join(ROOT, "apps", "macos", "EnvCloak.xcodeproj")
SHIPPED = {"EnvCloak", "EnvCloakAgent"}
TESTS = {"EnvCloakTests", "EnvCloakUITests", "EnvCloakHardwareTests"}


def settings(configuration):
    out = subprocess.run(
        ["xcodebuild", "-project", PROJECT, "-alltargets", "-configuration", configuration, "-showBuildSettings", "-json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout
    return {entry["target"]: entry["buildSettings"] for entry in json.loads(out)}


class ProjectSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = settings("Release")
        cls.debug = settings("Debug")

    def test_every_target_is_there(self):
        self.assertEqual(set(self.release), SHIPPED | TESTS)

    def test_swift_6_strict_and_warnings_as_errors_on_macos_26_everywhere(self):
        for config, targets in (("Release", self.release), ("Debug", self.debug)):
            for target, s in targets.items():
                with self.subTest(config=config, target=target):
                    self.assertEqual(s["MACOSX_DEPLOYMENT_TARGET"], "26.0")
                    self.assertEqual(s["SWIFT_VERSION"], "6.0")
                    self.assertEqual(s["SWIFT_STRICT_CONCURRENCY"], "complete")
                    self.assertEqual(s["SWIFT_TREAT_WARNINGS_AS_ERRORS"], "YES")
                    self.assertEqual(s["GCC_TREAT_WARNINGS_AS_ERRORS"], "YES")

    def test_what_ships_has_the_runtime_and_no_base_entitlements_in_release(self):
        for target in SHIPPED:
            with self.subTest(target=target):
                self.assertEqual(self.release[target]["ENABLE_HARDENED_RUNTIME"], "YES")
                self.assertEqual(self.release[target]["CODE_SIGN_INJECT_BASE_ENTITLEMENTS"], "NO")
                self.assertEqual(self.release[target].get("ENABLE_APP_SANDBOX", "NO"), "NO")

    def test_ad_hoc_signing_is_the_default(self):
        for target in SHIPPED:
            with self.subTest(target=target):
                self.assertEqual(self.release[target]["CODE_SIGN_IDENTITY"], "-")
                self.assertEqual(self.release[target].get("DEVELOPMENT_TEAM", ""), "")

    def test_identifiers_and_executables_are_the_layouts(self):
        app, agent = self.release["EnvCloak"], self.release["EnvCloakAgent"]
        self.assertEqual(app["PRODUCT_BUNDLE_IDENTIFIER"], "ai.envcloak.app")
        self.assertEqual(app["WRAPPER_NAME"], "EnvCloak.app")
        # Not "EnvCloak": on a case-insensitive volume that is the CLI's
        # Contents/MacOS/envcloak.
        self.assertEqual(app["EXECUTABLE_NAME"], "EnvCloakApp")
        self.assertEqual(agent["PRODUCT_BUNDLE_IDENTIFIER"], "ai.envcloak.agent")
        self.assertEqual(agent["WRAPPER_NAME"], "EnvCloakAgent.app")
        self.assertEqual(agent["CODE_SIGNING_ALLOWED"], "NO")

    def test_no_asset_symbols_name_colours_outside_the_tokens(self):
        for target in SHIPPED:
            with self.subTest(target=target):
                self.assertEqual(self.release[target]["ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS"], "NO")


if __name__ == "__main__":
    unittest.main(verbosity=2)
