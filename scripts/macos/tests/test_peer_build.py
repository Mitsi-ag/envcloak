#!/usr/bin/env python3
"""Build-time test configuration is bounded, fresh and never a source edit."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TargetDirectory(unittest.TestCase):
    @unittest.skipUnless(os.uname().sysname == "Darwin", "packaging is macOS only")
    def test_signed_packaging_requires_compiled_production_pin(self):
        with tempfile.TemporaryDirectory(prefix="ecq", dir="/tmp") as directory:
            home = Path(directory)
            cargo = home / "cargo"
            cargo.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$HOME/calls"\nexit 1\n')
            cargo.chmod(0o700)
            for tier in ["development", "ci"]:
                result = subprocess.run(["/bin/bash", str(ROOT / "scripts/macos/build-app.sh"),
                                         "--sign", tier, "--out", str(home / "out")],
                                        env={"PATH": "/usr/bin:/bin", "HOME": str(home), "CARGO": str(cargo)},
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("signed packaging blocked", result.stderr)
                self.assertIn("Q3-01", result.stderr)
                self.assertFalse((home / "out").exists())
            self.assertEqual((home / "calls").read_text().splitlines(),
                             ["run --release --locked --quiet -p envcloak-sys --bin production_pin"] * 2)

    def harness(self, missing=None):
        with tempfile.TemporaryDirectory(prefix="ect", dir="/tmp") as directory:
            root = Path(directory)
            scripts = root / "scripts/macos"
            (scripts / "tests").mkdir(parents=True)
            for name in ["check-peer-code.sh", "cargo-target.sh", "tests/run_peer_gates.sh", "tests/with_peer_pin.py"]:
                shutil.copyfile(ROOT / "scripts/macos" / name, scripts / name)
            bins = root / "bin"
            bins.mkdir()
            target = root / "configured target"
            # Stand-ins model Cargo's config-derived metadata and successful build.
            cargo = bins / "cargo"
            cargo.write_text('#!/usr/bin/python3\nimport json, pathlib, sys\n'
                             f'target = pathlib.Path({str(target)!r})\n'
                             'if sys.argv[1] == "metadata":\n'
                             ' print(json.dumps({"target_directory": str(target)}))\n'
                             'elif sys.argv[1] == "build":\n'
                             f' for name in {list(n for n in ["envcloak", "examples/identity_probe"] if n != missing)!r}:\n'
                             '  path = target / "debug" / name\n'
                             '  path.parent.mkdir(parents=True, exist_ok=True)\n'
                             '  path.write_text("fixture")\n'
                             '  path.chmod(0o700)\n')
            cargo.chmod(0o700)
            identity = scripts / "ci-identity.sh"
            identity.write_text('#!/usr/bin/python3\nimport json, pathlib, sys\n'
                                '(pathlib.Path(sys.argv[1]) / "identities.json").write_text('
                                'json.dumps([{"sha1": bytes(range(20)).hex()}]))\n')
            identity.chmod(0o700)
            release = scripts / "check-peer-release.sh"
            release.write_text("#!/bin/bash\nexit 0\n")
            release.chmod(0o700)
            result = subprocess.run(["/bin/bash", str(scripts / "check-peer-code.sh")],
                                    env={"PATH": f"{bins}:/usr/bin:/bin", "HOME": str(root)},
                                    capture_output=True, text=True, timeout=30)
            self.assertTrue(list(target.glob("peer-signing.*")), result.stderr)
            return result

    @unittest.skipUnless(os.uname().sysname == "Darwin", "native harness is macOS only")
    def test_configured_target_and_both_missing_probes(self):
        self.assertEqual(self.harness().returncode, 0)
        for name in ["envcloak", "examples/identity_probe"]:
            with self.subTest(probe=name):
                result = self.harness(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("probe binary missing after Cargo build:", result.stderr)
                self.assertIn(name, result.stderr)


class BuildConfiguration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="ecb", dir="/tmp")
        cls.home = Path(cls.scratch.name)
        cls.binary = cls.home / "build-config"
        subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(ROOT / "crates/envcloak-sys/build.rs"),
                        "-o", str(cls.binary)], check=True, timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def build(self, profile="debug", testing=True, pin=None, debug="true"):
        env = {"HOME": str(self.home), "PROFILE": profile, "DEBUG": debug}
        if testing:
            env["CARGO_FEATURE_TESTING"] = "1"
        if pin is not None:
            env["ENVCLOAK_TEST_CERT_SHA1"] = pin
        return subprocess.run([str(self.binary)], env=env, capture_output=True, text=True, timeout=10)

    def test_release_refuses_testing_even_with_debug_assertions(self):
        for debug in ("false", "true"):
            result = self.build(profile="release", debug=debug)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("testing features must not be compiled into release artifacts", result.stderr)
        self.assertEqual(self.build(profile="release", testing=False).returncode, 0)

    def test_pin_requires_testing_and_never_reaches_release(self):
        pin = bytes(range(20)).hex()
        for profile, testing in [("debug", False), ("release", False), ("release", True)]:
            self.assertNotEqual(self.build(profile, testing, pin).returncode, 0)
        result = self.build(pin=pin)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cargo:rustc-env=ENVCLOAK_COMPILED_TEST_CERT=" + pin, result.stdout)
        self.assertIn("cargo:rerun-if-env-changed=ENVCLOAK_TEST_CERT_SHA1", result.stdout)
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cargo:rustc-env=ENVCLOAK_COMPILED_TEST_CERT=\n", result.stdout)

    def test_hostile_pins_fail_without_echo(self):
        for pin in ("", "x" * 40, "é" * 20, "0" * 39, "0" * 41, "0" * 4096, b"\xff", "0" * 40 + "\ncargo:rustc-cfg=bad"):
            result = self.build(pin=pin)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("cargo:rustc-env=ENVCLOAK_COMPILED_TEST_CERT=", result.stdout)
            self.assertIn("invalid test certificate fingerprint", result.stderr)

    def test_runner_does_not_edit_tracked_pins(self):
        pins = ROOT / "crates/envcloak-sys/src/peer_code/pins.rs"
        original = pins.read_bytes()
        fixtures = self.home / "fixtures"
        fixtures.mkdir(exist_ok=True)
        pin = bytes(range(20)).hex()
        (fixtures / "identities.json").write_text(json.dumps([{"sha1": pin}]))
        script = self.home / "observe.py"
        script.write_text("import os, pathlib, sys\n"
                          "assert pathlib.Path(sys.argv[1]).read_bytes() == bytes.fromhex(sys.argv[2])\n"
                          "assert os.environ['ENVCLOAK_TEST_CERT_SHA1'] == sys.argv[3]\n")
        result = subprocess.run(["/usr/bin/python3", str(ROOT / "scripts/macos/tests/with_peer_pin.py"),
                                 str(fixtures), "/usr/bin/python3", str(script), str(pins), original.hex(), pin],
                                env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(pins.read_bytes(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
