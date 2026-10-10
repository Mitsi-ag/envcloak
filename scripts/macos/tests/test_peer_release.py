#!/usr/bin/env python3
"""Release-check control flow with modeled Cargo outcomes and stock utilities."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
GUARD = "EnvCloak testing features must not be compiled into release artifacts"


class PeerRelease(unittest.TestCase):
    def check_release(self, mode):
        # Only these system utilities are on PATH. Homebrew and runner extras
        # cannot accidentally satisfy a non-stock dependency such as ripgrep.
        with tempfile.TemporaryDirectory(prefix="ecr", dir="/tmp") as directory:
            home = Path(directory)
            bins = home / "bin"
            bins.mkdir()
            for name in ["dirname", "mktemp", "grep", "mkdir", "python3"]:
                (bins / name).symlink_to(Path("/bin" if name == "mkdir" else "/usr/bin") / name)
            cargo = bins / "cargo"
            cargo.write_text('''#!/bin/bash
printf '%s\\n' "$*" >> "$HOME/calls"
if [[ "$1" == metadata ]]; then
  printf '{"target_directory":"%s"}\\n' "$HOME/configured-target"
  exit 0
fi
if [[ "$*" != *'--features testing'* ]]; then
  if [[ "$CASE" == normal-error ]]; then exit 17; fi
  exit 0
fi
case "$CASE" in
  guard|override) if [[ "$CASE" == override && "$CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS" == true ]]; then exit 0; fi; echo 'error: ''' + GUARD + '''' >&2; exit 101 ;;
  removed) exit 0 ;;
  unrelated) echo 'error: unrelated compiler failure' >&2; exit 101 ;;
esac
exit 99
''')
            cargo.chmod(0o700)
            env = {"PATH": str(bins), "HOME": str(home), "TMPDIR": str(home),
                   "XDG_CONFIG_HOME": str(home / "config"), "XDG_DATA_HOME": str(home / "data"),
                   "XDG_STATE_HOME": str(home / "state"), "CARGO_TARGET_DIR": str(home), "CASE": mode}
            result = subprocess.run(["/bin/bash", str(ROOT / "scripts/macos/check-peer-release.sh")],
                                    env=env, capture_output=True, text=True, timeout=30)
            calls = (home / "calls").read_text().splitlines()
        self.assertNotIn("command not found", result.stderr)
        self.assertEqual(calls.pop(0), "metadata --locked --format-version 1 --no-deps")
        self.assertEqual(calls[0], "check --locked --release -p envcloak-sys")
        if mode != "normal-error":
            count = 2 if mode in ("guard", "override") else 1
            self.assertEqual(calls, [calls[0]] + [calls[0] + " --features testing"] * count)
        return result, calls

    def test_guard_failure_passes_without_runner_extras(self):
        result, _ = self.check_release("guard")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("testing feature refused; normal release passed", result.stdout)

    def test_debug_assertions_override_is_a_failure(self):
        result, _ = self.check_release("override")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED (testing feature compiled in release)", result.stderr)

    def test_removed_guard_is_a_failure(self):
        result, _ = self.check_release("removed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED (testing feature compiled in release)", result.stderr)
        self.assertNotIn("passed", result.stdout)

    def test_unrelated_compiler_error_is_a_failure(self):
        result, _ = self.check_release("unrelated")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED (unrelated compiler error)", result.stderr)
        self.assertNotIn("passed", result.stdout)

    def test_normal_release_failure_stops_the_check(self):
        result, calls = self.check_release("normal-error")
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
