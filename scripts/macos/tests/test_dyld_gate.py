#!/usr/bin/env python3
"""Modeled receipts exercise qualification failures, not native host coverage."""
import copy
import io
import json
import sys
import unittest
from contextlib import redirect_stderr

sys.dont_write_bytecode = True
from dyld_gate import qualify, finish


def receipt(allowed=False):
    def facts(identifier, runtime):
        return {"identifier": identifier, "valid": True, "runtime": runtime,
                "flags": 65538 if runtime else 2, "entitlements": [],
                "slices": {"arm64": {"flags": 65538 if runtime else 2, "runtime": runtime}}}
    def policy(runtime):
        return {"amfi": 483 if allowed and runtime else (481 if runtime else 479),
                "cs": 65539 if runtime else 3, "csr": 0 if not allowed else 239}
    before = {"hardened": policy(True), "plain": policy(False)}
    return {"artifacts": {"genuine": facts("ai.envcloak.app", True),
                          "no-runtime": facts("ai.envcloak.app", False),
                          "hardened": facts("ai.envcloak.dyld-oracle", True),
                          "plain": facts("ai.envcloak.dyld-oracle", False),
                          "library": facts("ai.envcloak.constructor", False)},
            "before": before, "after": copy.deepcopy(before),
            "loaded": {"genuine": allowed, "no-runtime": True,
                       "hardened": allowed, "plain": True}}


class Qualification(unittest.TestCase):
    def test_enforcing_host_keeps_the_negative_gate(self):
        self.assertEqual(qualify(receipt()), "passed")
        for name in ["genuine", "hardened"]:
            bad = receipt()
            bad["loaded"][name] = True
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "constructor"):
                qualify(bad)

    def test_relaxed_host_requires_independent_policy_and_observation(self):
        self.assertEqual(qualify(receipt(True)), "unsupported_host")
        for name in ["genuine", "hardened", "plain", "no-runtime"]:
            bad = receipt(True)
            bad["loaded"][name] = False
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "constructor"):
                qualify(bad)
        bad = receipt(True)
        for when in ["before", "after"]:
            bad[when]["hardened"]["amfi"] = 481
        with self.assertRaisesRegex(AssertionError, "constructor"):
            qualify(bad)

    def test_artifact_defects_never_become_host_skips(self):
        for allowed in [False, True]:
            for name in receipt()["artifacts"]:
                for field, value in [("valid", False), ("runtime", None), ("flags", 2 if name in ["genuine", "hardened"] else 65538),
                                     ("identifier", "wrong"), ("entitlements", None),
                                     ("entitlements", ["com.apple.security.cs.allow-dyld-environment-variables"]),
                                     ("slices", {}),
                                     ("slices", {"arm64": {"runtime": None, "flags": 0}})]:
                    bad = receipt(allowed)
                    bad["artifacts"][name][field] = value
                    with self.subTest(allowed=allowed, name=name, field=field), self.assertRaises(AssertionError):
                        qualify(bad)

    def test_missing_malformed_or_drifting_measurements_fail(self):
        for when in ["before", "after"]:
            for name in ["hardened", "plain"]:
                for field in ["amfi", "cs", "csr"]:
                    for value in [None, True, "0", -1, 1 << 65]:
                        bad = receipt(True)
                        bad[when][name][field] = value
                        with self.subTest(when=when, name=name, field=field, value=value), self.assertRaises(AssertionError):
                            qualify(bad)
        for name, field, value in [("hardened", "amfi", 481), ("plain", "csr", 0),
                                   ("hardened", "cs", 3), ("hardened", "cs", 65538), ("plain", "cs", 65539)]:
            bad = receipt(True)
            bad["after"][name][field] = value
            with self.subTest(name=name, field=field), self.assertRaises(AssertionError):
                qualify(bad)
        for bad in [{}, {"artifacts": {}}, receipt(True) | {"loaded": {}},
                    receipt(True) | {"before": {}}]:
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                qualify(bad)

    def test_unsupported_is_explicitly_skipped_and_reported(self):
        report = receipt(True)
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaisesRegex(unittest.SkipTest, "UNQUALIFIED.*AMFI"):
            finish(report)
        self.assertEqual(report["status"], "unsupported_host")
        self.assertIn("::warning::", output.getvalue())
        self.assertIn('"status": "unsupported_host"', output.getvalue())
        json.loads(output.getvalue().splitlines()[0].removeprefix("Gate 19 DYLD receipt: "))

    def test_failure_is_reported_as_failure(self):
        report = receipt()
        report["loaded"]["genuine"] = True
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(AssertionError):
            finish(report)
        self.assertEqual(report["status"], "failed")
        self.assertIn('"status": "failed"', output.getvalue())
        self.assertNotIn("::warning::", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
