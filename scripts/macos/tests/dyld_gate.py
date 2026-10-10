"""Qualify this run's bounded DYLD observation separately from artifact signing."""
import json
import sys
import unittest

RUNTIME = 0x10000
ALLOW_PATH_VARS = 1 << 1


def number(value, bits):
    assert type(value) is int and 0 <= value < 1 << bits, "invalid native policy field"
    return value


def artifact(facts, identifier, runtime):
    assert facts["valid"] is True, "invalid artifact signature"
    assert facts["identifier"] == identifier, "incorrect artifact identifier"
    assert facts["entitlements"] == [], "unexpected or unreadable artifact entitlements"
    assert facts["runtime"] is runtime, "incorrect artifact runtime flag"
    assert bool(number(facts["flags"], 32) & RUNTIME) is runtime, "incorrect artifact flags"
    assert facts["slices"], "missing artifact architecture facts"
    for slice_facts in facts["slices"].values():
        assert slice_facts["runtime"] is runtime, "incorrect slice runtime flag"
        assert bool(number(slice_facts["flags"], 32) & RUNTIME) is runtime, "incorrect slice flags"


def qualify(report):
    try:
        for name, identifier, runtime in [
            ("genuine", "ai.envcloak.app", True), ("no-runtime", "ai.envcloak.app", False),
            ("hardened", "ai.envcloak.dyld-oracle", True), ("plain", "ai.envcloak.dyld-oracle", False),
            ("library", "ai.envcloak.constructor", False),
        ]:
            artifact(report["artifacts"][name], identifier, runtime)
        csr = report["before"]["hardened"]["csr"]
        for when in ["before", "after"]:
            for name, runtime in [("hardened", True), ("plain", False)]:
                policy = report[when][name]
                number(policy["amfi"], 64)
                assert number(policy["csr"], 32) == csr, "host SIP configuration changed"
                flags = number(policy["cs"], 32)
                assert flags & 1, "kernel did not validate oracle signature"
                assert bool(flags & RUNTIME) is runtime, "incorrect oracle dynamic runtime flag"
                assert policy["amfi"] == report["before"][name]["amfi"], "AMFI policy changed"
        assert report["before"]["plain"]["amfi"] & ALLOW_PATH_VARS, "AMFI refused positive control"
        loaded = report["loaded"]
        assert loaded["plain"] is True and loaded["no-runtime"] is True, "positive constructor control failed"
        allowed = bool(report["before"]["hardened"]["amfi"] & ALLOW_PATH_VARS)
        assert loaded["hardened"] is allowed, "oracle constructor disagrees with AMFI policy"
        assert loaded["genuine"] is allowed, "genuine constructor disagrees with independent oracle"
        return "unsupported_host" if allowed else "passed"
    except (KeyError, TypeError, AttributeError) as error:
        raise AssertionError("missing or malformed DYLD evidence") from error


def emit(report):
    print("Gate 19 DYLD receipt: " + json.dumps(report, sort_keys=True), file=sys.stderr, flush=True)


def finish(report):
    report["status"] = "failed"
    try:
        report["status"] = qualify(report)
    finally:
        emit(report)
    if report["status"] == "unsupported_host":
        reason = ("Gate 19 DYLD runtime protection UNQUALIFIED: AMFI permits DYLD path variables "
                  "in the independently signed hardened oracle, and both hardened constructors ran. "
                  "Artifact checks passed; this host cannot qualify the negative loader gate.")
        print("::warning::" + reason, file=sys.stderr, flush=True)
        raise unittest.SkipTest(reason)
