#!/usr/bin/env python3
"""Checks a built EnvCloak.app before anything ships or installs it (SPEC
§12 "Signing and release", M3 plan D3-05, D3-06; gate 19 for the bundle),
run as scripts/macos/sign-check.sh.

Each executable is judged from its own signature, never from the outer
app's: a helper or CLI that was not inspected inherits nothing.

1. Inventory. The bundle holds exactly three executables, found by content
   (a Mach-O or fat header) or by an execute bit, whatever their names:
   Contents/MacOS/EnvCloakApp, Contents/MacOS/envcloak and
   Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd. Any other
   executable file, any symbolic link, and any two names in one directory
   that differ only in case fail. (The app's executable is not called
   `EnvCloak`: on the default, case-insensitive APFS volume that is the
   same file as the CLI's `envcloak`, and copying the CLI in would replace
   the app.)
2. Signatures. Each of the three is signed (`codesign --display`), with its
   own identifier (ai.envcloak.app, ai.envcloak.cli, ai.envcloak.agent),
   and its code directory's flags, read as a number, carry the hardened
   runtime bit (0x10000). The whole bundle verifies with
   `codesign --verify --strict --deep`, which fails when an outer signature
   was made before an inner one changed (the helper, then the CLI, then the
   app: SPEC §12).
3. Entitlements, parsed as a property list (`codesign --display
   --entitlements - --xml`): none holds a key outside ENTITLEMENTS (empty
   in M3-02: the ad hoc build signs none, and M3-10 adds the keychain
   group's keys for the development tier when it needs them). The forbidden
   keys get their own message: `com.apple.security.get-task-allow`, any
   `com.apple.security.cs.` key (the hardened runtime's exceptions:
   allow-jit, allow-unsigned-executable-memory,
   allow-dyld-environment-variables, disable-library-validation,
   disable-executable-page-protection, debugger, and any later one) and any
   `com.apple.security.temporary-exception.` key. A key counts when it is
   present, whatever its value.
4. Bundles. The app's and the helper's Info.plist hold only the keys their
   sources in apps/macos/Support/ set and the build keys Xcode adds (any
   other key, such as LSEnvironment, which would set the app's
   environment, fails), name their identifiers and executables, the helper
   is background-only, and no Info.plist in the bundle holds a side door
   (URL types, AppleScript, Services, documents, exported or imported
   types, user activities, extensions; SPEC §12).
5. Layout. Contents/Library/LaunchAgents/ai.envcloak.agent.plist is exactly
   EXPECTED_AGENT, key for key and value for value (its label, its
   BundleProgram, the helper's executable, its arguments, and the launchd
   settings of packaging/launchd/; SPEC §12, registered by M3-18): an
   added key (EnvironmentVariables, MachServices, Program), a changed
   argument or a dropped limit fails.
6. Architectures. Each executable is built for one architecture, the same
   for all three (`lipo -archs`): `codesign --display` reports only the
   host's slice of a universal file, so a slice signed without the runtime
   or with a forbidden entitlement would pass unseen. Universal builds
   arrive with M7, which reads each slice (`--arch`).
7. No test-only input. No executable holds the names of SwiftPM's
   Debug-only environment override of a package's resource bundle
   (`PACKAGE_RESOURCE_BUNDLE_PATH`, `PACKAGE_RESOURCE_BUNDLE_URL`, read by
   the generated resource_bundle_accessor.swift under `#if DEBUG`): a
   release app reads no environment variable to choose what it loads
   (docs/APP.md "The app run by an agent").

Usage: sign-check.sh [--facts] path/to/EnvCloak.app
--facts prints what was read (identifiers, flags, entitlement keys,
architectures) as JSON on standard output, for the independent reader in
scripts/macos/tests/ to compare.
"""

import json
import os
import plistlib
import re
import stat
import subprocess
import sys

EXECUTABLES = {
    "Contents/MacOS/EnvCloakApp": "ai.envcloak.app",
    "Contents/MacOS/envcloak": "ai.envcloak.cli",
    "Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd": "ai.envcloak.agent",
}
HELPER = "Contents/Helpers/EnvCloakAgent.app"
LAUNCH_AGENT = "Contents/Library/LaunchAgents/ai.envcloak.agent.plist"
RUNTIME = 0x10000
TEST_ONLY_INPUTS = (b"PACKAGE_RESOURCE_BUNDLE_PATH", b"PACKAGE_RESOURCE_BUNDLE_URL")
MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
# Entitlement keys a shipped executable may carry. Empty in M3-02; M3-10
# adds the keychain group's (D3-05) with the development tier.
ENTITLEMENTS = frozenset()
# The bundled LaunchAgent, exactly (apps/macos/Support/LaunchAgents/; a test
# keeps the source equal to this).
EXPECTED_AGENT = {
    "Label": "ai.envcloak.agent",
    "BundleProgram": "Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd",
    "ProgramArguments": ["envcloakd", "--foreground"],
    "AssociatedBundleIdentifiers": ["ai.envcloak.app"],
    "RunAtLoad": True,
    "KeepAlive": {"SuccessfulExit": False},
    "ProcessType": "Interactive",
    "Umask": 0o77,
    "SoftResourceLimits": {"Core": 0},
    "HardResourceLimits": {"Core": 0},
}
# Info.plist keys: what apps/macos/Support/*-Info.plist set, and what Xcode
# adds when it builds (the icon's keys for the app, the build machine and
# the DT* toolchain keys).
BUILD_KEYS = {"BuildMachineOSBuild", "CFBundleSupportedPlatforms"}
APP_INFO_KEYS = {
    "CFBundleDevelopmentRegion",
    "CFBundleDisplayName",
    "CFBundleExecutable",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "LSApplicationCategoryType",
    "LSMinimumSystemVersion",
    "CFBundleIconFile",
    "CFBundleIconName",
}
HELPER_INFO_KEYS = {
    "CFBundleDevelopmentRegion",
    "CFBundleExecutable",
    "CFBundleIdentifier",
    "CFBundleInfoDictionaryVersion",
    "CFBundleName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "LSBackgroundOnly",
    "LSMinimumSystemVersion",
}
SIDE_DOOR_KEYS = (
    "CFBundleURLTypes",
    "NSAppleScriptEnabled",
    "OSAScriptingDefinition",
    "NSServices",
    "CFBundleDocumentTypes",
    "UTExportedTypeDeclarations",
    "UTImportedTypeDeclarations",
    "NSUserActivityTypes",
    "NSExtension",
)
FLAGS = re.compile(r"^CodeDirectory v=\S+ size=\S+ flags=(0x[0-9a-fA-F]+)\(", re.M)
IDENT = re.compile(r"^Identifier=(.+)$", re.M)

problems = []


def fail(msg):
    problems.append(msg)


def run(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return 127, b"", str(e).encode()
    return p.returncode, p.stdout, p.stderr


def forbidden(key):
    return (
        key in ("com.apple.security.get-task-allow", "get-task-allow")
        or key.startswith("com.apple.security.cs.")
        or key.startswith("com.apple.security.temporary-exception.")
    )


def case_clashes(names):
    """Groups of names that differ only in case, which a case-insensitive
    volume (the default APFS) holds as one file."""
    folded = {}
    for name in names:
        folded.setdefault(name.casefold(), []).append(name)
    return [sorted(group) for group in folded.values() if len(group) > 1]


def inventory(app):
    found = []
    for dirpath, dirnames, filenames in os.walk(app):
        for names in case_clashes(dirnames + filenames):
            fail("%s: names that differ only in case: %s" % (os.path.relpath(dirpath, app), ", ".join(names)))
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, app)
            if os.path.islink(full):
                fail("%s: a symbolic link in the bundle" % rel)
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, app)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                fail("%s: not a regular file" % rel)
                continue
            with open(full, "rb") as f:
                head = f.read(4)
            if head in MACHO_MAGIC or st.st_mode & 0o111:
                found.append(rel)
    return sorted(found)


def signature(app, rel, want_id):
    path = os.path.join(app, rel)
    facts = {"identifier": None, "flags": None, "runtime": False, "entitlements": None, "archs": None}
    code, _, err = run(["codesign", "--display", "--verbose=4", path])
    text = err.decode("utf-8", "replace")
    if code != 0:
        fail("%s: not signed (codesign --display: %s)" % (rel, text.strip().splitlines()[-1] if text.strip() else code))
        return facts
    m = IDENT.search(text)
    facts["identifier"] = m.group(1) if m else None
    if facts["identifier"] != want_id:
        fail("%s: signed as %r, not %s" % (rel, facts["identifier"], want_id))
    m = FLAGS.search(text)
    if not m:
        fail("%s: no code directory flags in codesign's output" % rel)
    else:
        facts["flags"] = int(m.group(1), 16)
        facts["runtime"] = bool(facts["flags"] & RUNTIME)
        if not facts["runtime"]:
            fail("%s: signed without the hardened runtime (flags %s)" % (rel, m.group(1)))
    code, out, err = run(["codesign", "--display", "--entitlements", "-", "--xml", path])
    if code != 0:
        fail("%s: cannot read its entitlements (%s)" % (rel, err.decode("utf-8", "replace").strip()))
    else:
        keys = []
        if out.strip():
            try:
                ents = plistlib.loads(out)
            except Exception as e:  # noqa: BLE001 - any parse failure fails the check
                fail("%s: entitlements are not a property list (%s)" % (rel, type(e).__name__))
                ents = None
            if ents is not None and not isinstance(ents, dict):
                fail("%s: entitlements are not a dictionary" % rel)
            elif ents is not None:
                keys = sorted(ents)
        facts["entitlements"] = keys
        for key in keys:
            if forbidden(key):
                fail("%s: carries the entitlement %s" % (rel, key))
            elif key not in ENTITLEMENTS:
                fail("%s: carries the entitlement %s, which no tier signs yet" % (rel, key))
    with open(path, "rb") as f:
        data = f.read()
    for name in TEST_ONLY_INPUTS:
        if name in data:
            fail("%s: holds %s, a Debug build's environment override" % (rel, name.decode()))
    code, out, err = run(["lipo", "-archs", path])
    if code != 0:
        fail("%s: lipo cannot read its architectures (%s)" % (rel, err.decode("utf-8", "replace").strip()))
    else:
        facts["archs"] = sorted(out.decode().split())
        if len(facts["archs"]) != 1:
            fail("%s: built for %s; codesign shows one slice's signature, so one architecture until M7" % (rel, " and ".join(facts["archs"]) or "no architecture"))
    return facts


def read_plist(app, rel):
    path = os.path.join(app, rel)
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except FileNotFoundError:
        fail("%s: missing" % rel)
        return None
    except Exception as e:  # noqa: BLE001
        fail("%s: not a property list (%s)" % (rel, type(e).__name__))
        return None
    if not isinstance(data, dict):
        fail("%s: not a dictionary" % rel)
        return None
    return data


def unknown_keys(rel, data, allowed):
    for key in sorted(data):
        if key not in allowed and key not in BUILD_KEYS and not re.match(r"^DT[A-Za-z]+$", key):
            fail("%s: holds %s, a key its source does not set" % (rel, key))


def bundles(app):
    info = read_plist(app, "Contents/Info.plist")
    if info is not None:
        unknown_keys("Contents/Info.plist", info, APP_INFO_KEYS)
        if info.get("CFBundleIdentifier") != "ai.envcloak.app" or info.get("CFBundleExecutable") != "EnvCloakApp":
            fail("Contents/Info.plist: not ai.envcloak.app with the executable EnvCloakApp")
    helper = read_plist(app, HELPER + "/Contents/Info.plist")
    if helper is not None:
        unknown_keys(HELPER + "/Contents/Info.plist", helper, HELPER_INFO_KEYS)
        if helper.get("CFBundleIdentifier") != "ai.envcloak.agent" or helper.get("CFBundleExecutable") != "envcloakd":
            fail("%s/Contents/Info.plist: not ai.envcloak.agent with the executable envcloakd" % HELPER)
        if helper.get("LSBackgroundOnly") is not True:
            fail("%s/Contents/Info.plist: the helper is not background-only" % HELPER)
    for dirpath, _, filenames in os.walk(app):
        for name in filenames:
            if name != "Info.plist":
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), app)
            data = read_plist(app, rel)
            if data is None:
                continue
            for key in SIDE_DOOR_KEYS:
                if key in data:
                    fail("%s: holds %s, a side door (SPEC §12)" % (rel, key))
    agent = read_plist(app, LAUNCH_AGENT)
    if agent is not None:
        for key in sorted(set(agent) | set(EXPECTED_AGENT)):
            if key not in EXPECTED_AGENT:
                fail("%s: holds %s, which the agent's plist does not set" % (LAUNCH_AGENT, key))
            elif key not in agent:
                fail("%s: lacks %s" % (LAUNCH_AGENT, key))
            elif not same_plist_value(agent[key], EXPECTED_AGENT[key]):
                fail("%s: %s is not what the agent's plist sets" % (LAUNCH_AGENT, key))
        program = agent.get("BundleProgram")
        if isinstance(program, str) and not os.path.isfile(os.path.join(app, program)):
            fail("%s: BundleProgram names a file the bundle lacks" % LAUNCH_AGENT)


def same_plist_value(a, b):
    """Equal as property-list values: a boolean is never an integer."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(same_plist_value(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_plist_value(x, y) for x, y in zip(a, b))
    return a == b


def main(argv):
    args = argv[1:]
    facts_out = False
    if args and args[0] == "--facts":
        facts_out = True
        args = args[1:]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    app = args[0].rstrip("/")
    if os.path.islink(app) or not os.path.isdir(app) or not app.endswith(".app"):
        print("sign-check: %s is not an .app directory" % app, file=sys.stderr)
        return 2

    found = inventory(app)
    for rel in found:
        if rel not in EXECUTABLES:
            fail("%s: an executable the bundle must not hold" % rel)
    facts = {}
    for rel, want in EXECUTABLES.items():
        if rel not in found:
            fail("%s: missing" % rel)
            continue
        facts[rel] = signature(app, rel, want)
    code, _, err = run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", app])
    if code != 0:
        lines = err.decode("utf-8", "replace").strip().splitlines()
        fail("the bundle does not verify (codesign --verify --strict --deep): %s" % (lines[-1] if lines else code))
    bundles(app)
    archs = {tuple(f["archs"]) for f in facts.values() if f.get("archs") is not None}
    if len(archs) > 1:
        fail("the executables are built for different architectures: %s" % ", ".join(sorted(" ".join(a) for a in archs)))

    if facts_out:
        print(json.dumps(facts, indent=2, sort_keys=True))
    for msg in problems:
        print("sign-check: " + msg, file=sys.stderr)
    if problems:
        print("sign-check: %s failed (%d problem(s))" % (app, len(problems)), file=sys.stderr)
        return 1
    print("sign-check: ok (%s: %d executables, hardened runtime, no entitlement outside the list, one architecture)" % (app, len(facts)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
