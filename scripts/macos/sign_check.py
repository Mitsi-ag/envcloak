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
   --entitlements - --xml`): none holds `com.apple.security.get-task-allow`,
   any `com.apple.security.cs.` key (the hardened runtime's exceptions:
   allow-jit, allow-unsigned-executable-memory,
   allow-dyld-environment-variables, disable-library-validation,
   disable-executable-page-protection, debugger, and any later one) or any
   `com.apple.security.temporary-exception.` key. A key counts when it is
   present, whatever its value.
4. Bundles. The app's and the helper's Info.plist name their identifiers
   and executables, the helper is background-only, and no Info.plist in the
   bundle holds a side door (URL types, AppleScript, Services, documents,
   exported or imported types, user activities, extensions; SPEC §12).
5. Layout. Contents/Library/LaunchAgents/ai.envcloak.agent.plist is labelled
   ai.envcloak.agent and its BundleProgram is the helper's executable
   (SPEC §12; registered by M3-18).
6. Architectures. The three executables are built for the same
   architectures (`lipo -archs`).
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


def bundles(app):
    info = read_plist(app, "Contents/Info.plist")
    if info is not None:
        if info.get("CFBundleIdentifier") != "ai.envcloak.app" or info.get("CFBundleExecutable") != "EnvCloakApp":
            fail("Contents/Info.plist: not ai.envcloak.app with the executable EnvCloakApp")
    helper = read_plist(app, HELPER + "/Contents/Info.plist")
    if helper is not None:
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
        if agent.get("Label") != "ai.envcloak.agent":
            fail("%s: Label is not ai.envcloak.agent" % LAUNCH_AGENT)
        program = agent.get("BundleProgram")
        if program != HELPER + "/Contents/MacOS/envcloakd":
            fail("%s: BundleProgram is not the helper's envcloakd" % LAUNCH_AGENT)
        elif not os.path.isfile(os.path.join(app, program)):
            fail("%s: BundleProgram names a file the bundle lacks" % LAUNCH_AGENT)


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
    print("sign-check: ok (%s: %d executables, hardened runtime, no forbidden entitlement)" % (app, len(facts)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
