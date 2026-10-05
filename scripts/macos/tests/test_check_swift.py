#!/usr/bin/env python3
"""Tests for scripts/macos/check-swift.sh: a clean tree passes, and each
refusal fixture (one change to that tree) fails with the rule it breaks,
pinned to the changed file. Negative controls (code that looks close but
is allowed) must pass, so a rule that refuses everything fails here too.

The fixture trees are written at run time under a short temporary
directory: the key-literal case needs a key-shaped string, which is never
committed (M3 plan §5 rule 7), and the rest are kept beside it so each case
reads as one change. The provider registry is copied from this checkout.

Usage: python3 scripts/macos/tests/test_check_swift.py
"""

import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CHECK = os.path.join(ROOT, "scripts", "macos", "check-swift.sh")
FINDING = re.compile(r"^check-swift: \[([a-z0-9-]+)\] ([^:]+)(?::(\d+))?: ", re.M)

APP = "apps/macos/EnvCloak/App/App.swift"
VIEW = "apps/macos/EnvCloak/Features/View.swift"
KIT = "apps/macos/Packages/EnvCloakKit/Sources/EnvCloakKit/Client.swift"
TOKEN_FILE = "apps/macos/Packages/EnvCloakKit/Sources/EnvCloakKit/Log/LogToken.swift"
DESIGN = "apps/macos/Packages/EnvCloakDesign/Sources/EnvCloakDesign/Tokens.swift"
TEST = "apps/macos/EnvCloakTests/AppTests.swift"
INFO = "apps/macos/Support/EnvCloak-Info.plist"
ENTITLEMENTS = "apps/macos/Support/EnvCloak.entitlements"
MANIFEST = "apps/macos/Packages/EnvCloakKit/Package.swift"
PBXPROJ = "apps/macos/EnvCloak.xcodeproj/project.pbxproj"
EXPOSE = "apps/macos/security/expose-allowlist.txt"
RULES = "apps/macos/security/check-swift-allowlist.txt"
BRAND_SWIFT = "assets/brand/motion/swiftui/Motion.swift"
BRAND_LINK = "apps/macos/Packages/EnvCloakDesign/Sources/EnvCloakDesign/Motion.swift"

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
%s</dict>
</plist>
"""

BASE = {
    APP: """import SwiftUI
import EnvCloakKit

@main
struct DemoApp: App {
    @Environment(\\.openWindow) private var openWindow
    init() {
        ECLog.logger(.app).notice("\\(AppEvent.launched.logToken, privacy: .public)")
    }
    var body: some Scene {
        Window("Demo", id: "main") { View() }
    }
}

enum AppEvent: String, LogToken {
    case launched = "launched"
}
""",
    VIEW: """import SwiftUI
import EnvCloakDesign

struct View: SwiftUI.View {
    let total: Int
    var body: some SwiftUI.View {
        VStack {
            Text("Open the folder") // print("a comment is not code")
                .fontWeight(.black)
                .foregroundStyle(ECToken.text.color)
            Text("print(\\"in a string\\") and Color(red: 1, green: 0, blue: 0)")
                .foregroundStyle(.secondary)
            Button("Open") {}
                .keyboardShortcut(.defaultAction)
            Divider().background(Color.clear)
        }
        .environment(\\.locale, Locale(identifier: "en_GB"))
        .padding(total > 2 ? 8 : 4)
    }
}
""",
    KIT: """import Foundation

public struct Client {
    public init() {}
    public func size(_ n: Int) -> Int { n / 2 }
    // A child's streams are not the app's own.
    public func child() -> Process {
        let p = Process()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        return p
    }
}
""",
    TOKEN_FILE: """import os

public protocol LogToken: RawRepresentable, Sendable where RawValue == String {}

extension LogToken {
    public var logToken: String { rawValue }
}

public enum ECLog {
    public static func logger(_ category: ECLogCategory) -> Logger {
        Logger(subsystem: "ai.envcloak.app", category: category.rawValue)
    }
}

public enum ECLogCategory: String, Sendable {
    case app
}
""",
    DESIGN: """import SwiftUI

public enum ECToken: String, CaseIterable, Sendable {
    case text
    public var color: Color { Color(rawValue, bundle: .module) }
    public var named: Color { Color("text", bundle: .module) }
}
""",
    BRAND_SWIFT: """import SwiftUI

public enum ECColor {
    public static let ink = Color(.sRGB, red: 0.07, green: 0.07, blue: 0.06)
}
""",
    TEST: """import XCTest

final class AppTests: XCTestCase {
    func testPrintingIsFineInTests() {
        print("tests may print")
        _ = ProcessInfo.processInfo.environment["HOME"]
    }
}
""",
    INFO: PLIST % "\t<key>CFBundleIdentifier</key>\n\t<string>ai.envcloak.app</string>\n",
    ENTITLEMENTS: PLIST % "",
    MANIFEST: """// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "EnvCloakKit",
    dependencies: [.package(path: "../EnvCloakDesign")],
    targets: [.target(name: "EnvCloakKit")]
)
""",
    PBXPROJ: "// !$*UTF8*$!\n{\n\tobjects = {\n\t\tEC01 = {isa = XCLocalSwiftPackageReference; relativePath = Packages/EnvCloakKit; };\n\t};\n}\n",
    EXPOSE: "# path  # reason\n",
    RULES: "# rule path  # reason\n",
}


def key_shaped():
    """A string matching providers/openai.toml's first key pattern, made at
    run time."""
    alphabet = string.ascii_letters + string.digits
    return "sk-" + "proj" + "-" + "".join(random.SystemRandom().choice(alphabet) for _ in range(40))


def append(path, text):
    return ("append", path, text)


def replace(path, old, new):
    return ("replace", path, old, new)


def write(path, text):
    return ("write", path, text)


def link(path, target):
    return ("link", path, target)


SWIFT_REFUSALS = [
    # (name, rule, file the finding names, change)
    ("unsafe bytes", "unsafe-bytes", KIT, append(KIT, "func f(d: Data) { d.withUnsafeBytes { _ in } }\n")),
    ("mutable unsafe bytes", "unsafe-bytes", KIT, append(KIT, "func f(d: inout Data) { d.withUnsafeMutableBytes { _ in } }\n")),
    ("scene storage", "storage", VIEW, replace(VIEW, "    let total: Int\n", "    let total: Int\n    @SceneStorage(\"draft\") var draft = \"\"\n")),
    ("ubiquitous store", "storage", KIT, append(KIT, "let s = NSUbiquitousKeyValueStore.default\n")),
    ("command line", "launch-input", APP, append(APP, "let args = CommandLine.arguments\n")),
    ("environment", "launch-input", KIT, append(KIT, "let e = ProcessInfo.processInfo.environment[\"X\"]\n")),
    ("environment through a name", "launch-input", KIT, append(KIT, "let info = ProcessInfo.processInfo\nlet e = info.environment\n")),
    ("arguments", "launch-input", KIT, append(KIT, "let a = ProcessInfo.processInfo.arguments\n")),
    ("getenv", "launch-input", KIT, append(KIT, "let h = getenv(\"HOME\")\n")),
    ("user defaults", "launch-input", KIT, append(KIT, "let d = UserDefaults.standard.string(forKey: \"socket\")\n")),
    ("app storage", "launch-input", VIEW, replace(VIEW, "    let total: Int\n", "    let total: Int\n    @AppStorage(\"vault\") var vault = \"\"\n")),
    ("standard input", "launch-input", KIT, append(KIT, "let line = readLine()\n")),
    ("the app's standard input handle", "launch-input", KIT, append(KIT, "let h = FileHandle.standardInput\n")),
    ("the C standard input", "launch-input", KIT, append(KIT, "let c = getc(stdin)\n")),
    ("app intents", "side-door", APP, replace(APP, "import SwiftUI\n", "import SwiftUI\nimport AppIntents\n")),
    ("open url", "side-door", VIEW, replace(VIEW, "        .padding(total > 2 ? 8 : 4)\n", "        .padding(total > 2 ? 8 : 4)\n        .onOpenURL { _ in }\n")),
    ("external events", "side-door", APP, replace(APP, "Window(\"Demo\", id: \"main\") { View() }", "Window(\"Demo\", id: \"main\") { View() }.handlesExternalEvents(matching: [])")),
    ("apple events", "side-door", KIT, append(KIT, "func h() { NSAppleEventManager.shared().setEventHandler(nil, andSelector: Selector((\"x\")), forEventClass: 0, andEventID: 0) }\n")),
    ("delegate open", "side-door", KIT, append(KIT, "final class D { func application(_ a: AnyObject, open urls: [URL]) {} }\n")),
    ("user activity", "side-door", VIEW, replace(VIEW, "        .padding(total > 2 ? 8 : 4)\n", "        .padding(total > 2 ? 8 : 4)\n        .onContinueUserActivity(\"x\") { _ in }\n")),
    ("accessibility action", "a11y-action", VIEW, replace(VIEW, "            Divider()", "            Text(\"x\").accessibilityAction(named: \"Approve\") {}\n            Divider()")),
    ("approve on a key", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button(\"Approve with Touch ID\") {}")),
    ("reveal on a key, title in the label", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button { } label: { Text(\"Reveal\") }")),
    ("remove on a key press", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Button(\"Remove key\") {}\n                .padding(2)\n                .onKeyPress(.delete) { .handled }")),
    ("print", "log", KIT, append(KIT, "func p() { print(\"x\") }\n")),
    ("swift print", "log", KIT, append(KIT, "func p() { Swift.print(\"x\") }\n")),
    ("debugPrint", "log", KIT, append(KIT, "func p(x: Int) { debugPrint(x) }\n")),
    ("dump", "log", KIT, append(KIT, "func p(x: Int) { dump(x) }\n")),
    ("NSLog", "log", KIT, append(KIT, "func p() { NSLog(\"x\") }\n")),
    ("standard error", "log", KIT, append(KIT, "func p() { FileHandle.standardError.write(Data()) }\n")),
    ("C standard output", "log", KIT, append(KIT, "func p() { fflush(stdout) }\n")),
    ("print in an interpolation", "log", KIT, append(KIT, "let s = \"\\(print(\"x\"))\"\n")),
    ("a value in a log message", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.logToken, privacy: .public) \\(Secret.value)")),
    ("a public value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.rawValue, privacy: .public)")),
    ("a private value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.rawValue)")),
    ("public privacy outside a log call", "log", KIT, append(KIT, "import os\nfunc m(name: String) -> OSLogMessage { \"x \\(name, privacy: .public)\" }\n")),
    ("os_log value", "log", KIT, append(KIT, "import os\nfunc p(v: String) { os_log(\"x \\(v)\") }\n")),
    ("public format", "log", KIT, append(KIT, "let f = \"%{public}s\"\n")),
    ("a struct token", "log", KIT, append(KIT, "struct Word: RawRepresentable, LogToken { var rawValue: String }\n")),
    ("an extension token", "log", KIT, append(KIT, "extension Client: LogToken {}\n")),
    ("a second logToken", "log", KIT, append(KIT, "extension Client { var logToken: String { \"x\" } }\n")),
    ("raw daemon text", "daemon-text", VIEW, replace(VIEW, "Text(\"Open the folder\")", "Text(item.title.unescaped)")),
    ("component colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(red: 1, green: 0, blue: 0))")),
    ("colour space colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(.sRGB, red: 1, green: 0, blue: 0))")),
    ("init colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color.init(white: 0.5))")),
    ("AppKit colour", "color", KIT, append(KIT, "import AppKit\nlet c = NSColor(calibratedRed: 1, green: 0, blue: 0, alpha: 1)\n")),
    ("colour literal", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(#colorLiteral(red: 1, green: 0, blue: 0, alpha: 1)))")),
    ("system colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color.red)")),
    ("implicit system colour", "color", VIEW, replace(VIEW, ".foregroundStyle(.secondary)", ".foregroundStyle(.blue)")),
    ("system NSColor", "color", KIT, append(KIT, "import AppKit\nlet c = NSColor.systemRed\n")),
    ("CGColor", "color", KIT, append(KIT, "import CoreGraphics\nlet c = CGColor(gray: 0.5, alpha: 1)\n")),
    ("catalog colour outside the design package", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(\"background\", bundle: .main))")),
    ("unterminated string", "lex", KIT, append(KIT, "let s = \"open\n")),
    ("unterminated comment", "lex", KIT, append(KIT, "/* open\n")),
    ("bare regex", "lex", KIT, append(KIT, "let r = /a+b/\n")),
    ("brand file printing", "log", BRAND_LINK, append(BRAND_SWIFT, "func p() { print(\"x\") }\n")),
]

OTHER_REFUSALS = [
    ("url scheme in Info.plist", "side-door", INFO, replace(INFO, "</dict>", "\t<key>CFBundleURLTypes</key>\n\t<array/>\n</dict>")),
    ("AppleScript in Info.plist", "side-door", INFO, replace(INFO, "</dict>", "\t<key>NSAppleScriptEnabled</key>\n\t<true/>\n</dict>")),
    ("scripting definition", "side-door", INFO, replace(INFO, "</dict>", "\t<key>OSAScriptingDefinition</key>\n\t<string>x.sdef</string>\n</dict>")),
    ("services", "side-door", INFO, replace(INFO, "</dict>", "\t<key>NSServices</key>\n\t<array/>\n</dict>")),
    ("a key set by a build setting", "side-door", PBXPROJ, replace(PBXPROJ, "\t};\n}", "\t\tINFOPLIST_KEY_NSServices = x;\n\t};\n}")),
    ("get-task-allow", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>com.apple.security.get-task-allow</key>\n\t<true/>\n")),
    ("a runtime exception", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>com.apple.security.cs.allow-jit</key>\n\t<true/>\n")),
    ("a remote package", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(url: "https://example.invalid/sdk.git", from: "1.0.0")')),
    ("a registry package", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(id: "example.sdk", from: "1.0.0")')),
    ("a remote package in the project", "remote-package", PBXPROJ, replace(PBXPROJ, "XCLocalSwiftPackageReference", "XCRemoteSwiftPackageReference")),
    ("a stray Swift file", "stray-swift", "apps/macos/Tools/gen.swift", write("apps/macos/Tools/gen.swift", "let x = 1\n")),
    ("a link out of the brand", "symlink", "apps/macos/EnvCloak/App/Hosts.swift", link("apps/macos/EnvCloak/App/Hosts.swift", "/etc/hosts")),
    ("an allowlist entry without a reason", "allowlist", EXPOSE, append(EXPOSE, KIT + "\n")),
    ("an allowlist entry for no file", "allowlist", EXPOSE, append(EXPOSE, "apps/macos/EnvCloak/Gone.swift  # gone\n")),
    ("an unused allowlist entry", "allowlist", EXPOSE, append(EXPOSE, KIT + "  # nothing there now\n")),
    ("a rule that cannot be allowed", "allowlist", RULES, append(RULES, "log " + KIT + "  # no\n")),
]


class Tree:
    def __init__(self, base_dir):
        self.root = tempfile.mkdtemp(prefix="eccs", dir=base_dir)
        for rel, text in BASE.items():
            self.write(rel, text)
        os.makedirs(os.path.join(self.root, os.path.dirname(BRAND_LINK)), exist_ok=True)
        os.symlink(os.path.relpath(os.path.join(self.root, BRAND_SWIFT), os.path.join(self.root, os.path.dirname(BRAND_LINK))), os.path.join(self.root, BRAND_LINK))
        shutil.copytree(os.path.join(ROOT, "providers"), os.path.join(self.root, "providers"))

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def read(self, rel):
        with open(os.path.join(self.root, rel)) as f:
            return f.read()

    def apply(self, change):
        kind = change[0]
        if kind == "append":
            self.write(change[1], self.read(change[1]) + change[2])
        elif kind == "replace":
            text = self.read(change[1])
            if change[2] not in text:
                raise AssertionError("fixture change does not apply: %r" % (change[2],))
            self.write(change[1], text.replace(change[2], change[3], 1))
        elif kind == "write":
            self.write(change[1], change[2])
        elif kind == "link":
            path = os.path.join(self.root, change[1])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.symlink(change[2], path)

    def check(self):
        p = subprocess.run([CHECK, "--root", self.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode, p.stdout.decode() + p.stderr.decode()


class CheckSwift(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="eccs", dir="/tmp")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base)

    def findings(self, out):
        return [(m.group(1), m.group(2)) for m in FINDING.finditer(out)]

    def test_the_clean_tree_passes(self):
        code, out = Tree(self.base).check()
        self.assertEqual(code, 0, out)
        self.assertIn("check-swift: ok (6 product Swift files", out)

    def test_the_repository_passes(self):
        p = subprocess.run([CHECK], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def refusal(self, name, rule, where, change):
        tree = Tree(self.base)
        tree.apply(change)
        code, out = tree.check()
        self.assertEqual(code, 1, "%s: passed\n%s" % (name, out))
        found = self.findings(out)
        self.assertIn((rule, where), found, "%s: wanted [%s] in %s\n%s" % (name, rule, where, out))
        return found

    def test_each_swift_refusal_fixture_fails_with_its_rule(self):
        for name, rule, where, change in SWIFT_REFUSALS:
            with self.subTest(fixture=name):
                self.refusal(name, rule, where, change)

    def test_each_other_refusal_fixture_fails_with_its_rule(self):
        for name, rule, where, change in OTHER_REFUSALS:
            with self.subTest(fixture=name):
                self.refusal(name, rule, where, change)

    def test_a_key_shaped_literal_fails_anywhere(self):
        for rel in (TEST, INFO, "apps/macos/notes.md"):
            with self.subTest(file=rel):
                tree = Tree(self.base)
                if os.path.exists(os.path.join(tree.root, rel)):
                    tree.apply(append(rel, "\n// %s\n" % key_shaped()))
                else:
                    tree.write(rel, "%s\n" % key_shaped())
                code, out = tree.check()
                self.assertEqual(code, 1, out)
                self.assertIn(("key-literal", rel), self.findings(out))

    def test_an_allowlisted_file_passes_and_the_entry_must_be_used(self):
        tree = Tree(self.base)
        tree.apply(append(KIT, "func f(d: Data) { d.withUnsafeBytes { _ in } }\n"))
        tree.apply(append(EXPOSE, KIT + "  # reads a frame's bytes\n"))
        code, out = tree.check()
        self.assertEqual(code, 0, out)
        tree = Tree(self.base)
        tree.apply(append(KIT, "let d = UserDefaults.standard\n"))
        tree.apply(append(RULES, "launch-input " + KIT + "  # reviewed\n"))
        code, out = tree.check()
        self.assertEqual(code, 0, out)

    def test_the_brand_file_keeps_its_colours(self):
        # The brand's own Swift defines the brand colours from components;
        # the same line in the app is refused.
        tree = Tree(self.base)
        code, out = tree.check()
        self.assertEqual(code, 0, out)
        tree = Tree(self.base)
        tree.apply(append(KIT, "import SwiftUI\nlet ink = Color(.sRGB, red: 0.07, green: 0.07, blue: 0.06)\n"))
        code, out = tree.check()
        self.assertIn(("color", KIT), self.findings(out))

    def test_listing_names_every_swift_file_read(self):
        tree = Tree(self.base)
        p = subprocess.run([CHECK, "--list-swift", "--root", tree.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        listed = set(p.stdout.decode().split())
        want = {os.path.realpath(os.path.join(tree.root, rel)) for rel in (APP, VIEW, KIT, TOKEN_FILE, DESIGN, TEST, BRAND_SWIFT)}
        self.assertEqual(listed, want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
