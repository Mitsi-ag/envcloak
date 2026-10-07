#!/usr/bin/env python3
"""Tests for scripts/macos/check-swift.sh: a clean tree passes, and each
refusal fixture (one change to that tree) fails with the rule it breaks,
pinned to the changed file. Negative controls (code that looks close but
is allowed: a child process's streams, working directory, arguments and
environment being set, an implicit `.error(...)` case, a descriptor in a
variable, `/dev/null` and `/dev/urandom`, the temporary directory, an
NSException with a literal reason and a fixed name, a token enum's case
forms, a struct with its own `rawValue`, a nested one inside an extension,
a local named `rawValue`, an option set's implicit `.init(rawValue: 1)` in
a file without System, SwiftUI's `extension ShapeStyle where Self ==
Color`, buttons with ordinary actions and a text-and-image label given
shortcuts directly, `onSubmit` and `onExitCommand` that search, an empty
AppKit key equivalent, an alert whose Remove button is destructive (with a
gated title and message, which are not buttons), an NSAlert button titled
OK and a cleared default button, a descriptor computed to 3 and a write of
length 1, `try?` and `init(_:uniquingKeysWith:)`, ECLog's Logger from a
constant subsystem and a category enum, the brand's icon group, an SDK
framework, settings that name files inside apps/macos, a scheme and a JSON
file with escapes that spell nothing refused) sit in the clean tree, so a
rule that refuses too much fails here too.

The fixture trees are written at run time under a short temporary
directory: the key-literal case needs a key-shaped string, which is never
committed (M3 plan §5 rule 7), and the rest are kept beside it so each case
reads as one change. The provider registry is copied from this checkout.

Usage: python3 scripts/macos/tests/test_check_swift.py
"""

import os
import plistlib
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

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
TEST_SUPPORT = "apps/macos/Packages/EnvCloakKit/Sources/EnvCloakKitTestSupport/FakeDaemon.swift"
# A product file of its own, for fixtures whose import changes what the
# clean tree's files mean.
STREAM = "apps/macos/Packages/EnvCloakKit/Sources/EnvCloakKit/Stream.swift"
INFO = "apps/macos/Support/EnvCloak-Info.plist"
ENTITLEMENTS = "apps/macos/Support/EnvCloak.entitlements"
MANIFEST = "apps/macos/Packages/EnvCloakKit/Package.swift"
PBXPROJ = "apps/macos/EnvCloak.xcodeproj/project.pbxproj"
XCCONFIG = "apps/macos/Config/Base.xcconfig"
SCHEME = "apps/macos/EnvCloak.xcodeproj/xcshareddata/xcschemes/EnvCloak.xcscheme"
ASSET_JSON = "apps/macos/Packages/EnvCloakDesign/Sources/EnvCloakDesign/Resources/Colors.xcassets/Contents.json"
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
    TEST_SUPPORT: "func testOnly() { print(1) }\n",
    APP: """import SwiftUI
import EnvCloakKit

@main
struct DemoApp: App {
    @Environment(\\.openWindow) private var openWindow
    init() {
        ECLog.logger(.app).notice("\\(AppEvent.launched.logToken, privacy: .public)")
        ECLog.logger(.app).log(level: .info, "count \\(AppEvent.other.logToken)")
    }
    var body: some Scene {
        Window("Demo", id: "main") { View() }
    }
    func stop() -> Never {
        fatalError("stopped \\(AppEvent.third.logToken)")
    }
}

enum AppEvent: String, LogToken {
    case launched = "launched", other
    case third
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
            Button("Search") { search() }
                .keyboardShortcut("f")
            Button(action: search) { Label("Find", systemImage: "magnifyingglass") }
                .keyboardShortcut("g")
            TextField("Find", text: .constant("")).onSubmit { search() }
            Divider().background(Color.clear)
        }
        .onExitCommand { search() }
        // A destructive button answers no key (measured), so an alert may
        // hold Remove there; its title and message are not buttons.
        .alert("Remove the key?", isPresented: .constant(false)) {
            Button("Remove", role: .destructive) { removeKey() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Remove it from the vault")
        }
        .environment(\\.locale, Locale(identifier: "en_GB"))
        .padding(total > 2 ? 8 : 4)
    }
}
""",
    KIT: """import Foundation
import AppKit

public struct Client {
    public init() {}
    public func size(_ n: Int) -> Int { n / 2 }
    // A child's streams and working directory are not the app's own.
    public func child() -> Process {
        let p = Process()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        p.currentDirectoryURL = URL(fileURLWithPath: "/")
        p.arguments = ["status"]
        p.environment = [:]
        return p
    }
    // The null device is no one's stream.
    public func discard() -> FileHandle? { FileHandle(forWritingAtPath: "/dev/null") }
    public func stopped() -> NSException { NSException(name: .genericException, reason: "stopped", userInfo: nil) }
    // The program name comes from the executable, not argv[0] (measured).
    public func name() -> String { String(cString: getprogname()) }
    // A descriptor the client opened, not a standard stream.
    public func handle(_ fd: Int32) -> FileHandle { FileHandle(fileDescriptor: fd, closeOnDealloc: true) }
    // The temporary directory does not follow the environment (measured).
    public func scratch() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent(NSTemporaryDirectory()) }
    public func outcome() -> Outcome { return .error(1) }
    public func checked(_ n: Int) { precondition(n >= 0, "negative count") }
    // A name fixed in the source.
    public func named() -> NSException { NSException(name: NSExceptionName("ai.envcloak.stop"), reason: "stopped", userInfo: nil) }
    // Devices that are no one's stream.
    public func random() -> FileHandle? { FileHandle(forReadingAtPath: "/dev/urandom") }
    // An empty AppKit key equivalent binds no key.
    public func item() -> NSMenuItem { NSMenuItem(title: "Go", action: nil, keyEquivalent: "") }
    // A descriptor computed to 3 is no standard stream; a length of 1 is no
    // descriptor.
    public func third() -> FileHandle { FileHandle(fileDescriptor: 1 + 2) }
    public func put(_ b: UnsafeRawPointer) -> Int { write(3, b, 1) }
    // Traps that print nothing they caught: `try?` and a merge that keeps one.
    public func parse(_ d: Data) -> Any? { try? JSONSerialization.jsonObject(with: d) }
    public func merged(_ p: [(String, Int)]) -> [String: Int] { Dictionary(p, uniquingKeysWith: { a, _ in a }) }
    // An alert button that says nothing gated, and no default button.
    public func ask(_ a: NSAlert, _ w: NSWindow) { a.addButton(withTitle: "OK"); w.defaultButtonCell = nil }
}

// A key method that does nothing gated.
final class KeyView: NSView { override func keyDown(with event: NSEvent) { super.keyDown(with: event) } }

// An option set's implicit init, in a file that does not import System.
public struct Flags: OptionSet {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }
    public static let first: Flags = .init(rawValue: 1)
}

public enum Outcome { case ok, error(Int) }

public struct Slug: RawRepresentable { public let rawValue: String; public init?(rawValue: String) { self.rawValue = rawValue } }

extension Client {
    public struct Name: RawRepresentable { public let rawValue: String; public init(rawValue: String) { self.rawValue = rawValue } }
    func raw(_ s: Slug) -> String { let rawValue = s.rawValue; return rawValue }
}

public struct Box<T: LogToken> { let token: T }

final class Holder { class func make(t: some LogToken) {} }
""",
    TOKEN_FILE: """import os

public protocol LogToken: RawRepresentable, Sendable where RawValue == String {}

extension LogToken {
    public var logToken: String { rawValue }
}

public enum ECLog {
    public static let subsystem = "ai.envcloak.app"

    public static func logger(_ category: ECLogCategory) -> Logger {
        Logger(subsystem: subsystem, category: category.rawValue)
    }

    public static func other() -> Logger {
        Logger(subsystem: "ai.envcloak.app", category: "fixed")
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

extension ShapeStyle where Self == Color {
    public static var ecText: Color { ECToken.text.color }
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
    PBXPROJ: (
        "// !$*UTF8*$!\n{\n\tobjects = {\n"
        "\t\tEC01 = {isa = XCLocalSwiftPackageReference; relativePath = Packages/EnvCloakKit; };\n"
        "\t\tEC02 = {isa = PBXGroup; name = Brand; path = ../../assets/brand/icon; sourceTree = \"<group>\"; };\n"
        "\t\tEC03 = {isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = Security.framework; "
        "path = System/Library/Frameworks/Security.framework; sourceTree = SDKROOT; };\n"
        "\t\tEC04 = {isa = PBXFileReference; explicitFileType = wrapper.application; path = EnvCloak.app; sourceTree = BUILT_PRODUCTS_DIR; };\n"
        "\t\tEC05 = {isa = XCBuildConfiguration; buildSettings = {LD_RUNPATH_SEARCH_PATHS = \"@executable_path/../Frameworks\"; }; };\n"
        "\t};\n}\n"
    ),
    XCCONFIG: (
        "SWIFT_VERSION = 6.0\nLD_RUNPATH_SEARCH_PATHS = @executable_path/../Frameworks\n"
        "INFOPLIST_FILE = Support/EnvCloak-Info.plist\nCODE_SIGN_ENTITLEMENTS = $(SRCROOT)/Support/EnvCloak.entitlements\n"
        '#include "Signing-Adhoc.xcconfig"\n'
    ),
    SCHEME: '<?xml version="1.0" encoding="UTF-8"?>\n<Scheme version = "1.7">\n   <LaunchAction buildConfiguration = "Debug" &amp; "x"/>\n</Scheme>\n',
    ASSET_JSON: '{"info": {"author": "x\\u0063ode", "version": 1}}\n',
    EXPOSE: "# path  # reason\n",
    RULES: "# rule path  # reason\n",
}

# The clean tree's product Swift files: App, View, Client, LogToken, Tokens
# and the brand link.
PRODUCT_FILES = 6


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


def write_bytes(path, data):
    return ("bytes", path, data)


def link(path, target):
    return ("link", path, target)


def both(*changes):
    return ("both", changes)


def in_view(modifier):
    """A modifier on the view's stack."""
    return replace(VIEW, "        .padding(total > 2 ? 8 : 4)\n", "        .padding(total > 2 ? 8 : 4)\n        %s\n" % modifier)


def in_manifest(target_args):
    return replace(MANIFEST, '.target(name: "EnvCloakKit")', '.target(name: "EnvCloakKit", %s)' % target_args)


def in_pbxproj(line):
    return replace(PBXPROJ, "\t};\n}", "\t\t%s\n\t};\n}" % line)


SWIFT_REFUSALS = [
    # (name, rule, file the finding names, change)
    ("unsafe bytes", "unsafe-bytes", KIT, append(KIT, "func f(d: Data) { d.withUnsafeBytes { _ in } }\n")),
    ("mutable unsafe bytes", "unsafe-bytes", KIT, append(KIT, "func f(d: inout Data) { d.withUnsafeMutableBytes { _ in } }\n")),
    ("scene storage", "storage", VIEW, replace(VIEW, "    let total: Int\n", "    let total: Int\n    @SceneStorage(\"draft\") var draft = \"\"\n")),
    ("ubiquitous store", "storage", KIT, append(KIT, "let s = NSUbiquitousKeyValueStore.default\n")),
    # launch inputs: arguments, environment, defaults
    ("command line", "launch-input", APP, append(APP, "let args = CommandLine.arguments\n")),
    ("environment", "launch-input", KIT, append(KIT, "let e = ProcessInfo.processInfo.environment[\"X\"]\n")),
    ("environment through a name", "launch-input", KIT, append(KIT, "let info = ProcessInfo.processInfo\nlet e = info.environment\n")),
    ("arguments", "launch-input", KIT, append(KIT, "let a = ProcessInfo.processInfo.arguments\n")),
    ("getenv", "launch-input", KIT, append(KIT, "let h = getenv(\"HOME\")\n")),
    ("user defaults", "launch-input", KIT, append(KIT, "let d = UserDefaults.standard.string(forKey: \"socket\")\n")),
    ("app storage", "launch-input", VIEW, replace(VIEW, "    let total: Int\n", "    let total: Int\n    @AppStorage(\"vault\") var vault = \"\"\n")),
    ("default app storage", "launch-input", VIEW, in_view(".defaultAppStorage(store)")),
    ("CFPreferences", "launch-input", KIT, append(KIT, "let v = CFPreferencesCopyAppValue(\"socket\" as CFString, kCFPreferencesCurrentApplication)\n")),
    ("defaults controller", "launch-input", KIT, append(KIT, "import AppKit\nlet c = NSUserDefaultsController.shared\n")),
    ("global domain", "launch-input", KIT, append(KIT, "let g = NSGlobalDomain\n")),
    # launch inputs: standard input
    ("standard input", "launch-input", KIT, append(KIT, "let line = readLine()\n")),
    ("the app's standard input handle", "launch-input", KIT, append(KIT, "let h = FileHandle.standardInput\n")),
    ("standard input as an implicit member", "launch-input", KIT, append(KIT, "let h: FileHandle = .standardInput\n")),
    ("the C standard input", "launch-input", KIT, append(KIT, "let c = getc(stdin)\n")),
    ("the C standard input, module-qualified", "launch-input", KIT, append(KIT, "let c = getc(Darwin.stdin)\n")),
    ("standard input by descriptor", "launch-input", KIT, append(KIT, "let h = FileHandle(fileDescriptor: 0)\n")),
    ("standard input read by descriptor", "launch-input", KIT, append(KIT, "func r(p: UnsafeMutableRawPointer) { _ = read(0, p, 1) }\n")),
    ("standard input by its name", "launch-input", KIT, append(KIT, "func r(p: UnsafeMutableRawPointer) { _ = read(STDIN_FILENO, p, 1) }\n")),
    ("standard input by path", "launch-input", KIT, append(KIT, "let d = FileManager.default.contents(atPath: \"/dev/stdin\")\n")),
    ("an inherited descriptor by path", "launch-input", KIT, append(KIT, "let d = FileManager.default.contents(atPath: \"/dev/fd/3\")\n")),
    ("the launch arguments through sysctl", "launch-input", KIT, append(KIT, "let m: [Int32] = [CTL_KERN, KERN_PROCARGS2, getpid()]\n")),
    ("the launch arguments through sysctlbyname", "launch-input", KIT, append(KIT, "func p(b: UnsafeMutableRawPointer, n: UnsafeMutablePointer<Int>) { _ = sysctlbyname(\"kern.procargs2\", b, n, nil, 0) }\n")),
    ("a child's environment read back", "launch-input", KIT, append(KIT, "func e(p: Process) -> [String: String]? { p.environment }\n")),
    # launch inputs: home as Foundation finds it (CFFIXED_USER_HOME)
    ("NSHomeDirectory", "launch-input", KIT, append(KIT, "let h = NSHomeDirectory()\n")),
    ("NSHomeDirectoryForUser", "launch-input", KIT, append(KIT, "let h = NSHomeDirectoryForUser(\"x\")\n")),
    ("homeDirectoryForCurrentUser", "launch-input", KIT, append(KIT, "let h = FileManager.default.homeDirectoryForCurrentUser\n")),
    ("homeDirectory(forUser:)", "launch-input", KIT, append(KIT, "let h = FileManager.default.homeDirectory(forUser: \"x\")\n")),
    ("URL.homeDirectory", "launch-input", KIT, append(KIT, "let h = URL.homeDirectory\n")),
    ("URL.applicationSupportDirectory", "launch-input", KIT, append(KIT, "let h = URL.applicationSupportDirectory\n")),
    ("urls(for:in:)", "launch-input", KIT, append(KIT, "func u(d: FileManager.SearchPathDirectory, m: FileManager.SearchPathDomainMask) -> [URL] { FileManager.default.urls(for: d, in: m) }\n")),
    ("url(for:in:...)", "launch-input", KIT, append(KIT, "func u(d: FileManager.SearchPathDirectory, m: FileManager.SearchPathDomainMask) throws -> URL { try FileManager.default.url(for: d, in: m, appropriateFor: nil, create: false) }\n")),
    ("user domain mask", "launch-input", KIT, append(KIT, "let m: FileManager.SearchPathDomainMask = .userDomainMask\n")),
    ("search path function", "launch-input", KIT, append(KIT, "func s(d: FileManager.SearchPathDirectory, m: FileManager.SearchPathDomainMask) -> [String] { NSSearchPathForDirectoriesInDomains(d, m, true) }\n")),
    ("CFCopyHomeDirectoryURL", "launch-input", KIT, append(KIT, "let h = CFCopyHomeDirectoryURL()\n")),
    ("group container", "launch-input", KIT, append(KIT, "let g = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: \"g\")\n")),
    ("tilde expansion", "launch-input", KIT, append(KIT, "func t(s: String) -> String { (s as NSString).expandingTildeInPath }\n")),
    ("tilde abbreviation", "launch-input", KIT, append(KIT, "func t(s: String) -> String { (s as NSString).abbreviatingWithTildeInPath }\n")),
    ("standardizing a path", "launch-input", KIT, append(KIT, "func t(s: String) -> String { (s as NSString).standardizingPath }\n")),
    ("resolving links", "launch-input", KIT, append(KIT, "func t(u: URL) -> URL { u.resolvingSymlinksInPath() }\n")),
    ("a standardized URL", "launch-input", KIT, append(KIT, "func t(u: URL) -> URL { u.standardized }\n")),
    ("a tilde path", "launch-input", KIT, append(KIT, "let r = URL(fileURLWithPath: \"~/Library/Application Support/EnvCloak/run\")\n")),
    ("an escaped tilde path", "launch-input", KIT, append(KIT, "let r = URL(fileURLWithPath: \"\\u{7E}/Library\")\n")),
    ("a tilde path in a raw string", "launch-input", KIT, append(KIT, "let r = URL(fileURLWithPath: #\"\\#u{7E}/Library\"#)\n")),
    ("an indented tilde path in a multi-line literal", "launch-input", KIT, append(KIT, "let r = \"\"\"\n    ~/Library\n    \"\"\"\n")),
    ("a tilde path after a line continuation", "launch-input", KIT, append(KIT, "let r = \"\"\"\n    \\\n    ~/Library\n    \"\"\"\n")),
    ("an escaped sysctl name", "launch-input", KIT, append(KIT, "let n = \"kern.proc\\u{61}rgs2\"\n")),
    # launch inputs: working directory
    ("the working directory", "launch-input", KIT, append(KIT, "let d = FileManager.default.currentDirectoryPath\n")),
    ("getcwd", "launch-input", KIT, append(KIT, "let d = getcwd(nil, 0)\n")),
    # side doors and gated keys
    ("app intents", "side-door", APP, replace(APP, "import SwiftUI\n", "import SwiftUI\nimport AppIntents\n")),
    ("open url", "side-door", VIEW, in_view(".onOpenURL { _ in }")),
    ("external events", "side-door", APP, replace(APP, "Window(\"Demo\", id: \"main\") { View() }", "Window(\"Demo\", id: \"main\") { View() }.handlesExternalEvents(matching: [])")),
    ("apple events", "side-door", KIT, append(KIT, "func h() { NSAppleEventManager.shared().setEventHandler(nil, andSelector: Selector((\"x\")), forEventClass: 0, andEventID: 0) }\n")),
    ("delegate open", "side-door", KIT, append(KIT, "final class D { func application(_ a: AnyObject, open urls: [URL]) {} }\n")),
    ("user activity", "side-door", VIEW, in_view(".onContinueUserActivity(\"x\") { _ in }")),
    ("accessibility action", "a11y-action", VIEW, replace(VIEW, "            Divider()", "            Text(\"x\").accessibilityAction(named: \"Approve\") {}\n            Divider()")),
    ("approve on a key", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button(\"Approve with Touch ID\") {}")),
    ("reveal on a key, title in the label", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button { } label: { Text(\"Reveal\") }")),
    ("remove on a key press", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Button(\"Remove key\") {}\n                .padding(2)\n                .onKeyPress(.delete) { .handled }")),
    ("approve on a key, named by its action", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button(title) { approve() }")),
    ("an icon button that reveals on a key", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}", "            Button(action: revealValue) { Image(systemName: \"eye\") }")),
    ("approve on submit", "gated-key", VIEW, replace(VIEW, ".onSubmit { search() }", ".onSubmit { approveRequest() }")),
    ("Return as an AppKit key equivalent", "gated-key", KIT, append(KIT, "import AppKit\nfunc b(x: NSButton) { x.keyEquivalent = \"\\r\" }\n")),
    ("Return as a menu item's key equivalent", "gated-key", KIT, append(KIT, "import AppKit\nlet i = NSMenuItem(title: \"Go\", action: nil, keyEquivalent: \"\\u{0D}\")\n")),
    # A shortcut is in SwiftUI's environment: it reaches every button in
    # the view it is set on (measured: Return fired the inner Approve).
    ("a shortcut on a stack holding an Approve button", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            VStack { Button(\"Approve\") { approve() } }\n                .keyboardShortcut(.defaultAction)")),
    ("a shortcut on a wrapper view", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Wrapper()\n                .keyboardShortcut(\"k\", modifiers: [])")),
    ("a shortcut on a group holding a Reveal button", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Group { Button(\"Reveal\") {} }\n                .keyboardShortcut(\"r\")")),
    ("a shortcut after a modifier that adds a button", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Button(\"Open\") {}\n                .background(Button(\"Approve\") {})\n                .keyboardShortcut(.defaultAction)")),
    ("a shortcut on a button whose label is a view of its own", "gated-key", VIEW, replace(VIEW, "            Button(\"Open\") {}\n                .keyboardShortcut(.defaultAction)", "            Button(action: open) { Panel() }\n                .keyboardShortcut(.defaultAction)")),
    ("remove on the Delete command", "gated-key", VIEW, in_view(".onDeleteCommand { removeSelected() }")),
    ("approve through a command selector", "gated-key", VIEW, in_view(".onCommand(#selector(approveRequest)) {}")),
    ("approve in a key monitor", "gated-key", KIT, append(KIT, "let m = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { e in approveRequest(); return e }\n")),
    ("reveal in a keyDown override", "gated-key", KIT, append(KIT, "final class V: NSView { override func keyDown(with event: NSEvent) { revealValue() } }\n")),
    ("a menu item bound to a key", "gated-key", KIT, append(KIT, "let i = NSMenuItem(title: \"Approve\", action: nil, keyEquivalent: \"a\")\n")),
    ("Return as a key equivalent in parentheses", "gated-key", KIT, append(KIT, "func b(x: NSButton) { x.keyEquivalent = (\"\\r\") }\n")),
    # The system binds an alert's and a dialog's buttons to keys (measured:
    # Return fired the first button without a role, the cancel role answers
    # Escape, and a destructive button answers neither).
    ("Approve first in an alert", "gated-key", VIEW, in_view('.alert("Request", isPresented: .constant(true)) { Button("Approve") {}; Button("Cancel", role: .cancel) {} }')),
    ("Approve as an alert button's label", "gated-key", VIEW, in_view('.alert("Request", isPresented: .constant(true)) { Button {} label: { Text("Approve") } }')),
    ("a plain Remove in a confirmation dialog", "gated-key", VIEW, in_view('.confirmationDialog("Key", isPresented: .constant(true)) { Button("Remove") {}; Button("Cancel", role: .cancel) {} }')),
    ("Remove as an alert's cancel button", "gated-key", VIEW, in_view('.alert("Key", isPresented: .constant(true)) { Button("Remove", role: .cancel) {} }')),
    ("Reveal in an alert's actions argument", "gated-key", VIEW, in_view('.alert("Key", isPresented: .constant(true), actions: { Button("Reveal") {} }, message: { Text("m") })')),
    ("a gated view in an alert's actions", "gated-key", VIEW, in_view('.alert("Key", isPresented: .constant(true)) { ApproveButton() }')),
    ("Approve as a deprecated Alert's default button", "gated-key", VIEW, in_view('.alert(isPresented: .constant(true)) { Alert(title: Text("Request"), primaryButton: .default(Text("Approve")), secondaryButton: .cancel()) }')),
    ("Approve as an NSAlert button", "gated-key", KIT, append(KIT, 'func ask(a: NSAlert) { a.addButton(withTitle: "Approve") }\n')),
    ("an NSAlert button retitled Reveal", "gated-key", KIT, append(KIT, 'func ask(a: NSAlert) { a.buttons[0].title = "Reveal" }\n')),
    ("a window's default button", "gated-key", KIT, append(KIT, "func set(w: NSWindow, c: NSButtonCell) { w.defaultButtonCell = c }\n")),
    ("Replace as a file dialog's confirming label", "gated-key", VIEW, in_view('.fileDialogConfirmationLabel("Replace")')),
    ("Approve as a panel's prompt", "gated-key", KIT, append(KIT, 'func ask(p: NSSavePanel) { p.prompt = "Approve" }\n')),
    ("zoom action", "a11y-action", VIEW, in_view(".accessibilityZoomAction { _ in }")),
    ("an AppKit accessibility override", "a11y-action", KIT, append(KIT, "import AppKit\nfinal class B: NSButton { override func accessibilityPerformPress() -> Bool { true } }\n")),
    # log: other writers
    ("print", "log", KIT, append(KIT, "func p() { print(\"x\") }\n")),
    ("a function named like a writer", "log", KIT, append(KIT, "func print<T>(_ x: T) {}\n")),
    ("a log call with no message", "log", KIT, append(KIT, "func l(x: Logger) { x.info() }\n")),
    ("a log call whose message is labelled", "log", KIT, append(KIT, "func l(x: Logger) { x.error(note: \"stopped\") }\n")),
    ("a Logger without subsystem and category", "log", TOKEN_FILE, replace(TOKEN_FILE, 'Logger(subsystem: "ai.envcloak.app", category: "fixed")', "Logger()")),
    ("a token enum of plain cases", "log", KIT, append(KIT, "enum Moment: LogToken { case started }\n")),
    ("a token enum without a body", "log", KIT, append(KIT, "enum Moment: String, LogToken;\n")),
    ("a colour from an implicit member", "color", VIEW, replace(VIEW, "Divider().background(Color.clear)", "Divider().background(Color(.brandRed))")),
    ("swift print", "log", KIT, append(KIT, "func p() { Swift.print(\"x\") }\n")),
    ("module-qualified puts", "log", KIT, append(KIT, "func p() { Darwin.puts(\"x\") }\n")),
    ("module-qualified NSLog", "log", KIT, append(KIT, "func p() { Foundation.NSLog(\"x\") }\n")),
    ("debugPrint", "log", KIT, append(KIT, "func p(x: Int) { debugPrint(x) }\n")),
    ("dump", "log", KIT, append(KIT, "func p(x: Int) { dump(x) }\n")),
    ("NSLog", "log", KIT, append(KIT, "func p() { NSLog(\"x\") }\n")),
    ("err(3)", "log", KIT, append(KIT, "func p() { warnx(\"x\") }\n")),
    ("syslog", "log", KIT, append(KIT, "func p() { withVaList([]) { vsyslog(3, \"x\", $0) } }\n")),
    ("standard error", "log", KIT, append(KIT, "func p() { FileHandle.standardError.write(Data()) }\n")),
    ("standard error as an implicit member", "log", KIT, append(KIT, "let h: FileHandle = .standardError\n")),
    ("a child given the app's standard error", "log", KIT, append(KIT, "func c(p: Process) { p.standardError = FileHandle.standardError }\n")),
    ("standard error by descriptor", "log", KIT, append(KIT, "func p() { FileHandle(fileDescriptor: 2).write(Data()) }\n")),
    ("standard output by descriptor, through init", "log", KIT, append(KIT, "let h = FileHandle.init(fileDescriptor: 1)\n")),
    # Descriptors computed from literals, and the other calls that take one.
    ("standard error by a computed descriptor", "log", KIT, append(KIT, "func w() { _ = FileHandle(fileDescriptor: 1 + 1) }\n")),
    ("standard error by a negated descriptor", "log", KIT, append(KIT, "func w() { _ = FileHandle(fileDescriptor: -(-2)) }\n")),
    ("standard error by an exact conversion", "log", KIT, append(KIT, "func w() { _ = FileHandle(fileDescriptor: Int32(exactly: 2)!) }\n")),
    ("standard error through DispatchIO.write", "log", KIT, append(KIT, "func w() { DispatchIO.write(toFileDescriptor: 2, data: .empty, runningHandlerOn: .main) { _, _ in } }\n")),
    ("standard input through DispatchIO.read", "launch-input", KIT, append(KIT, "func r() { DispatchIO.read(fromFileDescriptor: 0, maxLength: 1, runningHandlerOn: .main) { _, _ in } }\n")),
    ("the terminal of standard input", "launch-input", KIT, append(KIT, "func t() { _ = ttyname(0) }\n")),
    ("standard error replaced through dup2", "log", KIT, append(KIT, "func d() { _ = dup2(3, 2) }\n")),
    ("standard input mapped", "launch-input", KIT, append(KIT, "func m() { _ = mmap(nil, 1, PROT_READ, MAP_PRIVATE, 0, 0) }\n")),
    ("a write to descriptor 2", "log", KIT, append(KIT, "func p(b: UnsafeRawPointer) { _ = write(2, b, 1) }\n")),
    ("a write to standard error by name", "log", KIT, append(KIT, "func p(b: UnsafeRawPointer) { _ = Darwin.write(STDERR_FILENO, b, 1) }\n")),
    ("C standard output", "log", KIT, append(KIT, "func p() { fflush(stdout) }\n")),
    ("C standard output, module-qualified", "log", KIT, append(KIT, "func p() { fflush(Darwin.stdout) }\n")),
    ("standard error by a converted descriptor", "log", KIT, append(KIT, "let h = FileHandle(fileDescriptor: Int32(2))\n")),
    ("standard error by path", "log", KIT, append(KIT, "let h = FileHandle(forWritingAtPath: \"/dev/stderr\")\n")),
    ("standard output through a URL", "log", KIT, append(KIT, "func w(d: Data) throws { try d.write(to: URL(fileURLWithPath: \"/dev/stdout\")) }\n")),
    ("fopen of standard error", "log", KIT, append(KIT, "let f = fopen(\"/dev/stderr\", \"w\")\n")),
    ("descriptor 2 by path", "log", KIT, append(KIT, "let f = fopen(\"/dev/fd/2\", \"w\")\n")),
    ("the terminal by path", "log", KIT, append(KIT, "let f = fopen(\"/dev/tty\", \"w\")\n")),
    ("CFShow", "log", KIT, append(KIT, "func p(x: CFTypeRef) { CFShow(x) }\n")),
    # The same streams in other spellings: the number in any base, through
    # conversions, casts and System's FileDescriptor; the path as the
    # kernel reads it and the literal as the compiler reads it.
    ("standard error through System's FileDescriptor", "log", STREAM, write(STREAM, "import System\nlet d = FileDescriptor(rawValue: 2)\n")),
    ("standard error through an implicit FileDescriptor init", "log", STREAM, write(STREAM, "import System\nlet d: FileDescriptor = .init(rawValue: 2)\n")),
    ("standard error by a hexadecimal descriptor", "log", KIT, append(KIT, "let h = FileHandle(fileDescriptor: 0x2)\n")),
    ("standard output by a converted, labelled descriptor", "log", KIT, append(KIT, "let h = FileHandle(fileDescriptor: CInt(truncatingIfNeeded: 0b1))\n")),
    ("standard error by a cast descriptor", "log", KIT, append(KIT, "let h = FileHandle(fileDescriptor: 2 as Int32)\n")),
    ("standard input through a dispatch source", "launch-input", KIT, append(KIT, "let s = DispatchSource.makeReadSource(fileDescriptor: 0, queue: .main)\n")),
    ("a child handed the app's standard error", "log", KIT, append(KIT, "func a(f: inout posix_spawn_file_actions_t) { posix_spawn_file_actions_adddup2(&f, 2, 2) }\n")),
    ("standard error by a path with a doubled slash", "log", KIT, append(KIT, "let h = FileHandle(forWritingAtPath: \"/dev//stderr\")\n")),
    ("descriptor 2 by a path with a dot segment", "log", KIT, append(KIT, "let h = FileHandle(forWritingAtPath: \"/dev/./fd/2\")\n")),
    ("standard error by a capitalised path", "log", KIT, append(KIT, "let h = FileHandle(forWritingAtPath: \"/DEV/stderr\")\n")),
    ("standard error by an escaped path", "log", KIT, append(KIT, "let h = FileHandle(forWritingAtPath: \"/dev/std\\u{65}rr\")\n")),
    ("standard error through a file URL", "log", KIT, append(KIT, "let u = URL(string: \"file:///dev/stderr\")\n")),
    ("standard error in a multi-line literal", "log", KIT, append(KIT, "let p = \"\"\"\n    /dev/std\\\n    err\n    \"\"\"\n")),
    ("a device path completed at run time", "log", KIT, append(KIT, "func p(s: String) -> String { \"/dev/\" + s }\n")),
    ("the system log facility", "log", KIT, append(KIT, "func p() { withVaList([]) { asl_vlog(nil, nil, 3, \"x\", $0) } }\n")),
    ("an NSException reason", "log", KIT, append(KIT, "func x(s: String) -> NSException { NSException(name: .genericException, reason: s, userInfo: nil) }\n")),
    ("raise with a format", "log", KIT, append(KIT, "func x(s: String) { withVaList([s]) { NSException.raise(.genericException, format: \"%@\", arguments: $0) } }\n")),
    ("print in an interpolation", "log", KIT, append(KIT, "let s = \"\\(print(\"x\"))\"\n")),
    # log: other log APIs
    ("os_log", "log", KIT, append(KIT, "import os\nfunc p(v: String) { os_log(\"x \\(v)\") }\n")),
    ("os_log with format arguments", "log", KIT, append(KIT, "import os\nfunc p(v: String) { os_log(\"%@\", v) }\n")),
    ("os_log with a type and format arguments", "log", KIT, append(KIT, "import os\nfunc p(v: String) { os_log(\"%{private}@\", log: .default, type: .info, v) }\n")),
    ("os_signpost", "log", KIT, append(KIT, "import os\nfunc p(l: OSLog, v: String) { os_signpost(.event, log: l, name: \"n\", \"%@\", v) }\n")),
    ("OSSignposter", "log", KIT, append(KIT, "import os\nlet s = OSSignposter()\n")),
    ("an OSLog object", "log", KIT, append(KIT, "import os\nlet l = OSLog(subsystem: \"x\", category: \"y\")\n")),
    ("a message built away from its call", "log", KIT, append(KIT, "import os\nfunc m(name: String) -> OSLogMessage { \"x \\(name)\" }\n")),
    ("a log message that is not a literal", "log", APP, append(APP, "func m(s: String) { ECLog.logger(.app).info(s) }\n")),
    ("a log message after level: that is not a literal", "log", APP, append(APP, "func m(s: String) { ECLog.logger(.app).log(level: .info, s) }\n")),
    # log: the message
    ("a value in a log message", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.logToken, privacy: .public) \\(Secret.value)")),
    ("a public value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.rawValue, privacy: .public)")),
    ("a private value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.rawValue)")),
    ("public privacy outside a log call", "log", KIT, append(KIT, "func m(name: String) -> String { \"x \\(name, privacy: .public)\" }\n")),
    ("public format", "log", KIT, append(KIT, "let f = \"%{public}s\"\n")),
    ("an escaped public format", "log", KIT, append(KIT, "let f = \"%{p\\u{75}blic}s\"\n")),
    # The token whole: nothing joined to it, chosen against it, or around it.
    ("a token joined to a value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(AppEvent.launched.logToken + Secret.value, privacy: .public)")),
    ("a token or a value", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(flag ? Secret.value : AppEvent.launched.logToken, privacy: .public)")),
    ("a value or a token", "log", APP, replace(APP, "\\(AppEvent.launched.logToken, privacy: .public)", "\\(Secret.value ?? AppEvent.launched.logToken)")),
    # The log's metadata: only ECLog builds a Logger, from fixed words.
    ("a Logger built in the app", "log", APP, append(APP, "import os\nlet extra = Logger(subsystem: \"ai.envcloak.app\", category: \"x\")\n")),
    ("a Logger built by an implicit init", "log", KIT, append(KIT, "import os\nlet l: Logger = .init(subsystem: \"a\", category: \"b\")\n")),
    # Traps that print a value (measured).
    ("an error printed by try!", "log", KIT, append(KIT, "func t() { _ = try! JSONSerialization.data(withJSONObject: [:]) }\n")),
    ("a duplicate key printed by a dictionary", "log", KIT, append(KIT, "func d(k: String) -> [String: Int] { Dictionary(uniqueKeysWithValues: [(k, 1)]) }\n")),
    # The type by another name.
    ("a Logger's metatype", "log", KIT, append(KIT, "import os\nlet loggerType: Logger.Type = Logger.self\n")),
    ("a typealias for Logger", "log", KIT, append(KIT, "import os\ntypealias AppLog = os.Logger\n")),
    ("an init given a subsystem on another receiver", "log", KIT, append(KIT, "import os\nfunc mk(s: String) { _ = type(of: ECLog.logger(.app)).init(subsystem: s, category: s) }\n")),
    ("a run-time subsystem", "log", TOKEN_FILE, replace(TOKEN_FILE, "Logger(subsystem: subsystem,", "Logger(subsystem: NSUserName(),")),
    ("a run-time category", "log", TOKEN_FILE, replace(TOKEN_FILE, "category: category.rawValue)", "category: ProcessInfo.processInfo.hostName)")),
    ("a category of a type not declared there", "log", TOKEN_FILE, replace(TOKEN_FILE, "_ category: ECLogCategory", "_ category: Wordy")),
    ("a subsystem bound twice", "log", TOKEN_FILE, replace(TOKEN_FILE, "        Logger(subsystem: subsystem, category: category.rawValue)", "        let subsystem = NSUserName()\n        return Logger(subsystem: subsystem, category: category.rawValue)")),
    ("an NSException name from a value", "log", KIT, append(KIT, "func x(s: String) -> NSException { NSException(name: NSExceptionName(s), reason: \"r\", userInfo: nil) }\n")),
    ("a value in fatalError", "log", APP, replace(APP, "fatalError(\"stopped \\(AppEvent.third.logToken)\")", "fatalError(\"stopped \\(total)\")")),
    ("a message variable in fatalError", "log", APP, replace(APP, "fatalError(\"stopped \\(AppEvent.third.logToken)\")", "fatalError(reason)")),
    ("a value in precondition", "log", KIT, replace(KIT, "precondition(n >= 0, \"negative count\")", "precondition(n >= 0, \"negative count \\(n)\")")),
    ("a value in assertionFailure", "log", KIT, append(KIT, "func a(n: Int) { assertionFailure(\"n \\(n)\") }\n")),
    # log: the token
    ("a struct token", "log", KIT, append(KIT, "struct Word: RawRepresentable, LogToken { var rawValue: String }\n")),
    ("an extension token", "log", KIT, append(KIT, "extension Client: LogToken {}\n")),
    ("a protocol refining the token", "log", KIT, append(KIT, "protocol Wordy: LogToken {}\n")),
    ("a second logToken", "log", KIT, append(KIT, "extension Client { var logToken: String { \"x\" } }\n")),
    # Measured: with no raw type, an enum of plain cases takes its rawValue
    # from another protocol's extension, here the user's name.
    ("a token enum without a raw type", "log", KIT, append(KIT, "protocol Raw {}\nextension Raw { var rawValue: String { NSUserName() }\n  init?(rawValue: String) { nil } }\nenum Leak: Raw, LogToken { case a }\n")),
    ("a token enum whose body writes rawValue and init", "log", KIT, append(KIT, "enum Leak: String, LogToken { case a\n  init?(rawValue: String) { nil } }\n")),
    ("a token enum that writes its own rawValue", "log", KIT, append(KIT, "nonisolated(unsafe) var leaked = \"\"\nenum Leak: String, LogToken { case a\n  var rawValue: String { leaked } }\n")),
    ("a token enum with an associated value", "log", KIT, append(KIT, "enum Leak: String, LogToken { case a(String) }\n")),
    ("a token enum's rawValue in another file's extension", "log", VIEW, both(
        append(KIT, "public enum Leak: String, LogToken { case a }\n"),
        append(VIEW, "nonisolated(unsafe) var leaked = \"\"\nextension Leak { var rawValue: String { leaked } }\n"),
    )),
    ("a token enum's init in an extension", "log", KIT, append(KIT, "enum Leak: String, LogToken { case a }\nextension Leak { init?(rawValue: String) { self = .a } }\n")),
    ("an extension of LogToken", "log", KIT, append(KIT, "extension LogToken { var shown: String { rawValue } }\n")),
    ("a typealias for the token", "log", KIT, append(KIT, "typealias Word = LogToken\n")),
    ("dynamic member lookup", "log", KIT, append(KIT, "@dynamicMemberLookup struct Any2 { subscript(dynamicMember m: String) -> String { m } }\n")),
    # Measured (Swift 6, Xcode 26.6): each of these made `.logToken` print
    # run-time data before the rule took the members whatever the type.
    ("rawValue from an extension of RawRepresentable", "log", VIEW, both(
        append(KIT, "public enum Leak: String, LogToken { case a }\n"),
        append(VIEW, "nonisolated(unsafe) var leaked = \"\"\nextension RawRepresentable where Self: LogToken { var rawValue: String { leaked } }\n"),
    )),
    ("rawValue from an extension pinned to one enum", "log", VIEW, both(
        append(KIT, "public enum Leak: String, LogToken { case a }\n"),
        append(VIEW, "nonisolated(unsafe) var leaked = \"\"\nextension RawRepresentable where Self == Leak { var rawValue: String { leaked } }\n"),
    )),
    ("rawValue through a typealias", "log", VIEW, both(
        append(KIT, "public enum Leak: String, LogToken { case a }\n"),
        append(VIEW, "nonisolated(unsafe) var leaked = \"\"\ntypealias Ev = Leak\nextension Ev { var rawValue: String { leaked } }\n"),
    )),
    ("init(rawValue:) in any extension", "log", KIT, append(KIT, "extension Outcome { init?(rawValue: String) { nil } }\n")),
    ("an init in a token enum's extension through a typealias", "log", VIEW, both(
        append(KIT, "public enum Leak: String, LogToken { case a }\n"),
        append(VIEW, "typealias L = Leak\nextension L { init(x: Int) { self = .a } }\n"),
    )),
    ("an extension constrained to LogToken", "log", KIT, append(KIT, "extension Sendable where Self: LogToken { var shown: Int { 0 } }\n")),
    ("a member in a token enum's extension", "log", KIT, append(KIT, "enum Leak: String, LogToken { case a }\nextension Leak { var shown: String { \"x\" } }\n")),
    ("a tuple labelled logToken", "log", APP, append(APP, "func m(s: String) { ECLog.logger(.app).notice(\"\\((logToken: s, n: 0).logToken, privacy: .public)\") }\n")),
    ("a parameter named logToken", "log", KIT, append(KIT, "func f(logToken: String) {}\n")),
    ("a String of its own", "log", KIT, append(KIT, "struct String {}\n")),
    ("a typealias named String", "log", KIT, append(KIT, "typealias String = Substring\n")),
    ("a LogToken of its own", "log", VIEW, append(VIEW, "protocol LogToken {}\n")),
    # indirect calls
    ("silgen name", "indirect", KIT, append(KIT, "@_silgen_name(\"puts\") func say(_ s: UnsafePointer<CChar>) -> Int32\n")),
    ("extern", "indirect", KIT, append(KIT, "@_extern(c, \"getenv\") func look(_ n: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?\n")),
    ("dlsym", "indirect", KIT, append(KIT, "let f = dlsym(UnsafeMutableRawPointer(bitPattern: -2), \"getenv\")\n")),
    ("a class by name", "indirect", KIT, append(KIT, "let c: AnyClass? = NSClassFromString(\"NSProcessInfo\")\n")),
    ("a selector from a string", "indirect", KIT, append(KIT, "let s = Selector(\"environment\")\n")),
    ("key-value coding", "indirect", KIT, append(KIT, "let e = ProcessInfo.processInfo.value(forKey: \"environment\")\n")),
    # daemon text
    ("raw daemon text", "daemon-text", VIEW, replace(VIEW, "Text(\"Open the folder\")", "Text(item.title.unescaped)")),
    # colour
    ("component colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(red: 1, green: 0, blue: 0))")),
    ("colour space colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(.sRGB, red: 1, green: 0, blue: 0))")),
    ("init colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color.init(white: 0.5))")),
    ("init colour with a colour space", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color.init(.sRGB, red: 1, green: 0, blue: 0))")),
    ("implicit init with components", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(.init(red: 1, green: 0, blue: 0))")),
    ("a resolved colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(Color.Resolved(red: 1, green: 0, blue: 0)))")),
    ("white after a colour space by its type", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(Color.RGBColorSpace.sRGB, white: 0.5, opacity: 1))")),
    ("a module-qualified colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(SwiftUI.Color(white: 0.5))")),
    ("AppKit colour", "color", KIT, append(KIT, "import AppKit\nlet c = NSColor(calibratedRed: 1, green: 0, blue: 0, alpha: 1)\n")),
    ("colour literal", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(#colorLiteral(red: 1, green: 0, blue: 0, alpha: 1)))")),
    ("system colour", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color.red)")),
    ("implicit system colour", "color", VIEW, replace(VIEW, ".foregroundStyle(.secondary)", ".foregroundStyle(.blue)")),
    ("system NSColor", "color", KIT, append(KIT, "import AppKit\nlet c = NSColor.systemRed\n")),
    ("CGColor", "color", KIT, append(KIT, "import CoreGraphics\nlet c = CGColor(gray: 0.5, alpha: 1)\n")),
    ("catalog colour outside the design package", "color", VIEW, replace(VIEW, ".foregroundStyle(ECToken.text.color)", ".foregroundStyle(Color(\"background\", bundle: .main))")),
    # the lexer
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
    ("a key set by a build setting", "side-door", PBXPROJ, in_pbxproj("INFOPLIST_KEY_NSServices = x;")),
    # Keys as each format's own grammar reads them.
    ("an escaped key in the project", "side-door", PBXPROJ, in_pbxproj("EC09 = {isa = XCBuildConfiguration; buildSettings = {\"INFOPLIST_KEY_\\U004eSServices\" = x; }; };")),
    ("an escaped key in a strings file", "side-door", "apps/macos/Support/InfoPlist.strings", write("apps/macos/Support/InfoPlist.strings", "\"\\U004eSServices\" = \"x\";\n")),
    ("LSEnvironment in a strings file", "launch-input", "apps/macos/Support/InfoPlist.strings", write("apps/macos/Support/InfoPlist.strings", "\"LSEnvironment\" = \"x\";\n")),
    ("a provider file that does not parse", "key-literal", "providers/zz-broken.toml", write("providers/zz-broken.toml", "key_patterns = [\n")),
    ("a provider pattern that does not compile", "key-literal", "providers/zz-broken.toml", write("providers/zz-broken.toml", "key_patterns = [\"(unclosed\"]\n")),
    ("a malformed rule allowlist entry", "allowlist", RULES, write(RULES, "launch-input  # a reason without a path\n")),
    ("a malformed expose allowlist entry", "allowlist", EXPOSE, write(EXPOSE, "one two  # two paths\n")),
    ("a link to a brand directory", "symlink", "apps/macos/brand-motion", link("apps/macos/brand-motion", "../../assets/brand/motion")),
    ("a product Swift file that is not text", "lex", "apps/macos/EnvCloak/Features/Binary.swift", write_bytes("apps/macos/EnvCloak/Features/Binary.swift", b"struct B {}\n\0\n")),
    ("a key in a scheme through a character reference", "side-door", SCHEME, replace(SCHEME, "<LaunchAction", "<EnvironmentVariable key = \"&#67;FBundleURLTypes\"/>\n   <LaunchAction")),
    ("an escaped key in JSON", "side-door", ASSET_JSON, write(ASSET_JSON, "{\"\\u0043FBundleURLTypes\": []}\n")),
    ("JSON that does not parse", "unreadable", ASSET_JSON, write(ASSET_JSON, "{\"info\": \n")),
    ("a key built from a build setting", "side-door", INFO, replace(INFO, "</dict>", "\t<key>$(EXTRA_KEY)</key>\n\t<array/>\n</dict>")),
    # Settings that build an Info.plist, entitlements or settings other
    # than the files this check reads.
    ("a preprocessed Info.plist", "side-door", XCCONFIG, append(XCCONFIG, "INFOPLIST_PREPROCESS = YES\n")),
    ("Info.plist macros", "side-door", PBXPROJ, in_pbxproj("EC09 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_PREPROCESSOR_DEFINITIONS = \"KEY=X\"; }; };")),
    ("an Info.plist from outside the tree", "side-door", XCCONFIG, append(XCCONFIG, "INFOPLIST_FILE = ../../Other/Info.plist\n")),
    ("an Info.plist named through a setting", "side-door", PBXPROJ, in_pbxproj("EC09 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_FILE = \"$(OTHER)/Info.plist\"; }; };")),
    ("entitlements from outside the tree", "entitlement", XCCONFIG, append(XCCONFIG, "CODE_SIGN_ENTITLEMENTS = /tmp/x.entitlements\n")),
    ("settings included from outside the tree", "linked-code", XCCONFIG, append(XCCONFIG, "#include \"../../../shared.xcconfig\"\n")),
    ("an environment in Info.plist", "launch-input", INFO, replace(INFO, "</dict>", "\t<key>LSEnvironment</key>\n\t<dict/>\n</dict>")),
    ("get-task-allow", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>com.apple.security.get-task-allow</key>\n\t<true/>\n")),
    ("a runtime exception", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>com.apple.security.cs.allow-jit</key>\n\t<true/>\n")),
    ("an entitlement no tier signs", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>com.apple.security.network.client</key>\n\t<true/>\n")),
    ("entitlements that do not parse", "entitlement", ENTITLEMENTS, replace(ENTITLEMENTS, "<dict>\n", "<dict>\n\t<key>open\n")),
    # Property lists in every form plistlib reads, under any name.
    ("a binary Info.plist", "side-door", "apps/macos/Support/Extra.plist", write_bytes("apps/macos/Support/Extra.plist", plistlib.dumps({"CFBundleURLTypes": []}, fmt=plistlib.FMT_BINARY))),
    ("a UTF-16 Info.plist", "side-door", INFO, write_bytes(INFO, (PLIST % "\t<key>CFBundleURLTypes</key>\n\t<array/>\n").replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16"))),
    ("a key nested in a property list", "side-door", INFO, replace(INFO, "</dict>", "\t<key>Extra</key>\n\t<dict><key>NSServices</key><array/></dict>\n</dict>")),
    ("an Info.plist under another name", "side-door", "apps/macos/Support/Extra-Info.xml", write("apps/macos/Support/Extra-Info.xml", PLIST % "\t<key>CFBundleURLTypes</key>\n\t<array/>\n")),
    ("a binary entitlements file", "entitlement", ENTITLEMENTS, write_bytes(ENTITLEMENTS, plistlib.dumps({"com.apple.security.get-task-allow": True}, fmt=plistlib.FMT_BINARY))),
    ("a property list that does not parse", "unreadable", INFO, replace(INFO, "<dict>\n", "<dict>\n\t<key>open\n")),
    ("a binary property list that does not parse", "unreadable", "apps/macos/Support/Extra.plist", write_bytes("apps/macos/Support/Extra.plist", b"bplist00" + bytes(8))),
    ("a settings file that is not text", "unreadable", XCCONFIG, write_bytes(XCCONFIG, b"SWIFT_VERSION = 6.0\0\n")),
    ("a UTF-16 build setting", "linked-code", XCCONFIG, write_bytes(XCCONFIG, "OTHER_LDFLAGS = -lanalytics\n".encode("utf-16"))),
    # packages from outside the tree
    ("a remote package", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(url: "https://example.invalid/sdk.git", from: "1.0.0")')),
    ("a registry package", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(id: "example.sdk", from: "1.0.0")')),
    ("a package path outside the packages", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(path: "../../../../vendor/sdk")')),
    ("an absolute package path", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(path: "/opt/sdk")')),
    # Read as its value: the source text `\u{2E}\u{2E}/../../Elsewhere`
    # stays inside the packages, the value `../../../Elsewhere` does not.
    ("an escaped package path outside the packages", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(path: "\\u{2E}\\u{2E}/../../Elsewhere")')),
    ("a package path built at run time", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(path: root + "/sdk")')),
    ("a package of no kind this check knows", "remote-package", MANIFEST, replace(MANIFEST, '.package(path: "../EnvCloakDesign")', '.package(name: "Analytics")')),
    ("a remote package in the project", "remote-package", PBXPROJ, replace(PBXPROJ, "XCLocalSwiftPackageReference", "XCRemoteSwiftPackageReference")),
    ("a local package outside the tree in the project", "remote-package", PBXPROJ, replace(PBXPROJ, "relativePath = Packages/EnvCloakKit;", "relativePath = ../../vendor/sdk;")),
    # code other than the Swift this check reads
    ("a remote binary target", "linked-code", MANIFEST, replace(MANIFEST, "targets: [", 'targets: [.binaryTarget(name: "SDK", url: "https://example.invalid/sdk.zip", checksum: "0"), ')),
    ("a local binary target", "linked-code", MANIFEST, replace(MANIFEST, "targets: [", 'targets: [.binaryTarget(name: "SDK", path: "SDK.xcframework"), ')),
    ("a system library target", "linked-code", MANIFEST, replace(MANIFEST, "targets: [", 'targets: [.systemLibrary(name: "Lib"), ')),
    ("unsafe flags", "linked-code", MANIFEST, in_manifest('linkerSettings: [.unsafeFlags(["-L/opt/lib"])]')),
    ("a linked library", "linked-code", MANIFEST, in_manifest('linkerSettings: [.linkedLibrary("analytics")]')),
    ("a linked framework", "linked-code", MANIFEST, in_manifest('linkerSettings: [.linkedFramework("Analytics")]')),
    ("a build plugin", "linked-code", MANIFEST, in_manifest('plugins: ["Gen"]')),
    ("a macro target", "linked-code", MANIFEST, replace(MANIFEST, "targets: [", 'targets: [.macro(name: "Gen"), ')),
    # Sources that compile into the app as something other than Swift.
    ("a C file in a package", "linked-code", KIT.replace("Client.swift", "shim.c"), write(KIT.replace("Client.swift", "shim.c"), "int shim(void) { return 0; }\n")),
    ("an Objective-C file in the app", "linked-code", "apps/macos/EnvCloak/App/Shim.m", write("apps/macos/EnvCloak/App/Shim.m", "#import <Foundation/Foundation.h>\n")),
    ("a header", "linked-code", "apps/macos/EnvCloak/App/Shim.h", write("apps/macos/EnvCloak/App/Shim.h", "int shim(void);\n")),
    ("a module map", "linked-code", "apps/macos/Packages/EnvCloakKit/Sources/CShim/include/module.modulemap", write("apps/macos/Packages/EnvCloakKit/Sources/CShim/include/module.modulemap", "module CShim {}\n")),
    ("assembly", "linked-code", "apps/macos/EnvCloak/App/start.S", write("apps/macos/EnvCloak/App/start.S", ".text\n")),
    ("a storyboard", "linked-code", "apps/macos/EnvCloak/App/Main.storyboard", write("apps/macos/EnvCloak/App/Main.storyboard", "<document/>\n")),
    ("a MIG definition", "linked-code", "apps/macos/EnvCloak/App/rpc.defs", write("apps/macos/EnvCloak/App/rpc.defs", "subsystem rpc 100;\n")),
    ("a DriverKit interface", "linked-code", "apps/macos/EnvCloak/App/Driver.iig", write("apps/macos/EnvCloak/App/Driver.iig", "class Driver;\n")),
    ("preprocessed C", "linked-code", "apps/macos/EnvCloak/App/shim.i", write("apps/macos/EnvCloak/App/shim.i", "int shim(void);\n")),
    ("preprocessed Objective-C++", "linked-code", "apps/macos/EnvCloak/App/shim.mii", write("apps/macos/EnvCloak/App/shim.mii", "int shim(void);\n")),
    ("AppleScript", "linked-code", "apps/macos/EnvCloak/App/Bridge.applescript", write("apps/macos/EnvCloak/App/Bridge.applescript", "script Bridge\nend script\n")),
    ("a data model", "linked-code", "apps/macos/EnvCloak/Model.xcdatamodeld/Model.xcdatamodel/contents", write("apps/macos/EnvCloak/Model.xcdatamodeld/Model.xcdatamodel/contents", "<model/>\n")),
    ("a script phase", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXShellScriptBuildPhase; shellScript = \"true\"; };")),
    ("a build rule", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXBuildRule; script = \"true\"; };")),
    ("a static library reference", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXFileReference; lastKnownFileType = archive.ar; path = libsdk.a; sourceTree = \"<group>\"; };")),
    ("a framework from outside the SDK", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXFileReference; lastKnownFileType = wrapper.xcframework; path = SDK.xcframework; sourceTree = SOURCE_ROOT; };")),
    ("an absolute reference", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXFileReference; lastKnownFileType = text; path = notes.txt; sourceTree = \"<absolute>\"; };")),
    ("a group outside the tree", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = PBXGroup; path = ../../../vendor; sourceTree = \"<group>\"; };")),
    ("linker flags in the project", "linked-code", PBXPROJ, in_pbxproj("EC09 = {isa = XCBuildConfiguration; buildSettings = {OTHER_LDFLAGS = \"-lanalytics\"; }; };")),
    ("library search paths in a configuration", "linked-code", XCCONFIG, append(XCCONFIG, "LIBRARY_SEARCH_PATHS[config=Release] = /opt/lib\n")),
    ("Swift flags in a configuration", "linked-code", XCCONFIG, append(XCCONFIG, "OTHER_SWIFT_FLAGS = -Xlinker -lanalytics\n")),
    ("a static library in the tree", "linked-code", "apps/macos/Vendor/libsdk.a", write("apps/macos/Vendor/libsdk.a", "not really\n")),
    ("a framework in the tree", "linked-code", "apps/macos/Vendor/SDK.framework/Info.plist", write("apps/macos/Vendor/SDK.framework/Info.plist", PLIST % "")),
    ("a Mach-O file in the tree", "linked-code", "apps/macos/Vendor/tool", write_bytes("apps/macos/Vendor/tool", b"\xcf\xfa\xed\xfe" + bytes(28))),
    # the tree
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
        self.write_bytes(rel, text.encode())

    def write_bytes(self, rel, data):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

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
        elif kind == "bytes":
            self.write_bytes(change[1], change[2])
        elif kind == "link":
            path = os.path.join(self.root, change[1])
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.symlink(change[2], path)
        elif kind == "both":
            for c in change[1]:
                self.apply(c)
        else:
            raise AssertionError("unknown fixture change %r" % kind)

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
        # The negative controls are in it: a rule that refuses one fails here.
        code, out = Tree(self.base).check()
        self.assertEqual(code, 0, out)
        self.assertIn("check-swift: ok (%d product Swift files" % PRODUCT_FILES, out)

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

    def test_a_missing_input_is_a_finding(self):
        # Each allowlist, the provider directory and its key patterns: a
        # missing one is a finding, never a skip.
        cases = (
            ("rule allowlist", ("allowlist", RULES)),
            ("expose allowlist", ("allowlist", EXPOSE)),
            ("provider directory", ("key-literal", "providers/")),
            ("provider patterns", ("key-literal", "providers/")),
        )
        for what, want in cases:
            with self.subTest(missing=what):
                tree = Tree(self.base)
                providers = os.path.join(tree.root, "providers")
                if what == "rule allowlist":
                    os.remove(os.path.join(tree.root, RULES))
                elif what == "expose allowlist":
                    os.remove(os.path.join(tree.root, EXPOSE))
                elif what == "provider directory":
                    shutil.rmtree(providers)
                else:
                    for name in os.listdir(providers):
                        os.remove(os.path.join(providers, name))
                    tree.write("providers/none.toml", 'name = "none"\n')
                code, out = tree.check()
                self.assertEqual(code, 1, "%s: passed\n%s" % (what, out))
                self.assertIn(want, self.findings(out), out)

    def test_views_cannot_reach_raw_metadata_helpers(self):
        for helper in ("path", "replaceTarget", "terminalCommand", "changeDirectoryCommand", "commandWords"):
            for spelling in ("MetadataRequest." + helper, "EnvCloak.MetadataRequest." + helper):
                for expression in (spelling + "(item.slug)", spelling):
                    with self.subTest(expression=expression):
                        tree = Tree(self.base)
                        tree.apply(replace(VIEW, 'Text("Open the folder")', "Text(" + expression + ")"))
                        code, out = tree.check()
                        self.assertEqual(code, 1, out)
                        self.assertIn(("daemon-text", VIEW), self.findings(out), out)

    def test_fixture_names_are_unique(self):
        names = [f[0] for f in SWIFT_REFUSALS + OTHER_REFUSALS]
        self.assertEqual(len(names), len(set(names)))

    def test_a_key_shaped_literal_fails_anywhere(self):
        for rel in (TEST, INFO, "apps/macos/notes.md", "apps/macos/blob.bin"):
            with self.subTest(file=rel):
                tree = Tree(self.base)
                if rel.endswith(".bin"):
                    # A file that is not text is read byte for byte.
                    tree.write_bytes(rel, b"\0\1" + key_shaped().encode() + b"\0")
                elif os.path.exists(os.path.join(tree.root, rel)):
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

    def test_listing_names_every_swift_file_read_with_its_class(self):
        tree = Tree(self.base)
        p = subprocess.run([CHECK, "--list-swift", "--root", tree.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        listed = {tuple(line.split(" ", 1)) for line in p.stdout.decode().splitlines()}
        product = {os.path.realpath(os.path.join(tree.root, rel)) for rel in (APP, VIEW, KIT, TOKEN_FILE, DESIGN, BRAND_SWIFT)}
        want = {("product", path) for path in product} | {("test", os.path.realpath(os.path.join(tree.root, rel))) for rel in (TEST, TEST_SUPPORT)}
        self.assertEqual(listed, want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
