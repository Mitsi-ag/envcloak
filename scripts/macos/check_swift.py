#!/usr/bin/env python3
"""The lane-C Swift rules for apps/macos (M3 plan §5 rules 1 to 5 and 7,
docs/APP.md "The app run by an agent"), run as scripts/macos/check-swift.sh.

Swift is read with a lexer, not with patterns over raw text: comments are
dropped, string literals keep their literal text apart from the code inside
their interpolations (which is checked as code), so neither a comment nor a
string can satisfy or trip a code rule. A file the lexer cannot read whole
(an unterminated comment, string or interpolation, or a bare `/regex/`
literal, which needs the compiler's context to tell from division) fails
rather than being skipped. Every rule is a guess from the text: it sees
names, not types, so each takes the conservative reading and the
allowlists say, with a reason, where a reviewed file may do more.

Product code is the app target (apps/macos/EnvCloak/) and the local
packages' sources (apps/macos/Packages/*/Sources/); it is what ships.
Test code (the three test targets and the packages' Tests/) is held only to
the key-literal rule. A Swift file anywhere else under apps/macos fails, so
a new source root is classified here before anything can compile it, and
scripts/check-sources.sh --swift fails a build that compiles a test file
into a shipping target.

Rules (the id is what a finding and an allowlist entry name):

  unsafe-bytes   `withUnsafeBytes` / `withUnsafeMutableBytes`, the way into
                 a SecretBuffer's bytes, only in files listed in
                 apps/macos/security/expose-allowlist.txt (rule 1).
  storage        `@SceneStorage` and `NSUbiquitousKeyValueStore`: state the
                 system saves for the app (rule 1).
  launch-input   anything the starter of the app controls (docs/APP.md "The
                 app run by an agent"):
                 - arguments and environment: `CommandLine`, any
                   `.arguments` or `.environment` (other than SwiftUI's
                   `.environment(...)` modifier) that is not a child
                   process's being set, `getenv`, `environ`, `_NSGetArgv`,
                   `_NSGetArgc`, `_NSGetEnviron`, `KERN_PROCARGS`,
                   `KERN_PROCARGS2`, `KERN_PROC_ARGS` and a
                   `"kern.procargs..."` literal (sysctl), an
                   `LSEnvironment` key;
                 - the defaults, whose argument domain launch arguments
                   (`-key value`) set: `UserDefaults`, `NSUserDefaults`,
                   `NSUserDefaultsController`, `@AppStorage`,
                   `defaultAppStorage`, any `CFPreferences...` function,
                   `NSGlobalDomain`, the argument domain;
                 - the app's own standard input: `FileHandle.standardInput`
                   or any `.standardInput` that is not a child process's
                   being set, `stdin`, `__stdinp`, `STDIN_FILENO`,
                   `readLine`, a descriptor-0 handle or read (the number
                   also inside `Int32(...)` and the like), and a string
                   literal naming `/dev/stdin` or `/dev/fd/N` (N other than
                   1 and 2: a descriptor the starter may have passed in);
                 - the home directory as Foundation finds it, which follows
                   the environment's `CFFIXED_USER_HOME` (measured on macOS
                   26.4.1): `NSHomeDirectory`, `NSHomeDirectoryForUser`,
                   `homeDirectoryForCurrentUser`, any `homeDirectory`,
                   `CFCopyHomeDirectoryURL`, `NSSearchPathForDirectoriesInDomains`,
                   `.userDomainMask`, `.allDomainsMask`, the user-domain
                   directories (`applicationSupportDirectory`,
                   `libraryDirectory`, `cachesDirectory` and the rest),
                   `url(for:in:...)` and `urls(for:in:)`, `containerURL`,
                   `expandingTildeInPath`, `abbreviatingWithTildeInPath`,
                   `standardizingPath`, `resolvingSymlinksInPath`,
                   `standardized`, `standardizedFileURL`, and a string
                   literal that starts with `~` (`URL(fileURLWithPath:)` and
                   `URL(filePath:)` expand it from the same lookup). Home
                   comes from `getpwuid_r` only;
                 - the working directory: `getcwd`, `getwd`,
                   `changeCurrentDirectoryPath`, and any
                   `currentDirectoryPath` or `currentDirectoryURL` that is
                   not a child process's being set.
  side-door      SPEC §12 "No side doors": Info.plist keys for URL schemes,
                 AppleScript, Services, documents, exported types, Handoff
                 and extensions (in every file), and in Swift: App Intents,
                 Intents, Spotlight, `onOpenURL`, `handlesExternalEvents`,
                 Apple event handlers, services providers, user activities
                 and the app delegate's open callbacks (rule 2). The keys
                 are read from every property list under apps/macos as
                 parsed (XML in any encoding, or binary, at any depth,
                 whatever the file is called) and as text from the build
                 settings (`INFOPLIST_KEY_...`).
  a11y-action    accessibility actions, which another program can perform
                 (rule 2: none may approve, reveal or write): SwiftUI's
                 action, adjustable, scroll, zoom and quick actions, custom
                 actions, `accessibilityActionNames` and AppKit's
                 `accessibilityPerform...` overrides.
  gated-key      (rule 2) a keyboard shortcut or key press on a button
                 whose title starts with Approve, Reveal, Replace or
                 Remove, or whose action names one (`approve()`,
                 `revealValue`: a name that is the verb or starts with it
                 and a capital); `onSubmit` or `onKeyPress` whose closure
                 names one; Return as an AppKit `keyEquivalent`.
  log            the app logs only through `Logger` with `LogToken` words
                 (rule 3: a launch environment can make the log store
                 "private" arguments in the clear, docs/APP.md "Logging"):
                 - no other writer: `print`, `debugPrint`, `dump`, `NSLog`,
                   the C stdio and err(3) writers, `syslog`, `CFShow`,
                   also when module-qualified (`Darwin.puts`); the app's
                   own `FileHandle.standardError` and `.standardOutput`
                   (any such member that is not a child's stream being
                   set), `stderr`, `stdout`, `STDOUT_FILENO`,
                   `STDERR_FILENO`, a descriptor-1 or -2 handle or write,
                   and a string literal naming `/dev/stdout`,
                   `/dev/stderr`, `/dev/fd/1`, `/dev/fd/2`, a terminal
                   (`/dev/tty...`) or `/dev/console`;
                 - no other log API: `os_log`, `os_signpost`, `os_trace`,
                   `os_activity` (any spelling), the system log facility
                   (`asl_...`), `OSLog`, `OSLogMessage`, `OSSignposter`,
                   `OSSignpostID`, `OSLogStore`;
                 - a `Logger` call (a level method on a receiver) takes its
                   message as a string literal at the call, and each
                   interpolation in it is `\\(x.logToken)`;
                   `privacy: .public` only on such a token; `%{public}`
                   nowhere;
                 - `fatalError`, `precondition`, `preconditionFailure`,
                   `assert`, `assertionFailure` and an `NSException`'s
                   `reason:` (which reach standard error and the crash
                   report) take a literal message with the same
                   interpolation rule; `raise(_:format:arguments:)` is
                   refused;
                 - `LogToken`: only an `enum` whose raw type, written first,
                   is `String` and whose body holds only cases with literal
                   raw values conforms. Measured (Swift 6): a `rawValue`
                   from any extension the enum's conformances reach
                   replaces the compiler's, so outside Log/LogToken.swift
                   no extension of anything declares `rawValue` or
                   `init(rawValue:)` at its top level, no extension is
                   constrained to `LogToken`, no extension of a token enum
                   (also through a `typealias`) or of `LogToken` declares
                   anything; `logToken` appears only as `x.logToken` (never
                   declared, used as a label, as in a tuple's
                   `(logToken: s, ...).logToken`, or bound); no type or
                   typealias is named `String` or `LogToken`; and no
                   `@dynamicMemberLookup` type (whose `x.logToken` could
                   be any string).
  indirect       a call by a name the other rules cannot see:
                 `@_silgen_name`, `@_extern`, `dlopen`, `dlsym`,
                 `NSClassFromString`, `NSSelectorFromString`, the
                 Objective-C runtime's lookups and `objc_msgSend`,
                 `Selector("...")` from a string, `value(forKey:)` and
                 `setValue(_:forKey:)` (and their key-path forms).
  daemon-text    `.unescaped`, the raw text of a string the daemon sent
                 (`DaemonText`, M3-03), outside the allowlist: views show
                 daemon text only through `Escape.display` (rule 4).
  color          a colour not from EnvCloakDesign's tokens: any call with a
                 colour-component label (`red:`, `hue:`, `srgbRed:`,
                 `cgColor:` and the rest, so `Color.Resolved(red:...)` and
                 `.init(red:...)` too), `Color` or `NSColor` (or its `init`)
                 built from components, `white:` or a colour space, `#colorLiteral`, CGColor, CIColor,
                 UIColor, named system colours, and catalog lookups by name
                 outside EnvCloakDesign (rule 5).
  remote-package a Swift package from anywhere but this tree: a manifest's
                 `.package(url:)`, `.package(id:)` or `.package(path:)`
                 outside apps/macos/Packages, and a project's remote
                 package or local package outside apps/macos/Packages
                 (R-M3-24: no third-party code, no analytics SDK).
  linked-code    code that reaches the app other than from the Swift this
                 check reads (R-M3-24): a manifest's `.binaryTarget`,
                 `.systemLibrary`, `.macro`, `unsafeFlags`, `linkedLibrary`,
                 `linkedFramework` or plugin; a project's script phase,
                 build rule, legacy or aggregate target, a library or
                 framework file reference other than the SDK's, an absolute
                 path, a path outside apps/macos and assets/brand, or a
                 linker or include search setting (`OTHER_LDFLAGS`, the
                 search paths, `OTHER_SWIFT_FLAGS`, `OTHER_CFLAGS`); any
                 Mach-O, archive, library or framework file in the tree;
                 and any source that compiles into the app as something
                 else, or generates code for it, or instantiates classes
                 by name: C, C++, Objective-C, headers, module maps,
                 assembly, Metal, lex and yacc, Rez, Swift interfaces and
                 modules, intent definitions, Core ML models, Core Data
                 models, storyboards, XIBs and NIBs, Reality files,
                 playgrounds (scripts/check-sources.sh --swift also checks
                 every object a build linked against the Swift it read).
  entitlement    any key in an entitlements file, which must parse as a
                 property list (XML or binary): no tier signs one yet
                 (M3-10 adds the keychain group's, as
                 scripts/macos/sign_check.py's list does), and
                 `com.apple.security.get-task-allow`, any
                 `com.apple.security.cs.` (hardened-runtime exception) and
                 any `com.apple.security.temporary-exception.` key are
                 never signed (D3-05, D3-06).
  unreadable     a file a rule must read but cannot: a property list (by
                 name, `.plist` or `.entitlements`, or by its content) that
                 does not parse, or a build setting, project, scheme, JSON
                 or strings file that is not UTF-8 or UTF-16 text. Never
                 skipped.
  key-literal    a string matching a provider's key pattern
                 (providers/*.toml) in any file, a file that is not text
                 read byte for byte (rule 7).
  symlink        a symbolic link that does not resolve inside assets/brand/.
  stray-swift    a Swift file outside the product and test roots.
  lex            a Swift file the lexer cannot read whole.
  allowlist      a malformed, unknown, missing or unused allowlist entry.

Limits (what a review still looks for): the rules read names and
literals, not types or values computed at run time, so these are not
seen: a `typealias` or a wrapper that renames a refused API (other than
the ones above); a path built at run time (one that starts with `~` and
reaches `URL(fileURLWithPath:)`, or `"/dev/" + "stderr"`); a relative path,
which resolves against the working directory the starter chose (the app
uses absolute paths from `getpwuid_r` and its bundle); a gated button whose
title is not a literal and whose action has another name (M3-12's review
looks for them, with `onSubmit` handlers named otherwise).

The brand's own Swift (assets/brand/motion/swiftui/EnvCloakMotion.swift,
reached through a symlink in EnvCloakDesign) is product code and held to
every rule but `color`: it defines the brand colours.

Usage: check-swift.sh [--root DIR]       check the tree (default: the repo)
       check-swift.sh --list-swift [--root DIR]
                                         print every Swift file read, one per
                                         line, as `<class> <real path>` with
                                         class `product` or `test`, and check
                                         nothing (scripts/check-sources.sh
                                         --swift compares it with what the
                                         compiler read, target by target)
"""

import os
import plistlib
import posixpath
import re
import subprocess
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

APP = "apps/macos"
PACKAGES = APP + "/Packages/"
EXPOSE_ALLOWLIST = APP + "/security/expose-allowlist.txt"
RULE_ALLOWLIST = APP + "/security/check-swift-allowlist.txt"
ALLOWLISTABLE = {"launch-input", "storage", "a11y-action", "daemon-text"}
LOG_TOKEN_FILE = APP + "/Packages/EnvCloakKit/Sources/EnvCloakKit/Log/LogToken.swift"
DESIGN_SOURCES = APP + "/Packages/EnvCloakDesign/Sources/"
BRAND = "assets/brand/"
SKIP_DIRS = {".git", "build", "DerivedData", ".build", ".swiftpm", "xcuserdata"}

SIDE_DOOR_KEYS = (
    "CFBundleURLTypes",
    "CFBundleURLSchemes",
    "NSAppleScriptEnabled",
    "OSAScriptingDefinition",
    "NSServices",
    "CFBundleDocumentTypes",
    "UTExportedTypeDeclarations",
    "UTImportedTypeDeclarations",
    "NSUserActivityTypes",
    "NSExtension",
)
# Info.plist keys that hand the app input from its starter.
LAUNCH_KEYS = ("LSEnvironment",)
SIDE_DOOR_IMPORTS = {"AppIntents", "Intents", "CoreSpotlight", "IntentsUI"}
SIDE_DOOR_NAMES = {
    "AppIntent",
    "AppShortcutsProvider",
    "AppEntity",
    "AppShortcut",
    "onOpenURL",
    "handlesExternalEvents",
    "NSAppleEventManager",
    "setEventHandler",
    "NSScriptCommand",
    "servicesProvider",
    "NSUpdateDynamicServices",
    "onContinueUserActivity",
    "userActivity",
    "NSUserActivity",
    "CSSearchableIndex",
    "CSSearchableItem",
}
OPEN_CALLBACK_LABELS = {
    "open",
    "openFile",
    "openFiles",
    "openTempFile",
    "openFileWithoutUI",
    "printFile",
    "printFiles",
    "continue",
}
A11Y_NAMES = {
    "accessibilityAction",
    "accessibilityActions",
    "accessibilityCustomActions",
    "NSAccessibilityCustomAction",
    "AccessibilityActionKind",
    "accessibilityAdjustableAction",
    "accessibilityScrollAction",
    "accessibilityZoomAction",
    "accessibilityQuickAction",
    "accessibilityActionNames",
}
# AppKit's action overrides (`accessibilityPerformPress()` and the rest, and
# the informal protocol's `accessibilityPerformAction(_:)`).
A11Y_PREFIXES = ("accessibilityPerform",)
GATED_VERBS = ("approve", "reveal", "replace", "remove")
PRINTERS = {
    "print",
    "debugPrint",
    "dump",
    "NSLog",
    "NSLogv",
    "puts",
    "fputs",
    "fputc",
    "putc",
    "putw",
    "printf",
    "fprintf",
    "dprintf",
    "vprintf",
    "vfprintf",
    "vdprintf",
    "putchar",
    "perror",
    "psignal",
    "fwrite",
    "warn",
    "warnx",
    "vwarn",
    "vwarnx",
    "err",
    "errx",
    "verr",
    "verrx",
    "syslog",
    "vsyslog",
    "CFShow",
    "CFShowStr",
    "putc_unlocked",
    "putchar_unlocked",
}
# Modules a writer can be qualified with (`Darwin.puts`): these, and every
# module the file imports.
SYSTEM_MODULES = {
    "Swift",
    "Foundation",
    "Darwin",
    "Glibc",
    "os",
    "OSLog",
    "CoreFoundation",
    "ObjectiveC",
    "Dispatch",
    "SwiftUI",
    "AppKit",
    "Cocoa",
    "Combine",
    "_Concurrency",
    "System",
    "Observation",
    "CoreGraphics",
    "CoreServices",
    "Security",
}
# Words after which `.name(` is an implicit member (`return .error(x)`),
# not a call on a receiver.
KEYWORDS = {
    "return",
    "case",
    "in",
    "where",
    "if",
    "guard",
    "while",
    "throw",
    "try",
    "await",
    "else",
    "is",
    "as",
    "let",
    "var",
    "switch",
    "repeat",
    "defer",
    "do",
}
# The process's own standard streams. Setting a child's
# (`process.standardOutput = pipe`) is not reading or writing the app's own.
STREAM_MEMBERS = {"standardError": "log", "standardOutput": "log", "standardInput": "launch-input"}
C_STREAM_WRITERS = {"stderr", "stdout", "__stderrp", "__stdoutp", "STDOUT_FILENO", "STDERR_FILENO"}
C_STREAM_READERS = {"stdin", "__stdinp", "STDIN_FILENO"}
# Calls whose first argument is a descriptor: 0 is the app's standard
# input, 1 and 2 its output and error.
FD_CALLS = {"FileHandle", "write", "read", "pwrite", "pread", "writev", "readv", "fdopen", "dup", "dup2", "send", "recv"}
LOG_LEVELS = {"debug", "info", "notice", "error", "warning", "fault", "critical", "trace", "log"}
LOG_APIS = {"OSLog", "OSLogMessage", "OSSignposter", "OSSignpostID", "OSLogStore", "OSLogInterpolation"}
LOG_API_PREFIXES = ("os_log", "_os_log", "os_signpost", "_os_signpost", "os_trace", "_os_trace", "os_activity", "_os_activity", "asl_")
# Calls that write their message to standard error and the crash report,
# with the index of the message among the unlabelled arguments.
FAIL_CALLS = {"fatalError": 0, "preconditionFailure": 0, "assertionFailure": 0, "precondition": 1, "assert": 1}
LAUNCH_NAMES = {
    # arguments and environment
    "CommandLine": "reads the launch arguments",
    "getenv": "reads the environment",
    "secure_getenv": "reads the environment",
    "environ": "reads the environment",
    "_NSGetEnviron": "reads the environment",
    "_NSGetArgv": "reads the launch arguments",
    "_NSGetArgc": "reads the launch arguments",
    "KERN_PROCARGS": "reads the launch arguments and environment through sysctl",
    "KERN_PROCARGS2": "reads the launch arguments and environment through sysctl",
    "KERN_PROC_ARGS": "reads the launch arguments through sysctl",
    # standard input
    "readLine": "reads the app's own standard input",
    # the defaults
    "NSArgumentDomain": "reads the defaults, which launch arguments set",
    "argumentDomain": "reads the defaults, which launch arguments set",
    "NSGlobalDomain": "reads the defaults, which launch arguments set",
    "UserDefaults": "reads the defaults, which launch arguments set",
    "NSUserDefaults": "reads the defaults, which launch arguments set",
    "NSUserDefaultsController": "reads the defaults, which launch arguments set",
    "defaultAppStorage": "reads the defaults, which launch arguments set",
    # home, as Foundation finds it (CFFIXED_USER_HOME)
    "NSHomeDirectory": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "NSHomeDirectoryForUser": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "homeDirectoryForCurrentUser": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "homeDirectory": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "CFCopyHomeDirectoryURL": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "NSSearchPathForDirectoriesInDomains": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "userDomainMask": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "allDomainsMask": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "containerURL": "follows CFFIXED_USER_HOME (home comes from getpwuid_r)",
    "expandingTildeInPath": "expands `~` from CFFIXED_USER_HOME",
    "abbreviatingWithTildeInPath": "abbreviates with a home from CFFIXED_USER_HOME",
    "standardizingPath": "expands `~` from CFFIXED_USER_HOME",
    "resolvingSymlinksInPath": "expands `~` from CFFIXED_USER_HOME",
    "standardized": "expands `~` from CFFIXED_USER_HOME",
    "standardizedFileURL": "expands `~` from CFFIXED_USER_HOME",
    # working directory
    "getcwd": "reads the working directory, which the starter sets",
    "getwd": "reads the working directory, which the starter sets",
    "changeCurrentDirectoryPath": "changes the working directory relative paths resolve against",
}
LAUNCH_PREFIXES = {"CFPreferences": "reads the defaults, which launch arguments set"}
# The user-domain directories URL and FileManager name, each under the home
# Foundation finds.
USER_DIRECTORIES = {
    "applicationSupportDirectory",
    "libraryDirectory",
    "cachesDirectory",
    "documentsDirectory",
    "documentDirectory",
    "desktopDirectory",
    "downloadsDirectory",
    "moviesDirectory",
    "musicDirectory",
    "picturesDirectory",
    "sharedPublicDirectory",
    "trashDirectory",
    "applicationDirectory",
    "autosavedInformationDirectory",
    "applicationScriptsDirectory",
    "inputMethodsDirectory",
    "preferencePanesDirectory",
}
# Members that read the working directory unless a child's is being set.
CWD_MEMBERS = {"currentDirectoryPath", "currentDirectoryURL"}
INDIRECT_NAMES = {
    "dlopen",
    "dlsym",
    "dlvsym",
    "NSClassFromString",
    "NSSelectorFromString",
    "NSProtocolFromString",
    "objc_getClass",
    "objc_lookUpClass",
    "objc_getRequiredClass",
    "objc_msgSend",
    "objc_msgSendSuper",
    "class_getInstanceMethod",
    "class_getClassMethod",
    "class_getMethodImplementation",
    "method_getImplementation",
    "method_setImplementation",
    "method_exchangeImplementations",
}
INDIRECT_ATTRS = {"_silgen_name", "_extern"}
KVC_CALLS = {"value": ("forKey", "forKeyPath"), "setValue": ("forKey", "forKeyPath")}
STORAGE_NAMES = {"NSUbiquitousKeyValueStore"}
COLOR_TYPES = {"Color", "NSColor"}
# Labels that build a colour from components whatever the callee.
COLOR_COMPONENT_LABELS = {
    "red",
    "srgbRed",
    "calibratedRed",
    "deviceRed",
    "displayP3Red",
    "colorLiteralRed",
    "hue",
    "calibratedHue",
    "deviceHue",
    "deviceCyan",
    "calibratedWhite",
    "deviceWhite",
    "genericGamma22White",
    "cgColor",
    "ciColor",
    "nsColor",
    "uiColor",
    "catalogName",
    "patternImage",
}
# Labels that build a colour on a colour type or its init.
COLOR_TYPE_LABELS = COLOR_COMPONENT_LABELS | {"white", "colorSpace", "hex"}
COLOR_NAME_LABELS = {"named", "name"}
SYSTEM_COLORS = {
    "red",
    "orange",
    "yellow",
    "green",
    "mint",
    "teal",
    "cyan",
    "blue",
    "indigo",
    "purple",
    "pink",
    "brown",
    "gray",
    "grey",
    "black",
    "white",
    "magenta",
    "darkGray",
    "lightGray",
}
# Implicit members that are colours and nothing else in SwiftUI or AppKit
# (`.black` and `.white` are also font weights, so they are left out).
IMPLICIT_COLORS = SYSTEM_COLORS - {"black", "white", "darkGray", "lightGray"}
FORBIDDEN_ENTITLEMENT = re.compile(
    r"com\.apple\.security\.(?:get-task-allow|cs\.[A-Za-z0-9.-]+|temporary-exception\.[A-Za-z0-9.-]+)"
)
# Project build settings that link or include code from outside the
# reviewed sources.
LINK_SETTINGS = re.compile(
    r"(?<![A-Za-z0-9_])(OTHER_LDFLAGS|LIBRARY_SEARCH_PATHS|FRAMEWORK_SEARCH_PATHS|SYSTEM_FRAMEWORK_SEARCH_PATHS"
    r"|SWIFT_INCLUDE_PATHS|HEADER_SEARCH_PATHS|OTHER_SWIFT_FLAGS|OTHER_CFLAGS|OTHER_LIBTOOLFLAGS)"
    r"(?:\[[^\]\n]*\])*\s*="
)
PBX_CODE_OBJECTS = ("PBXShellScriptBuildPhase", "PBXBuildRule", "PBXLegacyTarget", "PBXAggregateTarget")
LINKABLE_TYPE = re.compile(
    r"(?:lastKnownFileType|explicitFileType) = \"?(archive\.ar|wrapper\.framework|wrapper\.xcframework"
    r"|compiled\.mach-o[^\";]*|sourcecode\.text-based-dylib-definition|wrapper\.plug-in)\"?;"
)
BINARY_SUFFIXES = (".a", ".dylib", ".so", ".o", ".tbd", ".framework", ".xcframework")
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

# The app's own streams and descriptors reached by path: (pattern, rule,
# what). `/dev/fd/N` for N other than 1 and 2 is a descriptor the starter
# may have passed in.
DEVICE_PATHS = (
    (re.compile(r"/dev/(?:std(?:out|err)|fd/0*[12](?![0-9])|tty[A-Za-z0-9]*|console)"), "log", "the app's own output, error or terminal"),
    (re.compile(r"/dev/(?:stdin|fd(?:$|/(?!0*[12](?![0-9]))))"), "launch-input", "the app's own standard input or a descriptor its starter passed in"),
    (re.compile(r"^kern\.proc(?:args2?|\.args)"), "launch-input", "the launch arguments and environment, through sysctlbyname"),
)
# Source kinds that compile into the app (or generate code for it) as
# something other than the Swift this check reads, and interface archives
# that instantiate classes by name: refused anywhere under apps/macos.
COMPILED_SUFFIXES = (
    ".c",
    ".cc",
    ".cp",
    ".cpp",
    ".cxx",
    ".c++",
    ".m",
    ".mm",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".inl",
    ".ipp",
    ".pch",
    ".s",
    ".asm",
    ".modulemap",
    ".metal",
    ".cl",
    ".y",
    ".ym",
    ".l",
    ".lm",
    ".r",
    ".swiftinterface",
    ".swiftmodule",
    ".intentdefinition",
    ".mlmodel",
    ".mlpackage",
    ".mlmodelc",
    ".xcdatamodel",
    ".xcdatamodeld",
    ".xcmappingmodel",
    ".storyboard",
    ".xib",
    ".nib",
    ".rcproject",
    ".reality",
    ".playground",
)
# Names product code may not declare: a `String` of its own would stand in
# for the raw type of every token enum in its module, and only the token
# file declares the token.
SHADOWED_TYPES = {"String", "LogToken"}
# What a key equivalent must not be: Return (and Enter).
RETURN_KEYS = {"\r", "\n", "\r\n", "\x03"}

findings = []
# Cross-file facts for the LogToken rule: enums that conform, every
# extension's (file, line, extended type's last name, body tokens), and
# every `typealias A = B` (A to B's last name).
log_token_enums = set()
extensions = []
aliases = {}


def find(rule, path, line, msg):
    findings.append((rule, path, line, msg))


# ---------------------------------------------------------------- the lexer


class LexError(Exception):
    def __init__(self, line, msg):
        super().__init__(msg)
        self.line = line


class Tok:
    __slots__ = ("kind", "text", "line", "parts", "level")

    def __init__(self, kind, text, line, parts=None):
        self.kind = kind  # id, num, str, op, punct, attr, pound, regex
        self.text = text
        self.line = line
        self.parts = parts  # for str: [("lit", text) | ("interp", [Tok])]
        self.level = 0  # how many interpolations deep (set by flatten)

    def __repr__(self):  # pragma: no cover
        return "Tok(%s,%r,%d)" % (self.kind, self.text, self.line)


OPCHARS = set("/=-+!*%<>&|^~?.")
# A `/` after one of these starts an expression, where Swift 6 reads a bare
# regex literal; after anything else it is division.
EXPR_START_PUNCT = {"(", "[", "{", ",", ":", ";"}
EXPR_START_WORDS = {"return", "in", "case", "where", "if", "guard", "while", "throw", "try", "await", "else", "is", "as"}


def is_ident_start(c):
    return c == "_" or c == "$" or c.isalpha() or ord(c) > 127


def is_ident_char(c):
    return c == "_" or c == "$" or c.isalnum() or ord(c) > 127


class Lexer:
    def __init__(self, src):
        self.src = src
        self.n = len(src)
        self.newlines = [i for i, c in enumerate(src) if c == "\n"]

    def line(self, i):
        lo, hi = 0, len(self.newlines)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.newlines[mid] < i:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    def lex(self):
        toks, _ = self.run(0, nested=False)
        return toks

    def run(self, i, nested):
        src, n = self.src, self.n
        toks = []
        depth = 0
        while i < n:
            c = src[i]
            if c in " \t\r\n\f\v﻿":
                i += 1
                continue
            if src.startswith("//", i):
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if src.startswith("/*", i):
                i = self.block_comment(i)
                continue
            if c == '"' or (c == "#" and self.raw_string_start(i)):
                tok, i = self.string(i)
                toks.append(tok)
                continue
            if c == "#" and self.regex_start(i):
                tok, i = self.regex(i)
                toks.append(tok)
                continue
            if c == "#":
                j = i + 1
                while j < n and is_ident_char(src[j]):
                    j += 1
                toks.append(Tok("pound", src[i:j], self.line(i)))
                i = j
                continue
            if c == "@":
                j = i + 1
                while j < n and is_ident_char(src[j]):
                    j += 1
                toks.append(Tok("attr", src[i + 1 : j], self.line(i)))
                i = j
                continue
            if c == "`":
                j = src.find("`", i + 1)
                if j < 0 or "\n" in src[i:j]:
                    raise LexError(self.line(i), "unterminated backquoted name")
                toks.append(Tok("id", src[i + 1 : j], self.line(i)))
                i = j + 1
                continue
            if is_ident_start(c):
                j = i + 1
                while j < n and is_ident_char(src[j]):
                    j += 1
                toks.append(Tok("id", src[i:j], self.line(i)))
                i = j
                continue
            if c.isdigit():
                j = i + 1
                while j < n and (src[j].isalnum() or src[j] in "_" or (src[j] == "." and j + 1 < n and src[j + 1].isdigit())):
                    j += 1
                toks.append(Tok("num", src[i:j], self.line(i)))
                i = j
                continue
            if c == "(":
                depth += 1
                toks.append(Tok("punct", c, self.line(i)))
                i += 1
                continue
            if c == ")":
                if nested and depth == 0:
                    return toks, i + 1
                depth -= 1
                toks.append(Tok("punct", c, self.line(i)))
                i += 1
                continue
            if c in OPCHARS:
                if c == "/" and self.expression_start(toks):
                    raise LexError(
                        self.line(i),
                        "a bare /regex/ literal (or a `/` where an expression starts); write #/.../#",
                    )
                j = i
                while j < n and src[j] in OPCHARS and not src.startswith("//", j) and not src.startswith("/*", j):
                    j += 1
                toks.append(Tok("op", src[i:j], self.line(i)))
                i = j
                continue
            if c == "\\":
                # A key path (`\.foo`, `\Type.foo`).
                toks.append(Tok("op", c, self.line(i)))
                i += 1
                continue
            toks.append(Tok("punct", c, self.line(i)))
            i += 1
        if nested:
            raise LexError(self.line(min(i, n - 1)), "unterminated string interpolation")
        return toks, i

    @staticmethod
    def expression_start(toks):
        if not toks:
            return True
        last = toks[-1]
        if last.kind == "punct" and last.text in EXPR_START_PUNCT:
            return True
        if last.kind == "op" and last.text not in ("?", "!"):
            # After an operator an operand follows: `a / /x/` is a regex.
            return True
        if last.kind == "id" and last.text in EXPR_START_WORDS:
            return True
        return False

    def block_comment(self, i):
        src, n = self.src, self.n
        depth = 0
        j = i
        while j < n:
            if src.startswith("/*", j):
                depth += 1
                j += 2
            elif src.startswith("*/", j):
                depth -= 1
                j += 2
                if depth == 0:
                    return j
            else:
                j += 1
        raise LexError(self.line(i), "unterminated block comment")

    def raw_string_start(self, i):
        j = i
        while j < self.n and self.src[j] == "#":
            j += 1
        return j < self.n and self.src[j] == '"'

    def regex_start(self, i):
        j = i
        while j < self.n and self.src[j] == "#":
            j += 1
        return j < self.n and self.src[j] == "/"

    def regex(self, i):
        src = self.src
        j = i
        while src[j] == "#":
            j += 1
        hashes = j - i
        close = "/" + "#" * hashes
        k = src.find(close, j + 1)
        if k < 0:
            raise LexError(self.line(i), "unterminated regex literal")
        return Tok("regex", src[j + 1 : k], self.line(i)), k + len(close)

    def string(self, i):
        src, n = self.src, self.n
        start_line = self.line(i)
        j = i
        while src[j] == "#":
            j += 1
        hashes = j - i
        multiline = src.startswith('"""', j)
        quote = '"""' if multiline else '"'
        j += len(quote)
        close = quote + "#" * hashes
        esc = "\\" + "#" * hashes
        parts = []
        buf = []
        while True:
            if j >= n:
                raise LexError(start_line, "unterminated string literal")
            if src.startswith(close, j):
                j += len(close)
                break
            if not multiline and src[j] == "\n":
                raise LexError(start_line, "unterminated string literal")
            if src.startswith(esc, j):
                k = j + len(esc)
                if k < n and src[k] == "(":
                    if buf:
                        parts.append(("lit", "".join(buf)))
                        buf = []
                    inner, j = self.run(k + 1, nested=True)
                    parts.append(("interp", inner))
                    continue
                if k < n:
                    buf.append(src[j : k + 1])
                    j = k + 1
                    continue
            buf.append(src[j])
            j += 1
        if buf:
            parts.append(("lit", "".join(buf)))
        text = "".join(p[1] for p in parts if p[0] == "lit")
        if multiline:
            # A multi-line literal's text starts after its opening line.
            text = text[1:] if text.startswith("\n") else text
        return Tok("str", text, start_line, parts), j


def flatten(toks, level=0):
    """Every code token, descending into interpolations, in source order;
    each token's `level` says how many interpolations deep it is."""
    out = []
    for t in toks:
        t.level = level
        out.append(t)
        if t.kind == "str":
            for kind, part in t.parts:
                if kind == "interp":
                    out.extend(flatten(part, level + 1))
    return out


def interpolations(tok):
    return [part for kind, part in tok.parts if kind == "interp"]


def split_top(toks, sep=","):
    """Splits a token list at top-level commas."""
    out, cur, depth = [], [], 0
    for t in toks:
        if t.kind == "punct" and t.text in "([{":
            depth += 1
        elif t.kind == "punct" and t.text in ")]}":
            depth -= 1
        if depth == 0 and t.kind == "punct" and t.text == sep:
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    out.append(cur)
    return out


def matching(toks, i):
    """Index of the bracket that closes toks[i] (an opening bracket)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    want = pairs[toks[i].text]
    opener = toks[i].text
    depth = 0
    for j in range(i, len(toks)):
        t = toks[j]
        if t.kind == "punct" and t.text == opener:
            depth += 1
        elif t.kind == "punct" and t.text == want:
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


def call_args(flat, lp):
    """The top-level arguments of the call whose `(` is flat[lp], each as
    (label or None, tokens after the label)."""
    rp = matching(flat, lp)
    # A string's interpolations follow it in `flat`; they are part of that
    # argument, not arguments of their own.
    inner = [t for t in flat[lp + 1 : rp] if t.level == flat[lp].level]
    if not inner:
        return []
    out = []
    for arg in split_top(inner):
        if len(arg) >= 2 and arg[0].kind == "id" and arg[1].kind == "punct" and arg[1].text == ":":
            out.append((arg[0].text, arg[2:]))
        else:
            out.append((None, arg))
    return out


def is_literal(expr):
    """Whether an argument is one string literal, perhaps in parentheses."""
    while len(expr) >= 3 and expr[0].text == "(" and expr[-1].text == ")" and matching(expr, 0) == len(expr) - 1:
        expr = expr[1:-1]
    return len(expr) == 1 and expr[0].kind == "str"


def unwrap(expr):
    while len(expr) >= 3 and expr[0].text == "(" and expr[-1].text == ")" and matching(expr, 0) == len(expr) - 1:
        expr = expr[1:-1]
    return expr


# ---------------------------------------------------------------- the tree


def repo_files(root):
    """Files to check: in a git checkout, tracked files and untracked ones
    that are not ignored; elsewhere (the test fixtures), every file outside
    build output."""
    try:
        top = subprocess.run(
            ["git", "-C", root, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout.decode().strip()
    except (OSError, subprocess.CalledProcessError):
        top = None
    if top and os.path.realpath(top) == os.path.realpath(root):
        out = subprocess.run(
            ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", APP],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        files = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
        return sorted(f for f in files if os.path.lexists(os.path.join(root, f)))
    files = []
    base = os.path.join(root, APP)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in filenames:
            files.append(os.path.relpath(os.path.join(dirpath, name), root))
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                files.append(os.path.relpath(full, root))
    return sorted(files)


def classify(rel):
    if not rel.endswith(".swift"):
        return None
    parts = rel.split("/")
    if rel.startswith(APP + "/EnvCloak/"):
        return "product"
    if len(parts) >= 5 and parts[2] == "Packages" and parts[4] == "Sources":
        return "product"
    if len(parts) >= 3 and parts[2] in ("EnvCloakTests", "EnvCloakUITests", "EnvCloakHardwareTests"):
        return "test"
    if len(parts) >= 5 and parts[2] == "Packages" and parts[4] == "Tests":
        return "test"
    if len(parts) == 5 and parts[2] == "Packages" and parts[4] == "Package.swift":
        return "manifest"
    return "stray"


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    if b"\0" in data:
        return None
    return data.decode("utf-8", "surrogateescape")


# ---------------------------------------------------------------- the rules


def check_product_swift(rel, toks, brand):
    flat = flatten(toks)
    modules = set(SYSTEM_MODULES)
    for k, t in enumerate(flat):
        if t.kind == "id" and t.text == "import":
            j = k + 1
            if j < len(flat) and flat[j].kind == "id" and flat[j].text in ("struct", "class", "enum", "protocol", "func", "var", "let", "typealias"):
                j += 1
            if j < len(flat) and flat[j].kind == "id":
                modules.add(flat[j].text)

    def at(j):
        return flat[j] if 0 <= j < len(flat) else None

    def is_member(k):
        p = at(k - 1)
        return p is not None and p.kind == "op" and p.text.endswith(".")

    def receiver(k):
        """For flat[k] after a `.`: "module" (`Darwin.puts`), "explicit"
        (`logger.info`, `f().x`) or "implicit" (`.error(x)`)."""
        r = at(k - 2)
        if r is None:
            return "implicit"
        if r.kind == "id" and r.text in modules and (at(k - 3) is None or not (at(k - 3).kind == "op" and at(k - 3).text.endswith("."))):
            return "module"
        if r.kind == "id" and r.text not in KEYWORDS:
            return "explicit"
        if r.kind in ("str", "num") or (r.kind == "punct" and r.text in (")", "]")):
            return "explicit"
        return "implicit"

    def bare(k):
        """A free function or global: not a member, or qualified only by a
        module."""
        return not is_member(k) or receiver(k) == "module"

    def assigned_on_receiver(k):
        """`x.member = ...`: a child process's stream, directory, arguments
        or environment being set, not the app's own being read."""
        a = at(k + 1)
        return is_member(k) and receiver(k) == "explicit" and a is not None and a.kind == "op" and a.text == "="

    for k, t in enumerate(flat):
        if t.kind == "id":
            name = t.text
            after = at(k + 1)
            calls = after is not None and after.kind == "punct" and after.text == "("
            # rule 1
            if name in ("withUnsafeBytes", "withUnsafeMutableBytes"):
                find("unsafe-bytes", rel, t.line, "`%s` outside %s" % (name, EXPOSE_ALLOWLIST))
            if name in STORAGE_NAMES:
                find("storage", rel, t.line, "`%s` keeps state the system saves for the app" % name)
            # launch inputs
            if name in LAUNCH_NAMES:
                find("launch-input", rel, t.line, "`%s` %s" % (name, LAUNCH_NAMES[name]))
            for prefix, why in LAUNCH_PREFIXES.items():
                if name.startswith(prefix):
                    find("launch-input", rel, t.line, "`%s` %s" % (name, why))
            if name in USER_DIRECTORIES:
                find("launch-input", rel, t.line, "`%s` is under the home Foundation finds, which follows CFFIXED_USER_HOME" % name)
            if name in ("url", "urls") and calls:
                labels = [label for label, _ in call_args(flat, k + 1)]
                if labels[:1] == ["for"] and "in" in labels:
                    find("launch-input", rel, t.line, "`%s(for:in:)` looks up a directory under the home Foundation finds" % name)
            if name in CWD_MEMBERS and not assigned_on_receiver(k):
                find("launch-input", rel, t.line, "`%s` reads the working directory, which the starter sets" % name)
            if name == "arguments" and is_member(k) and not assigned_on_receiver(k):
                find("launch-input", rel, t.line, "`.arguments` (the app reads no launch argument; only a child's may be set)")
            if name == "environment" and is_member(k) and not calls and not assigned_on_receiver(k):
                find("launch-input", rel, t.line, "`.environment` (the app reads no environment variable; only a child's may be set)")
            if name in C_STREAM_READERS and bare(k):
                find("launch-input", rel, t.line, "`%s` reads the app's own standard input" % name)
            # rule 2
            if name in SIDE_DOOR_NAMES:
                find("side-door", rel, t.line, "`%s` is a way in that skips the gated sheets (SPEC §12)" % name)
            if name == "import":
                mod = at(k + 1)
                if mod is not None and mod.kind == "id" and mod.text in SIDE_DOOR_IMPORTS:
                    find("side-door", rel, t.line, "`import %s` (SPEC §12 \"No side doors\")" % mod.text)
            if name == "func" and at(k + 1) is not None and at(k + 1).text == "application":
                lp = k + 2
                if lp < len(flat) and flat[lp].text == "(":
                    rp = matching(flat, lp)
                    labels = {x.text for x in flat[lp:rp] if x.kind == "id"}
                    hit = labels & OPEN_CALLBACK_LABELS
                    if hit:
                        find("side-door", rel, t.line, "an app delegate callback that opens input from outside (%s)" % ", ".join(sorted(hit)))
            if name in A11Y_NAMES or name.startswith(A11Y_PREFIXES):
                find("a11y-action", rel, t.line, "`%s`: another program can perform it" % name)
            if name == "Button" and after is not None and after.kind == "punct" and after.text in ("(", "{"):
                check_gated_button(rel, flat, k)
            if name in ("onSubmit", "onKeyPress") and is_member(k):
                span = flat[k + 1 : closure_end(flat, k) + 1]
                verb = gated_call(span)
                if verb:
                    find("gated-key", rel, t.line, "`%s` runs `%s` on a key press: these go through Touch ID, never a key alone" % (name, verb))
            if name == "keyEquivalent":
                nxt, val = at(k + 1), at(k + 2)
                if nxt is not None and nxt.text in ("=", ":") and val is not None and val.kind == "str" and literal_value(val) in RETURN_KEYS:
                    find("gated-key", rel, t.line, "Return as a key equivalent (Return never approves; design §1)")
            # rule 3: other writers
            if name in PRINTERS and calls and bare(k):
                find("log", rel, t.line, "`%s` writes outside the unified log (use Logger with LogToken)" % name)
            if name in PRINTERS and at(k - 1) is not None and at(k - 1).text == "func":
                find("log", rel, t.line, "a function named `%s`" % name)
            if name in STREAM_MEMBERS and is_member(k) and not assigned_on_receiver(k):
                what = "writes to" if STREAM_MEMBERS[name] == "log" else "reads"
                find(STREAM_MEMBERS[name], rel, t.line, "`.%s` %s the app's own standard stream (only a child's may be set)" % (name, what))
            if name in C_STREAM_WRITERS and bare(k):
                find("log", rel, t.line, "`%s` writes to the app's own standard stream" % name)
            if name in FD_CALLS and calls and (bare(k) or name == "FileHandle"):
                check_descriptor_call(rel, flat, k)
            if name == "init" and calls and is_member(k) and at(k - 2) is not None and at(k - 2).text == "FileHandle":
                check_descriptor_call(rel, flat, k)
            # rule 3: other log APIs
            if (name in LOG_APIS and not (at(k - 1) is not None and at(k - 1).text == "import")) or name.startswith(LOG_API_PREFIXES):
                find("log", rel, t.line, "`%s`: the app logs only through Logger with LogToken words" % name)
            if name in LOG_LEVELS and calls and is_member(k) and receiver(k) == "explicit":
                check_log_call(rel, flat, k + 1)
            if name in FAIL_CALLS and calls and bare(k):
                check_fail_call(rel, flat, k + 1, FAIL_CALLS[name], name)
            exception_init = name == "init" and calls and is_member(k) and at(k - 2) is not None and at(k - 2).text == "NSException"
            if (name == "NSException" and calls and bare(k)) or exception_init:
                for label, expr in call_args(flat, k + 1):
                    if label == "reason" and [x.text for x in unwrap(expr)] != ["nil"]:
                        check_message(rel, expr, t.line, "an NSException reason, which reaches standard error and the crash report,")
            if name == "raise" and calls and is_member(k):
                if "format" in [label for label, _ in call_args(flat, k + 1)]:
                    find("log", rel, t.line, "`raise(_:format:arguments:)` formats values into standard error and the crash report")
            # rule 3: the token. Outside its file, `logToken` is only ever
            # read as a member: never declared, used as a label (a tuple's
            # `(logToken: s, ...).logToken` is any string) or bound.
            if name == "logToken" and rel != LOG_TOKEN_FILE and not is_member(k):
                find("log", rel, t.line, "`logToken` outside %s, other than as `x.logToken`" % LOG_TOKEN_FILE)
            if name in ("enum", "struct", "class", "actor", "extension", "protocol", "typealias") and not (at(k - 1) is not None and at(k - 1).text == "."):
                check_declaration(rel, flat, k)
            # indirect calls
            if name in INDIRECT_NAMES:
                find("indirect", rel, t.line, "`%s` reaches code by a name the other rules cannot see" % name)
            if name == "Selector" and calls:
                args = call_args(flat, k + 1)
                if args and args[0][0] is None and is_literal(args[0][1]):
                    find("indirect", rel, t.line, "`Selector(\"...\")` names a method by a string (use #selector)")
            if name in KVC_CALLS and calls:
                labels = {label for label, _ in call_args(flat, k + 1)}
                if labels & set(KVC_CALLS[name]):
                    find("indirect", rel, t.line, "`%s(forKey:)` reaches a property by a string" % name)
            # rule 4
            if name == "unescaped" and is_member(k):
                find("daemon-text", rel, t.line, "`.unescaped` reads a daemon string's raw text (show it with Escape.display)")
            # rule 5
            if not brand:
                check_color(rel, flat, k)
        elif t.kind == "attr":
            if t.text == "SceneStorage":
                find("storage", rel, t.line, "`@SceneStorage` saves view state with the window")
            if t.text == "AppStorage":
                find("launch-input", rel, t.line, "`@AppStorage` reads the defaults, which launch arguments set")
            if t.text in INDIRECT_ATTRS:
                find("indirect", rel, t.line, "`@%s` binds a symbol under another name" % t.text)
            if t.text == "dynamicMemberLookup":
                find("log", rel, t.line, "`@dynamicMemberLookup`: its `x.logToken` could be any string")
        elif t.kind == "pound":
            if t.text == "#colorLiteral" and not brand:
                find("color", rel, t.line, "`#colorLiteral` (use an EnvCloakDesign token)")
        elif t.kind == "str":
            if "%{public" in t.text:
                find("log", rel, t.line, "`%{public}` in a format string")
            if t.text.startswith("~"):
                find("launch-input", rel, t.line, "a path that starts with `~`, which Foundation expands from CFFIXED_USER_HOME")
            for pattern, rule, what in DEVICE_PATHS:
                if pattern.search(t.text):
                    find(rule, rel, t.line, "`%s` reaches %s by path" % (t.text, what))
            for inner in interpolations(t):
                args = split_top(inner)
                if len(args) > 1 and any(is_public_privacy(a) for a in args[1:]) and not is_log_token_expr(args[0]):
                    find("log", rel, t.line, "`privacy: .public` on something other than `x.logToken`")


def is_public_privacy(arg):
    texts = [x.text for x in arg]
    if len(texts) >= 3 and texts[0] == "privacy" and texts[1] == ":":
        rest = texts[2:]
        return rest[:2] == [".", "public"] or rest[:1] == [".public"] or "public" in rest
    return False


def is_log_token_expr(expr):
    if len(expr) < 2:
        return False
    return expr[-1].kind == "id" and expr[-1].text == "logToken" and expr[-2].kind == "op" and expr[-2].text.endswith(".")


def check_message(rel, message, line, what):
    """A message argument: one string literal whose every interpolation is
    `x.logToken`."""
    if not is_literal(message):
        find("log", rel, line, "%s whose message is not a string literal at the call, which this check cannot read" % what)
        return
    lit = unwrap(message)[0]
    for inner in interpolations(lit):
        args = split_top(inner)
        if not is_log_token_expr(args[0]):
            find(
                "log",
                rel,
                lit.line,
                "%s interpolates something other than `x.logToken` (a launch environment can make private arguments public)" % what,
            )


def check_log_call(rel, flat, lp):
    """flat[lp] is the `(` of a level method called on a receiver, a Logger
    call as far as the text shows. Its message is the first argument other
    than `level:`, a string literal at the call."""
    args = [a for a in call_args(flat, lp) if a[0] != "level"]
    if not args:
        find("log", rel, flat[lp].line, "a log call with no message this check can read")
        return
    label, message = args[0]
    if label is not None:
        find("log", rel, flat[lp].line, "a log call whose first argument is `%s:`, not the message" % label)
        return
    check_message(rel, message, flat[lp].line, "a log message")


def check_fail_call(rel, flat, lp, index, name):
    positional = [expr for label, expr in call_args(flat, lp) if label is None]
    if len(positional) > index:
        check_message(rel, positional[index], flat[lp].line, "`%s`, whose message reaches standard error and the crash report," % name)


# Conversions a descriptor number may be written in: `Int32(2)`.
INT_CONVERSIONS = {"Int32", "CInt", "Int", "UInt32", "Int16", "numericCast"}


def check_descriptor_call(rel, flat, k):
    args = call_args(flat, k + 1)
    if not args:
        return
    expr = unwrap(args[0][1])
    while len(expr) >= 4 and expr[0].kind == "id" and expr[0].text in INT_CONVERSIONS and expr[1].text == "(" and matching(expr, 1) == len(expr) - 1:
        expr = unwrap(expr[2:-1])
    if len(expr) == 1 and expr[0].kind == "num" and expr[0].text in ("0", "1", "2"):
        fd = expr[0].text
        if fd == "0":
            find("launch-input", rel, flat[k].line, "descriptor 0 is the app's own standard input")
        else:
            find("log", rel, flat[k].line, "descriptor %s is the app's own standard %s" % (fd, "output" if fd == "1" else "error"))


def declaration(flat, k):
    """For a type declaration keyword at flat[k]: (name tokens, inheritance
    clause entries, index of the body's `{` or None, whether it has
    generic parameters)."""
    j = k + 1
    name = []
    while j < len(flat) and (flat[j].kind == "id" or (flat[j].kind == "op" and flat[j].text == ".")):
        if flat[j].kind == "id" and flat[j].text == "where":
            break
        name.append(flat[j])
        j += 1
    inherits = []
    generic = False
    if j < len(flat) and flat[j].kind == "op" and flat[j].text.startswith("<"):
        # Generic parameters (`<T: LogToken>`) are not the inheritance clause.
        generic = True
        depth = 0
        while j < len(flat):
            if flat[j].kind == "op":
                depth += flat[j].text.count("<") - flat[j].text.count(">")
            j += 1
            if depth <= 0:
                break
    clause = []
    seen_colon = False
    while j < len(flat):
        t = flat[j]
        if t.kind == "punct" and t.text in ("{", ";"):
            break
        if t.kind == "id" and t.text == "where":
            while j < len(flat) and not (flat[j].kind == "punct" and flat[j].text in ("{", ";")):
                j += 1
            break
        if t.kind == "punct" and t.text == ":" and not seen_colon:
            seen_colon = True
        elif seen_colon:
            clause.append(t)
        j += 1
    if clause:
        inherits = split_top(clause)
    lbrace = j if j < len(flat) and flat[j].kind == "punct" and flat[j].text == "{" else None
    return name, inherits, lbrace, generic


DECL_MODIFIED = {"func", "var", "let", "subscript", "init", "deinit", "case", "static", "final", "override", "convenience", "required"}


def names_log_token(entry):
    ids = [t.text for t in entry if t.kind == "id"]
    return bool(ids) and ids[-1] == "LogToken"


def top_level(body):
    """The tokens of a declaration body outside any nested braces: its own
    members, not what their bodies or nested types hold."""
    out, depth = [], 0
    for t in body:
        if t.kind == "punct" and t.text == "{":
            depth += 1
        elif t.kind == "punct" and t.text == "}":
            depth -= 1
        elif depth == 0:
            out.append(t)
    return out


def raw_value_members(body):
    """`rawValue` declared (`var`, `let`, `func`, `subscript`, `case`) or an
    `init(rawValue:)` at a body's top level, as (token, what)."""
    found = []
    top = top_level(body)
    for j, t in enumerate(top):
        if t.kind != "id":
            continue
        if t.text == "rawValue" and j > 0 and top[j - 1].kind == "id" and top[j - 1].text in ("var", "let", "func", "subscript", "case"):
            found.append((t, "rawValue"))
        if t.text == "init":
            m = j + 1
            while m < len(top) and top[m].kind == "op" and top[m].text in ("?", "!"):
                m += 1
            if m + 1 < len(top) and top[m].text == "(" and top[m + 1].kind == "id" and top[m + 1].text == "rawValue":
                found.append((t, "init(rawValue:)"))
    return found


def check_declaration(rel, flat, k):
    kw = flat[k].text
    line = flat[k].line
    if kw == "typealias":
        alias = flat[k + 1] if k + 1 < len(flat) else None
        if alias is not None and alias.kind == "id" and alias.text in SHADOWED_TYPES and rel != LOG_TOKEN_FILE:
            find("log", rel, line, "a typealias named `%s`, which would stand in for the real one" % alias.text)
        j = k + 1
        target = []
        seen_eq = False
        while j < len(flat) and flat[j].line == line:
            if flat[j].kind == "id" and flat[j].text == "LogToken":
                if rel != LOG_TOKEN_FILE:
                    find("log", rel, line, "a typealias for LogToken")
                return
            if seen_eq and flat[j].kind == "id":
                target.append(flat[j].text)
            if flat[j].kind == "op" and flat[j].text == "=":
                seen_eq = True
            j += 1
        if alias is not None and alias.kind == "id" and target:
            aliases[alias.text] = target[-1]
        return
    nxt = flat[k + 1] if k + 1 < len(flat) else None
    if nxt is None or nxt.kind != "id" or nxt.text in DECL_MODIFIED:
        # `class func`, `class var`: a modifier, not a type declaration.
        return
    name, inherits, lbrace, generic = declaration(flat, k)
    simple = name[-1].text if name and name[-1].kind == "id" else None
    if kw != "extension" and simple in SHADOWED_TYPES and rel != LOG_TOKEN_FILE:
        find("log", rel, line, "a %s named `%s`, which would stand in for the real one" % (kw, simple))
    if kw == "extension":
        body = flat[lbrace + 1 : matching(flat, lbrace)] if lbrace is not None else []
        if rel != LOG_TOKEN_FILE:
            extensions.append((rel, line, simple, body))
            if simple == "LogToken":
                find("log", rel, line, "an extension of LogToken outside %s" % LOG_TOKEN_FILE)
            # Measured: a `rawValue` from any extension the enum's
            # conformances reach (`extension RawRepresentable where Self:
            # LogToken`, `where Self == E`, through a typealias) replaces the
            # compiler's, so no extension declares one, whatever it extends.
            for tok, what in raw_value_members(body):
                find("log", rel, tok.line, "an extension declares `%s`, which can replace a token enum's words" % what)
            end = lbrace if lbrace is not None else len(flat)
            where = [x for x in flat[k:end] if x.kind == "id"]
            if "where" in [x.text for x in where] and "LogToken" in [x.text for x in where[[x.text for x in where].index("where") :]]:
                find("log", rel, line, "an extension constrained to LogToken outside %s" % LOG_TOKEN_FILE)
    if rel == LOG_TOKEN_FILE or not any(names_log_token(e) for e in inherits):
        return
    if kw != "enum":
        find("log", rel, line, "only an enum declaration may conform to LogToken (this is a %s)" % kw)
        return
    raw = [t.text for t in inherits[0]] if inherits else []
    if raw not in (["String"], ["Swift", ".", "String"]) or generic:
        find("log", rel, line, "a LogToken enum has the raw type String, written first, so its words are the compiler's raw values")
    if lbrace is None:
        find("log", rel, line, "a LogToken enum without a body this check can read")
        return
    body = flat[lbrace + 1 : matching(flat, lbrace)]
    if not cases_only(body):
        find("log", rel, line, "a LogToken enum holds only cases with literal raw values (no rawValue, init or other member)")
    if simple:
        log_token_enums.add(simple)


def cases_only(body):
    """`case a, b = "b"; case c` and nothing else: names, each with an
    optional raw value that is a plain string literal."""
    i = 0
    n = len(body)
    while i < n:
        if body[i].kind == "punct" and body[i].text == ";":
            i += 1
            continue
        if not (body[i].kind == "id" and body[i].text == "case"):
            return False
        i += 1
        while True:
            if i >= n or body[i].kind != "id":
                return False
            i += 1
            if i < n and body[i].kind == "op" and body[i].text == "=":
                if i + 1 >= n or body[i + 1].kind != "str" or interpolations(body[i + 1]):
                    return False
                i += 2
            if i < n and body[i].kind == "punct" and body[i].text == ",":
                i += 1
                continue
            break
    return True


def resolve(name):
    seen = set()
    while name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return name


def check_log_token_extensions():
    for rel, line, simple, body in extensions:
        simple = resolve(simple)
        if simple not in log_token_enums:
            continue
        # An extension of a token enum may add a conformance; its body
        # stays empty, so nothing beside the cases can change the words.
        if body:
            find("log", rel, body[0].line, "an extension of the LogToken enum `%s` declares something (only an empty extension, adding a conformance, is allowed)" % simple)


def literal_value(tok):
    """A string literal's value, its escapes decoded (\\r, \\n, \\u{...})."""
    out = []
    text = tok.text
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            e = text[i + 1]
            if e == "u" and text[i + 2 : i + 3] == "{":
                close = text.find("}", i + 3)
                if close > 0:
                    try:
                        out.append(chr(int(text[i + 3 : close], 16)))
                    except ValueError:
                        out.append(text[i : close + 1])
                    i = close + 1
                    continue
            out.append({"r": "\r", "n": "\n", "t": "\t", "0": "\0"}.get(e, e))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def gated_name(name):
    """A name that says it approves, reveals, replaces or removes:
    `approve`, `Reveal`, `removeKey`, `replaceValue`."""
    for verb in GATED_VERBS:
        if name in (verb, verb.capitalize()):
            return True
        for head in (verb, verb.capitalize()):
            if name.startswith(head) and len(name) > len(head) and name[len(head)].isupper():
                return True
    return False


def gated_call(span):
    """The first name in a span of code that says it approves, reveals,
    replaces or removes, or None."""
    for t in span:
        if t.kind == "id" and gated_name(t.text):
            return t.text
    return None


def closure_end(flat, k):
    """For a call or modifier named at flat[k]: the index of the last token
    of its arguments and trailing closures (`{...}` and `label: {...}`)."""
    end = k
    if k + 1 < len(flat) and flat[k + 1].kind == "punct" and flat[k + 1].text == "(":
        end = matching(flat, k + 1)
    j = end + 1
    while j < len(flat):
        t = flat[j]
        if t.kind == "punct" and t.text == "{":
            end = matching(flat, j)
            j = end + 1
            continue
        if t.kind == "id" and j + 2 < len(flat) and flat[j + 1].text == ":" and flat[j + 2].text == "{":
            end = matching(flat, j + 2)
            j = end + 1
            continue
        break
    return end


def check_gated_button(rel, flat, k):
    """A button is gated when its title (the first string literal in it)
    starts with Approve, Reveal, Replace or Remove, or when its action names
    one of them (`approve()`, `removeKey`)."""
    end = closure_end(flat, k)
    span = flat[k + 1 : end + 1]
    title = None
    for t in span:
        if t.kind == "str":
            title = t.text
            break
    what = None
    if title is not None:
        first = re.match(r"\s*([A-Za-z]+)", title)
        if first and first.group(1).lower() in GATED_VERBS:
            what = '"%s" button' % title.strip()
    if what is None:
        verb = gated_call(span)
        if verb:
            what = "button that runs `%s`" % verb
    if what is None:
        return
    # The modifier chain after the button.
    j = end + 1
    while j + 1 < len(flat) and flat[j].kind == "op" and flat[j].text == "." and flat[j + 1].kind == "id":
        name = flat[j + 1].text
        if name in ("keyboardShortcut", "onKeyPress"):
            find("gated-key", rel, flat[j + 1].line, "`%s` on a %s: these go through Touch ID, never a key alone" % (name, what))
            return
        j += 2
        if j < len(flat) and flat[j].kind == "punct" and flat[j].text == "(":
            j = matching(flat, j) + 1
        while j < len(flat) and flat[j].kind == "punct" and flat[j].text == "{":
            j = matching(flat, j) + 1


def check_color(rel, flat, k):
    t = flat[k]
    name = t.text

    def at(j):
        return flat[j] if 0 <= j < len(flat) else None

    lp = at(k + 1)
    calls = lp is not None and lp.kind == "punct" and lp.text == "("
    member = at(k - 1) is not None and at(k - 1).kind == "op" and at(k - 1).text.endswith(".")
    # `Color(`, `NSColor(`, `SwiftUI.Color(` and `Color.init(`; any other
    # callee, `.init(` and `Color.Resolved(` included, is judged by its
    # component labels alone.
    color_init = name == "init" and member and at(k - 2) is not None and at(k - 2).text in COLOR_TYPES
    qualified = member and at(k - 2) is not None and at(k - 2).text in SYSTEM_MODULES
    color_callee = (name in COLOR_TYPES and (not member or qualified)) or color_init
    if calls:
        args = call_args(flat, k + 1)
        labels = {label for label, _ in args if label is not None}
        first = args[0][1] if args else []
        if color_callee:
            if labels & COLOR_TYPE_LABELS:
                find("color", rel, t.line, "`%s(%s:...)` builds a colour from components (use an EnvCloakDesign token)" % (name, sorted(labels & COLOR_TYPE_LABELS)[0]))
            elif args and args[0][0] is None and first and first[0].kind == "op" and first[0].text == ".":
                find("color", rel, t.line, "`%s(.colorSpace, ...)` builds a colour from components" % name)
            elif (args and args[0][0] is None and is_literal(first)) or labels & COLOR_NAME_LABELS or "bundle" in labels:
                if not rel.startswith(DESIGN_SOURCES):
                    find("color", rel, t.line, "a catalog colour looked up by name outside EnvCloakDesign")
        elif labels & COLOR_COMPONENT_LABELS:
            find("color", rel, t.line, "`%s(%s:...)` builds a colour from components (use an EnvCloakDesign token)" % (name, sorted(labels & COLOR_COMPONENT_LABELS)[0]))
    if name in ("Color", "NSColor") and at(k + 1) is not None and at(k + 1).kind == "op" and at(k + 1).text == ".":
        m = at(k + 2)
        if m is not None and m.kind == "id" and (m.text in SYSTEM_COLORS or m.text.startswith("system")):
            find("color", rel, t.line, "`%s.%s` (use an EnvCloakDesign token)" % (name, m.text))
    if name in ("CGColor", "CIColor", "UIColor"):
        find("color", rel, t.line, "`%s` (use an EnvCloakDesign token)" % name)
    if name in IMPLICIT_COLORS:
        p, pp, a = at(k - 1), at(k - 2), at(k + 1)
        implicit = p is not None and p.kind == "op" and p.text == "." and (
            pp is None or (pp.kind == "punct" and pp.text in ("(", ",", ":", "[")) or (pp.kind == "op" and pp.text in ("?", ":", "=", "??"))
        )
        if implicit and not (a is not None and a.kind == "punct" and a.text == "("):
            find("color", rel, t.line, "`.%s` is a system colour (use an EnvCloakDesign token)" % name)


def inside(path, prefixes):
    norm = posixpath.normpath(path)
    return any(norm == p.rstrip("/") or norm.startswith(p) for p in prefixes)


def check_manifest(rel, toks):
    flat = flatten(toks)
    base = posixpath.dirname(rel)
    for k, t in enumerate(flat):
        if t.kind != "id":
            continue
        member = k > 0 and flat[k - 1].kind == "op" and flat[k - 1].text == "."
        calls = k + 1 < len(flat) and flat[k + 1].text == "("
        if t.text == "package" and member and calls:
            args = dict((label, expr) for label, expr in call_args(flat, k + 1) if label is not None)
            if "url" in args or "id" in args:
                find("remote-package", rel, t.line, "a package from outside this tree (only `.package(path:)` into %s)" % PACKAGES)
            elif "path" in args:
                path = unwrap(args["path"])
                if not is_literal(path) or path[0].parts and any(kind == "interp" for kind, _ in path[0].parts):
                    find("remote-package", rel, t.line, "a package path this check cannot read")
                elif path[0].text.startswith("/") or not inside(posixpath.join(base, path[0].text), [PACKAGES]):
                    find("remote-package", rel, t.line, "a package path outside %s" % PACKAGES)
            else:
                find("remote-package", rel, t.line, "a package this check cannot place")
        if t.text in ("binaryTarget", "systemLibrary", "plugin", "macro") and member:
            find("linked-code", rel, t.line, "`.%s`: code that is not Swift this check reads" % t.text)
        if t.text in ("unsafeFlags", "linkedLibrary", "linkedFramework", "plugins"):
            find("linked-code", rel, t.line, "`%s`: links or runs code this check does not read" % t.text)


# Text formats whose keys and settings the rules read.
PLIST_INPUTS = (".plist", ".entitlements", ".xcconfig", ".pbxproj", ".xcscheme", ".json", ".strings", ".xcstrings")
# Files that must parse as a property list.
PLIST_REQUIRED = (".plist", ".entitlements")
LOOKS_LIKE_PLIST = re.compile(r"\A\s*(?:<\?xml[^>]*>\s*)?(?:<!DOCTYPE\s+plist[^>]*>\s*)?<plist[\s>]")


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def decode_text(data):
    """A file's text: UTF-8, or UTF-16 or UTF-32 with a byte order mark;
    None for anything else holding a NUL byte."""
    for bom, codec in ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            try:
                return data.decode(codec)
            except UnicodeDecodeError:
                return None
    if b"\0" in data:
        return None
    return data.decode("utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8", "surrogateescape")


def plist_keys(value):
    """Every dictionary key in a parsed property list, at any depth."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from plist_keys(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from plist_keys(inner)


def check_text_file(rel, data, text):
    """The key and settings rules for one file under apps/macos. A property
    list is read parsed (XML in any encoding, or binary), whatever its name,
    so a binary or UTF-16 Info.plist or one named `Extra-Info.xml` is read
    like any other; one that must parse and does not, and a text input that
    is not text, are findings, never skipped."""
    looks = data.startswith(b"bplist") or (text is not None and LOOKS_LIKE_PLIST.match(text) is not None)
    parsed = None
    if looks or rel.endswith(PLIST_REQUIRED + (".strings",)):
        try:
            parsed = plistlib.loads(data)
        except Exception:  # noqa: BLE001 - any parse failure is handled below
            parsed = None
        if parsed is None and (looks or rel.endswith(PLIST_REQUIRED)):
            find("unreadable", rel, 0, "a property list this check cannot parse, so its keys would go unchecked")
    if parsed is not None:
        keys = set(plist_keys(parsed))
        for key in SIDE_DOOR_KEYS:
            if key in keys:
                find("side-door", rel, 0, "`%s` (SPEC §12 \"No side doors\")" % key)
        for key in LAUNCH_KEYS:
            if key in keys:
                find("launch-input", rel, 0, "`%s` sets the app's environment" % key)
    elif rel.endswith(PLIST_INPUTS):
        if text is None:
            find("unreadable", rel, 0, "not UTF-8 or UTF-16 text, so this check cannot read it")
        else:
            for key in SIDE_DOOR_KEYS:
                # `_` may come before a key: INFOPLIST_KEY_<Key> sets it from a build setting.
                for m in re.finditer(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9_])" % re.escape(key), text):
                    find("side-door", rel, line_of(text, m.start()), "`%s` (SPEC §12 \"No side doors\")" % key)
            for key in LAUNCH_KEYS:
                for m in re.finditer(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9_])" % re.escape(key), text):
                    find("launch-input", rel, line_of(text, m.start()), "`%s` sets the app's environment" % key)
    if text is not None and rel.endswith((".pbxproj", ".xcconfig")):
        for m in LINK_SETTINGS.finditer(text):
            find("linked-code", rel, line_of(text, m.start()), "`%s` links or includes code from outside the reviewed sources" % m.group(1))
    if text is not None and rel.endswith(".pbxproj"):
        check_pbxproj(rel, text)
    if rel.endswith(".entitlements"):
        if not isinstance(parsed, dict):
            find("entitlement", rel, 0, "not a property list dictionary this check can read")
        else:
            for key in sorted(parsed):
                if FORBIDDEN_ENTITLEMENT.fullmatch(key):
                    find("entitlement", rel, 0, "`%s` is never signed into EnvCloak (D3-05, D3-06)" % key)
                else:
                    find("entitlement", rel, 0, "`%s`: no signing tier signs an entitlement yet (M3-10 adds the keychain group's)" % key)


def check_pbxproj(rel, text):
    project_dir = posixpath.dirname(posixpath.dirname(rel))  # apps/macos
    if "XCRemoteSwiftPackageReference" in text:
        find("remote-package", rel, line_of(text, text.index("XCRemoteSwiftPackageReference")), "a remote Swift package reference (only local packages)")
    for m in re.finditer(r"isa = XCLocalSwiftPackageReference;\s*relativePath = (\"?)([^\";\n]*)\1;", text):
        target = m.group(2)
        if target.startswith("/") or not inside(posixpath.join(project_dir, target), [PACKAGES]):
            find("remote-package", rel, line_of(text, m.start()), "a local package outside %s" % PACKAGES)
    for name in PBX_CODE_OBJECTS:
        for m in re.finditer(r"isa = %s;" % name, text):
            find("linked-code", rel, line_of(text, m.start()), "a `%s` runs code this check does not read" % name)
    for m in re.finditer(r"\{[^{}]*isa = PBXFileReference;[^{}]*\}", text):
        ref = m.group(0)
        if LINKABLE_TYPE.search(ref) and not re.search(r"sourceTree = (SDKROOT|BUILT_PRODUCTS_DIR);", ref):
            find("linked-code", rel, line_of(text, m.start()), "a library or framework reference other than the SDK's")
    for m in re.finditer(r"sourceTree = \"?<absolute>\"?;", text):
        find("linked-code", rel, line_of(text, m.start()), "a reference by absolute path")
    for m in re.finditer(r"(?<![A-Za-z])path = (\"?)([^\";\n]*)\1;", text):
        path = m.group(2)
        if path.startswith("/") or (".." in path.split("/") and not inside(posixpath.join(project_dir, path), [APP + "/", BRAND])):
            find("linked-code", rel, line_of(text, m.start()), "a path outside %s/ and %s: `%s`" % (APP, BRAND, path))


def check_tree_file(rel, real):
    segments = rel.split("/")
    for seg in segments[2:]:
        if seg.lower().endswith(COMPILED_SUFFIXES):
            find("linked-code", rel, 0, "`%s`: a source kind that compiles into the app as something other than the Swift this check reads" % seg)
            return
    if any(s.endswith((".framework", ".xcframework")) for s in segments[:-1]) or rel.endswith(BINARY_SUFFIXES):
        find("linked-code", rel, 0, "a library or framework in the tree")
        return
    try:
        with open(real, "rb") as f:
            head = f.read(8)
    except OSError:
        return
    if head[:4] in MACHO_MAGIC or head == b"!<arch>\n":
        find("linked-code", rel, 0, "a Mach-O or archive file in the tree")


def key_patterns(root):
    pats = []
    pdir = os.path.join(root, "providers")
    if not os.path.isdir(pdir) or tomllib is None:
        find("key-literal", "providers/", 0, "cannot read the provider key patterns (providers/*.toml with python3 tomllib)")
        return pats
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".toml"):
            continue
        with open(os.path.join(pdir, name), "rb") as f:
            data = tomllib.load(f)
        for p in data.get("key_patterns", []):
            body = p
            if body.startswith("^"):
                body = body[1:]
            if body.endswith("$"):
                body = body[:-1]
            pats.append((name, re.compile(body)))
    if not pats:
        find("key-literal", "providers/", 0, "no provider key pattern found, so nothing was scanned")
    return pats


def check_key_literals(rel, text, pats):
    for name, pat in pats:
        for m in pat.finditer(text):
            find("key-literal", rel, line_of(text, m.start()), "a string shaped like a key (%s); generate test values at run time" % name)


def read_allowlist(root, path, with_rule):
    entries = []
    full = os.path.join(root, path)
    if not os.path.exists(full):
        find("allowlist", path, 0, "missing")
        return entries
    with open(full, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            body, sep, reason = line.partition("#")
            words = body.split()
            if not sep or not reason.strip():
                find("allowlist", path, n, "an entry without a reason after `#`")
                continue
            if with_rule:
                if len(words) != 2:
                    find("allowlist", path, n, "an entry is `<rule> <path>  # <reason>`")
                    continue
                rule, target = words
                if rule not in ALLOWLISTABLE:
                    find("allowlist", path, n, "rule `%s` cannot be allowlisted (allowlistable: %s)" % (rule, ", ".join(sorted(ALLOWLISTABLE))))
                    continue
            else:
                if len(words) != 1:
                    find("allowlist", path, n, "an entry is `<path>  # <reason>`")
                    continue
                rule, target = "unsafe-bytes", words[0]
            if not os.path.isfile(os.path.join(root, target)) or classify(target) != "product":
                find("allowlist", path, n, "`%s` is not a product Swift file in this tree" % target)
                continue
            entries.append((rule, target, path, n))
    return entries


def main(argv):
    args = argv[1:]
    list_only = False
    root = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    while args:
        a = args.pop(0)
        if a == "--list-swift":
            list_only = True
        elif a == "--root" and args:
            root = os.path.realpath(args.pop(0))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    if not os.path.isdir(os.path.join(root, APP)):
        print("check-swift: %s has no %s" % (root, APP), file=sys.stderr)
        return 2

    files = repo_files(root)
    brand_root = os.path.realpath(os.path.join(root, BRAND))
    swift = []  # (rel, real path, class, brand)
    texts = []  # (rel, real path)
    for rel in files:
        full = os.path.join(root, rel)
        brand = False
        if os.path.islink(full):
            target = os.path.realpath(full)
            if not (target + os.sep).startswith(brand_root + os.sep) or not os.path.exists(target):
                find("symlink", rel, 0, "a symbolic link that does not resolve inside %s" % BRAND)
                continue
            if os.path.isdir(target):
                find("symlink", rel, 0, "a symbolic link to a directory")
                continue
            brand = True
        if os.path.isdir(full):
            continue
        cls = classify(rel)
        if cls is not None:
            swift.append((rel, os.path.realpath(full), cls, brand))
        texts.append((rel, os.path.realpath(full)))

    if list_only:
        for rel, real, cls, brand in swift:
            if cls in ("product", "test"):
                print("%s %s" % (cls, real))
        return 0

    pats = key_patterns(root)
    for rel, real in texts:
        check_tree_file(rel, real)
        with open(real, "rb") as f:
            data = f.read()
        text = decode_text(data)
        check_text_file(rel, data, text)
        # A file that is not text is read byte for byte.
        check_key_literals(rel, text if text is not None else data.decode("latin-1"), pats)

    for rel, real, cls, brand in swift:
        if cls == "stray":
            find("stray-swift", rel, 0, "a Swift file outside the app's product and test roots (classify it in scripts/macos/check_swift.py)")
            continue
        if cls == "test":
            continue
        text = read_text(real)
        if text is None:
            find("lex", rel, 0, "not a text file")
            continue
        try:
            toks = Lexer(text).lex()
        except LexError as e:
            find("lex", rel, e.line, str(e))
            continue
        if cls == "manifest":
            check_manifest(rel, toks)
        else:
            check_product_swift(rel, toks, brand)
    check_log_token_extensions()

    # Allowlists: each entry needs a reason, names a product file, and must
    # still be needed; a finding it covers is dropped.
    entries = read_allowlist(root, EXPOSE_ALLOWLIST, with_rule=False) + read_allowlist(root, RULE_ALLOWLIST, with_rule=True)
    allowed = {(rule, target) for rule, target, _, _ in entries}
    used = set()
    kept = []
    for f in findings:
        key = (f[0], f[1])
        if key in allowed:
            used.add(key)
        else:
            kept.append(f)
    for rule, target, path, n in entries:
        if (rule, target) not in used:
            kept.append(("allowlist", path, n, "`%s %s` allows nothing in that file now; remove it" % (rule, target)))

    for rule, path, line, msg in sorted(kept, key=lambda f: (f[1], f[2], f[0])):
        where = "%s:%d" % (path, line) if line else path
        print("check-swift: [%s] %s: %s" % (rule, where, msg), file=sys.stderr)
    product = sum(1 for s in swift if s[2] == "product")
    if kept:
        print("check-swift: %d finding(s) in %d product Swift file(s)" % (len(kept), product), file=sys.stderr)
        return 1
    if product == 0:
        print("check-swift: no product Swift file found under %s, so nothing was checked" % APP, file=sys.stderr)
        return 1
    print("check-swift: ok (%d product Swift files, %d text files)" % (product, len(texts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
