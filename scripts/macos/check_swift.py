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
a new source root is classified here before anything can compile it.

Rules (the id is what a finding and an allowlist entry name):

  unsafe-bytes   `withUnsafeBytes` / `withUnsafeMutableBytes`, the way into
                 a SecretBuffer's bytes, only in files listed in
                 apps/macos/security/expose-allowlist.txt (rule 1).
  storage        `@SceneStorage` and `NSUbiquitousKeyValueStore`: state the
                 system saves for the app (rule 1).
  launch-input   anything the starter of the app controls: `CommandLine`,
                 `.arguments`, `.environment` (other than SwiftUI's
                 `.environment(...)` modifier), `getenv`, `environ`,
                 `_NSGetArgv`, `_NSGetArgc`, `_NSGetEnviron`, the standard
                 input, `UserDefaults` and `@AppStorage` (launch arguments
                 `-key value` land in the defaults' argument domain).
  side-door      SPEC §12 "No side doors": Info.plist keys for URL schemes,
                 AppleScript, Services, documents, exported types, Handoff
                 and extensions (in every file), and in Swift: App Intents,
                 Intents, Spotlight, `onOpenURL`, `handlesExternalEvents`,
                 Apple event handlers, services providers, user activities
                 and the app delegate's open callbacks (rule 2).
  a11y-action    accessibility actions, which another program can perform
                 (rule 2: none may approve, reveal or write).
  gated-key      a keyboard shortcut on a button whose title starts with
                 Approve, Reveal, Replace or Remove (rule 2).
  log            `print`, `debugPrint`, `dump`, `NSLog` and the C stdio
                 writers; in a log call (`os_log`, or a `Logger` level
                 method given a string literal) every interpolation is
                 `\\(x.logToken)` (rule 3: a launch environment can make the
                 log store "private" arguments in the clear, docs/APP.md
                 "Logging"); `privacy: .public` only on such a token;
                 `%{public}` nowhere; only an `enum` conforms to `LogToken`
                 and only EnvCloakKit's Log/LogToken.swift declares
                 `logToken`.
  daemon-text    `.unescaped`, the raw text of a string the daemon sent
                 (`DaemonText`, M3-03), outside the allowlist: views show
                 daemon text only through `Escape.display` (rule 4).
  color          a colour not from EnvCloakDesign's tokens: colour
                 initialisers from components, `#colorLiteral`, CGColor,
                 CIColor, UIColor, named system colours, and catalog
                 lookups by name outside EnvCloakDesign (rule 5).
  remote-package a Swift package from anywhere but this tree (rule:
                 no third-party code and no analytics SDK, R-M3-24).
  entitlement    `com.apple.security.get-task-allow`, any
                 `com.apple.security.cs.` (hardened-runtime exception) or
                 `com.apple.security.temporary-exception.` key in an
                 entitlements file (D3-05, D3-06).
  key-literal    a string matching a provider's key pattern
                 (providers/*.toml) in any text file (rule 7).
  symlink        a symbolic link that does not resolve inside assets/brand/.
  stray-swift    a Swift file outside the product and test roots.
  lex            a Swift file the lexer cannot read whole.
  allowlist      a malformed, unknown, missing or unused allowlist entry.

The brand's own Swift (assets/brand/motion/swiftui/EnvCloakMotion.swift,
reached through a symlink in EnvCloakDesign) is product code and held to
every rule but `color`: it defines the brand colours.

Usage: check-swift.sh [--root DIR]       check the tree (default: the repo)
       check-swift.sh --list-swift [--root DIR]
                                         print every Swift file read, one per
                                         line, as the real path, and check
                                         nothing (scripts/check-sources.sh
                                         --swift compares it with what the
                                         compiler read)
"""

import os
import re
import subprocess
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

APP = "apps/macos"
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
}
GATED_VERBS = ("approve", "reveal", "replace", "remove")
PRINTERS = {
    "print",
    "debugPrint",
    "dump",
    "NSLog",
    "NSLogv",
    "puts",
    "fputs",
    "printf",
    "fprintf",
    "vprintf",
    "vfprintf",
    "putchar",
    "perror",
    "fwrite",
}
STDIO_WRITERS = {"standardError", "standardOutput", "stderr", "stdout"}
LOG_LEVELS = {"debug", "info", "notice", "error", "warning", "fault", "critical", "trace", "log"}
LAUNCH_NAMES = {
    "CommandLine",
    "getenv",
    "secure_getenv",
    "environ",
    "_NSGetEnviron",
    "_NSGetArgv",
    "_NSGetArgc",
    "standardInput",
    "readLine",
    "stdin",
    "NSArgumentDomain",
    "argumentDomain",
    "UserDefaults",
    "NSUserDefaults",
}
STORAGE_NAMES = {"NSUbiquitousKeyValueStore"}
COLOR_TYPES = {"Color", "NSColor"}
COLOR_COMPONENT_LABELS = {
    "red",
    "srgbRed",
    "calibratedRed",
    "deviceRed",
    "displayP3Red",
    "white",
    "calibratedWhite",
    "deviceWhite",
    "genericGamma22White",
    "hue",
    "calibratedHue",
    "deviceHue",
    "deviceCyan",
    "colorSpace",
    "cgColor",
    "ciColor",
    "nsColor",
    "uiColor",
    "hex",
    "catalogName",
    "patternImage",
}
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

findings = []


def find(rule, path, line, msg):
    findings.append((rule, path, line, msg))


# ---------------------------------------------------------------- the lexer


class LexError(Exception):
    def __init__(self, line, msg):
        super().__init__(msg)
        self.line = line


class Tok:
    __slots__ = ("kind", "text", "line", "parts")

    def __init__(self, kind, text, line, parts=None):
        self.kind = kind  # id, num, str, op, punct, attr, pound, regex
        self.text = text
        self.line = line
        self.parts = parts  # for str: [("lit", text) | ("interp", [Tok])]

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
        return Tok("str", text, start_line, parts), j


def flatten(toks):
    """Every code token, descending into interpolations, in source order."""
    out = []
    for t in toks:
        out.append(t)
        if t.kind == "str":
            for kind, part in t.parts:
                if kind == "interp":
                    out.extend(flatten(part))
    return out


def strings(toks):
    """Every string literal, inside interpolations too."""
    return [t for t in flatten(toks) if t.kind == "str"]


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
    ids = [(k, t) for k, t in enumerate(flat)]

    def prev(k, back=1):
        return flat[k - back] if k - back >= 0 else None

    def nxt(k, ahead=1):
        return flat[k + ahead] if k + ahead < len(flat) else None

    def is_member(k):
        p = prev(k)
        return p is not None and p.kind == "op" and p.text.endswith(".")

    for k, t in ids:
        if t.kind == "id":
            name = t.text
            after = nxt(k)
            calls = after is not None and after.kind == "punct" and after.text == "("
            # rule 1
            if name in ("withUnsafeBytes", "withUnsafeMutableBytes"):
                find("unsafe-bytes", rel, t.line, "`%s` outside %s" % (name, EXPOSE_ALLOWLIST))
            if name in STORAGE_NAMES:
                find("storage", rel, t.line, "`%s` keeps state the system saves for the app" % name)
            # launch inputs
            if name in LAUNCH_NAMES:
                find("launch-input", rel, t.line, "`%s` reads what the app's starter controls" % name)
            if name == "arguments" and is_member(k):
                find("launch-input", rel, t.line, "`.arguments` (the app reads no launch argument)")
            if name == "environment" and is_member(k) and not calls:
                find("launch-input", rel, t.line, "`.environment` (the app reads no environment variable)")
            # rule 2
            if name in SIDE_DOOR_NAMES:
                find("side-door", rel, t.line, "`%s` is a way in that skips the gated sheets (SPEC §12)" % name)
            if name == "import":
                mod = nxt(k)
                if mod is not None and mod.kind == "id" and mod.text in SIDE_DOOR_IMPORTS:
                    find("side-door", rel, t.line, "`import %s` (SPEC §12 \"No side doors\")" % mod.text)
            if name == "func" and nxt(k) is not None and nxt(k).text == "application":
                lp = k + 2
                if lp < len(flat) and flat[lp].text == "(":
                    rp = matching(flat, lp)
                    labels = {x.text for x in flat[lp:rp] if x.kind == "id"}
                    hit = labels & OPEN_CALLBACK_LABELS
                    if hit:
                        find("side-door", rel, t.line, "an app delegate callback that opens input from outside (%s)" % ", ".join(sorted(hit)))
            if name in A11Y_NAMES:
                find("a11y-action", rel, t.line, "`%s`: another program can perform it" % name)
            if name == "Button" and after is not None and after.kind == "punct" and after.text in ("(", "{"):
                check_gated_button(rel, flat, k)
            # rule 3
            if name in PRINTERS and calls:
                p = prev(k)
                member_of_other = p is not None and p.kind == "op" and p.text == "." and not (prev(k, 2) is not None and prev(k, 2).text == "Swift")
                if not member_of_other:
                    find("log", rel, t.line, "`%s` writes outside the unified log (use Logger with LogToken)" % name)
            if name in PRINTERS and prev(k) is not None and prev(k).text == "func":
                find("log", rel, t.line, "a function named `%s`" % name)
            if name in STDIO_WRITERS:
                find("log", rel, t.line, "`%s` writes to a standard stream" % name)
            if name == "logToken" and rel != LOG_TOKEN_FILE:
                p = prev(k)
                if p is not None and p.kind == "id" and p.text in ("var", "let", "func", "case", "subscript"):
                    find("log", rel, t.line, "`logToken` is declared only in %s" % LOG_TOKEN_FILE)
            if name in ("enum", "struct", "class", "actor", "extension", "protocol", "typealias") and rel != LOG_TOKEN_FILE:
                check_log_token_conformance(rel, flat, k)
            if name == "os_log" and calls:
                check_log_call(rel, flat, k + 1)
            if name in LOG_LEVELS and calls and is_member(k):
                check_log_call(rel, flat, k + 1)
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
        elif t.kind == "pound":
            if t.text == "#colorLiteral" and not brand:
                find("color", rel, t.line, "`#colorLiteral` (use an EnvCloakDesign token)")
        elif t.kind == "str":
            if "%{public" in t.text:
                find("log", rel, t.line, "`%{public}` in a format string")
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


def check_log_call(rel, flat, lp):
    """flat[lp] is the `(` of a log call. Its first top-level string
    argument is the message; each interpolation must be `x.logToken`."""
    if lp >= len(flat) or flat[lp].text != "(":
        return
    rp = matching(flat, lp)
    # The message is a direct argument: a string literal at depth 1, alone
    # or after a label.
    depth = 0
    message = None
    for j in range(lp, rp + 1):
        t = flat[j]
        if t.kind == "punct" and t.text in "([{":
            depth += 1
            continue
        if t.kind == "punct" and t.text in ")]}":
            depth -= 1
            continue
        if depth == 1 and t.kind == "str":
            message = t
            break
    if message is None:
        return
    for inner in interpolations(message):
        args = split_top(inner)
        if not is_log_token_expr(args[0]):
            find(
                "log",
                rel,
                message.line,
                "a log message interpolates something other than `x.logToken` (a launch environment can make private arguments public)",
            )


def check_log_token_conformance(rel, flat, k):
    kw = flat[k].text
    if kw == "typealias":
        j = k + 1
        while j < len(flat) and flat[j].line == flat[k].line:
            if flat[j].kind == "id" and flat[j].text == "LogToken":
                find("log", rel, flat[k].line, "a typealias for LogToken")
                return
            j += 1
        return
    j = k + 1
    seen_colon = False
    while j < len(flat):
        t = flat[j]
        if t.kind == "punct" and t.text in ("{", ";"):
            break
        if t.kind == "id" and t.text == "where":
            break
        if t.kind == "punct" and t.text == ":":
            seen_colon = True
        if seen_colon and t.kind == "id" and t.text == "LogToken" and kw != "enum":
            find("log", rel, flat[k].line, "only an enum declaration may conform to LogToken (this is a %s)" % kw)
            return
        j += 1


def check_gated_button(rel, flat, k):
    lp = k + 1
    if flat[lp].text == "(":
        end = matching(flat, lp)
    else:
        end = k
    # Trailing closures: `{...}` and `label: {...}`.
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
    span = flat[lp : end + 1]
    title = None
    for t in span:
        if t.kind == "str":
            title = t.text
            break
    if title is None:
        return
    first = re.match(r"\s*([A-Za-z]+)", title)
    if not first or first.group(1).lower() not in GATED_VERBS:
        return
    # The modifier chain after the button.
    j = end + 1
    while j + 1 < len(flat) and flat[j].kind == "op" and flat[j].text == "." and flat[j + 1].kind == "id":
        name = flat[j + 1].text
        if name in ("keyboardShortcut", "onKeyPress"):
            find("gated-key", rel, flat[j + 1].line, "`%s` on a \"%s\" button: these go through Touch ID, never a key alone" % (name, title.strip()))
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

    if name in COLOR_TYPES or (name == "init" and at(k - 1) is not None and at(k - 1).text == "."):
        lp = at(k + 1)
        if lp is not None and lp.text == "(":
            first = at(k + 2)
            label = first.text if first is not None and first.kind == "id" and at(k + 3) is not None and at(k + 3).text == ":" else None
            if label in COLOR_COMPONENT_LABELS:
                find("color", rel, t.line, "`%s(%s:...)` builds a colour from components (use an EnvCloakDesign token)" % (name, label))
            elif first is not None and first.kind == "op" and first.text == "." and name != "init":
                find("color", rel, t.line, "`%s(.colorSpace, ...)` builds a colour from components" % name)
            elif (first is not None and first.kind == "str") or label in COLOR_NAME_LABELS or has_label(flat, k + 1, "bundle"):
                if name != "init" and not rel.startswith(DESIGN_SOURCES):
                    find("color", rel, t.line, "a catalog colour looked up by name outside EnvCloakDesign")
        if name in COLOR_TYPES and at(k + 1) is not None and at(k + 1).kind == "op" and at(k + 1).text == ".":
            member = at(k + 2)
            if member is not None and member.kind == "id" and (member.text in SYSTEM_COLORS or member.text.startswith("system")):
                find("color", rel, t.line, "`%s.%s` (use an EnvCloakDesign token)" % (name, member.text))
    if name in ("CGColor", "CIColor", "UIColor"):
        find("color", rel, t.line, "`%s` (use an EnvCloakDesign token)" % name)
    if name in IMPLICIT_COLORS:
        p, pp, a = at(k - 1), at(k - 2), at(k + 1)
        implicit = p is not None and p.kind == "op" and p.text == "." and (
            pp is None or (pp.kind == "punct" and pp.text in ("(", ",", ":", "[")) or (pp.kind == "op" and pp.text in ("?", ":", "=", "??"))
        )
        if implicit and not (a is not None and a.kind == "punct" and a.text == "("):
            find("color", rel, t.line, "`.%s` is a system colour (use an EnvCloakDesign token)" % name)


def has_label(flat, lp, label):
    """Whether the call whose `(` is flat[lp] has a top-level `label:`."""
    rp = matching(flat, lp)
    depth = 0
    for j in range(lp, rp):
        t = flat[j]
        if t.kind == "punct" and t.text in "([{":
            depth += 1
        elif t.kind == "punct" and t.text in ")]}":
            depth -= 1
        elif depth == 1 and t.kind == "id" and t.text == label and flat[j + 1].text == ":":
            return True
    return False


def check_manifest(rel, toks):
    flat = flatten(toks)
    for k, t in enumerate(flat):
        if t.kind == "id" and t.text == "package" and k > 0 and flat[k - 1].text == "." and k + 1 < len(flat) and flat[k + 1].text == "(":
            rp = matching(flat, k + 1)
            labels = {x.text for x in flat[k + 2 : rp] if x.kind == "id"}
            if labels & {"url", "id"}:
                find("remote-package", rel, t.line, "a package from outside this tree (only `.package(path:)`)")


PLIST_INPUTS = (".plist", ".entitlements", ".xcconfig", ".pbxproj", ".xcscheme", ".json", ".strings", ".xcstrings")


def check_text_file(rel, text):
    if not rel.endswith(PLIST_INPUTS):
        return
    for key in SIDE_DOOR_KEYS:
        # `_` may come before a key: INFOPLIST_KEY_<Key> sets it from a build setting.
        for m in re.finditer(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9_])" % re.escape(key), text):
            find("side-door", rel, text.count("\n", 0, m.start()) + 1, "`%s` (SPEC §12 \"No side doors\")" % key)
    if rel.endswith(".pbxproj") and "XCRemoteSwiftPackageReference" in text:
        find("remote-package", rel, 1, "a remote Swift package reference (only local packages)")
    if rel.endswith(".entitlements") or rel.endswith(".plist") or rel.endswith(".xcconfig") or rel.endswith(".pbxproj"):
        for m in FORBIDDEN_ENTITLEMENT.finditer(text):
            if rel.endswith(".entitlements"):
                find("entitlement", rel, text.count("\n", 0, m.start()) + 1, "`%s` is never signed into EnvCloak (D3-05, D3-06)" % m.group(0))


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
            find("key-literal", rel, text.count("\n", 0, m.start()) + 1, "a string shaped like a key (%s); generate test values at run time" % name)


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
                print(real)
        return 0

    pats = key_patterns(root)
    for rel, real in texts:
        text = read_text(real)
        if text is None:
            continue
        check_text_file(rel, text)
        check_key_literals(rel, text, pats)

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
