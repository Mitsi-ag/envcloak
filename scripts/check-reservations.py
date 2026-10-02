#!/usr/bin/env python3
"""Checks the names and numbers reserved for the M2 and M2b tasks (plan
decision D-23) against each other and against the code.

Two lanes that append to the same fixed table can pick the same number or
name (review R-7). So every shared registry the M2 and M2b tasks add to is
assigned up front, in tables between `<!-- reservations:<registry> -->` and
`<!-- /reservations -->` markers in docs/IPC.md ("Reserved for M2 and M2b")
and docs/VAULT.md (the same heading). A task takes the rows it is named in;
to take another, or a new one, it changes the table in its own pull request.

Each row has a status: `reserved` (not in the code yet), `landed` (in the
code exactly as the row says) or `reuse` (an entry the code already has,
which a task uses again for a new case). This script refuses:

- a table that is missing, doubled, unknown or malformed (wrong columns, a
  name cell that is not one backticked name, a number that is not one);
- a name, or a number in a numbered table, used twice in one table; the
  coverage tokens (states, reasons and probe outcomes) share one namespace;
- a name in two of the tables whose tokens reach the person as
  `envcloak: <token>` (error kinds, reasons, the CLI's own failure tokens
  and sign-in tokens), unless SHARED below names it with both tables, and a
  `reserved` row in one of them whose name the code already uses in
  another;
- a malformed name, an unknown task or status, a spare row that is not
  `reserved`, or a number outside the table's reserved range;
- against the code, where the registry has a source the script reads: a
  `reserved` row whose name or number the code already uses, a `landed`
  row the code does not hold exactly so, a `reuse` row the code does not
  hold, and a code entry that no `landed` or `reuse` row accounts for and
  that is not in the baseline, scripts/check-reservations-baseline.txt:
  the entries the code held before the reservations (M1), which only
  shrinks. A baseline line the code no longer holds exactly so is refused
  too. A code source that yields nothing is an error, never an empty
  registry, and so is a code source that gives one number or token to two
  entries, or two tokens or codes to one.

Each code reader reads every declaration of its registry or refuses it, so
no entry is skipped unread (Codex review of PR #14): every variant of a
numbered enum is written `Name = <integer literal>` (decimal, hexadecimal,
octal or binary, with `_` separators and a type suffix), and a variant
without a number, with a number that is not an integer literal, or that is
not a unit variant is an error; every `AuditKind` and `ErrorKind` variant
has exactly one arm `Enum::Name => <value>` (or, in the enum's own `impl`,
`Self::Name`) in `fn token` and `fn code`, and a variant without one the
reader can read is an error; every `impl Method for` block in the
`envcloak-ipc` crate holds exactly one `const NAME` whose value is one
string literal, and a `const NAME` of another form or elsewhere is an
error; every entry of `REASONS` is one string literal; every MCP tool is
a `const TOOL: &str = "<name>";` in the `envcloak-mcp` crate, and a
`const TOOL` of another form, or one name declared twice, is an error.
String literals are read in every form Rust has (plain, raw, byte and C
strings), with their escapes decoded.

The CLI's failure tokens are read from every crate's `src/` (comments and
`#[cfg(test)]` modules left out): the first argument of `Failure::new` and
of every function whose first parameter is `token: &'static str` (or
`ExitToken`), every `token: <value>` field, every string in the body of a
`fn token`, and the `<token>` of every string literal that starts
`envcloak: <token>:` (a line printed directly, as `eprintln!` does for
`coverage`, `warning` and `usage`), whatever crate it is in. A value
written as a `&str` constant counts by the constant's string. The reader
over-counts rather than under-counts: a string it takes for a token that
is not printed makes a `reserved` row with that name fail, which is a
name to avoid anyway, and a new one needs a `landed` row like any token.
It also takes the tokens of audit kinds, error kinds and reasons, so a
`landed` or `reuse` row in any table accounts for a failure token.

Usage: scripts/check-reservations.py [--root <repository root>]
Prints "check-reservations: ok" and exits 0, or names every problem on
stderr and exits 1.
"""

import os
import re
import sys

DOCS = ("docs/IPC.md", "docs/VAULT.md")

TOKEN = re.compile(r"^[a-z][a-z0-9_]*$")
METHOD = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
FIELD = re.compile(r"^[a-z][a-z0-9_]*(=[a-z][a-z0-9_]*)?$")
MESSAGE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
DOMAIN = re.compile(r"^envcloak-[a-z0-9-]+/[1-9][0-9]*$")
TOOL = re.compile(r"^[a-z][a-z0-9_]*(_\*)?$")

TASKS = (
    {"M2-%02d" % n for n in range(1, 29)}
    | {"M2b-%02d" % n for n in range(1, 12)}
    | {"M%d" % n for n in range(3, 12)}
    | {"spare"}
)
STATUSES = ("reserved", "landed", "reuse")
COVERAGE_KINDS = ("state", "reason", "outcome")

# The tables whose tokens the person reads as `envcloak: <token>`: one
# namespace, so one name never means two things there (R-7).
PRINTED = ("error_kind", "reason", "exit_token", "signin_token")

# A name meant to be the same token in two of the PRINTED tables, with the
# tables it may be in. Empty: no reserved name is shared today. An entry
# needs a code owner's agreement that both rows mean one thing (this file
# is code-owned, .github/CODEOWNERS).
SHARED = {}

# Code sources, relative to the root.
AUDIT_RS = "crates/envcloak-core/src/audit/record.rs"
AAD_RS = "crates/envcloak-core/src/crypto/aad.rs"
PROTO_RS = "crates/envcloak-ipc/src/proto.rs"
CRATES = "crates"
BASELINE = "scripts/check-reservations-baseline.txt"

problems = []


def fail(msg):
    problems.append(msg)


class SourceError(Exception):
    pass


def read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as e:
        raise SourceError("%s could not be read (%s)" % (rel, getattr(e, "strerror", None) or e))


# --- Reading Rust source ---------------------------------------------------

SCAN = re.compile(r"//|/\*|\b[bc]?r#*\"|\b[bc]\"|\"|'")
BLOCK_COMMENT = re.compile(r"/\*|\*/")
STRING_END = re.compile(r"\\.|\"", re.S)
CHAR = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'")
BRACE = re.compile(r"[{}]")
BODY_OR_END = re.compile(r"[{;]")
TEST_MOD = re.compile(
    r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
)
NOT_NEWLINE = re.compile(r"[^\n]")
ESCAPE = re.compile(r"\\(?:([nrt0\\'\"])|x([0-9a-fA-F]{2})|u\{([0-9a-fA-F_]{1,8})\}|(\r?\n[ \t\r\n]*)|(.))", re.S)
SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def _blanked(s):
    return NOT_NEWLINE.sub(" ", s)


def _blank_spans(text, spans):
    out, last = [], 0
    for a, b in sorted(spans):
        out.append(text[last:a])
        out.append(_blanked(text[a:b]))
        last = b
    out.append(text[last:])
    return "".join(out)


def unescape(rel, s):
    """The value of a non-raw Rust string literal's contents `s`."""

    def one(m):
        simple, byte, uni, continuation, other = m.groups()
        if simple is not None:
            return SIMPLE_ESCAPES[simple]
        if byte is not None:
            return chr(int(byte, 16))
        if uni is not None:
            digits = uni.replace("_", "")
            try:
                return chr(int(digits, 16))
            except ValueError:
                raise SourceError("%s: a string literal holds the escape `\\u{%s}`, which is no character" % (rel, uni))
        if continuation is not None:
            return ""
        raise SourceError("%s: a string literal holds the escape `\\%s`, which the reader does not know" % (rel, other))

    return ESCAPE.sub(one, s)


class Source:
    """One Rust file as two views of the same length: `code`, with comments
    blanked, and `skel`, also with the inside of every string and character
    literal blanked, so that structure (braces, commas, `token:`) is found
    in `skel` and literals are read from `code` at the same offsets.
    `#[cfg(test)]` modules are blanked in both. Every string literal, raw
    (`r"..."`, `r#"..."#`), byte or C string or not, is kept by where it
    starts, with its value: escapes decoded, raw contents as written."""

    def __init__(self, rel, text):
        self.rel = rel
        comments, contents, strings = [], [], []
        n, i = len(text), 0
        while True:
            m = SCAN.search(text, i)
            if not m:
                break
            s, tok = m.start(), m.group(0)
            if tok == "//":
                j = text.find("\n", s)
                j = n if j < 0 else j
                comments.append((s, j))
                i = j
            elif tok == "/*":
                depth, j = 1, s + 2
                while depth:
                    k = BLOCK_COMMENT.search(text, j)
                    if not k:
                        j = n
                        break
                    depth += 1 if k.group(0) == "/*" else -1
                    j = k.end()
                comments.append((s, j))
                i = j
            elif tok == "'":
                c = CHAR.match(text, s)
                if c:
                    contents.append((s + 1, c.end() - 1))
                    i = c.end()
                else:
                    i = s + 1
            elif "r" not in tok:
                quote = m.end() - 1
                j = quote + 1
                while True:
                    k = STRING_END.search(text, j)
                    if not k:
                        j = n
                        break
                    if k.group(0) == '"':
                        j = k.start()
                        break
                    j = k.end()
                contents.append((quote + 1, j))
                strings.append((s, quote, j, min(j + 1, n), False))
                i = j + 1
            else:
                close = '"' + tok[tok.index("r") + 1: -1]
                j = text.find(close, m.end())
                j = n if j < 0 else j
                contents.append((m.end(), j))
                strings.append((s, m.end() - 1, j, min(j + len(close), n), True))
                i = j + len(close)
        self.code = _blank_spans(text, comments)
        self.skel = _blank_spans(text, comments + contents)
        tests = []
        for m in TEST_MOD.finditer(self.skel):
            if not tests or m.start() >= tests[-1][1]:
                tests.append((m.start(), self.block_end(m.end() - 1)))
        if tests:
            self.code = _blank_spans(self.code, tests)
            self.skel = _blank_spans(self.skel, tests)
        # start -> (end, value); and the starts in order.
        self.strings = {}
        for start, quote, close, end, raw in strings:
            if any(a <= start < b for a, b in tests):
                continue
            body = text[quote + 1: close]
            self.strings[start] = (end, body if raw else unescape(rel, body))
        self.starts = sorted(self.strings)

    def block_end(self, open_brace):
        """The offset just after the `}` that closes the `{` at `open_brace`."""
        depth = 0
        for m in BRACE.finditer(self.skel, open_brace):
            depth += 1 if m.group(0) == "{" else -1
            if depth == 0:
                return m.end()
        return len(self.skel)

    def close_of(self, open_at):
        """The offset of the bracket that closes the `(`, `[` or `{` at
        `open_at`, counting all three kinds."""
        depth = 0
        for k in range(open_at, len(self.skel)):
            ch = self.skel[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    return k
        return len(self.skel)

    def split_top(self, start, end):
        """The parts of [start, end) between commas at bracket depth 0, as
        (start, end, text), with attributes (`#[...]`) blanked in `text`;
        empty parts are left out."""
        view = list(self.skel[start:end])
        parts, depth, a, k = [], 0, start, start
        while k < end:
            ch = self.skel[k]
            if ch == "#" and depth == 0 and re.match(r"#!?\[", self.skel[k:k + 3]):
                close = self.close_of(self.skel.index("[", k))
                for x in range(k, min(close + 1, end)):
                    view[x - start] = " "
                k = close + 1
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append((a, k))
                a = k + 1
            k += 1
        parts.append((a, end))
        text = "".join(view)
        out = []
        for x, y in parts:
            part = text[x - start:y - start]
            if part.strip():
                out.append((x, y, part))
        return out

    def fn_bodies(self, name):
        """Spans of the bodies of every `fn <name>`."""
        spans = []
        for m in re.finditer(r"\bfn\s+%s\s*[<(]" % re.escape(name), self.skel):
            k = BODY_OR_END.search(self.skel, m.end())
            if k and k.group(0) == "{":
                spans.append((k.start(), self.block_end(k.start())))
        return spans

    def string_at(self, pos):
        """(value, end) of the string literal that starts at `pos`, after
        any whitespace; None if none starts there."""
        while pos < len(self.skel) and self.skel[pos].isspace():
            pos += 1
        return self.strings.get(pos)

    def only_string(self, start, end):
        """The value of [start, end) if it is exactly one string literal,
        else None."""
        lit = self.string_at(start)
        if lit is None or self.skel[lit[0]:end].strip():
            return None
        return lit[1]

    def literals(self, start, end):
        """The value of every string literal that starts inside [start, end)."""
        return [self.strings[s][1] for s in self.starts if start <= s < end]

    def first_arg(self, open_paren):
        """The span of the first argument of the call whose `(` is at
        `open_paren`."""
        depth, k = 0, open_paren + 1
        while k < len(self.skel):
            ch = self.skel[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            k += 1
        return open_paren + 1, k


def rust_sources(root, crate=None):
    """Every Rust file under `crates/<crate>/src/` (every crate's, or the
    one named), as `Source`s."""
    out = []
    base = os.path.join(root, CRATES)
    try:
        crates = sorted(os.listdir(base)) if crate is None else [crate]
    except OSError as e:
        raise SourceError("%s could not be listed (%s)" % (CRATES, e.strerror))
    for name in crates:
        src = os.path.join(base, name, "src")
        for dirpath, dirnames, names in os.walk(src):
            dirnames.sort()
            for file in sorted(names):
                if file.endswith(".rs"):
                    rel = os.path.relpath(os.path.join(dirpath, file), root)
                    out.append(Source(rel, read(root, rel)))
    if not out:
        raise SourceError("no Rust source under crates/%s/src" % (crate or "*"))
    return out


# --- Code registries ---------------------------------------------------------

# An integer literal as a discriminant or a code: decimal, hexadecimal,
# octal or binary, with `_` separators and an optional type suffix.
INT = re.compile(r"(-?)\s*(?:0x([0-9A-Fa-f_]+)|0o([0-7_]+)|0b([01_]+)|([0-9][0-9_]*))(?:[iu](?:8|16|32|64|128|size))?")


def int_value(text):
    m = INT.fullmatch(text.strip())
    if not m:
        return None
    for digits, base in zip(m.group(2, 3, 4, 5), (16, 8, 2, 10)):
        if digits is not None:
            digits = digits.replace("_", "")
            if not digits:
                return None
            value = int(digits, base)
            return -value if m.group(1) else value
    return None


def enum_variants(src, name):
    """(variant, discriminant text or None) for every variant of `pub enum
    <name>`. Only unit variants are read; any other form is an error, so a
    variant is never skipped unread."""
    m = re.search(r"\bpub enum %s\s*\{" % re.escape(name), src.skel)
    if not m:
        raise SourceError("%s has no `pub enum %s`" % (src.rel, name))
    start, end = m.end(), src.block_end(m.end() - 1) - 1
    out = []
    for _, _, text in src.split_top(start, end):
        item = " ".join(text.split())
        v = re.fullmatch(r"([A-Z][A-Za-z0-9]*)(?: ?= ?(.+))?", item)
        if not v:
            raise SourceError("%s: `%s` has a variant the reader cannot read (`%s`): it reads `Name` or `Name = <integer>`" % (src.rel, name, item[:60]))
        out.append((v.group(1), v.group(2)))
    if not out:
        raise SourceError("%s: `%s` has no variants" % (src.rel, name))
    unique_or_fail(src, "`%s` variant" % name, [v for v, _ in out])
    return out


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def numbered_variants(src, enum):
    """(variant, number) for every variant of `enum`, each of which must
    have an explicit integer discriminant."""
    found = []
    for v, d in enum_variants(src, enum):
        if d is None:
            raise SourceError("%s: `%s::%s` has no explicit number: every `%s` variant is written `%s = <number>`" % (src.rel, enum, v, enum, v))
        n = int_value(d)
        if n is None:
            raise SourceError("%s: `%s::%s = %s` is not an integer literal the reader can read" % (src.rel, enum, v, d))
        found.append((v, n))
    by_number = {}
    for v, n in found:
        by_number.setdefault(n, []).append(v)
    for n, vs in sorted(by_number.items()):
        if len(vs) > 1:
            raise SourceError("%s: `%s` gives %d to more than one variant (%s)" % (src.rel, enum, n, ", ".join(vs)))
    return found


def unique_or_fail(src, what, items):
    seen = set()
    for item in items:
        if item in seen:
            raise SourceError("%s: %s `%s` appears twice" % (src.rel, what, item))
        seen.add(item)


def enum_arms(src, enum, fn, value, convert=lambda x: x):
    """{variant: value} from every arm `Enum::A | Enum::B => <value>` (or
    `Self::A`) in the bodies of `fn <fn>`, for every variant of `enum`:
    a variant with no such arm, or with two, a value given to two variants
    and an arm naming no variant are errors. `convert` turns the matched
    text into the value, or None if it cannot."""
    variants = [v for v, _ in enum_variants(src, enum)]
    impls = [(m.end() - 1, src.block_end(m.end() - 1)) for m in re.finditer(r"\bimpl\s+%s\s*\{" % enum, src.skel)]
    pairs = []
    for start, end in src.fn_bodies(fn):
        # `Self::` names the enum only in its own `impl` block.
        names = "(?:%s|Self)" % enum if any(a < start < b for a, b in impls) else enum
        path = r"%s::[A-Z][A-Za-z0-9]*" % names
        arm = re.compile(r"((?:%s\s*\|\s*)*%s)\s*=>\s*%s" % (path, path, value))
        for m in arm.finditer(src.code, start, end):
            x = convert(m.group(2))
            if x is None:
                raise SourceError("%s: `fn %s` gives `%s` a value the reader cannot read (`%s`)" % (src.rel, fn, m.group(1), m.group(2)))
            for v in re.findall(r"(?:%s|Self)::([A-Z][A-Za-z0-9]*)" % enum, m.group(1)):
                pairs.append((v, x))
    by_variant, by_value = {}, {}
    for v, x in pairs:
        by_variant.setdefault(v, []).append(x)
        by_value.setdefault(x, []).append(v)
    for v, xs in sorted(by_variant.items()):
        if v not in variants:
            raise SourceError("%s: `fn %s` has an arm for `%s::%s`, which is not a variant" % (src.rel, fn, enum, v))
        if len(xs) > 1:
            raise SourceError("%s: `%s::%s` has more than one arm in `fn %s` (%s)" % (src.rel, enum, v, fn, ", ".join(map(str, xs))))
    for x, vs in sorted(by_value.items()):
        if len(vs) > 1:
            raise SourceError("%s: `fn %s` gives `%s` to more than one `%s` variant (%s)" % (src.rel, fn, x, enum, ", ".join(vs)))
    missing = [v for v in variants if v not in by_variant]
    if missing:
        raise SourceError("%s: `fn %s` has no `%s::<variant> => <value>` arm the reader can read for %s" % (src.rel, fn, enum, ", ".join(missing)))
    return {v: xs[0] for v, xs in by_variant.items()}


TOKEN_VALUE = r"(?:r#*)?\"([a-z][a-z0-9_]*)\""
CODE_VALUE = r"(-?\s*[0-9][0-9A-Za-z_]*)"


def code_audit_kinds(root):
    src = Source(AUDIT_RS, read(root, AUDIT_RS))
    numbers = dict(numbered_variants(src, "AuditKind"))
    tokens = enum_arms(src, "AuditKind", "token", TOKEN_VALUE)
    return {tokens[v]: n for v, n in numbers.items()}


def code_error_kinds(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    codes = enum_arms(src, "ErrorKind", "code", CODE_VALUE, int_value)
    tokens = enum_arms(src, "ErrorKind", "token", TOKEN_VALUE)
    return {tokens[v]: c for v, c in codes.items()}


def code_reasons(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    m = re.search(r"\bpub const REASONS\s*:\s*&\s*\[\s*&\s*(?:'static\s+)?str\s*\]\s*=\s*&\s*\[", src.skel)
    if not m:
        raise SourceError("%s has no `pub const REASONS: &[&str] = &[...]`" % PROTO_RS)
    found = []
    for a, b, _ in src.split_top(m.end(), src.close_of(m.end() - 1)):
        value = src.only_string(a, b)
        if value is None:
            raise SourceError("%s: REASONS holds an entry that is not one string literal (`%s`)" % (PROTO_RS, " ".join(src.code[a:b].split())[:60]))
        found.append(value)
    if not found:
        raise SourceError("%s: REASONS is empty" % PROTO_RS)
    unique_or_fail(src, "reason", found)
    return {r: PROTO_RS for r in found}


IMPL_METHOD = re.compile(r"\bimpl\b[^{;]*?\bMethod\s+for\b[^{;]*\{")
TRAIT_METHOD = re.compile(r"\btrait\s+Method\b[^{;]*\{")
CONST_NAME = re.compile(r"\bconst\s+NAME\b")
NAME_TYPE = re.compile(r"\s*:\s*&\s*(?:'static\s+)?str\s*([=;])")


def code_methods(root):
    """Method names: the `const NAME` of every `impl Method for` block in
    `envcloak-ipc`'s sources. A `const NAME` the reader cannot read (another
    type, a value that is not one string literal, a malformed name), one
    outside such a block (other than the trait's own declaration) and a
    block without exactly one are errors, never skipped."""
    found = {}
    for src in rust_sources(root, "envcloak-ipc"):
        impls = [(m.end() - 1, src.block_end(m.end() - 1)) for m in IMPL_METHOD.finditer(src.skel)]
        traits = [(m.end() - 1, src.block_end(m.end() - 1)) for m in TRAIT_METHOD.finditer(src.skel)]
        per_impl = {span: 0 for span in impls}
        for m in CONST_NAME.finditer(src.skel):
            t = NAME_TYPE.match(src.skel, m.end())
            if not t:
                raise SourceError("%s: a `const NAME` the reader cannot read: it reads `const NAME: &'static str = \"<method>\";`" % src.rel)
            if t.group(1) == ";":
                if any(a < m.start() < b for a, b in traits):
                    continue
                raise SourceError("%s: a `const NAME` without a value outside `trait Method`" % src.rel)
            inside = [span for span in impls if span[0] < m.start() < span[1]]
            if not inside:
                raise SourceError("%s: a `const NAME` outside an `impl Method for` block" % src.rel)
            lit = src.string_at(t.end())
            if lit is None or not re.match(r"\s*;", src.skel[lit[0]:]):
                raise SourceError("%s: a method's `const NAME` whose value is not one string literal" % src.rel)
            name = lit[1]
            if not METHOD.fullmatch(name):
                raise SourceError("%s: method name %r is not a well-formed method name" % (src.rel, name))
            if name in found:
                raise SourceError("%s: method name `%s` appears twice" % (src.rel, name))
            found[name] = src.rel
            per_impl[inside[-1]] += 1
        for span, count in sorted(per_impl.items()):
            if count != 1:
                line = src.skel.count("\n", 0, span[0]) + 1
                raise SourceError("%s line %d: an `impl Method for` block with %d `const NAME` the reader can read, not one" % (src.rel, line, count))
    if not found:
        raise SourceError("no `impl Method for` with a `const NAME` under crates/envcloak-ipc/src")
    return found


def tags(enum):
    def reader(root):
        src = Source(AAD_RS, read(root, AAD_RS))
        return {snake(v): n for v, n in numbered_variants(src, enum)}

    return reader


STR_TYPE = r"(?:&\s*(?:'static\s+)?str|ExitToken)"
CONST_DEF = re.compile(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*%s\s*=" % STR_TYPE)
HELPER_DEF = re.compile(r"\bfn\s+([a-z_][a-z0-9_]*)\s*(?:<[^>]*>)?\s*\(\s*token\s*:\s*(?:&\s*'static\s+str|ExitToken)\b")
CONST_REF = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]*)$")
PRINTED_PREFIX = re.compile(r"envcloak: ([a-z][a-z0-9_]*):")


def code_exit_tokens(root):
    """Tokens the CLI can print for its own failures, with the first file
    each is found in (see the module comment for what is read)."""
    sources = rust_sources(root)
    consts = {}
    helpers = set()
    for src in sources:
        for m in CONST_DEF.finditer(src.skel):
            lit = src.string_at(m.end())
            if lit is not None:
                consts.setdefault(m.group(1), set()).add(lit[1])
        for m in HELPER_DEF.finditer(src.skel):
            if m.group(1) != "new":
                helpers.add(m.group(1))
    found = {}

    def take_value(value, src):
        if TOKEN.match(value):
            found.setdefault(value, src.rel)

    def take(src, a, b):
        """The argument or field value at [a, b): a string literal of any
        form, or a constant by name."""
        value = src.only_string(a, b)
        if value is not None:
            take_value(value, src)
            return
        m = CONST_REF.match(src.skel[a:b].strip())
        for v in consts.get(m.group(1), ()) if m else ():
            take_value(v, src)

    calls = [r"\bFailure::new\s*\("] + [r"(?<!\w)(?<!fn )%s\s*\(" % re.escape(h) for h in sorted(helpers)]
    call = re.compile("|".join(calls))
    for src in sources:
        for m in call.finditer(src.skel):
            take(src, *src.first_arg(m.end() - 1))
        for m in re.finditer(r"\btoken\s*:\s*", src.skel):
            k = m.end()
            lit = src.string_at(k)
            if lit is not None:
                take_value(lit[1], src)
            else:
                ident = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Z0-9_]*\b", src.skel[k:])
                if ident:
                    take(src, k, k + ident.end())
        for start, end in src.fn_bodies("token"):
            for lit in src.literals(start, end):
                take_value(lit, src)
            for ident in re.findall(r"\b[A-Z][A-Z0-9_]*\b", src.skel[start:end]):
                for v in consts.get(ident, ()):
                    take_value(v, src)
        for lit in src.literals(0, len(src.skel)):
            m = PRINTED_PREFIX.match(lit)
            if m:
                take_value(m.group(1), src)
    if not found:
        raise SourceError("no CLI failure tokens found under crates/*/src")
    return found


TOOL_CONST = re.compile(r"\bconst\s+TOOL\s*:\s*%s\s*=" % STR_TYPE)
TOOL_ELSEWHERE = re.compile(r"\bconst\s+TOOL\b")


def code_mcp_tools(root):
    """The MCP tools the server registers: each tool's module in the
    `envcloak-mcp` crate declares its name as `const TOOL: &str =
    "<name>";` (M2-06). A `const TOOL` of any other form is an error, never
    skipped, and one name declared twice is an error."""
    found = {}
    for src in rust_sources(root, "envcloak-mcp"):
        typed = [m.start() for m in TOOL_CONST.finditer(src.skel)]
        for m in TOOL_ELSEWHERE.finditer(src.skel):
            if m.start() not in typed:
                raise SourceError("%s: a `const TOOL` that is not `&str` = one string literal" % src.rel)
        for m in TOOL_CONST.finditer(src.skel):
            lit = src.string_at(m.end())
            if lit is None:
                raise SourceError("%s: `const TOOL` is not one string literal" % src.rel)
            name = lit[1]
            if name in found:
                raise SourceError("%s: the tool `%s` is declared twice" % (src.rel, name))
            found[name] = src.rel
    if not found:
        raise SourceError("no `const TOOL` found under crates/envcloak-mcp/src")
    return found


def code_statement_domains(root):
    """Statement domains written as string literals in the workspace's Rust
    files (`b"envcloak-statement/1\n"`); a domain named in a comment is
    not one the code uses."""
    found = {}
    for dirpath, dirnames, names in os.walk(os.path.join(root, CRATES)):
        dirnames[:] = sorted(d for d in dirnames if d != "target")
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            src = Source(rel, read(root, rel))
            for lit in src.literals(0, len(src.skel)):
                m = re.match(r"(envcloak-[a-z0-9-]*statement/[0-9]+)", lit)
                if m:
                    found.setdefault(m.group(1), rel)
    if not found:
        raise SourceError("no statement domain (`envcloak-...statement/N`) found under crates/")
    return found


# Each registry: the document holding it, its columns, which columns are
# names (backticked) and numbers, the name grammar, the code source, and for
# numbered registries the reserved range (numbers a task may reserve; code
# entries there need a `landed` row).
REGISTRIES = {
    "audit_kind": dict(doc="docs/VAULT.md", cols=["Number", "Token", "Task", "Status", "Use"],
                       name="Token", num="Number", grammar=TOKEN, code=code_audit_kinds,
                       range=(22, 255)),
    "item_class": dict(doc="docs/VAULT.md", cols=["Number", "Class", "Task", "Status", "Use"],
                       name="Class", num="Number", grammar=TOKEN, code=tags("ItemClass"),
                       range=(4, 65535)),
    "table_tag": dict(doc="docs/VAULT.md", cols=["Number", "Table", "Task", "Status", "Use"],
                      name="Table", num="Number", grammar=TOKEN, code=tags("TableTag"),
                      range=(10, 65535)),
    "field_tag": dict(doc="docs/VAULT.md", cols=["Number", "Field", "Task", "Status", "Use"],
                      name="Field", num="Number", grammar=TOKEN, code=tags("FieldTag"),
                      range=(14, 65535)),
    "policy_kind": dict(doc="docs/VAULT.md", cols=["Number", "Kind", "Task", "Status", "Use"],
                        name="Kind", num="Number", grammar=TOKEN, code=None,
                        range=(1, 255)),
    "error_kind": dict(doc="docs/IPC.md", cols=["Token", "Code", "Task", "Status", "Use"],
                       name="Token", num="Code", grammar=TOKEN, code=code_error_kinds,
                       range=(-32098, -32035)),
    "reason": dict(doc="docs/IPC.md", cols=["Token", "Task", "Status", "Use"],
                   name="Token", grammar=TOKEN, code=code_reasons),
    "method": dict(doc="docs/IPC.md", cols=["Method", "Task", "Status", "Use"],
                   name="Method", grammar=METHOD, code=code_methods),
    "field": dict(doc="docs/IPC.md", cols=["Method", "Field", "Task", "Status", "Use"],
                  name="Field", scope="Method", scope_grammar=METHOD, grammar=FIELD, code=None),
    "exit_token": dict(doc="docs/IPC.md", cols=["Token", "Task", "Status", "Use"],
                       name="Token", grammar=TOKEN, code=code_exit_tokens),
    "coverage": dict(doc="docs/IPC.md", cols=["Token", "Kind", "Task", "Status", "Use"],
                     name="Token", grammar=TOKEN, code=None),
    "control_message": dict(doc="docs/IPC.md", cols=["Channel", "Message", "Task", "Status", "Use"],
                            name="Message", scope="Channel", scope_grammar=TOKEN, grammar=MESSAGE,
                            code=None),
    "statement_domain": dict(doc="docs/IPC.md", cols=["Domain", "Task", "Status", "Use"],
                             name="Domain", grammar=DOMAIN, code=code_statement_domains),
    "mcp_tool": dict(doc="docs/IPC.md", cols=["Tool", "Task", "Status", "Use"],
                     name="Tool", grammar=TOOL, code=code_mcp_tools),
    "signin_token": dict(doc="docs/IPC.md", cols=["Token", "Task", "Status", "Use"],
                         name="Token", grammar=TOKEN, code=None),
}

BLOCK = re.compile(r"<!-- reservations:([a-z_]+) -->\n(.*?)<!-- /reservations -->", re.S)
OPEN = re.compile(r"<!-- reservations:([^ >]*) -->")


def cells(line):
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")):
        return None
    return [c.strip() for c in line[1:-1].split("|")]


def backticked(cell):
    m = re.fullmatch(r"`([^`]+)`", cell)
    return m.group(1) if m else None


def read_tables(root):
    tables = {}
    for doc in DOCS:
        text = read(root, doc)
        opened = OPEN.findall(text)
        closed = text.count("<!-- /reservations -->")
        blocks = BLOCK.findall(text)
        if len(blocks) != len(opened) or closed != len(opened):
            fail("%s: a reservations marker is unmatched or malformed" % doc)
        for reg, body in blocks:
            if reg not in REGISTRIES:
                fail("%s: unknown reservations table `%s`" % (doc, reg))
                continue
            if REGISTRIES[reg]["doc"] != doc:
                fail("%s: the `%s` table belongs in %s" % (doc, reg, REGISTRIES[reg]["doc"]))
                continue
            if reg in tables:
                fail("%s: the `%s` table appears twice" % (doc, reg))
                continue
            tables[reg] = parse_table(doc, reg, body)
    for reg, spec in REGISTRIES.items():
        if reg not in tables:
            fail("%s: the `%s` reservations table is missing" % (spec["doc"], reg))
    return tables


def parse_table(doc, reg, body):
    spec = REGISTRIES[reg]
    lines = [l for l in body.split("\n") if l.strip()]
    if len(lines) < 2:
        fail("%s: the `%s` table has no header" % (doc, reg))
        return []
    header = cells(lines[0])
    if header != spec["cols"]:
        fail("%s: the `%s` table's columns are %s, not %s" % (doc, reg, header, spec["cols"]))
        return []
    sep = cells(lines[1])
    if sep is None or len(sep) != len(header) or not all(re.fullmatch(r":?-{3,}:?", c) for c in sep):
        fail("%s: the `%s` table has no separator row" % (doc, reg))
        return []
    rows = []
    for line in lines[2:]:
        c = cells(line)
        if c is None or len(c) != len(header):
            fail("%s: a row of the `%s` table is not %d cells: %s" % (doc, reg, len(header), line.strip()[:80]))
            continue
        rows.append(dict(zip(header, c)))
    if not rows:
        fail("%s: the `%s` table is empty" % (doc, reg))
    return rows


def check_rows(reg, rows):
    """Checks one table on its own; returns its rows as (key, number,
    status, task) with the names unquoted."""
    spec = REGISTRIES[reg]
    where = "%s `%s`" % (spec["doc"], reg)
    out = []
    names, numbers = {}, {}
    for row in rows:
        name = backticked(row[spec["name"]])
        if name is None:
            fail("%s: %r is not one backticked name" % (where, row[spec["name"]]))
            continue
        if not spec["grammar"].match(name):
            fail("%s: `%s` is not a well-formed name for this table" % (where, name))
        key = name
        if "scope" in spec:
            scope = backticked(row[spec["scope"]])
            if scope is None or not spec["scope_grammar"].match(scope):
                fail("%s: %r is not one backticked, well-formed %s" % (where, row[spec["scope"]], spec["scope"].lower()))
                continue
            key = "%s %s" % (scope, name)
        task, status = row["Task"], row["Status"]
        if task not in TASKS:
            fail("%s: `%s` names %r, which is not an M2 or M2b task, a later milestone or `spare`" % (where, key, task))
        if status not in STATUSES:
            fail("%s: `%s` has status %r, not one of %s" % (where, key, status, ", ".join(STATUSES)))
        if task == "spare" and status != "reserved":
            fail("%s: spare `%s` must be `reserved`" % (where, key))
        if not row["Use"]:
            fail("%s: `%s` says nothing about its use" % (where, key))
        if key in names:
            fail("%s: `%s` is reserved twice" % (where, key))
        names[key] = True
        number = None
        if "num" in spec:
            cell = row[spec["num"]]
            if not re.fullmatch(r"-?[0-9]+", cell):
                fail("%s: `%s` has number %r, not an integer" % (where, key, cell))
                continue
            number = int(cell)
            if number in numbers:
                fail("%s: number %d is reserved twice (`%s` and `%s`)" % (where, number, numbers[number], key))
            numbers[number] = key
            lo, hi = spec["range"]
            if status != "reuse" and not lo <= number <= hi:
                fail("%s: `%s` takes %d, outside the reserved range %d to %d" % (where, key, number, lo, hi))
        if reg == "coverage" and row["Kind"] not in COVERAGE_KINDS:
            fail("%s: `%s` has kind %r, not one of %s" % (where, key, row["Kind"], ", ".join(COVERAGE_KINDS)))
        out.append((key, number, status, task))
    return out


def read_code(root):
    """Each registry's code entries (name to number in a numbered table,
    name to the file it is in otherwise), or the SourceError reading it
    raised; None where the registry has no code source yet."""
    out = {}
    for reg, spec in REGISTRIES.items():
        if spec["code"] is None:
            out[reg] = None
            continue
        try:
            out[reg] = spec["code"](root)
        except SourceError as e:
            out[reg] = e
    return out


def read_baseline(root):
    """The entries each registry with a code source held before the
    reservations, as {registry: {name: number, or None if unnumbered}}."""
    out = {reg: {} for reg, spec in REGISTRIES.items() if spec["code"] is not None}
    text = read(root, BASELINE)
    for lineno, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        where = "%s line %d" % (BASELINE, lineno)
        reg = parts[0]
        if reg not in out:
            fail("%s: `%s` is not a registry whose code this script reads" % (where, reg))
            continue
        numbered = "num" in REGISTRIES[reg]
        if len(parts) != (3 if numbered else 2) or (numbered and not re.fullmatch(r"-?[0-9]+", parts[2])):
            fail("%s: not `%s <name>%s`" % (where, reg, " <number>" if numbered else ""))
            continue
        if parts[1] in out[reg]:
            fail("%s: `%s %s` is listed twice" % (where, reg, parts[1]))
            continue
        out[reg][parts[1]] = int(parts[2]) if numbered else None
    return out


def check_code(reg, rows, code, base, elsewhere):
    """Checks one table against the code: each row as its status says, and,
    with `base` (the registry's baseline), each code entry as one the code
    held before the reservations or one a `landed` or `reuse` row accounts
    for. `elsewhere` holds the names a `landed` or `reuse` row of any table
    accounts for, which also account for a failure token, since that reader
    also takes the tokens of audit kinds, error kinds and reasons."""
    spec = REGISTRIES[reg]
    where = "%s `%s`" % (spec["doc"], reg)
    if code is None:
        for key, _, status, _ in rows:
            if status == "reuse":
                fail("%s: `%s` is `reuse`, but this table has no code source to check it against" % (where, key))
        return
    if isinstance(code, SourceError):
        fail("%s: %s" % (where, code))
        return
    numbered = "num" in spec
    by_number = {n: k for k, n in code.items()} if numbered else {}
    for key, number, status, _ in rows:
        present = key in code
        if status == "reserved":
            if present:
                found = "" if numbered else " (%s)" % code[key]
                fail("%s: `%s` is reserved, but the code already has it%s: mark it `landed` if its task added it, `reuse` if it is older, or pick another name" % (where, key, found))
            if numbered and number in by_number:
                fail("%s: `%s` reserves %d, which the code gives to `%s`" % (where, key, number, by_number[number]))
        else:
            if not present:
                fail("%s: `%s` is `%s`, but the code has no such entry" % (where, key, status))
            elif numbered and code[key] != number:
                fail("%s: `%s` is %d here and %d in the code" % (where, key, number, code[key]))
    if base is None:
        return
    accounted = {k for k, _, s, _ in rows if s in ("landed", "reuse")}
    if reg == "exit_token":
        accounted |= elsewhere
    for key, value in sorted(code.items()):
        if key in accounted or (key in base and (not numbered or base[key] == value)):
            continue
        if numbered:
            lo, hi = spec["range"]
            if lo <= value <= hi:
                fail("%s: the code has `%s` = %d in the reserved range with no `landed` row for it" % (where, key, value))
            else:
                fail("%s: the code has `%s` = %d, which no `landed` row reserves and %s does not hold: reserve a number in the range %d to %d and mark it `landed`" % (where, key, value, BASELINE, lo, hi))
        else:
            fail("%s: the code has `%s` (%s), which no `landed` row reserves and %s does not hold: reserve it in this table and mark it `landed`" % (where, key, value, BASELINE))
    for key, number in sorted(base.items()):
        if key not in code or (numbered and code[key] != number):
            held = "" if not numbered else " = %d" % number
            now = "no such entry" if key not in code else "it as %d" % code[key]
            fail("%s holds `%s %s`%s, but the code has %s: an entry before the reservations is never renumbered or kept once gone, so remove the line" % (BASELINE, reg, key, held, now))


def check_printed_namespace(checked, codes):
    """Error kinds, reasons, the CLI's failure tokens and sign-in tokens all
    reach the person as `envcloak: <token>`: a name is in at most one of
    those tables, and a `reserved` name is not one the code already uses
    in another, unless SHARED names it with both tables."""
    in_tables = {}
    for reg in PRINTED:
        for key, _, _, _ in checked.get(reg, []):
            in_tables.setdefault(key, []).append(reg)

    def shared(name, regs):
        return set(regs) <= set(SHARED.get(name, ()))

    for name, regs in sorted(in_tables.items()):
        if len(regs) > 1 and not shared(name, regs):
            fail("docs/IPC.md: `%s` is reserved in both `%s`: error kinds, reasons, the CLI's failure tokens and sign-in tokens are printed as `envcloak: <token>` and share one namespace" % (name, "` and `".join(regs)))
    for reg in PRINTED:
        for key, _, status, _ in checked.get(reg, []):
            if status != "reserved":
                continue
            for other in PRINTED:
                code = codes.get(other)
                if other == reg or not isinstance(code, dict) or key not in code:
                    continue
                if not shared(key, (reg, other)):
                    found = "code %d" % code[key] if "num" in REGISTRIES[other] else code[key]
                    fail("docs/IPC.md `%s`: `%s` is reserved here, but the code already uses it in `%s` (%s)" % (reg, key, other, found))


def main(argv):
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    if len(argv) == 3 and argv[1] == "--root":
        root = argv[2]
    elif len(argv) != 1:
        sys.exit("usage: scripts/check-reservations.py [--root <repository root>]")
    try:
        tables = read_tables(root)
    except SourceError as e:
        fail(str(e))
        tables = {}
    checked = {}
    for reg, rows in tables.items():
        checked[reg] = check_rows(reg, rows)
    try:
        baseline = read_baseline(root)
    except SourceError as e:
        fail(str(e))
        baseline = {}
    elsewhere = {k for rows in checked.values() for k, _, s, _ in rows if s in ("landed", "reuse")}
    codes = read_code(root)
    for reg, rows in checked.items():
        check_code(reg, rows, codes[reg], baseline.get(reg), elsewhere)
    check_printed_namespace(checked, codes)
    if problems:
        for p in problems:
            print("check-reservations: " + p, file=sys.stderr)
        return 1
    count = sum(len(r) for r in checked.values())
    print("check-reservations: ok (%d rows in %d tables)" % (count, len(checked)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
