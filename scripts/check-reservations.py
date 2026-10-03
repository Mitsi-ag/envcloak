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
`Self::Name`) in `fn token` and `fn code`, whose whole expression is the
value (one string literal, or one integer literal), and a variant without
one the reader can read is an error, as is an arm whose value goes on
past the literal (`-32602 + 1`, `"invalid_params".split_at(8).1`); every
`impl Method for` block in the
`envcloak-ipc` crate holds exactly one `const NAME` whose value is one
string literal, and a `const NAME` of another form or elsewhere is an
error; every entry of `REASONS` is one string literal; every MCP tool is
a `const TOOL: &str = "<name>";` in the `envcloak-mcp` crate, and a
`const TOOL` of another form, or one name declared twice, is an error.
String literals are read in every form Rust has (plain, raw, byte and C
strings), with their escapes decoded.

The CLI's failure tokens are read from every crate's `src/` (comments and
`#[cfg(test)]` modules left out). `Failure` is defined once, in
crates/envcloak-client/src/fail.rs, with a private `token` field that
file never changes after a failure is made (each refused otherwise), so
no code elsewhere can set a failure's token but by making one, and a
token is read where a failure is made: the first argument of
`Failure::new` (also `Self::new` in its `impl`s, `<Failure>::new`, and
`<alias>::new` for every name `Failure` is imported or defined as: `use
... Failure as Fail`, `pub use ... as X`, `type X = Failure;`, and
aliases of those); the `token` field of a `Failure` struct literal,
written out or shorthand (a pattern only reads one, and is skipped); and
the argument at each `token` position of a token helper, a free function
with a `token: &'static str` parameter (or `ExitToken`, or an alias of
either) in any position, at every call by name. `Failure::new` or a
token helper named any other way (a function pointer, `use ... as`) is
an error, since its callers' tokens could not be read. A token argument
is a string literal, a `&str` constant by name, `concat!` of string
literals (read joined), another value's `.token()`, or an `if` with its
`else`, a `match` or a block (after `use` items only) whose every value
is one of those; in a token helper (and in `Failure::new`) also the
helper's own `token`, which it may only hand on so: a `let`, a pattern,
a closure or any other use of that name there is an error, since a
value its callers did not pass could then reach a failure. Anything else
is an error, never skipped (review of M2-RES1: a `token` handed on from
another parameter position, or a struct literal's conditional or
`concat!`, was passed over). A `.token()` is read from the `fn token`
bodies: every string literal in any of them counts, and one that returns
a static string (`&'static str`, `ExitToken` or an alias, or a `&str`
other than a borrow of its receiver's own field, which lives no longer
than the receiver) must have only such values, a `Failure`'s own field
in fail.rs being read where the failure is made. A string literal that
starts `envcloak: <token>:` counts (a line printed directly, as
`eprintln!` does for `coverage`, `warning` and `usage`), whatever crate
it is in; one that starts `envcloak: {...}:` prints its argument where a
token goes, which must be a token argument as above; and a usage line
`envcloak: {x}`, whose `x` must be bound by `Err(x)` or `Usage(x)` in a
function that calls its file's `fn parse`, counts the leading `<token>:`
of every string literal in that `fn parse`. Within these forms the reader
over-counts rather than under-counts: a string it takes for a token that
is not printed makes a `reserved` row with that name fail, which is a name to
avoid anyway, and a new one needs a `landed` row like any token. Outside
them, a token put together at run time (pieces joined into a string that
is printed later) is beyond what a reader of the source can see; review
keeps such code out. It also takes the tokens of audit kinds, error kinds and reasons, so a `landed`
or `reuse` row in one of the tables printed as `envcloak: <token>`, or in
the audit-kind table, accounts for a failure token; a row in any other
table does not. A table with no code reader yet (the coverage tokens,
control messages, fields, sign-in tokens and policy kinds) takes no
`landed` row: the task that lands one adds its reader first.

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
            # The literal is the arm's whole expression: what follows it is
            # the arm's end, never more of the value (review M2R-1).
            after = src.skel[m.end():end].lstrip()
            if not after or after[0] not in ",}":
                value = src.code[m.start() + m.group(0).index("=>") + 2:m.end() + 20]
                raise SourceError("%s: `fn %s` gives `%s` an expression the reader cannot read (`%s`): an arm's value is one literal" % (src.rel, fn, " ".join(m.group(1).split()), " ".join(value.split())))
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
CONST_REF = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]*)$")
PRINTED_PREFIX = re.compile(r"envcloak: ([a-z][a-z0-9_]*):")
# `use ... X as Y` (in a group too) and `type Y = ...::X;`: Y names X.
ALIAS_USE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s+as\s+([A-Z][A-Za-z0-9_]*)\b")
ALIAS_TYPE = re.compile(r"\btype\s+([A-Z][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Za-z0-9_]*)\s*;")
# `type X = &'static str;`: X is a static string type, as `ExitToken` is.
STATIC_STR_ALIAS = re.compile(r"\btype\s+([A-Z][A-Za-z0-9_]*)\s*=\s*&\s*'static\s+str\s*;")
FN_NAME = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# Another value's `.token()`: read from the `fn token` bodies.
TOKEN_CHAIN = re.compile(r"(?:%s\s*::\s*)*%s(?:\s*\.\s*%s)*\s*\.\s*token\s*\(\s*\)" % (IDENT, IDENT, IDENT))
# A `Failure`'s own field, read where it is set (fail.rs only).
FIELD_TOKEN = re.compile(r"%s\s*\.\s*token" % IDENT)
CONCAT = re.compile(r"(?:(?:::)?(?:std|core)::)?concat\s*!\s*\(")
MACRO = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*!\s*[\(\[\{]")
RECEIVER = re.compile(r"^(?:&\s*(?:'[A-Za-z_]+\s+)?)?(?:mut\s+)?self\b")
TOKEN_PARAM = re.compile(r"^(?:mut\s+)?token\s*:\s*(.+)$", re.S)
USE_STMT = re.compile(r"\buse\b[^;{}]*(?:\{[^;]*\})?[^;]*;")
# The file that defines `Failure`: the only one where its fields may be
# named, which `check_failure_struct` holds it to.
FAIL_RS = "crates/envcloak-client/src/fail.rs"


class Unreadable(Exception):
    """A failure token in a form the reader cannot read."""


class Fn:
    """A `fn` item: its name, parameters (flattened text), return type,
    body span (None for a declaration) and where its head starts."""

    def __init__(self, src, name, start, params, ret, body, public):
        self.src = src
        self.name = name
        self.start = start
        self.params = params
        self.ret = ret
        self.body = body
        self.public = public


def crate_of(rel):
    """`crates/<name>/` for a file under it."""
    parts = rel.split("/")
    return "/".join(parts[:2]) + "/"


def generic_end(skel, k):
    """The offset just after the `>` that closes the `<` at `k` (an `->`
    inside is not one), or None if a `{` or `;` comes first."""
    depth = 0
    for i in range(k, len(skel)):
        ch = skel[i]
        if ch == "<":
            depth += 1
        elif ch == ">" and skel[i - 1] != "-":
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch in "{;":
            return None
    return None


def fn_items(src):
    """Every `fn` item of `src`, generic ones too."""
    out = []
    for m in FN_NAME.finditer(src.skel):
        k = m.end()
        if src.skel.startswith("<", k):
            k = generic_end(src.skel, k)
            if k is None:
                continue
            while k < len(src.skel) and src.skel[k].isspace():
                k += 1
        if not src.skel.startswith("(", k):
            continue
        close = src.close_of(k)
        params = [" ".join(t.split()) for _, _, t in src.split_top(k + 1, close)]
        e = BODY_OR_END.search(src.skel, close)
        ret = " ".join(src.skel[close + 1:e.start() if e else len(src.skel)].split())
        body = (e.start(), src.block_end(e.start())) if e and e.group(0) == "{" else None
        head = src.skel[max(0, m.start() - 80):m.start()]
        public = bool(re.search(r"\bpub\b(?:\s*\([^)]*\))?\s*(?:(?:const|async|unsafe|extern\s*\"[^\"]*\")\s+)*$", head))
        out.append(Fn(src, m.group(1), m.start(), params, ret, body, public))
    return out


def find_top(src, start, end, what):
    """The first offset in [start, end) where `what` starts at bracket
    depth 0, or None."""
    depth = 0
    k = start
    while k < end:
        ch = src.skel[k]
        if depth == 0 and src.skel.startswith(what, k):
            return k
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        k += 1
    return None


def strip_span(src, a, b):
    while a < b and src.skel[a].isspace():
        a += 1
    while b > a and src.skel[b - 1].isspace():
        b -= 1
    return a, b


class Reading:
    """What a value may be where it is read: the enclosing token helper's
    own `token` parameter (`forward`), and a `Failure`'s own field (in
    fail.rs). `forwards` collects where `token` was taken so."""

    def __init__(self, consts, forward=False, field=False):
        self.consts = consts
        self.forward = forward
        self.field = field
        self.forwards = []


def values_of(src, a, b, r):
    """Every value the expression at [a, b) can have, as a failure token:
    a string literal, a `&str` constant, `concat!` of literals, and each
    branch of an `if`/`else` or a `match` and the tail of a block, read the
    same way; another value's `.token()` (read from the `fn token` bodies),
    and where `r` allows it the helper's own `token` and a `Failure`'s own
    field, add none here. Anything else is `Unreadable`, never skipped."""
    a, b = strip_span(src, a, b)
    text = " ".join(src.skel[a:b].split())
    if a >= b:
        raise Unreadable("a failure token the reader cannot read (an empty expression)")
    lit = src.only_string(a, b)
    if lit is not None:
        return [lit]
    if src.skel[a] in "({" and src.close_of(a) == b - 1:
        if src.skel[a] == "(":
            return values_of(src, a + 1, b - 1, r)
        return block_values(src, a, b, r)
    m = re.match(r"const\s*\{", src.skel[a:b])
    if m and src.close_of(a + m.end() - 1) == b - 1:
        return block_values(src, a + m.end() - 1, b, r)
    if re.match(r"if\b", text):
        return if_values(src, a, b, r)
    if re.match(r"match\b", text):
        return match_values(src, a, b, r)
    if text == "token":
        if r.forward:
            r.forwards.append(a)
            return []
        raise Unreadable("a failure token the reader cannot read (`token`): a `token` parameter is read at the callers only of a function whose callers the reader reads, a free function with that parameter of type `&'static str` or `ExitToken`")
    if TOKEN_CHAIN.fullmatch(text):
        return []
    if r.field and FIELD_TOKEN.fullmatch(text):
        return []
    m = CONST_REF.match(text)
    if m:
        if m.group(1) not in r.consts:
            raise Unreadable("a failure token names `%s`, which is no `&str` constant the reader knows" % text[:60])
        return sorted(r.consts[m.group(1)])
    c = CONCAT.match(src.skel, a)
    if c:
        close = src.close_of(c.end() - 1)
        parts = [src.only_string(x, y) for x, y, _ in src.split_top(c.end(), close)]
        if close != b - 1 or not parts or any(p is None for p in parts):
            raise Unreadable("a failure token in `concat!` of something other than string literals (`%s`)" % text[:60])
        return ["".join(parts)]
    if MACRO.match(src.skel, a):
        raise Unreadable("a failure token the reader cannot read (`%s`): a macro other than `concat!` of literals" % text[:60])
    raise Unreadable("a failure token the reader cannot read (`%s`): write one string literal, a `&str` constant, `concat!` of literals, another value's `.token()`, or an `if`, `match` or block whose every value is one of those" % text[:60])


def block_values(src, a, b, r):
    """The values of the block [a, b) (`{` to `}`): its tail expression,
    after nothing but `use` items."""
    inner_a, inner_b = a + 1, b - 1
    stmts = []
    k = inner_a
    while True:
        semi = find_top(src, k, inner_b, ";")
        if semi is None:
            break
        stmts.append((k, semi))
        k = semi + 1
    for x, y in stmts:
        if src.skel[x:y].strip() and not re.match(r"\s*use\b", src.skel[x:y]):
            raise Unreadable("a failure token the reader cannot read (`%s`): a block whose value comes after a statement" % " ".join(src.skel[a:b].split())[:60])
    return values_of(src, k, inner_b, r)


def if_values(src, a, b, r):
    """The values of every branch of the `if` at [a, b), which must end
    with an `else`."""
    whole = " ".join(src.skel[a:b].split())[:60]
    out = []
    k = a
    while True:
        open_at = find_top(src, k + 2, b, "{")
        if open_at is None:
            raise Unreadable("a failure token the reader cannot read (`%s`)" % whole)
        close = src.close_of(open_at)
        out += block_values(src, open_at, close + 1, r)
        rest = close + 1
        m = re.compile(r"\s*else\b\s*").match(src.skel, rest, b)
        if not m:
            raise Unreadable("a failure token the reader cannot read (`%s`): an `if` without `else`" % whole)
        k = m.end()
        if re.match(r"if\b", src.skel[k:b]):
            continue
        if not src.skel.startswith("{", k) or src.close_of(k) != b - 1:
            raise Unreadable("a failure token the reader cannot read (`%s`)" % whole)
        return out + block_values(src, k, b, r)


def match_values(src, a, b, r):
    """The values of every arm of the `match` at [a, b)."""
    whole = " ".join(src.skel[a:b].split())[:60]
    open_at = find_top(src, a + 5, b, "{")
    if open_at is None or src.close_of(open_at) != b - 1:
        raise Unreadable("a failure token the reader cannot read (`%s`)" % whole)
    out = []
    k, end = open_at + 1, b - 1
    while True:
        while k < end and (src.skel[k].isspace() or src.skel[k] == ","):
            k += 1
        if k >= end:
            break
        arrow = find_top(src, k, end, "=>")
        if arrow is None:
            raise Unreadable("a failure token the reader cannot read (`%s`)" % whole)
        v = arrow + 2
        while v < end and src.skel[v].isspace():
            v += 1
        if src.skel.startswith("{", v):
            stop = src.close_of(v) + 1
        else:
            comma = find_top(src, v, end, ",")
            stop = end if comma is None else comma
        out += values_of(src, v, stop, r)
        k = stop
    return out


def static_str_types(sources):
    """`ExitToken` and every alias of `&'static str` or of one of them."""
    names = {"ExitToken"}
    pairs = []
    for src in sources:
        names |= {m.group(1) for m in STATIC_STR_ALIAS.finditer(src.skel)}
        pairs += [(m.group(2), m.group(1)) for m in ALIAS_TYPE.finditer(src.skel)]
    grew = True
    while grew:
        grew = False
        for orig, alias in pairs:
            if orig in names and alias not in names:
                names.add(alias)
                grew = True
    return names


def is_static_str(ty, statics):
    ty = " ".join(ty.split())
    if re.fullmatch(r"&\s*'static\s+str", ty):
        return True
    last = re.fullmatch(r"(?:%s::)*(%s)" % (IDENT, IDENT), ty)
    return bool(last and last.group(1) in statics)


def failure_names(sources):
    """`Failure` and every name it is imported or defined as, aliases of
    aliases included."""
    names = {"Failure"}
    pairs = []
    for src in sources:
        pairs += [(m.group(1), m.group(2)) for m in ALIAS_USE.finditer(src.skel)]
        pairs += [(m.group(2), m.group(1)) for m in ALIAS_TYPE.finditer(src.skel)]
    grew = True
    while grew:
        grew = False
        for orig, alias in pairs:
            if orig in names and alias not in names:
                names.add(alias)
                grew = True
    return names


def impl_spans(src, names):
    """The bodies of `impl` blocks whose `Self` is one of `names`."""
    spans = []
    for m in re.finditer(r"\bimpl\b", src.skel):
        open_at = BODY_OR_END.search(src.skel, m.end())
        if not open_at or open_at.group(0) != "{":
            continue
        head = " ".join(src.skel[m.end():open_at.start()].split())
        head = re.sub(r"^<.*?>\s*", "", head) if head.startswith("<") else head
        target = head.split(" for ", 1)[1] if " for " in " %s " % head else head
        last = re.match(r"(?:%s::)*(%s)" % (IDENT, IDENT), target.strip())
        if last and last.group(1) in names:
            spans.append((open_at.start(), src.block_end(open_at.start())))
    return spans


def check_failure_struct(sources, names):
    """`Failure` is defined once, in fail.rs, and its `token` field is
    private: elsewhere no struct literal, field assignment or borrow of it
    compiles, so `Failure::new`, the struct literals of fail.rs and the
    conversions it defines are the only ways a failure gets its token."""
    defs = []
    for src in sources:
        for m in re.finditer(r"\bstruct\s+(%s)\b" % "|".join(map(re.escape, sorted(names))), src.skel):
            defs.append((src, m))
    if len(defs) != 1 or defs[0][0].rel != FAIL_RS:
        raise SourceError("`Failure` must be defined once, in %s (found in %s)" % (FAIL_RS, ", ".join(s.rel for s, _ in defs) or "no file"))
    src, m = defs[0]
    open_at = src.skel.index("{", m.end())
    fields = src.skel[open_at + 1:src.block_end(open_at) - 1]
    if re.search(r"\bpub\b(?:\s*\([^)]*\))?\s+token\s*:", fields):
        raise SourceError("%s: `Failure`'s `token` field is public: a failure's token could then be set where the reader does not look; keep it private" % FAIL_RS)
    for k in re.finditer(r"\.\s*token\s*(?:=(?!=)|[-+*/|&^]=)|&\s*mut\s+[\w.]*\btoken\b", src.skel):
        raise SourceError("%s line %d: `Failure`'s token is changed after it is made; a token is given only when the failure is made" % (FAIL_RS, src.skel.count("\n", 0, k.start()) + 1))


def code_exit_tokens(root):
    """Tokens the CLI can print for its own failures, with the first file
    each is found in (see the module comment for what is read)."""
    sources = rust_sources(root)
    statics = static_str_types(sources)
    names = failure_names(sources)
    check_failure_struct(sources, names)
    consts = {}
    for src in sources:
        for m in CONST_DEF.finditer(src.skel):
            lit = src.string_at(m.end())
            if lit is not None:
                consts.setdefault(m.group(1), set()).add(lit[1])
    fns = {src.rel: fn_items(src) for src in sources}
    # Token helpers: free functions with a `token: &'static str` (or an
    # alias) parameter, by name, with its positions.
    helpers = {}
    # Where each helper is defined: (file, crate, public). A private one is
    # visible in its crate only (its module's descendants included).
    defs = {}
    exempt = []
    for src in sources:
        failure_impls = impl_spans(src, names) if src.rel == FAIL_RS else []
        for f in fns[src.rel]:
            if f.body is None:
                continue
            positions = [i for i, p in enumerate(f.params)
                         if TOKEN_PARAM.match(p) and is_static_str(TOKEN_PARAM.match(p).group(1), statics)]
            if not positions:
                continue
            if f.params and RECEIVER.match(f.params[0]):
                continue
            if f.name == "new":
                # `Failure::new` itself, whose callers are read below.
                if any(x < f.start < y for x, y in failure_impls) and positions == [0]:
                    exempt.append((src, f))
                continue
            helpers.setdefault(f.name, set()).update(positions)
            defs.setdefault(f.name, []).append((src.rel, crate_of(src.rel), f.public))
            exempt.append((src, f))
    found = {}

    def take(values, src):
        for v in values:
            if TOKEN.match(v):
                found.setdefault(v, src.rel)

    def where(src, at):
        return "%s line %d" % (src.rel, src.skel.count("\n", 0, at) + 1)

    def body_of(src, at):
        """The exempt function whose body holds `at`, if any."""
        for s, f in exempt:
            if s is src and f.body[0] < at < f.body[1]:
                return f
        return None

    forwarded = {}
    field_names = {}

    def read(src, a, b, field=False):
        f = body_of(src, a)
        r = Reading(consts, forward=f is not None, field=field and src.rel == FAIL_RS)
        try:
            take(values_of(src, a, b, r), src)
        except Unreadable as e:
            raise SourceError("%s: %s" % (where(src, a), e))
        for at in r.forwards:
            forwarded.setdefault(src.rel, set()).add(at)

    alias = "|".join(map(re.escape, sorted(names)))
    ctor = re.compile(r"(?<![\w:])(?:<\s*)?(?:%s::)*(?:%s)(?:\s*>)?\s*::\s*new\b" % (IDENT, alias))
    helper_word = re.compile(r"\b(%s)\b" % "|".join(map(re.escape, sorted(helpers)))) if helpers else None
    literal_of = re.compile(r"(?<![\w:])(?:%s::)*(%s|Self)\s*\{" % (IDENT, alias))
    for src in sources:
        failure_impls = impl_spans(src, names)
        # `Failure::new(..)` (and its aliases): the first argument. Named
        # any other way (a function pointer, a turbofish), it is refused.
        ctors = list(ctor.finditer(src.skel))
        ctors += [m for m in re.finditer(r"(?<![\w:])Self\s*::\s*new\b", src.skel)
                  if any(x < m.start() < y for x, y in failure_impls)]
        for m in ctors:
            k = m.end()
            rest = src.skel[k:k + 200]
            call = re.match(r"\s*(?:::\s*<[^()]*>\s*)?\(", rest)
            if not call:
                raise SourceError("%s: `%s` is used other than called, so its tokens could not be read" % (where(src, m.start()), " ".join(m.group(0).split())))
            open_at = k + call.end() - 1
            args = src.split_top(open_at + 1, src.close_of(open_at))
            if args:
                read(src, args[0][0], args[0][1])
        # Token helpers: the argument at each `token` position, and every
        # mention of a helper other than a call or its own definition.
        if helper_word:
            uses = [u.group(0) for u in USE_STMT.finditer(src.skel)]
            for m in helper_word.finditer(src.skel):
                name = m.group(1)
                where_defined = defs[name]
                if not any(pub or crate == crate_of(src.rel) for _, crate, pub in where_defined):
                    continue
                before = src.skel[:m.start()].rstrip()
                if before.endswith(".") or re.search(r"\bfn$", before):
                    continue
                # Elsewhere than where it is defined, the bare name is the
                # helper only if this file imports it (or imports a glob);
                # otherwise it is a local of the same name. A path to it
                # (`super::name`) is the helper anywhere it is visible.
                imported = any(re.search(r"\b%s\b|::\s*\*" % re.escape(name), u) for u in uses)
                if (not before.endswith("::") and not imported
                        and src.rel not in {rel for rel, _, _ in where_defined}):
                    continue
                rest = src.skel[m.end():m.end() + 200]
                call = re.match(r"\s*(?:::\s*<[^()]*>\s*)?\(", rest)
                if not call:
                    in_use = any(u.start() < m.start() < u.end() for u in USE_STMT.finditer(src.skel))
                    if in_use and not re.match(r"\s+as\b", rest):
                        continue
                    raise SourceError("%s: the token helper `%s` is used other than called by name, so the tokens handed to it would not be read" % (where(src, m.start()), name))
                open_at = m.end() + call.end() - 1
                args = src.split_top(open_at + 1, src.close_of(open_at))
                for i in sorted(helpers[name]):
                    if i < len(args):
                        read(src, args[i][0], args[i][1])
        # Struct literals of `Failure` (and `Self` in its `impl`s): the
        # `token` field, written out or shorthand. A pattern (after `let`,
        # before `=>` or `=`, or with `..`) only reads one, and is skipped.
        for m in literal_of.finditer(src.skel):
            if m.group(1) == "Self" and not any(x < m.start() < y for x, y in failure_impls):
                continue
            before = src.skel[:m.start()].rstrip()
            if re.search(r"\b(?:struct|enum|union|impl|for|let)$", before) or before.endswith(("|", "->")):
                continue
            open_at = m.end() - 1
            close = src.close_of(open_at)
            after = src.skel[close + 1:close + 4].lstrip()
            if after.startswith("=>") or (after.startswith("=") and not after.startswith("==")):
                continue
            fields = src.split_top(open_at + 1, close)
            if any(t.strip() == ".." for _, _, t in fields):
                continue
            for x, y, t in fields:
                fm = re.match(r"(\s*)token\b(\s*:(?!:))?", src.skel[x:y])
                if not fm:
                    continue
                at = x + len(fm.group(1))
                field_names.setdefault(src.rel, set()).add(at)
                if fm.group(2):
                    read(src, x + fm.end(), y, field=True)
                elif not src.skel[at + 5:y].strip():
                    read(src, at, at + 5)
                else:
                    raise SourceError("%s: a `Failure` literal's `token` field the reader cannot read" % where(src, at))
        # Other structs' `token` fields: a literal or a constant counts.
        for m in re.finditer(r"\btoken\s*:\s*", src.skel):
            k = m.end()
            lit = src.string_at(k)
            if lit is not None:
                take([lit[1]], src)
            else:
                ident = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]*)\b", src.skel[k:])
                if ident and ident.group(1) in consts:
                    take(sorted(consts[ident.group(1)]), src)
        # `fn token`: every string in it; and one returning a static
        # string, every value it can have.
        for f in fns[src.rel]:
            if f.name != "token" or f.body is None:
                continue
            take(src.literals(*f.body), src)
            ret = re.sub(r"^->\s*", "", f.ret)
            ret = re.sub(r"\s*where\b.*$", "", ret)
            if is_static_str(ret, statics):
                pass
            elif re.fullmatch(r"&\s*str", ret):
                # A borrow of the receiver's own field lives no longer than
                # the receiver: never a `&'static str` failure token.
                body = " ".join(src.skel[f.body[0] + 1:f.body[1] - 1].split())
                if re.fullmatch(r"&\s*(?:\*\s*)?self\s*\.\s*%s|self\s*\.\s*%s\s*\.\s*as_str\s*\(\s*\)" % (IDENT, IDENT), body):
                    continue
            else:
                continue
            read(src, f.body[0], f.body[1], field=True)
        # A line printed as `envcloak: <token>:`: from a literal, the token;
        # from a placeholder, the value of its argument.
        for start in src.starts:
            lit = src.strings[start][1]
            m = PRINTED_PREFIX.match(lit)
            if m:
                take([m.group(1)], src)
            elif lit.startswith("envcloak: {"):
                printed_placeholder(src, start, lit, fns[src.rel], read, take)
    # A helper's `token` is only ever handed on as a failure token: any
    # other mention (a `let` or a pattern that rebinds it, a use in an
    # expression) would let a value the callers did not pass reach it.
    for src, f in exempt:
        for m in re.finditer(r"\btoken\b", src.skel[f.body[0]:f.body[1]]):
            at = f.body[0] + m.start()
            before = src.skel[:at].rstrip()
            after = src.skel[at + 5:at + 7]
            if before.endswith(".") or after.startswith("::") or after.startswith("!"):
                continue
            if at in forwarded.get(src.rel, ()):
                continue
            if at in field_names.get(src.rel, ()):
                continue
            raise SourceError("%s: `%s`'s `token` is used other than handed on as a failure token, so a value its callers did not pass could reach one" % (where(src, at), f.name))
    if not found:
        raise SourceError("no CLI failure tokens found under crates/*/src")
    return found


def printed_placeholder(src, start, lit, items, read, take):
    """A string literal starting `envcloak: {`: the placeholder is printed
    where a token goes. Followed by `:`, it is a token, and its argument
    must be one the reader reads. Otherwise it is a usage line, `envcloak:
    <message>`, whose message must come from this file's `fn parse` (an
    `Err(x)` or `Usage(x)` of a `parse(..)` call in the same function):
    every string there starting `<token>:` counts as a token."""
    end = src.strings[start][0]
    where = "%s line %d" % (src.rel, src.skel.count("\n", 0, start) + 1)
    pm = re.match(r"envcloak: \{([^{}:]*)(?::[^{}]*)?\}(:?)", lit)
    if not pm:
        raise SourceError("%s: a line printed as `envcloak: {...}` the reader cannot read" % where)
    name, token_position = pm.group(1).strip(), pm.group(2) == ":"
    # The format macro's arguments after the literal.
    depth, k = 0, start - 1
    while k >= 0:
        ch = src.skel[k]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                break
            depth -= 1
        k -= 1
    if k < 0 or src.skel[k] != "(":
        raise SourceError("%s: a line printed as `envcloak: {...}` outside a format macro's arguments" % where)
    args = src.split_top(k + 1, src.close_of(k))
    at = [i for i, (x, y, _) in enumerate(args) if x <= start < y]
    rest = args[at[0] + 1:] if at else []
    positional = [(x, y) for x, y, t in rest if not re.match(r"\s*%s\s*=(?!=)" % IDENT, t)]
    named = {re.match(r"\s*(%s)" % IDENT, t).group(1): (x + t.index("=") + 1, y)
             for x, y, t in rest if re.match(r"\s*%s\s*=(?!=)" % IDENT, t)}
    if name == "" or name.isdigit():
        i = int(name) if name else 0
        if i >= len(positional):
            raise SourceError("%s: a line printed as `envcloak: {}` without its argument" % where)
        span = positional[i]
    elif name in named:
        span = named[name]
    else:
        span = None
    if token_position:
        if span is not None:
            read(src, span[0], span[1], field=True)
            return
        raise SourceError("%s: a line printed as `envcloak: {%s}:` takes its token from a variable the reader cannot read; print a failure's token (`.token()`)" % (where, name))
    ident = None
    if span is None and re.fullmatch(IDENT, name):
        ident = name
    elif span is not None and re.fullmatch(IDENT, src.skel[span[0]:span[1]].strip()):
        ident = src.skel[span[0]:span[1]].strip()
    holder = [f for f in items if f.body and f.body[0] < start < f.body[1]]
    parse = [f for f in items if f.name == "parse" and f.body]
    ok = False
    if ident and holder and parse:
        body = src.skel[holder[-1].body[0]:holder[-1].body[1]]
        bound = re.search(r"(?:\bErr|::\s*Usage)\s*\(\s*%s\s*\)" % re.escape(ident), body)
        ok = bool(bound and re.search(r"(?<![\w.:])parse\s*\(", body))
    if not ok:
        raise SourceError("%s: a usage line `envcloak: {%s}` whose message the reader cannot trace to this file's `fn parse`" % (where, name))
    for f in parse:
        for v in src.literals(*f.body):
            m = re.match(r"([a-z][a-z0-9_]*):", v)
            if m:
                take([m.group(1)], src)


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
    for. `elsewhere` holds the names a `landed` or `reuse` row of a printed
    table or the audit-kind table accounts for, which also account for a
    failure token, since that reader also takes the tokens of audit kinds,
    error kinds and reasons."""
    spec = REGISTRIES[reg]
    where = "%s `%s`" % (spec["doc"], reg)
    if code is None:
        for key, _, status, _ in rows:
            if status in ("reuse", "landed"):
                fail("%s: `%s` is `%s`, but this table has no code reader to check it against: add its reader first" % (where, key, status))
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
    # Only the tables whose tokens the failure-token reader takes account
    # for a failure token: the ones printed as `envcloak: <token>`, and
    # the audit kinds (their `fn token`).
    elsewhere = {
        k
        for reg, rows in checked.items()
        if reg in PRINTED or reg == "audit_kind"
        for k, _, s, _ in rows
        if s in ("landed", "reuse")
    }
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
