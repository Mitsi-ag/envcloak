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
  hold, and, in a numbered table, a code entry in the reserved range with
  no `landed` row. A code source that yields nothing is an error, never an
  empty registry, and so is a code source that gives one number or token
  to two entries, or two tokens or codes to one.

The CLI's failure tokens are read from every crate's `src/` (comments and
`#[cfg(test)]` modules left out): the first argument of `Failure::new` and
of every function whose first parameter is `token: &'static str` (or
`ExitToken`), every `token: <value>` field, every string in the body of a
`fn token`, and the `<token>` of every string literal that starts
`envcloak: <token>:` (a line printed directly, as `eprintln!` does for
`coverage`, `warning` and `usage`), whatever crate it is in. A value
written as a `&str` constant counts by the constant's string. The reader over-counts rather
than under-counts: a string it takes for a token that is not printed only
makes a `reserved` row with that name fail, which is a name to avoid
anyway.

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
# needs a reviewer's agreement that both rows mean one thing.
SHARED = {}

# Code sources, relative to the root.
AUDIT_RS = "crates/envcloak-core/src/audit/record.rs"
AAD_RS = "crates/envcloak-core/src/crypto/aad.rs"
PROTO_RS = "crates/envcloak-ipc/src/proto.rs"
CRATES = "crates"

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

SCAN = re.compile(r"//|/\*|\bb?r#*\"|\"|'")
BLOCK_COMMENT = re.compile(r"/\*|\*/")
STRING_END = re.compile(r"\\.|\"", re.S)
CHAR = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'")
BRACE = re.compile(r"[{}]")
BODY_OR_END = re.compile(r"[{;]")
TEST_MOD = re.compile(
    r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{"
)
NOT_NEWLINE = re.compile(r"[^\n]")


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


class Source:
    """One Rust file as two views of the same length: `code`, with comments
    blanked, and `skel`, also with the inside of every string and character
    literal blanked, so that structure (braces, commas, `token:`) is found
    in `skel` and literals are read from `code` at the same offsets.
    `#[cfg(test)]` modules are blanked in both."""

    def __init__(self, rel, text):
        self.rel = rel
        comments, contents = [], []
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
            elif tok == '"':
                j = s + 1
                while True:
                    k = STRING_END.search(text, j)
                    if not k:
                        j = n
                        break
                    if k.group(0) == '"':
                        j = k.start()
                        break
                    j = k.end()
                contents.append((s + 1, j))
                i = j + 1
            else:
                close = '"' + tok[tok.index("r") + 1: -1]
                j = text.find(close, m.end())
                j = n if j < 0 else j
                contents.append((m.end(), j))
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

    def block_end(self, open_brace):
        """The offset just after the `}` that closes the `{` at `open_brace`."""
        depth = 0
        for m in BRACE.finditer(self.skel, open_brace):
            depth += 1 if m.group(0) == "{" else -1
            if depth == 0:
                return m.end()
        return len(self.skel)

    def fn_bodies(self, name):
        """Spans of the bodies of every `fn <name>`."""
        spans = []
        for m in re.finditer(r"\bfn\s+%s\s*[<(]" % re.escape(name), self.skel):
            k = BODY_OR_END.search(self.skel, m.end())
            if k and k.group(0) == "{":
                spans.append((k.start(), self.block_end(k.start())))
        return spans

    def literal_at(self, quote):
        """The string literal whose opening quote is at `quote`."""
        close = self.skel.find('"', quote + 1)
        return self.code[quote + 1: close if close >= 0 else len(self.code)]

    def literals(self, start, end):
        """Every string literal that opens inside [start, end)."""
        out, k = [], start
        while True:
            q = self.skel.find('"', k, end)
            if q < 0:
                return out
            close = self.skel.find('"', q + 1)
            if close < 0:
                return out
            out.append(self.code[q + 1: close])
            k = close + 1

    def first_arg(self, open_paren):
        """The text of the first argument of the call whose `(` is at
        `open_paren`, from `code`."""
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
        return self.code[open_paren + 1: k].strip()


def rust_sources(root):
    """Every Rust file under `crates/<crate>/src/`, as `Source`s."""
    out = []
    base = os.path.join(root, CRATES)
    try:
        crates = sorted(os.listdir(base))
    except OSError as e:
        raise SourceError("%s could not be listed (%s)" % (CRATES, e.strerror))
    for crate in crates:
        src = os.path.join(base, crate, "src")
        for dirpath, dirnames, names in os.walk(src):
            dirnames.sort()
            for name in sorted(names):
                if name.endswith(".rs"):
                    rel = os.path.relpath(os.path.join(dirpath, name), root)
                    out.append(Source(rel, read(root, rel)))
    if not out:
        raise SourceError("no Rust source under crates/*/src")
    return out


# --- Code registries ---------------------------------------------------------


def enum_body(src, name):
    m = re.search(r"pub enum %s\s*\{" % re.escape(name), src.skel)
    if not m:
        raise SourceError("%s has no `pub enum %s`" % (src.rel, name))
    return src.code[m.end(): src.block_end(m.end() - 1) - 1]


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def numbered_variants(src, enum):
    body = enum_body(src, enum)
    found = [(v, int(n)) for v, n in re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*=\s*(-?\d+)\s*,", body, re.M)]
    if not found:
        raise SourceError("%s: `%s` has no numbered variants" % (src.rel, enum))
    unique_or_fail(src, "`%s` variant" % enum, [v for v, _ in found])
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


def enum_arms(src, enum, fn, value):
    """(variant, value) for every arm `Enum::A | Enum::B => <value>` in the
    bodies of `fn <fn>` that match on `enum`, refusing a variant with two
    arms and a value given to two variants."""
    arm = re.compile(r"((?:%s::[A-Z][A-Za-z0-9]*\s*\|\s*)*%s::[A-Z][A-Za-z0-9]*)\s*=>\s*%s" % (enum, enum, value))
    pairs = []
    for start, end in src.fn_bodies(fn):
        for m in arm.finditer(src.code, start, end):
            for v in re.findall(r"%s::([A-Z][A-Za-z0-9]*)" % enum, m.group(1)):
                pairs.append((v, m.group(2)))
    if not pairs:
        raise SourceError("%s: no `%s::<variant> => ...` arms in `fn %s`" % (src.rel, enum, fn))
    by_variant, by_value = {}, {}
    for v, x in pairs:
        by_variant.setdefault(v, []).append(x)
        by_value.setdefault(x, []).append(v)
    for v, xs in sorted(by_variant.items()):
        if len(xs) > 1:
            raise SourceError("%s: `%s::%s` has more than one arm in `fn %s` (%s)" % (src.rel, enum, v, fn, ", ".join(xs)))
    for x, vs in sorted(by_value.items()):
        if len(vs) > 1:
            raise SourceError("%s: `fn %s` gives `%s` to more than one `%s` variant (%s)" % (src.rel, fn, x, enum, ", ".join(vs)))
    return {v: xs[0] for v, xs in by_variant.items()}


def code_audit_kinds(root):
    src = Source(AUDIT_RS, read(root, AUDIT_RS))
    numbers = dict(numbered_variants(src, "AuditKind"))
    tokens = enum_arms(src, "AuditKind", "token", r'"([a-z][a-z0-9_]*)"')
    missing = sorted(set(numbers) ^ set(tokens))
    if missing:
        raise SourceError("%s: AuditKind variants without both a number and a token: %s" % (AUDIT_RS, ", ".join(missing)))
    return {tokens[v]: n for v, n in numbers.items()}


def code_error_kinds(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    codes = enum_arms(src, "ErrorKind", "code", r"(-\d+)\b")
    tokens = enum_arms(src, "ErrorKind", "token", r'"([a-z][a-z0-9_]*)"')
    missing = sorted(set(codes) ^ set(tokens))
    if missing:
        raise SourceError("%s: ErrorKind variants without both a code and a token: %s" % (PROTO_RS, ", ".join(missing)))
    return {tokens[v]: int(c) for v, c in codes.items()}


def code_reasons(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    m = re.search(r"pub const REASONS: &\[&str\] = &\[", src.skel)
    if not m:
        raise SourceError("%s has no `pub const REASONS`" % PROTO_RS)
    end = src.skel.find("];", m.end())
    found = src.literals(m.end(), end if end >= 0 else len(src.skel))
    if not found:
        raise SourceError("%s: REASONS is empty" % PROTO_RS)
    unique_or_fail(src, "reason", found)
    return {r: PROTO_RS for r in found}


def code_methods(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    found = [src.literal_at(m.end() - 1) for m in re.finditer(r"const NAME: &'static str = \"", src.skel)]
    if not found:
        raise SourceError("%s: no method `NAME` constants" % PROTO_RS)
    unique_or_fail(src, "method name", found)
    return {name: PROTO_RS for name in found}


def tags(enum):
    def reader(root):
        src = Source(AAD_RS, read(root, AAD_RS))
        return {snake(v): n for v, n in numbered_variants(src, enum)}

    return reader


STR_TYPE = r"(?:&\s*(?:'static\s+)?str|ExitToken)"
CONST_DEF = re.compile(r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*%s\s*=\s*\"" % STR_TYPE)
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
            consts.setdefault(m.group(1), set()).add(src.literal_at(m.end() - 1))
        for m in HELPER_DEF.finditer(src.skel):
            if m.group(1) != "new":
                helpers.add(m.group(1))
    found = {}

    def take(value, src):
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            values = {value[1:-1]}
        else:
            m = CONST_REF.match(value)
            values = consts.get(m.group(1), set()) if m else set()
        for v in values:
            if TOKEN.match(v):
                found.setdefault(v, src.rel)

    calls = [r"\bFailure::new\s*\("] + [r"(?<!\w)(?<!fn )%s\s*\(" % re.escape(h) for h in sorted(helpers)]
    call = re.compile("|".join(calls))
    for src in sources:
        for m in call.finditer(src.skel):
            take(src.first_arg(m.end() - 1), src)
        for m in re.finditer(r"\btoken\s*:\s*", src.skel):
            k = m.end()
            if src.skel.startswith('"', k):
                take('"%s"' % src.literal_at(k), src)
            else:
                ident = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Z0-9_]*\b", src.skel[k:])
                if ident:
                    take(ident.group(0), src)
        for start, end in src.fn_bodies("token"):
            for lit in src.literals(start, end):
                take('"%s"' % lit, src)
            for ident in re.findall(r"\b[A-Z][A-Z0-9_]*\b", src.skel[start:end]):
                if ident in consts:
                    take(ident, src)
        for lit in src.literals(0, len(src.skel)):
            m = PRINTED_PREFIX.match(lit)
            if m:
                take('"%s"' % m.group(1), src)
    if not found:
        raise SourceError("no CLI failure tokens found under crates/*/src")
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
                     name="Tool", grammar=TOOL, code=None),
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


def check_code(reg, rows, code):
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
    if numbered:
        lo, hi = spec["range"]
        landed = {(k, n) for k, n, s, _ in rows if s in ("landed", "reuse")}
        for key, number in sorted(code.items(), key=lambda kv: kv[1]):
            if lo <= number <= hi and (key, number) not in landed:
                fail("%s: the code has `%s` = %d in the reserved range with no `landed` row for it" % (where, key, number))


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
    codes = read_code(root)
    for reg, rows in checked.items():
        check_code(reg, rows, codes[reg])
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
