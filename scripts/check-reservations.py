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
- a malformed name, an unknown task or status, a spare row that is not
  `reserved`, or a number outside the table's reserved range;
- against the code, where the registry has a source the script reads: a
  `reserved` row whose name or number the code already uses, a `landed`
  row the code does not hold exactly so, a `reuse` row the code does not
  hold, and, in a numbered table, a code entry in the reserved range with
  no `landed` row. A code source that yields nothing is an error, never an
  empty registry.

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

# Code sources, relative to the root.
AUDIT_RS = "crates/envcloak-core/src/audit/record.rs"
AAD_RS = "crates/envcloak-core/src/crypto/aad.rs"
PROTO_RS = "crates/envcloak-ipc/src/proto.rs"
CLIENT_RS = "crates/envcloak-ipc/src/client.rs"
CLI_SRC = "crates/envcloak-cli/src"
CRATES = "crates"

problems = []


def fail(msg):
    problems.append(msg)


def read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise SourceError("%s could not be read (%s)" % (rel, e.strerror))


class SourceError(Exception):
    pass


def strip_line_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def enum_body(text, name, rel):
    m = re.search(r"pub enum %s\s*\{(.*?)\n\}" % re.escape(name), text, re.S)
    if not m:
        raise SourceError("%s has no `pub enum %s`" % (rel, name))
    return strip_line_comments(m.group(1))


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def numbered_variants(text, enum, rel):
    body = enum_body(text, enum, rel)
    found = re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*=\s*(-?\d+)\s*,", body, re.M)
    if not found:
        raise SourceError("%s: `%s` has no numbered variants" % (rel, enum))
    return [(v, int(n)) for v, n in found]


def match_arms(text, enum, rel, value):
    arms = re.findall(r"%s::([A-Z][A-Za-z0-9]*)\s*=>\s*%s" % (enum, value), text)
    if not arms:
        raise SourceError("%s: no `%s::<variant> => ...` arms" % (rel, enum))
    return arms


def code_audit_kinds(root):
    text = read(root, AUDIT_RS)
    numbers = dict(numbered_variants(text, "AuditKind", AUDIT_RS))
    tokens = dict(match_arms(text, "AuditKind", AUDIT_RS, r'"([a-z][a-z0-9_]*)"'))
    missing = sorted(set(numbers) - set(tokens))
    if missing:
        raise SourceError("%s: AuditKind variants without a token: %s" % (AUDIT_RS, ", ".join(missing)))
    return {tokens[v]: n for v, n in numbers.items()}


def code_error_kinds(root):
    text = read(root, PROTO_RS)
    codes = dict(match_arms(text, "ErrorKind", PROTO_RS, r"(-\d+)\s*,"))
    tokens = dict(match_arms(text, "ErrorKind", PROTO_RS, r'"([a-z][a-z0-9_]*)"\s*,'))
    missing = sorted(set(codes) ^ set(tokens))
    if missing:
        raise SourceError("%s: ErrorKind variants without both a code and a token: %s" % (PROTO_RS, ", ".join(missing)))
    return {tokens[v]: int(c) for v, c in codes.items()}


def code_reasons(root):
    text = read(root, PROTO_RS)
    m = re.search(r"pub const REASONS: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not m:
        raise SourceError("%s has no `pub const REASONS`" % PROTO_RS)
    found = re.findall(r'"([^"]*)"', strip_line_comments(m.group(1)))
    if not found:
        raise SourceError("%s: REASONS is empty" % PROTO_RS)
    return set(found)


def code_methods(root):
    text = read(root, PROTO_RS)
    found = re.findall(r"const NAME: &'static str = \"([^\"]+)\";", text)
    if not found:
        raise SourceError("%s: no method `NAME` constants" % PROTO_RS)
    return set(found)


def tags(enum):
    def reader(root):
        text = read(root, AAD_RS)
        return {snake(v): n for v, n in numbered_variants(text, enum, AAD_RS)}

    return reader


def code_exit_tokens(root):
    """Tokens the CLI prints for its own failures: the first argument of
    every `Failure::new`, every `token: "..."` field, and the connection
    tokens of `ClientError::token`."""
    found = set()
    base = os.path.join(root, CLI_SRC)
    files = 0
    for dirpath, _, names in os.walk(base):
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            files += 1
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                text = f.read()
            found.update(re.findall(r'Failure::new\(\s*"([a-z][a-z0-9_]*)"', text))
            found.update(re.findall(r'\btoken:\s*"([a-z][a-z0-9_]*)"', text))
    if files == 0:
        raise SourceError("%s holds no Rust files" % CLI_SRC)
    text = read(root, CLIENT_RS)
    m = re.search(r"pub fn token\(self\) -> &'static str \{(.*?)\n    \}", text, re.S)
    if not m:
        raise SourceError("%s has no `ClientError::token`" % CLIENT_RS)
    found.update(re.findall(r'"([a-z][a-z0-9_]*)"', m.group(1)))
    if not found:
        raise SourceError("no CLI failure tokens found under %s" % CLI_SRC)
    return found


def code_statement_domains(root):
    """Statement domains written as string literals in the workspace's Rust
    files (`b"envcloak-statement/1\n"`); a domain named in a comment is
    not one the code uses."""
    found = set()
    for dirpath, dirnames, names in os.walk(os.path.join(root, CRATES)):
        dirnames[:] = [d for d in dirnames if d != "target"]
        for name in names:
            if not name.endswith(".rs"):
                continue
            with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                found.update(re.findall(r"b?\"(envcloak-[a-z0-9-]*statement/[0-9]+)", f.read()))
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


def check_code(root, reg, rows):
    spec = REGISTRIES[reg]
    where = "%s `%s`" % (spec["doc"], reg)
    if spec["code"] is None:
        for key, _, status, _ in rows:
            if status == "reuse":
                fail("%s: `%s` is `reuse`, but this table has no code source to check it against" % (where, key))
        return
    try:
        code = spec["code"](root)
    except SourceError as e:
        fail("%s: %s" % (where, e))
        return
    numbered = isinstance(code, dict)
    by_number = {n: k for k, n in code.items()} if numbered else {}
    for key, number, status, _ in rows:
        present = key in code
        if status == "reserved":
            if present:
                fail("%s: `%s` is reserved, but the code already has it: mark it `landed` if its task added it, `reuse` if it is older, or pick another name" % (where, key))
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
    for reg, rows in checked.items():
        check_code(root, reg, rows)
    if problems:
        for p in problems:
            print("check-reservations: " + p, file=sys.stderr)
        return 1
    count = sum(len(r) for r in checked.values())
    print("check-reservations: ok (%d rows in %d tables)" % (count, len(checked)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
