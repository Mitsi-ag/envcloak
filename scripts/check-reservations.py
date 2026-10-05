#!/usr/bin/env python3
"""Checks the names and numbers reserved for the M2 and M2b tasks (plan
decision D-23) and the M3 tasks (M3 plan, lane C rule 9) against each
other and against the code.

Two lanes that append to the same fixed table can pick the same number or
name (review R-7). So every shared registry the M2, M2b and M3 tasks add
to is assigned up front, in tables between `<!-- reservations:<registry>
-->` and `<!-- /reservations -->` markers in docs/IPC.md and docs/VAULT.md,
under the headings "Reserved for M2 and M2b" and "Reserved for M3". A task
takes the rows it is named in; to take another, or a new one, it changes
the table in its own pull request.

Each section holds a registry's table at most once, and the script reads
a registry's tables in both sections as one table, so a name or number is
taken once across them (task M3-01: -32051 reserved under both headings is
a number reserved twice). A table outside those two headings is an error.
A row of an M2 or M2b task (or M1-AUDIT) belongs under "Reserved for M2
and M2b" and a row of an M3 task or join under "Reserved for M3"; a later
milestone (a bare `M<n>`) is a task only in the section of an earlier
milestone, and `spare` in either. The app-role methods have their own
table, `app_method`: every name in it starts with `app.` and no name in
the client `method` table does, and each is read from the `impl Method
for` blocks of envcloak-ipc, split by that prefix (M1's `APP_METHODS` list
is not read: it holds names for gate 22's test and the log, no methods).
The unlocker kinds are read from `UnlockerKind` (envcloak-core's
crypto/envelope.rs); M1's two are in the baseline.

Where the code reads a stored number back with arms of its own, the
reader reads that decoder too, so it cannot hold a second mapping (review
of task M3-01: a second number for one unlocker kind passed): every arm
of `UnlockerKind::from_byte` and of `item_class_from` (vault/state.rs) is
`<integer literal> [if <guard>] => Some(<Enum>::<Variant>)` naming the
variant that number declares, and the last is `_ => None`; every arm of
`PolicyRecord::decode` is `(<kind>, <version>) => PolicyRecord::<Record>(..)`
whose kind is the number of the `PolicyKind` that `PolicyRecord::kind`
gives that record. A number read twice, or as a variant another number
declares, is an error, and a decoder of another form is refused, never
skipped. Each decoder must also read back every variant it declares (the
review of round two: a decoder without the Recovery Kit's arm passed),
but those the `NOT_DECODED` list names with the reason they are never
stored (`ItemClass::None`, the class of a row that is not an item), which
it must not read at all. `AuditKind::from_u8` and `ErrorKind::from_token`
search `ALL` with `as u8` and `token()`, so their mapping is the
declaration's own; `ALL` must then name every variant once, or the code
could not read back an entry it writes.

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
`#[cfg(test)]` modules left out). Each rule below reads a form or refuses
it, never skipping one (reviews of M2-RES1: forms that were neither read
nor refused let a reserved token through).

What is read. Every `.rs` file under each crate's `src/`, and nothing
the compiler builds a crate from is elsewhere (verifier review of
M2-RES1: a `#[path]` module in another directory, and a source
directory that was a symbolic link, compiled unread): a `#[path]`
attribute (also under `cfg_attr`, and `path = ` where a macro could
make one, as scripts/check-unsafe.sh has it) is refused, and so are a symbolic link
anywhere under a `src/`, a `.rs` entry that is not a regular file, a
library or binary target whose file a manifest puts outside its crate's
`src/`, a path dependency outside `crates/` (manifests are read as
text: a `path` whose value is not one plain string, and a quoted key
with an escape, are refused), and a workspace member
outside `crates/` other than the two canaries (which no crate may depend
on, scripts/check-unsafe.sh). scripts/check-unsafe.sh refuses `#[path]`
and `include!` in every Rust file too, and scripts/check-sources.sh
settles one a macro builds from pieces with the compiler's own list of
the files it read.

The source readers support ASCII Rust code tokens. Non-ASCII code outside
comments, string and character literals, and the omitted test modules is
refused before any reader runs. Unicode text in those places is kept;
Unicode identifiers and lifetimes are unsupported, never silently skipped.

Where a failure gets its token. `Failure` is defined once, in
crates/envcloak-client/src/fail.rs, with named fields, one of them a
private `token` of a static string type, and with no attribute or derive
but `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord` and
`Hash` (a derived `Default` or `Deserialize` would make a failure the
reader does not see); fail.rs declares no module in another file (a child
module could reach the field). In fail.rs every mention of `token` is one
the reader has read or knows to change nothing: the field's declaration,
a `Failure` literal's field, the field read whole as a token
(`self.token` where a failure is made, its token printed or returned),
`Failure::new`'s parameter and where it hands it on, `fn token` and a
`.token()` call; any other (a pattern that binds the field, `ref mut`,
an assignment, `clone_from`, a macro, a local of that name) is refused.
So no code can set a failure's token but by making one, and a token is
read where a failure is made: the first argument of every call of `new`
on `Failure`. Each `::new` in the sources is read back to the type it is
called on, whatever comes before (verifier review of M2-RES1: a pattern
anchored at the path's start missed `::envcloak_client::fail::Failure::
new` and `<Self>::new`): a path with or without a leading `::`, a
qualified path (`<Failure>::new`, `return <F<'a>>::new`), a turbofish
(`F::<'a>::new`), `Self` in an `impl` of `Failure` or of a trait for it,
and every name `Failure` is imported or defined as, whatever its case
(`use ... Failure as fail`, `pub use ... as X`, `type X = Failure;`,
`type X<'a> = Failure;`, and aliases of those). Refused: `new` on a type
the reader cannot tell, which could be `Failure` (a macro's
metavariable, `$t::new` or `<$t>::new`; `<_>`; a type a macro makes), a
trait's `new` for `Failure` (`<Failure as T>::new`), a type alias that
names `Failure` any other way, and an import or a type alias a macro
builds from a metavariable (`use $p as Q;`, `use .. as $n;`, `type $n =
..;`, `type Q = $t;`) or of a type a macro makes (`type Q = m!();`). Also
read: the `token` field of a `Failure` struct literal, written out or
shorthand; and the argument at each `token` position of a token helper,
a free or inherent function with a `token: &'static str` parameter (or
`ExitToken`, or an alias of either, made with `type` or `use ... as`) in
any position, at every call by name. `Failure::new` or a token helper
named any other way (a function pointer, `use ... as`) is refused, since
its callers' tokens could not be read, and so is a function with a
`token` to hand on inside a trait or a trait's implementation, which
code calls without naming it (`.into()` and `?` call `From::from`, a
generic `T::new` a trait's `new`): only the inherent `Failure::new` in
fail.rs is `Failure`'s constructor. A raw identifier is read as its name
(`r#token` is `token`).

What a token argument may be. A string literal, a `&str` constant or
static by name, `concat!` of literals (read joined), another value's
`.token()`, or an `if` with its `else`, a `match` or a block (after
`use` items only) whose every value is one of those; in a token helper
(and in `Failure::new`) also the helper's own `token`, which it may only
hand on so: a `let`, a pattern, a closure or any other use of that name
there is refused, since a value its callers did not pass could then
reach a failure. Anything else is refused. A constant or static is read
by its whole initializer, by the same rules, never by its leading
literal (Codex review of M2-RES1: `"approval_required".split_at(9).1`
was read as `approval_required`); one that is mutable, or whose value
cannot be read, is refused where it is named as a token, and a name
defined more than once counts every definition. A name in capitals is a
constant's: the lint overrides that would let a local, a parameter or a
pattern be named so (`non_snake_case`, `nonstandard_style`, `warnings`,
in the sources or a manifest) are refused, and CI denies warnings. A
`.token()` is read from the workspace's `fn token` bodies (no dependency
in Cargo.lock has one that returns a string): every string in any of
them counts, and one that returns a static string (`&'static str`,
`ExitToken` or an alias) must have only such values. Since a `.token()`
cannot be told from a failure's, every method named `token` returns a
static string so read: one that returns anything else (a borrow of its
receiver's field, a `String`, another type) is refused, and is renamed
(Codex review of M2-RES1: one lending a field was passed over while a
`.token()` printing it was taken). A free function named `token` is not
what `.token()` calls. A `fn`, `const` or `static` named by a macro's
metavariable, which could be a `fn token` or a constant named as a token
the reader does not see, is refused.

What is printed. Every string literal and every `concat!` the reader
can read is searched for `envcloak: <token>:` anywhere in it (a slice of
it, or a later line, prints it too), with any white space after the
colon, whatever crate it is in; the token
counts (a line printed directly, as `eprintln!` does for `coverage`,
`warning` and `usage`). A placeholder right after `envcloak:`, with
white space or none (padding such as `{:>16}`, or the value itself, can
give the space: verifier review of M2-RES1), and before `:` prints its
argument where a token goes, which must be a token argument as above
(counted among the format string's placeholders, so one after a newline
takes the right argument), its values counted without the white space
around them. Elsewhere in a line and not followed by `:`, its value is
counted by the token it starts with when the reader can read it (a
value can bring its own colon). A token in pieces is refused: a
placeholder followed by more of a token or by another placeholder
(`envcloak: {}{}:`), the start of a token followed by a placeholder
(`envcloak: pty_{}:`), and a placeholder right after `envcloak`
(`envcloak{}`), whose value could bring `: <token>:`. A format string
is also read with the values of its arguments the reader can read put
in its placeholders (a literal, a constant, also one captured by name,
`{NAME}`, a named argument, `concat!`, a conditional of those; Cargo's
name for the package, crate or binary, `env!("CARGO_PKG_NAME")`, taken
as the program's, `envcloak`), so a
line whose `envcloak:` or token is such an argument (`"{}: {}: x",
"envcloak", "tok"`) is read as printed. At the start of a line,
`envcloak: {x}` is a usage line: it must be printed in the arm of `match parse(..)`
that binds `x` (`Err(x)`, or `E::V(x)` for an error enum `E`), with a
free `fn parse` in its file (a method of that name is not the one
called), and every value that `fn parse` can give as its error is read
as a token argument, its leading `<token>:` counting (and that of every
string in `fn parse`): the error is `&'static str`, or an enum of that
file whose bound variant holds one, which derives nothing that converts
and whose every `From` is in that file and hands its value to a variant
unchanged (an `Into` for it, or a conversion a macro makes for a type
it is given, is refused); in `fn parse` the error is given only as
`Err(<value>)` (a variant around it, or `.into()` after it, read
through), by a `?` after `Err(..)`, `.ok_or(<value>)`, `.ok_or_else(||
<value>)` or `.map_err(|..| <value>)`, and every `return`, and the last
expression, is `Ok(..)` or `Err(..)`; a macro there other than
`concat!`, or anything else, is refused.

Text from outside the source is refused: `include!`, `include_str!` and
`include_bytes!` (another file's text), `env!` or `option_env!` of a
variable other than Cargo's own package variables (the build's
environment), a build script that sets one (`rustc-env`), `stringify!`
of text that holds `envcloak`, and `concat!` of anything but literals
(also in the statement-domain reader); so is a source directory that
cannot be listed. The statement-domain reader reads every Rust file
under `crates/` (tests too) by the same walk, and the text of the files
`include_str!` and `include_bytes!` bring in from the repository; it
refuses `include!`, `#[path]`, a symbolic link to a directory or a Rust
file, and `env!` of a variable Cargo does not set. The boundary: a line
put together at run time from pieces is beyond what a reader of the
source can see: a value printed that only the run knows (a count, a
label, the program's name the panic hook is given and prints as
`{program}:`), and a line printed in more than one call (`eprint!` then
`eprintln!`); review keeps failures out of such lines, and
`Failure::report` prints each one whole.
Within these forms the reader over-counts rather than under-counts: a
string it takes for a token that is not printed makes a `reserved` row
with that name fail, which is a name to avoid anyway, and a new one
needs a `landed` row like any token. It also takes the tokens of audit
kinds, error kinds and reasons, so a `landed` or `reuse` row in one of
the tables printed as `envcloak: <token>`, or in the audit-kind table,
accounts for a failure token; a row in any other table does not. A table
with no code reader yet (the coverage tokens, fields and sign-in tokens)
takes no `landed` row: the task that lands one adds its reader first. The
policy kinds are read from `PolicyKind` in the vault's policies module
(M2-07). The control messages are read, channel by channel, from the
enums CONTROL_CHANNELS names (M2-17: the PTY monitor's `Report` and
`Command`); a channel it does not name has no reader yet, so its rows
stay `reserved`, and a `landed` row there fails as one the code lacks.

Usage: scripts/check-reservations.py [--root <repository root>]
Prints "check-reservations: ok" and exits 0, or names every problem on
stderr and exits 1.
"""

import os
import re
import stat
import sys

DOCS = ("docs/IPC.md", "docs/VAULT.md")

TOKEN = re.compile(r"^[a-z][a-z0-9_]*$")
METHOD = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
# The client methods' table refuses an `app.` name, which belongs in the
# app-method table, where every name has that prefix.
CLIENT_METHOD = re.compile(r"^(?!app\.)[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
APP_METHOD = re.compile(r"^app(\.[a-z][a-z0-9_]*)+$")
# A field of a method's parameters or answer, nested with dots
# (`daemon.identity` in `status`), and `=<value>` for a value it can take.
FIELD = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(=[a-z][a-z0-9_]*)?$")
MESSAGE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
DOMAIN = re.compile(r"^envcloak-[a-z0-9-]+/[1-9][0-9]*$")
TOOL = re.compile(r"^[a-z][a-z0-9_]*(_\*)?$")

M2_TASKS = (
    {"M2-%02d" % n for n in range(1, 29)}
    | {"M2b-%02d" % n for n in range(1, 12)}
    # Repairs of M1 that the M2 plan schedules (plan section 8).
    | {"M1-AUDIT"}
)
# The M3 plan's lane-C tasks and its joins (M3 plan section 7).
M3_TASKS = {"M3-%02d" % n for n in range(1, 22)} | {"M3-J%d" % n for n in range(1, 7)}
# Later milestones, named bare.
LATER = {"M%d" % n for n in range(3, 12)}
TASKS = M2_TASKS | M3_TASKS | LATER | {"spare"}
# The headings a reservations table sits under: each section's own tasks,
# and its milestone (a bare later milestone must come after it).
SECTIONS = {
    "Reserved for M2 and M2b": (M2_TASKS, 2),
    "Reserved for M3": (M3_TASKS, 3),
}
HEADING = re.compile(r"^## (.*?)[ \t]*$", re.M)
STATUSES = ("reserved", "landed", "reuse")
COVERAGE_KINDS = ("surface", "state", "reason", "outcome", "availability", "sentinel", "case", "probed",
                  "identity")

# The tables whose tokens the person reads as `envcloak: <token>`: one
# namespace, so one name never means two things there (R-7).
PRINTED = ("error_kind", "reason", "exit_token", "signin_token")

# A name meant to be the same token in two of the PRINTED tables, with the
# tables it may be in. Empty: no reserved name is shared today. An entry
# needs a code owner's agreement that both rows mean one thing (this file
# is code-owned, .github/CODEOWNERS, which binds once main's branch
# protection requires code-owner review; until then it is the reviewers'
# rule, not the host's).
SHARED = {}

# Code sources, relative to the root.
AUDIT_RS = "crates/envcloak-core/src/audit/record.rs"
AAD_RS = "crates/envcloak-core/src/crypto/aad.rs"
ENVELOPE_RS = "crates/envcloak-core/src/crypto/envelope.rs"
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
# `r#` before an identifier: a raw identifier, the same name as without.
RAW_IDENT = re.compile(r"(?<![A-Za-z0-9_])r#(?=[A-Za-z_])")
# The macros whose text is made at compile time.
COMPILE_TIME = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:::)?(?:std|core)::)?"
    r"(concat|stringify|include_str|include_bytes|include|option_env|env)\s*!\s*[\(\[\{]"
)
# The variables Cargo sets from a package's manifest, none of which can
# hold a line of text (a version, a path, a package or crate name).
CARGO_ENV = {"CARGO_PKG_VERSION", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "CARGO_CRATE_NAME", "CARGO_BIN_NAME"}
# The ones that name the package, the crate or the binary.
CARGO_NAMES = {"CARGO_PKG_NAME", "CARGO_CRATE_NAME", "CARGO_BIN_NAME"}
FLOAT = re.compile(r"(-?)\s*([0-9][0-9_]*\.[0-9][0-9_]*(?:[eE][+-]?[0-9_]+)?|[0-9][0-9_]*[eE][+-]?[0-9_]+)(?:f32|f64)?")


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
        # A raw identifier is the plain one (`r#token` names `token`): its
        # `r#` is blanked in both views, so every reader sees the name.
        raws = [(m.start(), m.end()) for m in RAW_IDENT.finditer(self.skel)]
        if raws:
            self.code = _blank_spans(self.code, raws)
            self.skel = _blank_spans(self.skel, raws)
        tests = []
        for m in TEST_MOD.finditer(self.skel):
            if not tests or m.start() >= tests[-1][1]:
                tests.append((m.start(), self.block_end(m.end() - 1)))
        if tests:
            self.code = _blank_spans(self.code, tests)
            self.skel = _blank_spans(self.skel, tests)
        unsupported = re.search(r"[^\x00-\x7f]", self.skel)
        if unsupported:
            line = self.skel.count("\n", 0, unsupported.start()) + 1
            raise SourceError(
                "%s line %d: unsupported non-ASCII Rust code; use ASCII "
                "code tokens outside comments, literals and cfg(test) modules"
                % (rel, line)
            )
        # start -> (end, value); and the starts in order.
        self.strings = {}
        for start, quote, close, end, raw in strings:
            if any(a <= start < b for a, b in tests):
                continue
            body = text[quote + 1: close]
            self.strings[start] = (end, body if raw else unescape(rel, body))
        self.starts = sorted(self.strings)
        self.read_macros()

    def read_macros(self):
        """The text the compile-time macros make: `concat!` is read joined
        (start -> (end, value), the value None when a part is not a
        literal); and where the reader cannot know the text one makes, it
        is kept in `unreadable` as (offset, kind, why): `concat!` of
        anything but literals, `stringify!` of `envcloak`, `include!`,
        `include_str!` and `include_bytes!` (text from another file), and
        `env!` or `option_env!` of a variable other than Cargo's own
        (text from the build's environment)."""
        self.concats = {}
        self.unreadable = []
        self.env_vars = {}
        self.includes = {}
        for m in COMPILE_TIME.finditer(self.skel):
            name, open_at = m.group(1), m.end() - 1
            close = self.close_of(open_at)
            if name == "concat":
                self.concats[m.start()] = (open_at, close + 1)
            elif name == "stringify":
                if "envcloak" in self.code[open_at:close]:
                    self.unreadable.append((m.start(), "stringify", "`stringify!` of text that holds `envcloak`: write the line as a string literal"))
            elif name.startswith("include"):
                kind = "include" if name == "include" else "include_text"
                parts = self.split_top(open_at + 1, close)
                self.includes[m.start()] = self.only_string(parts[0][0], parts[0][1]) if len(parts) == 1 else None
                self.unreadable.append((m.start(), kind, "`%s!` brings in text from another file, which the reader does not read" % name))
            else:
                parts = self.split_top(open_at + 1, close)
                var = self.only_string(parts[0][0], parts[0][1]) if parts else None
                self.env_vars[m.start()] = var if len(parts) <= 2 else None
                if var not in CARGO_ENV or len(parts) > 2:
                    self.unreadable.append((m.start(), "env", "`%s!` of a variable other than Cargo's own package variables (%s): its text comes from the build's environment, which the reader cannot see" % (name, ", ".join(sorted(CARGO_ENV)))))
        values = {}

        def value(start):
            if start not in values:
                values[start] = None
                open_at, end = self.concats[start]
                out = []
                for x, y, _ in self.split_top(open_at + 1, end - 1):
                    v = self.literal_text(x, y)
                    if v is None:
                        x, y = self.strip(x, y)
                        if x in self.concats and self.concats[x][1] == y:
                            v = value(x)
                    if v is None:
                        out = None
                        break
                    out.append(v)
                values[start] = None if out is None else "".join(out)
            return values[start]

        for start in sorted(self.concats):
            if value(start) is None:
                self.unreadable.append((start, "concat", "`concat!` of something other than literals: the reader cannot read the string it makes"))
        self.concat_values = values

    def env_var(self, at):
        """The variable the `env!` or `option_env!` at `at` names, when it
        is one string literal; else None."""
        return self.env_vars.get(at)

    def strip(self, a, b):
        while a < b and self.skel[a].isspace():
            a += 1
        while b > a and self.skel[b - 1].isspace():
            b -= 1
        return a, b

    def literal_text(self, a, b):
        """The text `concat!` makes of the literal at [a, b): a string, a
        character, an integer (in decimal), a float (as written) or a
        bool; None for anything else."""
        s = self.only_string(a, b)
        if s is not None:
            return s
        a, b = self.strip(a, b)
        raw = self.code[a:b]
        c = CHAR.fullmatch(raw)
        if c:
            return unescape(self.rel, raw[1:-1])
        n = int_value(raw)
        if n is not None:
            return str(n)
        f = FLOAT.fullmatch(raw)
        if f:
            return f.group(1) + f.group(2)
        if raw in ("true", "false"):
            return raw
        return None

    def texts(self, start, end):
        """(offset, text) of every string literal and every `concat!` the
        reader can read that starts inside [start, end), in order."""
        out = [(s, self.strings[s][1]) for s in self.starts if start <= s < end]
        out += [(s, v) for s, v in self.concat_values.items() if start <= s < end and v is not None]
        return sorted(out)

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

    def open_of(self, close_at):
        """The offset of the bracket that opens the `)`, `]` or `}` at
        `close_at`, counting all three kinds, or None."""
        depth = 0
        for k in range(close_at, -1, -1):
            ch = self.skel[k]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                depth -= 1
                if depth == 0:
                    return k
        return None

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
        """The value of every string literal, and of every `concat!` the
        reader can read, that starts inside [start, end)."""
        return [v for _, v in self.texts(start, end)]


def walk_error(e):
    """`os.walk`'s `onerror`: a directory that cannot be listed is an
    error, never a directory with nothing in it."""
    raise SourceError("%s could not be listed (%s)" % (e.filename, e.strerror))


def rust_files(root, top, skip=(), any_link=False):
    """The paths, relative to `root`, of every `.rs` file under `top`
    (a crate's own directories named in `skip`, such as a build's
    `target/`, left out: only right under `crates/<name>/`, never a module
    of that name), refusing what the compiler can
    read and a walk would not (verifier review of M2-RES1): a directory
    that cannot be listed, a symbolic link to a directory (which the walk
    does not enter, while `mod` reads through it) or to a `.rs` file, any
    symbolic link at all with `any_link`, and a `.rs` entry that is not a
    regular file."""
    out = []
    for dirpath, dirnames, names in os.walk(os.path.join(root, top), onerror=walk_error):
        crate_level = len(os.path.relpath(dirpath, root).split(os.sep)) == 2
        dirnames[:] = sorted(d for d in dirnames if not (crate_level and d in skip))
        for d in dirnames:
            if os.path.islink(os.path.join(dirpath, d)):
                raise SourceError("%s is a symbolic link to a directory, whose files the reader would not read; keep the sources in the tree" % os.path.relpath(os.path.join(dirpath, d), root))
        for file in sorted(names):
            path = os.path.join(dirpath, file)
            rel = os.path.relpath(path, root)
            rust = file.endswith(".rs")
            if os.path.islink(path) and (rust or any_link):
                raise SourceError("%s is a symbolic link; keep the sources in the tree" % rel)
            if not rust:
                continue
            try:
                regular = stat.S_ISREG(os.lstat(path).st_mode)
            except OSError as e:
                raise SourceError("%s could not be read (%s)" % (rel, e.strerror))
            if not regular:
                raise SourceError("%s is not a regular file" % rel)
            out.append(rel)
    return out


def rust_sources(root, crate=None):
    """Every Rust file under `crates/<crate>/src/` (every crate's, or the
    one named), as `Source`s. A symbolic link anywhere under a `src/` is
    refused (`rust_files`)."""
    out = []
    base = os.path.join(root, CRATES)
    try:
        crates = sorted(os.listdir(base)) if crate is None else [crate]
    except OSError as e:
        raise SourceError("%s could not be listed (%s)" % (CRATES, e.strerror))
    for name in crates:
        if crate is None and os.path.isfile(os.path.join(base, name)):
            continue  # a file beside the crates (a `.DS_Store`) is no crate
        for rel in rust_files(root, os.path.join(CRATES, name, "src"), any_link=True):
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
    """{variant: value} from the arms `Enum::A | Enum::B => <value>` (or
    `Self::A`) of `<enum>::<fn>`, for every variant of `enum`. The
    function is read whole, as `match_arms` reads a decoder: its body is
    `match self { .. }` and nothing else, and every arm is one the reader
    reads, with no attribute and no guard, so no arm the reader counts is
    compiled out or never taken, and no arm it does not count gives a
    value (Codex's review of M3-01, the class of a mapping read in part).
    A variant with no such arm, or with two, a value given to two variants,
    an arm naming no variant and an arm of another form are errors.
    `convert` turns the matched text into the value, or None if it
    cannot."""
    variants = [v for v, _ in enum_variants(src, enum)]
    _, arms = match_arms(src, fn, impl=enum, scrutinee="self")
    path = r"(?:%s|Self)\s*::\s*[A-Z][A-Za-z0-9]*" % enum
    paths = re.compile(r"(?:%s\s*\|\s*)*%s" % (path, path))
    pairs, unread = [], []
    for pat, val in arms:
        m = re.match(value, val)
        if not paths.fullmatch(pat) or not m:
            unread.append("%s => %s" % (pat, val))
            continue
        x = convert(m.group(1))
        if x is None:
            raise SourceError("%s: `fn %s` gives `%s` a value the reader cannot read (`%s`)" % (src.rel, fn, pat, m.group(1)))
        # The literal is the arm's whole expression, never the start of a
        # longer one (review M2R-1).
        if m.end() != len(val):
            raise SourceError("%s: `fn %s` gives `%s` an expression the reader cannot read (`%s`): an arm's value is one literal" % (src.rel, fn, pat, val))
        for v in re.findall(r"(?:%s|Self)\s*::\s*([A-Z][A-Za-z0-9]*)" % enum, pat):
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
    if unread:
        raise SourceError("%s: `fn %s` has an arm the reader cannot read (`%s`): it reads `%s::<Variant> => <value>`, with no attribute or guard" % (src.rel, fn, unread[0][:80], enum))
    return {v: xs[0] for v, xs in by_variant.items()}


TOKEN_VALUE = r"(?:r#*)?\"([a-z][a-z0-9_]*)\""
CODE_VALUE = r"(-?\s*[0-9][0-9A-Za-z_]*)"


MATCH = re.compile(r"\bmatch\b[^{;]*\{")
INT_PATTERN = r"-?\s*(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|[0-9][0-9_]*)(?:[iu](?:8|16|32|64|128|size))?"


def collapse(text):
    """`text` with each run of white space one space, and none at the ends."""
    return " ".join(text.split())


def one_fn(src, fn, impl=None):
    """(where, Fn) of the one `fn <fn>` with a body: in an inherent `impl
    <impl>` block when `impl` is given, else anywhere in the file. A
    second such function or none is an error."""
    found = [f for f in fn_items(src) if f.name == fn and f.body]
    where = "`fn %s`" % fn
    if impl:
        spans = impl_spans(src, {impl}, traits=False)
        found = [f for f in found if any(x < f.start < y for x, y in spans)]
        where = "`%s::%s`" % (impl, fn)
    if len(found) != 1:
        raise SourceError("%s has %d %s, not one the reader can read" % (src.rel, len(found), where))
    return where, found[0]


def match_arms(src, fn, impl=None, scrutinee=None, before="", after=""):
    """(where, arms): the (pattern, value) of every arm of the one `match`
    in the one `fn <fn>` (see `one_fn`), each with its white space
    collapsed. The function's body must be `<before> match <scrutinee> {
    <arms> } <after>` and nothing else, white space aside: the `match`
    reads the input as the function took it (or as `before` read it), no
    statement before it changes that input, and what the function gives
    is the arm's value as `after` passes it on. So what the reader reads
    of the arms is what the function computes (Codex's review of M3-01: a
    decoder that changed its input before its `match` passed). A second
    such function or none, a body of another form, and an arm the reader
    cannot split are errors."""
    if scrutinee is None:
        raise SourceError("%s: the script reads `fn %s` without naming what it matches on" % (src.rel, fn))
    where, f = one_fn(src, fn, impl)
    a, b = f.body
    found = list(MATCH.finditer(src.skel, a, b))
    if len(found) != 1:
        raise SourceError("%s: %s holds %d `match`, not the one the reader reads" % (src.rel, where, len(found)))
    m = found[0]
    open_ = m.end() - 1
    close = src.close_of(open_)
    on = collapse(src.code[m.start() + len("match"):open_])
    if on != scrutinee:
        raise SourceError("%s: %s matches on `%s`, not on `%s`: the reader reads a `match` on the input as the function takes it, so no change to it goes unread" % (src.rel, where, on[:60], scrutinee))
    head, tail = collapse(src.code[a + 1:m.start()]), collapse(src.code[close + 1:b - 1])
    if head != before or tail != after:
        raise SourceError("%s: %s is not `%smatch %s { .. }%s` alone (it has `%s` before its `match` and `%s` after it): the reader cannot read what code around the `match` does to its input or its value" % (
            src.rel, where, before + " " if before else "", scrutinee, ("" if after.startswith(";") else " ") + after if after else "", head[:160], tail[:160]))
    arms = []
    for x, y, _ in src.split_top(open_ + 1, close):
        arm = collapse(src.code[x:y])
        parts = arm.split("=>")
        if len(parts) != 2:
            raise SourceError("%s: %s has an arm the reader cannot read (`%s`)" % (src.rel, where, arm[:80]))
        arms.append((parts[0].strip(), parts[1].strip()))
    if not arms:
        raise SourceError("%s: %s has no arms" % (src.rel, where))
    return where, arms


# The guards a decoder's arm may carry, by decoder: each a condition on the
# vault's schema, `<parameter> >= <constant>`, where the parameter is the
# decoder's own, with its type, and the constant is defined once in the
# file named. The constant must be at least 1 and at most CURRENT_SCHEMA
# (vault/schema.rs), the schema every vault is written at and migrated to,
# so the arm is taken for every vault the code writes now. Any other guard
# is an error: a guard the reader does not read can leave an arm that no
# input reaches (`2 if false`), and the decoder then refuses an entry the
# code writes as unknown (Codex's review of M3-01).
SCHEMA_GUARDS = {
    "item_class_from": [("schema", "u16", "RECORDS_V2_FROM", "crates/envcloak-core/src/vault/items.rs")],
}
SCHEMA_RS = "crates/envcloak-core/src/vault/schema.rs"


def const_u16(root, rel, name):
    """The value of the one `const <name>: u16 = <integer>;` in `rel`."""
    src = Source(rel, read(root, rel))
    found = re.findall(r"\bconst\s+%s\s*:\s*u16\s*=\s*([^;{}]+);" % re.escape(name), src.skel)
    if len(found) != 1:
        raise SourceError("%s has %d `const %s: u16 = <integer>;`, not one the reader can read" % (rel, len(found), name))
    n = int_value(found[0])
    if n is None:
        raise SourceError("%s: `const %s = %s` is not an integer literal the reader can read" % (rel, name, collapse(found[0])))
    return n


def schema_guards(root, src, fn):
    """{guard text: what it reads} for the decoder `fn <fn>`: the guards
    SCHEMA_GUARDS names for it, each checked here: the decoder has the
    parameter with its type, and the constant is between 1 and
    CURRENT_SCHEMA."""
    out = {}
    entries = SCHEMA_GUARDS.get(fn, ())
    if not entries:
        return out
    _, f = one_fn(src, fn)
    current = const_u16(root, SCHEMA_RS, "CURRENT_SCHEMA")
    for param, ty, const, rel in entries:
        if "%s: %s" % (param, ty) not in f.params:
            raise SourceError("%s: `fn %s` has no parameter `%s: %s`, which the script's SCHEMA_GUARDS names for its guard" % (src.rel, fn, param, ty))
        n = const_u16(root, rel, const)
        if not 1 <= n <= current:
            raise SourceError("%s: `%s` is %d, which is not between 1 and CURRENT_SCHEMA (%d): an arm guarded by `%s >= %s` is not taken for the vaults the code writes" % (rel, const, n, current, param, const))
        out["%s >= %s" % (param, const)] = "the schema the vault was written at"
    return out


def some_arms(src, enum, fn, impl=None, guards=None):
    """(where, [(number, variant)]) from `fn <fn>`'s arms `<integer>[ |
    <integer>] [if <guard>] => Some(<enum>::<Variant>)` (`Self::` in the
    enum's own `impl`), whose last arm is `_ => None`; any other arm is an
    error. The function is `fn <fn>(<input>: <integer type>[, ..]) ->
    Option<<enum>>` whose body is `match <input> { .. }` alone (see
    `match_arms`), and a guard is one of `guards` (see `schema_guards`) or
    an error, so no arm the reader counts is one no input reaches."""
    where, f = one_fn(src, fn, impl)
    first = re.fullmatch(r"([a-z_][a-z0-9_]*)\s*:\s*[iu](?:8|16|32|64|128|size)", f.params[0]) if f.params else None
    if not first:
        raise SourceError("%s: %s does not take its input as its first parameter, `<name>: <integer type>`, which the reader reads" % (src.rel, where))
    names = "(?:%s|Self)" % enum if impl == enum else enum
    if not re.fullmatch(r"->\s*Option\s*<\s*%s\s*>" % names, f.ret):
        raise SourceError("%s: %s gives `%s`, not `-> Option<%s>`" % (src.rel, where, f.ret[:60], enum))
    where, arms = match_arms(src, fn, impl, scrutinee=first.group(1))
    pattern = re.compile(r"(%s(?:\s*\|\s*%s)*)(?:\s+if\s+(.+))?" % (INT_PATTERN, INT_PATTERN))
    value = re.compile(r"Some\s*\(\s*%s\s*::\s*([A-Z][A-Za-z0-9]*)\s*\)" % names)
    if arms[-1] != ("_", "None"):
        raise SourceError("%s: %s does not end with `_ => None`" % (src.rel, where))
    taken = guards or {}
    out = []
    for pat, val in arms[:-1]:
        p, v = pattern.fullmatch(pat), value.fullmatch(val)
        if not p or not v:
            raise SourceError("%s: %s has an arm the reader cannot read (`%s => %s`): it reads `<integer> => Some(%s::<Variant>)`" % (src.rel, where, pat[:60], val[:60], enum))
        if p.group(2) is not None and p.group(2) not in taken:
            raise SourceError("%s: %s guards an arm with `if %s`, which the reader does not take: a guard it does not read can leave an arm no input reaches; it takes only the schema conditions the script's SCHEMA_GUARDS names (%s)" % (
                src.rel, where, p.group(2)[:60], ", ".join("`%s`" % g for g in sorted(taken)) or "none for this decoder"))
        for piece in p.group(1).split("|"):
            out.append((int_value(piece.strip()), v.group(1)))
    return where, out


# A declared entry that is never stored, so its decoder never reads it
# back, with the reason. Its decoder must hold no arm for it, and every
# other declared entry needs one (review of M3-01: a decoder without the
# Recovery Kit's arm passed, though the vault could no longer read that
# unlocker back). An entry here that the declaration no longer holds fails.
NOT_DECODED = {
    ("ItemClass", "None"): "the associated data's class of a row that is not an item (an unlocker, a backup); `items.class` never holds it",
}


def check_inverse(src, enum, where, numbers, decoded):
    """The decoder's (number, variant) pairs agree with the declaration:
    each number once, each naming a variant whose number it is, so no
    entry is read back under two numbers and no number as two entries; and
    every declared variant is read back, but the ones `NOT_DECODED` names,
    which are not read at all, so no entry the code writes is refused as
    unknown when it is read again."""
    seen = {}
    for n, v in decoded:
        if n in seen:
            raise SourceError("%s: %s reads %d twice (`%s::%s` and `%s::%s`)" % (src.rel, where, n, enum, seen[n], enum, v))
        seen[n] = v
        if v not in numbers:
            raise SourceError("%s: %s reads %d as `%s::%s`, which is not a variant" % (src.rel, where, n, enum, v))
        if numbers[v] != n:
            raise SourceError("%s: %s reads %d as `%s::%s`, whose number is %d: one entry with two numbers" % (src.rel, where, n, enum, v, numbers[v]))
        if (enum, v) in NOT_DECODED:
            raise SourceError("%s: %s reads %d as `%s::%s`, which is never stored (%s)" % (src.rel, where, n, enum, v, NOT_DECODED[(enum, v)]))
    for e, v in sorted(NOT_DECODED):
        if e == enum and v not in numbers:
            raise SourceError("%s: the script's NOT_DECODED names `%s::%s`, which `%s` does not declare" % (src.rel, e, v, enum))
    read = set(seen.values())
    missing = [v for v in sorted(numbers, key=numbers.get) if v not in read and (enum, v) not in NOT_DECODED]
    if missing:
        raise SourceError("%s: %s reads no number as %s: an entry the code declares, which it would refuse as unknown when it reads it back" % (
            src.rel, where, ", ".join("`%s::%s` (%d)" % (enum, v, numbers[v]) for v in missing)))


ALL_LIST = re.compile(r"\bconst\s+ALL\s*:\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*;[^\]=;{}]*\]\s*=\s*\[")


def check_all_list(src, enum, variants):
    """`<enum>::ALL`, the one list the decoder of a registry that holds no
    second mapping searches (`AuditKind::from_u8`, `ErrorKind::from_token`),
    names every variant of `enum` once, as `<enum>::V` or `Self::V`: a
    variant left out is an entry the code writes and then cannot read back
    (review of M3-01, the class of a decoder that misses a declared entry).
    One `const ALL` in the enum's own `impl`, or none the reader can read,
    is an error, and so is an entry with an attribute: a `#[cfg(..)]` on
    an array element takes it out of the list the code builds (rustc
    1.98, edition 2024, compiles it so), and the reader would count an entry
    the decoder never finds (Codex's review of M3-01, the class of a
    mapping read in part)."""
    spans = impl_spans(src, {enum}, traits=False)
    found = [m for m in ALL_LIST.finditer(src.skel)
             if m.group(1) in (enum, "Self") and any(a < m.start() < b for a, b in spans)]
    if len(found) != 1:
        raise SourceError("%s: `impl %s` has %d `const ALL: [%s; N] = [...]` the reader can read, not one" % (src.rel, enum, len(found), enum))
    open_ = found[0].end() - 1
    listed = []
    for a, b, _ in src.split_top(open_ + 1, src.close_of(open_)):
        item = collapse(src.code[a:b])
        v = re.fullmatch(r"(?:%s|Self)\s*::\s*([A-Z][A-Za-z0-9]*)" % enum, item)
        if not v:
            raise SourceError("%s: `%s::ALL` holds an entry the reader cannot read (`%s`): it reads `%s::<Variant>`" % (src.rel, enum, item[:60], enum))
        listed.append(v.group(1))
    unique_or_fail(src, "`%s::ALL` entry" % enum, listed)
    for v in listed:
        if v not in variants:
            raise SourceError("%s: `%s::ALL` names `%s::%s`, which is not a variant" % (src.rel, enum, enum, v))
    missing = [v for v in variants if v not in listed]
    if missing:
        raise SourceError("%s: `%s::ALL` leaves out %s, which the code would then not read back" % (
            src.rel, enum, ", ".join("`%s::%s`" % (enum, v) for v in missing)))


def check_all_search(src, enum, fn, param, key):
    """`<enum>::<fn>`, the decoder that searches `ALL`, is that search
    and nothing else: `fn <fn>(<param>) -> Option<<enum>>` whose body is
    `<enum>::ALL.into_iter().find(|k| <key> == <name>)`, `<name>` being
    the parameter. So it compares what the reader reads (the declared
    number, which `#[repr(u8)]` keeps to a byte, or the token `fn token`
    gives) with its input as it took it, and gives the entry it finds; a
    search that changes the input, adds a condition or gives another
    value is refused (Codex's review of M3-01, the class of a decoder
    read in part)."""
    where, f = one_fn(src, fn, impl=enum)
    name = param.split(":")[0].strip()
    if f.params != [param] or not re.fullmatch(r"->\s*Option\s*<\s*(?:%s|Self)\s*>" % enum, f.ret):
        raise SourceError("%s: %s is not `fn %s(%s) -> Option<%s>`, the decoder the reader reads" % (src.rel, where, fn, param, enum))
    body = collapse(src.code[f.body[0] + 1:f.body[1] - 1])
    want = ["%s::ALL.into_iter().find(|k| %s == %s)" % (e, key, name) for e in (enum, "Self")]
    if body not in want:
        raise SourceError("%s: %s is `%s`, not `%s`: the reader reads a decoder that searches `ALL` for its input as it took it, and nothing else" % (src.rel, where, body[:80], want[0]))


def code_audit_kinds(root):
    src = Source(AUDIT_RS, read(root, AUDIT_RS))
    numbers = dict(numbered_variants(src, "AuditKind"))
    tokens = enum_arms(src, "AuditKind", "token", TOKEN_VALUE)
    check_all_list(src, "AuditKind", list(numbers))
    check_all_search(src, "AuditKind", "from_u8", "v: u8", "*k as u8")
    return {tokens[v]: n for v, n in numbers.items()}


def code_error_kinds(root):
    src = Source(PROTO_RS, read(root, PROTO_RS))
    codes = enum_arms(src, "ErrorKind", "code", CODE_VALUE, int_value)
    tokens = enum_arms(src, "ErrorKind", "token", TOKEN_VALUE)
    check_all_list(src, "ErrorKind", [v for v, _ in enum_variants(src, "ErrorKind")])
    check_all_search(src, "ErrorKind", "from_token", "token: &str", "k.token()")
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
    """The client methods: every method name without the `app.` prefix."""
    return {k: v for k, v in methods_once(root).items() if not k.startswith("app.")}


def code_app_methods(root):
    """The app-role methods: every method name with the `app.` prefix,
    which may be none (before M3's first app method lands)."""
    return {k: v for k, v in methods_once(root).items() if k.startswith("app.")}


_methods = {}


def methods_once(root):
    """`all_methods(root)`, read once for both method tables; a source
    error is raised again for each."""
    if root not in _methods:
        try:
            _methods[root] = all_methods(root)
        except SourceError as e:
            _methods[root] = e
    if isinstance(_methods[root], SourceError):
        raise _methods[root]
    return _methods[root]


def code_unlocker_kinds(root):
    """The unlocker kinds: `UnlockerKind`'s variants in envelope.rs, each
    with its explicit number, which `UnlockerKind::from_byte` reads back
    under that number alone."""
    src = Source(ENVELOPE_RS, read(root, ENVELOPE_RS))
    numbers = dict(numbered_variants(src, "UnlockerKind"))
    where, decoded = some_arms(src, "UnlockerKind", "from_byte", impl="UnlockerKind")
    check_inverse(src, "UnlockerKind", where, numbers, decoded)
    return {snake(v): n for v, n in numbers.items()}


def all_methods(root):
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


POLICIES_RS = "crates/envcloak-core/src/vault/policies.rs"
COVERAGE_RS = "crates/envcloak-agents/src/coverage.rs"
# The enums whose `fn name` arms are the coverage tokens (M2-09): every
# token `agents status` prints, in its report and in `--json`.
COVERAGE_ENUMS = ("Surface", "State", "Reason", "Outcome", "Availability", "Sentinel", "Case",
                  "ProbeStatus", "Identity")


def code_coverage(root):
    """The coverage tokens: every `fn name` arm of the coverage module's
    surface, state, reason, outcome, availability, sentinel, case, probe
    status and identity enums, each enum read whole (a variant without an arm the
    reader can read is an error). A token two enums give
    (`needs_host_approval`, a reason and an availability; `not_probed`, a
    reason and a probe status) is one entry: the coverage tokens are one
    namespace."""
    src = Source(COVERAGE_RS, read(root, COVERAGE_RS))
    out = {}
    for enum in COVERAGE_ENUMS:
        for token in enum_arms(src, enum, "name", TOKEN_VALUE).values():
            out[token] = COVERAGE_RS
    return out


def code_policy_kinds(root):
    """The policy record kinds: `PolicyKind`'s variants in the vault's
    policies module, each with its explicit number, which
    `PolicyRecord::decode` reads back exactly: each arm's kind is the
    number of the `PolicyKind` that `PolicyRecord::kind` gives the record
    the arm makes. Both are read whole (see `match_arms`): `kind` is
    `match self { .. }` alone, and `decode` reads the kind and then the
    version as the record's first two bytes, matches on `(kind, version)`
    as read, makes each record from its own decoder, refuses any other
    pair as corrupt (`_ => return Err(corrupt())`, never a record) and
    gives the record its `match` made (DECODE_BEFORE, DECODE_AFTER)."""
    src = Source(POLICIES_RS, read(root, POLICIES_RS))
    numbers = dict(numbered_variants(src, "PolicyKind"))
    where_kind, kind_arms = match_arms(src, "kind", impl="PolicyRecord", scrutinee="self")
    record_kind = {}
    for pat, val in kind_arms:
        v = re.fullmatch(r"(?:PolicyKind|Self)\s*::\s*([A-Z][A-Za-z0-9]*)", val)
        records = [re.fullmatch(r"(?:PolicyRecord|Self)\s*::\s*([A-Z][A-Za-z0-9]*)\s*\(\s*_\s*\)", p.strip())
                   for p in pat.split("|")]
        if not v or not all(records):
            raise SourceError("%s: %s has an arm the reader cannot read (`%s => %s`): it reads `PolicyRecord::<Record>(_) => PolicyKind::<Kind>`" % (src.rel, where_kind, pat[:60], val[:60]))
        for r in records:
            if r.group(1) in record_kind:
                raise SourceError("%s: %s names `PolicyRecord::%s` twice" % (src.rel, where_kind, r.group(1)))
            record_kind[r.group(1)] = v.group(1)
    where, f = one_fn(src, "decode", impl="PolicyRecord")
    if f.params != ["b: &[u8]"]:
        raise SourceError("%s: %s does not take `b: &[u8]`, the record's bytes the reader reads it from" % (src.rel, where))
    where, arms = match_arms(src, "decode", impl="PolicyRecord", scrutinee="(kind, version)", before=DECODE_BEFORE, after=DECODE_AFTER)
    pattern = re.compile(r"\(\s*(%s)\s*,\s*(%s)\s*\)" % (INT_PATTERN, INT_PATTERN))
    value = re.compile(r"(?:PolicyRecord|Self)\s*::\s*([A-Z][A-Za-z0-9]*)\s*\(\s*[A-Z][A-Za-z0-9]*\s*::\s*decode(?:_v[0-9]+)?\s*\(\s*&\s*mut\s+d\s*\)\s*\?\s*\)")
    if arms[-1] != ("_", "return Err(corrupt())"):
        raise SourceError("%s: %s does not end with `_ => return Err(corrupt())`: a pair it does not know is refused as corrupt, never read as a record" % (src.rel, where))
    decoded, versions = [], set()
    for pat, val in arms[:-1]:
        p, v = pattern.fullmatch(pat), value.fullmatch(val)
        if not p or not v:
            raise SourceError("%s: %s has an arm the reader cannot read (`%s => %s`): it reads `(<kind>, <version>) => PolicyRecord::<Record>(<Type>::decode(&mut d)?)`" % (src.rel, where, pat[:60], val[:60]))
        n, version = int_value(p.group(1)), int_value(p.group(2))
        if (n, version) in versions:
            raise SourceError("%s: %s reads kind %d version %d twice" % (src.rel, where, n, version))
        versions.add((n, version))
        if v.group(1) not in record_kind:
            raise SourceError("%s: %s makes `PolicyRecord::%s`, which %s does not name" % (src.rel, where, v.group(1), where_kind))
        decoded.append((n, record_kind[v.group(1)]))
    # A kind may have several versions; each must read back as one kind.
    once = []
    for n, k in decoded:
        if (n, k) not in once:
            once.append((n, k))
    check_inverse(src, "PolicyKind", where, numbers, once)
    return {snake(v): n for v, n in numbers.items()}


# What `PolicyRecord::decode` holds around its `match`, white space
# collapsed: the kind is the record's first byte and the version its
# second, each read once from the record's own bytes before the `match`,
# and what it gives is the record the `match` made, once the bytes are
# used up and the record keeps its kind's bounds.
DECODE_BEFORE = "let mut d = Dec::new(b); let kind = d.u8()?; let version = d.u8()?; let record ="
DECODE_AFTER = "; d.end()?; if !record.in_bounds() { return Err(corrupt()); } Ok(record)"

STATE_RS = "crates/envcloak-core/src/vault/state.rs"


def tags(enum):
    def reader(root):
        src = Source(AAD_RS, read(root, AAD_RS))
        return {snake(v): n for v, n in numbered_variants(src, enum)}

    return reader


def code_item_classes(root):
    """The item classes: `ItemClass`'s variants in aad.rs, which
    `item_class_from` (vault/state.rs) reads back from `items.class`
    each under its own number."""
    src = Source(AAD_RS, read(root, AAD_RS))
    numbers = dict(numbered_variants(src, "ItemClass"))
    state = Source(STATE_RS, read(root, STATE_RS))
    where, decoded = some_arms(state, "ItemClass", "item_class_from", guards=schema_guards(root, state, "item_class_from"))
    check_inverse(state, "ItemClass", where, numbers, decoded)
    return {snake(v): n for v, n in numbers.items()}


STR_TYPE = r"(?:&\s*(?:'static\s+)?str|ExitToken)"
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
# `const NAME: <type> =` and `static [mut] NAME: <type> =`: a value read by
# its name.
VALUE_DEF = re.compile(r"\b(const|static)\s+(mut\s+)?(%s)\s*:\s*([^=;{}]+?)\s*=" % IDENT)
CONST_REF = re.compile(r"^(?:::\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Z][A-Z0-9_]*)$")
# `envcloak: <token>:`, with any white space after the colon (a tab, two
# spaces), which prints the token as plainly.
PRINTED_TOKEN = re.compile(r"envcloak:\s+([a-z][a-z0-9_]*):")
# A printed token, or the colon after `envcloak`, in pieces: a token's
# start right before a placeholder (`envcloak: pty_{}:`), or a placeholder
# right after the name (`envcloak{}`), whose value could hold `: <token>:`.
PIECES = re.compile(r"envcloak:\s*[a-z0-9_]+\{(?!\{)|envcloak\{(?!\{)")
# `X as Y` in a `use` item (in a group too): Y names X. Any identifier,
# whatever its case (Codex review of M2-RES1: `use Failure as failure`).
ALIAS_USE = re.compile(r"\b(%s)\s+as\s+(%s)\b" % (IDENT, IDENT))
# `type Y = <type>;`, generic or not: Y names the type.
TYPE_ALIAS = re.compile(r"\btype\s+(%s)\s*(?:<[^<>=;{}]*>)?\s*=([^;{}]*);" % IDENT)
FN_NAME = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
# Another value's `.token()`: read from the `fn token` bodies.
TOKEN_CHAIN = re.compile(r"(?:::\s*)?(?:%s\s*::\s*)*%s(?:\s*\.\s*%s)*\s*\.\s*token\s*\(\s*\)" % (IDENT, IDENT, IDENT))
# A `Failure`'s own field, read where it is set (fail.rs only).
FIELD_TOKEN = re.compile(r"%s\s*\.\s*token" % IDENT)
MACRO = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*!\s*[\(\[\{]")
# A macro's metavariable, `$crate` aside (a path to the macro's own crate).
METAVARIABLE = re.compile(r"\$(?!crate\b)[A-Za-z_]")
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

    def __init__(self, src, name, start, params, ret, body, public, params_span=None):
        self.src = src
        self.name = name
        self.start = start
        self.params = params
        self.params_span = params_span
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
        out.append(Fn(src, m.group(1), m.start(), params, ret, body, public, (k + 1, close)))
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
    fail.rs). `forwards` collects where `token` was taken so, `fields`
    where a `Failure`'s field was read whole, and `refs` the constants
    named. `bad` holds the names of constants and statics whose value the
    reader cannot read, each with why."""

    def __init__(self, consts, forward=False, field=False, bad=None):
        self.consts = consts
        self.forward = forward
        self.field = field
        self.bad = bad or {}
        self.forwards = []
        self.fields = []
        self.refs = []


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
        r.fields.append(b - 5)
        return []
    m = CONST_REF.match(text)
    if m:
        r.refs.append(m.group(1))
        if m.group(1) in r.bad:
            raise Unreadable("a failure token names `%s`, %s" % (text[:60], r.bad[m.group(1)]))
        if m.group(1) not in r.consts:
            raise Unreadable("a failure token names `%s`, which is no `&str` constant the reader knows" % text[:60])
        return sorted(r.consts[m.group(1)])
    if src.env_var(a) in CARGO_NAMES and re.fullmatch(r"(?:(?:::\s*)?(?:std|core)\s*::\s*)?env\s*!\s*\(\s*\"\s*\"\s*,?\s*\)", text):
        # Cargo's name for the package, the crate or the binary: taken as
        # the program's (over-counted), so a line that prints it before
        # `: <token>:` is read (the class of the verifier's review of
        # M2-RES1: a line made of pieces the source names).
        return ["envcloak"]
    if a in src.concats:
        joined = src.concat_values.get(a)
        if src.concats[a][1] != b or joined is None:
            raise Unreadable("a failure token in `concat!` of something other than literals (`%s`)" % text[:60])
        return [joined]
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


def use_aliases(src):
    """(original, alias) for every `X as Y` in a `use` item of `src`."""
    out = []
    for u in USE_STMT.finditer(src.skel):
        out += [(m.group(1), m.group(2)) for m in ALIAS_USE.finditer(u.group(0))]
    return out


def type_aliases(src):
    """(alias, right-hand side, offset) for every `type` alias of `src`."""
    return [(m.group(1), m.group(2), m.start()) for m in TYPE_ALIAS.finditer(src.skel)]


def plain_type(rhs):
    """The last segment of a type written as a path (in parentheses, or
    with generic arguments), or None for any other type."""
    t = " ".join(rhs.split())
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    t = re.sub(r"\s*<.*>$", "", t)
    m = re.fullmatch(r"(?:::\s*)?(?:%s\s*::\s*)*(%s)" % (IDENT, IDENT), t)
    return m.group(1) if m else None


def grow(names, pairs):
    """`names` and every alias of one of them, aliases of aliases too."""
    names = set(names)
    grew = True
    while grew:
        grew = False
        for orig, alias in pairs:
            if orig in names and alias not in names:
                names.add(alias)
                grew = True
    return names


def static_str_types(sources):
    """`ExitToken` and every alias of `&'static str` or of one of them,
    made with `type` or `use ... as`."""
    names = {"ExitToken"}
    pairs = []
    for src in sources:
        pairs += use_aliases(src)
        for alias, rhs, _ in type_aliases(src):
            if re.fullmatch(r"\s*&\s*'static\s+str\s*", rhs):
                names.add(alias)
            elif plain_type(rhs):
                pairs.append((plain_type(rhs), alias))
    return grow(names, pairs)


def is_static_str(ty, statics):
    ty = " ".join(ty.split())
    if re.fullmatch(r"&\s*'static\s+str", ty):
        return True
    last = re.fullmatch(r"(?:%s::)*(%s)" % (IDENT, IDENT), ty)
    return bool(last and last.group(1) in statics)


def failure_names(sources):
    """`Failure` and every name it is imported or defined as (`use ... as`
    and `type`, generic or not, whatever the name's case), aliases of
    aliases included. A type alias that names `Failure` in another form
    (a qualified path, a reference) is refused: its uses could not be
    read."""
    pairs = []
    for src in sources:
        pairs += use_aliases(src)
        pairs += [(plain_type(rhs), alias) for alias, rhs, _ in type_aliases(src) if plain_type(rhs)]
    names = grow({"Failure"}, pairs)
    word = re.compile(r"\b(?:%s)\b" % "|".join(map(re.escape, sorted(names))))
    for src in sources:
        # A name a macro gives (`use $p as Q;`, `type $n = ..;`, `type Q =
        # $t;`) or a type a macro makes (`type Q = m!();`) could be
        # `Failure` under a name the reader never sees (verifier review of
        # M2-RES1, the class of the aliases it read only when written out).
        for u in USE_STMT.finditer(src.skel):
            if METAVARIABLE.search(u.group(0)):
                raise SourceError("%s line %d: an import built from a macro's metavariable could name `Failure` under a name the reader does not see; write the import out" % (src.rel, src.skel.count("\n", 0, u.start()) + 1))
        for m in re.finditer(r"\btype\s+\$", src.skel):
            raise SourceError("%s line %d: a type alias named by a macro's metavariable could name `Failure` under a name the reader does not see; write the alias out" % (src.rel, src.skel.count("\n", 0, m.start()) + 1))
        for alias, rhs, at in type_aliases(src):
            if METAVARIABLE.search(rhs) or re.search(r"%s\s*!" % IDENT, rhs):
                raise SourceError("%s line %d: the type alias `%s` is of a type a macro gives (`%s`), which could be `Failure`; write the type out" % (src.rel, src.skel.count("\n", 0, at) + 1, alias, " ".join(rhs.split())[:60]))
        for alias, rhs, at in type_aliases(src):
            if plain_type(rhs) is None and word.search(rhs):
                raise SourceError("%s line %d: the type alias `%s` names `Failure` in a form the reader cannot read (`%s`); write `type %s = Failure;`" % (src.rel, src.skel.count("\n", 0, at) + 1, alias, " ".join(rhs.split())[:60], alias))
    return names


def impl_blocks(src):
    """Every `impl` block of `src`, as (body span, the last segment of the
    type it is for, or None when that is no path, whether it implements a
    trait). The type is read as `plain_type` reads one: with or without a
    leading `::`, in parentheses, with generic arguments (verifier review
    of M2-RES1: `impl Tr for ::envcloak_client::Failure` was not taken for
    `Failure`'s)."""
    out = []
    for m in re.finditer(r"\bimpl\b", src.skel):
        k = m.end()
        while k < len(src.skel) and src.skel[k].isspace():
            k += 1
        if src.skel.startswith("<", k):
            k = generic_end(src.skel, k)
            if k is None:
                continue
        open_at = BODY_OR_END.search(src.skel, k)
        if not open_at or open_at.group(0) != "{":
            continue
        head = " ".join(src.skel[k:open_at.start()].split())
        head = re.sub(r"\s+where\b.*$", "", head)
        trait = find_top_text(head, " for ")
        target = head[trait + 5:] if trait is not None else head
        target = re.sub(r"^!\s*", "", target.strip())
        out.append(((open_at.start(), src.block_end(open_at.start())), plain_type(target), trait is not None))
    return out


def find_top_text(text, what):
    """The first offset of `what` in `text` outside brackets of any kind,
    angle brackets included, or None."""
    depth = 0
    for k, ch in enumerate(text):
        if depth == 0 and text.startswith(what, k):
            return k
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}" and not (ch == ">" and k > 0 and text[k - 1] in "-="):
            depth -= 1
    return None


def impl_spans(src, names, traits=True):
    """The bodies of `impl` blocks whose `Self` is one of `names` (trait
    implementations too, unless `traits` is false)."""
    return [span for span, last, trait in impl_blocks(src) if last in names and (traits or not trait)]


def trait_spans(src):
    """The bodies of every `trait` block and every implementation of a
    trait in `src`: where a function can be called without its name."""
    spans = [span for span, _, trait in impl_blocks(src) if trait]
    for m in re.finditer(r"\btrait\s+%s\b" % IDENT, src.skel):
        open_at = BODY_OR_END.search(src.skel, m.end())
        if open_at and open_at.group(0) == "{":
            spans.append((open_at.start(), src.block_end(open_at.start())))
    return spans


# Keywords that can stand right before an expression, so before the `<` of
# a qualified path (`return <F>::new(..)`), never a type with generic
# arguments.
KEYWORDS = {
    "as", "async", "await", "box", "break", "const", "continue", "crate", "do", "dyn", "else",
    "enum", "extern", "false", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "match",
    "mod", "move", "mut", "pub", "ref", "return", "static", "struct", "trait", "true", "try",
    "type", "unsafe", "use", "where", "while", "yield",
}


def angle_open(skel, j):
    """The offset of the `<` that opens the `>` at `j`, counted back past
    nested ones (an `->` or `=>` is no bracket, and whatever is inside
    other brackets, `[u8; 16]` or `{ N }`, is passed over whole), or None
    if the brackets do not match before a `;` or the start."""
    depth, inner = 0, 0
    for k in range(j, -1, -1):
        ch = skel[k]
        if ch in ")]}":
            inner += 1
        elif ch in "([{":
            inner -= 1
            if inner < 0:
                return None
        elif inner:
            continue
        elif ch == ">" and not (k > 0 and skel[k - 1] in "-="):
            depth += 1
        elif ch == "<":
            depth -= 1
            if depth == 0:
                return k
        elif ch == ";":
            return None
    return None


def segment_before(skel, at):
    """What names the type whose item is named just after the `::` at
    `at`, read back from it, whatever comes before (verifier review of
    M2-RES1: a constructor written `::envcloak_client::fail::Failure::new`
    or `<Self>::new` was matched by no forward pattern, so neither read
    nor refused). Returns ("name", segment) for a path's last segment,
    after a turbofish (`F::<'a>::new`) or a qualified path (`<F>::new`,
    `<::a::F<'a>>::new`, `<(F)>::new`); ("as", segment) for `<T as
    Trait>::new`, the segment T's; ("meta", text) for a macro's
    metavariable (`$t::new`, `<$t>::new`), which could be any type; and
    ("unknown", text) for anything else (`<_>::new`, a type a macro
    makes)."""
    j = at - 1
    while j >= 0 and skel[j].isspace():
        j -= 1
    if j < 0:
        return ("unknown", "")
    if skel[j] == ">":
        o = angle_open(skel, j)
        if o is None:
            return ("unknown", " ".join(skel[max(0, j - 40):at].split()))
        k = o - 1
        while k >= 0 and skel[k].isspace():
            k -= 1
        if k >= 1 and skel[k - 1:k + 1] == "::":
            return segment_before(skel, k - 1)
        w = re.search(r"(\$?)(%s)$" % IDENT, skel[:k + 1]) if k >= 0 else None
        if w and w.group(2) not in KEYWORDS:
            return ("meta", w.group(0)) if w.group(1) else ("name", w.group(2))
        inner = " ".join(skel[o + 1:j].split())
        if "$" in inner:
            return ("meta", "<%s>" % inner)
        if "!" in inner:
            return ("unknown", "<%s>" % inner)
        cut = find_top_text(inner, " as ")
        if cut is not None:
            last = plain_type(inner[:cut])
            return ("as", last) if last else ("unknown", "<%s>" % inner)
        last = plain_type(inner)
        return ("name", last) if last else ("unknown", "<%s>" % inner)
    w = re.search(r"(\$?)(%s)$" % IDENT, skel[:j + 1])
    if w:
        return ("meta", w.group(0)) if w.group(1) else ("name", w.group(2))
    return ("unknown", " ".join(skel[max(0, j - 40):at].split()))


# What may be written on `Failure`: attributes and derives that give it no
# other way to be made (a derived `Default` or `Deserialize` would make a
# failure, and its token, where the reader does not look).
FAILURE_ATTRIBUTES = {"derive", "doc", "must_use", "allow", "expect", "warn", "deny", "forbid"}
FAILURE_DERIVES = {"Debug", "Clone", "Copy", "PartialEq", "Eq", "PartialOrd", "Ord", "Hash"}


def item_attributes(src, at):
    """(offset, text inside the brackets) of every outer attribute written
    before the item whose keyword is at `at` (after any visibility)."""
    m = re.search(r"(?:\bpub\b(?:\s*\([^)]*\))?\s*)?$", src.skel[:at])
    k = m.start()
    out = []
    while True:
        j = k - 1
        while j >= 0 and src.skel[j].isspace():
            j -= 1
        if j < 0 or src.skel[j] != "]":
            return out
        o = src.open_of(j)
        h = -1 if o is None else o - 1
        while h >= 0 and src.skel[h].isspace():
            h -= 1
        if h < 0 or src.skel[h] != "#":
            return out
        out.append((h, src.skel[o + 1:j]))
        k = h


def split_fields(src, a, b):
    """The fields (or variants) in [a, b), as `split_top` gives them, but
    with a comma inside a type's generic arguments (`Cow<'static, str>`)
    kept in its field."""
    out = []
    for x, y, text in src.split_top(a, b):
        if out and angle_depth(out[-1][2]) > 0:
            px, _, pt = out.pop()
            out.append((px, y, pt + "," + text))
        else:
            out.append((x, y, text))
    return out


def angle_depth(text):
    """`<` less `>` in a type's text, an `->` left out."""
    return text.count("<") - len(re.findall(r"(?<!-)>", text))


def check_failure_struct(sources, names, statics):
    """`Failure` is defined once, in fail.rs, with named fields, one of
    them a private `token` of a static string type, and no attribute or
    derive that would make one another way. Elsewhere no struct literal,
    field assignment or borrow of the token compiles, and fail.rs has no
    module in another file (a child module could reach the field). Returns
    where the field is declared; what fail.rs may do with the field is
    checked once its uses are read (`check_fail_rs_tokens`)."""
    defs = []
    for src in sources:
        for m in re.finditer(r"\bstruct\s+(%s)\b" % "|".join(map(re.escape, sorted(names))), src.skel):
            defs.append((src, m))
    if len(defs) != 1 or defs[0][0].rel != FAIL_RS:
        raise SourceError("`Failure` must be defined once, in %s (found in %s)" % (FAIL_RS, ", ".join(s.rel for s, _ in defs) or "no file"))
    src, m = defs[0]

    def where(at):
        return "%s line %d" % (FAIL_RS, src.skel.count("\n", 0, at) + 1)

    for at, text in item_attributes(src, m.start()):
        name = re.match(r"\s*(%s)\s*(.*)$" % IDENT, text, re.S)
        if not name or name.group(1) not in FAILURE_ATTRIBUTES:
            raise SourceError("%s: `Failure` carries `#[%s]`, which could make a failure, and its token, where the reader does not look" % (where(at), " ".join(text.split())[:60]))
        if name.group(1) == "derive":
            inner = name.group(2).strip()
            listed = [" ".join(d.split()) for d in inner[1:-1].split(",")] if inner.startswith("(") and inner.endswith(")") else [inner]
            for d in listed:
                last = plain_type(d) if d else None
                if d and last not in FAILURE_DERIVES:
                    raise SourceError("%s: `Failure` derives `%s`, which could make a failure, and its token, where the reader does not look; it may derive %s" % (where(at), d[:40], ", ".join(sorted(FAILURE_DERIVES))))
    body = BODY_OR_END.search(src.skel, m.end())
    head = src.skel[m.end():body.start() if body else len(src.skel)]
    if not body or body.group(0) != "{" or "(" in head:
        raise SourceError("%s: `Failure` is not a struct with named fields, `token` among them" % where(m.start()))
    open_at = body.start()
    tokens = []
    for x, y, text in split_fields(src, open_at + 1, src.block_end(open_at) - 1):
        f = re.match(r"\s*((?:pub\b(?:\s*\([^)]*\))?)?)\s*(%s)\s*:(.*)$" % IDENT, text, re.S)
        if not f:
            raise SourceError("%s: a field of `Failure` the reader cannot read (`%s`)" % (where(x), " ".join(text.split())[:60]))
        if f.group(2) != "token":
            continue
        if f.group(1):
            raise SourceError("%s: `Failure`'s `token` field is public: a failure's token could then be set where the reader does not look; keep it private" % FAIL_RS)
        if not is_static_str(f.group(3), statics):
            raise SourceError("%s: `Failure`'s `token` field is not a static string (`%s`)" % (where(x), " ".join(f.group(3).split())[:40]))
        tokens.append(x + text.index("token", len(f.group(1))))
    if len(tokens) != 1:
        raise SourceError("%s: `Failure` has %d `token` fields, not one" % (where(m.start()), len(tokens)))
    for k in re.finditer(r"\bmod\s+%s\s*;" % IDENT, src.skel):
        raise SourceError("%s: fail.rs declares a module in another file, which could reach `Failure`'s private `token` where the reader does not look" % where(k.start()))
    for k in re.finditer(r"\.\s*token\s*(?:=(?!=)|[-+*/|&^]=)|&\s*mut\s+[\w.]*\btoken\b", src.skel):
        raise SourceError("%s: `Failure`'s token is changed after it is made; a token is given only when the failure is made" % where(k.start()))
    return tokens[0]


def check_fail_rs_tokens(src, allowed, exempt):
    """Every mention of `token` in fail.rs is one the reader has read or
    knows to change nothing: the field's declaration, a `Failure`
    literal's field, a field read whole as a token (`self.token` where a
    failure is made or its token printed or returned), `Failure::new`'s
    own parameter and where it hands it on, `fn token` and a `.token()`
    call. Any other (a pattern that binds the field, `ref mut`, an
    assignment through a parenthesized place, `clone_from`, a macro, a
    local of that name) is refused (verifier review of M2-RES1: a
    destructuring `let Failure { token, .. } = &mut f` changed the token
    unseen)."""
    allowed = set(allowed)
    for f in exempt:
        a, b = f.params_span
        allowed |= {a + m.start() for m in re.finditer(r"\btoken\b(?=\s*:(?!:))", src.skel[a:b])}
    for m in re.finditer(r"\btoken\b", src.skel):
        at = m.start()
        if at in allowed:
            continue
        before = src.skel[:at].rstrip()
        after = src.skel[at + 5:at + 40].lstrip()
        if before.endswith(".") and after.startswith("("):
            continue
        if re.search(r"\bfn$", before) and after[:1] in ("(", "<"):
            continue
        raise SourceError("%s line %d: `Failure`'s `token` is named where the reader cannot tell it is not changed (`%s`): in fail.rs a token is only given where a failure is made, and read whole" % (FAIL_RS, src.skel.count("\n", 0, at) + 1, " ".join(src.skel[max(0, at - 20):at + 25].split())))


# A lint override that lets a local, a parameter or a pattern be named in
# capitals, as a constant is (`let PTY = ...`). CI denies warnings, so
# without one such a name never lands, and a name in capitals that the
# reader reads as a constant's is one.
LINT_OVERRIDE = re.compile(r"\b(?:allow|expect|warn)\s*\([^)]*\b(non_snake_case|nonstandard_style|warnings)\b")
# A `fn`, `const` or `static` named by a macro's metavariable: it could be
# a `fn token`, or a constant named as a token, the reader does not see.
MACRO_FN = re.compile(r"\b(?:fn|const|static)\s+(?:mut\s+)?\$")


def read_consts(sources, statics):
    """The values of every `&str` constant and static by name ({name: set
    of values}), and the names whose value the reader cannot read, with
    why ({name: why}): a mutable static, or one whose initializer is not a
    value the reader reads (a literal, another constant, `concat!` of
    literals, or a conditional or block of those). An initializer is read
    whole, never by its leading literal (Codex review of M2-RES1: `const
    T: &str = "approval_required".split_at(9).1;` was read as
    `approval_required`). A name defined more than once has every
    definition's values, and none if one of them cannot be read."""
    defs = []
    bad = {}
    for src in sources:
        for m in VALUE_DEF.finditer(src.skel):
            typ = " ".join(m.group(4).split())
            if not (is_static_str(typ, statics) or re.fullmatch(r"&\s*(?:'static\s+)?str", typ)):
                continue
            name = m.group(3)
            semi = find_top(src, m.end(), len(src.skel), ";")
            if m.group(2) or semi is None:
                bad[name] = "a mutable static, whose value the reader cannot know" if m.group(2) else "whose value the reader cannot find"
                continue
            defs.append((src, name, m.end(), semi))
    consts = {}
    pending = defs
    while pending:
        waiting = {d[1] for d in pending}
        rest, why = [], {}
        for d in pending:
            src, name, a, b = d
            r = Reading(consts, bad=bad)
            try:
                values = values_of(src, a, b, r)
            except Unreadable as e:
                rest.append(d)
                why[name] = "%s line %d: %s" % (src.rel, src.skel.count("\n", 0, a) + 1, e)
                continue
            if any(n in waiting for n in r.refs):
                rest.append(d)
                why[name] = "%s line %d: it names a constant the reader cannot read first" % (src.rel, src.skel.count("\n", 0, a) + 1)
                continue
            consts.setdefault(name, set()).update(values)
        if len(rest) == len(pending):
            for _, name, _, _ in rest:
                bad[name] = "whose value the reader cannot read (%s)" % why[name]
            break
        pending = rest
    for name in bad:
        consts.pop(name, None)
    return consts, bad


# Workspace members outside `crates/`: the canaries, which no crate may
# depend on (scripts/check-unsafe.sh) and which are empty in every build
# but their own check's.
CANARIES = ("security/lint-canary", "security/unsafe-canary")


def toml_lines(root, rel):
    """The manifest at `rel` as (line number, text) with each comment (a
    `#` outside a string, to the end of its line) left out. Read as text,
    not parsed: what the checks below need is a key or two, and a form
    they cannot read is refused (a multi-line string is one)."""
    out = []
    for n, line in enumerate(read(root, rel).split("\n"), 1):
        if '"""' in line or "'''" in line:
            raise SourceError("%s line %d: a multi-line string, which the reader of manifests does not read" % (rel, n))
        k, quote = 0, None
        while k < len(line):
            ch = line[k]
            if quote:
                if ch == "\\" and quote == '"':
                    k += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "#":
                line = line[:k]
                break
            k += 1
        out.append((n, line))
    return out


# A `path` key, bare or quoted, alone, dotted (`zz.path`) or in an inline
# table (`{ path = .. }`), and its value.
TOML_PATH = re.compile(r"""(?:^|(?<=[\s{,.]))(?:path|"path"|'path')\s*=\s*""")
TOML_STRING = re.compile(r"""\s*(?:"([^"\\]*)"|'([^']*)')""")
TOML_HEADER = re.compile(r"\s*\[\[?\s*([^\]]*?)\s*\]\]?\s*$")


def inside(path, top):
    """Whether `path` is `top` or under it, both made absolute and normal."""
    path, top = os.path.normpath(os.path.abspath(path)), os.path.normpath(os.path.abspath(top))
    return path == top or path.startswith(top + os.sep)


def check_manifest_paths(root, rel, src_dir=None):
    """Every `path` the manifest at `rel` gives, in any table, inline
    table or dotted key: a dependency's (or, in the root manifest, any)
    is under `crates/`, and so is a test, bench or example target's; any
    other in a crate's manifest (its `[lib]`, a `[[bin]]`) is a file under
    the crate's `src/` (`src_dir`). A `path` whose value is not one plain
    string is refused."""
    here = os.path.dirname(os.path.join(root, rel))
    header = ""
    for n, line in toml_lines(root, rel):
        h = TOML_HEADER.match(line)
        if h:
            header = re.sub(r"[\s\"']", "", h.group(1))
            continue
        # A key spelled with an escape (`"pa\u0074h" = ..`) is `path` to
        # Cargo and not to a reader of text: refused.
        if re.search(r"\"[^\"]*\\[^\"]*\"\s*[.=\]]", line):
            raise SourceError("%s line %d: a quoted key with an escape, which the reader of manifests does not read" % (rel, n))
        for m in TOML_PATH.finditer(line):
            v = TOML_STRING.match(line, m.end())
            if not v:
                raise SourceError("%s line %d: a `path` whose value the reader cannot read" % (rel, n))
            value = v.group(1) if v.group(1) is not None else v.group(2)
            where = re.sub(r"[\s\"']", "", header + "." + line[:m.start()])
            dependency = re.search(r"(?:^|[.={\[,])(?:dev-|build-)?dependencies(?:[.={]|$)", where) is not None
            if src_dir is None or dependency or header in ("test", "bench", "example"):
                if not inside(os.path.join(here, value), os.path.join(root, CRATES)):
                    raise SourceError("%s line %d: a path outside crates/ (`%s`), whose sources the reader does not read" % (rel, n, value))
            elif not inside(os.path.join(here, value), src_dir):
                raise SourceError("%s line %d: a target's file outside the crate's src/ (`%s`), which the reader reads" % (rel, n, value))


def check_workspace(root):
    """The workspace builds from no Rust the reader does not read: its
    members are `crates/*` and the canaries, and every path the root
    manifest gives is under `crates/` (verifier review of M2-RES1: the
    compiler read files the walk never reached)."""
    text = "\n".join(line for _, line in toml_lines(root, "Cargo.toml"))
    for m in re.finditer(r"(?:^|[\s.])members\s*=\s*\[", text):
        close = text.find("]", m.end())
        body = text[m.end():close if close >= 0 else len(text)]
        rest = re.sub(r"""\s*(?:"[^"\\]*"|'[^']*')\s*,?""", "", body)
        if close < 0 or rest.strip():
            raise SourceError("Cargo.toml: the workspace's members are not a list of plain strings the reader can read")
        for member in re.findall(r"""["']([^"']*)["']""", body):
            if member != "crates/*" and member not in CANARIES:
                raise SourceError("Cargo.toml: the workspace member `%s` is outside crates/, whose sources the reader reads" % member)
    check_manifest_paths(root, "Cargo.toml")


def check_targets(root, name, rel):
    """The crate at `crates/<name>` builds its library and binaries from
    files under its `src/`, and its path dependencies are crates under
    `crates/`."""
    check_manifest_paths(root, rel, os.path.join(root, CRATES, name, "src"))


def check_compile_time(root, sources):
    """Refuses, in every crate's sources, what would give the reader text
    it cannot see: a compile-time macro whose text it cannot read (see
    `Source.read_macros`), a `#[path]` attribute, a lint override that
    lets a local be named as a constant is, and a `fn`, `const` or
    `static` named by a macro; in the workspace, a member or a path
    dependency outside `crates/` (`check_workspace`); and, in every
    crate, a target whose file is outside `src/` or a path dependency
    outside `crates/` (`check_targets`), a build script that sets an
    environment variable for `env!`, and a manifest that quiets the
    naming lints."""
    for src in sources:
        for at, _, why in src.unreadable:
            raise SourceError("%s line %d: %s" % (src.rel, src.skel.count("\n", 0, at) + 1, why))
        refuse_path_attributes(src)
        for m in LINT_OVERRIDE.finditer(src.skel):
            raise SourceError("%s line %d: `%s` is allowed, so a local could be named as a constant is and read as one; name it in lower case" % (src.rel, src.skel.count("\n", 0, m.start()) + 1, m.group(1)))
        for m in MACRO_FN.finditer(src.skel):
            raise SourceError("%s line %d: a `fn`, `const` or `static` named by a macro's metavariable could be a `fn token`, or a constant named as a token, the reader does not see; write it out" % (src.rel, src.skel.count("\n", 0, m.start()) + 1))
    check_workspace(root)
    root_manifest = re.sub(r"#[^\n]*", "", read(root, "Cargo.toml"))
    for m in re.finditer(r"\b(non_snake_case|nonstandard_style|warnings)\s*=", root_manifest):
        raise SourceError("Cargo.toml sets `%s`, so a local could be named as a constant is and read as one" % m.group(1))
    base = os.path.join(root, CRATES)
    try:
        names = sorted(os.listdir(base))
    except OSError as e:
        raise SourceError("%s could not be listed (%s)" % (CRATES, e.strerror))
    for name in names:
        if not os.path.isdir(os.path.join(base, name, "src")):
            continue
        rel = "%s/%s/Cargo.toml" % (CRATES, name)
        manifest = re.sub(r"#[^\n]*", "", read(root, rel))
        for m in re.finditer(r"\b(non_snake_case|nonstandard_style|warnings)\s*=", manifest):
            raise SourceError("%s sets `%s`, so a local could be named as a constant is and read as one" % (rel, m.group(1)))
        check_targets(root, name, rel)
        m = re.search(r"^\s*build\s*=\s*\"([^\"]+)\"", manifest, re.M)
        script = m.group(1) if m else "build.rs"
        if os.path.exists(os.path.join(base, name, script)):
            text = read(root, "%s/%s/%s" % (CRATES, name, script))
            if "rustc-env" in text:
                raise SourceError("%s/%s/%s sets an environment variable for `env!` (`rustc-env`), whose text the reader cannot see" % (CRATES, name, script))


def code_exit_tokens(root):
    """Tokens the CLI can print for its own failures, with the first file
    each is found in (see the module comment for what is read)."""
    sources = rust_sources(root)
    check_compile_time(root, sources)
    statics = static_str_types(sources)
    names = failure_names(sources)
    declared = check_failure_struct(sources, names, statics)
    consts, bad = read_consts(sources, statics)
    fns = {src.rel: fn_items(src) for src in sources}
    # Token helpers: free functions with a `token: &'static str` (or an
    # alias) parameter, by name, with its positions.
    helpers = {}
    # Where each helper is defined: (file, crate, public). A private one is
    # visible in its crate only (its module's descendants included).
    defs = {}
    exempt = []
    for src in sources:
        # `Failure::new` is the inherent one in fail.rs: a trait's `new`
        # implemented for `Failure` is called through a generic, unnamed.
        inherent = impl_spans(src, names, traits=False) if src.rel == FAIL_RS else []
        traits = trait_spans(src)
        for f in fns[src.rel]:
            if f.body is None:
                continue
            positions = [i for i, p in enumerate(f.params)
                         if TOKEN_PARAM.match(p) and is_static_str(TOKEN_PARAM.match(p).group(1), statics)]
            if not positions:
                continue
            if f.params and RECEIVER.match(f.params[0]):
                continue
            if any(x < f.start < y for x, y in traits):
                # A trait's function is called without its name (`.into()`
                # for a `From`, `?`, a generic `T::new`), so its callers,
                # and the tokens they hand it, could not be read.
                raise SourceError("%s line %d: `fn %s` takes a `token` to hand on inside a trait or a trait's implementation, which code can call without naming it (`.into()`, `?`, a generic), so the tokens handed to it would not be read; make it a free function or an inherent one" % (src.rel, src.skel.count("\n", 0, f.start) + 1, f.name))
            if f.name == "new":
                # `Failure::new` itself, whose callers are read below.
                if any(x < f.start < y for x, y in inherent) and positions == [0]:
                    exempt.append((src, f))
                continue
            helpers.setdefault(f.name, set()).update(positions)
            defs.setdefault(f.name, []).append((src.rel, crate_of(src.rel), f.public))
            exempt.append((src, f))
    found = {}

    def take(values, src, printed=False):
        """Each value that is a token counts. A value printed where a
        token goes counts with the white space around it left out (a value
        can bring its own), and so does the token it starts with,
        `<token>:` (a value can bring its own colon)."""
        for v in values:
            if printed:
                v = v.strip()
                lead = re.match(r"([a-z][a-z0-9_]*):", v)
                if lead:
                    found.setdefault(lead.group(1), src.rel)
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
    field_reads = {}

    def read(src, a, b, field=False, printed=False, quiet=False):
        """Reads the token argument at [a, b) and takes its values; one
        the reader cannot read is refused, or with `quiet` passed over."""
        f = body_of(src, a)
        r = Reading(consts, forward=f is not None, field=field and src.rel == FAIL_RS, bad=bad)
        try:
            take(values_of(src, a, b, r), src, printed)
        except Unreadable as e:
            if quiet:
                return
            raise SourceError("%s: %s" % (where(src, a), e))
        for at in r.forwards:
            forwarded.setdefault(src.rel, set()).add(at)
        for at in r.fields:
            field_reads.setdefault(src.rel, set()).add(at)

    def quiet_values(src, a, b):
        """The values the expression at [a, b) can have, or None when the
        reader cannot read it (nothing is refused or recorded)."""
        try:
            return values_of(src, a, b, Reading(consts, bad=bad))
        except Unreadable:
            return None

    ctx = Context(sources, fns, consts, bad, read, take, quiet_values)
    alias = "|".join(map(re.escape, sorted(names)))
    helper_word = re.compile(r"\b(%s)\b" % "|".join(map(re.escape, sorted(helpers)))) if helpers else None
    literal_of = re.compile(r"(?<![\w:])(?:%s\s*::\s*)*(%s|Self)(?:\s*::\s*<[^<>()]*>)?\s*\{" % (IDENT, alias))
    for src in sources:
        failure_impls = impl_spans(src, names)
        # `Failure::new(..)`: the first argument. Every `::new` is read
        # back to the type it is called on, however the path before it is
        # written (a leading `::`, a qualified path, a turbofish, `Self` in
        # an `impl` of `Failure`), so no spelling of the constructor goes
        # unread; one on a type the reader cannot tell (a macro's
        # metavariable, `<_>`, a type a macro makes) is refused, and so is
        # `Failure::new` named other than called (a function pointer).
        for m in re.finditer(r"::\s*new\b", src.skel):
            kind, seg = segment_before(src.skel, m.start())
            in_impl = any(x < m.start() < y for x, y in failure_impls)
            failure = seg in names or (seg == "Self" and in_impl)
            if kind == "meta":
                raise SourceError("%s: `%s::new` is called on a macro's metavariable, which could be `Failure`, whose token would then not be read; write the type out" % (where(src, m.start()), seg))
            if kind == "unknown":
                raise SourceError("%s: `%s::new` is called on a type the reader cannot read, which could be `Failure`; write the type's path" % (where(src, m.start()), seg))
            if not failure:
                continue
            if kind == "as":
                raise SourceError("%s: `<%s as ..>::new` calls a trait's `new` for `Failure`, whose tokens the reader does not read; call `Failure::new`" % (where(src, m.start()), seg))
            k = m.end()
            rest = src.skel[k:k + 200]
            call = re.match(r"\s*(?:::\s*<[^()]*>\s*)?\(", rest)
            if not call:
                raise SourceError("%s: `%s::new` is used other than called, so its tokens could not be read" % (where(src, m.start()), seg))
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
            if f.name != "token":
                continue
            ret = re.sub(r"^->\s*", "", f.ret)
            ret = re.sub(r"\s*where\b.*$", "", ret).strip()
            # A method: `.token()` calls it, and a `.token()` is taken as a
            # token argument on the strength of these bodies, so each one
            # returns a static string they read (Codex review of M2-RES1: a
            # `token` method lending its receiver's field was passed over,
            # and a `.token()` printing it was taken unread).
            if f.params and RECEIVER.match(f.params[0]) and not is_static_str(ret, statics):
                raise SourceError("%s line %d: a method `token` returns `%s`, not a static string the reader reads: every `.token()` made into a failure or printed as one is read from the `fn token` bodies, so a method of that name returns `&'static str` or `ExitToken`; rename this one" % (src.rel, src.skel.count("\n", 0, f.start) + 1, ret[:40] or "()"))
            if f.body is None:
                continue
            take(src.literals(*f.body), src)
            if is_static_str(ret, statics):
                read(src, f.body[0], f.body[1], field=True)
        # A line printed as `envcloak: <token>:`, from a string literal or a
        # `concat!`: anywhere in it (a slice of it, or a later line, prints
        # it too), the token; from a placeholder where the token goes, the
        # value of its argument; and a usage line, `envcloak: {why}` at the
        # start of a line, the message's.
        for start, lit in src.texts(0, len(src.skel)):
            for m in PRINTED_TOKEN.finditer(lit):
                take([m.group(1)], src)
            for line in expand_format(src, start, lit, ctx):
                for m in PRINTED_TOKEN.finditer(line):
                    take([m.group(1)], src)
            for m in PIECES.finditer(lit):
                raise SourceError("%s line %d: a line printed as `envcloak: <token>:` whose token, or the colon after `envcloak`, comes in pieces (`%s`): print a whole token in one place" % (src.rel, src.skel.count("\n", 0, start) + 1, m.group(0)))
            starts = [0] + [i + 1 for i, ch in enumerate(lit) if ch in "\n\r"]
            # A placeholder after `envcloak:`, with white space or none:
            # padding (`{:>16}`) or the value itself can give the space
            # (verifier review of M2-RES1).
            for m in re.finditer(r"envcloak:\s*\{(?!\{)", lit):
                printed_placeholder(src, start, lit, m.start(), m.start() in starts, ctx)
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
    fail_rs = [src for src in sources if src.rel == FAIL_RS][0]
    allowed = {declared} | field_names.get(FAIL_RS, set()) | forwarded.get(FAIL_RS, set()) | field_reads.get(FAIL_RS, set())
    check_fail_rs_tokens(fail_rs, allowed, [f for s, f in exempt if s is fail_rs])
    if not found:
        raise SourceError("no CLI failure tokens found under crates/*/src")
    return found


def arm_at(src, open_at, pos):
    """The pattern span of the arm of the `match` block opened at
    `open_at` whose value holds `pos`, or None."""
    k, end = open_at + 1, src.close_of(open_at)
    while k < end:
        while k < end and (src.skel[k].isspace() or src.skel[k] == ","):
            k += 1
        arrow = find_top(src, k, end, "=>")
        if arrow is None:
            return None
        v = arrow + 2
        while v < end and src.skel[v].isspace():
            v += 1
        if src.skel.startswith("{", v):
            stop = src.close_of(v) + 1
        else:
            comma = find_top(src, v, end, ",")
            stop = end if comma is None else comma
        if v <= pos < stop:
            return (k, arrow)
        k = stop
    return None


class Context:
    """What the readers of printed lines share: every source, each file's
    `fn` items, the constants (and the names that cannot be read), and
    the functions that read a token argument and take a token."""

    def __init__(self, sources, fns, consts, bad, read, take, values=None):
        self.sources = sources
        self.fns = fns
        self.consts = consts
        self.bad = bad
        self.read = read
        self.take = take
        self.values = values


def implicit_args(text):
    """How many positional arguments the placeholders of the format
    string `text` take without naming one (`{}`, `{:x}`; a precision
    `.*` takes one more)."""
    n = 0
    for m in re.finditer(r"\{\{|\}\}|\{([^{}]*)\}", text):
        if m.group(1) is None:
            continue
        arg, _, spec = m.group(1).partition(":")
        n += (not arg.strip()) + (".*" in spec)
    return n


def format_arguments(src, start):
    """The arguments after the string that starts at `start`, in the
    brackets it is an argument in (a format macro's): (positional spans,
    {name: span} of the named ones); None when it is in no brackets."""
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
    if k < 0 or src.skel[k] not in "([{":
        return None
    args = src.split_top(k + 1, src.close_of(k))
    here = [i for i, (x, y, _) in enumerate(args) if x <= start < y]
    rest = args[here[0] + 1:] if here else []
    positional = [(x, y) for x, y, t in rest if not re.match(r"\s*%s\s*=(?!=)" % IDENT, t)]
    named = {re.match(r"\s*(%s)" % IDENT, t).group(1): (x + t.index("=") + 1, y)
             for x, y, t in rest if re.match(r"\s*%s\s*=(?!=)" % IDENT, t)}
    return positional, named


# Stands for a value the reader cannot read where a line is put together:
# no token or name holds it.
UNREAD = "\x00"
# The most lines one format string is read as, its readable arguments'
# values put in every way.
MAX_LINES = 256


def expand_format(src, start, lit, ctx):
    """The lines the format string `lit` (at `start`) prints with the
    values of its arguments the reader can read put in its placeholders
    (a literal, a constant, `concat!`, a conditional of those; a constant
    captured by name, `{NAME}`), every other one as `UNREAD`; [] when `lit`
    has no placeholder, is no macro's argument, or neither it nor a value
    holds `envcloak`. So a line whose `envcloak:`, or whose token, is a
    format argument the source holds (`"{}: {}: x", "envcloak", "tok"`)
    is read as printed (the class of the verifier's review of M2-RES1:
    a line made of pieces the reader could see)."""
    marks = list(re.finditer(r"\{\{|\}\}|\{([^{}]*)\}", lit))
    if not any(m.group(1) is not None for m in marks):
        return []
    found = format_arguments(src, start)
    if found is None:
        return []
    positional, named = found
    pieces, last, implicit = [], 0, 0
    for m in marks:
        pieces.append([lit[last:m.start()]])
        last = m.end()
        if m.group(1) is None:
            pieces.append([m.group(0)[0]])
            continue
        name, _, spec = m.group(1).partition(":")
        name = name.strip()
        values = None
        # A precision `.*` takes an argument of its own before the value.
        implicit += ".*" in spec
        if name == "" or name.isdigit():
            i = int(name) if name else implicit
            implicit += name == ""
            if i < len(positional):
                values = ctx.values(src, *positional[i])
        elif name in named:
            values = ctx.values(src, *named[name])
        elif name in ctx.consts and name not in ctx.bad:
            values = sorted(ctx.consts[name])
        pieces.append(values or [UNREAD])
    pieces.append([lit[last:]])
    if "envcloak" not in "".join(v for p in pieces for v in p):
        return []
    lines = [""]
    for p in pieces:
        lines = [a + b for a in lines for b in p]
        if len(lines) > MAX_LINES:
            raise SourceError("%s line %d: a format string whose arguments the reader reads as more than %d lines; print fewer pieces" % (src.rel, src.skel.count("\n", 0, start) + 1, MAX_LINES))
    return lines


def printed_placeholder(src, start, lit, at, line_start, ctx):
    """A placeholder after `envcloak:`, with white space or none, at offset
    `at` of the string (a literal or a `concat!`) that starts at `start`.
    Followed by `:`, it is printed where a token goes, and its argument
    must be one the reader reads. Followed by more of a token or another
    placeholder, the token would come in pieces, and it is refused. At the
    start of a line and not followed by `:`, it is a usage line,
    `envcloak: <message>` (see `usage_line`). Elsewhere in a line, its
    value is counted by the token it starts with when the reader can read
    it."""
    where = "%s line %d" % (src.rel, src.skel.count("\n", 0, start) + 1)
    pm = re.compile(r"envcloak:\s*\{([^{}:]*)(:[^{}]*)?\}(.?)", re.S).match(lit, at)
    if not pm:
        raise SourceError("%s: a line printed as `envcloak: {...}` the reader cannot read" % where)
    name, spec, after = pm.group(1).strip(), pm.group(2) or "", pm.group(3)
    token_position = after == ":"
    if re.fullmatch(r"[A-Za-z0-9_]", after) or (after == "{" and not lit.startswith("{", pm.end())):
        raise SourceError("%s: a line printed as `envcloak: {%s%s}%s...`, whose token comes in pieces: print a whole token in one place" % (where, name, spec, after))
    if "*" in spec or "$" in spec:
        raise SourceError("%s: a line printed as `envcloak: {%s%s}` the reader cannot read" % (where, name, spec))
    # The format macro's arguments after the string.
    found = format_arguments(src, start)
    if found is None:
        raise SourceError("%s: a line printed as `envcloak: {...}` outside a format macro's arguments" % where)
    positional, named = found
    if name == "" or name.isdigit():
        # An implicit placeholder takes the next positional argument after
        # those the placeholders before it in the string took.
        i = int(name) if name else implicit_args(lit[:at])
        if i >= len(positional):
            raise SourceError("%s: a line printed as `envcloak: {}` without its argument" % where)
        span = positional[i]
    elif name in named:
        span = named[name]
    else:
        span = None
    if token_position:
        if span is not None:
            ctx.read(src, span[0], span[1], field=True, printed=True)
            return
        raise SourceError("%s: a line printed as `envcloak: {%s}:` takes its token from a variable the reader cannot read; print a failure's token (`.token()`)" % (where, name))
    if line_start:
        usage_line(src, start, where, name, span, ctx)
        return
    # Elsewhere in a line and not followed by `:`, the value is printed
    # where a token goes and could bring its own colon: when the reader can
    # read it, the token it starts with counts. A value only known at run
    # time (a count, a label) is beyond it, as any line put together at run
    # time is.
    if span is not None:
        ctx.read(src, span[0], span[1], field=True, printed=True, quiet=True)


def usage_line(src, start, where, name, span, ctx):
    """A usage line, `envcloak: {x}`: it must be printed in the arm of
    `match parse(..)` that binds `x` (`Err(x)`, or a variant `E::V(x)` of
    the error), with `fn parse` in this file. Every value that `fn parse`
    can give as its error is read (`parse_errors`), and the leading
    `<token>:` of each counts, as does that of every string in `fn
    parse`."""
    ident = None
    if span is None and re.fullmatch(IDENT, name):
        ident = name
    elif span is not None and re.fullmatch(IDENT, src.skel[span[0]:span[1]].strip()):
        ident = src.skel[span[0]:span[1]].strip()
    items = ctx.fns[src.rel]
    holder = [f for f in items if f.body and f.body[0] < start < f.body[1]]
    # `parse` is this file's free `fn parse`: a method of that name is not
    # what a bare `parse(..)` calls (that is a free function, imported if
    # not defined here, and then not read: the line is refused).
    blocks = [(m.end() - 1, src.block_end(m.end() - 1)) for m in re.finditer(r"\b(?:impl|trait)\b[^{;]*\{", src.skel)]
    parse = [f for f in items if f.name == "parse" and f.body and not any(x < f.start < y for x, y in blocks)]
    binding = None
    if ident and holder and parse:
        # The line is in an arm of `match parse(..) { .. }` whose pattern
        # binds the message.
        a, b = holder[-1].body
        binds = re.compile(r"(?:(?<![\w:])Err|::\s*(%s))\s*\(\s*%s\s*\)" % (IDENT, re.escape(ident)))
        for m in re.finditer(r"\bmatch\s+parse\s*\(", src.skel[a:b]):
            call_close = src.close_of(a + m.end() - 1)
            open_at = find_top(src, call_close + 1, b, "{")
            if open_at is None or not open_at < start < src.close_of(open_at):
                continue
            arm = arm_at(src, open_at, start)
            bm = binds.search(src.skel, arm[0], arm[1]) if arm else None
            if bm:
                binding = bm.group(1) or "Err"
    if binding is None:
        raise SourceError("%s: a usage line `envcloak: {%s}` whose message the reader cannot trace to this file's `fn parse`" % (where, name))
    for f in parse:
        for v in parse_errors(src, f, binding, ctx) + src.literals(*f.body):
            m = re.match(r"([a-z][a-z0-9_]*):", v)
            if m:
                ctx.take([m.group(1)], src)


def parse_errors(src, f, binding, ctx):
    """Every value `fn parse` (`f`) can give as its error, each read as a
    failure token is (verifier review of M2-RES1: a message from a
    constant, `concat!` or a helper was not read). Its error is `&'static
    str`, or an enum of this file whose variant the usage line binds holds
    one; the enum derives nothing that converts, and every `From` into it
    is in this file and hands its value to a variant unchanged. In `fn
    parse` the error is given only so: `Err(<value>)` (a variant of the
    enum around it, or `.into()` after it, read through); a `?` after
    `Err(..)`, `.ok_or(<value>)`, `.ok_or_else(|| <value>)` or
    `.map_err(|..| <value>)`; and every `return`, and the last
    expression, is `Ok(..)` or `Err(..)`. Anything else is refused."""
    a, b = f.body

    def where(at):
        return "%s line %d" % (src.rel, src.skel.count("\n", 0, at) + 1)

    def refuse(at, why):
        raise SourceError("%s: `fn parse` %s" % (where(at), why))

    ret = re.sub(r"\s*where\b.*$", "", re.sub(r"^->\s*", "", f.ret)).strip()
    rm = re.fullmatch(r"(?:(?:::)?%s\s*::\s*)*Result\s*<(.*)>" % IDENT, ret)
    parts = split_generics(rm.group(1)) if rm else []
    if len(parts) != 2:
        refuse(f.start, "does not return a `Result<_, _>` the reader can read (`%s`)" % ret[:60])
    err = parts[1]
    enum, variants = None, {}
    if re.fullmatch(r"&\s*(?:'static\s+)?str", err):
        if binding != "Err":
            refuse(f.start, "gives a `&str` error, which has no variant `%s`" % binding)
    else:
        enum = plain_type(err)
        em = re.search(r"\benum\s+%s\b" % re.escape(enum), src.skel) if enum else None
        if not em:
            refuse(f.start, "gives an error, `%s`, that is not an enum of this file" % err[:40])
        for at, text in item_attributes(src, em.start()):
            am = re.match(r"\s*(%s)\s*(.*)$" % IDENT, text, re.S)
            ok = am and am.group(1) in FAILURE_ATTRIBUTES
            if ok and am.group(1) == "derive":
                inner = am.group(2).strip()
                ok = inner.startswith("(") and all(plain_type(d) in FAILURE_DERIVES for d in inner[1:-1].split(",") if d.strip())
            if not ok:
                refuse(at, "gives an error, `%s`, that carries `#[%s]`, which could make one where the reader does not look" % (enum, " ".join(text.split())[:40]))
        open_at = src.skel.index("{", em.end())
        for x, y, t in split_fields(src, open_at + 1, src.block_end(open_at) - 1):
            vm = re.fullmatch(r"\s*(%s)\s*(?:\((.*)\))?\s*" % IDENT, t, re.S)
            if vm:
                variants[vm.group(1)] = vm.group(2)
        if binding == "Err":
            refuse(f.start, "gives an error, `%s`, that a usage line prints whole, as its `Display` makes it: bind the variant that holds the message" % enum)
        field = variants.get(binding)
        if field is None or not is_static_str(field, static_str_types(ctx.sources)):
            refuse(f.start, "gives an error whose variant `%s` does not hold one `&'static str`" % binding)
        check_conversions(src, enum, ctx)
    out = []

    def error_values(x, y):
        x, y = strip_span(src, x, y)
        m = re.search(r"\.\s*into\s*\(\s*\)$", src.skel[x:y])
        if m:
            return error_values(x, x + m.start())
        if enum:
            v = re.match(r"(?:%s\s*::\s*)*%s\s*::\s*(%s)\s*\(" % (IDENT, re.escape(enum), IDENT), src.skel[x:y])
            if v and v.group(1) in variants and src.close_of(x + v.end() - 1) == y - 1:
                return error_values(x + v.end(), y - 1)
        try:
            return values_of(src, x, y, Reading(ctx.consts, bad=ctx.bad))
        except Unreadable as e:
            refuse(x, "gives an error the reader cannot read: %s" % e)

    for m in MACRO.finditer(src.skel, a, b):
        if m.start() in src.concats or re.match(r"concat\b", m.group(0)):
            continue  # read as a value, where it is one
        refuse(m.start(), "calls a macro (`%s`), which could give an error the reader does not see" % " ".join(m.group(0).split()))
    for m in re.finditer(r"(?<![\w.])Err\s*\(", src.skel[a:b]):
        open_at = a + m.end() - 1
        out += error_values(open_at + 1, src.close_of(open_at))
    for m in re.finditer(r"\?", src.skel[a:b]):
        q = a + m.start()
        k = q - 1
        while k > a and src.skel[k].isspace():
            k -= 1
        o = src.open_of(k) if src.skel[k] == ")" else None
        j = (o or a) - 1
        while j > a and src.skel[j].isspace():
            j -= 1
        w = re.search(r"(%s)$" % IDENT, src.skel[a:j + 1]) if o else None
        name = w.group(1) if w else None
        before = src.skel[a:a + w.start()].rstrip() if w else ""
        if name == "Err" and not before.endswith("."):
            continue
        if before.endswith(".") and name in ("ok_or", "ok_or_else", "map_err"):
            args = src.split_top(o + 1, k)
            if len(args) != 1:
                refuse(q, "has a `.%s(..)?` the reader cannot read" % name)
            x, y, _ = args[0]
            if name != "ok_or":
                c = re.match(r"\s*(?:move\s+)?\|[^|]*\|", src.skel[x:y])
                if not c:
                    refuse(q, "has a `.%s(..)?` whose closure the reader cannot read" % name)
                x += c.end()
            out += error_values(x, y)
            continue
        refuse(q, "has a `?` whose error the reader cannot read: write `Err(..)?`, `.ok_or(\"...\")?`, `.ok_or_else(|| \"...\")?` or `.map_err(|_| \"...\")?`")
    for m in re.finditer(r"\breturn\b", src.skel[a:b]):
        at = a + m.end()
        rm2 = re.match(r"\s*(Ok|Err)\s*\(", src.skel[at:b])
        close = src.close_of(at + rm2.end() - 1) if rm2 else None
        after = src.skel[close + 1:b].lstrip() if rm2 else ""
        if not rm2 or not after or after[0] not in ";},)":
            refuse(at, "returns something other than `Ok(..)` or `Err(..)`")
    last, depth = a + 1, 0
    for k in range(a + 1, b - 1):
        ch = src.skel[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0 and ch == "}":
                last = k + 1
        elif ch == ";" and depth == 0:
            last = k + 1
    x, y = strip_span(src, last, b - 1)
    tm = re.match(r"(Ok|Err)\s*\(", src.skel[x:y])
    if not tm or src.close_of(x + tm.end() - 1) != y - 1:
        refuse(x, "ends with something other than `Ok(..)` or `Err(..)`")
    return out


def split_generics(text):
    """The generic arguments in `text` (what is inside `<...>`), split at
    commas at depth 0, stripped."""
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return [p for p in parts if p]


def check_conversions(src, enum, ctx):
    """Every conversion into `fn parse`'s error enum (`From`, `Into`)
    across its crate: each `From` is in this file and its `fn from` hands
    its value to a variant unchanged (`E::V(value)`), and there is no
    `Into`; otherwise a `.into()` or `?` in `fn parse` could make a
    message the reader does not see."""
    for other in ctx.sources:
        if crate_of(other.rel) != crate_of(src.rel):
            continue
        for m in re.finditer(r"\bimpl\b", other.skel):
            body = BODY_OR_END.search(other.skel, m.end())
            if not body or body.group(0) != "{":
                continue
            head = re.sub(r"\swhere\s.*$", "", " ".join(other.skel[m.end():body.start()].split()))
            target = r"(?:%s\s*::\s*)*%s" % (IDENT, re.escape(enum))
            at = "%s line %d" % (other.rel, other.skel.count("\n", 0, m.start()) + 1)
            if "$" in head and re.search(r"\b(?:From|Into)\b", head):
                raise SourceError("%s: a conversion a macro makes for a type it is given could be one into `%s`, the error of `fn parse` in %s, which the reader does not read" % (at, enum, src.rel))
            if re.search(r"\bInto\s*<\s*%s\s*>" % target, head):
                raise SourceError("%s: an `Into` for `%s`, the error of `fn parse` in %s, could make a usage message the reader does not see" % (at, enum, src.rel))
            if not re.search(r"\bFrom\s*<.*>\s*for\s+%s$" % target, head):
                continue
            if other is not src:
                raise SourceError("%s: a `From` for `%s`, the error of `fn parse`, outside %s, could make a usage message the reader does not see" % (at, enum, src.rel))
            end = other.block_end(body.start())
            froms = [f for f in ctx.fns[other.rel] if f.name == "from" and f.body and body.start() < f.start < end]
            ok = len(froms) == 1 and len(froms[0].params) == 1
            if ok:
                pm = re.match(r"(?:mut\s+)?(%s)\s*:" % IDENT, froms[0].params[0])
                text = " ".join(other.skel[froms[0].body[0] + 1:froms[0].body[1] - 1].split())
                ok = bool(pm) and bool(re.fullmatch(r"(?:%s\s*::\s*)*(?:%s|Self)\s*::\s*%s\s*\(\s*%s\s*\)" % (IDENT, re.escape(enum), IDENT, re.escape(pm.group(1))), text))
            if not ok:
                raise SourceError("%s: a `From` for `%s`, the error of `fn parse`, that does not hand its value to a variant unchanged (`%s::Variant(value)`)" % (at, enum, enum))


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
            # The literal is the whole value, never read by its start
            # (the class of Codex's review of M2-RES1).
            if lit is None or not re.match(r"\s*;", src.skel[lit[0]:]):
                raise SourceError("%s: `const TOOL` is not one string literal" % src.rel)
            name = lit[1]
            if name in found:
                raise SourceError("%s: the tool `%s` is declared twice" % (src.rel, name))
            found[name] = src.rel
    if not found:
        raise SourceError("no `const TOOL` found under crates/envcloak-mcp/src")
    return found


# The control channels whose messages the code declares, each with the
# file that declares them and the enums whose variants are its messages
# (M2-17: the PTY monitor's reports and the CLI's commands to it). A
# channel not here has no reader: its rows stay `reserved` until its task
# adds one.
CONTROL_CHANNELS = {
    "pty_monitor": ("crates/envcloak-sys/src/pty_monitor.rs", ("Report", "Command")),
}
ENUM_DECL = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)")
VARIANT = re.compile(r"([A-Z][A-Za-z0-9]*)(\s*\((?:[^()]|\([^()]*\))*\))?")
CONTROL_ENUM_HEAD = re.compile(r"(?:\s*#\s*\[\s*derive\s*\([^()[\]{}]*\)\s*\])*\s*pub\s+")
INNER_CONDITIONAL = re.compile(r"#\s*!\s*\[\s*(?:cfg|cfg_attr)\b")


def direct_control_enum(src, start, line, name):
    """Bind a message enum to its direct public declaration in this file.
    A nested or macro declaration, or an unhandled attribute on the item,
    does not establish that binding. Refuse those forms rather than count
    the variants of an incidental enum with the same name."""
    stack = []
    item_start = 0
    closes = {"(": ")", "[": "]", "{": "}"}
    for i, c in enumerate(src.skel[:start]):
        if c in closes:
            stack.append(closes[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                raise SourceError("%s: unbalanced source before `enum %s`" % (line, name))
            if not stack and c == "}":
                item_start = i + 1
        elif c == ";" and not stack:
            item_start = i + 1
    if stack or not CONTROL_ENUM_HEAD.fullmatch(src.skel[item_start:start]):
        raise SourceError("%s: `enum %s` must be a direct module-scope public enum with only derive attributes; the reader cannot establish its control-message binding" % (line, name))


def code_control_messages(root):
    """The control-pipe messages each channel of CONTROL_CHANNELS declares:
    every variant of its enums, keyed `<channel> <Message>`. Each variant
    is read or refused, never skipped: a unit or tuple variant is read; an
    attribute on one (a `cfg` could take it away), a discriminant, a
    struct variant, or anything else is an error. So are an enum of the
    channel declared twice or not at all, generic, a message named twice
    on one channel, and a `#[path]` module in the file. The named enums
    must be direct module-scope public declarations with only derive
    attributes; nested, macro, conditional or other unhandled bindings
    are refused. A conditional inner attribute on the file is refused
    too, even when imports separate it from the enum."""
    found = {}
    for channel, (rel, enums) in sorted(CONTROL_CHANNELS.items()):
        src = Source(rel, read(root, rel))
        refuse_path_attributes(src)
        if INNER_CONDITIONAL.search(src.skel):
            raise SourceError("%s: a conditional inner attribute prevents the reader from establishing its control-message bindings" % rel)
        bodies = {}
        for m in ENUM_DECL.finditer(src.skel):
            name = m.group(1)
            if name not in enums:
                continue
            line = "%s line %d" % (rel, src.skel.count("\n", 0, m.start()) + 1)
            if name in bodies:
                raise SourceError("%s: `enum %s` is declared twice; the reader cannot tell which holds the `%s` channel's messages" % (line, name, channel))
            brace = src.skel.find("{", m.end())
            if brace < 0 or src.skel[m.end():brace].strip():
                raise SourceError("%s: `enum %s` is not a plain enum with a body the reader can read" % (line, name))
            bodies[name] = (line, src.skel[brace + 1:src.block_end(brace) - 1], m.start())
        for name in enums:
            if name not in bodies:
                raise SourceError("%s: no `enum %s`, whose variants are the `%s` channel's messages" % (rel, name, channel))
            # Establish uniqueness before binding: a decoy encountered before
            # the real declaration is still diagnosed as a duplicate enum.
            line, body, start = bodies[name]
            direct_control_enum(src, start, line, name)
            for item in split_generics(body):
                v = VARIANT.fullmatch(item)
                if not v:
                    raise SourceError("%s: `enum %s` has a variant the reader cannot read (`%s`): each message is a unit or tuple variant with no attribute and no discriminant" % (line, name, " ".join(item.split())[:60]))
                key = "%s %s" % (channel, v.group(1))
                if key in found:
                    raise SourceError("%s: the message `%s` is declared twice on the `%s` channel" % (line, v.group(1), channel))
                found[key] = rel
    if not found:
        raise SourceError("no control message found in %s" % ", ".join(f for f, _ in CONTROL_CHANNELS.values()))
    return found


STATEMENT_DOMAIN = re.compile(r"(envcloak-[a-z0-9-]*statement/[0-9]+)")
# `#[path = "..."]` and `#[cfg_attr(<cfg>, path = "...")]`: a module read
# from a file the walk may never reach (verifier review of M2-RES1).
# scripts/check-unsafe.sh refuses these too, and scripts/check-sources.sh
# settles one a macro builds from pieces with the compiler's own list.
PATH_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*(?:path\s*=|cfg_attr\s*\((?:[^\[\]]|\[[^\]]*\])*?\bpath\s*=)")


def cargo_path_or_name(var):
    """Whether `var` is one Cargo sets for a test or a crate, holding a
    path, a name or a version and never a domain: Cargo's package
    variables, `CARGO`, `CARGO_MANIFEST_PATH`, `CARGO_TARGET_TMPDIR` and
    `CARGO_BIN_EXE_<name>`."""
    return var is not None and (
        var in CARGO_ENV
        or var in ("CARGO", "CARGO_MANIFEST_PATH", "CARGO_TARGET_TMPDIR")
        or re.fullmatch(r"CARGO_BIN_EXE_[A-Za-z0-9_-]+", var) is not None
    )


# `path = ` as a key (not `path ==` or `path =>`).
PATH_KEY = re.compile(r"(?<![A-Za-z0-9_])path\s*=(?![=>])")


def refuse_path_attributes(src):
    """A `#[path]` attribute, which compiles a file the reader walks past,
    is refused; and, as scripts/check-unsafe.sh has it, so is `path = ` in
    any attribute or argument position (after `[`, `(` or `,`) and `path =
    "..."` anywhere but a `let` binding, which a macro can turn into one
    (`m! { path = "x.rs" }`)."""
    for m in PATH_ATTRIBUTE.finditer(src.skel):
        raise SourceError("%s line %d: a `#[path]` attribute compiles a file the reader does not walk to; keep each module in the file its name gives" % (src.rel, src.skel.count("\n", 0, m.start()) + 1))
    for m in PATH_KEY.finditer(src.skel):
        before = src.skel[:m.start()].rstrip()
        word = re.search(r"([A-Za-z_][A-Za-z0-9_]*)$", before)
        literal = re.match(r"\s*[bcr]*#*\"", src.skel[m.end():])
        if before[-1:] in ("[", "(", ",") or (literal and (not word or word.group(1) not in ("let", "mut"))):
            raise SourceError("%s line %d: `path = ` where a macro could make it a `#[path]` attribute, which compiles a file the reader does not walk to; rename it" % (src.rel, src.skel.count("\n", 0, m.start()) + 1))


def included_text(root, src, at, where):
    """The text of the file that the `include_str!` or `include_bytes!` at
    `at` of `src` brings in, so it is read too: its path must be one string
    literal naming a regular file in the repository, reached through no
    symbolic link; anything else is refused."""
    lit = src.includes.get(at)
    if lit is None:
        raise SourceError("%s: `include_str!` or `include_bytes!` of something other than one string literal: the reader cannot tell which file it brings in" % where)
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.join(root, src.rel)), lit))
    rel = os.path.relpath(path, root)
    if os.path.isabs(lit) or rel.startswith(".."):
        raise SourceError("%s: `include_str!` or `include_bytes!` of a file outside the repository (`%s`)" % (where, lit))
    if os.path.realpath(path) != os.path.join(os.path.realpath(root), rel):
        raise SourceError("%s: `include_str!` or `include_bytes!` of a file reached through a symbolic link (`%s`)" % (where, lit))
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise SourceError("%s: `include_str!` or `include_bytes!` of something other than a regular file (`%s`)" % (where, lit))
        with open(path, "rb") as f:
            return [f.read().decode("latin-1")]
    except OSError as e:
        raise SourceError("%s: the file `include_str!` or `include_bytes!` brings in could not be read (%s)" % (where, e.strerror))


def code_statement_domains(root):
    """Statement domains written in string literals, or `concat!` of
    literals, anywhere in them, in the workspace's Rust files
    (`b"envcloak-statement/1\n"`), and in the files `include_str!` and
    `include_bytes!` bring in; a domain named in a comment is not one the
    code uses. Refused, never skipped: a `concat!` of anything but
    literals, `include!`, `stringify!` of `envcloak`, `env!` of a variable
    other than Cargo's own, a `#[path]` module, and a symbolic link to a
    directory or a Rust file (verifier review of M2-RES1: a walk passed
    over what the compiler read)."""
    found = {}
    for rel in rust_files(root, CRATES, skip=("target",)):
        src = Source(rel, read(root, rel))
        refuse_path_attributes(src)
        for at, kind, why in src.unreadable:
            line = "%s line %d" % (rel, src.skel.count("\n", 0, at) + 1)
            if kind == "include_text":
                # Text brought in from another file: read too, as text.
                for text in included_text(root, src, at, line):
                    for m in STATEMENT_DOMAIN.finditer(text):
                        found.setdefault(m.group(1), rel)
                continue
            if kind == "env" and cargo_path_or_name(src.env_var(at)):
                continue  # Cargo's own: a path, a name or a version
            raise SourceError("%s: %s" % (line, why))
        # In a crate's sources, a domain anywhere in a literal; elsewhere
        # (tests, whose literals hold fixture code for this script's own
        # tests) at a literal's start, where a domain is written.
        product = rel.split("/")[2:3] == ["src"]
        for lit in src.literals(0, len(src.skel)):
            for m in (STATEMENT_DOMAIN.finditer(lit) if product else [STATEMENT_DOMAIN.match(lit)]):
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
                       name="Class", num="Number", grammar=TOKEN, code=code_item_classes,
                       range=(4, 65535)),
    "table_tag": dict(doc="docs/VAULT.md", cols=["Number", "Table", "Task", "Status", "Use"],
                      name="Table", num="Number", grammar=TOKEN, code=tags("TableTag"),
                      range=(10, 65535)),
    "field_tag": dict(doc="docs/VAULT.md", cols=["Number", "Field", "Task", "Status", "Use"],
                      name="Field", num="Number", grammar=TOKEN, code=tags("FieldTag"),
                      range=(14, 65535)),
    "policy_kind": dict(doc="docs/VAULT.md", cols=["Number", "Kind", "Task", "Status", "Use"],
                        name="Kind", num="Number", grammar=TOKEN, code=code_policy_kinds,
                        range=(1, 255)),
    "error_kind": dict(doc="docs/IPC.md", cols=["Token", "Code", "Task", "Status", "Use"],
                       name="Token", num="Code", grammar=TOKEN, code=code_error_kinds,
                       range=(-32098, -32035)),
    "reason": dict(doc="docs/IPC.md", cols=["Token", "Task", "Status", "Use"],
                   name="Token", grammar=TOKEN, code=code_reasons),
    "method": dict(doc="docs/IPC.md", cols=["Method", "Task", "Status", "Use"],
                   name="Method", grammar=CLIENT_METHOD, code=code_methods),
    "app_method": dict(doc="docs/IPC.md", cols=["Method", "Task", "Status", "Use"],
                       name="Method", grammar=APP_METHOD, code=code_app_methods),
    "unlocker_kind": dict(doc="docs/VAULT.md", cols=["Number", "Kind", "Task", "Status", "Use"],
                          name="Kind", num="Number", grammar=TOKEN, code=code_unlocker_kinds,
                          range=(3, 255)),
    "field": dict(doc="docs/IPC.md", cols=["Method", "Field", "Task", "Status", "Use"],
                  name="Field", scope="Method", scope_grammar=METHOD, grammar=FIELD, code=None),
    "exit_token": dict(doc="docs/IPC.md", cols=["Token", "Task", "Status", "Use"],
                       name="Token", grammar=TOKEN, code=code_exit_tokens),
    "coverage": dict(doc="docs/IPC.md", cols=["Token", "Kind", "Task", "Status", "Use"],
                     name="Token", grammar=TOKEN, code=code_coverage),
    "control_message": dict(doc="docs/IPC.md", cols=["Channel", "Message", "Task", "Status", "Use"],
                            name="Message", scope="Channel", scope_grammar=TOKEN, grammar=MESSAGE,
                            code=code_control_messages),
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
    """Each registry's rows, from its tables in every section, as one list;
    each row carries the heading it is under as `_section`."""
    tables = {}
    seen = set()
    for doc in DOCS:
        text = read(root, doc)
        opened = OPEN.findall(text)
        closed = text.count("<!-- /reservations -->")
        blocks = list(BLOCK.finditer(text))
        if len(blocks) != len(opened) or closed != len(opened):
            fail("%s: a reservations marker is unmatched or malformed" % doc)
        headings = [(m.start(), m.group(1)) for m in HEADING.finditer(text)]
        for block in blocks:
            reg, body = block.group(1), block.group(2)
            above = [h for at, h in headings if at < block.start()]
            section = above[-1] if above else None
            if section not in SECTIONS:
                fail("%s: the `%s` table is under %s, not one of the headings %s" % (
                    doc, reg, "no heading" if section is None else "\"%s\"" % section,
                    ", ".join("\"%s\"" % s for s in SECTIONS)))
                continue
            if reg not in REGISTRIES:
                fail("%s: unknown reservations table `%s`" % (doc, reg))
                continue
            if REGISTRIES[reg]["doc"] != doc:
                fail("%s: the `%s` table belongs in %s" % (doc, reg, REGISTRIES[reg]["doc"]))
                continue
            if (reg, section) in seen:
                fail("%s: the `%s` table appears twice under \"%s\"" % (doc, reg, section))
                continue
            seen.add((reg, section))
            rows = parse_table(doc, reg, body)
            for row in rows:
                row["_section"] = section
            tables.setdefault(reg, []).extend(rows)
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
            fail("%s: `%s` names %r, which is not an M2, M2b or M3 task, a later milestone or `spare`" % (where, key, task))
        section = row.get("_section")
        if section in SECTIONS:
            own, milestone = SECTIONS[section]
            if task in (M2_TASKS | M3_TASKS) and task not in own:
                home = [s for s, (tasks, _) in SECTIONS.items() if task in tasks]
                fail("%s: `%s` is %s's, so its row belongs under \"%s\", not \"%s\"" % (where, key, task, home[0], section))
            if task in LATER and int(task[1:]) <= milestone:
                fail("%s: `%s` names %s, which is not a milestone after the one \"%s\" reserves for" % (where, key, task, section))
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
