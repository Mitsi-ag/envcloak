#!/usr/bin/env bash
# Enforces the unsafe-code and secret-exposure boundaries (SPEC §5, "Memory
# hygiene" and "Process hardening"). The compiler does the enforcing where it
# can; this script checks that nothing in the tree switches it off:
#
# 1. Manifests, read with a real TOML parser (python3's tomllib, so quoting,
#    dotted keys and multi-line strings are read as Cargo reads them):
#    - the workspace forbids `unsafe_code`, denies `clippy::disallowed_methods`
#      above the priority of every group that contains it, and keeps
#      `warnings`, `clippy::all` and `clippy::style` at warn or above;
#    - every package inherits the workspace lints, except
#      crates/envcloak-sys, whose own tables must equal the workspace's with
#      `unsafe_code = "deny"`, so only its files can allow unsafe code;
#    - no package has a build script, is a proc-macro crate or points a
#      target at a file that is not a `.rs` file inside it; no manifest sets
#      rustflags, [patch] or [replace]; and the tree holds no cargo config.
# 2. clippy.toml forbids secrecy's expose_secret methods, and no other clippy
#    config exists. `disallowed_methods` may be allowed only in files listed
#    in security/expose-allowlist.txt (whose entries must exist), and those
#    files may not declare out-of-line modules that would inherit an allow.
#    Nothing may allow `warnings`, `clippy::all` or `clippy::style`.
# 3. No Rust file uses `include!` or a `#[path]` attribute, either of which
#    compiles a file this check never reads.
#
# Rust files are read with comments and the contents of string and
# character literals removed, raw identifiers (`r#name`) reduced to their
# names, and lint attributes matched as tokens, so neither a comment nor a
# string can satisfy or trip a check. Any other mention of `unsafe_code`,
# `disallowed_methods`, `clippy::all` or `clippy::style` (a macro building
# an attribute, say) fails. A file that ends inside a comment or literal
# fails too, rather than being skipped. scripts/check-unsafe-lint.sh and
# scripts/check-expose-lint.sh then prove with the compiler that the levels
# this script reads are the levels in effect.
#
# Usage: scripts/check-unsafe.sh [workspace-root]
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root"

status=0
fail() {
  echo "check-unsafe: $*" >&2
  status=1
}

# Word boundaries that work in both BSD and GNU grep -E.
b='(^|[^A-Za-z0-9_])'
e='([^A-Za-z0-9_]|$)'

# Every file to check. In a git checkout: tracked files plus untracked ones
# that are not ignored (so build output and local scratch copies are
# skipped). Elsewhere, such as the test fixtures: every file outside
# target/ and .git/.
all_files() {
  if [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ]; then
    git ls-files --cached --others --exclude-standard | while IFS= read -r f; do
      [ -f "$f" ] && printf '%s\n' "$f"
    done
  else
    find . \( -name target -o -name .git \) -prune -o -type f -print | sed 's|^\./||'
  fi | LC_ALL=C sort -u
}

rust_files() {
  all_files | grep -E '\.rs$' || true
}

if ! python3 -c 'import tomllib' 2>/dev/null; then
  echo "check-unsafe: needs python3 3.11 or later (tomllib) to read the manifests" >&2
  exit 1
fi

# 1 and 2a. Manifests and clippy.toml. Reads the file list on stdin and
# prints one "path: problem" line per problem.
manifest_check='
import os, sys, tomllib

ROOT = "Cargo.toml"
SYS = "crates/envcloak-sys/Cargo.toml"
TOOLS = ("rust", "clippy", "rustdoc")
LEVELS = ("allow", "warn", "deny", "forbid")
EXPOSE = ("secrecy::ExposeSecret::expose_secret", "secrecy::ExposeSecretMut::expose_secret_mut")
TARGETS = ("lib", "bin", "test", "bench", "example")

def fail(path, msg):
    print(path + ": " + msg)

def load(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        fail(path, "cannot be read as TOML (%s)" % e)
        return None

def rank(level):
    return LEVELS.index(level)

def lint_tables(path, where, table):
    """{tool: {name: (level, priority, other keys)}}, names normalized the
    way rustc matches them. None when unreadable."""
    if not isinstance(table, dict):
        fail(path, where + " must be a table")
        return None
    out = {}
    ok = True
    for tool, lints in table.items():
        if tool not in TOOLS:
            fail(path, "%s.%s: lints may only be set for rust, clippy and rustdoc" % (where, tool))
            ok = False
            continue
        if not isinstance(lints, dict):
            fail(path, "%s.%s must be a table" % (where, tool))
            ok = False
            continue
        seen = {}
        for name, spec in lints.items():
            label = "%s.%s.%s" % (where, tool, name)
            key = name.replace("-", "_").lower()
            if key.startswith("r#"):
                key = key[2:]
            if ":" in key or "." in key or not key:
                fail(path, label + ": use one plain lint name per key, in its tool table")
                ok = False
                continue
            if isinstance(spec, str):
                level, priority, rest = spec, 0, ()
            elif isinstance(spec, dict) and isinstance(spec.get("level"), str):
                level = spec["level"]
                priority = spec.get("priority", 0)
                rest = tuple(sorted((k, repr(v)) for k, v in spec.items() if k not in ("level", "priority")))
            else:
                fail(path, label + ": the level must be a string or a table with a level")
                ok = False
                continue
            if level not in LEVELS or type(priority) is not int:
                fail(path, label + ": unknown level or priority")
                ok = False
                continue
            if key in seen:
                fail(path, label + ": this lint is set twice")
                ok = False
                continue
            seen[key] = (level, priority, rest)
        out[tool] = seen
    return out if ok else None

def keys_named(obj, name):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == name:
                yield k
            yield from keys_named(v, name)
    elif isinstance(obj, list):
        for v in obj:
            yield from keys_named(v, name)

def common(path, doc):
    for key in ("patch", "replace"):
        if key in doc:
            fail(path, "[%s] is not allowed: it can swap secrecy or zeroize for other code" % key)
    if "cargo-features" in doc:
        fail(path, "cargo-features is not allowed")
    if any(keys_named(doc, "rustflags")):
        fail(path, "must not set rustflags (they can turn lints off)")

files = [line.rstrip("\n") for line in sys.stdin if line.strip()]
manifests = [f for f in files if os.path.basename(f) == "Cargo.toml"]

workspace = None
root = load(ROOT) if ROOT in manifests else None
if ROOT not in manifests:
    fail(ROOT, "is missing")
elif root is not None:
    common(ROOT, root)
    ws = root.get("workspace")
    if not isinstance(ws, dict) or "lints" not in ws:
        fail(ROOT, "must have a [workspace.lints] table")
    else:
        workspace = lint_tables(ROOT, "workspace.lints", ws["lints"])
    if workspace is not None:
        rust = workspace.get("rust", {})
        clippy = workspace.get("clippy", {})
        if rust.get("unsafe_code", ("",))[0] != "forbid":
            fail(ROOT, "[workspace.lints.rust] must set unsafe_code = \"forbid\"")
        if "warnings" in rust and rank(rust["warnings"][0]) < rank("warn"):
            fail(ROOT, "[workspace.lints.rust] warnings must stay at warn or above")
        if "disallowed_method" in clippy:
            fail(ROOT, "[workspace.lints.clippy] use disallowed_methods, not its old name")
        dm = clippy.get("disallowed_methods")
        if dm is None or rank(dm[0]) < rank("deny"):
            fail(ROOT, "[workspace.lints.clippy] must set disallowed_methods = \"deny\" (it enforces the expose_secret ban)")
        for group in ("all", "style"):
            g = clippy.get(group)
            if g is None:
                continue
            if rank(g[0]) < rank("warn"):
                fail(ROOT, "[workspace.lints.clippy] %s must stay at warn or above (it covers disallowed_methods)" % group)
            if dm is not None and g[1] >= dm[1]:
                fail(ROOT, "[workspace.lints.clippy] %s needs a lower priority than disallowed_methods, or its level wins" % group)

for m in manifests:
    if m == ROOT:
        continue
    doc = load(m)
    if doc is None:
        continue
    common(m, doc)
    pkg = doc.get("package")
    if not isinstance(pkg, dict) or "workspace" in doc:
        fail(m, "must be a package of this workspace (no virtual manifests or nested workspaces)")
        continue
    lints = doc.get("lints")
    if m == SYS:
        if workspace is not None:
            want = {tool: dict(names) for tool, names in workspace.items()}
            want.setdefault("rust", {})["unsafe_code"] = ("deny", 0, ())
            got = lint_tables(m, "lints", lints) if lints is not None else None
            if got != want:
                fail(m, "its [lints] tables must equal the workspace tables, with unsafe_code = \"deny\" and nothing else changed")
    elif lints != {"workspace": True}:
        fail(m, "needs [lints] workspace = true and nothing else, or the unsafe_code forbid does not apply")
    here = os.path.dirname(m)
    build = pkg.get("build")
    if build is True or isinstance(build, str) or (build is None and os.path.exists(os.path.join(here, "build.rs"))):
        fail(m, "build scripts are not allowed: one can change the environment its crate is linted in")
    for kind in TARGETS:
        targets = doc.get(kind)
        targets = [targets] if isinstance(targets, dict) else targets if isinstance(targets, list) else []
        for t in targets:
            if not isinstance(t, dict):
                continue
            if t.get("proc-macro") or t.get("proc_macro"):
                fail(m, "proc-macro crates are not allowed: their output can carry lint attributes no source check sees")
            p = t.get("path")
            if p is None:
                continue
            if not isinstance(p, str) or not p.endswith(".rs") or p.startswith("/") or ".." in p.split("/"):
                fail(m, "[%s] path must name a .rs file inside the package, which this check reads" % kind)

if "clippy.toml" not in files:
    fail("clippy.toml", "is missing")
else:
    conf = load("clippy.toml")
    if conf is not None:
        keys = [k for k in ("disallowed-methods", "disallowed_methods") if k in conf]
        paths = set()
        if len(keys) == 1 and isinstance(conf[keys[0]], list):
            for entry in conf[keys[0]]:
                if isinstance(entry, str):
                    paths.add(entry)
                elif isinstance(entry, dict) and isinstance(entry.get("path"), str):
                    paths.add(entry["path"])
        elif len(keys) > 1:
            fail("clippy.toml", "set disallowed-methods once")
        for need in EXPOSE:
            if need not in paths:
                fail("clippy.toml", "disallowed-methods must list " + need)
'
if ! manifest_problems="$(all_files | python3 -c "$manifest_check")"; then
  fail "the manifest check did not run to completion"
fi
while IFS= read -r msg; do
  [ -n "$msg" ] && fail "$msg"
done <<<"$manifest_problems"

# Cargo configuration can set rustflags, a rustc wrapper or CLIPPY_CONF_DIR,
# any of which can turn lints off.
while IFS= read -r config; do
  fail "$config: cargo configuration files are not allowed (they can turn lints off)"
done < <(all_files | grep -E '(^|/)\.cargo/config(\.toml)?$' || true)

while IFS= read -r extra; do
  fail "$extra: only the workspace root may hold clippy configuration"
done < <(all_files | grep -E '(^|/)\.?clippy\.toml$' | grep -vxF clippy.toml || true)

allowlist=security/expose-allowlist.txt
allowed=""
if [ -f "$allowlist" ]; then
  allowed="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$allowlist" | grep -v '^$' || true)"
else
  fail "$allowlist is missing"
fi

while IFS= read -r entry; do
  [ -n "$entry" ] || continue
  [ -f "$entry" ] || fail "$allowlist: listed file $entry does not exist"
done <<<"$allowed"

# 2 and 3. Rust source. Prints "LINE: problem" lines.
rust_lints_awk='
function ident(ch) { return ch ~ /[A-Za-z0-9_]/ }
function high(ch) { return ch > "\177" }
function blank(s, t) { t = s; gsub(/[^\n]/, " ", t); return t }
function line_of(pos, t) { t = substr(text, 1, pos); return gsub(/\n/, "", t) + 1 }
function report(ln, msg) { print ln ": " msg }
# Drops the `r#` of raw identifiers (raw strings are already gone), so
# `allow(r#unsafe_code)` reads as the `allow(unsafe_code)` rustc sees.
function unraw(s, out, p) {
  out = ""
  while (match(s, /r#[A-Za-z_]/)) {
    p = RSTART
    if (p > 1 && ident(substr(s, p - 1, 1))) out = out substr(s, 1, p + 1)
    else out = out substr(s, 1, p - 1)
    s = substr(s, p + 2)
  }
  return out s
}
# The previous character of `s` before `pos` that is not whitespace.
function before(s, pos, k) {
  k = pos - 1
  while (k > 0 && substr(s, k, 1) ~ /[ \t\n]/) k--
  return (k > 0) ? substr(s, k, 1) : ""
}
function check(level, lint, ln, relax) {
  relax = (level == "allow" || level == "expect")
  if (lint == "unsafe_code") {
    if (!in_sys && level != "deny" && level != "forbid")
      report(ln, "unsafe_code may only be relaxed in crates/envcloak-sys")
  } else if (lint == "warnings") {
    if (relax) report(ln, "must not allow warnings: it silences disallowed_methods; allow the specific lint instead")
  } else if (lint == "clippy::all" || lint == "clippy::style") {
    if (relax) report(ln, "clippy::all and clippy::style may not be allowed (they include disallowed_methods)")
  } else if (lint == "clippy::disallowed_methods" || lint == "clippy::disallowed_method") {
    if (relax && !allowlisted) report(ln, "allows disallowed_methods but is not listed in " allowlist)
  }
}
BEGIN { state = "code" }
{
  line = $0
  out = ""
  len = length(line)
  i = 1
  while (i <= len) {
    c = substr(line, i, 1)
    if (state == "block") {
      two = substr(line, i, 2)
      if (two == "/*") { depth++; i += 2; continue }
      if (two == "*/") {
        depth--
        i += 2
        if (depth == 0) { state = "code"; out = out " " }
        continue
      }
      i++
      continue
    }
    if (state == "str") {
      if (c == "\\") { i += 2; continue }
      if (c == "\"") { out = out "\""; state = "code" }
      i++
      continue
    }
    if (state == "raw") {
      if (c == "\"" && substr(line, i + 1, hashes) == hashstr) {
        out = out "\""
        state = "code"
        i += 1 + hashes
        continue
      }
      i++
      continue
    }
    two = substr(line, i, 2)
    if (two == "//") break
    if (two == "/*") { state = "block"; depth = 1; i += 2; continue }
    prev = (i > 1) ? substr(line, i - 1, 1) : ""
    if (c == "\"") { out = out "\""; state = "str"; i++; continue }
    if (!ident(prev) && (c == "r" || c == "b" || c == "c")) {
      j = i
      if (c != "r" && substr(line, i + 1, 1) == "\"") {
        out = out "\""
        state = "str"
        i += 2
        continue
      }
      if (c != "r") j++
      if (substr(line, j, 1) == "r") {
        k = j + 1
        hashes = 0
        hashstr = ""
        while (substr(line, k, 1) == "#") { k++; hashes++; hashstr = hashstr "#" }
        if (substr(line, k, 1) == "\"") {
          out = out "\""
          state = "raw"
          i = k + 1
          continue
        }
      }
    }
    if (c == "\047") {
      nx = substr(line, i + 1, 1)
      if (nx == "\\") {
        k = i + 3
        while (k <= len && substr(line, k, 1) != "\047") k++
        out = out "\047 \047"
        i = k + 1
        continue
      }
      if (nx != "" && substr(line, i + 2, 1) == "\047") {
        out = out "\047 \047"
        i += 3
        continue
      }
      if (high(nx)) {
        k = i + 1
        while (k <= len && k <= i + 4 && high(substr(line, k, 1))) k++
        if (substr(line, k, 1) == "\047") {
          out = out "\047 \047"
          i = k + 1
          continue
        }
      }
    }
    out = out c
    i++
  }
  text = text out "\n"
}
END {
  if (state != "code") {
    report(NR, "ends inside a comment or literal; this check cannot read it")
    exit
  }
  text = unraw(text)
  masked = text
  re = "(allow|expect|warn|deny|forbid)[ \t\n]*\\([^()]*\\)"
  pos = 1
  while (match(substr(text, pos), re)) {
    s = pos + RSTART - 1
    l = RLENGTH
    if (s > 1 && ident(substr(text, s - 1, 1))) { pos = s + 1; continue }
    grp = substr(text, s, l)
    level = grp
    sub(/[ \t\n]*\(.*/, "", level)
    inner = grp
    sub(/^[^(]*\(/, "", inner)
    sub(/\)$/, "", inner)
    ln = line_of(s)
    m = split(inner, items, ",")
    for (t = 1; t <= m; t++) {
      it = items[t]
      gsub(/[ \t\n]/, "", it)
      if (it != "" && it !~ /=/) check(level, it, ln)
    }
    masked = substr(masked, 1, s - 1) blank(grp) substr(masked, s + l)
    pos = s + l
  }
  # `path = ...` in an attribute position: #[path], or a cfg_attr or macro
  # argument that becomes one.
  pos = 1
  while (match(substr(masked, pos), /path[ \t\n]*=/)) {
    s = pos + RSTART - 1
    l = RLENGTH
    nx = substr(masked, s + l, 1)
    pc = before(masked, s)
    if ((s == 1 || !ident(substr(masked, s - 1, 1))) && nx != "=" && nx != ">" &&
        (pc == "[" || pc == "(" || pc == ","))
      report(line_of(s), "a #[path] attribute compiles a file this check does not read")
    pos = s + l
  }
  # An allow in a listed file would reach the modules it declares out of line.
  if (allowlisted) {
    pos = 1
    while (match(substr(masked, pos), /mod[ \t\n]+[A-Za-z_][A-Za-z0-9_]*[ \t\n]*;/)) {
      s = pos + RSTART - 1
      if (s == 1 || !ident(substr(masked, s - 1, 1)))
        report(line_of(s), "files listed in " allowlist " may not declare out-of-line modules")
      pos = s + RLENGTH
    }
  }
  n = split(masked, lines, "\n")
  for (q = 1; q <= n; q++) {
    if (!in_sys && lines[q] ~ /(^|[^A-Za-z0-9_])unsafe_code([^A-Za-z0-9_]|$)/)
      report(q, "mentions unsafe_code outside a lint attribute")
    if (lines[q] ~ /(^|[^A-Za-z0-9_])clippy[ \t]*::[ \t]*(all|style)([^A-Za-z0-9_]|$)/)
      report(q, "mentions clippy::all or clippy::style outside a lint attribute")
    if (!allowlisted && lines[q] ~ /(^|[^A-Za-z0-9_])disallowed_methods?([^A-Za-z0-9_]|$)/)
      report(q, "mentions disallowed_methods outside a lint attribute")
    if (lines[q] ~ /(^|[^A-Za-z0-9_])include([^A-Za-z0-9_]|$)/)
      report(q, "include! compiles a file this check does not read")
  }
}
'
while IFS= read -r file; do
  in_sys=0
  case "$file" in
    crates/envcloak-sys/*) in_sys=1 ;;
  esac
  listed=0
  if printf '%s\n' "$allowed" | grep -qxF "$file"; then
    listed=1
  fi
  while IFS= read -r msg; do
    fail "$file:$msg"
  done < <(LC_ALL=C awk -v in_sys="$in_sys" -v allowlisted="$listed" -v allowlist="$allowlist" \
    "$rust_lints_awk" "$file")
done < <(rust_files)

if [ "$status" -eq 0 ]; then
  echo "check-unsafe: ok"
fi
exit "$status"
