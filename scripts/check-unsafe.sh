#!/usr/bin/env bash
# Enforces the unsafe-code and secret-exposure boundaries (SPEC §5, "Memory
# hygiene" and "Process hardening"):
#
# 1. The workspace denies `unsafe_code`, every package in the tree inherits
#    the workspace lints, and the workspace lint tables keep `warnings`,
#    `clippy::all`, `clippy::style` and `clippy::disallowed_methods` at warn
#    or above. No cargo config in the tree sets rustflags.
# 2. Only crates/envcloak-sys may relax `unsafe_code`.
# 3. clippy.toml forbids secrecy's expose_secret methods, no other clippy
#    config can override it, and `disallowed_methods` may be allowed only in
#    files listed in security/expose-allowlist.txt (whose entries must exist).
#    Nothing may allow `warnings`, `clippy::all` or `clippy::style`, since
#    each of them silences `disallowed_methods` too.
#
# Rust files are read with comments and the contents of string and
# character literals removed, and lint attributes are matched as tokens, so
# neither a comment nor a string can satisfy or trip a check. Any other
# mention of `unsafe_code`, `disallowed_methods`, `clippy::all` or
# `clippy::style` (a macro building an attribute, say) fails. A file that
# ends inside a comment or literal fails too, rather than being skipped.
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

# 1. Workspace lint tables.
workspace_lints_awk='
function level_of(line, v) {
  if (match(line, /level[ \t]*=[ \t]*["\047][a-z]+["\047]/)) {
    v = substr(line, RSTART, RLENGTH)
    sub(/^level[ \t]*=[ \t]*/, "", v)
  } else {
    v = line
    sub(/^[^=]*=[ \t]*/, "", v)
  }
  if (match(v, /^["\047][a-z]+["\047]/)) return substr(v, 2, RLENGTH - 2)
  return "?"
}
function at_least_warn(lv) { return lv == "warn" || lv == "deny" || lv == "forbid" }
/^[ \t]*\[/ {
  sect = $0
  sub(/#.*/, "", sect)
  gsub(/[ \t]/, "", sect)
  if (sect ~ /^\[workspace\.lints\./ && sect != "[workspace.lints.rust]" &&
      sect != "[workspace.lints.clippy]" && sect != "[workspace.lints.rustdoc]") {
    print sect ": workspace lints may only be set in [workspace.lints.rust], [workspace.lints.clippy] and [workspace.lints.rustdoc]"
  }
  next
}
/^[ \t]*(#|$)/ { next }
{
  key = $0
  sub(/[ \t]*=.*/, "", key)
  gsub(/[ \t"\047]/, "", key)
  gsub(/-/, "_", key)
}
sect == "[workspace.lints]" {
  print "[workspace.lints]: set lints in the [workspace.lints.rust] and [workspace.lints.clippy] tables"
}
sect == "[workspace]" && key ~ /^lints(\.|$)/ {
  print "[workspace]: set lints in the [workspace.lints.rust] and [workspace.lints.clippy] tables"
}
sect == "[workspace.lints.rust]" && key == "unsafe_code" {
  lv = level_of($0)
  if (lv == "deny" || lv == "forbid") found = 1
}
sect == "[workspace.lints.rust]" && key == "warnings" && !at_least_warn(level_of($0)) {
  print "[workspace.lints.rust] warnings must stay at warn or above"
}
sect == "[workspace.lints.rust]" && key ~ /\./ {
  print "[workspace.lints.rust] " key ": use one key per lint"
}
sect == "[workspace.lints.clippy]" && key ~ /\./ {
  print "[workspace.lints.clippy] " key ": use one key per lint"
}
sect == "[workspace.lints.clippy]" && (key == "all" || key == "style" || key == "disallowed_methods" || key == "disallowed_method") && !at_least_warn(level_of($0)) {
  print "[workspace.lints.clippy] " key " must stay at warn or above (it covers disallowed_methods)"
}
END {
  if (!found) print "[workspace.lints.rust] must set unsafe_code = \"deny\""
}
'
while IFS= read -r msg; do
  fail "Cargo.toml: $msg"
done < <(LC_ALL=C awk "$workspace_lints_awk" Cargo.toml)

# Every package in the tree inherits the workspace lints.
while IFS= read -r manifest; do
  if ! awk '
    /^\[/ { in_lints = ($0 == "[lints]") }
    in_lints && /^[ \t]*workspace[ \t]*=[ \t]*true/ { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$manifest"; then
    fail "$manifest: needs [lints] workspace = true, or the unsafe_code deny does not apply"
  fi
  if grep -nE "${b}unsafe_code${e}" "$manifest" >/dev/null; then
    fail "$manifest: must not configure unsafe_code"
  fi
  if grep -nE "${b}disallowed_methods?${e}" "$manifest" >/dev/null; then
    fail "$manifest: must not configure disallowed_methods"
  fi
done < <(all_files | grep -E '(^|/)Cargo\.toml$' | grep -vxF Cargo.toml || true)

# Rustflags can turn any lint off for every crate.
while IFS= read -r config; do
  if grep -qiE 'rustflags|cap-lints' "$config"; then
    fail "$config: must not set rustflags (they can turn lints off)"
  fi
done < <(all_files | grep -E '(^|/)\.cargo/config(\.toml)?$' || true)

# 3a. Clippy configuration and the allowlist.
for path in "secrecy::ExposeSecret::expose_secret" "secrecy::ExposeSecretMut::expose_secret_mut"; do
  if ! grep -qF "\"$path\"" clippy.toml 2>/dev/null; then
    fail "clippy.toml: disallowed-methods must list $path"
  fi
done

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

# 2 and 3b. Lint attributes in Rust source. Prints "LINE: problem" lines.
rust_lints_awk='
function ident(ch) { return ch ~ /[A-Za-z0-9_]/ }
function high(ch) { return ch > "\177" }
function blank(s, t) { t = s; gsub(/[^\n]/, " ", t); return t }
function line_of(pos, t) { t = substr(text, 1, pos); return gsub(/\n/, "", t) + 1 }
function report(ln, msg) { print ln ": " msg }
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
  n = split(masked, lines, "\n")
  for (q = 1; q <= n; q++) {
    if (!in_sys && lines[q] ~ /(^|[^A-Za-z0-9_])unsafe_code([^A-Za-z0-9_]|$)/)
      report(q, "mentions unsafe_code outside a lint attribute")
    if (lines[q] ~ /(^|[^A-Za-z0-9_])clippy[ \t]*::[ \t]*(all|style)([^A-Za-z0-9_]|$)/)
      report(q, "mentions clippy::all or clippy::style outside a lint attribute")
    if (!allowlisted && lines[q] ~ /(^|[^A-Za-z0-9_])disallowed_methods?([^A-Za-z0-9_]|$)/)
      report(q, "mentions disallowed_methods outside a lint attribute")
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
