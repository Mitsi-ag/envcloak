#!/usr/bin/env bash
# Enforces the unsafe-code and secret-exposure boundaries (SPEC §5, "Memory
# hygiene" and "Process hardening"):
#
# 1. The workspace denies `unsafe_code`, and every crate inherits the
#    workspace lints.
# 2. Only crates/envcloak-sys may relax `unsafe_code`. Any other mention of
#    the lint in Rust source fails, unless it is a `deny` or `forbid`.
# 3. clippy.toml forbids secrecy's expose_secret methods, no other clippy
#    config can override it, and `disallowed_methods` may be allowed only in
#    files listed in security/expose-allowlist.txt (whose entries must exist).
#    `clippy::all` and `clippy::style` cannot be allowed in source either,
#    since both contain `disallowed_methods`.
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

# 1. Workspace lint table and per-crate inheritance.
if ! awk '
  /^\[/ { in_rust = ($0 == "[workspace.lints.rust]") }
  in_rust && /^[ \t]*unsafe_code[ \t]*=[ \t]*"(deny|forbid)"/ { found = 1 }
  END { exit found ? 0 : 1 }
' Cargo.toml; then
  fail "Cargo.toml: [workspace.lints.rust] must set unsafe_code = \"deny\""
fi

for manifest in crates/*/Cargo.toml; do
  [ -e "$manifest" ] || continue
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
done

# 2. unsafe_code in Rust source outside envcloak-sys.
while IFS= read -r file; do
  case "$file" in
    crates/envcloak-sys/*) continue ;;
  esac
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    line="${hit#*:}"
    if printf '%s\n' "$line" | grep -qE "(deny|forbid)[[:space:]]*\([[:space:]]*unsafe_code[[:space:]]*\)"; then
      continue
    fi
    fail "$file:${hit%%:*}: unsafe_code may only be relaxed in crates/envcloak-sys"
  done < <(grep -nE "${b}unsafe_code${e}" "$file" || true)
done < <(rust_files)

# 3. Secret exposure: clippy config and the allowlist.
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

while IFS= read -r file; do
  if grep -qE "${b}disallowed_methods?${e}" "$file"; then
    if ! printf '%s\n' "$allowed" | grep -qxF "$file"; then
      fail "$file: allows disallowed_methods but is not listed in $allowlist"
    fi
  fi
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    line="${hit#*:}"
    if printf '%s\n' "$line" | grep -qE "(warn|deny|forbid)[[:space:]]*\([[:space:]]*clippy::(all|style)[[:space:]]*\)"; then
      continue
    fi
    fail "$file:${hit%%:*}: clippy::all and clippy::style may not be allowed (they include disallowed_methods)"
  done < <(grep -nE "clippy::(all|style)${e}" "$file" || true)
done < <(rust_files)

if [ "$status" -eq 0 ]; then
  echo "check-unsafe: ok"
fi
exit "$status"
