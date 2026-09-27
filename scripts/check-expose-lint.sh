#!/usr/bin/env bash
# Proves that clippy.toml's disallowed-methods entry catches secret exposure
# in workspace crates: runs clippy on security/lint-canary, a workspace
# member that inherits the workspace lint levels and opens secrets in every
# way it can, and checks that each call site marked EXPECT-DISALLOWED is
# reported. A wrong path in clippy.toml, a workspace lint table that turns
# the lint off, or a clippy change in how trait methods are matched makes
# this fail instead of silently allowing every call.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
canary="$root/security/lint-canary"
cd "$root"

json="$(RUSTFLAGS="${RUSTFLAGS:-} --cfg envcloak_lint_canary" cargo clippy --quiet --locked \
  -p envcloak-lint-canary \
  --target-dir "$root/target/lint-canary" \
  --message-format=json 2>/dev/null || true)"

expected="$(grep -c '// EXPECT-DISALLOWED$' "$canary/src/lib.rs")"
got="$({ printf '%s\n' "$json" | grep -o '"code":"clippy::disallowed_methods"' || true; } | wc -l | tr -d '[:space:]')"

if [ "$expected" -eq 0 ] || [ "$got" -ne "$expected" ]; then
  echo "check-expose-lint: expected $expected disallowed_methods reports, got $got" >&2
  RUSTFLAGS="${RUSTFLAGS:-} --cfg envcloak_lint_canary" cargo clippy --locked \
    -p envcloak-lint-canary --target-dir "$root/target/lint-canary" >&2 || true
  exit 1
fi
echo "check-expose-lint: ok ($got of $expected call sites reported)"
