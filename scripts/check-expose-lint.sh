#!/usr/bin/env bash
# Proves that clippy.toml's disallowed-methods entry catches secret exposure:
# runs clippy on security/lint-canary, which opens secrets in every way it
# can, and checks that each call site marked EXPECT-DISALLOWED is reported.
# A wrong path in clippy.toml, or a clippy change in how trait methods are
# matched, makes this fail instead of silently allowing every call.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
canary="$root/security/lint-canary"

json="$(cargo clippy --quiet --locked \
  --manifest-path "$canary/Cargo.toml" \
  --target-dir "$root/target/lint-canary" \
  --message-format=json 2>/dev/null || true)"

expected="$(grep -c '// EXPECT-DISALLOWED$' "$canary/src/lib.rs")"
got="$(printf '%s\n' "$json" | grep -o '"code":"clippy::disallowed_methods"' | wc -l | tr -d '[:space:]')"

if [ "$got" -ne "$expected" ]; then
  echo "check-expose-lint: expected $expected disallowed_methods reports, got $got" >&2
  cargo clippy --locked --manifest-path "$canary/Cargo.toml" --target-dir "$root/target/lint-canary" >&2 || true
  exit 1
fi
echo "check-expose-lint: ok ($got of $expected call sites reported)"
