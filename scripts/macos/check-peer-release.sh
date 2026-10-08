#!/bin/bash
# A testing-feature release must fail specifically at the feature guard.
set -euo pipefail
cd "$(dirname "$0")/../.."
target="${CARGO_TARGET_DIR:-$PWD/target}"
log=$(mktemp "$target/peer-release.XXXXXX")
cargo check --locked --release -p envcloak-sys
if cargo check --locked --release -p envcloak-sys --features testing >"$log" 2>&1; then
  echo 'peer release: FAILED (testing feature compiled in release)' >&2
  exit 1
fi
if ! grep -F -q 'EnvCloak testing features must not be compiled into release artifacts' "$log"; then
  echo 'peer release: FAILED (unrelated compiler error)' >&2
  exit 1
fi
echo 'peer release: testing feature refused; normal release passed'
