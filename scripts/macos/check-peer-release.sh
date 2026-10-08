#!/bin/bash
# A testing-feature release must fail specifically at the feature guard.
set -euo pipefail
cd "$(dirname "$0")/../.."
. scripts/macos/cargo-target.sh
target=$(cargo_target_dir)
mkdir -p "$target"
log=$(mktemp "$target/peer-release.XXXXXX")
# The native harness supplies a test pin to its builds, never to this control.
unset ENVCLOAK_TEST_CERT_SHA1
cargo check --locked --release -p envcloak-sys
for assertions in false true; do
  if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=$assertions \
    cargo check --locked --release -p envcloak-sys --features testing >"$log" 2>&1; then
    echo 'peer release: FAILED (testing feature compiled in release)' >&2
    exit 1
  fi
  if ! grep -F -q 'EnvCloak testing features must not be compiled into release artifacts' "$log"; then
    echo 'peer release: FAILED (unrelated compiler error)' >&2
    exit 1
  fi
done
echo 'peer release: testing feature refused; normal release passed'
