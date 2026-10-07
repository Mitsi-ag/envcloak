#!/bin/bash
# Native M3-07 gates. Run outside any recognized agent's ancestry.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $(uname -s) != Darwin ]]; then
  echo 'peer code: skipped (requires macOS)' >&2
  exit 0
fi
target="${CARGO_TARGET_DIR:-$PWD/target}"
mkdir -p "$target"
target=$(cd "$target" && pwd)
fixtures=$(mktemp -d "$target/peer-signing.XXXXXX")
# The test identities and synthetic private keys stay in this owned target tree.
# No production identity or credential is selected, and no trust entry is added.
scripts/macos/ci-identity.sh "$fixtures"
export ENVCLOAK_PEER_FIXTURES="$fixtures"
export ENVCLOAK_IDENTITY_PROBE="$target/debug/examples/identity_probe"
export ENVCLOAK_CLI_PROBE="$target/debug/envcloak"
exec /usr/bin/python3 scripts/macos/tests/with_peer_pin.py "$fixtures" \
  /bin/bash scripts/macos/tests/run_peer_gates.sh
