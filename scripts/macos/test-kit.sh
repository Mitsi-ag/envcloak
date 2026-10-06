#!/usr/bin/env bash
# Run under an isolated HOME/TMPDIR, detached from any agent ancestry.
# The caller owns the private fixture directory and build cache.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
: "${ENVCLOAK_SWIFT_VECTORS:?set an empty private fixture directory}"
: "${CARGO_TARGET_DIR:?set the lane build cache}"
python3 apps/macos/oracles/escape.py "$ENVCLOAK_SWIFT_VECTORS/escape.json"
cargo test --no-fail-fast -p envcloak-ipc --test vectors -- --test-threads 3
cargo build -p envcloakd
python3 scripts/macos/tests/run_kit.py "$CARGO_TARGET_DIR/debug/envcloakd" \
  swift test --package-path apps/macos/Packages/EnvCloakKit \
  --scratch-path "$CARGO_TARGET_DIR/swift" --jobs 3 -Xswiftc -warnings-as-errors
# Keep the test-only observer under optimization too. The release library
# excludes it entirely, while these probes exercise optimized buffer code.
swift test --package-path apps/macos/Packages/EnvCloakKit \
  --scratch-path "$CARGO_TARGET_DIR/swift-optimized" --jobs 3 \
  -Xswiftc -warnings-as-errors -Xswiftc -O --filter WireTests/testGate11
