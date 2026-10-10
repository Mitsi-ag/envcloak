#!/bin/bash
set -euo pipefail
cargo build --locked -p envcloak --features envcloak-sys/testing
cargo build --locked -p envcloak-ipc --example identity_probe --features envcloak-sys/testing
for probe in "$ENVCLOAK_CLI_PROBE" "$ENVCLOAK_IDENTITY_PROBE"; do
  if [ ! -x "$probe" ]; then
    echo "peer code: FAILED (probe binary missing after Cargo build: $probe)" >&2
    exit 1
  fi
done
cargo test --locked -p envcloakd -p envcloak-ipc --test app_peer --test daemon_identity \
  --no-fail-fast -- --ignored --test-threads 3
scripts/macos/check-peer-release.sh
