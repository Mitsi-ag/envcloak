#!/bin/bash
set -euo pipefail
cargo build --locked -p envcloak --features envcloak-sys/testing
cargo build --locked -p envcloak-ipc --example identity_probe --features envcloak-sys/testing
cargo test --locked -p envcloakd -p envcloak-ipc --test app_peer --test daemon_identity \
  --no-fail-fast -- --ignored --test-threads 3
scripts/macos/check-peer-release.sh
