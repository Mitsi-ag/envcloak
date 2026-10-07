#!/usr/bin/env bash
# Caller uses a detached, isolated /tmp/ec05- HOME (detach_m305.py locally).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
: "${CARGO_TARGET_DIR:?use the lane cache}"
cargo build --locked -p envcloak -p envcloakd
python3 scripts/macos/tests/workspace_fixture.py
