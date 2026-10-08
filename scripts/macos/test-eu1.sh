#!/usr/bin/env bash
# Use the detached isolated runner locally; run_workspace.py --eu1 in CI.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
: "${CARGO_TARGET_DIR:?use the lane cache}"
cargo build --locked -p envcloak -p envcloakd
python3 scripts/macos/tests/workspace_fixture.py --eu1 "$@"
