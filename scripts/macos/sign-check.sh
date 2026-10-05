#!/usr/bin/env bash
# Checks a built EnvCloak.app: exactly three executables, each signed with
# its own identifier and the hardened runtime and none with get-task-allow
# or a hardened-runtime exception, the bundle verifying whole, no side door
# in any Info.plist, the LaunchAgent layout, one set of architectures
# (SPEC §12, M3 plan D3-05 and D3-06, gate 19 for the bundle). The rules
# and their reasons are in scripts/macos/sign_check.py, which this runs.
#
# Usage: scripts/macos/sign-check.sh [--facts] path/to/EnvCloak.app
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$here/sign_check.py" "$@"
