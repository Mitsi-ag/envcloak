#!/usr/bin/env bash
# The lane-C Swift rules for apps/macos (M3 plan §5; docs/APP.md). The
# rules, what each guesses from the text and its limits are documented in
# scripts/macos/check_swift.py, which this runs.
#
# Usage: scripts/macos/check-swift.sh [--root DIR]
#        scripts/macos/check-swift.sh --list-swift [--root DIR]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$here/check_swift.py" "$@"
