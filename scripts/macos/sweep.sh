#!/usr/bin/env bash
# Gate 12: stdin holds only the generated canary, never an argv value.
set -euo pipefail
exec python3 "$(dirname "$0")/sweep.py" "$@"
