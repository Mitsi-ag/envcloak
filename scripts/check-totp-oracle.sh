#!/usr/bin/env bash
# Run both independent implementations and check the committed fixture bytes.
set -euo pipefail
cd "$(dirname "$0")/.."
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ec-otp.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
env -i PATH="$PATH" HOME="$scratch" TMPDIR="$scratch" \
  XDG_CONFIG_HOME="$scratch" XDG_DATA_HOME="$scratch" \
  XDG_CACHE_HOME="$scratch" XDG_STATE_HOME="$scratch" LC_ALL=C \
  python3 -I -B crates/envcloak-signin/tests/oracles/totp_oracle.py
