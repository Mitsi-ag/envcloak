#!/usr/bin/env bash
# Enforces M4 plan decision D4-27 and task M4-06a (gate 11, s3, s4):
#   `envcloakd` never opens a network socket and never depends on `envcloak-poll`
#   or the HTTPS client stack (`ureq`, `rustls`, `ring`).
#
# Checks both default features and `--all-features` on `envcloakd`, and verifies
# as a positive control that `envcloak-poll`'s own normal dependency tree does
# contain `ureq`, `rustls`, `rustls-platform-verifier` and `ring`.
#
# Usage: scripts/check-daemon-tree.sh [workspace-root]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${1:-$here/..}" && pwd -P)"
cd "$root"

CARGO_BIN="${CARGO:-cargo}"

FORBIDDEN_IN_DAEMON=(
  "envcloak-poll"
  "ureq"
  "ureq-proto"
  "rustls"
  "rustls-platform-verifier"
  "rustls-webpki"
  "rustls-pki-types"
  "ring"
)

REQUIRED_IN_POLL=(
  "ureq"
  "rustls"
  "rustls-platform-verifier"
  "ring"
)

extract_crates() {
  # Strip tree drawing characters and extract package names before ` v<ver>`.
  sed -E 's/^[^a-zA-Z0-9_]*([a-zA-Z0-9_-]+) v[0-9].*/\1/' | sort -u
}

check_daemon_mode() {
  local label="$1"
  shift
  local tree_out
  tree_out="$("$CARGO_BIN" tree -p envcloakd -e normal,build "$@" --locked)"
  local crates
  crates="$(printf '%s\n' "$tree_out" | extract_crates)"

  for pkg in "${FORBIDDEN_IN_DAEMON[@]}"; do
    if printf '%s\n' "$crates" | grep -qx "$pkg"; then
      echo "check-daemon-tree: forbidden crate '$pkg' found in envcloakd ($label)" >&2
      exit 1
    fi
  done
}

check_daemon_mode "default features"
check_daemon_mode "all features" --all-features

poll_tree="$("$CARGO_BIN" tree -p envcloak-poll -e normal,build --locked)"
poll_crates="$(printf '%s\n' "$poll_tree" | extract_crates)"

for pkg in "${REQUIRED_IN_POLL[@]}"; do
  if ! printf '%s\n' "$poll_crates" | grep -qx "$pkg"; then
    echo "check-daemon-tree: positive control failed: '$pkg' missing from envcloak-poll tree" >&2
    exit 1
  fi
done

echo "check-daemon-tree: ok (envcloakd free of envcloak-poll, ureq, rustls, ring)"
