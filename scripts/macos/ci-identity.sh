#!/bin/bash
# Creates only a disposable fixture identity; never selects a default keychain.
set -euo pipefail
exec /usr/bin/python3 "$(dirname "$0")/tests/peer_identity.py" "$@"
