#!/bin/sh
# Pinned source builds, no install needed: PHP 8.4.5 CLI and CPython 3.14.0
# configured with --with-pydebug. The test prints each runtime's SHA-256.
set -eu
: "${ENVCLOAK_PHP_ORACLE:?absolute path to PHP 8.4.5 CLI required}"
: "${ENVCLOAK_PYTHON_DEBUG_ORACLE:?absolute path to debug CPython 3.14.0 required}"
: "${ENVCLOAK_NPM_ORACLE:?absolute path to npm 11.19.0 required}"
exec python3 -B scripts/check-managed-oracles.py
