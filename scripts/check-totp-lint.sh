#!/usr/bin/env bash
# A real compile refusal for every SHA-1 canary, plus a check that its
# lint exception remains confined to the pure TOTP implementation.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, os, pathlib, re, subprocess

root = pathlib.Path.cwd()
for path in root.joinpath('crates').rglob('*.rs'):
    if path == root / 'crates/envcloak-signin/src/totp.rs':
        continue
    for attr in re.findall(r'#!?\[.*?\]', path.read_text(), re.S):
        if re.search(r'\b(?:allow|expect)\b', attr) and 'disallowed_types' in attr:
            raise SystemExit('check-totp-lint: exception outside totp.rs')

canary = root / 'crates/envcloak-signin/tests/sha1_canary.rs'
expected = {i for i,line in enumerate(canary.read_text().splitlines(), 1) if line.endswith('// EXPECT-SHA1-REFUSAL')}
env = dict(os.environ)
env['RUSTFLAGS'] = env.get('RUSTFLAGS', '') + ' --cfg envcloak_lint_canary'
try:
    result = subprocess.run(['cargo', 'clippy', '--locked', '-p', 'envcloak-signin', '--test', 'sha1_canary', '--message-format=json'], env=env, capture_output=True, text=True, timeout=600)
except (OSError, subprocess.TimeoutExpired):
    raise SystemExit('check-totp-lint: compiler unavailable') from None
observed = set()
for line in result.stdout.splitlines():
    try:
        row = json.loads(line)
    except ValueError:
        continue
    message = row.get('message') or {}
    if (message.get('code') or {}).get('code') not in ('clippy::disallowed_types', 'clippy::disallowed_methods'):
        continue
    for span in message.get('spans', []):
        if span.get('is_primary') and span.get('file_name', '').endswith('tests/sha1_canary.rs'):
            observed.add(span['line_start'])
if result.returncode == 0 or not expected or observed != expected:
    print(result.stderr)
    raise SystemExit(f'check-totp-lint: expected {len(expected)} refusal lines, got {len(observed)}')
print(f'check-totp-lint: ok ({len(observed)} SHA-1 uses refused outside totp.rs)')
PY
