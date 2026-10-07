#!/usr/bin/env python3
"""Keep EU-0 wire registration and detached test isolation reviewable."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkspaceContracts(unittest.TestCase):
    def test_long_item_last_use_has_a_field_reservation(self):
        blocks = re.findall(r'<!-- reservations:field -->\n(.*?)<!-- /reservations -->',
                            (ROOT / 'docs/IPC.md').read_text(), re.S)
        for method in ['items.list', 'items.show']:
            with self.subTest(method=method):
                rows = [line for block in blocks for line in block.splitlines()
                        if line.startswith('| `' + method + '` | `last_used_secs` |')]
                self.assertEqual(len(rows), 1, method + ' last_used_secs needs exactly one field reservation')
                self.assertIn('| M3-05 | reserved |', rows[0])
                self.assertIn('no code reader', rows[0])


    def test_detached_commands_receive_only_allowlisted_environment(self):
        cache = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'target')))
        cache.mkdir(parents=True, exist_ok=True)
        # Keep the fixtures: lane runs must not delete their /tmp HOME paths.
        fixture = Path(tempfile.mkdtemp(prefix='runner-contract-', dir=cache))
        command = fixture / 'command.sh'
        command.write_text("python3 - <<'PROBE'\nimport json, os\nprint(json.dumps({'names': sorted(os.environ), 'path': os.environ['PATH']}))\nPROBE\n")
        # This synthetic inherited variable is the positive control. No real
        # inherited variables are copied into the process that runs the probe.
        environment = {'HOME': os.environ['HOME'], 'PATH': '/usr/bin:/bin',
                       'CARGO_HOME': str(fixture / 'cargo-cache'),
                       'ENVCLOAK_FIXTURE_INHERITED': 'fixture-only'}
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/macos/tests/detach_m305.py'),
                                 'environment', str(command)], env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        receipt = fixture / 'environment.exit'
        deadline = time.monotonic() + 15
        while not receipt.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(receipt.exists(), 'detached command did not finish within its deadline')
        self.assertEqual(receipt.read_text().strip(), '0')
        report = json.loads((fixture / 'environment.log').read_text())
        names = set(report['names'])
        self.assertIn(str(Path(environment['HOME']) / '.cargo/bin'), report['path'].split(':'))
        self.assertIn(str(fixture / 'cargo-cache/bin'), report['path'].split(':'))
        required = {'HOME', 'TMPDIR', 'PATH', 'LANG', 'CARGO_HOME', 'RUSTUP_HOME',
                    'CARGO_TARGET_DIR', 'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS',
                    'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME',
                    'XDG_RUNTIME_DIR', 'XDG_CACHE_HOME'}
        self.assertTrue(required <= names)
        self.assertEqual(names - required - {'PWD', 'SHLVL', '_', 'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}, set())
        self.assertNotIn('ENVCLOAK_FIXTURE_INHERITED', names)


if __name__ == '__main__':
    unittest.main(verbosity=2)
