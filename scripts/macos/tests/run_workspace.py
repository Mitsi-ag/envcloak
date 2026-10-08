#!/usr/bin/env python3
"""CI entry point for the real-daemon UI story, with a private short HOME."""
import os
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
fixture = pathlib.Path(tempfile.mkdtemp(prefix='ec05-', dir='/tmp'))
for directory in ('tmp', 'config', 'data', 'state', 'run', 'cache'):
    (fixture / directory).mkdir(mode=0o700)
original_home = pathlib.Path.home()
env = {'HOME': str(fixture), 'TMPDIR': str(fixture / 'tmp') + '/',
       'PATH': os.environ['PATH'], 'LANG': 'en_US.UTF-8',
       'CARGO_HOME': os.environ.get('CARGO_HOME', str(original_home / '.cargo')),
       'RUSTUP_HOME': os.environ.get('RUSTUP_HOME', str(original_home / '.rustup')),
       'CARGO_TARGET_DIR': os.environ.get('CARGO_TARGET_DIR', str(root / 'target')),
       'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '3'}
for suffix, folder in [('CONFIG', 'config'), ('DATA', 'data'), ('STATE', 'state'), ('RUNTIME', 'run'), ('CACHE', 'cache')]:
    env['XDG_' + suffix + '_HOME' if suffix != 'RUNTIME' else 'XDG_RUNTIME_DIR'] = str(fixture / folder)
if 'DEVELOPER_DIR' in os.environ:
    env['DEVELOPER_DIR'] = os.environ['DEVELOPER_DIR']
# Keep fixtures for diagnosis. The harness contains generated values only.
command = [str(root / ('scripts/macos/test-eu1.sh' if '--eu1' in sys.argv else 'scripts/macos/test-workspace.sh'))]
if '--eu1' in sys.argv and '--package' in sys.argv:
    command.append('--package')
result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL)
sys.exit(result.returncode)
