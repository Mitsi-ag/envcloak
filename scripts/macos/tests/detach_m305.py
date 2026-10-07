#!/usr/bin/env python3
"""Run a lane check without agent ancestry, in an isolated short HOME.

Receipts and command files live in the lane's target directory. The caller
keeps the private temporary fixtures for inspection; this runner deletes none.
"""
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[3]
name = sys.argv[1]
command = pathlib.Path(sys.argv[2]).resolve()
cache = command.parent
cargo_home = pathlib.Path(os.environ.get('CARGO_HOME', str(pathlib.Path.home() / '.cargo')))
rustup_home = pathlib.Path(os.environ.get('RUSTUP_HOME', str(pathlib.Path.home() / '.rustup')))
if not name.replace('-', '').replace('_', '').isalnum() or not command.is_file():
    raise SystemExit('invalid check name or command path')
if (cache / (name + '.exit')).exists():
    raise SystemExit('check name already has a receipt; use a new name')
# Reserve the name before detaching, so a collision fails the caller and
# cannot be mistaken for a new run's successful old receipt.
log = os.open(cache / (name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
fixture = pathlib.Path(tempfile.mkdtemp(prefix='ec05-', dir='/tmp'))
for folder in ('tmp', 'config', 'data', 'state', 'run', 'cache'):
    (fixture / folder).mkdir(mode=0o700)
env = {'HOME': str(fixture), 'TMPDIR': str(fixture / 'tmp') + '/',
       'PATH': str(pathlib.Path.home() / '.cargo/bin') + ':' + str(cargo_home / 'bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CARGO_HOME': str(cargo_home), 'RUSTUP_HOME': str(rustup_home),
       'CARGO_TARGET_DIR': str(cache), 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '3',
       'LANG': 'en_US.UTF-8'}
for suffix, folder in [('CONFIG', 'config'), ('DATA', 'data'), ('STATE', 'state'), ('RUNTIME', 'run'), ('CACHE', 'cache')]:
    env['XDG_' + suffix + '_HOME' if suffix != 'RUNTIME' else 'XDG_RUNTIME_DIR'] = str(fixture / folder)
if os.fork():
    os.wait()
    os.close(log)
    print(name + ': detached; fixture=' + str(fixture))
    raise SystemExit(0)
os.setsid()
if os.fork():
    os._exit(0)
os.chdir(root)
stdin = os.open('/dev/null', os.O_RDONLY)
os.dup2(stdin, 0)
os.dup2(log, 1)
os.dup2(log, 2)
os.close(stdin)
os.close(log)
# The shell writes a receipt after all descendants have returned.
os.execve('/bin/bash', ['bash', '-c', 'bash "$1"; rc=$?; echo "$rc" > "$2"; exit "$rc"', 'check', str(command), str(cache / (name + '.exit'))], env)
