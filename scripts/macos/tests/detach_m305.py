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
cache = pathlib.Path('/Volumes/KeenShiftDev/tmp/envcloak-target/D')
name = sys.argv[1]
command = pathlib.Path(sys.argv[2]).resolve()
if not name.replace('-', '').replace('_', '').isalnum() or command.parent != cache:
    raise SystemExit('invalid check name or command path')
fixture = pathlib.Path(tempfile.mkdtemp(prefix='ec05-', dir='/tmp'))
for folder in ('tmp', 'config', 'data', 'state', 'run', 'cache'):
    (fixture / folder).mkdir(mode=0o700)
env = {'HOME': str(fixture), 'TMPDIR': str(fixture / 'tmp') + '/',
       'PATH': '/Users/mitsi/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CARGO_HOME': '/Users/mitsi/.cargo', 'RUSTUP_HOME': '/Users/mitsi/.rustup',
       'CARGO_TARGET_DIR': str(cache), 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '3',
       'LANG': 'en_US.UTF-8'}
for suffix, folder in [('CONFIG', 'config'), ('DATA', 'data'), ('STATE', 'state'), ('RUNTIME', 'run'), ('CACHE', 'cache')]:
    env['XDG_' + suffix + '_HOME' if suffix != 'RUNTIME' else 'XDG_RUNTIME_DIR'] = str(fixture / folder)
if os.fork():
    os.wait()
    print(name + ': detached; fixture=' + str(fixture))
    raise SystemExit(0)
os.setsid()
if os.fork():
    os._exit(0)
os.chdir(root)
stdin = os.open('/dev/null', os.O_RDONLY)
log = os.open(cache / (name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.dup2(stdin, 0)
os.dup2(log, 1)
os.dup2(log, 2)
os.close(stdin)
os.close(log)
# The shell writes a receipt after all descendants have returned.
os.execve('/bin/bash', ['bash', '-c', 'bash "$1"; rc=$?; echo "$rc" > "$2"; exit "$rc"', 'check', str(command), str(cache / (name + '.exit'))], env)
