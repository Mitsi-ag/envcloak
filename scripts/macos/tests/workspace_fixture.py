#!/usr/bin/env python3
"""Real CLI/daemon fixture for EU-0 UI tests; only generated values.

Runs under test-workspace.sh's detached private HOME. Owns and reaps the
background process. Proofs come from this fixture's controlling terminal.
"""
import base64
import fcntl
import json
import os
import pathlib
import pty
import selectors
import signal
import socket
import struct
import subprocess
import sys
import termios
import time


def main():
    home = pathlib.Path(os.environ['HOME'])
    if not str(home).startswith('/tmp/ec05-') or home.stat().st_mode & 0o077:
        raise RuntimeError('private fixture HOME required')
    cache = pathlib.Path(os.environ['CARGO_TARGET_DIR'])
    daemon_bin, cli = cache / 'debug/envcloakd', cache / 'debug/envcloak'
    runtime = home / 'Library/Application Support/EnvCloak/run'
    project = home / 'workspace-fixture'
    project.mkdir(mode=0o700)
    (home / 'selected-alias').symlink_to(project, target_is_directory=True)
    manifest = project / 'envcloak.toml'
    manifest.write_text('[project]\nname = "Workspace fixture"\n[env]\nVARIABLE = "fixture"\n')
    # This process is not a group leader under the detached check shell.
    os.setsid()
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    env = {k: os.environ[k] for k in ('HOME', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR', 'XDG_CACHE_HOME')}
    env.update(PATH='/usr/bin:/bin', LANG='en_US.UTF-8')
    phrase = base64.b64encode(os.urandom(48))
    def invoke(args, with_phrase=False, kit=False):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, phrase + b'\n'); os.close(write_fd)
        null_fd = os.open('/dev/null', os.O_WRONLY)
        try:
            flags = (['--passphrase-fd', str(read_fd)] if with_phrase else []) + (['--kit-fd', str(null_fd)] if kit else [])
            result = subprocess.run([str(cli)] + args + flags, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(read_fd, null_fd), timeout=60)
            if result.returncode:
                raise RuntimeError('fixture CLI failed: ' + args[0] + ', exit ' + str(result.returncode))
        finally:
            os.close(read_fd); os.close(null_fd)
    serial = 0
    def rpc(method, params=None):
        nonlocal serial
        serial += 1
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(15); client.connect(str(runtime / 'envcloakd.sock'))
            raw = json.dumps(dict(jsonrpc='2.0', id=serial, method=method, params=params or {})).encode()
            client.sendall(struct.pack('>I', len(raw)) + raw)
            def take(n):
                data = bytearray()
                while len(data) < n:
                    part = client.recv(n - len(data))
                    if not part: raise RuntimeError('fixture RPC ended early')
                    data.extend(part)
                return data
            length = struct.unpack('>I', take(4))[0]
            if not 0 < length <= 1048576: raise RuntimeError('invalid RPC frame')
            result = json.loads(take(length))
            if 'error' in result:
                raise RuntimeError('fixture RPC refused: ' + method + ' ' + str(result['error']['code']))
            return result['result']
    with subprocess.Popen([str(daemon_bin), '--foreground'], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as daemon:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(daemon.stderr, selectors.EVENT_READ)
                received = b''; deadline = time.monotonic() + 15
                while b'envcloakd: listening on ' not in received:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining): raise RuntimeError('daemon not ready')
                    part = os.read(daemon.stderr.fileno(), 4096)
                    if not part or len(received) + len(part) > 16384: raise RuntimeError('daemon readiness failed')
                    received += part
            invoke(['vault', 'create', '--kdf-memory', '64MiB'], with_phrase=True, kit=True)
            if rpc('status')['vault']['state'] == 'locked': invoke(['unlock'], with_phrase=True)
            # WireSecret decodes base64. Generate an ASCII value first so
            # the decoded value cannot randomly contain a refused NUL.
            generated_value = base64.b64encode(os.urandom(48))
            rpc('items.add', dict(slug='fixture', value=base64.b64encode(generated_value).decode()))
            del generated_value
            params = dict(manifest=str(manifest), argv=['/usr/bin/true'])
            request = rpc('run.request', params)['decision']['request']
            invoke(['approve', request, '--for', '1h'], with_phrase=True)
            answer = rpc('run.request', params)
            if answer['decision']['decision'] != 'covered': raise RuntimeError('fixture delivery not covered')
            del answer
            if len(rpc('projects.list')['projects']) != 1: raise RuntimeError('project not adopted')
            if len(rpc('grants.list')['grants']) != 1: raise RuntimeError('positive grant control absent')
            (runtime / 'test-folders.json').write_text(json.dumps([str(home / 'selected-alias')]))
            command = ['xcodebuild', '-project', 'apps/macos/EnvCloak.xcodeproj', '-scheme', 'EnvCloakUITests', '-configuration', 'Debug', '-destination', 'platform=macOS,arch=arm64', '-derivedDataPath', str(cache / 'm305-ui'), '-jobs', '3', '-parallel-testing-enabled', 'NO', 'SWIFT_ACTIVE_COMPILATION_CONDITIONS=DEBUG ENVCLOAK_SCREEN_TESTS', 'SWIFT_SUPPRESS_WARNINGS=NO', 'SWIFT_TREAT_WARNINGS_AS_ERRORS=YES', 'CODE_SIGN_IDENTITY=-', 'test']
            test_env = dict(os.environ, TEST_RUNNER_ENVCLOAK_TEST_RUNTIME=str(runtime), TEST_RUNNER_ENVCLOAK_TEST_PROJECT=str(home / "selected-alias"))
            tested = subprocess.run(command, env=test_env, timeout=300)
            if tested.returncode: return tested.returncode
            if rpc('grants.list')['grants']: raise RuntimeError('UI revoke did not empty real grants.list')
            print('real daemon controls: adopted project=1, grant before=1, grant after=0', flush=True)
            subprocess.run(['scripts/check-sources.sh', '--swift', str(cache / 'm305-ui')], check=True, timeout=60)
            return 0
        finally:
            daemon.terminate()
            try: daemon.wait(timeout=5)
            except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
            # Closing our controlling PTY sends HUP to this session. The
            # tests are over; preserve their actual exit status on cleanup.
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            os.close(slave); os.close(master)


if __name__ == '__main__':
    sys.exit(main())
