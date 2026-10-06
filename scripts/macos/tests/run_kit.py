#!/usr/bin/env python3
"""Run the Swift suite beside this tree's daemon in the caller's private HOME.

No approval or unlock is submitted. Readiness is the daemon's listening
record, not a sleep. The child is terminated and reaped on every path.
"""
import os
import pathlib
import selectors
import subprocess
import sys
import time


def main():
    home = pathlib.Path(os.environ["HOME"])
    if not str(home).startswith("/tmp/") or not home.is_dir() or home.stat().st_mode & 0o077:
        raise RuntimeError("test-kit requires a private HOME below a short /tmp path")
    runtime = home / "Library/Application Support/EnvCloak/run"
    if runtime.exists():
        raise RuntimeError("test-kit requires a fresh HOME")
    env = {key: os.environ[key] for key in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME")}
    env.update(PATH="/usr/bin:/bin", LANG="en_US.UTF-8")
    with subprocess.Popen([sys.argv[1], "--foreground"], env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as daemon:
        try:
            selector = selectors.DefaultSelector()
            selector.register(daemon.stderr, selectors.EVENT_READ)
            received = b""
            deadline = time.monotonic() + 10
            while b"envcloakd: listening on " not in received:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise RuntimeError("fixture daemon did not become ready")
                part = os.read(daemon.stderr.fileno(), 4096)
                if not part or len(received) + len(part) > 16384:
                    raise RuntimeError("fixture daemon readiness failed")
                received += part
            selector.close()
            # This suite has only a few read/lock calls, far below pipe capacity.
            child_env = dict(os.environ, ENVCLOAK_TEST_RUNTIME=str(runtime))
            return subprocess.run(sys.argv[2:], env=child_env, stdin=subprocess.DEVNULL).returncode
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()


if __name__ == "__main__":
    sys.exit(main())
