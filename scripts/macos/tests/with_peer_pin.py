"""Pass a public fixture certificate to the build script without editing source.

Cargo fingerprints the build-time input. Other builds neither inherit it nor
reuse its outputs, even if this runner is killed before its children finish.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


def run(fixtures, command):
    identity = json.loads((fixtures / "identities.json").read_text())[0]
    fingerprint = identity["sha1"]
    if len(fingerprint) != 40 or any(c not in "0123456789abcdef" for c in fingerprint):
        raise ValueError("invalid fixture fingerprint")
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    for sig in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
        signal.signal(sig, interrupted)
    child = None
    try:
        allowed = ["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR",
                   "RUSTC_WRAPPER", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "RUSTFLAGS", "DEVELOPER_DIR",
                   "ENVCLOAK_PEER_FIXTURES", "ENVCLOAK_IDENTITY_PROBE", "ENVCLOAK_CLI_PROBE"]
        environment = {name: os.environ[name] for name in allowed if name in os.environ}
        environment["ENVCLOAK_TEST_CERT_SHA1"] = fingerprint
        child = subprocess.Popen(command, cwd=ROOT, env=environment, start_new_session=True)
        return child.wait()
    finally:
        if child is not None and child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


if __name__ == "__main__":
    sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:]))
