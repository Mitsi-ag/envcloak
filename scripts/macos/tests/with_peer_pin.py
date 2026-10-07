"""Compile a fixture certificate pin, then restore the source even on failure.

The pin is a literal in the one reviewed source file, so the reservation and
source checkers see exactly what is compiled. No environment value reaches a
production requirement. Use only in a checkout with no concurrent build.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PINS = ROOT / "crates/envcloak-sys/src/peer_code/pins.rs"


def run(fixtures, command):
    identity = json.loads((fixtures / "identities.json").read_text())[0]
    fingerprint = identity["sha1"]
    if len(fingerprint) != 40 or any(c not in "0123456789abcdef" for c in fingerprint):
        raise ValueError("invalid fixture fingerprint")
    original = PINS.read_bytes()
    marker = b"const CI_CERT_SHA1: Option<&str> = None;"
    if original.count(marker) != 1:
        raise ValueError("fixture pin slot is not empty")
    configured = original.replace(marker, f'const CI_CERT_SHA1: Option<&str> = Some("{fingerprint}");'.encode())
    (fixtures / "pins-source-sha256").write_text(hashlib.sha256(configured).hexdigest() + "\n")
    # SIGKILL cannot be handled; keep the original next to the test fixtures for
    # that recovery case. An already occupied pin slot always refuses a new run.
    (fixtures / "pins-original.rs").write_bytes(original)
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    for sig in [signal.SIGTERM, signal.SIGHUP, signal.SIGINT]:
        signal.signal(sig, interrupted)
    child = None
    try:
        PINS.write_bytes(configured)
        allowed = ["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR",
                   "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "RUSTFLAGS", "DEVELOPER_DIR",
                   "ENVCLOAK_PEER_FIXTURES", "ENVCLOAK_IDENTITY_PROBE", "ENVCLOAK_CLI_PROBE"]
        environment = {name: os.environ[name] for name in allowed if name in os.environ}
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
        PINS.write_bytes(original)


if __name__ == "__main__":
    sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:]))
