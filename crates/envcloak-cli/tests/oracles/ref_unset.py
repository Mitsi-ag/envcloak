"""M3-04 independent CLI observer: Python TOML plus exact byte/inode hashes.

Follows cycle325's no-write oracle. Uses only the supplied isolated test home.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

binary, root = Path(sys.argv[1]), Path(sys.argv[2])
project = root / "project"
project.mkdir()
manifest = project / "envcloak.toml"


def run(*args):
    return subprocess.run([binary, "ref", *args], cwd=project, env=dict(os.environ),
                          capture_output=True, timeout=20)


def stamp():
    s = manifest.lstat()
    return s.st_ino, s.st_mode, s.st_mtime_ns, hashlib.sha256(manifest.read_bytes()).digest()


for newline in (b"\n", b"\r\n"):
    for profile in (None, "ci"):
        for spelling in (b"DROP = 'ordinary' # removed", b'"DROP" = { ref = "ordinary", field = "value" }',
                         b"DROP = '''ordinary'''", b'DROP = """ordinary"""'):
            line = spelling + newline
            header = b"# kept comment" + newline + b"[project]" + newline + b"name = 'fixture'" + newline
            env = b"[env]" + newline + b"KEEP = 'kept' # retained" + newline
            selected = b"[env.ci]" + newline
            policy = newline + b"[policy]" + newline + b"agents = 'deny' # retained" + newline
            before = header + env + (line if profile is None else b"") + selected + (line if profile else b"") + policy
            manifest.write_bytes(before)
            manifest.chmod(0o640)
            args = ["--unset", "DROP", "--json"] + (["--profile", profile] if profile else [])
            result = run(*args)
            assert result.returncode == 0, ("remove", profile, result.returncode)
            receipt = json.loads(result.stdout)
            expected_ref = "ordinary#value" if b"field" in spelling else "ordinary"
            assert receipt == {"profile": profile, "env_name": "DROP", "reference": expected_ref}
            assert manifest.read_bytes() == before.replace(line, b"", 1), "golden bytes"
            parsed = tomllib.loads(manifest.read_text())
            assert parsed["env"]["KEEP"] == "kept" and parsed["policy"]["agents"] == "deny"
            assert "DROP" not in (parsed["env"][profile] if profile else parsed["env"])
            assert manifest.stat().st_mode & 0o777 == 0o640
            old = stamp()
            again = run(*args)
            assert again.returncode == 1 and b"binding_absent" in again.stderr and not again.stdout
            assert stamp() == old and list(project.iterdir()) == [manifest]

for before, expected, profile in (
    (b"env.DROP = 'ordinary'\nenv.KEEP = 'kept'\n", b"env.KEEP = 'kept'\n", None),
    (b"[env]\nci.DROP = 'ordinary'\nci.KEEP = 'kept'\n", b"[env]\nci.KEEP = 'kept'\n", "ci"),
    (b"[env]\n# kept\nDROP = 'ordinary'", b"[env]\n# kept\n", None),
    (b"env = { DROP = 'ordinary', KEEP = 'kept' }\n", b"env = {  KEEP = 'kept' }\n", None),
    (b"env = { KEEP = 'kept', DROP = 'ordinary' }\n", b"env = { KEEP = 'kept'  }\n", None),
    (b"env = { DROP = 'ordinary' }\n", b"env = {  }\n", None),
):
    manifest.write_bytes(before)
    args = ["--unset", "DROP", "--json"] + (["--profile", profile] if profile else [])
    result = run(*args)
    assert result.returncode == 0, "alternate syntax"
    assert manifest.read_bytes() == expected, "alternate bytes"
    tomllib.loads(manifest.read_text())

for args in (("--unset", ""), ("--unset", "A=B"), ("--unset", "DROP", "A=b"),
             ("--unset", "DROP", "--unset", "KEEP"), ("--unset", "é"),
             ("--unset", "DROP\n"), ("--unset", "DROP", "--profile", "missing")):
    manifest.write_bytes(b"[env]\nDROP = 'ordinary'\n[policy]\nagents = 'deny'\n")
    old = stamp()
    result = run(*args)
    assert result.returncode != 0 and not result.stdout
    assert stamp() == old, "hostile/absent write"

target = project / "target"
manifest.rename(target)
manifest.symlink_to(target)
original = target.read_bytes()
result = run("--unset", "DROP", "--json")
assert result.returncode != 0 and manifest.is_symlink() and target.read_bytes() == original
print("M3-04 independent TOML/byte oracle passed")
