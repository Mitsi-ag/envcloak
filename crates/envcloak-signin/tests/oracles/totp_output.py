"""Independent standard-library encodings and a silent-library output gate."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote_from_bytes

HERE = Path(__file__).resolve().parent
ENCODINGS = {"raw", "rust-debug", "hex", "HEX", "base64", "base64-unpadded",
             "base64url", "base64url-unpadded", "percent", "percent-all",
             "percent-lower", "json", "json-unicode"}


def representations(raw):
    return {
        "raw": raw,
        "rust-debug": str(list(raw)).encode(),
        "hex": raw.hex().encode(), "HEX": raw.hex().upper().encode(),
        "base64": base64.b64encode(raw),
        "base64-unpadded": base64.b64encode(raw).rstrip(b"="),
        "base64url": base64.urlsafe_b64encode(raw),
        "base64url-unpadded": base64.urlsafe_b64encode(raw).rstrip(b"="),
        "percent": quote_from_bytes(raw, safe="").encode(),
        "percent-all": "".join(f"%{b:02X}" for b in raw).encode(),
        "percent-lower": "".join(f"%{b:02x}" for b in raw).encode(),
        "json": json.dumps(raw.decode("latin1"), ensure_ascii=True)[1:-1].encode(),
        "json-unicode": "".join(f"\\u{b:04x}" for b in raw).encode(),
    }


def hits(output, forms):
    return sum(needle in output for name, needle in forms.items())


def main():
    rows = json.loads((HERE / "totp-cases.json").read_bytes())
    controls = 0
    # Independently produced representations, including the two previously
    # surviving Rust byte-list forms, must each trigger the detector.
    for field in ("seed", "base32", "expected_code"):
        forms = representations(bytes(rows[0][field]))
        assert set(forms) == ENCODINGS, "encoding coverage missing"
        for encoded in forms.values():
            assert hits(encoded, forms) > 0, "disclosure control missed"
            controls += 1
    with tempfile.TemporaryDirectory(prefix="otp-out-", dir=os.environ["TMPDIR"]) as home:
        env = {"HOME": home, "TMPDIR": home, "LC_ALL": "C"}
        env.update({f"XDG_{name}_HOME": home for name in ("CONFIG", "DATA", "CACHE", "STATE")})
        try:
            result = subprocess.run([sys.argv[1], "--fixture"], env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise SystemExit("TOTP output fixture unavailable") from None
    counts = [0, 0]
    for row in rows:
        for field in ("seed", "base32", "expected_code"):
            forms = representations(bytes(row[field]))
            for index, output in enumerate((result.stdout, result.stderr)):
                counts[index] += hits(output, forms)
    print(f"TOTP output: controls={controls} stdout_hits={counts[0]} stderr_hits={counts[1]} "
          f"stdout_bytes={len(result.stdout)} stderr_bytes={len(result.stderr)}")
    # Empty streams also reject encodings beyond this detector's vocabulary.
    if result.returncode or result.stdout or result.stderr or any(counts):
        raise SystemExit("TOTP library output refused")


if __name__ == "__main__":
    main()
