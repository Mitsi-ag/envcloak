#!/usr/bin/env bash
# Proves that the compiler forbids unsafe code in workspace crates, however
# the manifests are spelled: compiles security/unsafe-canary, a workspace
# member that inherits the workspace lints, with a generated module that
# uses `unsafe` plainly, under `#[allow(unsafe_code)]`, under the raw
# identifier `#[allow(r#unsafe_code)]`, under `#[expect(unsafe_code)]`, and
# in a file pulled in with `#[path]` that allows it for the whole module.
# Every unsafe block must be reported as an `unsafe_code` error and every
# allow as E0453 (an allow under forbid), each on its marked line and
# nothing more. A workspace table rustc never sees, a level of deny instead
# of forbid, or an allow that takes effect makes this fail.
#
# The module is written here, not committed, because scripts/check-unsafe.sh
# rightly rejects its attributes in any committed file. Git ignores it.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/security/unsafe-canary/src"
cd "$root"

cleanup() { rm -f "$src/generated.rs" "$src/generated_included.rs"; }
trap cleanup EXIT

cat >"$src/generated.rs" <<'EOF'
pub fn plain(v: &[u8]) -> u8 {
    unsafe { *v.as_ptr() } // EXPECT unsafe_code
}

#[allow(unsafe_code)] // EXPECT E0453
pub fn allowed(v: &[u8]) -> u8 {
    unsafe { *v.as_ptr() } // EXPECT unsafe_code
}

#[allow(r#unsafe_code)] // EXPECT E0453
pub fn raw(v: &[u8]) -> u8 {
    unsafe { *v.as_ptr() } // EXPECT unsafe_code
}

#[expect(unsafe_code)] // EXPECT E0453
pub fn expected(v: &[u8]) -> u8 {
    unsafe { *v.as_ptr() } // EXPECT unsafe_code
}

#[path = "generated_included.rs"]
pub mod included;
EOF

cat >"$src/generated_included.rs" <<'EOF'
#![allow(unsafe_code)] // EXPECT E0453

pub fn first(v: &[u8]) -> u8 {
    unsafe { *v.as_ptr() } // EXPECT unsafe_code
}
EOF

json="$(RUSTFLAGS="${RUSTFLAGS:-} --cfg envcloak_unsafe_canary" cargo check --quiet --locked \
  -p envcloak-unsafe-canary \
  --target-dir "$root/target/unsafe-canary" \
  --message-format=json 2>/dev/null || true)"

if ! printf '%s\n' "$json" | python3 -c '
import json, os, re, sys

src = sys.argv[1]
expected = set()
for name in ("generated.rs", "generated_included.rs"):
    with open(os.path.join(src, name)) as f:
        for n, line in enumerate(f, 1):
            m = re.search(r"// EXPECT (\S+)$", line.rstrip("\n"))
            if m:
                expected.add((name, n, m.group(1)))

got = set()
for raw in sys.stdin:
    try:
        msg = json.loads(raw)
    except ValueError:
        continue
    if msg.get("reason") != "compiler-message":
        continue
    d = msg["message"]
    code = (d.get("code") or {}).get("code")
    if d.get("level") != "error" or code not in ("unsafe_code", "E0453"):
        continue
    for span in d.get("spans", []):
        if span.get("is_primary"):
            got.add((os.path.basename(span["file_name"]), span["line_start"], code))

if not expected or got != expected:
    for item in sorted(expected - got):
        print("check-unsafe-lint: not reported: %s:%d %s" % item, file=sys.stderr)
    for item in sorted(got - expected):
        print("check-unsafe-lint: unexpected: %s:%d %s" % item, file=sys.stderr)
    sys.exit(1)
print("check-unsafe-lint: ok (%d of %d errors reported)" % (len(got), len(expected)))
' "$src"; then
  RUSTFLAGS="${RUSTFLAGS:-} --cfg envcloak_unsafe_canary" cargo check --locked \
    -p envcloak-unsafe-canary --target-dir "$root/target/unsafe-canary" >&2 || true
  exit 1
fi
