#!/usr/bin/env bash
# Enforces M4 plan §5 rule 2 (`D4-07`, gate `s7`):
#   "No surface composes control text. `scripts/check-spend-labels.sh` refuses
#   the phrase 'hard cap' in any case, and any literal equal to a control-table
#   text, outside `envcloak-spend/src/controls/` and the app's generated label
#   resource (tests and docs excepted). It does not police words like 'limit' or
#   'cap' alone, which name rate limits and size caps everywhere."
#
# Usage: scripts/check-spend-labels.sh [workspace-root]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${1:-$here/..}" && pwd -P)"

exec python3 - "$root" <<'PY'
import os
import re
import sys
import tomllib

root = sys.argv[1]

toml_path = os.path.join(
    root, "crates", "envcloak-spend", "src", "controls", "controls.toml"
)
if not os.path.isfile(toml_path):
    sys.exit(f"check-spend-labels: missing {toml_path}")

with open(toml_path, "rb") as f:
    data = tomllib.loads(f.read().decode("utf-8"))

table_literals = set()
for ctrl in data.get("control", []):
    for key in ("name", "enforced_by", "stops", "does_not_stop"):
        val = ctrl.get(key, "")
        # Ignore single-word cells like "Notifications" or "Nothing" that could
        # appear in unrelated UI or protocol code; check multi-word control
        # table sentences and control names.
        if isinstance(val, str) and " " in val.strip():
            table_literals.add(val.strip())

TOKEN_RE = re.compile(
    r"//[^\n]*"
    r"|/\*[\s\S]*?\*/"
    r'|b?r(#*)"([\s\S]*?)"\1'
    r"|b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|.)|[^'\\\n])'"
    r'|b?"((?:\\.|[^"\\])*)"'
)
HARD_CAP_RE = re.compile(r"\bhard[\s-]+cap\b", re.IGNORECASE)


def strip_comments_keep_strings(src: str):
    """Yields `(line_no, literal_text)` for every string literal outside line
    and block comments, and outside `#[cfg(test)] mod ...` blocks."""
    # Truncate at a top-level `#[cfg(test)]` module if present so unit tests in
    # the same file are excepted per §5 rule 2 ("tests and docs excepted").
    cfg_test = re.search(r"(?m)^\s*#\[cfg\(test\)\]", src)
    if cfg_test:
        src = src[: cfg_test.start()]

    for m in TOKEN_RE.finditer(src):
        if m.group(2) is not None:
            line_no = src.count("\n", 0, m.start()) + 1
            yield line_no, m.group(2)
        elif m.group(3) is not None:
            line_no = src.count("\n", 0, m.start()) + 1
            val = m.group(3).replace('\\"', '"').replace("\\\\", "\\")
            yield line_no, val


def is_allowed_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/")
    if rel.startswith("crates/envcloak-spend/src/controls/"):
        return True
    if rel.startswith("apps/macos/") and rel.endswith("ControlLabels.generated.swift"):
        return True
    if "/tests/" in f"/{rel}" or rel.endswith("_test.rs") or rel.endswith("Tests.swift"):
        return True
    if rel.startswith("docs/"):
        return True
    return False


scan_roots = [
    os.path.join(root, "crates"),
    os.path.join(root, "apps"),
]

failures = []
checked_files = 0

for base in scan_roots:
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        # Skip build output directories
        dirnames[:] = [
            d for d in sorted(dirnames) if d not in ("target", ".build", "DerivedData")
        ]
        for fname in sorted(filenames):
            if not (fname.endswith(".rs") or fname.endswith(".swift")):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if is_allowed_path(rel):
                continue
            checked_files += 1
            with open(full, encoding="utf-8") as f:
                src = f.read()
            for line_no, lit in strip_comments_keep_strings(src):
                if HARD_CAP_RE.search(lit):
                    failures.append(
                        f"{rel}:{line_no}: forbidden 'hard cap' literal outside envcloak-spend/src/controls/: {lit!r}"
                    )
                norm = lit.strip()
                if norm in table_literals:
                    failures.append(
                        f"{rel}:{line_no}: forbidden control-table literal outside envcloak-spend/src/controls/: {lit!r}"
                    )

if failures:
    for msg in failures:
        print(f"check-spend-labels: {msg}", file=sys.stderr)
    sys.exit(1)

print(f"check-spend-labels: ok ({checked_files} files)")
PY
