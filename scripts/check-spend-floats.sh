#!/usr/bin/env bash
# Enforces M4 §5 rule 4 and D4-08: money and spend arithmetic uses integer minor
# units only, never IEEE-754 floating point (`f32`, `f64`, `as f32`/`as f64`,
# `parse::<f32>`/`parse::<f64>`, `as_f64`/`as_f32`/`from_f64`/`from_f32`).
#
# Usage: scripts/check-spend-floats.sh [workspace-root]
set -euo pipefail

root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root"

python3 - "$root" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])

TARGET_PATTERNS = (
    "crates/envcloak-spend/**/*.rs",
    "crates/envcloak-poll/**/*.rs",
    "crates/envcloak-providers/src/metrics.rs",
    "crates/envcloak-core/src/money.rs",
    "crates/envcloak-core/src/vault/policy/**/*.rs",
    "crates/envcloak-daemon/src/spend*.rs",
    "crates/envcloak-daemon/src/spend/**/*.rs",
    "crates/envcloak-cli/src/cmd/spend*.rs",
    "crates/envcloak-cli/src/cmd/sub.rs",
    "crates/envcloak-cli/src/cmd/budget.rs",
    "crates/envcloak-cli/src/cmd/alerts.rs",
    "crates/envcloak-client/src/render/spend*.rs",
    "crates/envcloak-mcp/src/tools/usage_summary*.rs",
    "crates/envcloak-ipc/src/spend*.rs",
)


def strip_comments_and_strings(src: str) -> str:
    """Replaces comments and string/char literal bodies with spaces, preserving line numbers."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        two = src[i : i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if two == "/*":
            depth = 1
            out.extend((" ", " "))
            i += 2
            while i < n and depth > 0:
                if src[i : i + 2] == "/*":
                    depth += 1
                    out.extend((" ", " "))
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    out.extend((" ", " "))
                    i += 2
                else:
                    out.append("\n" if src[i] == "\n" else " ")
                    i += 1
            continue
        # Raw strings r#"..."# or br#"..."#
        if ch in ("r", "b") and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            j = i + (2 if src[i : i + 2] == "br" else 1 if ch == "r" else 0)
            if j > i:
                hashes = 0
                while j < n and src[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and src[j] == '"':
                    closing = '"' + ("#" * hashes)
                    out.append('"')
                    out.extend(" " * (j - i))
                    i = j + 1
                    while i < n and not src.startswith(closing, i):
                        out.append("\n" if src[i] == "\n" else " ")
                        i += 1
                    if i < n:
                        out.append('"')
                        out.extend(" " * hashes)
                        i += len(closing)
                    continue
        if ch == '"':
            out.append('"')
            i += 1
            while i < n:
                if src[i] == "\\":
                    out.extend((" ", " "))
                    i += 2
                    continue
                if src[i] == '"':
                    out.append('"')
                    i += 1
                    break
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    cleaned = re.sub(r"\br#([A-Za-z_])", r" \1", cleaned)
    return cleaned


FORBIDDEN_RES = (
    (re.compile(r"\b(?:f32|f64)\b"), "uses floating-point type f32 or f64"),
    (re.compile(r"\bas\s+f(?:32|64)?\b"), "casts with `as f32` or `as f64`"),
    (re.compile(r"\bparse\s*::\s*<\s*f"), "parses float with `parse::<f...>`"),
    (re.compile(r"\b(?:as_f64|as_f32|from_f64|from_f32)\b"), "calls float conversion helper (`as_f64`/`from_f64`)"),
)

files = sorted({p for pat in TARGET_PATTERNS for p in root.glob(pat) if p.is_file()})
if not files:
    print("check-spend-floats: no target files found", file=sys.stderr)
    sys.exit(1)

errors = []
for path in files:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    cleaned = strip_comments_and_strings(text)
    for lineno, line in enumerate(cleaned.splitlines(), start=1):
        for rx, reason in FORBIDDEN_RES:
            if rx.search(line):
                errors.append(f"{rel}:{lineno}: {reason}")

if errors:
    for err in errors:
        print(f"check-spend-floats: {err}", file=sys.stderr)
    sys.exit(1)

print(f"check-spend-floats: ok ({len(files)} files)")
PY
