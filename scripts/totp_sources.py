"""Conservative source confinement, independent of Clippy exposure exceptions."""
import os
from pathlib import Path
import re
import tomllib

IMPLEMENTATION = Path("crates/envcloak-signin/src/totp.rs")
CANARY = Path("crates/envcloak-signin/tests/sha1_canary.rs")


def source_problem(path, source):
    if path == IMPLEMENTATION:
        return None
    for attr in re.findall(r"#!?\[.*?\]", source, re.S):
        if re.search(r"\b(?:allow|expect)\b", attr) and "disallowed_types" in attr:
            return "exception outside totp.rs"
    if path == CANARY:
        if not source.startswith("#![cfg(envcloak_lint_canary)]\n"):
            return "unguarded SHA-1 canary"
        return None
    # Reserve the crate identifier even in comments, macros and inactive cfgs.
    # Only these complete string literals in tests name fixture algorithms.
    # No general Rust lexer or allow(disallowed_methods) can exempt a reference.
    if "tests" in path.parts:
        source = source.replace('"sha1"', '""').replace('"&algorithm=sha1"', '""')
    if re.search(r"\bsha1\b", source):
        return "SHA-1 outside totp.rs"
    return None


def manifest_problem(path, doc):
    def references(table):
        for name, value in table.items():
            if name == "sha1" or isinstance(value, dict) and value.get("package") == "sha1":
                yield name
            if isinstance(value, dict):
                yield from references(value)
    for name in references(doc):
        if name != "sha1" or path not in (Path("Cargo.toml"), Path("crates/envcloak-signin/Cargo.toml")):
            return "SHA-1 dependency outside its declared boundary"
    return None


def check_sources(root):
    # Match all source locations, including future test/fuzz targets. The
    # compiler source-list gate separately rejects hidden source inclusion.
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in (".git", "target", "node_modules")]
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root)
            if path.suffix == ".rs":
                problem = source_problem(relative, path.read_text())
            elif name == "Cargo.toml":
                problem = manifest_problem(relative, tomllib.loads(path.read_text()))
            else:
                continue
            if problem:
                raise SystemExit("check-totp-lint: " + problem)
