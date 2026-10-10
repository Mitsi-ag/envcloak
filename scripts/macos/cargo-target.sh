#!/bin/bash
# Source this from the workspace root. Cargo resolves config and environment.
cargo_target_dir() {
  cargo metadata --locked --format-version 1 --no-deps | python3 -c '
import json, os, sys
path = json.load(sys.stdin)["target_directory"]
if not isinstance(path, str) or not os.path.isabs(path) or "\n" in path:
    sys.exit("peer code: invalid Cargo target directory")
print(path)
'
}
