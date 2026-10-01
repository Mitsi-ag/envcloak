#!/usr/bin/env bash
# M2-01 dependency trial: one candidate at a time in a scratch crate, each
# through cargo tree -e normal,build, cargo deny and scripts/check-sources.sh.
set -u
root=/tmp/ec-m2-m2-01
out=/private/tmp/claude-501/-Users-mitsi/0618a37c-520d-4467-9d90-e4a5ca8db0c9/scratchpad/trial
deny=/private/tmp/claude-501/-Users-mitsi/0618a37c-520d-4467-9d90-e4a5ca8db0c9/scratchpad/cargo-deny-0.20.2-aarch64-apple-darwin/cargo-deny
export CARGO_TARGET_DIR=/tmp/ec-target-A CARGO_INCREMENTAL=0
mkdir -p "$out"
cd "$root"

candidate() {
  name="$1"; deps="$2"
  dir="$out/$name"; mkdir -p "$dir"
  cat > crates/envcloak-deptrial/Cargo.toml <<EOF
[package]
name = "envcloak-deptrial"
publish = false
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true

[lints]
workspace = true

[dependencies]
$deps
EOF
  git checkout -q Cargo.lock
  printf '%s\n' "$deps" > "$dir/deps.toml"
  cargo tree -e normal,build -p envcloak-deptrial --target all > "$dir/tree.txt" 2> "$dir/tree.err"
  echo "tree exit $?" > "$dir/status.txt"
  cargo tree -e normal,build -p envcloak-deptrial > "$dir/tree-host.txt" 2>> "$dir/tree.err"
  cargo metadata --format-version 1 --filter-platform aarch64-apple-darwin > "$dir/meta-mac.json" 2>/dev/null
  cargo metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu > "$dir/meta-linux.json" 2>/dev/null
  "$deny" --all-features check > "$dir/deny.txt" 2>&1
  echo "deny exit $?" >> "$dir/status.txt"
  scripts/check-sources.sh > "$dir/check-sources.txt" 2>&1
  echo "check-sources exit $?" >> "$dir/status.txt"
  echo "== $name"; cat "$dir/status.txt"
}

candidate sha1 'sha1 = { version = "=0.11.0", default-features = false }'
candidate rustls-platform-verifier 'rustls = { version = "=0.23.45", default-features = false, features = ["std", "ring", "tls12", "logging"] }
rustls-platform-verifier = "=0.7.1"'
candidate rustls-native-certs 'rustls = { version = "=0.23.45", default-features = false, features = ["std", "ring", "tls12"] }
rustls-native-certs = "=0.8.4"'
candidate ureq 'ureq = { version = "=3.4.2", default-features = false, features = ["rustls-no-provider", "platform-verifier"] }
rustls = { version = "=0.23.45", default-features = false, features = ["std", "ring", "tls12"] }'
candidate tiny_http 'tiny_http = { version = "=0.12.0", default-features = false }'
candidate url 'url = "=2.5.8"'
candidate ed25519-dalek 'ed25519-dalek = { version = "=3.0.0", default-features = false, features = ["std"] }'
git checkout -q Cargo.lock
