#!/usr/bin/env bash
# M3-01 dependency trial (plan D3-15; scratch branch, never merged): each
# candidate alone in a scratch crate, then the three together, each through
# cargo tree -e normal,build (every target and each named one), cargo
# metadata per platform (proc-macros and build scripts), cargo deny,
# scripts/check-sources.sh, and a build and test of a file that uses the API
# with the chosen features on this Mac (aarch64-apple-darwin).
set -u
root=/tmp/ec-m2-m3-01
here="$root/crates/envcloak-deptrial"
out="$here/results"
deny="${DENY:?path to cargo-deny 0.20.2}"
export CARGO_TARGET_DIR=/tmp/ec-target-D CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6
mkdir -p "$out"
cd "$root"

HPKE='hpke = { version = "=0.14.1", default-features = false, features = ["alloc", "getrandom", "x25519", "nistp", "aes", "chacha"] }'
HPKE_P256='hpke = { version = "=0.14.1", default-features = false, features = ["alloc", "getrandom", "nistp", "aes"] }'
P256='p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }'
SF_DEPS='security-framework = { version = "=3.7.0", default-features = false, features = ["OSX_10_15"] }
core-foundation = "=0.10.1"'

manifest() {
  printf '%s\n' '[package]' 'name = "envcloak-deptrial"' 'publish = false' \
    'version.workspace = true' 'edition.workspace = true' 'rust-version.workspace = true' \
    'license.workspace = true' 'repository.workspace = true' 'authors.workspace = true' '' \
    '[lints]' 'workspace = true' '' '[dependencies]'
  printf '%s\n' "$1"
  if [ -n "$2" ]; then
    printf '\n%s\n' "[target.'cfg(target_os = \"macos\")'.dependencies]"
    printf '%s\n' "$2"
  fi
}

candidate() {
  name="$1"; deps="$2"; macdeps="$3"; shift 3
  dir="$out/$name"; mkdir -p "$dir"
  manifest "$deps" "$macdeps" > crates/envcloak-deptrial/Cargo.toml
  : > crates/envcloak-deptrial/src/lib.rs
  for use in "$@"; do
    mod="${use%.rs}"; mod="${mod//-/_}"
    { printf 'pub mod %s {\n' "$mod"; cat "$here/uses/$use"; printf '}\n'; } >> crates/envcloak-deptrial/src/lib.rs
  done
  git checkout -q Cargo.lock
  { printf '%s\n' "$deps"; [ -n "$macdeps" ] && printf '[macOS only]\n%s\n' "$macdeps"; } > "$dir/deps.toml"
  cargo tree -e normal,build -p envcloak-deptrial --target all > "$dir/tree.txt" 2> "$dir/tree.err"
  echo "tree exit $?" > "$dir/status.txt"
  for t in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu; do
    cargo tree -e normal,build -p envcloak-deptrial --target "$t" > "$dir/tree-$t.txt" 2>> "$dir/tree.err"
    cargo metadata --format-version 1 --filter-platform "$t" > "$dir/meta-$t.json" 2>> "$dir/tree.err"
  done
  "$deny" --all-features check > "$dir/deny.txt" 2>&1
  echo "deny exit $?" >> "$dir/status.txt"
  scripts/check-sources.sh > "$dir/check-sources.txt" 2>&1
  echo "check-sources exit $?" >> "$dir/status.txt"
  cargo test -p envcloak-deptrial --locked -- --test-threads 6 > "$dir/test.txt" 2>&1
  echo "build and test on aarch64-apple-darwin exit $?" >> "$dir/status.txt"
  echo "== $name"; cat "$dir/status.txt"
}

candidate hpke "$HPKE" "" hpke.rs
candidate hpke-p256-fallback "$HPKE_P256" "" hpke-p256.rs
candidate p256-verify "$P256" "" p256.rs
candidate security-framework "" "$SF_DEPS" security-framework.rs
candidate combined "$HPKE
$P256" "$SF_DEPS" hpke.rs p256.rs security-framework.rs
python3 "$here/pm.py" "$out" > "$out/proc-macros-and-build-scripts.txt"
for d in "$out"/*/; do rm -f "$d"/meta-*.json; done
git checkout -q Cargo.lock
echo "trial done"
