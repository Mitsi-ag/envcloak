#!/usr/bin/env bash
# M3-01 dependency trial, second run (plan D3-15; scratch branch, never
# merged): the same five candidates as trial.sh, now compiled for
# x86_64-apple-darwin, so the source-boundary check reads what the compiler
# actually reads and expands for that target rather than the resolved
# graph alone. For each candidate: cargo tree -e normal,build for the
# target (which also brings the lockfile up to date), scripts/check-sources.sh
# with CARGO_BUILD_TARGET=x86_64-apple-darwin (its `cargo check` runs, the
# dep-info of every workspace unit and the proc-macro crates compiled for
# the workspace), and a build and test of the uses file for that target,
# whose test binary runs under Rosetta 2 on this arm64 Mac. A refusal by
# check-sources.sh is the expected result for the hpke candidates: it is
# what the proc-macro allowlist review of M3-08 must clear.
set -u
root=/tmp/ec-m2-m3-01
here="$root/crates/envcloak-deptrial"
target=x86_64-apple-darwin
out="$here/results/$target"
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

{
  echo "host: $(uname -m), macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  rustc -vV
  echo "rosetta: $(arch -x86_64 /usr/bin/uname -m)"
} > "$out/environment.txt" 2>&1

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
  cargo tree -e normal,build -p envcloak-deptrial --target "$target" > "$dir/tree.txt" 2> "$dir/tree.err"
  echo "tree ($target) exit $?" > "$dir/status.txt"
  CARGO_BUILD_TARGET="$target" scripts/check-sources.sh > "$dir/check-sources.txt" 2>&1
  echo "check-sources ($target) exit $?" >> "$dir/status.txt"
  cargo test -p envcloak-deptrial --locked --target "$target" -- --test-threads 6 > "$dir/test.txt" 2>&1
  echo "build and test on $target (Rosetta 2) exit $?" >> "$dir/status.txt"
  echo "== $name"; cat "$dir/status.txt"
}

candidate hpke "$HPKE" "" hpke.rs
candidate hpke-p256-fallback "$HPKE_P256" "" hpke-p256.rs
candidate p256-verify "$P256" "" p256.rs
candidate security-framework "" "$SF_DEPS" security-framework.rs
candidate combined "$HPKE
$P256" "$SF_DEPS" hpke.rs p256.rs security-framework.rs
git checkout -q Cargo.lock
echo "trial done"
