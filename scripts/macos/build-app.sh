#!/usr/bin/env bash
# Builds EnvCloak.app with the CLI and the daemon inside it (SPEC §12
# "Layout"; M3 plan D3-05, D3-18; docs/APP.md "Build commands"):
#
# 1. `cargo build --release --locked` of `envcloak` and `envcloakd`, the
#    shipped binaries, located from cargo's own report of what it built (so
#    CARGO_TARGET_DIR is honoured and no stale binary is picked up).
# 2. `xcodebuild` of the EnvCloak scheme, Release, for the architecture the
#    Rust binaries were built for, with Xcode's own signing off and no base
#    entitlements: this script signs every executable itself, once.
# 3. The bundle: the helper wrapper EnvCloakAgent.app with `envcloakd` in
#    Contents/Helpers/, and `envcloak` in Contents/MacOS/.
# 4. Signing inside out, each with the hardened runtime and its own
#    entitlements file from apps/macos/Support/: the helper (as
#    ai.envcloak.agent), then the CLI (ai.envcloak.cli), then the app
#    (ai.envcloak.app) (SPEC §12 "Signing and release").
# 5. scripts/macos/sign-check.sh on the result, and a check that the bundle's
#    version is the bundled CLI's. Only a bundle that passes replaces the
#    previous one at the output path.
# 6. With --install, a copy to /Applications (or --install-dir), checked
#    again there before it replaces the installed app. Restarting the
#    background process when its version changed is task M3-06's; this
#    script says that it did not.
#
# A replacement (steps 5 and 6) moves the previous app aside, then the new
# one into place. If the second move fails, or the script stops between the
# two (an error, or SIGHUP, SIGINT, SIGQUIT or SIGTERM), the exit cleanup
# moves the previous app back; if it cannot, it keeps the directory holding
# it and says where. It never deletes the last working app.
#
# However it stops, it leaves no step running and no directory of its own
# behind (the staging directories beside the output and the installed app,
# and its work directory): see "Stopping" below. A signal sent to the script
# alone takes effect when the step in progress ends; one sent to its process
# group (Ctrl-C, Ctrl-\, a closed terminal) ends that step too.
# scripts/macos/tests/test_build_swap.py runs this script with stand-ins for
# cargo, xcodebuild, codesign, sign-check.sh and mv, and checks each of
# these.
#
# Usage: scripts/macos/build-app.sh [--sign adhoc|development|ci] [--install]
#            [--install-dir DIR] [--out DIR] [--derived-data DIR]
#   --sign adhoc        tier 1: ad hoc, any Mac (the default)
#   --sign development  tier 2: the Apple Development identity on this Mac
#                       (ENVCLOAK_SIGN_IDENTITY names another one)
#   --sign ci           tier 3: the identity scripts/macos/ci-identity.sh
#                       (task M3-07) exports as ENVCLOAK_CI_IDENTITY, in the
#                       keychain ENVCLOAK_CI_KEYCHAIN
#   --out DIR           where EnvCloak.app is written (default apps/macos/build)
#   --derived-data DIR  xcodebuild's derived data (default apps/macos/build/DerivedData)
# The path of the built app is the last line on standard output.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd -P)"
app_src="$root/apps/macos"

die() {
  echo "build-app: $*" >&2
  exit 1
}
usage() {
  sed -n '/^# Usage:/,/^# The path/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

sign=adhoc
install=0
install_dir=/Applications
out="$app_src/build"
derived="$app_src/build/DerivedData"
while [ $# -gt 0 ]; do
  case "$1" in
    --sign) [ $# -ge 2 ] || usage; sign="$2"; shift 2 ;;
    --install) install=1; shift ;;
    --install-dir) [ $# -ge 2 ] || usage; install_dir="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
    --derived-data) [ $# -ge 2 ] || usage; derived="$2"; shift 2 ;;
    -h | --help) usage ;;
    *) echo "build-app: unknown argument: $1" >&2; usage ;;
  esac
done

[ "$(uname -s)" = Darwin ] || die "the app builds on macOS only"
# Signing an unpinned source build would still leave its IPC unverified. This
# preflight runs before keychain selection, output creation or installation.
case "$sign" in
  development|ci)
    (cd "$root" && "${CARGO:-cargo}" run --release --locked --quiet -p envcloak-sys --bin production_pin) ||
      die "signed packaging blocked: production pin preflight failed (Q3-01)"
    ;;
esac
keychain=()
case "$sign" in
  adhoc)
    identity=-
    tier=Adhoc
    ;;
  development)
    identity="${ENVCLOAK_SIGN_IDENTITY:-Apple Development}"
    tier=Development
    ;;
  ci)
    [ -n "${ENVCLOAK_CI_IDENTITY:-}" ] ||
      die "--sign ci needs ENVCLOAK_CI_IDENTITY (and ENVCLOAK_CI_KEYCHAIN), which scripts/macos/ci-identity.sh exports (task M3-07)"
    identity="$ENVCLOAK_CI_IDENTITY"
    tier=CI
    if [ -n "${ENVCLOAK_CI_KEYCHAIN:-}" ]; then
      keychain=(--keychain "$ENVCLOAK_CI_KEYCHAIN")
    fi
    ;;
  *) echo "build-app: --sign takes adhoc, development or ci, not '$sign'" >&2; usage ;;
esac

# Stopping. Every way this script stops (an error, a failed check, a
# signal) goes through `cleanup`, and nothing it makes can be left behind.
# Measured on this script with only an EXIT trap, under bash 3.2
# (/bin/bash) and 5.3: SIGQUIT between the two moves of a replacement ended
# bash 3.2 without the cleanup (the previous app stayed in the staging
# directory, nothing at the destination); SIGINT sent to the script alone
# was ignored and the new app went in; SIGTERM ran the cleanup at once while
# the step in progress ran on, orphaned; and once standard error was
# closed, the cleanup's first message ended it part way (bash 5.3 died of
# SIGPIPE, bash 3.2's failed write ended the trap under `set -e`), leaving
# its directories. So:
# - HUP, INT, QUIT and TERM are trapped. bash runs a trap when the
#   foreground command in progress ends, so no step is left running, and
#   the handler leaves through the cleanup. Once the traps are set, no
#   program runs inside a command substitution, where bash runs a trap
#   without waiting for it (measured): programs write to files in the work
#   directory instead.
# - SIGPIPE is ignored, so a write to a closed standard error fails and
#   `set -e` takes that path like any other error; the cleanup runs with
#   `set +e`, so a message it cannot write stops nothing.
# - Each directory the script makes is named `<prefix>.<pid>.<run>.<random>`,
#   where <run> is drawn once per run from /dev/urandom, and the cleanup
#   removes every such name of this run, so one made in the instant before
#   its name reached a variable is removed too. An earlier run with the same
#   pid may have kept its previous app in such a directory ("kept at"); its
#   <run> differs, so this run never removes it.
# - The cleanup ignores the four signals while it runs, and the commands it
#   starts inherit that, so a second signal cannot cut a restore short.
# After the cleanup, a script stopped by HUP, INT or TERM ends by that
# signal (a calling shell sees it); by QUIT, with status 131 and no core.
# This run's part of every name it makes (12 hexadecimal digits), read
# before any trap is set, so no program runs in a command substitution
# after that.
run_token="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
case "$run_token" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) die "cannot read a run token from /dev/urandom" ;;
esac
out_prefix=""
install_prefix=""
work_prefix="${TMPDIR:-/tmp}"
work_prefix="${work_prefix%/}/ec-build-app"
work=""
stage=""
incoming=""
# Set by replace_app while a replacement is between its two moves.
pending_backup=""
pending_destination=""
stopped_by=""
cleanup() {
  local status=$?
  set +e
  trap '' HUP INT QUIT TERM
  local keep="" dir prefix
  if [ -n "$pending_backup" ] && { [ -e "$pending_backup" ] || [ -L "$pending_backup" ]; }; then
    if [ ! -e "$pending_destination" ] && [ ! -L "$pending_destination" ] && mv "$pending_backup" "$pending_destination"; then
      echo "build-app: the replacement did not finish; the previous app is back at $pending_destination" >&2
    else
      keep="${pending_backup%/*}"
      echo "build-app: the replacement did not finish; the previous app is kept at $pending_backup" >&2
    fi
  fi
  for prefix in "$work_prefix" "$out_prefix" "$install_prefix"; do
    [ -n "$prefix" ] || continue
    for dir in "$prefix.$$.$run_token".*; do
      if { [ -e "$dir" ] || [ -L "$dir" ]; } && [ "$dir" != "$keep" ]; then
        rm -rf "$dir"
      fi
    done
  done
  if [ -n "$stopped_by" ]; then
    echo "build-app: stopped by SIG$stopped_by" >&2
    if [ "$stopped_by" != QUIT ]; then
      trap - EXIT "$stopped_by"
      kill -s "$stopped_by" "$$"
    fi
  fi
  exit "$status"
}
stop() {
  stopped_by="$1"
  exit $((128 + $2))
}
trap cleanup EXIT
trap 'stop HUP 1' HUP
trap 'stop INT 2' INT
trap 'stop QUIT 3' QUIT
trap 'stop TERM 15' TERM
trap '' PIPE

# make_dir VAR PREFIX: makes the directory PREFIX.<pid>.<run>.<random> (0700;
# mkdir refuses a name that exists, a symbolic link included) and sets VAR
# to it.
make_dir() {
  local path tries=0
  while :; do
    path="$2.$$.$run_token.$RANDOM$RANDOM"
    if mkdir -m 0700 "$path" 2>/dev/null; then
      eval "$1=\$path"
      return 0
    fi
    tries=$((tries + 1))
    [ "$tries" -lt 20 ] || die "cannot make a directory named $2.$$.$run_token.*"
  done
}

# first_line VAR FILE: VAR is FILE's first line.
first_line() {
  local line=""
  IFS= read -r line <"$2" || [ -n "$line" ] || die "$2 is empty"
  eval "$1=\$line"
}

mkdir -p "$out" "$derived"
out="$(cd "$out" && pwd -P)"
derived="$(cd "$derived" && pwd -P)"
out_prefix="$out/.stage"
make_dir work "$work_prefix"

# 1. The Rust binaries, from cargo's report of what it built.
cargo=("${CARGO:-cargo}")
"${cargo[0]}" -vV >"$work/cargo-version" 2>/dev/null || rustc -vV >"$work/cargo-version"
host=""
while IFS= read -r line; do
  case "$line" in host:\ *) host="${line#host: }" ;; esac
done <"$work/cargo-version"
case "$host" in
  aarch64-apple-darwin) arch=arm64 ;;
  x86_64-apple-darwin) arch=x86_64 ;;
  *) die "unexpected Rust host '$host' (want aarch64-apple-darwin or x86_64-apple-darwin)" ;;
esac
echo "build-app: cargo build --release (envcloak, envcloakd) for $host" >&2
artifacts="$work/cargo-build.json"
(cd "$root" && "${cargo[@]}" build --release --locked -p envcloak --bin envcloak -p envcloakd --bin envcloakd \
  --message-format=json-render-diagnostics >"$artifacts")
python3 - "$artifacts" >"$work/binaries" <<'PY'
import json, sys
found = {}
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] in ("envcloak", "envcloakd"):
        found[m["target"]["name"]] = m["executable"]
if sorted(found) != ["envcloak", "envcloakd"]:
    sys.exit("build-app: cargo did not report both binaries: %s" % sorted(found))
print(found["envcloak"])
print(found["envcloakd"])
PY
{ IFS= read -r cli_bin && IFS= read -r daemon_bin; } <"$work/binaries" || die "cargo's report names no binaries"
[ -x "$cli_bin" ] && [ -x "$daemon_bin" ] || die "cargo's binaries are missing"
"$cli_bin" --version >"$work/cli-version"
first_line version "$work/cli-version"
case "$version" in
  envcloak\ ?*) version="${version#envcloak }" ;;
  *) die "cannot read the CLI's version" ;;
esac

# 2. The app and the helper wrapper, unsigned.
echo "build-app: xcodebuild EnvCloak (Release, $arch, version $version)" >&2
xcodebuild -project "$app_src/EnvCloak.xcodeproj" -scheme EnvCloak -configuration Release \
  -derivedDataPath "$derived" -destination "platform=macOS,arch=$arch" \
  -xcconfig "$app_src/Config/Signing-$tier.xcconfig" \
  ARCHS="$arch" ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  SWIFT_SUPPRESS_WARNINGS=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES \
  MARKETING_VERSION="$version" \
  -quiet build >&2
products="$derived/Build/Products/Release"
[ -d "$products/EnvCloak.app" ] && [ -d "$products/EnvCloakAgent.app" ] || die "xcodebuild left no EnvCloak.app or EnvCloakAgent.app in $products"

# replace_app NEW DESTINATION BACKUP: the previous app at DESTINATION (if
# any) moves to BACKUP, then NEW to DESTINATION. The backup is recorded
# before anything moves, so the exit cleanup can put it back after a failure
# or a stop at any point between the moves; BACKUP's directory is removed
# by the cleanup only once the new app is in place.
replace_app() {
  local candidate="$1" destination="$2" backup="$3"
  pending_backup="$backup"
  pending_destination="$destination"
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    mv "$destination" "$backup" || return
  fi
  mv "$candidate" "$destination" || return
  pending_backup=""
  pending_destination=""
}

# plist_version VAR PLIST: VAR is PLIST's CFBundleShortVersionString.
plist_version() {
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$2" >"$work/plist-version"
  first_line "$1" "$work/plist-version"
}

# 3. The bundle, staged beside the output.
make_dir stage "$out_prefix"
app="$stage/EnvCloak.app"
ditto "$products/EnvCloak.app" "$app"
mkdir -p "$app/Contents/Helpers"
ditto "$products/EnvCloakAgent.app" "$app/Contents/Helpers/EnvCloakAgent.app"
mkdir -p "$app/Contents/Helpers/EnvCloakAgent.app/Contents/MacOS"
install -m 0755 "$daemon_bin" "$app/Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd"
install -m 0755 "$cli_bin" "$app/Contents/MacOS/envcloak"

# 4. Signing, inside out.
support="$app_src/Support"
sign_one() {
  echo "build-app: codesign $2 ($sign)" >&2
  codesign --force --sign "$identity" ${keychain[@]+"${keychain[@]}"} --options runtime --timestamp=none \
    --identifier "$2" --entitlements "$3" "$1"
}
sign_one "$app/Contents/Helpers/EnvCloakAgent.app" ai.envcloak.agent "$support/EnvCloakAgent.entitlements"
sign_one "$app/Contents/MacOS/envcloak" ai.envcloak.cli "$support/envcloak-cli.entitlements"
sign_one "$app" ai.envcloak.app "$support/EnvCloak.entitlements"

# 5. Checks, then the swap.
"$here/sign-check.sh" "$app"
plist_version bundle_version "$app/Contents/Info.plist"
[ "$bundle_version" = "$version" ] || die "the bundle says version $bundle_version, its CLI $version"
plist_version helper_version "$app/Contents/Helpers/EnvCloakAgent.app/Contents/Info.plist"
[ "$helper_version" = "$version" ] || die "the helper says version $helper_version, the CLI $version"

replace_app "$app" "$out/EnvCloak.app" "$stage/previous.app"
app="$out/EnvCloak.app"

# 6. Install.
if [ "$install" = 1 ]; then
  mkdir -p "$install_dir"
  dest="$(cd "$install_dir" && pwd -P)"
  install_prefix="$dest/.EnvCloak.install"
  make_dir incoming "$install_prefix"
  ditto "$app" "$incoming/EnvCloak.app"
  "$here/sign-check.sh" "$incoming/EnvCloak.app"
  replace_app "$incoming/EnvCloak.app" "$dest/EnvCloak.app" "$incoming/previous.app"
  rm -rf "$incoming"
  echo "build-app: installed $dest/EnvCloak.app (version $version, signed $sign); a running background process was not restarted (task M3-06)" >&2
  app="$dest/EnvCloak.app"
fi

echo "$app"
