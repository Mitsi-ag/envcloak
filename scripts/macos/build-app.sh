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
# two (an error, SIGTERM, SIGHUP), the exit cleanup moves the previous app
# back; if it cannot, it keeps the directory holding it and says where. It
# never deletes the last working app (scripts/macos/tests/test_build_swap.py).
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

mkdir -p "$out" "$derived"
out="$(cd "$out" && pwd -P)"
derived="$(cd "$derived" && pwd -P)"

# 1. The Rust binaries, from cargo's report of what it built.
cargo=("${CARGO:-cargo}")
host="$("${cargo[0]}" -vV 2>/dev/null | sed -n 's/^host: //p')"
[ -z "$host" ] && host="$(rustc -vV | sed -n 's/^host: //p')"
case "$host" in
  aarch64-apple-darwin) arch=arm64 ;;
  x86_64-apple-darwin) arch=x86_64 ;;
  *) die "unexpected Rust host '$host' (want aarch64-apple-darwin or x86_64-apple-darwin)" ;;
esac
echo "build-app: cargo build --release (envcloak, envcloakd) for $host" >&2
artifacts="$(mktemp "${TMPDIR:-/tmp}/ec-build-app.XXXXXX")"
trap 'rm -f "$artifacts"' EXIT
(cd "$root" && "${cargo[@]}" build --release --locked -p envcloak --bin envcloak -p envcloakd --bin envcloakd \
  --message-format=json-render-diagnostics >"$artifacts")
paths="$(python3 - "$artifacts" <<'PY'
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
)"
cli_bin="$(printf '%s\n' "$paths" | sed -n 1p)"
daemon_bin="$(printf '%s\n' "$paths" | sed -n 2p)"
[ -x "$cli_bin" ] && [ -x "$daemon_bin" ] || die "cargo's binaries are missing"
version="$("$cli_bin" --version | sed -n 's/^envcloak //p')"
[ -n "$version" ] || die "cannot read the CLI's version"

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

# 3. The bundle, staged beside the output.
stage="$(mktemp -d "$out/.stage.XXXXXX")"
incoming=""
# Set by replace_app while a replacement is between its two moves.
pending_backup=""
pending_destination=""
cleanup() {
  local status=$?
  local keep=""
  if [ -n "$pending_backup" ] && { [ -e "$pending_backup" ] || [ -L "$pending_backup" ]; }; then
    if [ ! -e "$pending_destination" ] && [ ! -L "$pending_destination" ] && mv "$pending_backup" "$pending_destination"; then
      echo "build-app: the replacement did not finish; the previous app is back at $pending_destination" >&2
    else
      keep="$(dirname "$pending_backup")"
      echo "build-app: the replacement did not finish; the previous app is kept at $pending_backup" >&2
    fi
  fi
  rm -f "$artifacts"
  if [ "$keep" != "$stage" ]; then rm -rf "$stage"; fi
  if [ -n "$incoming" ] && [ "$keep" != "$incoming" ]; then rm -rf "$incoming"; fi
  return "$status"
}
trap cleanup EXIT

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
bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
[ "$bundle_version" = "$version" ] || die "the bundle says version $bundle_version, its CLI $version"
helper_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Helpers/EnvCloakAgent.app/Contents/Info.plist")"
[ "$helper_version" = "$version" ] || die "the helper says version $helper_version, the CLI $version"

replace_app "$app" "$out/EnvCloak.app" "$stage/previous.app"
app="$out/EnvCloak.app"

# 6. Install.
if [ "$install" = 1 ]; then
  mkdir -p "$install_dir"
  dest="$(cd "$install_dir" && pwd -P)"
  incoming="$(mktemp -d "$dest/.EnvCloak.install.XXXXXX")"
  ditto "$app" "$incoming/EnvCloak.app"
  "$here/sign-check.sh" "$incoming/EnvCloak.app"
  replace_app "$incoming/EnvCloak.app" "$dest/EnvCloak.app" "$incoming/previous.app"
  rm -rf "$incoming"
  incoming=""
  echo "build-app: installed $dest/EnvCloak.app (version $version, signed $sign); a running background process was not restarted (task M3-06)" >&2
  app="$dest/EnvCloak.app"
fi

echo "$app"
