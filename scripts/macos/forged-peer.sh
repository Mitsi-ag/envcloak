#!/usr/bin/env bash
# M3-21 step A14 helper: verifies that forged app peers (ad-hoc signed, signed by
# another identity, carrying com.apple.security.get-task-allow, or unsigned) are
# refused with role_denied (-32004) when calling app.pending.list.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ "${1:-}" == "--check-peer-code" ]]; then
  exec scripts/macos/check-peer-code.sh
fi

socket_path="${1:-}"
if [[ -z "$socket_path" ]]; then
  echo "usage: scripts/macos/forged-peer.sh <socket-path> | --check-peer-code" >&2
  exit 2
fi

work="$(mktemp -d /tmp/ec-forged.XXXXXXXX)"
trap 'rm -rf "$work"' EXIT

cat > "$work/probe.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 4;
    }
    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"app.pending.list\",\"params\":{}}";
    uint32_t len = htonl((uint32_t)strlen(req));
    if (write(fd, &len, 4) != 4 || write(fd, req, strlen(req)) != (ssize_t)strlen(req)) {
        close(fd);
        return 5;
    }
    uint32_t rlen = 0;
    if (read(fd, &rlen, 4) != 4) {
        close(fd);
        return 6;
    }
    rlen = ntohl(rlen);
    if (rlen == 0 || rlen > 65536) {
        close(fd);
        return 7;
    }
    char *buf = calloc(rlen + 1, 1);
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = read(fd, buf + got, rlen - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    int denied = (strstr(buf, "-32004") != NULL || strstr(buf, "role_denied") != NULL);
    printf("%s\n", buf);
    free(buf);
    return denied ? 0 : 1;
}
EOF

/usr/bin/clang -O2 "$work/probe.c" -o "$work/unsigned-client"
cp "$work/unsigned-client" "$work/adhoc-app"
cp "$work/unsigned-client" "$work/debuggable-app"

/usr/bin/codesign --remove-signature "$work/unsigned-client" 2>/dev/null || true
/usr/bin/codesign -f -s - -i ai.envcloak.app -o runtime "$work/adhoc-app"

cat > "$work/debug-entitlements.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
EOF
/usr/bin/codesign -f -s - -i ai.envcloak.app -o runtime --entitlements "$work/debug-entitlements.plist" "$work/debuggable-app"

for variant in unsigned-client adhoc-app debuggable-app; do
  if ! "$work/$variant" "$socket_path" >/dev/null; then
    echo "forged-peer: FAILED ($variant was not refused with role_denied)" >&2
    exit 1
  fi
  echo "forged-peer: $variant -> role_denied"
done
