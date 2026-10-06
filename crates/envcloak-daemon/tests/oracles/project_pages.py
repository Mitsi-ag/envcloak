"""Independent JSON/framing reader for the synthetic M3-04 project index."""
import json
import socket
import struct
import sys


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        assert part, "truncated frame"
        data.extend(part)
    return bytes(data)


cursor = None
seen = set()
times = []
for page_number in range(1000):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(10)
        stream.connect(sys.argv[1])
        request = json.dumps({"jsonrpc": "2.0", "id": page_number,
                              "method": "projects.list", "params": {"after": cursor}}).encode()
        stream.sendall(struct.pack("!I", len(request)) + request)
        size = struct.unpack("!I", exact(stream, 4))[0]
        assert 0 < size <= 1024 * 1024, "frame bound"
        answer = json.loads(exact(stream, size))
    assert answer["id"] == page_number and "error" not in answer
    result = answer["result"]
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
    assert len(encoded) <= 768 * 1024, "encoded result bound"
    for row in result["projects"]:
        assert row["dir"] not in seen, "duplicate project"
        seen.add(row["dir"])
        times.append(row["last_seen_secs"])
        assert len(row["manifest_sha256"]) == 64
        assert set(row["manifest_sha256"]) <= set("0123456789abcdef")
        assert len(row["bindings"]) == 150
    cursor = result["next"]
    if cursor is None:
        break
else:
    raise AssertionError("pagination did not end")
assert len(seen) == int(sys.argv[2]) and times == sorted(times, reverse=True)
print("independent project frame oracle passed")
