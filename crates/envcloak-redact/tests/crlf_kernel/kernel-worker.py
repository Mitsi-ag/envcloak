"""What a real terminal's line discipline does to values that hold LF.

The independent oracle for the redactor's CR LF variants (M2 plan D-19;
adopted from an independent review, cycle 356): for eight shapes of value
(no LF, an inner LF, a leading and a trailing LF, two LFs in a row, a CR LF
already there, CR LF and LF mixed, and a NUL with a multi-byte character
before the LF), each made of fresh random hex around the shape, this writes
the value to the slave side of a new pseudo-terminal twice, once with
OPOST|ONLCR set and once with no output processing, and reads back what the
master side shows. No transformation is written by hand: the kernel makes
the "cooked" form. Prints the rows as JSON on standard output (the values
are random hex, generated here, and never a secret).
"""
import json
import os
import pty
import secrets
import select
import termios
import time

rows = []
for shape in range(8):
    prefix = secrets.token_hex(24).encode()
    suffix = secrets.token_hex(16).encode()
    forms = [
        prefix + suffix,
        prefix + b"\n" + suffix,
        b"\n" + prefix + suffix,
        prefix + suffix + b"\n",
        prefix + b"\n\n" + suffix,
        prefix + b"\r\n" + suffix,
        prefix + b"\r\n\n\r\n" + suffix,
        prefix + b"\x00" + chr(0x1F60A).encode() + b"\n" + suffix,
    ]
    value = forms[shape]
    capture = []
    for flags in (termios.OPOST | termios.ONLCR, 0):
        master, slave = pty.openpty()
        try:
            attrs = termios.tcgetattr(slave)
            attrs[1] = flags
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            assert termios.tcgetattr(slave)[1] == flags, "output flags not set"
            end = secrets.token_hex(24).encode()
            payload = value + end
            sent = 0
            os.set_blocking(slave, False)
            deadline = time.monotonic() + 20
            out = bytearray()
            while not out.endswith(end):
                remaining = deadline - time.monotonic()
                assert remaining > 0, "the terminal did not show the payload in time"
                writable = [slave] if sent < len(payload) else []
                rd, wr, _ = select.select([master], writable, [], remaining)
                if wr:
                    sent += os.write(slave, payload[sent:])
                if rd:
                    out.extend(os.read(master, 4096))
            assert sent == len(payload)
            capture.append(bytes(out[: -len(end)]))
        finally:
            os.close(slave)
            os.close(master)
    rows.append(
        {"value": list(value), "cooked": list(capture[0]), "raw": list(capture[1])}
    )
print(json.dumps(rows))
