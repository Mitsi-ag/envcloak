"""Independent cycle578-csv-oracle.py semantic corpus. Documented format, not tool output.
Reduced research caps are excluded by the adapter; production bounds have Rust tests.
"""
import csv
import io
import json

HEADER = ("Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes")

def token(index):
    return "".join(chr(n) for n in (113, 90, 118, 82, 107)) + str(index) + chr(95) + chr(89)


def row(index):
    return tuple(token(index * 9 + field) for field in range(9))


def change(cells, column, value):
    values = list(cells)
    values[column] = value
    return tuple(values)


def emit(rows, header=HEADER, all_quotes=False, ending="\r\n", final=True, bom=False):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator=ending,
                        quoting=csv.QUOTE_ALL if all_quotes else csv.QUOTE_MINIMAL)
    if header is not None:
        writer.writerow(header)
    writer.writerows(rows)
    wire = stream.getvalue().encode("utf-8")
    if not final and wire.endswith(ending.encode()):
        wire = wire[:-len(ending.encode())]
    return (b"\xef\xbb\xbf" if bom else b"") + wire


def ok(rows):
    # Semantic expectations are made before CSV serialization; no parser helper.
    rows = tuple(tuple(x) for x in rows)
    return {"status": "ok", "reason": None, "ordinal": None, "rows": rows,
            "candidates": tuple((i + 1, r[0], r[3]) for i, r in enumerate(rows) if r[3]),
            "unsupported_otp_rows": tuple(i + 1 for i, r in enumerate(rows) if r[4]),
            "empty_password_rows": tuple(i + 1 for i, r in enumerate(rows) if not r[3]),
            "parsing_complete": True, "durable_writes": 0,
            "source_retained": "not_touched", "provenance": "unverified",
            "coverage_scope": "supplied_file_supported_fields"}


def refused(reason, ordinal=1):
    return {"status": "refused", "reason": reason, "ordinal": ordinal,
            "rows": (), "candidates": (), "unsupported_otp_rows": (),
            "empty_password_rows": (), "parsing_complete": False,
            "durable_writes": 0, "source_retained": "not_touched",
            "provenance": "unverified", "coverage_scope": "supplied_file_supported_fields"}


def cases():
    result = []
    def add(identity, wire, expected, limits=None):
        result.append({"id": identity, "wire": wire, "expected": expected, "limits": limits})
    def positive(identity, rows, **options):
        expected = ok(rows)
        wire = emit(rows, **options)
        add(identity, wire, expected)
    first, second = row(1), row(2)
    positive("C01-two-rows", [first, second])
    positive("C01-all-quoted", [first], all_quotes=True)
    for name, suffix in (("comma", chr(44)), ("quote", chr(34)), ("lf", chr(10)),
                         ("crlf", chr(13) + chr(10)), ("cr", chr(13)),
                         ("literal-slash-n", chr(92) + chr(110))):
        cells = change(first, 3, token(90) + suffix + token(91))
        cells = change(cells, 8, token(92) + suffix + token(93))
        positive("C02-" + name, [cells], all_quotes=True)
    for n in range(4):
        positive("C03-backslash-" + str(n),
                 [change(first, 3, token(100) + chr(92) * n + chr(34) + token(101))])
    positive("C04-space-unicode",
             [change(change(first, 3, " \t" + chr(0x00e9) + chr(0x65) + chr(0x301) + "\n "),
                     0, " " + token(120) + " ")])
    header_wire = emit([], final=True)
    middle = list(first)
    middle[0] = token(130) + chr(34) + token(131) + chr(34)
    add("C05-even-unquoted-quotes", header_wire + (",".join(middle) + "\r\n").encode(),
        refused("malformed"))
    positive("C05-restored-quoted", [tuple(middle)])
    quote_row = emit([first], header=None, all_quotes=True)
    for suffix in (b"x", b" "):
        edited = quote_row.replace(b'","', b'"' + suffix + b',"', 1)
        add("C06-after-quote-" + str(suffix[0]), header_wire + edited, refused("malformed"))
    positive("C06-restored", [first], all_quotes=True, final=False)
    prefix = emit([first])
    add("C07-late-truncated", prefix + b'"' + token(140).encode(),
        refused("malformed", 2))
    positive("C07-restored", [first, change(second, 8, token(140))], all_quotes=True)
    positive("C08-bom", [first], bom=True)
    add("C08-double-bom", b"\xef\xbb\xbf" + emit([first], bom=True), refused("header", 0))
    positive("C08-value-bom", [change(first, 3, token(150) + chr(0xfeff) + token(151))])
    variants = {
        "missing": HEADER[:-1], "extra": HEADER + ("Other",),
        "duplicate": HEADER[:8] + (HEADER[3],),
        "case": HEADER[:1] + ("URL",) + HEADER[2:],
        "alias": HEADER[:1] + ("Website",) + HEADER[2:],
        "permuted": (HEADER[1], HEADER[0]) + HEADER[2:],
    }
    for name, head in variants.items():
        add("C09-" + name, emit([first], header=head), refused("header", 0))
    add("C09-absent", emit([first], header=None), refused("header", 0))
    positive("C09-restored", [first], all_quotes=True)
    add("C10-eight", emit([first[:-1]]), refused("row_width"))
    add("C10-ten", emit([first + (token(160),)]), refused("row_width"))
    positive("C10-empty-last", [change(first, 8, "")], final=False)
    positive("C10-header-only", [])
    add("C10-empty-input", b"", refused("missing_header", 0))
    add("C10-extra-blank-record", emit([first]) + b"\r\n", refused("row_width", 2))
    positive("C11-lf", [first, change(second, 8, token(170) + "\n" + chr(0x1f642))], ending="\n")
    add("C11-bare-cr", emit([first], final=False) + b"\r", refused("malformed"))
    positive("C11-splits", [change(first, 3, chr(0x1f642) + chr(34) + chr(13) + chr(10))],
             bom=True, all_quotes=True)
    wire = emit([first])
    add("C12-wire-at", wire, ok([first]), {"wire": len(wire)})
    add("C12-wire-over", wire, refused("wire_limit"), {"wire": len(wire) - 1})
    field_row = change(first, 3, token(180).ljust(64, chr(0x58)))
    add("C12-field-at", emit([field_row]), ok([field_row]), {"field": 64})
    add("C12-field-over", emit([field_row]), refused("field_limit"), {"field": 63})
    staged = sum(len(x.encode("utf-8")) for x in HEADER + first)
    add("C12-staging-at", wire, ok([first]), {"staging": staged})
    add("C12-staging-over", wire, refused("staging_limit"), {"staging": staged - 1})
    add("C12-rows-at", emit([first]), ok([first]), {"rows": 1})
    add("C12-rows-over", emit([first, second]), refused("row_limit", 2), {"rows": 1})
    add("C13-invalid-utf8", header_wire + emit([first], header=None).replace(first[3].encode(), b"\xff"), refused("encoding"))
    add("C13-truncated-utf8", header_wire + emit([first], header=None).replace(first[3].encode(), b"\xf0\x9f"), refused("encoding"))
    add("C13-nul", header_wire + emit([first], header=None).replace(first[3].encode(), b"\x00"), refused("encoding"))
    positive("C13-restored-unicode", [change(first, 3, chr(0x1f642) + token(190))])
    inert = change(first, 3, chr(61) + token(200))
    inert = change(inert, 8, chr(36) + chr(40) + token(201) + chr(41))
    positive("C14-inert", [inert])
    positive("C15-dual", [first])
    positive("C15-otp-only", [change(first, 3, "")])
    positive("C15-empty-credentials", [change(change(first, 3, ""), 4, "")])
    positive("C16-clean", [first])
    add("C16-malformed-with-witnesses", emit([first]) + b'"' + token(210).encode(),
        refused("malformed", 2))
    return result

