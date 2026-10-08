"""Independent cycle579-infisical-oracle-r1.py semantic corpus. Documented format, not tool output.
Reduced research caps are excluded by the adapter; production bounds have Rust tests.
"""
import csv
import io
import json

TEXT = ("key", "value", "workspace", "type", "_id", "secretPath", "comment", "Etag")
FIELDS = TEXT + ("tags", "skipMultilineEncoding")
TAG_FIELDS = ("id", "name", "slug", "color")

def token(index):
    return "".join(chr(n) for n in (118, 75, 113, 90, 114)) + str(index) + chr(95) + chr(84)


def tag(index):
    return {name: token(index * 20 + i) for i, name in enumerate(TAG_FIELDS)}


def record(index):
    obj = {name: token(index * 20 + i) for i, name in enumerate(TEXT)}
    obj.update(tags=None, skipMultilineEncoding=False)
    return obj


def changed(obj, **edits):
    return dict(obj, **edits)


def emit(obj, ascii_only=False):
    return json.dumps(obj, ensure_ascii=ascii_only, separators=(",", ":")).encode("utf-8")


def ok(rows, declared=False):
    return {"status": "ok", "reason": None,
            "entries": tuple((i, row["key"], row["value"]) for i, row in enumerate(rows)),
            "schema_match": "matched", "parsing_complete": True,
            "provenance": "user_declared" if declared else "unknown",
            "qualified_version": None, "upstream_total": None,
            "coverage_scope": "supplied_file_supported_fields",
            "durable_writes": 0, "source_retained": "not_touched"}


def refused(reason):
    result = ok([])
    result.update(status="refused", reason=reason, schema_match="refused", parsing_complete=False)
    return result


def cases():
    corpus = []
    def add(identity, wire, expected, limits=None, declaration=None, claim=None):
        corpus.append(dict(id=identity, wire=wire, expected=expected, limits=limits,
                           declaration=declaration, claim=claim))
    def positive(identity, rows, ascii_only=False, declaration=None, claim=None):
        expected = ok(rows, declaration is not None)
        add(identity, emit(rows, ascii_only), expected, declaration=declaration, claim=claim)
    first, second = record(1), record(2)
    positive("I01-null-tags", [first])
    positive("I01-empty-tags", [changed(first, tags=[])])
    empty_metadata = changed(first, **{name: "" for name in TEXT if name not in ("key", "value")})
    positive("I02-tag-object-empty-text", [changed(empty_metadata, tags=[tag(9)])])
    positive("I02-empty-tag-text", [changed(first, tags=[dict.fromkeys(TAG_FIELDS, "")])])
    positive("I03-equal-label", [first, changed(second, key=first["key"])])
    special = (
        ("lf", token(200) + chr(10) + token(201)),
        ("literal-slash-n", token(202) + chr(92) + chr(110) + chr(0x00e9)),
        ("unicode", " " + chr(0x00e9) + chr(101) + chr(0x301) + chr(0x1f642) + "\t "),
    )
    for name, value in special:
        for flag in (False, True):
            positive("I04-" + name + "-" + str(int(flag)),
                     [changed(first, value=value, skipMultilineEncoding=flag)], ascii_only=flag)
    positive("I04-empty-value", [changed(first, value="")])
    for field in FIELDS:
        absent = dict(first)
        del absent[field]
        add("I05-missing-" + field, emit([absent]), refused("missing_member"))
    positive("I05-restored", [first])
    for field in TEXT:
        add("I06-text-type-" + field, emit([changed(first, **{field: 7})]), refused("member_type"))
    for name, value in (("integer", 1), ("string", token(260)), ("null", None)):
        add("I06-boolean-" + name, emit([changed(first, skipMultilineEncoding=value)]),
            refused("member_type"))
    add("I06-tags-object", emit([changed(first, tags=tag(9))]), refused("member_type"))
    add("I06-tag-element-string", emit([changed(first, tags=[token(261)])]), refused("wrong_shape"))
    for field in TAG_FIELDS:
        invalid_tag = changed(tag(9), **{field: False})
        add("I06-tag-type-" + field, emit([changed(first, tags=[invalid_tag])]), refused("member_type"))
        missing_tag = tag(9)
        del missing_tag[field]
        add("I06-tag-missing-" + field, emit([changed(first, tags=[missing_tag])]), refused("missing_member"))
    positive("I06-restored", [changed(first, tags=[tag(9)], skipMultilineEncoding=True)])
    add("I07-unknown-record", emit([changed(first, unknown=token(270))]), refused("unknown_member"))
    wrong_case = dict(first)
    wrong_case["etag"] = wrong_case.pop("Etag")
    add("I07-case-record", emit([wrong_case]), refused("unknown_member"))
    add("I07-unknown-tag", emit([changed(first, tags=[changed(tag(9), unknown=token(271))])]),
        refused("unknown_member"))
    wrong_tag = tag(9)
    wrong_tag["Name"] = wrong_tag.pop("name")
    add("I07-case-tag", emit([changed(first, tags=[wrong_tag])]), refused("unknown_member"))
    # Duplicate members must be represented as wire, never as a dictionary.
    encoded = emit(first)
    duplicate = encoded[:-1] + b',"value":' + emit(token(272)) + b'}'
    add("I07-duplicate-record", b'[' + duplicate + b']', refused("duplicate_member"))
    original_tag = emit(tag(9))
    duplicate_tag = original_tag[:-1] + b',"name":' + emit(token(273)) + b'}'
    wire = emit([changed(first, tags=[tag(9)])]).replace(original_tag, duplicate_tag, 1)
    add("I07-duplicate-tag", wire, refused("duplicate_member"))
    escaped_duplicate = encoded[:-1] + b',"val\\u0075e":' + emit(token(274)) + b'}'
    add("I07-escaped-duplicate", b'[' + escaped_duplicate + b']', refused("duplicate_member"))
    positive("I07-restored", [first])
    positive("I08-empty-array", [])
    add("I08-null-root", b"null", refused("wrong_shape"))
    add("I08-object-root", emit(first), refused("wrong_shape"))
    add("I08-string-record", emit([token(280)]), refused("wrong_shape"))
    positive("I08-restored", [first])
    bad_last = changed(second, skipMultilineEncoding=token(281))
    add("I09-late-invalid", emit([first, bad_last]), refused("member_type"))
    add("I09-truncated", emit([first, second])[:-1], refused("invalid_json"))
    positive("I09-restored", [first, second])
    positive("I10-no-declaration", [first])
    positive("I10-user-declaration", [first], declaration="v0.43.139")
    positive("I10-forged-receipt", [first], claim={"verified": True, "version": "v0.43.139"})
    positive("I10-declared-forged", [first], declaration="v0.43.139", claim={"verified": True})
    add("I11-non-json-constant", emit([first]).replace(emit(first["value"]), b"NaN"), refused("invalid_json"))
    add("I11-unpaired-surrogate", emit([first]).replace(emit(first["value"]), b'"\\ud800"'), refused("invalid_unicode"))
    add("I11-invalid-utf8", b"\xff", refused("invalid_json"))
    add("I11-trailing-data", emit([first]) + b"null", refused("invalid_json"))
    positive("I11-restored", [first])
    wire = emit([first])
    add("I12-wire-at", wire, ok([first]), limits={"wire": len(wire)})
    add("I12-wire-over", wire, refused("wire_limit"), limits={"wire": len(wire) - 1})
    field_row = changed(first, value=token(290).ljust(80, chr(88)))
    add("I12-field-at", emit([field_row]), ok([field_row]), limits={"field": 80})
    add("I12-field-over", emit([field_row]), refused("field_limit"), limits={"field": 79})
    decoded = sum(len(name.encode()) for name in FIELDS) + sum(len(first[name].encode()) for name in TEXT)
    add("I12-decoded-at", wire, ok([first]), limits={"decoded": decoded})
    add("I12-decoded-over", wire, refused("decoded_limit"), limits={"decoded": decoded - 1})
    add("I12-records-at", emit([first]), ok([first]), limits={"records": 1})
    add("I12-records-over", emit([first, second]), refused("record_limit"), limits={"records": 1})
    nested = [changed(first, tags=[tag(9)])]
    add("I12-depth-at", emit(nested), ok(nested), limits={"depth": 4})
    add("I12-depth-over", emit(nested), refused("depth_limit"), limits={"depth": 3})
    return corpus

