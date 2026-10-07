"""Cycle570: pure synthetic scrub-plan oracle, never a product gate result.

Run --self-test for a count-only receipt. make_cases() separates public request
inputs from emitter-built hidden expectations; a future product adapter gets
ONLY a deep copy of request. It must not import this emitter/checker.
All sources are small in-memory generated buffers, never real transcripts.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys

CASE_IDS = tuple("O%02d" % i for i in range(1, 16))


def tag(item):
    return "[envcloak:redacted:" + item + "]"


def chunk(item, encoded=False, confirmed=True):
    return {"item": item, "encoded": encoded, "confirmed": confirmed}


def emit(file_id, parts, jsonl=False):
    # Expected preview is emitted alongside the source, fragment by fragment;
    # no completed-source search, range application, or reference planner call.
    source = bytearray()
    preview = bytearray()
    boundaries = {0}
    observations, expected_edits = [], []
    tokens = {}
    for part in parts:
        if isinstance(part, bytes):
            start = len(source)
            source.extend(part)
            preview.extend(part)
            position = start
            for character in part.decode("utf-8"):
                position += len(character.encode("utf-8"))
                boundaries.add(position)
            continue
        item = part["item"]
        if item not in tokens:
            tokens[item] = secrets.token_hex(16).encode("ascii")
        value = tokens[item]
        if part["encoded"]:
            units = [("\\u%04x" % byte).encode("ascii") for byte in value]
            mapping = "json"
        else:
            units = [bytes([byte]) for byte in value]
            mapping = "raw"
        start = len(source)
        for unit in units:
            source.extend(unit)
            boundaries.add(len(source))
        end = len(source)
        observation = {"start": start, "end": end, "item": item,
                       "marker": tag(item), "mapping": mapping,
                       "rewritable": True, "confirmed": part["confirmed"]}
        observations.append(observation)
        if part["confirmed"]:
            preview.extend(tag(item).encode("ascii"))
            expected_edits.append({k: observation[k] for k in (
                "start", "end", "item", "marker", "mapping")})
        else:
            preview.extend(b"".join(units))
    binding = hashlib.sha256(source).hexdigest()
    for observation in observations:
        observation["source_sha256"] = binding
    pending = any(not o["confirmed"] for o in observations)
    request = {"id": file_id, "source_hex": bytes(source).hex(),
               "boundaries": sorted(boundaries), "jsonl": jsonl,
               "complete": True, "count_only": False,
               "observations": observations}
    expected = {"id": file_id, "status": "partial" if pending else "ready",
                "reasons": ["unconfirmed"] if pending else [],
                "edits": expected_edits, "preview_hex": bytes(preview).hex()}
    if jsonl:
        for data in (bytes(source), bytes(preview)):
            for line in data.splitlines():
                json.loads(line)
    return request, expected


def basic(file_id="F01", parts=None):
    return emit(file_id, parts or [b"before|", chunk("item-a"), b"|after\n"])


def refuse(pair, reason):
    request, expected = pair
    expected.update(status="refused", reasons=[reason], edits=[],
                    preview_hex=request["source_hex"])
    return pair


def nested(file_id):
    pair = basic(file_id)
    o = copy.deepcopy(pair[0]["observations"][0])
    o.update(start=o["start"] + 2, end=o["end"] - 2,
             item="item-b", marker=tag("item-b"))
    pair[0]["observations"].append(o)
    return refuse(pair, "overlap")


def make_cases():
    cases = []
    def add(case_id, pairs, status=None):
        # Expected aggregate is specified here, never obtained from plan().
        if status is None:
            status = pairs[0][1]["status"]
        cases.append({"request": {"id": case_id, "files": [p[0] for p in pairs]},
                      "expected": {"id": case_id, "status": status,
                                   "files": [p[1] for p in pairs]}})
    add("O01", [basic()])
    add("O02", [emit("F01", [
        '{"text":"pré😀|'.encode("utf-8"),
        chunk("item-a", encoded=True), b'|tail"}\r\n'], jsonl=True)])
    add("O03", [basic(parts=[b"p|", chunk("item-a"), b"|",
                            chunk("item-b"), b"|q\n"])])
    add("O04", [basic(parts=[b"p|", chunk("item-a"), b"|",
                            chunk("item-a"), b"|", chunk("item-a"), b"|q\n"])])
    duplicate = basic()
    duplicate[0]["observations"] += [copy.deepcopy(duplicate[0]["observations"][0])
                                     for _ in range(3)]
    add("O05", [duplicate])
    add("O06", [basic(parts=[b"p|", chunk("item-a"), chunk("item-b"), b"|q\n"])])
    add("O07", [nested("F01")])
    cross = basic(parts=[b"p|", chunk("item-a"), chunk("item-b"), b"|q\n"])
    cross[0]["observations"][0]["end"] += 3
    add("O08", [refuse(cross, "overlap")])
    conflict = basic()
    o = copy.deepcopy(conflict[0]["observations"][0])
    o.update(item="item-b", marker=tag("item-b"))
    conflict[0]["observations"].append(o)
    add("O09", [refuse(conflict, "overlap")])
    counts = basic()
    counts[0].update(count_only=True, observations=[])
    add("O10", [refuse(counts, "count_only")])
    unsupported = basic()
    unsupported[0]["observations"][0].update(rewritable=False, mapping="encoded")
    add("O11", [refuse(unsupported, "unsupported")])
    invalid = []
    for i, kind in enumerate(("negative", "empty", "reversed", "overrun", "boolean")):
        pair = basic("F%02d" % (i + 1))
        o = pair[0]["observations"][0]
        if kind == "negative": o["start"] = -1
        if kind == "empty": o["end"] = o["start"]
        if kind == "reversed": o["start"], o["end"] = o["end"], o["start"]
        if kind == "overrun": o["end"] = len(bytes.fromhex(pair[0]["source_hex"])) + 1
        if kind == "boolean": o["start"] = False
        invalid.append(refuse(pair, "bounds"))
    split = emit("F06", [b'{"text":"', chunk("item-a", encoded=True), b'"}\n'], jsonl=True)
    split[0]["observations"][0]["start"] += 1
    invalid.append(refuse(split, "bounds"))
    stale = basic("F07")
    stale[0]["observations"][0]["source_sha256"] = "0" * 64
    invalid.append(refuse(stale, "binding"))
    add("O12", invalid, "refused")
    incomplete = basic()
    incomplete[0]["complete"] = False
    add("O13", [refuse(incomplete, "incomplete")])
    add("O14", [basic(parts=[b"p|", chunk("item-a"), b"|",
                            chunk("item-b", confirmed=False), b"|q\n"])], "partial")
    add("O15", [basic("F01"), nested("F02")], "partial")
    assert tuple(c["request"]["id"] for c in cases) == CASE_IDS
    return cases


def canonical_edits(edits):
    return sorted(edits, key=lambda e: (
        e["start"], e["end"], e["item"], e["marker"], e["mapping"]))


def assess(case, observed):
    request, expected = case["request"], case["expected"]
    if set(observed) != {"id", "status", "files"} or observed["id"] != expected["id"]:
        return "shape"
    ids = [f.get("id") for f in observed["files"]]
    wanted = [f["id"] for f in expected["files"]]
    if sorted(ids) != sorted(wanted):
        return "files"
    if observed["status"] != expected["status"]:
        return "aggregate"
    by_id = {f["id"]: f for f in observed["files"]}
    request_by_id = {f["id"]: f for f in request["files"]}
    for e in expected["files"]:
        got = by_id[e["id"]]
        if set(got) != {"id", "status", "reasons", "edits", "preview_hex"}:
            return "shape"
        if got["status"] != e["status"]:
            return "status"
        if sorted(got["reasons"]) != sorted(e["reasons"]):
            return "reasons"
        if canonical_edits(got["edits"]) != canonical_edits(e["edits"]):
            return "edits"
        if got["preview_hex"] != e["preview_hex"]:
            return "preview"
        if request_by_id[e["id"]]["jsonl"]:
            try:
                for line in bytes.fromhex(got["preview_hex"]).splitlines():
                    json.loads(line)
            except (ValueError, UnicodeError):
                return "json"
    return "ok"


def assess_set(cases, observations):
    ids = [o.get("id") for o in observations]
    if sorted(ids) != list(CASE_IDS):
        return "case_set"
    by_id = {o["id"]: o for o in observations}
    for case in cases:
        result = assess(case, by_id[case["request"]["id"]])
        if result != "ok":
            return result
    return "ok"


def self_test():
    location = Path(__file__).with_name("cycle570-scrub-plan-reference.py")
    spec = importlib.util.spec_from_file_location("scrub_reference", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = make_cases()
    baseline = [module.plan(copy.deepcopy(c["request"])) for c in cases]
    assert assess_set(cases, baseline) == "ok"
    reverse = []
    for case in cases:
        request = copy.deepcopy(case["request"])
        request["files"].reverse()
        for f in request["files"]:
            f["observations"].reverse()
        reverse.append(module.plan(request))
    reverse.reverse()
    assert assess_set(cases, reverse) == "ok"
    controls = []
    def attack(label, case_index, expected_failure, change):
        observed = copy.deepcopy(baseline[case_index])
        change(observed)
        failure = assess(cases[case_index], observed)
        assert failure == expected_failure
        controls.append({"id": label, "caught": True, "class": failure})
    attack("M01-refuse-all", 0, "aggregate", lambda o: o.update(status="refused"))
    attack("M02-drop-escaped", 1, "edits", lambda o: o["files"][0].update(edits=[]))
    attack("M03-collapse-occurrences", 3, "edits", lambda o: o["files"][0]["edits"].pop())
    attack("M04-duplicate-edit", 4, "edits", lambda o: o["files"][0]["edits"].append(
        copy.deepcopy(o["files"][0]["edits"][0])))
    attack("M05-refuse-adjacency", 5, "aggregate", lambda o: o.update(status="refused"))
    attack("M06-accept-nested", 6, "aggregate", lambda o: o.update(status="ready"))
    attack("M07-accept-crossing", 7, "aggregate", lambda o: o.update(status="ready"))
    attack("M08-pick-association", 8, "aggregate", lambda o: o.update(status="ready"))
    attack("M09-promote-counts", 9, "aggregate", lambda o: o.update(status="ready"))
    attack("M10-promote-encoded", 10, "aggregate", lambda o: o.update(status="ready"))
    attack("M11-clip-bounds", 11, "status", lambda o: o["files"][0].update(status="ready"))
    attack("M12-ignore-incomplete", 12, "aggregate", lambda o: o.update(status="ready"))
    attack("M13-hide-unconfirmed", 13, "reasons", lambda o: o["files"][0].update(reasons=[]))
    attack("M14-hide-partial-file", 14, "aggregate", lambda o: o.update(status="ready"))
    attack("M15-unrelated-rewrite", 0, "preview", lambda o: o["files"][0].update(
        preview_hex=(b"X" + bytes.fromhex(o["files"][0]["preview_hex"])[1:]).hex()))
    attack("M16-drop-refused-file", 14, "files", lambda o: o["files"].pop())
    attack("M17-wrong-marker", 0, "edits", lambda o: o["files"][0]["edits"][0].update(
        marker=tag("other-item")))
    attack("M18-invalid-escape-authority", 11, "status",
           lambda o: o["files"][5].update(status="ready"))
    attack("M19-stale-input-authority", 11, "status",
           lambda o: o["files"][6].update(status="ready"))
    attack("M20-false-refusal-reason", 6, "reasons",
           lambda o: o["files"][0].update(reasons=["incomplete"]))
    for label, selected in (
        ("M21-missing-case", baseline[:-1]),
        ("M22-duplicate-case", baseline[:-1] + [baseline[0]])):
        assert assess_set(cases, selected) == "case_set"
        controls.append({"id": label, "caught": True, "class": "case_set"})
    # Restore an ordinary positive after the refusal controls.
    assert assess(cases[0], module.plan(copy.deepcopy(cases[0]["request"]))) == "ok"
    positive_ids = CASE_IDS[:6]
    assert all(cases[i]["expected"]["files"][0]["edits"] for i in range(6))
    return {"schema": "envcloak-scrub-plan-self-check-v1", "cycle": 570,
            "status": "PASS", "qualification": "oracle_self_only",
            "case_ids": list(CASE_IDS), "cases": len(cases),
            "file_cases": sum(len(c["request"]["files"]) for c in cases),
            "forward_passed": len(baseline), "reversed_passed": len(reverse),
            "positive_nonempty_cases": list(positive_ids), "restored_positive": True,
            "controls": controls, "controls_caught": len(controls),
            "product_executed": False, "gate37_passed": False,
            "fixtures_written": False, "fixture_values_printed": False}


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        print(json.dumps({"status": "REFUSED", "reason": "self_test_only"}))
        raise SystemExit(2)
    try:
        receipt = self_test()
    except Exception:
        # Never emit an exception repr/traceback containing fixture content.
        print(json.dumps({"status": "FAIL", "reason": "self_check_failed"}))
        raise SystemExit(1)
    print(json.dumps(receipt, sort_keys=True))
