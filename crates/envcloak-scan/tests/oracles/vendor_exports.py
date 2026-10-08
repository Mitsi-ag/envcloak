"""Emit private bytes and independent semantic expectations to the Rust harness."""
import base64
import importlib.util
import json
from pathlib import Path

result = []
for module, kind in [("vendor_csv", "1password-csv"), ("vendor_infisical", "infisical-json")]:
    path = Path(__file__).with_name(module + ".py")
    spec = importlib.util.spec_from_file_location(module, path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    for case in oracle.cases():
        if case["limits"] is not None:
            continue
        expected = case["expected"]
        if kind == "1password-csv":
            # Empty credentials reach the shared daemon policy. The research
            # oracle omits them from its candidate count, but preserves rows.
            entries = [(i + 1, "PASSWORD", row[3]) for i, row in enumerate(expected["rows"])]
        else:
            entries = [(i + 1, name, value) for i, name, value in expected["entries"]]
        result.append(dict(id=case["id"], kind=kind,
                           wire=base64.b64encode(case["wire"]).decode(),
                           ok=expected["status"] == "ok", entries=entries))
print(json.dumps(result, ensure_ascii=True))
