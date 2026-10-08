#!/usr/bin/env python3
"""Mutation controls for the runtime-oracle execution receipt."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile

spec = importlib.util.spec_from_file_location("oracles", Path(__file__).with_name("check-managed-oracles.py"))
oracles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracles)


class ExecutionReceipt(unittest.TestCase):
    def test_every_case_is_required(self):
        lines = [f"test {name} ... ok\n" for name in sorted(oracles.EXPECTED)]
        summary = f"test result: ok. {len(oracles.EXPECTED)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        good = "".join(lines) + summary
        self.assertTrue(oracles.complete(0, good))
        self.assertFalse(oracles.complete(101, good))
        for line in lines:
            for changed in ("", line.replace("ok", "ignored"), line.replace("ok", "FAILED")):
                self.assertFalse(oracles.complete(0, good.replace(line, changed)))
        self.assertFalse(oracles.complete(0, good + lines[0]))
        self.assertFalse(oracles.complete(0, good.replace("0 filtered out", "1 filtered out")))
        self.assertFalse(oracles.complete(0, ""))


class ArchiveAdmission(unittest.TestCase):
    def test_changed_archive_never_reaches_extraction_or_build(self):
        spec = importlib.util.spec_from_file_location("provision", Path(__file__).with_name("provision-managed-oracles.py"))
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        with tempfile.TemporaryDirectory(prefix="eco", dir="/tmp") as directory:
            root = Path(directory)
            name, url, digest, flags, binary = provision.SOURCES[0]
            (root / url.rsplit("/", 1)[1]).write_bytes(b"changed archive")
            with patch.object(provision.tarfile, "open", side_effect=AssertionError("unchecked archive reached extraction")) as extract, patch.object(provision.subprocess, "run") as build:
                with self.assertRaisesRegex(ValueError, "archive digest mismatch"):
                    provision.provision(root)
                extract.assert_not_called()
                build.assert_not_called()

    def test_changed_deno_archive_is_never_extracted(self):
        spec = importlib.util.spec_from_file_location("provision", Path(__file__).with_name("provision-managed-oracles.py"))
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        with tempfile.TemporaryDirectory(prefix="eco", dir="/tmp") as directory:
            root = Path(directory)
            for key, (name, digest) in provision.DENO.items():
                (root / name).write_bytes(b"changed archive")
                with patch.object(provision.platform, "system", return_value=key[0]), \
                        patch.object(provision.platform, "machine", return_value=key[1]), \
                        patch.object(provision.zipfile, "ZipFile", side_effect=AssertionError("unchecked archive reached extraction")) as extract:
                    with self.assertRaisesRegex(ValueError, "archive digest mismatch: deno"):
                        provision.provision_deno(root)
                    extract.assert_not_called()


if __name__ == "__main__":
    unittest.main()
