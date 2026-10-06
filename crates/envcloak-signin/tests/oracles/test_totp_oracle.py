"""Runner controls, separate from the independent TOTP calculations."""
import importlib.util
from pathlib import Path
import subprocess
import re
import os
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("totp_oracle", Path(__file__).with_name("totp_oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class NodeRunnerTests(unittest.TestCase):
    def test_fuzz_handoff_names_parser_and_owner(self):
        handoff = Path("docs/SIGNIN.md").read_text()
        self.assertIn("M2-25/M2b fuzz handoff: add an `otpauth::parse` target", handoff)
        self.assertIn("No libFuzzer run is claimed.", handoff)

    def test_sha1_source_confinement_ignores_exposure_exceptions(self):
        source_spec = importlib.util.spec_from_file_location("totp_sources", Path("scripts/totp_sources.py"))
        sources = importlib.util.module_from_spec(source_spec)
        source_spec.loader.exec_module(sources)
        allowed = Path("crates/envcloak-signin/src/totp.rs")
        for path in [Path("crates/envcloak-signin/src/otpauth.rs"),
                     Path("crates/envcloak-core/src/example.rs"), Path("tests/example.rs")]:
            for reference in ["sha1::block_api::compress(&mut [0; 5], &[[0; 64]]);",
                              "use sha1 as digest;", "extern crate sha1 as digest;",
                              "use ::{sha1 as digest};", "r#sha1 /* gap */ ::block_api::compress;",
                              "#[cfg(any())] fn hidden() { sha1::block_api::compress; }"]:
                source = "#[allow(clippy::disallowed_methods)] fn fixture() { " + reference + " }"
                with self.subTest(path=str(path), reference=reference):
                    self.assertEqual(sources.source_problem(path, source), "SHA-1 outside totp.rs")
                    self.assertIsNone(sources.source_problem(allowed, source))
        self.assertIsNone(sources.source_problem(Path("crates/envcloak-signin/tests/totp.rs"),
                                                'match alg { "sha1" => 1, _ => 2 }'))
        self.assertIsNotNone(sources.source_problem(Path("crates/envcloak-signin/tests/sha1_canary.rs"),
                                                   "fn unguarded() {}"))
        self.assertIsNotNone(sources.source_problem(Path("crates/envcloak-signin/src/otpauth.rs"),
                                                   "#[expect(clippy::disallowed_types)] fn fixture() {}"))
        for path in [Path("Cargo.toml"), Path("crates/envcloak-signin/Cargo.toml"),
                     Path("crates/envcloak-core/Cargo.toml")]:
            self.assertIsNotNone(sources.manifest_problem(path,
                {"target": {"cfg(any())": {"dependencies": {"legacy": {"package": "sha1"}}}}}))
        self.assertIsNone(sources.manifest_problem(Path("Cargo.toml"),
                                                   {"workspace": {"dependencies": {"sha1": "0.11"}}}))
        self.assertIsNotNone(sources.manifest_problem(Path("crates/envcloak-core/Cargo.toml"),
                                                     {"dependencies": {"sha1": "0.11"}}))
        with tempfile.TemporaryDirectory(prefix="tps-", dir=os.environ.get("TMPDIR", "/tmp")) as temporary:
            root = Path(temporary)
            for relative in ["crates/example/src/lib.rs", "fuzz/targets/example.rs", "example.rs"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#[allow(clippy::disallowed_methods)] fn fixture() { sha1::block_api::compress; }")
                with self.assertRaisesRegex(SystemExit, "SHA-1 outside totp.rs"):
                    sources.check_sources(root)
                path.write_text("fn fixture() {}")
                sources.check_sources(root)

    def test_ci_runs_independent_oracle_with_isolation(self):
        workflow = Path(".github/workflows/ci.yml").read_text()
        self.assertIn("        run: scripts/check-totp-oracle.sh\n", workflow)
        script = Path("scripts/check-totp-oracle.sh").read_text()
        self.assertIn("env -i", script)
        self.assertIn('TMPDIR="$scratch"', script)
        self.assertIn("python3 -I -B crates/envcloak-signin/tests/oracles/totp_oracle.py", script)
        node_setup = workflow.split("- uses: actions/setup-node@v4", 1)[1].split("- uses:", 1)[0]
        self.assertNotIn("if:", node_setup)

    def test_receipt_commit_references_survive_rebase(self):
        receipt = Path("docs/M2B-03A-VALIDATION.md").read_text()
        section = receipt.split("## Commits\n", 1)[1].split("\n## ", 1)[0]
        references = re.findall(r"(?m)^- `([^`]+)`", section)
        self.assertGreaterEqual(len(references), 6)
        self.assertTrue(all(subject.startswith("M2 M2b-03a: ") for subject in references))
        self.assertFalse(re.search(r"\b[0-9a-f]{7,40}\b", section))

    def test_every_node_call_has_a_deadline(self):
        result = subprocess.CompletedProcess(["node"], 0, b"{}", b"")
        with patch.object(oracle.subprocess, "run", return_value=result) as run:
            self.assertIs(oracle.run_node(b"[]", {"HOME": "fixture"}), result)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.kwargs["env"], {"HOME": "fixture"})
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_runner_failures_have_fixed_diagnostics(self):
        for failure in [subprocess.TimeoutExpired("fixture", 30), OSError("fixture")]:
            with self.subTest(kind=type(failure).__name__):
                with patch.object(oracle.subprocess, "run", side_effect=failure):
                    with self.assertRaises(RuntimeError) as raised:
                        oracle.run_node(b"[]", {})
                self.assertEqual(str(raised.exception), "Node oracle unavailable")
                self.assertTrue(raised.exception.__suppress_context__)

    def test_compiler_call_has_a_deadline_and_fixed_failures(self):
        # Exercise the Python body of the shell checker with an owned
        # compiler failure. The normal canary run checks real compilation.
        script = Path("scripts/check-totp-lint.sh").read_text()
        body = script.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        for failure in [subprocess.TimeoutExpired("fixture", 600), OSError("fixture")]:
            with self.subTest(kind=type(failure).__name__):
                with patch.object(subprocess, "run", side_effect=failure) as run:
                    with self.assertRaises(SystemExit) as raised:
                        exec(compile(body, "check-totp-lint.sh", "exec"), {})
                self.assertEqual(run.call_args.kwargs["timeout"], 600)
                self.assertEqual(str(raised.exception), "check-totp-lint: compiler unavailable")
                self.assertTrue(raised.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
