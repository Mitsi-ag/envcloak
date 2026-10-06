"""Runner controls, separate from the independent TOTP calculations."""
import importlib.util
from pathlib import Path
import subprocess
import re
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("totp_oracle", Path(__file__).with_name("totp_oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class NodeRunnerTests(unittest.TestCase):
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
