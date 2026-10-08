#!/usr/bin/env python3
"""The macos-app CI job runs every script test whole: each
scripts/macos/tests/test_*.py has a step that runs it with no class named,
so a test class nobody listed (as sign-check's case-clash class once was)
cannot sit unrun while the job is green. A file that also needs a build
(--app, --derived-data) is run again with it; that run may name classes.

Reads .github/workflows/ci.yml as text: the job is the block from
`  macos-app:` to the next job at the same indentation.

Usage: python3 scripts/macos/tests/test_ci_job.py
"""

import os
import re
import sys
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")


def job(text, name):
    start = re.search(r"^  %s:\n" % re.escape(name), text, re.M)
    if not start:
        return None
    end = re.search(r"^  [A-Za-z0-9_-]+:\n", text[start.end() :], re.M)
    return text[start.start() : start.end() + end.start()] if end else text[start.start() :]


def whole_runs(block, name):
    """Lines that run scripts/macos/tests/<name> with nothing after it."""
    pattern = re.compile(r"^\s*(?:run:\s*)?python3 scripts/macos/tests/%s\s*$" % re.escape(name), re.M)
    return pattern.findall(block)


class CIJob(unittest.TestCase):
    def test_ui_failures_keep_results_and_run_independent_checks(self):
        with open(CI) as f:
            block = job(f.read(), "macos-app")
        steps = re.split(r'^      - ', block, flags=re.M)
        uploads = [step for step in steps if 'uses: actions/upload-artifact@' in step]
        self.assertEqual(len(uploads), 1, 'failed UI tests need their xcresult artifact')
        self.assertRegex(uploads[0], r'if:.*failure\(\)')
        for path in ['target/m305-ui/Logs/Test/*.xcresult', 'target/m306-ui/Logs/Test/*.xcresult',
                     '${{ runner.temp }}/dd-*/Logs/Test/*.xcresult']:
            self.assertIn(path, uploads[0])
        for name in ['EU-1 paste, bindings, exact undo and canary sweep',
                     'Compiled Swift sources are the scanned sources']:
            step = next(step for step in steps if step.startswith('name: ' + name))
            self.assertIn('!cancelled()', step, name + ' must still run after a UI failure')

    def test_every_script_test_runs_whole_in_macos_app(self):
        with open(CI) as f:
            block = job(f.read(), "macos-app")
        self.assertIsNotNone(block, "ci.yml has no macos-app job")
        tests = sorted(n for n in os.listdir(HERE) if re.match(r"^test_.*\.py$", n))
        self.assertIn("test_ci_job.py", tests)
        for name in tests:
            with self.subTest(test=name):
                self.assertTrue(whole_runs(block, name), "macos-app does not run scripts/macos/tests/%s whole" % name)

    def test_the_reader_finds_a_missing_run(self):
        # Positive control: a job without the line, and one that names a
        # class, are both found.
        block = "  macos-app:\n    steps:\n      - run: python3 scripts/macos/tests/test_sign_check.py SignCheck\n"
        self.assertEqual(whole_runs(block, "test_sign_check.py"), [])
        self.assertEqual(whole_runs(block, "test_build_swap.py"), [])
        self.assertTrue(whole_runs("        run: python3 scripts/macos/tests/test_sign_check.py\n", "test_sign_check.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
