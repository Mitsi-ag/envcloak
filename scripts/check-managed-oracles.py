#!/usr/bin/env python3
"""Require every managed runtime oracle to execute, not merely exit zero."""
import re
import subprocess
import sys

EXPECTED = frozenset((
    "php_attached_file_selects_the_actual_entry",
    "python_attached_options_can_import_before_the_entry",
    "npm_configuration_names_match_without_case",
    "python_startup_environment_cannot_select_unchecked_code",
    "bash_login_startup_is_refused_for_declarations_updates_and_shebangs",
    "luajit_module_options_load_code_before_the_entry",
))


def complete(code, output):
    passed = re.findall(r"^test (\w+) \.\.\. ok$", output, re.MULTILINE)
    summary = f"test result: ok. {len(EXPECTED)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
    return code == 0 and len(passed) == len(EXPECTED) and set(passed) == EXPECTED and summary in output


def main():
    result = subprocess.run([
        "cargo", "test", "--locked", "--no-fail-fast", "-p", "envcloak-policy",
        "--test", "managed_interpreter_oracle", "--", "--include-ignored",
        "--test-threads", "3", "--nocapture",
    ], stdout=subprocess.PIPE, text=True, check=False)
    print(result.stdout, end="")
    if not complete(result.returncode, result.stdout):
        sys.exit("managed runtime oracles did not all execute successfully")


if __name__ == "__main__":
    main()
