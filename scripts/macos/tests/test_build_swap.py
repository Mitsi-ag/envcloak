#!/usr/bin/env python3
"""The replacement in scripts/macos/build-app.sh never loses the last
working app (L-08, L-11): both call sites (the output directory and
--install) run the script's own `cleanup` and `replace_app` functions and
its own call lines, taken from the script text, on directories made here,
with `mv` wrapped so that a chosen move fails or the shell exits right
after one. Each fixture app holds random bytes, so where each copy ended
up is read back without trusting the script's messages.

No app is built, signed or installed: only the replacement runs, in a shell
started with a cleared environment and a core limit of zero, inside a short
temporary directory that is removed afterwards.

With --script PATH the same cases run against another copy of the script;
run against build-app.sh as it was before this test (it moved the previous
app into the staging directory, then deleted that directory on a failed
second move), the failure cases fail.

Usage: python3 scripts/macos/tests/test_build_swap.py [--script PATH]
"""

import hashlib
import os
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = {"path": os.path.join(os.path.dirname(HERE), "build-app.sh")}

OUTPUT_CALL = 'replace_app "$app" "$out/EnvCloak.app" "$stage/previous.app"'
INSTALL_CALL = 'replace_app "$incoming/EnvCloak.app" "$dest/EnvCloak.app" "$incoming/previous.app"'


def function(text, name):
    start = text.index(name + "() {\n")
    return text[start : text.index("\n}\n", start) + 3]


def call_site(text, install):
    if "replace_app() {" in text:
        line = INSTALL_CALL if install else OUTPUT_CALL
        if text.count(line) != 1:
            raise AssertionError("build-app.sh no longer has one `%s`" % line)
        return line
    # The script before replace_app: its two inline replacements.
    start = text.index('if [ -e "$dest/EnvCloak.app" ]; then' if install else 'if [ -e "$out/EnvCloak.app" ]; then')
    end = text.index('\n  rm -rf "$incoming"' if install else '\napp="$out/EnvCloak.app"', start)
    return text[start:end]


def digest(path):
    return hashlib.sha256(open(path, "rb").read()).digest() if os.path.isfile(path) else None


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Replacement(unittest.TestCase):
    def run_case(self, install, old=True, refuse=(), stop=0):
        """Runs one call site. `refuse` lists the moves (counted from 1)
        that fail; `stop` is a move after which the shell exits. Returns
        (exit status, where the new copy is, where the old copy is)."""
        text = open(SCRIPT["path"]).read()
        functions = function(text, "cleanup")
        if "replace_app() {" in text:
            functions += function(text, "replace_app")
        with tempfile.TemporaryDirectory(prefix="ecbs", dir="/tmp") as root:
            dirs = {name: os.path.join(root, name) for name in ("out", "stage", "dest", "incoming", "home")}
            for d in dirs.values():
                os.mkdir(d)
            candidate = os.path.join(dirs["incoming"] if install else dirs["stage"], "EnvCloak.app")
            destination = os.path.join(dirs["dest"] if install else dirs["out"], "EnvCloak.app")
            backup = os.path.join(dirs["incoming"] if install else dirs["stage"], "previous.app")
            new_mark = self.app(candidate)
            old_mark = self.app(destination) if old else None
            artifacts = os.path.join(root, "artifacts")
            open(artifacts, "w").close()
            values = dict(out=dirs["out"], stage=dirs["stage"], dest=dirs["dest"], incoming=dirs["incoming"], app=candidate, artifacts=artifacts)
            shell = "set -euo pipefail\n"
            shell += "".join("%s=%s\n" % (k, shlex.quote(v)) for k, v in values.items())
            shell += 'pending_backup=""\npending_destination=""\n' + functions + "trap cleanup EXIT\n"
            shell += "moves=0\nmv() {\n  moves=$((moves + 1))\n"
            if refuse:
                shell += "  case $moves in %s) return 73 ;; esac\n" % "|".join(map(str, refuse))
            shell += '  /bin/mv "$@" || return $?\n'
            if stop:
                shell += '  if [ "$moves" = %d ]; then exit 74; fi\n' % stop
            shell += "}\n" + call_site(text, install) + "\n"
            env = {"HOME": dirs["home"], "TMPDIR": root, "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            p = subprocess.Popen(
                ["/bin/bash", "--noprofile", "--norc", "-c", shell],
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=no_core,
            )
            try:
                _, err = p.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
                self.fail("the replacement shell did not finish")
            places = {"destination": destination, "backup": backup, "candidate": candidate}
            new_at = sorted(k for k, path in places.items() if digest(os.path.join(path, "mark")) == new_mark)
            old_at = sorted(k for k, path in places.items() if old and digest(os.path.join(path, "mark")) == old_mark)
            self.assertFalse(os.path.exists(artifacts), "cleanup left the cargo report")
            return p.returncode, new_at, old_at, err.decode()

    @staticmethod
    def app(path):
        os.mkdir(path)
        data = os.urandom(32)
        with open(os.path.join(path, "mark"), "wb") as f:
            f.write(data)
        return hashlib.sha256(data).digest()

    def each_site(self, check, **case):
        for install in (False, True):
            with self.subTest(site="install" if install else "output", **{k: str(v) for k, v in case.items()}):
                check(*self.run_case(install, **case))

    def test_a_replacement_installs_the_new_app_and_drops_the_old(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 0, err)
            self.assertEqual(new_at, ["destination"])
            self.assertEqual(old_at, [])

        self.each_site(check)

    def test_a_first_install_installs_the_new_app(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 0, err)
            self.assertEqual(new_at, ["destination"])

        self.each_site(check, old=False)

    def test_a_failed_move_aside_leaves_the_previous_app(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 73, err)
            self.assertEqual(old_at, ["destination"])

        self.each_site(check, refuse=(1,))

    def test_a_failed_move_in_puts_the_previous_app_back(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 73, err)
            self.assertEqual(old_at, ["destination"])
            self.assertIn("the previous app is back at", err)

        self.each_site(check, refuse=(2,))

    def test_a_failed_move_back_keeps_the_previous_app_and_says_where(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 73, err)
            self.assertEqual(old_at, ["backup"])
            self.assertIn("the previous app is kept at", err)

        self.each_site(check, refuse=(2, 3))

    def test_a_failed_first_install_leaves_nothing_installed(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 73, err)
            self.assertNotIn("destination", new_at)

        self.each_site(check, old=False, refuse=(1,))

    def test_a_stop_between_the_moves_puts_the_previous_app_back(self):
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 74, err)
            self.assertEqual(old_at, ["destination"])

        self.each_site(check, stop=1)

    def test_a_stop_after_both_moves_keeps_both(self):
        # The new app is in place but replace_app had not recorded it: the
        # cleanup keeps the previous one rather than guess.
        def check(code, new_at, old_at, err):
            self.assertEqual(code, 74, err)
            self.assertEqual(new_at, ["destination"])
            self.assertEqual(old_at, ["backup"])

        self.each_site(check, stop=2)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--script"] and len(args) >= 2:
        SCRIPT["path"] = os.path.abspath(args[1])
        args = args[2:]
    unittest.main(argv=[sys.argv[0]] + args, verbosity=2)


if __name__ == "__main__":
    main()
