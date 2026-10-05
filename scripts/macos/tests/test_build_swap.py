#!/usr/bin/env python3
"""scripts/macos/build-app.sh, run whole with stand-ins for the programs it
drives, never loses the last working app and leaves nothing behind however
it stops (L-08, L-11; docs/APP.md "Build commands").

Each case copies build-app.sh into a short temporary tree beside stand-ins:
cargo (reports two tiny binaries), xcodebuild (writes the two bundles, the
app with a random mark), codesign (does nothing), scripts/macos/sign-check.sh
(passes, or refuses the copy at a chosen site), and mv, mkdir and mktemp
(each counts or holds; mv can fail a chosen move). ditto, install,
PlistBuddy and python3 are the real programs. A stand-in "holds" by writing
held.<name> and waiting for release.<name>, so a signal lands at a known
point: between the two moves of a replacement, during the restore, during
a build step, or just after a staging directory was made.

For both replacements (the output directory, and --install) a case checks:
- where each copy of the app is, read back from the fixture apps' random
  marks, never from the script's messages;
- that no directory the script made is left (the staging directory beside
  the output or the installed app, the work directory), except the one
  holding the only copy of the previous app;
- that no process is left in the script's process group;
- the exit: 0 only when the new app is in place; after a stop by HUP, INT or
  TERM the script ends by that signal, after QUIT with 131;
- that each copy moved into place was sign-checked first.

Every case runs under each bash found: /bin/bash (3.2) and the first other
bash on the usual paths, which `#!/usr/bin/env bash` picks on a Mac with
Homebrew. Each script runs in its own session with a cleared environment,
the four signals at their defaults and a core limit of zero, inside a short
temporary directory that is removed afterwards.

With --script PATH the cases run against another copy of build-app.sh. Run
against the script before this test's round (an EXIT trap only, mktemp names
in command substitutions), the signal, closed-stderr and staging-directory
cases fail; with either sign-check call removed, the sign-check cases fail.

Usage: python3 scripts/macos/tests/test_build_swap.py [--script PATH]
"""

import hashlib
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = {"path": os.path.join(os.path.dirname(HERE), "build-app.sh")}
WAIT = 30.0
STATUS = {"HUP": -signal.SIGHUP, "INT": -signal.SIGINT, "TERM": -signal.SIGTERM, "QUIT": 131}


def bashes():
    found = []
    for path in ("/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash", shutil.which("bash") or ""):
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            real = os.path.realpath(path)
            if real not in [os.path.realpath(p) for p in found]:
                found.append(path)
    return found


HOLD = """hold() {
  : >"$FAKE/held.$1"
  n=0
  while [ ! -e "$FAKE/release.$1" ]; do
    /bin/sleep 0.02
    n=$((n + 1))
    [ "$n" -lt 2000 ] || exit 99
  done
}
"""

STUBS = {
    "cargo": """#!/bin/bash
. "$FAKE/hold.sh"
case "$1" in
  -vV) echo "cargo 1.0.0 (stand-in)"; echo "host: aarch64-apple-darwin"; exit 0 ;;
  build)
    if [ "${CARGO_HOLD:-}" = 1 ]; then hold cargo; fi
    printf '{"reason":"compiler-artifact","target":{"name":"envcloak"},"executable":"%s"}\\n' "$FAKE/bin/envcloak"
    printf '{"reason":"compiler-artifact","target":{"name":"envcloakd"},"executable":"%s"}\\n' "$FAKE/bin/envcloakd"
    exit 0 ;;
esac
exit 64
""",
    "xcodebuild": """#!/bin/bash
. "$FAKE/hold.sh"
dd=""
version=""
while [ $# -gt 0 ]; do
  case "$1" in
    -derivedDataPath) dd="$2"; shift 2 ;;
    MARKETING_VERSION=*) version="${1#MARKETING_VERSION=}"; shift ;;
    *) shift ;;
  esac
done
if [ "${XCODEBUILD_HOLD:-}" = 1 ]; then hold xcodebuild; fi
products="$dd/Build/Products/Release"
for name in EnvCloak EnvCloakAgent; do
  /bin/mkdir -p "$products/$name.app/Contents"
  printf '<?xml version="1.0" encoding="UTF-8"?>\\n<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>%s</string></dict></plist>\\n' "$version" >"$products/$name.app/Contents/Info.plist"
done
/bin/mkdir -p "$products/EnvCloak.app/Contents/MacOS"
printf '#!/bin/sh\n' >"$products/EnvCloak.app/Contents/MacOS/EnvCloakApp"
/bin/cp "$FAKE/new-mark" "$products/EnvCloak.app/mark"
""",
    "codesign": """#!/bin/bash
echo "codesign $*" >>"$FAKE/log"
""",
    "mv": """#!/bin/bash
. "$FAKE/hold.sh"
n=0
IFS= read -r n <"$FAKE/moves" || true
n=$((n + 1))
echo "$n" >"$FAKE/moves"
echo "mv $n $1 -> $2" >>"$FAKE/log"
case " ${MV_FAIL:-} " in *" $n "*) exit 73 ;; esac
if [ "${MV_HOLD_BEFORE:-}" = "$n" ]; then hold "mv$n"; fi
/bin/mv "$@" || exit $?
if [ "${MV_HOLD_AFTER:-}" = "$n" ]; then hold "mv$n"; fi
exit 0
""",
    "mkdir": """#!/bin/bash
. "$FAKE/hold.sh"
/bin/mkdir "$@" || exit $?
if [ -n "${MADE_HOLD:-}" ]; then
  for a in "$@"; do
    case "$a" in *"$MADE_HOLD"*) hold made; break ;; esac
  done
fi
exit 0
""",
    "mktemp": """#!/bin/bash
. "$FAKE/hold.sh"
made="$(/usr/bin/mktemp "$@")" || exit $?
case "$made" in *"${MADE_HOLD:-//}"*) hold made ;; esac
echo "$made"
""",
}

SIGN_CHECK = """#!/bin/bash
. "$FAKE/hold.sh"
echo "sign-check $1" >>"$FAKE/log"
case "$1" in
  */.stage.*) site=output ;;
  */.EnvCloak.install.*) site=install ;;
  *) site=other ;;
esac
if [ "${SIGN_CHECK_HOLD:-}" = "$site" ]; then hold "sign-check-$site"; fi
if [ "${SIGN_CHECK_FAIL:-}" = "$site" ]; then echo "sign-check: refused by the stand-in" >&2; exit 1; fi
exit 0
"""


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def mark_app(path):
    os.makedirs(path)
    data = os.urandom(32)
    with open(os.path.join(path, "mark"), "wb") as f:
        f.write(data)
    return hashlib.sha256(data).digest()


def child_setup():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGPIPE):
        signal.signal(sig, signal.SIG_DFL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Build:
    """One run of build-app.sh in its own tree."""

    def __init__(self, base, bash, site, old_out=True, old_installed=True):
        self.bash = bash
        self.site = site
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="ecbs", dir=base))
        r = self.root
        self.repo = os.path.join(r, "repo")
        self.fake = os.path.join(r, "fake")
        self.stubs = os.path.join(r, "stubs")
        self.out = os.path.join(r, "out")
        self.inst = os.path.join(r, "inst")
        self.dd = os.path.join(r, "dd")
        self.tmp = os.path.join(r, "tmp")
        for d in (self.out, self.inst, self.dd, self.tmp, os.path.join(r, "home"), os.path.join(self.repo, "apps", "macos")):
            os.makedirs(d, exist_ok=True)
        with open(SCRIPT["path"]) as f:
            write(os.path.join(self.repo, "scripts", "macos", "build-app.sh"), f.read(), 0o755)
        write(os.path.join(self.repo, "scripts", "macos", "sign-check.sh"), SIGN_CHECK, 0o755)
        for name, text in STUBS.items():
            write(os.path.join(self.stubs, name), text, 0o755)
        os.symlink(sys.executable, os.path.join(self.stubs, "python3"))
        write(os.path.join(self.fake, "hold.sh"), HOLD)
        write(os.path.join(self.fake, "moves"), "0\n")
        write(os.path.join(self.fake, "log"), "")
        write(os.path.join(self.fake, "bin", "envcloak"), "#!/bin/sh\necho 'envcloak 9.9.9-test'\n", 0o755)
        write(os.path.join(self.fake, "bin", "envcloakd"), "#!/bin/sh\nexit 0\n", 0o755)
        data = os.urandom(32)
        with open(os.path.join(self.fake, "new-mark"), "wb") as f:
            f.write(data)
        self.marks = {"new": hashlib.sha256(data).digest()}
        if old_out:
            self.marks["old-out"] = mark_app(os.path.join(self.out, "EnvCloak.app"))
        if old_installed and site == "install":
            self.marks["old-installed"] = mark_app(os.path.join(self.inst, "EnvCloak.app"))
        self.env = {
            "PATH": self.stubs + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.path.join(r, "home"),
            "TMPDIR": self.tmp,
            "FAKE": self.fake,
            "LC_ALL": "C",
        }
        # The moves at this site: the output replacement's are 1 and 2 (1
        # only on a first build); --install's follow them.
        out_moves = 2 if old_out else 1
        if site == "output":
            self.aside = 1 if old_out else None
            self.move_in = out_moves
        else:
            has_old = old_installed
            self.aside = out_moves + 1 if has_old else None
            self.move_in = out_moves + (2 if has_old else 1)
        self.restore = self.move_in + 1
        self.proc = None
        self.err_path = os.path.join(r, "stderr")
        self.out_path = os.path.join(r, "stdout")

    @property
    def destination(self):
        return os.path.join(self.inst if self.site == "install" else self.out, "EnvCloak.app")

    def start(self, stderr_pipe=False, **env):
        self.env.update({k: str(v) for k, v in env.items()})
        args = [self.bash, os.path.join(self.repo, "scripts", "macos", "build-app.sh"), "--out", self.out, "--derived-data", self.dd]
        if self.site == "install":
            args += ["--install", "--install-dir", self.inst]
        stdout = open(self.out_path, "wb")
        if stderr_pipe:
            self.err_read, err_write = os.pipe()
            stderr = err_write
        else:
            self.err_read = None
            stderr = open(self.err_path, "wb")
        self.proc = subprocess.Popen(
            args, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, preexec_fn=child_setup
        )
        stdout.close()
        if stderr_pipe:
            os.close(err_write)
        else:
            stderr.close()

    def wait_held(self, name):
        path = os.path.join(self.fake, "held." + name)
        deadline = time.monotonic() + WAIT
        while not os.path.exists(path):
            if self.proc.poll() is not None:
                raise AssertionError("the script ended (%s) before %s held\n%s" % (self.proc.returncode, name, self.stderr()))
            if time.monotonic() > deadline:
                raise AssertionError("%s never held\n%s" % (name, self.stderr()))
            time.sleep(0.01)

    def release(self, name):
        write(os.path.join(self.fake, "release." + name), "")

    def signal(self, name, group):
        sig = getattr(signal, "SIG" + name)
        if group:
            os.killpg(self.proc.pid, sig)
        else:
            os.kill(self.proc.pid, sig)

    def finish(self):
        """Waits for the script; returns (status, processes left)."""
        try:
            status = self.proc.wait(timeout=WAIT)
        except Exception:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
            raise AssertionError("the script did not end\n%s" % self.stderr())
        left = True
        for _ in range(20):
            try:
                os.killpg(self.proc.pid, 0)
            except ProcessLookupError:
                left = False
                break
            time.sleep(0.05)
        if left:
            os.killpg(self.proc.pid, signal.SIGKILL)
        if self.err_read is not None:
            try:
                os.close(self.err_read)
            except OSError:
                pass
        return status, left

    def stderr(self):
        try:
            with open(self.err_path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return ""

    def stdout(self):
        with open(self.out_path, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def where(self):
        """{mark name: sorted places}, a place relative to the tree."""
        found = {}
        skip = {self.dd, self.fake}
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in skip]
            if "mark" in filenames:
                with open(os.path.join(dirpath, "mark"), "rb") as f:
                    digest = hashlib.sha256(f.read()).digest()
                for name, value in self.marks.items():
                    if digest == value:
                        found.setdefault(name, []).append(os.path.relpath(dirpath, self.root))
        return {k: sorted(v) for k, v in found.items()}

    def leftovers(self):
        """The script's own directories still present."""
        left = []
        for d, prefix in ((self.out, ".stage."), (self.inst, ".EnvCloak.install."), (self.tmp, "ec-build-app.")):
            for name in os.listdir(d):
                if name.startswith(prefix):
                    left.append(os.path.relpath(os.path.join(d, name), self.root))
        return sorted(left)

    def checked_before_moved(self):
        """Every copy moved to a destination was sign-checked first."""
        with open(os.path.join(self.fake, "log")) as f:
            lines = f.read().splitlines()
        dests = {os.path.join(self.out, "EnvCloak.app"), os.path.join(self.inst, "EnvCloak.app")}
        checked = set()
        moved_in = []
        for line in lines:
            if line.startswith("sign-check "):
                checked.add(line[len("sign-check ") :])
            elif line.startswith("mv "):
                _, _, rest = line.split(" ", 2)
                src, _, dst = rest.partition(" -> ")
                if dst in dests:
                    moved_in.append(dst)
                    if src not in checked:
                        return False, "%s moved to %s unchecked" % (src, dst)
        return True, moved_in

    def remove(self):
        shutil.rmtree(self.root, ignore_errors=True)


def rel_dest(b):
    return os.path.relpath(b.destination, b.root)


class BuildApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="ecbs", dir="/tmp")
        cls.bashes = bashes()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def each(self, case, sites=("output", "install"), **kw):
        for bash in self.bashes:
            for site in sites:
                with self.subTest(bash=bash, site=site):
                    b = Build(self.base, bash, site, **kw)
                    try:
                        case(b)
                    finally:
                        b.remove()

    def at(self, b, name):
        return b.where().get(name, [])

    def old(self, b):
        return "old-installed" if b.site == "install" else "old-out"

    def assertClean(self, b, left, keep=()):
        self.assertFalse(left, "a process was left in the script's group\n" + b.stderr())
        self.assertEqual(b.leftovers(), sorted(keep), b.stderr())

    # ------------------------------------------------------------ outcomes

    def test_a_build_replaces_the_previous_app_after_checking_it(self):
        def case(b):
            b.start()
            status, left = b.finish()
            self.assertEqual(status, 0, b.stderr())
            self.assertEqual(self.at(b, "new"), sorted({"out/EnvCloak.app", rel_dest(b)}))
            self.assertEqual(self.at(b, self.old(b)), [])
            self.assertEqual(b.stdout().splitlines()[-1], b.destination)
            ok, moved = b.checked_before_moved()
            self.assertTrue(ok, moved)
            self.assertIn(b.destination, moved)
            self.assertClean(b, left)

        self.each(case)

    def test_a_first_build_puts_the_new_app_in_place(self):
        def case(b):
            b.start()
            status, left = b.finish()
            self.assertEqual(status, 0, b.stderr())
            self.assertIn(rel_dest(b), self.at(b, "new"))
            self.assertClean(b, left)

        self.each(case, old_out=False, old_installed=False)

    def test_a_failed_move_aside_leaves_the_previous_app(self):
        def case(b):
            b.start(MV_FAIL=b.aside)
            status, left = b.finish()
            self.assertEqual(status, 73, b.stderr())
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertNotIn(rel_dest(b), self.at(b, "new"))
            self.assertClean(b, left)

        self.each(case)

    def test_a_failed_move_in_puts_the_previous_app_back(self):
        def case(b):
            b.start(MV_FAIL=b.move_in)
            status, left = b.finish()
            self.assertEqual(status, 73, b.stderr())
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertIn("the previous app is back at", b.stderr())
            self.assertClean(b, left)

        self.each(case)

    def test_a_failed_move_back_keeps_the_previous_app_and_says_where(self):
        def case(b):
            b.start(MV_FAIL="%d %d" % (b.move_in, b.restore))
            status, left = b.finish()
            self.assertEqual(status, 73, b.stderr())
            places = self.at(b, self.old(b))
            self.assertEqual(len(places), 1, places)
            self.assertTrue(places[0].endswith("/previous.app"), places)
            self.assertIn("the previous app is kept at", b.stderr())
            self.assertClean(b, left, keep=[os.path.dirname(places[0])])

        self.each(case)

    def test_a_failed_first_install_leaves_nothing_in_place(self):
        def case(b):
            b.start(MV_FAIL=b.move_in)
            status, left = b.finish()
            self.assertEqual(status, 73, b.stderr())
            self.assertFalse(os.path.lexists(b.destination))
            self.assertClean(b, left)

        self.each(case, sites=("install",), old_installed=False)

    def test_a_copy_that_fails_sign_check_replaces_nothing(self):
        # Both sign-check calls: without the output's, the unchecked build
        # replaces the previous one; without the install's, the unchecked
        # copy is installed.
        def case(b):
            b.start(SIGN_CHECK_FAIL=b.site)
            status, left = b.finish()
            self.assertEqual(status, 1, b.stderr())
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertNotIn(rel_dest(b), self.at(b, "new"))
            self.assertIn("refused by the stand-in", b.stderr())
            self.assertClean(b, left)

        self.each(case)

    # ------------------------------------------------------------ signals

    def stop_between_moves(self, b, name, group):
        b.start(MV_HOLD_AFTER=b.aside)
        b.wait_held("mv%d" % b.aside)
        b.signal(name, group)
        if not group:
            # Sent to the script alone, it waits for the step in progress.
            time.sleep(0.3)
            self.assertIsNone(b.proc.poll(), "the script ended while its step still ran\n" + b.stderr())
        b.release("mv%d" % b.aside)
        status, left = b.finish()
        self.assertEqual(status, STATUS[name], b.stderr())
        self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
        self.assertNotIn(rel_dest(b), self.at(b, "new"))
        self.assertIn("stopped by SIG" + name, b.stderr())
        self.assertClean(b, left)

    def test_a_signal_to_the_group_between_the_moves_puts_the_previous_app_back(self):
        for name in ("HUP", "INT", "QUIT", "TERM"):
            with self.subTest(signal=name):
                self.each(lambda b: self.stop_between_moves(b, name, group=True))

    def test_a_signal_to_the_script_between_the_moves_puts_the_previous_app_back(self):
        for name in ("HUP", "INT", "QUIT", "TERM"):
            with self.subTest(signal=name):
                self.each(lambda b: self.stop_between_moves(b, name, group=False))

    def test_a_signal_after_both_moves_keeps_both_apps(self):
        # The new app is in place but replace_app had not recorded it: the
        # cleanup keeps the previous one rather than guess.
        def case(b):
            b.start(MV_HOLD_AFTER=b.move_in)
            b.wait_held("mv%d" % b.move_in)
            b.signal("TERM", True)
            status, left = b.finish()
            self.assertEqual(status, -signal.SIGTERM, b.stderr())
            self.assertIn(rel_dest(b), self.at(b, "new"))
            places = self.at(b, self.old(b))
            self.assertEqual(len(places), 1, places)
            self.assertTrue(places[0].endswith("/previous.app"), places)
            self.assertClean(b, left, keep=[os.path.dirname(places[0])])

        self.each(case)

    def test_a_second_signal_does_not_cut_the_restore_short(self):
        def case(b):
            # The restore is the move after the aside: the move in never ran.
            restore = b.aside + 1
            b.start(MV_HOLD_AFTER=b.aside, MV_HOLD_BEFORE=restore)
            b.wait_held("mv%d" % b.aside)
            b.signal("TERM", True)
            b.wait_held("mv%d" % restore)
            b.signal("TERM", True)
            b.signal("INT", True)
            time.sleep(0.1)
            b.release("mv%d" % restore)
            status, left = b.finish()
            self.assertEqual(status, -signal.SIGTERM, b.stderr())
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertClean(b, left)

        self.each(case)

    def test_a_signal_during_a_build_step_leaves_no_step_and_no_directory(self):
        for step, name, group in (("xcodebuild", "TERM", False), ("cargo", "INT", True)):
            with self.subTest(step=step, signal=name, group=group):

                def case(b):
                    b.start(**{step.upper() + "_HOLD": 1})
                    b.wait_held(step)
                    b.signal(name, group)
                    if not group:
                        time.sleep(0.3)
                        self.assertIsNone(b.proc.poll(), "the script ended while %s still ran\n%s" % (step, b.stderr()))
                    b.release(step)
                    status, left = b.finish()
                    self.assertEqual(status, STATUS[name], b.stderr())
                    self.assertEqual(self.at(b, "old-out"), ["out/EnvCloak.app"])
                    self.assertClean(b, left)

                self.each(case, sites=("output",))

    def test_a_signal_just_after_a_staging_directory_is_made_leaves_none(self):
        # The stand-in holds after making the directory and before the
        # script can record its name.
        def case(b):
            b.start(MADE_HOLD="/.stage." if b.site == "output" else "/.EnvCloak.install.")
            b.wait_held("made")
            b.signal("TERM", True)
            status, left = b.finish()
            self.assertEqual(status, -signal.SIGTERM, b.stderr())
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertClean(b, left)

        self.each(case)

    def test_a_closed_standard_error_still_gets_the_whole_cleanup(self):
        # The reader of standard error goes away mid-build; the failed move
        # in still puts the previous app back and removes every directory,
        # though the cleanup's message cannot be written.
        def case(b):
            b.start(stderr_pipe=True, SIGN_CHECK_HOLD=b.site, MV_FAIL=b.move_in)
            b.wait_held("sign-check-" + b.site)
            os.close(b.err_read)
            b.err_read = None
            b.release("sign-check-" + b.site)
            status, left = b.finish()
            self.assertNotEqual(status, 0)
            self.assertEqual(self.at(b, self.old(b)), [rel_dest(b)])
            self.assertClean(b, left)

        self.each(case)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--script"] and len(args) >= 2:
        SCRIPT["path"] = os.path.abspath(args[1])
        args = args[2:]
    if not bashes():
        print("test_build_swap: no bash found", file=sys.stderr)
        sys.exit(1)
    os.umask(0o077)
    unittest.main(argv=[sys.argv[0]] + args, verbosity=2)


if __name__ == "__main__":
    main()
