#!/usr/bin/env python3
"""Independent models of two of this task's checks, run with no process
started and no build read (an independent review's check, adopted with its
positive controls):

- procgroup.Group's cleanup, with every process, signal, process census
  and clock replaced: whatever state the group is in when close() runs (the
  leader ended at once, members still live for a while, a leader that ends
  late, the group already gone (ESRCH) or only zombies left (EPERM)), the
  group is killed and found quiet before the leader is reaped, the leader
  is reaped once, close() is idempotent, and nothing is signalled or
  counted after the reap; a group that never goes quiet raises at the
  deadline without reaping; and waiting for the leader never reaps it.
  test_build_swap.py's own `run_case` closes a case before removing its
  tree, on success and when the case raises.
- check_compiled_swift.py's record inventory, on synthetic build records
  under a short temporary directory: two complete targets of the same name
  in different directories pass; each of the three records beside a Swift
  file list, removed in turn from each target, is refused, and passes again
  once restored; a link list or linker record with no Swift file list is
  refused; a test-class source in a target whose linker wrote a prelinked
  object is refused, and passes once the linker's record says it wrote a
  .xctest bundle.

The real processes and builds are test_build_swap.py's, Stopped's and
RealBuild's; these models pin the control flow those tests rely on.

Usage: python3 scripts/macos/tests/test_owned_cleanup_and_records.py
"""

import contextlib
import importlib.util
import io
import json
import os
import signal
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
sys.path.insert(0, str(HERE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def no_process(*args, **kwargs):
    raise AssertionError("unexpected process operation")


class GroupCleanupModel(unittest.TestCase):
    def fixture(self, live_rounds=0, ended_rounds=0, kill_error=None):
        mod = load("owned_cleanup", HERE / "procgroup.py")
        mod.subprocess = types.SimpleNamespace(Popen=no_process, run=no_process)
        events, now = [], [0.0]
        state = {"live_rounds": live_rounds, "ended_rounds": ended_rounds, "live": False}
        pid = 12345

        def kill(p, sig):
            self.assertEqual((p, sig), (pid, signal.SIGKILL))
            events.append("kill")
            if kill_error:
                raise kill_error()

        def census(p):
            self.assertEqual(p, pid)
            state["live"] = state["live_rounds"] > 0
            state["live_rounds"] -= 1
            events.append("live" if state["live"] else "quiet")
            return [pid + 1] if state["live"] else []

        def peek(kind, p, flags):
            # P_PID, the pid, WEXITED | WNOHANG | WNOWAIT: never a reap.
            self.assertEqual((kind, p, flags), (1, pid, 14))
            events.append("peek")
            state["ended_rounds"] -= 1
            return object() if state["ended_rounds"] < 0 else None

        def wait(timeout):
            self.assertGreater(timeout, 0)
            self.assertFalse(state["live"], "reaped while a member was live")
            self.assertEqual(events[-1], "peek", "reaped before the leader was seen to end")
            events.append("reap")
            return -9

        mod.os = types.SimpleNamespace(killpg=kill, kill=no_process, waitid=peek, P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8)
        mod.live_in_group = census
        mod.time = types.SimpleNamespace(monotonic=lambda: now[0], sleep=lambda dt: now.__setitem__(0, now[0] + dt))
        g = mod.Group.__new__(mod.Group)
        g.pgid, g.status = pid, None
        g.proc = types.SimpleNamespace(wait=wait)
        return g, events

    def test_close_kills_then_reaps_once_in_every_state(self):
        for live, ended, error in [(0, 0, None), (2, 0, None), (0, 2, None), (0, 0, ProcessLookupError), (0, 0, PermissionError)]:
            with self.subTest(live=live, ended=ended, error=error):
                g, events = self.fixture(live, ended, error)
                self.assertEqual(g.close(bound=1), -9)
                self.assertEqual(events.count("reap"), 1)
                self.assertEqual(events[-1], "reap")
                self.assertIn("kill", events)
                before = list(events)
                self.assertEqual(g.close(), -9)
                self.assertTrue(g.ended())
                self.assertTrue(g.wait_ended(0))
                self.assertEqual(events, before)
                for action in (g.live, lambda: g.signal(signal.SIGTERM)):
                    with self.assertRaises(AssertionError):
                        action()
                self.assertEqual(events, before, "a group was used after its leader was reaped")

    def test_a_group_that_never_goes_quiet_fails_without_a_reap(self):
        g, events = self.fixture(999, 999, PermissionError)
        with self.assertRaises(AssertionError):
            g.close(bound=0.1)
        self.assertIsNone(g.status)
        self.assertNotIn("reap", events)

    def test_waiting_for_the_leader_never_reaps_it(self):
        g, events = self.fixture(0, 999)
        self.assertFalse(g.wait_ended(0.02))
        self.assertIsNone(g.status)
        self.assertTrue(events and all(e == "peek" for e in events))

    def test_run_case_closes_before_removing_on_success_and_failure(self):
        swap = load("build_swap_model", HERE / "test_build_swap.py")
        for early in (False, True):
            with self.subTest(early=early):
                events = []
                fake = types.SimpleNamespace(close=lambda: events.append("close"), remove=lambda: events.append("remove"))
                swap.Build = lambda *a, **kw: fake

                def case(b):
                    self.assertIs(b, fake)
                    events.append("case")
                    if early:
                        raise LookupError()

                try:
                    swap.BuildApp.run_case(types.SimpleNamespace(base=None), case, None, None)
                except LookupError:
                    self.assertTrue(early)
                self.assertEqual(events, ["case", "close", "remove"])


class RecordInventoryModel(unittest.TestCase):
    def check(self, mod, derived, listing, expected, needle=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mod.main(["checker", str(derived), str(listing)])
        self.assertEqual(code, expected, err.getvalue())
        if needle:
            self.assertIn(needle, err.getvalue())

    def test_each_record_is_required_and_the_kind_comes_from_the_output(self):
        mod = load("compiled_inventory", SCRIPTS / "check_compiled_swift.py")
        mod.subprocess = types.SimpleNamespace(run=no_process)
        with tempfile.TemporaryDirectory(prefix="ecir", dir="/tmp") as owned:
            root = Path(os.path.realpath(owned))
            derived = root / "derived"
            dev = root / "developer"
            dev.mkdir()
            mod.developer_dir = lambda: str(dev)
            listing = root / "source-list"
            records = []
            for index in range(2):
                directory = derived / "Build/Intermediates.noindex" / str(index)
                directory.mkdir(parents=True)
                base = directory / "SameName"
                source = root / ("unit%d.swift" % index)
                source.write_text("")
                obj = directory / ("unit%d.o" % index)
                output = derived / "Build/Products/Debug" / ("lib%d.o" % index)
                files = {
                    Path(str(base) + mod.SUFFIX): (str(source) + "\n").encode(),
                    Path(str(base) + mod.LINK_SUFFIX): (str(obj) + "\n").encode(),
                    Path(str(base) + mod.MAP_SUFFIX): json.dumps({str(source): {"object": str(obj)}}).encode(),
                    Path(str(base) + mod.DEP_SUFFIX): b"\x00linker\x00\x10" + str(obj).encode() + b"\x00\x40" + str(output).encode() + b"\x00",
                }
                for p, data in files.items():
                    p.write_bytes(data)
                records.append((base, source))
            listing.write_text("".join("product %s\n" % source for _, source in records))

            # Positive control: both complete targets pass.
            self.check(mod, derived, listing, 0)
            for base, _ in records:
                for suffix in (mod.LINK_SUFFIX, mod.MAP_SUFFIX, mod.DEP_SUFFIX):
                    with self.subTest(target=base.parent.name, missing=suffix):
                        p = Path(str(base) + suffix)
                        saved = p.read_bytes()
                        p.unlink()
                        self.check(mod, derived, listing, 1, "compiles Swift but the build left no")
                        p.write_bytes(saved)
                        self.check(mod, derived, listing, 0)
            for suffix in (mod.LINK_SUFFIX, mod.DEP_SUFFIX):
                with self.subTest(unpaired=suffix):
                    p = derived / "Build/Intermediates.noindex" / ("Unpaired" + suffix)
                    p.write_bytes(b"")
                    self.check(mod, derived, listing, 1, "which compiles no Swift file this check reads")
                    p.unlink()
                    self.check(mod, derived, listing, 0)
            # The kind comes from the linker's output, not the name.
            base, source = records[0]
            listing.write_text("test %s\nproduct %s\n" % (source, records[1][1]))
            self.check(mod, derived, listing, 1, "which ships, but check-swift.sh reads it as a test file")
            dep = Path(str(base) + mod.DEP_SUFFIX)
            output = derived / "Build/Products/Debug/Verified.xctest/Contents/MacOS/Verified"
            obj = Path(str(base) + mod.LINK_SUFFIX).read_text().strip()
            dep.write_bytes(b"\x00linker\x00\x10" + obj.encode() + b"\x00\x40" + str(output).encode() + b"\x00")
            self.check(mod, derived, listing, 0)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
