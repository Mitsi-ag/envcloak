"""Native M3-07 gates. All processes get cleared environments and owned lifetimes."""
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

SUITE, BINARY, FIXTURES = sys.argv[1:]
FIXTURES = Path(FIXTURES)
IDENTITIES = json.loads((FIXTURES / "identities.json").read_text())
EXCEPTIONS = ["allow-jit", "allow-unsigned-executable-memory", "allow-dyld-environment-variables",
              "disable-library-validation", "disable-executable-page-protection", "debugger"]
METHODS = ["app.unlock", "app.approve", "app.reveal", "app.paste", "app.policy.set",
           "app.device.add", "app.device.remove", "app.registry.override", "app.future"]


def read_exact(pipe, count):
    result = b""
    while len(result) < count:
        if not select.select([pipe], [], [], 30)[0]:
            raise AssertionError("fixture read timed out")
        part = os.read(pipe.fileno(), count - len(result))
        if not part:
            raise AssertionError("fixture closed before its receipt")
        result += part
    return result


def send(child, method="app.unlock", params=None):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    child.stdin.write(struct.pack("!I", len(data)) + data)
    child.stdin.flush()


def response(child):
    length = struct.unpack("!I", read_exact(child.stdout, 4))[0]
    assert length < 8192
    return json.loads(read_exact(child.stdout, length))


class Native(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="ecp", dir="/tmp"))
        self.env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "XDG_CONFIG_HOME": str(self.home / "config"), "XDG_DATA_HOME": str(self.home / "data"),
                    "XDG_STATE_HOME": str(self.home / "state"), "TMPDIR": str(self.home)}
        self.children = []
        self.run_dir = self.home / "Library/Application Support/EnvCloak/run"
        self.run_dir.mkdir(parents=True, mode=0o700)
        self.socket = str(self.run_dir / "envcloakd.sock")

    def tearDown(self):
        for child in reversed(self.children):
            # Own unreaped session leader. Never signal a group after wait or
            # poll released its leader's pid; fixture parents reap their children.
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
        shutil.rmtree(self.home)

    def child(self, args, extra=None, executable=None):
        child = subprocess.Popen(args, env=self.env | (extra or {}), stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                 start_new_session=True, executable=executable)
        self.children.append(child)
        return child

    def signed_copy(self, source, identifier, foreign=False):
        dest = self.home / ("copy-" + str(len(list(self.home.glob("copy-*")))))
        shutil.copyfile(source, dest)
        dest.chmod(0o700)
        identity = IDENTITIES[int(foreign)]
        subprocess.run([str(FIXTURES / "sign_peer"), identity["keychain"], identity["certificate"],
                        str(dest), identifier, "65536", ""], env=self.env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return str(dest)

    def daemon(self):
        daemon = self.signed_copy(BINARY, "ai.envcloak.agent")
        child = self.child([daemon, "--foreground"], {"ENVCLOAK_TEST_TRACE": "1"})
        # The daemon's own listen receipt is the startup barrier.
        log = b""
        while b"listening" not in log:
            log += read_exact(child.stderr, 1)
        self.daemon_child = child

    def peer(self, name, mode="call", extra=None):
        args = [str(FIXTURES / (name + "-peer")), mode, self.socket]
        if mode in ["exec", "pass", "reconnect"]:
            args.append(str(FIXTURES / "unsigned-peer"))
        return self.child(args, extra)

    def facts(self, name):
        file = str(FIXTURES / (name + "-peer"))
        got = subprocess.run([str(FIXTURES / "facts"), file], env=self.env, check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return json.loads(got.stdout)[file]


class App(Native):
    def test_cli_status_uses_verified_connection(self):
        self.daemon()
        cli = self.child([os.environ["ENVCLOAK_CLI_PROBE"], "status", "--json"])
        out, err = cli.communicate(timeout=30)
        self.assertEqual(cli.returncode, 0, err)
        self.assertEqual(json.loads(out)["daemon"]["identity"], "verified")

    def test_g1_positive(self):
        facts = self.facts("genuine")
        self.assertTrue(facts["runtime"])
        self.assertEqual(facts["identifier"], "ai.envcloak.app")
        self.daemon()
        child = self.peer("genuine")
        send(child)
        self.assertEqual(response(child)["error"]["data"]["kind"], "method_not_found")

    def test_g4_forged_and_gate19_entitlements(self):
        self.daemon()
        names = ["unsigned", "adhoc", "foreign", "debuggable", "no-runtime", *EXCEPTIONS, "debuggable-false", *[e + "-false" for e in EXCEPTIONS]]
        for name in names:
            with self.subTest(peer=name):
                facts = self.facts(name)
                if name in EXCEPTIONS:
                    self.assertIn("com.apple.security.cs." + name, facts["entitlements"])
                elif name == "debuggable":
                    self.assertIn("com.apple.security.get-task-allow", facts["entitlements"])
                elif name == "no-runtime":
                    self.assertFalse(facts["runtime"])
                child = self.peer(name)
                send(child)
                self.assertEqual(response(child)["error"]["data"]["kind"], "role_denied", name)
                child.stdin.close()
                self.assertEqual(child.wait(timeout=10), 0)
        self.daemon_child.terminate()
        _, log = self.daemon_child.communicate(timeout=10)
        self.assertEqual(log.count(b"reason=role_denied role=client"), len(names))

    def test_gate22_all_methods_are_denied_and_audited(self):
        self.daemon()
        for method in METHODS:
            child = self.peer("unsigned")
            send(child, method, {"claims": [], "arbitrary": "ignored before role admission"})
            reply = response(child)
            self.assertEqual(reply["error"]["data"]["kind"], "role_denied")
            self.assertNotIn("result", reply)
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 0)
        self.daemon_child.terminate()
        _, log = self.daemon_child.communicate(timeout=10)
        self.assertEqual(log.count(b"reason=role_denied role=client"), len(METHODS))

    def test_signed_claims_only_tighten_and_hostile_claims_fail(self):
        self.daemon()
        for claims, kind in [([], "method_not_found"), (["CODEX_CI"], "proof_refused"),
                             (None, "invalid_params"), ("CODEX_CI", "invalid_params"),
                             (["\u0000"], "invalid_params"), (["é"], "invalid_params"),
                             (["A"] * 17, "invalid_params")]:
            child = self.peer("genuine")
            send(child, params={"claims": claims})
            self.assertEqual(response(child)["error"]["data"]["kind"], kind)
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 0)
        # Locking only tightens; still reserved in M3-07.
        child = self.peer("genuine")
        send(child, "app.lock", {"claims": ["CODEX_CI"]})
        self.assertEqual(response(child)["error"]["data"]["kind"], "method_not_found")

    def test_g4_exec_and_passed_descriptor(self):
        self.daemon()
        for mode in ["exec", "pass"]:
            with self.subTest(mode=mode):
                child = self.peer("genuine", mode)
                send(child)
                self.assertEqual(response(child)["error"]["data"]["kind"], "method_not_found")
                send(child)
                self.assertEqual(read_exact(child.stdout, 7), b"CLOSED\n")
                self.assertEqual(child.wait(timeout=10), 0)

    def test_g4_reconnect_after_exec_is_checked_again(self):
        self.daemon()
        child = self.peer("genuine", "reconnect")
        send(child)
        self.assertEqual(response(child)["error"]["data"]["kind"], "method_not_found")
        send(child)
        self.assertEqual(response(child)["error"]["data"]["kind"], "role_denied")
        child.stdin.close()
        self.assertEqual(child.wait(timeout=10), 0)

    def test_signed_agent_ancestry_and_cut_chain_are_refused(self):
        self.daemon()
        genuine = str(FIXTURES / "genuine-peer")
        agent = self.home / "fixture-agent"
        shutil.copyfile(genuine, agent)
        agent.chmod(0o700)
        for args in [[str(agent), "parent", self.socket, genuine],
                     [genuine, "chain", self.socket, "65"]]:
            child = self.child(args)
            send(child)
            self.assertEqual(response(child)["error"]["data"]["kind"], "proof_refused")
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 0)

    def test_gate19_dyld_constructor_control(self):
        self.daemon()
        for name, expected in [("no-runtime", True), ("genuine", False)]:
            marker = self.home / (name + ".marker")
            child = self.peer(name, extra={"DYLD_INSERT_LIBRARIES": str(FIXTURES / "constructor.dylib"),
                                          "EC_CONSTRUCTOR_MARKER": str(marker)})
            send(child)
            response(child) # proves the main ran after dyld completed
            self.assertEqual(marker.exists(), expected)
            child.stdin.close()
            self.assertEqual(child.wait(timeout=10), 0)


class Client(Native):
    def test_g1_client_before_send(self):
        for foreign in [False, True]:
            with self.subTest(foreign=foreign):
                if os.path.exists(self.socket):
                    os.unlink(self.socket)
                daemon = self.signed_copy(FIXTURES / "base", "ai.envcloak.agent", foreign)
                server = self.child([daemon, "listen", self.socket])
                self.assertEqual(read_exact(server.stdout, 6), b"READY\n")
                probe = self.child([BINARY, str(self.run_dir)])
                out, err = probe.communicate(timeout=30)
                self.assertEqual(err, b"")
                server_out, server_err = server.communicate(timeout=30)
                self.assertEqual(server.returncode, 0, server_err)
                count = int(server_out)
                if foreign:
                    self.assertEqual((probe.returncode, count), (125, 0), out)
                    self.assertIn(b"CodeIdentity", out)
                    self.assertEqual(count, 0)
                else:
                    self.assertEqual(probe.returncode, 124, out)
                    self.assertEqual(out, b"verified\n")
                    self.assertGreater(count, 4)


if __name__ == "__main__":
    os.umask(0o077)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(App if SUITE == "app" else Client)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
