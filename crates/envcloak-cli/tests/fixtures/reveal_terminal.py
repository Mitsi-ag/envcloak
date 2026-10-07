"""Independent PTY observer. Reports counts only, never fixture bytes.

The kernel supplies the controlling terminal and its termios state. CLI
stdout/stderr use different files. Prompt observations, not sleeps, drive
proof entry and acknowledgement. Signals target our unreaped child only.
"""
import base64
import errno
import fcntl
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import urllib.parse

spec = json.load(open(sys.argv[1], encoding="utf-8"))
value = bytes.fromhex(spec["value"])
proof = bytes.fromhex(spec["proof"])
master, slave = pty.openpty()
before = termios.tcgetattr(slave)
output = tempfile.TemporaryFile()
errors = tempfile.TemporaryFile()
start_read, start_write = os.pipe()
ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(start_write)
    os.close(ready_read)
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.dup2(slave, 0)
    os.dup2(output.fileno(), 1)
    os.dup2(errors.fileno(), 2)
    os.close(master)
    os.close(slave)
    if spec.get("ancestor_name"):
        reveal = subprocess.Popen(sys.argv[2:])
        if os.read(start_read, 1) != b'1':
            raise RuntimeError('missing proof barrier')
        # Exec keeps this session leader's process instance and its child.
        # Only its argv identity changes, which can tighten but never grant.
        os.set_inheritable(ready_write, True)
        reaper = """import os, sys
os.write(int(sys.argv[2]), b'1')
os.close(int(sys.argv[2]))
_, status = os.waitpid(int(sys.argv[1]), 0)
sys.exit(os.waitstatus_to_exitcode(status))
"""
        os.execve(sys.executable, [spec["ancestor_name"], '-c', reaper,
                                  str(reveal.pid), str(ready_write)], os.environ)
    if spec.get("sibling"):
        # Keep the agent alive in this terminal while a sibling gives a
        # proof. The request itself may lead another session (F-70).
        agent_code = """import subprocess, sys
command = [sys.argv[1], 'run', '--manifest', sys.argv[2], '--', '/bin/true']
if len(sys.argv) > 3:
    command = [sys.argv[3], '--session', '--'] + command
out = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
assert b'approval_required' in out.stderr
print('pending', flush=True)
sys.stdin.buffer.read(1)
"""
        argv = [spec["sibling"], '--', sys.executable, '-c', agent_code, sys.argv[2], spec["manifest"]]
        if spec.get("through"):
            argv.append(spec["through"])
        reveal = None
        if spec.get("late"):
            reveal = subprocess.Popen(sys.argv[2:])
            if os.read(start_read, 1) != b'1':
                raise RuntimeError('missing prompt barrier')
        agent = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            if agent.stdout.readline() != b'pending\n':
                raise RuntimeError('no pending request control')
            if reveal is None:
                code = subprocess.call(sys.argv[2:])
            else:
                os.write(ready_write, b'1')
                code = reveal.wait(timeout=20)
        finally:
            agent.stdin.close()
            agent.wait(timeout=20)
        os._exit(code)
    os.execv(sys.argv[2], sys.argv[2:])

os.close(start_read)
os.close(ready_write)
shown = bytearray()
proof_sent = False
ack_sent = False
proof_echo_off = False
waited_for_ack = False
finished = False
interrupted = False
proof_barrier = False
ancestor_changed = False
start = time.monotonic()
status = None
try:
    while time.monotonic() - start < 45:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError as e:
                if e.errno != errno.EIO:
                    raise
                chunk = b""
            shown.extend(chunk)
        if b"Vault passphrase to reveal this: " in shown and not proof_sent:
            if spec.get("late"):
                os.write(start_write, b'1')
                if not select.select([ready_read], [], [], 20)[0] or os.read(ready_read, 1) != b'1':
                    raise RuntimeError('missing pending request barrier')
            proof_echo_off = not (termios.tcgetattr(slave)[3] & termios.ECHO)
            if spec.get("interrupt") == "proof":
                os.kill(pid, signal.SIGTERM)
                interrupted = True
            else:
                os.write(master, proof + b"\n")
            proof_sent = True
        if spec.get("ancestor_name") and proof_sent and not proof_barrier:
            if os.path.exists(spec["proof_reached"]):
                proof_barrier = True
                os.write(start_write, b'1')
                if not select.select([ready_read], [], [], 20)[0] or os.read(ready_read, 1) != b'1':
                    raise RuntimeError('missing ancestor exec barrier')
                ancestor_changed = True
                with open(spec["proof_release"], 'wb') as release:
                    release.write(b'release')
        if b"Press Enter to finish: " in shown and not ack_sent:
            # A non-reaping kernel observation. Exiting instead of waiting
            # cannot pass even when output scheduling happens to line up.
            waited_for_ack = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
            if spec.get("interrupt") == "ack":
                os.kill(pid, signal.SIGTERM)
                interrupted = True
            else:
                os.write(master, b"\n")
            ack_sent = True
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            finished = True
            break
    if not finished:
        os.killpg(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        finished = True
        raise RuntimeError("terminal child deadline")
    # Drain bytes already written after the child's exit; slave stays
    # open only to measure restored flags, so EOF is not a drain fence.
    while select.select([master], [], [], 0)[0]:
        shown.extend(os.read(master, 65536))
    after = termios.tcgetattr(slave)
    output.seek(0)
    errors.seek(0)
    stdout = output.read()
    stderr = errors.read()
    def encodings(raw):
        return set([raw, raw.hex().encode(), raw.hex().upper().encode(),
                    base64.b64encode(raw), base64.b64encode(raw).rstrip(b'='),
                    base64.urlsafe_b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b'='),
                    urllib.parse.quote_from_bytes(raw).encode(),
                    json.dumps(raw.decode(), ensure_ascii=True)[1:-1].encode()])
    value_forms = encodings(value)
    proof_forms = encodings(proof)
    def hits(stream, forms):
        return sum(stream.count(form) for form in forms)
    def controls(stream):
        return sum(c not in '\r\n' and (ord(c) < 32 or 127 <= ord(c) <= 159)
                   for c in stream.decode('utf-8', errors='replace'))
    print(json.dumps({
        "code": os.waitstatus_to_exitcode(status),
        "stdout_bytes": len(stdout),
        "stdout_leak_hits": hits(stdout, value_forms | proof_forms),
        "stderr_leak_hits": hits(stderr, value_forms | proof_forms),
        "proof_leak_hits": hits(shown, proof_forms),
        "tty_hits": shown.count(value),
        "stdout_hits": stdout.count(value),
        "stderr_hits": stderr.count(value),
        "proof_hits": shown.count(proof),
        "control_hits": (b"control=" + value).count(value),
        "control_terminal_controls": controls(value),
        "tty_controls": controls(shown),
        "warning": b"a terminal an agent drives can read what is shown here; scrollback keeps it" in shown,
        "warning_at": shown.find(b"a terminal an agent drives can read what is shown here; scrollback keeps it"),
        "prompt_at": shown.find(b"Vault passphrase to reveal this: "),
        "value_at": shown.find(value),
        "ack_at": shown.find(b"Press Enter to finish: "),
        "prompt": proof_sent,
        "ack": ack_sent,
        "waited": waited_for_ack,
        "echo_off": proof_echo_off,
        "restored": before == after,
        "interrupted": interrupted,
        "proof_barrier": proof_barrier,
        "ancestor_changed": ancestor_changed,
        "refused": b"proof_refused" in stderr,
        "audit_failed": b"audit_failed" in stderr,
        "invalid_value": b"invalid_value" in stderr,
        "app_required": b"app_required" in stderr,
        "traced": b"traced" in stderr,
    }))
finally:
    if not finished:
        os.killpg(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(master)
    os.close(slave)
    os.close(start_write)
    os.close(ready_read)
    output.close()
    errors.close()
