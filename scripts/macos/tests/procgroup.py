"""A command the script tests run in a session of its own, and its cleanup
(L-03: never signal a process by a bare pid after it may have been reaped).

The command is the leader of its session and of its process group, whose id
is the leader's pid. The leader is never reaped before the whole group is
gone: until it is, no other process can take that pid, so every signal
sent here, to the group or to the leader, reaches this test's processes and
no one else's. Whether the leader has ended is read with
waitid(WEXITED | WNOWAIT), which leaves it waiting to be reaped.

close() is the only place the leader is reaped. It sends SIGKILL to the
group until ps shows no live member (a zombie waiting to be reaped is no
step left running; macOS answers kill(-pgid, ...) with EPERM while the
only members left are zombies), then reaps the leader. When the group
cannot be confirmed empty within its bound, it raises: a cleanup that did
not happen is a failure, never a silent pass. Each test calls close() in a
`finally`, so an assertion that fails early still ends every process the
case started (stand-ins holding at a barrier included).

A process that leaves the group (setsid, setpgid) is not this module's to
find; the scripts under test and their stand-ins start none.
"""

import os
import resource
import signal
import subprocess
import time

# How long close() may take to see the group empty and reap the leader.
CLOSE_BOUND = 60.0


def child_setup():
    """In the child before exec: the four stop signals and SIGPIPE at their
    defaults (whatever the test runner had), and no core files."""
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGPIPE):
        signal.signal(sig, signal.SIG_DFL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def live_in_group(pgid):
    """Processes in a process group that are not zombies, read from ps."""
    out = subprocess.run(["/bin/ps", "-A", "-o", "pid=,pgid=,stat="], stdout=subprocess.PIPE, check=True).stdout.decode()
    live = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == str(pgid) and not fields[2].startswith("Z"):
            live.append(int(fields[0]))
    return live


class Group:
    """One command in its own session. Use as `g = Group(args, ...)`, then
    `try: ... finally: g.close()`."""

    def __init__(self, args, **popen_kw):
        self.proc = subprocess.Popen(args, start_new_session=True, preexec_fn=child_setup, **popen_kw)
        self.pgid = self.proc.pid
        # The leader's status, set when close() reaps it.
        self.status = None

    def ended(self):
        """Whether the leader has ended. It is left unreaped."""
        if self.status is not None:
            return True
        return os.waitid(os.P_PID, self.pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def wait_ended(self, timeout):
        deadline = time.monotonic() + timeout
        while not self.ended():
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    def live(self):
        """The group's live members. Only while the leader is unreaped: after
        that the id may be another group's."""
        if self.status is not None:
            raise AssertionError("process group %d was closed; its id may be another's now" % self.pgid)
        return live_in_group(self.pgid)

    def signal(self, sig, group=True):
        """Sends sig to the group, or to the leader alone."""
        if self.status is not None:
            raise AssertionError("process group %d was closed; its id may be another's now" % self.pgid)
        if group:
            os.killpg(self.pgid, sig)
        else:
            os.kill(self.pgid, sig)

    def ps(self):
        """The group as ps shows it, for a failure message."""
        if self.status is not None:
            return "(closed)"
        return subprocess.run(
            ["/bin/ps", "-o", "pid,pgid,stat,command", "-g", str(self.pgid)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ).stdout.decode()

    def close(self, bound=CLOSE_BOUND):
        """Kills every process left in the group, then reaps the leader, and
        returns its status (as Popen.returncode). Idempotent. Raises when
        the group cannot be confirmed empty, or the leader reaped, within
        the bound."""
        if self.status is not None:
            return self.status
        deadline = time.monotonic() + bound
        while True:
            try:
                os.killpg(self.pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # ESRCH: no member left. EPERM: only zombies left (macOS).
                pass
            live = live_in_group(self.pgid)
            if not live and self.ended():
                break
            if time.monotonic() > deadline:
                raise AssertionError(
                    "process group %d not confirmed empty %.0f s after SIGKILL: live %s, leader %s"
                    % (self.pgid, bound, live, "ended" if self.ended() else "running")
                )
            time.sleep(0.05)
        self.status = self.proc.wait(timeout=max(1.0, deadline - time.monotonic()))
        return self.status
