//! Daemon-side browser supervisor handle (`SPEC.md` §6.8, M2 plan D-31, D-34,
//! D-36, task `M2b-09`).
//!
//! After worker capture, the daemon starts the generation's browser supervisor
//! as a third owned child (`OwnedChild`), with the requesting MCP server's tool
//! pipes (descriptors 0 and 1), a control socketpair (`CONTROL_FD = 3`), and a
//! lifeline pipe (`LIFELINE_FD = 4`). The daemon sends [`ToSupervisor::InjectState`]
//! on the control pipe, reads [`FromSupervisor::IdentityResponse`], decides
//! publication ([`ToSupervisor::Publish`]), answers per-call [`FromSupervisor::Check`]
//! messages, and on generation end (end, cancel, lock, root exit, revision
//! change, timeout) sends [`ToSupervisor::Close`] and reaps the supervisor
//! through its [`OwnedChild`] handle.
#![allow(dead_code)]

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use envcloak_browser::EntryImageAnchor;
use envcloak_ipc::control::{
    CONTROL_FD, FromSupervisor, LIFELINE_FD, SupervisorClose, SupervisorInjectState,
    SupervisorPublish, ToSupervisor, receive as recv_from_supervisor, send as send_to_supervisor,
};
use envcloak_sys::{OwnedChild, ProcessOps, SystemProcesses, pipe_cloexec};

/// Daemon-held end of the browser supervisor control socketpair (`D-31`, `D-36`).
#[derive(Debug)]
pub struct ControlPipe {
    stream: UnixStream,
}

impl ControlPipe {
    /// Wraps the daemon's [`UnixStream`] end of the supervisor control channel.
    pub fn new(stream: UnixStream) -> Self {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
        Self { stream }
    }

    /// Creates a connected `(ControlPipe, peer_stream)` pair.
    pub fn pair() -> io::Result<(Self, UnixStream)> {
        let (ours, theirs) = UnixStream::pair()?;
        Ok((Self::new(ours), theirs))
    }

    /// Borrows the underlying [`UnixStream`].
    pub fn as_stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Unwraps the underlying [`UnixStream`].
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    /// Sends a [`ToSupervisor`] message over the control pipe.
    pub fn send(&self, msg: &ToSupervisor) -> io::Result<()> {
        send_to_supervisor(&self.stream, msg)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e:?}")))
    }

    /// Sends [`ToSupervisor::InjectState`] over the control pipe.
    pub fn send_inject_state(&self, state: SupervisorInjectState) -> io::Result<()> {
        self.send(&ToSupervisor::InjectState(state))
    }

    /// Sends [`ToSupervisor::Publish`] over the control pipe.
    pub fn send_publish(&self, publish: SupervisorPublish) -> io::Result<()> {
        self.send(&ToSupervisor::Publish(publish))
    }

    /// Sends [`ToSupervisor::Close`] over the control pipe.
    pub fn send_close(&self, close: SupervisorClose) -> io::Result<()> {
        self.send(&ToSupervisor::Close(close))
    }

    /// Receives a [`FromSupervisor`] message from the control pipe.
    pub fn recv(&self) -> io::Result<FromSupervisor> {
        recv_from_supervisor(&self.stream)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
    }
}

/// Daemon-side handle to a running browser supervisor generation (`M2b-09`).
#[derive(Debug)]
pub struct SupervisorHandle<P: ProcessOps = SystemProcesses> {
    pub child: OwnedChild<P>,
    pub control: ControlPipe,
    pub lifeline_w: OwnedFd,
}

impl<P: ProcessOps> SupervisorHandle<P> {
    /// Closes the generation: sends [`ToSupervisor::Close`] on the control
    /// pipe, drops the lifeline write end, stops the supervisor's process group
    /// if needed, and reaps the owned child handle.
    pub fn close_and_reap(
        self,
        request: &str,
        generation: u64,
        context: &str,
        grace: Duration,
    ) -> bool {
        let Self {
            child,
            control,
            lifeline_w,
        } = self;

        let _ = control.send_close(SupervisorClose {
            request: request.to_owned(),
            generation,
            context: context.to_owned(),
        });

        let mut cleaned_ack = false;
        let _ = control
            .as_stream()
            .set_read_timeout(Some(grace.min(Duration::from_secs(2))));
        if let Ok(FromSupervisor::Check(chk)) = control.recv()
            && chk.cleaned == Some(true)
        {
            cleaned_ack = true;
        }

        drop(control);
        drop(lifeline_w);

        let _ = child.stop_group(grace);
        let status = child.reap();
        cleaned_ack || status.is_ok_and(|s| s.success())
    }
}

/// Spawns `envcloak mcp --browser-supervisor` from a captured [`EntryImageAnchor`]
/// of the `envcloak` binary with the requesting MCP server's `tool_pipes`
/// (descriptors 0 and 1), `CONTROL_FD` (descriptor 3), and `LIFELINE_FD`
/// (descriptor 4).
pub fn spawn_browser_supervisor(
    envcloak_anchor: &EntryImageAnchor,
    tool_pipes: Option<(&OwnedFd, &OwnedFd)>,
) -> io::Result<SupervisorHandle> {
    let (control, peer_sock) = ControlPipe::pair()?;
    let (lifeline_r, lifeline_w) = pipe_cloexec()?;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;

    let (stdin_fd, stdout_fd): (BorrowedFd<'_>, BorrowedFd<'_>) = match tool_pipes {
        Some((r, w)) => (r.as_fd(), w.as_fd()),
        None => (devnull.as_fd(), devnull.as_fd()),
    };
    let fds = [
        (stdin_fd, 0),
        (stdout_fd, 1),
        (devnull.as_fd(), 2),
        (peer_sock.as_fd(), CONTROL_FD),
        (lifeline_r.as_fd(), LIFELINE_FD),
    ];

    let mut env_entries: Vec<Vec<u8>> = vec![b"PATH=/usr/bin:/bin".to_vec(), b"LANG=C".to_vec()];
    for (k, v) in envcloak_sys::test_hook_vars() {
        let mut entry = k.into_encoded_bytes();
        entry.push(b'=');
        entry.extend_from_slice(&v.into_encoded_bytes());
        env_entries.push(entry);
    }
    let env_slices: Vec<&[u8]> = env_entries.iter().map(Vec::as_slice).collect();
    let argv: &[&[u8]] = &[b"envcloak", b"mcp", b"--browser-supervisor"];

    let child = envcloak_anchor
        .spawn_bound(argv, &env_slices, &fds)
        .map_err(|e| io::Error::other(e.to_string()))?;

    drop(peer_sock);
    drop(lifeline_r);

    Ok(SupervisorHandle {
        child,
        control,
        lifeline_w,
    })
}

/// Captures the sibling `envcloak` binary beside `envcloakd` as an
/// [`EntryImageAnchor`] if present.
pub fn capture_sibling_envcloak() -> Option<EntryImageAnchor> {
    let exe = std::env::current_exe().ok()?;
    let dir: &Path = exe.parent()?;
    let sibling = std::fs::canonicalize(dir.join("envcloak")).ok()?;
    EntryImageAnchor::capture_from_path(&sibling).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::control::SupervisorIdentityResponse;

    #[test]
    fn control_pipe_round_trips_supervisor_messages() {
        let (daemon_pipe, peer_stream) = ControlPipe::pair().expect("pair");
        let peer_pipe = ControlPipe::new(peer_stream);

        daemon_pipe
            .send_inject_state(SupervisorInjectState {
                request: "req-1".to_owned(),
                generation: 3,
                context: "ctx-3".to_owned(),
                cookies: Vec::new(),
                storage: Vec::new(),
            })
            .expect("send inject");

        let received = recv_from_supervisor(peer_pipe.as_stream()).expect("recv inject");
        match received {
            ToSupervisor::InjectState(inj) => {
                assert_eq!(inj.request, "req-1");
                assert_eq!(inj.generation, 3);
                assert_eq!(inj.context, "ctx-3");
            }
            other => panic!("unexpected message: {other:?}"),
        }

        send_to_supervisor(
            peer_pipe.as_stream(),
            &FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
                request: "req-1".to_owned(),
                generation: 3,
                context: "ctx-3".to_owned(),
                account: Some("alice@example.com".to_owned()),
                tenant: Some("acme".to_owned()),
                role: Some("admin".to_owned()),
            }),
        )
        .expect("send identity");

        let from_sup = daemon_pipe.recv().expect("recv identity");
        assert_eq!(
            from_sup,
            FromSupervisor::IdentityResponse(SupervisorIdentityResponse {
                request: "req-1".to_owned(),
                generation: 3,
                context: "ctx-3".to_owned(),
                account: Some("alice@example.com".to_owned()),
                tenant: Some("acme".to_owned()),
                role: Some("admin".to_owned()),
            })
        );
    }
}
