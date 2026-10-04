//! Starting the child with the values in its environment only (SPEC §6.1
//! step 6, §15.2 gates 13 and 14).
//!
//! The values go to `Command::env`, which copies them into its own
//! strings and, at the spawn, into the C strings of the new environment;
//! both are freed when the command is dropped, just after the spawn, and
//! the wiping allocator clears them then (gate 11). Nothing is written to
//! a file or to this process's environment, and argv is the caller's own.
//!
//! In PTY mode ([`spawn_session`], M2 task M2-17) the command is started
//! by the PTY monitor `envcloak_sys::pty::spawn_session` forks, from C
//! strings built here and wiped when it returns: this process's
//! environment with the values on top, the same as `Command::env` gives.
//!
//! This file is on security/expose-allowlist.txt: it hands the values to
//! the child's environment.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use envcloak_core::SecretBytes;
use envcloak_policy::EnvName;
use envcloak_sys::pty::{SessionError, SessionMonitor};
use secrecy::ExposeSecret;

use crate::ExecError;

/// Starts `argv` with `injected` added to this process's environment,
/// standard input from `stdin` (or this process's), and standard output
/// and standard error as pipes. With `own_group`, the child leads a new
/// process group.
pub(crate) fn spawn(
    argv: &[OsString],
    injected: &[(EnvName, SecretBytes)],
    stdin: Option<OwnedFd>,
    own_group: bool,
) -> Result<Child, ExecError> {
    let (program, args) = argv.split_first().ok_or(ExecError::NoCommand)?;
    if injected.iter().any(|(_, v)| v.contains_byte(0)) {
        return Err(ExecError::NulByte);
    }
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (name, value) in injected {
        set_env(&mut cmd, name, value);
    }
    cmd.stdin(stdin.map_or_else(Stdio::inherit, Stdio::from))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if own_group {
        cmd.process_group(0);
    }
    let spawned = cmd.spawn();
    // The command's copies of the values are freed here, and wiped.
    drop(cmd);
    spawned.map_err(|e| spawn_error(&e))
}

#[allow(clippy::disallowed_methods)] // The value goes to the child's environment.
fn set_env(cmd: &mut Command, name: &EnvName, value: &SecretBytes) {
    cmd.env(name.as_str(), OsStr::from_bytes(value.expose_secret()));
}

#[allow(clippy::disallowed_methods)] // The value goes to the command's environment.
fn exposed(value: &SecretBytes) -> &OsStr {
    OsStr::from_bytes(value.expose_secret())
}

/// Starts `argv` on the PTY whose slave side is `slave`, under the PTY
/// monitor (PTY mode), with `injected` added to this process's
/// environment: a later entry for a name wins, and an injected name
/// replaces an inherited one, as with `Command::env`. The command's
/// environment is built here as C strings, which `spawn_session` wipes
/// when it returns; nothing is written to a file or to this process's
/// environment.
pub(crate) fn spawn_session(
    argv: &[OsString],
    injected: &[(EnvName, SecretBytes)],
    slave: OwnedFd,
) -> Result<SessionMonitor, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::NoCommand);
    }
    if injected.iter().any(|(_, v)| v.contains_byte(0)) {
        return Err(ExecError::NulByte);
    }
    // The last entry for each injected name.
    let mut seen = HashSet::new();
    let mut chosen: Vec<&(EnvName, SecretBytes)> = injected
        .iter()
        .rev()
        .filter(|(name, _)| seen.insert(name.as_str()))
        .collect();
    chosen.reverse();
    let inherited: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| name.to_str().is_none_or(|n| !seen.contains(n)))
        .collect();
    let mut env: Vec<(&OsStr, &OsStr)> = inherited
        .iter()
        .map(|(n, v)| (n.as_os_str(), v.as_os_str()))
        .collect();
    env.extend(
        chosen
            .iter()
            .map(|(name, value)| (OsStr::new(name.as_str()), exposed(value))),
    );
    let argv: Vec<&OsStr> = argv.iter().map(OsString::as_os_str).collect();
    envcloak_sys::pty::spawn_session(&argv, &env, slave).map_err(|e| match e {
        SessionError::Exec(e) => spawn_error(&e),
        SessionError::Setup(e) => ExecError::Setup(e.kind()),
    })
}

/// What a failed spawn means for the exit code (SPEC §6.1 step 9): a
/// command that does not exist is 127 and one that cannot be run 126, as
/// `env(1)` has them; running out of descriptors, processes or memory is
/// EnvCloak's own failure.
fn spawn_error(e: &io::Error) -> ExecError {
    match e.raw_os_error() {
        Some(libc::ENOENT) => ExecError::NotFound,
        Some(libc::EMFILE | libc::ENFILE | libc::EAGAIN | libc::ENOMEM) => {
            ExecError::Setup(e.kind())
        }
        _ if e.kind() == io::ErrorKind::NotFound => ExecError::NotFound,
        _ => ExecError::NotExecutable(e.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_errors_keep_their_env_1_codes() {
        let dir = tempfile::tempdir().unwrap();
        let not_exec = dir.path().join("plain");
        std::fs::write(&not_exec, b"#!/bin/sh\n").unwrap();
        for (argv, code) in [
            (vec![dir.path().join("missing").into_os_string()], 127),
            (
                vec![OsString::from("envcloak-no-such-command-anywhere")],
                127,
            ),
            (vec![not_exec.into_os_string()], 126),
            (vec![dir.path().as_os_str().to_owned()], 126),
        ] {
            let e = spawn(&argv, &[], None, false).unwrap_err();
            assert_eq!(e.exit_code(), code, "{e:?}");
        }
        assert_eq!(
            spawn(
                &[OsString::from("/usr/bin/true")],
                &[(EnvName::new("A").unwrap(), SecretBytes::copy_from(b"x\0y"))],
                None,
                false
            )
            .unwrap_err(),
            ExecError::NulByte
        );
        assert_eq!(
            spawn(&[], &[], None, false).unwrap_err(),
            ExecError::NoCommand
        );
    }
}
