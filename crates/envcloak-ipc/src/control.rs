//! The control channel between the daemon and a process it started itself
//! to receive values (M2 plan D-06, D-36; task M2-27; docs/IPC.md
//! "Control-pipe messages", channel `runner`): a Unix socket pair, the
//! daemon's end and the runner's descriptor [`CONTROL_FD`], never the
//! daemon's socket. No other process holds either end, so what crosses it
//! is the daemon's word, and the runner's answers reach the daemon alone.
//!
//! Messages are frames ([`Frame`]: a 4-byte length, then JSON), whose body
//! lives in wiped memory: [`Release`] carries the binding values.
//!
//! - Daemon to runner ([`ToRunner`]): [`ToRunner::Release`], once, with the
//!   values, the launch the runner starts and how it runs it;
//!   [`ToRunner::Confirmed`] or [`ToRunner::Refused`], on macOS, the answer
//!   to the runner's [`FromRunner::ConfirmSpawn`].
//! - Runner to daemon ([`FromRunner`]): [`FromRunner::ConfirmSpawn`], the
//!   pid of the server it started suspended (macOS), for the daemon's own
//!   check of the child's code directory hash before it runs.
//!
//! The runner's descriptors, as the daemon starts it: standard input,
//! output and error are the pipe ends the request handed over (standard
//! error is `/dev/null` when the request handed none), [`CONTROL_FD`] the
//! channel, [`LIFELINE_FD`] the lifeline, [`IMAGE_FD`] the program to run
//! on Linux (the sealed copy, or for a launch checked at rest only, the
//! checked descriptor), and [`CWD_FD`] the checked working directory.

use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

use crate::frame::{DecodeError, Frame, FrameError};
use crate::proto::ReleasedValue;

/// The runner's control channel.
pub const CONTROL_FD: i32 = 3;
/// The lifeline: the read end of a pipe whose write end the client keeps.
pub const LIFELINE_FD: i32 = 4;
/// The program to run (Linux).
pub const IMAGE_FD: i32 = 5;
/// The working directory, opened and checked by the daemon.
pub const CWD_FD: i32 = 6;

/// A message from the daemon to the runner.
#[derive(Debug, Serialize, Deserialize)]
pub enum ToRunner {
    /// The values and the launch, once, after the delivery's audit entry
    /// is on disk.
    Release(Box<Release>),
    /// The suspended child is the registered image: let it run.
    Confirmed,
    /// It is not: kill it through its handle and exit 125 with
    /// `managed_launch_changed`.
    Refused,
}

/// A message from the runner to the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum FromRunner {
    /// The pid of the server the runner started suspended (macOS).
    ConfirmSpawn(u32),
}

/// What the runner or relay receives: the binding values, and whom they
/// are for. Its `Debug` shows names and counts only.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub bindings: Vec<ReleasedValue>,
    pub to: Recipient,
}

impl core::fmt::Debug for Release {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&str> = self.bindings.iter().map(|b| b.env_name.as_str()).collect();
        f.debug_struct("Release")
            .field("bindings", &names)
            .field("to", &self.to)
            .finish()
    }
}

/// Whom a [`Release`] is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Recipient {
    /// `envcloak run --launch <id>`: the launch id (26 Crockford base32
    /// characters), which must be the one the runner was started with,
    /// and the launch it starts with the values in its environment.
    Runner { launch: String, spec: LaunchSpec },
    /// `envcloak mcp-bridge --relay`: the origin the header values go to,
    /// and to no other, and each header the relay inserts with the
    /// binding whose value it carries (M2 plan D-18; the relay's HTTP side
    /// is M2-18's). The headers are the record's, as registered with a
    /// proof; every released binding is one of theirs.
    Relay {
        origin: String,
        headers: Vec<RelayHeader>,
    },
}

/// One header a relay inserts: its name and the binding (`env_name` of a
/// [`ReleasedValue`]) whose value it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHeader {
    pub name: String,
    pub binding: String,
}

/// The registered launch, as the runner starts it: its argv, the recorded
/// `PATH` and variables (the runner adds the passthrough list from its
/// own environment and the bindings, `envcloak_policy::managed::
/// launch_environment`), the executable's path, and how the program is
/// run. Its `Debug` shows counts and names only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub argv: Vec<String>,
    pub path_env: String,
    pub vars: Vec<(String, String)>,
    /// The absolute executable, as registered.
    pub executable: String,
    pub exec: ExecSpec,
}

impl core::fmt::Debug for LaunchSpec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&str> = self.vars.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("LaunchSpec")
            .field("argv", &self.argv.len())
            .field("vars", &names)
            .field("exec", &self.exec)
            .finish_non_exhaustive()
    }
}

/// How the runner runs the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecSpec {
    /// Linux, `bound`: the sealed copy at [`IMAGE_FD`], whose digest the
    /// daemon compared with the record (`execveat`).
    Image,
    /// Linux, `checked_at_rest`: the descriptor the daemon checked, at
    /// [`IMAGE_FD`], once its stamp is read again and found the same.
    Descriptor { stamp: Stamp },
    /// The registered path. With `confirm` (macOS, a launch with a code
    /// directory hash) the server starts suspended and runs only once the
    /// daemon answers [`ToRunner::Confirmed`] to [`FromRunner::ConfirmSpawn`].
    Path { confirm: bool },
}

/// A file's state when the daemon checked it: device, inode, size and
/// change times, read again by the runner before it runs the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

/// Why a control message was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The channel failed or ended.
    Frame(FrameError),
    /// The frame is not a message of this channel.
    Decode(DecodeError),
}

impl From<FrameError> for ControlError {
    fn from(e: FrameError) -> Self {
        ControlError::Frame(e)
    }
}

/// Sends `msg` on the channel.
///
/// # Errors
/// [`FrameError`] when it does not fit in a frame or the write fails.
pub fn send<T: Serialize>(channel: &UnixStream, msg: &T) -> Result<(), FrameError> {
    let frame = Frame::encode(msg)?;
    let mut w = channel;
    frame.write_to(&mut w)
}

/// Receives one message from the channel.
///
/// # Errors
/// [`ControlError`]: the channel ended or failed (its timeout included),
/// or the frame is not a `T`.
pub fn receive<T: for<'de> Deserialize<'de>>(channel: &UnixStream) -> Result<T, ControlError> {
    let mut r = channel;
    let frame = Frame::read_from(&mut r)?;
    frame.decode::<T>().map_err(ControlError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_secret::WireSecret;
    use envcloak_core::SecretBytes;

    /// A release crosses whole, and its `Debug` shows no value.
    #[test]
    fn a_release_crosses_and_shows_no_value() {
        let (a, b) = UnixStream::pair().unwrap();
        let release = ToRunner::Release(Box::new(Release {
            bindings: vec![ReleasedValue {
                env_name: "API_KEY".into(),
                slug: "acme/key".into(),
                allow_short: false,
                value: WireSecret::new(SecretBytes::copy_from(b"not-a-real-value-0001")),
            }],
            to: Recipient::Runner {
                launch: "0123456789ABCDEFGHJKMNPQRS".into(),
                spec: LaunchSpec {
                    argv: vec!["/srv/server".into()],
                    path_env: "/usr/bin:/bin".into(),
                    vars: vec![("MODE".into(), "prod".into())],
                    executable: "/srv/server".into(),
                    exec: ExecSpec::Image,
                },
            },
        }));
        assert!(!format!("{release:?}").contains("not-a-real-value"));
        assert!(!format!("{release:?}").contains("prod"));
        send(&a, &release).unwrap();
        let got: ToRunner = receive(&b).unwrap();
        let ToRunner::Release(r) = got else {
            panic!("not a release")
        };
        assert_eq!(r.bindings.len(), 1);
        assert!(matches!(
            r.to,
            Recipient::Runner {
                spec: LaunchSpec {
                    exec: ExecSpec::Image,
                    ..
                },
                ..
            }
        ));
        send(&b, &FromRunner::ConfirmSpawn(42)).unwrap();
        assert!(matches!(
            receive::<FromRunner>(&a).unwrap(),
            FromRunner::ConfirmSpawn(42)
        ));
        send(&a, &ToRunner::Confirmed).unwrap();
        assert!(matches!(
            receive::<ToRunner>(&b).unwrap(),
            ToRunner::Confirmed
        ));
    }

    /// Hostile frames: a message of the other direction, an unknown
    /// message, a release with an unknown field, and garbage are refused;
    /// a channel that ends is the end.
    #[test]
    fn hostile_frames_are_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        for bad in [
            &br#"{"ConfirmSpawn":1}"#[..],
            br#""Approve""#,
            br#"{"Release":{"bindings":[],"to":{"relay":{"origin":"https://a.test"}},"extra":1}}"#,
            b"\xff\xfe",
            br#"{"Release":{}}"#,
        ] {
            let mut w = &a;
            std::io::Write::write_all(&mut w, &u32::try_from(bad.len()).unwrap().to_be_bytes())
                .unwrap();
            std::io::Write::write_all(&mut w, bad).unwrap();
            assert!(
                matches!(receive::<ToRunner>(&b), Err(ControlError::Decode(_))),
                "{bad:?}"
            );
        }
        drop(a);
        assert!(matches!(
            receive::<ToRunner>(&b),
            Err(ControlError::Frame(FrameError::Closed))
        ));
    }
}
