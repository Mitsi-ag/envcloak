//! EnvCloak's daemon protocol (SPEC §4.1 to §4.4; the format is in
//! docs/IPC.md): length-prefixed JSON-RPC 2.0 over a Unix socket.
//!
//! - [`frame`]: a 4-byte big-endian length and at most [`MAX_FRAME`]
//!   (1 MiB) of JSON, held in a buffer wiped on drop.
//! - [`proto`]: the methods, their parameters and results, the roles, and
//!   error kinds with stable tokens. Errors never carry text from the
//!   other side.
//! - [`WireSecret`]: a value inside a message, base64 on the wire, decoded
//!   from the frame straight into a wiped buffer.
//! - [`paths`]: where the socket lives, and the checks on its directory.
//! - [`client`]: a connection that verifies the daemon before it sends
//!   anything, and never starts one.
//! - [`view`]: what the daemon tells a client. Metadata only.
//!
//! The `testing` feature adds [`Client::connect_expecting_uid`], for tests
//! that present a same-uid server as a foreign one. Release binaries never
//! enable it.

pub mod client;
pub mod frame;
pub mod paths;
pub mod proto;
pub mod view;
mod wire_secret;

pub use client::{Client, ClientError, DaemonIdentity, Unverified};
pub use frame::{DecodeError, Frame, FrameError, MAX_FRAME};
pub use paths::{LOCK_NAME, RunPathError, RunPathErrorKind, RunPaths, SOCKET_NAME, SUN_PATH_MAX};
pub use proto::{ErrorKind, Method, Role, RpcError};
pub use wire_secret::WireSecret;
