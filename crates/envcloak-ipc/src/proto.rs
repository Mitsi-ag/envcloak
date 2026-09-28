//! Messages: JSON-RPC 2.0 over [`Frame`]s (SPEC §4.3, §4.4; the format is
//! in docs/IPC.md).
//!
//! - A request is `{"jsonrpc":"2.0","id":N,"method":"...","params":{...}}`
//!   and gets exactly one response with the same `id`: `result`, or
//!   `error` with a numeric `code`, a fixed `message`, and `data.kind`, a
//!   stable token (with `data.reason` for some kinds). Notifications and
//!   batches are not used.
//! - Each method is a [`Method`] type naming its parameters and result, so
//!   a client cannot read one method's result as another's.
//! - Methods named `app.*` belong to the `app` role (SPEC §4.3). Before the
//!   macOS app (M3) no peer has that role: the daemon rejects them with
//!   [`ErrorKind::RoleDenied`] and audits the attempt.
//! - Parsing never copies a string out of the frame except the fixed
//!   tokens of an error. Unknown fields are refused. Errors are
//!   [`RpcError`]s built from fixed tokens: a client never shows text it
//!   received, and the daemon never shows what a client sent.

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::frame::{DecodeError, Frame, FrameError};
use crate::view::{CreatedView, LockedView, StatusView, UnlockedView};
use crate::wire_secret::WireSecret;

/// The protocol version string every message carries.
pub const JSONRPC: &str = "2.0";

/// A method: its name, its parameters and its result.
pub trait Method {
    const NAME: &'static str;
    type Params: Serialize + for<'de> Deserialize<'de>;
    type Output: Serialize + for<'de> Deserialize<'de>;
}

/// Parameters of a method that takes none: `{}`, or no `params` at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// `status`: the daemon, its vault and its lock. Metadata only.
#[derive(Debug)]
pub struct Status;

impl Method for Status {
    const NAME: &'static str = "status";
    type Params = NoParams;
    type Output = StatusView;
}

/// `vault.create`: creates the vault and leaves it unlocked, or locked
/// when a lock arrived while Argon2id ran ([`CreatedView::locked`]).
#[derive(Debug)]
pub struct VaultCreate;

impl Method for VaultCreate {
    const NAME: &'static str = "vault.create";
    type Params = VaultCreateParams;
    type Output = CreatedView;
}

/// The passphrase and the Recovery Kit the client generated and showed,
/// and the Argon2id memory for both envelopes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultCreateParams {
    pub passphrase: WireSecret,
    /// The kit as the user wrote it down (`RecoveryKit::to_display`).
    pub recovery_kit: WireSecret,
    /// Argon2id memory in KiB, 64 MiB to 4 GiB; the default (256 MiB) when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_memory_kib: Option<u32>,
}

/// `unlock`: unlocks with the passphrase.
#[derive(Debug)]
pub struct Unlock;

impl Method for Unlock {
    const NAME: &'static str = "unlock";
    type Params = UnlockParams;
    type Output = UnlockedView;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockParams {
    pub passphrase: WireSecret,
}

/// `lock`: locks. Locking only tightens, so it needs no proof.
#[derive(Debug)]
pub struct Lock;

impl Method for Lock {
    const NAME: &'static str = "lock";
    type Params = NoParams;
    type Output = LockedView;
}

/// The client-role methods this daemon serves.
pub const CLIENT_METHODS: [&str; 4] = [Status::NAME, VaultCreate::NAME, Unlock::NAME, Lock::NAME];

/// The `app`-role methods (SPEC §4.3): Secure Enclave unlock, signed
/// approval, policy, reveal, the paste sheet, devices and registry
/// overrides. Any other `app.` name is an app method too.
pub const APP_METHODS: [&str; 8] = [
    "app.unlock",
    "app.approve",
    "app.policy.set",
    "app.reveal",
    "app.paste",
    "app.device.add",
    "app.device.remove",
    "app.registry.override",
];

/// The roles a peer can have (SPEC §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Any same-uid peer.
    Client,
    /// The signed macOS app (M3). No peer has it before then.
    App,
}

/// The role a method needs: [`Role::App`] for every `app.` name.
pub fn required_role(method: &str) -> Role {
    if method.starts_with("app.") {
        Role::App
    } else {
        Role::Client
    }
}

/// A method name that is safe to log: the name itself when it is one of
/// [`CLIENT_METHODS`] or [`APP_METHODS`], a fixed placeholder otherwise.
/// A name a client sent can hold anything, a pasted value included.
pub fn loggable_method(method: &str) -> &'static str {
    CLIENT_METHODS
        .iter()
        .chain(APP_METHODS.iter())
        .find(|m| **m == method)
        .copied()
        .unwrap_or(if method.starts_with("app.") {
            "app.(unknown)"
        } else {
            "(unknown)"
        })
}

/// What went wrong, as a stable token (`data.kind`) and a JSON-RPC code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The frame is not JSON.
    ParseError,
    /// The JSON is not a request.
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    /// The method belongs to the `app` role.
    RoleDenied,
    VaultLocked,
    /// No vault exists yet.
    NoVault,
    /// `vault create` found a vault already there.
    VaultExists,
    /// The one error for a wrong passphrase or a damaged unlocker.
    WrongPassphrase,
    /// A new passphrase breaks the rules; `reason` says which.
    PassphraseRejected,
    /// Argon2id parameters out of bounds.
    KdfParams,
    /// Another unlock or `vault create` is running.
    Busy,
    /// A tracer is attached to the daemon, so it will not handle values.
    Traced,
    /// The vault file could not be opened; `reason` says why.
    VaultUnavailable,
    /// The request did not fit in a frame.
    FrameTooLarge,
    Internal,
}

impl ErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: [ErrorKind; 16] = [
        ErrorKind::ParseError,
        ErrorKind::InvalidRequest,
        ErrorKind::MethodNotFound,
        ErrorKind::InvalidParams,
        ErrorKind::RoleDenied,
        ErrorKind::VaultLocked,
        ErrorKind::NoVault,
        ErrorKind::VaultExists,
        ErrorKind::WrongPassphrase,
        ErrorKind::PassphraseRejected,
        ErrorKind::KdfParams,
        ErrorKind::Busy,
        ErrorKind::Traced,
        ErrorKind::VaultUnavailable,
        ErrorKind::FrameTooLarge,
        ErrorKind::Internal,
    ];

    /// The JSON-RPC error code.
    pub fn code(self) -> i32 {
        match self {
            ErrorKind::ParseError => -32700,
            ErrorKind::InvalidRequest => -32600,
            ErrorKind::MethodNotFound => -32601,
            ErrorKind::InvalidParams => -32602,
            ErrorKind::RoleDenied => -32001,
            ErrorKind::VaultLocked => -32002,
            ErrorKind::NoVault => -32003,
            ErrorKind::VaultExists => -32004,
            ErrorKind::WrongPassphrase => -32005,
            ErrorKind::PassphraseRejected => -32006,
            ErrorKind::KdfParams => -32007,
            ErrorKind::Busy => -32008,
            ErrorKind::Traced => -32009,
            ErrorKind::VaultUnavailable => -32010,
            ErrorKind::FrameTooLarge => -32011,
            ErrorKind::Internal => -32099,
        }
    }

    /// The stable token, printed by the CLI as `envcloak: <token>: ...`.
    pub fn token(self) -> &'static str {
        match self {
            ErrorKind::ParseError => "parse_error",
            ErrorKind::InvalidRequest => "invalid_request",
            ErrorKind::MethodNotFound => "method_not_found",
            ErrorKind::InvalidParams => "invalid_params",
            ErrorKind::RoleDenied => "role_denied",
            ErrorKind::VaultLocked => "vault_locked",
            ErrorKind::NoVault => "no_vault",
            ErrorKind::VaultExists => "vault_exists",
            ErrorKind::WrongPassphrase => "wrong_passphrase",
            ErrorKind::PassphraseRejected => "passphrase_rejected",
            ErrorKind::KdfParams => "kdf_params",
            ErrorKind::Busy => "busy",
            ErrorKind::Traced => "traced",
            ErrorKind::VaultUnavailable => "vault_unavailable",
            ErrorKind::FrameTooLarge => "frame_too_large",
            ErrorKind::Internal => "internal",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            ErrorKind::ParseError => "the request is not valid JSON",
            ErrorKind::InvalidRequest => "the request is not a JSON-RPC 2.0 request",
            ErrorKind::MethodNotFound => "no such method",
            ErrorKind::InvalidParams => "the request's parameters are missing or malformed",
            ErrorKind::RoleDenied => {
                "this method needs the EnvCloak app; a command-line client cannot call it"
            }
            ErrorKind::VaultLocked => "the vault is locked; run `envcloak unlock`",
            ErrorKind::NoVault => "there is no vault yet; run `envcloak vault create`",
            ErrorKind::VaultExists => "a vault already exists",
            ErrorKind::WrongPassphrase => {
                "wrong passphrase or Recovery Kit, or the unlocker envelope is damaged"
            }
            ErrorKind::PassphraseRejected => "the passphrase does not meet the rules",
            ErrorKind::KdfParams => "key derivation memory must be between 64 MiB and 4 GiB",
            ErrorKind::Busy => "another unlock or vault creation is in progress; try again",
            ErrorKind::Traced => {
                "a debugger or tracer is attached to the daemon, so it will not handle secrets"
            }
            ErrorKind::VaultUnavailable => "the vault could not be opened",
            ErrorKind::FrameTooLarge => "the request exceeds the 1 MiB frame limit",
            ErrorKind::Internal => "the daemon failed",
        }
    }

    /// The kind with this token.
    pub fn from_token(token: &str) -> Option<ErrorKind> {
        ErrorKind::ALL.into_iter().find(|k| k.token() == token)
    }
}

/// The detail tokens an error may carry in `data.reason`: why a passphrase
/// was rejected, and why the vault could not be opened.
pub const REASONS: [&str; 12] = [
    // Passphrase rules (envcloak_core::PassphraseRejected).
    "not_text",
    "control_character",
    "too_short",
    "common",
    // The vault file.
    "busy",
    "damaged",
    "unsupported_version",
    "permissions",
    "disk_full",
    "storage",
    "io",
    "migration",
];

/// An error response. Built from fixed tokens only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RpcError {
    pub kind: ErrorKind,
    /// One of [`REASONS`], for [`ErrorKind::PassphraseRejected`] and
    /// [`ErrorKind::VaultUnavailable`].
    pub reason: Option<&'static str>,
}

impl RpcError {
    pub const fn new(kind: ErrorKind) -> Self {
        RpcError { kind, reason: None }
    }

    /// The error with a reason; one not in [`REASONS`] is dropped.
    pub fn with_reason(kind: ErrorKind, reason: &str) -> Self {
        RpcError {
            kind,
            reason: REASONS.iter().find(|r| **r == reason).copied(),
        }
    }
}

impl From<ErrorKind> for RpcError {
    fn from(kind: ErrorKind) -> Self {
        RpcError::new(kind)
    }
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())?;
        if let Some(r) = self.reason {
            write!(f, " ({r})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RpcError {}

#[derive(Serialize)]
struct OutRequest<'a, P> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: &'a P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

#[derive(Serialize)]
struct OutResult<'a, T> {
    jsonrpc: &'static str,
    id: u64,
    result: &'a T,
}

#[derive(Serialize)]
struct OutError {
    jsonrpc: &'static str,
    id: Option<u64>,
    error: OutErrorBody,
}

#[derive(Serialize)]
struct OutErrorBody {
    code: i32,
    message: &'static str,
    data: OutErrorData,
}

#[derive(Serialize)]
struct OutErrorData {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InResponse<'a> {
    jsonrpc: &'a str,
    id: Option<u64>,
    #[serde(borrow, default)]
    result: Option<&'a RawValue>,
    #[serde(default)]
    error: Option<InErrorBody>,
}

#[derive(Deserialize)]
struct InErrorBody {
    #[allow(dead_code)] // Read for the shape; the kind decides.
    code: i64,
    // Never shown: the client prints its own message for the kind.
    #[allow(dead_code)]
    message: IgnoredAny,
    #[serde(default)]
    data: Option<InErrorData>,
}

#[derive(Deserialize)]
struct InErrorData {
    kind: String,
    #[serde(default)]
    reason: Option<String>,
}

/// A request frame for method `M`.
///
/// # Errors
/// [`FrameError::TooLarge`] when the request does not fit in a frame.
pub fn request_frame<M: Method>(id: u64, params: &M::Params) -> Result<Frame, FrameError> {
    Frame::encode(&OutRequest {
        jsonrpc: JSONRPC,
        id,
        method: M::NAME,
        params,
    })
}

/// A request as the daemon receives it: the method name and parameters
/// still in the frame. Its `Debug` shows the id and a loggable method
/// name only; the parameters may hold a value.
pub struct IncomingRequest<'a> {
    pub id: u64,
    /// As the client sent it. Log it only through [`loggable_method`].
    pub method: &'a str,
    params: Option<&'a RawValue>,
}

impl core::fmt::Debug for IncomingRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("id", &self.id)
            .field("method", &loggable_method(self.method))
            .finish_non_exhaustive()
    }
}

impl<'a> IncomingRequest<'a> {
    /// Parses a request frame. On failure, the error to answer with and
    /// the request id when it could be read.
    pub fn parse(frame: &'a Frame) -> Result<Self, RpcError> {
        let req: InRequest<'a> = frame.decode().map_err(|e| match e {
            DecodeError::Syntax | DecodeError::Eof => RpcError::new(ErrorKind::ParseError),
            DecodeError::Data => RpcError::new(ErrorKind::InvalidRequest),
        })?;
        if req.jsonrpc != JSONRPC {
            return Err(RpcError::new(ErrorKind::InvalidRequest));
        }
        Ok(IncomingRequest {
            id: req.id,
            method: req.method,
            params: req.params,
        })
    }

    /// The parameters as `P`. Absent parameters read as `{}`.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidParams`] when they do not match `P`.
    pub fn params<P: Deserialize<'a>>(&self) -> Result<P, RpcError> {
        let raw = self.params.map_or("{}", RawValue::get);
        serde_json::from_str(raw).map_err(|_| RpcError::new(ErrorKind::InvalidParams))
    }
}

/// The success response to request `id`.
///
/// # Errors
/// [`FrameError::TooLarge`] when the result does not fit in a frame.
pub fn result_frame<T: Serialize>(id: u64, result: &T) -> Result<Frame, FrameError> {
    Frame::encode(&OutResult {
        jsonrpc: JSONRPC,
        id,
        result,
    })
}

/// The error response to request `id`, or to an unreadable request
/// (`None`).
///
/// # Errors
/// Only if a fixed error object could not be serialized.
pub fn error_frame(id: Option<u64>, e: &RpcError) -> Result<Frame, FrameError> {
    Frame::encode(&OutError {
        jsonrpc: JSONRPC,
        id,
        error: OutErrorBody {
            code: e.kind.code(),
            message: e.kind.message(),
            data: OutErrorData {
                kind: e.kind.token(),
                reason: e.reason,
            },
        },
    })
}

/// Why a response could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// The daemon answered with an error.
    Rpc(RpcError),
    /// The response is malformed, answers another request, or holds an
    /// error kind this client does not know.
    Protocol,
}

/// Reads the response to request `id` as `T`.
///
/// # Errors
/// [`ResponseError::Rpc`] for an error response, and
/// [`ResponseError::Protocol`] for anything else that is not a result of
/// type `T` for request `id`.
pub fn parse_response<'a, T: Deserialize<'a>>(
    frame: &'a Frame,
    id: u64,
) -> Result<T, ResponseError> {
    let resp: InResponse<'a> = frame.decode().map_err(|_| ResponseError::Protocol)?;
    if resp.jsonrpc != JSONRPC {
        return Err(ResponseError::Protocol);
    }
    match (resp.result, resp.error) {
        (Some(result), None) if resp.id == Some(id) => {
            serde_json::from_str(result.get()).map_err(|_| ResponseError::Protocol)
        }
        (None, Some(err)) if resp.id.is_none_or(|got| got == id) => {
            let data = err.data.ok_or(ResponseError::Protocol)?;
            let kind = ErrorKind::from_token(&data.kind).ok_or(ResponseError::Protocol)?;
            let e = match data.reason {
                Some(r) => RpcError::with_reason(kind, &r),
                None => RpcError::new(kind),
            };
            Err(ResponseError::Rpc(e))
        }
        _ => Err(ResponseError::Protocol),
    }
}
