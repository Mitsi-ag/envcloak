//! Hosted browser supervisor, D-30 tool allowlist, session delivery pipeline,
//! and MCP router integration (`M2b-08`, SPEC §7.6).

pub mod allowlist;
pub mod delivery;
pub mod dispatch;
pub mod relay;
pub mod supervisor;

pub use allowlist::{
    ALLOWED_BROWSER_TOOLS, EXCLUDED_BROWSER_TOOLS, FORBIDDEN_PATH_ARGS, TOOL_NOT_ALLOWED,
    ToolAllowlist,
};
pub use delivery::{
    BrokerStopOutcome, CleanupOutcome, RevocationOutcome, SessionDeliveryPlan,
    SessionDeliveryReceipt, StopOutcomes, deliver_secret_session, deliver_session, end_session,
};
pub use dispatch::register_browser_tools;
pub use relay::BrowserRelay;
pub use supervisor::{
    BROWSER_SUPERVISOR_FD_ENV, BrowserPins, BrowserSupervisor, CONTEXT_NOT_PUBLISHED,
    DeclaredSecretCookie, DeclaredSecretLocalStorageItem, DeclaredSecretOrigin,
    DeclaredSecretState, ExpectedIdentity, GRANT_REVOKED, HelperStats, IDENTITY_UNVERIFIED,
    IdentityResponse, MAX_SUPERVISOR_LINE_BYTES, NOT_STARTED_BY_DAEMON, SupervisorError,
    SupervisorOptions, TRACED_REFUSAL, UNSUPPORTED_SESSION_SCOPE, VerifiedBrowserRuntime,
    browser_versions_path, read_browser_pins, resolve_browser_runtime, resolve_node_binary,
    run_browser_supervisor, verify_chrome_executable, verify_started_by_daemon,
    verify_started_by_daemon_fd,
};
