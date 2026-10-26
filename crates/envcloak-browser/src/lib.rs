//! Isolated sign-in worker browser driver, CDP client, origin guard, state
//! machine, identity verifier, declared-state extractor, D-28 test-session
//! adapter client, and worker reaper (`SPEC.md` §6.8, M2 plan task `M2b-07`).

pub mod adapter;
pub mod cdp;
pub mod driver;
pub mod extract;
pub mod identity;
pub mod launch;
pub mod origin_guard;
pub mod reaper;
pub mod state_machine;

pub use adapter::{
    TEST_SESSION_PATH, execute_test_session_adapter, hmac_sha256_hex, sign_test_session_request,
};
pub use cdp::{
    ALLOWED_CDP_DOMAINS, CdpClient, CdpError, CdpErrorKind, CdpEvent, MAX_CDP_MESSAGE_BYTES,
    MAX_CDP_QUEUE_LEN,
};
pub use driver::{
    AttemptFlow, AttemptOutcome, AttemptSpec, DaemonToDriver, Driver, DriverMessage, DriverPipe,
    MAX_DRIVER_MESSAGE_BYTES, recv_from_driver, send_to_driver,
};
pub use extract::{
    CapturedCookie, CapturedStorage, DeclaredState, RawWorkerCookie, WorkerSessionFormat,
    extract_from_cdp, filter_declared_state, parse_raw_cookie_declaration,
};
pub use identity::{
    ExpectedIdentity, WorkerStopReason, verify_identity_json, verify_worker_identity,
};
pub use launch::{
    EntryImageAnchor, FORBIDDEN_CHROME_FLAGS, LaunchError, LaunchSpec, sha256_file_fd,
};
pub use origin_guard::{GuardPhase, GuardViolation, LoopbackOriginProxy, OriginGuard, TargetScope};
pub use reaper::{
    CleanupOutcome, ControlDecodeError, REAPER_COMMAND_BYTES, REAPER_LOCK_FILE, REAPER_REPLY_BYTES,
    Reaper, ReaperCommand, ReaperOutcome, ReaperReply, TEARDOWN_CONFIRMATION_FILE, TeardownRecord,
    TeardownStep, WORKER_DIAGNOSTIC_FILE, execute_teardown_sequence,
};
pub use state_machine::{
    InspectedInput, LoginFieldHints, LoginStateMachine, LoginStepDecision, MAX_CODE_SUBMISSIONS,
    MAX_PASSWORD_SUBMISSIONS, PageLoginSurface,
};
