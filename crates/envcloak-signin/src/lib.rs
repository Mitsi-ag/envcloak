//! The dev sign-in contract (SPEC §6.8, milestone M2b): the immutable
//! sign-in scope and its canonical encoding, the approval statement
//! (`envcloak-signin-statement/1`), the operation store keyed by the owner
//! root, the daemon instance and `operation_key`, authorizations and
//! attempt credits, the operation lifecycle and its serialized publication
//! decision, and the TOTP function.
//!
//! Pure code: no I/O, and the clock is injected, so the daemon can call it
//! as its only implementation of the contract and tests can enumerate every
//! interleaving of its events. Like every crate but `envcloak-sys`, it
//! forbids `unsafe`.
//!
//! Empty until plan task M2b-01. It exists from M2-01 so that the workspace
//! layout (SPEC §4), CODEOWNERS and the crate-graph check name it from the
//! start.
