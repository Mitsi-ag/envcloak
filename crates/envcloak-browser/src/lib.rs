//! The dev sign-in driver (SPEC §6.8, milestone M2b): the Chrome DevTools
//! protocol over a pipe, the launch spec, the origin guard, the login state
//! machine, the identity check, extraction of the declared session state,
//! the test-session adapter client and the protocol between the daemon and
//! its driver process.
//!
//! The driver runs as its own process (`envcloakd --signin-driver`), so
//! input a page influences is never parsed in the process that holds the
//! vault key. Like every crate but `envcloak-sys`, it forbids `unsafe`; the
//! descriptor handling its processes need is in `envcloak-sys`.
//!
//! Empty until plan task M2b-07. It exists from M2-01 so that the workspace
//! layout (SPEC §4), CODEOWNERS and the crate-graph check name it from the
//! start.
