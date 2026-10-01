//! The M2 acceptance story (M2 plan §4), one module per task that lands a
//! step; M2-26 composes them into the ordered story. The pull-request
//! `gates` job runs this target (§6 trigger table).
//!
//! - [`skeleton`] (M2-04): step S0, each pinned host running `envcloak run
//!   -- ./emit` through a scripted Bash call, the person approving from a
//!   terminal of their own, the rerun, and the sweep.
#![allow(clippy::unwrap_used)]

mod skeleton;
