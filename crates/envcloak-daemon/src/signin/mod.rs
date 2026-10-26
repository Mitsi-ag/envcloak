//! Daemon sign-in subsystem (`M2b-05`, `M2b-09`): target management
//! (`signin.target.add|edit|remove|list`), operation lifecycle
//! (`signin.request|status|cancel|end`), live `World` verification,
//! pipe-origin-bound supervisor messaging, approval / grant integration,
//! and attempt / driver / reaper / startup-sweep supervision.

pub mod attempt;
pub mod driver;
pub mod ops;
pub mod reaper;
pub mod supervisor;
pub mod sweep;
pub mod targets;
