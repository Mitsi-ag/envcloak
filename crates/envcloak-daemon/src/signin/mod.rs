//! Daemon sign-in subsystem (`M2b-05`): target management
//! (`signin.target.add|edit|remove|list`), operation lifecycle
//! (`signin.request|status|cancel|end`), live `World` verification,
//! pipe-origin-bound supervisor messaging, and approval / grant integration.

pub mod ops;
pub mod targets;
