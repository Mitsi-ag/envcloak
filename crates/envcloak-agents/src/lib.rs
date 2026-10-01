//! EnvCloak's agent integrations (SPEC §7).
//!
//! So far this crate holds [`probe::model`], the scripted model that the
//! agent hosts are pointed at when EnvCloak drives them for a coverage
//! probe or a test (M2 plan task M2-04, decision D-13), shipped as the
//! program `envcloak-probe-model`. The installers, the hook handler and
//! the catalog of host paths come with later tasks.

pub mod probe;
