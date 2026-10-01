//! Coverage probes (SPEC §7.2 rule 2): synthetic activation and denial
//! checks run against a real agent host in an isolated HOME. This task
//! lands the model the hosts talk to during a probe ([`model`]); the
//! probes themselves come with M2-09 and M2-28.

pub mod model;
