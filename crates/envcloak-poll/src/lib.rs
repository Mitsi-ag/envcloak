//! `envcloak-poll`: the one-shot `spend-poller` helper's provider adapters,
//! TLS verifier seam and response parser (SPEC §4.4, §8, §11; M4 plan D4-03,
//! D4-04, D4-27, task M4-06a). Linked into `envcloak` only and never into
//! `envcloakd`.
#![forbid(unsafe_code)]

pub mod tls;
