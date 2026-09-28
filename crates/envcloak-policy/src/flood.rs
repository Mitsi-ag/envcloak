//! Prompt-flood control (SPEC §10a "Bounds and display"; gate 32): the
//! pending caps, denied requests remembered for a while, and roots that
//! are denied outright after repeated denials.
//!
//! - At most [`MAX_PENDING_PER_ROOT`] pending requests per subject root
//!   and [`MAX_PENDING`] per daemon; a request beyond a cap is denied.
//! - A request identical to one denied in the last [`DENIAL_WINDOW`] is
//!   denied without a prompt. Identity is a fingerprint of the root, the
//!   project, the bindings, the mode and the command line.
//! - [`DENIALS_TO_AUTO_DENY`] denials for one root within
//!   [`DENIAL_WINDOW`] deny that root for [`AUTO_DENY`], whatever it asks.
//!
//! Windows count time awake ([`crate::Now::awake`]): a machine asleep
//! serves none of them. This state survives a lock; it only tightens. It
//! is bounded: at most [`MAX_DENIALS`] denials are remembered, the oldest
//! forgotten first, and auto-denied roots leave when their time passes.

use std::collections::HashMap;
use std::time::Duration;

use crate::evidence::ProcessInstance;
use crate::grants::Now;

/// Pending requests one root may hold.
pub const MAX_PENDING_PER_ROOT: usize = 3;
/// Pending requests the daemon holds in all.
pub const MAX_PENDING: usize = 20;
/// How long a denial is remembered, and the window for the auto-deny.
pub const DENIAL_WINDOW: Duration = Duration::from_secs(600);
/// Denials for one root within the window that deny it outright.
pub const DENIALS_TO_AUTO_DENY: u32 = 3;
/// How long an auto-denied root stays denied.
pub const AUTO_DENY: Duration = Duration::from_secs(1800);
/// The most denials remembered at once.
pub const MAX_DENIALS: usize = 64;

/// A denied request: whose, what, and when (awake time).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Denial {
    root: ProcessInstance,
    fingerprint: [u8; 32],
    at: Duration,
}

/// Denials and auto-denied roots.
#[derive(Debug, Clone, Default)]
pub struct FloodControl {
    denials: Vec<Denial>,
    /// Each root and the awake time its denial ends.
    auto_denied: HashMap<ProcessInstance, Duration>,
}

impl FloodControl {
    pub fn new() -> Self {
        FloodControl::default()
    }

    /// Forgets denials older than the window and auto-denies that ended.
    pub fn expire(&mut self, now: &Now) {
        self.denials
            .retain(|d| now.awake.saturating_sub(d.at) < DENIAL_WINDOW);
        self.auto_denied.retain(|_, until| *until > now.awake);
    }

    /// Whether `root` is auto-denied at `now`.
    pub fn root_denied(&self, root: &ProcessInstance, now: &Now) -> bool {
        self.auto_denied
            .get(root)
            .is_some_and(|until| *until > now.awake)
    }

    /// Whether a request with this fingerprint was denied within the
    /// window.
    pub fn recently_denied(&self, fingerprint: &[u8; 32], now: &Now) -> bool {
        self.denials.iter().any(|d| {
            d.fingerprint == *fingerprint && now.awake.saturating_sub(d.at) < DENIAL_WINDOW
        })
    }

    /// Records that a request from `root` was denied. Returns whether this
    /// denial auto-denied the root.
    pub fn record_denial(
        &mut self,
        root: ProcessInstance,
        fingerprint: [u8; 32],
        now: &Now,
    ) -> bool {
        self.expire(now);
        if self.denials.len() >= MAX_DENIALS {
            self.denials.remove(0);
        }
        self.denials.push(Denial {
            root: root.clone(),
            fingerprint,
            at: now.awake,
        });
        let recent = self.denials.iter().filter(|d| d.root == root).count();
        if recent >= DENIALS_TO_AUTO_DENY as usize {
            self.auto_denied.insert(root, now.awake + AUTO_DENY);
            true
        } else {
            false
        }
    }

    /// How many denials are remembered.
    pub fn denials(&self) -> usize {
        self.denials.len()
    }
}
