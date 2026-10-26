//! Registration and dispatch of the 19 D-30 hosted browser tools on
//! [`crate::router::Router`].

use crate::router::{RegisterError, Router};

use super::relay::BrowserRelay;

/// Registers the 19 allowlisted `@playwright/mcp` browser tools (`browser_*`)
/// onto `router` backed by `relay`.
///
/// Native `envcloak_*` and `envcloak.signin.*` tools remain handled by the
/// router's own handlers while `browser_*` tools route through `relay`.
pub fn register_browser_tools(
    router: &mut Router,
    relay: BrowserRelay,
) -> Result<(), RegisterError> {
    router.register_backend("browser_", Box::new(relay))
}
