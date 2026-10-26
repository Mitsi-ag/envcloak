//! Key health status derivation (SPEC §8, D4-18, M4-02).

/// Ninety days in seconds (`90 * 86_400`).
pub const UNUSED_90_DAYS_SECS: u64 = 90 * 86_400;

/// Default expiring-soon window in days (D4-16).
pub const DEFAULT_EXPIRING_DAYS: u16 = 14;

/// Status of a stored API key (SPEC §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyStatus {
    Ok,
    LowBalance,
    Expiring {
        /// Effective expiry timestamp (earlier of item and adapter expiry).
        expires_at: u64,
        /// Whole days remaining (0 when already expired or expiring today).
        days_left: u16,
    },
    Invalid,
    Leaked,
    Unused90Days,
}

impl KeyStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyStatus::Ok => "ok",
            KeyStatus::LowBalance => "low balance",
            KeyStatus::Expiring { .. } => "expiring",
            KeyStatus::Invalid => "invalid",
            KeyStatus::Leaked => "leaked",
            KeyStatus::Unused90Days => "unused 90 days",
        }
    }
}

/// Inputs used to evaluate a key's [`KeyStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStatusInputs {
    pub leaked: bool,
    pub invalid: bool,
    pub low_balance: bool,
    pub item_expires_at: Option<u64>,
    pub adapter_expires_at: Option<u64>,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub now: u64,
    pub expiring_window_days: u16,
}

/// Returns the earlier of an item's own `expires_at` and the adapter-reported
/// `expires_at` (M4-13, SPEC §8).
pub fn effective_expiry(
    item_expires_at: Option<u64>,
    adapter_expires_at: Option<u64>,
) -> Option<u64> {
    match (item_expires_at, adapter_expires_at) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Evaluates [`KeyStatus`] from [`KeyStatusInputs`].
pub fn evaluate_key_status(inputs: &KeyStatusInputs) -> KeyStatus {
    if inputs.leaked {
        return KeyStatus::Leaked;
    }
    if inputs.invalid {
        return KeyStatus::Invalid;
    }
    if inputs.low_balance {
        return KeyStatus::LowBalance;
    }
    if let Some(exp) = effective_expiry(inputs.item_expires_at, inputs.adapter_expires_at) {
        let window_secs = u64::from(inputs.expiring_window_days).saturating_mul(86_400);
        if exp <= inputs.now.saturating_add(window_secs) {
            let rem_secs = exp.saturating_sub(inputs.now);
            let days_left = u16::try_from(rem_secs / 86_400).unwrap_or(u16::MAX);
            return KeyStatus::Expiring {
                expires_at: exp,
                days_left,
            };
        }
    }
    let anchor = inputs.last_used_at.unwrap_or(inputs.created_at);
    if inputs.now.saturating_sub(anchor) >= UNUSED_90_DAYS_SECS {
        return KeyStatus::Unused90Days;
    }
    KeyStatus::Ok
}
