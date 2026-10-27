//! Registry grammar v2 (`[metrics]`, SPEC §8 "Adapters", D4-05) and its
//! value-free, float-free JSON and header extractor.
//!
//! Every value declared under `[metrics]` comes from one of three sources:
//! - a JSON path (`MetricSource::Json(JsonPath)`, up to 16 steps, with optional
//!   single-step `[field=value]` array selection),
//! - a response header on the fixed allowlist (`MetricSource::Header(AllowedHeader)`,
//!   never `set-cookie` or `authorization`), or
//! - a declared literal (`MetricSource::Literal { value, cited }`) that must carry
//!   a `source` citation naming the provider documentation it comes from.
//!
//! Every value has a declared `MetricUnit` (`major`, `minor`, `decimal_string`,
//! `cents_string`, `unix_seconds`, `rfc3339`, `github_expiry`, `bool`, `iso4217`,
//! or `enum(...)`). JSON `null` at a nullable value's path means "not set"
//! (`None`), never zero and never an error.

#![deny(clippy::float_arithmetic)]

use std::fmt;

use crate::error::RegistryErrorKind as K;
use crate::registry::Request;
use crate::safety::{FieldEq, JsonPath, PathSegment};

/// Maximum nesting depth when parsing an adapter JSON response body.
pub const MAX_JSON_DEPTH: usize = 64;

/// Earliest accepted timestamp (`1970-01-01T00:00:00Z`).
pub const MIN_TIMESTAMP_SECS: i64 = 0;

/// Latest accepted timestamp (`2100-01-01T00:00:00Z`).
pub const MAX_TIMESTAMP_SECS: i64 = 4_102_444_800;

/// Maximum fractional decimal scale (`0..=6`, matching `Money::MAX_SCALE`).
pub const MAX_DECIMAL_SCALE: u8 = 6;

/// A declarative `[metrics]` adapter (or a `[balance]` shorthand normalized
/// into the same structure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricsAdapter {
    pub request: Request,
    pub values: Vec<MetricSpec>,
}

/// One named value extracted by a `MetricsAdapter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricSpec {
    pub name: MetricName,
    pub source: MetricSource,
    pub unit: MetricUnit,
    pub select: Option<FieldEq>,
    pub nullable: bool,
}

/// Canonical metric names in registry grammar v2 (`D4-05`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricName {
    Balance,
    BalanceUsd,
    BalanceCny,
    VoucherBalance,
    CashBalance,
    Currency,
    CreditLimit,
    LimitRemaining,
    LimitReset,
    SpendDay,
    SpendWeek,
    SpendMonth,
    SpendTotal,
    ExpiresAt,
    CapAmount,
    CapEnforced,
    CapScope,
    IsManagementKey,
    ByokInLimit,
    RateLimitRemaining,
    RateLimitReset,
}

impl MetricName {
    pub fn parse(s: &str) -> Result<Self, K> {
        match s {
            "balance" => Ok(Self::Balance),
            "balance_usd" => Ok(Self::BalanceUsd),
            "balance_cny" => Ok(Self::BalanceCny),
            "voucher_balance" => Ok(Self::VoucherBalance),
            "cash_balance" => Ok(Self::CashBalance),
            "currency" => Ok(Self::Currency),
            "credit_limit" | "limit" => Ok(Self::CreditLimit),
            "limit_remaining" | "cap_remaining" => Ok(Self::LimitRemaining),
            "limit_reset" | "cap_reset" => Ok(Self::LimitReset),
            "spend_day" | "usage_daily" | "spend_daily" => Ok(Self::SpendDay),
            "spend_week" | "usage_weekly" | "spend_weekly" => Ok(Self::SpendWeek),
            "spend_month" | "usage_monthly" | "spend_monthly" => Ok(Self::SpendMonth),
            "spend_total" | "usage" => Ok(Self::SpendTotal),
            "expires_at" | "token_expires_at" => Ok(Self::ExpiresAt),
            "cap_amount" | "cap" => Ok(Self::CapAmount),
            "cap_enforced" => Ok(Self::CapEnforced),
            "cap_scope" => Ok(Self::CapScope),
            "is_management_key" => Ok(Self::IsManagementKey),
            "byok_in_limit" | "include_byok_in_limit" => Ok(Self::ByokInLimit),
            "rate_limit_remaining" => Ok(Self::RateLimitRemaining),
            "rate_limit_reset" => Ok(Self::RateLimitReset),
            _ => Err(K::InvalidMetricName),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Balance => "balance",
            Self::BalanceUsd => "balance_usd",
            Self::BalanceCny => "balance_cny",
            Self::VoucherBalance => "voucher_balance",
            Self::CashBalance => "cash_balance",
            Self::Currency => "currency",
            Self::CreditLimit => "credit_limit",
            Self::LimitRemaining => "limit_remaining",
            Self::LimitReset => "limit_reset",
            Self::SpendDay => "spend_day",
            Self::SpendWeek => "spend_week",
            Self::SpendMonth => "spend_month",
            Self::SpendTotal => "spend_total",
            Self::ExpiresAt => "expires_at",
            Self::CapAmount => "cap_amount",
            Self::CapEnforced => "cap_enforced",
            Self::CapScope => "cap_scope",
            Self::IsManagementKey => "is_management_key",
            Self::ByokInLimit => "byok_in_limit",
            Self::RateLimitRemaining => "rate_limit_remaining",
            Self::RateLimitReset => "rate_limit_reset",
        }
    }
}

impl fmt::Display for MetricName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a `MetricSpec` reads its value from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricSource {
    Json(JsonPath),
    Header(AllowedHeader),
    Literal { value: LiteralValue, cited: String },
}

/// Fixed allowlist of HTTP response headers a `[metrics]` value may read.
///
/// Never includes `set-cookie`, `authorization`, `cookie`, or any unlisted
/// header (`D4-05`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AllowedHeader {
    GithubAuthenticationTokenExpiration,
    XRateLimitRemaining,
    XRateLimitReset,
}

impl AllowedHeader {
    pub fn parse(s: &str) -> Result<Self, K> {
        match s {
            "github-authentication-token-expiration" => {
                Ok(Self::GithubAuthenticationTokenExpiration)
            }
            "x-ratelimit-remaining" => Ok(Self::XRateLimitRemaining),
            "x-ratelimit-reset" => Ok(Self::XRateLimitReset),
            _ => Err(K::HeaderNotAllowed),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GithubAuthenticationTokenExpiration => "github-authentication-token-expiration",
            Self::XRateLimitRemaining => "x-ratelimit-remaining",
            Self::XRateLimitReset => "x-ratelimit-reset",
        }
    }
}

impl fmt::Display for AllowedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A declared literal value inside a `MetricSpec`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiteralValue {
    Str(String),
    Bool(bool),
    Int(i64),
}

/// Declared unit of a `MetricSpec` (`D4-05`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricUnit {
    Major,
    Minor,
    DecimalString,
    CentsString,
    UnixSeconds,
    Rfc3339,
    GithubExpiry,
    Bool,
    Iso4217,
    Enum(Vec<String>),
}

impl MetricUnit {
    pub fn parse(s: &str) -> Result<Self, K> {
        match s {
            "major" => Ok(Self::Major),
            "minor" => Ok(Self::Minor),
            "decimal_string" => Ok(Self::DecimalString),
            "cents_string" => Ok(Self::CentsString),
            "unix_seconds" => Ok(Self::UnixSeconds),
            "rfc3339" => Ok(Self::Rfc3339),
            "github_expiry" => Ok(Self::GithubExpiry),
            "bool" => Ok(Self::Bool),
            "iso4217" => Ok(Self::Iso4217),
            _ => {
                let Some(inner) = s.strip_prefix("enum(").and_then(|r| r.strip_suffix(')')) else {
                    return Err(K::InvalidUnit);
                };
                let mut words = Vec::new();
                for part in inner.split(',') {
                    let word = part.trim_matches(' ');
                    if !valid_enum_word(word) || words.iter().any(|w| w == word) {
                        return Err(K::InvalidUnit);
                    }
                    words.push(word.to_owned());
                }
                if words.is_empty() || words.len() > 16 {
                    return Err(K::InvalidUnit);
                }
                Ok(Self::Enum(words))
            }
        }
    }

    /// Validates that a `LiteralValue` is well-formed for this unit.
    pub fn check_literal(&self, lit: &LiteralValue) -> Result<(), K> {
        match (self, lit) {
            (Self::Bool, LiteralValue::Bool(_)) => Ok(()),
            (Self::Iso4217, LiteralValue::Str(s)) if valid_iso4217(s) => Ok(()),
            (Self::Enum(words), LiteralValue::Str(s)) if words.iter().any(|w| w == s) => Ok(()),
            (Self::Major | Self::DecimalString, LiteralValue::Str(s))
                if parse_decimal_token(s, MAX_DECIMAL_SCALE).is_some() =>
            {
                Ok(())
            }
            (Self::Major | Self::Minor, LiteralValue::Int(_)) => Ok(()),
            (Self::Minor | Self::CentsString, LiteralValue::Str(s))
                if parse_decimal_token(s, 0).is_some() =>
            {
                Ok(())
            }
            (Self::UnixSeconds, LiteralValue::Int(ts))
                if (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS).contains(ts) =>
            {
                Ok(())
            }
            (Self::Rfc3339, LiteralValue::Str(s)) if parse_rfc3339(s).is_some() => Ok(()),
            (Self::GithubExpiry, LiteralValue::Str(s)) if parse_github_expiry(s).is_some() => {
                Ok(())
            }
            _ => Err(K::InvalidLiteral),
        }
    }
}

/// Validates that a literal's `source` citation is non-empty, has no control
/// characters, and references either an `https://` documentation URL or a
/// section in `research.md` / `SPEC.md`.
pub fn valid_literal_citation(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 512
        && !trimmed.chars().any(char::is_control)
        && (trimmed.contains("https://")
            || trimmed.contains("research.md")
            || trimmed.contains("SPEC.md"))
}

fn valid_enum_word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_iso4217(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// Exact base-10 value (`minor * 10^-scale`, with `scale` in `0..=6`) parsed
/// from a JSON number token or decimal string without `f64` (`D4-08`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScaledAmount {
    pub minor: i64,
    pub scale: u8,
}

impl ScaledAmount {
    /// Converts this amount to `target_scale` (`0..=6`), failing if rescaling
    /// would lose non-zero fractional digits or overflow `i64`.
    pub fn rescale(self, target_scale: u8) -> Option<i64> {
        if target_scale > MAX_DECIMAL_SCALE {
            return None;
        }
        if self.scale <= target_scale {
            let factor = 10_i64.checked_pow(u32::from(target_scale - self.scale))?;
            self.minor.checked_mul(factor)
        } else {
            let factor = 10_i64.checked_pow(u32::from(self.scale - target_scale))?;
            if self.minor % factor != 0 {
                return None;
            }
            Some(self.minor / factor)
        }
    }
}

/// A typed value extracted by `MetricsAdapter::extract`.
///
/// Carries no free-form provider text (`D4-03`, `D4-05`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricValue {
    Amount(ScaledAmount),
    Timestamp(i64),
    Bool(bool),
    Currency(String),
    Enum(String),
}

/// One extracted metric entry (`value` is `None` when a nullable metric's path
/// is `null` or absent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedMetric {
    pub name: MetricName,
    pub select: Option<FieldEq>,
    pub value: Option<MetricValue>,
}

/// All metrics extracted from one response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractedMetrics {
    pub entries: Vec<ExtractedMetric>,
}

impl ExtractedMetrics {
    /// Returns the first extracted metric matching `name` (with any `select`).
    pub fn get(&self, name: MetricName) -> Option<&ExtractedMetric> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Returns the extracted metric matching both `name` and `select`.
    pub fn get_selected(
        &self,
        name: MetricName,
        field: &str,
        value: &str,
    ) -> Option<&ExtractedMetric> {
        self.entries.iter().find(|e| {
            e.name == name
                && e.select
                    .as_ref()
                    .is_some_and(|s| s.field == field && s.value == value)
        })
    }
}

/// Value-free error returned when extracting metrics from a response fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsExtractError {
    MalformedJson,
    JsonTooDeep,
    PathNotFound,
    NullNotAllowed,
    TypeMismatch,
    ValueOutOfRange,
}

impl fmt::Display for MetricsExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MalformedJson => "response body is not valid JSON",
            Self::JsonTooDeep => "response JSON exceeds the maximum nesting depth",
            Self::PathNotFound => "declared metric path was not found in the response",
            Self::NullNotAllowed => "declared non-nullable metric was null",
            Self::TypeMismatch => "metric value did not match its declared unit",
            Self::ValueOutOfRange => "metric value is outside the accepted range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for MetricsExtractError {}

impl MetricsAdapter {
    /// Extracts all declared `MetricSpec` values from `body` and `headers`
    /// without floating-point arithmetic and without embedding any response
    /// text in errors.
    pub fn extract(
        &self,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<ExtractedMetrics, MetricsExtractError> {
        let needs_json = self
            .values
            .iter()
            .any(|v| matches!(v.source, MetricSource::Json(_)));
        let json_root = if needs_json || !body.is_empty() {
            let text = std::str::from_utf8(body).map_err(|_| MetricsExtractError::MalformedJson)?;
            Some(parse_json(text)?)
        } else {
            None
        };

        let mut entries = Vec::with_capacity(self.values.len());
        for spec in &self.values {
            let val = extract_one(spec, json_root.as_ref(), headers)?;
            entries.push(ExtractedMetric {
                name: spec.name,
                select: spec.select.clone(),
                value: val,
            });
        }
        Ok(ExtractedMetrics { entries })
    }
}

fn extract_one(
    spec: &MetricSpec,
    json_root: Option<&JsonVal>,
    headers: &[(&str, &str)],
) -> Result<Option<MetricValue>, MetricsExtractError> {
    match &spec.source {
        MetricSource::Literal { value, .. } => convert_literal(value, &spec.unit).map(Some),
        MetricSource::Header(hdr) => {
            let found = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(hdr.as_str()))
                .map(|(_, v)| v.trim());
            match found {
                None | Some("") | Some("none") if spec.nullable => Ok(None),
                None | Some("") => Err(MetricsExtractError::PathNotFound),
                Some(raw) => convert_str(raw, &spec.unit).map(Some),
            }
        }
        MetricSource::Json(path) => {
            let root = json_root.ok_or(MetricsExtractError::MalformedJson)?;
            match walk_json_path(root, path.segments())? {
                None => {
                    if spec.nullable {
                        Ok(None)
                    } else {
                        Err(MetricsExtractError::PathNotFound)
                    }
                }
                Some(JsonVal::Null) => {
                    if spec.nullable {
                        Ok(None)
                    } else {
                        Err(MetricsExtractError::NullNotAllowed)
                    }
                }
                Some(v) => convert_json_val(v, &spec.unit).map(Some),
            }
        }
    }
}

fn convert_literal(
    lit: &LiteralValue,
    unit: &MetricUnit,
) -> Result<MetricValue, MetricsExtractError> {
    match (unit, lit) {
        (MetricUnit::Bool, LiteralValue::Bool(b)) => Ok(MetricValue::Bool(*b)),
        (MetricUnit::Iso4217, LiteralValue::Str(s)) if valid_iso4217(s) => {
            Ok(MetricValue::Currency(s.clone()))
        }
        (MetricUnit::Enum(words), LiteralValue::Str(s)) if words.iter().any(|w| w == s) => {
            Ok(MetricValue::Enum(s.clone()))
        }
        (MetricUnit::Major, LiteralValue::Int(n)) => Ok(MetricValue::Amount(ScaledAmount {
            minor: *n,
            scale: 0,
        })),
        (MetricUnit::Minor, LiteralValue::Int(n)) => Ok(MetricValue::Amount(ScaledAmount {
            minor: *n,
            scale: 2,
        })),
        (MetricUnit::UnixSeconds, LiteralValue::Int(ts)) => {
            if (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS).contains(ts) {
                Ok(MetricValue::Timestamp(*ts))
            } else {
                Err(MetricsExtractError::ValueOutOfRange)
            }
        }
        (_, LiteralValue::Str(s)) => convert_str(s, unit),
        _ => Err(MetricsExtractError::TypeMismatch),
    }
}

fn convert_json_val(v: &JsonVal, unit: &MetricUnit) -> Result<MetricValue, MetricsExtractError> {
    match (unit, v) {
        (MetricUnit::Major, JsonVal::Number(raw)) => {
            let amt = parse_decimal_token(raw, MAX_DECIMAL_SCALE)
                .ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Amount(amt))
        }
        (MetricUnit::Minor, JsonVal::Number(raw)) => {
            let amt = parse_decimal_token(raw, 0).ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Amount(ScaledAmount {
                minor: amt.minor,
                scale: 2,
            }))
        }
        (MetricUnit::UnixSeconds, JsonVal::Number(raw)) => {
            let amt = parse_decimal_token(raw, 0).ok_or(MetricsExtractError::ValueOutOfRange)?;
            if (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS).contains(&amt.minor) {
                Ok(MetricValue::Timestamp(amt.minor))
            } else {
                Err(MetricsExtractError::ValueOutOfRange)
            }
        }
        (MetricUnit::Bool, JsonVal::Bool(b)) => Ok(MetricValue::Bool(*b)),
        (
            MetricUnit::DecimalString
            | MetricUnit::CentsString
            | MetricUnit::Rfc3339
            | MetricUnit::GithubExpiry
            | MetricUnit::Iso4217
            | MetricUnit::Enum(_),
            JsonVal::Str(s),
        ) => convert_str(s, unit),
        _ => Err(MetricsExtractError::TypeMismatch),
    }
}

fn convert_str(s: &str, unit: &MetricUnit) -> Result<MetricValue, MetricsExtractError> {
    match unit {
        MetricUnit::DecimalString | MetricUnit::Major => {
            let amt = parse_decimal_token(s, MAX_DECIMAL_SCALE)
                .ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Amount(amt))
        }
        MetricUnit::CentsString | MetricUnit::Minor => {
            let amt = parse_decimal_token(s, 0).ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Amount(ScaledAmount {
                minor: amt.minor,
                scale: 2,
            }))
        }
        MetricUnit::UnixSeconds => {
            let amt = parse_decimal_token(s, 0).ok_or(MetricsExtractError::ValueOutOfRange)?;
            if (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS).contains(&amt.minor) {
                Ok(MetricValue::Timestamp(amt.minor))
            } else {
                Err(MetricsExtractError::ValueOutOfRange)
            }
        }
        MetricUnit::Rfc3339 => {
            let ts = parse_rfc3339(s).ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Timestamp(ts))
        }
        MetricUnit::GithubExpiry => {
            let ts = parse_github_expiry(s).ok_or(MetricsExtractError::ValueOutOfRange)?;
            Ok(MetricValue::Timestamp(ts))
        }
        MetricUnit::Bool => match s {
            "true" => Ok(MetricValue::Bool(true)),
            "false" => Ok(MetricValue::Bool(false)),
            _ => Err(MetricsExtractError::TypeMismatch),
        },
        MetricUnit::Iso4217 => {
            if valid_iso4217(s) {
                Ok(MetricValue::Currency(s.to_owned()))
            } else {
                Err(MetricsExtractError::ValueOutOfRange)
            }
        }
        MetricUnit::Enum(words) => {
            if words.iter().any(|w| w == s) {
                Ok(MetricValue::Enum(s.to_owned()))
            } else {
                Err(MetricsExtractError::ValueOutOfRange)
            }
        }
    }
}

/// Parses a decimal number token (sign, integer part, optional fraction,
/// optional `e`/`E` exponent) into a `ScaledAmount` with `scale <= max_scale`
/// without touching `f32` or `f64` (`D4-08`).
pub fn parse_decimal_token(raw: &str, max_scale: u8) -> Option<ScaledAmount> {
    if max_scale > MAX_DECIMAL_SCALE || raw.is_empty() || raw.len() > 64 {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    let negative = if bytes[0] == b'-' {
        i += 1;
        true
    } else {
        false
    };
    if i >= bytes.len() {
        return None;
    }

    // Split mantissa and optional exponent (`e`/`E`).
    let exp_pos = bytes[i..]
        .iter()
        .position(|&b| b == b'e' || b == b'E')
        .map(|p| i + p);
    let mantissa = &raw[i..exp_pos.unwrap_or(raw.len())];
    let exp: i32 = if let Some(ep) = exp_pos {
        let exp_str = &raw[ep + 1..];
        if exp_str.is_empty() || exp_str.len() > 4 {
            return None;
        }
        let eb = exp_str.as_bytes();
        let (exp_neg, start) = match eb[0] {
            b'-' => (true, 1),
            b'+' => (false, 1),
            _ => (false, 0),
        };
        if start >= eb.len() || !eb[start..].iter().all(u8::is_ascii_digit) {
            return None;
        }
        let val: i32 = exp_str[start..].parse().ok()?;
        if exp_neg { -val } else { val }
    } else {
        0
    };

    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((a, b)) => {
            if b.is_empty() || b.contains('.') {
                return None;
            }
            (a, b)
        }
        None => (mantissa, ""),
    };
    if int_part.is_empty()
        || !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // RFC 8259 disallows leading zeros on the integer part (e.g. `01`).
    if int_part.len() > 1 && int_part.starts_with('0') {
        return None;
    }

    // Collect combined decimal digits and track the effective decimal shift.
    let mut digits: Vec<u8> = Vec::with_capacity(int_part.len() + frac_part.len());
    for b in int_part.bytes().chain(frac_part.bytes()) {
        digits.push(b - b'0');
    }
    let frac_len = i32::try_from(frac_part.len()).ok()?;
    // Value is `digits_int * 10^(exp - frac_len)`.
    let mut scale_i32 = frac_len.checked_sub(exp)?;

    // If `scale_i32 < 0`, append zeros so `scale_i32 == 0`.
    if scale_i32 < 0 {
        let zeros = usize::try_from(-scale_i32).ok()?;
        if zeros > 18 {
            return None;
        }
        digits.resize(digits.len() + zeros, 0);
        scale_i32 = 0;
    }

    // Strip trailing fractional zeros beyond `max_scale` (or down to minimum
    // needed scale while preserving exact value).
    while scale_i32 > i32::from(max_scale) && digits.last() == Some(&0) {
        digits.pop();
        scale_i32 -= 1;
    }
    if scale_i32 > i32::from(max_scale) {
        return None;
    }
    let scale = u8::try_from(scale_i32).ok()?;

    // Accumulate as `i128` with sign so `i64::MIN` and large values are checked cleanly.
    let mut acc: i128 = 0;
    for d in digits {
        acc = acc.checked_mul(10)?.checked_add(i128::from(d))?;
        if acc > i128::from(i64::MAX) {
            return None;
        }
    }
    let signed = if negative { -acc } else { acc };
    let minor = i64::try_from(signed).ok()?;
    Some(ScaledAmount { minor, scale })
}

/// Parses an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`) into
/// Unix seconds in `MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS`.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    if s.len() < 20 || s.len() > 40 || !s.is_ascii() {
        return None;
    }
    let date = &s[0..10];
    let sep = s.as_bytes()[10];
    if sep != b'T' && sep != b't' {
        return None;
    }
    let time = &s[11..19];
    let mut rest = &s[19..];

    // Optional fractional seconds (`.123456789`), truncated toward start of second.
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        if frac_len == 0 || frac_len > 9 {
            return None;
        }
        rest = &after_dot[frac_len..];
    }

    let offset_secs = match rest {
        "Z" | "z" => 0_i64,
        _ => parse_tz_offset(rest)?,
    };
    let utc_naive = parse_ymd_hms(date, time)?;
    let ts = utc_naive.checked_sub(offset_secs)?;
    (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS)
        .contains(&ts)
        .then_some(ts)
}

/// Parses GitHub's `GitHub-Authentication-Token-Expiration` header value
/// (`YYYY-MM-DD HH:MM:SS UTC` or `YYYY-MM-DD HH:MM:SS ±HHMM` / `±HH:MM`,
/// documented in `m4/research.md` §2.6, Review log `F29`) into Unix seconds.
pub fn parse_github_expiry(s: &str) -> Option<i64> {
    let trimmed = s.trim_matches(' ');
    if trimmed.len() < 22 || trimmed.len() > 32 || !trimmed.is_ascii() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    if bytes.get(10) != Some(&b' ') || bytes.get(19) != Some(&b' ') {
        return None;
    }
    let date = &trimmed[0..10];
    let time = &trimmed[11..19];
    let tz = &trimmed[20..];
    let offset_secs = match tz {
        "UTC" => 0_i64,
        _ => parse_tz_offset(tz)?,
    };
    let utc_naive = parse_ymd_hms(date, time)?;
    let ts = utc_naive.checked_sub(offset_secs)?;
    (MIN_TIMESTAMP_SECS..=MAX_TIMESTAMP_SECS)
        .contains(&ts)
        .then_some(ts)
}

fn parse_tz_offset(tz: &str) -> Option<i64> {
    let b = tz.as_bytes();
    if b.is_empty() {
        return None;
    }
    let sign: i64 = match b[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hh_str, mm_str) = match tz.len() {
        5 => (&tz[1..3], &tz[3..5]),
        6 if b[3] == b':' => (&tz[1..3], &tz[4..6]),
        _ => return None,
    };
    let hh = parse_2digits(hh_str)?;
    let mm = parse_2digits(mm_str)?;
    if hh > 23 || mm > 59 {
        return None;
    }
    Some(sign * (i64::from(hh) * 3600 + i64::from(mm) * 60))
}

fn parse_ymd_hms(date: &str, time: &str) -> Option<i64> {
    let db = date.as_bytes();
    let tb = time.as_bytes();
    if db.len() != 10 || db[4] != b'-' || db[7] != b'-' {
        return None;
    }
    if tb.len() != 8 || tb[2] != b':' || tb[5] != b':' {
        return None;
    }
    if !date[0..4].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i32 = date[0..4].parse().ok()?;
    let month = parse_2digits(&date[5..7])?;
    let day = parse_2digits(&date[8..10])?;
    let hour = parse_2digits(&time[0..2])?;
    let minute = parse_2digits(&time[3..5])?;
    let second = parse_2digits(&time[6..8])?;

    if !(1970..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?;
    Some(secs)
}

fn parse_2digits(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
}

const fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

const fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's civil-to-days algorithm (days since `1970-01-01`).
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    let y = i64::from(y) - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m_i64 = i64::from(m);
    let d_i64 = i64::from(d);
    let doy = (153 * (m_i64 + if m_i64 > 2 { -3 } else { 9 }) + 2) / 5 + d_i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

// ---------------------------------------------------------------------------
// Minimal, zero-float, depth-bounded RFC 8259 JSON parser and path walker
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum JsonVal {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonVal>),
    Object(Vec<(String, JsonVal)>),
}

fn walk_json_path<'a>(
    mut cur: &'a JsonVal,
    segments: &[PathSegment],
) -> Result<Option<&'a JsonVal>, MetricsExtractError> {
    for seg in segments {
        match seg {
            PathSegment::Key(key) => {
                let JsonVal::Object(entries) = cur else {
                    return Err(MetricsExtractError::TypeMismatch);
                };
                match entries.iter().find(|(k, _)| k == key) {
                    Some((_, v)) => cur = v,
                    None => return Ok(None),
                }
            }
            PathSegment::Index(idx) => {
                let JsonVal::Array(items) = cur else {
                    return Err(MetricsExtractError::TypeMismatch);
                };
                match usize::try_from(*idx).ok().and_then(|i| items.get(i)) {
                    Some(v) => cur = v,
                    None => return Ok(None),
                }
            }
            PathSegment::Select(eq) => {
                let JsonVal::Array(items) = cur else {
                    return Err(MetricsExtractError::TypeMismatch);
                };
                let mut matched = None;
                for item in items {
                    let JsonVal::Object(entries) = item else {
                        return Err(MetricsExtractError::TypeMismatch);
                    };
                    if entries.iter().any(|(k, v)| {
                        k == &eq.field && matches!(v, JsonVal::Str(s) if s == &eq.value)
                    }) {
                        matched = Some(item);
                        break;
                    }
                }
                match matched {
                    Some(v) => cur = v,
                    None => return Ok(None),
                }
            }
        }
    }
    Ok(Some(cur))
}

fn parse_json(input: &str) -> Result<JsonVal, MetricsExtractError> {
    let mut p = JsonParser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let val = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(MetricsExtractError::MalformedJson);
    }
    Ok(val)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonVal, MetricsExtractError> {
        if depth > MAX_JSON_DEPTH {
            return Err(MetricsExtractError::JsonTooDeep);
        }
        self.skip_ws();
        match self.peek().ok_or(MetricsExtractError::MalformedJson)? {
            b'n' => self.parse_literal(b"null", JsonVal::Null),
            b't' => self.parse_literal(b"true", JsonVal::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonVal::Bool(false)),
            b'"' => self.parse_string().map(JsonVal::Str),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number().map(JsonVal::Number),
            _ => Err(MetricsExtractError::MalformedJson),
        }
    }

    fn parse_literal(
        &mut self,
        expected: &[u8],
        out: JsonVal,
    ) -> Result<JsonVal, MetricsExtractError> {
        if self.bytes.get(self.pos..self.pos + expected.len()) == Some(expected) {
            self.pos += expected.len();
            Ok(out)
        } else {
            Err(MetricsExtractError::MalformedJson)
        }
    }

    fn parse_string(&mut self) -> Result<String, MetricsExtractError> {
        if self.peek() != Some(b'"') {
            return Err(MetricsExtractError::MalformedJson);
        }
        self.pos += 1;
        let mut out = String::new();
        while let Some(&b) = self.bytes.get(self.pos) {
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or(MetricsExtractError::MalformedJson)?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate: require `\uDC00`..`\uDFFF` next.
                                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(MetricsExtractError::MalformedJson);
                                }
                                self.pos += 2;
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(MetricsExtractError::MalformedJson);
                                }
                                let combined = 0x10000
                                    + ((u32::from(cp - 0xD800) << 10) | u32::from(low - 0xDC00));
                                let ch = char::from_u32(combined)
                                    .ok_or(MetricsExtractError::MalformedJson)?;
                                out.push(ch);
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err(MetricsExtractError::MalformedJson);
                            } else {
                                let ch = char::from_u32(u32::from(cp))
                                    .ok_or(MetricsExtractError::MalformedJson)?;
                                out.push(ch);
                            }
                        }
                        _ => return Err(MetricsExtractError::MalformedJson),
                    }
                }
                0x00..=0x1F => return Err(MetricsExtractError::MalformedJson),
                _ => {
                    // Advance one full UTF-8 scalar from `self.pos - 1`.
                    let start = self.pos - 1;
                    let rest = std::str::from_utf8(&self.bytes[start..])
                        .map_err(|_| MetricsExtractError::MalformedJson)?;
                    let ch = rest
                        .chars()
                        .next()
                        .ok_or(MetricsExtractError::MalformedJson)?;
                    self.pos = start + ch.len_utf8();
                    out.push(ch);
                }
            }
        }
        Err(MetricsExtractError::MalformedJson)
    }

    fn parse_hex4(&mut self) -> Result<u16, MetricsExtractError> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or(MetricsExtractError::MalformedJson)?;
        let s = std::str::from_utf8(slice).map_err(|_| MetricsExtractError::MalformedJson)?;
        let val = u16::from_str_radix(s, 16).map_err(|_| MetricsExtractError::MalformedJson)?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<String, MetricsExtractError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(MetricsExtractError::MalformedJson);
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(MetricsExtractError::MalformedJson),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(MetricsExtractError::MalformedJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(MetricsExtractError::MalformedJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| MetricsExtractError::MalformedJson)?;
        Ok(raw.to_owned())
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonVal, MetricsExtractError> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonVal::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonVal::Array(items));
                }
                _ => return Err(MetricsExtractError::MalformedJson),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonVal, MetricsExtractError> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries: Vec<(String, JsonVal)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonVal::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(MetricsExtractError::MalformedJson);
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            // Reject duplicate object keys in the same JSON object so ambiguous
            // responses cannot smuggle differing values between parsers.
            if entries.iter().any(|(k, _)| k == &key) {
                return Err(MetricsExtractError::MalformedJson);
            }
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonVal::Object(entries));
                }
                _ => return Err(MetricsExtractError::MalformedJson),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decimal_token_parsing_has_no_floats() {
        let a = parse_decimal_token("12.34", 6).unwrap();
        assert_eq!(a.rescale(2), Some(1234));
        assert_eq!(a.rescale(6), Some(12_340_000));

        let neg = parse_decimal_token("-3.25", 6).unwrap();
        assert_eq!(neg.rescale(2), Some(-325));

        let sci = parse_decimal_token("1.5e-3", 6).unwrap();
        assert_eq!(sci.rescale(4), Some(15));

        assert!(parse_decimal_token("1.1234567", 6).is_none());
        assert!(parse_decimal_token("01.5", 6).is_none());
        assert!(parse_decimal_token("", 6).is_none());
    }

    #[test]
    fn github_expiry_and_rfc3339_parsing() {
        assert_eq!(
            parse_github_expiry("2026-11-15 08:30:00 UTC"),
            Some(1_794_731_400)
        );
        assert_eq!(
            parse_github_expiry("2026-11-15 16:30:00 +0800"),
            Some(1_794_731_400)
        );
        assert_eq!(parse_rfc3339("2026-11-15T08:30:00Z"), Some(1_794_731_400));
        assert_eq!(
            parse_rfc3339("2026-11-15T08:30:00.123456Z"),
            Some(1_794_731_400)
        );
        assert!(parse_github_expiry("2026-02-29 00:00:00 UTC").is_none());
        assert!(parse_github_expiry("2101-01-01 00:00:00 UTC").is_none());
    }
}
