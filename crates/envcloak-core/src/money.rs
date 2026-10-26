//! Integer money representation, ISO 4217 currency codes, adapter units and
//! float-free decimal parsing (SPEC §5, §8; M4 plan decisions D4-05, D4-08,
//! D4-27, task M4-02).
//!
//! No floating-point type or operation is used anywhere in this module
//! (`scripts/check-spend-floats.sh`). JSON numbers and decimal strings are
//! parsed directly from their ASCII digits and optional exponent into exact
//! integer minor units.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

/// The largest scale [`Money`] stores (0 to 6 decimal places, D4-08).
pub const MAX_SCALE: u8 = 6;

/// The largest absolute minor-unit value [`Money`] accepts (`10^12`, M4 plan
/// §5 rule 3).
pub const MAX_MINOR: i64 = 1_000_000_000_000;

/// The smallest minor-unit value [`Money`] accepts (`-10^12`, M4 plan §5
/// rule 3).
pub const MIN_MINOR: i64 = -1_000_000_000_000;

const POW10_I64: [i64; 13] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
];

const POW10_I128: [i128; 20] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
    10_000_000_000_000,
    100_000_000_000_000,
    1_000_000_000_000_000,
    10_000_000_000_000_000,
    100_000_000_000_000_000,
    1_000_000_000_000_000_000,
    10_000_000_000_000_000_000,
];

/// An uppercase three-letter ISO 4217 currency code (`USD`, `EUR`, `CNY`,
/// `JPY`, ...).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Iso4217([u8; 3]);

impl Iso4217 {
    pub const USD: Self = Self(*b"USD");
    pub const EUR: Self = Self(*b"EUR");
    pub const GBP: Self = Self(*b"GBP");
    pub const CNY: Self = Self(*b"CNY");
    pub const JPY: Self = Self(*b"JPY");
    pub const CAD: Self = Self(*b"CAD");
    pub const AUD: Self = Self(*b"AUD");
    pub const CHF: Self = Self(*b"CHF");
    pub const HKD: Self = Self(*b"HKD");
    pub const SGD: Self = Self(*b"SGD");
    pub const KRW: Self = Self(*b"KRW");
    pub const INR: Self = Self(*b"INR");
    pub const BRL: Self = Self(*b"BRL");
    pub const MXN: Self = Self(*b"MXN");
    pub const NZD: Self = Self(*b"NZD");
    pub const SEK: Self = Self(*b"SEK");
    pub const NOK: Self = Self(*b"NOK");
    pub const DKK: Self = Self(*b"DKK");
    pub const PLN: Self = Self(*b"PLN");
    pub const ZAR: Self = Self(*b"ZAR");
    pub const TRY: Self = Self(*b"TRY");
    pub const AED: Self = Self(*b"AED");
    pub const SAR: Self = Self(*b"SAR");
    pub const ILS: Self = Self(*b"ILS");
    pub const TWD: Self = Self(*b"TWD");
    pub const THB: Self = Self(*b"THB");
    pub const MYR: Self = Self(*b"MYR");
    pub const IDR: Self = Self(*b"IDR");
    pub const PHP: Self = Self(*b"PHP");
    pub const VND: Self = Self(*b"VND");
    pub const CLP: Self = Self(*b"CLP");
    pub const ISK: Self = Self(*b"ISK");
    pub const KWD: Self = Self(*b"KWD");
    pub const BHD: Self = Self(*b"BHD");
    pub const OMR: Self = Self(*b"OMR");
    pub const JOD: Self = Self(*b"JOD");
    pub const TND: Self = Self(*b"TND");

    /// Known ISO 4217 currency codes and their standard minor-unit exponent.
    const KNOWN: &[([u8; 3], u8)] = &[
        (*b"AED", 2),
        (*b"ARS", 2),
        (*b"AUD", 2),
        (*b"BDT", 2),
        (*b"BGN", 2),
        (*b"BHD", 3),
        (*b"BRL", 2),
        (*b"CAD", 2),
        (*b"CHF", 2),
        (*b"CLP", 0),
        (*b"CNY", 2),
        (*b"COP", 2),
        (*b"CZK", 2),
        (*b"DKK", 2),
        (*b"EGP", 2),
        (*b"EUR", 2),
        (*b"GBP", 2),
        (*b"HKD", 2),
        (*b"HUF", 2),
        (*b"IDR", 2),
        (*b"ILS", 2),
        (*b"INR", 2),
        (*b"ISK", 0),
        (*b"JOD", 3),
        (*b"JPY", 0),
        (*b"KES", 2),
        (*b"KRW", 0),
        (*b"KWD", 3),
        (*b"MAD", 2),
        (*b"MXN", 2),
        (*b"MYR", 2),
        (*b"NGN", 2),
        (*b"NOK", 2),
        (*b"NZD", 2),
        (*b"OMR", 3),
        (*b"PEN", 2),
        (*b"PHP", 2),
        (*b"PKR", 2),
        (*b"PLN", 2),
        (*b"QAR", 2),
        (*b"RON", 2),
        (*b"SAR", 2),
        (*b"SEK", 2),
        (*b"SGD", 2),
        (*b"THB", 2),
        (*b"TND", 3),
        (*b"TRY", 2),
        (*b"TWD", 2),
        (*b"UAH", 2),
        (*b"USD", 2),
        (*b"VND", 0),
        (*b"ZAR", 2),
    ];

    /// Parses a three-letter uppercase ISO 4217 currency code.
    pub fn from_bytes(bytes: [u8; 3]) -> Result<Self, UnitError> {
        if Self::KNOWN
            .binary_search_by_key(&bytes, |(c, _)| *c)
            .is_ok()
        {
            Ok(Self(bytes))
        } else {
            Err(UnitError::InvalidCurrency)
        }
    }

    /// Parses a three-letter uppercase ISO 4217 currency code from a string.
    pub fn parse(s: &str) -> Result<Self, UnitError> {
        let b: [u8; 3] = s
            .as_bytes()
            .try_into()
            .map_err(|_| UnitError::InvalidCurrency)?;
        Self::from_bytes(b)
    }

    /// The three-byte ASCII code.
    pub const fn as_bytes(self) -> [u8; 3] {
        self.0
    }

    /// The three-letter code as a `&str`.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("???")
    }

    /// The standard ISO 4217 minor-unit scale (0, 2, or 3).
    pub fn default_scale(self) -> u8 {
        match Self::KNOWN.binary_search_by_key(&self.0, |(c, _)| *c) {
            Ok(i) => Self::KNOWN[i].1,
            Err(_) => 2,
        }
    }
}

impl fmt::Debug for Iso4217 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Iso4217 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Iso4217 {
    type Err = UnitError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Rounding modes when reducing a parsed decimal to a target scale (`D4-08`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rounding {
    /// Fail with [`UnitError::Inexact`] if non-zero digits would be discarded.
    Exact,
    /// Round half away from zero (`0.005 -> 0.01`, `-0.005 -> -0.01`).
    HalfAwayFromZero,
    /// Round toward positive infinity (conservative for spend/burn figures).
    Ceiling,
    /// Round toward negative infinity (conservative for remaining balance/runway).
    Floor,
    /// Truncate toward zero.
    TowardZero,
}

/// Adapter and parser units (D4-05, D4-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// A JSON number in major currency units (`12.34` USD -> `1234` at scale 2,
    /// or up to scale 6 when more fractional digits are present).
    Major(Iso4217),
    /// A JSON number in minor currency units (`1234` USD -> `12.34 USD`).
    Minor(Iso4217),
    /// A quoted decimal string in major currency units (`"12.34"` USD).
    DecimalString(Iso4217),
    /// A quoted decimal or integer string in cents (`"1234"` -> `12.34 USD`,
    /// `"12.5"` -> `0.125 USD` at scale 3; OpenAI/Anthropic cents strings).
    CentsString(Iso4217),
    /// Unix timestamp in seconds.
    UnixSeconds,
    /// RFC 3339 timestamp string.
    Rfc3339,
    /// GitHub `GitHub-Authentication-Token-Expiration` header timestamp.
    GithubExpiry,
    /// Boolean metric (`true` / `false`).
    Bool,
    /// Closed set of allowed enum words (`daily`, `weekly`, `monthly`).
    Enum(Vec<String>),
}

/// Errors returned by [`Money`], [`Iso4217`] and [`parse_decimal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitError {
    /// Currency code is not a known 3-letter uppercase ISO 4217 code.
    InvalidCurrency,
    /// Scale exceeds [`MAX_SCALE`] (6).
    InvalidScale(u8),
    /// Minor units exceed [`MIN_MINOR`]..=[`MAX_MINOR`] (`±10^12`) or overflowed.
    OutOfBounds,
    /// Two [`Money`] values have different currencies (`currency_mismatch`).
    CurrencyMismatch { expected: Iso4217, actual: Iso4217 },
    /// Input is not a valid decimal number or does not match the unit's form.
    MalformedDecimal,
    /// Non-zero fractional digits were discarded under [`Rounding::Exact`].
    Inexact,
    /// [`parse_decimal`] was called with a non-money [`Unit`] (`UnixSeconds`,
    /// `Rfc3339`, `GithubExpiry`, `Bool`, `Enum`).
    NotAMoneyUnit,
    /// A negative amount was given where only non-negative amounts are valid.
    NegativeNotAllowed,
}

/// Alias for [`UnitError`] used across spend modules.
pub type MoneyError = UnitError;

impl fmt::Display for UnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnitError::InvalidCurrency => f.write_str("invalid ISO 4217 currency code"),
            UnitError::InvalidScale(s) => write!(f, "money scale {s} exceeds maximum {MAX_SCALE}"),
            UnitError::OutOfBounds => f.write_str("money amount is out of bounds"),
            UnitError::CurrencyMismatch { expected, actual } => {
                write!(f, "currency mismatch: expected {expected}, got {actual}")
            }
            UnitError::MalformedDecimal => f.write_str("malformed decimal number"),
            UnitError::Inexact => {
                f.write_str("decimal has more fractional digits than target scale")
            }
            UnitError::NotAMoneyUnit => f.write_str("unit does not represent a money amount"),
            UnitError::NegativeNotAllowed => f.write_str("negative money amount is not allowed"),
        }
    }
}

impl std::error::Error for UnitError {}

/// An exact signed decimal parsed without floating point: `value = mantissa * 10^(-scale)`.
///
/// Supports up to 18 significant decimal digits and scale `0..=18`, so values
/// like JSON `0.1`, `1e2`, `-0` and `12.345678901` are represented without loss
/// before scaling or rounding into [`Money`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDecimal {
    pub mantissa: i128,
    pub scale: u8,
}

impl ParsedDecimal {
    /// Parses a decimal number token (`-12.34`, `0.1`, `1e2`, `-0`,
    /// `12.345678901`) without using floating point. Leading or trailing
    /// whitespace, NaN, Inf, leading `+` in strict JSON mode (allowed only in
    /// exponent), empty integer parts (`.5`) and empty fractional parts (`5.`)
    /// are rejected.
    pub fn parse(input: &str) -> Result<Self, UnitError> {
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Err(UnitError::MalformedDecimal);
        }
        let mut i = 0;
        let negative = if bytes[i] == b'-' {
            i += 1;
            true
        } else {
            false
        };
        if i >= bytes.len() {
            return Err(UnitError::MalformedDecimal);
        }

        // Integer part: must have at least one digit, and no leading zero
        // followed by another digit (JSON number grammar, RFC 8259 §6), except
        // for plain digit strings in CentsString / DecimalString which callers
        // may normalise or pass as standard decimals.
        let int_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let int_digits = &bytes[int_start..i];
        if int_digits.is_empty() {
            return Err(UnitError::MalformedDecimal);
        }

        // Optional fractional part.
        let mut frac_digits: &[u8] = &[];
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            let frac_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            frac_digits = &bytes[frac_start..i];
            if frac_digits.is_empty() {
                return Err(UnitError::MalformedDecimal);
            }
        }

        // Optional exponent part (`e` or `E`).
        let mut exp: i32 = 0;
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            if i >= bytes.len() {
                return Err(UnitError::MalformedDecimal);
            }
            let exp_neg = if bytes[i] == b'-' {
                i += 1;
                true
            } else if bytes[i] == b'+' {
                i += 1;
                false
            } else {
                false
            };
            let exp_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let exp_digits = &bytes[exp_start..i];
            if exp_digits.is_empty() || exp_digits.len() > 4 {
                return Err(UnitError::MalformedDecimal);
            }
            for &b in exp_digits {
                exp = exp * 10 + i32::from(b - b'0');
            }
            if exp_neg {
                exp = -exp;
            }
        }

        if i != bytes.len() {
            return Err(UnitError::MalformedDecimal);
        }

        // Trim leading zeros from integer digits and trailing zeros from
        // fractional digits only after recording effective scale.
        let mut mag: i128 = 0;
        let mut sig_digits: usize = 0;
        for &b in int_digits.iter().chain(frac_digits.iter()) {
            let d = i128::from(b - b'0');
            if mag == 0 && d == 0 {
                continue;
            }
            sig_digits += 1;
            if sig_digits > 24 {
                return Err(UnitError::OutOfBounds);
            }
            mag = mag
                .checked_mul(10)
                .and_then(|v| v.checked_add(d))
                .ok_or(UnitError::OutOfBounds)?;
        }

        if mag == 0 {
            // `-0`, `0.0`, `0e5` all normalise to exact zero at the fractional
            // scale (clamped to 18).
            let raw_scale = (i32::try_from(frac_digits.len()).unwrap_or(0) - exp).clamp(0, 18);
            return Ok(ParsedDecimal {
                mantissa: 0,
                scale: u8::try_from(raw_scale).unwrap_or(0),
            });
        }

        let frac_len = i32::try_from(frac_digits.len()).map_err(|_| UnitError::OutOfBounds)?;
        let net_scale = frac_len.checked_sub(exp).ok_or(UnitError::OutOfBounds)?;

        let (final_mag, final_scale) = if net_scale >= 0 {
            if net_scale > 18 {
                return Err(UnitError::OutOfBounds);
            }
            (mag, u8::try_from(net_scale).unwrap_or(0))
        } else {
            let shift = usize::try_from(-net_scale).map_err(|_| UnitError::OutOfBounds)?;
            if shift >= POW10_I128.len() {
                return Err(UnitError::OutOfBounds);
            }
            let m = mag
                .checked_mul(POW10_I128[shift])
                .ok_or(UnitError::OutOfBounds)?;
            (m, 0)
        };

        let signed = if negative { -final_mag } else { final_mag };
        Ok(ParsedDecimal {
            mantissa: signed,
            scale: final_scale,
        })
    }

    /// Converts this decimal into a [`Money`] in `currency`, choosing the scale
    /// in `currency.default_scale()..=MAX_SCALE` that preserves exact digits
    /// when possible, and applying `rounding` when more than [`MAX_SCALE`]
    /// fractional places are present.
    pub fn into_money(
        self,
        currency: Iso4217,
        min_scale: u8,
        max_scale: u8,
        rounding: Rounding,
    ) -> Result<Money, UnitError> {
        if min_scale > max_scale || max_scale > MAX_SCALE {
            return Err(UnitError::InvalidScale(max_scale));
        }
        // Strip redundant trailing zeros down to `min_scale` so `12.3400` in
        // USD becomes scale 2 while `12.345` becomes scale 3.
        let mut mantissa = self.mantissa;
        let mut scale = self.scale;
        while scale > min_scale && mantissa != 0 && mantissa % 10 == 0 {
            mantissa /= 10;
            scale -= 1;
        }
        if mantissa == 0 {
            scale = scale.clamp(min_scale, max_scale);
            return Money::new(0, scale, currency);
        }
        if scale < min_scale {
            let diff = usize::from(min_scale - scale);
            let factor = *POW10_I128.get(diff).ok_or(UnitError::OutOfBounds)?;
            mantissa = mantissa.checked_mul(factor).ok_or(UnitError::OutOfBounds)?;
            scale = min_scale;
        } else if scale > max_scale {
            let drop = usize::from(scale - max_scale);
            let divisor = *POW10_I128.get(drop).ok_or(UnitError::OutOfBounds)?;
            let quot = mantissa / divisor;
            let rem = mantissa % divisor;
            mantissa = round_quotient(quot, rem, divisor, rounding)?;
            scale = max_scale;
            while scale > min_scale && mantissa != 0 && mantissa % 10 == 0 {
                mantissa /= 10;
                scale -= 1;
            }
        }
        let minor = i64::try_from(mantissa).map_err(|_| UnitError::OutOfBounds)?;
        Money::new(minor, scale, currency)
    }
}

fn round_quotient(
    quot: i128,
    rem: i128,
    divisor: i128,
    rounding: Rounding,
) -> Result<i128, UnitError> {
    if rem == 0 {
        return Ok(quot);
    }
    match rounding {
        Rounding::Exact => Err(UnitError::Inexact),
        Rounding::TowardZero => Ok(quot),
        Rounding::Ceiling => {
            if rem > 0 {
                quot.checked_add(1).ok_or(UnitError::OutOfBounds)
            } else {
                Ok(quot)
            }
        }
        Rounding::Floor => {
            if rem < 0 {
                quot.checked_sub(1).ok_or(UnitError::OutOfBounds)
            } else {
                Ok(quot)
            }
        }
        Rounding::HalfAwayFromZero => {
            let half = divisor / 2;
            if rem.abs() >= half {
                if rem > 0 {
                    quot.checked_add(1).ok_or(UnitError::OutOfBounds)
                } else {
                    quot.checked_sub(1).ok_or(UnitError::OutOfBounds)
                }
            } else {
                Ok(quot)
            }
        }
    }
}

/// A signed monetary amount in one currency: `amount = minor * 10^(-scale)`
/// (`D4-08`).
#[derive(Clone, Copy, Eq)]
pub struct Money {
    pub minor: i64,
    pub scale: u8,
    pub currency: Iso4217,
}

impl Money {
    /// Creates a checked [`Money`] value. Normalises `-0` to `0`, checks
    /// `scale <= MAX_SCALE` (6), and bounds `minor` within
    /// [`MIN_MINOR`]..=[`MAX_MINOR`] (`±10^12`).
    pub fn new(minor: i64, scale: u8, currency: Iso4217) -> Result<Self, UnitError> {
        if scale > MAX_SCALE {
            return Err(UnitError::InvalidScale(scale));
        }
        if !(MIN_MINOR..=MAX_MINOR).contains(&minor) {
            return Err(UnitError::OutOfBounds);
        }
        Ok(Self {
            minor: if minor == 0 { 0 } else { minor },
            scale,
            currency,
        })
    }

    /// Zero in `currency` at `currency.default_scale()`.
    pub fn zero(currency: Iso4217) -> Self {
        Self {
            minor: 0,
            scale: currency.default_scale(),
            currency,
        }
    }

    /// Zero in `currency` at an explicit `scale`.
    pub const fn zero_at_scale(scale: u8, currency: Iso4217) -> Self {
        Self {
            minor: 0,
            scale,
            currency,
        }
    }

    pub const fn minor(&self) -> i64 {
        self.minor
    }

    pub const fn scale(&self) -> u8 {
        self.scale
    }

    pub const fn currency(&self) -> Iso4217 {
        self.currency
    }

    pub const fn within_poll_bounds(&self) -> bool {
        self.scale <= MAX_SCALE && self.minor >= MIN_MINOR && self.minor <= MAX_MINOR
    }

    /// Rescales this amount to `target_scale` (`0..=6`) using `rounding`.
    pub fn rescale(&self, target_scale: u8, rounding: Rounding) -> Result<Self, UnitError> {
        if target_scale > MAX_SCALE {
            return Err(UnitError::InvalidScale(target_scale));
        }
        match target_scale.cmp(&self.scale) {
            Ordering::Equal => Ok(*self),
            Ordering::Greater => {
                let diff = usize::from(target_scale - self.scale);
                let factor = POW10_I64[diff];
                let minor = self
                    .minor
                    .checked_mul(factor)
                    .ok_or(UnitError::OutOfBounds)?;
                Self::new(minor, target_scale, self.currency)
            }
            Ordering::Less => {
                let diff = usize::from(self.scale - target_scale);
                let divisor = i128::from(POW10_I64[diff]);
                let m = i128::from(self.minor);
                let rounded = round_quotient(m / divisor, m % divisor, divisor, rounding)?;
                let minor = i64::try_from(rounded).map_err(|_| UnitError::OutOfBounds)?;
                Self::new(minor, target_scale, self.currency)
            }
        }
    }

    fn align_pair(a: &Self, b: &Self) -> Result<(i64, i64, u8, Iso4217), UnitError> {
        if a.currency != b.currency {
            return Err(UnitError::CurrencyMismatch {
                expected: a.currency,
                actual: b.currency,
            });
        }
        let scale = a.scale.max(b.scale);
        let a_scaled = a.rescale(scale, Rounding::Exact)?;
        let b_scaled = b.rescale(scale, Rounding::Exact)?;
        Ok((a_scaled.minor, b_scaled.minor, scale, a.currency))
    }

    /// Checked addition of two amounts in the same currency. Returns
    /// [`UnitError::CurrencyMismatch`] when currencies differ and
    /// [`UnitError::OutOfBounds`] on overflow.
    pub fn checked_add(&self, other: &Self) -> Result<Self, UnitError> {
        let (a, b, scale, currency) = Self::align_pair(self, other)?;
        let sum = a.checked_add(b).ok_or(UnitError::OutOfBounds)?;
        Self::new(sum, scale, currency)
    }

    /// Checked subtraction of two amounts in the same currency.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, UnitError> {
        let (a, b, scale, currency) = Self::align_pair(self, other)?;
        let diff = a.checked_sub(b).ok_or(UnitError::OutOfBounds)?;
        Self::new(diff, scale, currency)
    }

    /// Compares two amounts of the same currency across potentially different
    /// scales. Returns [`UnitError::CurrencyMismatch`] if currencies differ.
    pub fn same_currency_cmp(&self, other: &Self) -> Result<Ordering, UnitError> {
        if self.currency != other.currency {
            return Err(UnitError::CurrencyMismatch {
                expected: self.currency,
                actual: other.currency,
            });
        }
        let scale = self.scale.max(other.scale);
        let a = i128::from(self.minor) * POW10_I128[usize::from(scale - self.scale)];
        let b = i128::from(other.minor) * POW10_I128[usize::from(scale - other.scale)];
        Ok(a.cmp(&b))
    }

    /// Formats the numeric part (`"12.34"`, `"-0.50"`, `"1000"`) without the
    /// currency code and without floating point.
    pub fn format_number(&self) -> String {
        let neg = self.minor < 0;
        let abs = self.minor.unsigned_abs();
        if self.scale == 0 {
            return if neg {
                format!("-{abs}")
            } else {
                format!("{abs}")
            };
        }
        let div = POW10_I64[usize::from(self.scale)].unsigned_abs();
        let whole = abs / div;
        let frac = abs % div;
        let width = usize::from(self.scale);
        if neg {
            format!("-{whole}.{frac:0width$}")
        } else {
            format!("{whole}.{frac:0width$}")
        }
    }
}

impl PartialEq for Money {
    fn eq(&self, other: &Self) -> bool {
        self.currency == other.currency && self.same_currency_cmp(other) == Ok(Ordering::Equal)
    }
}

impl core::hash::Hash for Money {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.currency.hash(state);
        // Canonicalise trailing zeros so equal values across scales hash
        // identically (`1200` scale 2 == `12` scale 0).
        let mut m = self.minor;
        let mut s = self.scale;
        while s > 0 && m != 0 && m % 10 == 0 {
            m /= 10;
            s -= 1;
        }
        if m == 0 {
            s = 0;
        }
        m.hash(state);
        s.hash(state);
    }
}

impl fmt::Debug for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.format_number(), self.currency)
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.format_number(), self.currency)
    }
}

/// Parses a borrowed JSON number token or string according to `unit` and
/// `rounding` (`D4-08`).
pub fn parse_decimal_with_rounding(
    input: &str,
    unit: &Unit,
    rounding: Rounding,
) -> Result<Money, UnitError> {
    match unit {
        Unit::Major(currency) | Unit::DecimalString(currency) => {
            let parsed = ParsedDecimal::parse(input)?;
            parsed.into_money(*currency, currency.default_scale(), MAX_SCALE, rounding)
        }
        Unit::Minor(currency) => {
            let parsed = ParsedDecimal::parse(input)?;
            if parsed.scale != 0 {
                return Err(UnitError::Inexact);
            }
            let minor = i64::try_from(parsed.mantissa).map_err(|_| UnitError::OutOfBounds)?;
            Money::new(minor, currency.default_scale(), *currency)
        }
        Unit::CentsString(currency) => {
            let parsed = ParsedDecimal::parse(input)?;
            // Input is in cents (`10^-2` major units), so its effective major
            // scale is `parsed.scale + 2`.
            let total_scale = parsed.scale.checked_add(2).ok_or(UnitError::OutOfBounds)?;
            let shifted = ParsedDecimal {
                mantissa: parsed.mantissa,
                scale: total_scale,
            };
            shifted.into_money(
                *currency,
                currency.default_scale().max(2),
                MAX_SCALE,
                rounding,
            )
        }
        Unit::UnixSeconds | Unit::Rfc3339 | Unit::GithubExpiry | Unit::Bool | Unit::Enum(_) => {
            Err(UnitError::NotAMoneyUnit)
        }
    }
}

/// Parses a borrowed JSON number token or string according to `unit`, rounding
/// half away from zero when more than [`MAX_SCALE`] (6) fractional places are
/// present (`D4-08`).
pub fn parse_decimal(input: &str, unit: Unit) -> Result<Money, UnitError> {
    parse_decimal_with_rounding(input, &unit, Rounding::HalfAwayFromZero)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cents_string_vs_decimal_string_and_round_trips() {
        let cents = parse_decimal("1234", Unit::CentsString(Iso4217::USD)).unwrap();
        assert_eq!(cents, Money::new(1234, 2, Iso4217::USD).unwrap());
        assert_eq!(cents.to_string(), "12.34 USD");

        let dec = parse_decimal("1234", Unit::DecimalString(Iso4217::USD)).unwrap();
        assert_eq!(dec, Money::new(123_400, 2, Iso4217::USD).unwrap());
        assert_eq!(dec.to_string(), "1234.00 USD");

        for s in [
            "0.00",
            "0.10",
            "12.34",
            "-99.95",
            "100.123456",
            "1000000.00",
        ] {
            let m = parse_decimal(s, Unit::DecimalString(Iso4217::USD)).unwrap();
            let reparsed =
                parse_decimal(&m.format_number(), Unit::DecimalString(Iso4217::USD)).unwrap();
            assert_eq!(m, reparsed, "round-trip failed for {s}");
        }
    }

    #[test]
    fn json_numbers_read_without_floats() {
        let p_tenth = ParsedDecimal::parse("0.1").unwrap();
        assert_eq!(
            p_tenth,
            ParsedDecimal {
                mantissa: 1,
                scale: 1
            }
        );
        let m_tenth = parse_decimal("0.1", Unit::Major(Iso4217::USD)).unwrap();
        assert_eq!(m_tenth.minor, 10);
        assert_eq!(m_tenth.scale, 2);

        let p_exp = ParsedDecimal::parse("1e2").unwrap();
        assert_eq!(
            p_exp,
            ParsedDecimal {
                mantissa: 100,
                scale: 0
            }
        );
        let m_exp = parse_decimal("1e2", Unit::Major(Iso4217::USD)).unwrap();
        assert_eq!(m_exp, Money::new(10_000, 2, Iso4217::USD).unwrap());

        let m_neg_zero = parse_decimal("-0", Unit::Major(Iso4217::USD)).unwrap();
        assert_eq!(m_neg_zero.minor, 0);
        assert_eq!(m_neg_zero.to_string(), "0.00 USD");

        let p_nine = ParsedDecimal::parse("12.345678901").unwrap();
        assert_eq!(
            p_nine,
            ParsedDecimal {
                mantissa: 12_345_678_901,
                scale: 9
            }
        );
        let m_nine = parse_decimal("12.345678901", Unit::Major(Iso4217::USD)).unwrap();
        assert_eq!(m_nine, Money::new(12_345_679, 6, Iso4217::USD).unwrap());
        assert_eq!(
            parse_decimal_with_rounding(
                "12.345678901",
                &Unit::Major(Iso4217::USD),
                Rounding::Exact
            ),
            Err(UnitError::Inexact)
        );
    }

    #[test]
    fn mixed_currency_arithmetic_and_comparison_fail() {
        let usd = Money::new(500, 2, Iso4217::USD).unwrap();
        let eur = Money::new(500, 2, Iso4217::EUR).unwrap();
        assert_eq!(
            usd.checked_add(&eur),
            Err(UnitError::CurrencyMismatch {
                expected: Iso4217::USD,
                actual: Iso4217::EUR,
            })
        );
        assert_eq!(
            usd.same_currency_cmp(&eur),
            Err(UnitError::CurrencyMismatch {
                expected: Iso4217::USD,
                actual: Iso4217::EUR,
            })
        );
    }

    #[test]
    fn bounds_and_rescaling_hold() {
        assert!(Money::new(MAX_MINOR + 1, 2, Iso4217::USD).is_err());
        assert!(Money::new(MIN_MINOR - 1, 2, Iso4217::USD).is_err());
        assert!(Money::new(0, 7, Iso4217::USD).is_err());

        let a = Money::new(125, 2, Iso4217::USD).unwrap();
        let b = Money::new(500, 4, Iso4217::USD).unwrap();
        let sum = a.checked_add(&b).unwrap();
        assert_eq!(sum, Money::new(13_000, 4, Iso4217::USD).unwrap());
    }
}
