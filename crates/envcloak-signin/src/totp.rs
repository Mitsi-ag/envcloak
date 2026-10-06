//! RFC 6238 calculation and injected-clock arithmetic. Authorization,
//! account serialization and submitted-step tracking belong to the daemon.
use std::fmt;
use std::num::NonZeroU64;

use envcloak_core::SecretBytes;

/// Enrollment policy: at least one eligible second, at most five minutes
/// to the next step. Arithmetic helpers can still model any positive period.
pub const MIN_PERIOD_SECONDS: u64 = 4;
pub const MAX_PERIOD_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Positive seconds per step. Construction rejects zero before arithmetic.
pub struct Period(NonZeroU64);

impl Period {
    pub fn new(seconds: u64) -> Result<Self, ParamsError> {
        NonZeroU64::new(seconds).map(Self).ok_or(ParamsError)
    }
    pub fn seconds(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for Period {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Period(..)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    algorithm: Algorithm,
    digits: u8,
    period: Period,
}

impl TotpParams {
    pub fn new(algorithm: Algorithm, digits: u8, period: u64) -> Result<Self, ParamsError> {
        if !matches!(digits, 6 | 8) || !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&period)
        {
            return Err(ParamsError);
        }
        Ok(Self {
            algorithm,
            digits,
            period: Period::new(period)?,
        })
    }
    pub fn algorithm(self) -> Algorithm {
        self.algorithm
    }
    pub fn digits(self) -> u8 {
        self.digits
    }
    pub fn period(self) -> Period {
        self.period
    }
}

impl fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpParams(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamsError;

impl fmt::Display for ParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid_totp_parameters")
    }
}
impl std::error::Error for ParamsError {}

/// A fixed-width code held in wiping storage. It is neither clonable nor
/// serializable; Debug and Display never reveal its digits.
pub struct Code(SecretBytes);

impl Code {
    pub fn as_secret(&self) -> &SecretBytes {
        &self.0
    }
}
impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(..)")
    }
}
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(..)")
    }
}

/// RFC 6238's moving factor, with epoch zero. A validated period makes
/// division total for every u64 timestamp.
pub fn step_at(unix_secs: u64, period: Period) -> u64 {
    unix_secs / period.seconds()
}

/// At the start of a step the full period remains. Subtracting a remainder
/// avoids overflowing a calculation of the next boundary at u64::MAX.
pub fn seconds_left(unix_secs: u64, period: Period) -> u64 {
    period.seconds() - unix_secs % period.seconds()
}

pub fn too_late_in_step(unix_secs: u64, period: Period) -> bool {
    seconds_left(unix_secs, period) <= 3
}

/// Keep this pair from the daemon's start, never recompute it at a request.
/// At epoch step zero there is no predecessor, so both entries are zero.
pub fn refused_after_start(start_unix: u64, period: Period) -> [u64; 2] {
    let step = step_at(start_unix, period);
    [step, step.saturating_sub(1)]
}

/// Pure calculation, not permission to generate or submit a code. The
/// daemon must first validate its attempt, clock, audit and account state.
#[allow(clippy::disallowed_methods)] // Seed stays in HMAC; result stays in SecretBytes.
#[allow(clippy::disallowed_types)] // SHA-1 is confined to RFC 6238 here.
pub fn code(seed: &SecretBytes, params: TotpParams, step: u64) -> Code {
    use secrecy::ExposeSecret;
    let seed = seed.expose_secret();
    match params.algorithm {
        Algorithm::Sha1 => calculate::<sha1::Sha1>(seed, params.digits, step),
        Algorithm::Sha256 => calculate::<sha2::Sha256>(seed, params.digits, step),
        Algorithm::Sha512 => calculate::<sha2::Sha512>(seed, params.digits, step),
    }
}

fn calculate<D: hmac::EagerHash>(seed: &[u8], digits: u8, step: u64) -> Code {
    use hmac::{KeyInit, Mac};
    use zeroize::{Zeroize, Zeroizing};
    // HMAC accepts every key length; this is not input validation.
    let mut mac = hmac::Hmac::<D>::new_from_slice(seed).expect("HMAC accepts every key length");
    mac.update(&step.to_be_bytes());
    let mut digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 15);
    let mut binary = Zeroizing::new(
        u32::from_be_bytes([
            digest[offset],
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) & 0x7fff_ffff,
    );
    digest.as_mut_slice().zeroize();
    *binary %= 10u32.pow(u32::from(digits));
    // No format!/String containing a code, nor a growing plaintext buffer.
    let mut out = Zeroizing::new([b'0'; 8]);
    for byte in out[..usize::from(digits)].iter_mut().rev() {
        *byte = b'0' + (*binary % 10) as u8;
        *binary /= 10;
    }
    Code(SecretBytes::copy_from(&out[..usize::from(digits)]))
}
