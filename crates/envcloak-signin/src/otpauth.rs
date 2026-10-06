//! Bounded enrollment parser. Labels never select an account or origin.
use crate::totp::TotpParams;
use envcloak_core::SecretBytes;
use std::fmt;

pub const MAX_URI_BYTES: usize = 4000;
pub const MAX_SEED_BYTES: usize = 512;
pub const MAX_LABEL_BYTES: usize = 256;

pub struct TotpSpec {
    seed: SecretBytes,
    params: TotpParams,
    label: SecretBytes,
    issuer: Option<SecretBytes>,
}

impl TotpSpec {
    pub fn seed(&self) -> &SecretBytes {
        &self.seed
    }
    pub fn params(&self) -> TotpParams {
        self.params
    }
    pub fn label(&self) -> &SecretBytes {
        &self.label
    }
    pub fn issuer(&self) -> Option<&SecretBytes> {
        self.issuer.as_ref()
    }
}
impl fmt::Debug for TotpSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSpec(..)")
    }
}
impl fmt::Display for TotpSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSpec(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtpauthError;
impl fmt::Display for OtpauthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid_otpauth")
    }
}
impl std::error::Error for OtpauthError {}

#[allow(clippy::disallowed_methods)] // Parse a borrowed URI; every decoded buffer wipes on all exits.
pub fn parse(input: &SecretBytes) -> Result<TotpSpec, OtpauthError> {
    use secrecy::ExposeSecret;
    parse_bytes(input.expose_secret())
}

fn parse_bytes(raw: &[u8]) -> Result<TotpSpec, OtpauthError> {
    use crate::totp::Algorithm;
    if raw.len() > MAX_URI_BYTES
        || raw.iter().any(|b| {
            !b.is_ascii() || b.is_ascii_control() || matches!(b, b' ' | b'\\' | b'#' | b'+')
        })
    {
        return Err(OtpauthError);
    }
    let tail = raw.strip_prefix(b"otpauth://totp/").ok_or(OtpauthError)?;
    let split = tail.iter().position(|b| *b == b'?').ok_or(OtpauthError)?;
    let label = decode(&tail[..split])?;
    display_text(&label)?;
    if label.contains(&b'/') || label.iter().filter(|b| **b == b':').count() > 1 {
        return Err(OtpauthError);
    }
    if let Some(colon) = label.iter().position(|b| *b == b':') {
        display_text(&label[..colon])?;
        display_text(&label[colon + 1..])?;
    }
    let mut seed = None;
    let mut issuer = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6;
    let mut period = 30;
    let mut seen = 0u8;
    for pair in tail[split + 1..].split(|b| *b == b'&') {
        let equal = pair.iter().position(|b| *b == b'=').ok_or(OtpauthError)?;
        let name = &pair[..equal];
        let flag = match name {
            b"secret" => 1,
            b"algorithm" => 2,
            b"digits" => 4,
            b"period" => 8,
            b"issuer" => 16,
            _ => return Err(OtpauthError),
        };
        if seen & flag != 0 {
            return Err(OtpauthError);
        }
        seen |= flag;
        let value = decode(&pair[equal + 1..])?;
        match name {
            b"secret" => seed = Some(base32(&value)?),
            b"algorithm" => {
                algorithm = match value.as_slice() {
                    b"SHA1" => Algorithm::Sha1,
                    b"SHA256" => Algorithm::Sha256,
                    b"SHA512" => Algorithm::Sha512,
                    _ => return Err(OtpauthError),
                }
            }
            b"digits" => {
                digits = match value.as_slice() {
                    b"6" => 6,
                    b"8" => 8,
                    _ => return Err(OtpauthError),
                }
            }
            b"period" => {
                if value.is_empty() || value[0] == b'0' {
                    return Err(OtpauthError);
                }
                period = 0u64;
                for byte in value.iter() {
                    if !byte.is_ascii_digit() {
                        return Err(OtpauthError);
                    }
                    period = period
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                        .ok_or(OtpauthError)?;
                }
            }
            b"issuer" => {
                display_text(&value)?;
                issuer = Some(SecretBytes::copy_from(&value));
            }
            _ => unreachable!("parameter name was checked"),
        }
    }
    Ok(TotpSpec {
        seed: seed.ok_or(OtpauthError)?,
        params: TotpParams::new(algorithm, digits, period).map_err(|_| OtpauthError)?,
        label: SecretBytes::copy_from(&label),
        issuer,
    })
}

/// Decode once into a fixed-capacity wiping buffer. Delimiters must be
/// escaped so they cannot acquire a second structural interpretation.
fn decode(raw: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, OtpauthError> {
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let pair = raw.get(i + 1..i + 3).ok_or(OtpauthError)?;
            let high = hex(pair[0]).ok_or(OtpauthError)?;
            let low = hex(pair[1]).ok_or(OtpauthError)?;
            out.push(high * 16 + low);
            i += 3;
        } else {
            if !matches!(raw[i], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@')
            {
                return Err(OtpauthError);
            }
            out.push(raw[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn display_text(raw: &[u8]) -> Result<(), OtpauthError> {
    if raw.is_empty() || raw.len() > MAX_LABEL_BYTES {
        return Err(OtpauthError);
    }
    let text = std::str::from_utf8(raw).map_err(|_| OtpauthError)?;
    if text.trim().is_empty() || text.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        return Err(OtpauthError);
    }
    Ok(())
}

fn base32(raw: &[u8]) -> Result<SecretBytes, OtpauthError> {
    // RFC 4648: valid unpadded lengths and canonical zero tail bits.
    if raw.is_empty()
        || !matches!(raw.len() % 8, 0 | 2 | 4 | 5 | 7)
        || raw.len() * 5 / 8 > MAX_SEED_BYTES
    {
        return Err(OtpauthError);
    }
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(raw.len() * 5 / 8));
    let mut bits = 0;
    let mut buffer = zeroize::Zeroizing::new(0u16);
    for byte in raw {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(OtpauthError),
        };
        *buffer = (*buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((*buffer >> bits) as u8);
            *buffer &= (1 << bits) - 1;
        }
    }
    if *buffer != 0 {
        return Err(OtpauthError);
    }
    Ok(SecretBytes::copy_from(&out))
}
