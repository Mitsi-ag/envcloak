//! Registered sign-in target origin parser (SPEC §6.8, M2 plan D-26, task
//! M2b-05).
//!
//! [`parse_registered`] parses a registered target's origin into an
//! [`Origin`]: `https`, or `http` for `127.0.0.1`, `::1` and `*.localhost`;
//! a lower-case DNS name, IPv4 or bracketed IPv6 host; no userinfo, path,
//! query or fragment; an explicit port kept when not the scheme's default
//! (`80` for `http`, `443` for `https`).
//!
//! The stored and compared form is `Origin::to_string()`:
//! `<scheme>://<host>[:<port>]`, which matches Node's WHATWG
//! `new URL(u).origin` byte for byte on every accepted input.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::scope::{Host, HostName, Origin, Scheme, ScopeError};

/// The longest origin string accepted by [`parse_registered`], in bytes.
pub const MAX_ORIGIN: usize = 512;

/// Why [`parse_registered`] refused an input string. Fixed and value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OriginError {
    /// Not `https://` or `http://`, or `http://` for a host other than
    /// `127.0.0.1`, `::1` or `*.localhost`.
    Scheme,
    /// A host that is empty, not lowercase ASCII in the registered DNS,
    /// canonical IPv4 or bracketed IPv6 form, or over the length bound.
    Host,
    /// A port that is empty, has leading zeros or non-digits, is 0, or
    /// exceeds 65535.
    Port,
    /// The input carries userinfo (`@`), a path (`/`), a query (`?`), a
    /// fragment (`#`) or a backslash (`\`).
    NotBareOrigin,
}

impl OriginError {
    /// Stable reason string for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            OriginError::Scheme => "invalid_origin_scheme",
            OriginError::Host => "invalid_origin_host",
            OriginError::Port => "invalid_origin_port",
            OriginError::NotBareOrigin => "invalid_origin",
        }
    }
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OriginError::Scheme => "origin scheme must be https, or http for 127.0.0.1, [::1] or *.localhost",
            OriginError::Host => "origin host must be a lowercase DNS name, IPv4 address or bracketed IPv6 address",
            OriginError::Port => "origin port must be 1..=65535 without leading zeros",
            OriginError::NotBareOrigin => "origin must be <scheme>://<host>[:<port>] with no userinfo, path, query or fragment",
        })
    }
}

impl std::error::Error for OriginError {}

impl From<ScopeError> for OriginError {
    fn from(e: ScopeError) -> Self {
        match e {
            ScopeError::Scheme => OriginError::Scheme,
            ScopeError::Port => OriginError::Port,
            _ => OriginError::Host,
        }
    }
}

/// Parses a registered target's origin (plan D-26):
/// - scheme `https`, or `http` for `127.0.0.1`, `[::1]` and `*.localhost`;
/// - a lower-case DNS name, canonical IPv4 address or bracketed IPv6 host;
/// - no userinfo, path, query or fragment;
/// - an optional `:port` (`1..=65535`, no leading zeros); omitted port uses
///   the scheme's default (`80` for `http`, `443` for `https`).
pub fn parse_registered(input: &str) -> Result<Origin, OriginError> {
    if input.is_empty() || input.len() > MAX_ORIGIN || !input.is_ascii() {
        return Err(OriginError::Host);
    }
    if input.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(OriginError::Host);
    }
    let (scheme, rest) = if let Some(r) = input.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = input.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err(OriginError::Scheme);
    };
    if rest
        .bytes()
        .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\'))
    {
        return Err(OriginError::NotBareOrigin);
    }
    if rest.is_empty() {
        return Err(OriginError::Host);
    }
    let (host, port_str) = if let Some(after_open) = rest.strip_prefix('[') {
        let Some((v6_str, tail)) = after_open.split_once(']') else {
            return Err(OriginError::Host);
        };
        let host = parse_ipv6_host(v6_str)?;
        let port_str = if tail.is_empty() {
            None
        } else if let Some(p) = tail.strip_prefix(':') {
            Some(p)
        } else {
            return Err(OriginError::Host);
        };
        (host, port_str)
    } else {
        if rest.contains('[') || rest.contains(']') {
            return Err(OriginError::Host);
        }
        let (host_str, port_str) = match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let host = parse_v4_or_name(host_str)?;
        (host, port_str)
    };
    let port = match port_str {
        Some(p) => parse_port(p)?,
        None => scheme.default_port(),
    };
    Origin::new(scheme, host, port).map_err(OriginError::from)
}

fn parse_port(s: &str) -> Result<u16, OriginError> {
    if s.is_empty()
        || s.len() > 5
        || s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(OriginError::Port);
    }
    let port = s.parse::<u16>().map_err(|_| OriginError::Port)?;
    if port == 0 {
        return Err(OriginError::Port);
    }
    Ok(port)
}

fn parse_ipv6_host(s: &str) -> Result<Host, OriginError> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b':')
    {
        return Err(OriginError::Host);
    }
    let addr = Ipv6Addr::from_str(s).map_err(|_| OriginError::Host)?;
    Ok(Host::V6(addr.octets()))
}

fn parse_v4_or_name(s: &str) -> Result<Host, OriginError> {
    if s.is_empty() {
        return Err(OriginError::Host);
    }
    if let Ok(v4) = Ipv4Addr::from_str(s) {
        return Ok(Host::V4(v4.octets()));
    }
    HostName::new(s)
        .map(Host::Name)
        .map_err(|_| OriginError::Host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn canonical_forms_and_rejections() {
        let cases = [
            ("https://app.example.com", "https://app.example.com"),
            ("https://app.example.com:443", "https://app.example.com"),
            ("https://app.example.com:8443", "https://app.example.com:8443"),
            ("http://127.0.0.1", "http://127.0.0.1"),
            ("http://127.0.0.1:80", "http://127.0.0.1"),
            ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
            ("http://[::1]:5173", "http://[::1]:5173"),
            ("http://[::1]:80", "http://[::1]"),
            ("http://app.localhost:3000", "http://app.localhost:3000"),
            ("http://sub.app.localhost", "http://sub.app.localhost"),
            ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
            ("https://[2001:0db8:0:0:0:0:0:1]", "https://[2001:db8::1]"),
            ("https://xn--bcher-kva.example", "https://xn--bcher-kva.example"),
        ];
        for (input, expected) in cases {
            let parsed = parse_registered(input).expect(input);
            assert_eq!(parsed.to_string(), expected, "input: {input}");
            let reparsed = parse_registered(&parsed.to_string()).expect(expected);
            assert_eq!(parsed, reparsed, "idempotent: {input}");
        }

        let rejected = [
            "",
            "app.example.com",
            "ftp://app.example.com",
            "ws://127.0.0.1:3000",
            "HTTPS://app.example.com",
            "http://app.example.com",
            "http://localhost:3000",
            "http://127.0.0.2:3000",
            "http://[::2]:3000",
            "https://App.example.com",
            "https://app.example.com/",
            "https://app.example.com/login",
            "https://app.example.com?x=1",
            "https://app.example.com#frag",
            "https://user@app.example.com",
            "https://user:pass@app.example.com",
            "https://app.example.com:0",
            "https://app.example.com:0443",
            "https://app.example.com:65536",
            "https://app.example.com:",
            "https://app.example.com:abc",
            "https://app.example.com.",
            "https://.app.example.com",
            "https://-app.example.com",
            "https://app-.example.com",
            "https://127.1",
            "https://127.0.0.01",
            "https://0x7f.0.0.1",
            "https://2130706433",
            "https://[::ffff:127.0.0.1]",
            "https://[2001:DB8::1]",
            "https://[::1%lo0]",
            "https://[::1]extra",
            "https://app.example.com\\path",
            "https://app.example.com:443:443",
            " https://app.example.com",
            "https://app.example.com ",
        ];
        for bad in rejected {
            assert!(
                parse_registered(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn matches_node_whatwg_url_origin_on_corpus() {
        let node = Command::new("node").arg("--version").output();
        let Ok(out) = node else {
            return;
        };
        if !out.status.success() {
            return;
        }
        let corpus = [
            "https://app.example.com",
            "https://app.example.com:443",
            "https://app.example.com:8443",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:3000",
            "http://[::1]",
            "http://[::1]:80",
            "http://[::1]:5173",
            "http://app.localhost",
            "http://app.localhost:80",
            "http://app.localhost:3000",
            "http://a.b.localhost:8080",
            "https://192.0.2.10:9443",
            "https://[2001:db8::1]",
            "https://[2001:db8::1]:443",
            "https://[2001:db8::1]:8443",
            "https://[2001:0db8:0000:0000:0001:0000:0000:0001]:9000",
            "https://xn--bcher-kva.example:444",
            "http://localhost:3000",
            "https://App.Example.com",
            "https://app.example.com/path",
            "https://user@app.example.com",
            "https://127.1:8443",
            "https://0x7f000001",
        ];
        let script = r#"
            const inputs = JSON.parse(process.argv[1]);
            const out = inputs.map((u) => {
                try {
                    return new URL(u).origin;
                } catch (_) {
                    return null;
                }
            });
            process.stdout.write(JSON.stringify(out));
        "#;
        let json_in = serde_json::to_string(&corpus).unwrap();
        let res = Command::new("node")
            .arg("-e")
            .arg(script)
            .arg(&json_in)
            .output()
            .unwrap();
        assert!(res.status.success());
        let node_origins: Vec<Option<String>> = serde_json::from_slice(&res.stdout).unwrap();
        for (input, node_origin) in corpus.iter().zip(node_origins.iter()) {
            if let Ok(origin) = parse_registered(input) {
                assert_eq!(
                    Some(origin.to_string()),
                    *node_origin,
                    "accepted origin {input} must equal Node URL.origin"
                );
            }
        }
    }
}
