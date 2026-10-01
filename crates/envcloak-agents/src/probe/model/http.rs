//! HTTP/1.1 request heads as the scripted model reads them: the grammar
//! of RFC 9112 for the parts a host sends, refused whole at the first
//! thing outside it, with fixed caps and fixed, non-echoing errors.
//!
//! Only what the stub needs is accepted: an origin-form target, version
//! `HTTP/1.1`, a `Host` header, a body framed by `Content-Length` alone.
//! `Transfer-Encoding`, `Expect`, a `Content-Encoding` other than
//! `identity`, obsolete line folding, a bare CR or LF, a byte outside
//! visible ASCII in a header, and a framing or credential header given
//! twice are refused, so a host whose requests drift from what the stub
//! was qualified against fails loudly instead of being half understood.

use std::fmt;

use zeroize::Zeroizing;

/// The most bytes a request head (request line and headers) may take.
pub const MAX_HEAD: usize = 64 * 1024;
/// The most header lines a head may hold.
pub const MAX_HEADERS: usize = 100;
/// The longest request target.
pub const MAX_TARGET: usize = 8 * 1024;

/// Why a head was refused. Fixed text only: nothing a request held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// Outside the grammar; the text names the rule, never the input.
    Malformed(&'static str),
    /// Longer than [`MAX_HEAD`] or more than [`MAX_HEADERS`] headers.
    HeadTooLarge,
    /// A `Content-Length` above the body cap.
    BodyTooLarge,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Malformed(rule) => write!(f, "malformed request ({rule})"),
            HttpError::HeadTooLarge => f.write_str("request head too large"),
            HttpError::BodyTooLarge => f.write_str("request body too large"),
        }
    }
}

/// A parsed request head. The credential headers are kept only to be
/// compared with the run's token; `Debug` shows neither.
pub struct Head {
    /// The method, upper-case letters only.
    pub method: String,
    /// The target's path, before any `?`.
    pub path: String,
    /// The target's query, after the first `?`.
    pub query: Option<String>,
    /// The body's length (0 without a `Content-Length`).
    pub content_length: usize,
    /// The client asked to close the connection after this request.
    pub close: bool,
    /// Every header name, lower-cased, in the order given.
    pub header_names: Vec<String>,
    pub(crate) api_key: Option<Zeroizing<Vec<u8>>>,
    pub(crate) authorization: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Head")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("content_length", &self.content_length)
            .field("close", &self.close)
            .field("header_names", &self.header_names)
            .finish_non_exhaustive()
    }
}

/// Where the head ends in `buf`: the index just past its `\r\n\r\n`.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// RFC 9110 `tchar`.
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parses `head`, which ends with `\r\n\r\n` ([`head_end`]). A
/// `Content-Length` above `body_cap` is [`HttpError::BodyTooLarge`].
///
/// # Errors
/// [`HttpError`] for anything outside the accepted grammar.
pub fn parse_head(head: &[u8], body_cap: usize) -> Result<Head, HttpError> {
    if head.len() > MAX_HEAD {
        return Err(HttpError::HeadTooLarge);
    }
    let Some(text) = head.strip_suffix(b"\r\n\r\n") else {
        return Err(HttpError::Malformed("head not terminated"));
    };
    let mut lines = split_crlf(text)?;
    let Some(request_line) = lines.next() else {
        return Err(HttpError::Malformed("request line"));
    };
    let (method, path, query) = request_line_parts(request_line)?;
    let mut head = Head {
        method,
        path,
        query,
        content_length: 0,
        close: false,
        header_names: Vec::new(),
        api_key: None,
        authorization: None,
    };
    let mut content_length = None;
    let mut host = false;
    for line in lines {
        if head.header_names.len() == MAX_HEADERS {
            return Err(HttpError::HeadTooLarge);
        }
        header(line, &mut head, &mut content_length, &mut host)?;
    }
    if !host {
        return Err(HttpError::Malformed("host header"));
    }
    let length = content_length.unwrap_or(0);
    if length > body_cap {
        return Err(HttpError::BodyTooLarge);
    }
    head.content_length = length;
    Ok(head)
}

/// The lines of `text`, split at `\r\n`; a lone `\r` or `\n` is refused.
fn split_crlf(text: &[u8]) -> Result<impl Iterator<Item = &[u8]>, HttpError> {
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'\r' if text.get(i + 1) == Some(&b'\n') => i += 2,
            b'\r' | b'\n' => return Err(HttpError::Malformed("line ending")),
            _ => i += 1,
        }
    }
    let mut rest = Some(text);
    Ok(std::iter::from_fn(move || {
        let r = rest?;
        match r.windows(2).position(|w| w == b"\r\n") {
            Some(at) => {
                rest = Some(&r[at + 2..]);
                Some(&r[..at])
            }
            None => {
                rest = None;
                Some(r)
            }
        }
    }))
}

fn request_line_parts(line: &[u8]) -> Result<(String, String, Option<String>), HttpError> {
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::Malformed("request line"));
    };
    if method.is_empty() || method.len() > 16 || !method.iter().all(u8::is_ascii_uppercase) {
        return Err(HttpError::Malformed("method"));
    }
    if version != b"HTTP/1.1" {
        return Err(HttpError::Malformed("version"));
    }
    if target.first() != Some(&b'/')
        || target.len() > MAX_TARGET
        || !target.iter().all(|&b| (0x21..=0x7e).contains(&b))
    {
        return Err(HttpError::Malformed("target"));
    }
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let (path, query) = match target.iter().position(|&b| b == b'?') {
        Some(at) => (text(&target[..at]), Some(text(&target[at + 1..]))),
        None => (text(target), None),
    };
    if path.contains('#') || query.as_deref().is_some_and(|q| q.contains('#')) {
        return Err(HttpError::Malformed("target"));
    }
    Ok((text(method), path, query))
}

fn header(
    line: &[u8],
    head: &mut Head,
    content_length: &mut Option<usize>,
    host: &mut bool,
) -> Result<(), HttpError> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(HttpError::Malformed("folded header"));
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Err(HttpError::Malformed("header line"));
    };
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || name.len() > 64 || !name.iter().all(|&b| tchar(b)) {
        return Err(HttpError::Malformed("header name"));
    }
    if !value
        .iter()
        .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        return Err(HttpError::Malformed("header value"));
    }
    let value = trim_ows(value);
    let name = name.to_ascii_lowercase();
    match name.as_slice() {
        b"content-length" => {
            if content_length.is_some() {
                return Err(HttpError::Malformed("content-length twice"));
            }
            if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
                return Err(HttpError::Malformed("content-length"));
            }
            let mut n: usize = 0;
            for &d in value {
                n = n
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(usize::from(d - b'0')))
                    .ok_or(HttpError::BodyTooLarge)?;
            }
            *content_length = Some(n);
        }
        b"transfer-encoding" => return Err(HttpError::Malformed("transfer-encoding")),
        b"expect" => return Err(HttpError::Malformed("expect")),
        b"content-encoding" if !value.eq_ignore_ascii_case(b"identity") => {
            return Err(HttpError::Malformed("content-encoding"));
        }
        b"host" => {
            if *host {
                return Err(HttpError::Malformed("host twice"));
            }
            *host = true;
        }
        b"connection" => {
            if value
                .split(|&b| b == b',')
                .any(|t| trim_ows(t).eq_ignore_ascii_case(b"close"))
            {
                head.close = true;
            }
        }
        b"x-api-key" => {
            if head.api_key.is_some() {
                return Err(HttpError::Malformed("x-api-key twice"));
            }
            head.api_key = Some(Zeroizing::new(value.to_vec()));
        }
        b"authorization" => {
            if head.authorization.is_some() {
                return Err(HttpError::Malformed("authorization twice"));
            }
            head.authorization = Some(Zeroizing::new(value.to_vec()));
        }
        _ => {}
    }
    head.header_names
        .push(String::from_utf8_lossy(&name).into_owned());
    Ok(())
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Head, HttpError> {
        parse_head(s.as_bytes(), 100)
    }

    #[test]
    fn a_plain_post_parses() {
        let h = parse(
            "POST /v1/messages?beta=true HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 12\r\n\
             X-Api-Key:  abc \r\nConnection: keep-alive, Close\r\n\r\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(h.method, "POST");
        assert_eq!(h.path, "/v1/messages");
        assert_eq!(h.query.as_deref(), Some("beta=true"));
        assert_eq!(h.content_length, 12);
        assert!(h.close);
        assert_eq!(
            h.header_names,
            ["host", "content-length", "x-api-key", "connection"]
        );
        assert_eq!(h.api_key.as_deref().map(Vec::as_slice), Some(&b"abc"[..]));
        let shown = format!("{h:?}");
        assert!(!shown.contains("abc"), "{shown}");
    }

    #[test]
    fn everything_outside_the_grammar_is_refused_with_a_fixed_error() {
        let cases: &[(&str, HttpError)] = &[
            (
                "GET / HTTP/1.1\r\n\r\n",
                HttpError::Malformed("host header"),
            ),
            (
                "GET / HTTP/1.0\r\nHost: x\r\n\r\n",
                HttpError::Malformed("version"),
            ),
            (
                "get / HTTP/1.1\r\nHost: x\r\n\r\n",
                HttpError::Malformed("method"),
            ),
            (
                "GET  / HTTP/1.1\r\nHost: x\r\n\r\n",
                HttpError::Malformed("request line"),
            ),
            (
                "GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n",
                HttpError::Malformed("target"),
            ),
            (
                "CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n",
                HttpError::Malformed("target"),
            ),
            (
                "GET /a#b HTTP/1.1\r\nHost: x\r\n\r\n",
                HttpError::Malformed("target"),
            ),
            (
                "GET / HTTP/1.1\nHost: x\r\n\r\n",
                HttpError::Malformed("line ending"),
            ),
            (
                "GET / HTTP/1.1\r\nHost: x\r\n x\r\n\r\n",
                HttpError::Malformed("folded header"),
            ),
            (
                "GET / HTTP/1.1\r\nHost x\r\n\r\n",
                HttpError::Malformed("header line"),
            ),
            (
                "GET / HTTP/1.1\r\nHo st: x\r\n\r\n",
                HttpError::Malformed("header name"),
            ),
            (
                "GET / HTTP/1.1\r\nHost: \u{e9}\r\n\r\n",
                HttpError::Malformed("header value"),
            ),
            (
                "GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
                HttpError::Malformed("host twice"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpError::Malformed("transfer-encoding"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                HttpError::Malformed("content-length twice"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\n",
                HttpError::Malformed("content-length"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 101\r\n\r\n",
                HttpError::BodyTooLarge,
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n",
                HttpError::Malformed("content-length"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\n\r\n",
                HttpError::Malformed("content-encoding"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n",
                HttpError::Malformed("expect"),
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: a\r\nAuthorization: b\r\n\r\n",
                HttpError::Malformed("authorization twice"),
            ),
            (
                "GET / HTTP/1.1\r\nHost: x\r\n",
                HttpError::Malformed("head not terminated"),
            ),
        ];
        for (input, want) in cases {
            match parse(input) {
                Ok(_) => panic!("accepted {input:?}"),
                Err(e) => assert_eq!(e, *want, "{input:?}"),
            }
        }
    }

    #[test]
    fn caps_on_the_head() {
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: 1\r\n")).collect();
        let input = format!("GET / HTTP/1.1\r\nHost: x\r\n{many}\r\n");
        assert_eq!(parse(&input).err(), Some(HttpError::HeadTooLarge));
        let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(parse(&long).err(), Some(HttpError::HeadTooLarge));
    }

    #[test]
    fn head_end_finds_the_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"), Some(27));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
    }
}
