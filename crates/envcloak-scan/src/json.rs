//! Bounded JSON syntax and string spans. Secret strings are never ordinary
//! Strings, including keys and strings discarded on a malformed document.
use envcloak_core::{SecretBuf, SecretBytes};
use std::ops::Range;

#[derive(Debug)]
pub(crate) struct Text {
    pub value: SecretBytes,
    pub range: Range<usize>,
    /// Each decoded byte's start in the raw document, and the final end.
    pub offsets: Vec<usize>,
}
#[derive(Debug)]
pub(crate) enum Node {
    Text(Text),
    Object(Vec<(Text, Node)>),
    Array(Vec<Node>),
    Scalar,
}
impl Node {
    pub fn object(&self) -> Option<&[(Text, Node)]> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn text(&self) -> Option<&Text> {
        if let Self::Text(v) = self {
            Some(v)
        } else {
            None
        }
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Node, ()> {
    std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut p = Parser {
        bytes,
        pos: 0,
        nodes: 0,
    };
    let node = p.value(0)?;
    p.space();
    if p.pos != bytes.len() {
        return Err(());
    }
    Ok(node)
}
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
}
impl Parser<'_> {
    fn space(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\t' | b'\r'))
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, b: u8) -> bool {
        self.space();
        if self.bytes.get(self.pos) == Some(&b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Node, ()> {
        self.nodes += 1;
        if depth > 64 || self.nodes > 100_000 {
            return Err(());
        }
        self.space();
        match self.bytes.get(self.pos).ok_or(())? {
            b'"' => Ok(Node::Text(self.text()?)),
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                let mut names = std::collections::HashSet::new();
                if self.take(b'}') {
                    return Ok(Node::Object(fields));
                }
                loop {
                    self.space();
                    let key = self.text()?;
                    #[allow(clippy::disallowed_methods)]
                    let digest = blake3::hash(secrecy::ExposeSecret::expose_secret(&key.value));
                    if !names.insert(*digest.as_bytes()) {
                        return Err(());
                    }
                    if !self.take(b':') {
                        return Err(());
                    }
                    let value = self.value(depth + 1)?;
                    fields.push((key, value));
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(());
                    }
                }
                Ok(Node::Object(fields))
            }
            b'[' => {
                self.pos += 1;
                let mut values = Vec::new();
                if self.take(b']') {
                    return Ok(Node::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(());
                    }
                }
                Ok(Node::Array(values))
            }
            _ => {
                let start = self.pos;
                while self.bytes.get(self.pos).is_some_and(|b| {
                    !matches!(b, b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t')
                }) {
                    self.pos += 1;
                }
                let token = &self.bytes[start..self.pos];
                if matches!(token, b"true" | b"false" | b"null") || number(token) {
                    Ok(Node::Scalar)
                } else {
                    Err(())
                }
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, ()> {
        let mut v = 0;
        for _ in 0..4 {
            let b = *self.bytes.get(self.pos).ok_or(())?;
            self.pos += 1;
            v = v * 16 + hex(b).ok_or(())? as u32;
        }
        Ok(v)
    }
    fn text(&mut self) -> Result<Text, ()> {
        if !self.take(b'"') {
            return Err(());
        }
        let start = self.pos;
        let mut out = SecretBuf::with_capacity(128.min(self.bytes.len() - start));
        let mut offsets = Vec::new();
        loop {
            let raw = self.pos;
            let b = *self.bytes.get(self.pos).ok_or(())?;
            self.pos += 1;
            if b == b'"' {
                offsets.push(raw);
                return Ok(Text {
                    value: out.freeze(),
                    range: start..raw,
                    offsets,
                });
            }
            if b < 32 {
                return Err(());
            }
            let mut buf = [0u8; 4];
            let decoded: &[u8] = if b == b'\\' {
                let escape = *self.bytes.get(self.pos).ok_or(())?;
                self.pos += 1;
                match escape {
                    b'"' | b'\\' | b'/' => {
                        buf[0] = escape;
                        &buf[..1]
                    }
                    b'b' => {
                        buf[0] = 8;
                        &buf[..1]
                    }
                    b'f' => {
                        buf[0] = 12;
                        &buf[..1]
                    }
                    b'n' => {
                        buf[0] = 10;
                        &buf[..1]
                    }
                    b'r' => {
                        buf[0] = 13;
                        &buf[..1]
                    }
                    b't' => {
                        buf[0] = 9;
                        &buf[..1]
                    }
                    b'u' => {
                        let mut c = self.hex4()?;
                        if (0xd800..=0xdbff).contains(&c) {
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err(());
                            }
                            self.pos += 2;
                            let low = self.hex4()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(());
                            }
                            c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
                        }
                        char::from_u32(c)
                            .ok_or(())?
                            .encode_utf8(&mut buf)
                            .as_bytes()
                    }
                    _ => return Err(()),
                }
            } else {
                buf[0] = b;
                &buf[..1]
            };
            if out.len() + decoded.len() > out.capacity() {
                out.grow((out.capacity() * 2).max(out.len() + decoded.len()));
            }
            out.extend(decoded).map_err(|_| ())?;
            offsets.extend(std::iter::repeat_n(raw, decoded.len()));
            zeroize::Zeroize::zeroize(&mut buf);
        }
    }
}
pub(crate) fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn number(b: &[u8]) -> bool {
    let mut i = usize::from(b.first() == Some(&b'-'));
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            i += 1;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i == b.len()
}
