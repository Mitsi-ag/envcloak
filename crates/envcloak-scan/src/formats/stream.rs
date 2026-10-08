//! Incremental wire reader. Buffers wipe on growth, reuse and drop.
use super::*;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Input<R> {
    reader: R,
    buffer: Zeroizing<[u8; 4096]>,
    pos: usize,
    end: usize,
    total: usize,
}
impl<R: Read> Input<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Zeroizing::new([0; 4096]),
            pos: 0,
            end: 0,
            total: 0,
        }
    }
    pub fn peek(&mut self) -> Result<Option<u8>, FormatError> {
        if self.pos == self.end {
            self.buffer.zeroize();
            self.end = loop {
                match self.reader.read(&mut *self.buffer) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(FormatError::Read),
                }
            };
            self.pos = 0;
        }
        if self.pos == self.end {
            Ok(None)
        } else if self.total == MAX_INPUT {
            Err(FormatError::Limit)
        } else {
            Ok(Some(self.buffer[self.pos]))
        }
    }
    pub fn next(&mut self) -> Result<Option<u8>, FormatError> {
        let b = self.peek()?;
        if b.is_some() {
            self.buffer[self.pos] = 0;
            self.pos += 1;
            self.total += 1;
        }
        Ok(b)
    }
    pub fn space(&mut self) -> Result<(), FormatError> {
        while matches!(self.peek()?, Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.next()?;
        }
        Ok(())
    }
    pub fn expect(&mut self, b: u8) -> Result<(), FormatError> {
        self.space()?;
        if self.next()? == Some(b) {
            Ok(())
        } else {
            Err(FormatError::Shape)
        }
    }
    pub fn end(&mut self, b: u8) -> Result<bool, FormatError> {
        self.space()?;
        if self.peek()? == Some(b) {
            self.next()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    /// One bounded JSON subtree. Delimiters in strings never end a record.
    #[allow(clippy::disallowed_methods)] // Decode bounded wiping JSON records.
    pub fn node(&mut self) -> Result<Node, FormatError> {
        self.space()?;
        let mut out = SecretBuf::with_capacity(256);
        let mut depth = 0usize;
        let mut string = false;
        let mut escape = false;
        while let Some(b) = self.peek()? {
            if !string
                && depth == 0
                && (matches!(b, b',' | b']' | b'}' | b':')
                    || (out.len() > 0 && b.is_ascii_whitespace()))
            {
                break;
            }
            self.next()?;
            append(&mut out, &[b], MAX_RECORD)?;
            if string {
                if escape {
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == b'"' {
                    string = false;
                }
            } else {
                match b {
                    b'"' => string = true,
                    b'{' | b'[' => {
                        depth += 1;
                        if depth > 64 {
                            return Err(FormatError::Limit);
                        }
                    }
                    b'}' | b']' => {
                        depth = depth.checked_sub(1).ok_or(FormatError::Invalid)?;
                    }
                    _ => {}
                }
            }
            if !string && depth == 0 && matches!(b, b'"' | b'}' | b']') {
                break;
            }
        }
        let bytes = out.freeze();
        let node = crate::json::parse(secrecy::ExposeSecret::expose_secret(&bytes))
            .map_err(|_| FormatError::Invalid)?;
        check(&node)?;
        Ok(node)
    }
    pub fn array(
        &mut self,
        mut f: impl FnMut(Node) -> Result<(), FormatError>,
    ) -> Result<(), FormatError> {
        self.expect(b'[')?;
        if self.end(b']')? {
            return Ok(());
        }
        loop {
            f(self.node()?)?;
            if self.end(b']')? {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }
    pub fn object(
        &mut self,
        mut f: impl FnMut(SecretBytes, &mut Self) -> Result<(), FormatError>,
    ) -> Result<(), FormatError> {
        self.expect(b'{')?;
        let mut names = std::collections::HashSet::new();
        if self.end(b'}')? {
            return Ok(());
        }
        loop {
            let name = text(self.node()?)?;
            if names.len() >= MAX_RECORDS || !names.insert(name.sha256()) {
                return Err(FormatError::Invalid);
            }
            self.expect(b':')?;
            f(name, self)?;
            if self.end(b'}')? {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }
}
pub(super) fn append(out: &mut SecretBuf, bytes: &[u8], cap: usize) -> Result<(), FormatError> {
    let len = out.len() + bytes.len();
    if len > cap {
        return Err(FormatError::Limit);
    }
    if len > out.capacity() {
        out.grow((out.capacity() * 2).max(len).min(cap));
    }
    out.extend(bytes).map_err(|_| FormatError::Limit)
}
fn check(node: &Node) -> Result<(), FormatError> {
    match node {
        Node::Text(t) if t.value.len() > MAX_FIELD => return Err(FormatError::Limit),
        Node::Object(fields) => {
            for (k, v) in fields {
                if k.value.len() > MAX_FIELD {
                    return Err(FormatError::Limit);
                }
                check(v)?;
            }
        }
        Node::Array(values) => {
            for v in values {
                check(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
