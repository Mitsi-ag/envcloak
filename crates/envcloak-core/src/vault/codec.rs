//! The binary encoding of the records sealed into vault rows (layouts in
//! docs/VAULT.md).
//!
//! Integers are big-endian. A byte string is a `u32` length then the bytes;
//! text is a byte string holding UTF-8. An optional value is a `0` byte, or
//! a `1` byte then the value. A list is a `u32` count then the items. No
//! serializer is involved, and decoding reports [`VaultErrorKind::Corrupt`]
//! without saying what it read: records are authenticated before they are
//! decoded, so a failure here means a bug, never an attacker's bytes.

use super::error::{VaultError, VaultErrorKind};

/// Builds a record.
#[derive(Debug, Default)]
pub(crate) struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub(crate) fn new() -> Self {
        Enc::default()
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// A list's count. Lists are capped far below 4 GiB before they are
    /// encoded, so a longer one is a bug.
    pub(crate) fn count(&mut self, n: usize) -> &mut Self {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX))
    }

    pub(crate) fn opt_bytes(&mut self, b: Option<&[u8]>) -> &mut Self {
        match b {
            None => self.u8(0),
            Some(b) => self.u8(1).bytes(b),
        }
    }

    pub(crate) fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// A length-prefixed byte string. Records are capped far below 4 GiB
    /// before they are sealed, so a longer input is a bug.
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    pub(crate) fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub(crate) fn opt_str(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.u8(0),
            Some(s) => self.u8(1).str(s),
        }
    }

    pub(crate) fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(v) => self.u8(1).u64(v),
        }
    }

    pub(crate) fn strs(&mut self, list: &[String]) -> &mut Self {
        let n = u32::try_from(list.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&n.to_be_bytes());
        for s in list {
            self.str(s);
        }
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }
}

/// Reads a record. Every method fails with [`VaultErrorKind::Corrupt`] on
/// short input, and [`Dec::end`] on trailing bytes.
#[derive(Debug)]
pub(crate) struct Dec<'a> {
    buf: &'a [u8],
    at: usize,
}

fn corrupt() -> VaultError {
    VaultErrorKind::Corrupt.into()
}

impl<'a> Dec<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Dec { buf, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        let end = self.at.checked_add(n).ok_or_else(corrupt)?;
        let s = self.buf.get(self.at..end).ok_or_else(corrupt)?;
        self.at = end;
        Ok(s)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, VaultError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, VaultError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, VaultError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn bool(&mut self) -> Result<bool, VaultError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(corrupt()),
        }
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], VaultError> {
        let len = usize::try_from(self.u32()?).map_err(|_| corrupt())?;
        self.take(len)
    }

    pub(crate) fn string(&mut self) -> Result<String, VaultError> {
        let b = self.bytes()?;
        core::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| corrupt())
    }

    pub(crate) fn opt_string(&mut self) -> Result<Option<String>, VaultError> {
        if self.bool()? {
            self.string().map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn opt_u64(&mut self) -> Result<Option<u64>, VaultError> {
        if self.bool()? {
            self.u64().map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn opt_bytes(&mut self) -> Result<Option<&'a [u8]>, VaultError> {
        if self.bool()? {
            self.bytes().map(Some)
        } else {
            Ok(None)
        }
    }

    /// A list's count: at most `max`, and at most as many items of
    /// `min_len` bytes each as the rest of the input holds, which also
    /// bounds what a caller allocates for them.
    pub(crate) fn count(&mut self, min_len: usize, max: usize) -> Result<usize, VaultError> {
        let n = usize::try_from(self.u32()?).map_err(|_| corrupt())?;
        let rest = self.buf.len() - self.at;
        if n > max || n > rest / min_len.max(1) {
            return Err(corrupt());
        }
        Ok(n)
    }

    pub(crate) fn strings(&mut self) -> Result<Vec<String>, VaultError> {
        let n = self.u32()?;
        // Each string takes at least its 4-byte length, so a count larger
        // than the remaining input is corrupt; this also bounds the
        // allocation.
        let rest = self.buf.len() - self.at;
        if usize::try_from(n).map_err(|_| corrupt())? > rest / 4 {
            return Err(corrupt());
        }
        (0..n).map(|_| self.string()).collect()
    }

    /// Fails unless every byte was read.
    pub(crate) fn end(&self) -> Result<(), VaultError> {
        if self.at == self.buf.len() {
            Ok(())
        } else {
            Err(corrupt())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_kind() {
        let list = vec!["a".to_owned(), String::new(), "\u{e9}t\u{e9}".to_owned()];
        let bytes = Enc::new()
            .u8(7)
            .u64(u64::MAX - 1)
            .raw(&[1, 2])
            .bytes(b"xyz")
            .str("text")
            .opt_str(None)
            .opt_str(Some("some"))
            .opt_u64(None)
            .opt_u64(Some(9))
            .strs(&list)
            .finish();
        let mut d = Dec::new(&bytes);
        assert_eq!(d.u8().unwrap(), 7);
        assert_eq!(d.u64().unwrap(), u64::MAX - 1);
        assert_eq!(d.array::<2>().unwrap(), [1, 2]);
        assert_eq!(d.bytes().unwrap(), b"xyz");
        assert_eq!(d.string().unwrap(), "text");
        assert_eq!(d.opt_string().unwrap(), None);
        assert_eq!(d.opt_string().unwrap().as_deref(), Some("some"));
        assert_eq!(d.opt_u64().unwrap(), None);
        assert_eq!(d.opt_u64().unwrap(), Some(9));
        assert_eq!(d.strings().unwrap(), list);
        d.end().unwrap();
    }

    #[test]
    fn short_bad_and_trailing_input_is_corrupt() {
        let is_corrupt = |r: Result<(), VaultError>| {
            assert_eq!(r.unwrap_err().kind(), VaultErrorKind::Corrupt);
        };
        is_corrupt(Dec::new(&[0, 0, 0, 5, b'a']).bytes().map(drop));
        is_corrupt(Dec::new(&[0, 0, 0, 1, 0xff]).string().map(drop));
        is_corrupt(Dec::new(&[2]).bool().map(drop));
        is_corrupt(Dec::new(&[0xff, 0xff, 0xff, 0xff]).strings().map(drop));
        is_corrupt(Dec::new(&[1, 2, 3]).u64().map(drop));
        let mut d = Dec::new(&[1, 2]);
        d.u8().unwrap();
        is_corrupt(d.end());
    }
}
