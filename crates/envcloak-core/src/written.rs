//! What a file the vault writes was written with, so it is answered for
//! only while it holds exactly that.
//!
//! A backup is answered as written only once its final name is shown to
//! hold the file this call wrote: callers delete or rewrite the originals
//! on the strength of that answer. The file's device and inode say which
//! file the name holds, not what it holds: another process of the same
//! user can write into it in place, or truncate it, before the answer, and
//! the backup would not restore. So every byte that reaches the file is
//! counted and hashed as it is written ([`Counted`]), and before the
//! answer the file the name holds is read back whole and must have that
//! length and SHA-256, its stamp unchanged while it is read
//! ([`Written::held_by`]). Nothing can keep the file from being changed
//! after the answer: the check is of the file as it is answered for.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};

use sha2::{Digest, Sha256};

/// A writer that counts and hashes every byte that reaches `inner`.
pub(crate) struct Counted<W> {
    inner: W,
    h: Sha256,
    len: u64,
}

impl<W> Counted<W> {
    pub(crate) fn new(inner: W) -> Self {
        Counted {
            inner,
            h: Sha256::new(),
            len: 0,
        }
    }

    /// The inner writer, and what reached it.
    pub(crate) fn finish(self) -> (W, Written) {
        (
            self.inner,
            Written {
                len: self.len,
                sha256: self.h.finalize().into(),
            },
        )
    }
}

impl<W: Write> Write for Counted<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        let wrote = buf.get(..n).unwrap_or_default();
        self.h.update(wrote);
        self.len += wrote.len() as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The length and SHA-256 of the bytes written to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Written {
    pub(crate) len: u64,
    sha256: [u8; 32],
}

impl Written {
    /// What writing `bytes` whole writes.
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Written {
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    /// Whether `f` holds exactly these bytes: read whole from its start
    /// through `f`, of this length and SHA-256, and its stamp (device,
    /// inode, size, modification and change times, mode, owner and links)
    /// the same before and after the read, so a write while it is read is
    /// seen too. Backups hold ciphertext only, so the bytes read need no
    /// wiping.
    ///
    /// # Errors
    /// When its metadata cannot be read; a failed read is `false`.
    pub(crate) fn held_by(&self, f: &File) -> std::io::Result<bool> {
        let stamp = |m: &std::fs::Metadata| {
            (
                (m.dev(), m.ino(), m.size(), m.mode(), m.uid(), m.nlink()),
                (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
            )
        };
        let before = stamp(&f.metadata()?);
        if before.0.2 != self.len {
            return Ok(false);
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut h = Sha256::new();
        let mut at: u64 = 0;
        loop {
            let n = match f.read_at(&mut buf, at) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Ok(false),
            };
            at += n as u64;
            if at > self.len {
                return Ok(false);
            }
            h.update(&buf[..n]);
            #[cfg(test)]
            tests::during_read();
        }
        let digest: [u8; 32] = h.finalize().into();
        Ok(at == self.len && digest == self.sha256 && stamp(&f.metadata()?) == before)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// What a test does each time [`Written::held_by`] read a part.
        static DURING_READ: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    }

    /// Runs this thread's hook, if a test set one.
    pub(super) fn during_read() {
        DURING_READ.with(|d| {
            if let Some(f) = d.borrow_mut().as_mut() {
                f();
            }
        });
    }

    /// A write while the file is read back is seen, though every part was
    /// read as written: right after the first 64 KiB are read, another
    /// handle writes into them in place (one byte, its modification time
    /// put back), so the bytes read make up the SHA-256 written, but the
    /// file no longer holds them. It is not taken for the file written.
    #[test]
    fn a_write_while_the_file_is_read_back_is_seen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &body).unwrap();
        let written = Written::of(&body);
        let f = File::open(&p).unwrap();
        assert!(written.held_by(&f).unwrap());
        let q = p.clone();
        let mut once = true;
        DURING_READ.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                if std::mem::take(&mut once) {
                    let w = File::options().write(true).open(&q).unwrap();
                    let modified = w.metadata().unwrap().modified().unwrap();
                    w.write_all_at(&[0xff], 10).unwrap();
                    w.set_modified(modified).unwrap();
                }
            }));
        });
        let held = written.held_by(&f).unwrap();
        DURING_READ.with(|h| *h.borrow_mut() = None);
        assert!(
            !held,
            "a file written into while it was read was taken for the one written"
        );
    }

    /// What a writer counts is what reached the file, and a file holds it
    /// only byte for byte: one byte changed in place (its modification
    /// time put back), one byte more or one less, or another file, does
    /// not.
    #[test]
    fn a_file_holds_what_was_written_only_byte_for_byte() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut w = Counted::new(File::create(&p).unwrap());
        w.write_all(&body[..70_000]).unwrap();
        w.write_all(&body[70_000..]).unwrap();
        let (f, written) = w.finish();
        drop(f);
        assert_eq!(written, Written::of(&body));
        let f = File::options().read(true).write(true).open(&p).unwrap();
        assert!(written.held_by(&f).unwrap());
        let modified = f.metadata().unwrap().modified().unwrap();
        f.write_all_at(&[body[123_456] ^ 1], 123_456).unwrap();
        f.set_modified(modified).unwrap();
        assert!(!written.held_by(&f).unwrap(), "a byte changed in place");
        f.write_all_at(&body[123_456..123_457], 123_456).unwrap();
        assert!(written.held_by(&f).unwrap());
        f.set_len(body.len() as u64 + 1).unwrap();
        assert!(!written.held_by(&f).unwrap(), "one byte more");
        f.set_len(body.len() as u64 - 1).unwrap();
        assert!(!written.held_by(&f).unwrap(), "one byte less");
        std::fs::write(d.path().join("g"), &body[..10]).unwrap();
        let g = File::open(d.path().join("g")).unwrap();
        assert!(!written.held_by(&g).unwrap(), "another file");
        assert!(Written::of(&body[..10]).held_by(&g).unwrap());
    }
}
