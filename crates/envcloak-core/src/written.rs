//! What a file the vault writes was written with, so it is answered for
//! only while it holds exactly that.
//!
//! A backup is answered as written only once its final name is shown to
//! hold the file this call wrote: callers delete or rewrite the originals
//! on the strength of that answer. The file's device and inode say which
//! file the name holds, not what it holds: another process of the same
//! user can write into it in place, or truncate it, before the answer, and
//! the backup would not restore. So every byte that reaches the file is
//! counted and hashed as it is written ([`Counted`]), and the file is read
//! back whole and must have that length and SHA-256, its stamp unchanged
//! while it is read ([`Written::read_back`]), which returns that stamp
//! ([`Stamp`]): where the read would take long under a lock (a backup v2
//! of up to 1 GiB), it is done first, and the file's stamp, compared again
//! later, stands for the bytes read. Nothing can keep the file from being
//! changed after the answer: the check is of the file as it is answered
//! for.
//!
//! A stamp shows a write only once the file system's clock has moved past
//! the file's last change: Linux stamps every change within one tick of
//! its clock (a millisecond or a few) with the same time, so a write right
//! after the file's own last one leaves its stamp as it was. So before the
//! read, [`Written::read_back`] waits until a change made in the file's
//! directory is stamped later than the file's last one
//! ([`envcloak_sys::wait_for_clock_past`]; at most a tick, and macOS's
//! APFS stamps each change apart at once): from then on any write, cut,
//! link or mode change moves the file's change time, which no program can
//! set.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The longest [`Written::read_back`] waits for the file system's clock
/// to move past a file's last change: a file system that stamps whole
/// seconds (HFS+, ext4 with small inodes) takes up to a second.
const CLOCK_WAIT: Duration = Duration::from_secs(3);

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

/// A file's stamp: its device, inode, size, mode, owner and link count,
/// and its modification and change times. Equal stamps of one file, taken
/// once the file system's clock moved past its last change
/// ([`Written::read_back`]), show that nothing wrote into it, cut, linked
/// or re-permissioned it in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    ids: (u64, u64, u64, u32, u32, u64),
    times: (i64, i64, i64, i64),
}

impl Stamp {
    /// `f`'s stamp now.
    ///
    /// # Errors
    /// When its metadata cannot be read.
    pub(crate) fn of(f: &File) -> std::io::Result<Stamp> {
        let m = f.metadata()?;
        Ok(Stamp {
            ids: (m.dev(), m.ino(), m.size(), m.mode(), m.uid(), m.nlink()),
            times: (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
        })
    }

    fn size(&self) -> u64 {
        self.ids.2
    }

    /// The change time.
    fn changed(&self) -> (i64, i64) {
        (self.times.2, self.times.3)
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

    /// The stamp `f` has while it holds exactly these bytes: read whole
    /// from its start through `f`, of this length and SHA-256, its stamp
    /// the same before and after the read. `None` when it holds anything
    /// else.
    ///
    /// Before the read it waits (up to [`CLOCK_WAIT`]) until a change to
    /// `clock`, a directory of this user on `f`'s file system (its own),
    /// is stamped later than `f`'s last change, so that from then on any
    /// change to `f` moves its change time: a write while it is read, or
    /// after it, shows in its stamp however soon it comes, and the stamp
    /// returned can stand for the bytes read until it changes
    /// ([`envcloak_sys::wait_for_clock_past`], which gives `clock` the
    /// permissions it has: that changes nothing but its change time).
    /// Backups hold ciphertext only, so the bytes read need no wiping.
    ///
    /// # Errors
    /// When a metadata cannot be read, `clock` cannot be probed, or the
    /// file system's clock did not move past `f`'s last change within
    /// [`CLOCK_WAIT`] (`TimedOut`: its clock went back, or it does not
    /// keep change times); a failed read is `None`.
    pub(crate) fn read_back(&self, f: &File, clock: &File) -> std::io::Result<Option<Stamp>> {
        let before = Stamp::of(f)?;
        if before.size() != self.len {
            return Ok(None);
        }
        envcloak_sys::wait_for_clock_past(clock, before.changed(), CLOCK_WAIT)?;
        // A test build can stop here (`ENVCLOAK_TEST_PAUSE=backup.read_back`),
        // before the read: the daemon's tests show what it holds meanwhile.
        envcloak_sys::pause_point("backup.read_back");
        let mut buf = vec![0u8; 64 * 1024];
        let mut h = Sha256::new();
        let mut at: u64 = 0;
        loop {
            let n = match f.read_at(&mut buf, at) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Ok(None),
            };
            at += n as u64;
            if at > self.len {
                return Ok(None);
            }
            h.update(&buf[..n]);
            #[cfg(test)]
            tests::during_read();
        }
        let digest: [u8; 32] = h.finalize().into();
        let held = at == self.len && digest == self.sha256 && Stamp::of(f)? == before;
        Ok(held.then_some(before))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// What a test does each time [`Written::read_back`] read a part.
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

    /// Makes `f` run each time [`Written::read_back`] read a part on this
    /// thread, until [`clear_during_read`].
    pub(crate) fn set_during_read(f: impl FnMut() + 'static) {
        DURING_READ.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    pub(crate) fn clear_during_read() {
        DURING_READ.with(|h| *h.borrow_mut() = None);
    }

    /// Writes one byte at `at` of the file at `p` in place, its value
    /// flipped, and puts its modification time back.
    fn write_into(p: &std::path::Path, at: u64) {
        let w = File::options().read(true).write(true).open(p).unwrap();
        let modified = w.metadata().unwrap().modified().unwrap();
        let mut b = [0u8];
        w.read_exact_at(&mut b, at).unwrap();
        w.write_all_at(&[b[0] ^ 1], at).unwrap();
        w.set_modified(modified).unwrap();
    }

    /// A write while the file is read back is seen, though every part was
    /// read as written: right after the first 64 KiB are read, another
    /// handle writes into them in place (one byte, its modification time
    /// put back), so the bytes read make up the SHA-256 written, but the
    /// file no longer holds them. It is not taken for the file written.
    #[test]
    fn a_write_while_the_file_is_read_back_is_seen() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        let p = d.path().join("f");
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &body).unwrap();
        let written = Written::of(&body);
        let f = File::open(&p).unwrap();
        assert!(written.read_back(&f, &dir).unwrap().is_some());
        let q = p.clone();
        let mut once = true;
        set_during_read(move || {
            if std::mem::take(&mut once) {
                write_into(&q, 10);
            }
        });
        let held = written.read_back(&f, &dir).unwrap();
        clear_during_read();
        assert!(
            held.is_none(),
            "a file written into while it was read was taken for the one written"
        );
    }

    /// The stamp a read back returns stands for the bytes read: a write
    /// into the file in place (one byte, its modification time put back,
    /// the length kept) made right after the read, as soon as a program
    /// can, moves it, every time. Linux stamps every change within one
    /// tick of its clock alike, and a file just written was changed within
    /// that tick, so this holds only because the read back waited for the
    /// clock to move past the file's last change.
    #[test]
    fn a_write_right_after_the_read_back_moves_the_stamp() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        for i in 0..40 {
            let p = d.path().join(format!("f{i}"));
            let mut w = Counted::new(File::create_new(&p).unwrap());
            w.write_all(&body).unwrap();
            let (f, written) = w.finish();
            f.sync_all().unwrap();
            let f = File::open(&p).unwrap();
            let stamp = written.read_back(&f, &dir).unwrap().unwrap();
            write_into(&p, 100);
            assert_ne!(
                Stamp::of(&f).unwrap(),
                stamp,
                "a write right after the read back (file {i}) left the stamp as read"
            );
        }
    }

    /// What a writer counts is what reached the file, and a file holds it
    /// only byte for byte: one byte changed in place (its modification
    /// time put back), one byte more or one less, or another file, does
    /// not.
    #[test]
    fn a_file_holds_what_was_written_only_byte_for_byte() {
        let d = tempfile::tempdir().unwrap();
        let dir = File::open(d.path()).unwrap();
        let p = d.path().join("f");
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut w = Counted::new(File::create(&p).unwrap());
        w.write_all(&body[..70_000]).unwrap();
        w.write_all(&body[70_000..]).unwrap();
        let (f, written) = w.finish();
        drop(f);
        assert_eq!(written, Written::of(&body));
        let held = |f: &File| written.read_back(f, &dir).unwrap().is_some();
        let f = File::options().read(true).write(true).open(&p).unwrap();
        assert!(held(&f));
        let modified = f.metadata().unwrap().modified().unwrap();
        f.write_all_at(&[body[123_456] ^ 1], 123_456).unwrap();
        f.set_modified(modified).unwrap();
        assert!(!held(&f), "a byte changed in place");
        f.write_all_at(&body[123_456..123_457], 123_456).unwrap();
        assert!(held(&f));
        f.set_len(body.len() as u64 + 1).unwrap();
        assert!(!held(&f), "one byte more");
        f.set_len(body.len() as u64 - 1).unwrap();
        assert!(!held(&f), "one byte less");
        std::fs::write(d.path().join("g"), &body[..10]).unwrap();
        let g = File::open(d.path().join("g")).unwrap();
        assert!(!held(&g), "another file");
        assert!(
            Written::of(&body[..10])
                .read_back(&g, &dir)
                .unwrap()
                .is_some()
        );
    }
}
