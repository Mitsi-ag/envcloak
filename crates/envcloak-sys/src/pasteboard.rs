//! Reading and clearing the macOS pasteboard (`envcloak add --from-clipboard`,
//! SPEC §6.3, M3 plan M3-19).
//!
//! Uses a minimal Objective-C runtime binding (`libobjc` + `AppKit`) so no
//! external Objective-C crate is added to the dependency tree and `unsafe`
//! stays confined to `envcloak-sys`.
//!
//! [`read_and_clear_pasteboard`] reads the `public.utf8-plain-text` string
//! from `NSPasteboard.generalPasteboard` into a wiping [`zeroize::Zeroizing`]
//! byte buffer, records `NSPasteboard.changeCount` at read time, and calls
//! `clearContents` only when `changeCount` is still equal to that count after
//! the read (SPEC §6.3, gate g6).

use zeroize::Zeroizing;

/// The `NSPasteboardType` for UTF-8 plain text (`NSPasteboardTypeString`).
pub const UTF8_PLAIN_TEXT_TYPE: &str = "public.utf8-plain-text";

/// Env var naming an isolated `NSPasteboard` in `testing` builds.
#[cfg(feature = "testing")]
pub const TEST_PASTEBOARD_ENV: &str = "ENVCLOAK_TEST_PASTEBOARD";

/// Env var that simulates a concurrent clipboard write between reading the
/// pasteboard and checking `changeCount` before clearing, in `testing` builds.
#[cfg(feature = "testing")]
pub const TEST_PASTEBOARD_WRITE_BETWEEN_ENV: &str = "ENVCLOAK_TEST_PASTEBOARD_WRITE_BETWEEN";

/// What [`read_and_clear_pasteboard`] read from the pasteboard.
#[derive(Clone, PartialEq, Eq)]
pub struct PasteboardRead {
    /// The UTF-8 bytes read from the pasteboard, wiped on drop.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Whether the pasteboard was cleared after reading (`true` when
    /// `changeCount` still matched the count at read time).
    pub cleared: bool,
}

impl core::fmt::Debug for PasteboardRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasteboardRead")
            .field("bytes", &"<redacted>")
            .field("cleared", &self.cleared)
            .finish()
    }
}

/// Why reading from the pasteboard failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteboardError {
    /// Clipboard reading is not supported on this platform, or the pasteboard
    /// server could not be reached.
    Unavailable,
    /// The pasteboard holds no plain-text string, or the string is empty.
    Empty,
    /// The pasteboard string exceeds `max_len` bytes.
    TooLong,
}

/// Reads the UTF-8 string (up to `max_len` bytes) from the general pasteboard,
/// and clears the pasteboard only if `changeCount` still matches the count
/// recorded when the read began.
///
/// # Errors
/// Returns [`PasteboardError::Unavailable`] when the pasteboard cannot be
/// reached (or on non-macOS platforms), [`PasteboardError::Empty`] when no
/// non-empty plain-text item is present, or [`PasteboardError::TooLong`] when
/// the UTF-8 byte length exceeds `max_len`.
pub fn read_and_clear_pasteboard(max_len: usize) -> Result<PasteboardRead, PasteboardError> {
    #[cfg(target_os = "macos")]
    {
        #[cfg(feature = "testing")]
        let name = std::env::var(TEST_PASTEBOARD_ENV)
            .ok()
            .filter(|s| !s.is_empty());
        #[cfg(not(feature = "testing"))]
        let name: Option<String> = None;

        #[cfg(feature = "testing")]
        let write_between = std::env::var(TEST_PASTEBOARD_WRITE_BETWEEN_ENV)
            .ok()
            .filter(|s| !s.is_empty());
        #[cfg(not(feature = "testing"))]
        let write_between: Option<String> = None;

        macos::read_and_clear(name.as_deref(), max_len, write_between.as_deref())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = max_len;
        Err(PasteboardError::Unavailable)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use core::ffi::c_void;
    use core_foundation::{
        base::TCFType,
        string::{CFString, CFStringRef},
    };
    use zeroize::Zeroizing;

    use super::{PasteboardError, PasteboardRead, UTF8_PLAIN_TEXT_TYPE};

    const NS_UTF8_STRING_ENCODING: usize = 4;

    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const libc::c_char) -> *mut c_void;
        fn sel_registerName(name: *const libc::c_char) -> *mut c_void;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    struct AutoreleasePool(*mut c_void);

    impl AutoreleasePool {
        fn new() -> Self {
            // SAFETY: objc_autoreleasePoolPush creates a new autorelease pool
            // on the current thread and returns an opaque token for pop.
            Self(unsafe { objc_autoreleasePoolPush() })
        }
    }

    impl Drop for AutoreleasePool {
        fn drop(&mut self) {
            // SAFETY: self.0 is the token returned by objc_autoreleasePoolPush
            // on this thread and is popped exactly once here.
            unsafe { objc_autoreleasePoolPop(self.0) };
        }
    }

    fn sel(name: &'static core::ffi::CStr) -> *mut c_void {
        // SAFETY: `name` is a NUL-terminated static C string.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    fn pasteboard_class() -> Result<*mut c_void, PasteboardError> {
        // SAFETY: static NUL-terminated class name.
        let cls = unsafe { objc_getClass(c"NSPasteboard".as_ptr()) };
        if cls.is_null() {
            Err(PasteboardError::Unavailable)
        } else {
            Ok(cls)
        }
    }

    pub(super) fn open_pasteboard(name: Option<&str>) -> Result<*mut c_void, PasteboardError> {
        let cls = pasteboard_class()?;
        let pb = match name {
            None => {
                // SAFETY: `+[NSPasteboard generalPasteboard]` takes `(id, SEL)`
                // and returns `NSPasteboard *`.
                unsafe {
                    let msg: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                        core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                    msg(cls, sel(c"generalPasteboard"))
                }
            }
            Some(name) => {
                let cf_name = CFString::new(name);
                // SAFETY: `CFStringRef` is toll-free bridged to `NSString *`;
                // `+[NSPasteboard pasteboardWithName:]` takes `(id, SEL, NSString *)`
                // and returns `NSPasteboard *`.
                unsafe {
                    let msg: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        CFStringRef,
                    ) -> *mut c_void = core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                    msg(
                        cls,
                        sel(c"pasteboardWithName:"),
                        cf_name.as_concrete_TypeRef(),
                    )
                }
            }
        };
        if pb.is_null() {
            Err(PasteboardError::Unavailable)
        } else {
            Ok(pb)
        }
    }

    pub(super) fn change_count(pb: *mut c_void) -> isize {
        // SAFETY: `-[NSPasteboard changeCount]` takes `(id, SEL)` and returns
        // `NSInteger` (`isize`). `pb` is a valid `NSPasteboard *`.
        unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(pb, sel(c"changeCount"))
        }
    }

    pub(super) fn clear_contents(pb: *mut c_void) -> isize {
        // SAFETY: `-[NSPasteboard clearContents]` takes `(id, SEL)` and returns
        // `NSInteger` (`isize`). `pb` is a valid `NSPasteboard *`.
        unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(pb, sel(c"clearContents"))
        }
    }

    pub(super) fn set_utf8_string(pb: *mut c_void, text: &str) -> bool {
        let _pool = AutoreleasePool::new();
        let _ = clear_contents(pb);
        let cf_text = CFString::new(text);
        let cf_type = CFString::new(UTF8_PLAIN_TEXT_TYPE);
        // SAFETY: `CFStringRef` is toll-free bridged to `NSString *`;
        // `-[NSPasteboard setString:forType:]` takes `(id, SEL, NSString *, NSString *)`
        // and returns `BOOL` (non-zero on success).
        let ok: i8 = unsafe {
            let msg: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                CFStringRef,
                CFStringRef,
            ) -> i8 = core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(
                pb,
                sel(c"setString:forType:"),
                cf_text.as_concrete_TypeRef(),
                cf_type.as_concrete_TypeRef(),
            )
        };
        ok != 0
    }

    pub(super) fn read_utf8_bytes(
        pb: *mut c_void,
        max_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, PasteboardError> {
        let cf_type = CFString::new(UTF8_PLAIN_TEXT_TYPE);
        // SAFETY: `-[NSPasteboard stringForType:]` takes `(id, SEL, NSString *)`
        // and returns a nullable `NSString *`.
        let ns_str = unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void, CFStringRef) -> *mut c_void =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(pb, sel(c"stringForType:"), cf_type.as_concrete_TypeRef())
        };
        if ns_str.is_null() {
            return Err(PasteboardError::Empty);
        }
        // SAFETY: `-[NSString lengthOfBytesUsingEncoding:]` takes
        // `(id, SEL, NSUInteger)` and returns `NSUInteger` (`usize`).
        let len = unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> usize =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(
                ns_str,
                sel(c"lengthOfBytesUsingEncoding:"),
                NS_UTF8_STRING_ENCODING,
            )
        };
        if len == 0 {
            return Err(PasteboardError::Empty);
        }
        if len > max_len {
            return Err(PasteboardError::TooLong);
        }
        // SAFETY: `-[NSString UTF8String]` takes `(id, SEL)` and returns a
        // pointer to at least `len` UTF-8 bytes valid for the lifetime of the
        // surrounding autorelease pool.
        let utf8_ptr = unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const u8 =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(ns_str, sel(c"UTF8String"))
        };
        if utf8_ptr.is_null() {
            return Err(PasteboardError::Empty);
        }
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        // SAFETY: `utf8_ptr` points to `len` initialized bytes and `bytes` has
        // length `len`; the regions do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(utf8_ptr, bytes.as_mut_ptr(), len);
        }
        Ok(bytes)
    }

    pub(super) fn read_and_clear(
        name: Option<&str>,
        max_len: usize,
        write_between: Option<&str>,
    ) -> Result<PasteboardRead, PasteboardError> {
        let _pool = AutoreleasePool::new();
        let pb = open_pasteboard(name)?;
        let before = change_count(pb);
        let bytes = read_utf8_bytes(pb, max_len)?;
        if let Some(other) = write_between {
            let _ = set_utf8_string(pb, other);
        }
        let cleared = if change_count(pb) == before {
            let _ = clear_contents(pb);
            true
        } else {
            false
        };
        Ok(PasteboardRead { bytes, cleared })
    }

    #[cfg(feature = "testing")]
    pub(super) fn release_globally(pb: *mut c_void) {
        let _pool = AutoreleasePool::new();
        // SAFETY: `-[NSPasteboard releaseGlobally]` takes `(id, SEL)` and
        // releases a named pasteboard's resources in the pasteboard server.
        unsafe {
            let msg: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                core::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            msg(pb, sel(c"releaseGlobally"));
        }
    }
}

/// An isolated named `NSPasteboard` for tests on macOS, released on drop.
#[cfg(all(target_os = "macos", feature = "testing"))]
#[derive(Debug)]
pub struct TestPasteboard {
    name: String,
}

#[cfg(all(target_os = "macos", feature = "testing"))]
impl TestPasteboard {
    /// Creates an isolated named `NSPasteboard` for a test.
    ///
    /// # Panics
    /// Panics if the macOS pasteboard server cannot be reached.
    #[must_use]
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("ai.envcloak.test.{}.{id}", std::process::id());
        let pb = macos::open_pasteboard(Some(&name)).expect("open test pasteboard");
        let _ = macos::clear_contents(pb);
        Self { name }
    }

    /// The pasteboard's name, to pass via [`TEST_PASTEBOARD_ENV`].
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Replaces the pasteboard's contents with `text` as UTF-8 plain text.
    ///
    /// # Panics
    /// Panics if the pasteboard write fails.
    pub fn set_string(&self, text: &str) {
        let pb = macos::open_pasteboard(Some(&self.name)).expect("open test pasteboard");
        assert!(
            macos::set_utf8_string(pb, text),
            "setString:forType: on test pasteboard failed"
        );
    }

    /// Reads the current UTF-8 plain-text string on the pasteboard, or `None`
    /// when it has been cleared.
    ///
    /// # Panics
    /// Panics if the pasteboard cannot be opened.
    #[must_use]
    pub fn read_string(&self) -> Option<String> {
        let pb = macos::open_pasteboard(Some(&self.name)).expect("open test pasteboard");
        match macos::read_utf8_bytes(pb, 64 * 1024) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(PasteboardError::Empty) => None,
            Err(e) => panic!("unexpected pasteboard read error: {e:?}"),
        }
    }

    /// Current `changeCount` of this test pasteboard.
    ///
    /// # Panics
    /// Panics if the pasteboard cannot be opened.
    #[must_use]
    pub fn change_count(&self) -> isize {
        let pb = macos::open_pasteboard(Some(&self.name)).expect("open test pasteboard");
        macos::change_count(pb)
    }
}

#[cfg(all(target_os = "macos", feature = "testing"))]
impl Default for TestPasteboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "macos", feature = "testing"))]
impl Drop for TestPasteboard {
    fn drop(&mut self) {
        if let Ok(pb) = macos::open_pasteboard(Some(&self.name)) {
            macos::release_globally(pb);
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn reads_and_clears_when_change_count_is_unchanged() {
        let pb = TestPasteboard::new();
        pb.set_string("synthetic-pasteboard-value\n");
        let before = pb.change_count();

        let got = macos::read_and_clear(Some(pb.name()), 1024, None).expect("read pasteboard");
        assert!(got.cleared);
        assert_eq!(&*got.bytes, b"synthetic-pasteboard-value\n");
        assert_eq!(pb.read_string(), None);
        assert!(pb.change_count() > before);
    }

    #[test]
    fn does_not_clear_when_change_count_changed_in_between() {
        let pb = TestPasteboard::new();
        pb.set_string("first-synthetic-value");

        let got = macos::read_and_clear(Some(pb.name()), 1024, Some("concurrent-other-text"))
            .expect("read pasteboard");
        assert!(!got.cleared);
        assert_eq!(&*got.bytes, b"first-synthetic-value");
        assert_eq!(
            pb.read_string().as_deref(),
            Some("concurrent-other-text"),
            "concurrent pasteboard write must not be cleared"
        );
    }

    #[test]
    fn empty_and_overlong_pasteboards_are_refused() {
        let pb = TestPasteboard::new();
        assert_eq!(
            macos::read_and_clear(Some(pb.name()), 1024, None),
            Err(PasteboardError::Empty)
        );
        pb.set_string("1234567890");
        assert_eq!(
            macos::read_and_clear(Some(pb.name()), 5, None),
            Err(PasteboardError::TooLong)
        );
    }
}
