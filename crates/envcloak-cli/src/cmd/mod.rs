//! The commands (SPEC §14 M1 list). T7 has `vault create`, `unlock`,
//! `lock`, `status` and `daemon install`; later tasks add the rest.
//!
//! Argument errors never echo an argument: one could be a pasted secret.

pub mod daemon;
pub mod lock;
pub mod status;
pub mod unlock;
pub mod vault;

/// A file descriptor number given on the command line: digits only.
pub fn fd_number(v: &str) -> Option<i32> {
    if v.is_empty() || v.len() > 9 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::fd_number;

    #[test]
    fn descriptor_numbers_are_plain_digits() {
        assert_eq!(fd_number("0"), Some(0));
        assert_eq!(fd_number("3"), Some(3));
        assert_eq!(fd_number("123456789"), Some(123_456_789));
        for bad in ["", "-1", "+3", "3 ", "0x3", "1234567890", "three"] {
            assert_eq!(fd_number(bad), None, "{bad}");
        }
    }
}
