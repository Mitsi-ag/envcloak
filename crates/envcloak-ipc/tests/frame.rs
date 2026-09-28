//! Framing (SPEC §10a "Bounds", gate 32's frame half): at most 1 MiB, a
//! refused header costs four bytes of reading and nothing else, and a
//! stream that ends or stalls inside a frame is reported as such.
#![allow(clippy::unwrap_used)]

use std::io::{self, Read};

use envcloak_ipc::{Frame, FrameError, MAX_FRAME};

/// A reader that serves `data` and counts what was taken.
struct Counting<'a> {
    data: &'a [u8],
    taken: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.data.len() - self.taken);
        buf[..n].copy_from_slice(&self.data[self.taken..self.taken + n]);
        self.taken += n;
        Ok(n)
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut v = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

#[test]
fn frames_round_trip() {
    let msg = serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "status"});
    let frame = Frame::encode(&msg).unwrap();
    let mut wire = Vec::new();
    frame.write_to(&mut wire).unwrap();
    assert_eq!(
        &wire[..4],
        &u32::try_from(frame.len()).unwrap().to_be_bytes()
    );
    let back = Frame::read_from(&mut &wire[..]).unwrap();
    let v: serde_json::Value = back.decode().unwrap();
    assert_eq!(v, msg);
    assert!(format!("{back:?}").contains("len"));
}

#[test]
fn a_header_over_the_limit_is_refused_after_four_bytes() {
    for len in [MAX_FRAME as u32 + 1, u32::MAX] {
        let mut wire = len.to_be_bytes().to_vec();
        wire.extend_from_slice(&[b'x'; 64]);
        let mut r = Counting {
            data: &wire,
            taken: 0,
        };
        assert_eq!(Frame::read_from(&mut r).unwrap_err(), FrameError::TooLarge);
        assert_eq!(r.taken, 4, "nothing past the header is read");
    }
    let mut r = Counting {
        data: &[0, 0, 0, 0, b'{'],
        taken: 0,
    };
    assert_eq!(Frame::read_from(&mut r).unwrap_err(), FrameError::Empty);
    assert_eq!(r.taken, 4);
}

#[test]
fn a_frame_of_exactly_the_limit_is_read() {
    // A JSON string filling the whole frame.
    let mut body = vec![b'a'; MAX_FRAME];
    body[0] = b'"';
    body[MAX_FRAME - 1] = b'"';
    let wire = framed(&body);
    let frame = Frame::read_from(&mut &wire[..]).unwrap();
    assert_eq!(frame.len(), MAX_FRAME);
    let s: String = frame.decode().unwrap();
    assert_eq!(s.len(), MAX_FRAME - 2);
}

#[test]
fn messages_that_do_not_fit_are_not_encoded() {
    let big = "a".repeat(MAX_FRAME);
    assert_eq!(Frame::encode(&big).unwrap_err(), FrameError::TooLarge);
    // Just under: a string of MAX_FRAME - 2 bytes plus its quotes.
    let fits = "a".repeat(MAX_FRAME - 2);
    assert_eq!(Frame::encode(&fits).unwrap().len(), MAX_FRAME);
}

#[test]
fn ends_and_truncations_are_told_apart() {
    assert_eq!(
        Frame::read_from(&mut &b""[..]).unwrap_err(),
        FrameError::Closed
    );
    assert_eq!(
        Frame::read_from(&mut &[0u8, 0][..]).unwrap_err(),
        FrameError::Truncated
    );
    let mut wire = framed(b"{\"a\":1}");
    wire.truncate(wire.len() - 1);
    assert_eq!(
        Frame::read_from(&mut &wire[..]).unwrap_err(),
        FrameError::Truncated
    );
    // Two frames back to back, then a clean end.
    let mut two = framed(b"1");
    two.extend(framed(b"[2]"));
    let mut r = &two[..];
    assert_eq!(Frame::read_from(&mut r).unwrap().decode::<u8>().unwrap(), 1);
    assert_eq!(
        Frame::read_from(&mut r)
            .unwrap()
            .decode::<Vec<u8>>()
            .unwrap(),
        [2]
    );
    assert_eq!(Frame::read_from(&mut r).unwrap_err(), FrameError::Closed);
}

/// A stream that stalls inside a frame (a read timeout) is a truncated
/// frame; one that stalls between frames is an I/O error the caller can
/// treat as an idle connection.
#[test]
fn a_stall_inside_a_frame_is_a_truncation() {
    struct Stall<'a>(&'a [u8]);
    impl Read for Stall<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let wire = framed(b"{\"partial\":true}");
    assert_eq!(
        Frame::read_from(&mut Stall(&wire[..10])).unwrap_err(),
        FrameError::Truncated
    );
    assert_eq!(
        Frame::read_from(&mut Stall(&wire[..2])).unwrap_err(),
        FrameError::Truncated
    );
    assert_eq!(
        Frame::read_from(&mut Stall(&[])).unwrap_err(),
        FrameError::Io(io::ErrorKind::WouldBlock)
    );
}
