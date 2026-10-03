//! An independent count of a `files.restore` answer's frame (M1-AUDIT:
//! `files.backup` takes a backup only when its restore's answer fits in
//! one frame for any request id, so the size of that answer must be what
//! the daemon's check computes). The expected size here comes from a
//! fixed grammar of the answer's JSON written out by hand: integer widths
//! in decimal, UTF-8 widths, JSON's quote, backslash and control escapes,
//! and standard padded base64's `4 * ceil(n / 3)`. No serializer and no
//! sizing helper of EnvCloak's computes it. `result_frame` is what is
//! tested, and a counting writer checks that the frame on the wire is the
//! body and its four header bytes.
//!
//! Six shapes of answer: a terminal's, an agent's and an unknown
//! process's backup, and one that records no maker; a removed and a
//! rewritten file, a result not recorded; a path and an agent's label
//! with every JSON escape and characters of two, three and four bytes;
//! modes from 0 to `u32::MAX`; and two files. Empty answers go to ids 0,
//! 9, 10 and `u64::MAX`; each shape with contents of 0 to 4 bytes (each
//! base64 padding) to ids 0 and `u64::MAX`. For each shape, an answer of
//! exactly `MAX_FRAME` to id `u64::MAX` is framed; a byte more of
//! metadata, or of contents (4 more bytes of base64), is refused; and an
//! answer of exactly a frame to id 0 is refused to id `u64::MAX`, 19
//! bytes over.
//!
//! Positive controls: an expected count four bytes short is caught for
//! every shape, and a grammar that leaves JSON's escapes out is caught on
//! the shape whose path and agent's label hold them, so a count that is
//! off cannot pass.
#![allow(clippy::unwrap_used)]

use std::io::{self, Write};

use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{self, FileLeft, RestoredFile, RestoredFiles};
use envcloak_ipc::view::FileBackupCreatorView;
use envcloak_ipc::{FrameError, MAX_FRAME, WireSecret};

#[derive(Clone)]
struct Meta {
    path: String,
    mode: u32,
    left: Option<FileLeft>,
    bytes: usize,
}

#[derive(Clone)]
struct Shape {
    creator: Option<FileBackupCreatorView>,
    files: Vec<Meta>,
}

#[derive(Default)]
struct Stats {
    checked: usize,
    accepted: usize,
    refused: usize,
    wrong_count_caught: usize,
    escapes_caught: usize,
}

/// The bytes `s` takes as a JSON string, by JSON's rules alone.
fn quoted(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match u32::from(c) {
            34 | 92 | 8 | 9 | 10 | 12 | 13 => 2,
            0..=31 => 6,
            _ => c.len_utf8(),
        })
        .sum::<usize>()
}

/// The bytes `s` would take as a JSON string if nothing were escaped: a
/// wrong grammar, for the positive control.
fn unescaped(s: &str) -> usize {
    2 + s.len()
}

/// The answer's frame body for request `id`, counted from the grammar.
fn expected(id: u64, s: &Shape) -> usize {
    expected_with(id, s, quoted)
}

/// [`expected`], with strings counted by `quoted`.
fn expected_with(id: u64, s: &Shape, quoted: fn(&str) -> usize) -> usize {
    let mut n = br#"{"jsonrpc":"2.0","id":"#.len() + id.to_string().len() + br#","result":{"#.len();
    if let Some(c) = &s.creator {
        n += br#""creator":{"kind":"#.len() + quoted(&c.kind);
        if let Some(a) = &c.agent {
            n += br#","agent":"#.len() + quoted(a);
        }
        n += b"},".len();
    }
    n += br#""files":["#.len();
    for (i, f) in s.files.iter().enumerate() {
        n += usize::from(i > 0);
        n += br#"{"path":"#.len()
            + quoted(&f.path)
            + br#","mode":"#.len()
            + f.mode.to_string().len()
            + br#","content":"#.len()
            + 2
            + 4 * f.bytes.div_ceil(3);
        if let Some(left) = &f.left {
            n += br#","left":"#.len();
            n += match left {
                FileLeft::Removed => br#""removed""#.len(),
                FileLeft::Rewritten(d) => br#"{"rewritten":"#.len() + quoted(d) + 1,
            };
        }
        n += 1;
    }
    n + b"]}}".len()
}

fn answer(s: &Shape) -> RestoredFiles {
    RestoredFiles {
        creator: s.creator.clone(),
        files: s
            .files
            .iter()
            .map(|f| RestoredFile {
                path: f.path.clone(),
                mode: f.mode,
                left: f.left.clone(),
                content: WireSecret::new(SecretBytes::copy_from(&vec![167; f.bytes])),
            })
            .collect(),
    }
}

/// Counts what is written, and keeps none of it.
#[derive(Default)]
struct CountWriter(usize);

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify(id: u64, s: &Shape, stats: &mut Stats) {
    let want = expected(id, s);
    match proto::result_frame(id, &answer(s)) {
        Ok(f) => {
            assert!(want <= MAX_FRAME, "framed, though {want} bytes");
            assert!(f.len() == want, "{} bytes framed, {want} counted", f.len());
            let mut sink = CountWriter::default();
            f.write_to(&mut sink).unwrap();
            assert!(sink.0 == want + 4, "the header is not four bytes");
            stats.accepted += 1;
        }
        Err(FrameError::TooLarge) => {
            assert!(want > MAX_FRAME, "refused, though {want} bytes");
            stats.refused += 1;
        }
        Err(_) => panic!("a frame error other than too_large"),
    }
    stats.checked += 1;
}

/// `s` with its first file's contents and path grown to an answer of
/// exactly `MAX_FRAME` bytes to request `id`, by the grammar.
fn budget_at(id: u64, s: &Shape) -> Shape {
    let mut s = s.clone();
    s.files[0].bytes = 0;
    let space = MAX_FRAME.checked_sub(expected(id, &s)).unwrap();
    s.files[0].bytes = 3 * (space / 4);
    s.files[0].path.extend(std::iter::repeat_n('x', space % 4));
    assert!(expected(id, &s) == MAX_FRAME);
    s
}

fn text(codes: &[u32]) -> String {
    codes.iter().map(|&c| char::from_u32(c).unwrap()).collect()
}

#[test]
fn a_restores_frame_is_what_an_independent_count_says() {
    let plain = text(&[47, 116, 109, 112, 47, 102]);
    let escaped = text(&[
        47, 116, 109, 112, 47, 34, 92, 8, 9, 10, 12, 13, 0, 1, 31, 127,
    ]);
    let unicode = text(&[47, 116, 109, 112, 47, 0xE9, 0x2028, 0x2029, 0x1F642]);
    let digest: String = std::iter::repeat_n('a', 64).collect();
    let terminal = Some(FileBackupCreatorView {
        kind: "terminal".into(),
        agent: None,
    });
    let agent = Some(FileBackupCreatorView {
        kind: "agent".into(),
        agent: Some(escaped.clone() + &unicode),
    });
    let meta = |path: String, left, mode| Meta {
        path,
        left,
        mode,
        bytes: 0,
    };
    let shapes = [
        Shape {
            creator: terminal.clone(),
            files: vec![meta(plain.clone(), Some(FileLeft::Removed), 384)],
        },
        Shape {
            creator: agent,
            files: vec![meta(
                escaped,
                Some(FileLeft::Rewritten(digest.clone())),
                u32::MAX,
            )],
        },
        Shape {
            creator: terminal.clone(),
            files: vec![meta(unicode, Some(FileLeft::Rewritten(digest)), 0)],
        },
        Shape {
            creator: None,
            files: vec![meta(plain.clone(), None, 384)],
        },
        Shape {
            creator: terminal,
            files: vec![
                meta(plain.clone(), Some(FileLeft::Removed), 384),
                Meta {
                    path: plain.clone(),
                    mode: 493,
                    left: None,
                    bytes: 5,
                },
            ],
        },
        Shape {
            creator: Some(FileBackupCreatorView {
                kind: "unknown".into(),
                agent: None,
            }),
            files: vec![meta(plain, None, 384)],
        },
    ];
    let mut stats = Stats::default();
    for id in [0, 9, 10, u64::MAX] {
        verify(
            id,
            &Shape {
                creator: None,
                files: vec![],
            },
            &mut stats,
        );
    }
    for shape in &shapes {
        for n in 0..=4 {
            let mut small = shape.clone();
            small.files[0].bytes = n;
            for id in [0, u64::MAX] {
                verify(id, &small, &mut stats);
            }
        }
        let max_id = budget_at(u64::MAX, shape);
        verify(u64::MAX, &max_id, &mut stats);
        // The positive controls: a count four bytes short is caught, and
        // so is one that leaves JSON's escapes out, for every shape whose
        // strings have one.
        let frame = proto::result_frame(u64::MAX, &answer(&max_id)).unwrap();
        assert!(frame.len() != expected(u64::MAX, &max_id) - 4);
        stats.wrong_count_caught += 1;
        let small = proto::result_frame(0, &answer(shape)).unwrap();
        if expected_with(0, shape, unescaped) != expected(0, shape) {
            assert!(small.len() != expected_with(0, shape, unescaped));
            stats.escapes_caught += 1;
        }
        let mut extra_metadata = max_id.clone();
        extra_metadata.files[0].path.push('x');
        assert!(expected(u64::MAX, &extra_metadata) == MAX_FRAME + 1);
        verify(u64::MAX, &extra_metadata, &mut stats);
        let mut extra_content = max_id.clone();
        extra_content.files[0].bytes += 1;
        assert!(expected(u64::MAX, &extra_content) == MAX_FRAME + 4);
        verify(u64::MAX, &extra_content, &mut stats);
        assert!(expected(0, &max_id) == MAX_FRAME - 19);
        verify(0, &max_id, &mut stats);
        let short_id = budget_at(0, shape);
        verify(0, &short_id, &mut stats);
        assert!(expected(u64::MAX, &short_id) == MAX_FRAME + 19);
        verify(u64::MAX, &short_id, &mut stats);
    }
    assert_eq!(
        (stats.checked, stats.accepted, stats.refused),
        (100, 82, 18)
    );
    assert_eq!(stats.wrong_count_caught, 6);
    assert_eq!(stats.escapes_caught, 1, "the shape with escapes");
}
