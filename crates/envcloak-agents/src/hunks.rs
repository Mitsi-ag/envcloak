//! What one change of a file inserted, kept so the change can be undone
//! exactly without keeping any of the file's own text (M2 plan M2-08;
//! lesson L-12): EnvCloak's state file sits outside the vault and its
//! sealed backups, and an agent's config can hold a literal key between
//! two places EnvCloak edits (an `env` block in Claude Code's
//! `settings.json`, `[mcp_servers.<name>.env]` in Codex's `config.toml`).
//!
//! A change is read as the runs of text it inserted ([`Hunk`]): where each
//! starts in the new text and how long it is, plus the white space it took
//! the place of, if any (an empty JSON container's inside). Nothing else of
//! either text is kept: the inserted text itself is EnvCloak's and is found
//! again in the file, whose SHA-256 the writer checks before an undo and
//! after it. A change that replaced anything but white space (a TOML value
//! set over another, an older block rewritten) has no hunks
//! ([`hunks`] gives `None`) and is undone by structure instead.
//!
//! The runs are found line by line (Myers's shortest edit script over
//! whole lines, so a line of the person's is only ever matched whole,
//! never character by character), each run of changed lines then trimmed
//! of what it shares at its start and end with the lines it replaced.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The most line edits one change may take and still be undone exactly.
pub const MAX_EDITS: usize = 512;
/// The most runs one change may hold.
pub const MAX_HUNKS: usize = 1024;

/// One run of inserted text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hunk {
    /// Where it starts in the text after the change, in bytes.
    pub at: usize,
    /// How many bytes were inserted.
    pub len: usize,
    /// The white space it took the place of (ASCII blanks and line
    /// breaks only, often empty).
    pub ws: String,
}

fn is_ws(b: &[u8]) -> bool {
    b.iter().all(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
}

fn lines(t: &[u8]) -> Vec<&[u8]> {
    t.split_inclusive(|&b| b == b'\n').collect()
}

/// The pairs of equal lines a shortest edit script keeps, in order, or
/// `None` past [`MAX_EDITS`] edits (Myers 1986, "An O(ND) difference
/// algorithm and its variations").
fn matched(a: &[usize], b: &[usize]) -> Option<Vec<(usize, usize)>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (a.len() + b.len()).min(MAX_EDITS) as isize;
    // Diagonal k = x - y is kept at k + off.
    let off = max + 1;
    let at = |k: isize| (k + off) as usize;
    let mut v = vec![0isize; (2 * max + 3) as usize];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    for d in 0..=max {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) {
                v[at(k + 1)]
            } else {
                v[at(k - 1)] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at(k)] = x;
            if x >= n && y >= m {
                return Some(backtrack(&trace, n, m, off));
            }
            k += 2;
        }
    }
    None
}

/// The matched pairs of the edit script whose steps `trace` holds (the
/// furthest points before each step), from the end back to the start.
fn backtrack(trace: &[Vec<isize>], n: isize, m: isize, off: isize) -> Vec<(usize, usize)> {
    let at = |k: isize| (k + off) as usize;
    let mut out = Vec::new();
    let (mut x, mut y) = (n, m);
    for (d, v) in trace.iter().enumerate().rev() {
        let d = d as isize;
        let k = x - y;
        // Where this step's edit started (px, py) and where its snake of
        // equal lines did (sx, sy): one line down for an insertion, one
        // across for a deletion.
        let (px, py, sx, sy) = if d == 0 {
            (0, 0, 0, 0)
        } else {
            let prev_k = if k == -d || (k != d && v[at(k - 1)] < v[at(k + 1)]) {
                k + 1
            } else {
                k - 1
            };
            let px = v[at(prev_k)];
            let py = px - prev_k;
            if prev_k == k + 1 {
                (px, py, px, py + 1)
            } else {
                (px, py, px + 1, py)
            }
        };
        while x > sx && y > sy {
            out.push(((x - 1) as usize, (y - 1) as usize));
            x -= 1;
            y -= 1;
        }
        x = px;
        y = py;
    }
    out.reverse();
    out
}

/// The runs `after` inserted into `before`, or `None` when it replaced
/// text other than white space, or took more than [`MAX_EDITS`] line
/// edits or [`MAX_HUNKS`] runs.
pub fn hunks(before: &[u8], after: &[u8]) -> Option<Vec<Hunk>> {
    // Whole lines alike at both ends need no edit script.
    let (la, lb) = (lines(before), lines(after));
    let pre = la.iter().zip(&lb).take_while(|(x, y)| x == y).count();
    let suf = la[pre..]
        .iter()
        .rev()
        .zip(lb[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (&la[pre..la.len() - suf], &lb[pre..lb.len() - suf]);
    // Each distinct line as a number, so lines compare whole and fast.
    let mut ids: HashMap<&[u8], usize> = HashMap::new();
    let a: Vec<usize> = ma
        .iter()
        .map(|&l| {
            let next = ids.len();
            *ids.entry(l).or_insert(next)
        })
        .collect();
    let b: Vec<usize> = mb
        .iter()
        .map(|&l| {
            let next = ids.len();
            *ids.entry(l).or_insert(next)
        })
        .collect();
    let pairs = matched(&a, &b)?;
    let base: usize = lb[..pre].iter().map(|l| l.len()).sum();
    let mut out = Vec::new();
    let (mut i, mut j, mut at) = (0usize, 0usize, base);
    let mut push = |old: &[&[u8]], new: &[&[u8]], at: usize| -> Option<()> {
        if old.is_empty() && new.is_empty() {
            return Some(());
        }
        let old: Vec<u8> = old.concat();
        let new: Vec<u8> = new.concat();
        let p = old.iter().zip(&new).take_while(|(x, y)| x == y).count();
        let s = old[p..]
            .iter()
            .rev()
            .zip(new[p..].iter().rev())
            .take_while(|(x, y)| x == y)
            .count();
        let (o, w) = (&old[p..old.len() - s], &new[p..new.len() - s]);
        if !is_ws(o) {
            return None;
        }
        if o.is_empty() && w.is_empty() {
            return Some(());
        }
        out.push(Hunk {
            at: at + p,
            len: w.len(),
            ws: String::from_utf8(o.to_vec()).ok()?,
        });
        (out.len() <= MAX_HUNKS).then_some(())
    };
    for (pi, pj) in pairs
        .iter()
        .copied()
        .chain(std::iter::once((a.len(), b.len())))
    {
        push(&ma[i..pi], &mb[j..pj], at)?;
        at += mb[j..pj].iter().map(|l| l.len()).sum::<usize>();
        if pj < b.len() {
            at += mb[pj].len();
        }
        i = pi + 1;
        j = pj + 1;
    }
    Some(out)
}

/// `after` with `hunks` taken out again: the text before the change, when
/// `after` is the text the hunks were found in.
pub fn unapply(after: &[u8], hunks: &[Hunk]) -> Option<Vec<u8>> {
    let mut out = after.to_vec();
    let mut limit = out.len();
    for h in hunks.iter().rev() {
        let end = h.at.checked_add(h.len)?;
        if end > limit || !is_ws(h.ws.as_bytes()) {
            return None;
        }
        out.splice(h.at..end, h.ws.bytes());
        limit = h.at;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(before: &str, after: &str) -> Option<Vec<Hunk>> {
        let h = hunks(before.as_bytes(), after.as_bytes())?;
        assert_eq!(
            unapply(after.as_bytes(), &h).as_deref(),
            Some(before.as_bytes()),
            "{before:?} -> {after:?}: {h:?}"
        );
        Some(h)
    }

    #[test]
    fn insertions_anywhere_undo_exactly() {
        for (before, after) in [
            ("", "abc\n"),
            ("a\n", "a\nb\n"),
            ("a\nc\n", "a\nb\nc\n"),
            ("x", "x\n\ny\n"),
            (
                "{\n  \"a\": [\n    1\n  ]\n}\n",
                "{\n  \"a\": [\n    1,\n    2\n  ]\n}\n",
            ),
            ("{}", "{\"a\": [1]}"),
            ("{\n}\n", "{\n  \"a\": [\n    1\n  ]\n}\n"),
            ("[ ]", "[1]"),
            ("a\nb\nc\nd\n", "a\nX\nb\nc\nY\nd\nZ\n"),
            ("same\nsame\n", "same\nsame\nsame\n"),
        ] {
            assert!(round(before, after).is_some(), "{before:?} -> {after:?}");
        }
    }

    #[test]
    fn replaced_text_that_is_not_white_space_has_no_hunks() {
        assert_eq!(hunks(b"a = false\n", b"a = true\n"), None);
        assert_eq!(hunks(b"old\n", b""), None);
        assert_eq!(hunks(b"one line", b"another"), None);
    }

    /// The point of this module: two edits on either side of the person's
    /// own text keep none of it, only where EnvCloak's text went.
    #[test]
    fn text_between_two_edits_is_never_kept() {
        let secret = "s3cr3t-value-made-for-this-test";
        let before = format!(
            "{{\n  \"permissions\": {{\n    \"deny\": [\n      \"A\"\n    ]\n  }},\n  \"env\": \
             {{\n    \"K\": \"{secret}\"\n  }}\n}}\n"
        );
        let after = format!(
            "{{\n  \"permissions\": {{\n    \"deny\": [\n      \"A\",\n      \"B\"\n    ]\n  \
             }},\n  \"env\": {{\n    \"K\": \"{secret}\"\n  }},\n  \"hooks\": {{}}\n}}\n"
        );
        let h = round(&before, &after).unwrap_or_default();
        assert_eq!(h.len(), 2, "{h:?}");
        let kept = serde_json::to_string(&h).unwrap_or_default();
        assert!(!kept.contains(secret), "{kept}");
        assert!(h.iter().all(|x| x.ws.is_empty()), "{h:?}");
    }

    #[test]
    fn too_many_edits_is_none_and_hostile_hunks_do_not_apply() {
        let before: String = (0..2000).map(|i| format!("{i}\n")).collect();
        let after: String = (0..2000).map(|i| format!("x{i}\n")).collect();
        assert_eq!(hunks(before.as_bytes(), after.as_bytes()), None);
        let h = [Hunk {
            at: 3,
            len: 10,
            ws: String::new(),
        }];
        assert_eq!(unapply(b"abc", &h), None);
        let h = [Hunk {
            at: 0,
            len: 1,
            ws: "x".to_owned(),
        }];
        assert_eq!(unapply(b"abc", &h), None);
        let overlap = [
            Hunk {
                at: 0,
                len: 2,
                ws: String::new(),
            },
            Hunk {
                at: 1,
                len: 1,
                ws: String::new(),
            },
        ];
        assert_eq!(unapply(b"abc", &overlap), None);
    }
}
