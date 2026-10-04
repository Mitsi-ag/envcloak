//! What a search glob may pick out (M2 plan M2-08; the verifier's and
//! Codex's reviews of the Grep glob): ripgrep's `--glob` and `--iglob`,
//! Claude Code's `Grep` `glob` (which Claude Code 2.1.280 splits before
//! it hands each piece to ripgrep, [`grep_tool_glob_may_name_env_file`]),
//! grep's `--include` and find's `-name` and `-path` patterns.
//!
//! A glob is read in its own language, not as text: `*` and `?` (which
//! match a leading `.` in these tools), character classes as the sets
//! they are (`[.]e[n]v` is `.env`), ranges and negation, `\` escapes, and
//! brace alternatives (the shell reader's expansion). Its last component
//! (the file name it matches) is then checked against the names of env
//! files, as `envcloak_scan::dotenv_kind` reads them, in any case: `.env`
//! and `.env.<suffix>`, unless a dot-separated part of the suffix is a
//! template's (`example`, `sample`, `template`, `dist`). That language is
//! an automaton here ([`Names`]), and a glob may pick out an env file
//! when:
//!
//! - it has no wildcard (`*` or `?`) and one of the names it stands for is
//!   an env file's (`.env.local`, `[.]e[n]v`);
//! - it starts with literals or classes, and what they spell can begin an
//!   env file's name (`.env*`, `.e?v`, `.[e]nv.*`, `.*`, `.E*`);
//! - it starts with a wildcard, the letters `e`, `n` and `v` appear in
//!   that order among its literals and classes, and an env file's name
//!   matches it (`*.env`, `*env*`, `*[e]nv`).
//!
//! A glob that starts with a wildcard and never spells `e`, `n`, `v` (`*`,
//! `*.rs`, `**/*.py`, which `.env.rs` or `.env.py` would match) is read as
//! a search of every file: docs/INSTALLERS.md lists it with the recursive
//! searches the hook does not see. An exclusion (`!...`) picks nothing
//! out. A glob past the bounds read ([`MAX_TOKENS`], or too many brace
//! alternatives) is taken as one that may.
//!
//! Where the last component starts is found in the glob's own grammar too
//! ([`Slash`], the verifier's F119 follow-up): a `/` inside a character
//! class is one of its members, not a separator, so `[/.]env*` is read
//! whole; and since a class that holds `/` (or a negated one that does
//! not leave it out) can match the separator itself in ripgrep
//! (`sub[/].env` and `sub[!a].env` pick out `sub/.env`, measured with
//! ripgrep 15.1.0), each such class is read both ways: as a member, and
//! as the separator before the last component. find's `-path` matches a
//! `/` with `*` and `?` too, so there each wildcard may end a component
//! as well; a stretch only known when the command runs may hold one
//! anywhere. A glob may pick out an env file when any of those readings'
//! last component may.

use std::collections::HashSet;

use envcloak_scan::TEMPLATE_SUFFIXES;
use zeroize::Zeroizing;

use super::{BraceCost, Ch, Word, brace_expand};

/// The most pieces of one glob's last component read; past it, the glob
/// may pick out an env file.
const MAX_TOKENS: usize = 4096;

/// The most places one glob's last component may start at (a `/`, a
/// class that may match one, or a wildcard that may in find's `-path`);
/// past it, the glob may pick out an env file.
const MAX_STARTS: usize = 64;

/// How a tool's glob matches the `/` between a path's components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Slash {
    /// ripgrep's globs (`--glob`, `--iglob`, and Claude Code's `Grep`),
    /// grep's `--include` and find's `-name`: `*` and `?` never match a
    /// `/` (measured with ripgrep 15.1.0: `su*.env` and `sub?.env` pick out
    /// no `sub/.env`), while a character class that holds one (`[/]`,
    /// `[.-0]`), or a negated one that does not leave it out (`[!a]`), may.
    Classes,
    /// find's `-path` and `-wholename`, which match the whole path as
    /// `fnmatch` does without `FNM_PATHNAME`: `*`, `?` and classes all
    /// match a `/` (measured with macOS's find: `./su*env` and `./sub?.env`
    /// pick out `./sub/.env`; GNU find documents the same).
    Any,
}

/// A set of bytes.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Bytes([u64; 4]);

impl Bytes {
    fn add(&mut self, b: u8) {
        self.0[usize::from(b >> 6)] |= 1 << (b & 63);
    }

    fn has(&self, b: u8) -> bool {
        self.0[usize::from(b >> 6)] & (1 << (b & 63)) != 0
    }

    /// Every byte a name can hold, in one case: all but `/` and NUL, an
    /// upper-case letter read as its lower case.
    fn any() -> Self {
        let mut s = Bytes::default();
        for b in 1..=255u8 {
            if b != b'/' {
                s.add(b.to_ascii_lowercase());
            }
        }
        s
    }

    fn iter(self) -> impl Iterator<Item = u8> {
        (0..=255u8).filter(move |b| self.has(*b))
    }
}

/// One piece of a glob's last component, in one case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    /// One byte of the set: a literal, or a class.
    Set(Bytes),
    /// `?`: any one byte.
    One,
    /// `*` (or `**`), or a stretch only known when the command runs: any
    /// run of bytes.
    Run,
}

impl zeroize::Zeroize for Tok {
    fn zeroize(&mut self) {
        // A literal's set spells a byte of the command's text: wiped with
        // the rest of it.
        *self = Tok::Run;
    }
}

/// A glob's last component as pieces: `None` past [`MAX_TOKENS`]. `pat`
/// holds its bytes, `None` for a stretch only known when the command
/// runs.
fn tokens(pat: &[Option<u8>]) -> Option<Zeroizing<Vec<Tok>>> {
    let mut out: Zeroizing<Vec<Tok>> = Zeroizing::new(Vec::new());
    let push_run = |out: &mut Vec<Tok>| {
        if out.last() != Some(&Tok::Run) {
            out.push(Tok::Run);
        }
    };
    let one = |b: u8| {
        let mut s = Bytes::default();
        s.add(b.to_ascii_lowercase());
        Tok::Set(s)
    };
    let mut i = 0;
    while i < pat.len() {
        if out.len() > MAX_TOKENS {
            return None;
        }
        match pat[i] {
            None | Some(b'*') => {
                push_run(&mut out);
                i += 1;
            }
            Some(b'?') => {
                out.push(Tok::One);
                i += 1;
            }
            Some(b'\\') if matches!(pat.get(i + 1), Some(Some(_))) => {
                if let Some(Some(b)) = pat.get(i + 1) {
                    out.push(one(*b));
                }
                i += 2;
            }
            Some(b'[') => match class(&pat[i + 1..]) {
                Some((t, used)) => {
                    out.push(t);
                    i += 1 + used;
                }
                // No closing `]`: a `[` of its own.
                None => {
                    out.push(one(b'['));
                    i += 1;
                }
            },
            Some(b) => {
                out.push(one(b));
                i += 1;
            }
        }
    }
    Some(out)
}

/// A character class after its `[`, as written: the bytes it lists (its
/// ranges spelled out), whether it is negated, whether a stretch only
/// known when the command runs is in it, and how many bytes it took, its
/// `]` included. `None` when no `]` closes it.
struct ClassParts {
    members: Bytes,
    neg: bool,
    unknown: bool,
    used: usize,
}

fn class_parts(rest: &[Option<u8>]) -> Option<ClassParts> {
    let mut k = 0;
    let neg = matches!(rest.first(), Some(Some(b'!' | b'^')));
    if neg {
        k += 1;
    }
    let start = k;
    let mut members = Bytes::default();
    let mut unknown = false;
    loop {
        match rest.get(k) {
            None => return None,
            // A `]` first in the class is one of its members.
            Some(Some(b']')) if k > start => break,
            Some(None) => {
                unknown = true;
                k += 1;
            }
            // A POSIX bracket expression inside the class (`[:alpha:]`,
            // `[=e=]`, `[.e.]`; the verifier's finding, read as text
            // before): the class is read as one that may match any byte,
            // `/` included, rather than modelled set by set. Its `]` does
            // not close the class.
            Some(Some(b'[')) if posix_end(&rest[k..]).is_some() => {
                unknown = true;
                k += posix_end(&rest[k..]).unwrap_or(1);
            }
            Some(Some(lo)) => {
                let lo = *lo;
                if let (Some(Some(b'-')), Some(Some(hi))) = (rest.get(k + 1), rest.get(k + 2)) {
                    if *hi != b']' {
                        for b in lo.min(*hi)..=lo.max(*hi) {
                            members.add(b);
                        }
                        k += 3;
                        continue;
                    }
                }
                members.add(lo);
                k += 1;
            }
        }
    }
    Some(ClassParts {
        members,
        neg,
        unknown,
        used: k + 1,
    })
}

/// The length of the POSIX bracket expression at the start of `at` inside
/// a class (`[:name:]`, `[=c=]`, `[.c.]`, up to and with its closing
/// delimiter and `]`), or `None` when `at` does not start one or it is not
/// closed.
fn posix_end(at: &[Option<u8>]) -> Option<usize> {
    let (Some(Some(b'[')), Some(Some(d @ (b':' | b'=' | b'.')))) = (at.first(), at.get(1)) else {
        return None;
    };
    (2..at.len().saturating_sub(1))
        .find(|&j| at[j] == Some(*d) && at[j + 1] == Some(b']'))
        .map(|j| j + 2)
}

impl ClassParts {
    /// Whether the class may match a `/`: it lists one (a range included),
    /// it is negated and does not, or what it holds is only known when the
    /// command runs.
    fn may_match_slash(&self) -> bool {
        self.unknown || self.members.has(b'/') != self.neg
    }
}

/// A character class after its `[`, as a piece of a last component: the
/// set of the bytes it matches there (in one case, never `/`) and how many
/// bytes it took, its `]` included; `None` when no `]` closes it. A
/// stretch only known when the command runs makes it any byte.
fn class(rest: &[Option<u8>]) -> Option<(Tok, usize)> {
    let c = class_parts(rest)?;
    if c.unknown {
        // Any byte, and still a class, which stands for a character of
        // the name (`[[=.=]]env`: the shell oracle's finding, read as a
        // wildcard it was left out of what a name spells).
        return Some((Tok::Set(Bytes::any()), c.used));
    }
    let mut set = Bytes::default();
    for b in 1..=255u8 {
        if b != b'/' && c.members.has(b) != c.neg {
            set.add(b.to_ascii_lowercase());
        }
    }
    Some((Tok::Set(set), c.used))
}

/// Where the last component of the glob `pat` (`None` for a stretch only
/// known when the command runs) may start, read in its grammar (see the
/// module documentation): after its last `/` (or `\/`), and after each
/// piece past that which may match a `/` in `slash`'s tools; at a `*` or
/// a stretch only known when the command runs, which may hold the `/`
/// and then the start of the name. `None` past [`MAX_STARTS`] places, or
/// past a bound on the bytes the classes are scanned for (a glob of many
/// unclosed `[`), when the glob may pick out an env file.
fn component_starts(pat: &[Option<u8>], slash: Slash) -> Option<Vec<usize>> {
    let mut starts = vec![0];
    let mut scanned = 0usize;
    let mut i = 0;
    while i < pat.len() {
        match pat[i] {
            Some(b'/') => {
                starts.clear();
                starts.push(i + 1);
                i += 1;
            }
            Some(b'\\') if matches!(pat.get(i + 1), Some(Some(_))) => {
                if pat[i + 1] == Some(b'/') {
                    starts.clear();
                    starts.push(i + 2);
                }
                i += 2;
            }
            Some(b'[') => {
                scanned = scanned.checked_add(pat.len() - i)?;
                if scanned > MAX_TOKENS.saturating_mul(MAX_TOKENS) {
                    return None;
                }
                match class_parts(&pat[i + 1..]) {
                    Some(c) => {
                        if c.may_match_slash() {
                            starts.push(i + 1 + c.used);
                        }
                        i += 1 + c.used;
                    }
                    // No closing `]`: a `[` of its own.
                    None => i += 1,
                }
            }
            Some(b'*') if slash == Slash::Any => {
                starts.push(i);
                i += 1;
            }
            Some(b'?') if slash == Slash::Any => {
                starts.push(i + 1);
                i += 1;
            }
            None => {
                starts.push(i);
                i += 1;
            }
            Some(_) => i += 1,
        }
        if starts.len() > MAX_STARTS {
            return None;
        }
    }
    Some(starts)
}

/// The names of env files, in lower case, as an automaton: `.env`, or
/// `.env.` and a suffix none of whose dot-separated parts is a template's
/// (`envcloak_scan::dotenv_kind`, which counts a suffix it cannot read as
/// one).
struct Names {
    /// The template words as a trie: each node's children and whether a
    /// word ends there.
    trie: Vec<(Vec<(u8, usize)>, bool)>,
}

/// The automaton's fixed states; a part of the suffix being read is
/// `PART + <trie node>`.
const START: usize = 0;
const DOT: usize = 1;
const E: usize = 2;
const EN: usize = 3;
const ENV: usize = 4;
/// In a part of the suffix that is no template's word.
const OTHER: usize = 5;
/// No env file's name starts this way.
const DEAD: usize = 6;
const PART: usize = 7;

impl Names {
    fn new() -> Self {
        let mut trie: Vec<(Vec<(u8, usize)>, bool)> = vec![(Vec::new(), false)];
        for w in TEMPLATE_SUFFIXES {
            let mut node = 0;
            for &b in w.as_bytes() {
                let next = trie[node].0.iter().find(|(c, _)| *c == b).map(|(_, n)| *n);
                node = match next {
                    Some(n) => n,
                    None => {
                        trie.push((Vec::new(), false));
                        let n = trie.len() - 1;
                        trie[node].0.push((b, n));
                        n
                    }
                };
            }
            trie[node].1 = true;
        }
        Names { trie }
    }

    fn step(&self, q: usize, c: u8) -> usize {
        if c == b'/' || c == 0 {
            return DEAD;
        }
        match q {
            START if c == b'.' => DOT,
            DOT if c == b'e' => E,
            E if c == b'n' => EN,
            EN if c == b'v' => ENV,
            ENV if c == b'.' => PART,
            START | DOT | E | EN | ENV | DEAD => DEAD,
            OTHER if c == b'.' => PART,
            OTHER => OTHER,
            p => {
                let node = p - PART;
                if c == b'.' {
                    if self.trie[node].1 { DEAD } else { PART }
                } else {
                    self.trie[node]
                        .0
                        .iter()
                        .find(|(b, _)| *b == c)
                        .map_or(OTHER, |(_, n)| PART + n)
                }
            }
        }
    }

    fn accepts(&self, q: usize) -> bool {
        q == ENV || q == OTHER || (q >= PART && !self.trie[q - PART].1)
    }
}

/// Whether some env file's name matches the pieces `toks` (a search of
/// the product of the glob's positions and the automaton's states). With
/// `spelled`, only a match in which a literal or a class, not a wildcard,
/// stands for one of the bytes of `.env` itself counts (see
/// [`component_may`]).
fn matches_a_name(toks: &[Tok], spelled: bool) -> bool {
    let names = Names::new();
    let any = Bytes::any();
    // (position, state, a literal or class stood for a byte of `.env`).
    let mut seen: HashSet<(usize, usize, bool)> = HashSet::new();
    let mut todo: Vec<(usize, usize, bool)> = Vec::new();
    // A run matches nothing too: every position a run can be skipped to.
    let reach = |i: usize, q: usize, by: bool, seen: &mut HashSet<_>, todo: &mut Vec<_>| {
        let mut i = i;
        loop {
            if seen.insert((i, q, by)) {
                todo.push((i, q, by));
            }
            if toks.get(i) == Some(&Tok::Run) {
                i += 1;
            } else {
                break;
            }
        }
    };
    reach(0, START, !spelled, &mut seen, &mut todo);
    while let Some((i, q, by)) = todo.pop() {
        let Some(t) = toks.get(i) else {
            if by && names.accepts(q) {
                return true;
            }
            continue;
        };
        let (set, next) = match t {
            Tok::Set(s) => (*s, i + 1),
            Tok::One => (any, i + 1),
            Tok::Run => (any, i),
        };
        let mut states: Vec<usize> = set.iter().map(|b| names.step(q, b)).collect();
        states.sort_unstable();
        states.dedup();
        for q2 in states.into_iter().filter(|s| *s != DEAD) {
            // A step into `.`, `.e`, `.en` or `.env` made by a literal or a
            // class.
            let spells = matches!(t, Tok::Set(_)) && matches!(q2, DOT | E | EN | ENV) && q2 != q;
            reach(next, q2, by || spells, &mut seen, &mut todo);
        }
    }
    false
}

/// Whether one path component as a shell word (`c`: no `/` in it; a quoted
/// glob character is itself, an unquoted one a wildcard, a class read in
/// its own grammar and one holding a POSIX bracket expression read as any
/// byte, a stretch only known when the command runs any text) may be
/// `target` (in lower case), in any case.
pub(super) fn component_may_match(c: &[Ch], target: &[u8]) -> bool {
    // Plain text (no wildcard, class or escape read below, no stretch only
    // known when it runs) is compared as it is, with nothing allocated: the
    // reader asks this of every word a command is given.
    let plain = c.iter().all(|ch| match ch {
        Ch::Lit { b, quoted } => *quoted || !matches!(b, b'*' | b'?' | b'[' | b'\\'),
        Ch::Unknown => false,
    });
    if plain {
        return c.len() == target.len()
            && c.iter()
                .zip(target)
                .all(|(ch, t)| matches!(ch, Ch::Lit { b, .. } if b.to_ascii_lowercase() == *t));
    }
    let mut pat: Zeroizing<Vec<Option<u8>>> = Zeroizing::new(Vec::with_capacity(c.len() * 2));
    for ch in c {
        match ch {
            Ch::Unknown => pat.push(None),
            Ch::Lit { b, quoted: true } if matches!(b, b'*' | b'?' | b'[' | b'\\') => {
                pat.push(Some(b'\\'));
                pat.push(Some(*b));
            }
            Ch::Lit { b, .. } => pat.push(Some(*b)),
        }
    }
    let Some(toks) = tokens(&pat) else {
        return true;
    };
    // Positions of `toks` that can stand where `target`'s first `k` bytes
    // were matched, for each `k`.
    let mut at: Vec<bool> = vec![false; toks.len() + 1];
    at[0] = true;
    let close = |at: &mut Vec<bool>| {
        for i in 0..toks.len() {
            if at[i] && toks[i] == Tok::Run {
                at[i + 1] = true;
            }
        }
    };
    close(&mut at);
    for &b in target {
        let b = b.to_ascii_lowercase();
        let mut next = vec![false; toks.len() + 1];
        for i in 0..toks.len() {
            if !at[i] {
                continue;
            }
            match toks[i] {
                Tok::Run => next[i] = true,
                Tok::One => next[i + 1] = true,
                Tok::Set(set) => {
                    if set.has(b) {
                        next[i + 1] = true;
                    }
                }
            }
        }
        close(&mut next);
        at = next;
    }
    at[toks.len()]
}

/// Whether a glob's last component (`None` for a stretch only known when
/// the command runs) may pick out an env file. See the module
/// documentation. One that starts with a wildcard may when an env file's
/// name matches it with a literal or a class standing for a byte of `.env`
/// itself (`*.env`, `*env*`, `*v`, which with a `/`-crossing `*` is
/// `./s*v`'s `sub/.env`: the verifier's finding); one whose literals and
/// classes would stand only for the suffix (`*.rs` matching `.env.rs`) is
/// read as a search of every file (docs/INSTALLERS.md).
fn component_may(c: &[Option<u8>]) -> bool {
    let Some(toks) = tokens(c) else {
        return true;
    };
    match toks.iter().position(|t| matches!(t, Tok::One | Tok::Run)) {
        None => matches_a_name(&toks, false),
        Some(0) => matches_a_name(&toks, true),
        Some(k) => {
            let mut start = Zeroizing::new(toks[..k].to_vec());
            start.push(Tok::Run);
            matches_a_name(&start, false)
        }
    }
}

/// A word as a tool reads its glob: the shell's quoting is gone, so a
/// quoted `*` or `{` is the tool's to read.
fn as_tool_glob(w: &[Ch]) -> Word {
    w.iter()
        .map(|ch| match ch {
            Ch::Lit { b, .. } => Ch::Lit {
                b: *b,
                quoted: false,
            },
            Ch::Unknown => Ch::Unknown,
        })
        .collect()
}

/// Whether the glob `w` may pick out an env file: each of its brace
/// alternatives, its last component found as `slash`'s tools read it
/// (every place it may start, [`component_starts`]), `**` read as `*`.
/// With `exclusions`, a glob starting with `!` excludes, and picks out
/// nothing (ripgrep's globs; a find pattern has no such form).
pub(super) fn word_may_name_env_file(w: &[Ch], exclusions: bool, slash: Slash) -> bool {
    let w: Zeroizing<Word> = Zeroizing::new(as_tool_glob(w));
    if exclusions
        && w.first()
            == Some(&Ch::Lit {
                b: b'!',
                quoted: false,
            })
    {
        return false;
    }
    let mut cost = BraceCost::default();
    let Ok(alts) = brace_expand(&w, &mut cost, 0) else {
        return true;
    };
    let alts = Zeroizing::new(alts);
    alts.iter().any(|a| {
        let pat: Zeroizing<Vec<Option<u8>>> = Zeroizing::new(
            a.iter()
                .map(|ch| match ch {
                    Ch::Lit { b, .. } => Some(*b),
                    Ch::Unknown => None,
                })
                .collect(),
        );
        // The verifier's F119 follow-up: a `/` in a class is not cut on
        // as text, and a class that may match one is read both ways.
        let Some(starts) = component_starts(&pat, slash) else {
            return true;
        };
        starts.iter().any(|&s| component_may(&pat[s..]))
    })
}

/// Whether one search glob (ripgrep's `--glob`; Claude Code's `Grep`
/// hands each piece of its `glob` to ripgrep this way) may pick out an
/// env file. See the module documentation.
pub fn glob_may_name_env_file(glob: &str) -> bool {
    let w: Zeroizing<Word> =
        Zeroizing::new(glob.bytes().map(|b| Ch::Lit { b, quoted: false }).collect());
    word_may_name_env_file(&w, true, Slash::Classes)
}

/// Whether Claude Code's `Grep` `glob` may pick out an env file, split as
/// Claude Code 2.1.280 splits it before it runs ripgrep (its Grep tool:
/// on white space, then each piece that does not hold both `{` and `}` on
/// commas, each piece one `--glob`): any piece that may is enough.
pub fn grep_tool_glob_may_name_env_file(glob: &str) -> bool {
    glob.split(|c: char| c.is_whitespace())
        .flat_map(|piece| {
            if piece.contains('{') && piece.contains('}') {
                vec![piece]
            } else {
                piece.split(',').collect()
            }
        })
        .filter(|p| !p.is_empty())
        .any(glob_may_name_env_file)
}

/// Whether a regular expression a tool matches file names with (find's
/// `-regex`, ag's `-G`) may pick out an env file: the letters `e`, `n`
/// and `v` appear in it in that order, a class's letters counted (`[.]e[n]v`).
/// A regular expression is not read further: one that never spells them
/// (`.*\.e.v`) is in docs/INSTALLERS.md's list of what the hook does not
/// see.
pub(super) fn regex_may_name_env_file(w: &[Ch]) -> bool {
    let mut want = b"env".iter().peekable();
    for ch in w {
        if let (Ch::Lit { b, .. }, Some(&&c)) = (ch, want.peek()) {
            if b.to_ascii_lowercase() == c {
                want.next();
            }
        }
    }
    want.peek().is_none()
}

/// ripgrep's built-in file types whose globs pick out an env file
/// (ripgrep 15.1.0's `--type-list`: `sh` holds `.env` and `*.env`), and
/// `all`, every type at once. A test checks this against the installed
/// ripgrep's own list.
pub const RG_ENV_TYPES: [&str; 2] = ["all", "sh"];

/// Whether ripgrep's `--type` `t` may pick out an env file.
pub(super) fn rg_type_may_name_env_file(t: &[Ch]) -> bool {
    let Some(name) = super::literal(t) else {
        // A type only known when the command runs: a runtime value.
        return false;
    };
    let name = Zeroizing::new(name.to_ascii_lowercase());
    RG_ENV_TYPES.iter().any(|k| k.as_bytes() == name.as_slice())
}

/// Whether a `--type-add` definition (`NAME:GLOB[,GLOB...]`, or
/// `NAME:include:TYPE[,TYPE...]`) gives a type a glob that may pick out
/// an env file, its own or an included type's.
pub(super) fn rg_type_add_may_name_env_file(def: &[Ch]) -> bool {
    let colon = |ch: &Ch| matches!(ch, Ch::Lit { b: b':', .. });
    let Some(p) = def.iter().position(colon) else {
        return false;
    };
    let globs = &def[p + 1..];
    let comma = |ch: &Ch| matches!(ch, Ch::Lit { b: b',', .. });
    let others: Vec<Ch> = b"include:"
        .iter()
        .map(|&b| Ch::Lit { b, quoted: false })
        .collect();
    let unquoted = as_tool_glob(globs);
    if let Some(types) = unquoted.strip_prefix(others.as_slice()) {
        return types.split(comma).any(rg_type_may_name_env_file);
    }
    globs
        .split(comma)
        .any(|g| word_may_name_env_file(g, true, Slash::Classes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_automaton_reads_names_as_dotenv_kind_does() {
        let lit = |s: &str| -> Vec<Tok> {
            s.bytes()
                .map(|b| {
                    let mut x = Bytes::default();
                    x.add(b.to_ascii_lowercase());
                    Tok::Set(x)
                })
                .collect()
        };
        for name in [
            ".env",
            ".env.local",
            ".ENV.Staging",
            ".env.",
            ".env.x..y",
            ".env.examples",
            ".env.local.prod",
        ] {
            assert!(matches_a_name(&lit(name), false), "{name}");
            assert!(
                super::super::names_dotenv(name.as_bytes()),
                "{name}: dotenv_kind disagrees"
            );
        }
        for name in [
            ".env.example",
            ".env.local.sample",
            ".env.Template",
            ".env.dist.x",
            ".envrc",
            "env",
            "x.env",
            ".env/x",
        ] {
            assert!(!matches_a_name(&lit(name), false), "{name}");
            assert!(
                !super::super::names_dotenv(name.as_bytes()),
                "{name}: dotenv_kind disagrees"
            );
        }
    }

    /// The verifier's finding (F119): a glob's character classes are
    /// sets, and Claude Code splits a Grep glob on white space and commas.
    ///
    /// Mutations checked: classes read as text (the previous
    /// `glob_may_name_env_file`), and the glob judged whole (no split):
    /// each fails this.
    #[test]
    fn classes_are_sets_and_the_grep_glob_is_split_as_the_host_splits_it() {
        for g in [
            "[.]e[n]v",
            "[.]e[n]v*",
            "[.][e][n][v].[l]ocal",
            "**/[.]env.q0",
            "{*.rs,[.][e][n][v].q1}",
            ".[a-z]nv",
            "[!a-z]env",
            "*[e]nv",
            "\\.env",
        ] {
            assert!(glob_may_name_env_file(g), "{g}");
        }
        for g in [
            ".env.local src/*.rs",
            "README.md,.env",
            ".env,config/app.yaml",
            ".env* src/**",
            ".env x",
            "a.rs\t.env.ci",
        ] {
            assert!(!glob_may_name_env_file(g), "{g}");
            assert!(grep_tool_glob_may_name_env_file(g), "{g}");
        }
        for g in [
            "[u]nit0.rs",
            "*.rs",
            "*.{ts,tsx}",
            "src/**",
            "*",
            "**/*.py",
            ".env.example",
            "[.]env.example",
            "!.env*",
            "*.[jt]s",
            "[A-Z]*.md",
            ".git*",
            "*inventory*.json",
        ] {
            assert!(!glob_may_name_env_file(g), "{g}");
            assert!(!grep_tool_glob_may_name_env_file(g), "{g}");
        }
        // A piece with both braces is one glob: its commas are its own.
        assert!(grep_tool_glob_may_name_env_file("{a,.env}"));
        assert!(!grep_tool_glob_may_name_env_file("{a,b}.rs"));
    }

    /// The verifier's F119 follow-up (and Codex's cycles 326 and 327): the
    /// last component was cut at the last `/` byte, so a `/` inside a
    /// class dropped the name after it (`[/.]env*` allowed while ripgrep
    /// picks out `.env.local` with it). A class is read in the glob's
    /// grammar: as a member, and, when it may match a `/` (it holds one,
    /// or is negated and does not leave it out), as the separator too, so
    /// `sub[/].env` is `sub/.env`. find's `-path` matches a `/` with `*`
    /// and `?` as well. ripgrep's answers for the same globs are in
    /// `tests/grep_glob_oracle.rs`.
    ///
    /// Mutations checked: the last component taken at the raw last `/`
    /// (the previous `rposition` split): the class cases are allowed and
    /// this fails; find's `-path` read with [`Slash::Classes`]: `x*env`
    /// and `./sub?.env` are allowed and this fails.
    #[test]
    fn a_slash_is_found_by_the_globs_own_grammar() {
        for g in [
            // Codex's six.
            "[/.]env*",
            "[.-/]env*",
            "[./]e[n]v*",
            "[/.][e][n][v]*",
            "[/\\.]env*",
            "[.\\/]env*",
            // A class that may match the separator, read as one.
            "**[/].env",
            "sub[/].env",
            "sub[!a].env",
            "sub[^a].env",
            "sub[.-0].env.local",
            "sub\\/.env",
            "{x.rs,sub[/].env}",
        ] {
            assert!(glob_may_name_env_file(g), "{g}");
            assert!(grep_tool_glob_may_name_env_file(g), "{g}");
        }
        for g in [
            "src/[a-c]*.rs",
            "src/[a-c]/main.rs",
            "src/.env.example",
            "sub[/]x.rs",
            "sub[/].env.example",
            "x[/]",
            "[!.]nv",
            "!sub[/].env",
        ] {
            assert!(!glob_may_name_env_file(g), "{g}");
            assert!(!grep_tool_glob_may_name_env_file(g), "{g}");
        }
        // Past the bounds read: one that may.
        assert!(glob_may_name_env_file(&"[".repeat(MAX_TOKENS * 2)));
        assert!(glob_may_name_env_file(&format!(
            "{}x.rs",
            "[/]".repeat(MAX_STARTS + 1)
        )));
        // find's `-path`: `*` and `?` match a `/` there; `-name`'s do not.
        let w = |s: &str| super::super::lits(s.as_bytes());
        for g in ["x*env", "./sub?.env", "./s*env.local", "./su*[e]nv"] {
            assert!(word_may_name_env_file(&w(g), false, Slash::Any), "{g}");
            assert!(!word_may_name_env_file(&w(g), false, Slash::Classes), "{g}");
        }
        for g in ["./src/*.rs", "*", "./node_modules/*", "x?y/*.md"] {
            assert!(!word_may_name_env_file(&w(g), false, Slash::Any), "{g}");
        }
    }
}
