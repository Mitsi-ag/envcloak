//! Whether a `.gitignore` keeps a file of its own directory out of git,
//! for `envcloak init` and `envcloak import` (SPEC §6.4): they add a line
//! for each plaintext env file the `.gitignore` does not already ignore.
//!
//! Git reads the lines in order, and the last line whose pattern matches
//! a path decides: a `!` line takes the path back in. So a file counts as
//! ignored here only when the last line that matches it, or may match it,
//! is a pattern that surely matches it and has no `!`. Lines are read as
//! git reads them (gitignore(5)): `#` starts a comment, trailing blanks go
//! unless escaped with `\`, a pattern ending in `/` names only
//! directories, a pattern with another `/` is relative to the
//! `.gitignore`'s directory (`**/` matches no directory too), and one
//! without matches the name at any depth; `*`, `?`, `[...]` and `\` are
//! wildcards and escapes.
//!
//! Every doubt adds a line, which only makes a duplicate: a `!` line is
//! read without regard to case, as git reads it with `core.ignoreCase`
//! (macOS), and a pattern with and without `!` whose wildcards are not
//! understood here (`[[:alpha:]]`) counts as keeping the file in git. Only
//! this `.gitignore` is read: a line appended to it comes after every line
//! of it and overrides those of the directories above, so what it says of
//! a file here is what git decides, whatever the others say.

/// Whether the lines of `text`, a `.gitignore`, surely ignore the file
/// `name` in the `.gitignore`'s own directory. See the module
/// documentation.
pub fn ignores(text: &str, name: &str) -> bool {
    let name: Vec<Pos> = name.bytes().map(Pos::Byte).collect();
    ignores_every(text, &name)
}

/// One byte of a name, or one of a run of bytes a name may have anything
/// in: a lowercase hex digit, as in the random part of a temporary name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pos {
    Byte(u8),
    Hex,
}

/// The sixteen bytes a [`Pos::Hex`] may be.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The name `prefix`, then `hex` lowercase hex digits of any value, then
/// `suffix`: every name of that shape at once, for [`ignores_every`].
pub fn shape(prefix: &str, hex: usize, suffix: &str) -> Vec<Pos> {
    let mut out: Vec<Pos> = prefix.bytes().map(Pos::Byte).collect();
    out.extend(std::iter::repeat_n(Pos::Hex, hex));
    out.extend(suffix.bytes().map(Pos::Byte));
    out
}

/// Whether the lines of `text` surely ignore every file whose name has
/// the shape `name` ([`shape`]), whatever its hex digits are: the last
/// line that matches, or may match, any of them must be a pattern that
/// surely matches all of them, and has no `!`. A line that matches some
/// of them and not others (`*f.tmp`, a sample's digits written out) is a
/// doubt, and so is a `!` line that may match any one. See the module
/// documentation.
pub fn ignores_every(text: &str, name: &[Pos]) -> bool {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    text.lines().rev().find_map(|l| verdict(l, name)) == Some(true)
}

/// What one line says of the names of the shape `name`: `None` when it
/// surely matches none of them, `Some(true)` when it surely ignores every
/// one, and `Some(false)` when it may take one back in, may match some and
/// not others, or may match and was not understood.
fn verdict(line: &str, name: &[Pos]) -> Option<bool> {
    let (negated, pattern) = pattern_of(line)?;
    let Some(t) = tokens(pattern.as_bytes()) else {
        return Some(false);
    };
    if negated {
        return glob_tokens(&t, name, true, Mode::Any).then_some(false);
    }
    if glob_tokens(&t, name, false, Mode::Every) {
        Some(true)
    } else {
        glob_tokens(&t, name, false, Mode::Any).then_some(false)
    }
}

/// A line's pattern, as it applies to a file directly in the
/// `.gitignore`'s directory, and whether it has `!`. `None` for a blank
/// line, a comment, and a pattern that names only directories or needs
/// one in the path.
fn pattern_of(line: &str) -> Option<(bool, &str)> {
    let line = trim_trailing_blanks(line);
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (negated, pattern) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    if pattern.is_empty() || ends_with_unescaped_slash(pattern) {
        return None;
    }
    if !pattern.contains('/') {
        return Some((negated, pattern));
    }
    // Relative to this directory: `**/` also matches no directory at all.
    let mut rest = pattern.strip_prefix('/').unwrap_or(pattern);
    while let Some(r) = rest.strip_prefix("**/") {
        rest = r;
    }
    if rest.contains('/') {
        return None;
    }
    Some((negated, rest))
}

/// `line` without its trailing blanks, which git drops unless the last
/// one is escaped with `\`.
fn trim_trailing_blanks(line: &str) -> &str {
    let b = line.as_bytes();
    let mut end = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            i += 2;
            end = i;
        } else {
            i += 1;
            if b[i - 1] != b' ' {
                end = i;
            }
        }
    }
    &line[..end]
}

/// Whether `p` ends with a `/` that is not escaped.
fn ends_with_unescaped_slash(p: &str) -> bool {
    let b = p.as_bytes();
    if b.last() != Some(&b'/') {
        return false;
    }
    let escapes = b[..b.len() - 1]
        .iter()
        .rev()
        .take_while(|&&c| c == b'\\')
        .count();
    escapes % 2 == 0
}

/// Whether the wildcard pattern `p` matches all of `s`, one path component
/// (no `/`): `Some(true)` or `Some(false)`, or `None` when `p` holds what
/// is not understood here. `fold` compares ASCII letters without regard to
/// case.
#[cfg(test)]
fn glob(p: &[u8], s: &[u8], fold: bool) -> Option<bool> {
    let s: Vec<Pos> = s.iter().copied().map(Pos::Byte).collect();
    Some(glob_tokens(&tokens(p)?, &s, fold, Mode::Every))
}

/// How [`glob_tokens`] reads a [`Pos::Hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Whether the pattern matches some name of the shape: a token
    /// matches a hex position when it matches one of its digits.
    Any,
    /// Whether the pattern surely matches every name of the shape: a token
    /// matches a hex position only when it matches all its digits. Surely,
    /// not exactly: a pattern that matches all of them only in ways this
    /// cannot see (none a `.gitignore` has any reason to hold) is a doubt.
    Every,
}

/// Whether the tokens `t` match all of the name `s`, in `mode`. Each
/// position of a shape is chosen on its own, so a pattern matches some
/// name exactly when it lines up with the shape with every token meeting
/// a digit it matches. Linear in `s` for each `*`, so no pattern a
/// repository ships makes a scan slow.
fn glob_tokens(t: &[Token], s: &[Pos], fold: bool, mode: Mode) -> bool {
    let (mut ti, mut si) = (0, 0);
    // Where to go on from after the last `*`, and how much it took.
    let mut back: Option<(usize, usize)> = None;
    while si < s.len() {
        match t.get(ti) {
            Some(Token::Star) => {
                back = Some((ti + 1, si));
                ti += 1;
                continue;
            }
            Some(one) if one.matches_at(s[si], fold, mode) => {
                ti += 1;
                si += 1;
                continue;
            }
            _ => {}
        }
        let Some((bt, bs)) = back else {
            return false;
        };
        back = Some((bt, bs + 1));
        ti = bt;
        si = bs + 1;
    }
    t[ti..].iter().all(|x| matches!(x, Token::Star))
}

/// One part of a wildcard pattern.
enum Token {
    /// `*` (or `**`): any run of characters.
    Star,
    /// `?`: any one character.
    One,
    /// `[...]`.
    Set(Class),
    /// A character, maybe escaped with `\`.
    Lit(u8),
}

impl Token {
    fn matches(&self, c: u8, fold: bool) -> bool {
        match self {
            Token::Star | Token::One => true,
            Token::Set(set) => set.contains(c, fold),
            Token::Lit(l) if fold => l.eq_ignore_ascii_case(&c),
            Token::Lit(l) => *l == c,
        }
    }

    fn matches_at(&self, at: Pos, fold: bool, mode: Mode) -> bool {
        match (at, mode) {
            (Pos::Byte(c), _) => self.matches(c, fold),
            (Pos::Hex, Mode::Any) => HEX.iter().any(|&c| self.matches(c, fold)),
            (Pos::Hex, Mode::Every) => HEX.iter().all(|&c| self.matches(c, fold)),
        }
    }
}

/// `p` as tokens; `None` when it holds what is not understood here (a
/// bracket expression with a character class or no end, a trailing `\`).
fn tokens(p: &[u8]) -> Option<Vec<Token>> {
    let mut out = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            b'*' => {
                if !matches!(out.last(), Some(Token::Star)) {
                    out.push(Token::Star);
                }
                i += 1;
            }
            b'?' => {
                out.push(Token::One);
                i += 1;
            }
            b'[' => {
                let (set, len) = class(&p[i + 1..])?;
                out.push(Token::Set(set));
                i += 1 + len;
            }
            b'\\' => {
                out.push(Token::Lit(*p.get(i + 1)?));
                i += 2;
            }
            c => {
                out.push(Token::Lit(c));
                i += 1;
            }
        }
    }
    Some(out)
}

/// A bracket expression's characters.
struct Class {
    negated: bool,
    ranges: Vec<(u8, u8)>,
}

impl Class {
    fn contains(&self, c: u8, fold: bool) -> bool {
        let within = |c: u8| self.ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi);
        let hit = within(c)
            || (fold && (within(c.to_ascii_lowercase()) || within(c.to_ascii_uppercase())));
        hit != self.negated
    }
}

/// The bracket expression at the start of `p`, just after its `[`, and how
/// many bytes it takes up to and with its `]`. `None` when it does not end
/// or holds a character class (`[:alpha:]`), not understood here.
fn class(p: &[u8]) -> Option<(Class, usize)> {
    let mut i = 0;
    let negated = matches!(p.first(), Some(b'!' | b'^'));
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let mut c = *p.get(i)?;
        if c == b']' && !first {
            return Some((Class { negated, ranges }, i + 1));
        }
        first = false;
        if c == b'[' && p.get(i + 1) == Some(&b':') {
            return None;
        }
        if c == b'\\' {
            i += 1;
            c = *p.get(i)?;
        }
        i += 1;
        if p.get(i) == Some(&b'-') && p.get(i + 1).is_some_and(|&n| n != b']') {
            let mut hi = p[i + 1];
            i += 2;
            if hi == b'\\' {
                hi = *p.get(i)?;
                i += 1;
            }
            ranges.push((c, hi));
        } else {
            ranges.push((c, c));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_positive_line_that_matches_ignores_the_file() {
        for (text, name) in [
            (".env\n", ".env"),
            ("/.env\n", ".env"),
            ("**/.env\n", ".env"),
            ("/**/.env\n", ".env"),
            (".env*\n", ".env.short"),
            ("  \n/.env.*   \n", ".env.short"),
            (".env.[a-z]*\n", ".env.local"),
            ("*\n", ".env"),
            ("/**\n", ".env"),
            ("\u{feff}.env\r\n", ".env"),
            ("*.tmp\n", "..env.envcloak-del-0123456789abcdef.tmp"),
            (
                ".*.envcloak-*.tmp\n",
                "..env.local.envcloak-new-0123456789abcdef.tmp",
            ),
            (".*.envcloak-*.tmp\n", "..envcloak-del-0123456789abcdef.tmp"),
            // A later `!` line for another file leaves it ignored.
            (".env*\n!.env.example\n", ".env.local"),
        ] {
            assert!(ignores(text, name), "{text:?} {name}");
        }
    }

    #[test]
    fn the_last_line_that_may_match_decides() {
        for (text, name) in [
            ("", ".env"),
            ("# .env\n", ".env"),
            ("\\#.env\n", ".env"),
            ("!.env\n", ".env"),
            (".env.*\n", ".env"),
            (".envrc\n", ".env"),
            (".env/\n", ".env"),
            ("sub/.env\n", ".env"),
            (" .env\n", ".env"),
            // A later `!` takes the file back in, whatever the case.
            (".env*\n!.env.local\n", ".env.local"),
            (".env*\n!/.env.local\n", ".env.local"),
            (".env*\n!**/.env.local\n", ".env.local"),
            (".env*\n!.ENV.LOCAL\n", ".env.local"),
            (".env*\n!*.local\n", ".env.local"),
            ("*.tmp\n!.*\n", "..env.envcloak-del-0123456789abcdef.tmp"),
            // What is not understood keeps it in git.
            (".env*\n![[:alpha:]]*\n", ".env"),
            (".env[[:alpha:]]\n", ".envx"),
            (".env[\n", ".env["),
            // A case that may differ does not ignore it.
            (".ENV\n", ".env"),
        ] {
            assert!(!ignores(text, name), "{text:?} {name}");
        }
        // A line after the `!` puts it back out.
        assert!(ignores(".env*\n!.env.local\n/.env.local\n", ".env.local"));
        // A `!` line for a directory, or one needing one, says nothing.
        assert!(ignores(".env*\n!.env.local/\n", ".env.local"));
        assert!(ignores(".env*\n!sub/.env.local\n", ".env.local"));
    }

    #[test]
    fn trailing_blanks_go_unless_escaped() {
        assert_eq!(trim_trailing_blanks(".env  "), ".env");
        assert_eq!(trim_trailing_blanks(".env\\ "), ".env\\ ");
        assert_eq!(trim_trailing_blanks(".env\\  "), ".env\\ ");
        assert_eq!(trim_trailing_blanks(".env\t"), ".env\t");
        assert!(ignores("a\\ \n", "a "));
        assert!(!ignores("a \n", "a "));
    }

    #[test]
    fn bracket_expressions() {
        assert_eq!(glob(b"[a-c]x", b"bx", false), Some(true));
        assert_eq!(glob(b"[!a-c]x", b"bx", false), Some(false));
        assert_eq!(glob(b"[^a-c]x", b"dx", false), Some(true));
        assert_eq!(glob(b"[]]", b"]", false), Some(true));
        assert_eq!(glob(b"[a-]", b"-", false), Some(true));
        assert_eq!(glob(b"[\\]]", b"]", false), Some(true));
        assert_eq!(glob(b"[A-C]", b"b", true), Some(true));
        assert_eq!(glob(b"[A-C]", b"b", false), Some(false));
        assert_eq!(glob(b"[a", b"a", false), None);
        assert_eq!(glob(b"a\\", b"a", false), None);
        assert_eq!(glob(b"\\*", b"*", false), Some(true));
        assert_eq!(glob(b"\\*", b"x", false), Some(false));
        assert_eq!(glob(b"a*b?c", b"aXXbYc", false), Some(true));
        assert_eq!(glob(b"a*b?c", b"aXXbc", false), Some(false));
        assert_eq!(glob(b"**", b"", false), Some(true));
    }

    /// Every name of a shape, whatever its hex digits: a line that matches
    /// only some of them (a sample's digits written out, `*f.tmp`), or a
    /// later `!` line that may match one, leaves them in doubt.
    #[test]
    fn a_shape_is_ignored_only_when_every_name_of_it_is() {
        let temp = shape("..env.envcloak-del-", 16, ".tmp");
        for text in [
            "*.tmp\n",
            ".*.envcloak-*.tmp\n",
            "*\n",
            ".*\n",
            "..env.envcloak-del-????????????????.tmp\n",
            "..env.envcloak-del-[0-9a-f]*.tmp\n",
            "*.tmp\n!*.TMP.bak\n",
            // A later `!` line that matches none of them.
            "*.tmp\n!..env.envcloak-del-*g.tmp\n",
        ] {
            assert!(ignores_every(text, &temp), "{text:?}");
        }
        for text in [
            "",
            "*f.tmp\n",
            "/.env\n*f.tmp\n",
            ".*.envcloak-*-0123456789abcdef.tmp\n",
            "..env.envcloak-del-[0-9]*.tmp\n",
            "*.tmp\n!*[0-9].tmp\n",
            "*.tmp\n!*01*\n",
            "*.tmp\n!..env.envcloak-del-*A.tmp\n",
            "*.tmp\n![[:digit:]]*\n",
        ] {
            assert!(!ignores_every(text, &temp), "{text:?}");
        }
        // With no hex position, a shape is the one name.
        assert!(ignores_every("/.env\n", &shape(".env", 0, "")));
    }

    /// A pattern built to make a backtracking matcher slow is matched in
    /// no time.
    #[test]
    fn many_stars_stay_fast() {
        let p = format!("{}b", "*a".repeat(40));
        let s = format!(".env.{}", "a".repeat(250));
        let started = std::time::Instant::now();
        assert!(!ignores(&format!("{p}\n"), &s));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
