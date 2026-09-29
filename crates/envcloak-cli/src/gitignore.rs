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
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    text.lines().rev().find_map(|l| verdict(l, name)) == Some(true)
}

/// What one line says of `name`: `None` when it surely does not match,
/// `Some(true)` when it surely ignores it, and `Some(false)` when it may
/// take it back in, or may match and was not understood.
fn verdict(line: &str, name: &str) -> Option<bool> {
    let (negated, pattern) = pattern_of(line)?;
    if negated {
        match glob(pattern.as_bytes(), name.as_bytes(), true) {
            Some(false) => None,
            _ => Some(false),
        }
    } else {
        match glob(pattern.as_bytes(), name.as_bytes(), false) {
            Some(true) => Some(true),
            Some(false) => None,
            None => Some(false),
        }
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
/// case. Linear in `s` for each `*`, so no pattern a repository ships
/// makes a scan slow.
fn glob(p: &[u8], s: &[u8], fold: bool) -> Option<bool> {
    let t = tokens(p)?;
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
            Some(one) if one.matches(s[si], fold) => {
                ti += 1;
                si += 1;
                continue;
            }
            _ => {}
        }
        let Some((bt, bs)) = back else {
            return Some(false);
        };
        back = Some((bt, bs + 1));
        ti = bt;
        si = bs + 1;
    }
    Some(t[ti..].iter().all(|x| matches!(x, Token::Star)))
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
