//! The programs some readers run, read for what they read besides their
//! input (Codex review: a reader's program was taken as a pattern and
//! never looked at, so `sed '1r .env'`, `awk 'BEGIN { while ((getline l <
//! ".env") > 0) print l }'`, `awk 'BEGIN { for (k in ENVIRON) print k,
//! ENVIRON[k] }'` and `jq -n env` were let through):
//!
//! - sed's script: `r` and `R` read the file they name; `e` and the `s`
//!   command's `e` flag run a command; `w`, `W` and the `w` flag write
//!   (not a read). The script is parsed as GNU and BSD sed read it; one
//!   that does not parse is not a script [`sed`] knows.
//! - awk's program: `getline < FILE` reads FILE; a pipe (`"cmd" | getline`,
//!   `print | "cmd"`, gawk's `|&`), `system`, `ARGV` and `ARGC` (which
//!   pick the files read), gawk's `@include`, `@load` and indirect calls
//!   are not modelled; `ENVIRON` other than `ENVIRON["NAME"]` names the
//!   whole environment.
//! - jq's and yq's filter: `env` and `$ENV` other than one variable by
//!   name name the whole environment; `import` and `include` load files;
//!   yq's `load` family reads the file it names; yq's `envsubst` and its
//!   expression evaluation are not modelled.
//!
//! What is not modelled makes [`ProgramReads::unresolved`] true: the
//! command is then asked about or stopped, never let through (fail
//! closed). A variable read by its name (`ENVIRON["HOME"]`, `env.HOME`) is
//! the honesty table's row of a variable's value printed.

use zeroize::Zeroizing;

/// The language of a reader's program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lang {
    Sed,
    Awk,
    Jq,
}

/// What a program reads besides its input, as far as it is known.
#[derive(Debug, Default)]
pub(super) struct ProgramReads {
    /// The files it names to read, as written.
    pub files: Vec<Zeroizing<Vec<u8>>>,
    /// It reads, or may read, what is not modelled: a file named by a
    /// value, a command's output, the whole environment, other code.
    pub unresolved: bool,
}

/// What `text`, a program of `lang`, reads; `None` when it is not one
/// (a sed script that does not parse).
pub(super) fn read(lang: Lang, text: &[u8]) -> Option<ProgramReads> {
    match lang {
        Lang::Sed => sed(text),
        Lang::Awk => Some(awk(text)),
        Lang::Jq => Some(jq(text)),
    }
}

// ---------------------------------------------------------------- sed

struct Cur<'a> {
    t: &'a [u8],
    i: usize,
}

impl Cur<'_> {
    fn peek(&self) -> Option<u8> {
        self.t.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.i += 1;
        Some(b)
    }
    fn blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    fn digits(&mut self) -> bool {
        let start = self.i;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.i += 1;
        }
        self.i > start
    }
    /// The rest of the line, without its newline (consumed).
    fn line(&mut self) -> &[u8] {
        let start = self.i;
        while self.peek().is_some_and(|b| b != b'\n') {
            self.i += 1;
        }
        let s = &self.t[start..self.i];
        if self.peek() == Some(b'\n') {
            self.i += 1;
        }
        s
    }
    /// A label: to the end of the line or a `;` (GNU ends one there; the
    /// shorter reading leaves more to read as commands).
    fn label(&mut self) {
        while self.peek().is_some_and(|b| b != b'\n' && b != b';') {
            self.i += 1;
        }
    }
}

/// A delimited part (`s`'s regular expression and replacement, `y`'s
/// lists, an address's expression) up to its unescaped closing `delim`.
/// With `regex`, a bracket expression's members are read as members (BSD
/// and GNU sed read the `/` in `s/[/]/x/` as one).
fn delimited(c: &mut Cur<'_>, delim: u8, regex: bool) -> Option<()> {
    loop {
        let b = c.bump()?;
        if b == b'\\' {
            c.bump()?;
        } else if b == delim {
            return Some(());
        } else if b == b'\n' {
            // An unescaped newline ends the command before its part does.
            return None;
        } else if regex && b == b'[' {
            // `[]...]`, `[^]...]`, `[[:class:]]`.
            if c.peek() == Some(b'^') {
                c.i += 1;
            }
            if c.peek() == Some(b']') {
                c.i += 1;
            }
            loop {
                let m = c.bump()?;
                if m == b'[' && matches!(c.peek(), Some(b':' | b'.' | b'=')) {
                    let kind = c.bump()?;
                    loop {
                        let x = c.bump()?;
                        if x == kind && c.peek() == Some(b']') {
                            c.i += 1;
                            break;
                        }
                    }
                } else if m == b']' {
                    break;
                } else if m == b'\n' {
                    return None;
                }
            }
        }
    }
}

/// One address, if there is one.
fn address(c: &mut Cur<'_>) -> Option<()> {
    match c.peek() {
        Some(b'0'..=b'9') => {
            c.digits();
            if c.peek() == Some(b'~') {
                c.i += 1;
                c.digits();
            }
        }
        Some(b'$') => c.i += 1,
        Some(b'/') => {
            c.i += 1;
            delimited(c, b'/', true)?;
            regex_flags(c);
        }
        Some(b'\\') => {
            c.i += 1;
            let d = c.bump()?;
            if d == b'\n' || d == b'\\' {
                return None;
            }
            delimited(c, d, true)?;
            regex_flags(c);
        }
        _ => {}
    }
    Some(())
}

fn regex_flags(c: &mut Cur<'_>) {
    while matches!(c.peek(), Some(b'I' | b'M')) {
        c.i += 1;
    }
}

/// Where a command ends: blanks, then the end, a newline, `;`, `}` or a
/// comment.
fn command_end(c: &mut Cur<'_>) -> Option<()> {
    c.blanks();
    match c.peek() {
        None | Some(b'\n' | b';' | b'}' | b'#') => Some(()),
        _ => None,
    }
}

/// A sed script, as GNU sed 4 and macOS's sed read it.
fn sed(text: &[u8]) -> Option<ProgramReads> {
    let mut out = ProgramReads::default();
    let mut c = Cur { t: text, i: 0 };
    let mut depth = 0usize;
    loop {
        while matches!(c.peek(), Some(b' ' | b'\t' | b'\n' | b';')) {
            c.i += 1;
        }
        let Some(first) = c.peek() else {
            break;
        };
        if first == b'#' {
            c.line();
            continue;
        }
        address(&mut c)?;
        c.blanks();
        if c.peek() == Some(b',') {
            c.i += 1;
            c.blanks();
            match c.peek() {
                Some(b'+' | b'~') => {
                    c.i += 1;
                    if !c.digits() {
                        return None;
                    }
                }
                _ => address(&mut c)?,
            }
            c.blanks();
        }
        while c.peek() == Some(b'!') {
            c.i += 1;
            c.blanks();
        }
        let cmd = c.bump()?;
        match cmd {
            b'{' => {
                depth += 1;
                continue;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
            }
            b'=' | b'd' | b'D' | b'g' | b'G' | b'h' | b'H' | b'n' | b'N' | b'p' | b'P' | b'x'
            | b'z' | b'F' => {}
            b'l' | b'L' | b'q' | b'Q' => {
                c.blanks();
                c.digits();
            }
            b':' | b'b' | b't' | b'T' | b'v' => {
                c.blanks();
                c.label();
                continue;
            }
            b'a' | b'i' | b'c' => {
                // Text: GNU's one-line form, or `\` and the lines that
                // follow, each but the last ending in `\`; data, never
                // commands.
                c.blanks();
                if c.peek() == Some(b'\\') {
                    c.i += 1;
                    c.blanks();
                    if c.peek() == Some(b'\n') {
                        c.i += 1;
                    }
                }
                loop {
                    match c.bump() {
                        None | Some(b'\n') => break,
                        Some(b'\\') => {
                            c.bump();
                        }
                        Some(_) => {}
                    }
                }
                continue;
            }
            b'r' | b'R' => {
                c.blanks();
                let name = c.line();
                out.files.push(Zeroizing::new(name.to_vec()));
                continue;
            }
            b'w' | b'W' => {
                c.line();
                continue;
            }
            b'e' => {
                out.unresolved = true;
                c.line();
                continue;
            }
            b's' => {
                let d = c.bump()?;
                if d == b'\n' || d == b'\\' {
                    return None;
                }
                delimited(&mut c, d, true)?;
                delimited(&mut c, d, false)?;
                loop {
                    match c.peek() {
                        Some(b'g' | b'p' | b'i' | b'I' | b'm' | b'M' | b'0'..=b'9') => c.i += 1,
                        Some(b'e') => {
                            out.unresolved = true;
                            c.i += 1;
                        }
                        Some(b'w') => {
                            c.line();
                            break;
                        }
                        _ => break,
                    }
                }
            }
            b'y' => {
                let d = c.bump()?;
                if d == b'\n' || d == b'\\' {
                    return None;
                }
                delimited(&mut c, d, false)?;
                delimited(&mut c, d, false)?;
            }
            _ => return None,
        }
        command_end(&mut c)?;
    }
    (depth == 0).then_some(out)
}

// ---------------------------------------------------------------- awk

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Ident(Vec<u8>),
    Str(Zeroizing<Vec<u8>>),
    Num,
    Regex,
    /// `|` (a pipe) and gawk's `|&`, not `||`.
    Pipe,
    /// Any other punctuation, by its first byte (`<`, `[`, `]`, `(`, ...;
    /// `||` is `&`).
    Punct(u8),
    Newline,
    /// gawk's `@` (`@include`, `@load`, `@namespace`, an indirect call).
    At,
}

/// Whether a `/` after `prev` starts a regular expression (an operand is
/// expected) rather than a division.
fn awk_operand_expected(prev: Option<&Tok>) -> bool {
    match prev {
        None | Some(Tok::Newline | Tok::Pipe | Tok::At) => true,
        Some(Tok::Punct(p)) => !matches!(p, b')' | b']' | b'$'),
        Some(Tok::Ident(w)) => matches!(
            w.as_slice(),
            b"print" | b"printf" | b"return" | b"in" | b"getline" | b"case"
        ),
        _ => false,
    }
}

fn awk_tokens(t: &[u8]) -> Vec<Tok> {
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0;
    while let Some(&b) = t.get(i) {
        i += 1;
        match b {
            b'#' => {
                while t.get(i).is_some_and(|c| *c != b'\n') {
                    i += 1;
                }
            }
            b'\n' => out.push(Tok::Newline),
            b'\\' if t.get(i) == Some(&b'\n') => i += 1,
            b' ' | b'\t' | b'\r' | b'\\' => {}
            b'"' => {
                let mut s = Zeroizing::new(Vec::new());
                while let Some(&c) = t.get(i) {
                    i += 1;
                    match c {
                        b'"' => break,
                        b'\\' => {
                            if let Some(&n) = t.get(i) {
                                i += 1;
                                s.push(match n {
                                    b'n' => b'\n',
                                    b't' => b'\t',
                                    other => other,
                                });
                            }
                        }
                        other => s.push(other),
                    }
                }
                out.push(Tok::Str(s));
            }
            b'/' if awk_operand_expected(out.last()) => {
                let mut in_class = false;
                while let Some(&c) = t.get(i) {
                    i += 1;
                    match c {
                        b'\\' => i += 1,
                        b'[' => in_class = true,
                        b']' => in_class = false,
                        b'/' if !in_class => break,
                        b'\n' => break,
                        _ => {}
                    }
                }
                out.push(Tok::Regex);
            }
            b'|' => {
                if t.get(i) == Some(&b'|') {
                    i += 1;
                    out.push(Tok::Punct(b'&'));
                } else {
                    // `|` and gawk's `|&`: a command's input or output.
                    out.push(Tok::Pipe);
                }
            }
            b'@' => out.push(Tok::At),
            b'0'..=b'9' => {
                while t
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'.')
                {
                    i += 1;
                }
                out.push(Tok::Num);
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i - 1;
                while t
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    i += 1;
                }
                out.push(Tok::Ident(t[start..i].to_vec()));
            }
            other => out.push(Tok::Punct(other)),
        }
    }
    out
}

/// An awk program (POSIX awk, gawk, mawk, macOS's one-true-awk).
fn awk(text: &[u8]) -> ProgramReads {
    let mut out = ProgramReads::default();
    let toks = awk_tokens(text);
    let mut k = 0;
    while let Some(tok) = toks.get(k) {
        k += 1;
        match tok {
            Tok::Pipe | Tok::At => out.unresolved = true,
            Tok::Ident(w) => match w.as_slice() {
                b"system" | b"ARGV" | b"ARGC" => out.unresolved = true,
                b"ENVIRON" => {
                    // One variable by its name is the honesty table's row;
                    // anything else names the whole environment.
                    let named = matches!(
                        (toks.get(k), toks.get(k + 1), toks.get(k + 2)),
                        (
                            Some(Tok::Punct(b'[')),
                            Some(Tok::Str(_)),
                            Some(Tok::Punct(b']'))
                        )
                    );
                    if !named {
                        out.unresolved = true;
                    }
                }
                b"getline" => awk_getline(&toks, k, &mut out),
                _ => {}
            },
            _ => {}
        }
    }
    out
}

/// `getline [var] [< file]`, the tokens after `getline` at `k`.
fn awk_getline(toks: &[Tok], k: usize, out: &mut ProgramReads) {
    let mut j = k;
    match toks.get(j) {
        Some(Tok::Ident(_)) => {
            j += 1;
            if toks.get(j) == Some(&Tok::Punct(b'[')) {
                let mut level = 0usize;
                while let Some(t) = toks.get(j) {
                    j += 1;
                    match t {
                        Tok::Punct(b'[') => level += 1,
                        Tok::Punct(b']') => {
                            level = level.saturating_sub(1);
                            if level == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Some(Tok::Punct(b'$')) => {
            j += 1;
            if matches!(toks.get(j), Some(Tok::Ident(_) | Tok::Num)) {
                j += 1;
            } else {
                // `$(...)`: a field picked by a value.
                out.unresolved = true;
            }
        }
        _ => {}
    }
    if toks.get(j) != Some(&Tok::Punct(b'<')) {
        // The next record of the input.
        return;
    }
    match (toks.get(j + 1), toks.get(j + 2)) {
        (
            Some(Tok::Str(name)),
            None
            | Some(
                Tok::Newline
                | Tok::Pipe
                | Tok::Punct(b')' | b';' | b'}' | b'>' | b'&' | b'=' | b'!' | b','),
            ),
        ) => out.files.push(name.clone()),
        // A name made at run time, or a string joined with more.
        _ => out.unresolved = true,
    }
}

// ---------------------------------------------------------- jq and yq

#[derive(Debug, PartialEq, Eq)]
enum JTok {
    Ident(Vec<u8>),
    /// `$name`.
    Var(Vec<u8>),
    /// `.name`.
    Field,
    Str(Zeroizing<Vec<u8>>),
    Punct(u8),
}

/// jq's tokens, a string's interpolations (`"\(...)"`) read as code.
fn jq_tokens(t: &[u8]) -> Vec<JTok> {
    let mut out = Vec::new();
    // Open interpolations: the parenthesis depth each started at.
    let mut interp: Vec<usize> = Vec::new();
    let mut parens = 0usize;
    let mut i = 0;
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut in_string = false;
    let mut s = Zeroizing::new(Vec::new());
    while let Some(&b) = t.get(i) {
        i += 1;
        if in_string {
            match b {
                b'"' => {
                    in_string = false;
                    out.push(JTok::Str(Zeroizing::new(std::mem::take(&mut *s))));
                }
                b'\\' if t.get(i) == Some(&b'(') => {
                    i += 1;
                    in_string = false;
                    // The string's text so far is left as one string.
                    out.push(JTok::Str(Zeroizing::new(std::mem::take(&mut *s))));
                    interp.push(parens);
                    parens += 1;
                }
                b'\\' => {
                    if let Some(&n) = t.get(i) {
                        i += 1;
                        s.push(n);
                    }
                }
                other => s.push(other),
            }
            continue;
        }
        match b {
            b'#' => {
                while t.get(i).is_some_and(|c| *c != b'\n') {
                    i += 1;
                }
            }
            b'"' => in_string = true,
            b'(' => {
                parens += 1;
                out.push(JTok::Punct(b'('));
            }
            b')' => {
                parens = parens.saturating_sub(1);
                if interp.last() == Some(&parens) {
                    interp.pop();
                    in_string = true;
                } else {
                    out.push(JTok::Punct(b')'));
                }
            }
            b'$' => {
                let start = i;
                while t.get(i).is_some_and(|c| ident(*c)) {
                    i += 1;
                }
                out.push(JTok::Var(t[start..i].to_vec()));
            }
            b'.' if t
                .get(i)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') =>
            {
                while t.get(i).is_some_and(|c| ident(*c)) {
                    i += 1;
                }
                out.push(JTok::Field);
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i - 1;
                // A module's name joins with `::` (`m::f`).
                loop {
                    if t.get(i).is_some_and(|c| ident(*c)) {
                        i += 1;
                    } else if t.get(i) == Some(&b':') && t.get(i + 1) == Some(&b':') {
                        i += 2;
                    } else {
                        break;
                    }
                }
                out.push(JTok::Ident(t[start..i].to_vec()));
            }
            c if c.is_ascii_whitespace() => {}
            other => out.push(JTok::Punct(other)),
        }
    }
    if in_string {
        // Unfinished: jq refuses it; what there was is kept as a string.
        out.push(JTok::Str(Zeroizing::new(std::mem::take(&mut *s))));
    }
    out
}

/// Whether the tokens at `j` read one variable by its name: `.NAME`,
/// `["NAME"]` or `.["NAME"]`.
fn jq_named(toks: &[JTok], j: usize) -> bool {
    matches!(toks.get(j), Some(JTok::Field))
        || matches!(
            (toks.get(j), toks.get(j + 1), toks.get(j + 2)),
            (
                Some(JTok::Punct(b'[')),
                Some(JTok::Str(_)),
                Some(JTok::Punct(b']'))
            )
        )
        || matches!(
            (
                toks.get(j),
                toks.get(j + 1),
                toks.get(j + 2),
                toks.get(j + 3)
            ),
            (
                Some(JTok::Punct(b'.')),
                Some(JTok::Punct(b'[')),
                Some(JTok::Str(_)),
                Some(JTok::Punct(b']'))
            )
        )
}

/// A jq filter (jq, gojq, jaq), or a yq expression (mikefarah's yq, whose
/// language is jq's with the `load` family, `env`, `strenv`, `envsubst`
/// and expression evaluation added).
fn jq(text: &[u8]) -> ProgramReads {
    let mut out = ProgramReads::default();
    let toks = jq_tokens(text);
    let mut k = 0;
    while let Some(tok) = toks.get(k) {
        k += 1;
        let next = toks.get(k);
        match tok {
            JTok::Var(v) if v.as_slice() == b"ENV" && !jq_named(&toks, k) => {
                out.unresolved = true;
            }
            JTok::Var(v) if v.as_slice() == b"__prog_args" => out.unresolved = true,
            JTok::Ident(w) => match w.as_slice() {
                // An object's key (`{env: 1}`) is not the builtin.
                _ if next == Some(&JTok::Punct(b':')) => {}
                b"env" | b"strenv" if next == Some(&JTok::Punct(b'(')) => {
                    // yq's `env(NAME)`: one variable by its name.
                    if !matches!(
                        (toks.get(k + 1), toks.get(k + 2)),
                        (Some(JTok::Ident(_)), Some(JTok::Punct(b')')))
                    ) {
                        out.unresolved = true;
                    }
                }
                b"env" if !jq_named(&toks, k) => out.unresolved = true,
                b"import" | b"include" | b"envsubst" | b"eval" | b"get_search_list" => {
                    out.unresolved = true;
                }
                w if w.starts_with(b"load") => {
                    match (toks.get(k), toks.get(k + 1), toks.get(k + 2)) {
                        (
                            Some(JTok::Punct(b'(')),
                            Some(JTok::Str(name)),
                            Some(JTok::Punct(b')')),
                        ) => out.files.push(name.clone()),
                        _ => out.unresolved = true,
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(r: &ProgramReads) -> Vec<String> {
        r.files
            .iter()
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect()
    }

    fn sed_reads(t: &str) -> Option<(Vec<String>, bool)> {
        sed(t.as_bytes()).map(|r| (names(&r), r.unresolved))
    }

    #[test]
    fn sed_scripts_are_read_for_what_they_read_and_run() {
        let none = Some((Vec::<String>::new(), false));
        for ok in [
            "",
            "p",
            "1,5p",
            "s/a/b/g",
            "s/[/]/x/",
            "s|a|b|2p",
            "/x/,/y/d",
            "$!N; s/\\n/ /",
            ":a;N;$!ba;s/\\n/ /g",
            "0~4 s/x/y/",
            "/start/I,+3 { p; }",
            "y/abc/xyz/",
            "a\\\nadded text; r .env",
            "a added text; r .env",
            "w /dev/stdout",
            "s/x/y/w out.txt",
            "# r .env\np",
            "\\%a%d",
            "l 5",
            "q 3",
            "=",
            "/.env/d",
            "s/.env/x/",
        ] {
            assert_eq!(sed_reads(ok), none, "{ok:?}");
        }
        for (script, file) in [
            ("1r .env", ".env"),
            ("$ R sub/.env", "sub/.env"),
            ("/x/ { r .env.local\n}", ".env.local"),
            ("p;r /proc/self/environ", "/proc/self/environ"),
        ] {
            assert_eq!(
                sed_reads(script),
                Some((vec![file.to_owned()], false)),
                "{script:?}"
            );
        }
        for run in ["e cat .env", "1e", "s/.*/printenv/e", "s/x/y/ge"] {
            assert!(sed_reads(run).is_some_and(|(_, u)| u), "{run:?}");
        }
        // A file's name can be a script (`README.md` is `R EADME.md`): the
        // reader reads the first operand as one only where sed does.
        assert_eq!(
            sed_reads("README.md"),
            Some((vec!["EADME.md".to_owned()], false))
        );
        // Not sed scripts: they do not parse.
        for bad in ["src/main.rs", ".bak", "Makefile", "{p", "s/a/b", "k"] {
            assert_eq!(sed_reads(bad), None, "{bad:?}");
        }
    }

    fn awk_reads(t: &str) -> (Vec<String>, bool) {
        let r = awk(t.as_bytes());
        (names(&r), r.unresolved)
    }

    #[test]
    fn awk_programs_are_read_for_what_they_read_and_run() {
        for ok in [
            "1",
            "{ print $1 }",
            "/a|b/ { n++ } END { print n }",
            "NR == 1 || NR == 2",
            "{ s += $2 / 3 } END { print s }",
            "BEGIN { print ENVIRON[\"HOME\"] }",
            "{ while ((getline line) > 0) print line }",
            "{ getline; print }",
            "{ print > \"/dev/stderr\" }",
            "# system\n{ print }",
            "{ print \"system\" }",
            "$1 ~ /ENVIRON/",
        ] {
            assert_eq!(awk_reads(ok), (Vec::<String>::new(), false), "{ok:?}");
        }
        for (program, file) in [
            (
                "BEGIN { while ((getline l < \".env\") > 0) print l }",
                ".env",
            ),
            (
                "BEGIN { getline x < \"/proc/self/environ\"; print x }",
                "/proc/self/environ",
            ),
        ] {
            assert_eq!(
                awk_reads(program),
                (vec![file.to_owned()], false),
                "{program:?}"
            );
        }
        for unknown in [
            "BEGIN { for (k in ENVIRON) print k, ENVIRON[k] }",
            "BEGIN { print ENVIRON[n] }",
            "BEGIN { system(\"cat .env\") }",
            "BEGIN { \"cat .env\" | getline x; print x }",
            "{ print | \"sh\" }",
            "BEGIN { ARGV[ARGC++] = \".env\" } { print }",
            "BEGIN { f = \".env\"; while ((getline l < f) > 0) print l }",
            "BEGIN { getline l < \".e\" \"nv\"; print l }",
            "@include \"x.awk\"",
            "BEGIN { \"cmd\" |& getline }",
        ] {
            assert!(awk_reads(unknown).1, "{unknown:?}");
        }
    }

    fn jq_reads(t: &str) -> (Vec<String>, bool) {
        let r = jq(t.as_bytes());
        (names(&r), r.unresolved)
    }

    #[test]
    fn jq_filters_are_read_for_what_they_read() {
        for ok in [
            ".",
            ".env",
            ".a.env",
            "{env: 1}",
            "select(.name == \"env\")",
            "env.HOME",
            "$ENV.HOME",
            "$ENV[\"HOME\"]",
            "strenv(HOME)",
            "\"\\(.a) env\"",
        ] {
            assert_eq!(jq_reads(ok), (Vec::<String>::new(), false), "{ok:?}");
        }
        assert_eq!(jq_reads("load(\".env\")"), (vec![".env".to_owned()], false));
        for unknown in [
            "env",
            "$ENV",
            "{$ENV}",
            "env | keys",
            "\"\\(env)\"",
            "import \"data\" as $d; $d",
            "include \"m\"; .",
            "load(.f)",
            "envsubst",
            "eval (\"env\")",
        ] {
            assert!(jq_reads(unknown).1, "{unknown:?}");
        }
    }
}
