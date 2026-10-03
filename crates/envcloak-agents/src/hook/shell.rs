//! The command reader behind the hook's tool-call check and the MCP
//! server's `run_with_secrets` refusal (M2 plan M2-08, D-12, D-22): which
//! of a few classes of command a shell command string, or an argv, falls
//! in.
//!
//! - [`Class::EnvFile`]: reads an env file (`.env`, `.env.<profile>`, as
//!   `envcloak_scan::dotenv_kind` names them; templates such as
//!   `.env.example` hold names only and are not counted): a reader command
//!   (`cat`, `head`, `tail`, `less`, `more`, `sed`, `awk`, `grep`, `rg`,
//!   `bat`, `source`, `.` and the others in [`reader`]) with one as a file
//!   operand, an input redirection from one (`< .env`, `$(<.env)`), a glob
//!   that could match one (`.env*`, `.e?v`, `.*`) or `find -name .env
//!   -exec cat {} \;`.
//! - [`Class::EnvDump`]: prints the environment: `env` with no command to
//!   run, `printenv`, `export` and `export -p`, a bare `set`, `declare -x`,
//!   `declare -p`, `typeset`, `ps e` and `ps -E`, and any path naming
//!   `/proc/<pid>/environ`.
//! - [`Class::Reveal`] and [`Class::Approve`]: `envcloak reveal` and
//!   `envcloak approve`, which only the person runs.
//! - [`Class::Ambiguous`]: the reader could not tell what runs: a quote,
//!   a substitution or a construct left open, a command whose name is only
//!   known when it runs (`$CMD`, `c${IFS}at`), `eval` or `sh -c` of text
//!   that is, or nesting past [`MAX_DEPTH`]. The hook denies these too
//!   (the conservative reading, lesson L-06).
//!
//! The grammar read is the POSIX shell's, with bash's additions an agent
//! uses: single, double and `$'...'` quotes and backslashes; `$name`,
//! `${...}`, `$(...)`, backquotes and `$((...))`; brace expansion;
//! pipelines and lists; subshells, groups, `if`, `while`, `until`, `for`,
//! `select`, `case`, `[[ ]]`, `(( ))` and functions; redirections with
//! their descriptor numbers, here-strings and here-documents (whose body,
//! unless its delimiter is quoted, is read for substitutions, and which a
//! shell reads as its script, as it reads a here-string); `dd if=`; and the
//! commands that run another command:
//! `command`, `builtin`, `exec`, `env`, `nohup`, `time`, `nice`, `stdbuf`,
//! `timeout`, `sudo`, `doas`, `xargs`, `busybox`, `setsid`, `caffeinate`,
//! `unbuffer`, `watch`, `eval`, `find -exec` and the shells with `-c`.
//!
//! What it does not see is listed, with an example each, in docs/
//! INSTALLERS.md ("What the hook does not see"), and a test keeps that
//! list equal to what this reader misses in its bypass corpus (lesson
//! L-15): a value known only when the command runs (a file name in a
//! variable, names piped to `xargs`), an interpreter's own code, a copy
//! read under another name, an alias or a function defined elsewhere, and
//! a recursive search of a directory. The hook prevents accidents; it is
//! not enforcement (SPEC §7.2 rule 4, T-14).
//!
//! Nothing here keeps or returns text from the command: the result is a
//! class.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use envcloak_scan::{FileKind, dotenv_kind};

/// A class of command the hook denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Reads an env file.
    EnvFile,
    /// Prints the environment.
    EnvDump,
    /// `envcloak reveal`.
    Reveal,
    /// `envcloak approve`.
    Approve,
    /// What runs could not be told.
    Ambiguous,
}

/// The deepest nesting of substitutions, subshells and `sh -c` scripts
/// read; deeper is [`Class::Ambiguous`].
pub const MAX_DEPTH: usize = 24;
/// The most words one word's brace expansions may make.
const MAX_EXPANSIONS: usize = 256;
/// The most steps one check may take (characters read and commands
/// looked at), so no input makes it slow: past it, [`Class::Ambiguous`].
const MAX_WORK: usize = 16 * 1024 * 1024;
/// The most quotes, `${...}`, `$((...))` and arrays open inside one
/// another; deeper is [`Class::Ambiguous`].
const MAX_NEST: usize = 64;

/// Reading stopped: what runs could not be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Amb;

/// One character of a word, after quote removal: a byte and whether it
/// was quoted (a quoted `*` is no glob), or a stretch the shell only knows
/// when it runs (an expansion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ch {
    Lit { b: u8, quoted: bool },
    Unknown,
}

type Word = Vec<Ch>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirKind {
    /// Input from a file (`<`, `<>`).
    Read,
    /// Output, or a descriptor copied.
    Other,
}

#[derive(Debug, Clone)]
struct Redir {
    kind: RedirKind,
    target: Word,
}

/// One simple command as read: its words and redirections.
#[derive(Debug, Clone, Default)]
struct Cmd {
    id: usize,
    depth: usize,
    words: Vec<Word>,
    redirs: Vec<Redir>,
}

/// A here-document whose body is still to be read, at the next newline.
#[derive(Debug, Clone)]
struct Pending {
    cmd: usize,
    delim: Vec<u8>,
    strip_tabs: bool,
    quoted: bool,
    depth: usize,
}

/// Where a list of commands ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// At the end of the text.
    Eof,
    /// At a `)` that closes it (a subshell or `$(`).
    Paren,
    /// At `;;`, `;&` or `;;&`, or before `esac` (a `case` item).
    CaseItem,
}

struct Cur<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a [u8]) -> Self {
        Cur { s, i: 0 }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn peek_at(&self, k: usize) -> Option<u8> {
        self.s.get(self.i + k).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.i += 1;
        Some(b)
    }
    fn starts_with(&self, p: &[u8]) -> bool {
        self.s.get(self.i..).is_some_and(|r| r.starts_with(p))
    }
}

struct Analyzer {
    cmds: Vec<Cmd>,
    pending: Vec<Pending>,
    /// Here-document bodies read: the command's id, the body, whether its
    /// delimiter was quoted.
    bodies: Vec<(usize, Vec<u8>, bool)>,
    found: Vec<Class>,
    work: usize,
    /// Quotes, expansions and arrays open inside one another: past
    /// [`MAX_NEST`], ambiguous (each is a frame on the stack).
    nest: usize,
    next_id: usize,
}

/// The class a shell command string falls in, if any: the first found,
/// [`Class::Ambiguous`] when reading stopped before any other was.
pub fn check_script(script: &str) -> Option<Class> {
    let mut a = Analyzer::new();
    let r = a
        .script(script.as_bytes(), 0)
        .and_then(|()| a.classify_all());
    a.result(r)
}

/// The class an argv falls in, if any, read as an exec runs it (no shell:
/// no quotes, globs or expansions), except that a shell given `-c` has its
/// script read as [`check_script`] reads one.
pub fn check_argv<S: AsRef<OsStr>>(argv: &[S]) -> Option<Class> {
    let mut a = Analyzer::new();
    let words: Vec<Word> = argv.iter().map(|w| lits(w.as_ref().as_bytes())).collect();
    let r = a.run(&words, &[], 0).and_then(|()| a.classify_all());
    a.result(r)
}

impl Analyzer {
    fn new() -> Self {
        Analyzer {
            cmds: Vec::new(),
            pending: Vec::new(),
            bodies: Vec::new(),
            found: Vec::new(),
            work: 0,
            nest: 0,
            next_id: 0,
        }
    }

    fn result(&self, r: Result<(), Amb>) -> Option<Class> {
        match (self.found.first(), r) {
            (Some(&c), _) => Some(c),
            (None, Err(Amb)) => Some(Class::Ambiguous),
            (None, Ok(())) => None,
        }
    }

    fn tick(&mut self, n: usize) -> Result<(), Amb> {
        self.work = self.work.saturating_add(n);
        if self.work > MAX_WORK {
            Err(Amb)
        } else {
            Ok(())
        }
    }

    /// `f`, one level further in: past [`MAX_NEST`], ambiguous.
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Amb>) -> Result<T, Amb> {
        if self.nest >= MAX_NEST {
            return Err(Amb);
        }
        self.nest += 1;
        let r = f(self);
        self.nest -= 1;
        r
    }

    fn new_cmd(&mut self, depth: usize) -> Cmd {
        let id = self.next_id;
        self.next_id += 1;
        Cmd {
            id,
            depth,
            ..Cmd::default()
        }
    }

    fn finish(&mut self, cmd: &mut Cmd) {
        let depth = cmd.depth;
        let fresh = self.new_cmd(depth);
        let done = std::mem::replace(cmd, fresh);
        if !done.words.is_empty() || !done.redirs.is_empty() {
            self.cmds.push(done);
        }
    }

    /// Reads a whole script.
    fn script(&mut self, s: &[u8], depth: usize) -> Result<(), Amb> {
        if depth > MAX_DEPTH {
            return Err(Amb);
        }
        let mut c = Cur::new(s);
        let pending = self.pending.len();
        self.list(&mut c, Stop::Eof, depth)?;
        // A here-document never ended reads to the end, as the shell does:
        // its body is empty here, since nothing follows.
        self.pending.truncate(pending);
        Ok(())
    }

    /// Reads commands until `stop`.
    fn list(&mut self, c: &mut Cur<'_>, stop: Stop, depth: usize) -> Result<(), Amb> {
        if depth > MAX_DEPTH {
            return Err(Amb);
        }
        let mut cmd = self.new_cmd(depth);
        loop {
            self.tick(1)?;
            if stop == Stop::CaseItem && cmd.words.is_empty() && at_reserved(c, b"esac") {
                self.finish(&mut cmd);
                return Ok(());
            }
            match c.peek() {
                None => {
                    self.finish(&mut cmd);
                    return if stop == Stop::Eof { Ok(()) } else { Err(Amb) };
                }
                Some(b' ' | b'\t' | b'\r') => {
                    c.bump();
                }
                Some(b'\\') if c.peek_at(1) == Some(b'\n') => c.i += 2,
                Some(b'#') => {
                    while let Some(b) = c.peek() {
                        if b == b'\n' {
                            break;
                        }
                        c.bump();
                    }
                }
                Some(b'\n') => {
                    c.bump();
                    self.finish(&mut cmd);
                    self.read_heredocs(c)?;
                }
                Some(b')') => {
                    if stop != Stop::Paren {
                        return Err(Amb);
                    }
                    c.bump();
                    self.finish(&mut cmd);
                    return Ok(());
                }
                Some(b';') => {
                    c.bump();
                    if matches!(c.peek(), Some(b';' | b'&')) {
                        c.bump();
                        if c.peek() == Some(b'&') {
                            c.bump();
                        }
                        self.finish(&mut cmd);
                        if stop == Stop::CaseItem {
                            return Ok(());
                        }
                        return Err(Amb);
                    }
                    self.finish(&mut cmd);
                }
                Some(b'&') => {
                    if c.peek_at(1) == Some(b'>') {
                        self.redirection(c, &mut cmd, depth)?;
                    } else {
                        c.bump();
                        if c.peek() == Some(b'&') {
                            c.bump();
                        }
                        self.finish(&mut cmd);
                    }
                }
                Some(b'|') => {
                    c.bump();
                    if matches!(c.peek(), Some(b'|' | b'&')) {
                        c.bump();
                    }
                    self.finish(&mut cmd);
                }
                Some(b'(') => {
                    if cmd.words.is_empty() && cmd.redirs.is_empty() {
                        if c.peek_at(1) == Some(b'(') {
                            c.i += 2;
                            self.arith(c, depth)?;
                        } else {
                            c.bump();
                            self.list(c, Stop::Paren, depth + 1)?;
                        }
                    } else if cmd.words.len() == 1 && cmd.redirs.is_empty() && fn_parens(c) {
                        // `name () { ...; }`: the body follows.
                        cmd.words.clear();
                    } else {
                        return Err(Amb);
                    }
                }
                Some(b'<' | b'>') => self.redirection(c, &mut cmd, depth)?,
                Some(_) => {
                    let w = self.word(c, depth)?;
                    if is_fd_prefix(&w) && matches!(c.peek(), Some(b'<' | b'>')) {
                        self.redirection(c, &mut cmd, depth)?;
                        continue;
                    }
                    if cmd.words.is_empty() && cmd.redirs.is_empty() && is_bare(&w) {
                        match plain(&w).as_deref() {
                            Some(
                                b"if" | b"then" | b"elif" | b"else" | b"fi" | b"do" | b"done"
                                | b"while" | b"until" | b"!" | b"{" | b"}" | b"coproc",
                            ) => continue,
                            Some(b"for" | b"select") => {
                                self.for_header(c, depth)?;
                                continue;
                            }
                            Some(b"case") => {
                                self.case(c, depth)?;
                                continue;
                            }
                            Some(b"function") => {
                                self.function_header(c, depth)?;
                                continue;
                            }
                            Some(b"[[") => {
                                self.cond(c, depth)?;
                                continue;
                            }
                            Some(b"esac") => return Err(Amb),
                            _ => {}
                        }
                    }
                    cmd.words.push(w);
                }
            }
        }
    }

    /// Reads a redirection at `c` (its descriptor number, if any, was read
    /// as the word before).
    fn redirection(&mut self, c: &mut Cur<'_>, cmd: &mut Cmd, depth: usize) -> Result<(), Amb> {
        enum Op {
            Read,
            Other,
            HereDoc { strip: bool },
            HereString,
        }
        let op = match (c.peek(), c.peek_at(1), c.peek_at(2)) {
            (Some(b'<' | b'>'), Some(b'('), _) => {
                // Process substitution: a word, the path of a pipe.
                c.i += 2;
                self.list(c, Stop::Paren, depth + 1)?;
                cmd.words.push(vec![Ch::Unknown]);
                return Ok(());
            }
            (Some(b'<'), Some(b'<'), Some(b'<')) => {
                c.i += 3;
                Op::HereString
            }
            (Some(b'<'), Some(b'<'), Some(b'-')) => {
                c.i += 3;
                Op::HereDoc { strip: true }
            }
            (Some(b'<'), Some(b'<'), _) => {
                c.i += 2;
                Op::HereDoc { strip: false }
            }
            (Some(b'<'), Some(b'>'), _) => {
                c.i += 2;
                Op::Read
            }
            (Some(b'<'), Some(b'&'), _) => {
                c.i += 2;
                Op::Other
            }
            (Some(b'<'), _, _) => {
                c.i += 1;
                Op::Read
            }
            (Some(b'>'), Some(b'>' | b'|' | b'&'), _) => {
                c.i += 2;
                Op::Other
            }
            (Some(b'>'), _, _) => {
                c.i += 1;
                Op::Other
            }
            (Some(b'&'), Some(b'>'), Some(b'>')) => {
                c.i += 3;
                Op::Other
            }
            (Some(b'&'), Some(b'>'), _) => {
                c.i += 2;
                Op::Other
            }
            _ => return Err(Amb),
        };
        skip_blanks(c);
        match c.peek() {
            Some(b) if !is_meta(b) && b != b'(' => {}
            _ => return Err(Amb),
        }
        let target = self.word(c, depth)?;
        match op {
            Op::Read => cmd.redirs.push(Redir {
                kind: RedirKind::Read,
                target,
            }),
            Op::Other => cmd.redirs.push(Redir {
                kind: RedirKind::Other,
                target,
            }),
            Op::HereString => {
                // A shell reads it as its script (`sh <<< 'cmd'`).
                let mut body = joined(std::slice::from_ref(&target));
                body.push(b'\n');
                self.bodies.push((cmd.id, body, true));
            }
            Op::HereDoc { strip } => {
                let delim = literal(&target).ok_or(Amb)?;
                let quoted = target
                    .iter()
                    .any(|ch| matches!(ch, Ch::Lit { quoted: true, .. }));
                self.pending.push(Pending {
                    cmd: cmd.id,
                    delim,
                    strip_tabs: strip,
                    quoted,
                    depth,
                });
                // Keeps the command, so its body is matched to it.
                cmd.redirs.push(Redir {
                    kind: RedirKind::Other,
                    target: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Reads the bodies of the here-documents waiting for this newline.
    fn read_heredocs(&mut self, c: &mut Cur<'_>) -> Result<(), Amb> {
        let pending = std::mem::take(&mut self.pending);
        for p in pending {
            let mut body = Vec::new();
            while c.peek().is_some() {
                let start = c.i;
                while let Some(b) = c.peek() {
                    if b == b'\n' {
                        break;
                    }
                    c.bump();
                }
                let mut line = &c.s[start..c.i];
                if c.peek() == Some(b'\n') {
                    c.bump();
                }
                self.tick(line.len() + 1)?;
                if p.strip_tabs {
                    while let [b'\t', rest @ ..] = line {
                        line = rest;
                    }
                }
                if line == p.delim.as_slice() {
                    break;
                }
                body.extend_from_slice(line);
                body.push(b'\n');
            }
            if !p.quoted {
                self.body_expansions(&body, p.depth)?;
            }
            self.bodies.push((p.cmd, body, p.quoted));
        }
        Ok(())
    }

    /// The substitutions in an unquoted here-document's body run.
    fn body_expansions(&mut self, body: &[u8], depth: usize) -> Result<(), Amb> {
        let mut c = Cur::new(body);
        while let Some(b) = c.peek() {
            self.tick(1)?;
            match b {
                b'\\' => c.i += 2,
                b'$' => {
                    let mut tmp = Vec::new();
                    self.dollar(&mut c, &mut tmp, depth, true)?;
                }
                b'`' => {
                    c.bump();
                    let inner = backquoted(&mut c)?;
                    self.script(&inner, depth + 1)?;
                }
                _ => c.i += 1,
            }
        }
        Ok(())
    }

    /// Reads one word, up to an unquoted metacharacter.
    fn word(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<Word, Amb> {
        let mut w: Word = Vec::new();
        loop {
            self.tick(1)?;
            match c.peek() {
                None => break,
                Some(b) if is_meta(b) => break,
                Some(b'(') => {
                    if is_assignment_prefix(&w) {
                        // `name=(a b c)`: an array's elements, as words.
                        c.bump();
                        self.array_elements(c, depth)?;
                        w.push(Ch::Unknown);
                    } else {
                        break;
                    }
                }
                Some(0) => {
                    // A stretch only known when the outer command runs
                    // ([`joined`]).
                    c.bump();
                    w.push(Ch::Unknown);
                }
                Some(b'\\') => {
                    c.bump();
                    match c.bump() {
                        None => return Err(Amb),
                        Some(b'\n') => {}
                        Some(b) => w.push(Ch::Lit { b, quoted: true }),
                    }
                }
                Some(b'\'') => {
                    c.bump();
                    loop {
                        match c.bump() {
                            None => return Err(Amb),
                            Some(b'\'') => break,
                            Some(b) => w.push(Ch::Lit { b, quoted: true }),
                        }
                    }
                }
                Some(b'"') => {
                    c.bump();
                    self.dquote(c, &mut w, depth)?;
                }
                Some(b'`') => {
                    c.bump();
                    let inner = backquoted(c)?;
                    self.script(&inner, depth + 1)?;
                    w.push(Ch::Unknown);
                }
                Some(b'$') => self.dollar(c, &mut w, depth, false)?,
                Some(b) => {
                    c.bump();
                    w.push(Ch::Lit { b, quoted: false });
                }
            }
        }
        Ok(w)
    }

    /// An array assignment's elements, after its `(`, through its `)`.
    fn array_elements(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        self.nested(|a| a.array_elements_in(c, depth))
    }

    fn array_elements_in(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        loop {
            self.tick(1)?;
            match c.peek() {
                None => return Err(Amb),
                Some(b')') => {
                    c.bump();
                    return Ok(());
                }
                Some(b' ' | b'\t' | b'\n' | b'\r') => {
                    c.bump();
                }
                Some(b) if is_meta(b) || b == b'(' => return Err(Amb),
                Some(_) => {
                    self.word(c, depth)?;
                }
            }
        }
    }

    /// A double-quoted string's contents, after its `"`, through its `"`.
    fn dquote(&mut self, c: &mut Cur<'_>, w: &mut Word, depth: usize) -> Result<(), Amb> {
        self.nested(|a| a.dquote_in(c, w, depth))
    }

    fn dquote_in(&mut self, c: &mut Cur<'_>, w: &mut Word, depth: usize) -> Result<(), Amb> {
        loop {
            self.tick(1)?;
            match c.bump() {
                None => return Err(Amb),
                Some(b'"') => return Ok(()),
                Some(b'\\') => match c.peek() {
                    Some(b @ (b'$' | b'`' | b'"' | b'\\')) => {
                        c.bump();
                        w.push(Ch::Lit { b, quoted: true });
                    }
                    Some(b'\n') => {
                        c.bump();
                    }
                    _ => w.push(Ch::Lit {
                        b: b'\\',
                        quoted: true,
                    }),
                },
                Some(b'$') => {
                    c.i -= 1;
                    self.dollar(c, w, depth, true)?;
                }
                Some(b'`') => {
                    let inner = backquoted(c)?;
                    self.script(&inner, depth + 1)?;
                    w.push(Ch::Unknown);
                }
                Some(0) => w.push(Ch::Unknown),
                Some(b) => w.push(Ch::Lit { b, quoted: true }),
            }
        }
    }

    /// A `$` at `c`: an expansion, a `$'...'` or `$"..."` string, or a `$`
    /// standing for itself.
    fn dollar(
        &mut self,
        c: &mut Cur<'_>,
        w: &mut Word,
        depth: usize,
        in_dquote: bool,
    ) -> Result<(), Amb> {
        self.nested(|a| a.dollar_in(c, w, depth, in_dquote))
    }

    fn dollar_in(
        &mut self,
        c: &mut Cur<'_>,
        w: &mut Word,
        depth: usize,
        in_dquote: bool,
    ) -> Result<(), Amb> {
        c.bump();
        match c.peek() {
            Some(b'\'') if !in_dquote => {
                c.bump();
                ansi_c(c, w)?;
            }
            Some(b'"') if !in_dquote => {
                c.bump();
                self.dquote(c, w, depth)?;
            }
            Some(b'(') => {
                if c.peek_at(1) == Some(b'(') {
                    c.i += 2;
                    self.arith(c, depth)?;
                } else {
                    c.bump();
                    self.list(c, Stop::Paren, depth + 1)?;
                }
                w.push(Ch::Unknown);
            }
            Some(b'{') => {
                c.bump();
                self.brace_param(c, depth)?;
                w.push(Ch::Unknown);
            }
            Some(b'[') => {
                // `$[...]`, bash's old arithmetic.
                c.bump();
                let mut level = 0usize;
                loop {
                    match c.bump() {
                        None | Some(b'$' | b'`') => return Err(Amb),
                        Some(b'[') => level += 1,
                        Some(b']') if level == 0 => break,
                        Some(b']') => level -= 1,
                        Some(_) => {}
                    }
                }
                w.push(Ch::Unknown);
            }
            Some(b) if b.is_ascii_alphabetic() || b == b'_' => {
                while matches!(c.peek(), Some(b) if b.is_ascii_alphanumeric() || b == b'_') {
                    c.bump();
                }
                w.push(Ch::Unknown);
            }
            Some(b) if b.is_ascii_digit() || b"@*#?$!-".contains(&b) => {
                c.bump();
                w.push(Ch::Unknown);
            }
            _ => w.push(Ch::Lit {
                b: b'$',
                quoted: in_dquote,
            }),
        }
        Ok(())
    }

    /// `${...}` after its `{`, through its `}`.
    fn brace_param(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        self.nested(|a| a.brace_param_in(c, depth))
    }

    fn brace_param_in(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        let mut level = 0usize;
        loop {
            self.tick(1)?;
            match c.peek() {
                None => return Err(Amb),
                Some(b'}') => {
                    c.bump();
                    if level == 0 {
                        return Ok(());
                    }
                    level -= 1;
                }
                Some(b'{') => {
                    c.bump();
                    level += 1;
                }
                Some(b'\\') => {
                    c.bump();
                    if c.bump().is_none() {
                        return Err(Amb);
                    }
                }
                Some(b'\'') => {
                    c.bump();
                    loop {
                        match c.bump() {
                            None => return Err(Amb),
                            Some(b'\'') => break,
                            Some(_) => {}
                        }
                    }
                }
                Some(b'"') => {
                    c.bump();
                    let mut tmp = Vec::new();
                    self.dquote(c, &mut tmp, depth)?;
                }
                Some(b'$') => {
                    let mut tmp = Vec::new();
                    self.dollar(c, &mut tmp, depth, true)?;
                }
                Some(b'`') => {
                    c.bump();
                    let inner = backquoted(c)?;
                    self.script(&inner, depth + 1)?;
                }
                Some(_) => {
                    c.bump();
                }
            }
        }
    }

    /// Arithmetic after its `((`, through its `))`: no command, but a
    /// substitution in it runs.
    fn arith(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        self.nested(|a| a.arith_in(c, depth))
    }

    fn arith_in(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        let mut level = 0usize;
        loop {
            self.tick(1)?;
            match c.peek() {
                None | Some(b'\'' | b'"') => return Err(Amb),
                Some(b'(') => {
                    c.bump();
                    level += 1;
                }
                Some(b')') => {
                    c.bump();
                    if level == 0 {
                        if c.peek() == Some(b')') {
                            c.bump();
                            return Ok(());
                        }
                        return Err(Amb);
                    }
                    level -= 1;
                }
                Some(b'$') => {
                    let mut tmp = Vec::new();
                    self.dollar(c, &mut tmp, depth, true)?;
                }
                Some(b'`') => {
                    c.bump();
                    let inner = backquoted(c)?;
                    self.script(&inner, depth + 1)?;
                }
                Some(_) => {
                    c.bump();
                }
            }
        }
    }

    /// After `for` or `select`: the name, and the words after `in`, which
    /// are data.
    fn for_header(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        skip_blanks(c);
        if c.starts_with(b"((") {
            c.i += 2;
            return self.arith(c, depth);
        }
        let name = self.word(c, depth)?;
        if plain(&name).is_none_or(|n| n.is_empty()) {
            return Err(Amb);
        }
        skip_blanks_and_newlines(c);
        if !at_reserved(c, b"in") {
            return Ok(());
        }
        c.i += 2;
        loop {
            self.tick(1)?;
            skip_blanks(c);
            match c.peek() {
                None | Some(b'\n') => return Ok(()),
                Some(b';') => {
                    c.bump();
                    return Ok(());
                }
                Some(b) if is_meta(b) || b == b'(' => return Err(Amb),
                Some(_) => {
                    self.word(c, depth)?;
                }
            }
        }
    }

    /// After `case`: the subject, `in`, and each item's patterns and
    /// commands, through `esac`.
    fn case(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        skip_blanks(c);
        self.word(c, depth)?;
        skip_blanks_and_newlines(c);
        if !at_reserved(c, b"in") {
            return Err(Amb);
        }
        c.i += 2;
        loop {
            self.tick(1)?;
            skip_blanks_and_newlines(c);
            if c.peek() == Some(b'#') {
                while !matches!(c.peek(), None | Some(b'\n')) {
                    c.bump();
                }
                continue;
            }
            if at_reserved(c, b"esac") {
                c.i += 4;
                return Ok(());
            }
            if c.peek().is_none() {
                return Err(Amb);
            }
            if c.peek() == Some(b'(') {
                c.bump();
            }
            // The patterns, up to the `)`.
            loop {
                self.tick(1)?;
                skip_blanks(c);
                match c.peek() {
                    Some(b')') => {
                        c.bump();
                        break;
                    }
                    Some(b'|') => {
                        c.bump();
                    }
                    None => return Err(Amb),
                    Some(b) if is_meta(b) || b == b'(' => return Err(Amb),
                    Some(_) => {
                        self.word(c, depth)?;
                    }
                }
            }
            self.list(c, Stop::CaseItem, depth + 1)?;
        }
    }

    /// After `function`: the name, and `()` if it follows.
    fn function_header(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        skip_blanks(c);
        let name = self.word(c, depth)?;
        if name.is_empty() {
            return Err(Amb);
        }
        skip_blanks(c);
        if c.peek() == Some(b'(') && !fn_parens(c) {
            return Err(Amb);
        }
        Ok(())
    }

    /// After `[[`: words and operators, which are data, through `]]`.
    fn cond(&mut self, c: &mut Cur<'_>, depth: usize) -> Result<(), Amb> {
        loop {
            self.tick(1)?;
            skip_blanks(c);
            if at_reserved(c, b"]]") {
                c.i += 2;
                return Ok(());
            }
            match c.peek() {
                None | Some(b';') => return Err(Amb),
                Some(b'\n' | b'(' | b')' | b'<' | b'>' | b'!' | b'&' | b'|') => {
                    c.bump();
                }
                Some(_) => {
                    self.word(c, depth)?;
                }
            }
        }
    }

    /// Looks at every command read, and at what they run.
    fn classify_all(&mut self) -> Result<(), Amb> {
        let mut i = 0;
        while i < self.cmds.len() {
            self.tick(1)?;
            let cmd = self.cmds[i].clone();
            let bodies: Vec<(Vec<u8>, bool)> = self
                .bodies
                .iter()
                .filter(|(id, _, _)| *id == cmd.id)
                .map(|(_, b, q)| (b.clone(), *q))
                .collect();
            self.classify(&cmd, &bodies)?;
            i += 1;
        }
        Ok(())
    }

    fn classify(&mut self, cmd: &Cmd, bodies: &[(Vec<u8>, bool)]) -> Result<(), Amb> {
        for r in &cmd.redirs {
            if r.kind == RedirKind::Read && dotenv(&r.target) == Tri::Is {
                self.found.push(Class::EnvFile);
            }
            if names_environ(&r.target) {
                self.found.push(Class::EnvDump);
            }
        }
        let mut words = Vec::new();
        let mut cost = BraceCost::default();
        for w in &cmd.words {
            words.extend(brace_expand(w, &mut cost, 0)?);
        }
        self.tick(cost.made.saturating_add(cost.steps))?;
        let start = words
            .iter()
            .position(|w| !is_assignment(w))
            .unwrap_or(words.len());
        self.run(&words[start..], bodies, cmd.depth)
    }

    /// What `words`, a command and its arguments, runs.
    fn run(&mut self, words: &[Word], bodies: &[(Vec<u8>, bool)], depth: usize) -> Result<(), Amb> {
        self.tick(1)?;
        if depth > MAX_DEPTH {
            return Err(Amb);
        }
        let Some((w0, args)) = words.split_first() else {
            return Ok(());
        };
        if args.iter().any(names_environ) || names_environ(w0) {
            self.found.push(Class::EnvDump);
        }
        let Some(name) = command_name(w0)? else {
            return Ok(());
        };
        let next = depth + 1;
        match name.as_slice() {
            b"command" => {
                let mut i = 0;
                while let Some(o) = args.get(i).and_then(|a| plain(a)) {
                    if !o.starts_with(b"-") || o == b"-" {
                        break;
                    }
                    i += 1;
                    if o == b"--" {
                        break;
                    }
                    if o.contains(&b'v') || o.contains(&b'V') {
                        return Ok(());
                    }
                }
                self.run(&args[i..], bodies, next)
            }
            b"builtin" | b"nohup" | b"setsid" | b"unbuffer" | b"busybox" => {
                let i = skip_flags(args, &[]);
                self.run(&args[i..], bodies, next)
            }
            b"exec" => {
                let i = skip_flags(args, &[b"-a"]);
                self.run(&args[i..], bodies, next)
            }
            b"time" => {
                let i = skip_flags(args, &[b"-f", b"--format", b"-o", b"--output"]);
                self.run(&args[i..], bodies, next)
            }
            b"nice" => {
                let i = skip_flags(args, &[b"-n", b"--adjustment"]);
                self.run(&args[i..], bodies, next)
            }
            b"stdbuf" => {
                let i = skip_flags(args, &[b"-i", b"-o", b"-e"]);
                self.run(&args[i..], bodies, next)
            }
            b"caffeinate" => {
                let i = skip_flags(args, &[b"-t", b"-w"]);
                self.run(&args[i..], bodies, next)
            }
            b"ionice" => {
                let i = skip_flags(args, &[b"-c", b"-n", b"-p", b"-P", b"-u"]);
                self.run(&args[i..], bodies, next)
            }
            b"timeout" => {
                let i = skip_flags(args, &[b"-s", b"--signal", b"-k", b"--kill-after"]);
                // Then the duration.
                let i = (i + 1).min(args.len());
                self.run(&args[i..], bodies, next)
            }
            b"sudo" => {
                let i = skip_flags(
                    args,
                    &[
                        b"-u",
                        b"-g",
                        b"-C",
                        b"-D",
                        b"-h",
                        b"-p",
                        b"-r",
                        b"-t",
                        b"-U",
                        b"-T",
                        b"--user",
                        b"--group",
                        b"--chdir",
                        b"--prompt",
                        b"--role",
                        b"--type",
                        b"--other-user",
                        b"--command-timeout",
                        b"--close-from",
                        b"--host",
                    ],
                );
                let rest = &args[i..];
                let skip = rest.iter().take_while(|w| is_assignment(w)).count();
                self.run(&rest[skip..], bodies, next)
            }
            b"doas" => {
                let i = skip_flags(args, &[b"-u", b"-C"]);
                self.run(&args[i..], bodies, next)
            }
            b"env" => self.env(args, bodies, next),
            b"xargs" => self.xargs(args, next),
            b"watch" => {
                let mut i = 0;
                let mut exec_form = false;
                while let Some(o) = args.get(i).and_then(|a| plain(a)) {
                    if !o.starts_with(b"-") {
                        break;
                    }
                    i += 1;
                    if o == b"--" {
                        break;
                    }
                    if o == b"-x" || o == b"--exec" {
                        exec_form = true;
                    } else if [&b"-n"[..], b"--interval", b"-q", b"--equexit"]
                        .contains(&o.as_slice())
                    {
                        i += 1;
                    }
                }
                let rest = args.get(i..).unwrap_or(&[]);
                if exec_form {
                    self.run(rest, bodies, next)
                } else {
                    self.script(&joined(rest), next)
                }
            }
            b"eval" => self.script(&joined(args), next),
            b"sh" | b"bash" | b"zsh" | b"dash" | b"ksh" | b"mksh" | b"ash" | b"yash" | b"posh"
            | b"fish" | b"rbash" | b"ksh93" | b"pdksh" | b"oksh" => self.shell(args, bodies, next),
            b"source" | b"." => {
                if args.first().is_some_and(|f| dotenv(f) == Tri::Is) {
                    self.found.push(Class::EnvFile);
                }
                Ok(())
            }
            b"printenv" => {
                self.found.push(Class::EnvDump);
                Ok(())
            }
            b"export" => {
                let operands = args.iter().filter(|a| !is_option(a)).count();
                let flags = option_chars(args);
                if operands == 0 && !flags.contains(&b'f') && !flags.contains(&b'n') {
                    self.found.push(Class::EnvDump);
                }
                Ok(())
            }
            b"set" => {
                if args.is_empty() {
                    self.found.push(Class::EnvDump);
                }
                Ok(())
            }
            b"declare" | b"typeset" | b"local" | b"readonly" => {
                let operands = args.iter().filter(|a| !is_option(a)).count();
                let flags = option_chars(args);
                let functions_only =
                    !flags.is_empty() && flags.iter().all(|f| *f == b'f' || *f == b'F');
                if (operands == 0 && !functions_only) || flags.contains(&b'p') {
                    self.found.push(Class::EnvDump);
                }
                Ok(())
            }
            b"ps" => {
                for a in args {
                    let Some(o) = plain(a) else { continue };
                    let bsd = !o.starts_with(b"-") && o.contains(&b'e');
                    let mac = o.starts_with(b"-") && !o.starts_with(b"--") && o.contains(&b'E');
                    if bsd || mac {
                        self.found.push(Class::EnvDump);
                    }
                }
                Ok(())
            }
            b"envcloak" => {
                for a in args {
                    match plain(a) {
                        Some(o) if o.starts_with(b"-") => continue,
                        Some(o) if o == b"reveal" => self.found.push(Class::Reveal),
                        Some(o) if o == b"approve" => self.found.push(Class::Approve),
                        Some(_) => {}
                        None => return Err(Amb),
                    }
                    break;
                }
                Ok(())
            }
            b"find" => self.find(args, next),
            b"dd" => {
                let reads_env = args.iter().any(|a| {
                    a.len() > 3
                        && a[..3]
                            == [
                                Ch::Lit {
                                    b: b'i',
                                    quoted: false,
                                },
                                Ch::Lit {
                                    b: b'f',
                                    quoted: false,
                                },
                                Ch::Lit {
                                    b: b'=',
                                    quoted: false,
                                },
                            ]
                        && dotenv(&a[3..]) == Tri::Is
                });
                if reads_env {
                    self.found.push(Class::EnvFile);
                }
                Ok(())
            }
            other => {
                if let Some(spec) = reader(other) {
                    if reads_env_file(&spec, args) {
                        self.found.push(Class::EnvFile);
                    }
                }
                Ok(())
            }
        }
    }

    /// `env [options] [NAME=VALUE]... [command]`: with no command, it
    /// prints the environment.
    fn env(&mut self, args: &[Word], bodies: &[(Vec<u8>, bool)], depth: usize) -> Result<(), Amb> {
        let mut i = 0;
        while let Some(a) = args.get(i) {
            let Some(o) = plain(a) else {
                if is_assignment(a) {
                    break;
                }
                return Err(Amb);
            };
            if o == b"--" {
                i += 1;
                break;
            }
            if o == b"-" {
                i += 1;
                continue;
            }
            if !o.starts_with(b"-") {
                break;
            }
            i += 1;
            match o.as_slice() {
                b"-u" | b"--unset" | b"-C" | b"--chdir" | b"-P" => i += 1,
                b"-S" | b"--split-string" => {
                    let s = args.get(i).ok_or(Amb)?;
                    let mut text = joined(std::slice::from_ref(s));
                    for rest in args.get(i + 1..).unwrap_or(&[]) {
                        text.push(b' ');
                        text.extend(joined(std::slice::from_ref(rest)));
                    }
                    return self.script(&text, depth);
                }
                _ if o.starts_with(b"--split-string=") || (o.starts_with(b"-S") && o.len() > 2) => {
                    let cut = if o.starts_with(b"-S") { 2 } else { 15 };
                    let mut text = o[cut..].to_vec();
                    for rest in args.get(i..).unwrap_or(&[]) {
                        text.push(b' ');
                        text.extend(joined(std::slice::from_ref(rest)));
                    }
                    return self.script(&text, depth);
                }
                _ => {}
            }
        }
        let rest = args.get(i..).unwrap_or(&[]);
        let skip = rest.iter().take_while(|w| is_assignment(w)).count();
        let rest = &rest[skip..];
        if rest.is_empty() {
            self.found.push(Class::EnvDump);
            return Ok(());
        }
        self.run(rest, bodies, depth)
    }

    /// `xargs [options] [command]`: the command runs with arguments read
    /// from its input (or from `-a FILE`).
    fn xargs(&mut self, args: &[Word], depth: usize) -> Result<(), Amb> {
        let mut i = 0;
        while let Some(o) = args.get(i).and_then(|a| plain(a)) {
            if !o.starts_with(b"-") || o == b"-" {
                break;
            }
            i += 1;
            if o == b"--" {
                break;
            }
            match o.as_slice() {
                b"-a" | b"--arg-file" => {
                    if args.get(i).is_some_and(|f| dotenv(f) == Tri::Is) {
                        self.found.push(Class::EnvFile);
                    }
                    i += 1;
                }
                b"-d" | b"--delimiter" | b"-E" | b"-I" | b"-L" | b"-n" | b"--max-args" | b"-P"
                | b"--max-procs" | b"-s" | b"--max-chars" | b"-J" | b"-R" | b"-S" => i += 1,
                _ if o.starts_with(b"--arg-file=") && dotenv(&lits(&o[11..])) == Tri::Is => {
                    self.found.push(Class::EnvFile);
                }
                _ => {}
            }
        }
        self.run(args.get(i..).unwrap_or(&[]), &[], depth)
    }

    /// A shell: with `-c`, its script; reading its standard input, a
    /// here-document's body is its script.
    fn shell(
        &mut self,
        args: &[Word],
        bodies: &[(Vec<u8>, bool)],
        depth: usize,
    ) -> Result<(), Amb> {
        let mut i = 0;
        let mut dash_c = false;
        while let Some(o) = args.get(i).and_then(|a| plain(a)) {
            if !(o.starts_with(b"-") || o.starts_with(b"+")) || o == b"-" || o == b"+" {
                break;
            }
            i += 1;
            if o == b"--" {
                break;
            }
            if o.starts_with(b"--") {
                if [&b"--rcfile"[..], b"--init-file"].contains(&o.as_slice()) {
                    i += 1;
                }
                if o == b"--command" {
                    dash_c = true;
                }
                continue;
            }
            if o[1..].contains(&b'c') {
                dash_c = true;
            }
            if o[1..].contains(&b'o') || o[1..].contains(&b'O') {
                i += 1;
            }
        }
        if dash_c {
            let s = args.get(i).ok_or(Amb)?;
            return self.script(&joined(std::slice::from_ref(s)), depth);
        }
        if args.get(i).is_some() {
            // A script file: its contents are not read here.
            return Ok(());
        }
        for (body, _) in bodies {
            self.script(body, depth)?;
        }
        Ok(())
    }

    /// `find ... -exec cmd {} ;`: the command runs on the files found,
    /// which are env files when a `-name` or `-path` test could match one.
    fn find(&mut self, args: &[Word], depth: usize) -> Result<(), Amb> {
        let mut names_env = false;
        let mut i = 0;
        while i < args.len() {
            let o = plain(&args[i]);
            i += 1;
            match o.as_deref() {
                Some(
                    b"-name" | b"-iname" | b"-path" | b"-ipath" | b"-wholename" | b"-iwholename",
                ) => {
                    if let Some(p) = args.get(i) {
                        // A find pattern is a glob, quoted or not.
                        let pat: Word = p
                            .iter()
                            .map(|ch| match ch {
                                Ch::Lit { b, .. } => Ch::Lit {
                                    b: *b,
                                    quoted: false,
                                },
                                Ch::Unknown => Ch::Unknown,
                            })
                            .collect();
                        if dotenv(&pat) != Tri::Not {
                            names_env = true;
                        }
                    }
                    i += 1;
                }
                Some(b"-regex" | b"-iregex") => {
                    if let Some(p) = args.get(i) {
                        let text = joined(std::slice::from_ref(p));
                        if text.windows(3).any(|w| w == b"env") {
                            names_env = true;
                        }
                    }
                    i += 1;
                }
                Some(b"-exec" | b"-execdir" | b"-ok" | b"-okdir") => {
                    let start = i;
                    while i < args.len() && !matches!(plain(&args[i]).as_deref(), Some(b";" | b"+"))
                    {
                        i += 1;
                    }
                    let sub: Vec<Word> = args[start..i]
                        .iter()
                        .map(|w| {
                            if names_env && plain(w).as_deref() == Some(b"{}") {
                                lits(b".env")
                            } else {
                                w.clone()
                            }
                        })
                        .collect();
                    self.run(&sub, &[], depth)?;
                    i += 1;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Whether `w` is a whole word that is one of the shell's reserved words,
/// at `c` (followed by a blank, a newline, a metacharacter or the end).
fn at_reserved(c: &Cur<'_>, w: &[u8]) -> bool {
    c.starts_with(w)
        && match c.s.get(c.i + w.len()) {
            None => true,
            Some(&b) => is_meta(b) || b == b'(',
        }
}

/// `()` at `c`, with blanks between, consumed.
fn fn_parens(c: &mut Cur<'_>) -> bool {
    let save = c.i;
    if c.peek() != Some(b'(') {
        return false;
    }
    c.bump();
    skip_blanks(c);
    if c.peek() == Some(b')') {
        c.bump();
        true
    } else {
        c.i = save;
        false
    }
}

fn skip_blanks(c: &mut Cur<'_>) {
    while matches!(c.peek(), Some(b' ' | b'\t' | b'\r')) {
        c.bump();
    }
}

fn skip_blanks_and_newlines(c: &mut Cur<'_>) {
    while matches!(c.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        c.bump();
    }
}

/// The characters that end an unquoted word.
fn is_meta(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b')'
    )
}

/// A backquoted command after its opening backquote, through the closing
/// one, with the backslashes that quote `` ` ``, `\` and `$` removed.
fn backquoted(c: &mut Cur<'_>) -> Result<Vec<u8>, Amb> {
    let mut out = Vec::new();
    loop {
        match c.bump() {
            None => return Err(Amb),
            Some(b'`') => return Ok(out),
            Some(b'\\') => match c.bump() {
                None => return Err(Amb),
                Some(b @ (b'`' | b'\\' | b'$')) => out.push(b),
                Some(b) => {
                    out.push(b'\\');
                    out.push(b);
                }
            },
            Some(b) => out.push(b),
        }
    }
}

/// A `$'...'` string after its `$'`, through its `'`, decoded.
fn ansi_c(c: &mut Cur<'_>, w: &mut Word) -> Result<(), Amb> {
    let push = |w: &mut Word, b: u8| w.push(Ch::Lit { b, quoted: true });
    loop {
        match c.bump() {
            None => return Err(Amb),
            Some(b'\'') => return Ok(()),
            Some(b'\\') => {
                let Some(e) = c.bump() else {
                    return Err(Amb);
                };
                match e {
                    b'a' => push(w, 7),
                    b'b' => push(w, 8),
                    b'e' | b'E' => push(w, 27),
                    b'f' => push(w, 12),
                    b'n' => push(w, b'\n'),
                    b'r' => push(w, b'\r'),
                    b't' => push(w, b'\t'),
                    b'v' => push(w, 11),
                    b'\\' | b'\'' | b'"' | b'?' => push(w, e),
                    b'c' => {
                        let Some(x) = c.bump() else {
                            return Err(Amb);
                        };
                        push(w, x & 0x1f);
                    }
                    b'x' => match hex_digits(c, 2) {
                        Some(v) => push(w, u8::try_from(v).map_err(|_| Amb)?),
                        None => {
                            push(w, b'\\');
                            push(w, b'x');
                        }
                    },
                    b'u' | b'U' => {
                        let n = if e == b'u' { 4 } else { 8 };
                        let v = hex_digits(c, n).ok_or(Amb)?;
                        let ch = char::from_u32(v).ok_or(Amb)?;
                        let mut buf = [0u8; 4];
                        for &b in ch.encode_utf8(&mut buf).as_bytes() {
                            push(w, b);
                        }
                    }
                    b'0'..=b'7' => {
                        let mut v = u32::from(e - b'0');
                        for _ in 0..2 {
                            match c.peek() {
                                Some(d @ b'0'..=b'7') => {
                                    c.bump();
                                    v = v * 8 + u32::from(d - b'0');
                                }
                                _ => break,
                            }
                        }
                        push(w, u8::try_from(v & 0xff).map_err(|_| Amb)?);
                    }
                    other => {
                        push(w, b'\\');
                        push(w, other);
                    }
                }
            }
            Some(b) => push(w, b),
        }
    }
}

/// Up to `n` hexadecimal digits at `c`, at least one.
fn hex_digits(c: &mut Cur<'_>, n: usize) -> Option<u32> {
    let mut v: u32 = 0;
    let mut k = 0;
    while k < n {
        let Some(d) = c.peek().and_then(|b| char::from(b).to_digit(16)) else {
            break;
        };
        c.bump();
        v = v.checked_mul(16)?.checked_add(d)?;
        k += 1;
    }
    (k > 0).then_some(v)
}

/// The bytes of a word that is all literal, quoted or not.
fn literal(w: &[Ch]) -> Option<Vec<u8>> {
    w.iter()
        .map(|ch| match ch {
            Ch::Lit { b, .. } => Some(*b),
            Ch::Unknown => None,
        })
        .collect()
}

/// The bytes of a word that is all literal and holds no unquoted glob
/// character: what the shell passes as it is.
fn plain(w: &[Ch]) -> Option<Vec<u8>> {
    w.iter()
        .enumerate()
        .map(|(i, ch)| match ch {
            Ch::Lit { .. } if glob_at(w, i) => None,
            Ch::Lit { b, .. } => Some(*b),
            Ch::Unknown => None,
        })
        .collect()
}

/// Whether the character at `i` is an unquoted glob character: `*`, `?`,
/// or a `[` that an unquoted `]` closes later in the word (a lone `[`, as
/// the test command, is itself).
fn glob_at(w: &[Ch], i: usize) -> bool {
    match w.get(i) {
        Some(Ch::Lit {
            b: b'*' | b'?',
            quoted: false,
        }) => true,
        Some(Ch::Lit {
            b: b'[',
            quoted: false,
        }) => w[i + 1..].iter().any(|ch| {
            *ch == Ch::Lit {
                b: b']',
                quoted: false,
            }
        }),
        _ => false,
    }
}

/// A word with no quoted character: what a reserved word must be.
fn is_bare(w: &[Ch]) -> bool {
    w.iter()
        .all(|ch| matches!(ch, Ch::Lit { quoted: false, .. }))
}

fn lits(s: &[u8]) -> Word {
    s.iter().map(|&b| Ch::Lit { b, quoted: true }).collect()
}

/// Words as one script text, with a NUL byte, which no shell text holds,
/// standing for each stretch only known when it runs, which
/// [`Analyzer::word`] reads back as one.
fn joined(words: &[Word]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, w) in words.iter().enumerate() {
        if k > 0 {
            out.push(b' ');
        }
        for ch in w {
            match ch {
                Ch::Lit { b, .. } => out.push(*b),
                Ch::Unknown => out.push(0),
            }
        }
    }
    out
}

/// A word that is a descriptor number before a redirection (`2>`, `0<`),
/// or `{name}`.
fn is_fd_prefix(w: &[Ch]) -> bool {
    if !is_bare(w) {
        return false;
    }
    match plain(w) {
        Some(b) if !b.is_empty() && b.iter().all(u8::is_ascii_digit) => true,
        Some(b) => {
            b.len() > 2
                && b.starts_with(b"{")
                && b.ends_with(b"}")
                && b[1..b.len() - 1]
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        }
        None => false,
    }
}

/// `name=`, `name+=` or `name[...]=` making up a whole word, unquoted.
fn is_assignment_prefix(w: &[Ch]) -> bool {
    let lit = |k: usize| match w.get(k) {
        Some(Ch::Lit { b, quoted: false }) => Some(*b),
        _ => None,
    };
    match lit(0) {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    let mut i = 0;
    while let Some(b) = lit(i) {
        if b.is_ascii_alphanumeric() || b == b'_' {
            i += 1;
        } else {
            break;
        }
    }
    if lit(i) == Some(b'[') {
        while let Some(b) = lit(i) {
            i += 1;
            if b == b']' {
                break;
            }
        }
    }
    if lit(i) == Some(b'+') {
        i += 1;
    }
    lit(i) == Some(b'=') && i + 1 == w.len()
}

/// A variable assignment word (`NAME=value`).
fn is_assignment(w: &Word) -> bool {
    w.iter()
        .position(|ch| {
            matches!(
                ch,
                Ch::Lit {
                    b: b'=',
                    quoted: false
                }
            )
        })
        .is_some_and(|eq| is_assignment_prefix(&w[..=eq]))
}

fn is_option(w: &Word) -> bool {
    plain(w).is_some_and(|o| o.len() > 1 && (o.starts_with(b"-") || o.starts_with(b"+")))
}

/// The letters of a command's single-dash options.
fn option_chars(args: &[Word]) -> Vec<u8> {
    args.iter()
        .filter_map(|a| plain(a))
        .filter(|o| {
            o.len() > 1 && (o.starts_with(b"-") || o.starts_with(b"+")) && !o.starts_with(b"--")
        })
        .flat_map(|o| o[1..].to_vec())
        .collect()
}

/// How many leading words are options, `valued` naming the ones that take
/// the next word as their value.
fn skip_flags(args: &[Word], valued: &[&[u8]]) -> usize {
    let mut i = 0;
    while let Some(o) = args.get(i).and_then(|a| plain(a)) {
        if !o.starts_with(b"-") || o == b"-" {
            break;
        }
        i += 1;
        if o == b"--" {
            break;
        }
        if valued.contains(&o.as_slice()) {
            i += 1;
        }
    }
    i.min(args.len())
}

/// The name a command word runs: its last path component. `None` for an
/// empty word; [`Amb`] when the name is only known when it runs.
fn command_name(w: &[Ch]) -> Result<Option<Vec<u8>>, Amb> {
    if w.is_empty() {
        return Ok(None);
    }
    let start = w
        .iter()
        .rposition(|ch| matches!(ch, Ch::Lit { b: b'/', .. }))
        .map_or(0, |p| p + 1);
    let name = plain(&w[start..]).ok_or(Amb)?;
    if name.is_empty() || name.contains(&0) {
        return Err(Amb);
    }
    Ok(Some(name))
}

/// Whether a path is, may be, or is not an env file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    Is,
    Maybe,
    Not,
}

/// Whether the path `w` names an env file, by its last component: an env
/// file or a name `dotenv_kind` cannot read (`.env.` and the like), not a
/// template. A glob that could match one counts (a leading `*`, `?` or
/// `[` never matches a leading `.`, as the shell's default has it); a name
/// only known when it runs may be one.
fn dotenv(w: &[Ch]) -> Tri {
    let start = w
        .iter()
        .rposition(|ch| matches!(ch, Ch::Lit { b: b'/', .. }))
        .map_or(0, |p| p + 1);
    let tail = &w[start..];
    if tail.is_empty() {
        return Tri::Not;
    }
    if let Some(name) = plain(tail) {
        return match dotenv_kind(OsStr::from_bytes(&name)) {
            Some(Ok(FileKind::Dotenv { .. }) | Err(())) => Tri::Is,
            _ => Tri::Not,
        };
    }
    let mut prefix = Vec::new();
    let mut unknown = false;
    for (i, ch) in tail.iter().enumerate() {
        match ch {
            Ch::Lit { .. } if glob_at(tail, i) => break,
            Ch::Lit { b, .. } => prefix.push(*b),
            Ch::Unknown => {
                unknown = true;
                break;
            }
        }
    }
    if prefix.is_empty() {
        return if unknown { Tri::Maybe } else { Tri::Not };
    }
    let fits = b".env".starts_with(&prefix) || prefix.starts_with(b".env");
    match (fits, unknown) {
        (false, _) => Tri::Not,
        (true, false) => Tri::Is,
        (true, true) => Tri::Maybe,
    }
}

/// Whether the path `w` names a process's environment,
/// `/proc/<pid>/environ` (any pid, a glob or a variable included).
fn names_environ(w: &Word) -> bool {
    let text: Vec<u8> = w
        .iter()
        .map(|ch| match ch {
            Ch::Lit { b, .. } => *b,
            Ch::Unknown => b'*',
        })
        .collect();
    if !text.windows(6).any(|x| x == b"/proc/") && !text.starts_with(b"proc/") {
        return false;
    }
    let tail = text.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    glob_match(tail, b"environ")
}

/// Whether the glob `pat` (`*`, `?`, `[set]`) matches `name`, `*` and `?`
/// matching any byte, a leading `.` included (as search tools' globs do).
pub fn glob_matches(pat: &[u8], name: &[u8]) -> bool {
    glob_match(pat, name)
}

/// Whether the glob `pat` (`*`, `?`, `[set]`) matches `name`.
fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    fn go(p: &[u8], n: &[u8], budget: &mut usize) -> bool {
        if *budget == 0 {
            return true;
        }
        *budget -= 1;
        match p.split_first() {
            None => n.is_empty(),
            Some((b'*', rest)) => (0..=n.len()).any(|k| go(rest, &n[k..], budget)),
            Some((b'?', rest)) => !n.is_empty() && go(rest, &n[1..], budget),
            Some((b'[', rest)) => {
                let Some(end) = rest.iter().position(|&b| b == b']') else {
                    return n.first() == Some(&b'[') && go(rest, &n[1..], budget);
                };
                let (set, after) = (&rest[..end], &rest[end + 1..]);
                let Some((&c, nrest)) = n.split_first() else {
                    return false;
                };
                let (neg, set) = match set.split_first() {
                    Some((b'!' | b'^', s)) => (true, s),
                    _ => (false, set),
                };
                let mut hit = false;
                let mut k = 0;
                while k < set.len() {
                    if k + 2 < set.len() && set[k + 1] == b'-' {
                        hit |= set[k] <= c && c <= set[k + 2];
                        k += 3;
                    } else {
                        hit |= set[k] == c;
                        k += 1;
                    }
                }
                hit != neg && go(after, nrest, budget)
            }
            Some((&b, rest)) => n.first() == Some(&b) && go(rest, &n[1..], budget),
        }
    }
    let mut budget = 100_000;
    go(pat, name, &mut budget)
}

/// Brace expansion of an unquoted `{a,b}` (each alternative a word) and
/// `{x..y}` (read as any text, like `*`), up to [`MAX_EXPANSIONS`] words.
/// What one command's brace expansions have cost: the words made and the
/// characters scanned and copied, both capped.
#[derive(Debug, Default)]
struct BraceCost {
    made: usize,
    steps: usize,
}

impl BraceCost {
    fn step(&mut self, n: usize) -> Result<(), Amb> {
        self.steps = self.steps.saturating_add(n);
        if self.steps > MAX_WORK {
            Err(Amb)
        } else {
            Ok(())
        }
    }
}

/// The deepest brace groups one word's expansion follows: more than
/// enough for [`MAX_EXPANSIONS`] words, so deeper ends ambiguous rather
/// than deep on the stack.
const MAX_BRACE_GROUPS: usize = 64;

fn brace_expand(w: &Word, cost: &mut BraceCost, groups: usize) -> Result<Vec<Word>, Amb> {
    if groups > MAX_BRACE_GROUPS {
        return Err(Amb);
    }
    let is = |ch: &Ch, c: u8| {
        *ch == Ch::Lit {
            b: c,
            quoted: false,
        }
    };
    for i in 0..w.len() {
        if !is(&w[i], b'{') {
            continue;
        }
        let mut level = 0usize;
        let mut commas = Vec::new();
        let mut end = None;
        for (j, ch) in w.iter().enumerate().skip(i + 1) {
            if is(ch, b'{') {
                level += 1;
            } else if is(ch, b'}') {
                if level == 0 {
                    end = Some(j);
                    break;
                }
                level -= 1;
            } else if is(ch, b',') && level == 0 {
                commas.push(j);
            }
        }
        cost.step(end.unwrap_or(w.len()) - i)?;
        let Some(end) = end else { continue };
        if !commas.is_empty() {
            let mut bounds = vec![i];
            bounds.extend(&commas);
            bounds.push(end);
            let mut out = Vec::new();
            for pair in bounds.windows(2) {
                cost.step(w.len())?;
                let mut nw: Word = w[..i].to_vec();
                nw.extend_from_slice(&w[pair[0] + 1..pair[1]]);
                nw.extend_from_slice(&w[end + 1..]);
                out.extend(brace_expand(&nw, cost, groups + 1)?);
                if out.len() > MAX_EXPANSIONS || cost.made > MAX_EXPANSIONS * 4 {
                    return Err(Amb);
                }
            }
            return Ok(out);
        }
        let inner = &w[i + 1..end];
        if inner.windows(2).any(|x| is(&x[0], b'.') && is(&x[1], b'.')) {
            cost.step(w.len())?;
            let mut nw: Word = w[..i].to_vec();
            nw.push(Ch::Lit {
                b: b'*',
                quoted: false,
            });
            nw.extend_from_slice(&w[end + 1..]);
            return brace_expand(&nw, cost, groups + 1);
        }
    }
    cost.made += 1;
    if cost.made > MAX_EXPANSIONS * 4 {
        return Err(Amb);
    }
    Ok(vec![w.clone()])
}

/// How a reader command takes its arguments.
#[derive(Debug, Clone, Copy)]
struct Reader {
    /// The first operand is a pattern or a program, not a file (unless
    /// one was given with an option).
    pattern_first: bool,
    /// Options that take the next word as a value that is not a file.
    valued: &'static [&'static str],
    /// Options whose value is a pattern (so no operand is).
    pattern_opts: &'static [&'static str],
    /// Options whose value is a file the command reads.
    file_opts: &'static [&'static str],
    /// Options that take two words (jq's `--arg name value`).
    two: &'static [&'static str],
    /// Options that take a name, then a file the command reads.
    name_then_file: &'static [&'static str],
}

const PLAIN: Reader = Reader {
    pattern_first: false,
    valued: &[],
    pattern_opts: &[],
    file_opts: &[],
    two: &[],
    name_then_file: &[],
};

/// The commands that print what they read, and how they take arguments.
fn reader(name: &[u8]) -> Option<Reader> {
    Some(match name {
        b"cat" | b"tac" | b"nl" | b"less" | b"more" | b"rev" | b"comm" | b"zcat" | b"pg"
        | b"view" => PLAIN,
        b"head" | b"tail" => Reader {
            valued: &[
                "-n",
                "-c",
                "--lines",
                "--bytes",
                "--pid",
                "-s",
                "--sleep-interval",
            ],
            ..PLAIN
        },
        b"bat" | b"batcat" => Reader {
            valued: &[
                "-l",
                "--language",
                "-H",
                "--highlight-line",
                "-m",
                "--map-syntax",
                "--style",
                "--theme",
                "-r",
                "--line-range",
                "--tabs",
                "--wrap",
                "--terminal-width",
                "--color",
                "--italic-text",
                "--decorations",
                "--paging",
                "--pager",
                "--file-name",
            ],
            ..PLAIN
        },
        b"od" => Reader {
            valued: &[
                "-t",
                "-A",
                "-j",
                "-N",
                "-w",
                "--format",
                "--address-radix",
                "--skip-bytes",
                "--read-bytes",
                "--width",
            ],
            ..PLAIN
        },
        b"xxd" => Reader {
            valued: &[
                "-s",
                "-l",
                "-c",
                "-g",
                "-o",
                "-n",
                "-seek",
                "-len",
                "-cols",
                "-groupsize",
                "-offset",
                "-name",
            ],
            ..PLAIN
        },
        b"hexdump" | b"hd" => Reader {
            valued: &["-n", "-s", "-e"],
            file_opts: &["-f"],
            ..PLAIN
        },
        b"strings" => Reader {
            valued: &["-n", "-t", "-e", "--bytes", "--radix", "--encoding"],
            ..PLAIN
        },
        b"base64" | b"base32" | b"basenc" => Reader {
            valued: &["-w", "--wrap", "-b", "--break", "-o", "--output"],
            file_opts: &["-i", "--input"],
            ..PLAIN
        },
        b"cut" => Reader {
            valued: &[
                "-d",
                "-f",
                "-c",
                "-b",
                "--delimiter",
                "--fields",
                "--characters",
                "--bytes",
                "--output-delimiter",
            ],
            ..PLAIN
        },
        b"sort" => Reader {
            valued: &[
                "-k",
                "-t",
                "-o",
                "-S",
                "-T",
                "--key",
                "--field-separator",
                "--output",
                "--buffer-size",
                "--temporary-directory",
                "--parallel",
                "--batch-size",
            ],
            file_opts: &["--files0-from"],
            ..PLAIN
        },
        b"uniq" => Reader {
            valued: &[
                "-f",
                "-s",
                "-w",
                "--skip-fields",
                "--skip-chars",
                "--check-chars",
            ],
            ..PLAIN
        },
        b"diff" | b"sdiff" | b"diff3" => Reader {
            valued: &[
                "-U",
                "-C",
                "--label",
                "-L",
                "--unified",
                "--context",
                "-x",
                "--exclude",
                "-I",
                "--ignore-matching-lines",
                "-W",
                "--width",
            ],
            file_opts: &["-X", "--exclude-from"],
            ..PLAIN
        },
        b"paste" => Reader {
            valued: &["-d", "--delimiters"],
            ..PLAIN
        },
        b"fold" | b"fmt" => Reader {
            valued: &["-w", "--width", "-p", "--prefix"],
            ..PLAIN
        },
        b"column" => Reader {
            valued: &["-s", "-c", "-o", "-t", "-N", "-R", "-H", "-W", "-l"],
            ..PLAIN
        },
        b"grep" | b"egrep" | b"fgrep" | b"zgrep" => Reader {
            pattern_first: true,
            valued: &[
                "-m",
                "-A",
                "-B",
                "-C",
                "-d",
                "-D",
                "--max-count",
                "--after-context",
                "--before-context",
                "--context",
                "--directories",
                "--devices",
                "--include",
                "--exclude",
                "--exclude-dir",
                "--label",
                "--binary-files",
                "--group-separator",
            ],
            pattern_opts: &["-e", "--regexp"],
            file_opts: &["-f", "--file", "--exclude-from"],
            ..PLAIN
        },
        b"rg" => Reader {
            pattern_first: true,
            valued: &[
                "-g",
                "--glob",
                "--iglob",
                "-t",
                "--type",
                "-T",
                "--type-not",
                "-m",
                "--max-count",
                "-A",
                "-B",
                "-C",
                "--after-context",
                "--before-context",
                "--context",
                "-j",
                "--threads",
                "-M",
                "--max-columns",
                "-r",
                "--replace",
                "--type-add",
                "--type-clear",
                "--max-depth",
                "-d",
                "-E",
                "--encoding",
                "--pre",
                "--pre-glob",
                "--sort",
                "--sortr",
                "--colors",
                "--color",
                "--path-separator",
                "--dfa-size-limit",
                "--regex-size-limit",
                "--max-filesize",
                "--engine",
                "--context-separator",
                "--field-match-separator",
                "--field-context-separator",
                "--hyperlink-format",
                "--generate",
            ],
            pattern_opts: &["-e", "--regexp"],
            file_opts: &["-f", "--file", "--ignore-file"],
            ..PLAIN
        },
        b"ag" => Reader {
            pattern_first: true,
            valued: &[
                "-G",
                "--file-search-regex",
                "-m",
                "--max-count",
                "-A",
                "-B",
                "-C",
                "--ignore",
                "--ignore-dir",
                "--depth",
                "--pager",
                "-W",
                "--width",
            ],
            file_opts: &["-p", "--path-to-ignore"],
            ..PLAIN
        },
        b"sed" | b"gsed" => Reader {
            pattern_first: true,
            valued: &["-l", "--line-length"],
            pattern_opts: &["-e", "--expression"],
            file_opts: &["-f", "--file"],
            ..PLAIN
        },
        b"awk" | b"gawk" | b"mawk" | b"nawk" => Reader {
            pattern_first: true,
            valued: &["-v", "-F", "--assign", "--field-separator"],
            pattern_opts: &["--source"],
            file_opts: &["-f", "--file", "-i", "--include"],
            ..PLAIN
        },
        b"jq" | b"yq" | b"gojq" | b"jaq" => Reader {
            pattern_first: true,
            valued: &["--indent", "-L", "--seq"],
            pattern_opts: &[],
            file_opts: &["-f", "--from-file"],
            two: &["--arg", "--argjson"],
            name_then_file: &["--slurpfile", "--rawfile"],
        },
        _ => return None,
    })
}

/// Whether a reader command, with `args`, reads an env file: as a file
/// operand or as the value of an option that names a file it reads.
fn reads_env_file(spec: &Reader, args: &[Word]) -> bool {
    let is_env = |w: &Word| dotenv(w) == Tri::Is;
    let mut pattern_given = false;
    let mut operands: Vec<&Word> = Vec::new();
    let mut i = 0;
    let mut only_operands = false;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if only_operands {
            operands.push(a);
            continue;
        }
        let Some(o) = plain(a) else {
            operands.push(a);
            continue;
        };
        if o == b"--" {
            only_operands = true;
            continue;
        }
        if !o.starts_with(b"-") || o == b"-" {
            operands.push(a);
            continue;
        }
        let text = String::from_utf8_lossy(&o).into_owned();
        if let Some(rest) = text.strip_prefix("--") {
            let (name, value) = match rest.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_owned())),
                None => (text.clone(), None),
            };
            let n = name.as_str();
            if spec.two.contains(&n) {
                i += 2;
            } else if spec.name_then_file.contains(&n) {
                if args.get(i + 1).is_some_and(is_env) {
                    return true;
                }
                i += 2;
            } else if spec.file_opts.contains(&n) {
                match value {
                    Some(v) => {
                        if is_env(&lits(v.as_bytes())) {
                            return true;
                        }
                    }
                    None => {
                        if args.get(i).is_some_and(is_env) {
                            return true;
                        }
                        i += 1;
                    }
                }
            } else if spec.pattern_opts.contains(&n) {
                pattern_given = true;
                if value.is_none() {
                    i += 1;
                }
            } else if spec.valued.contains(&n) && value.is_none() {
                i += 1;
            }
            continue;
        }
        if spec.valued.contains(&text.as_str()) && text.len() > 2 {
            // A long option written with one dash (xxd's `-seek`).
            i += 1;
            continue;
        }
        // A cluster of short options; one that takes a value takes the rest
        // of the cluster, or the next word.
        let bytes = o[1..].to_vec();
        for (k, &b) in bytes.iter().enumerate() {
            let flag = format!("-{}", char::from(b));
            let f = flag.as_str();
            let is_file = spec.file_opts.contains(&f);
            let is_pattern = spec.pattern_opts.contains(&f);
            if !(is_file || is_pattern || spec.valued.contains(&f)) {
                continue;
            }
            pattern_given |= is_pattern;
            let rest = &bytes[k + 1..];
            if rest.is_empty() {
                if is_file && args.get(i).is_some_and(is_env) {
                    return true;
                }
                i += 1;
            } else if is_file && is_env(&lits(rest)) {
                return true;
            }
            break;
        }
    }
    let files = if spec.pattern_first && !pattern_given {
        operands.get(1..).unwrap_or(&[])
    } else {
        &operands[..]
    };
    files.iter().any(|w| {
        // awk's `name=value` operands are assignments, not files.
        !(spec.pattern_first && is_assignment(w)) && is_env(w)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(script: &str) -> Option<Class> {
        check_script(script)
    }

    #[test]
    fn plain_commands_pass() {
        for ok in [
            "ls -la",
            "cat README.md",
            "cat .env.example",
            "grep -rn TODO src",
            "git status && git diff",
            "npm test 2>&1 | tail -n 20",
            "echo hi # cat .env",
            "for f in *.rs; do wc -l \"$f\"; done",
            "if [ -f .env ]; then echo yes; fi",
            "[[ -f .env && $x < 3 ]] && echo ok",
            "case $1 in a|b) echo one;; *) echo other;; esac",
            "f() { echo hi; }; f",
            "x=(a b c); echo ${x[@]}",
            "export PATH=/usr/bin:$PATH",
            "env FOO=1 make test",
            "ps aux",
            "ls .env",
            "rm -f .env.local",
            "echo KEY=1 >> .env",
            "git commit -m \"$(cat <<'EOF'\nfix: (a) and b)\nEOF\n)\"",
            "cat > notes.md <<'EOF'\n$(printenv)\nEOF",
            "envcloak run -- npm test",
            "envcloak ls",
            "(( i++ ))",
            "time -p make",
            "set -euo pipefail",
            "declare -f myfn",
            "grep -e .env notes.txt",
            "sed -n 1,5p README.md",
            "find . -name '*.rs' -exec wc -l {} +",
            "cat *",
        ] {
            assert_eq!(s(ok), None, "{ok}");
        }
    }

    #[test]
    fn env_files_are_found() {
        for bad in [
            "cat .env",
            "cat ./.env.local",
            "head -n 5 .env",
            "tail -f .env.production",
            "grep KEY .env",
            "rg -n KEY .env",
            "awk 1 .env",
            "sed -n p .env",
            "less .env",
            "bat .env",
            "source .env",
            ". ./.env",
            "cat < .env",
            "echo $(<.env)",
            "while read l; do echo $l; done < .env",
            "cat .env*",
            "cat .e*",
            "cat .*",
            "cat */.env",
            "cat .{env,bak}",
            "{cat,.env}",
            "c\\at .env",
            "ca''t .e\"n\"v",
            "cat $'\\x2eenv'",
            "$'\\x63at' .env",
            "echo `cat .env`",
            "bash -c 'cat .env'",
            "sh -lc \"head .env\"",
            "command cat .env",
            "sudo -u root cat .env",
            "timeout 5 cat .env",
            "env FOO=1 cat .env",
            "xargs -a .env echo",
            "find . -name .env -exec cat {} \\;",
            "eval 'cat .env'",
            "cat <<EOF\n$(cat .env)\nEOF",
            "bash <<'EOF'\ncat .env\nEOF",
            "export $(grep -v '^#' .env | xargs)",
            "cat \"$DIR/.env\"",
            "jq . .env",
            "base64 .env",
            "cat -- .env",
            "cat .env.",
        ] {
            assert_eq!(s(bad), Some(Class::EnvFile), "{bad}");
        }
    }

    #[test]
    fn environment_dumps_are_found() {
        for bad in [
            "env",
            "env | grep KEY",
            "/usr/bin/env",
            "\\env",
            "command env",
            "busybox env",
            "env -i",
            "env -u HOME",
            "printenv",
            "printenv OPENAI_API_KEY",
            "export",
            "export -p",
            "set",
            "declare -x",
            "declare -p",
            "typeset",
            "cat /proc/self/environ",
            "tr '\\0' '\\n' < /proc/1/environ",
            "strings /proc/*/environ",
            "ps eww",
            "ps -E",
            "sh -c printenv",
            "echo $(env)",
        ] {
            assert_eq!(s(bad), Some(Class::EnvDump), "{bad}");
        }
    }

    #[test]
    fn envcloak_reveal_and_approve_are_found() {
        assert_eq!(s("envcloak reveal openai/x"), Some(Class::Reveal));
        assert_eq!(s("/opt/bin/envcloak approve ABC"), Some(Class::Approve));
        assert_eq!(
            s("sh -c 'envcloak approve ABC --once'"),
            Some(Class::Approve)
        );
        assert_eq!(s("envcloak pending"), None);
        assert_eq!(s("envcloak run -- envcloak-reveal"), None);
    }

    #[test]
    fn what_cannot_be_read_is_ambiguous() {
        for amb in [
            "cat '.env",
            "echo \"unterminated",
            "echo $(cat",
            "$CMD .env",
            "c${IFS}at .env",
            "eval \"$X\"",
            "sh -c \"$SCRIPT\"",
            "echo `ls",
            "${PAGER:-less} x",
            "foo )",
        ] {
            assert_eq!(s(amb), Some(Class::Ambiguous), "{amb}");
        }
    }

    #[test]
    fn argv_is_read_without_a_shell() {
        assert_eq!(check_argv(&["printenv"]), Some(Class::EnvDump));
        assert_eq!(check_argv(&["cat", ".env"]), Some(Class::EnvFile));
        assert_eq!(check_argv(&["sh", "-c", "cat .env"]), Some(Class::EnvFile));
        assert_eq!(
            check_argv(&["envcloak", "approve", "X"]),
            Some(Class::Approve)
        );
        assert_eq!(check_argv(&["npm", "test"]), None);
        // No glob without a shell: `.env*` is one file's name, and not an
        // env file's.
        assert_eq!(check_argv(&["cat", ".env*"]), None);
        assert_eq!(check_argv(&["cat", ".env.local"]), Some(Class::EnvFile));
        assert_eq!(check_argv(&["ls", ".env*"]), None);
        assert_eq!(check_argv(&["echo", "$(printenv)"]), None);
        let empty: [&str; 0] = [];
        assert_eq!(check_argv(&empty), None);
    }

    #[test]
    fn deep_or_huge_input_ends_ambiguous_and_fast() {
        let deep = "echo ".to_owned() + &"$(".repeat(200) + &")".repeat(200);
        assert_eq!(s(&deep), Some(Class::Ambiguous));
        let braces = "echo ".to_owned() + &"{a,b}".repeat(20);
        assert_eq!(s(&braces), Some(Class::Ambiguous));
        // Sequences make no more words, but each is a step deeper.
        let seqs = "echo ".to_owned() + &"{1..2}".repeat(100);
        assert_eq!(s(&seqs), Some(Class::Ambiguous));
        assert_eq!(s("echo {a,b}{c,d} {1..3}"), None);
        let nested = "echo ".to_owned() + &"${x:-".repeat(100) + &"}".repeat(100);
        assert_eq!(s(&nested), Some(Class::Ambiguous));
        assert_eq!(s("echo ${x:-${y:-\"$(( 1 + ${z:-2} ))\"}}"), None);
        let long = "a".repeat(3 * 1024 * 1024);
        let t = std::time::Instant::now();
        let _ = s(&long);
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
    }
}
