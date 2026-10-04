//! The hook's command reader against the shells and tools themselves
//! (M2 plan M2-08, lesson L-02; the orchestrator's finding that the reader
//! enumerated forms a reviewer could always add to, and the verifier's
//! POSIX bracket, BSD grep `--include` and zsh findings).
//!
//! Random spellings of reading `.env` (and `sub/.env`), of `/proc/<pid>/
//! environ` on Linux and of printing the environment are run by every
//! shell installed here (bash, sh, dash, zsh, and Homebrew's bash 5), and
//! by find and grep with their own globs, in a fixture directory whose env
//! files hold a canary made at run time (and, for the environment, a shell
//! whose environment holds one). A spelling reaches the secret when the
//! canary is in what the command printed. Every spelling that reaches it
//! in any shell must not be let through by `check_script`: a denial or a
//! question, never `None` (the property is fail-closed: what the reader
//! cannot resolve, it does not allow). Spellings that reach nothing are
//! not judged.
//!
//! The spellings are built letter by letter from what each grammar has:
//! quotes, backslashes, `?`, `*`, character classes (ranges, negation, a
//! `]` first, POSIX `[:class:]`, `[=c=]` and `[.c.]`), brace lists and
//! sequences, `$'\xHH'`, command and parameter substitution, and command
//! words spelled with zsh's `=name`, precommand modifiers, paths and
//! globs. The run is seeded: `ENVCLOAK_ORACLE_SEED` and
//! `ENVCLOAK_ORACLE_CASES` change it, and a miss prints its script (the
//! scripts hold no secret: the canary is only in the files and the
//! environment).
//!
//! Positive controls: plain `cat .env` and `printenv` reach the canary in
//! every shell, a share of the random spellings does, and `cat a.txt`
//! does not and is allowed.
//!
//! A fourth family (`more_cases`) spells what the reader resolves only by
//! failing closed: names in variables and zsh's flagged expansions,
//! values read by a name only known when it runs, programs not on the
//! reader list given the file, a shell given it as its script, `emulate
//! -c`, and globs under changed options. A fifth (`carried_cases`)
//! carries the name the script spells to a program not on the reader
//! list by a value only known when it runs (a variable, an array, a
//! loop's name, positional parameters, names read from input, a
//! command's output, a shell's script from a pipe), gives globs under
//! changed options to any program, and has an interpreter's code or
//! input name the file or the environment.
//!
//! Round 6 adds named parameters printed with their values to the
//! environment family (`export -p NAME`, `readonly -p NAME`, `typeset -p
//! NAME`): zsh prints them, and dash prints every exported variable.
//! Mutation checked: `export`'s `-p` read only without operands (as before
//! round 6): zsh's and dash's `export -p ECX_PROBE` print the canary and
//! are allowed, and this fails.
//!
//! Mutations checked: POSIX bracket expressions read as plain members in
//! `glob.rs` (`posix_end` answering `None`): `find -name '.[[:alpha:]]nv'`
//! spellings that find reads `.env` with are allowed, and this fails.
//! zsh's `=name` not read (`run` taking `=printenv` as its own name): zsh's
//! `=printenv` spellings print the canary and are allowed, and this fails
//! where zsh is installed. Round 5: zsh's `$~x` read as a `$` of its own
//! (`zsh_flagged` answering false), the indirection check taken out
//! (`indirect` answering false), programs not on the reader list let be
//! (`unknown_named` doing nothing), a shell's script file not read, and
//! `emulate -c` not read: each makes `more_cases` spellings that reach
//! the canary allowed, and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use envcloak_agents::hook::shell::check_script;
use envcloak_testkit::agents::finish_capped;

/// A small seeded generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }
}

fn canary(rng: &mut Rng, tag: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let tail: String = (0..32)
        .map(|_| char::from(ALPHABET[rng.below(ALPHABET.len())]))
        .collect();
    format!("ec{tag}{tail}")
}

/// The shells installed here, each once.
fn shells() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for c in [
        "/bin/bash",
        "/bin/sh",
        "/bin/dash",
        "/usr/bin/dash",
        "/bin/zsh",
        "/usr/bin/zsh",
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash",
    ] {
        let p = Path::new(c);
        let Ok(real) = std::fs::canonicalize(p) else {
            continue;
        };
        // Each name once; sh is its own grammar even where it is bash
        // (posix mode) or dash.
        let named = real.with_file_name(p.file_name().unwrap_or_default());
        if seen.contains(&named) {
            continue;
        }
        seen.push(named);
        out.push(p.to_path_buf());
    }
    out
}

fn is_zsh(shell: &Path) -> bool {
    shell.file_name().is_some_and(|n| n == "zsh")
}

/// What `shell -c script` prints (standard output and error), in `dir`,
/// with only `env` in its environment, within 10 seconds of its start, its
/// output read to the end, at most 1 MiB of each stream kept; a run past
/// that fails the oracle (Codex F-127, the same class as the program
/// oracle's: a run past its limit gave what it had printed as if it had
/// ended, and the wait for its output was not bounded once the shell was
/// killed). The shell leads a process group of its own, killed with it.
fn run(shell: &Path, script: &str, dir: &Path, env: &[(&str, &str)]) -> Vec<u8> {
    let mut cmd = Command::new(shell);
    cmd.arg("-c")
        .arg(script)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = finish_capped(cmd, Duration::from_secs(10), 1 << 20);
    let mut b = out.stdout;
    b.extend(out.stderr);
    b
}

fn holds(out: &[u8], needle: &str) -> bool {
    out.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// A shell word that, by some shell's grammar, may stand for `c` (one
/// character of a path, `/` excluded).
fn shell_char(rng: &mut Rng, c: char, prev_star: bool) -> String {
    let alpha = c.is_ascii_alphabetic();
    loop {
        let s = match rng.below(22) {
            0..=3 => c.to_string(),
            4 => format!("'{c}'"),
            5 => format!("\"{c}\""),
            6 => format!("\\{c}"),
            7 => "?".to_owned(),
            8 if !prev_star => "*".to_owned(),
            9 => format!("[{c}]"),
            10 => format!("[!{}]", if c == 'q' { 'z' } else { 'q' }),
            11 if alpha => "[[:alpha:]]".to_owned(),
            11 if c == '.' => "[[:punct:]]".to_owned(),
            12 if c.is_ascii_lowercase() => "[[:lower:]]".to_owned(),
            13 => format!("[[={c}=]]"),
            14 => format!("[[.{c}.]]"),
            15 if alpha => format!("[a-{c}]"),
            16 => format!("[]{c}]"),
            17 => format!("{{{c},Q}}"),
            18 => format!("{{{c}..{c}}}"),
            19 => format!("$'\\x{:02x}'", u32::from(c)),
            20 => format!("$(printf '%s' '{c}')"),
            21 => format!("${{ECX_UNSET:-{c}}}"),
            _ => continue,
        };
        return s;
    }
}

/// A shell word for `path`.
fn shell_word(rng: &mut Rng, path: &str) -> String {
    let mut out = String::new();
    let mut prev_star = false;
    for c in path.chars() {
        if c == '/' {
            out.push('/');
            prev_star = false;
            continue;
        }
        let s = shell_char(rng, c, prev_star);
        prev_star = s == "*";
        out.push_str(&s);
    }
    out
}

/// A tool's glob (find, grep) that may stand for `path`, as the tool reads
/// it: wildcards, classes, escapes; `slash` when its `*` may span a `/`.
fn tool_glob(rng: &mut Rng, path: &str, slash: bool) -> String {
    let chars: Vec<char> = path.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '/' && !slash {
            out.push('/');
            i += 1;
            continue;
        }
        // The name's last character is always spelled (a literal, a class
        // or an escape): a pattern that spells nothing of the env file's
        // name (`*`, `????`, `./s*`) is a search of every file, which
        // docs/INSTALLERS.md lists with `grep -r` as what the hook does not
        // see, and which the honesty table's test covers.
        let last = i + 1 == chars.len();
        if !last && rng.chance(1, 6) {
            let max = chars.len() - 1 - i;
            let mut n = 1 + rng.below(max.min(5));
            if !slash {
                n = chars[i..i + n].iter().take_while(|x| **x != '/').count();
            }
            if n > 0 {
                out.push('*');
                i += n;
                continue;
            }
        }
        let s = match rng.below(12) {
            0..=3 => c.to_string(),
            4 if !last => "?".to_owned(),
            5 => format!("[{c}]"),
            6 if c.is_ascii_alphabetic() => "[[:alpha:]]".to_owned(),
            6 if c == '.' => "[[:punct:]]".to_owned(),
            7 => format!("[[={c}=]]"),
            8 => format!("[!{}]", if c == 'q' { 'z' } else { 'q' }),
            9 if c.is_ascii_lowercase() => "[[:lower:]]".to_owned(),
            10 => format!("\\{c}"),
            _ => c.to_string(),
        };
        out.push_str(&s);
        i += 1;
    }
    out
}

/// A command word that runs `name` (a program in `/usr/bin` or `/bin`), in
/// some shell's grammar.
fn command_word(rng: &mut Rng, name: &str, dir: &str) -> String {
    match rng.below(9) {
        0 => name.to_owned(),
        1 => format!("={name}"),
        2 => format!("command {name}"),
        3 => format!("{dir}/{name}"),
        4 => {
            // A glob over the program's path.
            let mut w = format!("{dir}/");
            for (k, c) in name.chars().enumerate() {
                w.push_str(&match rng.below(4) {
                    0 if k > 0 => "?".to_owned(),
                    1 => format!("[{c}]"),
                    _ => c.to_string(),
                });
            }
            w
        }
        5 => {
            let mut w = String::new();
            for c in name.chars() {
                w.push_str(&match rng.below(4) {
                    0 => format!("'{c}'"),
                    1 => format!("\\{c}"),
                    _ => c.to_string(),
                });
            }
            w
        }
        6 => format!("noglob {name}"),
        7 => format!("nohup {name}"),
        _ => format!("env {name}"),
    }
}

struct Case {
    script: String,
    family: &'static str,
}

fn rng_pick(rng: &mut Rng, items: &[&str]) -> String {
    items[rng.below(items.len())].to_owned()
}

fn read_cases(rng: &mut Rng, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let path = if rng.chance(1, 3) { "sub/.env" } else { ".env" };
        let w = shell_word(rng, path);
        let reader = match rng.below(12) {
            0 => format!("cat {w}"),
            1 => format!("head -n 50 {w}"),
            2 => format!("tail -n 50 {w}"),
            3 => format!("sed -n p {w}"),
            4 => format!("awk 1 {w}"),
            5 => format!("grep -h K {w}"),
            6 => format!("cat < {w}"),
            7 => format!("< {w} cat"),
            8 => format!(". {w}; printf '%s\\n' \"$K\""),
            9 => format!("sort {w}"),
            10 => format!("{} {w}", command_word(rng, "cat", "/bin")),
            _ => format!("nl {w}"),
        };
        out.push(Case {
            script: reader,
            family: "read",
        });
    }
    out
}

fn tool_cases(rng: &mut Rng, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let script = match rng.below(5) {
            0 | 1 => {
                let p = tool_glob(rng, ".env", false);
                format!("find . -name '{p}' -exec cat {{}} +")
            }
            2 => {
                let target = if rng.chance(1, 2) {
                    "./sub/.env"
                } else {
                    "./.env"
                };
                let p = tool_glob(rng, target, true);
                format!("find . -path '{p}' -exec cat {{}} +")
            }
            _ => {
                let target = if rng.chance(1, 2) {
                    "./sub/.env"
                } else {
                    ".env"
                };
                let p = tool_glob(rng, target, true);
                format!("grep -r --include='{p}' -h K .")
            }
        };
        out.push(Case {
            script,
            family: "tool",
        });
    }
    out
}

fn dump_cases(rng: &mut Rng, n: usize) -> Vec<Case> {
    let linux = cfg!(target_os = "linux");
    let mut out = Vec::new();
    for _ in 0..n {
        let script = match rng.below(if linux { 14 } else { 12 }) {
            0 => command_word(rng, "printenv", "/usr/bin"),
            1 => command_word(rng, "env", "/usr/bin"),
            2 => "export -p".to_owned(),
            3 => "set".to_owned(),
            4 => "declare -x".to_owned(),
            5 => "typeset -x".to_owned(),
            6 => "typeset -m 'ECX*'".to_owned(),
            7 => "declare -p".to_owned(),
            8 => format!("{} | sort", command_word(rng, "env", "/usr/bin")),
            9 => "export".to_owned(),
            // A named parameter printed with its value (Codex review,
            // round 6: zsh's `export -p NAME` and `readonly -p NAME`
            // print it, as `typeset -p NAME` does in bash and zsh, and
            // dash's `export -p NAME` prints every exported variable).
            10 => rng_pick(
                rng,
                &[
                    "export -p ECX_PROBE",
                    "readonly -p ECX_PROBE",
                    "typeset -p ECX_PROBE",
                    "declare -p ECX_PROBE",
                    "export -pf ECX_PROBE",
                ],
            ),
            11 => rng_pick(rng, &["local -p ECX_PROBE", "export -p -- ECX_PROBE"]),
            _ => {
                let w = shell_word(rng, "proc/self/environ");
                format!("tr '\\0' '\\n' < /{w}")
            }
        };
        out.push(Case {
            script,
            family: "dump",
        });
    }
    out
}

/// What the reader resolves only by failing closed (round 5's sweep of
/// the zsh-grammar and reader-list classes): a name held in a variable and
/// expanded by bash's or zsh's rules (`$x`, zsh's `$~x`, `$=x`, `${~x}`), a
/// value read by a name only known when it runs (bash's `${!v}`, zsh's
/// `${(P)n}`, zsh's `$mapfile`), programs not on the reader list given the
/// file (`pr`, `iconv`, `cp ... /dev/stdout`, `gzip -c`, `tar`), a shell
/// given it as its script (`bash -x`), `emulate -c`, and globs read under
/// changed options (`setopt globdots`, `shopt -s dotglob`, zsh's `^`).
fn more_cases(rng: &mut Rng, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let path = if rng.chance(1, 3) { "sub/.env" } else { ".env" };
        let w = shell_word(rng, path);
        let script = match rng.below(20) {
            0 => format!("x={w}; cat $x"),
            1 => format!("x='{path}'; cat $~x"),
            2 => "x='.e*'; cat $~x".to_owned(),
            3 => format!("x='{path}'; cat ${{~x}}"),
            4 => format!("x='{path}'; head -n 5 $=x"),
            5 => "for n in ${(k)parameters}; do print -r -- $n=${(P)n}; done".to_owned(),
            6 => "for v in $(compgen -e); do echo \"$v=${!v}\"; done".to_owned(),
            7 => format!("zmodload zsh/mapfile; print -r -- $mapfile[{path}]"),
            8 => format!("pr -t {w}"),
            9 => format!("iconv -f utf-8 -t utf-8 {w}"),
            10 => format!("cp {w} /dev/stdout"),
            11 => format!("gzip -c {w} | gunzip"),
            // Not into a directory the spelling also matches (`[!q]?*[!q]`
            // matches `sub`): a recursive read is a row of its own in the
            // honesty table.
            12 => format!("tar cf - --no-recursion {w} | tar xOf -"),
            13 => format!("bash -x {w}"),
            14 => format!("sh -v {w}"),
            15 => format!("emulate sh -c 'cat {path}'"),
            16 => "setopt globdots; cat *".to_owned(),
            17 => "shopt -s dotglob; cat *".to_owned(),
            18 => "setopt extendedglob; cat ^a.txt".to_owned(),
            _ => "setopt globdots; cat < *".to_owned(),
        };
        out.push(Case {
            script,
            family: "more",
        });
    }
    out
}

/// The class swept further in round 5: an env file's name the script
/// spells, carried to a program not on the reader list by a value only
/// known when it runs (a variable, an array, a loop's or a case's name,
/// positional parameters, names read from input, a command's output, a
/// shell's script from a pipe); globs under changed options given to any
/// program; an interpreter's code or input naming the file, or the
/// environment.
fn carried_cases(rng: &mut Rng, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let path = if rng.chance(1, 3) { "sub/.env" } else { ".env" };
        let w = shell_word(rng, path);
        let script = match rng.below(17) {
            0 => format!("x={w}; cp $x /dev/stdout"),
            1 => format!("for f in {w}; do cp \"$f\" /dev/stdout; done"),
            2 => format!("echo {w} | xargs cat"),
            3 => format!("printf '%s\\n' {w} | xargs -I@ cp @ /dev/stdout"),
            4 => format!("sh -c 'cp \"$1\" /dev/stdout' _ {w}"),
            5 => format!("read f <<< {w}; cp \"$f\" /dev/stdout"),
            6 => format!("printf 'cat {path}' | sh"),
            7 => format!("cp $(echo {w}) /dev/stdout"),
            8 => format!("a=({w}); cp \"${{a[@]}}\" /dev/stdout"),
            9 => format!("case x in x) f={w};; esac; cp $f /dev/stdout"),
            10 => "setopt globdots; tar cf - --no-recursion * | tar xOf -".to_owned(),
            11 => "shopt -s dotglob; tar cf - --no-recursion * | tar xOf -".to_owned(),
            12 => format!("python3 -c 'print(open(\"{path}\").read())'"),
            13 => "python3 -c 'import os; print(dict(os.environ))'".to_owned(),
            14 => "perl -e 'print \"$_=$ENV{$_}\\n\" for keys %ENV'".to_owned(),
            15 => format!("perl -ne print {w}"),
            _ => format!("python3 - <<'EOF'\nprint(open('{path}').read())\nEOF"),
        };
        out.push(Case {
            script,
            family: "carried",
        });
    }
    out
}

#[test]
fn every_spelling_that_reaches_a_secret_is_not_allowed() {
    let shells = shells();
    assert!(!shells.is_empty(), "no shell here");
    if let Ok(want) = std::env::var("ENVCLOAK_TEST_REQUIRE_SHELLS") {
        for name in want.split(',').filter(|n| !n.is_empty()) {
            assert!(
                shells
                    .iter()
                    .any(|s| s.file_name().is_some_and(|f| f == name)),
                "{name} is required here and not installed"
            );
        }
    }
    let seed = std::env::var("ENVCLOAK_ORACLE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5eed_08c1_0a4c_e11d_u64);
    let cases: usize = std::env::var("ENVCLOAK_ORACLE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(240);
    let mut rng = Rng(seed | 1);
    let dir = tempfile::Builder::new()
        .prefix("ecso")
        .tempdir_in("/tmp")
        .unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let (a, b, e) = (
        canary(&mut rng, "a"),
        canary(&mut rng, "b"),
        canary(&mut rng, "e"),
    );
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join(".env"), format!("K={a}\n")).unwrap();
    std::fs::write(root.join("sub/.env"), format!("K={b}\n")).unwrap();
    std::fs::write(root.join(".env.example"), "K=\n").unwrap();
    std::fs::write(root.join("a.txt"), "plain\n").unwrap();
    let env = [("ECX_PROBE", e.as_str())];
    let reached = |out: &[u8]| holds(out, &a) || holds(out, &b) || holds(out, &e);

    // Positive controls, in every shell.
    for sh in &shells {
        for script in ["cat .env", "printenv"] {
            let out = run(sh, script, &root, &env);
            assert!(
                reached(&out),
                "{}: control {script} reached nothing",
                sh.display()
            );
            assert!(check_script(script).is_some(), "{script}");
        }
        let out = run(sh, "cat a.txt", &root, &env);
        assert!(!reached(&out) && holds(&out, "plain"), "{}", sh.display());
        assert!(check_script("cat a.txt").is_none());
    }

    let mut all = read_cases(&mut rng, cases);
    all.extend(tool_cases(&mut rng, cases / 2));
    all.extend(dump_cases(&mut rng, cases / 3));
    all.extend(more_cases(&mut rng, cases / 2));
    all.extend(carried_cases(&mut rng, cases / 2));
    let mut misses: Vec<String> = Vec::new();
    let mut counts: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for case in &all {
        let decided = check_script(&case.script);
        let mut hit_by: Vec<String> = Vec::new();
        for sh in &shells {
            if reached(&run(sh, &case.script, &root, &env)) {
                hit_by.push(sh.display().to_string());
            }
        }
        let c = counts.entry(case.family).or_default();
        c.0 += 1;
        if !hit_by.is_empty() {
            c.1 += 1;
            if decided.is_none() {
                misses.push(format!(
                    "{} (reached in {})",
                    case.script,
                    hit_by.join(", ")
                ));
            }
        }
    }
    eprintln!("measurement: shells {shells:?}; (cases, reaching) by family: {counts:?}");
    // The generator must make spellings that reach the secret, in each
    // family, or the property is vacuous.
    for (family, (_, hits)) in &counts {
        assert!(
            *hits >= 5,
            "{family}: only {hits} spellings reached the secret"
        );
    }
    assert!(
        misses.is_empty(),
        "{} spelling(s) reach a secret and are allowed:\n{}",
        misses.len(),
        misses.join("\n")
    );
    // A spelling zsh alone reads, where zsh is here.
    if let Some(z) = shells.iter().find(|s| is_zsh(s)) {
        let out = run(z, "=printenv", &root, &env);
        assert!(reached(&out), "zsh's =printenv reached nothing");
        assert!(check_script("=printenv").is_some());
    }
}
