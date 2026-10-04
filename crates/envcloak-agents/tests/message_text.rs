//! The text EnvCloak prints holds no source indentation (verifier, round
//! 6: two messages of `agents install` had runs of 30 spaces mid-sentence,
//! where a string literal continued on the next source line had lost the
//! trailing backslash that drops the next line's indentation).
//!
//! Every ordinary string literal (`"..."`, `b"..."`; raw strings are kept
//! as written) in this crate's sources and in the CLI's agents, hook and
//! init commands is read, and none may hold a line break that is not
//! escaped followed by indentation, or a run of three spaces or more after
//! other text on the same line (spaces after an escaped `\n` are a
//! fixture's indentation, kept; a text laid out on lines of its own, such
//! as the instruction block, starts each line at the margin).
//!
//! Mutation checked: the trailing backslash of one line of the
//! `instruction_file_moved` message in `src/install.rs` taken out (as in
//! the round-6 head): its literal holds a line break and indentation, and
//! this fails.

use std::path::{Path, PathBuf};

/// The `.rs` files under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The ordinary string literals of `src`: each one's first line and its
/// content (escapes as written).
fn literals(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < n {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
        } else if src[i..].starts_with("//") {
            i = src[i..].find('\n').map_or(n, |j| i + j);
        } else if src[i..].starts_with("/*") {
            let mut depth = 1;
            i += 2;
            while i < n && depth > 0 {
                if src[i..].starts_with("/*") {
                    depth += 1;
                    i += 2;
                } else if src[i..].starts_with("*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    line += usize::from(b[i] == b'\n');
                    i += 1;
                }
            }
        } else if matches!(c, b'r' | b'b' | b'c') && (i == 0 || !ident(b[i - 1])) && {
            let j = if c != b'r' && b.get(i + 1) == Some(&b'r') {
                i + 1
            } else {
                i
            };
            b[j] == b'r' && {
                let k = b[j + 1..]
                    .iter()
                    .position(|&x| x != b'#')
                    .map_or(n, |p| j + 1 + p);
                b.get(k) == Some(&b'"')
            }
        } {
            // A raw string: kept as written, to its closing quote and hashes.
            let j = if c == b'r' { i } else { i + 1 };
            let hashes = b[j + 1..].iter().take_while(|&&x| x == b'#').count();
            let open = j + 1 + hashes;
            let close = format!("\"{}", "#".repeat(hashes));
            let end = src[open + 1..]
                .find(&close)
                .map_or(n, |e| open + 1 + e + close.len());
            line += src[i..end].matches('\n').count();
            i = end;
        } else if c == b'\'' {
            // A character literal, or a lifetime.
            if b.get(i + 1) == Some(&b'\\') {
                // The escaped character, then the closing quote.
                i = src[i + 3..].find('\'').map_or(n, |e| i + 3 + e + 1);
            } else if b.get(i + 2) == Some(&b'\'') {
                i += 3;
            } else if let Some(ch) = src[i + 1..].chars().next() {
                let w = ch.len_utf8();
                i += if b.get(i + 1 + w) == Some(&b'\'') {
                    2 + w
                } else {
                    1
                };
            } else {
                i += 1;
            }
        } else if c == b'"' {
            let first = line;
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                if b[j] == b'\\' {
                    line += usize::from(b.get(j + 1) == Some(&b'\n'));
                    j += 2;
                    continue;
                }
                line += usize::from(b[j] == b'\n');
                j += 1;
            }
            out.push((first, src[i + 1..j.min(n)].to_owned()));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// What is wrong with a literal's content, if anything.
fn fault(lit: &str) -> Option<&'static str> {
    let b = lit.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                // An escaped line break drops the next line's indentation.
                i += 2;
                if b.get(i - 1) == Some(&b'\n') {
                    i += b[i..]
                        .iter()
                        .take_while(|x| x.is_ascii_whitespace())
                        .count();
                }
                continue;
            }
            // A text laid out on lines of its own (the instruction block)
            // starts each at the margin; a lost continuation leaves the
            // source's indentation after the break.
            b'\n' if b[i + 1..].starts_with(b"   ") => {
                return Some("a line break that is not escaped, and indentation");
            }
            b' ' if i > 0 && b[i - 1] != b' ' && !lit[..i].ends_with("\\n") => {
                let run = b[i..].iter().take_while(|&&x| x == b' ').count();
                if run >= 3 && i + run < b.len() {
                    return Some("a run of spaces after text");
                }
                i += run;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[test]
fn printed_text_holds_no_source_indentation() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&here.join("src"), &mut files);
    for f in ["agents.rs", "hook.rs", "init.rs"] {
        files.push(here.join("../envcloak-cli/src/cmd").join(f));
    }
    files.sort();
    let mut faults = Vec::new();
    let mut seen = 0;
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        for (line, lit) in literals(&src) {
            seen += 1;
            // The usage texts of the CLI are laid out on purpose: their
            // lines start with the indentation `--help` prints.
            if (f.ends_with("cmd/agents.rs") || f.ends_with("cmd/init.rs"))
                && lit.starts_with("envcloak ")
                && lit.contains("\n       envcloak ")
            {
                continue;
            }
            if let Some(why) = fault(&lit) {
                faults.push(format!("{}:{line}: {why}", f.display()));
            }
        }
    }
    // The scan read the sources: the crate's own literals are many.
    assert!(seen > 1000, "only {seen} literals read");
    assert!(faults.is_empty(), "{faults:#?}");
}

#[test]
fn the_scan_finds_what_it_is_for() {
    // Positive controls: the round-6 fault, an unescaped break, and the
    // forms that are kept.
    let src = "let a = \"files                              changed\";\n\
               let b = \"one\n    line\";\n\
               let k = \"one\nline\";\n\
               let c = \"one \\\n             two\";\n\
               let d = \"{\\n    \\\"a\\\": 1\\n}\";\n\
               let e = r#\"raw \"   \" text\n\"#;\n\
               let f = 'x'; let g = '\\''; fn h<'a>() {}\n\
               // \"in   a comment\"\n\
               let i = \"    leading\";\n";
    let lits = literals(src);
    let faults: Vec<_> = lits.iter().map(|(_, l)| fault(l)).collect();
    assert_eq!(lits.len(), 6, "{lits:?}");
    assert_eq!(
        faults,
        [
            Some("a run of spaces after text"),
            Some("a line break that is not escaped, and indentation"),
            None,
            None,
            None,
            None
        ],
        "{lits:?}"
    );
    assert_eq!(lits[1].0, 2);
    assert_eq!(lits[5].0, 13);
}
