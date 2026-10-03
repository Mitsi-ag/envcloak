//! EnvCloak's managed block in an agent's Markdown instruction file (SPEC
//! §7: `<!-- envcloak:begin -->` / `<!-- envcloak:end -->`; M2 plan M2-08,
//! D-20): the M2 instruction block, and inserting, replacing and removing
//! it.
//!
//! The block is the same bytes in every file, so a host that reads
//! several (Claude Code falls back to `AGENTS.md`; Copilot and OpenCode
//! read `CLAUDE.md`) can tell the copies are one. Its text names only
//! commands this build ships, and is worded for any agent: it never says
//! a hook will stop anything, since some hosts that read these files run
//! no hook (Map C §2.1).
//!
//! The markers are HTML comments, which Claude Code strips before the
//! text reaches the model; the instructions are never inside one. A block
//! that would sit inside an open HTML comment or an open code fence (a
//! file that ends inside one, or an existing block inside one, even one
//! already as it should be) is refused ([`BlockError::Unclosed`]): it
//! would be read as part of it. A fence closes only with its own
//! character, at least as many of them and nothing after but white space
//! (CommonMark). A file whose markers are not exactly one begin before one
//! end, each a line of its own, is refused ([`BlockError::Damaged`]), and
//! so is one that is not UTF-8.
//!
//! A block whose text is not EnvCloak's (the person edited it between the
//! markers) is neither replaced nor removed ([`BlockError::Modified`]):
//! that text is theirs.

/// The line that opens the block.
pub const BEGIN: &str = "<!-- envcloak:begin -->";
/// The line that closes the block.
pub const END: &str = "<!-- envcloak:end -->";

/// The instructions (D-20, SPEC §7 items 1 to 4 in their M2 form).
pub const INSTRUCTIONS: &str = "## EnvCloak

This machine keeps API keys and other secrets in EnvCloak, not in files or in the chat.

- Never read `.env` files, never print environment variables, and never ask the person to paste a key into the chat.
- If the project has an `envcloak.toml`, run anything that needs its secrets as `envcloak run -- <command>`.
- If a key is missing, run `envcloak ls` (names only) and bind it with `envcloak ref NAME=<slug>`; if it does not exist, ask the person to run `envcloak add <provider>` in their own terminal.
- If the project has plaintext `.env` files and no `envcloak.toml`, suggest `envcloak init`.";

/// The whole block, markers included, ending with a newline.
pub fn block() -> String {
    format!("{BEGIN}\n{INSTRUCTIONS}\n{END}\n")
}

/// Why a file's block could not be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// Not UTF-8.
    NotUtf8,
    /// The markers are repeated, unpaired or out of order.
    Damaged,
    /// The file ends inside an open HTML comment or code fence.
    Unclosed,
    /// The text between the markers is not one EnvCloak wrote.
    Modified,
}

impl BlockError {
    /// A stable name for reports.
    pub fn name(self) -> &'static str {
        match self {
            BlockError::NotUtf8 => "not_utf8",
            BlockError::Damaged => "block_damaged",
            BlockError::Unclosed => "inside_comment",
            BlockError::Modified => "block_modified",
        }
    }

    /// What it means, for a person.
    pub fn message(self) -> &'static str {
        match self {
            BlockError::NotUtf8 => "the file is not UTF-8 text",
            BlockError::Damaged => {
                "the file's EnvCloak markers are repeated, unpaired or out of order; fix them by \
                 hand"
            }
            BlockError::Unclosed => {
                "the block would be inside an open HTML comment or code block, where the \
                 instructions would be hidden"
            }
            BlockError::Modified => {
                "the text between EnvCloak's markers changed since EnvCloak wrote it, so it was \
                 left as it is: it may be yours. Take out what is yours, or the whole block, and \
                 run this again"
            }
        }
    }
}

/// The byte range of the block in `text`, if it has one.
fn find(text: &str) -> Result<Option<(usize, usize)>, BlockError> {
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches('\n').trim_end_matches('\r');
        if bare == BEGIN {
            begins.push(at);
        } else if bare == END {
            ends.push(at + line.len());
        } else if bare.contains("envcloak:begin") || bare.contains("envcloak:end") {
            // A marker that is not a line of its own.
            return Err(BlockError::Damaged);
        }
        at += line.len();
    }
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        _ => Err(BlockError::Damaged),
    }
}

/// A fence line's character and length (CommonMark: up to three spaces,
/// then three or more backticks or tildes; a backtick fence's info string
/// holds no backtick), and whether nothing but white space follows, as a
/// closing fence needs.
fn fence(line: &str) -> Option<(u8, usize, bool)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let t = &line[indent..];
    let c = *t.as_bytes().first()?;
    if c != b'`' && c != b'~' {
        return None;
    }
    let n = t.bytes().take_while(|b| *b == c).count();
    if n < 3 {
        return None;
    }
    let info = &t[n..];
    if c == b'`' && info.contains('`') {
        return None;
    }
    Some((c, n, info.trim().is_empty()))
}

/// Whether the end of `text` is inside an open HTML comment or fenced code
/// block. A fence is closed only by a fence of its own character, at
/// least as long, with nothing after it (the Codex review: another
/// character or a shorter run closed it here before).
fn ends_open(text: &str) -> bool {
    let mut open_fence: Option<(u8, usize)> = None;
    let mut in_comment = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !in_comment {
            match (open_fence, fence(line)) {
                (None, Some((c, n, _))) => {
                    open_fence = Some((c, n));
                    continue;
                }
                (Some((c, n)), Some((c2, n2, bare))) if c2 == c && n2 >= n && bare => {
                    open_fence = None;
                    continue;
                }
                _ => {}
            }
        }
        if open_fence.is_some() {
            continue;
        }
        let mut rest = line;
        loop {
            if in_comment {
                match rest.find("-->") {
                    Some(p) => {
                        in_comment = false;
                        rest = &rest[p + 3..];
                    }
                    None => break,
                }
            } else {
                match rest.find("<!--") {
                    Some(p) => {
                        in_comment = true;
                        rest = &rest[p + 4..];
                    }
                    None => break,
                }
            }
        }
    }
    open_fence.is_some() || in_comment
}

/// A change to a file's block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The block is there, as it should be.
    Unchanged,
    /// The file's new text.
    New(String),
}

/// The blocks earlier versions of EnvCloak wrote, which [`insert`]
/// replaces and [`remove`] takes out: none before this one.
const EARLIER: &[&str] = &[];

/// Whether `found` (a block, markers and final newline included) is one
/// EnvCloak wrote: this version's or an earlier one's. Line ends do not
/// count: an editor that saves the file with CRLF leaves EnvCloak's block
/// EnvCloak's.
fn envcloaks(found: &str) -> bool {
    let lf = found.replace("\r\n", "\n");
    let bare = lf.strip_suffix('\n').unwrap_or(&lf);
    bare == block().trim_end_matches('\n')
        || EARLIER
            .iter()
            .any(|e| bare == format!("{BEGIN}\n{e}\n{END}"))
}

/// `text` with the block in it: appended after a blank line when there is
/// none, replaced in place when an earlier version's differs. A block
/// inside an open comment or fence is refused even when it is as it
/// should be (the Codex review: it reported success while hidden), and
/// one whose text the person changed is left (lesson L-09: not
/// EnvCloak's to write over).
pub fn insert(text: &[u8]) -> Result<Change, BlockError> {
    let text = std::str::from_utf8(text).map_err(|_| BlockError::NotUtf8)?;
    let want = block();
    match find(text)? {
        Some((b, e)) => {
            if ends_open(&text[..b]) {
                return Err(BlockError::Unclosed);
            }
            if text[b..e] == want {
                return Ok(Change::Unchanged);
            }
            if !envcloaks(&text[b..e]) {
                return Err(BlockError::Modified);
            }
            Ok(Change::New(format!("{}{want}{}", &text[..b], &text[e..])))
        }
        None => {
            if ends_open(text) {
                return Err(BlockError::Unclosed);
            }
            let sep = if text.is_empty() {
                ""
            } else if text.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok(Change::New(format!("{text}{sep}{want}")))
        }
    }
}

/// `text` without the block: the block, and the blank line before it that
/// [`insert`] adds, taken out (kept when no blank line or end of file
/// follows the block, so the text on either side stays apart).
/// Unchanged when there is no block.
///
/// # Errors
/// When the file is not UTF-8, its markers are damaged, or the block's
/// text is not one EnvCloak wrote ([`BlockError::Modified`]: the person's
/// text between the markers is never taken out).
pub fn remove(text: &[u8]) -> Result<Change, BlockError> {
    let text = std::str::from_utf8(text).map_err(|_| BlockError::NotUtf8)?;
    let Some((b, e)) = find(text)? else {
        return Ok(Change::Unchanged);
    };
    if !envcloaks(&text[b..e]) {
        return Err(BlockError::Modified);
    }
    let mut start = b;
    let after = &text[e..];
    if text[..b].ends_with("\n\n")
        && (after.is_empty() || after.starts_with('\n') || after.starts_with("\r\n"))
    {
        start -= 1;
    }
    Ok(Change::New(format!("{}{}", &text[..start], &text[e..])))
}

/// Every `envcloak <command>` the block names.
pub fn commands_named() -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut rest = INSTRUCTIONS;
    while let Some(p) = rest.find("`envcloak ") {
        rest = &rest[p + 10..];
        let word: &str = rest
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .next()
            .unwrap_or("");
        if !word.is_empty() && !out.contains(&word) {
            out.push(word);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(c: Change) -> String {
        match c {
            Change::New(s) => s,
            Change::Unchanged => String::from("<unchanged>"),
        }
    }

    #[test]
    fn insert_then_remove_gives_the_file_back() {
        for original in ["", "# Notes\n", "# Notes\n\n", "# Notes", "a\r\nb\r\n"] {
            let with = new(insert(original.as_bytes()).unwrap_or(Change::Unchanged));
            assert!(with.contains(&block()), "{original:?}");
            assert_eq!(insert(with.as_bytes()), Ok(Change::Unchanged));
            let without = new(remove(with.as_bytes()).unwrap_or(Change::Unchanged));
            let back = if original == "# Notes" {
                // A file without a final newline gets one blank line less
                // back: the block's separator is read as a blank line.
                "# Notes\n".to_owned()
            } else {
                original.to_owned()
            };
            assert_eq!(without, back, "{original:?}");
        }
    }

    /// Text the person added after the block stays, without the blank
    /// line the block's insertion made: the file reads as before plus the
    /// person's text.
    #[test]
    fn text_added_after_the_block_stays_and_the_separator_goes() {
        let with = new(insert(b"# Notes\n").unwrap_or(Change::Unchanged));
        let added = format!("{with}\nMore of mine.\n");
        assert_eq!(
            new(remove(added.as_bytes()).unwrap_or(Change::Unchanged)),
            "# Notes\n\nMore of mine.\n"
        );
        // Text right after the block, with no blank line: kept apart.
        let tight = format!("{with}Right after.\n");
        assert_eq!(
            new(remove(tight.as_bytes()).unwrap_or(Change::Unchanged)),
            "# Notes\n\nRight after.\n"
        );
    }

    /// Lesson L-09 for the block: text between the markers that is not
    /// EnvCloak's is the person's, and neither install nor uninstall
    /// writes over it or takes it out.
    ///
    /// Mutation checked: `envcloaks` answering true for any block (the
    /// previous replace-whatever-differs): the person's line is replaced,
    /// and removed, and this fails.
    #[test]
    fn a_block_the_person_changed_is_left_as_it_is() {
        let edited = format!("top\n\n{BEGIN}\nold words\n{END}\nbottom\n");
        assert_eq!(insert(edited.as_bytes()), Err(BlockError::Modified));
        assert_eq!(remove(edited.as_bytes()), Err(BlockError::Modified));
        let mine = new(insert(b"top\n").unwrap_or(Change::Unchanged));
        let added = mine.replace(END, &format!("- and mine\n{END}"));
        assert_eq!(insert(added.as_bytes()), Err(BlockError::Modified));
        assert_eq!(remove(added.as_bytes()), Err(BlockError::Modified));
        // CRLF line ends are still EnvCloak's block.
        let crlf = mine.replace('\n', "\r\n");
        assert!(remove(crlf.as_bytes()).is_ok());
    }

    /// The Codex review: a block already there, as it should be, inside an
    /// open fence or comment is hidden, and is refused, not reported as
    /// in place; a fence closes only with its own character, at least as
    /// long and bare.
    ///
    /// Mutations checked: the equality shortcut before the placement
    /// check (the previous order): the hidden identical block answers
    /// `Unchanged` and this fails; any fence line closing the open one
    /// (the previous toggle): the fences closed by `~~~` or a shorter run
    /// are taken as closed and this fails.
    #[test]
    fn a_hidden_block_is_refused_even_when_it_is_as_it_should_be() {
        for open in [
            "<!-- open\n",
            "```\n",
            "~~~~\n",
            "```sh\n",
            "````\n```\n",
            "```\n~~~\n",
            "~~~\n```\n",
            "```\n``` not a close\n",
            "  ```\n",
        ] {
            let hidden = format!("{open}{}", block());
            assert_eq!(
                insert(hidden.as_bytes()),
                Err(BlockError::Unclosed),
                "{open:?}"
            );
            assert_eq!(
                insert(open.as_bytes()),
                Err(BlockError::Unclosed),
                "{open:?}"
            );
        }
        for closed in [
            "```\ncode\n```\n",
            "~~~\ncode\n~~~~\n",
            "````\n```\n````\n",
            "<!-- c -->\n",
            "    ```\n",
            "``` a`b\n",
        ] {
            let shown = format!("{closed}\n{}", block());
            assert_eq!(
                insert(shown.as_bytes()),
                Ok(Change::Unchanged),
                "{closed:?}"
            );
            assert!(insert(closed.as_bytes()).is_ok(), "{closed:?}");
        }
    }

    #[test]
    fn damaged_open_and_non_utf8_files_are_refused() {
        assert_eq!(insert(b"\xff\xfe"), Err(BlockError::NotUtf8));
        let two = format!("{BEGIN}\n{END}\n{BEGIN}\n{END}\n");
        assert_eq!(insert(two.as_bytes()), Err(BlockError::Damaged));
        let reversed = format!("{END}\n{BEGIN}\n");
        assert_eq!(insert(reversed.as_bytes()), Err(BlockError::Damaged));
        assert_eq!(
            insert(b"text <!-- envcloak:begin --> inline\n"),
            Err(BlockError::Damaged)
        );
        assert_eq!(insert(b"<!-- an open comment\n"), Err(BlockError::Unclosed));
        assert_eq!(insert(b"```\ncode\n"), Err(BlockError::Unclosed));
        assert!(insert(b"<!-- closed -->\n```\ncode\n```\n").is_ok());
    }

    #[test]
    fn the_block_names_shipped_commands_only() {
        assert_eq!(commands_named(), ["run", "ls", "ref", "add", "init"]);
        assert!(!INSTRUCTIONS.contains("--ask"));
        assert!(!INSTRUCTIONS.contains("<!--"));
    }
}
