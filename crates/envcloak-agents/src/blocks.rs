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
//! text reaches the model; the instructions are never inside one. A file
//! that ends inside an open HTML comment or an open code fence is refused
//! ([`BlockError::Unclosed`]): the block appended there would be read as
//! part of it. A file whose markers are not exactly one begin before one
//! end, each a line of its own, is refused ([`BlockError::Damaged`]), and
//! so is one that is not UTF-8.

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
}

impl BlockError {
    /// A stable name for reports.
    pub fn name(self) -> &'static str {
        match self {
            BlockError::NotUtf8 => "not_utf8",
            BlockError::Damaged => "block_damaged",
            BlockError::Unclosed => "inside_comment",
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
                "the file ends inside an open HTML comment or code block, where the instructions \
                 would be hidden"
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

/// Whether the end of `text` is inside an open HTML comment or fenced code
/// block.
fn ends_open(text: &str) -> bool {
    let mut in_fence = false;
    let mut in_comment = false;
    for line in text.split('\n') {
        let t = line.trim_start();
        if !in_comment && (t.starts_with("```") || t.starts_with("~~~")) {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
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
    in_fence || in_comment
}

/// A change to a file's block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The block is there, as it should be.
    Unchanged,
    /// The file's new text.
    New(String),
}

/// `text` with the block in it: appended after a blank line when there is
/// none, replaced in place when an older one differs.
pub fn insert(text: &[u8]) -> Result<Change, BlockError> {
    let text = std::str::from_utf8(text).map_err(|_| BlockError::NotUtf8)?;
    let want = block();
    match find(text)? {
        Some((b, e)) => {
            if text[b..e] == want {
                return Ok(Change::Unchanged);
            }
            if ends_open(&text[..b]) {
                return Err(BlockError::Unclosed);
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
/// [`insert`] adds, taken out. Unchanged when there is no block.
pub fn remove(text: &[u8]) -> Result<Change, BlockError> {
    let text = std::str::from_utf8(text).map_err(|_| BlockError::NotUtf8)?;
    let Some((b, e)) = find(text)? else {
        return Ok(Change::Unchanged);
    };
    let mut start = b;
    if e == text.len() && text[..b].ends_with("\n\n") {
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

    #[test]
    fn an_older_block_is_replaced_in_place() {
        let old = format!("top\n\n{BEGIN}\nold words\n{END}\nbottom\n");
        let got = new(insert(old.as_bytes()).unwrap_or(Change::Unchanged));
        assert_eq!(got, format!("top\n\n{}bottom\n", block()));
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
