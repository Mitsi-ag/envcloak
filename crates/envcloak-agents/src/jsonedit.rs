//! Span-preserving edits of an agent's JSON settings (M2 plan M2-08; SPEC
//! §7: Claude Code's `settings.json`, Codex's `hooks.json`): every byte
//! outside the spans an edit changes stays as it was, so the person's
//! layout, order and spacing survive an install, and an uninstall right
//! after it gives the file back byte for byte (the installer keeps where
//! each edit's text went, [`crate::hunks`]). An edit only inserts, apart
//! from the white space inside an empty container it fills.
//!
//! The reader is strict JSON (RFC 8259): a comment or a trailing comma is
//! JSONC, which is refused and named ([`JsonError::Jsonc`]), not
//! rewritten as JSON; a key given twice in one object is refused
//! ([`JsonError::DuplicateKey`]), since programs disagree on which one
//! wins; so is a byte-order mark, invalid UTF-8, a lone surrogate, a
//! control character in a string and nesting past [`MAX_DEPTH`]. Errors
//! carry no text from the file.
//!
//! The edits add to an array (creating the objects and the array on the
//! way when they are missing) an element not already in it, and remove
//! an element equal to one given; and add a member to an object (Claude
//! Code's `mcpServers` in `.claude.json`) where that key is free, and
//! remove it while its value is still the one given. A removal takes out
//! the containers the add created once they are empty again.

use serde_json::Value;

/// The deepest nesting read.
pub const MAX_DEPTH: usize = 64;

/// Why a file could not be read as JSON or edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Not UTF-8, or starts with a byte-order mark.
    NotUtf8,
    /// A comment or a trailing comma: JSON with comments, which is not
    /// rewritten.
    Jsonc,
    /// A key given twice in one object.
    DuplicateKey,
    /// Nested past [`MAX_DEPTH`].
    TooDeep,
    /// Not JSON.
    Syntax,
    /// A value on the path is not an object, or the last one not an array.
    Shape,
}

impl JsonError {
    /// A stable name for reports.
    pub fn name(self) -> &'static str {
        match self {
            JsonError::NotUtf8 => "not_utf8",
            JsonError::Jsonc => "jsonc",
            JsonError::DuplicateKey => "duplicate_key",
            JsonError::TooDeep => "too_deep",
            JsonError::Syntax => "not_json",
            JsonError::Shape => "unexpected_shape",
        }
    }

    /// What it means, for a person.
    pub fn message(self) -> &'static str {
        match self {
            JsonError::NotUtf8 => "the file is not UTF-8 text",
            JsonError::Jsonc => {
                "the file has comments or trailing commas (JSONC), which EnvCloak does not \
                 rewrite"
            }
            JsonError::DuplicateKey => "the file gives a key twice in one object",
            JsonError::TooDeep => "the file nests deeper than EnvCloak reads",
            JsonError::Syntax => "the file is not valid JSON",
            JsonError::Shape => "a setting EnvCloak adds to is not of the type it expects",
        }
    }
}

/// A value read, with the byte span it takes in the text.
#[derive(Debug, Clone)]
pub struct Node {
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
}

#[derive(Debug, Clone)]
pub enum Kind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    Scalar,
}

/// An object's member: its key and value.
#[derive(Debug, Clone)]
pub struct Member {
    pub key: String,
    pub key_start: usize,
    pub value: Node,
}

/// A JSON text and its tree.
#[derive(Debug, Clone)]
pub struct Doc {
    text: String,
    root: Node,
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) -> Result<(), JsonError> {
        while let Some(&b) = self.s.get(self.i) {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                b'/' => return Err(JsonError::Jsonc),
                _ => break,
            }
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Node, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.ws()?;
        let start = self.i;
        let kind = match self.s.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut members: Vec<Member> = Vec::new();
                // Claude Code's `.claude.json` keeps one member per
                // project: keys are checked for duplicates in a set, not
                // against every earlier member.
                let mut keys = std::collections::HashSet::new();
                self.ws()?;
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws()?;
                        if self.s.get(self.i) == Some(&b'}') {
                            return Err(JsonError::Jsonc);
                        }
                        let key_start = self.i;
                        let key = self.string()?;
                        if !keys.insert(key.clone()) {
                            return Err(JsonError::DuplicateKey);
                        }
                        self.ws()?;
                        if self.s.get(self.i) != Some(&b':') {
                            return Err(JsonError::Syntax);
                        }
                        self.i += 1;
                        let value = self.value(depth + 1)?;
                        members.push(Member {
                            key,
                            key_start,
                            value,
                        });
                        self.ws()?;
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(JsonError::Syntax),
                        }
                    }
                }
                Kind::Object(members)
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws()?;
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws()?;
                        if self.s.get(self.i) == Some(&b']') {
                            return Err(JsonError::Jsonc);
                        }
                        items.push(self.value(depth + 1)?);
                        self.ws()?;
                        match self.s.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err(JsonError::Syntax),
                        }
                    }
                }
                Kind::Array(items)
            }
            Some(b'"') => {
                self.string()?;
                Kind::Scalar
            }
            Some(b't') => self.word(b"true")?,
            Some(b'f') => self.word(b"false")?,
            Some(b'n') => self.word(b"null")?,
            Some(b'-' | b'0'..=b'9') => self.number()?,
            _ => return Err(JsonError::Syntax),
        };
        Ok(Node {
            start,
            end: self.i,
            kind,
        })
    }

    fn word(&mut self, w: &[u8]) -> Result<Kind, JsonError> {
        if self.s[self.i..].starts_with(w) {
            self.i += w.len();
            Ok(Kind::Scalar)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn number(&mut self) -> Result<Kind, JsonError> {
        let digits = |p: &mut Self| {
            let from = p.i;
            while p.s.get(p.i).is_some_and(u8::is_ascii_digit) {
                p.i += 1;
            }
            p.i > from
        };
        if self.s.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(JsonError::Syntax),
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !digits(self) {
                return Err(JsonError::Syntax);
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digits(self) {
                return Err(JsonError::Syntax);
            }
        }
        Ok(Kind::Scalar)
    }

    /// A string at the cursor, decoded.
    fn string(&mut self) -> Result<String, JsonError> {
        if self.s.get(self.i) != Some(&b'"') {
            return Err(JsonError::Syntax);
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(&b) = self.s.get(self.i) else {
                return Err(JsonError::Syntax);
            };
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.s.get(self.i) else {
                        return Err(JsonError::Syntax);
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&hi) {
                                if !self.s[self.i..].starts_with(b"\\u") {
                                    return Err(JsonError::Syntax);
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JsonError::Syntax);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(JsonError::Syntax);
                            } else {
                                hi
                            };
                            out.push(char::from_u32(c).ok_or(JsonError::Syntax)?);
                        }
                        _ => return Err(JsonError::Syntax),
                    }
                }
                0..=0x1f => return Err(JsonError::Syntax),
                _ => {
                    // A whole UTF-8 sequence (the text is valid UTF-8).
                    let len = utf8_len(b);
                    let end = (self.i + len).min(self.s.len());
                    let piece =
                        std::str::from_utf8(&self.s[self.i..end]).map_err(|_| JsonError::Syntax)?;
                    out.push_str(piece);
                    self.i = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self.s.get(self.i..self.i + 4).ok_or(JsonError::Syntax)?;
        let t = std::str::from_utf8(h).map_err(|_| JsonError::Syntax)?;
        if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(JsonError::Syntax);
        }
        self.i += 4;
        u32::from_str_radix(t, 16).map_err(|_| JsonError::Syntax)
    }
}

fn utf8_len(b: u8) -> usize {
    match b {
        0xF0..=0xF7 => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

impl Doc {
    /// Reads `bytes` as one strict JSON document.
    pub fn parse(bytes: &[u8]) -> Result<Doc, JsonError> {
        if bytes.starts_with(b"\xEF\xBB\xBF") {
            return Err(JsonError::NotUtf8);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| JsonError::NotUtf8)?
            .to_owned();
        let mut p = P {
            s: text.as_bytes(),
            i: 0,
        };
        let root = p.value(0)?;
        p.ws()?;
        if p.i != text.len() {
            return Err(JsonError::Syntax);
        }
        Ok(Doc { text, root })
    }

    /// An empty object, for a file that does not exist yet.
    pub fn empty() -> Doc {
        Doc {
            text: "{\n}\n".to_owned(),
            root: Node {
                start: 0,
                end: 3,
                kind: Kind::Object(Vec::new()),
            },
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// The value as `serde_json` reads it.
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    /// The value at `path` of object keys.
    pub fn get(&self, path: &[&str]) -> Option<&Node> {
        let mut n = &self.root;
        for k in path {
            let Kind::Object(ms) = &n.kind else {
                return None;
            };
            n = &ms.iter().find(|m| m.key == *k)?.value;
        }
        Some(n)
    }

    fn reparse(&mut self, text: String) -> Result<(), JsonError> {
        *self = Doc::parse(text.as_bytes())?;
        Ok(())
    }

    /// The indentation unit the file uses: the first indented line's
    /// leading blanks, else two spaces.
    fn unit(&self) -> String {
        for line in self.text.lines().skip(1) {
            let lead: String = line
                .chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .collect();
            if !lead.is_empty() && line.len() > lead.len() {
                return lead;
            }
        }
        "  ".to_owned()
    }

    /// The leading blanks of the line `at` is on.
    fn indent_at(&self, at: usize) -> String {
        let line_start = self.text[..at].rfind('\n').map_or(0, |p| p + 1);
        self.text[line_start..]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect()
    }

    /// Adds `value` to the array at `path`, creating the missing objects
    /// and the array, unless an equal element is there. Returns how many
    /// keys of `path` it created (0 when they were all there), or `None`
    /// when nothing changed.
    pub fn add_to_array(
        &mut self,
        path: &[&str],
        value: &Value,
    ) -> Result<Option<usize>, JsonError> {
        // How much of the path is there.
        let mut have = 0;
        let mut node = &self.root;
        for k in path {
            let Kind::Object(ms) = &node.kind else {
                return Err(JsonError::Shape);
            };
            match ms.iter().find(|m| m.key == *k) {
                Some(m) => {
                    node = &m.value;
                    have += 1;
                }
                None => break,
            }
        }
        if have == path.len() {
            let Kind::Array(items) = &node.kind else {
                return Err(JsonError::Shape);
            };
            let existing: Value = serde_json::from_str(&self.text[node.start..node.end])
                .map_err(|_| JsonError::Syntax)?;
            if existing
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == value))
            {
                return Ok(None);
            }
            let node = node.clone();
            let last = items.last().map(|n| n.end);
            let text = self.append_item(&node, last, None, value);
            self.reparse(text)?;
            return Ok(Some(0));
        }
        if !matches!(node.kind, Kind::Object(_)) {
            return Err(JsonError::Shape);
        }
        // Build what is missing, innermost first.
        let mut built = Value::Array(vec![value.clone()]);
        for k in path[have + 1..].iter().rev() {
            let mut m = serde_json::Map::new();
            m.insert((*k).to_owned(), built);
            built = Value::Object(m);
        }
        let node = node.clone();
        let Kind::Object(ms) = &node.kind else {
            return Err(JsonError::Shape);
        };
        let last = ms.last().map(|m| m.value.end);
        let text = self.append_item(&node, last, Some(path[have]), &built);
        self.reparse(text)?;
        Ok(Some(path.len() - have))
    }

    /// The text with `value` (a member named `key` in an object, or an
    /// element) added at the end of the container `node`, whose last item
    /// ends at `last`. In a container laid out on lines, the item goes on a
    /// line of its own at its siblings' indentation, laid out on lines
    /// itself; in one written on one line, it is written on one line too.
    fn append_item(
        &self,
        node: &Node,
        last: Option<usize>,
        key: Option<&str>,
        value: &Value,
    ) -> String {
        let unit = self.unit();
        let own = &self.text[node.start..node.end];
        let multi = match last {
            Some(_) => own.contains('\n'),
            None => own.contains('\n') || self.text.trim_end().contains('\n'),
        };
        let item = |indent: &str| {
            let v = if multi {
                reindent(&render_value(value), indent, &unit)
            } else {
                serde_json::to_string(value).unwrap_or_default()
            };
            match key {
                Some(k) => format!("{}: {v}", json_string(k)),
                None => v,
            }
        };
        let close = node.end - 1;
        match last {
            Some(end) if multi => {
                let ind = self.indent_at(end);
                let it = item(&ind);
                format!("{},\n{ind}{it}{}", &self.text[..end], &self.text[end..])
            }
            Some(end) => format!("{}, {}{}", &self.text[..end], item(""), &self.text[end..]),
            None if multi => {
                let outer = self.indent_at(node.start);
                let inner = format!("{outer}{unit}");
                let it = item(&inner);
                format!(
                    "{}\n{inner}{it}\n{outer}{}",
                    &self.text[..node.start + 1],
                    &self.text[close..]
                )
            }
            None => format!(
                "{}{}{}",
                &self.text[..node.start + 1],
                item(""),
                &self.text[close..]
            ),
        }
    }

    /// Removes from the array at `path` the elements equal to `value`, and
    /// then the last `created` keys of `path` while what they hold is
    /// empty. Returns whether anything changed.
    pub fn remove_from_array(
        &mut self,
        path: &[&str],
        value: &Value,
        created: usize,
    ) -> Result<bool, JsonError> {
        let mut changed = false;
        while let Some(node) = self.get(path) {
            let Kind::Array(items) = &node.kind else {
                return Err(JsonError::Shape);
            };
            let mut hit = None;
            for (k, it) in items.iter().enumerate() {
                let v: Value = serde_json::from_str(&self.text[it.start..it.end])
                    .map_err(|_| JsonError::Syntax)?;
                if &v == value {
                    hit = Some(k);
                    break;
                }
            }
            let Some(k) = hit else { break };
            let spans: Vec<(usize, usize)> = items.iter().map(|n| (n.start, n.end)).collect();
            let text = self.cut(node.start, node.end, &spans, k);
            self.reparse(text)?;
            changed = true;
        }
        // The containers the add created, innermost first, while empty.
        let before = self.text.len();
        self.remove_empty(path, created)?;
        changed |= self.text.len() != before;
        Ok(changed)
    }

    /// Adds the member `key: value` to the object at `path`, creating the
    /// missing objects on the way. Returns how many keys of `path` it
    /// created (0 when they were all there), or `None` when the member is
    /// there already with an equal value.
    ///
    /// # Errors
    /// [`JsonError::Shape`] when a value on the path is not an object, or
    /// the member is there with another value (which is never written
    /// over: the caller decides whose it is).
    pub fn add_member(
        &mut self,
        path: &[&str],
        key: &str,
        value: &Value,
    ) -> Result<Option<usize>, JsonError> {
        let mut have = 0;
        let mut node = &self.root;
        for k in path {
            let Kind::Object(ms) = &node.kind else {
                return Err(JsonError::Shape);
            };
            match ms.iter().find(|m| m.key == *k) {
                Some(m) => {
                    node = &m.value;
                    have += 1;
                }
                None => break,
            }
        }
        let Kind::Object(ms) = &node.kind else {
            return Err(JsonError::Shape);
        };
        if have == path.len() {
            if let Some(m) = ms.iter().find(|m| m.key == key) {
                let existing: Value = serde_json::from_str(&self.text[m.value.start..m.value.end])
                    .map_err(|_| JsonError::Syntax)?;
                return if &existing == value {
                    Ok(None)
                } else {
                    Err(JsonError::Shape)
                };
            }
            let node = node.clone();
            let last = ms.last().map(|m| m.value.end);
            let text = self.append_item(&node, last, Some(key), value);
            self.reparse(text)?;
            return Ok(Some(0));
        }
        let mut built = serde_json::Map::new();
        built.insert(key.to_owned(), value.clone());
        let mut built = Value::Object(built);
        for k in path[have + 1..].iter().rev() {
            let mut m = serde_json::Map::new();
            m.insert((*k).to_owned(), built);
            built = Value::Object(m);
        }
        let node = node.clone();
        let last = ms.last().map(|m| m.value.end);
        let text = self.append_item(&node, last, Some(path[have]), &built);
        self.reparse(text)?;
        Ok(Some(path.len() - have))
    }

    /// Removes the member `key` of the object at `path` while its value
    /// equals `value` (one that differs is someone else's, and stays), and
    /// then the last `created` keys of `path` while what they hold is
    /// empty. Returns whether anything changed.
    ///
    /// # Errors
    /// [`JsonError::Shape`] when the value at `path` is not an object.
    pub fn remove_member(
        &mut self,
        path: &[&str],
        key: &str,
        value: &Value,
        created: usize,
    ) -> Result<bool, JsonError> {
        let Some(node) = self.get(path) else {
            return Ok(false);
        };
        let Kind::Object(ms) = &node.kind else {
            return Err(JsonError::Shape);
        };
        let Some(k) = ms.iter().position(|m| m.key == key) else {
            return Ok(false);
        };
        let m = &ms[k];
        let existing: Value = serde_json::from_str(&self.text[m.value.start..m.value.end])
            .map_err(|_| JsonError::Syntax)?;
        if &existing != value {
            return Ok(false);
        }
        let spans: Vec<(usize, usize)> = ms.iter().map(|m| (m.key_start, m.value.end)).collect();
        let text = self.cut(node.start, node.end, &spans, k);
        self.reparse(text)?;
        self.remove_empty(path, created)?;
        Ok(true)
    }

    /// Removes the last `created` keys of `path`, innermost first, while
    /// what each holds is empty.
    fn remove_empty(&mut self, path: &[&str], created: usize) -> Result<(), JsonError> {
        for depth in (path.len().saturating_sub(created)..path.len()).rev() {
            let Some(n) = self.get(&path[..=depth]) else {
                continue;
            };
            let empty = match &n.kind {
                Kind::Array(a) => a.is_empty(),
                Kind::Object(o) => o.is_empty(),
                Kind::Scalar => false,
            };
            if !empty {
                break;
            }
            let Some(parent) = self.get(&path[..depth]) else {
                break;
            };
            let Kind::Object(ms) = &parent.kind else {
                break;
            };
            let Some(k) = ms.iter().position(|m| m.key == path[depth]) else {
                break;
            };
            let spans: Vec<(usize, usize)> =
                ms.iter().map(|m| (m.key_start, m.value.end)).collect();
            let text = self.cut(parent.start, parent.end, &spans, k);
            self.reparse(text)?;
        }
        Ok(())
    }

    /// The text without item `k` of the container spanning `start..end`,
    /// whose items span `spans`, and without the separator that joined it
    /// to the others.
    fn cut(&self, start: usize, end: usize, spans: &[(usize, usize)], k: usize) -> String {
        let (from, to) = if spans.len() == 1 {
            // The only item: everything between the brackets.
            (start + 1, end - 1)
        } else if k + 1 == spans.len() {
            // The last: from the end of the one before.
            (spans[k - 1].1, spans[k].1)
        } else {
            // Any other: up to the start of the next.
            (spans[k].0, spans[k + 1].0)
        };
        format!("{}{}", &self.text[..from], &self.text[to..])
    }
}

/// `s` as a JSON string.
pub fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

/// A value laid out on lines, two spaces a level, the first line not
/// indented.
fn render_value(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// A rendered value's later lines moved to `indent`, a level's two spaces
/// replaced by `unit`.
fn reindent(rendered: &str, indent: &str, unit: &str) -> String {
    let mut out = String::new();
    for (k, line) in rendered.split('\n').enumerate() {
        if k > 0 {
            out.push('\n');
            out.push_str(indent);
        }
        let lead = line.len() - line.trim_start_matches(' ').len();
        out.push_str(&unit.repeat(lead / 2));
        out.push_str(&line[lead..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn added(src: &str, path: &[&str], v: &Value) -> (String, Option<usize>) {
        let mut d = Doc::parse(src.as_bytes()).unwrap_or_else(|_| Doc::empty());
        let c = d.add_to_array(path, v).unwrap_or(None);
        (d.text().to_owned(), c)
    }

    #[test]
    fn strict_json_only() {
        assert_eq!(Doc::parse(b"{\"a\":1,}").err(), Some(JsonError::Jsonc));
        assert_eq!(Doc::parse(b"{\"a\":[1,]}").err(), Some(JsonError::Jsonc));
        assert_eq!(Doc::parse(b"{ // c\n}").err(), Some(JsonError::Jsonc));
        assert_eq!(
            Doc::parse(b"{\"a\":1,\"a\":2}").err(),
            Some(JsonError::DuplicateKey)
        );
        assert_eq!(
            Doc::parse(b"\xEF\xBB\xBF{}").err(),
            Some(JsonError::NotUtf8)
        );
        assert_eq!(
            Doc::parse(b"{\"a\":\"\xff\"}").err(),
            Some(JsonError::NotUtf8)
        );
        assert_eq!(
            Doc::parse(b"{\"a\":\"\\ud800\"}").err(),
            Some(JsonError::Syntax)
        );
        assert_eq!(
            Doc::parse(b"{\"a\":\"\x01\"}").err(),
            Some(JsonError::Syntax)
        );
        assert_eq!(Doc::parse(b"{} {}").err(), Some(JsonError::Syntax));
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert_eq!(Doc::parse(deep.as_bytes()).err(), Some(JsonError::TooDeep));
        assert!(Doc::parse(b"{\"a\":[1,2.5e-3,-0,true,null,\"\\u00e9\\ud83d\\ude00\"]}").is_ok());
    }

    #[test]
    fn adds_keep_every_other_byte_and_removes_give_them_back() {
        let v = json!("Read(**/.env*)");
        let entry = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]});
        for src in [
            "{}",
            "{}\n",
            "{\n}\n",
            "{\"a\": 1}",
            "{\n  \"model\": \"x\",\n  \"permissions\": {\n    \"deny\": [\n      \"Bash(rm:*)\"\n    ]\n  }\n}\n",
            "{\n\t\"permissions\": {\"deny\": []}\n}",
            "{\"permissions\":{\"allow\":[\"Bash(ls)\"]},\"x\":[1,2]}",
        ] {
            for (path, value) in [
                (&["permissions", "deny"][..], &v),
                (&["hooks", "PreToolUse"][..], &entry),
            ] {
                let (text, created) = added(src, path, value);
                let mut d =
                    Doc::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{src}: {e:?}\n{text}"));
                assert!(
                    d.value().pointer(&format!("/{}", path.join("/"))).is_some(),
                    "{src}"
                );
                // Every byte of the original is still there, in order.
                let mut it = text.chars();
                assert!(src.chars().all(|c| it.any(|d| d == c)), "{src}\n{text}");
                // Adding again changes nothing.
                assert_eq!(d.add_to_array(path, value), Ok(None));
                // Only insertions (and white space filled): they undo
                // exactly.
                let h = crate::hunks::hunks(src.as_bytes(), text.as_bytes())
                    .unwrap_or_else(|| panic!("{src}\n{text}"));
                assert_eq!(
                    crate::hunks::unapply(text.as_bytes(), &h).as_deref(),
                    Some(src.as_bytes())
                );
                // The structural removal gives the value back.
                let created = created.unwrap_or(0);
                assert_eq!(d.remove_from_array(path, value, created), Ok(true));
                let back: Value = serde_json::from_str(d.text()).unwrap_or(Value::Null);
                let orig: Value = serde_json::from_str(src).unwrap_or(Value::Null);
                assert_eq!(back, orig, "{src}\n{}", d.text());
            }
        }
    }

    #[test]
    fn pretty_files_stay_pretty() {
        let src = "{\n  \"permissions\": {\n    \"deny\": [\n      \"A\"\n    ]\n  }\n}\n";
        let (text, _) = added(src, &["permissions", "deny"], &json!("B"));
        assert_eq!(
            text,
            "{\n  \"permissions\": {\n    \"deny\": [\n      \"A\",\n      \"B\"\n    ]\n  }\n}\n"
        );
        let (text, created) = added(
            src,
            &["sandbox", "network", "allowUnixSockets"],
            &json!("/s"),
        );
        assert_eq!(created, Some(3));
        assert!(text.ends_with(
            "  },\n  \"sandbox\": {\n    \"network\": {\n      \"allowUnixSockets\": [\n        \"/s\"\n      ]\n    }\n  }\n}\n"
        ), "{text}");
    }

    /// Claude Code's `mcpServers` in `.claude.json`: a member added where
    /// its key is free keeps every other byte and undoes exactly; one
    /// there with another value is never written over, and one whose
    /// value changed since is never removed.
    ///
    /// Mutation checked: `remove_member` without its value comparison
    /// (any member of that name removed): the changed member is taken out
    /// and this fails.
    #[test]
    fn members_are_added_where_free_and_removed_while_unchanged() {
        let entry = json!({"command": "/b/envcloak", "args": ["mcp"], "timeout": 60000});
        for src in [
            "{}",
            "{\n}\n",
            "{\n  \"numStartups\": 3,\n  \"projects\": {\n    \"/w\": {}\n  }\n}",
            "{\"mcpServers\":{\"other\":{\"command\":\"/usr/bin/true\"}}}",
            "{\n  \"mcpServers\": {}\n}\n",
        ] {
            let mut d = Doc::parse(src.as_bytes()).unwrap_or_else(|e| panic!("{src}: {e:?}"));
            let created = d
                .add_member(&["mcpServers"], "envcloak", &entry)
                .unwrap_or_else(|e| panic!("{src}: {e:?}"))
                .unwrap_or_else(|| panic!("{src}: nothing added"));
            let text = d.text().to_owned();
            assert_eq!(
                d.value().pointer("/mcpServers/envcloak"),
                Some(&entry),
                "{text}"
            );
            let h = crate::hunks::hunks(src.as_bytes(), text.as_bytes())
                .unwrap_or_else(|| panic!("{src}\n{text}"));
            assert_eq!(
                crate::hunks::unapply(text.as_bytes(), &h).as_deref(),
                Some(src.as_bytes())
            );
            assert_eq!(d.add_member(&["mcpServers"], "envcloak", &entry), Ok(None));
            assert_eq!(
                d.add_member(&["mcpServers"], "envcloak", &json!({"command": "x"})),
                Err(JsonError::Shape)
            );
            // Changed since: someone else's.
            assert_eq!(
                d.remove_member(
                    &["mcpServers"],
                    "envcloak",
                    &json!({"command": "x"}),
                    created
                ),
                Ok(false)
            );
            assert_eq!(d.text(), text);
            assert_eq!(
                d.remove_member(&["mcpServers"], "envcloak", &entry, created),
                Ok(true)
            );
            let back: Value = serde_json::from_str(d.text()).unwrap_or(Value::Null);
            let orig: Value = serde_json::from_str(src).unwrap_or(Value::Null);
            assert_eq!(back, orig, "{src}\n{}", d.text());
        }
        let mut d = Doc::parse(b"{\"mcpServers\": []}").unwrap_or_else(|_| Doc::empty());
        assert_eq!(
            d.add_member(&["mcpServers"], "envcloak", &entry),
            Err(JsonError::Shape)
        );
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused() {
        let mut d = Doc::parse(b"{\"permissions\": []}").unwrap_or_else(|_| Doc::empty());
        assert_eq!(
            d.add_to_array(&["permissions", "deny"], &json!("x")),
            Err(JsonError::Shape)
        );
        let mut d =
            Doc::parse(b"{\"permissions\": {\"deny\": \"x\"}}").unwrap_or_else(|_| Doc::empty());
        assert_eq!(
            d.add_to_array(&["permissions", "deny"], &json!("x")),
            Err(JsonError::Shape)
        );
        let mut d = Doc::parse(b"[]").unwrap_or_else(|_| Doc::empty());
        assert_eq!(d.add_to_array(&["a"], &json!(1)), Err(JsonError::Shape));
    }
}
