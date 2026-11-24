//! A small JSON-with-comments parser that records the byte span of every
//! value, so configuration files can be edited by splicing replacement text
//! into exactly the bytes that change. Everything else (formatting,
//! comments, key order, unrelated keys) is preserved byte for byte.
//!
//! Accepts `//` and `/* */` comments and trailing commas (VS Code's
//! `mcp.json` is JSONC).

/// Errors raised by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("JSON syntax error at byte {pos}: {msg}")]
pub struct SpanError {
    pub pos: usize,
    pub msg: String,
}

/// A parsed value with its byte span `[start, end)` in the source.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
}

/// Value kinds.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    String(String),
    Number,
    Bool(bool),
    Null,
}

/// An object member.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub key: String,
    pub value: Node,
}

impl Node {
    /// Member value by key.
    pub fn get(&self, key: &str) -> Option<&Node> {
        match &self.kind {
            Kind::Object(m) => m.iter().find(|x| x.key == key).map(|x| &x.value),
            _ => None,
        }
    }

    /// Object members.
    pub fn members(&self) -> &[Member] {
        match &self.kind {
            Kind::Object(m) => m,
            _ => &[],
        }
    }

    /// Array items.
    pub fn items(&self) -> &[Node] {
        match &self.kind {
            Kind::Array(a) => a,
            _ => &[],
        }
    }

    /// String value.
    pub fn as_str(&self) -> Option<&str> {
        match &self.kind {
            Kind::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Parses `src`.
pub fn parse(src: &str) -> Result<Node, SpanError> {
    let mut p = Parser { s: src.as_bytes(), src, i: 0 };
    p.skip_ws()?;
    // Tolerate a UTF-8 BOM.
    if src.starts_with('\u{feff}') {
        p.i = 3;
        p.skip_ws()?;
    }
    let v = p.value()?;
    p.skip_ws()?;
    if p.i != p.s.len() {
        return Err(p.err("trailing characters"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    src: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> SpanError {
        SpanError { pos: self.i, msg: msg.to_string() }
    }

    fn skip_ws(&mut self) -> Result<(), SpanError> {
        loop {
            while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\r' | b'\n') {
                self.i += 1;
            }
            if self.s[self.i..].starts_with(b"//") {
                while self.i < self.s.len() && self.s[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.s[self.i..].starts_with(b"/*") {
                let rest = &self.src[self.i + 2..];
                let end = rest.find("*/").ok_or_else(|| self.err("unterminated comment"))?;
                self.i += 2 + end + 2;
            } else {
                return Ok(());
            }
        }
    }

    fn value(&mut self) -> Result<Node, SpanError> {
        let start = self.i;
        let kind = match self.s.get(self.i) {
            Some(b'{') => self.object()?,
            Some(b'[') => self.array()?,
            Some(b'"') => Kind::String(self.string()?),
            Some(b't') => self.literal("true", Kind::Bool(true))?,
            Some(b'f') => self.literal("false", Kind::Bool(false))?,
            Some(b'n') => self.literal("null", Kind::Null)?,
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                while self.i < self.s.len() && matches!(self.s[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                Kind::Number
            }
            _ => return Err(self.err("expected a value")),
        };
        Ok(Node { start, end: self.i, kind })
    }

    fn literal(&mut self, word: &str, kind: Kind) -> Result<Kind, SpanError> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(kind)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn string(&mut self) -> Result<String, SpanError> {
        let start = self.i;
        self.i += 1;
        while self.i < self.s.len() {
            match self.s[self.i] {
                b'\\' => self.i += 2,
                b'"' => {
                    self.i += 1;
                    let raw = &self.src[start..self.i];
                    return serde_json::from_str(raw).map_err(|e| SpanError { pos: start, msg: e.to_string() });
                }
                _ => self.i += 1,
            }
        }
        Err(self.err("unterminated string"))
    }

    fn object(&mut self) -> Result<Kind, SpanError> {
        self.i += 1;
        let mut members = Vec::new();
        loop {
            self.skip_ws()?;
            match self.s.get(self.i) {
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Kind::Object(members));
                }
                Some(b'"') => {}
                _ => return Err(self.err("expected a key or '}'")),
            }
            let key = self.string()?;
            self.skip_ws()?;
            if self.s.get(self.i) != Some(&b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.skip_ws()?;
            let value = self.value()?;
            members.push(Member { key, value });
            self.skip_ws()?;
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {}
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self) -> Result<Kind, SpanError> {
        self.i += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws()?;
            if self.s.get(self.i) == Some(&b']') {
                self.i += 1;
                return Ok(Kind::Array(items));
            }
            items.push(self.value()?);
            self.skip_ws()?;
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {}
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }
}

/// A replacement of `src[start..end]` with `text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Splice {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// Applies non-overlapping splices to `src`.
pub fn apply(src: &str, splices: &[Splice]) -> String {
    let mut sorted: Vec<&Splice> = splices.iter().collect();
    sorted.sort_by_key(|s| s.start);
    let mut out = String::with_capacity(src.len() + 256);
    let mut pos = 0;
    for s in sorted {
        if s.start < pos {
            continue;
        }
        out.push_str(&src[pos..s.start]);
        out.push_str(&s.text);
        pos = s.end;
    }
    out.push_str(&src[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_and_comments() {
        let src = "{\n  // servers\n  \"servers\": { \"a\": { \"command\": \"npx\", \"args\": [\"-y\", \"x\",], }, },\n  /* block */ \"n\": 1.5e3, \"t\": true, \"z\": null\n}\n";
        let root = parse(src).unwrap();
        let cmd = root.get("servers").unwrap().get("a").unwrap().get("command").unwrap();
        assert_eq!(&src[cmd.start..cmd.end], "\"npx\"");
        assert_eq!(cmd.as_str(), Some("npx"));
        let args = root.get("servers").unwrap().get("a").unwrap().get("args").unwrap();
        assert_eq!(args.items().len(), 2);
        assert_eq!(root.get("t").unwrap().kind, Kind::Bool(true));
        let out = apply(src, &[Splice { start: cmd.start, end: cmd.end, text: "\"node\"".into() }]);
        assert_eq!(out, src.replace("\"npx\"", "\"node\""));
    }

    #[test]
    fn escapes_and_unicode() {
        let src = r#"{"p": "C:\\Program Files\\x \u00e9 \"q\""}"#;
        assert_eq!(parse(src).unwrap().get("p").unwrap().as_str(), Some("C:\\Program Files\\x é \"q\""));
    }

    #[test]
    fn errors() {
        for bad in ["{", "{\"a\" 1}", "[1 2]", "{\"a\":1} x", "\"open", "/* x"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
