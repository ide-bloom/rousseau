//! Newline-delimited framing for the MCP stdio transport.
//!
//! MCP stdio messages are JSON-RPC objects separated by `\n` and must not
//! contain embedded newlines. Reads from a pipe can split a message or
//! carry several; [`LineFramer`] reassembles complete lines while keeping the
//! exact bytes (including `\r` and the trailing `\n`) so relaying is
//! byte-exact.

/// Lines longer than this are passed through without being retained for
/// parsing, so a hostile peer cannot make the proxy buffer without bound.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

/// One framed chunk produced by [`LineFramer::push`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A complete line, including its trailing `\n`.
    Line(Vec<u8>),
    /// Bytes of an over-long line, to be forwarded unparsed.
    Oversized(Vec<u8>),
}

impl Frame {
    /// Raw bytes to forward.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Line(b) | Self::Oversized(b) => b,
        }
    }
}

/// Reassembles newline-terminated lines from arbitrary chunks.
#[derive(Debug, Default)]
pub struct LineFramer {
    buf: Vec<u8>,
    oversized: bool,
}

impl LineFramer {
    /// Empty framer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a chunk and returns every frame it completes.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut rest = chunk;
        while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            let (line, tail) = rest.split_at(pos + 1);
            if self.oversized {
                out.push(Frame::Oversized(line.to_vec()));
                self.oversized = false;
            } else {
                self.buf.extend_from_slice(line);
                out.push(Frame::Line(std::mem::take(&mut self.buf)));
            }
            rest = tail;
        }
        if !rest.is_empty() {
            if self.oversized {
                out.push(Frame::Oversized(rest.to_vec()));
            } else if self.buf.len() + rest.len() > MAX_LINE {
                let mut b = std::mem::take(&mut self.buf);
                b.extend_from_slice(rest);
                out.push(Frame::Oversized(b));
                self.oversized = true;
            } else {
                self.buf.extend_from_slice(rest);
            }
        }
        out
    }

    /// Bytes of an incomplete trailing line (flushed at EOF).
    pub fn take_remainder(&mut self) -> Vec<u8> {
        self.oversized = false;
        std::mem::take(&mut self.buf)
    }

    /// True if a partial line is buffered.
    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(frames: &[Frame]) -> Vec<String> {
        frames.iter().map(|f| String::from_utf8_lossy(f.bytes()).into_owned()).collect()
    }

    #[test]
    fn whole_partial_and_multi() {
        let mut f = LineFramer::new();
        assert!(f.push(b"{\"a\":").is_empty());
        assert!(f.has_partial());
        assert_eq!(lines(&f.push(b"1}\n{\"b\":2}\r\n{\"c\"")), vec!["{\"a\":1}\n", "{\"b\":2}\r\n"]);
        assert_eq!(lines(&f.push(b":3}\n")), vec!["{\"c\":3}\n"]);
        assert!(!f.has_partial());
        assert!(f.push(b"").is_empty());
        f.push(b"tail");
        assert_eq!(f.take_remainder(), b"tail");
    }

    #[test]
    fn byte_exact_reassembly_any_split() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1}\n\n{\"x\":\"\xc3\xa9\"}\n";
        for split in 0..input.len() {
            let mut f = LineFramer::new();
            let mut out = Vec::new();
            for fr in f.push(&input[..split]).into_iter().chain(f.push(&input[split..])) {
                out.extend_from_slice(fr.bytes());
            }
            assert_eq!(out, input, "split at {split}");
        }
    }
}
