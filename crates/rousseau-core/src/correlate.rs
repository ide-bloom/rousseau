//! Correlation: attributing OS activity to the tool call that caused it.
//!
//! Three sources of intent, in priority order (see `docs/correlation.md`):
//!
//! 1. **Inherited**: a process spawned for a tool call passes that
//!    attribution to all its descendants (handled by the process tree).
//! 2. **MCP windows**: while a `tools/call` to server *S* is in flight (plus a
//!    short grace period after the response), activity from *S*'s process
//!    subtree is attributed to that call. Concurrent calls to the same server
//!    are marked `ambiguous` and attributed to the most recent one.
//! 3. **Transcript tool uses**: a built-in tool use (e.g. Claude Code `Bash`)
//!    is matched to a process started by the same agent within a time window
//!    whose command line is similar to the tool's command. Matching works in
//!    both directions because transcripts are read with a small delay. File
//!    tools (`Read`, `Write`, `Edit`, …) are matched to file events from the
//!    agent process by path.
//!
//! Everything else inside an agent tree is `unexplained`.

use std::collections::VecDeque;

use crate::event::{Attribution, AttributionKind};
use crate::tree::ProcessKey;

/// Tunables. Defaults are documented in `docs/correlation.md`.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Activity this long after a `tools/call` response still belongs to it.
    pub mcp_grace_ms: i64,
    /// Open calls older than this are considered abandoned.
    pub mcp_max_open_ms: i64,
    /// A process may start this long before its transcript tool use timestamp.
    pub transcript_before_ms: i64,
    /// …or this long after it.
    pub transcript_after_ms: i64,
    /// Minimum share of the tool command's tokens found in the command line.
    pub min_similarity: f64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            mcp_grace_ms: 2_000,
            mcp_max_open_ms: 600_000,
            transcript_before_ms: 3_000,
            transcript_after_ms: 15_000,
            min_similarity: 0.6,
        }
    }
}

#[derive(Debug, Clone)]
struct CallWindow {
    call_id: String,
    server: String,
    tool: Option<String>,
    start: i64,
    end: Option<i64>,
}

#[derive(Debug, Clone)]
struct ToolUse {
    attribution: Attribution,
    agent: String,
    ts: i64,
    tokens: Vec<String>,
    file_path: Option<String>,
    matched: bool,
}

#[derive(Debug, Clone)]
struct RecentStart {
    key: ProcessKey,
    ts: i64,
    agent: String,
    tokens: Vec<String>,
    attributed: bool,
}

/// What a newly arrived transcript tool use matched retroactively.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RetroMatch {
    /// Process starts (and therefore their subtrees) caused by the tool use.
    pub processes: Vec<ProcessKey>,
    /// For file tools: the path and time window to re-attribute.
    pub file: Option<(String, i64, i64)>,
}

/// The correlation state machine.
#[derive(Debug, Default)]
pub struct Correlator {
    cfg: CorrelationConfig,
    windows: Vec<CallWindow>,
    tool_uses: VecDeque<ToolUse>,
    recent: VecDeque<RecentStart>,
}

const MAX_RECENT: usize = 4_096;
const MAX_TOOL_USES: usize = 1_024;

impl Correlator {
    /// New correlator with the given tunables.
    pub fn new(cfg: CorrelationConfig) -> Self {
        Self { cfg, ..Self::default() }
    }

    /// A `tools/call` request was sent to `server`.
    pub fn open_call(&mut self, call_id: &str, server: &str, tool: Option<&str>, ts: i64) {
        self.windows.push(CallWindow {
            call_id: call_id.to_string(),
            server: server.to_lowercase(),
            tool: tool.map(str::to_string),
            start: ts,
            end: None,
        });
    }

    /// The response to `call_id` arrived.
    pub fn close_call(&mut self, call_id: &str, ts: i64) {
        if let Some(w) = self.windows.iter_mut().find(|w| w.call_id == call_id) {
            w.end = Some(ts);
        }
    }

    /// Attribution for activity at `ts` from the subtree of MCP server `server`.
    pub fn mcp_attribution(&self, server: &str, ts: i64) -> Option<Attribution> {
        let server = server.to_lowercase();
        let mut candidates: Vec<&CallWindow> = self
            .windows
            .iter()
            .filter(|w| w.server == server && w.start <= ts && w.end.is_none_or(|e| ts <= e + self.cfg.mcp_grace_ms))
            .collect();
        candidates.sort_by_key(|w| w.start);
        let best = candidates.last()?;
        Some(Attribution {
            kind: AttributionKind::Mcp,
            tool_call: Some(best.call_id.clone()),
            tool: best.tool.clone(),
            server: Some(best.server.clone()),
            method: Some(if candidates.len() > 1 { "ambiguous" } else { "window" }.into()),
        })
    }

    /// A process started inside agent `agent`'s tree (outside any MCP server
    /// subtree). Returns a transcript attribution if a pending tool use
    /// matches; otherwise remembers the start for retroactive matching.
    pub fn on_process_start(&mut self, key: ProcessKey, ts: i64, agent: &str, command_line: &str) -> Option<Attribution> {
        let tokens = tokenize(command_line);
        let mut best: Option<(usize, f64)> = None;
        for (i, u) in self.tool_uses.iter().enumerate() {
            if u.matched || u.agent != agent || u.tokens.is_empty() {
                continue;
            }
            if ts < u.ts - self.cfg.transcript_before_ms || ts > u.ts + self.cfg.transcript_after_ms {
                continue;
            }
            let s = similarity(&u.tokens, &tokens);
            if s >= self.cfg.min_similarity && best.is_none_or(|(_, b)| s > b) {
                best = Some((i, s));
            }
        }
        if let Some((i, _)) = best {
            let u = &mut self.tool_uses[i];
            u.matched = true;
            let mut a = u.attribution.clone();
            a.method = Some("similarity".into());
            return Some(a);
        }
        self.recent.push_back(RecentStart { key, ts, agent: agent.to_string(), tokens, attributed: false });
        if self.recent.len() > MAX_RECENT {
            self.recent.pop_front();
        }
        None
    }

    /// Marks a recorded start as attributed by other means (MCP, inheritance).
    pub fn mark_attributed(&mut self, key: ProcessKey) {
        if let Some(r) = self.recent.iter_mut().find(|r| r.key == key) {
            r.attributed = true;
        }
    }

    /// A transcript tool use arrived. `command` is the shell command for
    /// shell tools; `file_path` is set for file tools.
    pub fn on_tool_use(
        &mut self,
        attribution: Attribution,
        agent: &str,
        ts: i64,
        command: Option<&str>,
        file_path: Option<&str>,
    ) -> RetroMatch {
        let tokens = command.map(tokenize).unwrap_or_default();
        let mut retro = RetroMatch::default();
        let mut matched = false;
        if !tokens.is_empty() {
            let mut best: Option<(usize, f64)> = None;
            for (i, r) in self.recent.iter().enumerate() {
                if r.attributed || r.agent != agent {
                    continue;
                }
                if r.ts < ts - self.cfg.transcript_before_ms || r.ts > ts + self.cfg.transcript_after_ms {
                    continue;
                }
                let s = similarity(&tokens, &r.tokens);
                if s >= self.cfg.min_similarity && best.is_none_or(|(_, b)| s > b) {
                    best = Some((i, s));
                }
            }
            if let Some((i, _)) = best {
                self.recent[i].attributed = true;
                retro.processes.push(self.recent[i].key);
                matched = true;
            }
        }
        if let Some(p) = file_path {
            retro.file = Some((p.to_string(), ts - self.cfg.transcript_before_ms, ts + self.cfg.transcript_after_ms));
        }
        self.tool_uses.push_back(ToolUse {
            attribution,
            agent: agent.to_string(),
            ts,
            tokens,
            file_path: file_path.map(normalize_path),
            matched,
        });
        if self.tool_uses.len() > MAX_TOOL_USES {
            self.tool_uses.pop_front();
        }
        retro
    }

    /// Attribution for a file event from the agent process itself, if a
    /// file tool use names the same path around the same time.
    pub fn file_attribution(&self, agent: &str, path: &str, ts: i64) -> Option<Attribution> {
        let p = normalize_path(path);
        self.tool_uses
            .iter()
            .rev()
            .find(|u| {
                u.agent == agent
                    && u.file_path.as_deref() == Some(p.as_str())
                    && ts >= u.ts - self.cfg.transcript_before_ms
                    && ts <= u.ts + self.cfg.transcript_after_ms
            })
            .map(|u| {
                let mut a = u.attribution.clone();
                a.method = Some("path".into());
                a
            })
    }

    /// Drops state that can no longer match.
    pub fn gc(&mut self, now: i64) {
        let grace = self.cfg.mcp_grace_ms;
        let max_open = self.cfg.mcp_max_open_ms;
        self.windows.retain(|w| match w.end {
            Some(e) => now - e <= grace * 4,
            None => now - w.start <= max_open,
        });
        let horizon = self.cfg.transcript_after_ms + self.cfg.transcript_before_ms;
        while self.recent.front().is_some_and(|r| now - r.ts > horizon) {
            self.recent.pop_front();
        }
        while self.tool_uses.front().is_some_and(|u| now - u.ts > horizon * 2) {
            self.tool_uses.pop_front();
        }
    }

    /// Number of in-flight MCP calls (for health/debugging).
    pub fn open_calls(&self) -> usize {
        self.windows.iter().filter(|w| w.end.is_none()).count()
    }
}

/// Lower-case path with forward slashes collapsed to backslashes.
pub fn normalize_path(p: &str) -> String {
    p.replace('/', "\\").to_lowercase()
}

/// Splits a command line into comparable tokens: lower-case, quotes and
/// shell punctuation removed, path prefixes stripped from executables.
pub fn tokenize(cmd: &str) -> Vec<String> {
    cmd.to_lowercase()
        .split(|c: char| c.is_whitespace() || "\"'`;&|()<>{}".contains(c))
        .filter(|t| !t.is_empty())
        .map(|t| {
            let base = t.rsplit(['\\', '/']).next().unwrap_or(t);
            let base = base.strip_suffix(".exe").unwrap_or(base);
            if base.is_empty() { t.to_string() } else { base.to_string() }
        })
        .collect()
}

/// Share of `needle` tokens present in `hay` (0.0–1.0).
pub fn similarity(needle: &[String], hay: &[String]) -> f64 {
    if needle.is_empty() {
        return 0.0;
    }
    let hits = needle.iter().filter(|t| hay.contains(t)).count();
    hits as f64 / needle.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pid: u32) -> ProcessKey {
        ProcessKey { pid, start: 0 }
    }

    fn tattr(id: &str) -> Attribution {
        Attribution { kind: AttributionKind::Transcript, tool_call: Some(id.into()), tool: Some("Bash".into()), ..Attribution::default() }
    }

    #[test]
    fn mcp_windows() {
        let mut c = Correlator::default();
        c.open_call("s#1", "Files", Some("read"), 1_000);
        assert!(c.mcp_attribution("files", 999).is_none());
        let a = c.mcp_attribution("FILES", 1_500).unwrap();
        assert_eq!(a.tool_call.as_deref(), Some("s#1"));
        assert_eq!(a.method.as_deref(), Some("window"));
        c.open_call("s#2", "files", Some("write"), 1_600);
        let a = c.mcp_attribution("files", 1_700).unwrap();
        assert_eq!(a.tool_call.as_deref(), Some("s#2"));
        assert_eq!(a.method.as_deref(), Some("ambiguous"));
        c.close_call("s#2", 1_800);
        c.close_call("s#1", 1_800);
        assert!(c.mcp_attribution("files", 3_800).is_some(), "grace inclusive");
        assert!(c.mcp_attribution("files", 3_801).is_none());
        assert!(c.mcp_attribution("other", 1_700).is_none());
        c.gc(100_000);
        assert_eq!(c.open_calls(), 0);
    }

    #[test]
    fn transcript_before_process() {
        let mut c = Correlator::default();
        c.on_tool_use(tattr("t1"), "claude-code", 1_000, Some("git status --short"), None);
        let a = c.on_process_start(key(5), 1_200, "claude-code", r#""C:\Program Files\Git\bin\bash.exe" -c -l "git status --short""#);
        assert_eq!(a.unwrap().tool_call.as_deref(), Some("t1"));
        // Already matched: a second similar process is not attributed again.
        assert!(c.on_process_start(key(6), 1_300, "claude-code", "bash -c 'git status --short'").is_none());
    }

    #[test]
    fn transcript_after_process() {
        let mut c = Correlator::default();
        assert!(c.on_process_start(key(5), 1_000, "codex", "powershell.exe -Command npm test").is_none());
        assert!(c.on_process_start(key(6), 1_010, "codex", "powershell.exe -Command dir").is_none());
        let r = c.on_tool_use(tattr("t2"), "codex", 1_500, Some("npm test"), None);
        assert_eq!(r.processes, vec![key(5)]);
        // Wrong agent never matches.
        let r = c.on_tool_use(tattr("t3"), "claude-code", 1_500, Some("dir"), None);
        assert!(r.processes.is_empty());
    }

    #[test]
    fn transcript_time_window() {
        let mut c = Correlator::default();
        c.on_tool_use(tattr("t1"), "a", 10_000, Some("cargo build"), None);
        assert!(c.on_process_start(key(1), 6_000, "a", "cargo build").is_none(), "too early");
        assert!(c.on_process_start(key(2), 26_000, "a", "cargo build").is_none(), "too late");
        assert!(c.on_process_start(key(3), 12_000, "a", "cargo build").is_some());
    }

    #[test]
    fn file_tools() {
        let mut c = Correlator::default();
        let r = c.on_tool_use(tattr("t1"), "claude-code", 5_000, None, Some("C:/repo/src/main.rs"));
        assert_eq!(r.file.as_ref().unwrap().0, "C:/repo/src/main.rs");
        let a = c.file_attribution("claude-code", r"C:\Repo\src\main.rs", 5_100).unwrap();
        assert_eq!(a.method.as_deref(), Some("path"));
        assert!(c.file_attribution("claude-code", r"C:\repo\other.rs", 5_100).is_none());
    }

    #[test]
    fn tokens() {
        assert_eq!(tokenize(r#""C:\Git\bin\bash.EXE" -c "ls -la""#), vec!["bash", "-c", "ls", "-la"]);
        assert_eq!(similarity(&tokenize("ls -la"), &tokenize("bash -c 'ls -la'")), 1.0);
        assert_eq!(similarity(&[], &tokenize("x")), 0.0);
    }
}
