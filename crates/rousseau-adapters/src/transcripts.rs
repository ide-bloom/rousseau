//! Read-only transcript adapters (opt-in).
//!
//! Agents' built-in tools never go through MCP, but the agents log them in
//! local session files. With explicit opt-in Rousseau tails those files and
//! extracts tool-use metadata (tool name, shell command or file path,
//! timestamp) so the correlation engine can attribute spawned processes and
//! file activity to the tool use that caused it.
//!
//! Formats (verified November 2026; both change without notice):
//!
//! * **Claude Code**: `~/.claude/projects/<encoded-cwd>/<session-id>.jsonl`.
//!   Lines with `"type": "assistant"` carry `message.content[]` items of
//!   type `tool_use` with `id`, `name` and `input`; the line has
//!   `timestamp`, `cwd` and `sessionId`.
//! * **Codex**: `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl`. Lines
//!   are `{"timestamp", "type", "payload"}`; `session_meta` payloads carry
//!   `cwd`, `response_item` payloads of type `function_call` (with a JSON
//!   `arguments` string), `local_shell_call` or `custom_tool_call` carry
//!   tool use. Older rollouts put the item at the top level.
//!
//! Parsing is defensive: unknown line types and fields are ignored. A
//! complete line that is not valid JSON means the format changed in a way
//! we do not understand, so that adapter is switched off with a warning
//! instead of guessing. Files are opened read-only and never copied.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rousseau_core::EventSink;
use rousseau_core::event::{Event, EventKind, SensorInfo, TranscriptInfo};
use rousseau_core::time::{now_ms, parse_rfc3339_ms};
use serde_json::{Map, Value};

/// A line could not be understood at all.
#[derive(Debug, thiserror::Error)]
#[error("{adapter}: unparseable line in {file}: {msg}")]
pub struct ParseError {
    pub adapter: String,
    pub file: String,
    pub msg: String,
}

/// Per-file parsing context (e.g. Codex `session_meta`).
#[derive(Debug, Clone, Default)]
pub struct FileContext {
    pub session: Option<String>,
    pub cwd: Option<String>,
}

/// One supported transcript format.
pub trait Adapter: Send + Sync {
    /// Adapter name (`claude-code`, `codex`).
    fn name(&self) -> &'static str;
    /// Directories to scan, given the user's profile directory.
    fn roots(&self, home: &Path) -> Vec<PathBuf>;
    /// Extracts tool uses from one parsed JSON line.
    fn extract(&self, line: &Value, ctx: &mut FileContext) -> Vec<TranscriptRecord>;
}

/// A tool use found in a transcript.
#[derive(Debug, Clone, PartialEq)]
pub struct TranscriptRecord {
    pub ts: Option<i64>,
    pub info: TranscriptInfo,
}

/// Keys of a tool's input that are kept (metadata only: no file contents,
/// patches or prompts).
const KEPT_INPUT_KEYS: &[&str] = &["command", "file_path", "path", "notebook_path", "pattern", "url", "description", "workdir", "cwd"];
const MAX_KEPT_LEN: usize = 2_048;

fn metadata_only(input: &Value) -> Option<Value> {
    let obj = input.as_object()?;
    let mut out = Map::new();
    for k in KEPT_INPUT_KEYS {
        if let Some(v) = obj.get(*k) {
            let v = match v {
                Value::String(s) if s.len() > MAX_KEPT_LEN => {
                    let mut end = MAX_KEPT_LEN;
                    while !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    Value::String(format!("{}…", &s[..end]))
                }
                Value::String(_) | Value::Number(_) | Value::Bool(_) => v.clone(),
                Value::Array(a) => Value::Array(a.iter().filter(|x| x.is_string()).take(64).cloned().collect()),
                _ => continue,
            };
            out.insert((*k).to_string(), v);
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// Joins a command vector the way a shell tool would run it; for
/// `[shell, -c|-lc|-Command, script]` returns the script.
pub fn command_from_vec(v: &[Value]) -> Option<String> {
    let parts: Vec<&str> = v.iter().filter_map(Value::as_str).collect();
    if parts.is_empty() {
        return None;
    }
    if parts.len() >= 3 {
        let flag = parts[parts.len() - 2].to_lowercase();
        if matches!(flag.as_str(), "-c" | "-lc" | "-command" | "/c" | "-noprofile") || flag.ends_with("command") {
            return Some(parts[parts.len() - 1].to_string());
        }
    }
    Some(parts.join(" "))
}

/// Claude Code session files.
#[derive(Debug, Default)]
pub struct ClaudeCode {
    /// Replaces `~/.claude` (from `CLAUDE_CONFIG_DIR`).
    pub config_dir: Option<PathBuf>,
}

impl ClaudeCode {
    /// Honours `CLAUDE_CONFIG_DIR`.
    pub fn from_env() -> Self {
        Self { config_dir: std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from) }
    }
}

impl Adapter for ClaudeCode {
    fn name(&self) -> &'static str {
        "claude-code"
    }

    fn roots(&self, home: &Path) -> Vec<PathBuf> {
        let base = self.config_dir.clone().unwrap_or_else(|| home.join(".claude"));
        vec![base.join("projects")]
    }

    fn extract(&self, line: &Value, ctx: &mut FileContext) -> Vec<TranscriptRecord> {
        if line.get("type").and_then(Value::as_str) != Some("assistant") {
            return Vec::new();
        }
        let ts = line.get("timestamp").and_then(Value::as_str).and_then(parse_rfc3339_ms);
        let cwd = line.get("cwd").and_then(Value::as_str).map(str::to_string).or_else(|| ctx.cwd.clone());
        let session = line.get("sessionId").and_then(Value::as_str).map(str::to_string).or_else(|| ctx.session.clone());
        if cwd.is_some() {
            ctx.cwd.clone_from(&cwd);
        }
        let Some(content) = line.pointer("/message/content").and_then(Value::as_array) else {
            return Vec::new();
        };
        content
            .iter()
            .filter(|c| c.get("type").and_then(Value::as_str) == Some("tool_use"))
            .filter_map(|c| {
                let tool = c.get("name").and_then(Value::as_str)?.to_string();
                let input = c.get("input").cloned().unwrap_or(Value::Null);
                Some(TranscriptRecord {
                    ts,
                    info: TranscriptInfo {
                        adapter: "claude-code".into(),
                        agent_session: session.clone(),
                        command: input.get("command").and_then(Value::as_str).map(str::to_string),
                        input: metadata_only(&input),
                        tool,
                        tool_use_id: c.get("id").and_then(Value::as_str).map(str::to_string),
                        cwd: cwd.clone(),
                    },
                })
            })
            .collect()
    }
}

/// Codex rollout files.
#[derive(Debug, Default)]
pub struct Codex {
    /// Replaces `~/.codex` (from `CODEX_HOME`).
    pub codex_home: Option<PathBuf>,
}

impl Codex {
    /// Honours `CODEX_HOME`.
    pub fn from_env() -> Self {
        Self { codex_home: std::env::var_os("CODEX_HOME").map(PathBuf::from) }
    }
}

impl Adapter for Codex {
    fn name(&self) -> &'static str {
        "codex"
    }

    fn roots(&self, home: &Path) -> Vec<PathBuf> {
        let base = self.codex_home.clone().unwrap_or_else(|| home.join(".codex"));
        vec![base.join("sessions")]
    }

    fn extract(&self, line: &Value, ctx: &mut FileContext) -> Vec<TranscriptRecord> {
        let ts = line.get("timestamp").and_then(Value::as_str).and_then(parse_rfc3339_ms);
        let ty = line.get("type").and_then(Value::as_str).unwrap_or_default();
        let item = match ty {
            "session_meta" => {
                if let Some(p) = line.get("payload") {
                    ctx.cwd = p.get("cwd").and_then(Value::as_str).map(str::to_string).or(ctx.cwd.take());
                    ctx.session = p.get("id").and_then(Value::as_str).map(str::to_string).or(ctx.session.take());
                }
                return Vec::new();
            }
            "response_item" => match line.get("payload") {
                Some(p) => p,
                None => return Vec::new(),
            },
            _ => line,
        };
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        let (tool, input, id) = match item_type {
            "function_call" => {
                let name = item.get("name").and_then(Value::as_str).unwrap_or("function").to_string();
                let args = match item.get("arguments") {
                    Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
                    Some(v) => v.clone(),
                    None => Value::Null,
                };
                (name, args, item.get("call_id").and_then(Value::as_str))
            }
            "local_shell_call" => {
                ("local_shell".to_string(), item.get("action").cloned().unwrap_or(Value::Null), item.get("call_id").and_then(Value::as_str))
            }
            "custom_tool_call" => (
                item.get("name").and_then(Value::as_str).unwrap_or("custom").to_string(),
                Value::Null,
                item.get("call_id").and_then(Value::as_str),
            ),
            _ => return Vec::new(),
        };
        let command = match input.get("command").or_else(|| input.get("cmd")) {
            Some(Value::Array(v)) => command_from_vec(v),
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        };
        let cwd = input
            .get("workdir")
            .or_else(|| input.get("working_directory"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| ctx.cwd.clone());
        vec![TranscriptRecord {
            ts,
            info: TranscriptInfo {
                adapter: "codex".into(),
                agent_session: ctx.session.clone(),
                tool,
                tool_use_id: id.map(str::to_string),
                command,
                input: metadata_only(&input),
                cwd,
            },
        }]
    }
}

#[derive(Debug)]
struct Tail {
    offset: u64,
    partial: Vec<u8>,
    ctx: FileContext,
}

/// Polls an adapter's roots and emits `transcript.tool_use` events.
pub struct Watcher {
    adapter: Box<dyn Adapter>,
    home: PathBuf,
    files: HashMap<PathBuf, Tail>,
    started: SystemTime,
    disabled: Option<String>,
}

/// Only files modified this recently are tailed.
const ACTIVE_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Bytes read per file per poll.
const MAX_READ: u64 = 4 * 1024 * 1024;

impl Watcher {
    /// New watcher. Existing content is skipped: only lines appended after
    /// the watcher starts (or in files created after it starts) are read.
    pub fn new(adapter: Box<dyn Adapter>, home: PathBuf) -> Self {
        Self { adapter, home, files: HashMap::new(), started: SystemTime::now(), disabled: None }
    }

    /// Adapter name.
    pub fn name(&self) -> &'static str {
        self.adapter.name()
    }

    /// Why the adapter was switched off, if it was.
    pub fn disabled(&self) -> Option<&str> {
        self.disabled.as_deref()
    }

    /// Scans once; returns the events found (the caller forwards them).
    pub fn poll(&mut self) -> Result<Vec<Event>, ParseError> {
        if self.disabled.is_some() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for root in self.adapter.roots(&self.home) {
            let mut files = Vec::new();
            collect_jsonl(&root, 0, &mut files);
            for (path, modified) in files {
                if SystemTime::now().duration_since(modified).unwrap_or_default() > ACTIVE_WINDOW {
                    continue;
                }
                // Size from an open handle: directory-listing metadata is
                // updated lazily by NTFS while a writer keeps the file open.
                let Ok(mut f) = std::fs::File::open(&path) else { continue };
                let Ok(len) = f.metadata().map(|m| m.len()) else { continue };
                let created_after_start = modified > self.started;
                let tail = self.files.entry(path.clone()).or_insert_with(|| Tail {
                    // Skip history for files that existed before we started.
                    offset: if created_after_start && len < MAX_READ { 0 } else { len },
                    partial: Vec::new(),
                    ctx: FileContext::default(),
                });
                if len < tail.offset {
                    // Truncated or replaced: start over.
                    tail.offset = 0;
                    tail.partial.clear();
                }
                if len == tail.offset {
                    continue;
                }
                let mut buf = Vec::new();
                let read = (|| -> std::io::Result<()> {
                    f.seek(SeekFrom::Start(tail.offset))?;
                    (&mut f).take(MAX_READ).read_to_end(&mut buf)?;
                    Ok(())
                })();
                if let Err(e) = read {
                    tracing::debug!(file = %path.display(), error = %e, "transcript read failed");
                    continue;
                }
                tail.offset += buf.len() as u64;
                tail.partial.extend_from_slice(&buf);
                while let Some(pos) = tail.partial.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = tail.partial.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&line);
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    let value: Value = match serde_json::from_str(text) {
                        Ok(v) => v,
                        Err(e) => {
                            let err =
                                ParseError { adapter: self.adapter.name().into(), file: path.display().to_string(), msg: e.to_string() };
                            self.disabled = Some(err.to_string());
                            return Err(err);
                        }
                    };
                    for rec in self.adapter.extract(&value, &mut tail.ctx) {
                        let mut e = Event::new(EventKind::TranscriptToolUse, rec.ts.unwrap_or_else(now_ms));
                        e.transcript = Some(rec.info);
                        out.push(e);
                    }
                }
            }
        }
        Ok(out)
    }
}

fn collect_jsonl(dir: &Path, depth: usize, out: &mut Vec<(PathBuf, SystemTime)>) {
    if depth > 4 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let p = entry.path();
        if meta.is_dir() {
            collect_jsonl(&p, depth + 1, out);
        } else if p.extension().is_some_and(|e| e == "jsonl") {
            out.push((p, meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
        }
    }
}

/// Builds the watcher for an adapter name.
pub fn adapter_by_name(name: &str) -> Option<Box<dyn Adapter>> {
    match name {
        "claude-code" => Some(Box::new(ClaudeCode::from_env())),
        "codex" => Some(Box::new(Codex::from_env())),
        _ => None,
    }
}

/// Runs watchers until the sink's receiver goes away. Emits a
/// `sensor.health` event when an adapter is switched off.
pub async fn run(mut watchers: Vec<Watcher>, sink: std::sync::Arc<dyn EventSink>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        for w in &mut watchers {
            match w.poll() {
                Ok(events) => {
                    for e in events {
                        sink.emit(e);
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "transcript adapter disabled");
                    let mut e = Event::new(EventKind::SensorHealth, now_ms());
                    e.sensor = Some(SensorInfo {
                        sensor: format!("transcript:{}", w.name()),
                        status: "down".into(),
                        message: format!("adapter disabled: {err}"),
                        ..SensorInfo::default()
                    });
                    sink.emit(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claude_code_lines() {
        let line = json!({
            "type": "assistant", "timestamp": "2026-11-23T10:00:00.000Z", "cwd": "C:\\dev\\app", "sessionId": "s-1",
            "unknownField": {"x": 1},
            "message": {"content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "git status", "description": "status"}},
                {"type": "tool_use", "id": "toolu_2", "name": "Write", "input": {"file_path": "C:\\dev\\app\\a.rs", "content": "SECRET FILE CONTENT"}}
            ]}
        });
        let mut ctx = FileContext::default();
        let recs = ClaudeCode::default().extract(&line, &mut ctx);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].info.command.as_deref(), Some("git status"));
        assert_eq!(recs[0].info.cwd.as_deref(), Some("C:\\dev\\app"));
        assert_eq!(recs[0].ts, parse_rfc3339_ms("2026-11-23T10:00:00.000Z"));
        let input = recs[1].info.input.as_ref().unwrap();
        assert_eq!(input["file_path"], "C:\\dev\\app\\a.rs");
        assert!(input.get("content").is_none(), "file contents must not be stored");
        assert!(ClaudeCode::default().extract(&json!({"type": "user", "message": {}}), &mut ctx).is_empty());
    }

    #[test]
    fn codex_lines_new_and_old_formats() {
        let mut ctx = FileContext::default();
        Codex::default().extract(
            &json!({"timestamp": "2026-11-23T10:00:00Z", "type": "session_meta", "payload": {"id": "c-1", "cwd": "C:\\dev\\x"}}),
            &mut ctx,
        );
        let r = Codex::default().extract(
            &json!({"timestamp": "2026-11-23T10:00:01Z", "type": "response_item", "payload": {
            "type": "function_call", "name": "shell", "call_id": "call_1",
            "arguments": "{\"command\":[\"powershell.exe\",\"-Command\",\"npm test\"],\"workdir\":\"C:\\\\dev\\\\x\"}"}}),
            &mut ctx,
        );
        assert_eq!(r[0].info.command.as_deref(), Some("npm test"));
        assert_eq!(r[0].info.agent_session.as_deref(), Some("c-1"));
        assert_eq!(r[0].info.cwd.as_deref(), Some("C:\\dev\\x"));
        let old = Codex::default()
            .extract(&json!({"type": "local_shell_call", "call_id": "c2", "action": {"command": ["bash", "-lc", "ls -la"]}}), &mut ctx);
        assert_eq!(old[0].info.command.as_deref(), Some("ls -la"));
        let exec = Codex::default().extract(&json!({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "{\"cmd\":\"cargo build\"}"}}), &mut ctx);
        assert_eq!(exec[0].info.command.as_deref(), Some("cargo build"));
        assert!(Codex::default().extract(&json!({"type": "event_msg", "payload": {"type": "token_count"}}), &mut ctx).is_empty());
    }

    #[test]
    fn watcher_tails_new_lines_and_disables_on_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join(".claude/projects/C--dev-app");
        std::fs::create_dir_all(&proj).unwrap();
        let old = proj.join("old.jsonl");
        std::fs::write(&old, "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"tool_use\",\"id\":\"h\",\"name\":\"Bash\",\"input\":{\"command\":\"history\"}}]}}\n").unwrap();
        let mut w = Watcher::new(Box::new(ClaudeCode::default()), dir.path().to_path_buf());
        // Make sure "new" files are clearly newer than the watcher start.
        w.started = SystemTime::now() - Duration::from_secs(1);
        // Pre-existing history is skipped… unless the file was created after start; force "old".
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(60)).unwrap();
        assert!(w.poll().unwrap().is_empty());
        let line = "{\"type\":\"assistant\",\"timestamp\":\"2026-11-23T10:00:00Z\",\"message\":{\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Bash\",\"input\":{\"command\":\"ls\"}}]}}\n";
        let mut f = std::fs::OpenOptions::new().append(true).open(&old).unwrap();
        use std::io::Write;
        // Partial line first: nothing emitted until the newline arrives.
        f.write_all(&line.as_bytes()[..20]).unwrap();
        assert!(w.poll().unwrap().is_empty());
        f.write_all(&line.as_bytes()[20..]).unwrap();
        let ev = w.poll().unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].transcript.as_ref().unwrap().tool_use_id.as_deref(), Some("t"));
        f.write_all(b"{not json\n").unwrap();
        assert!(w.poll().is_err());
        assert!(w.disabled().is_some());
        assert!(w.poll().unwrap().is_empty(), "stays off");
    }

    #[test]
    fn command_vectors() {
        assert_eq!(command_from_vec(&[json!("bash"), json!("-lc"), json!("echo hi")]).as_deref(), Some("echo hi"));
        assert_eq!(command_from_vec(&[json!("git"), json!("status")]).as_deref(), Some("git status"));
        assert_eq!(command_from_vec(&[]), None);
    }
}
