//! The event pipeline: enrich → store → detect → respond → broadcast.
//!
//! Sensors and proxies push raw events into a bounded channel; a single task
//! owns the [`Pipeline`] and drains the channel in batches. Each batch runs
//! in one SQLite transaction. Side effects (alerts, suspension) run after
//! the commit through the [`Responder`], and live updates go out on a
//! `broadcast` channel whose slow receivers lag (drop messages) instead of
//! stalling the sensors.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::config::ResponseConfig;
use crate::correlate::{CorrelationConfig, Correlator};
use crate::event::{Attribution, AttributionKind, Event, EventKind, ProcessInfo, SessionInfo, TranscriptInfo};
use crate::incident::{Incident, IncidentGrouper};
use crate::rules::{ResponseMode, Rule, RuleEngine, RuleMatch};
use crate::storage::{Batch, ServerRecord, Store, StoreError};
use crate::tree::{ProcessKey, ProcessTree, StartOutcome};

/// PIDs currently inside agent trees, shared with the ETW callbacks so they
/// can discard events from untracked processes before allocating anything.
pub type TrackedPids = Arc<RwLock<HashSet<u32>>>;

/// Decides whether a process is an AI agent.
pub trait AgentMatcher: Send + Sync {
    /// Agent label (e.g. `claude-code`) if `p` matches a signature.
    fn match_agent(&self, p: &ProcessInfo) -> Option<String>;
    /// Transcript adapter name (`claude-code`, `codex`) used by agent `label`.
    fn transcript_adapter(&self, label: &str) -> Option<String>;
}

/// Executes response actions. Implementations must not block.
pub trait Responder: Send + Sync {
    /// Sends alerts for a new incident (channels filter by severity).
    fn alert(&self, incident: &Incident);
    /// Suspends the given processes. Returns how many were suspended.
    fn suspend(&self, pids: &[u32]) -> Result<usize, String>;
}

/// Messages on the live broadcast channel (and the named pipe).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LiveMessage {
    Event { event: Box<Event> },
    Incident { incident: Box<Incident> },
}

enum Action {
    Alert(Box<Incident>),
    Suspend { incident: u64, pids: Vec<u32> },
}

/// The pipeline state. Owned by one task.
pub struct Pipeline {
    store: Arc<Store>,
    tree: ProcessTree,
    correlator: Correlator,
    engine: RuleEngine,
    grouper: IncidentGrouper,
    live: broadcast::Sender<LiveMessage>,
    matcher: Arc<dyn AgentMatcher>,
    responder: Option<Arc<dyn Responder>>,
    tracked: TrackedPids,
    response: ResponseConfig,
    retention_days: u32,
    sessions: HashMap<String, SessionInfo>,
    next_incident: u64,
    last_prune: i64,
}

impl Pipeline {
    /// Builds a pipeline. Rule overrides stored in the database are applied.
    pub fn new(
        store: Arc<Store>,
        rules: Vec<Rule>,
        matcher: Arc<dyn AgentMatcher>,
        live: broadcast::Sender<LiveMessage>,
        tracked: TrackedPids,
    ) -> Result<Self, StoreError> {
        let next_incident = store.max_incident_id()? + 1;
        let mut p = Self {
            store,
            tree: ProcessTree::new(),
            correlator: Correlator::new(CorrelationConfig::default()),
            engine: RuleEngine::default(),
            grouper: IncidentGrouper::new(),
            live,
            matcher,
            responder: None,
            tracked,
            response: ResponseConfig::default(),
            retention_days: 14,
            sessions: HashMap::new(),
            next_incident,
            last_prune: 0,
        };
        p.set_rules(rules)?;
        Ok(p)
    }

    /// Replaces the rule set, applying persisted overrides. State of
    /// stateful rules restarts.
    pub fn set_rules(&mut self, mut rules: Vec<Rule>) -> Result<(), StoreError> {
        let overrides = self.store.rule_overrides()?;
        for r in &mut rules {
            if let Some((enabled, mode)) = overrides.get(&r.id) {
                if let Some(e) = enabled {
                    r.enabled = *e;
                }
                if mode.is_some() {
                    r.mode = *mode;
                }
            }
        }
        self.engine = RuleEngine::new(rules);
        Ok(())
    }

    /// Updates response settings.
    pub fn set_response(&mut self, response: ResponseConfig, retention_days: u32) {
        self.response = response;
        self.retention_days = retention_days;
    }

    /// Sets the responder used for alerts and suspension.
    pub fn set_responder(&mut self, responder: Arc<dyn Responder>) {
        self.responder = Some(responder);
    }

    /// Replaces the correlation tunables.
    pub fn set_correlation(&mut self, cfg: CorrelationConfig) {
        self.correlator = Correlator::new(cfg);
    }

    /// The loaded rules.
    pub fn rules(&self) -> &[Rule] {
        self.engine.rules()
    }

    /// Read access to the process tree.
    pub fn tree(&self) -> &ProcessTree {
        &self.tree
    }

    /// Active sessions.
    pub fn active_sessions(&self) -> impl Iterator<Item = &SessionInfo> {
        self.sessions.values()
    }

    /// Processes a batch of raw events. Returns the stored (enriched) events.
    pub fn process_batch(&mut self, events: Vec<Event>) -> Result<Vec<Event>, StoreError> {
        let store = Arc::clone(&self.store);
        let mut stored = Vec::with_capacity(events.len());
        let mut incidents: Vec<Incident> = Vec::new();
        let mut actions = Vec::new();
        store.batch(|b| {
            for raw in events {
                for mut e in self.enrich(b, raw)? {
                    b.insert_event(&mut e)?;
                    let matches = self.engine.process(&e.to_value());
                    for m in matches {
                        if let Some(inc) = self.handle_match(b, &e, &m, &mut actions)? {
                            incidents.retain(|i| i.id != inc.id);
                            incidents.push(inc);
                        }
                    }
                    stored.push(e);
                }
            }
            Ok(())
        })?;
        for e in &stored {
            // No receivers is fine (headless mode).
            let _ = self.live.send(LiveMessage::Event { event: Box::new(e.clone()) });
        }
        for action in actions {
            match action {
                Action::Alert(inc) => {
                    if let Some(r) = &self.responder {
                        r.alert(&inc);
                    }
                    if let Some(updated) = self.grouper.add_action(inc.id, "alerted") {
                        self.store.upsert_incident(&updated)?;
                        incidents.retain(|i| i.id != updated.id);
                        incidents.push(updated);
                    }
                }
                Action::Suspend { incident, pids } => {
                    let note = match self.responder.as_ref().map(|r| r.suspend(&pids)) {
                        Some(Ok(n)) => format!("suspended {n} process(es)"),
                        Some(Err(e)) => format!("suspend failed: {e}"),
                        None => "suspend skipped: no responder".to_string(),
                    };
                    if let Some(updated) = self.grouper.add_action(incident, &note) {
                        self.store.upsert_incident(&updated)?;
                        incidents.retain(|i| i.id != updated.id);
                        incidents.push(updated);
                    }
                }
            }
        }
        for inc in incidents {
            let _ = self.live.send(LiveMessage::Incident { incident: Box::new(inc) });
        }
        Ok(stored)
    }

    /// Periodic maintenance: garbage-collects state and applies retention.
    pub fn tick(&mut self, now: i64) -> Result<(), StoreError> {
        self.tree.gc(now);
        self.correlator.gc(now);
        self.grouper.gc(now);
        if now - self.last_prune > 3_600_000 {
            self.last_prune = now;
            let cutoff = now - i64::from(self.retention_days) * 86_400_000;
            let n = self.store.prune(cutoff)?;
            if n > 0 {
                tracing::info!(deleted = n, "retention pruned old events");
            }
        }
        Ok(())
    }

    fn handle_match(
        &mut self,
        b: &mut Batch<'_>,
        e: &Event,
        m: &RuleMatch,
        actions: &mut Vec<Action>,
    ) -> Result<Option<Incident>, StoreError> {
        let Some(rule) = self.engine.rule(&m.rule).cloned() else {
            return Ok(None);
        };
        let mode = rule.mode.unwrap_or(self.response.mode);
        let next = &mut self.next_incident;
        let mut alloc = || {
            let id = *next;
            *next += 1;
            id
        };
        let upd = self.grouper.add(&rule, m, e.session.as_deref(), e.agent(), mode, &mut alloc);
        b.upsert_incident(&upd.incident)?;
        if upd.is_new {
            if mode != ResponseMode::Observe {
                actions.push(Action::Alert(Box::new(upd.incident.clone())));
            }
            if mode == ResponseMode::Enforce
                && rule.response.suspend_tree
                && self.response.allow_suspend
                && let Some(root) = e.lineage.as_ref().and_then(|l| l.root.as_deref()).and_then(parse_key)
            {
                let pids: Vec<u32> = self
                    .tree
                    .subtree(root)
                    .into_iter()
                    .filter(|k| self.tree.get(k).is_some_and(|n| n.exited.is_none()))
                    .map(|k| k.pid)
                    .collect();
                if !pids.is_empty() {
                    actions.push(Action::Suspend { incident: upd.incident.id, pids });
                }
            }
        }
        Ok(Some(upd.incident))
    }

    fn track(&self, pid: u32, on: bool) {
        if let Ok(mut set) = self.tracked.write() {
            if on {
                set.insert(pid);
            } else {
                set.remove(&pid);
            }
        }
    }

    /// Enriches one raw event; returns the events to store (possibly none,
    /// possibly with a synthesized session event first).
    fn enrich(&mut self, b: &mut Batch<'_>, mut e: Event) -> Result<Vec<Event>, StoreError> {
        let mut out = Vec::with_capacity(2);
        match e.kind {
            EventKind::ProcessStart => {
                let Some(info) = e.process.clone() else {
                    return Ok(out);
                };
                let agent = self.matcher.match_agent(&info);
                match self.tree.on_start(&info, agent.as_deref()) {
                    StartOutcome::Untracked => return Ok(out),
                    StartOutcome::NewRoot { session } => {
                        let s = self.new_session(&session, &info, agent.as_deref().unwrap_or("agent"));
                        b.upsert_session(&s)?;
                        let mut se = Event::new(EventKind::SessionStart, e.ts);
                        se.session = Some(session.clone());
                        se.process = Some(info.clone());
                        se.session_info = Some(s.clone());
                        if let Some(n) = self.tree.lookup(info.pid) {
                            se.lineage = Some(n.lineage());
                        }
                        self.sessions.insert(session, s);
                        out.push(se);
                    }
                    StartOutcome::Descendant => {}
                }
                self.track(info.pid, true);
                let Some(node) = self.tree.lookup(info.pid) else {
                    return Ok(out);
                };
                let key = node.key;
                let depth = node.depth;
                let agent_label = node.agent.clone();
                e.lineage = Some(node.lineage());
                e.session = Some(node.session.clone());
                let mut attr = node.attribution.clone();
                if attr.is_none()
                    && let Some(server) = node.mcp_server.clone()
                {
                    attr = self.correlator.mcp_attribution(&server, e.ts);
                }
                if attr.is_some() {
                    self.correlator.mark_attributed(key);
                } else if depth > 0
                    && node.mcp_server.is_none()
                    && let Some(adapter) = self.matcher.transcript_adapter(&agent_label)
                {
                    attr = self.correlator.on_process_start(key, e.ts, &adapter, info.command_line.as_deref().unwrap_or_default());
                }
                if let Some(a) = &attr
                    && node_attr_differs(self.tree.get(&key).and_then(|n| n.attribution.as_ref()), a)
                {
                    self.tree.set_attribution(key, a);
                }
                if depth > 0 {
                    e.attribution = Some(attr.unwrap_or_else(unexplained));
                }
                out.push(e);
            }
            EventKind::ProcessStop => {
                let Some(pid) = e.pid() else { return Ok(out) };
                let exit = e.process.as_ref().and_then(|p| p.exit_code);
                let Some((node, is_root)) = self.tree.on_stop(pid, e.ts, exit) else {
                    return Ok(out);
                };
                self.track(pid, false);
                e.lineage = Some(node.lineage());
                e.session = Some(node.session.clone());
                if let Some(p) = &mut e.process
                    && p.image.is_none()
                {
                    p.image = node.info.image.clone();
                    p.name = node.info.name.clone();
                }
                e.attribution = node.attribution.clone();
                out.push(e);
                if is_root && let Some(mut s) = self.sessions.remove(&node.session) {
                    s.ended = Some(out[0].ts);
                    b.upsert_session(&s)?;
                    let mut end = Event::new(EventKind::SessionEnd, out[0].ts);
                    end.session = Some(s.id.clone());
                    end.lineage = Some(node.lineage());
                    end.session_info = Some(s);
                    out.push(end);
                }
            }
            k if k.is_os_effect() => {
                let Some(pid) = e.pid() else { return Ok(out) };
                let Some(node) = self.tree.lookup(pid) else {
                    return Ok(out);
                };
                e.lineage = Some(node.lineage());
                e.session = Some(node.session.clone());
                if let Some(p) = &mut e.process {
                    p.image = p.image.take().or_else(|| node.info.image.clone());
                    p.name = p.name.take().or_else(|| node.info.name.clone());
                    p.command_line = p.command_line.take().or_else(|| node.info.command_line.clone());
                }
                let mut attr = node.attribution.clone();
                if attr.is_none()
                    && let Some(server) = &node.mcp_server
                {
                    attr = self.correlator.mcp_attribution(server, e.ts);
                }
                if attr.is_none()
                    && node.depth == 0
                    && let (Some(f), Some(adapter)) = (&e.file, self.matcher.transcript_adapter(&node.agent))
                {
                    attr = self.correlator.file_attribution(&adapter, &f.path, e.ts);
                }
                e.attribution = Some(attr.unwrap_or_else(unexplained));
                out.push(e);
            }
            EventKind::McpServerStart => {
                let (server, server_pid, proxy_pid) = match &e.mcp {
                    Some(m) => (m.server.clone(), m.server_pid, m.proxy_pid),
                    None => return Ok(out),
                };
                self.attach_proxy(&mut e, proxy_pid, &mut out, b)?;
                if let Some(spid) = server_pid {
                    self.tree.label_mcp_server(spid, &server);
                }
                let m = e.mcp.as_ref();
                Self::store_server(
                    b,
                    &server,
                    m.map(|m| m.transport.clone()).unwrap_or_default(),
                    m.and_then(|m| m.command.clone().or_else(|| m.upstream.clone())),
                    None,
                    e.ts,
                )?;
                out.push(e);
            }
            k if k.is_mcp() => {
                let proxy_pid = e.mcp.as_ref().and_then(|m| m.proxy_pid);
                self.attach_proxy(&mut e, proxy_pid, &mut out, b)?;
                if let Some(m) = e.mcp.clone() {
                    match k {
                        EventKind::McpCall => {
                            if let Some(call_id) = &m.call_id {
                                self.correlator.open_call(call_id, &m.server, m.tool.as_deref(), e.ts);
                                e.attribution = Some(Attribution {
                                    kind: AttributionKind::Mcp,
                                    tool_call: Some(call_id.clone()),
                                    tool: m.tool.clone(),
                                    server: Some(m.server.clone()),
                                    method: Some("exact".into()),
                                });
                            }
                        }
                        EventKind::McpResult | EventKind::McpBlocked => {
                            if let Some(call_id) = &m.call_id {
                                self.correlator.close_call(call_id, e.ts);
                                e.attribution = Some(Attribution {
                                    kind: AttributionKind::Mcp,
                                    tool_call: Some(call_id.clone()),
                                    tool: m.tool.clone(),
                                    server: Some(m.server.clone()),
                                    method: Some("exact".into()),
                                });
                            }
                        }
                        EventKind::McpInitialize => {
                            Self::store_server(b, &m.server, m.transport.clone(), None, m.result.clone(), e.ts)?;
                        }
                        _ => {}
                    }
                }
                out.push(e);
            }
            EventKind::TranscriptToolUse => {
                let Some(t) = e.transcript.clone() else { return Ok(out) };
                let session = self.session_for_transcript(&t);
                let attr = Attribution {
                    kind: AttributionKind::Transcript,
                    tool_call: Some(format!("tx:{}:{}", t.adapter, t.tool_use_id.clone().unwrap_or_else(|| e.ts.to_string()))),
                    tool: Some(t.tool.clone()),
                    server: None,
                    method: Some("exact".into()),
                };
                let file_path = t
                    .input
                    .as_ref()
                    .and_then(|i| i.get("file_path").or_else(|| i.get("path")))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let retro = self.correlator.on_tool_use(attr.clone(), &t.adapter, e.ts, t.command.as_deref(), file_path.as_deref());
                if let Some(s) = &session {
                    e.session = Some(s.id.clone());
                    for key in &retro.processes {
                        self.tree.set_attribution(*key, &attr);
                        for k in self.tree.subtree(*key) {
                            let mut a = attr.clone();
                            a.method = Some(if k == *key { "similarity" } else { "inherited" }.into());
                            b.reattribute_process(&s.id, k.pid, k.start, &a)?;
                        }
                    }
                    if let Some((path, from, to)) = &retro.file {
                        let mut a = attr.clone();
                        a.method = Some("path".into());
                        b.reattribute_file(&s.id, s.root_pid, path, *from, *to, &a)?;
                    }
                }
                e.attribution = Some(attr);
                out.push(e);
            }
            _ => out.push(e),
        }
        Ok(out)
    }

    /// Resolves the session of an MCP event from the proxy process. When the
    /// proxy is not in a tracked tree (no ETW, or an unknown client), the
    /// proxy's reported parent becomes the root of a new session so MCP
    /// activity is still grouped.
    fn attach_proxy(&mut self, e: &mut Event, proxy_pid: Option<u32>, out: &mut Vec<Event>, b: &mut Batch<'_>) -> Result<(), StoreError> {
        let Some(ppid) = proxy_pid else { return Ok(()) };
        if self.tree.lookup(ppid).is_none() && e.kind == EventKind::McpServerStart {
            let parent: Option<ProcessInfo> = e
                .mcp
                .as_ref()
                .and_then(|m| m.params.as_ref())
                .and_then(|p| p.get("parent"))
                .and_then(|p| serde_json::from_value(p.clone()).ok());
            if let (Some(parent), Some(proxy)) = (parent, e.process.clone()) {
                let label = self.matcher.match_agent(&parent).unwrap_or_else(|| "mcp-client".to_string());
                if let StartOutcome::NewRoot { session } = self.tree.on_start(&parent, Some(&label)) {
                    let s = self.new_session(&session, &parent, &label);
                    b.upsert_session(&s)?;
                    let mut se = Event::new(EventKind::SessionStart, e.ts);
                    se.session = Some(session.clone());
                    se.process = Some(parent.clone());
                    se.session_info = Some(s.clone());
                    if let Some(n) = self.tree.lookup(parent.pid) {
                        se.lineage = Some(n.lineage());
                    }
                    self.sessions.insert(session, s);
                    out.push(se);
                    self.track(parent.pid, true);
                }
                if self.tree.lookup(proxy.pid).is_none() {
                    self.tree.on_start(&proxy, None);
                    self.track(proxy.pid, true);
                }
            }
        }
        if let Some(node) = self.tree.lookup(ppid) {
            e.session = Some(node.session.clone());
            e.lineage = Some(node.lineage());
        }
        Ok(())
    }

    fn store_server(
        b: &mut Batch<'_>,
        name: &str,
        transport: String,
        target: Option<String>,
        info: Option<serde_json::Value>,
        ts: i64,
    ) -> Result<(), StoreError> {
        // Must go through the open transaction: the store mutex is held by
        // `Store::batch` and is not re-entrant.
        b.upsert_server(&ServerRecord { name: name.to_string(), transport, target, first_seen: ts, last_seen: ts, info })
    }

    fn new_session(&self, id: &str, info: &ProcessInfo, agent: &str) -> SessionInfo {
        let cwd = info.cwd.clone();
        SessionInfo {
            id: id.to_string(),
            agent: agent.to_string(),
            root_pid: info.pid,
            started: info.start_time.unwrap_or(0),
            ended: None,
            project: cwd.as_deref().and_then(|c| project_root(Path::new(c))),
            cwd,
            image: info.image.clone(),
            command_line: info.command_line.clone(),
        }
    }

    fn session_for_transcript(&self, t: &TranscriptInfo) -> Option<SessionInfo> {
        let candidates: Vec<&SessionInfo> =
            self.sessions.values().filter(|s| self.matcher.transcript_adapter(&s.agent).as_deref() == Some(t.adapter.as_str())).collect();
        let norm = |p: &str| p.replace('/', "\\").trim_end_matches('\\').to_lowercase();
        if let Some(cwd) = &t.cwd {
            let want = norm(cwd);
            let by_cwd = candidates.iter().filter(|s| {
                s.cwd.as_deref().map(norm).as_deref() == Some(want.as_str())
                    || s.project.as_deref().map(norm).as_deref() == Some(want.as_str())
            });
            if let Some(s) = by_cwd.max_by_key(|s| s.started) {
                return Some((*s).clone());
            }
        }
        candidates.into_iter().max_by_key(|s| s.started).cloned()
    }
}

fn unexplained() -> Attribution {
    Attribution { kind: AttributionKind::Unexplained, ..Attribution::default() }
}

fn node_attr_differs(current: Option<&Attribution>, new: &Attribution) -> bool {
    current.is_none_or(|c| c.tool_call != new.tool_call)
}

fn parse_key(s: &str) -> Option<ProcessKey> {
    let (pid, start) = s.split_once(':')?;
    Some(ProcessKey { pid: pid.parse().ok()?, start: start.parse().ok()? })
}

/// Nearest ancestor of `cwd` (inclusive) containing a `.git` entry.
pub fn project_root(cwd: &Path) -> Option<String> {
    let mut dir = Some(cwd);
    let mut steps = 0;
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return Some(d.display().to_string());
        }
        dir = d.parent();
        steps += 1;
        if steps > 32 {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{FileInfo, McpInfo, NetInfo};
    use std::sync::Mutex;

    struct Matcher;
    impl AgentMatcher for Matcher {
        fn match_agent(&self, p: &ProcessInfo) -> Option<String> {
            (p.name.as_deref() == Some("claude.exe")).then(|| "claude-code".to_string())
        }
        fn transcript_adapter(&self, label: &str) -> Option<String> {
            (label == "claude-code").then(|| "claude-code".to_string())
        }
    }

    #[derive(Default)]
    struct Recorder {
        alerts: Mutex<Vec<String>>,
        suspended: Mutex<Vec<u32>>,
    }
    impl Responder for Recorder {
        fn alert(&self, incident: &Incident) {
            self.alerts.lock().unwrap().push(incident.rule_id.clone());
        }
        fn suspend(&self, pids: &[u32]) -> Result<usize, String> {
            self.suspended.lock().unwrap().extend_from_slice(pids);
            Ok(pids.len())
        }
    }

    fn proc_start(ts: i64, pid: u32, ppid: u32, name: &str, cmd: &str) -> Event {
        let mut e = Event::new(EventKind::ProcessStart, ts);
        e.process = Some(ProcessInfo {
            pid,
            ppid: Some(ppid),
            name: Some(name.into()),
            image: Some(format!(r"C:\bin\{name}")),
            command_line: Some(cmd.into()),
            start_time: Some(ts),
            ..ProcessInfo::default()
        });
        e
    }

    fn file_read(ts: i64, pid: u32, path: &str) -> Event {
        let mut e = Event::new(EventKind::FileRead, ts);
        e.process = Some(ProcessInfo { pid, ..ProcessInfo::default() });
        e.file = Some(FileInfo { path: path.into(), ..FileInfo::default() });
        e
    }

    fn connect(ts: i64, pid: u32) -> Event {
        let mut e = Event::new(EventKind::NetConnect, ts);
        e.process = Some(ProcessInfo { pid, ..ProcessInfo::default() });
        e.net = Some(NetInfo {
            protocol: "tcp".into(),
            direction: "outbound".into(),
            remote_addr: "203.0.113.5".into(),
            remote_port: 443,
            remote_scope: "public".into(),
            remote: "203.0.113.5:443".into(),
            ..NetInfo::default()
        });
        e
    }

    fn mcp(kind: EventKind, ts: i64, call: &str, proxy: u32) -> Event {
        let mut e = Event::new(kind, ts);
        e.mcp = Some(McpInfo {
            server: "files".into(),
            transport: "stdio".into(),
            call_id: Some(call.into()),
            tool: Some("read".into()),
            proxy_pid: Some(proxy),
            server_pid: Some(proxy + 1),
            ..McpInfo::default()
        });
        e
    }

    const SEQ: &str = "id: SEQ\ntitle: cred then egress\nseverity: high\nmode: enforce\nresponse: {suspend_tree: true}\ndetection:\n  type: sequence\n  by: [lineage.root]\n  within: 60s\n  steps:\n    - where: {all: [{field: kind, equals: file.read}, {field: file.path, glob: '*/.ssh/*'}]}\n    - where: {all: [{field: kind, equals: net.connect}, {field: net.remote_scope, equals: public}]}\n";

    fn pipeline() -> (Pipeline, Arc<Recorder>, broadcast::Receiver<LiveMessage>, TrackedPids) {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (tx, rx) = broadcast::channel(1024);
        let tracked: TrackedPids = Arc::default();
        let mut p = Pipeline::new(store, vec![Rule::from_yaml(SEQ).unwrap()], Arc::new(Matcher), tx, tracked.clone()).unwrap();
        let r = Arc::new(Recorder::default());
        p.set_responder(r.clone());
        p.set_response(ResponseConfig { allow_suspend: true, ..ResponseConfig::default() }, 14);
        (p, r, rx, tracked)
    }

    #[test]
    fn end_to_end_attribution_and_detection() {
        let (mut p, rec, mut rx, tracked) = pipeline();
        let stored = p
            .process_batch(vec![
                proc_start(1_000, 1, 0, "explorer.exe", "explorer"),
                proc_start(2_000, 10, 1, "claude.exe", "claude"),
                proc_start(3_000, 11, 10, "rousseau.exe", "rousseau wrap --name files -- python s.py"),
                mcp(EventKind::McpServerStart, 3_100, "", 11),
                proc_start(3_200, 12, 11, "python.exe", "python s.py"),
                mcp(EventKind::McpCall, 4_000, "files#1", 11),
                file_read(4_100, 12, r"C:\Users\dev\.ssh\id_ed25519"),
                connect(4_200, 12),
                mcp(EventKind::McpResult, 4_300, "files#1", 11),
                file_read(9_000, 12, r"C:\Users\dev\notes.txt"),
                file_read(9_000, 999, r"C:\untracked"),
            ])
            .unwrap();
        // explorer and pid 999 are untracked; a session.start was synthesized.
        assert_eq!(stored[0].kind, EventKind::SessionStart);
        assert!(stored.iter().all(|e| e.pid() != Some(1) && e.pid() != Some(999)));
        let read = stored.iter().find(|e| e.file.as_ref().is_some_and(|f| f.path.contains(".ssh"))).unwrap();
        assert_eq!(read.lineage.as_ref().unwrap().mcp_server.as_deref(), Some("files"));
        assert_eq!(read.attribution.as_ref().unwrap().tool_call.as_deref(), Some("files#1"));
        assert_eq!(read.session.as_deref(), Some("claude-code-10-2000"));
        let late = stored.iter().find(|e| e.file.as_ref().is_some_and(|f| f.path.contains("notes"))).unwrap();
        assert_eq!(late.attribution.as_ref().unwrap().kind, AttributionKind::Unexplained);
        // The sequence rule fired once, in enforce mode: alert + suspend.
        assert_eq!(*rec.alerts.lock().unwrap(), vec!["SEQ".to_string()]);
        let suspended = rec.suspended.lock().unwrap().clone();
        assert!(suspended.contains(&10) && suspended.contains(&12));
        let inc = p.store.incidents(10, None).unwrap();
        assert_eq!(inc.len(), 1);
        assert!(inc[0].actions.iter().any(|a| a.starts_with("suspended")));
        assert!(tracked.read().unwrap().contains(&12));
        let mut saw_incident = false;
        while let Ok(m) = rx.try_recv() {
            if matches!(m, LiveMessage::Incident { .. }) {
                saw_incident = true;
            }
        }
        assert!(saw_incident);
    }

    #[test]
    fn transcript_retro_attribution_and_session_end() {
        let (mut p, _, _, tracked) = pipeline();
        p.process_batch(vec![
            proc_start(1_000, 10, 1, "claude.exe", "claude"),
            proc_start(2_000, 20, 10, "bash.exe", r#"bash -c -l "npm test""#),
            file_read(2_100, 20, r"C:\repo\package.json"),
        ])
        .unwrap();
        let mut t = Event::new(EventKind::TranscriptToolUse, 2_500);
        t.transcript = Some(TranscriptInfo {
            adapter: "claude-code".into(),
            tool: "Bash".into(),
            tool_use_id: Some("toolu_1".into()),
            command: Some("npm test".into()),
            ..TranscriptInfo::default()
        });
        p.process_batch(vec![t]).unwrap();
        let ev = p.store.query_events(&crate::storage::EventQuery { kind: Some("file.read".into()), ..Default::default() }).unwrap();
        assert_eq!(ev[0].attribution.as_ref().unwrap().tool_call.as_deref(), Some("tx:claude-code:toolu_1"));
        // Later children inherit the attribution through the tree.
        let stored = p.process_batch(vec![proc_start(3_000, 21, 20, "node.exe", "node jest")]).unwrap();
        assert_eq!(stored[0].attribution.as_ref().unwrap().tool_call.as_deref(), Some("tx:claude-code:toolu_1"));
        // Root exit ends the session.
        let mut stop = Event::new(EventKind::ProcessStop, 5_000);
        stop.process = Some(ProcessInfo { pid: 10, ..ProcessInfo::default() });
        let stored = p.process_batch(vec![stop]).unwrap();
        assert_eq!(stored.last().unwrap().kind, EventKind::SessionEnd);
        assert_eq!(p.store.session("claude-code-10-1000").unwrap().unwrap().ended, Some(5_000));
        assert!(!tracked.read().unwrap().contains(&10));
    }

    #[test]
    fn proxy_without_etw_creates_session() {
        let (mut p, _, _, _) = pipeline();
        let mut e = mcp(EventKind::McpServerStart, 1_000, "", 50);
        e.process = Some(ProcessInfo {
            pid: 50,
            ppid: Some(40),
            start_time: Some(900),
            name: Some("rousseau.exe".into()),
            ..ProcessInfo::default()
        });
        e.mcp.as_mut().unwrap().params = Some(serde_json::json!({"parent": {"pid": 40, "start_time": 500, "name": "cursor.exe"}}));
        let stored = p.process_batch(vec![e, mcp(EventKind::McpCall, 1_100, "files#1", 50)]).unwrap();
        assert_eq!(stored[0].kind, EventKind::SessionStart);
        assert_eq!(stored[0].session_info.as_ref().unwrap().agent, "mcp-client");
        assert_eq!(stored[2].session.as_deref(), Some("mcp-client-40-500"));
        assert_eq!(p.store.servers().unwrap()[0].name, "files");
    }

    #[test]
    fn project_root_detection() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("repo/.git")).unwrap();
        std::fs::create_dir_all(dir.path().join("repo/src/deep")).unwrap();
        let root = project_root(&dir.path().join("repo/src/deep")).unwrap();
        assert!(root.ends_with("repo"));
    }
}
