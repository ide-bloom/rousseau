//! Builds the causal tree shown in the session view:
//! intent (tool call) → action (processes, nested by parentage) → effects
//! (files, network, DNS, registry, MCP results and findings).
//!
//! The same algorithm is implemented in `rousseau_lab.report` for offline
//! reports.

use std::collections::{BTreeMap, HashMap};

use rousseau_core::event::{AttributionKind, Event, EventKind, Severity};
use serde::Serialize;

/// One node of the causal tree.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TreeNode {
    /// `intent`, `process`, `effect` or `group`.
    pub kind: String,
    pub label: String,
    pub ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Attribution method or intent source (`mcp`, `transcript`, `unexplained`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    fn new(kind: &str, label: String, ts: i64) -> Self {
        Self { kind: kind.into(), label, ts, event_id: None, severity: None, detail: None, children: Vec::new() }
    }
}

/// Human-readable one-line summary of an event.
pub fn summarize(e: &Event) -> String {
    let proc_name = e.process.as_ref().and_then(|p| p.name.clone()).unwrap_or_default();
    match e.kind {
        EventKind::ProcessStart => {
            let p = e.process.as_ref();
            let cmd = p.and_then(|p| p.command_line.clone()).or_else(|| p.and_then(|p| p.image.clone())).unwrap_or_default();
            format!("{} (pid {}) {}", proc_name, e.pid().unwrap_or(0), truncate(&cmd, 200))
        }
        EventKind::ProcessStop => format!("{} (pid {}) exited", proc_name, e.pid().unwrap_or(0)),
        k if k.as_str().starts_with("file.") || k == EventKind::ImageLoad => {
            let f = e.file.as_ref();
            let mut s = format!("{} {}", k.as_str(), f.map(|f| f.path.as_str()).unwrap_or(""));
            if let Some(n) = f.and_then(|f| f.new_path.as_deref()) {
                s.push_str(&format!(" → {n}"));
            }
            s
        }
        EventKind::NetConnect | EventKind::NetAccept | EventKind::NetClose => {
            let n = e.net.as_ref();
            let mut s = format!(
                "{} {} {}",
                e.kind.as_str(),
                n.map(|n| n.protocol.as_str()).unwrap_or(""),
                n.map(|n| n.remote.as_str()).unwrap_or("")
            );
            if let Some(n) = n
                && (n.bytes_sent.is_some() || n.bytes_recv.is_some())
            {
                s.push_str(&format!(" ({} B out, {} B in)", n.bytes_sent.unwrap_or(0), n.bytes_recv.unwrap_or(0)));
            }
            s
        }
        EventKind::DnsQuery => format!("dns {}", e.dns.as_ref().map(|d| d.query.as_str()).unwrap_or("")),
        EventKind::RegistrySet | EventKind::RegistryDelete => {
            let r = e.registry.as_ref();
            format!(
                "{} {}\\{} = {}",
                e.kind.as_str(),
                r.map(|r| r.key.as_str()).unwrap_or(""),
                r.and_then(|r| r.value.as_deref()).unwrap_or(""),
                truncate(r.and_then(|r| r.data.as_deref()).unwrap_or(""), 120)
            )
        }
        EventKind::McpCall => {
            let m = e.mcp.as_ref();
            format!(
                "{}.{}({})",
                m.map(|m| m.server.as_str()).unwrap_or(""),
                m.and_then(|m| m.tool.as_deref()).unwrap_or(""),
                truncate(&m.and_then(|m| m.arguments.as_ref()).map(|a| a.to_string()).unwrap_or_default(), 160)
            )
        }
        EventKind::McpResult => {
            let m = e.mcp.as_ref();
            format!(
                "result{} in {} ms",
                if m.and_then(|m| m.is_error).unwrap_or(false) { " (error)" } else { "" },
                m.and_then(|m| m.duration_ms).unwrap_or(0)
            )
        }
        EventKind::McpBlocked => format!("BLOCKED: {}", e.mcp.as_ref().and_then(|m| m.blocked_reason.clone()).unwrap_or_default()),
        EventKind::McpFinding => {
            let f = e.finding.as_ref();
            format!("{}: {}", f.map(|f| f.title.as_str()).unwrap_or(""), truncate(f.map(|f| f.detail.as_str()).unwrap_or(""), 200))
        }
        EventKind::McpDrift => {
            let d = e.drift.as_ref();
            format!("tool {} {}", d.map(|d| d.tool.as_str()).unwrap_or(""), d.map(|d| d.change.as_str()).unwrap_or(""))
        }
        EventKind::TranscriptToolUse => {
            let t = e.transcript.as_ref();
            let what =
                t.and_then(|t| t.command.clone()).or_else(|| t.and_then(|t| t.input.as_ref()).map(|i| i.to_string())).unwrap_or_default();
            format!("{} {}", t.map(|t| t.tool.as_str()).unwrap_or(""), truncate(&what, 200))
        }
        EventKind::McpMessage | EventKind::McpInitialize | EventKind::McpTools => {
            format!("{} {}", e.kind.as_str(), e.mcp.as_ref().and_then(|m| m.method.clone()).unwrap_or_default())
        }
        k => k.as_str().to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

fn leaf(e: &Event) -> TreeNode {
    let mut n = TreeNode::new("effect", summarize(e), e.ts);
    n.event_id = Some(e.id);
    n.severity = e.severity;
    n.detail = Some(e.kind.as_str().to_string());
    n
}

/// Builds the causal tree for one session's events (in id order).
pub fn build_session_tree(events: &[Event]) -> Vec<TreeNode> {
    // Intent roots keyed by tool_call id, in first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut intents: HashMap<String, TreeNode> = HashMap::new();
    // Per intent: processes by pid, and pid → parent pid.
    let mut procs: HashMap<String, BTreeMap<u32, TreeNode>> = HashMap::new();
    let mut parents: HashMap<u32, u32> = HashMap::new();
    let mut proc_intent: HashMap<u32, String> = HashMap::new();

    const UNEXPLAINED: &str = "unexplained";
    let ensure = |id: &str, label: String, ts: i64, detail: &str, order: &mut Vec<String>, intents: &mut HashMap<String, TreeNode>| {
        if !intents.contains_key(id) {
            let mut n = TreeNode::new("intent", label, ts);
            n.detail = Some(detail.into());
            intents.insert(id.to_string(), n);
            order.push(id.to_string());
        }
    };

    for e in events {
        if matches!(e.kind, EventKind::SessionStart | EventKind::SessionEnd | EventKind::SensorHealth) {
            continue;
        }
        let attr = e.attribution.as_ref();
        let call = attr.and_then(|a| a.tool_call.clone());
        match e.kind {
            EventKind::McpCall | EventKind::TranscriptToolUse => {
                let id = call.unwrap_or_else(|| format!("event-{}", e.id));
                let src = if e.kind == EventKind::McpCall { "mcp" } else { "transcript" };
                ensure(&id, summarize(e), e.ts, src, &mut order, &mut intents);
                if let Some(n) = intents.get_mut(&id) {
                    n.event_id = Some(e.id);
                }
                continue;
            }
            _ => {}
        }
        let key = match (&call, attr.map(|a| a.kind)) {
            (Some(c), _) => c.clone(),
            (None, Some(AttributionKind::Unexplained)) | (None, None) => {
                // MCP findings without a call (tool definitions) group per server.
                if let Some(srv) = e.server().filter(|_| e.kind.is_mcp()) { format!("server:{srv}") } else { UNEXPLAINED.to_string() }
            }
            (None, Some(_)) => UNEXPLAINED.to_string(),
        };
        if !intents.contains_key(&key) {
            let (label, detail) = if key == UNEXPLAINED {
                ("Unexplained activity (no tool call attributed)".to_string(), "unexplained")
            } else if let Some(srv) = key.strip_prefix("server:") {
                (format!("MCP server {srv}"), "mcp")
            } else {
                (format!("Tool call {key}"), "mcp")
            };
            ensure(&key, label, e.ts, detail, &mut order, &mut intents);
        }
        let pid = e.pid();
        if e.kind == EventKind::ProcessStart {
            if let Some(pid) = pid {
                let mut n = TreeNode::new("process", summarize(e), e.ts);
                n.event_id = Some(e.id);
                n.detail = attr.and_then(|a| a.method.clone());
                procs.entry(key.clone()).or_default().insert(pid, n);
                if let Some(pp) = e.process.as_ref().and_then(|p| p.ppid) {
                    parents.insert(pid, pp);
                }
                proc_intent.insert(pid, key);
            }
            continue;
        }
        // Effects attach to their process node when it belongs to the same intent.
        let target = pid.filter(|p| proc_intent.get(p) == Some(&key));
        match target.and_then(|p| procs.get_mut(&key).and_then(|m| m.get_mut(&p))) {
            Some(pnode) => pnode.children.push(leaf(e)),
            None => {
                if let Some(i) = intents.get_mut(&key) {
                    i.children.push(leaf(e));
                }
            }
        }
    }

    // Nest processes by parentage within each intent.
    for (key, mut map) in procs {
        let pids: Vec<u32> = map.keys().copied().collect();
        // Deepest first so children are moved before their parents.
        let depth = |pid: u32| {
            let mut d = 0;
            let mut cur = pid;
            while let Some(p) = parents.get(&cur) {
                if !pids.contains(p) || d > 64 {
                    break;
                }
                cur = *p;
                d += 1;
            }
            d
        };
        let mut sorted = pids.clone();
        sorted.sort_by_key(|p| std::cmp::Reverse(depth(*p)));
        for pid in sorted {
            if let Some(pp) = parents.get(&pid).copied().filter(|pp| *pp != pid && map.contains_key(pp))
                && let Some(child) = map.remove(&pid)
                && let Some(parent) = map.get_mut(&pp)
            {
                parent.children.push(child);
            }
        }
        if let Some(i) = intents.get_mut(&key) {
            let mut roots: Vec<TreeNode> = map.into_values().collect();
            roots.sort_by_key(|n| n.ts);
            i.children.extend(roots);
            i.children.sort_by_key(|n| n.ts);
        }
    }
    let mut out: Vec<TreeNode> = order.into_iter().filter_map(|k| intents.remove(&k)).collect();
    for n in &mut out {
        n.severity = max_severity(n);
    }
    out
}

fn max_severity(n: &TreeNode) -> Option<Severity> {
    n.children.iter().filter_map(max_severity).chain(n.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rousseau_core::event::{Attribution, FileInfo, McpInfo, ProcessInfo};

    fn ev(id: u64, kind: EventKind, pid: Option<u32>, call: Option<&str>) -> Event {
        let mut e = Event::new(kind, id as i64 * 10);
        e.id = id;
        if let Some(p) = pid {
            e.process = Some(ProcessInfo { pid: p, name: Some(format!("p{p}.exe")), ..ProcessInfo::default() });
        }
        e.attribution = Some(Attribution {
            kind: if call.is_some() { AttributionKind::Mcp } else { AttributionKind::Unexplained },
            tool_call: call.map(str::to_string),
            ..Attribution::default()
        });
        e
    }

    #[test]
    fn intent_process_effect_nesting() {
        let mut call = ev(1, EventKind::McpCall, Some(5), Some("srv#1"));
        call.mcp = Some(McpInfo { server: "srv".into(), tool: Some("run".into()), ..McpInfo::default() });
        let mut p10 = ev(2, EventKind::ProcessStart, Some(10), Some("srv#1"));
        p10.process.as_mut().unwrap().ppid = Some(5);
        let mut p11 = ev(3, EventKind::ProcessStart, Some(11), Some("srv#1"));
        p11.process.as_mut().unwrap().ppid = Some(10);
        let mut read = ev(4, EventKind::FileRead, Some(11), Some("srv#1"));
        read.file = Some(FileInfo { path: r"C:\secret.txt".into(), ..FileInfo::default() });
        read.severity = Some(Severity::High);
        let stray = ev(5, EventKind::FileWrite, Some(99), None);
        let tree = build_session_tree(&[call, p10, p11, read, stray]);
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].kind, "intent");
        assert!(tree[0].label.starts_with("srv.run("));
        let proc10 = &tree[0].children[0];
        assert_eq!(proc10.kind, "process");
        let proc11 = &proc10.children[0];
        assert!(proc11.label.starts_with("p11.exe"));
        assert!(proc11.children[0].label.contains("secret.txt"));
        assert_eq!(tree[0].severity, Some(Severity::High));
        assert_eq!(tree[1].detail.as_deref(), Some("unexplained"));
    }
}
