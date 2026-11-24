//! Live process table for agent trees.
//!
//! Processes are identified by `(pid, start_time)` because Windows reuses
//! PIDs. Only processes inside an agent tree are kept as nodes; for every
//! other process we only remember which PID is currently live so that a
//! reused PID never inherits a dead agent's label.

use std::collections::{HashMap, VecDeque};

use crate::event::{Attribution, Lineage, ProcessInfo};

/// Process identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub start: i64,
}

impl ProcessKey {
    /// `"<pid>:<start>"`, used as `lineage.root`.
    pub fn id(&self) -> String {
        format!("{}:{}", self.pid, self.start)
    }
}

/// A tracked process.
#[derive(Debug, Clone)]
pub struct ProcNode {
    pub key: ProcessKey,
    pub parent: Option<ProcessKey>,
    pub info: ProcessInfo,
    pub agent: String,
    pub root: ProcessKey,
    pub depth: u32,
    pub mcp_server: Option<String>,
    /// Tool call this process was spawned for; inherited by descendants.
    pub attribution: Option<Attribution>,
    pub session: String,
    pub children: Vec<ProcessKey>,
    pub exited: Option<i64>,
    pub ancestors: Vec<String>,
}

impl ProcNode {
    /// Lineage section for events from this process.
    pub fn lineage(&self) -> Lineage {
        Lineage {
            agent: Some(self.agent.clone()),
            root: Some(self.root.id()),
            root_pid: Some(self.root.pid),
            depth: self.depth,
            mcp_server: self.mcp_server.clone(),
            ancestors: self.ancestors.clone(),
        }
    }
}

/// Outcome of registering a process start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    /// Not part of any agent tree.
    Untracked,
    /// A new agent root: a new session begins.
    NewRoot { session: String },
    /// A descendant of an existing agent tree.
    Descendant,
}

const MAX_ANCESTORS: usize = 8;
/// How long exited nodes stay queryable for late-arriving events.
pub const EXIT_GRACE_MS: i64 = 120_000;

/// The process table.
#[derive(Debug, Default)]
pub struct ProcessTree {
    nodes: HashMap<ProcessKey, ProcNode>,
    /// Currently live process per PID (tracked or not).
    live: HashMap<u32, i64>,
    exited: VecDeque<(i64, ProcessKey)>,
    /// Server labels announced before the process start was observed.
    pending_labels: HashMap<u32, String>,
}

impl ProcessTree {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a process start. `agent` is the agent label if the process
    /// matches an agent signature. Session ids are `"<agent>-<pid>-<start>"`.
    pub fn on_start(&mut self, info: &ProcessInfo, agent: Option<&str>) -> StartOutcome {
        let start = info.start_time.unwrap_or(0);
        let key = ProcessKey { pid: info.pid, start };
        if let Some(old_start) = self.live.insert(info.pid, start)
            && old_start != start
        {
            // PID reuse: the previous holder is gone even if we missed its stop.
            let old = ProcessKey { pid: info.pid, start: old_start };
            self.mark_exited(old, start);
        }
        let parent_key = info.ppid.and_then(|ppid| {
            let pstart = *self.live.get(&ppid)?;
            // A "parent" that started after the child is a reused PID.
            (pstart <= start).then_some(ProcessKey { pid: ppid, start: pstart })
        });
        let parent = parent_key.and_then(|k| self.nodes.get(&k)).filter(|p| p.exited.is_none());
        let (outcome, node) = match (parent, agent) {
            (Some(p), _) => {
                let mut ancestors = Vec::with_capacity(MAX_ANCESTORS);
                ancestors.push(p.info.name.clone().unwrap_or_default());
                ancestors.extend(p.ancestors.iter().take(MAX_ANCESTORS - 1).cloned());
                let node = ProcNode {
                    key,
                    parent: Some(p.key),
                    info: info.clone(),
                    agent: p.agent.clone(),
                    root: p.root,
                    depth: p.depth + 1,
                    mcp_server: p.mcp_server.clone(),
                    attribution: p.attribution.clone().map(|mut a| {
                        a.method = Some("inherited".into());
                        a
                    }),
                    session: p.session.clone(),
                    children: Vec::new(),
                    exited: None,
                    ancestors,
                };
                (StartOutcome::Descendant, node)
            }
            (None, Some(agent)) => {
                let session = format!("{agent}-{}-{start}", info.pid);
                let node = ProcNode {
                    key,
                    parent: None,
                    info: info.clone(),
                    agent: agent.to_string(),
                    root: key,
                    depth: 0,
                    mcp_server: None,
                    attribution: None,
                    session: session.clone(),
                    children: Vec::new(),
                    exited: None,
                    ancestors: Vec::new(),
                };
                (StartOutcome::NewRoot { session }, node)
            }
            (None, None) => return StartOutcome::Untracked,
        };
        if let Some(pk) = node.parent
            && let Some(p) = self.nodes.get_mut(&pk)
        {
            p.children.push(key);
        }
        self.nodes.insert(key, node);
        if let Some(label) = self.pending_labels.remove(&info.pid) {
            self.label_mcp_server(info.pid, &label);
        }
        outcome
    }

    /// Registers a process exit. Returns the node if it was tracked, and
    /// whether it was an agent root (session end).
    pub fn on_stop(&mut self, pid: u32, ts: i64, exit_code: Option<u32>) -> Option<(ProcNode, bool)> {
        let start = self.live.remove(&pid)?;
        let key = ProcessKey { pid, start };
        if let Some(n) = self.nodes.get_mut(&key) {
            n.info.exit_code = exit_code;
        }
        self.mark_exited(key, ts);
        let node = self.nodes.get(&key)?.clone();
        let is_root = node.root == key;
        Some((node, is_root))
    }

    fn mark_exited(&mut self, key: ProcessKey, ts: i64) {
        if let Some(n) = self.nodes.get_mut(&key)
            && n.exited.is_none()
        {
            n.exited = Some(ts);
            self.exited.push_back((ts, key));
        }
    }

    /// The tracked node for a live PID (or one that exited within the grace period).
    pub fn lookup(&self, pid: u32) -> Option<&ProcNode> {
        if let Some(start) = self.live.get(&pid) {
            return self.nodes.get(&ProcessKey { pid, start: *start });
        }
        // Late events for a process that already exited: newest exited node wins.
        self.exited.iter().rev().find(|(_, k)| k.pid == pid).and_then(|(_, k)| self.nodes.get(k))
    }

    /// Node by key.
    pub fn get(&self, key: &ProcessKey) -> Option<&ProcNode> {
        self.nodes.get(key)
    }

    /// True if `pid` belongs to a tracked tree.
    pub fn is_tracked(&self, pid: u32) -> bool {
        self.lookup(pid).is_some()
    }

    /// Labels the process `pid` and its descendants as belonging to MCP
    /// server `name`. If the process has not been seen yet the label is
    /// applied when it starts.
    pub fn label_mcp_server(&mut self, pid: u32, name: &str) {
        let Some(start) = self.live.get(&pid).copied() else {
            self.pending_labels.insert(pid, name.to_string());
            return;
        };
        let key = ProcessKey { pid, start };
        if !self.nodes.contains_key(&key) {
            self.pending_labels.insert(pid, name.to_string());
            return;
        }
        self.for_subtree(key, |n| n.mcp_server = Some(name.to_string()));
    }

    /// Sets the causing tool call on a process and all its descendants that
    /// do not already have a more specific attribution.
    pub fn set_attribution(&mut self, key: ProcessKey, attribution: &Attribution) {
        let mut first = true;
        self.for_subtree(key, |n| {
            if first || n.attribution.is_none() {
                let mut a = attribution.clone();
                if !first {
                    a.method = Some("inherited".into());
                }
                n.attribution = Some(a);
            }
            first = false;
        });
    }

    /// All keys in the subtree rooted at `key` (including it), breadth first.
    pub fn subtree(&self, key: ProcessKey) -> Vec<ProcessKey> {
        let mut out = Vec::new();
        let mut queue = VecDeque::from([key]);
        while let Some(k) = queue.pop_front() {
            if let Some(n) = self.nodes.get(&k) {
                out.push(k);
                queue.extend(n.children.iter().copied());
            }
        }
        out
    }

    fn for_subtree(&mut self, key: ProcessKey, mut f: impl FnMut(&mut ProcNode)) {
        for k in self.subtree(key) {
            if let Some(n) = self.nodes.get_mut(&k) {
                f(n);
            }
        }
    }

    /// Live tracked PIDs (for the ETW pre-filter).
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.nodes.values().filter(|n| n.exited.is_none()).map(|n| n.key.pid).collect()
    }

    /// Number of tracked nodes (including recently exited).
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True if no nodes are tracked.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Forgets nodes that exited more than [`EXIT_GRACE_MS`] before `now`.
    pub fn gc(&mut self, now: i64) {
        while let Some((ts, key)) = self.exited.front().copied() {
            if now - ts <= EXIT_GRACE_MS {
                break;
            }
            self.exited.pop_front();
            if let Some(n) = self.nodes.remove(&key)
                && let Some(pk) = n.parent
                && let Some(p) = self.nodes.get_mut(&pk)
            {
                p.children.retain(|c| *c != key);
            }
        }
        if self.pending_labels.len() > 1_024 {
            self.pending_labels.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AttributionKind;

    fn p(pid: u32, ppid: u32, start: i64, name: &str) -> ProcessInfo {
        ProcessInfo { pid, ppid: Some(ppid), start_time: Some(start), name: Some(name.into()), ..ProcessInfo::default() }
    }

    #[test]
    fn inheritance() {
        let mut t = ProcessTree::new();
        assert_eq!(t.on_start(&p(1, 0, 0, "explorer.exe"), None), StartOutcome::Untracked);
        let out = t.on_start(&p(10, 1, 100, "claude.exe"), Some("claude-code"));
        assert_eq!(out, StartOutcome::NewRoot { session: "claude-code-10-100".into() });
        assert_eq!(t.on_start(&p(11, 10, 200, "cmd.exe"), None), StartOutcome::Descendant);
        // A descendant that also matches an agent signature does not open a nested session.
        assert_eq!(t.on_start(&p(12, 11, 300, "node.exe"), Some("gemini-cli")), StartOutcome::Descendant);
        let n = t.lookup(12).unwrap();
        assert_eq!(n.agent, "claude-code");
        assert_eq!(n.depth, 2);
        assert_eq!(n.ancestors, vec!["cmd.exe", "claude.exe"]);
        assert_eq!(n.lineage().root.as_deref(), Some("10:100"));
        assert!(!t.is_tracked(1));
    }

    #[test]
    fn pid_reuse() {
        let mut t = ProcessTree::new();
        t.on_start(&p(10, 1, 100, "claude.exe"), Some("claude-code"));
        t.on_start(&p(20, 10, 200, "cmd.exe"), None);
        // pid 20 exits without us seeing the stop and is reused by an unrelated process.
        t.on_start(&p(20, 1, 300, "notepad.exe"), None);
        assert!(!t.is_tracked(20), "reused pid must not inherit the agent label");
        assert!(t.get(&ProcessKey { pid: 20, start: 200 }).unwrap().exited.is_some());
        // Agent root exits; its PID is reused; a child of the new holder is not tracked.
        t.on_stop(10, 400, Some(0));
        t.on_start(&p(10, 1, 500, "svchost.exe"), None);
        assert_eq!(t.on_start(&p(30, 10, 600, "cmd.exe"), None), StartOutcome::Untracked);
    }

    #[test]
    fn parent_started_after_child_is_not_parent() {
        let mut t = ProcessTree::new();
        t.on_start(&p(10, 1, 500, "claude.exe"), Some("claude-code"));
        // Snapshot enumeration can deliver a child whose ppid was reused later.
        assert_eq!(t.on_start(&p(11, 10, 400, "cmd.exe"), None), StartOutcome::Untracked);
    }

    #[test]
    fn mcp_labels_and_attribution() {
        let mut t = ProcessTree::new();
        t.on_start(&p(10, 1, 100, "claude.exe"), Some("claude-code"));
        t.on_start(&p(11, 10, 110, "rousseau.exe"), None);
        // Label announced before the server process start is observed.
        t.label_mcp_server(12, "files");
        t.on_start(&p(12, 11, 120, "python.exe"), None);
        t.on_start(&p(13, 12, 130, "git.exe"), None);
        assert_eq!(t.lookup(13).unwrap().mcp_server.as_deref(), Some("files"));
        let a = Attribution { kind: AttributionKind::Mcp, tool_call: Some("c1".into()), ..Attribution::default() };
        t.set_attribution(t.lookup(12).unwrap().key, &a);
        assert_eq!(t.lookup(13).unwrap().attribution.as_ref().unwrap().method.as_deref(), Some("inherited"));
        t.on_start(&p(14, 13, 140, "ssh.exe"), None);
        assert_eq!(t.lookup(14).unwrap().attribution.as_ref().unwrap().tool_call.as_deref(), Some("c1"));
    }

    #[test]
    fn gc_after_grace() {
        let mut t = ProcessTree::new();
        t.on_start(&p(10, 1, 100, "claude.exe"), Some("claude-code"));
        t.on_start(&p(11, 10, 110, "cmd.exe"), None);
        let (_, root) = t.on_stop(11, 1_000, Some(1)).unwrap();
        assert!(!root);
        assert!(t.lookup(11).is_some(), "late events still resolve");
        t.gc(1_000 + EXIT_GRACE_MS + 1);
        assert!(t.lookup(11).is_none());
        assert!(t.lookup(10).unwrap().children.is_empty());
        assert_eq!(t.tracked_pids(), vec![10]);
    }
}
