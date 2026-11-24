//! The stateful rule engine.
//!
//! Processing contract (identical in `rousseau_lab.rules.engine`):
//!
//! * Events are processed one at a time in the order given. Each event needs
//!   integer `id` and `ts` (Unix ms) fields.
//! * Rules are evaluated in load order; disabled rules are skipped.
//! * **event**: one match per matching event.
//! * **sequence**: per group key, a list of partial chains in creation order.
//!   For each event: (1) drop chains whose first event is more than `within`
//!   older than this event; (2) advance every chain whose next step matches;
//!   the first chain to complete emits a match with its event ids and clears
//!   all chains of the group, and the event then does not start a new chain;
//!   (3) otherwise, if the event matches step 1 a new chain starts. At most
//!   [`MAX_CHAINS`] chains are kept per group (oldest dropped).
//! * **threshold**: per group, a window of matching events; entries more than
//!   `within` older than the current event are evicted; when the count (or
//!   the number of distinct `distinct` values; events lacking that field are
//!   ignored) reaches `count`, a match with every event id in the window is
//!   emitted and the window is cleared.
//! * **first_seen**: per group, a set of seen values (lower-cased); the
//!   first event carrying an unseen value emits a match. Events lacking the
//!   value field are ignored.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::condition::{group_key, resolve, scalar_string};
use super::{Detection, Rule};

/// Upper bound on partial sequence chains per group, to bound memory.
pub const MAX_CHAINS: usize = 64;
/// Upper bound on groups tracked per stateful rule.
pub const MAX_GROUPS: usize = 10_000;
/// Upper bound on window entries per threshold group.
pub const MAX_WINDOW: usize = 100_000;

/// One rule hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule: String,
    /// Ids of the evidence events, in order.
    pub events: Vec<u64>,
    /// Timestamp of the event that completed the match.
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Debug, Clone)]
struct Chain {
    next: usize,
    start: i64,
    events: Vec<u64>,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    None,
    Sequence(HashMap<String, Vec<Chain>>),
    Threshold(HashMap<String, VecDeque<(i64, u64, Option<String>)>>),
    FirstSeen(HashMap<String, HashSet<String>>),
}

/// Evaluates a set of rules over an ordered event stream.
#[derive(Debug, Default)]
pub struct RuleEngine {
    rules: Vec<Rule>,
    state: Vec<State>,
}

impl RuleEngine {
    /// Builds an engine over `rules` (kept in the given order).
    pub fn new(rules: Vec<Rule>) -> Self {
        let state = rules.iter().map(initial_state).collect();
        Self { rules, state }
    }

    /// The loaded rules.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Looks up a rule by id.
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Enables or disables a rule; returns false if the id is unknown.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> bool {
        match self.rules.iter_mut().position(|r| r.id == id) {
            Some(i) => {
                self.rules[i].enabled = enabled;
                if !enabled {
                    self.state[i] = initial_state(&self.rules[i]);
                }
                true
            }
            None => false,
        }
    }

    /// Processes one event and returns the matches it completes.
    pub fn process(&mut self, event: &Value) -> Vec<RuleMatch> {
        let id = event.get("id").and_then(Value::as_u64).unwrap_or(0);
        let ts = event.get("ts").and_then(Value::as_i64).unwrap_or(0);
        let mut out = Vec::new();
        for (rule, state) in self.rules.iter().zip(self.state.iter_mut()) {
            if !rule.enabled {
                continue;
            }
            match (&rule.detection, state) {
                (Detection::Event { condition }, _) => {
                    if condition.eval(event) {
                        out.push(RuleMatch { rule: rule.id.clone(), events: vec![id], ts, group: None });
                    }
                }
                (Detection::Sequence { by, within_ms, steps }, State::Sequence(groups)) => {
                    // Cheap pre-check: an event matching no step cannot change state.
                    let matches: Vec<bool> = steps.iter().map(|s| s.eval(event)).collect();
                    if !matches.iter().any(|m| *m) {
                        continue;
                    }
                    let key = group_key(event, by);
                    if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
                        evict_one(groups);
                    }
                    let chains = groups.entry(key.clone()).or_default();
                    chains.retain(|c| ts - c.start <= *within_ms);
                    let mut completed = None;
                    for c in chains.iter_mut() {
                        if matches[c.next] {
                            c.events.push(id);
                            c.next += 1;
                            if c.next == steps.len() {
                                completed = Some(c.events.clone());
                                break;
                            }
                        }
                    }
                    if let Some(events) = completed {
                        chains.clear();
                        out.push(RuleMatch { rule: rule.id.clone(), events, ts, group: Some(key) });
                        continue;
                    }
                    if matches[0] {
                        chains.push(Chain { next: 1, start: ts, events: vec![id] });
                        if chains.len() > MAX_CHAINS {
                            chains.remove(0);
                        }
                    }
                    if chains.is_empty() {
                        groups.remove(&key);
                    }
                }
                (Detection::Threshold { condition, by, within_ms, count, distinct }, State::Threshold(groups)) => {
                    if !condition.eval(event) {
                        continue;
                    }
                    let dval = match distinct {
                        Some(path) => {
                            let p: Vec<&str> = path.iter().map(String::as_str).collect();
                            match resolve(event, &p).first().and_then(|v| scalar_string(v)) {
                                Some(v) => Some(v.to_lowercase()),
                                None => continue,
                            }
                        }
                        None => None,
                    };
                    let key = group_key(event, by);
                    if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
                        evict_one(groups);
                    }
                    let window = groups.entry(key.clone()).or_default();
                    window.push_back((ts, id, dval));
                    while window.front().is_some_and(|(t, _, _)| ts - t > *within_ms) {
                        window.pop_front();
                    }
                    while window.len() > MAX_WINDOW {
                        window.pop_front();
                    }
                    let n = if distinct.is_some() {
                        window.iter().filter_map(|(_, _, d)| d.as_deref()).collect::<HashSet<_>>().len()
                    } else {
                        window.len()
                    };
                    if n >= *count {
                        let events = window.iter().map(|(_, i, _)| *i).collect();
                        groups.remove(&key);
                        out.push(RuleMatch { rule: rule.id.clone(), events, ts, group: Some(key) });
                    }
                }
                (Detection::FirstSeen { condition, by, value }, State::FirstSeen(groups)) => {
                    if !condition.eval(event) {
                        continue;
                    }
                    let p: Vec<&str> = value.iter().map(String::as_str).collect();
                    let Some(v) = resolve(event, &p).first().and_then(|v| scalar_string(v)) else {
                        continue;
                    };
                    let key = group_key(event, by);
                    if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
                        evict_one(groups);
                    }
                    if groups.entry(key.clone()).or_default().insert(v.to_lowercase()) {
                        out.push(RuleMatch { rule: rule.id.clone(), events: vec![id], ts, group: Some(key) });
                    }
                }
                // State always matches the detection type (see initial_state).
                _ => {}
            }
        }
        out
    }

    /// Seeds a first-seen rule with already-known values (e.g. a learned
    /// baseline), so they do not fire.
    pub fn seed_first_seen(&mut self, rule_id: &str, group: &str, values: &[String]) {
        if let Some(i) = self.rules.iter().position(|r| r.id == rule_id)
            && let State::FirstSeen(groups) = &mut self.state[i]
        {
            let set = groups.entry(group.to_string()).or_default();
            for v in values {
                set.insert(v.to_lowercase());
            }
        }
    }
}

fn initial_state(rule: &Rule) -> State {
    match rule.detection {
        Detection::Event { .. } => State::None,
        Detection::Sequence { .. } => State::Sequence(HashMap::new()),
        Detection::Threshold { .. } => State::Threshold(HashMap::new()),
        Detection::FirstSeen { .. } => State::FirstSeen(HashMap::new()),
    }
}

/// Drops an arbitrary group when the group table is full. Memory safety
/// matters more than perfect recall under a flood of distinct groups.
fn evict_one<V>(groups: &mut HashMap<String, V>) {
    if let Some(k) = groups.keys().next().cloned() {
        groups.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine(yaml: &str) -> RuleEngine {
        RuleEngine::new(vec![Rule::from_yaml(yaml).unwrap()])
    }

    fn ev(id: u64, ts: i64, kind: &str, root: &str) -> Value {
        json!({"id": id, "ts": ts, "kind": kind, "lineage": {"root": root}})
    }

    const SEQ: &str = "id: S\ntitle: s\nseverity: high\ndetection:\n  type: sequence\n  by: [lineage.root]\n  within: 60s\n  steps:\n    - where: {field: kind, equals: file.read}\n    - where: {field: kind, equals: net.connect}\n";

    #[test]
    fn sequence_basic_and_window() {
        let mut e = engine(SEQ);
        assert!(e.process(&ev(1, 0, "file.read", "a")).is_empty());
        assert!(e.process(&ev(2, 1_000, "net.connect", "b")).is_empty(), "other group");
        let m = e.process(&ev(3, 2_000, "net.connect", "a"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].events, vec![1, 3]);
        // State cleared: another connect does not fire.
        assert!(e.process(&ev(4, 3_000, "net.connect", "a")).is_empty());
        // Window expiry.
        e.process(&ev(5, 10_000, "file.read", "a"));
        assert!(e.process(&ev(6, 70_001, "net.connect", "a")).is_empty());
        e.process(&ev(7, 80_000, "file.read", "a"));
        assert_eq!(e.process(&ev(8, 140_000, "net.connect", "a")).len(), 1, "inclusive bound");
    }

    #[test]
    fn sequence_oldest_chain_completes() {
        let mut e = engine(SEQ);
        e.process(&ev(1, 0, "file.read", "a"));
        e.process(&ev(2, 10, "file.read", "a"));
        let m = e.process(&ev(3, 20, "net.connect", "a"));
        assert_eq!(m[0].events, vec![1, 3]);
        assert!(e.process(&ev(4, 30, "net.connect", "a")).is_empty());
    }

    #[test]
    fn threshold_count_and_distinct() {
        let mut e = engine(
            "id: T\ntitle: t\nseverity: low\ndetection:\n  type: threshold\n  where: {field: kind, equals: file.delete}\n  by: [session]\n  within: 10s\n  count: 3\n",
        );
        let d = |id: u64, ts: i64| json!({"id": id, "ts": ts, "kind": "file.delete", "session": "s"});
        assert!(e.process(&d(1, 0)).is_empty());
        assert!(e.process(&d(2, 1_000)).is_empty());
        assert!(e.process(&d(3, 20_000)).is_empty(), "1 and 2 evicted");
        assert!(e.process(&d(4, 21_000)).is_empty());
        let m = e.process(&d(5, 22_000));
        assert_eq!(m[0].events, vec![3, 4, 5]);

        let mut e = engine(
            "id: T\ntitle: t\nseverity: low\ndetection:\n  type: threshold\n  where: {field: kind, equals: file.write}\n  within: 10s\n  count: 2\n  distinct: file.path\n",
        );
        let w = |id: u64, p: &str| json!({"id": id, "ts": id, "kind": "file.write", "file": {"path": p}});
        assert!(e.process(&w(1, "A")).is_empty());
        assert!(e.process(&w(2, "a")).is_empty(), "case-insensitive distinct");
        assert!(e.process(&json!({"id": 3, "ts": 3, "kind": "file.write"})).is_empty());
        assert_eq!(e.process(&w(4, "b"))[0].events, vec![1, 2, 4]);
    }

    #[test]
    fn first_seen() {
        let mut e = engine(
            "id: F\ntitle: f\nseverity: medium\ndetection:\n  type: first_seen\n  where: {field: kind, equals: net.connect}\n  by: [lineage.mcp_server]\n  value: net.remote\n",
        );
        let c = |id: u64, s: &str, r: &str| json!({"id": id, "ts": id, "kind": "net.connect", "lineage": {"mcp_server": s}, "net": {"remote": r}});
        assert_eq!(e.process(&c(1, "x", "1.1.1.1:443")).len(), 1);
        assert!(e.process(&c(2, "x", "1.1.1.1:443")).is_empty());
        assert_eq!(e.process(&c(3, "y", "1.1.1.1:443")).len(), 1);
        e.seed_first_seen("F", "x", &["9.9.9.9:53".into()]);
        assert!(e.process(&c(4, "x", "9.9.9.9:53")).is_empty());
    }

    #[test]
    fn disabled_rules_skip() {
        let mut e = engine("id: E\ntitle: e\nseverity: low\nenabled: false\ndetection: {where: {field: kind, equals: x}}\n");
        assert!(e.process(&json!({"id": 1, "ts": 1, "kind": "x"})).is_empty());
        assert!(e.set_enabled("E", true));
        assert_eq!(e.process(&json!({"id": 2, "ts": 2, "kind": "x"})).len(), 1);
        assert!(!e.set_enabled("nope", true));
    }
}
