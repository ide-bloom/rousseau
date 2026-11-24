//! Incidents: rule matches grouped so the dashboard shows "one problem"
//! instead of a hundred identical alerts.
//!
//! Matches of the same rule in the same session (and same rule group key)
//! are merged into one open incident as long as they arrive within
//! [`MERGE_WINDOW_MS`] of the incident's last activity.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::event::Severity;
use crate::rules::{ResponseMode, Rule, RuleMatch};

/// Matches within this window of the last one join the same incident.
pub const MERGE_WINDOW_MS: i64 = 600_000;
/// Evidence ids kept per incident.
pub const MAX_EVIDENCE: usize = 500;

/// A grouped detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: u64,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Number of rule matches merged into this incident.
    pub count: u64,
    /// `open`, `acknowledged` or `closed`.
    pub status: String,
    /// Response mode in effect when the incident was raised.
    pub mode: ResponseMode,
    /// The rule's description: why this matters.
    pub explanation: String,
    pub owasp: Vec<String>,
    pub mitre: Vec<String>,
    /// Evidence event ids, oldest first (bounded).
    pub evidence: Vec<u64>,
    /// Response actions taken (`alerted`, `suspended pid 123`, …).
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Result of feeding a match to the grouper.
#[derive(Debug, Clone)]
pub struct IncidentUpdate {
    pub incident: Incident,
    pub is_new: bool,
}

/// Groups matches into incidents.
#[derive(Debug, Default)]
pub struct IncidentGrouper {
    open: HashMap<(String, String, String), Incident>,
}

impl IncidentGrouper {
    /// Empty grouper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merges a match. `session`/`agent` come from the completing event.
    /// `next_id` is called to allocate an id for a new incident.
    pub fn add(
        &mut self,
        rule: &Rule,
        m: &RuleMatch,
        session: Option<&str>,
        agent: Option<&str>,
        mode: ResponseMode,
        next_id: &mut dyn FnMut() -> u64,
    ) -> IncidentUpdate {
        let key = (rule.id.clone(), session.unwrap_or_default().to_string(), m.group.clone().unwrap_or_default());
        if let Some(inc) = self.open.get_mut(&key)
            && m.ts - inc.last_ts <= MERGE_WINDOW_MS
            && inc.status != "closed"
        {
            inc.last_ts = inc.last_ts.max(m.ts);
            inc.count += 1;
            for id in &m.events {
                if inc.evidence.len() < MAX_EVIDENCE && !inc.evidence.contains(id) {
                    inc.evidence.push(*id);
                }
            }
            return IncidentUpdate { incident: inc.clone(), is_new: false };
        }
        let inc = Incident {
            id: next_id(),
            rule_id: rule.id.clone(),
            title: rule.title.clone(),
            severity: rule.severity,
            session: session.map(str::to_string),
            agent: agent.map(str::to_string),
            first_ts: m.ts,
            last_ts: m.ts,
            count: 1,
            status: "open".into(),
            mode,
            explanation: rule.description.clone(),
            owasp: rule.owasp.clone(),
            mitre: rule.mitre.clone(),
            evidence: m.events.iter().copied().take(MAX_EVIDENCE).collect(),
            actions: Vec::new(),
            group: m.group.clone(),
        };
        self.open.insert(key, inc.clone());
        IncidentUpdate { incident: inc, is_new: true }
    }

    /// Records a response action on an open incident.
    pub fn add_action(&mut self, incident_id: u64, action: &str) -> Option<Incident> {
        let inc = self.open.values_mut().find(|i| i.id == incident_id)?;
        inc.actions.push(action.to_string());
        Some(inc.clone())
    }

    /// Forgets incidents idle for longer than the merge window.
    pub fn gc(&mut self, now: i64) {
        self.open.retain(|_, i| now - i.last_ts <= MERGE_WINDOW_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_within_window() {
        let rule = Rule::from_yaml(
            "id: R\ntitle: r\nseverity: high\ndescription: why\nowasp: [ASI02]\ndetection: {where: {field: kind, exists: true}}\n",
        )
        .unwrap();
        let mut g = IncidentGrouper::new();
        let mut n = 0;
        let mut next = || {
            n += 1;
            n
        };
        let m = |id: u64, ts: i64| RuleMatch { rule: "R".into(), events: vec![id], ts, group: None };
        let a = g.add(&rule, &m(1, 0), Some("s"), Some("claude-code"), ResponseMode::Alert, &mut next);
        assert!(a.is_new);
        assert_eq!(a.incident.explanation, "why");
        let b = g.add(&rule, &m(2, 1_000), Some("s"), None, ResponseMode::Alert, &mut next);
        assert!(!b.is_new);
        assert_eq!(b.incident.count, 2);
        assert_eq!(b.incident.evidence, vec![1, 2]);
        let c = g.add(&rule, &m(3, 1_000), Some("other"), None, ResponseMode::Alert, &mut next);
        assert!(c.is_new);
        let d = g.add(&rule, &m(4, 1_000 + MERGE_WINDOW_MS + 1), Some("s"), None, ResponseMode::Alert, &mut next);
        assert!(d.is_new);
        assert_eq!(g.add_action(d.incident.id, "alerted").unwrap().actions, vec!["alerted"]);
    }
}
