//! Detection rules: YAML model, loader and stateful engine.
//!
//! See `docs/rules.md` for the format. The engine is deterministic: given the
//! same rules and the same ordered event stream it produces the same matches,
//! which is what the shared `conformance/` suite checks against the Python
//! implementation.

pub mod condition;
pub mod engine;

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use condition::Condition;

pub use engine::{RuleEngine, RuleMatch};

use crate::event::Severity;
use crate::time::parse_duration_ms;

/// Errors raised while loading or compiling rules.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("invalid rule: {0}")]
    Invalid(String),
    #[error("rule {id}: {msg}")]
    InRule { id: String, msg: String },
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("YAML error in {path}: {source}")]
    Yaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("duplicate rule id {0}")]
    Duplicate(String),
}

/// How Rousseau responds to a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ResponseMode {
    /// Record only.
    #[default]
    Observe,
    /// Record and send alerts.
    Alert,
    /// Alert, block MCP tool calls and (opt-in) suspend the process tree.
    Enforce,
}

impl ResponseMode {
    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Alert => "alert",
            Self::Enforce => "enforce",
        }
    }

    /// Parses a lower-case mode name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "observe" => Some(Self::Observe),
            "alert" => Some(Self::Alert),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// The detection logic of a rule.
#[derive(Debug, Clone)]
pub enum Detection {
    /// Fires on each event matching `condition`.
    Event { condition: Condition },
    /// Fires when `steps` match in order, per group, within `within_ms` of
    /// the first step.
    Sequence { by: Vec<Vec<String>>, within_ms: i64, steps: Vec<Condition> },
    /// Fires when at least `count` matching events (or distinct values of
    /// `distinct`) occur per group within `within_ms`.
    Threshold { condition: Condition, by: Vec<Vec<String>>, within_ms: i64, count: usize, distinct: Option<Vec<String>> },
    /// Fires the first time a group sees a given value of `value`.
    FirstSeen { condition: Condition, by: Vec<Vec<String>>, value: Vec<String> },
}

/// Optional response hints.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuleResponse {
    /// In enforce mode, suspend the offending agent's process tree (also
    /// requires `response.allow_suspend = true` in the configuration).
    #[serde(default)]
    pub suspend_tree: bool,
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub references: Vec<String>,
    pub owasp: Vec<String>,
    pub mitre: Vec<String>,
    pub falsepositives: Vec<String>,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub mode: Option<ResponseMode>,
    pub response: RuleResponse,
    pub detection: Detection,
    /// Original YAML source, shown in the dashboard.
    pub source: String,
    /// File the rule was loaded from, if any.
    pub path: Option<String>,
}

/// Serializable rule metadata for the API and bundles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleMeta {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub references: Vec<String>,
    pub owasp: Vec<String>,
    pub mitre: Vec<String>,
    pub falsepositives: Vec<String>,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub mode: Option<ResponseMode>,
    pub detection_type: String,
    pub source: String,
}

impl Rule {
    /// Parses one rule from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, RuleError> {
        let value: Value = serde_yaml::from_str(text).map_err(|e| RuleError::Yaml { path: "<inline>".into(), source: e })?;
        let mut rule = Self::from_value(&value)?;
        rule.source = text.to_string();
        Ok(rule)
    }

    /// Parses one rule from its JSON form.
    pub fn from_value(v: &Value) -> Result<Self, RuleError> {
        let obj = v.as_object().ok_or_else(|| RuleError::Invalid("rule must be a mapping".into()))?;
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| RuleError::Invalid("rule is missing 'id'".into()))?
            .to_string();
        let err = |msg: String| RuleError::InRule { id: id.clone(), msg };
        const KNOWN: &[&str] = &[
            "id",
            "title",
            "severity",
            "description",
            "references",
            "owasp",
            "mitre",
            "falsepositives",
            "tags",
            "enabled",
            "mode",
            "response",
            "detection",
        ];
        for k in obj.keys() {
            if !KNOWN.contains(&k.as_str()) {
                return Err(err(format!("unknown key '{k}'")));
            }
        }
        let title = obj.get("title").and_then(Value::as_str).ok_or_else(|| err("missing 'title'".into()))?.to_string();
        let severity = obj
            .get("severity")
            .and_then(Value::as_str)
            .and_then(Severity::parse)
            .ok_or_else(|| err("missing or invalid 'severity'".into()))?;
        let strings = |key: &str| -> Result<Vec<String>, RuleError> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|x| x.as_str().map(str::to_string).ok_or_else(|| err(format!("'{key}' must be a list of strings"))))
                    .collect(),
                Some(_) => Err(err(format!("'{key}' must be a list of strings"))),
            }
        };
        let enabled = match obj.get("enabled") {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(err("'enabled' must be a boolean".into())),
        };
        let mode = match obj.get("mode") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(ResponseMode::parse(s).ok_or_else(|| err(format!("unknown mode '{s}'")))?),
            Some(_) => return Err(err("'mode' must be a string".into())),
        };
        let response = match obj.get("response") {
            None | Some(Value::Null) => RuleResponse::default(),
            Some(r) => serde_json::from_value(r.clone()).map_err(|e| err(format!("invalid 'response': {e}")))?,
        };
        let det = obj.get("detection").and_then(Value::as_object).ok_or_else(|| err("missing 'detection'".into()))?;
        let detection = parse_detection(det).map_err(|e| err(e.to_string()))?;
        Ok(Self {
            id: id.clone(),
            title,
            severity,
            description: obj.get("description").and_then(Value::as_str).unwrap_or_default().trim().to_string(),
            references: strings("references")?,
            owasp: strings("owasp")?,
            mitre: strings("mitre")?,
            falsepositives: strings("falsepositives")?,
            tags: strings("tags")?,
            enabled,
            mode,
            response,
            detection,
            source: String::new(),
            path: None,
        })
    }

    /// Metadata view.
    pub fn meta(&self) -> RuleMeta {
        RuleMeta {
            id: self.id.clone(),
            title: self.title.clone(),
            severity: self.severity,
            description: self.description.clone(),
            references: self.references.clone(),
            owasp: self.owasp.clone(),
            mitre: self.mitre.clone(),
            falsepositives: self.falsepositives.clone(),
            tags: self.tags.clone(),
            enabled: self.enabled,
            mode: self.mode,
            detection_type: match self.detection {
                Detection::Event { .. } => "event",
                Detection::Sequence { .. } => "sequence",
                Detection::Threshold { .. } => "threshold",
                Detection::FirstSeen { .. } => "first_seen",
            }
            .to_string(),
            source: self.source.clone(),
        }
    }
}

fn path_of(s: &str) -> Vec<String> {
    s.split('.').map(str::to_string).collect()
}

fn parse_by(det: &serde_json::Map<String, Value>) -> Result<Vec<Vec<String>>, RuleError> {
    match det.get("by") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![path_of(s)]),
        Some(Value::Array(a)) => {
            a.iter().map(|x| x.as_str().map(path_of).ok_or_else(|| RuleError::Invalid("'by' must list field paths".into()))).collect()
        }
        Some(_) => Err(RuleError::Invalid("'by' must list field paths".into())),
    }
}

fn parse_within(det: &serde_json::Map<String, Value>) -> Result<i64, RuleError> {
    let s = det.get("within").and_then(Value::as_str).ok_or_else(|| RuleError::Invalid("missing 'within' (e.g. 60s)".into()))?;
    parse_duration_ms(s).ok_or_else(|| RuleError::Invalid(format!("bad duration '{s}'")))
}

fn parse_where(det: &serde_json::Map<String, Value>) -> Result<Condition, RuleError> {
    Condition::parse(det.get("where").ok_or_else(|| RuleError::Invalid("missing 'where'".into()))?)
}

fn check_keys(det: &serde_json::Map<String, Value>, allowed: &[&str]) -> Result<(), RuleError> {
    for k in det.keys() {
        if k != "type" && !allowed.contains(&k.as_str()) {
            return Err(RuleError::Invalid(format!("unknown detection key '{k}'")));
        }
    }
    Ok(())
}

fn parse_detection(det: &serde_json::Map<String, Value>) -> Result<Detection, RuleError> {
    let ty = det.get("type").and_then(Value::as_str).unwrap_or("event");
    match ty {
        "event" => {
            check_keys(det, &["where"])?;
            Ok(Detection::Event { condition: parse_where(det)? })
        }
        "sequence" => {
            check_keys(det, &["by", "within", "steps"])?;
            let steps = det.get("steps").and_then(Value::as_array).ok_or_else(|| RuleError::Invalid("sequence needs 'steps'".into()))?;
            if steps.len() < 2 {
                return Err(RuleError::Invalid("sequence needs at least two steps".into()));
            }
            let steps = steps
                .iter()
                .map(|s| {
                    let m = s.as_object().ok_or_else(|| RuleError::Invalid("step must be a mapping".into()))?;
                    for k in m.keys() {
                        if k != "where" && k != "name" {
                            return Err(RuleError::Invalid(format!("unknown step key '{k}'")));
                        }
                    }
                    parse_where(m)
                })
                .collect::<Result<_, _>>()?;
            Ok(Detection::Sequence { by: parse_by(det)?, within_ms: parse_within(det)?, steps })
        }
        "threshold" => {
            check_keys(det, &["where", "by", "within", "count", "distinct"])?;
            let count = det
                .get("count")
                .and_then(Value::as_u64)
                .filter(|c| *c >= 1)
                .ok_or_else(|| RuleError::Invalid("threshold needs 'count' >= 1".into()))?;
            let distinct = match det.get("distinct") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(path_of(s)),
                Some(_) => return Err(RuleError::Invalid("'distinct' must be a field path".into())),
            };
            Ok(Detection::Threshold {
                condition: parse_where(det)?,
                by: parse_by(det)?,
                within_ms: parse_within(det)?,
                count: usize::try_from(count).unwrap_or(usize::MAX),
                distinct,
            })
        }
        "first_seen" => {
            check_keys(det, &["where", "by", "value"])?;
            let value = det.get("value").and_then(Value::as_str).ok_or_else(|| RuleError::Invalid("first_seen needs 'value'".into()))?;
            Ok(Detection::FirstSeen { condition: parse_where(det)?, by: parse_by(det)?, value: path_of(value) })
        }
        other => Err(RuleError::Invalid(format!("unknown detection type '{other}'"))),
    }
}

/// Loads every `*.yaml`/`*.yml` rule under `dir` (non-recursive, sorted by
/// file name for deterministic ordering). Each file may contain one rule or
/// several YAML documents separated by `---`.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, RuleError> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| RuleError::Io { path: dir.display().to_string(), source: e })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml")))
        .collect();
    files.sort();
    let mut rules = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| RuleError::Io { path: f.display().to_string(), source: e })?;
        for mut r in parse_multi(&text, &f.display().to_string())? {
            r.path = Some(f.display().to_string());
            rules.push(r);
        }
    }
    check_unique(&rules)?;
    Ok(rules)
}

/// Parses a YAML stream that may hold several rule documents.
pub fn parse_multi(text: &str, origin: &str) -> Result<Vec<Rule>, RuleError> {
    let mut out = Vec::new();
    for doc_text in split_documents(text) {
        let value: Value = serde_yaml::from_str(&doc_text).map_err(|e| RuleError::Yaml { path: origin.to_string(), source: e })?;
        if value.is_null() {
            continue;
        }
        let mut r = Rule::from_value(&value)?;
        r.source = doc_text;
        out.push(r);
    }
    Ok(out)
}

fn split_documents(text: &str) -> Vec<String> {
    let mut docs = vec![String::new()];
    for line in text.lines() {
        if line.trim_end() == "---" {
            if !docs.last().is_some_and(|d| d.trim().is_empty()) {
                docs.push(String::new());
            }
            continue;
        }
        if let Some(last) = docs.last_mut() {
            last.push_str(line);
            last.push('\n');
        }
    }
    docs.retain(|d| !d.trim().is_empty());
    docs
}

/// Fails on duplicate rule ids.
pub fn check_unique(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = std::collections::HashSet::new();
    for r in rules {
        if !seen.insert(r.id.as_str()) {
            return Err(RuleError::Duplicate(r.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
id: TEST-1
title: Test
severity: high
description: A test rule.
owasp: [ASI02]
mitre: [T1552.004]
detection:
  type: sequence
  by: [lineage.root]
  within: 60s
  steps:
    - name: read
      where: {field: kind, equals: file.read}
    - where: {field: kind, equals: net.connect}
"#;

    #[test]
    fn parses_rule() {
        let r = Rule::from_yaml(RULE).unwrap();
        assert_eq!(r.id, "TEST-1");
        assert_eq!(r.severity, Severity::High);
        assert!(r.enabled);
        assert_eq!(r.meta().detection_type, "sequence");
        match r.detection {
            Detection::Sequence { within_ms, steps, .. } => {
                assert_eq!(within_ms, 60_000);
                assert_eq!(steps.len(), 2);
            }
            _ => panic!("wrong detection"),
        }
    }

    #[test]
    fn rejects_bad_rules() {
        assert!(Rule::from_yaml("id: x\ntitle: t\nseverity: nope\ndetection: {where: {field: a, exists: true}}").is_err());
        assert!(Rule::from_yaml("id: x\ntitle: t\nseverity: low\nbogus: 1\ndetection: {where: {field: a, exists: true}}").is_err());
        assert!(
            Rule::from_yaml(
                "id: x\ntitle: t\nseverity: low\ndetection: {type: sequence, within: 5s, steps: [{where: {field: a, exists: true}}]}"
            )
            .is_err()
        );
        assert!(
            Rule::from_yaml(
                "id: x\ntitle: t\nseverity: low\ndetection: {type: threshold, within: 5s, count: 0, where: {field: a, exists: true}}"
            )
            .is_err()
        );
    }

    #[test]
    fn multi_documents() {
        let text = "id: A\ntitle: a\nseverity: low\ndetection: {where: {field: a, exists: true}}\n---\nid: B\ntitle: b\nseverity: low\ndetection: {where: {field: b, exists: true}}\n";
        let rules = parse_multi(text, "x").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[1].source.contains("id: B"));
        assert!(!rules[1].source.contains("id: A"));
    }

    #[test]
    fn builtin_rules_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let rules = load_dir(&dir).unwrap();
        assert!(rules.len() >= 25, "only {} built-in rules", rules.len());
        for r in &rules {
            assert!(!r.owasp.is_empty(), "{} lacks an OWASP mapping", r.id);
            assert!(!r.mitre.is_empty(), "{} lacks MITRE techniques", r.id);
            assert!(!r.description.is_empty(), "{} lacks a description", r.id);
            assert!(!r.falsepositives.is_empty(), "{} lacks false-positive notes", r.id);
            for o in &r.owasp {
                assert!(
                    o.len() == 5 && o.starts_with("ASI") && o[3..].parse::<u8>().is_ok_and(|n| (1..=10).contains(&n)),
                    "{}: bad OWASP id {o}",
                    r.id
                );
            }
        }
    }
}
