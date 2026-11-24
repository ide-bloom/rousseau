//! Condition trees and field matchers.
//!
//! Semantics (mirrored exactly by `rousseau_lab.rules`; see `docs/rules.md`):
//!
//! * A field path is split on `.`; arrays encountered on the way are
//!   flattened, so a path can yield several candidate values. `null` counts
//!   as missing.
//! * A predicate is true if **any** candidate satisfies it. A missing field
//!   satisfies nothing except `exists: false`.
//! * String comparisons are case-insensitive unless `case_sensitive: true`.
//! * Numbers are compared numerically when both sides are numbers; otherwise
//!   values are compared as strings (integers render without a fraction).
//! * `glob`: `*` matches any run of characters (including separators), `?`
//!   one character, and `/` or `\` in the pattern matches either separator.
//!   The whole value must match.
//! * `regex`: unanchored search; restrict yourself to the syntax shared by
//!   Rust `regex` and Python `re`.
//! * List values for `contains`, `startswith`, `endswith`, `glob` and
//!   `regex` mean "any of these".

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use super::RuleError;

/// A comparison operator with its compiled operand(s).
#[derive(Debug, Clone)]
pub enum Op {
    Equals(Value),
    In(Vec<Value>),
    Contains(Vec<String>),
    StartsWith(Vec<String>),
    EndsWith(Vec<String>),
    Glob(Vec<Regex>),
    Regex(Vec<Regex>),
    Exists(bool),
    Gt(f64),
    Gte(f64),
    Lt(f64),
    Lte(f64),
}

/// A field predicate.
#[derive(Debug, Clone)]
pub struct FieldPredicate {
    pub path: Vec<String>,
    pub op: Op,
    pub case_sensitive: bool,
}

/// A boolean condition tree.
#[derive(Debug, Clone)]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Field(FieldPredicate),
    /// True when the process is an agent root or one of its descendants.
    DescendantOfAgent(bool),
    /// `true`/`false`: inside / outside any MCP server subtree.
    SpawnedByMcpServer(bool),
    /// Inside the subtree of the named MCP server.
    SpawnedByMcpServerNamed(String),
}

const OPS: &[&str] = &["equals", "in", "contains", "startswith", "endswith", "glob", "regex", "exists", "gt", "gte", "lt", "lte"];

impl Condition {
    /// Parses a condition from its JSON form (converted from YAML).
    pub fn parse(v: &Value) -> Result<Self, RuleError> {
        let obj = v.as_object().ok_or_else(|| RuleError::Invalid(format!("condition must be a mapping, got {v}")))?;
        if let Some(list) = obj.get("all") {
            Self::only_key(obj, "all")?;
            return Ok(Self::All(Self::parse_list(list, "all")?));
        }
        if let Some(list) = obj.get("any") {
            Self::only_key(obj, "any")?;
            return Ok(Self::Any(Self::parse_list(list, "any")?));
        }
        if let Some(inner) = obj.get("not") {
            Self::only_key(obj, "not")?;
            return Ok(Self::Not(Box::new(Self::parse(inner)?)));
        }
        if let Some(b) = obj.get("descendant_of_agent") {
            Self::only_key(obj, "descendant_of_agent")?;
            let b = b.as_bool().ok_or_else(|| RuleError::Invalid("descendant_of_agent must be true or false".into()))?;
            return Ok(Self::DescendantOfAgent(b));
        }
        if let Some(s) = obj.get("spawned_by_mcp_server") {
            Self::only_key(obj, "spawned_by_mcp_server")?;
            return match s {
                Value::Bool(b) => Ok(Self::SpawnedByMcpServer(*b)),
                Value::String(name) => Ok(Self::SpawnedByMcpServerNamed(name.to_lowercase())),
                _ => Err(RuleError::Invalid("spawned_by_mcp_server must be a boolean or a server name".into())),
            };
        }
        let field = obj.get("field").and_then(Value::as_str).ok_or_else(|| RuleError::Invalid(format!("unknown condition {v}")))?;
        let case_sensitive = match obj.get("case_sensitive") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(RuleError::Invalid("case_sensitive must be a boolean".into())),
        };
        let mut op_key = None;
        for k in obj.keys() {
            match k.as_str() {
                "field" | "case_sensitive" => {}
                other if OPS.contains(&other) => {
                    if op_key.replace(other).is_some() {
                        return Err(RuleError::Invalid(format!("predicate on '{field}' has more than one operator")));
                    }
                }
                other => {
                    return Err(RuleError::Invalid(format!("unknown key '{other}' in predicate on '{field}'")));
                }
            }
        }
        let op_key = op_key.ok_or_else(|| RuleError::Invalid(format!("predicate on '{field}' has no operator")))?;
        let operand = &obj[op_key];
        let op = match op_key {
            "equals" => {
                if operand.is_array() || operand.is_object() {
                    return Err(RuleError::Invalid("equals takes a scalar".into()));
                }
                Op::Equals(operand.clone())
            }
            "in" => Op::In(operand.as_array().ok_or_else(|| RuleError::Invalid("in takes a list".into()))?.clone()),
            "contains" => Op::Contains(Self::strings(operand, op_key, case_sensitive)?),
            "startswith" => Op::StartsWith(Self::strings(operand, op_key, case_sensitive)?),
            "endswith" => Op::EndsWith(Self::strings(operand, op_key, case_sensitive)?),
            "glob" => {
                Op::Glob(Self::strings(operand, op_key, true)?.iter().map(|g| compile_glob(g, case_sensitive)).collect::<Result<_, _>>()?)
            }
            "regex" => Op::Regex(
                Self::strings(operand, op_key, true)?
                    .iter()
                    .map(|r| {
                        RegexBuilder::new(r)
                            .case_insensitive(!case_sensitive)
                            .build()
                            .map_err(|e| RuleError::Invalid(format!("bad regex '{r}': {e}")))
                    })
                    .collect::<Result<_, _>>()?,
            ),
            "exists" => Op::Exists(operand.as_bool().ok_or_else(|| RuleError::Invalid("exists takes a boolean".into()))?),
            "gt" | "gte" | "lt" | "lte" => {
                let n = operand.as_f64().ok_or_else(|| RuleError::Invalid(format!("{op_key} takes a number")))?;
                match op_key {
                    "gt" => Op::Gt(n),
                    "gte" => Op::Gte(n),
                    "lt" => Op::Lt(n),
                    _ => Op::Lte(n),
                }
            }
            _ => unreachable!("op_key is always one of OPS"),
        };
        Ok(Self::Field(FieldPredicate { path: field.split('.').map(str::to_string).collect(), op, case_sensitive }))
    }

    fn only_key(obj: &serde_json::Map<String, Value>, key: &str) -> Result<(), RuleError> {
        if obj.len() != 1 {
            return Err(RuleError::Invalid(format!("'{key}' must be the only key in its mapping")));
        }
        Ok(())
    }

    fn parse_list(v: &Value, key: &str) -> Result<Vec<Self>, RuleError> {
        let list = v.as_array().ok_or_else(|| RuleError::Invalid(format!("'{key}' takes a list")))?;
        if list.is_empty() {
            return Err(RuleError::Invalid(format!("'{key}' list is empty")));
        }
        list.iter().map(Self::parse).collect()
    }

    fn strings(v: &Value, op: &str, case_sensitive: bool) -> Result<Vec<String>, RuleError> {
        let fold = |s: &str| {
            if case_sensitive { s.to_string() } else { s.to_lowercase() }
        };
        match v {
            Value::String(s) => Ok(vec![fold(s)]),
            Value::Array(items) if !items.is_empty() => items
                .iter()
                .map(|i| i.as_str().map(fold).ok_or_else(|| RuleError::Invalid(format!("{op} list must hold strings"))))
                .collect(),
            _ => Err(RuleError::Invalid(format!("{op} takes a string or a non-empty list of strings"))),
        }
    }

    /// Evaluates the condition against an event's JSON form.
    pub fn eval(&self, event: &Value) -> bool {
        match self {
            Self::All(cs) => cs.iter().all(|c| c.eval(event)),
            Self::Any(cs) => cs.iter().any(|c| c.eval(event)),
            Self::Not(c) => !c.eval(event),
            Self::DescendantOfAgent(want) => {
                let has = !resolve(event, &["lineage", "agent"]).is_empty();
                has == *want
            }
            Self::SpawnedByMcpServer(want) => {
                let has = !resolve(event, &["lineage", "mcp_server"]).is_empty();
                has == *want
            }
            Self::SpawnedByMcpServerNamed(name) => {
                resolve(event, &["lineage", "mcp_server"]).iter().any(|v| v.as_str().is_some_and(|s| s.to_lowercase() == *name))
            }
            Self::Field(p) => p.eval(event),
        }
    }
}

impl FieldPredicate {
    fn eval(&self, event: &Value) -> bool {
        let path: Vec<&str> = self.path.iter().map(String::as_str).collect();
        let values = resolve(event, &path);
        if let Op::Exists(want) = self.op {
            return values.is_empty() != want;
        }
        values.iter().any(|v| self.eval_one(v))
    }

    fn eval_one(&self, v: &Value) -> bool {
        let fold = |s: String| {
            if self.case_sensitive { s } else { s.to_lowercase() }
        };
        match &self.op {
            Op::Equals(want) => values_equal(v, want, self.case_sensitive),
            Op::In(list) => list.iter().any(|w| values_equal(v, w, self.case_sensitive)),
            Op::Contains(needles) => scalar_string(v).is_some_and(|s| {
                let s = fold(s);
                needles.iter().any(|n| s.contains(n.as_str()))
            }),
            Op::StartsWith(needles) => scalar_string(v).is_some_and(|s| {
                let s = fold(s);
                needles.iter().any(|n| s.starts_with(n.as_str()))
            }),
            Op::EndsWith(needles) => scalar_string(v).is_some_and(|s| {
                let s = fold(s);
                needles.iter().any(|n| s.ends_with(n.as_str()))
            }),
            Op::Glob(res) | Op::Regex(res) => scalar_string(v).is_some_and(|s| res.iter().any(|r| r.is_match(&s))),
            Op::Gt(n) => v.as_f64().is_some_and(|x| x > *n),
            Op::Gte(n) => v.as_f64().is_some_and(|x| x >= *n),
            Op::Lt(n) => v.as_f64().is_some_and(|x| x < *n),
            Op::Lte(n) => v.as_f64().is_some_and(|x| x <= *n),
            Op::Exists(_) => unreachable!("handled in eval"),
        }
    }
}

/// Resolves a dotted path into candidate leaf values (arrays flattened,
/// nulls dropped).
pub fn resolve<'a>(root: &'a Value, path: &[&str]) -> Vec<&'a Value> {
    let mut current = vec![root];
    for key in path {
        let mut next = Vec::new();
        for v in current {
            collect_key(v, key, &mut next);
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    let mut out = Vec::new();
    for v in current {
        flatten(v, &mut out);
    }
    out
}

fn collect_key<'a>(v: &'a Value, key: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(m) => {
            if let Some(child) = m.get(key) {
                out.push(child);
            }
        }
        Value::Array(items) => {
            for i in items {
                collect_key(i, key, out);
            }
        }
        _ => {}
    }
}

fn flatten<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Null => {}
        Value::Array(items) => {
            for i in items {
                flatten(i, out);
            }
        }
        other => out.push(other),
    }
}

/// String form of a scalar for string operators. Objects and arrays have none.
pub fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(number_string(n)),
        _ => None,
    }
}

fn number_string(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        let f = n.as_f64().unwrap_or(0.0);
        if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", f as i64) } else { f.to_string() }
    }
}

fn values_equal(field: &Value, want: &Value, case_sensitive: bool) -> bool {
    if let (Some(a), Some(b)) = (field.as_f64(), want.as_f64())
        && field.is_number()
        && want.is_number()
    {
        return a == b;
    }
    match (scalar_string(field), scalar_string(want)) {
        (Some(a), Some(b)) => {
            if case_sensitive {
                a == b
            } else {
                a.to_lowercase() == b.to_lowercase()
            }
        }
        _ => false,
    }
}

/// Compiles a glob pattern to an anchored regex.
pub fn compile_glob(glob: &str, case_sensitive: bool) -> Result<Regex, RuleError> {
    let mut re = String::with_capacity(glob.len() * 2 + 4);
    re.push('^');
    for c in glob.chars() {
        match c {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '/' | '\\' => re.push_str(r"[/\\]"),
            other => {
                let mut buf = [0u8; 4];
                re.push_str(&regex::escape(other.encode_utf8(&mut buf)));
            }
        }
    }
    re.push('$');
    RegexBuilder::new(&re)
        .case_insensitive(!case_sensitive)
        .dot_matches_new_line(true)
        .build()
        .map_err(|e| RuleError::Invalid(format!("bad glob '{glob}': {e}")))
}

/// Group key: the first candidate of each field, stringified, joined by U+001F.
pub fn group_key(event: &Value, fields: &[Vec<String>]) -> String {
    let mut parts = Vec::with_capacity(fields.len());
    for f in fields {
        let path: Vec<&str> = f.iter().map(String::as_str).collect();
        let v = resolve(event, &path).first().and_then(|v| scalar_string(v)).unwrap_or_default();
        parts.push(v);
    }
    parts.join("\u{1f}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cond(v: Value) -> Condition {
        Condition::parse(&v).unwrap()
    }

    #[test]
    fn equals_and_case() {
        let e = json!({"process": {"name": "PowerShell.exe", "pid": 42}});
        assert!(cond(json!({"field": "process.name", "equals": "powershell.exe"})).eval(&e));
        assert!(!cond(json!({"field": "process.name", "equals": "powershell.exe", "case_sensitive": true})).eval(&e));
        assert!(cond(json!({"field": "process.pid", "equals": 42})).eval(&e));
        assert!(cond(json!({"field": "process.pid", "equals": "42"})).eval(&e));
        assert!(!cond(json!({"field": "process.missing", "equals": "x"})).eval(&e));
    }

    #[test]
    fn string_ops() {
        let e = json!({"file": {"path": "C:\\Users\\dev\\.ssh\\id_ed25519"}});
        assert!(cond(json!({"field": "file.path", "contains": "\\.SSH\\"})).eval(&e));
        assert!(cond(json!({"field": "file.path", "startswith": ["d:", "c:\\users"]})).eval(&e));
        assert!(cond(json!({"field": "file.path", "endswith": "id_ed25519"})).eval(&e));
        assert!(cond(json!({"field": "file.path", "glob": "*/.ssh/id_*"})).eval(&e));
        assert!(cond(json!({"field": "file.path", "glob": "C:\\Users\\*\\.ssh\\*"})).eval(&e));
        assert!(!cond(json!({"field": "file.path", "glob": "*.pub"})).eval(&e));
        assert!(cond(json!({"field": "file.path", "regex": "id_(rsa|ed25519)$"})).eval(&e));
        assert!(cond(json!({"field": "file.path", "glob": "c:?users*"})).eval(&e));
    }

    #[test]
    fn in_exists_numeric() {
        let e = json!({"net": {"remote_port": 443, "remote_scope": "public"}, "tags": ["a", "b"]});
        assert!(cond(json!({"field": "net.remote_port", "in": [80, 443]})).eval(&e));
        assert!(cond(json!({"field": "net.remote_port", "gte": 443})).eval(&e));
        assert!(!cond(json!({"field": "net.remote_port", "gt": 443})).eval(&e));
        assert!(cond(json!({"field": "net.remote_port", "lt": 1024})).eval(&e));
        assert!(cond(json!({"field": "net.bytes", "exists": false})).eval(&e));
        assert!(cond(json!({"field": "net", "exists": true})).eval(&e));
        assert!(cond(json!({"field": "tags", "equals": "b"})).eval(&e));
    }

    #[test]
    fn arrays_flatten_through_objects() {
        let e = json!({"items": [{"name": "x"}, {"name": "y"}]});
        assert!(cond(json!({"field": "items.name", "equals": "y"})).eval(&e));
    }

    #[test]
    fn boolean_tree_and_lineage() {
        let e = json!({"lineage": {"agent": "claude-code", "mcp_server": "Files"}});
        assert!(cond(json!({"descendant_of_agent": true})).eval(&e));
        assert!(cond(json!({"spawned_by_mcp_server": true})).eval(&e));
        assert!(cond(json!({"spawned_by_mcp_server": "files"})).eval(&e));
        assert!(!cond(json!({"spawned_by_mcp_server": "other"})).eval(&e));
        let c = cond(json!({"all": [{"descendant_of_agent": true}, {"not": {"spawned_by_mcp_server": false}}]}));
        assert!(c.eval(&e));
        assert!(cond(json!({"descendant_of_agent": false})).eval(&json!({})));
        assert!(cond(json!({"any": [{"field": "a", "exists": true}, {"field": "lineage.agent", "contains": "claude"}]})).eval(&e));
    }

    #[test]
    fn invalid_conditions() {
        for bad in [
            json!({"field": "a"}),
            json!({"field": "a", "equals": 1, "contains": "x"}),
            json!({"field": "a", "bogus": 1}),
            json!({"all": []}),
            json!({"all": [], "any": []}),
            json!({"field": "a", "regex": "("}),
            json!({"field": "a", "gt": "x"}),
            json!("string"),
        ] {
            assert!(Condition::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn group_keys() {
        let e = json!({"lineage": {"root": "1:2"}, "session": "s"});
        let fields = vec![vec!["lineage".into(), "root".into()], vec!["missing".into()]];
        assert_eq!(group_key(&e, &fields), "1:2\u{1f}");
    }
}
