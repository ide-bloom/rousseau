//! Runs the shared `conformance/` suite against the Rust rule engine.
//! The Python engine runs the same files (lab/tests/test_conformance.py).

use std::path::{Path, PathBuf};

use rousseau_core::rules::{Rule, RuleEngine, parse_multi};
use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn split_docs(text: &str) -> Vec<String> {
    let mut docs = vec![String::new()];
    for line in text.lines() {
        if line.trim_end() == "---" {
            docs.push(String::new());
        } else if let Some(d) = docs.last_mut() {
            d.push_str(line);
            d.push('\n');
        }
    }
    docs.into_iter().filter(|d| !d.trim().is_empty()).collect()
}

fn load_rule(case: &Value) -> Result<Rule, String> {
    if let Some(r) = case.get("rule") {
        return Rule::from_value(r).map_err(|e| e.to_string());
    }
    let rref = case.get("rule_ref").ok_or("case has neither rule nor rule_ref")?;
    let file = rref["file"].as_str().ok_or("rule_ref.file")?;
    let id = rref["id"].as_str().ok_or("rule_ref.id")?;
    let path = repo_root().join(file);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_multi(&text, file).map_err(|e| e.to_string())?.into_iter().find(|r| r.id == id).ok_or_else(|| format!("{id} not found in {file}"))
}

#[test]
fn conformance_suite() {
    let dir = repo_root().join("conformance/cases");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("conformance/cases exists")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    let mut total = 0;
    let mut failures = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for doc in split_docs(&text) {
            let case: Value = serde_yaml::from_str(&doc).unwrap();
            let name = case["name"].as_str().unwrap_or("?").to_string();
            total += 1;
            let invalid = case.get("invalid").and_then(Value::as_bool).unwrap_or(false);
            let rule = load_rule(&case);
            if invalid {
                if rule.is_ok() {
                    failures.push(format!("{name}: invalid rule was accepted"));
                }
                continue;
            }
            let rule = match rule {
                Ok(r) => r,
                Err(e) => {
                    failures.push(format!("{name}: rule failed to load: {e}"));
                    continue;
                }
            };
            let mut engine = RuleEngine::new(vec![rule]);
            let mut got: Vec<Vec<u64>> = Vec::new();
            for ev in case["events"].as_array().cloned().unwrap_or_default() {
                for m in engine.process(&ev) {
                    got.push(m.events);
                }
            }
            let want: Vec<Vec<u64>> = case["expected"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|m| m["events"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect())
                .collect();
            if got != want {
                failures.push(format!("{name}: expected {want:?}, got {got:?}"));
            }
        }
    }
    assert!(total >= 30, "only {total} cases found");
    assert!(failures.is_empty(), "{} of {total} cases failed:\n{}", failures.len(), failures.join("\n"));
}
