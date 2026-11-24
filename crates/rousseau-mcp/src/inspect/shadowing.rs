//! Tool shadowing: the same or a confusable tool name exposed by different
//! servers. A malicious server can register `send_email` (or `sеnd_email`
//! with a Cyrillic `е`) to intercept calls meant for a trusted one.

use rousseau_core::event::{FindingInfo, Severity};

use super::confusables::skeleton;
use super::finding;

/// Compares `tools` of `server` against `(server, tool)` pairs known from
/// other servers.
pub fn inspect(server: &str, tools: &[String], others: &[(String, String)]) -> Vec<FindingInfo> {
    let mut out = Vec::new();
    for tool in tools {
        let sk = skeleton(tool);
        for (other_server, other_tool) in others {
            if other_server.eq_ignore_ascii_case(server) {
                continue;
            }
            if skeleton(other_tool) != sk {
                continue;
            }
            let exact = other_tool == tool;
            let mut f = finding(
                "shadowing",
                if exact { "shadowing.duplicate" } else { "shadowing.confusable" },
                if exact { Severity::Medium } else { Severity::High },
                if exact { "Tool name duplicated across servers" } else { "Confusable tool name across servers" },
                if exact {
                    format!("Tool '{tool}' is also offered by server '{other_server}'. The model may call the wrong one.")
                } else {
                    format!(
                        "Tool '{tool}' looks identical to '{other_tool}' on server '{other_server}' but differs in its characters ({}).",
                        describe_diff(tool, other_tool)
                    )
                },
            );
            f.server = Some(server.to_string());
            f.tool = Some(tool.clone());
            f.location = format!("tools/list {tool}.name");
            out.push(f);
        }
    }
    out
}

fn describe_diff(a: &str, b: &str) -> String {
    let fmt = |s: &str| s.chars().filter(|c| !c.is_ascii()).map(|c| format!("U+{:04X}", c as u32)).collect::<Vec<_>>().join(" ");
    let (fa, fb) = (fmt(a), fmt(b));
    match (fa.is_empty(), fb.is_empty()) {
        (true, true) => "ASCII look-alikes".into(),
        (false, true) => format!("non-ASCII: {fa}"),
        (true, false) => format!("other name has non-ASCII: {fb}"),
        (false, false) => format!("{fa} vs {fb}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_and_confusables() {
        let others = vec![("gmail".to_string(), "send_email".to_string()), ("fs".to_string(), "read_file".to_string())];
        let f = inspect("evil", &["sеnd_email".to_string(), "read_file".to_string(), "unique".to_string()], &others);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].code, "shadowing.confusable");
        assert!(f[0].detail.contains("U+0435"));
        assert_eq!(f[1].code, "shadowing.duplicate");
        // A server never shadows itself.
        assert!(inspect("gmail", &["send_email".to_string()], &others).is_empty());
    }
}
