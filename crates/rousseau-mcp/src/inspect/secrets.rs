//! Secret detection by prefix, format, checksum and entropy.
//!
//! Matches are reported redacted (prefix plus length), never in full, so the
//! Rousseau database does not become a second copy of the secret.
//!
//! GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) end in a 6-character
//! base62 CRC32 of the 30 random characters; a valid checksum raises
//! confidence (severity high), an invalid one marks a likely placeholder
//! (severity low).

use std::sync::OnceLock;

use regex::Regex;
use rousseau_core::event::{FindingInfo, Severity, shannon_entropy};

use super::finding;

struct Rule {
    code: &'static str,
    title: &'static str,
    severity: Severity,
    re: Regex,
    /// Capture group holding the secret value (0 = whole match).
    group: usize,
    validate: Validate,
}

#[derive(Clone, Copy)]
enum Validate {
    None,
    GitHubChecksum,
    Entropy(f64),
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let defs: &[(&str, &str, Severity, &str, usize, Validate)] = &[
            ("secrets.aws_access_key", "AWS access key id", Severity::High, r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b", 1, Validate::None),
            ("secrets.github_token", "GitHub token", Severity::High, r"\b(gh[pousr]_[A-Za-z0-9]{36})\b", 1, Validate::GitHubChecksum),
            ("secrets.github_pat", "GitHub fine-grained token", Severity::High, r"\b(github_pat_[A-Za-z0-9_]{82})\b", 1, Validate::None),
            ("secrets.gitlab_token", "GitLab personal access token", Severity::High, r"\b(glpat-[A-Za-z0-9_\-]{20,})", 1, Validate::None),
            ("secrets.slack_token", "Slack token", Severity::High, r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})", 1, Validate::None),
            ("secrets.slack_webhook", "Slack incoming webhook", Severity::Medium, r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,})", 1, Validate::None),
            ("secrets.stripe_key", "Stripe live key", Severity::High, r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,})", 1, Validate::None),
            ("secrets.google_api_key", "Google API key", Severity::High, r"\b(AIza[0-9A-Za-z_\-]{35})", 1, Validate::None),
            ("secrets.openai_key", "OpenAI API key", Severity::High, r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})", 1, Validate::None),
            ("secrets.openai_project_key", "OpenAI project key", Severity::High, r"\b(sk-proj-[A-Za-z0-9_\-]{80,})", 1, Validate::None),
            ("secrets.anthropic_key", "Anthropic API key", Severity::High, r"\b(sk-ant-(?:api03|admin01|oat01)-[A-Za-z0-9_\-]{80,})", 1, Validate::None),
            ("secrets.npm_token", "npm access token", Severity::High, r"\b(npm_[A-Za-z0-9]{36})\b", 1, Validate::None),
            ("secrets.pypi_token", "PyPI API token", Severity::High, r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})", 1, Validate::None),
            ("secrets.private_key", "Private key block", Severity::Critical, r"(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)", 1, Validate::None),
            ("secrets.jwt", "JSON Web Token", Severity::Medium, r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})", 1, Validate::None),
            ("secrets.azure_storage_key", "Azure storage account key", Severity::High, r"(?i)AccountKey=([A-Za-z0-9+/=]{80,})", 1, Validate::None),
            ("secrets.discord_bot_token", "Discord bot token", Severity::High, r"\b([MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b", 1, Validate::Entropy(4.0)),
            ("secrets.generic_assignment", "Credential-like assignment", Severity::Medium,
             r#"(?i)\b(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token)\b["']?\s*[:=]\s*["']?([^\s"',;}{]{12,})"#, 1, Validate::Entropy(3.5)),
        ];
        defs.iter()
            .filter_map(|(code, title, severity, re, group, validate)| {
                Regex::new(re)
                    .map_err(|e| tracing::error!(code, error = %e, "bad secret pattern"))
                    .ok()
                    .map(|re| Rule { code, title, severity: *severity, re, group: *group, validate: *validate })
            })
            .collect()
    })
}

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// CRC-32 (IEEE 802.3, reflected).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Base62 encoding left-padded with `0` to `width`.
pub fn base62(mut n: u32, width: usize) -> String {
    let mut out = Vec::new();
    while n > 0 {
        out.push(BASE62[(n % 62) as usize]);
        n /= 62;
    }
    while out.len() < width {
        out.push(b'0');
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// True if a classic GitHub token's checksum is valid.
pub fn github_checksum_ok(token: &str) -> bool {
    let Some((_, body)) = token.split_once('_') else { return false };
    if body.len() != 36 {
        return false;
    }
    let (random, check) = body.split_at(30);
    base62(crc32(random.as_bytes()), 6) == check
}

fn is_placeholder(v: &str) -> bool {
    let l = v.to_lowercase();
    [
        "xxxx",
        "<",
        "${",
        "{{",
        "example",
        "changeme",
        "placeholder",
        "your_",
        "your-",
        "redacted",
        "*****",
        "dummy",
        "process.env",
        "os.environ",
    ]
    .iter()
    .any(|p| l.contains(p))
}

/// Redacted preview: first four characters and the length.
pub fn redact(v: &str) -> String {
    let head: String = v.chars().take(4).collect();
    format!("{head}… ({} chars)", v.chars().count())
}

/// Inspects one string.
pub fn inspect(s: &str) -> Vec<FindingInfo> {
    if s.len() < 12 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for r in rules() {
        for caps in r.re.captures_iter(s) {
            let Some(m) = caps.get(r.group) else { continue };
            let v = m.as_str();
            let mut severity = r.severity;
            let mut note = String::new();
            match r.validate {
                Validate::None => {}
                Validate::GitHubChecksum => {
                    if github_checksum_ok(v) {
                        note = " Checksum valid.".into();
                    } else {
                        severity = Severity::Low;
                        note = " Checksum invalid (likely a placeholder or test value).".into();
                    }
                }
                Validate::Entropy(min) => {
                    let e = shannon_entropy(v);
                    if e < min || is_placeholder(v) {
                        continue;
                    }
                    note = format!(" Entropy {e:.2} bits/char.");
                }
            }
            if r.code != "secrets.private_key" && is_placeholder(v) {
                continue;
            }
            out.push(finding("secrets", r.code, severity, r.title, format!("{} found: {}.{note}", r.title, redact(v))));
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Token-shaped fixtures are assembled from fragments at runtime so that
    // no literal token appears in the repository.
    fn gh_token(valid: bool) -> String {
        let random = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy";
        let mut check = base62(crc32(random.as_bytes()), 6);
        if !valid {
            check = "000000".into();
        }
        format!("{}{}_{random}{check}", "gh", "p")
    }

    #[test]
    fn crc_and_base62() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(base62(0, 6), "000000");
        assert_eq!(base62(61, 1), "z");
        assert_eq!(base62(62, 2), "10");
    }

    #[test]
    fn github_checksums() {
        let good = gh_token(true);
        assert!(github_checksum_ok(&good));
        let f = inspect(&format!("token={good}"));
        let gh = f.iter().find(|x| x.code == "secrets.github_token").unwrap();
        assert_eq!(gh.severity, Severity::High);
        assert!(!gh.detail.contains(&good), "secret must be redacted");
        let bad = inspect(&gh_token(false));
        assert_eq!(bad[0].severity, Severity::Low);
    }

    #[test]
    fn prefixes_and_formats() {
        let aws = format!("{}{}", "AK", "IAQWERTYUIOPASDFGH");
        assert_eq!(inspect(&format!("key {aws} here"))[0].code, "secrets.aws_access_key");
        let pem = format!("-----BEGIN {} PRIVATE KEY-----\nMIIE", "OPENSSH");
        assert_eq!(inspect(&pem)[0].severity, Severity::Critical);
        let ant = format!("{}{}{}", "sk-ant-", "api03-", "a1B2c3D4e5".repeat(9));
        assert!(inspect(&ant).iter().any(|f| f.code == "secrets.anthropic_key"));
        let jwt = format!("{}.{}.{}", "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
        assert!(inspect(&jwt).iter().any(|f| f.code == "secrets.jwt"));
    }

    #[test]
    fn generic_assignment_needs_entropy_and_no_placeholder() {
        let strong = format!("{}={}", "api_key", "q8Zt2vLx9RmW4kPj7NcB");
        assert!(inspect(&strong).iter().any(|f| f.code == "secrets.generic_assignment"));
        assert!(inspect("password=aaaaaaaaaaaaaaaa").is_empty());
        assert!(inspect("api_key=<your-api-key-here>").is_empty());
        assert!(inspect("token: ${GITHUB_TOKEN_VALUE}").is_empty());
    }

    #[test]
    fn plain_text_is_quiet() {
        assert!(inspect("The weather in Paris is sunny, 21 degrees.").is_empty());
    }
}
