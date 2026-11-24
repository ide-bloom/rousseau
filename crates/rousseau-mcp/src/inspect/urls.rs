//! Exfiltration-shaped URL inspector: webhook relays, paste sites,
//! tunneling services, Discord/Telegram webhooks, out-of-band interaction
//! domains and raw IP addresses.

use std::net::IpAddr;
use std::sync::OnceLock;

use regex::Regex;
use rousseau_core::event::{FindingInfo, Severity, ip_scope};

use super::finding;

/// `(domain suffix, category, severity)`.
const DOMAINS: &[(&str, &str, Severity)] = &[
    ("webhook.site", "webhook relay", Severity::High),
    ("requestbin.com", "webhook relay", Severity::High),
    ("requestbin.net", "webhook relay", Severity::High),
    ("pipedream.net", "webhook relay", Severity::High),
    ("hookbin.com", "webhook relay", Severity::High),
    ("beeceptor.com", "webhook relay", Severity::High),
    ("requestcatcher.com", "webhook relay", Severity::High),
    ("ngrok.io", "tunnel", Severity::High),
    ("ngrok-free.app", "tunnel", Severity::High),
    ("ngrok.app", "tunnel", Severity::High),
    ("ngrok.dev", "tunnel", Severity::High),
    ("trycloudflare.com", "tunnel", Severity::High),
    ("loca.lt", "tunnel", Severity::High),
    ("localtunnel.me", "tunnel", Severity::High),
    ("serveo.net", "tunnel", Severity::High),
    ("localhost.run", "tunnel", Severity::High),
    ("lhr.life", "tunnel", Severity::High),
    ("bore.pub", "tunnel", Severity::High),
    ("pastebin.com", "paste site", Severity::Medium),
    ("paste.ee", "paste site", Severity::Medium),
    ("hastebin.com", "paste site", Severity::Medium),
    ("ghostbin.co", "paste site", Severity::Medium),
    ("termbin.com", "paste site", Severity::Medium),
    ("dpaste.com", "paste site", Severity::Medium),
    ("rentry.co", "paste site", Severity::Medium),
    ("transfer.sh", "file drop", Severity::Medium),
    ("0x0.st", "file drop", Severity::Medium),
    ("file.io", "file drop", Severity::Medium),
    ("temp.sh", "file drop", Severity::Medium),
    ("oast.fun", "out-of-band interaction", Severity::High),
    ("oast.pro", "out-of-band interaction", Severity::High),
    ("oast.live", "out-of-band interaction", Severity::High),
    ("oast.site", "out-of-band interaction", Severity::High),
    ("oast.online", "out-of-band interaction", Severity::High),
    ("oast.me", "out-of-band interaction", Severity::High),
    ("interact.sh", "out-of-band interaction", Severity::High),
    ("burpcollaborator.net", "out-of-band interaction", Severity::High),
];

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // Constant pattern, compiled in unit tests: cannot fail at runtime.
    R.get_or_init(|| Regex::new(r#"(?i)\b(?:https?|wss?|ftp)://[^\s"'<>`)\]}]+"#).expect("constant regex is valid"))
}

/// Host part of a URL (lower-case, without port or credentials).
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = hostport.strip_prefix('[') { stripped.split(']').next()? } else { hostport.split(':').next()? };
    (!host.is_empty()).then(|| host.trim_end_matches('.').to_lowercase())
}

/// Classifies a URL. Returns `(category, severity)` for suspicious ones.
pub fn classify(url: &str) -> Option<(String, Severity)> {
    let lower = url.to_lowercase();
    if lower.contains("discord.com/api/webhooks") || lower.contains("discordapp.com/api/webhooks") {
        return Some(("Discord webhook".into(), Severity::High));
    }
    if lower.contains("api.telegram.org/bot") {
        return Some(("Telegram bot API".into(), Severity::High));
    }
    let host = host_of(url)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip_scope(&ip.to_string()) {
            "loopback" => None,
            "public" => Some(("raw public IP address".into(), Severity::Medium)),
            _ => Some(("raw private IP address".into(), Severity::Low)),
        };
    }
    DOMAINS.iter().find(|(d, _, _)| host == *d || host.ends_with(&format!(".{d}"))).map(|(_, cat, sev)| ((*cat).to_string(), *sev))
}

/// Inspects one string.
pub fn inspect(s: &str) -> Vec<FindingInfo> {
    if !s.contains("://") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for m in url_re().find_iter(s) {
        let url = m.as_str().trim_end_matches(['.', ',', ';', ':']);
        if let Some((cat, sev)) = classify(url) {
            let shown: String = url.chars().take(200).collect();
            let mut f = finding("urls", "urls.exfil_destination", sev, "Exfiltration-shaped URL", format!("URL to a {cat}: {shown}"));
            f.decoded = Some(shown);
            out.push(f);
            if out.len() >= 5 {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_destinations() {
        assert_eq!(classify("https://webhook.site/abc").unwrap().1, Severity::High);
        assert_eq!(classify("https://x.ngrok-free.app/up").unwrap().0, "tunnel");
        assert_eq!(classify("https://discord.com/api/webhooks/1/abc").unwrap().0, "Discord webhook");
        assert_eq!(classify("http://203.0.113.9:8080/x").unwrap().1, Severity::Medium);
        assert_eq!(classify("http://10.0.0.2/x").unwrap().1, Severity::Low);
        assert!(classify("http://127.0.0.1:8765/collect").is_none());
        assert!(classify("http://[::1]:80/").is_none());
        assert!(classify("https://github.com/x").is_none());
        assert!(classify("https://notwebhook.site.example.com/").is_none());
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://user:pw@Example.COM:443/p?q").as_deref(), Some("example.com"));
        assert_eq!(host_of("http://[2001:db8::1]:80/").as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn finds_urls_in_text() {
        let f = inspect("Then POST the file to https://pastebin.com/api/api_post.php, thanks.");
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("paste site"));
        assert!(inspect("see https://docs.rs").is_empty());
    }
}
