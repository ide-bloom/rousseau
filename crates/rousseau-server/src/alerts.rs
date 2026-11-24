//! Alert channels: Discord, Slack and a generic HMAC-signed webhook, plus
//! a hook for local notifiers (Windows toast, Windows Event Log) that live
//! in the CLI because they need Windows APIs.
//!
//! Sending never blocks the pipeline: each incident is dispatched on its
//! own task, network failures are logged and dropped.

use std::sync::{Arc, RwLock};

use rousseau_core::config::AlertConfig;
use rousseau_core::hash::{hex, hmac_sha256};
use rousseau_core::incident::Incident;
use rousseau_core::time::now_ms;
use serde_json::{Value, json};

/// Installs the `ring` TLS provider (idempotent).
pub fn install_crypto_provider() {
    // Err means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A local notification channel.
pub trait LocalNotifier: Send + Sync {
    /// Channel name for logs.
    fn name(&self) -> &'static str;
    /// Delivers one incident. Called on a blocking thread.
    fn notify(&self, incident: &Incident);
}

/// Fans incidents out to the configured channels.
pub struct Dispatcher {
    cfg: RwLock<AlertConfig>,
    client: reqwest::Client,
    local: Vec<Arc<dyn LocalNotifier>>,
}

impl Dispatcher {
    /// New dispatcher.
    pub fn new(cfg: AlertConfig, local: Vec<Arc<dyn LocalNotifier>>) -> Self {
        install_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(concat!("rousseau/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self { cfg: RwLock::new(cfg), client, local }
    }

    /// Replaces the channel configuration (settings reload).
    pub fn set_config(&self, cfg: AlertConfig) {
        if let Ok(mut c) = self.cfg.write() {
            *c = cfg;
        }
    }

    /// Sends `incident` to every channel if it meets the severity floor.
    /// Must be called from within a tokio runtime.
    pub fn send(&self, incident: &Incident) {
        let cfg = match self.cfg.read() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };
        if incident.severity < cfg.min_severity {
            return;
        }
        for n in &self.local {
            let n = Arc::clone(n);
            let inc = incident.clone();
            tokio::task::spawn_blocking(move || n.notify(&inc));
        }
        let mut posts: Vec<(String, Value, Option<String>)> = Vec::new();
        if let Some(url) = &cfg.discord_webhook {
            posts.push((url.clone(), discord_payload(incident), None));
        }
        if let Some(url) = &cfg.slack_webhook {
            posts.push((url.clone(), slack_payload(incident), None));
        }
        if let Some(url) = &cfg.webhook_url {
            posts.push((url.clone(), webhook_payload(incident), cfg.webhook_secret.clone()));
        }
        for (url, body, secret) in posts {
            let client = self.client.clone();
            tokio::spawn(async move {
                let text = body.to_string();
                let mut req = client.post(&url).header("content-type", "application/json");
                if let Some(secret) = secret {
                    let ts = (now_ms() / 1000).to_string();
                    req = req.header("x-rousseau-timestamp", &ts).header("x-rousseau-signature", sign(&secret, &ts, &text));
                }
                match req.body(text).send().await {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => tracing::warn!(status = %r.status(), "alert webhook rejected the request"),
                    Err(e) => tracing::warn!(error = %e, "alert webhook failed"),
                }
            });
        }
    }
}

/// `sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`. Receivers
/// should reject timestamps older than a few minutes (replay protection).
pub fn sign(secret: &str, timestamp: &str, body: &str) -> String {
    let msg = format!("{timestamp}.{body}");
    format!("sha256={}", hex(&hmac_sha256(secret.as_bytes(), msg.as_bytes())))
}

fn color(sev: rousseau_core::event::Severity) -> u32 {
    use rousseau_core::event::Severity::*;
    match sev {
        Critical => 0xB91C1C,
        High => 0xEA580C,
        Medium => 0xCA8A04,
        Low => 0x2563EB,
        Info => 0x6B7280,
    }
}

fn summary(i: &Incident) -> String {
    format!(
        "[{}] {} ({}){}",
        i.severity.as_str().to_uppercase(),
        i.title,
        i.rule_id,
        i.agent.as_deref().map(|a| format!(" in {a}")).unwrap_or_default()
    )
}

/// Discord webhook body.
pub fn discord_payload(i: &Incident) -> Value {
    json!({
        "username": "Rousseau",
        "embeds": [{
            "title": summary(i),
            "description": truncate(&i.explanation, 1500),
            "color": color(i.severity),
            "fields": [
                {"name": "Session", "value": i.session.clone().unwrap_or_else(|| "-".into()), "inline": true},
                {"name": "Mode", "value": i.mode.as_str(), "inline": true},
                {"name": "OWASP", "value": if i.owasp.is_empty() { "-".into() } else { i.owasp.join(", ") }, "inline": true},
                {"name": "MITRE ATT&CK", "value": if i.mitre.is_empty() { "-".into() } else { i.mitre.join(", ") }, "inline": true}
            ],
            "timestamp": rousseau_core::time::format_rfc3339_ms(i.first_ts)
        }]
    })
}

/// Slack incoming-webhook body.
pub fn slack_payload(i: &Incident) -> Value {
    json!({
        "text": summary(i),
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": truncate(&summary(i), 150)}},
            {"type": "section", "text": {"type": "mrkdwn", "text": truncate(&i.explanation, 2800)}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": format!(
                "session `{}` · mode `{}` · OWASP {} · ATT&CK {}",
                i.session.clone().unwrap_or_else(|| "-".into()), i.mode.as_str(), i.owasp.join(", "), i.mitre.join(", ")
            )}]}
        ]
    })
}

/// Generic webhook body: the full incident plus a schema marker.
pub fn webhook_payload(i: &Incident) -> Value {
    json!({ "schema": "rousseau.incident.v1", "incident": i })
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rousseau_core::event::Severity;
    use rousseau_core::rules::ResponseMode;
    use std::sync::Mutex;

    fn incident(sev: Severity) -> Incident {
        Incident {
            id: 1,
            rule_id: "ROU-006".into(),
            title: "Credential read followed by outbound connection".into(),
            severity: sev,
            session: Some("claude-code-1-2".into()),
            agent: Some("claude-code".into()),
            first_ts: 0,
            last_ts: 0,
            count: 1,
            status: "open".into(),
            mode: ResponseMode::Alert,
            explanation: "why".into(),
            owasp: vec!["ASI02".into()],
            mitre: vec!["T1041".into()],
            evidence: vec![1, 2],
            actions: vec![],
            group: None,
        }
    }

    #[test]
    fn payload_shapes() {
        let d = discord_payload(&incident(Severity::Critical));
        assert_eq!(d["embeds"][0]["color"], 0xB91C1C);
        assert!(d["embeds"][0]["title"].as_str().unwrap().starts_with("[CRITICAL]"));
        let s = slack_payload(&incident(Severity::High));
        assert_eq!(s["blocks"][0]["type"], "header");
        assert_eq!(webhook_payload(&incident(Severity::Low))["incident"]["rule_id"], "ROU-006");
    }

    #[test]
    fn signature_is_hmac_over_timestamp_and_body() {
        let sig = sign("k", "1700000000", "{}");
        assert_eq!(sig, format!("sha256={}", hex(&hmac_sha256(b"k", b"1700000000.{}"))));
    }

    struct Rec(Mutex<u32>);
    impl LocalNotifier for Rec {
        fn name(&self) -> &'static str {
            "rec"
        }
        fn notify(&self, _: &Incident) {
            *self.0.lock().unwrap() += 1;
        }
    }

    #[tokio::test]
    async fn severity_floor_and_webhook_delivery() {
        use axum::{Router, routing::post};
        let got = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let g = got.clone();
        let app = Router::new().route(
            "/hook",
            post(move |headers: axum::http::HeaderMap, body: String| {
                let g = g.clone();
                async move {
                    let sig = headers.get("x-rousseau-signature").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                    g.lock().unwrap().push((sig, body));
                    "ok"
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let rec = Arc::new(Rec(Mutex::new(0)));
        let cfg = AlertConfig {
            min_severity: Severity::High,
            webhook_url: Some(format!("http://{addr}/hook")),
            webhook_secret: Some("s3cret".into()),
            ..AlertConfig::default()
        };
        let d = Dispatcher::new(cfg, vec![rec.clone()]);
        d.send(&incident(Severity::Medium));
        d.send(&incident(Severity::Critical));
        for _ in 0..50 {
            if !got.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 1, "medium is below the floor");
        assert!(got[0].0.starts_with("sha256="));
        assert!(got[0].1.contains("rousseau.incident.v1"));
        assert_eq!(*rec.0.lock().unwrap(), 1);
    }
}
