//! JSON API and WebSocket handlers.

use std::collections::BTreeMap;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rousseau_core::config::Config;
use rousseau_core::event::{Event, Severity};
use rousseau_core::rules::ResponseMode;
use rousseau_core::storage::{EventQuery, PinStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::tree::build_session_tree;

/// API error with a JSON body.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn bad(msg: &str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.to_string())
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

fn writable(st: &AppState) -> Result<(), ApiError> {
    if st.replay { Err(ApiError(StatusCode::CONFLICT, "replay mode is read-only".into())) } else { Ok(()) }
}

/// Routes under `/api`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(overview))
        .route("/events", get(events))
        .route("/events/{id}", get(event))
        .route("/sessions", get(sessions))
        .route("/sessions/{id}", get(session))
        .route("/incidents", get(incidents))
        .route("/incidents/{id}", get(incident))
        .route("/incidents/{id}/status", post(incident_status))
        .route("/servers", get(servers))
        .route("/servers/{name}", get(server))
        .route("/pins/approve", post(approve_pin))
        .route("/pins/deny", post(deny_pin))
        .route("/rules", get(rules))
        .route("/rules/reload", post(reload_rules))
        .route("/rules/{id}", post(set_rule))
        .route("/settings", get(get_settings).put(put_settings))
}

async fn overview(State(st): State<AppState>) -> ApiResult<Value> {
    let stats = st.store.stats()?;
    let cfg = Config::load(&st.config_path).unwrap_or_default();
    Ok(Json(json!({
        "version": rousseau_core::VERSION,
        "replay": st.replay,
        "mode": cfg.response.mode,
        "stats": stats,
        "health": st.control.health(),
    })))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct EventParams {
    session: Option<String>,
    agent: Option<String>,
    server: Option<String>,
    kind: Option<String>,
    min_severity: Option<String>,
    tool_call: Option<String>,
    after_id: Option<u64>,
    before_id: Option<u64>,
    limit: Option<u32>,
    ascending: Option<bool>,
}

async fn events(State(st): State<AppState>, Query(p): Query<EventParams>) -> ApiResult<Vec<Event>> {
    let q = EventQuery {
        session: p.session.filter(|s| !s.is_empty()),
        agent: p.agent.filter(|s| !s.is_empty()),
        server: p.server.filter(|s| !s.is_empty()),
        kind: p.kind.filter(|s| !s.is_empty()),
        min_severity: p.min_severity.as_deref().and_then(Severity::parse),
        tool_call: p.tool_call.filter(|s| !s.is_empty()),
        after_id: p.after_id,
        before_id: p.before_id,
        limit: Some(p.limit.unwrap_or(300).min(5_000)),
        ascending: p.ascending.unwrap_or(false),
        ..EventQuery::default()
    };
    Ok(Json(st.store.query_events(&q)?))
}

async fn event(State(st): State<AppState>, Path(id): Path<u64>) -> ApiResult<Event> {
    st.store.event(id)?.map(Json).ok_or_else(|| not_found("event"))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Limit {
    limit: Option<u32>,
    session: Option<String>,
}

async fn sessions(State(st): State<AppState>, Query(p): Query<Limit>) -> ApiResult<Value> {
    let sessions = st.store.sessions(p.limit.unwrap_or(200).min(2_000))?;
    let incidents = st.store.incidents(5_000, None)?;
    let mut counts: BTreeMap<String, (u64, Severity)> = BTreeMap::new();
    for i in &incidents {
        if let Some(s) = &i.session {
            let e = counts.entry(s.clone()).or_insert((0, Severity::Info));
            e.0 += 1;
            e.1 = e.1.max(i.severity);
        }
    }
    let out: Vec<Value> = sessions
        .into_iter()
        .map(|s| {
            let (n, sev) = counts.get(&s.id).copied().unwrap_or((0, Severity::Info));
            let mut v = serde_json::to_value(&s).unwrap_or(Value::Null);
            v["incidents"] = json!(n);
            v["max_severity"] = json!(sev);
            v
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

async fn session(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Value> {
    let s = st.store.session(&id)?.ok_or_else(|| not_found("session"))?;
    let mut events = Vec::new();
    let mut after = 0;
    // Bounded: the session view is for investigation, not bulk export.
    while events.len() < 50_000 {
        let page = st.store.query_events(&EventQuery {
            session: Some(id.clone()),
            after_id: Some(after),
            ascending: true,
            limit: Some(10_000),
            ..EventQuery::default()
        })?;
        let Some(last) = page.last() else { break };
        after = last.id;
        events.extend(page);
    }
    let incidents = st.store.incidents(1_000, Some(&id))?;
    let tree = build_session_tree(&events);
    Ok(Json(json!({ "session": s, "tree": tree, "incidents": incidents, "event_count": events.len() })))
}

async fn incidents(State(st): State<AppState>, Query(p): Query<Limit>) -> ApiResult<Value> {
    Ok(Json(json!(st.store.incidents(p.limit.unwrap_or(300).min(5_000), p.session.as_deref())?)))
}

async fn incident(State(st): State<AppState>, Path(id): Path<u64>) -> ApiResult<Value> {
    let inc = st.store.incident(id)?.ok_or_else(|| not_found("incident"))?;
    let evidence = st.store.events_by_ids(&inc.evidence)?;
    let rule = st.control.rules().into_iter().find(|r| r.id == inc.rule_id).map(|r| r.meta());
    Ok(Json(json!({ "incident": inc, "evidence": evidence, "rule": rule })))
}

#[derive(Deserialize)]
struct StatusBody {
    status: String,
}

async fn incident_status(State(st): State<AppState>, Path(id): Path<u64>, Json(b): Json<StatusBody>) -> ApiResult<Value> {
    writable(&st)?;
    if !matches!(b.status.as_str(), "open" | "acknowledged" | "closed") {
        return Err(bad("status must be open, acknowledged or closed"));
    }
    if !st.store.set_incident_status(id, &b.status)? {
        return Err(not_found("incident"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn servers(State(st): State<AppState>) -> ApiResult<Value> {
    let pins = st.store.pins(None)?;
    let findings = st.store.findings(None, 5_000)?;
    let mut names: Vec<String> = st.store.servers()?.into_iter().map(|s| s.name).collect();
    for p in &pins {
        if !names.contains(&p.server) {
            names.push(p.server.clone());
        }
    }
    names.sort();
    let records = st.store.servers()?;
    let out: Vec<Value> = names
        .iter()
        .map(|n| {
            let ps: Vec<_> = pins.iter().filter(|p| &p.server == n).collect();
            let fs: Vec<_> = findings.iter().filter(|f| f.server() == Some(n.as_str())).collect();
            json!({
                "name": n,
                "record": records.iter().find(|r| &r.name == n),
                "tools": ps.len(),
                "pending": ps.iter().filter(|p| matches!(p.status, PinStatus::Pending | PinStatus::Denied)).count(),
                "findings": fs.len(),
                "max_finding": fs.iter().filter_map(|f| f.severity).max(),
            })
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

async fn server(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult<Value> {
    let record = st.store.servers()?.into_iter().find(|s| s.name == name);
    let pins = st.store.pins(Some(&name))?;
    if record.is_none() && pins.is_empty() {
        return Err(not_found("server"));
    }
    let findings = st.store.findings(Some(&name), 500)?;
    let drift = st.store.query_events(&EventQuery {
        server: Some(name.clone()),
        kind: Some("mcp.drift".into()),
        limit: Some(200),
        ..EventQuery::default()
    })?;
    Ok(Json(json!({ "record": record, "pins": pins, "findings": findings, "drift": drift })))
}

#[derive(Deserialize)]
struct PinBody {
    server: String,
    tool: String,
}

async fn approve_pin(State(st): State<AppState>, Json(b): Json<PinBody>) -> ApiResult<Value> {
    writable(&st)?;
    if !st.store.approve_pin(&b.server, &b.tool, rousseau_core::time::now_ms())? {
        return Err(not_found("tool pin"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn deny_pin(State(st): State<AppState>, Json(b): Json<PinBody>) -> ApiResult<Value> {
    writable(&st)?;
    if !st.store.deny_pin(&b.server, &b.tool, rousseau_core::time::now_ms())? {
        return Err(not_found("tool pin"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn rules(State(st): State<AppState>) -> ApiResult<Value> {
    let cfg = Config::load(&st.config_path).unwrap_or_default();
    let out: Vec<Value> = st
        .control
        .rules()
        .iter()
        .map(|r| {
            let mut v = serde_json::to_value(r.meta()).unwrap_or(Value::Null);
            v["effective_mode"] = json!(r.mode.unwrap_or(cfg.response.mode));
            v
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

async fn reload_rules(State(st): State<AppState>) -> ApiResult<Value> {
    writable(&st)?;
    st.control.reload();
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RuleBody {
    enabled: Option<bool>,
    /// `observe`, `alert`, `enforce`, or `inherit` to follow the global mode.
    mode: Option<String>,
}

async fn set_rule(State(st): State<AppState>, Path(id): Path<String>, Json(b): Json<RuleBody>) -> ApiResult<Value> {
    writable(&st)?;
    if !st.control.rules().iter().any(|r| r.id == id) {
        return Err(not_found("rule"));
    }
    let current = st.store.rule_overrides()?.get(&id).copied().unwrap_or((None, None));
    let mode = match b.mode.as_deref() {
        None => current.1,
        Some("inherit") => None,
        Some(m) => Some(ResponseMode::parse(m).ok_or_else(|| bad("mode must be observe, alert, enforce or inherit"))?),
    };
    st.store.set_rule_override(&id, b.enabled, mode)?;
    st.control.reload();
    Ok(Json(json!({ "ok": true })))
}

async fn get_settings(State(st): State<AppState>) -> ApiResult<Value> {
    let cfg = Config::load(&st.config_path)?;
    let mut v = serde_json::to_value(&cfg)?;
    // Never echo secrets back to the browser.
    for k in ["discord_webhook", "slack_webhook", "webhook_url", "webhook_secret"] {
        if v["alerts"][k].is_string() {
            v["alerts"][k] = json!("(set)");
        }
    }
    Ok(Json(v))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SettingsBody {
    mode: Option<String>,
    allow_suspend: Option<bool>,
    strict_pinning: Option<bool>,
    transcripts_claude_code: Option<bool>,
    transcripts_codex: Option<bool>,
    retention_days: Option<u32>,
    alert_min_severity: Option<String>,
    toast: Option<bool>,
    eventlog: Option<bool>,
}

async fn put_settings(State(st): State<AppState>, Json(b): Json<SettingsBody>) -> ApiResult<Value> {
    writable(&st)?;
    let mut cfg = Config::load(&st.config_path)?;
    if let Some(m) = b.mode {
        cfg.response.mode = ResponseMode::parse(&m).ok_or_else(|| bad("invalid mode"))?;
    }
    if let Some(v) = b.allow_suspend {
        cfg.response.allow_suspend = v;
    }
    if let Some(v) = b.strict_pinning {
        cfg.pinning.strict = v;
    }
    if let Some(v) = b.transcripts_claude_code {
        cfg.transcripts.claude_code = v;
    }
    if let Some(v) = b.transcripts_codex {
        cfg.transcripts.codex = v;
    }
    if let Some(v) = b.retention_days {
        if !(1..=3_650).contains(&v) {
            return Err(bad("retention_days must be between 1 and 3650"));
        }
        cfg.retention_days = v;
    }
    if let Some(s) = b.alert_min_severity {
        cfg.alerts.min_severity = Severity::parse(&s).ok_or_else(|| bad("invalid severity"))?;
    }
    if let Some(v) = b.toast {
        cfg.alerts.toast = v;
    }
    if let Some(v) = b.eventlog {
        cfg.alerts.eventlog = v;
    }
    cfg.save(&st.config_path)?;
    st.control.reload();
    Ok(Json(json!({ "ok": true })))
}

/// `GET /ws`: streams [`rousseau_core::pipeline::LiveMessage`]s as JSON text frames.
pub async fn websocket(State(st): State<AppState>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    // Echo the token subprotocol back, as browsers require.
    let proto = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').map(str::trim).find(|p| p.starts_with("rousseau.")).map(str::to_string));
    let ws = match proto {
        Some(p) => ws.protocols([p]),
        None => ws,
    };
    let rx = st.live.subscribe();
    ws.on_upgrade(move |socket| stream(socket, rx))
}

async fn stream(mut socket: WebSocket, mut rx: tokio::sync::broadcast::Receiver<rousseau_core::pipeline::LiveMessage>) {
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(m) => {
                    let Ok(text) = serde_json::to_string(&m) else { continue };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // The browser is slower than the sensors: tell it to refetch.
                    let note = json!({ "type": "lagged", "missed": n }).to_string();
                    if socket.send(Message::Text(note.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::start;

    #[tokio::test]
    async fn settings_round_trip_hides_secrets() {
        crate::alerts::install_crypto_provider();
        let (_url, token, port) = start().await;
        let base = format!("http://127.0.0.1:{port}/api");
        let c = reqwest::Client::new();
        let r = c
            .put(format!("{base}/settings"))
            .header("x-rousseau-token", &token)
            .json(&serde_json::json!({"mode": "alert", "retention_days": 7}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let s: serde_json::Value =
            c.get(format!("{base}/settings")).header("x-rousseau-token", &token).send().await.unwrap().json().await.unwrap();
        assert_eq!(s["response"]["mode"], "alert");
        assert_eq!(s["retention_days"], 7);
        let bad = c
            .put(format!("{base}/settings"))
            .header("x-rousseau-token", &token)
            .json(&serde_json::json!({"mode": "nope"}))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), 400);
        let missing = c.get(format!("{base}/sessions/none")).header("x-rousseau-token", &token).send().await.unwrap();
        assert_eq!(missing.status(), 404);
    }
}
