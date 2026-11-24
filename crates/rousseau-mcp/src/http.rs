//! `rousseau wrap-http`: a local reverse proxy for Streamable HTTP MCP
//! servers.
//!
//! The MCP client is pointed at `http://127.0.0.1:<port>/mcp`; requests are
//! forwarded to the upstream URL with their headers (including
//! `Authorization`, `Mcp-Session-Id`, `MCP-Protocol-Version` and
//! `Last-Event-ID`), minus hop-by-hop headers. JSON responses are buffered
//! and observed; `text/event-stream` responses are streamed through
//! unchanged while a parser observes each SSE `data:` payload. Requests to
//! other paths (for example OAuth `/.well-known/…` discovery) are forwarded
//! to the upstream origin with the same path.
//!
//! JSON-RPC batches are supported for observation; if a batch contains a
//! call that must be blocked, the whole batch is answered with errors (MCP
//! revisions since 2025-06-18 no longer use batching).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use futures_util::StreamExt;
use serde_json::Value;

use crate::jsonrpc::Message;
use crate::observer::{Observer, Verdict};

/// Errors from the HTTP proxy.
#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    #[error("invalid upstream URL '{0}'")]
    BadUpstream(String),
    #[error("cannot bind {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
    #[error("HTTP client error: {0}")]
    Client(#[from] reqwest::Error),
    #[error("server error: {0}")]
    Serve(#[source] std::io::Error),
}

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Upstream MCP endpoint, e.g. `https://example.com/mcp`.
    pub upstream: String,
    /// Local port (0 = pick a free one).
    pub port: u16,
}

#[derive(Clone)]
struct ProxyState {
    upstream: reqwest::Url,
    client: reqwest::Client,
    observer: Arc<Observer>,
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    // Keep bodies uncompressed so they can be inspected.
    "accept-encoding",
];

/// Builds the proxy router (exposed for tests).
pub fn router(upstream: &str, observer: Arc<Observer>) -> Result<Router, HttpProxyError> {
    let upstream = reqwest::Url::parse(upstream).map_err(|_| HttpProxyError::BadUpstream(upstream.to_string()))?;
    if !matches!(upstream.scheme(), "http" | "https") {
        return Err(HttpProxyError::BadUpstream(upstream.to_string()));
    }
    crate::install_crypto_provider();
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    let state = ProxyState { upstream, client, observer };
    Ok(Router::new().fallback(proxy).with_state(state))
}

/// Binds `127.0.0.1:<port>` and serves until the process ends. Calls
/// `on_ready` with the local MCP URL once listening.
pub async fn run(opts: HttpOptions, observer: Arc<Observer>, on_ready: impl FnOnce(String)) -> Result<(), HttpProxyError> {
    let app = router(&opts.upstream, Arc::clone(&observer))?;
    let addr = SocketAddr::from(([127, 0, 0, 1], opts.port));
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| HttpProxyError::Bind(addr, e))?;
    let local = listener.local_addr().map_err(HttpProxyError::Serve)?;
    observer.server_started(None);
    on_ready(format!("http://{local}/mcp"));
    axum::serve(listener, app).await.map_err(HttpProxyError::Serve)
}

fn target_url(upstream: &reqwest::Url, uri: &Uri) -> reqwest::Url {
    let path = uri.path();
    let mut url = upstream.clone();
    if !(path == "/" || path == "/mcp" || path == upstream.path()) {
        url.set_path(path);
    }
    if let Some(q) = uri.query() {
        url.set_query(Some(q));
    }
    url
}

fn forward_headers(src: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (k, v) in src {
        if HOP_BY_HOP.contains(&k.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(val)) =
            (reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()), reqwest::header::HeaderValue::from_bytes(v.as_bytes()))
        {
            out.append(name, val);
        }
    }
    out
}

fn session_of(h: &HeaderMap) -> Option<String> {
    h.get("mcp-session-id").and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

async fn proxy(State(st): State<ProxyState>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let session = session_of(&parts.headers);
    let body = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return json_response(StatusCode::PAYLOAD_TOO_LARGE, "{\"error\":\"request too large\"}".into()),
    };

    if parts.method == Method::POST && !body.is_empty() {
        let msgs = Message::parse_all(&body);
        let mut blocked = Vec::new();
        for (_, m) in &msgs {
            if let Verdict::Block(resp) = st.observer.client_message(m, session.as_deref()) {
                blocked.push(resp);
            }
        }
        if !blocked.is_empty() {
            let is_batch = body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'[');
            let out = if is_batch || blocked.len() > 1 { Value::Array(blocked).to_string() } else { blocked.remove(0).to_string() };
            return json_response(StatusCode::OK, out);
        }
    }

    let url = target_url(&st.upstream, &parts.uri);
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let upstream = st.client.request(method, url).headers(forward_headers(&parts.headers)).body(body.to_vec()).send().await;
    let resp = match upstream {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            return json_response(StatusCode::BAD_GATEWAY, format!("{{\"error\":\"upstream unavailable: {}\"}}", escape(&e.to_string())));
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (k, v) in resp.headers() {
        if HOP_BY_HOP.contains(&k.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_str().as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
            headers.append(name, val);
        }
    }
    let resp_session = session_of(&headers).or(session);
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default().to_lowercase();

    let body = if content_type.starts_with("text/event-stream") {
        let observer = Arc::clone(&st.observer);
        let mut parser = SseParser::default();
        let stream = resp.bytes_stream().map(move |chunk| {
            if let Ok(bytes) = &chunk {
                for data in parser.push(bytes) {
                    for (_, m) in Message::parse_all(data.as_bytes()) {
                        observer.server_message(&m, resp_session.as_deref());
                    }
                }
            }
            chunk.map_err(std::io::Error::other)
        });
        Body::from_stream(stream)
    } else {
        let bytes: Bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => return json_response(StatusCode::BAD_GATEWAY, format!("{{\"error\":\"{}\"}}", escape(&e.to_string()))),
        };
        if content_type.starts_with("application/json") {
            for (_, m) in Message::parse_all(&bytes) {
                st.observer.server_message(&m, resp_session.as_deref());
            }
        }
        Body::from(bytes)
    };
    let mut out = Response::new(body);
    *out.status_mut() = status;
    *out.headers_mut() = headers;
    out
}

fn escape(s: &str) -> String {
    serde_json::to_string(s).map(|q| q.trim_matches('"').to_string()).unwrap_or_default()
}

/// Incremental Server-Sent Events parser: returns the `data` payload of
/// each complete event (multiple `data:` lines joined with `\n`).
#[derive(Debug, Default)]
pub struct SseParser {
    buf: String,
    data: Vec<String>,
}

impl SseParser {
    /// Feeds bytes; returns completed event payloads.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buf.push_str(&String::from_utf8_lossy(bytes));
        let mut out = Vec::new();
        while let Some(pos) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=pos).collect();
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                if !self.data.is_empty() {
                    out.push(self.data.join("\n"));
                    self.data.clear();
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
            // `event:`, `id:`, `retry:` and comments are irrelevant for observation.
        }
        if self.buf.len() > 64 * 1024 * 1024 {
            self.buf.clear();
            self.data.clear();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::ObserverConfig;
    use crate::pinning::{MemoryPins, Pinner};
    use rousseau_core::event::{Event, ProcessInfo, Severity};
    use rousseau_core::rules::ResponseMode;
    use std::sync::Mutex;

    #[test]
    fn sse_parsing() {
        let mut p = SseParser::default();
        assert!(p.push(b"event: message\ndata: {\"a\":").is_empty());
        let out = p.push(b"1}\r\n\r\n: comment\ndata: x\ndata: y\n\n");
        assert_eq!(out, vec!["{\"a\":1}".to_string(), "x\ny".to_string()]);
    }

    #[test]
    fn target_urls() {
        let up = reqwest::Url::parse("https://example.com/v1/mcp?k=1").unwrap();
        assert_eq!(target_url(&up, &"/mcp".parse().unwrap()).as_str(), "https://example.com/v1/mcp?k=1");
        assert_eq!(target_url(&up, &"/mcp?x=2".parse().unwrap()).as_str(), "https://example.com/v1/mcp?x=2");
        assert_eq!(
            target_url(&up, &"/.well-known/oauth-protected-resource".parse().unwrap()).as_str(),
            "https://example.com/.well-known/oauth-protected-resource?k=1"
        );
    }

    #[derive(Default)]
    struct Collect(Mutex<Vec<Event>>);
    impl rousseau_core::EventSink for Collect {
        fn emit(&self, e: Event) -> bool {
            self.0.lock().unwrap().push(e);
            true
        }
    }

    /// End to end: a fake upstream answering JSON and SSE, through the proxy.
    #[tokio::test(flavor = "multi_thread")]
    async fn proxies_json_and_sse_with_session_header() {
        use axum::routing::post;
        let upstream = Router::new().route(
            "/mcp",
            post(|headers: HeaderMap, body: Bytes| async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                let id = v["id"].clone();
                assert!(headers.get("accept-encoding").is_none());
                if v["method"] == "tools/list" {
                    let payload = serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"echo","description":"Echo"}]}});
                    let mut r = Response::new(Body::from(format!("event: message\ndata: {payload}\n\n")));
                    r.headers_mut().insert("content-type", HeaderValue::from_static("text/event-stream"));
                    r
                } else {
                    let mut r = Response::new(Body::from(serde_json::json!({"jsonrpc":"2.0","id":id,"result":{}}).to_string()));
                    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
                    r.headers_mut().insert("mcp-session-id", HeaderValue::from_static("sess-1"));
                    r
                }
            }),
        );
        let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(up_listener, upstream).await.unwrap() });

        let sink = Arc::new(Collect::default());
        let obs = Arc::new(Observer::new(
            ObserverConfig {
                server: "remote".into(),
                transport: "http".into(),
                mode: ResponseMode::Observe,
                block_findings_at: Severity::High,
                proxy: ProcessInfo { pid: 1, ..ProcessInfo::default() },
                command: None,
                upstream: Some(format!("http://{up_addr}/mcp")),
            },
            Pinner::new(Arc::new(MemoryPins::default()), false),
            sink.clone(),
        ));
        let app = router(&format!("http://{up_addr}/mcp"), obs).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        crate::install_crypto_provider();
        let client = reqwest::Client::new();
        let r = client
            .post(format!("http://{addr}/mcp"))
            .header("content-type", "application/json")
            .header("accept-encoding", "gzip")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(r.headers()["mcp-session-id"], "sess-1");
        let r = client
            .post(format!("http://{addr}/mcp"))
            .header("mcp-session-id", "sess-1")
            .body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
            .send()
            .await
            .unwrap();
        let text = r.text().await.unwrap();
        assert!(text.starts_with("event: message\ndata: "));
        let events = sink.0.lock().unwrap();
        let kinds: Vec<_> = events.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"mcp.initialize"), "{kinds:?}");
        assert!(kinds.contains(&"mcp.tools"), "{kinds:?}");
        let init = events.iter().find(|e| e.kind.as_str() == "mcp.initialize").unwrap();
        assert_eq!(init.mcp.as_ref().unwrap().session_id.as_deref(), Some("sess-1"));
    }
}
