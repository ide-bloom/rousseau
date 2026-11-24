//! The local dashboard: HTTP API, WebSocket live stream and the embedded
//! web UI, plus alert channels.
//!
//! Security model (see `docs/architecture.md`):
//!
//! * binds `127.0.0.1` on a random port only;
//! * every API and WebSocket request must present the per-launch token
//!   (header `X-Rousseau-Token`, or the WebSocket subprotocol
//!   `rousseau.<token>`); the token travels in the URL fragment, which
//!   browsers never send to servers or in `Referer` headers;
//! * the `Host` header must name the loopback address and port (blocks DNS
//!   rebinding), and state-changing requests must come from the same origin;
//! * a strict Content-Security-Policy; no remote assets.

pub mod alerts;
pub mod api;
pub mod tree;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rousseau_core::event::SensorInfo;
use rousseau_core::pipeline::LiveMessage;
use rousseau_core::rules::Rule;
use rousseau_core::storage::Store;
use rust_embed::RustEmbed;
use tokio::sync::broadcast;

/// Embedded dashboard assets (`web/`).
#[derive(RustEmbed)]
#[folder = "../../web/"]
struct Assets;

/// Hooks into the process hosting the dashboard.
pub trait Control: Send + Sync {
    /// The rule set currently loaded (with overrides applied).
    fn rules(&self) -> Vec<Rule>;
    /// Asks the sensor pipeline to reload rules, overrides and settings.
    fn reload(&self);
    /// Sensor health reports.
    fn health(&self) -> Vec<SensorInfo>;
}

/// Shared state of the dashboard server.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub live: broadcast::Sender<LiveMessage>,
    pub control: Arc<dyn Control>,
    pub token: Arc<str>,
    pub config_path: PathBuf,
    /// Replay mode: data comes from a bundle; writes are refused.
    pub replay: bool,
    /// Set once the listener is bound.
    pub port: u16,
}

/// Generates a 256-bit random token (hex).
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    if getrandom::fill(&mut b).is_err() {
        // The OS RNG is unavailable: refuse to run with a guessable token.
        tracing::error!("system random number generator unavailable");
        std::process::exit(1);
    }
    rousseau_core::hash::hex(&b)
}

fn csp(port: u16) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; \
         connect-src 'self' ws://127.0.0.1:{port} ws://localhost:{port}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

async fn security(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h == format!("127.0.0.1:{}", st.port) || h == format!("localhost:{}", st.port));
    if !host_ok {
        return (StatusCode::MISDIRECTED_REQUEST, "invalid Host header").into_response();
    }
    let path = req.uri().path().to_string();
    let needs_token = path.starts_with("/api/") || path == "/ws";
    if needs_token {
        let token_ok = req
            .headers()
            .get("x-rousseau-token")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| constant_time_eq(v.as_bytes(), st.token.as_bytes()))
            || req.headers().get(header::SEC_WEBSOCKET_PROTOCOL).and_then(|v| v.to_str().ok()).is_some_and(|v| {
                v.split(',')
                    .map(str::trim)
                    .any(|p| p.strip_prefix("rousseau.").is_some_and(|t| constant_time_eq(t.as_bytes(), st.token.as_bytes())))
            });
        if !token_ok {
            return (StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
        }
        let mutating = !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD);
        if (mutating || path == "/ws")
            && let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok())
        {
            let ok = origin == format!("http://127.0.0.1:{}", st.port) || origin == format!("http://localhost:{}", st.port);
            if !ok {
                return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
            }
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&csp(st.port)) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Constant-time comparison for secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn static_file(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(file) => {
            let mime = match path.rsplit('.').next() {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "text/javascript; charset=utf-8",
                Some("css") => "text/css; charset=utf-8",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("ico") => "image/x-icon",
                Some("woff2") => "font/woff2",
                Some("txt") | Some("md") => "text/plain; charset=utf-8",
                _ => "application/octet-stream",
            };
            let mut r = Response::new(Body::from(file.data.into_owned()));
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
            r
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Builds the full router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .nest("/api", api::routes())
        .route("/ws", axum::routing::get(api::websocket))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .with_state(state)
}

/// Binds `127.0.0.1:<port>` (0 = random) and serves the dashboard in the
/// background. Returns the URL to open (token in the fragment).
pub async fn serve(mut state: AppState, port: u16) -> std::io::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    let local = listener.local_addr()?;
    state.port = local.port();
    let url = format!("http://127.0.0.1:{}/#token={}", local.port(), state.token);
    let app = router(state);
    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "dashboard server stopped");
        }
    });
    Ok((url, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoControl;
    impl Control for NoControl {
        fn rules(&self) -> Vec<Rule> {
            Vec::new()
        }
        fn reload(&self) {}
        fn health(&self) -> Vec<SensorInfo> {
            Vec::new()
        }
    }

    pub(crate) async fn start() -> (String, String, u16) {
        crate::alerts::install_crypto_provider();
        let (tx, _) = broadcast::channel(16);
        let state = AppState {
            store: Arc::new(Store::open_in_memory().unwrap()),
            live: tx,
            control: Arc::new(NoControl),
            token: Arc::from("t0ken"),
            config_path: std::env::temp_dir().join(format!("rousseau-test-{}.toml", new_token())),
            replay: false,
            port: 0,
        };
        let (url, _h) = serve(state, 0).await.unwrap();
        let port: u16 = url.split(':').nth(2).unwrap().split('/').next().unwrap().parse().unwrap();
        (url, "t0ken".into(), port)
    }

    #[tokio::test]
    async fn token_host_and_headers() {
        let (url, token, port) = start().await;
        assert!(url.ends_with("/#token=t0ken"));
        let c = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{port}");
        // Static page without token, with CSP.
        let r = c.get(format!("{base}/")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
        // API needs the token.
        assert_eq!(c.get(format!("{base}/api/overview")).send().await.unwrap().status(), 401);
        let ok = c.get(format!("{base}/api/overview")).header("x-rousseau-token", &token).send().await.unwrap();
        assert_eq!(ok.status(), 200);
        // DNS-rebinding style Host header is refused.
        let bad =
            c.get(format!("{base}/api/overview")).header("host", "evil.example").header("x-rousseau-token", &token).send().await.unwrap();
        assert_eq!(bad.status(), 421);
        // Cross-origin POST is refused.
        let xo = c
            .post(format!("{base}/api/rules/reload"))
            .header("x-rousseau-token", &token)
            .header("origin", "http://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(xo.status(), 403);
    }

    #[test]
    fn tokens() {
        let a = new_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_token());
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
