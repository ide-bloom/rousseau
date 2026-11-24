//! Named pipe between the sensor host (service or `rousseau run`) and the
//! user-side processes (`rousseau wrap`, `wrap-http`, `ui`).
//!
//! `\\.\pipe\rousseau` carries JSON Lines. Requests:
//! `{"op":"ingest","event":…}`, `{"op":"subscribe"}`, `{"op":"reload"}`,
//! `{"op":"health"}`. The DACL grants SYSTEM, Administrators and the
//! installing user only, denies network logons, and remote clients are
//! rejected. Ingest accepts MCP events only, so a user-level process cannot
//! forge OS telemetry.

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rousseau_core::EventSink;
use rousseau_core::event::{Event, SensorInfo};
use rousseau_core::pipeline::LiveMessage;
use rousseau_core::storage::Store;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, mpsc};

/// Pipe path.
pub const PIPE_NAME: &str = r"\\.\pipe\rousseau";

/// A request sent to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Ingest { event: Box<Event> },
    Subscribe,
    Reload,
    Health,
    Policy,
}

/// Policy the host hands to MCP proxies, so a proxy launched by an agent
/// enforces the same mode and uses the same database as the sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub mode: rousseau_core::rules::ResponseMode,
    pub block_findings_at: rousseau_core::event::Severity,
    pub strict_pinning: bool,
    pub data_dir: std::path::PathBuf,
}

/// Messages the host acts on.
#[derive(Debug)]
pub enum HostMsg {
    Reload,
}

/// What the pipe server needs from the host.
#[derive(Clone)]
pub struct PipeContext {
    pub sink: Arc<dyn EventSink>,
    pub live: broadcast::Sender<LiveMessage>,
    pub control: mpsc::Sender<HostMsg>,
    pub health: Arc<RwLock<Vec<SensorInfo>>>,
    pub policy: Arc<RwLock<Policy>>,
}

struct SecurityAttrs {
    sa: windows::Win32::Security::SECURITY_ATTRIBUTES,
    sd: windows::Win32::Security::PSECURITY_DESCRIPTOR,
}

impl SecurityAttrs {
    fn new(user_sid: Option<&str>) -> Result<Self> {
        use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
        // SYSTEM and Administrators: full access; installing user: read/write;
        // network logons: denied.
        let mut sddl = String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)");
        if let Some(sid) = user_sid {
            sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
        }
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor that is freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(windows::core::PCWSTR(wide.as_ptr()), SDDL_REVISION_1, &mut sd, None)
        }
        .context("invalid pipe security descriptor")?;
        let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        Ok(Self { sa, sd })
    }

    fn create(&mut self, first: bool) -> std::io::Result<NamedPipeServer> {
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `self.sa` and the descriptor it points to live as long as
        // `self`, which outlives this call; CreateNamedPipeW copies them.
        unsafe {
            opts.create_with_security_attributes_raw(PIPE_NAME, (&mut self.sa as *mut windows::Win32::Security::SECURITY_ATTRIBUTES).cast())
        }
    }
}

impl Drop for SecurityAttrs {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by ConvertStringSecurityDescriptor… with LocalAlloc.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(self.sd.0)));
        }
    }
}

// SAFETY: the raw pointers only reference the descriptor owned by this
// struct; it is never shared mutably across threads.
unsafe impl Send for SecurityAttrs {}

/// Runs the pipe server until the task is cancelled.
pub async fn serve(ctx: PipeContext, user_sid: Option<String>) -> Result<()> {
    let mut attrs = SecurityAttrs::new(user_sid.as_deref())?;
    let mut server = attrs.create(true).context("cannot create the Rousseau named pipe (is another instance running?)")?;
    loop {
        server.connect().await?;
        let conn = server;
        server = attrs.create(false)?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, ctx).await {
                tracing::debug!(error = %e, "pipe client ended");
            }
        });
    }
}

async fn handle(conn: NamedPipeServer, ctx: PipeContext) -> Result<()> {
    let (r, mut w) = tokio::io::split(conn);
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "bad pipe request");
                continue;
            }
        };
        match req {
            Request::Ingest { event } => {
                if event.kind.is_mcp() {
                    ctx.sink.emit(*event);
                }
            }
            Request::Reload => {
                let _ = ctx.control.send(HostMsg::Reload).await;
                w.write_all(b"{\"type\":\"ok\"}\n").await?;
            }
            Request::Health => {
                let sensors = ctx.health.read().map(|h| h.clone()).unwrap_or_default();
                let mut s = serde_json::to_string(&serde_json::json!({"type": "health", "sensors": sensors}))?;
                s.push('\n');
                w.write_all(s.as_bytes()).await?;
            }
            Request::Policy => {
                let policy = ctx.policy.read().map(|p| p.clone()).map_err(|_| anyhow::anyhow!("policy lock poisoned"))?;
                let mut s = serde_json::to_string(&serde_json::json!({"type": "policy", "policy": policy}))?;
                s.push('\n');
                w.write_all(s.as_bytes()).await?;
            }
            Request::Subscribe => {
                let mut rx = ctx.live.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(m) => {
                            let mut s = serde_json::to_string(&m)?;
                            s.push('\n');
                            w.write_all(s.as_bytes()).await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    }
                }
            }
        }
    }
    Ok(())
}

async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    // ERROR_PIPE_BUSY: every instance is taken until the server creates the
    // next one (a few microseconds after each accept); retry briefly.
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut tries = 0;
    loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            other => return other,
        }
    }
}

/// True if a sensor host is listening.
pub async fn available() -> bool {
    connect().await.is_ok()
}

async fn request(req: &Request) -> Result<Option<String>> {
    let c = connect().await.context("no Rousseau sensor is listening on the named pipe")?;
    let (r, mut w) = tokio::io::split(c);
    let mut s = serde_json::to_string(req)?;
    s.push('\n');
    w.write_all(s.as_bytes()).await?;
    let mut lines = BufReader::new(r).lines();
    Ok(tokio::time::timeout(std::time::Duration::from_secs(3), lines.next_line()).await.ok().transpose()?.flatten())
}

/// Asks the host to reload rules and settings.
pub async fn reload() -> Result<()> {
    request(&Request::Reload).await.map(|_| ())
}

/// Sensor health from the host.
pub async fn health() -> Result<Vec<SensorInfo>> {
    let line = request(&Request::Health).await?.unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
    Ok(serde_json::from_value(v["sensors"].clone()).unwrap_or_default())
}

/// The running host's proxy policy, if a host is listening.
pub async fn policy() -> Option<Policy> {
    let line = request(&Request::Policy).await.ok()??;
    let v: serde_json::Value = serde_json::from_str(&line).ok()?;
    serde_json::from_value(v["policy"].clone()).ok()
}

/// Forwards the host's live stream into `tx` until the pipe closes.
pub async fn subscribe(tx: broadcast::Sender<LiveMessage>) -> Result<()> {
    let c = connect().await?;
    let (r, mut w) = tokio::io::split(c);
    w.write_all(b"{\"op\":\"subscribe\"}\n").await?;
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        if let Ok(m) = serde_json::from_str::<LiveMessage>(&line) {
            let _ = tx.send(m);
        }
    }
    Ok(())
}

/// Event sink used by the MCP proxies: sends events to the host over the
/// pipe; if no host is listening, writes them straight to the database
/// (recorded, but without correlation or rule evaluation).
pub struct PipeSink {
    tx: mpsc::Sender<Event>,
}

impl PipeSink {
    /// Starts the background forwarder. `fallback` is used when the pipe is
    /// unavailable.
    pub fn start(fallback: Option<Arc<Store>>) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<Event>(4_096);
        let handle = tokio::spawn(async move {
            let mut pipe = connect().await.ok();
            if pipe.is_none() {
                tracing::warn!("no Rousseau sensor running; MCP events are written to the database without rule evaluation");
            }
            while let Some(e) = rx.recv().await {
                let mut sent = false;
                if let Some(p) = pipe.as_mut() {
                    let line = serde_json::to_string(&Request::Ingest { event: Box::new(e.clone()) }).map(|mut s| {
                        s.push('\n');
                        s
                    });
                    if let Ok(line) = line {
                        sent = p.write_all(line.as_bytes()).await.is_ok();
                    }
                    if !sent {
                        pipe = None;
                    }
                }
                if !sent && let Some(store) = &fallback {
                    let mut e = e;
                    if let Err(err) = store.insert_event(&mut e) {
                        tracing::debug!(error = %err, "fallback event write failed");
                    }
                }
            }
            if let Some(mut p) = pipe {
                let _ = p.flush().await;
            }
        });
        (Self { tx }, handle)
    }
}

impl EventSink for PipeSink {
    fn emit(&self, event: Event) -> bool {
        self.tx.try_send(event).is_ok()
    }
}
