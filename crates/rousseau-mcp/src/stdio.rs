//! `rousseau wrap`: the stdio MCP proxy.
//!
//! The proxy spawns the real server, relays our stdin to its stdin and its
//! stdout to our stdout byte-for-byte, and passes stderr through untouched
//! (the child inherits our stderr handle). Lines are parsed on the way:
//!
//! * client → server lines are classified *before* being relayed, because a
//!   `tools/call` may have to be blocked (enforce mode). Parsing one line is
//!   microseconds; nothing else delays relaying.
//! * server → client lines are written to our stdout first and observed
//!   afterwards on a separate task fed by a bounded channel. If that channel
//!   is full, the observation is dropped rather than slowing the server.

use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::framing::{Frame, LineFramer};
use crate::jsonrpc::Message;
use crate::observer::{Observer, Verdict};

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct StdioOptions {
    /// Program to run.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The proxy's parent process (the MCP client), reported in
    /// `mcp.server_start` so sessions can be built without ETW.
    pub parent: Option<rousseau_core::event::ProcessInfo>,
}

/// Errors from the stdio proxy.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    #[error("failed to start MCP server '{program}': {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

const READ_BUF: usize = 64 * 1024;

/// Runs the proxy with the process's own stdin/stdout. Returns the server's
/// exit code.
pub async fn run(opts: StdioOptions, observer: Arc<Observer>) -> Result<i32, StdioError> {
    run_with_io(opts, observer, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Runs the proxy over arbitrary client streams (used by tests).
pub async fn run_with_io<R, W>(opts: StdioOptions, observer: Arc<Observer>, client_in: R, client_out: W) -> Result<i32, StdioError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut cmd = Command::new(&opts.program);
    cmd.args(&opts.args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| StdioError::Spawn { program: opts.program.clone(), source: e })?;
    observer.set_server_pid(child.id());
    // Announce only now: `mcp.server_start` must carry the server's PID so the
    // pipeline can label the server's process subtree.
    observer.server_started(opts.parent.as_ref());
    let (Some(child_in), Some(child_out)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(StdioError::Io(std::io::Error::other("child pipes unavailable")));
    };

    // Single writer for our stdout: relayed server output and synthesized
    // block responses never interleave mid-line.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    let writer = tokio::spawn(async move {
        let mut w = client_out;
        while let Some(buf) = out_rx.recv().await {
            if w.write_all(&buf).await.is_err() {
                break;
            }
            if w.flush().await.is_err() {
                break;
            }
        }
    });

    // Server output observation runs off the relay path.
    let (obs_tx, mut obs_rx) = mpsc::channel::<Vec<u8>>(1024);
    let obs = Arc::clone(&observer);
    let observe_task = tokio::spawn(async move {
        while let Some(line) = obs_rx.recv().await {
            for (_, msg) in Message::parse_all(&line) {
                obs.server_message(&msg, None);
            }
        }
    });

    let up_obs = Arc::clone(&observer);
    let up_out = out_tx.clone();
    let upstream = tokio::spawn(relay_client_to_server(client_in, child_in, up_obs, up_out));
    let down_obs = Arc::clone(&observer);
    let downstream = tokio::spawn(relay_server_to_client(child_out, out_tx, obs_tx, down_obs));

    let status = child.wait().await?;
    // The server is gone: stop reading the client and let output drain.
    upstream.abort();
    let _ = downstream.await;
    let _ = observe_task.await;
    let _ = writer.await;
    let code = status.code().unwrap_or(1);
    observer.server_exited(Some(code));
    Ok(code)
}

async fn relay_client_to_server<R, W>(mut client_in: R, mut child_in: W, observer: Arc<Observer>, out: mpsc::Sender<Vec<u8>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framer = LineFramer::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = match client_in.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for frame in framer.push(&buf[..n]) {
            let forward = match &frame {
                Frame::Line(line) => {
                    let mut blocked = None;
                    for (_, msg) in Message::parse_all(line) {
                        if let Verdict::Block(resp) = observer.client_message(&msg, None) {
                            blocked = Some(resp);
                        }
                    }
                    match blocked {
                        Some(resp) => {
                            let mut bytes = resp.to_string().into_bytes();
                            bytes.push(b'\n');
                            let _ = out.send(bytes).await;
                            false
                        }
                        None => true,
                    }
                }
                Frame::Oversized(_) => true,
            };
            if forward && (child_in.write_all(frame.bytes()).await.is_err() || child_in.flush().await.is_err()) {
                return;
            }
        }
    }
    // EOF from the client: pass on any unterminated tail, then close the
    // server's stdin so it can exit cleanly.
    let rest = framer.take_remainder();
    if !rest.is_empty() {
        let _ = child_in.write_all(&rest).await;
    }
    let _ = child_in.shutdown().await;
}

async fn relay_server_to_client<R>(mut child_out: R, out: mpsc::Sender<Vec<u8>>, obs: mpsc::Sender<Vec<u8>>, observer: Arc<Observer>)
where
    R: AsyncRead + Unpin,
{
    let mut framer = LineFramer::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = match child_out.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for frame in framer.push(&buf[..n]) {
            match frame {
                Frame::Line(line) => {
                    let msgs = Message::parse_all(&line);
                    if msgs.iter().any(|(_, m)| observer.observe_before_relay(m)) {
                        // Tool lists are pinned before the client sees them.
                        for (_, m) in &msgs {
                            observer.server_message(m, None);
                        }
                        if out.send(line).await.is_err() {
                            return;
                        }
                    } else {
                        // Relay first, exactly as received; observe off the hot path.
                        if out.send(line.clone()).await.is_err() {
                            return;
                        }
                        // Dropping an observation is preferable to stalling the relay.
                        let _ = obs.try_send(line);
                    }
                }
                Frame::Oversized(bytes) => {
                    if out.send(bytes).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
    let rest = framer.take_remainder();
    if !rest.is_empty() {
        let _ = out.send(rest).await;
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

    #[derive(Default)]
    struct Collect(Mutex<Vec<Event>>);
    impl rousseau_core::EventSink for Collect {
        fn emit(&self, e: Event) -> bool {
            self.0.lock().unwrap().push(e);
            true
        }
    }

    /// A tiny echo "server": the platform shell copying stdin to stdout.
    fn echo_server() -> StdioOptions {
        if cfg!(windows) {
            StdioOptions {
                program: "powershell.exe".into(),
                args: vec![
                    "-NoProfile".into(),
                    "-Command".into(),
                    "$i=[Console]::OpenStandardInput(); $o=[Console]::OpenStandardOutput(); $i.CopyTo($o)".into(),
                ],
                parent: None,
            }
        } else {
            StdioOptions { program: "cat".into(), args: vec![], parent: None }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relays_byte_exactly_and_blocks() {
        let sink = Arc::new(Collect::default());
        let pins = Arc::new(MemoryPins::default());
        // Pre-pin a tool and mark it pending so calls are blocked.
        pins_put_pending(&pins);
        let obs = Arc::new(Observer::new(
            ObserverConfig {
                server: "echo".into(),
                transport: "stdio".into(),
                mode: ResponseMode::Enforce,
                block_findings_at: Severity::High,
                proxy: ProcessInfo { pid: std::process::id(), ..ProcessInfo::default() },
                command: None,
                upstream: None,
            },
            Pinner::new(pins, false),
            sink.clone(),
        ));
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"bad\"}}\nnot json at all\n".to_vec();
        let (client_w, client_r) = tokio::io::duplex(1 << 16);
        let (out_w, mut out_r) = tokio::io::duplex(1 << 16);
        let mut client_w = client_w;
        let task = tokio::spawn(run_with_io(echo_server(), obs, client_r, out_w));
        client_w.write_all(&input).await.unwrap();
        client_w.shutdown().await.unwrap();
        drop(client_w);
        let mut output = Vec::new();
        out_r.read_to_end(&mut output).await.unwrap();
        let code = task.await.unwrap().unwrap();
        assert_eq!(code, 0);
        let text = String::from_utf8(output).unwrap();
        // The ping and the garbage line are echoed exactly; the call was answered by Rousseau.
        assert!(text.contains("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n"));
        assert!(text.contains("not json at all\n"));
        assert!(!text.contains("\"method\":\"tools/call\""));
        assert!(text.contains("Blocked by Rousseau"));
        let kinds: Vec<_> = sink.0.lock().unwrap().iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"mcp.blocked"));
        assert!(kinds.contains(&"mcp.server_exit"));
        // The start announcement carries the spawned server's PID.
        let events = sink.0.lock().unwrap();
        let start = events.iter().find(|e| e.kind.as_str() == "mcp.server_start").expect("mcp.server_start emitted");
        assert!(start.mcp.as_ref().unwrap().server_pid.is_some_and(|p| p != std::process::id()));
    }

    fn pins_put_pending(pins: &MemoryPins) {
        use crate::pinning::PinStore;
        use rousseau_core::storage::{PinStatus, ToolPin};
        pins.put(&ToolPin {
            server: "echo".into(),
            tool: "bad".into(),
            approved_hash: Some("old".into()),
            approved_def: Some("{}".into()),
            current_hash: "new".into(),
            current_def: "{}".into(),
            status: PinStatus::Pending,
            first_seen: 0,
            updated: 0,
        });
    }
}
