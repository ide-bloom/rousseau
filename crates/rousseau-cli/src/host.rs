//! The sensor host shared by `rousseau run` (foreground) and the Windows
//! service: storage, pipeline, ETW sensor, transcript adapters, named pipe
//! and alert dispatch.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use rousseau_adapters::transcripts::{self, Watcher};
use rousseau_core::config::Config;
use rousseau_core::event::{Event, EventKind, SensorInfo, Severity};
use rousseau_core::incident::Incident;
use rousseau_core::pipeline::{LiveMessage, Pipeline, Responder, TrackedPids};
use rousseau_core::rules::Rule;
use rousseau_core::storage::Store;
use rousseau_core::time::now_ms;
use rousseau_core::{ChannelSink, EventSink};
use rousseau_etw::sensor::{Sensor, SensorOptions};
use rousseau_server::Control;
use rousseau_server::alerts::{Dispatcher, LocalNotifier};
use tokio::sync::{broadcast, mpsc};

use crate::notify;
use crate::paths::{Paths, load_agents, load_rules};
use crate::pipe::{self, HostMsg, PipeContext};

/// Bounded queue between sensors and the pipeline. A full queue drops
/// events (counted in health) rather than stalling ETW callbacks.
const QUEUE: usize = 65_536;

/// Options for [`Host::start`].
#[derive(Debug, Clone)]
pub struct HostOptions {
    /// Show toasts (interactive sessions only).
    pub toast: bool,
    /// Extra agent signature files given on the command line.
    pub extra_agents: Vec<std::path::PathBuf>,
    /// Override the configured response mode.
    pub mode: Option<rousseau_core::rules::ResponseMode>,
}

/// Responds to incidents: alerts plus (opt-in) suspension.
struct HostResponder {
    dispatcher: Arc<Dispatcher>,
}

impl Responder for HostResponder {
    fn alert(&self, incident: &Incident) {
        self.dispatcher.send(incident);
    }
    fn suspend(&self, pids: &[u32]) -> Result<usize, String> {
        let n = rousseau_etw::process::suspend(pids);
        if n == 0 { Err("no process could be suspended (protected or already gone)".into()) } else { Ok(n) }
    }
}

/// Dashboard hooks for the in-process host.
pub struct HostControl {
    rules: Arc<RwLock<Vec<Rule>>>,
    ctrl: mpsc::Sender<HostMsg>,
    health: Arc<RwLock<Vec<SensorInfo>>>,
}

impl Control for HostControl {
    fn rules(&self) -> Vec<Rule> {
        self.rules.read().map(|r| r.clone()).unwrap_or_default()
    }
    fn reload(&self) {
        let _ = self.ctrl.try_send(HostMsg::Reload);
    }
    fn health(&self) -> Vec<SensorInfo> {
        self.health.read().map(|h| h.clone()).unwrap_or_default()
    }
}

/// A running host.
pub struct Host {
    pub store: Arc<Store>,
    pub live: broadcast::Sender<LiveMessage>,
    pub control: Arc<HostControl>,
    task: tokio::task::JoinHandle<()>,
}

impl Host {
    /// Starts everything. Must be called inside a tokio runtime.
    pub async fn start(paths: &Paths, opts: HostOptions) -> Result<Self> {
        paths.ensure()?;
        let mut cfg = paths.load_config()?;
        if let Some(m) = opts.mode {
            cfg.response.mode = m;
        }
        let store = Arc::new(Store::open(&paths.db()).with_context(|| format!("cannot open {}", paths.db().display()))?);
        let closed = store.close_dangling_sessions(now_ms())?;
        if closed > 0 {
            tracing::info!(closed, "closed sessions left open by a previous run");
        }
        let mut agent_files = cfg.agent_files.clone();
        agent_files.extend(opts.extra_agents.iter().cloned());
        let agents = Arc::new(load_agents(&agent_files)?);
        let rules = load_rules(&cfg.rule_dirs)?;
        tracing::info!(rules = rules.len(), agents = agents.agents().len(), mode = cfg.response.mode.as_str(), "starting sensor host");

        let (live, _) = broadcast::channel::<LiveMessage>(4_096);
        let tracked: TrackedPids = Arc::default();
        let (tx, rx) = mpsc::channel::<Event>(QUEUE);
        let channel_sink = ChannelSink::new(tx);
        let sink: Arc<dyn EventSink> = Arc::new(channel_sink.clone());

        let mut local: Vec<Arc<dyn LocalNotifier>> = Vec::new();
        if cfg.alerts.eventlog {
            local.push(Arc::new(notify::EventLog));
        }
        if cfg.alerts.toast && opts.toast {
            notify::register_toast_app();
            local.push(Arc::new(notify::Toast));
        }
        let dispatcher = Arc::new(Dispatcher::new(cfg.alerts.clone(), local));

        let mut pipeline = Pipeline::new(Arc::clone(&store), rules, agents.clone(), live.clone(), tracked.clone())?;
        pipeline.set_response(cfg.response.clone(), cfg.retention_days);
        pipeline.set_responder(Arc::new(HostResponder { dispatcher: Arc::clone(&dispatcher) }));
        let rules_view = Arc::new(RwLock::new(pipeline.rules().to_vec()));
        let health = Arc::new(RwLock::new(Vec::<SensorInfo>::new()));
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<HostMsg>(16);

        // Seed the process tree with processes already running, oldest
        // first, so agents started before Rousseau are tracked too.
        let interesting: HashSet<String> = interesting_names(&agents);
        let snap_interesting = interesting.clone();
        let snapshot = tokio::task::spawn_blocking(move || rousseau_etw::process::snapshot(&|n| snap_interesting.contains(n))).await?;
        let seed: Vec<Event> = snapshot
            .into_iter()
            .map(|p| {
                let mut e = Event::new(EventKind::ProcessStart, p.start_time.unwrap_or_else(now_ms));
                e.process = Some(p);
                e
            })
            .collect();
        pipeline.process_batch(seed)?;

        // ETW (needs elevation).
        let sensor = match Sensor::start(&SensorOptions::default(), Arc::clone(&sink), tracked.clone(), interesting) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(error = %e, "ETW sensor not started; MCP proxy and transcript visibility only");
                set_health(
                    &health,
                    SensorInfo { sensor: "etw".into(), status: "down".into(), message: e.to_string(), ..SensorInfo::default() },
                );
                None
            }
        };

        // Transcript adapters (opt-in).
        let home = cfg.user_profile.clone().or_else(|| std::env::var_os("USERPROFILE").map(Into::into));
        if let Some(home) = home {
            let mut watchers = Vec::new();
            if cfg.transcripts.claude_code {
                watchers.extend(transcripts::adapter_by_name("claude-code").map(|a| Watcher::new(a, home.clone())));
            }
            if cfg.transcripts.codex {
                watchers.extend(transcripts::adapter_by_name("codex").map(|a| Watcher::new(a, home.clone())));
            }
            if !watchers.is_empty() {
                tokio::spawn(transcripts::run(watchers, Arc::clone(&sink), Duration::from_secs(1)));
            }
        }

        // Named pipe for proxies and the UI.
        let policy = Arc::new(RwLock::new(policy_of(&cfg, paths)));
        let pctx = PipeContext {
            sink: Arc::clone(&sink),
            live: live.clone(),
            control: ctrl_tx.clone(),
            health: Arc::clone(&health),
            policy: Arc::clone(&policy),
        };
        let user_sid = cfg.user_sid.clone().or_else(rousseau_etw::process::current_user_sid);
        tokio::spawn(async move {
            if let Err(e) = pipe::serve(pctx, user_sid).await {
                tracing::error!(error = %e, "named pipe server stopped");
            }
        });

        notify::report(notify::EVENT_STARTED, Severity::Info, &format!("Rousseau sensor started (mode {}).", cfg.response.mode.as_str()));
        let state = LoopState {
            pipeline,
            rx,
            ctrl_rx,
            sensor,
            channel_sink,
            health: Arc::clone(&health),
            rules_view: Arc::clone(&rules_view),
            dispatcher,
            paths: paths.clone(),
            mode_override: opts.mode,
            extra_dirs: cfg.rule_dirs.clone(),
            policy,
        };
        let task = tokio::spawn(run_loop(state));
        Ok(Self { store, live, control: Arc::new(HostControl { rules: rules_view, ctrl: ctrl_tx, health }), task })
    }

    /// Waits until the host loop ends.
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

fn interesting_names(agents: &rousseau_adapters::agents::AgentTable) -> HashSet<String> {
    // Exe names come from the embedded table; node/python/bun cover agents
    // that run on an interpreter and need a command line to be recognised.
    let mut s: HashSet<String> = [
        "claude.exe",
        "codex.exe",
        "codex-x86_64-pc-windows-msvc.exe",
        "codex-aarch64-pc-windows-msvc.exe",
        "cursor.exe",
        "windsurf.exe",
        "code.exe",
        "code - insiders.exe",
        "gemini.exe",
        "aider.exe",
        "opencode.exe",
        "goose.exe",
        "node.exe",
        "bun.exe",
        "python.exe",
        "pythonw.exe",
        "py.exe",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for a in agents.agents() {
        s.insert(a.id.clone());
    }
    s
}

fn policy_of(cfg: &Config, paths: &Paths) -> pipe::Policy {
    pipe::Policy {
        mode: cfg.response.mode,
        block_findings_at: cfg.response.block_findings_at,
        strict_pinning: cfg.pinning.strict,
        data_dir: paths.data.clone(),
    }
}

fn set_health(h: &RwLock<Vec<SensorInfo>>, info: SensorInfo) {
    if let Ok(mut v) = h.write() {
        v.retain(|x| x.sensor != info.sensor);
        v.push(info);
    }
}

struct LoopState {
    pipeline: Pipeline,
    rx: mpsc::Receiver<Event>,
    ctrl_rx: mpsc::Receiver<HostMsg>,
    sensor: Option<Sensor>,
    channel_sink: ChannelSink,
    health: Arc<RwLock<Vec<SensorInfo>>>,
    rules_view: Arc<RwLock<Vec<Rule>>>,
    dispatcher: Arc<Dispatcher>,
    paths: Paths,
    mode_override: Option<rousseau_core::rules::ResponseMode>,
    extra_dirs: Vec<std::path::PathBuf>,
    policy: Arc<RwLock<pipe::Policy>>,
}

impl LoopState {
    fn reload(&mut self) {
        let mut cfg: Config = match self.paths.load_config() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "reload: configuration invalid; keeping previous settings");
                return;
            }
        };
        if let Some(m) = self.mode_override {
            cfg.response.mode = m;
        }
        self.extra_dirs.clone_from(&cfg.rule_dirs);
        match load_rules(&self.extra_dirs) {
            Ok(rules) => {
                if let Err(e) = self.pipeline.set_rules(rules) {
                    tracing::error!(error = %e, "reload: rule overrides unreadable");
                }
                if let Ok(mut v) = self.rules_view.write() {
                    *v = self.pipeline.rules().to_vec();
                }
            }
            Err(e) => tracing::error!(error = %e, "reload: rules invalid; keeping previous rules"),
        }
        self.pipeline.set_response(cfg.response.clone(), cfg.retention_days);
        self.dispatcher.set_config(cfg.alerts.clone());
        if let Ok(mut p) = self.policy.write() {
            *p = policy_of(&cfg, &self.paths);
        }
        tracing::info!(mode = cfg.response.mode.as_str(), "reloaded rules and settings");
    }

    /// Refreshes the in-memory health (served to `doctor` and the dashboard).
    /// With `record`, also refreshes drive mappings, reports degraded health
    /// to the Event Log and returns `sensor.health` events to store.
    fn health_tick(&mut self, record: bool) -> Vec<Event> {
        let mut out = Vec::new();
        let mut infos = Vec::new();
        if let Some(s) = &self.sensor {
            if record {
                s.refresh_devices();
            }
            let mut h = s.health();
            h.events_dropped += self.channel_sink.dropped();
            infos.push(h);
        }
        for h in infos {
            if record {
                if h.status != "ok" {
                    notify::report(notify::EVENT_HEALTH, Severity::Medium, &format!("Sensor {}: {} — {}", h.sensor, h.status, h.message));
                }
                let mut e = Event::new(EventKind::SensorHealth, now_ms());
                e.sensor = Some(h.clone());
                out.push(e);
            }
            set_health(&self.health, h);
        }
        out
    }
}

async fn run_loop(mut st: LoopState) {
    let mut buf = Vec::with_capacity(1_024);
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut health_every = 0u32;
    loop {
        tokio::select! {
            n = st.rx.recv_many(&mut buf, 1_024) => {
                if n == 0 {
                    break;
                }
                let batch = std::mem::take(&mut buf);
                if let Err(e) = st.pipeline.process_batch(batch) {
                    tracing::error!(error = %e, "pipeline batch failed");
                }
            }
            Some(msg) = st.ctrl_rx.recv() => match msg {
                HostMsg::Reload => st.reload(),
            },
            _ = tick.tick() => {
                if let Err(e) = st.pipeline.tick(now_ms()) {
                    tracing::warn!(error = %e, "maintenance failed");
                }
                health_every += 1;
                // Live health every tick; a stored health event once a minute.
                let events = st.health_tick(health_every % 12 == 1);
                if !events.is_empty()
                    && let Err(e) = st.pipeline.process_batch(events)
                {
                    tracing::warn!(error = %e, "health event failed");
                }
            }
        }
    }
    notify::report(notify::EVENT_STOPPED, Severity::Info, "Rousseau sensor stopped.");
}
