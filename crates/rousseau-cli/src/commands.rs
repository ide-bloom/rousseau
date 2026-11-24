//! Command implementations.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use rousseau_core::bundle;
use rousseau_core::event::SensorInfo;
use rousseau_core::pipeline::{AgentMatcher, LiveMessage};
use rousseau_core::rules::{ResponseMode, Rule};
use rousseau_core::storage::Store;
use rousseau_mcp::clients::{self, Resolver};
use rousseau_mcp::observer::{Observer, ObserverConfig};
use rousseau_mcp::pinning::{MemoryPins, PinStore, Pinner};
use rousseau_server::{AppState, Control, new_token};
use tokio::sync::broadcast;

use crate::host::{Host, HostOptions};
use crate::paths::{Paths, current_exe, load_agents, load_rules, user_state_dir};
use crate::{Cli, Command, RulesAction, notify, pipe, service, winsec};

/// Runs a command; returns the process exit code.
pub fn dispatch(cli: Cli, paths: Paths) -> Result<i32> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match cli.command {
        Command::Run { mode, headless, no_browser, port, agents } => {
            rt.block_on(run(&paths, mode.map(Into::into), headless, no_browser, port, agents))
        }
        Command::Install => install(&paths),
        Command::Uninstall { purge } => uninstall(&paths, purge),
        Command::Ui { port, no_browser } => rt.block_on(ui(&paths, port, no_browser)),
        Command::Wrap { name, mode, command } => rt.block_on(wrap(&paths, name, mode.map(Into::into), command)),
        Command::WrapHttp { name, upstream, port, mode } => rt.block_on(wrap_http(&paths, name, upstream, port, mode.map(Into::into))),
        Command::Protect { projects, dry_run } => protect(projects, dry_run),
        Command::Unprotect { dry_run } => unprotect(dry_run),
        Command::Doctor => rt.block_on(doctor(&paths)),
        Command::Export { session, output } => export(&paths, &session, &output),
        Command::Replay { bundle, port, no_browser } => rt.block_on(replay(&bundle, port, no_browser)),
        Command::Rules { action } => rules(&paths, action),
        Command::Agents => agents(&paths),
        Command::Resume { pids } => {
            let n = rousseau_etw::process::resume(&pids);
            println!("resumed {n} process(es)");
            Ok(if n > 0 { 0 } else { 1 })
        }
        Command::Service => unreachable!("handled in main"),
    }
}

fn open_browser(url: &str) {
    // `start` treats the first quoted argument as a window title, hence "".
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).status();
}

async fn serve_dashboard(
    store: Arc<Store>,
    live: broadcast::Sender<LiveMessage>,
    control: Arc<dyn Control>,
    paths: &Paths,
    replay: bool,
    port: u16,
    no_browser: bool,
) -> Result<String> {
    let state = AppState { store, live, control, token: Arc::from(new_token()), config_path: paths.config(), replay, port: 0 };
    let (url, _h) = rousseau_server::serve(state, port).await.context("cannot start the dashboard")?;
    println!("Dashboard: {url}");
    println!("(The token after # authorizes this browser session; do not share it.)");
    if !no_browser {
        open_browser(&url);
    }
    Ok(url)
}

async fn run(paths: &Paths, mode: Option<ResponseMode>, headless: bool, no_browser: bool, port: u16, agents: Vec<PathBuf>) -> Result<i32> {
    // Starting a second sensor would replace the running one's ETW session.
    if pipe::available().await {
        bail!("a Rousseau sensor (the service or another `rousseau run`) is already running; use `rousseau ui` to view it");
    }
    let elevated = rousseau_etw::process::is_elevated();
    if !elevated {
        eprintln!("warning: not elevated; ETW sensors are off (MCP proxy events and transcripts only). Use an administrator terminal.");
    }
    let host = Host::start(paths, HostOptions { toast: true, extra_agents: agents, mode }).await?;
    if !headless {
        serve_dashboard(Arc::clone(&host.store), host.live.clone(), host.control.clone(), paths, false, port, no_browser).await?;
    }
    println!("Rousseau is running. Press Ctrl+C to stop.");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = host.join() => {}
    }
    // main() exits with std::process::exit, which skips the sensor's
    // destructor; stop the ETW session explicitly so none is left behind.
    if elevated {
        rousseau_etw::sensor::stop_session();
    }
    Ok(0)
}

fn program_files_exe() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    pf.join("Rousseau").join("rousseau.exe")
}

fn install(paths: &Paths) -> Result<i32> {
    if !rousseau_etw::process::is_elevated() {
        bail!("`rousseau install` must run from an elevated (administrator) terminal");
    }
    let src = current_exe()?;
    let dst = program_files_exe();
    // The service runs as LocalSystem: its binary must live in an
    // admin-only directory, never in a user-writable download folder.
    if !src.eq(&dst) {
        if let Some(d) = dst.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::copy(&src, &dst).with_context(|| format!("cannot copy rousseau.exe to {}", dst.display()))?;
    }
    paths.ensure()?;
    let sid = rousseau_etw::process::current_user_sid();
    winsec::restrict_dir(&paths.data, sid.as_deref())?;
    let mut cfg = paths.load_config()?;
    cfg.user_profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    cfg.user_sid = sid;
    cfg.save(&paths.config())?;
    register_event_source();
    service::install(&dst, &paths.data)?;
    println!("Installed {} and started the '{}' service.", dst.display(), service::SERVICE_NAME);
    println!("Data directory: {} (SYSTEM, Administrators and you only).", paths.data.display());
    println!("Next: `rousseau protect` to wrap your MCP servers, then `rousseau ui`.");
    println!("New installs start in observe mode; change it in the dashboard Settings.");
    Ok(0)
}

const EVENTLOG_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Rousseau";

fn register_event_source() {
    // EventLogMessages.dll (part of .NET Framework 4, present on Windows 11)
    // maps every event id to "%1", so our message text displays verbatim.
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let dll = format!(r"{windir}\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll");
    let _ = std::process::Command::new("reg.exe")
        .args(["add", EVENTLOG_KEY, "/v", "EventMessageFile", "/t", "REG_EXPAND_SZ", "/d", &dll, "/f"])
        .stdout(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new("reg.exe")
        .args(["add", EVENTLOG_KEY, "/v", "TypesSupported", "/t", "REG_DWORD", "/d", "7", "/f"])
        .stdout(std::process::Stdio::null())
        .status();
}

fn uninstall(paths: &Paths, purge: bool) -> Result<i32> {
    if !rousseau_etw::process::is_elevated() {
        bail!("`rousseau uninstall` must run elevated");
    }
    match service::uninstall() {
        Ok(()) => println!("Service removed."),
        Err(e) => println!("Service not removed: {e:#}"),
    }
    let _ = std::process::Command::new("reg.exe")
        .args(["delete", EVENTLOG_KEY, "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if purge {
        std::fs::remove_dir_all(&paths.data).with_context(|| format!("cannot delete {}", paths.data.display()))?;
        println!("Deleted {}.", paths.data.display());
    }
    println!("MCP client configs are unchanged; run `rousseau unprotect` to restore them.");
    Ok(0)
}

/// Dashboard hooks when the sensor runs in the service.
struct UiControl {
    store: Arc<Store>,
    rule_dirs: Vec<PathBuf>,
    health: Arc<RwLock<Vec<SensorInfo>>>,
    handle: tokio::runtime::Handle,
}

impl Control for UiControl {
    fn rules(&self) -> Vec<Rule> {
        let mut rules = load_rules(&self.rule_dirs).unwrap_or_default();
        if let Ok(o) = self.store.rule_overrides() {
            for r in &mut rules {
                if let Some((en, mode)) = o.get(&r.id) {
                    if let Some(e) = en {
                        r.enabled = *e;
                    }
                    if mode.is_some() {
                        r.mode = *mode;
                    }
                }
            }
        }
        rules
    }
    fn reload(&self) {
        self.handle.spawn(async {
            if let Err(e) = pipe::reload().await {
                tracing::warn!(error = %e, "could not ask the sensor to reload");
            }
        });
    }
    fn health(&self) -> Vec<SensorInfo> {
        self.health.read().map(|h| h.clone()).unwrap_or_default()
    }
}

async fn ui(paths: &Paths, port: u16, no_browser: bool) -> Result<i32> {
    let store = Arc::new(
        Store::open(&paths.db())
            .with_context(|| format!("cannot open {} (is Rousseau installed? try `rousseau run`)", paths.db().display()))?,
    );
    let cfg = paths.load_config()?;
    let (live, _) = broadcast::channel(4_096);
    let health = Arc::new(RwLock::new(Vec::new()));
    if pipe::available().await {
        let tx = live.clone();
        tokio::spawn(async move {
            if let Err(e) = pipe::subscribe(tx).await {
                tracing::warn!(error = %e, "live stream ended");
            }
        });
        let h = Arc::clone(&health);
        tokio::spawn(async move {
            loop {
                if let Ok(v) = pipe::health().await
                    && let Ok(mut g) = h.write()
                {
                    *g = v;
                }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    } else {
        eprintln!(
            "warning: no sensor is running (start the service with `rousseau install` or use `rousseau run`); showing stored data only."
        );
        if let Ok(mut g) = health.write() {
            g.push(SensorInfo {
                sensor: "service".into(),
                status: "down".into(),
                message: "no sensor listening on the named pipe".into(),
                ..SensorInfo::default()
            });
        }
    }
    // Toasts for new incidents (the service cannot show them itself).
    if cfg.alerts.toast {
        notify::register_toast_app();
        let mut rx = live.subscribe();
        let floor = cfg.alerts.min_severity;
        tokio::spawn(async move {
            let mut seen = std::collections::HashSet::new();
            while let Ok(m) = rx.recv().await {
                if let LiveMessage::Incident { incident } = m
                    && incident.mode != ResponseMode::Observe
                    && incident.severity >= floor
                    && seen.insert(incident.id)
                {
                    let t = notify::Toast;
                    rousseau_server::alerts::LocalNotifier::notify(&t, &incident);
                }
            }
        });
    }
    let control = Arc::new(UiControl {
        store: Arc::clone(&store),
        rule_dirs: cfg.rule_dirs.clone(),
        health,
        handle: tokio::runtime::Handle::current(),
    });
    serve_dashboard(store, live, control, paths, false, port, no_browser).await?;
    println!("Press Ctrl+C to close the dashboard.");
    let _ = tokio::signal::ctrl_c().await;
    Ok(0)
}

/// Settings for an MCP proxy: the running host's policy when one is
/// listening (so `rousseau run --mode enforce --data-dir …` applies to proxies
/// the agent launches), otherwise the configuration file.
async fn proxy_parts(paths: &Paths, mode: Option<ResponseMode>) -> (rousseau_core::config::Config, Option<Arc<Store>>, Arc<dyn PinStore>) {
    let mut cfg = paths.load_config().unwrap_or_default();
    let mut db = paths.db();
    if let Some(p) = pipe::policy().await {
        cfg.response.mode = p.mode;
        cfg.response.block_findings_at = p.block_findings_at;
        cfg.pinning.strict = p.strict_pinning;
        db = Paths::resolve(Some(p.data_dir)).db();
    }
    if let Some(m) = mode {
        cfg.response.mode = m;
    }
    let store = Store::open(&db).map(Arc::new).map_err(|e| tracing::warn!(error = %e, "database unavailable; pins kept in memory")).ok();
    let pins: Arc<dyn PinStore> = match &store {
        Some(s) => s.clone(),
        None => Arc::new(MemoryPins::default()),
    };
    (cfg, store, pins)
}

async fn wrap(paths: &Paths, name: String, mode: Option<ResponseMode>, command: Vec<String>) -> Result<i32> {
    let (cfg, store, pins) = proxy_parts(paths, mode).await;
    let (sink, forwarder) = pipe::PipeSink::start(store);
    let (program, args) = command.split_first().map(|(p, a)| (p.clone(), a.to_vec())).context("missing server command after --")?;
    let observer = Arc::new(Observer::new(
        ObserverConfig {
            server: name,
            transport: "stdio".into(),
            mode: cfg.response.mode,
            block_findings_at: cfg.response.block_findings_at,
            proxy: rousseau_etw::process::current(),
            command: Some(command.join(" ")),
            upstream: None,
        },
        Pinner::new(pins, cfg.pinning.strict),
        Arc::new(sink),
    ));
    attach_classifier(&observer, &cfg, paths);
    let code = rousseau_mcp::stdio::run(
        rousseau_mcp::stdio::StdioOptions { program, args, parent: rousseau_etw::process::parent_of_current() },
        Arc::clone(&observer),
    )
    .await?;
    drop(observer);
    // Give the forwarder a moment to deliver the last events.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), forwarder).await;
    Ok(code)
}

async fn wrap_http(paths: &Paths, name: String, upstream: String, port: u16, mode: Option<ResponseMode>) -> Result<i32> {
    let (cfg, store, pins) = proxy_parts(paths, mode).await;
    let (sink, _forwarder) = pipe::PipeSink::start(store);
    let observer = Arc::new(Observer::new(
        ObserverConfig {
            server: name.clone(),
            transport: "http".into(),
            mode: cfg.response.mode,
            block_findings_at: cfg.response.block_findings_at,
            proxy: rousseau_etw::process::current(),
            command: None,
            upstream: Some(upstream.clone()),
        },
        Pinner::new(pins, cfg.pinning.strict),
        Arc::new(sink),
    ));
    attach_classifier(&observer, &cfg, paths);
    let opts = rousseau_mcp::http::HttpOptions { upstream, port };
    tokio::select! {
        r = rousseau_mcp::http::run(opts, observer, |url| eprintln!("rousseau: MCP server '{name}' proxied at {url}")) => r?,
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(0)
}

/// Loads the on-device classifier in the background when enabled (`ml`
/// builds only); the proxy starts immediately and gains the classifier
/// once the verified model is ready.
#[cfg(feature = "ml")]
fn attach_classifier(observer: &Arc<Observer>, cfg: &rousseau_core::config::Config, paths: &Paths) {
    if !cfg.classifier {
        return;
    }
    let observer = Arc::clone(observer);
    let dir = paths.data.join("models");
    tokio::spawn(async move {
        use rousseau_mcp::inspect::classifier::{Classifier, ensure_model};
        let loaded = match ensure_model(&dir).await {
            Ok((model, tok)) => tokio::task::spawn_blocking(move || Classifier::load(&model, &tok, 0.9)).await.ok(),
            Err(e) => Some(Err(e)),
        };
        match loaded {
            Some(Ok(c)) => observer.set_classifier(Arc::new(c)),
            Some(Err(e)) => tracing::warn!(error = %e, "prompt-injection classifier unavailable; heuristic inspectors only"),
            None => {}
        }
    });
}

#[cfg(not(feature = "ml"))]
fn attach_classifier(_observer: &Arc<Observer>, cfg: &rousseau_core::config::Config, _paths: &Paths) {
    if cfg.classifier {
        tracing::warn!("`classifier = true` but this build lacks the `ml` feature; heuristic inspectors only");
    }
}

fn manifest_path() -> PathBuf {
    user_state_dir().join("protect-manifest.json")
}

fn print_reports(reports: &[clients::FileReport]) {
    if reports.is_empty() {
        println!("No MCP client configuration files found.");
    }
    for r in reports {
        println!("\n{} — {}\n  {}", r.client, r.path.display(), r.status);
        if !r.servers.is_empty() {
            println!("  servers: {}", r.servers.join(", "));
        }
        if !r.already_wrapped.is_empty() {
            println!("  already wrapped: {}", r.already_wrapped.join(", "));
        }
        if !r.remote.is_empty() {
            println!("  remote (not rewritten; use `rousseau wrap-http`): {}", r.remote.join(", "));
        }
        for l in r.diff.lines() {
            println!("    {l}");
        }
    }
}

fn protect(projects: Vec<PathBuf>, dry_run: bool) -> Result<i32> {
    let projects = if projects.is_empty() { vec![std::env::current_dir()?] } else { projects };
    let installed = program_files_exe();
    let exe = if installed.is_file() { installed } else { current_exe()? };
    let res = Resolver::from_env(projects);
    let reports = clients::protect(&res, &exe.display().to_string(), &manifest_path(), dry_run, rousseau_core::time::now_ms())?;
    print_reports(&reports);
    if !dry_run && reports.iter().any(|r| r.status == "wrapped") {
        println!("\nRestart your agents/IDEs so they pick up the new configuration. Undo with `rousseau unprotect`.");
    }
    Ok(if reports.iter().any(|r| r.status.starts_with("error")) { 1 } else { 0 })
}

fn unprotect(dry_run: bool) -> Result<i32> {
    let reports = clients::unprotect(&manifest_path(), dry_run)?;
    if reports.is_empty() {
        println!("Nothing to restore.");
    }
    print_reports(&reports);
    Ok(if reports.iter().any(|r| r.status.starts_with("error")) { 1 } else { 0 })
}

async fn doctor(paths: &Paths) -> Result<i32> {
    let mut problems = 0;
    let mut line = |ok: Option<bool>, what: &str, detail: String| {
        let tag = match ok {
            Some(true) => "  ok  ",
            Some(false) => {
                problems += 1;
                " FAIL "
            }
            None => " info ",
        };
        println!("[{tag}] {what}: {detail}");
    };
    let elevated = rousseau_etw::process::is_elevated();
    line(None, "privileges", if elevated { "elevated".into() } else { "not elevated (ETW checks limited)".into() });
    line(
        None,
        "version",
        format!("{} (classifier feature: {})", rousseau_core::VERSION, if cfg!(feature = "ml") { "built" } else { "not built" }),
    );
    let cfg = match paths.load_config() {
        Ok(c) => {
            line(Some(true), "configuration", format!("{} (mode {})", paths.config().display(), c.response.mode.as_str()));
            c
        }
        Err(e) => {
            line(Some(false), "configuration", format!("{e:#}"));
            Default::default()
        }
    };
    match Store::open(&paths.db()) {
        Ok(s) => {
            let st = s.stats()?;
            line(
                Some(true),
                "database",
                format!(
                    "{} ({} events, {} sessions, {} open incidents, {} pins pending)",
                    paths.db().display(),
                    st.events,
                    st.sessions,
                    st.open_incidents,
                    st.pending_pins
                ),
            );
        }
        Err(e) => line(Some(false), "database", format!("{}: {e}", paths.db().display())),
    }
    match load_rules(&cfg.rule_dirs) {
        Ok(r) => line(Some(true), "rules", format!("{} loaded ({} enabled)", r.len(), r.iter().filter(|r| r.enabled).count())),
        Err(e) => line(Some(false), "rules", format!("{e:#}")),
    }
    match service::status() {
        Some(s) => line(Some(s == "Running"), "service", s),
        None => line(None, "service", "not installed (use `rousseau install`, or `rousseau run` in the foreground)".into()),
    }
    let pipe_up = pipe::available().await;
    line(
        Some(pipe_up || service::status().is_none()),
        "sensor pipe",
        if pipe_up { "listening".into() } else { "no sensor listening".into() },
    );
    if pipe_up {
        if let Some(p) = pipe::policy().await {
            line(None, "response mode", format!("{} (running sensor; data {})", p.mode.as_str(), p.data_dir.display()));
        }
        for h in pipe::health().await.unwrap_or_default() {
            line(
                Some(h.status == "ok"),
                &format!("sensor {}", h.sensor),
                format!("{} — {} (lost {}, dropped {})", h.status, h.message, h.events_lost, h.events_dropped),
            );
        }
    }
    match rousseau_etw::sensor::query_session(rousseau_etw::providers::SESSION_NAME) {
        // A session with no sensor attached is left over from a process that
        // was killed; with no consumer, ETW counts every event as lost.
        Some(_) if !pipe_up => line(
            None,
            "ETW session",
            "stale session from a previous run (no sensor attached); it is replaced when the sensor next starts".into(),
        ),
        Some(q) => line(
            Some(q.events_lost == 0 && q.buffers_lost == 0),
            "ETW session",
            format!("running; {} events lost, {} buffers lost", q.events_lost, q.buffers_lost),
        ),
        None => line(None, "ETW session", "not running".into()),
    }
    let agents = load_agents(&cfg.agent_files)?;
    let running: Vec<String> = rousseau_etw::process::snapshot(&|_| false)
        .into_iter()
        .filter_map(|p| agents.match_agent(&p).map(|a| format!("{a} (pid {})", p.pid)))
        .collect();
    line(None, "agents running", if running.is_empty() { "none".into() } else { running.join(", ") });
    let res = Resolver::from_env(vec![std::env::current_dir()?]);
    for f in clients::discover(&res)? {
        let text = std::fs::read_to_string(&f.path).unwrap_or_default();
        match clients::list_servers(&text, f.format, &f.servers, &f.path.display().to_string()) {
            Ok(s) => {
                let stdio: Vec<_> = s.iter().filter(|e| e.transport == "stdio").collect();
                let wrapped = stdio.iter().filter(|e| e.wrapped).count();
                line(
                    Some(wrapped == stdio.len()),
                    &format!("MCP config {}", f.client),
                    format!("{} — {wrapped}/{} stdio servers wrapped, {} remote", f.path.display(), stdio.len(), s.len() - stdio.len()),
                );
            }
            Err(e) => line(Some(false), &format!("MCP config {}", f.client), format!("{e}")),
        }
    }
    let home = cfg.user_profile.clone().or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from)).unwrap_or_default();
    for (name, on) in [("claude-code", cfg.transcripts.claude_code), ("codex", cfg.transcripts.codex)] {
        let roots = rousseau_adapters::transcripts::adapter_by_name(name).map(|a| a.roots(&home)).unwrap_or_default();
        let exists = roots.iter().any(|r| r.is_dir());
        line(
            None,
            &format!("transcripts {name}"),
            format!(
                "{} ({}: {})",
                if on { "enabled" } else { "disabled (opt-in)" },
                roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", "),
                if exists { "found" } else { "not found" }
            ),
        );
    }
    println!("\n{}", if problems == 0 { "No problems found." } else { "Problems found; see FAIL lines above." });
    Ok(if problems == 0 { 0 } else { 1 })
}

fn export(paths: &Paths, session: &str, output: &Path) -> Result<i32> {
    let store = Store::open(&paths.db())?;
    let id = if session == "latest" {
        store.sessions(1)?.into_iter().next().map(|s| s.id).context("no sessions recorded yet")?
    } else {
        session.to_string()
    };
    let m = bundle::export_session(&store, &id, output)?;
    println!("Exported session {id}: {} events, {} incidents → {}", m.event_count, m.incidents.len(), output.display());
    Ok(0)
}

/// Read-only hooks for replayed bundles.
struct ReplayControl {
    rules: Vec<Rule>,
}

impl Control for ReplayControl {
    fn rules(&self) -> Vec<Rule> {
        self.rules.clone()
    }
    fn reload(&self) {}
    fn health(&self) -> Vec<SensorInfo> {
        vec![SensorInfo {
            sensor: "replay".into(),
            status: "ok".into(),
            message: "showing a recorded bundle".into(),
            ..SensorInfo::default()
        }]
    }
}

async fn replay(path: &Path, port: u16, no_browser: bool) -> Result<i32> {
    let (manifest, events) = bundle::read_bundle(path).with_context(|| format!("cannot read {}", path.display()))?;
    let store = Arc::new(Store::open_in_memory()?);
    bundle::import_into(&store, &manifest, &events)?;
    let dir = std::env::temp_dir().join(format!("rousseau-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let paths = Paths::resolve(Some(dir));
    println!(
        "Replaying {} ({} events, {} incidents, produced by {}).",
        path.display(),
        events.len(),
        manifest.incidents.len(),
        manifest.producer
    );
    let (live, _) = broadcast::channel(16);
    let control = Arc::new(ReplayControl { rules: load_rules(&[]).unwrap_or_default() });
    serve_dashboard(store, live, control, &paths, true, port, no_browser).await?;
    println!("Press Ctrl+C to stop.");
    let _ = tokio::signal::ctrl_c().await;
    Ok(0)
}

fn rules(paths: &Paths, action: RulesAction) -> Result<i32> {
    match action {
        RulesAction::List => {
            let cfg = paths.load_config().unwrap_or_default();
            for r in load_rules(&cfg.rule_dirs)? {
                println!(
                    "{:<9} {:<8} {:<10} {:<9} {}",
                    r.id,
                    r.severity.as_str(),
                    r.meta().detection_type,
                    if r.enabled { "enabled" } else { "disabled" },
                    r.title
                );
            }
            Ok(0)
        }
        RulesAction::Validate { paths: files } => {
            let mut bad = 0;
            for p in files {
                let result = if p.is_dir() {
                    rousseau_core::rules::load_dir(&p).map(|r| r.len())
                } else {
                    std::fs::read_to_string(&p)
                        .map_err(|e| rousseau_core::rules::RuleError::Io { path: p.display().to_string(), source: e })
                        .and_then(|t| rousseau_core::rules::parse_multi(&t, &p.display().to_string()).map(|r| r.len()))
                };
                match result {
                    Ok(n) => println!("ok    {} ({n} rule(s))", p.display()),
                    Err(e) => {
                        bad += 1;
                        println!("FAIL  {}: {e}", p.display());
                    }
                }
            }
            Ok(if bad == 0 { 0 } else { 1 })
        }
    }
}

fn agents(paths: &Paths) -> Result<i32> {
    let cfg = paths.load_config().unwrap_or_default();
    let table = load_agents(&cfg.agent_files)?;
    let mut n = 0;
    for mut p in rousseau_etw::process::snapshot(&|_| false) {
        if let Some(a) = table.find(&p) {
            n += 1;
            p.signer = p.image.as_deref().and_then(rousseau_etw::process::signer);
            println!(
                "{:<16} pid {:<7} {}{}",
                a.id,
                p.pid,
                p.image.unwrap_or_default(),
                p.signer.map(|s| format!("  [signed: {s}]")).unwrap_or_default()
            );
        }
    }
    if n == 0 {
        println!("No known agents running.");
    }
    Ok(0)
}
