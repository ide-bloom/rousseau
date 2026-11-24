//! The real-time ETW sensor.
//!
//! One user-mode session (`Rousseau-Sensor`) enables the five kernel
//! providers. Process start/stop events are always forwarded (the pipeline
//! needs them to maintain the process tree); every other event is dropped
//! in the callback unless its process is in the shared tracked-PID set, so
//! the cost of untracked activity is a hash lookup.
//!
//! Callbacks never block: events go to the pipeline through a bounded
//! channel ([`rousseau_core::ChannelSink`]) and are counted as dropped if it
//! is full. Lost ETW buffers are reported by [`Sensor::health`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ferrisetw::native::time::FileTime;
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::Provider;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use ferrisetw::{EventRecord, SchemaLocator};
use rousseau_core::EventSink;
use rousseau_core::event::{
    DnsInfo, Event, EventKind, FileInfo, NetInfo, ProcessInfo, RegistryInfo, SensorInfo, dns_info, extension_lower, file_name_lower,
    ip_scope,
};
use rousseau_core::paths::{DeviceMap, normalize_registry};
use rousseau_core::pipeline::TrackedPids;
use rousseau_core::time::filetime_to_ms;

use crate::decode::{ip_from_bytes, is_security_relevant_key, join_registry, port_from_bytes, registry_data};
use crate::process;
use crate::providers::{SESSION_NAME, dns_client, kernel_file, kernel_network, kernel_process, kernel_registry};

/// Sensor errors.
#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("ETW sessions require an elevated (administrator) process")]
    NotElevated,
    #[error("failed to start ETW session: {0}")]
    Start(String),
}

/// Which providers to enable.
#[derive(Debug, Clone)]
pub struct SensorOptions {
    pub file: bool,
    pub network: bool,
    pub dns: bool,
    pub registry: bool,
    pub image_loads: bool,
}

impl Default for SensorOptions {
    fn default() -> Self {
        Self { file: true, network: true, dns: true, registry: true, image_loads: true }
    }
}

/// Counters exposed for health and performance measurement.
#[derive(Debug, Default)]
pub struct Stats {
    pub received: AtomicU64,
    pub forwarded: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped: AtomicU64,
    pub parse_errors: AtomicU64,
}

#[derive(Debug, Clone)]
struct FileObj {
    path: String,
    read: bool,
    written: bool,
}

#[derive(Debug, Clone)]
struct Conn {
    remote: (String, u16),
    sent: u64,
    recv: u64,
}

const MAX_MAP: usize = 200_000;

struct Shared {
    sink: Arc<dyn EventSink>,
    tracked: TrackedPids,
    devices: RwLock<DeviceMap>,
    /// Lower-case exe names of possible agent roots (get command lines,
    /// working directories and signers).
    interesting: HashSet<String>,
    files: Mutex<HashMap<usize, FileObj>>,
    conns: Mutex<HashMap<(u32, u32), Conn>>,
    udp_seen: Mutex<HashSet<(u32, String, u16)>>,
    keys: Mutex<HashMap<usize, String>>,
    stats: Arc<Stats>,
}

impl Shared {
    fn is_tracked(&self, pid: u32) -> bool {
        self.tracked.read().map(|s| s.contains(&pid)).unwrap_or(false)
    }

    fn emit(&self, e: Event) {
        if self.sink.emit(e) {
            self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn normalize(&self, p: &str) -> String {
        self.devices.read().map(|m| m.normalize(p)).unwrap_or_else(|_| p.to_string())
    }

    fn proc_event(&self, kind: EventKind, rec: &EventRecord, pid: u32) -> Event {
        let mut e = Event::new(kind, filetime_to_ms(rec.raw_timestamp()));
        e.process = Some(ProcessInfo { pid, ..ProcessInfo::default() });
        e
    }
}

fn parser_for(rec: &EventRecord, loc: &SchemaLocator, stats: &Stats) -> Option<Arc<ferrisetw::schema::Schema>> {
    stats.received.fetch_add(1, Ordering::Relaxed);
    match loc.event_schema(rec) {
        Ok(s) => Some(s),
        Err(_) => {
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// A running sensor. Dropping it stops the ETW session.
pub struct Sensor {
    trace: Option<UserTrace>,
    shared: Arc<Shared>,
}

impl Sensor {
    /// Starts the ETW session. `interesting` are lower-case exe names of
    /// candidate agent roots (from the agent table).
    pub fn start(
        opts: &SensorOptions,
        sink: Arc<dyn EventSink>,
        tracked: TrackedPids,
        interesting: HashSet<String>,
    ) -> Result<Self, SensorError> {
        if !process::is_elevated() {
            return Err(SensorError::NotElevated);
        }
        // A session left behind by a crashed instance would make start fail.
        let _ = stop_trace_by_name(SESSION_NAME);
        let shared = Arc::new(Shared {
            sink,
            tracked,
            devices: RwLock::new(process::device_map()),
            interesting,
            files: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            udp_seen: Mutex::new(HashSet::new()),
            keys: Mutex::new(HashMap::new()),
            stats: Arc::new(Stats::default()),
        });

        let sh = Arc::clone(&shared);
        let mut proc_kw = kernel_process::KEYWORD_PROCESS;
        if opts.image_loads {
            proc_kw |= kernel_process::KEYWORD_IMAGE;
        }
        let mut builder = UserTrace::new().named(SESSION_NAME.to_string()).enable(
            Provider::by_guid(kernel_process::GUID)
                .any(proc_kw)
                .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_process(&sh, r, l))
                .build(),
        );
        if opts.file {
            let sh = Arc::clone(&shared);
            let kw = kernel_file::KEYWORD_FILENAME
                | kernel_file::KEYWORD_FILEIO
                | kernel_file::KEYWORD_CREATE
                | kernel_file::KEYWORD_READ
                | kernel_file::KEYWORD_WRITE
                | kernel_file::KEYWORD_DELETE_PATH
                | kernel_file::KEYWORD_RENAME_SETLINK_PATH
                | kernel_file::KEYWORD_CREATE_NEW_FILE;
            builder = builder.enable(
                Provider::by_guid(kernel_file::GUID)
                    .any(kw)
                    .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_file(&sh, r, l))
                    .build(),
            );
        }
        if opts.network {
            let sh = Arc::clone(&shared);
            let kw = kernel_network::KEYWORD_IPV4 | kernel_network::KEYWORD_IPV6;
            builder = builder.enable(
                Provider::by_guid(kernel_network::GUID)
                    .any(kw)
                    .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_network(&sh, r, l))
                    .build(),
            );
        }
        if opts.dns {
            let sh = Arc::clone(&shared);
            builder = builder.enable(
                Provider::by_guid(dns_client::GUID).add_callback(move |r: &EventRecord, l: &SchemaLocator| on_dns(&sh, r, l)).build(),
            );
        }
        if opts.registry {
            let sh = Arc::clone(&shared);
            let kw = kernel_registry::KEYWORD_SET_VALUE_KEY
                | kernel_registry::KEYWORD_DELETE_VALUE_KEY
                | kernel_registry::KEYWORD_CREATE_KEY
                | kernel_registry::KEYWORD_OPEN_KEY;
            builder = builder.enable(
                Provider::by_guid(kernel_registry::GUID)
                    .any(kw)
                    .add_callback(move |r: &EventRecord, l: &SchemaLocator| on_registry(&sh, r, l))
                    .build(),
            );
        }
        let trace = builder.start_and_process().map_err(|e| SensorError::Start(format!("{e:?}")))?;
        Ok(Self { trace: Some(trace), shared })
    }

    /// Counters.
    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.shared.stats)
    }

    /// Re-reads drive mappings (new volumes, mapped network drives).
    pub fn refresh_devices(&self) {
        if let Ok(mut m) = self.shared.devices.write() {
            *m = process::device_map();
        }
    }

    /// Health report including ETW-side lost events.
    pub fn health(&self) -> SensorInfo {
        let s = &self.shared.stats;
        let q = query_session(SESSION_NAME);
        let dropped = s.dropped.load(Ordering::Relaxed);
        let (status, message) = match &q {
            None => ("down".to_string(), "ETW session not found".to_string()),
            Some(q) if q.events_lost > 0 || q.buffers_lost > 0 || dropped > 0 => (
                "degraded".into(),
                format!(
                    "{} events and {} real-time buffers lost by ETW; {dropped} dropped by Rousseau (pipeline busy)",
                    q.events_lost, q.buffers_lost
                ),
            ),
            Some(_) => (
                "ok".into(),
                format!("{} events received, {} forwarded", s.received.load(Ordering::Relaxed), s.forwarded.load(Ordering::Relaxed)),
            ),
        };
        SensorInfo {
            sensor: "etw".into(),
            status,
            message,
            events_lost: q.map(|q| u64::from(q.events_lost) + u64::from(q.buffers_lost)).unwrap_or(0),
            events_dropped: dropped,
        }
    }

    /// Stops the session.
    pub fn stop(mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

fn on_process(sh: &Shared, rec: &EventRecord, loc: &SchemaLocator) {
    let Some(schema) = parser_for(rec, loc, &sh.stats) else { return };
    let p = Parser::create(rec, &schema);
    match rec.event_id() {
        kernel_process::EVENT_PROCESS_START => {
            let Ok(pid) = p.try_parse::<u32>("ProcessID") else { return };
            let ppid = p.try_parse::<u32>("ParentProcessID").ok();
            let created = p.try_parse::<FileTime>("CreateTime").ok().map(|f| f.as_unix_timestamp());
            let image = p.try_parse::<String>("ImageName").ok().map(|i| sh.normalize(&i));
            let name = image.as_deref().map(file_name_lower);
            let parent_tracked = ppid.is_some_and(|pp| sh.is_tracked(pp));
            if parent_tracked {
                // A descendant of a tracked process is tracked: insert now so
                // its first file or network events are not filtered out
                // before the pipeline catches up.
                if let Ok(mut t) = sh.tracked.write() {
                    t.insert(pid);
                }
            }
            let candidate = name.as_deref().is_some_and(|n| sh.interesting.contains(n));
            let mut info = ProcessInfo { pid, ppid, image: image.clone(), name, start_time: created, ..ProcessInfo::default() };
            if candidate || parent_tracked {
                info.command_line = process::command_line(pid);
            }
            if candidate {
                info.cwd = process::cwd(pid);
                info.signer = image.as_deref().and_then(process::signer);
            }
            let mut e = sh.proc_event(EventKind::ProcessStart, rec, pid);
            e.process = Some(info);
            sh.emit(e);
        }
        kernel_process::EVENT_PROCESS_STOP => {
            let Ok(pid) = p.try_parse::<u32>("ProcessID") else { return };
            let mut e = sh.proc_event(EventKind::ProcessStop, rec, pid);
            if let Some(pi) = &mut e.process {
                pi.exit_code = p.try_parse::<u32>("ExitCode").ok();
            }
            sh.emit(e);
        }
        kernel_process::EVENT_IMAGE_LOAD => {
            let Ok(pid) = p.try_parse::<u32>("ProcessID") else { return };
            if !sh.is_tracked(pid) {
                sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let Ok(image) = p.try_parse::<String>("ImageName") else { return };
            let path = sh.normalize(&image);
            let mut e = sh.proc_event(EventKind::ImageLoad, rec, pid);
            e.file = Some(FileInfo { ext: extension_lower(&path), path, ..FileInfo::default() });
            sh.emit(e);
        }
        _ => {}
    }
}

fn on_file(sh: &Shared, rec: &EventRecord, loc: &SchemaLocator) {
    let pid = rec.process_id();
    if !sh.is_tracked(pid) {
        sh.stats.received.fetch_add(1, Ordering::Relaxed);
        sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(schema) = parser_for(rec, loc, &sh.stats) else { return };
    let p = Parser::create(rec, &schema);
    let fo = p.try_parse::<Pointer>("FileObject").map(|x| *x).unwrap_or(0);
    let file_event = |kind: EventKind, path: String, new_path: Option<String>| {
        let mut e = sh.proc_event(kind, rec, pid);
        e.file = Some(FileInfo { ext: extension_lower(new_path.as_deref().unwrap_or(&path)), path, new_path, size: None });
        sh.emit(e);
    };
    match rec.event_id() {
        kernel_file::EVENT_CREATE | kernel_file::EVENT_CREATE_NEW_FILE => {
            let Ok(name) = p.try_parse::<String>("FileName") else { return };
            let path = sh.normalize(&name);
            if let Ok(mut m) = sh.files.lock() {
                if m.len() > MAX_MAP {
                    m.clear();
                }
                m.insert(fo, FileObj { path: path.clone(), read: false, written: false });
            }
            if rec.event_id() == kernel_file::EVENT_CREATE_NEW_FILE {
                file_event(EventKind::FileCreate, path, None);
            }
        }
        kernel_file::EVENT_READ | kernel_file::EVENT_WRITE => {
            let is_read = rec.event_id() == kernel_file::EVENT_READ;
            // Only the first read/write per open file object is reported.
            let path = sh.files.lock().ok().and_then(|mut m| {
                let f = m.get_mut(&fo)?;
                let first = if is_read { !std::mem::replace(&mut f.read, true) } else { !std::mem::replace(&mut f.written, true) };
                first.then(|| f.path.clone())
            });
            if let Some(path) = path {
                file_event(if is_read { EventKind::FileRead } else { EventKind::FileWrite }, path, None);
            }
        }
        kernel_file::EVENT_CLOSE => {
            if let Ok(mut m) = sh.files.lock() {
                m.remove(&fo);
            }
        }
        kernel_file::EVENT_DELETE_PATH => {
            if let Ok(path) = p.try_parse::<String>("FilePath") {
                file_event(EventKind::FileDelete, sh.normalize(&path), None);
            }
        }
        kernel_file::EVENT_RENAME_PATH => {
            let new = p.try_parse::<String>("FilePath").ok().map(|x| sh.normalize(&x));
            let old = sh.files.lock().ok().and_then(|m| m.get(&fo).map(|f| f.path.clone()));
            match (old, new) {
                (Some(o), Some(n)) if o != n => file_event(EventKind::FileRename, o, Some(n)),
                (Some(o), _) => file_event(EventKind::FileRename, o, None),
                (None, Some(n)) => file_event(EventKind::FileRename, n, None),
                (None, None) => {}
            }
        }
        _ => {}
    }
}

fn on_network(sh: &Shared, rec: &EventRecord, loc: &SchemaLocator) {
    let Some(schema) = parser_for(rec, loc, &sh.stats) else { return };
    let p = Parser::create(rec, &schema);
    let Ok(pid) = p.try_parse::<u32>("PID") else { return };
    if !sh.is_tracked(pid) {
        sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let bytes = |name: &str| p.try_parse::<Vec<u8>>(name).ok();
    let remote = || -> Option<(String, u16, Option<String>, Option<u16>)> {
        let d = ip_from_bytes(&bytes("daddr")?)?;
        let dp = port_from_bytes(&bytes("dport")?)?;
        let s = bytes("saddr").and_then(|b| ip_from_bytes(&b)).map(|a| a.to_string());
        let sp = bytes("sport").and_then(|b| port_from_bytes(&b));
        Some((d.to_string(), dp, s, sp))
    };
    let connid = p.try_parse::<u32>("connid").unwrap_or(0);
    let size = u64::from(p.try_parse::<u32>("size").unwrap_or(0));
    let net_event = |kind: EventKind,
                     protocol: &str,
                     direction: &str,
                     addr: String,
                     port: u16,
                     local: Option<String>,
                     lport: Option<u16>,
                     sent: Option<u64>,
                     recv: Option<u64>| {
        let mut e = sh.proc_event(kind, rec, pid);
        e.net = Some(NetInfo {
            protocol: protocol.into(),
            direction: direction.into(),
            remote_scope: ip_scope(&addr).into(),
            remote: if addr.contains(':') { format!("[{addr}]:{port}") } else { format!("{addr}:{port}") },
            remote_addr: addr,
            remote_port: port,
            local_addr: local,
            local_port: lport,
            bytes_sent: sent,
            bytes_recv: recv,
        });
        sh.emit(e);
    };
    use kernel_network::*;
    match rec.event_id() {
        TCP4_CONNECT | TCP6_CONNECT | TCP4_ACCEPT | TCP6_ACCEPT => {
            let Some((addr, port, local, lport)) = remote() else { return };
            if let Ok(mut c) = sh.conns.lock() {
                if c.len() > MAX_MAP {
                    c.clear();
                }
                c.insert((pid, connid), Conn { remote: (addr.clone(), port), sent: 0, recv: 0 });
            }
            let inbound = matches!(rec.event_id(), TCP4_ACCEPT | TCP6_ACCEPT);
            net_event(
                if inbound { EventKind::NetAccept } else { EventKind::NetConnect },
                "tcp",
                if inbound { "inbound" } else { "outbound" },
                addr,
                port,
                local,
                lport,
                None,
                None,
            );
        }
        TCP4_SEND | TCP6_SEND | TCP4_RECV | TCP6_RECV => {
            if let Ok(mut c) = sh.conns.lock()
                && let Some(conn) = c.get_mut(&(pid, connid))
            {
                if matches!(rec.event_id(), TCP4_SEND | TCP6_SEND) {
                    conn.sent += size;
                } else {
                    conn.recv += size;
                }
            }
        }
        TCP4_DISCONNECT | TCP6_DISCONNECT => {
            let conn = sh.conns.lock().ok().and_then(|mut c| c.remove(&(pid, connid)));
            if let Some(conn) = conn {
                net_event(
                    EventKind::NetClose,
                    "tcp",
                    "outbound",
                    conn.remote.0,
                    conn.remote.1,
                    None,
                    None,
                    Some(conn.sent),
                    Some(conn.recv),
                );
            }
        }
        UDP4_SEND | UDP6_SEND => {
            let Some((addr, port, local, lport)) = remote() else { return };
            let first = sh.udp_seen.lock().map(|mut s| {
                if s.len() > MAX_MAP {
                    s.clear();
                }
                s.insert((pid, addr.clone(), port))
            });
            if first.unwrap_or(false) {
                net_event(EventKind::NetConnect, "udp", "outbound", addr, port, local, lport, Some(size), None);
            }
        }
        _ => {}
    }
}

fn on_dns(sh: &Shared, rec: &EventRecord, loc: &SchemaLocator) {
    if rec.event_id() != dns_client::EVENT_QUERY {
        return;
    }
    let pid = rec.process_id();
    if !sh.is_tracked(pid) {
        sh.stats.received.fetch_add(1, Ordering::Relaxed);
        sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(schema) = parser_for(rec, loc, &sh.stats) else { return };
    let p = Parser::create(rec, &schema);
    let Ok(name) = p.try_parse::<String>("QueryName") else { return };
    let mut info: DnsInfo = dns_info(&name);
    info.query_type = p.try_parse::<u32>("QueryType").ok();
    let mut e = sh.proc_event(EventKind::DnsQuery, rec, pid);
    e.dns = Some(info);
    sh.emit(e);
}

fn on_registry(sh: &Shared, rec: &EventRecord, loc: &SchemaLocator) {
    let pid = rec.process_id();
    if !sh.is_tracked(pid) {
        sh.stats.received.fetch_add(1, Ordering::Relaxed);
        sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(schema) = parser_for(rec, loc, &sh.stats) else { return };
    let p = Parser::create(rec, &schema);
    let status = p.try_parse::<u32>("Status").unwrap_or(0);
    if status != 0 {
        return;
    }
    let key_obj = p.try_parse::<Pointer>("KeyObject").map(|x| *x).unwrap_or(0);
    match rec.event_id() {
        kernel_registry::EVENT_CREATE_KEY | kernel_registry::EVENT_OPEN_KEY => {
            let base_obj = p.try_parse::<Pointer>("BaseObject").map(|x| *x).unwrap_or(0);
            let base_name = p.try_parse::<String>("BaseName").unwrap_or_default();
            let rel = p.try_parse::<String>("RelativeName").unwrap_or_default();
            if let Ok(mut m) = sh.keys.lock() {
                let base = if base_name.is_empty() { m.get(&base_obj).cloned().unwrap_or_default() } else { base_name };
                if m.len() > MAX_MAP {
                    m.clear();
                }
                m.insert(key_obj, join_registry(&base, &rel));
            }
        }
        kernel_registry::EVENT_SET_VALUE_KEY | kernel_registry::EVENT_DELETE_VALUE_KEY => {
            let key_name = p.try_parse::<String>("KeyName").unwrap_or_default();
            let raw = if key_name.to_ascii_uppercase().starts_with(r"\REGISTRY") {
                key_name
            } else {
                sh.keys.lock().ok().and_then(|m| m.get(&key_obj).cloned()).unwrap_or(key_name)
            };
            let key = normalize_registry(&raw);
            if !is_security_relevant_key(&key) {
                sh.stats.filtered.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let value = p.try_parse::<String>("ValueName").ok();
            let set = rec.event_id() == kernel_registry::EVENT_SET_VALUE_KEY;
            let (data, data_type) = if set {
                let ty = p.try_parse::<u32>("Type").unwrap_or(0);
                let d = p.try_parse::<Vec<u8>>("CapturedData").unwrap_or_default();
                (Some(registry_data(ty, &d)), Some(ty))
            } else {
                (None, None)
            };
            let mut e = sh.proc_event(if set { EventKind::RegistrySet } else { EventKind::RegistryDelete }, rec, pid);
            e.registry = Some(RegistryInfo { key, value, data, data_type });
            sh.emit(e);
        }
        _ => {}
    }
}

/// Stops Rousseau's ETW session by name. Used on shutdown paths that exit
/// the process without running destructors.
pub fn stop_session() {
    let _ = stop_trace_by_name(SESSION_NAME);
}

/// Result of an `EVENT_TRACE_CONTROL_QUERY`.
#[derive(Debug, Clone, Copy)]
pub struct SessionQuery {
    pub events_lost: u32,
    pub buffers_lost: u32,
    pub buffers_written: u32,
}

/// Queries a running session by name (lost-event counters).
pub fn query_session(name: &str) -> Option<SessionQuery> {
    use windows::Win32::System::Diagnostics::Etw::{CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES};
    let header = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = header + 2 * 1024 * 2;
    // u64 storage keeps EVENT_TRACE_PROPERTIES correctly aligned.
    let mut buf = vec![0u64; total.div_ceil(8)];
    let props = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `buf` holds a zeroed EVENT_TRACE_PROPERTIES followed by room
    // for the logger and log file names, as ControlTraceW requires; offsets
    // point inside the buffer and BufferSize states its full length.
    unsafe {
        (*props).Wnode.BufferSize = (buf.len() * 8) as u32;
        (*props).LoggerNameOffset = header as u32;
        (*props).LogFileNameOffset = (header + 2048) as u32;
        let rc = ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, windows::core::PCWSTR(wname.as_ptr()), props, EVENT_TRACE_CONTROL_QUERY);
        if rc.0 != 0 {
            return None;
        }
        Some(SessionQuery {
            events_lost: (*props).EventsLost,
            buffers_lost: (*props).RealTimeBuffersLost,
            buffers_written: (*props).BuffersWritten,
        })
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration {
    use super::*;
    use rousseau_core::ChannelSink;

    /// Starts the real session, spawns a child of this (tracked) process
    /// that reads a file and checks that start, read and stop arrive.
    #[test]
    fn sensor_sees_tracked_child() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100_000);
        let tracked: TrackedPids = Arc::default();
        tracked.write().unwrap().insert(std::process::id());
        let sensor =
            Sensor::start(&SensorOptions::default(), Arc::new(ChannelSink::new(tx)), tracked, HashSet::new()).expect("run elevated");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let dir = std::env::temp_dir().join(format!("rousseau-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("probe.txt");
        std::fs::write(&f, "x").unwrap();
        let status = std::process::Command::new("cmd.exe").args(["/c", "type", &f.display().to_string()]).status().unwrap();
        assert!(status.success());
        std::thread::sleep(std::time::Duration::from_secs(3));
        let health = sensor.health();
        sensor.stop();
        let mut kinds = Vec::new();
        let mut saw_read = false;
        while let Ok(e) = rx.try_recv() {
            if e.kind == EventKind::FileRead && e.file.as_ref().is_some_and(|x| x.path.to_lowercase().ends_with("probe.txt")) {
                saw_read = true;
            }
            kinds.push(e.kind);
        }
        assert!(kinds.contains(&EventKind::ProcessStart), "{kinds:?}");
        assert!(saw_read, "probe.txt read by cmd.exe not observed");
        assert_ne!(health.status, "down");
    }
}
