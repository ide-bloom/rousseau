//! Portable `.rousseau` bundles (see `docs/bundle-format.md`).
//!
//! A bundle is a single zstd frame containing UTF-8 JSON Lines. The first
//! line is the [`Manifest`]; every following line is one [`Event`] in id
//! order. Readers must reject unknown `format` values and schema versions
//! newer than they understand.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::event::{Event, SessionInfo};
use crate::incident::Incident;
use crate::storage::{EventQuery, ServerRecord, Store, StoreError, ToolPin};

/// Value of `manifest.format`.
pub const BUNDLE_FORMAT: &str = "rousseau-bundle";
/// Current bundle schema version.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
/// zstd compression level used for exports.
const ZSTD_LEVEL: i32 = 9;

/// Bundle errors.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error on line {line}: {source}")]
    Json {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("not a Rousseau bundle (format = {0:?})")]
    Format(String),
    #[error("bundle schema version {0} is newer than supported version {BUNDLE_SCHEMA_VERSION}")]
    Version(u32),
    #[error("bundle is empty")]
    Empty,
    #[error("unknown session {0}")]
    UnknownSession(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// First line of a bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub schema_version: u32,
    pub rousseau_version: String,
    /// Unix ms when the bundle was written.
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    pub event_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_ts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ts: Option<i64>,
    #[serde(default)]
    pub incidents: Vec<Incident>,
    #[serde(default)]
    pub servers: Vec<ServerRecord>,
    #[serde(default)]
    pub pins: Vec<ToolPin>,
    /// Free-form producer note (e.g. `rousseau export`, `rousseau-lab synth`).
    #[serde(default)]
    pub producer: String,
}

impl Manifest {
    /// A manifest describing `events`.
    pub fn for_events(events: &[Event], producer: &str) -> Self {
        Self {
            format: BUNDLE_FORMAT.into(),
            schema_version: BUNDLE_SCHEMA_VERSION,
            rousseau_version: crate::VERSION.into(),
            created: crate::time::now_ms(),
            session: None,
            event_count: events.len() as u64,
            first_ts: events.iter().map(|e| e.ts).min(),
            last_ts: events.iter().map(|e| e.ts).max(),
            incidents: Vec::new(),
            servers: Vec::new(),
            pins: Vec::new(),
            producer: producer.into(),
        }
    }
}

/// Writes a bundle to any writer.
pub fn write_to(w: impl Write, manifest: &Manifest, events: &[Event]) -> Result<(), BundleError> {
    let mut enc = zstd::stream::Encoder::new(w, ZSTD_LEVEL)?;
    serde_json::to_writer(&mut enc, manifest).map_err(|e| BundleError::Json { line: 1, source: e })?;
    enc.write_all(b"\n")?;
    for (i, e) in events.iter().enumerate() {
        serde_json::to_writer(&mut enc, e).map_err(|err| BundleError::Json { line: i + 2, source: err })?;
        enc.write_all(b"\n")?;
    }
    enc.finish()?.flush()?;
    Ok(())
}

/// Writes a bundle file.
pub fn write_bundle(path: &Path, manifest: &Manifest, events: &[Event]) -> Result<(), BundleError> {
    let f = std::fs::File::create(path)?;
    write_to(std::io::BufWriter::new(f), manifest, events)
}

/// Reads a bundle from any reader.
pub fn read_from(r: impl Read) -> Result<(Manifest, Vec<Event>), BundleError> {
    let dec = zstd::stream::Decoder::new(r)?;
    let mut lines = BufReader::new(dec).lines();
    let first = lines.next().ok_or(BundleError::Empty)??;
    let raw: serde_json::Value = serde_json::from_str(&first).map_err(|e| BundleError::Json { line: 1, source: e })?;
    let format = raw.get("format").and_then(|v| v.as_str()).unwrap_or_default();
    if format != BUNDLE_FORMAT {
        return Err(BundleError::Format(format.to_string()));
    }
    let version = raw.get("schema_version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    if version > BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::Version(version));
    }
    let manifest: Manifest = serde_json::from_value(raw).map_err(|e| BundleError::Json { line: 1, source: e })?;
    let mut events = Vec::new();
    for (i, line) in lines.enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line).map_err(|e| BundleError::Json { line: i + 2, source: e })?);
    }
    Ok((manifest, events))
}

/// Reads a bundle file.
pub fn read_bundle(path: &Path) -> Result<(Manifest, Vec<Event>), BundleError> {
    read_from(BufReader::new(std::fs::File::open(path)?))
}

/// Collects one session (events, incidents, involved servers and pins) from
/// the store and writes it to `path`.
pub fn export_session(store: &Store, session_id: &str, path: &Path) -> Result<Manifest, BundleError> {
    let session = store.session(session_id)?.ok_or_else(|| BundleError::UnknownSession(session_id.to_string()))?;
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let page = store.query_events(&EventQuery {
            session: Some(session_id.to_string()),
            after_id: Some(after),
            ascending: true,
            limit: Some(10_000),
            ..EventQuery::default()
        })?;
        let Some(last) = page.last() else { break };
        after = last.id;
        events.extend(page);
    }
    let incidents = store.incidents(10_000, Some(session_id))?;
    let mut server_names: Vec<String> = events.iter().filter_map(|e| e.server().map(str::to_string)).collect();
    server_names.sort();
    server_names.dedup();
    let servers = store.servers()?.into_iter().filter(|s| server_names.contains(&s.name)).collect();
    let pins = store.pins(None)?.into_iter().filter(|p| server_names.contains(&p.server)).collect();
    let mut manifest = Manifest::for_events(&events, "rousseau export");
    manifest.session = Some(session);
    manifest.incidents = incidents;
    manifest.servers = servers;
    manifest.pins = pins;
    write_bundle(path, &manifest, &events)?;
    Ok(manifest)
}

/// Loads a bundle into a (normally empty) store, keeping original ids.
pub fn import_into(store: &Store, manifest: &Manifest, events: &[Event]) -> Result<(), BundleError> {
    store.batch(|b| {
        if let Some(s) = &manifest.session {
            b.upsert_session(s)?;
        }
        for e in events {
            let mut e = e.clone();
            b.insert_event(&mut e)?;
            if let Some(info) = &e.session_info {
                b.upsert_session(info)?;
            }
        }
        for inc in &manifest.incidents {
            b.upsert_incident(inc)?;
        }
        Ok(())
    })?;
    for s in &manifest.servers {
        store.upsert_server(s)?;
    }
    for p in &manifest.pins {
        store.put_pin(p)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, ProcessInfo};

    #[test]
    fn round_trip_through_store() {
        let store = Store::open_in_memory().unwrap();
        let session = SessionInfo { id: "s1".into(), agent: "claude-code".into(), root_pid: 1, started: 1, ..SessionInfo::default() };
        store.upsert_session(&session).unwrap();
        for i in 0..5 {
            let mut e = Event::new(EventKind::ProcessStart, i);
            e.session = Some(if i == 4 { "other".into() } else { "s1".into() });
            e.process = Some(ProcessInfo { pid: i as u32, ..ProcessInfo::default() });
            store.insert_event(&mut e).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s1.rousseau");
        let m = export_session(&store, "s1", &path).unwrap();
        assert_eq!(m.event_count, 4);
        let (m2, events) = read_bundle(&path).unwrap();
        assert_eq!(m2, m);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].id, 1);

        let replay = Store::open_in_memory().unwrap();
        import_into(&replay, &m2, &events).unwrap();
        assert_eq!(replay.max_event_id().unwrap(), 4);
        assert_eq!(replay.session("s1").unwrap().unwrap().agent, "claude-code");
        assert!(matches!(export_session(&store, "nope", &path), Err(BundleError::UnknownSession(_))));
    }

    #[test]
    fn rejects_foreign_and_future() {
        let mut buf = Vec::new();
        let mut m = Manifest::for_events(&[], "test");
        m.format = "other".into();
        write_to(&mut buf, &m, &[]).unwrap();
        assert!(matches!(read_from(&buf[..]), Err(BundleError::Format(_))));
        let mut buf = Vec::new();
        let mut m = Manifest::for_events(&[], "test");
        m.schema_version = BUNDLE_SCHEMA_VERSION + 1;
        write_to(&mut buf, &m, &[]).unwrap();
        assert!(matches!(read_from(&buf[..]), Err(BundleError::Version(_))));
    }
}
