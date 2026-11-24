//! SQLite storage (WAL mode).
//!
//! Each event is stored as its full JSON body plus a few indexed columns used
//! for filtering. The sensor service, the dashboard and MCP proxies open the
//! same database concurrently; WAL mode lets readers proceed while one writer
//! commits, and a busy timeout absorbs short write contention.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::event::{Attribution, Event, SessionInfo, Severity};
use crate::incident::Incident;
use crate::rules::ResponseMode;

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database lock poisoned")]
    Poisoned,
}

/// Result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    session TEXT,
    pid INTEGER,
    agent TEXT,
    server TEXT,
    severity INTEGER,
    tool_call TEXT,
    attribution_kind TEXT,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_session ON events(session, id);
CREATE INDEX IF NOT EXISTS events_tool_call ON events(tool_call);
CREATE INDEX IF NOT EXISTS events_pid ON events(pid, ts);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    root_pid INTEGER NOT NULL,
    started INTEGER NOT NULL,
    ended INTEGER,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    rule_id TEXT NOT NULL,
    severity INTEGER NOT NULL,
    session TEXT,
    status TEXT NOT NULL,
    first_ts INTEGER NOT NULL,
    last_ts INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_last ON incidents(last_ts);

CREATE TABLE IF NOT EXISTS tool_pins (
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    approved_hash TEXT,
    approved_def TEXT,
    current_hash TEXT NOT NULL,
    current_def TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    PRIMARY KEY (server, tool)
);

CREATE TABLE IF NOT EXISTS servers (
    name TEXT PRIMARY KEY,
    transport TEXT NOT NULL,
    target TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    info TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    ts INTEGER NOT NULL,
    server TEXT,
    tool TEXT,
    severity INTEGER NOT NULL,
    code TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_server ON findings(server, tool);

CREATE TABLE IF NOT EXISTS rule_overrides (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER,
    mode TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Status of a pinned tool definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PinStatus {
    /// Current definition equals the approved one.
    Approved,
    /// Definition is new or changed and awaits review.
    Pending,
    /// The user rejected the current definition.
    Denied,
    /// The tool disappeared from `tools/list`.
    Removed,
}

impl PinStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Pending => "pending",
            Self::Denied => "denied",
            Self::Removed => "removed",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "approved" => Self::Approved,
            "denied" => Self::Denied,
            "removed" => Self::Removed,
            _ => Self::Pending,
        }
    }
}

/// A pinned tool definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolPin {
    pub server: String,
    pub tool: String,
    pub approved_hash: Option<String>,
    /// Canonical JSON of the approved definition.
    pub approved_def: Option<String>,
    pub current_hash: String,
    pub current_def: String,
    pub status: PinStatus,
    pub first_seen: i64,
    pub updated: i64,
}

/// An MCP server seen by a proxy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerRecord {
    pub name: String,
    pub transport: String,
    /// Command line (stdio) or upstream URL (http).
    pub target: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// `serverInfo` / capabilities from `initialize`.
    pub info: Option<serde_json::Value>,
}

/// Filters for event queries. All set fields must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventQuery {
    pub session: Option<String>,
    pub agent: Option<String>,
    pub server: Option<String>,
    /// Kind prefix, e.g. `file.` or `mcp.call`.
    pub kind: Option<String>,
    pub min_severity: Option<Severity>,
    pub tool_call: Option<String>,
    /// Only events with id greater than this.
    pub after_id: Option<u64>,
    /// Only events with id lower than this (paging backwards).
    pub before_id: Option<u64>,
    pub since_ts: Option<i64>,
    pub until_ts: Option<i64>,
    pub limit: Option<u32>,
    /// Oldest first instead of newest first.
    pub ascending: bool,
}

/// Persisted per-rule overrides: rule id → (enabled, mode).
pub type RuleOverrides = HashMap<String, (Option<bool>, Option<ResponseMode>)>;

/// Aggregate counts for the dashboard header and `rousseau doctor`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreStats {
    pub events: u64,
    pub sessions: u64,
    pub active_sessions: u64,
    pub open_incidents: u64,
    pub servers: u64,
    pub pending_pins: u64,
    pub max_event_id: u64,
}

/// Thread-safe handle to the database.
pub struct Store {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// An in-memory database (tests, replay).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // journal_mode returns a row; query it rather than execute.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)", params![SCHEMA_VERSION.to_string()])?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| StoreError::Poisoned)
    }

    /// Runs `f` inside one transaction, committing if it returns `Ok`.
    pub fn batch<R>(&self, f: impl FnOnce(&mut Batch<'_>) -> Result<R>) -> Result<R> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut b = Batch { tx };
        let r = f(&mut b)?;
        b.tx.commit()?;
        Ok(r)
    }

    /// Inserts one event (assigning its id when `event.id == 0`).
    pub fn insert_event(&self, event: &mut Event) -> Result<u64> {
        self.batch(|b| b.insert_event(event))
    }

    /// Fetches one event.
    pub fn event(&self, id: u64) -> Result<Option<Event>> {
        let conn = self.lock()?;
        let body: Option<String> = conn.query_row("SELECT body FROM events WHERE id = ?1", params![id as i64], |r| r.get(0)).optional()?;
        body.map(|b| parse_event(id, &b)).transpose()
    }

    /// Fetches events by id (missing ids are skipped), ordered by id.
    pub fn events_by_ids(&self, ids: &[u64]) -> Result<Vec<Event>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare_cached("SELECT id, body FROM events WHERE id = ?1")?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some((i, b)) = stmt.query_row(params![*id as i64], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).optional()? {
                out.push(parse_event(i as u64, &b)?);
            }
        }
        out.sort_by_key(|e| e.id);
        Ok(out)
    }

    /// Queries events.
    pub fn query_events(&self, q: &EventQuery) -> Result<Vec<Event>> {
        let mut sql = String::from("SELECT id, body FROM events WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut push = |clause: &str, v: rusqlite::types::Value| {
            sql.push_str(clause);
            args.push(v);
        };
        if let Some(s) = &q.session {
            push(" AND session = ?", s.clone().into());
        }
        if let Some(a) = &q.agent {
            push(" AND agent = ?", a.clone().into());
        }
        if let Some(s) = &q.server {
            push(" AND server = ?", s.clone().into());
        }
        if let Some(k) = &q.kind {
            push(" AND kind LIKE ? ESCAPE '\\'", format!("{}%", escape_like(k)).into());
        }
        if let Some(s) = q.min_severity {
            push(" AND severity >= ?", s.rank().into());
        }
        if let Some(t) = &q.tool_call {
            push(" AND tool_call = ?", t.clone().into());
        }
        if let Some(a) = q.after_id {
            push(" AND id > ?", (a as i64).into());
        }
        if let Some(b) = q.before_id {
            push(" AND id < ?", (b as i64).into());
        }
        if let Some(s) = q.since_ts {
            push(" AND ts >= ?", s.into());
        }
        if let Some(u) = q.until_ts {
            push(" AND ts <= ?", u.into());
        }
        sql.push_str(if q.ascending { " ORDER BY id ASC" } else { " ORDER BY id DESC" });
        sql.push_str(&format!(" LIMIT {}", q.limit.unwrap_or(500).min(50_000)));
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, body) = row?;
            out.push(parse_event(id as u64, &body)?);
        }
        Ok(out)
    }

    /// Highest event id (0 if empty).
    pub fn max_event_id(&self) -> Result<u64> {
        let conn = self.lock()?;
        let v: Option<i64> = conn.query_row("SELECT MAX(id) FROM events", [], |r| r.get(0))?;
        Ok(v.unwrap_or(0) as u64)
    }

    /// Inserts or updates a session.
    pub fn upsert_session(&self, s: &SessionInfo) -> Result<()> {
        self.batch(|b| b.upsert_session(s))
    }

    /// Recent sessions, newest first.
    pub fn sessions(&self, limit: u32) -> Result<Vec<SessionInfo>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT body FROM sessions ORDER BY started DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r?)?);
        }
        Ok(out)
    }

    /// One session.
    pub fn session(&self, id: &str) -> Result<Option<SessionInfo>> {
        let conn = self.lock()?;
        let body: Option<String> = conn.query_row("SELECT body FROM sessions WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
        Ok(body.map(|b| serde_json::from_str(&b)).transpose()?)
    }

    /// Marks sessions without an end as ended at `ts` (startup recovery
    /// after a crash: their processes are gone).
    pub fn close_dangling_sessions(&self, ts: i64) -> Result<usize> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT body FROM sessions WHERE ended IS NULL")?;
        let bodies: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
        drop(stmt);
        for b in &bodies {
            let mut s: SessionInfo = serde_json::from_str(b)?;
            s.ended = Some(ts);
            conn.execute("UPDATE sessions SET ended = ?2, body = ?3 WHERE id = ?1", params![s.id, ts, serde_json::to_string(&s)?])?;
        }
        Ok(bodies.len())
    }

    /// Inserts or replaces an incident.
    pub fn upsert_incident(&self, inc: &Incident) -> Result<()> {
        self.batch(|b| b.upsert_incident(inc))
    }

    /// Recent incidents, most recently active first.
    pub fn incidents(&self, limit: u32, session: Option<&str>) -> Result<Vec<Incident>> {
        let conn = self.lock()?;
        let (sql, args): (&str, Vec<rusqlite::types::Value>) = match session {
            Some(s) => (
                "SELECT body FROM incidents WHERE session = ?1 ORDER BY last_ts DESC LIMIT ?2",
                vec![s.to_string().into(), i64::from(limit).into()],
            ),
            None => ("SELECT body FROM incidents ORDER BY last_ts DESC LIMIT ?1", vec![i64::from(limit).into()]),
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r?)?);
        }
        Ok(out)
    }

    /// One incident.
    pub fn incident(&self, id: u64) -> Result<Option<Incident>> {
        let conn = self.lock()?;
        let body: Option<String> =
            conn.query_row("SELECT body FROM incidents WHERE id = ?1", params![id as i64], |r| r.get(0)).optional()?;
        Ok(body.map(|b| serde_json::from_str(&b)).transpose()?)
    }

    /// Changes an incident's status.
    pub fn set_incident_status(&self, id: u64, status: &str) -> Result<bool> {
        let Some(mut inc) = self.incident(id)? else {
            return Ok(false);
        };
        inc.status = status.to_string();
        self.upsert_incident(&inc)?;
        Ok(true)
    }

    /// Highest incident id (0 if none).
    pub fn max_incident_id(&self) -> Result<u64> {
        let conn = self.lock()?;
        let v: Option<i64> = conn.query_row("SELECT MAX(id) FROM incidents", [], |r| r.get(0))?;
        Ok(v.unwrap_or(0) as u64)
    }

    /// Pin for `(server, tool)`.
    pub fn pin(&self, server: &str, tool: &str) -> Result<Option<ToolPin>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT server, tool, approved_hash, approved_def, current_hash, current_def, status, first_seen, updated
             FROM tool_pins WHERE server = ?1 AND tool = ?2",
            params![server, tool],
            row_to_pin,
        )
        .optional()
        .map_err(Into::into)
    }

    /// All pins, optionally for one server.
    pub fn pins(&self, server: Option<&str>) -> Result<Vec<ToolPin>> {
        let conn = self.lock()?;
        let sql = "SELECT server, tool, approved_hash, approved_def, current_hash, current_def, status, first_seen, updated FROM tool_pins";
        let mut out = Vec::new();
        match server {
            Some(s) => {
                let mut stmt = conn.prepare(&format!("{sql} WHERE server = ?1 ORDER BY tool"))?;
                for r in stmt.query_map(params![s], row_to_pin)? {
                    out.push(r?);
                }
            }
            None => {
                let mut stmt = conn.prepare(&format!("{sql} ORDER BY server, tool"))?;
                for r in stmt.query_map([], row_to_pin)? {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    /// Inserts or replaces a pin.
    pub fn put_pin(&self, p: &ToolPin) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO tool_pins(server, tool, approved_hash, approved_def, current_hash, current_def, status, first_seen, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(server, tool) DO UPDATE SET approved_hash = ?3, approved_def = ?4,
               current_hash = ?5, current_def = ?6, status = ?7, updated = ?9",
            params![
                p.server,
                p.tool,
                p.approved_hash,
                p.approved_def,
                p.current_hash,
                p.current_def,
                p.status.as_str(),
                p.first_seen,
                p.updated
            ],
        )?;
        Ok(())
    }

    /// Approves the current definition of a tool (re-pins it).
    pub fn approve_pin(&self, server: &str, tool: &str, ts: i64) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn.execute(
            "UPDATE tool_pins SET approved_hash = current_hash, approved_def = current_def,
               status = 'approved', updated = ?3 WHERE server = ?1 AND tool = ?2",
            params![server, tool, ts],
        )?;
        Ok(n > 0)
    }

    /// Denies the current definition of a tool (calls stay blocked).
    pub fn deny_pin(&self, server: &str, tool: &str, ts: i64) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn
            .execute("UPDATE tool_pins SET status = 'denied', updated = ?3 WHERE server = ?1 AND tool = ?2", params![server, tool, ts])?;
        Ok(n > 0)
    }

    /// Records a server sighting.
    pub fn upsert_server(&self, s: &ServerRecord) -> Result<()> {
        let conn = self.lock()?;
        upsert_server_sql(&conn, s)
    }

    /// All known servers.
    pub fn servers(&self) -> Result<Vec<ServerRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT name, transport, target, first_seen, last_seen, info FROM servers ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(ServerRecord {
                name: r.get(0)?,
                transport: r.get(1)?,
                target: r.get(2)?,
                first_seen: r.get(3)?,
                last_seen: r.get(4)?,
                info: r.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Inspector findings for a server (newest first).
    pub fn findings(&self, server: Option<&str>, limit: u32) -> Result<Vec<Event>> {
        let conn = self.lock()?;
        let mut out = Vec::new();
        let mut stmt;
        let rows = match server {
            Some(s) => {
                stmt = conn.prepare("SELECT event_id, body FROM findings WHERE server = ?1 ORDER BY id DESC LIMIT ?2")?;
                stmt.query_map(params![s, limit], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => {
                stmt = conn.prepare("SELECT event_id, body FROM findings ORDER BY id DESC LIMIT ?1")?;
                stmt.query_map(params![limit], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            }
        };
        for (id, body) in rows {
            out.push(parse_event(id.unwrap_or(0) as u64, &body)?);
        }
        Ok(out)
    }

    /// Persisted rule enable/mode overrides.
    pub fn rule_overrides(&self) -> Result<RuleOverrides> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT rule_id, enabled, mode FROM rule_overrides")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<bool>>(1)?, r.get::<_, Option<String>>(2)?)))?;
        let mut out = HashMap::new();
        for r in rows {
            let (id, en, mode) = r?;
            out.insert(id, (en, mode.as_deref().and_then(ResponseMode::parse)));
        }
        Ok(out)
    }

    /// Persists a rule override. `None` fields keep the rule's own setting.
    pub fn set_rule_override(&self, id: &str, enabled: Option<bool>, mode: Option<ResponseMode>) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO rule_overrides(rule_id, enabled, mode) VALUES (?1, ?2, ?3)
             ON CONFLICT(rule_id) DO UPDATE SET enabled = COALESCE(?2, enabled), mode = ?3",
            params![id, enabled, mode.map(ResponseMode::as_str)],
        )?;
        Ok(())
    }

    /// Reads a meta value.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
    }

    /// Writes a meta value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", params![key, value])?;
        Ok(())
    }

    /// Deletes events, findings and closed sessions/incidents older than `before_ts`.
    pub fn prune(&self, before_ts: i64) -> Result<usize> {
        let conn = self.lock()?;
        let n = conn.execute("DELETE FROM events WHERE ts < ?1", params![before_ts])?;
        conn.execute("DELETE FROM findings WHERE ts < ?1", params![before_ts])?;
        conn.execute("DELETE FROM incidents WHERE last_ts < ?1", params![before_ts])?;
        conn.execute("DELETE FROM sessions WHERE ended IS NOT NULL AND ended < ?1", params![before_ts])?;
        Ok(n)
    }

    /// Aggregate counts.
    pub fn stats(&self) -> Result<StoreStats> {
        let conn = self.lock()?;
        let count = |sql: &str| -> Result<u64> { Ok(conn.query_row(sql, [], |r| r.get::<_, Option<i64>>(0))?.unwrap_or(0) as u64) };
        Ok(StoreStats {
            events: count("SELECT COUNT(*) FROM events")?,
            sessions: count("SELECT COUNT(*) FROM sessions")?,
            active_sessions: count("SELECT COUNT(*) FROM sessions WHERE ended IS NULL")?,
            open_incidents: count("SELECT COUNT(*) FROM incidents WHERE status = 'open'")?,
            servers: count("SELECT COUNT(*) FROM servers")?,
            pending_pins: count("SELECT COUNT(*) FROM tool_pins WHERE status IN ('pending', 'denied')")?,
            max_event_id: count("SELECT MAX(id) FROM events")?,
        })
    }
}

/// Writes inside one transaction (see [`Store::batch`]).
pub struct Batch<'a> {
    tx: Transaction<'a>,
}

impl Batch<'_> {
    /// Inserts an event; assigns `event.id` when it is 0.
    pub fn insert_event(&mut self, event: &mut Event) -> Result<u64> {
        let body = serde_json::to_string(&*event)?;
        let attribution_kind = event.attribution.as_ref().map(|a| match a.kind {
            crate::event::AttributionKind::Mcp => "mcp",
            crate::event::AttributionKind::Transcript => "transcript",
            crate::event::AttributionKind::Unexplained => "unexplained",
        });
        let id = if event.id == 0 { None } else { Some(event.id as i64) };
        self.tx.execute(
            "INSERT INTO events(id, ts, kind, session, pid, agent, server, severity, tool_call, attribution_kind, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                event.ts,
                event.kind.as_str(),
                event.session,
                event.pid(),
                event.agent(),
                event.server(),
                event.severity.map(Severity::rank),
                event.attribution.as_ref().and_then(|a| a.tool_call.clone()),
                attribution_kind,
                body
            ],
        )?;
        let new_id = self.tx.last_insert_rowid() as u64;
        event.id = new_id;
        if let Some(f) = &event.finding {
            self.tx.execute(
                "INSERT INTO findings(event_id, ts, server, tool, severity, code, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![new_id as i64, event.ts, f.server, f.tool, f.severity.rank(), f.code, serde_json::to_string(&*event)?],
            )?;
        }
        Ok(new_id)
    }

    /// Re-attributes still-unexplained events of process `pid` (started at
    /// `since_ts`) in `session`. Returns the number of rows changed.
    pub fn reattribute_process(&mut self, session: &str, pid: u32, since_ts: i64, attribution: &Attribution) -> Result<usize> {
        let a = serde_json::to_string(attribution)?;
        Ok(self.tx.execute(
            "UPDATE events SET tool_call = ?4, attribution_kind = 'transcript',
               body = json_set(body, '$.attribution', json(?5))
             WHERE session = ?1 AND pid = ?2 AND ts >= ?3
               AND (attribution_kind IS NULL OR attribution_kind = 'unexplained')",
            params![session, pid, since_ts, attribution.tool_call, a],
        )?)
    }

    /// Re-attributes unexplained file events on `path` from the agent root
    /// process of `session` within `[from, to]`.
    pub fn reattribute_file(
        &mut self,
        session: &str,
        root_pid: u32,
        path: &str,
        from: i64,
        to: i64,
        attribution: &Attribution,
    ) -> Result<usize> {
        let a = serde_json::to_string(attribution)?;
        Ok(self.tx.execute(
            "UPDATE events SET tool_call = ?6, attribution_kind = 'transcript',
               body = json_set(body, '$.attribution', json(?7))
             WHERE session = ?1 AND pid = ?2 AND ts BETWEEN ?4 AND ?5 AND kind LIKE 'file.%'
               AND lower(replace(json_extract(body, '$.file.path'), '/', '\')) = ?3
               AND (attribution_kind IS NULL OR attribution_kind = 'unexplained')",
            params![session, root_pid, crate::correlate::normalize_path(path), from, to, attribution.tool_call, a],
        )?)
    }

    /// Inserts or updates a session.
    pub fn upsert_session(&mut self, s: &SessionInfo) -> Result<()> {
        self.tx.execute(
            "INSERT INTO sessions(id, agent, root_pid, started, ended, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET ended = ?5, body = ?6",
            params![s.id, s.agent, s.root_pid, s.started, s.ended, serde_json::to_string(s)?],
        )?;
        Ok(())
    }

    /// Records a server sighting inside the transaction.
    pub fn upsert_server(&mut self, s: &ServerRecord) -> Result<()> {
        upsert_server_sql(&self.tx, s)
    }

    /// Inserts or replaces an incident.
    pub fn upsert_incident(&mut self, inc: &Incident) -> Result<()> {
        self.tx.execute(
            "INSERT INTO incidents(id, rule_id, severity, session, status, first_ts, last_ts, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET status = ?5, last_ts = ?7, body = ?8",
            params![
                inc.id as i64,
                inc.rule_id,
                inc.severity.rank(),
                inc.session,
                inc.status,
                inc.first_ts,
                inc.last_ts,
                serde_json::to_string(inc)?
            ],
        )?;
        Ok(())
    }
}

fn upsert_server_sql(conn: &Connection, s: &ServerRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO servers(name, transport, target, first_seen, last_seen, info)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(name) DO UPDATE SET transport = CASE WHEN ?2 = '' THEN transport ELSE ?2 END,
           target = COALESCE(?3, target), last_seen = ?5, info = COALESCE(?6, info)",
        params![s.name, s.transport, s.target, s.first_seen, s.last_seen, s.info.as_ref().map(|v| v.to_string())],
    )?;
    Ok(())
}

fn row_to_pin(r: &rusqlite::Row<'_>) -> rusqlite::Result<ToolPin> {
    Ok(ToolPin {
        server: r.get(0)?,
        tool: r.get(1)?,
        approved_hash: r.get(2)?,
        approved_def: r.get(3)?,
        current_hash: r.get(4)?,
        current_def: r.get(5)?,
        status: PinStatus::parse(&r.get::<_, String>(6)?),
        first_seen: r.get(7)?,
        updated: r.get(8)?,
    })
}

fn parse_event(id: u64, body: &str) -> Result<Event> {
    let mut e: Event = serde_json::from_str(body)?;
    e.id = id;
    Ok(e)
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AttributionKind, EventKind, FileInfo, FindingInfo, ProcessInfo};

    fn file_event(ts: i64, session: &str, pid: u32, path: &str) -> Event {
        Event {
            ts,
            kind: EventKind::FileRead,
            session: Some(session.into()),
            process: Some(ProcessInfo { pid, ..ProcessInfo::default() }),
            attribution: Some(Attribution::default()),
            file: Some(FileInfo { path: path.into(), ..FileInfo::default() }),
            ..Event::default()
        }
    }

    #[test]
    fn events_round_trip_and_query() {
        let s = Store::open_in_memory().unwrap();
        let mut a = file_event(10, "s1", 5, r"C:\x");
        let mut b = Event::new(EventKind::McpFinding, 20);
        b.severity = Some(Severity::High);
        b.finding = Some(FindingInfo {
            inspector: "unicode".into(),
            code: "unicode.tags".into(),
            severity: Severity::High,
            server: Some("srv".into()),
            ..FindingInfo::default()
        });
        s.insert_event(&mut a).unwrap();
        s.insert_event(&mut b).unwrap();
        assert_eq!((a.id, b.id), (1, 2));
        assert_eq!(s.event(1).unwrap().unwrap(), a);
        let q = EventQuery { min_severity: Some(Severity::Medium), ..EventQuery::default() };
        assert_eq!(s.query_events(&q).unwrap().len(), 1);
        let q = EventQuery { kind: Some("file.".into()), ..EventQuery::default() };
        assert_eq!(s.query_events(&q).unwrap()[0].id, 1);
        let q = EventQuery { after_id: Some(1), ascending: true, ..EventQuery::default() };
        assert_eq!(s.query_events(&q).unwrap()[0].id, 2);
        assert_eq!(s.findings(Some("srv"), 10).unwrap().len(), 1);
        assert_eq!(s.events_by_ids(&[2, 1, 99]).unwrap().len(), 2);
        assert_eq!(s.max_event_id().unwrap(), 2);
    }

    #[test]
    fn reattribution() {
        let s = Store::open_in_memory().unwrap();
        let mut e1 = file_event(100, "s1", 7, r"C:\repo\a.rs");
        let mut e2 = file_event(50, "s1", 7, r"C:\repo\a.rs");
        let mut e3 = file_event(100, "s1", 8, r"C:\repo\a.rs");
        s.insert_event(&mut e1).unwrap();
        s.insert_event(&mut e2).unwrap();
        s.insert_event(&mut e3).unwrap();
        let attr = Attribution { kind: AttributionKind::Transcript, tool_call: Some("tx:1".into()), ..Attribution::default() };
        let n = s.batch(|b| b.reattribute_process("s1", 7, 60, &attr)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(s.event(e1.id).unwrap().unwrap().attribution.unwrap().tool_call.as_deref(), Some("tx:1"));
        let n = s.batch(|b| b.reattribute_file("s1", 8, "c:/REPO/a.rs", 0, 200, &attr)).unwrap();
        assert_eq!(n, 1);
        let q = EventQuery { tool_call: Some("tx:1".into()), ..EventQuery::default() };
        assert_eq!(s.query_events(&q).unwrap().len(), 2);
    }

    #[test]
    fn pins_and_overrides() {
        let s = Store::open_in_memory().unwrap();
        let p = ToolPin {
            server: "srv".into(),
            tool: "t".into(),
            approved_hash: Some("a".into()),
            approved_def: Some("{}".into()),
            current_hash: "b".into(),
            current_def: "{\"x\":1}".into(),
            status: PinStatus::Pending,
            first_seen: 1,
            updated: 2,
        };
        s.put_pin(&p).unwrap();
        assert_eq!(s.pin("srv", "t").unwrap().unwrap(), p);
        assert!(s.approve_pin("srv", "t", 3).unwrap());
        let a = s.pin("srv", "t").unwrap().unwrap();
        assert_eq!(a.approved_hash.as_deref(), Some("b"));
        assert_eq!(a.status, PinStatus::Approved);
        assert!(s.deny_pin("srv", "t", 4).unwrap());
        assert_eq!(s.pins(None).unwrap()[0].status, PinStatus::Denied);
        s.set_rule_override("R1", Some(false), Some(ResponseMode::Enforce)).unwrap();
        s.set_rule_override("R1", None, None).unwrap();
        let o = s.rule_overrides().unwrap();
        assert_eq!(o["R1"], (Some(false), None));
    }

    #[test]
    fn sessions_incidents_prune() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("t.db")).unwrap();
        let sess = SessionInfo { id: "s1".into(), agent: "a".into(), root_pid: 1, started: 5, ..SessionInfo::default() };
        s.upsert_session(&sess).unwrap();
        assert_eq!(s.stats().unwrap().active_sessions, 1);
        assert_eq!(s.close_dangling_sessions(9).unwrap(), 1);
        assert_eq!(s.session("s1").unwrap().unwrap().ended, Some(9));
        let inc = Incident {
            id: 1,
            rule_id: "R".into(),
            title: "t".into(),
            severity: Severity::High,
            session: Some("s1".into()),
            agent: None,
            first_ts: 1,
            last_ts: 2,
            count: 1,
            status: "open".into(),
            mode: ResponseMode::Observe,
            explanation: String::new(),
            owasp: vec![],
            mitre: vec![],
            evidence: vec![1],
            actions: vec![],
            group: None,
        };
        s.upsert_incident(&inc).unwrap();
        assert!(s.set_incident_status(1, "closed").unwrap());
        assert_eq!(s.incidents(10, Some("s1")).unwrap()[0].status, "closed");
        let mut e = file_event(1, "s1", 1, "x");
        s.insert_event(&mut e).unwrap();
        assert_eq!(s.prune(100).unwrap(), 1);
        assert!(s.session("s1").unwrap().is_none());
    }
}
