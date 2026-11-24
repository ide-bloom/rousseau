//! The normalized event model. Every sensor, proxy and adapter produces
//! [`Event`]s; the pipeline enriches them with lineage, session and
//! attribution, and the rule engine evaluates their JSON form.
//!
//! The JSON shape is documented in `docs/event-schema.md` and mirrored by the
//! Python `rousseau_lab.models` module. Optional sections are omitted when
//! empty so rules can test for presence with `exists`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What happened. Serialized as dotted lower-case strings, e.g. `file.read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EventKind {
    #[serde(rename = "process.start")]
    ProcessStart,
    #[serde(rename = "process.stop")]
    ProcessStop,
    #[serde(rename = "image.load")]
    ImageLoad,
    #[serde(rename = "file.create")]
    FileCreate,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "file.rename")]
    FileRename,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "net.accept")]
    NetAccept,
    #[serde(rename = "net.close")]
    NetClose,
    #[serde(rename = "dns.query")]
    DnsQuery,
    #[serde(rename = "registry.set")]
    RegistrySet,
    #[serde(rename = "registry.delete")]
    RegistryDelete,
    #[serde(rename = "mcp.server_start")]
    McpServerStart,
    #[serde(rename = "mcp.server_exit")]
    McpServerExit,
    #[serde(rename = "mcp.initialize")]
    McpInitialize,
    #[serde(rename = "mcp.tools")]
    McpTools,
    #[serde(rename = "mcp.call")]
    McpCall,
    #[serde(rename = "mcp.result")]
    McpResult,
    #[serde(rename = "mcp.message")]
    McpMessage,
    #[serde(rename = "mcp.blocked")]
    McpBlocked,
    #[serde(rename = "mcp.drift")]
    McpDrift,
    #[serde(rename = "mcp.finding")]
    McpFinding,
    #[serde(rename = "transcript.tool_use")]
    TranscriptToolUse,
    #[serde(rename = "session.start")]
    SessionStart,
    #[serde(rename = "session.end")]
    SessionEnd,
    #[serde(rename = "sensor.health")]
    SensorHealth,
    /// Forward compatibility: kinds written by a newer Rousseau.
    #[default]
    #[serde(other, rename = "unknown")]
    Unknown,
}

impl EventKind {
    /// The dotted string form used in JSON, SQLite and rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessStart => "process.start",
            Self::ProcessStop => "process.stop",
            Self::ImageLoad => "image.load",
            Self::FileCreate => "file.create",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileDelete => "file.delete",
            Self::FileRename => "file.rename",
            Self::NetConnect => "net.connect",
            Self::NetAccept => "net.accept",
            Self::NetClose => "net.close",
            Self::DnsQuery => "dns.query",
            Self::RegistrySet => "registry.set",
            Self::RegistryDelete => "registry.delete",
            Self::McpServerStart => "mcp.server_start",
            Self::McpServerExit => "mcp.server_exit",
            Self::McpInitialize => "mcp.initialize",
            Self::McpTools => "mcp.tools",
            Self::McpCall => "mcp.call",
            Self::McpResult => "mcp.result",
            Self::McpMessage => "mcp.message",
            Self::McpBlocked => "mcp.blocked",
            Self::McpDrift => "mcp.drift",
            Self::McpFinding => "mcp.finding",
            Self::TranscriptToolUse => "transcript.tool_use",
            Self::SessionStart => "session.start",
            Self::SessionEnd => "session.end",
            Self::SensorHealth => "sensor.health",
            Self::Unknown => "unknown",
        }
    }

    /// OS-level effects observed through ETW. These are only recorded for
    /// processes inside tracked agent trees.
    pub fn is_os_effect(self) -> bool {
        matches!(
            self,
            Self::ImageLoad
                | Self::FileCreate
                | Self::FileRead
                | Self::FileWrite
                | Self::FileDelete
                | Self::FileRename
                | Self::NetConnect
                | Self::NetAccept
                | Self::NetClose
                | Self::DnsQuery
                | Self::RegistrySet
                | Self::RegistryDelete
        )
    }

    /// Events produced by the MCP proxy.
    pub fn is_mcp(self) -> bool {
        self.as_str().starts_with("mcp.")
    }
}

/// Severity shared by findings, rules and incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Numeric rank (0 = info … 4 = critical) used for SQL filtering.
    pub fn rank(self) -> i64 {
        self as i64
    }

    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parses a lower-case severity name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => return None,
        })
    }

    /// Inverse of [`Severity::rank`].
    pub fn from_rank(rank: i64) -> Self {
        match rank {
            i64::MIN..=0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// The process an event belongs to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Full image path (drive-letter form).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Lower-case file name of the image, e.g. `powershell.exe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Process creation time, Unix ms. Together with `pid` this is the
    /// process identity (PIDs are reused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u32>,
}

/// Where a process sits relative to tracked agents and MCP servers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Lineage {
    /// Agent label (e.g. `claude-code`) when the process is the agent root
    /// or any of its descendants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Stable identifier of the agent root, `"<pid>:<start_ms>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
    /// Distance from the agent root (0 = the agent itself).
    #[serde(default)]
    pub depth: u32,
    /// Name of the MCP server whose process subtree this process is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    /// Lower-case image names of ancestors, nearest first (bounded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<String>,
}

/// How an event was attributed to intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttributionKind {
    /// Caused by an MCP `tools/call`.
    Mcp,
    /// Caused by an agent built-in tool use recovered from a transcript.
    Transcript,
    /// Inside an agent tree but not explained by any known tool call.
    #[default]
    Unexplained,
}

/// Link from an event to the tool call that caused it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Attribution {
    pub kind: AttributionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `exact`, `inherited`, `window`, `similarity` or `ambiguous`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// File activity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Lower-case extension without the dot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

/// Network activity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetInfo {
    /// `tcp` or `udp`.
    pub protocol: String,
    /// `outbound` or `inbound`.
    pub direction: String,
    pub remote_addr: String,
    pub remote_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    /// `loopback`, `private`, `link_local`, `multicast` or `public`.
    pub remote_scope: String,
    /// `"addr:port"`, convenient for first-seen rules.
    pub remote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_recv: Option<u64>,
}

/// A DNS query.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsInfo {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_type: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<String>,
    /// Length of the longest label, used by tunneling rules.
    pub longest_label: u32,
    /// Shannon entropy (bits/char) of the leftmost labels excluding the
    /// registrable domain, rounded to two decimals.
    pub subdomain_entropy: f64,
}

/// A registry modification.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RegistryInfo {
    /// Normalized key path, e.g. `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<u32>,
}

/// An observed MCP message.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct McpInfo {
    pub server: String,
    /// `stdio` or `http`.
    pub transport: String,
    /// `client_to_server` or `server_to_client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_id: Option<Value>,
    /// Unique id of a `tools/call`, also used as `attribution.tool_call`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// An inspector finding (hidden Unicode, instructions, secrets, …).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingInfo {
    /// `unicode`, `instructions`, `shadowing`, `secrets`, `urls`, `args`, `classifier`.
    pub inspector: String,
    /// Short machine-readable code, e.g. `unicode.tags`.
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Where the content was found, e.g. `tools/list get_weather.description`.
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// A tool definition changed relative to its pin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DriftInfo {
    pub server: String,
    pub tool: String,
    /// `added`, `removed` or `changed`.
    pub change: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
    /// Unified-style line diff of the canonical definitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// A built-in tool use recovered from an agent transcript.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TranscriptInfo {
    /// `claude-code` or `codex`.
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<String>,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    /// Shell command when the tool is a shell tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Sensor health report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SensorInfo {
    pub sensor: String,
    /// `ok`, `degraded`, `down`.
    pub status: String,
    pub message: String,
    #[serde(default)]
    pub events_lost: u64,
    #[serde(default)]
    pub events_dropped: u64,
}

/// Session metadata attached to `session.start` / `session.end`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub agent: String,
    pub root_pid: u32,
    pub started: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
}

/// One normalized event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Storage-assigned monotonically increasing id (0 before storage).
    #[serde(default)]
    pub id: u64,
    /// Unix milliseconds.
    pub ts: i64,
    pub kind: EventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<Lineage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<NetInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<FindingInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<TranscriptInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor: Option<SensorInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "session_info")]
    pub session_info: Option<SessionInfo>,
}

impl Event {
    /// A new event of `kind` at `ts` with everything else empty.
    pub fn new(kind: EventKind, ts: i64) -> Self {
        Self { kind, ts, ..Self::default() }
    }

    /// The pid of the acting process, if any.
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.pid)
    }

    /// The MCP server name this event concerns, from the MCP section or lineage.
    pub fn server(&self) -> Option<&str> {
        self.mcp
            .as_ref()
            .map(|m| m.server.as_str())
            .or_else(|| self.drift.as_ref().map(|d| d.server.as_str()))
            .or_else(|| self.finding.as_ref().and_then(|f| f.server.as_deref()))
            .or_else(|| self.lineage.as_ref().and_then(|l| l.mcp_server.as_deref()))
    }

    /// The agent label from lineage.
    pub fn agent(&self) -> Option<&str> {
        self.lineage.as_ref().and_then(|l| l.agent.as_deref())
    }

    /// The JSON form evaluated by rules.
    pub fn to_value(&self) -> Value {
        // Serializing a plain data struct with string keys cannot fail.
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Lower-case file name of a Windows or POSIX path.
pub fn file_name_lower(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase()
}

/// Lower-case extension (without the dot) of a path, if any.
pub fn extension_lower(path: &str) -> Option<String> {
    let name = file_name_lower(path);
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() { None } else { Some(ext.to_string()) }
}

/// Classifies an IP address string into a scope used by rules.
pub fn ip_scope(addr: &str) -> &'static str {
    use std::net::IpAddr;
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                "loopback"
            } else if v4.is_private() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64 {
                "private"
            } else if v4.is_link_local() {
                "link_local"
            } else if v4.is_multicast() || v4.is_broadcast() {
                "multicast"
            } else if v4.is_unspecified() {
                "loopback"
            } else {
                "public"
            }
        }
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_scope(&v4.to_string());
            }
            let seg0 = v6.segments()[0];
            if v6.is_loopback() || v6.is_unspecified() {
                "loopback"
            } else if (seg0 & 0xfe00) == 0xfc00 {
                "private"
            } else if (seg0 & 0xffc0) == 0xfe80 {
                "link_local"
            } else if v6.is_multicast() {
                "multicast"
            } else {
                "public"
            }
        }
        Err(_) => "public",
    }
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, usize>::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    let n = n as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Builds [`DnsInfo`] statistics for a query name.
pub fn dns_info(query: &str) -> DnsInfo {
    let q = query.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = q.split('.').filter(|l| !l.is_empty()).collect();
    let longest = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0) as u32;
    // Everything left of the last two labels is the "subdomain" part.
    let sub = if labels.len() > 2 { labels[..labels.len() - 2].join("") } else { String::new() };
    let ent = (shannon_entropy(&sub) * 100.0).round() / 100.0;
    DnsInfo { query: q, longest_label: longest, subdomain_entropy: ent, ..DnsInfo::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trip() {
        let e = Event::new(EventKind::FileRead, 5);
        let v = e.to_value();
        assert_eq!(v["kind"], "file.read");
        let back: Event = serde_json::from_value(v).unwrap();
        assert_eq!(back.kind, EventKind::FileRead);
        let unknown: Event = serde_json::from_str(r#"{"ts":1,"kind":"future.thing"}"#).unwrap();
        assert_eq!(unknown.kind, EventKind::Unknown);
    }

    #[test]
    fn severity_order() {
        assert!(Severity::Critical > Severity::High);
        assert_eq!(Severity::from_rank(Severity::Medium.rank()), Severity::Medium);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
    }

    #[test]
    fn scopes() {
        assert_eq!(ip_scope("127.0.0.1"), "loopback");
        assert_eq!(ip_scope("::1"), "loopback");
        assert_eq!(ip_scope("10.1.2.3"), "private");
        assert_eq!(ip_scope("192.168.1.1"), "private");
        assert_eq!(ip_scope("100.64.0.1"), "private");
        assert_eq!(ip_scope("169.254.1.1"), "link_local");
        assert_eq!(ip_scope("8.8.8.8"), "public");
        assert_eq!(ip_scope("::ffff:127.0.0.1"), "loopback");
        assert_eq!(ip_scope("fd00::1"), "private");
    }

    #[test]
    fn names() {
        assert_eq!(file_name_lower(r"C:\Windows\System32\CMD.EXE"), "cmd.exe");
        assert_eq!(extension_lower(r"C:\a\b.TXT"), Some("txt".into()));
        assert_eq!(extension_lower(r"C:\a\.bashrc"), None);
    }

    #[test]
    fn dns_stats() {
        let d = dns_info("aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbA.evil.example.com.");
        assert_eq!(d.query, "agvsbg8gd29ybgqgdghpcybpcyblegzpba.evil.example.com");
        assert!(d.longest_label >= 30);
        assert!(d.subdomain_entropy > 3.0);
        assert_eq!(dns_info("example.com").subdomain_entropy, 0.0);
    }
}
