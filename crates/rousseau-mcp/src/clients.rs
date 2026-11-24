//! MCP client configuration discovery and rewriting.
//!
//! `rousseau protect` rewrites each stdio server entry so the client
//! launches it through `rousseau wrap --name <server> -- <command> <args…>`.
//! Edits are spliced into the original text (JSON) or applied with
//! `toml_edit` (Codex), so formatting, comments and unrelated keys are
//! preserved. A timestamped backup is written next to each file and
//! recorded in a manifest; `rousseau unprotect` restores the backup byte for
//! byte when the file has not changed since, and otherwise unwraps the
//! entries in place.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical::line_diff;
use crate::jsonspan::{self, Node, Splice};

const CLIENTS_TOML: &str = include_str!("clients.toml");

/// Errors from config handling.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: invalid JSON: {source}")]
    Json {
        path: String,
        #[source]
        source: jsonspan::SpanError,
    },
    #[error("{path}: invalid TOML: {msg}")]
    Toml { path: String, msg: String },
    #[error("invalid client table: {0}")]
    Table(String),
    #[error("manifest error: {0}")]
    Manifest(String),
}

/// Configuration file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Json,
    Toml,
}

/// One client entry from `clients.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDef {
    pub id: String,
    pub name: String,
    pub format: Format,
    pub paths: Vec<String>,
    pub servers: Vec<String>,
}

#[derive(Deserialize)]
struct Table {
    client: Vec<ClientDef>,
}

/// The embedded client table.
pub fn client_table() -> Result<Vec<ClientDef>, ClientError> {
    toml::from_str::<Table>(CLIENTS_TOML).map(|t| t.client).map_err(|e| ClientError::Table(e.to_string()))
}

/// Expands path templates.
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    pub home: PathBuf,
    pub appdata: PathBuf,
    pub localappdata: PathBuf,
    pub codex_home: Option<PathBuf>,
    pub projects: Vec<PathBuf>,
}

impl Resolver {
    /// Resolver for the current user from environment variables.
    pub fn from_env(projects: Vec<PathBuf>) -> Self {
        let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
        let home = env("USERPROFILE").or_else(|| env("HOME")).unwrap_or_default();
        Self {
            appdata: env("APPDATA").unwrap_or_else(|| home.join("AppData").join("Roaming")),
            localappdata: env("LOCALAPPDATA").unwrap_or_else(|| home.join("AppData").join("Local")),
            codex_home: env("CODEX_HOME"),
            home,
            projects,
        }
    }

    /// Expands one template into concrete paths.
    pub fn expand(&self, template: &str) -> Vec<PathBuf> {
        let join = |base: &Path, rest: &str| {
            let mut p = base.to_path_buf();
            for part in rest.split(['/', '\\']).filter(|s| !s.is_empty()) {
                p.push(part);
            }
            p
        };
        if let Some(rest) = template.strip_prefix("<project>") {
            return self.projects.iter().map(|d| join(d, rest)).collect();
        }
        let (base, rest) = if let Some(r) = template.strip_prefix('~') {
            (self.home.clone(), r)
        } else if let Some(r) = template.strip_prefix("%APPDATA%") {
            (self.appdata.clone(), r)
        } else if let Some(r) = template.strip_prefix("%LOCALAPPDATA%") {
            (self.localappdata.clone(), r)
        } else if let Some(r) = template.strip_prefix("$CODEX_HOME") {
            (self.codex_home.clone().unwrap_or_else(|| self.home.join(".codex")), r)
        } else {
            return vec![PathBuf::from(template)];
        };
        vec![join(&base, rest)]
    }
}

/// A discovered configuration file.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigFile {
    pub client: String,
    pub client_name: String,
    pub path: PathBuf,
    pub format: Format,
    pub servers: Vec<String>,
}

/// All candidate config files that exist.
pub fn discover(res: &Resolver) -> Result<Vec<ConfigFile>, ClientError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in client_table()? {
        for t in &c.paths {
            for p in res.expand(t) {
                if p.is_file() && seen.insert(p.clone()) {
                    out.push(ConfigFile {
                        client: c.id.clone(),
                        client_name: c.name.clone(),
                        path: p,
                        format: c.format,
                        servers: c.servers.clone(),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// A server entry in a config file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerEntry {
    pub name: String,
    /// Dotted location of the servers object, e.g. `mcpServers`.
    pub location: String,
    /// `stdio` or `remote`.
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    /// Already launched through `rousseau wrap`.
    pub wrapped: bool,
}

fn is_rousseau(cmd: &str) -> bool {
    let base = cmd.rsplit(['\\', '/']).next().unwrap_or(cmd).to_lowercase();
    base == "rousseau.exe" || base == "rousseau"
}

fn wrap_args(name: &str, command: &str, args: &[String]) -> Vec<String> {
    let mut v = vec!["wrap".to_string(), "--name".to_string(), name.to_string(), "--".to_string(), command.to_string()];
    v.extend(args.iter().cloned());
    v
}

/// Splits wrapped args back into `(command, args)`.
pub fn unwrap_args(args: &[String]) -> Option<(String, Vec<String>)> {
    if args.first().map(String::as_str) != Some("wrap") {
        return None;
    }
    let sep = args.iter().position(|a| a == "--")?;
    let cmd = args.get(sep + 1)?.clone();
    Some((cmd, args[sep + 2..].to_vec()))
}

#[cfg(test)]
fn wrapped_name(args: &[String]) -> Option<&str> {
    let i = args.iter().position(|a| a == "--name")?;
    args.get(i + 1).map(String::as_str)
}

// ---------------------------------------------------------------- JSON

fn json_server_objects<'a>(root: &'a Node, pattern: &str) -> Vec<(String, &'a Node)> {
    let mut current: Vec<(String, &Node)> = vec![(String::new(), root)];
    for part in pattern.split('.') {
        let mut next = Vec::new();
        for (loc, node) in current {
            if part == "*" {
                for m in node.members() {
                    next.push((join_loc(&loc, &m.key), &m.value));
                }
            } else if let Some(child) = node.get(part) {
                next.push((join_loc(&loc, part), child));
            }
        }
        current = next;
    }
    current.into_iter().filter(|(_, n)| matches!(n.kind, jsonspan::Kind::Object(_))).collect()
}

fn join_loc(a: &str, b: &str) -> String {
    if a.is_empty() { b.to_string() } else { format!("{a}.{b}") }
}

fn json_entry(name: &str, location: &str, node: &Node) -> ServerEntry {
    let command = node.get("command").and_then(Node::as_str).map(str::to_string);
    let args: Vec<String> =
        node.get("args").map(|a| a.items().iter().filter_map(|i| i.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let url = ["url", "serverUrl", "httpUrl"].iter().find_map(|k| node.get(k).and_then(Node::as_str)).map(str::to_string);
    let ty = node.get("type").and_then(Node::as_str).unwrap_or_default().to_lowercase();
    let remote = url.is_some() || matches!(ty.as_str(), "http" | "sse" | "streamable-http" | "streamablehttp");
    let wrapped = command.as_deref().is_some_and(is_rousseau) && args.first().map(String::as_str) == Some("wrap");
    ServerEntry {
        name: name.to_string(),
        location: location.to_string(),
        transport: if remote || command.is_none() { "remote" } else { "stdio" }.to_string(),
        command,
        args,
        url,
        wrapped,
    }
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn json_array(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| json_string(s)).collect::<Vec<_>>().join(", "))
}

/// Lists server entries in a config file's text.
pub fn list_servers(text: &str, format: Format, patterns: &[String], path: &str) -> Result<Vec<ServerEntry>, ClientError> {
    match format {
        Format::Json => {
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }
            let root = jsonspan::parse(text).map_err(|e| ClientError::Json { path: path.into(), source: e })?;
            let mut out = Vec::new();
            for p in patterns {
                for (loc, obj) in json_server_objects(&root, p) {
                    for m in obj.members() {
                        if matches!(m.value.kind, jsonspan::Kind::Object(_)) {
                            out.push(json_entry(&m.key, &loc, &m.value));
                        }
                    }
                }
            }
            Ok(out)
        }
        Format::Toml => toml_servers(text, patterns, path).map(|(_, v)| v),
    }
}

/// Decides the `--name` for each server: its key, qualified with the
/// client id when the same key maps to different commands in different
/// places (so unrelated servers do not share pins).
pub type NameFn<'a> = &'a dyn Fn(&ServerEntry) -> String;

/// Rewrites a config's text so every unwrapped stdio server goes through
/// `rousseau wrap`. Returns the new text and the names of wrapped servers.
pub fn protect_text(
    text: &str,
    format: Format,
    patterns: &[String],
    exe: &str,
    path: &str,
    name_of: NameFn<'_>,
) -> Result<(String, Vec<String>), ClientError> {
    match format {
        Format::Json => {
            let root = jsonspan::parse(text).map_err(|e| ClientError::Json { path: path.into(), source: e })?;
            let mut splices = Vec::new();
            let mut changed = Vec::new();
            for p in patterns {
                for (loc, obj) in json_server_objects(&root, p) {
                    for m in obj.members() {
                        let entry = json_entry(&m.key, &loc, &m.value);
                        if entry.transport != "stdio" || entry.wrapped {
                            continue;
                        }
                        let (Some(cmd_node), Some(command)) = (m.value.get("command"), entry.command.as_deref()) else {
                            continue;
                        };
                        let name = name_of(&entry);
                        let new_args = json_array(&wrap_args(&name, command, &entry.args));
                        splices.push(Splice { start: cmd_node.start, end: cmd_node.end, text: json_string(exe) });
                        match m.value.get("args") {
                            Some(a) => splices.push(Splice { start: a.start, end: a.end, text: new_args }),
                            None => {
                                splices.push(Splice { start: cmd_node.end, end: cmd_node.end, text: format!(", \"args\": {new_args}") })
                            }
                        }
                        changed.push(name);
                    }
                }
            }
            Ok((jsonspan::apply(text, &splices), changed))
        }
        Format::Toml => {
            let (mut doc, entries) = toml_servers(text, patterns, path)?;
            let mut changed = Vec::new();
            for e in entries {
                if e.transport != "stdio" || e.wrapped {
                    continue;
                }
                let Some(command) = e.command.as_deref() else { continue };
                let name = name_of(&e);
                if let Some(tbl) = toml_server_table(&mut doc, &e.location, &e.name) {
                    set_keep_decor(tbl, "command", toml_edit::Value::from(exe));
                    set_keep_decor(tbl, "args", toml_edit::Value::Array(toml_array(&wrap_args(&name, command, &e.args))));
                    changed.push(name);
                }
            }
            Ok((doc.to_string(), changed))
        }
    }
}

/// Reverses [`protect_text`] in place (used when the file changed after
/// protection, so the backup cannot be restored byte for byte).
pub fn unwrap_text(text: &str, format: Format, patterns: &[String], path: &str) -> Result<(String, Vec<String>), ClientError> {
    match format {
        Format::Json => {
            let root = jsonspan::parse(text).map_err(|e| ClientError::Json { path: path.into(), source: e })?;
            let mut splices = Vec::new();
            let mut changed = Vec::new();
            for p in patterns {
                for (loc, obj) in json_server_objects(&root, p) {
                    for m in obj.members() {
                        let entry = json_entry(&m.key, &loc, &m.value);
                        if !entry.wrapped {
                            continue;
                        }
                        let (Some(cmd_node), Some(args_node)) = (m.value.get("command"), m.value.get("args")) else {
                            continue;
                        };
                        let Some((cmd, args)) = unwrap_args(&entry.args) else { continue };
                        splices.push(Splice { start: cmd_node.start, end: cmd_node.end, text: json_string(&cmd) });
                        splices.push(Splice { start: args_node.start, end: args_node.end, text: json_array(&args) });
                        changed.push(m.key.clone());
                    }
                }
            }
            Ok((jsonspan::apply(text, &splices), changed))
        }
        Format::Toml => {
            let (mut doc, entries) = toml_servers(text, patterns, path)?;
            let mut changed = Vec::new();
            for e in entries {
                if !e.wrapped {
                    continue;
                }
                let Some((cmd, args)) = unwrap_args(&e.args) else { continue };
                if let Some(tbl) = toml_server_table(&mut doc, &e.location, &e.name) {
                    set_keep_decor(tbl, "command", toml_edit::Value::from(cmd));
                    set_keep_decor(tbl, "args", toml_edit::Value::Array(toml_array(&args)));
                    changed.push(e.name.clone());
                }
            }
            Ok((doc.to_string(), changed))
        }
    }
}

// ---------------------------------------------------------------- TOML

fn toml_array(items: &[String]) -> toml_edit::Array {
    let mut a = toml_edit::Array::new();
    for i in items {
        a.push(i.as_str());
    }
    a
}

fn toml_servers(text: &str, patterns: &[String], path: &str) -> Result<(toml_edit::DocumentMut, Vec<ServerEntry>), ClientError> {
    let doc: toml_edit::DocumentMut =
        text.parse().map_err(|e: toml_edit::TomlError| ClientError::Toml { path: path.into(), msg: e.to_string() })?;
    let mut out = Vec::new();
    for p in patterns {
        let Some(servers) = doc.get(p).and_then(|i| i.as_table_like()) else { continue };
        for (name, item) in servers.iter() {
            let Some(t) = item.as_table_like() else { continue };
            let command = t.get("command").and_then(|v| v.as_str()).map(str::to_string);
            let args: Vec<String> = t
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let url = t.get("url").and_then(|v| v.as_str()).map(str::to_string);
            let wrapped = command.as_deref().is_some_and(is_rousseau) && args.first().map(String::as_str) == Some("wrap");
            out.push(ServerEntry {
                name: name.to_string(),
                location: p.clone(),
                transport: if url.is_some() || command.is_none() { "remote" } else { "stdio" }.to_string(),
                command,
                args,
                url,
                wrapped,
            });
        }
    }
    Ok((doc, out))
}

/// Replaces a value while keeping the surrounding whitespace and trailing
/// comment of the old one.
fn set_keep_decor(tbl: &mut dyn toml_edit::TableLike, key: &str, mut new: toml_edit::Value) {
    if let Some(old) = tbl.get(key).and_then(|i| i.as_value()) {
        *new.decor_mut() = old.decor().clone();
    } else {
        new.decor_mut().set_prefix(" ");
    }
    tbl.insert(key, toml_edit::Item::Value(new));
}

fn toml_server_table<'a>(doc: &'a mut toml_edit::DocumentMut, location: &str, name: &str) -> Option<&'a mut dyn toml_edit::TableLike> {
    doc.get_mut(location)?.as_table_like_mut()?.get_mut(name)?.as_table_like_mut()
}

// ---------------------------------------------------------------- protect / unprotect

/// One protected file recorded for `unprotect`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub client: String,
    pub path: PathBuf,
    pub backup: PathBuf,
    pub original_sha256: String,
    pub protected_sha256: String,
    pub ts: i64,
    pub servers: Vec<String>,
}

/// The protect manifest (stored in the user's state directory).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Loads the manifest (empty if missing).
    pub fn load(path: &Path) -> Result<Self, ClientError> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| ClientError::Manifest(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ClientError::Io { path: path.display().to_string(), source: e }),
        }
    }

    /// Saves the manifest.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| ClientError::Io { path: d.display().to_string(), source: e })?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| ClientError::Manifest(e.to_string()))?;
        std::fs::write(path, text).map_err(|e| ClientError::Io { path: path.display().to_string(), source: e })
    }
}

/// What happened to one file.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub client: String,
    pub path: PathBuf,
    /// Servers wrapped (protect) or restored (unprotect).
    pub servers: Vec<String>,
    /// Remote servers that cannot be wrapped by rewriting (use `wrap-http`).
    pub remote: Vec<String>,
    pub already_wrapped: Vec<String>,
    /// Changed lines (`- old` / `+ new`).
    pub diff: String,
    /// `wrapped`, `unchanged`, `restored-backup`, `unwrapped-in-place`, `error: …`.
    pub status: String,
}

fn read(path: &Path) -> Result<String, ClientError> {
    std::fs::read_to_string(path).map_err(|e| ClientError::Io { path: path.display().to_string(), source: e })
}

fn changed_lines(old: &str, new: &str) -> String {
    line_diff(old, new).lines().filter(|l| !l.starts_with("  ")).map(|l| format!("{l}\n")).collect()
}

/// Wraps the stdio servers of every discovered config file.
pub fn protect(res: &Resolver, exe: &str, manifest_path: &Path, dry_run: bool, now: i64) -> Result<Vec<FileReport>, ClientError> {
    let files = discover(res)?;
    // Pass 1: find names that refer to different commands in different files.
    let mut commands: HashMap<String, HashSet<String>> = HashMap::new();
    let mut texts = BTreeMap::new();
    for f in &files {
        let Ok(text) = read(&f.path) else { continue };
        if let Ok(entries) = list_servers(&text, f.format, &f.servers, &f.path.display().to_string()) {
            for e in entries.iter().filter(|e| e.transport == "stdio" && !e.wrapped) {
                let line = format!("{} {}", e.command.clone().unwrap_or_default(), e.args.join(" "));
                commands.entry(e.name.clone()).or_default().insert(line);
            }
        }
        texts.insert(f.path.clone(), text);
    }
    let mut manifest = Manifest::load(manifest_path)?;
    let mut reports = Vec::new();
    for f in &files {
        let Some(text) = texts.get(&f.path) else { continue };
        let path_str = f.path.display().to_string();
        let entries = match list_servers(text, f.format, &f.servers, &path_str) {
            Ok(e) => e,
            Err(e) => {
                reports.push(FileReport {
                    client: f.client.clone(),
                    path: f.path.clone(),
                    servers: vec![],
                    remote: vec![],
                    already_wrapped: vec![],
                    diff: String::new(),
                    status: format!("error: {e}"),
                });
                continue;
            }
        };
        let client = f.client.clone();
        let name_of = |e: &ServerEntry| {
            if commands.get(&e.name).is_some_and(|s| s.len() > 1) { format!("{}@{client}", e.name) } else { e.name.clone() }
        };
        let (new_text, wrapped) = protect_text(text, f.format, &f.servers, exe, &path_str, &name_of)?;
        let remote = entries.iter().filter(|e| e.transport == "remote").map(|e| e.name.clone()).collect();
        let already = entries.iter().filter(|e| e.wrapped).map(|e| e.name.clone()).collect();
        let mut report = FileReport {
            client: f.client.clone(),
            path: f.path.clone(),
            servers: wrapped.clone(),
            remote,
            already_wrapped: already,
            diff: changed_lines(text, &new_text),
            status: if wrapped.is_empty() { "unchanged".into() } else { "wrapped".into() },
        };
        if !wrapped.is_empty() && !dry_run {
            let backup = PathBuf::from(format!("{}.rousseau-backup-{now}", f.path.display()));
            std::fs::copy(&f.path, &backup).map_err(|e| ClientError::Io { path: backup.display().to_string(), source: e })?;
            std::fs::write(&f.path, &new_text).map_err(|e| ClientError::Io { path: path_str.clone(), source: e })?;
            manifest.entries.push(ManifestEntry {
                client: f.client.clone(),
                path: f.path.clone(),
                backup,
                original_sha256: rousseau_core::hash::sha256_hex(text.as_bytes()),
                protected_sha256: rousseau_core::hash::sha256_hex(new_text.as_bytes()),
                ts: now,
                servers: wrapped,
            });
        } else if dry_run && !wrapped.is_empty() {
            report.status = "would wrap".into();
        }
        reports.push(report);
    }
    if !dry_run {
        manifest.save(manifest_path)?;
    }
    Ok(reports)
}

/// Restores every file recorded in the manifest. Files protected several
/// times are restored to their earliest backup (the state before Rousseau).
pub fn unprotect(manifest_path: &Path, dry_run: bool) -> Result<Vec<FileReport>, ClientError> {
    let manifest = Manifest::load(manifest_path)?;
    let mut by_path: BTreeMap<PathBuf, Vec<&ManifestEntry>> = BTreeMap::new();
    for e in &manifest.entries {
        by_path.entry(e.path.clone()).or_default().push(e);
    }
    let mut reports = Vec::new();
    let mut remaining = Vec::new();
    for (path, mut entries) in by_path {
        entries.sort_by_key(|e| e.ts);
        let (Some(first), Some(last)) = (entries.first(), entries.last()) else { continue };
        let path_str = path.display().to_string();
        let current = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                reports.push(FileReport {
                    client: last.client.clone(),
                    path: path.clone(),
                    servers: vec![],
                    remote: vec![],
                    already_wrapped: vec![],
                    diff: String::new(),
                    status: format!("error: {e}"),
                });
                remaining.extend(entries.iter().map(|e| (*e).clone()));
                continue;
            }
        };
        let current_text = String::from_utf8_lossy(&current).into_owned();
        let unchanged = rousseau_core::hash::sha256_hex(&current) == last.protected_sha256;
        let result: Result<FileReport, ClientError> = (|| {
            if unchanged && first.backup.is_file() {
                let original =
                    std::fs::read(&first.backup).map_err(|e| ClientError::Io { path: first.backup.display().to_string(), source: e })?;
                let diff = changed_lines(&current_text, &String::from_utf8_lossy(&original));
                if !dry_run {
                    std::fs::write(&path, &original).map_err(|e| ClientError::Io { path: path_str.clone(), source: e })?;
                    for e in &entries {
                        let _ = std::fs::remove_file(&e.backup);
                    }
                }
                Ok(FileReport {
                    client: last.client.clone(),
                    path: path.clone(),
                    servers: last.servers.clone(),
                    remote: vec![],
                    already_wrapped: vec![],
                    diff,
                    status: if dry_run { "would restore backup".into() } else { "restored-backup".into() },
                })
            } else {
                let table = client_table()?;
                let def = table
                    .iter()
                    .find(|c| c.id == last.client)
                    .ok_or_else(|| ClientError::Table(format!("unknown client {}", last.client)))?;
                let (new_text, servers) = unwrap_text(&current_text, def.format, &def.servers, &path_str)?;
                let diff = changed_lines(&current_text, &new_text);
                if !dry_run {
                    std::fs::write(&path, &new_text).map_err(|e| ClientError::Io { path: path_str.clone(), source: e })?;
                }
                Ok(FileReport {
                    client: last.client.clone(),
                    path: path.clone(),
                    servers,
                    remote: vec![],
                    already_wrapped: vec![],
                    diff,
                    status: if dry_run {
                        "would unwrap in place".into()
                    } else {
                        "unwrapped-in-place (file changed since protect; backup kept)".into()
                    },
                })
            }
        })();
        match result {
            Ok(r) => reports.push(r),
            Err(e) => {
                reports.push(FileReport {
                    client: last.client.clone(),
                    path: path.clone(),
                    servers: vec![],
                    remote: vec![],
                    already_wrapped: vec![],
                    diff: String::new(),
                    status: format!("error: {e}"),
                });
                remaining.extend(entries.iter().map(|e| (*e).clone()));
            }
        }
    }
    if !dry_run {
        Manifest { entries: remaining }.save(manifest_path)?;
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\Program Files\Rousseau\rousseau.exe";

    fn plain(e: &ServerEntry) -> String {
        e.name.clone()
    }

    fn golden_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
    }

    /// Golden-file test per client: `<id>.input.<ext>` → `<id>.protected.<ext>`.
    /// Set `UPDATE_GOLDEN=1` to regenerate after an intentional change.
    #[test]
    fn golden_rewrites_per_client() {
        let table = client_table().unwrap();
        let mut checked = 0;
        for c in &table {
            let ext = if c.format == Format::Toml { "toml" } else { "json" };
            let input_path = golden_dir().join(format!("{}.input.{ext}", c.id));
            let expected_path = golden_dir().join(format!("{}.protected.{ext}", c.id));
            let input = std::fs::read_to_string(&input_path).unwrap_or_else(|_| panic!("missing golden input {}", input_path.display()));
            let (out, wrapped) = protect_text(&input, c.format, &c.servers, EXE, &c.id, &plain).unwrap();
            assert!(!wrapped.is_empty(), "{}: nothing wrapped", c.id);
            if std::env::var_os("UPDATE_GOLDEN").is_some() {
                std::fs::write(&expected_path, &out).unwrap();
            }
            let expected = std::fs::read_to_string(&expected_path).unwrap();
            assert_eq!(out, expected, "{} golden mismatch", c.id);
            // Idempotent: protecting again changes nothing.
            let (again, w2) = protect_text(&out, c.format, &c.servers, EXE, &c.id, &plain).unwrap();
            assert_eq!(again, out);
            assert!(w2.is_empty());
            // Unwrapping restores every server's command and args.
            let (unwrapped, _) = unwrap_text(&out, c.format, &c.servers, &c.id).unwrap();
            let before = list_servers(&input, c.format, &c.servers, "a").unwrap();
            let after = list_servers(&unwrapped, c.format, &c.servers, "b").unwrap();
            assert_eq!(before, after, "{} unwrap mismatch", c.id);
            checked += 1;
        }
        assert_eq!(checked, table.len());
    }

    #[test]
    fn wrap_preserves_unrelated_text() {
        let src = "{\n  // keep me\n  \"theme\": \"dark\",\n  \"mcpServers\": {\n    \"fs\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"C:\\\\code\"],\n      \"env\": {\"A\": \"1\"}\n    },\n    \"remote\": {\"url\": \"https://example.com/mcp\"},\n    \"bare\": {\"command\": \"python\"}\n  }\n}\n";
        let (out, wrapped) = protect_text(src, Format::Json, &["mcpServers".into()], EXE, "t", &plain).unwrap();
        assert_eq!(wrapped, vec!["fs", "bare"]);
        assert!(out.contains("// keep me\n  \"theme\": \"dark\","));
        assert!(out.contains("\"env\": {\"A\": \"1\"}"));
        assert!(out.contains("\"remote\": {\"url\": \"https://example.com/mcp\"}"));
        assert!(out.contains(r#""args": ["wrap", "--name", "bare", "--", "python"]"#));
        let entries = list_servers(&out, Format::Json, &["mcpServers".into()], "t").unwrap();
        assert!(entries.iter().filter(|e| e.transport == "stdio").all(|e| e.wrapped));
        assert_eq!(wrapped_name(&entries[0].args), Some("fs"));
    }

    #[test]
    fn protect_and_unprotect_restore_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = dir.path().join("proj");
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::create_dir_all(project.join(".vscode")).unwrap();
        let cursor = home.join(".cursor/mcp.json");
        let vscode = project.join(".vscode/mcp.json");
        let cursor_src =
            "{\r\n  \"mcpServers\": {\r\n    \"git\": { \"command\": \"uvx\", \"args\": [\"mcp-server-git\"] }\r\n  }\r\n}\r\n";
        let vscode_src = "{\n  // workspace\n  \"servers\": { \"git\": { \"type\": \"stdio\", \"command\": \"docker\", \"args\": [\"run\", \"-i\", \"git\"] } },\n}\n";
        std::fs::write(&cursor, cursor_src).unwrap();
        std::fs::write(&vscode, vscode_src).unwrap();
        let res = Resolver {
            home: home.clone(),
            appdata: dir.path().join("roaming"),
            localappdata: dir.path().join("local"),
            codex_home: None,
            projects: vec![project.clone()],
        };
        let manifest = dir.path().join("state/protect-manifest.json");

        let dry = protect(&res, EXE, &manifest, true, 1).unwrap();
        assert!(dry.iter().all(|r| r.status == "would wrap"));
        assert_eq!(std::fs::read_to_string(&cursor).unwrap(), cursor_src, "dry run writes nothing");
        assert!(dry[0].diff.contains("+ "));

        let reports = protect(&res, EXE, &manifest, false, 2).unwrap();
        assert_eq!(reports.len(), 2);
        // Same key "git" with different commands: names are qualified by client.
        let names: Vec<_> = reports.iter().flat_map(|r| r.servers.clone()).collect();
        assert!(names.contains(&"git@cursor".to_string()) && names.contains(&"git@vscode-workspace".to_string()), "{names:?}");
        assert!(std::fs::read_to_string(&cursor).unwrap().contains("rousseau.exe"));

        // The user edits the VS Code file afterwards: it is unwrapped in place instead.
        let edited = std::fs::read_to_string(&vscode).unwrap().replace("// workspace", "// workspace (edited)");
        std::fs::write(&vscode, &edited).unwrap();

        let back = unprotect(&manifest, false).unwrap();
        assert_eq!(std::fs::read(&cursor).unwrap(), cursor_src.as_bytes(), "byte-for-byte restore");
        let v = std::fs::read_to_string(&vscode).unwrap();
        assert!(v.contains("(edited)") && v.contains("\"command\": \"docker\"") && !v.contains("rousseau"));
        assert!(back.iter().any(|r| r.status == "restored-backup"));
        assert!(back.iter().any(|r| r.status.starts_with("unwrapped-in-place")));
        assert!(Manifest::load(&manifest).unwrap().entries.is_empty());
    }

    #[test]
    fn expansion() {
        let res = Resolver {
            home: PathBuf::from(r"C:\Users\a"),
            appdata: PathBuf::from(r"C:\Users\a\AppData\Roaming"),
            localappdata: PathBuf::new(),
            codex_home: None,
            projects: vec![PathBuf::from(r"D:\p")],
        };
        assert_eq!(res.expand("~/.cursor/mcp.json"), vec![PathBuf::from(r"C:\Users\a").join(".cursor").join("mcp.json")]);
        assert_eq!(res.expand("$CODEX_HOME/config.toml"), vec![PathBuf::from(r"C:\Users\a").join(".codex").join("config.toml")]);
        assert_eq!(res.expand("<project>/.mcp.json"), vec![PathBuf::from(r"D:\p").join(".mcp.json")]);
    }
}
