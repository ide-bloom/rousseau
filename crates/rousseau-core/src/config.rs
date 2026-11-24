//! `rousseau.toml`: the runtime configuration, stored in the data directory.
//!
//! The dashboard's Settings page rewrites this file, so keep hand edits to
//! the documented keys (comments are not preserved).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::event::Severity;
use crate::rules::ResponseMode;

/// Errors loading or saving configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {0}: {1}")]
    Read(String, #[source] std::io::Error),
    #[error("cannot write {0}: {1}")]
    Write(String, #[source] std::io::Error),
    #[error("invalid configuration in {0}: {1}")]
    Parse(String, #[source] toml::de::Error),
    #[error("cannot serialize configuration: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Opt-in transcript adapters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscriptConfig {
    /// Read Claude Code session JSONL files (`~/.claude/projects`).
    pub claude_code: bool,
    /// Read Codex rollout files (`~/.codex/sessions`).
    pub codex: bool,
}

/// Response settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseConfig {
    /// Global response mode; rules may override it.
    pub mode: ResponseMode,
    /// Allow enforce-mode rules marked `suspend_tree` to suspend agent trees.
    pub allow_suspend: bool,
    /// In enforce mode, block tool calls whose arguments trigger inspector
    /// findings at or above this severity.
    pub block_findings_at: Severity,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self { mode: ResponseMode::Observe, allow_suspend: false, block_findings_at: Severity::High }
    }
}

/// Tool pinning settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PinningConfig {
    /// Strict mode: tools of a newly seen server start as `pending` and need
    /// approval (instead of trust-on-first-use).
    pub strict: bool,
}

/// Alert channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Only incidents at or above this severity are sent.
    pub min_severity: Severity,
    pub toast: bool,
    pub eventlog: bool,
    pub discord_webhook: Option<String>,
    pub slack_webhook: Option<String>,
    pub webhook_url: Option<String>,
    /// HMAC-SHA256 key for `X-Rousseau-Signature`.
    pub webhook_secret: Option<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Medium,
            toast: true,
            eventlog: true,
            discord_webhook: None,
            slack_webhook: None,
            webhook_url: None,
            webhook_secret: None,
        }
    }
}

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub response: ResponseConfig,
    pub pinning: PinningConfig,
    pub transcripts: TranscriptConfig,
    pub alerts: AlertConfig,
    /// Events older than this are deleted.
    pub retention_days: u32,
    /// Extra rule directories loaded after the built-in rules.
    pub rule_dirs: Vec<PathBuf>,
    /// Extra agent signature files (TOML, same format as `agents.toml`).
    pub agent_files: Vec<PathBuf>,
    /// Enable the optional on-device prompt-injection classifier (requires a
    /// build with the `ml` feature).
    pub classifier: bool,
    /// Profile directory of the user who installed Rousseau. The service runs
    /// as LocalSystem and reads that user's agent transcripts from here.
    pub user_profile: Option<PathBuf>,
    /// SID of the installing user; granted access to the named pipe and the
    /// data directory.
    pub user_sid: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            response: ResponseConfig::default(),
            pinning: PinningConfig::default(),
            transcripts: TranscriptConfig::default(),
            alerts: AlertConfig::default(),
            retention_days: 14,
            rule_dirs: Vec::new(),
            agent_files: Vec::new(),
            classifier: false,
            user_profile: None,
            user_sid: None,
        }
    }
}

impl Config {
    /// Loads `path`, or returns defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| ConfigError::Parse(path.display().to_string(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError::Read(path.display().to_string(), e)),
        }
    }

    /// Writes the configuration atomically (temp file + rename).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = format!(
            "# Rousseau configuration. Rewritten by `rousseau ui` Settings; see docs/architecture.md.\n{}",
            toml::to_string_pretty(self)?
        );
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).map_err(|e| ConfigError::Write(tmp.display().to_string(), e))?;
        std::fs::rename(&tmp, path).map_err(|e| ConfigError::Write(path.display().to_string(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rousseau.toml");
        let c = Config::load(&p).unwrap();
        assert_eq!(c.response.mode, ResponseMode::Observe);
        assert!(!c.transcripts.claude_code, "transcripts are opt-in");
        let mut c2 = c.clone();
        c2.response.mode = ResponseMode::Enforce;
        c2.alerts.discord_webhook = Some("https://example.invalid/hook".into());
        c2.save(&p).unwrap();
        assert_eq!(Config::load(&p).unwrap(), c2);
    }

    #[test]
    fn partial_file() {
        let c: Config = toml::from_str("retention_days = 3\n[response]\nmode = \"alert\"\n").unwrap();
        assert_eq!(c.retention_days, 3);
        assert_eq!(c.response.mode, ResponseMode::Alert);
        assert_eq!(c.response.block_findings_at, Severity::High);
    }
}
