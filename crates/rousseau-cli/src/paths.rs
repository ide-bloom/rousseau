//! Well-known locations.
//!
//! * Data directory (database, configuration): `%ProgramData%\Rousseau`,
//!   overridable with `--data-dir` or `ROUSSEAU_DATA_DIR`.
//! * Per-user state (the `protect` manifest): `%LOCALAPPDATA%\Rousseau`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rousseau_core::config::Config;
use rousseau_core::rules::{Rule, check_unique, parse_multi};
use rust_embed::RustEmbed;

/// Built-in rules compiled into the binary.
#[derive(RustEmbed)]
#[folder = "../../rules/"]
struct BuiltinRules;

/// Resolved locations for one invocation.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
}

impl Paths {
    /// Resolves the data directory.
    pub fn resolve(data_dir: Option<PathBuf>) -> Self {
        let data = data_dir.or_else(|| std::env::var_os("ROUSSEAU_DATA_DIR").map(PathBuf::from)).unwrap_or_else(|| {
            let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            base.join("Rousseau")
        });
        Self { data }
    }

    /// `rousseau.db`.
    pub fn db(&self) -> PathBuf {
        self.data.join("rousseau.db")
    }

    /// `rousseau.toml`.
    pub fn config(&self) -> PathBuf {
        self.data.join("rousseau.toml")
    }

    /// Creates the data directory if needed.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data).with_context(|| format!("cannot create {}", self.data.display()))
    }

    /// Loads the configuration (defaults if absent).
    pub fn load_config(&self) -> Result<Config> {
        Config::load(&self.config()).map_err(Into::into)
    }
}

/// Per-user state directory.
pub fn user_state_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("Rousseau")
}

/// Built-in rules followed by rules from `extra` directories.
pub fn load_rules(extra: &[PathBuf]) -> Result<Vec<Rule>> {
    let mut names: Vec<String> = BuiltinRules::iter().map(|n| n.into_owned()).collect();
    names.sort();
    let mut rules = Vec::new();
    for n in names {
        let Some(f) = BuiltinRules::get(&n) else { continue };
        let text = String::from_utf8_lossy(&f.data).into_owned();
        for mut r in parse_multi(&text, &n).with_context(|| format!("built-in rule file {n}"))? {
            r.path = Some(format!("builtin:{n}"));
            rules.push(r);
        }
    }
    for dir in extra {
        rules.extend(rousseau_core::rules::load_dir(dir).with_context(|| format!("rules in {}", dir.display()))?);
    }
    check_unique(&rules)?;
    Ok(rules)
}

/// Loads the agent table plus user files.
pub fn load_agents(files: &[PathBuf]) -> Result<rousseau_adapters::agents::AgentTable> {
    let mut t = rousseau_adapters::agents::AgentTable::embedded()?;
    for f in files {
        t.add_file(f)?;
    }
    Ok(t)
}

/// The path of the running executable (for `protect` and `install`).
pub fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("cannot determine the path of rousseau.exe")
}
