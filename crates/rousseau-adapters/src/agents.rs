//! Agent signature table.

use std::path::Path;

use regex::Regex;
use rousseau_core::event::ProcessInfo;
use rousseau_core::pipeline::AgentMatcher;
use rousseau_core::rules::condition::compile_glob;
use serde::Deserialize;

const EMBEDDED: &str = include_str!("agents.toml");

/// Errors loading agent tables.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("cannot read {0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("invalid agent table {0}: {1}")]
    Parse(String, String),
}

#[derive(Debug, Deserialize)]
struct RawTable {
    #[serde(default)]
    agent: Vec<RawAgent>,
}

#[derive(Debug, Deserialize)]
struct RawAgent {
    id: String,
    name: String,
    #[serde(default)]
    transcript: String,
    #[serde(default, rename = "match")]
    matches: Vec<RawMatch>,
}

#[derive(Debug, Deserialize, Default)]
struct RawMatch {
    #[serde(default)]
    exe: Vec<String>,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    not_path: Vec<String>,
    #[serde(default)]
    cmdline: Vec<String>,
    #[serde(default)]
    signer: Option<String>,
}

#[derive(Debug, Clone)]
struct Signature {
    exe: Vec<String>,
    path: Vec<Regex>,
    not_path: Vec<Regex>,
    cmdline: Vec<Regex>,
    signer: Option<String>,
}

/// One known agent.
#[derive(Debug, Clone)]
pub struct Agent {
    pub id: String,
    pub name: String,
    /// Transcript adapter name, or empty.
    pub transcript: String,
    signatures: Vec<Signature>,
}

impl Signature {
    fn matches(&self, p: &ProcessInfo) -> bool {
        let name = p.name.clone().unwrap_or_else(|| p.image.as_deref().map(rousseau_core::event::file_name_lower).unwrap_or_default());
        if !self.exe.is_empty() && !self.exe.contains(&name) {
            return false;
        }
        let image = p.image.as_deref().unwrap_or_default();
        if !self.path.is_empty() && !self.path.iter().any(|r| r.is_match(image)) {
            return false;
        }
        if self.not_path.iter().any(|r| r.is_match(image)) {
            return false;
        }
        if !self.cmdline.is_empty() {
            let cmd = p.command_line.as_deref().unwrap_or_default();
            if !self.cmdline.iter().any(|r| r.is_match(cmd)) {
                return false;
            }
        }
        if let (Some(want), Some(have)) = (&self.signer, &p.signer)
            && !have.to_lowercase().contains(&want.to_lowercase())
        {
            return false;
        }
        true
    }
}

/// The agent table (embedded entries first, then user files).
#[derive(Debug, Clone, Default)]
pub struct AgentTable {
    agents: Vec<Agent>,
}

impl AgentTable {
    /// The embedded table.
    pub fn embedded() -> Result<Self, AgentError> {
        let mut t = Self::default();
        t.add_toml(EMBEDDED, "agents.toml (embedded)")?;
        Ok(t)
    }

    /// Adds entries from TOML text. User entries are checked before the
    /// embedded ones so they can refine or override them.
    pub fn add_toml(&mut self, text: &str, origin: &str) -> Result<(), AgentError> {
        let raw: RawTable = toml::from_str(text).map_err(|e| AgentError::Parse(origin.into(), e.to_string()))?;
        let glob = |g: &String| compile_glob(g, false).map_err(|e| AgentError::Parse(origin.into(), e.to_string()));
        let mut new = Vec::new();
        for a in raw.agent {
            let mut signatures = Vec::new();
            for m in a.matches {
                signatures.push(Signature {
                    exe: m.exe.iter().map(|e| e.to_lowercase()).collect(),
                    path: m.path.iter().map(glob).collect::<Result<_, _>>()?,
                    not_path: m.not_path.iter().map(glob).collect::<Result<_, _>>()?,
                    cmdline: m.cmdline.iter().map(glob).collect::<Result<_, _>>()?,
                    signer: m.signer,
                });
            }
            if signatures.is_empty() {
                return Err(AgentError::Parse(origin.into(), format!("agent '{}' has no [[agent.match]]", a.id)));
            }
            new.push(Agent { id: a.id, name: a.name, transcript: a.transcript, signatures });
        }
        if self.agents.is_empty() {
            self.agents = new;
        } else {
            new.append(&mut self.agents);
            self.agents = new;
        }
        Ok(())
    }

    /// Adds entries from a file.
    pub fn add_file(&mut self, path: &Path) -> Result<(), AgentError> {
        let text = std::fs::read_to_string(path).map_err(|e| AgentError::Io(path.display().to_string(), e))?;
        self.add_toml(&text, &path.display().to_string())
    }

    /// All agents.
    pub fn agents(&self) -> &[Agent] {
        &self.agents
    }

    /// The first agent matching `p`.
    pub fn find(&self, p: &ProcessInfo) -> Option<&Agent> {
        self.agents.iter().find(|a| a.signatures.iter().any(|s| s.matches(p)))
    }
}

impl AgentMatcher for AgentTable {
    fn match_agent(&self, p: &ProcessInfo) -> Option<String> {
        self.find(p).map(|a| a.id.clone())
    }

    fn transcript_adapter(&self, label: &str) -> Option<String> {
        self.agents.iter().find(|a| a.id == label).map(|a| a.transcript.clone()).filter(|t| !t.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(image: &str, cmd: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 1,
            name: Some(rousseau_core::event::file_name_lower(image)),
            image: Some(image.into()),
            command_line: Some(cmd.into()),
            ..ProcessInfo::default()
        }
    }

    #[test]
    fn known_agents() {
        let t = AgentTable::embedded().unwrap();
        let cases = [
            (
                r"C:\Users\dev\AppData\Local\Microsoft\WinGet\Packages\Anthropic.ClaudeCode_Microsoft.Winget.Source_8wekyb3d8bbwe\claude.exe",
                "claude",
                Some("claude-code"),
            ),
            (r"C:\Users\dev\.local\bin\claude.exe", "claude --resume", Some("claude-code")),
            (r"C:\Users\dev\AppData\Local\AnthropicClaude\app-1.2.3\claude.exe", "claude.exe", Some("claude-desktop")),
            (
                r"C:\Program Files\nodejs\node.exe",
                r"node C:\Users\dev\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js",
                Some("claude-code"),
            ),
            (
                r"C:\Users\dev\AppData\Roaming\npm\node_modules\@openai\codex\vendor\x86_64-pc-windows-msvc\codex\codex.exe",
                "codex",
                Some("codex-cli"),
            ),
            (r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__abc\Codex.exe", "Codex.exe", Some("codex-app")),
            (r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe", "Cursor.exe", Some("cursor")),
            (r"C:\Users\dev\AppData\Local\Programs\Windsurf\Windsurf.exe", "", Some("windsurf")),
            (r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe", "", Some("vscode-copilot")),
            (r"C:\Program Files\nodejs\node.exe", r"node C:\npm\node_modules\@google\gemini-cli\dist\index.js", Some("gemini-cli")),
            (r"C:\Python313\python.exe", "python -m aider --model x", Some("aider")),
            (r"C:\Users\dev\.local\bin\aider.exe", "aider", Some("aider")),
            (r"C:\Users\dev\.opencode\bin\opencode.exe", "opencode", Some("opencode")),
            (r"C:\Users\dev\.local\bin\goose.exe", "goose session", Some("goose")),
            (r"C:\Program Files\nodejs\node.exe", "node server.js", None),
            (r"C:\Windows\System32\cmd.exe", "cmd", None),
        ];
        for (image, cmd, want) in cases {
            assert_eq!(t.match_agent(&proc(image, cmd)).as_deref(), want, "{image} {cmd}");
        }
        assert_eq!(t.transcript_adapter("claude-code").as_deref(), Some("claude-code"));
        assert_eq!(t.transcript_adapter("codex-app").as_deref(), Some("codex"));
        assert_eq!(t.transcript_adapter("cursor"), None);
    }

    #[test]
    fn signer_mismatch_rejects_when_verified() {
        let t = AgentTable::embedded().unwrap();
        let mut p = proc(r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe", "");
        p.signer = Some("Evil Corp".into());
        assert_eq!(t.match_agent(&p), None);
        p.signer = Some("Microsoft Corporation".into());
        assert_eq!(t.match_agent(&p).as_deref(), Some("vscode-copilot"));
    }

    #[test]
    fn user_entries_take_precedence() {
        let mut t = AgentTable::embedded().unwrap();
        t.add_toml("[[agent]]\nid = \"demo\"\nname = \"Demo\"\n[[agent.match]]\ncmdline = [\"*rousseau-demo-agent*\"]\n", "user").unwrap();
        assert_eq!(t.match_agent(&proc(r"C:\Python\python.exe", "python rousseau-demo-agent.py")).as_deref(), Some("demo"));
        assert!(t.add_toml("[[agent]]\nid = \"x\"\nname = \"X\"\n", "bad").is_err());
    }
}
