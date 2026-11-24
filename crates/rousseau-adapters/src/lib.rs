//! Agent discovery and read-only transcript adapters.
//!
//! * [`agents`]: the embedded `agents.toml` signature table (plus user
//!   files) used to recognise agent processes.
//! * [`transcripts`]: opt-in readers for agents' own local session logs
//!   (Claude Code, Codex) that recover built-in tool use. They never write
//!   to or copy these files; only extracted tool-use metadata is emitted.

pub mod agents;
pub mod transcripts;
