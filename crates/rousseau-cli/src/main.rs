//! `rousseau.exe`: endpoint detection and response for AI coding agents.

#[cfg(not(windows))]
compile_error!("rousseau.exe targets Windows (x86_64/aarch64-pc-windows-msvc)");

mod commands;
mod host;
mod notify;
mod paths;
mod pipe;
mod service;
mod winsec;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Endpoint detection and response for AI coding agents on Windows.
#[derive(Debug, Parser)]
#[command(name = "rousseau", version, about, propagate_version = true)]
pub struct Cli {
    /// Data directory (database and rousseau.toml). Default: %ProgramData%\Rousseau.
    #[arg(long, global = true, env = "ROUSSEAU_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// More logging (-v info, -vv debug).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}

/// Response mode on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Mode {
    Observe,
    Alert,
    Enforce,
}

impl From<Mode> for rousseau_core::rules::ResponseMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Observe => Self::Observe,
            Mode::Alert => Self::Alert,
            Mode::Enforce => Self::Enforce,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run sensors, rules and the dashboard in the foreground (elevated terminal for ETW).
    Run {
        /// Override the configured response mode for this run.
        #[arg(long, value_enum)]
        mode: Option<Mode>,
        /// Do not start the dashboard.
        #[arg(long)]
        headless: bool,
        /// Do not open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Dashboard port (0 = random).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Extra agent signature file(s) (agents.toml format).
        #[arg(long = "agents")]
        agents: Vec<PathBuf>,
    },
    /// Register the LocalSystem sensor service (run elevated).
    Install,
    /// Remove the sensor service.
    Uninstall {
        /// Also delete the data directory.
        #[arg(long)]
        purge: bool,
    },
    /// Open the dashboard (connects to the running sensor).
    Ui {
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_browser: bool,
    },
    /// Run a stdio MCP server through the Rousseau proxy.
    Wrap {
        /// Server name used for pinning and in the dashboard.
        #[arg(long)]
        name: String,
        /// Override the configured response mode.
        #[arg(long, value_enum)]
        mode: Option<Mode>,
        /// The server command and its arguments.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Run a local reverse proxy for a Streamable HTTP MCP server.
    WrapHttp {
        #[arg(long)]
        name: String,
        /// Upstream MCP endpoint, e.g. https://example.com/mcp.
        #[arg(long)]
        upstream: String,
        /// Local port (0 = random; set a fixed port for client configs).
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, value_enum)]
        mode: Option<Mode>,
    },
    /// Rewrite MCP client configs so stdio servers launch through `rousseau wrap`.
    Protect {
        /// Project directories with project-level configs (default: current directory).
        #[arg(long = "project")]
        projects: Vec<PathBuf>,
        /// Show the changes without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore MCP client configs changed by `protect`.
    Unprotect {
        #[arg(long)]
        dry_run: bool,
    },
    /// Check privileges, sensors, storage, agents and MCP configs.
    Doctor,
    /// Export a session as a portable .rousseau bundle.
    Export {
        /// Session id, or `latest`.
        #[arg(long)]
        session: String,
        /// Output file.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Load a .rousseau bundle into a read-only dashboard.
    Replay {
        bundle: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_browser: bool,
    },
    /// List or validate detection rules.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// List running AI agents recognised by the signature table.
    Agents,
    /// Resume processes suspended by an enforce-mode rule.
    Resume {
        #[arg(required = true)]
        pids: Vec<u32>,
    },
    /// Service entry point (used by the Service Control Manager).
    #[command(hide = true)]
    Service,
}

#[derive(Debug, Subcommand)]
pub enum RulesAction {
    /// List loaded rules.
    List,
    /// Validate rule files or directories.
    Validate { paths: Vec<PathBuf> },
}

fn init_logging(verbose: u8, to_file: Option<PathBuf>) {
    use tracing_subscriber::EnvFilter;
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_env("ROUSSEAU_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    match to_file.and_then(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok()) {
        Some(f) => builder.with_ansi(false).with_writer(std::sync::Mutex::new(f)).init(),
        // stdout carries MCP traffic for `wrap`, so logs always go to stderr.
        None => builder.with_writer(std::io::stderr).init(),
    }
}

fn main() {
    let cli = Cli::parse();
    let paths = paths::Paths::resolve(cli.data_dir.clone());
    if matches!(cli.command, Command::Service) {
        let _ = paths.ensure();
        init_logging(cli.verbose.max(1), Some(paths.data.join("rousseau-service.log")));
        if let Err(e) = service::run_dispatcher(paths.data.clone()) {
            eprintln!("rousseau service: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    init_logging(cli.verbose, None);
    rousseau_mcp::install_crypto_provider();
    let code = match commands::dispatch(cli, paths) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rousseau: {e:#}");
            1
        }
    };
    // Exit explicitly: blocking stdin readers (wrap) must not keep the
    // process alive after the work is done.
    std::process::exit(code);
}
