use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "leaktap",
    version,
    about = "See what your AI coding agents actually leak — local secret & MCP auditor + live session wiretap.",
    long_about = "leaktap audits local AI coding agent transcripts (Claude Code, Codex, Cursor, Gemini CLI)\nand MCP server configs completely offline, cleans exposed credentials from local logs,\nand wiretaps live agent/MCP stdio sessions."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Offline audit of local AI agent transcripts and MCP server configurations (default)
    Scan(ScanArgs),

    /// Redact exposed secrets from local AI session transcripts (dry-run by default)
    Clean(CleanArgs),

    /// Wiretap a live AI coding agent or MCP stdio server for secrets, env leaks, and outbound URLs
    Tap(TapArgs),

    /// List all built-in secret, PII, and MCP security detection rules
    Rules,
}

#[derive(Debug, Clone, Parser)]
pub struct ScanArgs {
    /// Specific file(s) or directory(ies) to scan (defaults to ~/.claude, ~/.codex, ~/.cursor, ~/.gemini + workspace MCP configs)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Output format: terminal receipt, structured JSON, or SARIF 2.1.0 for CI
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Skip personal/internal metadata checks (emails and internal *.corp/*.internal hostnames)
    #[arg(long)]
    pub no_pii: bool,

    /// Skip MCP configuration supply-chain and environment exposure checks
    #[arg(long)]
    pub no_mcp: bool,

    /// Exit with code 1 if any finding meets or exceeds this severity (useful in CI / pre-commit)
    #[arg(long, value_enum, default_value_t = FailThreshold::None)]
    pub fail_on: FailThreshold,
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            format: OutputFormat::Terminal,
            no_pii: false,
            no_mcp: false,
            fail_on: FailThreshold::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailThreshold {
    None,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Parser)]
pub struct CleanArgs {
    /// Specific file(s) or directory(ies) to clean (defaults to auto-discovered agent session directories)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Write redacted files to disk (without --apply, runs a safe read-only preview)
    #[arg(long)]
    pub apply: bool,

    /// Skip creating `<file>.leaktap.bak` backups when --apply is set
    #[arg(long)]
    pub no_backup: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct TapArgs {
    /// Strip secret-looking environment variables before spawning the child process
    #[arg(long)]
    pub scrub_env: bool,

    /// Comma-separated environment variables to preserve when --scrub-env is enabled
    #[arg(long, value_delimiter = ',')]
    pub allow_env: Vec<String>,

    /// Write structured JSONL wiretap alerts to a log file (safe for MCP stdio servers)
    #[arg(long)]
    pub log: Option<PathBuf>,

    /// Suppress live stderr alert lines (still writes to --log if configured)
    #[arg(long, short)]
    pub quiet: bool,

    /// Command and arguments to wrap (e.g. `leaktap tap -- claude`)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
