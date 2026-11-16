use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "leaktap",
    version,
    about = "See what your AI coding CLIs actually leak — offline log/plugin/MCP scanner, terminal UI, and live CLI wiretap.",
    long_about = "leaktap is built for AI coding CLIs — Claude Code, Codex CLI, Antigravity CLI, and Gemini CLI — plus local MCP servers and marketplace plugins.\n\nQuickstart:\n  leaktap          Scan local chat logs, MCP configs, and installed plugins/hooks/skills\n  leaktap ui       Open the interactive 3-tab terminal UI\n  leaktap claude   Start Claude Code with live API, env, and socket watching\n  leaktap codex    Start Codex CLI with live API, env, and socket watching\n  leaktap agy      Start Antigravity CLI with live env and socket watching"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Offline check of local AI chat logs, MCP configs, and installed plugins/hooks/skills (default)
    Scan(ScanArgs),

    /// Scrub leaked secrets from local AI chat logs (safe preview by default)
    Clean(CleanArgs),

    /// Open the interactive terminal dashboard (transcripts, MCP/plugin risks, and live wiretap stream)
    Ui(UiArgs),

    /// Start Claude Code (`claude`) with live API inspection, env scrubbing, and socket watching
    Claude(DirectCliArgs),

    /// Start Codex CLI (`codex`) with live API inspection, env scrubbing, and socket watching
    Codex(DirectCliArgs),

    /// Start Antigravity CLI (`agy`) with live API inspection, env scrubbing, and socket watching
    Agy(DirectCliArgs),

    /// Start Gemini CLI (`gemini`) with live API inspection, env scrubbing, and socket watching
    Gemini(DirectCliArgs),

    /// Wrap any CLI or MCP server command with custom wiretap flags
    Tap(TapArgs),

    /// List all built-in secret, privacy, header, plugin, and MCP detection rules
    Rules,
}

#[derive(Debug, Clone, Parser)]
#[command(
    trailing_var_arg = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct DirectCliArgs {
    /// Arguments passed straight through to the wrapped CLI
    #[arg(allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Parser)]
pub struct ScanArgs {
    /// Specific file(s) or folder(s) to scan (defaults to ~/.claude, ~/.codex, ~/.cursor, ~/.gemini + workspace configs)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Output format: terminal receipt, JSON, or SARIF 2.1.0 for CI
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Skip personal/internal metadata checks (emails and internal *.corp/*.internal hostnames)
    #[arg(long)]
    pub no_pii: bool,

    /// Skip MCP, plugin, hook, and skill checks
    #[arg(long)]
    pub no_mcp: bool,

    /// Exit with code 1 if any finding meets or exceeds this severity (useful in CI)
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
    /// Specific file(s) or folder(s) to clean (defaults to auto-discovered agent session folders)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Write scrubbed files to disk (without --apply, runs a safe read-only preview)
    #[arg(long)]
    pub apply: bool,

    /// Skip creating `<file>.leaktap.bak` backups when --apply is set
    #[arg(long)]
    pub no_backup: bool,
}

#[derive(Debug, Clone, Parser)]
pub struct UiArgs {
    /// Specific file(s) or folder(s) to inspect in the dashboard
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Custom live wiretap JSONL file to tail (defaults to ~/.leaktap/live.jsonl)
    #[arg(long)]
    pub log: Option<PathBuf>,

    /// Render a single dashboard snapshot to stdout and exit (useful for scripts/tests)
    #[arg(long)]
    pub once: bool,
}

#[derive(Debug, Clone, Parser)]
#[command(trailing_var_arg = true)]
pub struct TapArgs {
    /// Strip secret-looking shell environment variables before starting the child command
    #[arg(long)]
    pub scrub_env: bool,

    /// Keep all inherited environment variables even when using a CLI shorthand
    #[arg(long)]
    pub no_scrub_env: bool,

    /// Comma-separated environment variables to keep when --scrub-env is enabled
    #[arg(long, value_delimiter = ',')]
    pub allow_env: Vec<String>,

    /// Route ANTHROPIC_BASE_URL / OPENAI_BASE_URL / GOOGLE_GEMINI_BASE_URL through a local zero-cert loopback tap to inspect outgoing HTTP headers and prompt bodies
    #[arg(long)]
    pub inspect_api: bool,

    /// Disable local loopback HTTP API inspection
    #[arg(long)]
    pub no_inspect_api: bool,

    /// Disable background OS TCP socket polling for the child process tree
    #[arg(long)]
    pub no_net_watch: bool,

    /// Do not append events to ~/.leaktap/live.jsonl (used by `leaktap ui`)
    #[arg(long)]
    pub no_live_log: bool,

    /// Write JSONL wiretap events to an explicit file path
    #[arg(long)]
    pub log: Option<PathBuf>,

    /// Suppress live stderr alert lines
    #[arg(long, short)]
    pub quiet: bool,

    /// CLI or MCP server command and arguments to wrap
    #[arg(required = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl TapArgs {
    pub fn for_direct_cli(program: &str, extra_args: Vec<String>) -> Self {
        let mut command = Vec::with_capacity(extra_args.len() + 1);
        command.push(program.to_string());
        command.extend(extra_args);
        Self {
            scrub_env: true,
            no_scrub_env: false,
            allow_env: Vec::new(),
            inspect_api: true,
            no_inspect_api: false,
            no_net_watch: false,
            no_live_log: false,
            log: None,
            quiet: false,
            command,
        }
    }
}
