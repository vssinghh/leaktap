use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "leaktap",
    version,
    about = "See what your AI coding CLIs actually leak — offline log/plugin/MCP scanner, terminal UI, and live CLI wiretap.",
    long_about = "leaktap is built for AI coding CLIs — Claude Code, Codex CLI, Antigravity CLI, and Gemini CLI — plus local MCP servers and marketplace plugins.\n\nSecurity boundary: `leaktap` provides offline secret/MCP/plugin auditing and cooperative user-space DLP (`*_BASE_URL` proxy + env scrubbing + 10ms Linux / 1s macOS OS socket polling). It is not a kernel eBPF/network-namespace sandbox — pair with `bubblewrap`, `sandbox-exec`, or a container firewall when running untrusted code.\n\nQuickstart:\n  leaktap                          Scan local chat logs, SQLite state, MCP configs, and plugins/hooks/skills\n  leaktap scan --all               Scan both the current workspace repo and all user-home AI agent stores\n  leaktap scan --verify            Verify whether detected API keys/tokens are still live\n  leaktap scan --inspect-mcp       Query configured MCP servers for tool poisoning & schema rug-pulls\n  leaktap ui                       Open the interactive 4-tab terminal UI\n  leaktap claude                   Start Claude Code with live API, env, and socket watching\n  leaktap --block-secrets claude   Actively block outgoing prompts that contain leaked secrets\n  leaktap --redact-secrets claude  Scrub secrets to [REDACTED_BY_LEAKTAP] in-transit without interrupting the turn"
)]
pub struct Cli {
    /// Explicit path to a trusted `.leaktap.toml` or `.leaktapignore` policy file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Load trusted project `.leaktap.toml` and `.leaktapignore` from a git ref (e.g. `origin/main`) instead of the untrusted working tree
    #[arg(long, global = true)]
    pub policy_git_ref: Option<String>,

    /// Opt in to loading `.leaktap.toml`, `leaktap.toml`, and `.leaktapignore` from cwd or `--path` targets
    #[arg(long, global = true)]
    pub trust_project_config: bool,

    /// Ignore all policy and allowlist files (including `~/.config/leaktap/config.toml`)
    #[arg(long, global = true)]
    pub no_config: bool,

    /// Refresh stored MCP `tools/list` schema pins in `~/.local/share/leaktap/mcp_tool_pins.json` when a server upgrades
    #[arg(long, global = true)]
    pub update_mcp_pins: bool,

    /// Actively block outgoing LLM API requests (`HTTP 400`) when a secret is detected in the prompt or headers
    #[arg(long, global = true)]
    pub block_secrets: bool,

    /// Scrub detected secrets in-transit (`[REDACTED_BY_LEAKTAP]`) inside outgoing LLM API requests instead of blocking the turn
    #[arg(long, global = true)]
    pub redact_secrets: bool,

    /// Strip `SSH_AUTH_SOCK` and `SSH_AGENT_PID` before starting a wrapped CLI session
    #[arg(long, global = true)]
    pub scrub_ssh_agent: bool,

    /// Comma-separated environment variables to keep when `--scrub-env` is active (works with `leaktap --allow-env GH_TOKEN claude` or `tap`)
    #[arg(long, global = true, value_delimiter = ',')]
    pub allow_env: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Offline check of local AI chat logs, SQLite state, MCP configs, and installed plugins/hooks/skills (default)
    Scan(ScanArgs),

    /// Scrub leaked secrets from local AI chat logs (safe read-only preview unless --apply is set)
    Clean(CleanArgs),

    /// Open the interactive terminal dashboard (transcripts, MCP/plugin risks, live wiretap, and PII)
    Ui(UiArgs),

    /// Start Claude Code (`claude`) with live API inspection, env scrubbing, and socket watching
    Claude(DirectCliArgs),

    /// Start Codex CLI (`codex`) with live API inspection, env scrubbing, and socket watching
    Codex(DirectCliArgs),

    /// Start Antigravity CLI (`agy`) with live API inspection, env scrubbing, and socket watching
    Agy(DirectCliArgs),

    /// Start Gemini CLI (`gemini`) with live API inspection, env scrubbing, and socket watching
    Gemini(DirectCliArgs),

    /// Wrap any CLI or MCP server command with custom wiretap flags (cooperative DLP + user-space socket watch)
    #[command(
        long_about = "Wrap any CLI or MCP server command with environment scrubbing, cooperative `*_BASE_URL` HTTP API inspection (`--block-secrets` / `--redact-secrets`), passive stdio/API MCP tool poisoning checks, and user-space child socket telemetry (`10ms` Linux `/proc`, `1s` macOS `ps`+`lsof`).\n\nSecurity boundary: `tap` operates without root or kernel hooks. A hostile binary that ignores `*_BASE_URL` env vars or sends connectionless UDP/DNS packets can bypass user-space interception — run untrusted code inside `bubblewrap`, `sandbox-exec`, or a network-isolated container."
    )]
    Tap(TapArgs),

    /// List all built-in and configured secret, privacy, header, plugin, and MCP detection rules
    Rules(RulesArgs),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum RulesFormat {
    #[default]
    Text,
    Terminal,
    Json,
}

#[derive(Debug, Clone, Default, Parser)]
pub struct RulesArgs {
    /// Output format: text table (`text`) or machine-readable JSON (`json`)
    #[arg(short, long, value_enum, default_value_t = RulesFormat::Text)]
    pub format: RulesFormat,
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

#[derive(Debug, Clone, Default, Parser)]
pub struct ScanArgs {
    /// Specific file(s) or folder(s) to scan (defaults to ~/.claude, ~/.codex, ~/.cursor, ~/.gemini + workspace configs)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Scan both the full current workspace directory AND all user-home global AI agent directories together
    #[arg(long)]
    pub all: bool,

    /// Output format: terminal receipt, JSON, or SARIF 2.1.0 for CI
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Skip personal/internal metadata checks (emails and internal *.corp/*.internal hostnames)
    #[arg(long)]
    pub no_pii: bool,

    /// Skip MCP, plugin, hook, and skill checks
    #[arg(long)]
    pub no_mcp: bool,

    /// Actively check detected API keys/tokens against read-only provider endpoints to label `[VERIFIED ACTIVE]` vs `[unverified/inactive]`
    #[arg(long)]
    pub verify: bool,

    /// Actively query configured MCP servers (`initialize` + `tools/list`, 4s timeout) for live tool poisoning and schema rug-pulls
    #[arg(long)]
    pub inspect_mcp: bool,

    /// Ignore inline `# leaktap:ignore` / `// leaktap:allow` suppression comments in scanned text files
    #[arg(long)]
    pub no_inline_ignore: bool,

    /// Exit with code 1 if any finding meets or exceeds this severity (default `none` exits 0 for interactive use; pass `--fail-on high` or `--fail-on medium` in CI/pre-commit)
    #[arg(long, value_enum, default_value_t = FailThreshold::None)]
    pub fail_on: FailThreshold,

    /// Scan staged git diff additions (`git diff --cached -U0`) for pre-commit secret & config checks
    #[arg(long)]
    pub staged: bool,

    /// Scan git commit history patches across all refs (`git log --all -p -U0`) for historical leaks
    #[arg(long)]
    pub git_history: bool,

    /// Optional cap on the number of git commits scanned when `--git-history` is enabled (scans full history by default)
    #[arg(long)]
    pub max_commits: Option<usize>,

    /// Optional `.leaktap.toml` policy file path
    #[arg(skip)]
    pub config: Option<PathBuf>,

    /// Optional git ref to load trusted project policy from
    #[arg(skip)]
    pub policy_git_ref: Option<String>,

    /// Opt in to loading project/target `.leaktap.toml` and `.leaktapignore`
    #[arg(skip)]
    pub trust_project_config: bool,

    /// Ignore all policy files
    #[arg(skip)]
    pub no_config: bool,

    /// Refresh stored MCP `tools/list` schema pins
    #[arg(skip)]
    pub update_mcp_pins: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum FailThreshold {
    #[default]
    None,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Default, Parser)]
pub struct CleanArgs {
    /// Specific file(s) or folder(s) to clean (defaults to auto-discovered agent session folders)
    #[arg(short, long = "path")]
    pub paths: Vec<PathBuf>,

    /// Write scrubbed files to disk (without --apply, runs a safe read-only preview)
    #[arg(long)]
    pub apply: bool,

    /// Scrub secrets in repository source code, configs, and Markdown docs in addition to session logs
    #[arg(long)]
    pub include_code: bool,

    /// Keep a `0600` `<file>.leaktap.bak` backup of the original unredacted file (off by default so raw secrets are not left on disk)
    #[arg(long)]
    pub backup: bool,

    /// Compatibility flag (no-backup is now the default so raw secrets are not left on disk)
    #[arg(long, hide = true)]
    pub no_backup: bool,

    /// Optional `.leaktap.toml` policy file path
    #[arg(skip)]
    pub config: Option<PathBuf>,

    /// Optional git ref to load trusted project policy from
    #[arg(skip)]
    pub policy_git_ref: Option<String>,

    /// Opt in to loading project/target `.leaktap.toml` and `.leaktapignore`
    #[arg(skip)]
    pub trust_project_config: bool,

    /// Ignore all policy files
    #[arg(skip)]
    pub no_config: bool,
}

#[derive(Debug, Clone, Default, Parser)]
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

    /// Allow `[c]` in the dashboard to scrub repository source code, configs, and docs (session logs only by default)
    #[arg(long)]
    pub include_code: bool,

    /// Optional `.leaktap.toml` policy file path
    #[arg(skip)]
    pub config: Option<PathBuf>,

    /// Optional git ref to load trusted project policy from
    #[arg(skip)]
    pub policy_git_ref: Option<String>,

    /// Opt in to loading project/target `.leaktap.toml` and `.leaktapignore`
    #[arg(skip)]
    pub trust_project_config: bool,

    /// Ignore all policy files
    #[arg(skip)]
    pub no_config: bool,
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

    /// Strip `SSH_AUTH_SOCK` and `SSH_AGENT_PID` from the child command environment
    #[arg(long)]
    pub scrub_ssh_agent: bool,

    /// Comma-separated environment variables to keep when --scrub-env is enabled
    #[arg(skip)]
    pub allow_env: Vec<String>,

    /// Route ANTHROPIC/OPENAI/GEMINI/OPENROUTER/DEEPSEEK/XAI/GROQ `*_BASE_URL` through a local zero-cert loopback tap
    #[arg(long)]
    pub inspect_api: bool,

    /// Disable local loopback HTTP API inspection
    #[arg(long)]
    pub no_inspect_api: bool,

    /// Reject outgoing LLM API requests (`HTTP 400`) when a secret is detected in the prompt or headers
    #[arg(skip)]
    pub block_secrets: bool,

    /// Scrub detected secrets to `[REDACTED_BY_LEAKTAP]` inside outgoing LLM API requests before forwarding upstream
    #[arg(skip)]
    pub redact_secrets: bool,

    /// Disable best-effort OS socket polling (`10ms` Linux `/proc`, `1s` macOS `ps`+`lsof`; TCP & connected UDP)
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

    /// Optional `.leaktap.toml` policy file path
    #[arg(skip)]
    pub config: Option<PathBuf>,

    /// Optional git ref to load trusted project policy from
    #[arg(skip)]
    pub policy_git_ref: Option<String>,

    /// Opt in to loading project/target `.leaktap.toml` and `.leaktapignore`
    #[arg(skip)]
    pub trust_project_config: bool,

    /// Ignore all policy files
    #[arg(skip)]
    pub no_config: bool,

    /// Refresh stored MCP `tools/list` schema pins
    #[arg(skip)]
    pub update_mcp_pins: bool,

    /// CLI or MCP server command and arguments to wrap
    #[arg(required = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl TapArgs {
    #[allow(clippy::too_many_arguments)]
    pub fn for_direct_cli(
        program: &str,
        extra_args: Vec<String>,
        block_secrets: bool,
        scrub_ssh_agent: bool,
        allow_env: Vec<String>,
        config: Option<PathBuf>,
        policy_git_ref: Option<String>,
        trust_project_config: bool,
        no_config: bool,
    ) -> Self {
        let mut command = Vec::with_capacity(extra_args.len() + 1);
        command.push(program.to_string());
        command.extend(extra_args);
        Self {
            scrub_env: true,
            no_scrub_env: false,
            scrub_ssh_agent,
            allow_env,
            inspect_api: true,
            no_inspect_api: false,
            block_secrets,
            redact_secrets: false,
            no_net_watch: false,
            no_live_log: false,
            log: None,
            quiet: false,
            config,
            policy_git_ref,
            trust_project_config,
            no_config,
            update_mcp_pins: false,
            command,
        }
    }
}
