use crate::cleaner::CleanSummary;
use crate::report::FullScanReport;
use crate::rules::{RuleEngine, Severity};
use std::env;
use std::io::{self, IsTerminal};

struct Style {
    color: bool,
}

impl Style {
    fn detect() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some()
            || env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
        let is_tty = io::stdout().is_terminal();
        Self {
            color: is_tty && !no_color,
        }
    }

    fn bold(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn dim(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn red(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1;31m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn yellow(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1;33m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn cyan(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1;36m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn green(&self, s: &str) -> String {
        if self.color {
            format!("\x1b[1;32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

pub fn render_scan_terminal(report: &FullScanReport) -> String {
    let st = Style::detect();
    let mut out = String::new();

    let version = env!("CARGO_PKG_VERSION");
    out.push_str(&format!(
        "{} {}\n",
        st.bold(&format!("leaktap v{version}")),
        st.dim("— local offline audit (0 network requests)")
    ));

    let total_files = report.transcripts.files_scanned + report.mcp_files_scanned;
    let size_str = format_bytes(report.transcripts.bytes_scanned + report.mcp_bytes_scanned);
    let ms = report.duration.as_millis();

    if report.roots.is_empty() && total_files == 0 {
        out.push_str(&format!(
            "{}\n\n{}\n",
            st.dim("No local agent session directories (~/.claude, ~/.codex, ~/.cursor, ~/.gemini) or MCP configs found."),
            "Tip: pass `--path <dir>` to scan a specific project or transcript directory."
        ));
        return out;
    }

    let roots_label = if report.roots.is_empty() {
        "workspace MCP & instruction configs".to_string()
    } else {
        report.roots.join(", ")
    };

    out.push_str(&format!(
        "Scanned {} file(s) ({}) in {}ms across {}\n\n",
        total_files, size_str, ms, roots_label
    ));

    // Section 1: Leaked secrets
    if !report.transcripts.secret_findings.is_empty() {
        let count = report.transcripts.secret_findings.len();
        let max_sec_sev = report
            .transcripts
            .secret_findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::High);
        let sec_badge = format_severity_badge(&st, max_sec_sev);
        out.push_str(&format!("{sec_badge}  {count} unique secret(s) found\n"));

        let max_rows = 20usize;
        let shown = report.transcripts.secret_findings.len().min(max_rows);
        for (idx, f) in report.transcripts.secret_findings[..shown]
            .iter()
            .enumerate()
        {
            let branch = if idx + 1 == shown && report.transcripts.secret_findings.len() <= max_rows
            {
                "└─"
            } else {
                "├─"
            };
            let sev_str = f.severity.as_str();
            let rule_label = match f.secret_key.as_deref() {
                Some(key) if !key.is_empty() => format!("{} ({key})", f.rule_name),
                _ => f.rule_name.clone(),
            };
            let meta_note = if f.distinct_files > 1 {
                format!(
                    " ({}x across {} files) [{sev_str}] [fp:{}]",
                    f.occurrences, f.distinct_files, f.fingerprint
                )
            } else if f.occurrences > 1 {
                format!(" ({}x) [{sev_str}] [fp:{}]", f.occurrences, f.fingerprint)
            } else {
                format!(" [{sev_str}] [fp:{}]", f.fingerprint)
            };
            out.push_str(&format!(
                "  {branch} {:<20} {:<22} {}:{}{}\n",
                rule_label,
                st.yellow(&f.masked),
                f.first_file,
                f.first_line,
                st.dim(&meta_note)
            ));
        }
        if report.transcripts.secret_findings.len() > max_rows {
            out.push_str(&format!(
                "  └─ ... +{} more secret(s) (use `--format json` for full list)\n",
                report.transcripts.secret_findings.len() - max_rows
            ));
        }
        out.push('\n');
    }

    // Section 2: MCP server, plugin, hook, and skill issues
    if !report.mcp_findings.is_empty() {
        let max_mcp_sev = report
            .mcp_findings
            .iter()
            .map(|m| m.severity)
            .max()
            .unwrap_or(Severity::Medium);
        let badge = format_severity_badge(&st, max_mcp_sev);
        out.push_str(&format!(
            "{badge}  {} MCP / plugin risk(s) detected\n",
            report.mcp_findings.len()
        ));

        for (idx, m) in report.mcp_findings.iter().enumerate() {
            let is_last = idx + 1 == report.mcp_findings.len();
            let branch = if is_last { "└─" } else { "├─" };
            let cont = if is_last { "   " } else { "│  " };
            let loc_str = if m.line > 0 {
                format!("{}:{}", m.config_file, m.line)
            } else {
                m.config_file.clone()
            };
            out.push_str(&format!(
                "  {branch} {} {}\n",
                st.bold(&m.server_name),
                st.dim(&format!(
                    "({loc_str}) [{} · {}] [fp:{}]",
                    m.severity.as_str(),
                    m.rule_id,
                    m.fingerprint
                ))
            ));
            out.push_str(&format!("  {cont}  {}\n", m.message));
        }
        out.push('\n');
    }

    // Section 3: Personal & internal metadata summary
    if !report.transcripts.pii_findings.is_empty() {
        let email_count = report
            .transcripts
            .pii_findings
            .iter()
            .filter(|f| f.rule_id == "pii-email")
            .count();
        let host_count = report
            .transcripts
            .pii_findings
            .iter()
            .filter(|f| f.rule_id == "internal-hostname")
            .count();
        let other_count = report
            .transcripts
            .pii_findings
            .len()
            .saturating_sub(email_count + host_count);
        let total_hits: usize = report
            .transcripts
            .pii_findings
            .iter()
            .map(|f| f.occurrences)
            .sum();

        out.push_str(&format!(
            "{}  Identity & internal metadata in scanned files\n",
            st.cyan("MEDIUM  ")
        ));
        let mut parts = Vec::new();
        if email_count > 0 {
            parts.push(format!("{email_count} email address(es)"));
        }
        if host_count > 0 {
            parts.push(format!("{host_count} internal hostname(s)"));
        }
        if other_count > 0 {
            parts.push(format!("{other_count} custom metadata match(es)"));
        }
        out.push_str(&format!(
            "  └─ {} appeared across {} hit(s)\n\n",
            parts.join(" + "),
            total_hits
        ));
    }

    if report.total_findings() == 0 {
        out.push_str(&format!(
            "{} 0 leaked secrets or risky MCP / plugin configs found.\n",
            st.green("✓ Clean —")
        ));
    } else {
        out.push_str(&format!("{}\n", st.bold("Next steps:")));
        out.push_str("  • Open interactive dashboard:    leaktap ui\n");
        if !report.transcripts.secret_findings.is_empty() {
            let mut has_text_secret = false;
            let mut has_sqlite_secret = false;
            for f in &report.transcripts.secret_findings {
                if f.locations.is_empty() {
                    if crate::scanner::is_sqlite_extension(&f.first_path) {
                        has_sqlite_secret = true;
                    } else {
                        has_text_secret = true;
                    }
                } else {
                    for loc in &f.locations {
                        if crate::scanner::is_sqlite_extension(&loc.path) {
                            has_sqlite_secret = true;
                        } else {
                            has_text_secret = true;
                        }
                    }
                }
            }
            if has_text_secret {
                out.push_str("  • Preview & scrub local logs:    leaktap clean --apply\n");
            }
            if has_sqlite_secret {
                out.push_str("  • Purge SQLite chat state:       clear session history inside the IDE/CLI (binary DBs are not rewritten in place)\n");
            }
        }
        out.push_str(
            "  • Start a watched CLI session:   leaktap --block-secrets claude   (or `codex` / `agy`)\n",
        );
    }

    out
}

pub fn render_clean_terminal(summary: &CleanSummary) -> String {
    let st = Style::detect();
    let mut out = String::new();

    if summary.total_redactions == 0 {
        if summary.uncleaned_sqlite_secrets > 0 {
            out.push_str(&format!(
                "{} 0 text files modified, but {} secret(s) remain inside {} binary SQLite/WAL file(s):\n",
                st.yellow("! Warning —"),
                summary.uncleaned_sqlite_secrets,
                summary.uncleaned_sqlite_files.len()
            ));
            for (idx, file) in summary.uncleaned_sqlite_files.iter().enumerate() {
                let branch = if idx + 1 == summary.uncleaned_sqlite_files.len() {
                    "└─"
                } else {
                    "├─"
                };
                out.push_str(&format!("  {branch} {file}\n"));
            }
            out.push_str(
                "SQLite state databases are not rewritten as raw text to avoid corrupting B-tree page offsets. Clear chat/session history inside the IDE/CLI (or remove the local state DB while the app is closed).\n",
            );
            return out;
        }
        out.push_str(&format!(
            "{} Inspected {} file(s); 0 exposed secrets needed redaction.\n",
            st.green("✓ Clean —"),
            summary.files_inspected
        ));
        if !summary.skipped_binary_files.is_empty() {
            out.push_str(&format!(
                "{}\n",
                st.dim(&format!(
                    "Note: skipped {} binary/SQLite file(s) during text redaction.",
                    summary.skipped_binary_files.len()
                ))
            ));
        }
        return out;
    }

    let mode = if summary.applied {
        st.green("APPLIED")
    } else {
        st.yellow("DRY RUN (no files modified)")
    };

    out.push_str(&format!(
        "leaktap clean — {mode}\nRedactions: {} secret(s) across {} of {} file(s)\n\n",
        summary.total_redactions,
        summary.files_modified.len(),
        summary.files_inspected
    ));

    for (idx, item) in summary.files_modified.iter().enumerate() {
        let branch = if idx + 1 == summary.files_modified.len() {
            "└─"
        } else {
            "├─"
        };
        let bak_note = item
            .backup_file
            .as_ref()
            .map(|b| format!(" (0600 backup: {b})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {branch} {} — {} secret(s){}\n",
            item.display_file,
            item.secrets_redacted,
            st.dim(&bak_note)
        ));
    }

    if summary.uncleaned_sqlite_secrets > 0 {
        out.push_str(&format!(
            "\n{} {} secret(s) still remain inside {} binary SQLite/WAL file(s) ({}) — clear chat/session history inside the IDE/CLI to purge binary DB rows.\n",
            st.yellow("! Warning:"),
            summary.uncleaned_sqlite_secrets,
            summary.uncleaned_sqlite_files.len(),
            summary.uncleaned_sqlite_files.join(", ")
        ));
    } else if !summary.skipped_binary_files.is_empty() {
        out.push_str(&format!(
            "\n{}\n",
            st.dim(&format!(
                "Note: skipped {} binary/SQLite file(s) ({}) — use CLI session clear commands to purge binary DB rows.",
                summary.skipped_binary_files.len(),
                summary.skipped_binary_files.join(", ")
            ))
        ));
    }

    if !summary.applied {
        out.push_str(&format!(
            "\nRun {} to scrub these files in place without leaving plaintext backup copies on disk (pass `--backup` if you want `0600` `.leaktap.bak` copies).\n",
            st.bold("`leaktap clean --apply`")
        ));
    }

    out
}

pub fn render_rules_terminal(engine: &RuleEngine) -> String {
    let st = Style::detect();
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n",
        st.bold("Detection Rules (Transcripts, SQLite State & Live Wiretap)")
    ));
    for r in engine.rules() {
        out.push_str(&format!(
            "  {:<9} {:<27} {}\n",
            r.severity.as_str(),
            r.id,
            st.dim(&r.description)
        ));
    }
    out.push_str(&format!(
        "\n{}\n\n",
        st.bold("Built-in MCP, Plugin, Hook & Skill Rules")
    ));
    let mcp_rules = [
        (
            "CRITICAL",
            "mcp-hardcoded-secret",
            "Plaintext secret or token stored inside MCP `env`, `args`, or `headers`.",
        ),
        (
            "CRITICAL",
            "mcp-remote-code-exec",
            "MCP server command downloads and executes remote payloads (`curl | sh`, `eval`, etc.).",
        ),
        (
            "CRITICAL",
            "mcp-credential-harvest",
            "MCP server command directly reads `~/.ssh`, `~/.aws`, keychain, or CLI auth stores.",
        ),
        (
            "HIGH",
            "mcp-inline-code-exec",
            "MCP server executes inline `npx -c` / `python -c` / `node -e` code.",
        ),
        (
            "HIGH",
            "mcp-unpinned-package",
            "Unpinned `npx -y` / `uvx` / `uv run --with` / `bunx` package executing mutable registry code.",
        ),
        (
            "HIGH",
            "mcp-unrestricted-shell",
            "MCP server exposing raw unrestricted shell execution or privileged container flags.",
        ),
        (
            "HIGH",
            "mcp-broad-filesystem",
            "MCP server granted `/`, `~`, or sensitive directories (`~/.ssh`, `~/.aws`, `/etc`, `docker.sock`).",
        ),
        (
            "HIGH",
            "mcp-plaintext-http",
            "Remote MCP server connected over unencrypted `http://`.",
        ),
        (
            "HIGH",
            "mcp-oversized-config",
            "MCP config exceeding the 16 MiB structured AST limit.",
        ),
        (
            "MEDIUM",
            "mcp-telemetry-endpoint",
            "MCP config referencing known third-party telemetry/analytics endpoints.",
        ),
        (
            "CRITICAL",
            "plugin-remote-code-exec",
            "Plugin, hook, or skill executing piped, encoded, or dynamically fetched remote code.",
        ),
        (
            "CRITICAL",
            "plugin-credential-harvest",
            "Plugin, hook, or skill reading `~/.ssh`, `~/.aws`, `~/.npmrc`, `~/.config/gh`, or keychain.",
        ),
        (
            "CRITICAL",
            "plugin-env-exfiltration",
            "Plugin, hook, MCP script, or skill exfiltrating `process.env` / `os.environ` / API keys over the network.",
        ),
        (
            "CRITICAL",
            "plugin-hardcoded-secret",
            "Live API key or credential bundled inside an installed plugin, hook, or skill.",
        ),
        (
            "CRITICAL",
            "plugin-env-code-exec",
            "Settings overriding `NODE_OPTIONS`, `LD_PRELOAD`, `BASH_ENV`, `GIT_SSH_COMMAND`, or workspace `PATH`.",
        ),
        (
            "CRITICAL",
            "plugin-api-base-override",
            "Settings redirecting LLM base URLs, `HTTPS_PROXY`, custom CA bundles, or disabling TLS checks.",
        ),
        (
            "HIGH",
            "plugin-workspace-hook-exec",
            "Workspace settings registering an automatic shell or helper command hook.",
        ),
        (
            "HIGH",
            "plugin-hook-network",
            "Lifecycle hook (`PreToolUse`, `SessionStart`, etc.) making outbound network calls.",
        ),
        (
            "HIGH",
            "plugin-prompt-injection",
            "Skill or instruction file (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.windsurf/rules`, `.clinerules`) with stealth overrides or exfil commands.",
        ),
        (
            "HIGH",
            "plugin-oversized-config",
            "Plugin or workspace JSON config exceeding the 16 MiB structured AST limit.",
        ),
        (
            "HIGH",
            "plugin-telemetry-endpoint",
            "Plugin manifest, hook, or script referencing third-party analytics endpoints.",
        ),
    ];
    for (sev, id, desc) in mcp_rules {
        out.push_str(&format!("  {sev:<9} {id:<27} {}\n", st.dim(desc)));
    }

    out.push_str(&format!(
        "\n{}\n\n",
        st.bold("Built-in Live HTTP Header, Prompt Blocking & Socket Wiretap Rules (`tap`)")
    ));
    let live_rules = [
        (
            "CRITICAL",
            "header-secret-leak",
            "Non-provider secret or leaked token sent inside an outgoing HTTP header (blocked under `--block-secrets`).",
        ),
        (
            "HIGH",
            "header-email-leak",
            "Developer email address embedded inside `User-Agent` or custom HTTP headers.",
        ),
        (
            "MEDIUM",
            "header-os-username",
            "Local OS username exposed inside outgoing HTTP headers.",
        ),
        (
            "MEDIUM",
            "header-machine-hostname",
            "Local machine hostname exposed inside outgoing HTTP headers.",
        ),
        (
            "MEDIUM",
            "tcp-connection",
            "Outbound TCP connection opened by the wrapped CLI or child MCP/hook process (with PID & cmdline).",
        ),
        (
            "MEDIUM",
            "udp-connection",
            "Connected outbound UDP socket opened by the wrapped CLI or child MCP/hook process (with PID & cmdline).",
        ),
    ];
    for (sev, id, desc) in live_rules {
        out.push_str(&format!("  {sev:<9} {id:<27} {}\n", st.dim(desc)));
    }
    out
}

fn format_severity_badge(st: &Style, sev: Severity) -> String {
    match sev {
        Severity::Critical => st.red("CRITICAL"),
        Severity::High => st.yellow("HIGH    "),
        Severity::Medium => st.cyan("MEDIUM  "),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}
