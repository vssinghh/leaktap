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
    let size_str = format_bytes(report.transcripts.bytes_scanned);
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
        "workspace MCP configs".to_string()
    } else {
        report.roots.join(", ")
    };

    out.push_str(&format!(
        "Scanned {} file(s) ({}) in {}ms across {}\n\n",
        total_files, size_str, ms, roots_label
    ));

    // Section 1: Leaked secrets in transcripts
    if !report.transcripts.secret_findings.is_empty() {
        let count = report.transcripts.secret_findings.len();
        out.push_str(&format!(
            "{}  {} unique secret(s) found in local agent transcripts\n",
            st.red("CRITICAL"),
            count
        ));

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
            let repeat_note = if f.occurrences > 1 {
                format!(" ({}x)", f.occurrences)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {branch} {:<20} {:<22} {}:{}{}\n",
                f.rule_name,
                st.yellow(&f.masked),
                f.first_file,
                f.first_line,
                st.dim(&repeat_note)
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

    // Section 2: MCP server configuration issues
    if !report.mcp_findings.is_empty() {
        let has_crit = report
            .mcp_findings
            .iter()
            .any(|m| m.severity == Severity::Critical);
        let badge = if has_crit {
            st.red("CRITICAL")
        } else {
            st.yellow("HIGH    ")
        };
        out.push_str(&format!(
            "{badge}  {} MCP configuration risk(s) detected\n",
            report.mcp_findings.len()
        ));

        for (idx, m) in report.mcp_findings.iter().enumerate() {
            let is_last = idx + 1 == report.mcp_findings.len();
            let branch = if is_last { "└─" } else { "├─" };
            let cont = if is_last { "   " } else { "│  " };
            out.push_str(&format!(
                "  {branch} {} {}\n",
                st.bold(&m.server_name),
                st.dim(&format!("({})", m.config_file))
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
        let total_hits: usize = report
            .transcripts
            .pii_findings
            .iter()
            .map(|f| f.occurrences)
            .sum();

        out.push_str(&format!(
            "{}  Identity & internal metadata in outbound context\n",
            st.cyan("MEDIUM  ")
        ));
        let mut parts = Vec::new();
        if email_count > 0 {
            parts.push(format!("{email_count} email address(es)"));
        }
        if host_count > 0 {
            parts.push(format!("{host_count} internal hostname(s)"));
        }
        out.push_str(&format!(
            "  └─ {} appeared across {} transcript hit(s)\n\n",
            parts.join(" + "),
            total_hits
        ));
    }

    if report.total_findings() == 0 {
        out.push_str(&format!(
            "{} 0 leaked secrets or risky MCP configs found.\n",
            st.green("✓ Clean —")
        ));
    } else {
        out.push_str(&format!("{}\n", st.bold("Next steps:")));
        if !report.transcripts.secret_findings.is_empty() {
            out.push_str("  • Preview local log redaction:   leaktap clean\n");
            out.push_str("  • Apply redaction with backup:   leaktap clean --apply\n");
        }
        out.push_str("  • Wiretap a live agent session:  leaktap tap --scrub-env -- claude\n");
    }

    out
}

pub fn render_clean_terminal(summary: &CleanSummary) -> String {
    let st = Style::detect();
    let mut out = String::new();

    if summary.total_redactions == 0 {
        out.push_str(&format!(
            "{} Inspected {} file(s); 0 exposed secrets needed redaction.\n",
            st.green("✓ Clean —"),
            summary.files_inspected
        ));
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
            .map(|b| format!(" (backup: {b})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {branch} {} — {} secret(s){}\n",
            item.display_file,
            item.secrets_redacted,
            st.dim(&bak_note)
        ));
    }

    if !summary.applied {
        out.push_str(&format!(
            "\nRun {} to write these redactions to disk (creates `.leaktap.bak` backups by default).\n",
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
        st.bold("Built-in Detection Rules (Transcripts & Live Wiretap)")
    ));
    for r in engine.rules() {
        out.push_str(&format!(
            "  {:<9} {:<24} {}\n",
            r.severity.as_str(),
            r.id,
            st.dim(r.description)
        ));
    }
    out.push_str(&format!(
        "\n{}\n\n",
        st.bold("Built-in MCP Configuration Rules")
    ));
    let mcp_rules = [
        (
            "CRITICAL",
            "mcp-hardcoded-secret",
            "Plaintext secret or token stored inside MCP `env` or `headers`.",
        ),
        (
            "HIGH",
            "mcp-unpinned-package",
            "Unpinned `npx -y` / `uvx` package executing latest remote registry code.",
        ),
        (
            "HIGH",
            "mcp-unrestricted-shell",
            "MCP server exposing raw unrestricted shell execution.",
        ),
        (
            "HIGH",
            "mcp-broad-filesystem",
            "MCP server granted root (`/`) or full home (`~`) directory access.",
        ),
        (
            "HIGH",
            "mcp-plaintext-http",
            "Remote MCP server connected over unencrypted `http://`.",
        ),
        (
            "HIGH",
            "mcp-telemetry-endpoint",
            "MCP config referencing known third-party telemetry/analytics endpoints.",
        ),
    ];
    for (sev, id, desc) in mcp_rules {
        out.push_str(&format!("  {sev:<9} {id:<24} {}\n", st.dim(desc)));
    }
    out
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
