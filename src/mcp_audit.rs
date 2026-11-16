use crate::discovery::shorten_home;
use crate::rules::{
    fingerprint_match, is_likely_placeholder, mask_value, shannon_entropy, RuleCategory,
    RuleEngine, Severity,
};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct McpFinding {
    pub rule_id: &'static str,
    pub server_name: String,
    pub config_file: String,
    pub config_path: PathBuf,
    pub severity: Severity,
    pub message: String,
    pub fingerprint: String,
}

const TELEMETRY_DOMAINS: &[&str] = &[
    "posthog.com",
    "i.posthog.com",
    "segment.io",
    "api.segment.io",
    "mixpanel.com",
    "amplitude.com",
    "sentry.io",
    "ingest.sentry.io",
    "datadoghq.com",
    "google-analytics.com",
    "telemetry.",
    "events.",
];

const SENSITIVE_ENV_KEYWORDS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CREDENTIALS",
    "AUTH",
];

pub fn audit_mcp_configs(files: &[PathBuf], engine: &RuleEngine) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    for path in files {
        audit_single_mcp_file(path, engine, &mut findings);
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });
    findings
}

fn audit_single_mcp_file(path: &Path, engine: &RuleEngine, out: &mut Vec<McpFinding>) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let is_toml = path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"));
    let parsed: Option<Value> = if is_toml {
        toml::from_str::<Value>(&raw).ok()
    } else {
        crate::plugin_audit::parse_json_or_jsonc(&raw)
    };
    let Some(json) = parsed else {
        return;
    };

    let display = shorten_home(path);

    // 1. Top-level `mcpServers` (JSON), `mcp_servers` (Codex TOML), or `servers` (VS Code)
    for top_key in ["mcpServers", "mcp_servers", "servers"] {
        if let Some(servers) = json.get(top_key).and_then(|v| v.as_object()) {
            for (name, spec) in servers {
                inspect_server(name, spec, path, &display, engine, out);
            }
        }
    }

    // 2. Project-scoped MCP blocks (`projects.<workspace>.mcpServers` / `mcp_servers`)
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_proj_path, proj_val) in projects {
            for nested_key in ["mcpServers", "mcp_servers"] {
                if let Some(servers) = proj_val.get(nested_key).and_then(|v| v.as_object()) {
                    for (name, spec) in servers {
                        inspect_server(name, spec, path, &display, engine, out);
                    }
                }
            }
        }
    }
}

fn inspect_server(
    server_name: &str,
    spec: &Value,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let command = spec.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let args: Vec<&str> = spec
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();

    // Check 1: Unpinned remote package execution (`npx -y @foo/bar` or `uvx foo` without version pin)
    check_unpinned_execution(server_name, command, &args, path, display, out);

    // Check 2: Broad filesystem root/home access or unrestricted shell MCP
    check_broad_host_access(server_name, command, &args, path, display, out);

    // Check 3: Plaintext hardcoded secrets in `env` or `headers`
    check_hardcoded_credentials(server_name, spec, path, display, engine, out);

    // Check 4: Remote URL transport (insecure HTTP or external host) + telemetry domains
    check_network_and_telemetry(server_name, spec, &args, path, display, out);
}

fn check_unpinned_execution(
    server_name: &str,
    command: &str,
    args: &[&str],
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    let cmd_base = Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command);

    if matches!(cmd_base, "npx" | "bunx" | "uvx" | "pipx") {
        let has_auto_install = args.iter().any(|&a| a == "-y" || a == "--yes");
        // Find package specifier (first non-flag argument)
        let pkg_arg = args.iter().copied().find(|a| !a.starts_with('-'));

        if let Some(pkg) = pkg_arg {
            if pkg.starts_with('<') && pkg.ends_with('>') {
                return;
            }
            if !has_explicit_version_pin(pkg) {
                let msg = if has_auto_install {
                    format!(
                        "Runs unpinned `{cmd_base} -y {pkg}` — pulls latest remote code on start with local file/env access"
                    )
                } else {
                    format!(
                        "Runs unpinned `{cmd_base} {pkg}` without an exact version pin (e.g. `{pkg}@x.y.z`)"
                    )
                };
                out.push(McpFinding {
                    rule_id: "mcp-unpinned-package",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-unpinned-package",
                        &format!("{display}:{server_name}:{pkg}"),
                    ),
                    message: msg,
                });
            }
        }
    }
}

fn has_explicit_version_pin(pkg: &str) -> bool {
    // Python uvx/pipx pin (`pkg==1.2.3`)
    if pkg.contains("==") {
        return true;
    }
    // Scoped npm package: `@scope/name@1.2.3` vs `@scope/name` vs `@scope/name@latest`
    let version_suffix = if let Some(stripped) = pkg.strip_prefix('@') {
        stripped.split_once('@').map(|(_, ver)| ver)
    } else {
        pkg.split_once('@').map(|(_, ver)| ver)
    };

    match version_suffix {
        None => false,
        Some(ver) => {
            !ver.is_empty()
                && ver != "latest"
                && ver != "next"
                && ver != "main"
                && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
    }
}

fn check_broad_host_access(
    server_name: &str,
    command: &str,
    args: &[&str],
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    let joined = format!("{command} {}", args.join(" ")).to_ascii_lowercase();

    // Unrestricted shell MCP servers
    if joined.contains("mcp-shell")
        || joined.contains("server-shell")
        || joined.contains("shell-mcp")
        || joined.contains("mcp-server-bash")
        || matches!(command, "bash" | "sh" | "zsh" | "/bin/bash" | "/bin/sh")
            && args.iter().all(|a| !a.ends_with(".sh"))
    {
        out.push(McpFinding {
            rule_id: "mcp-unrestricted-shell",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            severity: Severity::High,
            fingerprint: fingerprint_match(
                "mcp-unrestricted-shell",
                &format!("{display}:{server_name}"),
            ),
            message: "Exposes unrestricted shell execution via MCP server".to_string(),
        });
    }

    // Filesystem root or entire home directory mounted into MCP server
    let home_str = crate::discovery::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    for &arg in args {
        let is_root = arg == "/" || arg == "C:\\" || arg == "c:\\";
        let is_full_home = arg == "~" || (!home_str.is_empty() && arg == home_str);
        if is_root || is_full_home {
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-broad-filesystem",
                    &format!("{display}:{server_name}:{arg}"),
                ),
                message: format!(
                    "Grants broad filesystem access (`{arg}`) instead of scoping to one workspace folder"
                ),
            });
        }
    }
}

fn check_hardcoded_credentials(
    server_name: &str,
    spec: &Value,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    for field in ["env", "headers", "http_headers"] {
        let Some(map) = spec.get(field).and_then(|v| v.as_object()) else {
            continue;
        };

        for (key, val_node) in map {
            let Some(val) = val_node.as_str() else {
                continue;
            };
            inspect_credential_value(
                server_name,
                &format!("{field}.{key}"),
                key,
                val,
                path,
                display,
                engine,
                out,
            );
        }
    }

    for direct_key in ["bearer_token", "oauth_client_secret", "api_key"] {
        if let Some(val) = spec.get(direct_key).and_then(|v| v.as_str()) {
            inspect_credential_value(
                server_name,
                direct_key,
                direct_key,
                val,
                path,
                display,
                engine,
                out,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_credential_value(
    server_name: &str,
    location_label: &str,
    key: &str,
    val: &str,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let trimmed = val.trim();
    // `${VAR}` or `$VAR` interpolation references are safe best practice, not hardcoded secrets
    if trimmed.is_empty()
        || trimmed.starts_with("${")
        || (trimmed.starts_with('$') && !trimmed.contains(' '))
        || trimmed.starts_with("env:")
    {
        return;
    }

    // First check known secret patterns
    let matches = engine.scan_text(trimmed);
    if let Some(m) = matches.iter().find(|m| m.category == RuleCategory::Secret) {
        out.push(McpFinding {
            rule_id: "mcp-hardcoded-secret",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            severity: Severity::Critical,
            fingerprint: fingerprint_match(
                "mcp-hardcoded-secret",
                &format!("{display}:{server_name}:{location_label}:{trimmed}"),
            ),
            message: format!(
                "Hardcoded {} (`{}`) in `{location_label}` — use `${{{key}}}` env interpolation or a keychain",
                m.rule_name, m.masked
            ),
        });
        return;
    }

    // Fallback: secret-named key with high-entropy plaintext literal
    let upper_key = key.to_ascii_uppercase();
    let looks_sensitive_key = SENSITIVE_ENV_KEYWORDS
        .iter()
        .any(|kw| upper_key.contains(kw));
    if looks_sensitive_key
        && trimmed.len() >= 16
        && !is_likely_placeholder(trimmed)
        && shannon_entropy(trimmed) >= 3.75
    {
        let masked = mask_value("dotenv-generic-secret", trimmed);
        out.push(McpFinding {
            rule_id: "mcp-hardcoded-secret",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            severity: Severity::Critical,
            fingerprint: fingerprint_match(
                "mcp-hardcoded-secret",
                &format!("{display}:{server_name}:{location_label}:{trimmed}"),
            ),
            message: format!(
                "Hardcoded secret (`{masked}`) in `{location_label}` — avoid storing raw secrets in MCP config files"
            ),
        });
    }
}

fn check_network_and_telemetry(
    server_name: &str,
    spec: &Value,
    args: &[&str],
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    // Remote MCP `url` / `serverUrl` check
    for url_field in ["url", "serverUrl"] {
        if let Some(url) = spec.get(url_field).and_then(|v| v.as_str()) {
            let lower = url.to_ascii_lowercase();
            let is_local = lower.contains("://localhost")
                || lower.contains("://127.0.0.1")
                || lower.contains("://[::1]");
            if lower.starts_with("http://") && !is_local {
                out.push(McpFinding {
                    rule_id: "mcp-plaintext-http",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-plaintext-http",
                        &format!("{display}:{server_name}:{url}"),
                    ),
                    message: format!(
                        "Connects to remote MCP server over unencrypted HTTP (`{url}`)"
                    ),
                });
            }
        }
    }

    // Check serialized spec for known third-party analytics / telemetry ingestion domains
    let serialized = spec.to_string().to_ascii_lowercase();
    for &domain in TELEMETRY_DOMAINS {
        if serialized.contains(domain) {
            let matched_host = extract_domain_token(&serialized, domain)
                .unwrap_or_else(|| domain.trim_end_matches('.').to_string());
            let _ = args;
            out.push(McpFinding {
                rule_id: "mcp-telemetry-endpoint",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-telemetry-endpoint",
                    &format!("{display}:{server_name}:{matched_host}"),
                ),
                message: format!(
                    "References outbound analytics/telemetry endpoint (`{matched_host}`)"
                ),
            });
            break;
        }
    }
}

fn extract_domain_token(haystack: &str, needle: &str) -> Option<String> {
    let idx = haystack.find(needle)?;
    let bytes = haystack.as_bytes();
    let mut start = idx;
    while start > 0 && is_domain_char(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = idx + needle.len();
    while end < bytes.len() && is_domain_char(bytes[end]) {
        end += 1;
    }
    Some(haystack[start..end].trim_matches('.').to_string())
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}
