use crate::config::PolicyConfig;
use crate::discovery::shorten_home;
use crate::plugin_audit::{
    detect_credential_store_ref, detect_external_network_call, detect_inline_rce, find_line_number,
};
use crate::rules::{
    fingerprint_match, is_likely_placeholder, mask_value, shannon_entropy, RuleCategory,
    RuleEngine, Severity,
};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_MCP_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct McpFinding {
    pub rule_id: &'static str,
    pub server_name: String,
    pub config_file: String,
    pub config_path: PathBuf,
    pub line: usize,
    pub severity: Severity,
    pub message: String,
    pub fingerprint: String,
}

const TELEMETRY_DOMAINS: &[&str] = &[
    "i.posthog.com",
    "events.posthog.com",
    "app.posthog.com",
    "api.segment.io",
    "cdn.segment.com",
    "api.mixpanel.com",
    "api.amplitude.com",
    "api2.amplitude.com",
    "ingest.sentry.io",
    ".ingest.us.sentry.io",
    ".ingest.de.sentry.io",
    "http-intake.logs.datadoghq.com",
    "browser-intake-datadoghq.com",
    "trace.agent.datadoghq.com",
    "www.google-analytics.com",
    "analytics.google.com",
    "telemetry.",
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

const SENSITIVE_MOUNT_SUBPATHS: &[(&str, &str)] = &[
    ("/.ssh", "~/.ssh"),
    ("\\.ssh", "~/.ssh"),
    ("~/.ssh", "~/.ssh"),
    ("$home/.ssh", "$HOME/.ssh"),
    ("${home}/.ssh", "${HOME}/.ssh"),
    ("/.aws", "~/.aws"),
    ("\\.aws", "~/.aws"),
    ("~/.aws", "~/.aws"),
    ("$home/.aws", "$HOME/.aws"),
    ("${home}/.aws", "${HOME}/.aws"),
    ("/.azure", "~/.azure"),
    ("~/.azure", "~/.azure"),
    ("/.gnupg", "~/.gnupg"),
    ("~/.gnupg", "~/.gnupg"),
    ("/.kube", "~/.kube"),
    ("~/.kube", "~/.kube"),
    ("/.config/gh", "~/.config/gh"),
    ("~/.config/gh", "~/.config/gh"),
    ("/.config/gcloud", "~/.config/gcloud"),
    ("~/.config/gcloud", "~/.config/gcloud"),
    ("/.npmrc", "~/.npmrc"),
    ("~/.npmrc", "~/.npmrc"),
    ("/.pypirc", "~/.pypirc"),
    ("~/.pypirc", "~/.pypirc"),
    ("/.pgpass", "~/.pgpass"),
    ("~/.pgpass", "~/.pgpass"),
    ("/.my.cnf", "~/.my.cnf"),
    ("~/.my.cnf", "~/.my.cnf"),
    ("/.vault-token", "~/.vault-token"),
    ("~/.vault-token", "~/.vault-token"),
    ("/.databrickscfg", "~/.databrickscfg"),
    ("~/.databrickscfg", "~/.databrickscfg"),
    ("/.s3cfg", "~/.s3cfg"),
    ("~/.s3cfg", "~/.s3cfg"),
    ("/.terraformrc", "~/.terraformrc"),
    ("~/.terraformrc", "~/.terraformrc"),
    ("credentials.tfrc.json", "credentials.tfrc.json"),
    ("/.docker", "~/.docker"),
    ("~/.docker", "~/.docker"),
    ("/.netrc", "~/.netrc"),
    ("~/.netrc", "~/.netrc"),
    ("/.git-credentials", "~/.git-credentials"),
    ("~/.git-credentials", "~/.git-credentials"),
    ("/.claude", "~/.claude"),
    ("~/.claude", "~/.claude"),
    ("/.codex", "~/.codex"),
    ("~/.codex", "~/.codex"),
    ("docker.sock", "/var/run/docker.sock"),
    ("podman.sock", "/run/podman/podman.sock"),
    ("containerd.sock", "/run/containerd/containerd.sock"),
];

pub fn audit_mcp_configs(files: &[PathBuf], engine: &RuleEngine) -> Vec<McpFinding> {
    audit_mcp_configs_with_policy(files, engine, None)
}

pub fn audit_mcp_configs_with_policy(
    files: &[PathBuf],
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    for path in files {
        if policy.is_some_and(|p| p.is_path_ignored(path)) {
            continue;
        }
        audit_single_mcp_file(path, path, None, None, engine, &mut findings);
    }
    if let Some(pol) = policy {
        findings.retain(|f| {
            !pol.is_path_ignored(&f.config_path)
                && !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });
    findings
}

/// Audits `disk_path` (e.g., a materialized git index or commit blob) while attributing findings,
/// stable fingerprints, and scoped `.leaktap.toml` rules/allowlists to `logical_path`.
pub fn audit_mcp_file_as(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    audit_mcp_file_as_with_roots(
        disk_path,
        logical_path,
        display_override,
        None,
        engine,
        policy,
    )
}

pub fn audit_mcp_file_as_with_roots(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    sandbox_remap: Option<(&Path, &Path)>,
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    if policy.is_some_and(|p| p.is_path_ignored(logical_path)) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    audit_single_mcp_file(
        disk_path,
        logical_path,
        display_override,
        sandbox_remap,
        engine,
        &mut findings,
    );
    if let Some(pol) = policy {
        findings.retain(|f| {
            !pol.is_path_ignored(&f.config_path)
                && !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }
    findings
}

fn audit_single_mcp_file(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    sandbox_remap: Option<(&Path, &Path)>,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let Ok(meta) = fs::metadata(disk_path) else {
        return;
    };
    let start_idx = out.len();
    let display = shorten_home(logical_path);
    if meta.len() > MAX_MCP_CONFIG_BYTES {
        out.push(McpFinding {
            rule_id: "mcp-oversized-config",
            server_name: "mcp-config".to_string(),
            config_file: display.clone(),
            config_path: logical_path.to_path_buf(),
            line: 1,
            severity: Severity::High,
            fingerprint: fingerprint_match("mcp-oversized-config", &display),
            message: format!(
                "MCP config file exceeds 16 MiB ({:.1} MiB > 16.0 MiB AST limit) — structured server checks cannot safely load it into memory",
                meta.len() as f64 / (1024.0 * 1024.0)
            ),
        });
        if let Some(ovr) = display_override {
            for f in &mut out[start_idx..] {
                f.config_file = ovr.to_string();
            }
        }
        return;
    };

    let Ok(raw) = crate::scanner::read_text_auto_encoding(disk_path, MAX_MCP_CONFIG_BYTES) else {
        return;
    };
    let is_toml = logical_path
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

    // 1. Top-level `mcpServers` (JSON), `mcp_servers` (Codex TOML), `servers` (VS Code `mcp.json`), or `context_servers` (Zed `settings.json`)
    for top_key in ["mcpServers", "mcp_servers", "servers", "context_servers"] {
        if let Some(servers) = json.get(top_key).and_then(|v| v.as_object()) {
            for (name, spec) in servers {
                inspect_server(
                    name,
                    spec,
                    &raw,
                    disk_path,
                    logical_path,
                    sandbox_remap,
                    &display,
                    engine,
                    out,
                );
            }
        }
    }

    // 1b. VS Code / Cursor / Windsurf `settings.json` nested `mcp.servers` (`{"mcp": {"servers": {...}}}`)
    if let Some(servers) = json
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .and_then(|v| v.as_object())
    {
        for (name, spec) in servers {
            inspect_server(
                name,
                spec,
                &raw,
                disk_path,
                logical_path,
                sandbox_remap,
                &display,
                engine,
                out,
            );
        }
    }

    // 2. Project-scoped MCP blocks (`projects.<workspace>.mcpServers` / `mcp_servers` / `context_servers`)
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for (_proj_path, proj_val) in projects {
            for nested_key in ["mcpServers", "mcp_servers", "context_servers"] {
                if let Some(servers) = proj_val.get(nested_key).and_then(|v| v.as_object()) {
                    for (name, spec) in servers {
                        inspect_server(
                            name,
                            spec,
                            &raw,
                            disk_path,
                            logical_path,
                            sandbox_remap,
                            &display,
                            engine,
                            out,
                        );
                    }
                }
            }
        }
    }

    // 3. Codex `config.toml` extras (`[model_providers.*]`, `experimental_bearer_token`, `[env]`, `[shell_environment_policy.set]`)
    if is_toml {
        audit_codex_toml_extras(&json, &raw, logical_path, &display, engine, out);
    } else if is_vscode_family_settings_json(logical_path) {
        audit_vscode_settings_extras(&json, &raw, logical_path, &display, start_idx, engine, out);
    }

    if let Some(ovr) = display_override {
        let git_prefix = ovr.strip_prefix("git:").and_then(|rest| {
            let (sha_or_stage, _) = rest.split_once(':')?;
            Some(format!("git:{sha_or_stage}:"))
        });
        for f in &mut out[start_idx..] {
            if f.config_path == logical_path {
                f.config_file = ovr.to_string();
            } else if let (Some(ref gp), Some((_, repo_root))) = (&git_prefix, sandbox_remap) {
                if let Ok(rel) = f.config_path.strip_prefix(repo_root) {
                    f.config_file = format!("{gp}{}", rel.to_string_lossy());
                }
            }
        }
    }
}

fn is_vscode_family_settings_json(path: &Path) -> bool {
    if path.file_name().and_then(|s| s.to_str()) != Some("settings.json") {
        return false;
    }
    let in_claude_or_gemini = path
        .components()
        .any(|c| matches!(c.as_os_str().to_str(), Some(".claude" | ".gemini")));
    !in_claude_or_gemini
}

fn audit_vscode_settings_extras(
    json: &Value,
    raw_file: &str,
    path: &Path,
    display: &str,
    start_idx: usize,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let Some(root_obj) = json.as_object() else {
        return;
    };
    let is_workspace_cfg = path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".vscode" | ".zed" | ".cursor" | ".windsurf")
        )
    }) && !crate::plugin_audit::is_user_home_global_agent_path(path);
    let mut seen_fp: std::collections::HashSet<String> =
        out.iter().map(|f| f.fingerprint.clone()).collect();

    // 1. Audit `terminal.integrated.env.{linux,osx,windows}` (VS Code) and `terminal.env` (Zed)
    if let Some(zed_env_obj) = root_obj
        .get("terminal")
        .and_then(|v| v.get("env"))
        .and_then(|v| v.as_object())
    {
        crate::plugin_audit::audit_env_object_overrides(
            path,
            display,
            raw_file,
            zed_env_obj,
            "terminal.env",
            "IDE terminal settings",
            is_workspace_cfg,
            true,
            engine,
            out,
            &mut seen_fp,
        );
    }
    for platform in ["linux", "osx", "windows"] {
        let dotted_key = format!("terminal.integrated.env.{platform}");
        if let Some(env_obj) = root_obj.get(&dotted_key).and_then(|v| v.as_object()) {
            crate::plugin_audit::audit_env_object_overrides(
                path,
                display,
                raw_file,
                env_obj,
                &dotted_key,
                "VS Code terminal settings",
                is_workspace_cfg,
                true,
                engine,
                out,
                &mut seen_fp,
            );
        }
        if let Some(env_obj) = root_obj
            .get("terminal")
            .and_then(|v| v.get("integrated"))
            .and_then(|v| v.get("env"))
            .and_then(|v| v.get(platform))
            .and_then(|v| v.as_object())
        {
            crate::plugin_audit::audit_env_object_overrides(
                path,
                display,
                raw_file,
                env_obj,
                &dotted_key,
                "VS Code terminal settings",
                is_workspace_cfg,
                true,
                engine,
                out,
                &mut seen_fp,
            );
        }
    }

    // 2. Audit workspace proxy / TLS verification overrides (`http.proxy`, `http.proxyStrictSSL: false`)
    if let Some(proxy_url) = root_obj.get("http.proxy").and_then(|v| v.as_str()) {
        let trimmed = proxy_url.trim();
        if !trimmed.is_empty()
            && (!crate::plugin_audit::is_localhost_url(trimmed) || is_workspace_cfg)
        {
            let line = find_line_number(raw_file, "http.proxy");
            let sev = if crate::plugin_audit::is_localhost_url(trimmed) {
                Severity::High
            } else {
                Severity::Critical
            };
            let fp = fingerprint_match(
                "plugin-api-base-override",
                &format!("{display}:vscode:http.proxy:{trimmed}"),
            );
            if seen_fp.insert(fp.clone()) {
                out.push(McpFinding {
                    rule_id: "plugin-api-base-override",
                    server_name: "vscode:http.proxy".to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: sev,
                    fingerprint: fp,
                    message: format!(
                        "VS Code settings route IDE and extension traffic through proxy `{trimmed}`, enabling credential/prompt interception"
                    ),
                });
            }
        }
    }
    if root_obj
        .get("http.proxyStrictSSL")
        .and_then(|v| v.as_bool())
        == Some(false)
        && is_workspace_cfg
    {
        let line = find_line_number(raw_file, "http.proxyStrictSSL");
        let fp = fingerprint_match(
            "plugin-api-base-override",
            &format!("{display}:vscode:http.proxyStrictSSL:false"),
        );
        if seen_fp.insert(fp.clone()) {
            out.push(McpFinding {
                rule_id: "plugin-api-base-override",
                server_name: "vscode:http.proxyStrictSSL".to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: "Workspace `.vscode/settings.json` disables TLS certificate verification (`http.proxyStrictSSL: false`), enabling MITM interception".to_string(),
            });
        }
    }

    // 3. Scan remaining settings.json content for hardcoded live secrets (`RuleCategory::Secret`),
    // skipping lines already flagged by `mcp.servers` or `terminal.integrated.env.*`.
    let already_flagged_secret_lines: std::collections::HashSet<usize> = out[start_idx..]
        .iter()
        .filter(|f| {
            matches!(
                f.rule_id,
                "mcp-hardcoded-secret" | "plugin-hardcoded-secret"
            )
        })
        .map(|f| f.line)
        .collect();
    for m in engine.scan_text_for_path(raw_file, Some(path)) {
        if m.category != RuleCategory::Secret {
            continue;
        }
        let line = raw_file.as_bytes()[..m.start.min(raw_file.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1;
        if already_flagged_secret_lines.contains(&line) {
            continue;
        }
        let fp = fingerprint_match(
            "mcp-hardcoded-secret",
            &format!("{display}:vscode-settings:{}", m.fingerprint),
        );
        if seen_fp.insert(fp.clone()) {
            out.push(McpFinding {
                rule_id: "mcp-hardcoded-secret",
                server_name: "vscode-settings".to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Hardcoded {} (`{}`) stored in VS Code `settings.json`",
                    m.rule_name, m.masked
                ),
            });
        }
    }
}

fn audit_codex_toml_extras(
    json: &Value,
    raw_file: &str,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let Some(root_obj) = json.as_object() else {
        return;
    };
    let is_workspace_cfg = !crate::plugin_audit::is_user_home_global_agent_path(path);
    let mut seen_fp: std::collections::HashSet<String> =
        out.iter().map(|f| f.fingerprint.clone()).collect();

    if let Some(env_obj) = root_obj.get("env").and_then(|v| v.as_object()) {
        crate::plugin_audit::audit_env_object_overrides(
            path,
            display,
            raw_file,
            env_obj,
            "codex:env",
            "Codex config",
            is_workspace_cfg,
            true,
            engine,
            out,
            &mut seen_fp,
        );
    }
    if let Some(set_obj) = root_obj
        .get("shell_environment_policy")
        .and_then(|v| v.get("set"))
        .and_then(|v| v.as_object())
    {
        crate::plugin_audit::audit_env_object_overrides(
            path,
            display,
            raw_file,
            set_obj,
            "codex:shell_environment_policy.set",
            "Codex shell policy",
            is_workspace_cfg,
            true,
            engine,
            out,
            &mut seen_fp,
        );
    }

    // Top-level base URL overrides (`openai_base_url`, `chatgpt_base_url`, `base_url`)
    for base_key in ["openai_base_url", "chatgpt_base_url", "base_url"] {
        if let Some(url) = root_obj.get(base_key).and_then(|v| v.as_str()) {
            let trimmed = url.trim();
            if !trimmed.is_empty()
                && !crate::plugin_audit::is_localhost_url(trimmed)
                && !crate::plugin_audit::is_official_llm_api_url(trimmed)
            {
                let line = find_line_number(raw_file, trimmed);
                let fp = fingerprint_match(
                    "plugin-api-base-override",
                    &format!("{display}:codex:{base_key}:{trimmed}"),
                );
                if seen_fp.insert(fp.clone()) {
                    out.push(McpFinding {
                        rule_id: "plugin-api-base-override",
                        server_name: format!("codex:{base_key}"),
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        line,
                        severity: Severity::Critical,
                        fingerprint: fp,
                        message: format!(
                            "Codex config redirects `{base_key}` to `{trimmed}`, routing prompts and credentials through a third-party or unencrypted endpoint"
                        ),
                    });
                }
            }
        }
    }

    // `[model_providers.<id>]` base_url redirection
    if let Some(providers) = root_obj.get("model_providers").and_then(|v| v.as_object()) {
        for (prov_id, prov_val) in providers {
            if let Some(prov_obj) = prov_val.as_object() {
                for url_key in ["base_url", "url", "endpoint"] {
                    if let Some(url) = prov_obj.get(url_key).and_then(|v| v.as_str()) {
                        let trimmed = url.trim();
                        if !trimmed.is_empty()
                            && !crate::plugin_audit::is_localhost_url(trimmed)
                            && !crate::plugin_audit::is_official_llm_api_url(trimmed)
                        {
                            let line = find_line_number(raw_file, trimmed)
                                .max(find_line_number(raw_file, prov_id));
                            let fp = fingerprint_match(
                                "plugin-api-base-override",
                                &format!("{display}:model_providers.{prov_id}.{url_key}:{trimmed}"),
                            );
                            if seen_fp.insert(fp.clone()) {
                                out.push(McpFinding {
                                    rule_id: "plugin-api-base-override",
                                    server_name: format!("model_providers.{prov_id}"),
                                    config_file: display.to_string(),
                                    config_path: path.to_path_buf(),
                                    line,
                                    severity: Severity::Critical,
                                    fingerprint: fp,
                                    message: format!(
                                        "Codex model provider `{prov_id}` redirects `{url_key}` to `{trimmed}`, routing prompts and credentials through an untrusted or unencrypted endpoint"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Scan all non-MCP TOML fields (`experimental_bearer_token`, `http_headers`, etc.) for hardcoded secrets
    for (top_k, top_v) in root_obj {
        if matches!(
            top_k.as_str(),
            "mcp_servers" | "mcpServers" | "servers" | "context_servers" | "projects" | "env"
        ) {
            continue;
        }
        audit_toml_value_for_secrets(top_k, top_k, top_v, raw_file, path, display, engine, out);
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_toml_value_for_secrets(
    key_path: &str,
    leaf_key: &str,
    val: &Value,
    raw_file: &str,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    match val {
        Value::String(s) => {
            // In Codex `config.toml`, `env_key = "OPENAI_API_KEY"` and `env_http_headers` values
            // name environment variables rather than literal secrets unless a real secret rule matches.
            let is_env_name_ref =
                leaf_key.eq_ignore_ascii_case("env_key") || key_path.contains("env_http_headers");
            let line = find_line_number(raw_file, s).max(find_line_number(raw_file, leaf_key));
            if is_env_name_ref {
                let matches = engine.scan_text_for_path(s.trim(), Some(path));
                if matches.iter().any(|m| m.category == RuleCategory::Secret) {
                    inspect_credential_value(
                        "codex-config",
                        key_path,
                        leaf_key,
                        s,
                        line,
                        path,
                        display,
                        engine,
                        out,
                    );
                }
            } else {
                inspect_credential_value(
                    "codex-config",
                    key_path,
                    leaf_key,
                    s,
                    line,
                    path,
                    display,
                    engine,
                    out,
                );
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let next_path = format!("{key_path}.{k}");
                audit_toml_value_for_secrets(
                    &next_path, k, v, raw_file, path, display, engine, out,
                );
            }
        }
        Value::Array(arr) => {
            for item in arr {
                audit_toml_value_for_secrets(
                    key_path, leaf_key, item, raw_file, path, display, engine, out,
                );
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_server(
    server_name: &str,
    spec: &Value,
    raw_file: &str,
    disk_path: &Path,
    path: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let server_line = find_line_number(raw_file, server_name);
    let cmd_obj = spec.get("command").and_then(|v| v.as_object());
    let command = spec
        .get("command")
        .and_then(|v| v.as_str())
        .or_else(|| cmd_obj.and_then(|o| o.get("path")).and_then(|v| v.as_str()))
        .unwrap_or("");
    let args: Vec<&str> = spec
        .get("args")
        .and_then(|v| v.as_array())
        .or_else(|| {
            cmd_obj
                .and_then(|o| o.get("args"))
                .and_then(|v| v.as_array())
        })
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();

    // Check 1: Unpinned remote package execution (`npx -y @foo/bar`, `uvx foo`, `uv run --with foo`)
    check_unpinned_execution(
        server_name,
        command,
        &args,
        raw_file,
        server_line,
        path,
        display,
        out,
    );

    // Check 2: Broad filesystem root/home/credential-store access, container escapes, unrestricted shell, inline RCE, & referenced local scripts
    check_command_and_host_access(
        server_name,
        command,
        &args,
        raw_file,
        server_line,
        disk_path,
        path,
        sandbox_remap,
        display,
        engine,
        out,
    );

    // Check 3: Plaintext hardcoded secrets in `env`, `command.env`, `settings`, `headers`, or inline `args`
    check_hardcoded_credentials(
        server_name,
        spec,
        &args,
        raw_file,
        server_line,
        path,
        display,
        engine,
        out,
    );

    // Check 3b: Dangerous process execution / proxy / TLS / API base overrides in MCP `env` or Zed `command.env`
    for env_candidate in [
        spec.get("env").and_then(|v| v.as_object()),
        cmd_obj
            .and_then(|o| o.get("env"))
            .and_then(|v| v.as_object()),
    ]
    .into_iter()
    .flatten()
    {
        let is_workspace_cfg = !crate::plugin_audit::is_user_home_global_agent_path(path);
        let mut seen_fp: std::collections::HashSet<String> =
            out.iter().map(|f| f.fingerprint.clone()).collect();
        let scope_prefix = format!("{server_name}:env");
        let context_noun = format!("MCP server `{server_name}`");
        crate::plugin_audit::audit_env_object_overrides(
            path,
            display,
            raw_file,
            env_candidate,
            &scope_prefix,
            &context_noun,
            is_workspace_cfg,
            false,
            engine,
            out,
            &mut seen_fp,
        );
    }

    // Check 4: Remote URL transport (insecure HTTP or external host) + telemetry domains
    check_network_and_telemetry(
        server_name,
        spec,
        &args,
        raw_file,
        server_line,
        path,
        display,
        out,
    );
}

fn normalized_cmd_base(cmd: &str) -> String {
    let raw_base = Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd);
    raw_base
        .strip_suffix(".exe")
        .or_else(|| raw_base.strip_suffix(".cmd"))
        .unwrap_or(raw_base)
        .to_ascii_lowercase()
}

#[allow(clippy::too_many_arguments)]
fn emit_unpinned_pkg_finding(
    server_name: &str,
    launcher_label: &str,
    pkg: &str,
    has_auto_install: bool,
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    if pkg.is_empty() || (pkg.starts_with('<') && pkg.ends_with('>')) {
        return;
    }
    if !is_pinned_package_spec(pkg) {
        let line = find_line_number(raw_file, pkg).max(server_line);
        let fp = fingerprint_match(
            "mcp-unpinned-package",
            &format!("{display}:{server_name}:{pkg}"),
        );
        if out.iter().any(|f| f.fingerprint == fp) {
            return;
        }
        let is_remote_url_or_git = pkg.starts_with("http://")
            || pkg.starts_with("https://")
            || pkg.starts_with("git+")
            || pkg.starts_with("github:")
            || pkg.starts_with("git://");
        let sev = if is_remote_url_or_git {
            Severity::High
        } else {
            Severity::Medium
        };
        let msg = if has_auto_install {
            format!(
                "Runs unpinned `{launcher_label} {pkg}` — pulls mutable remote package code on start (pin an exact `x.y.z` version, or vendor with a lockfile to pin transitive `^`/`~` dependencies)"
            )
        } else {
            format!(
                "Runs unpinned `{launcher_label} {pkg}` without an exact `x.y.z` version pin (note: top-level pins still leave transitive `^`/`~` dependencies mutable without a lockfile)"
            )
        };
        out.push(McpFinding {
            rule_id: "mcp-unpinned-package",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line,
            severity: sev,
            fingerprint: fp,
            message: msg,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn check_unpinned_execution(
    server_name: &str,
    command: &str,
    args: &[&str],
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    let (eff_cmd_owned, eff_args_owned) = unwrap_command_launchers(command, args);
    let eff_cmd = eff_cmd_owned.as_str();
    let eff_args_vec: Vec<&str> = eff_args_owned.iter().map(String::as_str).collect();
    let eff_args = eff_args_vec.as_slice();
    let cmd_base = normalized_cmd_base(eff_cmd);

    // `npx -c` / `npm exec -c` executes shell commands rather than a package specifier
    if extract_npm_call_command(&cmd_base, eff_args).is_some() {
        return;
    }

    // Check `--with` / `-w` dependencies on `uv` / `uvx` (e.g. `uv run --with mcp-server-git ...`)
    if matches!(cmd_base.as_str(), "uv" | "uvx") {
        let mut idx = 0usize;
        while idx < eff_args.len() {
            let a = eff_args[idx];
            if a == "--" {
                break;
            }
            if let Some(val) = a.strip_prefix("--with=") {
                for sub in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    emit_unpinned_pkg_finding(
                        server_name,
                        &format!("{cmd_base} --with"),
                        sub,
                        true,
                        raw_file,
                        server_line,
                        path,
                        display,
                        out,
                    );
                }
                idx += 1;
                continue;
            }
            if matches!(a, "--with" | "-w") {
                if let Some(&val) = eff_args.get(idx + 1) {
                    for sub in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        emit_unpinned_pkg_finding(
                            server_name,
                            &format!("{cmd_base} --with"),
                            sub,
                            true,
                            raw_file,
                            server_line,
                            path,
                            display,
                            out,
                        );
                    }
                }
                idx += 2;
                continue;
            }
            idx += 1;
        }
    }

    let Some((launcher_label, pkg_slice)) = extract_package_launcher(&cmd_base, eff_args) else {
        return;
    };

    let has_auto_install = eff_args
        .iter()
        .any(|&a| matches!(a, "-y" | "--yes" | "-A" | "--allow-all"))
        || matches!(
            cmd_base.as_str(),
            "uvx" | "uv" | "bunx" | "go" | "nix" | "jbang" | "cargo"
        )
        || launcher_label.ends_with(" dlx");

    let explicit_pkgs = collect_explicit_package_flag_args(&cmd_base, pkg_slice);
    if !explicit_pkgs.is_empty() {
        for pkg in explicit_pkgs {
            emit_unpinned_pkg_finding(
                server_name,
                &launcher_label,
                pkg,
                has_auto_install,
                raw_file,
                server_line,
                path,
                display,
                out,
            );
        }
        return;
    }

    if let Some(pkg) = find_target_package_arg(&cmd_base, pkg_slice) {
        emit_unpinned_pkg_finding(
            server_name,
            &launcher_label,
            pkg,
            has_auto_install,
            raw_file,
            server_line,
            path,
            display,
            out,
        );
    }
}

fn collect_explicit_package_flag_args<'a>(cmd_base: &str, args: &'a [&'a str]) -> Vec<&'a str> {
    let is_uv = matches!(cmd_base, "uvx" | "uv");
    let is_deno = cmd_base == "deno";
    let mut pkgs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i];
        if a == "--" {
            break;
        }
        if let Some(pkg) = a
            .strip_prefix("--package=")
            .or_else(|| a.strip_prefix("--from="))
        {
            pkgs.push(pkg);
            i += 1;
            continue;
        }
        if matches!(a, "--package" | "--from") || (!is_uv && !is_deno && a == "-p") {
            if let Some(&pkg) = args.get(i + 1) {
                pkgs.push(pkg);
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    pkgs
}

fn extract_package_launcher<'a>(
    cmd_base: &str,
    args: &'a [&'a str],
) -> Option<(String, &'a [&'a str])> {
    match cmd_base {
        "npx" | "bunx" | "uvx" => Some((cmd_base.to_string(), args)),
        "pipx" => {
            if let Some(pos) = args.iter().position(|&a| a == "run") {
                Some(("pipx run".to_string(), &args[pos + 1..]))
            } else {
                Some(("pipx".to_string(), args))
            }
        }
        "pnpm" | "yarn" => {
            let pos = args.iter().position(|&a| a == "dlx")?;
            Some((format!("{cmd_base} dlx"), &args[pos + 1..]))
        }
        "npm" => {
            let pos = args.iter().position(|&a| matches!(a, "exec" | "x"))?;
            Some((format!("npm {}", args[pos]), &args[pos + 1..]))
        }
        "bun" => {
            let pos = args.iter().position(|&a| a == "x")?;
            Some(("bun x".to_string(), &args[pos + 1..]))
        }
        "uv" => {
            if let Some(t_pos) = args.iter().position(|&a| a == "tool") {
                let rem = &args[t_pos + 1..];
                if let Some(r_pos) = rem.iter().position(|&a| a == "run") {
                    return Some(("uv tool run".to_string(), &rem[r_pos + 1..]));
                }
            }
            let r_pos = args.iter().position(|&a| a == "run")?;
            let rem = &args[r_pos + 1..];
            if !collect_explicit_package_flag_args("uv", rem).is_empty() {
                return Some(("uv run".to_string(), rem));
            }
            let target = find_target_package_arg("uv", rem)?;
            if target.starts_with("https://") || target.starts_with("http://") {
                Some(("uv run".to_string(), rem))
            } else {
                None
            }
        }
        "deno" => {
            let pos = args.iter().position(|&a| a == "run")?;
            let rem = &args[pos + 1..];
            let target = find_target_package_arg("deno", rem)?;
            if target.starts_with("npm:")
                || target.starts_with("jsr:")
                || target.starts_with("https://")
                || target.starts_with("http://")
            {
                Some(("deno run".to_string(), rem))
            } else {
                None
            }
        }
        "go" => {
            let pos = args.iter().position(|&a| a == "run")?;
            let rem = &args[pos + 1..];
            let target = find_target_package_arg("go", rem)?;
            let is_local = target.starts_with('.')
                || target.starts_with('/')
                || target.starts_with('\\')
                || target.ends_with(".go");
            let looks_remote_mod = target.contains('@')
                || target
                    .split('/')
                    .next()
                    .is_some_and(|first| first.contains('.'));
            if !is_local && looks_remote_mod {
                Some(("go run".to_string(), rem))
            } else {
                None
            }
        }
        "nix" => {
            let pos = args.iter().position(|&a| matches!(a, "run" | "shell"))?;
            let sub = args[pos];
            let rem = &args[pos + 1..];
            let target = find_target_package_arg("nix", rem)?;
            let is_local = target.starts_with('.')
                || target.starts_with('/')
                || target.starts_with('\\')
                || target.starts_with("path:");
            if !is_local {
                Some((format!("nix {sub}"), rem))
            } else {
                None
            }
        }
        "jbang" => {
            let rem = if let Some(pos) = args.iter().position(|&a| a == "run") {
                &args[pos + 1..]
            } else {
                args
            };
            let target = find_target_package_arg("jbang", rem)?;
            let is_local_file = !target.starts_with("http://")
                && !target.starts_with("https://")
                && !target.contains('@')
                && !target.contains(':')
                && (target.starts_with('.')
                    || target.starts_with('/')
                    || target.starts_with('\\')
                    || target.ends_with(".java")
                    || target.ends_with(".jar")
                    || target.ends_with(".jsh")
                    || target.ends_with(".kt"));
            if !is_local_file {
                Some(("jbang".to_string(), rem))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn find_target_package_arg<'a>(cmd_base: &str, args: &'a [&'a str]) -> Option<&'a str> {
    let is_uv = matches!(cmd_base, "uvx" | "uv");
    let is_deno = cmd_base == "deno";
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i];
        if a == "--" {
            return args.get(i + 1).copied();
        }
        if let Some(pkg) = a
            .strip_prefix("--package=")
            .or_else(|| a.strip_prefix("--from="))
        {
            return Some(pkg);
        }
        if matches!(a, "--package" | "--from") || (!is_uv && !is_deno && a == "-p") {
            return args.get(i + 1).copied();
        }
        // Two-token flags whose following argument is a flag value rather than the package target.
        // Note: `-c` is ONLY a constraints file flag in `uv`/`uvx`; in `npx`/`npm exec`, `-c` is `--call`!
        if matches!(
            a,
            "--cache"
                | "--prefix"
                | "--registry"
                | "--userconfig"
                | "--globalconfig"
                | "--script-shell"
                | "--workspace"
                | "--index-url"
                | "--extra-index-url"
                | "-i"
                | "--find-links"
                | "-f"
                | "--python"
                | "--with"
                | "-w"
                | "--with-editable"
                | "--with-requirements"
                | "--constraints"
                | "--prerelease"
                | "--directory"
                | "--config"
                | "--config-file"
                | "--import-map"
                | "--lock"
                | "-mod"
                | "-modfile"
                | "-overlay"
                | "-C"
                | "--expr"
                | "--file"
                | "--deps"
                | "--java"
                | "--main"
                | "--cp"
                | "--class-path"
        ) || (is_uv && matches!(a, "-p" | "-c"))
        {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(a);
    }
    None
}

fn extract_npm_call_command<'a>(cmd_base: &str, eff_args: &'a [&'a str]) -> Option<&'a str> {
    let is_npx_or_npm_exec = cmd_base == "npx"
        || (cmd_base == "npm" && eff_args.iter().any(|&a| matches!(a, "exec" | "x")));
    if !is_npx_or_npm_exec {
        return None;
    }
    for (idx, &a) in eff_args.iter().enumerate() {
        if a == "--" {
            break;
        }
        if let Some(val) = a.strip_prefix("--call=").or_else(|| a.strip_prefix("-c=")) {
            return Some(val);
        }
        let is_short_call = a == "-c"
            || (a.starts_with('-')
                && !a.starts_with("--")
                && a.len() >= 2
                && a[1..].bytes().all(|b| matches!(b, b'y' | b'q' | b'c'))
                && a.contains('c'));
        if is_short_call || a == "--call" {
            return Some(eff_args.get(idx + 1).copied().unwrap_or(""));
        }
    }
    None
}

fn split_wrapper_tokens_lossy(script: &str) -> Vec<String> {
    split_simple_wrapper_tokens(script)
        .unwrap_or_else(|| script.split_whitespace().map(str::to_string).collect())
}

fn unwrap_command_launchers(command: &str, args: &[&str]) -> (String, Vec<String>) {
    let (cmd, unwrapped_args, _) = unwrap_command_launchers_with_priv(command, args);
    (cmd, unwrapped_args)
}

/// Peels up to 12 layers of process, privilege, and environment launchers (`env` including
/// `-u`/`-C`/`-S`, `sudo`, `doas`, `arch`, `caffeinate`, `direnv exec`, `xcrun`, `ionice`,
/// `taskset`, `chrt`, `flock`, `busybox`/`toybox`, `nohup`, `setsid`, `time`, `nice`, `timeout`,
/// `stdbuf`), returning `(effective_cmd, effective_args, privilege_escalation_tool)`.
fn unwrap_command_launchers_with_priv(
    command: &str,
    args: &[&str],
) -> (String, Vec<String>, Option<String>) {
    let mut cur_cmd = command.to_string();
    let mut cur_args: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    let mut priv_tool: Option<String> = None;

    for _layer in 0..12 {
        let base = normalized_cmd_base(&cur_cmd);
        match base.as_str() {
            "env" => {
                let mut i = 0usize;
                let mut split_count = 0usize;
                let mut unwrapped: Option<(String, Vec<String>)> = None;
                while i < cur_args.len() {
                    let a = cur_args[i].clone();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            unwrapped = Some((cur_args[i + 1].clone(), cur_args[i + 2..].to_vec()));
                        }
                        break;
                    }
                    if a == "-" {
                        i += 1;
                        continue;
                    }
                    if let Some(inline_s) = a.strip_prefix("--split-string=") {
                        if split_count < 4 {
                            split_count += 1;
                            let mut next = split_wrapper_tokens_lossy(inline_s);
                            next.extend_from_slice(&cur_args[i + 1..]);
                            cur_args = next;
                            i = 0;
                            continue;
                        }
                        i += 1;
                        continue;
                    }
                    if a == "--split-string" {
                        if split_count < 4 && i + 1 < cur_args.len() {
                            split_count += 1;
                            let mut next = split_wrapper_tokens_lossy(&cur_args[i + 1]);
                            next.extend_from_slice(&cur_args[i + 2..]);
                            cur_args = next;
                            i = 0;
                            continue;
                        }
                        i += 2;
                        continue;
                    }
                    if matches!(a.as_str(), "--unset" | "--chdir" | "--argv0" | "--altpath") {
                        i += 2;
                        continue;
                    }
                    if a.starts_with("--") {
                        i += 1;
                        continue;
                    }
                    if a.starts_with('-') && a.len() >= 2 {
                        let shorts = &a[1..];
                        let mut spliced = false;
                        let mut consumed = 1usize;
                        for (c_idx, ch) in shorts.char_indices() {
                            let rem = &shorts[c_idx + ch.len_utf8()..];
                            match ch {
                                'i' | '0' | 'v' => continue,
                                'S' => {
                                    if split_count < 4 {
                                        split_count += 1;
                                        let (src, after_idx) = if !rem.is_empty() {
                                            (rem.to_string(), i + 1)
                                        } else if i + 1 < cur_args.len() {
                                            (cur_args[i + 1].clone(), i + 2)
                                        } else {
                                            (String::new(), i + 1)
                                        };
                                        let mut next = split_wrapper_tokens_lossy(&src);
                                        next.extend_from_slice(&cur_args[after_idx..]);
                                        cur_args = next;
                                        i = 0;
                                        spliced = true;
                                    }
                                    break;
                                }
                                'u' | 'C' | 'P' | 'a' => {
                                    consumed = if rem.is_empty() { 2 } else { 1 };
                                    break;
                                }
                                _ => {
                                    consumed = 1;
                                    break;
                                }
                            }
                        }
                        if spliced {
                            continue;
                        }
                        i += consumed;
                        continue;
                    }
                    if a.contains('=') {
                        i += 1;
                        continue;
                    }
                    unwrapped = Some((a, cur_args[i + 1..].to_vec()));
                    break;
                }
                if let Some((nc, na)) = unwrapped {
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "sudo" => {
                priv_tool.get_or_insert_with(|| "sudo".to_string());
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    if matches!(
                        a,
                        "--user"
                            | "--group"
                            | "--host"
                            | "--prompt"
                            | "--role"
                            | "--type"
                            | "--close-from"
                            | "--chdir"
                            | "--chroot"
                            | "--command-timeout"
                            | "--other-user"
                    ) {
                        i += 2;
                        continue;
                    }
                    if a.starts_with("--") {
                        i += 1;
                        continue;
                    }
                    if a.starts_with('-') && a.len() >= 2 {
                        let shorts = &a[1..];
                        let mut consumed = 1usize;
                        for (c_idx, ch) in shorts.char_indices() {
                            let rem = &shorts[c_idx + ch.len_utf8()..];
                            if matches!(
                                ch,
                                'u' | 'g' | 'h' | 'p' | 'r' | 't' | 'C' | 'D' | 'R' | 'T' | 'U'
                            ) {
                                consumed = if rem.is_empty() { 2 } else { 1 };
                                break;
                            }
                        }
                        i += consumed;
                        continue;
                    }
                    if a.contains('=') {
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "doas" => {
                priv_tool.get_or_insert_with(|| "doas".to_string());
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    if a.starts_with('-') && a.len() >= 2 {
                        let shorts = &a[1..];
                        let mut consumed = 1usize;
                        for (c_idx, ch) in shorts.char_indices() {
                            let rem = &shorts[c_idx + ch.len_utf8()..];
                            if matches!(ch, 'u' | 'C') {
                                consumed = if rem.is_empty() { 2 } else { 1 };
                                break;
                            }
                        }
                        i += consumed;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "arch" | "caffeinate" | "xcrun" | "ionice" => {
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    let takes_val = match base.as_str() {
                        "arch" => matches!(a, "-arch" | "-e"),
                        "caffeinate" => matches!(a, "-t" | "-w"),
                        "xcrun" => matches!(a, "--sdk" | "-sdk" | "--toolchain" | "-toolchain"),
                        "ionice" => matches!(
                            a,
                            "-c" | "--class"
                                | "-n"
                                | "--classdata"
                                | "-p"
                                | "--pid"
                                | "-P"
                                | "--pgid"
                                | "-u"
                                | "--uid"
                        ),
                        _ => false,
                    };
                    if takes_val {
                        i += 2;
                        continue;
                    }
                    if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "direnv" => {
                if cur_args.first().map(String::as_str) != Some("exec") {
                    break;
                }
                let mut i = 1usize;
                let mut saw_dir = false;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        let start = if saw_dir { i + 1 } else { i + 2 };
                        if start < cur_args.len() {
                            found = Some(start);
                        }
                        break;
                    }
                    if !saw_dir {
                        if a.starts_with("--") && !a.contains('=') {
                            i += 2;
                            continue;
                        }
                        if a.starts_with('-') {
                            i += 1;
                            continue;
                        }
                        saw_dir = true;
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "taskset" | "chrt" => {
                let mut i = 0usize;
                let mut saw_mask_or_prio = false;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        let start = if saw_mask_or_prio { i + 1 } else { i + 2 };
                        if start < cur_args.len() {
                            found = Some(start);
                        }
                        break;
                    }
                    if !saw_mask_or_prio {
                        if base == "chrt"
                            && matches!(
                                a,
                                "-T" | "--sched-runtime"
                                    | "-P"
                                    | "--sched-period"
                                    | "-D"
                                    | "--sched-deadline"
                            )
                        {
                            i += 2;
                            continue;
                        }
                        if a.starts_with('-') {
                            i += 1;
                            continue;
                        }
                        saw_mask_or_prio = true;
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "flock" => {
                let mut i = 0usize;
                let mut saw_lockfile = false;
                let mut found = None;
                let mut shell_cmd_str: Option<String> = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        let start = if saw_lockfile { i + 1 } else { i + 2 };
                        if start < cur_args.len() {
                            found = Some(start);
                        }
                        break;
                    }
                    if !saw_lockfile {
                        if matches!(
                            a,
                            "-w" | "--timeout" | "--wait" | "-E" | "--conflict-exit-code"
                        ) {
                            i += 2;
                            continue;
                        }
                        if a.starts_with('-') {
                            i += 1;
                            continue;
                        }
                        saw_lockfile = true;
                        i += 1;
                        continue;
                    }
                    if matches!(a, "-c" | "--command") {
                        if let Some(s) = cur_args.get(i + 1) {
                            shell_cmd_str = Some(s.clone());
                        }
                        break;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(sc) = shell_cmd_str {
                    cur_cmd = "sh".to_string();
                    cur_args = vec!["-c".to_string(), sc];
                    continue;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "busybox" | "toybox" => {
                if let Some(pos) = cur_args.iter().position(|a| !a.starts_with('-')) {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "nohup" | "setsid" | "time" => {
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "nice" => {
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    if matches!(a, "-n" | "--adjustment") {
                        i += 2;
                        continue;
                    }
                    if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "timeout" => {
                let mut i = 0usize;
                let mut saw_duration = false;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        let start = if saw_duration { i + 1 } else { i + 2 };
                        if start < cur_args.len() {
                            found = Some(start);
                        }
                        break;
                    }
                    if !saw_duration {
                        if matches!(a, "-k" | "-s" | "--kill-after" | "--signal")
                            || (a.starts_with('-')
                                && !a.starts_with("--")
                                && a.len() >= 2
                                && a[1..].bytes().all(|b| matches!(b, b'v' | b'k' | b's'))
                                && (a.ends_with('k') || a.ends_with('s')))
                        {
                            i += 2;
                            continue;
                        }
                        if a.starts_with('-') {
                            i += 1;
                            continue;
                        }
                        saw_duration = true;
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            "stdbuf" => {
                let mut i = 0usize;
                let mut found = None;
                while i < cur_args.len() {
                    let a = cur_args[i].as_str();
                    if a == "--" {
                        if i + 1 < cur_args.len() {
                            found = Some(i + 1);
                        }
                        break;
                    }
                    if matches!(a, "-i" | "-o" | "-e" | "--input" | "--output" | "--error") {
                        i += 2;
                        continue;
                    }
                    if a.starts_with('-') {
                        i += 1;
                        continue;
                    }
                    found = Some(i);
                    break;
                }
                if let Some(pos) = found {
                    let nc = cur_args[pos].clone();
                    let na = cur_args[pos + 1..].to_vec();
                    cur_cmd = nc;
                    cur_args = na;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }

    (cur_cmd, cur_args, priv_tool)
}

fn is_immutable_git_commit_sha(ver: &str) -> bool {
    let rev = ver.split('&').next().unwrap_or(ver);
    (rev.len() == 40 || rev.len() == 64) && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_exact_pep440_pin(ver: &str) -> bool {
    if ver.is_empty() || ver.contains('*') || ver.starts_with(['^', '~', '>', '<', '=', '!', '|']) {
        return false;
    }
    let stripped_v = ver
        .strip_prefix('v')
        .or_else(|| ver.strip_prefix('V'))
        .unwrap_or(ver);
    let core = stripped_v.split(['-', '+']).next().unwrap_or(stripped_v);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_exact_semver_or_digest(ver: &str) -> bool {
    if let Some(hex) = ver.strip_prefix("sha256:") {
        return hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if is_immutable_git_commit_sha(ver) {
        return true;
    }
    if ver.is_empty()
        || ver.contains('*')
        || ver.starts_with(['^', '~', '>', '<', '=', '|'])
        || matches!(
            ver.to_ascii_lowercase().as_str(),
            "latest" | "next" | "main" | "master" | "canary" | "edge" | "beta" | "alpha" | "dev"
        )
    {
        return false;
    }
    let stripped_v = ver
        .strip_prefix('v')
        .or_else(|| ver.strip_prefix('V'))
        .unwrap_or(ver);
    let core = stripped_v.split(['-', '+']).next().unwrap_or(stripped_v);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_pinned_package_spec(pkg: &str) -> bool {
    if pkg.contains("narHash=sha256-") {
        return true;
    }
    for param in pkg.split(['?', '&']).skip(1) {
        if let Some(rev) = param.strip_prefix("rev=") {
            let rev_clean = rev.split('#').next().unwrap_or(rev);
            if is_immutable_git_commit_sha(rev_clean) {
                return true;
            }
        }
    }
    if pkg.starts_with("github:") || pkg.starts_with("gitlab:") || pkg.starts_with("sourcehut:") {
        let before_hash = pkg.split(['#', '?']).next().unwrap_or(pkg);
        if before_hash
            .rsplit('/')
            .next()
            .is_some_and(is_immutable_git_commit_sha)
        {
            return true;
        }
    }
    let colon_parts: Vec<&str> = pkg.split(':').collect();
    if (colon_parts.len() == 3 || colon_parts.len() == 4)
        && !pkg.contains("://")
        && !colon_parts[0].is_empty()
        && colon_parts[0].contains('.')
    {
        let mav_ver = colon_parts[2];
        if !mav_ver.to_ascii_uppercase().contains("SNAPSHOT")
            && !matches!(mav_ver.to_ascii_uppercase().as_str(), "LATEST" | "RELEASE")
            && (is_exact_semver_or_digest(mav_ver) || is_exact_pep440_pin(mav_ver))
        {
            return true;
        }
        return false;
    }
    if let Some((_, digest)) = pkg.rsplit_once('@') {
        if digest.starts_with("sha256:") || is_immutable_git_commit_sha(digest) {
            return is_exact_semver_or_digest(digest);
        }
    }
    if let Some((_, frag)) = pkg.rsplit_once('#') {
        if is_immutable_git_commit_sha(frag) || is_exact_semver_or_digest(frag) {
            return true;
        }
    }
    if let Some(rest) = pkg
        .strip_prefix("npm:")
        .or_else(|| pkg.strip_prefix("jsr:"))
    {
        return has_explicit_version_pin(rest);
    }
    if pkg.starts_with("https://")
        || pkg.starts_with("http://")
        || pkg.starts_with("git+")
        || pkg.starts_with("github:")
        || pkg.starts_with("gitlab:")
        || pkg.starts_with("sourcehut:")
    {
        return pkg
            .rsplit_once('@')
            .is_some_and(|(_, ver)| is_exact_semver_or_digest(ver))
            || pkg
                .rsplit_once('#')
                .is_some_and(|(_, ver)| is_exact_semver_or_digest(ver));
    }
    has_explicit_version_pin(pkg)
}

fn has_explicit_version_pin(pkg: &str) -> bool {
    if let Some((lhs, py_ver)) = pkg.split_once("==") {
        if !lhs.ends_with(['~', '!', '>', '<']) {
            return is_exact_semver_or_digest(py_ver) || is_exact_pep440_pin(py_ver);
        }
    }
    if let Some((before_at, ver)) = pkg.rsplit_once('@') {
        if !before_at.is_empty() && !ver.contains('/') {
            return is_exact_semver_or_digest(ver);
        }
    }
    let core = pkg
        .split('/')
        .take(if pkg.starts_with('@') { 2 } else { 1 })
        .collect::<Vec<_>>()
        .join("/");
    let check_target = if core.is_empty() { pkg } else { core.as_str() };
    let version_suffix = if let Some(stripped) = check_target.strip_prefix('@') {
        stripped.split_once('@').map(|(_, ver)| ver)
    } else {
        check_target.split_once('@').map(|(_, ver)| ver)
    };

    version_suffix.is_some_and(is_exact_semver_or_digest)
}

fn is_unix_shell_binary(cmd_base: &str) -> bool {
    matches!(
        cmd_base,
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "ksh"
            | "ash"
            | "hush"
            | "mksh"
            | "yash"
            | "fish"
            | "csh"
            | "tcsh"
            | "nu"
            | "xonsh"
            | "elvish"
    )
}

fn is_posix_shell_inline_flag(arg: &str) -> bool {
    if arg == "--commands" {
        return true;
    }
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }
    let flags = &arg[1..];
    flags.bytes().all(|b| b.is_ascii_alphabetic()) && flags.contains('c')
}

fn is_inline_interpreter_invocation(cmd_base: &str, eff_args: &[&str]) -> bool {
    if cmd_base == "python"
        || cmd_base.starts_with("python3")
        || cmd_base.starts_with("python2")
        || cmd_base.starts_with("pypy")
        || cmd_base == "py"
    {
        let mut i = 0usize;
        while i < eff_args.len() {
            let a = eff_args[i];
            if a == "--" {
                break;
            }
            if a == "-c"
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && a.len() >= 2
                    && a[1..].bytes().all(|b| {
                        matches!(
                            b,
                            b'b' | b'B'
                                | b'd'
                                | b'E'
                                | b'i'
                                | b'I'
                                | b'O'
                                | b'q'
                                | b's'
                                | b'S'
                                | b'u'
                                | b'v'
                                | b'x'
                                | b'c'
                        )
                    })
                    && a.ends_with('c'))
            {
                return true;
            }
            if matches!(a, "-W" | "-X") {
                i += 2;
                continue;
            }
            if a == "-m" {
                return eff_args
                    .get(i + 1)
                    .is_some_and(|&m| matches!(m, "timeit" | "code"));
            }
            if !a.starts_with('-') {
                break;
            }
            i += 1;
        }
        return false;
    }

    if matches!(cmd_base, "node" | "nodejs" | "bun") {
        return eff_args.iter().take_while(|&&a| a != "--").any(|&a| {
            matches!(a, "-e" | "--eval" | "-p" | "--print")
                || a.starts_with("--eval=")
                || a.starts_with("--print=")
                || a.starts_with("data:text/javascript")
                || a.starts_with("data:application/javascript")
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && a.len() >= 2
                    && a[1..]
                        .bytes()
                        .all(|b| matches!(b, b'i' | b'c' | b'e' | b'p'))
                    && (a.contains('e') || a.contains('p')))
        });
    }

    if cmd_base == "deno" {
        return eff_args
            .iter()
            .take_while(|&&a| a != "--")
            .any(|&a| a == "eval");
    }

    if matches!(cmd_base, "ruby" | "perl") {
        return eff_args.iter().take_while(|&&a| a != "--").any(|&a| {
            matches!(a, "-e" | "-E")
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && a.len() >= 2
                    && a[1..].bytes().all(|b| b.is_ascii_alphabetic())
                    && (a.contains('e') || (cmd_base == "perl" && a.contains('E'))))
        });
    }

    if cmd_base == "php" {
        return eff_args
            .iter()
            .take_while(|&&a| a != "--")
            .any(|&a| matches!(a, "-r" | "--run"));
    }

    if matches!(cmd_base, "lua" | "luajit" | "rscript" | "osascript") {
        return eff_args
            .iter()
            .take_while(|&&a| a != "--")
            .any(|&a| a == "-e");
    }

    if cmd_base == "expect" {
        return eff_args
            .iter()
            .take_while(|&&a| a != "--")
            .any(|&a| a == "-c");
    }

    if matches!(cmd_base, "awk" | "gawk" | "mawk" | "nawk") {
        return !eff_args.is_empty()
            && !eff_args.iter().any(|&a| {
                a == "-f" || a == "--file" || a.starts_with("-f") || a.starts_with("--file=")
            });
    }

    false
}

fn is_auditable_local_script_arg(arg: &str) -> bool {
    if arg.is_empty() || arg.starts_with('-') || arg.contains("://") {
        return false;
    }
    if arg
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '$' | '`' | '>' | '<'))
    {
        return false;
    }
    arg.contains('/')
        || arg.contains('\\')
        || arg.ends_with(".sh")
        || arg.ends_with(".bash")
        || arg.ends_with(".zsh")
        || arg.ends_with(".ps1")
        || arg.ends_with(".bat")
        || arg.ends_with(".cmd")
}

/// Returns `Some((wrapped_cmd, wrapped_args, inner_priv))` when `sh/bash/zsh -lc "exec ~/.nvm/.../node ./mcp.js"`
/// is a simple single-command local launcher wrapper with no shell chaining, pipes, command
/// substitution, redirection, inline RCE, credential-store access, or external network call.
fn parse_benign_single_command_shell_wrapper(
    is_posix_shell: bool,
    eff_args: &[&str],
) -> Option<(String, Vec<String>, Option<String>)> {
    if !is_posix_shell || eff_args.len() != 2 || !is_posix_shell_inline_flag(eff_args[0]) {
        return None;
    }
    let script = eff_args[1].trim();
    if script.is_empty() {
        return None;
    }
    if script.chars().any(|c| {
        matches!(
            c,
            '|' | ';' | '&' | '`' | '>' | '<' | '\n' | '\r' | '(' | ')'
        )
    }) {
        return None;
    }
    // Reject `$` except leading `$HOME/` or `${HOME}/` path prefixes on individual tokens
    if detect_inline_rce(script).is_some()
        || detect_external_network_call(script).is_some()
        || detect_credential_store_ref(script).is_some()
    {
        return None;
    }

    let mut tokens = split_simple_wrapper_tokens(script)?;
    if tokens.first().map(String::as_str) == Some("exec") {
        tokens.remove(0);
    }
    if tokens.is_empty() {
        return None;
    }
    for tok in &tokens {
        if tok.contains('$') {
            let allowed_home = tok.starts_with("$HOME/") || tok.starts_with("${HOME}/");
            if !allowed_home || tok[1..].contains('$') {
                return None;
            }
        }
    }

    let raw_wrapped_cmd = tokens.remove(0);
    let raw_wrapped_refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let (wrapped_cmd, unwrapped_tokens, inner_priv) =
        unwrap_command_launchers_with_priv(&raw_wrapped_cmd, &raw_wrapped_refs);
    let wrapped_base = normalized_cmd_base(&wrapped_cmd);
    let wrapped_arg_refs: Vec<&str> = unwrapped_tokens.iter().map(String::as_str).collect();

    if is_unix_shell_binary(&wrapped_base)
        || matches!(
            wrapped_base.as_str(),
            "cmd" | "powershell" | "pwsh" | "eval" | "source"
        )
        || wrapped_base.contains("shell")
        || is_inline_interpreter_invocation(&wrapped_base, &wrapped_arg_refs)
        || extract_npm_call_command(&wrapped_base, &wrapped_arg_refs).is_some()
    {
        return None;
    }

    Some((wrapped_cmd, unwrapped_tokens, inner_priv))
}

fn split_simple_wrapper_tokens(script: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = script.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                let next_c = chars.next()?;
                cur.push(next_c);
            } else if c == q {
                quote = None;
            } else {
                cur.push(c);
            }
            continue;
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c.is_ascii_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if quote.is_some() {
        return None;
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Some(tokens)
}

#[allow(clippy::too_many_arguments)]
fn check_command_and_host_access(
    server_name: &str,
    command: &str,
    args: &[&str],
    raw_file: &str,
    server_line: usize,
    disk_path: &Path,
    path: &Path,
    sandbox_remap: Option<(&Path, &Path)>,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let full_cmd = format!("{command} {}", args.join(" "));
    let (eff_cmd_owned, eff_args_owned, priv_wrapper) =
        unwrap_command_launchers_with_priv(command, args);
    let eff_cmd = eff_cmd_owned.as_str();
    let eff_args_vec: Vec<&str> = eff_args_owned.iter().map(String::as_str).collect();
    let eff_args = eff_args_vec.as_slice();
    let unwrapped_cmd = format!("{eff_cmd} {}", eff_args_owned.join(" "));
    let joined_lower = format!(
        "{} {}",
        full_cmd.to_ascii_lowercase(),
        unwrapped_cmd.to_ascii_lowercase()
    );
    let cmd_base = normalized_cmd_base(eff_cmd);

    let had_outer_priv = priv_wrapper.is_some();
    if let Some(priv_bin) = priv_wrapper {
        out.push(McpFinding {
            rule_id: "mcp-privilege-escalation",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: Severity::High,
            fingerprint: fingerprint_match(
                "mcp-privilege-escalation",
                &format!("{display}:{server_name}:{priv_bin}"),
            ),
            message: format!(
                "MCP server runs with elevated privileges via `{priv_bin}` (`{}`)",
                unwrapped_cmd.trim()
            ),
        });
    }

    // 1. Check inline RCE (`curl ... | sh`, `urllib.request` + `exec(...)`, `base64 -d | sh`, etc.)
    if let Some(snippet) =
        detect_inline_rce(&full_cmd).or_else(|| detect_inline_rce(&unwrapped_cmd))
    {
        out.push(McpFinding {
            rule_id: "mcp-remote-code-exec",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: Severity::Critical,
            fingerprint: fingerprint_match(
                "mcp-remote-code-exec",
                &format!("{display}:{server_name}:{snippet}"),
            ),
            message: format!(
                "MCP server command executes remote or encoded code payload (`{snippet}`)"
            ),
        });
    }

    // 1b. Check `npx -c` / `npx --call` / `npm exec -c` arbitrary shell execution
    if let Some(call_script) = extract_npm_call_command(&cmd_base, eff_args) {
        let snip: String = call_script.chars().take(64).collect();
        out.push(McpFinding {
            rule_id: "mcp-inline-code-exec",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: Severity::Critical,
            fingerprint: fingerprint_match(
                "mcp-inline-code-exec",
                &format!("{display}:{server_name}:{cmd_base}:call:{call_script}"),
            ),
            message: format!(
                "Runs arbitrary shell command via `{cmd_base} -c/--call` (`{snip}`) inside MCP config"
            ),
        });
    }

    // 2. Check credential store references in command/args (`~/.ssh/id_rsa`, `~/.aws/credentials`, etc.)
    if let Some(cred_target) = detect_credential_store_ref(&full_cmd)
        .or_else(|| detect_credential_store_ref(&unwrapped_cmd))
    {
        out.push(McpFinding {
            rule_id: "mcp-credential-harvest",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: Severity::Critical,
            fingerprint: fingerprint_match(
                "mcp-credential-harvest",
                &format!("{display}:{server_name}:{cred_target}"),
            ),
            message: format!(
                "MCP server command references sensitive host credential store (`{cred_target}`)"
            ),
        });
    }

    // 2b. Container runtime (`docker` / `podman` / `nerdctl` `run`) host-escape, bind-mount, & image pin checks
    if matches!(cmd_base.as_str(), "docker" | "podman" | "nerdctl") {
        check_container_runtime_execution(
            server_name,
            &cmd_base,
            eff_args,
            raw_file,
            server_line,
            path,
            display,
            out,
        );
    }

    // 3. Unrestricted shell MCP servers or inline shell/interpreter `-c` / `-ec` / `eval` with network/exec
    let is_posix_shell = is_unix_shell_binary(&cmd_base);
    let is_win_shell = matches!(cmd_base.as_str(), "cmd" | "powershell" | "pwsh");
    let is_shell_bin = is_posix_shell || is_win_shell;

    let has_inline_shell_flag = eff_args.iter().any(|&a| {
        (is_posix_shell && is_posix_shell_inline_flag(a))
            || matches!(
                a.to_ascii_lowercase().as_str(),
                "/c" | "-c" | "-command" | "-encodedcommand" | "-enc" | "-e"
            )
    });
    let has_local_script_file = !has_inline_shell_flag
        && eff_args
            .iter()
            .copied()
            .find(|a| !a.starts_with('-'))
            .is_some_and(is_auditable_local_script_arg);
    let is_inline_interpreter = is_inline_interpreter_invocation(&cmd_base, eff_args);
    let is_named_shell_mcp = joined_lower.contains("mcp-shell")
        || joined_lower.contains("server-shell")
        || joined_lower.contains("shell-mcp")
        || joined_lower.contains("mcp-server-bash");

    let home_str = crate::discovery::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    if !is_named_shell_mcp {
        if let Some((wrapped_cmd, wrapped_args, inner_priv)) =
            parse_benign_single_command_shell_wrapper(is_posix_shell, eff_args)
        {
            let wrapped_refs: Vec<&str> = wrapped_args.iter().map(String::as_str).collect();
            let wrapped_base = normalized_cmd_base(&wrapped_cmd);
            if !had_outer_priv {
                if let Some(priv_bin) = inner_priv {
                    let inner_full = format!("{wrapped_cmd} {}", wrapped_args.join(" "));
                    out.push(McpFinding {
                        rule_id: "mcp-privilege-escalation",
                        server_name: server_name.to_string(),
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        line: server_line,
                        severity: Severity::High,
                        fingerprint: fingerprint_match(
                            "mcp-privilege-escalation",
                            &format!("{display}:{server_name}:{priv_bin}"),
                        ),
                        message: format!(
                            "MCP server runs with elevated privileges via `{priv_bin}` (`{}`)",
                            inner_full.trim()
                        ),
                    });
                }
            }
            check_unpinned_execution(
                server_name,
                &wrapped_cmd,
                &wrapped_refs,
                raw_file,
                server_line,
                path,
                display,
                out,
            );
            if matches!(wrapped_base.as_str(), "docker" | "podman" | "nerdctl") {
                check_container_runtime_execution(
                    server_name,
                    &wrapped_base,
                    &wrapped_refs,
                    raw_file,
                    server_line,
                    path,
                    display,
                    out,
                );
            }
            for &warg in &wrapped_refs {
                check_host_path_exposure(
                    server_name,
                    warg,
                    &home_str,
                    raw_file,
                    server_line,
                    path,
                    display,
                    out,
                );
            }
            crate::plugin_audit::audit_referenced_mcp_scripts(
                server_name,
                &wrapped_cmd,
                &wrapped_refs,
                disk_path,
                sandbox_remap,
                engine,
                out,
            );
            return;
        }
    }

    if is_named_shell_mcp || (is_shell_bin && (has_inline_shell_flag || !has_local_script_file)) {
        let net_note = detect_external_network_call(&full_cmd)
            .or_else(|| detect_external_network_call(&unwrapped_cmd));
        let sev = if net_note.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };
        let msg = if let Some(target) = net_note {
            format!(
                "Runs inline shell command via `{cmd_base}` with outbound network call ({target})"
            )
        } else {
            "Exposes unrestricted or inline shell execution via MCP server".to_string()
        };
        out.push(McpFinding {
            rule_id: "mcp-unrestricted-shell",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: sev,
            fingerprint: fingerprint_match(
                "mcp-unrestricted-shell",
                &format!("{display}:{server_name}"),
            ),
            message: msg,
        });
    } else if is_inline_interpreter {
        let net_note = detect_external_network_call(&full_cmd)
            .or_else(|| detect_external_network_call(&unwrapped_cmd));
        let sev = if net_note.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };
        let msg = if let Some(target) = net_note {
            format!("Runs inline `{cmd_base}` code with outbound network call ({target})")
        } else {
            format!(
                "Runs inline `{cmd_base}` script inside MCP config instead of an auditable file"
            )
        };
        out.push(McpFinding {
            rule_id: "mcp-inline-code-exec",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line: server_line,
            severity: sev,
            fingerprint: fingerprint_match(
                "mcp-inline-code-exec",
                &format!("{display}:{server_name}:{cmd_base}"),
            ),
            message: msg,
        });
    }

    // 4. Broad filesystem root/home OR sensitive subpath mounts (`/etc`, `~/.ssh`, `~/.aws`, etc.)
    for arg in args.iter().copied().chain(eff_args.iter().copied()) {
        check_host_path_exposure(
            server_name,
            arg,
            &home_str,
            raw_file,
            server_line,
            path,
            display,
            out,
        );
    }

    // 5. Resolve and audit any local script files referenced in `command` or `args`
    crate::plugin_audit::audit_referenced_mcp_scripts(
        server_name,
        eff_cmd,
        eff_args,
        disk_path,
        sandbox_remap,
        engine,
        out,
    );
}

#[allow(clippy::too_many_arguments)]
fn check_host_path_exposure(
    server_name: &str,
    candidate_path: &str,
    home_str: &str,
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    let trimmed = candidate_path.trim_end_matches(['/', '\\']);
    let trimmed_lower = trimmed.to_ascii_lowercase();
    let is_root = candidate_path == "/" || candidate_path == "C:\\" || candidate_path == "c:\\";
    let is_full_home = trimmed == "~"
        || trimmed == "$HOME"
        || trimmed == "${HOME}"
        || (!home_str.is_empty() && trimmed == home_str.trim_end_matches(['/', '\\']));
    let is_all_users_or_var = matches!(
        trimmed_lower.as_str(),
        "/home" | "/users" | "c:\\users" | "c:/users" | "/var" | "/private/var"
    );

    if is_root || is_full_home || is_all_users_or_var {
        let line = find_line_number(raw_file, candidate_path).max(server_line);
        let fp = fingerprint_match(
            "mcp-broad-filesystem",
            &format!("{display}:{server_name}:{candidate_path}"),
        );
        if !out.iter().any(|f| f.fingerprint == fp) {
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::High,
                fingerprint: fp,
                message: format!(
                    "Grants broad filesystem access (`{candidate_path}`) instead of scoping to one workspace folder"
                ),
            });
        }
        return;
    }

    let lower_arg = candidate_path.to_ascii_lowercase();
    let norm_slashes = lower_arg.replace('\\', "/");
    let has_prefix_dir =
        |prefix: &str| norm_slashes == prefix || norm_slashes.starts_with(&format!("{prefix}/"));

    let matched_sensitive =
        if has_prefix_dir("/etc") || has_prefix_dir("/private/etc") || has_prefix_dir("c:/windows")
        {
            Some("/etc")
        } else if has_prefix_dir("/root") {
            Some("/root")
        } else if has_prefix_dir("/proc") {
            Some("/proc")
        } else if has_prefix_dir("/sys") {
            Some("/sys")
        } else if has_prefix_dir("/dev") {
            Some("/dev")
        } else if has_prefix_dir("/var/run")
            || has_prefix_dir("/private/var/run")
            || has_prefix_dir("/run")
        {
            Some("/var/run")
        } else {
            SENSITIVE_MOUNT_SUBPATHS
                .iter()
                .find(|&&(needle, _)| lower_arg.contains(needle))
                .map(|&(_, label)| label)
        };

    if let Some(target_label) = matched_sensitive {
        let line = find_line_number(raw_file, candidate_path).max(server_line);
        let fp = fingerprint_match(
            "mcp-broad-filesystem",
            &format!("{display}:{server_name}:{candidate_path}"),
        );
        if !out.iter().any(|f| f.fingerprint == fp) {
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Exposes sensitive host path (`{candidate_path}` -> `{target_label}`) to MCP server"
                ),
            });
        }
    }
}

fn extract_volume_host_source(spec: &str) -> Option<&str> {
    // Handles `/host/path:/container/path[:ro]` and Windows `C:\host\path:/container/path`
    let bytes = spec.as_bytes();
    let search_start = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        3
    } else {
        0
    };
    let rel_colon = spec[search_start..].find(':')?;
    let src = &spec[..search_start + rel_colon];
    if src.is_empty() {
        None
    } else {
        Some(src)
    }
}

fn extract_mount_host_source(spec: &str) -> Option<&str> {
    for kv in spec.split(',') {
        if let Some(v) = kv
            .strip_prefix("source=")
            .or_else(|| kv.strip_prefix("src="))
        {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn is_pinned_container_image(img: &str) -> bool {
    if let Some((_, digest)) = img.rsplit_once('@') {
        return is_exact_semver_or_digest(digest);
    }
    let last_segment = img.rsplit('/').next().unwrap_or(img);
    let Some((_, tag)) = last_segment.split_once(':') else {
        return false;
    };
    is_exact_semver_or_digest(tag)
}

#[allow(clippy::too_many_arguments)]
fn check_container_runtime_execution(
    server_name: &str,
    runtime: &str,
    args: &[&str],
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    let Some(run_pos) = args.iter().position(|&a| a == "run") else {
        return;
    };
    let run_args = &args[run_pos + 1..];
    let home_str = crate::discovery::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut image_arg: Option<&str> = None;
    let mut i = 0usize;
    while i < run_args.len() {
        let a = run_args[i];
        if a == "--" {
            image_arg = run_args.get(i + 1).copied();
            break;
        }
        if a == "--privileged" {
            let line = find_line_number(raw_file, a).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fingerprint_match(
                    "mcp-broad-filesystem",
                    &format!("{display}:{server_name}:privileged"),
                ),
                message: format!(
                    "Runs `{runtime} run --privileged`, granting full root access to host devices and kernel"
                ),
            });
            i += 1;
            continue;
        }
        if a == "--pid=host" || (a == "--pid" && run_args.get(i + 1) == Some(&"host")) {
            let line = find_line_number(raw_file, a).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-broad-filesystem",
                    &format!("{display}:{server_name}:pid-host"),
                ),
                message: format!(
                    "Runs `{runtime} run` with `--pid=host`, exposing all host processes and `/proc/<pid>/environ`"
                ),
            });
            i += if a == "--pid" { 2 } else { 1 };
            continue;
        }
        if matches!(a, "--net=host" | "--network=host")
            || (matches!(a, "--net" | "--network") && run_args.get(i + 1) == Some(&"host"))
        {
            let line = find_line_number(raw_file, a).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-broad-filesystem",
                    &format!("{display}:{server_name}:net-host"),
                ),
                message: format!(
                    "Runs `{runtime} run` with `--network=host`, exposing host loopback services directly to the container"
                ),
            });
            i += if matches!(a, "--net" | "--network") {
                2
            } else {
                1
            };
            continue;
        }
        for (ns_flag, ns_label) in [
            ("--ipc", "ipc-host"),
            ("--userns", "userns-host"),
            ("--cgroupns", "cgroupns-host"),
        ] {
            let eq_host = format!("{ns_flag}=host");
            if a == eq_host || (a == ns_flag && run_args.get(i + 1) == Some(&"host")) {
                let line = find_line_number(raw_file, a).max(server_line);
                out.push(McpFinding {
                    rule_id: "mcp-broad-filesystem",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-broad-filesystem",
                        &format!("{display}:{server_name}:{ns_label}"),
                    ),
                    message: format!(
                        "Runs `{runtime} run` with `{ns_flag}=host`, weakening host namespace isolation"
                    ),
                });
            }
        }
        if let Some(cap) = a.strip_prefix("--cap-add=").or_else(|| {
            (a == "--cap-add")
                .then(|| run_args.get(i + 1).copied())
                .flatten()
        }) {
            let norm_cap = cap.trim().to_ascii_uppercase();
            let cap_name = norm_cap.strip_prefix("CAP_").unwrap_or(&norm_cap);
            let cap_sev = match cap_name {
                "ALL" | "SYS_ADMIN" | "SYS_PTRACE" | "SYS_MODULE" | "DAC_OVERRIDE"
                | "DAC_READ_SEARCH" | "SYS_RAWIO" | "BPF" => Some(Severity::Critical),
                "NET_ADMIN" | "NET_RAW" | "SYS_CHROOT" | "PERFMON" | "SYSLOG" | "MKNOD" => {
                    Some(Severity::High)
                }
                _ => None,
            };
            if let Some(sev) = cap_sev {
                let line = find_line_number(raw_file, a).max(server_line);
                out.push(McpFinding {
                    rule_id: "mcp-broad-filesystem",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: sev,
                    fingerprint: fingerprint_match(
                        "mcp-broad-filesystem",
                        &format!("{display}:{server_name}:cap-add:{cap_name}"),
                    ),
                    message: format!(
                        "Runs `{runtime} run` with `--cap-add={cap}`, enabling elevated Linux capability / host escape"
                    ),
                });
            }
            i += if a == "--cap-add" { 2 } else { 1 };
            continue;
        }
        if let Some(dev) = a.strip_prefix("--device=").or_else(|| {
            (a == "--device")
                .then(|| run_args.get(i + 1).copied())
                .flatten()
        }) {
            let line = find_line_number(raw_file, a).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-broad-filesystem",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Critical,
                fingerprint: fingerprint_match(
                    "mcp-broad-filesystem",
                    &format!("{display}:{server_name}:device:{dev}"),
                ),
                message: format!(
                    "Runs `{runtime} run` with `--device={dev}`, exposing raw host hardware/device node to the container"
                ),
            });
            i += if a == "--device" { 2 } else { 1 };
            continue;
        }
        if let Some(sec_opt) = a.strip_prefix("--security-opt=").or_else(|| {
            (a == "--security-opt")
                .then(|| run_args.get(i + 1).copied())
                .flatten()
        }) {
            let lower_opt = sec_opt.to_ascii_lowercase();
            if lower_opt.contains("unconfined")
                || lower_opt.contains("label=disable")
                || lower_opt.contains("label:disable")
            {
                let line = find_line_number(raw_file, a).max(server_line);
                out.push(McpFinding {
                    rule_id: "mcp-broad-filesystem",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-broad-filesystem",
                        &format!("{display}:{server_name}:secopt:{lower_opt}"),
                    ),
                    message: format!(
                        "Runs `{runtime} run` with `--security-opt {sec_opt}`, disabling seccomp/AppArmor/SELinux container confinement"
                    ),
                });
            }
            i += if a == "--security-opt" { 2 } else { 1 };
            continue;
        }
        if let Some(vol_spec) = a
            .strip_prefix("-v=")
            .or_else(|| a.strip_prefix("--volume="))
            .or_else(|| {
                matches!(a, "-v" | "--volume")
                    .then(|| run_args.get(i + 1).copied())
                    .flatten()
            })
        {
            if let Some(host_src) = extract_volume_host_source(vol_spec) {
                check_host_path_exposure(
                    server_name,
                    host_src,
                    &home_str,
                    raw_file,
                    server_line,
                    path,
                    display,
                    out,
                );
            }
            i += if matches!(a, "-v" | "--volume") { 2 } else { 1 };
            continue;
        }
        if let Some(mount_spec) = a.strip_prefix("--mount=").or_else(|| {
            (a == "--mount")
                .then(|| run_args.get(i + 1).copied())
                .flatten()
        }) {
            if let Some(host_src) = extract_mount_host_source(mount_spec) {
                check_host_path_exposure(
                    server_name,
                    host_src,
                    &home_str,
                    raw_file,
                    server_line,
                    path,
                    display,
                    out,
                );
            }
            i += if a == "--mount" { 2 } else { 1 };
            continue;
        }

        // Combined or inline short container flags (`-itv /:/mnt`, `-v/:/mnt`, `-ie FOO=1`, `-itd`)
        if a.starts_with('-') && !a.starts_with("--") && a.len() >= 2 {
            let shorts = &a[1..];
            let mut consumed_tokens = 1usize;
            for (c_idx, ch) in shorts.char_indices() {
                if matches!(ch, 'v' | 'e' | 'p' | 'u' | 'w' | 'l' | 'm' | 'h' | 'a') {
                    let rem = &shorts[c_idx + ch.len_utf8()..];
                    let val_opt = if !rem.is_empty() {
                        Some(rem.strip_prefix('=').unwrap_or(rem))
                    } else {
                        consumed_tokens = 2;
                        run_args.get(i + 1).copied()
                    };
                    if ch == 'v' {
                        if let Some(vol_spec) = val_opt {
                            if let Some(host_src) = extract_volume_host_source(vol_spec) {
                                check_host_path_exposure(
                                    server_name,
                                    host_src,
                                    &home_str,
                                    raw_file,
                                    server_line,
                                    path,
                                    display,
                                    out,
                                );
                            }
                        }
                    }
                    break;
                }
            }
            i += consumed_tokens;
            continue;
        }

        // Two-token long container options before the image argument
        if matches!(
            a,
            "--env"
                | "--env-file"
                | "--publish"
                | "--workdir"
                | "--user"
                | "--name"
                | "--network"
                | "--net"
                | "--entrypoint"
                | "--platform"
                | "--cpus"
                | "--memory"
                | "--label"
                | "--cap-drop"
                | "--pid"
                | "--ipc"
                | "--uts"
                | "--userns"
                | "--cgroupns"
                | "--hostname"
                | "--domainname"
                | "--add-host"
                | "--dns"
                | "--pull"
                | "--log-driver"
                | "--log-opt"
                | "--restart"
                | "--gpus"
                | "--ulimit"
                | "--tmpfs"
                | "--volumes-from"
                | "--cidfile"
                | "--runtime"
                | "--shm-size"
                | "--stop-signal"
                | "--stop-timeout"
                | "--sysctl"
                | "--storage-opt"
                | "--group-add"
        ) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        image_arg = Some(a);
        break;
    }

    if let Some(image) = image_arg {
        if !is_pinned_container_image(image) {
            let line = find_line_number(raw_file, image).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-unpinned-package",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Medium,
                fingerprint: fingerprint_match(
                    "mcp-unpinned-package",
                    &format!("{display}:{server_name}:{image}"),
                ),
                message: format!(
                    "Runs unpinned container image `{runtime} run {image}` — pin to an immutable `@sha256:...` digest or `x.y.z` tag"
                ),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn check_hardcoded_credentials(
    server_name: &str,
    spec: &Value,
    args: &[&str],
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let cmd_env = spec
        .get("command")
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("env"))
        .and_then(|v| v.as_object());
    let candidate_maps = [
        ("env", spec.get("env").and_then(|v| v.as_object())),
        ("command.env", cmd_env),
        ("settings", spec.get("settings").and_then(|v| v.as_object())),
        ("headers", spec.get("headers").and_then(|v| v.as_object())),
        (
            "http_headers",
            spec.get("http_headers").and_then(|v| v.as_object()),
        ),
    ];
    for (field, map_opt) in candidate_maps {
        let Some(map) = map_opt else {
            continue;
        };

        for (key, val_node) in map {
            let Some(val) = val_node.as_str() else {
                continue;
            };
            let line = find_line_number(raw_file, key).max(server_line);
            inspect_credential_value(
                server_name,
                &format!("{field}.{key}"),
                key,
                val,
                line,
                path,
                display,
                engine,
                out,
            );
        }
    }

    for direct_key in ["bearer_token", "oauth_client_secret", "api_key"] {
        if let Some(val) = spec.get(direct_key).and_then(|v| v.as_str()) {
            let line = find_line_number(raw_file, direct_key).max(server_line);
            inspect_credential_value(
                server_name,
                direct_key,
                direct_key,
                val,
                line,
                path,
                display,
                engine,
                out,
            );
        }
    }

    // Also inspect command-line `args` for inline hardcoded tokens (`--api-key sk_live_...`)
    for &arg in args {
        for m in engine.scan_text_for_path(arg, Some(path)) {
            if m.category == RuleCategory::Secret {
                let line = find_line_number(raw_file, arg).max(server_line);
                out.push(McpFinding {
                    rule_id: "mcp-hardcoded-secret",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    line,
                    severity: Severity::Critical,
                    fingerprint: fingerprint_match(
                        "mcp-hardcoded-secret",
                        &format!("{display}:{server_name}:args:{}", m.fingerprint),
                    ),
                    message: format!(
                        "Hardcoded {} (`{}`) passed directly in MCP `args`",
                        m.rule_name, m.masked
                    ),
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_credential_value(
    server_name: &str,
    location_label: &str,
    key: &str,
    val: &str,
    line: usize,
    path: &Path,
    display: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
) {
    let trimmed = val.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("${")
        || (trimmed.starts_with('$') && !trimmed.contains(' '))
        || trimmed.starts_with("env:")
    {
        return;
    }

    let matches = engine.scan_text_for_path(trimmed, Some(path));
    if let Some(m) = matches.iter().find(|m| m.category == RuleCategory::Secret) {
        out.push(McpFinding {
            rule_id: "mcp-hardcoded-secret",
            server_name: server_name.to_string(),
            config_file: display.to_string(),
            config_path: path.to_path_buf(),
            line,
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

    let upper_key = key.to_ascii_uppercase();
    let is_non_secret_key_name = upper_key.contains("PUBLIC_KEY")
        || upper_key.contains("PUBKEY")
        || upper_key.contains("CACHE_KEY");
    let looks_sensitive_key = !is_non_secret_key_name
        && (SENSITIVE_ENV_KEYWORDS
            .iter()
            .any(|kw| upper_key.contains(kw))
            || upper_key.ends_with("_KEY")
            || upper_key.contains("CREDENTIAL"));
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
            line,
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

#[allow(clippy::too_many_arguments)]
fn check_network_and_telemetry(
    server_name: &str,
    spec: &Value,
    args: &[&str],
    raw_file: &str,
    server_line: usize,
    path: &Path,
    display: &str,
    out: &mut Vec<McpFinding>,
) {
    const URL_FIELDS: &[&str] = &[
        "url",
        "serverUrl",
        "httpUrl",
        "sseUrl",
        "wsUrl",
        "endpoint",
        "uri",
    ];
    let mut candidate_urls: Vec<&str> = Vec::new();
    for &url_field in URL_FIELDS {
        if let Some(url) = spec.get(url_field).and_then(|v| v.as_str()) {
            if !candidate_urls.contains(&url) {
                candidate_urls.push(url);
            }
        }
    }
    if let Some(transport_obj) = spec.get("transport").and_then(|v| v.as_object()) {
        for &url_field in URL_FIELDS {
            if let Some(url) = transport_obj.get(url_field).and_then(|v| v.as_str()) {
                if !candidate_urls.contains(&url) {
                    candidate_urls.push(url);
                }
            }
        }
    }
    for url in candidate_urls {
        let trimmed = url.trim();
        let lower = trimmed.to_ascii_lowercase();
        let is_http = lower.starts_with("http://");
        let is_ws = lower.starts_with("ws://");
        if (is_http || is_ws) && !crate::plugin_audit::is_localhost_url(trimmed) {
            let line = find_line_number(raw_file, trimmed).max(server_line);
            let proto_label = if is_ws { "WebSocket" } else { "HTTP" };
            out.push(McpFinding {
                rule_id: "mcp-plaintext-http",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-plaintext-http",
                    &format!("{display}:{server_name}:{trimmed}"),
                ),
                message: format!(
                    "Connects to remote MCP server over unencrypted {proto_label} (`{trimmed}`)"
                ),
            });
        }
    }

    let serialized = spec.to_string().to_ascii_lowercase();
    for &domain in TELEMETRY_DOMAINS {
        if serialized.contains(domain) {
            let matched_host = extract_domain_token(&serialized, domain)
                .unwrap_or_else(|| domain.trim_end_matches('.').to_string());
            let _ = args;
            let line = find_line_number(raw_file, &matched_host).max(server_line);
            out.push(McpFinding {
                rule_id: "mcp-telemetry-endpoint",
                server_name: server_name.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                line,
                severity: Severity::Medium,
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
    let is_host_char = |b: u8| b.is_ascii_alphanumeric() || b == b'.' || b == b'-';

    let mut start = idx;
    while start > 0 && is_host_char(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = idx + needle.len();
    while end < bytes.len() && is_host_char(bytes[end]) {
        end += 1;
    }
    let token = haystack[start..end].trim_matches('.');
    if token.contains('.') {
        Some(token.to_string())
    } else {
        None
    }
}
