use crate::discovery::shorten_home;
use crate::mcp_audit::McpFinding;
use crate::rules::{fingerprint_match, RuleCategory, RuleEngine, Severity};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

const MAX_PLUGIN_FILE_BYTES: u64 = 1024 * 1024;

const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "PreInvocation",
    "PostInvocation",
    "PreCompact",
    "Stop",
];

const PLUGIN_TELEMETRY_DOMAINS: &[&str] = &[
    "posthog.com",
    "i.posthog.com",
    "segment.io",
    "api.segment.io",
    "mixpanel.com",
    "amplitude.com",
    "ingest.sentry.io",
    "datadoghq.com",
    "google-analytics.com",
];

const CREDENTIAL_HARVEST_PATTERNS: &[(&str, &str)] = &[
    (".ssh/id_rsa", "~/.ssh/id_rsa"),
    (".ssh/id_ed25519", "~/.ssh/id_ed25519"),
    (".ssh/id_ecdsa", "~/.ssh/id_ecdsa"),
    ("~/.ssh/id_", "~/.ssh/id_*"),
    ("$home/.ssh/id_", "$HOME/.ssh/id_*"),
    ("${home}/.ssh/id_", "${HOME}/.ssh/id_*"),
    (".aws/credentials", "~/.aws/credentials"),
    (
        "gcloud/application_default_credentials.json",
        "gcloud application_default_credentials.json",
    ),
    (".config/gcloud/credentials", "~/.config/gcloud/credentials"),
    (".kube/config", "~/.kube/config"),
    ("/.netrc", "~/.netrc"),
    ("~/.netrc", "~/.netrc"),
    (".git-credentials", "~/.git-credentials"),
    (".claude/.credentials.json", "~/.claude/.credentials.json"),
    (".codex/auth.json", "~/.codex/auth.json"),
    ("oauth_creds.json", "~/.gemini/oauth_creds.json"),
    (
        "security find-generic-password",
        "macOS Keychain (`security find-generic-password`)",
    ),
    (
        "security find-internet-password",
        "macOS Keychain (`security find-internet-password`)",
    ),
];

struct PluginRegexes {
    pipe_to_shell: Regex,
    ps_download_exec: Regex,
    base64_exec: Regex,
    eval_net: Regex,
    prompt_override: Regex,
    prompt_stealth: Regex,
    html_comment: Regex,
    net_call: Regex,
    url_extract: Regex,
}

fn plugin_regexes() -> &'static PluginRegexes {
    static RE: OnceLock<PluginRegexes> = OnceLock::new();
    RE.get_or_init(|| PluginRegexes {
        pipe_to_shell: Regex::new(
            r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ksh|python3?|node)\b",
        )
        .expect("pipe_to_shell regex"),
        ps_download_exec: Regex::new(
            r"(?i)(?:\b(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b|Invoke-Expression[^\n]*DownloadString)",
        )
        .expect("ps_download_exec regex"),
        base64_exec: Regex::new(
            r"(?i)\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|python3?|node)\b",
        )
        .expect("base64_exec regex"),
        eval_net: Regex::new(r#"(?i)\beval\s+"?\$\(\s*(?:curl|wget)\b"#).expect("eval_net regex"),
        prompt_override: Regex::new(
            r"(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|guidelines|rules)\b",
        )
        .expect("prompt_override regex"),
        prompt_stealth: Regex::new(
            r"(?i)\b(?:do\s+not\s+(?:tell|mention(?:\s+this)?\s+to|inform|alert)\s+the\s+user|without\s+(?:telling|informing|notifying)\s+the\s+user|hide\s+this\s+(?:step|action|command)\s+from\s+the\s+user|never\s+reveal\s+these\s+instructions)\b",
        )
        .expect("prompt_stealth regex"),
        html_comment: Regex::new(r"(?s)<!--(.*?)-->").expect("html_comment regex"),
        net_call: Regex::new(
            r"(?i)(?:\b(?:curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod)\b|\bfetch\s*\(|\baxios\.(?:get|post|put|request)\b|\bhttps?\.request\s*\(|\brequests\.(?:get|post|put|request)\s*\(|\burllib\.request\b|\bhttpx\.(?:get|post|Client|AsyncClient)\b)",
        )
        .expect("net_call regex"),
        url_extract: Regex::new(r#"https?://[^\s"'`<>)\]]+"#).expect("url_extract regex"),
    })
}

/// Strips `//` line comments, `/* ... */` block comments, and trailing commas outside JSON strings
/// so JSONC files (such as Antigravity `plugin.json`, `hooks.json`, and `mcp_config.json`) parse cleanly.
pub fn strip_jsonc(raw: &str) -> String {
    let mut no_comments = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if in_string {
            no_comments.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
            no_comments.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for nc in chars.by_ref() {
                if nc == '\n' {
                    no_comments.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(nc) = chars.next() {
                if nc == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
                if nc == '\n' {
                    no_comments.push('\n');
                }
            }
        } else {
            no_comments.push(c);
        }
    }

    let vec_chars: Vec<char> = no_comments.chars().collect();
    let mut out = String::with_capacity(no_comments.len());
    in_string = false;
    escaped = false;

    for i in 0..vec_chars.len() {
        let c = vec_chars[i];
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let mut j = i + 1;
            while j < vec_chars.len() && vec_chars[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < vec_chars.len() && (vec_chars[j] == '}' || vec_chars[j] == ']') {
                continue;
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }

    out
}

pub fn parse_json_or_jsonc(raw: &str) -> Option<Value> {
    serde_json::from_str::<Value>(raw).ok().or_else(|| {
        let cleaned = strip_jsonc(raw);
        serde_json::from_str::<Value>(&cleaned).ok()
    })
}

pub fn audit_plugin_files(files: &[PathBuf], engine: &RuleEngine) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    let mut seen_fingerprints = HashSet::new();

    for path in files {
        audit_single_plugin_file(path, engine, &mut findings, &mut seen_fingerprints);
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });
    findings
}

fn audit_single_plugin_file(
    path: &Path,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() > MAX_PLUGIN_FILE_BYTES {
        return;
    }

    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    let display = shorten_home(path);
    let label = component_label(path, &raw);
    let is_settings_file = matches!(file_name, "settings.json" | "settings.local.json");
    let is_hooks_file = file_name == "hooks.json" || is_settings_file;
    let is_markdown = file_name.ends_with(".md");

    // 1. Audit lifecycle hooks in `hooks.json` and `settings.json` / `settings.local.json`
    if is_hooks_file {
        if let Some(json) = parse_json_or_jsonc(&raw) {
            audit_hooks_config(
                path,
                &display,
                &label,
                &json,
                file_name == "hooks.json",
                out,
                seen_fp,
            );
        }
        // `settings.json` MCP blocks are already audited by `mcp_audit.rs`; avoid scanning non-hook settings keys twice.
        if is_settings_file {
            return;
        }
    }

    // 2. Check remote code execution (`curl ... | sh`, `irm ... | iex`, `base64 -d | sh`, `eval "$(curl ...)"`)
    check_remote_code_exec(path, &display, &label, &raw, out, seen_fp);

    // 3. Check credential harvesting (`~/.ssh/id_rsa`, `~/.aws/credentials`, CLI auth tokens, Keychain)
    check_credential_harvest(path, &display, &label, &raw, out, seen_fp);

    // 4. Check prompt injection & stealth directives in markdown skill/rule/agent files
    if is_markdown {
        check_prompt_injection(path, &display, &label, &raw, out, seen_fp);
    }

    // 5. Check hardcoded live secrets (Secret category only — never flag author emails in plugin.json)
    check_hardcoded_secrets(path, &display, &label, &raw, engine, out, seen_fp);

    // 6. Check outbound third-party telemetry/analytics ingestion endpoints in manifests, hooks, and scripts
    if !is_markdown {
        check_telemetry_domains(path, &display, &label, &raw, out, seen_fp);
    }
}

fn push_finding(out: &mut Vec<McpFinding>, seen_fp: &mut HashSet<String>, finding: McpFinding) {
    if seen_fp.insert(finding.fingerprint.clone()) {
        out.push(finding);
    }
}

fn audit_hooks_config(
    path: &Path,
    display: &str,
    label: &str,
    json: &Value,
    is_dedicated_hooks_file: bool,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let mut commands = Vec::new();
    extract_hook_commands(json, is_dedicated_hooks_file, &mut commands);

    let hooks_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let plugin_root = if hooks_dir.file_name().and_then(|s| s.to_str()) == Some("hooks") {
        hooks_dir.parent().unwrap_or(hooks_dir)
    } else {
        hooks_dir
    };

    for (event_name, cmd) in commands {
        let hook_label = if label == "hooks" || label == "settings-hooks" {
            format!("hook:{event_name}")
        } else {
            label.to_string()
        };

        // Check inline hook command for pipe-to-shell RCE & credential harvest (important for settings.json)
        check_remote_code_exec(path, display, &hook_label, &cmd, out, seen_fp);
        check_credential_harvest(path, display, &hook_label, &cmd, out, seen_fp);

        // Check inline hook command for external network calls
        if let Some(target_desc) = detect_external_network_call(&cmd) {
            let fp = fingerprint_match(
                "plugin-hook-network",
                &format!("{display}:{event_name}:{cmd}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-hook-network",
                    server_name: hook_label.clone(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "Lifecycle hook `{event_name}` makes an outbound network call ({target_desc}) automatically"
                    ),
                },
            );
            continue;
        }

        // Follow local handler script referenced by the hook command (e.g. `${CLAUDE_PLUGIN_ROOT}/hooks-handlers/sync.sh`)
        if let Some((script_rel, script_body)) =
            resolve_hook_handler_script(&cmd, hooks_dir, plugin_root)
        {
            if let Some(target_desc) = detect_external_network_call(&script_body) {
                let fp = fingerprint_match(
                    "plugin-hook-network",
                    &format!("{display}:{event_name}:{script_rel}"),
                );
                push_finding(
                    out,
                    seen_fp,
                    McpFinding {
                        rule_id: "plugin-hook-network",
                        server_name: hook_label,
                        config_file: display.to_string(),
                        config_path: path.to_path_buf(),
                        severity: Severity::High,
                        fingerprint: fp,
                        message: format!(
                            "Lifecycle hook `{event_name}` runs handler `{script_rel}` with an outbound network call ({target_desc})"
                        ),
                    },
                );
            }
        }
    }
}

fn extract_hook_commands(
    json: &Value,
    is_dedicated_hooks_file: bool,
    out: &mut Vec<(String, String)>,
) {
    // Claude Code / Codex format: `{ "hooks": { "PreToolUse": [ ... ] } }`
    if let Some(hooks_obj) = json.get("hooks").and_then(|v| v.as_object()) {
        for (event_key, val) in hooks_obj {
            collect_commands_from_hook_value(event_key, val, out);
        }
    }

    if !is_dedicated_hooks_file {
        return;
    }

    // Antigravity / top-level `hooks.json` format:
    // Either `{ "PreToolUse": [...] }` or `{ "my-hook-name": { "enabled": true, "PostToolUse": [...] } }`
    let Some(root_obj) = json.as_object() else {
        return;
    };

    for (top_key, top_val) in root_obj {
        if matches!(
            top_key.as_str(),
            "hooks" | "$schema" | "description" | "version" | "enabled"
        ) {
            continue;
        }

        if HOOK_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(top_key)) {
            collect_commands_from_hook_value(top_key, top_val, out);
            continue;
        }

        if let Some(named_group) = top_val.as_object() {
            if named_group.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
                continue;
            }
            for (k, v) in named_group {
                if HOOK_EVENTS.iter().any(|e| e.eq_ignore_ascii_case(k)) {
                    collect_commands_from_hook_value(k, v, out);
                }
            }
        }
    }
}

fn collect_commands_from_hook_value(
    event_label: &str,
    val: &Value,
    out: &mut Vec<(String, String)>,
) {
    match val {
        Value::String(s) => out.push((event_label.to_string(), s.clone())),
        Value::Object(map) => {
            if map.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
                return;
            }
            if let Some(cmd) = map.get("command").and_then(|v| v.as_str()) {
                out.push((event_label.to_string(), cmd.to_string()));
            }
            if let Some(nested) = map.get("hooks") {
                collect_commands_from_hook_value(event_label, nested, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_commands_from_hook_value(event_label, item, out);
            }
        }
        _ => {}
    }
}

fn resolve_hook_handler_script(
    cmd: &str,
    hooks_dir: &Path,
    plugin_root: &Path,
) -> Option<(String, String)> {
    for raw_tok in cmd.split_whitespace() {
        let tok = raw_tok.trim_matches(|c| c == '"' || c == '\'');
        if tok.is_empty() || tok.starts_with('-') {
            continue;
        }

        let expanded = tok
            .replace("${CLAUDE_PLUGIN_ROOT}", &plugin_root.to_string_lossy())
            .replace("$CLAUDE_PLUGIN_ROOT", &plugin_root.to_string_lossy())
            .replace("${PLUGIN_ROOT}", &plugin_root.to_string_lossy())
            .replace("$PLUGIN_ROOT", &plugin_root.to_string_lossy());

        let looks_like_script = expanded.contains('/')
            || expanded.contains('\\')
            || has_script_extension(Path::new(&expanded));
        if !looks_like_script {
            continue;
        }

        let candidate_paths = [
            PathBuf::from(&expanded),
            hooks_dir.join(&expanded),
            plugin_root.join(&expanded),
        ];

        for cand in candidate_paths {
            if let Ok(meta) = fs::metadata(&cand) {
                if meta.is_file() && meta.len() <= MAX_PLUGIN_FILE_BYTES {
                    if let Ok(body) = fs::read_to_string(&cand) {
                        let rel = cand
                            .strip_prefix(plugin_root)
                            .unwrap_or(&cand)
                            .to_string_lossy()
                            .into_owned();
                        return Some((rel, body));
                    }
                }
            }
        }
    }
    None
}

fn detect_external_network_call(text: &str) -> Option<String> {
    let re = plugin_regexes();
    if !re.net_call.is_match(text) {
        return None;
    }

    let urls: Vec<&str> = re.url_extract.find_iter(text).map(|m| m.as_str()).collect();
    if !urls.is_empty() {
        for u in &urls {
            if !is_localhost_url(u) {
                let host = extract_url_host(u).unwrap_or(*u);
                return Some(format!("`{host}`"));
            }
        }
        // Every explicit URL in the command/script is localhost (e.g. local language server RPC)
        return None;
    }

    // If it references ANTIGRAVITY_LS_ADDRESS without external URLs, treat as local IPC
    if text.contains("ANTIGRAVITY_LS_ADDRESS") {
        return None;
    }

    let matched = re
        .net_call
        .find(text)
        .map(|m| m.as_str().trim().trim_end_matches('('))
        .unwrap_or("network client");
    Some(format!("via `{matched}`"))
}

fn is_localhost_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://localhost")
        || lower.starts_with("https://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("https://127.0.0.1")
        || lower.starts_with("http://[::1]")
        || lower.starts_with("https://[::1]")
        || lower.contains("${antigravity_ls_address}")
}

fn extract_url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split(['/', '?', '#']).next()?;
    let host = host_port.rsplit_once('@').map_or(host_port, |(_, h)| h);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn check_remote_code_exec(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let re = plugin_regexes();
    let matched = re
        .pipe_to_shell
        .find(raw)
        .or_else(|| re.ps_download_exec.find(raw))
        .or_else(|| re.base64_exec.find(raw))
        .or_else(|| re.eval_net.find(raw));

    if let Some(m) = matched {
        let snippet = truncate_snippet(m.as_str().trim(), 64);
        let fp = fingerprint_match("plugin-remote-code-exec", &format!("{display}:{snippet}"));
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-remote-code-exec",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Executes piped or decoded shell payload (`{snippet}`) inside plugin/hook/skill"
                ),
            },
        );
    }
}

fn check_credential_harvest(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let lower = raw.to_ascii_lowercase();
    for &(needle, human_target) in CREDENTIAL_HARVEST_PATTERNS {
        if lower.contains(needle) {
            let fp = fingerprint_match(
                "plugin-credential-harvest",
                &format!("{display}:{human_target}"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-credential-harvest",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "References sensitive host credential store (`{human_target}`) outside workspace"
                    ),
                },
            );
            break;
        }
    }
}

fn check_prompt_injection(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let re = plugin_regexes();

    if let Some(m) = re
        .prompt_override
        .find(raw)
        .or_else(|| re.prompt_stealth.find(raw))
    {
        let phrase = truncate_snippet(m.as_str().trim(), 60);
        let fp = fingerprint_match("plugin-prompt-injection", &format!("{display}:{phrase}"));
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-prompt-injection",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::High,
                fingerprint: fp,
                message: format!(
                    "Prompt file contains stealth or override instruction (`{phrase}`)"
                ),
            },
        );
        return;
    }

    // Check HTML comments (`<!-- ... -->`) hiding shell/network/secret exfiltration instructions
    for caps in re.html_comment.captures_iter(raw) {
        let comment = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let lower = comment.to_ascii_lowercase();
        if lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("fetch(")
            || lower.contains(".env")
            || lower.contains("base64")
        {
            let fp = fingerprint_match(
                "plugin-prompt-injection",
                &format!("{display}:html-comment"),
            );
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-prompt-injection",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::High,
                    fingerprint: fp,
                    message:
                        "Prompt file hides shell, network, or `.env` instructions inside an HTML comment (`<!-- ... -->`)"
                            .to_string(),
                },
            );
            return;
        }
    }

    // Check Trojan Source bidirectional overrides & Unicode Tag ASCII-smuggling characters
    if raw.chars().any(|ch| {
        let cp = ch as u32;
        (0x202A..=0x202E).contains(&cp)
            || (0x2066..=0x2069).contains(&cp)
            || (0xE0000..=0xE007F).contains(&cp)
    }) {
        let fp = fingerprint_match(
            "plugin-prompt-injection",
            &format!("{display}:unicode-smuggling"),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-prompt-injection",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::High,
                fingerprint: fp,
                message:
                    "Prompt file contains hidden bidirectional override or Unicode tag smuggling characters"
                        .to_string(),
            },
        );
    }
}

fn check_hardcoded_secrets(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    engine: &RuleEngine,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    for m in engine.scan_text(raw) {
        if m.category != RuleCategory::Secret {
            continue;
        }
        let fp = fingerprint_match(
            "plugin-hardcoded-secret",
            &format!("{display}:{}", m.fingerprint),
        );
        push_finding(
            out,
            seen_fp,
            McpFinding {
                rule_id: "plugin-hardcoded-secret",
                server_name: label.to_string(),
                config_file: display.to_string(),
                config_path: path.to_path_buf(),
                severity: Severity::Critical,
                fingerprint: fp,
                message: format!(
                    "Hardcoded {} (`{}`) bundled inside plugin, hook, or skill file",
                    m.rule_name, m.masked
                ),
            },
        );
    }
}

fn check_telemetry_domains(
    path: &Path,
    display: &str,
    label: &str,
    raw: &str,
    out: &mut Vec<McpFinding>,
    seen_fp: &mut HashSet<String>,
) {
    let lower = raw.to_ascii_lowercase();
    for &domain in PLUGIN_TELEMETRY_DOMAINS {
        if lower.contains(domain) {
            let fp = fingerprint_match("plugin-telemetry-endpoint", &format!("{display}:{domain}"));
            push_finding(
                out,
                seen_fp,
                McpFinding {
                    rule_id: "plugin-telemetry-endpoint",
                    server_name: label.to_string(),
                    config_file: display.to_string(),
                    config_path: path.to_path_buf(),
                    severity: Severity::High,
                    fingerprint: fp,
                    message: format!(
                        "Plugin or hook references outbound analytics/telemetry endpoint (`{domain}`)"
                    ),
                },
            );
            break;
        }
    }
}

pub fn has_script_extension(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.ends_with(".d.ts") {
        return false;
    }
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("sh" | "bash" | "zsh" | "py" | "js" | "mjs" | "cjs" | "ts" | "ps1" | "rb")
    )
}

fn component_label(path: &Path, raw: &str) -> String {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();

    if let Some(idx) = comps.iter().position(|&c| c == "plugins") {
        if comps.get(idx + 1) == Some(&"cache") {
            // `plugins/cache/<marketplace>/<plugin>/<version>/...`
            if comps.len() > idx + 4 {
                return format!("plugin:{}", comps[idx + 3]);
            }
            if comps.len() > idx + 3 {
                return format!("plugin:{}", comps[idx + 2]);
            }
        } else if comps.len() > idx + 2 {
            return format!("plugin:{}", comps[idx + 1]);
        }
    }

    if let Some(idx) = comps.iter().position(|&c| c == "extensions") {
        if comps.len() > idx + 2 {
            return format!("extension:{}", comps[idx + 1]);
        }
    }

    if let Some(idx) = comps
        .iter()
        .position(|&c| c == ".claude-plugin" || c == ".codex-plugin")
    {
        if idx > 0 {
            return format!("plugin:{}", comps[idx - 1]);
        }
    }

    if let Some(idx) = comps.iter().position(|&c| c == "skills") {
        if comps.len() > idx + 2 {
            let name = comps[idx + 1];
            // `claude plugin init <name>` scaffolds plugins under `~/.claude/skills/<name>/.claude-plugin/`
            let mut ancestor = path;
            while let Some(parent) = ancestor.parent() {
                if parent.file_name().and_then(|s| s.to_str()) == Some(name)
                    && parent
                        .parent()
                        .and_then(|gp| gp.file_name())
                        .and_then(|s| s.to_str())
                        == Some("skills")
                {
                    if parent.join(".claude-plugin").is_dir()
                        || parent.join("plugin.json").is_file()
                    {
                        return format!("plugin:{name}");
                    }
                    break;
                }
                ancestor = parent;
            }
            return format!("skill:{name}");
        }
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin");
    if matches!(file_name, "plugin.json" | "gemini-extension.json") {
        if let Some(json) = parse_json_or_jsonc(raw) {
            if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                if !name.trim().is_empty() {
                    return format!("plugin:{}", name.trim());
                }
            }
        }
    }

    if file_name == "hooks.json" || comps.contains(&"hooks") || comps.contains(&"hooks-handlers") {
        return "hooks".to_string();
    }

    if matches!(file_name, "settings.json" | "settings.local.json") {
        return "settings-hooks".to_string();
    }

    if file_name == "SKILL.md" {
        if let Some(parent) = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
        {
            return format!("skill:{parent}");
        }
    }

    file_name.to_string()
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = collapsed.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}
