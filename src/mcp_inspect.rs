use crate::api_tap::simple_http_exchange;
use crate::config::PolicyConfig;
use crate::discovery::{home_dir, shorten_home};
use crate::mcp_audit::McpFinding;
use crate::plugin_audit::{
    detect_credential_store_ref, detect_external_network_call, parse_json_or_jsonc,
};
use crate::rules::{fingerprint_match, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MCP_INSPECT_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_MCP_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct McpPinStore {
    #[serde(default)]
    servers: BTreeMap<String, ServerPinEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerPinEntry {
    sha256: String,
    #[serde(default)]
    tools: BTreeMap<String, String>,
}

/// Passively or actively audits an MCP `tools` array (or JSON-RPC `tools/list` response object)
/// for tool-description prompt injection, stealth exfiltration directives, credential reads,
/// hidden Unicode smuggling (`mcp-tool-poisoning`), and silent schema mutations (`mcp-tool-rugpull`).
pub fn audit_mcp_tools_payload(
    server_name: &str,
    config_file: &str,
    config_path: &Path,
    tools_val: &Value,
    check_pins: bool,
    out: &mut Vec<McpFinding>,
) {
    let Some(tools_arr) = extract_tools_array(tools_val) else {
        return;
    };

    let mut tool_hashes: BTreeMap<String, String> = BTreeMap::new();
    let mut seen_poison_fps: HashSet<String> = HashSet::new();

    for (idx, tool) in tools_arr.iter().enumerate() {
        let tool_name = tool
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("tool_{idx}"));

        if let Ok(canon_tool) = serde_json::to_string(tool) {
            let digest = Sha256::digest(canon_tool.as_bytes());
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            tool_hashes.insert(tool_name.clone(), hex);
        }

        let mut raw_text = String::new();
        collect_tool_metadata_text(tool, 0, &mut raw_text);
        if raw_text.trim().is_empty() {
            continue;
        }

        let mut reasons: Vec<(&'static str, String)> = Vec::new();
        if contains_hidden_unicode(&raw_text) {
            reasons.push((
                "hidden-unicode",
                "hidden zero-width, bidirectional override, or Unicode Tag smuggling characters"
                    .to_string(),
            ));
        }

        let cleaned = strip_hidden_unicode(&raw_text);
        let lower = cleaned.to_ascii_lowercase();

        if let Some(directive) = detect_tool_prompt_injection(&lower) {
            reasons.push((
                "prompt-injection",
                format!("stealth/override directive (`{directive}`)"),
            ));
        }

        if let Some(cred_ref) = detect_tool_credential_target(&cleaned, &lower) {
            reasons.push((
                "credential-access",
                format!("instructs model to read sensitive credentials (`{cred_ref}`)"),
            ));
        }

        if let Some(exfil_sink) = detect_tool_exfil_sink(&cleaned, &lower) {
            reasons.push((
                "exfil-sink",
                format!("embeds outbound exfiltration sink (`{exfil_sink}`)"),
            ));
        }

        if !reasons.is_empty() {
            let reason_keys: Vec<&str> = reasons.iter().map(|(k, _)| *k).collect();
            let reason_desc: Vec<&str> = reasons.iter().map(|(_, d)| d.as_str()).collect();
            let fp = fingerprint_match(
                "mcp-tool-poisoning",
                &format!(
                    "{config_file}:{server_name}:{tool_name}:{}",
                    reason_keys.join("+")
                ),
            );
            if seen_poison_fps.insert(fp.clone()) {
                out.push(McpFinding {
                    rule_id: "mcp-tool-poisoning",
                    server_name: server_name.to_string(),
                    config_file: config_file.to_string(),
                    config_path: config_path.to_path_buf(),
                    line: 1,
                    severity: Severity::Critical,
                    fingerprint: fp,
                    message: format!(
                        "Live MCP tool `{tool_name}` metadata contains poisoning indicator(s): {}",
                        reason_desc.join("; ")
                    ),
                });
            }
        }
    }

    if check_pins && !tool_hashes.is_empty() {
        check_and_update_pins(server_name, config_file, config_path, &tool_hashes, out);
    }
}

/// Opt-in (`leaktap scan --inspect-mcp`) live interrogation of configured HTTP/SSE and stdio
/// MCP servers (`initialize` + `tools/list`, bounded to 4s per server).
/// Workspace-scoped `stdio` commands require `trust_project_config = true` so auditing an
/// untrusted repository with `--inspect-mcp` never executes repo-controlled local binaries.
pub fn inspect_live_mcp_configs(
    mcp_config_files: &[PathBuf],
    trust_project_config: bool,
    policy: Option<&PolicyConfig>,
) -> Vec<McpFinding> {
    let mut findings = Vec::new();

    for path in mcp_config_files {
        if policy.is_some_and(|p| p.is_path_ignored(path)) {
            continue;
        }
        let Ok(raw) = crate::scanner::read_text_auto_encoding(path, MAX_MCP_CONFIG_BYTES) else {
            continue;
        };
        let is_toml = path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"));
        let parsed: Option<Value> = if is_toml {
            toml::from_str::<Value>(&raw).ok()
        } else {
            parse_json_or_jsonc(&raw)
        };
        let Some(doc) = parsed else {
            continue;
        };

        let display = shorten_home(path);
        let allow_stdio_spawn = trust_project_config || is_user_global_mcp_config(path);
        let mut warned_untrusted_stdio = false;
        let mut specs: Vec<(String, &Value)> = Vec::new();
        collect_mcp_server_specs(&doc, &mut specs);

        for (server_name, spec) in specs {
            if spec
                .get("disabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let tools_resp = if let Some(http_url) = extract_http_mcp_url(spec) {
                query_http_mcp_tools(&http_url, spec)
            } else if let Some((cmd_str, cmd_scope)) = extract_stdio_mcp_command(spec) {
                if !allow_stdio_spawn {
                    if !warned_untrusted_stdio {
                        eprintln!(
                            "[leaktap:warn] skipping live stdio MCP spawn from untrusted workspace config {display} (pass `--trust-project-config` to execute workspace stdio servers)"
                        );
                        warned_untrusted_stdio = true;
                    }
                    None
                } else {
                    query_stdio_mcp_tools(cmd_str, cmd_scope, spec, path.parent())
                }
            } else {
                None
            };

            if let Some(resp_val) = tools_resp {
                audit_mcp_tools_payload(
                    &server_name,
                    &display,
                    path,
                    &resp_val,
                    true,
                    &mut findings,
                );
            }
        }
    }

    if let Some(pol) = policy {
        findings.retain(|f| {
            !pol.is_path_ignored(&f.config_path)
                && !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }

    findings
}

fn extract_stdio_mcp_command(spec: &Value) -> Option<(&str, &Value)> {
    if let Some(s) = spec.get("command").and_then(Value::as_str) {
        return Some((s, spec));
    }
    if let Some(cmd_obj) = spec.get("command") {
        if let Some(p) = cmd_obj.get("path").and_then(Value::as_str) {
            return Some((p, cmd_obj));
        }
    }
    None
}

fn is_user_global_mcp_config(path: &Path) -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    let canon_home = fs::canonicalize(&home).unwrap_or(home);
    let canon_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let Ok(rel) = canon_path.strip_prefix(&canon_home) else {
        return false;
    };
    let mut comps = rel.components();
    let Some(first) = comps.next().and_then(|c| c.as_os_str().to_str()) else {
        return false;
    };
    if comps.next().is_none() {
        return matches!(first, ".claude.json" | ".mcp.json");
    }
    matches!(
        first,
        ".claude"
            | ".cursor"
            | ".codex"
            | ".gemini"
            | ".codeium"
            | ".continue"
            | ".zed"
            | ".junie"
            | ".kiro"
            | ".trae"
            | ".augment"
            | ".amazonq"
            | ".config"
            | "Library"
            | "AppData"
    )
}

fn collect_mcp_server_specs<'a>(doc: &'a Value, out: &mut Vec<(String, &'a Value)>) {
    for top_key in ["mcpServers", "mcp_servers", "servers", "context_servers"] {
        if let Some(map) = doc.get(top_key).and_then(Value::as_object) {
            for (name, spec) in map {
                out.push((name.clone(), spec));
            }
        }
    }
    if let Some(map) = doc
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .and_then(Value::as_object)
    {
        for (name, spec) in map {
            out.push((name.clone(), spec));
        }
    }
    if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
        for (_proj, proj_val) in projects {
            for nested_key in ["mcpServers", "mcp_servers", "context_servers"] {
                if let Some(map) = proj_val.get(nested_key).and_then(Value::as_object) {
                    for (name, spec) in map {
                        out.push((name.clone(), spec));
                    }
                }
            }
        }
    }
}

fn extract_http_mcp_url(spec: &Value) -> Option<String> {
    for key in ["url", "httpUrl", "serverUrl", "sseUrl", "endpoint", "uri"] {
        if let Some(u) = spec.get(key).and_then(Value::as_str) {
            let trimmed = u.trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                return Some(trimmed.to_string());
            }
        }
    }
    if let Some(tr) = spec.get("transport").and_then(Value::as_object) {
        for key in ["url", "httpUrl", "serverUrl", "sseUrl", "endpoint", "uri"] {
            if let Some(u) = tr.get(key).and_then(Value::as_str) {
                let trimmed = u.trim();
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn expand_env_placeholders(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(idx) = rest.find("${") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 2..];
        if let Some(end) = after.find('}') {
            let var_expr = &after[..end];
            let var_name = var_expr.strip_prefix("env:").unwrap_or(var_expr).trim();
            if let Ok(val) = std::env::var(var_name) {
                out.push_str(&val);
            }
            rest = &after[end + 1..];
        } else {
            out.push_str("${");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn query_http_mcp_tools(url: &str, spec: &Value) -> Option<Value> {
    let mut extra_headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
    ];
    for hdr_key in ["headers", "http_headers"] {
        if let Some(hdr_map) = spec.get(hdr_key).and_then(Value::as_object) {
            for (k, v) in hdr_map {
                if let Some(vs) = v.as_str() {
                    extra_headers.push((k.clone(), expand_env_placeholders(vs)));
                }
            }
        }
    }

    let init_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "leaktap",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    })
    .to_string();

    let init_hdr_refs: Vec<(&str, &str)> = extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if let Ok((_code, resp_hdrs, _init_body)) = simple_http_exchange(
        "POST",
        url,
        &init_hdr_refs,
        Some(init_payload.as_bytes()),
        MCP_INSPECT_TIMEOUT,
    ) {
        for (rk, rv) in resp_hdrs {
            if rk.eq_ignore_ascii_case("mcp-session-id") && !rv.trim().is_empty() {
                extra_headers.push(("Mcp-Session-Id".to_string(), rv.trim().to_string()));
                break;
            }
        }
    }

    let notif_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
    .to_string();
    let hdr_refs: Vec<(&str, &str)> = extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let _ = simple_http_exchange(
        "POST",
        url,
        &hdr_refs,
        Some(notif_payload.as_bytes()),
        Duration::from_secs(2),
    );

    let list_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    })
    .to_string();

    let Ok((status, _hdrs, body_text)) = simple_http_exchange(
        "POST",
        url,
        &hdr_refs,
        Some(list_payload.as_bytes()),
        MCP_INSPECT_TIMEOUT,
    ) else {
        return None;
    };
    if !(200..300).contains(&status) {
        return None;
    }

    parse_jsonrpc_or_sse_tools(&body_text)
}

fn parse_jsonrpc_or_sse_tools(body: &str) -> Option<Value> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if extract_tools_array(&val).is_some() {
            return Some(val);
        }
    }
    for line in trimmed.lines() {
        let l = line.trim();
        let candidate = l.strip_prefix("data:").map(str::trim).unwrap_or(l);
        if candidate.starts_with('{') {
            if let Ok(val) = serde_json::from_str::<Value>(candidate) {
                if extract_tools_array(&val).is_some() {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn query_stdio_mcp_tools(
    cmd_str: &str,
    cmd_scope: &Value,
    spec: &Value,
    default_cwd: Option<&Path>,
) -> Option<Value> {
    let trimmed_cmd = cmd_str.trim();
    if trimmed_cmd.is_empty() {
        return None;
    }

    let mut cmd = Command::new(trimmed_cmd);
    let args_val = cmd_scope
        .get("args")
        .or_else(|| spec.get("args"))
        .and_then(Value::as_array);
    if let Some(args_arr) = args_val {
        for a in args_arr {
            if let Some(s) = a.as_str() {
                cmd.arg(s);
            }
        }
    }
    if let Some(cwd_str) = spec
        .get("cwd")
        .or_else(|| cmd_scope.get("cwd"))
        .and_then(Value::as_str)
    {
        let p = Path::new(cwd_str);
        if p.is_dir() {
            cmd.current_dir(p);
        }
    } else if let Some(dir) = default_cwd.filter(|d| d.is_dir()) {
        cmd.current_dir(dir);
    }
    for scope in [spec, cmd_scope] {
        if let Some(env_map) = scope.get("env").and_then(Value::as_object) {
            for (k, v) in env_map {
                if let Some(vs) = v.as_str() {
                    cmd.env(k, expand_env_placeholders(vs));
                }
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().ok()?;
    let child_pid = child.id();
    let mut stdin = child.stdin.take()?;
    let stdout = child.stdout.take()?;

    let requests = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"leaktap\",\"version\":\"0.3.0\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
    );
    let _ = stdin.write_all(requests.as_bytes());
    let _ = stdin.flush();

    let (tx, rx) = mpsc::channel::<Value>();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        for _ in 0..128 {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let t = line.trim();
                    if t.starts_with('{') {
                        if let Ok(val) = serde_json::from_str::<Value>(t) {
                            if extract_tools_array(&val).is_some() {
                                let _ = tx.send(val);
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    let deadline = Instant::now() + MCP_INSPECT_TIMEOUT;
    let mut found = None;
    let rem = deadline.saturating_duration_since(Instant::now());
    if let Ok(val) = rx.recv_timeout(rem) {
        found = Some(val);
    }

    drop(stdin);
    #[cfg(unix)]
    if child_pid > 1 && child_pid <= i32::MAX as u32 {
        // SAFETY: `child` was spawned with `process_group(0)` so `child_pid` is its own PGID.
        unsafe {
            let _ = libc::kill(-(child_pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    found
}

fn extract_tools_array(val: &Value) -> Option<&Vec<Value>> {
    if let Some(arr) = val.as_array() {
        return Some(arr);
    }
    if let Some(arr) = val.get("tools").and_then(Value::as_array) {
        return Some(arr);
    }
    val.get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
}

fn collect_tool_metadata_text(val: &Value, depth: usize, out: &mut String) {
    if depth > 16 || out.len() > 256 * 1024 {
        return;
    }
    match val {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(arr) => {
            for item in arr {
                collect_tool_metadata_text(item, depth + 1, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                out.push_str(k);
                out.push_str(": ");
                collect_tool_metadata_text(v, depth + 1, out);
            }
        }
        _ => {}
    }
}

fn is_emoji_scalar(c: char) -> bool {
    matches!(
        c,
        '\u{203C}'
            | '\u{2049}'
            | '\u{2122}'
            | '\u{2139}'
            | '\u{2194}'..='\u{21AA}'
            | '\u{231A}'..='\u{27BF}'
            | '\u{2934}'..='\u{2935}'
            | '\u{2B05}'..='\u{2B55}'
            | '\u{1F000}'..='\u{1FAFF}'
    )
}

fn is_hidden_smuggling_char(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

fn contains_hidden_unicode(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    for (idx, &c) in chars.iter().enumerate() {
        if !is_hidden_smuggling_char(c) {
            continue;
        }
        if c == '\u{200D}' {
            let prev_emoji = idx > 0
                && (is_emoji_scalar(chars[idx - 1])
                    || matches!(chars[idx - 1], '\u{FE0F}' | '\u{1F3FB}'..='\u{1F3FF}'));
            let next_emoji = chars.get(idx + 1).is_some_and(|&nc| is_emoji_scalar(nc));
            if prev_emoji && next_emoji {
                continue;
            }
        }
        return true;
    }
    false
}

fn strip_hidden_unicode(s: &str) -> String {
    s.chars()
        .filter(|&c| !is_hidden_smuggling_char(c))
        .collect()
}

fn detect_tool_prompt_injection(lower: &str) -> Option<&'static str> {
    const DIRECTIVES: &[&str] = &[
        "<important>",
        "</important>",
        "<system>",
        "[system]",
        "<hidden>",
        "<!--",
        "ignore previous instructions",
        "ignore all prior instructions",
        "disregard previous",
        "override system prompt",
        "do not mention",
        "don't mention",
        "never mention",
        "do not tell the user",
        "don't tell the user",
        "hide this from the user",
        "without telling the user",
        "without informing the user",
        "keep this secret from",
        "silently read",
        "silently send",
        "silently upload",
        "in the background without",
        "before using any other tool",
        "always call this tool first",
        "instead of calling",
    ];
    DIRECTIVES.iter().copied().find(|pat| lower.contains(pat))
}

fn detect_tool_credential_target(cleaned: &str, lower: &str) -> Option<&'static str> {
    if let Some(store) = detect_credential_store_ref(cleaned) {
        return Some(store);
    }
    const EXTRA_TARGETS: &[(&str, &str)] = &[
        ("id_rsa", "~/.ssh/id_rsa"),
        ("id_ed25519", "~/.ssh/id_ed25519"),
        (".aws/credentials", "~/.aws/credentials"),
        ("/etc/shadow", "/etc/shadow"),
        ("/etc/passwd", "/etc/passwd"),
        ("read .env", ".env"),
        ("contents of .env", ".env"),
        ("from .env", ".env"),
        ("`~/.ssh`", "~/.ssh"),
        ("process.env", "process.env"),
    ];
    for &(needle, label) in EXTRA_TARGETS {
        if lower.contains(needle) {
            return Some(label);
        }
    }
    None
}

fn detect_tool_exfil_sink(cleaned: &str, lower: &str) -> Option<String> {
    if let Some(sink) = detect_external_network_call(cleaned) {
        return Some(sink);
    }
    for domain in [
        "webhook.site",
        "oastify.com",
        "burpcollaborator.net",
        "interact.sh",
        "requestbin",
        "pipedream.net",
        "ngrok-free.app",
        "ngrok.io",
    ] {
        if lower.contains(domain) {
            return Some(domain.to_string());
        }
    }

    let has_exfil_verb = [
        "send ",
        "post ",
        "upload ",
        "exfiltrate",
        "forward ",
        "transmit ",
        "include contents",
        "pass contents",
        "append contents",
    ]
    .iter()
    .any(|v| lower.contains(v));

    if has_exfil_verb {
        for scheme in ["https://", "http://"] {
            if let Some(idx) = lower.find(scheme) {
                let after = &cleaned[idx..];
                let url_tok: String = after
                    .chars()
                    .take_while(|c| {
                        !c.is_whitespace() && !matches!(c, '"' | '\'' | ')' | '>' | ']')
                    })
                    .collect();
                if !crate::plugin_audit::is_localhost_url(&url_tok)
                    && url_tok.len() > scheme.len() + 3
                {
                    return Some(url_tok);
                }
            }
        }
    }
    None
}

fn mcp_pins_file_path() -> Option<PathBuf> {
    if let Some(ovr) = std::env::var_os("LEAKTAP_MCP_PINS_FILE") {
        if !ovr.is_empty() {
            return Some(PathBuf::from(ovr));
        }
    }
    home_dir().map(|h| {
        h.join(".local")
            .join("share")
            .join("leaktap")
            .join("mcp_tool_pins.json")
    })
}

fn check_and_update_pins(
    server_name: &str,
    config_file: &str,
    config_path: &Path,
    tool_hashes: &BTreeMap<String, String>,
    out: &mut Vec<McpFinding>,
) {
    let Some(pin_path) = mcp_pins_file_path() else {
        return;
    };

    let mut hasher = Sha256::new();
    for (t_name, t_hash) in tool_hashes {
        hasher.update(t_name.as_bytes());
        hasher.update(b"=");
        hasher.update(t_hash.as_bytes());
        hasher.update(b"\n");
    }
    let current_sha256: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let mut store: McpPinStore = fs::read_to_string(&pin_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let server_key = format!("{}::{server_name}", config_path.display());
    if let Some(prev) = store.servers.get(&server_key) {
        if prev.sha256 != current_sha256 {
            let mut diffs: Vec<String> = Vec::new();
            for (t_name, cur_h) in tool_hashes {
                match prev.tools.get(t_name) {
                    None => diffs.push(format!("+{t_name}")),
                    Some(old_h) if old_h != cur_h => diffs.push(format!("~{t_name}")),
                    _ => {}
                }
            }
            for old_name in prev.tools.keys() {
                if !tool_hashes.contains_key(old_name) {
                    diffs.push(format!("-{old_name}"));
                }
            }
            let diff_summary = if diffs.is_empty() {
                "schema hash changed".to_string()
            } else {
                diffs.join(", ")
            };
            let old_short = &prev.sha256[..prev.sha256.len().min(8)];
            let new_short = &current_sha256[..current_sha256.len().min(8)];
            out.push(McpFinding {
                rule_id: "mcp-tool-rugpull",
                server_name: server_name.to_string(),
                config_file: config_file.to_string(),
                config_path: config_path.to_path_buf(),
                line: 1,
                severity: Severity::High,
                fingerprint: fingerprint_match(
                    "mcp-tool-rugpull",
                    &format!("{config_file}:{server_name}:{current_sha256}"),
                ),
                message: format!(
                    "MCP `tools/list` schema changed silently since pinned baseline ({diff_summary}; pin {old_short} -> {new_short})"
                ),
            });

            let update_pins = std::env::var("LEAKTAP_UPDATE_MCP_PINS")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            if update_pins {
                store.servers.insert(
                    server_key,
                    ServerPinEntry {
                        sha256: current_sha256,
                        tools: tool_hashes.clone(),
                    },
                );
                let _ = write_pin_store_private(&pin_path, &store);
            }
        }
    } else {
        store.servers.insert(
            server_key,
            ServerPinEntry {
                sha256: current_sha256,
                tools: tool_hashes.clone(),
            },
        );
        let _ = write_pin_store_private(&pin_path, &store);
    }
}

fn write_pin_store_private(path: &Path, store: &McpPinStore) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&serialized)?;
        f.flush()
    }
    #[cfg(not(unix))]
    {
        fs::write(path, serialized)
    }
}
