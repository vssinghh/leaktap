use crate::report::FullScanReport;
use crate::rules::{fingerprint_match, RuleCategory, RuleEngine, Severity};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

pub const BUILTIN_STATIC_RULES: &[(&str, &str, &str, Severity)] = &[
    (
        "mcp-hardcoded-secret",
        "MCP Hardcoded Secret",
        "Plaintext secret or token stored inside MCP server env, args, or HTTP headers.",
        Severity::Critical,
    ),
    (
        "mcp-remote-code-exec",
        "MCP Remote Code Execution",
        "MCP server command downloads and executes remote code at startup.",
        Severity::Critical,
    ),
    (
        "mcp-credential-harvest",
        "MCP Credential Store Access",
        "MCP server command directly reads host SSH, cloud, browser, or CLI credential stores.",
        Severity::Critical,
    ),
    (
        "mcp-privilege-escalation",
        "MCP Privilege Escalation",
        "MCP server command invokes sudo or doas privilege escalation.",
        Severity::High,
    ),
    (
        "mcp-inline-code-exec",
        "MCP Inline Code Execution",
        "MCP server runs inline interpreter code (-c / -e) with network or credential access.",
        Severity::High,
    ),
    (
        "mcp-unpinned-package",
        "MCP Unpinned Package",
        "Unpinned npx/uvx/bunx/pipx/docker package pulls mutable registry or URL/git code at launch.",
        Severity::Medium,
    ),
    (
        "mcp-unrestricted-shell",
        "MCP Unrestricted Shell",
        "MCP server exposes raw unrestricted shell command execution or privileged container flags.",
        Severity::High,
    ),
    (
        "mcp-broad-filesystem",
        "MCP Sensitive or Broad Filesystem Scope",
        "MCP server is granted root (/), home (~), or sensitive credential directory access.",
        Severity::High,
    ),
    (
        "mcp-plaintext-http",
        "MCP Plaintext HTTP or WebSocket Transport",
        "Remote MCP server connects over unencrypted http:// or ws:// transport.",
        Severity::High,
    ),
    (
        "mcp-telemetry-endpoint",
        "MCP Outbound Telemetry Endpoint",
        "MCP configuration references a third-party analytics or telemetry endpoint.",
        Severity::Medium,
    ),
    (
        "mcp-tool-poisoning",
        "MCP Live Tool Poisoning",
        "MCP tools/list schema or description contains prompt injection, stealth instructions, credential reads, or external exfiltration URLs.",
        Severity::Critical,
    ),
    (
        "mcp-tool-rugpull",
        "MCP Live Tool Schema Rug-Pull",
        "MCP tools/list schema or description changed silently since its recorded local pin.",
        Severity::High,
    ),
    (
        "plugin-remote-code-exec",
        "Plugin Remote Code Execution",
        "Plugin, hook, or skill executes piped, encoded, or dynamically fetched remote payloads.",
        Severity::Critical,
    ),
    (
        "plugin-credential-harvest",
        "Plugin Credential Store Access",
        "Plugin, hook, or skill accesses ~/.ssh, ~/.aws, ~/.azure, browser DBs, keychain, or CLI credential files.",
        Severity::Critical,
    ),
    (
        "plugin-env-exfiltration",
        "Plugin or Skill Environment Exfiltration",
        "Plugin, hook, MCP script, or skill exfiltrates environment variables or credentials over an outbound network call.",
        Severity::Critical,
    ),
    (
        "plugin-hardcoded-secret",
        "Plugin Bundled Secret",
        "Live API key, token, or private key is hardcoded inside an installed plugin or skill.",
        Severity::Critical,
    ),
    (
        "plugin-compiled-binary",
        "Plugin or Hook Compiled Binary",
        "Plugin, hook, skill, or MCP helper bundles or executes an opaque native, Wasm, or bytecode binary.",
        Severity::High,
    ),
    (
        "plugin-skill-network",
        "Skill Script Outbound Network Call",
        "Executable skill script makes outbound network calls to non-official external endpoints.",
        Severity::High,
    ),
    (
        "plugin-hook-network",
        "Lifecycle Hook Outbound Network Call",
        "Lifecycle hook makes outbound network requests during CLI tool or prompt events.",
        Severity::High,
    ),
    (
        "plugin-prompt-injection",
        "Skill or Instruction Prompt Injection",
        "Skill or instruction file contains stealth override directives, hidden Unicode payloads, or exfiltration commands.",
        Severity::High,
    ),
    (
        "plugin-telemetry-endpoint",
        "Plugin Outbound Telemetry Endpoint",
        "Plugin manifest, hook, or script sends data to a third-party analytics endpoint.",
        Severity::High,
    ),
    (
        "plugin-api-base-override",
        "Workspace LLM API, Proxy, or TLS Override",
        "Workspace settings redirect LLM API base URLs, HTTP proxies, custom CA bundles, or disable TLS certificate verification.",
        Severity::Critical,
    ),
    (
        "plugin-env-code-exec",
        "Settings Environment Code Execution Override",
        "Workspace or plugin settings override runtime preload, dynamic linker, shell startup, or PATH variables (NODE_OPTIONS, LD_PRELOAD, BASH_ENV, GIT_SSH_COMMAND, etc.).",
        Severity::Critical,
    ),
    (
        "plugin-workspace-hook-exec",
        "Workspace Automatic Hook Command",
        "Workspace settings register an automatic shell or helper command hook that executes repository-controlled code.",
        Severity::Medium,
    ),
    (
        "plugin-oversized-config",
        "Oversized Plugin or Workspace Config",
        "Plugin or workspace JSON configuration exceeds the 16 MiB structured AST limit.",
        Severity::High,
    ),
    (
        "mcp-oversized-config",
        "Oversized MCP Config",
        "MCP configuration file exceeds the 16 MiB structured AST limit.",
        Severity::High,
    ),
];

pub const BUILTIN_LIVE_RULES: &[(&str, &str, &str, Severity)] = &[
    (
        "header-secret-leak",
        "HTTP Header Secret or Cross-Provider Auth Leak",
        "Cross-provider token, internal JWT, opaque credential, or secret sent inside an outgoing HTTP header (blocked under `--block-secrets`).",
        Severity::Critical,
    ),
    (
        "header-email-leak",
        "HTTP Header Email Leak",
        "Developer email address embedded inside `User-Agent` or custom HTTP headers.",
        Severity::High,
    ),
    (
        "header-os-username",
        "HTTP Header OS Username Exposure",
        "Local OS username exposed inside outgoing HTTP headers.",
        Severity::Medium,
    ),
    (
        "header-machine-hostname",
        "HTTP Header Machine Hostname Exposure",
        "Local machine hostname exposed inside outgoing HTTP headers.",
        Severity::Medium,
    ),
    (
        "secret-redacted",
        "In-Transit Outgoing Secret Redacted",
        "Detected secret in outgoing LLM API URL, header, or body was scrubbed to `[REDACTED:...]` before forwarding upstream (`--redact-secrets`).",
        Severity::High,
    ),
    (
        "tcp-connection",
        "Outbound TCP Socket",
        "Outbound TCP connection opened by the wrapped CLI or child MCP/hook process (with PID & scrubbed cmdline).",
        Severity::Medium,
    ),
    (
        "udp-connection",
        "Outbound Connected UDP Socket",
        "Connected outbound UDP socket opened by the wrapped CLI or child MCP/hook process (with PID & scrubbed cmdline).",
        Severity::Medium,
    ),
];

pub fn render_rules_json(engine: &RuleEngine) -> String {
    let mut items = Vec::new();
    for r in engine.rules() {
        let cat = match r.category {
            RuleCategory::Secret => "secret",
            RuleCategory::Pii => "pii",
        };
        items.push(json!({
            "id": r.id,
            "name": r.name,
            "category": cat,
            "severity": r.severity.as_str(),
            "description": r.description,
        }));
    }
    for &(id, name, desc, sev) in BUILTIN_STATIC_RULES {
        let cat = if id.starts_with("plugin-") {
            "plugin"
        } else {
            "mcp"
        };
        items.push(json!({
            "id": id,
            "name": name,
            "category": cat,
            "severity": sev.as_str(),
            "description": desc,
        }));
    }
    for &(id, name, desc, sev) in BUILTIN_LIVE_RULES {
        items.push(json!({
            "id": id,
            "name": name,
            "category": "wiretap",
            "severity": sev.as_str(),
            "description": desc,
        }));
    }
    serde_json::to_string_pretty(&json!({
        "version": env!("CARGO_PKG_VERSION"),
        "total_rules": items.len(),
        "rules": items,
    }))
    .expect("valid rules JSON")
}

fn extract_git_commit_sha(display_file: &str) -> Option<&str> {
    let rest = display_file.strip_prefix("git:")?;
    let (sha, _rel) = rest.split_once(':')?;
    if !sha.is_empty() && sha != "staged" {
        Some(sha)
    } else {
        None
    }
}

/// Renders a SARIF 2.1.0 document compatible with GitHub Code Scanning (`upload-sarif`).
pub fn render_scan_sarif(report: &FullScanReport) -> String {
    let engine = RuleEngine::all_rules();
    render_scan_sarif_with_rules(report, &engine)
}

/// Renders a SARIF 2.1.0 document including rule metadata from `engine` (including custom `.leaktap.toml` rules).
pub fn render_scan_sarif_with_rules(report: &FullScanReport, engine: &RuleEngine) -> String {
    let cwd = env::current_dir().ok();
    let cwd_canon = cwd.as_ref().and_then(|c| c.canonicalize().ok());
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let home_canon = home.as_ref().and_then(|h| h.canonicalize().ok());

    let mut extra_roots: Vec<(PathBuf, Option<PathBuf>)> = report
        .scan_paths
        .iter()
        .map(|sp| {
            let root = if sp.is_dir() {
                sp.clone()
            } else if sp.is_file() || sp.extension().is_some() {
                sp.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| sp.clone())
            } else {
                sp.clone()
            };
            let canon = root.canonicalize().ok();
            (root, canon)
        })
        .collect();
    if let Some(h) = home {
        extra_roots.push((h, home_canon));
    }

    let mut results = Vec::new();
    let mut referenced_rules: HashSet<String> = HashSet::new();

    let has_salt = crate::rules::has_active_fingerprint_salt();

    for (f, is_pii) in report
        .transcripts
        .secret_findings
        .iter()
        .map(|f| (f, false))
        .chain(report.transcripts.pii_findings.iter().map(|f| (f, true)))
    {
        referenced_rules.insert(f.rule_id.clone());

        let loc_quads: Vec<(&str, &Path, usize, usize)> = if f.locations.is_empty() {
            vec![(
                f.first_file.as_str(),
                &f.first_path,
                f.first_line.max(1),
                f.first_column.max(1),
            )]
        } else {
            f.locations
                .iter()
                .map(|loc| {
                    (
                        loc.file.as_str(),
                        loc.path.as_path(),
                        loc.line.max(1),
                        loc.column.max(1),
                    )
                })
                .collect()
        };

        let title_with_key = match f.secret_key.as_deref() {
            Some(k) if !k.is_empty() => format!("{} `{k}`", f.rule_name),
            _ => f.rule_name.clone(),
        };
        let verify_suffix = match f.verified {
            Some(true) => " [VERIFIED ACTIVE]",
            Some(false) => " [unverified/inactive]",
            None => "",
        };

        for (disp_str, loc_path, loc_line, loc_col) in loc_quads {
            let (loc_val, uri_str) = sarif_location(
                loc_path,
                loc_line,
                loc_col,
                cwd.as_deref(),
                cwd_canon.as_deref(),
                &extra_roots,
            );
            let commit_sha = extract_git_commit_sha(disp_str);
            let msg_text = if let Some(sha) = commit_sha {
                format!(
                    "{} ({}){} detected in git commit {} ({})",
                    title_with_key, f.masked, verify_suffix, sha, uri_str
                )
            } else {
                format!(
                    "{} ({}){} detected in local file or agent session transcript",
                    title_with_key, f.masked, verify_suffix
                )
            };
            let mut res_obj = json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": {
                    "text": msg_text
                },
                "locations": [loc_val]
            });
            // Privacy boundary: omit unsalted value hashes (`partialFingerprints`) on low-entropy
            // PII findings (emails, SSNs, phone numbers, IPv4s) unless a fingerprint salt is active.
            if !is_pii || has_salt {
                let loc_fp_seed = if let Some(sha) = commit_sha {
                    format!("{}:{sha}:{uri_str}:{loc_line}:{loc_col}", f.fingerprint)
                } else {
                    format!("{}:{uri_str}:{loc_line}:{loc_col}", f.fingerprint)
                };
                let loc_fp = fingerprint_match(&f.rule_id, &loc_fp_seed);
                if let Some(map) = res_obj.as_object_mut() {
                    map.insert(
                        "partialFingerprints".to_string(),
                        json!({
                            "leaktapFingerprint/v1": f.fingerprint,
                            "leaktapLocationFingerprint/v1": loc_fp
                        }),
                    );
                }
            }
            if commit_sha.is_some()
                || f.secret_key.is_some()
                || f.verified.is_some()
                || f.verification_detail.is_some()
            {
                let mut props = serde_json::Map::new();
                if let Some(sha) = commit_sha {
                    props.insert("commitSha".to_string(), json!(sha));
                }
                if let Some(ref key) = f.secret_key {
                    props.insert("secretKey".to_string(), json!(key));
                }
                if let Some(ver) = f.verified {
                    props.insert("verified".to_string(), json!(ver));
                }
                if let Some(ref det) = f.verification_detail {
                    props.insert("verificationDetail".to_string(), json!(det));
                }
                if let Some(map) = res_obj.as_object_mut() {
                    map.insert("properties".to_string(), Value::Object(props));
                }
            }
            results.push(res_obj);
        }
    }

    for m in &report.mcp_findings {
        referenced_rules.insert(m.rule_id.to_string());

        let prefix = if m.rule_id.starts_with("plugin-") {
            format!("[`{}`]", m.server_name)
        } else {
            format!("[MCP server `{}`]", m.server_name)
        };
        let (loc_val, _) = sarif_location(
            &m.config_path,
            m.line.max(1),
            1,
            cwd.as_deref(),
            cwd_canon.as_deref(),
            &extra_roots,
        );
        let commit_sha = extract_git_commit_sha(&m.config_file);
        let msg_text = if let Some(sha) = commit_sha {
            format!("{prefix} {} (git commit {sha})", m.message)
        } else {
            format!("{prefix} {}", m.message)
        };
        let mut res_obj = json!({
            "ruleId": m.rule_id,
            "level": m.severity.sarif_level(),
            "message": {
                "text": msg_text
            },
            "locations": [loc_val],
            "partialFingerprints": {
                "leaktapFingerprint/v1": m.fingerprint
            }
        });
        if let Some(sha) = commit_sha {
            if let Some(map) = res_obj.as_object_mut() {
                map.insert("properties".to_string(), json!({ "commitSha": sha }));
            }
        }
        results.push(res_obj);
    }

    let mut driver_rules = Vec::new();
    let mut emitted_rule_ids = HashSet::new();

    for r in engine.rules() {
        if emitted_rule_ids.insert(r.id.clone()) {
            let subtag = if r.category == RuleCategory::Pii {
                "privacy"
            } else {
                "secrets"
            };
            driver_rules.push(json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.name },
                "fullDescription": { "text": r.description },
                "defaultConfiguration": { "level": r.severity.sarif_level() },
                "properties": {
                    "security-severity": r.severity.security_severity_score(),
                    "tags": ["security", subtag]
                }
            }));
        }
    }

    for &(id, name, desc, sev) in BUILTIN_STATIC_RULES {
        if emitted_rule_ids.insert(id.to_string()) {
            driver_rules.push(json!({
                "id": id,
                "name": name,
                "shortDescription": { "text": name },
                "fullDescription": { "text": desc },
                "defaultConfiguration": { "level": sev.sarif_level() },
                "properties": {
                    "security-severity": sev.security_severity_score(),
                    "tags": ["security", "supply-chain"]
                }
            }));
        }
    }

    // Ensure any custom or future rule ID present in `results` always has a matching descriptor
    let mut extra_ids: Vec<String> = referenced_rules
        .into_iter()
        .filter(|id| !emitted_rule_ids.contains(id))
        .collect();
    extra_ids.sort();
    for id in extra_ids {
        driver_rules.push(json!({
            "id": id,
            "name": id,
            "shortDescription": { "text": id },
            "defaultConfiguration": { "level": "warning" },
            "properties": {
                "security-severity": Severity::Medium.security_severity_score(),
                "tags": ["security"]
            }
        }));
    }

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "leaktap",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/vssinghh/leaktap",
                    "rules": driver_rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("valid SARIF JSON")
}

fn sarif_location(
    path: &Path,
    line: usize,
    column: usize,
    cwd: Option<&Path>,
    cwd_canon: Option<&Path>,
    extra_roots: &[(PathBuf, Option<PathBuf>)],
) -> (Value, String) {
    let uri = path_to_sarif_uri(path, cwd, cwd_canon, extra_roots);
    let artifact_location = json!({
        "uri": uri,
        "uriBaseId": "%SRCROOT%"
    });

    (
        json!({
            "physicalLocation": {
                "artifactLocation": artifact_location,
                "region": {
                    "startLine": line.max(1),
                    "startColumn": column.max(1)
                }
            }
        }),
        uri,
    )
}

fn path_to_sarif_uri(
    path: &Path,
    cwd: Option<&Path>,
    cwd_canon: Option<&Path>,
    extra_roots: &[(PathBuf, Option<PathBuf>)],
) -> String {
    if path.is_relative() {
        if let Some(clean) = sanitize_relative_sarif_uri(&path.to_string_lossy()) {
            if !clean.starts_with("..") && !clean.starts_with('~') {
                return clean;
            }
        }
    }

    if let Some(base) = cwd {
        if let Ok(stripped) = path.strip_prefix(base) {
            if let Some(clean) = sanitize_relative_sarif_uri(&stripped.to_string_lossy()) {
                return clean;
            }
        }
    }

    let canon_path = path.canonicalize().ok();
    if let (Some(ref cp), Some(base_canon)) = (&canon_path, cwd_canon) {
        if let Ok(stripped) = cp.strip_prefix(base_canon) {
            if let Some(clean) = sanitize_relative_sarif_uri(&stripped.to_string_lossy()) {
                return clean;
            }
        }
    }

    for (root, root_canon) in extra_roots {
        if let Ok(stripped) = path.strip_prefix(root) {
            if let Some(clean) = sanitize_relative_sarif_uri(&stripped.to_string_lossy()) {
                return clean;
            }
        }
        if let (Some(ref cp), Some(ref rc)) = (&canon_path, root_canon) {
            if let Ok(stripped) = cp.strip_prefix(rc) {
                if let Some(clean) = sanitize_relative_sarif_uri(&stripped.to_string_lossy()) {
                    return clean;
                }
            }
        }
    }

    // Fallback for paths outside cwd, scan_paths, and HOME: emit a clean relative URI without
    // `file://` or leading `/` so GitHub Code Scanning (`upload-sarif`) never rejects the report.
    let raw_norm = normalize_slashes(&path.to_string_lossy());
    let without_drive = strip_windows_drive(&raw_norm);
    let trimmed = without_drive.trim_start_matches('/');
    sanitize_relative_sarif_uri(trimmed).unwrap_or_else(|| "unknown".to_string())
}

fn strip_windows_drive(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        &s[3..]
    } else {
        s
    }
}

fn sanitize_relative_sarif_uri(raw: &str) -> Option<String> {
    let norm = normalize_slashes(raw);
    let mut parts = Vec::new();
    for seg in norm.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            continue;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        return None;
    }
    let joined = parts.join("/");
    Some(percent_encode_uri_path(&joined))
}

fn normalize_slashes(s: &str) -> String {
    s.replace('\\', "/")
}

fn percent_encode_uri_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
