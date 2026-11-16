use crate::api_tap::{start_local_api_tap, TapCallback};
use crate::cli::TapArgs;
use crate::discovery::home_dir;
use crate::header_audit::HeaderAuditor;
use crate::netwatch::spawn_socket_watcher;
use crate::rules::{is_likely_placeholder, shannon_entropy, RuleCategory, RuleEngine};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiretapEvent {
    pub ts_ms: u128,
    pub stream: String,
    pub kind: String,
    pub rule_id: String,
    pub severity: String,
    pub detail: String,
}

const SENSITIVE_ENV_NAMES: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "DATABASE_URL",
    "REDIS_URL",
    "MONGODB_URI",
];

pub fn default_live_log_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".leaktap").join("live.jsonl"))
}

fn open_private_append_file(path: &PathBuf) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

pub fn run_tap(args: &TapArgs) -> io::Result<i32> {
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    let engine = Arc::new(RuleEngine::all_rules());
    let header_auditor = Arc::new(HeaderAuditor::new());
    let url_regex = Arc::new(
        Regex::new(r#"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})(?::\d+)?(?:/[^\s"'<>)]*)?"#)
            .expect("valid url regex"),
    );

    let mut writers: Vec<File> = Vec::new();
    if let Some(ref p) = args.log {
        writers.push(open_private_append_file(p)?);
    }
    if !args.no_live_log {
        if let Some(default_log) = default_live_log_path() {
            let same_as_explicit = args.log.as_ref().is_some_and(|p| p == &default_log);
            if !same_as_explicit {
                if let Ok(f) = open_private_append_file(&default_log) {
                    writers.push(f);
                }
            }
        }
    }
    let log_writers = Arc::new(Mutex::new(writers));

    let quiet = args.quiet;
    let writers_for_cb = Arc::clone(&log_writers);
    let emit_cb: TapCallback = Arc::new(move |stream, kind, rule_id, severity, detail| {
        emit_alert(
            quiet,
            &writers_for_cb,
            stream,
            kind,
            rule_id,
            severity,
            detail,
        );
    });

    let mut allow_set: HashSet<String> = args
        .allow_env
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    for &provider_key in default_provider_env_keys(program) {
        allow_set.insert(provider_key.to_string());
    }

    let mut exposed_env_keys = Vec::new();
    for (k, v) in env::vars() {
        if allow_set.contains(&k) {
            continue;
        }
        if is_sensitive_env_pair(&k, &v, &engine) {
            exposed_env_keys.push(k);
        }
    }
    exposed_env_keys.sort();

    // Optional zero-cert local loopback API tap (`--inspect-api`)
    let local_api_tap = if args.inspect_api {
        let anth_upstream = env::var("LEAKTAP_UPSTREAM_ANTHROPIC_URL")
            .or_else(|_| env::var("ANTHROPIC_BASE_URL"))
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        let openai_explicit = env::var_os("LEAKTAP_UPSTREAM_OPENAI_URL").is_some()
            || env::var_os("OPENAI_BASE_URL").is_some();
        let oai_upstream = env::var("LEAKTAP_UPSTREAM_OPENAI_URL")
            .or_else(|_| env::var("OPENAI_BASE_URL"))
            .unwrap_or_else(|_| "https://api.openai.com".to_string());
        let chatgpt_upstream = env::var("LEAKTAP_UPSTREAM_CHATGPT_URL")
            .unwrap_or_else(|_| "https://chatgpt.com/backend-api/codex".to_string());
        let gemini_upstream = env::var("LEAKTAP_UPSTREAM_GEMINI_URL")
            .or_else(|_| env::var("GOOGLE_GEMINI_BASE_URL"))
            .or_else(|_| env::var("GEMINI_API_BASE_URL"))
            .unwrap_or_else(|_| "https://generativelanguage.googleapis.com".to_string());

        let tap = start_local_api_tap(
            anth_upstream,
            oai_upstream,
            chatgpt_upstream,
            openai_explicit,
            gemini_upstream,
            Arc::clone(&engine),
            Arc::clone(&header_auditor),
            Arc::clone(&emit_cb),
        )?;
        Some(tap)
    } else {
        None
    };

    let mut final_args: Vec<String> = Vec::with_capacity(cmd_args.len() + 2);
    if let Some(ref tap) = local_api_tap {
        let is_info_only = cmd_args
            .iter()
            .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version"));
        let has_base_override = cmd_args.iter().any(|a| a.contains("openai_base_url"));
        if program_stem(program) == "codex" && !is_info_only && !has_base_override {
            final_args.push("-c".to_string());
            final_args.push(format!("openai_base_url=\"{}/v1\"", tap.openai_base_url));
        }
    }
    final_args.extend(cmd_args.iter().cloned());

    let mut cmd = Command::new(program);
    cmd.args(&final_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if !exposed_env_keys.is_empty() {
        if args.scrub_env {
            for k in &exposed_env_keys {
                cmd.env_remove(k);
            }
            emit_cb(
                "env",
                "env_scrubbed",
                "env-inheritance",
                "HIGH",
                format!(
                    "Scrubbed {} sensitive env var(s) before launch: {}",
                    exposed_env_keys.len(),
                    summarize_list(&exposed_env_keys, 5)
                ),
            );
        } else {
            emit_cb(
                "env",
                "env_inherited",
                "env-inheritance",
                "HIGH",
                format!(
                    "Child inherits {} sensitive env var(s): {} (pass --scrub-env to strip)",
                    exposed_env_keys.len(),
                    summarize_list(&exposed_env_keys, 5)
                ),
            );
        }
    }

    if let Some(ref tap) = local_api_tap {
        cmd.env("ANTHROPIC_BASE_URL", &tap.anthropic_base_url);
        cmd.env("OPENAI_BASE_URL", &tap.openai_base_url);
        cmd.env("GOOGLE_GEMINI_BASE_URL", &tap.gemini_base_url);
        cmd.env("GEMINI_API_BASE_URL", &tap.gemini_base_url);
        let no_proxy = build_loopback_no_proxy();
        cmd.env("NO_PROXY", &no_proxy);
        cmd.env("no_proxy", &no_proxy);
    }

    let mut child = cmd.spawn()?;
    let child_pid = child.id();
    let child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");
    let child_stderr = child.stderr.take().expect("piped stderr");

    // Zero-root OS socket watcher for outbound TCP connections across child process tree
    let stop_sockets = Arc::new(AtomicBool::new(false));
    let socket_handle = if !args.no_net_watch {
        let emit_sock = Arc::clone(&emit_cb);
        Some(spawn_socket_watcher(
            child_pid,
            Arc::clone(&stop_sockets),
            move |remote| {
                emit_sock(
                    "socket",
                    "outbound_socket",
                    "tcp-connection",
                    "MEDIUM",
                    format!("Outbound TCP connection opened to {remote}"),
                );
            },
        ))
    } else {
        None
    };

    let seen_domains: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // stdin pump (detached so non-closing parent stdin does not hang after child exits)
    {
        let engine = Arc::clone(&engine);
        let auditor = Arc::clone(&header_auditor);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let emit = Arc::clone(&emit_cb);
        thread::spawn(move || {
            pump_stream(
                io::stdin(),
                child_stdin,
                "stdin",
                &engine,
                &auditor,
                &url_re,
                &domains,
                &emit,
            );
        });
    }

    // stdout pump — preserves exact raw bytes so MCP JSON-RPC framing is never altered
    let stdout_handle = {
        let engine = Arc::clone(&engine);
        let auditor = Arc::clone(&header_auditor);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let emit = Arc::clone(&emit_cb);
        thread::spawn(move || {
            pump_stream(
                child_stdout,
                io::stdout(),
                "stdout",
                &engine,
                &auditor,
                &url_re,
                &domains,
                &emit,
            );
        })
    };

    // stderr pump
    let stderr_handle = {
        let engine = Arc::clone(&engine);
        let auditor = Arc::clone(&header_auditor);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let emit = Arc::clone(&emit_cb);
        thread::spawn(move || {
            pump_stream(
                child_stderr,
                io::stderr(),
                "stderr",
                &engine,
                &auditor,
                &url_re,
                &domains,
                &emit,
            );
        })
    };

    let status = child.wait()?;
    stop_sockets.store(true, Ordering::Relaxed);
    if let Some(tap) = local_api_tap {
        tap.stop();
    }
    if let Some(h) = socket_handle {
        let _ = h.join();
    }
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    Ok(status.code().unwrap_or(1))
}

#[allow(clippy::too_many_arguments)]
fn pump_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    stream_name: &'static str,
    engine: &RuleEngine,
    header_auditor: &HeaderAuditor,
    url_regex: &Regex,
    seen_domains: &Mutex<HashSet<String>>,
    emit: &TapCallback,
) {
    let mut buf = [0u8; 8192];
    let mut line_acc: Vec<u8> = Vec::with_capacity(4096);

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        if writer.write_all(&buf[..n]).is_err() {
            break;
        }
        let _ = writer.flush();

        for &b in &buf[..n] {
            line_acc.push(b);
            if b == b'\n' || line_acc.len() >= 64 * 1024 {
                inspect_chunk(
                    &line_acc,
                    stream_name,
                    engine,
                    header_auditor,
                    url_regex,
                    seen_domains,
                    emit,
                );
                line_acc.clear();
            }
        }
    }

    if !line_acc.is_empty() {
        inspect_chunk(
            &line_acc,
            stream_name,
            engine,
            header_auditor,
            url_regex,
            seen_domains,
            emit,
        );
    }
}

fn inspect_chunk(
    bytes: &[u8],
    stream_name: &'static str,
    engine: &RuleEngine,
    header_auditor: &HeaderAuditor,
    url_regex: &Regex,
    seen_domains: &Mutex<HashSet<String>>,
    emit: &TapCallback,
) {
    let text = String::from_utf8_lossy(bytes);

    // Check if the line looks like an HTTP header dump (`> User-Agent: ...` or `User-Agent: ...`)
    let trimmed = text.trim_start_matches(['>', '<', ' ', '\t']);
    if let Some((hdr_k, hdr_v)) = parse_probable_http_header(trimmed) {
        for hf in header_auditor.inspect_header(hdr_k, hdr_v, engine) {
            emit(
                stream_name,
                "header_leak",
                hf.rule_id,
                hf.severity.as_str(),
                hf.detail,
            );
        }
    }

    for m in engine.scan_text(&text) {
        let kind = match m.category {
            RuleCategory::Secret => "secret_in_flight",
            RuleCategory::Pii => "pii_in_flight",
        };
        emit(
            stream_name,
            kind,
            m.rule_id,
            m.severity.as_str(),
            format!("{} ({}) crossed `{stream_name}`", m.rule_name, m.masked),
        );
    }

    for caps in url_regex.captures_iter(&text) {
        let Some(host_m) = caps.get(1) else {
            continue;
        };
        let host = host_m.as_str().to_ascii_lowercase();
        if host == "localhost" || host == "127.0.0.1" || host.ends_with(".example.com") {
            continue;
        }
        let is_new = seen_domains
            .lock()
            .map(|mut s| s.insert(host.clone()))
            .unwrap_or(false);
        if is_new {
            emit(
                stream_name,
                "outbound_endpoint",
                "endpoint-seen",
                "MEDIUM",
                format!("Endpoint referenced on `{stream_name}`: {host}"),
            );
        }
    }
}

fn parse_probable_http_header(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(':')?;
    let key = k.trim();
    if key.is_empty()
        || key.len() > 48
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    let lower = key.to_ascii_lowercase();
    if lower == "user-agent"
        || lower == "from"
        || lower == "referer"
        || lower.starts_with("x-")
        || lower.starts_with("anthropic-")
        || lower.starts_with("openai-")
        || lower.starts_with("x-goog-")
    {
        return Some((key, v.trim()));
    }
    None
}

fn program_stem(program: &str) -> String {
    let base = std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    base.strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".cmd"))
        .or_else(|| base.strip_suffix(".bat"))
        .unwrap_or(&base)
        .to_string()
}

fn default_provider_env_keys(program: &str) -> &'static [&'static str] {
    match program_stem(program).as_str() {
        "claude" | "claude-code" => &[
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ],
        "codex" => &["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"],
        "agy" | "antigravity" | "antigravity-cli" | "gemini" | "gemini-cli" => {
            &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
        }
        _ => &[],
    }
}

fn emit_alert(
    quiet: bool,
    log_writers: &Arc<Mutex<Vec<File>>>,
    stream: &str,
    kind: &str,
    rule_id: &str,
    severity: &str,
    detail: String,
) {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let ev = WiretapEvent {
        ts_ms,
        stream: stream.to_string(),
        kind: kind.to_string(),
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        detail: detail.clone(),
    };
    if let Ok(line) = serde_json::to_string(&ev) {
        if let Ok(mut guard) = log_writers.lock() {
            for w in guard.iter_mut() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
    }

    if !quiet {
        let _ = writeln!(io::stderr(), "[leaktap:{severity}] {detail}");
    }
}

fn is_sensitive_env_pair(key: &str, val: &str, engine: &RuleEngine) -> bool {
    if val.len() < 12 || is_likely_placeholder(val) {
        return false;
    }
    if engine
        .scan_text(val)
        .iter()
        .any(|m| m.category == RuleCategory::Secret)
    {
        return true;
    }
    let upper = key.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "PATH" | "HOME" | "PWD" | "SHELL" | "TERM" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
    ) || upper.ends_with("_FILE")
        || upper.ends_with("_PATH")
        || upper.ends_with("_DIR")
        || upper.ends_with("_SOCK")
    {
        return false;
    }
    SENSITIVE_ENV_NAMES.iter().any(|kw| upper.contains(kw)) && shannon_entropy(val) >= 3.5
}

fn build_loopback_no_proxy() -> String {
    let existing = env::var("NO_PROXY")
        .or_else(|_| env::var("no_proxy"))
        .unwrap_or_default();
    let mut parts: Vec<String> = existing
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for host in ["localhost", "127.0.0.1", "::1"] {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(host)) {
            parts.push(host.to_string());
        }
    }
    parts.join(",")
}

fn summarize_list(items: &[String], max_show: usize) -> String {
    if items.len() <= max_show {
        items.join(", ")
    } else {
        let head = items[..max_show].join(", ");
        format!("{head} (+{} more)", items.len() - max_show)
    }
}
