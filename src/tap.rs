use crate::api_tap::{start_local_api_tap_with_options, TapCallback};
use crate::cli::TapArgs;
use crate::config::PolicyConfig;
use crate::discovery::home_dir;
use crate::header_audit::HeaderAuditor;
use crate::mcp_inspect::audit_mcp_tools_payload;
use crate::netwatch::{
    disable_process_dumpable, enable_child_subreaper, reap_reparented_zombies,
    reap_reparented_zombies_except, spawn_socket_watcher, OS_SOCKET_WATCH_SUPPORTED,
};
use crate::rules::{
    is_likely_placeholder, looks_like_filesystem_path, shannon_entropy, RuleCategory, RuleEngine,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum size (`10 MiB`) of `~/.leaktap/live.jsonl` before rotating to `live.jsonl.1`.
pub const LIVE_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiretapEvent {
    pub ts_ms: u128,
    pub stream: String,
    pub kind: String,
    pub rule_id: String,
    pub severity: String,
    pub detail: String,
}

struct LogSink {
    path: PathBuf,
    rotate_at_bytes: Option<u64>,
    bytes_written: u64,
    file: File,
}

impl LogSink {
    fn open(path: PathBuf, rotate_at_bytes: Option<u64>) -> io::Result<Self> {
        if let Some(limit) = rotate_at_bytes {
            let _ = rotate_log_file_if_exceeded(&path, limit);
        }
        let existing_len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = open_private_append_file(&path)?;
        Ok(Self {
            path,
            rotate_at_bytes,
            bytes_written: existing_len,
            file,
        })
    }

    fn write_line(&mut self, line: &str) {
        let _ = writeln!(self.file, "{line}");
        let _ = self.file.flush();
        self.bytes_written = self.bytes_written.saturating_add(line.len() as u64 + 1);
        if let Some(limit) = self.rotate_at_bytes {
            if self.bytes_written >= limit {
                let rotated = rotated_backup_path(&self.path);
                if fs::rename(&self.path, &rotated).is_ok() {
                    enforce_private_permissions(&rotated);
                    if let Ok(fresh) = open_private_append_file(&self.path) {
                        self.file = fresh;
                        self.bytes_written = 0;
                    }
                }
            }
        }
    }
}

fn rotated_backup_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".1");
    PathBuf::from(os)
}

fn enforce_private_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Rotates `path` to `<path>.1` (`0600`) when its current size meets or exceeds `max_bytes`.
pub fn rotate_log_file_if_exceeded(path: &Path, max_bytes: u64) -> io::Result<bool> {
    let len = match fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if len < max_bytes {
        return Ok(false);
    }
    let rotated = rotated_backup_path(path);
    fs::rename(path, &rotated)?;
    enforce_private_permissions(&rotated);
    Ok(true)
}

const SENSITIVE_ENV_NAMES: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "MYSQL_PWD",
    "PGPASSWORD",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CLIENT_SECRET",
    "WEBHOOK_SECRET",
    "CREDENTIAL",
    "CONNECTION_STRING",
    "CONN_STR",
    "DATABASE_URL",
    "REDIS_URL",
    "MONGODB_URI",
];

const PASSWORD_ENV_NAMES: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "MYSQL_PWD",
    "PGPASSWORD",
    "REDISCLI_AUTH",
];

pub fn default_live_log_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".leaktap").join("live.jsonl"))
}

fn open_private_append_file(path: &Path) -> io::Result<File> {
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

    let is_coding_cli = is_known_coding_cli(program);
    let is_info_only = cmd_args
        .iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version"));
    let parent_is_tty = io::stdin().is_terminal() && io::stdout().is_terminal();
    let inherit_tty = is_coding_cli && parent_is_tty;
    let is_fullscreen_tui =
        inherit_tty && !is_info_only && !is_oneshot_cli_invocation(program, cmd_args);

    let block_secrets_enabled = args.block_secrets || env_flag_enabled("LEAKTAP_BLOCK_SECRETS");
    let redact_secrets_enabled = args.redact_secrets || env_flag_enabled("LEAKTAP_REDACT_SECRETS");
    let scrub_env_enabled = args.scrub_env && !args.no_scrub_env;
    let inspect_api_enabled = (args.inspect_api || block_secrets_enabled || redact_secrets_enabled)
        && !args.no_inspect_api
        && !is_info_only;

    let policy = PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &[],
        args.trust_project_config,
        args.no_config,
    )
    .ok();
    let engine = Arc::new(RuleEngine::with_policy(true, policy.as_ref()));
    let header_auditor = Arc::new(HeaderAuditor::new());
    let url_regex = Arc::new(
        Regex::new(r#"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})(?::\d+)?(?:/[^\s"'<>)]*)?"#)
            .expect("valid url regex"),
    );

    let default_live_path = default_live_log_path();
    let mut writers: Vec<LogSink> = Vec::new();
    if let Some(ref p) = args.log {
        let rotate = if default_live_path.as_ref() == Some(p) {
            Some(LIVE_LOG_MAX_BYTES)
        } else {
            None
        };
        writers.push(LogSink::open(p.clone(), rotate)?);
    }
    if !args.no_live_log && !is_info_only {
        if let Some(default_log) = default_live_path {
            let same_as_explicit = args.log.as_ref().is_some_and(|p| p == &default_log);
            if !same_as_explicit {
                if let Ok(sink) = LogSink::open(default_log, Some(LIVE_LOG_MAX_BYTES)) {
                    writers.push(sink);
                }
            }
        }
    }
    let log_writers = Arc::new(Mutex::new(writers));

    let suppress_live_stderr = args.quiet || is_fullscreen_tui || is_info_only;
    let alert_count = Arc::new(AtomicUsize::new(0));
    let alert_count_for_cb = Arc::clone(&alert_count);
    let writers_for_cb = Arc::clone(&log_writers);
    let emit_cb: TapCallback = Arc::new(move |stream, kind, rule_id, severity, detail| {
        alert_count_for_cb.fetch_add(1, Ordering::Relaxed);
        emit_alert(
            suppress_live_stderr,
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

    let local_api_tap = if inspect_api_enabled {
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

        let tap = start_local_api_tap_with_options(
            anth_upstream,
            oai_upstream,
            chatgpt_upstream,
            openai_explicit,
            gemini_upstream,
            block_secrets_enabled,
            redact_secrets_enabled,
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
        let has_base_override = cmd_args.iter().any(|a| a.contains("openai_base_url"));
        if program_stem(program) == "codex" && !is_info_only && !has_base_override {
            final_args.push("-c".to_string());
            final_args.push(format!("openai_base_url=\"{}/v1\"", tap.openai_base_url));
        }
    }
    final_args.extend(cmd_args.iter().cloned());

    let mut cmd = Command::new(program);
    cmd.args(&final_args);
    if inherit_tty {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    if !exposed_env_keys.is_empty() && !is_info_only {
        if scrub_env_enabled {
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

    if !is_info_only
        && !allow_set.contains("SSH_AUTH_SOCK")
        && env::var_os("SSH_AUTH_SOCK").is_some_and(|v| !v.is_empty())
    {
        if args.scrub_ssh_agent {
            cmd.env_remove("SSH_AUTH_SOCK");
            cmd.env_remove("SSH_AGENT_PID");
            emit_cb(
                "env",
                "ssh_agent_scrubbed",
                "env-ssh-agent",
                "MEDIUM",
                "Scrubbed `SSH_AUTH_SOCK` agent socket before launch".to_string(),
            );
        } else {
            emit_cb(
                "env",
                "ssh_agent_inherited",
                "env-ssh-agent",
                "MEDIUM",
                "Child session inherits active `SSH_AUTH_SOCK` agent socket (pass --scrub-ssh-agent to strip)".to_string(),
            );
        }
    }

    if let Some(ref tap) = local_api_tap {
        cmd.env("ANTHROPIC_BASE_URL", &tap.anthropic_base_url);
        cmd.env("OPENAI_BASE_URL", &tap.openai_base_url);
        cmd.env("GOOGLE_GEMINI_BASE_URL", &tap.gemini_base_url);
        cmd.env("GEMINI_API_BASE_URL", &tap.gemini_base_url);
        cmd.env("OPENROUTER_BASE_URL", &tap.openrouter_base_url);
        cmd.env("DEEPSEEK_BASE_URL", &tap.deepseek_base_url);
        cmd.env("XAI_BASE_URL", &tap.xai_base_url);
        cmd.env("GROQ_BASE_URL", &tap.groq_base_url);
        let no_proxy = build_loopback_no_proxy();
        cmd.env("NO_PROXY", &no_proxy);
        cmd.env("no_proxy", &no_proxy);
    }

    if is_fullscreen_tui && !args.quiet {
        let mode_label = if block_secrets_enabled {
            "active secret blocking enabled"
        } else if redact_secrets_enabled {
            "in-transit secret redaction enabled"
        } else {
            "audit mode"
        };
        let _ = writeln!(
            io::stderr(),
            "[leaktap] Watching `{}` ({mode_label}) — live events streaming to ~/.leaktap/live.jsonl (`leaktap ui` to view)",
            program_stem(program)
        );
    }

    if inspect_api_enabled {
        emit_api_tap_bypass_warnings(program, args.quiet, &emit_cb);
    }

    if !args.no_net_watch && !is_info_only && !OS_SOCKET_WATCH_SUPPORTED && !args.quiet {
        let _ = writeln!(
            io::stderr(),
            "[leaktap:note] Per-process OS socket telemetry is only supported on Linux and macOS; HTTP API inspection and env scrubbing remain active."
        );
    }

    if scrub_env_enabled && !is_info_only {
        disable_process_dumpable();
    }

    if !args.no_net_watch && !is_info_only {
        enable_child_subreaper();
    }

    let mut child = cmd.spawn()?;
    let child_pid = child.id();
    let ignore_tap_port = local_api_tap.as_ref().map(|t| t.port);

    // Zero-root OS socket watcher for outbound TCP/UDP connections across child process tree
    let stop_sockets = Arc::new(AtomicBool::new(false));
    let socket_handle = if !args.no_net_watch && !is_info_only {
        let emit_sock = Arc::clone(&emit_cb);
        let engine_for_sock = Arc::clone(&engine);
        Some(spawn_socket_watcher(
            child_pid,
            ignore_tap_port,
            Arc::clone(&stop_sockets),
            move |obs| {
                let cmd_context = sanitize_cmdline_for_log(&obs.cmdline, &engine_for_sock);
                let cmd_suffix = if cmd_context.is_empty() {
                    String::new()
                } else {
                    format!(": {cmd_context}")
                };
                let detail = if obs.is_proxy_loopback {
                    format!(
                        "Outbound {} connection via local proxy {} by {} (pid {}{})",
                        obs.proto, obs.remote, obs.comm, obs.pid, cmd_suffix
                    )
                } else {
                    format!(
                        "Outbound {} connection opened to {} by {} (pid {}{})",
                        obs.proto, obs.remote, obs.comm, obs.pid, cmd_suffix
                    )
                };
                let rule_id = if obs.proto == "UDP" {
                    "udp-connection"
                } else {
                    "tcp-connection"
                };
                emit_sock("socket", "outbound_socket", rule_id, "MEDIUM", detail);
            },
        ))
    } else {
        None
    };

    let pipe_handles = if !inherit_tty {
        let child_stdin = child.stdin.take().expect("piped stdin");
        let child_stdout = child.stdout.take().expect("piped stdout");
        let child_stderr = child.stderr.take().expect("piped stderr");
        let seen_domains: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

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
        Some((stdout_handle, stderr_handle))
    } else {
        None
    };

    let status = wait_for_child_and_reap_orphans(&mut child, !args.no_net_watch && !is_info_only)?;
    stop_sockets.store(true, Ordering::Relaxed);
    if let Some(tap) = local_api_tap {
        tap.stop();
    }
    if let Some(h) = socket_handle {
        let _ = h.join();
    }
    reap_reparented_zombies();
    if let Some((stdout_handle, stderr_handle)) = pipe_handles {
        let _ = stdout_handle.join();
        let _ = stderr_handle.join();
    }

    if is_fullscreen_tui && !args.quiet {
        let total = alert_count.load(Ordering::Relaxed);
        if total > 0 {
            let _ = writeln!(
                io::stderr(),
                "[leaktap] Session ended — {total} event(s) logged. Run `leaktap ui` to inspect."
            );
        }
    }

    Ok(status.code().unwrap_or(1))
}

fn wait_for_child_and_reap_orphans(
    child: &mut Child,
    subreaper_active: bool,
) -> io::Result<ExitStatus> {
    if !subreaper_active || cfg!(not(target_os = "linux")) {
        return child.wait();
    }
    let child_pid = child.id();
    let mut last_reap = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
        if last_reap.elapsed() >= Duration::from_millis(250) {
            reap_reparented_zombies_except(child_pid);
            last_reap = Instant::now();
        }
    }
}

fn env_flag_enabled(var: &str) -> bool {
    env::var(var)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn sanitize_cmdline_for_log(cmdline: &str, engine: &RuleEngine) -> String {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut scrubbed = trimmed.to_string();
    let matches = engine.scan_text(&scrubbed);
    for m in matches.iter().rev() {
        if m.category == RuleCategory::Secret {
            scrubbed.replace_range(m.start..m.end, &m.masked);
        }
    }
    let collapsed: String = scrubbed.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = collapsed.chars();
    let head: String = chars.by_ref().take(96).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
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
            &m.rule_id,
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

    // Passively audit MCP `tools/list` JSON-RPC responses crossing stdio streams
    if text.contains("\"tools\"") && text.contains("\"jsonrpc\"") {
        let json_cand = text.trim();
        if json_cand.starts_with('{') {
            if let Ok(rpc_val) = serde_json::from_str::<serde_json::Value>(json_cand) {
                let mut mcp_findings = Vec::new();
                audit_mcp_tools_payload(
                    "stdio-mcp",
                    stream_name,
                    Path::new(stream_name),
                    &rpc_val,
                    true,
                    &mut mcp_findings,
                );
                for mf in mcp_findings {
                    emit(
                        stream_name,
                        "mcp_tool_risk",
                        mf.rule_id,
                        mf.severity.as_str(),
                        mf.message,
                    );
                }
            }
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

fn is_known_coding_cli(program: &str) -> bool {
    matches!(
        program_stem(program).as_str(),
        "claude"
            | "claude-code"
            | "codex"
            | "agy"
            | "antigravity"
            | "antigravity-cli"
            | "gemini"
            | "gemini-cli"
    )
}

fn is_oneshot_cli_invocation(program: &str, cmd_args: &[String]) -> bool {
    let stem = program_stem(program);
    if stem == "codex"
        && cmd_args
            .first()
            .is_some_and(|a| matches!(a.as_str(), "exec" | "e" | "login" | "mcp" | "plugin"))
    {
        return true;
    }
    cmd_args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-p" | "--print" | "--prompt" | "plugin" | "mcp" | "auth" | "doctor"
        )
    })
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
    log_writers: &Arc<Mutex<Vec<LogSink>>>,
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
            for sink in guard.iter_mut() {
                sink.write_line(&line);
            }
        }
    }

    if !quiet {
        let _ = writeln!(io::stderr(), "[leaktap:{severity}] {detail}");
    }
}

pub fn is_sensitive_env_pair(key: &str, val: &str, engine: &RuleEngine) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower_val = trimmed.to_ascii_lowercase();
    let is_bool_or_null = matches!(
        lower_val.as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off" | "none" | "null"
    );
    let upper = key.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "PATH"
            | "HOME"
            | "PWD"
            | "OLDPWD"
            | "SHELL"
            | "TERM"
            | "COLORTERM"
            | "LANG"
            | "LC_ALL"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
            | "LESSKEY"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "NODE_EXTRA_CA_CERTS"
            | "REQUESTS_CA_BUNDLE"
            | "CURL_CA_BUNDLE"
            | "GIT_SSL_CAINFO"
    ) || upper.contains("PUBLIC_KEY")
        || upper.contains("PUBKEY")
        || upper.contains("GPG_KEY")
        || upper.contains("CACHE_KEY")
        || upper.contains("HOST_KEY")
    {
        return false;
    }

    // Scrub ambient cloud/cluster credential file pointers and profile selectors by default
    // (pass `--allow-env <VAR>` to forward intentionally to a trusted CLI/MCP server).
    let is_credential_file_or_profile = matches!(
        upper.as_str(),
        "GOOGLE_APPLICATION_CREDENTIALS"
            | "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"
            | "CLOUDSDK_CONFIG"
            | "AWS_SHARED_CREDENTIALS_FILE"
            | "AWS_CONFIG_FILE"
            | "AWS_WEB_IDENTITY_TOKEN_FILE"
            | "AZURE_FEDERATED_TOKEN_FILE"
            | "KUBECONFIG"
            | "DOCKER_CONFIG"
            | "NPM_CONFIG_USERCONFIG"
            | "AWS_PROFILE"
            | "AWS_DEFAULT_PROFILE"
            | "AZURE_CONFIG_DIR"
            | "GH_CONFIG_DIR"
            | "TF_CLI_CONFIG_FILE"
            | "NETRC"
            | "PGPASSFILE"
            | "VAULT_TOKEN"
    ) || upper.ends_with("_SECRET_FILE")
        || upper.ends_with("_PASSWORD_FILE")
        || upper.ends_with("_PASSWD_FILE")
        || upper.ends_with("_TOKEN_FILE")
        || upper.ends_with("_KEY_FILE")
        || upper.ends_with("_CREDENTIALS_FILE")
        || upper.ends_with("_CREDENTIAL_FILE")
        || upper.ends_with("_AUTH_FILE")
        || upper.ends_with("_PEM_FILE");
    if is_credential_file_or_profile {
        return !is_bool_or_null;
    }

    if upper.ends_with("_FILE")
        || upper.ends_with("_PATH")
        || upper.ends_with("_DIR")
        || upper.ends_with("_SOCK")
    {
        return false;
    }
    if is_bool_or_null {
        return false;
    }

    let is_template_marker = trimmed.starts_with("${")
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'));

    let is_pass_token = upper == "PASS" || upper.ends_with("_PASS") || upper.contains("_PASS_");
    let is_direct_secret_or_key_var = upper == "SECRET"
        || upper == "API_KEY"
        || upper.ends_with("_SECRET")
        || upper.ends_with("_API_KEY");
    let is_unambiguous_password_or_cloud_secret =
        PASSWORD_ENV_NAMES.iter().any(|kw| upper.contains(kw))
            || upper.ends_with("_PWD")
            || is_pass_token
            || is_direct_secret_or_key_var
            || matches!(
                upper.as_str(),
                "AWS_SECRET_ACCESS_KEY" | "AWS_SESSION_TOKEN" | "AZURE_STORAGE_KEY"
            );
    if is_unambiguous_password_or_cloud_secret && !is_template_marker {
        return true;
    }

    if is_likely_placeholder(trimmed) {
        return false;
    }

    if trimmed.len() < 8 {
        return false;
    }
    if engine
        .scan_text(trimmed)
        .iter()
        .any(|m| m.category == RuleCategory::Secret)
    {
        return true;
    }

    // Do not treat genuine local filesystem paths (`/usr/local/bin/node`, `./key.pem`, `C:\creds\...`)
    // as inline secrets, while still scrubbing Base64 secrets that happen to start with `/` (`APP_SECRET=/9j4kL8m...=`).
    let looks_like_local_path = looks_like_filesystem_path(trimmed)
        && !trimmed.contains("://")
        && !trimmed.contains("-----BEGIN");
    if looks_like_local_path {
        return false;
    }

    let is_pat_token = upper == "PAT" || upper.ends_with("_PAT") || upper.contains("_PAT_");
    let has_sensitive_name = SENSITIVE_ENV_NAMES.iter().any(|kw| upper.contains(kw))
        || upper.ends_with("_KEY")
        || upper == "KEY"
        || is_pat_token;
    trimmed.len() >= 12 && has_sensitive_name && shannon_entropy(trimmed) >= 3.4
}

fn emit_api_tap_bypass_warnings(program: &str, quiet: bool, emit_cb: &TapCallback) {
    let mut warnings: Vec<String> = Vec::new();
    let stem = program_stem(program);

    for var in [
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ] {
        if env_flag_enabled(var) {
            warnings.push(format!(
                "`{var}=1` routes model traffic directly via cloud SDK endpoints, bypassing local HTTP API inspection/blocking"
            ));
        }
    }

    if matches!(stem.as_str(), "agy" | "antigravity" | "antigravity-cli")
        && env::var("GEMINI_API_KEY")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        && env::var("GOOGLE_API_KEY")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
    {
        warnings.push(
            "Antigravity without `GEMINI_API_KEY` / `GOOGLE_API_KEY` may use Google OAuth/gRPC channels that bypass local HTTP API inspection/blocking".to_string(),
        );
    }

    // Check workspace and user `.claude/settings*.json` for `env` overrides that hijack BASE_URL or cloud routing after launch
    let mut settings_candidates = Vec::new();
    if let Ok(cwd) = env::current_dir() {
        settings_candidates.push(cwd.join(".claude").join("settings.json"));
        settings_candidates.push(cwd.join(".claude").join("settings.local.json"));
    }
    if let Some(home) = home_dir() {
        settings_candidates.push(home.join(".claude").join("settings.json"));
    }
    for cand in settings_candidates {
        let Ok(raw) = fs::read_to_string(&cand) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(env_obj) = val.get("env").and_then(|e| e.as_object()) else {
            continue;
        };
        for k in env_obj.keys() {
            let ku = k.to_ascii_uppercase();
            if matches!(
                ku.as_str(),
                "ANTHROPIC_BASE_URL"
                    | "OPENAI_BASE_URL"
                    | "GOOGLE_GEMINI_BASE_URL"
                    | "GEMINI_API_BASE_URL"
                    | "OPENROUTER_BASE_URL"
                    | "DEEPSEEK_BASE_URL"
                    | "XAI_BASE_URL"
                    | "GROQ_BASE_URL"
                    | "CLAUDE_CODE_USE_BEDROCK"
                    | "CLAUDE_CODE_USE_VERTEX"
                    | "CLAUDE_CODE_USE_FOUNDRY"
            ) {
                warnings.push(format!(
                    "`{}` defines `env.{k}`, which can override `leaktap`'s local API tap URL after startup",
                    cand.display()
                ));
            }
        }
    }

    // Check workspace and user `.codex/config.toml` for `[model_providers]` `base_url` or env overrides
    // that route Codex requests directly to a custom endpoint instead of `OPENAI_BASE_URL`.
    let mut codex_candidates = Vec::new();
    if let Ok(cwd) = env::current_dir() {
        codex_candidates.push(cwd.join(".codex").join("config.toml"));
    }
    if let Some(home) = home_dir() {
        codex_candidates.push(home.join(".codex").join("config.toml"));
    }
    for cand in codex_candidates {
        let Ok(raw) = fs::read_to_string(&cand) else {
            continue;
        };
        let Ok(doc) = toml::from_str::<toml::Value>(&raw) else {
            continue;
        };
        let Some(tbl) = doc.as_table() else {
            continue;
        };
        for top_key in ["chatgpt_base_url", "base_url"] {
            if tbl
                .get(top_key)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.trim().is_empty())
            {
                warnings.push(format!(
                    "`{}` defines `{top_key}`, which can bypass `leaktap`'s local OpenAI API tap",
                    cand.display()
                ));
            }
        }
        if let Some(providers) = tbl.get("model_providers").and_then(|v| v.as_table()) {
            for (prov_id, prov_val) in providers {
                if prov_val
                    .as_table()
                    .and_then(|pt| pt.get("base_url"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty())
                {
                    warnings.push(format!(
                        "`{}` defines `model_providers.{prov_id}.base_url`, which routes custom provider traffic around `OPENAI_BASE_URL`",
                        cand.display()
                    ));
                }
            }
        }
        for env_tbl_opt in [
            tbl.get("env").and_then(|v| v.as_table()),
            tbl.get("shell_environment_policy")
                .and_then(|v| v.as_table())
                .and_then(|st| st.get("set"))
                .and_then(|v| v.as_table()),
        ]
        .into_iter()
        .flatten()
        {
            for k in env_tbl_opt.keys() {
                let ku = k.to_ascii_uppercase();
                if matches!(
                    ku.as_str(),
                    "OPENAI_BASE_URL"
                        | "ANTHROPIC_BASE_URL"
                        | "GOOGLE_GEMINI_BASE_URL"
                        | "GEMINI_API_BASE_URL"
                        | "OPENROUTER_BASE_URL"
                        | "DEEPSEEK_BASE_URL"
                        | "XAI_BASE_URL"
                        | "GROQ_BASE_URL"
                ) {
                    warnings.push(format!(
                        "`{}` defines `{k}` in env settings, which can override `leaktap`'s local API tap URL",
                        cand.display()
                    ));
                }
            }
        }
    }

    for msg in warnings {
        emit_cb(
            "http",
            "tap_bypass_warning",
            "tap-bypass-warning",
            "HIGH",
            msg.clone(),
        );
        if !quiet {
            let _ = writeln!(io::stderr(), "[leaktap:warn] {msg}");
        }
    }
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
