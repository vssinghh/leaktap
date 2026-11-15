use crate::cli::TapArgs;
use crate::rules::{is_likely_placeholder, shannon_entropy, RuleCategory, RuleEngine};
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
struct WiretapEvent<'a> {
    ts_ms: u128,
    stream: &'a str,
    kind: &'a str,
    rule_id: &'a str,
    severity: &'a str,
    detail: String,
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

pub fn run_tap(args: &TapArgs) -> io::Result<i32> {
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    let engine = Arc::new(RuleEngine::all_rules());
    let url_regex = Arc::new(
        Regex::new(r#"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})(?::\d+)?(?:/[^\s"'<>)]*)?"#)
            .expect("valid url regex"),
    );

    let log_writer: Option<Arc<Mutex<std::fs::File>>> = match &args.log {
        Some(p) => {
            let f = OpenOptions::new().create(true).append(true).open(p)?;
            Some(Arc::new(Mutex::new(f)))
        }
        None => None,
    };

    let allow_set: HashSet<String> = args
        .allow_env
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

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

    let mut cmd = Command::new(program);
    cmd.args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if !exposed_env_keys.is_empty() {
        if args.scrub_env {
            for k in &exposed_env_keys {
                cmd.env_remove(k);
            }
            emit_alert(
                args.quiet,
                &log_writer,
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
            emit_alert(
                args.quiet,
                &log_writer,
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

    let mut child = cmd.spawn()?;
    let child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");
    let child_stderr = child.stderr.take().expect("piped stderr");

    let seen_domains: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // stdin pump (detached so non-closing parent stdin does not hang after child exits)
    {
        let engine = Arc::clone(&engine);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let log_w = log_writer.clone();
        let quiet = args.quiet;
        thread::spawn(move || {
            pump_stream(
                io::stdin(),
                child_stdin,
                "stdin",
                quiet,
                &engine,
                &url_re,
                &domains,
                &log_w,
            );
        });
    }

    // stdout pump — preserves exact raw bytes so MCP JSON-RPC framing is never altered
    let stdout_handle = {
        let engine = Arc::clone(&engine);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let log_w = log_writer.clone();
        let quiet = args.quiet;
        thread::spawn(move || {
            pump_stream(
                child_stdout,
                io::stdout(),
                "stdout",
                quiet,
                &engine,
                &url_re,
                &domains,
                &log_w,
            );
        })
    };

    // stderr pump
    let stderr_handle = {
        let engine = Arc::clone(&engine);
        let url_re = Arc::clone(&url_regex);
        let domains = Arc::clone(&seen_domains);
        let log_w = log_writer.clone();
        let quiet = args.quiet;
        thread::spawn(move || {
            pump_stream(
                child_stderr,
                io::stderr(),
                "stderr",
                quiet,
                &engine,
                &url_re,
                &domains,
                &log_w,
            );
        })
    };

    let status = child.wait()?;
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    Ok(status.code().unwrap_or(1))
}

#[allow(clippy::too_many_arguments)]
fn pump_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    stream_name: &'static str,
    quiet: bool,
    engine: &RuleEngine,
    url_regex: &Regex,
    seen_domains: &Mutex<HashSet<String>>,
    log_writer: &Option<Arc<Mutex<std::fs::File>>>,
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

        // Inspect complete lines for secrets and outbound URLs without delaying raw byte forwarding
        for &b in &buf[..n] {
            line_acc.push(b);
            if b == b'\n' || line_acc.len() >= 64 * 1024 {
                inspect_chunk(
                    &line_acc,
                    stream_name,
                    quiet,
                    engine,
                    url_regex,
                    seen_domains,
                    log_writer,
                );
                line_acc.clear();
            }
        }
    }

    if !line_acc.is_empty() {
        inspect_chunk(
            &line_acc,
            stream_name,
            quiet,
            engine,
            url_regex,
            seen_domains,
            log_writer,
        );
    }
}

fn inspect_chunk(
    bytes: &[u8],
    stream_name: &'static str,
    quiet: bool,
    engine: &RuleEngine,
    url_regex: &Regex,
    seen_domains: &Mutex<HashSet<String>>,
    log_writer: &Option<Arc<Mutex<std::fs::File>>>,
) {
    let text = String::from_utf8_lossy(bytes);

    for m in engine.scan_text(&text) {
        let kind = match m.category {
            RuleCategory::Secret => "secret_in_flight",
            RuleCategory::Pii => "pii_in_flight",
        };
        emit_alert(
            quiet,
            log_writer,
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
            emit_alert(
                quiet,
                log_writer,
                stream_name,
                "outbound_endpoint",
                "endpoint-seen",
                "MEDIUM",
                format!("Endpoint referenced on `{stream_name}`: {host}"),
            );
        }
    }
}

fn emit_alert(
    quiet: bool,
    log_writer: &Option<Arc<Mutex<std::fs::File>>>,
    stream: &str,
    kind: &str,
    rule_id: &str,
    severity: &str,
    detail: String,
) {
    if let Some(lw) = log_writer {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let ev = WiretapEvent {
            ts_ms,
            stream,
            kind,
            rule_id,
            severity,
            detail: detail.clone(),
        };
        if let Ok(line) = serde_json::to_string(&ev) {
            if let Ok(mut guard) = lw.lock() {
                let _ = writeln!(guard, "{line}");
                let _ = guard.flush();
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
    // Skip internal proxy / shell vars
    if matches!(
        upper.as_str(),
        "PATH" | "HOME" | "PWD" | "SHELL" | "TERM" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
    ) {
        return false;
    }
    SENSITIVE_ENV_NAMES.iter().any(|kw| upper.contains(kw)) && shannon_entropy(val) >= 3.5
}

fn summarize_list(items: &[String], max_show: usize) -> String {
    if items.len() <= max_show {
        items.join(", ")
    } else {
        let head = items[..max_show].join(", ");
        format!("{head} (+{} more)", items.len() - max_show)
    }
}
