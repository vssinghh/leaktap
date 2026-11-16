use crate::header_audit::{HeaderAuditor, UpstreamProvider};
use crate::rules::{RuleCategory, RuleEngine};
use flate2::bufread::{DeflateDecoder, GzDecoder, ZlibDecoder};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CONCURRENT_TAP_CONNS: usize = 64;
const MAX_REQUEST_LINE_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;
const MAX_TOTAL_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 128;
const MAX_IDLE_CONNS_PER_ORIGIN: usize = 8;
const MAX_TOTAL_IDLE_CONNS: usize = 64;
const IDLE_CONN_TTL: Duration = Duration::from_secs(45);

#[derive(Hash, PartialEq, Eq, Clone)]
struct PoolKey {
    is_https: bool,
    host: String,
    port: u16,
    proxy_tag: String,
}

struct IdleUpstreamConn {
    reader: BufReader<UpstreamStream>,
    parked_at: Instant,
}

type UpstreamPool = Arc<Mutex<HashMap<PoolKey, VecDeque<IdleUpstreamConn>>>>;

struct ConnSlotGuard(Arc<AtomicUsize>);

impl Drop for ConnSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

enum BoundedLine {
    Line(String),
    Eof,
    TooLong,
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<BoundedLine> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(BoundedLine::Eof);
            }
            return Ok(BoundedLine::Line(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = newline_pos + 1;
            if buf.len().saturating_add(take_len) > max_bytes {
                reader.consume(take_len);
                return Ok(BoundedLine::TooLong);
            }
            buf.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            return Ok(BoundedLine::Line(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        let chunk_len = available.len();
        if buf.len().saturating_add(chunk_len) > max_bytes {
            reader.consume(chunk_len);
            return Ok(BoundedLine::TooLong);
        }
        buf.extend_from_slice(available);
        reader.consume(chunk_len);
    }
}

fn write_json_error_response(
    client: &mut TcpStream,
    status_line: &str,
    code: &str,
    message: &str,
) -> io::Result<()> {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "code": code,
            "message": message,
        }
    })
    .to_string();
    write!(
        client,
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    )?;
    client.flush()
}

pub struct LocalApiTap {
    pub port: u16,
    pub anthropic_base_url: String,
    pub openai_base_url: String,
    pub gemini_base_url: String,
    pub openrouter_base_url: String,
    pub deepseek_base_url: String,
    pub xai_base_url: String,
    pub groq_base_url: String,
    stop: Arc<AtomicBool>,
    pool: UpstreamPool,
}

impl LocalApiTap {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.pool.lock() {
            guard.clear();
        }
    }
}

pub type TapCallback = Arc<dyn Fn(&str, &str, &str, &str, String) + Send + Sync + 'static>;

#[derive(Clone)]
struct UpstreamTargets {
    anthropic: String,
    openai: String,
    chatgpt: String,
    openai_explicit: bool,
    gemini: String,
    openrouter: String,
    deepseek: String,
    xai: String,
    groq: String,
    block_secrets: bool,
    redact_secrets: bool,
    pool: UpstreamPool,
}

fn spawn_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    active_conns: Arc<AtomicUsize>,
    upstreams: UpstreamTargets,
    engine: Arc<RuleEngine>,
    header_auditor: Arc<HeaderAuditor>,
    emit: TapCallback,
) {
    let _ = listener.set_nonblocking(true);
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let _ = stream.set_nonblocking(false);
                    let prev = active_conns.fetch_add(1, Ordering::AcqRel);
                    if prev >= MAX_CONCURRENT_TAP_CONNS {
                        active_conns.fetch_sub(1, Ordering::AcqRel);
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = write_json_error_response(
                            &mut stream,
                            "503 Service Unavailable",
                            "leaktap_too_many_connections",
                            "[leaktap] Too many concurrent local API tap connections.",
                        );
                        continue;
                    }
                    let slot_guard = ConnSlotGuard(Arc::clone(&active_conns));
                    let engine = Arc::clone(&engine);
                    let auditor = Arc::clone(&header_auditor);
                    let emit = Arc::clone(&emit);
                    let targets = upstreams.clone();
                    thread::spawn(move || {
                        let _guard = slot_guard;
                        let _ = handle_client(stream, &targets, &engine, &auditor, &emit);
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(15));
                }
                Err(_) => break,
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn start_local_api_tap(
    anthropic_upstream: String,
    openai_upstream: String,
    chatgpt_upstream: String,
    openai_explicit: bool,
    gemini_upstream: String,
    block_secrets: bool,
    engine: Arc<RuleEngine>,
    header_auditor: Arc<HeaderAuditor>,
    emit: TapCallback,
) -> io::Result<LocalApiTap> {
    start_local_api_tap_with_options(
        anthropic_upstream,
        openai_upstream,
        chatgpt_upstream,
        openai_explicit,
        gemini_upstream,
        block_secrets,
        false,
        engine,
        header_auditor,
        emit,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn start_local_api_tap_with_options(
    anthropic_upstream: String,
    openai_upstream: String,
    chatgpt_upstream: String,
    openai_explicit: bool,
    gemini_upstream: String,
    block_secrets: bool,
    redact_secrets: bool,
    engine: Arc<RuleEngine>,
    header_auditor: Arc<HeaderAuditor>,
    emit: TapCallback,
) -> io::Result<LocalApiTap> {
    let v4_listener = TcpListener::bind("127.0.0.1:0")?;
    let port = v4_listener.local_addr()?.port();

    let openrouter_upstream = std::env::var("LEAKTAP_UPSTREAM_OPENROUTER_URL")
        .or_else(|_| std::env::var("OPENROUTER_BASE_URL"))
        .unwrap_or_else(|_| "https://openrouter.ai/api/v1".to_string());
    let deepseek_upstream = std::env::var("LEAKTAP_UPSTREAM_DEEPSEEK_URL")
        .or_else(|_| std::env::var("DEEPSEEK_BASE_URL"))
        .unwrap_or_else(|_| "https://api.deepseek.com".to_string());
    let xai_upstream = std::env::var("LEAKTAP_UPSTREAM_XAI_URL")
        .or_else(|_| std::env::var("XAI_BASE_URL"))
        .unwrap_or_else(|_| "https://api.x.ai/v1".to_string());
    let groq_upstream = std::env::var("LEAKTAP_UPSTREAM_GROQ_URL")
        .or_else(|_| std::env::var("GROQ_BASE_URL"))
        .unwrap_or_else(|_| "https://api.groq.com".to_string());

    let stop = Arc::new(AtomicBool::new(false));
    let active_conns = Arc::new(AtomicUsize::new(0));
    let pool: UpstreamPool = Arc::new(Mutex::new(HashMap::new()));
    let upstreams = UpstreamTargets {
        anthropic: anthropic_upstream.trim_end_matches('/').to_string(),
        openai: openai_upstream.trim_end_matches('/').to_string(),
        chatgpt: chatgpt_upstream.trim_end_matches('/').to_string(),
        openai_explicit,
        gemini: gemini_upstream.trim_end_matches('/').to_string(),
        openrouter: openrouter_upstream.trim_end_matches('/').to_string(),
        deepseek: deepseek_upstream.trim_end_matches('/').to_string(),
        xai: xai_upstream.trim_end_matches('/').to_string(),
        groq: groq_upstream.trim_end_matches('/').to_string(),
        block_secrets,
        redact_secrets,
        pool: Arc::clone(&pool),
    };

    spawn_accept_loop(
        v4_listener,
        Arc::clone(&stop),
        Arc::clone(&active_conns),
        upstreams.clone(),
        Arc::clone(&engine),
        Arc::clone(&header_auditor),
        Arc::clone(&emit),
    );

    if let Ok(v6_listener) = TcpListener::bind(("[::1]", port)) {
        spawn_accept_loop(
            v6_listener,
            Arc::clone(&stop),
            active_conns,
            upstreams,
            engine,
            header_auditor,
            emit,
        );
    }

    Ok(LocalApiTap {
        port,
        anthropic_base_url: format!("http://127.0.0.1:{port}/_anthropic"),
        openai_base_url: format!("http://127.0.0.1:{port}/_openai"),
        gemini_base_url: format!("http://localhost:{port}/_gemini"),
        openrouter_base_url: format!("http://127.0.0.1:{port}/_openrouter"),
        deepseek_base_url: format!("http://127.0.0.1:{port}/_deepseek"),
        xai_base_url: format!("http://127.0.0.1:{port}/_xai"),
        groq_base_url: format!("http://127.0.0.1:{port}/_groq"),
        stop,
        pool,
    })
}

fn handle_client(
    mut client: TcpStream,
    upstreams: &UpstreamTargets,
    engine: &RuleEngine,
    auditor: &HeaderAuditor,
    emit: &TapCallback,
) -> io::Result<()> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
    let cloned = client.try_clone()?;
    let mut reader = BufReader::new(cloned);

    let request_line = match read_bounded_line(&mut reader, MAX_REQUEST_LINE_BYTES)? {
        BoundedLine::Eof => return Ok(()),
        BoundedLine::TooLong => {
            let _ = write_json_error_response(
                &mut client,
                "414 URI Too Long",
                "leaktap_uri_too_long",
                "[leaktap] Request line exceeds 16 KiB limit.",
            );
            return Ok(());
        }
        BoundedLine::Line(l) => l,
    };
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_string();
    let raw_path = parts[1].to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut seen_content_length: Option<usize> = None;
    let mut seen_transfer_encoding = false;
    let mut is_chunked = false;
    let mut content_encoding = String::new();
    let mut is_websocket_upgrade = false;
    let mut has_chatgpt_account_id = false;
    let mut total_header_bytes: usize = 0;
    let mut framing_error: Option<&'static str> = None;

    loop {
        let line = match read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES)? {
            BoundedLine::Eof => break,
            BoundedLine::TooLong => {
                let _ = write_json_error_response(
                    &mut client,
                    "431 Request Header Fields Too Large",
                    "leaktap_headers_too_large",
                    "[leaktap] Individual HTTP header exceeds 16 KiB limit.",
                );
                return Ok(());
            }
            BoundedLine::Line(l) => l,
        };
        if line == "\r\n" || line == "\n" {
            break;
        }
        total_header_bytes = total_header_bytes.saturating_add(line.len());
        if total_header_bytes > MAX_TOTAL_HEADER_BYTES || headers.len() >= MAX_HEADER_COUNT {
            let _ = write_json_error_response(
                &mut client,
                "431 Request Header Fields Too Large",
                "leaktap_headers_too_large",
                "[leaktap] HTTP headers exceed size or count limits.",
            );
            return Ok(());
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            framing_error = Some("obsolete folded HTTP header lines are not allowed");
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            framing_error = Some("malformed HTTP header line");
            continue;
        };
        let key = k.trim().to_string();
        if key.is_empty() || key.bytes().any(|b| b.is_ascii_whitespace()) {
            framing_error = Some("invalid HTTP header field name");
            continue;
        }
        let val = v.trim().to_string();
        if key.eq_ignore_ascii_case("content-length") {
            if seen_content_length.is_some() {
                framing_error = Some("duplicate Content-Length headers are not allowed");
            } else if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                framing_error = Some("invalid Content-Length header value");
            } else {
                match val.parse::<usize>() {
                    Ok(len) => seen_content_length = Some(len),
                    Err(_) => framing_error = Some("Content-Length value overflow"),
                }
            }
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            seen_transfer_encoding = true;
            let tokens: Vec<String> = val
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            if tokens.len() == 1 && tokens[0] == "chunked" && !is_chunked {
                is_chunked = true;
            } else {
                framing_error = Some("unsupported or duplicate Transfer-Encoding header");
            }
        } else if key.eq_ignore_ascii_case("content-encoding") {
            let enc_lc = val.to_ascii_lowercase();
            if !enc_lc.is_empty() {
                if content_encoding.is_empty() {
                    content_encoding = enc_lc;
                } else {
                    content_encoding.push_str(", ");
                    content_encoding.push_str(&enc_lc);
                }
            }
        } else if key.eq_ignore_ascii_case("upgrade") && val.eq_ignore_ascii_case("websocket") {
            is_websocket_upgrade = true;
        } else if key.eq_ignore_ascii_case("chatgpt-account-id") && !val.is_empty() {
            has_chatgpt_account_id = true;
        }
        headers.push((key, val));
    }

    if seen_transfer_encoding && seen_content_length.is_some() {
        framing_error =
            Some("simultaneous Transfer-Encoding and Content-Length headers are not allowed");
    }

    if let Some(reason) = framing_error {
        emit(
            "http",
            "framing_rejected",
            "http-invalid-framing",
            "HIGH",
            format!("Rejected ambiguous or malformed HTTP request ({reason})"),
        );
        let _ = write_json_error_response(
            &mut client,
            "400 Bad Request",
            "leaktap_invalid_framing",
            &format!("[leaktap] Invalid HTTP request framing: {reason}."),
        );
        return Ok(());
    }

    let content_length = seen_content_length.unwrap_or(0);

    if is_websocket_upgrade {
        let _ = write!(
            client,
            "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = client.flush();
        return Ok(());
    }

    const MAX_TAP_BODY_BYTES: usize = 32 * 1024 * 1024;
    const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

    if !is_chunked && content_length > MAX_TAP_BODY_BYTES {
        emit(
            "http-body",
            "payload_too_large",
            "tap-body-limit",
            "HIGH",
            format!(
                "Rejected oversized API request ({content_length} bytes > {MAX_TAP_BODY_BYTES} byte tap limit)"
            ),
        );
        let _ = write_json_error_response(
            &mut client,
            "413 Payload Too Large",
            "leaktap_payload_too_large",
            "[leaktap] Request body exceeds 32 MiB inspection limit.",
        );
        return Ok(());
    }

    let body = if is_chunked {
        match read_chunked_body(&mut reader, MAX_TAP_BODY_BYTES) {
            Ok(Some(b)) => b,
            Ok(None) => {
                emit(
                    "http-body",
                    "payload_too_large",
                    "tap-body-limit",
                    "HIGH",
                    format!(
                        "Rejected oversized chunked API request (> {MAX_TAP_BODY_BYTES} byte tap limit)"
                    ),
                );
                let _ = write_json_error_response(
                    &mut client,
                    "413 Payload Too Large",
                    "leaktap_payload_too_large",
                    "[leaktap] Chunked request body exceeds 32 MiB inspection limit.",
                );
                return Ok(());
            }
            Err(chunk_err) => {
                emit(
                    "http",
                    "framing_rejected",
                    "http-invalid-framing",
                    "HIGH",
                    format!("Rejected malformed chunked HTTP body ({chunk_err})"),
                );
                let _ = write_json_error_response(
                    &mut client,
                    "400 Bad Request",
                    "leaktap_invalid_framing",
                    "[leaktap] Malformed chunked request body.",
                );
                return Ok(());
            }
        }
    } else if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    let (provider, upstream_provider, mut target_url) =
        if let Some(rest) = raw_path.strip_prefix("/_anthropic") {
            (
                "anthropic",
                UpstreamProvider::Anthropic,
                join_upstream_path(&upstreams.anthropic, rest),
            )
        } else if let Some(rest) = raw_path.strip_prefix("/_openai") {
            if has_chatgpt_account_id && !upstreams.openai_explicit {
                let stripped = rest.strip_prefix("/v1").unwrap_or(rest);
                (
                    "openai",
                    UpstreamProvider::OpenAi,
                    join_upstream_path(&upstreams.chatgpt, stripped),
                )
            } else {
                (
                    "openai",
                    UpstreamProvider::OpenAi,
                    join_upstream_path(&upstreams.openai, rest),
                )
            }
        } else if let Some(rest) = raw_path.strip_prefix("/_gemini") {
            (
                "gemini",
                UpstreamProvider::Gemini,
                join_upstream_path(&upstreams.gemini, rest),
            )
        } else if let Some(rest) = raw_path.strip_prefix("/_openrouter") {
            (
                "openrouter",
                UpstreamProvider::OpenRouter,
                join_upstream_path(&upstreams.openrouter, rest),
            )
        } else if let Some(rest) = raw_path.strip_prefix("/_deepseek") {
            (
                "deepseek",
                UpstreamProvider::DeepSeek,
                join_upstream_path(&upstreams.deepseek, rest),
            )
        } else if let Some(rest) = raw_path.strip_prefix("/_xai") {
            (
                "xai",
                UpstreamProvider::Xai,
                join_upstream_path(&upstreams.xai, rest),
            )
        } else if let Some(rest) = raw_path.strip_prefix("/_groq") {
            (
                "groq",
                UpstreamProvider::Groq,
                join_upstream_path(&upstreams.groq, rest),
            )
        } else {
            let suffix = if raw_path.starts_with('/') {
                raw_path.as_str()
            } else {
                "/"
            };
            (
                "anthropic",
                UpstreamProvider::Anthropic,
                format!("{}{suffix}", upstreams.anthropic),
            )
        };

    emit(
        "http",
        "api_request",
        "api-call",
        "MEDIUM",
        format!(
            "API {method} -> {provider} ({}) [{} bytes]",
            strip_query(&target_url),
            body.len()
        ),
    );

    let mut blocked_summary: Option<(String, String, &'static str)> = None;
    let redact_active = upstreams.redact_secrets && !upstreams.block_secrets;
    let mut redacted_total: usize = 0;

    // 1. Audit outgoing request URL path and query string (exempting Gemini's auth `key=` parameter)
    let url_inspect_target = sanitize_request_path_for_scan(&raw_path, provider);
    if !url_inspect_target.is_empty() {
        let mut url_matches = engine.scan_text(&url_inspect_target);
        let decoded_url = percent_decode(&url_inspect_target);
        if decoded_url != url_inspect_target {
            let mut seen_fps: HashSet<(String, String)> = url_matches
                .iter()
                .map(|m| (m.rule_id.clone(), m.fingerprint.clone()))
                .collect();
            for m in engine.scan_text(&decoded_url) {
                if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                    url_matches.push(m);
                }
            }
        }
        let mut url_had_secret = false;
        for m in url_matches {
            if m.category == RuleCategory::Secret {
                url_had_secret = true;
            }
            if upstreams.block_secrets
                && m.category == RuleCategory::Secret
                && blocked_summary.is_none()
            {
                blocked_summary = Some((
                    m.rule_id.clone(),
                    format!("URL query/path {} ({})", m.rule_name, m.masked),
                    "leaktap_secret_blocked",
                ));
            }
            let kind = match m.category {
                RuleCategory::Secret => "secret_in_url",
                RuleCategory::Pii => "pii_in_url",
            };
            emit(
                "http-url",
                kind,
                &m.rule_id,
                m.severity.as_str(),
                format!(
                    "{} ({}) sent in outgoing {provider} API URL",
                    m.rule_name, m.masked
                ),
            );
        }
        if redact_active && url_had_secret {
            let (new_url, cnt) = redact_target_url_secrets(&target_url, provider, engine);
            if cnt > 0 {
                target_url = new_url;
                redacted_total += cnt;
            }
        }
    }

    // 2. Audit outgoing HTTP headers (`User-Agent` email leaks, hostname/OS user, cross-provider/leaked keys)
    for (k, v) in &mut headers {
        let mut header_had_secret_leak = false;
        for hf in auditor.inspect_header_for_provider(k, v, Some(upstream_provider), engine) {
            if hf.rule_id == "header-secret-leak" {
                header_had_secret_leak = true;
            }
            if upstreams.block_secrets
                && hf.rule_id == "header-secret-leak"
                && blocked_summary.is_none()
            {
                blocked_summary = Some((
                    hf.rule_id.to_string(),
                    format!("HTTP header `{k}` ({})", hf.detail),
                    "leaktap_secret_blocked",
                ));
            }
            emit(
                "http-header",
                "header_leak",
                hf.rule_id,
                hf.severity.as_str(),
                hf.detail,
            );
        }
        if redact_active && header_had_secret_leak {
            let (scrubbed_hdr, cnt) = redact_header_value_secrets(v, engine);
            *v = scrubbed_hdr;
            redacted_total += cnt;
        }
    }

    // 3. Audit outgoing request body (decompressing zstd, br, multi-member gzip + RFC 1952 headers, deflate,
    // multi-layer encodings, percent-encoded payloads, and deep JSON strings/keys)
    let mut decoded_body_override: Option<Vec<u8>> = None;
    if !body.is_empty() {
        match decompress_request_body(&body, &content_encoding, MAX_DECOMPRESSED_BYTES) {
            Ok((decoded, aux_metadata)) => {
                let inspect_bytes: &[u8] = decoded.as_deref().unwrap_or(&body);
                let body_text = String::from_utf8_lossy(inspect_bytes);
                let mut body_matches = engine.scan_text(&body_text);
                let mut seen_fps: HashSet<(String, String)> = body_matches
                    .iter()
                    .map(|m| (m.rule_id.clone(), m.fingerprint.clone()))
                    .collect();

                if !aux_metadata.is_empty() {
                    for m in engine.scan_text(&aux_metadata) {
                        if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                            body_matches.push(m);
                        }
                    }
                }

                if body_text.contains('%') {
                    let pct1 = percent_decode(&body_text);
                    if pct1 != body_text {
                        for m in engine.scan_text(&pct1) {
                            if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                                body_matches.push(m);
                            }
                        }
                        if pct1.contains('%') {
                            let pct2 = percent_decode(&pct1);
                            if pct2 != pct1 {
                                for m in engine.scan_text(&pct2) {
                                    if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                                        body_matches.push(m);
                                    }
                                }
                            }
                        }
                    }
                }

                let first_non_ws = inspect_bytes.iter().find(|b| !b.is_ascii_whitespace());
                let mut parsed_json_body: Option<serde_json::Value> = None;
                if matches!(first_non_ws, Some(b'{' | b'[')) {
                    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(inspect_bytes)
                    {
                        let mut flattened = String::with_capacity(inspect_bytes.len().min(65536));
                        collect_json_value_strings(&json_val, 0, &mut flattened);
                        for m in engine.scan_text(&flattened) {
                            if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                                body_matches.push(m);
                            }
                        }
                        if flattened.contains('%') {
                            let pct_flat = percent_decode(&flattened);
                            if pct_flat != flattened {
                                for m in engine.scan_text(&pct_flat) {
                                    if seen_fps.insert((m.rule_id.clone(), m.fingerprint.clone())) {
                                        body_matches.push(m);
                                    }
                                }
                            }
                        }
                        parsed_json_body = Some(json_val);
                    }
                }

                let mut body_had_secret = false;
                for m in body_matches {
                    if m.category == RuleCategory::Secret {
                        body_had_secret = true;
                    }
                    if upstreams.block_secrets
                        && m.category == RuleCategory::Secret
                        && blocked_summary.is_none()
                    {
                        blocked_summary = Some((
                            m.rule_id.clone(),
                            format!("{} ({})", m.rule_name, m.masked),
                            "leaktap_secret_blocked",
                        ));
                    }
                    let kind = match m.category {
                        RuleCategory::Secret => "secret_in_prompt",
                        RuleCategory::Pii => "pii_in_prompt",
                    };
                    emit(
                        "http-body",
                        kind,
                        &m.rule_id,
                        m.severity.as_str(),
                        format!(
                            "{} ({}) sent in outgoing {provider} API body",
                            m.rule_name, m.masked
                        ),
                    );
                }

                if redact_active && body_had_secret {
                    if let Some(mut json_doc) = parsed_json_body {
                        let cnt = redact_json_secrets_in_place(&mut json_doc, 0, engine);
                        if cnt > 0 {
                            if let Ok(redacted_bytes) = serde_json::to_vec(&json_doc) {
                                decoded_body_override = Some(redacted_bytes);
                                redacted_total += cnt;
                            } else {
                                decoded_body_override = decoded;
                            }
                        } else {
                            let (scrubbed_str, raw_cnt) = redact_text_secrets(&body_text, engine);
                            if raw_cnt > 0
                                && serde_json::from_str::<serde_json::Value>(&scrubbed_str).is_ok()
                            {
                                decoded_body_override = Some(scrubbed_str.into_bytes());
                                redacted_total += raw_cnt;
                            } else {
                                decoded_body_override = decoded;
                            }
                        }
                    } else {
                        let (scrubbed_str, cnt) = redact_text_secrets(&body_text, engine);
                        if cnt > 0 {
                            decoded_body_override = Some(scrubbed_str.into_bytes());
                            redacted_total += cnt;
                        } else {
                            decoded_body_override = decoded;
                        }
                    }
                } else {
                    decoded_body_override = decoded;
                }
            }
            Err(decode_err) => {
                let enforce_closed = upstreams.block_secrets || upstreams.redact_secrets;
                let sev = if enforce_closed { "CRITICAL" } else { "HIGH" };
                emit(
                    "http-body",
                    "uninspectable_body",
                    "uninspectable-content-encoding",
                    sev,
                    format!(
                        "Could not decompress `{content_encoding}` {provider} API body ({decode_err})"
                    ),
                );
                if enforce_closed && blocked_summary.is_none() {
                    blocked_summary = Some((
                        "uninspectable-content-encoding".to_string(),
                        format!(
                            "uninspectable Content-Encoding `{content_encoding}` ({decode_err})"
                        ),
                        "leaktap_uninspectable_payload",
                    ));
                }
            }
        }
    }

    if let Some((rule_id, summary, err_code)) = blocked_summary {
        emit(
            "http-body",
            "secret_blocked",
            &rule_id,
            "CRITICAL",
            format!("Blocked outgoing {provider} API request: {summary}"),
        );
        let err_json = serde_json::json!({
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "code": err_code,
                "message": format!(
                    "[leaktap] Blocked outgoing {provider} API request: {summary}. Remove or redact the secret before retrying (if it is already saved in local session history, run 'leaktap clean --apply' or start a new agent session so subsequent turns are not repeatedly blocked)."
                )
            }
        })
        .to_string();
        let _ = write!(
            client,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            err_json.len(),
            err_json
        );
        let _ = client.flush();
        return Ok(());
    }

    if redact_active && redacted_total > 0 {
        emit(
            "http-body",
            "secret_redacted",
            "secret-redacted",
            "HIGH",
            format!(
                "Redacted {redacted_total} secret(s) in-transit before forwarding {provider} API request"
            ),
        );
    }

    // 4. Forward exact inspected canonical plaintext upstream (eliminating compression smuggling differentials)
    let strip_content_encoding = decoded_body_override.is_some();
    let forward_body: &[u8] = decoded_body_override.as_deref().unwrap_or(&body);
    if let Err(err) = forward_upstream(
        &mut client,
        &method,
        &target_url,
        &headers,
        forward_body,
        strip_content_encoding,
        &upstreams.pool,
    ) {
        let msg = format!("{{\"error\":\"leaktap upstream transport error: {err}\"}}");
        let _ = write!(
            client,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            msg.len(),
            msg
        );
        let _ = client.flush();
    }

    Ok(())
}

struct ParsedUrl {
    is_https: bool,
    host: String,
    port: u16,
    origin_target: String,
}

fn parse_target_url(url: &str) -> io::Result<ParsedUrl> {
    let (scheme, after_scheme) = url
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing URL scheme"))?;
    let is_https = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported URL scheme",
            ))
        }
    };
    let default_port = if is_https { 443 } else { 80 };
    let (authority, path_part) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (h, after_bracket) = rest
            .split_once(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 host"))?;
        let p = after_bracket
            .strip_prefix(':')
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(default_port);
        (h.to_string(), p)
    } else if let Some((h, p_str)) = host_port.rsplit_once(':') {
        let p = p_str.parse::<u16>().unwrap_or(default_port);
        (h.to_string(), p)
    } else {
        (host_port.to_string(), default_port)
    };

    Ok(ParsedUrl {
        is_https,
        host,
        port,
        origin_target: path_part.to_string(),
    })
}

struct ProxyConfig {
    host: String,
    port: u16,
    basic_auth: Option<String>,
}

fn parse_proxy_url(raw: &str) -> Option<ProxyConfig> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let after_scheme = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, rest)| rest)
        .split('/')
        .next()?;
    let (creds, host_port) = match after_scheme.rsplit_once('@') {
        Some((c, hp)) => (Some(c), hp),
        None => (None, after_scheme),
    };
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (h, rem) = rest.split_once(']')?;
        let p = rem
            .strip_prefix(':')
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(8080);
        (h.to_string(), p)
    } else if let Some((h, p_str)) = host_port.rsplit_once(':') {
        (h.to_string(), p_str.parse::<u16>().ok()?)
    } else {
        (host_port.to_string(), 8080)
    };
    if host.is_empty() {
        return None;
    }
    let basic_auth = creds.map(|c| {
        let decoded = percent_decode(c);
        base64_encode(decoded.as_bytes())
    });
    Some(ProxyConfig {
        host,
        port,
        basic_auth,
    })
}

enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl UpstreamStream {
    fn tcp_ref(&self) -> &TcpStream {
        match self {
            Self::Plain(s) => s,
            Self::Tls(s) => s.get_ref(),
        }
    }

    fn is_stale_or_dirty(&self) -> bool {
        let is_plain = matches!(self, Self::Plain(_));
        let tcp = self.tcp_ref();
        if tcp.set_nonblocking(true).is_err() {
            return true;
        }
        let mut probe = [0u8; 1];
        let stale = match tcp.peek(&mut probe) {
            Ok(0) => true,
            Ok(_) => is_plain,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        };
        let _ = tcp.set_nonblocking(false);
        stale
    }
}

impl Read for UpstreamStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => match s.read(buf) {
                Ok(n) => Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
                Err(e) => Err(e),
            },
        }
    }
}

impl Write for UpstreamStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

fn take_pooled_upstream(pool: &UpstreamPool, key: &PoolKey) -> Option<BufReader<UpstreamStream>> {
    loop {
        let cand = {
            let mut map = pool.lock().ok()?;
            let queue = map.get_mut(key)?;
            let mut found = None;
            while let Some(entry) = queue.pop_back() {
                if entry.parked_at.elapsed() < IDLE_CONN_TTL {
                    found = Some(entry.reader);
                    break;
                }
            }
            if queue.is_empty() {
                map.remove(key);
            }
            found
        }?;
        if cand.buffer().is_empty() && !cand.get_ref().is_stale_or_dirty() {
            return Some(cand);
        }
    }
}

fn return_pooled_upstream(pool: &UpstreamPool, key: PoolKey, reader: BufReader<UpstreamStream>) {
    if !reader.buffer().is_empty() || reader.get_ref().is_stale_or_dirty() {
        return;
    }
    let Ok(mut map) = pool.lock() else {
        return;
    };
    map.retain(|_, q| {
        q.retain(|c| c.parked_at.elapsed() < IDLE_CONN_TTL);
        !q.is_empty()
    });
    let total_idle: usize = map.values().map(VecDeque::len).sum();
    if total_idle >= MAX_TOTAL_IDLE_CONNS {
        return;
    }
    let queue = map.entry(key).or_default();
    while queue.len() >= MAX_IDLE_CONNS_PER_ORIGIN {
        queue.pop_front();
    }
    queue.push_back(IdleUpstreamConn {
        reader,
        parked_at: Instant::now(),
    });
}

fn connect_tcp_timeout(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(300)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(60)));
                return Ok(s);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS lookup empty")))
}

fn open_fresh_upstream(
    parsed: &ParsedUrl,
    proxy: &Option<ProxyConfig>,
    timeout: Duration,
) -> io::Result<BufReader<UpstreamStream>> {
    let stream = match (proxy, parsed.is_https) {
        (Some(p), true) => {
            let mut tcp = connect_tcp_timeout(&p.host, p.port, timeout)?;
            let authority = if parsed.host.contains(':') {
                format!("[{}]:{}", parsed.host, parsed.port)
            } else {
                format!("{}:{}", parsed.host, parsed.port)
            };
            write!(tcp, "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n")?;
            if let Some(ref auth) = p.basic_auth {
                write!(tcp, "Proxy-Authorization: Basic {auth}\r\n")?;
            }
            write!(tcp, "\r\n")?;
            tcp.flush()?;

            let mut connect_reader = BufReader::new(tcp);
            let status_line = match read_bounded_line(&mut connect_reader, MAX_HEADER_LINE_BYTES)? {
                BoundedLine::Line(l) => l,
                BoundedLine::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "proxy closed during CONNECT",
                    ))
                }
                BoundedLine::TooLong => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "proxy CONNECT status line too long",
                    ))
                }
            };
            let code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            for _ in 0..MAX_HEADER_COUNT {
                match read_bounded_line(&mut connect_reader, MAX_HEADER_LINE_BYTES)? {
                    BoundedLine::Eof => break,
                    BoundedLine::TooLong => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "proxy CONNECT header too long",
                        ))
                    }
                    BoundedLine::Line(hdr) => {
                        if hdr == "\r\n" || hdr == "\n" {
                            break;
                        }
                    }
                }
            }
            if !(200..300).contains(&code) {
                return Err(io::Error::other(format!(
                    "proxy CONNECT returned HTTP {code}"
                )));
            }
            let tcp = connect_reader.into_inner();
            let sni = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let tls_conn = rustls::ClientConnection::new(shared_tls_config(), sni)
                .map_err(|e| io::Error::other(e.to_string()))?;
            UpstreamStream::Tls(Box::new(rustls::StreamOwned::new(tls_conn, tcp)))
        }
        (Some(p), false) => {
            let tcp = connect_tcp_timeout(&p.host, p.port, timeout)?;
            UpstreamStream::Plain(tcp)
        }
        (None, true) => {
            let tcp = connect_tcp_timeout(&parsed.host, parsed.port, timeout)?;
            let sni = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let tls_conn = rustls::ClientConnection::new(shared_tls_config(), sni)
                .map_err(|e| io::Error::other(e.to_string()))?;
            UpstreamStream::Tls(Box::new(rustls::StreamOwned::new(tls_conn, tcp)))
        }
        (None, false) => {
            let tcp = connect_tcp_timeout(&parsed.host, parsed.port, timeout)?;
            UpstreamStream::Plain(tcp)
        }
    };
    Ok(BufReader::new(stream))
}

#[allow(clippy::too_many_arguments)]
fn forward_upstream(
    client: &mut TcpStream,
    method: &str,
    target_url: &str,
    headers: &[(String, String)],
    body: &[u8],
    strip_content_encoding: bool,
    pool: &UpstreamPool,
) -> io::Result<()> {
    let _ = client.set_write_timeout(Some(Duration::from_secs(300)));
    let parsed = parse_target_url(target_url)?;
    let proxy = proxy_for_url(target_url, &parsed.host);
    let timeout = Duration::from_secs(15);

    let (request_target, extra_proxy_auth, proxy_tag, can_pool_origin) =
        match (&proxy, parsed.is_https) {
            (Some(p), true) => (
                parsed.origin_target.clone(),
                None,
                format!("connect:{}:{}", p.host.to_ascii_lowercase(), p.port),
                true,
            ),
            (Some(p), false) => (
                target_url.to_string(),
                p.basic_auth.clone(),
                format!("http:{}:{}", p.host.to_ascii_lowercase(), p.port),
                false,
            ),
            (None, _) => (parsed.origin_target.clone(), None, String::new(), true),
        };
    let pool_key = PoolKey {
        is_https: parsed.is_https,
        host: parsed.host.to_ascii_lowercase(),
        port: parsed.port,
        proxy_tag,
    };

    let default_port = if parsed.is_https { 443 } else { 80 };
    let host_hdr = if parsed.host.contains(':') {
        if parsed.port == default_port {
            format!("[{}]", parsed.host)
        } else {
            format!("[{}]:{}", parsed.host, parsed.port)
        }
    } else if parsed.port == default_port {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let mut req_buf = Vec::with_capacity(512 + body.len());
    write!(req_buf, "{method} {request_target} HTTP/1.1\r\n")?;
    write!(req_buf, "Host: {host_hdr}\r\n")?;
    if let Some(auth) = extra_proxy_auth {
        write!(req_buf, "Proxy-Authorization: Basic {auth}\r\n")?;
    }
    let mut merged_content_encoding = String::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-encoding") {
            if !strip_content_encoding && !v.trim().is_empty() {
                if merged_content_encoding.is_empty() {
                    merged_content_encoding.push_str(v.trim());
                } else {
                    merged_content_encoding.push_str(", ");
                    merged_content_encoding.push_str(v.trim());
                }
            }
            continue;
        }
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "host"
                | "content-length"
                | "connection"
                | "proxy-connection"
                | "transfer-encoding"
                | "accept-encoding"
        ) {
            continue;
        }
        write!(req_buf, "{k}: {v}\r\n")?;
    }
    if !strip_content_encoding && !merged_content_encoding.is_empty() {
        write!(req_buf, "Content-Encoding: {merged_content_encoding}\r\n")?;
    }
    write!(req_buf, "Accept-Encoding: identity\r\n")?;
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        write!(req_buf, "Content-Length: {}\r\n", body.len())?;
    }
    if can_pool_origin {
        write!(req_buf, "Connection: keep-alive\r\n\r\n")?;
    } else {
        write!(req_buf, "Connection: close\r\n\r\n")?;
    }
    req_buf.extend_from_slice(body);

    let send_and_read_status =
        |reader: &mut BufReader<UpstreamStream>, payload: &[u8]| -> io::Result<BoundedLine> {
            reader.get_mut().write_all(payload)?;
            reader.get_mut().flush()?;
            read_bounded_line(reader, MAX_HEADER_LINE_BYTES)
        };

    let (mut up_reader, resp_status) = if can_pool_origin {
        if let Some(mut pooled) = take_pooled_upstream(pool, &pool_key) {
            match send_and_read_status(&mut pooled, &req_buf) {
                Ok(BoundedLine::Line(line)) => (pooled, line),
                Ok(BoundedLine::TooLong) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream status line exceeds limit",
                    ));
                }
                Ok(BoundedLine::Eof) | Err(_) => {
                    let mut fresh = open_fresh_upstream(&parsed, &proxy, timeout)?;
                    match send_and_read_status(&mut fresh, &req_buf)? {
                        BoundedLine::Line(l) => (fresh, l),
                        BoundedLine::Eof => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "upstream closed before sending status line",
                            ))
                        }
                        BoundedLine::TooLong => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "upstream status line exceeds limit",
                            ))
                        }
                    }
                }
            }
        } else {
            let mut fresh = open_fresh_upstream(&parsed, &proxy, timeout)?;
            match send_and_read_status(&mut fresh, &req_buf)? {
                BoundedLine::Line(l) => (fresh, l),
                BoundedLine::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream closed before sending status line",
                    ))
                }
                BoundedLine::TooLong => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream status line exceeds limit",
                    ))
                }
            }
        }
    } else {
        let mut fresh = open_fresh_upstream(&parsed, &proxy, timeout)?;
        match send_and_read_status(&mut fresh, &req_buf)? {
            BoundedLine::Line(l) => (fresh, l),
            BoundedLine::Eof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed before sending status line",
                ))
            }
            BoundedLine::TooLong => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream status line exceeds limit",
                ))
            }
        }
    };
    client.write_all(resp_status.as_bytes())?;

    let status_code = resp_status
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let is_http_10 = resp_status.starts_with("HTTP/1.0");

    let mut resp_chunked = false;
    let mut resp_content_length: Option<usize> = None;
    let mut resp_conn_close = false;
    let mut resp_explicit_keep_alive = false;
    let mut headers_terminated_cleanly = false;
    for _ in 0..(MAX_HEADER_COUNT * 2) {
        let line = match read_bounded_line(&mut up_reader, MAX_HEADER_LINE_BYTES * 2)? {
            BoundedLine::Eof => break,
            BoundedLine::TooLong => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream response header exceeds limit",
                ))
            }
            BoundedLine::Line(l) => l,
        };
        if line == "\r\n" || line == "\n" {
            headers_terminated_cleanly = true;
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key_lc = k.trim().to_ascii_lowercase();
            let val_trim = v.trim();
            if key_lc == "connection" || key_lc == "proxy-connection" {
                for tok in val_trim.split(',').map(str::trim) {
                    if tok.eq_ignore_ascii_case("close") {
                        resp_conn_close = true;
                    } else if tok.eq_ignore_ascii_case("keep-alive") {
                        resp_explicit_keep_alive = true;
                    }
                }
                continue;
            }
            if key_lc == "keep-alive" {
                continue;
            }
            if key_lc == "transfer-encoding" && val_trim.to_ascii_lowercase().contains("chunked") {
                resp_chunked = true;
            }
            if key_lc == "content-length" {
                resp_content_length = val_trim.parse::<usize>().ok();
            }
        }
        client.write_all(line.as_bytes())?;
    }
    write!(client, "Connection: close\r\n\r\n")?;
    client.flush()?;

    let body_complete_and_framed =
        if method.eq_ignore_ascii_case("HEAD") || matches!(status_code, 204 | 304) {
            true
        } else if resp_chunked {
            let mut clean_chunked = false;
            let mut premature_eof = false;
            loop {
                let mut size_line = String::new();
                if up_reader.read_line(&mut size_line)? == 0 {
                    break;
                }
                client.write_all(size_line.as_bytes())?;
                let hex = size_line.trim().split(';').next().unwrap_or("0").trim();
                let chunk_len = usize::from_str_radix(hex, 16).unwrap_or(0);
                if chunk_len == 0 {
                    loop {
                        let mut trailer = String::new();
                        let n = up_reader.read_line(&mut trailer)?;
                        if n == 0 {
                            break;
                        }
                        client.write_all(trailer.as_bytes())?;
                        if trailer == "\r\n" || trailer == "\n" {
                            clean_chunked = !premature_eof;
                            break;
                        }
                    }
                    client.flush()?;
                    break;
                }
                let mut remaining = chunk_len + 2; // chunk bytes + trailing CRLF
                let mut buf = [0u8; 8192];
                while remaining > 0 {
                    let to_read = remaining.min(buf.len());
                    let n = up_reader.read(&mut buf[..to_read])?;
                    if n == 0 {
                        premature_eof = true;
                        break;
                    }
                    client.write_all(&buf[..n])?;
                    remaining -= n;
                }
                client.flush()?;
                if premature_eof {
                    break;
                }
            }
            clean_chunked
        } else if let Some(mut remaining) = resp_content_length {
            let mut buf = [0u8; 8192];
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = up_reader.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n])?;
                client.flush()?;
                remaining -= n;
            }
            remaining == 0
        } else {
            let mut buf = [0u8; 8192];
            loop {
                let n = up_reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n])?;
                client.flush()?;
            }
            false
        };

    let allow_keep_alive = can_pool_origin
        && headers_terminated_cleanly
        && status_code >= 200
        && !resp_conn_close
        && (!is_http_10 || resp_explicit_keep_alive)
        && body_complete_and_framed;
    if allow_keep_alive {
        return_pooled_upstream(pool, pool_key, up_reader);
    }

    Ok(())
}

fn shared_tls_config() -> Arc<rustls::ClientConfig> {
    static TLS_CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    TLS_CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            root_store.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            let config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .expect("ring supports TLS 1.2 and TLS 1.3")
            .with_root_certificates(root_store)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

fn proxy_for_url(target_url: &str, host: &str) -> Option<ProxyConfig> {
    if is_loopback_or_no_proxy(host) {
        return None;
    }

    let env_keys: &[&str] = if target_url.starts_with("https://") {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };

    for key in env_keys {
        if let Ok(val) = std::env::var(key) {
            if let Some(proxy) = parse_proxy_url(&val) {
                return Some(proxy);
            }
        }
    }
    None
}

fn is_loopback_or_no_proxy(host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    if matches!(host_lc.as_str(), "localhost" | "127.0.0.1" | "::1") || host_lc.starts_with("127.")
    {
        return true;
    }

    for key in ["NO_PROXY", "no_proxy"] {
        if let Ok(raw) = std::env::var(key) {
            for entry in raw.split(',') {
                let pat = entry.trim().to_ascii_lowercase();
                if pat.is_empty() {
                    continue;
                }
                if pat == "*" {
                    return true;
                }
                let pat_host = pat.split(':').next().unwrap_or(&pat);
                if host_lc == pat_host {
                    return true;
                }
                let suffix = pat_host.strip_prefix('.').unwrap_or(pat_host);
                if !suffix.is_empty() && host_lc.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            }
        }
    }
    false
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn read_chunked_body<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let size_line = match read_bounded_line(reader, 4096)? {
            BoundedLine::Eof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in chunked body",
                ))
            }
            BoundedLine::TooLong => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk size line exceeds 4 KiB",
                ))
            }
            BoundedLine::Line(l) => l,
        };
        let hex = size_line.trim().split(';').next().unwrap_or("").trim();
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hexadecimal chunk size",
            ));
        }
        let chunk_len = usize::from_str_radix(hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        if chunk_len == 0 {
            for _ in 0..32 {
                match read_bounded_line(reader, MAX_HEADER_LINE_BYTES)? {
                    BoundedLine::Eof => break,
                    BoundedLine::TooLong => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk trailer line too long",
                        ))
                    }
                    BoundedLine::Line(trailer) => {
                        if trailer == "\r\n" || trailer == "\n" {
                            break;
                        }
                    }
                }
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > max_bytes {
            return Ok(None);
        }
        let mut buf = vec![0u8; chunk_len];
        reader.read_exact(&mut buf)?;
        out.extend_from_slice(&buf);
        let crlf_line = match read_bounded_line(reader, 4)? {
            BoundedLine::Line(l) => l,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing CRLF after chunk payload",
                ))
            }
        };
        if crlf_line != "\r\n" && crlf_line != "\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk boundary delimiter",
            ));
        }
    }
    Ok(Some(out))
}

fn decompress_request_body(
    compressed: &[u8],
    content_encoding: &str,
    max_bytes: u64,
) -> Result<(Option<Vec<u8>>, String), String> {
    let layers: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("identity"))
        .collect();

    if layers.is_empty() {
        return Ok((None, String::new()));
    }
    if layers.len() > 4 {
        return Err("more than 4 nested Content-Encoding layers".to_string());
    }

    let mut current: Vec<u8> = compressed.to_vec();
    let mut aux_metadata = String::new();
    // HTTP Content-Encoding is applied in order; peel in reverse order (`deflate, gzip` -> `gzip` then `deflate`)
    for enc_raw in layers.into_iter().rev() {
        let enc = enc_raw.to_ascii_lowercase();
        current = decode_single_layer(&current, &enc, max_bytes, &mut aux_metadata)?;
    }

    Ok((Some(current), aux_metadata))
}

fn decode_single_layer(
    input: &[u8],
    enc: &str,
    max_bytes: u64,
    aux_metadata: &mut String,
) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let cap = max_bytes.saturating_add(1);
    let mut out = Vec::new();

    match enc {
        "br" => {
            let mut available_in = input.len();
            let mut input_offset = 0usize;
            let mut output_buf = [0u8; 8192];
            while available_in > 0 {
                let prev_avail = available_in;
                let mut state = brotli::BrotliState::new(
                    brotli::HeapAlloc::default(),
                    brotli::HeapAlloc::default(),
                    brotli::HeapAlloc::default(),
                );
                loop {
                    let mut available_out = output_buf.len();
                    let mut output_offset = 0usize;
                    let mut total_out = 0usize;
                    let res = brotli::BrotliDecompressStream(
                        &mut available_in,
                        &mut input_offset,
                        input,
                        &mut available_out,
                        &mut output_offset,
                        &mut output_buf,
                        &mut total_out,
                        &mut state,
                    );
                    if output_offset > 0 {
                        out.extend_from_slice(&output_buf[..output_offset]);
                    }
                    if out.len() as u64 > max_bytes {
                        return Err(format!(
                            "decompressed payload exceeds {} MiB limit",
                            max_bytes / (1024 * 1024)
                        ));
                    }
                    match res {
                        brotli::BrotliResult::ResultSuccess => break,
                        brotli::BrotliResult::NeedsMoreOutput => continue,
                        brotli::BrotliResult::NeedsMoreInput => {
                            return Err(
                                "truncated brotli stream or trailing unconsumed bytes".to_string()
                            );
                        }
                        brotli::BrotliResult::ResultFailure => {
                            return Err(
                                "invalid brotli stream or trailing unconsumed bytes".to_string()
                            );
                        }
                    }
                }
                if available_in == prev_avail {
                    return Err("trailing unconsumed bytes after brotli stream".to_string());
                }
            }
        }
        "zstd" => {
            let mut slice: &[u8] = input;
            let mut dec = ruzstd::decoding::StreamingDecoder::new(&mut slice)
                .map_err(|e| format!("invalid zstd stream: {e}"))?;
            (&mut dec)
                .take(cap)
                .read_to_end(&mut out)
                .map_err(|e| format!("corrupt zstd frame: {e}"))?;
            if (out.len() as u64) <= max_bytes && !slice.is_empty() {
                return Err(format!(
                    "zstd payload contains {} trailing unconsumed non-zstd byte(s)",
                    slice.len()
                ));
            }
        }
        "gzip" | "x-gzip" => {
            // Decode each concatenated RFC 1952 gzip member individually via `bufread::GzDecoder`
            // so we extract `FEXTRA` / `FNAME` / `FCOMMENT` headers AND reject any trailing non-gzip bytes.
            let mut slice: &[u8] = input;
            while !slice.is_empty() {
                let prev_len = slice.len();
                let rem_cap = cap.saturating_sub(out.len() as u64);
                let mut dec = GzDecoder::new(&mut slice);
                (&mut dec)
                    .take(rem_cap)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("invalid gzip stream: {e}"))?;
                if let Some(hdr) = dec.header() {
                    if let Some(extra) = hdr.extra() {
                        aux_metadata.push_str(&String::from_utf8_lossy(extra));
                        aux_metadata.push('\n');
                    }
                    if let Some(fname) = hdr.filename() {
                        aux_metadata.push_str(&String::from_utf8_lossy(fname));
                        aux_metadata.push('\n');
                    }
                    if let Some(comment) = hdr.comment() {
                        aux_metadata.push_str(&String::from_utf8_lossy(comment));
                        aux_metadata.push('\n');
                    }
                }
                if out.len() as u64 > max_bytes {
                    break;
                }
                if slice.len() == prev_len {
                    return Err("trailing unconsumed bytes after gzip stream".to_string());
                }
            }
        }
        "deflate" => {
            let mut zlib_slice: &[u8] = input;
            let zlib_ok = {
                let mut dec = ZlibDecoder::new(&mut zlib_slice);
                (&mut dec).take(cap).read_to_end(&mut out).is_ok()
            };
            if zlib_ok {
                if (out.len() as u64) <= max_bytes && !zlib_slice.is_empty() {
                    return Err("trailing unconsumed bytes after zlib deflate stream".to_string());
                }
            } else {
                out.clear();
                let mut def_slice: &[u8] = input;
                let mut dec = DeflateDecoder::new(&mut def_slice);
                (&mut dec)
                    .take(cap)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("invalid deflate stream: {e}"))?;
                if (out.len() as u64) <= max_bytes && !def_slice.is_empty() {
                    return Err("trailing unconsumed bytes after raw deflate stream".to_string());
                }
            }
        }
        other => {
            return Err(format!("unsupported Content-Encoding `{other}`"));
        }
    }

    if out.len() as u64 > max_bytes {
        return Err(format!(
            "decompressed payload exceeds {} MiB limit",
            max_bytes / (1024 * 1024)
        ));
    }

    Ok(out)
}

fn join_upstream_path(base: &str, rest: &str) -> String {
    if rest.is_empty() {
        return format!("{base}/");
    }
    let mut trimmed_base = base;
    for prefix in ["/api/v1", "/openai/v1", "/v1"] {
        if trimmed_base.ends_with(prefix)
            && (rest == prefix
                || rest.starts_with(&format!("{prefix}/"))
                || rest.starts_with(&format!("{prefix}?")))
        {
            trimmed_base = trimmed_base.strip_suffix(prefix).unwrap_or(trimmed_base);
            break;
        }
    }
    if rest.starts_with('/') {
        format!("{trimmed_base}{rest}")
    } else {
        format!("{trimmed_base}/{rest}")
    }
}

fn sanitize_request_path_for_scan(raw_path: &str, provider: &str) -> String {
    let stripped = raw_path
        .strip_prefix("/_anthropic")
        .or_else(|| raw_path.strip_prefix("/_openai"))
        .or_else(|| raw_path.strip_prefix("/_gemini"))
        .or_else(|| raw_path.strip_prefix("/_openrouter"))
        .or_else(|| raw_path.strip_prefix("/_deepseek"))
        .or_else(|| raw_path.strip_prefix("/_xai"))
        .or_else(|| raw_path.strip_prefix("/_groq"))
        .unwrap_or(raw_path);
    if provider != "gemini" {
        return stripped.to_string();
    }
    let Some((path_only, query)) = stripped.split_once('?') else {
        return stripped.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let Some((k, v)) = pair.split_once('=') else {
                return true;
            };
            if !k.eq_ignore_ascii_case("key") {
                return true;
            }
            // Only exempt legitimate Google Gemini API keys (`AIza` + `[A-Za-z0-9_-]` chars)
            let decoded_v = percent_decode(v);
            let tv = decoded_v.trim();
            !(tv.starts_with("AIza")
                && (35..=49).contains(&tv.len())
                && tv
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        })
        .collect();
    if kept.is_empty() {
        path_only.to_string()
    } else {
        format!("{path_only}?{}", kept.join("&"))
    }
}

fn redact_text_secrets(input: &str, engine: &RuleEngine) -> (String, usize) {
    let hints = crate::rules::DocHints::from_text(input);
    let matches: Vec<_> = engine
        .scan_text_with_hints(input, None, hints)
        .into_iter()
        .filter(|m| m.category == RuleCategory::Secret)
        .collect();
    if !matches.is_empty() {
        let mut out = input.to_string();
        let mut count = 0usize;
        for m in matches.iter().rev() {
            if m.end <= out.len() && out.is_char_boundary(m.start) && out.is_char_boundary(m.end) {
                let repl = crate::rules::redact_replacement(&m.rule_id, &out[m.start..m.end]);
                out.replace_range(m.start..m.end, &repl);
                count += 1;
            }
        }
        if count > 0 {
            return (out, count);
        }
    }
    if input.contains('%') {
        let pct = percent_decode(input);
        if pct != input {
            let pct_hints = crate::rules::DocHints::from_text(&pct);
            let pct_matches: Vec<_> = engine
                .scan_text_with_hints(&pct, None, pct_hints)
                .into_iter()
                .filter(|m| m.category == RuleCategory::Secret)
                .collect();
            if !pct_matches.is_empty() {
                let mut out = pct;
                let mut count = 0usize;
                for m in pct_matches.iter().rev() {
                    if m.end <= out.len()
                        && out.is_char_boundary(m.start)
                        && out.is_char_boundary(m.end)
                    {
                        let repl =
                            crate::rules::redact_replacement(&m.rule_id, &out[m.start..m.end]);
                        out.replace_range(m.start..m.end, &repl);
                        count += 1;
                    }
                }
                if count > 0 {
                    return (out, count);
                }
            }
        }
    }
    (input.to_string(), 0)
}

fn redact_header_value_secrets(val: &str, engine: &RuleEngine) -> (String, usize) {
    let (scrubbed, cnt) = redact_text_secrets(val, engine);
    if cnt > 0 {
        return (scrubbed, cnt);
    }
    let trimmed = val.trim();
    if let Some(rest) = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
    {
        if !rest.trim().is_empty() {
            return ("Bearer [REDACTED:header-secret-leak]".to_string(), 1);
        }
    }
    ("[REDACTED:header-secret-leak]".to_string(), 1)
}

fn redact_target_url_secrets(
    target_url: &str,
    provider: &str,
    engine: &RuleEngine,
) -> (String, usize) {
    let Some(scheme_sep) = target_url.find("://") else {
        return (target_url.to_string(), 0);
    };
    let after_scheme = &target_url[scheme_sep + 3..];
    let Some(path_idx) = after_scheme.find('/') else {
        return (target_url.to_string(), 0);
    };
    let origin = &target_url[..scheme_sep + 3 + path_idx];
    let path_and_query = &after_scheme[path_idx..];

    if provider == "gemini" {
        if let Some((path_only, query)) = path_and_query.split_once('?') {
            let (new_path, mut total) = redact_text_secrets(path_only, engine);
            let mut new_pairs: Vec<String> = Vec::new();
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    let decoded_v = percent_decode(v);
                    let tv = decoded_v.trim();
                    let is_legit_gemini_key = k.eq_ignore_ascii_case("key")
                        && tv.starts_with("AIza")
                        && (35..=49).contains(&tv.len())
                        && tv
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                    if is_legit_gemini_key {
                        new_pairs.push(pair.to_string());
                        continue;
                    }
                    let (sv, c) = redact_text_secrets(v, engine);
                    total += c;
                    new_pairs.push(format!("{k}={sv}"));
                } else {
                    let (sp, c) = redact_text_secrets(pair, engine);
                    total += c;
                    new_pairs.push(sp);
                }
            }
            if total > 0 {
                return (format!("{origin}{new_path}?{}", new_pairs.join("&")), total);
            }
            return (target_url.to_string(), 0);
        }
    }

    let (scrubbed_pq, cnt) = redact_text_secrets(path_and_query, engine);
    if cnt > 0 {
        (format!("{origin}{scrubbed_pq}"), cnt)
    } else {
        (target_url.to_string(), 0)
    }
}

fn redact_json_secrets_in_place(
    val: &mut serde_json::Value,
    depth: usize,
    engine: &RuleEngine,
) -> usize {
    if depth > 64 {
        return 0;
    }
    match val {
        serde_json::Value::String(s) => {
            let mut count = 0usize;
            if depth <= 24 {
                let first_non_ws = s.as_bytes().iter().find(|b| !b.is_ascii_whitespace());
                if matches!(first_non_ws, Some(b'{' | b'[')) {
                    if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(s) {
                        let inner_cnt = redact_json_secrets_in_place(&mut inner, depth + 1, engine);
                        if inner_cnt > 0 {
                            if let Ok(reencoded) = serde_json::to_string(&inner) {
                                *s = reencoded;
                                count += inner_cnt;
                            }
                        }
                    }
                }
            }
            let (scrubbed, direct_cnt) = redact_text_secrets(s, engine);
            if direct_cnt > 0 {
                *s = scrubbed;
                count += direct_cnt;
            }
            count
        }
        serde_json::Value::Array(arr) => arr
            .iter_mut()
            .map(|item| redact_json_secrets_in_place(item, depth + 1, engine))
            .sum(),
        serde_json::Value::Object(map) => {
            let mut count = 0usize;
            let is_gcp_sa_obj = map
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|t| t == "service_account")
                || map
                    .get("client_email")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|e| e.contains(".iam.gserviceaccount.com"));
            if is_gcp_sa_obj {
                if let Some(serde_json::Value::String(pk_id)) = map.get_mut("private_key_id") {
                    let probe = format!("\"private_key_id\": \"{pk_id}\"");
                    if engine
                        .scan_text_with_doc_hint(&probe, None, true)
                        .iter()
                        .any(|m| m.rule_id == "gcp-service-account-key")
                    {
                        *pk_id = crate::rules::redact_replacement("gcp-service-account-key", pk_id);
                        count += 1;
                    }
                }
            }
            let kty = map
                .get("kty")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let has_d = map.contains_key("d");
            if matches!(kty.as_str(), "RSA" | "EC" | "OKP" | "oct") {
                let jwk_hints = crate::rules::DocHints {
                    has_jwk_asymmetric_kty: matches!(kty.as_str(), "RSA" | "EC" | "OKP"),
                    has_jwk_d_param: has_d,
                    has_jwk_oct_kty: kty == "oct",
                    ..Default::default()
                };
                for jwk_field in ["d", "p", "q", "dp", "dq", "qi", "k"] {
                    if let Some(serde_json::Value::String(secret_val)) = map.get_mut(jwk_field) {
                        let probe = format!("\"{jwk_field}\": \"{secret_val}\"");
                        if engine
                            .scan_text_with_hints(&probe, None, jwk_hints)
                            .iter()
                            .any(|m| m.rule_id == "jwk-private-key")
                        {
                            *secret_val =
                                crate::rules::redact_replacement("jwk-private-key", secret_val);
                            count += 1;
                        }
                    }
                }
            }
            for v in map.values_mut() {
                count += redact_json_secrets_in_place(v, depth + 1, engine);
            }
            count
        }
        _ => 0,
    }
}

/// Performs a bounded single HTTP/1.1 request/response exchange (supporting TLS via `rustls` and
/// `HTTP_PROXY`/`HTTPS_PROXY`) with strict `timeout` enforcement for `--verify` and `--inspect-mcp`.
pub(crate) type HttpExchangeResponse = (u16, Vec<(String, String)>, String);

pub(crate) fn simple_http_exchange(
    method: &str,
    target_url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<HttpExchangeResponse> {
    const MAX_EXCHANGE_RESP_BYTES: usize = 2 * 1024 * 1024;

    let parsed = parse_target_url(target_url)?;
    let proxy = proxy_for_url(target_url, &parsed.host);
    let mut up_reader = open_fresh_upstream(&parsed, &proxy, timeout)?;
    let _ = up_reader
        .get_ref()
        .tcp_ref()
        .set_read_timeout(Some(timeout));
    let _ = up_reader
        .get_ref()
        .tcp_ref()
        .set_write_timeout(Some(timeout));

    let (request_target, extra_proxy_auth) = match (&proxy, parsed.is_https) {
        (Some(p), false) => (target_url.to_string(), p.basic_auth.clone()),
        _ => (parsed.origin_target.clone(), None),
    };

    let default_port = if parsed.is_https { 443 } else { 80 };
    let host_hdr = if parsed.host.contains(':') {
        if parsed.port == default_port {
            format!("[{}]", parsed.host)
        } else {
            format!("[{}]:{}", parsed.host, parsed.port)
        }
    } else if parsed.port == default_port {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    let payload = body.unwrap_or(&[]);
    let mut req_buf = Vec::with_capacity(384 + payload.len());
    write!(req_buf, "{method} {request_target} HTTP/1.1\r\n")?;
    write!(req_buf, "Host: {host_hdr}\r\n")?;
    if let Some(auth) = extra_proxy_auth {
        write!(req_buf, "Proxy-Authorization: Basic {auth}\r\n")?;
    }
    let mut has_user_agent = false;
    for &(k, v) in headers {
        if k.eq_ignore_ascii_case("user-agent") {
            has_user_agent = true;
        }
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "connection" | "accept-encoding"
        ) {
            continue;
        }
        write!(req_buf, "{k}: {v}\r\n")?;
    }
    if !has_user_agent {
        write!(
            req_buf,
            "User-Agent: leaktap/{}\r\n",
            env!("CARGO_PKG_VERSION")
        )?;
    }
    write!(req_buf, "Accept-Encoding: identity\r\n")?;
    if body.is_some() || matches!(method, "POST" | "PUT" | "PATCH") {
        write!(req_buf, "Content-Length: {}\r\n", payload.len())?;
    }
    write!(req_buf, "Connection: close\r\n\r\n")?;
    req_buf.extend_from_slice(payload);

    up_reader.get_mut().write_all(&req_buf)?;
    up_reader.get_mut().flush()?;

    let status_line = match read_bounded_line(&mut up_reader, MAX_HEADER_LINE_BYTES)? {
        BoundedLine::Line(l) => l,
        BoundedLine::Eof => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before status line",
            ))
        }
        BoundedLine::TooLong => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream status line too long",
            ))
        }
    };
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut resp_headers: Vec<(String, String)> = Vec::new();
    let mut resp_chunked = false;
    let mut resp_content_length: Option<usize> = None;
    let mut is_event_stream = false;

    for _ in 0..(MAX_HEADER_COUNT * 2) {
        let line = match read_bounded_line(&mut up_reader, MAX_HEADER_LINE_BYTES * 2)? {
            BoundedLine::Eof => break,
            BoundedLine::TooLong => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream response header too long",
                ))
            }
            BoundedLine::Line(l) => l,
        };
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                resp_chunked = true;
            } else if key.eq_ignore_ascii_case("content-length") {
                resp_content_length = val.parse::<usize>().ok();
            } else if key.eq_ignore_ascii_case("content-type")
                && val.to_ascii_lowercase().contains("text/event-stream")
            {
                is_event_stream = true;
            }
            resp_headers.push((key, val));
        }
    }

    let body_bytes = if method.eq_ignore_ascii_case("HEAD") || matches!(status_code, 204 | 304) {
        Vec::new()
    } else if is_event_stream && !resp_chunked {
        let mut acc = Vec::new();
        for _ in 0..256 {
            match read_bounded_line(&mut up_reader, 64 * 1024) {
                Ok(BoundedLine::Line(l)) => {
                    acc.extend_from_slice(l.as_bytes());
                    if l.contains("\"tools\"") || acc.len() >= MAX_EXCHANGE_RESP_BYTES {
                        break;
                    }
                }
                _ => break,
            }
        }
        acc
    } else if resp_chunked {
        if is_event_stream {
            let mut acc = Vec::new();
            while let Ok(BoundedLine::Line(size_line)) = read_bounded_line(&mut up_reader, 4096) {
                let hex = size_line.trim().split(';').next().unwrap_or("0").trim();
                let Ok(chunk_len) = usize::from_str_radix(hex, 16) else {
                    break;
                };
                if chunk_len == 0 || acc.len().saturating_add(chunk_len) > MAX_EXCHANGE_RESP_BYTES {
                    break;
                }
                let mut chunk = vec![0u8; chunk_len];
                if up_reader.read_exact(&mut chunk).is_err() {
                    break;
                }
                let _ = read_bounded_line(&mut up_reader, 4);
                acc.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&chunk).contains("\"tools\"") {
                    break;
                }
            }
            acc
        } else {
            read_chunked_body(&mut up_reader, MAX_EXCHANGE_RESP_BYTES)?.unwrap_or_default()
        }
    } else if let Some(cl) = resp_content_length {
        let cap = cl.min(MAX_EXCHANGE_RESP_BYTES);
        let mut out = Vec::with_capacity(cap.min(65536));
        let _ = (&mut up_reader).take(cap as u64).read_to_end(&mut out);
        out
    } else {
        let mut out = Vec::new();
        let _ = (&mut up_reader)
            .take(MAX_EXCHANGE_RESP_BYTES as u64)
            .read_to_end(&mut out);
        out
    };

    Ok((
        status_code,
        resp_headers,
        String::from_utf8_lossy(&body_bytes).into_owned(),
    ))
}

fn collect_json_value_strings(val: &serde_json::Value, depth: usize, out: &mut String) {
    if depth > 64 || out.len() > 72 * 1024 * 1024 {
        return;
    }
    match val {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
            // Unpack nested stringified JSON (e.g. tool/function call `arguments` or `input` payloads)
            if depth <= 24 {
                let first_non_ws = s.as_bytes().iter().find(|b| !b.is_ascii_whitespace());
                if matches!(first_non_ws, Some(b'{' | b'[')) {
                    if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                        collect_json_value_strings(&inner, depth + 1, out);
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_value_strings(item, depth + 1, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                out.push_str(k);
                out.push('=');
                if let serde_json::Value::String(s) = v {
                    out.push('"');
                    out.push_str(s);
                    out.push_str("\"\n");
                    if depth <= 24 {
                        let first_non_ws = s.as_bytes().iter().find(|b| !b.is_ascii_whitespace());
                        if matches!(first_non_ws, Some(b'{' | b'[')) {
                            if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                                collect_json_value_strings(&inner, depth + 1, out);
                            }
                        }
                    }
                } else {
                    out.push('\n');
                    collect_json_value_strings(v, depth + 1, out);
                }
            }
        }
        _ => {}
    }
}

fn strip_query(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}
