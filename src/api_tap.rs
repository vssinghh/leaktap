use crate::header_audit::HeaderAuditor;
use crate::rules::{RuleCategory, RuleEngine};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct LocalApiTap {
    pub anthropic_base_url: String,
    pub openai_base_url: String,
    pub gemini_base_url: String,
    stop: Arc<AtomicBool>,
}

impl LocalApiTap {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub type TapCallback = Arc<dyn Fn(&str, &str, &str, &str, String) + Send + Sync + 'static>;

#[derive(Clone)]
struct UpstreamTargets {
    anthropic: String,
    openai: String,
    gemini: String,
}

fn spawn_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    upstreams: UpstreamTargets,
    engine: Arc<RuleEngine>,
    header_auditor: Arc<HeaderAuditor>,
    emit: TapCallback,
) {
    let _ = listener.set_nonblocking(true);
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = stream.set_nonblocking(false);
                    let engine = Arc::clone(&engine);
                    let auditor = Arc::clone(&header_auditor);
                    let emit = Arc::clone(&emit);
                    let targets = upstreams.clone();
                    thread::spawn(move || {
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

pub fn start_local_api_tap(
    anthropic_upstream: String,
    openai_upstream: String,
    gemini_upstream: String,
    engine: Arc<RuleEngine>,
    header_auditor: Arc<HeaderAuditor>,
    emit: TapCallback,
) -> io::Result<LocalApiTap> {
    let v4_listener = TcpListener::bind("127.0.0.1:0")?;
    let port = v4_listener.local_addr()?.port();

    let stop = Arc::new(AtomicBool::new(false));
    let upstreams = UpstreamTargets {
        anthropic: anthropic_upstream.trim_end_matches('/').to_string(),
        openai: openai_upstream.trim_end_matches('/').to_string(),
        gemini: gemini_upstream.trim_end_matches('/').to_string(),
    };

    spawn_accept_loop(
        v4_listener,
        Arc::clone(&stop),
        upstreams.clone(),
        Arc::clone(&engine),
        Arc::clone(&header_auditor),
        Arc::clone(&emit),
    );

    // Also bind IPv6 loopback `[::1]:port` when available so `http://localhost:<port>`
    // (required by Gemini CLI for plain HTTP) connects immediately on IPv6-first systems.
    if let Ok(v6_listener) = TcpListener::bind(("[::1]", port)) {
        spawn_accept_loop(
            v6_listener,
            Arc::clone(&stop),
            upstreams,
            engine,
            header_auditor,
            emit,
        );
    }

    Ok(LocalApiTap {
        anthropic_base_url: format!("http://127.0.0.1:{port}/_anthropic"),
        openai_base_url: format!("http://127.0.0.1:{port}/_openai"),
        gemini_base_url: format!("http://localhost:{port}/_gemini"),
        stop,
    })
}

fn handle_client(
    mut client: TcpStream,
    upstreams: &UpstreamTargets,
    engine: &RuleEngine,
    auditor: &HeaderAuditor,
    emit: &TapCallback,
) -> io::Result<()> {
    let cloned = client.try_clone()?;
    let mut reader = BufReader::new(cloned);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_string();
    let raw_path = parts[1].to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    let mut is_chunked = false;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().unwrap_or(0);
            }
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
            headers.push((key, val));
        }
    }

    let body = if is_chunked {
        read_chunked_body(&mut reader)?
    } else if content_length > 0 {
        let capped = content_length.min(32 * 1024 * 1024);
        let mut buf = vec![0u8; capped];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    // Route prefix (`/_anthropic/...`, `/_openai/...`, or `/_gemini/...`)
    let (provider, target_url) = if let Some(rest) = raw_path.strip_prefix("/_anthropic") {
        let suffix = if rest.is_empty() { "/" } else { rest };
        ("anthropic", format!("{}{suffix}", upstreams.anthropic))
    } else if let Some(rest) = raw_path.strip_prefix("/_openai") {
        let suffix = if rest.is_empty() { "/" } else { rest };
        ("openai", format!("{}{suffix}", upstreams.openai))
    } else if let Some(rest) = raw_path.strip_prefix("/_gemini") {
        let suffix = if rest.is_empty() { "/" } else { rest };
        ("gemini", format!("{}{suffix}", upstreams.gemini))
    } else {
        let suffix = if raw_path.starts_with('/') {
            raw_path.as_str()
        } else {
            "/"
        };
        ("anthropic", format!("{}{suffix}", upstreams.anthropic))
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

    // 1. Audit outgoing HTTP headers (`User-Agent` email leaks, hostname/OS user, leaked keys)
    for (k, v) in &headers {
        for hf in auditor.inspect_header(k, v, engine) {
            emit(
                "http-header",
                "header_leak",
                hf.rule_id,
                hf.severity.as_str(),
                hf.detail,
            );
        }
    }

    // 2. Audit outgoing request body (prompt context + tool outputs)
    if !body.is_empty() {
        let body_text = String::from_utf8_lossy(&body);
        for m in engine.scan_text(&body_text) {
            let kind = match m.category {
                RuleCategory::Secret => "secret_in_prompt",
                RuleCategory::Pii => "pii_in_prompt",
            };
            emit(
                "http-body",
                kind,
                m.rule_id,
                m.severity.as_str(),
                format!(
                    "{} ({}) sent in outgoing {provider} API body",
                    m.rule_name, m.masked
                ),
            );
        }
    }

    // 3. Forward upstream and stream response back chunk-by-chunk (preserving SSE streaming)
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .build();

    let mut req = agent.request(&method, &target_url);
    for (k, v) in &headers {
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "connection" | "transfer-encoding" | "accept-encoding"
        ) {
            continue;
        }
        req = req.set(k, v);
    }
    // Request uncompressed response so streaming passthrough framing is clean and immediate
    req = req.set("Accept-Encoding", "identity");

    let upstream_result = if body.is_empty() {
        req.call()
    } else {
        req.send_bytes(&body)
    };

    let response = match upstream_result {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_code, resp)) => resp,
        Err(ureq::Error::Transport(err)) => {
            let msg = format!("{{\"error\":\"leaktap upstream transport error: {err}\"}}");
            write!(
                client,
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                msg.len(),
                msg
            )?;
            client.flush()?;
            return Ok(());
        }
    };

    let status = response.status();
    let status_text = response.status_text().to_string();
    write!(client, "HTTP/1.1 {status} {status_text}\r\n")?;

    for name in response.headers_names() {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "transfer-encoding" | "connection" | "content-length"
        ) {
            continue;
        }
        for val in response.all(&name) {
            write!(client, "{name}: {val}\r\n")?;
        }
    }
    write!(client, "Connection: close\r\n\r\n")?;
    client.flush()?;

    let mut resp_reader = response.into_reader();
    let mut chunk = [0u8; 8192];
    loop {
        let n = resp_reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        client.write_all(&chunk[..n])?;
        client.flush()?;
    }

    Ok(())
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            break;
        }
        let hex = size_line.trim().split(';').next().unwrap_or("0").trim();
        let chunk_len = usize::from_str_radix(hex, 16).unwrap_or(0);
        if chunk_len == 0 {
            let mut trailer = String::new();
            let _ = reader.read_line(&mut trailer);
            break;
        }
        let mut buf = vec![0u8; chunk_len];
        reader.read_exact(&mut buf)?;
        out.extend_from_slice(&buf);
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf);
        if out.len() > 32 * 1024 * 1024 {
            break;
        }
    }
    Ok(out)
}

fn strip_query(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}
