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
    if let Err(err) = forward_upstream(&mut client, &method, &target_url, &headers, &body) {
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

fn connect_tcp_timeout(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS lookup empty")))
}

fn forward_upstream(
    client: &mut TcpStream,
    method: &str,
    target_url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> io::Result<()> {
    let parsed = parse_target_url(target_url)?;
    let proxy = proxy_for_url(target_url, &parsed.host);
    let timeout = Duration::from_secs(15);

    let (mut upstream, request_target, extra_proxy_auth) = match (&proxy, parsed.is_https) {
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
            let mut status_line = String::new();
            if connect_reader.read_line(&mut status_line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy closed during CONNECT",
                ));
            }
            let code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            loop {
                let mut hdr = String::new();
                let n = connect_reader.read_line(&mut hdr)?;
                if n == 0 || hdr == "\r\n" || hdr == "\n" {
                    break;
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
            (
                UpstreamStream::Tls(Box::new(rustls::StreamOwned::new(tls_conn, tcp))),
                parsed.origin_target.clone(),
                None,
            )
        }
        (Some(p), false) => {
            let tcp = connect_tcp_timeout(&p.host, p.port, timeout)?;
            (
                UpstreamStream::Plain(tcp),
                target_url.to_string(),
                p.basic_auth.clone(),
            )
        }
        (None, true) => {
            let tcp = connect_tcp_timeout(&parsed.host, parsed.port, timeout)?;
            let sni = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let tls_conn = rustls::ClientConnection::new(shared_tls_config(), sni)
                .map_err(|e| io::Error::other(e.to_string()))?;
            (
                UpstreamStream::Tls(Box::new(rustls::StreamOwned::new(tls_conn, tcp))),
                parsed.origin_target.clone(),
                None,
            )
        }
        (None, false) => {
            let tcp = connect_tcp_timeout(&parsed.host, parsed.port, timeout)?;
            (
                UpstreamStream::Plain(tcp),
                parsed.origin_target.clone(),
                None,
            )
        }
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
    for (k, v) in headers {
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
    write!(req_buf, "Accept-Encoding: identity\r\n")?;
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        write!(req_buf, "Content-Length: {}\r\n", body.len())?;
    }
    write!(req_buf, "Connection: close\r\n\r\n")?;
    req_buf.extend_from_slice(body);

    upstream.write_all(&req_buf)?;
    upstream.flush()?;

    let mut up_reader = BufReader::new(upstream);
    let mut resp_status = String::new();
    if up_reader.read_line(&mut resp_status)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "upstream closed before sending status line",
        ));
    }
    client.write_all(resp_status.as_bytes())?;

    let mut resp_chunked = false;
    let mut resp_content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = up_reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key_lc = k.trim().to_ascii_lowercase();
            let val_trim = v.trim();
            if key_lc == "connection" || key_lc == "keep-alive" || key_lc == "proxy-connection" {
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

    if method.eq_ignore_ascii_case("HEAD") {
        return Ok(());
    }

    if resp_chunked {
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
                    break;
                }
                client.write_all(&buf[..n])?;
                remaining -= n;
            }
            client.flush()?;
        }
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
            if let Ok(native_certs) = rustls_native_certs::load_native_certs() {
                root_store.add_parsable_certificates(native_certs);
            }
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
