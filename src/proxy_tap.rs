use crate::api_tap::TapCallback;
use base64::Engine as _;
use std::collections::HashSet;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT_PROXY_CONNS: usize = 64;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 128;

#[derive(Clone)]
struct UpstreamHttpProxy {
    host: String,
    port: u16,
    basic_auth: Option<String>,
}

pub struct ConnectObserverTap {
    pub port: u16,
    pub proxy_url: String,
    stop: Arc<AtomicBool>,
}

impl ConnectObserverTap {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

enum LineOutcome {
    Line(String),
    Eof,
    TooLong,
}

fn read_bounded<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<LineOutcome> {
    let mut buf = Vec::new();
    loop {
        let avail = reader.fill_buf()?;
        if avail.is_empty() {
            if buf.is_empty() {
                return Ok(LineOutcome::Eof);
            }
            return Ok(LineOutcome::Line(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        if let Some(pos) = avail.iter().position(|&b| b == b'\n') {
            let take_len = pos + 1;
            if buf.len().saturating_add(take_len) > max_bytes {
                reader.consume(take_len);
                return Ok(LineOutcome::TooLong);
            }
            buf.extend_from_slice(&avail[..take_len]);
            reader.consume(take_len);
            return Ok(LineOutcome::Line(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        let chunk_len = avail.len();
        if buf.len().saturating_add(chunk_len) > max_bytes {
            reader.consume(chunk_len);
            return Ok(LineOutcome::TooLong);
        }
        buf.extend_from_slice(avail);
        reader.consume(chunk_len);
    }
}

/// Starts a zero-cert local HTTP / `CONNECT` pass-through observer on `127.0.0.1:0`.
///
/// - Preserves end-to-end TLS without installing custom root certificates.
/// - Chains through the parent process's `HTTPS_PROXY` / `HTTP_PROXY` if an `http://` proxy is set
///   (and returns `Ok(None)` if a non-HTTP `socks5://` proxy is configured in the parent environment so
///   SOCKS workflows are never disrupted).
/// - Emits deduplicated `mcp-live-telemetry` (`MEDIUM`) and `http-connect` (`LOW`) wiretap events
///   recording the exact destination `host:port` contacted by wrapped MCP servers and child tools.
pub fn start_connect_observer_tap(emit: TapCallback) -> io::Result<Option<ConnectObserverTap>> {
    let https_parent =
        match resolve_parent_proxy(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]) {
            ParentProxyLookup::UnsupportedScheme => return Ok(None),
            ParentProxyLookup::Found(p) => Some(p),
            ParentProxyLookup::None => None,
        };
    let http_parent =
        match resolve_parent_proxy(&["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]) {
            ParentProxyLookup::UnsupportedScheme => return Ok(None),
            ParentProxyLookup::Found(p) => Some(p),
            ParentProxyLookup::None => None,
        };
    let parent_no_proxy = env::var("NO_PROXY")
        .or_else(|_| env::var("no_proxy"))
        .unwrap_or_default();

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let _ = listener.set_nonblocking(true);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    let active = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(HashSet::<String>::new()));

    thread::spawn(move || {
        while !stop_loop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_nonblocking(false);
                    let prev = active.fetch_add(1, Ordering::AcqRel);
                    if prev >= MAX_CONCURRENT_PROXY_CONNS {
                        active.fetch_sub(1, Ordering::AcqRel);
                        let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = write!(
                            client,
                            "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        );
                        continue;
                    }
                    let guard = SlotGuard(Arc::clone(&active));
                    let https_p = https_parent.clone();
                    let http_p = http_parent.clone();
                    let no_p = parent_no_proxy.clone();
                    let seen_ref = Arc::clone(&seen);
                    let emit_ref = Arc::clone(&emit);
                    thread::spawn(move || {
                        let _g = guard;
                        let _ = handle_proxy_client(
                            client,
                            port,
                            https_p.as_ref(),
                            http_p.as_ref(),
                            &no_p,
                            &seen_ref,
                            &emit_ref,
                        );
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(15));
                }
                Err(_) => break,
            }
        }
    });

    Ok(Some(ConnectObserverTap {
        port,
        proxy_url: format!("http://127.0.0.1:{port}"),
        stop,
    }))
}

enum ParentProxyLookup {
    None,
    Found(UpstreamHttpProxy),
    UnsupportedScheme,
}

fn resolve_parent_proxy(keys: &[&str]) -> ParentProxyLookup {
    for &k in keys {
        let Ok(raw) = env::var(k) else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("socks") || lower.starts_with("https://") {
            return ParentProxyLookup::UnsupportedScheme;
        }
        if let Some(parsed) = parse_http_proxy_url(trimmed) {
            return ParentProxyLookup::Found(parsed);
        }
        return ParentProxyLookup::UnsupportedScheme;
    }
    ParentProxyLookup::None
}

fn parse_http_proxy_url(raw: &str) -> Option<UpstreamHttpProxy> {
    let trimmed = raw.trim();
    let rest = if let Some((scheme, after)) = trimmed.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") {
            return None;
        }
        after
    } else {
        trimmed
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let (basic_auth, host_port) = if let Some((userinfo, hp)) = authority.rsplit_once('@') {
        let decoded = percent_decode(userinfo);
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        (Some(b64), hp)
    } else {
        (None, authority)
    };
    let (host, port) = split_host_port(host_port, 8080)?;
    Some(UpstreamHttpProxy {
        host,
        port,
        basic_auth,
    })
}

fn split_host_port(host_port: &str, default_port: u16) -> Option<(String, u16)> {
    let hp = host_port.trim();
    if hp.is_empty() {
        return None;
    }
    if let Some(rest) = hp.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']')?;
        if tail.is_empty() {
            return Some((v6.to_string(), default_port));
        }
        let port_str = tail.strip_prefix(':')?;
        let p = port_str.parse::<u16>().ok()?;
        return Some((v6.to_string(), p));
    }
    if let Some((h, p_str)) = hp.rsplit_once(':') {
        if !h.contains(':') {
            let p = p_str.parse::<u16>().ok()?;
            if h.is_empty() {
                return None;
            }
            return Some((h.to_string(), p));
        }
    }
    Some((hp.to_string(), default_port))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn matches_no_proxy(host: &str, no_proxy_raw: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if matches!(h.as_str(), "localhost" | "127.0.0.1" | "::1") || h.starts_with("127.") {
        return true;
    }
    for entry in no_proxy_raw.split(',') {
        let pat = entry.trim().to_ascii_lowercase();
        if pat.is_empty() {
            continue;
        }
        if pat == "*" {
            return true;
        }
        let pat_host = pat.split(':').next().unwrap_or(&pat);
        if h == pat_host {
            return true;
        }
        let suffix = pat_host.strip_prefix('.').unwrap_or(pat_host);
        if !suffix.is_empty() && h.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }
    false
}

fn is_self_loop(host: &str, port: u16, own_port: u16) -> bool {
    if port != own_port {
        return false;
    }
    let h = host.to_ascii_lowercase();
    matches!(h.as_str(), "127.0.0.1" | "localhost" | "::1")
}

/// Classifies known vendor analytics / usage telemetry collectors observed on live connections.
pub fn classify_live_telemetry(host: &str, path: Option<&str>) -> Option<&'static str> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h == "us.i.posthog.com"
        || h == "eu.i.posthog.com"
        || h == "i.posthog.com"
        || h == "app.posthog.com"
        || h == "events.posthog.com"
        || h.ends_with(".posthog.com")
    {
        return Some("PostHog");
    }
    if h == "play.googleapis.com" {
        return Some("Google Clearcut");
    }
    if h == "www.google-analytics.com"
        || h == "analytics.google.com"
        || h.ends_with(".google-analytics.com")
    {
        return Some("Google Analytics");
    }
    if h == "api.segment.io" || h == "cdn.segment.com" || h.ends_with(".segment.io") {
        return Some("Segment");
    }
    if h == "ingest.sentry.io"
        || h.ends_with(".ingest.sentry.io")
        || h.contains(".ingest.us.sentry.io")
        || h.contains(".ingest.de.sentry.io")
    {
        return Some("Sentry");
    }
    if h == "api.mixpanel.com" || h.ends_with(".mixpanel.com") {
        return Some("Mixpanel");
    }
    if h == "api.amplitude.com" || h == "api2.amplitude.com" || h.ends_with(".amplitude.com") {
        return Some("Amplitude");
    }
    if h == "http-intake.logs.datadoghq.com"
        || h == "browser-intake-datadoghq.com"
        || h == "trace.agent.datadoghq.com"
    {
        return Some("Datadog");
    }
    if h == "static.scarf.sh" || h.ends_with(".scarf.sh") {
        return Some("Scarf");
    }
    if h.starts_with("telemetry.") || h.contains(".telemetry.") {
        return Some("dedicated telemetry collector");
    }
    if let Some(p) = path {
        let pl = p.to_ascii_lowercase();
        if pl.contains("/telemetry/events")
            || pl.contains("/rest/v1/telemetry_events")
            || pl.contains("/mp/collect")
        {
            return Some("telemetry endpoint");
        }
    }
    None
}

fn connect_host_timeout(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(60)));
                return Ok(s);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS lookup empty")))
}

fn emit_proxy_observation(
    is_connect: bool,
    host: &str,
    port: u16,
    path: Option<&str>,
    seen: &Mutex<HashSet<String>>,
    emit: &TapCallback,
) {
    let host_lc = host.to_ascii_lowercase();
    let dedup_key = format!(
        "{}:{}:{}",
        if is_connect { "connect" } else { "http" },
        host_lc,
        port
    );
    let is_first = seen.lock().map(|mut s| s.insert(dedup_key)).unwrap_or(true);
    if !is_first {
        return;
    }

    if let Some(vendor) = classify_live_telemetry(&host_lc, path) {
        emit(
            "proxy",
            "live_telemetry",
            "mcp-live-telemetry",
            "MEDIUM",
            format!("Live outbound telemetry connection to `{host_lc}:{port}` ({vendor})"),
        );
    } else {
        let proto_label = if is_connect { "HTTPS CONNECT" } else { "HTTP" };
        emit(
            "proxy",
            "outbound_connect",
            "http-connect",
            "MEDIUM",
            format!("Live outbound {proto_label} connection to `{host_lc}:{port}`"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_proxy_client(
    mut client: TcpStream,
    own_port: u16,
    https_parent: Option<&UpstreamHttpProxy>,
    http_parent: Option<&UpstreamHttpProxy>,
    parent_no_proxy: &str,
    seen: &Mutex<HashSet<String>>,
    emit: &TapCallback,
) -> io::Result<()> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));

    let mut reader = BufReader::new(client.try_clone()?);
    let req_line = match read_bounded(&mut reader, MAX_LINE_BYTES)? {
        LineOutcome::Line(l) => l,
        LineOutcome::Eof | LineOutcome::TooLong => return Ok(()),
    };
    let trimmed_req = req_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed_req.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(());
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for _ in 0..MAX_HEADERS {
        match read_bounded(&mut reader, MAX_LINE_BYTES)? {
            LineOutcome::Eof | LineOutcome::TooLong => return Ok(()),
            LineOutcome::Line(l) => {
                if l == "\r\n" || l == "\n" {
                    break;
                }
                if let Some((k, v)) = l.split_once(':') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_host_port(target, 443) else {
            let _ = write!(
                client,
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
            return Ok(());
        };
        if is_self_loop(&host, port, own_port) {
            let _ = write!(
                client,
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
            return Ok(());
        }

        emit_proxy_observation(true, &host, port, None, seen, emit);

        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let timeout = Duration::from_secs(10);
        let parent_opt = if !matches_no_proxy(&host, parent_no_proxy) {
            https_parent
        } else {
            None
        };

        if let Some(p) = parent_opt {
            let mut upstream = match connect_host_timeout(&p.host, p.port, timeout) {
                Ok(s) => s,
                Err(_) => {
                    let _ = write!(
                        client,
                        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    );
                    return Ok(());
                }
            };
            write!(
                upstream,
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            )?;
            if let Some(ref auth) = p.basic_auth {
                write!(upstream, "Proxy-Authorization: Basic {auth}\r\n")?;
            }
            write!(upstream, "\r\n")?;
            if !reader.buffer().is_empty() {
                upstream.write_all(reader.buffer())?;
            }
            upstream.flush()?;
            let client_raw = reader.into_inner();
            splice_bidirectional(client_raw, upstream);
        } else {
            let mut upstream = match connect_host_timeout(&host, port, timeout) {
                Ok(s) => s,
                Err(_) => {
                    let _ = write!(
                        client,
                        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    );
                    return Ok(());
                }
            };
            write!(client, "HTTP/1.1 200 Connection Established\r\n\r\n")?;
            client.flush()?;
            if !reader.buffer().is_empty() {
                upstream.write_all(reader.buffer())?;
                upstream.flush()?;
            }
            let client_raw = reader.into_inner();
            splice_bidirectional(client_raw, upstream);
        }
        return Ok(());
    }

    // Plain HTTP proxy request (`GET http://host[:port]/path HTTP/1.1`)
    let Some(after_scheme) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
    else {
        let _ = write!(
            client,
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        return Ok(());
    };
    let (authority_str, origin_path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let Some((host, port)) = split_host_port(authority_str, 80) else {
        let _ = write!(
            client,
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        return Ok(());
    };
    if is_self_loop(&host, port, own_port) {
        let _ = write!(
            client,
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        return Ok(());
    }

    emit_proxy_observation(false, &host, port, Some(origin_path), seen, emit);

    let timeout = Duration::from_secs(10);
    let parent_opt = if !matches_no_proxy(&host, parent_no_proxy) {
        http_parent
    } else {
        None
    };

    if let Some(p) = parent_opt {
        let mut upstream = match connect_host_timeout(&p.host, p.port, timeout) {
            Ok(s) => s,
            Err(_) => {
                let _ = write!(
                    client,
                    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                );
                return Ok(());
            }
        };
        write!(upstream, "{method} {target} {version}\r\n")?;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("proxy-connection")
                || k.eq_ignore_ascii_case("proxy-authorization")
                || k.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            write!(upstream, "{k}: {v}\r\n")?;
        }
        if let Some(ref auth) = p.basic_auth {
            write!(upstream, "Proxy-Authorization: Basic {auth}\r\n")?;
        }
        write!(upstream, "Connection: close\r\n\r\n")?;
        if !reader.buffer().is_empty() {
            upstream.write_all(reader.buffer())?;
        }
        upstream.flush()?;
        let client_raw = reader.into_inner();
        splice_bidirectional(client_raw, upstream);
    } else {
        let mut upstream = match connect_host_timeout(&host, port, timeout) {
            Ok(s) => s,
            Err(_) => {
                let _ = write!(
                    client,
                    "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                );
                return Ok(());
            }
        };
        write!(upstream, "{method} {origin_path} {version}\r\n")?;
        let mut has_host = false;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if k.eq_ignore_ascii_case("proxy-connection")
                || k.eq_ignore_ascii_case("proxy-authorization")
                || k.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            write!(upstream, "{k}: {v}\r\n")?;
        }
        if !has_host {
            write!(upstream, "Host: {authority_str}\r\n")?;
        }
        write!(upstream, "Connection: close\r\n\r\n")?;
        if !reader.buffer().is_empty() {
            upstream.write_all(reader.buffer())?;
        }
        upstream.flush()?;
        let client_raw = reader.into_inner();
        splice_bidirectional(client_raw, upstream);
    }

    Ok(())
}

fn splice_bidirectional(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(60)));
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(60)));

    let (Ok(mut c_read), Ok(mut u_write)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };

    let c_to_u = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match c_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if u_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = u_write.flush();
                }
            }
        }
        let _ = u_write.shutdown(Shutdown::Write);
    });

    let mut buf = [0u8; 8192];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = client.flush();
            }
        }
    }
    let _ = client.shutdown(Shutdown::Write);
    let _ = c_to_u.join();
}
