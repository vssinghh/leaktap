use crate::rules::{
    is_likely_placeholder, mask_value, shannon_entropy, RuleCategory, RuleEngine, Severity,
};
use std::env;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProvider {
    Anthropic,
    OpenAi,
    Gemini,
}

#[derive(Debug, Clone)]
pub struct HeaderFinding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub header_name: String,
    pub detail: String,
}

const GENERIC_USERNAMES: &[&str] = &[
    "user", "root", "admin", "ubuntu", "debian", "ec2-user", "runner", "docker", "postgres",
    "nobody", "default", "test", "dev", "git", "node", "python", "rust", "code", "agent", "claude",
    "cursor",
];

pub struct HeaderAuditor {
    local_user: Option<String>,
    local_host: Option<String>,
}

impl Default for HeaderAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderAuditor {
    pub fn new() -> Self {
        let local_user = env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .ok()
            .map(|u| u.trim().to_ascii_lowercase())
            .filter(|u| u.len() >= 4 && !GENERIC_USERNAMES.contains(&u.as_str()));

        let local_host = detect_hostname()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| {
                h.len() >= 4
                    && h != "localhost"
                    && !h.starts_with("localhost.")
                    && h != "ubuntu"
                    && h != "debian"
            });

        Self {
            local_user,
            local_host,
        }
    }

    pub fn with_identity(local_user: Option<String>, local_host: Option<String>) -> Self {
        Self {
            local_user: local_user.map(|s| s.to_ascii_lowercase()),
            local_host: local_host.map(|s| s.to_ascii_lowercase()),
        }
    }

    /// Audits an HTTP header `(name, value)` without an upstream provider binding (e.g. terminal stream logs).
    pub fn inspect_header(
        &self,
        name: &str,
        value: &str,
        engine: &RuleEngine,
    ) -> Vec<HeaderFinding> {
        self.inspect_header_for_provider(name, value, None, engine)
    }

    /// Audits an outgoing HTTP header `(name, value)` bound to a specific `UpstreamProvider`,
    /// exempting only credentials valid for that target provider while flagging cross-provider
    /// keys, internal JWTs, and unrecognized opaque bearer/API tokens.
    pub fn inspect_header_for_provider(
        &self,
        name: &str,
        value: &str,
        provider: Option<UpstreamProvider>,
        engine: &RuleEngine,
    ) -> Vec<HeaderFinding> {
        let mut findings = Vec::new();
        let lower_name = name.trim().to_ascii_lowercase();
        let trimmed_val = value.trim();
        if trimmed_val.is_empty() {
            return findings;
        }

        let is_auth_header_name = matches!(
            lower_name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "x-api-key"
                | "anthropic-api-key"
                | "openai-api-key"
                | "api-key"
                | "x-goog-api-key"
                | "x-auth-token"
                | "x-access-token"
                | "x-secret-key"
        );

        let raw_cred = extract_auth_credential(trimmed_val);
        let exempted_provider_auth =
            provider.is_some_and(|prov| is_expected_provider_auth(&lower_name, raw_cred, prov));

        let mut header_matches = engine.scan_text(trimmed_val);
        if trimmed_val.contains('%') {
            let decoded = percent_decode_header(trimmed_val);
            if decoded != trimmed_val {
                for dm in engine.scan_text(&decoded) {
                    if !header_matches
                        .iter()
                        .any(|m| m.rule_id == dm.rule_id && m.fingerprint == dm.fingerprint)
                    {
                        header_matches.push(dm);
                    }
                }
            }
        }

        let mut emitted_secret_leak = false;
        for m in header_matches {
            match m.category {
                RuleCategory::Pii if m.rule_id == "pii-email" => {
                    if !exempted_provider_auth {
                        findings.push(HeaderFinding {
                            rule_id: "header-email-leak",
                            severity: Severity::High,
                            header_name: name.to_string(),
                            detail: format!(
                                "Email address ({}) sent in HTTP header `{name}`",
                                m.masked
                            ),
                        });
                    }
                }
                RuleCategory::Pii if m.rule_id == "internal-hostname" => {
                    if !exempted_provider_auth {
                        findings.push(HeaderFinding {
                            rule_id: "header-internal-host",
                            severity: Severity::Medium,
                            header_name: name.to_string(),
                            detail: format!(
                                "Internal hostname ({}) sent in HTTP header `{name}`",
                                m.masked
                            ),
                        });
                    }
                }
                RuleCategory::Secret if !exempted_provider_auth => {
                    emitted_secret_leak = true;
                    findings.push(HeaderFinding {
                        rule_id: "header-secret-leak",
                        severity: Severity::Critical,
                        header_name: name.to_string(),
                        detail: format!(
                            "{} ({}) sent in HTTP header `{name}`",
                            m.rule_name, m.masked
                        ),
                    });
                }
                _ => {}
            }
        }

        if is_auth_header_name
            && !exempted_provider_auth
            && !emitted_secret_leak
            && is_opaque_unrecognized_credential(raw_cred)
        {
            let masked = mask_value("http-bearer-token", raw_cred);
            findings.push(HeaderFinding {
                rule_id: "header-secret-leak",
                severity: Severity::Critical,
                header_name: name.to_string(),
                detail: format!(
                    "Unrecognized or cross-provider credential ({masked}) sent in HTTP header `{name}`"
                ),
            });
        }

        if !exempted_provider_auth {
            let lower_val = trimmed_val.to_ascii_lowercase();

            if let Some(ref user) = self.local_user {
                if contains_token_boundary(&lower_val, user) {
                    let masked = mask_value("pii-email", user);
                    findings.push(HeaderFinding {
                        rule_id: "header-os-username",
                        severity: Severity::Medium,
                        header_name: name.to_string(),
                        detail: format!(
                            "Local OS username ({masked}) exposed in HTTP header `{name}`"
                        ),
                    });
                }
            }

            if let Some(ref host) = self.local_host {
                let short_host = host.split('.').next().unwrap_or(host);
                if short_host.len() >= 5 && contains_token_boundary(&lower_val, short_host) {
                    findings.push(HeaderFinding {
                        rule_id: "header-machine-hostname",
                        severity: Severity::Medium,
                        header_name: name.to_string(),
                        detail: format!("Local machine hostname exposed in HTTP header `{name}`"),
                    });
                }
            }
        }

        findings
    }
}

fn extract_auth_credential(trimmed_val: &str) -> &str {
    if let Some((scheme, rest)) = trimmed_val.split_once(char::is_whitespace) {
        if scheme.eq_ignore_ascii_case("bearer")
            || scheme.eq_ignore_ascii_case("basic")
            || scheme.eq_ignore_ascii_case("token")
            || scheme.eq_ignore_ascii_case("apikey")
        {
            return rest.trim();
        }
    }
    trimmed_val
}

fn is_expected_provider_auth(
    lower_header_name: &str,
    raw_cred: &str,
    provider: UpstreamProvider,
) -> bool {
    if raw_cred.is_empty() {
        return false;
    }
    match provider {
        UpstreamProvider::Anthropic => {
            if !matches!(
                lower_header_name,
                "x-api-key" | "anthropic-api-key" | "authorization"
            ) {
                return false;
            }
            raw_cred.starts_with("sk-ant-")
                || matches_env_vars(
                    raw_cred,
                    &[
                        "ANTHROPIC_API_KEY",
                        "ANTHROPIC_AUTH_TOKEN",
                        "CLAUDE_CODE_OAUTH_TOKEN",
                    ],
                )
        }
        UpstreamProvider::OpenAi => {
            if !matches!(
                lower_header_name,
                "authorization" | "api-key" | "openai-api-key"
            ) {
                return false;
            }
            let is_openai_sk = raw_cred.starts_with("sk-")
                && !raw_cred.starts_with("sk-ant-")
                && !raw_cred.starts_with("sk_live_")
                && !raw_cred.starts_with("sk_test_")
                && !raw_cred.starts_with("sk-or-v1-");
            is_openai_sk
                || is_jwt_with_issuer_markers(
                    raw_cred,
                    &["api.openai.com", "auth.openai.com", "chatgpt.com"],
                )
                || matches_env_vars(
                    raw_cred,
                    &["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"],
                )
        }
        UpstreamProvider::Gemini => {
            if !matches!(
                lower_header_name,
                "x-goog-api-key" | "authorization" | "x-api-key"
            ) {
                return false;
            }
            (raw_cred.starts_with("AIza")
                && (35..=49).contains(&raw_cred.len())
                && raw_cred
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
                || raw_cred.starts_with("ya29.")
                || is_jwt_with_issuer_markers(raw_cred, &["accounts.google.com", "googleapis.com"])
                || matches_env_vars(raw_cred, &["GEMINI_API_KEY", "GOOGLE_API_KEY"])
        }
    }
}

fn matches_env_vars(raw_cred: &str, vars: &[&str]) -> bool {
    for &var in vars {
        if let Ok(val) = env::var(var) {
            let tv = val.trim();
            if !tv.is_empty() && tv == raw_cred {
                return true;
            }
        }
    }
    false
}

fn is_jwt_with_issuer_markers(token: &str, markers: &[&str]) -> bool {
    let mut parts = token.split('.');
    let Some(hdr) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    if parts.next().is_none() || parts.next().is_some() || !hdr.starts_with("eyJ") {
        return false;
    }
    let Some(decoded) = decode_base64url_ascii(payload) else {
        return false;
    };
    let lower = decoded.to_ascii_lowercase();
    markers.iter().any(|m| lower.contains(m))
}

fn decode_base64url_ascii(seg: &str) -> Option<String> {
    if seg.is_empty() || seg.len() > 16 * 1024 {
        return None;
    }
    let mut buf = Vec::with_capacity(seg.len());
    let mut acc = 0u32;
    let mut bits = 0u8;
    for b in seg.bytes() {
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push(((acc >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8(buf).ok()
}

fn is_opaque_unrecognized_credential(raw_cred: &str) -> bool {
    if raw_cred.len() < 20 || raw_cred.len() > 8192 {
        return false;
    }
    if raw_cred.chars().any(char::is_whitespace) {
        return false;
    }
    if looks_like_uuid(raw_cred) || is_likely_placeholder(raw_cred) {
        return false;
    }
    shannon_entropy(raw_cred) >= 3.6
}

fn looks_like_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (idx, b) in s.bytes().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn contains_token_boundary(haystack: &str, needle: &str) -> bool {
    let mut offset = 0usize;
    let bytes = haystack.as_bytes();
    while let Some(pos) = haystack[offset..].find(needle) {
        let start = offset + pos;
        let end = start + needle.len();
        let prev_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let next_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if prev_ok && next_ok {
            return true;
        }
        offset = start + 1;
    }
    false
}

fn detect_hostname() -> Option<String> {
    if let Ok(h) = env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return Some(h);
        }
    }
    if let Ok(h) = env::var("COMPUTERNAME") {
        if !h.trim().is_empty() {
            return Some(h);
        }
    }
    if let Ok(raw) = fs::read_to_string("/etc/hostname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn percent_decode_header(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = match bytes[i + 1] {
                b'0'..=b'9' => Some(bytes[i + 1] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 1] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 1] - b'A' + 10),
                _ => None,
            };
            let lo = match bytes[i + 2] {
                b'0'..=b'9' => Some(bytes[i + 2] - b'0'),
                b'a'..=b'f' => Some(bytes[i + 2] - b'a' + 10),
                b'A'..=b'F' => Some(bytes[i + 2] - b'A' + 10),
                _ => None,
            };
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
