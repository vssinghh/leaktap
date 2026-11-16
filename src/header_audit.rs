use crate::rules::{mask_value, RuleCategory, RuleEngine, Severity};
use std::env;
use std::fs;

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

    /// Audits an outgoing HTTP header `(name, value)` for identity, email, and secret leaks.
    pub fn inspect_header(
        &self,
        name: &str,
        value: &str,
        engine: &RuleEngine,
    ) -> Vec<HeaderFinding> {
        let mut findings = Vec::new();
        let lower_name = name.trim().to_ascii_lowercase();
        let trimmed_val = value.trim();
        if trimmed_val.is_empty() {
            return findings;
        }

        // Standard API auth headers carry LLM provider tokens (`sk-ant-...`, `sk-proj-...`, `AIza...`, OAuth/JWT);
        // non-LLM secrets (`sk_live_...`, `AKIA...`, `ghp_...`, DB URIs, PEM keys) must still be flagged and blocked!
        let is_standard_auth_header = matches!(
            lower_name.as_str(),
            "authorization" | "x-api-key" | "anthropic-api-key" | "api-key" | "x-goog-api-key"
        );

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

        for m in header_matches {
            match m.category {
                RuleCategory::Pii if m.rule_id == "pii-email" => {
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
                RuleCategory::Pii if m.rule_id == "internal-hostname" => {
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
                RuleCategory::Secret => {
                    let is_expected_llm_auth = is_standard_auth_header
                        && matches!(
                            m.rule_id.as_str(),
                            "anthropic-api-key"
                                | "openai-api-key"
                                | "gcp-api-key"
                                | "google-oauth-token"
                                | "jwt-token"
                                | "http-bearer-token"
                                | "groq-api-key"
                                | "perplexity-api-key"
                        );
                    if !is_expected_llm_auth {
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
                }
                _ => {}
            }
        }

        if !is_standard_auth_header {
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
