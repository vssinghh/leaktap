use crate::api_tap::simple_http_exchange;
use crate::rules::{
    fingerprint_match, is_likely_placeholder, shannon_entropy, DocHints, RuleEngine,
};
use crate::scanner::TranscriptFinding;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine as _;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_VERIFY_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_VERIFY_WORKERS: usize = 4;

#[derive(Clone)]
struct VerificationOutcome {
    verified: Option<bool>,
    detail: Option<String>,
}

#[derive(Clone)]
enum ResolvedCredential {
    Standard {
        effective_rule_id: String,
        secret: String,
    },
    Aws {
        access_key_id: String,
        secret_access_key: Option<String>,
        session_token: Option<String>,
    },
}

struct VerifyTask {
    cache_key: (String, String),
    cred: ResolvedCredential,
}

/// Opt-in (`leaktap scan --verify`) read-only live credential check against provider APIs.
/// Populates `verified: Some(true | false)` and `verification_detail` without storing raw secrets.
pub fn verify_secret_findings(findings: &mut [TranscriptFinding], engine: &RuleEngine) {
    let mut file_text_cache: HashMap<(PathBuf, String), Option<String>> = HashMap::new();
    let mut queued_keys: HashMap<(String, String), usize> = HashMap::new();
    let mut tasks: Vec<VerifyTask> = Vec::new();

    for finding in findings.iter() {
        if !is_verifiable_or_wrapper_rule(&finding.rule_id) {
            continue;
        }
        let cache_key = (finding.rule_id.clone(), finding.fingerprint.clone());
        if queued_keys.contains_key(&cache_key) {
            continue;
        }

        let file_key = (finding.first_path.clone(), finding.first_file.clone());
        let maybe_text = file_text_cache
            .entry(file_key)
            .or_insert_with(|| load_source_text(&finding.first_path, &finding.first_file));

        let Some(ref src_text) = maybe_text else {
            continue;
        };

        let Some((effective_rule_id, raw_secret)) = extract_matching_secret(
            src_text,
            &finding.first_path,
            finding.first_line,
            &finding.rule_id,
            &finding.fingerprint,
            engine,
        ) else {
            continue;
        };

        if !is_verifiable_provider_rule(&effective_rule_id) {
            continue;
        }

        let cred = if effective_rule_id == "aws-access-key" {
            let (secret_access_key, session_token) =
                extract_aws_companion_credentials(src_text, &raw_secret, finding.first_line);
            ResolvedCredential::Aws {
                access_key_id: raw_secret,
                secret_access_key,
                session_token,
            }
        } else {
            ResolvedCredential::Standard {
                effective_rule_id,
                secret: raw_secret,
            }
        };

        queued_keys.insert(cache_key.clone(), tasks.len());
        tasks.push(VerifyTask { cache_key, cred });
    }

    if tasks.is_empty() {
        return;
    }

    let results: Mutex<HashMap<(String, String), VerificationOutcome>> =
        Mutex::new(HashMap::with_capacity(tasks.len()));
    let next_idx = AtomicUsize::new(0);
    let worker_count = tasks.len().min(MAX_VERIFY_WORKERS);

    std::thread::scope(|s| {
        for _ in 0..worker_count {
            s.spawn(|| loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= tasks.len() {
                    break;
                }
                let task = &tasks[idx];
                let outcome = match &task.cred {
                    ResolvedCredential::Standard {
                        effective_rule_id,
                        secret,
                    } => check_single_credential(effective_rule_id, secret),
                    ResolvedCredential::Aws {
                        access_key_id,
                        secret_access_key,
                        session_token,
                    } => check_aws_sts_credential(
                        access_key_id,
                        secret_access_key.as_deref(),
                        session_token.as_deref(),
                    ),
                };
                if let Ok(mut guard) = results.lock() {
                    guard.insert(task.cache_key.clone(), outcome);
                }
            });
        }
    });

    let completed = results.into_inner().unwrap_or_default();
    for finding in findings.iter_mut() {
        let cache_key = (finding.rule_id.clone(), finding.fingerprint.clone());
        if let Some(outcome) = completed.get(&cache_key) {
            finding.verified = outcome.verified;
            finding.verification_detail = outcome.detail.clone();
        }
    }
}

fn is_verifiable_or_wrapper_rule(rule_id: &str) -> bool {
    is_verifiable_provider_rule(rule_id)
        || matches!(rule_id, "base64-encoded-secret" | "hex-encoded-secret")
}

fn is_verifiable_provider_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "aws-access-key"
            | "github-pat"
            | "gitlab-pat"
            | "slack-token"
            | "discord-webhook"
            | "stripe-live-key"
            | "openai-api-key"
            | "anthropic-api-key"
            | "openrouter-api-key"
            | "groq-api-key"
            | "xai-api-key"
            | "huggingface-token"
            | "notion-api-token"
            | "digitalocean-token"
            | "vercel-access-token"
            | "figma-pat"
            | "postman-api-key"
            | "replicate-api-token"
            | "telegram-bot-token"
            | "sendgrid-api-key"
            | "npm-access-token"
            | "cloudflare-api-token"
            | "datadog-api-key"
            | "mailgun-api-key"
    )
}

fn load_source_text(path: &Path, display_file: &str) -> Option<String> {
    if let Some(rest) = display_file.strip_prefix("git:") {
        if let Some((rev, rel_path)) = rest.split_once(':') {
            let spec = if rev == "staged" {
                format!(":{rel_path}")
            } else {
                format!("{rev}:{rel_path}")
            };
            let mut repo_dir = path.parent();
            while let Some(dir) = repo_dir {
                if dir.join(".git").exists() {
                    break;
                }
                repo_dir = dir.parent();
            }
            if let Some(root) = repo_dir {
                if let Ok(out) = Command::new("git")
                    .arg("-C")
                    .arg(root)
                    .arg("show")
                    .arg(&spec)
                    .output()
                {
                    if out.status.success() {
                        return Some(String::from_utf8_lossy(&out.stdout).into_owned());
                    }
                }
            }
        }
    }

    if let Some(mut sqlite_corpus) =
        crate::scanner::extract_sqlite_text_corpus(path, MAX_VERIFY_FILE_BYTES as usize)
    {
        // Also include companion `-wal` text if `path` is a main SQLite database so paired
        // credentials (e.g. AWS key + secret) split across main DB and WAL can be resolved.
        let path_str = path.to_string_lossy();
        if !path_str.ends_with("-wal") {
            let wal_cand = PathBuf::from(format!("{path_str}-wal"));
            if wal_cand.is_file() {
                if let Some(wal_corpus) = crate::scanner::extract_sqlite_text_corpus(
                    &wal_cand,
                    MAX_VERIFY_FILE_BYTES as usize,
                ) {
                    sqlite_corpus.push('\n');
                    sqlite_corpus.push_str(&wal_corpus);
                }
            }
        }
        if !sqlite_corpus.is_empty() {
            return Some(sqlite_corpus);
        }
    }

    if let Ok(text) = crate::scanner::read_text_auto_encoding(path, MAX_VERIFY_FILE_BYTES) {
        if !text.is_empty() {
            return Some(text);
        }
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() as u64 > MAX_VERIFY_FILE_BYTES {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn extract_matching_secret(
    src_text: &str,
    path: &Path,
    first_line: usize,
    rule_id: &str,
    target_fp: &str,
    engine: &RuleEngine,
) -> Option<(String, String)> {
    if first_line > 0 {
        if let Some(line) = src_text.lines().nth(first_line - 1) {
            if let Some(found) = scan_slice_for_exact_secret(line, path, rule_id, target_fp, engine)
            {
                return Some(found);
            }
        }
    }
    scan_slice_for_exact_secret(src_text, path, rule_id, target_fp, engine)
}

fn scan_slice_for_exact_secret(
    text: &str,
    path: &Path,
    rule_id: &str,
    target_fp: &str,
    engine: &RuleEngine,
) -> Option<(String, String)> {
    let hints = DocHints::from_text(text);
    for m in engine.scan_text_with_hints(text, Some(path), hints) {
        if m.rule_id == rule_id && m.fingerprint == target_fp {
            if let Some((inner_rule_id, inner_secret)) = m.decoded_inner {
                return Some((inner_rule_id, inner_secret));
            }
            if m.end <= text.len() && text.is_char_boundary(m.start) && text.is_char_boundary(m.end)
            {
                let slice = &text[m.start..m.end];
                if fingerprint_match(rule_id, slice) == target_fp {
                    return Some((rule_id.to_string(), slice.to_string()));
                }
            }
        }
    }
    None
}

fn aws_secret_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:aws_secret_access_key|secret_?access_?key|aws_secret_key|secret_key)\s*(?:=|:|" ?: ?"?|' ?: ?'?)\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        )
        .expect("valid aws secret regex")
    })
}

fn aws_session_token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:aws_session_token|session_?token|security_?token)\s*(?:=|:|" ?: ?"?|' ?: ?'?)\s*["']?([A-Za-z0-9/+=]{16,2048})["']?"#,
        )
        .expect("valid aws session token regex")
    })
}

fn extract_aws_companion_credentials(
    src_text: &str,
    access_key_id: &str,
    first_line: usize,
) -> (Option<String>, Option<String>) {
    let lines: Vec<&str> = src_text.lines().collect();
    let window_text = if first_line > 0 && !lines.is_empty() {
        let idx = (first_line - 1).min(lines.len() - 1);
        let start = idx.saturating_sub(25);
        let end = (idx + 26).min(lines.len());
        Some(lines[start..end].join("\n"))
    } else {
        None
    };

    let find_secret = |haystack: &str| -> Option<String> {
        for caps in aws_secret_regex().captures_iter(haystack) {
            if let Some(m) = caps.get(1) {
                let cand = m.as_str();
                if cand != access_key_id
                    && !is_likely_placeholder(cand)
                    && shannon_entropy(cand) >= 3.3
                {
                    return Some(cand.to_string());
                }
            }
        }
        None
    };

    let find_token = |haystack: &str| -> Option<String> {
        if !access_key_id.starts_with("ASIA") {
            return None;
        }
        aws_session_token_regex()
            .captures(haystack)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    };

    let secret = window_text
        .as_deref()
        .and_then(find_secret)
        .or_else(|| find_secret(src_text));
    let token = window_text
        .as_deref()
        .and_then(find_token)
        .or_else(|| find_token(src_text));
    (secret, token)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn format_utc_amz_datetime(unix_secs: u64) -> (String, String) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    let date_stamp = format!("{year:04}{m:02}{d:02}");
    let amz_date = format!("{date_stamp}T{hour:02}{min:02}{sec:02}Z");
    (date_stamp, amz_date)
}

fn parse_url_host_and_path(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let path_only = path_part.split('?').next().unwrap_or("/");
    Some((authority.to_string(), path_only.to_string()))
}

fn check_aws_sts_credential(
    access_key_id: &str,
    secret_access_key: Option<&str>,
    session_token: Option<&str>,
) -> VerificationOutcome {
    let Some(secret_key) = secret_access_key else {
        return VerificationOutcome {
            verified: None,
            detail: Some(
                "AWS Access Key ID found without paired 40-char secret key in file".to_string(),
            ),
        };
    };
    if access_key_id.starts_with("ASIA") && session_token.is_none() {
        return VerificationOutcome {
            verified: None,
            detail: Some(
                "Temporary AWS ASIA key found without paired session token in file".to_string(),
            ),
        };
    }

    let url = endpoint_url("aws", "https://sts.amazonaws.com", "/");
    let Some((host_hdr, canonical_uri)) = parse_url_host_and_path(&url) else {
        return VerificationOutcome {
            verified: None,
            detail: Some("Invalid AWS STS endpoint URL".to_string()),
        };
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (date_stamp, amz_date) = format_utc_amz_datetime(now_secs);
    let body = b"Action=GetCallerIdentity&Version=2011-06-15";
    let payload_hash = hex_lower(&Sha256::digest(body));

    let (canonical_headers, signed_headers) = if let Some(tok) = session_token {
        (
            format!(
                "content-type:application/x-www-form-urlencoded\nhost:{host_hdr}\nx-amz-date:{amz_date}\nx-amz-security-token:{tok}\n"
            ),
            "content-type;host;x-amz-date;x-amz-security-token",
        )
    } else {
        (
            format!(
                "content-type:application/x-www-form-urlencoded\nhost:{host_hdr}\nx-amz-date:{amz_date}\n"
            ),
            "content-type;host;x-amz-date",
        )
    };

    let canonical_request =
        format!("POST\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let credential_scope = format!("{date_stamp}/us-east-1/sts/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_lower(&Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac_sha256(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, b"us-east-1");
    let k_service = hmac_sha256(&k_region, b"sts");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut hdrs = vec![
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("X-Amz-Date", amz_date.as_str()),
        ("Authorization", auth_header.as_str()),
    ];
    if let Some(tok) = session_token {
        hdrs.push(("X-Amz-Security-Token", tok));
    }

    match simple_http_exchange("POST", &url, &hdrs, Some(body), VERIFY_TIMEOUT) {
        Ok((200..=299, _, resp_body)) => {
            let acct = resp_body
                .split("<Account>")
                .nth(1)
                .and_then(|s| s.split("</Account>").next())
                .unwrap_or("verified");
            VerificationOutcome {
                verified: Some(true),
                detail: Some(format!(
                    "AWS STS GetCallerIdentity active (account: {acct})"
                )),
            }
        }
        Ok((401 | 403, _, resp_body)) => {
            let lower = resp_body.to_ascii_lowercase();
            if lower.contains("invalidclienttokenid")
                || lower.contains("expiredtoken")
                || lower.contains("invalidaccesskeyid")
                || lower.contains("signaturedoesnotmatch")
            {
                VerificationOutcome {
                    verified: Some(false),
                    detail: Some("AWS STS rejected credential pair".to_string()),
                }
            } else {
                VerificationOutcome {
                    verified: None,
                    detail: Some("AWS STS returned inconclusive 403".to_string()),
                }
            }
        }
        Ok((code, _, _)) => VerificationOutcome {
            verified: None,
            detail: Some(format!("HTTP {code} inconclusive on AWS STS")),
        },
        Err(e) => VerificationOutcome {
            verified: None,
            detail: Some(format!("AWS STS verification network error: {e}")),
        },
    }
}

fn endpoint_url(provider_slug: &str, default_origin: &str, path: &str) -> String {
    if let Ok(base_ovr) = std::env::var("LEAKTAP_VERIFY_BASE_URL") {
        let trimmed = base_ovr.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return format!("{trimmed}/{provider_slug}{path}");
        }
    }
    format!("{default_origin}{path}")
}

fn check_single_credential(rule_id: &str, secret: &str) -> VerificationOutcome {
    let bearer = format!("Bearer {secret}");

    match rule_id {
        "github-pat" => {
            let url = endpoint_url("github", "https://api.github.com", "/user");
            let hdrs = [
                ("Authorization", bearer.as_str()),
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2022-11-28"),
            ];
            classify_rest_check("GitHub API", &url, &hdrs, true)
        }
        "gitlab-pat" => {
            let url = endpoint_url(
                "gitlab",
                "https://gitlab.com",
                "/api/v4/personal_access_tokens/self",
            );
            let hdrs = [("PRIVATE-TOKEN", secret)];
            classify_rest_check("GitLab API", &url, &hdrs, false)
        }
        "slack-token" => {
            let url = endpoint_url("slack", "https://slack.com", "/api/auth.test");
            let hdrs = [
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ];
            match simple_http_exchange("POST", &url, &hdrs, Some(b""), VERIFY_TIMEOUT) {
                Ok((200..=299, _, body)) => {
                    if let Ok(val) = serde_json::from_str::<Value>(&body) {
                        if val.get("ok").and_then(Value::as_bool) == Some(true) {
                            let team = val
                                .get("team")
                                .and_then(Value::as_str)
                                .unwrap_or("workspace");
                            return VerificationOutcome {
                                verified: Some(true),
                                detail: Some(format!("Slack auth.test ok (team: {team})")),
                            };
                        }
                        let err = val
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("invalid_auth");
                        if matches!(
                            err,
                            "invalid_auth"
                                | "token_revoked"
                                | "token_expired"
                                | "account_inactive"
                                | "not_authed"
                        ) {
                            return VerificationOutcome {
                                verified: Some(false),
                                detail: Some(format!("Slack API rejected token ({err})")),
                            };
                        }
                    }
                    VerificationOutcome {
                        verified: None,
                        detail: Some("Slack API returned unexpected response".to_string()),
                    }
                }
                Ok((401, _, _)) => VerificationOutcome {
                    verified: Some(false),
                    detail: Some("HTTP 401 unauthorized on Slack API".to_string()),
                },
                Ok((code, _, _)) => VerificationOutcome {
                    verified: None,
                    detail: Some(format!("HTTP {code} inconclusive on Slack API")),
                },
                Err(e) => VerificationOutcome {
                    verified: None,
                    detail: Some(format!("Slack verification network error: {e}")),
                },
            }
        }
        "discord-webhook" => {
            let url = if let Ok(base_ovr) = std::env::var("LEAKTAP_VERIFY_BASE_URL") {
                let trimmed = base_ovr.trim().trim_end_matches('/');
                if !trimmed.is_empty() {
                    let path_part = secret
                        .find("/api/webhooks/")
                        .map(|i| &secret[i..])
                        .unwrap_or("/api/webhooks/unknown");
                    format!("{trimmed}/discord{path_part}")
                } else {
                    secret.to_string()
                }
            } else {
                secret.to_string()
            };
            match simple_http_exchange("GET", &url, &[], None, VERIFY_TIMEOUT) {
                Ok((200..=299, _, _)) => VerificationOutcome {
                    verified: Some(true),
                    detail: Some("HTTP 200 active Discord webhook".to_string()),
                },
                Ok((401 | 404, _, _)) => VerificationOutcome {
                    verified: Some(false),
                    detail: Some("Discord webhook revoked or deleted".to_string()),
                },
                Ok((code, _, _)) => VerificationOutcome {
                    verified: None,
                    detail: Some(format!("HTTP {code} inconclusive on Discord webhook")),
                },
                Err(e) => VerificationOutcome {
                    verified: None,
                    detail: Some(format!("Discord webhook check error: {e}")),
                },
            }
        }
        "stripe-live-key" => {
            let url = endpoint_url("stripe", "https://api.stripe.com", "/v1/charges?limit=1");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("Stripe API", &url, &hdrs, true)
        }
        "openai-api-key" => {
            let url = endpoint_url("openai", "https://api.openai.com", "/v1/models");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("OpenAI API", &url, &hdrs, false)
        }
        "anthropic-api-key" => {
            let url = endpoint_url("anthropic", "https://api.anthropic.com", "/v1/models");
            let hdrs = [("x-api-key", secret), ("anthropic-version", "2023-06-01")];
            classify_rest_check("Anthropic API", &url, &hdrs, false)
        }
        "openrouter-api-key" => {
            let url = endpoint_url("openrouter", "https://openrouter.ai", "/api/v1/auth/key");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("OpenRouter API", &url, &hdrs, false)
        }
        "groq-api-key" => {
            let url = endpoint_url("groq", "https://api.groq.com", "/openai/v1/models");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("Groq API", &url, &hdrs, false)
        }
        "xai-api-key" => {
            let url = endpoint_url("xai", "https://api.x.ai", "/v1/models");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("xAI API", &url, &hdrs, false)
        }
        "huggingface-token" => {
            let url = endpoint_url("huggingface", "https://huggingface.co", "/api/whoami-v2");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("HuggingFace API", &url, &hdrs, false)
        }
        "notion-api-token" => {
            let url = endpoint_url("notion", "https://api.notion.com", "/v1/users/me");
            let hdrs = [
                ("Authorization", bearer.as_str()),
                ("Notion-Version", "2022-06-28"),
            ];
            classify_rest_check("Notion API", &url, &hdrs, false)
        }
        "digitalocean-token" => {
            let url = endpoint_url(
                "digitalocean",
                "https://api.digitalocean.com",
                "/v2/account",
            );
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("DigitalOcean API", &url, &hdrs, false)
        }
        "vercel-access-token" => {
            let url = endpoint_url("vercel", "https://api.vercel.com", "/v2/user");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("Vercel API", &url, &hdrs, false)
        }
        "figma-pat" => {
            let url = endpoint_url("figma", "https://api.figma.com", "/v1/me");
            let hdrs = [("X-Figma-Token", secret)];
            classify_rest_check("Figma API", &url, &hdrs, false)
        }
        "postman-api-key" => {
            let url = endpoint_url("postman", "https://api.getpostman.com", "/me");
            let hdrs = [("X-Api-Key", secret)];
            classify_rest_check("Postman API", &url, &hdrs, false)
        }
        "replicate-api-token" => {
            let url = endpoint_url("replicate", "https://api.replicate.com", "/v1/account");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("Replicate API", &url, &hdrs, false)
        }
        "telegram-bot-token" => {
            let path = format!("/bot{secret}/getMe");
            let url = endpoint_url("telegram", "https://api.telegram.org", &path);
            classify_rest_check("Telegram Bot API", &url, &[], false)
        }
        "sendgrid-api-key" => {
            let url = endpoint_url("sendgrid", "https://api.sendgrid.com", "/v3/scopes");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("SendGrid API", &url, &hdrs, true)
        }
        "npm-access-token" => {
            let url = endpoint_url("npm", "https://registry.npmjs.org", "/-/whoami");
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("npm Registry", &url, &hdrs, false)
        }
        "cloudflare-api-token" => {
            let url = endpoint_url(
                "cloudflare",
                "https://api.cloudflare.com",
                "/client/v4/user/tokens/verify",
            );
            let hdrs = [("Authorization", bearer.as_str())];
            classify_rest_check("Cloudflare API", &url, &hdrs, false)
        }
        "datadog-api-key" => {
            let url = endpoint_url("datadog", "https://api.datadoghq.com", "/api/v1/validate");
            let hdrs = [("DD-API-KEY", secret)];
            classify_rest_check("Datadog API", &url, &hdrs, false)
        }
        "mailgun-api-key" => {
            let basic = format!("Basic {}", B64_STD.encode(format!("api:{secret}")));
            let url = endpoint_url("mailgun", "https://api.mailgun.net", "/v3/domains");
            let hdrs = [("Authorization", basic.as_str())];
            classify_rest_check("Mailgun API", &url, &hdrs, false)
        }
        _ => VerificationOutcome {
            verified: None,
            detail: None,
        },
    }
}

fn classify_rest_check(
    provider_label: &str,
    url: &str,
    headers: &[(&str, &str)],
    scoped_403_means_authenticated: bool,
) -> VerificationOutcome {
    match simple_http_exchange("GET", url, headers, None, VERIFY_TIMEOUT) {
        Ok((code @ 200..=299, _, _)) => VerificationOutcome {
            verified: Some(true),
            detail: Some(format!("HTTP {code} active on {provider_label}")),
        },
        Ok((401, _, _)) => VerificationOutcome {
            verified: Some(false),
            detail: Some(format!("HTTP 401 unauthorized/revoked on {provider_label}")),
        },
        Ok((403, resp_hdrs, body)) => {
            let lower = body.to_ascii_lowercase();
            if lower.contains("rate limit") || lower.contains("abuse detection") {
                return VerificationOutcome {
                    verified: None,
                    detail: Some(format!("HTTP 403 rate-limited on {provider_label}")),
                };
            }
            let has_oauth_scope_hdr = resp_hdrs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-oauth-scopes"));
            if scoped_403_means_authenticated
                && (has_oauth_scope_hdr
                    || lower.contains("resource not accessible")
                    || lower.contains("does not have the required permissions"))
            {
                return VerificationOutcome {
                    verified: Some(true),
                    detail: Some(format!(
                        "HTTP 403 authenticated (restricted scope) on {provider_label}"
                    )),
                };
            }
            if lower.contains("invalid")
                || lower.contains("revoked")
                || lower.contains("expired")
                || (provider_label == "Datadog API" && lower.contains("forbidden"))
            {
                return VerificationOutcome {
                    verified: Some(false),
                    detail: Some(format!("HTTP 403 rejected on {provider_label}")),
                };
            }
            VerificationOutcome {
                verified: None,
                detail: Some(format!("HTTP 403 inconclusive on {provider_label}")),
            }
        }
        Ok((code, _, _)) => VerificationOutcome {
            verified: None,
            detail: Some(format!("HTTP {code} inconclusive on {provider_label}")),
        },
        Err(e) => VerificationOutcome {
            verified: None,
            detail: Some(format!("{provider_label} verification network error: {e}")),
        },
    }
}
