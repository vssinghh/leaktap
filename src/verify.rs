use crate::api_tap::simple_http_exchange;
use crate::rules::{fingerprint_match, DocHints, RuleEngine};
use crate::scanner::TranscriptFinding;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_VERIFY_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone)]
struct VerificationOutcome {
    verified: Option<bool>,
    detail: Option<String>,
}

/// Opt-in (`leaktap scan --verify`) read-only live credential check against provider APIs.
/// Populates `verified: Some(true | false)` and `verification_detail` without storing raw secrets.
pub fn verify_secret_findings(findings: &mut [TranscriptFinding], engine: &RuleEngine) {
    let mut cache: HashMap<(String, String), VerificationOutcome> = HashMap::new();
    let mut file_text_cache: HashMap<(PathBuf, String), Option<String>> = HashMap::new();

    for finding in findings.iter_mut() {
        if !is_verifiable_rule(&finding.rule_id) {
            continue;
        }
        let cache_key = (finding.rule_id.clone(), finding.fingerprint.clone());
        if let Some(prev) = cache.get(&cache_key) {
            finding.verified = prev.verified;
            finding.verification_detail = prev.detail.clone();
            continue;
        }

        let file_key = (finding.first_path.clone(), finding.first_file.clone());
        let maybe_text = file_text_cache
            .entry(file_key)
            .or_insert_with(|| load_source_text(&finding.first_path, &finding.first_file));

        let Some(ref src_text) = maybe_text else {
            continue;
        };

        let Some(raw_secret) = extract_matching_secret(
            src_text,
            &finding.first_path,
            finding.first_line,
            &finding.rule_id,
            &finding.fingerprint,
            engine,
        ) else {
            continue;
        };

        let outcome = check_single_credential(&finding.rule_id, &raw_secret);
        finding.verified = outcome.verified;
        finding.verification_detail = outcome.detail.clone();
        cache.insert(cache_key, outcome);
    }
}

fn is_verifiable_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "github-pat"
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
) -> Option<String> {
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
) -> Option<String> {
    let hints = DocHints::from_text(text);
    for m in engine.scan_text_with_hints(text, Some(path), hints) {
        if m.rule_id == rule_id
            && m.fingerprint == target_fp
            && m.end <= text.len()
            && text.is_char_boundary(m.start)
            && text.is_char_boundary(m.end)
        {
            let slice = &text[m.start..m.end];
            if fingerprint_match(rule_id, slice) == target_fp {
                return Some(slice.to_string());
            }
        }
    }
    None
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
            if lower.contains("invalid") || lower.contains("revoked") || lower.contains("expired") {
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
