use crate::config::PolicyConfig;
use aho_corasick::AhoCorasick;
use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
        }
    }

    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
        }
    }

    pub fn security_severity_score(&self) -> &'static str {
        match self {
            Severity::Critical => "9.5",
            Severity::High => "7.5",
            Severity::Medium => "5.0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Secret,
    Pii,
}

pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: RuleCategory,
    pub anchors: Vec<String>,
    pub regex: Regex,
    /// Capture group containing the sensitive value (0 = full match)
    pub secret_group: usize,
    /// Minimum Shannon entropy required on the captured secret (0.0 = skip check)
    pub min_entropy: f64,
    /// If `Some(idx)`, this custom rule came from `policy.scoped_policies[idx]` and ONLY runs inside that project root.
    pub scoped_policy_idx: Option<usize>,
}

pub const MAX_B64_CANDIDATE_CHARS: usize = 131_072;
const MAX_B64_DECODED_BYTES: usize = 98_304;

#[derive(Debug, Clone)]
pub struct RawMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub category: RuleCategory,
    /// Byte start of the sensitive value within the scanned text
    pub start: usize,
    /// Byte end of the sensitive value within the scanned text
    pub end: usize,
    pub masked: String,
    pub fingerprint: String,
    /// Variable, header, or query parameter name when matched via a key=value rule (e.g. `PROD_DB_PASSWORD`)
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DocHints {
    pub has_gcp_sa: bool,
    pub has_jwk_asymmetric_kty: bool,
    pub has_jwk_d_param: bool,
    pub has_jwk_oct_kty: bool,
    pub is_k8s_secret_manifest: bool,
    pub in_k8s_data_entry: bool,
    pub in_k8s_string_data_entry: bool,
}

impl DocHints {
    pub fn from_text(text: &str) -> Self {
        let lower = text.to_ascii_lowercase();
        let has_gcp_sa =
            lower.contains("service_account") || lower.contains(".iam.gserviceaccount.com");
        let has_kty =
            text.contains("\"kty\"") || text.contains("\\\"kty\\\"") || text.contains("'kty'");
        let has_jwk_asymmetric_kty = has_kty
            && (text.contains("\"RSA\"")
                || text.contains("\\\"RSA\\\"")
                || text.contains("'RSA'")
                || text.contains("\"EC\"")
                || text.contains("\\\"EC\\\"")
                || text.contains("'EC'")
                || text.contains("\"OKP\"")
                || text.contains("\\\"OKP\\\"")
                || text.contains("'OKP'"));
        let has_jwk_d_param =
            text.contains("\"d\"") || text.contains("\\\"d\\\"") || text.contains("'d'");
        let has_jwk_oct_kty = has_kty
            && (text.contains("\"oct\"") || text.contains("\\\"oct\\\"") || text.contains("'oct'"));
        let has_k8s_kind_secret =
            (text.contains("kind:") || text.contains("\"kind\"") || text.contains("\\\"kind\\\""))
                && text.contains("Secret");
        let has_k8s_data = text.contains("data:")
            || text.contains("stringData:")
            || text.contains("\"data\"")
            || text.contains("\\\"data\\\"")
            || text.contains("\"stringData\"")
            || text.contains("\\\"stringData\\\"");
        Self {
            has_gcp_sa,
            has_jwk_asymmetric_kty,
            has_jwk_d_param,
            has_jwk_oct_kty,
            is_k8s_secret_manifest: has_k8s_kind_secret && has_k8s_data,
            in_k8s_data_entry: false,
            in_k8s_string_data_entry: false,
        }
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            has_gcp_sa: self.has_gcp_sa || other.has_gcp_sa,
            has_jwk_asymmetric_kty: self.has_jwk_asymmetric_kty || other.has_jwk_asymmetric_kty,
            has_jwk_d_param: self.has_jwk_d_param || other.has_jwk_d_param,
            has_jwk_oct_kty: self.has_jwk_oct_kty || other.has_jwk_oct_kty,
            is_k8s_secret_manifest: self.is_k8s_secret_manifest || other.is_k8s_secret_manifest,
            in_k8s_data_entry: self.in_k8s_data_entry || other.in_k8s_data_entry,
            in_k8s_string_data_entry: self.in_k8s_string_data_entry
                || other.in_k8s_string_data_entry,
        }
    }
}

/// Tracks whether a line in a YAML or JSON `kind: Secret` manifest sits inside `data` or `stringData`,
/// including multi-document YAML (`---`) streams mixing `Secret` with `ConfigMap` / `Deployment`.
#[derive(Debug, Clone, Copy, Default)]
pub struct K8sDataTracker {
    yaml_indent: Option<(usize, bool)>, // (indent_cols, is_string_data)
    json_depth: Option<(usize, bool)>,  // (brace_depth, is_string_data)
    doc_kind_is_secret: Option<bool>,
}

impl K8sDataTracker {
    pub fn is_active_secret_doc(&self, fallback: bool) -> bool {
        self.doc_kind_is_secret.unwrap_or(fallback)
    }

    pub fn is_tracking(&self) -> bool {
        self.doc_kind_is_secret.is_some() || self.yaml_indent.is_some() || self.json_depth.is_some()
    }

    pub fn observe_line(&mut self, line: &str) -> (bool, bool) {
        let trimmed_cr = line.trim_end_matches(['\r', '\n']);
        let leading_ws = trimmed_cr
            .bytes()
            .take_while(|&b| b == b' ' || b == b'\t')
            .count();
        let trimmed = trimmed_cr[leading_ws..].trim_end();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            return (false, false);
        }
        if trimmed == "---" || trimmed.starts_with("--- ") || trimmed == "..." {
            self.yaml_indent = None;
            self.json_depth = None;
            self.doc_kind_is_secret = None;
            return (false, false);
        }

        if let Some(is_sec) = detect_k8s_kind_line(trimmed, leading_ws) {
            self.doc_kind_is_secret = Some(is_sec);
            if !is_sec {
                self.yaml_indent = None;
                self.json_depth = None;
                return (false, false);
            }
        }

        let allowed_doc = self.doc_kind_is_secret != Some(false);

        // JSON multiline tracking (`"data": {` ... `}`)
        if let Some((mut depth, is_str_data)) = self.json_depth {
            let opens = trimmed.bytes().filter(|&b| b == b'{').count();
            let closes = trimmed.bytes().filter(|&b| b == b'}').count();
            depth = depth.saturating_add(opens);
            if closes >= depth {
                self.json_depth = None;
                return (false, false);
            }
            self.json_depth = Some((depth - closes, is_str_data));
            return if allowed_doc {
                (!is_str_data, is_str_data)
            } else {
                (false, false)
            };
        }

        if let Some(is_str_data) = detect_json_k8s_data_open(trimmed) {
            if !trimmed.contains('}') {
                self.json_depth = Some((1, is_str_data));
            }
            return if allowed_doc {
                (!is_str_data, is_str_data)
            } else {
                (false, false)
            };
        }

        // YAML block mapping tracking (`data:` / `stringData:`)
        if let Some((base_indent, is_str_data)) = self.yaml_indent {
            if leading_ws > base_indent {
                return if allowed_doc {
                    (!is_str_data, is_str_data)
                } else {
                    (false, false)
                };
            }
            self.yaml_indent = None;
        }

        if trimmed == "data:" || trimmed.starts_with("data: #") {
            self.yaml_indent = Some((leading_ws, false));
            return (false, false);
        }
        if trimmed == "stringData:" || trimmed.starts_with("stringData: #") {
            self.yaml_indent = Some((leading_ws, true));
            return (false, false);
        }

        (false, false)
    }
}

fn detect_k8s_kind_line(trimmed: &str, leading_ws: usize) -> Option<bool> {
    if leading_ws <= 2 {
        if let Some(rest) = trimmed.strip_prefix("kind:") {
            let val = rest
                .split(" #")
                .next()
                .unwrap_or(rest)
                .trim()
                .trim_matches(['"', '\'', ',']);
            if !val.is_empty() {
                return Some(val == "Secret");
            }
        }
    }
    for key in ["\"kind\"", "\\\"kind\\\""] {
        if let Some(pos) = trimmed.find(key) {
            let rest = trimmed[pos + key.len()..].trim_start();
            if let Some(after_colon) = rest.strip_prefix(':') {
                let val = after_colon
                    .trim_start()
                    .trim_start_matches(['"', '\'', '\\'])
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric())
                    .collect::<Vec<u8>>();
                if !val.is_empty() {
                    return Some(val.as_slice() == b"Secret");
                }
            }
        }
    }
    None
}

fn detect_json_k8s_data_open(trimmed: &str) -> Option<bool> {
    for (key, is_str) in [
        ("\"data\"", false),
        ("\\\"data\\\"", false),
        ("\"stringData\"", true),
        ("\\\"stringData\\\"", true),
    ] {
        if let Some(pos) = trimmed.find(key) {
            let rest = trimmed[pos + key.len()..].trim_start();
            if let Some(after_colon) = rest.strip_prefix(':') {
                if after_colon.trim_start().starts_with('{') {
                    return Some(is_str);
                }
            }
        }
    }
    None
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    prefilter: AhoCorasick,
    anchor_to_rule: Vec<usize>,
    unanchored_rules: Vec<usize>,
    b64_rule_enabled: bool,
    hex_rule_enabled: bool,
    k8s_rule_enabled: bool,
    policy: Option<PolicyConfig>,
}

struct RuleSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    severity: Severity,
    category: RuleCategory,
    anchors: &'static [&'static str],
    pattern: &'static str,
    secret_group: usize,
    min_entropy: f64,
}

const RULE_SPECS: &[RuleSpec] = &[
    RuleSpec {
        id: "stripe-live-key",
        name: "Stripe Live Key",
        description: "Live Stripe secret, restricted API key, or webhook signing secret.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk_live_", "rk_live_", "whsec_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:(?:sk|rk)_live|whsec)_[0-9a-zA-Z]{24,99})\b"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "aws-access-key",
        name: "AWS Access Key",
        description: "AWS IAM access key ID or STS session key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["AKIA", "ASIA", "AGPA", "AIDA", "AROA"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b"#,
        secret_group: 1,
        min_entropy: 3.0,
    },
    RuleSpec {
        id: "aws-secret-key",
        name: "AWS Secret Key",
        description: "40-character AWS secret access key in env, config, or STS JSON credentials.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[
            "AWS_SECRET_ACCESS_KEY",
            "aws_secret_access_key",
            "AwsSecretAccessKey",
            "SecretAccessKey",
            "secretAccessKey",
            "aws_secret_key",
            "aws_secret",
        ],
        pattern: r#"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|AwsSecretAccessKey|SecretAccessKey|secretAccessKey|aws_secret_key|aws_secret)(?:\\"|\\+u002[27]|["'])?\s*(?:[:=]|\\+u003[aAdD])\s*(?:\\"|\\+u002[27]|["'])?([A-Za-z0-9/+=]{40})(?:$|[^A-Za-z0-9/+=]|\\+u00[0-3][0-9a-fA-F]|\\[nrt"'\\])"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "anthropic-api-key",
        name: "Anthropic Key / OAuth Token",
        description: "Anthropic API key or Claude Code OAuth/session token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk-ant-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sk-ant-(?:api\d+|admin\d+|oat\d+|sid\d+)-[A-Za-z0-9\-_]{24,160})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "openai-api-key",
        name: "OpenAI API Key",
        description: "OpenAI project, service-account, admin, or legacy API key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk-proj-", "sk-svcacct-", "sk-admin-", "T3BlbkFJ"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{32,200}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}))\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "github-pat",
        name: "GitHub PAT",
        description: "GitHub classic or fine-grained personal access / OAuth token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "gitlab-pat",
        name: "GitLab Token",
        description: "GitLab personal, OAuth, agent, deploy, pipeline trigger, or runner token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[
            "glpat-",
            "gldt-",
            "glrt-",
            "gloas-",
            "glagent-",
            "glsoat-",
            "glptt-",
            "glft-",
        ],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:glpat|gldt|glrt|gloas|glagent|glsoat|glptt|glft)-[A-Za-z0-9\-_.]{20,128})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "gcp-api-key",
        name: "Google Cloud API Key",
        description: "Google Cloud / Firebase / Gemini `AIza` API key.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["AIza"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(AIza[0-9A-Za-z\-_]{35})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "google-oauth-token",
        name: "Google OAuth Access Token",
        description: "Google Cloud / Workspace OAuth 2.0 bearer access token (`ya29....`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["ya29."],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(ya29\.[0-9A-Za-z\-_]{40,512})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "gcp-service-account-key",
        name: "GCP Service Account Key",
        description: "Google Cloud service account credential JSON (`private_key_id`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["private_key_id"],
        pattern: r#"private_key_id(?:\\"|\\+u002[27]|["'])\s*(?:[:=]|\\+u003[aAdD])\s*(?:\\"|\\+u002[27]|["'])([a-f0-9]{40})(?:\\"|\\+u002[27]|["'])"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "azure-storage-key",
        name: "Azure Storage Account Key",
        description: "Azure Storage connection string `AccountKey` secret.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["AccountKey"],
        pattern: r#"AccountKey\s*=\s*([A-Za-z0-9+/]{40,120}={0,2})"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "supabase-secret-key",
        name: "Supabase Secret / Access Token",
        description: "Supabase secret API key (`sb_secret_...`) or personal access token (`sbp_...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sb_secret_", "sbp_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sb_secret_[A-Za-z0-9\-_]{20,120}|sbp_[a-f0-9]{40})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "shopify-access-token",
        name: "Shopify Access Token",
        description: "Shopify Admin, custom app, or shared secret token (`shpat_`, `shpca_`, `shppa_`, `shpss_`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["shpat_", "shpca_", "shppa_", "shpss_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32,64})\b"#,
        secret_group: 1,
        min_entropy: 3.3,
    },
    RuleSpec {
        id: "slack-token",
        name: "Slack Token",
        description: "Slack bot, user, workspace, or app-level token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:xox[baprs]|xapp)-[0-9A-Za-z\-]{24,160})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "slack-webhook",
        name: "Slack Webhook URL",
        description: "Incoming Slack webhook URL allowing external message posting.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["hooks.slack.com/services/"],
        pattern: r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,30})",
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "huggingface-token",
        name: "Hugging Face Token",
        description: "Hugging Face Hub access token.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["hf_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(hf_[A-Za-z0-9]{34,64})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "groq-api-key",
        name: "Groq API Key",
        description: "Groq Cloud inference API key (`gsk_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["gsk_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(gsk_[A-Za-z0-9]{48,64})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "perplexity-api-key",
        name: "Perplexity API Key",
        description: "Perplexity Sonar API key (`pplx-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["pplx-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pplx-[A-Za-z0-9]{40,64})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "linear-api-key",
        name: "Linear API Key",
        description: "Linear personal API key (`lin_api_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["lin_api_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(lin_api_[A-Za-z0-9]{36,64})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "postman-api-key",
        name: "Postman API Key",
        description: "Postman workspace API key (`PMAK-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["PMAK-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "npm-access-token",
        name: "npm Access Token",
        description: "npm registry publish or automation token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["npm_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(npm_[A-Za-z0-9]{36})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "pypi-upload-token",
        name: "PyPI Upload Token",
        description: "PyPI package publishing API token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["pypi-AgEIcHlwaS5vcmc"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,200})\b"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "sendgrid-api-key",
        name: "SendGrid API Key",
        description: "SendGrid transactional email API key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["SG."],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "vault-token",
        name: "HashiCorp Vault Token",
        description: "HashiCorp Vault service or batch authentication token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["hvs.", "hvb."],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(hv[sb]\.[A-Za-z0-9_\-]{24,160})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "digitalocean-token",
        name: "DigitalOcean Token",
        description: "DigitalOcean personal access, OAuth, or refresh token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["dop_v1_", "doo_v1_", "dor_v1_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(do[por]_v1_[a-f0-9]{64})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "databricks-pat",
        name: "Databricks PAT",
        description: "Databricks workspace personal access token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["dapi"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(dapi[a-f0-9]{32})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "age-secret-key",
        name: "Age Secret Key",
        description: "Age / SOPS private encryption key (`AGE-SECRET-KEY-1...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["AGE-SECRET-KEY-1"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(AGE-SECRET-KEY-1[A-Z0-9]{58})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "private-key-pem",
        name: "Private Key Block",
        description: "PEM or OpenPGP RSA, EC, OpenSSH, DSA, PGP, or PKCS#8 private key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["-----BEGIN "],
        // Requires a real base64 key body after the BEGIN header without ever crossing JSON quotes (`"`),
        // catching full keys, OpenPGP `PRIVATE KEY BLOCK` keys, AND truncated `head -n 2 id_rsa` keys
        // (including trailing short `< 16`-char Base64 padding lines) while ignoring bare header mentions in prose.
        pattern: r#"(-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+(?:[ \t]*[A-Za-z0-9-]+:[ \t]*[^\r\n"'`{}\[\]\\]+(?:[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA]))+)*[ \t]*[A-Za-z0-9+/=]{16,}(?:[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+[ \t]*[A-Za-z0-9+/=]{16,})*(?:(?:[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+[ \t]*[A-Za-z0-9+/]{1,76}={0,2})?[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+(?:[ \t]*=[A-Za-z0-9+/=]{4}[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+)?-----END (?:(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|(?:[ \t]*(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])+[ \t]*(?:[A-Za-z0-9+/]{2,15}={1,2}|[A-Za-z0-9+/]{0,15}[0-9+/][A-Za-z0-9+/]{2,15}={0,2}))?))"#,
        secret_group: 1,
        min_entropy: 0.0,
    },
    RuleSpec {
        id: "database-uri",
        name: "Database URI",
        description: "Connection URL with embedded credentials (Postgres, MySQL, MongoDB, Redis, or AMQP).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[
            "postgres://",
            "postgresql://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "rediss://",
            "amqp://",
            "amqps://",
        ],
        pattern: r#"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s"':/@\\`]{0,64}:[^\s"'/@\\`]{6,128}@[^\s"'<>\\`()\[\]{},;]+)"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "http-basic-auth-url",
        name: "HTTP Basic Auth URL",
        description: "HTTP/HTTPS or Git URL containing embedded username and password credentials.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["https://", "http://"],
        pattern: r#"(https?://[^\s"':/@\\`]{1,64}:[^\s"'/@\\`]{6,128}@[^\s"'<>\\`()\[\]{},;]+)"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "jwt-token",
        name: "JWT Bearer Token",
        description: "Signed JSON Web Token appearing in headers, logs, or tool payloads.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["eyJ"],
        pattern: r#"(?:^|[^A-Za-z0-9_\-\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,})\b"#,
        secret_group: 1,
        min_entropy: 3.9,
    },
    RuleSpec {
        id: "http-bearer-token",
        name: "HTTP Bearer Token",
        description: "High-entropy opaque Bearer token in Authorization or X-Auth-Token header.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["Bearer ", "bearer "],
        pattern: r#"(?i)\b(?:authorization|proxy-authorization|x-auth-token)(?:\\"|["'])?\s*[:=]\s*(?:\\"|["'])?bearer\s+([A-Za-z0-9_\-\.~+/]{20,512}={0,2})"# ,
        secret_group: 1,
        min_entropy: 3.85,
    },
    RuleSpec {
        id: "url-query-secret",
        name: "URL / JDBC Query Secret",
        description: "Password, API key, or access token passed in a URL or JDBC query parameter.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &[
            "password=",
            "passwd=",
            "pwd=",
            "api_key=",
            "apikey=",
            "access_token=",
            "client_secret=",
            "auth_token=",
            "PASSWORD=",
            "API_KEY=",
        ],
        pattern: r#"(?i)[?&;](?:password|passwd|pwd|api_key|apikey|access_token|client_secret|auth_token)=([A-Za-z0-9/+=\-_!@#$%^*~]{12,160})"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "discord-webhook",
        name: "Discord Webhook URL",
        description: "Discord incoming webhook URL with embedded secret token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["discord.com/api/webhooks/", "discordapp.com/api/webhooks/"],
        pattern: r#"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,76})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "resend-api-key",
        name: "Resend API Key",
        description: "Resend email service API key (`re_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["re_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(re_[A-Za-z0-9_]{24,64})\b"#,
        secret_group: 1,
        min_entropy: 3.7,
    },
    RuleSpec {
        id: "twilio-api-key",
        name: "Twilio API Key",
        description: "Twilio standard or restricted API key (`SK...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["SK"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(SK[0-9a-f]{32})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "sentry-auth-token",
        name: "Sentry Auth Token",
        description: "Sentry organization or user authentication token (`sntrys_...` / `sntryu_...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sntrys_", "sntryu_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sntry[su]_[A-Za-z0-9_+/=]{32,256})"# ,
        secret_group: 1,
        min_entropy: 3.7,
    },
    RuleSpec {
        id: "grafana-token",
        name: "Grafana Service Account / Cloud Token",
        description: "Grafana service account (`glsa_...`) or Grafana Cloud (`glc_...`) token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["glsa_", "glc_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:glsa_[A-Za-z0-9_]{32,64}|glc_[A-Za-z0-9_+/=]{32,160}))"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "planetscale-token",
        name: "PlanetScale Token / Password",
        description: "PlanetScale database password, service token, or OAuth token (`pscale_...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["pscale_tkn_", "pscale_pw_", "pscale_oauth_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_]{32,64})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "flyio-token",
        name: "Fly.io Access Token",
        description: "Fly.io organization or macaroon deploy token (`fo1_...` / `fm2_...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["fo1_", "fm2_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:fo1_[A-Za-z0-9_\-]{32,64}|fm2_[A-Za-z0-9+/=_\-]{32,256}))"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "telegram-bot-token",
        name: "Telegram Bot Token",
        description: "Telegram Bot HTTP API authentication token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[":AA"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])([0-9]{8,11}:AA[A-Za-z0-9_\-]{33})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "azure-sas-token",
        name: "Azure Shared Access Signature (SAS)",
        description: "Azure Storage / Service Bus SAS URL signature parameter (`sig=...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["sig="],
        pattern: r#"[?&]sig=([A-Za-z0-9%+/=]{40,128})(?:$|[^A-Za-z0-9%+/=])"#,
        secret_group: 1,
        min_entropy: 3.7,
    },
    RuleSpec {
        id: "terraform-api-token",
        name: "Terraform Cloud / Enterprise Token",
        description: "HashiCorp Terraform Cloud or Enterprise API token (`*.atlasv1.*`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[".atlasv1."],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,72})"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "doppler-api-token",
        name: "Doppler API Token",
        description: "Doppler service, personal, CLI, or SCIM token (`dp.st.*` / `dp.pt.*` / `dp.ct.*`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["dp.st.", "dp.pt.", "dp.ct.", "dp.scim."],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(dp\.(?:st|pt|ct|scim)\.(?:[a-z0-9_\-]{2,40}\.)?[A-Za-z0-9]{40,48})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "newrelic-api-key",
        name: "New Relic API Key",
        description: "New Relic user (`NRAK-*`), ingest (`NRII-*`), or browser (`NRJS-*`) API key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["NRAK-", "NRII-", "NRJS-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:NRAK|NRII)-[A-Z0-9]{27}|NRJS-[a-f0-9]{19})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "buildkite-agent-token",
        name: "Buildkite API / Agent Token",
        description: "Buildkite user API access token (`bkua_*`) or agent registration token (`bkagent_*`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["bkua_", "bkagent_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:bkua|bkagent)_[A-Za-z0-9]{36,48})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "discord-bot-token",
        name: "Discord Bot Token",
        description: "Discord application bot authentication token (`<snowflake_b64>.<ts>.<hmac>`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["MT", "Mj", "Mz", "ND", "NT", "Nj", "Nz", "OD", "OT"],
        pattern: r#"(?:^|[^A-Za-z0-9_.\-\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:MT|Mj|Mz|ND|NT|Nj|Nz|OD|OT)[A-Za-z0-9_\-]{21,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,42})(?:$|[^A-Za-z0-9_.\-])"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "atlassian-api-token",
        name: "Atlassian API Token",
        description: "Atlassian Jira / Confluence personal or service API token (`ATATT3xFfGF0...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["ATATT3xFfGF0", "ATCTT3xFfGN0"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(AT[AC]TT3xFfG[FN]0[A-Za-z0-9+/=_\-]{48,220})"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "putty-private-key",
        name: "PuTTY Private Key (PPK)",
        description: "PuTTY SSH private key file block (`PuTTY-User-Key-File-2` / `PuTTY-User-Key-File-3`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["PuTTY-User-Key-File-"],
        pattern: r#"(PuTTY-User-Key-File-[23]:\s*[A-Za-z0-9\-]+(?:\\r\\n|\\n|\r?\n)[^\x00"]{20,2048}?Private-Lines:\s*[0-9]+(?:\\r\\n|\\n|\r?\n)[A-Za-z0-9+/=\\r\\n\r\n ]{24,4096})"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "openrouter-api-key",
        name: "OpenRouter API Key",
        description: "OpenRouter LLM gateway API key (`sk-or-v1-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk-or-v1-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sk-or-v1-[a-f0-9]{64})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "xai-api-key",
        name: "xAI / Grok API Key",
        description: "xAI (Grok) inference API key (`xai-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["xai-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(xai-[A-Za-z0-9]{32,128})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "replicate-api-token",
        name: "Replicate API Token",
        description: "Replicate model inference API token (`r8_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["r8_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(r8_[A-Za-z0-9]{35,45})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "langsmith-api-key",
        name: "LangSmith / LangChain API Key",
        description: "LangSmith personal or service API key (`lsv2_pt_...` / `lsv2_sk_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["lsv2_pt_", "lsv2_sk_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{8,16})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "pinecone-api-key",
        name: "Pinecone API Key",
        description: "Pinecone vector database API key (`pcsk_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["pcsk_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pcsk_[A-Za-z0-9_]{35,100})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "google-oauth-client-secret",
        name: "Google OAuth Client Secret",
        description: "Google Cloud OAuth 2.0 client secret (`GOCSPX-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["GOCSPX-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(GOCSPX-[A-Za-z0-9_\-]{24,40})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "tailscale-api-key",
        name: "Tailscale Auth / API Key",
        description: "Tailscale tailnet auth, API, OAuth client, or SCIM key (`tskey-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["tskey-auth-", "tskey-api-", "tskey-client-", "tskey-scim-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(tskey-(?:auth|api|client|scim)-[A-Za-z0-9_\-]{20,96})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "pulumi-access-token",
        name: "Pulumi Access Token",
        description: "Pulumi Cloud personal, organization, or team access token (`pul-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["pul-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pul-[a-f0-9]{40})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "tavily-api-key",
        name: "Tavily API Key",
        description: "Tavily AI search MCP / SDK API key (`tvly-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["tvly-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(tvly-(?:dev-|prod-)?[A-Za-z0-9_\-]{28,64})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "neon-api-key",
        name: "Neon Postgres API Key",
        description: "Neon serverless Postgres API key (`napi_...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["napi_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(napi_[a-z0-9]{50,80})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "cerebras-api-key",
        name: "Cerebras API Key",
        description: "Cerebras inference API key (`csk-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["csk-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(csk-[A-Za-z0-9]{40,64})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "fireworks-api-key",
        name: "Fireworks AI API Key",
        description: "Fireworks AI inference API key (`fw_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["fw_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(fw_[A-Za-z0-9]{24,64})\b"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "dotenv-generic-secret",
        name: "Secret Assignment",
        description: "High-entropy secret assigned to API_KEY, PASSWORD, SECRET, TOKEN, or camelCase/snake_case secret fields in .env, shell, YAML, or JSON.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &[
            "_SECRET",
            "_API_KEY",
            "_TOKEN",
            "_PRIVATE_KEY",
            "_ENCRYPTION_KEY",
            "_MASTER_KEY",
            "_SIGNING_KEY",
            "_SERVICE_ROLE_KEY",
            "_SERVICE_KEY",
            "_STORAGE_KEY",
            "_AUTH_KEY",
            "_HMAC_KEY",
            "_PASSWORD",
            "_PASSWD",
            "_PASS",
            "_PWD",
            "_PAT",
            "API_KEY",
            "SECRET_KEY",
            "ACCESS_TOKEN",
            "AUTH_TOKEN",
            "REFRESH_TOKEN",
            "PRIVATE_KEY",
            "PASSWORD",
            "PASSWD",
            "SECRET",
            "TOKEN",
            "DB_PASSWORD",
            "DATABASE_PASSWORD",
            "MYSQL_PWD",
            "PGPASSWORD",
            "CLIENT_SECRET",
            "WEBHOOK_SECRET",
            "ENCRYPTION_KEY",
            "MASTER_KEY",
            "SIGNING_KEY",
            "APP_KEY",
            "_secret",
            "_api_key",
            "_token",
            "_password",
            "_passwd",
            "_pass",
            "_private_key",
            "_encryption_key",
            "_master_key",
            "_signing_key",
            "_service_role_key",
            "_service_key",
            "_storage_key",
            "api_key",
            "password",
            "passwd",
            "secret",
            "token",
            "client_secret",
            "webhook_secret",
            "encryption_key",
            "master_key",
            "signing_key",
            "secret_key",
            "app_key",
            "_APP_KEY",
            "_app_key",
            "_APPKEY",
            "_appkey",
            "-app-key",
            "app-key",
            "appKey",
            "AppKey",
            "APIKEY",
            "apikey",
            "_APIKEY",
            "_apikey",
            "apiKey",
            "secretKey",
            "clientSecret",
            "accessToken",
            "authToken",
            "refreshToken",
            "privateKey",
            "signingKey",
            "encryptionKey",
            "masterKey",
            "webhookSecret",
            "dbPassword",
            "databasePassword",
            "redisPassword",
            "bearerToken",
            "sessionSecret",
            "jwtSecret",
            "appSecret",
            "serviceRoleKey",
            "storageKey",
            "accessKeySecret",
            "api-key",
            "client-secret",
            "access-token",
        ],
        pattern: r#"(?:^|[^A-Za-z0-9_.\-\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(?:[A-Za-z][A-Za-z0-9_\-]*(?:_SECRET|_SECRET_KEY|_SECRET_KEY_BASE|_API_KEY|_APIKEY|_APP_KEY|_APPKEY|_ACCESS_TOKEN|_AUTH_TOKEN|_OAUTH_TOKEN|_REFRESH_TOKEN|_PRIVATE_KEY|_ENCRYPTION_KEY|_MASTER_KEY|_SIGNING_KEY|_SERVICE_ROLE_KEY|_SERVICE_KEY|_STORAGE_KEY|_AUTH_KEY|_HMAC_KEY|_PASSWORD|_PASSWD|_PASS|_PWD|_PAT|_TOKEN|_secret|_secret_key|_secret_key_base|_api_key|_apikey|_app_key|_appkey|_access_token|_auth_token|_oauth_token|_refresh_token|_private_key|_encryption_key|_master_key|_signing_key|_service_role_key|_service_key|_storage_key|_auth_key|_hmac_key|_password|_passwd|_pass|_token|-secret|-api-key|-app-key|-access-token|-auth-token|-refresh-token|-private-key|-password|ApiKey|AppKey|SecretKey|ClientSecret|AccessToken|AuthToken|RefreshToken|PrivateKey|SigningKey|EncryptionKey|MasterKey|WebhookSecret|Password)|API_KEY|APIKEY|SECRET_KEY|SECRET_KEY_BASE|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN|PRIVATE_KEY|DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PWD|PGPASSWORD|CLIENT_SECRET|WEBHOOK_SECRET|ENCRYPTION_KEY|MASTER_KEY|SIGNING_KEY|APP_KEY|PASSWORD|PASSWD|SECRET|TOKEN|api_key|apikey|client_secret|webhook_secret|encryption_key|master_key|signing_key|secret_key|secret_key_base|app_key|access_token|auth_token|refresh_token|private_key|password|passwd|apiKey|appKey|secretKey|clientSecret|accessToken|authToken|refreshToken|privateKey|signingKey|encryptionKey|masterKey|webhookSecret|dbPassword|databasePassword|redisPassword|bearerToken|sessionSecret|jwtSecret|appSecret|serviceRoleKey|storageKey|accessKeySecret|api-key|app-key|client-secret|access-token)(?:\\+"|\\+u002[27]|["'])?(?:[ \t]*:[ \t]*[|>][0-9]*[-+]?[0-9]*[ \t]*(?:#[^\r\n\\]*)?(?:\r?\n|(?:\\+r)?\\+n|(?:\\+u000[dD])?\\+u000[aA])[ \t]+([A-Za-z0-9/+=\-_!@#$%^&*~.?]{12,180})|\s*(?:[:=]|\\+u003[aAdD])\s*(?:\\+"|\\+u002[27]|["'])?([A-Za-z0-9/+=\-_!@#$%^&*~.?]{16,180})(?:\\+"|\\+u002[27]|["'])?)"#,
        secret_group: 1,
        min_entropy: 3.30,
    },
    RuleSpec {
        id: "jwk-private-key",
        name: "JSON Web Key (JWK) Private Key",
        description: "RFC 7517 / RFC 7518 JWK asymmetric (`d`, `p`, `q`, `dp`, `dq`, `qi`) or symmetric (`k`) private key material.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[
            "\"d\"", "\\\"d\\\"", "'d'", "\"p\"", "\\\"p\\\"", "\"q\"", "\\\"q\\\"", "\"dp\"",
            "\\\"dp\\\"", "\"dq\"", "\\\"dq\\\"", "\"qi\"", "\\\"qi\\\"", "\"k\"", "\\\"k\\\"",
            "'k'",
        ],
        pattern: r#"(?:\\+"|["'])(?:d|p|q|dp|dq|qi|k)(?:\\+"|["'])\s*:\s*(?:\\+"|["'])([A-Za-z0-9+/_=\-]{22,1024})(?:\\+"|["'])"#,
        secret_group: 1,
        min_entropy: 3.30,
    },
    RuleSpec {
        id: "kubernetes-secret-data",
        name: "Kubernetes Secret Manifest Data",
        description: "Base64-encoded secret payload inside a Kubernetes `kind: Secret` manifest `data` map.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        // Handled contextually in `scan_text_inner` when `DocHints.is_k8s_secret_manifest` is active.
        anchors: &[],
        pattern: r"([A-Za-z0-9+/]{12,}={0,2})",
        secret_group: 1,
        min_entropy: 3.0,
    },
    RuleSpec {
        id: "notion-api-token",
        name: "Notion Integration Token",
        description: "Notion internal or OAuth integration secret (`ntn_...` / `secret_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["ntn_", "secret_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:ntn_[0-9A-Za-z]{40,60}|secret_[A-Za-z0-9]{43}))\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "airtable-pat",
        name: "Airtable Personal Access Token",
        description: "Airtable scoped personal access token (`pat<14>.<64-hex>`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["pat"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b"#,
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "hubspot-pat",
        name: "HubSpot Private App Token",
        description: "HubSpot private app access token (`pat-na1-...` / `pat-eu1-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["pat-na1-", "pat-eu1-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pat-(?:na1|eu1)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"#,
        secret_group: 1,
        min_entropy: 3.2,
    },
    RuleSpec {
        id: "square-access-token",
        name: "Square Access Token / Secret",
        description: "Square OAuth access token or application secret (`sq0atp-...` / `sq0csp-...`).",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sq0atp-", "sq0csp-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,64})\b"#,
        secret_group: 1,
        min_entropy: 3.4,
    },
    RuleSpec {
        id: "figma-pat",
        name: "Figma Personal Access Token",
        description: "Figma personal access token (`figd_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["figd_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(figd_[A-Za-z0-9_\-]{36,56})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "voyage-api-key",
        name: "Voyage AI API Key",
        description: "Voyage AI embedding and reranker API key (`pa-...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["pa-"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(pa-[A-Za-z0-9_\-]{38,56})\b"#,
        secret_group: 1,
        min_entropy: 3.7,
    },
    RuleSpec {
        id: "vercel-access-token",
        name: "Vercel Access Token",
        description: "Vercel personal or OAuth access token (`vcp_...` / `vca_...` / `vck_...`).",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &["vcp_", "vca_", "vck_"],
        pattern: r#"(?:^|[^A-Za-z0-9_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])(vc[pak]_[A-Za-z0-9]{24,72})\b"#,
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "base64-encoded-secret",
        name: "Base64-Encoded Secret",
        description: "Base64-encoded API key, cloud token, or PEM private key across any byte alignment.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        // Handled by `scan_base64_candidates` across all byte/char alignments and wrapped lines.
        anchors: &[],
        pattern: r"([A-Za-z0-9+/]{28,}={0,2})",
        secret_group: 1,
        min_entropy: 3.6,
    },
    RuleSpec {
        id: "hex-encoded-secret",
        name: "Hex-Encoded Secret",
        description: "Hex-encoded (`xxd` / `od -tx1` / `hexdump` / `.toString('hex')`) API key, cloud token, database URI, or private key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        // Handled by `scan_hex_candidates` across continuous, `0x`-prefixed, and line-wrapped hex dumps.
        anchors: &[],
        pattern: r"([0-9a-fA-F]{40,})",
        secret_group: 1,
        min_entropy: 3.0,
    },
    RuleSpec {
        id: "pii-email",
        name: "Email Address",
        description: "Personal or corporate email address included in outbound agent context or headers.",
        severity: Severity::Medium,
        category: RuleCategory::Pii,
        anchors: &["@"],
        pattern: r#"(?:^|[^A-Za-z0-9._%+@/\\-]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])([A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,120}\.[A-Za-z]{2,12})\b"#,
        secret_group: 1,
        min_entropy: 0.0,
    },
    RuleSpec {
        id: "internal-hostname",
        name: "Internal Hostname",
        description: "Internal corporate or cluster hostname (*.corp, *.internal, *.intranet, *.svc.cluster.local).",
        severity: Severity::Medium,
        category: RuleCategory::Pii,
        anchors: &[
            ".corp",
            ".internal",
            ".intranet",
            ".svc.cluster.local",
            ".localdomain",
        ],
        pattern: r#"(?:^|[^A-Za-z0-9.\-_\\]|\\+u00[0-3][0-9a-fA-F]|\\\\|\\[nrt"'])((?:https?://)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\.corp|\.internal|\.intranet|\.svc\.cluster\.local|\.localdomain))\b"#,
        secret_group: 1,
        min_entropy: 0.0,
    },
];

const NON_SECRET_TOKEN_KEYS: &[&str] = &[
    "NEXT_PAGE_TOKEN",
    "PAGE_TOKEN",
    "PAGINATION_TOKEN",
    "CONTINUATION_TOKEN",
    "SYNC_TOKEN",
    "CANCEL_TOKEN",
    "CSRF_TOKEN",
    "MAX_TOKEN",
    "INPUT_TOKEN",
    "OUTPUT_TOKEN",
    "PROMPT_TOKEN",
    "COMPLETION_TOKEN",
    "CACHE_READ_INPUT_TOKEN",
    "TOKEN_COUNT",
    "TOKEN_LIMIT",
    "TOKEN_TYPE",
    "TOKEN_URI",
    "TOKEN_URL",
    "TOKEN_ENDPOINT",
];

const NON_SECRET_KEY_SUBSTRINGS: &[&str] = &[
    "COMMIT",
    "SHA1",
    "SHA256",
    "SHA512",
    "_SHA",
    "HASH",
    "DIGEST",
    "CHECKSUM",
    "ETAG",
    "REVISION",
    "TRACE",
    "SPAN",
    "FINGERPRINT",
    "PUBLIC_KEY",
    "PUBLICKEY",
    "PUBKEY",
    "KEY_ID",
    "KEYID",
    "KEY_NAME",
    "KEY_PATH",
    "KEY_FILE",
    "SECRET_NAME",
    "SECRET_ID",
    "SECRET_ARN",
    "CACHE_KEY",
    "ROUTING_KEY",
    "PARTITION_KEY",
    "SORT_KEY",
    "IDEMPOTENCY",
];

const CODE_RECEIVER_LABELS: &[&str] = &[
    "this", "self", "super", "cls", "window", "document", "process", "global", "module", "exports",
    "crate", "std", "core", "alloc",
];

const INFRA_INTERNAL_ZONES: &[&str] = &[
    "prod",
    "production",
    "stg",
    "stage",
    "staging",
    "dev",
    "qa",
    "uat",
    "corp",
    "hq",
    "infra",
    "k8s",
    "svc",
    "cluster",
    "compute",
    "ec2",
    "vpc",
    "google",
    "cloudapp",
    "internal",
];

impl RuleEngine {
    pub fn new(include_pii: bool) -> Self {
        Self::with_policy(include_pii, None)
    }

    pub fn with_policy(include_pii: bool, policy: Option<&PolicyConfig>) -> Self {
        let mut rules = Vec::new();
        let mut patterns: Vec<String> = Vec::new();
        let mut anchor_to_rule = Vec::new();
        let mut unanchored_rules = Vec::new();
        let mut b64_rule_enabled = false;
        let mut hex_rule_enabled = false;
        let mut k8s_rule_enabled = false;

        for spec in RULE_SPECS {
            if !include_pii && spec.category == RuleCategory::Pii {
                continue;
            }
            if policy.is_some_and(|p| p.is_rule_disabled(spec.id)) {
                continue;
            }
            if spec.id == "base64-encoded-secret" {
                b64_rule_enabled = true;
            }
            if spec.id == "hex-encoded-secret" {
                hex_rule_enabled = true;
            }
            if spec.id == "kubernetes-secret-data" {
                k8s_rule_enabled = true;
            }
            let rule_idx = rules.len();
            for &anchor in spec.anchors {
                patterns.push(anchor.to_string());
                anchor_to_rule.push(rule_idx);
            }
            rules.push(CompiledRule {
                id: spec.id.to_string(),
                name: spec.name.to_string(),
                description: spec.description.to_string(),
                severity: spec.severity,
                category: spec.category,
                anchors: spec.anchors.iter().map(|s| (*s).to_string()).collect(),
                regex: Regex::new(spec.pattern).expect("valid built-in regex"),
                secret_group: spec.secret_group,
                min_entropy: spec.min_entropy,
                scoped_policy_idx: None,
            });
        }

        if let Some(pol) = policy {
            let mut push_custom_rule =
                |custom: &crate::config::CustomRuleSpec, scoped_policy_idx: Option<usize>| {
                    if !include_pii && custom.category == RuleCategory::Pii {
                        return;
                    }
                    if scoped_policy_idx.is_none() && pol.is_rule_disabled(&custom.id) {
                        return;
                    }
                    let Ok(re) = Regex::new(&custom.pattern) else {
                        return;
                    };
                    // Default custom rules to full match (`0`) unless `(?P<secret>...)` or `secret_group` is specified,
                    // preventing `(foo|bar)_secret_...` alternations from accidentally capturing only `"foo"`.
                    let named_secret_group = re.capture_names().position(|n| n == Some("secret"));
                    let secret_group = custom
                        .secret_group
                        .or(named_secret_group)
                        .unwrap_or(0)
                        .min(re.captures_len().saturating_sub(1));
                    let rule_idx = rules.len();
                    if custom.anchors.is_empty() {
                        unanchored_rules.push(rule_idx);
                    } else {
                        for anchor in &custom.anchors {
                            if !anchor.is_empty() {
                                patterns.push(anchor.clone());
                                anchor_to_rule.push(rule_idx);
                            }
                        }
                    }
                    rules.push(CompiledRule {
                        id: custom.id.trim().to_string(),
                        name: custom
                            .name
                            .clone()
                            .unwrap_or_else(|| custom.id.trim().to_string()),
                        description: custom
                            .description
                            .clone()
                            .unwrap_or_else(|| "Custom organization policy rule".to_string()),
                        severity: custom.severity,
                        category: custom.category,
                        anchors: custom.anchors.clone(),
                        regex: re,
                        secret_group,
                        min_entropy: custom.min_entropy,
                        scoped_policy_idx,
                    });
                };

            for custom in &pol.custom_rules {
                push_custom_rule(custom, None);
            }
            for (sp_idx, sp) in pol.scoped_policies.iter().enumerate() {
                for custom in &sp.custom_rules {
                    push_custom_rule(custom, Some(sp_idx));
                }
            }
        }

        let prefilter = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&patterns)
            .expect("valid Aho-Corasick anchors");
        Self {
            rules,
            prefilter,
            anchor_to_rule,
            unanchored_rules,
            b64_rule_enabled,
            hex_rule_enabled,
            k8s_rule_enabled,
            policy: policy.cloned(),
        }
    }

    pub fn all_rules() -> Self {
        Self::new(true)
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Scans a single line or chunk in linear O(n) time using SIMD Aho-Corasick prefiltering.
    pub fn scan_text(&self, text: &str) -> Vec<RawMatch> {
        self.scan_text_inner(text, None, 0, true, true, DocHints::default())
    }

    /// Scans text while applying path-scoped allowlists (`[allowlist.rule_paths]` and `--trust-project-config`).
    pub fn scan_text_for_path(&self, text: &str, path: Option<&std::path::Path>) -> Vec<RawMatch> {
        self.scan_text_inner(text, path, 0, true, true, DocHints::default())
    }

    /// Scans text with an optional file-level GCP service-account context hint so multi-line
    /// pretty-printed `service-account.json` files trigger `gcp-service-account-key` on `"private_key_id"`.
    pub fn scan_text_with_doc_hint(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        has_gcp_sa_markers: bool,
    ) -> Vec<RawMatch> {
        self.scan_text_with_hints(
            text,
            path,
            DocHints {
                has_gcp_sa: has_gcp_sa_markers,
                ..DocHints::default()
            },
        )
    }

    /// Scans text with document-level context hints (GCP SA JSON, JWK `kty`, Kubernetes `kind: Secret`).
    pub fn scan_text_with_hints(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        hints: DocHints,
    ) -> Vec<RawMatch> {
        self.scan_text_inner(text, path, 0, true, true, hints)
    }

    fn scan_text_inner(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
        allow_json_unescape: bool,
        allow_percent_decode: bool,
        hints: DocHints,
    ) -> Vec<RawMatch> {
        if text.is_empty() {
            return Vec::new();
        }
        let eff_hints = hints.merge(DocHints::from_text(text));

        let mut candidate_bits: u128 = 0;
        let mut extra_candidates: Option<HashSet<usize>> = None;

        for &rule_idx in &self.unanchored_rules {
            if rule_idx < 128 {
                candidate_bits |= 1u128 << rule_idx;
            } else {
                extra_candidates
                    .get_or_insert_with(HashSet::new)
                    .insert(rule_idx);
            }
        }

        for mat in self.prefilter.find_overlapping_iter(text) {
            let rule_idx = self.anchor_to_rule[mat.pattern().as_usize()];
            if rule_idx < 128 {
                candidate_bits |= 1u128 << rule_idx;
            } else {
                extra_candidates
                    .get_or_insert_with(HashSet::new)
                    .insert(rule_idx);
            }
        }

        let mut matches = Vec::new();

        if candidate_bits != 0 || extra_candidates.is_some() {
            for (idx, rule) in self.rules.iter().enumerate() {
                if matches!(
                    rule.id.as_str(),
                    "base64-encoded-secret" | "hex-encoded-secret" | "kubernetes-secret-data"
                ) {
                    continue;
                }
                let active = if idx < 128 {
                    (candidate_bits & (1u128 << idx)) != 0
                } else {
                    extra_candidates
                        .as_ref()
                        .is_some_and(|set| set.contains(&idx))
                };
                if !active {
                    continue;
                }
                if let Some(sp_idx) = rule.scoped_policy_idx {
                    let in_scope = match (self.policy.as_ref(), path) {
                        (Some(pol), Some(p)) => pol
                            .scoped_policies
                            .get(sp_idx)
                            .is_some_and(|sp| sp.applies_to(p)),
                        _ => false,
                    };
                    if !in_scope {
                        continue;
                    }
                }
                if self
                    .policy
                    .as_ref()
                    .is_some_and(|p| p.is_rule_disabled_for(&rule.id, path))
                {
                    continue;
                }

                for caps in rule.regex.captures_iter(text) {
                    let m = if rule.id == "dotenv-generic-secret" {
                        caps.get(1).or_else(|| caps.get(2))
                    } else {
                        caps.get(rule.secret_group)
                    };
                    let Some(m) = m else {
                        continue;
                    };
                    let val = m.as_str();
                    let full_match = caps.get(0).map(|c| c.as_str()).unwrap_or(val);

                    if self.has_stopword(val, path) {
                        continue;
                    }

                    if !passes_post_filter(
                        rule,
                        text,
                        full_match,
                        m.start(),
                        m.end(),
                        val,
                        eff_hints,
                    ) {
                        continue;
                    }

                    let fp = fingerprint_match(&rule.id, val);
                    if self.is_fingerprint_ignored(&fp, path) {
                        continue;
                    }

                    matches.push(RawMatch {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        category: rule.category,
                        start: m.start(),
                        end: m.end(),
                        masked: mask_value(&rule.id, val),
                        fingerprint: fp,
                        secret_key: extract_matched_key_name(&rule.id, full_match),
                    });
                }
            }
        }

        if eff_hints.is_k8s_secret_manifest
            && self.k8s_rule_enabled
            && !self
                .policy
                .as_ref()
                .is_some_and(|p| p.is_rule_disabled_for("kubernetes-secret-data", path))
        {
            self.scan_k8s_secret_data_entries(text, path, eff_hints, &mut matches);
        }

        if decode_depth < 2 {
            if self.b64_rule_enabled
                && !self
                    .policy
                    .as_ref()
                    .is_some_and(|p| p.is_rule_disabled_for("base64-encoded-secret", path))
            {
                self.scan_base64_candidates(text, path, decode_depth, &mut matches);
            }
            if self.hex_rule_enabled
                && !self
                    .policy
                    .as_ref()
                    .is_some_and(|p| p.is_rule_disabled_for("hex-encoded-secret", path))
            {
                self.scan_hex_candidates(text, path, decode_depth, &mut matches);
            }
        }

        // Decode RFC 8259 inline JSON `\uXXXX` (including UTF-16 surrogates, double-escaped `\\uXXXX`
        // in `.jsonl` transcripts), `\t`, and `\/` escapes, mapping match offsets back to exact raw byte spans.
        if allow_json_unescape
            && (text.contains("\\u")
                || text.contains("\\U")
                || text.contains("\\/")
                || text.contains("\\t"))
        {
            if let Some((unescaped, raw_starts, raw_ends)) = unescape_json_inline_with_spans(text) {
                for mut um in self.scan_text_inner(
                    &unescaped,
                    path,
                    decode_depth,
                    false,
                    allow_percent_decode,
                    eff_hints,
                ) {
                    if um.start < um.end && um.end <= raw_ends.len() {
                        um.start = raw_starts[um.start];
                        um.end = raw_ends[um.end - 1];
                        matches.push(um);
                    }
                }
            }
        }

        // Decode RFC 3986 `%XX` URL percent-encoded characters (up to 2 passes for `%252D`),
        // mapping decoded match offsets back to exact raw byte spans for both `scan` and `clean`.
        if allow_percent_decode && decode_depth < 2 && has_percent_hex_escape(text.as_bytes()) {
            if let Some((pct_decoded, raw_starts, raw_ends)) =
                decode_percent_inline_with_spans(text)
            {
                for mut pm in self.scan_text_inner(
                    &pct_decoded,
                    path,
                    decode_depth + 1,
                    allow_json_unescape,
                    true,
                    eff_hints,
                ) {
                    if pm.start < pm.end && pm.end <= raw_ends.len() {
                        pm.start = raw_starts[pm.start];
                        pm.end = raw_ends[pm.end - 1];
                        matches.push(pm);
                    }
                }
            }
        }

        if matches.is_empty() {
            return matches;
        }

        // Sort by byte offset, then Secret before Pii, then highest severity, then longest span
        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| {
                    (a.category == RuleCategory::Pii).cmp(&(b.category == RuleCategory::Pii))
                })
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| b.end.cmp(&a.end))
        });

        let mut deduped: Vec<RawMatch> = Vec::with_capacity(matches.len());
        for m in matches {
            if let Some(prev) = deduped.last_mut() {
                if m.start < prev.end {
                    match (prev.category, m.category) {
                        (RuleCategory::Secret, RuleCategory::Secret) => {
                            let is_generic = |id: &str| {
                                matches!(
                                    id,
                                    "dotenv-generic-secret"
                                        | "kubernetes-secret-data"
                                        | "base64-encoded-secret"
                                        | "hex-encoded-secret"
                                        | "http-bearer-token"
                                        | "url-query-secret"
                                )
                            };
                            let prev_is_generic = is_generic(&prev.rule_id);
                            let m_is_specific = !is_generic(&m.rule_id);
                            let k8s_upgrades_dotenv = prev.rule_id == "dotenv-generic-secret"
                                && m.rule_id == "kubernetes-secret-data";
                            // Upgrade overlapping generic matches to the higher-severity / specific secret rule
                            // while preserving the union byte span (and any captured variable name) so `clean` scrubs the entire value.
                            if m.severity > prev.severity
                                || (m.severity == prev.severity
                                    && ((prev_is_generic && m_is_specific) || k8s_upgrades_dotenv))
                            {
                                let union_start = prev.start.min(m.start);
                                let union_end = prev.end.max(m.end);
                                let preserved_key = m.secret_key.or_else(|| prev.secret_key.take());
                                prev.rule_id = m.rule_id;
                                prev.rule_name = m.rule_name;
                                prev.severity = m.severity;
                                prev.masked = m.masked;
                                prev.fingerprint = m.fingerprint;
                                prev.secret_key = preserved_key;
                                prev.start = union_start;
                                prev.end = union_end;
                            } else {
                                prev.end = prev.end.max(m.end);
                                if prev.secret_key.is_none() {
                                    prev.secret_key = m.secret_key;
                                }
                            }
                            continue;
                        }
                        (RuleCategory::Pii, RuleCategory::Secret) => {
                            // Never let an overlapping `Pii` rule swallow a `Secret` match; replace `prev`
                            // with `m`'s exact span so any subsequent secrets on the line also survive.
                            *prev = m;
                            continue;
                        }
                        (RuleCategory::Secret, RuleCategory::Pii) => {
                            continue;
                        }
                        (RuleCategory::Pii, RuleCategory::Pii) => {
                            if m.severity > prev.severity {
                                *prev = m;
                            }
                            continue;
                        }
                    }
                }
            }
            deduped.push(m);
        }

        deduped
    }

    fn scan_k8s_secret_data_entries(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        eff_hints: DocHints,
        out: &mut Vec<RawMatch>,
    ) {
        // 1. Streaming single-line mode from `scanner.rs` / `cleaner.rs`
        if eff_hints.in_k8s_data_entry || eff_hints.in_k8s_string_data_entry {
            self.inspect_k8s_data_line(
                text,
                0,
                eff_hints.in_k8s_data_entry,
                eff_hints.in_k8s_string_data_entry,
                path,
                out,
            );
        }

        // 2. Inline JSON `{"kind":"Secret","data":{"creds":"..."}}` (including JSONL-escaped quotes)
        for (marker, is_str_data) in [
            ("\"data\"", false),
            ("\\\"data\\\"", false),
            ("\"stringData\"", true),
            ("\\\"stringData\\\"", true),
        ] {
            let mut search_from = 0usize;
            while let Some(rel) = text[search_from..].find(marker) {
                let pos = search_from + rel;
                search_from = pos + marker.len();
                let rest = &text[search_from..];
                let ws1 = rest.bytes().take_while(|b| b.is_ascii_whitespace()).count();
                if rest.as_bytes().get(ws1) != Some(&b':') {
                    continue;
                }
                let after_colon = &rest[ws1 + 1..];
                let ws2 = after_colon
                    .bytes()
                    .take_while(|b| b.is_ascii_whitespace())
                    .count();
                if after_colon.as_bytes().get(ws2) != Some(&b'{') {
                    continue;
                }
                let brace_open_abs = search_from + ws1 + 1 + ws2;
                let mut depth = 1usize;
                let mut brace_close_abs = None;
                for (off, b) in text[brace_open_abs + 1..].bytes().enumerate() {
                    if b == b'{' {
                        depth += 1;
                    } else if b == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            brace_close_abs = Some(brace_open_abs + 1 + off);
                            break;
                        }
                    }
                }
                if let Some(close_abs) = brace_close_abs {
                    let inner = &text[brace_open_abs + 1..close_abs];
                    let mut seg_start = 0usize;
                    for (idx, ch) in inner.char_indices() {
                        if ch == ',' || ch == '\n' {
                            let seg = &inner[seg_start..idx];
                            self.inspect_k8s_data_line(
                                seg,
                                brace_open_abs + 1 + seg_start,
                                !is_str_data,
                                is_str_data,
                                path,
                                out,
                            );
                            seg_start = idx + 1;
                        }
                    }
                    if seg_start < inner.len() {
                        self.inspect_k8s_data_line(
                            &inner[seg_start..],
                            brace_open_abs + 1 + seg_start,
                            !is_str_data,
                            is_str_data,
                            path,
                            out,
                        );
                    }
                }
            }
        }

        // 3. Multi-line YAML/JSON manifest in `text` (splitting on physical `\n` and JSONL `\n`)
        if text.contains('\n') || text.contains("\\n") {
            let mut tracker = K8sDataTracker::default();
            for (line_start, line_end) in split_logical_lines_with_offsets(text) {
                let line = &text[line_start..line_end];
                let (in_data, in_str_data) = tracker.observe_line(line);
                if in_data || in_str_data {
                    self.inspect_k8s_data_line(line, line_start, in_data, in_str_data, path, out);
                }
            }
        }
    }

    fn inspect_k8s_data_line(
        &self,
        line: &str,
        line_abs_offset: usize,
        in_data: bool,
        in_str_data: bool,
        path: Option<&std::path::Path>,
        out: &mut Vec<RawMatch>,
    ) {
        let Some(colon_idx) = line.find(':') else {
            return;
        };
        let raw_key = line[..colon_idx].trim_matches(|c: char| {
            c.is_ascii_whitespace() || matches!(c, '"' | '\'' | '\\' | ',' | '{')
        });
        if raw_key.is_empty()
            || raw_key.len() > 128
            || matches!(
                raw_key,
                "apiVersion" | "kind" | "metadata" | "type" | "data" | "stringData" | "immutable"
            )
            || !raw_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return;
        }

        let rhs = &line[colon_idx + 1..];
        let rhs_no_comment = if let Some(hash_pos) = rhs.find(" #") {
            &rhs[..hash_pos]
        } else {
            rhs
        };
        let lead_trim = rhs_no_comment
            .bytes()
            .take_while(|&b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'\\'))
            .count();
        if lead_trim >= rhs_no_comment.len() {
            return;
        }
        let tail_slice = &rhs_no_comment[lead_trim..];
        let trimmed_val = tail_slice.trim_end_matches(|c: char| {
            c.is_ascii_whitespace() || matches!(c, '"' | '\'' | '\\' | ',' | '}')
        });
        if trimmed_val.is_empty() {
            return;
        }
        let abs_start = line_abs_offset + colon_idx + 1 + lead_trim;
        let abs_end = abs_start + trimmed_val.len();

        if out.iter().any(|existing| {
            existing.rule_id != "dotenv-generic-secret"
                && existing.start <= abs_start
                && existing.end >= abs_end
        }) {
            return;
        }
        if trimmed_val.contains("REDACTED_BY_LEAKTAP")
            || self.has_stopword(trimmed_val, path)
            || is_likely_placeholder(trimmed_val)
        {
            return;
        }

        if in_data {
            if trimmed_val.len() < 8
                || trimmed_val.len() > MAX_B64_CANDIDATE_CHARS
                || !trimmed_val
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return;
            }
            let no_pad = trimmed_val.trim_end_matches('=');
            if no_pad.len() < 6 || trimmed_val.len() - no_pad.len() > 2 {
                return;
            }
            let Ok(decoded) = base64::engine::general_purpose::STANDARD
                .decode(trimmed_val)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(no_pad))
            else {
                return;
            };
            if decoded.len() < 6 {
                return;
            }
            if let Ok(dec_str) = std::str::from_utf8(&decoded) {
                let dt = dec_str.trim();
                if dt.len() < 4
                    || is_likely_placeholder(dt)
                    || matches!(
                        dt.to_ascii_lowercase().as_str(),
                        "true" | "false" | "{}" | "[]"
                    )
                {
                    return;
                }
            }
        } else if in_str_data {
            let lower = trimmed_val.to_ascii_lowercase();
            if trimmed_val.len() < 8
                || matches!(lower.as_str(), "true" | "false" | "opaque")
                || lower.starts_with("http://")
                || lower.starts_with("https://")
                || looks_like_filesystem_path(trimmed_val)
                || shannon_entropy(trimmed_val) < 2.8
            {
                return;
            }
        } else {
            return;
        }

        let fp = fingerprint_match("kubernetes-secret-data", trimmed_val);
        if self.is_fingerprint_ignored(&fp, path) {
            return;
        }
        out.push(RawMatch {
            rule_id: "kubernetes-secret-data".to_string(),
            rule_name: "Kubernetes Secret Manifest Data".to_string(),
            severity: Severity::High,
            category: RuleCategory::Secret,
            start: abs_start,
            end: abs_end,
            masked: mask_value("kubernetes-secret-data", trimmed_val),
            fingerprint: fp,
            secret_key: Some(raw_key.to_string()),
        });
    }

    /// Single-pass linear O(n) scanner for standard, URL-safe, prefixed, and line-wrapped Base64 blobs.
    fn scan_base64_candidates(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
        out: &mut Vec<RawMatch>,
    ) {
        let bytes = text.as_bytes();
        let len = bytes.len();
        let mut i = 0usize;

        while i < len {
            let b = bytes[i];
            let is_b64_body = b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_');
            if !is_b64_body {
                i += 1;
                continue;
            }

            let start = i;
            let mut has_upper = false;
            let mut has_lower = false;
            let mut has_url_sym = false;
            let mut wrapped_multiline = false;

            loop {
                while i < len {
                    let c = bytes[i];
                    if c.is_ascii_uppercase() {
                        has_upper = true;
                        i += 1;
                    } else if c.is_ascii_lowercase() {
                        has_lower = true;
                        i += 1;
                    } else if c.is_ascii_digit() || c == b'+' || c == b'/' {
                        i += 1;
                    } else if !wrapped_multiline && (c == b'-' || c == b'_') {
                        has_url_sym = true;
                        i += 1;
                    } else {
                        break;
                    }
                }

                // Coalesce wrapped multi-line Base64 output (physical `\r?\n` or JSONL `\n` escapes) up to 128 KiB
                if !has_url_sym && (i - start) >= 32 && (i - start) < MAX_B64_CANDIDATE_CHARS {
                    if let Some(next_b64_pos) = peek_wrapped_b64_continuation(bytes, i) {
                        wrapped_multiline = true;
                        i = next_b64_pos;
                        continue;
                    }
                }
                break;
            }

            let body_end = i;
            let mut pad_count = 0usize;
            while i < len && bytes[i] == b'=' && pad_count < 2 {
                // Only treat `=` as Base64 padding when not immediately followed by another Base64 body (`KEY=VALUE`)
                if i + 1 < len && bytes[i + 1] != b'=' && bytes[i + 1].is_ascii_alphanumeric() {
                    break;
                }
                pad_count += 1;
                i += 1;
            }
            let end = body_end + pad_count;
            let tok_len = end - start;

            if !(28..=MAX_B64_CANDIDATE_CHARS).contains(&tok_len) || !(has_upper && has_lower) {
                continue;
            }

            let candidate = &text[start..end];

            // Skip dot-delimited JWT header/payload/signature segments (`eyJ...`) which `jwt-token` inspects directly,
            // while still catching Base64 secrets followed by a sentence-ending period (`c2tfbGl2ZV8...=`).
            if is_jwt_dot_segment(text, start, end) {
                continue;
            }

            if self.has_stopword(candidate, path) {
                continue;
            }

            let normalized_b64 = if wrapped_multiline {
                Some(strip_b64_line_breaks(candidate))
            } else {
                None
            };
            let to_verify = normalized_b64.as_deref().unwrap_or(candidate);

            if let Some(inner) = self.verify_base64_secret(to_verify, path, decode_depth) {
                // Avoid re-wrapping a token that already matched directly at the exact same span
                if out
                    .iter()
                    .any(|existing| existing.start <= start && existing.end >= end)
                {
                    continue;
                }
                let fp = fingerprint_match("base64-encoded-secret", to_verify);
                if self.is_fingerprint_ignored(&fp, path) {
                    continue;
                }
                out.push(RawMatch {
                    rule_id: "base64-encoded-secret".to_string(),
                    rule_name: format!("Base64 {}", inner.rule_name),
                    severity: inner.severity.max(Severity::High),
                    category: RuleCategory::Secret,
                    start,
                    end,
                    masked: format!("b64({})", inner.masked),
                    fingerprint: fp,
                    secret_key: inner.secret_key,
                });
            }
        }
    }

    fn verify_base64_secret(
        &self,
        b64_candidate: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
    ) -> Option<RawMatch> {
        let mut start_offsets = vec![0usize];
        // Also check right after `_` or `-` prefixes (e.g. `_tok_c2tfbGl2ZV8...` or `my_org_prefix_tok_c2tf...`)
        let prefix_scan_limit = b64_candidate.len().min(96);
        for (idx, b) in b64_candidate.as_bytes()[..prefix_scan_limit]
            .iter()
            .enumerate()
        {
            if (*b == b'_' || *b == b'-')
                && idx + 24 < b64_candidate.len()
                && start_offsets.len() < 16
            {
                start_offsets.push(idx + 1);
            }
        }

        for base_off in start_offsets {
            let sub = &b64_candidate[base_off..];
            // Try all 4 Base64 character alignments (`0..4`) so unaligned substrings still decode cleanly
            for shift in 0..4usize {
                if sub.len() < shift + 24 {
                    break;
                }
                let slice = &sub[shift..];
                let slice_has_std = slice.bytes().any(|b| b == b'+' || b == b'/');
                let slice_has_url = slice.bytes().any(|b| b == b'-' || b == b'_');
                if slice_has_std && slice_has_url {
                    continue;
                }
                if let Some(found) =
                    self.try_decode_b64_slice(slice, slice_has_url, path, decode_depth)
                {
                    return Some(found);
                }
            }
        }
        None
    }

    fn try_decode_b64_slice(
        &self,
        slice: &str,
        url_safe: bool,
        path: Option<&std::path::Path>,
        decode_depth: u8,
    ) -> Option<RawMatch> {
        let trimmed = slice.trim_end_matches('=');
        let candidate_for_no_pad = if trimmed.len() % 4 == 1 {
            &trimmed[..trimmed.len() - 1]
        } else {
            trimmed
        };
        let decoded = if url_safe {
            base64::engine::general_purpose::URL_SAFE
                .decode(slice)
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(candidate_for_no_pad)
                })
                .ok()?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(slice)
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(candidate_for_no_pad)
                })
                .ok()?
        };
        if decoded.len() < 16 || decoded.len() > MAX_B64_DECODED_BYTES {
            return None;
        }
        let printable = decoded
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        if printable * 10 < decoded.len() * 8 {
            return None;
        }
        let decoded_cow = match std::str::from_utf8(&decoded) {
            Ok(s) => std::borrow::Cow::Borrowed(s),
            Err(_) => String::from_utf8_lossy(&decoded),
        };
        let inner_hints = DocHints::from_text(&decoded_cow);
        self.scan_text_inner(
            &decoded_cow,
            path,
            decode_depth + 1,
            true,
            true,
            inner_hints,
        )
        .into_iter()
        .filter(|m| m.category == RuleCategory::Secret)
        .max_by_key(|m| m.severity)
    }

    /// Single-pass linear O(n) scanner for continuous, `0x`-prefixed, `xxd` (default + `-p`),
    /// `od -tx1`, `hexdump -C`, and space/colon-delimited hex byte dumps.
    fn scan_hex_candidates(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
        out: &mut Vec<RawMatch>,
    ) {
        // First pass: structured address-prefixed hex dumps (`xxd`, `od -tx1`, `hexdump -C`)
        self.scan_structured_hexdump_blocks(text, path, decode_depth, out);

        let bytes = text.as_bytes();
        let len = bytes.len();
        let mut i = 0usize;

        while i < len {
            let at_word_start = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let (start, hex_start) = if at_word_start
                && i + 2 < len
                && bytes[i] == b'0'
                && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
                && bytes[i + 2].is_ascii_hexdigit()
            {
                (i, i + 2)
            } else if bytes[i].is_ascii_hexdigit() {
                (i, i)
            } else {
                i += 1;
                continue;
            };

            let mut j = hex_start;
            while j < len && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }

            // Case 1: Space- or colon-separated 2- or 4-hex-digit sequences (`73 6b 5f ...`, `736b 5f6c ...`, `73:6b:5f:...`)
            let first_grp_len = j - hex_start;
            if at_word_start
                && start == hex_start
                && (first_grp_len == 2 || first_grp_len == 4)
                && j < len
                && (bytes[j] == b' ' || (first_grp_len == 2 && bytes[j] == b':'))
            {
                let sep = bytes[j];
                let mut total_hex = first_grp_len;
                let mut end = j;
                while end < len && total_hex < 16384 {
                    let mut k = end;
                    if bytes[k] == sep {
                        k += 1;
                        if sep == b' ' && k < len && bytes[k] == b' ' {
                            k += 1;
                        }
                    } else if sep == b' ' && total_hex >= 16 {
                        if bytes[k] == b'\r' && k + 1 < len && bytes[k + 1] == b'\n' {
                            k += 2;
                        } else if bytes[k] == b'\n' {
                            k += 1;
                        } else if bytes[k] == b'\\' && k + 1 < len && bytes[k + 1] == b'n' {
                            k += 2;
                        } else {
                            break;
                        }
                        while k < len && (bytes[k] == b' ' || bytes[k] == b'\t') {
                            k += 1;
                        }
                    } else {
                        break;
                    }

                    let mut grp_end = k;
                    while grp_end < len
                        && bytes[grp_end].is_ascii_hexdigit()
                        && (grp_end - k) <= first_grp_len
                    {
                        grp_end += 1;
                    }
                    let grp_len = grp_end - k;
                    let valid_grp =
                        grp_len == first_grp_len || (first_grp_len == 4 && grp_len == 2);
                    if valid_grp && (grp_end == len || !bytes[grp_end].is_ascii_alphanumeric()) {
                        total_hex += grp_len;
                        end = grp_end;
                    } else {
                        break;
                    }
                }

                if total_hex >= 32 {
                    i = end;
                    let raw_span = &text[start..end];
                    if !self.has_stopword(raw_span, path) {
                        let clean_hex: String = raw_span
                            .bytes()
                            .filter(|b| b.is_ascii_hexdigit())
                            .map(|b| b as char)
                            .collect();
                        if let Some(inner) = self.verify_hex_secret(&clean_hex, path, decode_depth)
                        {
                            self.push_hex_match(inner, &clean_hex, start, end, path, out);
                        }
                    }
                    continue;
                }
            }

            // Case 2: Continuous or `xxd -p` line-wrapped hex strings
            let mut wrapped = false;
            if (j - hex_start) >= 32 && (j - hex_start) < 16384 {
                while j - hex_start < 16384 {
                    if let Some(next_hex) = peek_wrapped_hex_continuation(bytes, j) {
                        wrapped = true;
                        j = next_hex;
                        while j < len && bytes[j].is_ascii_hexdigit() {
                            j += 1;
                        }
                    } else {
                        break;
                    }
                }
            }

            let end = j;
            i = end;
            let hex_len = end - hex_start;
            if !(36..=16384).contains(&hex_len) {
                continue;
            }

            let raw_span = &text[start..end];
            if self.has_stopword(raw_span, path) {
                continue;
            }

            let clean_cow: std::borrow::Cow<'_, str> = if wrapped {
                std::borrow::Cow::Owned(
                    text[hex_start..end]
                        .bytes()
                        .filter(|b| b.is_ascii_hexdigit())
                        .map(|b| b as char)
                        .collect(),
                )
            } else {
                std::borrow::Cow::Borrowed(&text[hex_start..end])
            };

            if let Some(inner) = self.verify_hex_secret(&clean_cow, path, decode_depth) {
                self.push_hex_match(inner, &clean_cow, start, end, path, out);
            }
        }
    }

    fn scan_structured_hexdump_blocks(
        &self,
        text: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
        out: &mut Vec<RawMatch>,
    ) {
        let mut block_start: Option<usize> = None;
        let mut block_end: usize = 0;
        let mut clean_hex = String::new();

        let flush_block =
            |b_start: usize, b_end: usize, hex_buf: &str, out_vec: &mut Vec<RawMatch>| {
                if hex_buf.len() < 32 || self.has_stopword(&text[b_start..b_end], path) {
                    return;
                }
                if let Some(inner) = self.verify_hex_secret(hex_buf, path, decode_depth) {
                    self.push_hex_match(inner, hex_buf, b_start, b_end, path, out_vec);
                }
            };

        for (line_start, line_end) in split_logical_lines_with_offsets(text) {
            let line = &text[line_start..line_end];
            if let Some(line_hex) = parse_hexdump_line_hex(line) {
                if clean_hex.len() + line_hex.len() <= 16384 {
                    if block_start.is_none() {
                        block_start = Some(line_start);
                    }
                    block_end = line_end;
                    clean_hex.push_str(&line_hex);
                    continue;
                }
            }
            if let Some(bs) = block_start.take() {
                flush_block(bs, block_end, &clean_hex, out);
                clean_hex.clear();
            }
        }

        if let Some(bs) = block_start.take() {
            flush_block(bs, block_end, &clean_hex, out);
        }
    }

    fn push_hex_match(
        &self,
        inner: RawMatch,
        clean_hex: &str,
        start: usize,
        end: usize,
        path: Option<&std::path::Path>,
        out: &mut Vec<RawMatch>,
    ) {
        if out
            .iter()
            .any(|existing| existing.start <= start && existing.end >= end)
        {
            return;
        }
        let fp = fingerprint_match("hex-encoded-secret", clean_hex);
        if self.is_fingerprint_ignored(&fp, path) {
            return;
        }
        out.push(RawMatch {
            rule_id: "hex-encoded-secret".to_string(),
            rule_name: format!("Hex {}", inner.rule_name),
            severity: inner.severity.max(Severity::High),
            category: RuleCategory::Secret,
            start,
            end,
            masked: format!("hex({})", inner.masked),
            fingerprint: fp,
            secret_key: inner.secret_key,
        });
    }

    fn verify_hex_secret(
        &self,
        hex_str: &str,
        path: Option<&std::path::Path>,
        decode_depth: u8,
    ) -> Option<RawMatch> {
        for shift in [0usize, 1usize] {
            if shift == 1 && (hex_str.len() & 1) == 0 {
                break;
            }
            if hex_str.len() < shift + 32 {
                break;
            }
            let even_len = (hex_str.len() - shift) & !1;
            let slice = &hex_str.as_bytes()[shift..shift + even_len];
            let byte_len = slice.len() / 2;
            if !(16..=8192).contains(&byte_len) {
                continue;
            }
            let mut decoded = Vec::with_capacity(byte_len);
            let mut ok = true;
            let mut pair_idx = 0usize;
            while pair_idx + 1 < slice.len() {
                let hi = (slice[pair_idx] as char).to_digit(16);
                let lo = (slice[pair_idx + 1] as char).to_digit(16);
                pair_idx += 2;
                match (hi, lo) {
                    (Some(h), Some(l)) => decoded.push(((h << 4) | l) as u8),
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            let printable = decoded
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            if printable * 10 < decoded.len() * 8 {
                continue;
            }
            let decoded_cow = match std::str::from_utf8(&decoded) {
                Ok(s) => std::borrow::Cow::Borrowed(s),
                Err(_) => String::from_utf8_lossy(&decoded),
            };
            let inner_hints = DocHints::from_text(&decoded_cow);
            if let Some(best) = self
                .scan_text_inner(
                    &decoded_cow,
                    path,
                    decode_depth + 1,
                    true,
                    true,
                    inner_hints,
                )
                .into_iter()
                .filter(|m| m.category == RuleCategory::Secret)
                .max_by_key(|m| m.severity)
            {
                return Some(best);
            }
        }
        None
    }

    fn has_stopword(&self, val: &str, path: Option<&std::path::Path>) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|p| p.has_stopword_for(val, path))
    }

    fn is_fingerprint_ignored(&self, fp: &str, path: Option<&std::path::Path>) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|p| p.is_fingerprint_ignored_for(fp, path))
    }
}

/// Splits `text` into logical lines on physical `\r?\n` AND JSONL `\\r\\n` / `\\n` escapes,
/// returning `(start_byte, end_byte)` slices (excluding line terminators).
fn split_logical_lines_with_offsets(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = Vec::new();
    let mut line_start = 0usize;
    let mut i = 0usize;

    while i < len {
        if bytes[i] == b'\r' && i + 1 < len && bytes[i + 1] == b'\n' {
            out.push((line_start, i));
            i += 2;
            line_start = i;
        } else if bytes[i] == b'\n' {
            out.push((line_start, i));
            i += 1;
            line_start = i;
        } else if bytes[i] == b'\\' && i + 1 < len && bytes[i + 1] == b'n' {
            out.push((line_start, i));
            i += 2;
            line_start = i;
        } else if bytes[i] == b'\\'
            && i + 3 < len
            && bytes[i + 1] == b'r'
            && bytes[i + 2] == b'\\'
            && bytes[i + 3] == b'n'
        {
            out.push((line_start, i));
            i += 4;
            line_start = i;
        } else {
            i += 1;
        }
    }
    if line_start <= len {
        out.push((line_start, len));
    }
    out
}

/// Returns `true` if `line` is a structured `xxd`, `od -tx1`, or `hexdump -C` dump line.
pub fn is_hexdump_line(line: &str) -> bool {
    parse_hexdump_line_hex(line).is_some()
}

/// Extracts the raw hex byte digits from a single `xxd`, `od -tx1`, or `hexdump -C` line.
pub fn parse_hexdump_line_hex(line: &str) -> Option<String> {
    let s = line
        .trim_end_matches(['\r', '\n'])
        .trim_start_matches([' ', '\t']);
    if s.len() < 10 {
        return None;
    }
    let after_0x = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let addr_len = after_0x
        .bytes()
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    if !(4..=16).contains(&addr_len) {
        return None;
    }
    let after_addr = &after_0x[addr_len..];
    let (has_colon, rest_start) = if let Some(after_colon) = after_addr.strip_prefix(':') {
        let ws = after_colon
            .bytes()
            .take_while(|&b| b == b' ' || b == b'\t')
            .count();
        if ws == 0 {
            return None;
        }
        (true, &after_colon[ws..])
    } else if addr_len >= 6 {
        let ws = after_addr
            .bytes()
            .take_while(|&b| b == b' ' || b == b'\t')
            .count();
        if !(1..=6).contains(&ws) {
            return None;
        }
        (false, &after_addr[ws..])
    } else {
        return None;
    };

    if has_colon {
        // `xxd` / `objdump` format: 2- or 4-hex groups separated by single spaces, followed by `>= 2` spaces + ASCII gutter
        let mut hex_out = String::with_capacity(32);
        let rbytes = rest_start.as_bytes();
        let mut idx = 0usize;
        while idx < rbytes.len() {
            let grp_start = idx;
            while idx < rbytes.len() && rbytes[idx].is_ascii_hexdigit() && (idx - grp_start) <= 8 {
                idx += 1;
            }
            let grp_len = idx - grp_start;
            if !matches!(grp_len, 2 | 4 | 8) {
                return None;
            }
            hex_out.push_str(&rest_start[grp_start..idx]);
            let ws_start = idx;
            while idx < rbytes.len() && rbytes[idx] == b' ' {
                idx += 1;
            }
            let ws_len = idx - ws_start;
            if idx == rbytes.len() {
                break;
            }
            if ws_len >= 2 {
                // Remaining tail is the `xxd` ASCII gutter (`<= 36` chars)
                if rest_start[idx..].len() > 36 {
                    return None;
                }
                break;
            }
            if ws_len == 0 {
                return None;
            }
        }
        if hex_out.len() >= 2 && (hex_out.len() & 1) == 0 {
            Some(hex_out)
        } else {
            None
        }
    } else {
        // `od -tx1` or `hexdump -C`: optional trailing `|...|` ASCII gutter, preceded purely by hex groups
        let trimmed_end = rest_start.trim_end_matches([' ', '\t']);
        let hex_region = if let Some(without_close) = trimmed_end.strip_suffix('|') {
            let open_pipe = without_close.rfind('|')?;
            &without_close[..open_pipe]
        } else {
            trimmed_end
        };
        let mut hex_out = String::with_capacity(32);
        let mut tok_count = 0usize;
        for tok in hex_region.split_whitespace() {
            if !matches!(tok.len(), 2 | 4 | 8) || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            hex_out.push_str(tok);
            tok_count += 1;
        }
        if tok_count >= 1 && hex_out.len() >= 2 {
            Some(hex_out)
        } else {
            None
        }
    }
}

/// Decodes RFC 8259 inline `\uXXXX` (including UTF-16 surrogate pairs and double-escaped `\\uXXXX`
/// inside JSONL transcripts), `\t`, and `\/` escapes while recording the exact `[raw_start, raw_end)`
/// byte span in `raw` for each output byte in the returned `String`.
fn unescape_json_inline_with_spans(raw: &str) -> Option<(String, Vec<usize>, Vec<usize>)> {
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut starts = Vec::with_capacity(len);
    let mut ends = Vec::with_capacity(len);
    let mut changed = false;
    let mut i = 0usize;

    let parse_hex4 = |slice: &[u8]| -> Option<u16> {
        if slice.len() < 4 || !slice[..4].iter().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let s = std::str::from_utf8(&slice[..4]).ok()?;
        u16::from_str_radix(s, 16).ok()
    };

    while i < len {
        if bytes[i] == b'\\' {
            let bs_start = i;
            let mut bs_end = i;
            while bs_end < len && bytes[bs_end] == b'\\' && (bs_end - bs_start) < 4 {
                bs_end += 1;
            }
            if bs_end < len && bytes[bs_end] == b'/' {
                out.push('/');
                starts.push(bs_start);
                ends.push(bs_end + 1);
                changed = true;
                i = bs_end + 1;
                continue;
            }
            if bs_end < len && bytes[bs_end] == b't' {
                out.push('\t');
                starts.push(bs_start);
                ends.push(bs_end + 1);
                changed = true;
                i = bs_end + 1;
                continue;
            }
            if bs_end + 5 <= len && (bytes[bs_end] == b'u' || bytes[bs_end] == b'U') {
                if let Some(code) = parse_hex4(&bytes[bs_end + 1..bs_end + 5]) {
                    let first_end = bs_end + 5;
                    if (0xD800..=0xDBFF).contains(&code) {
                        // Look ahead for low UTF-16 surrogate `\uDC00`..`\uDFFF`
                        let mut ls_bs_end = first_end;
                        while ls_bs_end < len
                            && bytes[ls_bs_end] == b'\\'
                            && (ls_bs_end - first_end) < 4
                        {
                            ls_bs_end += 1;
                        }
                        if ls_bs_end > first_end
                            && ls_bs_end + 5 <= len
                            && (bytes[ls_bs_end] == b'u' || bytes[ls_bs_end] == b'U')
                        {
                            if let Some(low) = parse_hex4(&bytes[ls_bs_end + 1..ls_bs_end + 5]) {
                                if (0xDC00..=0xDFFF).contains(&low) {
                                    let cp = 0x10000
                                        + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                                    if let Some(ch) = char::from_u32(cp) {
                                        let pair_end = ls_bs_end + 5;
                                        out.push(ch);
                                        for _ in 0..ch.len_utf8() {
                                            starts.push(bs_start);
                                            ends.push(pair_end);
                                        }
                                        changed = true;
                                        i = pair_end;
                                        continue;
                                    }
                                }
                            }
                        }
                    } else if !(0xDC00..=0xDFFF).contains(&code) && code != 0 {
                        if let Some(ch) = char::from_u32(code as u32) {
                            out.push(ch);
                            for _ in 0..ch.len_utf8() {
                                starts.push(bs_start);
                                ends.push(first_end);
                            }
                            changed = true;
                            i = first_end;
                            continue;
                        }
                    }
                }
            }
        }

        let ch = raw[i..].chars().next().expect("non-empty UTF-8 slice");
        let ch_len = ch.len_utf8();
        out.push(ch);
        for _ in 0..ch_len {
            starts.push(i);
            ends.push(i + ch_len);
        }
        i += ch_len;
    }

    if changed {
        Some((out, starts, ends))
    } else {
        None
    }
}

fn peek_wrapped_b64_continuation(bytes: &[u8], pos: usize) -> Option<usize> {
    let len = bytes.len();
    let mut j = pos;
    while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    let mut saw_break = false;
    while j < len {
        if bytes[j] == b'\r' && j + 1 < len && bytes[j + 1] == b'\n' {
            saw_break = true;
            j += 2;
        } else if bytes[j] == b'\n' {
            saw_break = true;
            j += 1;
        } else if bytes[j] == b'\\' && j + 1 < len && bytes[j + 1] == b'n' {
            saw_break = true;
            j += 2;
        } else if bytes[j] == b'\\'
            && j + 3 < len
            && bytes[j + 1] == b'r'
            && bytes[j + 2] == b'\\'
            && bytes[j + 3] == b'n'
        {
            saw_break = true;
            j += 4;
        } else {
            break;
        }
        while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
    }
    if !saw_break {
        return None;
    }
    let mut run = 0usize;
    let mut k = j;
    while k < len
        && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'+' || bytes[k] == b'/')
        && run <= 160
    {
        run += 1;
        k += 1;
    }
    if run > 160 {
        return None;
    }
    let mut pad = 0usize;
    while k + pad < len && bytes[k + pad] == b'=' && pad < 2 {
        pad += 1;
    }
    let after = k + pad;
    if after < len
        && (bytes[after].is_ascii_alphanumeric()
            || matches!(bytes[after], b'+' | b'/' | b'=' | b'_' | b'-' | b':'))
    {
        return None;
    }
    let ends_line_or_quote =
        after == len || matches!(bytes[after], b'\r' | b'\n' | b'\\' | b'"' | b'\'');
    if run >= 12 || (run >= 2 && pad >= 1) || (run >= 4 && ends_line_or_quote) {
        Some(j)
    } else {
        None
    }
}

fn peek_wrapped_hex_continuation(bytes: &[u8], pos: usize) -> Option<usize> {
    let len = bytes.len();
    let mut j = pos;
    while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    let mut saw_break = false;
    while j < len {
        if bytes[j] == b'\r' && j + 1 < len && bytes[j + 1] == b'\n' {
            saw_break = true;
            j += 2;
        } else if bytes[j] == b'\n' {
            saw_break = true;
            j += 1;
        } else if bytes[j] == b'\\' && j + 1 < len && bytes[j + 1] == b'n' {
            saw_break = true;
            j += 2;
        } else if bytes[j] == b'\\'
            && j + 3 < len
            && bytes[j + 1] == b'r'
            && bytes[j + 2] == b'\\'
            && bytes[j + 3] == b'n'
        {
            saw_break = true;
            j += 4;
        } else {
            break;
        }
        while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
    }
    if !saw_break {
        return None;
    }
    let mut run = 0usize;
    let mut k = j;
    while k < len && bytes[k].is_ascii_hexdigit() && run <= 200 {
        run += 1;
        k += 1;
    }
    if !(4..=200).contains(&run) || (run & 1) != 0 {
        return None;
    }
    if k < len && bytes[k].is_ascii_alphanumeric() {
        return None;
    }
    let ends_line_or_quote = k == len || matches!(bytes[k], b'\r' | b'\n' | b'\\' | b'"' | b'\'');
    if run >= 16 || ends_line_or_quote {
        Some(j)
    } else {
        None
    }
}

fn strip_b64_line_breaks(raw: &str) -> String {
    let replaced = raw.replace("\\r\\n", "").replace("\\n", "");
    replaced
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | ' ' | '\t'))
        .collect()
}

fn is_jwt_dot_segment(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let cand = &text[start..end];
    if cand.starts_with("eyJ") && end < bytes.len() && bytes[end] == b'.' {
        return true;
    }
    if start > 4 && bytes[start - 1] == b'.' {
        let mut seg_start = start - 1;
        while seg_start > 0 {
            let prev = bytes[seg_start - 1];
            if prev.is_ascii_alphanumeric() || matches!(prev, b'-' | b'_' | b'.') {
                seg_start -= 1;
            } else {
                break;
            }
        }
        if text[seg_start..start].starts_with("eyJ") {
            return true;
        }
    }
    false
}

/// Distinguishes genuine Unix/Windows filesystem paths from Base64 secrets that start with `/`.
pub fn looks_like_filesystem_path(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    if lower.starts_with("./") || lower.starts_with("../") || lower.starts_with("~/") {
        return true;
    }
    if val.len() >= 3
        && val.as_bytes()[0].is_ascii_alphabetic()
        && matches!(&val[1..3], ":\\" | ":/")
    {
        return true;
    }
    if !val.starts_with('/') {
        return false;
    }
    const KNOWN_ROOTS: &[&str] = &[
        "etc",
        "usr",
        "var",
        "opt",
        "home",
        "users",
        "volumes",
        "library",
        "system",
        "applications",
        "tmp",
        "private",
        "run",
        "proc",
        "sys",
        "dev",
        "bin",
        "sbin",
        "lib",
        "lib64",
        "mnt",
        "media",
        "srv",
        "root",
        "boot",
        "nix",
        "snap",
        "app",
        "workspace",
        "workspaces",
        "data",
        "config",
        "certs",
        "secrets",
        "path",
    ];
    let rest = &lower[1..];
    let first_seg = rest.split('/').next().unwrap_or(rest);
    if KNOWN_ROOTS.contains(&first_seg) {
        return true;
    }
    // Base64 padding (`=`) or `+` outside known OS directories strongly indicates Base64, not a path
    if val.ends_with('=') || val.contains('+') {
        return false;
    }
    let segments: Vec<&str> = val[1..].split('/').collect();
    if segments.len() == 1 {
        let s = segments[0];
        return !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
            && shannon_entropy(s) < 3.8;
    }
    segments.iter().all(|s| {
        if s.is_empty() {
            return false;
        }
        let looks_random_b64_chunk = s.len() >= 10
            && s.bytes().any(|b| b.is_ascii_uppercase())
            && s.bytes().any(|b| b.is_ascii_lowercase())
            && s.bytes().any(|b| b.is_ascii_digit())
            && shannon_entropy(s) >= 3.8;
        !looks_random_b64_chunk
    })
}

fn has_percent_hex_escape(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit()
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Decodes RFC 3986 `%XX` ASCII graphic/whitespace sequences while mapping every output byte back
/// to its exact `[raw_start, raw_end)` byte span in `text` so `scan` and `clean` work on URL-encoded logs.
fn decode_percent_inline_with_spans(text: &str) -> Option<(String, Vec<usize>, Vec<usize>)> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut starts = Vec::with_capacity(len);
    let mut ends = Vec::with_capacity(len);
    let mut changed = false;
    let mut i = 0usize;

    while i < len {
        if bytes[i] == b'%'
            && i + 2 < len
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0);
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0);
            let b = ((hi << 4) | lo) as u8;
            if b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                out.push(b as char);
                starts.push(i);
                ends.push(i + 3);
                changed = true;
                i += 3;
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap();
        let ch_len = ch.len_utf8();
        out.push(ch);
        for off in 0..ch_len {
            starts.push(i + off);
            ends.push(i + off + 1);
        }
        i += ch_len;
    }

    if changed {
        Some((out, starts, ends))
    } else {
        None
    }
}

fn extract_matched_key_name(rule_id: &str, full_match: &str) -> Option<String> {
    if !matches!(
        rule_id,
        "dotenv-generic-secret" | "url-query-secret" | "aws-secret-key" | "jwk-private-key"
    ) {
        return None;
    }
    let lhs = full_match.split([':', '=']).next()?;
    let trimmed = lhs.trim_matches(|c: char| {
        c.is_ascii_whitespace()
            || matches!(
                c,
                '"' | '\'' | '?' | '&' | ';' | ',' | '{' | '(' | '[' | '\\'
            )
    });
    // Strip leading JSONL escape prefixes like `n` from `\nAPI_KEY` or `u0022` from `\u0022API_KEY`
    let cleaned = if let Some(rest) = trimmed
        .strip_prefix("u0022")
        .or_else(|| trimmed.strip_prefix("u0027"))
        .or_else(|| trimmed.strip_prefix("u000a"))
        .or_else(|| trimmed.strip_prefix("u000A"))
    {
        rest
    } else if full_match.starts_with("\\n")
        || full_match.starts_with("\\r")
        || full_match.starts_with("\\t")
    {
        trimmed
            .strip_prefix(['n', 'r', 't'])
            .unwrap_or(trimmed)
            .trim_matches(['"', '\'', '\\'])
    } else {
        trimmed
    };
    let final_key = cleaned
        .trim_end_matches(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\'' | '\\'));
    let final_key = final_key
        .strip_suffix("u0022")
        .or_else(|| final_key.strip_suffix("u0027"))
        .unwrap_or(final_key)
        .trim_end_matches('\\');
    if final_key.is_empty()
        || final_key.len() > 96
        || !final_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return None;
    }
    Some(final_key.to_string())
}

fn passes_post_filter(
    rule: &CompiledRule,
    full_text: &str,
    full_match: &str,
    match_start: usize,
    match_end: usize,
    val: &str,
    eff_hints: DocHints,
) -> bool {
    if val.contains("[REDACTED_BY_LEAKTAP]") || val.contains("REDACTED_BY_LEAKTAP") {
        return false;
    }

    // Do not run whole-match substring placeholder checks on composite rules (`database-uri`,
    // `http-basic-auth-url`, `private-key-pem`, `putty-private-key`, `jwt-token`) or PII rules where hostnames, DB names,
    // or PGP/PuTTY `Comment: ops@example.com` headers legitimately contain words like `example`.
    let check_whole_val_placeholder = !matches!(
        rule.id.as_str(),
        "database-uri"
            | "http-basic-auth-url"
            | "private-key-pem"
            | "putty-private-key"
            | "jwt-token"
            | "pii-email"
            | "internal-hostname"
    );
    if check_whole_val_placeholder && is_likely_placeholder(val) {
        return false;
    }

    if rule.min_entropy > 0.0 && shannon_entropy(val) < rule.min_entropy {
        return false;
    }

    match rule.id.as_str() {
        "aws-access-key" => {
            if val.ends_with("EXAMPLE") || val == "AKIAIOSFODNN7EXAMPLE" {
                return false;
            }
        }
        "gcp-service-account-key" => {
            if !eff_hints.has_gcp_sa {
                let lower_ctx = full_text.to_ascii_lowercase();
                if !lower_ctx.contains("service_account")
                    && !lower_ctx.contains(".iam.gserviceaccount.com")
                {
                    return false;
                }
            }
        }
        "jwk-private-key" => {
            let lhs = full_match.split(':').next().unwrap_or("");
            let param = lhs
                .trim_matches(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\'' | '\\'));
            match param {
                "d" => {
                    if !eff_hints.has_jwk_asymmetric_kty {
                        return false;
                    }
                }
                "p" | "q" | "dp" | "dq" | "qi" => {
                    if !(eff_hints.has_jwk_asymmetric_kty && eff_hints.has_jwk_d_param) {
                        return false;
                    }
                }
                "k" => {
                    if !eff_hints.has_jwk_oct_kty {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        "notion-api-token" => {
            if let Some(sfx) = val.strip_prefix("secret_") {
                let has_upper = sfx.bytes().any(|b| b.is_ascii_uppercase());
                let has_lower = sfx.bytes().any(|b| b.is_ascii_lowercase());
                let has_digit = sfx.bytes().any(|b| b.is_ascii_digit());
                if !(has_upper && has_lower && has_digit) {
                    return false;
                }
            } else if let Some(sfx) = val.strip_prefix("ntn_") {
                let has_alpha = sfx.bytes().any(|b| b.is_ascii_alphabetic());
                let has_digit = sfx.bytes().any(|b| b.is_ascii_digit());
                if !(has_alpha && has_digit) {
                    return false;
                }
            }
        }
        "voyage-api-key" => {
            let sfx = val.strip_prefix("pa-").unwrap_or(val);
            let has_upper = sfx.bytes().any(|b| b.is_ascii_uppercase());
            let has_lower = sfx.bytes().any(|b| b.is_ascii_lowercase());
            let has_digit = sfx.bytes().any(|b| b.is_ascii_digit());
            let hyphens = sfx.bytes().filter(|&b| b == b'-').count();
            if !(has_upper && has_lower && has_digit) || hyphens > 2 {
                return false;
            }
        }
        "vercel-access-token" => {
            let sfx = if val.len() > 4 { &val[4..] } else { val };
            let has_digit = sfx.bytes().any(|b| b.is_ascii_digit());
            let has_alpha = sfx.bytes().any(|b| b.is_ascii_alphabetic());
            if !(has_digit && has_alpha) {
                return false;
            }
        }
        "fireworks-api-key" => {
            let suffix = val.strip_prefix("fw_").unwrap_or(val);
            let has_digit = suffix.bytes().any(|b| b.is_ascii_digit());
            let has_upper = suffix.bytes().any(|b| b.is_ascii_uppercase());
            if !has_digit || !has_upper {
                return false;
            }
        }
        "jwt-token" => {
            // Canonical RFC 7519 / jwt.io documentation token (`{"sub":"1234567890","name":"John Doe"}`)
            if val.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw") {
                return false;
            }
        }
        "resend-api-key" => {
            let suffix = val.strip_prefix("re_").unwrap_or(val);
            let underscore_count = suffix.bytes().filter(|&b| b == b'_').count();
            let has_digit_or_upper = suffix
                .bytes()
                .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase());
            if underscore_count >= 3 || !has_digit_or_upper {
                return false;
            }
        }
        "azure-sas-token" => {
            let lower_ctx = full_text.to_ascii_lowercase();
            if !lower_ctx.contains("sv=")
                && !lower_ctx.contains("se=")
                && !lower_ctx.contains(".windows.net")
                && !lower_ctx.contains(".azure")
            {
                return false;
            }
        }
        "http-bearer-token" | "url-query-secret" => {
            let lower_val = val.to_ascii_lowercase();
            if is_uuid_like(&lower_val)
                || lower_val.contains("%7b")
                || lower_val.contains("%3c")
                || lower_val.starts_with("http://")
                || lower_val.starts_with("https://")
            {
                return false;
            }
            let pure_alpha_ident = val
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'-');
            if pure_alpha_ident && shannon_entropy(val) < 4.2 {
                return false;
            }
        }
        "dotenv-generic-secret" => {
            let key_part = full_match
                .split([':', '='])
                .next()
                .unwrap_or(full_match)
                .to_ascii_uppercase();
            if NON_SECRET_TOKEN_KEYS.iter().any(|k| key_part.contains(k))
                || NON_SECRET_KEY_SUBSTRINGS
                    .iter()
                    .any(|sub| key_part.contains(sub))
            {
                return false;
            }
            let lower_val = val.to_ascii_lowercase();
            // Reject URLs, genuine filesystem paths, env interpolations, standard UUIDs,
            // and truncated documentation/report ellipses (`...`) while catching Base64
            // secrets that start with `/`.
            if lower_val.starts_with("http://")
                || lower_val.starts_with("https://")
                || looks_like_filesystem_path(val)
                || is_uuid_like(&lower_val)
                || val.contains("....")
                || (val.contains("...") && val.len() <= 24)
            {
                return false;
            }
            // Reject function calls, array indexing, or generic type annotations (`token = getSecret(...)`, `secret: Box<...>`)
            if let Some(&next_b) = full_text.as_bytes().get(match_end) {
                if matches!(next_b, b'(' | b'[' | b'<') {
                    return false;
                }
            }
            let is_val_quoted =
                match_start > 0 && matches!(full_text.as_bytes()[match_start - 1], b'"' | b'\'');
            // Reject unquoted code member chains (`process.env.SECRET_KEY`, `self.config.api_key`)
            // and unquoted pure-alphabetic type names (`token: AuthenticationTokenService`)
            if !is_val_quoted {
                if val.contains('.')
                    && val.split('.').all(|seg| {
                        !seg.is_empty()
                            && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    })
                {
                    return false;
                }
                if val.bytes().all(|b| b.is_ascii_alphabetic()) && shannon_entropy(val) < 4.3 {
                    return false;
                }
            }
            let is_pure_hex = val.bytes().all(|b| b.is_ascii_hexdigit());
            let ent = shannon_entropy(val);
            let has_pw_complexity = val.bytes().any(|b| b.is_ascii_uppercase())
                && val.bytes().any(|b| b.is_ascii_lowercase())
                && val.bytes().any(|b| b.is_ascii_digit())
                && val.bytes().any(|b| !b.is_ascii_alphanumeric());
            if !is_pure_hex && !has_pw_complexity && ent < 3.50 {
                return false;
            }
            // Preserve 32/40-char hex keys on explicit API/app/auth/private/signing/secret/password names
            // (e.g. `AZURE_OPENAI_API_KEY`, `DD_API_KEY`, `DD_APP_KEY`), while rejecting 32/40-char MD5/SHA-1
            // digests assigned to bare generic `*_TOKEN` names (`GIT_TOKEN=<40-char-sha>`).
            let explicit_hex_secret_key = [
                "SECRET",
                "PASS",
                "PWD",
                "API_KEY",
                "API-KEY",
                "APIKEY",
                "APP_KEY",
                "APP-KEY",
                "APPKEY",
                "AUTH_KEY",
                "AUTH_TOKEN",
                "ACCESS_KEY",
                "ACCESS_TOKEN",
                "PRIVATE_KEY",
                "SIGNING_KEY",
                "MASTER_KEY",
                "ENCRYPTION_KEY",
                "SERVICE_KEY",
                "STORAGE_KEY",
                "HMAC_KEY",
            ]
            .iter()
            .any(|kw| key_part.contains(kw));
            if is_pure_hex && matches!(val.len(), 32 | 40) && !explicit_hex_secret_key {
                return false;
            }
            let all_lower_ident = !is_pure_hex
                && val
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || matches!(c, '_' | '-' | '.'));
            let all_upper_ident = !is_pure_hex
                && val
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || matches!(c, '_' | '-' | '.'));
            if (all_lower_ident || all_upper_ident) && ent < 4.1 {
                return false;
            }
        }
        "private-key-pem" => {
            if val.len() > 32_768 {
                return false;
            }
            // Extract pure base64 payload characters (excluding headers, armor metadata, and JSON escapes)
            let b64_body = extract_pem_body_chars(val);
            if b64_body.len() < 16 || shannon_entropy(&b64_body) < 3.0 {
                return false;
            }
        }
        "putty-private-key" => {
            if val.len() > 32_768 {
                return false;
            }
        }
        "database-uri" | "http-basic-auth-url" => {
            let lower = val.to_ascii_lowercase();
            let is_local_host = lower.contains("@localhost")
                || lower.contains("@127.0.0.1")
                || lower.contains("@0.0.0.0")
                || lower.contains("@[::1]")
                || lower.contains("@host.docker.internal");
            if is_local_host {
                return false;
            }
            if let Some((scheme, after_scheme)) = lower.split_once("://") {
                let Some((creds, host_rest)) = after_scheme.split_once('@') else {
                    return false;
                };
                // For http/https Basic Auth URLs, require a real domain/IP host after `@`
                if (scheme == "http" || scheme == "https") && !host_rest.contains('.') {
                    return false;
                }
                if let Some((user, pass)) = creds.split_once(':') {
                    // Redis / Upstash URLs commonly omit username (`redis://:password@host`),
                    // whereas HTTP Basic Auth requires a non-empty username.
                    if (rule.id == "http-basic-auth-url" && user.is_empty())
                        || pass.is_empty()
                        || is_likely_placeholder(pass)
                        || matches!(
                            pass,
                            "password"
                                | "postgres"
                                | "root"
                                | "admin"
                                | "secret"
                                | "pass"
                                | "test"
                                | "changeme"
                                | "x-oauth-basic"
                        )
                    {
                        return false;
                    }
                }
            }
        }
        "internal-hostname" => {
            let lower = val.to_ascii_lowercase();
            let has_scheme = lower.starts_with("http://") || lower.starts_with("https://");
            let host_only = lower
                .strip_prefix("https://")
                .or_else(|| lower.strip_prefix("http://"))
                .unwrap_or(&lower);
            if matches!(
                host_only,
                "host.docker.internal"
                    | "gateway.docker.internal"
                    | "vm.docker.internal"
                    | "host.containers.internal"
                    | "host.lima.internal"
                    | "host.minikube.internal"
                    | "kubernetes.default.svc.cluster.local"
            ) {
                return false;
            }
            let labels: Vec<&str> = host_only.split('.').collect();
            if let Some(&first_label) = labels.first() {
                if !has_scheme && CODE_RECEIVER_LABELS.contains(&first_label) {
                    return false;
                }
            }
            // Suppress JS/TS/Python/Rust/Go property access chains like `app.config.internal` or `service.auth.internal`
            if host_only.ends_with(".internal") && !has_scheme {
                let prev_has_url_delim =
                    match_start > 0 && matches!(full_text.as_bytes()[match_start - 1], b'/' | b'@');
                let next_has_port_or_path = match_end < full_text.len()
                    && matches!(full_text.as_bytes()[match_end], b':' | b'/');
                let has_hyphen_or_digit =
                    host_only.bytes().any(|b| b == b'-' || b.is_ascii_digit());
                let penultimate = labels
                    .len()
                    .checked_sub(2)
                    .and_then(|i| labels.get(i))
                    .copied()
                    .unwrap_or("");
                let has_infra_zone = INFRA_INTERNAL_ZONES
                    .iter()
                    .any(|z| penultimate == *z || penultimate.starts_with(z));

                if !prev_has_url_delim
                    && !next_has_port_or_path
                    && !has_hyphen_or_digit
                    && !has_infra_zone
                {
                    return false;
                }
            }
        }
        "pii-email" => {
            let lower = val.to_ascii_lowercase();
            if match_start > 0 {
                let prev_byte = full_text.as_bytes()[match_start - 1];
                if prev_byte == b'/' || prev_byte == b'@' {
                    return false;
                }
                if prev_byte == b':'
                    && !full_text[..match_start]
                        .to_ascii_lowercase()
                        .ends_with("mailto:")
                {
                    return false;
                }
            }
            let Some((local, domain)) = lower.split_once('@') else {
                return false;
            };
            if local == "git"
                || local == "noreply"
                || local == "no-reply"
                || local == "support"
                || local == "security"
                || local.starts_with("test")
            {
                return false;
            }
            if domain.ends_with("example.com")
                || domain.ends_with("example.org")
                || domain.ends_with("test.com")
                || domain.ends_with("localhost")
                || domain.ends_with("users.noreply.github.com")
                || domain.ends_with("anthropic.com")
                || domain.ends_with("openai.com")
            {
                return false;
            }
            if domain.ends_with(".json")
                || domain.ends_with(".js")
                || domain.ends_with(".ts")
                || domain.ends_with(".png")
                || domain.ends_with(".svg")
                || domain.ends_with(".py")
                || domain.ends_with(".rs")
                || domain.ends_with(".lock")
                || domain.ends_with(".toml")
                || domain.ends_with(".yaml")
                || domain.ends_with(".yml")
            {
                return false;
            }
        }
        _ => {}
    }

    true
}

fn extract_pem_body_chars(pem: &str) -> String {
    let normalized = pem
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\u000a", "\n")
        .replace("\\u000A", "\n")
        .replace("\\u000d", "\r")
        .replace("\\u000D", "\r");
    let mut body = String::new();
    for line in normalized.lines() {
        let t = line.trim().trim_end_matches('\\');
        if t.is_empty()
            || t.starts_with("-----BEGIN ")
            || t.starts_with("-----END ")
            || t.contains(": ")
            || (t.starts_with('=') && t.len() == 5)
        {
            continue;
        }
        for ch in t.chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=') {
                body.push(ch);
            }
        }
    }
    body
}

fn is_uuid_like(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    for (idx, &ch) in b.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub fn is_likely_placeholder(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "example"
            | "placeholder"
            | "dummy"
            | "changeme"
            | "change_me"
            | "change-me"
            | "replace_me"
            | "password"
            | "secret"
            | "token"
            | "null"
            | "undefined"
            | "none"
    ) {
        return true;
    }
    const UNCONDITIONAL_MARKERS: &[&str] = &[
        "your_api_key",
        "your-api-key",
        "your_secret",
        "your-secret",
        "your_token",
        "your-token",
        "replace_me",
        "replace-me",
        "insert_your",
        "redacted_by_leaktap",
        "[redacted]",
        "<redacted>",
        "xxxxxxxx",
        "${",
        "<your",
    ];
    if UNCONDITIONAL_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }

    for seq in ["0000000000", "abcdef123456"] {
        if lower.contains(seq) {
            let ent = shannon_entropy(val);
            if ent < 3.5 || seq.len() * 100 >= val.len() * 45 {
                return true;
            }
        }
    }

    const SOFT_DOC_WORDS: &[&str] = &[
        "example",
        "placeholder",
        "dummy",
        "changeme",
        "change_me",
        "change-me",
    ];
    if SOFT_DOC_WORDS.iter().any(|w| lower.contains(w)) {
        // Do not discard complex real passwords (`K9#mP2$vL8@exampleProdDb99!`, `ChAnGeMe!9#kL2$vP8@Prod`)
        // or high-entropy cryptographic tokens (`entropy >= 4.5`) that happen to contain an English substring.
        let has_pw_symbol = val.bytes().any(|b| {
            matches!(
                b,
                b'!' | b'#' | b'$' | b'%' | b'^' | b'&' | b'*' | b'@' | b'?' | b'~'
            )
        });
        let has_upper = val.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = val.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = val.bytes().any(|b| b.is_ascii_digit());
        let ent = shannon_entropy(val);
        if (has_pw_symbol && has_upper && has_lower && has_digit && val.len() >= 16 && ent >= 3.85)
            || (val.len() >= 32 && ent >= 4.5)
        {
            return false;
        }
        return true;
    }
    false
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn mask_value(rule_id: &str, raw: &str) -> String {
    if rule_id == "private-key-pem" {
        let fp = &fingerprint_match(rule_id, raw)[..6];
        if raw.contains("PGP PRIVATE KEY BLOCK") {
            return format!("-----BEGIN PGP PRIVATE KEY BLOCK----- ({fp})");
        }
        return format!("-----BEGIN ... PRIVATE KEY----- ({fp})");
    }
    if rule_id == "putty-private-key" {
        let fp = &fingerprint_match(rule_id, raw)[..6];
        return format!("PuTTY-User-Key-File-... ({fp})");
    }
    if rule_id == "database-uri" || rule_id == "http-basic-auth-url" {
        if let Some((scheme, rest)) = raw.split_once("://") {
            if let Some((_, host_part)) = rest.split_once('@') {
                let host_short = host_part.split('/').next().unwrap_or(host_part);
                return format!("{scheme}://***@{host_short}");
            }
        }
    }
    if rule_id == "pii-email" {
        if let Some((local, domain)) = raw.split_once('@') {
            let first = local.chars().next().unwrap_or('*');
            return format!("{first}***@{domain}");
        }
    }
    if rule_id == "internal-hostname" {
        return raw.to_string();
    }

    let chars: Vec<char> = raw.chars().collect();
    let len = chars.len();
    if len <= 10 {
        let first = chars.first().copied().unwrap_or('*');
        let last = chars.last().copied().unwrap_or('*');
        return format!("{first}***{last}");
    }
    // Keep generic user-chosen passwords and raw key payloads tightly masked (at most 3 leading + 2 trailing chars)
    if matches!(
        rule_id,
        "dotenv-generic-secret"
            | "url-query-secret"
            | "http-bearer-token"
            | "aws-secret-key"
            | "jwk-private-key"
            | "kubernetes-secret-data"
    ) {
        let prefix: String = chars[..3].iter().collect();
        let suffix: String = chars[len - 2..].iter().collect();
        return format!("{prefix}***{suffix}");
    }
    let prefix_len = len.min(10).min(len / 3 + 3);
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
    format!("{prefix}...{suffix}")
}

/// Extracts only the non-secret vendor/type prefix (e.g. `sk-ant-`, `ghp_`, `AKIA`) when present.
/// User-chosen passwords and unprefixed secret material (`dotenv-generic-secret`, `aws-secret-key`,
/// `url-query-secret`, `http-bearer-token`, `azure-storage-key`, etc.) return `None` so 100% of
/// the secret value is replaced with `[REDACTED_BY_LEAKTAP]`.
fn public_vendor_prefix(rule_id: &str, raw: &str) -> Option<&'static str> {
    const KNOWN_PREFIXES: &[(&str, &[&str])] = &[
        ("stripe-live-key", &["sk_live_", "rk_live_", "whsec_"]),
        ("aws-access-key", &["AKIA", "ASIA", "AGPA", "AIDA", "AROA"]),
        ("anthropic-api-key", &["sk-ant-"]),
        (
            "openai-api-key",
            &["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"],
        ),
        (
            "github-pat",
            &["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        ),
        (
            "gitlab-pat",
            &[
                "glagent-", "glpat-", "gloas-", "glsoat-", "glptt-", "gldt-", "glrt-", "glft-",
            ],
        ),
        ("gcp-api-key", &["AIza"]),
        ("google-oauth-token", &["ya29."]),
        ("google-oauth-client-secret", &["GOCSPX-"]),
        ("supabase-secret-key", &["sb_secret_", "sbp_"]),
        (
            "shopify-access-token",
            &["shpat_", "shpca_", "shppa_", "shpss_"],
        ),
        (
            "slack-token",
            &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"],
        ),
        ("huggingface-token", &["hf_"]),
        ("groq-api-key", &["gsk_"]),
        ("perplexity-api-key", &["pplx-"]),
        ("linear-api-key", &["lin_api_"]),
        ("postman-api-key", &["PMAK-"]),
        ("npm-access-token", &["npm_"]),
        ("pypi-upload-token", &["pypi-"]),
        ("sendgrid-api-key", &["SG."]),
        ("vault-token", &["hvs.", "hvb."]),
        ("digitalocean-token", &["dop_v1_", "doo_v1_", "dor_v1_"]),
        ("databricks-pat", &["dapi"]),
        ("age-secret-key", &["AGE-SECRET-KEY-1"]),
        ("resend-api-key", &["re_"]),
        ("twilio-api-key", &["SK"]),
        ("sentry-auth-token", &["sntrys_", "sntryu_"]),
        ("grafana-token", &["glsa_", "glc_"]),
        (
            "planetscale-token",
            &["pscale_tkn_", "pscale_pw_", "pscale_oauth_"],
        ),
        ("flyio-token", &["fo1_", "fm2_"]),
        ("terraform-api-token", &["atlasv1."]),
        (
            "doppler-api-token",
            &["dp.st.", "dp.pt.", "dp.ct.", "dp.sa.", "dp.scim."],
        ),
        ("newrelic-api-key", &["NRAK-", "NRJS-"]),
        ("buildkite-agent-token", &["bkua_", "bkagent_"]),
        ("atlassian-api-token", &["ATATT3", "ATCTT3"]),
        ("openrouter-api-key", &["sk-or-v1-"]),
        ("xai-api-key", &["xai-"]),
        ("replicate-api-token", &["r8_"]),
        ("langsmith-api-key", &["lsv2_pt_", "lsv2_sk_"]),
        ("pinecone-api-key", &["pcsk_"]),
        (
            "tailscale-api-key",
            &["tskey-auth-", "tskey-api-", "tskey-client-", "tskey-scim-"],
        ),
        ("pulumi-access-token", &["pul-"]),
        ("tavily-api-key", &["tvly-"]),
        ("neon-api-key", &["napi_"]),
        ("cerebras-api-key", &["csk-"]),
        ("fireworks-api-key", &["fw_"]),
        ("notion-api-token", &["ntn_", "secret_"]),
        ("airtable-pat", &["pat"]),
        ("hubspot-pat", &["pat-na1-", "pat-eu1-"]),
        ("square-access-token", &["sq0atp-", "sq0csp-"]),
        ("figma-pat", &["figd_"]),
        ("voyage-api-key", &["pa-"]),
        ("vercel-access-token", &["vcp_", "vca_", "vck_"]),
        ("jwt-token", &["eyJ"]),
    ];

    for &(id, prefixes) in KNOWN_PREFIXES {
        if id == rule_id {
            for &pfx in prefixes {
                if raw.starts_with(pfx) {
                    return Some(pfx);
                }
            }
            return None;
        }
    }
    None
}

pub fn redact_replacement(rule_id: &str, raw: &str) -> String {
    if rule_id == "private-key-pem" {
        if raw.contains("PGP PRIVATE KEY BLOCK") {
            return "-----BEGIN [REDACTED_BY_LEAKTAP] PGP PRIVATE KEY BLOCK-----".to_string();
        }
        return "-----BEGIN [REDACTED_BY_LEAKTAP] PRIVATE KEY-----".to_string();
    }
    if rule_id == "putty-private-key" {
        return "PuTTY-User-Key-File-3: [REDACTED_BY_LEAKTAP]".to_string();
    }
    if rule_id == "database-uri" || rule_id == "http-basic-auth-url" {
        if let Some((scheme, rest)) = raw.split_once("://") {
            if let Some((creds, host_part)) = rest.split_once('@') {
                let user = creds.split(':').next().unwrap_or("");
                return format!("{scheme}://{user}:[REDACTED_BY_LEAKTAP]@{host_part}");
            }
        }
    }
    if rule_id == "slack-webhook" {
        return "https://hooks.slack.com/services/[REDACTED_BY_LEAKTAP]".to_string();
    }
    if rule_id == "discord-webhook" {
        return "https://discord.com/api/webhooks/[REDACTED_BY_LEAKTAP]".to_string();
    }
    if let Some(vendor_pfx) = public_vendor_prefix(rule_id, raw) {
        return format!("{vendor_pfx}[REDACTED_BY_LEAKTAP]");
    }
    "[REDACTED_BY_LEAKTAP]".to_string()
}

pub fn fingerprint_match(rule_id: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    // 16 hex chars (64 bits) is collision-free for local dedup + SARIF partialFingerprints
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}
