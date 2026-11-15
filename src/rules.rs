use aho_corasick::AhoCorasick;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Secret,
    Pii,
}

pub struct CompiledRule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub category: RuleCategory,
    pub anchors: &'static [&'static str],
    pub regex: Regex,
    /// Capture group containing the sensitive value (0 = full match)
    pub secret_group: usize,
    /// Minimum Shannon entropy required on the captured secret (0.0 = skip check)
    pub min_entropy: f64,
}

#[derive(Debug, Clone)]
pub struct RawMatch {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub category: RuleCategory,
    /// Byte start of the sensitive value within the scanned text
    pub start: usize,
    /// Byte end of the sensitive value within the scanned text
    pub end: usize,
    pub masked: String,
    pub fingerprint: String,
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    prefilter: AhoCorasick,
    anchor_to_rule: Vec<usize>,
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
        description: "Live Stripe secret or restricted API key granting production payment access.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk_live_", "rk_live_"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b",
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
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b",
        secret_group: 1,
        min_entropy: 3.0,
    },
    RuleSpec {
        id: "aws-secret-key",
        name: "AWS Secret Key",
        description: "40-character AWS secret access key assigned in config or environment text.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &[
            "AWS_SECRET_ACCESS_KEY",
            "aws_secret_access_key",
            "AwsSecretAccessKey",
        ],
        pattern: r#"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|AwsSecretAccessKey)\s*[:=]\s*\\?["']?([A-Za-z0-9/+=]{40})\\?["']?"#,
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "anthropic-api-key",
        name: "Anthropic API Key",
        description: "Anthropic API key capable of billing model inference directly.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk-ant-"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(sk-ant-(?:api03|admin01)-[A-Za-z0-9\-_]{32,140})\b",
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "openai-api-key",
        name: "OpenAI API Key",
        description: "OpenAI project, service-account, or admin API key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{32,200})\b",
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "github-pat",
        name: "GitHub PAT",
        description: "GitHub classic or fine-grained personal access / OAuth token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "gitlab-pat",
        name: "GitLab Token",
        description: "GitLab personal access token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["glpat-"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(glpat-[A-Za-z0-9\-_]{20,64})\b",
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
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(AIza[0-9A-Za-z\-_]{35})\b",
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "slack-token",
        name: "Slack Token",
        description: "Slack bot, user, workspace, or app-level token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])((?:xox[baprs]|xapp)-[0-9A-Za-z\-]{24,160})\b",
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
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(hf_[A-Za-z0-9]{34,64})\b",
        secret_group: 1,
        min_entropy: 3.5,
    },
    RuleSpec {
        id: "npm-access-token",
        name: "npm Access Token",
        description: "npm registry publish or automation token.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["npm_"],
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(npm_[A-Za-z0-9]{36})\b",
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
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,200})\b",
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
        pattern: r"(?:^|[^A-Za-z0-9_]|\\[nrt])(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b",
        secret_group: 1,
        min_entropy: 3.8,
    },
    RuleSpec {
        id: "private-key-pem",
        name: "Private Key Block",
        description: "PEM-encoded RSA, EC, OpenSSH, DSA, or PKCS#8 private key.",
        severity: Severity::Critical,
        category: RuleCategory::Secret,
        anchors: &["-----BEGIN "],
        pattern: r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----)",
        secret_group: 1,
        min_entropy: 0.0,
    },
    RuleSpec {
        id: "database-uri",
        name: "Database URI",
        description: "Connection string with embedded credentials for Postgres, MySQL, MongoDB, Redis, or AMQP.",
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
        ],
        pattern: r#"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqp)://[^\s"':/@\\]+:[^\s"'/@\\]{6,}@[^\s"'<>\\]+)"#,
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
        pattern: r"\b(eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{20,})\b",
        secret_group: 1,
        min_entropy: 3.9,
    },
    RuleSpec {
        id: "dotenv-generic-secret",
        name: "Env Secret Assignment",
        description: "High-entropy secret assigned to *_SECRET, *_TOKEN, *_PASSWORD, or *_API_KEY.",
        severity: Severity::High,
        category: RuleCategory::Secret,
        anchors: &[
            "_SECRET=",
            "_SECRET_KEY=",
            "_API_KEY=",
            "_ACCESS_TOKEN=",
            "_AUTH_TOKEN=",
            "_PRIVATE_KEY=",
            "DB_PASSWORD=",
            "DATABASE_PASSWORD=",
        ],
        pattern: r#"\b[A-Z][A-Z0-9_]*(?:_SECRET|_SECRET_KEY|_API_KEY|_ACCESS_TOKEN|_AUTH_TOKEN|_PRIVATE_KEY|DB_PASSWORD|DATABASE_PASSWORD)=["']?([A-Za-z0-9/+=\-_!@#$%^&*]{18,160})["']?"#,
        secret_group: 1,
        min_entropy: 3.85,
    },
    RuleSpec {
        id: "pii-email",
        name: "Email Address",
        description: "Personal or corporate email address included in outbound agent context or headers.",
        severity: Severity::Medium,
        category: RuleCategory::Pii,
        anchors: &["@"],
        pattern: r"\b([A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,120}\.[A-Za-z]{2,12})\b",
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
        pattern: r"\b((?:https?://)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\.corp|\.internal|\.intranet|\.svc\.cluster\.local|\.localdomain))\b",
        secret_group: 1,
        min_entropy: 0.0,
    },
];

impl RuleEngine {
    pub fn new(include_pii: bool) -> Self {
        let mut rules = Vec::new();
        let mut patterns = Vec::new();
        let mut anchor_to_rule = Vec::new();

        for spec in RULE_SPECS {
            if !include_pii && spec.category == RuleCategory::Pii {
                continue;
            }
            let rule_idx = rules.len();
            for &anchor in spec.anchors {
                patterns.push(anchor);
                anchor_to_rule.push(rule_idx);
            }
            rules.push(CompiledRule {
                id: spec.id,
                name: spec.name,
                description: spec.description,
                severity: spec.severity,
                category: spec.category,
                anchors: spec.anchors,
                regex: Regex::new(spec.pattern).expect("valid built-in regex"),
                secret_group: spec.secret_group,
                min_entropy: spec.min_entropy,
            });
        }

        let prefilter = AhoCorasick::new(&patterns).expect("valid Aho-Corasick anchors");
        Self {
            rules,
            prefilter,
            anchor_to_rule,
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
        if text.is_empty() {
            return Vec::new();
        }

        // Fast pass: collect only candidate rules whose anchor substrings appear in `text`.
        let mut candidate_bits: u64 = 0;
        let mut extra_candidates: Option<HashSet<usize>> = None;

        for mat in self.prefilter.find_iter(text) {
            let rule_idx = self.anchor_to_rule[mat.pattern().as_usize()];
            if rule_idx < 64 {
                candidate_bits |= 1u64 << rule_idx;
            } else {
                extra_candidates
                    .get_or_insert_with(HashSet::new)
                    .insert(rule_idx);
            }
        }

        if candidate_bits == 0 && extra_candidates.is_none() {
            return Vec::new();
        }

        let mut matches = Vec::new();

        for (idx, rule) in self.rules.iter().enumerate() {
            let active = if idx < 64 {
                (candidate_bits & (1u64 << idx)) != 0
            } else {
                extra_candidates
                    .as_ref()
                    .is_some_and(|set| set.contains(&idx))
            };
            if !active {
                continue;
            }

            for caps in rule.regex.captures_iter(text) {
                let Some(m) = caps.get(rule.secret_group) else {
                    continue;
                };
                let val = m.as_str();

                if !passes_post_filter(rule, text, m.start(), val) {
                    continue;
                }

                matches.push(RawMatch {
                    rule_id: rule.id,
                    rule_name: rule.name,
                    severity: rule.severity,
                    category: rule.category,
                    start: m.start(),
                    end: m.end(),
                    masked: mask_value(rule.id, val),
                    fingerprint: fingerprint_match(rule.id, val),
                });
            }
        }

        // Sort by byte offset and drop overlapping weaker matches on the exact same span
        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| b.severity.cmp(&a.severity))
        });
        let mut deduped: Vec<RawMatch> = Vec::with_capacity(matches.len());
        for m in matches {
            if let Some(prev) = deduped.last() {
                if m.start < prev.end && m.category == prev.category {
                    continue;
                }
            }
            deduped.push(m);
        }

        deduped
    }
}

fn passes_post_filter(rule: &CompiledRule, full_text: &str, match_start: usize, val: &str) -> bool {
    if is_likely_placeholder(val) {
        return false;
    }

    if rule.min_entropy > 0.0 && shannon_entropy(val) < rule.min_entropy {
        return false;
    }

    match rule.id {
        "aws-access-key" => {
            if val.ends_with("EXAMPLE") || val == "AKIAIOSFODNN7EXAMPLE" {
                return false;
            }
        }
        "database-uri" => {
            let lower = val.to_ascii_lowercase();
            // Ignore local dev URIs with trivial credentials
            let is_local_host = lower.contains("@localhost")
                || lower.contains("@127.0.0.1")
                || lower.contains("@0.0.0.0")
                || lower.contains("@host.docker.internal");
            if is_local_host {
                return false;
            }
            if let Some((_, after_scheme)) = lower.split_once("://") {
                if let Some((creds, _)) = after_scheme.split_once('@') {
                    if let Some((_, pass)) = creds.split_once(':') {
                        if matches!(
                            pass,
                            "password"
                                | "postgres"
                                | "root"
                                | "admin"
                                | "secret"
                                | "pass"
                                | "test"
                                | "changeme"
                        ) {
                            return false;
                        }
                    }
                }
            }
        }
        "pii-email" => {
            let lower = val.to_ascii_lowercase();
            // Exclude git SSH prefixes (`git@github.com`), npm scopes, noreply addresses, and dummy domains
            if match_start > 0 {
                let prev_byte = full_text.as_bytes()[match_start - 1];
                if prev_byte == b'/' || prev_byte == b'@' {
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
            // Reject version-like suffixes or file extensions (`foo@bar.json`, `pkg@1.2.3`, `icon@2x.png`)
            if domain.ends_with(".json")
                || domain.ends_with(".js")
                || domain.ends_with(".ts")
                || domain.ends_with(".png")
                || domain.ends_with(".svg")
                || domain.ends_with(".py")
                || domain.ends_with(".rs")
                || domain.ends_with(".lock")
            {
                return false;
            }
        }
        _ => {}
    }

    true
}

pub fn is_likely_placeholder(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "example",
        "placeholder",
        "your_api_key",
        "your-api-key",
        "your_secret",
        "your_token",
        "changeme",
        "replace_me",
        "dummy",
        "redacted",
        "leaktap",
        "xxxxxxxx",
        "0000000000",
        "abcdef123456",
        "${",
        "<your",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
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
        return "-----BEGIN ... PRIVATE KEY-----".to_string();
    }
    if rule_id == "database-uri" {
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
    let prefix_len = len.min(10).min(len / 3 + 3);
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
    format!("{prefix}...{suffix}")
}

pub fn redact_replacement(rule_id: &str, raw: &str) -> String {
    if rule_id == "private-key-pem" {
        return "-----BEGIN [REDACTED_BY_LEAKTAP] PRIVATE KEY-----".to_string();
    }
    if rule_id == "database-uri" {
        if let Some((scheme, rest)) = raw.split_once("://") {
            if let Some((creds, host_part)) = rest.split_once('@') {
                let user = creds.split(':').next().unwrap_or("user");
                return format!("{scheme}://{user}:[REDACTED_BY_LEAKTAP]@{host_part}");
            }
        }
    }
    let chars: Vec<char> = raw.chars().collect();
    let prefix_len = chars.len().min(6);
    let prefix: String = chars[..prefix_len].iter().collect();
    format!("{prefix}[REDACTED_BY_LEAKTAP]")
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
