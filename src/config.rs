use crate::discovery::home_dir;
use crate::rules::{RuleCategory, Severity};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default, Clone, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub allowlist: AllowlistSpec,
    #[serde(default)]
    pub rules: Vec<CustomRuleSpec>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct AllowlistSpec {
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
    /// Per-rule path allowlists, e.g. `mcp-unpinned-package = ["docs/**", "README.md"]`
    #[serde(default)]
    pub rule_paths: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRuleSpec {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_custom_severity")]
    pub severity: Severity,
    #[serde(default = "default_custom_category")]
    pub category: RuleCategory,
    #[serde(alias = "regex")]
    pub pattern: String,
    #[serde(default)]
    pub anchors: Vec<String>,
    #[serde(default)]
    pub secret_group: Option<usize>,
    #[serde(default)]
    pub min_entropy: f64,
}

fn default_custom_severity() -> Severity {
    Severity::High
}

fn default_custom_category() -> RuleCategory {
    RuleCategory::Secret
}

/// Project-scoped policy loaded from `<project>/.leaktap.toml` or `<project>/.leaktapignore`
/// when `--trust-project-config` is explicitly enabled.
///
/// SECURITY INVARIANT: A `ScopedPolicy` ONLY applies to files physically inside `root_abs`
/// (or `root_canon`). It NEVER suppresses findings in `~/.claude`, `~/.codex`, other repos,
/// or live `--block-secrets` wiretap traffic.
#[derive(Debug, Clone)]
pub struct ScopedPolicy {
    pub root_abs: PathBuf,
    pub root_canon: Option<PathBuf>,
    pub disabled_rules: HashSet<String>,
    pub ignored_fingerprints: HashSet<String>,
    pub stopwords_lower: Vec<String>,
    pub path_matchers: Vec<Regex>,
    pub rule_path_matchers: HashMap<String, Vec<Regex>>,
    pub custom_rules: Vec<CustomRuleSpec>,
}

impl ScopedPolicy {
    fn new(root: &Path) -> Self {
        let root_abs = normalize_abs_path(root);
        let root_canon = fs::canonicalize(&root_abs).ok();
        Self {
            root_abs,
            root_canon,
            disabled_rules: HashSet::new(),
            ignored_fingerprints: HashSet::new(),
            stopwords_lower: Vec::new(),
            path_matchers: Vec::new(),
            rule_path_matchers: HashMap::new(),
            custom_rules: Vec::new(),
        }
    }

    pub fn applies_to(&self, path: &Path) -> bool {
        let abs = normalize_abs_path(path);
        if abs.starts_with(&self.root_abs) {
            return true;
        }
        if let Some(ref rc) = self.root_canon {
            if abs.starts_with(rc) {
                return true;
            }
            if let Ok(canon) = fs::canonicalize(&abs) {
                if canon.starts_with(rc) || canon.starts_with(&self.root_abs) {
                    return true;
                }
            }
        }
        false
    }

    fn matches_regex_slice(matchers: &[Regex], path: &Path) -> bool {
        if matchers.is_empty() {
            return false;
        }
        let abs = normalize_abs_path(path);
        let abs_str = abs.to_string_lossy().replace('\\', "/");
        if matchers.iter().any(|re| re.is_match(&abs_str)) {
            return true;
        }
        if let Ok(canon) = fs::canonicalize(&abs) {
            let canon_str = canon.to_string_lossy().replace('\\', "/");
            if canon_str != abs_str && matchers.iter().any(|re| re.is_match(&canon_str)) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Default, Clone)]
pub struct PolicyConfig {
    pub disabled_rules: HashSet<String>,
    pub ignored_fingerprints: HashSet<String>,
    pub stopwords_lower: Vec<String>,
    pub path_matchers: Vec<Regex>,
    pub rule_path_matchers: HashMap<String, Vec<Regex>>,
    pub scoped_policies: Vec<ScopedPolicy>,
    pub custom_rules: Vec<CustomRuleSpec>,
    pub ignored_untrusted_configs: Vec<PathBuf>,
}

impl PolicyConfig {
    pub fn load(explicit_config: Option<&Path>, scan_paths: &[PathBuf]) -> Result<Self, String> {
        Self::load_with_options(explicit_config, scan_paths, false, false)
    }

    pub fn load_with_options(
        explicit_config: Option<&Path>,
        scan_paths: &[PathBuf],
        trust_project_config: bool,
        no_config: bool,
    ) -> Result<Self, String> {
        Self::load_with_git_ref(
            explicit_config,
            None,
            scan_paths,
            trust_project_config,
            no_config,
        )
    }

    pub fn load_with_git_ref(
        explicit_config: Option<&Path>,
        policy_git_ref: Option<&str>,
        scan_paths: &[PathBuf],
        trust_project_config: bool,
        no_config: bool,
    ) -> Result<Self, String> {
        if no_config {
            if explicit_config.is_some() || policy_git_ref.is_some() {
                return Err(
                    "cannot combine `--config` or `--policy-git-ref` with `--no-config`"
                        .to_string(),
                );
            }
            return Ok(PolicyConfig::default());
        }

        let mut merged = PolicyConfig::default();

        // 1. Trusted user/fleet policy (`~/.config/leaktap/config.toml` or `~/.leaktap/config.toml`),
        // loaded ONLY when `--config` and `--policy-git-ref` were NOT explicitly provided (so CI stays hermetic).
        if explicit_config.is_none() && policy_git_ref.is_none() {
            if let Some(home) = home_dir() {
                for cand in [
                    home.join(".config/leaktap/config.toml"),
                    home.join(".leaktap/config.toml"),
                ] {
                    if cand.is_file() {
                        let raw = fs::read_to_string(&cand)
                            .map_err(|e| format!("failed to read `{}`: {e}", cand.display()))?;
                        let parsed: PolicyFile = toml::from_str(&raw)
                            .map_err(|e| format!("invalid TOML in `{}`: {e}", cand.display()))?;
                        merged.merge_global_policy_file(parsed, &[])?;
                    }
                }
            }
        }

        // Collect scan roots and cwd for anchoring relative globs in `--config <file>` and discovering project configs
        let mut anchor_dirs: Vec<PathBuf> = Vec::new();
        if let Ok(cwd) = env::current_dir() {
            anchor_dirs.push(cwd);
        }
        for p in scan_paths {
            let root_dir = if p.is_dir() {
                Some(p.clone())
            } else {
                p.parent().map(Path::to_path_buf)
            };
            if let Some(dir) = root_dir {
                if !dir.as_os_str().is_empty() && !anchor_dirs.contains(&dir) {
                    anchor_dirs.push(dir);
                }
            }
        }

        // 2. Explicit `--config <file>` policy (hermetic override; relative globs anchor to cwd, scan_paths, and config parent)
        if let Some(cfg) = explicit_config {
            let raw = fs::read_to_string(cfg)
                .map_err(|e| format!("failed to read config `{}`: {e}", cfg.display()))?;
            let is_ignore_file = cfg
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("ignore"));
            let mut explicit_anchors = anchor_dirs.clone();
            if let Some(parent) = cfg.parent() {
                if !parent.as_os_str().is_empty()
                    && !explicit_anchors.contains(&parent.to_path_buf())
                {
                    explicit_anchors.push(parent.to_path_buf());
                }
            }
            if is_ignore_file {
                merged.add_global_ignore_lines(&raw, &explicit_anchors);
            } else {
                let parsed: PolicyFile = toml::from_str(&raw)
                    .map_err(|e| format!("invalid TOML in `{}`: {e}", cfg.display()))?;
                merged.merge_global_policy_file(parsed, &explicit_anchors)?;
            }
            if !trust_project_config && policy_git_ref.is_none() {
                return Ok(merged);
            }
        }

        // 2b. Trusted git ref policy (`--policy-git-ref origin/main`) for pull-request CI:
        // loads `.leaktap.toml`, `leaktap.toml`, and `.leaktapignore` directly from `<REF>` via `git`
        // (scoped strictly to each discovered git repo root) while ignoring untrusted working-tree edits.
        if let Some(raw_ref) = policy_git_ref {
            let git_ref = raw_ref.trim();
            if git_ref.is_empty() || git_ref.starts_with('-') || git_ref.contains('\0') {
                return Err(format!("invalid `--policy-git-ref` value `{git_ref}`"));
            }
            let repo_roots = discover_git_repo_roots(&anchor_dirs);
            if repo_roots.is_empty() {
                return Err(format!(
                    "`--policy-git-ref {git_ref}` requires running inside or targeting a git repository"
                ));
            }
            let mut verified_any_ref = false;
            for repo_root in &repo_roots {
                let verify_spec = format!("{git_ref}^{{commit}}");
                if !git_ref_exists(repo_root, &verify_spec) {
                    continue;
                }
                verified_any_ref = true;
                for name in [".leaktap.toml", "leaktap.toml"] {
                    let obj_spec = format!("{git_ref}:{name}");
                    if let Some(raw) = read_git_blob_utf8(repo_root, &obj_spec) {
                        let parsed: PolicyFile = toml::from_str(&raw).map_err(|e| {
                            format!(
                                "invalid TOML in `{}` ({obj_spec}): {e}",
                                repo_root.display()
                            )
                        })?;
                        merged.merge_scoped_project_policy_file(parsed, repo_root)?;
                    }
                }
                let ig_spec = format!("{git_ref}:.leaktapignore");
                if let Some(raw) = read_git_blob_utf8(repo_root, &ig_spec) {
                    merged.add_scoped_project_ignore_lines(&raw, repo_root);
                }
            }
            if !verified_any_ref {
                return Err(format!(
                    "git ref `{git_ref}` passed to `--policy-git-ref` could not be resolved"
                ));
            }
            // Always return here so untrusted working-tree `.leaktap.toml` / `.leaktapignore`
            // edits are NEVER merged on top of `--policy-git-ref <REF>`, even if `--trust-project-config` was also passed.
            return Ok(merged);
        }

        // 3. Discover project / target configs in `cwd` and `scan_paths`
        let explicit_canon = explicit_config.and_then(|c| fs::canonicalize(c).ok());
        let mut project_toml_files = Vec::new();
        let mut project_ignore_files = Vec::new();

        for dir in &anchor_dirs {
            for name in [".leaktap.toml", "leaktap.toml"] {
                let cand = dir.join(name);
                if cand.is_file() {
                    let is_same_as_explicit = explicit_config.is_some_and(|ec| ec == cand)
                        || (explicit_canon.is_some()
                            && fs::canonicalize(&cand).ok() == explicit_canon);
                    if !is_same_as_explicit && !project_toml_files.contains(&cand) {
                        project_toml_files.push(cand);
                    }
                }
            }
            let ig = dir.join(".leaktapignore");
            if ig.is_file() {
                let is_same_as_explicit = explicit_config.is_some_and(|ec| ec == ig)
                    || (explicit_canon.is_some() && fs::canonicalize(&ig).ok() == explicit_canon);
                if !is_same_as_explicit && !project_ignore_files.contains(&ig) {
                    project_ignore_files.push(ig);
                }
            }
        }

        if !trust_project_config {
            // Security boundary: untrusted repos, PR checkouts, and plugins cannot self-suppress
            // findings or disable `--block-secrets` unless `--trust-project-config` or `--config` is set.
            merged.ignored_untrusted_configs.extend(project_toml_files);
            merged
                .ignored_untrusted_configs
                .extend(project_ignore_files);
            return Ok(merged);
        }

        for cfg in project_toml_files {
            let raw = fs::read_to_string(&cfg)
                .map_err(|e| format!("failed to read `{}`: {e}", cfg.display()))?;
            let parsed: PolicyFile = toml::from_str(&raw)
                .map_err(|e| format!("invalid TOML in `{}`: {e}", cfg.display()))?;
            let proj_root = cfg.parent().unwrap_or_else(|| Path::new("."));
            merged.merge_scoped_project_policy_file(parsed, proj_root)?;
        }

        for ig in project_ignore_files {
            if let Ok(raw) = fs::read_to_string(&ig) {
                let proj_root = ig.parent().unwrap_or_else(|| Path::new("."));
                merged.add_scoped_project_ignore_lines(&raw, proj_root);
            }
        }

        Ok(merged)
    }

    fn get_or_create_scoped(&mut self, proj_root: &Path) -> &mut ScopedPolicy {
        let abs = normalize_abs_path(proj_root);
        if let Some(idx) = self
            .scoped_policies
            .iter()
            .position(|sp| sp.root_abs == abs)
        {
            return &mut self.scoped_policies[idx];
        }
        self.scoped_policies.push(ScopedPolicy::new(proj_root));
        self.scoped_policies.last_mut().expect("just pushed")
    }

    fn validate_custom_rules(rules: Vec<CustomRuleSpec>) -> Result<Vec<CustomRuleSpec>, String> {
        let mut out = Vec::with_capacity(rules.len());
        for rule in rules {
            if rule.id.trim().is_empty() {
                return Err("custom rule in .leaktap.toml has empty `id`".to_string());
            }
            if rule.pattern.len() > 4096 {
                return Err(format!(
                    "custom rule `{}` regex exceeds 4096 byte safety limit",
                    rule.id.trim()
                ));
            }
            RegexBuilder::new(&rule.pattern)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("invalid regex in custom rule `{}`: {e}", rule.id.trim()))?;
            out.push(rule);
        }
        Ok(out)
    }

    fn merge_global_policy_file(
        &mut self,
        file: PolicyFile,
        anchor_dirs: &[PathBuf],
    ) -> Result<(), String> {
        for r in file.allowlist.rules {
            let trimmed = r.trim();
            if !trimmed.is_empty() {
                self.disabled_rules.insert(trimmed.to_string());
            }
        }
        for fp in file.allowlist.fingerprints {
            let trimmed = fp.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                self.ignored_fingerprints.insert(trimmed);
            }
        }
        for sw in file.allowlist.stopwords {
            let trimmed = sw.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !self.stopwords_lower.contains(&trimmed) {
                self.stopwords_lower.push(trimmed);
            }
        }
        for pat in file.allowlist.paths {
            let clean = pat.trim().replace('\\', "/");
            if !clean.is_empty() {
                for re in compile_global_glob_regexes(&clean, anchor_dirs) {
                    self.path_matchers.push(re);
                }
            }
        }
        for (rule_id, pats) in file.allowlist.rule_paths {
            let rid = rule_id.trim();
            if rid.is_empty() {
                continue;
            }
            let entry = self.rule_path_matchers.entry(rid.to_string()).or_default();
            for pat in pats {
                let clean = pat.trim().replace('\\', "/");
                if !clean.is_empty() {
                    for re in compile_global_glob_regexes(&clean, anchor_dirs) {
                        entry.push(re);
                    }
                }
            }
        }
        let validated = Self::validate_custom_rules(file.rules)?;
        self.custom_rules.extend(validated);
        Ok(())
    }

    fn add_global_ignore_lines(&mut self, raw: &str, anchor_dirs: &[PathBuf]) {
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(fp) = trimmed.strip_prefix("fingerprint:") {
                let fp_clean = fp.trim().to_ascii_lowercase();
                if !fp_clean.is_empty() {
                    self.ignored_fingerprints.insert(fp_clean);
                }
                continue;
            }
            if let Some(rule_id) = trimmed.strip_prefix("rule:") {
                let r_clean = rule_id.trim();
                if !r_clean.is_empty() {
                    self.disabled_rules.insert(r_clean.to_string());
                }
                continue;
            }
            let clean = trimmed.replace('\\', "/");
            if !clean.is_empty() {
                for re in compile_global_glob_regexes(&clean, anchor_dirs) {
                    self.path_matchers.push(re);
                }
            }
        }
    }

    fn merge_scoped_project_policy_file(
        &mut self,
        file: PolicyFile,
        proj_root: &Path,
    ) -> Result<(), String> {
        let validated = Self::validate_custom_rules(file.rules)?;
        let scoped = self.get_or_create_scoped(proj_root);
        for r in file.allowlist.rules {
            let trimmed = r.trim();
            if !trimmed.is_empty() {
                scoped.disabled_rules.insert(trimmed.to_string());
            }
        }
        for fp in file.allowlist.fingerprints {
            let trimmed = fp.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                scoped.ignored_fingerprints.insert(trimmed);
            }
        }
        for sw in file.allowlist.stopwords {
            let trimmed = sw.trim().to_ascii_lowercase();
            if !trimmed.is_empty() && !scoped.stopwords_lower.contains(&trimmed) {
                scoped.stopwords_lower.push(trimmed);
            }
        }
        for pat in file.allowlist.paths {
            let clean = pat.trim().replace('\\', "/");
            if !clean.is_empty() {
                for re in compile_project_scoped_glob_regexes(&clean, proj_root) {
                    scoped.path_matchers.push(re);
                }
            }
        }
        for (rule_id, pats) in file.allowlist.rule_paths {
            let rid = rule_id.trim();
            if rid.is_empty() {
                continue;
            }
            let entry = scoped
                .rule_path_matchers
                .entry(rid.to_string())
                .or_default();
            for pat in pats {
                let clean = pat.trim().replace('\\', "/");
                if !clean.is_empty() {
                    for re in compile_project_scoped_glob_regexes(&clean, proj_root) {
                        entry.push(re);
                    }
                }
            }
        }
        scoped.custom_rules.extend(validated);
        Ok(())
    }

    fn add_scoped_project_ignore_lines(&mut self, raw: &str, proj_root: &Path) {
        let scoped = self.get_or_create_scoped(proj_root);
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(fp) = trimmed.strip_prefix("fingerprint:") {
                let fp_clean = fp.trim().to_ascii_lowercase();
                if !fp_clean.is_empty() {
                    scoped.ignored_fingerprints.insert(fp_clean);
                }
                continue;
            }
            if let Some(rule_id) = trimmed.strip_prefix("rule:") {
                let r_clean = rule_id.trim();
                if !r_clean.is_empty() {
                    scoped.disabled_rules.insert(r_clean.to_string());
                }
                continue;
            }
            let clean = trimmed.replace('\\', "/");
            if !clean.is_empty() {
                for re in compile_project_scoped_glob_regexes(&clean, proj_root) {
                    scoped.path_matchers.push(re);
                }
            }
        }
    }

    /// Global-only rule check (used at engine build time and in pathless contexts such as live `--block-secrets`).
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.contains(rule_id)
    }

    /// Path-aware rule check: applies global rules, `[allowlist.rule_paths]`, and project-scoped policies
    /// ONLY when `path` is inside that project's directory.
    pub fn is_rule_disabled_for(&self, rule_id: &str, path: Option<&Path>) -> bool {
        if self.disabled_rules.contains(rule_id) {
            return true;
        }
        let Some(p) = path else {
            return false;
        };
        if let Some(matchers) = self.rule_path_matchers.get(rule_id) {
            if ScopedPolicy::matches_regex_slice(matchers, p) {
                return true;
            }
        }
        for sp in &self.scoped_policies {
            if sp.applies_to(p) {
                if sp.disabled_rules.contains(rule_id) {
                    return true;
                }
                if let Some(matchers) = sp.rule_path_matchers.get(rule_id) {
                    if ScopedPolicy::matches_regex_slice(matchers, p) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn is_fingerprint_ignored(&self, fp: &str) -> bool {
        self.is_fingerprint_ignored_for(fp, None)
    }

    pub fn is_fingerprint_ignored_for(&self, fp: &str, path: Option<&Path>) -> bool {
        let lower = fp.to_ascii_lowercase();
        if self.ignored_fingerprints.contains(&lower) {
            return true;
        }
        if let Some(p) = path {
            for sp in &self.scoped_policies {
                if sp.applies_to(p) && sp.ignored_fingerprints.contains(&lower) {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_stopword(&self, val: &str) -> bool {
        self.has_stopword_for(val, None)
    }

    pub fn has_stopword_for(&self, val: &str, path: Option<&Path>) -> bool {
        let has_global = !self.stopwords_lower.is_empty();
        let has_scoped = path.is_some_and(|p| {
            self.scoped_policies
                .iter()
                .any(|sp| !sp.stopwords_lower.is_empty() && sp.applies_to(p))
        });
        if !has_global && !has_scoped {
            return false;
        }
        let lower = val.to_ascii_lowercase();
        if self.stopwords_lower.iter().any(|sw| lower.contains(sw)) {
            return true;
        }
        if let Some(p) = path {
            for sp in &self.scoped_policies {
                if sp.applies_to(p) && sp.stopwords_lower.iter().any(|sw| lower.contains(sw)) {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_path_ignored(&self, path: &Path) -> bool {
        if ScopedPolicy::matches_regex_slice(&self.path_matchers, path) {
            return true;
        }
        for sp in &self.scoped_policies {
            if sp.applies_to(path) && ScopedPolicy::matches_regex_slice(&sp.path_matchers, path) {
                return true;
            }
        }
        false
    }
}

fn normalize_abs_path(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn glob_body_to_regex(trimmed: &str) -> String {
    let mut regex_body = String::new();
    let chars: Vec<char> = trimmed.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            if i + 2 < chars.len() && chars[i + 2] == '/' {
                regex_body.push_str("(?:.*/)?");
                i += 3;
            } else {
                regex_body.push_str(".*");
                i += 2;
            }
        } else if chars[i] == '*' {
            regex_body.push_str("[^/]*");
            i += 1;
        } else if chars[i] == '?' {
            regex_body.push_str("[^/]");
            i += 1;
        } else {
            regex_body.push_str(&regex::escape(&chars[i].to_string()));
            i += 1;
        }
    }
    regex_body
}

fn anchor_bases_with_canonical(bases: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for b in bases {
        let abs = normalize_abs_path(b);
        if !out.contains(&abs) {
            out.push(abs.clone());
        }
        if let Ok(canon) = fs::canonicalize(&abs) {
            if !out.contains(&canon) {
                out.push(canon);
            }
        }
    }
    out
}

/// Compiles globs for trusted global user config (`~/.config/leaktap/config.toml`) or `--config <file>`.
fn compile_global_glob_regexes(glob: &str, anchor_dirs: &[PathBuf]) -> Vec<Regex> {
    let mut out = Vec::new();

    if glob == "~" || glob.starts_with("~/") {
        if let Some(home) = home_dir() {
            let rest = glob.strip_prefix("~/").unwrap_or("").trim_end_matches('/');
            for h in anchor_bases_with_canonical(&[home]) {
                let home_norm = h.to_string_lossy().replace('\\', "/");
                let home_esc = regex::escape(home_norm.trim_end_matches('/'));
                let pat = if rest.is_empty() {
                    format!("^{home_esc}(?:$|/)")
                } else {
                    let body = glob_body_to_regex(rest);
                    format!("^{home_esc}/{body}(?:$|/)")
                };
                if let Ok(re) = Regex::new(&pat) {
                    out.push(re);
                }
            }
        }
        return out;
    }

    if glob.starts_with('/') {
        let trimmed = glob.trim_end_matches('/');
        if trimmed.is_empty() {
            if let Ok(re) = Regex::new("^/.*$") {
                out.push(re);
            }
        } else {
            let body = glob_body_to_regex(trimmed);
            let pat = format!("^{body}(?:$|/)");
            if let Ok(re) = Regex::new(&pat) {
                out.push(re);
            }
        }
        return out;
    }

    let trimmed = glob.trim_start_matches("./").trim_end_matches('/');
    if trimmed.is_empty() {
        return out;
    }
    let body = glob_body_to_regex(trimmed);

    if trimmed.starts_with("**") {
        let pat = format!("(?:^|/){body}(?:$|/)");
        if let Ok(re) = Regex::new(&pat) {
            out.push(re);
        }
        return out;
    }

    let mut roots = anchor_dirs.to_vec();
    if roots.is_empty() {
        if let Ok(cwd) = env::current_dir() {
            roots.push(cwd);
        }
    }
    for b in anchor_bases_with_canonical(&roots) {
        let b_norm = b.to_string_lossy().replace('\\', "/");
        let b_esc = regex::escape(b_norm.trim_end_matches('/'));
        let pat = format!("^{b_esc}/{body}(?:$|/)");
        if let Ok(re) = Regex::new(&pat) {
            out.push(re);
        }
    }
    out
}

/// Compiles globs for project-discovered `.leaktap.toml` / `.leaktapignore` (`--trust-project-config`).
/// Strictly rejects any `~/...`, `/...`, or `../...` glob that resolves outside `proj_root`.
fn compile_project_scoped_glob_regexes(glob: &str, proj_root: &Path) -> Vec<Regex> {
    let mut out = Vec::new();
    let proj_bases = anchor_bases_with_canonical(&[proj_root.to_path_buf()]);

    // Reject path traversal segments in project globs
    if glob.split('/').any(|seg| seg == "..") {
        return out;
    }

    // If a project config writes `~/...` or `/...`, only allow it if the prefix is inside `proj_root`
    if glob == "~" || glob.starts_with("~/") {
        let Some(home) = home_dir() else {
            return out;
        };
        let rest = glob.strip_prefix("~/").unwrap_or("").trim_end_matches('/');
        let candidate = if rest.is_empty() {
            normalize_abs_path(&home)
        } else {
            normalize_abs_path(&home.join(rest))
        };
        if !proj_bases.iter().any(|pb| candidate.starts_with(pb)) {
            return out;
        }
        let body = glob_body_to_regex(&candidate.to_string_lossy().replace('\\', "/"));
        if let Ok(re) = Regex::new(&format!("^{body}(?:$|/)")) {
            out.push(re);
        }
        return out;
    }

    if glob.starts_with('/') {
        let trimmed = glob.trim_end_matches('/');
        if trimmed.is_empty() {
            return out;
        }
        let candidate = normalize_abs_path(Path::new(trimmed));
        if !proj_bases.iter().any(|pb| candidate.starts_with(pb)) {
            return out;
        }
        let body = glob_body_to_regex(trimmed);
        if let Ok(re) = Regex::new(&format!("^{body}(?:$|/)")) {
            out.push(re);
        }
        return out;
    }

    let trimmed = glob.trim_start_matches("./").trim_end_matches('/');
    if trimmed.is_empty() {
        return out;
    }
    let body = glob_body_to_regex(trimmed);
    for b in proj_bases {
        let b_norm = b.to_string_lossy().replace('\\', "/");
        let b_esc = regex::escape(b_norm.trim_end_matches('/'));
        let pat = format!("^{b_esc}/{body}(?:$|/)");
        if let Ok(re) = Regex::new(&pat) {
            out.push(re);
        }
    }
    out
}

fn discover_git_repo_roots(anchor_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for dir in anchor_dirs {
        let Ok(out) = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "--show-toplevel"])
            .output()
        else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            let pb = normalize_abs_path(Path::new(trimmed));
            if !roots.contains(&pb) {
                roots.push(pb);
            }
        }
    }
    roots
}

fn git_ref_exists(repo_root: &Path, verify_spec: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", "--quiet", verify_spec])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn read_git_blob_utf8(repo_root: &Path, obj_spec: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["cat-file", "-p", obj_spec])
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() > 2 * 1024 * 1024 {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

pub fn is_ci_environment() -> bool {
    for var in [
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "BUILDKITE",
        "TF_BUILD",
        "JENKINS_URL",
        "CI",
    ] {
        if let Ok(val) = env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("false") && trimmed != "0" {
                return true;
            }
        }
    }
    false
}
