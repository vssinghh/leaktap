use crate::config::PolicyConfig;
use crate::discovery::{home_dir, shorten_home};
use crate::mcp_audit::{inspect_server, is_sensitive_cli_secret_flag, McpFinding};
use crate::plugin_audit::{find_line_number, parse_json_or_jsonc};
use crate::rules::{fingerprint_match, RuleEngine, Severity};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const MAX_REPO_DOC_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REPO_SOURCE_BYTES: u64 = 512 * 1024;

const PREREQUISITE_INSTALLER_DOMAINS: &[&str] = &[
    "astral.sh/uv",
    "sh.rustup.rs",
    "brew.sh",
    "raw.githubusercontent.com/homebrew",
    "get.docker.com",
    "raw.githubusercontent.com/nvm-sh/nvm",
    "fnm.vercel.app",
    "bun.sh/install",
    "get.pnpm.io",
    "chocolatey.org",
];

const SENSITIVE_CONFIG_KEY_HINTS: &[&str] = &[
    "API_KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH_KEY",
    "CLIENT_SECRET",
    "CREDENTIALS",
    "PAT",
];

#[derive(Debug, Default)]
pub struct RepoAuditOutcome {
    pub findings: Vec<McpFinding>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
}

/// Audits explicit directory scan targets that are MCP server repositories:
/// 1. Documented MCP client configuration blocks and install commands (`README.md`, subpackage READMEs, setup docs).
/// 2. Server runtime source code & manifests for default-on outbound usage telemetry (and whether root `README.md` discloses it).
pub fn audit_mcp_server_repos(
    explicit_paths: &[PathBuf],
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> RepoAuditOutcome {
    let mut outcome = RepoAuditOutcome::default();
    let mut seen_repos = HashSet::new();

    for raw_path in explicit_paths {
        if !raw_path.is_dir() {
            continue;
        }
        if policy.is_some_and(|p| p.is_path_ignored(raw_path)) {
            continue;
        }
        let canon = fs::canonicalize(raw_path).unwrap_or_else(|_| raw_path.clone());
        if !seen_repos.insert(canon) {
            continue;
        }
        if !is_mcp_server_repo(raw_path) {
            continue;
        }
        audit_single_mcp_repo(raw_path, engine, policy, &mut outcome);
    }

    if let Some(pol) = policy {
        outcome.findings.retain(|f| {
            !pol.is_path_ignored(&f.config_path)
                && !pol.is_rule_disabled_for(f.rule_id, Some(&f.config_path))
                && !pol.is_fingerprint_ignored_for(&f.fingerprint, Some(&f.config_path))
        });
    }

    outcome
}

/// Returns `true` when `dir` is the root of an MCP server repository (TypeScript/JS, Python, Go, Rust, C#/Unity, Java, or standalone binary).
pub fn is_mcp_server_repo(dir: &Path) -> bool {
    if !dir.is_dir() || dir == Path::new("/") || dir == Path::new("/tmp") {
        return false;
    }
    if let Some(home) = home_dir() {
        if dir == home
            || dir.starts_with(home.join(".claude"))
            || dir.starts_with(home.join(".codex"))
            || dir.starts_with(home.join(".cursor"))
            || dir.starts_with(home.join(".gemini"))
        {
            return false;
        }
    }

    // If a Rust `Cargo.toml` exists at root without an MCP server SDK (`rmcp`), treat it as a non-MCP Rust project
    // (prevents security scanners like `leaktap` that mention `mcpServers` in docs from self-matching).
    let root_cargo = dir.join("Cargo.toml");
    if root_cargo.is_file() {
        if let Ok(cargo_txt) = fs::read_to_string(&root_cargo) {
            if !cargo_toml_has_mcp_sdk(&cargo_txt) {
                return false;
            }
        }
    }

    let mut candidate_dirs = vec![dir.to_path_buf()];
    for sub in ["Server", "server", "MCPForUnity", "python", "ts", "js"] {
        let p = dir.join(sub);
        if p.is_dir() {
            candidate_dirs.push(p);
        }
    }
    for container in ["packages", "src", "apps"] {
        let base = dir.join(container);
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten().take(40) {
                let p = entry.path();
                if p.is_dir() {
                    candidate_dirs.push(p);
                }
            }
        }
    }

    for cand in &candidate_dirs {
        if dir_has_mcp_manifest_marker(cand) {
            return true;
        }
    }

    // Fallback for standalone C/Go/Python/Java MCP servers without a standard SDK manifest:
    // require `"mcpServers"` (or `mcp_servers`) in root `README.md` AND an MCP server implementation marker in source.
    let readme_path = dir.join("README.md");
    if let Ok(readme) = crate::scanner::read_text_auto_encoding(&readme_path, MAX_REPO_DOC_BYTES) {
        if (readme.contains("\"mcpServers\"")
            || readme.contains("mcp_servers")
            || readme.contains("claude mcp add"))
            && repo_has_mcp_server_code_marker(dir)
        {
            return true;
        }
    }

    false
}

fn cargo_toml_has_mcp_sdk(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("rmcp")
        || lower.contains("mcp-server")
        || lower.contains("model-context-protocol")
}

fn dir_has_mcp_manifest_marker(dir: &Path) -> bool {
    let server_json = dir.join("server.json");
    if server_json.is_file() {
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&server_json, 256 * 1024) {
            if txt.contains("modelcontextprotocol")
                || (txt.contains("\"packages\"") && txt.contains("\"transport\""))
            {
                return true;
            }
        }
    }

    let manifest_json = dir.join("manifest.json");
    if manifest_json.is_file() {
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&manifest_json, 256 * 1024) {
            if txt.contains("\"mcp_config\"") {
                return true;
            }
        }
    }

    for plugin_manifest in [
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        "gemini-extension.json",
    ] {
        let pm = dir.join(plugin_manifest);
        if pm.is_file() {
            if let Ok(txt) = crate::scanner::read_text_auto_encoding(&pm, 256 * 1024) {
                if txt.contains("\"mcpServers\"") {
                    return true;
                }
            }
        }
    }

    let pkg_json = dir.join("package.json");
    if pkg_json.is_file() {
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&pkg_json, 512 * 1024) {
            if let Some(val) = parse_json_or_jsonc(&txt) {
                for dep_field in [
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ] {
                    if let Some(deps) = val.get(dep_field).and_then(|v| v.as_object()) {
                        if deps.keys().any(|k| {
                            k == "@modelcontextprotocol/sdk"
                                || k.starts_with("@modelcontextprotocol/")
                                || k == "fastmcp"
                                || k == "mcp-framework"
                                || k.starts_with("@toolbox-sdk/")
                        }) {
                            return true;
                        }
                    }
                }
                let name = val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let has_mcp_kw =
                    val.get("keywords")
                        .and_then(|v| v.as_array())
                        .is_some_and(|arr| {
                            arr.iter().filter_map(|x| x.as_str()).any(|kw| {
                                matches!(
                                    kw.to_ascii_lowercase().as_str(),
                                    "mcp" | "mcp-server" | "model-context-protocol"
                                )
                            })
                        });
                if (name.contains("mcp")
                    && (val.get("bin").is_some() || name.contains("unity-mcp")))
                    || (has_mcp_kw && val.get("bin").is_some())
                {
                    return true;
                }
            }
        }
    }

    for py_file in [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
    ] {
        let p = dir.join(py_file);
        if p.is_file() {
            if let Ok(txt) = crate::scanner::read_text_auto_encoding(&p, 256 * 1024) {
                if python_manifest_has_mcp(&txt) {
                    return true;
                }
            }
        }
    }

    let go_mod = dir.join("go.mod");
    if go_mod.is_file() {
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&go_mod, 256 * 1024) {
            if txt.contains("github.com/modelcontextprotocol/go-sdk")
                || txt.contains("github.com/mark3labs/mcp-go")
            {
                return true;
            }
        }
    }

    let cargo_toml = dir.join("Cargo.toml");
    if cargo_toml.is_file() {
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&cargo_toml, 256 * 1024) {
            if cargo_toml_has_mcp_sdk(&txt) {
                return true;
            }
        }
    }

    false
}

fn python_manifest_has_mcp(txt: &str) -> bool {
    static PY_MCP_DEP_RE: OnceLock<Regex> = OnceLock::new();
    let re = PY_MCP_DEP_RE.get_or_init(|| {
        Regex::new(
            r#"(?im)(?:^|["'\s])(?:mcp(?:\[[a-z0-9_, -]+\])?\s*(?:[><=~!]=|["'\s,\n])|fastmcp\b)"#,
        )
        .expect("valid py mcp regex")
    });
    re.is_match(txt)
}

fn repo_has_mcp_server_code_marker(root: &Path) -> bool {
    let mut files = Vec::new();
    collect_repo_source_files(root, root, false, 0, &mut files, 120);
    for path in files {
        let Ok(txt) = crate::scanner::read_text_auto_encoding(&path, MAX_REPO_SOURCE_BYTES) else {
            continue;
        };
        if txt.contains("FastMCP")
            || txt.contains("McpServer")
            || txt.contains("StdioServerTransport")
            || txt.contains("StreamableHTTPServerTransport")
            || txt.contains("from mcp.server")
            || txt.contains("import mcp.server")
            || (txt.contains("\"tools/list\"") && txt.contains("\"tools/call\""))
        {
            return true;
        }
    }
    false
}

fn audit_single_mcp_repo(
    repo_dir: &Path,
    engine: &RuleEngine,
    _policy: Option<&PolicyConfig>,
    outcome: &mut RepoAuditOutcome,
) {
    let repo_name = repo_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mcp-repo")
        .to_string();

    let mut audited_files = HashSet::new();
    let mut seen_dedup_keys = HashSet::new();

    // 1. Collect setup Markdown documentation files (root README, subpackage READMEs, English setup guides).
    let doc_files = collect_setup_doc_files(repo_dir);
    for doc_path in &doc_files {
        let Ok(meta) = fs::metadata(doc_path) else {
            continue;
        };
        if meta.len() > MAX_REPO_DOC_BYTES {
            continue;
        }
        if audited_files.insert(doc_path.clone()) {
            outcome.files_scanned += 1;
            outcome.bytes_scanned += meta.len();
        }
        let Ok(raw_doc) = crate::scanner::read_text_auto_encoding(doc_path, MAX_REPO_DOC_BYTES)
        else {
            continue;
        };
        audit_setup_markdown_doc(
            repo_dir,
            &repo_name,
            doc_path,
            &raw_doc,
            engine,
            &mut seen_dedup_keys,
            &mut outcome.findings,
        );
    }

    // 2. Audit runtime server source files for default-on outbound telemetry.
    let has_dedicated_mcp_subpkg = repo_dir.join("packages/mcp").is_dir();
    let mut source_files = Vec::new();
    collect_repo_source_files(
        repo_dir,
        repo_dir,
        has_dedicated_mcp_subpkg,
        0,
        &mut source_files,
        800,
    );
    source_files.sort();

    for src_path in &source_files {
        if let Ok(meta) = fs::metadata(src_path) {
            if meta.len() <= MAX_REPO_SOURCE_BYTES && audited_files.insert(src_path.clone()) {
                outcome.files_scanned += 1;
                outcome.bytes_scanned += meta.len();
            }
        }
    }

    audit_repo_runtime_telemetry(repo_dir, &repo_name, &source_files, &mut outcome.findings);
}

fn collect_setup_doc_files(repo_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root_readme = repo_dir.join("README.md");
    if root_readme.is_file() {
        out.push(root_readme);
    }

    for sub in ["Server/README.md", "server/README.md"] {
        let p = repo_dir.join(sub);
        if p.is_file() {
            out.push(p);
        }
    }

    let pkgs_dir = repo_dir.join("packages");
    if let Ok(entries) = fs::read_dir(pkgs_dir) {
        let mut pkg_paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        pkg_paths.sort();
        for p in pkg_paths {
            let rm = p.join("README.md");
            if rm.is_file() {
                out.push(rm);
            }
        }
    }

    let docs_dir = repo_dir.join("docs");
    if docs_dir.is_dir() {
        collect_english_setup_docs(&docs_dir, 0, &mut out);
    }

    out
}

fn collect_english_setup_docs(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 2 || out.len() >= 25 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if p.is_dir() {
            if matches!(
                lower.as_str(),
                "i18n"
                    | "zh"
                    | "ja"
                    | "ko"
                    | "adr"
                    | "architecture"
                    | "images"
                    | "img"
                    | "assets"
                    | "wiki"
            ) {
                continue;
            }
            collect_english_setup_docs(&p, depth + 1, out);
        } else if p.is_file() && lower.ends_with(".md") {
            if lower.contains("-zh")
                || lower.contains(".zh")
                || lower.contains(".ja")
                || matches!(
                    lower.as_str(),
                    "changelog.md" | "contributing.md" | "code_of_conduct.md" | "security.md"
                )
            {
                continue;
            }
            if lower.contains("setup")
                || lower.contains("install")
                || lower.contains("self_hosting")
                || lower.contains("self-hosting")
                || lower.contains("client")
                || lower.contains("running")
                || lower.contains("quickstart")
                || lower.contains("configuration")
                || lower.contains("deployment")
            {
                out.push(p);
            }
        }
    }
}

#[derive(Debug)]
struct FencedBlock {
    lang: String,
    content_start_line: usize,
    content: String,
}

fn extract_fenced_blocks(markdown: &str) -> Vec<FencedBlock> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = markdown.lines().collect();
    let mut idx = 0usize;

    while idx < lines.len() {
        let trimmed = lines[idx].trim_start();
        let fence_len = trimmed.bytes().take_while(|&b| b == b'`').count();
        if fence_len >= 3 {
            let lang = trimmed[fence_len..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let start_line = idx + 2; // 1-indexed first content line
            idx += 1;
            let mut buf = String::new();
            while idx < lines.len() {
                let close_trim = lines[idx].trim_start();
                let close_ticks = close_trim.bytes().take_while(|&b| b == b'`').count();
                if close_ticks >= fence_len && close_trim[close_ticks..].trim().is_empty() {
                    idx += 1;
                    break;
                }
                buf.push_str(lines[idx]);
                buf.push('\n');
                idx += 1;
            }
            blocks.push(FencedBlock {
                lang,
                content_start_line: start_line,
                content: buf,
            });
            continue;
        }
        idx += 1;
    }

    blocks
}

#[allow(clippy::too_many_arguments)]
fn audit_setup_markdown_doc(
    repo_dir: &Path,
    repo_name: &str,
    doc_path: &Path,
    raw_doc: &str,
    engine: &RuleEngine,
    seen_dedup_keys: &mut HashSet<String>,
    out: &mut Vec<McpFinding>,
) {
    let display = shorten_home(doc_path);
    let blocks = extract_fenced_blocks(raw_doc);
    let mut shell_blocks = Vec::new();

    for block in &blocks {
        // Skip outer `markdown` system-prompt blocks
        if matches!(
            block.lang.as_str(),
            "markdown" | "md" | "bibtex" | "mermaid"
        ) {
            continue;
        }

        let is_config_lang = matches!(block.lang.as_str(), "json" | "jsonc" | "toml" | "");
        if is_config_lang {
            if let Some((parsed_val, is_toml)) = parse_doc_mcp_block(&block.content, &block.lang) {
                let padded_raw = format!(
                    "{}{}",
                    "\n".repeat(block.content_start_line.saturating_sub(1)),
                    block.content
                );
                audit_parsed_doc_mcp_config(
                    repo_dir,
                    doc_path,
                    &display,
                    &padded_raw,
                    &parsed_val,
                    is_toml,
                    engine,
                    seen_dedup_keys,
                    out,
                );
                continue;
            }
        }

        if matches!(
            block.lang.as_str(),
            "bash"
                | "sh"
                | "shell"
                | "zsh"
                | "powershell"
                | "ps1"
                | "pwsh"
                | "cmd"
                | "console"
                | ""
        ) {
            shell_blocks.push(block);
        }
    }

    for block in shell_blocks {
        audit_setup_shell_block(repo_name, doc_path, &display, block, seen_dedup_keys, out);
    }

    // Check root README prose for Unity / git URLs pinned to mutable `#main` branch when no unpinned finding was recorded yet.
    if doc_path == repo_dir.join("README.md") {
        audit_prose_mutable_git_install(
            repo_name,
            doc_path,
            &display,
            raw_doc,
            seen_dedup_keys,
            out,
        );
    }
}

fn parse_doc_mcp_block(content: &str, lang: &str) -> Option<(Value, bool)> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    if lang == "toml" || trimmed.starts_with("[mcp_servers") {
        if let Ok(val) = toml::from_str::<Value>(content) {
            if val.get("mcp_servers").is_some() {
                return Some((val, true));
            }
        }
        return None;
    }

    if !trimmed.contains("mcpServers")
        && !trimmed.contains("mcp_servers")
        && !trimmed.contains("\"servers\"")
        && !trimmed.contains("context_servers")
        && !trimmed.contains("\"mcp\"")
        && !(trimmed.contains("\"command\"") && trimmed.contains("\"args\""))
    {
        return None;
    }

    if let Some(val) = parse_json_or_jsonc(content) {
        return Some((val, false));
    }

    // Handle partial snippets like `"github": { "command": "docker", "args": [...] }`
    let wrapped = format!("{{\n{content}\n}}");
    if let Some(val) = parse_json_or_jsonc(&wrapped) {
        if let Some(obj) = val.as_object() {
            if obj.contains_key("mcpServers") || obj.contains_key("servers") {
                return Some((val, false));
            }
            if obj.values().any(|v| {
                v.as_object()
                    .is_some_and(|o| o.contains_key("command") || o.contains_key("url"))
            }) {
                let mut root = serde_json::Map::new();
                root.insert("mcpServers".to_string(), Value::Object(obj.clone()));
                return Some((Value::Object(root), false));
            }
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn audit_parsed_doc_mcp_config(
    repo_dir: &Path,
    doc_path: &Path,
    display: &str,
    padded_raw: &str,
    json: &Value,
    _is_toml: bool,
    engine: &RuleEngine,
    seen_dedup_keys: &mut HashSet<String>,
    out: &mut Vec<McpFinding>,
) {
    let mut servers: Vec<(&str, &Value)> = Vec::new();
    for top_key in ["mcpServers", "mcp_servers", "servers", "context_servers"] {
        if let Some(map) = json.get(top_key).and_then(|v| v.as_object()) {
            for (name, spec) in map {
                servers.push((name.as_str(), spec));
            }
        }
    }
    if let Some(mcp_obj) = json.get("mcp").and_then(|v| v.as_object()) {
        if let Some(map) = mcp_obj.get("servers").and_then(|v| v.as_object()) {
            for (name, spec) in map {
                servers.push((name.as_str(), spec));
            }
        } else {
            for (name, spec) in mcp_obj {
                if spec.as_object().is_some_and(|o| {
                    o.contains_key("command")
                        || o.contains_key("url")
                        || o.contains_key("serverUrl")
                }) {
                    servers.push((name.as_str(), spec));
                }
            }
        }
    }

    for (server_name, spec) in servers {
        let mut raw_findings = Vec::new();
        inspect_server(
            server_name,
            spec,
            padded_raw,
            repo_dir,
            doc_path,
            None,
            display,
            engine,
            &mut raw_findings,
        );

        for f in raw_findings {
            // Skip `@modelcontextprotocol/inspector` testing helper snippets
            if f.message.contains("@modelcontextprotocol/inspector") {
                continue;
            }
            let dedup_sig = normalize_finding_dedup_key(f.rule_id, &f.message);
            if seen_dedup_keys.insert(dedup_sig) {
                out.push(f);
            }
        }

        inspect_documented_secret_templates(
            server_name,
            spec,
            padded_raw,
            doc_path,
            display,
            seen_dedup_keys,
            out,
        );
    }
}

fn normalize_finding_dedup_key(rule_id: &str, message: &str) -> String {
    if rule_id == "mcp-broad-filesystem" {
        if let Some(arrow_idx) = message.find(" -> `") {
            let rest = &message[arrow_idx + 5..];
            if let Some(end) = rest.find('`') {
                return format!("{rule_id}:{}", &rest[..end]);
            }
        }
    }
    // Collapse multiple client config examples (Claude Desktop, Cursor, VS Code, Windsurf) that launch the same unpinned package
    if let Some(start) = message.find('`') {
        if let Some(rel_end) = message[start + 1..].find('`') {
            let subject = &message[start + 1..start + 1 + rel_end];
            return format!("{rule_id}:{subject}");
        }
    }
    format!("{rule_id}:{message}")
}

fn inspect_documented_secret_templates(
    server_name: &str,
    spec: &Value,
    padded_raw: &str,
    doc_path: &Path,
    display: &str,
    seen_dedup_keys: &mut HashSet<String>,
    out: &mut Vec<McpFinding>,
) {
    let server_line = find_line_number(padded_raw, server_name);
    let cmd_obj = spec.get("command").and_then(|v| v.as_object());
    let cmd_arr = spec.get("command").and_then(|v| v.as_array());
    let args: Vec<&str> = spec
        .get("args")
        .and_then(|v| v.as_array())
        .or_else(|| {
            cmd_obj
                .and_then(|o| o.get("args"))
                .and_then(|v| v.as_array())
        })
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
        .or_else(|| cmd_arr.map(|arr| arr.iter().skip(1).filter_map(|x| x.as_str()).collect()))
        .unwrap_or_default();

    // 1. Check CLI `args` for secret flags (`--api-key YOUR_API_KEY` or `--figma-api-key=YOUR-KEY`)
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = args[idx];
        if let Some((flag_part, val_part)) = arg.split_once('=') {
            if is_sensitive_cli_secret_flag(flag_part) && is_literal_secret_template_value(val_part)
            {
                let dedup = format!("mcp-cli-arg-secret:{flag_part}");
                if seen_dedup_keys.insert(dedup) {
                    let line = find_line_number(padded_raw, arg).max(server_line);
                    out.push(McpFinding {
                        rule_id: "mcp-cli-arg-secret",
                        server_name: server_name.to_string(),
                        config_file: display.to_string(),
                        config_path: doc_path.to_path_buf(),
                        line,
                        severity: Severity::High,
                        fingerprint: fingerprint_match(
                            "mcp-cli-arg-secret",
                            &format!("{display}:{server_name}:{flag_part}"),
                        ),
                        message: format!(
                            "Setup config passes credential via CLI flag `{flag_part}` in MCP `args` — exposes live secrets in both plain-text config and OS process lists (`ps aux`)"
                        ),
                    });
                }
            }
            idx += 1;
            continue;
        }

        if is_sensitive_cli_secret_flag(arg) {
            if let Some(&next_val) = args.get(idx + 1) {
                if !next_val.starts_with('-') && is_literal_secret_template_value(next_val) {
                    let dedup = format!("mcp-cli-arg-secret:{arg}");
                    if seen_dedup_keys.insert(dedup) {
                        let line = find_line_number(padded_raw, arg).max(server_line);
                        out.push(McpFinding {
                            rule_id: "mcp-cli-arg-secret",
                            server_name: server_name.to_string(),
                            config_file: display.to_string(),
                            config_path: doc_path.to_path_buf(),
                            line,
                            severity: Severity::High,
                            fingerprint: fingerprint_match(
                                "mcp-cli-arg-secret",
                                &format!("{display}:{server_name}:{arg}"),
                            ),
                            message: format!(
                                "Setup config passes credential via CLI flag `{arg}` in MCP `args` — exposes live secrets in both plain-text config and OS process lists (`ps aux`)"
                            ),
                        });
                    }
                }
                idx += 2;
                continue;
            }
        }
        idx += 1;
    }

    // 1b. Check `args` for unpinned `git+https://github.com/...` specs inside shell-wrapped commands (`bash -c "... uvx --from git+https://... ..."`)
    static INLINE_GIT_URL_RE: OnceLock<Regex> = OnceLock::new();
    let inline_git_re = INLINE_GIT_URL_RE.get_or_init(|| {
        Regex::new(r#"git\+https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+([^\s"'`]*)"#)
            .expect("valid inline git url regex")
    });
    for &arg in &args {
        if let Some(caps) = inline_git_re.captures(arg) {
            let full_url = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let suffix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !suffix.contains('@') && !suffix.contains('#') {
                let dedup = format!("mcp-unpinned-package:{full_url}");
                if seen_dedup_keys.insert(dedup) {
                    let line = find_line_number(padded_raw, full_url).max(server_line);
                    out.push(McpFinding {
                        rule_id: "mcp-unpinned-package",
                        server_name: server_name.to_string(),
                        config_file: display.to_string(),
                        config_path: doc_path.to_path_buf(),
                        line,
                        severity: Severity::High,
                        fingerprint: fingerprint_match(
                            "mcp-unpinned-package",
                            &format!("{display}:{server_name}:{full_url}"),
                        ),
                        message: format!(
                            "Setup config installs directly from mutable Git `HEAD` (`{full_url}`) without a release tag or commit SHA"
                        ),
                    });
                }
            }
        }
    }

    // 2. Check `env`, `environment`, `headers`, `http_headers`, and `settings` for plain-text secret placeholders
    let cmd_env = cmd_obj
        .and_then(|o| o.get("env"))
        .and_then(|v| v.as_object());
    let candidate_maps = [
        ("env", spec.get("env").and_then(|v| v.as_object())),
        (
            "environment",
            spec.get("environment").and_then(|v| v.as_object()),
        ),
        ("command.env", cmd_env),
        ("headers", spec.get("headers").and_then(|v| v.as_object())),
        (
            "http_headers",
            spec.get("http_headers").and_then(|v| v.as_object()),
        ),
        ("settings", spec.get("settings").and_then(|v| v.as_object())),
    ];

    for (field, map_opt) in candidate_maps {
        let Some(map) = map_opt else {
            continue;
        };
        for (key, val_node) in map {
            let Some(val) = val_node.as_str() else {
                continue;
            };
            if !is_sensitive_config_key_name(field, key) || !is_literal_secret_template_value(val) {
                continue;
            }
            let dedup = format!("mcp-plaintext-secret-template:{field}.{key}");
            if seen_dedup_keys.insert(dedup) {
                let line = find_line_number(padded_raw, key).max(server_line);
                out.push(McpFinding {
                    rule_id: "mcp-plaintext-secret-template",
                    server_name: server_name.to_string(),
                    config_file: display.to_string(),
                    config_path: doc_path.to_path_buf(),
                    line,
                    severity: Severity::Medium,
                    fingerprint: fingerprint_match(
                        "mcp-plaintext-secret-template",
                        &format!("{display}:{server_name}:{field}.{key}"),
                    ),
                    message: format!(
                        "Setup config stores plain-text credential in `{field}.{key}` instead of `${{ENV_VAR}}` or `${{input:...}}` secret interpolation"
                    ),
                });
            }
        }
    }
}

fn is_sensitive_config_key_name(field: &str, key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if upper.contains("PUBLIC_KEY")
        || upper.contains("PUBKEY")
        || upper.contains("CACHE_KEY")
        || upper.contains("PATH")
        || upper.contains("FILE")
        || upper.contains("DIR")
        || upper.contains("URL")
        || upper.contains("HOST")
        || upper.contains("PORT")
        || upper.contains("TIMEOUT")
        || upper.contains("DISABLE")
        || upper.contains("ENABLE")
    {
        return false;
    }
    if matches!(field, "headers" | "http_headers")
        && (upper == "AUTHORIZATION" || upper == "X-API-KEY" || upper.ends_with("-API-KEY"))
    {
        return true;
    }
    SENSITIVE_CONFIG_KEY_HINTS
        .iter()
        .any(|kw| upper == *kw || upper.contains(kw))
        || upper.ends_with("_KEY")
}

fn is_literal_secret_template_value(val: &str) -> bool {
    let trimmed = val.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return false;
    }
    // Strip `Bearer ` / `Token ` / `Basic ` scheme prefix so `Bearer ${API_KEY}` is recognized as safe interpolation
    let payload = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .or_else(|| trimmed.strip_prefix("Token "))
        .or_else(|| trimmed.strip_prefix("Basic "))
        .map(str::trim)
        .unwrap_or(trimmed);

    if payload.is_empty()
        || payload.starts_with("${")
        || (payload.starts_with('$') && !payload.contains(' '))
        || payload.starts_with("env:")
        || payload.starts_with("{env:")
        || payload.starts_with("op://")
    {
        return false;
    }

    let lower = payload.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no" | "none" | "null" | "stdio" | "http"
    ) {
        return false;
    }
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || payload.starts_with('/')
        || payload.starts_with("./")
        || payload.starts_with("~/")
    {
        return false;
    }
    payload.len() >= 4
}

fn audit_setup_shell_block(
    repo_name: &str,
    doc_path: &Path,
    display: &str,
    block: &FencedBlock,
    seen_dedup_keys: &mut HashSet<String>,
    out: &mut Vec<McpFinding>,
) {
    static PIPE_SHELL_RE: OnceLock<Regex> = OnceLock::new();
    static POWERSHELL_IEX_RE: OnceLock<Regex> = OnceLock::new();
    static PIP_MAIN_ARCHIVE_RE: OnceLock<Regex> = OnceLock::new();
    static UVX_GIT_UNPINNED_RE: OnceLock<Regex> = OnceLock::new();
    static CLI_UNPINNED_NPX_UVX_RE: OnceLock<Regex> = OnceLock::new();
    static DOCKER_LATEST_RE: OnceLock<Regex> = OnceLock::new();

    let pipe_re = PIPE_SHELL_RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:curl|wget)\b[^\n|]*https?://([^\s"'|]+)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"#)
            .expect("valid pipe shell regex")
    });
    let ps_re = POWERSHELL_IEX_RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|]*https?://([^\s"'|)]+)[^\n|]*\|\s*(?:iex|Invoke-Expression)\b"#)
            .expect("valid powershell iex regex")
    });
    let pip_main_re = PIP_MAIN_ARCHIVE_RE.get_or_init(|| {
        Regex::new(r#"(?i)\bpip3?\s+install\s+(?:-[a-zA-Z]+\s+)*(https://github\.com/[^\s"']+/archive/refs/heads/[^\s"']+)"#)
            .expect("valid pip main archive regex")
    });
    let uvx_git_re = UVX_GIT_UNPINNED_RE.get_or_init(|| {
        Regex::new(r#"\buvx\s+--from\s+(git\+https://github\.com/[^\s"'@]+)(?:\s|$)"#)
            .expect("valid uvx git regex")
    });
    let cli_npx_uvx_re = CLI_UNPINNED_NPX_UVX_RE.get_or_init(|| {
        Regex::new(
            r#"\b(npx|uvx)\s+(?:-y\s+|--yes\s+)?(@?[a-z0-9][a-z0-9._/-]*[a-z0-9](?:@latest)?)\b"#,
        )
        .expect("valid cli npx/uvx regex")
    });
    let docker_latest_re = DOCKER_LATEST_RE.get_or_init(|| {
        Regex::new(r#"\bdocker\s+run\b[^\n]*\s([a-z0-9._-]+/[a-z0-9._/-]+:latest)\b"#)
            .expect("valid docker latest regex")
    });
    static GLOBAL_MCP_INSTALL_RE: OnceLock<Regex> = OnceLock::new();
    let global_install_re = GLOBAL_MCP_INSTALL_RE.get_or_init(|| {
        Regex::new(
            r#"\b((?:npm|pnpm|bun)\s+(?:install|i|add)\s+(?:-g|--global)\s+|uv\s+tool\s+install\s+|pipx\s+install\s+)(@?[a-z0-9][a-z0-9._/-]*[a-z0-9](?:@latest)?)(?:\s|$)"#,
        )
        .expect("valid global mcp install regex")
    });
    static EXT_GIT_HEAD_RE: OnceLock<Regex> = OnceLock::new();
    let ext_git_re = EXT_GIT_HEAD_RE.get_or_init(|| {
        Regex::new(r#"\b(?:(?:gemini|qwen)\s+extensions\s+install\s+(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)|(?:claude|codex|zcode)\s+plugins?\s+marketplace\s+add\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+))(?:\s|$)"#)
            .expect("valid extension git head regex")
    });

    for (offset, raw_line) in block.content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let line_no = block.content_start_line + offset;

        if let Some(caps) = pipe_re
            .captures(trimmed)
            .or_else(|| ps_re.captures(trimmed))
        {
            let url_part = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let url_lower = url_part.to_ascii_lowercase();
            if PREREQUISITE_INSTALLER_DOMAINS
                .iter()
                .any(|d| url_lower.contains(d))
            {
                continue;
            }
            let full_url = format!("https://{url_part}");
            let dedup = format!("mcp-remote-code-exec:{url_lower}");
            if seen_dedup_keys.insert(dedup) {
                out.push(McpFinding {
                    rule_id: "mcp-remote-code-exec",
                    server_name: repo_name.to_string(),
                    config_file: display.to_string(),
                    config_path: doc_path.to_path_buf(),
                    line: line_no,
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-remote-code-exec",
                        &format!("{display}:{line_no}:{url_lower}"),
                    ),
                    message: format!(
                        "Setup guide pipes unpinned remote installer script (`{full_url}`) directly into a shell"
                    ),
                });
            }
            continue;
        }

        if let Some(caps) = pip_main_re.captures(trimmed) {
            let url = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let dedup = format!("mcp-unpinned-package:{url}");
            if seen_dedup_keys.insert(dedup) {
                out.push(McpFinding {
                    rule_id: "mcp-unpinned-package",
                    server_name: repo_name.to_string(),
                    config_file: display.to_string(),
                    config_path: doc_path.to_path_buf(),
                    line: line_no,
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-unpinned-package",
                        &format!("{display}:{line_no}:{url}"),
                    ),
                    message: format!(
                        "Setup guide installs directly from mutable Git branch archive (`{url}`) without a release tag or commit hash"
                    ),
                });
            }
            continue;
        }

        if let Some(caps) = uvx_git_re.captures(trimmed) {
            let git_url = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let dedup = format!("mcp-unpinned-package:uvx {git_url}");
            if seen_dedup_keys.insert(dedup) {
                out.push(McpFinding {
                    rule_id: "mcp-unpinned-package",
                    server_name: repo_name.to_string(),
                    config_file: display.to_string(),
                    config_path: doc_path.to_path_buf(),
                    line: line_no,
                    severity: Severity::High,
                    fingerprint: fingerprint_match(
                        "mcp-unpinned-package",
                        &format!("{display}:{line_no}:{git_url}"),
                    ),
                    message: format!(
                        "Setup guide runs unpinned `uvx {git_url}` from mutable `HEAD` without a commit SHA or release tag"
                    ),
                });
            }
            continue;
        }

        // Only emit shell-level `npx` / `uvx` / global install / `docker :latest` / extension git-HEAD if not already recorded from a structured JSON/TOML block
        let already_has_unpinned = seen_dedup_keys
            .iter()
            .any(|k| k.starts_with("mcp-unpinned-package:"));
        if !already_has_unpinned {
            if let Some(caps) = ext_git_re.captures(trimmed) {
                let target = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                let dedup = format!("mcp-unpinned-package:ext:{target}");
                if seen_dedup_keys.insert(dedup) {
                    out.push(McpFinding {
                        rule_id: "mcp-unpinned-package",
                        server_name: repo_name.to_string(),
                        config_file: display.to_string(),
                        config_path: doc_path.to_path_buf(),
                        line: line_no,
                        severity: Severity::Medium,
                        fingerprint: fingerprint_match(
                            "mcp-unpinned-package",
                            &format!("{display}:{line_no}:ext:{target}"),
                        ),
                        message: format!(
                            "Setup command installs plugin/MCP extension from mutable GitHub branch (`{target}`) without a pinned tag or commit"
                        ),
                    });
                }
                continue;
            }

            if let Some(caps) = cli_npx_uvx_re.captures(trimmed) {
                let launcher = caps.get(1).map(|m| m.as_str()).unwrap_or("npx");
                let pkg = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let is_helper_cli = matches!(pkg, "mcporter" | "@smithery/cli" | "mcp-Get");
                let is_mcp_launch_line = !is_helper_cli
                    && (trimmed.contains("@latest")
                        || trimmed.contains("mcp add")
                        || pkg.contains("mcp"));
                if is_mcp_launch_line
                    && !pkg.contains("@modelcontextprotocol/inspector")
                    && (!pkg.contains('@')
                        || pkg.starts_with('@') && !pkg[1..].contains('@')
                        || pkg.ends_with("@latest"))
                {
                    let clean_pkg = pkg.strip_suffix("@latest").unwrap_or(pkg);
                    let dedup = format!("mcp-unpinned-package:{launcher} {clean_pkg}");
                    if seen_dedup_keys.insert(dedup) {
                        out.push(McpFinding {
                            rule_id: "mcp-unpinned-package",
                            server_name: repo_name.to_string(),
                            config_file: display.to_string(),
                            config_path: doc_path.to_path_buf(),
                            line: line_no,
                            severity: Severity::Medium,
                            fingerprint: fingerprint_match(
                                "mcp-unpinned-package",
                                &format!("{display}:{line_no}:{launcher}:{pkg}"),
                            ),
                            message: format!(
                                "Setup command runs unpinned `{launcher} {pkg}` — pulls mutable remote package code without an exact `x.y.z` pin"
                            ),
                        });
                    }
                }
            } else if let Some(caps) = global_install_re.captures(trimmed) {
                let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                let pkg = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let is_helper_cli = matches!(pkg, "mcporter" | "@smithery/cli" | "mcp-Get");
                if !is_helper_cli
                    && pkg.contains("mcp")
                    && !pkg.contains("@modelcontextprotocol/inspector")
                    && (!pkg.contains('@')
                        || pkg.starts_with('@') && !pkg[1..].contains('@')
                        || pkg.ends_with("@latest"))
                {
                    let clean_pkg = pkg.strip_suffix("@latest").unwrap_or(pkg);
                    let dedup = format!("mcp-unpinned-package:{prefix} {clean_pkg}");
                    if seen_dedup_keys.insert(dedup) {
                        out.push(McpFinding {
                            rule_id: "mcp-unpinned-package",
                            server_name: repo_name.to_string(),
                            config_file: display.to_string(),
                            config_path: doc_path.to_path_buf(),
                            line: line_no,
                            severity: Severity::Medium,
                            fingerprint: fingerprint_match(
                                "mcp-unpinned-package",
                                &format!("{display}:{line_no}:{prefix}:{pkg}"),
                            ),
                            message: format!(
                                "Setup command installs unpinned global package `{prefix} {pkg}` without an exact `x.y.z` version pin"
                            ),
                        });
                    }
                }
            } else if let Some(caps) = docker_latest_re.captures(trimmed) {
                let img = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let dedup = format!("mcp-unpinned-package:docker run {img}");
                if seen_dedup_keys.insert(dedup) {
                    out.push(McpFinding {
                        rule_id: "mcp-unpinned-package",
                        server_name: repo_name.to_string(),
                        config_file: display.to_string(),
                        config_path: doc_path.to_path_buf(),
                        line: line_no,
                        severity: Severity::Medium,
                        fingerprint: fingerprint_match(
                            "mcp-unpinned-package",
                            &format!("{display}:{line_no}:{img}"),
                        ),
                        message: format!(
                            "Setup command runs mutable container tag `docker run {img}` without a version or `@sha256:...` digest"
                        ),
                    });
                }
            }
        }
    }
}

fn audit_prose_mutable_git_install(
    repo_name: &str,
    doc_path: &Path,
    display: &str,
    raw_doc: &str,
    seen_dedup_keys: &mut HashSet<String>,
    out: &mut Vec<McpFinding>,
) {
    if seen_dedup_keys
        .iter()
        .any(|k| k.starts_with("mcp-unpinned-package:"))
    {
        return;
    }
    static GIT_HASH_MAIN_RE: OnceLock<Regex> = OnceLock::new();
    let re = GIT_HASH_MAIN_RE.get_or_init(|| {
        Regex::new(r#"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git(?:\?[^\s`"')]*)?#(main|master)\b"#)
            .expect("valid git #main regex")
    });
    for (idx, line) in raw_doc.lines().enumerate() {
        if let Some(m) = re.find(line) {
            let url = m.as_str();
            let dedup = format!("mcp-unpinned-package:{url}");
            if seen_dedup_keys.insert(dedup) {
                out.push(McpFinding {
                    rule_id: "mcp-unpinned-package",
                    server_name: repo_name.to_string(),
                    config_file: display.to_string(),
                    config_path: doc_path.to_path_buf(),
                    line: idx + 1,
                    severity: Severity::Medium,
                    fingerprint: fingerprint_match(
                        "mcp-unpinned-package",
                        &format!("{display}:{}:{url}", idx + 1),
                    ),
                    message: format!(
                        "Quickstart package URL (`{url}`) tracks mutable branch `HEAD` instead of a pinned release tag"
                    ),
                });
            }
            break;
        }
    }
}

fn collect_repo_source_files(
    _repo_root: &Path,
    dir: &Path,
    skip_separate_cli_pkg: bool,
    depth: usize,
    out: &mut Vec<PathBuf>,
    budget: usize,
) {
    if depth > 7 || out.len() >= budget {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();

    for p in paths {
        if out.len() >= budget {
            return;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if p.is_dir() {
            if name.starts_with('.')
                || matches!(
                    lower.as_str(),
                    "node_modules"
                        | "vendored"
                        | "vendor"
                        | "third_party"
                        | "target"
                        | "dist"
                        | "build"
                        | "out"
                        | "coverage"
                        | "test"
                        | "tests"
                        | "__tests__"
                        | "bench"
                        | "benchmarks"
                        | "examples"
                        | "example"
                        | "website"
                        | "docs"
                        | "fixtures"
                        | "eval"
                        | "skills"
                )
            {
                continue;
            }
            if skip_separate_cli_pkg
                && lower == "cli"
                && p.parent()
                    .and_then(|par| par.file_name())
                    .and_then(|s| s.to_str())
                    == Some("packages")
            {
                continue;
            }
            collect_repo_source_files(
                _repo_root,
                &p,
                skip_separate_cli_pkg,
                depth + 1,
                out,
                budget,
            );
        } else if p.is_file() {
            if is_test_or_minified_filename(&lower) {
                continue;
            }
            let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if matches!(
                ext.to_ascii_lowercase().as_str(),
                "ts" | "tsx" | "js" | "mjs" | "cjs" | "py" | "go" | "rs" | "cs" | "java" | "kt"
            ) {
                if let Ok(meta) = fs::metadata(&p) {
                    if meta.len() <= MAX_REPO_SOURCE_BYTES {
                        out.push(p);
                    }
                }
            }
        }
    }
}

fn is_test_or_minified_filename(lower_name: &str) -> bool {
    lower_name.ends_with(".min.js")
        || lower_name.contains(".test.")
        || lower_name.contains(".spec.")
        || lower_name.ends_with("_test.go")
        || lower_name.ends_with("_test.py")
        || lower_name.starts_with("test_")
}

struct TelemetryHit {
    file_path: PathBuf,
    line: usize,
    collector_label: String,
    opt_out_hint: Option<String>,
}

fn audit_repo_runtime_telemetry(
    repo_dir: &Path,
    repo_name: &str,
    source_files: &[PathBuf],
    out: &mut Vec<McpFinding>,
) {
    let mut hits: Vec<TelemetryHit> = Vec::new();
    let mut all_collectors = BTreeSet::new();
    let mut opt_out_vars = BTreeSet::new();
    let mut explicitly_opt_in_only = false;

    for src_path in source_files {
        let Ok(txt) = crate::scanner::read_text_auto_encoding(src_path, MAX_REPO_SOURCE_BYTES)
        else {
            continue;
        };

        // Skip browser ad/tracker blocklists (e.g., `doubleclick.net` + `googlesyndication.com`)
        let lower = txt.to_ascii_lowercase();
        if lower.contains("doubleclick.net") && lower.contains("googlesyndication.com") {
            continue;
        }

        // Detect explicit opt-in-only CLI telemetry flags (e.g., `--telemetry-gcp, false`)
        if lower.contains("\"telemetry-gcp\", false") || lower.contains("telemetry_enabled = false")
        {
            explicitly_opt_in_only = true;
        }

        for env_var in extract_telemetry_opt_out_vars(&txt) {
            opt_out_vars.insert(env_var);
        }

        if let Some((line, label)) = detect_runtime_telemetry_collector(&txt, &lower) {
            all_collectors.insert(label.clone());
            hits.push(TelemetryHit {
                file_path: src_path.clone(),
                line,
                collector_label: label,
                opt_out_hint: opt_out_vars.iter().next().cloned(),
            });
        }
    }

    if hits.is_empty() {
        return;
    }

    // If a codebase only wires optional user-configured telemetry that defaults to `false` and has no opt-out disable vars, skip.
    if explicitly_opt_in_only && opt_out_vars.is_empty() {
        return;
    }

    // Prefer a hit inside a dedicated `telemetry` module/file if present so the line link is maximally informative.
    hits.sort_by_key(|h| {
        let p = h.file_path.to_string_lossy().to_ascii_lowercase();
        let priority = if p.contains("telemetry") || p.contains("clearcut") || p.contains("track") {
            0usize
        } else {
            1usize
        };
        (priority, h.file_path.clone(), h.line)
    });
    let primary = &hits[0];

    let root_readme_discloses = root_readme_mentions_telemetry(repo_dir);
    let subfolder_discloses = !root_readme_discloses && subfolder_docs_mention_telemetry(repo_dir);
    let ml_training_note = repo_mentions_ml_training_on_telemetry(repo_dir);

    let collectors_joined: Vec<String> = all_collectors.into_iter().collect();
    let collectors_str = collectors_joined.join(" + ");
    let opt_out_note = if !opt_out_vars.is_empty() {
        let vars: Vec<String> = opt_out_vars.into_iter().take(2).collect();
        format!("; opt-out via `{}`", vars.join("` / `"))
    } else if let Some(ref hint) = primary.opt_out_hint {
        format!("; opt-out via `{hint}`")
    } else {
        String::new()
    };
    let ml_suffix = if ml_training_note {
        "; docs state collected data may be used to train AI/ML models"
    } else {
        ""
    };

    let display = shorten_home(&primary.file_path);
    let (rule_id, severity, disclosure_note) = if root_readme_discloses {
        (
            "mcp-server-telemetry",
            Severity::Medium,
            format!(
                "Server enables default-on outbound usage telemetry ({collectors_str}{opt_out_note}{ml_suffix})"
            ),
        )
    } else if subfolder_discloses {
        (
            "mcp-undisclosed-telemetry",
            Severity::High,
            format!(
                "Server enables default-on outbound usage telemetry ({collectors_str}{opt_out_note}{ml_suffix}) with no disclosure in root `README.md` (opt-out documented in sub-folder docs)"
            ),
        )
    } else {
        (
            "mcp-undisclosed-telemetry",
            Severity::High,
            format!(
                "Server enables default-on outbound usage telemetry ({collectors_str}{opt_out_note}{ml_suffix}) with no disclosure in root `README.md` or setup docs"
            ),
        )
    };

    out.push(McpFinding {
        rule_id,
        server_name: repo_name.to_string(),
        config_file: display.clone(),
        config_path: primary.file_path.clone(),
        line: primary.line,
        severity,
        fingerprint: fingerprint_match(rule_id, &format!("{display}:{}", primary.collector_label)),
        message: disclosure_note,
    });
}

fn detect_runtime_telemetry_collector(txt: &str, lower: &str) -> Option<(usize, String)> {
    // 1. Direct vendor collector hosts/paths
    const DIRECT_ENDPOINTS: &[(&str, &str)] = &[
        ("us.i.posthog.com", "PostHog `us.i.posthog.com`"),
        ("eu.i.posthog.com", "PostHog `eu.i.posthog.com`"),
        ("app.posthog.com", "PostHog `app.posthog.com`"),
        ("i.posthog.com", "PostHog `i.posthog.com`"),
        (
            "play.googleapis.com/log",
            "Google Clearcut `play.googleapis.com/log`",
        ),
        ("static.scarf.sh", "Scarf pixel `static.scarf.sh`"),
        ("api.segment.io", "Segment `api.segment.io`"),
        (".ingest.us.sentry.io", "Sentry `.ingest.us.sentry.io`"),
        (".ingest.de.sentry.io", "Sentry `.ingest.de.sentry.io`"),
        ("ingest.sentry.io", "Sentry `ingest.sentry.io`"),
        ("api.mixpanel.com", "Mixpanel `api.mixpanel.com`"),
        ("api.amplitude.com", "Amplitude `api.amplitude.com`"),
    ];

    for &(needle, label) in DIRECT_ENDPOINTS {
        if lower.contains(needle) {
            let line = find_case_insensitive_line(txt, needle);
            return Some((line, label.to_string()));
        }
    }

    // 2. Vendor analytics SDK imports/clients (excluding `segmentio/encoding` JSON parser and OpenTelemetry)
    const SDK_MARKERS: &[(&str, &str)] = &[
        (
            "@segment/analytics-node",
            "Segment `@segment/analytics-node`",
        ),
        ("segmentio/analytics-go", "Segment `analytics-go`"),
        ("posthog-node", "PostHog `posthog-node`"),
        ("from posthog import", "PostHog Python SDK"),
        ("@sentry/node", "Sentry `@sentry/node`"),
        ("clearcutlogger", "Google `ClearcutLogger`"),
    ];
    for &(needle, label) in SDK_MARKERS {
        if lower.contains(needle) {
            let line = find_case_insensitive_line(txt, needle);
            return Some((line, label.to_string()));
        }
    }

    // 3. Explicit `https://telemetry.<domain>` collector host in runtime code (even when `fetch` lives in a sibling `telemetry-fetch` file)
    static DEDICATED_TELEMETRY_HOST_RE: OnceLock<Regex> = OnceLock::new();
    let host_re = DEDICATED_TELEMETRY_HOST_RE.get_or_init(|| {
        Regex::new(r#"https://telemetry\.[a-z0-9.-]+(?:/[^\s"'`]*)?"#)
            .expect("valid dedicated telemetry host regex")
    });
    if let Some(m) = host_re.find(lower) {
        let url = m.as_str();
        let line = find_case_insensitive_line(txt, url);
        return Some((line, format!("`{url}`")));
    }

    // 4. First-party telemetry paths (`/telemetry/events`, `/rest/v1/telemetry_events`, `/mp/collect`)
    // paired with an outbound HTTP client in the same file.
    let has_http_client = lower.contains("fetch(")
        || lower.contains("globalthis.fetch")
        || lower.contains("httpx.")
        || lower.contains("requests.post")
        || lower.contains("urllib.request")
        || lower.contains("axios.")
        || lower.contains("http.request")
        || lower.contains("https.request")
        || lower.contains("httpclient");

    if has_http_client {
        static CUSTOM_TELEMETRY_PATH_RE: OnceLock<Regex> = OnceLock::new();
        let re = CUSTOM_TELEMETRY_PATH_RE.get_or_init(|| {
            Regex::new(r#"https://[a-z0-9.-]+/(?:telemetry/events|mp/collect)\b"#)
                .expect("valid custom telemetry path regex")
        });
        if let Some(m) = re.find(lower) {
            let url = m.as_str();
            let line = find_case_insensitive_line(txt, url);
            return Some((line, format!("`{url}`")));
        }

        if lower.contains("/rest/v1/telemetry_events") {
            let line = find_case_insensitive_line(txt, "/rest/v1/telemetry_events");
            return Some((line, "Supabase `/rest/v1/telemetry_events`".to_string()));
        }
    }

    None
}

fn extract_telemetry_opt_out_vars(txt: &str) -> Vec<String> {
    static OPT_OUT_RE: OnceLock<Regex> = OnceLock::new();
    let re = OPT_OUT_RE.get_or_init(|| {
        Regex::new(r#"\b([A-Z][A-Z0-9_]*(?:DISABLE_TELEMETRY|TELEMETRY_DISABLED|NO_USAGE_STATISTICS|WITHOUT_TELEMETRY|ANONYMIZED_TELEMETRY|MCP_TELEMETRY)|DISABLE_TELEMETRY|--no-telemetry|--no-usage-statistics|--telemetry-enabled)\b"#)
            .expect("valid telemetry opt-out regex")
    });
    re.captures_iter(txt)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn doc_text_mentions_telemetry(txt: &str) -> bool {
    let lower = txt.to_ascii_lowercase();
    lower.contains("telemetry")
        || lower.contains("usage statistics")
        || lower.contains("data collection")
        || lower.contains("posthog")
}

fn root_readme_mentions_telemetry(repo_dir: &Path) -> bool {
    let readme_path = repo_dir.join("README.md");
    let Ok(txt) = crate::scanner::read_text_auto_encoding(&readme_path, MAX_REPO_DOC_BYTES) else {
        return false;
    };
    doc_text_mentions_telemetry(&txt)
}

fn subfolder_docs_mention_telemetry(repo_dir: &Path) -> bool {
    let root_readme = repo_dir.join("README.md");
    let mut candidates = collect_setup_doc_files(repo_dir);
    candidates.push(repo_dir.join("PRIVACY.md"));
    let web_docs = repo_dir.join("website/docs");
    if web_docs.is_dir() {
        collect_english_setup_docs(&web_docs, 0, &mut candidates);
    }
    for p in candidates {
        if p == root_readme || !p.is_file() {
            continue;
        }
        if let Ok(txt) = crate::scanner::read_text_auto_encoding(&p, MAX_REPO_DOC_BYTES) {
            if doc_text_mentions_telemetry(&txt) {
                return true;
            }
        }
    }
    false
}

fn repo_mentions_ml_training_on_telemetry(repo_dir: &Path) -> bool {
    let mut found_ml_clause = false;
    for doc in ["TERMS_AND_CONDITIONS.md", "PRIVACY.md", "README.md"] {
        let p = repo_dir.join(doc);
        let Ok(txt) = crate::scanner::read_text_auto_encoding(&p, MAX_REPO_DOC_BYTES) else {
            continue;
        };
        let lower = txt.to_ascii_lowercase();
        if lower.contains("telemetry is **opt-in**")
            || lower.contains("telemetry is strictly opt-in")
            || lower.contains("if you opt in to telemetry")
        {
            return false;
        }
        if lower.contains("telemetry")
            && (lower.contains("train ai models")
                || lower.contains("machine learning models")
                || lower.contains("build datasets and machine learning"))
        {
            found_ml_clause = true;
        }
    }
    found_ml_clause
}

fn find_case_insensitive_line(raw: &str, needle_lower: &str) -> usize {
    for (idx, line) in raw.lines().enumerate() {
        if line.to_ascii_lowercase().contains(needle_lower) {
            return idx + 1;
        }
    }
    1
}
