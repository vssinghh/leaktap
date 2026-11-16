use crate::plugin_audit::has_script_extension;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct DiscoveredTargets {
    pub transcript_files: Vec<PathBuf>,
    pub mcp_config_files: Vec<PathBuf>,
    pub plugin_files: Vec<PathBuf>,
    pub scanned_roots: Vec<String>,
}

const IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    "Cache",
    "caches",
    "GPUCache",
    "Code Cache",
    "builtin",
    ".system",
    "marketplaces",
    "store",
    "assets",
    "evals",
    "crashes",
    "backups",
];

struct WalkContext<'a> {
    transcripts: &'a mut Vec<PathBuf>,
    mcp_configs: &'a mut Vec<PathBuf>,
    plugin_files: &'a mut Vec<PathBuf>,
    seen: &'a mut HashSet<PathBuf>,
    include_mcp: bool,
}

pub fn discover_targets(custom_paths: &[PathBuf], include_mcp: bool) -> DiscoveredTargets {
    let mut transcripts = Vec::new();
    let mut mcp_configs = Vec::new();
    let mut plugin_files = Vec::new();
    let mut seen = HashSet::new();
    let mut roots = Vec::new();

    {
        let mut ctx = WalkContext {
            transcripts: &mut transcripts,
            mcp_configs: &mut mcp_configs,
            plugin_files: &mut plugin_files,
            seen: &mut seen,
            include_mcp,
        };

        if !custom_paths.is_empty() {
            for p in custom_paths {
                roots.push(shorten_home(p));
                let start_in_cust =
                    has_customization_ancestor(p) || (p.is_dir() && is_plugin_or_skill_root(p));
                walk_path(p, &mut ctx, start_in_cust, 0);
            }
        } else {
            if let Some(home) = home_dir() {
                let agent_dirs = [
                    (".claude", home.join(".claude")),
                    (".codex", home.join(".codex")),
                    (".cursor", home.join(".cursor")),
                    (".gemini", home.join(".gemini")),
                ];

                for (_, dir) in &agent_dirs {
                    if dir.exists() {
                        roots.push(shorten_home(dir));
                        walk_path(dir, &mut ctx, false, 0);
                    }
                }

                if include_mcp {
                    let extra_mcp_files = [
                        home.join(".claude.json"),
                        home.join(".config/Claude/claude_desktop_config.json"),
                        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                    ];
                    for cfg in &extra_mcp_files {
                        if cfg.is_file() && ctx.seen.insert(cfg.clone()) {
                            ctx.mcp_configs.push(cfg.clone());
                        }
                    }
                }
            }

            if include_mcp {
                if let Ok(cwd) = env::current_dir() {
                    let workspace_configs = [
                        cwd.join(".mcp.json"),
                        cwd.join("mcp.json"),
                        cwd.join(".agents/mcp_config.json"),
                        cwd.join(".antigravitycli/mcp_config.json"),
                        cwd.join(".codex/config.toml"),
                        cwd.join(".cursor/mcp.json"),
                        cwd.join(".vscode/mcp.json"),
                        cwd.join(".gemini/settings.json"),
                        cwd.join(".claude/settings.json"),
                        cwd.join(".claude/settings.local.json"),
                    ];
                    for cfg in &workspace_configs {
                        if cfg.is_file() {
                            classify_file(cfg, &mut ctx, false);
                        }
                    }

                    let workspace_customization_paths = [
                        cwd.join(".claude/plugins"),
                        cwd.join(".claude/skills"),
                        cwd.join(".claude/hooks"),
                        cwd.join(".codex/plugins"),
                        cwd.join(".codex/skills"),
                        cwd.join(".codex/hooks.json"),
                        cwd.join(".agents"),
                        cwd.join(".agent"),
                        cwd.join(".antigravitycli"),
                    ];
                    for cust in &workspace_customization_paths {
                        if cust.exists() {
                            walk_path(cust, &mut ctx, true, 0);
                        }
                    }
                }
            }
        }
    }

    transcripts.sort();
    mcp_configs.sort();
    plugin_files.sort();

    DiscoveredTargets {
        transcript_files: transcripts,
        mcp_config_files: mcp_configs,
        plugin_files,
        scanned_roots: roots,
    }
}

fn walk_path(path: &Path, ctx: &mut WalkContext<'_>, in_customization_tree: bool, depth: usize) {
    if depth > 14 || !path.exists() {
        return;
    }

    if path.is_file() {
        classify_file(path, ctx, in_customization_tree);
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if should_ignore_dir(path, name) {
            continue;
        }

        // Follow regular directories; skip symlinks to avoid cycles
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            let child_in_cust = in_customization_tree
                || is_customization_dir_name(name)
                || is_plugin_or_skill_root(&p);
            walk_path(&p, ctx, child_in_cust, depth + 1);
        } else if ft.is_file() {
            classify_file(&p, ctx, in_customization_tree);
        }
    }
}

fn should_ignore_dir(parent: &Path, name: &str) -> bool {
    if IGNORED_DIRS.contains(&name) {
        return true;
    }
    if name == "cache" {
        // Allow `~/.claude/plugins/cache/...` and `~/.codex/plugins/cache/...`,
        // while skipping general CLI caches like `~/.claude/cache` or `~/.gemini/antigravity-cli/cache`.
        let parent_name = parent.file_name().and_then(|s| s.to_str()).unwrap_or("");
        return !matches!(parent_name, "plugins" | "extensions");
    }
    false
}

fn is_customization_dir_name(name: &str) -> bool {
    matches!(
        name,
        "plugins"
            | ".claude-plugin"
            | ".codex-plugin"
            | "extensions"
            | "skills"
            | "hooks"
            | "hooks-handlers"
            | ".agents"
            | ".agent"
            | ".antigravitycli"
    )
}

fn has_customization_ancestor(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(s) => s.to_str().is_some_and(is_customization_dir_name),
        _ => false,
    })
}

fn is_plugin_or_skill_root(dir: &Path) -> bool {
    dir.join("plugin.json").is_file()
        || dir.join(".claude-plugin").is_dir()
        || dir.join(".codex-plugin").is_dir()
        || dir.join("gemini-extension.json").is_file()
        || dir.join("SKILL.md").is_file()
}

fn classify_file(path: &Path, ctx: &mut WalkContext<'_>, in_customization_tree: bool) {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    if file_name.ends_with(".leaktap.bak") {
        return;
    }

    // Skip files > 256 MB to stay responsive on unexpected disk dumps
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > 256 * 1024 * 1024 {
            return;
        }
    }

    if is_mcp_config_filename(path, file_name) {
        if ctx.include_mcp && ctx.seen.insert(path.to_path_buf()) {
            ctx.mcp_configs.push(path.to_path_buf());
            // Claude / Gemini `settings.json` can also define lifecycle `hooks`
            if matches!(file_name, "settings.json" | "settings.local.json") {
                ctx.plugin_files.push(path.to_path_buf());
            }
        }
        return;
    }

    let is_explicit_plugin_file = matches!(
        file_name,
        "hooks.json" | "plugin.json" | "gemini-extension.json" | "SKILL.md"
    );

    if is_explicit_plugin_file || in_customization_tree {
        if ctx.include_mcp
            && (is_explicit_plugin_file || is_auditable_customization_file(path, file_name))
            && ctx.seen.insert(path.to_path_buf())
        {
            ctx.plugin_files.push(path.to_path_buf());
        }
        // Never treat plugin manifests, licenses, or skill files as chat transcripts
        return;
    }

    if is_transcript_filename(file_name) && ctx.seen.insert(path.to_path_buf()) {
        ctx.transcripts.push(path.to_path_buf());
    }
}

fn is_auditable_customization_file(path: &Path, file_name: &str) -> bool {
    if matches!(
        file_name,
        "hooks.json"
            | "plugin.json"
            | "gemini-extension.json"
            | "SKILL.md"
            | "AGENTS.md"
            | "GEMINI.md"
    ) {
        return true;
    }

    if has_script_extension(path) {
        return true;
    }

    // Subagent and slash-command prompt markdown files inside plugins (`agents/*.md`, `commands/*.md`, `rules/*.md`)
    if file_name.ends_with(".md")
        && !matches!(
            file_name,
            "README.md" | "CHANGELOG.md" | "LICENSE.md" | "CONTRIBUTING.md"
        )
    {
        if let Some(parent_name) = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
        {
            if matches!(parent_name, "agents" | "commands" | "rules") {
                return true;
            }
        }
    }

    false
}

fn is_mcp_config_filename(path: &Path, file_name: &str) -> bool {
    if matches!(
        file_name,
        ".mcp.json"
            | "mcp.json"
            | "mcp_config.json"
            | "claude_desktop_config.json"
            | ".claude.json"
    ) {
        return true;
    }
    if matches!(file_name, "settings.json" | "settings.local.json") {
        let path_str = path.to_string_lossy();
        if path_str.contains(".gemini") || path_str.contains(".claude") {
            return true;
        }
    }
    if file_name == "config.toml" {
        let path_str = path.to_string_lossy().to_ascii_lowercase();
        if path_str.contains("codex") {
            return true;
        }
    }
    false
}

fn is_transcript_filename(file_name: &str) -> bool {
    // Skip package metadata, lockfiles, signed policy metadata, and CLI OAuth/login state files
    if matches!(
        file_name,
        "package.json"
            | "package-lock.json"
            | "tsconfig.json"
            | "Cargo.lock"
            | "Cargo.toml"
            | "oauth_creds.json"
            | "google_accounts.json"
            | ".credentials.json"
            | "credentials.json"
            | "auth.json"
            | "plugin-secrets.json"
            | "keybindings.json"
            | "onboarding.json"
            | "policy-limits.json"
    ) || file_name.ends_with(".signature.json")
        || file_name.ends_with(".stamp.json")
    {
        return false;
    }

    file_name.ends_with(".jsonl")
        || file_name.ends_with(".json")
        || file_name.ends_with(".log")
        || file_name.ends_with(".txt")
}

pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

pub fn shorten_home(path: &Path) -> String {
    if let Some(home) = home_dir() {
        if let Ok(stripped) = path.strip_prefix(&home) {
            let rel = stripped.to_string_lossy();
            if rel.is_empty() {
                return "~".to_string();
            }
            return format!("~/{rel}");
        }
    }
    path.to_string_lossy().into_owned()
}
