use crate::config::PolicyConfig;
use crate::plugin_audit::{has_script_extension, is_shebang_script};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct DiscoveredTargets {
    pub transcript_files: Vec<PathBuf>,
    pub mcp_config_files: Vec<PathBuf>,
    pub plugin_files: Vec<PathBuf>,
    pub scanned_roots: Vec<String>,
}

const ALWAYS_IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".pnpm-store",
    "Cache",
    "caches",
    "GPUCache",
    "Code Cache",
    "CachedData",
    "CachedExtensionVSIXs",
    "DawnCache",
    "blob_storage",
    "Session Storage",
    "Local Storage",
    "IndexedDB",
    "crashes",
];

const NON_PLUGIN_IGNORED_DIRS: &[&str] = &["dist", "build", "out", ".next", "coverage"];

struct WalkContext<'a> {
    transcripts: &'a mut Vec<PathBuf>,
    mcp_configs: &'a mut Vec<PathBuf>,
    plugin_files: &'a mut Vec<PathBuf>,
    seen: &'a mut HashSet<PathBuf>,
    visited_dirs: &'a mut HashSet<PathBuf>,
    include_mcp: bool,
    explicit_scan: bool,
    /// True during `leaktap clean` without `--include-code`: directory walks only select actual
    /// chat/session transcripts and never mutate repository source code, configs, or docs.
    clean_session_logs_only: bool,
    policy: Option<&'a PolicyConfig>,
}

pub fn discover_targets(custom_paths: &[PathBuf], include_mcp: bool) -> DiscoveredTargets {
    discover_targets_with_policy(custom_paths, include_mcp, None)
}

pub fn discover_targets_with_policy(
    custom_paths: &[PathBuf],
    include_mcp: bool,
    policy: Option<&PolicyConfig>,
) -> DiscoveredTargets {
    discover_targets_internal(custom_paths, false, include_mcp, false, policy)
}

pub fn discover_targets_with_all_and_policy(
    custom_paths: &[PathBuf],
    scan_all: bool,
    include_mcp: bool,
    policy: Option<&PolicyConfig>,
) -> DiscoveredTargets {
    discover_targets_internal(custom_paths, scan_all, include_mcp, false, policy)
}

pub fn discover_clean_targets_with_policy(
    custom_paths: &[PathBuf],
    include_code: bool,
    policy: Option<&PolicyConfig>,
) -> DiscoveredTargets {
    discover_targets_internal(custom_paths, false, false, !include_code, policy)
}

fn discover_targets_internal(
    custom_paths: &[PathBuf],
    scan_all: bool,
    include_mcp: bool,
    clean_session_logs_only: bool,
    policy: Option<&PolicyConfig>,
) -> DiscoveredTargets {
    let mut transcripts = Vec::new();
    let mut mcp_configs = Vec::new();
    let mut plugin_files = Vec::new();
    let mut seen = HashSet::new();
    let mut visited_dirs = HashSet::new();
    let mut roots = Vec::new();

    {
        let mut ctx = WalkContext {
            transcripts: &mut transcripts,
            mcp_configs: &mut mcp_configs,
            plugin_files: &mut plugin_files,
            seen: &mut seen,
            visited_dirs: &mut visited_dirs,
            include_mcp,
            explicit_scan: !custom_paths.is_empty(),
            clean_session_logs_only,
            policy,
        };

        if !custom_paths.is_empty() && !scan_all {
            for p in custom_paths {
                roots.push(shorten_home(p));
                let start_in_cust =
                    has_customization_ancestor(p) || (p.is_dir() && is_plugin_or_skill_root(p));
                walk_path(p, &mut ctx, start_in_cust, 0);
            }
        } else {
            if let Some(home) = home_dir() {
                let agent_dirs = [
                    home.join(".claude"),
                    home.join(".codex"),
                    home.join(".cursor"),
                    home.join(".gemini"),
                    home.join(".continue"),
                    home.join(".windsurf"),
                    home.join(".codeium/windsurf"),
                ];

                for dir in &agent_dirs {
                    if dir.exists() {
                        roots.push(shorten_home(dir));
                        walk_path(dir, &mut ctx, false, 0);
                    }
                }

                // Cross-platform IDE & desktop agent storage (Linux ~/.config, macOS ~/Library/Application Support, Windows %APPDATA%)
                let app_cfg_roots = os_app_config_dirs(&home);
                for cfg_root in &app_cfg_roots {
                    let ide_state_dirs = [
                        cfg_root.join("Cursor/User/globalStorage"),
                        cfg_root.join("Cursor/User/workspaceStorage"),
                        cfg_root.join("Windsurf/User/globalStorage"),
                        cfg_root.join("Windsurf/User/workspaceStorage"),
                    ];
                    for dir in &ide_state_dirs {
                        if dir.exists() {
                            let label = shorten_home(dir);
                            if !roots.contains(&label) {
                                roots.push(label);
                            }
                            walk_path(dir, &mut ctx, false, 0);
                        }
                    }

                    // Cline (`saoudrizwan.claude-dev`) & Roo Code (`rooveterinaryinc.roo-cline`) under VS Code variants
                    for ide in ["Code", "Code - Insiders", "VSCodium"] {
                        for ext_id in ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"] {
                            let ext_dir =
                                cfg_root.join(ide).join("User/globalStorage").join(ext_id);
                            if ext_dir.exists() {
                                let label = shorten_home(&ext_dir);
                                if !roots.contains(&label) {
                                    roots.push(label);
                                }
                                walk_path(&ext_dir, &mut ctx, false, 0);
                            }
                        }
                    }
                }

                // Remote SSH / container VS Code & Cursor server storage
                for srv in [".vscode-server", ".cursor-server", ".windsurf-server"] {
                    for ext_id in ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"] {
                        let ext_dir = home.join(srv).join("data/User/globalStorage").join(ext_id);
                        if ext_dir.exists() {
                            let label = shorten_home(&ext_dir);
                            if !roots.contains(&label) {
                                roots.push(label);
                            }
                            walk_path(&ext_dir, &mut ctx, false, 0);
                        }
                    }
                }

                let home_claude_json = home.join(".claude.json");
                if home_claude_json.is_file()
                    && !ctx.is_ignored(&home_claude_json)
                    && ctx.seen.insert(home_claude_json.clone())
                {
                    let label = shorten_home(&home_claude_json);
                    if !roots.contains(&label) {
                        roots.push(label);
                    }
                    ctx.transcripts.push(home_claude_json.clone());
                    if include_mcp {
                        ctx.mcp_configs.push(home_claude_json);
                    }
                }

                if include_mcp {
                    let mut extra_mcp_files = Vec::new();
                    for cfg_root in &app_cfg_roots {
                        extra_mcp_files.push(cfg_root.join("Claude/claude_desktop_config.json"));
                        for ide in ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"] {
                            extra_mcp_files.push(cfg_root.join(ide).join("User/mcp.json"));
                            extra_mcp_files.push(cfg_root.join(ide).join("User/settings.json"));
                        }
                    }
                    for cfg in &extra_mcp_files {
                        if cfg.is_file() && !ctx.is_ignored(cfg) && ctx.seen.insert(cfg.clone()) {
                            ctx.mcp_configs.push(cfg.clone());
                        }
                    }
                }
            }

            if let Ok(cwd) = env::current_dir() {
                let aider_files = [
                    cwd.join(".aider.chat.history.md"),
                    cwd.join(".aider.input.history"),
                ];
                for af in &aider_files {
                    if af.is_file() && !ctx.is_ignored(af) && ctx.seen.insert(af.clone()) {
                        ctx.transcripts.push(af.clone());
                    }
                }

                if include_mcp {
                    let workspace_configs = [
                        cwd.join(".mcp.json"),
                        cwd.join("mcp.json"),
                        cwd.join(".claude.json"),
                        cwd.join(".agents/mcp_config.json"),
                        cwd.join(".antigravitycli/mcp_config.json"),
                        cwd.join(".codex/config.toml"),
                        cwd.join(".cursor/mcp.json"),
                        cwd.join(".roo/mcp.json"),
                        cwd.join(".vscode/mcp.json"),
                        cwd.join(".vscode/settings.json"),
                        cwd.join(".gemini/settings.json"),
                        cwd.join(".claude/settings.json"),
                        cwd.join(".claude/settings.local.json"),
                        cwd.join(".junie/mcp/mcp.json"),
                        cwd.join(".amazonq/mcp.json"),
                        cwd.join(".kiro/settings/mcp.json"),
                        cwd.join(".zed/settings.json"),
                    ];
                    for cfg in &workspace_configs {
                        if cfg.is_file() {
                            classify_file(cfg, &mut ctx, false, false);
                        }
                    }

                    let workspace_customization_paths = [
                        cwd.join("CLAUDE.md"),
                        cwd.join("AGENTS.md"),
                        cwd.join("GEMINI.md"),
                        cwd.join(".cursorrules"),
                        cwd.join(".windsurfrules"),
                        cwd.join(".clinerules"),
                        cwd.join(".roomodes"),
                        cwd.join(".github/copilot-instructions.md"),
                        cwd.join(".github/instructions"),
                        cwd.join(".github/prompts"),
                        cwd.join(".claude/CLAUDE.md"),
                        cwd.join(".claude/plugins"),
                        cwd.join(".claude/skills"),
                        cwd.join(".claude/hooks"),
                        cwd.join(".claude/commands"),
                        cwd.join(".claude/agents"),
                        cwd.join(".codex/plugins"),
                        cwd.join(".codex/skills"),
                        cwd.join(".codex/hooks.json"),
                        cwd.join(".cursor/rules"),
                        cwd.join(".windsurf/rules"),
                        cwd.join(".windsurf/workflows"),
                        cwd.join(".roo/rules"),
                        cwd.join(".roo/rules-code"),
                        cwd.join(".roo/rules-architect"),
                        cwd.join(".roo/rules-ask"),
                        cwd.join(".junie"),
                        cwd.join(".amazonq"),
                        cwd.join(".kiro"),
                        cwd.join(".augment"),
                        cwd.join(".trae"),
                        cwd.join(".agents"),
                        cwd.join(".agent"),
                        cwd.join(".antigravitycli"),
                    ];
                    for cust in &workspace_customization_paths {
                        if cust.exists() {
                            walk_path(cust, &mut ctx, true, 0);
                        }
                    }

                    // Discover nested monorepo package agent configs (e.g. `packages/*/CLAUDE.md`,
                    // `services/*/.mcp.json`) up to depth 3 when `cwd` is a project directory (not `$HOME` or `/`).
                    let is_home_or_root =
                        cwd == Path::new("/") || home_dir().is_some_and(|h| cwd == h);
                    if !is_home_or_root {
                        let mut dir_budget = 256usize;
                        discover_monorepo_subconfigs(&cwd, &mut ctx, 0, &mut dir_budget);
                    }
                }
            }

            if scan_all {
                ctx.explicit_scan = true;
                for p in custom_paths {
                    let label = shorten_home(p);
                    if !roots.contains(&label) {
                        roots.push(label);
                    }
                    let start_in_cust =
                        has_customization_ancestor(p) || (p.is_dir() && is_plugin_or_skill_root(p));
                    walk_path(p, &mut ctx, start_in_cust, 0);
                }
                if let Ok(cwd) = env::current_dir() {
                    let is_home_or_root =
                        cwd == Path::new("/") || home_dir().is_some_and(|h| cwd == h);
                    if !is_home_or_root {
                        let label = shorten_home(&cwd);
                        if !roots.contains(&label) {
                            roots.push(label);
                        }
                        let start_in_cust = has_customization_ancestor(&cwd)
                            || (cwd.is_dir() && is_plugin_or_skill_root(&cwd));
                        walk_path(&cwd, &mut ctx, start_in_cust, 0);
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

fn discover_monorepo_subconfigs(
    dir: &Path,
    ctx: &mut WalkContext<'_>,
    depth: usize,
    dir_budget: &mut usize,
) {
    if depth > 3 || *dir_budget == 0 || ctx.is_ignored(dir) {
        return;
    }
    *dir_budget = dir_budget.saturating_sub(1);

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if ctx.is_ignored(&p) {
            continue;
        }
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&p) else {
            continue;
        };
        if meta.is_dir() {
            if should_ignore_dir(dir, name, false) {
                continue;
            }
            if is_customization_dir_name(name) || is_plugin_or_skill_root(&p) {
                walk_path(&p, ctx, true, 0);
                continue;
            }
            if name.starts_with('.') {
                if matches!(
                    name,
                    ".claude"
                        | ".codex"
                        | ".cursor"
                        | ".gemini"
                        | ".windsurf"
                        | ".roo"
                        | ".vscode"
                        | ".github"
                        | ".junie"
                        | ".amazonq"
                        | ".kiro"
                        | ".augment"
                        | ".trae"
                        | ".zed"
                ) && depth > 0
                {
                    discover_dotdir_in_subpackage(&p, name, ctx);
                }
                continue;
            }
            discover_monorepo_subconfigs(&p, ctx, depth + 1, dir_budget);
        } else if meta.is_file()
            && depth > 0
            && (is_mcp_config_filename(&p, name)
                || is_top_level_instruction_or_plugin_file(&p, name))
        {
            classify_file(&p, ctx, false, false);
        }
    }
}

fn discover_dotdir_in_subpackage(dotdir: &Path, name: &str, ctx: &mut WalkContext<'_>) {
    match name {
        ".claude" => {
            for f in ["settings.json", "settings.local.json"] {
                let fp = dotdir.join(f);
                if fp.is_file() {
                    classify_file(&fp, ctx, false, false);
                }
            }
            for sub in [
                "CLAUDE.md",
                "plugins",
                "skills",
                "hooks",
                "commands",
                "agents",
            ] {
                let sp = dotdir.join(sub);
                if sp.exists() {
                    walk_path(&sp, ctx, true, 0);
                }
            }
        }
        ".codex" => {
            let cfg = dotdir.join("config.toml");
            if cfg.is_file() {
                classify_file(&cfg, ctx, false, false);
            }
            for sub in ["plugins", "skills", "hooks.json"] {
                let sp = dotdir.join(sub);
                if sp.exists() {
                    walk_path(&sp, ctx, true, 0);
                }
            }
        }
        ".cursor" => {
            let cfg = dotdir.join("mcp.json");
            if cfg.is_file() {
                classify_file(&cfg, ctx, false, false);
            }
            let rules = dotdir.join("rules");
            if rules.exists() {
                walk_path(&rules, ctx, true, 0);
            }
        }
        ".windsurf" => {
            for sub in ["rules", "workflows"] {
                let sp = dotdir.join(sub);
                if sp.exists() {
                    walk_path(&sp, ctx, true, 0);
                }
            }
        }
        ".roo" => {
            let cfg = dotdir.join("mcp.json");
            if cfg.is_file() {
                classify_file(&cfg, ctx, false, false);
            }
            for sub in ["rules", "rules-code", "rules-architect", "rules-ask"] {
                let rules = dotdir.join(sub);
                if rules.exists() {
                    walk_path(&rules, ctx, true, 0);
                }
            }
        }
        ".gemini" => {
            let cfg = dotdir.join("settings.json");
            if cfg.is_file() {
                classify_file(&cfg, ctx, false, false);
            }
        }
        ".vscode" => {
            for f in ["mcp.json", "settings.json"] {
                let cfg = dotdir.join(f);
                if cfg.is_file() {
                    classify_file(&cfg, ctx, false, false);
                }
            }
        }
        ".zed" => {
            let cfg = dotdir.join("settings.json");
            if cfg.is_file() {
                classify_file(&cfg, ctx, false, false);
            }
        }
        ".github" => {
            for sub in ["copilot-instructions.md", "instructions", "prompts"] {
                let sp = dotdir.join(sub);
                if sp.exists() {
                    walk_path(&sp, ctx, true, 0);
                }
            }
        }
        ".junie" | ".amazonq" | ".kiro" | ".augment" | ".trae" => {
            walk_path(dotdir, ctx, true, 0);
        }
        _ => {}
    }
}

fn os_app_config_dirs(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    };

    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            push_unique(PathBuf::from(xdg));
        }
    }
    push_unique(home.join(".config"));
    push_unique(home.join("Library/Application Support"));
    if let Some(appdata) = env::var_os("APPDATA") {
        if !appdata.is_empty() {
            push_unique(PathBuf::from(appdata));
        }
    }
    push_unique(home.join("AppData/Roaming"));
    dirs
}

impl WalkContext<'_> {
    fn is_ignored(&self, path: &Path) -> bool {
        self.policy.is_some_and(|p| p.is_path_ignored(path))
    }
}

fn walk_path(path: &Path, ctx: &mut WalkContext<'_>, in_customization_tree: bool, depth: usize) {
    if depth > 16 || !path.exists() || ctx.is_ignored(path) {
        return;
    }

    let Ok(meta) = fs::metadata(path) else {
        return;
    };

    if meta.is_file() {
        let file_in_cust = in_customization_tree
            || has_customization_ancestor(path)
            || path.parent().is_some_and(is_plugin_or_skill_root);
        classify_file(path, ctx, file_in_cust, true);
        return;
    }

    if !meta.is_dir() {
        return;
    }

    // Track canonical real directory path to traverse symlinked plugins safely without cycles
    if let Ok(canon) = fs::canonicalize(path) {
        if !ctx.visited_dirs.insert(canon) {
            return;
        }
    }

    let dir_is_cust = in_customization_tree || is_plugin_or_skill_root(path);

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if ctx.is_ignored(&p) {
            continue;
        }
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let Ok(target_meta) = fs::metadata(&p) else {
            continue;
        };

        if target_meta.is_dir() {
            if should_ignore_dir(path, name, dir_is_cust) {
                continue;
            }
            let child_in_cust = dir_is_cust
                || is_customization_dir_name(name)
                || has_customization_ancestor(&p)
                || is_plugin_or_skill_root(&p);
            walk_path(&p, ctx, child_in_cust, depth + 1);
        } else if target_meta.is_file() {
            classify_file(&p, ctx, dir_is_cust, false);
        }
    }
}

fn should_ignore_dir(parent: &Path, name: &str, in_customization_tree: bool) -> bool {
    if ALWAYS_IGNORED_DIRS.contains(&name) {
        return true;
    }
    if !in_customization_tree && NON_PLUGIN_IGNORED_DIRS.contains(&name) {
        return true;
    }
    if matches!(name, ".system" | "builtin") {
        // Only skip shipped first-party system/builtin skill folders inside the user's home `~/.codex`
        // or `~/.gemini` installation directories — NEVER skip `.system` or `builtin` in repositories!
        return home_dir().is_some_and(|h| {
            parent.starts_with(h.join(".codex")) || parent.starts_with(h.join(".gemini"))
        });
    }
    if name == "backups" {
        // Only skip `~/.claude/backups` internal CLI config backups, NOT repository `backups/` folders
        let parent_name = parent.file_name().and_then(|s| s.to_str()).unwrap_or("");
        return parent_name == ".claude";
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
            | "marketplaces"
            | ".claude-plugin"
            | ".codex-plugin"
            | "extensions"
            | "skills"
            | "hooks"
            | "hooks-handlers"
            | ".clinerules"
            | ".agents"
            | ".agent"
            | ".antigravitycli"
            | ".junie"
            | ".amazonq"
            | ".kiro"
            | ".augment"
            | ".trae"
    )
}

fn has_customization_ancestor(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();

    for (idx, &c) in comps.iter().enumerate() {
        if is_customization_dir_name(c) {
            return true;
        }
        if (matches!(
            c,
            "commands" | "agents" | "rules" | "workflows" | "instructions" | "prompts" | "steering"
        ) || c.starts_with("rules-"))
            && idx > 0
            && matches!(
                comps[idx - 1],
                ".claude"
                    | ".codex"
                    | ".cursor"
                    | ".gemini"
                    | ".windsurf"
                    | ".roo"
                    | ".github"
                    | ".junie"
                    | ".amazonq"
                    | ".kiro"
                    | ".augment"
                    | ".trae"
            )
        {
            return true;
        }
    }
    false
}

fn is_plugin_or_skill_root(dir: &Path) -> bool {
    dir.join("plugin.json").is_file()
        || dir.join(".claude-plugin").is_dir()
        || dir.join(".codex-plugin").is_dir()
        || dir.join("gemini-extension.json").is_file()
        || dir.join("SKILL.md").is_file()
}

fn is_temporary_leaktap_artifact(file_name: &str) -> bool {
    file_name.ends_with(".leaktap.bak")
        || file_name.ends_with(".leaktap.tmp")
        || (file_name.contains(".leaktap.") && file_name.ends_with(".tmp"))
}

fn classify_file(
    path: &Path,
    ctx: &mut WalkContext<'_>,
    in_customization_tree: bool,
    explicit_file: bool,
) {
    if ctx.is_ignored(path) {
        return;
    }
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    if is_temporary_leaktap_artifact(file_name) {
        return;
    }

    // Non-SQLite text files > 256 MB are skipped; SQLite/WAL files stream up to 2 GB in scanner.rs
    if !crate::scanner::is_sqlite_extension(path) {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > 256 * 1024 * 1024 {
                return;
            }
        }
    }

    // `.claude.json` is dual-role: it holds both `mcpServers` configs AND `projects.<path>.history` prompt transcripts!
    if file_name == ".claude.json" {
        if ctx.seen.insert(path.to_path_buf()) {
            ctx.transcripts.push(path.to_path_buf());
            if ctx.include_mcp && !ctx.clean_session_logs_only {
                ctx.mcp_configs.push(path.to_path_buf());
            }
        }
        return;
    }

    // If the user passed `--path <specific-file>` to `leaktap clean`, always honor that exact file!
    if explicit_file && !ctx.include_mcp {
        if ctx.seen.insert(path.to_path_buf()) {
            ctx.transcripts.push(path.to_path_buf());
        }
        return;
    }

    // During directory `clean` without `--include-code`, never mutate MCP configs, plugins, skills, or repo source code
    if ctx.clean_session_logs_only {
        if is_mcp_config_filename(path, file_name)
            || is_top_level_instruction_or_plugin_file(path, file_name)
            || in_customization_tree
        {
            return;
        }
        if is_session_clean_target(path, file_name) && ctx.seen.insert(path.to_path_buf()) {
            ctx.transcripts.push(path.to_path_buf());
        }
        return;
    }

    if is_mcp_config_filename(path, file_name) {
        if ctx.include_mcp && ctx.seen.insert(path.to_path_buf()) {
            ctx.mcp_configs.push(path.to_path_buf());
            // Claude / Gemini `settings.json` can also define lifecycle `hooks`, `apiKeyHelper`, `statusLine`, and `env`
            if matches!(file_name, "settings.json" | "settings.local.json") {
                let ps = path.to_string_lossy();
                if ps.contains(".claude") || ps.contains(".gemini") {
                    ctx.plugin_files.push(path.to_path_buf());
                }
            }
        } else if !ctx.include_mcp && ctx.seen.insert(path.to_path_buf()) {
            // `clean --include-code`
            ctx.transcripts.push(path.to_path_buf());
        }
        return;
    }

    let is_explicit_plugin_file = is_top_level_instruction_or_plugin_file(path, file_name);

    if is_explicit_plugin_file || in_customization_tree {
        if ctx.include_mcp {
            if crate::scanner::is_sqlite_extension(path)
                || file_name.ends_with(".jsonl")
                || file_name.ends_with(".log")
            {
                if ctx.seen.insert(path.to_path_buf()) {
                    ctx.transcripts.push(path.to_path_buf());
                }
            } else if is_compiled_binary_file(path) {
                if ctx.seen.insert(path.to_path_buf()) {
                    ctx.plugin_files.push(path.to_path_buf());
                    ctx.transcripts.push(path.to_path_buf());
                }
            } else if (is_explicit_plugin_file || is_auditable_customization_file(path, file_name))
                && ctx.seen.insert(path.to_path_buf())
            {
                ctx.plugin_files.push(path.to_path_buf());
            } else if explicit_file && ctx.seen.insert(path.to_path_buf()) {
                // Guarantee an explicit `--path <file>` inside a skill/plugin directory is never silently skipped
                ctx.transcripts.push(path.to_path_buf());
            }
        } else if !is_compiled_binary_file(path) && ctx.seen.insert(path.to_path_buf()) {
            // `clean --include-code`
            ctx.transcripts.push(path.to_path_buf());
        }
        return;
    }

    if is_transcript_file(path, file_name, explicit_file, ctx.explicit_scan)
        && ctx.seen.insert(path.to_path_buf())
    {
        ctx.transcripts.push(path.to_path_buf());
    }
}

/// Returns `true` if `path` is a chat/session transcript safe to scrub by default without `--include-code`.
pub fn is_safe_default_clean_target(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if is_temporary_leaktap_artifact(file_name) {
        return false;
    }
    if file_name == ".claude.json" {
        return true;
    }
    if is_mcp_config_filename(path, file_name)
        || is_top_level_instruction_or_plugin_file(path, file_name)
        || has_customization_ancestor(path)
    {
        return false;
    }
    is_session_clean_target(path, file_name)
}

fn is_session_clean_target(path: &Path, file_name: &str) -> bool {
    if is_lock_or_metadata_file(file_name) {
        return false;
    }
    if matches!(
        file_name,
        "package.json"
            | "tsconfig.json"
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
    ) {
        return false;
    }
    if crate::scanner::is_sqlite_extension(path) {
        // Included so `clean` reports skipped binary SQLite session files clearly without modifying them
        return has_agent_session_ancestor(path)
            || file_name.ends_with(".vscdb")
            || file_name.ends_with(".vscdb-wal");
    }
    if file_name.ends_with(".jsonl")
        || file_name == ".aider.chat.history.md"
        || file_name == ".aider.input.history"
    {
        return true;
    }
    if has_agent_session_ancestor(path) {
        return file_name.ends_with(".json")
            || file_name.ends_with(".log")
            || file_name.ends_with(".txt")
            || (file_name.ends_with(".md") && !matches!(file_name, "LICENSE.md" | "CHANGELOG.md"));
    }
    file_name.ends_with(".log")
}

/// Returns `true` if `rel_path` can be classified as an MCP config, plugin manifest, hook, or skill/instruction file.
pub fn is_mcp_or_plugin_candidate_relpath(rel_path: &Path) -> bool {
    let Some(file_name) = rel_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if is_temporary_leaktap_artifact(file_name) || is_lock_or_metadata_file(file_name) {
        return false;
    }
    is_mcp_config_filename(rel_path, file_name)
        || is_top_level_instruction_or_plugin_file(rel_path, file_name)
        || has_customization_ancestor(rel_path)
}

fn is_top_level_instruction_or_plugin_file(path: &Path, file_name: &str) -> bool {
    if matches!(
        file_name,
        "hooks.json"
            | "plugin.json"
            | "gemini-extension.json"
            | "SKILL.md"
            | "CLAUDE.md"
            | "AGENTS.md"
            | "GEMINI.md"
            | ".cursorrules"
            | ".windsurfrules"
            | ".clinerules"
            | ".roomodes"
            | "copilot-instructions.md"
    ) {
        return true;
    }
    if file_name == "guidelines.md" && path.to_string_lossy().contains(".junie") {
        return true;
    }
    if file_name.ends_with(".mdc") {
        let p = path.to_string_lossy();
        if p.contains(".cursor") || p.contains("rules") {
            return true;
        }
    }
    if (file_name.ends_with(".instructions.md") || file_name.ends_with(".prompt.md"))
        && path.to_string_lossy().contains(".github")
    {
        return true;
    }
    false
}

/// Detects compiled native / WebAssembly / bytecode binaries (`ELF`, `Mach-O`, `PE`, `Wasm`, `.node`, `.so`, `.dylib`, `.dll`, `.exe`, `.pyc`).
pub fn is_compiled_binary_file(path: &Path) -> bool {
    if crate::scanner::is_sqlite_extension(path) {
        return false;
    }
    if let Some(ext) = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
    {
        if matches!(
            ext.as_str(),
            "exe" | "dll" | "so" | "dylib" | "node" | "wasm" | "pyc" | "pyo" | "class" | "o" | "a"
        ) {
            return true;
        }
        // Skip common non-executable media/archive/font files inside `assets/`
        if matches!(
            ext.as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "icns"
                | "svg"
                | "pdf"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "mp3"
                | "mp4"
                | "wav"
                | "zip"
                | "gz"
                | "tgz"
                | "tar"
                | "xz"
                | "zst"
        ) {
            return false;
        }
    }
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut hdr = [0u8; 64];
    let Ok(n) = f.read(&mut hdr) else {
        return false;
    };
    if n < 4 {
        return false;
    }
    is_compiled_binary_magic(&hdr[..n])
}

pub fn is_compiled_binary_magic(hdr: &[u8]) -> bool {
    if hdr.len() < 4 {
        return false;
    }
    // ELF (`\x7fELF`), WebAssembly (`\0asm`), Java `.class` / Mach-O fat (`\xca\xfe\xba\xbe`),
    // Mach-O 32/64-bit little/big endian, or Windows PE/COFF (`MZ` with binary NUL bytes)
    if hdr.starts_with(b"\x7fELF")
        || hdr.starts_with(b"\0asm")
        || matches!(
            &hdr[..4],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        )
    {
        return true;
    }
    if hdr.starts_with(b"MZ") && hdr.contains(&0) {
        return true;
    }
    false
}

fn is_auditable_customization_file(path: &Path, file_name: &str) -> bool {
    if is_lock_or_metadata_file(file_name) {
        return false;
    }

    if is_top_level_instruction_or_plugin_file(path, file_name) || file_name.ends_with(".mdc") {
        return true;
    }

    if has_script_extension(path) || is_compiled_binary_file(path) {
        return true;
    }

    // Extensionless scripts inside plugins/hooks (`#!/usr/bin/env python3`, `#!/bin/sh`, etc.)
    // or extensionless rule files inside `.clinerules/`, `rules/`, `instructions/`, or `prompts/`.
    if path.extension().is_none() && (is_shebang_script(path) || has_instruction_dir_ancestor(path))
    {
        return true;
    }

    // Audit ALL companion markdown and text prompt files inside skills/plugins (`extra.md`, `prompt.txt`, etc.)
    if (file_name.ends_with(".md") && !matches!(file_name, "LICENSE.md" | "CHANGELOG.md"))
        || (file_name.ends_with(".txt") && !file_name.eq_ignore_ascii_case("LICENSE.txt"))
    {
        return true;
    }

    // Audit companion JSON/YAML/TOML/dotenv/key files bundled inside plugins/skills (`assets/`, `config/`, etc.)
    if is_dotenv_filename(file_name) {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some(
            "json"
                | "yaml"
                | "yml"
                | "toml"
                | "ini"
                | "cfg"
                | "conf"
                | "xml"
                | "pem"
                | "key"
                | "asc"
        )
    )
}

fn has_instruction_dir_ancestor(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(s) => s.to_str().is_some_and(|name| {
            matches!(
                name,
                ".clinerules"
                    | "rules"
                    | "workflows"
                    | "instructions"
                    | "prompts"
                    | "commands"
                    | "steering"
            ) || name.starts_with("rules-")
        }),
        _ => false,
    })
}

fn is_mcp_config_filename(path: &Path, file_name: &str) -> bool {
    if matches!(
        file_name,
        ".mcp.json"
            | "mcp.json"
            | "mcp_config.json"
            | "claude_desktop_config.json"
            | "cline_mcp_settings.json"
            | "roo_mcp_settings.json"
            | ".claude.json"
    ) {
        return true;
    }
    if matches!(file_name, "settings.json" | "settings.local.json") {
        let path_str = path.to_string_lossy();
        if path_str.contains(".gemini")
            || path_str.contains(".claude")
            || (file_name == "settings.json"
                && (path_str.contains(".vscode")
                    || path_str.contains(".zed")
                    || path_str.contains("User/settings.json")
                    || path_str.contains("User\\settings.json")))
        {
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

pub fn has_agent_session_ancestor(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(s) => matches!(
            s.to_str(),
            Some(
                ".claude"
                    | ".codex"
                    | ".cursor"
                    | ".gemini"
                    | ".continue"
                    | ".windsurf"
                    | "saoudrizwan.claude-dev"
                    | "rooveterinaryinc.roo-cline"
            )
        ),
        _ => false,
    })
}

fn is_lock_or_metadata_file(file_name: &str) -> bool {
    matches!(
        file_name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "bun.lock"
            | "bun.lockb"
            | "Cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "Pipfile.lock"
            | "composer.lock"
            | "Gemfile.lock"
            | "go.sum"
            | "leaktap.toml"
            | ".leaktap.toml"
            | ".leaktapignore"
            | "cookies.sqlite"
            | "cookies.sqlite-wal"
            | "favicons.sqlite"
            | "places.sqlite"
            | "permissions.sqlite"
    ) || file_name.ends_with(".signature.json")
        || file_name.ends_with(".stamp.json")
}

fn is_dotenv_filename(file_name: &str) -> bool {
    file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env")
}

fn is_explicit_scan_code_or_config_file(path: &Path, file_name: &str) -> bool {
    if is_dotenv_filename(file_name) || matches!(file_name, "Dockerfile" | "Makefile") {
        return true;
    }
    if file_name.ends_with(".md") && !matches!(file_name, "LICENSE.md" | "CHANGELOG.md") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some(
            "yaml"
                | "yml"
                | "toml"
                | "ini"
                | "cfg"
                | "conf"
                | "properties"
                | "xml"
                | "pem"
                | "key"
                | "asc"
                | "pkcs8"
                | "py"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "rs"
                | "go"
                | "rb"
                | "php"
                | "java"
                | "kt"
                | "kts"
                | "swift"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
                | "cs"
                | "sh"
                | "bash"
                | "zsh"
                | "fish"
                | "ps1"
                | "sql"
                | "tf"
                | "tfvars"
                | "hcl"
                | "lua"
                | "pl"
                | "r"
                | "scala"
                | "ex"
                | "exs"
        )
    )
}

fn is_transcript_file(
    path: &Path,
    file_name: &str,
    explicit_file: bool,
    explicit_scan: bool,
) -> bool {
    // 1. An explicit `--path <file>` target is ALWAYS scanned regardless of filename
    if explicit_file {
        return true;
    }

    // 2. Skip lockfiles, browser cookie DBs, and leaktap's own policy files
    if is_lock_or_metadata_file(file_name) {
        return false;
    }

    // 3. During default home-directory discovery (`!explicit_scan`), skip CLI login/OAuth session state
    // and generic build manifests so legitimate user login sessions are not flagged as transcript leaks.
    if !explicit_scan
        && matches!(
            file_name,
            "package.json"
                | "tsconfig.json"
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
        )
    {
        return false;
    }

    if crate::scanner::is_sqlite_extension(path) {
        // Under VS Code/Cursor workspaceStorage, only scan `state.vscdb` / `state.vscdb-wal` or explicit targets
        return true;
    }

    if explicit_scan && is_explicit_scan_code_or_config_file(path, file_name) {
        return true;
    }

    if file_name.ends_with(".md")
        && !matches!(file_name, "LICENSE.md" | "CHANGELOG.md")
        && has_agent_session_ancestor(path)
    {
        return true;
    }

    file_name.ends_with(".jsonl")
        || file_name.ends_with(".json")
        || file_name.ends_with(".log")
        || file_name.ends_with(".txt")
        || file_name == "conversation_summaries.db"
        || file_name == "conversation_summaries.db-wal"
        || file_name == ".aider.chat.history.md"
        || file_name == ".aider.input.history"
}

pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Returns `true` when `path` resolves to `$HOME/.claude.json` even when invoked via a relative
/// path (`.claude.json`, `./.claude.json`) or through a symlinked `$HOME` directory.
pub fn is_home_claude_state_file(path: &Path) -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    let target = home.join(".claude.json");
    if path == target {
        return true;
    }
    let abs_candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    if abs_candidate == target {
        return true;
    }
    match (fs::canonicalize(&abs_candidate), fs::canonicalize(&target)) {
        (Ok(c_path), Ok(c_target)) => c_path == c_target,
        _ => {
            let canon_parent_join = |p: &Path| -> Option<PathBuf> {
                let fname = p.file_name()?;
                let parent = p
                    .parent()
                    .filter(|pr| !pr.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                Some(fs::canonicalize(parent).ok()?.join(fname))
            };
            match (
                canon_parent_join(&abs_candidate),
                canon_parent_join(&target),
            ) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        }
    }
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
