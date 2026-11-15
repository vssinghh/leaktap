use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct DiscoveredTargets {
    pub transcript_files: Vec<PathBuf>,
    pub mcp_config_files: Vec<PathBuf>,
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
    "cache",
    "caches",
    "GPUCache",
    "Code Cache",
    "builtin",
    "marketplaces",
    "plugins",
    "extensions",
    "crashes",
];

pub fn discover_targets(custom_paths: &[PathBuf], include_mcp: bool) -> DiscoveredTargets {
    let mut transcripts = Vec::new();
    let mut mcp_configs = Vec::new();
    let mut seen = HashSet::new();
    let mut roots = Vec::new();

    if !custom_paths.is_empty() {
        for p in custom_paths {
            roots.push(shorten_home(p));
            walk_path(
                p,
                &mut transcripts,
                &mut mcp_configs,
                &mut seen,
                include_mcp,
                0,
            );
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
                    walk_path(
                        dir,
                        &mut transcripts,
                        &mut mcp_configs,
                        &mut seen,
                        include_mcp,
                        0,
                    );
                }
            }

            if include_mcp {
                let extra_mcp_files = [
                    home.join(".claude.json"),
                    home.join(".config/Claude/claude_desktop_config.json"),
                    home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                ];
                for cfg in &extra_mcp_files {
                    if cfg.is_file() && seen.insert(cfg.clone()) {
                        mcp_configs.push(cfg.clone());
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
                    cwd.join(".cursor/mcp.json"),
                    cwd.join(".vscode/mcp.json"),
                    cwd.join(".gemini/settings.json"),
                ];
                for cfg in &workspace_configs {
                    if cfg.is_file() && seen.insert(cfg.clone()) {
                        mcp_configs.push(cfg.clone());
                    }
                }
            }
        }
    }

    transcripts.sort();
    mcp_configs.sort();

    DiscoveredTargets {
        transcript_files: transcripts,
        mcp_config_files: mcp_configs,
        scanned_roots: roots,
    }
}

fn walk_path(
    path: &Path,
    transcripts: &mut Vec<PathBuf>,
    mcp_configs: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    include_mcp: bool,
    depth: usize,
) {
    if depth > 12 || !path.exists() {
        return;
    }

    if path.is_file() {
        classify_file(path, transcripts, mcp_configs, seen, include_mcp);
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

        if IGNORED_DIRS.contains(&name) {
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
            walk_path(&p, transcripts, mcp_configs, seen, include_mcp, depth + 1);
        } else if ft.is_file() {
            classify_file(&p, transcripts, mcp_configs, seen, include_mcp);
        }
    }
}

fn classify_file(
    path: &Path,
    transcripts: &mut Vec<PathBuf>,
    mcp_configs: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    include_mcp: bool,
) {
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
        if include_mcp && seen.insert(path.to_path_buf()) {
            mcp_configs.push(path.to_path_buf());
        }
        return;
    }

    if is_transcript_filename(file_name) && seen.insert(path.to_path_buf()) {
        transcripts.push(path.to_path_buf());
    }
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
    if file_name == "settings.json" {
        let path_str = path.to_string_lossy();
        if path_str.contains(".gemini") || path_str.contains(".claude") {
            return true;
        }
    }
    false
}

fn is_transcript_filename(file_name: &str) -> bool {
    // Skip package metadata, lockfiles, and CLI OAuth/login state files
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
    ) {
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
