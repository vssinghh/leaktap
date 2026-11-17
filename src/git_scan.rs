use crate::config::PolicyConfig;
use crate::discovery::{
    discover_targets_with_policy, is_mcp_or_plugin_candidate_relpath, shorten_home,
};
use crate::mcp_audit::{audit_mcp_file_as_with_roots, McpFinding};
use crate::plugin_audit::audit_plugin_file_as;
use crate::rules::{RuleCategory, RuleEngine};
use crate::scanner::{
    compute_line_and_column, contains_gcp_sa_markers, is_multiline_putty_header,
    is_pem_or_pgp_continuation_line, is_putty_continuation_line,
    is_wrapped_base64_continuation_line, is_wrapped_base64_start_line,
    is_yaml_block_scalar_continuation, scan_single_file_as, yaml_block_scalar_parent_indent,
    FileHit, FindingLocation, TranscriptFinding, TranscriptScanResult, MULTILINE_B64_COALESCE_CAP,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const IGNORED_DIFF_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".pnpm-store",
];

const MAX_GIT_BLOB_AUDIT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GIT_BINARY_SCAN_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DIFF_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HISTORICAL_CONFIG_BLOBS: usize = 10_000;
const MAX_HISTORICAL_BINARY_BLOBS: usize = 1_024;

static SANDBOX_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct GitScanOutput {
    pub transcripts: TranscriptScanResult,
    pub mcp_findings: Vec<McpFinding>,
    pub mcp_files_scanned: usize,
    pub mcp_bytes_scanned: u64,
    pub roots: Vec<String>,
}

struct GitBlobSandbox {
    root: PathBuf,
}

impl GitBlobSandbox {
    fn new() -> Option<Self> {
        let base = env::temp_dir();
        let pid = std::process::id();
        for attempt in 0..32u64 {
            let seq = SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let candidate = base.join(format!("leaktap-git-{pid}-{seq}-{nanos}-{attempt}"));
            #[cfg_attr(not(unix), allow(unused_mut))]
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            if builder.create(&candidate).is_ok() {
                return Some(Self { root: candidate });
            }
        }
        None
    }

    fn write_rel_blob(&self, sub_root: &Path, rel: &str, bytes: &[u8]) -> Option<PathBuf> {
        let clean_rel = validate_safe_rel_path(rel)?;
        let dest = sub_root.join(clean_rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).ok()?;
        }
        fs::write(&dest, bytes).ok()?;
        Some(dest)
    }
}

impl Drop for GitBlobSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn validate_safe_rel_path(rel: &str) -> Option<&Path> {
    if rel.is_empty() {
        return None;
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return None;
    }
    for comp in p.components() {
        if !matches!(comp, Component::Normal(_)) {
            return None;
        }
    }
    Some(p)
}

pub fn run_git_scan(
    scan_paths: &[PathBuf],
    staged: bool,
    git_history: bool,
    max_commits: Option<usize>,
    audit_mcp_and_plugins: bool,
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
) -> GitScanOutput {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let repo_groups = resolve_repo_groups(scan_paths, &cwd);
    if repo_groups.is_empty() {
        let display_hint = scan_paths
            .first()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| cwd.display().to_string());
        eprintln!(
            "[leaktap:warn] `--staged` / `--git-history` requested, but {} is not inside a git repository.",
            display_hint
        );
        return GitScanOutput {
            transcripts: TranscriptScanResult::default(),
            mcp_findings: Vec::new(),
            mcp_files_scanned: 0,
            mcp_bytes_scanned: 0,
            roots: Vec::new(),
        };
    }

    let mut all_hits: Vec<FileHit> = Vec::new();
    let mut touched_files: HashSet<PathBuf> = HashSet::new();
    let mut bytes_scanned = 0u64;
    let mut mcp_findings: Vec<McpFinding> = Vec::new();
    let mut seen_mcp_fp: HashSet<String> = HashSet::new();
    let mut mcp_files_scanned = 0usize;
    let mut mcp_bytes_scanned = 0u64;
    let mut roots = Vec::new();

    let mcp_engine = if audit_mcp_and_plugins {
        Some(RuleEngine::with_policy(false, policy))
    } else {
        None
    };

    for (repo_root, path_filters) in repo_groups {
        if staged {
            roots.push(format!("git:staged ({})", shorten_home(&repo_root)));
            let mut staged_binary_targets: Vec<(Option<String>, String)> = Vec::new();
            stream_unified_diff(
                &repo_root,
                &[
                    "-c",
                    "core.quotePath=false",
                    "diff",
                    "--cached",
                    "--no-color",
                    "--no-ext-diff",
                    "-U0",
                ],
                &path_filters,
                false,
                engine,
                policy,
                &mut bytes_scanned,
                &mut touched_files,
                &mut all_hits,
                &mut staged_binary_targets,
            );
            collect_staged_numstat_binaries(
                &repo_root,
                &path_filters,
                policy,
                &mut staged_binary_targets,
            );
            scan_binary_git_blobs(
                &repo_root,
                &staged_binary_targets,
                false,
                engine,
                &mut bytes_scanned,
                &mut touched_files,
                &mut all_hits,
            );

            if let Some(ref m_engine) = mcp_engine {
                audit_staged_index_configs(
                    &repo_root,
                    &path_filters,
                    m_engine,
                    policy,
                    &mut mcp_findings,
                    &mut seen_mcp_fp,
                    &mut mcp_files_scanned,
                    &mut mcp_bytes_scanned,
                );
            }
        }

        if git_history {
            roots.push(format!("git:history ({})", shorten_home(&repo_root)));
            let mut log_args: Vec<String> = vec![
                "-c".into(),
                "core.quotePath=false".into(),
                "log".into(),
                "--all".into(),
                "-m".into(),
                "-p".into(),
                "--no-color".into(),
                "--no-ext-diff".into(),
                "-U0".into(),
                "--format=LEAKTAP_COMMIT:%h".into(),
            ];
            if let Some(limit) = max_commits {
                log_args.push("-n".into());
                log_args.push(limit.to_string());
            }
            let log_arg_refs: Vec<&str> = log_args.iter().map(String::as_str).collect();
            let mut history_binary_targets: Vec<(Option<String>, String)> = Vec::new();
            stream_unified_diff(
                &repo_root,
                &log_arg_refs,
                &path_filters,
                true,
                engine,
                policy,
                &mut bytes_scanned,
                &mut touched_files,
                &mut all_hits,
                &mut history_binary_targets,
            );
            scan_binary_git_blobs(
                &repo_root,
                &history_binary_targets,
                true,
                engine,
                &mut bytes_scanned,
                &mut touched_files,
                &mut all_hits,
            );

            if let Some(ref m_engine) = mcp_engine {
                audit_history_configs(
                    &repo_root,
                    &path_filters,
                    max_commits,
                    m_engine,
                    policy,
                    &mut mcp_findings,
                    &mut seen_mcp_fp,
                    &mut mcp_files_scanned,
                    &mut mcp_bytes_scanned,
                );
            }
        }
    }

    mcp_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });

    let transcripts = group_git_hits(touched_files.len(), bytes_scanned, all_hits);
    GitScanOutput {
        transcripts,
        mcp_findings,
        mcp_files_scanned,
        mcp_bytes_scanned,
        roots,
    }
}

fn resolve_repo_groups(scan_paths: &[PathBuf], cwd: &Path) -> Vec<(PathBuf, Vec<PathBuf>)> {
    if scan_paths.is_empty() {
        return resolve_git_toplevel(cwd)
            .map(|r| vec![(r, Vec::new())])
            .unwrap_or_default();
    }

    let mut groups: Vec<(PathBuf, PathBuf, Option<Vec<PathBuf>>)> = Vec::new();
    for sp in scan_paths {
        let abs = if sp.is_absolute() {
            sp.clone()
        } else {
            cwd.join(sp)
        };
        let hint = if abs.is_file() {
            abs.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| abs.clone())
        } else {
            abs.clone()
        };
        let Some(repo_root) = resolve_git_toplevel(&hint) else {
            continue;
        };
        let repo_canon = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.clone());
        let filter_canon = abs.canonicalize().unwrap_or(abs);
        let is_whole_repo = filter_canon == repo_canon || filter_canon == repo_root;

        if let Some((_, _, filters_opt)) = groups.iter_mut().find(|(_, rc, _)| *rc == repo_canon) {
            if is_whole_repo {
                *filters_opt = None;
            } else if let Some(ref mut vec) = filters_opt {
                if !vec.contains(&filter_canon) {
                    vec.push(filter_canon);
                }
            }
        } else {
            let filters_opt = if is_whole_repo {
                None
            } else {
                Some(vec![filter_canon])
            };
            groups.push((repo_root, repo_canon, filters_opt));
        }
    }

    groups
        .into_iter()
        .map(|(root, _, filters_opt)| (root, filters_opt.unwrap_or_default()))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn audit_staged_index_configs(
    repo_root: &Path,
    path_filters: &[PathBuf],
    mcp_engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
    mcp_findings: &mut Vec<McpFinding>,
    seen_mcp_fp: &mut HashSet<String>,
    mcp_files_scanned: &mut usize,
    mcp_bytes_scanned: &mut u64,
) {
    let Some(names_bytes) = run_git_bytes(
        repo_root,
        &[
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
        ],
    ) else {
        return;
    };

    let text = String::from_utf8_lossy(&names_bytes);
    let mut candidate_rels = Vec::new();
    let mut candidate_set = HashSet::new();
    let mut staged_non_cfg_rels = HashSet::new();

    for rel in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if has_ignored_diff_component(rel) || validate_safe_rel_path(rel).is_none() {
            continue;
        }
        let full = repo_root.join(rel);
        if !matches_filters(&full, path_filters) {
            continue;
        }
        if policy.is_some_and(|p| p.is_path_ignored(&full)) {
            continue;
        }
        let norm_rel = rel.replace('\\', "/");
        if is_mcp_or_plugin_candidate_relpath(Path::new(&norm_rel)) {
            if candidate_set.insert(norm_rel.clone()) {
                candidate_rels.push(norm_rel);
            }
        } else {
            staged_non_cfg_rels.insert(norm_rel);
        }
    }

    // If a staged commit modifies a local helper script or binary (`scripts/mcp.py`, `bin/hook`)
    // without touching its parent `.mcp.json` or `hooks.json`, find tracked parent configs in the
    // git index that reference any staged path and include them in the staged audit.
    if !staged_non_cfg_rels.is_empty() {
        if let Some(ls_bytes) =
            run_git_bytes(repo_root, &["-c", "core.quotePath=false", "ls-files"])
        {
            let ls_text = String::from_utf8_lossy(&ls_bytes);
            for tracked_rel in ls_text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let norm_cfg = tracked_rel.replace('\\', "/");
                if candidate_set.contains(&norm_cfg)
                    || has_ignored_diff_component(&norm_cfg)
                    || validate_safe_rel_path(&norm_cfg).is_none()
                    || !is_hook_bearing_config_rel(&norm_cfg)
                {
                    continue;
                }
                let full_cfg = repo_root.join(&norm_cfg);
                if policy.is_some_and(|p| p.is_path_ignored(&full_cfg)) {
                    continue;
                }
                let spec = format!(":{norm_cfg}");
                let Some(cfg_blob) =
                    run_git_bytes_capped(repo_root, &["cat-file", "-p", &spec], 2 * 1024 * 1024)
                else {
                    continue;
                };
                let mut refs = extract_companion_script_candidates(&norm_cfg, &cfg_blob);
                let direct_refs = refs.clone();
                for dr in direct_refs {
                    let dr_spec = format!(":{dr}");
                    if let Some(sb) =
                        run_git_bytes_capped(repo_root, &["cat-file", "-p", &dr_spec], 512 * 1024)
                    {
                        for imp in
                            crate::plugin_audit::extract_local_import_candidate_relpaths(&dr, &sb)
                        {
                            if !refs.contains(&imp) {
                                refs.push(imp);
                            }
                        }
                    }
                }
                if refs.iter().any(|r| staged_non_cfg_rels.contains(r))
                    && candidate_set.insert(norm_cfg.clone())
                {
                    candidate_rels.push(norm_cfg);
                }
            }
        }
    }

    if candidate_rels.is_empty() {
        return;
    }

    let Some(sandbox) = GitBlobSandbox::new() else {
        return;
    };
    let mut staged_pairs: Vec<(PathBuf, String)> = Vec::new();
    let mut companion_scripts_loaded: HashSet<String> = HashSet::new();

    for rel in &candidate_rels {
        let spec = format!(":{rel}");
        if let Some(blob_size) = git_blob_size(repo_root, &spec) {
            if blob_size > MAX_GIT_BLOB_AUDIT_BYTES {
                emit_oversized_git_blob_finding(
                    repo_root,
                    rel,
                    blob_size,
                    None,
                    policy,
                    mcp_findings,
                    seen_mcp_fp,
                );
                *mcp_files_scanned += 1;
                continue;
            }
        }
        let Some(blob) = run_git_bytes_capped(
            repo_root,
            &["cat-file", "-p", &spec],
            MAX_GIT_BINARY_SCAN_BYTES as usize,
        ) else {
            continue;
        };
        if let Some(disk_path) = sandbox.write_rel_blob(&sandbox.root, rel, &blob) {
            *mcp_bytes_scanned += blob.len() as u64;
            companion_scripts_loaded.insert(rel.clone());
            // Materialize any relative hook/MCP handler scripts or binaries from the git index
            if is_hook_bearing_config_rel(rel) {
                materialize_companion_hook_scripts(
                    repo_root,
                    "",
                    rel,
                    &blob,
                    &sandbox,
                    &sandbox.root,
                    &mut companion_scripts_loaded,
                );
            }
            staged_pairs.push((disk_path, rel.clone()));
        }
    }

    for (disk_path, rel) in staged_pairs {
        let logical_path = repo_root.join(&rel);
        let classified = discover_targets_with_policy(std::slice::from_ref(&disk_path), true, None);
        let mut audited_this_file = false;
        for mf in &classified.mcp_config_files {
            audited_this_file = true;
            for f in audit_mcp_file_as_with_roots(
                mf,
                &logical_path,
                None,
                Some((&sandbox.root, repo_root)),
                mcp_engine,
                policy,
            ) {
                if seen_mcp_fp.insert(f.fingerprint.clone()) {
                    mcp_findings.push(f);
                }
            }
        }
        for pf in &classified.plugin_files {
            audited_this_file = true;
            for f in audit_plugin_file_as(
                pf,
                &logical_path,
                None,
                Some((&sandbox.root, repo_root)),
                mcp_engine,
                policy,
            ) {
                if seen_mcp_fp.insert(f.fingerprint.clone()) {
                    mcp_findings.push(f);
                }
            }
        }
        if audited_this_file {
            *mcp_files_scanned += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_history_configs(
    repo_root: &Path,
    path_filters: &[PathBuf],
    max_commits: Option<usize>,
    mcp_engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
    mcp_findings: &mut Vec<McpFinding>,
    seen_mcp_fp: &mut HashSet<String>,
    mcp_files_scanned: &mut usize,
    mcp_bytes_scanned: &mut u64,
) {
    // Seed referenced helper script -> parent config map from HEAD so commits within `--max-commits`
    // that modify a helper script whose `.mcp.json` / `hooks.json` was added in an older commit are caught.
    let mut script_to_configs: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut inspected_cfg_blobs: HashSet<String> = HashSet::new();
    if let Some(head_tree) = run_git_bytes(
        repo_root,
        &[
            "-c",
            "core.quotePath=false",
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
        ],
    ) {
        let head_text = String::from_utf8_lossy(&head_tree);
        for tracked_rel in head_text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let norm_cfg = tracked_rel.replace('\\', "/");
            if has_ignored_diff_component(&norm_cfg)
                || validate_safe_rel_path(&norm_cfg).is_none()
                || !is_hook_bearing_config_rel(&norm_cfg)
            {
                continue;
            }
            let spec = format!("HEAD:{norm_cfg}");
            if let Some(cfg_blob) =
                run_git_bytes_capped(repo_root, &["cat-file", "-p", &spec], 2 * 1024 * 1024)
            {
                let mut refs = extract_companion_script_candidates(&norm_cfg, &cfg_blob);
                let direct_refs = refs.clone();
                for dr in direct_refs {
                    let dr_spec = format!("HEAD:{dr}");
                    if let Some(sb) =
                        run_git_bytes_capped(repo_root, &["cat-file", "-p", &dr_spec], 512 * 1024)
                    {
                        for imp in
                            crate::plugin_audit::extract_local_import_candidate_relpaths(&dr, &sb)
                        {
                            if !refs.contains(&imp) {
                                refs.push(imp);
                            }
                        }
                    }
                }
                for cand_rel in refs {
                    script_to_configs
                        .entry(cand_rel)
                        .or_default()
                        .insert(norm_cfg.clone());
                }
            }
        }
    }

    let mut raw_args: Vec<String> = vec![
        "-c".into(),
        "core.quotePath=false".into(),
        "log".into(),
        "--all".into(),
        "-m".into(),
        "--raw".into(),
        "--no-abbrev".into(),
        "--diff-filter=AMR".into(),
        "--format=LEAKTAP_COMMIT:%h".into(),
    ];
    if let Some(limit) = max_commits {
        raw_args.push("-n".into());
        raw_args.push(limit.to_string());
    }
    let raw_arg_refs: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    let Ok(mut child) = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(&raw_arg_refs)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.wait();
        return;
    };

    let mut reader = BufReader::with_capacity(64 * 1024, stdout);
    let mut line_buf = Vec::with_capacity(1024);
    let mut current_commit = String::new();
    let mut seen_blobs: HashSet<(String, String)> = HashSet::new();
    let mut entries: Vec<(String, String, String)> = Vec::new();
    let mut touched_non_cfg: Vec<(String, String, String)> = Vec::new();

    while let Ok(n) = read_line_bounded(&mut reader, &mut line_buf, 64 * 1024) {
        if n == 0 {
            break;
        }
        let raw_line = String::from_utf8_lossy(&line_buf);
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if let Some(sha) = line.strip_prefix("LEAKTAP_COMMIT:") {
            current_commit = sha.trim().to_string();
            continue;
        }
        if !line.starts_with(':') || current_commit.is_empty() {
            continue;
        }
        let mut tab_parts = line.split('\t');
        let Some(meta_part) = tab_parts.next() else {
            continue;
        };
        let Some(rel) = tab_parts.next_back() else {
            continue;
        };
        let meta_tokens: Vec<&str> = meta_part.split_whitespace().collect();
        if meta_tokens.len() < 5 {
            continue;
        }
        let new_mode = meta_tokens[1];
        if new_mode == "120000" || new_mode == "160000" {
            continue;
        }
        let new_blob_sha = meta_tokens[3];
        if new_blob_sha.chars().all(|c| c == '0') {
            continue;
        }
        if has_ignored_diff_component(rel) || validate_safe_rel_path(rel).is_none() {
            continue;
        }
        let norm_rel = rel.replace('\\', "/");
        let full = repo_root.join(&norm_rel);
        if !matches_filters(&full, path_filters) {
            continue;
        }
        if policy.is_some_and(|p| p.is_path_ignored(&full)) {
            continue;
        }
        if !is_mcp_or_plugin_candidate_relpath(Path::new(&norm_rel)) {
            if touched_non_cfg.len() < MAX_HISTORICAL_CONFIG_BLOBS {
                touched_non_cfg.push((current_commit.clone(), new_blob_sha.to_string(), norm_rel));
            }
            continue;
        }
        if is_hook_bearing_config_rel(&norm_rel)
            && inspected_cfg_blobs.len() < 512
            && inspected_cfg_blobs.insert(new_blob_sha.to_string())
        {
            if let Some(cfg_blob) = run_git_bytes_capped(
                repo_root,
                &["cat-file", "-p", new_blob_sha],
                2 * 1024 * 1024,
            ) {
                for cand_rel in extract_companion_script_candidates(&norm_rel, &cfg_blob) {
                    script_to_configs
                        .entry(cand_rel)
                        .or_default()
                        .insert(norm_rel.clone());
                }
            }
        }
        if seen_blobs.insert((new_blob_sha.to_string(), norm_rel.clone())) {
            entries.push((current_commit.clone(), new_blob_sha.to_string(), norm_rel));
            if entries.len() >= MAX_HISTORICAL_CONFIG_BLOBS {
                eprintln!(
                    "[leaktap:warn] Reached historical config blob cap ({MAX_HISTORICAL_CONFIG_BLOBS}) in {}; pass `--max-commits` to scope history windows.",
                    shorten_home(repo_root)
                );
                let _ = child.kill();
                break;
            }
        }
    }
    drop(reader);
    let _ = child.wait();

    // Enqueue historical commits where a referenced helper script/binary was modified even though
    // its parent `.mcp.json` / `hooks.json` was unchanged in that commit.
    if !script_to_configs.is_empty() {
        for (commit_sha, script_blob_sha, script_rel) in touched_non_cfg {
            if entries.len() >= MAX_HISTORICAL_CONFIG_BLOBS {
                break;
            }
            let Some(parent_cfgs) = script_to_configs.get(&script_rel) else {
                continue;
            };
            for cfg_rel in parent_cfgs {
                let full_cfg = repo_root.join(cfg_rel);
                if policy.is_some_and(|p| p.is_path_ignored(&full_cfg)) {
                    continue;
                }
                let spec = format!("{commit_sha}:{cfg_rel}");
                let Some(rev_bytes) = run_git_bytes(repo_root, &["rev-parse", "--verify", &spec])
                else {
                    continue;
                };
                let cfg_blob_sha = String::from_utf8_lossy(&rev_bytes).trim().to_string();
                if cfg_blob_sha.is_empty() {
                    continue;
                }
                let dedup_key = format!("{cfg_blob_sha}+{script_blob_sha}");
                if seen_blobs.insert((dedup_key, cfg_rel.clone())) {
                    entries.push((commit_sha.clone(), cfg_blob_sha, cfg_rel.clone()));
                }
            }
        }
    }

    if entries.is_empty() {
        return;
    }

    let Some(sandbox) = GitBlobSandbox::new() else {
        return;
    };

    for (idx, (commit_sha, blob_sha, rel)) in entries.into_iter().enumerate() {
        if let Some(blob_size) = git_blob_size(repo_root, &blob_sha) {
            if blob_size > MAX_GIT_BLOB_AUDIT_BYTES {
                emit_oversized_git_blob_finding(
                    repo_root,
                    &rel,
                    blob_size,
                    Some(&commit_sha),
                    policy,
                    mcp_findings,
                    seen_mcp_fp,
                );
                *mcp_files_scanned += 1;
                continue;
            }
        }
        let Some(blob) = run_git_bytes_capped(
            repo_root,
            &["cat-file", "-p", &blob_sha],
            MAX_GIT_BINARY_SCAN_BYTES as usize,
        ) else {
            continue;
        };
        let sub_root = sandbox.root.join(format!("c{idx}"));
        let Some(disk_path) = sandbox.write_rel_blob(&sub_root, &rel, &blob) else {
            continue;
        };
        *mcp_bytes_scanned += blob.len() as u64;

        if is_hook_bearing_config_rel(&rel) {
            let mut loaded = HashSet::new();
            loaded.insert(rel.clone());
            materialize_companion_hook_scripts(
                repo_root,
                &commit_sha,
                &rel,
                &blob,
                &sandbox,
                &sub_root,
                &mut loaded,
            );
        }

        let logical_path = repo_root.join(&rel);
        let git_disp = format!("git:{commit_sha}:{rel}");
        let classified = discover_targets_with_policy(std::slice::from_ref(&disk_path), true, None);
        let mut audited_this_file = false;
        for mf in &classified.mcp_config_files {
            audited_this_file = true;
            for f in audit_mcp_file_as_with_roots(
                mf,
                &logical_path,
                Some(&git_disp),
                Some((&sub_root, repo_root)),
                mcp_engine,
                policy,
            ) {
                if seen_mcp_fp.insert(f.fingerprint.clone()) {
                    mcp_findings.push(f);
                }
            }
        }
        for pf in &classified.plugin_files {
            audited_this_file = true;
            for f in audit_plugin_file_as(
                pf,
                &logical_path,
                Some(&commit_sha),
                Some((&sub_root, repo_root)),
                mcp_engine,
                policy,
            ) {
                if seen_mcp_fp.insert(f.fingerprint.clone()) {
                    mcp_findings.push(f);
                }
            }
        }
        if audited_this_file {
            *mcp_files_scanned += 1;
        }
        let _ = fs::remove_dir_all(&sub_root);
    }
}

fn is_hook_bearing_config_rel(rel: &str) -> bool {
    Path::new(rel)
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "hooks.json"
                    | "settings.json"
                    | "settings.local.json"
                    | "tasks.json"
                    | "devcontainer.json"
                    | ".devcontainer.json"
                    | "package.json"
                    | ".mcp.json"
                    | "mcp.json"
                    | "mcp_config.json"
                    | "claude_desktop_config.json"
                    | "cline_mcp_settings.json"
                    | "roo_mcp_settings.json"
                    | ".claude.json"
                    | "config.toml"
            )
        })
}

fn extract_companion_script_candidates(config_rel: &str, config_blob: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(config_blob);
    let config_dir = Path::new(config_rel)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let plugin_root = if config_dir.file_name().and_then(|s| s.to_str()) == Some("hooks") {
        config_dir.parent().unwrap_or(config_dir)
    } else {
        config_dir
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for raw_tok in text.split(['"', '\'', ' ', '\t', '\n', '\r', ';', '&', '|', ',']) {
        let tok = raw_tok.trim();
        if tok.is_empty() || tok.len() > 240 || tok.contains("://") || tok.starts_with('-') {
            continue;
        }
        let norm_tok = tok.replace('\\', "/");
        let stripped = norm_tok
            .strip_prefix("${CLAUDE_PLUGIN_ROOT}/")
            .or_else(|| norm_tok.strip_prefix("$CLAUDE_PLUGIN_ROOT/"))
            .or_else(|| {
                norm_tok
                    .strip_prefix("${PLUGIN_ROOT}/")
                    .or_else(|| norm_tok.strip_prefix("$PLUGIN_ROOT/"))
            })
            .or_else(|| norm_tok.strip_prefix("${CLAUDE_PROJECT_DIR}/"))
            .or_else(|| norm_tok.strip_prefix("$CLAUDE_PROJECT_DIR/"))
            .or_else(|| norm_tok.strip_prefix("${PROJECT_DIR}/"))
            .or_else(|| norm_tok.strip_prefix("$PROJECT_DIR/"))
            .or_else(|| norm_tok.strip_prefix("${workspaceFolder}/"))
            .or_else(|| norm_tok.strip_prefix("$workspaceFolder/"))
            .or_else(|| norm_tok.strip_prefix("${WORKSPACE_FOLDER}/"))
            .or_else(|| norm_tok.strip_prefix("$WORKSPACE_FOLDER/"))
            .or_else(|| norm_tok.strip_prefix("${extensionPath}/"))
            .or_else(|| norm_tok.strip_prefix("${PWD}/"))
            .or_else(|| norm_tok.strip_prefix("$PWD/"))
            .or_else(|| norm_tok.strip_prefix("./"))
            .unwrap_or(&norm_tok);

        let had_path_prefix = stripped != norm_tok || stripped.contains('/');
        let has_known_ext = Path::new(stripped)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .is_some_and(|ext| {
                matches!(
                    ext.as_str(),
                    "sh" | "bash"
                        | "zsh"
                        | "py"
                        | "js"
                        | "mjs"
                        | "cjs"
                        | "ts"
                        | "tsx"
                        | "jsx"
                        | "rb"
                        | "pl"
                        | "php"
                        | "lua"
                        | "ps1"
                        | "cmd"
                        | "bat"
                        | "exe"
                        | "dll"
                        | "so"
                        | "dylib"
                        | "node"
                        | "wasm"
                )
            });
        if !had_path_prefix && !has_known_ext {
            continue;
        }

        let mut candidate_rels = vec![stripped.to_string()];
        if !config_dir.as_os_str().is_empty() {
            candidate_rels.push(config_dir.join(stripped).to_string_lossy().into_owned());
        }
        if !plugin_root.as_os_str().is_empty() {
            candidate_rels.push(plugin_root.join(stripped).to_string_lossy().into_owned());
        }

        for cand in candidate_rels {
            let norm = cand.replace('\\', "/");
            if validate_safe_rel_path(&norm).is_some() && seen.insert(norm.clone()) {
                out.push(norm);
                if out.len() >= 64 {
                    return out;
                }
            }
        }
    }
    out
}

fn materialize_companion_hook_scripts(
    repo_root: &Path,
    commit_prefix: &str,
    config_rel: &str,
    config_blob: &[u8],
    sandbox: &GitBlobSandbox,
    sub_root: &Path,
    loaded: &mut HashSet<String>,
) {
    let mut queue: std::collections::VecDeque<(String, usize)> =
        extract_companion_script_candidates(config_rel, config_blob)
            .into_iter()
            .map(|r| (r, 0usize))
            .collect();

    while let Some((norm, hop)) = queue.pop_front() {
        if !loaded.insert(norm.clone()) {
            continue;
        }
        let spec = if commit_prefix.is_empty() {
            format!(":{norm}")
        } else {
            format!("{commit_prefix}:{norm}")
        };
        if let Some(sz) = git_blob_size(repo_root, &spec) {
            if sz <= MAX_GIT_BINARY_SCAN_BYTES {
                if let Some(script_bytes) = run_git_bytes_capped(
                    repo_root,
                    &["cat-file", "-p", &spec],
                    MAX_GIT_BINARY_SCAN_BYTES as usize,
                ) {
                    let _ = sandbox.write_rel_blob(sub_root, &norm, &script_bytes);
                    if hop < 2 && script_bytes.len() <= 2 * 1024 * 1024 {
                        for imp_rel in crate::plugin_audit::extract_local_import_candidate_relpaths(
                            &norm,
                            &script_bytes,
                        ) {
                            if validate_safe_rel_path(&imp_rel).is_some()
                                && !loaded.contains(&imp_rel)
                            {
                                queue.push_back((imp_rel, hop + 1));
                            }
                        }
                    }
                }
            }
        }
        if loaded.len() >= 64 {
            return;
        }
    }
}

fn git_blob_size(repo_root: &Path, spec: &str) -> Option<u64> {
    let out = run_git_bytes(repo_root, &["cat-file", "-s", spec])?;
    String::from_utf8_lossy(&out).trim().parse::<u64>().ok()
}

fn emit_oversized_git_blob_finding(
    repo_root: &Path,
    rel: &str,
    blob_size: u64,
    commit_sha: Option<&str>,
    policy: Option<&PolicyConfig>,
    mcp_findings: &mut Vec<McpFinding>,
    seen_mcp_fp: &mut HashSet<String>,
) {
    let logical_path = repo_root.join(rel);
    let fp_display = shorten_home(&logical_path);
    let file_name = logical_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let is_mcp = matches!(
        file_name,
        ".mcp.json"
            | "mcp.json"
            | "mcp_config.json"
            | "claude_desktop_config.json"
            | "cline_mcp_settings.json"
            | "roo_mcp_settings.json"
            | ".claude.json"
            | "config.toml"
    );
    let rule_id = if is_mcp {
        "mcp-oversized-config"
    } else {
        "plugin-oversized-config"
    };
    let fp = crate::rules::fingerprint_match(rule_id, &fp_display);
    if policy.is_some_and(|p| {
        p.is_rule_disabled_for(rule_id, Some(&logical_path))
            || p.is_fingerprint_ignored_for(&fp, Some(&logical_path))
    }) {
        return;
    }
    let config_file = commit_sha
        .map(|sha| format!("git:{sha}:{rel}"))
        .unwrap_or(fp_display);
    if seen_mcp_fp.insert(fp.clone()) {
        mcp_findings.push(McpFinding {
            rule_id,
            server_name: "git-blob".to_string(),
            config_file,
            config_path: logical_path,
            line: 1,
            severity: crate::rules::Severity::High,
            fingerprint: fp,
            message: format!(
                "Staged or historical config blob exceeds 16 MiB ({:.1} MiB > 16.0 MiB AST limit)",
                blob_size as f64 / (1024.0 * 1024.0)
            ),
        });
    }
}

fn resolve_git_toplevel(dir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn run_git_bytes(repo_root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

fn matches_filters(file_path: &Path, filters: &[PathBuf]) -> bool {
    if filters.is_empty() {
        return true;
    }
    let canon = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.to_path_buf());
    filters
        .iter()
        .any(|f| canon == *f || canon.starts_with(f) || file_path.starts_with(f))
}

fn has_ignored_diff_component(rel_path: &str) -> bool {
    Path::new(rel_path).components().any(|c| {
        if let Component::Normal(os) = c {
            let s = os.to_string_lossy();
            IGNORED_DIFF_DIRS.contains(&s.as_ref())
        } else {
            false
        }
    })
}

fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<usize> {
    out.clear();
    let mut total = 0usize;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(total);
        }
        if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let take_len = nl + 1;
            if out.len() < max_bytes {
                let copy_len = take_len.min(max_bytes - out.len());
                out.extend_from_slice(&buf[..copy_len]);
            }
            reader.consume(take_len);
            total += take_len;
            return Ok(total);
        }
        let avail = buf.len();
        if out.len() < max_bytes {
            let copy_len = avail.min(max_bytes - out.len());
            out.extend_from_slice(&buf[..copy_len]);
        }
        reader.consume(avail);
        total += avail;
    }
}

fn collect_staged_numstat_binaries(
    repo_root: &Path,
    path_filters: &[PathBuf],
    policy: Option<&PolicyConfig>,
    out: &mut Vec<(Option<String>, String)>,
) {
    let Some(bytes) = run_git_bytes(
        repo_root,
        &[
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--numstat",
            "--diff-filter=ACMR",
        ],
    ) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let Some(rel) = line.strip_prefix("-\t-\t") else {
            continue;
        };
        let rel = rel.trim();
        if rel.is_empty()
            || has_ignored_diff_component(rel)
            || validate_safe_rel_path(rel).is_none()
        {
            continue;
        }
        let abs = repo_root.join(rel);
        if !matches_filters(&abs, path_filters) || policy.is_some_and(|p| p.is_path_ignored(&abs)) {
            continue;
        }
        if !out.iter().any(|(_, r)| r == rel) {
            out.push((None, rel.to_string()));
        }
    }
}

fn run_git_bytes_capped(repo_root: &Path, args: &[&str], max_bytes: usize) -> Option<Vec<u8>> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut exceeded = false;
    loop {
        match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > max_bytes {
                    exceeded = true;
                    let _ = child.kill();
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                exceeded = true;
                let _ = child.kill();
                break;
            }
        }
    }
    drop(stdout);
    let status = child.wait().ok()?;
    if exceeded || !status.success() {
        return None;
    }
    Some(buf)
}

fn scan_binary_git_blobs(
    repo_root: &Path,
    targets: &[(Option<String>, String)],
    include_commit_prefix: bool,
    engine: &RuleEngine,
    bytes_scanned: &mut u64,
    touched_files: &mut HashSet<PathBuf>,
    hits: &mut Vec<FileHit>,
) {
    if targets.is_empty() {
        return;
    }
    let Some(sandbox) = GitBlobSandbox::new() else {
        return;
    };
    let mut seen: HashSet<(Option<String>, String)> = HashSet::new();
    for (idx, (commit_opt, rel)) in targets.iter().enumerate() {
        if !seen.insert((commit_opt.clone(), rel.clone())) {
            continue;
        }
        let spec = match commit_opt {
            Some(sha) => format!("{sha}:{rel}"),
            None => format!(":{rel}"),
        };
        let Some(blob_size) = git_blob_size(repo_root, &spec) else {
            continue;
        };
        if blob_size == 0 || blob_size > MAX_GIT_BINARY_SCAN_BYTES {
            continue;
        }
        let Some(blob) = run_git_bytes_capped(
            repo_root,
            &["cat-file", "-p", &spec],
            MAX_GIT_BINARY_SCAN_BYTES as usize,
        ) else {
            continue;
        };
        let sub_dir = sandbox.root.join(format!("bin{idx}"));
        if let Some(disk_path) = sandbox.write_rel_blob(&sub_dir, rel, &blob) {
            let logical_path = repo_root.join(rel);
            let disp = format_display_file(rel, commit_opt.as_deref(), include_commit_prefix);
            if let Some((b_len, file_hits)) =
                scan_single_file_as(&disk_path, &logical_path, Some(&disp), engine)
            {
                *bytes_scanned += b_len;
                touched_files.insert(logical_path);
                hits.extend(file_hits);
            }
        }
        let _ = fs::remove_dir_all(&sub_dir);
    }
}

#[derive(Clone, Copy)]
enum DiffBlockKind {
    Pem,
    Putty,
    YamlScalar(usize),
    Hexdump,
}

#[allow(clippy::too_many_arguments)]
fn stream_unified_diff(
    repo_root: &Path,
    git_args: &[&str],
    path_filters: &[PathBuf],
    include_commit_prefix: bool,
    engine: &RuleEngine,
    policy: Option<&PolicyConfig>,
    bytes_scanned: &mut u64,
    touched_files: &mut HashSet<PathBuf>,
    hits: &mut Vec<FileHit>,
    binary_targets: &mut Vec<(Option<String>, String)>,
) {
    let Ok(mut child) = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(git_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.wait();
        return;
    };

    let mut reader = BufReader::with_capacity(128 * 1024, stdout);
    let mut line_buf = Vec::with_capacity(4096);

    let mut current_commit: Option<String> = None;
    let mut current_rel_file: Option<String> = None;
    let mut current_abs_file: Option<PathBuf> = None;
    let mut current_doc_hints = crate::rules::DocHints::default();
    let mut current_checked_doc_blob = false;
    let mut current_blob_text: Option<String> = None;
    let mut k8s_tracker = crate::rules::K8sDataTracker::default();
    let mut skip_current_file = false;
    let mut in_hunk = false;
    let mut current_new_line: usize = 1;
    let mut warned_binary_cap = false;
    let mut pending_diff_ignore: Option<(usize, crate::rules::InlineIgnoreSpec)> = None;

    let mut block_buf = String::new();
    let mut block_start_line = 1usize;
    let mut active_block: Option<DiffBlockKind> = None;

    let mut b64_buf = String::new();
    let mut b64_start_line = 1usize;
    let mut b64_lines = 0usize;

    let flush_multiline = |block_buf: &mut String,
                           active_block: &mut Option<DiffBlockKind>,
                           block_start_line: usize,
                           b64_buf: &mut String,
                           b64_lines: &mut usize,
                           b64_start_line: usize,
                           doc_hints: crate::rules::DocHints,
                           abs_file: &Option<PathBuf>,
                           rel_file: &Option<String>,
                           commit: &Option<String>,
                           hits: &mut Vec<FileHit>| {
        if active_block.is_some() && !block_buf.is_empty() {
            if let (Some(abs), Some(rel)) = (abs_file, rel_file) {
                let disp = format_display_file(rel, commit.as_deref(), include_commit_prefix);
                for m in engine.scan_text_with_hints(block_buf, Some(abs), doc_hints) {
                    let (rel_line, col) = compute_line_and_column(block_buf, 1, m.start);
                    hits.push(FileHit {
                        file: abs.clone(),
                        display_file: disp.clone(),
                        line: block_start_line + rel_line.saturating_sub(1),
                        column: col,
                        rule_id: m.rule_id,
                        rule_name: m.rule_name,
                        secret_key: m.secret_key,
                        severity: m.severity,
                        category: m.category,
                        masked: m.masked,
                        fingerprint: m.fingerprint,
                    });
                }
            }
            block_buf.clear();
            *active_block = None;
        }
        if *b64_lines >= 2 && b64_buf.len() >= 28 {
            if let (Some(abs), Some(rel)) = (abs_file, rel_file) {
                let disp = format_display_file(rel, commit.as_deref(), include_commit_prefix);
                for m in engine.scan_text_with_hints(b64_buf, Some(abs), doc_hints) {
                    let (_, col) = compute_line_and_column(b64_buf, 1, m.start);
                    hits.push(FileHit {
                        file: abs.clone(),
                        display_file: disp.clone(),
                        line: b64_start_line,
                        column: col,
                        rule_id: m.rule_id,
                        rule_name: m.rule_name,
                        secret_key: m.secret_key,
                        severity: m.severity,
                        category: m.category,
                        masked: m.masked,
                        fingerprint: m.fingerprint,
                    });
                }
            }
        }
        b64_buf.clear();
        *b64_lines = 0;
    };

    while let Ok(read_n) = read_line_bounded(&mut reader, &mut line_buf, MAX_DIFF_LINE_BYTES) {
        if read_n == 0 {
            break;
        }
        *bytes_scanned += read_n as u64;
        let raw_cow = String::from_utf8_lossy(&line_buf);
        let line = raw_cow.trim_end_matches(['\r', '\n']);

        if let Some(sha) = line.strip_prefix("LEAKTAP_COMMIT:") {
            flush_multiline(
                &mut block_buf,
                &mut active_block,
                block_start_line,
                &mut b64_buf,
                &mut b64_lines,
                b64_start_line,
                current_doc_hints,
                &current_abs_file,
                &current_rel_file,
                &current_commit,
                hits,
            );
            current_commit = Some(sha.trim().to_string());
            current_rel_file = None;
            current_abs_file = None;
            current_doc_hints = crate::rules::DocHints::default();
            current_checked_doc_blob = false;
            current_blob_text = None;
            k8s_tracker = crate::rules::K8sDataTracker::default();
            in_hunk = false;
            continue;
        }

        if line.starts_with("diff --git ") {
            flush_multiline(
                &mut block_buf,
                &mut active_block,
                block_start_line,
                &mut b64_buf,
                &mut b64_lines,
                b64_start_line,
                current_doc_hints,
                &current_abs_file,
                &current_rel_file,
                &current_commit,
                hits,
            );
            current_rel_file = None;
            current_abs_file = None;
            current_doc_hints = crate::rules::DocHints::default();
            current_checked_doc_blob = false;
            current_blob_text = None;
            k8s_tracker = crate::rules::K8sDataTracker::default();
            skip_current_file = false;
            in_hunk = false;
            continue;
        }

        if !in_hunk {
            if let Some(rest) = line.strip_prefix("Binary files ") {
                if let Some(without_differ) = rest.strip_suffix(" differ") {
                    if let Some((_, rhs)) = without_differ.rsplit_once(" and ") {
                        if rhs != "/dev/null" {
                            let rel = rhs.strip_prefix("b/").unwrap_or(rhs);
                            let abs = repo_root.join(rel);
                            let allowed = !has_ignored_diff_component(rel)
                                && validate_safe_rel_path(rel).is_some()
                                && matches_filters(&abs, path_filters)
                                && !policy.is_some_and(|p| p.is_path_ignored(&abs));
                            if allowed {
                                if !include_commit_prefix
                                    || binary_targets.len() < MAX_HISTORICAL_BINARY_BLOBS
                                {
                                    binary_targets.push((current_commit.clone(), rel.to_string()));
                                } else if !warned_binary_cap {
                                    eprintln!(
                                        "[leaktap:warn] Reached historical binary blob cap ({MAX_HISTORICAL_BINARY_BLOBS}) in {}; pass `--max-commits` to scope history windows.",
                                        shorten_home(repo_root)
                                    );
                                    warned_binary_cap = true;
                                }
                            }
                        }
                    }
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("+++ ") {
                current_doc_hints = crate::rules::DocHints::default();
                current_checked_doc_blob = false;
                current_blob_text = None;
                k8s_tracker = crate::rules::K8sDataTracker::default();
                pending_diff_ignore = None;
                if rest == "/dev/null" {
                    current_rel_file = None;
                    current_abs_file = None;
                    skip_current_file = true;
                } else {
                    let rel = rest.strip_prefix("b/").unwrap_or(rest).to_string();
                    let abs = repo_root.join(&rel);
                    skip_current_file = has_ignored_diff_component(&rel)
                        || !matches_filters(&abs, path_filters)
                        || policy.is_some_and(|p| p.is_path_ignored(&abs));
                    if !skip_current_file {
                        touched_files.insert(abs.clone());
                    }
                    current_rel_file = Some(rel);
                    current_abs_file = Some(abs);
                }
                continue;
            }
        }

        if line.starts_with("@@ ") {
            flush_multiline(
                &mut block_buf,
                &mut active_block,
                block_start_line,
                &mut b64_buf,
                &mut b64_lines,
                b64_start_line,
                current_doc_hints,
                &current_abs_file,
                &current_rel_file,
                &current_commit,
                hits,
            );
            in_hunk = true;
            current_new_line = parse_hunk_new_start(line).unwrap_or(1);
            if !skip_current_file {
                if let Some(ref rel) = current_rel_file {
                    let lower_rel = rel.to_ascii_lowercase();
                    let is_structured_manifest = lower_rel.ends_with(".yaml")
                        || lower_rel.ends_with(".yml")
                        || lower_rel.ends_with(".json");
                    if is_structured_manifest && !current_checked_doc_blob {
                        current_checked_doc_blob = true;
                        let spec = match &current_commit {
                            Some(sha) => format!("{sha}:{rel}"),
                            None => format!(":{rel}"),
                        };
                        if let Some(blob) =
                            run_git_bytes_capped(repo_root, &["cat-file", "-p", &spec], 512 * 1024)
                        {
                            let blob_str = String::from_utf8_lossy(&blob).into_owned();
                            current_doc_hints = current_doc_hints
                                .merge(crate::rules::DocHints::from_text(&blob_str));
                            if contains_gcp_sa_markers(&blob_str) {
                                current_doc_hints.has_gcp_sa = true;
                            }
                            current_blob_text = Some(blob_str);
                        }
                    }
                }
                if let Some(ref blob_str) = current_blob_text {
                    k8s_tracker = crate::rules::K8sDataTracker::default();
                    for prev_line in blob_str.lines().take(current_new_line.saturating_sub(1)) {
                        let _ = k8s_tracker.observe_line(prev_line);
                    }
                }
            }
            continue;
        }

        if !in_hunk || skip_current_file {
            continue;
        }

        if let Some(added) = line.strip_prefix('+') {
            let line_no = current_new_line;
            current_new_line += 1;

            let Some(ref abs) = current_abs_file else {
                continue;
            };
            let Some(ref rel) = current_rel_file else {
                continue;
            };
            let disp = format_display_file(rel, current_commit.as_deref(), include_commit_prefix);

            current_doc_hints = current_doc_hints.merge(crate::rules::DocHints::from_text(added));
            if contains_gcp_sa_markers(added) {
                current_doc_hints.has_gcp_sa = true;
            }
            if !current_checked_doc_blob
                && (added.contains("\"private_key_id\"")
                    || added.contains("\"kty\"")
                    || added.contains("\"d\"")
                    || added.contains("\"k\"")
                    || added.contains("Secret")
                    || added.contains("data:")
                    || added.contains("stringData:")
                    || added.contains("\"data\""))
            {
                current_checked_doc_blob = true;
                let spec = match &current_commit {
                    Some(sha) => format!("{sha}:{rel}"),
                    None => format!(":{rel}"),
                };
                if let Some(blob) =
                    run_git_bytes_capped(repo_root, &["cat-file", "-p", &spec], 512 * 1024)
                {
                    let blob_str = String::from_utf8_lossy(&blob).into_owned();
                    current_doc_hints =
                        current_doc_hints.merge(crate::rules::DocHints::from_text(&blob_str));
                    if contains_gcp_sa_markers(&blob_str) {
                        current_doc_hints.has_gcp_sa = true;
                    }
                    k8s_tracker = crate::rules::K8sDataTracker::default();
                    for prev_line in blob_str.lines().take(line_no.saturating_sub(1)) {
                        let _ = k8s_tracker.observe_line(prev_line);
                    }
                    current_blob_text = Some(blob_str);
                }
            }

            let mut line_hints = current_doc_hints;
            if line_hints.is_k8s_secret_manifest
                || k8s_tracker.is_tracking()
                || added.contains("kind:")
                || added.contains("\"kind\"")
            {
                let (in_d, in_sd) = k8s_tracker.observe_line(added);
                line_hints.in_k8s_data_entry = in_d;
                line_hints.in_k8s_string_data_entry = in_sd;
                line_hints.is_k8s_secret_manifest =
                    k8s_tracker.is_active_secret_doc(line_hints.is_k8s_secret_manifest);
            }

            if let Some(kind) = active_block {
                let continues = match kind {
                    DiffBlockKind::Pem => is_pem_or_pgp_continuation_line(added.as_bytes()),
                    DiffBlockKind::Putty => is_putty_continuation_line(added.as_bytes()),
                    DiffBlockKind::YamlScalar(indent) => {
                        is_yaml_block_scalar_continuation(added.as_bytes(), indent)
                    }
                    DiffBlockKind::Hexdump => crate::rules::is_hexdump_line(added),
                };
                if continues {
                    block_buf.push_str(added);
                    block_buf.push('\n');
                    let finished = match kind {
                        DiffBlockKind::Pem => added.contains("-----END "),
                        DiffBlockKind::Putty => {
                            added.contains("Private-MAC:") || added.contains("Private-Hash:")
                        }
                        DiffBlockKind::YamlScalar(_) | DiffBlockKind::Hexdump => false,
                    };
                    if finished || block_buf.len() > 32 * 1024 {
                        flush_multiline(
                            &mut block_buf,
                            &mut active_block,
                            block_start_line,
                            &mut b64_buf,
                            &mut b64_lines,
                            b64_start_line,
                            line_hints,
                            &current_abs_file,
                            &current_rel_file,
                            &current_commit,
                            hits,
                        );
                    }
                    continue;
                } else {
                    flush_multiline(
                        &mut block_buf,
                        &mut active_block,
                        block_start_line,
                        &mut b64_buf,
                        &mut b64_lines,
                        b64_start_line,
                        line_hints,
                        &current_abs_file,
                        &current_rel_file,
                        &current_commit,
                        hits,
                    );
                }
            }

            if active_block.is_none() {
                if is_pem_header_line(added) {
                    active_block = Some(DiffBlockKind::Pem);
                    block_start_line = line_no;
                    block_buf.clear();
                    block_buf.push_str(added);
                    block_buf.push('\n');
                    if added.contains("-----END ") {
                        flush_multiline(
                            &mut block_buf,
                            &mut active_block,
                            block_start_line,
                            &mut b64_buf,
                            &mut b64_lines,
                            b64_start_line,
                            line_hints,
                            &current_abs_file,
                            &current_rel_file,
                            &current_commit,
                            hits,
                        );
                    }
                    continue;
                } else if is_multiline_putty_header(added.as_bytes()) {
                    active_block = Some(DiffBlockKind::Putty);
                    block_start_line = line_no;
                    block_buf.clear();
                    block_buf.push_str(added);
                    block_buf.push('\n');
                    continue;
                } else if let Some(indent) = yaml_block_scalar_parent_indent(added.as_bytes()) {
                    active_block = Some(DiffBlockKind::YamlScalar(indent));
                    block_start_line = line_no;
                    block_buf.clear();
                    block_buf.push_str(added);
                    block_buf.push('\n');
                    continue;
                } else if crate::rules::is_hexdump_line(added) {
                    active_block = Some(DiffBlockKind::Hexdump);
                    block_start_line = line_no;
                    block_buf.clear();
                    block_buf.push_str(added);
                    block_buf.push('\n');
                    continue;
                }
            }

            let trimmed = added.trim();
            if b64_lines == 0 {
                if is_wrapped_b64_chunk(trimmed) || is_wrapped_base64_start_line(added.as_bytes()) {
                    b64_start_line = line_no;
                    b64_buf.clear();
                    b64_buf.push_str(added);
                    b64_buf.push('\n');
                    b64_lines = 1;
                }
            } else if is_wrapped_b64_chunk(trimmed)
                || is_wrapped_base64_continuation_line(added.as_bytes())
            {
                if b64_buf.len() < MULTILINE_B64_COALESCE_CAP {
                    b64_buf.push_str(added);
                    b64_buf.push('\n');
                    b64_lines += 1;
                }
                if trimmed.ends_with('=') || trimmed.ends_with('"') || trimmed.ends_with('\'') {
                    for m in engine.scan_text_with_hints(&b64_buf, Some(abs), line_hints) {
                        let (_, col) = compute_line_and_column(&b64_buf, 1, m.start);
                        hits.push(FileHit {
                            file: abs.clone(),
                            display_file: disp.clone(),
                            line: b64_start_line,
                            column: col,
                            rule_id: m.rule_id,
                            rule_name: m.rule_name,
                            secret_key: m.secret_key,
                            severity: m.severity,
                            category: m.category,
                            masked: m.masked,
                            fingerprint: m.fingerprint,
                        });
                    }
                    b64_buf.clear();
                    b64_lines = 0;
                }
            } else {
                if b64_lines >= 2 && b64_buf.len() >= 28 {
                    for m in engine.scan_text_with_hints(&b64_buf, Some(abs), line_hints) {
                        let (_, col) = compute_line_and_column(&b64_buf, 1, m.start);
                        hits.push(FileHit {
                            file: abs.clone(),
                            display_file: disp.clone(),
                            line: b64_start_line,
                            column: col,
                            rule_id: m.rule_id,
                            rule_name: m.rule_name,
                            secret_key: m.secret_key,
                            severity: m.severity,
                            category: m.category,
                            masked: m.masked,
                            fingerprint: m.fingerprint,
                        });
                    }
                }
                b64_buf.clear();
                b64_lines = 0;
                if is_wrapped_b64_chunk(trimmed) || is_wrapped_base64_start_line(added.as_bytes()) {
                    b64_start_line = line_no;
                    b64_buf.push_str(added);
                    b64_buf.push('\n');
                    b64_lines = 1;
                }
            }

            let allow_inline_ignore =
                engine.honors_inline_ignore() && crate::rules::path_allows_inline_ignore(Some(abs));

            for m in engine.scan_text_with_hints(added, Some(abs), line_hints) {
                if allow_inline_ignore {
                    let suppressed_by_added =
                        pending_diff_ignore.as_ref().is_some_and(|(t_ln, spec)| {
                            *t_ln == line_no && crate::rules::match_suppressed_by_spec(spec, &m)
                        });
                    if suppressed_by_added {
                        continue;
                    }
                    // In `-U0` diffs, line `line_no - 1` may be an unchanged `# leaktap:ignore-next-line` comment
                    if line_no >= 2
                        && pending_diff_ignore
                            .as_ref()
                            .is_none_or(|(t_ln, _)| *t_ln != line_no)
                    {
                        if !current_checked_doc_blob {
                            current_checked_doc_blob = true;
                            let spec = match &current_commit {
                                Some(sha) => format!("{sha}:{rel}"),
                                None => format!(":{rel}"),
                            };
                            if let Some(blob) = run_git_bytes_capped(
                                repo_root,
                                &["cat-file", "-p", &spec],
                                512 * 1024,
                            ) {
                                current_blob_text =
                                    Some(String::from_utf8_lossy(&blob).into_owned());
                            }
                        }
                        if let Some(ref blob_str) = current_blob_text {
                            if let Some(prev_ln) = blob_str.lines().nth(line_no - 2) {
                                if let Some(spec) =
                                    crate::rules::parse_inline_ignore_directive(prev_ln, true)
                                {
                                    if crate::rules::match_suppressed_by_spec(&spec, &m) {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
                let (_, col) = compute_line_and_column(added, 1, m.start);
                hits.push(FileHit {
                    file: abs.clone(),
                    display_file: disp.clone(),
                    line: line_no,
                    column: col,
                    rule_id: m.rule_id,
                    rule_name: m.rule_name,
                    secret_key: m.secret_key,
                    severity: m.severity,
                    category: m.category,
                    masked: m.masked,
                    fingerprint: m.fingerprint,
                });
            }
            if allow_inline_ignore {
                pending_diff_ignore = crate::rules::parse_inline_ignore_directive(added, true)
                    .map(|spec| (line_no + 1, spec));
            }
        } else if line.starts_with(' ') || line.starts_with('-') {
            if let Some(ctx) = line.strip_prefix(' ') {
                let ctx_line_no = current_new_line;
                current_new_line += 1;
                if engine.honors_inline_ignore() {
                    pending_diff_ignore = crate::rules::parse_inline_ignore_directive(ctx, true)
                        .map(|spec| (ctx_line_no + 1, spec));
                }
                current_doc_hints = current_doc_hints.merge(crate::rules::DocHints::from_text(ctx));
                if contains_gcp_sa_markers(ctx) {
                    current_doc_hints.has_gcp_sa = true;
                }
                if current_doc_hints.is_k8s_secret_manifest
                    || k8s_tracker.is_tracking()
                    || ctx.contains("kind:")
                    || ctx.contains("\"kind\"")
                    || ctx.trim() == "---"
                {
                    let _ = k8s_tracker.observe_line(ctx);
                }
            }
            flush_multiline(
                &mut block_buf,
                &mut active_block,
                block_start_line,
                &mut b64_buf,
                &mut b64_lines,
                b64_start_line,
                current_doc_hints,
                &current_abs_file,
                &current_rel_file,
                &current_commit,
                hits,
            );
        }
    }

    drop(reader);
    let _ = child.wait();

    flush_multiline(
        &mut block_buf,
        &mut active_block,
        block_start_line,
        &mut b64_buf,
        &mut b64_lines,
        b64_start_line,
        current_doc_hints,
        &current_abs_file,
        &current_rel_file,
        &current_commit,
        hits,
    );
}

fn format_display_file(rel: &str, commit: Option<&str>, include_commit: bool) -> String {
    if include_commit {
        if let Some(sha) = commit {
            return format!("git:{sha}:{rel}");
        }
    }
    rel.to_string()
}

fn parse_hunk_new_start(line: &str) -> Option<usize> {
    // Format: @@ -old_start[,old_count] +new_start[,new_count] @@ ...
    let plus_idx = line.find(" +")?;
    let after_plus = &line[plus_idx + 2..];
    let end = after_plus
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_plus.len());
    after_plus[..end].parse::<usize>().ok().map(|n| n.max(1))
}

fn is_pem_header_line(line: &str) -> bool {
    line.contains("-----BEGIN ")
        && (line.contains("PRIVATE KEY-----") || line.contains("PRIVATE KEY BLOCK-----"))
        && !line.contains("\\n")
}

fn is_wrapped_b64_chunk(trimmed: &str) -> bool {
    let without_pad = trimmed
        .strip_suffix("==")
        .or_else(|| trimmed.strip_suffix('='))
        .unwrap_or(trimmed);
    trimmed.len() >= 16
        && trimmed.len() <= 256
        && !without_pad.is_empty()
        && without_pad
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

fn group_git_hits(
    files_scanned: usize,
    bytes_scanned: u64,
    hits: Vec<FileHit>,
) -> TranscriptScanResult {
    struct Entry {
        finding: TranscriptFinding,
        files: HashSet<PathBuf>,
        loc_set: BTreeSet<(String, usize, usize, PathBuf)>,
    }

    let mut grouped: HashMap<String, Entry> = HashMap::new();
    for hit in hits {
        let entry = grouped.entry(hit.fingerprint.clone()).or_insert_with(|| {
            let mut files = HashSet::new();
            files.insert(hit.file.clone());
            let mut loc_set = BTreeSet::new();
            loc_set.insert((
                hit.display_file.clone(),
                hit.line,
                hit.column,
                hit.file.clone(),
            ));
            Entry {
                finding: TranscriptFinding {
                    rule_id: hit.rule_id.clone(),
                    rule_name: hit.rule_name.clone(),
                    secret_key: hit.secret_key.clone(),
                    verified: None,
                    verification_detail: None,
                    severity: hit.severity,
                    category: hit.category,
                    masked: hit.masked.clone(),
                    fingerprint: hit.fingerprint.clone(),
                    first_file: hit.display_file.clone(),
                    first_path: hit.file.clone(),
                    first_line: hit.line,
                    first_column: hit.column,
                    occurrences: 0,
                    distinct_files: 1,
                    locations: Vec::new(),
                },
                files,
                loc_set,
            }
        });
        entry.finding.occurrences += 1;
        if entry.finding.secret_key.is_none() && hit.secret_key.is_some() {
            entry.finding.secret_key = hit.secret_key;
        }
        entry.files.insert(hit.file.clone());
        entry
            .loc_set
            .insert((hit.display_file, hit.line, hit.column, hit.file));
        entry.finding.distinct_files = entry.files.len();
    }

    let mut secret_findings = Vec::new();
    let mut pii_findings = Vec::new();
    for (_, mut entry) in grouped {
        entry.finding.locations = entry
            .loc_set
            .into_iter()
            .map(|(file, line, column, path)| FindingLocation {
                file,
                path,
                line,
                column,
            })
            .collect();
        if let Some(first_loc) = entry.finding.locations.first() {
            entry.finding.first_file = first_loc.file.clone();
            entry.finding.first_path = first_loc.path.clone();
            entry.finding.first_line = first_loc.line;
            entry.finding.first_column = first_loc.column;
        }
        match entry.finding.category {
            RuleCategory::Secret => secret_findings.push(entry.finding),
            RuleCategory::Pii => pii_findings.push(entry.finding),
        }
    }

    let sorter = |a: &TranscriptFinding, b: &TranscriptFinding| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.first_file.cmp(&b.first_file))
            .then_with(|| a.first_line.cmp(&a.first_line))
    };
    secret_findings.sort_by(sorter);
    pii_findings.sort_by(sorter);

    TranscriptScanResult {
        files_scanned,
        bytes_scanned,
        secret_findings,
        pii_findings,
    }
}
