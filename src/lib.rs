pub mod api_tap;
pub mod cleaner;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod git_scan;
pub mod header_audit;
pub mod mcp_audit;
pub mod netwatch;
pub mod plugin_audit;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod tap;
pub mod tui;

use crate::cleaner::clean_transcripts_with_policy;
use crate::cli::{
    CleanArgs, Cli, Commands, FailThreshold, OutputFormat, RulesFormat, ScanArgs, TapArgs,
};
use crate::config::{is_ci_environment, PolicyConfig};
use crate::discovery::{discover_clean_targets_with_policy, discover_targets_with_all_and_policy};
use crate::git_scan::run_git_scan;
use crate::mcp_audit::audit_mcp_configs_with_policy;
use crate::plugin_audit::audit_plugin_files_with_policy;
use crate::report::json::render_scan_json;
use crate::report::sarif::{render_rules_json, render_scan_sarif_with_rules};
use crate::report::terminal::{render_clean_terminal, render_rules_terminal, render_scan_terminal};
use crate::report::FullScanReport;
use crate::rules::{RuleEngine, Severity};
use crate::scanner::scan_transcripts;
use crate::tap::run_tap;
use crate::tui::run_ui;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn execute(cli: Cli) -> i32 {
    let global_config = cli.config;
    let global_policy_git_ref = cli.policy_git_ref;
    let global_trust_project_config = cli.trust_project_config;
    let global_no_config = cli.no_config;
    let global_block_secrets = cli.block_secrets;
    let global_scrub_ssh_agent = cli.scrub_ssh_agent;
    let global_allow_env = cli.allow_env;

    match cli.command.unwrap_or(Commands::Scan(ScanArgs::default())) {
        Commands::Scan(mut args) => {
            if args.config.is_none() {
                args.config = global_config;
            }
            if args.policy_git_ref.is_none() {
                args.policy_git_ref = global_policy_git_ref;
            }
            args.trust_project_config |= global_trust_project_config;
            args.no_config |= global_no_config;
            execute_scan(&args)
        }
        Commands::Clean(mut args) => {
            if args.config.is_none() {
                args.config = global_config;
            }
            if args.policy_git_ref.is_none() {
                args.policy_git_ref = global_policy_git_ref;
            }
            args.trust_project_config |= global_trust_project_config;
            args.no_config |= global_no_config;
            execute_clean(&args)
        }
        Commands::Ui(mut args) => {
            if args.config.is_none() {
                args.config = global_config;
            }
            if args.policy_git_ref.is_none() {
                args.policy_git_ref = global_policy_git_ref;
            }
            args.trust_project_config |= global_trust_project_config;
            args.no_config |= global_no_config;
            warn_ci_untrusted_project_config(
                args.trust_project_config,
                args.config.as_deref(),
                args.policy_git_ref.as_deref(),
            );
            match PolicyConfig::load_with_git_ref(
                args.config.as_deref(),
                args.policy_git_ref.as_deref(),
                &args.paths,
                args.trust_project_config,
                args.no_config,
            ) {
                Ok(policy) => warn_ignored_untrusted_configs(&policy),
                Err(err) => {
                    eprintln!("leaktap config error: {err}");
                    return 2;
                }
            }
            match run_ui(&args) {
                Ok(code) => code,
                Err(err) => {
                    eprintln!("leaktap ui error: {err}");
                    2
                }
            }
        }
        Commands::Claude(args) => execute_tap(&TapArgs::for_direct_cli(
            "claude",
            args.args,
            global_block_secrets,
            global_scrub_ssh_agent,
            global_allow_env,
            global_config,
            global_policy_git_ref,
            global_trust_project_config,
            global_no_config,
        )),
        Commands::Codex(args) => execute_tap(&TapArgs::for_direct_cli(
            "codex",
            args.args,
            global_block_secrets,
            global_scrub_ssh_agent,
            global_allow_env,
            global_config,
            global_policy_git_ref,
            global_trust_project_config,
            global_no_config,
        )),
        Commands::Agy(args) => execute_tap(&TapArgs::for_direct_cli(
            "agy",
            args.args,
            global_block_secrets,
            global_scrub_ssh_agent,
            global_allow_env,
            global_config,
            global_policy_git_ref,
            global_trust_project_config,
            global_no_config,
        )),
        Commands::Gemini(args) => execute_tap(&TapArgs::for_direct_cli(
            "gemini",
            args.args,
            global_block_secrets,
            global_scrub_ssh_agent,
            global_allow_env,
            global_config,
            global_policy_git_ref,
            global_trust_project_config,
            global_no_config,
        )),
        Commands::Tap(mut args) => {
            args.block_secrets |= global_block_secrets;
            args.scrub_ssh_agent |= global_scrub_ssh_agent;
            args.trust_project_config |= global_trust_project_config;
            args.no_config |= global_no_config;
            for v in global_allow_env {
                if !args.allow_env.contains(&v) {
                    args.allow_env.push(v);
                }
            }
            if args.config.is_none() {
                args.config = global_config;
            }
            if args.policy_git_ref.is_none() {
                args.policy_git_ref = global_policy_git_ref;
            }
            execute_tap(&args)
        }
        Commands::Rules(rules_args) => {
            warn_ci_untrusted_project_config(
                global_trust_project_config,
                global_config.as_deref(),
                global_policy_git_ref.as_deref(),
            );
            let policy = match PolicyConfig::load_with_git_ref(
                global_config.as_deref(),
                global_policy_git_ref.as_deref(),
                &[],
                global_trust_project_config,
                global_no_config,
            ) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("leaktap config error: {err}");
                    return 2;
                }
            };
            warn_ignored_untrusted_configs(&policy);
            let engine = RuleEngine::with_policy(true, Some(&policy));
            match rules_args.format {
                RulesFormat::Json => println!("{}", render_rules_json(&engine)),
                RulesFormat::Text | RulesFormat::Terminal => {
                    print!("{}", render_rules_terminal(&engine));
                }
            }
            0
        }
    }
}

fn warn_ci_untrusted_project_config(
    trust_project_config: bool,
    explicit_config: Option<&Path>,
    policy_git_ref: Option<&str>,
) {
    if trust_project_config
        && explicit_config.is_none()
        && policy_git_ref.is_none()
        && is_ci_environment()
    {
        eprintln!(
            "[leaktap:warn] `--trust-project-config` is enabled in CI without `--policy-git-ref` or `--config`; untrusted pull-request branches can edit `.leaktap.toml` to self-suppress findings. Prefer `--policy-git-ref origin/main` in PR CI."
        );
    }
}

fn warn_ignored_untrusted_configs(policy: &PolicyConfig) {
    if !policy.ignored_untrusted_configs.is_empty() {
        let joined: Vec<String> = policy
            .ignored_untrusted_configs
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        eprintln!(
            "[leaktap] Note: ignored untrusted project policy file(s): {} (pass `--trust-project-config`, `--policy-git-ref <ref>`, or `--config <file>` to apply)",
            joined.join(", ")
        );
    }
}

fn execute_tap(args: &TapArgs) -> i32 {
    if !args.quiet {
        warn_ci_untrusted_project_config(
            args.trust_project_config,
            args.config.as_deref(),
            args.policy_git_ref.as_deref(),
        );
    }
    match PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &[],
        args.trust_project_config,
        args.no_config,
    ) {
        Ok(policy) => {
            if !args.quiet {
                warn_ignored_untrusted_configs(&policy);
            }
        }
        Err(err) => {
            eprintln!("leaktap config error: {err}");
            return 2;
        }
    }
    match run_tap(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("leaktap tap error: {err}");
            2
        }
    }
}

pub fn run_scan_report(args: &ScanArgs) -> FullScanReport {
    let policy = PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &args.paths,
        args.trust_project_config,
        args.no_config,
    )
    .unwrap_or_default();
    run_scan_report_with_policy(args, &policy)
}

pub fn run_scan_report_with_policy(args: &ScanArgs, policy: &PolicyConfig) -> FullScanReport {
    let started = Instant::now();
    let engine = RuleEngine::with_policy(!args.no_pii, Some(policy));

    if args.staged || args.git_history {
        let git_out = run_git_scan(
            &args.paths,
            args.staged,
            args.git_history,
            args.max_commits,
            !args.no_mcp,
            &engine,
            Some(policy),
        );

        return FullScanReport {
            roots: git_out.roots,
            scan_paths: args.paths.clone(),
            mcp_files_scanned: git_out.mcp_files_scanned,
            mcp_bytes_scanned: git_out.mcp_bytes_scanned,
            duration: started.elapsed(),
            transcripts: git_out.transcripts,
            mcp_findings: git_out.mcp_findings,
        };
    }

    let targets =
        discover_targets_with_all_and_policy(&args.paths, args.all, !args.no_mcp, Some(policy));
    let transcripts = scan_transcripts(&targets.transcript_files, &engine);
    let (mcp_findings, mcp_files_scanned, mcp_bytes_scanned) = if args.no_mcp {
        (Vec::new(), 0, 0)
    } else {
        audit_discovered_mcp_and_plugins(&targets.mcp_config_files, &targets.plugin_files, policy)
    };

    FullScanReport {
        roots: targets.scanned_roots,
        scan_paths: args.paths.clone(),
        mcp_files_scanned,
        mcp_bytes_scanned,
        duration: started.elapsed(),
        transcripts,
        mcp_findings,
    }
}

fn audit_discovered_mcp_and_plugins(
    mcp_config_files: &[PathBuf],
    plugin_files: &[PathBuf],
    policy: &PolicyConfig,
) -> (Vec<crate::mcp_audit::McpFinding>, usize, u64) {
    let mcp_engine = RuleEngine::with_policy(false, Some(policy));
    let mut combined = audit_mcp_configs_with_policy(mcp_config_files, &mcp_engine, Some(policy));
    let plugin_findings = audit_plugin_files_with_policy(plugin_files, &mcp_engine, Some(policy));

    let mut seen_fp: HashSet<String> = combined.iter().map(|f| f.fingerprint.clone()).collect();
    for pf in plugin_findings {
        if seen_fp.insert(pf.fingerprint.clone()) {
            combined.push(pf);
        }
    }
    combined.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.config_file.cmp(&b.config_file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });

    let unique_audited: HashSet<&PathBuf> = mcp_config_files.iter().chain(plugin_files).collect();
    let audited_bytes: u64 = unique_audited
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len().min(64 * 1024 * 1024))
        .sum();
    (combined, unique_audited.len(), audited_bytes)
}

pub fn execute_scan(args: &ScanArgs) -> i32 {
    warn_ci_untrusted_project_config(
        args.trust_project_config,
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
    );
    let policy = match PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &args.paths,
        args.trust_project_config,
        args.no_config,
    ) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("leaktap config error: {err}");
            return 2;
        }
    };
    warn_ignored_untrusted_configs(&policy);
    let report = run_scan_report_with_policy(args, &policy);

    match args.format {
        OutputFormat::Terminal => print!("{}", render_scan_terminal(&report)),
        OutputFormat::Json => println!("{}", render_scan_json(&report)),
        OutputFormat::Sarif => {
            let sarif_engine = RuleEngine::with_policy(true, Some(&policy));
            println!("{}", render_scan_sarif_with_rules(&report, &sarif_engine));
        }
    }

    let should_fail = match (args.fail_on, report.highest_severity()) {
        (FailThreshold::None, _) | (_, None) => false,
        (FailThreshold::Medium, Some(sev)) => sev >= Severity::Medium,
        (FailThreshold::High, Some(sev)) => sev >= Severity::High,
        (FailThreshold::Critical, Some(sev)) => sev >= Severity::Critical,
    };

    if should_fail {
        1
    } else {
        0
    }
}

pub fn execute_clean(args: &CleanArgs) -> i32 {
    warn_ci_untrusted_project_config(
        args.trust_project_config,
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
    );
    let policy = match PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &args.paths,
        args.trust_project_config,
        args.no_config,
    ) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("leaktap config error: {err}");
            return 2;
        }
    };
    warn_ignored_untrusted_configs(&policy);
    let targets = discover_clean_targets_with_policy(&args.paths, args.include_code, Some(&policy));
    let create_backup = args.backup && !args.no_backup;
    match clean_transcripts_with_policy(
        &targets.transcript_files,
        args.apply,
        create_backup,
        Some(&policy),
    ) {
        Ok(summary) => {
            print!("{}", render_clean_terminal(&summary));
            if args.apply && summary.uncleaned_sqlite_secrets > 0 {
                1
            } else {
                0
            }
        }
        Err(err) => {
            eprintln!("leaktap clean error: {err}");
            2
        }
    }
}
