pub mod api_tap;
pub mod cleaner;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod git_scan;
pub mod header_audit;
pub mod mcp_audit;
pub mod mcp_inspect;
pub mod netwatch;
pub mod plugin_audit;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod tap;
pub mod tui;
pub mod verify;

use crate::cleaner::clean_transcripts_with_policy;
use crate::cli::{
    CleanArgs, Cli, Commands, FailThreshold, OutputFormat, RulesFormat, ScanArgs, TapArgs,
};
use crate::config::{is_ci_environment, PolicyConfig};
use crate::discovery::{discover_clean_targets_with_policy, discover_targets_with_all_and_policy};
use crate::git_scan::run_git_scan;
use crate::mcp_audit::audit_mcp_configs_with_policy;
use crate::mcp_inspect::inspect_live_mcp_configs_with_options;
use crate::plugin_audit::audit_plugin_files_with_policy;
use crate::report::json::render_scan_json;
use crate::report::sarif::{render_rules_json, render_scan_sarif_with_rules};
use crate::report::terminal::{render_clean_terminal, render_rules_terminal, render_scan_terminal};
use crate::report::FullScanReport;
use crate::rules::{RuleEngine, Severity};
use crate::scanner::scan_transcripts;
use crate::tap::run_tap;
use crate::tui::run_ui;
use crate::verify::verify_secret_findings;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn execute(cli: Cli) -> i32 {
    let global_config = cli.config;
    let global_policy_git_ref = cli.policy_git_ref;
    let global_trust_project_config = cli.trust_project_config;
    let global_mcp_pins_file = cli.mcp_pins_file;
    let global_update_mcp_pins = cli.update_mcp_pins;
    let global_no_config = cli.no_config;
    let global_block_secrets = cli.block_secrets;
    let global_redact_secrets = cli.redact_secrets;
    let global_scrub_ssh_agent = cli.scrub_ssh_agent;
    let global_allow_env = cli.allow_env;

    crate::mcp_inspect::set_configured_mcp_pins_path(global_mcp_pins_file.clone());

    match cli.command.unwrap_or(Commands::Scan(ScanArgs::default())) {
        Commands::Scan(mut args) => {
            if args.config.is_none() {
                args.config = global_config;
            }
            if args.policy_git_ref.is_none() {
                args.policy_git_ref = global_policy_git_ref;
            }
            if args.mcp_pins_file.is_none() {
                args.mcp_pins_file = global_mcp_pins_file;
            }
            args.trust_project_config |= global_trust_project_config;
            args.update_mcp_pins |= global_update_mcp_pins;
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
        Commands::Claude(args) => {
            let mut tap_args = TapArgs::for_direct_cli(
                "claude",
                args.args,
                global_block_secrets,
                global_scrub_ssh_agent,
                global_allow_env,
                global_config,
                global_policy_git_ref,
                global_trust_project_config,
                global_no_config,
            );
            tap_args.redact_secrets = global_redact_secrets;
            tap_args.mcp_pins_file = global_mcp_pins_file;
            tap_args.update_mcp_pins = global_update_mcp_pins;
            execute_tap(&tap_args)
        }
        Commands::Codex(args) => {
            let mut tap_args = TapArgs::for_direct_cli(
                "codex",
                args.args,
                global_block_secrets,
                global_scrub_ssh_agent,
                global_allow_env,
                global_config,
                global_policy_git_ref,
                global_trust_project_config,
                global_no_config,
            );
            tap_args.redact_secrets = global_redact_secrets;
            tap_args.mcp_pins_file = global_mcp_pins_file;
            tap_args.update_mcp_pins = global_update_mcp_pins;
            execute_tap(&tap_args)
        }
        Commands::Agy(args) => {
            let mut tap_args = TapArgs::for_direct_cli(
                "agy",
                args.args,
                global_block_secrets,
                global_scrub_ssh_agent,
                global_allow_env,
                global_config,
                global_policy_git_ref,
                global_trust_project_config,
                global_no_config,
            );
            tap_args.redact_secrets = global_redact_secrets;
            tap_args.mcp_pins_file = global_mcp_pins_file;
            tap_args.update_mcp_pins = global_update_mcp_pins;
            execute_tap(&tap_args)
        }
        Commands::Gemini(args) => {
            let mut tap_args = TapArgs::for_direct_cli(
                "gemini",
                args.args,
                global_block_secrets,
                global_scrub_ssh_agent,
                global_allow_env,
                global_config,
                global_policy_git_ref,
                global_trust_project_config,
                global_no_config,
            );
            tap_args.redact_secrets = global_redact_secrets;
            tap_args.mcp_pins_file = global_mcp_pins_file;
            tap_args.update_mcp_pins = global_update_mcp_pins;
            execute_tap(&tap_args)
        }
        Commands::Tap(mut args) => {
            args.block_secrets |= global_block_secrets;
            args.redact_secrets |= global_redact_secrets;
            args.scrub_ssh_agent |= global_scrub_ssh_agent;
            args.trust_project_config |= global_trust_project_config;
            args.update_mcp_pins |= global_update_mcp_pins;
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
            if args.mcp_pins_file.is_none() {
                args.mcp_pins_file = global_mcp_pins_file;
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
    if let Some(ref pins) = args.mcp_pins_file {
        crate::mcp_inspect::set_configured_mcp_pins_path(Some(pins.clone()));
    }
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
    let eff_paths = args.effective_paths();
    let policy = PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &eff_paths,
        args.trust_project_config,
        args.no_config,
    )
    .unwrap_or_default();
    run_scan_report_with_policy(args, &policy)
}

pub fn run_scan_report_with_policy(args: &ScanArgs, policy: &PolicyConfig) -> FullScanReport {
    if let Some(ref pins) = args.mcp_pins_file {
        crate::mcp_inspect::set_configured_mcp_pins_path(Some(pins.clone()));
    }
    let eff_paths = args.effective_paths();
    let started = Instant::now();
    let mut engine = RuleEngine::with_policy(!args.no_pii, Some(policy));
    let honor_inline =
        !args.no_inline_ignore && (args.policy_git_ref.is_none() || args.allow_inline_ignore);
    engine.set_honor_inline_ignore(honor_inline);
    let active_checks = args.verify || (args.inspect_mcp && !args.no_mcp);

    if args.staged || args.git_history {
        let mut git_out = run_git_scan(
            &eff_paths,
            args.staged,
            args.git_history,
            args.max_commits,
            !args.no_mcp,
            &engine,
            Some(policy),
        );
        if args.verify {
            verify_secret_findings(&mut git_out.transcripts.secret_findings, &engine);
        }

        return FullScanReport {
            roots: git_out.roots,
            scan_paths: eff_paths,
            mcp_files_scanned: git_out.mcp_files_scanned,
            mcp_bytes_scanned: git_out.mcp_bytes_scanned,
            active_checks,
            duration: started.elapsed(),
            transcripts: git_out.transcripts,
            mcp_findings: git_out.mcp_findings,
        };
    }

    let targets =
        discover_targets_with_all_and_policy(&eff_paths, args.all, !args.no_mcp, Some(policy));
    let mut transcripts = scan_transcripts(&targets.transcript_files, &engine);
    if args.verify {
        verify_secret_findings(&mut transcripts.secret_findings, &engine);
    }

    let (mut mcp_findings, mcp_files_scanned, mcp_bytes_scanned) = if args.no_mcp {
        (Vec::new(), 0, 0)
    } else {
        audit_discovered_mcp_and_plugins(&targets.mcp_config_files, &targets.plugin_files, policy)
    };

    if args.inspect_mcp && !args.no_mcp {
        let mut seen_fp: HashSet<String> =
            mcp_findings.iter().map(|f| f.fingerprint.clone()).collect();
        for lf in inspect_live_mcp_configs_with_options(
            &targets.mcp_config_files,
            args.trust_project_config,
            args.update_mcp_pins,
            Some(policy),
        ) {
            if seen_fp.insert(lf.fingerprint.clone()) {
                mcp_findings.push(lf);
            }
        }
        mcp_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.config_file.cmp(&b.config_file))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.server_name.cmp(&b.server_name))
        });
    }

    FullScanReport {
        roots: targets.scanned_roots,
        scan_paths: eff_paths,
        mcp_files_scanned,
        mcp_bytes_scanned,
        active_checks,
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
    let eff_paths = args.effective_paths();
    warn_ci_untrusted_project_config(
        args.trust_project_config,
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
    );
    let policy = match PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &eff_paths,
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

    let effective_fail_on = if args.ci && args.fail_on == FailThreshold::None {
        FailThreshold::High
    } else {
        args.fail_on
    };

    if effective_fail_on == FailThreshold::None
        && is_ci_environment()
        && report
            .highest_severity()
            .is_some_and(|s| s >= Severity::High)
    {
        eprintln!(
            "[leaktap:info] HIGH/CRITICAL findings detected in advisory mode (`--fail-on none`, exit 0); pass `--ci` or `--fail-on high` to fail CI builds."
        );
    }

    let should_fail = match (effective_fail_on, report.highest_severity()) {
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
    let eff_paths = args.effective_paths();
    warn_ci_untrusted_project_config(
        args.trust_project_config,
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
    );
    let policy = match PolicyConfig::load_with_git_ref(
        args.config.as_deref(),
        args.policy_git_ref.as_deref(),
        &eff_paths,
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
    let targets = discover_clean_targets_with_policy(&eff_paths, args.include_code, Some(&policy));
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
