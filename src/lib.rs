pub mod cleaner;
pub mod cli;
pub mod discovery;
pub mod mcp_audit;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod tap;

use crate::cleaner::clean_transcripts;
use crate::cli::{CleanArgs, Cli, Commands, FailThreshold, OutputFormat, ScanArgs};
use crate::discovery::discover_targets;
use crate::mcp_audit::audit_mcp_configs;
use crate::report::json::render_scan_json;
use crate::report::sarif::render_scan_sarif;
use crate::report::terminal::{render_clean_terminal, render_rules_terminal, render_scan_terminal};
use crate::report::FullScanReport;
use crate::rules::{RuleEngine, Severity};
use crate::scanner::scan_transcripts;
use crate::tap::run_tap;
use std::time::Instant;

pub fn execute(cli: Cli) -> i32 {
    match cli.command.unwrap_or(Commands::Scan(ScanArgs::default())) {
        Commands::Scan(args) => execute_scan(&args),
        Commands::Clean(args) => execute_clean(&args),
        Commands::Tap(args) => match run_tap(&args) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("leaktap tap error: {err}");
                2
            }
        },
        Commands::Rules => {
            let engine = RuleEngine::all_rules();
            print!("{}", render_rules_terminal(&engine));
            0
        }
    }
}

pub fn run_scan_report(args: &ScanArgs) -> FullScanReport {
    let started = Instant::now();
    let engine = RuleEngine::new(!args.no_pii);
    let targets = discover_targets(&args.paths, !args.no_mcp);

    let transcripts = scan_transcripts(&targets.transcript_files, &engine);
    let mcp_findings = if args.no_mcp {
        Vec::new()
    } else {
        let mcp_engine = RuleEngine::new(false);
        audit_mcp_configs(&targets.mcp_config_files, &mcp_engine)
    };

    FullScanReport {
        roots: targets.scanned_roots,
        mcp_files_scanned: targets.mcp_config_files.len(),
        duration: started.elapsed(),
        transcripts,
        mcp_findings,
    }
}

pub fn execute_scan(args: &ScanArgs) -> i32 {
    let report = run_scan_report(args);

    match args.format {
        OutputFormat::Terminal => print!("{}", render_scan_terminal(&report)),
        OutputFormat::Json => println!("{}", render_scan_json(&report)),
        OutputFormat::Sarif => println!("{}", render_scan_sarif(&report)),
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
    let targets = discover_targets(&args.paths, false);
    match clean_transcripts(&targets.transcript_files, args.apply, !args.no_backup) {
        Ok(summary) => {
            print!("{}", render_clean_terminal(&summary));
            0
        }
        Err(err) => {
            eprintln!("leaktap clean error: {err}");
            2
        }
    }
}
