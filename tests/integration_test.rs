use leaktap::cleaner::clean_transcripts;
use leaktap::cli::{FailThreshold, OutputFormat, ScanArgs};
use leaktap::report::json::render_scan_json;
use leaktap::report::sarif::render_scan_sarif;
use leaktap::run_scan_report;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn build_realistic_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");

    // 1. Realistic Claude Code session `.jsonl` with repeated secret + PII + tricky false positives
    let claude_dir = dir
        .path()
        .join(".claude")
        .join("projects")
        .join("payments-service");
    fs::create_dir_all(&claude_dir).unwrap();

    // Build realistic-format synthetic test tokens dynamically so static repo scanners don't trip on source literals
    let stripe_key = format!("sk_live_{}", "9f8a7B6c5D4e3F2g1H0jKlMnOp4c21");
    let aws_key = format!("AKIA{}", "5F29QWERTY787Q2M");
    let gh_pat = format!("ghp_{}", "x82KmN9pQrStUvWxYz0123456789AbCd91aB");
    let pg_uri =
        "postgres://billing_admin:Sup3rS3cr3tP4ss!@prod-db.us-east-1.rds.amazonaws.com:5432/ledger";

    let session_lines = [
        serde_json::json!({
            "type": "user",
            "message": "Debug checkout failure for vipin@acme-payments.io against https://ledger-api.payments.corp/v1/charge"
        })
        .to_string(),
        serde_json::json!({
            "type": "tool_result",
            "tool": "Read",
            "path": ".env.local",
            "content": format!(
                "STRIPE_SECRET_KEY={stripe_key}\nAWS_ACCESS_KEY_ID={aws_key}\nDATABASE_URL={pg_uri}\nGITHUB_TOKEN={gh_pat}\n"
            )
        })
        .to_string(),
        // Duplicate occurrence of the same Stripe key on a later turn (must deduplicate!)
        serde_json::json!({
            "type": "assistant",
            "message": format!("Found live key {stripe_key} in .env.local; checking webhook handler.")
        })
        .to_string(),
        // Benign false-positive landmines that MUST be ignored
        serde_json::json!({
            "type": "tool_result",
            "content": "AWS_EXAMPLE=AKIAIOSFODNN7EXAMPLE\nLOCAL_DB=postgres://postgres:postgres@localhost:5432/dev\nGIT=git@github.com:org/repo.git\nPKG=@modelcontextprotocol/server-filesystem\nPLACEHOLDER=sk_live_your_api_key_placeholder_0000"
        })
        .to_string(),
    ];

    fs::write(
        claude_dir.join("session-08fa.jsonl"),
        session_lines.join("\n") + "\n",
    )
    .unwrap();

    // 2. Realistic `.mcp.json` with both risky and clean servers
    let mcp_config = serde_json::json!({
        "mcpServers": {
            "risky-community-db": {
                "command": "npx",
                "args": ["-y", "@community/db-mcp", "/"],
                "env": {
                    "GITHUB_PERSONAL_TOKEN": gh_pat,
                    "TELEMETRY_URL": "https://events.posthog.com/capture"
                }
            },
            "safe-pinned-server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-memory@1.2.3", "./workspace"],
                "env": {
                    "GITHUB_PERSONAL_TOKEN": "${GITHUB_PERSONAL_TOKEN}"
                }
            }
        }
    });
    fs::write(
        dir.path().join(".mcp.json"),
        serde_json::to_string_pretty(&mcp_config).unwrap(),
    )
    .unwrap();

    dir
}

#[test]
fn scan_detects_real_leaks_deduplicates_and_suppresses_false_positives() {
    let fixture = build_realistic_fixture();

    let args = ScanArgs {
        paths: vec![fixture.path().to_path_buf()],
        format: OutputFormat::Json,
        no_pii: false,
        no_mcp: false,
        fail_on: FailThreshold::Critical,
    };

    let report = run_scan_report(&args);

    // Exactly 4 unique secrets (Stripe, AWS, Postgres URI, GitHub PAT) — zero false positives!
    assert_eq!(
        report.transcripts.secret_findings.len(),
        4,
        "unexpected secret findings: {:?}",
        report.transcripts.secret_findings
    );

    // Verify Stripe key was deduplicated with occurrences == 2 and safely masked
    let stripe = report
        .transcripts
        .secret_findings
        .iter()
        .find(|f| f.rule_id == "stripe-live-key")
        .expect("stripe finding");
    assert_eq!(stripe.occurrences, 2);
    assert!(stripe.masked.starts_with("sk_live_"));
    assert!(stripe.masked.ends_with("4c21"));
    assert!(!stripe.masked.contains("9f8a7B6c5D4e3F2g1H0jKlMnOp"));

    // Verify PII / internal metadata caught work email + *.corp hostname, ignoring git@github.com and @scope/pkg
    assert_eq!(report.transcripts.pii_findings.len(), 2);

    // Verify MCP audit caught risky-community-db issues and ignored safe-pinned-server
    assert!(
        report
            .mcp_findings
            .iter()
            .all(|m| m.server_name == "risky-community-db"),
        "safe server should have zero findings: {:?}",
        report.mcp_findings
    );
    let mcp_rules: Vec<&str> = report.mcp_findings.iter().map(|m| m.rule_id).collect();
    assert!(mcp_rules.contains(&"mcp-unpinned-package"));
    assert!(mcp_rules.contains(&"mcp-broad-filesystem"));
    assert!(mcp_rules.contains(&"mcp-hardcoded-secret"));
    assert!(mcp_rules.contains(&"mcp-telemetry-endpoint"));

    // Validate JSON and SARIF 2.1.0 outputs serialize as valid structured documents
    let json_doc: Value = serde_json::from_str(&render_scan_json(&report)).unwrap();
    assert_eq!(json_doc["summary"]["unique_secrets"], 4);

    let sarif_doc: Value = serde_json::from_str(&render_scan_sarif(&report)).unwrap();
    assert_eq!(sarif_doc["version"], "2.1.0");
    assert!(!sarif_doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn clean_dry_run_is_readonly_and_apply_preserves_valid_jsonl() {
    let fixture = build_realistic_fixture();
    let session_file = fixture
        .path()
        .join(".claude/projects/payments-service/session-08fa.jsonl");
    let original = fs::read_to_string(&session_file).unwrap();

    // 1. Dry run must NOT modify the file
    let dry = clean_transcripts(std::slice::from_ref(&session_file), false, true).unwrap();
    assert_eq!(dry.total_redactions, 5); // 4 secrets on turn 2 + 1 repeated Stripe key on turn 3
    assert_eq!(fs::read_to_string(&session_file).unwrap(), original);

    // 2. Apply mode scrubs secrets, creates `.leaktap.bak`, and keeps every JSONL line valid JSON
    let applied = clean_transcripts(std::slice::from_ref(&session_file), true, true).unwrap();
    assert_eq!(applied.total_redactions, 5);

    let bak_file = fixture
        .path()
        .join(".claude/projects/payments-service/session-08fa.jsonl.leaktap.bak");
    assert!(bak_file.exists(), "backup file must exist");
    assert_eq!(fs::read_to_string(&bak_file).unwrap(), original);

    let cleaned = fs::read_to_string(&session_file).unwrap();
    assert!(cleaned.contains("[REDACTED_BY_LEAKTAP]"));
    assert!(!cleaned.contains("Sup3rS3cr3tP4ss!"));

    for (idx, line) in cleaned.lines().enumerate() {
        serde_json::from_str::<Value>(line)
            .unwrap_or_else(|e| panic!("line {} invalid JSON after clean: {e}", idx + 1));
    }

    // 3. Re-scanning cleaned transcript finds 0 secrets
    let rescan = run_scan_report(&ScanArgs {
        paths: vec![session_file],
        no_mcp: true,
        no_pii: true,
        ..Default::default()
    });
    assert_eq!(rescan.transcripts.secret_findings.len(), 0);
}

#[test]
fn tap_scrubs_inherited_secret_env_and_preserves_exact_stdout_jsonrpc() {
    let bin = env!("CARGO_BIN_EXE_leaktap");
    let tmp = TempDir::new().unwrap();
    let wiretap_log = tmp.path().join("wiretap.jsonl");

    let fake_stripe = format!("sk_live_{}", "9f8a7B6c5D4e3F2g1H0jKlMnOp4c21");
    let fake_gh = format!("ghp_{}", "x82KmN9pQrStUvWxYz0123456789AbCd91aB");

    // Child prints JSON-RPC frame + checks whether STRIPE_SECRET_KEY was scrubbed
    let child_script = format!(
        r#"printf '{{"jsonrpc":"2.0","id":1,"result":{{"leak":"{fake_gh}","ping":"https://telemetry.vendor.io/v1"}}}}\n'; printf 'ENV=%s\n' "${{STRIPE_SECRET_KEY:-SCRUBBED}}""#
    );

    let output = Command::new(bin)
        .args([
            "tap",
            "--scrub-env",
            "--quiet",
            "--log",
            wiretap_log.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &child_script,
        ])
        .env("STRIPE_SECRET_KEY", &fake_stripe)
        .output()
        .expect("run leaktap tap");

    assert!(output.status.success());

    // stdout must remain byte-for-byte pure child output (no `[leaktap]` corruption!)
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    let rpc: Value = serde_json::from_str(lines[0]).expect("intact JSON-RPC stdout line");
    assert_eq!(rpc["jsonrpc"], "2.0");
    assert_eq!(lines[1], "ENV=SCRUBBED");

    // Wiretap JSONL log must capture env_scrubbed, secret_in_flight, and outbound_endpoint
    let log_content = fs::read_to_string(&wiretap_log).unwrap();
    assert!(log_content.contains("env_scrubbed"));
    assert!(log_content.contains("secret_in_flight"));
    assert!(log_content.contains("telemetry.vendor.io"));
    // Raw GitHub PAT must NEVER be logged unmasked in wiretap log!
    assert!(!log_content.contains(&fake_gh));
}
