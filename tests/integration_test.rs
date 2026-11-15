use leaktap::cleaner::clean_transcripts;
use leaktap::cli::{FailThreshold, OutputFormat, ScanArgs, UiArgs};
use leaktap::report::json::render_scan_json;
use leaktap::report::sarif::render_scan_sarif;
use leaktap::run_scan_report;
use leaktap::tui::{render_snapshot_text, ActiveTab, DashboardApp};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use tempfile::TempDir;

fn build_realistic_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");

    let claude_dir = dir
        .path()
        .join(".claude")
        .join("projects")
        .join("payments-service");
    fs::create_dir_all(&claude_dir).unwrap();

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
        serde_json::json!({
            "type": "assistant",
            "message": format!("Found live key {stripe_key} in .env.local; checking webhook handler.")
        })
        .to_string(),
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

    assert_eq!(
        report.transcripts.secret_findings.len(),
        4,
        "unexpected secret findings: {:?}",
        report.transcripts.secret_findings
    );

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

    assert_eq!(report.transcripts.pii_findings.len(), 2);

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

    let dry = clean_transcripts(std::slice::from_ref(&session_file), false, true).unwrap();
    assert_eq!(dry.total_redactions, 5);
    assert_eq!(fs::read_to_string(&session_file).unwrap(), original);

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

    let child_script = format!(
        r#"printf '{{"jsonrpc":"2.0","id":1,"result":{{"leak":"{fake_gh}","ping":"https://telemetry.vendor.io/v1"}}}}\n'; printf 'ENV=%s\n' "${{STRIPE_SECRET_KEY:-SCRUBBED}}""#
    );

    let output = Command::new(bin)
        .args([
            "tap",
            "--scrub-env",
            "--no-net-watch",
            "--no-live-log",
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

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    let rpc: Value = serde_json::from_str(lines[0]).expect("intact JSON-RPC stdout line");
    assert_eq!(rpc["jsonrpc"], "2.0");
    assert_eq!(lines[1], "ENV=SCRUBBED");

    let log_content = fs::read_to_string(&wiretap_log).unwrap();
    assert!(log_content.contains("env_scrubbed"));
    assert!(log_content.contains("secret_in_flight"));
    assert!(log_content.contains("telemetry.vendor.io"));
    assert!(!log_content.contains(&fake_gh));
}

#[test]
fn inspect_api_catches_user_agent_email_leak_and_prompt_secrets_without_tls_certs() {
    // Start a tiny local mock Anthropic server on loopback
    let mock_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mock_port = mock_listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = mock_listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
        }
        let body = r#"{"id":"msg_mock_01","type":"message","content":"ok"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    });

    let bin = env!("CARGO_BIN_EXE_leaktap");
    let tmp = TempDir::new().unwrap();
    let wiretap_log = tmp.path().join("api_tap.jsonl");
    let fake_stripe = format!("sk_live_{}", "9f8a7B6c5D4e3F2g1H0jKlMnOp4c21");

    // Use a tiny cross-platform Rust/Python/Node-independent HTTP client via Node (installed everywhere in CI) or Python?
    // Even better: write a 10-line cross-platform TCP request using rust/sh? Wait: `rustc` tests run on Linux, macOS, and Windows!
    // On Windows `sh` might be Git Bash, or we can invoke `curl` (built into Windows 10/11, macOS, and Ubuntu!).
    let payload = format!(r#"{{"model":"claude","prompt":"key is {fake_stripe}"}}"#);
    let payload_file = tmp.path().join("payload.json");
    fs::write(&payload_file, &payload).unwrap();

    // Pass target URL via env var `ANTHROPIC_BASE_URL` using a tiny platform-neutral node one-liner or curl:
    // Actually `curl` is preinstalled on ubuntu-latest, macos-latest, AND windows-latest (`curl.exe`)!
    // Wait: on Windows `curl.exe` doesn't expand `$ANTHROPIC_BASE_URL` without a shell, whereas `python3` or `node` isn't guaranteed on bare Windows unless called cleanly.
    // Even cleaner: spawn our OWN test binary or `node`? Wait: let's check if `curl` works via `python` or write 6 lines with `curl` on Unix + `powershell` on Windows!
    #[cfg(unix)]
    let child_cmd: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        format!(
            "curl -sS --noproxy '*' -X POST \"$ANTHROPIC_BASE_URL/v1/messages\" -H 'User-Agent: claude-cli/2.1 (vipin@acme-corp.io)' -H 'Content-Type: application/json' --data-binary @{}",
            payload_file.display()
        ),
    ];

    #[cfg(windows)]
    let child_cmd: Vec<String> = vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "curl.exe -sS --noproxy '*' -X POST \"$env:ANTHROPIC_BASE_URL/v1/messages\" -H \"User-Agent: claude-cli/2.1 (vipin@acme-corp.io)\" -H \"Content-Type: application/json\" --data-binary \"@{}\"",
            payload_file.display()
        ),
    ];

    let mut args: Vec<String> = vec![
        "tap".into(),
        "--inspect-api".into(),
        "--no-net-watch".into(),
        "--no-live-log".into(),
        "--quiet".into(),
        "--log".into(),
        wiretap_log.to_string_lossy().into_owned(),
        "--".into(),
    ];
    args.extend(child_cmd);

    let output = Command::new(bin)
        .args(&args)
        .env(
            "LEAKTAP_UPSTREAM_ANTHROPIC_URL",
            format!("http://127.0.0.1:{mock_port}"),
        )
        .output()
        .expect("run leaktap tap --inspect-api");

    server_handle.join().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("msg_mock_01"),
        "unexpected response: {stdout}"
    );

    let log_content = fs::read_to_string(&wiretap_log).unwrap();
    assert!(
        log_content.contains("header-email-leak"),
        "missing header-email-leak in:\n{log_content}"
    );
    assert!(
        log_content.contains("v***@acme-corp.io"),
        "missing masked email in:\n{log_content}"
    );
    assert!(
        log_content.contains("secret_in_prompt"),
        "missing secret_in_prompt in:\n{log_content}"
    );
    assert!(!log_content.contains(&fake_stripe));
}

#[test]
fn tui_dashboard_renders_all_tabs_and_scrubs_selected_file() {
    let fixture = build_realistic_fixture();
    let live_log = fixture.path().join("live.jsonl");
    fs::write(
        &live_log,
        r#"{"ts_ms":1700000000,"stream":"http-header","kind":"header_leak","rule_id":"header-email-leak","severity":"HIGH","detail":"Email address (v***@acme.io) sent in HTTP header `User-Agent`"}"#,
    )
    .unwrap();

    let mut app = DashboardApp::new(&UiArgs {
        paths: vec![fixture.path().to_path_buf()],
        log: Some(live_log),
        once: true,
    });

    // Tab 1: Secrets
    let snap1 = render_snapshot_text(&mut app, 110, 26).unwrap();
    assert!(snap1.contains("Transcript Leaks (4)"));
    assert!(snap1.contains("Stripe Live Key"));

    // Tab 2: MCP Config Risks
    app.tab = ActiveTab::Mcp;
    let snap2 = render_snapshot_text(&mut app, 110, 26).unwrap();
    assert!(snap2.contains("MCP Config Risks (4)"));
    assert!(snap2.contains("risky-community-db"));

    // Tab 3: Live Wiretap Stream
    app.tab = ActiveTab::Live;
    let snap3 = render_snapshot_text(&mut app, 110, 26).unwrap();
    assert!(snap3.contains("Live Wiretap (1)"));
    assert!(snap3.contains("User-Agent"));

    // Scrub selected secret file directly from Tab 1
    app.tab = ActiveTab::Secrets;
    app.scrub_selected_secret_file();
    assert_eq!(app.report.transcripts.secret_findings.len(), 0);
}
