use leaktap::cleaner::clean_transcripts;
use leaktap::cli::{FailThreshold, OutputFormat, ScanArgs, UiArgs};
use leaktap::report::json::render_scan_json;
use leaktap::report::sarif::render_scan_sarif;
use leaktap::run_scan_report;
use leaktap::tui::{render_snapshot_text, ActiveTab, DashboardApp};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::process::Command;
use std::thread;
use tempfile::TempDir;

fn serve_single_mock_http(
    listener: TcpListener,
    content_type: &'static str,
    resp_body: &'static str,
) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut req_line = String::new();
        reader.read_line(&mut req_line).unwrap();

        let mut content_len = 0usize;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse::<usize>().unwrap_or(0);
                }
            }
        }
        if content_len > 0 {
            let mut req_body = vec![0u8; content_len];
            reader.read_exact(&mut req_body).unwrap();
        }

        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = stream.shutdown(Shutdown::Write);
        let mut eof_buf = [0u8; 64];
        while let Ok(n) = reader.read(&mut eof_buf) {
            if n == 0 {
                break;
            }
        }
        req_line
    })
}

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

    let server_handle = serve_single_mock_http(
        mock_listener,
        "application/json",
        r#"{"id":"msg_mock_01","type":"message","content":"ok"}"#,
    );

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

#[test]
fn inspect_api_supports_gemini_cli_and_ignores_x_goog_api_key_auth_header() {
    let mock_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mock_port = mock_listener.local_addr().unwrap().port();

    let server_handle = serve_single_mock_http(
        mock_listener,
        "text/event-stream",
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"gemini_ok\"}]}}]}\n\n",
    );

    let bin = env!("CARGO_BIN_EXE_leaktap");
    let tmp = TempDir::new().unwrap();
    let wiretap_log = tmp.path().join("gemini_tap.jsonl");
    let fake_gemini_auth = format!("AIza{}", "SyDa9B8c7D6e5F4g3H2j1K0lMnOpQrStUvWx");
    let fake_aws = format!("AKIA{}", "9F28Q7M4K1L8Z3P6");

    let payload = format!(
        r#"{{"contents":[{{"role":"user","parts":[{{"text":"deploy key {fake_aws}"}}]}}]}}"#
    );
    let payload_file = tmp.path().join("gemini_payload.json");
    fs::write(&payload_file, &payload).unwrap();

    #[cfg(unix)]
    let child_cmd: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        format!(
            "curl -sS --noproxy '*' -X POST \"$GOOGLE_GEMINI_BASE_URL/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse\" -H 'x-goog-api-key: {fake_gemini_auth}' -H 'User-Agent: GeminiCLI/0.45 (dev@corp-internal.io)' -H 'Content-Type: application/json' --data-binary @{}",
            payload_file.display()
        ),
    ];

    #[cfg(windows)]
    let child_cmd: Vec<String> = vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "curl.exe -sS --noproxy '*' -X POST \"$env:GOOGLE_GEMINI_BASE_URL/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse\" -H \"x-goog-api-key: {fake_gemini_auth}\" -H \"User-Agent: GeminiCLI/0.45 (dev@corp-internal.io)\" -H \"Content-Type: application/json\" --data-binary \"@{}\"",
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
            "LEAKTAP_UPSTREAM_GEMINI_URL",
            format!("http://127.0.0.1:{mock_port}"),
        )
        .output()
        .expect("run leaktap tap --inspect-api for gemini");

    let req_line = server_handle.join().unwrap();
    assert!(
        req_line.contains("/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"),
        "unexpected upstream path: {req_line}"
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("gemini_ok"),
        "unexpected SSE stdout: {stdout}"
    );

    let log_content = fs::read_to_string(&wiretap_log).unwrap();
    assert!(log_content.contains("API POST -> gemini"));
    assert!(log_content.contains("header-email-leak"));
    assert!(log_content.contains("secret_in_prompt"));
    // x-goog-api-key is Gemini's standard auth header, so it must NOT trigger header-secret-leak
    assert!(
        !log_content.contains("header-secret-leak"),
        "unexpected false positive on x-goog-api-key:\n{log_content}"
    );
    assert!(!log_content.contains(&fake_aws));
    assert!(!log_content.contains(&fake_gemini_auth));
}

#[test]
fn scan_and_tap_support_antigravity_cli_paths_and_env_preservation() {
    let bin = env!("CARGO_BIN_EXE_leaktap");
    let fake_home = TempDir::new().unwrap();
    let fake_workspace = TempDir::new().unwrap();

    // 1. Antigravity CLI transcript inside ~/.gemini/antigravity-cli/brain/<id>/.system_generated/logs/
    let agy_logs = fake_home
        .path()
        .join(".gemini/antigravity-cli/brain/conv-123/.system_generated/logs");
    fs::create_dir_all(&agy_logs).unwrap();
    let fake_aws = format!("AKIA{}", "7Q29M4K8L1Z3P6R2");
    fs::write(
        agy_logs.join("transcript.jsonl"),
        format!(r#"{{"type":"USER_INPUT","content":"aws key is {fake_aws}"}}"#),
    )
    .unwrap();

    // 2. Antigravity CLI workspace MCP config at .agents/mcp_config.json
    let agents_dir = fake_workspace.path().join(".agents");
    fs::create_dir_all(&agents_dir).unwrap();
    fs::write(
        agents_dir.join("mcp_config.json"),
        r#"{"mcpServers":{"agy-db":{"command":"npx","args":["-y","@org/db-mcp"]}}}"#,
    )
    .unwrap();

    let scan_out = Command::new(bin)
        .current_dir(fake_workspace.path())
        .args(["scan", "--format", "json"])
        .env("HOME", fake_home.path())
        .env("USERPROFILE", fake_home.path())
        .output()
        .expect("run default leaktap scan for Antigravity CLI");

    assert!(
        scan_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan_out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&scan_out.stdout).unwrap();
    assert_eq!(report["summary"]["unique_secrets"], 1);
    assert_eq!(report["summary"]["mcp_risks"], 1);

    // 3. `leaktap tap --scrub-env -- agy` preserves GEMINI_API_KEY while scrubbing unrelated secrets
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = TempDir::new().unwrap();
        let mock_agy = bin_dir.path().join("agy");
        fs::write(
            &mock_agy,
            "#!/bin/sh\nprintf 'GEMINI=%s|STRIPE=%s\\n' \"$GEMINI_API_KEY\" \"$STRIPE_SECRET_KEY\"\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&mock_agy).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&mock_agy, perms).unwrap();

        let fake_gemini = format!("AIza{}", "SyDa9B8c7D6e5F4g3H2j1K0lMnOpQrStUvWx");
        let fake_stripe = format!("sk_live_{}", "9f8e7d6c5b4a392817263544");
        let new_path = format!(
            "{}:{}",
            bin_dir.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let tap_out = Command::new(bin)
            .args([
                "tap",
                "--scrub-env",
                "--no-net-watch",
                "--no-live-log",
                "--quiet",
                "--",
                mock_agy.to_str().unwrap(),
            ])
            .env("PATH", new_path)
            .env("GEMINI_API_KEY", &fake_gemini)
            .env("STRIPE_SECRET_KEY", &fake_stripe)
            .output()
            .expect("run leaktap tap --scrub-env -- agy");

        assert!(tap_out.status.success());
        let stdout = String::from_utf8(tap_out.stdout).unwrap();
        assert!(
            stdout.contains(&format!("GEMINI={fake_gemini}|STRIPE=")),
            "expected GEMINI_API_KEY preserved and STRIPE_SECRET_KEY scrubbed, got: {stdout}"
        );
        assert!(!stdout.contains(&fake_stripe));
    }

    // 4. Markdown-wrapped DB URIs (`postgres://...`) hash identically to raw `.env` URIs,
    //    do not trigger false-positive pii-email on `user:pass@host`, and marketplace caches are ignored.
    let cache_dir = fake_home
        .path()
        .join(".gemini/antigravity-cli/cache/marketplaces");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("marketplace.json"),
        r#"{"vendor_contact":"devrel@grafana.com"}"#,
    )
    .unwrap();

    let db_uri = "postgres://app_admin:Pr0dDbPass_987654321@pg-primary.corp.internal:5432/orders";
    fs::write(
        agy_logs.join("transcript_full.jsonl"),
        format!(
            "{{\"content\":\"DATABASE_URL={db_uri}\"}}\n{{\"content\":\"- `DATABASE_URL`: `{db_uri}`\"}}\n"
        ),
    )
    .unwrap();

    let scan_out2 = Command::new(bin)
        .current_dir(fake_workspace.path())
        .args(["scan", "--format", "json"])
        .env("HOME", fake_home.path())
        .env("USERPROFILE", fake_home.path())
        .output()
        .expect("run scan with markdown db uri and marketplace cache");
    assert!(scan_out2.status.success());
    let report2: serde_json::Value = serde_json::from_slice(&scan_out2.stdout).unwrap();
    // 1 AWS key + 1 deduplicated Database URI = 2 unique secrets (not 3)
    assert_eq!(report2["summary"]["unique_secrets"], 2);
    // 0 metadata exposures (neither marketplace.json nor user:pass@host/hostname inside database-uri should match)
    assert_eq!(report2["summary"]["metadata_exposures"], 0);
}

#[test]
fn claude_live_e2e_regressions_proxy_forwarding_backups_and_oauth_env() {
    let bin = env!("CARGO_BIN_EXE_leaktap");

    // 1. Verify `--inspect-api` honors `HTTP_PROXY` (with percent-encoded Basic auth) + chunked SSE streaming
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let proxy_handle = thread::spawn(move || {
        let (mut stream, _) = proxy_listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut req_line = String::new();
        reader.read_line(&mut req_line).unwrap();

        let mut proxy_auth = String::new();
        let mut content_len = 0usize;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("proxy-authorization") {
                    proxy_auth = v.trim().to_string();
                }
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse::<usize>().unwrap_or(0);
                }
            }
        }
        if content_len > 0 {
            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body).unwrap();
        }

        let chunk = "data: {\"type\":\"message_start\",\"proxy_ok\":true}\n\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            chunk.len(),
            chunk
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = stream.shutdown(Shutdown::Write);
        let mut eof_buf = [0u8; 64];
        while let Ok(n) = reader.read(&mut eof_buf) {
            if n == 0 {
                break;
            }
        }
        (req_line, proxy_auth)
    });

    let tmp = TempDir::new().unwrap();
    let wiretap_log = tmp.path().join("claude_proxy_tap.jsonl");
    let payload_file = tmp.path().join("claude_payload.json");
    fs::write(
        &payload_file,
        r#"{"model":"claude-sonnet-4-5","stream":true}"#,
    )
    .unwrap();

    #[cfg(unix)]
    let child_cmd: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        format!(
            "curl -sS --noproxy '*' -X POST \"$ANTHROPIC_BASE_URL/v1/messages?beta=true\" -H 'Content-Type: application/json' --data-binary @{}",
            payload_file.display()
        ),
    ];

    #[cfg(windows)]
    let child_cmd: Vec<String> = vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "curl.exe -sS --noproxy '*' -X POST \"$env:ANTHROPIC_BASE_URL/v1/messages?beta=true\" -H \"Content-Type: application/json\" --data-binary \"@{}\"",
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

    let out = Command::new(bin)
        .args(&args)
        .env(
            "LEAKTAP_UPSTREAM_ANTHROPIC_URL",
            "http://api.anthropic.mock:8080",
        )
        .env(
            "HTTP_PROXY",
            format!("http://proxy_user:proxy%40pass@127.0.0.1:{proxy_port}"),
        )
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("run leaktap tap through mock proxy");

    let (req_line, proxy_auth) = proxy_handle.join().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        req_line.contains("POST http://api.anthropic.mock:8080/v1/messages?beta=true HTTP/1.1"),
        "unexpected proxy request line: {req_line}"
    );
    assert_eq!(proxy_auth, "Basic cHJveHlfdXNlcjpwcm94eUBwYXNz");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("proxy_ok"),
        "expected streamed SSE chunk, got: {stdout}"
    );

    // 2. Verify `~/.claude/backups/` is ignored during default scan
    let fake_home = TempDir::new().unwrap();
    let backups_dir = fake_home.path().join(".claude/backups");
    fs::create_dir_all(&backups_dir).unwrap();
    let fake_anth_key = format!("sk-ant-api03-{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    fs::write(
        backups_dir.join("claude_backup.json"),
        format!(r#"{{"primaryApiKey":"{fake_anth_key}"}}"#),
    )
    .unwrap();

    let scan_out = Command::new(bin)
        .current_dir(tmp.path())
        .args(["scan", "--format", "json"])
        .env("HOME", fake_home.path())
        .env("USERPROFILE", fake_home.path())
        .output()
        .expect("run scan with .claude/backups");
    assert!(scan_out.status.success());
    let report: Value = serde_json::from_slice(&scan_out.stdout).unwrap();
    assert_eq!(report["summary"]["unique_secrets"], 0);

    // 3. Verify `CLAUDE_CODE_OAUTH_TOKEN` is preserved under `leaktap tap --scrub-env -- claude`
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = TempDir::new().unwrap();
        let mock_claude = bin_dir.path().join("claude");
        fs::write(
            &mock_claude,
            "#!/bin/sh\nprintf 'OAUTH=%s|STRIPE=%s\\n' \"$CLAUDE_CODE_OAUTH_TOKEN\" \"$STRIPE_SECRET_KEY\"\n",
        )
        .unwrap();
        let mut perms = fs::metadata(&mock_claude).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&mock_claude, perms).unwrap();

        let fake_oauth = "sk-ant-oat01-9f8e7d6c5b4a392817263544aabbccdd";
        let fake_stripe = format!("sk_live_{}", "9f8e7d6c5b4a392817263544");

        let tap_out = Command::new(bin)
            .args([
                "tap",
                "--scrub-env",
                "--no-net-watch",
                "--no-live-log",
                "--quiet",
                "--",
                mock_claude.to_str().unwrap(),
            ])
            .env("CLAUDE_CODE_OAUTH_TOKEN", fake_oauth)
            .env("STRIPE_SECRET_KEY", &fake_stripe)
            .output()
            .expect("run leaktap tap --scrub-env -- claude");

        assert!(tap_out.status.success());
        let tap_stdout = String::from_utf8(tap_out.stdout).unwrap();
        assert!(
            tap_stdout.contains(&format!("OAUTH={fake_oauth}|STRIPE=")),
            "expected CLAUDE_CODE_OAUTH_TOKEN preserved, got: {tap_stdout}"
        );
        assert!(!tap_stdout.contains(&fake_stripe));
    }
}
