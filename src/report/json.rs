use crate::mcp_audit::McpFinding;
use crate::report::FullScanReport;
use crate::scanner::TranscriptFinding;
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    version: &'static str,
    files_scanned: usize,
    mcp_configs_scanned: usize,
    bytes_scanned: u64,
    duration_ms: u128,
    summary: JsonSummary,
    secrets: &'a [TranscriptFinding],
    mcp_risks: &'a [McpFinding],
    metadata_exposures: &'a [TranscriptFinding],
}

#[derive(Serialize)]
struct JsonSummary {
    unique_secrets: usize,
    mcp_risks: usize,
    metadata_exposures: usize,
}

pub fn render_scan_json(report: &FullScanReport) -> String {
    let payload = JsonReport {
        tool: "leaktap",
        version: env!("CARGO_PKG_VERSION"),
        files_scanned: report.transcripts.files_scanned,
        mcp_configs_scanned: report.mcp_files_scanned,
        bytes_scanned: report.transcripts.bytes_scanned + report.mcp_bytes_scanned,
        duration_ms: report.duration.as_millis(),
        summary: JsonSummary {
            unique_secrets: report.transcripts.secret_findings.len(),
            mcp_risks: report.mcp_findings.len(),
            metadata_exposures: report.transcripts.pii_findings.len(),
        },
        secrets: &report.transcripts.secret_findings,
        mcp_risks: &report.mcp_findings,
        metadata_exposures: &report.transcripts.pii_findings,
    };

    serde_json::to_string_pretty(&payload).expect("serializable JSON report")
}
