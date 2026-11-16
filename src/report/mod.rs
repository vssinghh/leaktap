pub mod json;
pub mod sarif;
pub mod terminal;

use crate::mcp_audit::McpFinding;
use crate::rules::Severity;
use crate::scanner::TranscriptScanResult;
use std::time::Duration;

pub struct FullScanReport {
    pub roots: Vec<String>,
    pub mcp_files_scanned: usize,
    pub mcp_bytes_scanned: u64,
    pub duration: Duration,
    pub transcripts: TranscriptScanResult,
    pub mcp_findings: Vec<McpFinding>,
}

impl FullScanReport {
    pub fn highest_severity(&self) -> Option<Severity> {
        let s1 = self
            .transcripts
            .secret_findings
            .iter()
            .map(|f| f.severity)
            .max();
        let s2 = self
            .transcripts
            .pii_findings
            .iter()
            .map(|f| f.severity)
            .max();
        let s3 = self.mcp_findings.iter().map(|f| f.severity).max();
        [s1, s2, s3].into_iter().flatten().max()
    }

    pub fn total_findings(&self) -> usize {
        self.transcripts.secret_findings.len()
            + self.transcripts.pii_findings.len()
            + self.mcp_findings.len()
    }
}
