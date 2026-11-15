use crate::discovery::shorten_home;
use crate::rules::{RuleCategory, RuleEngine, Severity};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct FileHit {
    pub file: PathBuf,
    pub display_file: String,
    pub line: usize,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub category: RuleCategory,
    pub masked: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptFinding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub category: RuleCategory,
    pub masked: String,
    pub fingerprint: String,
    pub first_file: String,
    pub first_path: PathBuf,
    pub first_line: usize,
    pub occurrences: usize,
    pub distinct_files: usize,
}

#[derive(Debug, Default)]
pub struct TranscriptScanResult {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub secret_findings: Vec<TranscriptFinding>,
    pub pii_findings: Vec<TranscriptFinding>,
}

struct PerFileResult {
    bytes: u64,
    hits: Vec<FileHit>,
}

pub fn scan_transcripts(files: &[PathBuf], engine: &RuleEngine) -> TranscriptScanResult {
    let per_file: Vec<PerFileResult> = files
        .par_iter()
        .filter_map(|path| scan_single_file(path, engine))
        .collect();

    let files_scanned = per_file.len();
    let mut bytes_scanned = 0u64;

    // Deduplicate hits by fingerprint while preserving earliest deterministic hit
    let mut grouped: HashMap<String, (TranscriptFinding, HashSet<PathBuf>)> = HashMap::new();

    for pf in per_file {
        bytes_scanned += pf.bytes;
        for hit in pf.hits {
            let entry = grouped.entry(hit.fingerprint.clone()).or_insert_with(|| {
                let mut set = HashSet::new();
                set.insert(hit.file.clone());
                (
                    TranscriptFinding {
                        rule_id: hit.rule_id,
                        rule_name: hit.rule_name,
                        severity: hit.severity,
                        category: hit.category,
                        masked: hit.masked.clone(),
                        fingerprint: hit.fingerprint.clone(),
                        first_file: hit.display_file.clone(),
                        first_path: hit.file.clone(),
                        first_line: hit.line,
                        occurrences: 0,
                        distinct_files: 1,
                    },
                    set,
                )
            });
            entry.0.occurrences += 1;
            entry.1.insert(hit.file);
            entry.0.distinct_files = entry.1.len();
        }
    }

    let mut secret_findings = Vec::new();
    let mut pii_findings = Vec::new();

    for (_, (finding, _)) in grouped {
        match finding.category {
            RuleCategory::Secret => secret_findings.push(finding),
            RuleCategory::Pii => pii_findings.push(finding),
        }
    }

    // Sort highest severity first, then occurrence count descending, then path
    let sorter = |a: &TranscriptFinding, b: &TranscriptFinding| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.first_file.cmp(&b.first_file))
            .then_with(|| a.first_line.cmp(&b.first_line))
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

fn scan_single_file(path: &Path, engine: &RuleEngine) -> Option<PerFileResult> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut buf = Vec::with_capacity(4096);
    let mut line_num = 0usize;
    let mut total_bytes = 0u64;
    let mut hits = Vec::new();
    let display_file = shorten_home(path);

    loop {
        buf.clear();
        let bytes_read = match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        line_num += 1;
        total_bytes += bytes_read as u64;

        // Skip binary files immediately if NUL byte encountered on line 1
        if line_num == 1 && buf.contains(&0) {
            return None;
        }

        let text = String::from_utf8_lossy(&buf);
        for m in engine.scan_text(&text) {
            hits.push(FileHit {
                file: path.to_path_buf(),
                display_file: display_file.clone(),
                line: line_num,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                category: m.category,
                masked: m.masked,
                fingerprint: m.fingerprint,
            });
        }
    }

    Some(PerFileResult {
        bytes: total_bytes,
        hits,
    })
}
