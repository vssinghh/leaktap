use crate::discovery::shorten_home;
use crate::rules::{RuleCategory, RuleEngine, Severity};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const MAX_SQLITE_SCAN_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SQLITE_STREAM_CHUNK_BYTES: usize = 256 * 1024;
const SQLITE_MAX_RUN_BYTES: usize = 512 * 1024;
const SQLITE_OVERLAP_BYTES: usize = 2048;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingLocation {
    pub file: String,
    #[serde(skip_serializing)]
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileHit {
    pub file: PathBuf,
    pub display_file: String,
    pub line: usize,
    pub column: usize,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub category: RuleCategory,
    pub masked: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub category: RuleCategory,
    pub masked: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_detail: Option<String>,
    pub first_file: String,
    pub first_path: PathBuf,
    pub first_line: usize,
    pub first_column: usize,
    pub occurrences: usize,
    pub distinct_files: usize,
    pub locations: Vec<FindingLocation>,
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

struct GroupedEntry {
    finding: TranscriptFinding,
    files: HashSet<PathBuf>,
    loc_set: BTreeSet<(String, usize, usize, PathBuf)>,
}

pub fn scan_transcripts(files: &[PathBuf], engine: &RuleEngine) -> TranscriptScanResult {
    let per_file: Vec<PerFileResult> = files
        .par_iter()
        .filter_map(|path| scan_single_file(path, engine))
        .collect();

    let files_scanned = per_file.len();
    let mut bytes_scanned = 0u64;

    let mut grouped: HashMap<String, GroupedEntry> = HashMap::new();

    for pf in per_file {
        bytes_scanned += pf.bytes;
        for hit in pf.hits {
            let entry = grouped.entry(hit.fingerprint.clone()).or_insert_with(|| {
                let mut files_set = HashSet::new();
                files_set.insert(hit.file.clone());
                let mut loc_set = BTreeSet::new();
                loc_set.insert((
                    hit.display_file.clone(),
                    hit.line,
                    hit.column,
                    hit.file.clone(),
                ));
                GroupedEntry {
                    finding: TranscriptFinding {
                        rule_id: hit.rule_id.clone(),
                        rule_name: hit.rule_name.clone(),
                        severity: hit.severity,
                        category: hit.category,
                        masked: hit.masked.clone(),
                        fingerprint: hit.fingerprint.clone(),
                        secret_key: hit.secret_key.clone(),
                        verified: None,
                        verification_detail: None,
                        first_file: hit.display_file.clone(),
                        first_path: hit.file.clone(),
                        first_line: hit.line,
                        first_column: hit.column,
                        occurrences: 0,
                        distinct_files: 1,
                        locations: Vec::new(),
                    },
                    files: files_set,
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
            .then_with(|| a.first_line.cmp(&b.first_line))
            .then_with(|| a.first_column.cmp(&b.first_column))
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
    scan_single_file_impl(path, path, None, engine)
}

/// Scans `disk_path` (such as a materialized staged git blob) while attributing hits and
/// path-scoped `.leaktap.toml` rules/allowlists to `logical_path`.
pub fn scan_single_file_as(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    engine: &RuleEngine,
) -> Option<(u64, Vec<FileHit>)> {
    scan_single_file_impl(disk_path, logical_path, display_override, engine)
        .map(|pf| (pf.bytes, pf.hits))
}

fn scan_single_file_impl(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    engine: &RuleEngine,
) -> Option<PerFileResult> {
    if is_sqlite_extension(logical_path) || is_sqlite_extension(disk_path) {
        return scan_sqlite_strings_as(disk_path, logical_path, display_override, engine);
    }

    let display_file = display_override
        .map(str::to_string)
        .unwrap_or_else(|| shorten_home(logical_path));

    if logical_path.file_name().and_then(|n| n.to_str()) == Some(".claude.json") {
        if let Some(res) = scan_claude_json_file(disk_path, logical_path, &display_file, engine) {
            return Some(res);
        }
    }

    let file = File::open(disk_path).ok()?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut buf = Vec::with_capacity(4096);
    let mut pending_line: Option<(Vec<u8>, usize)> = None;
    let mut line_num = 0usize;
    let mut total_bytes = 0u64;
    let mut hits = Vec::new();
    let mut doc_hints: Option<crate::rules::DocHints> = None;
    let mut k8s_tracker = crate::rules::K8sDataTracker::default();
    let allow_inline_ignore = engine.honors_inline_ignore()
        && crate::rules::path_allows_inline_ignore(Some(logical_path));
    let mut pending_ignore: Option<(usize, crate::rules::InlineIgnoreSpec)> = None;

    loop {
        buf.clear();
        let start_line = if let Some((saved, saved_line)) = pending_line.take() {
            buf.extend_from_slice(&saved);
            saved_line
        } else {
            let bytes_read = match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            line_num += 1;
            total_bytes += bytes_read as u64;
            line_num
        };

        if start_line == 1 {
            if is_sqlite_or_wal_magic(&buf) {
                return scan_sqlite_strings_as(disk_path, logical_path, display_override, engine);
            }
            if buf.starts_with(&[0xFF, 0xFE]) || buf.starts_with(&[0xFE, 0xFF]) {
                return scan_utf16_file_as(disk_path, logical_path, &display_file, engine);
            }
            if buf.contains(&0) {
                if looks_like_utf16(&buf) {
                    return scan_utf16_file_as(disk_path, logical_path, &display_file, engine);
                }
                if buf.len() < 8 {
                    let mut sample = [0u8; 64];
                    if let Ok(mut peek_f) = File::open(disk_path) {
                        if let Ok(n) = peek_f.read(&mut sample) {
                            if looks_like_utf16(&sample[..n]) {
                                return scan_utf16_file_as(
                                    disk_path,
                                    logical_path,
                                    &display_file,
                                    engine,
                                );
                            }
                        }
                    }
                }
                return scan_binary_strings_as(disk_path, logical_path, &display_file, engine);
            }
        } else if buf.contains(&0) {
            return scan_binary_strings_as(disk_path, logical_path, &display_file, engine);
        }

        // Coalesce physical multi-line PEM/PGP/PuTTY private keys, wrapped Base64, YAML block scalars,
        // and structured `xxd` / `od -tx1` / `hexdump -C` blocks without crossing JSONL line boundaries.
        if is_multiline_pem_header(&buf) {
            while buf.len() < 32 * 1024 {
                let prev_len = buf.len();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(extra) => {
                        line_num += 1;
                        total_bytes += extra as u64;
                        let added = &buf[prev_len..];
                        if contains_subslice(added, b"-----END ") {
                            break;
                        }
                        if !is_pem_or_pgp_continuation_line(added) {
                            pending_line = Some((added.to_vec(), line_num));
                            buf.truncate(prev_len);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        } else if is_multiline_putty_header(&buf) {
            while buf.len() < 32 * 1024 {
                let prev_len = buf.len();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(extra) => {
                        line_num += 1;
                        total_bytes += extra as u64;
                        let added = &buf[prev_len..];
                        if contains_subslice(added, b"Private-MAC:")
                            || contains_subslice(added, b"Private-Hash:")
                        {
                            break;
                        }
                        if !is_putty_continuation_line(added) {
                            pending_line = Some((added.to_vec(), line_num));
                            buf.truncate(prev_len);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        } else if let Some(parent_indent) = yaml_block_scalar_parent_indent(&buf) {
            while buf.len() < 32 * 1024 {
                let prev_len = buf.len();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(extra) => {
                        line_num += 1;
                        total_bytes += extra as u64;
                        let added = &buf[prev_len..];
                        if !is_yaml_block_scalar_continuation(added, parent_indent) {
                            pending_line = Some((added.to_vec(), line_num));
                            buf.truncate(prev_len);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        } else if std::str::from_utf8(&buf)
            .ok()
            .is_some_and(crate::rules::is_hexdump_line)
        {
            while buf.len() < 32 * 1024 {
                let prev_len = buf.len();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(extra) => {
                        line_num += 1;
                        total_bytes += extra as u64;
                        let added = &buf[prev_len..];
                        let is_cont = std::str::from_utf8(added)
                            .ok()
                            .is_some_and(crate::rules::is_hexdump_line);
                        if !is_cont {
                            pending_line = Some((added.to_vec(), line_num));
                            buf.truncate(prev_len);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        } else if is_wrapped_base64_start_line(&buf) {
            while buf.len() < MULTILINE_B64_COALESCE_CAP {
                let prev_len = buf.len();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(extra) => {
                        line_num += 1;
                        total_bytes += extra as u64;
                        let added = &buf[prev_len..];
                        if !is_wrapped_base64_continuation_line(added) {
                            pending_line = Some((added.to_vec(), line_num));
                            buf.truncate(prev_len);
                            break;
                        }
                        let trimmed_added = trim_ascii_bytes(added);
                        let unquoted_added = trim_trailing_quotes(trimmed_added);
                        if unquoted_added.ends_with(b"=")
                            || trimmed_added.ends_with(b"\"")
                            || trimmed_added.ends_with(b"'")
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let text = String::from_utf8_lossy(&buf);
        let needs_doc_hints = doc_hints.is_some()
            || text.contains("private_key_id")
            || text.contains("\"kty\"")
            || text.contains("'kty'")
            || text.contains("\"d\"")
            || text.contains("\"k\"")
            || text.contains("kind:")
            || text.contains("\"kind\"")
            || text.contains("data:")
            || text.contains("stringData:");
        let mut line_hints = if needs_doc_hints {
            *doc_hints.get_or_insert_with(|| file_doc_hints(disk_path))
        } else {
            crate::rules::DocHints::default()
        };
        if line_hints.is_k8s_secret_manifest
            || k8s_tracker.is_tracking()
            || text.contains("kind:")
            || text.contains("\"kind\"")
        {
            for sub in text.lines() {
                let (in_d, in_sd) = k8s_tracker.observe_line(sub);
                line_hints.in_k8s_data_entry |= in_d;
                line_hints.in_k8s_string_data_entry |= in_sd;
            }
            line_hints.is_k8s_secret_manifest =
                k8s_tracker.is_active_secret_doc(line_hints.is_k8s_secret_manifest);
        }

        for m in engine.scan_text_with_hints(&text, Some(logical_path), line_hints) {
            let (hit_line, hit_col) = compute_line_and_column(&text, start_line, m.start);
            if allow_inline_ignore
                && pending_ignore.as_ref().is_some_and(|(target_ln, spec)| {
                    *target_ln == hit_line && crate::rules::match_suppressed_by_spec(spec, &m)
                })
            {
                continue;
            }
            hits.push(FileHit {
                file: logical_path.to_path_buf(),
                display_file: display_file.clone(),
                line: hit_line,
                column: hit_col,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                category: m.category,
                masked: m.masked,
                fingerprint: m.fingerprint,
                secret_key: m.secret_key,
            });
        }
        if allow_inline_ignore {
            let last_ln = if pending_line.is_some() {
                line_num.saturating_sub(1)
            } else {
                line_num
            };
            let last_sub = text.lines().last().unwrap_or("");
            pending_ignore = crate::rules::parse_inline_ignore_directive(last_sub, true)
                .map(|spec| (last_ln + 1, spec));
        }
    }

    Some(PerFileResult {
        bytes: total_bytes,
        hits,
    })
}

pub const MULTILINE_B64_COALESCE_CAP: usize = crate::rules::MAX_B64_CANDIDATE_CHARS + 8192;

pub fn compute_line_and_column(
    chunk: &str,
    base_line: usize,
    byte_offset: usize,
) -> (usize, usize) {
    let clamped = byte_offset.min(chunk.len());
    let prefix = &chunk[..clamped];
    let nl_count = prefix.bytes().filter(|&b| b == b'\n').count();
    let after_last_nl = match prefix.rfind('\n') {
        Some(pos) => &prefix[pos + 1..],
        None => prefix,
    };
    let col = after_last_nl.chars().count() + 1;
    (base_line.max(1) + nl_count, col.max(1))
}

pub fn contains_gcp_sa_markers(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("service_account") || lower.contains(".iam.gserviceaccount.com")
}

pub fn file_has_gcp_sa_markers(path: &Path) -> bool {
    file_doc_hints(path).has_gcp_sa
}

pub fn file_doc_hints(path: &Path) -> crate::rules::DocHints {
    let Ok(text) = read_text_auto_encoding(path, 4 * 1024 * 1024) else {
        return crate::rules::DocHints::default();
    };
    crate::rules::DocHints::from_text(&text)
}

/// Scans printable ASCII strings (`>= 12` bytes) inside compiled ELF/Mach-O/PE/Wasm or binary files
/// up to 32 MiB so hardcoded secrets (`sk_live_...`, `AKIA...`) in hook/MCP/plugin binaries are detected.
fn scan_binary_strings_as(
    disk_path: &Path,
    logical_path: &Path,
    display_file: &str,
    engine: &RuleEngine,
) -> Option<PerFileResult> {
    let meta = fs::metadata(disk_path).ok()?;
    if meta.len() > 32 * 1024 * 1024 {
        return None;
    }
    let mut file = File::open(disk_path).ok()?;
    let mut io_buf = vec![0u8; 64 * 1024];
    let mut run_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut hits = Vec::new();
    let mut total_bytes = 0u64;

    let flush_run = |run: &[u8], out: &mut Vec<FileHit>| {
        let Ok(s) = std::str::from_utf8(run) else {
            return;
        };
        for m in engine.scan_text_for_path(s, Some(logical_path)) {
            if m.category != RuleCategory::Secret {
                continue;
            }
            out.push(FileHit {
                file: logical_path.to_path_buf(),
                display_file: display_file.to_string(),
                line: 1,
                column: 1,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                category: m.category,
                masked: m.masked,
                fingerprint: m.fingerprint,
                secret_key: m.secret_key,
            });
        }
    };

    loop {
        let n = match file.read(&mut io_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total_bytes += n as u64;
        for &b in &io_buf[..n] {
            if b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                run_buf.push(b);
                if run_buf.len() >= SQLITE_MAX_RUN_BYTES {
                    flush_run(&run_buf, &mut hits);
                    let keep = run_buf.len().saturating_sub(SQLITE_OVERLAP_BYTES);
                    run_buf.drain(0..keep);
                }
            } else {
                if run_buf.len() >= 12 {
                    flush_run(&run_buf, &mut hits);
                }
                run_buf.clear();
            }
        }
    }
    if run_buf.len() >= 12 {
        flush_run(&run_buf, &mut hits);
    }

    Some(PerFileResult {
        bytes: total_bytes,
        hits,
    })
}

/// Scans `.claude.json` prompt history and pasted contents while skipping CLI login metadata
/// (`oauthAccount`, `primaryApiKey`, `customApiKeyResponses`) on `~/.claude.json` and `mcpServers`
/// (which `mcp_audit.rs` inspects separately).
fn scan_claude_json_file(
    disk_path: &Path,
    logical_path: &Path,
    display_file: &str,
    engine: &RuleEngine,
) -> Option<PerFileResult> {
    let raw = read_text_auto_encoding(disk_path, 64 * 1024 * 1024).ok()?;
    let mut parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let root = parsed.as_object_mut()?;

    let is_home_file = crate::discovery::is_home_claude_state_file(logical_path)
        || crate::discovery::is_home_claude_state_file(disk_path);
    if is_home_file {
        root.remove("oauthAccount");
        root.remove("customApiKeyResponses");
        if root
            .get("primaryApiKey")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| s.starts_with("sk-ant-"))
        {
            root.remove("primaryApiKey");
        }
    }
    root.remove("pluginUsage");
    root.remove("mcpServers");
    if let Some(projects) = root
        .get_mut("projects")
        .and_then(serde_json::Value::as_object_mut)
    {
        for proj_val in projects.values_mut() {
            if let Some(proj_obj) = proj_val.as_object_mut() {
                proj_obj.remove("mcpServers");
            }
        }
    }

    let mut leaf_strings = Vec::new();
    collect_claude_json_strings(&parsed, &mut leaf_strings);

    let mut hits = Vec::new();
    for s in leaf_strings {
        let hints = crate::rules::DocHints::from_text(s);
        for m in engine.scan_text_with_hints(s, Some(logical_path), hints) {
            let needle = &s[m.start..m.end];
            let (line, column) = find_line_and_col_of_substr(&raw, needle).unwrap_or((1, 1));
            hits.push(FileHit {
                file: logical_path.to_path_buf(),
                display_file: display_file.to_string(),
                line,
                column,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                category: m.category,
                masked: m.masked,
                fingerprint: m.fingerprint,
                secret_key: m.secret_key,
            });
        }
    }

    Some(PerFileResult {
        bytes: raw.len() as u64,
        hits,
    })
}

fn collect_claude_json_strings<'a>(val: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match val {
        serde_json::Value::String(s) => {
            if s.len() >= 6 {
                out.push(s.as_str());
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_claude_json_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_claude_json_strings(v, out);
            }
        }
        _ => {}
    }
}

fn find_line_and_col_of_substr(haystack: &str, needle: &str) -> Option<(usize, usize)> {
    let probe = needle.lines().next().unwrap_or(needle);
    if probe.is_empty() {
        return None;
    }
    let idx = haystack.find(probe)?;
    Some(compute_line_and_column(haystack, 1, idx))
}

/// Reads a UTF-8 or UTF-16LE/BE text file up to `max_bytes`, automatically stripping any BOM.
pub fn read_text_auto_encoding(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} byte limit"),
        ));
    }
    let raw = fs::read(path)?;
    if raw.starts_with(&[0xFF, 0xFE])
        || raw.starts_with(&[0xFE, 0xFF])
        || (raw.contains(&0) && looks_like_utf16(&raw))
    {
        return Ok(decode_utf16_bytes(&raw));
    }
    let body = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
    match String::from_utf8(body.to_vec()) {
        Ok(s) => Ok(s),
        Err(e) => Ok(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

pub(crate) fn decode_utf16_with_endianness(raw: &[u8]) -> (bool, bool, String) {
    let (is_be, has_bom, body) = if let Some(stripped) = raw.strip_prefix(&[0xFF, 0xFE]) {
        (false, true, stripped)
    } else if let Some(stripped) = raw.strip_prefix(&[0xFE, 0xFF]) {
        (true, true, stripped)
    } else {
        let even_zeros = raw.iter().step_by(2).filter(|&&b| b == 0).count();
        let odd_zeros = raw.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        (even_zeros > odd_zeros, false, raw)
    };
    let mut units = Vec::with_capacity(body.len() / 2);
    for &pair in body.as_chunks::<2>().0 {
        let u = if is_be {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        };
        units.push(u);
    }
    let decoded = String::from_utf16_lossy(&units);
    let clean = decoded
        .strip_prefix('\u{FEFF}')
        .map(str::to_string)
        .unwrap_or(decoded);
    (is_be, has_bom, clean)
}

pub(crate) fn encode_utf16_with_endianness(text: &str, is_be: bool, has_bom: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + if has_bom { 2 } else { 0 });
    if has_bom {
        if is_be {
            out.extend_from_slice(&[0xFE, 0xFF]);
        } else {
            out.extend_from_slice(&[0xFF, 0xFE]);
        }
    }
    for u in text.encode_utf16() {
        let bytes = if is_be {
            u.to_be_bytes()
        } else {
            u.to_le_bytes()
        };
        out.extend_from_slice(&bytes);
    }
    out
}

fn decode_utf16_bytes(raw: &[u8]) -> String {
    decode_utf16_with_endianness(raw).2
}

pub(crate) fn looks_like_utf16(sample: &[u8]) -> bool {
    if sample.starts_with(&[0xFF, 0xFE]) || sample.starts_with(&[0xFE, 0xFF]) {
        return true;
    }
    if sample.len() < 8 {
        return false;
    }
    let check_len = sample.len().min(256) & !1;
    if check_len < 8 {
        return false;
    }
    let pairs = check_len / 2;
    let mut le_ascii = 0usize;
    let mut be_ascii = 0usize;
    for &chunk in sample[..check_len].as_chunks::<2>().0 {
        if chunk[1] == 0 && (chunk[0].is_ascii_graphic() || chunk[0].is_ascii_whitespace()) {
            le_ascii += 1;
        }
        if chunk[0] == 0 && (chunk[1].is_ascii_graphic() || chunk[1].is_ascii_whitespace()) {
            be_ascii += 1;
        }
    }
    le_ascii * 10 >= pairs * 7 || be_ascii * 10 >= pairs * 7
}

fn scan_utf16_file_as(
    disk_path: &Path,
    logical_path: &Path,
    display_file: &str,
    engine: &RuleEngine,
) -> Option<PerFileResult> {
    let meta = fs::metadata(disk_path).ok()?;
    if meta.len() > 16 * 1024 * 1024 {
        return None;
    }
    let raw = fs::read(disk_path).ok()?;
    let decoded = decode_utf16_bytes(&raw);
    let base_hints = crate::rules::DocHints::from_text(&decoded);
    let mut k8s_tracker = crate::rules::K8sDataTracker::default();
    let allow_inline_ignore = engine.honors_inline_ignore()
        && crate::rules::path_allows_inline_ignore(Some(logical_path));
    let mut pending_ignore: Option<(usize, crate::rules::InlineIgnoreSpec)> = None;
    let lines: Vec<&str> = decoded.lines().collect();
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let start_line = i + 1;
        let first = lines[i];
        let mut block = String::from(first);
        i += 1;
        if is_multiline_pem_header(first.as_bytes()) {
            block.push('\n');
            while i < lines.len() && block.len() < 32 * 1024 {
                let next = lines[i];
                if next.contains("-----END ") {
                    block.push_str(next);
                    block.push('\n');
                    i += 1;
                    break;
                }
                if !is_pem_or_pgp_continuation_line(next.as_bytes()) {
                    break;
                }
                block.push_str(next);
                block.push('\n');
                i += 1;
            }
        } else if is_multiline_putty_header(first.as_bytes()) {
            block.push('\n');
            while i < lines.len() && block.len() < 32 * 1024 {
                let next = lines[i];
                if next.contains("Private-MAC:") || next.contains("Private-Hash:") {
                    block.push_str(next);
                    block.push('\n');
                    i += 1;
                    break;
                }
                if !is_putty_continuation_line(next.as_bytes()) {
                    break;
                }
                block.push_str(next);
                block.push('\n');
                i += 1;
            }
        } else if let Some(parent_indent) = yaml_block_scalar_parent_indent(first.as_bytes()) {
            block.push('\n');
            while i < lines.len() && block.len() < 32 * 1024 {
                let next = lines[i];
                if !is_yaml_block_scalar_continuation(next.as_bytes(), parent_indent) {
                    break;
                }
                block.push_str(next);
                block.push('\n');
                i += 1;
            }
        } else if crate::rules::is_hexdump_line(first) {
            block.push('\n');
            while i < lines.len() && block.len() < 32 * 1024 {
                let next = lines[i];
                if !crate::rules::is_hexdump_line(next) {
                    break;
                }
                block.push_str(next);
                block.push('\n');
                i += 1;
            }
        } else if is_wrapped_base64_start_line(first.as_bytes()) {
            block.push('\n');
            while i < lines.len() && block.len() < MULTILINE_B64_COALESCE_CAP {
                let next = lines[i];
                if !is_wrapped_base64_continuation_line(next.as_bytes()) {
                    break;
                }
                block.push_str(next);
                block.push('\n');
                i += 1;
                let trimmed_next = trim_ascii_bytes(next.as_bytes());
                let unquoted_next = trim_trailing_quotes(trimmed_next);
                if unquoted_next.ends_with(b"=")
                    || trimmed_next.ends_with(b"\"")
                    || trimmed_next.ends_with(b"'")
                {
                    break;
                }
            }
        }

        let mut line_hints = base_hints;
        if line_hints.is_k8s_secret_manifest
            || k8s_tracker.is_tracking()
            || block.contains("kind:")
            || block.contains("\"kind\"")
        {
            for sub in block.lines() {
                let (in_d, in_sd) = k8s_tracker.observe_line(sub);
                line_hints.in_k8s_data_entry |= in_d;
                line_hints.in_k8s_string_data_entry |= in_sd;
            }
            line_hints.is_k8s_secret_manifest =
                k8s_tracker.is_active_secret_doc(line_hints.is_k8s_secret_manifest);
        }
        for m in engine.scan_text_with_hints(&block, Some(logical_path), line_hints) {
            let (hit_line, hit_col) = compute_line_and_column(&block, start_line, m.start);
            if allow_inline_ignore
                && pending_ignore.as_ref().is_some_and(|(target_ln, spec)| {
                    *target_ln == hit_line && crate::rules::match_suppressed_by_spec(spec, &m)
                })
            {
                continue;
            }
            hits.push(FileHit {
                file: logical_path.to_path_buf(),
                display_file: display_file.to_string(),
                line: hit_line,
                column: hit_col,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                category: m.category,
                masked: m.masked,
                fingerprint: m.fingerprint,
                secret_key: m.secret_key,
            });
        }
        if allow_inline_ignore {
            let last_ln = i;
            let last_sub = block.lines().last().unwrap_or("");
            pending_ignore = crate::rules::parse_inline_ignore_directive(last_sub, true)
                .map(|spec| (last_ln + 1, spec));
        }
    }
    Some(PerFileResult {
        bytes: raw.len() as u64,
        hits,
    })
}

fn scan_sqlite_strings_as(
    disk_path: &Path,
    logical_path: &Path,
    display_override: Option<&str>,
    engine: &RuleEngine,
) -> Option<PerFileResult> {
    let meta = fs::metadata(disk_path).ok()?;
    let display_file = display_override
        .map(str::to_string)
        .unwrap_or_else(|| shorten_home(logical_path));
    if meta.len() > MAX_SQLITE_SCAN_BYTES {
        eprintln!(
            "[leaktap:warn] Skipping oversized SQLite/WAL file {} ({} MB > {} MB limit)",
            display_file,
            meta.len() / (1024 * 1024),
            MAX_SQLITE_SCAN_BYTES / (1024 * 1024)
        );
        return None;
    }

    let mut hits = Vec::new();
    let mut seen_fps: HashSet<String> = HashSet::new();

    // 1. Primary pass: parse SQLite B-tree records (`0x0d` table leaf, `0x0a` WITHOUT ROWID/index leaf,
    // `0x02` WITHOUT ROWID/index interior pivot, plus `-wal` page frames and overflow page chains),
    // inserting `\n` between every column so adjacent row columns (`'composerData'`, `'sk_live_...'`)
    // never concatenate across word boundaries.
    scan_sqlite_btree_records(
        disk_path,
        logical_path,
        meta.len(),
        &display_file,
        engine,
        &mut seen_fps,
        &mut hits,
        None,
    );

    // 2. Secondary pass: stream printable runs across the raw file to catch deleted/freelist slack bytes,
    // deduplicating by secret fingerprint.
    let mut file = File::open(disk_path).ok()?;
    let mut io_buf = vec![0u8; SQLITE_STREAM_CHUNK_BYTES];
    let mut run_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut raw_hits = Vec::new();
    let mut total_bytes = 0u64;

    loop {
        let n = match file.read(&mut io_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total_bytes += n as u64;

        for &b in &io_buf[..n] {
            let is_text_byte = b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t';
            if is_text_byte {
                run_buf.push(b);
                if run_buf.len() >= SQLITE_MAX_RUN_BYTES {
                    scan_sqlite_chunk(&run_buf, logical_path, &display_file, engine, &mut raw_hits);
                    for h in raw_hits.drain(..) {
                        if seen_fps.insert(h.fingerprint.clone()) {
                            hits.push(h);
                        }
                    }
                    let keep_from = run_buf.len().saturating_sub(SQLITE_OVERLAP_BYTES);
                    run_buf.drain(0..keep_from);
                }
            } else {
                if run_buf.len() >= 16 {
                    scan_sqlite_chunk(&run_buf, logical_path, &display_file, engine, &mut raw_hits);
                    for h in raw_hits.drain(..) {
                        if seen_fps.insert(h.fingerprint.clone()) {
                            hits.push(h);
                        }
                    }
                }
                run_buf.clear();
            }
        }
    }

    if run_buf.len() >= 16 {
        scan_sqlite_chunk(&run_buf, logical_path, &display_file, engine, &mut raw_hits);
        for h in raw_hits.drain(..) {
            if seen_fps.insert(h.fingerprint.clone()) {
                hits.push(h);
            }
        }
    }

    Some(PerFileResult {
        bytes: total_bytes,
        hits,
    })
}

/// Extracts column-delimited text from a SQLite 3 database or `-wal` journal (up to `max_corpus_bytes`)
/// for live `--verify` secret extraction without breaking on >32 MiB binary DBs or concatenated columns.
pub(crate) fn extract_sqlite_text_corpus(
    disk_path: &Path,
    max_corpus_bytes: usize,
) -> Option<String> {
    let meta = fs::metadata(disk_path).ok()?;
    if meta.len() > MAX_SQLITE_SCAN_BYTES {
        return None;
    }
    let dummy_engine = RuleEngine::new(false);
    let mut seen_fps = HashSet::new();
    let mut dummy_hits = Vec::new();
    let mut corpus = Vec::with_capacity(max_corpus_bytes.min(256 * 1024));
    scan_sqlite_btree_records(
        disk_path,
        disk_path,
        meta.len(),
        "",
        &dummy_engine,
        &mut seen_fps,
        &mut dummy_hits,
        Some((&mut corpus, max_corpus_bytes)),
    );

    if corpus.len() < max_corpus_bytes {
        if let Ok(mut file) = File::open(disk_path) {
            let mut io_buf = vec![0u8; SQLITE_STREAM_CHUNK_BYTES];
            let mut run_buf: Vec<u8> = Vec::with_capacity(4096);
            'outer: loop {
                let n = match file.read(&mut io_buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                for &b in &io_buf[..n] {
                    if b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t') {
                        run_buf.push(b);
                    } else {
                        if run_buf.len() >= 12 {
                            let rem = max_corpus_bytes.saturating_sub(corpus.len());
                            if rem == 0 {
                                break 'outer;
                            }
                            let take = run_buf.len().min(rem);
                            corpus.extend_from_slice(&run_buf[..take]);
                            corpus.push(b'\n');
                        }
                        run_buf.clear();
                    }
                }
            }
            if run_buf.len() >= 12 && corpus.len() < max_corpus_bytes {
                let take = run_buf.len().min(max_corpus_bytes - corpus.len());
                corpus.extend_from_slice(&run_buf[..take]);
                corpus.push(b'\n');
            }
        }
    }

    Some(String::from_utf8_lossy(&corpus).into_owned())
}

#[allow(clippy::too_many_arguments)]
fn scan_sqlite_btree_records(
    disk_path: &Path,
    logical_path: &Path,
    file_len: u64,
    display_file: &str,
    engine: &RuleEngine,
    seen_fps: &mut HashSet<String>,
    hits: &mut Vec<FileHit>,
    mut corpus_out: Option<(&mut Vec<u8>, usize)>,
) {
    use std::collections::HashMap;
    use std::io::{Seek, SeekFrom};

    if file_len < 32 {
        return;
    }
    let Ok(mut file) = File::open(disk_path) else {
        return;
    };
    let mut magic_hdr = [0u8; 100];
    let hdr_read = file.read(&mut magic_hdr).unwrap_or(0);
    if hdr_read < 32 {
        return;
    }

    let is_wal = matches!(
        &magic_hdr[..4],
        [0x37, 0x7f, 0x06, 0x82] | [0x37, 0x7f, 0x06, 0x83]
    );
    let is_db = hdr_read == 100 && magic_hdr.starts_with(b"SQLite format 3\0");
    if !is_db && !is_wal {
        return;
    }

    let mut sibling_db_file: Option<File> = None;
    let mut sibling_db_pages: u32 = 0;

    let (page_size, reserved, text_encoding) = if is_db {
        let raw_ps = u16::from_be_bytes([magic_hdr[16], magic_hdr[17]]);
        let ps: usize = if raw_ps == 1 { 65536 } else { raw_ps as usize };
        let res = magic_hdr[20] as usize;
        let enc = u32::from_be_bytes([magic_hdr[56], magic_hdr[57], magic_hdr[58], magic_hdr[59]]);
        (ps, res, if matches!(enc, 1..=3) { enc } else { 1 })
    } else {
        let raw_ps = u32::from_be_bytes([magic_hdr[8], magic_hdr[9], magic_hdr[10], magic_hdr[11]]);
        let ps: usize = if raw_ps == 1 || raw_ps == 65536 {
            65536
        } else {
            raw_ps as usize
        };
        let mut res = 0usize;
        let mut enc = 1u32;
        if let Some(s_str) = disk_path.to_str().and_then(|s| s.strip_suffix("-wal")) {
            let sib_path = Path::new(s_str);
            if let Ok(mut sf) = File::open(sib_path) {
                let mut shdr = [0u8; 100];
                if sf.read_exact(&mut shdr).is_ok() && shdr.starts_with(b"SQLite format 3\0") {
                    res = shdr[20] as usize;
                    let senc = u32::from_be_bytes([shdr[56], shdr[57], shdr[58], shdr[59]]);
                    if matches!(senc, 1..=3) {
                        enc = senc;
                    }
                    if ps > 0 {
                        if let Ok(smeta) = sf.metadata() {
                            sibling_db_pages = (smeta.len() / ps as u64) as u32;
                        }
                    }
                    sibling_db_file = Some(sf);
                }
            }
        }
        (ps, res, enc)
    };

    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return;
    }
    if reserved >= page_size || page_size - reserved < 480 {
        return;
    }
    let usable = page_size - reserved;
    if usable <= 35 {
        return;
    }

    let mut wal_page_offsets: HashMap<u32, u64> = HashMap::new();
    let mut frames_to_visit: Vec<(u32, u64)> = Vec::new();

    if is_wal {
        let frame_stride = 24u64 + page_size as u64;
        let mut f_off = 32u64;
        let mut f_hdr = [0u8; 24];
        while f_off + frame_stride <= file_len {
            if file.seek(SeekFrom::Start(f_off)).is_err() || file.read_exact(&mut f_hdr).is_err() {
                break;
            }
            let pgno = u32::from_be_bytes([f_hdr[0], f_hdr[1], f_hdr[2], f_hdr[3]]);
            if pgno >= 1 {
                let page_data_off = f_off + 24;
                wal_page_offsets.insert(pgno, page_data_off);
                frames_to_visit.push((pgno, page_data_off));
            }
            f_off += frame_stride;
        }
    } else {
        let total_pages = (file_len / page_size as u64) as u32;
        for pgno in 1..=total_pages {
            frames_to_visit.push((pgno, (pgno as u64 - 1) * page_size as u64));
        }
    }

    let total_db_pages = if is_db {
        (file_len / page_size as u64) as u32
    } else {
        sibling_db_pages
    };

    let mut page_buf = vec![0u8; page_size];
    let mut ovf_buf = vec![0u8; page_size];
    let mut batch_buf: Vec<u8> = Vec::with_capacity(65536);
    let mut cell_hits = Vec::new();

    let flush_batch = |batch: &mut Vec<u8>,
                       seen: &mut HashSet<String>,
                       out_hits: &mut Vec<FileHit>,
                       tmp_hits: &mut Vec<FileHit>,
                       corpus: &mut Option<(&mut Vec<u8>, usize)>| {
        if batch.is_empty() {
            return;
        }
        if let Some((ref mut c_vec, max_c)) = corpus {
            let rem = max_c.saturating_sub(c_vec.len());
            if rem > 0 {
                let take = batch.len().min(rem);
                c_vec.extend_from_slice(&batch[..take]);
            }
        } else {
            tmp_hits.clear();
            scan_sqlite_chunk(batch, logical_path, display_file, engine, tmp_hits);
            for h in tmp_hits.drain(..) {
                if seen.insert(h.fingerprint.clone()) {
                    out_hits.push(h);
                }
            }
        }
        batch.clear();
    };

    for (page_num, page_off) in frames_to_visit {
        if let Some((ref c_vec, max_c)) = corpus_out {
            if c_vec.len() >= max_c {
                break;
            }
        }
        if file.seek(SeekFrom::Start(page_off)).is_err() || file.read_exact(&mut page_buf).is_err()
        {
            break;
        }
        let btree_hdr_off = if page_num == 1 { 100usize } else { 0usize };
        if btree_hdr_off + 8 > usable {
            continue;
        }
        let page_type = page_buf[btree_hdr_off];
        // 0x0d = table leaf, 0x0a = index / WITHOUT ROWID leaf, 0x02 = index / WITHOUT ROWID interior
        let hdr_len = match page_type {
            0x0d | 0x0a => 8usize,
            0x02 => 12usize,
            _ => continue,
        };
        if btree_hdr_off + hdr_len > usable {
            continue;
        }
        let cell_count =
            u16::from_be_bytes([page_buf[btree_hdr_off + 3], page_buf[btree_hdr_off + 4]]) as usize;
        let ptr_table_end = btree_hdr_off + hdr_len + cell_count.saturating_mul(2);
        if ptr_table_end > usable {
            continue;
        }

        let max_local = if page_type == 0x0d {
            usable - 35
        } else {
            ((usable - 12) * 64 / 255).saturating_sub(23)
        };
        let min_local = ((usable - 12) * 32 / 255).saturating_sub(23);
        if min_local > max_local || max_local == 0 {
            continue;
        }

        for cell_idx in 0..cell_count {
            let ptr_pos = btree_hdr_off + hdr_len + cell_idx * 2;
            let raw_cell_off = u16::from_be_bytes([page_buf[ptr_pos], page_buf[ptr_pos + 1]]);
            let mut cursor = if raw_cell_off == 0 && page_size == 65536 {
                65536
            } else {
                raw_cell_off as usize
            };
            if page_type == 0x02 {
                cursor = cursor.saturating_add(4); // skip 4-byte left-child page pointer
            }
            if cursor >= usable {
                continue;
            }

            let Some((payload_size_u64, v1_len)) = read_sqlite_varint(&page_buf[cursor..usable])
            else {
                continue;
            };
            if payload_size_u64 == 0 || payload_size_u64 > 4 * 1024 * 1024 {
                continue;
            }
            let payload_size = payload_size_u64 as usize;
            cursor += v1_len;

            if page_type == 0x0d {
                if cursor >= usable {
                    continue;
                }
                let Some((_rowid, v2_len)) = read_sqlite_varint(&page_buf[cursor..usable]) else {
                    continue;
                };
                cursor += v2_len;
            }

            let has_overflow = payload_size > max_local;
            let local_len = if !has_overflow {
                payload_size
            } else {
                let k = min_local + ((payload_size - min_local) % (usable - 4));
                if k <= max_local {
                    k
                } else {
                    min_local
                }
            };
            let needed = local_len + if has_overflow { 4 } else { 0 };
            if cursor + needed > usable {
                continue;
            }

            if !has_overflow {
                let cell_payload = &page_buf[cursor..cursor + local_len];
                append_sqlite_record_columns(cell_payload, text_encoding, &mut batch_buf);
                if batch_buf.len() >= 48 * 1024 {
                    flush_batch(
                        &mut batch_buf,
                        seen_fps,
                        hits,
                        &mut cell_hits,
                        &mut corpus_out,
                    );
                }
            } else {
                let ovf_ptr_pos = cursor + local_len;
                let mut next_ovf = u32::from_be_bytes([
                    page_buf[ovf_ptr_pos],
                    page_buf[ovf_ptr_pos + 1],
                    page_buf[ovf_ptr_pos + 2],
                    page_buf[ovf_ptr_pos + 3],
                ]);
                let mut assembled = Vec::with_capacity(payload_size.min(2 * 1024 * 1024));
                assembled.extend_from_slice(&page_buf[cursor..cursor + local_len]);
                let mut visited_ovf = HashSet::new();

                while next_ovf != 0
                    && assembled.len() < payload_size
                    && assembled.len() < 2 * 1024 * 1024
                    && visited_ovf.len() < 512
                    && visited_ovf.insert(next_ovf)
                {
                    let read_ok = if is_wal {
                        if let Some(&wal_off) = wal_page_offsets.get(&next_ovf) {
                            file.seek(SeekFrom::Start(wal_off)).is_ok()
                                && file.read_exact(&mut ovf_buf).is_ok()
                        } else if next_ovf <= total_db_pages {
                            if let Some(ref mut sf) = sibling_db_file {
                                let sib_off = (next_ovf as u64 - 1) * page_size as u64;
                                sf.seek(SeekFrom::Start(sib_off)).is_ok()
                                    && sf.read_exact(&mut ovf_buf).is_ok()
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else if next_ovf <= total_db_pages {
                        let ovf_off = (next_ovf as u64 - 1) * page_size as u64;
                        file.seek(SeekFrom::Start(ovf_off)).is_ok()
                            && file.read_exact(&mut ovf_buf).is_ok()
                    } else {
                        false
                    };
                    if !read_ok {
                        break;
                    }
                    next_ovf = u32::from_be_bytes([ovf_buf[0], ovf_buf[1], ovf_buf[2], ovf_buf[3]]);
                    let rem = payload_size - assembled.len();
                    let copy_len = rem.min(usable - 4);
                    assembled.extend_from_slice(&ovf_buf[4..4 + copy_len]);
                }

                append_sqlite_record_columns(&assembled, text_encoding, &mut batch_buf);
                flush_batch(
                    &mut batch_buf,
                    seen_fps,
                    hits,
                    &mut cell_hits,
                    &mut corpus_out,
                );
            }
        }
    }

    flush_batch(
        &mut batch_buf,
        seen_fps,
        hits,
        &mut cell_hits,
        &mut corpus_out,
    );
}

fn append_raw_sqlite_payload(payload: &[u8], out: &mut Vec<u8>) {
    if payload.is_empty() {
        return;
    }
    if payload.starts_with(&[0xFF, 0xFE])
        || payload.starts_with(&[0xFE, 0xFF])
        || (payload.contains(&0) && looks_like_utf16(payload))
    {
        let decoded = decode_utf16_bytes(payload);
        for &b in decoded.as_bytes() {
            out.push(if b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t') {
                b
            } else {
                b' '
            });
        }
    } else {
        for &b in payload {
            out.push(if b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t') {
                b
            } else {
                b' '
            });
        }
    }
    out.push(b'\n');
}

/// Parses a SQLite record payload into `\n`-separated TEXT/BLOB column values (plus synthetic `key=value`
/// pairs for `(key, value)` state tables) so adjacent columns never merge across `\b` word boundaries.
/// Falls back to contiguous printable bytes when `payload` is not a well-formed SQLite record.
fn append_sqlite_record_columns(payload: &[u8], text_encoding: u32, out: &mut Vec<u8>) {
    let Some((hdr_sz_u64, mut hdr_pos)) = read_sqlite_varint(payload) else {
        return;
    };
    if hdr_sz_u64 < hdr_pos as u64 || hdr_sz_u64 > payload.len() as u64 || hdr_sz_u64 > 65536 {
        append_raw_sqlite_payload(payload, out);
        return;
    }
    let hdr_sz = hdr_sz_u64 as usize;
    let initial_out_len = out.len();
    let mut body_pos = hdr_sz;
    let mut prev_key_col: Option<String> = None;
    let mut cols_seen = 0usize;
    let mut aborted = false;

    while hdr_pos < hdr_sz && cols_seen < 2048 {
        let Some((serial_type, v_len)) = read_sqlite_varint(&payload[hdr_pos..hdr_sz]) else {
            aborted = true;
            break;
        };
        hdr_pos += v_len;
        cols_seen += 1;

        let (col_len, is_text, is_blob) = match serial_type {
            0 | 8 | 9 => (0usize, false, false),
            1 => (1, false, false),
            2 => (2, false, false),
            3 => (3, false, false),
            4 => (4, false, false),
            5 => (6, false, false),
            6 | 7 => (8, false, false),
            10 | 11 => {
                aborted = true;
                break;
            }
            n if n >= 12 && n % 2 == 0 => (((n - 12) / 2) as usize, false, true),
            n => (((n - 13) / 2) as usize, true, false),
        };

        if body_pos.saturating_add(col_len) > payload.len() {
            if payload.len() < 2 * 1024 * 1024 {
                aborted = true;
            }
            break;
        }
        let col_bytes = &payload[body_pos..body_pos + col_len];
        body_pos += col_len;

        if !(is_text || is_blob) || col_len == 0 {
            prev_key_col = None;
            continue;
        }

        let decoded_col: Option<String> = if is_text && (text_encoding == 2 || text_encoding == 3) {
            let is_be = text_encoding == 3;
            let mut units = Vec::with_capacity(col_bytes.len() / 2);
            for &pair in col_bytes.as_chunks::<2>().0 {
                units.push(if is_be {
                    u16::from_be_bytes(pair)
                } else {
                    u16::from_le_bytes(pair)
                });
            }
            Some(String::from_utf16_lossy(&units))
        } else if col_bytes.starts_with(&[0xFF, 0xFE])
            || col_bytes.starts_with(&[0xFE, 0xFF])
            || (col_bytes.contains(&0) && looks_like_utf16(col_bytes))
        {
            Some(decode_utf16_bytes(col_bytes))
        } else {
            None
        };

        let start_out = out.len();
        if let Some(ref s) = decoded_col {
            for &b in s.as_bytes() {
                out.push(if b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t') {
                    b
                } else {
                    b' '
                });
            }
        } else {
            for &b in col_bytes {
                out.push(if b >= 0x20 || matches!(b, b'\n' | b'\r' | b'\t') {
                    b
                } else {
                    b' '
                });
            }
        }
        let col_str_len = out.len() - start_out;
        out.push(b'\n');

        // Also emit `key=value` when a short identifier key column precedes a single-line value column
        if let Some(ref key_name) = prev_key_col {
            let val_ok = {
                let val_slice = &out[start_out..start_out + col_str_len];
                (8..=256).contains(&val_slice.len())
                    && val_slice
                        .iter()
                        .all(|&b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\''))
            };
            if val_ok {
                out.extend_from_slice(key_name.as_bytes());
                out.push(b'=');
                out.extend_from_within(start_out..start_out + col_str_len);
                out.push(b'\n');
            }
        }

        let written_slice = &out[start_out..start_out + col_str_len];
        if (2..=96).contains(&written_slice.len())
            && written_slice
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            prev_key_col = std::str::from_utf8(written_slice).ok().map(str::to_string);
        } else {
            prev_key_col = None;
        }
    }

    if aborted
        || hdr_pos != hdr_sz
        || (body_pos != payload.len() && payload.len() < 2 * 1024 * 1024)
    {
        out.truncate(initial_out_len);
        append_raw_sqlite_payload(payload, out);
    }
}

fn read_sqlite_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mut val = 0u64;
    for (i, &b) in buf.iter().take(9).enumerate() {
        if i == 8 {
            val = (val << 8) | (b as u64);
            return Some((val, 9));
        }
        val = (val << 7) | ((b & 0x7f) as u64);
        if (b & 0x80) == 0 {
            return Some((val, i + 1));
        }
    }
    None
}

fn scan_sqlite_chunk(
    chunk: &[u8],
    path: &Path,
    display_file: &str,
    engine: &RuleEngine,
    hits: &mut Vec<FileHit>,
) {
    let text = String::from_utf8_lossy(chunk);
    let mut hints = crate::rules::DocHints::from_text(&text);
    if text.contains("private_key_id") && contains_gcp_sa_markers(&text) {
        hints.has_gcp_sa = true;
    }
    for m in engine.scan_text_with_hints(&text, Some(path), hints) {
        hits.push(FileHit {
            file: path.to_path_buf(),
            display_file: display_file.to_string(),
            line: 1,
            column: 1,
            rule_id: m.rule_id,
            rule_name: m.rule_name,
            severity: m.severity,
            category: m.category,
            masked: m.masked,
            fingerprint: m.fingerprint,
            secret_key: m.secret_key,
        });
    }
}

/// Counts unique secret fingerprints inside a binary SQLite/WAL database so `leaktap clean`
/// can warn clearly when secrets remain in skipped SQLite state files.
pub fn count_sqlite_secret_hits(
    path: &Path,
    engine: &RuleEngine,
    target_fingerprint: Option<&str>,
) -> usize {
    let Some(res) = scan_sqlite_strings_as(path, path, None, engine) else {
        return 0;
    };
    let mut unique_fps = HashSet::new();
    for h in res.hits {
        if h.category == RuleCategory::Secret
            && target_fingerprint.is_none_or(|fp| h.fingerprint == fp)
        {
            unique_fps.insert(h.fingerprint);
        }
    }
    unique_fps.len()
}

pub fn is_sqlite_or_wal_magic(header: &[u8]) -> bool {
    header.starts_with(b"SQLite format 3\0")
        || (header.len() >= 4
            && matches!(
                &header[..4],
                [0x37, 0x7f, 0x06, 0x82] | [0x37, 0x7f, 0x06, 0x83]
            ))
}

pub fn is_sqlite_extension(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".sqlite")
            || lower.ends_with(".sqlite3")
            || lower.ends_with(".vscdb")
            || lower.ends_with(".db")
            || lower.ends_with(".sqlite-wal")
            || lower.ends_with(".sqlite3-wal")
            || lower.ends_with(".vscdb-wal")
            || lower.ends_with(".db-wal")
        {
            return true;
        }
    }
    false
}

pub fn is_multiline_pem_header(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    let is_json_line =
        (trimmed.starts_with(b"{") || trimmed.starts_with(b"[")) && trimmed.contains(&b'"');
    !is_json_line
        && !contains_subslice(line, b"\\n")
        && contains_subslice(line, b"-----BEGIN ")
        && (contains_subslice(line, b"PRIVATE KEY-----")
            || contains_subslice(line, b"PRIVATE KEY BLOCK-----"))
        && !contains_subslice(line, b"-----END ")
}

pub fn is_wrapped_base64_start_line(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    if (32..=120).contains(&trimmed.len())
        && trimmed
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return true;
    }
    // Also support quoted `KEY="c2tfbGl2ZV8...` or `key: 'c2tfbGl2ZV8...` wrapped across lines
    // (where the opening quote is not closed on the same line).
    if let Some(eq_or_colon) = trimmed.iter().position(|&b| b == b'=' || b == b':') {
        let rhs = trim_ascii_bytes(&trimmed[eq_or_colon + 1..]);
        if let Some(stripped) = rhs.strip_prefix(b"\"").or_else(|| rhs.strip_prefix(b"'")) {
            if !stripped.ends_with(b"\"")
                && !stripped.ends_with(b"'")
                && (32..=160).contains(&stripped.len())
                && stripped
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            {
                return true;
            }
        }
    }
    false
}

pub fn is_wrapped_base64_continuation_line(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    let unquoted = trim_trailing_quotes(trimmed);
    let without_pad = unquoted
        .strip_suffix(b"==")
        .or_else(|| unquoted.strip_suffix(b"="))
        .unwrap_or(unquoted);
    (2..=120).contains(&without_pad.len())
        && unquoted.len() >= 4
        && without_pad
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

pub fn is_pem_or_pgp_continuation_line(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    if trimmed.is_empty() {
        return true;
    }
    if contains_subslice(trimmed, b"-----END ") {
        return true;
    }
    if trimmed.starts_with(b"\"\"\"") || trimmed.starts_with(b"'''") {
        return false;
    }
    // OpenPGP CRC24 checksum line (`=abcd`)
    if trimmed.len() == 5
        && trimmed[0] == b'='
        && trimmed[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return true;
    }
    // PEM / OpenPGP armor header line (`Proc-Type: 4,ENCRYPTED`, `Version: GnuPG v2`, etc.)
    if let Some(colon_pos) = trimmed.iter().position(|&b| b == b':') {
        let key = &trimmed[..colon_pos];
        if !key.is_empty()
            && key.len() <= 24
            && key.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-')
            && !trimmed.contains(&b'"')
            && !trimmed.contains(&b'{')
            && !trimmed.contains(&b'}')
        {
            return true;
        }
    }
    // Base64 body line (possibly ending with closing `"` or `"""` on the final line if END was omitted)
    let stripped_quotes = trim_trailing_quotes(trimmed);
    stripped_quotes.len() >= 4
        && stripped_quotes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn trim_trailing_quotes(mut s: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = s.split_last() {
        if matches!(last, b'"' | b'\'' | b';') {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn trim_ascii_bytes(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn is_multiline_putty_header(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    let is_json_line =
        (trimmed.starts_with(b"{") || trimmed.starts_with(b"[")) && trimmed.contains(&b'"');
    !is_json_line
        && !contains_subslice(line, b"\\n")
        && contains_subslice(trimmed, b"PuTTY-User-Key-File-")
}

pub fn is_putty_continuation_line(line: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(line);
    if trimmed.is_empty() {
        return false;
    }
    if let Some(colon_pos) = trimmed.iter().position(|&b| b == b':') {
        let key = &trimmed[..colon_pos];
        if !key.is_empty()
            && key.len() <= 32
            && key.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return true;
        }
    }
    let stripped = trim_trailing_quotes(trimmed);
    stripped.len() >= 4
        && stripped
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

pub fn yaml_block_scalar_parent_indent(line: &[u8]) -> Option<usize> {
    let indent = line
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let rest = trim_ascii_bytes(&line[indent..]);
    if rest.is_empty() || rest.starts_with(b"#") {
        return None;
    }
    let key_part = rest.strip_prefix(b"- ").unwrap_or(rest);
    let colon_pos = key_part.iter().position(|&b| b == b':')?;
    let key = trim_ascii_bytes(&key_part[..colon_pos]);
    if key.is_empty()
        || key.len() > 128
        || !key
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'"' | b'\''))
    {
        return None;
    }
    let rhs = trim_ascii_bytes(&key_part[colon_pos + 1..]);
    let (&style, after_style) = rhs.split_first()?;
    if style != b'|' && style != b'>' {
        return None;
    }
    let mut idx = 0usize;
    while idx < after_style.len() && idx < 2 {
        let b = after_style[idx];
        if b == b'-' || b == b'+' || (b'1'..=b'9').contains(&b) {
            idx += 1;
        } else {
            break;
        }
    }
    let tail = trim_ascii_bytes(&after_style[idx..]);
    if tail.is_empty() || tail.starts_with(b"#") {
        Some(indent)
    } else {
        None
    }
}

pub fn is_yaml_block_scalar_continuation(line: &[u8], parent_indent: usize) -> bool {
    if trim_ascii_bytes(line).is_empty() {
        return true;
    }
    let indent = line
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    indent > parent_indent
}
