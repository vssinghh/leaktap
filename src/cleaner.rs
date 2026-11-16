use crate::config::PolicyConfig;
use crate::discovery::{has_agent_session_ancestor, shorten_home};
use crate::rules::{redact_replacement, RuleEngine};
use crate::scanner::{
    contains_subslice, count_sqlite_secret_hits, decode_utf16_with_endianness,
    encode_utf16_with_endianness, is_multiline_pem_header, is_pem_or_pgp_continuation_line,
    is_sqlite_extension, is_sqlite_or_wal_magic, is_wrapped_base64_continuation_line,
    is_wrapped_base64_start_line, looks_like_utf16, MULTILINE_B64_COALESCE_CAP,
};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static CLEAN_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct CleanedFileSummary {
    pub display_file: String,
    pub secrets_redacted: usize,
    pub backup_file: Option<String>,
}

#[derive(Debug, Default)]
pub struct CleanSummary {
    pub files_inspected: usize,
    pub files_modified: Vec<CleanedFileSummary>,
    pub skipped_binary_files: Vec<String>,
    pub uncleaned_sqlite_secrets: usize,
    pub uncleaned_sqlite_files: Vec<String>,
    pub total_redactions: usize,
    pub applied: bool,
}

enum ProcessOutcome {
    Modified(CleanedFileSummary),
    Unchanged,
    SkippedBinary,
    SkippedSqlite,
}

pub fn clean_transcripts(
    files: &[PathBuf],
    apply: bool,
    create_backup: bool,
) -> io::Result<CleanSummary> {
    clean_transcripts_with_policy(files, apply, create_backup, None)
}

pub fn clean_transcripts_with_policy(
    files: &[PathBuf],
    apply: bool,
    create_backup: bool,
    policy: Option<&PolicyConfig>,
) -> io::Result<CleanSummary> {
    clean_transcripts_filtered(files, apply, create_backup, policy, None)
}

pub fn clean_transcripts_filtered(
    files: &[PathBuf],
    apply: bool,
    create_backup: bool,
    policy: Option<&PolicyConfig>,
    target_fingerprint: Option<&str>,
) -> io::Result<CleanSummary> {
    // Clean only secrets (RuleCategory::Secret), leaving emails/hostnames untouched
    let engine = RuleEngine::with_policy(false, policy);
    let mut summary = CleanSummary {
        files_inspected: 0,
        applied: apply,
        ..Default::default()
    };

    for path in files {
        if policy.is_some_and(|p| p.is_path_ignored(path)) {
            continue;
        }
        // Never follow or replace symlinks during in-place cleaning
        let Ok(sym_meta) = fs::symlink_metadata(path) else {
            continue;
        };
        if sym_meta.file_type().is_symlink() || !sym_meta.file_type().is_file() {
            continue;
        }
        if is_sqlite_extension(path) {
            let disp = shorten_home(path);
            let uncleaned = count_sqlite_secret_hits(path, &engine, target_fingerprint);
            if uncleaned > 0 {
                summary.uncleaned_sqlite_secrets += uncleaned;
                summary.uncleaned_sqlite_files.push(disp.clone());
            }
            summary.skipped_binary_files.push(disp);
            continue;
        }
        summary.files_inspected += 1;
        match process_file(
            path,
            &sym_meta,
            &engine,
            apply,
            create_backup,
            target_fingerprint,
        )? {
            ProcessOutcome::Modified(item) => {
                summary.total_redactions += item.secrets_redacted;
                summary.files_modified.push(item);
            }
            ProcessOutcome::Unchanged => {}
            ProcessOutcome::SkippedSqlite => {
                let disp = shorten_home(path);
                let uncleaned = count_sqlite_secret_hits(path, &engine, target_fingerprint);
                if uncleaned > 0 {
                    summary.uncleaned_sqlite_secrets += uncleaned;
                    summary.uncleaned_sqlite_files.push(disp.clone());
                }
                summary.skipped_binary_files.push(disp);
            }
            ProcessOutcome::SkippedBinary => {
                summary.skipped_binary_files.push(shorten_home(path));
            }
        }
    }

    Ok(summary)
}

fn process_file(
    path: &Path,
    orig_meta: &fs::Metadata,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
    target_fingerprint: Option<&str>,
) -> io::Result<ProcessOutcome> {
    if path.file_name().and_then(|n| n.to_str()) == Some(".claude.json") {
        if let Some(outcome) = process_claude_json_file(
            path,
            orig_meta,
            engine,
            apply,
            create_backup,
            target_fingerprint,
        )? {
            return Ok(outcome);
        }
    }

    let Ok(mut peek_file) = File::open(path) else {
        return Ok(ProcessOutcome::Unchanged);
    };
    let mut header = [0u8; 256];
    let peek_n = peek_file.read(&mut header)?;
    if peek_n == 0 {
        return Ok(ProcessOutcome::Unchanged);
    }
    let sample = &header[..peek_n];
    if is_sqlite_or_wal_magic(sample) {
        return Ok(ProcessOutcome::SkippedSqlite);
    }

    let is_json_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));

    if sample.starts_with(&[0xFF, 0xFE])
        || sample.starts_with(&[0xFE, 0xFF])
        || (sample.contains(&0) && looks_like_utf16(sample))
    {
        return process_utf16_file(
            path,
            orig_meta,
            is_json_ext,
            engine,
            apply,
            create_backup,
            target_fingerprint,
        );
    }
    if sample.contains(&0) {
        return Ok(ProcessOutcome::SkippedBinary);
    }

    let Ok(in_file) = File::open(path) else {
        return Ok(ProcessOutcome::Unchanged);
    };
    let (transformed, redactions, saw_binary_nul) = redact_utf8_stream(
        BufReader::new(in_file),
        path,
        is_json_ext,
        engine,
        target_fingerprint,
    )?;
    if saw_binary_nul {
        return Ok(ProcessOutcome::SkippedBinary);
    }
    if redactions == 0 {
        return Ok(ProcessOutcome::Unchanged);
    }

    commit_cleaned_bytes(
        path,
        orig_meta,
        &transformed,
        redactions,
        apply,
        create_backup,
    )
    .map(ProcessOutcome::Modified)
}

fn process_utf16_file(
    path: &Path,
    orig_meta: &fs::Metadata,
    is_json_ext: bool,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
    target_fingerprint: Option<&str>,
) -> io::Result<ProcessOutcome> {
    if orig_meta.len() > 16 * 1024 * 1024 {
        return Ok(ProcessOutcome::SkippedBinary);
    }
    let raw = fs::read(path)?;
    let (is_be, has_bom, decoded) = decode_utf16_with_endianness(&raw);
    let (rewritten_utf8, redactions, _) = redact_utf8_stream(
        io::Cursor::new(decoded.as_bytes()),
        path,
        is_json_ext,
        engine,
        target_fingerprint,
    )?;
    if redactions == 0 {
        return Ok(ProcessOutcome::Unchanged);
    }
    let rewritten_str = String::from_utf8_lossy(&rewritten_utf8);
    let encoded = encode_utf16_with_endianness(&rewritten_str, is_be, has_bom);
    commit_cleaned_bytes(path, orig_meta, &encoded, redactions, apply, create_backup)
        .map(ProcessOutcome::Modified)
}

fn process_claude_json_file(
    path: &Path,
    orig_meta: &fs::Metadata,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
    target_fingerprint: Option<&str>,
) -> io::Result<Option<ProcessOutcome>> {
    if orig_meta.len() > 64 * 1024 * 1024 {
        return Ok(Some(ProcessOutcome::Unchanged));
    }
    let raw = match crate::scanner::read_text_auto_encoding(path, 64 * 1024 * 1024) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let Ok(mut doc) = serde_json::from_str::<Value>(&raw) else {
        return Ok(None);
    };
    let Some(root) = doc.as_object_mut() else {
        return Ok(None);
    };

    let is_home_file = crate::discovery::is_home_claude_state_file(path);
    let saved_oauth = if is_home_file {
        root.remove("oauthAccount")
    } else {
        None
    };
    let saved_custom_keys = if is_home_file {
        root.remove("customApiKeyResponses")
    } else {
        None
    };
    let saved_primary_key = if is_home_file
        && root
            .get("primaryApiKey")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("sk-ant-"))
    {
        root.remove("primaryApiKey")
    } else {
        None
    };
    let saved_top_mcp = root.remove("mcpServers");
    let mut saved_proj_mcp: Vec<(String, Value)> = Vec::new();
    if let Some(projects) = root.get_mut("projects").and_then(Value::as_object_mut) {
        for (proj_key, proj_val) in projects.iter_mut() {
            if let Some(proj_obj) = proj_val.as_object_mut() {
                if let Some(mcp_val) = proj_obj.remove("mcpServers") {
                    saved_proj_mcp.push((proj_key.clone(), mcp_val));
                }
            }
        }
    }

    let redactions = scrub_json_value(&mut doc, engine, path, target_fingerprint);
    if redactions == 0 {
        return Ok(Some(ProcessOutcome::Unchanged));
    }

    if let Some(root) = doc.as_object_mut() {
        if let Some(v) = saved_oauth {
            root.insert("oauthAccount".to_string(), v);
        }
        if let Some(v) = saved_custom_keys {
            root.insert("customApiKeyResponses".to_string(), v);
        }
        if let Some(v) = saved_primary_key {
            root.insert("primaryApiKey".to_string(), v);
        }
        if let Some(v) = saved_top_mcp {
            root.insert("mcpServers".to_string(), v);
        }
        if !saved_proj_mcp.is_empty() {
            if let Some(projects) = root.get_mut("projects").and_then(Value::as_object_mut) {
                for (proj_key, mcp_val) in saved_proj_mcp {
                    if let Some(proj_obj) =
                        projects.get_mut(&proj_key).and_then(Value::as_object_mut)
                    {
                        proj_obj.insert("mcpServers".to_string(), mcp_val);
                    }
                }
            }
        }
    }

    let is_pretty = raw.lines().take(5).count() >= 3;
    let mut out_bytes = if is_pretty {
        serde_json::to_vec_pretty(&doc).map_err(io::Error::other)?
    } else {
        serde_json::to_vec(&doc).map_err(io::Error::other)?
    };
    if raw.ends_with('\n') && !out_bytes.ends_with(b"\n") {
        out_bytes.push(b'\n');
    }

    commit_cleaned_bytes(
        path,
        orig_meta,
        &out_bytes,
        redactions,
        apply,
        create_backup,
    )
    .map(|item| Some(ProcessOutcome::Modified(item)))
}

fn redact_utf8_stream<R: BufRead>(
    mut reader: R,
    path: &Path,
    is_json_ext: bool,
    engine: &RuleEngine,
    target_fingerprint: Option<&str>,
) -> io::Result<(Vec<u8>, usize, bool)> {
    let mut raw_buf = Vec::new();
    let mut pending_line: Option<Vec<u8>> = None;
    let mut original_bytes = if is_json_ext { Some(Vec::new()) } else { None };
    let mut transformed = Vec::new();
    let mut redactions = 0usize;
    let mut line_idx = 0usize;
    let mut doc_hints: Option<crate::rules::DocHints> = None;
    let mut stream_hints = crate::rules::DocHints::default();
    let mut k8s_tracker = crate::rules::K8sDataTracker::default();

    loop {
        raw_buf.clear();
        if let Some(saved) = pending_line.take() {
            raw_buf.extend_from_slice(&saved);
        } else {
            let n = reader.read_until(b'\n', &mut raw_buf)?;
            if n == 0 {
                break;
            }
            line_idx += 1;
        }

        if raw_buf.contains(&0) || (line_idx == 1 && is_sqlite_or_wal_magic(&raw_buf)) {
            return Ok((Vec::new(), 0, true));
        }

        // Coalesce physical multi-line PEM/PGP/PuTTY blocks, YAML block scalars, hexdumps, and wrapped Base64 lines safely
        if is_multiline_pem_header(&raw_buf) {
            while raw_buf.len() < 32 * 1024 {
                let prev_len = raw_buf.len();
                let extra = reader.read_until(b'\n', &mut raw_buf)?;
                if extra == 0 {
                    break;
                }
                line_idx += 1;
                let added = &raw_buf[prev_len..];
                if contains_subslice(added, b"-----END ") {
                    break;
                }
                if !is_pem_or_pgp_continuation_line(added) {
                    pending_line = Some(added.to_vec());
                    raw_buf.truncate(prev_len);
                    break;
                }
            }
        } else if crate::scanner::is_multiline_putty_header(&raw_buf) {
            while raw_buf.len() < 32 * 1024 {
                let prev_len = raw_buf.len();
                let extra = reader.read_until(b'\n', &mut raw_buf)?;
                if extra == 0 {
                    break;
                }
                line_idx += 1;
                let added = &raw_buf[prev_len..];
                if contains_subslice(added, b"Private-MAC:")
                    || contains_subslice(added, b"Private-Hash:")
                {
                    break;
                }
                if !crate::scanner::is_putty_continuation_line(added) {
                    pending_line = Some(added.to_vec());
                    raw_buf.truncate(prev_len);
                    break;
                }
            }
        } else if let Some(parent_indent) =
            crate::scanner::yaml_block_scalar_parent_indent(&raw_buf)
        {
            while raw_buf.len() < 32 * 1024 {
                let prev_len = raw_buf.len();
                let extra = reader.read_until(b'\n', &mut raw_buf)?;
                if extra == 0 {
                    break;
                }
                line_idx += 1;
                let added = &raw_buf[prev_len..];
                if !crate::scanner::is_yaml_block_scalar_continuation(added, parent_indent) {
                    pending_line = Some(added.to_vec());
                    raw_buf.truncate(prev_len);
                    break;
                }
            }
        } else if std::str::from_utf8(&raw_buf)
            .ok()
            .is_some_and(crate::rules::is_hexdump_line)
        {
            while raw_buf.len() < 32 * 1024 {
                let prev_len = raw_buf.len();
                let extra = reader.read_until(b'\n', &mut raw_buf)?;
                if extra == 0 {
                    break;
                }
                line_idx += 1;
                let added = &raw_buf[prev_len..];
                let is_cont = std::str::from_utf8(added)
                    .ok()
                    .is_some_and(crate::rules::is_hexdump_line);
                if !is_cont {
                    pending_line = Some(added.to_vec());
                    raw_buf.truncate(prev_len);
                    break;
                }
            }
        } else if is_wrapped_base64_start_line(&raw_buf) {
            while raw_buf.len() < MULTILINE_B64_COALESCE_CAP {
                let prev_len = raw_buf.len();
                let extra = reader.read_until(b'\n', &mut raw_buf)?;
                if extra == 0 {
                    break;
                }
                line_idx += 1;
                let added = &raw_buf[prev_len..];
                if !is_wrapped_base64_continuation_line(added) {
                    pending_line = Some(added.to_vec());
                    raw_buf.truncate(prev_len);
                    break;
                }
                if matches!(
                    added.iter().rev().find(|&&b| !b.is_ascii_whitespace()),
                    Some(&b'=') | Some(&b'"') | Some(&b'\'')
                ) {
                    break;
                }
            }
        }

        if let Some(ref mut orig) = original_bytes {
            orig.extend_from_slice(&raw_buf);
        }

        let Ok(line_str) = std::str::from_utf8(&raw_buf) else {
            transformed.extend_from_slice(&raw_buf);
            continue;
        };

        stream_hints = stream_hints.merge(crate::rules::DocHints::from_text(line_str));
        let needs_doc_hints = doc_hints.is_some()
            || line_str.contains("private_key_id")
            || line_str.contains("\"kty\"")
            || line_str.contains("'kty'")
            || line_str.contains("\"d\"")
            || line_str.contains("\"k\"")
            || line_str.contains("kind:")
            || line_str.contains("\"kind\"")
            || line_str.contains("data:")
            || line_str.contains("stringData:");
        let mut line_hints = if needs_doc_hints {
            stream_hints
                .merge(*doc_hints.get_or_insert_with(|| crate::scanner::file_doc_hints(path)))
        } else {
            stream_hints
        };
        if line_hints.is_k8s_secret_manifest
            || k8s_tracker.is_tracking()
            || line_str.contains("kind:")
            || line_str.contains("\"kind\"")
        {
            for sub in line_str.lines() {
                let (in_d, in_sd) = k8s_tracker.observe_line(sub);
                line_hints.in_k8s_data_entry |= in_d;
                line_hints.in_k8s_string_data_entry |= in_sd;
            }
            line_hints.is_k8s_secret_manifest =
                k8s_tracker.is_active_secret_doc(line_hints.is_k8s_secret_manifest);
        }

        let all_matches = engine.scan_text_with_hints(line_str, Some(path), line_hints);
        let matches: Vec<_> = all_matches
            .into_iter()
            .filter(|m| target_fingerprint.is_none_or(|fp| m.fingerprint == fp))
            .collect();
        if matches.is_empty() {
            transformed.extend_from_slice(&raw_buf);
            continue;
        };

        let mut rewritten = line_str.to_string();
        let mut line_redactions = 0usize;
        // Replace from right to left so earlier byte spans remain valid
        for m in matches.iter().rev() {
            let raw_secret = &rewritten[m.start..m.end];
            let safe_token = redact_replacement(&m.rule_id, raw_secret);
            rewritten.replace_range(m.start..m.end, &safe_token);
            line_redactions += 1;
        }

        // Guarantee JSONL structural validity: if the original line was valid JSON, ensure the
        // rewritten line is still valid JSON (falling back to AST string scrubbing if needed).
        let trimmed_orig = line_str.trim();
        if (trimmed_orig.starts_with('{') || trimmed_orig.starts_with('['))
            && serde_json::from_str::<Value>(trimmed_orig).is_ok()
            && serde_json::from_str::<Value>(rewritten.trim()).is_err()
        {
            if let Ok(mut parsed_line) = serde_json::from_str::<Value>(trimmed_orig) {
                let ast_redactions =
                    scrub_json_value(&mut parsed_line, engine, path, target_fingerprint);
                if let Ok(mut safe_json) = serde_json::to_string(&parsed_line) {
                    if line_str.ends_with("\r\n") {
                        safe_json.push_str("\r\n");
                    } else if line_str.ends_with('\n') {
                        safe_json.push('\n');
                    }
                    rewritten = safe_json;
                    line_redactions = ast_redactions;
                }
            }
        }

        redactions += line_redactions;
        transformed.extend_from_slice(rewritten.as_bytes());
    }

    // Whole-file JSON validity guard for multi-line `.json` transcripts
    if redactions > 0 {
        if let Some(ref orig) = original_bytes {
            if serde_json::from_slice::<Value>(orig).is_ok()
                && serde_json::from_slice::<Value>(&transformed).is_err()
            {
                if let Ok(mut parsed_doc) = serde_json::from_slice::<Value>(orig) {
                    let ast_redactions =
                        scrub_json_value(&mut parsed_doc, engine, path, target_fingerprint);
                    if let Ok(mut pretty) = serde_json::to_vec_pretty(&parsed_doc) {
                        pretty.push(b'\n');
                        transformed = pretty;
                        redactions = ast_redactions;
                    }
                }
            }
        }
    }

    Ok((transformed, redactions, false))
}

fn commit_cleaned_bytes(
    path: &Path,
    orig_meta: &fs::Metadata,
    transformed: &[u8],
    redactions: usize,
    apply: bool,
    create_backup: bool,
) -> io::Result<CleanedFileSummary> {
    let display_file = shorten_home(path);
    let mut backup_display = None;

    if apply {
        // Re-check symlink_metadata immediately before writing to narrow any TOCTOU window
        let pre_write_meta = fs::symlink_metadata(path)?;
        if pre_write_meta.file_type().is_symlink() || !pre_write_meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to clean non-regular file or symlink",
            ));
        }

        if create_backup {
            let mut bak_os = path.as_os_str().to_os_string();
            bak_os.push(".leaktap.bak");
            let bak_path = PathBuf::from(bak_os);
            copy_file_private_perms(path, &bak_path)?;
            backup_display = Some(shorten_home(&bak_path));
        }

        let (tmp_path, tmp_file) = create_unique_temp_file(path, orig_meta)?;
        let write_result = (|| -> io::Result<()> {
            let mut writer = BufWriter::new(tmp_file);
            writer.write_all(transformed)?;
            writer.flush()?;
            writer.into_inner().map_err(|e| e.into_error())?.sync_all()
        })();
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(rename_err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(rename_err);
        }
    }

    Ok(CleanedFileSummary {
        display_file,
        secrets_redacted: redactions,
        backup_file: backup_display,
    })
}

fn scrub_json_value(
    val: &mut Value,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> usize {
    match val {
        Value::String(s) => {
            let hints = crate::rules::DocHints::from_text(s);
            let matches: Vec<_> = engine
                .scan_text_with_hints(s, Some(path), hints)
                .into_iter()
                .filter(|m| target_fingerprint.is_none_or(|fp| m.fingerprint == fp))
                .collect();
            if matches.is_empty() {
                return 0;
            }
            let mut count = 0usize;
            for m in matches.iter().rev() {
                let raw_secret = &s[m.start..m.end];
                let safe_token = redact_replacement(&m.rule_id, raw_secret);
                s.replace_range(m.start..m.end, &safe_token);
                count += 1;
            }
            count
        }
        Value::Array(arr) => arr
            .iter_mut()
            .map(|item| scrub_json_value(item, engine, path, target_fingerprint))
            .sum(),
        Value::Object(map) => {
            let is_gcp_sa_obj = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t == "service_account")
                || map
                    .get("client_email")
                    .and_then(Value::as_str)
                    .is_some_and(|e| e.contains(".iam.gserviceaccount.com"));
            let mut count = 0usize;
            if is_gcp_sa_obj {
                if let Some(Value::String(pk_id)) = map.get_mut("private_key_id") {
                    let probe = format!("\"private_key_id\": \"{pk_id}\"");
                    let matches: Vec<_> = engine
                        .scan_text_with_doc_hint(&probe, Some(path), true)
                        .into_iter()
                        .filter(|m| {
                            m.rule_id == "gcp-service-account-key"
                                && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
                        })
                        .collect();
                    if !matches.is_empty() {
                        *pk_id = redact_replacement("gcp-service-account-key", pk_id);
                        count += 1;
                    }
                }
            }
            let kty = map
                .get("kty")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let has_d = map.contains_key("d");
            if matches!(kty.as_str(), "RSA" | "EC" | "OKP" | "oct") {
                let jwk_hints = crate::rules::DocHints {
                    has_jwk_asymmetric_kty: matches!(kty.as_str(), "RSA" | "EC" | "OKP"),
                    has_jwk_d_param: has_d,
                    has_jwk_oct_kty: kty == "oct",
                    ..Default::default()
                };
                for jwk_field in ["d", "p", "q", "dp", "dq", "qi", "k"] {
                    if let Some(Value::String(secret_val)) = map.get_mut(jwk_field) {
                        let probe = format!("\"{jwk_field}\": \"{secret_val}\"");
                        let matched = engine
                            .scan_text_with_hints(&probe, Some(path), jwk_hints)
                            .into_iter()
                            .any(|m| {
                                m.rule_id == "jwk-private-key"
                                    && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
                            });
                        if matched {
                            *secret_val = redact_replacement("jwk-private-key", secret_val);
                            count += 1;
                        }
                    }
                }
            }
            count
                + map
                    .values_mut()
                    .map(|v| scrub_json_value(v, engine, path, target_fingerprint))
                    .sum::<usize>()
        }
        _ => 0,
    }
}

fn compute_target_mode(orig_path: &Path, orig_meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let orig_mode = orig_meta.permissions().mode() & 0o777;
        let is_session = has_agent_session_ancestor(orig_path)
            || orig_path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));
        if is_session {
            // Tighten group/world permissions on agent transcripts while preserving owner bits (including +x if set)
            let owner_only = orig_mode & 0o700;
            if (owner_only & 0o600) == 0 {
                0o600
            } else {
                owner_only
            }
        } else {
            // Preserve original file permissions (e.g. 0755 on scripts or 0644 on configs) for explicit repo files
            if orig_mode == 0 {
                0o600
            } else {
                orig_mode
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (orig_path, orig_meta);
        0o600
    }
}

fn create_unique_temp_file(
    orig_path: &Path,
    orig_meta: &fs::Metadata,
) -> io::Result<(PathBuf, File)> {
    let pid = std::process::id();
    let target_mode = compute_target_mode(orig_path, orig_meta);

    for attempt in 0..16u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = CLEAN_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut tmp_os = orig_path.as_os_str().to_os_string();
        tmp_os.push(format!(".leaktap.{pid}.{nanos:x}.{seq}.{attempt}.tmp"));
        let tmp_path = PathBuf::from(tmp_os);

        let open_res = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let res = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(target_mode)
                    .open(&tmp_path);
                if let Ok(ref f) = res {
                    let _ = f.set_permissions(fs::Permissions::from_mode(target_mode));
                }
                res
            }
            #[cfg(not(unix))]
            {
                let _ = target_mode;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp_path)
            }
        };

        match open_res {
            Ok(f) => return Ok((tmp_path, f)),
            Err(ref e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique temporary file for atomic clean",
    ))
}

fn copy_file_private_perms(src: &Path, dst: &Path) -> io::Result<()> {
    if let Ok(existing_meta) = fs::symlink_metadata(dst) {
        if existing_meta.file_type().is_symlink() || existing_meta.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to overwrite symlink or directory backup path",
            ));
        }
        fs::remove_file(dst)?;
    }

    let mut reader = BufReader::new(File::open(src)?);
    #[cfg(unix)]
    let dst_file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dst)?;
        let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        f
    };
    #[cfg(not(unix))]
    let dst_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;

    let mut writer = BufWriter::new(dst_file);
    io::copy(&mut reader, &mut writer)?;
    writer.flush()
}
