use crate::config::PolicyConfig;
#[cfg(unix)]
use crate::discovery::has_agent_session_ancestor;
use crate::discovery::shorten_home;
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

    // Process main SQLite DB files before companion `-wal`/`-shm` files so WAL frames
    // are checkpointed, scrubbed, and VACUUMed into the main DB atomically.
    let mut ordered_files: Vec<&PathBuf> = files.iter().collect();
    ordered_files.sort_by_key(|p| u8::from(is_wal_or_shm_companion(p)));
    let mut scrubbed_sqlite_companions: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();

    for path in ordered_files {
        if scrubbed_sqlite_companions.contains(path.as_path()) {
            continue;
        }
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
            let is_comp = is_wal_or_shm_companion(path);
            let initial_hits = count_sqlite_secret_hits(path, &engine, target_fingerprint);
            let wal_hits = if !is_comp {
                let wal_p = companion_sqlite_path(path, "-wal");
                if wal_p.is_file() {
                    count_sqlite_secret_hits(&wal_p, &engine, target_fingerprint)
                } else {
                    0
                }
            } else {
                0
            };
            let total_db_hits = initial_hits + wal_hits;
            if total_db_hits > 0 && !is_comp {
                if let Ok(Some((item, remaining))) = try_scrub_sqlite_db(
                    path,
                    &sym_meta,
                    &engine,
                    apply,
                    create_backup,
                    target_fingerprint,
                ) {
                    scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-wal"));
                    scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-shm"));
                    summary.files_inspected += 1;
                    summary.total_redactions += item.secrets_redacted;
                    summary.files_modified.push(item);
                    if remaining > 0 {
                        summary.uncleaned_sqlite_secrets += remaining;
                        summary.uncleaned_sqlite_files.push(disp);
                    }
                    continue;
                }
            }
            if !is_comp && total_db_hits > 0 {
                scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-wal"));
                scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-shm"));
                summary.uncleaned_sqlite_secrets += total_db_hits;
                summary.uncleaned_sqlite_files.push(disp.clone());
            } else if is_comp && initial_hits > 0 {
                summary.uncleaned_sqlite_secrets += initial_hits;
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
                let is_comp = is_wal_or_shm_companion(path);
                let initial_hits = count_sqlite_secret_hits(path, &engine, target_fingerprint);
                let wal_hits = if !is_comp {
                    let wal_p = companion_sqlite_path(path, "-wal");
                    if wal_p.is_file() {
                        count_sqlite_secret_hits(&wal_p, &engine, target_fingerprint)
                    } else {
                        0
                    }
                } else {
                    0
                };
                let total_db_hits = initial_hits + wal_hits;
                if total_db_hits > 0 && !is_comp {
                    if let Ok(Some((item, remaining))) = try_scrub_sqlite_db(
                        path,
                        &sym_meta,
                        &engine,
                        apply,
                        create_backup,
                        target_fingerprint,
                    ) {
                        scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-wal"));
                        scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-shm"));
                        summary.total_redactions += item.secrets_redacted;
                        summary.files_modified.push(item);
                        if remaining > 0 {
                            summary.uncleaned_sqlite_secrets += remaining;
                            summary.uncleaned_sqlite_files.push(disp);
                        }
                        continue;
                    }
                }
                if !is_comp && total_db_hits > 0 {
                    scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-wal"));
                    scrubbed_sqlite_companions.insert(companion_sqlite_path(path, "-shm"));
                    summary.uncleaned_sqlite_secrets += total_db_hits;
                    summary.uncleaned_sqlite_files.push(disp.clone());
                } else if is_comp && initial_hits > 0 {
                    summary.uncleaned_sqlite_secrets += initial_hits;
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

fn is_wal_or_shm_companion(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.ends_with("-wal") || lower.ends_with("-shm") || lower.ends_with("-journal")
}

fn companion_sqlite_path(base: &Path, suffix: &str) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn scrub_sqlite_cell_string(
    raw: &str,
    prev_key_col: Option<&str>,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> Option<(String, usize)> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(mut parsed) = serde_json::from_str::<Value>(raw) {
            let json_hits = scrub_json_value(&mut parsed, engine, path, target_fingerprint);
            if json_hits > 0 {
                if let Ok(serialized) = serde_json::to_string(&parsed) {
                    return Some((serialized, json_hits));
                }
            }
        }
    }

    let hints = crate::rules::DocHints::from_text(raw);
    let matches: Vec<_> = engine
        .scan_text_with_hints(raw, Some(path), hints)
        .into_iter()
        .filter(|m| target_fingerprint.is_none_or(|fp| m.fingerprint == fp))
        .collect();
    if !matches.is_empty() {
        let mut out = raw.to_string();
        let mut count = 0usize;
        for m in matches.iter().rev() {
            if m.end <= out.len() && out.is_char_boundary(m.start) && out.is_char_boundary(m.end) {
                let secret_slice = &out[m.start..m.end];
                let repl = redact_replacement(&m.rule_id, secret_slice);
                out.replace_range(m.start..m.end, &repl);
                count += 1;
            }
        }
        if count > 0 {
            return Some((out, count));
        }
    }

    // Also scrub `(key, value)` SQLite state rows (e.g. `('PROD_DB_PASSWORD', 'Sup3rS3cr3t...')`)
    if let Some(pk_key) = prev_key_col {
        if (2..=96).contains(&pk_key.len())
            && (8..=256).contains(&raw.len())
            && raw
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\''))
        {
            let synthetic = format!("{pk_key}={raw}");
            let prefix_len = pk_key.len() + 1;
            let kv_matches: Vec<_> = engine
                .scan_text_for_path(&synthetic, Some(path))
                .into_iter()
                .filter(|m| {
                    m.start >= prefix_len
                        && m.end <= synthetic.len()
                        && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
                })
                .collect();
            if !kv_matches.is_empty() {
                let mut out = raw.to_string();
                let mut count = 0usize;
                for m in kv_matches.iter().rev() {
                    let rel_s = m.start - prefix_len;
                    let rel_e = m.end - prefix_len;
                    if rel_e <= out.len()
                        && out.is_char_boundary(rel_s)
                        && out.is_char_boundary(rel_e)
                    {
                        let secret_slice = &out[rel_s..rel_e];
                        let repl = redact_replacement(&m.rule_id, secret_slice);
                        out.replace_range(rel_s..rel_e, &repl);
                        count += 1;
                    }
                }
                if count > 0 {
                    return Some((out, count));
                }
            }
        }
    }

    None
}

const SQLITE_DUMP_PY: &str = r#"
import base64, json, sqlite3, sys

def enc_pk(v):
    if isinstance(v, (bytes, bytearray)):
        return {"__b64__": base64.b64encode(bytes(v)).decode("ascii")}
    return v

db_path = sys.argv[1]
conn = sqlite3.connect(db_path, timeout=2.0)
cur = conn.cursor()
tables = [r[0] for r in cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
).fetchall()]
for tbl in tables:
    q_tbl = '"' + tbl.replace('"', '""') + '"'
    try:
        cols_info = cur.execute(f"PRAGMA table_info({q_tbl})").fetchall()
    except Exception:
        continue
    if not cols_info:
        continue
    pks = []
    pk_raw = False
    for rk in ("_rowid_", "rowid", "oid"):
        try:
            cur.execute(f"SELECT {rk} FROM {q_tbl} LIMIT 1")
            pks = [rk]
            pk_raw = True
            break
        except Exception:
            continue
    if not pks:
        pk_sorted = sorted((c for c in cols_info if int(c[5] or 0) > 0), key=lambda x: int(x[5]))
        pks = [c[1] for c in pk_sorted]
        pk_raw = False
    if not pks:
        continue
    cand_cols = [c[1] for c in cols_info] if pk_raw else [c[1] for c in cols_info if int(c[5] or 0) == 0]
    if not cand_cols:
        continue
    all_col_names = [c[1] for c in cols_info]
    q_pks = ", ".join((p if pk_raw else '"' + p.replace('"', '""') + '"') for p in pks)
    sel_cols = ", ".join('"' + c.replace('"', '""') + '"' for c in all_col_names)
    cand_set = set(cand_cols)
    pk_len = len(pks)
    for row in cur.execute(f"SELECT {q_pks}, {sel_cols} FROM {q_tbl}"):
        pk_vals = [enc_pk(x) for x in row[:pk_len]]
        if not all(isinstance(x, (int, float, str, dict)) or x is None for x in pk_vals):
            continue
        prev_k = None
        for col_name, val in zip(all_col_names, row[pk_len:]):
            s_val = None
            kind = None
            if isinstance(val, str):
                s_val = val
                kind = "s"
            elif isinstance(val, (bytes, bytearray)):
                raw_b = bytes(val)
                try:
                    s_val = raw_b.decode("utf-8")
                    kind = "b"
                except Exception:
                    if col_name in cand_set and len(raw_b) >= 8:
                        print(json.dumps({
                            "t": tbl,
                            "pks": pks,
                            "pk_raw": pk_raw,
                            "ids": pk_vals,
                            "c": col_name,
                            "k": "r",
                            "v": base64.b64encode(raw_b).decode("ascii"),
                            "pk_k": prev_k,
                        }))
                    s_val = None
            if col_name in cand_set and s_val is not None and len(s_val) >= 8:
                print(json.dumps({"t": tbl, "pks": pks, "pk_raw": pk_raw, "ids": pk_vals, "c": col_name, "k": kind, "v": s_val, "pk_k": prev_k}))
            if s_val is not None and 2 <= len(s_val) <= 96 and all(ch.isalnum() or ch in "_-." for ch in s_val):
                prev_k = s_val
            else:
                prev_k = None
conn.close()
"#;

const SQLITE_APPLY_PY: &str = r#"
import base64, json, sqlite3, sys

def dec_pk(v):
    if isinstance(v, dict) and "__b64__" in v:
        return base64.b64decode(v["__b64__"])
    return v

db_path = sys.argv[1]
conn = sqlite3.connect(db_path, timeout=5.0)
cur = conn.cursor()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    item = json.loads(line)
    q_tbl = '"' + item["t"].replace('"', '""') + '"'
    q_col = '"' + item["c"].replace('"', '""') + '"'
    pk_vals = [dec_pk(x) for x in item["ids"]]
    where_parts = []
    if item["k"] == "r":
        raw_col = base64.b64decode(item["v"])
    elif item["k"] == "b":
        raw_col = item["v"].encode("utf-8")
    else:
        raw_col = item["v"]
    bind_vals = [raw_col]
    for pk_name, pv in zip(item["pks"], pk_vals):
        q_pk = pk_name if item.get("pk_raw") else ('"' + pk_name.replace('"', '""') + '"')
        if pv is None:
            where_parts.append(f"{q_pk} IS NULL")
        else:
            where_parts.append(f"{q_pk} = ?")
            bind_vals.append(pv)
    where_sql = " AND ".join(where_parts)
    cur.execute(f"UPDATE {q_tbl} SET {q_col} = ? WHERE {where_sql}", tuple(bind_vals))
conn.commit()
try:
    cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
except Exception:
    pass
conn.isolation_level = None
cur.execute("VACUUM")
chk = cur.execute("PRAGMA integrity_check").fetchone()
conn.close()
if not chk or chk[0] != "ok":
    sys.exit(2)
"#;

fn same_len_redaction_bytes(rule_id: &str, raw_slice: &[u8]) -> Vec<u8> {
    let n = raw_slice.len();
    if n == 0 {
        return Vec::new();
    }
    let raw_str = std::str::from_utf8(raw_slice).unwrap_or("");
    let repl_owned = if !raw_str.is_empty() {
        Some(redact_replacement(rule_id, raw_str))
    } else {
        None
    };
    let pfx = repl_owned
        .as_deref()
        .and_then(|r| r.strip_suffix("[REDACTED_BY_LEAKTAP]"))
        .unwrap_or("");
    let pfx_bytes = pfx.as_bytes();
    let keep_pfx = if !pfx_bytes.is_empty() && pfx_bytes.len() + 10 <= n {
        pfx_bytes
    } else {
        &[][..]
    };
    let rem = n - keep_pfx.len();
    let mut out = Vec::with_capacity(n);
    out.extend_from_slice(keep_pfx);
    if rem >= 21 {
        out.extend_from_slice(b"[REDACTED_BY_LEAKTAP");
        out.resize(n - 1, b'*');
        out.push(b']');
    } else if rem >= 10 {
        out.extend_from_slice(b"[REDACTED");
        out.resize(n - 1, b'*');
        out.push(b']');
    } else {
        out.resize(n, b'*');
    }
    out
}

fn scrub_utf8_bytes_in_place_same_len(
    buf: &mut [u8],
    prev_key_col: Option<&str>,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> usize {
    let Ok(s) = std::str::from_utf8(buf) else {
        return 0;
    };
    let hints = crate::rules::DocHints::from_text(s);
    let matches: Vec<_> = engine
        .scan_text_with_hints(s, Some(path), hints)
        .into_iter()
        .filter(|m| {
            m.start < m.end
                && m.end <= buf.len()
                && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
        })
        .collect();
    if !matches.is_empty() {
        let mut count = 0usize;
        let mut last_start = buf.len() + 1;
        for m in matches.iter().rev() {
            if m.end <= last_start {
                let repl = same_len_redaction_bytes(&m.rule_id, &buf[m.start..m.end]);
                buf[m.start..m.end].copy_from_slice(&repl);
                last_start = m.start;
                count += 1;
            }
        }
        if count > 0 {
            return count;
        }
    }

    if let Some(pk_key) = prev_key_col {
        if let Ok(s2) = std::str::from_utf8(buf) {
            if (2..=96).contains(&pk_key.len())
                && (8..=256).contains(&s2.len())
                && s2
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\''))
            {
                let synthetic = format!("{pk_key}={s2}");
                let prefix_len = pk_key.len() + 1;
                let kv_matches: Vec<_> = engine
                    .scan_text_for_path(&synthetic, Some(path))
                    .into_iter()
                    .filter(|m| {
                        m.start >= prefix_len
                            && m.end <= synthetic.len()
                            && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
                    })
                    .collect();
                let mut count = 0usize;
                let mut last_start = buf.len() + 1;
                for m in kv_matches.iter().rev() {
                    let rel_s = m.start - prefix_len;
                    let rel_e = m.end - prefix_len;
                    if rel_s < rel_e && rel_e <= buf.len() && rel_e <= last_start {
                        let repl = same_len_redaction_bytes(&m.rule_id, &buf[rel_s..rel_e]);
                        buf[rel_s..rel_e].copy_from_slice(&repl);
                        last_start = rel_s;
                        count += 1;
                    }
                }
                if count > 0 {
                    return count;
                }
            }
        }
    }
    0
}

fn read_protobuf_varint_len(buf: &[u8]) -> Option<(usize, usize)> {
    let mut val = 0usize;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().take(4).enumerate() {
        val |= ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            return Some((val, i + 1));
        }
        shift += 7;
    }
    None
}

/// Scrubs secrets inside arbitrary binary/protobuf `BLOB` bytes using exact same-length byte
/// replacements so surrounding binary framing and protobuf varint lengths remain 100% intact.
fn scrub_binary_bytes_same_len(
    buf: &mut [u8],
    prev_key_col: Option<&str>,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> usize {
    if buf.len() < 8 {
        return 0;
    }
    let mut redactions = 0usize;

    // Pass 1: Protobuf length-delimited (`wire_type == 2`) UTF-8 string fields so single-byte
    // alphanumeric length varints (e.g. `0x41` == `'A'` for a 65-byte string) never merge into the value!
    let mut p = 0usize;
    while p + 2 < buf.len() {
        let tag = buf[p];
        if tag != 0 && (tag & 0x07) == 2 {
            if let Some((str_len, v_bytes)) = read_protobuf_varint_len(&buf[p + 1..]) {
                let start = p + 1 + v_bytes;
                if (8..=65_536).contains(&str_len) && start + str_len <= buf.len() {
                    let field_slice = &buf[start..start + str_len];
                    let printable_ok = field_slice
                        .iter()
                        .all(|&b| b >= 0x20 || matches!(b, b'\t' | b'\r' | b'\n'));
                    if printable_ok && std::str::from_utf8(field_slice).is_ok() {
                        redactions += scrub_utf8_bytes_in_place_same_len(
                            &mut buf[start..start + str_len],
                            prev_key_col,
                            engine,
                            path,
                            target_fingerprint,
                        );
                        p = start + str_len;
                        continue;
                    }
                }
            }
        }
        p += 1;
    }

    // Pass 2: Contiguous valid UTF-8 runs across the remaining binary payload
    let mut i = 0usize;
    while i < buf.len() {
        let b = buf[i];
        if b == 0 || (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < buf.len() {
            let c = buf[i];
            if c == 0 || (c < 0x20 && !matches!(c, b'\t' | b'\r' | b'\n')) || c == 0x7f {
                break;
            }
            i += 1;
        }
        let run_end = i;
        let mut sub_off = run_start;
        while sub_off + 8 <= run_end {
            match std::str::from_utf8(&buf[sub_off..run_end]) {
                Ok(_) => {
                    redactions += scrub_utf8_bytes_in_place_same_len(
                        &mut buf[sub_off..run_end],
                        prev_key_col,
                        engine,
                        path,
                        target_fingerprint,
                    );
                    break;
                }
                Err(err) => {
                    let valid_len = err.valid_up_to();
                    if valid_len >= 8 {
                        redactions += scrub_utf8_bytes_in_place_same_len(
                            &mut buf[sub_off..sub_off + valid_len],
                            prev_key_col,
                            engine,
                            path,
                            target_fingerprint,
                        );
                    }
                    let skip = err.error_len().unwrap_or(1).max(1);
                    sub_off += valid_len + skip;
                }
            }
        }
    }
    redactions
}

fn read_sqlite_varint_local(buf: &[u8]) -> Option<(u64, usize)> {
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

fn scrub_sqlite_leaf_page_in_place(
    page_buf: &mut [u8],
    page_no: u32,
    reserved_bytes: usize,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> usize {
    let page_size = page_buf.len();
    if page_size < 512 || reserved_bytes >= page_size {
        return 0;
    }
    let usable = page_size - reserved_bytes;
    let btree_hdr_off = if page_no == 1 { 100usize } else { 0usize };
    if btree_hdr_off + 8 > usable {
        return 0;
    }
    let page_type = page_buf[btree_hdr_off];
    // Only scrub table leaf (`0x0d`) and index/WITHOUT ROWID leaf (`0x0a`) pages cleanly at
    // column boundaries; never touch interior B-tree pointer pages (`0x02`, `0x05`).
    if page_type != 0x0d && page_type != 0x0a {
        return 0;
    }
    let hdr_len = 8usize;
    let cell_count =
        u16::from_be_bytes([page_buf[btree_hdr_off + 3], page_buf[btree_hdr_off + 4]]) as usize;
    if btree_hdr_off + hdr_len + cell_count * 2 > usable {
        return 0;
    }
    let max_local = if page_type == 0x0d {
        usable - 35
    } else {
        ((usable - 12) * 64 / 255).saturating_sub(23)
    };
    let min_local = ((usable - 12) * 32 / 255).saturating_sub(23);
    if min_local > max_local || max_local == 0 {
        return 0;
    }

    let mut cell_ranges: Vec<(usize, usize)> = Vec::with_capacity(cell_count);
    for cell_idx in 0..cell_count {
        let ptr_pos = btree_hdr_off + hdr_len + cell_idx * 2;
        let raw_cell_off = u16::from_be_bytes([page_buf[ptr_pos], page_buf[ptr_pos + 1]]);
        let mut cursor = if raw_cell_off == 0 && page_size == 65536 {
            65536
        } else {
            raw_cell_off as usize
        };
        if cursor >= usable {
            continue;
        }
        let Some((payload_size_u64, v1_len)) = read_sqlite_varint_local(&page_buf[cursor..usable])
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
            let Some((_rowid, v2_len)) = read_sqlite_varint_local(&page_buf[cursor..usable]) else {
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
        if cursor + local_len <= usable {
            cell_ranges.push((cursor, cursor + local_len));
        }
    }

    let mut redactions = 0usize;
    for (c_start, c_end) in cell_ranges {
        let payload = &mut page_buf[c_start..c_end];
        let Some((hdr_sz_u64, mut hdr_pos)) = read_sqlite_varint_local(payload) else {
            continue;
        };
        if hdr_sz_u64 < hdr_pos as u64 || hdr_sz_u64 > payload.len() as u64 || hdr_sz_u64 > 65536 {
            continue;
        }
        let hdr_sz = hdr_sz_u64 as usize;
        let mut col_specs: Vec<(usize, usize, bool, bool)> = Vec::new();
        let mut body_pos = hdr_sz;
        while hdr_pos < hdr_sz && col_specs.len() < 2048 {
            let Some((serial_type, v_len)) = read_sqlite_varint_local(&payload[hdr_pos..hdr_sz])
            else {
                break;
            };
            hdr_pos += v_len;
            let (col_len, is_text, is_blob) = match serial_type {
                0 | 8 | 9 => (0usize, false, false),
                1 => (1, false, false),
                2 => (2, false, false),
                3 => (3, false, false),
                4 => (4, false, false),
                5 => (6, false, false),
                6 | 7 => (8, false, false),
                10 | 11 => break,
                n if n >= 12 && n % 2 == 0 => (((n - 12) / 2) as usize, false, true),
                n => (((n - 13) / 2) as usize, true, false),
            };
            if body_pos + col_len > payload.len() {
                break;
            }
            col_specs.push((body_pos, body_pos + col_len, is_text, is_blob));
            body_pos += col_len;
        }

        let mut prev_key_col: Option<String> = None;
        for (col_idx, (cs, ce, is_text, is_blob)) in col_specs.into_iter().enumerate() {
            if !(is_text || is_blob) || cs == ce {
                prev_key_col = None;
                continue;
            }
            let next_key = std::str::from_utf8(&payload[cs..ce])
                .ok()
                .filter(|s| {
                    (2..=96).contains(&s.len())
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                })
                .map(str::to_string);

            // On index / WITHOUT ROWID leaf pages (`0x0a`), skip column 0 so index sort order is never perturbed
            if !(page_type == 0x0a && col_idx == 0) {
                redactions += scrub_binary_bytes_same_len(
                    &mut payload[cs..ce],
                    prev_key_col.as_deref(),
                    engine,
                    path,
                    target_fingerprint,
                );
            }
            prev_key_col = next_key;
        }
    }
    redactions
}

fn sqlite_wal_checksum_words(data: &[u8], native_be: bool, mut s0: u32, mut s1: u32) -> (u32, u32) {
    for &chunk in data.as_chunks::<8>().0 {
        let w0 = if native_be {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        } else {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        };
        let w1 = if native_be {
            u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
        } else {
            u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
        };
        s0 = s0.wrapping_add(w0).wrapping_add(s1);
        s1 = s1.wrapping_add(w1).wrapping_add(s0);
    }
    (s0, s1)
}

fn scrub_sqlite_wal_bytes_in_place(
    wal: &mut Vec<u8>,
    reserved_bytes: usize,
    engine: &RuleEngine,
    path: &Path,
    target_fingerprint: Option<&str>,
) -> Option<usize> {
    if wal.len() < 32 {
        return Some(0);
    }
    let magic = u32::from_be_bytes([wal[0], wal[1], wal[2], wal[3]]);
    let native_be = match magic {
        0x377f0682 => false,
        0x377f0683 => true,
        _ => return None,
    };
    let page_size = u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]) as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_multiple_of(8) {
        return None;
    }
    let hdr_s0 = u32::from_be_bytes([wal[24], wal[25], wal[26], wal[27]]);
    let hdr_s1 = u32::from_be_bytes([wal[28], wal[29], wal[30], wal[31]]);
    // Self-verify WAL header checksum before touching any frames
    if sqlite_wal_checksum_words(&wal[0..24], native_be, 0, 0) != (hdr_s0, hdr_s1) {
        return None;
    }
    let salt1 = [wal[16], wal[17], wal[18], wal[19]];
    let salt2 = [wal[20], wal[21], wal[22], wal[23]];

    let frame_len = 24 + page_size;
    let mut orig_s0 = hdr_s0;
    let mut orig_s1 = hdr_s1;
    let mut new_s0 = hdr_s0;
    let mut new_s1 = hdr_s1;
    let mut pos = 32usize;
    let mut redactions = 0usize;

    while pos + frame_len <= wal.len() {
        if wal[pos + 8..pos + 12] != salt1 || wal[pos + 12..pos + 16] != salt2 {
            break;
        }
        let stored_s0 =
            u32::from_be_bytes([wal[pos + 16], wal[pos + 17], wal[pos + 18], wal[pos + 19]]);
        let stored_s1 =
            u32::from_be_bytes([wal[pos + 20], wal[pos + 21], wal[pos + 22], wal[pos + 23]]);
        let (chk_h0, chk_h1) =
            sqlite_wal_checksum_words(&wal[pos..pos + 8], native_be, orig_s0, orig_s1);
        let (chk_s0, chk_s1) = sqlite_wal_checksum_words(
            &wal[pos + 24..pos + 24 + page_size],
            native_be,
            chk_h0,
            chk_h1,
        );
        if (chk_s0, chk_s1) != (stored_s0, stored_s1) {
            break;
        }
        orig_s0 = chk_s0;
        orig_s1 = chk_s1;

        let page_no = u32::from_be_bytes([wal[pos], wal[pos + 1], wal[pos + 2], wal[pos + 3]]);
        redactions += scrub_sqlite_leaf_page_in_place(
            &mut wal[pos + 24..pos + 24 + page_size],
            page_no,
            reserved_bytes,
            engine,
            path,
            target_fingerprint,
        );
        (new_s0, new_s1) = sqlite_wal_checksum_words(&wal[pos..pos + 8], native_be, new_s0, new_s1);
        (new_s0, new_s1) = sqlite_wal_checksum_words(
            &wal[pos + 24..pos + 24 + page_size],
            native_be,
            new_s0,
            new_s1,
        );
        wal[pos + 16..pos + 20].copy_from_slice(&new_s0.to_be_bytes());
        wal[pos + 20..pos + 24].copy_from_slice(&new_s1.to_be_bytes());
        pos += frame_len;
    }

    // Truncate dead post-checkpoint slack frames at `pos` so stale frames from earlier WAL epochs
    // never retain plaintext secrets on disk.
    if pos < wal.len() {
        let slack_text = String::from_utf8_lossy(&wal[pos..]);
        let slack_hits = engine
            .scan_text_for_path(&slack_text, Some(path))
            .into_iter()
            .filter(|m| {
                m.category == crate::rules::RuleCategory::Secret
                    && target_fingerprint.is_none_or(|fp| m.fingerprint == fp)
            })
            .count();
        redactions += slack_hits;
        wal.truncate(pos);
    }

    Some(redactions)
}

/// Pure-Rust zero-Python fallback that scrubs SQLite B-tree leaf cells (`0x0d` / `0x0a`) and
/// companion `-wal` frames in-place using same-length byte replacements and cumulative WAL
/// checksum recomputation when `python3` is unavailable on `PATH`.
fn try_scrub_sqlite_db_pure_rust(
    path: &Path,
    orig_meta: &fs::Metadata,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
    target_fingerprint: Option<&str>,
) -> io::Result<Option<(CleanedFileSummary, usize)>> {
    if orig_meta.len() > 128 * 1024 * 1024 {
        return Ok(None);
    }
    let mut db_bytes = fs::read(path)?;
    if db_bytes.len() < 100 || !db_bytes.starts_with(b"SQLite format 3\0") {
        return Ok(None);
    }
    let raw_ps = u16::from_be_bytes([db_bytes[16], db_bytes[17]]);
    let page_size = if raw_ps == 1 {
        65536usize
    } else {
        raw_ps as usize
    };
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Ok(None);
    }
    let reserved_bytes = db_bytes[20] as usize;

    let mut total_redactions = 0usize;
    let num_pages = db_bytes.len() / page_size;
    for idx in 0..num_pages {
        let p_start = idx * page_size;
        let p_end = p_start + page_size;
        total_redactions += scrub_sqlite_leaf_page_in_place(
            &mut db_bytes[p_start..p_end],
            (idx + 1) as u32,
            reserved_bytes,
            engine,
            path,
            target_fingerprint,
        );
    }

    let wal_path = companion_sqlite_path(path, "-wal");
    let mut wal_meta_and_bytes: Option<(fs::Metadata, Vec<u8>, usize)> = None;
    if let Ok(wm) = fs::symlink_metadata(&wal_path) {
        if wm.file_type().is_file() && !wm.file_type().is_symlink() && wm.len() <= 128 * 1024 * 1024
        {
            if let Ok(mut wbytes) = fs::read(&wal_path) {
                if let Some(w_hits) = scrub_sqlite_wal_bytes_in_place(
                    &mut wbytes,
                    reserved_bytes,
                    engine,
                    &wal_path,
                    target_fingerprint,
                ) {
                    total_redactions += w_hits;
                    wal_meta_and_bytes = Some((wm, wbytes, w_hits));
                }
            }
        }
    }

    if total_redactions == 0 {
        return Ok(None);
    }

    let display_file = shorten_home(path);
    if !apply {
        return Ok(Some((
            CleanedFileSummary {
                display_file,
                secrets_redacted: total_redactions,
                backup_file: None,
            },
            0,
        )));
    }

    let (tmp_db, mut tmp_file) = create_unique_temp_file(path, orig_meta)?;
    if tmp_file.write_all(&db_bytes).is_err() || tmp_file.sync_all().is_err() {
        cleanup_temp_sqlite_family(&tmp_db);
        return Ok(None);
    }
    drop(tmp_file);

    let mut tmp_wal_to_commit: Option<PathBuf> = None;
    if let Some((ref wm, ref wbytes, _)) = wal_meta_and_bytes {
        let (tw, mut tw_file) = create_unique_temp_file(&wal_path, wm)?;
        if tw_file.write_all(wbytes).is_err() || tw_file.sync_all().is_err() {
            let _ = fs::remove_file(&tw);
            cleanup_temp_sqlite_family(&tmp_db);
            return Ok(None);
        }
        drop(tw_file);
        // Copy temp wal next to `tmp_db` too so `count_sqlite_secret_hits` checks both cleanly
        let comp_tmp_wal = companion_sqlite_path(&tmp_db, "-wal");
        let _ = copy_file_private_perms(&tw, &comp_tmp_wal);
        tmp_wal_to_commit = Some(tw);
    }

    let mut remaining = count_sqlite_secret_hits(&tmp_db, engine, target_fingerprint);
    let comp_tmp_wal = companion_sqlite_path(&tmp_db, "-wal");
    if comp_tmp_wal.is_file() {
        remaining += count_sqlite_secret_hits(&comp_tmp_wal, engine, target_fingerprint);
        let _ = fs::remove_file(&comp_tmp_wal);
    }

    let pre_write_meta = fs::symlink_metadata(path)?;
    if pre_write_meta.file_type().is_symlink() || !pre_write_meta.file_type().is_file() {
        if let Some(tw) = tmp_wal_to_commit {
            let _ = fs::remove_file(&tw);
        }
        cleanup_temp_sqlite_family(&tmp_db);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to clean non-regular SQLite file or symlink",
        ));
    }

    let mut backup_display = None;
    if create_backup {
        let bak_path = companion_sqlite_path(path, ".leaktap.bak");
        copy_file_private_perms(path, &bak_path)?;
        if wal_meta_and_bytes.is_some() {
            let wal_bak = companion_sqlite_path(&wal_path, ".leaktap.bak");
            let _ = copy_file_private_perms(&wal_path, &wal_bak);
        }
        backup_display = Some(shorten_home(&bak_path));
    }

    if let Err(rename_err) = fs::rename(&tmp_db, path) {
        if let Some(tw) = tmp_wal_to_commit {
            let _ = fs::remove_file(&tw);
        }
        cleanup_temp_sqlite_family(&tmp_db);
        return Err(rename_err);
    }

    if let Some(tw) = tmp_wal_to_commit {
        if let Ok(pre_wm) = fs::symlink_metadata(&wal_path) {
            if pre_wm.file_type().is_file() && !pre_wm.file_type().is_symlink() {
                let _ = fs::rename(&tw, &wal_path);
            } else {
                let _ = fs::remove_file(&tw);
            }
        } else {
            let _ = fs::remove_file(&tw);
        }
    }

    Ok(Some((
        CleanedFileSummary {
            display_file,
            secrets_redacted: total_redactions,
            backup_file: backup_display,
        },
        remaining,
    )))
}

fn find_python_for_sqlite() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|&cand| {
        std::process::Command::new(cand)
            .args(["-c", "import sqlite3"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn cleanup_temp_sqlite_family(tmp_db: &Path) {
    let _ = fs::remove_file(tmp_db);
    let _ = fs::remove_file(companion_sqlite_path(tmp_db, "-wal"));
    let _ = fs::remove_file(companion_sqlite_path(tmp_db, "-shm"));
    let _ = fs::remove_file(companion_sqlite_path(tmp_db, "-journal"));
}

fn is_sqlite_db_locked_by_another_process(path: &Path, py_bin: &str) -> bool {
    const LOCK_PROBE_PY: &str = r#"import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1], timeout=1.0, isolation_level=None)
    con.execute("BEGIN EXCLUSIVE")
    con.execute("ROLLBACK")
    con.close()
    sys.exit(0)
except sqlite3.OperationalError as exc:
    msg = str(exc).lower()
    if "locked" in msg or "busy" in msg:
        sys.exit(75)
    sys.exit(0)
except Exception:
    sys.exit(0)
"#;
    std::process::Command::new(py_bin)
        .arg("-c")
        .arg(LOCK_PROBE_PY)
        .arg(path.as_os_str())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.code() == Some(75))
}

fn try_scrub_sqlite_db(
    path: &Path,
    orig_meta: &fs::Metadata,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
    target_fingerprint: Option<&str>,
) -> io::Result<Option<(CleanedFileSummary, usize)>> {
    let Some(py_bin) = find_python_for_sqlite() else {
        return try_scrub_sqlite_db_pure_rust(
            path,
            orig_meta,
            engine,
            apply,
            create_backup,
            target_fingerprint,
        );
    };

    if apply && is_sqlite_db_locked_by_another_process(path, py_bin) {
        eprintln!(
            "[leaktap:warn] skipping live-locked SQLite database {} (close the active IDE/agent session before running `leaktap clean --apply`)",
            shorten_home(path)
        );
        return Ok(None);
    }

    let (tmp_db, tmp_file) = create_unique_temp_file(path, orig_meta)?;
    // Copy main SQLite DB bytes into the unique `0600` sibling temp file
    let copy_res = (|| -> io::Result<()> {
        let mut src = BufReader::new(File::open(path)?);
        let mut dst = BufWriter::new(tmp_file);
        io::copy(&mut src, &mut dst)?;
        dst.flush()?;
        dst.into_inner().map_err(|e| e.into_error())?.sync_all()
    })();
    if copy_res.is_err() {
        cleanup_temp_sqlite_family(&tmp_db);
        return Ok(None);
    }

    // Copy any companion `-wal` / `-shm` regular files so uncommitted WAL transactions are preserved and scrubbed
    for suffix in ["-wal", "-shm"] {
        let comp_src = companion_sqlite_path(path, suffix);
        if let Ok(cm) = fs::symlink_metadata(&comp_src) {
            if cm.file_type().is_file() && !cm.file_type().is_symlink() {
                let comp_dst = companion_sqlite_path(&tmp_db, suffix);
                if copy_file_private_perms(&comp_src, &comp_dst).is_err() {
                    cleanup_temp_sqlite_family(&tmp_db);
                    return Ok(None);
                }
            }
        }
    }

    let Ok(mut dump_child) = std::process::Command::new(py_bin)
        .arg("-c")
        .arg(SQLITE_DUMP_PY)
        .arg(&tmp_db)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        cleanup_temp_sqlite_family(&tmp_db);
        return try_scrub_sqlite_db_pure_rust(
            path,
            orig_meta,
            engine,
            apply,
            create_backup,
            target_fingerprint,
        );
    };

    let mut updates_jsonl = Vec::<u8>::new();
    let mut total_redactions = 0usize;

    if let Some(stdout) = dump_child.stdout.take() {
        use base64::engine::general_purpose::STANDARD as B64_STD;
        use base64::Engine as _;
        let reader = BufReader::new(stdout);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                break;
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(mut row_obj) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let kind = row_obj.get("k").and_then(Value::as_str).unwrap_or("s");
            let Some(cell_val) = row_obj.get("v").and_then(Value::as_str) else {
                continue;
            };
            let prev_k = row_obj.get("pk_k").and_then(Value::as_str);

            if kind == "r" {
                if let Ok(mut raw_blob) = B64_STD.decode(cell_val) {
                    let count = scrub_binary_bytes_same_len(
                        &mut raw_blob,
                        prev_k,
                        engine,
                        path,
                        target_fingerprint,
                    );
                    if count > 0 {
                        let reencoded = B64_STD.encode(&raw_blob);
                        if let Some(map) = row_obj.as_object_mut() {
                            map.insert("v".to_string(), Value::String(reencoded));
                            map.remove("pk_k");
                            if let Ok(mut encoded) = serde_json::to_vec(&Value::Object(map.clone()))
                            {
                                encoded.push(b'\n');
                                updates_jsonl.extend_from_slice(&encoded);
                                total_redactions += count;
                            }
                        }
                    }
                }
                continue;
            }

            if let Some((scrubbed, count)) =
                scrub_sqlite_cell_string(cell_val, prev_k, engine, path, target_fingerprint)
            {
                if let Some(map) = row_obj.as_object_mut() {
                    map.insert("v".to_string(), Value::String(scrubbed));
                    map.remove("pk_k");
                    if let Ok(mut encoded) = serde_json::to_vec(&Value::Object(map.clone())) {
                        encoded.push(b'\n');
                        updates_jsonl.extend_from_slice(&encoded);
                        total_redactions += count;
                    }
                }
            }
        }
    }
    let dump_ok = dump_child.wait().is_ok_and(|s| s.success());
    if !dump_ok || total_redactions == 0 {
        cleanup_temp_sqlite_family(&tmp_db);
        return try_scrub_sqlite_db_pure_rust(
            path,
            orig_meta,
            engine,
            apply,
            create_backup,
            target_fingerprint,
        );
    }

    let display_file = shorten_home(path);
    if !apply {
        cleanup_temp_sqlite_family(&tmp_db);
        return Ok(Some((
            CleanedFileSummary {
                display_file,
                secrets_redacted: total_redactions,
                backup_file: None,
            },
            0,
        )));
    }

    let Ok(mut apply_child) = std::process::Command::new(py_bin)
        .arg("-c")
        .arg(SQLITE_APPLY_PY)
        .arg(&tmp_db)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        cleanup_temp_sqlite_family(&tmp_db);
        return Ok(None);
    };

    if let Some(mut stdin) = apply_child.stdin.take() {
        if stdin.write_all(&updates_jsonl).is_err() {
            let _ = apply_child.wait();
            cleanup_temp_sqlite_family(&tmp_db);
            return Ok(None);
        }
    }
    if !apply_child.wait().is_ok_and(|s| s.success()) {
        cleanup_temp_sqlite_family(&tmp_db);
        return Ok(None);
    }

    // Remove temporary companion `-wal`/`-shm` files left next to `tmp_db` before scanning `tmp_db`
    let _ = fs::remove_file(companion_sqlite_path(&tmp_db, "-wal"));
    let _ = fs::remove_file(companion_sqlite_path(&tmp_db, "-shm"));
    let _ = fs::remove_file(companion_sqlite_path(&tmp_db, "-journal"));

    let remaining = count_sqlite_secret_hits(&tmp_db, engine, target_fingerprint);

    let pre_write_meta = fs::symlink_metadata(path)?;
    if pre_write_meta.file_type().is_symlink() || !pre_write_meta.file_type().is_file() {
        cleanup_temp_sqlite_family(&tmp_db);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to clean non-regular SQLite file or symlink",
        ));
    }

    let mut backup_display = None;
    if create_backup {
        let bak_path = companion_sqlite_path(path, ".leaktap.bak");
        copy_file_private_perms(path, &bak_path)?;
        let wal_src = companion_sqlite_path(path, "-wal");
        if let Ok(wm) = fs::symlink_metadata(&wal_src) {
            if wm.file_type().is_file() && !wm.file_type().is_symlink() {
                let wal_bak = companion_sqlite_path(&wal_src, ".leaktap.bak");
                let _ = copy_file_private_perms(&wal_src, &wal_bak);
            }
        }
        backup_display = Some(shorten_home(&bak_path));
    }

    if let Err(rename_err) = fs::rename(&tmp_db, path) {
        cleanup_temp_sqlite_family(&tmp_db);
        return Err(rename_err);
    }

    // Since all WAL frames were checkpointed and VACUUMed into `path`, remove stale `-wal`/`-shm`
    for suffix in ["-wal", "-shm"] {
        let comp = companion_sqlite_path(path, suffix);
        if let Ok(cm) = fs::symlink_metadata(&comp) {
            if cm.file_type().is_file() && !cm.file_type().is_symlink() {
                let _ = fs::remove_file(&comp);
            }
        }
    }

    Ok(Some((
        CleanedFileSummary {
            display_file,
            secrets_redacted: total_redactions,
            backup_file: backup_display,
        },
        remaining,
    )))
}
