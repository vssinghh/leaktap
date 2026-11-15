use crate::discovery::shorten_home;
use crate::rules::{redact_replacement, RuleEngine};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

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
    pub total_redactions: usize,
    pub applied: bool,
}

pub fn clean_transcripts(
    files: &[PathBuf],
    apply: bool,
    create_backup: bool,
) -> std::io::Result<CleanSummary> {
    // Clean only secrets (RuleCategory::Secret), leaving emails/hostnames untouched
    let engine = RuleEngine::new(false);
    let mut summary = CleanSummary {
        files_inspected: files.len(),
        applied: apply,
        ..Default::default()
    };

    for path in files {
        if let Some(item) = process_file(path, &engine, apply, create_backup)? {
            summary.total_redactions += item.secrets_redacted;
            summary.files_modified.push(item);
        }
    }

    Ok(summary)
}

fn process_file(
    path: &Path,
    engine: &RuleEngine,
    apply: bool,
    create_backup: bool,
) -> std::io::Result<Option<CleanedFileSummary>> {
    let Ok(in_file) = File::open(path) else {
        return Ok(None);
    };
    let mut reader = BufReader::new(in_file);
    let mut raw_buf = Vec::new();
    let mut transformed = Vec::new();
    let mut redactions = 0usize;
    let mut line_idx = 0usize;

    loop {
        raw_buf.clear();
        let n = reader.read_until(b'\n', &mut raw_buf)?;
        if n == 0 {
            break;
        }
        line_idx += 1;

        if line_idx == 1 && raw_buf.contains(&0) {
            return Ok(None);
        }

        let Ok(line_str) = std::str::from_utf8(&raw_buf) else {
            transformed.extend_from_slice(&raw_buf);
            continue;
        };

        let matches = engine.scan_text(line_str);
        if matches.is_empty() {
            transformed.extend_from_slice(&raw_buf);
            continue;
        }

        let mut rewritten = line_str.to_string();
        // Replace from right to left so earlier byte spans remain valid
        for m in matches.iter().rev() {
            let raw_secret = &rewritten[m.start..m.end];
            let safe_token = redact_replacement(m.rule_id, raw_secret);
            rewritten.replace_range(m.start..m.end, &safe_token);
            redactions += 1;
        }
        transformed.extend_from_slice(rewritten.as_bytes());
    }

    if redactions == 0 {
        return Ok(None);
    }

    let display_file = shorten_home(path);
    let mut backup_display = None;

    if apply {
        if create_backup {
            let mut bak_os = path.as_os_str().to_os_string();
            bak_os.push(".leaktap.bak");
            let bak_path = PathBuf::from(bak_os);
            fs::copy(path, &bak_path)?;
            backup_display = Some(shorten_home(&bak_path));
        }

        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(".leaktap.tmp");
        let tmp_path = PathBuf::from(tmp_os);

        {
            let tmp_file = File::create(&tmp_path)?;
            if let Ok(meta) = fs::metadata(path) {
                let _ = tmp_file.set_permissions(meta.permissions());
            }
            let mut writer = BufWriter::new(tmp_file);
            writer.write_all(&transformed)?;
            writer.flush()?;
        }

        fs::rename(&tmp_path, path)?;
    }

    Ok(Some(CleanedFileSummary {
        display_file,
        secrets_redacted: redactions,
        backup_file: backup_display,
    }))
}
