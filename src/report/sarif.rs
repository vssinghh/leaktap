use crate::report::FullScanReport;
use serde_json::json;

/// Renders a SARIF 2.1.0 document compatible with GitHub Code Scanning (`upload-sarif`).
pub fn render_scan_sarif(report: &FullScanReport) -> String {
    let mut results = Vec::new();

    for f in report
        .transcripts
        .secret_findings
        .iter()
        .chain(report.transcripts.pii_findings.iter())
    {
        results.push(json!({
            "ruleId": f.rule_id,
            "level": f.severity.sarif_level(),
            "message": {
                "text": format!("{} ({}) detected in agent session transcript ({} occurrence(s))", f.rule_name, f.masked, f.occurrences)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.first_file
                    },
                    "region": {
                        "startLine": f.first_line.max(1)
                    }
                }
            }],
            "partialFingerprints": {
                "leaktapFingerprint/v1": f.fingerprint
            }
        }));
    }

    for m in &report.mcp_findings {
        let prefix = if m.rule_id.starts_with("plugin-") {
            format!("[`{}`]", m.server_name)
        } else {
            format!("[MCP server `{}`]", m.server_name)
        };
        results.push(json!({
            "ruleId": m.rule_id,
            "level": m.severity.sarif_level(),
            "message": {
                "text": format!("{prefix} {}", m.message)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": m.config_file
                    },
                    "region": {
                        "startLine": 1
                    }
                }
            }],
            "partialFingerprints": {
                "leaktapFingerprint/v1": m.fingerprint
            }
        }));
    }

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "leaktap",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/vssinghh/leaktap"
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("valid SARIF JSON")
}
