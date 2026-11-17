# leaktap

`leaktap` scans local AI coding CLI logs, SQLite databases, MCP configs, and installed plugins for leaked secrets and risky shell hooks. It includes a 4-tab terminal UI, safe log scrubbing, and live CLI session watching.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, **Gemini CLI**, and local or remote **MCP servers**.

## Quickstart

```bash
# Scan local logs, SQLite databases, MCP configs, and installed plugins offline
npx leaktap@0.3.0

# Open the interactive terminal UI
npx leaktap@0.3.0 ui

# Start Claude Code, Codex CLI, or Antigravity CLI with live watching, blocking, or redaction
npx leaktap@0.3.0 claude
npx leaktap@0.3.0 --block-secrets claude
npx leaktap@0.3.0 --redact-secrets claude
npx leaktap@0.3.0 --allow-env GH_TOKEN claude
npx leaktap@0.3.0 codex
npx leaktap@0.3.0 agy
```

Docs, `.leaktap.toml` policy examples, and limitations: https://github.com/vssinghh/leaktap
