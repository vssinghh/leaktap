# leaktap

See what your AI coding CLIs actually leak — and stop live secrets before they leave your machine.

`leaktap` audits local AI chat logs, SQLite/WAL state DBs, MCP configs, instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`), and installed marketplace plugins, hooks, and skills for leaked API keys, risky shell hooks, and hidden prompt payloads, with a 4-tab interactive terminal UI and live CLI session watching.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, **Gemini CLI**, and local **MCP servers**.

## Quickstart

```bash
# Check local logs, SQLite/WAL state, MCP configs, and installed plugins offline (0 network requests)
npx leaktap@0.3.0

# Open the 4-tab interactive terminal UI
npx leaktap@0.3.0 ui

# Start Claude Code, Codex CLI, or Antigravity CLI with live watching & prompt DLP
npx leaktap@0.3.0 claude
npx leaktap@0.3.0 --block-secrets claude
npx leaktap@0.3.0 --allow-env GH_TOKEN claude
npx leaktap@0.3.0 codex
npx leaktap@0.3.0 agy
```

Source, `.leaktap.toml` policy docs (`--trust-project-config`), and threat model: https://github.com/vssinghh/leaktap
