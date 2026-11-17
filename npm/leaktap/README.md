# leaktap

See what your AI coding CLIs actually leak — and stop live secrets before they leave your machine.

`leaktap` scans local AI chat logs, SQLite databases, MCP configs, instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`), and installed plugins, hooks, and skills for leaked API keys, risky shell commands, and hidden prompt instructions. Includes a 4-tab terminal UI, safe log cleaning, and live CLI session watching.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, **Gemini CLI**, and local or remote **MCP servers**.

## Quickstart

```bash
# Check local logs, SQLite databases, MCP configs, and installed plugins offline (0 network requests)
npx leaktap@0.3.0

# Open the 4-tab interactive terminal UI
npx leaktap@0.3.0 ui

# Start Claude Code, Codex CLI, or Antigravity CLI with live watching, blocking, or secret scrubbing
npx leaktap@0.3.0 claude
npx leaktap@0.3.0 --block-secrets claude
npx leaktap@0.3.0 --redact-secrets claude
npx leaktap@0.3.0 --allow-env GH_TOKEN claude
npx leaktap@0.3.0 codex
npx leaktap@0.3.0 agy
```

Full docs, `.leaktap.toml` policy examples, and security notes: https://github.com/vssinghh/leaktap
