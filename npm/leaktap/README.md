# leaktap

See what your AI coding CLIs actually leak.

`leaktap` scans local AI chat logs and MCP configs for leaked API keys, database URLs, and personal info, with a terminal UI (`leaktap ui`) and live CLI session watching (`leaktap tap`).

Supports **Claude Code** (`claude`), **Codex CLI** (`codex`), **Gemini CLI** (`gemini`), and local **MCP servers**. (Live watching targets terminal CLIs for now, not desktop or IDE apps.)

## Quickstart

```bash
# Check local logs and MCP configs offline
npx leaktap scan

# Open the interactive terminal UI
npx leaktap ui

# Watch Claude Code, Codex, or Gemini CLI live
npx leaktap tap --inspect-api --scrub-env -- claude
npx leaktap tap --inspect-api --scrub-env -- gemini
```

Source and docs: https://github.com/vssinghh/leaktap
