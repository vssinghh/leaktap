# leaktap

See what your AI coding CLIs actually leak.

`leaktap` scans local AI chat logs and MCP configs for leaked API keys, database URLs, and personal info, with a terminal UI and live CLI session watching.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, and local **MCP servers**. Live watching targets terminal CLIs for now, not desktop or IDE apps.

## Quickstart

```bash
# Check local logs and MCP configs offline
npx leaktap scan

# Open the interactive terminal UI
npx leaktap ui

# Watch Claude Code, Codex CLI, or Antigravity CLI live
npx leaktap tap --inspect-api --scrub-env -- claude
npx leaktap tap --inspect-api --scrub-env -- agy
```

Source and docs: https://github.com/vssinghh/leaktap
