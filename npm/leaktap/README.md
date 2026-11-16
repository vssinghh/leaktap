# leaktap

See what your AI coding CLIs actually leak.

`leaktap` scans local AI chat logs, MCP configs, and installed marketplace plugins, hooks, and skills for leaked API keys, risky shell hooks, and hidden prompt instructions, with a terminal UI and live CLI session watching.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, and local **MCP servers**. Live watching targets terminal CLIs for now, not desktop or IDE apps.

## Quickstart

```bash
# Check local logs, MCP configs, and installed plugins offline
npx leaktap

# Open the interactive terminal UI
npx leaktap ui

# Start Claude Code, Codex CLI, or Antigravity CLI with live watching
npx leaktap claude
npx leaktap codex
npx leaktap agy
```

Source and docs: https://github.com/vssinghh/leaktap
