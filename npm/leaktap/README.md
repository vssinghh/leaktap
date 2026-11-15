# leaktap

**See what your AI coding CLIs actually leak.**

Fast command-line tool built for **terminal AI coding agents**. Checks local AI coding logs and MCP plugin configs for leaked API keys, passwords, and private data—with an interactive terminal dashboard (`leaktap ui`) and live CLI HTTP header/prompt/socket watching (`leaktap tap`).

Supports **Claude Code (`claude`)** · **Codex CLI (`codex`)** · **Gemini CLI (`gemini`)** — plus the local **MCP tool plugins** they run *(CLI-focused right now; desktop/IDE GUIs are not intercepted live yet)*.

## Quickstart

```bash
# 1. Check your local agent logs & MCP configs offline
npx leaktap scan

# 2. Browse leaks, MCP risks & live wiretap stream in an interactive terminal UI
npx leaktap ui

# 3. Run Claude Code, Codex, or Gemini CLI while checking outgoing HTTP headers & prompts
npx leaktap tap --inspect-api --scrub-env -- claude
npx leaktap tap --inspect-api --scrub-env -- gemini
```

Source code and full docs: https://github.com/vssinghh/leaktap
