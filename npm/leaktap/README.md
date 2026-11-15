# leaktap

**See what your AI coding agents actually leak.**

Fast command-line tool that checks your local AI coding logs and MCP configs for leaked API keys, passwords, and private data—with an interactive terminal dashboard (`leaktap ui`) and live HTTP header/socket watching (`leaktap tap`).

Works with **Claude Code** · **Cursor** · **Codex CLI** · **Gemini CLI** · **Windsurf** · **MCP Servers**

## Quickstart

```bash
# 1. Check your local agent logs & MCP configs offline
npx leaktap scan

# 2. Browse leaks, MCP risks & live wiretap stream in an interactive terminal UI
npx leaktap ui

# 3. Run an agent while checking outgoing HTTP headers/prompts and stripping extra shell secrets
npx leaktap tap --inspect-api --scrub-env -- claude
```

Source code and full docs: https://github.com/vssinghh/leaktap
