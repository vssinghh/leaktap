# leaktap

**See what your AI coding agents actually leak.**

Fast command-line tool that checks your local AI coding logs and MCP configs for leaked API keys, passwords, and private data—and watches live agent sessions without needing Docker or custom HTTPS certificates.

Works with **Claude Code** · **Cursor** · **Codex CLI** · **Gemini CLI** · **Windsurf** · **MCP Servers**

## Quickstart

```bash
# 1. Check your local agent logs & MCP configs offline
npx leaktap scan

# 2. Preview & scrub leaked secrets out of local chat logs
npx leaktap clean
npx leaktap clean --apply

# 3. Run an agent while stripping unrelated shell secrets
npx leaktap tap --scrub-env -- claude
```

Source code and full docs: https://github.com/vssinghh/leaktap
