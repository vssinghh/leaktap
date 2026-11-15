# leaktap

**See what your AI coding agents actually leak.**

Offline secret, personal-metadata, and MCP supply-chain auditor + live `stdio`/environment wiretap for **Claude Code**, **Cursor**, **Codex CLI**, **Gemini CLI**, and **MCP servers**.

## Quickstart

```bash
# 1. Audit local agent transcripts & MCP configs completely offline
npx leaktap scan

# 2. Preview & redact exposed credentials from local session logs
npx leaktap clean
npx leaktap clean --apply

# 3. Wiretap a live agent or MCP server and scrub inherited secret env vars
npx leaktap tap --scrub-env -- claude
```

Full documentation and source code: https://github.com/vssinghh/leaktap
