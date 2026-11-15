# What We Found Auditing the Top 50 Open-Source MCP Servers

*Date: November 15, 2026 · Reproducible script: [`scripts/audit_top_mcp_servers.py`](../scripts/audit_top_mcp_servers.py)*

**MCP (Model Context Protocol)** is the standard plugin system that lets AI coding agents (like Claude Code, Cursor, Codex, and Gemini CLI) connect to external tools—such as databases, GitHub, Figma, Slack, or browsers. Despite the name **"MCP server,"** most of them are small helper programs that run **locally on your laptop** (usually started via `npx` or `uvx`), with direct access to your local files, shell environment variables, and network.

To see what typical setups look like in practice, we audited the **50 most-starred dedicated MCP server repositories on GitHub** (spanning `3,668★` to `56,528★`, and over **515,000 combined stars**).

We checked each project's official `README` install snippet and package manifest (`package.json` / `pyproject.toml`) for three everyday security and privacy risks that affect developer laptops.

---

## Key Findings Across the Top 50 MCP Servers

| Risk Pattern Checked | Count (out of 50) | Share | Why It Matters on Your Laptop |
| :--- | :---: | :---: | :--- |
| **1. Unpinned auto-install (`npx -y` / `uvx` without version)** | **35 / 50** | **70%** | Pulls and runs whatever code was most recently published to npm or PyPI every time your agent starts, with access to your local files and shell environment. |
| **2. Plain-text API keys in JSON config examples** | **12 / 50** | **24%** | Guides users to paste raw tokens (`"API_KEY": "sk-..."`) directly inside `.mcp.json` or `claude_desktop_config.json`, where other agents read them or git commits accidentally include them. |
| **3. Built-in analytics or telemetry** | **12 / 50** | **24%** | Ships third-party analytics SDKs (`PostHog`, `Segment`, `Sentry`) or usage pings inside a local tool bridge—often without developers realizing their local MCP server makes background network calls. |

---

## Why This Happens (No Bad Intent Needed)

Open-source maintainers optimize `README` snippets for a 10-second setup:

1. Writing `"command": "npx", "args": ["-y", "@org/some-mcp"]` guarantees users always run the newest version without version-mismatch issues.
2. Showing `"env": { "SERVICE_API_KEY": "your-real-key" }` is simpler to explain than shell environment variable forwarding (`"${SERVICE_API_KEY}"`).
3. Adding `PostHog` or `Sentry` helps maintainers see crash rates and tool popularity.

The catch is what happens **when a developer installs 5 to 10 MCP servers side by side**:
- If any one unpinned npm or PyPI package is hijacked, the next time you open Claude Code or Cursor it automatically downloads and runs the compromised version.
- Every child process started by your coding agent inherits shell environment variables unless stripped—meaning an unrelated MCP server can often read `AWS_SECRET_ACCESS_KEY` or `STRIPE_SECRET_KEY` from your shell.
- When an agent reads `.mcp.json` or `.env` while debugging code, any plain-text keys inside those files get copied into `~/.claude` or `~/.codex` session logs on disk.

---

## How to Lock Down Your Setup in 60 Seconds

1. **Pin exact versions in `.mcp.json` and `claude_desktop_config.json`:**
   Change `"@org/server"` to `"@org/server@1.2.3"` (or `pkg==1.2.3` for `uvx`) so updates only happen when you choose.
2. **Keep raw keys out of JSON config files:**
   Use environment variable references (`"${GITHUB_PERSONAL_ACCESS_TOKEN}"`) where supported, and add `.mcp.json` to `.gitignore` if it holds project-specific settings.
3. **Strip extra shell secrets when launching agents or MCP servers:**
   Wrap commands with `leaktap tap --scrub-env -- <command>` so child tools only receive the variables you explicitly allow (`--allow-env`).
4. **Run an offline check on your machine:**
   Run `leaktap scan` to spot plain-text keys already sitting in your local chat transcripts (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`) and risky settings in your MCP configs.

---

## Reproduce This Audit Yourself

Anyone can re-run this exact check against live GitHub data using the GitHub CLI (`gh`):

```bash
python3 scripts/audit_top_mcp_servers.py /tmp/mcp_top50_audit.json
```
