# Auditing the Top 50 Open-Source MCP Servers

*Snapshot date: November 16, 2026 · Raw JSON dataset: [`docs/mcp-top-50-audit.json`](mcp-top-50-audit.json) · Script: [`scripts/audit_top_mcp_servers.py`](../scripts/audit_top_mcp_servers.py)*

**MCP (Model Context Protocol)** lets AI coding tools (Claude Code, Cursor, Codex, Gemini CLI) connect to external tools like databases, GitHub, Figma, Slack, and browsers. Most MCP servers are small helper programs that run locally on your machine (usually launched via `npx` or `uvx`) with direct access to your local files, shell environment variables, and network.

To see what typical setups look like in practice, we checked the **50 most-starred dedicated MCP server repositories on GitHub** (`3,672` to `57,776` stars, `579,264` stars combined).

For each repository, we checked its official `README` install snippet and package manifest (`package.json` or `pyproject.toml`) for three concrete patterns.

## Summary

| Pattern Checked | Count (of 50) | Share | Practical Risk on a Developer Machine |
| :--- | :---: | :---: | :--- |
| **1. Unpinned auto-install (`npx -y` / `uvx` without version)** | **35 / 50** | **70%** | Pulls and runs whatever code was most recently published to npm or PyPI every time your agent starts, with access to local files and shell env vars. |
| **2. Plain-text API keys in JSON config examples** | **12 / 50** | **24%** | Guides users to paste raw tokens (`"API_KEY": "sk-..."`) directly inside `.mcp.json` or `claude_desktop_config.json`, where other agents read them or git commits pick them up. |
| **3. Built-in analytics or telemetry** | **12 / 50** | **24%** | Ships third-party analytics SDKs (`PostHog`, `Segment`, `Sentry`) or usage pings inside a local tool bridge, making background network calls many users do not expect. |

## Why This Happens

Maintainers optimize `README` snippets for a 10-second setup:

1. Writing `"command": "npx", "args": ["-y", "@org/some-mcp"]` avoids version-mismatch issues when new releases ship.
2. Showing `"env": { "SERVICE_API_KEY": "your-real-key" }` is shorter to explain than environment variable forwarding (`"${SERVICE_API_KEY}"`).
3. Adding `PostHog` or `Sentry` helps maintainers track crash rates and adoption.

The risk compounds when a developer installs 5 to 10 MCP servers side by side:
- If any unpinned npm or PyPI package is hijacked, opening Claude Code or Cursor automatically downloads and runs the compromised version.
- Every child process started by your coding CLI inherits shell environment variables unless stripped, so an unrelated MCP server can read `AWS_SECRET_ACCESS_KEY` or `STRIPE_SECRET_KEY` from your shell.
- When an agent reads `.mcp.json` or `.env` while debugging code, plain-text keys inside those files get copied into `~/.claude` or `~/.codex` session logs on disk.

## Quick Fixes

1. **Pin exact versions in `.mcp.json` and `claude_desktop_config.json`:**
   Change `"@org/server"` to `"@org/server@1.2.3"` (or `pkg==1.2.3` for `uvx`) so updates only happen when you choose.
2. **Keep raw keys out of JSON config files:**
   Use environment variable references (`"${GITHUB_PERSONAL_ACCESS_TOKEN}"`) where supported, and add `.mcp.json` to `.gitignore` if it holds project settings.
3. **Strip extra shell secrets when launching agents or MCP servers:**
   Run `leaktap claude` (or `leaktap tap --scrub-env -- <command>`) so child tools only receive variables you explicitly allow (`--allow-env`).
4. **Scan existing logs and configs offline:**
   Run `leaktap` to check for plain-text keys already saved in local chat transcripts (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`) and risky settings in MCP configs.

## Full 50-Repository Results

| # | Repository | Stars | Language | Unpinned Install | Plain-Text Key Docs | Telemetry Signal |
| :---: | :--- | ---: | :--- | :---: | :---: | :--- |
| 1 | [`ChromeDevTools/chrome-devtools-mcp`](https://github.com/ChromeDevTools/chrome-devtools-mcp) | 57,776 | TypeScript | Yes | - | - |
| 2 | [`DeusData/codebase-memory-mcp`](https://github.com/DeusData/codebase-memory-mcp) | 48,742 | C | Yes | - | `documented-telemetry` |
| 3 | [`microsoft/playwright-mcp`](https://github.com/microsoft/playwright-mcp) | 39,755 | TypeScript | Yes | - | - |
| 4 | [`ahujasid/mcp-for-blender`](https://github.com/ahujasid/mcp-for-blender) | 34,683 | Python | Yes | - | `documented-telemetry` |
| 5 | [`github/github-mcp-server`](https://github.com/github/github-mcp-server) | 34,535 | Go | - | Yes | - |
| 6 | [`czlonkowski/n8n-mcp`](https://github.com/czlonkowski/n8n-mcp) | 23,266 | TypeScript | - | - | `documented-telemetry` |
| 7 | [`xpzouying/xiaohongshu-mcp`](https://github.com/xpzouying/xiaohongshu-mcp) | 17,159 | Go | - | - | - |
| 8 | [`googleapis/mcp-toolbox`](https://github.com/googleapis/mcp-toolbox) | 16,890 | Go | Yes | - | `documented-telemetry` |
| 9 | [`apify/apify-mcp-server`](https://github.com/apify/apify-mcp-server) | 16,577 | TypeScript | Yes | Yes | `analytics-node`, `documented-telemetry`, `segment`, `sentry` |
| 10 | [`GLips/Figma-Context-MCP`](https://github.com/GLips/Figma-Context-MCP) | 16,219 | TypeScript | Yes | - | `posthog` |
| 11 | [`hangwin/mcp-chrome`](https://github.com/hangwin/mcp-chrome) | 12,548 | TypeScript | Yes | - | - |
| 12 | [`LaurieWired/GhidraMCP`](https://github.com/LaurieWired/GhidraMCP) | 11,955 | Java | Yes | - | - |
| 13 | [`BeehiveInnovations/pal-mcp-server`](https://github.com/BeehiveInnovations/pal-mcp-server) | 11,841 | Python | Yes | Yes | - |
| 14 | [`CursorTouch/Windows-MCP`](https://github.com/CursorTouch/Windows-MCP) | 11,773 | Python | Yes | Yes | `documented-telemetry`, `posthog` |
| 15 | [`mobile-next/mobile-mcp`](https://github.com/mobile-next/mobile-mcp) | 10,631 | TypeScript | Yes | - | `documented-telemetry` |
| 16 | [`wonderwhy-er/DesktopCommanderMCP`](https://github.com/wonderwhy-er/DesktopCommanderMCP) | 10,331 | JavaScript | Yes | - | `documented-telemetry` |
| 17 | [`Ryze-AI-Adgent/open-seo-mcp-skills`](https://github.com/Ryze-AI-Adgent/open-seo-mcp-skills) | 10,260 | Shell | - | - | - |
| 18 | [`awslabs/mcp`](https://github.com/awslabs/mcp) | 9,929 | Python | Yes | Yes | - |
| 19 | [`idosal/git-mcp`](https://github.com/idosal/git-mcp) | 8,524 | TypeScript | Yes | - | - |
| 20 | [`irinabuht12-oss/google-ads-meta-ads-mcp`](https://github.com/irinabuht12-oss/google-ads-meta-ads-mcp) | 8,067 | Other | - | - | - |
| 21 | [`homeassistant-ai/ha-mcp`](https://github.com/homeassistant-ai/ha-mcp) | 7,910 | Python | Yes | - | `documented-telemetry` |
| 22 | [`firecrawl/firecrawl-mcp-server`](https://github.com/firecrawl/firecrawl-mcp-server) | 7,842 | JavaScript | Yes | Yes | - |
| 23 | [`BrowserMCP/mcp`](https://github.com/BrowserMCP/mcp) | 7,370 | TypeScript | - | - | - |
| 24 | [`AgentDeskAI/browser-tools-mcp`](https://github.com/AgentDeskAI/browser-tools-mcp) | 7,344 | TypeScript | Yes | - | `documented-telemetry` |
| 25 | [`tradesdontlie/tradingview-mcp`](https://github.com/tradesdontlie/tradingview-mcp) | 7,213 | JavaScript | - | - | - |
| 26 | [`grab/cursor-talk-to-figma-mcp`](https://github.com/grab/cursor-talk-to-figma-mcp) | 7,115 | JavaScript | Yes | - | - |
| 27 | [`lharries/whatsapp-mcp`](https://github.com/lharries/whatsapp-mcp) | 6,906 | Go | - | - | - |
| 28 | [`Coding-Solo/godot-mcp`](https://github.com/Coding-Solo/godot-mcp) | 6,679 | JavaScript | Yes | Yes | - |
| 29 | [`21st-dev/magic-mcp`](https://github.com/21st-dev/magic-mcp) | 6,573 | TypeScript | Yes | - | - |
| 30 | [`jacob-bd/gemini-notebook-mcp-cli`](https://github.com/jacob-bd/gemini-notebook-mcp-cli) | 6,525 | Python | Yes | - | - |
| 31 | [`bethington/ghidra-mcp`](https://github.com/bethington/ghidra-mcp) | 6,258 | Java | - | - | - |
| 32 | [`sooperset/mcp-atlassian`](https://github.com/sooperset/mcp-atlassian) | 6,128 | Python | Yes | Yes | - |
| 33 | [`54yyyu/zotero-mcp`](https://github.com/54yyyu/zotero-mcp) | 5,944 | Python | - | - | - |
| 34 | [`excalidraw/excalidraw-mcp`](https://github.com/excalidraw/excalidraw-mcp) | 5,687 | TypeScript | - | - | - |
| 35 | [`executeautomation/mcp-playwright`](https://github.com/executeautomation/mcp-playwright) | 5,683 | TypeScript | Yes | - | - |
| 36 | [`atilaahmettaner/tradingview-mcp`](https://github.com/atilaahmettaner/tradingview-mcp) | 5,302 | Python | Yes | - | - |
| 37 | [`exa-labs/exa-mcp-server`](https://github.com/exa-labs/exa-mcp-server) | 5,241 | TypeScript | - | - | - |
| 38 | [`openclaw/mcporter`](https://github.com/openclaw/mcporter) | 5,125 | TypeScript | - | - | - |
| 39 | [`makenotion/notion-mcp-server`](https://github.com/makenotion/notion-mcp-server) | 4,715 | TypeScript | Yes | Yes | - |
| 40 | [`IvanMurzak/Unity-MCP`](https://github.com/IvanMurzak/Unity-MCP) | 4,649 | C# | - | - | - |
| 41 | [`MarkusPfundstein/mcp-obsidian`](https://github.com/MarkusPfundstein/mcp-obsidian) | 4,543 | Python | Yes | Yes | - |
| 42 | [`open-webui/mcpo`](https://github.com/open-webui/mcpo) | 4,429 | Python | Yes | - | - |
| 43 | [`antvis/mcp-server-chart`](https://github.com/antvis/mcp-server-chart) | 4,417 | TypeScript | Yes | - | - |
| 44 | [`haris-musa/excel-mcp-server`](https://github.com/haris-musa/excel-mcp-server) | 4,311 | Python | Yes | - | - |
| 45 | [`Pimzino/spec-workflow-mcp`](https://github.com/Pimzino/spec-workflow-mcp) | 4,306 | TypeScript | Yes | - | - |
| 46 | [`stickerdaniel/linkedin-mcp-server`](https://github.com/stickerdaniel/linkedin-mcp-server) | 4,230 | Python | Yes | - | - |
| 47 | [`samuelgursky/davinci-resolve-mcp`](https://github.com/samuelgursky/davinci-resolve-mcp) | 4,134 | Python | - | - | - |
| 48 | [`googleanalytics/google-analytics-mcp`](https://github.com/googleanalytics/google-analytics-mcp) | 3,802 | Python | Yes | Yes | - |
| 49 | [`Minidoracat/mcp-feedback-enhanced`](https://github.com/Minidoracat/mcp-feedback-enhanced) | 3,750 | JavaScript | Yes | - | - |
| 50 | [`grafana/mcp-grafana`](https://github.com/grafana/mcp-grafana) | 3,672 | Go | Yes | Yes | `documented-telemetry` |

## Reproduce This Audit

Re-run the script against live GitHub data with the GitHub CLI (`gh`):

```bash
python3 scripts/audit_top_mcp_servers.py /tmp/mcp_top50_audit.json
```
