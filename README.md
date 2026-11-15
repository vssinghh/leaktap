# leaktap

**See what your AI coding agents actually leak.**

`leaktap` audits your local AI coding sessions and installed MCP servers for leaked secrets, personal data, and hidden outbound calls—and wiretaps live agent sessions without Docker, cloud accounts, or broken code patches.

Works across **Claude Code** · **Cursor** · **Codex CLI** · **Gemini CLI** · **MCP Servers**

> [!IMPORTANT]
> **Status:** Early active development (`v0.1.0` CLI in progress). Star or watch the repo to follow the initial release.

---

## Why `leaktap` Exists

Suppose you ask a coding agent to fix a payment bug in your repository:

1. **Silent file read:** While grepping the codebase, the agent reads `.env.local` (`STRIPE_SECRET_KEY=sk_live_9f8a...` and `DATABASE_URL=postgres://...`) plus your git email and internal service URLs.
2. **Plaintext logs + outbound payloads:** Those raw credentials are saved in plaintext inside `~/.claude/` or `~/.codex/` session logs, sent out in model prompts, and passed into third-party MCP tools or shell commands.
3. **Why OS file sandboxes miss it:** Tools like macOS `sandbox-exec` and Linux `bubblewrap` are great at blocking `~/.ssh`, **until** you grant access to your project folder and outbound HTTPS so the agent can do its job. Once HTTPS is open, OS file sandboxes cannot see what leaves inside headers, prompt bodies, or MCP tool calls.
4. **Why heavy proxies break coding:** Traditional DLP proxies require Docker Desktop, custom TLS root certificates, and naive `[REDACTED]` text replacement—which breaks OAuth logins and causes `git apply` to fail when the model echoes `[REDACTED]` back in a diff.

`leaktap` takes an **audit-first, zero-Docker** approach: see what already leaked on your machine in 5 seconds offline, then wrap live sessions when you want active protection.

---

## Preview: The 5-Second Offline Audit (`leaktap scan`)

```text
$ npx leaktap scan

leaktap v0.1.0 — local offline audit (0 network requests)
Scanned 142 sessions across ~/.claude, ~/.codex, ~/.cursor, ~/.gemini

CRITICAL  4 live secrets found in local agent transcripts
  ├─ Stripe Live Key   sk_live_9f...4c21   ~/.claude/projects/app/08fa.jsonl:184
  ├─ AWS Access Key    AKIA5F29...7Q2M     ~/.claude/projects/infra/91bc.jsonl:42
  ├─ Postgres URI      postgres://...prod  ~/.codex/sessions/2026-11-12.jsonl:309
  └─ GitHub PAT        ghp_x82K...91aB     ~/.cursor/chats/auth-fix/chat.json:77

HIGH      2 risky MCP server configs detected
  ├─ @community/db-mcp (.mcp.json)
  │    Passes full shell env (29 vars incl. AWS_SECRET_ACCESS_KEY) + unpinned npx -y
  └─ docs-helper-mcp (claude_desktop_config.json)
       Known outbound telemetry endpoint: events.docs-helper.io

MEDIUM    Identity & internal metadata in outbound context
  └─ Work email + 3 internal *.corp hostnames appeared in 19 prompts

Next steps:
  • Redact leaked secrets from local logs:   npx leaktap clean --dry-run
  • Wiretap a live coding session:           npx leaktap tap -- claude
```

---

## Core Capabilities

### 1. Offline Transcript & Config Audit (`leaktap scan`)
- **Zero setup, 100% offline:** Scans existing local session histories (`.jsonl` / SQLite / JSON) for Claude Code, Codex CLI, Cursor, and Gemini CLI without making a single network call.
- **High-precision secret detection:** Catches cloud keys (AWS, GCP, Azure), API tokens (Stripe, GitHub, Slack, OpenAI, Anthropic), private keys, JWTs, and database URLs—while ignoring placeholder test values (`EXAMPLE`, `xxxx`, dummy fixtures).
- **MCP config & supply-chain check:** Inspects `.mcp.json`, `claude_desktop_config.json`, and `.cursor/mcp.json` for full environment-variable inheritance, unpinned `npx -y` execution, unrestricted filesystem/shell access, and silent analytics endpoints.
- **Safe local cleanup (`leaktap clean`):** Scrubs exposed credentials out of local `.jsonl` session transcripts in place (with backup + `--dry-run` preview) so old chats stop sitting on disk as a plaintext credential vault.

### 2. Live Session Wiretap (`leaktap tap -- <agent>`)
- **MCP `stdio` & subprocess wiretap:** Sits transparently between your coding agent and its MCP servers / child commands to log every tool call, file read, and outbound destination in real time.
- **Header & telemetry watch:** Flags unexpected outbound domains and identity leaks in HTTP headers (such as emails or hostnames embedded in `User-Agent` or custom `X-*` headers).
- **Lossless fake-token swap *(planned `v0.3`)*:** Replaces a real secret like `sk_live_9f8a...` with a same-format placeholder (`sk_live_LEAKTAP_0001...`) before it leaves your machine, and swaps the real value back locally if referenced—so secrets stay local while code edits and `git apply` keep working.

---

## How `leaktap` Fits With Existing Tools

| Approach | Catches secrets inside current repo `.env`? | Sees MCP payloads & outbound leaks? | Requires Docker or TLS Root CA? | Keeps `git apply` & OAuth intact? |
| :--- | :---: | :---: | :---: | :---: |
| **OS File Sandboxes** (`sandbox-exec`, `safehouse`) | No *(agent needs repo read access)* | No | No | Yes |
| **Docker MITM Proxies** (`codegate`, corp DLP) | Partial | Yes | **Yes (heavy)** | Often breaks |
| **MCP-Only Sniffers** (`mcpsnoop`) | No *(misses transcripts & configs)* | MCP `stdio` only | No | Yes |
| **`leaktap`** | **Yes** | **Yes** | **No** | **Yes** |

> **Tip:** `leaktap` pairs cleanly with OS sandboxes. Use an OS sandbox to block `~/.ssh` and `~/.aws` outside your workspace, and use `leaktap` to catch `.env` secrets, transcript leaks, and MCP/network behavior inside your workspace.

---

## Privacy & Trust Model

Security tools should never become a new data risk:

- **Offline by default:** `leaktap scan` and `leaktap clean` run strictly on your machine and make **zero** outbound network connections.
- **Zero telemetry:** No analytics, no crash reporting, no account sign-up.
- **Always masked:** Matched secrets are truncated by default (`sk_live_9f...4c21`) so running `leaktap` never dumps raw credentials into your terminal scrollback or CI logs.

---

## Roadmap

- [ ] **`v0.1` — Offline Scanner & Cleaner (`scan`, `clean`):** Scan Claude Code, Codex, Cursor, and Gemini CLI transcripts + audit MCP configs + export JSON/SARIF reports for CI.
- [ ] **`v0.2` — Live Wiretap (`tap`):** Wrap MCP `stdio` servers and agent subprocesses with live outbound domain, tool-argument, and header leak alerts.
- [ ] **`v0.3` — Lossless Secret Guard:** Deterministic format-preserving token substitution before prompts or tool outputs leave your machine.
- [ ] **`v0.4` — Public MCP Leak Benchmark:** Automated reproducible audit methodology for popular open-source MCP servers and skills.

---

## License

MIT
