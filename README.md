# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**See what your AI coding agents actually leak.**

`leaktap` is a small, fast command-line tool (single Rust binary, zero tracking) that checks your local AI coding logs and MCP server configs for leaked API keys, passwords, and private info—and watches live agent sessions for secret, HTTP header, and network connection leaks without needing Docker or custom HTTPS certificates.

Works with **Claude Code** · **Cursor** · **Codex CLI** · **Gemini CLI** · **Windsurf** · **MCP Servers**

> [!NOTE]
> **2026 MCP Audit ([read full report](docs/mcp-top-50-audit.md)):** Across the Top 50 open-source MCP servers on GitHub, **70%** recommend unpinned `npx -y` / `uvx` auto-installs, **24%** guide users to paste plain-text API keys into JSON config files, and **24%** include built-in telemetry or analytics SDKs.

---

## Quick Install

### macOS & Linux (1-Line Installer — Verifies SHA-256 Checksum)

```bash
curl -fsSL https://raw.githubusercontent.com/vssinghh/leaktap/master/install.sh | sh
```

### Or Run via `npx` / `cargo` / Prebuilt Binaries

```bash
# Via npx (Node 18+)
npx leaktap scan

# Via Cargo (Rust 1.75+)
cargo install --git https://github.com/vssinghh/leaktap
```

Prebuilt binaries for **macOS (`arm64` / `x64`)**, **Linux (`x64` / `arm64`)**, and **Windows (`x64`)** are also available on **[GitHub Releases](https://github.com/vssinghh/leaktap/releases)**.

---

## The Problem (One Simple Example)

Say you ask Claude Code or Cursor to fix a Stripe checkout bug in your repo:

1. **The agent reads your `.env` file:** While searching your code, the agent opens `.env.local` and reads `STRIPE_SECRET_KEY=sk_live_9f8a...` and `DATABASE_URL=postgres://...`, along with your work email and internal company URLs.
2. **Your live keys get saved in plain text and sent out:** Those raw keys are written straight to local chat logs (`~/.claude/` or `~/.codex/`), included in model prompts, and passed into third-party MCP servers or shell commands—while HTTP headers like `User-Agent` can quietly attach your email or machine name.
3. **Why OS file sandboxes don't stop this:** File sandboxes (`sandbox-exec` on macOS, `bubblewrap` on Linux) are great at blocking folders outside your project like `~/.ssh`. **But** the agent needs read access to your project folder and internet access to work. Once internet access is on, OS file sandboxes cannot see what is inside outgoing headers, prompts, or MCP tool calls.
4. **Why heavy network proxies get in your way:** Classic security proxies ask you to run Docker, trust a custom root certificate, and replace secrets with `[REDACTED]`. That often breaks OAuth logins—and makes `git apply` fail when `[REDACTED]` comes back inside a code patch.

`leaktap` keeps things simple: **audit what already leaked on your laptop in under a second offline**, browse and clean leaks in an interactive terminal UI, and watch live commands without Docker or custom root certificates.

---

## What `leaktap scan` Looks Like

```text
$ leaktap scan

leaktap v0.2.0 — local offline audit (0 network requests)
Scanned 142 file(s) (49.0 MB) in 119ms across ~/.claude, ~/.codex, ~/.cursor

CRITICAL  3 unique secret(s) found in local agent transcripts
  ├─ Database URI          postgres://***@db.prod.acme.io  ~/.claude/projects/app/08fa.jsonl:184
  ├─ AWS Access Key        AKIA5F29Q...7Q2M                ~/.claude/projects/infra/91bc.jsonl:42
  └─ Stripe Live Key       sk_live_9f...4c21 (2x)          ~/.claude/projects/app/08fa.jsonl:184

HIGH      3 MCP configuration risk(s) detected
  ├─ @community/db-mcp (.mcp.json)
  │    Runs unpinned `npx -y @community/db-mcp` — pulls latest remote code on start with local file/env access
  ├─ @community/db-mcp (.mcp.json)
  │    Grants broad filesystem access (`/`) instead of scoping to one workspace folder
  └─ @community/db-mcp (.mcp.json)
       References outbound analytics/telemetry endpoint (`events.posthog.com`)

MEDIUM    Identity & internal metadata in outbound context
  └─ 1 email address(es) + 1 internal hostname(s) appeared across 2 transcript hit(s)

Next steps:
  • Open interactive dashboard:    leaktap ui
  • Preview & scrub local logs:    leaktap clean --apply
  • Watch live headers & prompts:  leaktap tap --inspect-api --scrub-env -- claude
```

---

## Commands

### 1. Check Local Logs and MCP Configs (`scan`)

Runs 100% offline. Checks `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`, `~/.codeium`, and any MCP config files in your current project:

```bash
# Default scan across your local coding agents
leaktap

# Scan one specific folder or file
leaktap scan --path ./my-project

# Output JSON or SARIF (for GitHub Actions / CI checks)
leaktap scan --path . --format json
leaktap scan --path . --format sarif --fail-on high > leaktap.sarif
```

### 2. Open the Interactive Terminal Dashboard (`ui`)

Opens a keyboard-driven terminal dashboard with three tabs (**`[1] Transcript Leaks`**, **`[2] MCP Config Risks`**, and **`[3] Live Wiretap`**):

```bash
leaktap ui
```

- Move with `↑`/`↓` or `j`/`k`, switch tabs with `Tab` or `1`–`3`, press **`c`** on any leaked secret to scrub that log file in place (with a `.leaktap.bak` backup), and watch live `leaktap tap` events stream into Tab 3 automatically.

### 3. Scrub Leaked Keys from Old Chat Logs (`clean`)

By default, `leaktap clean` runs a **safe preview** without touching any files. When you pass `--apply`, it saves a `.leaktap.bak` backup first and replaces only the secret values so your `.jsonl` chat history still opens cleanly in `/resume`:

```bash
# Preview how many secrets would be scrubbed
leaktap clean

# Scrub secrets and keep .leaktap.bak backups
leaktap clean --apply
```

### 4. Watch Live Sessions, HTTP Headers & Outbound Connections (`tap`)

Wraps any agent CLI or MCP server:
- **`--scrub-env`** removes unrelated secret environment variables (like `AWS_SECRET_ACCESS_KEY` or `STRIPE_SECRET_KEY` sitting in your shell) before starting the child process.
- **`--inspect-api`** routes `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` through a local zero-certificate loopback listener so `leaktap` can check outgoing HTTP headers (`User-Agent` email/hostname leaks) and prompt bodies in real time while streaming model responses straight back.
- **Process socket watch** monitors outbound TCP connections opened by the agent and its child MCP tools without needing `sudo`.

```bash
# Run Claude Code while checking outgoing HTTP headers/prompts and stripping unrelated shell secrets
leaktap tap --inspect-api --scrub-env --allow-env ANTHROPIC_API_KEY -- claude

# Wrap a third-party MCP server inside .mcp.json (alerts go to stderr/log so stdout tool responses stay intact)
leaktap tap --scrub-env --quiet --log /tmp/mcp-wiretap.jsonl -- npx -y @org/some-mcp
```

### 5. List All Built-in Checks (`rules`)

```bash
leaktap rules
```

---

## How It Stays Fast and Low-Noise

- **Scans ~400 MB/s without freezing on huge log lines:** AI logs often contain giant 20 MB single-line JSON outputs from build tools. `leaktap` checks quick text prefixes first and uses Rust's non-backtracking regex engine across all CPU cores, scanning 50 MB (110,000 turns) in ~120ms.
- **Catches keys inside escaped `.jsonl` strings:** Properly finds secrets sitting right next to `\n`, `\r`, or `\t` escapes inside JSON log lines.
- **Skips dummy values and local test noise:** Checks how random a secret looks so real keys get flagged while dummy strings (`AKIAIOSFODNN7EXAMPLE`, `your_api_key`), local test DBs (`localhost`), `git@github.com`, and npm `@scope/pkg` names are ignored.
- **Groups duplicate hits:** If the same Stripe key shows up 15 times in one chat, `leaktap` hashes it in memory and lists it once (`(15x)`) instead of flooding your terminal.

---

## Privacy Promise

- **Offline by default:** `leaktap scan` and `leaktap clean` make **zero** internet requests.
- **Zero tracking:** No analytics, no telemetry, no accounts.
- **Always masked:** Secrets are always shortened (`sk_live_9f...4c21`) in terminal, TUI, JSON, SARIF, and wiretap outputs so `leaktap` never dumps raw credentials onto your screen or CI logs.

---

## Roadmap

- [x] **`v0.1` — Core CLI (`scan`, `clean`, `tap`, `rules`):** Fast offline log scanner, MCP config checker, safe `.jsonl` cleaner, `stdio`/env wrapper, and JSON/SARIF output.
- [x] **`v0.2` — Interactive Dashboard + Header & Socket Watch:** 3-tab terminal UI (`leaktap ui`), zero-cert `--inspect-api` HTTP header/prompt inspector, OS socket watcher, and 1-line SHA-256-verified installer.
- [ ] **`v0.3` — Safe Placeholder Swap:** Swap real secrets with same-format placeholders before prompts leave your machine, then swap the real value back locally so `git apply` patches still work.

---

## License

[MIT](LICENSE)
