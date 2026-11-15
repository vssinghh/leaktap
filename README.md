# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See what your AI coding CLIs actually leak.

`leaktap` scans your local AI chat logs and MCP configs for leaked API keys, database URLs, and personal info, scrubs old logs, and watches live CLI sessions for leaked secrets, HTTP headers, and network connections.

Currently supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, and local **MCP servers**. Desktop and IDE apps aren't supported for live watching yet, though `leaktap scan` will still check any local logs and MCP configs they leave on disk.

> **2026 MCP Audit:** Out of the 50 most-starred MCP servers on GitHub, **70%** tell users to run unpinned `npx -y` or `uvx` installs, **24%** show plain-text API keys in JSON config examples, and **24%** ship built-in analytics or telemetry. [Read the full write-up →](docs/mcp-top-50-audit.md)

## Install

macOS and Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/vssinghh/leaktap/master/install.sh | sh
```

Or run via `npx` or `cargo`:

```bash
npx leaktap scan

cargo install --git https://github.com/vssinghh/leaktap
```

Prebuilt binaries for macOS, Linux, and Windows are on [GitHub Releases](https://github.com/vssinghh/leaktap/releases).

## Example output

```text
$ leaktap scan

leaktap v0.2.5 — local offline audit (0 network requests)
Scanned 142 file(s) (49.0 MB) in 119ms across ~/.claude, ~/.codex, ~/.gemini

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

## Why I built this

When you run `claude`, `codex`, or `agy` inside a project, it reads files like `.env` while debugging code. Those keys and database URLs get saved in plain text inside `~/.claude`, `~/.codex`, or `~/.gemini` chat logs, sent out in prompts, and exposed to MCP servers through inherited shell variables. Outgoing HTTP headers like `User-Agent` can also carry your email or machine hostname.

OS file sandboxes like `sandbox-exec` and `bubblewrap` are good at blocking folders outside your repo like `~/.ssh`, which helps, but the CLI still needs read access to your repo and internet access to work. Once network access is open, file sandboxes can't see what goes out in prompts or headers. Full HTTPS proxies go too far the other way: they need Docker and a custom root certificate, and replacing keys with `[REDACTED]` breaks `git apply` when a patch comes back.

`leaktap` is a single binary with no setup. It checks what already leaked on your machine in ~120ms offline, gives you a terminal UI to browse and clean findings, and can wrap `claude`, `codex`, or `agy` to inspect live calls without installing root certificates.

## Usage

### Scan local logs and MCP configs

Runs offline. Checks `~/.claude`, `~/.codex`, `~/.gemini`, `~/.cursor`, and MCP config files like `.mcp.json` and `.agents/mcp_config.json` in your current directory:

```bash
# Default scan
leaktap

# Scan a specific folder or file
leaktap scan --path ./my-project

# JSON or SARIF output for CI
leaktap scan --path . --format json
leaktap scan --path . --format sarif --fail-on high > leaktap.sarif
```

### Terminal UI

Opens an interactive terminal view with three tabs: `Transcript Leaks`, `MCP Config Risks`, and `Live Wiretap`.

```bash
leaktap ui
```

Use `j`/`k` or arrow keys to move, `1`-`3` or `Tab` to switch tabs, and `c` to scrub the selected log file in place after saving a `.leaktap.bak` backup.

### Clean leaked keys from old chat logs

Runs a dry-run preview by default. Passing `--apply` writes a `.leaktap.bak` backup and replaces only the secret strings so `.jsonl` files stay valid when resuming chats. Add `--no-backup` if you do not want backup copies left on disk:

```bash
# Preview what would be cleaned
leaktap clean

# Apply changes and keep .leaktap.bak backups
leaktap clean --apply

# Apply changes without keeping backup copies
leaktap clean --apply --no-backup
```

### Watch live CLI sessions

Wraps `claude`, `codex`, `agy`, `gemini`, or an MCP server command:

- `--scrub-env` strips extra secret variables from your shell like `AWS_SECRET_ACCESS_KEY` or `STRIPE_SECRET_KEY` before starting the command, while keeping the CLI's own API key.
- `--inspect-api` points `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `GOOGLE_GEMINI_BASE_URL` at a local port on `localhost` so `leaktap` can check outgoing HTTP headers and prompt bodies before forwarding requests over HTTPS. For Antigravity CLI, Google sign-in skips `GOOGLE_GEMINI_BASE_URL`; pass `--settings '{"modelProvider":"gemini"}'` with `GEMINI_API_KEY` set when using `--inspect-api`.
- Outbound TCP connections opened by the CLI and its child processes are logged automatically without `sudo`.

```bash
# Watch Claude Code or Codex CLI
leaktap tap --inspect-api --scrub-env -- claude
leaktap tap --inspect-api --scrub-env -- codex

# Watch Antigravity CLI with Google sign-in, or inspect API calls with GEMINI_API_KEY
leaktap tap --scrub-env -- agy
leaktap tap --inspect-api --scrub-env -- agy --settings '{"modelProvider":"gemini"}'

# Wrap an MCP server in .mcp.json or .agents/mcp_config.json
leaktap tap --scrub-env --quiet --log /tmp/mcp-wiretap.jsonl -- npx -y @org/some-mcp
```

### List built-in checks

```bash
leaktap rules
```

## Privacy

- `leaktap scan` and `leaktap clean` make zero network requests.
- No telemetry, analytics, or accounts.
- Matched secrets are always masked like `sk_live_9f...4c21` in terminal, UI, JSON, SARIF, and log output.

## License

[MIT](LICENSE)
