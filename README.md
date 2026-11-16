# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See what your AI coding CLIs actually leak.

`leaktap` scans your local AI chat logs, MCP configs, and installed marketplace plugins, hooks, and skills for leaked API keys, risky shell hooks, and hidden prompt instructions. It also scrubs old logs and watches live CLI sessions for leaked secrets, HTTP headers, and network connections.

Currently supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, and local **MCP servers**. Desktop and IDE apps aren't supported for live watching yet, though `leaktap scan` will still check any local logs, plugins, and MCP configs they leave on disk.

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
$ leaktap

leaktap v0.2.8 — local offline audit (0 network requests)
Scanned 148 file(s) (49.1 MB) in 122ms across ~/.claude, ~/.codex, ~/.gemini

CRITICAL  3 unique secret(s) found in local agent transcripts
  ├─ Database URI          postgres://***@db.prod.acme.io  ~/.claude/projects/app/08fa.jsonl:184
  ├─ AWS Access Key        AKIA5F29Q...7Q2M                ~/.claude/projects/infra/91bc.jsonl:42
  └─ Stripe Live Key       sk_live_9f...4c21 (2x)          ~/.claude/projects/app/08fa.jsonl:184

CRITICAL  4 MCP / plugin risk(s) detected
  ├─ plugin:shady-linter (~/.claude/plugins/cache/community/shady-linter/0.1.0/hooks-handlers/sync.sh)
  │    References sensitive host credential store (`~/.ssh/id_rsa`) outside workspace
  ├─ plugin:shady-linter (~/.claude/plugins/cache/community/shady-linter/0.1.0/hooks/hooks.json)
  │    Lifecycle hook `PreToolUse` runs handler `hooks-handlers/sync.sh` with an outbound network call (`collect.shady-plugin.io`)
  ├─ @community/db-mcp (.mcp.json)
  │    Runs unpinned `npx -y @community/db-mcp` — pulls latest remote code on start with local file/env access
  └─ @community/db-mcp (.mcp.json)
       References outbound analytics/telemetry endpoint (`events.posthog.com`)

MEDIUM    Identity & internal metadata in outbound context
  └─ 1 email address(es) + 1 internal hostname(s) appeared across 2 transcript hit(s)

Next steps:
  • Open interactive dashboard:    leaktap ui
  • Preview & scrub local logs:    leaktap clean --apply
  • Start a watched CLI session:   leaktap claude   (or `codex` / `agy`)
```

## Why I built this

When you run `claude`, `codex`, or `agy` inside a project, two things create most of the real exposure. First, the CLI reads files like `.env` while debugging code and saves those keys and database URLs in plain text inside `~/.claude`, `~/.codex`, or `~/.gemini` chat logs. Second, community MCP servers and marketplace plugins run directly on your machine: plugins can register `hooks.json` commands that run on every tool call, bundle unpinned `npx -y` servers, read `~/.ssh` or `~/.aws`, or hide instructions inside `SKILL.md`.

OS file sandboxes like `sandbox-exec` and `bubblewrap` are good at blocking folders outside your repo like `~/.ssh`, which helps, but the CLI and its plugins still need read access to your repo and internet access to work. Once network access is open, file sandboxes can't see what goes out in prompts or headers. Full HTTPS proxies go too far the other way: they need Docker and a custom root certificate, and replacing keys with `[REDACTED]` breaks `git apply` when a patch comes back.

`leaktap` is a single binary with no setup. It checks your chat logs, MCP configs, and installed plugins and hooks in ~120ms offline, gives you a terminal UI to browse and clean findings, and starts `claude`, `codex`, or `agy` with live session watching in two words without installing root certificates.

## Usage

### Scan local logs, MCP configs, and plugins

Runs offline. Checks `~/.claude`, `~/.codex`, `~/.gemini`, `~/.cursor`, installed marketplace plugins, `hooks.json` lifecycle hooks, `SKILL.md` skills, and MCP config files like `.mcp.json`, `.codex/config.toml`, and `.agents/mcp_config.json`:

```bash
# Default scan
leaktap

# Scan a specific project or plugin folder before enabling it
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

Start `claude`, `codex`, `agy`, or `gemini` directly through `leaktap` — any extra arguments pass straight through to the CLI:

```bash
leaktap claude
leaktap codex
leaktap agy
```

What happens automatically when you run those commands:

- Extra secret variables in your shell like `AWS_SECRET_ACCESS_KEY` or `STRIPE_SECRET_KEY` are stripped before launch, while keeping the CLI's own API key.
- Outgoing API calls from `claude`, `codex`, and `gemini` route through a local port on `localhost` so `leaktap` can check HTTP headers and prompt bodies before forwarding over HTTPS. For Antigravity CLI, Google sign-in skips `GOOGLE_GEMINI_BASE_URL`; pass `leaktap agy --settings '{"modelProvider":"gemini"}'` with `GEMINI_API_KEY` set if you also want prompt and header inspection.
- Outbound TCP connections opened by the CLI and its child MCP processes are logged to `~/.leaktap/live.jsonl` without `sudo` so you can watch them live in `leaktap ui`.

If you want custom flags or want to wrap an individual MCP server command in `.mcp.json` or `.agents/mcp_config.json`, use `leaktap tap`:

```bash
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
