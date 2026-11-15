# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**See what your AI coding agents actually leak.**

`leaktap` is a fast, zero-telemetry Rust CLI (`2.6 MB` single binary) that audits local AI coding sessions and MCP server configs for leaked secrets, personal metadata, and supply-chain risks—and wiretaps live agent or MCP `stdio` sessions without Docker or custom TLS root certificates.

Works across **Claude Code** · **Cursor** · **Codex CLI** · **Gemini CLI** · **Windsurf** · **MCP Servers**

---

## Why `leaktap` Exists

Suppose you ask a coding agent to fix a payment bug in your repository:

1. **Silent file read:** While grepping the codebase, the agent reads `.env.local` (`STRIPE_SECRET_KEY=sk_live_9f8a...` and `DATABASE_URL=postgres://...`) plus your git email and internal service URLs.
2. **Plaintext logs + outbound payloads:** Those raw credentials are saved in plaintext inside `~/.claude/` or `~/.codex/` session logs, sent out in model prompts, and passed into third-party MCP tools or shell commands.
3. **Why OS file sandboxes miss it:** Tools like macOS `sandbox-exec` and Linux `bubblewrap` are great at blocking `~/.ssh`, **until** you grant access to your project folder and outbound HTTPS so the agent can do its job. Once HTTPS is open, OS file sandboxes cannot see what leaves inside headers, prompt bodies, or MCP tool calls.
4. **Why heavy proxies break coding:** Traditional DLP proxies require Docker Desktop, custom TLS root certificates, and naive `[REDACTED]` text replacement—which breaks OAuth logins and causes `git apply` to fail when the model echoes `[REDACTED]` back in a diff.

`leaktap` takes an **audit-first, zero-Docker** approach: see what already leaked on your machine in milliseconds offline, scrub local logs safely, and wrap live sessions when you want active protection.

---

## Example Output (`leaktap scan`)

```text
$ leaktap scan

leaktap v0.1.0 — local offline audit (0 network requests)
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
  • Preview local log redaction:   leaktap clean
  • Apply redaction with backup:   leaktap clean --apply
  • Wiretap a live agent session:  leaktap tap --scrub-env -- claude
```

---

## Installation

### From GitHub (Rust 1.75+)

```bash
cargo install --git https://github.com/vssinghh/leaktap
```

### Build from Source

```bash
git clone https://github.com/vssinghh/leaktap.git
cd leaktap
cargo build --release
./target/release/leaktap scan
```

*(Prebuilt macOS, Linux, and Windows binaries via GitHub Releases, `crates.io`, and `npx leaktap` are wired up in [`.github/workflows/release.yml`](.github/workflows/release.yml) and [`npm/leaktap`](npm/leaktap) for tagged releases.)*

---

## Usage

### 1. Offline Transcript & MCP Audit (`scan`)

```bash
# Scan ~/.claude, ~/.codex, ~/.cursor, ~/.gemini, ~/.codeium + workspace MCP configs
leaktap

# Scan a specific project or transcript directory
leaktap scan --path ./my-project

# Export machine-readable JSON or SARIF 2.1.0 (for GitHub Code Scanning / CI)
leaktap scan --path . --format json
leaktap scan --path . --format sarif --fail-on high > leaktap.sarif
```

### 2. Redact Leaked Secrets from Local Session Logs (`clean`)

`leaktap clean` runs in **read-only dry-run mode by default**, preserves valid JSONL syntax on every line so `/resume` history never breaks, and writes `.leaktap.bak` backups before modifying files:

```bash
# Preview how many exposed secrets would be redacted
leaktap clean

# Write redactions atomically (creates <file>.leaktap.bak backups)
leaktap clean --apply
```

### 3. Wiretap Live Agent or MCP `stdio` Sessions (`tap`)

`leaktap tap` wraps any agent CLI or MCP `stdio` server, strips sensitive shell environment variables (`--scrub-env`) before child processes inherit them, and inspects `stdin`/`stdout`/`stderr` in flight **without altering `stdout` JSON-RPC framing**:

```bash
# Wrap Claude Code and strip unrelated cloud secrets from inherited shell env
leaktap tap --scrub-env --allow-env ANTHROPIC_API_KEY -- claude

# Wrap a third-party MCP server inside .mcp.json and log wiretap events to JSONL
leaktap tap --scrub-env --quiet --log /tmp/mcp-wiretap.jsonl -- npx -y @org/some-mcp
```

### 4. Inspect Built-in Detection Rules (`rules`)

```bash
leaktap rules
```

---

## Under the Hood

- **Linear-time `O(n)` scanning at ~400 MB/s:** Uses SIMD `aho-corasick` anchor prefiltering in front of Rust's finite-automaton `regex` engine + `rayon` multi-core parallelism. Giant 20 MB minified `.jsonl` tool-output lines never trigger regex backtracking freezes.
- **JSONL escape-aware matching:** Correctly detects credentials preceded or terminated by JSON string escapes (`\n`, `\r`, `\t`) inside `.jsonl` transcripts while preserving exact byte offsets for atomic redaction.
- **False-positive suppression:** Combines Shannon entropy thresholds with context filters so placeholder keys (`AKIAIOSFODNN7EXAMPLE`, `your_api_key`), local dev URIs (`postgres://postgres:postgres@localhost`), `git@github.com`, and `@scope/pkg` names don't flood you with noise.
- **SHA-256 deduplication:** Identical secrets repeated across dozens of conversation turns are grouped by hash so each unique credential is reported once with an occurrence count.

---

## Privacy & Trust Model

- **Offline by default:** `leaktap scan` and `leaktap clean` make **zero** outbound network connections.
- **Zero telemetry:** No analytics, no crash reporting, no cloud accounts.
- **Always masked:** Matched secrets are truncated (`sk_live_9f...4c21`) in terminal, JSON, SARIF, and wiretap log outputs so `leaktap` never writes raw credentials into your scrollback or CI artifacts.

---

## Roadmap

- [x] **`v0.1` — Core Rust Engine (`scan`, `clean`, `tap`, `rules`):** Multi-agent transcript scanner (`~400 MB/s`), MCP config supply-chain/secret/telemetry auditor, JSONL-safe cleaner, `stdio`/env wiretap, and JSON/SARIF CI outputs.
- [ ] **`v0.2` — Interactive Terminal Dashboard & Socket Monitor:** Live TUI view + OS-level per-process outbound domain/header monitor (`User-Agent` / `X-*` identity leak alerts).
- [ ] **`v0.3` — Lossless Format-Preserving Token Swap:** Deterministic fake-token substitution before prompts leave your machine so `git apply` diffs keep working without exposing real keys.
- [ ] **`v0.4` — Public MCP Leak Benchmark:** Reproducible audit dataset across top open-source MCP servers and skills.

---

## License

[MIT](LICENSE)
