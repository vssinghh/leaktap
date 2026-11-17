# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See what your AI coding CLIs actually leak — and stop live secrets before they leave your machine.

`leaktap` scans your local AI chat logs, SQLite databases, MCP server configs, instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`), and installed plugins, hooks, and skills for leaked keys, risky shell commands, and hidden prompt instructions. It also cleans leaked secrets out of old logs and wraps live CLI sessions to inspect, block, or scrub outgoing requests.

Supports **Claude Code** (`claude`), **Codex CLI** (`codex`), **Antigravity CLI** (`agy`), **Gemini CLI** (`gemini`), and local or remote **MCP servers** (plus OpenRouter, DeepSeek, xAI, and Groq API endpoints). Offline `scan` also checks local databases, MCP configs, and rule folders for Cursor, Windsurf, Cline, Roo Code, Zed, JetBrains Junie, Amazon Q, Kiro, Augment, Trae, Continue, and Aider.

> **2026 MCP Audit:** Out of the 50 most-starred MCP servers on GitHub, **70%** tell users to run unpinned `npx -y` or `uvx` installs, **24%** show plain-text API keys in JSON config examples, and **24%** ship built-in analytics or telemetry. [Read the full write-up →](docs/mcp-top-50-audit.md)

## What `leaktap` covers (and what it doesn't)

`leaktap` is a developer tool for finding leaked secrets, auditing AI configs and plugins, and catching accidental prompt leaks — **not** an OS kernel sandbox or system-wide firewall:

- **Offline scanning and log cleaning (`scan` / `clean`):**
  - Finds API keys, private keys (PEM, OpenPGP, JWK, GCP service accounts, Kubernetes `Secret` files), database URLs, and passwords across `.jsonl` chat logs, `.env*` files, `.leaktap.bak` backups, and SQLite databases (including uncommitted `-wal` write-ahead log files).
  - Unwraps secrets hidden in Base64, `gzip`+Base64, hex dumps, `\uXXXX`/`\xXX`/`%XX` escapes, UTF-16 text, and Node.js `Buffer` byte arrays.
  - Audits MCP configs, plugins, hooks, skills, instruction files, `.vscode/tasks.json` auto-run tasks, `.devcontainer/devcontainer.json` commands, and `package.json` install scripts — following local helper imports up to 2 files deep when one file reads secrets and another sends network requests.
  - Optional flags check whether leaked keys are still active (`--verify`) or connect to MCP servers (`--inspect-mcp`) to spot hidden prompt instructions and silent tool changes after install (while blocking calls to internal or cloud-metadata IPs and never expanding `${ENV}` secrets from untrusted repo files).
  - Note: PII checks only cover developer emails and internal hostnames — not SSNs, credit cards, or medical records. Cleaning local logs removes secrets from your disk, not from remote servers — **always rotate keys that already left your machine**.
- **Live CLI wrapper (`claude` / `codex` / `agy` / `gemini` / `tap`):**
  - Strips unrelated secrets from child environment variables while keeping profile names like `AWS_PROFILE` and `KUBECONFIG` so tools don't accidentally fall back to `[default]` or production accounts.
  - Routes supported API calls (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, `OPENROUTER_BASE_URL`, `DEEPSEEK_BASE_URL`, `XAI_BASE_URL`, `GROQ_BASE_URL`) through a local HTTP port — no custom root certificates needed.
  - `--block-secrets` rejects outgoing API turns (`HTTP 400`) that contain leaked secrets or critical prompt injections, and refuses to start if a repo config tries to override `*_BASE_URL`.
  - `--redact-secrets` replaces secrets with `[REDACTED_BY_LEAKTAP]` in transit (and blocks the request if a secret cannot be cleanly removed).
  - Checks MCP tool lists and tool outputs for hidden prompt instructions, and polls OS socket tables (`15ms` on Linux, `500ms` on macOS) to log outbound TCP and UDP connections opened by child processes.
- **Where you still need an OS sandbox:**
  - `leaktap` runs in normal user space without `sudo`, root certificates, or kernel drivers. Direct HTTPS calls made by child tools to third-party servers are logged by IP and port (not decrypted). A deliberately hostile program that ignores `*_BASE_URL`, uses gRPC, finishes a network burst in under `15ms`, or sends raw UDP/DNS packets will bypass user-space checks. Run untrusted third-party code inside `bubblewrap` / `landlock` (Linux), `sandbox-exec` (macOS), or a container/VM.

## Install

Build from a pinned release tag with `cargo` (recommended):

```bash
cargo install --git https://github.com/vssinghh/leaktap --tag v0.3.0 --locked
```

Download a prebuilt binary on macOS or Linux (inspect the script first rather than piping straight to `sh`):

```bash
curl -fsSLO https://raw.githubusercontent.com/vssinghh/leaktap/v0.3.0/install.sh
less install.sh
LEAKTAP_VERSION=v0.3.0 sh install.sh

# Optional: verify that GitHub Actions built the binary from the tagged source commit
gh attestation verify ~/.local/bin/leaktap --repo vssinghh/leaktap
```

Or run a pinned version with `npx`:

```bash
npx leaktap@0.3.0 scan
```

Prebuilt binaries, `.sha256` checksums, and GitHub build provenance files for macOS, Linux, and Windows are on [GitHub Releases](https://github.com/vssinghh/leaktap/releases).

## Example output

```text
$ leaktap

leaktap v0.3.0 — local offline audit (0 network requests)
Scanned 148 file(s) (49.1 MB) in 118ms across ~/.claude, ~/.codex, ~/.gemini

CRITICAL  3 unique secret(s) found
  ├─ Database URI          postgres://***@db.prod.acme.io  ~/.claude/projects/app/08fa.jsonl:184 [CRITICAL] [fp:4a1e9c02b7d38f11]
  ├─ AWS Access Key        AKIA5F29Q...7Q2M                ~/.claude/projects/infra/91bc.jsonl:42 [CRITICAL] [fp:8c31d4029ab71e50]
  └─ Stripe Live Key       sk_live_9f...4c21               ~/.claude/projects/app/08fa.jsonl:184 (3x across 2 files) [CRITICAL] [fp:9f86d081884c7d65]
  ! Rotate any exposed live credentials immediately — scrubbing local logs does not revoke keys already sent to an API or repo.

CRITICAL  4 MCP / plugin risk(s) detected
  ├─ plugin:shady-linter (~/.claude/plugins/cache/community/shady-linter/0.1.0/hooks-handlers/sync.sh:2) [CRITICAL · plugin-credential-harvest] [fp:7d2a91e04c8b113f]
  │    References sensitive host credential store (`~/.ssh/id_rsa`) outside workspace
  ├─ plugin:shady-linter (~/.claude/plugins/cache/community/shady-linter/0.1.0/hooks/hooks.json:6) [HIGH · plugin-hook-network] [fp:1b4f82c90e73a512]
  │    Lifecycle hook `PreToolUse` runs handler `hooks-handlers/sync.sh` with an outbound network call (`collect.shady-plugin.io`)
  ├─ @community/db-mcp (.mcp.json:4) [MEDIUM · mcp-unpinned-package] [fp:6e90c31a5f28d407]
  │    Runs unpinned `npx -y @community/db-mcp` — pulls mutable remote code on start with local file/env access
  └─ @community/db-mcp (.mcp.json:8) [MEDIUM · mcp-telemetry-endpoint] [fp:3c08f71d9a42e619]
       References outbound analytics/telemetry endpoint (`events.posthog.com`)

MEDIUM    Identity & internal metadata in scanned files
  └─ 1 email address(es) + 1 internal hostname(s) appeared across 2 hit(s)

Next steps:
  • Open interactive dashboard:    leaktap ui
  • Preview & scrub local logs:    leaktap clean --apply
  • Start a watched CLI session:   leaktap --block-secrets claude   (or `--redact-secrets`)
  • Gate CI / pre-commit builds:   leaktap scan --ci                (exits 1 on HIGH/CRITICAL)
```

## Why I built this

When you run `claude`, `codex`, or `agy` inside a repo, most real-world leaks happen in two places:

1. **Plain-text chat logs and outgoing prompts:** While debugging code, the CLI reads `.env` files, cloud credentials, Kubernetes `Secret` manifests, private keys, or hex dumps. Those secrets get sent out in prompts (often compressed with `gzip`, Brotli, or `zstd`) and saved to disk inside `~/.claude`, `~/.codex`, `~/.cursor`, or `~/.gemini` `.jsonl` files and SQLite databases.
2. **Third-party MCP servers, plugins, hooks, and repo tasks:** Cloned repos and community plugins can run shell commands or webhooks through `.claude/settings.json` and `hooks.json`, trigger `.vscode/tasks.json` on folder open, run `devcontainer.json` or `package.json` `postinstall` scripts, launch unpinned `npx` / `uvx` / `docker run` packages, override `ANTHROPIC_BASE_URL` or `NODE_OPTIONS`, read `~/.ssh` or `~/.aws`, change MCP tool descriptions after you approve them, or hide instructions and invisible Unicode characters inside `SKILL.md`, `CLAUDE.md`, or `.cursorrules`.

`leaktap` is a single Rust binary with zero setup. It scans your local chat logs, SQLite databases, MCP configs, and plugins offline in ~120ms, cleans leaked keys from text logs and SQLite files without breaking JSON syntax or CLI login state, and watches live CLI sessions without requiring Docker or custom root certificates.

## Usage

### 1. Scan local logs, SQLite databases, MCP configs, and plugins

Runs 100% offline by default (0 network requests unless you pass `--verify` or `--inspect-mcp`). Checks `~/.claude` (and `~/.claude.json`), `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.codeium/windsurf`, `~/.continue`, installed plugins and skills, lifecycle hooks, IDE tasks, and workspace MCP or rule files:

```bash
# Default laptop audit (0 network requests; exits 0; add --ci to fail builds)
leaktap

# Scan BOTH the current repo AND your global ~/.claude / ~/.codex / ~/.cursor / ~/.gemini folders
leaktap scan --all --ci

# Opt-in: check provider APIs (read-only) to see which leaked keys are still active
leaktap scan --verify --fail-on critical

# Opt-in: query live MCP servers and lock their tool descriptions in a repo file
leaktap --mcp-pins-file ./mcp-pins.lock scan --inspect-mcp --ci

# Refresh saved MCP tool hashes after upgrading an MCP server
leaktap --mcp-pins-file ./mcp-pins.lock scan --inspect-mcp --update-mcp-pins

# Scan a specific repo, skill folder, or single file before using it
leaktap scan ./my-project --ci
leaktap scan ./third-party-skill --ci

# Pre-commit check (scans staged git files, imported helper scripts, and K8s Secret files)
leaktap scan --staged --ci

# Scan full git commit history across all branches
leaktap scan --git-history --fail-on critical
leaktap scan --git-history --max-commits 1000 --ci

# Pull-request CI check using the policy file from origin/main (SARIF format for GitHub Code Scanning)
LEAKTAP_FINGERPRINT_SALT="$SARIF_SALT" leaktap scan . --policy-git-ref origin/main --format sarif --ci > leaktap.sarif
```

### 2. Watch, block, or scrub live CLI sessions

Run `claude`, `codex`, `agy`, or `gemini` directly through `leaktap` — any extra flags are passed straight to the wrapped CLI:

```bash
# Live alerts + shell secret cleanup + child socket logging
leaktap claude
leaktap codex
leaktap agy

# Also strip SSH agent forwarding (SSH_AUTH_SOCK) from the CLI and its MCP servers
leaktap --scrub-ssh-agent claude

# Keep a specific environment variable needed by a tool or MCP server
leaktap --allow-env GH_TOKEN,GOOGLE_APPLICATION_CREDENTIALS claude

# Strict mode: block outgoing API requests (HTTP 400) that contain secrets or critical prompt injections
leaktap --block-secrets claude

# Seamless mode: replace secrets with [REDACTED_BY_LEAKTAP] in transit (blocks if a secret can't be cleanly removed)
leaktap --redact-secrets claude
```

What happens automatically:

- **Environment cleanup:** Removes unrelated shell secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, `DATABASE_URL`, `GITHUB_PAT`, etc.) and credential file variables (`GOOGLE_APPLICATION_CREDENTIALS`, `GH_CONFIG_DIR`, `DOCKER_CONFIG`, `NPM_CONFIG_USERCONFIG`, `VAULT_TOKEN`, `NETRC`, `PGPASSFILE`) before starting the CLI. Keeps profile selectors (`AWS_PROFILE`, `KUBECONFIG`, `CLOUDSDK_ACTIVE_CONFIG_NAME`), the CLI's own login key, custom TLS certificate paths (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`), and anything listed in `--allow-env`.
- **Zero-cert API inspection (`--inspect-api` / `--block-secrets` / `--redact-secrets`):** Points supported `*_BASE_URL` variables at a local HTTP port, decompresses `zstd`, Brotli, `gzip`, and `deflate` request bodies in memory, checks headers, URLs, JSON fields, encoded strings, and MCP tool results, and forwards the exact inspected body upstream over HTTPS. WebSocket upgrade requests get `HTTP 426` so clients cleanly fall back to normal HTTP/SSE.
- **MCP pipe checks & socket logging:** Passively checks non-TTY MCP `tools/list` and `tools/call` messages for tool poisoning, unexpected description changes, and prompt injections. Logs outbound TCP and UDP connections across all child processes (including background child processes on Linux) to `~/.leaktap/live.jsonl` (`0600` permissions, auto-rotated at `10 MiB`).

You can also wrap a single MCP server command directly inside `.mcp.json`:

```bash
leaktap tap --scrub-env --scrub-ssh-agent --quiet --log ~/.leaktap/mcp.jsonl -- npx @org/some-mcp@1.2.0
```

### 3. Clean leaked keys from chat logs and SQLite databases

Runs a read-only preview by default. When scanning a folder, `clean` only touches AI session logs (so repo source code, skill scripts, `.leaktap.bak` backups, and docs are left alone unless you pass `--include-code` or point directly at one file).

Passing `--apply` safely rewrites UTF-8 and UTF-16 logs, cleans prompt history in `~/.claude.json` without touching login accounts or `mcpServers`, and scrubs text and binary columns inside SQLite and `-wal` databases. It checks for active database locks first so an open IDE or CLI is never corrupted mid-session, uses a built-in Rust SQLite/WAL cleaner when `python3` isn't installed, and exits with code `1` if a locked database still holds uncleaned secrets:

```bash
# Read-only preview of what would be cleaned
leaktap clean

# Scrub leaked secrets in session logs and SQLite databases in place
leaktap clean --apply

# Clean a specific file, or include repo source files too
leaktap clean ./leaked.env --apply
leaktap clean ./my-repo --include-code --apply

# Optional: save a 0600 <file>.leaktap.bak copy before modifying
leaktap clean --apply --backup
```

### 4. Interactive terminal UI

```bash
leaktap ui
```

Opens a 4-tab terminal dashboard: `Transcript Leaks`, `MCP / Plugin Risks`, `Live Wiretap`, and `Context & PII`. Press `/` to filter findings across tabs, press `c` (then `y` to confirm) to scrub **only** the selected secret across your session logs and SQLite databases (pass `leaktap ui --include-code` to allow cleaning repo files too), or press `q` / `Ctrl+C` to exit without changing anything.

### 5. Policy files, inline ignores, and allowlists (`.leaktap.toml`)

You can keep personal or company-wide defaults at `~/.config/leaktap/config.toml` (loaded automatically), pass `--config path/to/policy.toml` in CI, or pass `--policy-git-ref origin/main` on pull requests to load `.leaktap.toml` and `.leaktapignore` from a trusted base branch while ignoring untrusted PR edits.

For intentional test keys in code or config files, add `# leaktap:ignore` on the same line (or `// leaktap:ignore[stripe-live-key]`, `/* leaktap:ignore */`, `<!-- leaktap:ignore -->`, or `# leaktap:ignore-next-line` on the line above). Inline ignore comments are automatically disabled when `--policy-git-ref` or `--no-inline-ignore` is used, are never honored inside chat logs, backups, SQLite files, or AI state folders (`.claude/`, `.codex/`, `.gemini/`, `.cursor/`), and never silence MCP, plugin, hook, or prompt-injection alerts.

> **Untrusted repos:** `.leaktap.toml` and `.leaktapignore` files inside cloned repos or `--path` targets are **ignored by default** (pass `--trust-project-config` to opt in) so a cloned repo cannot hide its own alerts. In SARIF output, unsalted hashes are left off email and hostname findings so public CI reports cannot be used to guess addresses unless `LEAKTAP_FINGERPRINT_SALT` or `fingerprint_salt` is set.

```toml
# Optional secret salt for `[fp:...]` IDs and SARIF fingerprints
# (prefer setting LEAKTAP_FINGERPRINT_SALT in CI secrets rather than committing it):
# fingerprint_salt = "org-random-secret-salt"

[allowlist]
paths = ["tests/fixtures/**"]
rules = ["internal-hostname"]
stopwords = ["acme-sandbox-dummy"]
# Copy any 16-char `[fp:...]` ID from terminal, TUI, JSON, or SARIF output:
fingerprints = ["9f86d081884c7d65"]

[allowlist.rule_paths]
# Allow a specific rule on specific files without hiding leaked keys in those files:
mcp-unpinned-package = ["docs/examples/**"]

[[rules]]
id = "acme-prod-token"
name = "Acme Internal Prod Token"
description = "Internal Acme production service token (acme_live_...)."
severity = "critical"
category = "secret"
anchors = ["acme_live_"]
pattern = 'acme_live_[A-Za-z0-9]{24,64}'
min_entropy = 3.2
```

### 6. List active detection rules

```bash
leaktap rules
leaktap rules --format json
```

## Privacy

- `leaktap scan` (default) and `leaktap clean` make **zero** network requests (`--verify` and `--inspect-mcp` are opt-in, and the `npx` wrapper never downloads binaries at runtime unless `LEAKTAP_ALLOW_DOWNLOAD=1` is set).
- Zero telemetry, analytics, or external accounts.
- Matched secrets are always masked (`sk_live_9f...4c21`) across terminal, TUI, JSON, SARIF, and `~/.leaktap/live.jsonl` (`0600`) outputs.

## License

[MIT](LICENSE)
