# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`leaktap` scans local AI coding CLI logs, SQLite databases, MCP configs, and installed plugins for leaked secrets and risky shell hooks. It can also scrub old logs in place and wrap live CLI sessions to inspect, block, or redact outgoing API requests.

Live session wrapping works with **Claude Code** (`claude`), **Codex CLI** (`codex`), **Antigravity CLI** (`agy`), **Gemini CLI** (`gemini`), and local MCP servers (plus OpenRouter, DeepSeek, xAI, and Groq API endpoints). Offline `scan` also checks local state, MCP configs, and rule files left by Cursor, Windsurf, Cline, Roo Code, Zed, JetBrains Junie, Amazon Q, Kiro, Augment, Trae, Continue, and Aider.

> **2026 MCP Audit ([full write-up](docs/mcp-top-50-audit.md)):** Out of the 50 most-starred MCP servers on GitHub, **70%** tell users to run unpinned `npx -y` or `uvx` installs, **24%** show plain-text API keys in JSON config examples, and **24%** ship built-in analytics or telemetry.

## Install

Build from a tagged release with `cargo`:

```bash
cargo install --git https://github.com/vssinghh/leaktap --tag v0.3.0 --locked
```

Download a prebuilt binary on macOS or Linux (read the script before running it):

```bash
curl -fsSLO https://raw.githubusercontent.com/vssinghh/leaktap/v0.3.0/install.sh
less install.sh
LEAKTAP_VERSION=v0.3.0 sh install.sh

# Optional: verify GitHub Actions build attestation
gh attestation verify ~/.local/bin/leaktap --repo vssinghh/leaktap
```

Or run via `npx`:

```bash
npx leaktap@0.3.0 scan
```

Prebuilt binaries, `.sha256` checksums, and build attestations for macOS, Linux, and Windows are on [GitHub Releases](https://github.com/vssinghh/leaktap/releases).

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

When you run `claude`, `codex`, or `agy` in a repo, it reads `.env` files, cloud credentials, private keys, and Kubernetes manifests while debugging. Those values get saved in plain text inside `~/.claude`, `~/.codex`, `~/.cursor`, and `~/.gemini` chat logs and SQLite databases, and sent out in API prompts.

Third-party MCP servers, plugins, and cloned repos add a second problem. A repo or plugin can register shell hooks in `.claude/settings.json` or `hooks.json`, auto-run commands in `.vscode/tasks.json`, `devcontainer.json`, or `package.json`, launch unpinned `npx` or `uvx` packages, override `ANTHROPIC_BASE_URL`, read `~/.ssh` or `~/.aws`, or sneak hidden instructions into `SKILL.md`, `CLAUDE.md`, or MCP tool descriptions.

File sandboxes like `bubblewrap` and `sandbox-exec` can block folders outside your repo, but the CLI still needs read access to your workspace and access to the internet. Full HTTPS MITM proxies require custom root certificates and extra setup. `leaktap` is a single Rust binary that scans local state offline in ~120ms, scrubs leaked keys from text logs and SQLite databases, and inspects live API calls over localhost without installing root certificates.

## Usage

### Scan logs, databases, MCP configs, and plugins

Runs offline by default. Checks `~/.claude`, `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.codeium/windsurf`, `~/.continue`, installed plugins and skills, hooks, IDE tasks, and workspace MCP or rule files.

It catches API keys, private keys (PEM, OpenPGP, JWK, GCP service accounts, Kubernetes `Secret` files), database URLs, and passwords, even when encoded in Base64, `gzip`+Base64, hex dumps, UTF-16, Unicode/URL escapes, or SQLite `-wal` files. For plugins and MCP scripts, it also follows local helper imports (up to 2 files deep) to spot split exfiltration scripts.

```bash
# Default local audit (exits 0; add --ci to fail builds on HIGH/CRITICAL findings)
leaktap

# Scan both the current repo and global ~/.claude, ~/.codex, ~/.cursor, and ~/.gemini folders
leaktap scan --all --ci

# Opt-in: run read-only API checks across 24 providers to see which leaked keys are still active
leaktap scan --verify --fail-on critical

# Opt-in: query live MCP servers for poisoned tool descriptions and save hashes in a lockfile
leaktap --mcp-pins-file ./mcp-pins.lock scan --inspect-mcp --ci

# Refresh saved MCP tool hashes after upgrading a server
leaktap --mcp-pins-file ./mcp-pins.lock scan --inspect-mcp --update-mcp-pins

# Scan a specific repo, skill folder, or single file
leaktap scan ./my-project --ci
leaktap scan ./third-party-skill --ci

# Pre-commit check on staged git files
leaktap scan --staged --ci

# Scan git commit history across all branches
leaktap scan --git-history --fail-on critical
leaktap scan --git-history --max-commits 1000 --ci

# Pull-request CI check using the policy from origin/main with SARIF output
LEAKTAP_FINGERPRINT_SALT="$SARIF_SALT" leaktap scan . --policy-git-ref origin/main --format sarif --ci > leaktap.sarif
```

`--inspect-mcp` blocks connections to loopback, private, and cloud-metadata IPs and does not expand `${ENV}` variables from untrusted repo configs.

### Watch, block, or redact live CLI sessions

Start `claude`, `codex`, `agy`, or `gemini` through `leaktap`. Extra flags pass straight to the CLI:

```bash
# Watch outgoing prompts, scrub extra shell secrets, and log child sockets
leaktap claude
leaktap codex
leaktap agy

# Also strip SSH_AUTH_SOCK from the CLI and its MCP servers
leaktap --scrub-ssh-agent claude

# Keep specific env vars needed by a tool or MCP server
leaktap --allow-env GH_TOKEN,GOOGLE_APPLICATION_CREDENTIALS claude

# Reject outgoing API requests (HTTP 400) containing secrets or critical prompt injections
leaktap --block-secrets claude

# Replace secrets with [REDACTED_BY_LEAKTAP] in transit (returns HTTP 400 if a secret cannot be cleanly removed)
leaktap --redact-secrets claude
```

When wrapping a session, `leaktap`:

- Strips unrelated shell secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, `DATABASE_URL`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOCKER_CONFIG`, etc.) while keeping profile selectors (`AWS_PROFILE`, `KUBECONFIG`), the CLI's own API key, TLS CA paths, and anything in `--allow-env`.
- Routes supported `*_BASE_URL` env vars through a local HTTP port, decodes `zstd`/`br`/`gzip`/`deflate` bodies in memory, checks headers, prompts, and MCP tool results, and forwards the request upstream over HTTPS. WebSocket upgrades get `HTTP 426` so clients fall back to HTTP/SSE. With `--block-secrets`, `leaktap` refuses to start if a repo config overrides `*_BASE_URL`.
- Checks non-TTY MCP `tools/list` and `tools/call` traffic for tool poisoning or unexpected schema changes, and logs child TCP/UDP sockets to `~/.leaktap/live.jsonl` (`0600`, rotated at `10 MiB`).

To wrap a single MCP server inside `.mcp.json`:

```bash
leaktap tap --scrub-env --scrub-ssh-agent --quiet --log ~/.leaktap/mcp.jsonl -- npx @org/some-mcp@1.2.0
```

### Clean old logs and SQLite databases

Runs a dry run by default. On a folder, `clean` only modifies AI session logs and skips repo code, scripts, and `.leaktap.bak` backups unless you pass `--include-code` or target one file directly.

With `--apply`, it rewrites UTF-8 and UTF-16 logs, cleans prompt history in `~/.claude.json` without touching login accounts or `mcpServers`, and scrubs SQLite and `-wal` databases (checking for active locks first so open IDEs are not corrupted, using a built-in Rust cleaner if `python3` is missing, and exiting `1` if locked secrets remain).

```bash
# Preview changes without editing files
leaktap clean

# Scrub leaked secrets in place
leaktap clean --apply

# Clean a specific file, or include repo source files
leaktap clean ./leaked.env --apply
leaktap clean ./my-repo --include-code --apply

# Keep a 0600 <file>.leaktap.bak copy before editing
leaktap clean --apply --backup
```

### Terminal UI

```bash
leaktap ui
```

Opens a 4-tab view (`Transcript Leaks`, `MCP / Plugin Risks`, `Live Wiretap`, and `Context & PII`). Press `/` to filter, `c` then `y` to scrub just the selected secret across session logs and SQLite databases (pass `--include-code` to include repo files), or `q` / `Ctrl+C` to exit.

### Policy files and allowlists (`.leaktap.toml`)

`leaktap` loads `~/.config/leaktap/config.toml` automatically. In CI, pass `--config path/to/policy.toml` or `--policy-git-ref origin/main` to load policy from a trusted base branch instead of a PR branch.

For test keys in source or config files, add `# leaktap:ignore` on the same line (or `// leaktap:ignore[rule-id]`, `/* leaktap:ignore */`, `<!-- leaktap:ignore -->`, or `# leaktap:ignore-next-line` above it). These comments are turned off under `--policy-git-ref` and `--no-inline-ignore`, do not apply to chat logs, backups, SQLite files, or AI state folders (`.claude/`, `.codex/`, `.gemini/`, `.cursor/`), and never silence MCP, plugin, or hook alerts.

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

### List detection rules

```bash
leaktap rules
leaktap rules --format json
```

## Limitations

- `leaktap` runs in user space without `sudo`, custom root certificates, or kernel hooks. Direct HTTPS traffic sent by child tools to third-party hosts is logged by IP and port, not decrypted.
- A hostile binary that ignores `*_BASE_URL`, uses gRPC, finishes a network connection faster than the socket poll interval (`15ms` on Linux, `500ms` on macOS), or sends raw UDP/DNS packets will bypass user-space checks. Run untrusted third-party code in `bubblewrap`, `landlock`, `sandbox-exec`, or a VM/container.
- PII checks only cover developer email addresses and internal hostnames. They do not detect SSNs, payment cards, or medical records.
- `leaktap clean --apply` only removes secrets from your local disk. Rotate any key that was already sent to an API or committed to a repo.
- `.leaktap.toml` and `.leaktapignore` files inside scanned repos are ignored by default so a cloned repo cannot hide its own findings. Pass `--trust-project-config` or `--policy-git-ref` to use them.
- In SARIF output, unsalted hashes are omitted on email and hostname findings unless `LEAKTAP_FINGERPRINT_SALT` or `fingerprint_salt` is set.

## Privacy

- `leaktap scan` and `leaktap clean` make no network requests by default. Live checks only run when `--verify` or `--inspect-mcp` is passed, and the `npx` wrapper skips runtime downloads unless `LEAKTAP_ALLOW_DOWNLOAD=1` is set.
- No telemetry, analytics, or accounts.
- Matched secrets are masked (`sk_live_9f...4c21`) in terminal, UI, JSON, SARIF, and `~/.leaktap/live.jsonl` output.

## License

[MIT](LICENSE)
