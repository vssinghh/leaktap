# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See what your AI coding CLIs actually leak — and stop live secrets before they leave your machine.

`leaktap` audits your local AI chat logs, SQLite state DBs, MCP server configs, instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`), and installed marketplace plugins, hooks, and skills for leaked credentials, risky shell hooks, and hidden prompt payloads. It also scrubs old text and SQLite/WAL logs in place and wraps live CLI sessions with zero-cert prompt/header inspection, optional secret blocking (`--block-secrets`) or in-transit redaction (`--redact-secrets`), environment scrubbing, and child socket tracking.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, **Gemini CLI**, and local/remote **MCP servers** (plus OpenRouter, DeepSeek, xAI, and Groq API endpoints). Offline `scan` also checks local state, MCP configs, and rule directories for Cursor, Windsurf, Cline, Roo Code, Zed (`context_servers`), JetBrains Junie (`.junie`), Amazon Q (`.amazonq`), Kiro (`.kiro`), Augment (`.augment`), Trae (`.trae`), Continue, and Aider.

> **2026 MCP Audit:** Out of the 50 most-starred MCP servers on GitHub, **70%** tell users to run unpinned `npx -y` or `uvx` installs, **24%** show plain-text API keys in JSON config examples, and **24%** ship built-in analytics or telemetry. [Read the full write-up →](docs/mcp-top-50-audit.md)

## Threat Model & Security Boundaries

`leaktap` is built for **developer secret hygiene, AI supply-chain config/plugin auditing, and cooperative LLM prompt DLP** — **not** as an OS kernel sandbox or mandatory network firewall:

- **Offline hygiene & supply-chain auditing (`scan` / `clean`):** Catches leaked credentials persisted in `.jsonl`, `.json`, UTF-16, `.env*`, Kubernetes `Secret` manifests, `gzip`+Base64 blobs, serialized Node.js `Buffer` arrays, and SQLite/WAL state DBs; audits MCP configs, helper scripts, PowerShell `-EncodedCommand` payloads, standalone skills, hooks, and instruction files using windowed static co-occurrence heuristics and literal-concatenation folding (not full cross-file inter-procedural AST taint analysis); and optionally verifies live token liveness across 24 provider families including AWS STS SigV4 (`--verify`) or queries live MCP `tools/list` schemas (`--inspect-mcp`) for tool poisoning and silent schema rug-pulls (blocking SSRF to cloud metadata/RFC1918 targets and never expanding `${ENV}` vars from untrusted workspace configs). Note that the `Pii` rule category covers developer identity & internal infrastructure metadata (`pii-email` and `internal-hostname` only — not SSN, payment-card, or HIPAA regulated PII). **Important:** scrubbing a secret from local logs (`clean --apply`) removes local disk exposure, **not** upstream exposure — **rotate any credential that already left the machine**.
- **Cooperative live wiretap (`claude` / `codex` / `agy` / `gemini` / `tap`):** Strips ambient secrets from child env vars, intercepts HTTP traffic for SDKs that honor `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, `OPENROUTER_BASE_URL`, `DEEPSEEK_BASE_URL`, `XAI_BASE_URL`, or `GROQ_BASE_URL` (`--block-secrets` rejects with `HTTP 400`; `--redact-secrets` rewrites secrets to `[REDACTED_BY_LEAKTAP]` in-transit; WebSocket `Upgrade` requests receive `HTTP 426` so clients fall back to inspectable HTTP/SSE), passively inspects MCP `tools[]` declarations and `tool_result` outputs in both LLM HTTP requests and wrapped non-TTY stdio JSON-RPC pipes (interactive full-screen CLIs inherit the host TTY directly via `Stdio::inherit()`), and polls OS socket tables (`10ms` Linux `/proc`, `1s` macOS `ps`+`lsof`) for outbound TCP and connected UDP sockets.
- **What requires an OS sandbox / firewall:** Because `leaktap` runs in user space without root, custom root CAs, or kernel eBPF, direct HTTPS requests made by child tools/MCP servers to third-party hosts are logged at the socket layer (not MITM-decrypted), and a deliberately hostile binary that ignores `*_BASE_URL` env vars, uses Bedrock/Vertex/OAuth gRPC channels, completes a sub-`10ms` socket burst between polls, or sends stateless `sendto()` UDP/DNS tunneling packets will bypass user-space HTTP blocking and socket polling. Run untrusted third-party code inside `bubblewrap` / `landlock` (Linux), `sandbox-exec` (macOS), or a network-isolated container/VM.

## Install

Build from a pinned release tag with `cargo` (recommended):

```bash
cargo install --git https://github.com/vssinghh/leaktap --tag v0.3.0 --locked
```

Download a prebuilt binary on macOS or Linux (inspect the script first — never pipe untrusted URLs straight to `sh`):

```bash
curl -fsSLO https://raw.githubusercontent.com/vssinghh/leaktap/v0.3.0/install.sh
less install.sh
LEAKTAP_VERSION=v0.3.0 sh install.sh

# Optional cryptographic build provenance check via GitHub Sigstore attestations:
gh attestation verify ~/.local/bin/leaktap --repo vssinghh/leaktap
```

Or run a pinned version via `npx`:

```bash
npx leaktap@0.3.0 scan
```

Prebuilt binaries, `.sha256` download-integrity files, and Sigstore build provenance attestations for macOS, Linux, and Windows are published on [GitHub Releases](https://github.com/vssinghh/leaktap/releases).

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
```

## Why I built this

When you run `claude`, `codex`, or `agy` inside a repo, two paths create most of the practical risk:

1. **Silent secret persistence and prompt leaks:** While debugging code, the CLI reads `.env` files, Kubernetes `Secret` manifests, JWK/PEM/PuTTY/GCP keys, or `xxd` hexdumps, sends them in the prompt body (`gzip`-, `br`-, or `zstd`-compressed in some CLIs), and writes them to `~/.claude` (including `~/.claude.json`), `~/.codex`, `~/.cursor`, or `~/.gemini` `.jsonl` and SQLite/WAL state files.
2. **Third-party MCP servers, plugins, hooks, and skills:** Community plugins and cloned repos can register `.claude/settings.json` or `hooks.json` commands/HTTP webhooks on `PreToolUse` or `SessionStart`, bundle opaque native/Wasm binaries, override `NODE_OPTIONS` / `LD_PRELOAD` / `HTTPS_PROXY` / `ANTHROPIC_BASE_URL` / Codex `[model_providers]` `base_url` or `apiKeyHelper` / `statusLine`, run unpinned `npx` / `pnpm dlx` / `uvx` / `uv run --with` / `bunx` / `docker run` servers (or `sh -c "sudo ..."` / `arch` / `direnv exec` wrappers), poison live MCP `tools/list` descriptions or mutate pinned schemas (`mcp-tool-poisoning` / `mcp-tool-rugpull`), inject covert instructions in MCP `tools/call` outputs (`mcp-indirect-prompt-injection`), mount `~/.ssh`, `/etc`, or `docker.sock`, or hide prompt-injection, PowerShell `-EncodedCommand` payloads, dynamic `__import__`/`getattr` execution (`plugin-dynamic-code-exec`), invisible Unicode tag/zero-width smuggling, and exfiltration scripts inside `SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.windsurf/rules`, `.clinerules`, `.junie`, `.amazonq`, `.kiro`, `.augment`, or `.trae`.

`leaktap` is a single Rust binary with zero setup. It audits local transcripts, SQLite + `-wal` state DBs (parsing both `rowid` and `WITHOUT ROWID` B-tree pages with column boundaries intact), MCP configs, and installed plugins offline in ~120ms, scrubs leaked keys from `.jsonl`, `.claude.json`, UTF-8/UTF-16 logs, and SQLite/WAL databases without breaking JSON/SQLite integrity or CLI login state, and wraps live CLI sessions without requiring Docker or custom root certificates.

## Usage

### 1. Scan local logs, SQLite/WAL state, MCP configs, and plugins

Runs 100% offline by default (0 network requests unless `--verify` or `--inspect-mcp` is explicitly passed). Checks `~/.claude` and `~/.claude.json`, `~/.codex`, `~/.gemini`, `~/.cursor` (including Cursor/VS Code `User/mcp.json`, `User/settings.json`, `globalStorage/state.vscdb` + `-wal`, and Cline/Roo settings), `~/.codeium/windsurf`, `~/.continue`, installed marketplace plugins, standalone skill repositories, `hooks.json` / `.claude/settings.json` lifecycle hooks, `SKILL.md` / `CLAUDE.md` / `AGENTS.md` / `.cursorrules` / `.windsurf/rules` / `.clinerules` / `.roo/rules*` / `.junie` / `.amazonq` / `.kiro` / `.augment` / `.trae` / `.github/instructions` instruction files, and workspace MCP configs (`.mcp.json`, `.zed/settings.json`, `.vscode/mcp.json`, `.vscode/settings.json`, `.codex/config.toml`, `.agents/mcp_config.json`, plus monorepo subpackages) along with any local helper scripts or compiled binaries they invoke:

```bash
# Default interactive laptop audit (0 network requests; exits 0; pass --fail-on high in CI)
leaktap

# Scan BOTH the full current workspace repo AND all global ~/.claude / ~/.codex / ~/.cursor / ~/.gemini dirs
leaktap scan --all --fail-on high

# Opt-in live credential verification (parallel read-only API checks -> [VERIFIED ACTIVE] vs [unverified/inactive])
leaktap scan --verify --fail-on critical

# Opt-in live MCP server interrogation (queries initialize + tools/list for poisoning & schema rug-pulls)
leaktap scan --inspect-mcp --fail-on high

# Intentionally refresh pinned MCP tool schema baselines after a verified server upgrade
leaktap scan --inspect-mcp --update-mcp-pins

# Audit a specific repo, standalone skill/plugin folder, or single file before enabling it
leaktap scan --path ./my-project --fail-on high
leaktap scan --path ./third-party-skill --fail-on high

# Pre-commit check (audits staged git index blobs + modified helper scripts + K8s Secret manifests)
leaktap scan --staged --fail-on high

# Full git commit history audit across --all refs (including merge commits & historical helper script edits)
leaktap scan --git-history --fail-on critical
leaktap scan --git-history --max-commits 1000 --fail-on high

# Pull-request CI check loading trusted base-branch policy + ignoring inline comments if desired
LEAKTAP_FINGERPRINT_SALT="$SARIF_SALT" leaktap scan --path . --policy-git-ref origin/main --format sarif --fail-on high > leaktap.sarif
```

### 2. Watch, block, or redact live CLI sessions

Start `claude`, `codex`, `agy`, or `gemini` directly through `leaktap` — extra flags pass straight through to the wrapped CLI:

```bash
# Live alerting + env scrubbing + socket watching
leaktap claude
leaktap codex
leaktap agy

# Also strip SSH_AUTH_SOCK agent forwarding from the child CLI and MCP servers
leaktap --scrub-ssh-agent claude

# Pass through a specific shell secret or cloud credential path needed by a tool/MCP server
leaktap --allow-env GH_TOKEN,GOOGLE_APPLICATION_CREDENTIALS claude

# Cooperative HTTP DLP (strict): reject outgoing LLM API prompts (`HTTP 400`) containing a live secret
leaktap --block-secrets claude

# Cooperative HTTP DLP (seamless): scrub secrets in-transit (`[REDACTED_BY_LEAKTAP]`) without failing the turn
leaktap --redact-secrets claude
```

What happens automatically:

- **Shell secret, SSH agent & ambient credential scrubbing:** Strips unrelated inline secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, `APP_SECRET`, `DATABASE_URL`, `PGPASSWORD`, `REDIS_PASS`, `GITHUB_PAT`, Base64 secrets starting with `/`, etc.) **and** ambient cloud/CLI credential pointers (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`, `AZURE_CONFIG_DIR`, `GH_CONFIG_DIR`, `TF_CLI_CONFIG_FILE`, `NETRC`, `PGPASSFILE`, `KUBECONFIG`, `DOCKER_CONFIG`, `VAULT_TOKEN`, `*_SECRET_FILE`, `*_KEY_FILE`) from the child environment while preserving the CLI's own login key, TLS CA trust bundles (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`), and any `--allow-env` variables. Pass `--scrub-ssh-agent` to also remove `SSH_AUTH_SOCK` before launch. On Linux, `leaktap` marks its supervisor process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) so a child process cannot read `leaktap`'s pre-scrub `/proc/<pid>/environ`.
- **Cooperative zero-cert API tap (`--inspect-api` / `--block-secrets` / `--redact-secrets`):** Routes `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, `OPENROUTER_BASE_URL`, `DEEPSEEK_BASE_URL`, `XAI_BASE_URL`, and `GROQ_BASE_URL` through a local loopback HTTP listener with upstream HTTP/TLS keep-alive connection pooling, binds auth header exemptions strictly to the target provider (flagging cross-provider keys, leaked internal JWTs, and unrecognized opaque credentials), decompresses `zstd`/`br`/`gzip`/`deflate` in memory, forwards the exact inspected plaintext body upstream so parser differentials cannot smuggle trailing bytes, decodes URL `%` escapes, JSON `\uXXXX` escapes, UTF-8/UTF-16/gzip Base64/Hex blobs (up to `128 KiB`), serialized Node `Buffer` arrays, and nested stringified JSON, and passively audits `tools[]` declarations and `tool_result` blocks for MCP poisoning, rug-pulls, and indirect prompt injection. With `--block-secrets`, requests containing secrets or uninspectable compressed payloads fail closed (`HTTP 400`); with `--redact-secrets`, matched secrets in JSON/text bodies, headers, and URLs are rewritten to `[REDACTED_BY_LEAKTAP]` in-transit before forwarding upstream.
- **Passive stdio MCP `tools/list` + `tools/call` auditing & user-space socket watcher:** Inspects JSON-RPC `tools/list` and `tools/call` responses crossing wrapped MCP stdio pipes (keyed per server command + arguments) for live tool poisoning (`mcp-tool-poisoning`), silent schema mutations (`mcp-tool-rugpull`), and indirect prompt injection (`mcp-indirect-prompt-injection`). On Linux (`/proc` polling every `10ms` across `ESTABLISHED`/`SYN_*`/`FIN_WAIT*`/`CLOSE_WAIT`/`CLOSING` sockets with `PR_SET_CHILD_SUBREAPER`) and macOS (`ps` + `lsof` polling every `1s`), records outbound TCP and connected UDP sockets across the child process tree to `~/.leaktap/live.jsonl` (`0600`, auto-rotated at `10 MiB`).

Wrap an individual MCP server command directly in `.mcp.json` or `.agents/mcp_config.json`:

```bash
leaktap tap --scrub-env --scrub-ssh-agent --quiet --log ~/.leaktap/mcp.jsonl -- npx @org/some-mcp@1.2.0
```

### 3. Clean leaked keys from chat logs & SQLite/WAL state DBs

Runs a read-only dry run by default. Directory cleans target agent session logs only (so source code, standalone skill scripts, and docs inside a repository are never modified unless `--include-code` is explicitly passed, or a single file is targeted with `--path <file>`). Passing `--apply` atomically rewrites UTF-8 and UTF-16LE/BE text logs (`0600` permissions on session logs, refusal on symlinks), scrubs prompt history inside `~/.claude.json` without touching login accounts or `mcpServers`, preserves valid JSONL/JSON syntax, and uses `python3` (`sqlite3` stdlib) to transactionally scrub `TEXT` and UTF-8 `BLOB` columns across both `rowid` and composite-PK `WITHOUT ROWID` tables inside SQLite + companion `-wal` databases (`PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA integrity_check`) on a private sibling temp copy before atomic rename. If `python3` is unavailable on `PATH` or a locked/custom binary SQLite file still retains uncleaned secret bytes, `leaktap clean --apply` warns clearly, reports the exact uncleaned count, and exits with code `1`:

```bash
# Read-only preview of session log & SQLite redactions
leaktap clean

# Scrub exposed secrets in session logs & SQLite/WAL DBs in place (no plaintext backup left on disk)
leaktap clean --apply

# Scrub secrets inside a specific file or across repo source/docs too
leaktap clean --path ./leaked.env --apply
leaktap clean --path ./my-repo --include-code --apply

# Optional: keep a 0600 <file>.leaktap.bak backup copy
leaktap clean --apply --backup
```

### 4. Interactive terminal UI

```bash
leaktap ui
```

Four tabs (`Transcript Leaks`, `MCP / Plugin Risks`, `Live Wiretap` up to `1,000` recent events / `1 MiB` tail, and `Context & PII`). Press `/` to filter findings across all tabs, press `c` (then `y` to confirm) on any selected secret to scrub **only** that secret across affected session logs and SQLite DBs in place (pass `leaktap ui --include-code` if you also want `[c]` to rewrite repository source or config files), or `q` / `Ctrl+C` to exit cleanly.

### 5. Organization policy, inline suppressions & allowlists (`.leaktap.toml`)

Place a trusted user/fleet policy at `~/.config/leaktap/config.toml` (auto-loaded by default), pass `--config path/to/policy.toml` for a hermetic CI policy file, or pass `--policy-git-ref origin/main` in pull-request CI to load `.leaktap.toml` and `.leaktapignore` from a trusted base git ref while ignoring untrusted PR edits (avoid `--trust-project-config` alone on untrusted PR branches).

For intentional test fixtures in source or config files, developers can also annotate a line with `# leaktap:ignore` (or `// leaktap:ignore[stripe-live-key]`, `/* leaktap:ignore */`, `<!-- leaktap:ignore -->`, or `# leaktap:ignore-next-line` on the line above). Pass `leaktap scan --no-inline-ignore` in strict audit pipelines to disable inline comments. Inline suppressions are **never** honored inside `.jsonl`/`.ndjson`/SQLite session transcripts and **never** suppress MCP, plugin, hook, or prompt-injection security findings.

> **Security boundary:** Untrusted `.leaktap.toml` and `.leaktapignore` files inside cloned repositories or `--path` targets are **ignored by default** so a malicious repo, PR branch, or plugin cannot silence its own findings. In SARIF output, unsalted `partialFingerprints` are automatically omitted on low-entropy PII findings (`pii-email`, `internal-hostname`) to prevent rainbow-table reversal in public CI artifacts unless `LEAKTAP_FINGERPRINT_SALT` or `fingerprint_salt` is configured.

```toml
# Optional organization secret salt for HMAC-like SHA-256 `[fp:...]` and SARIF partialFingerprints
# (prefer setting LEAKTAP_FINGERPRINT_SALT in CI secrets so the salt itself is not committed):
# fingerprint_salt = "org-random-secret-salt"

[allowlist]
paths = ["tests/fixtures/**"]
rules = ["internal-hostname"]
stopwords = ["acme-sandbox-dummy"]
# Copy any 16-hex-char `[fp:...]` value directly from terminal, TUI, JSON, or SARIF output:
fingerprints = ["9f86d081884c7d65"]

[allowlist.rule_paths]
# Suppress a specific rule on specific paths without hiding hardcoded secrets in those files:
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

- `leaktap scan` (default) and `leaktap clean` make **zero** network requests (`--verify` and `--inspect-mcp` are strictly opt-in; the `npx` wrapper also refuses fallback runtime downloads unless `LEAKTAP_ALLOW_DOWNLOAD=1` is explicitly set).
- Zero telemetry, analytics, or external accounts.
- Matched secrets are masked (`sk_live_9f...4c21`) across terminal, TUI, JSON, SARIF, and `~/.leaktap/live.jsonl` (`0600`) outputs.

## License

[MIT](LICENSE)
