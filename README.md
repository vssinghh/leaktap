# leaktap

[![CI](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml/badge.svg)](https://github.com/vssinghh/leaktap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

See what your AI coding CLIs actually leak — and stop live secrets before they leave your machine.

`leaktap` audits your local AI chat logs, SQLite state DBs, MCP server configs, instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`), and installed marketplace plugins, hooks, and skills for leaked credentials, risky shell hooks, and hidden prompt payloads. It also scrubs old logs in place and wraps live CLI sessions with zero-cert prompt/header inspection, optional secret blocking (`--block-secrets`), environment scrubbing, and child socket tracking.

Supports **Claude Code**, **Codex CLI**, **Antigravity CLI**, **Gemini CLI**, and local **MCP servers**. Offline `scan` also checks local state, MCP configs, and rule directories for Cursor, Windsurf, Cline, Roo Code, Zed (`context_servers`), JetBrains Junie (`.junie`), Amazon Q (`.amazonq`), Kiro (`.kiro`), Augment (`.augment`), Trae (`.trae`), Continue, and Aider.

> **2026 MCP Audit:** Out of the 50 most-starred MCP servers on GitHub, **70%** tell users to run unpinned `npx -y` or `uvx` installs, **24%** show plain-text API keys in JSON config examples, and **24%** ship built-in analytics or telemetry. [Read the full write-up →](docs/mcp-top-50-audit.md)

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
  • Start a watched CLI session:   leaktap --block-secrets claude   (or `codex` / `agy`)
```

## Why I built this

When you run `claude`, `codex`, or `agy` inside a repo, two paths create most of the practical risk:

1. **Silent secret persistence and prompt leaks:** While debugging code, the CLI reads `.env` files, Kubernetes `Secret` manifests, JWK/PEM/PuTTY/GCP keys, or `xxd` hexdumps, sends them in the prompt body (`gzip`-, `br`-, or `zstd`-compressed in some CLIs), and writes them to `~/.claude` (including `~/.claude.json`), `~/.codex`, `~/.cursor`, or `~/.gemini` `.jsonl` and SQLite/WAL state files.
2. **Third-party MCP servers, plugins, hooks, and skills:** Community plugins and cloned repos can register `.claude/settings.json` or `hooks.json` commands/HTTP webhooks on `PreToolUse` or `SessionStart`, bundle opaque native/Wasm binaries, override `NODE_OPTIONS` / `LD_PRELOAD` / `HTTPS_PROXY` / `ANTHROPIC_BASE_URL` / Codex `[model_providers]` `base_url` or `apiKeyHelper` / `statusLine`, run unpinned `npx` / `pnpm dlx` / `uvx` / `uv run --with` / `bunx` / `docker run` servers (or `sudo` / `arch` / `direnv exec` wrappers), mount `~/.ssh`, `/etc`, or `docker.sock`, or hide prompt-injection, invisible Unicode tag/zero-width smuggling, and exfiltration scripts inside `SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.windsurf/rules`, `.clinerules`, `.junie`, `.amazonq`, `.kiro`, `.augment`, or `.trae`.

`leaktap` is a single Rust binary with zero setup. It audits local transcripts, SQLite + `-wal` state DBs (reassembling multi-page B-tree overflow rows), MCP configs, and installed plugins offline in ~120ms, scrubs leaked keys from `.jsonl`, `.claude.json`, and UTF-8/UTF-16 logs without breaking JSON validity or CLI login state, and wraps live CLI sessions without requiring Docker or custom root certificates.

## Usage

### 1. Scan local logs, SQLite/WAL state, MCP configs, and plugins

Runs 100% offline. Checks `~/.claude` and `~/.claude.json`, `~/.codex`, `~/.gemini`, `~/.cursor` (including Cursor/VS Code `User/mcp.json`, `User/settings.json`, `globalStorage/state.vscdb` + `-wal`, and Cline/Roo settings), `~/.codeium/windsurf`, `~/.continue`, installed marketplace plugins, `hooks.json` / `.claude/settings.json` lifecycle hooks, `SKILL.md` / `CLAUDE.md` / `AGENTS.md` / `.cursorrules` / `.windsurf/rules` / `.clinerules` / `.roo/rules*` / `.junie` / `.amazonq` / `.kiro` / `.augment` / `.trae` / `.github/instructions` instruction files, and workspace MCP configs (`.mcp.json`, `.zed/settings.json`, `.vscode/mcp.json`, `.vscode/settings.json`, `.codex/config.toml`, `.agents/mcp_config.json`, plus monorepo subpackages) along with any local helper scripts or compiled binaries they invoke:

```bash
# Default interactive laptop audit (exits 0; pass --fail-on high in CI)
leaktap

# Scan BOTH the full current workspace repo AND all global ~/.claude / ~/.codex / ~/.cursor / ~/.gemini dirs
leaktap scan --all --fail-on high

# Audit a specific repo, plugin folder, or single file before enabling it
leaktap scan --path ./my-project --fail-on high
leaktap scan --path ./credentials.json --fail-on medium

# Pre-commit check (audits staged git index blobs + modified helper scripts referenced by tracked MCP/hook configs)
leaktap scan --staged --fail-on high

# Full git commit history audit across --all refs (including merge commits & historical helper script edits)
leaktap scan --git-history --fail-on critical
leaktap scan --git-history --max-commits 1000 --fail-on high

# Pull-request CI check loading trusted base-branch policy instead of untrusted PR working-tree policy
leaktap scan --path . --policy-git-ref origin/main --format sarif --fail-on high > leaktap.sarif
```

### 2. Watch (and optionally block) live CLI sessions

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

# Cooperative HTTP DLP mode: reject outgoing LLM API prompts (`HTTP 400`) containing a live secret
leaktap --block-secrets claude
leaktap --block-secrets codex
```

What happens automatically:

- **Shell secret, SSH agent & ambient credential scrubbing:** Strips unrelated inline secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, `APP_SECRET`, `DATABASE_URL`, `PGPASSWORD`, `REDIS_PASS`, `GITHUB_PAT`, Base64 secrets starting with `/`, etc.) **and** ambient cloud/CLI credential pointers (`GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_PROFILE`, `AZURE_CONFIG_DIR`, `GH_CONFIG_DIR`, `TF_CLI_CONFIG_FILE`, `NETRC`, `PGPASSFILE`, `KUBECONFIG`, `DOCKER_CONFIG`, `VAULT_TOKEN`, `*_SECRET_FILE`, `*_KEY_FILE`) from the child environment while preserving the CLI's own login key, TLS CA trust bundles (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`), and any `--allow-env` variables. Pass `--scrub-ssh-agent` to also remove `SSH_AUTH_SOCK` before launch. On Linux, `leaktap` marks its supervisor process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) so a child process cannot read `leaktap`'s pre-scrub `/proc/<pid>/environ`.
- **Cooperative zero-cert API tap (`--inspect-api` / `--block-secrets`):** Routes `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `GOOGLE_GEMINI_BASE_URL` through a local loopback HTTP listener with upstream HTTP/TLS keep-alive connection pooling, binds auth header exemptions strictly to the target provider (blocking cross-provider keys, leaked internal JWTs, and unrecognized opaque credentials), decompresses `zstd`/`br`/`gzip`/`deflate` (including multi-member `gzip` streams, RFC 1952 `FNAME`/`FCOMMENT`/`FEXTRA` header metadata, and multi-layer encodings) in memory, forwards the exact inspected plaintext body upstream so parser differentials cannot smuggle trailing bytes, decodes URL `%` escapes, JSON `\uXXXX` escapes, Base64/Hex blobs (up to `128 KiB`), and nested stringified JSON, and with `--block-secrets` fails closed (`HTTP 400`) with session-cleanup guidance on live secrets, malformed framing, or unconsumed trailing bytes (and `HTTP 413` above `32 MiB`). Emits an explicit startup warning if `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` / `CLAUDE_CODE_USE_FOUNDRY`, Antigravity Google OAuth, or workspace `.claude/settings*.json` / `.codex/config.toml` `base_url` overrides would bypass the local HTTP tap.
- **Best-effort user-space socket watcher:** On Linux (`/proc` polling every `20ms` with `PR_SET_CHILD_SUBREAPER` + periodic orphan zombie reaping so double-forked background children stay visible) and macOS (`ps` + `lsof` polling every `250ms` with cached command-line attribution), records outbound TCP and connected UDP sockets across the child process tree and logs destination IP/port, PID, and secret-scrubbed command line to `~/.leaktap/live.jsonl` (`0600`, auto-rotated at `10 MiB`). Prints a clear notice on Windows, where user-space `/proc`/`lsof` socket polling is unavailable.

Wrap an individual MCP server command directly in `.mcp.json` or `.agents/mcp_config.json`:

```bash
leaktap tap --scrub-env --scrub-ssh-agent --quiet --log ~/.leaktap/mcp.jsonl -- npx @org/some-mcp@1.2.0
```

### 3. Clean leaked keys from chat logs

Runs a read-only dry run by default. Directory cleans target agent session logs only (so source code and docs inside a repository are never modified unless `--include-code` is explicitly passed, or a single file is targeted with `--path <file>`). Passing `--apply` atomically rewrites UTF-8 and UTF-16LE/BE text logs (`0600` permissions on session logs, refusal on symlinks), scrubs prompt history inside `~/.claude.json` without touching login accounts or `mcpServers`, preserves valid JSONL/JSON syntax even when scrubbing multi-line or `\n`-escaped PEM/OpenPGP/PuTTY/GCP/JWK/Kubernetes private keys, and leaves **no plaintext `.leaktap.bak` copies behind** unless `--backup` is explicitly requested. Binary SQLite/WAL databases are never rewritten blindly in place: if uncleaned secrets remain inside a SQLite/WAL file, `leaktap clean --apply` reports the exact count and file paths and exits with code `1`:

```bash
# Read-only preview of session log redactions
leaktap clean

# Scrub exposed secrets in session logs in place (no plaintext backup left on disk)
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

Four tabs (`Transcript Leaks`, `MCP / Plugin Risks`, `Live Wiretap` up to `1,000` recent events / `1 MiB` tail, and `Context & PII`). Press `/` to filter findings across all tabs, press `c` (then `y` to confirm) on any selected secret to scrub **only** that secret across affected session logs in place (pass `leaktap ui --include-code` if you also want `[c]` to rewrite repository source or config files), or `q` / `Ctrl+C` to exit cleanly.

### 5. Organization policy & allowlists (`.leaktap.toml`)

Place a trusted user/fleet policy at `~/.config/leaktap/config.toml` (auto-loaded by default), pass `--config path/to/policy.toml` for a hermetic CI policy file, or pass `--policy-git-ref origin/main` in pull-request CI to load `.leaktap.toml` and `.leaktapignore` from a trusted base git ref while ignoring untrusted PR edits.

> **Security boundary:** Untrusted `.leaktap.toml` and `.leaktapignore` files inside cloned repositories or `--path` targets are **ignored by default** so a malicious repo, PR branch, or plugin cannot silence its own findings. Pass `--policy-git-ref origin/main` in PR CI, or `--trust-project-config` when scanning your own local repository (`leaktap` warns if `--trust-project-config` is used in CI without `--policy-git-ref` or `--config`). Project allowlists and custom `[[rules]]` are strictly contained to files inside that project root and never leak into `~/.claude` or sibling folders.

```toml
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

## Scope & Threat Model

`leaktap` is built for **developer secret hygiene, AI supply-chain config auditing, and cooperative LLM prompt DLP** — not as a replacement for an OS kernel sandbox or network firewall:

- **What `leaktap` catches well:** Accidental credential leaks in UTF-8/UTF-16 `.jsonl`, `.claude.json`, `.env*` (including `.env.example` templates with real keys pasted in), multi-line YAML `|-` block scalars, Kubernetes `Secret` `data:`/`stringData:` manifests, JWK private keys, multi-line GCP `service-account.json` files, `xxd`/`hexdump` dumps, and SQLite/WAL chat history (including multi-page SQLite B-tree overflow cells, URL `%XX` escapes, JSON `\uXXXX` escapes, and Base64- or Hex-encoded tokens up to `128 KiB` across two nested encoding layers); outgoing secrets, cross-provider/unauthorized auth headers, or identity leaks in `claude`/`codex`/`gemini` HTTP URLs, headers, and compressed bodies (blocking them fail-closed with `--block-secrets`); plaintext secrets, unpinned `npx`/`pnpm dlx`/`yarn dlx`/`uvx`/`uv run`/`bunx` packages (`MEDIUM` for registry specs, `HIGH` for mutable git/URL specs — note that pinning top-level semver without a lockfile does not freeze transitive `^`/`~` sub-dependencies), multi-layer `sudo`/`doas`/`env`/`arch`/`caffeinate`/`direnv`/`busybox`/`nice`/`timeout` launchers, local helper scripts or compiled binaries referenced by MCP servers, privileged `docker`/`podman` flags, and sensitive host mounts (`~/.ssh`, `~/.aws`, `~/.azure`, `.pgpass`, `/etc`, `docker.sock`) in MCP, Zed `settings.json`, VS Code/Cursor `settings.json`, and Codex `config.toml` configs; and `.claude/settings.json` / `hooks.json` lifecycle hooks, `NODE_OPTIONS`/`LD_PRELOAD`/`HTTPS_PROXY` overrides, skill scripts making non-official outbound network calls (`plugin-skill-network`), compiled plugin/hook binaries (`plugin-compiled-binary` + embedded string scanning), invisible Unicode tag/zero-width smuggling, whole-file `process.env`/`os.environ`/`.env` exfiltration, or prompt-injection directives.
- **Known boundaries (pair with an OS sandbox or network firewall for untrusted code):**
  - **Static script, binary & Markdown heuristics:** Static plugin/MCP rules flag compiled native/Wasm/bytecode binaries (`plugin-compiled-binary`), scan their printable strings, strip invisible Unicode smuggling before regex/AST matching, and correlate credential reads with network sinks across entire files, but packed/encrypted binaries, heavily obfuscated scripts, or subtle natural-language social engineering inside `SKILL.md` / `CLAUDE.md` that avoids override/exfiltration phrasing can still evade static analysis.
  - **Cooperative HTTP interception (`--inspect-api` / `--block-secrets`):** `--block-secrets` intercepts requests from CLIs and SDKs that honor `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or `GOOGLE_GEMINI_BASE_URL`. It stops accidental secret leaks in normal coding sessions, but it is **not** a mandatory network firewall: cloud SDK modes (Bedrock, Vertex, Foundry), OAuth-pinned gRPC channels, or a malicious plugin/binary that ignores `*_BASE_URL` and opens direct TLS sockets to a hardcoded IP will bypass the HTTP proxy (`leaktap` warns at startup when cloud, OAuth, or workspace `.claude` / `.codex` `base_url` overrides are present).
  - **User-space socket polling (`netwatch`):** Without root privileges or kernel eBPF, `leaktap` polls `/proc` every `20ms` on Linux and `ps`+`lsof` every `250ms` on macOS (and does not poll sockets on Windows). Short-lived sub-interval connections that open and close between polls, or connectionless `sendto()` UDP/DNS exfiltration packets that never call `connect()` on a UDP socket, will not appear in `/proc/net/udp` or `lsof`. Run untrusted third-party code inside `sandbox-exec` (macOS), `bubblewrap` / `landlock` (Linux), or a network-restricted container/VM.

## Privacy

- `leaktap scan` and `leaktap clean` make **zero** network requests (the `npx` wrapper also refuses fallback runtime downloads unless `LEAKTAP_ALLOW_DOWNLOAD=1` is explicitly set).
- Zero telemetry, analytics, or external accounts.
- Matched secrets are masked (`sk_live_9f...4c21`) across terminal, TUI, JSON, SARIF, and `~/.leaktap/live.jsonl` (`0600`) outputs.

## License

[MIT](LICENSE)
