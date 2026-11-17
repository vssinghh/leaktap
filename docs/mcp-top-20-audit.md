# Auditing the Top 20 Open-Source MCP Servers with `leaktap`

*Snapshot date: November 17, 2026 · Machine-readable dataset: [`docs/mcp-top-20-audit.json`](mcp-top-20-audit.json) · Reproduction script: [`scripts/audit_top_mcp_servers.py`](../scripts/audit_top_mcp_servers.py)*

**MCP (Model Context Protocol)** is a standard way for AI coding tools like Claude Code, Codex CLI, Cursor, and Gemini CLI to call external tools such as GitHub, browsers, Figma, and databases. Most MCP servers run as local child processes on your laptop (usually started with `npx`, `uvx`, or `docker run`) with access to your local files, shell environment variables, and internet connection.

Every finding in this report comes directly from running `leaktap` (`v0.3.0`) in two layers across the **20 most-starred open-source MCP server repositories on GitHub** (`11,969` to `84,118` stars; **`464,529` combined stars**):

1. **Layer 1: Static Repository & Config Scan (`leaktap scan <repo> --no-pii --format json`).** Scans each cloned repository offline for unpinned `npx`/`uvx`/`docker` commands, API keys placed in JSON config examples or CLI flags, pipe-to-shell install commands (`curl ... | sh`), auto-run workspace hooks, lifecycle scripts, and default-on telemetry code.
2. **Layer 2: Live Wire & Socket Audit (`leaktap tap`).** Starts each server inside `leaktap tap`, runs a live MCP JSON-RPC handshake (`initialize` followed by `tools/list`, the standard startup messages an AI client sends over standard input/output to ask a server what tools it offers), computes a SHA-256 hash of every returned tool schema, checks live tool descriptions for hidden prompt-injection instructions, and logs every outbound network connection (`HTTP CONNECT` proxy tunnels and OS sockets) opened during startup before any tool is called.

---

## Summary Results

In Layer 2, **18 of the 20 servers (`90%`)** completed a live `stdio` `initialize` + `tools/list` handshake inside `leaktap tap` (`mcp-tools-inventory`), exposing **470 live MCP tools** (`1` to `150` per server) whose schemas were hashed into `pins.json` so silent tool changes trigger `mcp-tool-rugpull` (see Section 5 for the 2 servers that require an HTTP client or a commercial desktop GUI).

| Layer | Check (`leaktap` Rule IDs) | Count (of 20) | Share | Why It Matters on a Developer Machine |
| :--- | :--- | :---: | :---: | :--- |
| **Layer 1 (`scan`)** | **Unpinned packages, `:latest` tags, or branch installs** (`mcp-unpinned-package`) | **18 / 20** | **90%** | Downloads and runs the newest code from npm, PyPI, Docker Hub, or GitHub `main` on start instead of locking a fixed version. |
| **Layer 1 (`scan`)** | **Secrets in JSON configs or CLI flags** (`mcp-cli-arg-secret`, `mcp-plaintext-secret-template`) | **7 / 20** | **35%** | Guides users to paste raw tokens into `.mcp.json` or pass `--api-key` on the command line (visible to any local process via `ps aux`). |
| **Layer 1 (`scan`)** | **Default-on usage telemetry in source code** (`mcp-server-telemetry`, `mcp-undisclosed-telemetry`) | **6 / 20** | **30%** | Sends usage or crash events to external servers unless you set an opt-out environment variable. **2 / 20** do not mention telemetry in their root `README.md`. |
| **Layer 1 (`scan`)** | **Pipe-to-shell remote installers** (`mcp-remote-code-exec`) | **2 / 20** | **10%** | Setup docs pipe a mutable `https://.../install.sh` URL straight into `sh`, `bash`, or PowerShell `iex`. |
| **Layer 2 (`tap`)** | **Non-API outbound HTTPS calls on startup** (`mcp-live-telemetry`, `http-connect`) | **5 / 20** | **25%** | Sent telemetry, checked for updates, or downloaded a `140` to `190 MB` browser archive during startup before any tool was called (excludes expected primary API calls like `github-mcp-server` calling `api.github.com`). |
| **Layer 2 (`tap`)** | **Poisoned live tool descriptions** (`mcp-tool-poisoning`) | **0 / 20** | **0%** | Zero hidden prompt-injection instructions or stealth credential-stealing directives across all **470** live tools (`18 / 20` servers). |

---

## Key Findings Across Both Layers

### 1. Five servers (`25%`) made non-API internet calls on startup before any tool ran

When you start a coding session in Claude Code, Codex CLI, Cursor, Gemini CLI, or Claude Desktop, the client starts every enabled `stdio` MCP server in the active configuration scope right away to run `initialize` and `tools/list` so it knows what tools exist, even if your prompt never calls those tools. If a server is configured for one project (such as `.mcp.json` or Claude Code's default `local` scope), it starts on every session in that project. If it is installed globally at `user` scope (such as `claude mcp add --scope user`, `~/.codex/config.toml`, `~/.cursor/mcp.json`, or `claude_desktop_config.json`, as many `README` guides recommend), it starts on every session across every folder you open.

`leaktap tap` sets a local pass-through HTTP proxy (`HTTP_PROXY` / `HTTPS_PROXY` plus `NODE_USE_ENV_PROXY=1`) and watches child OS sockets. When a wrapped program opens an HTTPS connection, it sends an unencrypted `HTTP CONNECT host:443` header to ask the proxy for a TCP tunnel. `leaktap tap` records that destination hostname without installing custom TLS certificates or decrypting traffic.

During a bare `initialize` + `tools/list` startup check (with zero `tools/call` requests), `leaktap tap` recorded outbound HTTPS connections from `6` of the Top 20 servers. One of those (`github/github-mcp-server`, `#7`) connected only to its expected primary API (`api.github.com:443`). The other **5 servers (`25%`)** made non-API outbound HTTPS calls before a single tool was called:

- **`CoplayDev/unity-mcp` (`#16`, 13,049 stars):** Layer 1 (`leaktap scan`) flagged `mcp-undisclosed-telemetry` (`HIGH`) at `Server/src/core/telemetry.py:152` because this local Unity Editor bridge sends events to `https://api-prod.coplay.dev/telemetry/events` by default without mentioning telemetry in its root `README.md`. Layer 2 (`leaktap tap`) confirmed this live on the wire: during startup, `unity-mcp` opened outbound HTTPS tunnels to both **`api-prod.coplay.dev:443`** and **`pypi.org:443`**.
- **`oraios/serena` (`#10`, 16,724 stars):** Static package files showed no third-party analytics SDKs (`PostHog`, `Sentry`, or `Segment`). When launched inside `leaktap tap`, this local code-search server immediately opened live HTTPS connections to **`oraios-software.de:443`** and **`pypi.org:443`** on startup. A static manifest check misses custom first-party pings like this; live wiretapping catches them immediately.
- **`apify/apify-mcp-server` (`#14`, 13,621 stars):** Layer 1 flagged Segment and Sentry in `src/telemetry.ts:3` (`mcp-server-telemetry`). Layer 2 caught a live `mcp-live-telemetry` connection to **`o272833.ingest.us.sentry.io:443`** (Sentry) alongside its expected primary API (**`api.apify.com:443`**) during startup.
- **`xpzouying/xiaohongshu-mcp` (`#12`, 15,025 stars):** Runs as a local HTTP daemon rather than a `stdio` server. On first launch inside `leaktap tap`, it immediately connected to **`cdn.one-world.ai:443`** to download a `140` to `190 MB` bundled browser archive (`linux-x64.tar.xz`).
- **`googleapis/mcp-toolbox` (`#13`, 14,686 stars):** Configured strictly with an in-memory local SQLite database (`:memory:`) and a `SELECT 1` health tool, `toolbox` still opened a live HTTPS connection to **`api.github.com:443`** on startup to check for newer releases.

### 2. Why static `scan` and live `tap` complement each other on telemetry

Four servers flagged statically for default-on telemetry (`ChromeDevTools/chrome-devtools-mcp`, `ahujasid/mcp-for-blender`, `czlonkowski/n8n-mcp`, and `GLips/Figma-Context-MCP`) made **zero** network calls during `initialize` + `tools/list` because their telemetry code waits until a tool is actually called or a session closes:

- **`GLips/Figma-Context-MCP` (`#15`):** `src/telemetry/client.ts:11` sends usage events to PostHog (`us.i.posthog.com`) by default with no mention in the root `README.md` (`mcp-undisclosed-telemetry`, `HIGH`).
- **`ChromeDevTools/chrome-devtools-mcp` (`#3`):** `src/telemetry/ClearcutLogger.ts:76` enables Google Clearcut logging (`play.googleapis.com/log`), documented with opt-out `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS` (`mcp-server-telemetry`, `MEDIUM`).
- **`ahujasid/mcp-for-blender` (`#6`)** (`src/blender_mcp/telemetry.py:314`, Supabase collector) and **`czlonkowski/n8n-mcp` (`#11`)** (`src/telemetry/telemetry-types.ts:120`, `telemetry.n8n-mcp.com`): Both document opt-out environment variables (`DISABLE_TELEMETRY`) and note in their privacy documentation that collected usage data may be used to train AI/ML models (`mcp-server-telemetry`, `MEDIUM`).

Running `leaktap scan` catches deferred telemetry code before you call a tool, while running `leaktap tap` catches custom startup connections and runtime downloads on the wire.

### 3. CLI flag secrets (`ps aux` exposure) and plain-text config templates (`35%`)

Seven repositories (`35%`) instruct users to put raw credentials directly into MCP configuration files:

- **CLI flag secrets (`mcp-cli-arg-secret`, `HIGH`, `2 / 20`):** `upstash/context7` (`packages/mcp/README.md:126`, `--api-key`) and `GLips/Figma-Context-MCP` (`README.md:66`, `--figma-api-key`) pass live API keys as command-line arguments in `"args"`. On Linux and macOS, command-line arguments are readable by other processes on the machine through the OS process table (`ps aux` or `/proc/<pid>/cmdline`), in addition to sitting in plain text on disk.
- **Plain-text JSON `env` and `headers` blocks (`mcp-plaintext-secret-template`, `MEDIUM`, `6 / 20`):** `upstash/context7`, `github/github-mcp-server`, `czlonkowski/n8n-mcp`, `xpzouying/xiaohongshu-mcp`, `apify/apify-mcp-server`, and `CoplayDev/unity-mcp` include setup examples with literal token strings inside `"env"` or `"headers"` instead of `${ENV_VAR}` or `${input:...}` secret references. When an AI coding agent reads `.mcp.json` while debugging a project, any literal key in that file is copied into local session transcripts (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`).

### 4. Unpinned installs (`90%`), workspace hooks, and container privileges

- **`18 / 20` (`90%`)** trigger `mcp-unpinned-package` via unpinned `npx` / `uvx` commands, `:latest` container tags (`ghcr.io/github/github-mcp-server`, `ghcr.io/oraios/serena:latest`, `ghcr.io/czlonkowski/n8n-mcp:latest`, `mcp/context7`), or mutable GitHub branch URLs (`DeusData/codebase-memory-mcp`, `mksglu/context-mode`, `CoplayDev/unity-mcp`, `mrexodia/ida-pro-mcp`, `LaurieWired/GhidraMCP`). Note that pinning a top-level package (`npx pkg@1.2.3`) pins the entry package, whereas full transitive dependency locking requires a local install with a lockfile.
- **Workspace hooks and lifecycle configs:** `leaktap scan` also flagged automatic `SessionStart` / `PostToolUse` shell hooks in `modelcontextprotocol/servers` (`.claude/settings.json:3`) and `tirth8205/code-review-graph` (`hooks/hooks.json:3,15`), `"privileged": true` in `microsoft/playwright-mcp` (`.devcontainer/devcontainer.json:5`), `--network=host` Docker usage in `ahujasid/mcp-for-blender` (`README.md:356`), an auto-run `postinstall` network downloader in `DeusData/codebase-memory-mcp` (`pkg/npm/package.json:30`), and an unencrypted remote HTTP example (`http://remote-server:8080/mcp`) in `CoplayDev/unity-mcp` (`Server/README.md:227`).

### 5. All `470` live tool schemas were clean (`0` tool-poisoning findings)

Across the **18 servers** that completed a live `stdio` MCP handshake inside `leaktap tap`, tool counts ranged from `1` (`googleapis/mcp-toolbox`) to `150` (`0x4m4/hexstrike-ai`), totaling **`470` tools**. Every tool schema was hashed into `pins.json` (SHA-256) and checked for hidden Unicode characters, prompt-override directives, and credential-stealing instructions. None of the Top 20 repositories contained poisoned tool metadata.

The two servers that did not complete `tools/list` had straightforward runtime requirements:
- `xpzouying/xiaohongshu-mcp` (`#12`) is an HTTP-only Go server that spends its first launch downloading a `140` to `190 MB` browser archive from `cdn.one-world.ai:443`.
- `mrexodia/ida-pro-mcp` (`#18`) completed `initialize` over `stdio` and exited cleanly on `tools/list` (`[MCP] No IDA instances discovered, using default 127.0.0.1:13337`) because it dynamically queries a running commercial IDA Pro desktop disassembler plugin.

---

## Full Top 20 Results

| # | Repository | Stars | Lang | Layer 1: Static `leaktap scan` Rules (Primary File:Line) | Layer 2: Live `tap` Tools | Layer 2: Live Startup Outbound Hosts (`leaktap tap`) |
| :---: | :--- | ---: | :--- | :--- | :---: | :--- |
| 1 | [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) | 84,118 | TS | `mcp-unpinned-package` (`README.md:87`), `plugin-workspace-hook-exec` (`.claude/settings.json:3`) | **16** | None |
| 2 | [`upstash/context7`](https://github.com/upstash/context7) | 52,897 | TS | `mcp-cli-arg-secret` (`packages/mcp/README.md:126`), `mcp-plaintext-secret-template` (`:694`), `mcp-unpinned-package` (`:126`), `plugin-skill-network` (`packages/pi/lib/api.ts:35`) | **2** | None |
| 3 | [`ChromeDevTools/chrome-devtools-mcp`](https://github.com/ChromeDevTools/chrome-devtools-mcp) | 35,888 | TS | `mcp-unpinned-package` (`README.md:77`), `mcp-server-telemetry` (`src/telemetry/ClearcutLogger.ts:76`) | **33** | None |
| 4 | [`DeusData/codebase-memory-mcp`](https://github.com/DeusData/codebase-memory-mcp) | 35,664 | C | `mcp-remote-code-exec` (`README.md:73`), `npm-lifecycle-script-exec` (`pkg/npm/package.json:30`), `mcp-unpinned-package` (`README.md:591`) | **17** | None |
| 5 | [`microsoft/playwright-mcp`](https://github.com/microsoft/playwright-mcp) | 31,507 | TS | `devcontainer-lifecycle-exec` (`.devcontainer/devcontainer.json:5`), `mcp-unpinned-package` (`README.md:86`) | **25** | None |
| 6 | [`ahujasid/mcp-for-blender`](https://github.com/ahujasid/mcp-for-blender) | 19,168 | Python | `mcp-remote-code-exec` (`README.md:46`), `mcp-broad-filesystem` (`README.md:356`), `plugin-compiled-binary`, `mcp-unpinned-package` (`README.md:103`), `mcp-server-telemetry` (`src/blender_mcp/telemetry.py:314`) | **10** | None |
| 7 | [`github/github-mcp-server`](https://github.com/github/github-mcp-server) | 18,757 | Go | `mcp-unpinned-package` (`README.md:276`), `mcp-plaintext-secret-template` (`README.md:434`) | **46** | `api.github.com:443` *(expected API)* |
| 8 | [`mksglu/context-mode`](https://github.com/mksglu/context-mode) | 17,435 | TS | `mcp-unpinned-package` (`README.md:63`) | **9** | None |
| 9 | [`tirth8205/code-review-graph`](https://github.com/tirth8205/code-review-graph) | 16,898 | Python | `mcp-unpinned-package` (`.mcp.json:3`), `plugin-workspace-hook-exec` (`hooks/hooks.json:3,15`) | **30** | None |
| 10 | [`oraios/serena`](https://github.com/oraios/serena) | 16,724 | Python | `mcp-unpinned-package` (`docs/02-usage/020_running.md:238`) | **3** | `oraios-software.de:443`, `pypi.org:443` |
| 11 | [`czlonkowski/n8n-mcp`](https://github.com/czlonkowski/n8n-mcp) | 16,472 | TS | `mcp-unpinned-package` (`docs/CLAUDE_CODE_SETUP.md:72`), `mcp-plaintext-secret-template` (`:80`), `mcp-server-telemetry` (`src/telemetry/telemetry-types.ts:120`) | **7** | None |
| 12 | [`xpzouying/xiaohongshu-mcp`](https://github.com/xpzouying/xiaohongshu-mcp) | 15,025 | Go | `mcp-plaintext-secret-template` (`README.md:493`), `plugin-skill-network` (`skills/post-to-xhs/scripts/cdp_publish.py:94`) | *HTTP daemon* | `cdn.one-world.ai:443` *(140-190 MB browser download)* |
| 13 | [`googleapis/mcp-toolbox`](https://github.com/googleapis/mcp-toolbox) | 14,686 | Go | `mcp-unpinned-package` (`README.md:86`) | **1** | `api.github.com:443` *(release check)* |
| 14 | [`apify/apify-mcp-server`](https://github.com/apify/apify-mcp-server) | 13,621 | TS | `mcp-unpinned-package` (`README.md:160`), `mcp-plaintext-secret-template` (`README.md:162`), `mcp-server-telemetry` (`src/telemetry.ts:3`) | **13** | `o272833.ingest.us.sentry.io:443` *(Sentry)*, `api.apify.com:443` *(expected API)* |
| 15 | [`GLips/Figma-Context-MCP`](https://github.com/GLips/Figma-Context-MCP) | 13,561 | TS | `mcp-cli-arg-secret` (`README.md:66`), `mcp-undisclosed-telemetry` (`src/telemetry/client.ts:11`), `mcp-unpinned-package` (`README.md:66`) | **2** | None |
| 16 | [`CoplayDev/unity-mcp`](https://github.com/CoplayDev/unity-mcp) | 13,049 | Python | `mcp-plaintext-http` (`Server/README.md:227`), `mcp-undisclosed-telemetry` (`Server/src/core/telemetry.py:152`), `mcp-unpinned-package` (`README.md:55`), `mcp-plaintext-secret-template` (`Server/README.md:229`) | **49** | `api-prod.coplay.dev:443` *(telemetry)*, `pypi.org:443` |
| 17 | [`0x4m4/hexstrike-ai`](https://github.com/0x4m4/hexstrike-ai) | 12,546 | Python | Clean (`0` static MCP/plugin findings) | **150** | None |
| 18 | [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) | 12,358 | Python | `mcp-unpinned-package` (`README.md:62,98`) | *Needs IDA GUI* | None |
| 19 | [`hangwin/mcp-chrome`](https://github.com/hangwin/mcp-chrome) | 12,186 | TS | `mcp-unpinned-package` (`README.md:133`) | **27** | None |
| 20 | [`LaurieWired/GhidraMCP`](https://github.com/LaurieWired/GhidraMCP) | 11,969 | Java | `mcp-unpinned-package` (`README.md:59`) | **30** | None |

---

## Practical Steps to Harden Your MCP Setup

1. **Pin versions (or install locally with a lockfile) in `.mcp.json`:**
   Replace `"@org/server"` or `"@org/server@latest"` with `"@org/server@1.2.3"` (or `pkg==1.2.3` for `uvx`, and `@sha256:...` digests for Docker images).
2. **Keep API keys out of CLI flags and JSON config files:**
   Pass credentials through environment variable references (`"${GITHUB_PERSONAL_ACCESS_TOKEN}"`) rather than `--api-key` flags or literal strings inside `.mcp.json`.
3. **Opt out of default-on MCP telemetry where supported:**
   Set `DISABLE_TELEMETRY=1`, `MCP_DISABLE_TELEMETRY=1`, `N8N_MCP_TELEMETRY_DISABLED=true`, `BLENDER_MCP_DISABLE_TELEMETRY=1`, or `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` in your MCP `"env"` block if you do not want local tool servers sending usage events.
4. **Wrap MCP servers or coding CLIs with `leaktap`:**
   - Run `leaktap scan --all` to check local chat logs, `.mcp.json` files, hooks, and installed skills offline.
   - Wrap an individual MCP server inside `.mcp.json` to strip unrelated shell secrets (`AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET_KEY`, `SSH_AUTH_SOCK`), pin its `tools/list` schema, and log outbound connections:
     ```bash
     leaktap --mcp-pins-file ~/.leaktap/mcp-pins.json tap --scrub-env --scrub-ssh-agent --quiet --log ~/.leaktap/mcp.jsonl -- npx @org/some-mcp@1.2.3
     ```

---

## Reproduce This Audit

Every static finding and commit hash in [`docs/mcp-top-20-audit.json`](mcp-top-20-audit.json) can be reproduced locally with `leaktap`:

```bash
# Build leaktap
cargo build --release

# Re-run Layer 1 (`leaktap scan`) across the exact 20 commits in the dataset
python3 scripts/audit_top_mcp_servers.py \
  --from-dataset docs/mcp-top-20-audit.json \
  --clones-dir /tmp/mcp-top-20-clones \
  --leaktap ./target/release/leaktap \
  /tmp/reproduced-top-20.json

# Wrap any installed MCP server in Layer 2 (`leaktap tap`) to inspect live tools and outbound connections
./target/release/leaktap --no-config --mcp-pins-file /tmp/pins.json \
  tap --scrub-env --no-inspect-api --quiet --log /tmp/wire.jsonl \
  -- npx @apify/actors-mcp-server@0.9.3
```
