#!/usr/bin/env python3
"""
Reproducible empirical audit of the Top 50 dedicated open-source MCP servers on GitHub.

Selection criteria:
  - Repository name contains `mcp` (sorted by GitHub stars descending)
  - Excludes curated `awesome-*` lists, SDKs, tutorials, and MCP clients/inspectors
  - README contains actual MCP server setup instructions (`"mcpServers"` or `claude mcp add`)

Checks each repository's official README setup instructions and package manifests
(`package.json` / `pyproject.toml`) for three concrete security and privacy patterns:
  1. Unpinned remote auto-install (`npx -y <pkg>` / `uvx <pkg>` without an exact version pin)
  2. Plaintext secret templates inside JSON config files (`"env": {"API_KEY": "..."}` instead of `${VAR}`)
  3. Bundled analytics / telemetry SDKs (`posthog`, `sentry`, `segment`, `mixpanel`, `amplitude`, etc.)
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

EXCLUDED_REPOS = {
    "punkpeye/awesome-mcp-servers",
    "appcypher/awesome-mcp-servers",
    "wong2/awesome-mcp-servers",
    "PrefectHQ/fastmcp",
    "modelcontextprotocol/inspector",
    "modelcontextprotocol/typescript-sdk",
    "modelcontextprotocol/python-sdk",
    "modelcontextprotocol/java-sdk",
    "modelcontextprotocol/csharp-sdk",
    "modelcontextprotocol/rust-sdk",
    "modelcontextprotocol/go-sdk",
    "modelcontextprotocol/specification",
    "modelcontextprotocol/modelcontextprotocol",
    "mcp-use/mcp-use",
    "microsoft/mcp-for-beginners",
    "lastmile-ai/mcp-agent",
    "cline/mcp-marketplace",
}

EXCLUDED_NAME_SUBSTRINGS = (
    "awesome-",
    "-awesome",
    "for-beginners",
    "-sdk",
    "sdk-",
    "tutorial",
    "course",
    "client",
    "inspector",
    "gateway",
    "proxy",
    "registry",
    "benchmark",
)

TELEMETRY_DEPS = (
    "posthog",
    "@sentry/",
    "sentry-sdk",
    "analytics-node",
    "@segment/",
    "mixpanel",
    "@amplitude/",
    "amplitude-js",
    "dd-trace",
    "applicationinsights",
)

RAW_SECRET_ENV_RE = re.compile(
    r'"([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PAT|CREDENTIALS|AUTH_KEY)[A-Z0-9_]*)"\s*:\s*"([^"$][^"]*)"'
)


def gh_json(args: list[str]) -> object | None:
    res = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return None


def fetch_decoded_file(repo: str, path: str) -> str:
    data = gh_json(["api", f"repos/{repo}/contents/{path}"])
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return ""
    try:
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def fetch_readme(repo: str) -> str:
    data = gh_json(["api", f"repos/{repo}/readme"])
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return ""
    try:
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def is_dedicated_mcp_server(repo_full: str, readme: str) -> bool:
    if repo_full in EXCLUDED_REPOS:
        return False
    short_name = repo_full.split("/", 1)[1].lower()
    if any(sub in short_name for sub in EXCLUDED_NAME_SUBSTRINGS):
        return False
    return (
        '"mcpServers"' in readme
        or '"servers"' in readme
        or "claude mcp add" in readme
        or "claude_desktop_config.json" in readme
        or ".mcp.json" in readme
    )


def is_pinned_pkg(pkg: str) -> bool:
    if "==" in pkg:
        return True
    rest = pkg[1:] if pkg.startswith("@") else pkg
    if "@" not in rest:
        return False
    ver = rest.split("@", 1)[1]
    return bool(ver) and ver not in ("latest", "next", "main") and ver[0].isdigit()


def has_unpinned_install(readme: str) -> bool:
    for m in re.finditer(r"(?:npx|bunx)\s+(?:-y|--yes)\s+([^\s`\"'\]]+)", readme):
        pkg = m.group(1).strip().rstrip(",")
        if not is_pinned_pkg(pkg):
            return True

    for m in re.finditer(
        r'"command"\s*:\s*"(npx|uvx|bunx|pipx)"[\s\S]{0,240}?"args"\s*:\s*\[([^\]]+)\]',
        readme,
    ):
        tokens = re.findall(r'"([^"]+)"', m.group(2))
        pkgs = [t for t in tokens if not t.startswith("-") and t not in ("run", "from")]
        if pkgs and not is_pinned_pkg(pkgs[0]):
            return True

    for m in re.finditer(r"\buvx\s+([A-Za-z0-9_.\-]+)", readme):
        pkg = m.group(1)
        if "==" not in pkg and pkg not in ("from", "run"):
            return True

    return False


def has_plaintext_env_secret_template(readme: str) -> bool:
    for m in RAW_SECRET_ENV_RE.finditer(readme):
        val = m.group(2).strip()
        if val.startswith("${") or val.startswith("$") or val.startswith("env:"):
            continue
        return True
    return False


def detect_telemetry_sdk(repo: str, readme: str) -> list[str]:
    found: set[str] = set()
    pkg_json = fetch_decoded_file(repo, "package.json").lower()
    pyproject = fetch_decoded_file(repo, "pyproject.toml").lower()
    combined = f"{pkg_json}\n{pyproject}"

    for dep in TELEMETRY_DEPS:
        if dep in combined:
            found.add(dep.strip("@/"))

    lower_readme = readme.lower()
    if "telemetry" in lower_readme and any(
        phrase in lower_readme
        for phrase in ("disable", "opt-out", "opt out", "anonymous usage", "_telemetry")
    ):
        found.add("documented-telemetry")

    return sorted(found)


def main() -> int:
    candidates = gh_json(
        [
            "search",
            "repos",
            "mcp in:name",
            "--sort",
            "stars",
            "--limit",
            "100",
            "--json",
            "fullName,stargazersCount,language,description",
        ]
    )
    if not isinstance(candidates, list):
        print("Failed to query GitHub search API", file=sys.stderr)
        return 1

    results = []
    for item in candidates:
        repo = item["fullName"]
        readme = fetch_readme(repo)
        if not is_dedicated_mcp_server(repo, readme):
            continue

        unpinned = has_unpinned_install(readme)
        raw_env = has_plaintext_env_secret_template(readme)
        telemetry = detect_telemetry_sdk(repo, readme)

        results.append(
            {
                "rank": len(results) + 1,
                "repo": repo,
                "stars": item["stargazersCount"],
                "language": item.get("language") or "Other",
                "unpinned_remote_exec": unpinned,
                "plaintext_secret_in_config_docs": raw_env,
                "telemetry_signals": telemetry,
            }
        )
        if len(results) == 50:
            break

    total = len(results)
    if total == 0:
        print("No repositories matched criteria", file=sys.stderr)
        return 1

    unpinned_n = sum(1 for r in results if r["unpinned_remote_exec"])
    raw_env_n = sum(1 for r in results if r["plaintext_secret_in_config_docs"])
    telem_n = sum(1 for r in results if r["telemetry_signals"])

    summary = {
        "audited_count": total,
        "unpinned_remote_exec_count": unpinned_n,
        "unpinned_remote_exec_pct": round(unpinned_n * 100 / total, 1),
        "plaintext_secret_docs_count": raw_env_n,
        "plaintext_secret_docs_pct": round(raw_env_n * 100 / total, 1),
        "telemetry_sdk_or_notice_count": telem_n,
        "telemetry_sdk_or_notice_pct": round(telem_n * 100 / total, 1),
        "servers": results,
    }

    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/mcp_top50_audit.json")
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "servers"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
