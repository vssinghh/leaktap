#!/usr/bin/env python3
"""
Reproducible Two-Layer Security & Privacy Audit of the Top 20 Open-Source MCP Servers.

Every finding in `docs/mcp-top-20-audit.json` is produced directly by running `leaktap`
(zero regex scraping of READMEs outside `leaktap`):

  Layer 1 (Static Repository & Config Audit):
    Clones each repository and runs:
      leaktap --no-config scan <repo_dir> --no-pii --format json

  Layer 2 (Live MCP JSON-RPC & Wiretap Audit):
    Wraps runnable MCP server commands inside:
      leaktap --no-config --mcp-pins-file <pins.json> tap --scrub-env --no-inspect-api \
        --no-live-log --quiet --log <wire.jsonl> -- <server_command...>
    Sends a real JSON-RPC 2.0 `initialize` + `notifications/initialized` + `tools/list`
    handshake, holds the session open briefly so async startup telemetry flushes, and
    reads `wire.jsonl` and `pins.json` written by `leaktap`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Excluded SDKs, protocol specs, curated lists, and general CLI/web/workflow platforms
# whose primary product is not a dedicated standalone MCP server.
EXCLUDED_REPOS = {
    # Curated lists, tutorials, specs, and SDKs / wrapper libraries
    "punkpeye/awesome-mcp-servers",
    "appcypher/awesome-mcp-servers",
    "wong2/awesome-mcp-servers",
    "PrefectHQ/fastmcp",
    "tadata-org/fastapi_mcp",
    "modelcontextprotocol/inspector",
    "modelcontextprotocol/typescript-sdk",
    "modelcontextprotocol/python-sdk",
    "modelcontextprotocol/java-sdk",
    "modelcontextprotocol/csharp-sdk",
    "modelcontextprotocol/rust-sdk",
    "modelcontextprotocol/go-sdk",
    "modelcontextprotocol/specification",
    "modelcontextprotocol/modelcontextprotocol",
    "modelcontextprotocol/registry",
    "mcp-use/mcp-use",
    "microsoft/mcp-for-beginners",
    "lastmile-ai/mcp-agent",
    "cline/mcp-marketplace",
    # General CLI agents, web apps, and workflow platforms (not standalone MCP servers)
    "n8n-io/n8n",
    "activepieces/activepieces",
    "triggerdotdev/trigger.dev",
    "pipedreamhq/pipedream",
    "ComposioHQ/composio",
    "CopilotKit/CopilotKit",
    "google-gemini/gemini-cli",
    "D4Vinci/Scrapling",
    "koala73/worldmonitor",
    "ruvnet/ruflo",
    "sansan0/TrendRadar",
    "reactive-resume/reactive-resume",
    "bytedance/UI-TARS-desktop",
    "DayuanJiang/next-ai-draw-io",
    "assafelovic/gpt-researcher",
    "yikart/AiToEarn",
    "pascalorg/editor",
    "1Panel-dev/MaxKB",
    "Evil0ctal/Douyin_TikTok_Download_API",
    "modelscope/FunASR",
    "wanshuiyin/Auto-claude-code-research-in-sleep",
    "nukeop/nuclear",
    "budtmo/docker-android",
    "open-metadata/OpenMetadata",
    "liketrek/TREK",
    "xerj-org/xerj",
    "yusufkaraaslan/Skill_Seekers",
    "tonhowtf/omniget",
    "OpenByteInc/QuantDinger",
    "ccfos/nightingale",
    "JoeanAmier/XHS-Downloader",
    "Graphify-Labs/graphify",
}

EXCLUDED_NAME_SUBSTRINGS = (
    "awesome-",
    "-awesome",
    "for-beginners",
    "-sdk",
    "sdk-",
    "tutorial",
    "course",
    "inspector",
    "gateway",
    "registry",
    "benchmark",
    "marketplace",
)


def resolve_leaktap_bin(explicit: str | None) -> str:
    if explicit:
        return explicit
    repo_root = Path(__file__).resolve().parent.parent
    release_bin = repo_root / "target" / "release" / "leaktap"
    if release_bin.is_file():
        return str(release_bin)
    found = shutil.which("leaktap")
    if found:
        return found
    raise FileNotFoundError(
        "Could not find `leaktap` binary. Run `cargo build --release` first or pass `--leaktap`."
    )


def discover_top_mcp_repos(limit: int) -> list[dict]:
    """Discover top-starred standalone MCP server repositories on GitHub via `gh search repos`."""
    seen: dict[str, dict] = {}
    search_arg_sets = (
        ["mcp in:name"],
        ["--topic", "mcp-server"],
        ["--owner", "modelcontextprotocol"],
        ["--topic", "mcp", "--topic", "tree-sitter"],
    )
    for query_args in search_arg_sets:
        res = subprocess.run(
            [
                "gh",
                "search",
                "repos",
                *query_args,
                "--sort",
                "stars",
                "--limit",
                "80",
                "--json",
                "fullName,stargazersCount,language,description",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0 or not res.stdout.strip():
            continue
        for item in json.loads(res.stdout):
            full = item["fullName"]
            if full in EXCLUDED_REPOS:
                continue
            short = full.split("/", 1)[1].lower()
            if any(sub in short for sub in EXCLUDED_NAME_SUBSTRINGS):
                continue
            seen[full] = {
                "repo": full,
                "stars": item["stargazersCount"],
                "language": item.get("language") or "Other",
            }
    ranked = sorted(seen.values(), key=lambda r: r["stars"], reverse=True)
    return ranked[:limit]


def ensure_clone(repo: str, clones_dir: Path, commit: str | None = None) -> tuple[Path, str]:
    slug = repo.replace("/", "__")
    dest = clones_dir / slug
    if not (dest / ".git").is_dir():
        clones_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(dest)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if commit:
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if not head.startswith(commit[:8]):
            subprocess.run(
                ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", commit],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "-C", str(dest), "checkout", "--quiet", commit],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "--short=12", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return dest, sha


def normalize_repo_rel_path(raw_file: str, clone_dir: Path) -> str:
    expanded = os.path.expanduser(raw_file)
    clone_str = str(clone_dir.resolve())
    for prefix in (clone_str + "/", str(clone_dir) + "/"):
        if expanded.startswith(prefix):
            return expanded[len(prefix) :]
    slug_marker = f"/{clone_dir.name}/"
    if slug_marker in raw_file:
        return raw_file.split(slug_marker, 1)[1]
    return raw_file


def normalize_message_paths(msg: str, clone_dir: Path) -> str:
    short_prefix = shorten_like_prefix = f"~/.cache/mcp_audit_work/clones/{clone_dir.name}/"
    msg = msg.replace(short_prefix, "")
    for pfx in (str(clone_dir.resolve()) + "/", str(clone_dir) + "/"):
        msg = msg.replace(pfx, "")
    slug_marker = f"/{clone_dir.name}/"
    if slug_marker in msg and ("`" in msg):
        # Strip any `~/.../<slug>/` prefix inside backticked archive/script paths
        parts = msg.split("`")
        for idx in range(1, len(parts), 2):
            if slug_marker in parts[idx] and not parts[idx].startswith(("http://", "https://")):
                parts[idx] = parts[idx].split(slug_marker, 1)[1]
        msg = "`".join(parts)
    return msg


def run_layer1_static_scan(leaktap_bin: str, clone_dir: Path) -> dict:
    t0 = time.monotonic()
    res = subprocess.run(
        [leaktap_bin, "--no-config", "scan", str(clone_dir), "--no-pii", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    doc = json.loads(res.stdout) if res.stdout.strip() else {}
    risks = []
    for r in doc.get("mcp_risks", []):
        raw_path = r.get("config_file") or r.get("file") or ""
        risks.append(
            {
                "rule_id": r["rule_id"],
                "severity": r["severity"],
                "file": normalize_repo_rel_path(raw_path, clone_dir),
                "line": r.get("line", 1),
                "server_name": r.get("server_name", ""),
                "message": normalize_message_paths(r.get("message", ""), clone_dir),
            }
        )
    return {
        "scan_elapsed_ms": elapsed_ms,
        "mcp_configs_scanned": doc.get("mcp_configs_scanned", 0),
        "findings": risks,
    }


def _read_lines(pipe, sink: list[str], stop: threading.Event) -> None:
    while not stop.is_set():
        line = pipe.readline()
        if not line:
            break
        sink.append(line)


def run_layer2_stdio_tap(
    leaktap_bin: str,
    cmd: list[str],
    extra_env: dict[str, str] | None = None,
    allow_env: list[str] | None = None,
    cwd: str | None = None,
) -> dict:
    """Wrap a stdio MCP server inside `leaktap tap` and run `initialize` + `tools/list`."""
    with tempfile.TemporaryDirectory() as td:
        wire_log = os.path.join(td, "wire.jsonl")
        pins_file = os.path.join(td, "pins.json")
        tap_cmd = [leaktap_bin, "--no-config", "--mcp-pins-file", pins_file]
        if allow_env:
            tap_cmd.extend(["--allow-env", ",".join(allow_env)])
        tap_cmd.extend(
            [
                "tap",
                "--scrub-env",
                "--no-inspect-api",
                "--no-live-log",
                "--quiet",
                "--log",
                wire_log,
                "--",
                *cmd,
            ]
        )
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        proc = subprocess.Popen(
            tap_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=cwd,
            env=env,
        )
        out_lines: list[str] = []
        err_lines: list[str] = []
        stop = threading.Event()
        t_out = threading.Thread(target=_read_lines, args=(proc.stdout, out_lines, stop), daemon=True)
        t_err = threading.Thread(target=_read_lines, args=(proc.stderr, err_lines, stop), daemon=True)
        t_out.start()
        t_err.start()

        init_ok = False
        tools_ok = False
        rpc_tools: list[str] = []
        try:
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "leaktap-audit", "version": "0.4.2"},
                },
            }
            assert proc.stdin is not None
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()

            seen = 0
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if proc.poll() is not None and seen >= len(out_lines):
                    break
                while seen < len(out_lines):
                    raw = out_lines[seen].strip()
                    seen += 1
                    if raw.startswith("{"):
                        try:
                            msg = json.loads(raw)
                            if msg.get("id") == 1 and "result" in msg:
                                init_ok = True
                                break
                        except json.JSONDecodeError:
                            pass
                if init_ok:
                    break
                time.sleep(0.05)

            if init_ok and proc.poll() is None:
                proc.stdin.write(
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
                )
                proc.stdin.write(
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    + "\n"
                )
                proc.stdin.flush()
                deadline2 = time.monotonic() + 10.0
                while time.monotonic() < deadline2:
                    if proc.poll() is not None and seen >= len(out_lines):
                        break
                    while seen < len(out_lines):
                        raw = out_lines[seen].strip()
                        seen += 1
                        if raw.startswith("{"):
                            try:
                                msg = json.loads(raw)
                                if msg.get("id") == 2 and "result" in msg:
                                    arr = msg["result"].get("tools", [])
                                    if isinstance(arr, list):
                                        tools_ok = True
                                        rpc_tools = [
                                            t["name"]
                                            for t in arr
                                            if isinstance(t, dict) and isinstance(t.get("name"), str)
                                        ]
                                        break
                            except json.JSONDecodeError:
                                pass
                    if tools_ok:
                        break
                    time.sleep(0.05)

            if proc.poll() is None:
                time.sleep(2.5)
        except BrokenPipeError:
            pass
        finally:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
            stop.set()
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)

        events = []
        if os.path.isfile(wire_log):
            with open(wire_log) as fh:
                for line in fh:
                    if line.strip():
                        events.append(json.loads(line))
        pin_sha256 = None
        pinned_count = 0
        if os.path.isfile(pins_file):
            pins_doc = json.load(open(pins_file))
            for entry in pins_doc.get("servers", {}).values():
                tools_map = entry.get("tools", {})
                if isinstance(tools_map, dict) and len(tools_map) >= pinned_count:
                    pinned_count = len(tools_map)
                    pin_sha256 = entry.get("sha256")

        return {
            "handshake_ok": bool(init_ok and tools_ok),
            "tools_count": pinned_count or len(rpc_tools),
            "schema_pin_sha256": pin_sha256,
            "sample_tools": rpc_tools[:6],
            "tool_poisoning_findings": [
                e for e in events if e.get("kind") == "mcp_tool_risk"
            ],
            "live_telemetry": [
                e["detail"] for e in events if e.get("rule_id") == "mcp-live-telemetry"
            ],
            "live_connect_hosts": [
                e["detail"] for e in events if e.get("rule_id") == "http-connect"
            ],
            "live_raw_sockets": [
                e["detail"]
                for e in events
                if e.get("rule_id") in ("tcp-connection", "udp-connection")
            ],
        }


EXPECTED_PRIMARY_API_HOSTS: dict[str, set[str]] = {
    "github/github-mcp-server": {"api.github.com:443"},
    "apify/apify-mcp-server": {"api.apify.com:443"},
    "upstash/context7": {"mcp.context7.com:443"},
}


def _extract_backticked_host(detail: str) -> str:
    parts = detail.split("`")
    return parts[1] if len(parts) >= 2 else detail


def _has_non_api_startup_call(server: dict) -> bool:
    lt = server.get("live_tap", {})
    if lt.get("live_telemetry") or lt.get("live_raw_sockets"):
        return True
    expected = EXPECTED_PRIMARY_API_HOSTS.get(server["repo"], set())
    for detail in lt.get("live_connect_hosts", []):
        if _extract_backticked_host(detail) not in expected:
            return True
    return False


def compute_summary(servers: list[dict]) -> dict:
    total = len(servers)

    def count_rule(*rule_ids: str) -> int:
        rset = set(rule_ids)
        return sum(
            1
            for s in servers
            if any(f["rule_id"] in rset for f in s["static_scan"]["findings"])
        )

    unpinned = count_rule("mcp-unpinned-package")
    secret_cfg = count_rule("mcp-cli-arg-secret", "mcp-plaintext-secret-template")
    cli_arg_secret = count_rule("mcp-cli-arg-secret")
    telemetry_any = count_rule("mcp-server-telemetry", "mcp-undisclosed-telemetry")
    telemetry_undisclosed = count_rule("mcp-undisclosed-telemetry")
    pipe_to_shell = count_rule("mcp-remote-code-exec")

    live_handshakes = sum(
        1 for s in servers if s.get("live_tap", {}).get("handshake_ok")
    )
    live_outbound = sum(
        1
        for s in servers
        if s.get("live_tap", {}).get("live_telemetry")
        or s.get("live_tap", {}).get("live_connect_hosts")
        or s.get("live_tap", {}).get("live_raw_sockets")
    )
    live_non_api_outbound = sum(1 for s in servers if _has_non_api_startup_call(s))
    total_tools_pinned = sum(
        int(s.get("live_tap", {}).get("tools_count") or 0) for s in servers
    )
    tool_poisoning = sum(
        1
        for s in servers
        if s.get("live_tap", {}).get("tool_poisoning_findings")
    )

    return {
        "audited_count": total,
        "combined_stars": sum(s["stars"] for s in servers),
        "unpinned_package_or_tag_count": unpinned,
        "secret_in_config_or_cli_arg_count": secret_cfg,
        "cli_arg_secret_count": cli_arg_secret,
        "default_on_telemetry_count": telemetry_any,
        "undisclosed_telemetry_count": telemetry_undisclosed,
        "pipe_to_shell_installer_count": pipe_to_shell,
        "live_tap_handshake_completed_count": live_handshakes,
        "live_tap_startup_network_count": live_outbound,
        "live_tap_non_api_startup_network_count": live_non_api_outbound,
        "live_tap_total_tools_pinned": total_tools_pinned,
        "live_tap_tool_poisoning_count": tool_poisoning,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=20, help="Number of top MCP repos to audit")
    parser.add_argument("--leaktap", default=None, help="Path to `leaktap` binary")
    parser.add_argument(
        "--clones-dir",
        default="/tmp/leaktap-mcp-audit-clones",
        help="Directory for shallow repository clones",
    )
    parser.add_argument(
        "--from-dataset",
        default=None,
        help="Re-run static `leaktap scan` against exact repos/commits in an existing JSON dataset",
    )
    parser.add_argument(
        "--refresh-stars",
        action="store_true",
        help="Refresh live GitHub stargazers_count via `gh api` when using `--from-dataset`",
    )
    parser.add_argument(
        "--tap-cmd",
        action="append",
        default=[],
        metavar="OWNER/REPO=CMD",
        help="Optional live `leaktap tap` command for a repository (repeatable)",
    )
    parser.add_argument("out", nargs="?", default=None, help="Optional output JSON path")
    args = parser.parse_args()

    leaktap_bin = resolve_leaktap_bin(args.leaktap)
    clones_dir = Path(args.clones_dir)

    tap_cmds: dict[str, list[str]] = {}
    for entry in args.tap_cmd:
        if "=" in entry:
            repo_key, raw_cmd = entry.split("=", 1)
            tap_cmds[repo_key.strip()] = raw_cmd.strip().split()

    ver_proc = subprocess.run([leaktap_bin, "--version"], capture_output=True, text=True, check=False)
    detected_ver = (
        ver_proc.stdout.strip().split()[-1]
        if ver_proc.returncode == 0 and ver_proc.stdout.strip()
        else "0.4.2"
    )

    existing_live: dict[str, dict] = {}
    snapshot_date = time.strftime("%Y-%m-%d")
    leaktap_version = detected_ver
    if args.from_dataset:
        prev = json.loads(Path(args.from_dataset).read_text())
        snapshot_date = prev.get("snapshot_date") or snapshot_date
        candidates = []
        for r in prev.get("repositories", [])[: args.limit]:
            stars = r["stars"]
            if args.refresh_stars:
                gh_res = subprocess.run(
                    ["gh", "api", f"repos/{r['repo']}", "--jq", ".stargazers_count"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if gh_res.returncode == 0 and gh_res.stdout.strip().isdigit():
                    stars = int(gh_res.stdout.strip())
            candidates.append(
                {
                    "repo": r["repo"],
                    "stars": stars,
                    "language": r["language"],
                    "commit": r.get("commit"),
                }
            )
        for r in prev.get("repositories", []):
            if "live_tap" in r:
                existing_live[r["repo"]] = r["live_tap"]
    else:
        candidates = discover_top_mcp_repos(args.limit)

    if not candidates:
        print("No repositories matched criteria.", file=sys.stderr)
        return 1

    servers_out = []
    for rank, item in enumerate(candidates, 1):
        repo = item["repo"]
        clone_dir, sha = ensure_clone(repo, clones_dir, item.get("commit"))
        static_res = run_layer1_static_scan(leaktap_bin, clone_dir)
        rec: dict = {
            "rank": rank,
            "repo": repo,
            "stars": item["stars"],
            "language": item["language"],
            "commit": sha,
            "static_scan": static_res,
        }
        if repo in tap_cmds:
            rec["live_tap"] = run_layer2_stdio_tap(leaktap_bin, tap_cmds[repo])
        elif repo in existing_live:
            rec["live_tap"] = existing_live[repo]
        servers_out.append(rec)
        rule_ids = sorted({f["rule_id"] for f in static_res["findings"]})
        print(
            f"#{rank:02d} {repo:<36} ({sha}) findings={len(static_res['findings']):<2} rules={rule_ids}",
            file=sys.stderr,
        )

    payload = {
        "snapshot_date": snapshot_date,
        "leaktap_version": leaktap_version,
        "summary": compute_summary(servers_out),
        "repositories": servers_out,
    }
    text = json.dumps(payload, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
