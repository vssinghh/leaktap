#!/usr/bin/env python3
"""
Stages platform-specific npm binary packages (`@leaktap/<os>-<arch>`) and the main
`leaktap` launcher package into an output directory for automated `npm publish`.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

PLATFORMS = [
    {
        "pkg": "@leaktap/darwin-arm64",
        "dir": "darwin-arm64",
        "os": "darwin",
        "cpu": "arm64",
        "artifact": "leaktap-darwin-arm64",
        "bin": "leaktap",
    },
    {
        "pkg": "@leaktap/darwin-x64",
        "dir": "darwin-x64",
        "os": "darwin",
        "cpu": "x64",
        "artifact": "leaktap-darwin-x64",
        "bin": "leaktap",
    },
    {
        "pkg": "@leaktap/linux-x64",
        "dir": "linux-x64",
        "os": "linux",
        "cpu": "x64",
        "artifact": "leaktap-linux-x64",
        "bin": "leaktap",
    },
    {
        "pkg": "@leaktap/linux-arm64",
        "dir": "linux-arm64",
        "os": "linux",
        "cpu": "arm64",
        "artifact": "leaktap-linux-arm64",
        "bin": "leaktap",
    },
    {
        "pkg": "@leaktap/win32-x64",
        "dir": "win32-x64",
        "os": "win32",
        "cpu": "x64",
        "artifact": "leaktap-win32-x64.exe",
        "bin": "leaktap.exe",
    },
]


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "Usage: stage_npm_packages.py <version_or_tag> <artifacts_dir> <out_dir>",
            file=sys.stderr,
        )
        return 1

    version = sys.argv[1].lstrip("v")
    artifacts_dir = Path(sys.argv[2])
    out_dir = Path(sys.argv[3])
    repo_root = Path(__file__).resolve().parent.parent

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    # 1. Stage each platform binary package
    for p in PLATFORMS:
        src_bin = artifacts_dir / p["artifact"]
        if not src_bin.is_file():
            print(f"Missing binary artifact: {src_bin}", file=sys.stderr)
            return 1

        pkg_dir = out_dir / p["dir"]
        bin_dir = pkg_dir / "bin"
        bin_dir.mkdir(parents=True)

        dst_bin = bin_dir / p["bin"]
        shutil.copy2(src_bin, dst_bin)
        os.chmod(dst_bin, os.stat(dst_bin).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        manifest = {
            "name": p["pkg"],
            "version": version,
            "description": f"Prebuilt {p['os']}-{p['cpu']} native binary for leaktap.",
            "license": "MIT",
            "repository": {
                "type": "git",
                "url": "git+https://github.com/vssinghh/leaktap.git",
            },
            "os": [p["os"]],
            "cpu": [p["cpu"]],
            "files": ["bin/"],
        }
        (pkg_dir / "package.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    # 2. Stage root `leaktap` launcher package with synced version
    root_out = out_dir / "leaktap"
    shutil.copytree(repo_root / "npm" / "leaktap", root_out)
    root_pkg_path = root_out / "package.json"
    root_pkg = json.loads(root_pkg_path.read_text(encoding="utf-8"))
    root_pkg["version"] = version
    for opt_key in list(root_pkg.get("optionalDependencies", {}).keys()):
        root_pkg["optionalDependencies"][opt_key] = version
    root_pkg_path.write_text(json.dumps(root_pkg, indent=2) + "\n", encoding="utf-8")

    print(f"Staged 5 platform packages + root leaktap@{version} in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
