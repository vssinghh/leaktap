#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@leaktap/darwin-arm64",
  "darwin-x64": "@leaktap/darwin-x64",
  "linux-x64": "@leaktap/linux-x64",
  "linux-arm64": "@leaktap/linux-arm64",
  "win32-x64": "@leaktap/win32-x64",
};

function resolveBinary() {
  const binName = process.platform === "win32" ? "leaktap.exe" : "leaktap";
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];

  if (pkg) {
    try {
      return require.resolve(`${pkg}/bin/${binName}`);
    } catch (_) {
      // Fall through to local repository cargo build for local development
    }
  }

  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(repoRoot, "target", profile, binName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  process.stderr.write(
    `leaktap: no prebuilt binary found for ${key}.\n` +
      `Build from source with \`cargo install --git https://github.com/vssinghh/leaktap\`.\n`
  );
  process.exit(2);
}

const binPath = resolveBinary();
const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  process.stderr.write(`leaktap launch error: ${result.error.message}\n`);
  process.exit(2);
}

process.exit(result.status ?? 1);
