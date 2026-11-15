#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const pkgJson = require("../package.json");
const VERSION = `v${pkgJson.version}`;
const REPO = "vssinghh/leaktap";

const PLATFORM_MAP = {
  "darwin-arm64": { pkg: "@leaktap/darwin-arm64", artifact: "leaktap-darwin-arm64" },
  "darwin-x64": { pkg: "@leaktap/darwin-x64", artifact: "leaktap-darwin-x64" },
  "linux-x64": { pkg: "@leaktap/linux-x64", artifact: "leaktap-linux-x64" },
  "linux-arm64": { pkg: "@leaktap/linux-arm64", artifact: "leaktap-linux-arm64" },
  "win32-x64": { pkg: "@leaktap/win32-x64", artifact: "leaktap-win32-x64.exe" },
};

function fetchBuffer(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": `leaktap-npx/${pkgJson.version}` } }, (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          if (redirectsLeft <= 0) {
            return reject(new Error("too many redirects"));
          }
          return resolve(fetchBuffer(res.headers.location, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

async function resolveBinary() {
  const binName = process.platform === "win32" ? "leaktap.exe" : "leaktap";
  const key = `${process.platform}-${process.arch}`;
  const entry = PLATFORM_MAP[key];

  // 1. Preinstalled platform npm package (`@leaktap/<os>-<arch>`)
  if (entry) {
    try {
      return require.resolve(`${entry.pkg}/bin/${binName}`);
    } catch (_) {
      // Fall through
    }
  }

  // 2. Local repository cargo build (when running from git checkout)
  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  for (const profile of ["release", "debug"]) {
    const candidate = path.join(repoRoot, "target", profile, binName);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // 3. Cached or on-demand verified GitHub Release binary
  if (!entry) {
    process.stderr.write(`leaktap: unsupported platform ${key}\n`);
    process.exit(2);
  }

  const cacheDir = path.join(os.homedir(), ".cache", "leaktap", VERSION);
  const cachedBin = path.join(cacheDir, binName);
  if (fs.existsSync(cachedBin)) {
    return cachedBin;
  }

  const base = `https://github.com/${REPO}/releases/download/${VERSION}/${entry.artifact}`;
  process.stderr.write(`leaktap: downloading verified ${entry.artifact} (${VERSION})...\n`);
  const [binBuf, shaBuf] = await Promise.all([
    fetchBuffer(base),
    fetchBuffer(`${base}.sha256`),
  ]);

  const expected = shaBuf.toString("utf8").trim().split(/\s+/)[0];
  const actual = crypto.createHash("sha256").update(binBuf).digest("hex");
  if (expected !== actual) {
    throw new Error(`SHA-256 mismatch (expected ${expected}, got ${actual})`);
  }

  fs.mkdirSync(cacheDir, { recursive: true });
  const tmpPath = `${cachedBin}.tmp.${process.pid}`;
  fs.writeFileSync(tmpPath, binBuf, { mode: 0o755 });
  fs.renameSync(tmpPath, cachedBin);
  return cachedBin;
}

async function main() {
  try {
    const binPath = await resolveBinary();
    const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
    if (result.error) {
      process.stderr.write(`leaktap launch error: ${result.error.message}\n`);
      process.exit(2);
    }
    process.exit(result.status ?? 1);
  } catch (err) {
    process.stderr.write(`leaktap error: ${err.message}\n`);
    process.exit(2);
  }
}

main();
