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

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
  "github-releases.githubusercontent.com",
]);

function validateDownloadUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_) {
    throw new Error(`invalid download URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`refusing non-HTTPS download URL: ${rawUrl}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED_DOWNLOAD_HOSTS.has(host)) {
    throw new Error(`refusing untrusted redirect host: ${host}`);
  }
  return parsed;
}

function fetchBuffer(url, redirectsLeft = 5) {
  const parsed = validateDownloadUrl(url);
  return new Promise((resolve, reject) => {
    const req = https.get(
      parsed,
      {
        headers: { "User-Agent": `leaktap-npx/${pkgJson.version}` },
        timeout: 30000,
      },
      (res) => {
        res.on("error", reject);
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
          const nextUrl = new URL(res.headers.location, parsed).toString();
          return resolve(fetchBuffer(nextUrl, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
        }
        const chunks = [];
        let total = 0;
        const maxBytes = 64 * 1024 * 1024;
        res.on("data", (c) => {
          total += c.length;
          if (total > maxBytes) {
            res.destroy(new Error("download exceeded 64 MiB safety limit"));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => resolve(Buffer.concat(chunks)));
      }
    );
    req.on("timeout", () => {
      req.destroy(new Error(`timeout fetching ${url}`));
    });
    req.on("error", reject);
  });
}

async function resolveBinary() {
  // 1. Explicit user-configured binary override (never inferred from relative working tree)
  if (process.env.LEAKTAP_BIN_PATH) {
    const explicit = path.resolve(process.env.LEAKTAP_BIN_PATH);
    const stat = fs.statSync(explicit, { throwIfNoEntry: false });
    if (!stat || !stat.isFile()) {
      throw new Error(`LEAKTAP_BIN_PATH does not point to a regular file: ${explicit}`);
    }
    return explicit;
  }

  const binName = process.platform === "win32" ? "leaktap.exe" : "leaktap";
  const key = `${process.platform}-${process.arch}`;
  const entry = PLATFORM_MAP[key];

  // 2. Preinstalled platform npm package (`@leaktap/<os>-<arch>`)
  if (entry) {
    try {
      return require.resolve(`${entry.pkg}/bin/${binName}`);
    } catch (_) {
      // Fall through
    }
  }

  // 3. Cached or opt-in verified GitHub Release binary
  if (!entry) {
    process.stderr.write(`leaktap: unsupported platform ${key}\n`);
    process.exit(2);
  }

  const cacheDir = path.join(os.homedir(), ".cache", "leaktap", VERSION);
  const cachedBin = path.join(cacheDir, binName);
  const cachedStat = fs.lstatSync(cachedBin, { throwIfNoEntry: false });
  if (cachedStat) {
    if (cachedStat.isSymbolicLink() || !cachedStat.isFile()) {
      throw new Error(`refusing non-regular cached binary at ${cachedBin}`);
    }
    return cachedBin;
  }

  const allowDownload =
    process.env.LEAKTAP_ALLOW_DOWNLOAD === "1" ||
    process.env.LEAKTAP_ALLOW_DOWNLOAD === "true";
  if (!allowDownload) {
    throw new Error(
      `preinstalled platform binary package (${entry.pkg}) was not found (e.g. npm --omit=optional). ` +
        `Refusing to make runtime network requests by default; reinstall without --omit=optional, ` +
        `set LEAKTAP_BIN_PATH=/path/to/leaktap, or set LEAKTAP_ALLOW_DOWNLOAD=1 to fetch ${entry.artifact} (${VERSION}) from GitHub Releases.`
    );
  }

  const base = `https://github.com/${REPO}/releases/download/${VERSION}/${entry.artifact}`;
  process.stderr.write(`leaktap: downloading ${entry.artifact} (${VERSION}) via LEAKTAP_ALLOW_DOWNLOAD=1...\n`);
  const [binBuf, shaBuf] = await Promise.all([
    fetchBuffer(base),
    fetchBuffer(`${base}.sha256`),
  ]);

  const expected = shaBuf.toString("utf8").trim().split(/\s+/)[0].toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(expected)) {
    throw new Error(`invalid SHA-256 manifest format for ${entry.artifact}`);
  }
  const actual = crypto.createHash("sha256").update(binBuf).digest("hex");
  if (expected !== actual) {
    throw new Error(`SHA-256 mismatch (expected ${expected}, got ${actual})`);
  }

  fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const nonce = crypto.randomBytes(8).toString("hex");
  const tmpPath = `${cachedBin}.tmp.${process.pid}.${nonce}`;
  fs.writeFileSync(tmpPath, binBuf, { mode: 0o755, flag: "wx" });
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
