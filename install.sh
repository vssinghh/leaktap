#!/bin/sh
# 1-line installer for leaktap (https://github.com/vssinghh/leaktap)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/vssinghh/leaktap/master/install.sh | sh

set -eu

REPO="vssinghh/leaktap"
INSTALL_DIR="${LEAKTAP_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${LEAKTAP_VERSION:-}"

say() {
  printf 'leaktap-install: %s\n' "$*"
}

err() {
  printf 'leaktap-install: error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "missing required command: $1"
  fi
}

need_cmd uname
need_cmd curl

OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$OS_RAW" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux" ;;
  *)      err "unsupported OS '$OS_RAW' (download Windows binary from https://github.com/$REPO/releases)" ;;
esac

case "$ARCH_RAW" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="x64" ;;
  *)             err "unsupported CPU architecture '$ARCH_RAW'" ;;
esac

ARTIFACT="leaktap-${OS}-${ARCH}"

if [ -z "$VERSION" ]; then
  VERSION="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  if [ -z "$VERSION" ]; then
    err "failed to resolve latest release tag from GitHub; set LEAKTAP_VERSION=v0.2.0 manually"
  fi
fi

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

say "downloading ${ARTIFACT} (${VERSION})..."
curl -fsSL "${BASE_URL}/${ARTIFACT}" -o "${TMP_DIR}/${ARTIFACT}"
curl -fsSL "${BASE_URL}/${ARTIFACT}.sha256" -o "${TMP_DIR}/${ARTIFACT}.sha256"

say "verifying SHA-256 checksum..."
EXPECTED_HASH="$(awk '{print $1}' "${TMP_DIR}/${ARTIFACT}.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${ARTIFACT}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${ARTIFACT}" | awk '{print $1}')"
else
  err "neither sha256sum nor shasum found to verify binary integrity"
fi

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  err "SHA-256 checksum mismatch (expected $EXPECTED_HASH, got $ACTUAL_HASH)"
fi

mkdir -p "$INSTALL_DIR"
TARGET="${INSTALL_DIR}/leaktap"
mv "${TMP_DIR}/${ARTIFACT}" "$TARGET"
chmod 755 "$TARGET"

say "installed leaktap ${VERSION} to ${TARGET}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*)
    say "run 'leaktap scan' or 'leaktap ui' to get started."
    ;;
  *)
    printf '\nNote: %s is not in your PATH yet. Add it with:\n' "$INSTALL_DIR"
    printf '  export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
    printf 'Or run directly:\n  %s scan\n' "$TARGET"
    ;;
esac
