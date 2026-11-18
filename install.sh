#!/bin/sh
# Installer for leaktap (https://github.com/vssinghh/leaktap)
# Inspect before running:
#   curl -fsSLO https://raw.githubusercontent.com/vssinghh/leaktap/v0.4.2/install.sh
#   less install.sh && sh install.sh

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
    curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  if [ -z "$VERSION" ]; then
    err "failed to resolve latest release tag from GitHub; set LEAKTAP_VERSION=v0.4.2 manually"
  fi
fi

case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*|[0-9]*.[0-9]*.[0-9]*)
    case "$VERSION" in
      *[!A-Za-z0-9._-]*) err "invalid release tag '$VERSION'" ;;
    esac
    ;;
  *)
    err "invalid release tag '$VERSION' (expected vX.Y.Z)"
    ;;
esac

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR="$(mktemp -d)"
STAGE_TARGET=""
cleanup() {
  rm -rf "$TMP_DIR"
  if [ -n "$STAGE_TARGET" ] && [ -e "$STAGE_TARGET" ]; then
    rm -f "$STAGE_TARGET"
  fi
}
trap cleanup EXIT INT TERM

say "downloading ${ARTIFACT} (${VERSION})..."
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/${ARTIFACT}" -o "${TMP_DIR}/${ARTIFACT}"
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/${ARTIFACT}.sha256" -o "${TMP_DIR}/${ARTIFACT}.sha256"

say "checking SHA-256 download integrity..."
EXPECTED_HASH="$(awk 'NR==1 {print $1}' "${TMP_DIR}/${ARTIFACT}.sha256" | tr 'A-F' 'a-f')"
case "$EXPECTED_HASH" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) err "malformed SHA-256 checksum in ${ARTIFACT}.sha256" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${ARTIFACT}" | awk '{print $1}' | tr 'A-F' 'a-f')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${ARTIFACT}" | awk '{print $1}' | tr 'A-F' 'a-f')"
else
  err "neither sha256sum nor shasum found to check binary download integrity"
fi

if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
  err "SHA-256 checksum mismatch (expected $EXPECTED_HASH, got $ACTUAL_HASH)"
fi

VERIFY_MODE="${LEAKTAP_VERIFY_ATTESTATION:-auto}"
if [ "$VERIFY_MODE" = "1" ]; then
  need_cmd gh
  say "verifying GitHub Sigstore build provenance attestation..."
  gh attestation verify "${TMP_DIR}/${ARTIFACT}" --repo "$REPO"
elif [ "$VERIFY_MODE" != "0" ]; then
  case "$VERSION" in
    v0.1.*|0.1.*|v0.2.*|0.2.*)
      ;;
    *)
      if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        say "verifying GitHub Sigstore build provenance attestation..."
        gh attestation verify "${TMP_DIR}/${ARTIFACT}" --repo "$REPO"
      fi
      ;;
  esac
fi

mkdir -p "$INSTALL_DIR"
TARGET="${INSTALL_DIR}/leaktap"
STAGE_TARGET="$(mktemp "${INSTALL_DIR}/.leaktap.tmp.XXXXXX")"
cp "${TMP_DIR}/${ARTIFACT}" "$STAGE_TARGET"
chmod 755 "$STAGE_TARGET"
mv -f "$STAGE_TARGET" "$TARGET"
STAGE_TARGET=""

say "installed leaktap ${VERSION} to ${TARGET} (cryptographic provenance check: gh attestation verify ${TARGET} --repo ${REPO})"

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
