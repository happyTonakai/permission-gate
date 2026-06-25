#!/usr/bin/env bash
set -eu
# pipefail is bash-only; silently skip when running under sh (dash)
(set -o pipefail) 2>/dev/null && set -o pipefail

REPO="happyTonakai/permission-gate"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# ── Detect OS & arch ──────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin)  GOOS="darwin"  ;;
  linux)   GOOS="linux"   ;;
  *)
    echo "Unsupported OS: $OS (only darwin and linux are supported)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH (only amd64 and arm64 are supported)" >&2
    exit 1
    ;;
esac

# ── Resolve the download URL ─────────────────────────────────────
# If VERSION is set (e.g. "v1.0.0"), download that specific release;
# otherwise fetch the latest release.
if [ -n "${VERSION:-}" ]; then
  TAG="$VERSION"
else
  echo "Detecting latest release..." >&2
  TAG=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name":' \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$TAG" ]; then
    echo "Failed to detect the latest release tag." >&2
    exit 1
  fi
fi

BINARY="pgate_${GOOS}_${GOARCH}"
URL="https://github.com/$REPO/releases/download/$TAG/$BINARY"

# ── Download ──────────────────────────────────────────────────────
echo "Downloading $BINARY ($TAG)..." >&2
mkdir -p "$INSTALL_DIR"
curl -sSfL "$URL" -o "$INSTALL_DIR/pgate"
chmod +x "$INSTALL_DIR/pgate"

# ── Done ──────────────────────────────────────────────────────────
echo "Installed pgate to $INSTALL_DIR/pgate" >&2

if ! echo ":$PATH:" | grep -q ":$INSTALL_DIR:" 2>/dev/null; then
  echo "" >&2
  echo "⚠  $INSTALL_DIR is not in your PATH." >&2
  echo "   Add it by running:" >&2
  echo "" >&2
  echo "   export PATH=\"\$HOME/.local/bin:\$PATH\"" >&2
  echo "" >&2
  echo "   Or add that line to your ~/.bashrc / ~/.zshrc." >&2
fi

# ── Verify ────────────────────────────────────────────────────────
echo "" >&2
"$INSTALL_DIR/pgate" version
