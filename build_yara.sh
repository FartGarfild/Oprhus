#!/bin/bash
# =============================================================================
# build_yara.sh — one-time static-ish build of yara/yarac for bundling
# alongside av_scan.sh (same idea as bin/busybox).
#
# Unlike busybox, YARA does not publish ready static binaries, so this
# builds one from source. Result: a "mostly static" binary that depends
# only on libc/libm (not on libyara/openssl/libmagic/jansson/lzma/bz2/zlib
# like a normal system install) — portable across any glibc-based Linux
# of a similar or newer age. Fully static (musl-style, zero dependencies
# like busybox) would need a musl cross-toolchain; not done here.
#
# Usage:
#   ./build_yara.sh [version]      # default version: 4.5.8
#
# Output: ./bin/yara and ./bin/yarac (drop these into the av_scan package's
# bin/ directory, next to busybox).
# =============================================================================
set -euo pipefail

VERSION="${1:-4.5.8}"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "[*] Installing build dependencies (requires apt + sudo)..."
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential autoconf automake libtool pkg-config curl

echo "[*] Downloading YARA v${VERSION} source..."
curl -sL "https://github.com/VirusTotal/yara/archive/refs/tags/v${VERSION}.tar.gz" -o "$WORKDIR/yara.tar.gz"
tar -xzf "$WORKDIR/yara.tar.gz" -C "$WORKDIR"

cd "$WORKDIR/yara-${VERSION}"
echo "[*] Configuring (static libyara, no openssl/magic/jansson dependency)..."
./bootstrap.sh
./configure --disable-shared --enable-static --without-crypto

echo "[*] Building..."
make -j"$(nproc)"

echo "[*] Verifying..."
./yara --version
./yarac --version
echo "[*] Dynamic dependencies (should only be libc/libm/ld-linux):"
ldd ./yara

strip ./yara ./yarac

mkdir -p "$OLDPWD/bin"
cp ./yara ./yarac "$OLDPWD/bin/"
chmod +x "$OLDPWD/bin/yara" "$OLDPWD/bin/yarac"

echo ""
echo "[OK] Built: $OLDPWD/bin/yara, $OLDPWD/bin/yarac"
echo "     Copy these into your av_scan package's bin/ directory."
