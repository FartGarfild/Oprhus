#!/bin/bash
# =============================================================================
#  Oprhus Signature Updater — Maldet + MalwareBazaar + YARA
# =============================================================================

set -uo pipefail

SIG_DIR="$(cd "$(dirname "$0")" && pwd)/signatures"
mkdir -p "$SIG_DIR"/{maldet,hashes,yara,strings}

echo -e "\033[1m[*] Multi-source signature update...\033[0m"

# ==================== 1. Maldet Sigpack (без встановлення) ====================
echo "[*] Downloading latest Maldet signatures..."
cd /tmp || exit 1
wget -q https://cdn.rfxn.com/downloads/maldet-sigpack.tgz -O maldet-sigpack.tgz

if [ -s maldet-sigpack.tgz ]; then
    tar -xzf maldet-sigpack.tgz -C "$SIG_DIR/maldet" --strip-components=1 2>/dev/null || true
    echo "    ✓ Maldet signatures: $(find "$SIG_DIR/maldet" -type f 2>/dev/null | wc -l) files"
else
    echo "[!] Failed to download maldet-sigpack"
fi

# ==================== 2. MalwareBazaar ====================
echo "[*] Fetching MalwareBazaar hashes..."
AUTH_KEY="YOUR_AUTH_KEY_HERE"   # ← Заміни!

if [ "$AUTH_KEY" != "YOUR_AUTH_KEY_HERE" ]; then
    curl -s -H "Auth-Key: $AUTH_KEY" \
         -d "query=get_recent&selector=sha256&limit=30000" \
         https://mb-api.abuse.ch/api/v1/ | \
         jq -r '.data[]? | select(.sha256_hash) | "\(.sha256_hash)\tMalwareBazaar.\(.file_type // "Generic")"' \
         > "$SIG_DIR/hashes/malwarebazaar.sha256"
    echo "    ✓ MalwareBazaar: $(wc -l < "$SIG_DIR/hashes/malwarebazaar.sha256" 2>/dev/null || echo 0) hashes"
fi

# ==================== 3. YARA Rules ====================
echo "[*] Updating YARA rules..."
YARA_DIR="$SIG_DIR/yara"
mkdir -p "$YARA_DIR"

for repo in \
  "https://github.com/Neo23x0/signature-base.git" \
  "https://github.com/Yara-Rules/rules.git"; do
    name=$(basename "$repo" .git)
    if [ -d "$YARA_DIR/$name" ]; then
        git -C "$YARA_DIR/$name" pull --quiet
    else
        git clone --depth 1 "$repo" "$YARA_DIR/$name" --quiet
    fi
    echo "    Updated $name"
done

# ==================== 4. Custom strings ====================
cat << 'EOF' > "$SIG_DIR/strings/custom.txt"
eval\(base64_decode
/bin/sh -i
bash -i
nc -e /bin
python -c.*socket
chmod 777
EOF

echo -e "\n\033[1;32m[OK] Update finished!\033[0m"
echo "Signatures ready in: $SIG_DIR"
echo "Run scan: ./av_scan.sh --sigs $SIG_DIR"
