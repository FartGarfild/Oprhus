#!/bin/bash
# =============================================================================
#  Oprhus Signature Updater — Maldet + ClamAV + MalwareBazaar + YARA
# =============================================================================

set -uo pipefail

SIG_DIR="$(cd "$(dirname "$0")" && pwd)/signatures"
mkdir -p "$SIG_DIR"/{maldet,clamav,hashes,yara,strings}

echo -e "\033[1m[*] Оновлення всіх баз сигнатур...\033[0m"

# 1. Maldet
echo "[*] Maldet sigpack..."
wget -q https://cdn.rfxn.com/downloads/maldet-sigpack.tgz -O /tmp/maldet-sigpack.tgz
if [ -s /tmp/maldet-sigpack.tgz ]; then
    tar -xzf /tmp/maldet-sigpack.tgz -C "$SIG_DIR/maldet" --strip-components=1 2>/dev/null || true
    echo "    ✓ Maldet: $(find "$SIG_DIR/maldet" -type f 2>/dev/null | wc -l) файлів"
    rm -f /tmp/maldet-sigpack.tgz
fi

# 2. ClamAV (main + daily)
echo "[*] ClamAV databases..."
CLAM_DIR="$SIG_DIR/clamav"
mkdir -p "$CLAM_DIR"
cd /tmp || exit 1
wget -q https://database.clamav.net/main.cvd -O main.cvd
wget -q https://database.clamav.net/daily.cvd -O daily.cvd

if [ -s main.cvd ] && [ -s daily.cvd ]; then
    cp main.cvd daily.cvd "$CLAM_DIR/"
    echo "    ✓ ClamAV: $(du -sh "$CLAM_DIR" | cut -f1)"
    
    if command -v sigtool &>/dev/null; then
        sigtool --unpack "$CLAM_DIR/main.cvd" 2>/dev/null || true
        sigtool --unpack "$CLAM_DIR/daily.cvd" 2>/dev/null || true
    fi
fi

# 3. MalwareBazaar hashes
echo "[*] MalwareBazaar..."
AUTH_KEY="YOUR_AUTH_KEY_HERE"
if [ "$AUTH_KEY" != "YOUR_AUTH_KEY_HERE" ]; then
    curl -s -H "Auth-Key: $AUTH_KEY" \
         -d "query=get_recent&selector=sha256&limit=30000" \
         https://mb-api.abuse.ch/api/v1/ | \
         jq -r '.data[]? | select(.sha256_hash) | "\(.sha256_hash)\tMalwareBazaar"' \
         > "$SIG_DIR/hashes/malwarebazaar.sha256"
    echo "    ✓ MalwareBazaar: $(wc -l < "$SIG_DIR/hashes/malwarebazaar.sha256" 2>/dev/null) hashes"
fi

# 4. YARA rules
echo "[*] YARA rules..."
YARA_DIR="$SIG_DIR/yara"
mkdir -p "$YARA_DIR"
for repo in "https://github.com/Neo23x0/signature-base.git" "https://github.com/Yara-Rules/rules.git"; do
    name=$(basename "$repo" .git)
    git -C "$YARA_DIR/$name" pull --quiet 2>/dev/null || git clone --depth 1 "$repo" "$YARA_DIR/$name" --quiet
done

# ==================== Custom signatures ====================
echo "[*] Додаємо custom сигнатури..."

CUSTOM_DIR="$SIG_DIR/custom"
mkdir -p "$CUSTOM_DIR"

# MD5 hashes
cat << 'EOF' > "$CUSTOM_DIR/custom.md5"
50f28383803099955e695f2e825a0a38	Custom.MD5
75a74e0626359e933405389656209e51	Custom.MD5
1a1828113400d3d57f18b57111e64906	Custom.MD5
d928ce67cefc6b57096f171298f5dc23	Custom.MD5
EOF

# SHA256 hashes
cat << 'EOF' > "$CUSTOM_DIR/custom.sha256"
# Тут можна додавати свої SHA256
# приклад:
# abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890	Custom.SHA256
EOF

# Regex / Strings / Patterns
cat << 'EOF' > "$CUSTOM_DIR/custom.strings"
eval\(base64_decode
/bin/sh -i
bash -i
nc -e /bin
python -c.*socket
chmod 777
PHPDATA.*mbd;[0-9-]+\s*<\/PHPDATA>
round\((\d+\.?\d*\+?){2,}\)
goto [A-Za-z0-9_]+;
EOF

# Regex для hex/ERE
cat << 'EOF' > "$CUSTOM_DIR/custom.hex"
# Приклади regex для hex-дампу
EOF

echo "    ✓ Custom signatures added"

echo -e "\n\033[1;32m[OK] Усі бази оновлено!\033[0m"
echo "Розмір signatures: $(du -sh "$SIG_DIR" | cut -f1)"
echo "Запуск скану: ./av_scan.sh --sigs $SIG_DIR"
