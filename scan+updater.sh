#!/bin/bash
# =============================================================================
# Oprhus AV Scanner Unified v6.1
# Best of v5.1 + v6.0 + Signature Updater
#
# Features:
#   - Built-in signature updater (Maldet, ClamAV, YARA, MalwareBazaar, custom)
#   - Parallel workers with batch hashing (SHA256 + MD5) and YARA batching
#   - Zero-RAM lookup + strict RAM ceiling
#   - Real-time RAM / CPU / ETA / FPS monitor
#   - Full heuristics: strings, hex-ERE, b64 payloads, disguised files, SUID/SGID
#   - Magic-bytes fast filter + busybox fallback
#   - Pure self-contained single file
#
# Usage:
#   ./av_scan.sh [OPTIONS]
#
# Options:
#   -u, --update          Update all signatures before scanning
#   -r, --max-ram MB      Max RAM limit in megabytes (default: 500)
#   -j, --workers N       Number of parallel worker processes (default: auto)
#   -d, --dir PATH        Target directory to scan (default: /mnt)
#   -s, --sigs PATH       Signature directory (default: ./signatures)
#   -m, --max-size MB     Max file size for deep inspection in MB (default: 10)
#   -o, --output FILE     Save final report to file
#   --no-ram              Force /tmp instead of /dev/shm
#   --no-busybox          Do not offer busybox download
#   --mb-key KEY          MalwareBazaar Auth-Key (optional)
#   -h, --help            Show this help
# =============================================================================
set -uo pipefail
export LC_ALL=C

VERSION="6.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIGNATURES="${SCRIPT_DIR}/signatures"
## =============================
# DEFAULTS
## =============================
WORKERS=$(cpu_count)
ROOT_DIR="/mnt"
MAX_SCAN_MB=10
MAX_RAM_MB=500
OUTPUT_FILE=""
DO_UPDATE=false
USE_RAM=true
ALLOW_BUSYBOX=true
MB_KEY=""
## =============================
# DEFAULTS
## =============================

# ── OS / Arch ────────────────────────────────────────────────────────────────
case "$(uname -s 2>/dev/null)" in
    Darwin) OS="macos" ;;
    *)      OS="linux" ;;
esac
ARCH="$(uname -m 2>/dev/null)"
case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    armv7*)         ARCH="armv7" ;;
    *)              ARCH="x86_64" ;;
esac

# ── Utilities ────────────────────────────────────────────────────────────────
cpu_count() {
    command -v nproc &>/dev/null && { nproc; return; }
    command -v sysctl &>/dev/null && { sysctl -n hw.logicalcpu 2>/dev/null; return; }
    grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4
}

detect_sha256() {
    if command -v sha256sum &>/dev/null; then echo "sha256sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 256"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -sha256"
    else echo "none"; fi
}

detect_md5() {
    if command -v md5sum &>/dev/null; then echo "md5sum"
    elif command -v md5 &>/dev/null; then echo "md5 -q"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -md5"
    else echo "none"; fi
}

detect_yara() {
    command -v yara &>/dev/null && echo "yara" || echo "none"
}

# ── Work directory (RAM-disk preference) ─────────────────────────────────────
choose_work_dir() {
    local use_ram="$1" workers="$2"
    if [ "$use_ram" = true ] && [ "$OS" = "linux" ] && [ -d "/dev/shm" ]; then
        local needed=$(( workers * 12 + 60 ))
        local avail
        avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        [ "${avail:-0}" -ge "$needed" ] && { echo "/dev/shm/av_scan_$$"; return; }
    fi
    echo "${TMPDIR:-/tmp}/av_scan_$$"
}

# ── Busybox / strings / file detection ───────────────────────────────────────
BUSYBOX_BIN=""
STRINGS_CMD="bash"
FILE_CMD="bash"

check_network() {
    if command -v curl &>/dev/null; then
        curl -sf --connect-timeout 3 "https://busybox.net" >/dev/null 2>&1
    elif command -v wget &>/dev/null; then
        wget -q --timeout=3 --spider "https://busybox.net" 2>/dev/null
    else
        return 1
    fi
}

busybox_url() {
    case "${OS}_${ARCH}" in
        linux_x86_64) echo "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" ;;
        linux_arm64)  echo "https://busybox.net/downloads/binaries/1.35.0-aarch64-linux-musl/busybox" ;;
        linux_armv7)  echo "https://busybox.net/downloads/binaries/1.35.0-armv7l-linux-musleabihf/busybox" ;;
        *) echo "" ;;
    esac
}

download_busybox() {
    local url="$1" dest="$SCRIPT_DIR/bin/busybox"
    mkdir -p "$SCRIPT_DIR/bin"
    echo -e "${C}[*] Downloading busybox (~1MB)...${Z}"
    local ok=false
    if command -v curl &>/dev/null; then
        curl -fL --progress-bar -o "$dest" "$url" 2>&1 && ok=true
    elif command -v wget &>/dev/null; then
        wget -q --show-progress -O "$dest" "$url" 2>&1 && ok=true
    fi
    if $ok && [ -s "$dest" ]; then
        chmod +x "$dest"
        if "$dest" strings --help &>/dev/null 2>&1; then
            echo -e "${G}[OK] busybox saved: $dest${Z}"
            BUSYBOX_BIN="$dest"
            return 0
        fi
    fi
    rm -f "$dest" 2>/dev/null
    echo -e "${R}[FAIL] busybox download/verify failed${Z}"
    return 1
}

offer_busybox() {
    local util="$1" allow="$2"
    [ "$allow" = "false" ] || [ "$OS" = "macos" ] && return 1
    local url; url=$(busybox_url)
    [ -z "$url" ] && return 1
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        echo -e "${G}[OK] '${util}' -> pre-loaded busybox${Z}"
        return 0
    fi
    echo -e "${Y}[WARN] '${util}' not found${Z}"
    if ! check_network; then
        echo -e "${Y}[WARN] No network -> bash fallback${Z}"
        return 1
    fi
    echo -e "${C} Download static busybox for faster scanning? [Y/n]: ${Z}"
    local ans
    if read -r -t 12 ans 2>/dev/null; then ans="${ans,,}"; else echo ""; ans="n"; fi
    case "$ans" in
        ""|y|yes) download_busybox "$url"; return $? ;;
        *) echo -e "${Y}[INFO] Skipped -> bash fallback${Z}"; return 1 ;;
    esac
}

find_local_busybox() {
    local c="$SCRIPT_DIR/bin/busybox"
    if [ -x "$c" ] && "$c" strings --help &>/dev/null 2>&1; then
        BUSYBOX_BIN="$c"; return 0
    fi
    return 1
}

detect_tools() {
    local allow_busybox="$1"
    echo -e "[*] Detecting utilities..."
    find_local_busybox && echo -e "${G}[OK] local busybox: $BUSYBOX_BIN${Z}"

    if command -v strings &>/dev/null; then
        STRINGS_CMD="strings"; echo -e "${G}[OK] strings : native${Z}"
    elif [ -n "$BUSYBOX_BIN" ]; then
        STRINGS_CMD="$BUSYBOX_BIN strings"; echo -e "${G}[OK] strings : busybox${Z}"
    elif offer_busybox "strings" "$allow_busybox" && [ -n "$BUSYBOX_BIN" ]; then
        STRINGS_CMD="$BUSYBOX_BIN strings"
    else
        STRINGS_CMD="bash"; echo -e "${Y}[WARN] strings : bash fallback${Z}"
    fi

    if command -v file &>/dev/null; then
        FILE_CMD="file"; echo -e "${G}[OK] file : native${Z}"
    elif [ -n "$BUSYBOX_BIN" ]; then
        FILE_CMD="$BUSYBOX_BIN file"; echo -e "${G}[OK] file : busybox${Z}"
    elif offer_busybox "file" "$allow_busybox" && [ -n "$BUSYBOX_BIN" ]; then
        FILE_CMD="$BUSYBOX_BIN file"
    else
        FILE_CMD="bash"; echo -e "${Y}[WARN] file : bash magic-bytes${Z}"
    fi
    echo ""
}

# =============================================================================
# UPDATER MODULE
# =============================================================================
update_signatures() {
    local sig_dir="$1"
    local mb_key="${2:-}"
    mkdir -p "$sig_dir"/{maldet,clamav,hashes,yara,strings,custom}

    echo -e "\033[1;36m[*] Updating signature databases...\033[0m"

    # 1. Maldet
    echo "[*] Maldet sigpack..."
    wget -q https://cdn.rfxn.com/downloads/maldet-sigpack.tgz -O /tmp/maldet-sigpack.tgz 2>/dev/null || true
    if [ -s /tmp/maldet-sigpack.tgz ]; then
        tar -xzf /tmp/maldet-sigpack.tgz -C "$sig_dir/maldet" --strip-components=1 2>/dev/null || true
        echo "  ✓ Maldet: $(find "$sig_dir/maldet" -type f 2>/dev/null | wc -l | tr -d ' ') files"
        rm -f /tmp/maldet-sigpack.tgz
    else
        echo "  ! Maldet download failed (skipped)"
    fi

    # 2. ClamAV
    echo "[*] ClamAV databases..."
    local clam_dir="$sig_dir/clamav"
    wget -q https://database.clamav.net/main.cvd -O /tmp/main.cvd 2>/dev/null || true
    wget -q https://database.clamav.net/daily.cvd -O /tmp/daily.cvd 2>/dev/null || true
    if [ -s /tmp/main.cvd ] && [ -s /tmp/daily.cvd ]; then
        if command -v sigtool &>/dev/null; then
            sigtool --unpack /tmp/main.cvd -d "$clam_dir" 2>/dev/null || true
            sigtool --unpack /tmp/daily.cvd -d "$clam_dir" 2>/dev/null || true
        else
            # Fallback: strip 512-byte header
            tail -c +513 /tmp/main.cvd | tar -xz -C "$clam_dir" 2>/dev/null || true
            tail -c +513 /tmp/daily.cvd | tar -xz -C "$clam_dir" 2>/dev/null || true
        fi
        echo "  ✓ ClamAV unpacked"
        rm -f /tmp/main.cvd /tmp/daily.cvd
    else
        echo "  ! ClamAV download failed (skipped)"
    fi

    # 3. MalwareBazaar (optional)
    if [ -n "$mb_key" ] && [ "$mb_key" != "YOUR_AUTH_KEY_HERE" ]; then
        echo "[*] MalwareBazaar hashes..."
        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            curl -s -H "Auth-Key: $mb_key" \
                -d "query=get_recent&selector=sha256&limit=30000" \
                https://mb-api.abuse.ch/api/v1/ 2>/dev/null | \
                jq -r '.data[]? | select(.sha256_hash) | "\(.sha256_hash)\tMalwareBazaar"' \
                > "$sig_dir/hashes/malwarebazaar.sha256" 2>/dev/null || true
            local cnt
            cnt=$(wc -l < "$sig_dir/hashes/malwarebazaar.sha256" 2>/dev/null | tr -d ' ')
            echo "  ✓ MalwareBazaar: ${cnt:-0} hashes"
        else
            echo "  ! curl/jq missing -> skipped"
        fi
    fi

    # 4. YARA rules
    echo "[*] YARA rules..."
    local yara_dir="$sig_dir/yara"
    for repo in "https://github.com/Neo23x0/signature-base.git" "https://github.com/Yara-Rules/rules.git"; do
        local name; name=$(basename "$repo" .git)
        git -C "$yara_dir/$name" pull --quiet 2>/dev/null || \
            git clone --depth 1 "$repo" "$yara_dir/$name" --quiet 2>/dev/null || true
    done

    if command -v yarac &>/dev/null; then
        echo "  [*] Compiling YARA rules (may take time)..."
        local yara_index="$yara_dir/index.yar"
        local yara_compiled="$yara_dir/rules.yarc"
        > "$yara_index"
        find "$yara_dir" -type f \( -name "*.yar" -o -name "*.yara" \) ! -name "index.yar" 2>/dev/null | while read -r yfile; do
            if yarac "$yfile" /dev/null &>/dev/null; then
                echo "include \"$yfile\"" >> "$yara_index"
            fi
        done
        if [ -s "$yara_index" ] && yarac "$yara_index" "$yara_compiled" &>/dev/null; then
            echo "  ✓ YARA compiled -> rules.yarc"
        else
            echo "  ! YARA index compile failed -> will use text rules"
            rm -f "$yara_compiled" 2>/dev/null
        fi
    else
        echo "  ! yarac not found -> text rules only"
    fi

    # 5. Custom boilerplate
    local custom_dir="$sig_dir/custom"
    if [ ! -f "$custom_dir/custom.strings" ]; then
        cat << 'EOF' > "$custom_dir/custom.strings"
eval(base64_decode
/bin/sh -i
bash -i >
nc -e /bin
python -c import socket
chmod 777
PHPDATA.*mbd;[0-9-]+\s*<\/PHPDATA>
round\((\d+\.?\d*\+?){2,}\)
goto [A-Za-z0-9_]+;
EOF
    fi
    [ ! -f "$custom_dir/custom.md5" ] && cat << 'EOF' > "$custom_dir/custom.md5"
# Add your MD5 hashes (hash<TAB>name)
EOF
    [ ! -f "$custom_dir/custom.sha256" ] && cat << 'EOF' > "$custom_dir/custom.sha256"
# Add your SHA256 hashes (hash<TAB>name)
EOF

    echo -e "\033[1;32m[OK] Signature update finished\033[0m"
    echo "    Size: $(du -sh "$sig_dir" 2>/dev/null | cut -f1)"
    echo ""
}

# =============================================================================
# DEFAULTS & ARGUMENTS
# =============================================================================

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--update)     DO_UPDATE=true; shift ;;
        -r|--max-ram)    MAX_RAM_MB="$2"; shift 2 ;;
        -j|--workers)    WORKERS="$2"; shift 2 ;;
        -d|--dir)        ROOT_DIR="$2"; shift 2 ;;
        -s|--sigs)       SIGNATURES="$2"; shift 2 ;;
        -m|--max-size)   MAX_SCAN_MB="$2"; shift 2 ;;
        -o|--output)     OUTPUT_FILE="$2"; shift 2 ;;
        --no-ram)        USE_RAM=false; shift ;;
        --no-busybox)    ALLOW_BUSYBOX=false; shift ;;
        --mb-key)        MB_KEY="$2"; shift 2 ;;
        -h|--help)       usage ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

# Colors
if [ -t 1 ]; then
    R='\033[0;31m' Y='\033[1;33m' G='\033[0;32m'
    C='\033[0;36m' B='\033[1m' Z='\033[0m'
else
    R='' Y='' G='' C='' B='' Z=''
fi

# Update if requested
[ "$DO_UPDATE" = true ] && update_signatures "$SIGNATURES" "$MB_KEY"

# ── RAM Guard ────────────────────────────────────────────────────────────────
echo -e "${B}[*] RAM Guard: ceiling ${C}${MAX_RAM_MB} MB${Z}"

YARA_CMD=$(detect_yara)
if [ "$YARA_CMD" != "none" ] && [ -d "$SIGNATURES/yara" ]; then
    ESTIMATED_YARA_MB=120
    MAX_SAFE_WORKERS=$(( MAX_RAM_MB / ESTIMATED_YARA_MB ))
    [ "$MAX_SAFE_WORKERS" -lt 1 ] && MAX_SAFE_WORKERS=1
    if [ "$WORKERS" -gt "$MAX_SAFE_WORKERS" ]; then
        echo -e "${Y}[WARN] YARA RAM estimate: reducing workers $WORKERS -> $MAX_SAFE_WORKERS${Z}"
        WORKERS=$MAX_SAFE_WORKERS
    fi
fi

if [ "$MAX_RAM_MB" -le 512 ]; then
    USE_RAM=false
    if [ "$WORKERS" -gt 4 ]; then
        echo -e "${Y}[WARN] Low-RAM profile: workers reduced to 4${Z}"
        WORKERS=4
    fi
elif [ "$MAX_RAM_MB" -le 1024 ] && [ "$WORKERS" -gt 8 ]; then
    WORKERS=8
fi

SHA256_CMD=$(detect_sha256)
MD5_CMD=$(detect_md5)
WORK_DIR=$(choose_work_dir "$USE_RAM" "$WORKERS")
WORKER_FILE="$WORK_DIR/worker.sh"
SIG_DIR="$WORK_DIR/sigs"
mkdir -p "$WORK_DIR/reports" "$SIG_DIR"

check_deps() {
    local miss=()
    for cmd in bash find awk grep od dd cut tr wc; do
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [ ${#miss[@]} -gt 0 ] && { echo -e "${R}[FAIL] Missing: ${miss[*]}${Z}"; exit 1; }
}
check_deps
detect_tools "$ALLOW_BUSYBOX"

# =============================================================================
# SIGNATURE COMPILER (v5.1 advanced + YARA)
# =============================================================================
compile_signatures() {
    local sig_input="$1"
    local out_dir="$2"

    echo -e "[*] Compiling signatures into flat artifacts..."

    # Built-in heuristics
    cat << 'EOF' > "$out_dir/strings.txt"
eval(base64_decode
/bin/sh -i
bash -i >
nc -e /bin
python -c import socket
chmod 777 /
EOF

    touch "$out_dir/sha256.tsv" "$out_dir/md5.tsv" "$out_dir/hex_ere.txt" "$out_dir/b64_payloads.tsv"

    if [ ! -e "$sig_input" ]; then
        echo -e "${Y}[INFO] No signature base found. Using built-in heuristics only.${Z}"
        return
    fi

    local sig_files=()
    if [ -d "$sig_input" ]; then
        while IFS= read -r -d '' sf; do
            sig_files+=("$sf")
        done < <(find "$sig_input" -type f -print0 2>/dev/null)
    else
        sig_files+=("$sig_input")
    fi

    # Advanced parser from v5.1
    awk -v out="$out_dir" '
        function hex2ere(s, a, p) {
            s = tolower(s)
            gsub(/[^0-9a-f?*{}|()]/, "", s)
            if (length(s) < 8) return ""
            gsub(/\?\?/, "..", s)
            gsub(/\*/, ".*", s)
            while (match(s, /\{[0-9]+(-[0-9]+)?\}/)) {
                p = substr(s, RSTART+1, RLENGTH-2)
                if (index(p, "-")) {
                    split(p, a, "-")
                    sub(/\{[0-9]+-[0-9]+\}/, ".{" (2*a[1]) "," (2*a[2]) "}", s)
                } else {
                    sub(/\{[0-9]+\}/, ".{" (2*p) "}", s)
                }
            }
            return s
        }
        {
            line = $0
            sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
            if (line == "" || line ~ /^#/) next
            if (line ~ /^sha256:/) {
                split(line, a, ":")
                print tolower(a[2]) "\tCustom.SHA256" >> (out "/sha256.tsv")
                next
            }
            if (line ~ /^str:/) {
                print substr(line, 5) >> (out "/strings.txt")
                next
            }
            if (line ~ /^b64sig:/) {
                print substr(line, 8) "\tCustom.B64" >> (out "/b64_payloads.tsv")
                next
            }
            # ClamAV / Maldet hashes
            if (line ~ /^[0-9a-fA-F]{32,64}:[0-9*]+:/) {
                split(line, a, ":")
                h = tolower(a[1]); name = a[3]
                if (length(h) == 64) print h "\t" name >> (out "/sha256.tsv")
                else if (length(h) == 32) print h "\t" name >> (out "/md5.tsv")
                next
            }
            # Hex signatures
            if (line ~ /:[0-9]+:[0-9*a-fA-F>=-]*:/ || line ~ /:[0-9a-fA-F?*{}|()]{10,}$/) {
                n = split(line, a, ":")
                if (length(a[n]) >= 8) {
                    ere = hex2ere(a[n])
                    if (ere != "") print ere >> (out "/hex_ere.txt")
                }
                next
            }
        }
    ' "${sig_files[@]}" 2>/dev/null

    # External hash lists
    find "$sig_input" \( -name "*.sha256" -o -name "malwarebazaar.sha256" \) 2>/dev/null | while read -r f; do
        [ -s "$f" ] && awk '{print $1 "\t" ($2 ? $2 : "External.Hash")}' "$f" >> "$out_dir/sha256.tsv"
    done

    # YARA
    mkdir -p "$out_dir/yara"
    if [ -d "$sig_input/yara" ]; then
        # Prefer compiled if exists
        if [ -f "$sig_input/yara/rules.yarc" ]; then
            cp "$sig_input/yara/rules.yarc" "$out_dir/yara/" 2>/dev/null || true
        fi
        if [ -f "$sig_input/yara/index.yar" ]; then
            cp "$sig_input/yara/index.yar" "$out_dir/yara/" 2>/dev/null || true
        fi
        # Copy individual rules as fallback
        find "$sig_input/yara" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -200 | while read -r yf; do
            cp "$yf" "$out_dir/yara/" 2>/dev/null || true
        done
    fi

    # Base64 -> SHA256 precompute
    if [ -s "$out_dir/b64_payloads.tsv" ] && [ "$SHA256_CMD" != "none" ]; then
        local tmp_b64="$out_dir/b64_compiled.tsv"
        while IFS=$'\t' read -r payload name; do
            [ -z "$payload" ] && continue
            local dh
            dh=$(printf '%s' "$payload" | ( [ "$OS" = "macos" ] && base64 -D || base64 -d ) 2>/dev/null | $SHA256_CMD 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
            [ -n "$dh" ] && echo -e "${dh}\t${name:-Custom.B64}" >> "$tmp_b64"
        done < "$out_dir/b64_payloads.tsv"
        mv -f "$tmp_b64" "$out_dir/b64_payloads.tsv" 2>/dev/null || touch "$out_dir/b64_payloads.tsv"
    fi

    # Custom
    local cdir=""
    if [ -d "$sig_input/custom" ]; then cdir="$sig_input/custom"
    elif [ -d "$SIG_DIR/custom" ]; then cdir="$SIG_DIR/custom"; fi
    if [ -n "$cdir" ] && [ -d "$cdir" ]; then
        find "$cdir" -name "*.md5" -exec cat {} + 2>/dev/null >> "$out_dir/md5.tsv" || true
        find "$cdir" -name "*.sha256" -exec cat {} + 2>/dev/null >> "$out_dir/sha256.tsv" || true
        find "$cdir" -name "*.strings" -exec cat {} + 2>/dev/null >> "$out_dir/strings.txt" || true
        echo "  ✓ Custom signatures loaded"
    fi

    # Dedup
    for f in sha256.tsv md5.tsv strings.txt hex_ere.txt b64_payloads.tsv; do
        [ -s "$out_dir/$f" ] && sort -u "$out_dir/$f" -o "$out_dir/$f" 2>/dev/null || true
    done

    echo -e "  SHA256 : ${C}$(wc -l < "$out_dir/sha256.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  MD5    : ${C}$(wc -l < "$out_dir/md5.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  HexERE : ${C}$(wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  Strings: ${C}$(wc -l < "$out_dir/strings.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  YARA   : ${C}$(find "$out_dir/yara" -name "*.ya*" 2>/dev/null | wc -l | tr -d ' ')${Z}"
    echo ""
}

# ── Extract embedded worker ──────────────────────────────────────────────────
extract_worker() {
    local inside=false
    while IFS= read -r ln; do
        [ "$ln" = "#__WORKER_START__" ] && { inside=true; continue; }
        [ "$ln" = "#__WORKER_END__" ] && break
        $inside && printf '%s\n' "$ln"
    done < "$0" > "$WORKER_FILE"
    chmod +x "$WORKER_FILE"
}

extract_worker
compile_signatures "$SIGNATURES" "$SIG_DIR"

START_MS=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))

# Banner
echo -e "${B}=================================================${Z}"
echo -e "${B} Oprhus AV Scanner Unified v${VERSION}${Z}  [OS: $OS | ARCH: $ARCH]"
echo -e " RAM Ceiling  : ${C}${MAX_RAM_MB} MB${Z}"
echo -e " Workers      : ${C}${WORKERS}${Z}"
echo -e " Target       : ${C}${ROOT_DIR}${Z}"
echo -e " Signatures   : ${C}${SIGNATURES}${Z}"
echo -e " Max size     : ${C}${MAX_SCAN_MB} MB${Z}"
echo -e " SHA256 / MD5 : ${C}${SHA256_CMD} / ${MD5_CMD}${Z}"
echo -e " YARA         : ${C}${YARA_CMD}${Z}"
echo -e " strings/file : ${C}${STRINGS_CMD} / ${FILE_CMD}${Z}"
echo -e "${B}=================================================${Z}"

# File collection
echo -e "[*] Collecting file tree..."
EXCL=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")
if [ "$OS" = "linux" ] && find "$SCRIPT_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
    find "$ROOT_DIR" -type f "${EXCL[@]}" -printf "%s\t%m\t%p\n" 2>/dev/null > "$WORK_DIR/all_files.tsv"
else
    find "$ROOT_DIR" -type f "${EXCL[@]}" -print 2>/dev/null > "$WORK_DIR/all_files.tsv"
fi
TOTAL_FILES=$(wc -l < "$WORK_DIR/all_files.tsv" | tr -d ' ')
echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z}\n"

awk -v w="$WORKERS" -v d="$WORK_DIR/reports" '{ print > (d "/pool_" (NR % w) ".txt") }' "$WORK_DIR/all_files.tsv"

# Launch workers
echo -e "[*] Launching ${WORKERS} workers (batch hash + YARA)...\n"
WORKER_PIDS=()
for pool in "$WORK_DIR/reports"/pool_*.txt; do
    [ -f "$pool" ] || continue
    wid=$(basename "$pool" .txt)
    bash "$WORKER_FILE" \
        "$pool" "$wid" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" &
    WORKER_PIDS+=($!)
done

# ── Live Progress Monitor (from v5.1) ────────────────────────────────────────
show_progress() {
    local prev=0 prev_ms="$START_MS"
    tput civis 2>/dev/null || true
    printf '\n\n\n\n\n'
    while true; do
        local now elapsed_ms elapsed_s
        now=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))
        elapsed_ms=$(( now - START_MS )); elapsed_s=$(( elapsed_ms / 1000 ))

        local tf=0 tt=0
        for f in "$WORK_DIR/reports"/pool_*.progress; do
            [ -f "$f" ] || continue
            local fv tv
            fv=$(grep "^FILES=" "$f" 2>/dev/null | cut -d= -f2)
            tv=$(grep "^THREATS=" "$f" 2>/dev/null | cut -d= -f2)
            tf=$(( tf + ${fv:-0} )); tt=$(( tt + ${tv:-0} ))
        done

        local dt=$(( now - prev_ms )) fps=0 avg=0
        [ "$dt" -gt 0 ] && fps=$(( (tf - prev) * 1000 / dt ))
        [ "$fps" -lt 0 ] && fps=0
        [ "$elapsed_s" -gt 0 ] && avg=$(( tf / elapsed_s ))
        prev=$tf; prev_ms=$now

        local eta="--:--"
        [ "${avg:-0}" -gt 0 ] && [ "${TOTAL_FILES:-0}" -gt "$tf" ] && {
            local r=$(( (TOTAL_FILES - tf) / avg ))
            eta=$(printf '%02d:%02d' $(( r/60 )) $(( r%60 )))
        }

        local active=0 active_pids=($$ "$MONITOR_PID")
        for pid in "${WORKER_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                active=$(( active + 1 ))
                active_pids+=("$pid")
            fi
        done

        local mem_mb=0
        if [ "${#active_pids[@]}" -gt 0 ]; then
            mem_mb=$(ps -o rss= -p "${active_pids[@]}" 2>/dev/null | awk '{s+=$1} END {print int(s/1024)}')
        fi
        local ram_pct=0
        [ "$MAX_RAM_MB" -gt 0 ] && ram_pct=$(( mem_mb * 100 / MAX_RAM_MB ))

        local cpu_load="0.00"
        if [ -r /proc/loadavg ]; then
            cpu_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
        else
            cpu_load=$(uptime 2>/dev/null | awk -F'load averages?:' '{print $2}' | cut -d, -f1 | tr -d ' ')
        fi

        local efmt; efmt=$(printf '%02d:%02d' $(( elapsed_s/60 )) $(( elapsed_s%60 )))
        local tc="$G"; [ "$tt" -gt 0 ] && tc="$R"

        printf '\033[5A'
        printf '\033[K'"${B}Time     :${Z} %-8s ${C}Workers : %d/%d${Z}\n" "$efmt" "$active" "$WORKERS"
        printf '\033[K'"${B}Files    :${Z} %-8d ${tc}${B}Threats : %d${Z}\n" "$tf" "$tt"
        printf '\033[K'"${B}Speed    :${Z} %-8s ${C}RAM     : %s / %s MB (%d%%)${Z}\n" "${fps} f/s" "${mem_mb:-0}" "$MAX_RAM_MB" "$ram_pct"
        printf '\033[K'"${B}Avg Speed:${Z} %-8s ${C}CPU Load: %s${Z}\n" "${avg} f/s" "${cpu_load:-0.00}"
        printf '\033[K'"${B}ETA      :${Z} %s\n" "$eta"
        sleep 1
    done
}

show_progress &
MONITOR_PID=$!

cleanup() {
    kill "$MONITOR_PID" 2>/dev/null || true
    for p in "${WORKER_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    tput cnorm 2>/dev/null || true
    rm -rf "$WORK_DIR"
    echo -e "\n${Y}[WARN] Scan aborted${Z}"
    exit 130
}
trap cleanup INT TERM

# Wait
for pid in "${WORKER_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
kill "$MONITOR_PID" 2>/dev/null || true
tput cnorm 2>/dev/null || true

# Final report
END_MS=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))
ELAPSED_S=$(( (END_MS - START_MS) / 1000 ))

TF=0; TT=0
for r in "$WORK_DIR/reports"/pool_*.txt; do
    [ -f "$r" ] || continue
    f=$(grep "^FILES_SCANNED:" "$r" 2>/dev/null | cut -d: -f2)
    t=$(grep "^THREATS_FOUND:" "$r" 2>/dev/null | cut -d: -f2)
    TF=$(( TF + ${f:-0} )); TT=$(( TT + ${t:-0} ))
done
SPEED=0; [ "$ELAPSED_S" -gt 0 ] && SPEED=$(( TF / ELAPSED_S ))

RPT="
=================================================
 SCAN RESULTS  (Oprhus Unified v${VERSION})
=================================================
 OS / Arch          : $OS / $ARCH
 Target             : $ROOT_DIR
 Files Scanned      : $TF
 Threats Found      : $TT
 Time Elapsed       : $(printf '%02d:%02d' $(( ELAPSED_S/60 )) $(( ELAPSED_S%60 )))
 Avg Speed          : ${SPEED} files/s
 Workers            : $WORKERS
================================================="

echo -e "\n"
if [ "$TT" -gt 0 ]; then
    echo -e "${R}${RPT}${Z}"
    echo -e "\n${R}${B}=== DETECTED THREATS ===${Z}"
    grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null \
        | cut -d: -f2- | sort -u \
        | while IFS='|' read -r type file info; do
            echo -e " ${R}[!]${Z} [${Y}${type}${Z}] ${file} ${C}${info:-}${Z}"
          done
else
    echo -e "${G}${RPT}${Z}"
    echo -e "\n ${G}[OK] No threats detected [CLEAN]${Z}"
fi

[ -n "$OUTPUT_FILE" ] && {
    {
        echo "$RPT"
        [ "$TT" -gt 0 ] && {
            echo -e "\n=== DETECTED THREATS ==="
            grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d: -f2- | sort -u
        }
    } > "$OUTPUT_FILE"
    echo -e "\n[*] Report saved: ${C}${OUTPUT_FILE}${Z}"
}

rm -rf "$WORK_DIR"
exit 0

# =============================================================================
# EMBEDDED WORKER (best of v5.1 + v6.0)
# =============================================================================
#__WORKER_START__
#!/bin/bash
set -uo pipefail
export LC_ALL=C

POOL_FILE="${1:?}"
WORKER_ID="${2:?}"
REPORT_DIR="${3:?}"
SIG_DIR="${4:?}"
MAX_SCAN_MB="${5:-10}"
OS="${6:-linux}"
SHA256_CMD="${7:-none}"
MD5_CMD="${8:-none}"
STRINGS_CMD="${9:-bash}"
FILE_CMD="${10:-bash}"
YARA_CMD="${11:-none}"

REPORT="$REPORT_DIR/${WORKER_ID}.txt"
PROGRESS="$REPORT_DIR/${WORKER_ID}.progress"
FILES_SCANNED=0
THREATS_FOUND=0
MAX_SIZE=$(( MAX_SCAN_MB * 1024 * 1024 ))

HAS_SHA256=false
HAS_MD5=false
HAS_B64=false
HAS_STRINGS=false
HAS_HEX_ERE=false
HAS_YARA=false
YARA_TARGET=""

[ -s "$SIG_DIR/sha256.tsv" ] && HAS_SHA256=true
[ -s "$SIG_DIR/md5.tsv" ] && HAS_MD5=true
[ -s "$SIG_DIR/b64_payloads.tsv" ] && HAS_B64=true
[ -s "$SIG_DIR/strings.txt" ] && HAS_STRINGS=true
[ -s "$SIG_DIR/hex_ere.txt" ] && HAS_HEX_ERE=true

if [ -f "$SIG_DIR/yara/rules.yarc" ]; then
    HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/rules.yarc"
elif [ -f "$SIG_DIR/yara/index.yar" ]; then
    HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/index.yar"
fi

_stat_size() {
    if [ "$OS" = "macos" ]; then stat -f '%z' "$1" 2>/dev/null
    else stat -c '%s' "$1" 2>/dev/null; fi
}
_stat_mode() {
    if [ "$OS" = "macos" ]; then
        local m; m=$(stat -f '%Op' "$1" 2>/dev/null) && printf '%s' "${m: -4}"
    else
        stat -c '%a' "$1" 2>/dev/null
    fi
}
_sha256_stdin() {
    [ "$SHA256_CMD" = "none" ] && { cat >/dev/null; echo ""; return; }
    $SHA256_CMD 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1
}
_b64decode() {
    if [ "$OS" = "macos" ]; then base64 -D 2>/dev/null
    else base64 -d 2>/dev/null; fi
}

_bash_strings() {
    local file="$1" min_len="${2:-6}" max_bytes="${3:-524288}"
    dd if="$file" bs="$max_bytes" count=1 2>/dev/null \
    | od -An -tx1 -v | tr -s ' ' '\n' | grep -v '^\s*$' \
    | awk -v min="$min_len" '
        function h2d(h, v,i,c) {
            v=0; h=tolower(h)
            for(i=1;i<=length(h);i++){ c=substr(h,i,1); v=v*16+(c~/[0-9]/?c+0:index("abcdef",c)+9) }
            return v
        }
        {
            b = h2d($0)
            if (b >= 32 && b <= 126) buf = buf sprintf("%c", b)
            else { if (length(buf) >= min) print buf; buf = "" }
        }
        END { if (length(buf) >= min) print buf }
    '
}

_bash_file_type() {
    local magic
    magic=$(dd if="$1" bs=8 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
    [ -z "$magic" ] && { echo "EMPTY"; return; }
    case "$magic" in
        7f454c46*) echo "ELF" ;;
        4d5a*)     echo "PE_MZ" ;;
        25504446*) echo "PDF" ;;
        504b0304*) echo "ZIP" ;;
        89504e470d0a*) echo "PNG" ;;
        ffd8ff*)   echo "JPEG" ;;
        47494638*) echo "GIF" ;;
        1f8b*)     echo "GZIP" ;;
        425a68*)   echo "BZIP2" ;;
        377abcaf*) echo "7ZIP" ;;
        2321*)     echo "SCRIPT" ;;
        *)         echo "UNKNOWN";;
    esac
}

do_strings() {
    local file="$1" min="${2:-6}" maxb="${3:-524288}"
    if [ "$STRINGS_CMD" = "bash" ]; then
        _bash_strings "$file" "$min" "$maxb"
    else
        dd if="$file" bs="$maxb" count=1 2>/dev/null | $STRINGS_CMD -n "$min" 2>/dev/null
    fi
}

do_file_type() {
    local file="$1"
    if [ "$FILE_CMD" = "bash" ]; then
        _bash_file_type "$file"
    else
        local out
        out=$($FILE_CMD -b "$file" 2>/dev/null | head -1)
        case "$out" in
            ELF*) echo "ELF" ;;
            PE32*|MS-DOS*|MZ*) echo "PE_MZ" ;;
            PDF*) echo "PDF" ;;
            Zip*|Java*archive*) echo "ZIP" ;;
            PNG*) echo "PNG" ;;
            JPEG*) echo "JPEG" ;;
            GIF*) echo "GIF" ;;
            gzip*) echo "GZIP" ;;
            bzip2*) echo "BZIP2" ;;
            *7-zip*) echo "7ZIP" ;;
            *shell*script*|*Python*|*Perl*|*Ruby*|*PHP*) echo "SCRIPT" ;;
            *) echo "UNKNOWN" ;;
        esac
    fi
}

log() { printf '[%s] %s\n' "$WORKER_ID" "$*" >> "$REPORT"; }
threat() { printf 'THREAT:%s\n' "$*" >> "$REPORT"; THREATS_FOUND=$(( THREATS_FOUND + 1 )); }
progress() {
    printf 'FILES=%d\nTHREATS=%d\nCURRENT=%s\n' \
        "$FILES_SCANNED" "$THREATS_FOUND" "${1:-}" > "$PROGRESS"
}

# Batch hash
process_hash_batch() {
    local htype="$1" sig_file="$2"
    shift 2
    [ $# -eq 0 ] && return
    local cmd="$SHA256_CMD"
    [ "$htype" = "md5" ] && cmd="$MD5_CMD"
    [ "$cmd" = "none" ] && return

    local out
    out=$($cmd "$@" 2>/dev/null)
    [ -z "$out" ] && return

    local hits
    hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | grep -F -f - "$sig_file" 2>/dev/null)
    if [ -n "$hits" ]; then
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            local tname
            tname=$(grep -F -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -d$'\t' -f2)
            local hit_file
            hit_file=$(printf '%s\n' "$out" | grep -iE "^${hit_hash}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
            [ -n "$hit_file" ] && threat "KNOWN_MALWARE|$hit_file|name=${tname:-Malware}|$htype=$hit_hash"
        done <<< "$hits"
    fi
}

# YARA batch
process_yara_batch() {
    [ $# -eq 0 ] || [ "$HAS_YARA" = false ] || [ "$YARA_CMD" = "none" ] && return
    local yara_out
    yara_out=$($YARA_CMD "$YARA_TARGET" "$@" 2>/dev/null)
    if [ -n "$yara_out" ]; then
        while IFS= read -r yline; do
            [ -z "$yline" ] && continue
            local yrule; yrule=$(echo "$yline" | awk '{print $1}')
            local yfile; yfile=$(echo "$yline" | cut -d' ' -f2-)
            threat "YARA_MATCH|$yfile|rule=$yrule"
        done <<< "$yara_out"
    fi
}

# Heuristics (v5.1)
check_file_heuristics() {
    local file="$1" size="$2" oct="$3"

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # Strings
        if [ "$HAS_STRINGS" = true ]; then
            local str_match
            str_match=$(do_strings "$file" 6 524288 | grep -F -i -f "$SIG_DIR/strings.txt" 2>/dev/null | head -1)
            if [ -n "$str_match" ]; then
                threat "SIG_STRING_MATCH|$file|pattern=${str_match:0:50}"
                return
            fi
        fi

        # Hex ERE
        if [ "$HAS_HEX_ERE" = true ]; then
            local hex_dump hex_match
            hex_dump=$(dd if="$file" bs=524288 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
            if [ -n "$hex_dump" ]; then
                hex_match=$(printf '%s\n' "$hex_dump" | grep -E -o -i -f "$SIG_DIR/hex_ere.txt" 2>/dev/null | head -1)
                if [ -n "$hex_match" ]; then
                    threat "HEX_SIG_MATCH|$file|hex=${hex_match:0:40}..."
                    return
                fi
            fi
        fi

        # Base64 payloads
        while IFS= read -r chunk; do
            [ -z "$chunk" ] && continue
            if [ "$HAS_B64" = true ] && [ "$SHA256_CMD" != "none" ]; then
                local dh
                dh=$(printf '%s' "$chunk" | _b64decode | _sha256_stdin)
                if [ -n "$dh" ] && grep -qF "$dh" "$SIG_DIR/b64_payloads.tsv" 2>/dev/null; then
                    local bname
                    bname=$(grep -F -m 1 "^$dh" "$SIG_DIR/b64_payloads.tsv" | cut -d$'\t' -f2)
                    threat "KNOWN_B64_PAYLOAD|$file|name=${bname:-B64.Malware}|b64=${chunk:0:20}..."
                    continue
                fi
            fi
            local magic
            magic=$(printf '%s' "$chunk" | _b64decode 2>/dev/null | dd bs=8 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
            case "$magic" in
                7f454c46*) threat "SUSPICIOUS_B64_PAYLOAD|$file|decoded=ELF|b64=${chunk:0:20}..." ;;
                4d5a*)     threat "SUSPICIOUS_B64_PAYLOAD|$file|decoded=PE_MZ|b64=${chunk:0:20}..." ;;
                2321*)     threat "SUSPICIOUS_B64_PAYLOAD|$file|decoded=SCRIPT|b64=${chunk:0:20}..." ;;
            esac
        done < <(grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$file" 2>/dev/null | head -20)
    fi

    # Disguised
    local ext="${file##*.}"
    ext="${ext,,}"
    case "$ext" in
        jpg|jpeg|png|gif|bmp|webp|pdf|doc|docx|xls|xlsx)
            local real_type
            real_type=$(do_file_type "$file")
            case "$real_type" in
                ELF|PE_MZ|SCRIPT) threat "DISGUISED_FILE|$file|ext=.$ext|real=$real_type" ;;
            esac
            ;;
    esac

    # Permissions
    if [ -n "$oct" ] && [ "$oct" != "0" ]; then
        oct="${oct: -4}"
        (( 8#$oct & 8#6000 )) 2>/dev/null && threat "SUID_SGID|$file|perms=$oct"
        (( 8#$oct & 8#0002 )) && (( 8#$oct & 8#0111 )) 2>/dev/null && threat "WORLD_WRITABLE_EXEC|$file|perms=$oct"
    fi
}

# Main loop
log "Worker started PID=$$ OS=$OS yara=$YARA_CMD"
progress "init"

declare -a BATCH_SHA=()
declare -a BATCH_MD5=()
declare -a BATCH_YARA=()
SHA_BATCH_CNT=0
MD5_BATCH_CNT=0
YARA_BATCH_CNT=0

while IFS=$'\t' read -r col1 col2 col3; do
    local file size oct
    if [ -n "${col3:-}" ]; then
        size="$col1"; oct="$col2"; file="$col3"
    else
        file="$col1"
        [ -z "$file" ] || [ ! -f "$file" ] || [ ! -r "$file" ] && continue
        size=$(_stat_size "$file") || continue
        oct=$(_stat_mode "$file")
    fi

    [ -z "$file" ] || [ ! -f "$file" ] || [ ! -r "$file" ] && continue
    FILES_SCANNED=$(( FILES_SCANNED + 1 ))
    [ "$size" -eq 0 ] && continue

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # Hash batches
        if [ "$HAS_SHA256" = true ] && [ "$SHA256_CMD" != "none" ]; then
            BATCH_SHA+=("$file")
            SHA_BATCH_CNT=$(( SHA_BATCH_CNT + 1 ))
            if [ "$SHA_BATCH_CNT" -ge 50 ]; then
                process_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
                BATCH_SHA=(); SHA_BATCH_CNT=0
            fi
        fi
        if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
            BATCH_MD5+=("$file")
            MD5_BATCH_CNT=$(( MD5_BATCH_CNT + 1 ))
            if [ "$MD5_BATCH_CNT" -ge 50 ]; then
                process_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
                BATCH_MD5=(); MD5_BATCH_CNT=0
            fi
        fi

        # Magic filter + YARA decision
        local magic_type skip_deep=false
        magic_type=$(_bash_file_type "$file")
        case "$magic_type" in
            JPEG|PNG|GIF) skip_deep=true ;;
        esac

        # Disguised override
        local ext="${file##*.}"
        case "${ext,,}" in
            jpg|jpeg|png|gif)
                if [ "$magic_type" = "ELF" ] || [ "$magic_type" = "PE_MZ" ]; then
                    threat "DISGUISED_FILE|$file|ext=.$ext|real=$magic_type"
                    skip_deep=false
                fi
                ;;
        esac

        if [ "$skip_deep" = false ] && [ "$HAS_YARA" = true ]; then
            BATCH_YARA+=("$file")
            YARA_BATCH_CNT=$(( YARA_BATCH_CNT + 1 ))
            if [ "$YARA_BATCH_CNT" -ge 50 ]; then
                process_yara_batch "${BATCH_YARA[@]}"
                BATCH_YARA=(); YARA_BATCH_CNT=0
            fi
        fi
    fi

    # Full heuristics
    check_file_heuristics "$file" "$size" "${oct:-0}"

    [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
done < "$POOL_FILE"

# Flush
[ "$SHA_BATCH_CNT" -gt 0 ] && process_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
[ "$MD5_BATCH_CNT" -gt 0 ] && process_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
[ "$YARA_BATCH_CNT" -gt 0 ] && process_yara_batch "${BATCH_YARA[@]}"

progress "done"
printf 'FILES_SCANNED:%d\nTHREATS_FOUND:%d\n' "$FILES_SCANNED" "$THREATS_FOUND" >> "$REPORT"
log "Completed - files: $FILES_SCANNED, threats: $THREATS_FOUND"
touch "${REPORT_DIR}/${WORKER_ID}.done"
#__WORKER_END__
