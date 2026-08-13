#!/bin/bash
# =============================================================================
# Oprhus AV Scanner Unified v6.3 (modular + quarantine + real-time)
# Features:
#   - Built-in signature updater (Maldet, ClamAV, YARA, MalwareBazaar, custom)
#   - Parallel workers with batch hashing (SHA256 + MD5) and YARA batching
#   - Zero-RAM lookup + strict RAM ceiling
#   - Real-time RAM / CPU / ETA / FPS monitor (progress UI, не плутати з
#     режимом --real-time нижче)
#   - Full heuristics: strings, hex-ERE, b64 payloads, disguised files, SUID/SGID
#   - Magic-bytes fast filter + busybox fallback
#   - Quarantine mode: перенесення виявлених файлів в ізольовану директорію
#   - Real-time watch mode: фоновий демон, що індексує дерево файлів і
#     автоматично сканує щойно створені файли
#   - Pure self-contained single file
#
# Usage:
#   ./av_scan.sh [OPTIONS]
#
# Options:
#   -u, --update            Update all signatures before scanning
#   -r, --max-ram MB        Max RAM limit in megabytes (default: 500)
#   -j, --workers N         Number of parallel worker processes (default: auto)
#   -d, --dir PATH          Target directory to scan (default: /mnt)
#   -s, --sigs PATH         Signature directory (default: ./signatures)
#   -m, --max-size MB       Max file size for deep inspection in MB (default: 10)
#   -o, --output FILE       Save final report to file
#   --no-ram                Force /tmp instead of /dev/shm
#   --no-busybox            Do not offer busybox download
#   --mb-key KEY            MalwareBazaar Auth-Key (optional)
#   -q, --quarantine        Enable quarantine mode (default dir: ./quarantine)
#   --quarantine-dir PATH   Enable quarantine mode with a custom directory
#   --quarantine-perm MODE  chmod-режим для карантинних файлів (default: 0400,
#                            тобто лише читання, без запуску)
#   -w, --real-time         Після базового скану перейти в режим фонового
#                            моніторингу: новостворені файли перевіряються
#                            автоматично (inotifywait, або polling як фолбек)
#   --watch-interval SEC    Інтервал опитування для polling-фолбеку (default: 5)
#   -h, --help               Show this help
#
# ── Структура файлу ──────────────────────────────────────────────────────────
#   1. GLOBALS         — усі змінні скрипта, визначені один раз тут
#   2. MODULE: platform / cpu
#   3. MODULE: hash & yara detection
#   4. MODULE: busybox / strings / file fallback
#   5. MODULE: CLI (usage, parse_args, colors)
#   6. MODULE: worker sizing / RAM guard
#   7. MODULE: quarantine (ініціалізація на боці головного скрипта)
#   8. MODULE: signature updater
#   9. MODULE: signature compiler
#  10. MODULE: workdir & worker extraction
#  11. MODULE: dependency check
#  12. MODULE: file collection & worker orchestration
#  13. MODULE: progress monitor / cleanup
#  14. MODULE: reporting
#  15. MODULE: real-time watch (фоновий демон)
#  16. main()          — єдина точка, що викликає модулі в потрібному порядку
#  17. EMBEDDED WORKER  — окремий self-contained скрипт (теж модульний;
#                          містить і сканування, і фактичний карантин)
# =============================================================================
set -uo pipefail
export LC_ALL=C

# ============================================================================
# 1. GLOBALS — усі змінні скрипта визначені один раз тут, ДО будь-якого коду,
#    що їх використовує. Дефолти або порожні "заглушки"; реальні значення
#    заповнюються відповідними init_*/detect_* функціями та parse_args().
#    Це усуває клас помилок "змінна використана раніше, ніж визначена"
#    (напр. WORKERS=$(cpu_count) викликався в оригіналі до оголошення
#    функції cpu_count — тут такого бути не може, бо порядок жорстко
#    контролює main()).
# ============================================================================
VERSION="6.2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- CLI-конфігуровані параметри (дефолти, можуть бути перевизначені parse_args) ---
SIGNATURES="${SCRIPT_DIR}/signatures"
ROOT_DIR="/mnt"
MAX_SCAN_MB=10
MAX_RAM_MB=500
OUTPUT_FILE=""
DO_UPDATE=false
USE_RAM=true
ALLOW_BUSYBOX=true
MB_KEY=""
WORKERS=""            # порожньо = "авто", вираховується в init_workers()

# --- Карантин ---
QUARANTINE_ENABLED=false
QUARANTINE_DIR="${SCRIPT_DIR}/quarantine"
QUARANTINE_PERM="0400"   # read-only, без виконання (НЕ буквальне "100" —
                          # 100 у chmod означає --x------, тобто "лише
                          # виконання", протилежне до "тільки читання без
                          # запуску"; 0400 = r-------- це і є той режим)

# --- Real-time watch (фоновий демон) ---
REALTIME_MODE=false
WATCH_INTERVAL=5
REALTIME_FIFO=""
REALTIME_WORKER_PID=""
REALTIME_REPORT=""
REALTIME_TAIL_PID=""

# --- Платформа (заповнює detect_platform) ---
OS=""
ARCH=""

# --- Інструменти (заповнюють detect_tools / detect_sha256 / detect_md5 / detect_yara) ---
BUSYBOX_BIN=""
STRINGS_CMD="bash"
FILE_CMD="bash"
SHA256_CMD="none"
MD5_CMD="none"
YARA_CMD="none"

# --- Робочі шляхи рантайму (заповнює init_workdir) ---
WORK_DIR=""
WORKER_FILE=""
SIG_DIR=""

# --- Кольори термінала (заповнює setup_colors) ---
R=''; Y=''; G=''; C=''; B=''; Z=''

# --- Стан сканування ---
START_MS=0
END_MS=0
ELAPSED_S=0
TOTAL_FILES=0
WORKER_PIDS=()
MONITOR_PID=""
TF=0            # files scanned (сумарно по воркерах)
TT=0            # threats found (сумарно по воркерах)
QC=0            # quarantined (сумарно по воркерах)
SPEED=0
RPT=""          # текст фінального звіту

# ============================================================================
# 2. MODULE: platform / cpu
# ============================================================================
detect_platform() {
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
}

cpu_count() {
    command -v nproc &>/dev/null && { nproc; return; }
    command -v sysctl &>/dev/null && { sysctl -n hw.logicalcpu 2>/dev/null; return; }
    grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4
}

now_ms() {
    date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 ))
}

# ============================================================================
# 3. MODULE: hash & yara detection
# ============================================================================
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

# ============================================================================
# 4. MODULE: busybox / strings / file fallback
# ============================================================================
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

# ============================================================================
# 5. MODULE: CLI (usage, argument parsing, colors)
# ============================================================================
usage() {
    head -n 40 "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
    exit 0
}

parse_args() {
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
            -q|--quarantine) QUARANTINE_ENABLED=true; shift ;;
            --quarantine-dir)  QUARANTINE_ENABLED=true; QUARANTINE_DIR="$2"; shift 2 ;;
            --quarantine-perm) QUARANTINE_PERM="$2"; shift 2 ;;
            -w|--real-time|--realtime) REALTIME_MODE=true; shift ;;
            --watch-interval)  WATCH_INTERVAL="$2"; shift 2 ;;
            -h|--help)       usage ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
}

setup_colors() {
    if [ -t 1 ]; then
        R='\033[0;31m' Y='\033[1;33m' G='\033[0;32m'
        C='\033[0;36m' B='\033[1m' Z='\033[0m'
    fi
}

# ============================================================================
# 6. MODULE: worker sizing / RAM guard
#    Замінює всі гілки логіки (кількість воркерів + RAM ceiling), які раніше
#    були "розсипані" прямо в тілі скрипта.
# ============================================================================
init_workers() {
    # WORKERS могло бути задано через -j/--workers; якщо ні — авто за CPU.
    [ -z "$WORKERS" ] && WORKERS=$(cpu_count)

    # Захист: WORKERS має бути додатним цілим (напр. -j 0 або сміттєве
    # значення не повинні призводити до ділення на нуль пізніше в awk).
    case "$WORKERS" in
        ''|*[!0-9]*) WORKERS=$(cpu_count) ;;
    esac
    [ "${WORKERS:-0}" -ge 1 ] 2>/dev/null || WORKERS=1

    echo -e "${B}[*] RAM Guard: ceiling ${C}${MAX_RAM_MB} MB${Z}"

    if [ "$YARA_CMD" != "none" ] && [ -d "$SIGNATURES/yara" ]; then
        local est_yara_mb=120
        local max_safe=$(( MAX_RAM_MB / est_yara_mb ))
        [ "$max_safe" -lt 1 ] && max_safe=1
        if [ "$WORKERS" -gt "$max_safe" ]; then
            echo -e "${Y}[WARN] YARA RAM estimate: reducing workers $WORKERS -> $max_safe${Z}"
            WORKERS=$max_safe
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
}

# ============================================================================
# 7. MODULE: quarantine (ініціалізація на боці головного скрипта)
#    Фактичне перенесення файлу відбувається у воркері (EMBEDDED WORKER,
#    функція quarantine_file) — саме там, де файл детектується, щоб не було
#    затримки/гонитви між моментом виявлення і моментом ізоляції.
# ============================================================================
init_quarantine() {
    [ "$QUARANTINE_ENABLED" = true ] || return 0

    mkdir -p "$QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$QUARANTINE_DIR" 2>/dev/null

    # Попередження: якщо карантин лежить всередині цілі сканування, карантинні
    # файли можуть потрапити в наступний прохід сканера (або в real-time watch)
    # і будуть повторно позначені/оброблені.
    case "$QUARANTINE_DIR" in
        "$ROOT_DIR"/*|"$ROOT_DIR")
            echo -e "${Y}[WARN] Карантинна директорія всередині цілі сканування ($ROOT_DIR) — можливе повторне сканування карантинних файлів${Z}"
            ;;
    esac

    echo -e "${C}[*] Quarantine: ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
}

count_quarantined() {
    grep -h "QUARANTINED:" "$WORK_DIR/reports"/*.txt 2>/dev/null | wc -l | tr -d ' '
}

# ============================================================================
# 8. MODULE: signature updater
# ============================================================================
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
    curl -A "Mozilla/5.0" -sL --connect-timeout 10 "https://packages.microsoft.com/clamav/main.cvd" -o /tmp/main.cvd || true
    curl -A "Mozilla/5.0" -sL --connect-timeout 10 "https://packages.microsoft.com/clamav/daily.cvd" -o /tmp/daily.cvd || true    
    if [ -s /tmp/main.cvd ] && [ -s /tmp/daily.cvd ]; then
    # Перевірка, що це справді CVD, а не HTML від Cloudflare
    if head -c 11 /tmp/main.cvd | grep -q "ClamAV-VDB"; then
        dd if=/tmp/main.cvd  bs=512 skip=1 status=none 2>/dev/null | tar -xz -C "$clam_dir" 2>/dev/null || true
        dd if=/tmp/daily.cvd bs=512 skip=1 status=none 2>/dev/null | tar -xz -C "$clam_dir" 2>/dev/null || true
        echo " ✓ ClamAV unpacked"
    else
        echo " ! ClamAV files are not valid CVD (probably Cloudflare block)"
    fi
    rm -f /tmp/main.cvd /tmp/daily.cvd
	else
    echo " ! ClamAV download failed (skipped)"
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

# ============================================================================
# PARALLEL AWK WRAPPER (v5.3.1 — production ready)
# ============================================================================
# Приймає: $1 = вхідний файл, $2 = вихідний файл, $3 = awk script / logic
run_awk_parallel() {
    local infile="$1"
    local outfile="$2"
    local awk_code="$3"

    if [ ! -s "$infile" ]; then
        : > "$outfile"
        return 0
    fi

    local nproc_cmd
    nproc_cmd=$(nproc 2>/dev/null \
             || sysctl -n hw.ncpu 2>/dev/null \
             || grep -c ^processor /proc/cpuinfo 2>/dev/null \
             || echo 2)

    local line_cnt
    line_cnt=$(wc -l < "$infile" 2>/dev/null || echo 0)

    if [ "$nproc_cmd" -le 1 ]; then
        awk "$awk_code" "$infile" > "$outfile"
        return $?
    fi

    local chunk_dir
    chunk_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'awk_chunks.XXXXXX')
    trap 'rm -rf "$chunk_dir"' EXIT

    local awk_script_file="$chunk_dir/script.awk"
    printf '%s\n' "$awk_code" > "$awk_script_file"

    local num_chunks=$(( nproc_cmd * 10 ))
    if [ "$line_cnt" -lt "$num_chunks" ]; then
        num_chunks=$line_cnt
        [ "$num_chunks" -lt 1 ] && num_chunks=1
    fi

    local lines_per_chunk=$(( (line_cnt + num_chunks - 1) / num_chunks ))

    if command -v shuf >/dev/null 2>&1; then
        shuf "$infile" | split -l "$lines_per_chunk" - "$chunk_dir/chunk_"
    else
        split -l "$lines_per_chunk" "$infile" "$chunk_dir/chunk_"
    fi

    # Список усіх чанків
    local chunks=()
    local f
    for f in "$chunk_dir"/chunk_*; do
        [[ "$f" == *.awk ]] && continue
        chunks+=("$f")
    done

    local total=${#chunks[@]}
    echo "[*] Parallel: ${nproc_cmd} cores, ${total} chunks (~${lines_per_chunk} lines)" >&2

    # Прогрес-бар
    print_progress() {
        local done=$1
        local total=$2
        local width=28
        local percent=0
        [ "$total" -gt 0 ] && percent=$(( done * 100 / total ))
        local filled=$(( done * width / total ))
        local bar=""
        local i
        for i in $(seq 1 $filled); do bar="${bar}#"; done
        for i in $(seq 1 $((width - filled))); do bar="${bar}-"; done
        printf "\r[*] [%s] %3d%% (%d/%d) " "$bar" "$percent" "$done" "$total" >&2
    }

    local next=0
    local running=0
    local finished=0
    local pids=""

    # Головний цикл
    while [ $finished -lt $total ]; do

        # Запускаємо нові задачі, поки є вільні слоти
        while [ $running -lt "$nproc_cmd" ] && [ $next -lt $total ]; do
            local chunk="${chunks[$next]}"
            next=$((next + 1))

            (
                awk -f "$awk_script_file" "$chunk" > "${chunk}.out"
                rm -f "$chunk"
            ) &
            # Зберігаємо PID просто рядком
            pids="$pids $!"
            running=$((running + 1))
        done

        # Перевіряємо, хто вже закінчив
        local new_pids=""
        local pid
        for pid in $pids; do
            if kill -0 "$pid" 2>/dev/null; then
                new_pids="$new_pids $pid"
            else
                wait "$pid" 2>/dev/null
                running=$((running - 1))
                finished=$((finished + 1))
                print_progress "$finished" "$total"
            fi
        done
        pids="$new_pids"

        # Якщо ніхто не закінчив — трохи чекаємо
        if [ $running -ge "$nproc_cmd" ] || [ $next -ge $total ]; then
            sleep 0.2
        fi
    done

    printf "\n[*] All chunks finished, merging...\n" >&2

    cat $(find "$chunk_dir" -name 'chunk_*.out' | sort) > "$outfile" 2>/dev/null
    echo "[*] Done." >&2

    return 0
}

compile_signatures() {
    local sig_input="$1"
    local out_dir="$2"
    local compiled_flag="$sig_input/.compiled"

    # Якщо бази вже скомпільовані і не було примусового оновлення (-u) — пропускаємо
    if [ "$DO_UPDATE" != true ] && [ -f "$compiled_flag" ] && [ "$compiled_flag" -nt "$sig_input" ]; then
        echo -e "[*] Signatures are already compiled and up to date."
        return 0
    fi

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
        # Збираємо суворо ТЕКСТОВІ бази сигнатур, ігноруючи .git, yara, custom та бінарні файли
        while IFS= read -r -d '' sf; do
            sig_files+=("$sf")
        done < <(find "$sig_input" -type f \
            -not -path '*/.git/*' \
            -not -path '*/yara/*' \
            -not -path '*/custom/*' \
            -not -name "*.pack" -not -name "*.idx" -not -name "*.cvd" \
            -not -name "*.yarc" -not -name "*.compiled" \
            -print0 2>/dev/null)
    else
        sig_files+=("$sig_input")
    fi

    # Advanced parser (виклики awk виконуються тільки на валідних текстових базах)
    if [ ${#sig_files[@]} -gt 0 ]; then
        # 1. Створюємо один об'єднаний список файлів для обробки
        local tmp_inputlist="$out_dir/sig_files.tmp"
        printf "%s\n" "${sig_files[@]}" > "$tmp_inputlist"

        # 2. Скрипт awk (код той самий, але пише в стандартний вивід STDOUT з префіксом типу)
        local awk_script='
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
                    print "SHA256\t" tolower(a[2]) "\tCustom.SHA256"
                    next
                }
                if (line ~ /^str:/) {
                    print "STR\t" substr(line, 5)
                    next
                }
                if (line ~ /^b64sig:/) {
                    print "B64\t" substr(line, 8) "\tCustom.B64"
                    next
                }
                # ClamAV / Maldet hashes
                if (line ~ /^[0-9a-fA-F]{32,64}:[0-9*]+:/) {
                    split(line, a, ":")
                    h = tolower(a[1]); name = a[3]
                    if (length(h) == 64) print "SHA256\t" h "\t" name
                    else if (length(h) == 32) print "MD5\t" h "\t" name
                    next
                }
                # Hex signatures
                if (line ~ /:[0-9]+:[0-9*a-fA-F>=-]*:/ || line ~ /:[0-9a-fA-F?*{}|()]{10,}$/) {
                    n = split(line, a, ":")
                    if (length(a[n]) >= 8) {
                        ere = hex2ere(a[n])
                        if (ere != "") print "HEX\t" ere
                    }
                    next
                }
            }
        '

        # 3. Об'єднуємо вміст усіх файлів баз і проганяємо через паралельний awk
        local tmp_raw_sigs="$out_dir/raw_compiled.tmp"
        
        # Об'єднуємо файли в один потік і паралелимо його
        cat "${sig_files[@]}" > "$out_dir/merged_sigs.tmp"
        run_awk_parallel "$out_dir/merged_sigs.tmp" "$tmp_raw_sigs" "$awk_script"

        # 4. Розкладаємо оброблений потік по відповідних файлах (.tsv / .txt)
        awk -F'\t' -v out="$out_dir" '
            $1 == "SHA256" { print $2 "\t" $3 >> (out "/sha256.tsv") }
            $1 == "MD5"    { print $2 "\t" $3 >> (out "/md5.tsv") }
            $1 == "STR"    { print $2 >> (out "/strings.txt") }
            $1 == "B64"    { print $2 "\t" $3 >> (out "/b64_payloads.tsv") }
            $1 == "HEX"    { print $2 >> (out "/hex_ere.txt") }
        ' "$tmp_raw_sigs"

        # Прибирання тимчасових файлів
        rm -f "$out_dir/merged_sigs.tmp" "$tmp_raw_sigs" "$tmp_inputlist"
    fi

    # External hash lists
    find "$sig_input" -not -path '*/.git/*' \( -name "*.sha256" -o -name "malwarebazaar.sha256" \) 2>/dev/null | while read -r f; do
        [ -s "$f" ] && awk '{print $1 "\t" ($2 ? $2 : "External.Hash")}' "$f" >> "$out_dir/sha256.tsv"
    done

    # YARA
    mkdir -p "$out_dir/yara"
    if [ -d "$sig_input/yara" ]; then
        if [ -f "$sig_input/yara/rules.yarc" ]; then
            cp "$sig_input/yara/rules.yarc" "$out_dir/yara/" 2>/dev/null || true
        fi
        if [ -f "$sig_input/yara/index.yar" ]; then
            cp "$sig_input/yara/index.yar" "$out_dir/yara/" 2>/dev/null || true
        fi
        find "$sig_input/yara" -not -path '*/.git/*' \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | head -200 | while read -r yf; do
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

    # Dedup (Виключено hex_ere.txt з sort -u, щоб не навантажувати CPU марним сортуванням Regex)
    for f in sha256.tsv md5.tsv strings.txt b64_payloads.tsv; do
        [ -s "$out_dir/$f" ] && sort -u "$out_dir/$f" -o "$out_dir/$f" 2>/dev/null || true
    done

    # Ставимо прапорець успішної компіляції
    touch "$compiled_flag" 2>/dev/null || true

    echo -e "  SHA256 : ${C}$(wc -l < "$out_dir/sha256.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  MD5    : ${C}$(wc -l < "$out_dir/md5.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  HexERE : ${C}$(wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  Strings: ${C}$(wc -l < "$out_dir/strings.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  YARA   : ${C}$(find "$out_dir/yara" -name "*.ya*" 2>/dev/null | wc -l | tr -d ' ')${Z}"
    echo ""
}


# ============================================================================
# 10. MODULE: workdir & worker extraction
# ============================================================================
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

init_workdir() {
    WORK_DIR=$(choose_work_dir "$USE_RAM" "$WORKERS")
    WORKER_FILE="$WORK_DIR/worker.sh"
    SIG_DIR="$WORK_DIR/sigs"
    mkdir -p "$WORK_DIR/reports" "$SIG_DIR"
}

extract_worker() {
    local inside=false
    while IFS= read -r ln; do
        [ "$ln" = "#__WORKER_START__" ] && { inside=true; continue; }
        [ "$ln" = "#__WORKER_END__" ] && break
        $inside && printf '%s\n' "$ln"
    done < "$0" > "$WORKER_FILE"
    chmod +x "$WORKER_FILE"
}

# ============================================================================
# 11. MODULE: dependency check
# ============================================================================
check_deps() {
    local miss=()
    for cmd in bash find awk grep od dd cut tr wc; do
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [ ${#miss[@]} -gt 0 ] && { echo -e "${R}[FAIL] Missing: ${miss[*]}${Z}"; exit 1; }
}

# ============================================================================
# 12. MODULE: file collection & worker orchestration
# ============================================================================
print_banner() {
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
    if [ "$QUARANTINE_ENABLED" = true ]; then
        echo -e " Quarantine   : ${C}ON -> ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
    else
        echo -e " Quarantine   : off"
    fi
    if [ "$REALTIME_MODE" = true ]; then
        echo -e " Real-time    : ${C}ON${Z} (стартує після базового скану)"
    fi
    echo -e "${B}=================================================${Z}"
}

collect_files() {
    echo -e "[*] Collecting file tree..."
    local excl=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")
    if [ "$OS" = "linux" ] && find "$SCRIPT_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
        find "$ROOT_DIR" -type f "${excl[@]}" -printf "%s\t%m\t%p\n" 2>/dev/null > "$WORK_DIR/all_files.tsv"
    else
        find "$ROOT_DIR" -type f "${excl[@]}" -print 2>/dev/null > "$WORK_DIR/all_files.tsv"
    fi
    TOTAL_FILES=$(wc -l < "$WORK_DIR/all_files.tsv" | tr -d ' ')
    echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z}\n"
}

split_pools() {
    awk -v w="$WORKERS" -v d="$WORK_DIR/reports" '{ print > (d "/pool_" (NR % w) ".txt") }' "$WORK_DIR/all_files.tsv"
}

launch_workers() {
    echo -e "[*] Launching ${WORKERS} workers (batch hash + YARA)...\n"
    WORKER_PIDS=()
    local pool wid qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"
    for pool in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$pool" ] || continue
        wid=$(basename "$pool" .txt)
        bash "$WORKER_FILE" \
            "$pool" "$wid" "$WORK_DIR/reports" \
            "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
            "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
            "$qdir" "$QUARANTINE_PERM" &
        WORKER_PIDS+=($!)
    done
}

wait_for_workers() {
    local pid
    for pid in "${WORKER_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    kill "$MONITOR_PID" 2>/dev/null || true
    tput cnorm 2>/dev/null || true
}

# ============================================================================
# 13. MODULE: progress monitor / cleanup
# ============================================================================
show_progress() {
    local prev=0 prev_ms="$START_MS"
    tput civis 2>/dev/null || true
    printf '\n\n\n\n\n'
    while true; do
        local now elapsed_ms elapsed_s
        now=$(now_ms)
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

start_monitor() {
    show_progress &
    MONITOR_PID=$!
}

cleanup() {
    kill "$MONITOR_PID" 2>/dev/null || true
    local p
    for p in "${WORKER_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    cleanup_realtime
    tput cnorm 2>/dev/null || true
    rm -rf "$WORK_DIR"
    echo -e "\n${Y}[WARN] Scan aborted${Z}"
    exit 130
}

# ============================================================================
# 14. MODULE: reporting
# ============================================================================
build_report() {
    ELAPSED_S=$(( (END_MS - START_MS) / 1000 ))
    TF=0; TT=0
    local r f t
    for r in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$r" ] || continue
        f=$(grep "^FILES_SCANNED:" "$r" 2>/dev/null | cut -d: -f2)
        t=$(grep "^THREATS_FOUND:" "$r" 2>/dev/null | cut -d: -f2)
        TF=$(( TF + ${f:-0} )); TT=$(( TT + ${t:-0} ))
    done
    SPEED=0; [ "$ELAPSED_S" -gt 0 ] && SPEED=$(( TF / ELAPSED_S ))

    QC=0
    [ "$QUARANTINE_ENABLED" = true ] && QC=$(count_quarantined)
    local quarantine_line=""
    [ "$QUARANTINE_ENABLED" = true ] && quarantine_line="
 Quarantined        : $QC ($QUARANTINE_DIR)"

    RPT="
=================================================
 SCAN RESULTS  (Oprhus Unified v${VERSION})
=================================================
 OS / Arch          : $OS / $ARCH
 Target             : $ROOT_DIR
 Files Scanned      : $TF
 Threats Found      : $TT${quarantine_line}
 Time Elapsed       : $(printf '%02d:%02d' $(( ELAPSED_S/60 )) $(( ELAPSED_S%60 )))
 Avg Speed          : ${SPEED} files/s
 Workers            : $WORKERS
================================================="
}

print_report() {
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
}

save_report() {
    [ -n "$OUTPUT_FILE" ] || return 0
    {
        echo "$RPT"
        [ "$TT" -gt 0 ] && {
            echo -e "\n=== DETECTED THREATS ==="
            grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d: -f2- | sort -u
        }
    } > "$OUTPUT_FILE"
    echo -e "\n[*] Report saved: ${C}${OUTPUT_FILE}${Z}"
}

# ============================================================================
# 15. MODULE: real-time watch (фоновий демон)
#
#     Ідея: замість дублювання логіки сканування, запускаємо ОДИН екземпляр
#     того ж самого воркера (той самий файл WORKER_FILE, ті ж функції
#     хешування/YARA/евристик/карантину), але замість статичного pool-файлу
#     він читає шляхи з іменованого каналу (FIFO). "while read ... done < FIFO"
#     у воркері автоматично блокується й чекає нових рядків — тобто воркер
#     сам по собі вже є "нескінченним" процесом реального часу, нічого
#     додатково писати в ньому не треба.
#
#     Головний скрипт лише постачає шляхи до нових файлів у FIFO:
#       - якщо є inotifywait -> миттєво, по подіях файлової системи
#       - інакше -> періодичний polling (find + порівняння з попереднім
#         знімком) кожні WATCH_INTERVAL секунд
# ============================================================================
start_realtime_worker() {
    REALTIME_FIFO="$WORK_DIR/realtime.fifo"
    mkfifo "$REALTIME_FIFO" 2>/dev/null || {
        echo -e "${R}[FAIL] Не вдалося створити FIFO для real-time режиму${Z}"
        return 1
    }

    local qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"

    REALTIME_REPORT="$WORK_DIR/reports/rt.txt"
    : > "$REALTIME_REPORT"

    # Воркер відкриє FIFO на читання і забльокується всередині свого звичного
    # run_scan_loop(), очікуючи нові рядки-шляхи.
    bash "$WORKER_FILE" \
        "$REALTIME_FIFO" "rt" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
        "$qdir" "$QUARANTINE_PERM" &
    REALTIME_WORKER_PID=$!

    # Тримаємо дескриптор на запис відкритим постійно (fd 3). Якщо відкривати
    # FIFO на запис окремо для кожного нового файлу, кожен виклик блокуватиме
    # до появи читача і зашумлятиме логіку — набагато простіше й надійніше
    # тримати один довгоживучий канал запису.
    exec 3> "$REALTIME_FIFO"
}

feed_realtime_path() {
    local path="$1"
    [ -f "$path" ] || return 0
    printf '%s\n' "$path" >&3 2>/dev/null || true
}

# Виводить нові THREAT-рядки з живого звіту воркера прямо в консоль
tail_realtime_report() {
    tail -n0 -F "$REALTIME_REPORT" 2>/dev/null | while IFS= read -r line; do
        case "$line" in
            THREAT:*)
                echo -e "${R}${B}[RT-THREAT]${Z} ${line#THREAT:}"
                ;;
        esac
    done &
    REALTIME_TAIL_PID=$!
}

watch_inotify() {
    echo -e "${C}[*] Real-time: використовую inotifywait (миттєва реакція)${Z}"
    inotifywait -m -r -e create -e moved_to -e close_write \
        --format '%w%f' "$ROOT_DIR" 2>/dev/null | while IFS= read -r path; do
        feed_realtime_path "$path"
    done
}

watch_poll() {
    echo -e "${Y}[WARN] inotifywait не знайдено -> fallback на polling кожні ${WATCH_INTERVAL}с (встанови пакет inotify-tools для миттєвої реакції)${Z}"
    local known="$WORK_DIR/rt_known.tsv" cur="$WORK_DIR/rt_current.tsv"
    find "$ROOT_DIR" -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null \
        | sort > "$known"
    while true; do
        sleep "$WATCH_INTERVAL"
        find "$ROOT_DIR" -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null \
            | sort > "$cur"
        comm -13 "$known" "$cur" | while IFS= read -r newpath; do
            [ -n "$newpath" ] && feed_realtime_path "$newpath"
        done
        mv -f "$cur" "$known"
    done
}

cleanup_realtime() {
    exec 3>&- 2>/dev/null || true
    [ -n "$REALTIME_WORKER_PID" ] && kill "$REALTIME_WORKER_PID" 2>/dev/null || true
    [ -n "$REALTIME_TAIL_PID" ] && kill "$REALTIME_TAIL_PID" 2>/dev/null || true
    [ -n "$REALTIME_FIFO" ] && rm -f "$REALTIME_FIFO" 2>/dev/null || true
}

run_realtime_watch() {
    echo -e "\n${B}=================================================${Z}"
    echo -e "${B} REAL-TIME MODE${Z} — базовий скан завершено, слідкую за ${C}${ROOT_DIR}${Z}"
    echo -e " Ctrl+C щоб зупинити"
    echo -e "${B}=================================================${Z}\n"

    start_realtime_worker || return 1
    tail_realtime_report

    if command -v inotifywait &>/dev/null; then
        watch_inotify
    else
        watch_poll
    fi
}

# ============================================================================
# 16. main() — єдина точка входу; жорстко фіксує порядок ініціалізації, тож
#     жоден модуль ніколи не викликається раніше, ніж заповнені потрібні йому
#     глобальні змінні.
# ============================================================================
main() {
    detect_platform
    parse_args "$@"
    setup_colors

    [ "$DO_UPDATE" = true ] && update_signatures "$SIGNATURES" "$MB_KEY"

    YARA_CMD=$(detect_yara)
    init_workers

    SHA256_CMD=$(detect_sha256)
    MD5_CMD=$(detect_md5)

    init_workdir
    check_deps
    detect_tools "$ALLOW_BUSYBOX"
    init_quarantine

    extract_worker
    compile_signatures "$SIGNATURES" "$SIG_DIR"

    START_MS=$(now_ms)
    print_banner

    collect_files
    split_pools
    launch_workers

    start_monitor
    trap cleanup INT TERM

    wait_for_workers

    END_MS=$(now_ms)
    build_report
    print_report
    save_report

    # Real-time watch стартує ПІСЛЯ базового скану (той самий trap cleanup
    # вже активний і покриє й цю фазу — Ctrl+C/SIGTERM коректно зупинить
    # і воркер-демон, і FIFO).
    if [ "$REALTIME_MODE" = true ]; then
        run_realtime_watch
    fi

    rm -rf "$WORK_DIR"
    exit 0
}

main "$@"

# =============================================================================
# 17. EMBEDDED WORKER (self-contained, теж модульний)
# =============================================================================
#__WORKER_START__
#!/bin/bash
set -uo pipefail
export LC_ALL=C

# ----------------------------------------------------------------------------
# GLOBALS — усі змінні воркера визначені один раз тут, ДО функцій, що їх
# використовують.
# ----------------------------------------------------------------------------
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
QUARANTINE_DIR="${12:-}"      # порожньо = карантин вимкнено
QUARANTINE_PERM="${13:-0400}"

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

declare -a BATCH_SHA=()
declare -a BATCH_MD5=()
declare -a BATCH_YARA=()
SHA_BATCH_CNT=0
MD5_BATCH_CNT=0
YARA_BATCH_CNT=0

# ----------------------------------------------------------------------------
# MODULE: init
# ----------------------------------------------------------------------------
init_worker_state() {
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
}

# ----------------------------------------------------------------------------
# MODULE: low-level helpers (stat / hash / decode / strings / file-type)
# ----------------------------------------------------------------------------
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

# ----------------------------------------------------------------------------
# MODULE: logging
# ----------------------------------------------------------------------------
log() { printf '[%s] %s\n' "$WORKER_ID" "$*" >> "$REPORT"; }

# threat() — єдина точка входу для будь-якої знахідки: логує Й (за потреби)
# одразу відправляє файл у карантин. Раніше виклики виглядали як
# threat "TYPE|$file|info=..." (один рядок), що не давало явного доступу до
# шляху файлу для подальших дій. Тепер сигнатура threat(type, file, info) —
# формат рядка в звіті лишився ідентичним ("TYPE|file|info"), тож парсер
# у головному скрипті (build_report/print_report) не зламався.
threat() {
    local type="$1" file="$2" info="${3:-}"
    printf 'THREAT:%s|%s|%s\n' "$type" "$file" "$info" >> "$REPORT"
    THREATS_FOUND=$(( THREATS_FOUND + 1 ))
    [ -n "$QUARANTINE_DIR" ] && quarantine_file "$file" "$type"
}

progress() {
    printf 'FILES=%d\nTHREATS=%d\nCURRENT=%s\n' \
        "$FILES_SCANNED" "$THREATS_FOUND" "${1:-}" > "$PROGRESS"
}

# ----------------------------------------------------------------------------
# MODULE: quarantine
# ----------------------------------------------------------------------------
quarantine_file() {
    local src="$1" type="${2:-UNKNOWN}"
    [ -n "$QUARANTINE_DIR" ] || return 0
    [ -f "$src" ] || return 0

    mkdir -p "$QUARANTINE_DIR" 2>/dev/null

    # Ім'я в карантині = sha256(оригінальний_шлях) + оригінальна назва файлу.
    # Це унікально ідентифікує файл (навіть якщо однакові імена лежали в
    # різних директоріях) без потреби відтворювати всю оригінальну структуру
    # директорій всередині карантину.
    local path_hash qfile ts
    ts=$(date +%s)
    path_hash=$(printf '%s' "$src" | sha256sum 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
    [ -z "$path_hash" ] && path_hash="$(date +%s%N)_$$"
    qfile="${QUARANTINE_DIR}/${path_hash}_$(basename -- "$src")"

    if mv -f -- "$src" "$qfile" 2>/dev/null; then
        chmod "$QUARANTINE_PERM" "$qfile" 2>/dev/null
        # Маніфест для відновлення: оригінальний_шлях <TAB> файл_в_карантині
        # <TAB> тип_загрози <TAB> unix-час. Відновлення — це просто
        # `mv "$qfile" "$src"` за даними з цього рядка.
        printf '%s\t%s\t%s\t%s\n' "$src" "$qfile" "$type" "$ts" >> "${QUARANTINE_DIR}/manifest.tsv"
        log "QUARANTINED: $src -> $qfile ($type)"
    else
        log "QUARANTINE_FAILED (mv error): $src ($type)"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: hash matching
# ----------------------------------------------------------------------------
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

    # ФІКС: "grep -F -f - sig_file" повертає ПОВНІ рядки бази (hash<TAB>name),
    # а не самі хеші. Без завершального "cut -f1" наступний grep "^$hit_hash"
    # порівнював рядок з рядком і ніколи нічого не знаходив — виявлення
    # відомого малваре за хешем не працювало. Тепер hits містить чисті хеші.
    local hits
    hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | grep -F -f - "$sig_file" 2>/dev/null | cut -f1)
    if [ -n "$hits" ]; then
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            local tname
            tname=$(grep -F -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -d$'\t' -f2)
            local hit_file
            hit_file=$(printf '%s\n' "$out" | grep -iE "^${hit_hash}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
            [ -n "$hit_file" ] && threat "KNOWN_MALWARE" "$hit_file" "name=${tname:-Malware}|$htype=$hit_hash"
        done <<< "$hits"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: yara matching
# ----------------------------------------------------------------------------
process_yara_batch() {
    [ $# -eq 0 ] || [ "$HAS_YARA" = false ] || [ "$YARA_CMD" = "none" ] && return
    local yara_out
    yara_out=$($YARA_CMD "$YARA_TARGET" "$@" 2>/dev/null)
    if [ -n "$yara_out" ]; then
        while IFS= read -r yline; do
            [ -z "$yline" ] && continue
            local yrule; yrule=$(echo "$yline" | awk '{print $1}')
            local yfile; yfile=$(echo "$yline" | cut -d' ' -f2-)
            threat "YARA_MATCH" "$yfile" "rule=$yrule"
        done <<< "$yara_out"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: heuristics
# ----------------------------------------------------------------------------
check_file_heuristics() {
    local file="$1" size="$2" oct="$3"

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # Strings
        if [ "$HAS_STRINGS" = true ]; then
            local str_match
            str_match=$(do_strings "$file" 6 524288 | grep -F -i -f "$SIG_DIR/strings.txt" 2>/dev/null | head -1)
            if [ -n "$str_match" ]; then
                threat "SIG_STRING_MATCH" "$file" "pattern=${str_match:0:50}"
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
                    threat "HEX_SIG_MATCH" "$file" "hex=${hex_match:0:40}..."
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
                    threat "KNOWN_B64_PAYLOAD" "$file" "name=${bname:-B64.Malware}|b64=${chunk:0:20}..."
                    continue
                fi
            fi
            local magic
            magic=$(printf '%s' "$chunk" | _b64decode 2>/dev/null | dd bs=8 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
            case "$magic" in
                7f454c46*) threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=ELF|b64=${chunk:0:20}..." ;;
                4d5a*)     threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=PE_MZ|b64=${chunk:0:20}..." ;;
                2321*)     threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=SCRIPT|b64=${chunk:0:20}..." ;;
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
                ELF|PE_MZ|SCRIPT) threat "DISGUISED_FILE" "$file" "ext=.$ext|real=$real_type" ;;
            esac
            ;;
    esac

    # Permissions
    # ФІКС: stat/find зазвичай повертають 3-значний октальний режим ("644"),
    # без setuid/setgid-біта. "${oct: -4}" на рядку коротшому за 4 символи
    # в bash повертає ПОРОЖНІЙ рядок (від'ємний офсет виходить за межі), тому
    # 8#$oct ставав "8#" -> "invalid integer constant", і перевірка
    # SUID/SGID/world-writable мовчки ламалась на кожному файлі. Тепер
    # спочатку доповнюємо нулями зліва до 4 символів, і лише потім беремо
    # останні 4.
    if [ -n "$oct" ] && [ "$oct" != "0" ]; then
        oct="0000${oct}"
        oct="${oct: -4}"
        (( 8#$oct & 8#6000 )) 2>/dev/null && threat "SUID_SGID" "$file" "perms=$oct"
        (( 8#$oct & 8#0002 )) 2>/dev/null && (( 8#$oct & 8#0111 )) 2>/dev/null && threat "WORLD_WRITABLE_EXEC" "$file" "perms=$oct"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: scan loop
# ФІКС: увесь цикл тепер живе всередині функції run_scan_loop(), а не на
# верхньому рівні файлу. Раніше "local file size oct" стояло поза функцією,
# що в bash — помилка ("local: can only be used in a function") на кожній
# ітерації. Тепер local-змінні коректні й справді ізольовані від глобального
# простору імен.
# ----------------------------------------------------------------------------
run_scan_loop() {
    local col1 col2 col3 file size oct magic_type skip_deep ext

    while IFS=$'\t' read -r col1 col2 col3; do
        file=""; size=""; oct=""
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
            magic_type=$(_bash_file_type "$file")
            skip_deep=false
            case "$magic_type" in
                JPEG|PNG|GIF) skip_deep=true ;;
            esac

            # Disguised override
            ext="${file##*.}"
            case "${ext,,}" in
                jpg|jpeg|png|gif)
                    if [ "$magic_type" = "ELF" ] || [ "$magic_type" = "PE_MZ" ]; then
                        threat "DISGUISED_FILE" "$file" "ext=.$ext|real=$magic_type"
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

    # Flush залишків батчів
    [ "$SHA_BATCH_CNT" -gt 0 ] && process_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
    [ "$MD5_BATCH_CNT" -gt 0 ] && process_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
    [ "$YARA_BATCH_CNT" -gt 0 ] && process_yara_batch "${BATCH_YARA[@]}"
}

# ----------------------------------------------------------------------------
# MODULE: finalize
# ----------------------------------------------------------------------------
finalize_worker() {
    progress "done"
    printf 'FILES_SCANNED:%d\nTHREATS_FOUND:%d\n' "$FILES_SCANNED" "$THREATS_FOUND" >> "$REPORT"
    log "Completed - files: $FILES_SCANNED, threats: $THREATS_FOUND"
    touch "${REPORT_DIR}/${WORKER_ID}.done"
}

# ----------------------------------------------------------------------------
# main() воркера
# ----------------------------------------------------------------------------
main() {
    log "Worker started PID=$$ OS=$OS yara=$YARA_CMD"
    progress "init"
    init_worker_state
    run_scan_loop
    finalize_worker
}

main "$@"
#__WORKER_END__
