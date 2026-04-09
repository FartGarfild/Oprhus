#!/bin/bash
# =============================================================================
#  Parallel AV Scanner v4
#  Self-contained однофайловий сканер з автоматичним визначенням утиліт.
#
#  Пріоритети для strings і file:
#    1. Системна утиліта     — якщо є в PATH
#    2. ./bin/busybox         — статичний бінарник поруч зі скриптом
#    3. Завантажений busybox  — пропонується якщо немає системної і є мережа
#    4. bash-реалізація       — fallback якщо зовсім нічого немає
#
#  Обов'язкові залежності: bash 4+, find, awk, grep, od, dd, cut, tr, wc
#  Бажані (sha256):        sha256sum | shasum | openssl
#  Опціональні:            strings, file, busybox, curl | wget
#
#  Використання:
#    ./av_scan.sh [OPTIONS]
#
#  Параметри:
#    -j, --workers   N     Кількість паралельних воркерів (default: CPU count)
#    -d, --dir       PATH  Директорія для сканування (default: /home)
#    -s, --sigs      FILE  Файл з сигнатурами (default: поруч зі скриптом)
#                          Формати рядків у файлі сигнатур:
#                            sha256:<hex64>      SHA256 хеш файлу у hex
#                            sha256b64:<base64>  SHA256 хеш у base64
#                            b64sig:<base64>     Підозрілий base64 payload
#                            str:<pattern>       Рядковий патерн (grep -F)
#    -m, --max-size  MB    Макс. розмір файлу для глибокої перевірки (default: 10)
#    -o, --output    FILE  Зберегти звіт у файл (default: тільки stdout)
#    --no-ram              Писати tmp у /tmp замість /dev/shm
#    --no-busybox          Не пропонувати busybox, одразу bash-fallback
#    -h, --help            Показати цю довідку
#
#  Структура директорії (опціонально):
#    av_scan.sh
#    signatures.sha256
#    bin/
#    └── busybox        ← статичний busybox, завантажується автоматично
#
#  Приклади:
#    ./av_scan.sh -j 8 -d /var/www -s ./sigs.sha256 -o report.txt
#    ./av_scan.sh -d / --no-busybox
# =============================================================================

set -uo pipefail
VERSION="4.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── ОС і архітектура ──────────────────────────────────────────────────────────
case "$(uname -s 2>/dev/null)" in
    Darwin) OS="macos" ;;
    *)      OS="linux" ;;
esac

ARCH="$(uname -m 2>/dev/null)"
case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64"  ;;
    armv7*)        ARCH="armv7"  ;;
    *)             ARCH="x86_64" ;;
esac

# ── CPU count ─────────────────────────────────────────────────────────────────
cpu_count() {
    command -v nproc  &>/dev/null && { nproc; return; }
    command -v sysctl &>/dev/null && { sysctl -n hw.logicalcpu 2>/dev/null; return; }
    grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4
}

# ── Stat (Linux -c / macOS -f) ────────────────────────────────────────────────
stat_size() {
    if [ "$OS" = "macos" ]; then stat -f '%z' "$1" 2>/dev/null
    else                         stat -c '%s' "$1" 2>/dev/null; fi
}

# ── SHA256 ────────────────────────────────────────────────────────────────────
detect_sha256() {
    if   command -v sha256sum &>/dev/null; then echo "sha256sum"
    elif command -v shasum    &>/dev/null; then echo "shasum -a 256"
    elif command -v openssl   &>/dev/null; then echo "openssl dgst -sha256"
    else                                        echo "none"; fi
}

# ── Tmpdir ────────────────────────────────────────────────────────────────────
choose_work_dir() {
    local use_ram="$1" workers="$2"
    if [ "$use_ram" = true ] && [ "$OS" = "linux" ] && [ -d "/dev/shm" ]; then
        local needed=$(( workers * 10 + 50 ))
        local avail
        avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        [ "${avail:-0}" -ge "$needed" ] && { echo "/dev/shm/av_scan_$$"; return; }
    fi
    echo "${TMPDIR:-/tmp}/av_scan_$$"
}

# =============================================================================
#  ВИЗНАЧЕННЯ УТИЛІТ: strings і file
#
#  Результат зберігається у змінних:
#    STRINGS_CMD — "strings" | "<path>/busybox strings" | "bash"
#    FILE_CMD    — "file"    | "<path>/busybox file"    | "bash"
#    BUSYBOX_BIN — шлях до busybox або ""
# =============================================================================

BUSYBOX_BIN=""
STRINGS_CMD="bash"
FILE_CMD="bash"

# ── Перевірка мережі ──────────────────────────────────────────────────────────
check_network() {
    if command -v curl &>/dev/null; then
        curl -sf --connect-timeout 3 "https://busybox.net" > /dev/null 2>&1
    elif command -v wget &>/dev/null; then
        wget -q --timeout=3 --spider "https://busybox.net" 2>/dev/null
    else
        return 1
    fi
}

# ── URL busybox для поточної архітектури ──────────────────────────────────────
busybox_url() {
    # busybox.net надає готові статичні Linux-бінарники
    # macOS не підтримується busybox.net — повертаємо порожній рядок
    case "${OS}_${ARCH}" in
        linux_x86_64) echo "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" ;;
        linux_arm64)  echo "https://busybox.net/downloads/binaries/1.35.0-aarch64-linux-musl/busybox" ;;
        linux_armv7)  echo "https://busybox.net/downloads/binaries/1.35.0-armv7l-linux-musleabihf/busybox" ;;
        *)            echo "" ;;
    esac
}

# ── Завантаження busybox ──────────────────────────────────────────────────────
download_busybox() {
    local url="$1"
    local dest="$SCRIPT_DIR/bin/busybox"
    mkdir -p "$SCRIPT_DIR/bin"

    echo -e "${C}[*] Завантажуємо busybox (~1MB)...${Z}"

    local ok=false
    if command -v curl &>/dev/null; then
        curl -fL --progress-bar -o "$dest" "$url" 2>&1 && ok=true
    elif command -v wget &>/dev/null; then
        wget -q --show-progress -O "$dest" "$url" 2>&1 && ok=true
    fi

    if $ok && [ -s "$dest" ]; then
        chmod +x "$dest"
        # Перевіряємо що завантажений файл дійсно busybox
        if "$dest" strings --help &>/dev/null 2>&1; then
            echo -e "${G}[✓] busybox збережено: $dest${Z}"
            BUSYBOX_BIN="$dest"
            return 0
        fi
    fi

    rm -f "$dest" 2>/dev/null
    echo -e "${R}[!] Не вдалося завантажити або перевірити busybox${Z}"
    return 1
}

# ── Пропозиція завантажити busybox ───────────────────────────────────────────
# Викликається якщо утиліта відсутня і дозволено завантаження.
# Повертає 0 якщо busybox тепер доступний, 1 — якщо ні.
offer_busybox() {
    local util="$1"        # "strings" або "file" — для повідомлення
    local allow="$2"       # true/false

    [ "$allow" = "false" ] && return 1

    # busybox.net не підтримує macOS
    [ "$OS" = "macos" ] && return 1

    local url; url=$(busybox_url)
    [ -z "$url" ] && return 1

    # Якщо busybox вже є (завантажений для іншої утиліти) — просто використовуємо
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        echo -e "${G}[✓] '${util}' — використовуємо вже завантажений busybox${Z}"
        return 0
    fi

    echo -e "${Y}[!] Утиліта '${util}' не знайдена${Z}"

    if ! check_network; then
        echo -e "${Y}[!] Мережа недоступна — буде bash-fallback${Z}"
        return 1
    fi

    echo -e "${C}    Завантажити busybox (~1MB) для покращеного сканування?${Z}"
    printf "    [Y/n]: "

    local ans
    # timeout: якщо не відповів за 15с — вважаємо "n"
    if read -r -t 15 ans 2>/dev/null; then
        ans="${ans,,}"
    else
        echo ""  # перенос рядка після timeout
        ans="n"
    fi

    case "$ans" in
        ""|y|yes|т|так)
            download_busybox "$url"
            return $?
            ;;
        *)
            echo -e "${Y}[!] Пропущено — буде bash-fallback${Z}"
            return 1
            ;;
    esac
}

# ── Перевіряємо локальний busybox у bin/ ──────────────────────────────────────
find_local_busybox() {
    local candidate="$SCRIPT_DIR/bin/busybox"
    if [ -x "$candidate" ] && "$candidate" strings --help &>/dev/null 2>&1; then
        BUSYBOX_BIN="$candidate"
        return 0
    fi
    return 1
}

# ── Головна функція визначення інструментів ───────────────────────────────────
detect_tools() {
    local allow_busybox="$1"

    echo -e "[*] Визначаємо доступні утиліти..."

    # Шукаємо локальний busybox заздалегідь — щоб не питати двічі
    if find_local_busybox; then
        echo -e "${G}[✓] Знайдено локальний busybox: $BUSYBOX_BIN${Z}"
    fi

    # ── strings ──────────────────────────────────────────────────────────────
    if command -v strings &>/dev/null; then
        STRINGS_CMD="strings"
        echo -e "${G}[✓] strings : системна утиліта${Z}"

    elif [ -n "$BUSYBOX_BIN" ]; then
        STRINGS_CMD="$BUSYBOX_BIN strings"
        echo -e "${G}[✓] strings : $BUSYBOX_BIN strings${Z}"

    elif offer_busybox "strings" "$allow_busybox" && [ -n "$BUSYBOX_BIN" ]; then
        STRINGS_CMD="$BUSYBOX_BIN strings"
        echo -e "${G}[✓] strings : $BUSYBOX_BIN strings${Z}"

    else
        STRINGS_CMD="bash"
        echo -e "${Y}[~] strings : bash-fallback (od+awk, повільніше)${Z}"
    fi

    # ── file ─────────────────────────────────────────────────────────────────
    if command -v file &>/dev/null; then
        FILE_CMD="file"
        echo -e "${G}[✓] file    : системна утиліта${Z}"

    elif [ -n "$BUSYBOX_BIN" ]; then
        FILE_CMD="$BUSYBOX_BIN file"
        echo -e "${G}[✓] file    : $BUSYBOX_BIN file${Z}"

    elif offer_busybox "file" "$allow_busybox" && [ -n "$BUSYBOX_BIN" ]; then
        FILE_CMD="$BUSYBOX_BIN file"
        echo -e "${G}[✓] file    : $BUSYBOX_BIN file${Z}"

    else
        FILE_CMD="bash"
        echo -e "${Y}[~] file    : bash magic bytes (завжди працює)${Z}"
    fi

    echo ""
}

# ── Дефолти ───────────────────────────────────────────────────────────────────
WORKERS=$(cpu_count)
ROOT_DIR="/home"
SIGNATURES="$SCRIPT_DIR/signatures.sha256"
MAX_SCAN_MB=10
OUTPUT_FILE=""
USE_RAM=true
ALLOW_BUSYBOX=true

# ── Аргументи ─────────────────────────────────────────────────────────────────
usage() { grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -j|--workers)    WORKERS="$2";       shift 2 ;;
        -d|--dir)        ROOT_DIR="$2";      shift 2 ;;
        -s|--sigs)       SIGNATURES="$2";    shift 2 ;;
        -m|--max-size)   MAX_SCAN_MB="$2";   shift 2 ;;
        -o|--output)     OUTPUT_FILE="$2";   shift 2 ;;
        --no-ram)        USE_RAM=false;      shift   ;;
        --no-busybox)    ALLOW_BUSYBOX=false;shift   ;;
        -h|--help)       usage ;;
        *) echo "Невідомий параметр: $1"; exit 1 ;;
    esac
done

SHA256_CMD=$(detect_sha256)
WORK_DIR=$(choose_work_dir "$USE_RAM" "$WORKERS")
WORKER_FILE="$WORK_DIR/worker.sh"
mkdir -p "$WORK_DIR/reports"

# ── Кольори ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    R='\033[0;31m' Y='\033[1;33m' G='\033[0;32m'
    C='\033[0;36m' B='\033[1m'   Z='\033[0m'
else
    R='' Y='' G='' C='' B='' Z=''
fi

# ── Мінімальні залежності ─────────────────────────────────────────────────────
check_deps() {
    local miss=()
    for cmd in bash find awk grep od dd cut tr wc; do
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [ ${#miss[@]} -gt 0 ] && {
        echo -e "${R}[!] Відсутні обов'язкові утиліти: ${miss[*]}${Z}"; exit 1
    }
    [ "$SHA256_CMD" = "none" ] && \
        echo -e "${Y}[!] sha256sum/shasum/openssl не знайдено — хеш-перевірка вимкнена${Z}"
}
check_deps

# ── Визначаємо strings і file ─────────────────────────────────────────────────
detect_tools "$ALLOW_BUSYBOX"

# ── Розпаковуємо вбудований worker ───────────────────────────────────────────
extract_worker() {
    local inside=false
    while IFS= read -r ln; do
        [ "$ln" = "#__WORKER_START__" ] && { inside=true;  continue; }
        [ "$ln" = "#__WORKER_END__"   ] && break
        $inside && printf '%s\n' "$ln"
    done < "$0" > "$WORKER_FILE"
    chmod +x "$WORKER_FILE"
}
extract_worker

START_MS=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))

# ── Заголовок ─────────────────────────────────────────────────────────────────
echo -e "${B}=================================================${Z}"
echo -e "${B}  Parallel AV Scanner v${VERSION}${Z}  [OS: $OS | ARCH: $ARCH]"
echo -e "  Воркерів   : ${C}${WORKERS}${Z}"
echo -e "  Директорія : ${C}${ROOT_DIR}${Z}"
echo -e "  Сигнатури  : ${C}${SIGNATURES}${Z}"
echo -e "  Макс. файл : ${C}${MAX_SCAN_MB}MB${Z}"
echo -e "  SHA256     : ${C}${SHA256_CMD}${Z}"
echo -e "  strings    : ${C}${STRINGS_CMD}${Z}"
echo -e "  file       : ${C}${FILE_CMD}${Z}"
echo -e "  Tmp        : ${C}${WORK_DIR}${Z}"
echo -e "${B}=================================================${Z}"

# ── Збираємо директорії ───────────────────────────────────────────────────────
echo -e "[*] Збираємо дерево директорій..."
EXCL=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")
find "$ROOT_DIR" -type d "${EXCL[@]}" 2>/dev/null > "$WORK_DIR/all_dirs.txt"
TOTAL_DIRS=$(wc -l < "$WORK_DIR/all_dirs.txt" | tr -d ' ')
echo -e "[*] Директорій: ${C}${TOTAL_DIRS}${Z}"

# ETA: рахуємо загальну кількість файлів у фоні
find "$ROOT_DIR" -type f "${EXCL[@]}" 2>/dev/null | wc -l | tr -d ' ' \
    > "$WORK_DIR/total_files.txt" &
ESTIMATE_PID=$!

# ── Round-robin розподіл ──────────────────────────────────────────────────────
awk -v w="$WORKERS" -v d="$WORK_DIR/reports" \
    '{ print > d"/pool_" (NR % w) ".txt" }' "$WORK_DIR/all_dirs.txt"

# ── Запускаємо воркери ────────────────────────────────────────────────────────
# STRINGS_CMD і FILE_CMD передаються як аргументи — воркер не знає про busybox
echo -e "[*] Запускаємо ${WORKERS} воркерів...\n"
WORKER_PIDS=()
for pool in "$WORK_DIR/reports"/pool_*.txt; do
    wid=$(basename "$pool" .txt)
    bash "$WORKER_FILE" \
        "$pool" "$wid" "$WORK_DIR/reports" \
        "$SIGNATURES" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$STRINGS_CMD" "$FILE_CMD" &
    WORKER_PIDS+=($!)
done

# ── Progress monitor ──────────────────────────────────────────────────────────
show_progress() {
    local prev=0 prev_ms="$START_MS"
    tput civis 2>/dev/null || true
    printf '\n\n\n\n\n'

    while true; do
        local now elapsed_ms elapsed_s
        now=$(date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 )))
        elapsed_ms=$(( now - START_MS ))
        elapsed_s=$(( elapsed_ms / 1000 ))

        local tf=0 tt=0
        for f in "$WORK_DIR/reports"/pool_*.progress; do
            [ -f "$f" ] || continue
            local fv tv
            fv=$(grep "^FILES="   "$f" 2>/dev/null | cut -d= -f2)
            tv=$(grep "^THREATS=" "$f" 2>/dev/null | cut -d= -f2)
            tf=$(( tf + ${fv:-0} )); tt=$(( tt + ${tv:-0} ))
        done

        local dt=$(( now - prev_ms )) fps=0 avg=0
        [ "$dt" -gt 0 ] && fps=$(( (tf - prev) * 1000 / dt ))
        [ "$fps" -lt 0 ] && fps=0
        [ "$elapsed_s" -gt 0 ] && avg=$(( tf / elapsed_s ))
        prev=$tf; prev_ms=$now

        local eta="--:--"
        if [ -f "$WORK_DIR/total_files.txt" ]; then
            local tot; tot=$(cat "$WORK_DIR/total_files.txt" 2>/dev/null)
            [ "${avg:-0}" -gt 0 ] && [ "${tot:-0}" -gt "$tf" ] && {
                local r=$(( (tot - tf) / avg ))
                eta=$(printf '%02d:%02d' $(( r/60 )) $(( r%60 )))
            }
        fi

        local active=0
        for pid in "${WORKER_PIDS[@]}"; do
            kill -0 "$pid" 2>/dev/null && active=$(( active + 1 ))
        done

        local efmt; efmt=$(printf '%02d:%02d' $(( elapsed_s/60 )) $(( elapsed_s%60 )))
        local tc="$G"; [ "$tt" -gt 0 ] && tc="$R"

        printf '\033[5A'
        printf '\033[K'"${B}⏱  Час       :${Z} %s\n"                                "$efmt"
        printf '\033[K'"${B}📁 Файлів    :${Z} %-8d  ${tc}${B}🚨 Загроз: %d${Z}\n" "$tf" "$tt"
        printf '\033[K'"${B}⚡ Зараз     :${Z} %-6d файл/с\n"                       "$fps"
        printf '\033[K'"${B}📊 Середня   :${Z} %-6d файл/с\n"                       "$avg"
        printf '\033[K'"${B}ETA          :${Z} %-8s  ${C}Воркерів: %d/%d${Z}\n"    "$eta" "$active" "$WORKERS"
        sleep 1
    done
}
show_progress &
MONITOR_PID=$!

# ── Cleanup при Ctrl+C ────────────────────────────────────────────────────────
cleanup() {
    kill "$MONITOR_PID" 2>/dev/null || true
    for p in "${WORKER_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    tput cnorm 2>/dev/null || true
    rm -rf "$WORK_DIR"
    echo -e "\n${Y}[!] Перервано${Z}"; exit 130
}
trap cleanup INT TERM

# ── Чекаємо ───────────────────────────────────────────────────────────────────
for pid in "${WORKER_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
kill "$MONITOR_PID" 2>/dev/null || true
wait "$ESTIMATE_PID" 2>/dev/null || true
tput cnorm 2>/dev/null || true

# ── Фінальний звіт ────────────────────────────────────────────────────────────
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
 РЕЗУЛЬТАТ СКАНУВАННЯ
=================================================
 ОС / Архітектура      : $OS / $ARCH
 Директорія            : $ROOT_DIR
 Директорій оброблено  : $TOTAL_DIRS
 Файлів перевірено     : $TF
 Загроз знайдено       : $TT
 Загальний час         : $(printf '%02d:%02d' $(( ELAPSED_S/60 )) $(( ELAPSED_S%60 )))
 Середня швидкість     : ${SPEED} файл/с
 Воркерів              : $WORKERS
 strings               : $STRINGS_CMD
 file                  : $FILE_CMD
================================================="

echo -e "\n"
if [ "$TT" -gt 0 ]; then
    echo -e "${R}${RPT}${Z}"
    echo -e "\n${R}${B}=== ЗНАЙДЕНІ ЗАГРОЗИ ===${Z}"
    grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null \
        | cut -d: -f2- | sort -u \
        | while IFS='|' read -r type file info; do
            echo -e "  ${R}✗${Z} [${Y}${type}${Z}] ${file} ${C}${info:-}${Z}"
          done
else
    echo -e "${G}${RPT}${Z}"
    echo -e "\n  ${G}✓ Загроз не знайдено${Z}"
fi

[ -n "$OUTPUT_FILE" ] && {
    { echo "$RPT"
      [ "$TT" -gt 0 ] && {
          echo -e "\n=== ЗНАЙДЕНІ ЗАГРОЗИ ==="
          grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null \
              | cut -d: -f2- | sort -u
      }
    } > "$OUTPUT_FILE"
    echo -e "\n[*] Звіт: ${C}${OUTPUT_FILE}${Z}"
}

rm -rf "$WORK_DIR"
exit 0

# =============================================================================
#  ВБУДОВАНИЙ WORKER
#  Розпаковується extract_worker() між маркерами у тимчасовий файл.
#  Аргументи 8 і 9 (STRINGS_CMD, FILE_CMD) передаються master'ом —
#  воркер не знає нічого про busybox, системні утиліти чи bash-fallback.
# =============================================================================
#__WORKER_START__
#!/bin/bash
set -uo pipefail

POOL_FILE="${1:?}"
WORKER_ID="${2:?}"
REPORT_DIR="${3:?}"
SIGNATURES="${4:-}"
MAX_SCAN_MB="${5:-10}"
OS="${6:-linux}"
SHA256_CMD="${7:-none}"
STRINGS_CMD="${8:-bash}"   # "strings" | "/path/busybox strings" | "bash"
FILE_CMD="${9:-bash}"      # "file"    | "/path/busybox file"    | "bash"

REPORT="$REPORT_DIR/${WORKER_ID}.txt"
PROGRESS="$REPORT_DIR/${WORKER_ID}.progress"
FILES_SCANNED=0
THREATS_FOUND=0
MAX_SIZE=$(( MAX_SCAN_MB * 1024 * 1024 ))

# ── Портативний stat ──────────────────────────────────────────────────────────
_stat_size() {
    if [ "$OS" = "macos" ]; then stat -f '%z' "$1" 2>/dev/null
    else                         stat -c '%s' "$1" 2>/dev/null; fi
}
_stat_mtime() {
    if [ "$OS" = "macos" ]; then stat -f '%m' "$1" 2>/dev/null
    else                         stat -c '%Y' "$1" 2>/dev/null; fi
}
_stat_mode() {
    if [ "$OS" = "macos" ]; then
        local m; m=$(stat -f '%Op' "$1" 2>/dev/null) && printf '%s' "${m: -4}"
    else
        stat -c '%a' "$1" 2>/dev/null
    fi
}

# ── SHA256 ────────────────────────────────────────────────────────────────────
_sha256_file() {
    [ "$SHA256_CMD" = "none" ] && return
    $SHA256_CMD "$1" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1
}
_sha256_stdin() {
    [ "$SHA256_CMD" = "none" ] && { cat > /dev/null; echo ""; return; }
    $SHA256_CMD 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1
}

# ── Base64 ───────────────────────────────────────────────────────────────────
_b64decode() {
    if [ "$OS" = "macos" ]; then base64 -D 2>/dev/null
    else                         base64 -d 2>/dev/null; fi
}

# =============================================================================
#  BASH-FALLBACK: strings
#
#  Використовується тільки якщо STRINGS_CMD="bash".
#  od дампить байти у hex, awk з h2d() збирає друковані ASCII послідовності.
#  h2d() — портативна hex→decimal без strtonum (є лише у gawk).
# =============================================================================
_bash_strings() {
    local file="$1" min_len="${2:-6}" max_bytes="${3:-524288}"
    dd if="$file" bs="$max_bytes" count=1 2>/dev/null \
    | od -An -tx1 -v \
    | tr -s ' ' '\n' \
    | grep -v '^\s*$' \
    | awk -v min="$min_len" '
        function h2d(h,   v,i,c) {
            v=0; h=tolower(h)
            for(i=1;i<=length(h);i++){
                c=substr(h,i,1)
                v=v*16+(c~/[0-9]/?c+0:index("abcdef",c)+9)
            }
            return v
        }
        {
            b = h2d($0)
            if (b >= 32 && b <= 126) {
                buf = buf sprintf("%c", b)
            } else {
                if (length(buf) >= min) print buf
                buf = ""
            }
        }
        END { if (length(buf) >= min) print buf }
    '
}

# =============================================================================
#  BASH-FALLBACK: file (magic bytes)
#
#  Використовується тільки якщо FILE_CMD="bash".
#  Читає перші 8 байт через dd+od, порівнює з таблицею magic bytes.
#  Повертає: ELF | PE_MZ | PDF | ZIP | PNG | JPEG | GIF |
#            GZIP | BZIP2 | 7ZIP | SCRIPT | UNKNOWN | EMPTY
# =============================================================================
_bash_file_type() {
    local file="$1"
    local magic
    magic=$(dd if="$file" bs=8 count=1 2>/dev/null \
            | od -An -tx1 -v | tr -d ' \n')
    [ -z "$magic" ] && { echo "EMPTY"; return; }
    case "$magic" in
        7f454c46*)     echo "ELF"    ;;  # Linux/Unix binary
        4d5a*)         echo "PE_MZ"  ;;  # Windows .exe/.dll (MZ header)
        25504446*)     echo "PDF"    ;;  # %PDF
        504b0304*)     echo "ZIP"    ;;  # ZIP / DOCX / XLSX / JAR
        89504e470d0a*) echo "PNG"    ;;
        ffd8ff*)       echo "JPEG"   ;;
        47494638*)     echo "GIF"    ;;  # GIF87a або GIF89a
        1f8b*)         echo "GZIP"   ;;
        425a68*)       echo "BZIP2"  ;;
        377abcaf*)     echo "7ZIP"   ;;
        2321*)         echo "SCRIPT" ;;  # #! shebang
        *)             echo "UNKNOWN" ;;
    esac
}

# =============================================================================
#  АДАПТЕРИ: do_strings і do_file_type
#
#  Воркер завжди викликає ці дві функції.
#  Вони прозоро перемикаються між нативною утилітою і bash-fallback
#  залежно від STRINGS_CMD / FILE_CMD переданих master'ом.
# =============================================================================
do_strings() {
    local file="$1" min="${2:-6}" maxb="${3:-524288}"
    if [ "$STRINGS_CMD" = "bash" ]; then
        _bash_strings "$file" "$min" "$maxb"
    else
        # Нативний strings або busybox strings (-n задає мінімальну довжину)
        dd if="$file" bs="$maxb" count=1 2>/dev/null \
            | $STRINGS_CMD -n "$min" 2>/dev/null
    fi
}

do_file_type() {
    local file="$1"
    if [ "$FILE_CMD" = "bash" ]; then
        _bash_file_type "$file"
    else
        # Нативний file або busybox file — нормалізуємо вивід до наших типів
        local out
        out=$($FILE_CMD -b "$file" 2>/dev/null | head -1)
        case "$out" in
            ELF*)                                        echo "ELF"    ;;
            PE32*|MS-DOS*|MZ*)                           echo "PE_MZ"  ;;
            PDF*)                                        echo "PDF"    ;;
            Zip*|Java*archive*)                          echo "ZIP"    ;;
            PNG*)                                        echo "PNG"    ;;
            JPEG*)                                       echo "JPEG"   ;;
            GIF*)                                        echo "GIF"    ;;
            gzip*)                                       echo "GZIP"   ;;
            bzip2*)                                      echo "BZIP2"  ;;
            *7-zip*)                                     echo "7ZIP"   ;;
            *shell*script*|*Python*|*Perl*|*Ruby*|*PHP*) echo "SCRIPT" ;;
            *)                                           echo "UNKNOWN" ;;
        esac
    fi
}

# ── Завантажуємо сигнатури ────────────────────────────────────────────────────
declare -A SIG_HEX
declare -A SIG_B64PAY
SIG_STRINGS=()

if [ -s "$SIGNATURES" ]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        case "$line" in
            sha256:*)
                SIG_HEX["${line#sha256:}"]=1
                ;;
            sha256b64:*)
                local b64="${line#sha256b64:}"
                local hex
                hex=$(printf '%s' "$b64" | _b64decode \
                      | od -An -tx1 -v | tr -d ' \n' 2>/dev/null)
                [ -n "$hex" ] && SIG_HEX["$hex"]=1
                ;;
            b64sig:*)
                local payload="${line#b64sig:}"
                local dh
                dh=$(printf '%s' "$payload" | _b64decode | _sha256_stdin)
                [ -n "$dh" ] && SIG_B64PAY["$dh"]="$payload"
                ;;
            str:*)
                SIG_STRINGS+=("${line#str:}")
                ;;
        esac
    done < "$SIGNATURES"
fi

SIG_HEX_CNT=${#SIG_HEX[@]}
SIG_B64_CNT=${#SIG_B64PAY[@]}
SIG_STR_CNT=${#SIG_STRINGS[@]}

# ── Хелпери ───────────────────────────────────────────────────────────────────
log()    { printf '[%s] %s\n' "$WORKER_ID" "$*" >> "$REPORT"; }
threat() { printf 'THREAT:%s\n' "$*" >> "$REPORT"; THREATS_FOUND=$(( THREATS_FOUND + 1 )); }
progress() {
    printf 'FILES=%d\nTHREATS=%d\nCURRENT=%s\n' \
        "$FILES_SCANNED" "$THREATS_FOUND" "${1:-}" > "$PROGRESS"
}

# ── Перевірка файлу ───────────────────────────────────────────────────────────
check_file() {
    local file="$1"
    FILES_SCANNED=$(( FILES_SCANNED + 1 ))

    local size; size=$(_stat_size "$file") || return

    # 1. SHA256 хеш vs база ───────────────────────────────────────────────────
    if [ "$SIG_HEX_CNT" -gt 0 ] && [ "$SHA256_CMD" != "none" ] \
       && [ "$size" -lt "$MAX_SIZE" ]; then
        local hash; hash=$(_sha256_file "$file")
        [ -n "${SIG_HEX[${hash,,}]+_}" ] && {
            threat "KNOWN_MALWARE|$file|sha256=$hash"
            return
        }
    fi

    if [ "$size" -gt 0 ] && [ "$size" -lt "$MAX_SIZE" ]; then

        # 2. Підозрілі рядки — do_strings (нативний або bash) ────────────────
        local sus
        sus=$(do_strings "$file" 6 524288 \
              | grep -iE \
                'eval\(base64_decode|/bin/sh -i|bash -i >|nc -e /bin|wget .+\|.+sh|curl .+\|.+sh|python.*import.*socket.*exec|chmod [0-9]*7 |rm -rf /' \
              | head -3)
        [ -n "$sus" ] && \
            threat "SUSPICIOUS_STRINGS|$file|$(printf '%s' "$sus" | head -1 | cut -c1-80)"

        # 3. Base64 payload всередині файлу ──────────────────────────────────
        grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$file" 2>/dev/null \
        | head -20 \
        | while IFS= read -r chunk; do
            # 3a. Хеш декодованого проти бази b64sig
            if [ "$SIG_B64_CNT" -gt 0 ] && [ "$SHA256_CMD" != "none" ]; then
                local dh; dh=$(printf '%s' "$chunk" | _b64decode | _sha256_stdin)
                [ -n "${SIG_B64PAY[$dh]+_}" ] && {
                    printf 'THREAT:KNOWN_B64_PAYLOAD|%s|b64=%s...\n' \
                        "$file" "${chunk:0:20}" >> "$REPORT"
                    THREATS_FOUND=$(( THREATS_FOUND + 1 ))
                    continue
                }
            fi
            # 3b. Magic bytes декодованого через do_file_type
            local tmp_f="/tmp/av_b64_${WORKER_ID}_$$"
            printf '%s' "$chunk" | _b64decode > "$tmp_f" 2>/dev/null
            if [ -s "$tmp_f" ]; then
                local dtype; dtype=$(do_file_type "$tmp_f")
                case "$dtype" in
                    ELF|PE_MZ|SCRIPT)
                        printf 'THREAT:SUSPICIOUS_B64_PAYLOAD|%s|decoded=%s|b64=%s...\n' \
                            "$file" "$dtype" "${chunk:0:20}" >> "$REPORT"
                        THREATS_FOUND=$(( THREATS_FOUND + 1 ))
                        ;;
                esac
            fi
            rm -f "$tmp_f" 2>/dev/null
        done

        # 4. Рядкові патерни з бази сигнатур ─────────────────────────────────
        if [ "$SIG_STR_CNT" -gt 0 ]; then
            local pat
            for pat in "${SIG_STRINGS[@]}"; do
                grep -qF "$pat" "$file" 2>/dev/null && {
                    threat "SIG_STRING_MATCH|$file|pattern=${pat:0:50}"
                    break
                }
            done
        fi
    fi

    # 5. Замаскований тип файлу — do_file_type ────────────────────────────────
    local ext real_type
    ext="${file##*.}"; ext="${ext,,}"
    case "$ext" in
        jpg|jpeg|png|gif|bmp|webp|pdf|doc|docx|xls|xlsx)
            real_type=$(do_file_type "$file")
            case "$real_type" in
                ELF|PE_MZ|SCRIPT)
                    threat "DISGUISED_FILE|$file|ext=.$ext|real=$real_type"
                    ;;
            esac
            ;;
    esac

    # 6. SUID / SGID і world-writable exec ────────────────────────────────────
    local oct; oct=$(_stat_mode "$file")
    if [ -n "$oct" ]; then
        oct="${oct: -4}"
        (( 8#$oct & 8#6000 )) 2>/dev/null && threat "SUID_SGID|$file|perms=$oct"
        (( 8#$oct & 8#0002 )) && (( 8#$oct & 8#0111 )) 2>/dev/null && \
            threat "WORLD_WRITABLE_EXEC|$file|perms=$oct"
    fi

    [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
}

# ── Перевірка директорії ──────────────────────────────────────────────────────
check_dir() {
    local dir="$1"
    case "$dir" in
        /bin|/sbin|/usr/bin|/usr/sbin|/etc|/lib|/lib64|/usr/lib*)
            local dm rm
            dm=$(_stat_mtime "$dir"); rm=$(_stat_mtime "${TMPDIR:-/tmp}")
            [ -n "$dm" ] && [ -n "$rm" ] && [ "$dm" -gt "$rm" ] && \
                threat "MODIFIED_SYSTEM_DIR|$dir"
            ;;
    esac
    local bn; bn=$(basename "$dir")
    [[ "$bn" == .* ]] && [[ "$dir" != /home/* ]] \
    && [[ "$dir" != /root* ]] && [[ "$dir" != /Users/* ]] \
    && log "HIDDEN_DIR|$dir"
}

# ── Головний цикл ─────────────────────────────────────────────────────────────
log "Старт PID=$$ OS=$OS strings='$STRINGS_CMD' file='$FILE_CMD' sha256=$SHA256_CMD"
log "Сигнатур: hex=$SIG_HEX_CNT b64=$SIG_B64_CNT str=$SIG_STR_CNT"
progress "init"

while IFS= read -r dir; do
    [ -d "$dir" ] && [ -r "$dir" ] || continue
    check_dir "$dir"
    while IFS= read -r -d '' file; do
        [ -f "$file" ] && [ -r "$file" ] || continue
        check_file "$file"
    done < <(find "$dir" -maxdepth 1 -type f -print0 2>/dev/null)
done < "$POOL_FILE"

progress "done"
printf 'FILES_SCANNED:%d\nTHREATS_FOUND:%d\n' \
    "$FILES_SCANNED" "$THREATS_FOUND" >> "$REPORT"
log "Завершено — файлів: $FILES_SCANNED, загроз: $THREATS_FOUND"
touch "${REPORT_DIR}/${WORKER_ID}.done"
#__WORKER_END__
