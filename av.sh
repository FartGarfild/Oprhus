#!/bin/bash
# =============================================================================
# Oprhus AV Scanner Unified v6.4 (modular + quarantine + real-time + busybox-first)
# Features:
#   - Built-in signature updater (Maldet, ClamAV, YARA, MalwareBazaar, custom)
#   - Parallel workers with batch hashing (SHA256 + MD5) and YARA batching
#   - Zero-RAM lookup + strict RAM ceiling
#   - Live RAM / CPU / ETA / FPS progress monitor
#   - Full heuristics: strings, hex-ERE, b64 payloads, disguised files, SUID/SGID
#   - Magic-bytes fast filter
#   - Quarantine mode: moves detected files to an isolated directory
#   - Real-time watch mode: background daemon, scans new files as they appear
#   - Pure self-contained single file
#
# BusyBox-first: looks for a local busybox (./bin/busybox); if missing, tries
# to auto-download a static binary (no prompts). Once available, all key ops
# (hashing, strings, find/grep/awk in the signature pipeline) go through it
# instead of $PATH. System tools are only a fallback. Exception: the first
# download itself needs system wget/curl (nothing else to fetch busybox with).
#
# Usage:
#   ./av_scan.sh [OPTIONS]
#
# Options:
#   -u, --update            Update signatures and EXIT (no auto-scan after)
#   -r, --max-ram MB        Max RAM limit in megabytes (default: 500)
#   -j, --workers N         Number of parallel worker processes (default: auto)
#   -d, --dir PATH          Target directory to scan (default: /mnt)
#   -s, --sigs PATH         Signature directory (default: ./signatures)
#   -m, --max-size MB       Max file size for deep inspection in MB (default: 10)
#   -o, --output FILE       Report file. Written to LIVE as threats are
#                            found (not just at the end) — if the scan gets
#                            interrupted, whatever's in this file up to
#                            that point is still valid. Without -o, a
#                            default ./av_scan_threats_<timestamp>.log is
#                            used automatically (never silently discarded).
#   --no-ram                Force /tmp instead of /dev/shm
#   --no-busybox            Fully disable busybox (no auto-download, no local
#                            binary use) — system tools only
#   -b, --busybox PATH      Explicit path to an existing busybox binary
#   --mb-key KEY            MalwareBazaar Auth-Key (optional)
#   -q, --quarantine        Enable quarantine mode (default dir: ./quarantine)
#   --quarantine-dir PATH   Enable quarantine mode with a custom directory
#   --quarantine-perm MODE  chmod mode for quarantined files (default: 0400,
#                            i.e. read-only, not executable)
#   -w, --real-time         After the base scan, switch to background watch
#                            mode: new files get scanned automatically
#                            (inotifywait, or polling as fallback)
#   --watch-interval SEC    Polling interval for the fallback watcher (default: 5)
#   --max-hex-patterns N    Cap on compiled hex signature patterns (default:
#                            8000) — grep -E -f cannot build a usable match
#                            automaton from a full real ClamAV .ndb+.ldb set
#                            (100k+ patterns); raising this trades scan
#                            speed for hex-signature coverage
#   --batch-size N            Files per hash/YARA batch (default: 50).
#                            Smaller = smoother progress (threats show up
#                            more incrementally instead of jumping when a
#                            big batch finishes), at some throughput cost.
#   --heur-batch-size N       Files per strings/hex heuristic batch (default: 50)
#   --pe-batch-size N         Files per PE-section/.mdb batch (default: 50)
#   --setup                  Install yara/yarac into bin/ (and fetch busybox
#                            if missing), then exit. Prefers --yara-url if
#                            given; otherwise compiles from source (needs a
#                            C toolchain — auto-installed via whichever of
#                            apt/dnf/yum/zypper/pacman/apk is present).
#   --yara-url URL            Install yara/yarac from a prebuilt tarball at
#                            this URL instead of compiling — no compiler
#                            needed on the target machine. YARA publishes no
#                            official prebuilt binaries, so this is meant to
#                            point at your OWN mirror: build once with
#                            --setup --compile on one machine, host the
#                            resulting bin/{yara,yarac} as a .tar.gz
#                            somewhere reachable, then every other machine
#                            just downloads it (same idea as busybox, just
#                            self-hosted since no upstream exists for yara)
#   --busybox-url URL         Override the busybox download URL (internal
#                            mirror), same idea as --yara-url
#   --setup --compile         Force compiling from source even if
#                            --yara-url is also given
#   --setup --force           Reinstall/rebuild even if bin/yara already exists
#   --check-deps             Print bundled/system/missing status for
#                            busybox and yara/yarac, then exit
#   -h, --help               Show this help (also runs --check-deps)
#
# File layout:
#   1. GLOBALS         — all script variables, defined once here
#   2. MODULE: platform / cpu
#   3. MODULE: busybox bootstrap (find / auto-download / bb wrapper)
#   4. MODULE: hash & yara & strings/file detection (busybox-first)
#   5. MODULE: CLI (usage, parse_args, colors)
#   6. MODULE: worker sizing / RAM guard
#   7. MODULE: quarantine (main-script side init)
#   8. MODULE: signature updater
#   9. MODULE: signature compiler (+ parallel awk pool)
#  10. MODULE: workdir & worker extraction
#  11. MODULE: dependency check
#  12. MODULE: file collection & worker orchestration
#  13. MODULE: progress monitor / cleanup
#  14. MODULE: reporting
#  15. MODULE: real-time watch (background daemon)
#  16. main()          — single entry point, calls modules in order
#  17. EMBEDDED WORKER  — separate self-contained script (also modular;
#                          does the scanning and the actual quarantine)
#
# Package layout (for building a distributable archive):
#   Paths below are relative to SCRIPT_DIR (where av_scan.sh lives). Only
#   av_scan.sh itself is required; everything else is either bundled or
#   auto-created on first run.
#
#   av_scan/
#   ├── av_scan.sh              [REQUIRED]
#   ├── bin/
#   │   ├── busybox              [RECOMMENDED] static busybox binary
#   │   │                        (x86_64/arm64/armv7, linux-musl static build)
#   │   ├── yara                 [RECOMMENDED] built by `av_scan.sh --setup`
#   │   └── yarac                (not fetched automatically like busybox —
#   │                            YARA ships no ready static binaries, so
#   │                            --setup compiles them from source; needs
#   │                            a C toolchain + network once)
#   ├── signatures/              [OPTIONAL] signature DB; created by
#   │   ├── maldet/               update_signatures() on -u if missing, or
#   │   ├── clamav/                the scanner just runs on built-in
#   │   ├── hashes/                heuristics without it.
#   │   ├── yara/
#   │   ├── strings/
#   │   ├── custom/
#   │   │   ├── custom.sha256    [OPTIONAL] own hashes: "hash<TAB>name"
#   │   │   ├── custom.md5       [OPTIONAL] same for MD5
#   │   │   └── custom.strings   [OPTIONAL] own string signatures
#   │   ├── .cache/               [AUTO] persistent compiled cache
#   │   └── .compiled            [AUTO] compile flag, no need to ship
#   └── quarantine/              [AUTO, only with -q] auto-created
#       └── manifest.tsv           auto-created, no need to ship
#
#   Temp work dirs (/dev/shm/av_scan_$$ or $TMPDIR/av_scan_$$) are created
#   and removed by the script each run — not part of the package.
#
#   Minimal fully-offline archive: av_scan.sh + bin/{busybox,yara,yarac}
#   + signatures/ (pre-populated). Just av_scan.sh alone also works: run
#   `av_scan.sh --setup` once (needs network + a C toolchain) to build
#   yara/yarac locally, and busybox auto-downloads on first scan.
# =============================================================================
set -uo pipefail
export LC_ALL=C

# ============================================================================
# 1. GLOBALS — all script variables defined once here, before any code uses
#    them. init_*/detect_* functions and parse_args() fill in real values.
# ============================================================================
VERSION="6.4"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- CLI-configured params (defaults, overridable via parse_args) ---
SIGNATURES="${SCRIPT_DIR}/signatures"
ROOT_DIR="/mnt"
MAX_SCAN_MB=10
MAX_RAM_MB=500
OUTPUT_FILE=""
LIVE_REPORT_FILE=""    # persistent (outside WORK_DIR) file threats are
                        # appended to AS THEY'RE FOUND, so Ctrl+C/SIGTERM
                        # mid-scan doesn't lose already-detected results
DO_UPDATE=false
USE_RAM=true
ALLOW_BUSYBOX=true
MB_KEY=""
WORKERS=""            # empty = "auto", resolved in init_workers()
MAX_HEX_PATTERNS=8000 # cap on compiled hex_ere.txt entries, see compile_signatures
BATCH_SIZE=50          # files per hash/YARA batch — smaller = smoother
                        # progress updates (threats appear more incrementally
                        # instead of jumping when a big batch finishes), at
                        # some cost to throughput from more subprocess calls
HEUR_BATCH_SIZE=50     # files per strings/hex heuristic batch
PE_BATCH_SIZE=50       # files per PE-section (.mdb) batch
DO_SETUP=false         # --setup: build yara/yarac (and fetch busybox) then exit
SETUP_FORCE=false       # --setup --force: rebuild even if already present
SETUP_COMPILE_ONLY=false # --setup --compile: skip --yara-url, always compile
DO_CHECK_DEPS=false     # --check-deps: print dependency status and exit
YARA_URL_ARG=""         # --yara-url: fetch a prebuilt yara/yarac tarball
                        # instead of compiling from source (own mirror/CDN)
BUSYBOX_URL_ARG=""      # --busybox-url: override the busybox download URL

# --- Quarantine ---
QUARANTINE_ENABLED=false
QUARANTINE_DIR="${SCRIPT_DIR}/quarantine"
QUARANTINE_PERM="0400"   # read-only, not executable (NOT literal "100" —
                          # that means --x------, the opposite)

# --- Real-time watch (background daemon) ---
REALTIME_MODE=false
WATCH_INTERVAL=5
REALTIME_FIFO=""
REALTIME_WORKER_PID=""
REALTIME_REPORT=""
REALTIME_TAIL_PID=""

# --- Platform (filled by detect_platform) ---
OS=""
ARCH=""

# --- Toolchain (filled by init_toolchain / detect_sha256 / detect_md5 / detect_yara) ---
BUSYBOX_BIN=""        # path to busybox binary (empty = not found/disabled)
BUSYBOX_PATH_ARG=""   # explicit path from -b/--busybox, if given
BB_APPLETS=""         # cached applet list, space-padded on both ends
STRINGS_CMD="bash"
FILE_CMD="bash"
SHA256_CMD="none"
MD5_CMD="none"
YARA_CMD="none"
YARAC_BIN=""           # path to yarac (compile-time only; empty = not found

# --- Runtime work paths (filled by init_workdir) ---
WORK_DIR=""
WORKER_FILE=""
SIG_DIR=""

# --- Terminal colors (filled by setup_colors) ---
R=''; Y=''; G=''; C=''; B=''; Z=''

# --- Scan state ---
START_MS=0
END_MS=0
ELAPSED_S=0
TOTAL_FILES=0
WORKER_PIDS=()
MONITOR_PID=""
TF=0            # files scanned (total across workers)
TT=0            # threats found (total across workers)
QC=0            # quarantined (total across workers)
SPEED=0
RPT=""          # final report text

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
# 3. MODULE: busybox bootstrap (find / auto-download / bb wrapper)
# ============================================================================
net_fetch() {
    # Downloader chain: busybox wget -> system wget -> system curl.
    # Optional 4th arg is a User-Agent (e.g. for the ClamAV mirror).
    local url="$1" dest="$2" timeout="${3:-10}" ua="${4:-}"

    if [ -n "$BUSYBOX_BIN" ] && "$BUSYBOX_BIN" wget --help &>/dev/null 2>&1; then
        if [ -n "$ua" ]; then
            "$BUSYBOX_BIN" wget -q -T "$timeout" -U "$ua" -O "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        else
            "$BUSYBOX_BIN" wget -q -T "$timeout" -O "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        fi
    fi
    if command -v wget &>/dev/null; then
        if [ -n "$ua" ]; then
            wget -q --timeout="$timeout" -U "$ua" -O "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        else
            wget -q --timeout="$timeout" -O "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        fi
    fi
    if command -v curl &>/dev/null; then
        if [ -n "$ua" ]; then
            curl -fsSL -A "$ua" --connect-timeout "$timeout" -o "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        else
            curl -fsSL --connect-timeout "$timeout" -o "$dest" "$url" 2>/dev/null && [ -s "$dest" ] && return 0
        fi
    fi
    rm -f "$dest" 2>/dev/null
    return 1
}

check_network() {
    # Probes the actual URL that will be fetched (defaults to busybox.net)
    # rather than a fixed unrelated host — otherwise a working --busybox-url
    # mirror would still be reported as "no network" if busybox.net itself
    # happens to be unreachable from this machine.
    local target="${1:-https://busybox.net}"
    # On the first call, BUSYBOX_BIN is still empty, so this naturally
    # falls back to system wget/curl (same bootstrap exception as net_fetch).
    if [ -n "$BUSYBOX_BIN" ] && "$BUSYBOX_BIN" wget --help &>/dev/null 2>&1; then
        "$BUSYBOX_BIN" wget -q -T 3 -O /dev/null "$target" 2>/dev/null && return 0
    fi
    if command -v wget &>/dev/null; then
        wget -q --timeout=3 --spider "$target" 2>/dev/null && return 0
    fi
    if command -v curl &>/dev/null; then
        curl -sf --connect-timeout 3 "$target" >/dev/null 2>&1 && return 0
    fi
    return 1
}

busybox_url() {
    # Overridable via -b-url/BUSYBOX_URL_ARG for internal mirrors — useful
    # when target machines can't reach busybox.net directly.
    if [ -n "$BUSYBOX_URL_ARG" ]; then
        echo "$BUSYBOX_URL_ARG"
        return
    fi
    case "${OS}_${ARCH}" in
        linux_x86_64) echo "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" ;;
        linux_arm64)  echo "https://busybox.net/downloads/binaries/1.35.0-aarch64-linux-musl/busybox" ;;
        linux_armv7)  echo "https://busybox.net/downloads/binaries/1.35.0-armv7l-linux-musleabihf/busybox" ;;
        *) echo "" ;;
    esac
}

verify_busybox_binary() {
    # Sanity check: executable, and --help output looks like busybox.
    local c="$1"
    [ -x "$c" ] || return 1
    "$c" --help 2>&1 | head -1 | grep -qi "busybox" || return 1
    return 0
}

find_local_busybox() {
    # Priority: explicit -b/--busybox -> $SCRIPT_DIR/bin/busybox.
    local candidates=()
    [ -n "$BUSYBOX_PATH_ARG" ] && candidates+=("$BUSYBOX_PATH_ARG")
    candidates+=("$SCRIPT_DIR/bin/busybox")

    local c
    for c in "${candidates[@]}"; do
        if verify_busybox_binary "$c"; then
            BUSYBOX_BIN="$c"
            return 0
        fi
    done
    return 1
}

download_busybox() {
    local url="$1" dest="$SCRIPT_DIR/bin/busybox"
    mkdir -p "$SCRIPT_DIR/bin"
    echo -e "${C}[*] BusyBox not found locally -> auto-downloading (~1MB)...${Z}"
    if net_fetch "$url" "$dest" 15 && verify_busybox_binary "$dest" 2>/dev/null; then
        :
    else
        chmod +x "$dest" 2>/dev/null
        verify_busybox_binary "$dest" || { rm -f "$dest" 2>/dev/null; echo -e "${R}[FAIL] BusyBox download/verify failed${Z}"; return 1; }
    fi
    chmod +x "$dest" 2>/dev/null
    echo -e "${G}[OK] busybox saved: $dest${Z}"
    BUSYBOX_BIN="$dest"
    return 0
}

ensure_busybox() {
    # busybox ships together with the scanner, so find_local_busybox should
    # succeed on the first try. Anything past that (auto-download, system
    # fallback) means the package is damaged/incomplete, hence WARN/FAIL.
    [ "$ALLOW_BUSYBOX" = true ] || { echo -e "${Y}[INFO] BusyBox disabled (--no-busybox) -> system tools only${Z}"; return 1; }

    find_local_busybox && { echo -e "${G}[OK] Local busybox: $BUSYBOX_BIN${Z}"; return 0; }

    echo -e "${R}[WARN] Expected bundled busybox not found at ${SCRIPT_DIR}/bin/busybox${Z}"
    echo -e "${R}       This is unusual — check the package (file missing or corrupted).${Z}"

    if [ "$OS" = "macos" ]; then
        echo -e "${Y}[INFO] macOS: no official static busybox builds -> system tools${Z}"
        return 1
    fi

    local dl_url
    dl_url=$(busybox_url)
    if check_network "$dl_url"; then
        echo -e "${Y}[*] Trying emergency auto-download as a fallback...${Z}"
        download_busybox "$dl_url" && return 0
        echo -e "${R}[WARN] Emergency download also failed -> system tools (shell fallback)${Z}"
        return 1
    else
        echo -e "${R}[WARN] No network -> system tools (shell fallback), no busybox${Z}"
        return 1
    fi
}

busybox_has_applet() {
    case "$BB_APPLETS" in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

cache_busybox_applets() {
    [ -n "$BUSYBOX_BIN" ] || return 0
    local a
    BB_APPLETS=" "
    while IFS= read -r a; do
        [ -n "$a" ] && BB_APPLETS="${BB_APPLETS}${a} "
    done < <("$BUSYBOX_BIN" --list 2>/dev/null)
}

# bb <applet> [args...] — runs the applet via busybox if available/supported,
# else falls back to the system command of the same name.
bb() {
    local applet="$1"; shift
    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet "$applet"; then
        "$BUSYBOX_BIN" "$applet" "$@"
    else
        command "$applet" "$@"
    fi
}

# ============================================================================
# 4. MODULE: hash & yara & strings/file detection (busybox-first)
#    Priority: busybox applet -> system tool -> (for strings/file) our own
#    self-contained dd+od based detector.
# ============================================================================
detect_sha256() {
    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet sha256sum; then echo "$BUSYBOX_BIN sha256sum"
    elif command -v sha256sum &>/dev/null; then echo "sha256sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 256"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -sha256"
    else echo "none"; fi
}

detect_md5() {
    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet md5sum; then echo "$BUSYBOX_BIN md5sum"
    elif command -v md5sum &>/dev/null; then echo "md5sum"
    elif command -v md5 &>/dev/null; then echo "md5 -q"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -md5"
    else echo "none"; fi
}

detect_yara() {
    # YARA isn't part of busybox, but a bundled bin/yara (see --setup)
    # is preferred over a system install for the same reason as busybox:
    # a known, consistent binary rather than whatever's on $PATH. YARA now
    # also does the .ndb/.ldb hex-signature matching (see MODULE: ClamAV
    # format support) since grep -E -f cannot scale to that many patterns.
    if [ -x "$SCRIPT_DIR/bin/yara" ]; then
        echo "$SCRIPT_DIR/bin/yara"
    elif command -v yara &>/dev/null; then
        echo "yara"
    else
        echo "none"
    fi
}

detect_yarac() {
    if [ -x "$SCRIPT_DIR/bin/yarac" ]; then
        YARAC_BIN="$SCRIPT_DIR/bin/yarac"
    elif command -v yarac &>/dev/null; then
        YARAC_BIN="yarac"
    else
        YARAC_BIN=""
    fi
}

init_toolchain() {
    echo -e "[*] Initializing toolchain..."
    ensure_busybox
    cache_busybox_applets

    SHA256_CMD=$(detect_sha256)
    MD5_CMD=$(detect_md5)

    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet strings; then
        STRINGS_CMD="$BUSYBOX_BIN strings"; echo -e "${G}[OK] strings : busybox${Z}"
    elif command -v strings &>/dev/null; then
        STRINGS_CMD="strings"; echo -e "${Y}[OK] strings : system (fallback)${Z}"
    else
        STRINGS_CMD="bash"; echo -e "${Y}[WARN] strings : built-in bash detector${Z}"
    fi

    # "file" is not part of busybox; our own magic-bytes detector
    # (_bash_file_type, dd/od based) already covers what we need.
    FILE_CMD="bash"
    echo -e "${G}[OK] file    : built-in magic-bytes detector${Z}"

    echo -e " SHA256 : ${C}${SHA256_CMD}${Z}"
    echo -e " MD5    : ${C}${MD5_CMD}${Z}"
    if [ -n "$BUSYBOX_BIN" ]; then
        echo -e " BusyBox: ${G}${BUSYBOX_BIN}${Z}"
    else
        echo -e " BusyBox: ${Y}not in use (system-only mode)${Z}"
    fi
    echo ""
}

# ============================================================================
# 5. MODULE: CLI (usage, argument parsing, colors)
# ============================================================================
usage() {
    awk '/^# ====/{c++; next} c==1' "$0" | sed 's/^# \{0,2\}//'
    echo ""
    check_dependencies_report
    exit 0
}

# Prints a plain status report of optional-but-important components
# (busybox, yara/yarac) so the user immediately knows what will and won't
# work, without having to start a scan first. Run automatically by -h/--help
# and by --check-deps.
check_dependencies_report() {
    echo "Dependency check:"
    if [ -x "$SCRIPT_DIR/bin/busybox" ]; then
        echo "  [OK]   busybox : bundled at bin/busybox"
    elif command -v busybox &>/dev/null; then
        echo "  [WARN] busybox : not bundled, found on system PATH instead"
    else
        echo "  [MISS] busybox : not found — will try to auto-download on first run"
        echo "         (needs network); or run: $0 --setup"
    fi

    if [ -x "$SCRIPT_DIR/bin/yara" ] && [ -x "$SCRIPT_DIR/bin/yarac" ]; then
        echo "  [OK]   yara/yarac : bundled at bin/yara, bin/yarac"
    elif command -v yara &>/dev/null && command -v yarac &>/dev/null; then
        echo "  [WARN] yara/yarac : not bundled, found on system PATH instead"
    else
        echo "  [MISS] yara/yarac : not found — .ndb/.ldb ClamAV signatures and"
        echo "         YARA_MATCH detection will be unavailable, and the"
        echo "         hex/string fallback path is much slower at scale."
        echo "         Fix: run '$0 --setup' to build them automatically"
        echo "         (needs a C toolchain, or the ability to install one)."
    fi
    echo ""
}

# ============================================================================
# MODULE: self-setup (--setup)
#
# Two ways to get yara/yarac into $SCRIPT_DIR/bin/, tried in this order:
#
#   1. --yara-url URL — fetch a PREBUILT tarball (containing "yara" and
#      "yarac" binaries) from a URL you control. Unlike busybox, YARA
#      publishes no official prebuilt binaries, so there's no universal
#      default URL to hardcode here — but if you build once (this same
#      --setup does that) and host the resulting bin/{yara,yarac} tarball
#      on your own mirror/CDN/internal server, every other machine can
#      then install it with a plain download and NO compiler at all,
#      which is both faster and works identically across distros. This is
#      the "do it like busybox" path, just pointed at infrastructure you
#      host yourself instead of a project-run one that doesn't exist.
#
#   2. Compile from source (fallback, or always with --setup --compile).
#      Needs a C toolchain; installed automatically via whichever of
#      apt/dnf/yum/zypper/pacman/apk is present. Different distros name
#      packages differently, so each branch below lists its own package
#      names for the same underlying tools (gcc/make, autotools,
#      pkg-config, OpenSSL dev headers).
# ============================================================================
_install_build_toolchain() {
    local as_root="$1"
    if command -v apt-get &>/dev/null; then
        echo "[*] Installing build dependencies via apt..."
        $as_root apt-get update -qq
        $as_root apt-get install -y -qq build-essential autoconf automake libtool pkg-config libssl-dev curl
    elif command -v dnf &>/dev/null; then
        echo "[*] Installing build dependencies via dnf..."
        $as_root dnf install -y gcc make autoconf automake libtool pkgconfig openssl-devel curl
    elif command -v yum &>/dev/null; then
        echo "[*] Installing build dependencies via yum..."
        $as_root yum install -y gcc make autoconf automake libtool pkgconfig openssl-devel curl
    elif command -v zypper &>/dev/null; then
        echo "[*] Installing build dependencies via zypper..."
        $as_root zypper --non-interactive install gcc make autoconf automake libtool pkg-config libopenssl-devel curl
    elif command -v pacman &>/dev/null; then
        echo "[*] Installing build dependencies via pacman..."
        $as_root pacman -Sy --noconfirm base-devel autoconf automake libtool pkgconf openssl curl
    elif command -v apk &>/dev/null; then
        echo "[*] Installing build dependencies via apk..."
        $as_root apk add build-base autoconf automake libtool pkgconfig openssl-dev curl
    else
        echo -e "${R}[FAIL] No supported package manager found (apt/dnf/yum/zypper/pacman/apk)${Z}"
        echo -e "${R}       Install a C toolchain, autoconf, automake, libtool, pkg-config,${Z}"
        echo -e "${R}       and OpenSSL dev headers manually, then re-run --setup --compile,${Z}"
        echo -e "${R}       or use --yara-url to install a prebuilt binary instead.${Z}"
        return 1
    fi
}

# Installs yara/yarac from a prebuilt tarball URL — no compiler needed.
# Expects a .tar.gz (or .zip, if unzip is available) containing "yara" and
# "yarac" binaries somewhere inside (top level or in a subdirectory).
install_yara_from_url() {
    local url="$1"
    echo "[*] Downloading prebuilt yara/yarac from: $url"

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    local dest="$workdir/download"

    if ! net_fetch "$url" "$dest" 60; then
        echo -e "${R}[FAIL] Download failed (bad URL, or unreachable from this machine)${Z}"
        rm -rf "$workdir"
        return 1
    fi

    local extract_dir="$workdir/extract"
    mkdir -p "$extract_dir"
    if tar -xzf "$dest" -C "$extract_dir" 2>/dev/null || tar -xf "$dest" -C "$extract_dir" 2>/dev/null; then
        :
    elif command -v unzip &>/dev/null && unzip -q "$dest" -d "$extract_dir" 2>/dev/null; then
        :
    else
        # Not an archive we can unpack — maybe it's a bare "yara" binary.
        # We still need yarac too, so this only helps if the URL is itself
        # a directory listing situation, which we can't handle generically.
        cp "$dest" "$extract_dir/yara" 2>/dev/null
    fi

    local found_yara found_yarac
    found_yara=$(find "$extract_dir" -type f -name "yara" 2>/dev/null | head -1)
    found_yarac=$(find "$extract_dir" -type f -name "yarac" 2>/dev/null | head -1)

    if [ -z "$found_yara" ] || [ -z "$found_yarac" ]; then
        echo -e "${R}[FAIL] Downloaded archive doesn't contain both a 'yara' and a 'yarac' binary${Z}"
        rm -rf "$workdir"
        return 1
    fi

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$found_yara" "$SCRIPT_DIR/bin/yara"
    cp "$found_yarac" "$SCRIPT_DIR/bin/yarac"
    chmod +x "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
    rm -rf "$workdir"

    if ! "$SCRIPT_DIR/bin/yara" --version &>/dev/null; then
        echo -e "${R}[FAIL] Downloaded 'yara' binary doesn't run on this machine (wrong arch/libc?)${Z}"
        rm -f "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
        return 1
    fi

    echo -e "${G}[OK] Installed prebuilt yara/yarac from URL — no compiler needed${Z}"
    "$SCRIPT_DIR/bin/yara" --version
    return 0
}

# Builds yara/yarac from source. Needs a C toolchain (installed
# automatically if a supported package manager is found) and network
# access to fetch the YARA source tarball from GitHub.
build_yara_from_source() {
    local version="${SETUP_YARA_VERSION:-4.5.8}"

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"

    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    echo "[*] Downloading YARA v${version} source..."
    if ! net_fetch "https://github.com/VirusTotal/yara/archive/refs/tags/v${version}.tar.gz" "$workdir/yara.tar.gz" 30; then
        echo -e "${R}[FAIL] Could not download YARA source (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/yara.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/yara-${version}" || exit 1
        echo "[*] Configuring (static libyara, dynamic libcrypto/libc/libm only)..."
        ./bootstrap.sh >/dev/null 2>&1
        ./configure --disable-shared --enable-static >/tmp/av_yara_setup_configure.log 2>&1 || exit 1
        echo "[*] Building (this can take a minute)..."
        make -j"$(nproc 2>/dev/null || echo 2)" >/tmp/av_yara_setup_make.log 2>&1 || exit 1
        strip ./yara ./yarac 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/yara-${version}/yara" ]; then
        echo -e "${R}[FAIL] Build failed — see /tmp/av_yara_setup_configure.log and /tmp/av_yara_setup_make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/yara-${version}/yara" "$workdir/yara-${version}/yarac" "$SCRIPT_DIR/bin/"
    chmod +x "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/yara, $SCRIPT_DIR/bin/yarac${Z}"
    "$SCRIPT_DIR/bin/yara" --version
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/yara" 2>/dev/null | awk '{print $1}' | grep -v '^$' | tr '\n' ' ')"
    return 0
}

run_self_setup() {
    echo -e "${B}=== av_scan.sh self-setup ===${Z}"
    echo "Target: $SCRIPT_DIR/bin/{yara,yarac}"
    echo ""

    if [ -x "$SCRIPT_DIR/bin/yara" ] && [ -x "$SCRIPT_DIR/bin/yarac" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/yara and bin/yarac already present -> nothing to do (use --setup --force to rebuild)${Z}"
    elif [ -n "$YARA_URL_ARG" ] && [ "${SETUP_COMPILE_ONLY:-false}" != true ]; then
        install_yara_from_url "$YARA_URL_ARG" || {
            echo -e "${Y}[WARN] Prebuilt install failed -> falling back to compiling from source${Z}"
            build_yara_from_source
        }
    else
        build_yara_from_source
    fi

    # busybox too, while we're setting things up, if it isn't there yet.
    if [ ! -x "$SCRIPT_DIR/bin/busybox" ]; then
        echo ""
        echo "[*] busybox not bundled yet — attempting the same auto-download used at scan time..."
        BUSYBOX_BIN=""
        ensure_busybox
    fi

    echo ""
    echo -e "${G}[OK] Setup complete.${Z} Re-run $0 --help to confirm dependency status."
    return 0
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
            -b|--busybox)    BUSYBOX_PATH_ARG="$2"; shift 2 ;;
            --busybox-url)   BUSYBOX_URL_ARG="$2"; shift 2 ;;
            --yara-url)      YARA_URL_ARG="$2"; shift 2 ;;
            --mb-key)        MB_KEY="$2"; shift 2 ;;
            -q|--quarantine) QUARANTINE_ENABLED=true; shift ;;
            --quarantine-dir)  QUARANTINE_ENABLED=true; QUARANTINE_DIR="$2"; shift 2 ;;
            --quarantine-perm) QUARANTINE_PERM="$2"; shift 2 ;;
            -w|--real-time|--realtime) REALTIME_MODE=true; shift ;;
            --watch-interval)  WATCH_INTERVAL="$2"; shift 2 ;;
            --max-hex-patterns) MAX_HEX_PATTERNS="$2"; shift 2 ;;
            --batch-size)    BATCH_SIZE="$2"; shift 2 ;;
            --heur-batch-size) HEUR_BATCH_SIZE="$2"; shift 2 ;;
            --pe-batch-size) PE_BATCH_SIZE="$2"; shift 2 ;;
            --setup)         DO_SETUP=true; shift ;;
            --force)         SETUP_FORCE=true; shift ;;
            --compile)       SETUP_COMPILE_ONLY=true; shift ;;
            --check-deps)    DO_CHECK_DEPS=true; shift ;;
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
# ============================================================================
init_workers() {
    # WORKERS may be set via -j/--workers; otherwise auto by CPU count.
    [ -z "$WORKERS" ] && WORKERS=$(cpu_count)

    # Guard: WORKERS must be a positive int (avoid div-by-zero later in awk).
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
# 7. MODULE: quarantine (main-script side init)
#    The actual file move happens in the worker (quarantine_file) right
#    where the threat is detected, to avoid a gap between detection and
#    isolation.
# ============================================================================
init_quarantine() {
    [ "$QUARANTINE_ENABLED" = true ] || return 0

    mkdir -p "$QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$QUARANTINE_DIR" 2>/dev/null

    # If quarantine is inside the scan target, quarantined files could get
    # rescanned on the next pass (or by real-time watch).
    case "$QUARANTINE_DIR" in
        "$ROOT_DIR"/*|"$ROOT_DIR")
            echo -e "${Y}[WARN] Quarantine dir is inside the scan target ($ROOT_DIR) — quarantined files may get rescanned${Z}"
            ;;
    esac

    echo -e "${C}[*] Quarantine: ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
}

count_quarantined() {
    bb grep -h "QUARANTINED:" "$WORK_DIR/reports"/*.txt 2>/dev/null | bb wc -l | tr -d ' '
}

# Sets up a persistent live threat log OUTSIDE WORK_DIR (which cleanup()
# deletes on interrupt) — workers append to it AS threats are found, so an
# interrupted scan still leaves usable results behind instead of losing
# everything found up to that point.
init_live_report() {
    if [ -n "$OUTPUT_FILE" ]; then
        LIVE_REPORT_FILE="$OUTPUT_FILE"
    else
        LIVE_REPORT_FILE="$(pwd)/av_scan_threats_$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$").log"
    fi

    if ! { : > "$LIVE_REPORT_FILE"; } 2>/dev/null; then
        echo -e "${Y}[WARN] Can't write to ${LIVE_REPORT_FILE} -> live threat log disabled (results only available at the end)${Z}"
        LIVE_REPORT_FILE=""
        return 0
    fi

    {
        echo "# Oprhus AV Scanner — live threat log (updated as threats are found)"
        echo "# Target: $ROOT_DIR"
        echo "# Started: $(date 2>/dev/null || echo unknown)"
        echo "# If this scan gets interrupted, whatever is below this line is still valid."
        echo "#"
    } >> "$LIVE_REPORT_FILE" 2>/dev/null

    echo -e "${C}[*] Live threat log: ${LIVE_REPORT_FILE}${Z}"
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
    net_fetch "https://cdn.rfxn.com/downloads/maldet-sigpack.tgz" "/tmp/maldet-sigpack.tgz" 15
    if [ -s /tmp/maldet-sigpack.tgz ]; then
        tar -xzf /tmp/maldet-sigpack.tgz -C "$sig_dir/maldet" --strip-components=1 2>/dev/null || true
        echo "  ✓ Maldet: $(bb find "$sig_dir/maldet" -type f 2>/dev/null | bb wc -l | tr -d ' ') files"
        rm -f /tmp/maldet-sigpack.tgz
    else
        echo "  ! Maldet download failed (skipped)"
    fi

    # 2. ClamAV
    echo "[*] ClamAV databases..."
    local clam_dir="$sig_dir/clamav"
    net_fetch "https://packages.microsoft.com/clamav/main.cvd" "/tmp/main.cvd" 10 "Mozilla/5.0"
    net_fetch "https://packages.microsoft.com/clamav/daily.cvd" "/tmp/daily.cvd" 10 "Mozilla/5.0"
    if [ -s /tmp/main.cvd ] && [ -s /tmp/daily.cvd ]; then
    # Check it's actually a CVD, not an HTML block page from Cloudflare
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

    # 3. MalwareBazaar (optional; curl+jq are outside busybox, silently
    # skipped if either is missing)
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
            echo "  ! curl/jq not found (outside busybox) -> skipped"
        fi
    fi

    # 4. YARA rules (git is outside busybox; optional, skipped if missing)
    echo "[*] YARA rules..."
    local yara_dir="$sig_dir/yara"
    if command -v git &>/dev/null; then
        for repo in "https://github.com/Neo23x0/signature-base.git" "https://github.com/Yara-Rules/rules.git"; do
            local name; name=$(basename "$repo" .git)
            git -C "$yara_dir/$name" pull --quiet 2>/dev/null || \
                git clone --depth 1 "$repo" "$yara_dir/$name" --quiet 2>/dev/null || true
        done
    else
        echo "  ! git not found (outside busybox) -> YARA rule update skipped"
    fi

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

    report_signature_counts "$sig_dir"
}

# Prints raw entry counts per signature file, split into "parsed by this
# scanner" vs "excluded" (see MODULE: ClamAV format support). Lets you spot
# at a glance if an update download came back empty/truncated.
report_signature_counts() {
    local sig_dir="$1"
    local parsed_exts="hdb hdu hsb hsu ndb ndu ldb ldu mdb mdu"
    local excluded_exts="msb msu cdb idb wdb pdb gdb ftm fp sfp"

    echo -e "${C}[*] Signature source counts (raw lines per file):${Z}"

    local ext f lines total_parsed=0
    for ext in $parsed_exts; do
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            lines=$(bb wc -l < "$f" 2>/dev/null || echo 0)
            [ "$lines" -eq 0 ] 2>/dev/null && continue
            printf "  %-24s %10d lines\n" "$(basename "$f")" "$lines"
            total_parsed=$((total_parsed + lines))
        done < <(bb find "$sig_dir" -type f -name "*.${ext}" 2>/dev/null)
    done
    echo -e "  ${G}Total parsed (supported formats): ${total_parsed} lines${Z}"

    local excl_bytes=0
    for ext in $excluded_exts; do
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            excl_bytes=$((excl_bytes + $(bb stat -c%s "$f" 2>/dev/null || echo 0)))
        done < <(bb find "$sig_dir" -type f -name "*.${ext}" 2>/dev/null)
    done
    if [ "$excl_bytes" -gt 0 ]; then
        local excl_human
        if [ "$excl_bytes" -ge 1048576 ]; then
            excl_human="$(( excl_bytes / 1048576 )) MB"
        elif [ "$excl_bytes" -ge 1024 ]; then
            excl_human="$(( excl_bytes / 1024 )) KB"
        else
            excl_human="${excl_bytes} bytes"
        fi
        echo -e "  ${Y}Excluded (unsupported formats — .mdb/.msb/.cdb/.idb/.wdb/.pdb/.ftm/.fp/.sfp): ${excl_human} not parsed${Z}"
    fi
    echo ""
}

# ============================================================================
# PARALLEL AWK WRAPPER
# ============================================================================
# $1 = input file, $2 = output file, $3 = awk script
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
    # chunk_dir is removed explicitly at the end of this function (not via
    # a trap — a trap set here would fire on the whole script's exit, not
    # just this function's return).

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

    # List of all chunks
    local chunks=()
    local f
    for f in "$chunk_dir"/chunk_*; do
        [[ "$f" == *.awk ]] && continue
        chunks+=("$f")
    done

    local total=${#chunks[@]}
    echo "[*] Parallel: ${nproc_cmd} cores, ${total} chunks (~${lines_per_chunk} lines)" >&2

    # Progress bar
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

    # Uses `wait -n` to reap finished children (kill -0 polling can't tell
    # zombies from running processes, which caused the pool to hang). Falls
    # back to `jobs -pr` on bash without `wait -n` (e.g. macOS system bash).
    local next=0
    local finished=0
    local -a pids=()

    local supports_wait_n=false
    if help wait 2>/dev/null | grep -q -- '-n'; then
        supports_wait_n=true
    fi

    _awk_pool_launch_more() {
        while [ "$next" -lt "$total" ] && [ "${#pids[@]}" -lt "$nproc_cmd" ]; do
            local chunk="${chunks[$next]}"
            next=$((next + 1))
            (
                bb awk -f "$awk_script_file" "$chunk" > "${chunk}.out"
                rm -f "$chunk"
            ) &
            pids+=("$!")
        done
    }

    _awk_pool_launch_more

    if [ "$supports_wait_n" = true ]; then
        while [ "${#pids[@]}" -gt 0 ]; do
            wait -n "${pids[@]}" 2>/dev/null
            local still=() pid
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    still+=("$pid")
                else
                    finished=$((finished + 1))
                    print_progress "$finished" "$total"
                fi
            done
            pids=("${still[@]}")
            _awk_pool_launch_more
        done
    else
        while [ "${#pids[@]}" -gt 0 ]; do
            sleep 0.1
            local running_now still=() pid
            running_now=" $(jobs -pr 2>/dev/null) "
            for pid in "${pids[@]}"; do
                case "$running_now" in
                    *" $pid "*) still+=("$pid") ;;
                    *)
                        wait "$pid" 2>/dev/null
                        finished=$((finished + 1))
                        print_progress "$finished" "$total"
                        ;;
                esac
            done
            pids=("${still[@]}")
            _awk_pool_launch_more
        done
    fi

    printf "\n[*] All chunks finished, merging...\n" >&2

    cat $(find "$chunk_dir" -name 'chunk_*.out' | sort) > "$outfile" 2>/dev/null
    echo "[*] Done." >&2

    rm -rf "$chunk_dir" 2>/dev/null
    return 0
}

compile_signatures() {
    local sig_input="$1"
    local out_dir="$2"
    # FIX: the compiled artifacts (sha256.tsv, hex_ere.txt, ...) always land
    # in out_dir, which is a fresh EPHEMERAL work directory created per run
    # (/dev/shm/av_scan_$$). The old skip-check compared a flag file's mtime
    # against sig_input's mtime and, on "fresh enough", returned early
    # WITHOUT ever populating out_dir — meaning a positive cache hit would
    # leave the scan with zero signatures loaded. It also touch'd the flag
    # file INSIDE sig_input, which updates sig_input's own mtime as the same
    # operation, so flag-mtime == dir-mtime and "-nt" (strictly newer) was
    # always false anyway — the cache never activated here, just recompiled
    # every run (safe but wasteful, not silently broken). Either way, a
    # PERSISTENT cache dir (survives between runs, unlike out_dir) is the
    # correct fix: on a cache hit we copy from it into out_dir, so out_dir
    # is always populated one way or another.
    local cache_dir="$sig_input/.cache"
    local compiled_flag="$cache_dir/.compiled"

    if [ "$DO_UPDATE" != true ] && [ -f "$compiled_flag" ] && [ "$compiled_flag" -nt "$sig_input" ]; then
        echo -e "[*] Signatures already compiled -> reusing cache ($cache_dir)"
        mkdir -p "$out_dir"
        cp -f "$cache_dir"/sha256.tsv "$cache_dir"/md5.tsv "$cache_dir"/hex_ere.txt \
              "$cache_dir"/strings.txt "$cache_dir"/b64_payloads.tsv "$cache_dir"/mdb.tsv "$out_dir/" 2>/dev/null || true
        [ -d "$cache_dir/yara" ] && cp -rf "$cache_dir/yara" "$out_dir/" 2>/dev/null
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

    touch "$out_dir/sha256.tsv" "$out_dir/md5.tsv" "$out_dir/hex_ere.txt" "$out_dir/b64_payloads.tsv" "$out_dir/mdb.tsv"

    if [ ! -e "$sig_input" ]; then
        echo -e "${Y}[INFO] No signature base found. Using built-in heuristics only.${Z}"
        return
    fi

    local sig_files=()
    if [ -d "$sig_input" ]; then
        # Collect only text signature files, skip .git, yara, custom, and
        # non-actionable ClamAV extensions (PE-section hashes, container
        # sigs, icon hashes, domain/URL sigs, fuzzy hashes, and — important
        # — .fp/.sfp which are KNOWN-CLEAN whitelists, not malware sigs).
        # See "MODULE: ClamAV format support" below for details.
        while IFS= read -r -d '' sf; do
            sig_files+=("$sf")
        done < <(bb find "$sig_input" -type f \
            -not -path '*/.git/*' \
            -not -path '*/yara/*' \
            -not -path '*/custom/*' \
            -not -path '*/.cache/*' \
            -not -name "*.pack" -not -name "*.idx" -not -name "*.cvd" \
            -not -name "*.yarc" -not -name "*.compiled" \
            -not -name "*.msb" -not -name "*.msu" \
            -not -name "*.cdb" -not -name "*.idb" -not -name "*.wdb" \
            -not -name "*.pdb" -not -name "*.gdb" -not -name "*.ftm" \
            -not -name "*.fp" -not -name "*.sfp" \
            -not -name "*.ign" -not -name "*.ign2" \
            -not -name "*.info" -not -name "*.cfg" -not -name "*.crb" \
            -not -name "*.cdiff" \
            -print0 2>/dev/null)
    else
        sig_files+=("$sig_input")
    fi

    # ============================================================================
    # MODULE: ClamAV format support
    #
    # ClamAV signature files are a family of formats, not one — files are
    # routed by extension to a dedicated parser per format.
    #
    # Supported:
    #   .hdb/.hdu, .hsb/.hsu — file hashes (MD5/SHA256)
    #   .ndb/.ndu            — extended hex signatures with gap quantifiers:
    #                           {n}, {n-m}, {-n}, {n-}, ??, *, (aa|bb) —
    #                           compiled into YARA hex-string rules, not
    #                           grep -E patterns (see note below)
    #   .ldb/.ldu             — logical signatures: subsignatures AND their
    #                           boolean AND/OR expression are reconstructed
    #                           as a proper YARA rule (condition), so match
    #                           precision matches real ClamAV, not a
    #                           degraded "any fragment matches" heuristic
    #   .mdb/.mdu             — PE SECTION MD5 hashes ("size:md5:name").
    #                           The worker parses the PE section table
    #                           itself (see _pe_section_table in the
    #                           embedded worker), hashes each section's raw
    #                           bytes, and batch-matches (size,md5) pairs
    #                           against the compiled mdb.tsv — this is the
    #                           single largest chunk of a real ClamAV
    #                           database (often >50% of its total size),
    #                           so this is worth a real PE parser rather
    #                           than excluding it.
    #
    # Intentionally NOT supported (excluded above, not silently dropped):
    #   .msb/.msu              — PE section SHA256 hashes (same idea as
    #                          .mdb but SHA256) — real-world databases have
    #                          this be a tiny fraction of a percent of
    #                          total signatures (low priority; the MD5
    #                          form above already covers the bulk).
    #   .cdb, .idb            — container signatures / icon hashes, need an
    #                          archive/PE-resource parser we don't have.
    #   .wdb, .pdb, .gdb       — domain/URL signatures, not file content.
    #   .ftm                   — fuzzy hashes (need distance calc, not us).
    #   .fp, .sfp              — KNOWN-CLEAN whitelists, not malware sigs.
    #
    # WHY YARA INSTEAD OF grep -E: a real ClamAV .ndb+.ldb set is tens to
    # hundreds of thousands of hex patterns. grep -E -f rebuilds its match
    # automaton from every pattern on EVERY invocation — empirically, just
    # 10,000 patterns took 4.5s to build ONCE, and 200,000 timed out past
    # 30s. That made scanning thousands of files effectively hang. YARA is
    # built for exactly this (multi-pattern matching at malware-database
    # scale): a compiled ruleset of 50,000 rules loads and matches 500
    # files in under a second. NDB/LDB signatures are compiled into a YARA
    # rules file here, then yarac'd into one binary ruleset alongside any
    # externally-fetched YARA rules (see below), and matched through the
    # same batched process_yara_batch() used for hand-written YARA rules.
    # LDB subsignatures that use PCRE (start with "/") are skipped —
    # PCRE-in-YARA is a distinct syntax we don't attempt to convert; a rule
    # referencing a skipped subsignature is dropped entirely rather than
    # emitting a broken condition.
    # ============================================================================

    local hash_files=() ndb_files=() ldb_files=() sect_files=() generic_files=()
    local sf ext
    for sf in "${sig_files[@]}"; do
        ext="${sf##*.}"
        case "${ext,,}" in
            hdb|hdu|hsb|hsu) hash_files+=("$sf") ;;
            ndb|ndu)         ndb_files+=("$sf") ;;
            ldb|ldu)         ldb_files+=("$sf") ;;
            mdb|mdu)         sect_files+=("$sf") ;;
            *)               generic_files+=("$sf") ;;
        esac
    done

    # Shared NDB/LDB helper: converts a ClamAV hex signature into a YARA
    # hex-string token sequence (space-separated bytes / ?? / [n] / [n-m] /
    # [n-] / [0-m] / ( aa | bb ) alternation groups). Unlike the old ERE
    # path, jump distances stay EXACT — YARA is built to handle this at
    # scale, so there is no need to loosen them to "any distance".
    local ndb2yara_fn='
        function ndb2yara(raw,    s, out, i, c, n, buf, j, spec, inner, alts, cnt, k, a, pa, m, alt_out) {
            s = tolower(raw)
            gsub(/[ \t]+/, "", s)
            n = length(s)
            out = ""
            buf = ""
            i = 1
            while (i <= n) {
                c = substr(s, i, 1)
                if (substr(s, i, 2) == "??") {
                    out = out "?? "
                    i += 2
                } else if (c == "*") {
                    out = out "[0-] "
                    i += 1
                } else if (c == "{") {
                    j = index(substr(s, i), "}")
                    if (j == 0) { i = n + 1 } else {
                        spec = substr(s, i + 1, j - 2)
                        if (spec ~ /^[0-9]+$/) out = out "[" spec "] "
                        else if (spec ~ /^[0-9]+-[0-9]+$/) out = out "[" spec "] "
                        else if (spec ~ /^[0-9]+-$/) out = out "[" spec "] "
                        else if (spec ~ /^-[0-9]+$/) out = out "[0" spec "] "
                        i += j
                    }
                } else if (c == "(") {
                    j = index(substr(s, i), ")")
                    if (j == 0) { i = n + 1 } else {
                        inner = substr(s, i + 1, j - 2)
                        cnt = split(inner, alts, "|")
                        alt_out = ""
                        for (k = 1; k <= cnt; k++) {
                            a = alts[k]
                            pa = ""
                            for (m = 1; m <= length(a); m += 2) pa = pa substr(a, m, 2) " "
                            gsub(/ +$/, "", pa)
                            alt_out = (alt_out == "" ? pa : alt_out " | " pa)
                        }
                        out = out "( " alt_out " ) "
                        i += j
                    }
                } else if (c ~ /[0-9a-f]/) {
                    buf = buf c
                    if (length(buf) == 2) { out = out buf " "; buf = "" }
                    i += 1
                } else {
                    i += 1
                }
            }
            gsub(/ +$/, "", out)
            return out
        }
        function yara_rule_name(base,    r) {
            r = base
            gsub(/[^a-zA-Z0-9_]/, "_", r)
            return "s_" r
        }
    '

    # GENERIC category fallback still uses the ERE-based approach (low
    # volume — custom/misc files, not the bulk .ndb/.ldb databases — so
    # grep -E -f's per-pattern-count cost isn't a practical problem here).
    local hex2ere_fn='
        function hex2ere(s, a, p, guard, n) {
            s = tolower(s)
            gsub(/[^0-9a-f?*{}|()-]/, "", s)
            if (length(s) < 8) return ""
            gsub(/\?\?/, "..", s)
            gsub(/\*/, ".*", s)
            guard = 0
            while (match(s, /\{(-[0-9]+|[0-9]+-[0-9]+|[0-9]+-|[0-9]+)\}/)) {
                guard++
                if (guard > 1000) { return "" }
                sub(/\{(-[0-9]+|[0-9]+-[0-9]+|[0-9]+-|[0-9]+)\}/, "@GAPSTAR@", s)
            }
            gsub(/@GAPSTAR@/, ".*", s)
            return s
        }
    '

    local tmp_raw_sigs="$out_dir/raw_compiled.tmp"
    : > "$tmp_raw_sigs"
    mkdir -p "$out_dir/yara"
    local tmp_yara_rules="$out_dir/yara/generated_ndb_ldb.yar"
    : > "$tmp_yara_rules"

    # --- HASH category (.hdb/.hdu/.hsb/.hsu): "hash:size:name" ---
    if [ ${#hash_files[@]} -gt 0 ]; then
        local tmp_hash="$out_dir/cat_hash.tmp" tmp_hash_out="$out_dir/cat_hash.out"
        cat "${hash_files[@]}" > "$tmp_hash"
        run_awk_parallel "$tmp_hash" "$tmp_hash_out" '
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 1) next
                h = tolower(a[1])
                name = (n >= 3 ? a[3] : "ClamAV.Hash")
                if (h ~ /^[0-9a-f]{64}$/) print "SHA256\t" h "\t" name
                else if (h ~ /^[0-9a-f]{32}$/) print "MD5\t" h "\t" name
            }
        '
        cat "$tmp_hash_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_hash" "$tmp_hash_out"
    fi

    # --- SECT category (.mdb/.mdu): "PESectionSize:PESectionMD5:Name" ---
    # Unlike HASH, the hash is the MIDDLE field, and it identifies a PE
    # SECTION's raw bytes, not the whole file — matched separately by the
    # worker's PE section parser (see check_pe_sections / process_pe_batch).
    if [ ${#sect_files[@]} -gt 0 ]; then
        local tmp_sect="$out_dir/cat_sect.tmp" tmp_sect_out="$out_dir/cat_sect.out"
        cat "${sect_files[@]}" > "$tmp_sect"
        run_awk_parallel "$tmp_sect" "$tmp_sect_out" '
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 2) next
                sz = a[1] + 0
                h = tolower(a[2])
                name = (n >= 3 ? a[3] : "ClamAV.Section")
                if (sz > 0 && h ~ /^[0-9a-f]{32}$/) print "SECTMD5\t" sz "\t" h "\t" name
            }
        '
        cat "$tmp_sect_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_sect" "$tmp_sect_out"
    fi

    # --- NDB category (.ndb/.ndu): "Name:Type:Offset:HexSig[:MinFL:MaxFL]" ---
    # The hex signature is always field 4, not "the last field" — optional
    # trailing :MinFL:MaxFL would otherwise shift it out. Compiled into a
    # YARA rule per signature (see MODULE: ClamAV format support above).
    if [ ${#ndb_files[@]} -gt 0 ]; then
        local tmp_ndb="$out_dir/cat_ndb.tmp" tmp_ndb_out="$out_dir/cat_ndb.out"
        cat "${ndb_files[@]}" > "$tmp_ndb"
        run_awk_parallel "$tmp_ndb" "$tmp_ndb_out" "$ndb2yara_fn"'
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 4) next
                yhex = ndb2yara(a[4])
                if (yhex == "" || length(yhex) < 8) next
                rname = yara_rule_name("ndb_" FILENAME "_" NR)
                print "YARARULE\trule " rname " { strings: $a = { " yhex " } condition: $a }"
            }
        '
        cat "$tmp_ndb_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_ndb" "$tmp_ndb_out"
    fi

    # --- LDB category (.ldb/.ldu): "Name:Type:Expression:Subsig0:Subsig1:..." ---
    # Unlike the old grep-based approach, the boolean AND/OR expression
    # (field 3) is now reconstructed as a real YARA condition instead of
    # being dropped — e.g. ClamAV "(0&1)|2" becomes YARA "($s0 and $s1) or
    # $s2". A rule is skipped entirely (not partially emitted) if any of
    # its subsignatures is PCRE-based ("/pattern/") or fails to convert,
    # since a condition referencing a missing $sN would be a broken rule.
    if [ ${#ldb_files[@]} -gt 0 ]; then
        local tmp_ldb="$out_dir/cat_ldb.tmp" tmp_ldb_out="$out_dir/cat_ldb.out"
        cat "${ldb_files[@]}" > "$tmp_ldb"
        run_awk_parallel "$tmp_ldb" "$tmp_ldb_out" "$ndb2yara_fn"'
            function translate_condition(expr,    out2, j, L, ch, numstr) {
                out2 = ""
                j = 1
                L = length(expr)
                while (j <= L) {
                    ch = substr(expr, j, 1)
                    if (ch ~ /[0-9]/) {
                        numstr = ch
                        j++
                        while (j <= L && substr(expr, j, 1) ~ /[0-9]/) { numstr = numstr substr(expr, j, 1); j++ }
                        out2 = out2 "$s" numstr
                    } else if (ch == "&") { out2 = out2 " and "; j++ }
                    else if (ch == "|") { out2 = out2 " or "; j++ }
                    else { out2 = out2 ch; j++ }
                }
                return out2
            }
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 4) next
                ok = 1
                strs = ""
                for (i = 4; i <= n; i++) {
                    if (a[i] ~ /^\//) { ok = 0; break }
                    yhex = ndb2yara(a[i])
                    if (yhex == "" || length(yhex) < 8) { ok = 0; break }
                    strs = strs "$s" (i - 4) " = { " yhex " } "
                }
                if (!ok) next
                cond = translate_condition(a[3])
                if (cond == "") next
                rname = yara_rule_name("ldb_" FILENAME "_" NR)
                print "YARARULE\trule " rname " { strings: " strs "condition: " cond " }"
            }
        '
        cat "$tmp_ldb_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_ldb" "$tmp_ldb_out"
    fi

    # --- GENERIC category: everything else (custom.*, maldet's own bare-hash
    # formats like md5.dat/sha256v2.dat, our sha256:/str:/b64sig: DSL) — same
    # content-guessing approach as before, plus bare-hash support.
    if [ ${#generic_files[@]} -gt 0 ]; then
        local tmp_generic="$out_dir/cat_generic.tmp" tmp_generic_out="$out_dir/cat_generic.out"
        cat "${generic_files[@]}" > "$tmp_generic"
        run_awk_parallel "$tmp_generic" "$tmp_generic_out" "$hex2ere_fn"'
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
                # Bare hash (e.g. maldet md5.dat/sha256v2.dat: one hash per
                # line, optionally with a name after ":")
                if (line ~ /^[0-9a-fA-F]{64}(:.*)?$/) {
                    split(line, a, ":")
                    print "SHA256\t" tolower(a[1]) "\t" (a[2] != "" ? a[2] : "Maldet.Hash")
                    next
                }
                if (line ~ /^[0-9a-fA-F]{32}(:.*)?$/) {
                    split(line, a, ":")
                    print "MD5\t" tolower(a[1]) "\t" (a[2] != "" ? a[2] : "Maldet.Hash")
                    next
                }
                # ClamAV/Maldet-style "hash:size:name"
                if (line ~ /^[0-9a-fA-F]{32,64}:[0-9*]+:/) {
                    split(line, a, ":")
                    h = tolower(a[1]); name = a[3]
                    if (length(h) == 64) print "SHA256\t" h "\t" name
                    else if (length(h) == 32) print "MD5\t" h "\t" name
                    next
                }
                # Loosest fallback: last field looks like a hex signature
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
        cat "$tmp_generic_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_generic" "$tmp_generic_out"
    fi

    if [ -s "$tmp_raw_sigs" ]; then
        # Distribute the merged processed stream into the .tsv/.txt/.yar outputs
        bb awk -F'\t' -v out="$out_dir" '
            $1 == "SHA256"   { print $2 "\t" $3 >> (out "/sha256.tsv") }
            $1 == "MD5"      { print $2 "\t" $3 >> (out "/md5.tsv") }
            $1 == "STR"      { print $2 >> (out "/strings.txt") }
            $1 == "B64"      { print $2 "\t" $3 >> (out "/b64_payloads.tsv") }
            $1 == "HEX"      { print $2 >> (out "/hex_ere.txt") }
            $1 == "YARARULE" { print $2 >> (out "/yara/generated_ndb_ldb.yar") }
            $1 == "SECTMD5"  { print $2 "\t" $3 "\t" $4 >> (out "/mdb.tsv") }
        ' "$tmp_raw_sigs"
    fi
    rm -f "$tmp_raw_sigs"

    # External hash lists
    bb find "$sig_input" -not -path '*/.git/*' \( -name "*.sha256" -o -name "malwarebazaar.sha256" \) 2>/dev/null | while read -r f; do
        [ -s "$f" ] && bb awk '{print $1 "\t" ($2 ? $2 : "External.Hash")}' "$f" >> "$out_dir/sha256.tsv"
    done

    # YARA: gather external rule sources (fetched during -u) plus our own
    # generated NDB/LDB rules, and compile them ALL into one ruleset here —
    # so every worker just loads a single pre-compiled rules.yarc instead
    # of each re-parsing rule text from scratch (see MODULE: ClamAV format
    # support above for why this matters at scale).
    mkdir -p "$out_dir/yara"
    if [ -d "$sig_input/yara" ]; then
        bb find "$sig_input/yara" -not -path '*/.git/*' \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | head -200 | while read -r yf; do
            cp "$yf" "$out_dir/yara/" 2>/dev/null || true
        done
    fi

    # "filename"/"filepath"/"extension" are external variables in modern
    # YARA (not automatic built-ins) — plenty of real-world rules reference
    # them, and compilation fails outright if they aren't declared. Empty
    # defaults are fine: this scanner batches many files per yara call, so
    # there's no single "current filename" to give them anyway; rules that
    # depend on a real value just won't match on that condition.
    local yara_extvars=(-d filename= -d filepath= -d extension=)

    local yar_sources
    yar_sources=$(bb find "$out_dir/yara" -maxdepth 1 \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null)
    if [ -n "$yar_sources" ] && [ -n "$YARAC_BIN" ]; then
        # Validate each file in ISOLATION first and only include the ones
        # that compile cleanly — one incompatible rule (unsupported module,
        # syntax our yarac build doesn't handle) would otherwise fail the
        # ENTIRE combined ruleset and silently disable all YARA detection,
        # including our own generated NDB/LDB rules.
        local yara_index="$out_dir/yara/_index.yar"
        local skipped=0 included=0
        : > "$yara_index"
        while IFS= read -r yf; do
            [ -z "$yf" ] && continue
            if "$YARAC_BIN" "${yara_extvars[@]}" "$yf" /dev/null &>/dev/null; then
                echo "include \"$yf\"" >> "$yara_index"
                included=$((included + 1))
            else
                skipped=$((skipped + 1))
            fi
        done <<< "$yar_sources"
        [ "$skipped" -gt 0 ] && echo -e "${Y}[WARN] Skipped ${skipped} incompatible YARA rule file(s) (unsupported module/syntax) — ${included} included${Z}"

        if [ -s "$yara_index" ] && "$YARAC_BIN" "${yara_extvars[@]}" "$yara_index" "$out_dir/yara/rules.yarc" 2>/dev/null; then
            :
        else
            echo -e "${Y}[WARN] yarac failed on the combined ruleset -> falling back to source (slower)${Z}"
            rm -f "$out_dir/yara/rules.yarc" 2>/dev/null
            mv -f "$yara_index" "$out_dir/yara/index.yar" 2>/dev/null
        fi
        rm -f "$yara_index"
    elif [ -n "$yar_sources" ]; then
        # No yarac available: fall back to an include-index the worker can
        # load as source (works, just recompiles from text on every call).
        local yara_index="$out_dir/yara/index.yar"
        : > "$yara_index"
        while IFS= read -r yf; do
            [ -n "$yf" ] && echo "include \"$yf\"" >> "$yara_index"
        done <<< "$yar_sources"
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
        bb find "$cdir" -name "*.md5" -exec cat {} + 2>/dev/null >> "$out_dir/md5.tsv" || true
        bb find "$cdir" -name "*.sha256" -exec cat {} + 2>/dev/null >> "$out_dir/sha256.tsv" || true
        bb find "$cdir" -name "*.strings" -exec cat {} + 2>/dev/null >> "$out_dir/strings.txt" || true
        echo "  ✓ Custom signatures loaded"
    fi

    # Dedup (also collapses now-common ".*"-only variants of what used to be
    # distinct bounded-quantifier patterns)
    for f in sha256.tsv md5.tsv strings.txt b64_payloads.tsv hex_ere.txt mdb.tsv; do
        [ -s "$out_dir/$f" ] && bb sort -u "$out_dir/$f" -o "$out_dir/$f" 2>/dev/null || true
    done

    # Cap hex_ere.txt: grep -E -f builds its match automaton from ALL
    # patterns on every call. A full real ClamAV .ndb+.ldb set is hundreds
    # of thousands of patterns — tested empirically, that alone can take
    # 30+ SECONDS to build per call, regardless of batching. Keep it small
    # enough that even a fresh automaton build stays sub-second.
    if [ -s "$out_dir/hex_ere.txt" ]; then
        local hex_count
        hex_count=$(bb wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')
        if [ "${hex_count:-0}" -gt "$MAX_HEX_PATTERNS" ]; then
            echo -e "${Y}[WARN] hex_ere.txt has ${hex_count} patterns, capping to ${MAX_HEX_PATTERNS} (--max-hex-patterns to change) — coverage reduced, but grep -E -f cannot build a usable automaton from the full set${Z}"
            head -n "$MAX_HEX_PATTERNS" "$out_dir/hex_ere.txt" > "$out_dir/hex_ere.txt.tmp" && mv -f "$out_dir/hex_ere.txt.tmp" "$out_dir/hex_ere.txt"
        fi
    fi

    # Save compiled artifacts to the persistent cache so the next run can
    # reuse them without recompiling (see comment at the top of this function)
    mkdir -p "$cache_dir"
    cp -f "$out_dir"/sha256.tsv "$out_dir"/md5.tsv "$out_dir"/hex_ere.txt \
          "$out_dir"/strings.txt "$out_dir"/b64_payloads.tsv "$out_dir"/mdb.tsv "$cache_dir/" 2>/dev/null || true
    [ -d "$out_dir/yara" ] && cp -rf "$out_dir/yara" "$cache_dir/" 2>/dev/null
    touch "$compiled_flag" 2>/dev/null || true

    echo -e "  SHA256 : ${C}$(bb wc -l < "$out_dir/sha256.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  MD5    : ${C}$(bb wc -l < "$out_dir/md5.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  PE Sections (mdb): ${C}$(bb wc -l < "$out_dir/mdb.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  HexERE : ${C}$(bb wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  Strings: ${C}$(bb wc -l < "$out_dir/strings.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  YARA   : ${C}$(bb find "$out_dir/yara" -name "*.ya*" 2>/dev/null | bb wc -l | tr -d ' ')${Z}"
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
    # Check via bb() first (busybox if available, else system) — matches
    # what the script actually uses at runtime.
    local miss=()
    for cmd in find awk grep od dd cut tr wc; do
        if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet "$cmd"; then
            continue
        fi
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [ ${#miss[@]} -gt 0 ] && { echo -e "${R}[FAIL] Missing required tools (not in busybox or system): ${miss[*]}${Z}"; exit 1; }
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
    echo -e " strings/file : ${C}${STRINGS_CMD} / built-in magic-bytes${Z}"
    if [ -n "$BUSYBOX_BIN" ]; then
        echo -e " BusyBox      : ${G}ON${Z} -> ${BUSYBOX_BIN}"
    elif [ "$ALLOW_BUSYBOX" = false ]; then
        echo -e " BusyBox      : ${Y}off (--no-busybox, intentional)${Z}"
    else
        echo -e " BusyBox      : ${R}MISSING (system-only) — unusual, check the package${Z}"
    fi
    if [ "$QUARANTINE_ENABLED" = true ]; then
        echo -e " Quarantine   : ${C}ON -> ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
    else
        echo -e " Quarantine   : off"
    fi
    if [ "$REALTIME_MODE" = true ]; then
        echo -e " Real-time    : ${C}ON${Z} (starts after the base scan)"
    fi
    echo -e "${B}=================================================${Z}"
}

collect_files() {
    echo -e "[*] Collecting file tree..."
    local excl=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")
    if [ "$OS" = "linux" ] && bb find "$SCRIPT_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
        bb find "$ROOT_DIR" -type f "${excl[@]}" -printf "%s\t%m\t%p\n" 2>/dev/null > "$WORK_DIR/all_files.tsv"
    else
        bb find "$ROOT_DIR" -type f "${excl[@]}" -print 2>/dev/null > "$WORK_DIR/all_files.tsv"
    fi
    TOTAL_FILES=$(bb wc -l < "$WORK_DIR/all_files.tsv" | tr -d ' ')
    echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z}\n"
}

split_pools() {
    bb awk -v w="$WORKERS" -v d="$WORK_DIR/reports" '{ print > (d "/pool_" (NR % w) ".txt") }' "$WORK_DIR/all_files.tsv"
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
            "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
            "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" &
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
            # Workers spend most of their active time inside short-lived
            # CHILD processes (grep against a 600k+ line md5.tsv, yara,
            # dd/od) rather than holding memory in the worker bash process
            # itself — summing only the parent PIDs' own RSS massively
            # undercounts real usage (reads as ~0MB even under real load).
            # Include direct children too.
            local ppid_list child_pids all_pids
            ppid_list=$(IFS=,; echo "${active_pids[*]}")
            child_pids=$(ps --ppid "$ppid_list" -o pid= 2>/dev/null | tr -d ' ')
            all_pids="${active_pids[*]} $child_pids"
            mem_mb=$(ps -o rss= -p $all_pids 2>/dev/null | awk '{s+=$1} END {print int(s/1024)}')
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

    local found=0
    if [ -n "$LIVE_REPORT_FILE" ] && [ -f "$LIVE_REPORT_FILE" ]; then
        # NOTE: grep -c legitimately PRINTS "0" on zero matches while also
        # exiting 1 (that's not an error, just "no match") — a "|| echo 0"
        # fallback here would double up and print "0\n0" into $found.
        found=$(bb grep -c "^\[" "$LIVE_REPORT_FILE" 2>/dev/null)
        found="${found:-0}"
    fi

    rm -rf "$WORK_DIR"
    echo -e "\n${Y}[WARN] Scan aborted${Z}"
    if [ -n "$LIVE_REPORT_FILE" ]; then
        echo -e "${C}[*] ${found} threat(s) found before interruption -> saved to: ${LIVE_REPORT_FILE}${Z}"
    fi
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
        f=$(bb grep "^FILES_SCANNED:" "$r" 2>/dev/null | cut -d: -f2)
        t=$(bb grep "^THREATS_FOUND:" "$r" 2>/dev/null | cut -d: -f2)
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
        bb grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null \
            | cut -d: -f2- | bb sort -u \
            | while IFS='|' read -r type file info; do
                echo -e " ${R}[!]${Z} [${Y}${type}${Z}] ${file} ${C}${info:-}${Z}"
              done
    else
        echo -e "${G}${RPT}${Z}"
        echo -e "\n ${G}[OK] No threats detected [CLEAN]${Z}"
    fi
}

save_report() {
    [ -n "$LIVE_REPORT_FILE" ] || return 0
    {
        echo "$RPT"
        [ "$TT" -gt 0 ] && {
            echo -e "\n=== DETECTED THREATS ==="
            bb grep "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d: -f2- | bb sort -u
        }
    } > "$LIVE_REPORT_FILE"
    echo -e "\n[*] Report saved: ${C}${LIVE_REPORT_FILE}${Z}"
}

# ============================================================================
# 15. MODULE: real-time watch (background daemon)
#
#     Runs a single instance of the same worker (same WORKER_FILE, same
#     hashing/YARA/heuristics/quarantine code), but reads paths from a FIFO
#     instead of a static pool file. "while read ... done < FIFO" already
#     blocks and waits for new lines, so the worker is inherently a
#     long-running real-time process without extra code.
#
#     The main script just feeds new file paths into the FIFO:
#       - inotifywait if available -> instant, event-driven
#       - otherwise -> polling (find + diff against previous snapshot)
#         every WATCH_INTERVAL seconds
# ============================================================================
start_realtime_worker() {
    REALTIME_FIFO="$WORK_DIR/realtime.fifo"
    mkfifo "$REALTIME_FIFO" 2>/dev/null || {
        echo -e "${R}[FAIL] Could not create FIFO for real-time mode${Z}"
        return 1
    }

    local qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"

    REALTIME_REPORT="$WORK_DIR/reports/rt.txt"
    : > "$REALTIME_REPORT"

    # The worker opens the FIFO for reading and blocks inside its usual
    # run_scan_loop(), waiting for new path lines.
    bash "$WORKER_FILE" \
        "$REALTIME_FIFO" "rt" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
        "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
        "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" &
    REALTIME_WORKER_PID=$!

    # Keep the write fd (3) open permanently — opening/closing per event
    # would block until a reader shows up each time.
    exec 3> "$REALTIME_FIFO"
}

feed_realtime_path() {
    local path="$1"
    [ -f "$path" ] || return 0
    printf '%s\n' "$path" >&3 2>/dev/null || true
}

# Streams new THREAT lines from the worker's live report to the console
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
    echo -e "${C}[*] Real-time: using inotifywait (instant reaction)${Z}"
    inotifywait -m -r -e create -e moved_to -e close_write \
        --format '%w%f' "$ROOT_DIR" 2>/dev/null | while IFS= read -r path; do
        feed_realtime_path "$path"
    done
}

watch_poll() {
    echo -e "${Y}[WARN] inotifywait not found -> falling back to polling every ${WATCH_INTERVAL}s (install inotify-tools for instant reaction)${Z}"
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
    echo -e "${B} REAL-TIME MODE${Z} — base scan done, watching ${C}${ROOT_DIR}${Z}"
    echo -e " Ctrl+C to stop"
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
# 16. main() — single entry point; enforces init order so no module runs
#     before its required globals are set.
# ============================================================================
main() {
    detect_platform
    parse_args "$@"
    setup_colors

    if [ "$DO_SETUP" = true ]; then
        run_self_setup
        exit $?
    fi

    if [ "$DO_CHECK_DEPS" = true ]; then
        check_dependencies_report
        exit 0
    fi

    # BusyBox bootstrap must happen before everything else — the signature
    # updater, compiler, and scanning all depend on BUSYBOX_BIN/SHA256_CMD/
    # MD5_CMD/STRINGS_CMD/FILE_CMD set here.
    init_toolchain
    YARA_CMD=$(detect_yara)
    detect_yarac

    # --update is a standalone action (like typical AV tools separate
    # update from scan): update signatures, then exit, no auto-scan.
    if [ "$DO_UPDATE" = true ]; then
        update_signatures "$SIGNATURES" "$MB_KEY"

        # Compile right away (not a scan — no target files touched) so the
        # persistent cache is fresh immediately and the printed SHA256/MD5/
        # HexERE/Strings/YARA counts reflect exactly what the next scan
        # will use, as a sanity check that nothing broke in the update.
        local tmp_compile_dir
        tmp_compile_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'av_update_compile.XXXXXX')
        compile_signatures "$SIGNATURES" "$tmp_compile_dir"
        rm -rf "$tmp_compile_dir"

        echo -e "${C}[*] Update finished. Auto-scan after --update is disabled — run a scan as a separate command.${Z}"
        exit 0
    fi

    init_workers

    init_workdir
    check_deps
    init_quarantine

    extract_worker
    compile_signatures "$SIGNATURES" "$SIG_DIR"

    init_live_report

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

    # Real-time watch starts AFTER the base scan (the same trap cleanup is
    # already active and covers this phase too — Ctrl+C/SIGTERM stops both
    # the worker daemon and the FIFO cleanly).
    if [ "$REALTIME_MODE" = true ]; then
        run_realtime_watch
    fi

    rm -rf "$WORK_DIR"
    exit 0
}

main "$@"

# =============================================================================
# 17. EMBEDDED WORKER (self-contained, also modular)
# =============================================================================
#__WORKER_START__
#!/bin/bash
set -uo pipefail
export LC_ALL=C

# ----------------------------------------------------------------------------
# GLOBALS — all worker variables defined once here, before any function
# uses them.
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
QUARANTINE_DIR="${12:-}"      # empty = quarantine disabled
QUARANTINE_PERM="${13:-0400}"
BUSYBOX_BIN="${14:-}"         # inherited from the main script (same binary)
BATCH_SIZE="${15:-50}"        # files per hash/YARA batch
HEUR_BATCH_SIZE="${16:-50}"   # files per strings/hex heuristic batch
PE_BATCH_SIZE="${17:-50}"     # files per PE-section (.mdb) batch
LIVE_REPORT_FILE="${18:-}"    # persistent live threat log (outside the
                               # ephemeral WORK_DIR) — written to immediately
                               # as each threat is found, see threat() below

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
HAS_MDB=false
YARA_HAS_SCAN_LIST=false
YARA_TARGET=""
BB_APPLETS=""

declare -a BATCH_SHA=()
declare -a BATCH_MD5=()
declare -a BATCH_YARA=()
declare -a BATCH_HEUR=()
declare -a BATCH_PE=()
SHA_BATCH_CNT=0
MD5_BATCH_CNT=0
YARA_BATCH_CNT=0
HEUR_BATCH_CNT=0
PE_BATCH_CNT=0
# All batch sizes come from the main script (--batch-size/--heur-batch-size/
# --pe-batch-size), defaulting to 50. Smaller batches mean smoother/more
# incremental progress (threats appear as they're found instead of jumping
# when a big batch completes) at some cost to throughput, since the fixed
# per-call cost (building a grep/YARA match set) is amortized over fewer
# files.

# ----------------------------------------------------------------------------
# MODULE: busybox wrapper (own copy — the worker runs as a separate bash
# process, so it cannot share the main script's function)
# ----------------------------------------------------------------------------
if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
    while IFS= read -r _a; do
        [ -n "$_a" ] && BB_APPLETS="${BB_APPLETS}${_a} "
    done < <("$BUSYBOX_BIN" --list 2>/dev/null)
    BB_APPLETS=" ${BB_APPLETS}"
fi

bb() {
    local applet="$1"; shift
    case "$BB_APPLETS" in
        *" $applet "*) "$BUSYBOX_BIN" "$applet" "$@" ;;
        *) command "$applet" "$@" ;;
    esac
}

# ----------------------------------------------------------------------------
# MODULE: init
# ----------------------------------------------------------------------------
init_worker_state() {
    [ -s "$SIG_DIR/sha256.tsv" ] && HAS_SHA256=true
    [ -s "$SIG_DIR/md5.tsv" ] && HAS_MD5=true
    [ -s "$SIG_DIR/b64_payloads.tsv" ] && HAS_B64=true
    [ -s "$SIG_DIR/strings.txt" ] && HAS_STRINGS=true
    [ -s "$SIG_DIR/hex_ere.txt" ] && HAS_HEX_ERE=true
    [ -s "$SIG_DIR/mdb.tsv" ] && HAS_MDB=true

    if [ -f "$SIG_DIR/yara/rules.yarc" ]; then
        HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/rules.yarc"
    elif [ -f "$SIG_DIR/yara/index.yar" ]; then
        HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/index.yar"
    fi

    # YARA 4.0+ / YARA-X support --scan-list for batch scanning; older
    # builds don't and need the symlink-directory fallback in
    # process_yara_batch(). Probed once per worker, not once per batch.
    YARA_HAS_SCAN_LIST=false
    if [ "$HAS_YARA" = true ] && "$YARA_CMD" --help 2>&1 | bb grep -q -- "--scan-list"; then
        YARA_HAS_SCAN_LIST=true
    fi
}

# ----------------------------------------------------------------------------
# MODULE: low-level helpers (stat / hash / decode / strings / file-type)
# ----------------------------------------------------------------------------
_stat_size() {
    if [ "$OS" = "macos" ]; then bb stat -f '%z' "$1" 2>/dev/null
    else bb stat -c '%s' "$1" 2>/dev/null; fi
}
_stat_mode() {
    if [ "$OS" = "macos" ]; then
        local m; m=$(bb stat -f '%Op' "$1" 2>/dev/null) && printf '%s' "${m: -4}"
    else
        bb stat -c '%a' "$1" 2>/dev/null
    fi
}
_sha256_stdin() {
    [ "$SHA256_CMD" = "none" ] && { cat >/dev/null; echo ""; return; }
    $SHA256_CMD 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1
}
_b64decode() {
    if [ "$OS" = "macos" ]; then base64 -D 2>/dev/null
    else base64 -d 2>/dev/null; fi
}

# ----------------------------------------------------------------------------
# MODULE: PE section parsing (for .mdb ClamAV signatures — PE section hashes)
#
# Parses just enough of the PE/COFF header to find each section's raw
# offset and raw size within the file: DOS header -> e_lfanew -> PE
# signature -> COFF header (NumberOfSections, SizeOfOptionalHeader) ->
# section table (40 bytes/entry, PointerToRawData @ +20, SizeOfRawData
# @ +16). Only the first 4096 bytes are read, which covers the header of
# virtually every real-world PE file.
# ----------------------------------------------------------------------------
_hex_byte() {
    local h="${1:$(( $2 * 2 )):2}"
    [ -z "$h" ] && { echo 0; return; }
    echo $((16#$h))
}
_hex_le16() {
    echo $(( $(_hex_byte "$1" "$2") + $(_hex_byte "$1" $(($2+1))) * 256 ))
}
_hex_le32() {
    echo $(( $(_hex_byte "$1" "$2") \
             + $(_hex_byte "$1" $(($2+1))) * 256 \
             + $(_hex_byte "$1" $(($2+2))) * 65536 \
             + $(_hex_byte "$1" $(($2+3))) * 16777216 ))
}

# Prints "offset\tsize" per PE section, one per line. Returns non-zero (no
# output) if the file isn't a well-formed PE within the first 4096 bytes.
_pe_section_table() {
    local file="$1"
    local hexdump
    hexdump=$(bb dd if="$file" bs=4096 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
    [ -z "$hexdump" ] && return 1
    local hexlen=${#hexdump}

    [ "${hexdump:0:4}" != "4d5a" ] && return 1

    local e_lfanew
    e_lfanew=$(_hex_le32 "$hexdump" 60)
    [ "$e_lfanew" -le 0 ] 2>/dev/null && return 1
    [ $(( (e_lfanew + 24) * 2 )) -gt "$hexlen" ] && return 1
    [ "${hexdump:$((e_lfanew*2)):8}" != "50450000" ] && return 1

    local num_sections opt_hdr_size sec_table_off
    num_sections=$(_hex_le16 "$hexdump" $((e_lfanew+6)))
    opt_hdr_size=$(_hex_le16 "$hexdump" $((e_lfanew+20)))
    sec_table_off=$((e_lfanew + 24 + opt_hdr_size))

    local i off ptr rawsize
    for ((i = 0; i < num_sections && i < 96; i++)); do
        off=$((sec_table_off + i * 40))
        [ $(( (off + 40) * 2 )) -gt "$hexlen" ] && break
        rawsize=$(_hex_le32 "$hexdump" $((off+16)))
        ptr=$(_hex_le32 "$hexdump" $((off+20)))
        [ "$rawsize" -gt 0 ] 2>/dev/null && printf '%s\t%s\n' "$ptr" "$rawsize"
    done
}

# Batched (size, md5) lookup for a set of candidate PE files' sections
# against mdb.tsv. Same rationale as the other batch functions: mdb.tsv can
# be millions of lines for a real ClamAV database, so the per-call cost is
# paid once for the whole batch, not once per file.
process_pe_batch() {
    [ $# -eq 0 ] || [ "$HAS_MDB" = false ] && return

    local tmp_candidates
    tmp_candidates=$(mktemp 2>/dev/null) || return
    local -a cand_file=() cand_off=() cand_sz=() cand_md5=()
    local idx=0 f sections off sz sec_md5

    for f in "$@"; do
        sections=$(_pe_section_table "$f" 2>/dev/null) || continue
        [ -z "$sections" ] && continue
        while IFS=$'\t' read -r off sz; do
            [ -z "$sz" ] || [ "$sz" -le 0 ] 2>/dev/null && continue
            [ "$sz" -gt 20971520 ] && continue   # 20MB/section sanity cap
            sec_md5=$(tail -c "+$((off+1))" "$f" 2>/dev/null | head -c "$sz" | $MD5_CMD 2>/dev/null | bb grep -oE '[0-9a-f]{32}' | head -1)
            [ -z "$sec_md5" ] && continue
            printf '%s\t%s\n' "$sz" "$sec_md5" >> "$tmp_candidates"
            cand_file[$idx]="$f"; cand_off[$idx]="$off"; cand_sz[$idx]="$sz"; cand_md5[$idx]="$sec_md5"
            idx=$((idx + 1))
        done <<< "$sections"
    done

    if [ -s "$tmp_candidates" ]; then
        local hits
        hits=$(bb grep -F -f "$tmp_candidates" "$SIG_DIR/mdb.tsv" 2>/dev/null)
        if [ -n "$hits" ]; then
            local hsz hhash hname i
            while IFS=$'\t' read -r hsz hhash hname; do
                [ -z "$hhash" ] && continue
                for ((i = 0; i < idx; i++)); do
                    if [ "${cand_sz[$i]}" = "$hsz" ] && [ "${cand_md5[$i]}" = "$hhash" ]; then
                        threat "KNOWN_MALWARE_SECTION" "${cand_file[$i]}" "name=${hname:-Section.Malware}|size=$hsz|md5=$hhash"
                    fi
                done
            done <<< "$hits"
        fi
    fi
    rm -f "$tmp_candidates"
}

_bash_strings() {
    local file="$1" min_len="${2:-6}" max_bytes="${3:-524288}"
    bb dd if="$file" bs="$max_bytes" count=1 2>/dev/null \
    | bb od -An -tx1 -v | tr -s ' ' '\n' | bb grep -v '^\s*$' \
    | bb awk -v min="$min_len" '
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
    magic=$(bb dd if="$1" bs=8 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
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
        bb dd if="$file" bs="$maxb" count=1 2>/dev/null | $STRINGS_CMD -n "$min" 2>/dev/null
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

# threat() — single entry point for any finding: logs it, streams it
# immediately to the persistent live report (so Ctrl+C/SIGTERM mid-scan
# doesn't lose already-found results — see init_live_report in the main
# script), and quarantines the file if enabled. Report line format
# ("TYPE|file|info") is unchanged so build_report/print_report still work.
threat() {
    local type="$1" file="$2" info="${3:-}"
    printf 'THREAT:%s|%s|%s\n' "$type" "$file" "$info" >> "$REPORT"
    THREATS_FOUND=$(( THREATS_FOUND + 1 ))
    if [ -n "$LIVE_REPORT_FILE" ]; then
        # Single printf = single write() syscall = atomic append even with
        # multiple worker processes writing the same file concurrently, as
        # long as the line stays under PIPE_BUF (a few KB) — safe here.
        printf '[%s] [%s] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$type" "$file" "$info" >> "$LIVE_REPORT_FILE" 2>/dev/null
    fi
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

    # Quarantine filename = sha256(original path) + original basename —
    # unique even for same-name files from different directories, without
    # recreating the original directory tree inside quarantine.
    local path_hash qfile ts
    ts=$(date +%s)
    path_hash=$(printf '%s' "$src" | bb sha256sum 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1)
    [ -z "$path_hash" ] && path_hash="$(date +%s%N)_$$"
    qfile="${QUARANTINE_DIR}/${path_hash}_$(basename -- "$src")"

    if mv -f -- "$src" "$qfile" 2>/dev/null; then
        chmod "$QUARANTINE_PERM" "$qfile" 2>/dev/null
        # Manifest for restore: original_path <TAB> quarantined_file <TAB>
        # threat_type <TAB> unix_time. Restore = mv "$qfile" "$src".
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

    # "grep -F -f - sig_file" returns full "hash<TAB>name" lines, not just
    # the hash — the trailing "cut -f1" extracts the clean hash.
    local hits
    hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | bb grep -F -f - "$sig_file" 2>/dev/null | cut -f1)
    if [ -n "$hits" ]; then
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            local tname
            tname=$(bb grep -F -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -d$'\t' -f2)
            local hit_file
            hit_file=$(printf '%s\n' "$out" | bb grep -iE "^${hit_hash}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
            [ -n "$hit_file" ] && threat "KNOWN_MALWARE" "$hit_file" "name=${tname:-Malware}|$htype=$hit_hash"
        done <<< "$hits"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: yara matching
# ----------------------------------------------------------------------------
process_yara_batch() {
    [ $# -eq 0 ] || [ "$HAS_YARA" = false ] || [ "$YARA_CMD" = "none" ] && return

    local yara_out yara_flags=(-d filename= -d filepath= -d extension=)
    # A compiled ruleset (.yarc) MUST be loaded with -C, or yara tries to
    # parse the binary as rule *source* and fails outright.
    case "$YARA_TARGET" in
        *.yarc) yara_flags+=(-C) ;;
    esac

    if [ "$YARA_HAS_SCAN_LIST" = true ]; then
        # YARA 4.0+/YARA-X: --scan-list takes a plain text file of paths
        # (one per line) and scans them in one call with the ruleset
        # loaded/compiled ONCE for the whole batch — this is what LMD's own
        # docs point to for exactly this problem ("YARA CLI can't take a
        # list of arbitrary files directly"). Simpler and a bit faster
        # end-to-end than the symlink-directory fallback below, since it
        # skips one filesystem syscall (symlink create) per file.
        local listfile
        listfile=$(mktemp 2>/dev/null) || return
        printf '%s\n' "$@" > "$listfile"
        yara_out=$($YARA_CMD "${yara_flags[@]}" --scan-list "$YARA_TARGET" "$listfile" 2>/dev/null)
        rm -f "$listfile"
    else
        # Fallback for older yara builds without --scan-list: the CLI only
        # accepts ONE scan target (a file, or a directory with -r), so
        # symlink the whole batch into a throwaway directory and scan that.
        local tmpdir
        tmpdir=$(mktemp -d 2>/dev/null) || return
        local f
        for f in "$@"; do
            ln -sf "$f" "$tmpdir/$(bb basename "$f" 2>/dev/null || basename "$f")_$RANDOM" 2>/dev/null
        done
        yara_out=$($YARA_CMD "${yara_flags[@]}" -r "$YARA_TARGET" "$tmpdir" 2>/dev/null)
        # Symlink names don't map back to real paths 1:1 in this fallback
        # path (RANDOM-suffixed to avoid collisions) — resolve via readlink.
        if [ -n "$yara_out" ]; then
            yara_out=$(echo "$yara_out" | while IFS= read -r l; do
                [ -z "$l" ] && continue
                r=$(echo "$l" | awk '{print $1}')
                p=$(echo "$l" | cut -d' ' -f2-)
                real=$(readlink -f "$p" 2>/dev/null || echo "$p")
                echo "$r $real"
            done)
        fi
        rm -rf "$tmpdir"
    fi

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
# MODULE: heuristics (batched strings/hex matching)
#
# grep -E -f builds its match automaton FROM SCRATCH on every invocation.
# With a realistic ClamAV .ndb+.ldb signature set that's tens/hundreds of
# thousands of patterns, that build alone can take seconds — calling it
# once PER FILE (as before) made a scan of 20k+ files effectively hang.
# Same fix pattern as hashes/YARA: batch many files into one grep call so
# the automaton is built once per batch, not once per file.
# ----------------------------------------------------------------------------
process_heuristic_batch() {
    [ $# -eq 0 ] && return
    { [ "$HAS_STRINGS" = true ] || [ "$HAS_HEX_ERE" = true ]; } || return

    local tmpdir
    tmpdir=$(mktemp -d 2>/dev/null) || return

    local -a idx_to_file=()
    local -a flagged=()
    local i=0 f
    for f in "$@"; do
        idx_to_file[$i]="$f"
        flagged[$i]=0
        [ "$HAS_STRINGS" = true ] && do_strings "$f" 6 524288 > "$tmpdir/${i}.str" 2>/dev/null
        [ "$HAS_HEX_ERE" = true ] && bb dd if="$f" bs=524288 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n' > "$tmpdir/${i}.hex" 2>/dev/null
        i=$((i + 1))
    done

    if [ "$HAS_STRINGS" = true ]; then
        local mf mi orig pat
        while IFS= read -r mf; do
            [ -z "$mf" ] && continue
            mi="${mf##*/}"; mi="${mi%.str}"
            orig="${idx_to_file[$mi]:-}"
            [ -z "$orig" ] && continue
            flagged[$mi]=1
            pat=$(bb grep -F -i -o -f "$SIG_DIR/strings.txt" "$mf" 2>/dev/null | head -1)
            threat "SIG_STRING_MATCH" "$orig" "pattern=${pat:0:50}"
        done < <(bb grep -F -i -l -f "$SIG_DIR/strings.txt" "$tmpdir"/*.str 2>/dev/null)
    fi

    if [ "$HAS_HEX_ERE" = true ]; then
        local mf mi orig hx
        while IFS= read -r mf; do
            [ -z "$mf" ] && continue
            mi="${mf##*/}"; mi="${mi%.hex}"
            [ "${flagged[$mi]:-0}" = "1" ] && continue
            orig="${idx_to_file[$mi]:-}"
            [ -z "$orig" ] && continue
            hx=$(bb grep -E -o -i -f "$SIG_DIR/hex_ere.txt" "$mf" 2>/dev/null | head -1)
            [ -n "$hx" ] && threat "HEX_SIG_MATCH" "$orig" "hex=${hx:0:40}..."
        done < <(bb grep -E -l -i -f "$SIG_DIR/hex_ere.txt" "$tmpdir"/*.hex 2>/dev/null)
    fi

    rm -rf "$tmpdir"
}

check_file_heuristics() {
    local file="$1" size="$2" oct="$3"

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # Base64 payloads
        while IFS= read -r chunk; do
            [ -z "$chunk" ] && continue
            if [ "$HAS_B64" = true ] && [ "$SHA256_CMD" != "none" ]; then
                local dh
                dh=$(printf '%s' "$chunk" | _b64decode | _sha256_stdin)
                if [ -n "$dh" ] && bb grep -qF "$dh" "$SIG_DIR/b64_payloads.tsv" 2>/dev/null; then
                    local bname
                    bname=$(bb grep -F -m 1 "^$dh" "$SIG_DIR/b64_payloads.tsv" | cut -d$'\t' -f2)
                    threat "KNOWN_B64_PAYLOAD" "$file" "name=${bname:-B64.Malware}|b64=${chunk:0:20}..."
                    continue
                fi
            fi
            local magic
            magic=$(printf '%s' "$chunk" | _b64decode 2>/dev/null | bb dd bs=8 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
            case "$magic" in
                7f454c46*) threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=ELF|b64=${chunk:0:20}..." ;;
                4d5a*)     threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=PE_MZ|b64=${chunk:0:20}..." ;;
                2321*)     threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=SCRIPT|b64=${chunk:0:20}..." ;;
            esac
        done < <(bb grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$file" 2>/dev/null | head -20)
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
    # stat/find usually return a 3-digit octal mode ("644") with no
    # setuid/setgid bit. "${oct: -4}" on a string shorter than 4 chars
    # returns EMPTY in bash, so pad with zeros first.
    if [ -n "$oct" ] && [ "$oct" != "0" ]; then
        oct="0000${oct}"
        oct="${oct: -4}"
        (( 8#$oct & 8#6000 )) 2>/dev/null && threat "SUID_SGID" "$file" "perms=$oct"
        (( 8#$oct & 8#0002 )) 2>/dev/null && (( 8#$oct & 8#0111 )) 2>/dev/null && threat "WORLD_WRITABLE_EXEC" "$file" "perms=$oct"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: scan loop (lives inside a function so "local" is valid)
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
                if [ "$SHA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    process_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
                    BATCH_SHA=(); SHA_BATCH_CNT=0
                fi
            fi
            if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
                BATCH_MD5+=("$file")
                MD5_BATCH_CNT=$(( MD5_BATCH_CNT + 1 ))
                if [ "$MD5_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
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
                if [ "$YARA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    process_yara_batch "${BATCH_YARA[@]}"
                    BATCH_YARA=(); YARA_BATCH_CNT=0
                fi
            fi

            # Batched strings/hex heuristic matching (see process_heuristic_batch)
            if [ "$HAS_STRINGS" = true ] || [ "$HAS_HEX_ERE" = true ]; then
                BATCH_HEUR+=("$file")
                HEUR_BATCH_CNT=$(( HEUR_BATCH_CNT + 1 ))
                if [ "$HEUR_BATCH_CNT" -ge "$HEUR_BATCH_SIZE" ]; then
                    process_heuristic_batch "${BATCH_HEUR[@]}"
                    BATCH_HEUR=(); HEUR_BATCH_CNT=0
                fi
            fi

            # Batched PE-section hash matching (.mdb signatures) — only for
            # files whose magic bytes actually look like a PE/MZ executable.
            if [ "$HAS_MDB" = true ] && [ "$magic_type" = "PE_MZ" ]; then
                BATCH_PE+=("$file")
                PE_BATCH_CNT=$(( PE_BATCH_CNT + 1 ))
                if [ "$PE_BATCH_CNT" -ge "$PE_BATCH_SIZE" ]; then
                    process_pe_batch "${BATCH_PE[@]}"
                    BATCH_PE=(); PE_BATCH_CNT=0
                fi
            fi
        fi

        # Cheap per-file checks (base64 payloads, disguised ext, perms)
        check_file_heuristics "$file" "$size" "${oct:-0}"

        [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
    done < "$POOL_FILE"

    # Flush remaining batches
    [ "$SHA_BATCH_CNT" -gt 0 ] && process_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
    [ "$MD5_BATCH_CNT" -gt 0 ] && process_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
    [ "$YARA_BATCH_CNT" -gt 0 ] && process_yara_batch "${BATCH_YARA[@]}"
    [ "$HEUR_BATCH_CNT" -gt 0 ] && process_heuristic_batch "${BATCH_HEUR[@]}"
    [ "$PE_BATCH_CNT" -gt 0 ] && process_pe_batch "${BATCH_PE[@]}"
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
# worker main()
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
