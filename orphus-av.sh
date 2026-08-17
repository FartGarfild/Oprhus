#!/bin/bash
# =============================================================================
# Oprhus AV Scanner Unified (modular + quarantine + real-time + busybox-first)
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
#   --ignore-sigs FILE       Suppress noisy detections without editing
#                            downloaded signature/rule files (which get
#                            overwritten on the next -u). One ERE pattern
#                            per line, matched against "TYPE|info" of each
#                            detection. Default: signatures/ignore_sigs
#                            (auto-created with a commented template).
#   -X, --exclude PATH        Skip this file/directory entirely (repeat for
#                            multiple: -X /path/one -X /path/two). The AV's
#                            own install dir, signature dir, and quarantine
#                            dir are always excluded automatically.
#   -A, --scan-archives      Look inside archives (.zip/.jar/.tar/.tar.gz/
#                            .tgz/.tar.bz2/.tar.xz/.gz/.bz2/.xz, plus .7z/
#                            .rar if 7z/unrar is installed) — off by
#                            default (extraction has real CPU/time cost and
#                            some risk from malformed/huge archives, hence
#                            the safety limits below). A detection inside
#                            an archive is reported against the ARCHIVE
#                            FILE itself (with the internal member path
#                            noted), not a temp path, and quarantine (if
#                            enabled) moves the whole archive.
#   --archive-max-mb N        Skip archives bigger than this, compressed
#                            (default: 200)
#   --archive-ram-max-mb N    Extract archives up to this COMPRESSED size
#                            straight into RAM (/dev/shm) instead of disk
#                            — faster, especially on IOPS-capped hosts
#                            (default: 50). Bigger archives fall back to
#                            disk regardless of --archive-max-mb.
#   --archive-max-extract-mb N Abort extraction past this much decompressed
#                            data — defense against decompression/zip
#                            bombs (default: 500)
#   --archive-max-depth N     How many nested-archive levels to recurse
#                            into, e.g. a zip containing a zip (default: 2)
#   --archive-max-files N     Only scan the first N files inside one
#                            archive (default: 2000)
#   --yara-timeout SECONDS    Abort a single yara call after this long
#                            (default: 30) — protects against a scan
#                            hanging indefinitely on a pathological file.
#                            On a timeout, that batch is retried one file
#                            at a time with a short timeout each: fast
#                            files still get scanned normally, and
#                            whichever one is actually slow gets reported
#                            (as SCAN_TIMEOUT) and skipped instead of
#                            stalling the whole scan.
#   -L, --long-time           Just LOG any single batch call that takes
#                            longer than --long-time-threshold (default:
#                            20s) — batch type, elapsed time, and the
#                            exact file list — to <output>.slow, without
#                            aborting or changing scan behavior at all.
#                            Survives even a successful finish (a separate
#                            file from the main report, which gets
#                            overwritten with the clean summary at the
#                            end) — tail -f it during a scan to watch live.
#   --long-time-threshold N   Seconds threshold for -L above (default: 20)
#   --sandbox-mode MODE       Isolate archive EXTRACTION (the highest-risk
#                            operation — parsing attacker-controlled zip/
#                            tar/7z/rar) as defense-in-depth against a bug
#                            in the extractor itself being exploited by a
#                            malicious archive. auto|bwrap|unshare|chroot|
#                            simple|none (default: none — off, changes
#                            nothing unless explicitly requested). auto
#                            picks the strongest available: bwrap >
#                            unshare > simple. Rewritten from a person's
#                            draft after finding and fixing several real
#                            bugs during review/testing (broken bwrap
#                            argument passing, leaked chroot bind mounts,
#                            missing access to the archive/extraction tool
#                            paths inside the isolated filesystem view).
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
#                            (inotifywait, or polling as fallback). Also
#                            auto-enables -I (incremental) and dpkg SUID
#                            verification (see both below) — real-time's
#                            whole point is running/watching continuously,
#                            which is exactly when both pay off.
#   --watch-interval SEC    Polling interval for the fallback watcher (default: 5)
#   -I, --incremental        Skip files unchanged (mtime+size) since they
#                            were last found clean, using a persistent
#                            cache under the signature dir. Auto-on for -w;
#                            use --no-incremental to force it off there.
#   --incremental-cache PATH Override the cache file location (default:
#                            signatures/.incremental_cache.tsv)
#   --verify-suid            Verify SUID/SGID files against the distro
#                            package manager's checksum DB (dpkg/rpm) to
#                            suppress known-legitimate system binaries
#                            (sudo, su, mount, ...) and flag ones that
#                            don't match as TAMPERED. Off by default for a
#                            one-off scan (the common case: no cache, run
#                            once — dpkg lookups it'll never benefit from
#                            again aren't worth paying for), auto-on for
#                            -w where catching a system binary getting
#                            swapped WHILE something is watching is the
#                            actual point. Use --no-verify-suid to force
#                            it off even under -w.
#   --low-priority           Renice + ionice this process (and everything
#                            it spawns) to the lowest CPU/disk priority, and
#                            default to a single worker unless -j overrides
#                            — for running unobtrusively alongside other
#                            services on the same box (e.g. -w in the
#                            background long-term).
#   -P, --scan-processes     Check running processes for simple rootkit
#                            indicators: a process whose backing binary
#                            was deleted from disk (still running, but
#                            invisible to any file-based scan — the
#                            classic "malware deletes itself, keeps
#                            running in memory" case), a live process
#                            hashing to a known-malware signature, an
#                            LD_PRELOAD hooking indicator, and a process
#                            visible in /proc but hidden from `ps`. Can
#                            run standalone (no -d needed — just checks
#                            processes and exits) or alongside a normal
#                            file scan. Does NOT and cannot reliably catch
#                            a genuine kernel-level (LKM) rootkit, which
#                            can lie to /proc itself same as any tool.
#   -K, --check-kernel        Check kernel image / initramfs / loaded
#                            module (.ko) files against the package
#                            manager's own recorded checksums (dpkg -V
#                            logic) — a tampered boot file or a module not
#                            owned by any package is a strong persistence
#                            indicator. MEANINGLESS RUN AGAINST THE LIVE
#                            SYSTEM if that system's own kernel is what's
#                            compromised (same limitation as -P — it can
#                            lie to this check too). Only really means
#                            something paired with --offline-root, run
#                            from your host's rescue/recovery boot (every
#                            major provider offers one — the practical
#                            cloud-VPS equivalent of a LiveCD).
#   --offline-root PATH       Point every check (including -K, and the
#                            normal file scan via -d) at a MOUNTED, NOT
#                            BOOTED disk instead of the live filesystem —
#                            e.g. after booting your provider's rescue
#                            system and mounting the suspect disk at
#                            /mnt/suspect-root:
#                              ./av.sh --offline-root /mnt/suspect-root \
#                                -K -d /mnt/suspect-root
#                            This is what makes -K meaningful against a
#                            real kernel-level rootkit — everything reads
#                            through the RESCUE kernel, not a potentially
#                            compromised one. Booting into rescue mode
#                            itself is always a manual step through your
#                            provider's control panel — nothing here can
#                            or should try to trigger that automatically
#                            from within a system you don't trust the
#                            kernel of. Incompatible with -P (no running
#                            processes to inspect on an unmounted disk).
#   --sig-in-ram              Force the compiled signature set (hash/YARA
#                            databases) into /dev/shm specifically,
#                            independent of the general RAM-ceiling
#                            decision that governs everything else — for
#                            powerful boxes with room to spare, guarantees
#                            every batch lookup is a RAM hit instead of
#                            hoping the OS page cache wasn't evicted.
#   --deep, --paranoid        One-off scan with maximum scrutiny: turns on
#                            SUID/SGID package verification and archive
#                            scanning (both -w-only by default), skips
#                            incremental-cache shortcuts, and — the main
#                            point — bypasses EVERY automatic suppression
#                            mechanism (ignore_sigs, the vendor-
#                            obfuscation allowlist) so nothing is
#                            filtered out before you see it. The person
#                            decides what's a false positive, not the tool.
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
VERSION="0.2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Re-exec into our OWN bundled bash (see build_bash_from_source /
# --setup), if it's present, and we aren't already running under it — as
# early as possible, before any other code runs. Rootkits (Diamorphine,
# t0rn-style, and others) commonly patch system binaries that admin
# tooling routinely runs through, /bin/bash among them — narrows how much
# of this scan's own execution ever touches a potentially-tampered
# interpreter. AV_NO_REEXEC=1 escapes this (debugging, or intentionally
# testing under system bash).
#
# HONEST LIMIT, stated plainly rather than implied: this does NOT fully
# solve the problem. Whatever shell interprets THIS invocation, up to and
# including the moment this check itself runs, is still exposed — no
# script can fully bootstrap trust in its own interpreter from within
# that same interpreter. Real protection comes from copying av.sh +
# bin/bash from a known-clean source and running "./bin/bash ./av.sh"
# directly, never touching system bash at all. This re-exec narrows
# exposure for the common case (person just runs "bash av.sh" or
# "./av.sh"), it does not eliminate it.
if [ -z "${AV_NO_REEXEC:-}" ] && [ -z "${AV_REEXECD:-}" ] && [ -x "$SCRIPT_DIR/bin/bash" ]; then
    if [ "$(readlink -f "$(command -v bash 2>/dev/null)" 2>/dev/null)" != "$(readlink -f "$SCRIPT_DIR/bin/bash" 2>/dev/null)" ]; then
        AV_REEXECD=1 exec "$SCRIPT_DIR/bin/bash" "$0" "$@"
    fi
fi

# Used everywhere this script launches ANOTHER bash process of its own
# (workers, the extracted setup module) — same reasoning as the re-exec
# above, just extended to child processes too, since a plain literal
# "bash" in those spots would resolve through $PATH to whatever system
# bash provides, undoing the point of re-exec'ing in the first place.
WORKER_BASH="bash"
[ -x "$SCRIPT_DIR/bin/bash" ] && WORKER_BASH="$SCRIPT_DIR/bin/bash"

# --- CLI-configured params (defaults, overridable via parse_args) ---
SIGNATURES="${SCRIPT_DIR}/signatures"
ROOT_DIR="/mnt"
ROOT_DIR_EXPLICIT=""    # set to 1 if -d/--dir was explicitly passed —
                        # lets -P/--scan-processes run standalone (process
                        # scan only, no file tree scan) when -d wasn't given
MAX_SCAN_MB=50
MAX_SCAN_MB_EXPLICIT=""  # set to 1 if -m/--max-size was explicitly
                        # passed — lets --deep raise the default without
                        # overriding a person's own explicit choice
MAX_RAM_MB=500
OUTPUT_FILE=""
LIVE_REPORT_FILE=""    # persistent (outside WORK_DIR) file threats are
                        # appended to AS THEY'RE FOUND, so Ctrl+C/SIGTERM
                        # mid-scan doesn't lose already-detected results
IGNORE_SIGS_FILE=""    # set in init_ignore_sigs(); patterns (ERE, one per
                        # line) matched against "TYPE|info" of each threat —
                        # a match suppresses that detection entirely (no
                        # log, no quarantine). For noisy signatures/rules
                        # that false-positive on specific legitimate
                        # software (e.g. CMSes that ship obfuscated core
                        # files for license protection, which structurally
                        # resembles webshell obfuscation to generic YARA
                        # heuristics). Same idea as LMD's ignore_sigs.
GENERIC_OBFUSCATION_RULES_FILE=""  # see init_vendor_obfuscation_allowlist
KNOWN_VENDOR_OBFUSCATION_FILE=""   # see init_vendor_obfuscation_allowlist
EXCLUDE_PATHS=()        # -X/--exclude PATH (repeatable): extra paths/dirs
                        # to skip. Always ALSO includes the scanner's own
                        # install dir, signature dir, quarantine dir, work
                        # dir, and report files — otherwise scanning a
                        # target that happens to contain the AV's own
                        # installation (e.g. scanning "/" or "/root")
                        # makes every YARA rule/signature file detect
                        # ITSELF, since the signature files literally
                        # contain the patterns being searched for. Logic
                        # lives inline in collect_files(), not a
                        # separately-named function.
DO_UPDATE=false
USE_RAM=true
ARCHIVE_USE_RAM=true   # captured separately from USE_RAM — see comment
                        # where it's set, in init_workers()
SIG_IN_RAM=false       # --sig-in-ram: force the COMPILED signature set
                        # (sha256.tsv/md5.tsv/rules.yarc/mdb.tsv — can be
                        # tens to a couple hundred MB for a real
                        # ClamAV+Maldet+YARA-repo combined database) into
                        # /dev/shm specifically, independent of the
                        # general USE_RAM/low-RAM-profile decision that
                        # governs the rest of WORK_DIR. Off by default —
                        # the low-RAM-profile default (500MB ceiling)
                        # already keeps normal runs modest on RAM; this is
                        # an explicit opt-in for people running on boxes
                        # with room to spare who want every batch's
                        # hash/YARA lookup to be a guaranteed RAM hit
                        # instead of hoping the OS page cache didn't get
                        # evicted partway through a long scan.
NO_RAM_EXPLICIT=""     # set when --no-ram is explicitly passed — the
                        # low-RAM-profile auto-tuning below can force
                        # USE_RAM=false on its own (default RAM ceiling is
                        # 500MB, which trips that), but that heuristic is
                        # about sizing the MAIN ephemeral WORK_DIR (which
                        # scales with worker count) and shouldn't also
                        # block the much smaller, independently-bounded
                        # archive-RAM-extraction feature — see ARCHIVE_USE_RAM.
ALLOW_BUSYBOX=true
MB_KEY=""
WORKERS=""            # empty = "auto", resolved in init_workers()
MAX_HEX_PATTERNS=8000 # cap on compiled hex_ere.txt entries, see compile_signatures
# Batch sizes: real-world testing showed the smaller "smoother progress"
# defaults (50) cost real throughput on weaker hardware — a slow VPS
# genuinely bottlenecks on the fixed per-call cost of grep/yara being paid
# more often, not just perceived choppiness. Raised the defaults back up;
# --batch-size/--heur-batch-size/--pe-batch-size are still there for anyone
# who wants smoother-but-slower progress updates instead.
BATCH_SIZE=200         # files per hash/YARA batch
HEUR_BATCH_SIZE=200    # files per strings/hex heuristic batch
PE_BATCH_SIZE=100      # files per PE-section (.mdb) batch
SANDBOX_MODE="none"    # --sandbox-mode auto|bwrap|unshare|chroot|simple|none
                        # — isolates archive EXTRACTION specifically (the
                        # highest-risk operation: parsing an
                        # attacker-controlled zip/tar/7z/rar). Off by
                        # default; see MODULE: sandboxed extraction in the
                        # worker for the actual implementation.
SANDBOX_USER="nobody"
SANDBOX_MEM_KB=1048576  # 1GB, simple mode only
SANDBOX_CPU_SEC=60
YARA_TIMEOUT_SEC=30    # --yara-timeout: abort a yara call after this many
                        # seconds (yara's own -a flag) — a real scan can
                        # otherwise hang indefinitely on a pathological
                        # file/rule combination (reported in practice: a
                        # live yara process sitting idle-looking but never
                        # finishing on ordinary PHP/JS files). On a
                        # timeout, the batch is retried file-by-file with a
                        # much shorter per-file timeout to both salvage
                        # results from the files that AREN'T the problem
                        # and identify+report the one(s) that are.
LONG_TIME_MODE=false    # -L/--long-time: log any SINGLE batch call that
                        # takes longer than LONG_TIME_THRESHOLD_SEC (batch
                        # type, elapsed time, exact file list) to the live
                        # report — pure observability, no behavior change.
                        # Pairs well with --yara-timeout for cases you
                        # want to actively abort, or use alone just to
                        # monitor "what's slow" without touching behavior.
LONG_TIME_THRESHOLD_SEC=20
SCAN_ARCHIVES=false     # -A/--scan-archives: opt-in (extraction has real
                        # cost and some risk — see MODULE: archive scanning)
ARCHIVE_MAX_MB=200      # skip archives bigger than this (compressed size)
ARCHIVE_MAX_EXTRACT_MB=500 # abort extraction past this much decompressed
                        # data — defense against decompression bombs
ARCHIVE_RAM_MAX_MB=50   # extract archives up to this COMPRESSED size
                        # straight into /dev/shm (RAM) — faster than disk,
                        # especially on IOPS-capped hosts. Bigger archives
                        # fall back to disk (still respects --no-ram /
                        # /dev/shm free-space checks either way) to avoid
                        # unbounded RAM pressure from one huge archive.
ARCHIVE_MAX_DEPTH=2     # how many nested-archive levels to recurse into
ARCHIVE_MAX_FILES=2000  # only scan the first N files inside one archive
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
LOW_PRIORITY=false     # --low-priority: run as unobtrusively as possible
                        # (nice + ionice, fewer workers unless -j overrides)
WORKERS_EXPLICIT=""    # set to 1 if -j/--workers was explicitly passed
INCREMENTAL_MODE=false # -I/--incremental, also auto-enabled for -w unless
                        # --no-incremental explicitly says otherwise — see
                        # MODULE: incremental scan cache
INCREMENTAL_EXPLICIT_OFF=""
INCREMENTAL_CACHE_FILE=""  # default set in init_incremental_cache()
SKIPPED_UNCHANGED=0     # files skipped this run because the cache says
                        # they're unchanged since they were last found clean
SUID_VERIFY_MODE=true   # dpkg/rpm package-checksum verification for
                        # SUID/SGID files — ON BY DEFAULT (changed from
                        # opt-in): the existing "unowned" short-circuit
                        # (see _verify_package_file) already skips the
                        # dpkg lookup entirely for anything outside
                        # /usr,/bin,/sbin,/lib,/opt, so this only costs a
                        # dpkg -S call for the small, fixed set of REAL
                        # system SUID/SGID binaries — not the unbounded
                        # cost the old opt-in gate was guarding against.
                        # Real complaint this fixes: a normal one-off scan
                        # unconditionally reported passwd/sudo/su/mount/
                        # ssh-keysign/etc (every standard Ubuntu SUID
                        # binary, plus its snap-packaged duplicates) EVERY
                        # single run, package-verified-clean or not —
                        # pure noise a person has to re-triage each time.
                        # --no-verify-suid restores the old raw/unverified
                        # behavior if dpkg isn't trusted or available.
SUID_VERIFY_EXPLICIT_OFF=""
DEEP_MODE=false         # --deep/--paranoid: convenience umbrella for a
                        # one-off scan that wants -w's extra scrutiny
                        # (SUID/SGID package verification, archive
                        # scanning) without actually running in real-time
                        # mode — see parse_args for exactly what it sets.
                        # ALSO bypasses every automatic suppression
                        # mechanism (ignore_sigs, vendor-obfuscation
                        # allowlist, incremental cache skip) — the whole
                        # point of a deep pass is maximum precision with
                        # no exclusions at all; the person reviews and
                        # dismisses findings themselves, not the tool.
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
SHA1_CMD="none"
YARA_CMD="none"
YARAC_BIN=""           # path to yarac (compile-time only; empty = not found
GREP_BIN=""            # bundled static grep (bin/grep, see --setup); empty
                        # = fall back to whatever "grep" resolves to on PATH

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
HAS_SETSID=false       # set once in launch_workers()/start_realtime_worker()
                        # — controls whether cleanup() can safely kill each
                        # worker's WHOLE PROCESS GROUP (needed to also kill
                        # a yara/grep/etc subprocess currently running
                        # INSIDE a worker when the worker itself gets
                        # killed — plain `kill $worker_pid` only kills the
                        # worker's own PID, not its in-flight children,
                        # which is exactly what orphaned them running
                        # unkillable in the background after Ctrl+C).
TF=0            # files scanned (total across workers)
TT=0            # threats found (total across workers)
QC=0            # quarantined (total across workers)
SC=0            # suppressed by ignore_sigs (total across workers)
SPEED=0
RPT=""          # final report text

# ============================================================================
# 2. MODULE: platform / cpu
# ============================================================================
#__SETUP_MODULE_START__
# Everything from here through the end of run_self_setup() is the
# self-contained BOOTSTRAP module: platform detection, busybox
# acquisition, and building yara/grep/bash from source. Marked off so it
# can be extracted to its own file (see extract_setup_module below) and
# run/debugged in isolation — the explicit design goal being "should work
# almost anywhere: needs only a filesystem and a kernel, and if the
# system's own tools are compromised or missing, build known-good
# replacements from source rather than trusting whatever's already there."
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
    # FIX (real bottleneck found and measured): busybox's sha256sum is
    # ~1.8x slower than a real coreutils sha256sum on realistic file sizes
    # (confirmed: 340ms vs 188ms hashing 200 files). Combined with the
    # grep lookup fix below, this was the dominant cost in a real scan
    # (hash= was 69% of total time). Same reasoning as bundling a real
    # grep: prefer a known-fast implementation, busybox only as fallback
    # for portability when nothing else is available.
    if command -v sha256sum &>/dev/null; then echo "sha256sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet sha256sum; then echo "$BUSYBOX_BIN sha256sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 256"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -sha256"
    else echo "none"; fi
}

detect_md5() {
    if command -v md5sum &>/dev/null; then echo "md5sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet md5sum; then echo "$BUSYBOX_BIN md5sum"
    elif command -v md5 &>/dev/null; then echo "md5 -q"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -md5"
    else echo "none"; fi
}

detect_sha1() {
    # SHA1 support recovers a real, previously-silent gap: ClamAV's .hsb
    # signature format (same field layout as .hdb: hash:size:name) can
    # contain SHA1 hashes (40 hex chars) alongside MD5/SHA256 — our
    # parser used to only recognize 32 and 64-char hashes, so every SHA1
    # entry in a real daily.hsb/main.hsb was silently dropped, not just
    # skipped-with-a-warning.
    if command -v sha1sum &>/dev/null; then echo "sha1sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet sha1sum; then echo "$BUSYBOX_BIN sha1sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 1"
    elif command -v openssl &>/dev/null; then echo "openssl dgst -sha1"
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
    SHA1_CMD=$(detect_sha1)

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

    if [ -x "$SCRIPT_DIR/bin/grep" ]; then
        echo "  [OK]   grep : bundled at bin/grep (static GNU grep)"
    else
        echo "  [WARN] grep : not bundled, using system/busybox grep instead —"
        echo "         busybox's grep is known to silently miss matches in"
        echo "         files containing NUL bytes, even with -a (confirmed)."
        echo "         Fix: run '$0 --setup' to build a bundled static grep."
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

# Builds a fully static GNU grep from source. Unlike YARA (dynamically
# linked against libcrypto/libc/libm at best), grep has no such
# dependencies once PCRE support is dropped — the result is a genuinely
# static binary, zero runtime dependencies, guaranteed identical behavior
# on every target machine regardless of whatever grep the OS ships.
#
# WHY THIS MATTERS (found empirically, not theoretically): busybox's grep
# silently finds NOTHING in files containing NUL bytes, even with -a —
# confirmed with a real repro (system grep found the match, busybox grep
# didn't, no error either way). Since binary-safe string search is used
# throughout scanning (webshells embedded in otherwise-binary files,
# SIG_STRING_MATCH, base64 payload screening), a correctness gap here is
# a real, silent detection gap — a bundled, known-good grep closes it for
# good instead of hoping the OS's grep behaves.
build_grep_from_source() {
    local version="${SETUP_GREP_VERSION:-3.11}"

    if [ -x "$SCRIPT_DIR/bin/grep" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/grep already present -> nothing to do${Z}"
        return 0
    fi

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"
    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    echo "[*] Downloading GNU grep v${version} source..."
    # Multiple official GNU mirrors — ftp.gnu.org occasionally rate-limits
    # or is geo-blocked on some networks; falling through a short mirror
    # list is cheap insurance against a one-off download failure.
    local grep_urls=(
        "https://ftp.gnu.org/gnu/grep/grep-${version}.tar.gz"
        "https://mirror.team-cymru.com/gnu/grep/grep-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/grep/grep-${version}.tar.gz"
        "https://ftpmirror.gnu.org/grep/grep-${version}.tar.gz"
    )
    local fetched=false gurl
    for gurl in "${grep_urls[@]}"; do
        if net_fetch "$gurl" "$workdir/grep.tar.gz" 30; then
            fetched=true
            break
        fi
    done
    if [ "$fetched" != true ]; then
        echo -e "${R}[FAIL] Could not download grep source from any mirror (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/grep.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/grep-${version}" || exit 1
        echo "[*] Configuring (no PCRE -> no external deps -> true static link)..."
        ./configure --disable-perl-regexp LDFLAGS="-static" >/tmp/av_grep_setup_configure.log 2>&1 || exit 1
        echo "[*] Building..."
        make -j"$(nproc 2>/dev/null || echo 2)" >/tmp/av_grep_setup_make.log 2>&1 || exit 1
        strip ./src/grep 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/grep-${version}/src/grep" ]; then
        echo -e "${R}[FAIL] Build failed — see /tmp/av_grep_setup_configure.log and /tmp/av_grep_setup_make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/grep-${version}/src/grep" "$SCRIPT_DIR/bin/grep"
    chmod +x "$SCRIPT_DIR/bin/grep"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/grep${Z}"
    "$SCRIPT_DIR/bin/grep" --version | head -1
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/grep" 2>&1 | head -1)"
    return 0
}

# Builds a fully static bash from source — same reasoning as grep/yara
# (guaranteed known-good behavior, no dependency on whatever's on the
# host), but with an ADDITIONAL, distinct motivation: a rootkit that
# patches system binaries (classic technique — Diamorphine, t0rn-style,
# LD_PRELOAD hooking) very often includes /bin/bash itself among the
# tools it tampers with, since bash is what most admin tooling (including
# this scanner) runs through. Re-exec'ing early into a bundled, verified
# bash (see the re-exec check near the top of main()) narrows how much of
# the scan ever touches a potentially-compromised interpreter.
#
# HONEST LIMIT: this does NOT fully solve the problem. If the shell that
# runs THIS SPECIFIC INVOCATION (before the re-exec check even executes)
# is itself compromised, that first fraction of a second of execution is
# still exposed — no script can fully bootstrap trust in its own
# interpreter from within that same interpreter. The real protection
# comes from copying av.sh + bin/bash from a KNOWN-CLEAN source and
# invoking "./bin/bash ./av.sh" directly, never touching system bash at
# all. The re-exec is a narrowing of exposure for the common case (person
# just runs "bash av.sh" or "./av.sh"), not a full guarantee.
build_bash_from_source() {
    local version="${SETUP_BASH_VERSION:-5.2.21}"

    if [ -x "$SCRIPT_DIR/bin/bash" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/bash already present -> nothing to do${Z}"
        return 0
    fi

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"
    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    echo "[*] Downloading GNU bash v${version} source..."
    local bash_urls=(
        "https://ftp.gnu.org/gnu/bash/bash-${version}.tar.gz"
        "https://mirror.team-cymru.com/gnu/bash/bash-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"
        "https://ftpmirror.gnu.org/bash/bash-${version}.tar.gz"
    )
    local fetched=false burl
    for burl in "${bash_urls[@]}"; do
        if net_fetch "$burl" "$workdir/bash.tar.gz" 30; then
            fetched=true
            break
        fi
    done
    if [ "$fetched" != true ]; then
        echo -e "${R}[FAIL] Could not download bash source from any mirror (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/bash.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/bash-${version}" || exit 1
        echo "[*] Configuring (static link, no NLS — smaller, fewer moving parts)..."
        ./configure --enable-static-link --disable-nls --without-bash-malloc LDFLAGS="-static" \
            >/tmp/av_bash_setup_configure.log 2>&1 || exit 1
        echo "[*] Building..."
        make -j"$(nproc 2>/dev/null || echo 2)" >/tmp/av_bash_setup_make.log 2>&1 || exit 1
        strip ./bash 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/bash-${version}/bash" ]; then
        echo -e "${R}[FAIL] Build failed — see /tmp/av_bash_setup_configure.log and /tmp/av_bash_setup_make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/bash-${version}/bash" "$SCRIPT_DIR/bin/bash"
    chmod +x "$SCRIPT_DIR/bin/bash"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/bash${Z}"
    "$SCRIPT_DIR/bin/bash" --version | head -1
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/bash" 2>&1 | head -1)"
    return 0
}

run_self_setup() {
    echo -e "${B}=== av_scan.sh self-setup ===${Z}"
    echo "Target: $SCRIPT_DIR/bin/{yara,yarac,grep}"
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

    echo ""
    build_grep_from_source

    echo ""
    build_bash_from_source

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
#__SETUP_MODULE_END__


parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--update)     DO_UPDATE=true; shift ;;
            -r|--max-ram)    MAX_RAM_MB="$2"; shift 2 ;;
            -j|--workers)    WORKERS="$2"; WORKERS_EXPLICIT=1; shift 2 ;;
            -d|--dir)        ROOT_DIR="$2"; ROOT_DIR_EXPLICIT=1; shift 2 ;;
            -s|--sigs)       SIGNATURES="$2"; shift 2 ;;
            -m|--max-size)   MAX_SCAN_MB="$2"; MAX_SCAN_MB_EXPLICIT=1; shift 2 ;;
            -o|--output)     OUTPUT_FILE="$2"; shift 2 ;;
            --ignore-sigs)   IGNORE_SIGS_FILE="$2"; shift 2 ;;
            -X|--exclude)    EXCLUDE_PATHS+=("$2"); shift 2 ;;
            -A|--scan-archives)  SCAN_ARCHIVES=true; shift ;;
            --archive-max-mb)         ARCHIVE_MAX_MB="$2"; shift 2 ;;
            --archive-ram-max-mb)     ARCHIVE_RAM_MAX_MB="$2"; shift 2 ;;
            --archive-max-extract-mb) ARCHIVE_MAX_EXTRACT_MB="$2"; shift 2 ;;
            --archive-max-depth)      ARCHIVE_MAX_DEPTH="$2"; shift 2 ;;
            --archive-max-files)      ARCHIVE_MAX_FILES="$2"; shift 2 ;;
            --yara-timeout)           YARA_TIMEOUT_SEC="$2"; shift 2 ;;
            --sandbox-mode)  SANDBOX_MODE="$2"; shift 2 ;;
            -P|--scan-processes) SCAN_PROCESSES=true; shift ;;
            -K|--check-kernel)   CHECK_KERNEL=true; shift ;;
            --offline-root)      OFFLINE_ROOT="$2"; shift 2 ;;
            --sig-in-ram)        SIG_IN_RAM=true; shift ;;
            --deep|--paranoid)   SUID_VERIFY_MODE=true; SCAN_ARCHIVES=true; DEEP_MODE=true
                                 # Real gap found: the default 10MB deep-
                                 # inspection cap (hash/YARA/strings ALL
                                 # gated on it) silently skipped files
                                 # like /var/lib/clamav/main.cvd (89MB) —
                                 # a blind spot --deep's own "no
                                 # exclusions" philosophy shouldn't have.
                                 # Bumped unless the person ALSO passed an
                                 # explicit -m/--max-size of their own.
                                 [ -z "$MAX_SCAN_MB_EXPLICIT" ] && MAX_SCAN_MB=200
                                 shift ;;
            -L|--long-time)  LONG_TIME_MODE=true; shift ;;
            --long-time-threshold)    LONG_TIME_THRESHOLD_SEC="$2"; shift 2 ;;
            --no-ram)        USE_RAM=false; NO_RAM_EXPLICIT=1; shift ;;
            --no-busybox)    ALLOW_BUSYBOX=false; shift ;;
            -b|--busybox)    BUSYBOX_PATH_ARG="$2"; shift 2 ;;
            --busybox-url)   BUSYBOX_URL_ARG="$2"; shift 2 ;;
            --yara-url)      YARA_URL_ARG="$2"; shift 2 ;;
            --mb-key)        MB_KEY="$2"; shift 2 ;;
            -q|--quarantine) QUARANTINE_ENABLED=true; shift ;;
            --quarantine-dir)  QUARANTINE_ENABLED=true; QUARANTINE_DIR="$2"; shift 2 ;;
            --quarantine-perm) QUARANTINE_PERM="$2"; shift 2 ;;
            -w|--real-time|--realtime) REALTIME_MODE=true; shift ;;
            --low-priority|--background|--bg) LOW_PRIORITY=true; shift ;;
            -I|--incremental)  INCREMENTAL_MODE=true; shift ;;
            --no-incremental)  INCREMENTAL_MODE=false; INCREMENTAL_EXPLICIT_OFF=1; shift ;;
            --verify-suid)     SUID_VERIFY_MODE=true; shift ;;
            --no-verify-suid)  SUID_VERIFY_MODE=false; SUID_VERIFY_EXPLICIT_OFF=1; shift ;;
            --incremental-cache) INCREMENTAL_CACHE_FILE="$2"; shift 2 ;;
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
# --low-priority: renice + ionice the CURRENT process (this main script) —
# children (workers) forked afterward inherit both the nice value and the
# ionice class/priority automatically on Linux, so this one call covers
# the whole process tree without needing to wrap every worker launch.
# Best-effort: missing `ionice` (non-Linux, minimal container) or lack of
# permission to renice just means one less lever pulled, not a failure.
apply_low_priority() {
    [ "$LOW_PRIORITY" = true ] || return 0
    echo -e "${C}[*] --low-priority: reducing CPU/IO priority to stay out of the way${Z}"
    renice -n 19 -p $$ &>/dev/null || true
    if command -v ionice &>/dev/null; then
        # Class 3 = idle: only gets disk I/O when nothing else wants it.
        # Falls back to best-effort class 2 at the lowest priority (7) on
        # kernels/schedulers where idle I/O class isn't available.
        ionice -c 3 -p $$ &>/dev/null || ionice -c 2 -n 7 -p $$ &>/dev/null || true
    fi
}

init_workers() {
    # WORKERS may be set via -j/--workers; otherwise auto by CPU count.
    [ -z "$WORKERS" ] && WORKERS=$(cpu_count)

    # Guard: WORKERS must be a positive int (avoid div-by-zero later in awk).
    case "$WORKERS" in
        ''|*[!0-9]*) WORKERS=$(cpu_count) ;;
    esac
    [ "${WORKERS:-0}" -ge 1 ] 2>/dev/null || WORKERS=1

    # --low-priority: default to a single worker unless the person
    # explicitly asked for more via -j — the whole point is to stay out
    # of the way of everything else running on the box, and running
    # several workers in parallel (even niced/ionice'd) still competes for
    # the same disk/IOPS budget as a single one, just faster and busier.
    if [ "$LOW_PRIORITY" = true ] && [ -z "$WORKERS_EXPLICIT" ]; then
        WORKERS=1
    fi

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

    # Capture the person's ORIGINAL --no-ram preference for archive
    # extraction BEFORE the low-RAM-profile auto-tuning below can
    # override USE_RAM — archive RAM extraction is independently bounded
    # by ARCHIVE_RAM_MAX_MB (default 50MB, tiny compared to a worker's own
    # RAM ceiling) and shouldn't be silently disabled just because the
    # overall RAM ceiling looks modest.
    ARCHIVE_USE_RAM="$USE_RAM"

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

count_suppressed() {
    bb grep -h "^SUPPRESSED:" "$WORK_DIR/reports"/*.txt 2>/dev/null | cut -d: -f2 | \
        awk '{s+=$1} END {print s+0}'
}

# Locates (or creates, with a helpful commented template) the ignore_sigs
# file — patterns that suppress specific noisy detections without editing
# downloaded signature/rule files (which get overwritten on the next -u).
# Same idea as LMD's ignore_sigs: https://github.com/rfxn/linux-malware-detect
init_ignore_sigs() {
    [ -n "$IGNORE_SIGS_FILE" ] || IGNORE_SIGS_FILE="${SIGNATURES}/ignore_sigs"

    if [ ! -f "$IGNORE_SIGS_FILE" ]; then
        mkdir -p "$(dirname "$IGNORE_SIGS_FILE")" 2>/dev/null
        cat << 'EOF' > "$IGNORE_SIGS_FILE" 2>/dev/null
# Oprhus AV Scanner — ignore_sigs
#
# One extended-regex (ERE) pattern per line, matched against
# "TYPE|info|FILEPATH" of each detection, e.g.:
#   YARA_MATCH|rule=WEBSHELL_PHP_Dynamic_Big|/home/site/upload/engine/init.php
# A match SUPPRESSES that detection entirely — no log entry, no
# quarantine. Patterns match as substrings anywhere on the line, so a
# bare "rule=WEBSHELL_PHP_Dynamic_Big" suppresses that rule EVERYWHERE,
# on every file, on every future scan — including a real webshell on some
# other site that happens to trip the same rule. Prefer scoping to a path
# too, e.g. "rule=WEBSHELL_PHP_Dynamic_Big.*/upload/engine/" only
# suppresses it under that one directory, leaving the rule fully active
# everywhere else.
#
# Use this for signatures/rules that are individually too broad for your
# specific software (e.g. a CMS that ships obfuscated/encoded core files
# for license protection — generic webshell-obfuscation heuristics can't
# tell that apart from an actual backdoor by pattern alone).
#
# Active by default (not commented out) — affects virtually anyone
# scanning system binaries, not specific to any one server: the real
# /usr/sbin/chroot binary (and its snap-packaged duplicates under
# /snap/core*/*/usr/sbin/chroot) contains the literal string "/bin/sh -i"
# as part of its own internal fallback-shell logic, not because it's
# compromised. Scoped to paths ending in /sbin/chroot specifically — the
# same pattern text on any OTHER file still triggers normally.
pattern=/bin/sh -i.*/sbin/chroot$
#
# Same class of false positive, different universal system file: the
# netcat-openbsd manual page (/usr/share/man/man1/nc_openbsd.1.gz)
# documents "-e /bin/sh -i"-style usage examples as part of explaining
# what the flag does — text content, not an actual reverse shell.
# Present on any Debian/Ubuntu box with netcat-openbsd installed.
pattern=/bin/sh -i.*nc_openbsd\.1\.gz$
#
# Examples (uncomment / adapt the path to your actual install):
# rule=WEBSHELL_PHP_Dynamic_Big.*/upload/engine/
# rule=WEBSHELL_PHP_Encoded_Big.*/upload/engine/
# rule=EXT_WEBSHELL_PHP_Generic.*/vendor/matomo/device-detector/README\.md
EOF
    fi
}

# Known-vendor-obfuscation allowlist: an ALTERNATIVE to path-based
# ignore_sigs that works automatically on ANY install, no per-server path
# configuration needed. If a file matches one of the "generic" YARA rules
# in GENERIC_OBFUSCATION_RULES_FILE (broad obfuscation heuristics that
# can't distinguish a real backdoor from a vendor protecting their own
# code) AND the SAME file also contains one of the fingerprint strings in
# KNOWN_VENDOR_OBFUSCATION_FILE (distinctive enough that a real attacker
# copying it verbatim to impersonate the vendor would be an unusually
# sophisticated, deliberate move, not a generic webshell), the detection
# is suppressed automatically. Ships pre-populated with DataLife Engine's
# own obfuscator fingerprint (confirmed from real samples: a
# "DataLife Engine - by SoftNews Media Group" header combined with a
# strrev('edoced_46esab') [= "base64_decode" reversed] decode wrapper) —
# add more vendors' fingerprints here as you run into them.
init_vendor_obfuscation_allowlist() {
    [ -n "$GENERIC_OBFUSCATION_RULES_FILE" ] || GENERIC_OBFUSCATION_RULES_FILE="${SIGNATURES}/generic_obfuscation_rules"
    [ -n "$KNOWN_VENDOR_OBFUSCATION_FILE" ] || KNOWN_VENDOR_OBFUSCATION_FILE="${SIGNATURES}/known_vendor_obfuscation"

    if [ ! -f "$GENERIC_OBFUSCATION_RULES_FILE" ]; then
        mkdir -p "$(dirname "$GENERIC_OBFUSCATION_RULES_FILE")" 2>/dev/null
        cat << 'EOF' > "$GENERIC_OBFUSCATION_RULES_FILE" 2>/dev/null
# Oprhus AV Scanner — generic_obfuscation_rules
#
# One ERE pattern per line, matched against a YARA rule NAME. These are
# rules broad/generic enough ("does this look obfuscated at all") that
# they can't tell a real backdoor apart from a vendor obfuscating their
# OWN code (license protection etc) — a match against one of these rule
# names is only auto-suppressed if the SAME file also matches a
# fingerprint in known_vendor_obfuscation (both conditions required, not
# either alone). Add more rule names here as you find other overly-broad
# ones tripping on legitimate vendor code.
^WEBSHELL_PHP_Dynamic_Big$
^WEBSHELL_PHP_Encoded_Big$
^EXT_WEBSHELL_PHP_Generic$
^WEBSHELL_PHP_Generic_Eval$
^WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex$
^WEBSHELL_PHP_OBFUSC_Fopo$
^WEBSHELL_PHP_Gzinflated$
^webshell_php_by_string_obfuscation$
EOF
    fi

    if [ ! -f "$KNOWN_VENDOR_OBFUSCATION_FILE" ]; then
        mkdir -p "$(dirname "$KNOWN_VENDOR_OBFUSCATION_FILE")" 2>/dev/null
        cat << 'EOF' > "$KNOWN_VENDOR_OBFUSCATION_FILE" 2>/dev/null
# Oprhus AV Scanner — known_vendor_obfuscation
#
# One ERE pattern per line — a distinctive fingerprint of a SPECIFIC,
# LEGITIMATE vendor's own code-obfuscation scheme (usually license
# protection on core files, not malware). Only consulted for files that
# ALSO matched a rule listed in generic_obfuscation_rules — this file
# alone never suppresses anything by itself. Add a new line per vendor
# you run into, ideally a string unlikely to appear by accident.
#
# NOTE: grep matches line-by-line — "." does NOT cross newlines here, so
# a pattern spanning e.g. a header comment AND a decode call several
# lines later (real files have a large base64 blob in between) will never
# match. Keep each pattern to something that appears on ONE line.
#
# DataLife Engine (dle-news.ru) — confirmed from real obfuscated core
# files: a "base64_decode" spelled backwards and un-reversed via strrev()
# at decode time (a deliberate trick to dodge naive "eval(base64_decode"
# string signatures — which is also exactly why our OWN eval(base64_decode
# heuristic never caught it either, for what it's worth). Distinctive
# enough on its own without needing to also match the header line.
strrev\('edoced_46esab'\)
EOF
    fi
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

    if [ "$LONG_TIME_MODE" = true ]; then
        : > "${LIVE_REPORT_FILE}.slow" 2>/dev/null
        echo -e "${C}[*] Slow-batch log (-L): ${LIVE_REPORT_FILE}.slow — tail -f it to watch live${Z}"
    fi
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
        # FIX (real crash reproduced): plain system "awk" can silently BE
        # mawk (Ubuntu/Debian's update-alternatives default) — confirmed
        # mawk's regex engine both crashes outright on some ERE patterns
        # this script generates (a bounded quantifier "{n}" immediately
        # followed by a group, e.g. "{64}(:.*)?") AND silently
        # mis-evaluates two-number range quantifiers like "{32,64}"
        # (matches nothing, no error). busybox's awk handles both
        # correctly — already used on the parallel (nproc>1) path below,
        # so use it here too instead of whatever "awk" happens to resolve
        # to on the host.
        bb awk "$awk_code" "$infile" > "$outfile"
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
    local version_flag="$cache_dir/.compiled_version"

    # FIX (real bug reported): the cache freshness check only compared
    # mtimes — it had no idea the SCRIPT ITSELF changed (e.g. a built-in
    # heuristic pattern was fixed/removed). Updating av.sh alone, without
    # also running -u or clearing the cache, silently kept serving the
    # OLD compiled strings.txt/rules forever, so script fixes never took
    # effect for anyone reusing an existing signatures/ directory. Now the
    # cache is also invalidated whenever VERSION doesn't match what it was
    # compiled with.
    local cached_version=""
    [ -f "$version_flag" ] && cached_version=$(cat "$version_flag" 2>/dev/null)

    # FIX (real bug reported): comparing against $sig_input's OWN top-level
    # mtime is fragile — creating ANY new direct child inside it (e.g. an
    # auto-created ignore_sigs or incremental-cache file the first time
    # either feature runs) bumps that mtime, making a cache written
    # SECONDS earlier look "stale" on the very next invocation even though
    # no actual signature data changed (this is exactly what caused
    # "-u finishes, cache is fresh, but the next plain scan recompiles
    # everything anyway"). Compare against the newest mtime among the
    # REAL signature source files instead (excluding .cache/ itself and
    # our own auxiliary state files) — semantically correct (what we
    # actually care about IS whether any signature content changed) and
    # immune to unrelated files appearing alongside it.
    local newest_src=""
    if [ -d "$sig_input" ]; then
        newest_src=$(bb find "$sig_input" -mindepth 1 -not -path '*/.cache/*' \
            -not -name "ignore_sigs" -not -name ".incremental_cache.tsv" \
            -newer "$compiled_flag" -print -quit 2>/dev/null)
    fi

    if [ "$DO_UPDATE" != true ] && [ -f "$compiled_flag" ] && [ -z "$newest_src" ] && [ "$cached_version" = "$VERSION" ]; then
        echo -e "[*] Signatures already compiled -> reusing cache ($cache_dir)"
        mkdir -p "$out_dir"
        cp -f "$cache_dir"/sha256.tsv "$cache_dir"/sha1.tsv "$cache_dir"/md5.tsv "$cache_dir"/hex_ere.txt \
              "$cache_dir"/strings.txt "$cache_dir"/b64_payloads.tsv "$cache_dir"/mdb.tsv \
              "$cache_dir"/str_sig_map.tsv "$out_dir/" 2>/dev/null || true
        [ -d "$cache_dir/yara" ] && cp -rf "$cache_dir/yara" "$out_dir/" 2>/dev/null
        return 0
    fi
    [ -n "$cached_version" ] && [ "$cached_version" != "$VERSION" ] && \
        echo -e "${Y}[*] av.sh version changed ($cached_version -> $VERSION) -> recompiling signatures${Z}"

    echo -e "[*] Compiling signatures into flat artifacts..."

    # Built-in heuristics
    # FIX (real false positives reported): "chmod 777" as a bare literal
    # string was removed — it matched plain INSTALLATION INSTRUCTIONS in
    # docs/language files (e.g. "chmod 777 the cache/ folder"), not just
    # malicious code. The remaining patterns are specific reverse-shell /
    # backdoor indicators unlikely to appear in legitimate documentation.
    cat << 'EOF' > "$out_dir/strings.txt"
eval(base64_decode
/bin/sh -i
bash -i >
nc -e /bin
python -c import socket
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
            -not -name "*.yar" -not -name "*.yara" \
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
                else if (h ~ /^[0-9a-f]{40}$/) print "SHA1\t" h "\t" name
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
                # NOTE: intentionally NOT written as
                # /^[0-9a-fA-F]{64}(:.*)?$/ — mawk (Ubuntu/Debians default
                # "awk" via update-alternatives) crashes outright compiling
                # a bounded quantifier immediately followed by a group
                # (confirmed: "REcompile() - panic: values still on
                # machine stack"). length()+substr() sidesteps it, works
                # identically on every awk implementation.
                if (length(line) >= 64) {
                    hexpart = substr(line, 1, 64)
                    resthex = substr(line, 65)
                    if (hexpart ~ /^[0-9a-fA-F]{64}$/ && (resthex == "" || substr(resthex,1,1) == ":")) {
                        split(line, a, ":")
                        print "SHA256\t" tolower(a[1]) "\t" (a[2] != "" ? a[2] : "Maldet.Hash")
                        next
                    }
                }
                if (length(line) >= 32) {
                    hexpart = substr(line, 1, 32)
                    resthex = substr(line, 33)
                    if (hexpart ~ /^[0-9a-fA-F]{32}$/ && (resthex == "" || substr(resthex,1,1) == ":")) {
                        split(line, a, ":")
                        print "MD5\t" tolower(a[1]) "\t" (a[2] != "" ? a[2] : "Maldet.Hash")
                        next
                    }
                }
                # ClamAV/Maldet-style "hash:size:name". NOTE: not written
                # as {32,64} — separately confirmed mawk silently fails to
                # match ANY input against a two-number range quantifier
                # like {32,64} (no crash, just never matches, which is
                # arguably worse since it fails silently). "+" always
                # works the same everywhere; length(h)==64/32 below already
                # does the real 32-vs-64 disambiguation after split().
                if (line ~ /^[0-9a-fA-F]+:[0-9*]+:/) {
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

    # Guarantee every expected output file exists (even empty) regardless
    # of whether the awk distribution below actually found any matching
    # lines — FIX (real bug found): awk's ">>" only creates a file the
    # first time that specific print branch actually fires, so a
    # signature set with zero SHA1 entries (common — the real ClamAV .hsb
    # format turned out to carry almost none) left sha1.tsv never created
    # at all. Later reads did `wc -l < sha1.tsv` — a MISSING input file
    # for a shell redirect fails at the shell level, which "2>/dev/null"
    # on that same command does NOT suppress (confirmed in practice: a
    # stray "No such file or directory" on stderr despite the redirect).
    touch "$out_dir/sha256.tsv" "$out_dir/sha1.tsv" "$out_dir/md5.tsv" \
          "$out_dir/strings.txt" "$out_dir/b64_payloads.tsv" "$out_dir/hex_ere.txt" \
          "$out_dir/mdb.tsv" 2>/dev/null

    if [ -s "$tmp_raw_sigs" ]; then
        # Distribute the merged processed stream into the .tsv/.txt/.yar outputs
        bb awk -F'\t' -v out="$out_dir" '
            $1 == "SHA256"   { print $2 "\t" $3 >> (out "/sha256.tsv") }
            $1 == "SHA1"     { print $2 "\t" $3 >> (out "/sha1.tsv") }
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

    # Strip known-degenerate hashes: the empty-input MD5/SHA256 constant.
    # A 0-byte file always hashes to the SAME value regardless of content —
    # if any upstream/custom signature source ever contains that hash
    # (whether by genuine upstream data or by our own parsing picking up
    # a blank/malformed field somewhere), every empty file anywhere would
    # match it. This filters both hashes out at the source, as defense in
    # depth alongside the explicit 0-byte skip in the scan paths.
    local empty_md5="d41d8cd98f00b204e9800998ecf8427e"
    local empty_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    local empty_sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    # NOTE: grep -v exits 1 (not an error) when it filters out EVERY line —
    # a plain "&&" chain would then skip the mv and leave the bad entry in
    # place, so the mv runs unconditionally after grep regardless of its
    # exit code.
    if [ -s "$out_dir/md5.tsv" ]; then
        bb grep -v "^${empty_md5}" "$out_dir/md5.tsv" > "$out_dir/md5.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/md5.tsv.tmp" "$out_dir/md5.tsv" 2>/dev/null
    fi
    if [ -s "$out_dir/sha256.tsv" ]; then
        bb grep -v "^${empty_sha256}" "$out_dir/sha256.tsv" > "$out_dir/sha256.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/sha256.tsv.tmp" "$out_dir/sha256.tsv" 2>/dev/null
    fi
    if [ -s "$out_dir/sha1.tsv" ]; then
        bb grep -v "^${empty_sha1}" "$out_dir/sha1.tsv" > "$out_dir/sha1.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/sha1.tsv.tmp" "$out_dir/sha1.tsv" 2>/dev/null
    fi

    # Strip known-overbroad string patterns regardless of source (our own
    # built-in list, custom.strings, OR an external database like maldet's
    # own signature pack — confirmed in practice: "chmod 777" persisted
    # after removing it from our own built-in list, meaning some other
    # source was reintroducing it). "chmod 777" as bare text matches
    # ordinary installation INSTRUCTIONS in docs/language files, not just
    # malicious code — too weak a signal on its own from any source.
    if [ -s "$out_dir/strings.txt" ]; then
        bb grep -v -i "^chmod 777" "$out_dir/strings.txt" > "$out_dir/strings.txt.tmp" 2>/dev/null
        mv -f "$out_dir/strings.txt.tmp" "$out_dir/strings.txt" 2>/dev/null
    fi

    # Dedup strings.txt BEFORE generating YARA rules from it (not after —
    # that was a real bug: the general dedup pass used to run AFTER rule
    # generation, so a pattern appearing twice — e.g. once from the
    # built-in list and once from custom.strings — became TWO separate
    # YARA rules, both matching the same file and double-counting every
    # such hit in the threat total, even though the displayed list looked
    # fine since it dedupes the STRING content, hiding the duplicate).
    [ -s "$out_dir/strings.txt" ] && bb sort -u "$out_dir/strings.txt" -o "$out_dir/strings.txt" 2>/dev/null

    # Move string-based text signatures into the SAME YARA pass used for
    # NDB/LDB/external rules ("максимально задіяти YARA" — requested after
    # confirming the per-file grep -a string search was still a full extra
    # read of every file on top of the YARA pass, base64 scan, and hash
    # computation). One rule per pattern (mirrors the NDB/LDB approach),
    # with a companion name->pattern map so the worker can still report
    # "SIG_STRING_MATCH pattern=..." instead of a raw YARA rule name.
    #
    # NOTE: this is deliberately NOT done for hash signatures (sha256.tsv/
    # md5.tsv) — measured empirically: YARA's hash module evaluates one
    # condition per rule with no literal-atom prefiltering to skip most of
    # them, so a realistic 100k-entry hash database took ~58ms/file to
    # check via YARA vs the current batched "grep -F against a flat file"
    # approach (a few ms/file amortized across a whole batch) — YARA would
    # make hash lookups SLOWER, not faster, at real ClamAV/Maldet database
    # scale (hundreds of thousands of entries). String signatures don't
    # have this problem since they're normal byte/text patterns that DO
    # benefit from YARA's usual prefiltering.
    mkdir -p "$out_dir/yara"
    : > "$out_dir/yara/generated_strings.yar"
    : > "$out_dir/str_sig_map.tsv"
    if [ -s "$out_dir/strings.txt" ]; then
        bb awk -v yarout="$out_dir/yara/generated_strings.yar" -v mapout="$out_dir/str_sig_map.tsv" '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            {
                line = $0
                if (line == "" || line ~ /^#/) next
                rname = "strsig_" NR "_" FILENAME
                gsub(/[^a-zA-Z0-9_]/, "_", rname)
                print "rule " rname " { strings: $a = \"" esc(line) "\" nocase ascii condition: $a }" >> yarout
                print rname "\t" line >> mapout
            }
        ' "$out_dir/strings.txt"
    fi

    # REVERTED (real regression reported): base64-payload screening used
    # to be folded into this same YARA pass via a reserved
    # "__av_av_b64_screen__" regex rule, to save one full-file read per
    # scanned file (an IOPS optimization). In practice, on real DLE
    # installations, this made specific files take 74-113+ SECONDS EACH —
    # confirmed to be exactly DLE's own license-obfuscated engine files,
    # which are (by design) one enormous single-line base64-ish blob.
    # YARA's regex engine scales badly against that shape of content with
    # an unbounded {200,} quantifier, in a way a plain `grep -oE` call
    # (the original, pre-YARA implementation) did not — confirmed by the
    # person: the exact same files processed correctly and faster before
    # this optimization. Reliability beats a marginal IOPS win here, so
    # base64 screening is back to being its own grep pass (see
    # check_file_heuristics -> _check_b64_payload in the worker) — no
    # generated_b64_screen.yar, no "__av_b64_screen__" rule anymore.
    rm -f "$out_dir/yara/generated_b64_screen.yar" 2>/dev/null

    # YARA: gather external rule sources (fetched during -u) plus our own
    # generated NDB/LDB/string rules, and compile them ALL into one
    # ruleset here — so every worker just loads a single pre-compiled
    # rules.yarc instead of each re-parsing rule text from scratch (see
    # MODULE: ClamAV format support above for why this matters at scale).
    #
    # FIX (real gap found on audit): this used to only look in
    # "$sig_input/yara/" — but Maldet's own sigpack ships a real YARA file
    # (rfxn.yara) inside "$sig_input/maldet/", which was never picked up
    # here. Worse, since its extension didn't match hdb/ndb/ldb/mdb, it
    # fell into the GENERIC line-based hash/pattern parser instead, which
    # doesn't understand YARA syntax — so it was silently doing nothing
    # useful with real rule definitions. Now searches ALL of $sig_input
    # for *.yar/*.yara files (any subdirectory, not just yara/), and those
    # files are excluded from sig_files/generic_files below so they're
    # compiled as actual YARA rules, not misrouted as hash/pattern text.
    if [ -d "$sig_input" ]; then
        bb find "$sig_input" -not -path '*/.git/*' -not -path '*/.cache/*' \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | head -500 | while read -r yf; do
            cp "$yf" "$out_dir/yara/" 2>/dev/null || true
        done
    fi

    # "filename"/"filepath"/"extension" are external variables in modern
    # YARA (not automatic built-ins) — plenty of real-world rules reference
    # them, and compilation fails outright if they aren't declared. Empty
    # defaults are fine: this scanner batches many files per yara call, so
    # there's no single "current filename" to give them anyway; rules that
    # depend on a real value just won't match on that condition.
    #
    # IMPORTANT: these -d declarations must be given IDENTICALLY at both
    # yarac (here) and yara scan time (process_yara_batch et al) — tested
    # empirically: compiling WITH -d but scanning WITHOUT (or vice versa)
    # makes yara -C fail with "error: 29" on EVERY file, silently
    # (--scan-list mode doesn't even print the error to a visible stream
    # by default), which would otherwise look exactly like "just no
    # matches" instead of "totally broken".
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

    # Dedup (also collapses now-common ".*"-only variants of what used to be
    # distinct bounded-quantifier patterns)
    for f in sha256.tsv sha1.tsv md5.tsv strings.txt b64_payloads.tsv hex_ere.txt mdb.tsv; do
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
    #
    # FIX (real bug found): cp -rf only overwrites files that exist in the
    # FRESH out_dir/yara — it doesn't delete stray old files already
    # sitting in cache_dir/yara that aren't part of this compile (e.g. a
    # generated_b64_screen.yar left over from a previous script version
    # that no longer generates one at all). rm -rf the cache's yara/ dir
    # first so a recompile can't leave stale artifacts behind.
    mkdir -p "$cache_dir"
    rm -rf "$cache_dir/yara" 2>/dev/null
    cp -f "$out_dir"/sha256.tsv "$out_dir"/sha1.tsv "$out_dir"/md5.tsv "$out_dir"/hex_ere.txt \
          "$out_dir"/strings.txt "$out_dir"/b64_payloads.tsv "$out_dir"/mdb.tsv \
          "$out_dir"/str_sig_map.tsv "$cache_dir/" 2>/dev/null || true
    [ -d "$out_dir/yara" ] && cp -rf "$out_dir/yara" "$cache_dir/" 2>/dev/null
    touch "$compiled_flag" 2>/dev/null || true
    printf '%s' "$VERSION" > "$version_flag" 2>/dev/null || true

    echo -e "  SHA256 : ${C}$(bb wc -l < "$out_dir/sha256.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  SHA1   : ${C}$(bb wc -l < "$out_dir/sha1.tsv" 2>/dev/null | tr -d ' ')${Z}"
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

_sweep_stale_shm_dirs() {
    # FIX (real leftover found in practice: a real archive-extraction
    # directory from Aug 15 was STILL sitting in /dev/shm days later,
    # despite scan_archive() ending with its own rm -rf). Root cause:
    # cleanup()'s worker kill (kill -TERM -$PGID) terminates a worker
    # mid-extraction OUTRIGHT — it never reaches its own cleanup line —
    # and the same is unavoidably true for SIGKILL/a hard crash, which no
    # trap anywhere could ever catch. Sweep any of THIS scanner's own
    # /dev/shm directories at the START of a fresh run instead of trying
    # to make every possible kill path individually reliable — anything
    # found here is guaranteed orphaned, since this run has not yet
    # created any of its own (each run's dirs are freshly randomized via
    # mktemp/$$, so there is zero risk of touching a directory actually
    # in use by another concurrent run).
    [ -d /dev/shm ] || return
    local d
    for d in /dev/shm/av_arch_* /dev/shm/av_chroot.* /dev/shm/av_sigs_* /dev/shm/av_scan_*; do
        [ -d "$d" ] || continue
        rm -rf "$d" 2>/dev/null
    done
    # Same sweep, disk side — _archive_tmpdir()'s non-RAM fallback creates
    # av_arch_* dirs under TMPDIR/tmp too (only its RAM path was covered
    # here before, and separately, that fallback used to have no prefix
    # at all — see the fix in _archive_tmpdir itself). Real leftovers
    # from BEFORE that prefix fix will be un-prefixed "tmp.XXXXXXXXXX" and
    # can't be told apart from unrelated system temp dirs by name alone —
    # those need a one-time manual cleanup; anything created going
    # forward is swept here same as the /dev/shm case.
    local tdir="${TMPDIR:-/tmp}"
    [ -d "$tdir" ] || return
    for d in "$tdir"/av_arch_* "$tdir"/av_chroot.* "$tdir"/av_scan_*; do
        [ -d "$d" ] || continue
        rm -rf "$d" 2>/dev/null
    done
    # FIX (real leak found in practice — grew by exactly 3-per-worker on
    # every Ctrl+C'd run): av_filtered_* are FILES, not directories (the
    # per-worker filtered ignore_sigs/generic_obfuscation_rules/
    # known_vendor_obfuscation copies) — same orphan-on-interrupt problem,
    # different resource type, so a separate "-f" check rather than "-d".
    for d in "$tdir"/av_filtered_*; do
        [ -f "$d" ] || continue
        rm -f "$d" 2>/dev/null
    done
}

init_workdir() {
    _sweep_stale_shm_dirs
    WORK_DIR=$(choose_work_dir "$USE_RAM" "$WORKERS")
    WORKER_FILE="$WORK_DIR/worker.sh"

    if [ "$SIG_IN_RAM" = true ] && [ "$OS" = "linux" ] && [ -d /dev/shm ]; then
        # Independent of WORK_DIR's own placement (see SIG_IN_RAM global
        # comment) — needs its own free-space check since a real combined
        # ClamAV+Maldet+YARA-repo database's compiled form (sha256.tsv/
        # md5.tsv/mdb.tsv/rules.yarc) can run into the hundreds of MB.
        local sig_needed=300 sig_avail
        sig_avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        if [ "${sig_avail:-0}" -ge "$sig_needed" ]; then
            SIG_DIR="/dev/shm/av_sigs_$$"
        else
            echo -e "${Y}[WARN] --sig-in-ram requested but /dev/shm doesn't have enough free space (need ~${sig_needed}MB, have ${sig_avail:-0}MB) -> falling back to normal placement${Z}"
            SIG_DIR="$WORK_DIR/sigs"
        fi
    else
        SIG_DIR="$WORK_DIR/sigs"
    fi

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

# Pulls the bootstrap/setup module (detect_platform through run_self_setup
# — see #__SETUP_MODULE_START__/_END__ markers) out into its own runnable
# script, same technique as extract_worker() above. Written to a
# PERSISTENT location next to this script (not the ephemeral WORK_DIR
# used for scan runs) specifically so it stays around afterward for
# independent debugging: edit it, re-run it directly with plain
# `bash setup_module.sh --setup [--force]`, without needing to invoke the
# whole scanner or touch any scan-related code at all.
extract_setup_module() {
    local target="${1:-$SCRIPT_DIR/setup_module.sh}"
    {
        echo '#!/bin/bash'
        echo '# Auto-extracted bootstrap/setup module — see av.sh for the source of'
        echo '# truth (#__SETUP_MODULE_START__/_END__ markers). Safe to run standalone:'
        echo '#   bash setup_module.sh --setup [--force]'
        echo 'SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"'
        echo 'R="" G="" Y="" C="" B="" Z=""'
        echo '[ -t 1 ] && { R="\033[0;31m"; Y="\033[1;33m"; G="\033[0;32m"; C="\033[0;36m"; B="\033[1m"; Z="\033[0m"; }'
        echo 'YARA_URL_ARG="${YARA_URL_ARG:-}"'
        echo 'SETUP_FORCE="${SETUP_FORCE:-false}"'
        echo 'SETUP_COMPILE_ONLY="${SETUP_COMPILE_ONLY:-false}"'
        echo 'BUSYBOX_BIN="${BUSYBOX_BIN:-}"'
        echo 'ALLOW_BUSYBOX="${ALLOW_BUSYBOX:-true}"'
        echo 'OS=""; ARCH=""'
        local inside=false
        while IFS= read -r ln; do
            [ "$ln" = "#__SETUP_MODULE_START__" ] && { inside=true; continue; }
            [ "$ln" = "#__SETUP_MODULE_END__" ] && break
            $inside && printf '%s\n' "$ln"
        done < "$0"
        echo ''
        echo 'detect_platform'
        echo 'case "$1" in --force) SETUP_FORCE=true ;; esac'
        echo 'run_self_setup'
    } > "$target"
    chmod +x "$target"
}

# ============================================================================
# MODULE: process/memory anomaly scanning (-P/--scan-processes)
#
# Addresses a specific, real gap in pure file-tree scanning: a process can
# keep running after its own backing executable is deleted from disk (the
# kernel keeps the inode open as long as something references it) — the
# exact "видаляє процес й лишається тільки в ОЗУ" scenario. A file-based
# scanner alone can NEVER see this, no matter how good its signatures are,
# since there's no file left to check.
#
# HONEST SCOPE — stated plainly, not just implied: this catches simple,
# common rootkit techniques (deleted binaries, ps/proc hiding via
# userspace hooks, LD_PRELOAD injection). It does NOT and CANNOT reliably
# catch a genuine kernel-level (LKM) rootkit — one that patches the
# kernel itself can lie to /proc, ps, and every other userspace tool
# equally, INCLUDING this one, since we go through the exact same syscalls
# everything else does. Real detection at that level needs analysis from
# OUTSIDE the running kernel (offline disk/memory forensics), which is a
# fundamentally different tool than a bash-based file/process scanner.
# This module is a real, useful net for the common case, not a guarantee.
# ============================================================================
SCAN_PROCESSES=false   # -P/--scan-processes

scan_processes() {
    echo -e "${B}[*] Scanning running processes for rootkit indicators...${Z}"
    [ -d /proc ] || { echo -e "${Y}[WARN] /proc not available -> skipping process scan${Z}"; return; }

    local pid_dir pid exe_link cmdline found=0

    # --- 1. Deleted-binary check + known-malware hash check for live exes ---
    # Reuses the ALREADY-COMPILED hash database (same sha256.tsv/md5.tsv
    # the file scan uses) — a process running a KNOWN-BAD binary gets
    # caught the same way a file would, just read from /proc/PID/exe
    # instead of a path on the tree.
    local has_hash_db=false
    [ -s "$SIG_DIR/sha256.tsv" ] && has_hash_db=true

    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"
        [ -r "$pid_dir/exe" ] || continue
        exe_link=$(readlink "$pid_dir/exe" 2>/dev/null)
        [ -z "$exe_link" ] && continue
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 150)

        case "$exe_link" in
            *" (deleted)")
                local real_path="${exe_link% (deleted)}"
                echo -e "${R}[!] [PROCESS_DELETED_BINARY] PID=${pid} exe=${real_path} cmdline=${cmdline}${Z}"
                found=$(( found + 1 ))
                ;;
            *)
                if [ "$has_hash_db" = true ] && [ -r "$pid_dir/exe" ]; then
                    local h
                    h=$($SHA256_CMD "$pid_dir/exe" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
                    if [ -n "$h" ] && bb grep -qF "$h" "$SIG_DIR/sha256.tsv" 2>/dev/null; then
                        local n; n=$(bb grep -m1 "^$h" "$SIG_DIR/sha256.tsv" | cut -f2)
                        echo -e "${R}[!] [PROCESS_KNOWN_MALWARE] PID=${pid} exe=${exe_link} name=${n:-Malware} cmdline=${cmdline}${Z}"
                        found=$(( found + 1 ))
                    fi
                fi
                ;;
        esac

        # LD_PRELOAD is the classic userspace hooking-rootkit technique
        # (intercepting libc calls like readdir/stat to hide files or
        # processes) — a process running with it set is at minimum worth
        # a look, even though plenty of legitimate tools use it too
        # (this is a LEAD to check, not proof by itself).
        if [ -r "$pid_dir/environ" ]; then
            local preload
            preload=$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | bb grep "^LD_PRELOAD=" | head -1)
            if [ -n "$preload" ]; then
                echo -e "${Y}[!] [PROCESS_LD_PRELOAD] PID=${pid} ${preload} cmdline=${cmdline}${Z}"
                found=$(( found + 1 ))
            fi
        fi
    done

    # --- 2. /proc vs ps cross-check ---
    # A classic sign of a userspace rootkit hiding a process: it still has
    # a live /proc/PID entry (the kernel itself isn't lying, only ps/ls
    # are being fooled — e.g. via a hooked readdir()), but doesn't show up
    # in `ps`. Re-verified against a SECOND /proc sample before reporting
    # — a discrepancy from ordinary process churn (something exiting
    # between the two enumeration passes) is expected noise, not a
    # finding, and would NOT survive a re-check moments later.
    if command -v ps &>/dev/null; then
        local proc_pids ps_pids missing p still_there
        proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
        ps_pids=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
        missing=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") 2>/dev/null)
        if [ -n "$missing" ]; then
            sleep 0.3
            still_there=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
            for p in $missing; do
                [ -d "/proc/$p" ] || continue   # already exited -> just churn
                if ! echo "$still_there" | grep -qx "$p"; then
                    local pcmd; pcmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | head -c 150)
                    echo -e "${R}[!] [PROCESS_HIDDEN_FROM_PS] PID=${p} visible in /proc but not ps, twice -- cmdline=${pcmd}${Z}"
                    found=$(( found + 1 ))
                fi
            done
        fi
    fi

    if [ "$found" -eq 0 ]; then
        echo -e "${G}[OK] No process anomalies detected${Z} (deleted binaries, known-malware hashes, LD_PRELOAD, ps/proc mismatch)"
    else
        echo -e "${Y}[*] ${found} process anomaly(ies) flagged above${Z} — investigate manually; this module cannot auto-quarantine a running process."
    fi
    echo -e "${C}[*] Note: catches simple/userspace rootkit techniques only — cannot see through a genuine kernel-level (LKM) rootkit, which can lie to /proc itself.${Z}"
}

# ============================================================================
# MODULE: kernel/boot integrity check (-K/--check-kernel, --offline-root)
#
# THE POINT OF THIS MODULE ONLY HOLDS IF RUN FROM A TRUSTED KERNEL. Run
# against the LIVE system, this is no better than scan_processes() above —
# still going through whatever kernel is currently running, which a real
# LKM rootkit fully controls and can lie to just like anything else. Its
# real value is when paired with --offline-root: boot your host's rescue
# system (every major provider — Hetzner, DigitalOcean, Vultr, OVH,
# etc. — offers one; it's the practical cloud-VPS equivalent of a LiveCD,
# just triggered manually through their control panel, not something this
# script can do FROM WITHIN a system you don't trust the kernel of), mount
# the suspect disk read-only somewhere (e.g. /mnt/suspect-root), then run:
#   ./av.sh --offline-root /mnt/suspect-root -K -d /mnt/suspect-root
# Now every check here reads through the RESCUE kernel, not the
# potentially-compromised one — which is the entire reason this is
# meaningfully different from running it live.
#
# Checks: kernel image + initramfs + loaded-module files against the
# package manager's OWN recorded checksums (dpkg -V) — a tampered boot
# image or an unowned .ko file are strong persistence indicators. This
# reuses the exact same "package should own this system file" logic
# already built for SUID/SGID verification, just aimed at /boot and
# /lib/modules instead.
#
# ON REMEDIATION: this deliberately only ever REPORTS. A confirmed kernel/
# boot-level compromise is not something to try to surgically fix in
# place — standard incident response is full reinstall from a known-clean
# image, not disinfection, precisely because nothing on a kernel-level-
# compromised system can be trusted to judge its own cleanliness anymore.
# This module's job is to hand you the evidence to make that call, not to
# pretend it can quarantine a kernel the way it quarantines a PHP file.
# ============================================================================
CHECK_KERNEL=false     # -K/--check-kernel
OFFLINE_ROOT=""         # --offline-root PATH — see module comment above

scan_kernel_integrity() {
    local root="${OFFLINE_ROOT:-}"
    echo -e "${B}[*] Checking kernel/boot file integrity...${Z}"
    if [ -z "$root" ]; then
        echo -e "${Y}[WARN] Running against the LIVE kernel — if that kernel is what's"
        echo -e "       compromised, this check can be lied to same as anything else."
        echo -e "       For a check that actually means something against an LKM"
        echo -e "       rootkit: boot your host's rescue/recovery system, mount the"
        echo -e "       disk read-only, and re-run with --offline-root.${Z}"
    fi

    if ! command -v dpkg &>/dev/null; then
        echo -e "${Y}[WARN] dpkg not found -> can't cross-check against package records, skipping${Z}"
        return
    fi

    local dpkg_root_arg=()
    [ -n "$root" ] && dpkg_root_arg=(--root="$root")

    local found=0 pkg md5file relpath expected actual f
    # Every /boot and /lib/modules file that dpkg -S can attribute to a
    # package gets its checksum cross-checked against that package's own
    # record. Files it can't attribute at all (not owned by any package —
    # a hand-dropped .ko, a DKMS-built module, or a genuinely planted
    # rootkit module) are reported separately as lower-confidence
    # "unowned" findings, since legitimate reasons for that exist too
    # (custom-compiled drivers) — worth a look, not proof by itself.
    for f in "${root}/boot"/vmlinuz* "${root}/boot"/initrd* "${root}/boot"/initramfs* \
             $(find "${root}/lib/modules" -name "*.ko" -o -name "*.ko.xz" -o -name "*.ko.zst" 2>/dev/null); do
        [ -f "$f" ] || continue
        relpath="${f#$root/}"
        pkg=$(dpkg "${dpkg_root_arg[@]}" -S "/$relpath" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -z "$pkg" ]; then
            echo -e "${Y}[!] [KERNEL_FILE_UNOWNED] ${f} — not tracked by any installed package${Z}"
            found=$(( found + 1 ))
            continue
        fi
        md5file="${root}/var/lib/dpkg/info/${pkg}.md5sums"
        [ -f "$md5file" ] || md5file="${root}/var/lib/dpkg/info/${pkg%:*}.md5sums"
        [ -f "$md5file" ] || continue
        expected=$(grep -F "  ${relpath}" "$md5file" 2>/dev/null | awk '{print $1}' | head -1)
        [ -z "$expected" ] && continue
        actual=$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)
        if [ "$expected" != "$actual" ]; then
            echo -e "${R}[!] [KERNEL_FILE_TAMPERED] ${f} (package: ${pkg}) — checksum does NOT match package record${Z}"
            found=$(( found + 1 ))
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo -e "${G}[OK] No kernel/boot integrity issues found${Z} against package records"
    else
        echo -e "${R}[*] ${found} kernel/boot finding(s) above.${Z} If this was run with --offline-root"
        echo -e "    (trusted rescue kernel), treat a TAMPERED result as strong evidence for a full"
        echo -e "    rebuild — do not attempt to patch a compromised kernel/module in place."
    fi
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
# Purely informational — looks (shallow, few levels deep, fast) for
# well-known marker files of common CMS platforms in the scan target, to
# label the report with what it's likely looking at. Deliberately does
# NOT exclude or deprioritize anything based on this: a CMS's own
# cache/tmp/upload directories are exactly where a webshell is most
# likely to land (writable, less scrutinized) — auto-excluding them for
# "performance" would create a false sense of thoroughness while
# silently skipping the places that matter most. This is identification
# only, nothing more.
detect_cms() {
    local root="$1" found=()
    [ -d "$root" ] || return
    local f
    for f in "$root"/wp-config.php "$root"/*/wp-config.php; do
        [ -f "$f" ] && { found+=("WordPress"); break; }
    done
    for f in "$root"/configuration.php "$root"/*/configuration.php; do
        [ -f "$f" ] && bb grep -ql "JConfig" "$f" 2>/dev/null && { found+=("Joomla"); break; }
    done
    [ -d "$root/bitrix" ] && found+=("Bitrix")
    for f in "$root"/sites/default/settings.php "$root"/*/sites/default/settings.php; do
        [ -f "$f" ] && { found+=("Drupal"); break; }
    done
    for f in "$root"/engine/data/dbconfig.php "$root"/*/engine/data/dbconfig.php; do
        [ -f "$f" ] && { found+=("DataLife Engine"); break; }
    done
    [ -d "$root/wp-content" ] && [ ${#found[@]} -eq 0 ] && found+=("WordPress")
    for f in "$root"/config.inc.php "$root"/*/config.inc.php; do
        [ -f "$f" ] && bb grep -ql "PrestaShop\|OpenCart" "$f" 2>/dev/null && { found+=("PrestaShop/OpenCart-family"); break; }
    done
    ((${#found[@]})) && { printf '%s' "${found[0]}"; return; }
}

print_banner() {
    echo -e "${B}=================================================${Z}"
    echo -e "${B} Oprhus AV Scanner Unified v${VERSION}${Z}  [OS: $OS | ARCH: $ARCH]"
    echo -e " RAM Ceiling  : ${C}${MAX_RAM_MB} MB${Z}"
    echo -e " Workers      : ${C}${WORKERS}${Z}"
    echo -e " Target       : ${C}${ROOT_DIR}${Z}"
    echo -e " Signatures   : ${C}${SIGNATURES}${Z}"
    echo -e " Max size     : ${C}${MAX_SCAN_MB} MB${Z}"
    local cms_detected; cms_detected=$(detect_cms "$ROOT_DIR")
    [ -n "$cms_detected" ] && echo -e " Detected CMS : ${C}${cms_detected}${Z} (informational only — nothing is excluded based on this)"
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

# ============================================================================
# MODULE: incremental scan cache (-I/--incremental, auto-on for -w)
#
# Persists a "path -> (mtime, size)" record for every file found CLEAN on
# the last run. On a later run, any file whose mtime+size still matches is
# skipped ENTIRELY — never queued to a worker, so it costs zero disk I/O,
# not just a cheap in-worker check. This is the biggest lever on an
# IOPS-capped host for anything that gets rescanned repeatedly (real-time
# mode's base scan being the main case, but works for any repeat scan of
# the same tree via -I).
#
# Cache location defaults under the signature dir (persists like the
# compiled-signature cache) unless overridden with --incremental-cache.
# A file that comes back with a THREAT is never written to the cache, so
# it's always re-verified on the next run rather than silently trusted.
# ============================================================================
init_incremental_cache() {
    [ -n "$INCREMENTAL_CACHE_FILE" ] || INCREMENTAL_CACHE_FILE="${SIGNATURES}/.incremental_cache.tsv"
    mkdir -p "$(dirname "$INCREMENTAL_CACHE_FILE")" 2>/dev/null
    [ -f "$INCREMENTAL_CACHE_FILE" ] || : > "$INCREMENTAL_CACHE_FILE"
}

# Filters $WORK_DIR/all_files_raw.tsv (size\tmode\tmtime\tpath, 4 fields)
# down into $WORK_DIR/all_files.tsv (size\tmode\tpath, the worker's normal
# 3-field format) — dropping any line whose (path, mtime, size) exactly
# matches a cache entry. Sets SKIPPED_UNCHANGED for the final report.
apply_incremental_filter() {
    local raw="$WORK_DIR/all_files_raw.tsv"
    local out="$WORK_DIR/all_files.tsv"

    if [ "$INCREMENTAL_MODE" != true ] || [ ! -s "$INCREMENTAL_CACHE_FILE" ]; then
        bb awk -F'\t' '{print $1"\t"$2"\t"$4}' "$raw" > "$out" 2>/dev/null
        SKIPPED_UNCHANGED=0
        return
    fi

    local skipcount_file="$WORK_DIR/.skipped_count"
    bb awk -F'\t' -v cachefile="$INCREMENTAL_CACHE_FILE" -v skipfile="$skipcount_file" '
        BEGIN {
            while ((getline line < cachefile) > 0) {
                split(line, c, "\t")
                known[c[1] "\x1f" c[2] "\x1f" c[3]] = 1   # path\x1fmtime\x1fsize
            }
            close(cachefile)
        }
        {
            size=$1; mode=$2; mtime=$3; path=$4
            if ((path "\x1f" mtime "\x1f" size) in known) { skipped++; next }
            print size "\t" mode "\t" path
        }
        END { print skipped+0 > skipfile }
    ' "$raw" > "$out" 2>/dev/null
    SKIPPED_UNCHANGED=$(cat "$skipcount_file" 2>/dev/null || echo 0)
}

# Post-scan: merges this run's results back into the cache. Files that
# were scanned (not skipped) and came back clean get added/refreshed;
# files that came back as a THREAT are explicitly dropped from the cache
# (always re-verified next time); files outside this run's scope entirely
# keep whatever cache entry they already had.
update_incremental_cache() {
    [ "$INCREMENTAL_MODE" = true ] || return 0
    local raw="$WORK_DIR/all_files_raw.tsv"
    [ -s "$raw" ] || return 0

    local threat_paths="$WORK_DIR/.threat_paths"
    bb grep -h "^THREAT:" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d'|' -f2 | bb sort -u > "$threat_paths" 2>/dev/null
    [ -f "$threat_paths" ] || : > "$threat_paths"

    local new_cache="${INCREMENTAL_CACHE_FILE}.new"
    bb awk -F'\t' -v threatfile="$threat_paths" -v oldcache="$INCREMENTAL_CACHE_FILE" '
        BEGIN {
            while ((getline line < threatfile) > 0) { threat[line] = 1 }
            close(threatfile)
            while ((getline line < oldcache) > 0) {
                split(line, c, "\t")
                oldval[c[1]] = line
            }
            close(oldcache)
        }
        {
            size=$1; mtime=$3; path=$4
            seen[path] = 1
            if (!(path in threat)) print path "\t" mtime "\t" size
        }
        END {
            for (p in oldval) if (!(p in seen)) print oldval[p]
        }
    ' "$raw" > "$new_cache" 2>/dev/null
    mv -f "$new_cache" "$INCREMENTAL_CACHE_FILE" 2>/dev/null
}

collect_files() {
    echo -e "[*] Collecting file tree..."
    local excl=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")

    # Always exclude the scanner's own footprint (install dir, signature
    # dir, quarantine dir, ephemeral work dir, live report file) —
    # otherwise scanning a target that happens to contain the AV's own
    # installation makes every YARA rule/signature file "detect" itself,
    # since it literally contains the patterns being searched for
    # (confirmed in practice: scanning "/" produced hundreds of
    # self-matches against signatures/yara/*.yar). This logic lives here
    # inline, not in a separately-named function — if you're looking for
    # "init_self_exclude()" from an old comment elsewhere, this is it.
    #
    # FIX (real bug reported): WORK_DIR was missing from this list —
    # SCRIPT_DIR and SIGNATURES were covered, but the EPHEMERAL per-run
    # work directory (worker.sh, reports, extracted setup module) was
    # not, so worker.sh itself — which necessarily contains the literal
    # string patterns this scanner looks for, since that's what a copy
    # of its own detection logic looks like — got flagged scanning its
    # own temp file. Confirmed in practice: "/tmp/av_scan_NNNNN/worker.sh
    # pattern=eval(base64_decode". SIG_DIR listed separately too — it's
    # usually WORK_DIR/sigs (already covered), but --sig-in-ram can place
    # it at its own /dev/shm/av_sigs_NNNNN path outside WORK_DIR entirely.
    local self_paths=("$SCRIPT_DIR" "$SIGNATURES" "$WORK_DIR" "$SIG_DIR")
    [ "$QUARANTINE_ENABLED" = true ] && self_paths+=("$QUARANTINE_DIR")
    local p
    for p in "${self_paths[@]}"; do
        [ -n "$p" ] && excl+=(-not -path "$p" -not -path "${p}/*")
    done
    for p in "$LIVE_REPORT_FILE" "$OUTPUT_FILE"; do
        [ -n "$p" ] && excl+=(-not -path "$p")
    done

    # User-specified extra exclusions (-X/--exclude, repeatable)
    for p in "${EXCLUDE_PATHS[@]}"; do
        [ -n "$p" ] && excl+=(-not -path "$p" -not -path "${p}/*")
    done

    # FIX (real bug found, pre-existing — not introduced by incremental
    # mode): this printf-capability check used to go through bb() (which
    # routes to busybox's find when busybox is bundled/preferred) — but
    # busybox's find does NOT support -printf AT ALL ("unrecognized:
    # -printf"). Since busybox is the preferred path throughout this
    # script, that meant the size/mode-via-printf optimization here had
    # essentially never actually been active in practice: every file fell
    # back to the worker doing individual stat() calls per file instead of
    # getting size+mode for free from the one `find` pass. GNU find (the
    # system one, NOT busybox's) supports -printf properly, so this now
    # explicitly uses `command find` for this specific call, bypassing
    # bb() on purpose — busybox find is still used everywhere else it's
    # actually correct (the plain -print fallback below, and every other
    # find call in the script).
    local sys_find_printf_ok=false
    if [ "$OS" = "linux" ] && command -v find &>/dev/null && command find "$SCRIPT_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
        sys_find_printf_ok=true
    fi

    if [ "$sys_find_printf_ok" = true ]; then
        command find "$ROOT_DIR" -type f "${excl[@]}" -printf "%s\t%m\t%T@\t%p\n" 2>/dev/null > "$WORK_DIR/all_files_raw.tsv"
        apply_incremental_filter
    else
        # No printf-capable find available (BSD find on macOS, or no
        # system find at all) — incremental mode has no effect on this
        # path, every file is always scanned (correct, just not
        # IOPS-optimized here).
        bb find "$ROOT_DIR" -type f "${excl[@]}" -print 2>/dev/null > "$WORK_DIR/all_files.tsv"
        SKIPPED_UNCHANGED=0
    fi
    TOTAL_FILES=$(bb wc -l < "$WORK_DIR/all_files.tsv" | tr -d ' ')
    if [ "${SKIPPED_UNCHANGED:-0}" -gt 0 ] 2>/dev/null; then
        echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z} (skipped ${C}${SKIPPED_UNCHANGED}${Z} unchanged since last clean scan)\n"
    else
        echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z}\n"
    fi
}

split_pools() {
    bb awk -v w="$WORKERS" -v d="$WORK_DIR/reports" '{ print > (d "/pool_" (NR % w) ".txt") }' "$WORK_DIR/all_files.tsv"
}

# Launches CMD... as its own SESSION/PROCESS GROUP LEADER when setsid is
# available (checked once, cached in HAS_SETSID) — this is what lets
# cleanup() below kill a worker's ENTIRE process tree (including whatever
# yara/grep/etc subprocess it currently has running) with one signal,
# instead of only the worker's own PID while any in-flight child gets
# orphaned and keeps running. Falls back to a plain background launch if
# setsid isn't available (non-Linux, minimal container) — cleanup() then
# falls back too, matching the previous (imperfect but not worse) behavior.
_launch_grouped() {
    if [ "$HAS_SETSID" = true ]; then
        setsid "$@" &
    else
        "$@" &
    fi
}

launch_workers() {
    echo -e "[*] Launching ${WORKERS} workers (batch hash + YARA)...\n"
    WORKER_PIDS=()
    command -v setsid &>/dev/null && HAS_SETSID=true
    local pool wid qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"
    for pool in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$pool" ] || continue
        wid=$(basename "$pool" .txt)
        _launch_grouped "$WORKER_BASH" "$WORKER_FILE" \
            "$pool" "$wid" "$WORK_DIR/reports" \
            "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
            "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
            "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
            "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "$LONG_TIME_MODE" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD"
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
        # FIX (real bug reported): process RSS is BLIND to /dev/shm
        # (tmpfs) usage — reading a file from tmpfs doesn't inflate the
        # READING process's own RSS the way heap/stack allocations do,
        # even though tmpfs content is unambiguously real system RAM
        # (confirmed directly: a 50MB file in /dev/shm showed 0 in the
        # reading process's RSS). This under-reported real usage
        # specifically whenever WORK_DIR or --sig-in-ram's SIG_DIR live in
        # /dev/shm (~300MB actual vs ~12MB shown, per the report) — add
        # actual tmpfs usage for both paths on top of process RSS.
        local shm_mb=0 _du
        case "$WORK_DIR" in
            /dev/shm/*)
                _du=$(du -sm "$WORK_DIR" 2>/dev/null | cut -f1)
                shm_mb=$(( shm_mb + ${_du:-0} ))
                ;;
        esac
        case "$SIG_DIR" in
            "$WORK_DIR"/*) : ;;  # already counted above, part of WORK_DIR
            /dev/shm/*)
                _du=$(du -sm "$SIG_DIR" 2>/dev/null | cut -f1)
                shm_mb=$(( shm_mb + ${_du:-0} ))
                ;;
        esac
        mem_mb=$(( mem_mb + shm_mb ))
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
    for p in "${WORKER_PIDS[@]}"; do
        # FIX (real bug reported): a worker currently blocked inside a
        # foreground child call (yara/grep/etc via command substitution)
        # does NOT pass a signal on to that child when the worker itself
        # is killed — the child gets orphaned (re-parented to init) and
        # keeps running/using CPU indefinitely, exactly what was observed:
        # stopping the script left yara processes still loading the CPU.
        # -TERM to the NEGATIVE pid signals the whole PROCESS GROUP at
        # once (worker + whatever it currently has running), but that's
        # only safe/correct when the worker was launched with setsid
        # (guarantees its own PID == its own PGID — otherwise a negative
        # PID could coincidentally target an unrelated process group).
        if [ "$HAS_SETSID" = true ]; then
            kill -TERM -"$p" 2>/dev/null || kill "$p" 2>/dev/null || true
        else
            kill "$p" 2>/dev/null || true
        fi
    done
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
    # SIG_DIR lives OUTSIDE WORK_DIR when --sig-in-ram placed it directly
    # under /dev/shm (see init_workdir) — the rm -rf above wouldn't touch
    # a sibling path, so clean it up explicitly too.
    case "$SIG_DIR" in
        "$WORK_DIR"/*) : ;;  # already covered by the rm -rf above
        /dev/shm/av_sigs_*) rm -rf "$SIG_DIR" 2>/dev/null ;;
    esac
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
    TF=0; TT=0; SC=0
    local r f t
    local th_ms=0 ty_ms=0 tu_ms=0 tp_ms=0 v
    for r in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$r" ] || continue
        f=$(bb grep "^FILES_SCANNED:" "$r" 2>/dev/null | cut -d: -f2)
        t=$(bb grep "^THREATS_FOUND:" "$r" 2>/dev/null | cut -d: -f2)
        TF=$(( TF + ${f:-0} )); TT=$(( TT + ${t:-0} ))
        v=$(bb grep "^TIMING_HASH_MS:" "$r" 2>/dev/null | cut -d: -f2); th_ms=$(( th_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_YARA_MS:" "$r" 2>/dev/null | cut -d: -f2); ty_ms=$(( ty_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_HEUR_MS:" "$r" 2>/dev/null | cut -d: -f2); tu_ms=$(( tu_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_PE_MS:" "$r" 2>/dev/null | cut -d: -f2); tp_ms=$(( tp_ms + ${v:-0} ))
    done
    SC=$(count_suppressed)
    SPEED=0; [ "$ELAPSED_S" -gt 0 ] && SPEED=$(( TF / ELAPSED_S ))

    QC=0
    [ "$QUARANTINE_ENABLED" = true ] && QC=$(count_quarantined)
    local quarantine_line=""
    [ "$QUARANTINE_ENABLED" = true ] && quarantine_line="
 Quarantined        : $QC ($QUARANTINE_DIR)"
    local suppressed_line=""
    [ "${SC:-0}" -gt 0 ] 2>/dev/null && suppressed_line="
 Suppressed (ignore_sigs / known vendor obfuscation): $SC"
    local skipped_line=""
    [ "$INCREMENTAL_MODE" = true ] && skipped_line="
 Skipped (unchanged): $SKIPPED_UNCHANGED (incremental cache: $INCREMENTAL_CACHE_FILE)"

    # Diagnostic time breakdown: these 4 numbers are SUMMED ACROSS ALL
    # WORKERS (so they can individually exceed wall-clock elapsed time when
    # running with multiple workers in parallel — that's expected, compare
    # them to each other and to elapsed*workers, not to elapsed alone).
    # "unaccounted" is whatever's left: per-file base64/disguised/
    # permission checks, file collection, process/fork overhead, and disk
    # I/O wait not otherwise attributed. A large unaccounted share with all
    # 4 named phases small points at I/O (or per-file base64 scan cost)
    # rather than any single batch subsystem.
    local total_batch_ms=$(( th_ms + ty_ms + tu_ms + tp_ms ))
    local elapsed_ms=$(( ELAPSED_S * 1000 * (WORKERS > 0 ? WORKERS : 1) ))
    local unaccounted_ms=$(( elapsed_ms - total_batch_ms ))
    [ "$unaccounted_ms" -lt 0 ] && unaccounted_ms=0
    local timing_line="
 Time breakdown (ms, summed across ${WORKERS} worker(s)):
   hash=${th_ms} yara=${ty_ms} strings/hex=${tu_ms} pe-sections=${tp_ms}
   other/unaccounted=${unaccounted_ms} (per-file checks, I/O wait, overhead)"

    RPT="
=================================================
 SCAN RESULTS  (Oprhus Unified v${VERSION})
=================================================
 OS / Arch          : $OS / $ARCH
 Target             : $ROOT_DIR
 Files Scanned      : $TF
 Threats Found      : $TT${quarantine_line}${suppressed_line}${skipped_line}
 Time Elapsed       : $(printf '%02d:%02d' $(( ELAPSED_S/60 )) $(( ELAPSED_S%60 )))
 Avg Speed          : ${SPEED} files/s
 Workers            : $WORKERS${timing_line}
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
    command -v setsid &>/dev/null && HAS_SETSID=true
    _launch_grouped "$WORKER_BASH" "$WORKER_FILE" \
        "$REALTIME_FIFO" "rt" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
        "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
        "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "$LONG_TIME_MODE" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD"
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
    if [ -n "$REALTIME_WORKER_PID" ]; then
        if [ "$HAS_SETSID" = true ]; then
            kill -TERM -"$REALTIME_WORKER_PID" 2>/dev/null || kill "$REALTIME_WORKER_PID" 2>/dev/null || true
        else
            kill "$REALTIME_WORKER_PID" 2>/dev/null || true
        fi
    fi
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
    apply_low_priority

    # -I is implied by -w unless the person explicitly said --no-incremental
    # — real-time mode's whole point is running the base scan repeatedly
    # (service restarts, periodic re-supervision), and that's exactly the
    # case where NOT re-reading every unchanged file every time matters
    # most on an IOPS-capped host.
    if [ "$REALTIME_MODE" = true ] && [ -z "$INCREMENTAL_EXPLICIT_OFF" ]; then
        INCREMENTAL_MODE=true
    fi

    # --deep/--paranoid overrides incremental caching off regardless of
    # how it got turned on — deep mode means every file gets a full,
    # fresh check, never trusting a cached "was clean before" verdict.
    if [ "$DEEP_MODE" = true ]; then
        INCREMENTAL_MODE=false
    fi

    # SUID_VERIFY_MODE is true by default now (see its declaration) — this
    # block is effectively a no-op today, kept only so --no-verify-suid
    # (which sets SUID_VERIFY_EXPLICIT_OFF) still wins over -w if someone
    # explicitly wants raw/unverified SUID reporting even in real-time mode.
    if [ "$REALTIME_MODE" = true ] && [ -z "$SUID_VERIFY_EXPLICIT_OFF" ]; then
        SUID_VERIFY_MODE=true
    fi

    if [ "$DO_SETUP" = true ]; then
        # Runs through the extracted standalone module (not the inline
        # function directly) — this is the actual, meaningful benefit of
        # having it as a separate file: it's not just "the same code
        # somewhere else", every real --setup run exercises the EXACT
        # file a person would use to debug it standalone, so the two
        # never drift apart.
        extract_setup_module
        local setup_args=()
        [ "${SETUP_FORCE:-false}" = true ] && setup_args+=(--force)
        "$WORKER_BASH" "$SCRIPT_DIR/setup_module.sh" "${setup_args[@]}"
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
    [ -x "$SCRIPT_DIR/bin/grep" ] && GREP_BIN="$SCRIPT_DIR/bin/grep"

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

    if [ "$SCAN_PROCESSES" = true ]; then
        if [ -n "$OFFLINE_ROOT" ]; then
            echo -e "${Y}[WARN] -P/--scan-processes doesn't make sense with --offline-root${Z}"
            echo -e "${Y}       (there are no running processes to inspect on a mounted, not-booted disk) — skipping.${Z}"
        else
            scan_processes
            # -P without an explicit -d means "just check processes" —
            # skip the whole file-tree scan entirely rather than
            # defaulting to scanning /mnt, which the person never asked for.
            if [ -z "$ROOT_DIR_EXPLICIT" ] && [ "$CHECK_KERNEL" != true ]; then
                exit 0
            fi
            echo ""
        fi
    fi

    if [ "$CHECK_KERNEL" = true ]; then
        scan_kernel_integrity
        if [ -z "$ROOT_DIR_EXPLICIT" ]; then
            exit 0
        fi
        echo ""
    fi

    # FIX (real bug reported): these two used to run BEFORE
    # compile_signatures. Both auto-create a file DIRECTLY inside
    # $SIGNATURES the first time they're used (ignore_sigs,
    # .incremental_cache.tsv) — creating a new direct child bumps the
    # PARENT directory's own mtime. compile_signatures' cache-freshness
    # check compares its compiled flag against exactly that parent mtime,
    # so on the very first run after either feature's file didn't exist
    # yet, the freshly-written cache would look "stale" on the VERY NEXT
    # invocation even though nothing about the actual signature data had
    # changed — forcing a full, unnecessary recompile every time (this is
    # what caused "-u finishes, cache is fresh, but the next plain scan
    # recompiles everything anyway"). Running them after compile_signatures
    # sidesteps this entirely — neither has any dependency on running
    # earlier (ignore_sigs is only consulted per-threat during scanning;
    # the incremental cache is only consulted in collect_files(), which
    # itself runs after this point).
    init_ignore_sigs
    init_incremental_cache
    init_vendor_obfuscation_allowlist

    init_live_report

    START_MS=$(now_ms)
    print_banner

    collect_files
    split_pools
    launch_workers

    start_monitor
    # HUP added alongside INT/TERM: closing the terminal/session (not just
    # Ctrl+C) sends SIGHUP to the foreground process group — without
    # trapping it too, the script (and its workers) would die without
    # cleanup running at all, leaving the same kind of orphaned processes
    # this whole fix is about.
    trap cleanup INT TERM HUP

    wait_for_workers

    END_MS=$(now_ms)
    update_incremental_cache
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
    case "$SIG_DIR" in
        "$WORK_DIR"/*) : ;;
        /dev/shm/av_sigs_*) rm -rf "$SIG_DIR" 2>/dev/null ;;
    esac
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

# Tracks archive-extraction directories currently in use by scan_archive()
# — see the trap below and the array-append in scan_archive() itself. If
# this worker gets TERM'd/INT'd while mid-extraction (e.g. the main
# script's cleanup() killing workers on Ctrl+C), it would otherwise die
# outright without ever reaching scan_archive()'s own end-of-function
# rm -rf, leaking the directory (confirmed in practice — a real leftover
# extraction sat in /dev/shm for two days after an interrupted archive
# scan). This is defense-in-depth for the common graceful-interrupt case;
# it cannot catch SIGKILL/a hard crash, which is what the startup sweep
# in the main script's init_workdir() exists for instead — the two
# together cover both the common case and the case nothing can trap.
declare -a _ACTIVE_EXTRACT_DIRS=()
_cleanup_active_extractions() {
    local d
    for d in "${_ACTIVE_EXTRACT_DIRS[@]:-}"; do
        # FIX (real bug found in testing): this array tracks BOTH archive
        # extraction DIRECTORIES and the three filtered pattern FILES
        # (ignore_sigs/generic_obfuscation_rules/known_vendor_obfuscation
        # copies) — but this check was "-d" (directory) only, a leftover
        # from when the array was archive-dirs-only. For the file
        # entries, "-d" is always false, so "&&" short-circuited and
        # rm -rf NEVER ran for them — confirmed directly: the trap fired
        # with the exact correct paths logged, yet the files remained on
        # disk untouched afterward. "-e" (exists, either type) covers both.
        [ -n "$d" ] && [ -e "$d" ] && rm -rf "$d" 2>/dev/null
    done
    exit 143
}
trap _cleanup_active_extractions TERM INT

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
BATCH_SIZE="${15:-200}"       # files per hash/YARA batch
HEUR_BATCH_SIZE="${16:-200}"  # files per strings/hex heuristic batch
PE_BATCH_SIZE="${17:-100}"    # files per PE-section (.mdb) batch
LIVE_REPORT_FILE="${18:-}"    # persistent live threat log (outside the
                               # ephemeral WORK_DIR) — written to immediately
                               # as each threat is found, see threat() below
IGNORE_SIGS_FILE="${19:-}"    # ERE patterns that suppress noisy detections
                               # entirely — see init_ignore_sigs in the main
                               # script
SCAN_ARCHIVES="${20:-false}"
ARCHIVE_MAX_MB="${21:-200}"
ARCHIVE_MAX_EXTRACT_MB="${22:-500}"
ARCHIVE_MAX_DEPTH="${23:-2}"
ARCHIVE_MAX_FILES="${24:-2000}"
ARCHIVE_DEPTH_CUR=0            # current recursion depth, tracked at runtime
USE_RAM="${25:-true}"          # prefer /dev/shm for archive extraction too
GREP_BIN="${26:-}"             # bundled static grep — see MODULE below
SUID_VERIFY_MODE="${27:-false}" # dpkg/rpm checksum verify for SUID/SGID —
                                 # off by default, on for -w (real-time)
YARA_TIMEOUT_SEC="${28:-30}"    # abort a single yara call after this long
                                 # (yara's own -a flag) — see global comment
LONG_TIME_MODE="${29:-false}"   # -L/--long-time: log slow batches
LONG_TIME_THRESHOLD_SEC="${30:-20}"
ARCHIVE_RAM_MAX_MB="${31:-50}"  # extract archives up to this compressed
                                 # size straight into RAM — see global note
ARCHIVE_USE_RAM="${32:-true}"   # explicit --no-ram choice, NOT auto-tuned
                                 # by the low-RAM-profile logic — see main
                                 # script comment where it's captured
GENERIC_OBFUSCATION_RULES_FILE="${33:-}"
KNOWN_VENDOR_OBFUSCATION_FILE="${34:-}"
SANDBOX_MODE="${35:-none}"
SANDBOX_USER="${36:-nobody}"
SANDBOX_MEM_KB="${37:-1048576}"
SANDBOX_CPU_SEC="${38:-60}"
DEEP_MODE="${39:-false}"       # --deep/--paranoid: bypass ALL automatic
                                 # suppression (ignore_sigs, vendor
                                 # obfuscation allowlist) — the whole
                                 # point of deep mode is showing
                                 # everything and letting the person
                                 # decide, not trusting our own filters.
SHA1_CMD="${40:-none}"          # recovers ClamAV .hsb SHA1 entries that
                                 # used to be silently dropped — see
                                 # detect_sha1() in the main script.

REPORT="$REPORT_DIR/${WORKER_ID}.txt"
PROGRESS="$REPORT_DIR/${WORKER_ID}.progress"
FILES_SCANNED=0
THREATS_FOUND=0
SUPPRESSED_FOUND=0
# Coarse per-phase timing (ms), accumulated across all batches this worker
# processes — reported at the end so a slow scan can be diagnosed (CPU/fork
# overhead vs disk I/O vs a specific subsystem) instead of guessed at.
T_HASH_MS=0
T_YARA_MS=0
T_HEUR_MS=0
T_PE_MS=0
T_CHECK_MS=0
_now_ms() {
    date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 ))
}

# FIX (real bug found — not just in the new vendor-obfuscation feature,
# but a LATENT bug in the pre-existing ignore_sigs mechanism too): grep -f
# treats EVERY line of a pattern file as a literal pattern, including
# comment lines starting with "#" — and this script's own auto-generated
# template comments contain unbalanced parentheses (e.g. explaining
# "eval(base64_decode" as prose), which makes grep -f error out entirely
# ("Unmatched ( or \(") on the untouched default template. Strips
# comment/blank lines ONCE per file at worker startup (not on every
# check) into a filtered copy, used for all pattern-file grep -f lookups
# from here on.
_filter_patterns_file() {
    local src="$1" dst="$2"
    [ -n "$src" ] && [ -s "$src" ] || { : > "$dst" 2>/dev/null; return; }
    bb grep -v '^[[:space:]]*#' "$src" 2>/dev/null | bb grep -v '^[[:space:]]*$' > "$dst" 2>/dev/null
}
_IGNORE_SIGS_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_XXXXXX" 2>/dev/null || echo "${TMPDIR:-/tmp}/av_filtered_ignore_sigs.$$")"
_GENERIC_OBFUSCATION_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_XXXXXX" 2>/dev/null || echo "${TMPDIR:-/tmp}/av_filtered_generic_obf.$$")"
_KNOWN_VENDOR_OBFUSCATION_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_XXXXXX" 2>/dev/null || echo "${TMPDIR:-/tmp}/av_filtered_vendor_obf.$$")"
# FIX (real leak found in practice — Ctrl+C during a scan left these
# behind, growing by 3-per-worker on every subsequent interrupted run):
# these three live for the worker's WHOLE lifetime (created once here at
# startup, only removed in finalize_worker() on NORMAL completion) — a
# bare, unprefixed mktemp meant an interrupt anywhere in between leaked
# an unidentifiable "tmp.XXXXXXXXXX" file, same class of bug as the
# archive-extraction directories fixed earlier. Now prefixed (sweepable
# by _sweep_stale_shm_dirs at the next run's startup) AND tracked in the
# same active-resource array the TERM/INT trap already cleans up below.
_ACTIVE_EXTRACT_DIRS+=("$_IGNORE_SIGS_FILTERED" "$_GENERIC_OBFUSCATION_FILTERED" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED")
# NOTE: the actual _filter_patterns_file CALLS happen further down, after
# this worker's own bb() is defined — bb() is a function, and top-level
# code in a bash script runs sequentially as it's reached, so calling
# anything that uses bb() from here (before its definition further below)
# would silently fail (bb not yet a recognized command), leaving the
# filtered files empty. Confirmed exactly this way via direct debug trace.

# "Real" (non-busybox) grep, for the specific searches that need correct
# binary-safe (-a) handling — busybox's grep confirmed to silently miss
# matches in NUL-containing files even with -a. Prefers the bundled static
# build (see --setup / build_grep_from_source), falls back to whatever
# system grep is on PATH, since either is a real GNU/POSIX grep unlike
# busybox's minimal reimplementation.
_real_grep() {
    if [ -n "$GREP_BIN" ] && [ -x "$GREP_BIN" ]; then
        "$GREP_BIN" "$@"
    else
        command grep "$@"
    fi
}
_has_real_grep() {
    { [ -n "$GREP_BIN" ] && [ -x "$GREP_BIN" ]; } || command -v grep &>/dev/null
}
MAX_SIZE=$(( MAX_SCAN_MB * 1024 * 1024 ))

HAS_SHA256=false
HAS_SHA1=false
HAS_MD5=false
HAS_B64=false
HAS_STRINGS=false
HAS_HEX_ERE=false
HAS_YARA=false
HAS_MDB=false
HAS_STR_SIG_MAP=false
YARA_HAS_SCAN_LIST=false
YARA_TARGET=""
BB_APPLETS=""

declare -a BATCH_SHA=()
declare -a BATCH_SHA1=()
declare -a BATCH_MD5=()
declare -a BATCH_YARA=()
declare -a BATCH_HEUR=()
declare -a BATCH_PE=()
SHA_BATCH_CNT=0
SHA1_BATCH_CNT=0
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
    [ -s "$SIG_DIR/sha1.tsv" ] && HAS_SHA1=true
    [ -s "$SIG_DIR/md5.tsv" ] && HAS_MD5=true
    [ -s "$SIG_DIR/b64_payloads.tsv" ] && HAS_B64=true
    [ -s "$SIG_DIR/strings.txt" ] && HAS_STRINGS=true
    [ -s "$SIG_DIR/hex_ere.txt" ] && HAS_HEX_ERE=true
    [ -s "$SIG_DIR/mdb.tsv" ] && HAS_MDB=true
    [ -s "$SIG_DIR/str_sig_map.tsv" ] && HAS_STR_SIG_MAP=true

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

    # String signatures are folded into the YARA ruleset (one rule per
    # pattern, see compile_signatures) whenever both YARA and the
    # name->pattern map are available — that covers the string search in
    # the SAME pass as YARA_MATCH, instead of a separate grep -a read of
    # every file. Only fall back to the standalone grep -a pass in
    # process_heuristic_batch when YARA isn't usable.
    if [ "$HAS_YARA" = true ] && [ "$HAS_STR_SIG_MAP" = true ]; then
        HAS_STRINGS=false
    fi

    # Now safe to filter the pattern files (bb() is defined by this point
    # in the worker — see the NOTE further up where these get declared).
    _filter_patterns_file "$IGNORE_SIGS_FILE" "$_IGNORE_SIGS_FILTERED"
    _filter_patterns_file "$GENERIC_OBFUSCATION_RULES_FILE" "$_GENERIC_OBFUSCATION_FILTERED"
    _filter_patterns_file "$KNOWN_VENDOR_OBFUSCATION_FILE" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED"
}

# ----------------------------------------------------------------------------
# MODULE: low-level helpers (stat / hash / decode / strings / file-type)
# ----------------------------------------------------------------------------
# Translates a "strsig_*" YARA rule name (generated in compile_signatures
# from strings.txt) back into the original pattern text, so results still
# read as "SIG_STRING_MATCH pattern=..." instead of a raw internal rule
# name. Returns empty if the rule isn't a string-signature rule (i.e. a
# real YARA rule from NDB/LDB or an external ruleset).
_resolve_str_sig() {
    local rule="$1"
    [ "$HAS_STR_SIG_MAP" = true ] || return 1
    case "$rule" in
        strsig_*) ;;
        *) return 1 ;;
    esac
    local pat
    pat=$(bb grep -m1 "^${rule}"$'\t' "$SIG_DIR/str_sig_map.tsv" 2>/dev/null | cut -f2-)
    [ -z "$pat" ] && return 1
    echo "$pat"
    return 0
}

# Returns success (0) if a YARA match should be auto-suppressed as known,
# legitimate vendor code-obfuscation (e.g. a CMS encoding its own core
# files for license protection) rather than reported — see
# init_vendor_obfuscation_allowlist in the main script for the two files
# this reads. BOTH conditions must hold, checked cheapest-first: the rule
# that fired has to be in the "too broad to tell obfuscation apart from a
# real backdoor" list, AND the file's own content has to match a known
# vendor's specific fingerprint — a rule-name match alone never suppresses
# anything by itself.
_is_vendor_obfuscation() {
    local rule="$1" file="$2"
    # DEEP_MODE bypasses this too — same reasoning as threat()'s
    # ignore_sigs bypass: --deep means show everything, don't trust any
    # automatic filter, including our own vendor-obfuscation allowlist.
    [ "$DEEP_MODE" = "true" ] && return 1
    [ -s "$_GENERIC_OBFUSCATION_FILTERED" ] || return 1
    [ -s "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" ] || return 1
    echo "$rule" | bb grep -qE -f "$_GENERIC_OBFUSCATION_FILTERED" 2>/dev/null || return 1
    if _has_real_grep; then
        _real_grep -qE -f "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" "$file" 2>/dev/null && return 0
    else
        bb grep -qE -f "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" "$file" 2>/dev/null && return 0
    fi
    return 1
}

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

# Timed wrappers around each batch-processing function — accumulate coarse
# per-phase timing (T_*_MS) so a slow scan can be diagnosed by WHERE time
# actually goes (reported in the final summary) instead of guessed at.
# Deliberately NOT applied to per-file calls (check_file_heuristics) — the
# timing itself forks `date`, and doing that thousands of times would add
# real overhead to exactly what we're trying to measure.
#
# -L/--long-time: when a SINGLE batch call takes longer than
# LONG_TIME_THRESHOLD_SEC, log it immediately (batch type, elapsed time,
# and the exact file list) — pure observability, no behavior change to
# the scan itself. This is the direct "what got stuck" answer requested:
# instead of inferring from a hung-looking process, the log shows exactly
# which batch (and which files in it) was slow, the moment it happens,
# while the scan keeps going.
#
# NOTE: written to a DEDICATED file (LIVE_REPORT_FILE + ".slow"), not
# LIVE_REPORT_FILE itself — on a normal (non-interrupted) finish,
# save_report() in the main script OVERWRITES LIVE_REPORT_FILE with the
# clean final summary, which would silently wipe out every slow-batch
# entry logged during a scan that ultimately completed successfully. A
# separate file survives that regardless of how the scan ends.
_log_if_long() {
    local kind="$1" elapsed_ms="$2"; shift 2
    [ "$LONG_TIME_MODE" = "true" ] || return
    [ $(( elapsed_ms / 1000 )) -ge "$LONG_TIME_THRESHOLD_SEC" ] || return
    [ -n "$LIVE_REPORT_FILE" ] || return
    printf '[%s] [SLOW_BATCH] type=%s elapsed_ms=%d files=%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$kind" "$elapsed_ms" "$*" \
        >> "${LIVE_REPORT_FILE}.slow" 2>/dev/null
}
_timed_hash_batch() {
    local _t0; _t0=$(_now_ms)
    process_hash_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_HASH_MS=$(( T_HASH_MS + _t1 - _t0 ))
    _log_if_long "hash" $(( _t1 - _t0 )) "$@"
}
_timed_yara_batch() {
    local _t0; _t0=$(_now_ms)
    process_yara_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_YARA_MS=$(( T_YARA_MS + _t1 - _t0 ))
    _log_if_long "yara" $(( _t1 - _t0 )) "$@"
}
_timed_heur_batch() {
    local _t0; _t0=$(_now_ms)
    process_heuristic_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_HEUR_MS=$(( T_HEUR_MS + _t1 - _t0 ))
    _log_if_long "heur" $(( _t1 - _t0 )) "$@"
}
_timed_pe_batch() {
    local _t0; _t0=$(_now_ms)
    process_pe_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_PE_MS=$(( T_PE_MS + _t1 - _t0 ))
    _log_if_long "pe" $(( _t1 - _t0 )) "$@"
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

# ----------------------------------------------------------------------------
# MODULE: package-manager integrity check (dpkg/rpm)
#
# Verifies a file against the distro's own package checksum database.
# Result cached per-worker: dpkg -S/-V calls aren't free, but SUID/SGID
# files are rare (dozens, not thousands) so per-file cost is negligible.
# ----------------------------------------------------------------------------
declare -A _PKG_VERIFY_CACHE 2>/dev/null
_verify_package_file() {
    local file="$1"
    [ -n "${_PKG_VERIFY_CACHE[$file]:-}" ] && { echo "${_PKG_VERIFY_CACHE[$file]}"; return; }

    # FIX (real slowdown found and measured): `dpkg -S` on a file that's
    # NOT package-owned takes over a SECOND (confirmed: 1.18s) — it has to
    # linearly scan every installed package's file list before it can
    # conclude there's no match. Package managers only ever install into a
    # known, fixed set of system directories — a SUID/SGID file under a
    # web root or home directory (exactly where this kept firing on a real
    # scan) is essentially guaranteed not to be package-owned, so skip the
    # lookup ENTIRELY for paths outside that set instead of paying ~1s+ to
    # confirm the obvious on every such hit in a content tree. This is
    # what was silently turning "average 8-9 files/s" into "3 files/s" —
    # peak throughput (the batched hash/YARA path) was unaffected, but
    # every SUID/SGID file outside /usr,/bin,/sbin,/lib,/opt added a
    # second-plus synchronous stall outside any batching.
    case "$file" in
        /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*) : ;;
        *)
            _PKG_VERIFY_CACHE[$file]="unowned"
            echo "unowned"
            return
            ;;
    esac

    local result="unowned"
    if command -v dpkg &>/dev/null; then
        local pkg
        # timeout as defense in depth: even within a system dir, an
        # unowned file (manually installed software, etc.) hits the same
        # slow "confirm the negative" path — cap the worst case instead of
        # letting a single lookup stall a whole batch.
        pkg=$(timeout 2 dpkg -S "$file" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -n "$pkg" ]; then
            local md5file="/var/lib/dpkg/info/${pkg}.md5sums"
            [ -f "$md5file" ] || md5file="/var/lib/dpkg/info/${pkg%:*}.md5sums"
            if [ -f "$md5file" ]; then
                local relpath="${file#/}"
                local expected
                expected=$(bb grep -F "  ${relpath}" "$md5file" 2>/dev/null | awk '{print $1}' | head -1)
                if [ -n "$expected" ]; then
                    local actual
                    actual=$(bb md5sum "$file" 2>/dev/null | bb grep -oE '[0-9a-f]{32}' | head -1)
                    if [ "$expected" = "$actual" ]; then
                        result="verified"
                    else
                        result="tampered"
                    fi
                fi
            fi
        fi
    elif command -v rpm &>/dev/null; then
        if timeout 2 rpm -qf "$file" &>/dev/null; then
            local vout
            vout=$(timeout 2 rpm -Vf "$file" 2>/dev/null)
            if [ -z "$vout" ]; then
                result="verified"
            elif echo "$vout" | bb grep -q "^..5"; then
                result="tampered"
            fi
        fi
    fi

    _PKG_VERIFY_CACHE[$file]="$result"
    echo "$result"
}

_bash_file_type() {
    # PERFORMANCE: this is called on essentially every scanned file (YARA
    # skip_deep decision). The old dd+od pipeline forks 2 external
    # processes per call — on millions of files that overhead adds up
    # fast, especially on weaker/shared-CPU hosts. Read the first 8 bytes
    # via bash's own `read` builtin and convert to hex in pure bash — zero
    # forks. Falls back to the dd+od path if the pure-bash read comes up
    # empty for any reason (e.g. exotic filesystem edge cases), so this
    # can't silently lose detection coverage.
    local bytes="" hex="" i c ord
    { IFS= read -r -d '' -n 8 bytes < "$1"; } 2>/dev/null
    if [ -n "$bytes" ]; then
        for (( i=0; i<${#bytes}; i++ )); do
            c="${bytes:$i:1}"
            printf -v ord '%02x' "'$c"
            hex+="$ord"
        done
    fi
    if [ -z "$hex" ]; then
        hex=$(bb dd if="$1" bs=8 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
    fi
    [ -z "$hex" ] && { echo "EMPTY"; return; }
    case "$hex" in
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

# ----------------------------------------------------------------------------
# MODULE: archive scanning (-A/--scan-archives, opt-in)
#
# Extracts supported archive types into a throwaway directory and runs each
# extracted member through the SAME hash/YARA/string checks used for real
# files. Detections are reported against the ARCHIVE FILE itself (not the
# transient extracted path — that stops existing once the scan ends), with
# the internal member path in the info field, so the user always has a
# real, persistent file to act on. If quarantine is enabled, the WHOLE
# ARCHIVE gets quarantined (moving just the extracted copy would leave the
# infected archive sitting right where it was).
#
# Safety limits (all overridable via CLI flags — see usage):
#   - skip archives bigger than ARCHIVE_MAX_MB compressed
#   - abort extraction past ARCHIVE_MAX_EXTRACT_MB decompressed (bomb guard)
#   - only look at the first ARCHIVE_MAX_FILES members
#   - only recurse ARCHIVE_MAX_DEPTH levels into nested archives
#   - every extraction command runs under `timeout`, so a malformed/hostile
#     archive can't hang a worker indefinitely
# ----------------------------------------------------------------------------
_archive_type() {
    case "${1,,}" in
        *.tar.gz|*.tgz)   echo "targz" ;;
        *.tar.bz2|*.tbz2) echo "tarbz2" ;;
        *.tar.xz|*.txz)   echo "tarxz" ;;
        *.tar)            echo "tar" ;;
        *.zip|*.jar|*.war|*.apk|*.ear) echo "zip" ;;
        *.gz)             echo "gz" ;;
        *.bz2)            echo "bz2" ;;
        *.xz)             echo "xz" ;;
        *.7z)             command -v 7z &>/dev/null && echo "7z" ;;
        *.rar)            { command -v unrar &>/dev/null || command -v 7z &>/dev/null; } && echo "rar" ;;
        *) ;;
    esac
}

# ----------------------------------------------------------------------------
# MODULE: sandboxed extraction (optional, --sandbox-mode)
#
# Archive extraction is the highest-risk operation in this whole script:
# it parses an ATTACKER-CONTROLLED file format (zip/tar/7z/rar) with
# external tools that have historically had real vulnerabilities (path
# traversal / "zip slip", decompression bombs, parser buffer overflows).
# This wraps that extraction in an isolation layer as defense-in-depth —
# a bug in unzip/tar/7z exploited by a malicious archive is far less
# dangerous running as an unprivileged, network-less, filesystem-isolated
# process than running as whatever this scanner itself runs as (often
# root, to reach protected files).
#
# Off by default (SANDBOX_MODE=none) — this changes nothing unless
# explicitly requested via --sandbox-mode, and even then only wraps
# archive extraction, not the rest of the scan.
#
# Rewritten from a person's own draft (credited to a suggestion from
# another AI) after finding two real, serious bugs in it during review:
#   1. bwrap mode had "2>/dev/null || true" INSIDE a backslash-continued
#      argument list — that's not a per-argument fallback, it's a real
#      shell "||", so bwrap's later arguments (--proc, --tmpfs, --uid,
#      --gid, and the command to actually run) were silently NEVER
#      passed at all. Confirmed by reproducing the exact pattern: only
#      the arguments before the first "|| true" ever reached the command.
#   2. chroot mode bind-mounted 5 directories but only ever `rm -rf`'d the
#      chroot dir afterward — never unmounted them. Every archive
#      processed would leak 5 more stale bind mounts, accumulating for
#      the life of a long-running scan.
# Both fixed below: conditional binds are built into an ARGS ARRAY with
# separate statements before bwrap ever runs (no inline "|| true" inside
# its argument list), and chroot mode unmounts everything (in reverse
# order) in a trap before removing the directory.
#
# SANDBOX_MODE/SANDBOX_USER/SANDBOX_MEM_KB/SANDBOX_CPU_SEC are already set
# from positional params above (33-38) — no re-declaration needed here.

_sandbox_has() { command -v "$1" &>/dev/null; }

_sandbox_run_bwrap() {
    local target_dir="$1" archive_src="$2"; shift 2
    local args=(
        --unshare-all --new-session --die-with-parent
        --ro-bind /usr /usr
        --proc /proc --dev /dev
        --tmpfs /home --tmpfs /root
        --chdir /tmp
        --setenv HOME /tmp --setenv USER nobody
        --uid 65534 --gid 65534
    )
    # bind /bin, /lib, /lib64, /sbin only if they exist as real entries —
    # checked as SEPARATE statements before the call, not inline in it.
    [ -d /bin ]   && args+=(--ro-bind /bin /bin)
    [ -d /lib ]   && args+=(--ro-bind /lib /lib)
    [ -d /lib64 ] && args+=(--ro-bind /lib64 /lib64)
    [ -d /sbin ]  && args+=(--ro-bind /sbin /sbin)
    # The extraction target dir needs to be WRITABLE inside the sandbox
    # (that's the whole point — the extracted files have to land
    # somewhere this worker can then read back out).
    args+=(--bind "$target_dir" "$target_dir" --tmpfs /tmp)
    # FIX (real bug found in testing): the ARCHIVE FILE ITSELF lives
    # somewhere else entirely (wherever it was found on the scanned
    # tree) — --unshare-all + explicit binds means NOTHING outside those
    # binds is visible at all, so the extraction tool couldn't even open
    # its own input file ("cannot find or open ..."). Bind its containing
    # directory read-only too, same real path as outside, so the
    # extraction command's own "$archive" argument still resolves.
    if [ -n "$archive_src" ]; then
        local archive_dir; archive_dir=$(dirname "$archive_src")
        args+=(--ro-bind "$archive_dir" "$archive_dir")
    fi
    # FIX (second, separate instance of the SAME bug — found right after
    # fixing the first): the extraction tool ITSELF is very often our own
    # bundled busybox (e.g. "$BUSYBOX_BIN unzip"), installed somewhere
    # under this scanner's OWN directory tree — NOT under /bin or /usr, so
    # it was ALSO invisible inside the sandbox, and extraction failed
    # silently for the exact same "can't find the binary" reason.
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        local bb_dir; bb_dir=$(dirname "$BUSYBOX_BIN")
        args+=(--ro-bind "$bb_dir" "$bb_dir")
    fi
    bwrap "${args[@]}" -- "$@"
}

_sandbox_run_unshare() {
    local target_dir="$1" archive_src="$2"; shift 2
    # --user needs unprivileged user namespaces enabled in the kernel —
    # not universal (disabled on some hardened kernels/containers). Falls
    # through to the caller's own fallback chain if this exits non-zero.
    # NOTE: unlike bwrap/chroot, this does NOT pivot/chroot the root
    # filesystem — it only gets its own independent mount table, so the
    # archive's original path stays visible without any extra binding.
    unshare --user --map-root-user --pid --mount --ipc --uts --fork --kill-child -- \
        bash -c 'mount -t proc proc /proc 2>/dev/null || true; cd "$1"; shift; exec "$@"' \
        _ "$target_dir" "$@"
}

_sandbox_run_chroot() {
    local target_dir="$1" archive_src="$2"; shift 2
    [ "$(id -u)" = "0" ] || { "$@"; return; }  # chroot needs root
    local chroot_dir
    chroot_dir=$(mktemp -d /tmp/av_chroot.XXXXXX 2>/dev/null) || { "$@"; return; }
    mkdir -p "$chroot_dir"/{bin,lib,lib64,usr,proc,dev,sbin} 2>/dev/null

    # FIX (real bug found in testing): binding target_dir to "$chroot_dir/tmp"
    # and cd-ing to /tmp inside the jail looked reasonable, but the
    # extraction COMMAND itself (built in _archive_extract, which has no
    # idea it might run inside a chroot) still references target_dir by
    # its ORIGINAL absolute path (e.g. "-d /dev/shm/av_arch_XXXXXX") — a
    # path that doesn't exist inside a jail that only knows it as /tmp.
    # Confirmed: extraction silently found nothing (0 threats) with the
    # old /tmp remap. Recreate target_dir at its OWN real path inside the
    # jail instead, matching what bwrap mode already does with --bind.
    mkdir -p "${chroot_dir}${target_dir}" 2>/dev/null

    local -a mounted=()
    _cbind() { mount --bind "$1" "$2" 2>/dev/null && mounted+=("$2"); }
    [ -d /bin ]   && _cbind /bin   "$chroot_dir/bin"
    [ -d /lib ]   && _cbind /lib   "$chroot_dir/lib"
    [ -d /lib64 ] && _cbind /lib64 "$chroot_dir/lib64"
    [ -d /usr ]   && _cbind /usr   "$chroot_dir/usr"
    [ -d /sbin ]  && _cbind /sbin  "$chroot_dir/sbin"
    mount -t proc proc "$chroot_dir/proc" 2>/dev/null && mounted+=("$chroot_dir/proc")
    _cbind "$target_dir" "${chroot_dir}${target_dir}"

    # FIX (same class of bug as bwrap mode, found right after fixing that
    # one): the archive file itself lives OUTSIDE target_dir — bind its
    # containing directory too (read-only), same real path, so the
    # extraction command can still open its own input file inside the jail.
    if [ -n "$archive_src" ]; then
        local archive_dir; archive_dir=$(dirname "$archive_src")
        mkdir -p "${chroot_dir}${archive_dir}" 2>/dev/null
        mount --bind "$archive_dir" "${chroot_dir}${archive_dir}" 2>/dev/null && mount -o remount,ro,bind "${chroot_dir}${archive_dir}" 2>/dev/null
        mounted+=("${chroot_dir}${archive_dir}")
    fi

    # FIX (third instance of the same bug, found right after archive_src):
    # the extraction tool itself is very often our own bundled busybox,
    # installed under this scanner's OWN directory — not /bin or /usr —
    # so it was ALSO invisible inside the jail. Bind that in too.
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        local bb_dir; bb_dir=$(dirname "$BUSYBOX_BIN")
        mkdir -p "${chroot_dir}${bb_dir}" 2>/dev/null
        mount --bind "$bb_dir" "${chroot_dir}${bb_dir}" 2>/dev/null && mount -o remount,ro,bind "${chroot_dir}${bb_dir}" 2>/dev/null
        mounted+=("${chroot_dir}${bb_dir}")
    fi

    # FIX: unmount everything (reverse order — last mounted, first
    # unmounted, matters when one mount is nested under another) BEFORE
    # removing the directory, not just rm -rf on top of active mounts.
    _cleanup_chroot() {
        local i
        for (( i=${#mounted[@]}-1; i>=0; i-- )); do
            umount "${mounted[$i]}" 2>/dev/null || umount -l "${mounted[$i]}" 2>/dev/null || true
        done
        rm -rf "$chroot_dir" 2>/dev/null
    }
    trap _cleanup_chroot RETURN

    chroot "$chroot_dir" /bin/bash -c 'cd "$1"; shift; exec "$@"' _ "$target_dir" "$@"
}

_sandbox_run_simple() {
    local target_dir="$1" archive_src="$2"; shift 2
    # NOTE: simple mode doesn't isolate the filesystem view at all (just
    # drops privileges + resource limits), so the archive's own read
    # permissions still apply as-is after the UID switch — if it's only
    # readable by root (protected directory), extraction under "nobody"
    # can still fail for that reason. Known, documented limitation of
    # this specific mode; bwrap/chroot don't have it since they instead
    # explicitly bind the archive's directory in.
    #
    # FIX: sudo often isn't installed at all on minimal VPS images
    # (confirmed missing in testing) — setpriv (util-linux, near-universal
    # on Linux) drops privileges without needing sudo configured at all.
    local dropper=()
    if [ "$(id -u)" = "0" ]; then
        # FIX (real bug found in testing): mktemp -d creates directories
        # mode 0700 — root-owned, unreadable/unwritable by anyone else.
        # Dropping to an unprivileged user for extraction WITHOUT first
        # opening up the target dir means the extraction tool can't write
        # into it at all, failing silently (confirmed: 0 threats found on
        # an archive that should have had 1 — extraction produced nothing
        # because "nobody" had no permission to write there). chmod while
        # still root, before dropping privileges.
        chmod 0777 "$target_dir" 2>/dev/null
        if _sandbox_has setpriv; then
            dropper=(setpriv --reuid 65534 --regid 65534 --clear-groups)
        elif _sandbox_has runuser; then
            dropper=(runuser -u "$SANDBOX_USER" --)
        fi
    fi
    # FIX: ulimit -v (virtual memory) routinely breaks legitimate binaries
    # that reserve large address space upfront (thread stacks, mmap'd
    # shared libs) even when actual RSS usage is modest — using -m (RSS,
    # where the OS enforces it) instead avoids killing extraction tools
    # that were never actually going to use that much real memory.
    (
        ulimit -t "$SANDBOX_CPU_SEC" 2>/dev/null
        ulimit -f 512000 2>/dev/null
        ulimit -n 256 2>/dev/null
        ulimit -u 128 2>/dev/null
        cd "$target_dir" 2>/dev/null || true
        if [ ${#dropper[@]} -gt 0 ]; then
            "${dropper[@]}" "$@"
        else
            "$@"
        fi
    )
}

# run_sandboxed TARGET_DIR ARCHIVE_SRC CMD...
# TARGET_DIR is the extraction destination — needs to stay reachable
# (writable) inside whichever isolation mode runs. ARCHIVE_SRC is the
# archive file's own path — filesystem-isolating modes (bwrap/chroot)
# need read access to it explicitly bound in too, since it normally lives
# somewhere else entirely on the scanned tree, not under TARGET_DIR.
# Falls all the way through to running CMD un-sandboxed only for
# SANDBOX_MODE=none (explicit opt-out, not a silent fallback).
run_sandboxed() {
    local target_dir="$1" archive_src="$2"; shift 2
    local mode="$SANDBOX_MODE"
    if [ "$mode" = "auto" ]; then
        if _sandbox_has bwrap; then mode="bwrap"
        elif _sandbox_has unshare; then mode="unshare"
        else mode="simple"; fi
    fi
    case "$mode" in
        bwrap)    _sandbox_has bwrap    && { _sandbox_run_bwrap "$target_dir" "$archive_src" "$@"; return; } ;;
        unshare)  _sandbox_has unshare  && { _sandbox_run_unshare "$target_dir" "$archive_src" "$@"; return; } ;;
        chroot)   _sandbox_has chroot   && { _sandbox_run_chroot "$target_dir" "$archive_src" "$@"; return; } ;;
        simple)   { _sandbox_run_simple "$target_dir" "$archive_src" "$@"; return; } ;;
        none|*)   "$@"; return ;;
    esac
    # Requested mode's tool isn't actually available -> run unsandboxed
    # rather than silently fail extraction entirely.
    "$@"
}

_archive_extract() {
    local archive="$1" atype="$2" extract_dir="$3"
    # FIX: `timeout CMD` execs CMD as a real process — it cannot see shell
    # FUNCTIONS like bb(), so "timeout 30 bb unzip ..." failed with "bb:
    # command not found" (exit 127) every time, silently (stderr
    # discarded), extracting nothing. Resolve the real command (busybox
    # binary + applet, or the system tool) into a plain string BEFORE
    # handing it to timeout, same lookup bb() does internally. Same
    # reasoning applies to run_sandboxed below — it's also a shell
    # function, so `timeout` has to wrap the REAL command being passed
    # INTO it, not run_sandboxed itself.
    local unzip_c="unzip" tar_c="tar" gunzip_c="gunzip"
    case "$BB_APPLETS" in *" unzip "*)  unzip_c="$BUSYBOX_BIN unzip" ;; esac
    case "$BB_APPLETS" in *" tar "*)    tar_c="$BUSYBOX_BIN tar" ;; esac
    case "$BB_APPLETS" in *" gunzip "*) gunzip_c="$BUSYBOX_BIN gunzip" ;; esac
    case "$atype" in
        zip)    run_sandboxed "$extract_dir" "$archive" timeout 30 $unzip_c -qq -o "$archive" -d "$extract_dir" 2>/dev/null ;;
        tar)    run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xf "$archive" -C "$extract_dir" 2>/dev/null ;;
        targz)  run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xzf "$archive" -C "$extract_dir" 2>/dev/null ;;
        tarbz2) run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xjf "$archive" -C "$extract_dir" 2>/dev/null ;;
        tarxz)  run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xJf "$archive" -C "$extract_dir" 2>/dev/null ;;
        gz)     run_sandboxed "$extract_dir" "$archive" timeout 30 $gunzip_c -c "$archive" > "$extract_dir/$(basename "${archive%.gz}")" 2>/dev/null ;;
        bz2)    run_sandboxed "$extract_dir" "$archive" timeout 30 bunzip2 -c "$archive" > "$extract_dir/$(basename "${archive%.bz2}")" 2>/dev/null ;;
        xz)     run_sandboxed "$extract_dir" "$archive" timeout 30 unxz -c "$archive" > "$extract_dir/$(basename "${archive%.xz}")" 2>/dev/null ;;
        7z)     run_sandboxed "$extract_dir" "$archive" timeout 30 7z x -y -o"$extract_dir" "$archive" &>/dev/null ;;
        rar)
            if command -v unrar &>/dev/null; then
                run_sandboxed "$extract_dir" "$archive" timeout 30 unrar x -y "$archive" "$extract_dir/" &>/dev/null
            else
                run_sandboxed "$extract_dir" "$archive" timeout 30 7z x -y -o"$extract_dir" "$archive" &>/dev/null
            fi
            ;;
    esac
}

_archive_tmpdir() {
    local compressed_size_mb="${1:-0}"
    # Extract into RAM (/dev/shm) when it makes sense, same reasoning as
    # the main WORK_DIR: much less I/O-bound than disk, which matters most
    # on exactly the kind of low-end/IOPS-capped VPS where every bit of
    # speed counts. Two conditions, both must hold:
    #   1. the ARCHIVE's own compressed size is under ARCHIVE_RAM_MAX_MB
    #      (default 50) — bounds how much RAM one archive can claim,
    #      independent of the (much larger) ARCHIVE_MAX_EXTRACT_MB bomb
    #      guard, which is about the DECOMPRESSED size instead.
    #   2. /dev/shm actually has that much free right now.
    # Respects --no-ram (USE_RAM=false); falls back to disk for archives
    # over the threshold, or when /dev/shm doesn't have room.
    if [ "$ARCHIVE_USE_RAM" = "true" ] && [ "$compressed_size_mb" -le "$ARCHIVE_RAM_MAX_MB" ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
        local avail
        avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        if [ "${avail:-0}" -ge "$ARCHIVE_MAX_EXTRACT_MB" ]; then
            mktemp -d /dev/shm/av_arch_XXXXXX 2>/dev/null && return
        fi
    fi
    # FIX (real bug found in practice): this fallback used to be a bare
    # `mktemp -d` with no template — every large/disk-fallback archive
    # extraction got an UNPREFIXED "tmp.XXXXXXXXXX" name indistinguishable
    # from any other random system tmp dir. That meant these directories
    # were invisible to both the startup stale-dir sweep (which matches
    # on the "av_*" prefix) and self-exclusion — confirmed in practice: a
    # "/" scan re-discovered its OWN old leftover extractions sitting in
    # /tmp as if they were regular target files, re-reporting the same
    # DLE content a second time under a path that looked unrelated to
    # this scanner at all. Prefixed now, matching every other tmp dir
    # this script creates.
    mktemp -d "${TMPDIR:-/tmp}/av_arch_XXXXXX" 2>/dev/null
}

# Batched hash check across ALL members of one archive at once — computing
# each member's hash is inherently per-file (unavoidable), but the lookup
# itself uses the same fast grep -qF path the main scan uses.
_archive_batch_hash_check() {
    local top_archive="$1" extract_dir="$2" cur_rel="$3"; shift 3

    # FIX (real hang reported: an 18MB DLE zip "hanging" for over a
    # minute): despite the name, this used to loop per-member, calling
    # sha256sum/md5sum AND a busybox-grep lookup against sha256.tsv/
    # md5.tsv SEPARATELY FOR EVERY FILE inside the archive — exactly the
    # same per-file overhead problem already fixed for the main scan
    # pipeline (busybox grep against the 632k-line md5.tsv alone measured
    # ~1.5s/call), just never applied here. A few hundred files inside one
    # archive meant a few hundred seconds. Now genuinely batched, same
    # pattern as process_hash_batch(): hash the whole member set in ONE
    # command, look up ALL hashes in ONE grep call, via the fast
    # bundled/system grep (_real_grep), not busybox's.
    local -a valid=()
    local m msize
    for m in "$@"; do
        msize=$(_stat_size "$m" 2>/dev/null) || continue
        { [ "${msize:-0}" -eq 0 ] || [ "${msize:-0}" -gt "$MAX_SIZE" ]; } && continue
        valid+=("$m")
    done
    [ ${#valid[@]} -eq 0 ] && return

    local rel out hits h n

    if [ "$HAS_SHA256" = true ] && [ "$SHA256_CMD" != "none" ]; then
        out=$($SHA256_CMD "${valid[@]}" 2>/dev/null)
        hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | _real_grep -F -f - "$SIG_DIR/sha256.tsv" 2>/dev/null | cut -f1)
        if [ -n "$hits" ]; then
            while IFS= read -r h; do
                [ -z "$h" ] && continue
                n=$(_real_grep -m 1 "^${h}" "$SIG_DIR/sha256.tsv" 2>/dev/null | cut -f2)
                m=$(printf '%s\n' "$out" | bb grep -iE "^${h}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
                [ -z "$m" ] && continue
                rel="${m#$extract_dir/}"
                [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
                threat "KNOWN_MALWARE" "$top_archive" "archive_member=${rel}|name=${n:-Malware}|sha256=$h"
            done <<< "$hits"
        fi
    fi

    if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
        out=$($MD5_CMD "${valid[@]}" 2>/dev/null)
        hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | _real_grep -F -f - "$SIG_DIR/md5.tsv" 2>/dev/null | cut -f1)
        if [ -n "$hits" ]; then
            while IFS= read -r h; do
                [ -z "$h" ] && continue
                n=$(_real_grep -m 1 "^${h}" "$SIG_DIR/md5.tsv" 2>/dev/null | cut -f2)
                m=$(printf '%s\n' "$out" | bb grep -iE "^${h}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
                [ -z "$m" ] && continue
                rel="${m#$extract_dir/}"
                [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
                threat "KNOWN_MALWARE" "$top_archive" "archive_member=${rel}|name=${n:-Malware}|md5=$h"
            done <<< "$hits"
        fi
    fi
}

# Batched YARA check across ALL members of one archive in ONE call. This is
# the fix for the real slowdown reported: the old per-member design called
# $YARA_CMD separately for EVERY file inside the archive, reloading/
# compiling the whole ruleset each time — on an archive with dozens of
# members that alone made a single zip take minutes. Same --scan-list (or
# symlink+-r fallback) technique already used for the main file batches.
_archive_batch_yara_check() {
    local top_archive="$1" extract_dir="$2" cur_rel="$3"; shift 3
    [ $# -eq 0 ] && return

    # FIX (real bug found — confirmed via YARA CLI source: `static int
    # threads = YR_MAX_THREADS;`): without an explicit -p, yara defaults to
    # its MAXIMUM allowed thread count, not something sane like nproc. That
    # meant EVERY single yara invocation — and we already run one PER
    # WORKER PROCESS, i.e. our own -j-controlled parallelism — was ALSO
    # spawning its own large internal thread pool, all fighting over the
    # same CPU cores as every other worker's yara call. Confirmed on a
    # real 2-CPU box: 7+ concurrent yara threads/processes, load average
    # ~5 on 2 cores — severe oversubscription that tanks throughput
    # despite high CPU%, not genuine parallel speedup. -p 1 makes each
    # yara call single-threaded; the worker-process level (-j) is where
    # parallelism should live, not duplicated inside every yara call too.
    local yflags=(-d filename= -d filepath= -d extension= -p 1 -a "$YARA_TIMEOUT_SEC")
    case "$YARA_TARGET" in *.yarc) yflags+=(-C) ;; esac

    local yara_out
    if [ "$YARA_HAS_SCAN_LIST" = true ]; then
        local listfile
        listfile=$(mktemp 2>/dev/null) || return
        printf '%s\n' "$@" > "$listfile"
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yflags[@]}" --scan-list "$YARA_TARGET" "$listfile" 2>/dev/null)
        rm -f "$listfile"
    else
        local tmpdir2
        tmpdir2=$(mktemp -d 2>/dev/null) || return
        local f
        for f in "$@"; do
            ln -sf "$f" "$tmpdir2/$(basename "$f")_$RANDOM" 2>/dev/null
        done
        local raw
        raw=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yflags[@]}" -r "$YARA_TARGET" "$tmpdir2" 2>/dev/null)
        if [ -n "$raw" ]; then
            yara_out=$(while IFS= read -r l; do
                [ -z "$l" ] && continue
                local r p real
                r=$(echo "$l" | awk '{print $1}')
                p=$(echo "$l" | cut -d' ' -f2-)
                real=$(readlink -f "$p" 2>/dev/null || echo "$p")
                echo "$r $real"
            done <<< "$raw")
        fi
        rm -rf "$tmpdir2"
    fi

    [ -z "$yara_out" ] && return
    local yline yrule yfile rel spat
    while IFS= read -r yline; do
        [ -z "$yline" ] && continue
        yrule=$(echo "$yline" | awk '{print $1}')
        yfile=$(echo "$yline" | cut -d' ' -f2-)
        rel="${yfile#$extract_dir/}"
        [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
        if spat=$(_resolve_str_sig "$yrule"); then
            threat "SIG_STRING_MATCH" "$top_archive" "archive_member=${rel}|pattern=${spat:0:50}"
        elif _is_vendor_obfuscation "$yrule" "$yfile"; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
        else
            threat "YARA_MATCH" "$top_archive" "archive_member=${rel}|rule=$yrule"
        fi
    done <<< "$yara_out"
}

# scan_archive TOP_ARCHIVE [CURRENT_FILE] [CURRENT_REL]
# TOP_ARCHIVE is always the real, original archive file to report against.
# CURRENT_FILE/CURRENT_REL are set when called recursively for a nested
# archive found inside an already-extracted one.
scan_archive() {
    local top_archive="$1" cur="${2:-$1}" cur_rel="${3:-}"
    [ "$SCAN_ARCHIVES" = "true" ] || return

    local asize
    asize=$(_stat_size "$cur" 2>/dev/null) || return
    [ "${asize:-0}" -gt $(( ARCHIVE_MAX_MB * 1024 * 1024 )) ] && return

    local atype
    atype=$(_archive_type "$cur")
    [ -z "$atype" ] && return

    local extract_dir
    extract_dir=$(_archive_tmpdir $(( asize / 1024 / 1024 ))) || return
    # Tracked so a graceful interrupt (TERM/INT — see trap near the top of
    # this worker script) can still clean this up even if the worker gets
    # killed mid-extraction, before reaching this function's own rm -rf at
    # the end. Not removed from the array on the normal path below — a
    # second rm -rf on an already-gone directory is a harmless no-op, and
    # keeping this simple matters more than pruning it precisely.
    _ACTIVE_EXTRACT_DIRS+=("$extract_dir")

    _archive_extract "$cur" "$atype" "$extract_dir"

    local extracted_kb
    extracted_kb=$(du -sk "$extract_dir" 2>/dev/null | awk '{print $1}')
    if [ -n "$extracted_kb" ] && [ "$extracted_kb" -gt $(( ARCHIVE_MAX_EXTRACT_MB * 1024 )) ]; then
        log "Archive extraction exceeded ${ARCHIVE_MAX_EXTRACT_MB}MB cap, scan may be incomplete: $top_archive"
    fi

    local -a members=()
    local inner n=0
    while IFS= read -r -d '' inner; do
        n=$(( n + 1 ))
        [ "$n" -gt "$ARCHIVE_MAX_FILES" ] && break
        members+=("$inner")
    done < <(find "$extract_dir" -type f -print0 2>/dev/null)

    if [ ${#members[@]} -gt 0 ]; then
        _archive_batch_hash_check "$top_archive" "$extract_dir" "$cur_rel" "${members[@]}"
        [ "$HAS_YARA" = true ] && _archive_batch_yara_check "$top_archive" "$extract_dir" "$cur_rel" "${members[@]}"

        # Strings + nested-archive recursion stay per-member: grep -F is
        # cheap enough not to need batching, and nested archives are rare.
        local m rel msize
        for m in "${members[@]}"; do
            msize=$(_stat_size "$m" 2>/dev/null) || continue
            { [ "${msize:-0}" -eq 0 ] || [ "${msize:-0}" -gt "$MAX_SIZE" ]; } && continue
            rel="${m#$extract_dir/}"
            [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"

            if [ "$HAS_STRINGS" = true ]; then
                local sm
                sm=$(do_strings "$m" 6 524288 | bb grep -F -i -f "$SIG_DIR/strings.txt" 2>/dev/null | head -1)
                [ -n "$sm" ] && threat "SIG_STRING_MATCH" "$top_archive" "archive_member=${rel}|pattern=${sm:0:50}"
            fi

            if [ "$ARCHIVE_DEPTH_CUR" -lt "$ARCHIVE_MAX_DEPTH" ]; then
                local atype2
                atype2=$(_archive_type "$m")
                if [ -n "$atype2" ]; then
                    ARCHIVE_DEPTH_CUR=$(( ARCHIVE_DEPTH_CUR + 1 ))
                    scan_archive "$top_archive" "$m" "$rel"
                    ARCHIVE_DEPTH_CUR=$(( ARCHIVE_DEPTH_CUR - 1 ))
                fi
            fi
        done
    fi

    rm -rf "$extract_dir"
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

# threat() — single entry point for any finding: checks ignore_sigs first
# (a match suppresses the detection entirely — no log, no quarantine), then
# logs it, streams it immediately to the persistent live report (so
# Ctrl+C/SIGTERM mid-scan doesn't lose already-found results — see
# init_live_report in the main script), and quarantines the file if
# enabled. Report line format ("TYPE|file|info") is unchanged so
# build_report/print_report still work.
threat() {
    local type="$1" file="$2" info="${3:-}"

    # NOTE: matched string includes the file PATH too (not just type+info)
    # — lets ignore_sigs patterns be scoped to specific paths, e.g.
    # suppress a noisy rule only under a known-legitimate directory
    # instead of everywhere it might ever fire. Old simple patterns (no
    # anchors) keep working unchanged, since they just match as a
    # substring regardless of what else is on the line.
    #
    # DEEP_MODE bypasses this entirely — the whole point of --deep is
    # maximum precision with no automatic suppression at all; the person
    # reviews and dismisses findings themselves rather than trusting the
    # tool's own filters, which is exactly what a deep/paranoid pass is
    # for.
    if [ "$DEEP_MODE" != "true" ] && [ -n "$IGNORE_SIGS_FILE" ] && [ -s "$_IGNORE_SIGS_FILTERED" ]; then
        if printf '%s|%s|%s\n' "$type" "$info" "$file" | bb grep -qE -f "$_IGNORE_SIGS_FILTERED" 2>/dev/null; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            return
        fi
    fi

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
    [ "$htype" = "sha1" ] && cmd="$SHA1_CMD"
    [ "$cmd" = "none" ] && return

    local out
    out=$($cmd "$@" 2>/dev/null)
    [ -z "$out" ] && return

    # "grep -F -f - sig_file" returns full "hash<TAB>name" lines, not just
    # the hash — the trailing "cut -f1" extracts the clean hash.
    #
    # FIX (real bottleneck found and measured on a live scan — hash
    # lookups were 69% of total scan time): this used to go through
    # busybox's grep, which measured ~2.2x slower than a real grep for
    # exactly this shape of query (-F -f - against a 632k-line hash
    # database — confirmed 1528ms vs 701ms per call on a realistic
    # benchmark). Same fix already applied to the string-signature search
    # — use _real_grep (bundled/system grep) here too.
    local hits
    hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | _real_grep -F -f - "$sig_file" 2>/dev/null | cut -f1)
    if [ -n "$hits" ]; then
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            local tname
            tname=$(_real_grep -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -f2)
            local hit_file
            hit_file=$(printf '%s\n' "$out" | bb grep -iE "^${hit_hash}\s+" | sed 's/^[^ ]*[ ]*//' | head -1)
            [ -n "$hit_file" ] && threat "KNOWN_MALWARE" "$hit_file" "name=${tname:-Malware}|$htype=$hit_hash"
        done <<< "$hits"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: yara matching
# ----------------------------------------------------------------------------
# Called when a --scan-list batch hit (or nearly hit) the -a timeout —
# retries the SAME batch one file at a time with a short per-file timeout,
# so a single pathological file doesn't cost the whole batch's results and
# gets identified by name instead of just "the scan is stuck".
_yara_bisect_slow_batch() {
    local short_timeout=5
    [ "$YARA_TIMEOUT_SEC" -lt 20 ] && short_timeout=$(( YARA_TIMEOUT_SEC / 4 ))
    [ "$short_timeout" -lt 2 ] && short_timeout=2

    local yflags2=(-d filename= -d filepath= -d extension= -p 1 -a "$short_timeout")
    case "$YARA_TARGET" in *.yarc) yflags2+=(-C) ;; esac

    local f t0 t1 out
    for f in "$@"; do
        t0=$(_now_ms)
        out=$(timeout $(( short_timeout + 2 )) $YARA_CMD "${yflags2[@]}" "$YARA_TARGET" "$f" 2>/dev/null)
        t1=$(_now_ms)
        if [ $(( (t1 - t0) / 1000 )) -ge "$short_timeout" ]; then
            # This is the (or a) culprit — report it as a diagnostic entry
            # (not necessarily malicious — pathologically slow-to-scan
            # files are usually just unusual content, e.g. one enormous
            # minified line — but worth the person's attention either way)
            # and move on instead of hanging the whole scan on it.
            threat "SCAN_TIMEOUT" "$f" "yara_timeout_sec=${short_timeout}|note=file took too long to scan, skipped"
            continue
        fi
        [ -z "$out" ] && continue
        local yrule yfile spat
        yrule=$(echo "$out" | head -1 | awk '{print $1}')
        yfile="$f"
        if spat=$(_resolve_str_sig "$yrule"); then
            threat "SIG_STRING_MATCH" "$yfile" "pattern=${spat:0:50}"
        elif _is_vendor_obfuscation "$yrule" "$yfile"; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
        else
            threat "YARA_MATCH" "$yfile" "rule=$yrule"
        fi
    done
}

process_yara_batch() {
    [ $# -eq 0 ] || [ "$HAS_YARA" = false ] || [ "$YARA_CMD" = "none" ] && return

    local yara_out yara_flags=(-d filename= -d filepath= -d extension= -p 1 -a "$YARA_TIMEOUT_SEC")
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
        local t0; t0=$(_now_ms)
        # FIX (real bug reported — "goes into infinity"): yara's own -a
        # flag was measured NOT reliably capping --scan-list duration (a
        # real batch took 74-113 SECONDS despite the configured 30s
        # limit). Relying only on -a meant the elapsed-time check below
        # would only ever fire AFTER yara eventually finished on its own,
        # however long that took — defeating the whole point of a
        # timeout. Wrap with the shell's own `timeout` (SIGTERM then
        # SIGKILL at the OS level) as a HARD guarantee that doesn't depend
        # on yara's internal timeout logic working correctly at all.
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags[@]}" --scan-list "$YARA_TARGET" "$listfile" 2>/dev/null)
        local t1; t1=$(_now_ms)
        rm -f "$listfile"

        # FIX (real hang reported): a batch call that hits -a's timeout
        # aborts the WHOLE --scan-list operation, losing results for every
        # OTHER file in the batch too — not just the slow one. Detect a
        # likely timeout by comparing actual elapsed time against the
        # configured limit (yara doesn't give a clean distinct exit code
        # for this), and if so, fall back to checking this SAME batch's
        # files ONE AT A TIME with a much shorter per-file timeout: fast
        # files still get scanned normally (nothing lost), and whichever
        # file(s) also blow the short timeout get identified and reported
        # instead of silently swallowing the whole batch or hanging again.
        if [ $(( (t1 - t0) / 1000 )) -ge "$YARA_TIMEOUT_SEC" ]; then
            _yara_bisect_slow_batch "$@"
            return
        fi
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
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags[@]}" -r "$YARA_TARGET" "$tmpdir" 2>/dev/null)
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
            local spat
            if spat=$(_resolve_str_sig "$yrule"); then
                threat "SIG_STRING_MATCH" "$yfile" "pattern=${spat:0:50}"
            elif _is_vendor_obfuscation "$yrule" "$yfile"; then
                SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            else
                threat "YARA_MATCH" "$yfile" "rule=$yrule"
            fi
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

    # PERFORMANCE FIX: this used to fork dd+strings (do_strings) for EVERY
    # file before the batched search even ran — batching only combined the
    # SEARCH step, not this per-file preparation step, so it never actually
    # eliminated the dominant cost (~2 forks/file, e.g. ~5000 forks for
    # 2485 files). strings.txt patterns are literal readable text, which
    # already appears as a substring in a file's raw bytes whether the
    # file is genuine text or binary — no separate "extract printable
    # runs" step is actually needed. GNU grep -a searches binary files as
    # text directly, AND (unlike yara) accepts many files as plain
    # arguments in one call, so the whole batch can be searched with zero
    # per-file preparation forks.
    #
    # CAVEAT: busybox's grep does NOT handle -a / binary content
    # correctly (verified: silently finds nothing in files containing NUL
    # bytes, matched or not) — this path requires real GNU grep. Falls
    # back to the slower do_strings-based per-file extraction (the
    # previous behavior) if system grep isn't available.
    if [ "$HAS_STRINGS" = true ]; then
        if _has_real_grep; then
            local mf pat
            while IFS= read -r mf; do
                [ -z "$mf" ] && continue
                pat=$(_real_grep -F -a -i -o -f "$SIG_DIR/strings.txt" "$mf" 2>/dev/null | head -1)
                threat "SIG_STRING_MATCH" "$mf" "pattern=${pat:0:50}"
            done < <(_real_grep -F -a -i -l -f "$SIG_DIR/strings.txt" "$@" 2>/dev/null)
        else
            local tmpdir_s f i=0
            tmpdir_s=$(mktemp -d 2>/dev/null) && {
                local -a idx_s=()
                for f in "$@"; do
                    idx_s[$i]="$f"
                    do_strings "$f" 6 524288 > "$tmpdir_s/${i}.str" 2>/dev/null
                    i=$((i + 1))
                done
                local mf mi orig pat
                while IFS= read -r mf; do
                    [ -z "$mf" ] && continue
                    mi="${mf##*/}"; mi="${mi%.str}"
                    orig="${idx_s[$mi]:-}"
                    [ -z "$orig" ] && continue
                    pat=$(bb grep -F -i -o -f "$SIG_DIR/strings.txt" "$mf" 2>/dev/null | head -1)
                    threat "SIG_STRING_MATCH" "$orig" "pattern=${pat:0:50}"
                done < <(bb grep -F -i -l -f "$SIG_DIR/strings.txt" "$tmpdir_s"/*.str 2>/dev/null)
                rm -rf "$tmpdir_s"
            }
        fi
    fi

    # hex_ere.txt patterns are hex-DIGIT TEXT meant to match a hex-encoded
    # dump of the file's bytes, not the raw bytes themselves — this still
    # needs the per-file hex-dump preparation (can't skip it the way
    # strings could). In practice HAS_HEX_ERE is false for most setups
    # now that .ndb/.ldb signatures compile to YARA instead (see MODULE:
    # ClamAV format support), so this path is rarely exercised.
    if [ "$HAS_HEX_ERE" = true ]; then
        local tmpdir_h f i=0
        tmpdir_h=$(mktemp -d 2>/dev/null) && {
            local -a idx_h=()
            for f in "$@"; do
                idx_h[$i]="$f"
                bb dd if="$f" bs=524288 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n' > "$tmpdir_h/${i}.hex" 2>/dev/null
                i=$((i + 1))
            done
            local mf mi orig hx
            while IFS= read -r mf; do
                [ -z "$mf" ] && continue
                mi="${mf##*/}"; mi="${mi%.hex}"
                orig="${idx_h[$mi]:-}"
                [ -z "$orig" ] && continue
                hx=$(bb grep -E -o -i -f "$SIG_DIR/hex_ere.txt" "$mf" 2>/dev/null | head -1)
                [ -n "$hx" ] && threat "HEX_SIG_MATCH" "$orig" "hex=${hx:0:40}..."
            done < <(bb grep -E -l -i -f "$SIG_DIR/hex_ere.txt" "$tmpdir_h"/*.hex 2>/dev/null)
            rm -rf "$tmpdir_h"
        }
    fi
}

# Decodes and checks candidate base64 chunks in ONE file: hash-lookup
# against known payloads, then (if still unmatched) a follow-up YARA scan
# of the DECODED content for anything ELF/PE/script-shaped. Runs directly
# per-file (via check_file_heuristics) — NOT gated behind a YARA screening
# rule anymore. That WAS tried (an embedded "__av_b64_screen__" regex rule,
# to save one read per file), but caused a real regression: YARA's regex
# engine scales badly against a very long single-line base64-ish blob —
# confirmed on real DLE installations, whose own license-obfuscated engine
# files are exactly that shape, making specific files take 74-113+
# SECONDS each. A plain `grep -oE` call handles the same content fine.
_check_b64_payload() {
    local file="$1"
    while IFS= read -r chunk; do
        [ -z "$chunk" ] && continue
        local b64tmp
        b64tmp=$(mktemp 2>/dev/null) || continue
        printf '%s' "$chunk" | _b64decode > "$b64tmp" 2>/dev/null
        [ -s "$b64tmp" ] || { rm -f "$b64tmp"; continue; }

        local magic
        magic=$(bb od -An -tx1 -v "$b64tmp" 2>/dev/null | head -1 | tr -d ' \n')
        case "$magic" in
            7f454c46*|4d5a*|2321*) : ;;
            *) rm -f "$b64tmp"; continue ;;
        esac

        if [ "$HAS_B64" = true ] && [ "$SHA256_CMD" != "none" ]; then
            local dh
            dh=$($SHA256_CMD "$b64tmp" 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1)
            if [ -n "$dh" ] && bb grep -qF "$dh" "$SIG_DIR/b64_payloads.tsv" 2>/dev/null; then
                local bname
                bname=$(bb grep -m 1 "^$dh" "$SIG_DIR/b64_payloads.tsv" | cut -f2)
                threat "KNOWN_B64_PAYLOAD" "$file" "name=${bname:-B64.Malware}|b64=${chunk:0:20}..."
                rm -f "$b64tmp"
                continue
            fi
        fi

        local dtype="SCRIPT"
        case "$magic" in 7f454c46*) dtype="ELF" ;; 4d5a*) dtype="PE_MZ" ;; esac
        if [ "$HAS_YARA" = true ]; then
            local yara_flags3=(-d filename= -d filepath= -d extension= -p 1 -a "$YARA_TIMEOUT_SEC") yhit
            case "$YARA_TARGET" in *.yarc) yara_flags3+=(-C) ;; esac
            yhit=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags3[@]}" "$YARA_TARGET" "$b64tmp" 2>/dev/null | head -1 | awk '{print $1}')
            [ -n "$yhit" ] && threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=${dtype}|yara=${yhit}|b64=${chunk:0:20}..."
        else
            threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=${dtype}|b64=${chunk:0:20}..."
        fi
        rm -f "$b64tmp"
    done < <(if _has_real_grep; then _real_grep -oE '[A-Za-z0-9+/]{200,}={0,2}' "$file" 2>/dev/null; else bb grep -oE '[A-Za-z0-9+/]{200,}={0,2}' "$file" 2>/dev/null; fi | head -8)
}

check_file_heuristics() {
    local file="$1" size="$2" oct="$3"

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # REVERTED to always running this own grep-based pass (see the
        # REVERTED comment in compile_signatures for why) — no longer
        # gated on HAS_YARA / a screening rule.
        _check_b64_payload "$file"
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
        if (( 8#$oct & 8#6000 )) 2>/dev/null; then
            # SUID/SGID on standard system binaries (sudo, su, mount, passwd,
            # ...) is EXPECTED — every Linux install has these, so flagging
            # them on every scan of a system directory is pure noise. But a
            # virus/rootkit REPLACING one of those binaries is exactly what
            # we want to still catch. The distro package manager already
            # keeps a checksum database for this — use it: if the file is
            # package-owned AND its checksum matches the package's record,
            # it is verified legitimate and suppressed; if it's unowned,
            # unverifiable, or the checksum DOESN'T match, it's reported
            # (with 'unverified' or 'TAMPERED' noted, since a checksum
            # mismatch on a package-owned SUID binary is a strong compromise
            # indicator, not a minor discrepancy).
            #
            # SUID_VERIFY_MODE is on by default now (see its declaration)
            # — this just gates whether verification runs at all
            # (--no-verify-suid skips it entirely, e.g. if dpkg isn't
            # trusted/available). DEEP_MODE separately controls whether a
            # VERIFIED-clean file still gets suppressed — consistent with
            # --deep's "no automatic filtering" rule elsewhere, a person
            # running a deep/paranoid pass sees every SUID/SGID file
            # regardless of verification status, with that status noted
            # as context rather than used to hide anything.
            if [ "$SUID_VERIFY_MODE" = "true" ]; then
                local suid_status
                suid_status=$(_verify_package_file "$file")
                case "$suid_status" in
                    verified)
                        [ "$DEEP_MODE" = "true" ] && threat "SUID_SGID" "$file" "perms=$oct|verified (package checksum matches)"
                        ;;
                    tampered) threat "SUID_SGID" "$file" "perms=$oct|TAMPERED (fails package checksum verification)" ;;
                    *)        threat "SUID_SGID" "$file" "perms=$oct" ;;
                esac
            else
                threat "SUID_SGID" "$file" "perms=$oct"
            fi
        fi
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
                    _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
                    BATCH_SHA=(); SHA_BATCH_CNT=0
                fi
            fi
            if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
                BATCH_MD5+=("$file")
                MD5_BATCH_CNT=$(( MD5_BATCH_CNT + 1 ))
                if [ "$MD5_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
                    BATCH_MD5=(); MD5_BATCH_CNT=0
                fi
            fi
            # SHA1 gated the same way — only queued at all when the
            # compiled signature set actually HAS sha1.tsv entries (a
            # real ClamAV .hsb file with none would leave this HAS_SHA1
            # false, and this whole extra per-file read never happens —
            # no IOPS cost paid for a hash type nobody's database uses).
            if [ "$HAS_SHA1" = true ] && [ "$SHA1_CMD" != "none" ]; then
                BATCH_SHA1+=("$file")
                SHA1_BATCH_CNT=$(( SHA1_BATCH_CNT + 1 ))
                if [ "$SHA1_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_hash_batch "sha1" "$SIG_DIR/sha1.tsv" "${BATCH_SHA1[@]}"
                    BATCH_SHA1=(); SHA1_BATCH_CNT=0
                fi
            fi

            # Magic filter + YARA decision
            magic_type=$(_bash_file_type "$file")
            skip_deep=false
            case "$magic_type" in
                JPEG|PNG|GIF) skip_deep=true ;;
            esac

            # Extension/magic mismatch override: force full YARA scanning
            # even for image extensions that would otherwise skip_deep, so
            # a real executable disguised as a .jpg still gets checked.
            # The actual DISGUISED_FILE report happens once, in
            # check_file_heuristics() below (which covers more extensions
            # — bmp/webp/pdf/doc/xls too) — reporting it here TOO used to
            # double-count every disguised-file hit (threats displayed
            # once due to dedup, but counted twice).
            ext="${file##*.}"
            case "${ext,,}" in
                jpg|jpeg|png|gif)
                    if [ "$magic_type" = "ELF" ] || [ "$magic_type" = "PE_MZ" ]; then
                        skip_deep=false
                    fi
                    ;;
            esac

            if [ "$skip_deep" = false ] && [ "$HAS_YARA" = true ]; then
                BATCH_YARA+=("$file")
                YARA_BATCH_CNT=$(( YARA_BATCH_CNT + 1 ))
                if [ "$YARA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_yara_batch "${BATCH_YARA[@]}"
                    BATCH_YARA=(); YARA_BATCH_CNT=0
                fi
            fi

            # Batched strings/hex heuristic matching (see process_heuristic_batch)
            if [ "$HAS_STRINGS" = true ] || [ "$HAS_HEX_ERE" = true ]; then
                BATCH_HEUR+=("$file")
                HEUR_BATCH_CNT=$(( HEUR_BATCH_CNT + 1 ))
                if [ "$HEUR_BATCH_CNT" -ge "$HEUR_BATCH_SIZE" ]; then
                    _timed_heur_batch "${BATCH_HEUR[@]}"
                    BATCH_HEUR=(); HEUR_BATCH_CNT=0
                fi
            fi

            # Batched PE-section hash matching (.mdb signatures) — only for
            # files whose magic bytes actually look like a PE/MZ executable.
            if [ "$HAS_MDB" = true ] && [ "$magic_type" = "PE_MZ" ]; then
                BATCH_PE+=("$file")
                PE_BATCH_CNT=$(( PE_BATCH_CNT + 1 ))
                if [ "$PE_BATCH_CNT" -ge "$PE_BATCH_SIZE" ]; then
                    _timed_pe_batch "${BATCH_PE[@]}"
                    BATCH_PE=(); PE_BATCH_CNT=0
                fi
            fi
        fi

        # Archive scanning (-A/--scan-archives) — deliberately OUTSIDE the
        # MAX_SIZE gate above: archives are checked against their own,
        # separate ARCHIVE_MAX_MB limit (typically larger than MAX_SIZE,
        # since compressed archives commonly exceed the deep-inspection
        # size cutoff for regular files). scan_archive() itself is a fast
        # no-op for non-archive extensions and when -A wasn't passed.
        [ "$SCAN_ARCHIVES" = "true" ] && scan_archive "$file"

        # Cheap per-file checks (base64 payloads, disguised ext, perms)
        check_file_heuristics "$file" "$size" "${oct:-0}"

        [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
    done < "$POOL_FILE"

    # Flush remaining batches
    [ "$SHA_BATCH_CNT" -gt 0 ] && _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
    [ "$SHA1_BATCH_CNT" -gt 0 ] && _timed_hash_batch "sha1" "$SIG_DIR/sha1.tsv" "${BATCH_SHA1[@]}"
    [ "$MD5_BATCH_CNT" -gt 0 ] && _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
    [ "$YARA_BATCH_CNT" -gt 0 ] && _timed_yara_batch "${BATCH_YARA[@]}"
    [ "$HEUR_BATCH_CNT" -gt 0 ] && _timed_heur_batch "${BATCH_HEUR[@]}"
    [ "$PE_BATCH_CNT" -gt 0 ] && _timed_pe_batch "${BATCH_PE[@]}"
}

# ----------------------------------------------------------------------------
# MODULE: finalize
# ----------------------------------------------------------------------------
finalize_worker() {
    progress "done"
    printf 'FILES_SCANNED:%d\nTHREATS_FOUND:%d\nSUPPRESSED:%d\n' "$FILES_SCANNED" "$THREATS_FOUND" "$SUPPRESSED_FOUND" >> "$REPORT"
    printf 'TIMING_HASH_MS:%d\nTIMING_YARA_MS:%d\nTIMING_HEUR_MS:%d\nTIMING_PE_MS:%d\n' "$T_HASH_MS" "$T_YARA_MS" "$T_HEUR_MS" "$T_PE_MS" >> "$REPORT"
    log "Completed - files: $FILES_SCANNED, threats: $THREATS_FOUND, suppressed: $SUPPRESSED_FOUND"
    rm -f "$_IGNORE_SIGS_FILTERED" "$_GENERIC_OBFUSCATION_FILTERED" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" 2>/dev/null
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
