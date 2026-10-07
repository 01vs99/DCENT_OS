#!/bin/sh
# measure_image.sh - DCENT_axe UI Gauntlet measurement station (Stage M).
#
# Wraps GAUNTLET_LOOP.md Stage B steps 1-4 and writes the `measure.json` that a
# blind critic is handed (CRITIC_RUBRIC.md sections 0/1/5):
#
#   * image bytes per board + the OTA slot size + percent used  (the HARD budget)
#   * the ELF text/data/bss triple
#   * the invocation-aware handler count from tools/count_handlers.py
#   * a per-asset byte table (dashboard.rs and the include_str! assets), so a lane
#     that grows the image has to say which asset paid for it
#   * host-gate pass/fail counts
#   * delta_vs_baseline when a previous measure.json is supplied
#
# The document itself is written by `tools/measure_assemble.py`, which BOTH this
# script and `tools/measure_image.ps1` call. Neither port formats JSON of its own:
# round 1 shipped two independent writers and they disagreed on the shape a blind
# critic was handed. `tools/check_measure_ports.py` runs both and diffs them.
#
# Builders do NOT run this: `C:/bt` is one shared warm ESP-IDF cache and the
# ESP-IDF path-length limit forbids per-worktree target dirs, so the lead runs it
# serially, one lane at a time (GAUNTLET_LOOP.md Stage M).
#
# Usage:
#   tools/measure_image.sh [--lane <id>] [--pass <id>] [--boards "<a> <b>"]
#                          [--out <measure.json>] [--image-dir <dir>]
#                          [--target-dir <CARGO_TARGET_DIR>]
#                          [--host-target-dir <dir>]
#                          [--baseline <measure.json>]
#                          [--skip-build] [--skip-host-gate] [--allow-cr]
#
# Environment: PYTHON (default `python`), CARGO (default `cargo`),
#              ESPFLASH (default `espflash`), SIZE_TOOL (default
#              `xtensa-esp32s3-elf-size`), HOST_TARGET (default
#              `x86_64-pc-windows-msvc`; use x86_64-unknown-linux-gnu on WSL),
#              HOST_TOOLCHAIN (default `+stable`; `rust-toolchain.toml` pins
#              `esp`, so the host gate MUST name a host toolchain explicitly).
#
# Both target dirs default to short paths outside the worktree: the ESP-IDF
# build has a hard path-length limit, and a per-worktree `target/` is exactly
# the accumulation the root  disk-hygiene rule forbids.
#
# CR refusal (P1-I6, 2026-09-03): `include_str!` keeps carriage-return bytes,
# so a CRLF checkout of `dashboard.rs`'s embedded assets inflates every board's
# image by roughly one byte per embedded line and makes the run's numbers
# incomparable to an LF baseline (`PROGRESS.md` 2026-09-03 ~14:10/~14:35). Step
# 0 below (`tools/measure_cr_check.py`) enumerates dashboard.rs and every asset
# it embeds via `include_str!`/`include_bytes!` — parsed from the macro
# invocations, never a hard-coded list — and FAILS CLOSED (exit 2) the moment
# any of them carries a CR byte, before the build/host-gate steps run and
# regardless of `--skip-build`/`--skip-host-gate` (it is a SOURCE-state check).
# `--allow-cr` downgrades a CR hit to a loud stderr warning and lets the run
# continue (its byte-budget numbers are then known-inflated, not usable for a
# lane's D8/H1 verdict). See `tools/README.md` "CR refusal" for the recipe to
# normalise a CRLF worktree instead.
#
# Exit codes: 0 = measured and every board fits its slot; 1 = a board's image
# exceeds its OTA slot, the handler census failed, or a requested tool is
# missing; 2 = the embedded-asset CR check failed (a CR byte was found and
# --allow-cr was not given, or dashboard.rs / a file it embeds could not be
# found). Fail-closed: an image that does not fit, or a CRLF checkout that was
# not explicitly waived, is a failed lane, never a warning.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$ROOT_DIR/../.." && pwd)

PYTHON=${PYTHON:-python}
CARGO=${CARGO:-cargo}
ESPFLASH=${ESPFLASH:-espflash}
SIZE_TOOL=${SIZE_TOOL:-xtensa-esp32s3-elf-size}
HOST_TARGET=${HOST_TARGET:-x86_64-pc-windows-msvc}
HOST_TOOLCHAIN=${HOST_TOOLCHAIN:-+stable}

LANE=baseline
PASS=pass1
BOARDS="bitaxe-hex-supra bitaxe-gamma"
OUT=""
IMAGE_DIR=""
TARGET_DIR=${CARGO_TARGET_DIR:-C:/bt}
HOST_TARGET_DIR=${HOST_TARGET_DIR:-C:/bt-host}
BASELINE=""
SKIP_BUILD=0
SKIP_HOST_GATE=0
ALLOW_CR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --lane) LANE=$2; shift 2 ;;
        --pass) PASS=$2; shift 2 ;;
        --boards) BOARDS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --image-dir) IMAGE_DIR=$2; shift 2 ;;
        --target-dir) TARGET_DIR=$2; shift 2 ;;
        --host-target-dir) HOST_TARGET_DIR=$2; shift 2 ;;
        --baseline) BASELINE=$2; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-host-gate) SKIP_HOST_GATE=1; shift ;;
        --allow-cr) ALLOW_CR=1; shift ;;
        -h|--help) sed -n '2,63p' "$0"; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
done

EVIDENCE_DIR="$REPO_ROOT/projects/.axe-gauntlet/$PASS/$LANE"
[ -n "$OUT" ] || OUT="$EVIDENCE_DIR/measure.json"
[ -n "$IMAGE_DIR" ] || IMAGE_DIR="$EVIDENCE_DIR/images"
mkdir -p "$(dirname "$OUT")" "$IMAGE_DIR"

WORK=$(mktemp -d 2>/dev/null || printf '%s' "$EVIDENCE_DIR/.measure-tmp")
mkdir -p "$WORK"
cleanup() { [ -d "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

GATE_LOG="$EVIDENCE_DIR/gate.log"
: >"$WORK/boards.tsv"
: >"$WORK/gate.tsv"

# ---------------------------------------------------------------------------
# 0. Embedded-asset CR refusal (P1-I6). A SOURCE-state check, so it runs
#    unconditionally, before every other step, and regardless of
#    --skip-build/--skip-host-gate: a CRLF checkout inflates the image whether
#    or not this run goes on to build one. See the file header for why.
# ---------------------------------------------------------------------------
printf '== embedded-asset CR check ==\n'
if [ "$ALLOW_CR" -eq 1 ]; then
    set +e
    "$PYTHON" "$SCRIPT_DIR/measure_cr_check.py" \
        --dcentaxe-src "$ROOT_DIR/dcentaxe/src" --allow-cr
    cr_status=$?
    set -e
else
    set +e
    "$PYTHON" "$SCRIPT_DIR/measure_cr_check.py" \
        --dcentaxe-src "$ROOT_DIR/dcentaxe/src"
    cr_status=$?
    set -e
fi
if [ "$cr_status" -ne 0 ]; then
    printf 'embedded-asset CR check FAILED (exit %s) - see output above\n' "$cr_status" >&2
    exit "$cr_status"
fi

# ---------------------------------------------------------------------------
# 1. Handler census (Stage B step 4) - always run, it is cheap and it is the
#    only number that gates a lane's brief before a critic is spent on it.
# ---------------------------------------------------------------------------
printf '== handler census ==\n'
if ! "$PYTHON" "$SCRIPT_DIR/count_handlers.py" --json >"$WORK/handlers.json"; then
    printf 'handler census FAILED - see tools/count_handlers.py output\n' >&2
    exit 1
fi
"$PYTHON" "$SCRIPT_DIR/count_handlers.py" --quiet

# ---------------------------------------------------------------------------
# 2. Host gate (Stage B step 1)
# ---------------------------------------------------------------------------
run_gate() {
    label=$1
    shift
    printf '== host gate: %s ==\n' "$label"
    if (cd "$ROOT_DIR" && CARGO_TARGET_DIR="$HOST_TARGET_DIR" "$@") >"$WORK/gate-$label.out" 2>&1; then
        status=ok
    else
        status=failed
    fi
    cat "$WORK/gate-$label.out" >>"$GATE_LOG"
    # Sum the per-suite `test result: ok. N passed; M failed; ...` summary lines.
    counts=$(awk '/^test result:/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "passed;") p += $(i - 1)
                if ($i == "failed;") f += $(i - 1)
            }
        } END { printf "%d %d", p + 0, f + 0 }' "$WORK/gate-$label.out")
    passed=${counts% *}
    failed=${counts#* }
    printf '%s\t%s\t%s\t%s\n' "$label" "$passed" "$failed" "$status" >>"$WORK/gate.tsv"
    printf '%s: %s (%s passed, %s failed)\n' "$label" "$status" "$passed" "$failed"
}

if [ "$SKIP_HOST_GATE" -eq 0 ]; then
    : >"$GATE_LOG"
    run_gate core "$CARGO" "$HOST_TOOLCHAIN" test --locked --target "$HOST_TARGET" \
        -p dcentaxe-core -p dcentaxe-bap -p dcentaxe-stratum -p dcentaxe-mining \
        -p dcentaxe-stratum-v2 -p dcentaxe-asic -p dcentaxe-lora
    run_gate hal "$CARGO" "$HOST_TOOLCHAIN" test --locked --target "$HOST_TARGET" \
        -p dcentaxe-hal --no-default-features --features pins-bitaxe
else
    printf '== host gate SKIPPED (--skip-host-gate) ==\n'
fi

# ---------------------------------------------------------------------------
# 3. Per-board image measurement (Stage B steps 2-3)
# ---------------------------------------------------------------------------
flash_layout_for() { "$PYTHON" "$ROOT_DIR/scripts/target_matrix.py" lookup "$1" flash_layout; }

ota_slot_size() {
    "$PYTHON" - "$1" ota_0 <<'PY'
import sys
path, partition = sys.argv[1], sys.argv[2]
for raw in open(path, encoding="utf-8"):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    cols = [c.strip() for c in line.split(",")]
    if len(cols) >= 5 and cols[0] == partition and cols[1] == "app":
        print(int(cols[4], 0))
        break
else:
    raise SystemExit(f"{partition} app partition not found in {path}")
PY
}

if [ "$SKIP_BUILD" -eq 0 ]; then
    for board in $BOARDS; do
        printf '== board: %s ==\n' "$board"
        layout=$(flash_layout_for "$board")
        if [ "$layout" = "n16r8" ]; then
            csv="$ROOT_DIR/partitions-16mb.csv"
            flash_size=16mb
        else
            csv="$ROOT_DIR/partitions.csv"
            flash_size=8mb
        fi
        slot=$(ota_slot_size "$csv")

        # The release build subsumes Stage B step 2's `cargo check` for this board.
        (cd "$ROOT_DIR" && CARGO_TARGET_DIR="$TARGET_DIR" "$CARGO" build --release \
            -p dcentaxe --no-default-features --features "$board")

        elf="$TARGET_DIR/xtensa-esp32s3-espidf/release/dcentaxe"
        img="$IMAGE_DIR/$board.bin"
        "$ESPFLASH" save-image --chip esp32s3 --flash-size "$flash_size" \
            --partition-table "$csv" --target-app-partition ota_0 "$elf" "$img"

        bytes=$(wc -c <"$img" | tr -d ' ')
        set -- $("$SIZE_TOOL" "$elf" | awk 'NR==2 {print $1, $2, $3}')
        text=${1:-0}; data=${2:-0}; bss=${3:-0}
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$board" "$bytes" "$slot" "$text" "$data" "$bss" "$flash_size" "$img" \
            >>"$WORK/boards.tsv"
        printf '%s: %s / %s bytes\n' "$board" "$bytes" "$slot"
        if [ "$bytes" -gt "$slot" ]; then
            printf 'FAIL: %s image %s exceeds its ota_0 slot %s\n' "$board" "$bytes" "$slot" >&2
        fi
    done
else
    printf '== image build SKIPPED (--skip-build) ==\n'
fi

# ---------------------------------------------------------------------------
# 4. Per-asset byte table + JSON assembly
# ---------------------------------------------------------------------------
# measure_assemble.py is the ONE writer of measure.json. Both ports feed it the
# same three inputs and neither formats the document itself, so the two can not
# drift into different schemas (round 1 shipped two independent writers that
# disagreed on `xtensa_check` and on the `boards` container - see that file's
# header). `tools/check_measure_ports.py` proves the parity end to end.
"$PYTHON" "$SCRIPT_DIR/measure_assemble.py" \
    --work "$WORK" \
    --root "$ROOT_DIR" \
    --repo "$REPO_ROOT" \
    --out "$OUT" \
    --lane "$LANE" \
    --baseline "$BASELINE"
