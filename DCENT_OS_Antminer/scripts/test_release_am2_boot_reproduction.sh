#!/bin/sh
# Blocking gate: offline reproduction of the ten native AM2 boot pins with the
# sha-pinned mkimage, plus static wiring pins for the producer plumbing.
# Fails loud when the pinned tool or donor is missing — never skips.
# NOTE: run under a Linux shell (the blocking-gate host). Under MSYS/Git Bash
# the /toolchain-local pattern is path-converted and the pinned ELF cannot
# execute — standalone Windows runs fail closed, which is intended.
set -eu
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $1" >&2; exit 1; }

# Anchor the wiring checks to the Phase-4 docker run specifically.
PHASE4=$(sed -n '/^# -------- Phase 4: admit/,/release_stage_boot\.py/p' scripts/build_in_docker.sh)
[ -n "$PHASE4" ] || fail "Phase-4 block not found in build_in_docker.sh"
printf '%s\n' "$PHASE4" | grep -q 'MKIMAGE_MOUNT_ARGS\[@\]' ||
    fail "Phase-4 docker run must expand MKIMAGE_MOUNT_ARGS"
printf '%s\n' "$PHASE4" | grep -q 'e DCENT_MKIMAGE="/toolchain-local/u-boot-2026.04-mkimage/mkimage"' ||
    fail "Phase-4 docker run must pass the pinned mkimage path via DCENT_MKIMAGE"

[ "$(grep -c '998314bbd994aa5a8d37f089975f727e6500bce207dfda1322da0877c9b4c99d' scripts/build_in_docker.sh)" -eq 1 ] ||
    fail "pinned mkimage sha256 must be wired into build_in_docker.sh exactly once"
[ "$(grep -c '"--mkimage", mkimage' scripts/release_stage_boot.py)" -eq 1 ] ||
    fail "release_stage_boot must forward --mkimage to the boot producer exactly once"
[ "$(grep -c 'DCENT_MKIMAGE' scripts/release_stage_boot.py)" -eq 2 ] ||
    fail "release_stage_boot must read DCENT_MKIMAGE and name it in its refusal (exactly twice)"
[ "$(grep -c 'MKIMAGE_PIN_VERSION' scripts/prepare_release_am2_boot.py)" -ge 2 ] ||
    fail "prepare_release_am2_boot must define and enforce the pinned mkimage version"

python3 scripts/test_release_am2_boot_reproduction.py
echo "AM2 boot-pin reproduction gate: all checks passed"
