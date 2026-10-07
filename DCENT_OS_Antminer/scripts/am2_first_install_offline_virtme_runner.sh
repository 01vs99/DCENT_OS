#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Exact no-fastmap module closure plus canonical AM2 first-install transaction.
set -euo pipefail
BUNDLE=${1:-}
KERNEL=${2:-/boot/vmlinuz-5.15.0-181-generic}
LAYOUT=${3:-canonical}
WRITER=${4:-/root/dcent-beta-i01-tools/am2-nand-window}
case "$LAYOUT" in canonical|blank|vendor) ;; *) exit 64 ;; esac
[[ -d "$BUNDLE" && -f "$KERNEL" ]] || exit 64
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
TOOLBOX=$(CDPATH='' cd -- "$SCRIPT_DIR/../../dcent-toolbox" && pwd -P)
VERIFY="$SCRIPT_DIR/virtme/am2-ubi/verify_manifest.py"
LOCK="$SCRIPT_DIR/virtme/am2-ubi/inputs.lock.json"
cmp "$LOCK" "$BUNDLE/inputs.lock.json"
python3 "$VERIFY" verify-bundle --manifest "$BUNDLE/manifest.json" --lock "$LOCK" --bundle-dir "$BUNDLE"
python3 "$VERIFY" verify-kernel --lock "$LOCK" --kernel "$KERNEL"
python3 "$SCRIPT_DIR/first_install/build_am2_stock_window.py" verify --output-dir "$(dirname "$WRITER")"
STAGE1="$TOOLBOX/src/dcent_toolbox/_am2_first_install/stage1.sh"
HARNESS="$SCRIPT_DIR/am2_first_install_offline_nandsim_harness.sh"
sha256sum "$STAGE1" "$HARNESS" "$WRITER" "$BUNDLE/ubi-nofastmap.ko" "$BUNDLE/ubifs-nofastmap.ko" "$KERNEL"
printf -v GUEST 'set -e; export DCENT_DISPOSABLE_VIRTME=am2-first-install-v1 DCENT_AM2_NANDSIM_LAYOUT=%q; modprobe mtd; insmod %q; insmod %q; bash %q %q %q %q' \
    "$LAYOUT" \
    "$BUNDLE/ubi-nofastmap.ko" "$BUNDLE/ubifs-nofastmap.ko" "$HARNESS" \
    "/tmp/dcent-am2-nandsim-$(date +%s)-$$" "$STAGE1" "$WRITER"
vng --run "$KERNEL" --memory 2048M --cpus 2 --disable-kvm --exec "$GUEST"
