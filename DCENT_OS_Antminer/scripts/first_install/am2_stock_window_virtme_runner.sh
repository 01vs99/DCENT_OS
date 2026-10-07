#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
HELPER=${1:-}; KERNEL=${2:-/boot/vmlinuz-5.15.0-181-generic}; ARM_HELPER=${3:-}
[[ -f "$HELPER" && ! -L "$HELPER" && -f "$KERNEL" && -f "$ARM_HELPER" && ! -L "$ARM_HELPER" ]] || exit 64
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
TOOLS=$(CDPATH='' cd -- "$(dirname -- "$HELPER")" && pwd -P)
[[ "$HELPER" == "$TOOLS/am2-nand-window" && "$ARM_HELPER" == "$TOOLS/am2-nand-window-armv7" ]] || exit 64
python3 "$HERE/build_am2_stock_window.py" verify --output-dir "$TOOLS"
python3 "$HERE/../virtme/am2-ubi/verify_manifest.py" verify-kernel \
    --lock "$HERE/../virtme/am2-ubi/inputs.lock.json" --kernel "$KERNEL"
sha256sum "$HERE/am2_nand_window.c" "$HELPER" "$ARM_HELPER" "$HERE/am2_stock_window_nandsim.sh" "$KERNEL"
printf -v GUEST 'set -e; export DCENT_DISPOSABLE_VIRTME=am2-stock-window-v1; bash %q %q %q %q' \
    "$HERE/am2_stock_window_nandsim.sh" "/tmp/dcent-am2-stock-window-$(date +%s)-$$" "$HELPER" "$ARM_HELPER"
vng --run "$KERNEL" --memory 2048M --cpus 2 --disable-kvm --exec "$GUEST"
