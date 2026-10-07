#!/bin/sh
# Check the current source contract without consuming a workstation's retained
# physical/source receipts. Their exact-byte validation remains independently
# covered by test_s19k_gauntlet_workflow.py and the operator workflow command.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DCENT_S19K_CHECKOUT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/dcent-s19k-checkout.XXXXXX")
trap 'rmdir "$DCENT_S19K_CHECKOUT_TMP"' EXIT
python3 "$SCRIPT_DIR/s19k_gauntlet_workflow.py" \
    --evidence-root "$DCENT_S19K_CHECKOUT_TMP" verify \
    --expect-frontier portable-artifact-custody,native-build-reproducibility,native-secure-firmware-re,static-bhb5690x-controller-interface
