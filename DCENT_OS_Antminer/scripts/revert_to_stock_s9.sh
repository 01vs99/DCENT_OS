#!/bin/sh
# S9 owner-host entry to the full-backup stock transaction. Run on the host
# with dcent-toolbox installed; this wrapper never opens controller devices.
# The executor validates the original stock layout, observed firmware selector,
# pinned unit/key, complete backup and independent write readback. It retains
# the workspace across interruption and never restarts the controller.
set -eu

case "${1:-}" in
    source-import-s9|source-check|prepare|execute|resume|rollback|confirm-boot|--help|-h) ;;
    *)
        printf '%s\n' 'Usage: revert_to_stock_s9.sh {source-import-s9|source-check|prepare|execute|resume|rollback|confirm-boot} [stock transaction options]' \
            'Run on the owner host with dcent-toolbox installed. A saved original stock source and retained workspace are required.' >&2
        exit 2
        ;;
esac
exec python3 -m dcent_toolbox.cli.stock_revert "$@" --require-board-target am1-s9
