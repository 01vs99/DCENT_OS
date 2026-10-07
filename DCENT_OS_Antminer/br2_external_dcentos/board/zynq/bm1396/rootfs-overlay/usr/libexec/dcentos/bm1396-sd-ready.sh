#!/bin/sh
# Read-only startup condition; this marker never authorizes mining hardware.
dcent_bm1396_sd_ready() (
    [ "$#" = 3 ] || exit 1
    dcent_identity=$1 dcent_runtime=$2 dcent_bootid=$3
    for dcent_file in "$dcent_identity/board_target" "$dcent_identity/bm1396-data-uuid" \
        "$dcent_runtime/bm1396-sd-data-ready" "$dcent_runtime/bm1396-boot-cut-ready" \
        "$dcent_runtime/bm1396-boot-cut.json" "$dcent_runtime/bm1396-fabric.json" "$dcent_bootid"; do
        [ -f "$dcent_file" ] && [ ! -L "$dcent_file" ] || exit 1
        [ "$(wc -c < "$dcent_file")" -le 1024 ] || exit 1
    done
    case "$(cat "$dcent_identity/board_target")" in am2-s17e|am2-t17e) ;; *) exit 1 ;; esac
    dcent_boot=$(cat "$dcent_bootid")
    printf '%s\n' "$dcent_boot" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 1
    [ "$(cat "$dcent_runtime/bm1396-boot-cut-ready")" = "$dcent_boot" ] || exit 1
    dcent_data=$(cat "$dcent_identity/bm1396-data-uuid")
    printf '%s\n' "$dcent_data" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 1
    [ "$(cat "$dcent_runtime/bm1396-sd-data-ready")" = "$dcent_data" ] || exit 1
)
