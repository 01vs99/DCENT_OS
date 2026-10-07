#!/bin/sh
# Observe successful exact U-Boot load and current kernel PROG_DONE. The
# runtime validates this root-owned receipt again before reserving the fabric.
dcent_bm1396_fabric_identity() (
    [ "$#" = 6 ] || exit 1
    dcent_board=$1 dcent_pin=$2 dcent_cmdline=$3
    dcent_bootid=$4 dcent_progdone=$5 dcent_output=$6
    dcent_sha=39109da8ab92a08842141bd960d70987a47f368c9529c124540dce71c4098195
    [ ! -L "$dcent_output" ] || exit 1
    umask 077
    mkdir -p "$dcent_output" && chmod 700 "$dcent_output" || exit 1
    rm -f "$dcent_output/bm1396-fabric.json" || exit 1
    for dcent_input in "$dcent_board" "$dcent_pin" "$dcent_cmdline" "$dcent_bootid" "$dcent_progdone"; do
        [ -f "$dcent_input" ] && [ ! -L "$dcent_input" ] || exit 1
    done
    dcent_target=$(cat "$dcent_board") || exit 1
    case "$dcent_target" in am2-s17e|am2-t17e) ;; *) exit 1 ;; esac
    [ "$(cat "$dcent_pin")" = "$dcent_sha" ] || exit 1
    dcent_load_count=0 dcent_sha_count=0 dcent_target_count=0
    dcent_loaded= dcent_observed_sha= dcent_observed_target=
    set -f
    for dcent_arg in $(cat "$dcent_cmdline"); do
        case "$dcent_arg" in
            dcent.bm1396_load_completed=*) dcent_load_count=$((dcent_load_count + 1)); dcent_loaded=${dcent_arg#*=} ;;
            dcent.bm1396_sha256=*) dcent_sha_count=$((dcent_sha_count + 1)); dcent_observed_sha=${dcent_arg#*=} ;;
            dcent.bm1396_target=*) dcent_target_count=$((dcent_target_count + 1)); dcent_observed_target=${dcent_arg#*=} ;;
        esac
    done
    [ "$dcent_load_count" = 1 ] && [ "$dcent_loaded" = 1 ] || exit 1
    [ "$dcent_sha_count" = 1 ] && [ "$dcent_observed_sha" = "$dcent_sha" ] || exit 1
    [ "$dcent_target_count" = 1 ] && [ "$dcent_observed_target" = "$dcent_target" ] || exit 1
    [ "$(cat "$dcent_progdone")" = 1 ] || exit 1
    dcent_boot=$(cat "$dcent_bootid") || exit 1
    printf '%s\n' "$dcent_boot" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || exit 1
    dcent_tmp=$(mktemp "$dcent_output/.bm1396-fabric.XXXXXX") || exit 1
    trap 'rm -f "$dcent_tmp"' EXIT HUP INT TERM
    printf '{"schema":1,"boot_id":"%s","board_target":"%s","bitstream_sha256":"%s","load_completed":true,"prog_done":true}\n' \
        "$dcent_boot" "$dcent_target" "$dcent_sha" > "$dcent_tmp" || exit 1
    mv -f "$dcent_tmp" "$dcent_output/bm1396-fabric.json" || exit 1
)
