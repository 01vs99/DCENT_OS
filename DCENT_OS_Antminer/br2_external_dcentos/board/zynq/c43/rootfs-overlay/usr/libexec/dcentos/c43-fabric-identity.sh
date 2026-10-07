#!/bin/sh
# Observe the exact successful U-Boot FPGA load and current kernel PROG_DONE.
# This helper neither programs the FPGA nor writes any hardware register.
dcent_c43_fabric_identity() {
    dcent_board=$1
    dcent_pin=$2
    dcent_cmdline=$3
    dcent_bootid=$4
    dcent_progdone=$5
    dcent_output=$6
    dcent_sha=1681558e124de9a3721bf4fe4b885ba9a122d2a9f2a4d7e0f560824d95cdd6cc
    case "$(cat "$dcent_board" 2>/dev/null)" in am1-s9se|am1-s9k) ;; *) return 1 ;; esac
    mkdir -p "$dcent_output" || return 1
    rm -f "$dcent_output/c43-fabric.json" || return 1
    [ -f "$dcent_pin" ] && [ ! -L "$dcent_pin" ] || return 1
    [ "$(cat "$dcent_pin")" = "$dcent_sha" ] || return 1
    dcent_load_count=0 dcent_sha_count=0 dcent_loaded= dcent_observed_sha=
    set -f
    for dcent_arg in $(cat "$dcent_cmdline"); do
        case "$dcent_arg" in
            dcent.c43_load_completed=*) dcent_load_count=$((dcent_load_count + 1)); dcent_loaded=${dcent_arg#*=} ;;
            dcent.c43_sha256=*) dcent_sha_count=$((dcent_sha_count + 1)); dcent_observed_sha=${dcent_arg#*=} ;;
        esac
    done
    [ "$dcent_load_count" = 1 ] && [ "$dcent_loaded" = 1 ] || return 1
    [ "$dcent_sha_count" = 1 ] && [ "$dcent_observed_sha" = "$dcent_sha" ] || return 1
    [ "$(cat "$dcent_progdone" 2>/dev/null)" = 1 ] || return 1
    dcent_boot=$(cat "$dcent_bootid") || return 1
    printf '%s\n' "$dcent_boot" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || return 1
    (umask 077
     printf '{"schema":1,"boot_id":"%s","bitstream_sha256":"%s","load_completed":true,"prog_done":true}\n' \
       "$dcent_boot" "$dcent_sha" > "$dcent_output/.c43-fabric.json.tmp") || return 1
    mv -f "$dcent_output/.c43-fabric.json.tmp" "$dcent_output/c43-fabric.json"
}
