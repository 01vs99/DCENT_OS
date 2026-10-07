#!/bin/sh
# Loaded by S12fpga_identity. Arguments are the boot-owned observation paths.
# This helper observes programming; it never programs the FPGA or changes clocks.
dcent_am2_fabric_identity() {
    dcent_board_file=$1
    dcent_cmdline_file=$2
    dcent_boot_id_file=$3
    dcent_prog_done_file=$4
    dcent_fclk_export_file=$5
    dcent_fclk_rate_file=$6
    dcent_receipt_dir=$7
    dcent_expected_sha=4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22

    case "$(cat "$dcent_board_file" 2>/dev/null)" in
        am2-s17p|am2-s17plus|am2-t17|am2-t17plus) dcent_receipt_name=s17-fabric.json ;;
        am2-s19pro) dcent_receipt_name=bm1398-fabric.json ;;
        *) return 0 ;;
    esac
    mkdir -p "$dcent_receipt_dir" || return 1
    rm -f "$dcent_receipt_dir/$dcent_receipt_name" || return 1

    dcent_loaded=
    dcent_loaded_sha=
    dcent_load_count=0
    dcent_sha_count=0
    # Kernel command line fields are whitespace-separated tokens, not shell code.
    set -f
    for dcent_arg in $(cat "$dcent_cmdline_file"); do
        case "$dcent_arg" in
            dcent.fpga_load_completed=*)
                dcent_loaded=${dcent_arg#*=}
                dcent_load_count=$((dcent_load_count + 1)) ;;
            dcent.fpga_sha256=*)
                dcent_loaded_sha=${dcent_arg#*=}
                dcent_sha_count=$((dcent_sha_count + 1)) ;;
        esac
    done
    [ "$dcent_load_count" = 1 ] && [ "$dcent_loaded" = 1 ] || return 1
    [ "$dcent_sha_count" = 1 ] && [ "$dcent_loaded_sha" = "$dcent_expected_sha" ] || return 1
    [ "$(cat "$dcent_prog_done_file" 2>/dev/null)" = 1 ] || return 1
    dcent_boot_id=$(cat "$dcent_boot_id_file") || return 1
    printf '%s\n' "$dcent_boot_id" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || return 1

    # xilinx-v2016.4 xdevcfg: fclk_export creates an observation node and
    # clk_prepare()s it. Only the separate enable/set_rate stores change clocks.
    if [ ! -r "$dcent_fclk_rate_file" ]; then
        printf '%s\n' fclk0 > "$dcent_fclk_export_file" || return 1
    fi
    [ -r "$dcent_fclk_rate_file" ] || return 1
    dcent_clock_rate=$(cat "$dcent_fclk_rate_file") || return 1
    case "$dcent_clock_rate" in ''|*[!0-9]*) return 1 ;; esac
    [ "$dcent_clock_rate" -gt 0 ] || return 1

    (umask 077
     printf '{"schema":1,"boot_id":"%s","bitstream_sha256":"%s","load_completed":true,"prog_done":1}\n' \
         "$dcent_boot_id" "$dcent_expected_sha" > "$dcent_receipt_dir/.$dcent_receipt_name.tmp"
    ) || return 1
    mv -f "$dcent_receipt_dir/.$dcent_receipt_name.tmp" "$dcent_receipt_dir/$dcent_receipt_name"
}
