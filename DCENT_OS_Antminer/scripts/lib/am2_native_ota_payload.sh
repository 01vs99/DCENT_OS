#!/bin/sh
# Stage the exact raw FPGA bytes consumed by the native two-slot AM2 updater.
dcent_stage_am2_native_ota_payload() {
    case "$BOARD_NAME" in
        am2-s17p|am2-s17plus|am2-t17|am2-t17plus|am2-s19pro|am2-s19j) ;;
        *) echo "Error: no native AM2 OTA fabric for $BOARD_NAME" >&2; return 1 ;;
    esac
    DCENT_NATIVE_FPGA_SOURCE=${DCENT_AM2_NATIVE_BITSTREAM:-${BITSTREAM:-}}
    [ -n "$DCENT_NATIVE_FPGA_SOURCE" ] || {
        echo "Error: set DCENT_AM2_NATIVE_BITSTREAM to the admitted raw AM2 FPGA payload" >&2
        return 1
    }
    [ -f "$DCENT_NATIVE_FPGA_SOURCE" ] && [ ! -L "$DCENT_NATIVE_FPGA_SOURCE" ] || return 1
    python3 "$PROJECT_ROOT/scripts/lib/am2_ota_boot.py" verify-payload "$DCENT_NATIVE_FPGA_SOURCE" || return 1
    cp "$DCENT_NATIVE_FPGA_SOURCE" "$SUP_DIR/fpga_bitstream.bit" || return 1
    python3 "$PROJECT_ROOT/scripts/lib/am2_ota_boot.py" verify-payload "$SUP_DIR/fpga_bitstream.bit" || return 1
    BITSTREAM_SIZE=$(stat -c%s "$SUP_DIR/fpga_bitstream.bit") || return 1
    BITSTREAM_SHA256=$(sha256sum "$SUP_DIR/fpga_bitstream.bit" | awk '{print $1}') || return 1
    if [ -f "$SUP_DIR/SHA256SUMS" ]; then
        awk '$2 != "fpga_bitstream.bit"' "$SUP_DIR/SHA256SUMS" > "$SUP_DIR/.SHA256SUMS.native" || return 1
        printf '%s  fpga_bitstream.bit\n' "$BITSTREAM_SHA256" >> "$SUP_DIR/.SHA256SUMS.native" || return 1
        mv "$SUP_DIR/.SHA256SUMS.native" "$SUP_DIR/SHA256SUMS" || return 1
    fi
    DCENT_EXTRA_PAYLOAD_BLOCK=",
    \"bitstream\": {
      \"path\": \"sysupgrade-${BOARD_NAME}/fpga_bitstream.bit\",
      \"size\": ${BITSTREAM_SIZE},
      \"sha256\": \"${BITSTREAM_SHA256}\"
    }"
}
