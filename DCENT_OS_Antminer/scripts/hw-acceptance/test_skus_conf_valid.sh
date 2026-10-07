#!/bin/sh
# Structural validator for the acceptance harness's single source of truth,
# skus.conf. dcent-accept.sh parses each row with `set -- $line` on IFS='|', so a
# row with the wrong column count or a malformed field silently MIS-ASSIGNS the
# per-SKU metadata (e.g. ENUM_EXPECT ends up holding a note fragment) and the
# whole acceptance flow then runs with wrong parameters against LIVE hardware.
# This fails such a typo offline. It also enforces the documented column
# vocabulary and the arch<->soc<->boot_chain pairings the harness assumes, so the
# "plug in and press Enter" flow is trustworthy for every SKU row.
set -u

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONF="$here/skus.conf"
[ -r "$CONF" ] || { echo "FAIL: skus.conf not found at $CONF"; exit 1; }

fails=0
bad() { echo "  FAIL: $*"; fails=$((fails + 1)); }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$CONF" > "$tmp"

rows=0
seen=" "
OLDIFS=$IFS
while IFS= read -r line; do
    [ -n "$line" ] || continue
    rows=$((rows + 1))

    # Exactly 11 columns => exactly 10 '|' separators. A wrong count is the
    # silent-misparse case (`set --` shifts every field after the gap).
    bars=$(printf '%s' "$line" | tr -cd '|' | wc -c | tr -d ' ')
    if [ "$bars" != "10" ]; then
        bad "row $rows: $bars '|' separators (need 10 for 11 columns): $line"
        continue
    fi

    IFS='|'
    # shellcheck disable=SC2086
    set -- $line
    IFS=$OLDIFS
    sku=$1; bt=$2; arch=$3; chip=$4; cid=$5; en=$6; soc=$7; bc=$8; rs=$9; pkg=${10}; note=${11}

    for pair in "sku=$sku" "board_target=$bt" "arch=$arch" "chip=$chip" \
                "chip_id=$cid" "enum_expect=$en" "soc=$soc" "boot_chain=$bc" \
                "release_state=$rs" "package=$pkg" "note=$note"; do
        [ -n "${pair#*=}" ] || bad "row $rows ($sku): empty ${pair%%=*}"
    done

    lc=$(printf '%s' "$sku" | tr 'A-Z' 'a-z')
    case "$seen" in *" $lc "*) bad "duplicate SKU token: $sku" ;; esac
    seen="$seen$lc "

    case "$arch" in armv7 | aarch64) : ;; *) bad "row $rows ($sku): arch '$arch' not armv7|aarch64" ;; esac
    case "$chip" in BM[0-9]*) : ;; *) bad "row $rows ($sku): chip '$chip' not BM<digits>" ;; esac
    case "$cid" in 0 | 0x[0-9a-fA-F]*) : ;; *) bad "row $rows ($sku): chip_id '$cid' not 0 or 0x<hex>" ;; esac
    case "$en" in '' | *[!0-9]*) bad "row $rows ($sku): enum_expect '$en' not a non-negative integer" ;; esac
    case "$soc" in zynq | amlogic | am335x) : ;; *) bad "row $rows ($sku): soc '$soc' not zynq|amlogic|am335x" ;; esac
    case "$bc" in nand-ab | single-image | external-media) : ;; *) bad "row $rows ($sku): boot_chain '$bc' not nand-ab|single-image|external-media" ;; esac
    case "$rs" in PRODUCTION | EXPERIMENTAL | NOT-IMPLEMENTED) : ;; *) bad "row $rows ($sku): release_state '$rs' invalid" ;; esac

    # Cross-field consistency the harness relies on. AM335x is ARMv7 but is a
    # distinct external-media-only route, never a Zynq A/B alias.
    case "$arch/$soc" in armv7/zynq | armv7/am335x | aarch64/amlogic) : ;; *) bad "row $rows ($sku): arch/soc mismatch '$arch/$soc'" ;; esac
    case "$soc/$bc" in
        zynq/nand-ab | amlogic/single-image | am335x/external-media) : ;;
        zynq/external-media)
            case "$sku/$bt" in
                S15/am1-s15 | T15/am1-t15) : ;;
                *) bad "row $rows ($sku): unadmitted Zynq external-media target '$bt'" ;;
            esac
            ;;
        *) bad "row $rows ($sku): soc/boot_chain mismatch '$soc/$bc'" ;;
    esac
    case "$soc/$bt" in am335x/am3-bb-*) : ;; am335x/*) bad "row $rows ($sku): AM335x board_target '$bt' must start am3-bb-" ;; esac
done < "$tmp"

[ "$rows" -eq 28 ] || bad "expected exactly 28 target SKU rows, found $rows"

if [ "$fails" -eq 0 ]; then
    echo "PASS: skus.conf structurally valid — $rows SKU rows; columns, vocabulary, and arch/soc/boot_chain consistency all OK"
    exit 0
fi
echo "FAIL: $fails skus.conf validation error(s)"
exit 1
