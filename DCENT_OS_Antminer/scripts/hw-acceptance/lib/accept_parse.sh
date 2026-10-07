# accept_parse.sh — pure, hardware-free parsers for the DCENT_OS acceptance harness.
#
# This library is the load-bearing PASS/FAIL logic behind dcent-accept.sh. It is
# deliberately split out and side-effect-free so it can be unit-tested against
# captured fixtures with NO miner attached (test_accept_parse.sh, wired into the
# offline CI gate). If the accepted-share counter parse ever silently breaks, the
# whole acceptance gate would rubber-stamp a dead miner — so every function here
# has fixture coverage.
#
# POSIX sh only (runs under BusyBox ash on the miner and `sh -n` in CI). No bashisms.
#
# The firmware-agnostic accepted-share counter is the CGMiner-compatible API on
# port 4028: `{"command":"summary"}` -> SUMMARY[0].Accepted. This is identical
# across DCENT_OS, BraiinsOS, LuxOS, and stock bmminer/cgminer, so the same parser
# validates a miner regardless of which firmware answered.

# accept_parse_accepted — read a CGMiner summary JSON on stdin, echo the SUMMARY
# Accepted counter as a bare integer. The REST `sharesAccepted` mirror is the
# no-`nc` fallback. Echoes nothing if both shapes are absent/malformed.
#
# Precision note: the regex requires a double-quote IMMEDIATELY before `Accepted`,
# so it matches the real "Accepted" key but NOT "Difficulty Accepted" (which CGMiner
# also emits, preceded by a space) and NOT "Rejected". head -n1 guards the POOLS
# section also carrying an Accepted key on other commands.
accept_parse_accepted() {
    body=$(cat)
    n=$(printf '%s' "$body" \
        | grep -oE '"Accepted"[[:space:]]*:[[:space:]]*[0-9]+' 2>/dev/null \
        | head -n1 | grep -oE '[0-9]+$' || true)
    if [ -z "$n" ]; then
        n=$(printf '%s' "$body" \
            | grep -oE '"sharesAccepted"[[:space:]]*:[[:space:]]*[0-9]+' 2>/dev/null \
            | head -n1 | grep -oE '[0-9]+$' || true)
    fi
    printf '%s' "$n"
}

# accept_parse_mhs_av — echo SUMMARY "MHS av" or normalize REST `hashRate`
# from GH/s to MH/s.
accept_parse_mhs_av() {
    body=$(cat)
    n=$(printf '%s' "$body" \
        | grep -oE '"MHS av"[[:space:]]*:[[:space:]]*[0-9]+\.?[0-9]*' 2>/dev/null \
        | head -n1 | grep -oE '[0-9]+\.?[0-9]*$' || true)
    if [ -z "$n" ]; then
        n=$(printf '%s' "$body" \
            | grep -oE '"hashRate"[[:space:]]*:[[:space:]]*[0-9]+\.?[0-9]*' 2>/dev/null \
            | head -n1 | grep -oE '[0-9]+\.?[0-9]*$' \
            | awk '{ value=$1*1000; printf "%.6f", value }' \
            | sed 's/0*$//; s/\.$//' || true)
    fi
    printf '%s' "$n"
}

# accept_parse_elapsed — echo SUMMARY "Elapsed" or REST `uptime_s` in seconds.
accept_parse_elapsed() {
    body=$(cat)
    n=$(printf '%s' "$body" \
        | grep -oE '"Elapsed"[[:space:]]*:[[:space:]]*[0-9]+' 2>/dev/null \
        | head -n1 | grep -oE '[0-9]+$' || true)
    if [ -z "$n" ]; then
        n=$(printf '%s' "$body" \
            | grep -oE '"uptime_s"[[:space:]]*:[[:space:]]*[0-9]+' 2>/dev/null \
            | head -n1 | grep -oE '[0-9]+$' || true)
    fi
    printf '%s' "$n"
}

# accept_parse_enumerated — echo the enumerated chip count from a dcentrald log line
# or REST /api/status body (e.g. "enumerated 342 chips",
# `"chips_enumerated":342`). Configured address-assignment totals are
# deliberately not parsed as observed chip population.
accept_parse_enumerated() {
    body=$(cat)
    n=$(printf '%s' "$body" \
        | grep -oE 'enumerated[[:space:]]+[0-9]+[[:space:]]+chips' 2>/dev/null \
        | head -n1 | grep -oE '[0-9]+' | head -n1 || true)
    if [ -z "$n" ]; then
        n=$(printf '%s' "$body" \
            | grep -oE '"chips?_?enumerated?"[[:space:]]*:[[:space:]]*[0-9]+' 2>/dev/null \
            | head -n1 | grep -oE '[0-9]+$' || true)
    fi
    printf '%s' "$n"
}

# Extract one JSON string field from the simple one-line objects emitted by the
# harness. This is intentionally not a general JSON parser; decision-making
# callers separately reject duplicate fields.
accept_parse_json_string_field() {
    _jfield=${1:-}
    grep -oE '"'"$_jfield"'"[[:space:]]*:[[:space:]]*"[^"]*"' 2>/dev/null \
        | head -n1 \
        | sed 's/^[^:]*:[[:space:]]*"//; s/"$//' \
        || true
}

# Prove that one current dcentrald process owns BOTH loopback listeners used by
# an acceptance verdict and that port 4028 identifies itself as DCENT_OS. The
# normalized process lines are produced read-only from /proc by the harness;
# the remaining line is the raw CGMiner `version` response. An expected PID is
# optional, but AM3-BB supplies its route-admission PID.
accept_dcentrald_producer_verdict() {
    _dpexpected=${1:-}
    _dpdata=$(cat)
    _dppid=$(printf '%s\n' "$_dpdata" | sed -n 's/^producer_pid=//p')
    _dpstart=$(printf '%s\n' "$_dpdata" | sed -n 's/^producer_start_ticks=//p')
    _dpexe=$(printf '%s\n' "$_dpdata" | sed -n 's/^producer_exe=//p')
    [ "$(printf '%s\n' "$_dpdata" | grep -c '^producer_pid=')" -eq 1 ] &&
        [ "$(printf '%s\n' "$_dpdata" | grep -c '^producer_start_ticks=')" -eq 1 ] &&
        [ "$(printf '%s\n' "$_dpdata" | grep -c '^producer_exe=')" -eq 1 ] &&
        [ "$(printf '%s\n' "$_dpdata" | grep -c '^listener_pair=4028,8080$')" -eq 1 ] &&
        accept_is_uint "$_dppid" && accept_is_uint "$_dpstart" || {
            echo PRODUCER_FAIL:listener_ownership
            return 1
        }
    case "$_dpexe" in
        /*/dcentrald|/*/dcentrald_runtime) : ;;
        *) echo PRODUCER_FAIL:executable; return 1 ;;
    esac
    if [ -n "$_dpexpected" ] && [ "$_dppid" != "$_dpexpected" ]; then
        echo PRODUCER_FAIL:route_pid
        return 1
    fi
    [ "$(printf '%s' "$_dpdata" | grep -oE '"Firmware"[[:space:]]*:[[:space:]]*"DCENTOS"' | wc -l | tr -d ' ')" -eq 1 ] &&
        [ "$(printf '%s' "$_dpdata" | grep -oE '"DCENTOS"[[:space:]]*:[[:space:]]*"[^"]+"' | wc -l | tr -d ' ')" -eq 1 ] &&
        [ "$(printf '%s' "$_dpdata" | grep -oE '"Miner"[[:space:]]*:[[:space:]]*"dcentrald/[^"]+"' | wc -l | tr -d ' ')" -eq 1 ] || {
            echo PRODUCER_FAIL:firmware_identity
            return 1
        }
    echo PRODUCER_PASS
    return 0
}

# Strict AM3-BB route identity. Reads normalized read-only SSH/REST evidence
# and accepts only the exact live LuxOS device-tree tuple, current process,
# runtime-admission receipt, and reachable REST API.
accept_am3_bb_identity_verdict() {
    _aicase=${1:-}
    printf '%s' "$_aicase" | grep -Eq '^/tmp/dcentos-am3-bb\.[A-Za-z0-9]+$' || {
        echo IDENTITY_FAIL:case_dir
        return 1
    }
    _aidata=$(cat)
    _aistate=$(printf '%s\n' "$_aidata" | grep -E '^marker_state=(absent|present)$' || true)
    [ "$(printf '%s\n' "$_aistate" | grep -c .)" -eq 1 ] || {
        echo IDENTITY_FAIL:marker_state
        return 1
    }
    case "$_aistate" in
        marker_state=absent)
            [ "$(printf '%s\n' "$_aidata" | grep -c '^marker=')" -eq 0 ] || {
                echo IDENTITY_FAIL:board_target
                return 1
            }
            ;;
        marker_state=present)
            [ "$(printf '%s\n' "$_aidata" | grep -c '^marker=')" -eq 1 ] &&
                [ "$(printf '%s\n' "$_aidata" | grep -c '^marker=am3-bb-s19jpro$')" -eq 1 ] || {
                echo IDENTITY_FAIL:board_target
                return 1
            }
            ;;
    esac
    [ "$(printf '%s\n' "$_aidata" | grep -c '^compatible=ti,am335x-bone-black$')" -eq 1 ] || {
        echo IDENTITY_FAIL:soc
        return 1
    }
    [ "$(printf '%s\n' "$_aidata" | grep -c '^model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0$')" -eq 1 ] || {
        echo IDENTITY_FAIL:carrier
        return 1
    }
    _aipid=$(printf '%s\n' "$_aidata" | sed -n 's/^current_pid=//p')
    [ "$(printf '%s\n' "$_aidata" | grep -c '^current_pid=')" -eq 1 ] && accept_is_uint "$_aipid" || {
        echo IDENTITY_FAIL:process
        return 1
    }
    _aicmd=$(printf '%s\n' "$_aidata" | sed -n 's/^cmdline=//p')
    [ "$(printf '%s\n' "$_aidata" | grep -c '^cmdline=')" -eq 1 ] || {
        echo IDENTITY_FAIL:process
        return 1
    }
    _aiexec=$(printf '%s\n' "$_aicmd" | awk 'NF { print $1; exit }')
    [ "$_aiexec" = "$_aicase/dcentrald" ] || {
        echo IDENTITY_FAIL:process
        return 1
    }
    printf '%s\n' "$_aicmd" | awk '{ for (i=2; i<=NF; i++) if ($i == "--am3-bb-mining") n++ } END { exit !(n == 1) }' || {
        echo IDENTITY_FAIL:process
        return 1
    }
    _aireceipt="AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v3 run_pid=$_aipid board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence=exact_device_tree"
    [ "$(printf '%s\n' "$_aidata" | grep -F -x -c "$_aireceipt")" -eq 1 ] || {
        echo IDENTITY_FAIL:runtime_receipt
        return 1
    }
    [ "$(printf '%s\n' "$_aidata" | grep -c '^rest_reachable=1$')" -eq 1 ] || {
        echo IDENTITY_FAIL:rest
        return 1
    }
    [ "$(printf '%s\n' "$_aidata" | grep -c '^rest_board_target=am3-bb-s19jpro$')" -eq 1 ] || {
        echo IDENTITY_FAIL:rest_identity
        return 1
    }
    echo IDENTITY_PASS
    return 0
}

# Exact AM3-BB measured-population receipt. Configured address assignment,
# aggregate-only totals, repeated unassigned GetAddress frames, or a stale PID
# can never satisfy this contract.
accept_am3_bb_enumeration_verdict() {
    _aepid=${1:-}
    accept_is_uint "$_aepid" || {
        echo AM3_ENUM_FAIL:process
        return 1
    }
    _aedata=$(cat)
    _aelines=$(printf '%s\n' "$_aedata" | grep -F 'AM3_BB_ENUMERATION_RECEIPT ' || true)
    if [ -z "$_aelines" ]; then
        echo AM3_ENUM_PENDING:no_unique_population_receipt
        return 1
    fi
    [ "$(printf '%s\n' "$_aelines" | grep -c .)" -eq 1 ] || {
        echo AM3_ENUM_FAIL:ambiguous_receipts
        return 1
    }
    _aeexpected="AM3_BB_ENUMERATION_RECEIPT schema=v1 run_pid=$_aepid chains=3 chain0=126 chain1=126 chain2=126 total=378 evidence=post_assignment_unique"
    [ "$_aelines" = "$_aeexpected" ] || {
        echo AM3_ENUM_FAIL:receipt_mismatch
        return 1
    }
    echo AM3_ENUM_PASS
    return 0
}

# accept_parse_temp_c — echo the highest temperature (deg C) found in a REST
# /api/status body or CGMiner-style stats. Reads `temp_c`, `"temp"`, or
# `chip_temp_c` numeric fields and returns the maximum (so a hot board is never
# masked by a cooler sibling reading). Echoes nothing if no temperature present.
accept_parse_temp_c() {
    body=$(cat)
    # Extract every numeric value attached to a temperature-ish key, take the max.
    printf '%s' "$body" \
        | grep -oiE '"(temp_c|chip_temp_c|temp|board_temp_c|soc_temp_c)"[[:space:]]*:[[:space:]]*-?[0-9]+(\.[0-9]+)?' 2>/dev/null \
        | grep -oE '\-?[0-9]+(\.[0-9]+)?$' \
        | sort -n \
        | tail -n1 \
        || true
}

# accept_temp_safe <temp_c> <ceiling_c> — echo SAFE and return 0 when the observed
# temperature is a finite number at or below the ceiling; echo HOT and return 1
# when it exceeds the ceiling. A MISSING/non-numeric reading fails CLOSED (echo
# UNKNOWN, return 1) — a soak that cannot read temperature must not be trusted to
# keep hashing (cut-hash-before-noise / never mask a thermal blind spot).
accept_temp_safe() {
    _t=${1:-}
    _ceil=${2:-75}
    printf '%s\n' "$_t" | grep -Eq '^-?[0-9]+([.][0-9]+)?$' || {
        echo UNKNOWN; return 1
    }
    printf '%s\n' "$_ceil" | grep -Eq '^-?[0-9]+([.][0-9]+)?$' || {
        echo UNKNOWN; return 1
    }
    # Preserve fractional precision and reject impossible/sentinel readings.
    # -40..150 C covers supported ambient/board sensors without accepting
    # values such as -273 or 255 as evidence of thermal safety.
    awk -v t="$_t" -v c="$_ceil" 'BEGIN {
        if (t < -40 || t > 150 || c < -40 || c > 150) exit 2
        if (t <= c) exit 0
        exit 1
    }'
    _temp_rc=$?
    case "$_temp_rc" in
        0) echo SAFE; return 0 ;;
        1) echo HOT; return 1 ;;
        *) echo UNKNOWN; return 1 ;;
    esac
}

# accept_is_uint — return 0 if $1 is a non-empty string of only decimal digits.
accept_is_uint() {
    case "${1:-}" in
        '' | *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# accept_verdict <count> <threshold> — echo PASS and return 0 iff count>=threshold
# (both coerced to non-negative ints; junk -> 0 for count, 1 for threshold), else
# echo FAIL and return 1. This is the single source of the accept gate decision.
accept_verdict() {
    _c=${1:-0}
    _t=${2:-1}
    accept_is_uint "$_c" || _c=0
    accept_is_uint "$_t" || _t=1
    if [ "$_c" -ge "$_t" ]; then
        echo PASS
        return 0
    fi
    echo FAIL
    return 1
}

# Evaluate one share-window sample against a captured baseline. A capstone
# passes only after its complete minimum duration and only on NEW shares. Every
# sample must have a readable, safe temperature; cumulative-counter rollback is
# a producer-reset fault, never fresh progress.
accept_share_window_verdict() {
    _swbase=${1:-}
    _swcurrent=${2:-}
    _swneeded=${3:-1}
    _swelapsed=${4:-0}
    _swminimum=${5:-0}
    _swtemp=${6:-}
    _swceiling=${7:-75}
    _swprevious=${8:-$_swbase}
    accept_is_uint "$_swbase" && accept_is_uint "$_swcurrent" &&
        accept_is_uint "$_swneeded" && accept_is_uint "$_swelapsed" &&
        accept_is_uint "$_swminimum" && accept_is_uint "$_swprevious" || {
            echo SHARE_FAIL:counter
            return 1
        }
    if [ "$_swcurrent" -lt "$_swbase" ] || [ "$_swcurrent" -lt "$_swprevious" ]; then
        echo SHARE_FAIL:counter_reset
        return 1
    fi
    _swthermal=$(accept_temp_safe "$_swtemp" "$_swceiling")
    case "$_swthermal" in
        HOT) echo SHARE_FAIL:overtemp; return 1 ;;
        SAFE) : ;;
        *) echo SHARE_FAIL:thermal_unknown; return 1 ;;
    esac
    _swdelta=$((_swcurrent - _swbase))
    if [ "$_swdelta" -lt "$_swneeded" ]; then
        echo SHARE_PENDING:shares
        return 1
    fi
    if [ "$_swelapsed" -lt "$_swminimum" ]; then
        echo SHARE_PENDING:duration
        return 1
    fi
    echo SHARE_PASS
    return 0
}

# accept_soak_verdict — SUSTAINED-mining stability verdict from a series of soak
# snapshots on stdin, one per line: "elapsed_s accepted mhs_av temp_c". Args:
#   <temp_ceiling_c> [min_hashrate_retention_pct=70] [min_samples=3]
#   [min_new_shares=1] [min_duration_seconds=0]
# Echoes SOAK_PASS and returns 0 when the run is stable; else SOAK_FAIL:<reason>
# and returns 1. This catches what the single-point accept gate CANNOT: a miner
# that produces its first shares then death-spirals, thermally throttles, or
# stalls. A soak is STABLE iff:
#   (1) at least <min_samples> snapshots (a soak needs duration);
#   (2) the Accepted DELTA meets <min_new_shares> (never lifetime totals);
#   (3) timestamps cover at least <min_duration_seconds> and never go backward;
#   (4) hashrate did NOT collapse — the minimum "MHS av" across all samples is at
#       least <retention_pct>% of the maximum (a throttle/death-spiral is a FAIL
#       even if shares kept trickling in);
#   (5) EVERY temperature stayed SAFE (<= ceiling) — one hot OR one unreadable
#       (thermal-blind) sample fails the whole soak (fail-closed, never mask a
#       thermal excursion or a blind spot).
# Malformed / short input fails CLOSED. Iterates via a here-doc (not a pipe) so
# the accumulators survive under BusyBox ash whether stdin is piped or redirected.
accept_soak_verdict() {
    _ceil=${1:-75}
    _ret=${2:-70}
    _minn=${3:-3}
    _minshares=${4:-1}
    _minduration=${5:-0}
    _maxsharestall=${6:-300}
    case "$_ret" in '' | *[!0-9]*) _ret=70 ;; esac
    case "$_minn" in '' | *[!0-9]*) _minn=3 ;; esac
    case "$_minshares" in '' | *[!0-9]*) _minshares=1 ;; esac
    case "$_minduration" in '' | *[!0-9]*) _minduration=0 ;; esac
    case "$_maxsharestall" in '' | *[!0-9]*) _maxsharestall=300 ;; esac

    _sk_data=$(cat)
    _sk_n=0
    _sk_first=''
    _sk_last=''
    _sk_first_elapsed=''
    _sk_last_elapsed=''
    _sk_min=''
    _sk_max=''
    _sk_hot=0
    _sk_blind=0
    _sk_last_progress_elapsed=''
    _sk_stalled=0
    while read -r _sk_el _sk_acc _sk_mhs _sk_temp _sk_rest; do
        # Skip blank lines (a trailing newline in the here-doc, etc.).
        [ -n "$_sk_el$_sk_acc$_sk_mhs$_sk_temp" ] || continue
        accept_is_uint "$_sk_el" || { echo "SOAK_FAIL:nonnumeric_elapsed"; return 1; }
        accept_is_uint "$_sk_acc" || { echo "SOAK_FAIL:nonnumeric_accepted"; return 1; }
        _sk_mhi=${_sk_mhs%%.*}
        case "$_sk_mhi" in
            '') _sk_mhi=0 ;;
            *[!0-9]*) echo "SOAK_FAIL:nonnumeric_mhs"; return 1 ;;
        esac
        _sk_n=$(( _sk_n + 1 ))
        if [ -z "$_sk_first" ]; then
            _sk_first=$_sk_acc
            _sk_first_elapsed=$_sk_el
            _sk_last_progress_elapsed=$_sk_el
        fi
        if [ -n "$_sk_last_elapsed" ] && [ "$_sk_el" -lt "$_sk_last_elapsed" ]; then
            echo "SOAK_FAIL:elapsed_not_monotonic"
            return 1
        fi
        if [ -n "$_sk_last" ] && [ "$_sk_acc" -lt "$_sk_last" ]; then
            echo "SOAK_FAIL:counter_reset($_sk_last->$_sk_acc)"
            return 1
        fi
        if [ -n "$_sk_last" ] && [ "$_sk_acc" -gt "$_sk_last" ]; then
            if [ $((_sk_el - _sk_last_progress_elapsed)) -gt "$_maxsharestall" ]; then
                _sk_stalled=1
            fi
            _sk_last_progress_elapsed=$_sk_el
        fi
        _sk_last=$_sk_acc
        _sk_last_elapsed=$_sk_el
        if [ -z "$_sk_min" ] || [ "$_sk_mhi" -lt "$_sk_min" ]; then _sk_min=$_sk_mhi; fi
        if [ -z "$_sk_max" ] || [ "$_sk_mhi" -gt "$_sk_max" ]; then _sk_max=$_sk_mhi; fi
        case "$(accept_temp_safe "$_sk_temp" "$_ceil")" in
            SAFE) : ;;
            HOT) _sk_hot=1 ;;
            *) _sk_blind=1 ;;
        esac
    done <<SOAK_EOF
$_sk_data
SOAK_EOF

    if [ "$_sk_n" -lt "$_minn" ]; then
        echo "SOAK_FAIL:too_few_samples($_sk_n<$_minn)"
        return 1
    fi
    if [ "$_sk_hot" -ne 0 ]; then
        echo "SOAK_FAIL:thermal_excursion"
        return 1
    fi
    if [ "$_sk_blind" -ne 0 ]; then
        echo "SOAK_FAIL:thermal_blind"
        return 1
    fi
    if [ "$_sk_stalled" -ne 0 ] ||
       [ $((_sk_last_elapsed - _sk_last_progress_elapsed)) -gt "$_maxsharestall" ]; then
        echo "SOAK_FAIL:share_progress_stalled"
        return 1
    fi
    if [ "$_sk_last" -lt "$_sk_first" ]; then
        echo "SOAK_FAIL:counter_reset($_sk_first->$_sk_last)"
        return 1
    fi
    _sk_delta=$((_sk_last - _sk_first))
    if [ "$_sk_delta" -lt "$_minshares" ]; then
        echo "SOAK_FAIL:share_delta($_sk_delta<$_minshares)"
        return 1
    fi
    _sk_duration=$((_sk_last_elapsed - _sk_first_elapsed))
    if [ "$_sk_duration" -lt "$_minduration" ]; then
        echo "SOAK_FAIL:duration($_sk_duration<$_minduration)"
        return 1
    fi
    if [ "$_sk_max" -le 0 ]; then
        echo "SOAK_FAIL:hashrate_unavailable"
        return 1
    fi
    # Divide-first to stay clear of 32-bit overflow on TH/s-scale MHS values.
    _sk_floor=$(( (_sk_max / 100) * _ret ))
    if [ "$_sk_min" -lt "$_sk_floor" ]; then
        echo "SOAK_FAIL:hashrate_collapse(min=$_sk_min<floor=$_sk_floor)"
        return 1
    fi
    echo SOAK_PASS
    return 0
}

# accept_boot_verdict — read a captured boot / UART serial-console log on stdin.
# Echo BOOT_PASS (the unit reached mining) or BOOT_FAIL:<furthest_stage> so a failed
# cold boot is diagnosed at its EXACT stall point instead of "it didn't come up".
# This is the missing analysis step for the deferred SD-first cold-boot blockers
# (am3-bb §"SD-first Cold-Boot Blocker" requires a UART capture — this turns that
# capture into an actionable verdict). Firmware-agnostic: recognizes the boot chain
# (U-Boot -> kernel -> userspace init) plus the DCENT_OS daemon / chip-enum / mining
# markers. Milestones are ordered; the furthest one observed wins (a boot log is
# cumulative, so reaching a later stage implies the earlier banners also appeared).
# Fail-closed: an empty/garbage log yields BOOT_FAIL:none.
accept_boot_verdict() {
    _bv=$(cat)
    _stage=none
    printf '%s' "$_bv" | grep -qiE 'U-Boot (SPL |20)|Hit any key to stop|BOOT_from' && _stage=uboot
    printf '%s' "$_bv" | grep -qiE 'Starting kernel|Booting Linux|Linux version [0-9]|Uncompressing Linux' && _stage=kernel
    printf '%s' "$_bv" | grep -qiE 'Freeing unused kernel|Run /sbin/init|Starting S[0-9]|/etc/init.d/rcS|BusyBox v' && _stage=init
    printf '%s' "$_bv" | grep -qiE 'dcentrald|DCENT_OS v|mining daemon|CGMiner API' && _stage=dcentrald
    printf '%s' "$_bv" | grep -qiE 'enumerated [0-9]+ chips|chips_enumerated' && _stage=enum
    printf '%s' "$_bv" | grep -qiE '[Aa]ccepted share|shares?_accepted|ACCEPT GATE PASS|MHS av|first accepted' && _stage=mining
    if [ "$_stage" = "mining" ]; then
        echo BOOT_PASS
        return 0
    fi
    echo "BOOT_FAIL:$_stage"
    return 1
}

# accept_matrix_verdict <skus.conf> <SKU:mode,...> — diagnostic completeness
# roll-up. It deliberately has no release authority. The explicit required scope
# is the completeness contract; stdin cannot define its own universe. Every
# result is schema-checked and bound to one exact manifest SKU, board_target, and
# declared mode. Boot-log diagnosis cannot satisfy acceptance scope.
accept_matrix_verdict() {
    _mxconf=${1:-}
    _mxscope=${2:-}
    [ -r "$_mxconf" ] || {
        echo ACCEPTANCE_SCOPE_NOGO:manifest_unreadable
        return 1
    }
    printf '%s' "$_mxscope" \
        | grep -Eq '^[A-Za-z0-9+_-]+:[a-z-]+(,[A-Za-z0-9+_-]+:[a-z-]+)*$' || {
            echo ACCEPTANCE_SCOPE_NOGO:required_scope
            return 1
        }

    awk -F '|' '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        NF != 11 { bad=1; next }
        $1 !~ /^[A-Za-z0-9+_-]+$/ ||
        $2 !~ /^[A-Za-z0-9._+-]+$/ ||
        $4 !~ /^[A-Za-z0-9._+-]+$/ ||
        $7 !~ /^(zynq|amlogic|am335x)$/ ||
        $8 !~ /^(nand-ab|single-image|external-media)$/ ||
        $9 !~ /^(PRODUCTION|EXPERIMENTAL|NOT-IMPLEMENTED)$/ ||
        $10 !~ /^[A-Za-z0-9._+-]+$/ { bad=1 }
        seen[$1]++ { bad=1 }
        END { exit bad ? 1 : 0 }
    ' "$_mxconf" || {
        echo ACCEPTANCE_SCOPE_NOGO:manifest_invalid
        return 1
    }

    _mxrequired='|'
    for _mxreq in $(printf '%s' "$_mxscope" | tr ',' ' '); do
        case "$_mxrequired" in
            *"|$_mxreq|"*) echo ACCEPTANCE_SCOPE_NOGO:duplicate_scope; return 1 ;;
        esac
        _mxreqsku=${_mxreq%%:*}
        _mxreqmode=${_mxreq#*:}
        _mxreqrow=$(awk -F '|' -v sku="$_mxreqsku" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            $1 == sku { count++; row=$0 }
            END { if (count == 1) print row; else exit 1 }
        ' "$_mxconf") || {
            echo "ACCEPTANCE_SCOPE_NOGO:$_mxreqsku:unknown_sku"
            return 1
        }
        case "$_mxreqmode" in
            first-light|capstone|soak|ota) : ;;
            bootlog) echo "ACCEPTANCE_SCOPE_NOGO:$_mxreqsku:diagnostic_only"; return 1 ;;
            *) echo "ACCEPTANCE_SCOPE_NOGO:$_mxreqsku:unknown_mode"; return 1 ;;
        esac
        _mxreqboot=$(printf '%s\n' "$_mxreqrow" | awk -F '|' '{print $8}')
        if [ "$_mxreqboot" = external-media ] && [ "$_mxreqmode" = ota ]; then
            echo "ACCEPTANCE_SCOPE_NOGO:$_mxreqsku:route_forbidden"
            return 1
        fi
        _mxrequired="$_mxrequired$_mxreq|"
    done

    _mxdata=$(cat)
    _mxfails=""
    _mxtotal=0
    _mxseen='|'
    while IFS= read -r _mxline; do
        case "$_mxline" in *'"result"'*) : ;; *) continue ;; esac
        printf '%s\n' "$_mxline" | grep -Eq '^[[:space:]]*\{[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*("[^"]*"|-?[0-9]+(\.[0-9]+)?|true|false|null)([[:space:]]*,[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*("[^"]*"|-?[0-9]+(\.[0-9]+)?|true|false|null))*[[:space:]]*\}[[:space:]]*$' || {
            echo ACCEPTANCE_SCOPE_NOGO:malformed_result
            return 1
        }
        _mxschema_count=$(printf '%s' "$_mxline" | grep -oE '"schema"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        _mxauthority_count=$(printf '%s' "$_mxline" | grep -oE '"authority"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        _mxpolicy_count=$(printf '%s' "$_mxline" | grep -oE '"policy_id"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        _mxrcount=$(printf '%s' "$_mxline" | grep -oE '"result"[[:space:]]*:' | wc -l | tr -d ' ')
        _mxscount=$(printf '%s' "$_mxline" | grep -oE '"sku"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        _mxbtcount=$(printf '%s' "$_mxline" | grep -oE '"board_target"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        _mxmcount=$(printf '%s' "$_mxline" | grep -oE '"mode"[[:space:]]*:[[:space:]]*"[^"]*"' | wc -l | tr -d ' ')
        if [ "$_mxschema_count" -ne 1 ] || [ "$_mxauthority_count" -ne 1 ] || [ "$_mxpolicy_count" -ne 1 ] ||
            [ "$_mxrcount" -ne 1 ] || [ "$_mxscount" -ne 1 ] ||
            [ "$_mxbtcount" -ne 1 ] || [ "$_mxmcount" -ne 1 ]; then
            echo ACCEPTANCE_SCOPE_NOGO:unbound_result
            return 1
        fi
        _mxschema=$(printf '%s' "$_mxline" | accept_parse_json_string_field schema)
        _mxauthority=$(printf '%s' "$_mxline" | accept_parse_json_string_field authority)
        _mxpolicy=$(printf '%s' "$_mxline" | accept_parse_json_string_field policy_id)
        if [ "$_mxschema" != dcent-accept-v2 ] || [ "$_mxauthority" != diagnostic-observer ] ||
            [ "$_mxpolicy" != dcent-accept-policy-v2 ]; then
            echo ACCEPTANCE_SCOPE_NOGO:unbound_result
            return 1
        fi
        _mxr=$(printf '%s' "$_mxline" \
            | grep -oiE '"result"[[:space:]]*:[[:space:]]*"(PASS|FAIL)"' \
            | grep -oiE 'PASS|FAIL' | head -n1 | tr 'a-z' 'A-Z')
        [ -n "$_mxr" ] || {
            echo ACCEPTANCE_SCOPE_NOGO:unbound_result
            return 1
        }
        _mxs=$(printf '%s' "$_mxline" | accept_parse_json_string_field sku)
        _mxbt=$(printf '%s' "$_mxline" | accept_parse_json_string_field board_target)
        _mxm=$(printf '%s' "$_mxline" | accept_parse_json_string_field mode)
        printf '%s' "$_mxs" | grep -Eq '^[A-Za-z0-9+_-]+$' || {
            echo ACCEPTANCE_SCOPE_NOGO:malformed_sku
            return 1
        }
        printf '%s' "$_mxbt" | grep -Eq '^[A-Za-z0-9._+-]+$' || {
            echo ACCEPTANCE_SCOPE_NOGO:malformed_board_target
            return 1
        }
        printf '%s' "$_mxm" | grep -Eq '^[a-z-]+$' || {
            echo ACCEPTANCE_SCOPE_NOGO:malformed_mode
            return 1
        }
        _mxrow=$(awk -F '|' -v sku="$_mxs" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            $1 == sku { count++; row=$0 }
            END { if (count == 1) print row; else exit 1 }
        ' "$_mxconf") || {
            echo "ACCEPTANCE_SCOPE_NOGO:$_mxs:unknown_sku"
            return 1
        }
        _mxoldifs=$IFS; IFS='|'
        # shellcheck disable=SC2086
        set -- $_mxrow
        IFS=$_mxoldifs
        _mxexpectedbt=$2
        _mxboot=$8
        _mxrelease=$9
        if [ "$_mxbt" != "$_mxexpectedbt" ]; then
            echo "ACCEPTANCE_SCOPE_NOGO:$_mxs:board_target_mismatch"
            return 1
        fi
        case "$_mxm" in
            first-light|capstone|soak|ota) : ;;
            bootlog) echo "ACCEPTANCE_SCOPE_NOGO:$_mxs:diagnostic_only"; return 1 ;;
            *) echo "ACCEPTANCE_SCOPE_NOGO:$_mxs:unknown_mode"; return 1 ;;
        esac
        if [ "$_mxboot" = external-media ] && [ "$_mxm" = ota ]; then
            echo "ACCEPTANCE_SCOPE_NOGO:$_mxs:route_forbidden"
            return 1
        fi
        _mxpair="$_mxs:$_mxm"
        case "$_mxrequired" in
            *"|$_mxpair|"*) : ;;
            *) echo "ACCEPTANCE_SCOPE_NOGO:$_mxpair:outside_scope"; return 1 ;;
        esac
        case "$_mxseen" in
            *"|$_mxpair|"*) echo "ACCEPTANCE_SCOPE_NOGO:$_mxpair:duplicate"; return 1 ;;
        esac
        _mxseen="$_mxseen$_mxpair|"
        _mxtotal=$((_mxtotal + 1))
        printf '  %-10s %-12s %s\n' "$_mxs" "$_mxm" "$_mxr" >&2
        if [ "$_mxr" = PASS ] && [ "$_mxrelease" = NOT-IMPLEMENTED ]; then
            _mxfails="${_mxfails}${_mxs}:not_implemented "
        elif [ "$_mxr" != PASS ]; then
            _mxfails="${_mxfails}${_mxs}:${_mxm} "
        fi
    done <<MATRIX_EOF
$_mxdata
MATRIX_EOF

    if [ "$_mxtotal" -eq 0 ]; then
        echo ACCEPTANCE_SCOPE_NOGO:no_results
        return 1
    fi
    for _mxreq in $(printf '%s' "$_mxscope" | tr ',' ' '); do
        case "$_mxseen" in
            *"|$_mxreq|"*) : ;;
            *) _mxfails="${_mxfails}${_mxreq}:missing " ;;
        esac
    done
    if [ -n "$_mxfails" ]; then
        echo "ACCEPTANCE_SCOPE_NOGO:$(printf '%s' "$_mxfails" | sed 's/ *$//' | tr ' ' ',')"
        return 1
    fi
    echo ACCEPTANCE_SCOPE_PASS
    return 0
}

# accept_ota_verdict <sku> <board-target> <artifact-sha256> <version> — read a
# witnessed OTA-capstone transcript on stdin. Echo
# OTA_PASS (the signed OTA update completed end-to-end and the unit is mining the
# new version) or OTA_FAIL:<furthest_stage> so a stalled capstone is diagnosed at
# its exact point. This is the reproducible verdict for the witnessed-OTA blocker:
# run the OTA sequence capturing its output, pipe it here for one PASS/FAIL.
#
# Ordered milestones — deliberately encoding the  OTA truth contracts so a
# weaker signal can NEVER be scored as a stronger one:
#   uploaded -> signature_verified -> scheduled -> rebooted -> version_confirmed
#   -> mining_resumed
# "uploaded" alone is NOT proof; "scheduled" != flashed; only an OBSERVED reboot +
# the EXPECTED version + resumed accepted shares is a real capstone pass. The
# furthest ordered marker present wins (a capstone log is cumulative). Fail-closed:
# a markerless/truncated transcript cannot pass. Exact BEGIN/END envelope,
# artifact hash, and observed-version bindings prevent unrelated/stale lines
# from being combined into a false capstone.
accept_ota_verdict() {
    _osku=${1:-}
    _obt=${2:-}
    _osha=${3:-}
    _over=${4:-}
    printf '%s' "$_osku" | grep -Eq '^[A-Za-z0-9+_-]+$' || { echo OTA_FAIL:invalid_expectation; return 2; }
    printf '%s' "$_obt" | grep -Eq '^[A-Za-z0-9._+-]+$' || { echo OTA_FAIL:invalid_expectation; return 2; }
    printf '%s' "$_osha" | grep -Eq '^[0-9a-f]{64}$' || { echo OTA_FAIL:invalid_expectation; return 2; }
    printf '%s' "$_over" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' || { echo OTA_FAIL:invalid_expectation; return 2; }

    awk -v sku="$_osku" -v bt="$_obt" -v sha="$_osha" -v ver="$_over" '
        BEGIN {
            begin = "DCENT_OTA_CAPSTONE_BEGIN sku=" sku " board_target=" bt " artifact_sha256=" sha " expected_version=" ver
            finish = "DCENT_OTA_CAPSTONE_END sku=" sku " board_target=" bt " artifact_sha256=" sha " observed_version=" ver
            artifact = "artifact sha256 verified: " sha
            version = "version matches expected: " ver
            stage = 0
        }
        function category(line) {
            if (line == "upload accepted") return 2
            if (line ~ /^artifact sha256 verified: /) return 3
            if (line == "OTA signature verified") return 4
            if (line == "sysupgrade scheduled") return 5
            if (line == "reboot observed") return 6
            if (line ~ /^version matches expected: /) return 7
            if (line ~ /^ACCEPT GATE PASS: [1-9][0-9]* accepted shares$/) return 8
            return 0
        }
        {
            line = $0
            sub(/\r$/, "", line)
            if (line ~ /^DCENT_OTA_CAPSTONE_BEGIN /) {
                begin_count++
                if (line != begin) unbound = 1
                else if (stage != 0) order = 1
                else stage = 1
                next
            }
            if (stage == 0) next
            if (line ~ /^DCENT_OTA_CAPSTONE_END /) {
                end_count++
                if (line != finish) end_mismatch = 1
                else if (stage != 8) order = 1
                else { passed = 1; ended = 1 }
                next
            }
            cat = category(line)
            if (cat == 0) next
            if (ended) {
                order = 1
                next
            }
            if (cat == 3 && line != artifact) {
                artifact_mismatch = 1
                next
            }
            if (cat == 7 && line != version) {
                version_mismatch = 1
                next
            }
            if (cat == stage + 1) stage = cat
            else if (cat > stage) order = 1
        }
        END {
            if (passed && begin_count == 1 && end_count == 1 && !unbound && !order && !artifact_mismatch && !version_mismatch && !end_mismatch) {
                print "OTA_PASS"
                exit 0
            }
            if (unbound) reason = "unbound"
            else if (artifact_mismatch) reason = "artifact_mismatch"
            else if (version_mismatch) reason = "version_mismatch"
            else if (end_mismatch) reason = "end_mismatch"
            else if (begin_count > 1 || end_count > 1) reason = "envelope"
            else if (order) reason = "order"
            else if (stage == 8) reason = "end_missing"
            else if (stage == 7) reason = "version_confirmed"
            else if (stage == 6) reason = "rebooted"
            else if (stage == 5) reason = "scheduled"
            else if (stage == 4) reason = "signature_verified"
            else if (stage == 3) reason = "artifact_verified"
            else if (stage == 2) reason = "uploaded"
            else if (stage == 1) reason = "bound"
            else reason = "none"
            print "OTA_FAIL:" reason
            exit 1
        }
    '
}

# accept_enum_verdict <observed> <expected> — enumeration sanity. Expected 0 means
# UNCONFIRMED (capture-first SKU): any non-zero observed count is a CAPTURE pass.
# Otherwise require observed within +/-10% of expected (binning tolerance) and echo
# PASS / CAPTURE / FAIL accordingly.
accept_enum_verdict() {
    _obs=${1:-0}
    _exp=${2:-0}
    accept_is_uint "$_obs" || _obs=0
    accept_is_uint "$_exp" || _exp=0
    if [ "$_exp" -eq 0 ]; then
        if [ "$_obs" -gt 0 ]; then
            echo CAPTURE
            return 0
        fi
        echo FAIL
        return 1
    fi
    # tolerance band = expected +/- 10% (integer math, floor/ceil-safe)
    _lo=$(( _exp - (_exp / 10) - 1 ))
    _hi=$(( _exp + (_exp / 10) + 1 ))
    if [ "$_obs" -ge "$_lo" ] && [ "$_obs" -le "$_hi" ]; then
        echo PASS
        return 0
    fi
    echo FAIL
    return 1
}
