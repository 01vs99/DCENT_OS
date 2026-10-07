#!/bin/sh
#
# dcent-accept.sh — DCENT_OS one-command hardware acceptance harness.
#
# Release Commander goal: reduce the human job to  ->  plug in miner, press Enter,
# watch PASS or FAIL. This harness drives the full reversible acceptance flow for
# the Antminer rows declared in skus.conf and exits 0 (PASS) / 1 (FAIL) /
# 2 (setup error) so it drops straight into CI, a dashboard, or an operator run.
#
#   ./dcent-accept.sh all S19jPro 203.0.113.25 --ssh-known-hosts=FILE --expected-mac=MAC
#   ./dcent-accept.sh shares S21 203.0.113.135     # just the accept gate
#   ./dcent-accept.sh list                           # SKU table + release states
#
# SAFETY (load-bearing — do NOT weaken):
#   * This harness NEVER writes NAND / persistent flash and NEVER commands fan
#     PWM above the fixed home-quiet cap.
#     `all` is reversible /tmp-first only (a reboot fully reverts). Persistent
#     install is a separate, explicitly operator-gated step (see `install-hint`),
#     never run automatically.
#   * A captured, route-specific, readback-verified backup must pass before any
#     persistent install. Temporary first-light does not install to persistent
#     storage. Partition inventory alone is never accepted as a backup.
#   * fan cap: the deployed config carries thermal.fan_max_pwm<=30 (home/quiet).
#
# The PASS/FAIL decision comes from lib/accept_parse.sh (unit-tested, hardware-free,
# CI-gated) reading the firmware-agnostic CGMiner Accepted counter on port 4028 —
# so this gate reads the same on DCENT_OS, BraiinsOS, LuxOS, or stock cgminer.
#
# POSIX sh. Needs: ssh, scp, nc (or curl fallback). Windows operators: run under
# WSL/Git-Bash, or use the node helpers in tools/ for the ssh/scp legs.

set -u

DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
SCRIPTS_DIR=$(CDPATH= cd "$DIR/.." && pwd)
WORKSPACE_ROOT=$(CDPATH= cd "$DIR/../../../.." && pwd)
CONF="$DIR/skus.conf"
ENABLEMENT_MATRIX="$DIR/../../docs/architecture/hardware_enablement_matrix.json"
ARTIFACT_PRODUCERS="$DIR/../../docs/architecture/artifact_producers.json"

# shellcheck source=lib/accept_parse.sh
. "$DIR/lib/accept_parse.sh"

# ---- fixed acceptance policy ----------------------------------------------
# Ambient environment cannot weaken verdict thresholds. Pool selection is an
# operator input, but every scoring constant is literal and result JSON records
# the stable policy identifier.
ACCEPT_POLICY_ID=dcent-accept-policy-v2
POOL=${DCENT_ACCEPT_POOL:-stratum+tcp://public-pool.io:21496}
API_PORT=4028
REST_PORT=8080
FIRSTLIGHT_N=1
FIRSTLIGHT_T=180
CAPSTONE_N=5
CAPSTONE_T=600
POLL=10
TEMP_CEILING=75
SOAK_T=600
SOAK_RETENTION=70
SOAK_MIN_SAMPLES=3
SOAK_MAX_SHARE_STALL=300

say()  { printf '%s\n' "$*"; }
info() { printf '[dcent-accept] %s\n' "$*"; }
err()  { printf '[dcent-accept] ERROR: %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
dcent-accept.sh — DCENT_OS hardware acceptance harness

USAGE:
  dcent-accept.sh <phase> <SKU> <IP> --ssh-known-hosts=FILE --expected-mac=MAC
                  [--capstone] [--json] [--case-dir=PATH]
  dcent-accept.sh list
  dcent-accept.sh install-hint <SKU> <IP>
  dcent-accept.sh matrix <results.jsonl> --require=SKU:mode,...

PHASES:
  detect       confirm SoC + board_target + chip identity over SSH/REST
  backup       audit the verified full-NAND / boot-region backup prerequisite for install
  firstlight   reversible /tmp deploy (dev_deploy.sh) — reboot reverts
  enum         chip-enumeration sanity vs the SKU nameplate
  shares       ACCEPT GATE: poll CGMiner Accepted counter -> PASS/FAIL   (the gate)
  soak         STABILITY GATE: poll over N min -> PASS/FAIL on shares-advancing +
               no hashrate-collapse + no thermal-excursion (catches die-spirals)
  bench        capture MHS av / elapsed / enumerated (benchmark line)
  bootlog      diagnose a captured UART/serial boot log -> stall stage (offline; arg3=logfile or -)
  ota          diagnose a witnessed OTA-capstone transcript -> stall stage (offline; arg3=transcript or -)
  all          firstlight -> detect -> enum -> shares -> bench (tmpfs-only; reversible)

FLAGS:
  --capstone   use the capstone soak thresholds (>=5 shares over 10 min) not first-light
  --json       emit a machine-readable result line for CI/dashboards
  --minutes=N  soak duration in minutes (soak phase; default 10)
  --soak-seconds=N   soak duration in seconds (overrides --minutes)
  --retention=P      min hashrate retention % for the soak gate (default 70)
  --case-dir=PATH    witnessed AM3-BB /tmp case directory (external-media observers; required)
  --ssh-known-hosts=FILE  operator-curated pinned host-key file (all live phases; required)
  --expected-mac=MAC exact eth0 address independently recorded for this unit (required)
  --artifact-sha256=HEX  externally verified OTA artifact SHA-256 (ota; required)
  --expected-version=V   exact post-reboot version token (ota; required)
  --require=SCOPE        complete matrix scope, e.g. S9:capstone,S19jPro:soak

OTA TRANSCRIPT (exact ordered lines inside a hash/SKU/route-bound BEGIN/END):
  DCENT_OTA_CAPSTONE_BEGIN sku=<SKU> board_target=<target> artifact_sha256=<HEX> expected_version=<V>
  upload accepted
  artifact sha256 verified: <HEX>
  OTA signature verified
  sysupgrade scheduled
  reboot observed
  version matches expected: <V>
  ACCEPT GATE PASS: <N> accepted shares
  DCENT_OTA_CAPSTONE_END sku=<SKU> board_target=<target> artifact_sha256=<HEX> observed_version=<V>

SKU: one of  S9 S15 T15 S17 S17Pro S17Plus T17 T17Plus S17e T17e S19 S19Pro
     S19jPro S19jProBB S19kPro T19 S19XP S21 T21 S21Pro S21XP  (see `list`)

EXIT: 0 = PASS   1 = FAIL   2 = usage/setup error
EOF
}

# ---- SKU table lookup ------------------------------------------------------
# Sets SKU BOARD_TARGET ARCH CHIP CHIP_ID ENUM_EXPECT SOC BOOT_CHAIN RELEASE_STATE PACKAGE NOTE
sku_lookup() {
    want=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    line=$(grep -v '^[[:space:]]*#' "$CONF" | grep -v '^[[:space:]]*$' | while IFS='|' read -r s rest; do
        low=$(printf '%s' "$s" | tr 'A-Z' 'a-z')
        if [ "$low" = "$want" ]; then printf '%s|%s\n' "$s" "$rest"; break; fi
    done)
    if [ -z "$line" ]; then return 1; fi
    OLDIFS=$IFS; IFS='|'
    # shellcheck disable=SC2086
    set -- $line
    IFS=$OLDIFS
    SKU=$1; BOARD_TARGET=$2; ARCH=$3; CHIP=$4; CHIP_ID=$5; ENUM_EXPECT=$6
    SOC=$7; BOOT_CHAIN=$8; RELEASE_STATE=$9; PACKAGE=${10}; NOTE=${11}
    return 0
}

cmd_list() {
    printf '%-8s %-18s %-7s %-8s %-6s %-9s %-15s %s\n' \
        SKU BOARD_TARGET ARCH CHIP ENUM SOC RELEASE_STATE PACKAGE
    grep -v '^[[:space:]]*#' "$CONF" | grep -v '^[[:space:]]*$' | while IFS='|' read -r s bt ar ch cid en so bc rs pk nt; do
        printf '%-8s %-18s %-7s %-8s %-6s %-9s %-15s %s\n' "$s" "$bt" "$ar" "$ch" "$en" "$so" "$rs" "$pk"
    done
}

# ---- transport helpers -----------------------------------------------------
ssh_run() {
    ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS" "root@$IP" "$1" 2>/dev/null
}

validate_live_transport_args() {
    [ -n "${SSH_KNOWN_HOSTS:-}" ] && [ -f "$SSH_KNOWN_HOSTS" ] && [ -r "$SSH_KNOWN_HOSTS" ] || {
        err "live phase requires a readable operator-pinned --ssh-known-hosts=FILE"
        return 2
    }
    [ -s "$SSH_KNOWN_HOSTS" ] || {
        err "pinned known_hosts file is empty; host authenticity is unproven"
        return 2
    }
    case "$SSH_KNOWN_HOSTS" in
        *[!A-Za-z0-9_./:-]*)
            err "pinned known_hosts path contains unsupported characters"
            return 2
            ;;
    esac
    EXPECTED_MAC=$(printf '%s' "${EXPECTED_MAC:-}" | tr 'A-F' 'a-f')
    printf '%s' "$EXPECTED_MAC" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' || {
        err "live phase requires --expected-mac=xx:xx:xx:xx:xx:xx from independent unit records"
        return 2
    }
}

verify_live_unit_mac() {
    observed_mac=$(ssh_run 'tr "A-F" "a-f" </sys/class/net/eth0/address 2>/dev/null | tr -d "\r\n"')
    if [ "$observed_mac" != "$EXPECTED_MAC" ]; then
        err "eth0 identity mismatch: observed '${observed_mac:-<missing>}' != independently expected '$EXPECTED_MAC'"
        return 1
    fi
    say "  eth0 MAC identity = $observed_mac (exact match)"
}

validate_case_dir() {
    printf '%s' "${CASE_DIR:-}" | grep -Eq '^/tmp/dcentos-am3-bb\.[A-Za-z0-9]+$' || {
        err "external-media observer requires --case-dir=/tmp/dcentos-am3-bb.<mktemp-suffix>"
        return 2
    }
}

# CASE_DIR is regex-confined above, so it can safely prefix a single remote
# POSIX-sh command without creating a second predictable global evidence path.
ssh_case_run() { ssh_run "case_dir=$CASE_DIR; $1"; }

json_result_prefix() {
    printf '%s' "{\"schema\":\"dcent-accept-v2\",\"authority\":\"diagnostic-observer\",\"policy_id\":\"$ACCEPT_POLICY_ID\",\"result\":\"$1\",\"sku\":\"$SKU\",\"board_target\":\"$BOARD_TARGET\""
}

live_identity_json() {
    printf '%s' "\"identity_verified\":${ACCEPT_IDENTITY_VERIFIED:-0},\"identity_mac\":\"${observed_mac:-}\",\"identity_chip\":\"${ACCEPT_IDENTITY_CHIP:-}\",\"identity_soc\":\"${ACCEPT_IDENTITY_SOC:-}\",\"producer_pid\":\"${ACCEPT_PRODUCER_PID:-}\",\"producer_start_ticks\":\"${ACCEPT_PRODUCER_START_TICKS:-}\",\"producer_exe\":\"${ACCEPT_PRODUCER_EXE:-}\""
}

api_summary() {
    ssh_run 'command -v nc >/dev/null 2>&1 || exit 127
        printf '\''{"command":"summary"}'\'' | nc -w 3 127.0.0.1 4028'
}

api_version() {
    ssh_run 'command -v nc >/dev/null 2>&1 || exit 127
        printf '\''{"command":"version"}'\'' | nc -w 3 127.0.0.1 4028' | tr -d '\000\r\n'
}

rest_status() {
    ssh_run 'if command -v curl >/dev/null 2>&1; then curl -fsS -m 4 http://127.0.0.1:8080/api/status; elif command -v wget >/dev/null 2>&1; then wget -q -T 4 -O - http://127.0.0.1:8080/api/status; fi'
}
rest_system_info() {
    ssh_run 'if command -v curl >/dev/null 2>&1; then curl -fsS -m 4 http://127.0.0.1:8080/api/system/info; elif command -v wget >/dev/null 2>&1; then wget -q -T 4 -O - http://127.0.0.1:8080/api/system/info; fi'
}

# Read Linux socket ownership directly from procfs. A scored CGMiner counter
# and REST identity are admissible only when one current dcentrald process owns
# BOTH listening sockets. This closes the co-resident-stock-miner split-brain
# case without trusting process names or network reachability alone.
producer_process_evidence() {
    ssh_run '
listen_inodes() {
    port=$1
    awk -v p="$port" '\''$4 == "0A" && toupper($2) ~ (":" p "$") { print $10 }'\'' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null | sort -u
}
owns_port() {
    owner=$1
    port=$2
    for inode in $(listen_inodes "$port"); do
        for fd in /proc/$owner/fd/*; do
            [ "$(readlink "$fd" 2>/dev/null)" = "socket:[$inode]" ] && return 0
        done
    done
    return 1
}
matches=0
for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    owns_port "$pid" 0FBC || continue
    owns_port "$pid" 1F90 || continue
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    start=$(sed "s/^[^)]*) //" "/proc/$pid/stat" 2>/dev/null | awk '\''{ print $20 }'\'') || continue
    case "$start" in ""|*[!0-9]*) continue ;; esac
    matches=$((matches + 1))
    printf "producer_pid=%s\nproducer_start_ticks=%s\nproducer_exe=%s\nlistener_pair=4028,8080\n" \
        "$pid" "$start" "$exe"
done
[ "$matches" -eq 1 ]'
}

verify_dcentrald_producer() {
    route_pid=${1:-}
    process_evidence_before=$(producer_process_evidence)
    version_evidence=$(api_version)
    process_evidence_after=$(producer_process_evidence)
    if [ "$process_evidence_before" != "$process_evidence_after" ]; then
        err "dcentrald producer changed while the API identity response was sampled"
        return 1
    fi
    process_evidence=$process_evidence_after
    producer_verdict=$(printf '%s\n%s\n' "$process_evidence" "$version_evidence" \
        | accept_dcentrald_producer_verdict "$route_pid"); producer_rc=$?
    say "  $producer_verdict"
    if [ "$producer_rc" -ne 0 ]; then
        err "REST/CGMiner producer identity failed closed: $producer_verdict"
        return 1
    fi
    producer_pid=$(printf '%s\n' "$process_evidence" | sed -n 's/^producer_pid=//p')
    producer_start=$(printf '%s\n' "$process_evidence" | sed -n 's/^producer_start_ticks=//p')
    producer_exe=$(printf '%s\n' "$process_evidence" | sed -n 's/^producer_exe=//p')
    if [ -n "${ACCEPT_PRODUCER_PID:-}" ] &&
        { [ "$producer_pid" != "$ACCEPT_PRODUCER_PID" ] ||
          [ "$producer_start" != "$ACCEPT_PRODUCER_START_TICKS" ] ||
          [ "$producer_exe" != "$ACCEPT_PRODUCER_EXE" ]; }; then
        err "dcentrald producer changed during the observation window"
        return 1
    fi
    ACCEPT_PRODUCER_PID=$producer_pid
    ACCEPT_PRODUCER_START_TICKS=$producer_start
    ACCEPT_PRODUCER_EXE=$producer_exe
    say "  REST:$REST_PORT and CGMiner:$API_PORT producer = PID $producer_pid start=$producer_start exe=$producer_exe"
}

stop_exact_runtime_launch() {
    launch_pid=${1:-}
    launch_start=${2:-}
    launch_exe=${3:-}
    case "$launch_pid:$launch_start" in *[!0-9:]*|:*|*:) return 1 ;; esac
    [ "$launch_exe" = /tmp/dcentrald_runtime ] || return 1
    ssh_run '
pid='"$launch_pid"'
expected_start='"$launch_start"'
expected_exe=/tmp/dcentrald_runtime
identity_matches() {
    [ -r "/proc/$pid/stat" ] || return 1
    current_start=$(sed "s/^[^)]*) //" "/proc/$pid/stat" 2>/dev/null | awk "{print \$20}")
    current_exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    [ "$current_start" = "$expected_start" ] && [ "$current_exe" = "$expected_exe" ]
}
identity_matches || exit 0
kill -TERM "$pid" 2>/dev/null || true
for i in $(seq 1 30); do identity_matches || exit 0; sleep 1; done
identity_matches && kill -9 "$pid" 2>/dev/null || true
for i in $(seq 1 10); do identity_matches || exit 0; sleep 1; done
exit 1'
}

# Known board_target aliases: strings the daemon treats as the SAME SKU/chip.
# The S19j Pro overlay stamps the short `am2-s19j` (serial.rs:943 exact-matches
# it, so it cannot change), while skus.conf/ use the canonical
# `am2-s19jpro-zynq`; both resolve to ZynqVariant::S19 / BM1362. Without this, a
# correctly-flashed S19j Pro (the beta SKU) false-fails detect as "WRONG SKU".
board_targets_equivalent() {
    # $1 = reported (on-miner), $2 = expected (skus.conf); order-insensitive.
    case "$1,$2" in
        am2-s19j,am2-s19jpro-zynq|am2-s19jpro-zynq,am2-s19j) return 0 ;;
        am2-s19j,am2-s19jpro|am2-s19jpro,am2-s19j) return 0 ;;
        am2-s19jpro,am2-s19jpro-zynq|am2-s19jpro-zynq,am2-s19jpro) return 0 ;;
    esac
    return 1
}

canonical_board_desc_target() {
    case "$1" in
        am2-s19jpro-zynq|am2-s19jpro) printf '%s\n' am2-s19j ;;
        am2-s19) printf '%s\n' am2-s19pro ;;
        *) printf '%s\n' "$1" ;;
    esac
}

artifact_filename_for() {
    _producer_target=$1
    if [ ! -r "$ARTIFACT_PRODUCERS" ]; then
        err "artifact producer manifest is missing or unreadable: $ARTIFACT_PRODUCERS"
        return 2
    fi
    if ! grep -Eq '^[[:space:]]*"schema":[[:space:]]*2,[[:space:]]*$' "$ARTIFACT_PRODUCERS"; then
        err "artifact producer manifest schema is unsupported"
        return 2
    fi
    _producer_needle="\"board_target\":\"$_producer_target\""
    _producer_count=$(grep -Fc "$_producer_needle" "$ARTIFACT_PRODUCERS")
    if [ "$_producer_count" -ne 1 ]; then
        err "artifact producer for $_producer_target is not uniquely declared"
        return 2
    fi
    _producer_row=$(grep -F "$_producer_needle" "$ARTIFACT_PRODUCERS")
    _artifact_filename=$(printf '%s\n' "$_producer_row" |
        sed -n 's/^.*"artifact_filename":"\([^"]*\)".*$/\1/p')
    case "$_artifact_filename" in
        ""|*/*|*\\*|*..*)
            err "artifact producer for $_producer_target has an unsafe or malformed filename"
            return 2
            ;;
    esac
    printf '%s\n' "$_artifact_filename"
}

artifact_install_contract_for() {
    _producer_target=$1
    _producer_needle="\"board_target\":\"$_producer_target\""
    _producer_count=$(grep -Fc "$_producer_needle" "$ARTIFACT_PRODUCERS")
    if [ "$_producer_count" -ne 1 ]; then
        err "artifact producer for $_producer_target is not uniquely declared"
        return 2
    fi
    _producer_row=$(grep -F "$_producer_needle" "$ARTIFACT_PRODUCERS")
    _install_contract=$(printf '%s\n' "$_producer_row" |
        sed -n 's/^.*"install_contract":"\([^"]*\)"}.*$/\1/p')
    case "$_install_contract" in
        managed_s9_install|guarded_am2_self_update|guarded_amlogic_rootfs_window|external_media|package_only_denied)
            printf '%s\n' "$_install_contract"
            ;;
        *)
            err "artifact producer for $_producer_target has an unknown install contract"
            return 2
            ;;
    esac
}

install_hint_policy_allows() {
    _policy_target=$(canonical_board_desc_target "$BOARD_TARGET")
    if [ ! -r "$ENABLEMENT_MATRIX" ]; then
        err "install policy matrix is missing or unreadable: $ENABLEMENT_MATRIX"
        return 2
    fi
    _policy_needle="\"board_target\":\"$_policy_target\""
    _policy_count=$(grep -Fc "$_policy_needle" "$ENABLEMENT_MATRIX")
    if [ "$_policy_count" -ne 1 ]; then
        err "install policy for $_policy_target is not uniquely declared"
        return 2
    fi
    _policy_row=$(grep -F "$_policy_needle" "$ENABLEMENT_MATRIX")
    case "$_policy_row" in
        *'"install_authorization":"denied"'*)
            info "PERSISTENT INSTALL REFUSED for $SKU ($BOARD_TARGET)"
            _denied_contract=$(artifact_install_contract_for "$_policy_target" 2>/dev/null || true)
            if [ "$_denied_contract" = "package_only_denied" ]; then
                _denied_artifact=$(artifact_filename_for "$_policy_target") || return $?
                say "  Offline package-only artifact: output/$_denied_artifact"
                say "  Contract: package_only_denied; no dcent install, update, upload, reboot, or device write is authorized."
                say "  Validate the package on the host only; cold boot, rollback, and accepted-share proof remain required."
            else
                case "$_policy_row" in
                    *'"artifact_kind":"none"'*)
                        say "  The typed hardware matrix denies install and declares no artifact for $_policy_target."
                        say "  This route is management/diagnostic only; do not infer an install image from its SoC family."
                        ;;
                    *)
                        say "  The typed hardware matrix denies install for $_policy_target."
                        say "  This route is management/diagnostic only; do not infer install authority from an artifact kind or SoC family."
                        ;;
                esac
            fi
            return 1
            ;;
        *'"artifact_kind":"none"'*)
            info "PERSISTENT INSTALL REFUSED for $SKU ($BOARD_TARGET)"
            say "  The typed hardware matrix declares no artifact for $_policy_target."
            say "  This route is management/diagnostic only; do not infer an install image from its SoC family."
            return 1
            ;;
    esac
    return 0
}

# ---- phases ----------------------------------------------------------------
cmd_detect() {
    info "detect $SKU ($CHIP / $BOARD_TARGET) on $IP"
    verify_live_unit_mac || return $?
    if [ "$BOOT_CHAIN" = "external-media" ]; then
        # LuxOS has no DCENT_OS marker. Normalize only read-only evidence from
        # the live unit and bind DT identity, process PID/cmdline, the runtime
        # admission receipt, and REST reachability into one strict verdict.
        evidence=$(ssh_case_run '
if [ -e /etc/dcentos/board_target ]; then
    printf "marker_state=present\n"
    printf "marker=%s\n" "$(tr -d "\r\n" </etc/dcentos/board_target 2>/dev/null)"
else
    printf "marker_state=absent\n"
fi
if [ -r /proc/device-tree/compatible ]; then
    tr "\000" "\n" </proc/device-tree/compatible | sed "s/^/compatible=/"
fi
if [ -r /proc/device-tree/model ]; then
    printf "model=%s\n" "$(tr -d "\000\r\n" </proc/device-tree/model)"
fi
pid=$(tr -d "\r\n" <"$case_dir/dcentrald.pid" 2>/dev/null)
case "$pid" in
    ""|*[!0-9]*) ;;
    *)
        if [ -r "/proc/$pid/cmdline" ]; then
            printf "current_pid=%s\n" "$pid"
            printf "cmdline=%s\n" "$(tr "\000" " " <"/proc/$pid/cmdline")"
            receipt="AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v3 run_pid=$pid board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence=exact_device_tree"
            grep -F "$receipt" "$case_dir/dcentrald.log" 2>/dev/null \
                | sed -n "s/^.*\($receipt\).*$/\1/p"
        fi
        ;;
esac')
        sys=$(rest_system_info)
        rest=0; rest_bt=
        if [ -n "$sys" ]; then
            rest=1
            rest_bt=$(printf '%s' "$sys" | accept_parse_json_string_field board_target)
        fi
        v=$(printf '%s\nrest_reachable=%s\nrest_board_target=%s\n' "$evidence" "$rest" "$rest_bt" | accept_am3_bb_identity_verdict "$CASE_DIR"); rc=$?
        say "  $v"
        if [ "$rc" -eq 0 ] && verify_dcentrald_producer "$(printf '%s\n' "$evidence" | sed -n 's/^current_pid=//p')"; then
            ACCEPT_IDENTITY_VERIFIED=1
            ACCEPT_IDENTITY_BOARD_TARGET=$BOARD_TARGET
            ACCEPT_IDENTITY_CHIP=$CHIP
            ACCEPT_IDENTITY_SOC=$SOC
            info "identity PASS: exact AM3-BB route, current admitted process, and REST endpoint"
        else
            rc=1
            err "identity failed closed: $v"
        fi
        return $rc
    fi

    bt=$(ssh_run 'cat /etc/dcentos/board_target 2>/dev/null')
    say "  board_target(reported) = ${bt:-<unreachable>}   board_target(expected) = $BOARD_TARGET"
    if [ -z "$bt" ]; then
        err "board_target unreadable; identity is unproven"
        return 1
    fi
    st=$(rest_status)
    if [ -n "$st" ]; then
        say "  REST /api/status reachable ($REST_PORT)"
    else
        say "  REST /api/status not reachable (miner may be pre-deploy — run firstlight)"
    fi
    if [ "$bt" != "$BOARD_TARGET" ]; then
        if board_targets_equivalent "$bt" "$BOARD_TARGET"; then
            say "  note: reported '$bt' is a known alias of expected '$BOARD_TARGET' (same SKU/chip) — OK"
        else
            err "board_target mismatch: reported '$bt' != expected '$BOARD_TARGET' — WRONG SKU or wrong image"
            return 1
        fi
    fi
    sys=$(rest_system_info)
    if [ -z "$sys" ]; then
        err "REST /api/system/info unreachable; ASIC/SoC identity is unproven"
        return 1
    fi
    chip_reported=$(printf '%s' "$sys" | accept_parse_json_string_field chip_type)
    soc_reported=$(printf '%s' "$sys" | accept_parse_json_string_field soc)
    say "  chip_type(reported) = ${chip_reported:-<missing>}   chip_type(expected) = $CHIP"
    say "  soc(reported) = ${soc_reported:-<missing>}   soc-family(expected) = $SOC"
    if [ "$chip_reported" != "$CHIP" ]; then
        err "chip_type mismatch: reported '${chip_reported:-<missing>}' != expected '$CHIP'"
        return 1
    fi
    case "$SOC/$soc_reported" in
        zynq/Zynq*|amlogic/Amlogic*|am335x/AM335x*) : ;;
        *) err "SoC mismatch: reported '${soc_reported:-<missing>}' is not family '$SOC'"; return 1 ;;
    esac
    api_bt=$(printf '%s' "$sys" | accept_parse_json_string_field board_target)
    if [ "$api_bt" != "$BOARD_TARGET" ] && ! board_targets_equivalent "$api_bt" "$BOARD_TARGET"; then
        err "REST board_target mismatch: reported '${api_bt:-<missing>}' != expected '$BOARD_TARGET'"
        return 1
    fi
    verify_dcentrald_producer || return $?
    ACCEPT_IDENTITY_VERIFIED=1
    ACCEPT_IDENTITY_BOARD_TARGET=$BOARD_TARGET
    ACCEPT_IDENTITY_CHIP=$CHIP
    ACCEPT_IDENTITY_SOC=$SOC
    say "  REST /api/system/info identity reachable through pinned SSH loopback ($REST_PORT)"
    return 0
}

cmd_backup() {
    info "backup prerequisite audit (read-only) $SKU on $IP"
    say "  toolbox 'dcent backup nand' only lists /proc/mtd; it is not a backup producer"
    say "  this harness will not delegate to an unpinned transport or infer backup success from command exit status"
    mtds=$(ssh_run 'cat /proc/mtd 2>/dev/null | sed -n "s/^\(mtd[0-9]*\):.*/\1/p"')
    if [ -z "$mtds" ]; then
        err "could not read /proc/mtd over SSH — cannot verify a backup — STOP"; return 1
    fi
    say "  observed partitions: $(printf '%s' "$mtds" | tr '\n' ' ')"
    say "  follow $PACKAGE Step 1 to capture exact-unit images, off-unit hashes, and readback evidence"
    err "no route-bound verified-backup manifest was supplied; partition inventory cannot satisfy this gate — STOP"
    return 1
}

cmd_firstlight() {
    info "first-light (reversible /tmp deploy) $SKU on $IP — reboot reverts"
    dep="$SCRIPTS_DIR/dev_deploy.sh"
    if [ ! -f "$dep" ]; then err "dev_deploy.sh missing at $dep"; return 2; fi

    # Bind the exact requested SKU/board/chip/SoC and the current API-owning
    # process before dev_deploy is allowed to stop or launch anything. A raw
    # vendor baseline without this read-only proof must use its route-specific
    # witnessed procedure; broad family heuristics cannot authorize mutation.
    cmd_detect || {
        err "first-light refused before process mutation: exact current-unit identity is unproven"
        return 1
    }

    # Capture the selected remote config into a private local file, validate
    # those exact bytes, then pass them explicitly. dev_deploy uploads them to a
    # content-addressed /tmp path and verifies the hash immediately before
    # launch, so a concurrent edit cannot replace the quiet configuration.
    firstlight_tmp=$(mktemp -d "${TMPDIR:-/tmp}/dcent-firstlight.XXXXXX") || {
        err "could not allocate first-light evidence directory"; return 2;
    }
    bound_config=$firstlight_tmp/dcentrald.toml
    deploy_receipt=$firstlight_tmp/deploy.json
    cap_path=$(ssh_run 'for f in /tmp/dcentrald.runtime.toml /data/dcentrald.toml /etc/dcentrald.toml; do [ -f "$f" ] && { printf "%s\n" "$f"; exit; }; done')
    case "$cap_path" in
        /tmp/dcentrald.runtime.toml|/data/dcentrald.toml|/etc/dcentrald.toml) ;;
        *) rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"; err "no exact runtime config was selected"; return 1 ;;
    esac
    if ! ssh_run "cat '$cap_path'" >"$bound_config"; then
        rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
        err "could not capture the selected runtime config"; return 1
    fi
    cap_evidence=$(awk -v path="$cap_path" '
        BEGIN { in_thermal=0; count=0; value="" }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            in_thermal = ($0 ~ /^[[:space:]]*\[thermal\][[:space:]]*$/)
            next
        }
        in_thermal && /^[[:space:]]*fan_max_pwm[[:space:]]*=/ {
            line=$0
            sub(/^[^=]*=[[:space:]]*/, "", line)
            sub(/[[:space:]#].*$/, "", line)
            value=line
            count++
        }
        END { printf "config=%s\nfan_max_pwm=%s\nfan_max_pwm_count=%d\n", path, value, count }
    ' "$bound_config")
    cap_value=$(printf '%s\n' "$cap_evidence" | sed -n 's/^fan_max_pwm=//p')
    cap_count=$(printf '%s\n' "$cap_evidence" | sed -n 's/^fan_max_pwm_count=//p')
    if [ -z "$cap_path" ] || [ "$cap_count" != 1 ] || ! accept_is_uint "$cap_value" || [ "$cap_value" -gt 30 ]; then
        rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
        err "first-light requires exactly one numeric [thermal].fan_max_pwm<=30 in the config selected by runtime deploy"
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        cap_sha=$(sha256sum "$bound_config" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        cap_sha=$(shasum -a 256 "$bound_config" | awk '{print $1}')
    else
        rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
        err "first-light requires a local SHA-256 utility to bind the selected config"
        return 2
    fi
    chmod 400 "$bound_config"
    say "  bound runtime config $cap_path: SHA256=$cap_sha thermal.fan_max_pwm=$cap_value (<=30)"
    say "  running: bash $dep $IP --runtime-only --verify --config <bound-bytes>"
    previous_pid=$ACCEPT_PRODUCER_PID
    previous_start=$ACCEPT_PRODUCER_START_TICKS
    previous_exe=$ACCEPT_PRODUCER_EXE
    if DCENT_SSH_KNOWN_HOSTS="$SSH_KNOWN_HOSTS" DCENT_EXPECTED_MAC="$EXPECTED_MAC" \
        bash "$dep" "$IP" --runtime-only --verify --config "$bound_config" --output="$deploy_receipt"; then
        launch_pid=$(sed -n 's/^[[:space:]]*"pid":[[:space:]]*\([0-9][0-9]*\),*$/\1/p' "$deploy_receipt")
        launch_start=$(sed -n 's/^[[:space:]]*"start_ticks":[[:space:]]*"\([0-9][0-9]*\)",*$/\1/p' "$deploy_receipt")
        launch_exe=$(sed -n 's/^[[:space:]]*"exe":[[:space:]]*"\([^"]*\)",*$/\1/p' "$deploy_receipt")
        ACCEPT_PRODUCER_PID=
        ACCEPT_PRODUCER_START_TICKS=
        ACCEPT_PRODUCER_EXE=
        if ! cmd_detect; then
            stop_exact_runtime_launch "$launch_pid" "$launch_start" "$launch_exe" || true
            rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
            err "post-launch exact SKU/producer binding failed; runtime launch was stopped"
            return 1
        fi
        if [ "$ACCEPT_PRODUCER_PID:$ACCEPT_PRODUCER_START_TICKS:$ACCEPT_PRODUCER_EXE" != "$launch_pid:$launch_start:$launch_exe" ] ||
           [ "$ACCEPT_PRODUCER_PID:$ACCEPT_PRODUCER_START_TICKS:$ACCEPT_PRODUCER_EXE" = "$previous_pid:$previous_start:$previous_exe" ]; then
            stop_exact_runtime_launch "$launch_pid" "$launch_start" "$launch_exe" || true
            rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
            err "first-light producer transition was not exactly bound to the launched runtime"
            return 1
        fi
        rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
        info "first-light deploy PASS (daemon staged to /tmp and rebound to exact producer)"; return 0
    fi
    rm -f "$bound_config" "$deploy_receipt"; rmdir "$firstlight_tmp"
    err "first-light deploy failed"; return 1
}

cmd_enum() {
    cmd_detect || return $?
    info "enumeration sanity $SKU (expect $ENUM_EXPECT, 0=capture-first)"
    if [ "$BOOT_CHAIN" = "external-media" ]; then
        evidence=$(ssh_case_run '
pid=$(tr -d "\r\n" <"$case_dir/dcentrald.pid" 2>/dev/null)
case "$pid" in
    ""|*[!0-9]*) ;;
    *)
        if [ -r "/proc/$pid/cmdline" ]; then
            printf "current_pid=%s\n" "$pid"
            grep -F "AM3_BB_ENUMERATION_RECEIPT " "$case_dir/dcentrald.log" 2>/dev/null \
                | sed -n "s/^.*\(AM3_BB_ENUMERATION_RECEIPT .*\)$/\1/p"
            grep -F "configured BM1362 address assignment" "$case_dir/dcentrald.log" 2>/dev/null | tail -n 1
        fi
        ;;
esac')
        pid=$(printf '%s\n' "$evidence" | sed -n 's/^current_pid=//p')
        v=$(printf '%s\n' "$evidence" | accept_am3_bb_enumeration_verdict "$pid"); rc=$?
        say "  $v"
        if [ "$rc" -eq 0 ]; then
            info "enumeration PASS: exact current-run post-assignment unique-population receipt"
        else
            err "enumeration is not proven: $v (configured address totals are not observations)"
        fi
        return $rc
    fi

    body=$(rest_status)
    n=$(printf '%s' "$body" | accept_parse_enumerated)
    if [ -z "$n" ]; then
        n=$(ssh_run 'grep -aoE "enumerated [0-9]+ chips" /tmp/dcentrald.log 2>/dev/null | tail -1' | accept_parse_enumerated)
    fi
    n=${n:-0}
    v=$(accept_enum_verdict "$n" "$ENUM_EXPECT"); rc=$?
    say "  enumerated=$n expected=$ENUM_EXPECT -> $v"
    if [ "$v" = "CAPTURE" ]; then
        info "enum CAPTURE: $n chips recorded for an UNCONFIRMED SKU (feed into $PACKAGE)"; return 0
    fi
    return $rc
}

cmd_shares() {
    cmd_detect || return $?
    N=$FIRSTLIGHT_N; T=$FIRSTLIGHT_T; MIN_DURATION=0; mode=first-light
    if [ "${CAPSTONE:-0}" = "1" ]; then N=$CAPSTONE_N; T=$CAPSTONE_T; MIN_DURATION=$CAPSTONE_T; mode=capstone; fi
    info "accept gate ($mode): need >=$N NEW accepted shares over >=${MIN_DURATION}s (timeout ${T}s) on $IP:$API_PORT"
    say "  pool=$POOL  fan cap<=30 (config-enforced)  overtemp ceiling=${TEMP_CEILING}C"
    body=$(api_summary)
    baseline=$(printf '%s' "$body" | accept_parse_accepted)
    accept_is_uint "$baseline" || {
        err "ACCEPT GATE FAIL: could not capture the initial dcentrald Accepted counter"
        return 1
    }
    start_uptime=$(ssh_run 'cut -d. -f1 /proc/uptime 2>/dev/null')
    accept_is_uint "$start_uptime" || {
        err "ACCEPT GATE FAIL: could not capture the unit monotonic-uptime baseline"
        return 1
    }
    say "  baseline Accepted=$baseline; unit uptime baseline=${start_uptime}s"
    acc=$baseline; previous_acc=$baseline; delta=0; elapsed=0; temp=
    while [ "$elapsed" -le "$T" ]; do
        body=$(api_summary)
        got=$(printf '%s' "$body" | accept_parse_accepted)
        accept_is_uint "$got" || {
            err "ACCEPT GATE FAIL: dcentrald Accepted counter became unreadable"
            return 1
        }
        acc=$got
        now_uptime=$(ssh_run 'cut -d. -f1 /proc/uptime 2>/dev/null')
        accept_is_uint "$now_uptime" && [ "$now_uptime" -ge "$start_uptime" ] || {
            err "ACCEPT GATE FAIL: unit monotonic time became unreadable or moved backwards"
            return 1
        }
        elapsed=$((now_uptime - start_uptime))
        if [ "$elapsed" -gt "$T" ] && [ "$MIN_DURATION" -eq 0 ]; then break; fi
        temp=$(rest_status | accept_parse_temp_c)
        verify_dcentrald_producer "${ACCEPT_PRODUCER_PID:-}" || return 1
        v=$(accept_share_window_verdict "$baseline" "$acc" "$N" "$elapsed" "$MIN_DURATION" "$temp" "$TEMP_CEILING" "$previous_acc"); vrc=$?
        previous_acc=$acc
        if [ "$acc" -ge "$baseline" ]; then delta=$((acc - baseline)); else delta=0; fi
        case "$v" in
        SHARE_PASS)
            cmd_detect || {
                err "ACCEPT GATE FAIL: endpoint identity changed or became unprovable before verdict"
                return 1
            }
            mhs=$(printf '%s' "$body" | accept_parse_mhs_av)
            info "ACCEPT GATE PASS: $delta new accepted shares over ${elapsed}s (baseline=$baseline current=$acc, MHS av=${mhs:-?}, temp=${temp}C)"
            [ "${JSON:-0}" = "1" ] && say "$(json_result_prefix PASS),$(live_identity_json),\"ip\":\"$IP\",\"accepted_baseline\":$baseline,\"accepted_current\":$acc,\"accepted_delta\":$delta,\"needed_delta\":$N,\"minimum_duration_seconds\":$MIN_DURATION,\"window_seconds\":$T,\"seconds\":$elapsed,\"temp_c\":\"$temp\",\"ceiling_c\":$TEMP_CEILING,\"mode\":\"$mode\"}"
            return 0
            ;;
        SHARE_FAIL:*)
            reason=${v#SHARE_FAIL:}
            err "ACCEPT GATE FAIL ($reason): baseline=$baseline current=$acc delta=$delta elapsed=${elapsed}s temp=${temp:-missing}C"
            [ "${JSON:-0}" = "1" ] && say "$(json_result_prefix FAIL),$(live_identity_json),\"reason\":\"$reason\",\"ip\":\"$IP\",\"accepted_baseline\":$baseline,\"accepted_current\":$acc,\"accepted_delta\":$delta,\"needed_delta\":$N,\"minimum_duration_seconds\":$MIN_DURATION,\"window_seconds\":$T,\"seconds\":$elapsed,\"temp_c\":\"${temp:-}\",\"ceiling_c\":$TEMP_CEILING,\"mode\":\"$mode\"}"
            return 1
            ;;
        esac
        [ "$vrc" -ne 0 ] || { err "ACCEPT GATE FAIL: invalid share-window verdict '$v'"; return 1; }
        [ "$elapsed" -lt "$T" ] || break
        remaining=$((T - elapsed))
        nap=$POLL; [ "$remaining" -lt "$nap" ] && nap=$remaining
        [ "$nap" -gt 0 ] && sleep "$nap"
    done
    err "ACCEPT GATE FAIL: only $delta new accepted shares in ${elapsed}s (needed $N over >=${MIN_DURATION}s)"
    [ "${JSON:-0}" = "1" ] && say "$(json_result_prefix FAIL),$(live_identity_json),\"reason\":\"window_expired\",\"ip\":\"$IP\",\"accepted_baseline\":$baseline,\"accepted_current\":$acc,\"accepted_delta\":$delta,\"needed_delta\":$N,\"minimum_duration_seconds\":$MIN_DURATION,\"window_seconds\":$T,\"seconds\":$elapsed,\"ceiling_c\":$TEMP_CEILING,\"mode\":\"$mode\"}"
    return 1
}

cmd_bench() {
    cmd_detect || return $?
    info "benchmark snapshot $SKU on $IP"
    body=$(api_summary)
    mhs=$(printf '%s' "$body" | accept_parse_mhs_av)
    el=$(printf '%s' "$body" | accept_parse_elapsed)
    acc=$(printf '%s' "$body" | accept_parse_accepted)
    st=$(rest_status)
    tmp=$(printf '%s' "$st" | accept_parse_temp_c)
    enr=$(printf '%s' "$st" | accept_parse_enumerated)
    say "  MHS av=${mhs:-?}  elapsed=${el:-?}s  accepted=${acc:-?}  enumerated=${enr:-?}  temp=${tmp:-?}C"
    [ "${JSON:-0}" = "1" ] && say "{\"schema\":\"dcent-accept-v2\",\"authority\":\"diagnostic-observer\",\"policy_id\":\"$ACCEPT_POLICY_ID\",\"kind\":\"benchmark\",\"sku\":\"$SKU\",\"board_target\":\"$BOARD_TARGET\",$(live_identity_json),\"mhs_av\":\"${mhs:-}\",\"elapsed\":\"${el:-}\",\"accepted\":\"${acc:-}\",\"enumerated\":\"${enr:-}\",\"temp_c\":\"${tmp:-}\"}"
    return 0
}

cmd_install_hint() {
    install_hint_policy_allows
    policy_rc=$?
    [ "$policy_rc" -eq 0 ] || return "$policy_rc"

    procedure="$WORKSPACE_ROOT/docs/dev/2026-07-02-antminer-production-readiness/hw-procedures/$PACKAGE.md"
    if [ ! -r "$procedure" ]; then
        err "acceptance procedure is missing or unreadable: $procedure"
        return 2
    fi
    policy_target=$(canonical_board_desc_target "$BOARD_TARGET")
    artifact_filename=$(artifact_filename_for "$policy_target") || return $?
    install_contract=$(artifact_install_contract_for "$policy_target") || return $?

    if [ "$install_contract" = "external_media" ]; then
        info "PERSISTENT INSTALL REFUSED for $SKU ($BOARD_TARGET)"
        say "  This Experimental external-media route is runtime/SD lab-only and has no admitted persistent-write transaction."
        say "  Do not write NAND, run sysupgrade, call fw_setenv, or reuse the Zynq/Amlogic install paths."
        say "  Physical payload: output/$artifact_filename"
        say "  Manually launch the hash-bound temporary binary/config only under the witnessed procedure:"
        say "    $procedure"
        say "  detect, enum, shares, soak, and bench are read-only observers after that route-specific launch."
        return 0
    fi

    info "PERSISTENT INSTALL is operator-gated — this only PRINTS the exact steps (no writes)"
    say "  1. Confirm the route-specific backup/restore proof and 'shares' both PASSED on this exact unit."
    say "  2. Use a fresh independently verified signed artifact; an artifact lane alone is not install authority."
    case "$install_contract" in
        managed_s9_install)
            say "  3. Managed S9 package route (the Toolbox plan and preflight remain authoritative):"
            say "       dcent install $IP -f output/$artifact_filename --yes"
            say "     Dry-run any later revert-to-stock route and retain the exact-unit backup; no generic rollback is implied here."
            ;;
        guarded_am2_self_update)
            say "  3. Guarded AM2 DCENT_OS self-update (inactive slot, exact restore evidence, physical recovery staged):"
            say "       dcent install $IP -f output/$artifact_filename --artifact-dir <restore_verified_dir> --accept-am2-persistent-lab --i-have-recovery --yes"
            say "     Vendor-source first install remains evidence-gap; this command is only executable from an admitted DCENT_OS self-update route."
            say "     The writer flips the selected slot but does not auto-reboot. Retain the exact restore artifact and follow the witnessed recovery procedure."
            ;;
        guarded_amlogic_rootfs_window)
            say "  3. Guarded Amlogic rootfs-window write: efuse preflight (BP-AMLOGIC Step 0) MUST read UNLOCKED."
            say "     Stock source:"
            say "       dcent install $IP -f output/$artifact_filename --artifact-dir <restore_verified_dir> --yes"
            say "     VNish source (additional source-specific acknowledgement):"
            say "       dcent install $IP -f output/$artifact_filename --artifact-dir <restore_verified_dir> --accept-vnish-aml-rootfs-window --yes"
            say "     There is no A/B rollback slot and no automatic reboot; recovery requires the exact restore artifact plus the witnessed physical plan."
            ;;
        *)
            err "unsupported install contract for $policy_target: $install_contract"
            return 2
            ;;
    esac
    say "  4. After the route-specific boot/recovery step, re-run:  ./dcent-accept.sh shares $SKU $IP --capstone"
    say "  Full procedure + checklist: $procedure"
    return 0
}

# Diagnostic completeness roll-up. It aggregates schema-v2 observer results but
# never grants release authority: local JSON is neither immutable nor signed.
cmd_matrix() {
    _rf=${RESULTS:-}
    if [ -z "${MATRIX_REQUIRE:-}" ]; then
        err "matrix: --require=SKU:mode,... is mandatory and defines the complete expected scope"
        return 2
    fi
    if [ "$_rf" = "-" ] || [ -z "$_rf" ]; then
        v=$(accept_matrix_verdict "$CONF" "$MATRIX_REQUIRE"); rc=$?
    elif [ -f "$_rf" ]; then
        v=$(accept_matrix_verdict "$CONF" "$MATRIX_REQUIRE" < "$_rf"); rc=$?
    else
        err "matrix: pass a --json results file (or - / omit for stdin): dcent-accept.sh matrix <results.jsonl>"
        return 2
    fi
    info "diagnostic acceptance-scope roll-up (never release authority)"
    say "  $v"
    if [ "$rc" -eq 0 ]; then
        info "ACCEPTANCE SCOPE PASS: every declared diagnostic result PASSED"
    else
        err "ACCEPTANCE SCOPE NO-GO: ${v#ACCEPTANCE_SCOPE_NOGO:}"
    fi
    return $rc
}

# Diagnose a captured UART / serial-console boot log (arg 3 = log file path, or '-'
# for stdin). Reports the exact stall stage so a deferred SD-first cold boot can be
# triaged without a live re-attempt (bootloader hang vs kernel panic vs userspace
# vs enum vs no-shares). No hardware contact — pure offline log analysis.
cmd_bootlog() {
    _lf=${IP:-}
    if [ -z "$_lf" ] || { [ "$_lf" != "-" ] && [ ! -f "$_lf" ]; }; then
        err "bootlog: pass a captured boot-log file (or - for stdin): dcent-accept.sh bootlog $SKU <logfile>"
        return 2
    fi
    info "boot-log stall-stage diagnosis $SKU"
    if [ "$_lf" = "-" ]; then
        v=$(accept_boot_verdict); rc=$?
    else
        v=$(accept_boot_verdict < "$_lf"); rc=$?
    fi
    say "  $v"
    if [ "$rc" -eq 0 ]; then
        info "BOOT PASS: the capture reached mining"
    else
        err "BOOT $v — the boot stalled at stage '${v#BOOT_FAIL:}'; inspect the log around that milestone"
    fi
    if [ "${JSON:-0}" = "1" ]; then
        _r=FAIL; [ "$rc" -eq 0 ] && _r=PASS
        say "$(json_result_prefix "$_r"),\"verdict\":\"$v\",\"mode\":\"bootlog\"}"
    fi
    return $rc
}

# Diagnose a witnessed OTA-capstone transcript (arg 3 = transcript file, or '-' for
# stdin). Reports the exact OTA stall stage so a failed capstone is triaged from its
# captured output instead of re-running the whole update. Honors the OTA truth
# contracts (uploaded != scheduled != flashed != mining). No hardware contact.
cmd_ota() {
    _of=${IP:-}
    if [ -z "${OTA_ARTIFACT_SHA256:-}" ] || [ -z "${OTA_EXPECTED_VERSION:-}" ]; then
        err "ota: --artifact-sha256=HEX and --expected-version=V are mandatory"
        return 2
    fi
    if [ -z "$_of" ] || { [ "$_of" != "-" ] && [ ! -f "$_of" ]; }; then
        err "ota: pass a captured OTA-capstone transcript (or - for stdin): dcent-accept.sh ota $SKU <transcript>"
        return 2
    fi
    info "OTA-capstone stage diagnosis $SKU"
    if [ "$_of" = "-" ]; then
        v=$(accept_ota_verdict "$SKU" "$BOARD_TARGET" "$OTA_ARTIFACT_SHA256" "$OTA_EXPECTED_VERSION"); rc=$?
    else
        v=$(accept_ota_verdict "$SKU" "$BOARD_TARGET" "$OTA_ARTIFACT_SHA256" "$OTA_EXPECTED_VERSION" < "$_of"); rc=$?
    fi
    say "  $v"
    if [ "$rc" -eq 0 ]; then
        info "OTA PASS: capstone completed end-to-end (signed -> rebooted -> correct version -> mining)"
    else
        err "OTA $v — the capstone stalled at stage '${v#OTA_FAIL:}'; inspect the transcript around that milestone"
    fi
    if [ "${JSON:-0}" = "1" ]; then
        _r=FAIL; [ "$rc" -eq 0 ] && _r=PASS
        say "$(json_result_prefix "$_r"),\"verdict\":\"$v\",\"artifact_sha256\":\"$OTA_ARTIFACT_SHA256\",\"expected_version\":\"$OTA_EXPECTED_VERSION\",\"mode\":\"ota\"}"
    fi
    return $rc
}

# Sustained-stability soak gate. Polls the CGMiner summary + REST temp every $POLL
# for $SOAK_T seconds, then runs the pure accept_soak_verdict for a PASS/FAIL that
# catches a first-shares-then-die-spiral, thermal throttle, or stall — none of which
# the single-point 'shares' gate can see. Read-only + reversible: never raises fans,
# never writes. Reduces the operator job to "run soak, read PASS/FAIL".
cmd_soak() {
    cmd_detect || return $?
    T=$SOAK_T
    nl='
'
    info "stability soak $SKU on $IP:$API_PORT for ${T}s (interval ${POLL}s, retention ${SOAK_RETENTION}%, ceiling ${TEMP_CEILING}C)"
    start_uptime=""
    samples=""; elapsed=0; nsam=0
    while [ "$elapsed" -le "$T" ]; do
        body=$(api_summary)
        acc=$(printf '%s' "$body" | accept_parse_accepted)
        accept_is_uint "$acc" || { err "SOAK FAIL: dcentrald Accepted counter unreadable"; return 1; }
        mhs=$(printf '%s' "$body" | accept_parse_mhs_av)
        temp=$(rest_status | accept_parse_temp_c)
        verify_dcentrald_producer "${ACCEPT_PRODUCER_PID:-}" || return 1
        # Timestamp the completed sample, not the start of its remote calls.
        # The first completed sample is the exact origin, so the parser's
        # last-first span cannot lose a second to pre-sample scheduling.
        now_uptime=$(ssh_run 'cut -d. -f1 /proc/uptime 2>/dev/null')
        accept_is_uint "$now_uptime" || {
            err "SOAK FAIL: unit monotonic uptime unreadable"
            return 1
        }
        if [ -z "$start_uptime" ]; then
            start_uptime=$now_uptime
            elapsed=0
        else
            [ "$now_uptime" -ge "$start_uptime" ] || {
                err "SOAK FAIL: unit monotonic time moved backwards"
                return 1
            }
            elapsed=$((now_uptime - start_uptime))
        fi
        samples="${samples}${elapsed} ${acc} ${mhs:-0} ${temp:-}${nl}"
        nsam=$((nsam + 1))
        [ "$elapsed" -lt "$T" ] || break
        remaining=$((T - elapsed))
        nap=$POLL; [ "$remaining" -lt "$nap" ] && nap=$remaining
        [ "$nap" -gt 0 ] && sleep "$nap"
    done
    v=$(printf '%s' "$samples" | accept_soak_verdict "$TEMP_CEILING" "$SOAK_RETENTION" "$SOAK_MIN_SAMPLES" "$CAPSTONE_N" "$T" "$SOAK_MAX_SHARE_STALL"); rc=$?
    if ! cmd_detect; then
        v=SOAK_FAIL:identity_changed
        rc=1
    fi
    say "  samples=$nsam over ${elapsed}s -> $v"
    if [ "$rc" -eq 0 ]; then
        info "SOAK PASS: >=$CAPSTONE_N new shares and sustained mining stayed stable over ${elapsed}s across $nsam samples"
    else
        err "SOAK FAIL: $v"
    fi
    if [ "${JSON:-0}" = "1" ]; then
        _r=FAIL; [ "$rc" -eq 0 ] && _r=PASS
        say "$(json_result_prefix "$_r"),$(live_identity_json),\"verdict\":\"$v\",\"ip\":\"$IP\",\"samples\":$nsam,\"seconds\":$elapsed,\"minimum_duration_seconds\":$T,\"minimum_new_shares\":$CAPSTONE_N,\"maximum_share_stall_seconds\":$SOAK_MAX_SHARE_STALL,\"poll_seconds\":$POLL,\"retention_percent\":$SOAK_RETENTION,\"minimum_samples\":$SOAK_MIN_SAMPLES,\"ceiling_c\":$TEMP_CEILING,\"mode\":\"soak\"}"
    fi
    return $rc
}

cmd_all() {
    rc=0
    verify_live_unit_mac || return $?
    cmd_firstlight  || return 1
    cmd_detect      || return $?
    cmd_enum        || rc=1
    cmd_shares      || rc=1
    cmd_bench       || true
    if [ "$rc" -eq 0 ]; then
        info "DIAGNOSTIC FLOW PASS: $SKU on $IP (reversible /tmp observation; no release or install authority)"
    else
        err "acceptance flow had FAIL(s) for $SKU on $IP — see above (nothing persistent was written)"
    fi
    return $rc
}

# ---- arg parse -------------------------------------------------------------
PHASE=${1:-}
[ -z "$PHASE" ] && { usage; exit 2; }
case "$PHASE" in
    -h|--help|help) usage; exit 0 ;;
    list) cmd_list; exit 0 ;;
    matrix)
        RESULTS=${2:-}; MATRIX_REQUIRE=
        for a in "$@"; do
            case "$a" in --require=*) MATRIX_REQUIRE=${a#*=} ;; esac
        done
        case "$RESULTS" in --require=*) RESULTS= ;; esac
        cmd_matrix; exit $?
        ;;
esac

SKUARG=${2:-}
IP=${3:-}
CAPSTONE=0; JSON=0; OTA_ARTIFACT_SHA256=; OTA_EXPECTED_VERSION=; CASE_DIR=; SSH_KNOWN_HOSTS=; EXPECTED_MAC=; ACCEPT_IDENTITY_VERIFIED=0; ARG_ERROR=
for a in "$@"; do
    case "$a" in
        --capstone) CAPSTONE=1 ;;
        --json) JSON=1 ;;
        --soak-seconds=*)
            _v=${a#*=}
            case "$_v" in ''|*[!0-9]*) ARG_ERROR="--soak-seconds must be an integer >=600" ;;
                *) [ "$_v" -ge 600 ] && SOAK_T=$_v || ARG_ERROR="--soak-seconds cannot weaken the 600s minimum" ;;
            esac
            ;;
        --minutes=*)
            _v=${a#*=}
            case "$_v" in ''|*[!0-9]*) ARG_ERROR="--minutes must be an integer >=10" ;;
                *) [ "$_v" -ge 10 ] && SOAK_T=$((_v * 60)) || ARG_ERROR="--minutes cannot weaken the 10-minute minimum" ;;
            esac
            ;;
        --retention=*)
            _v=${a#*=}
            case "$_v" in ''|*[!0-9]*) ARG_ERROR="--retention must be an integer from 70 through 100" ;;
                *) if [ "$_v" -ge 70 ] && [ "$_v" -le 100 ]; then SOAK_RETENTION=$_v; else ARG_ERROR="--retention must be from 70 through 100"; fi ;;
            esac
            ;;
        --case-dir=*) CASE_DIR=${a#*=} ;;
        --ssh-known-hosts=*) SSH_KNOWN_HOSTS=${a#*=} ;;
        --expected-mac=*) EXPECTED_MAC=${a#*=} ;;
        --artifact-sha256=*) OTA_ARTIFACT_SHA256=${a#*=} ;;
        --expected-version=*) OTA_EXPECTED_VERSION=${a#*=} ;;
    esac
done
[ -z "$ARG_ERROR" ] || { err "$ARG_ERROR"; exit 2; }
[ -z "$SKUARG" ] && { err "missing SKU (see: dcent-accept.sh list)"; exit 2; }
if ! sku_lookup "$SKUARG"; then err "unknown SKU '$SKUARG' — see: dcent-accept.sh list"; exit 2; fi

# A capture-first inventory row is not a runnable acceptance route. Keep the
# offline boot-log parser available so new evidence can retire the row, but
# refuse every live, deployment, install-guidance, and OTA path before argument
# validation or transport. Otherwise a NOT-IMPLEMENTED label is merely cosmetic
# and an operator can still reach SSH/dev_deploy with the scaffold.
case "$RELEASE_STATE/$PHASE" in
    NOT-IMPLEMENTED/bootlog) : ;;
    NOT-IMPLEMENTED/*)
        err "$PHASE is refused for NOT-IMPLEMENTED route $SKU ($BOARD_TARGET)"
        err "capture-first rows admit only offline bootlog diagnosis; follow $PACKAGE to collect the missing hardware evidence"
        exit 1
        ;;
esac

# External-media routes deliberately have no generic deploy or backup action.
# Refuse before the IP check and before any helper can reach SSH, SCP, dcent, or
# dev_deploy.sh; S19 model-name heuristics would otherwise select the AM2 path.
case "$BOOT_CHAIN/$PHASE" in
    external-media/all|external-media/backup|external-media/firstlight|external-media/ota)
        err "$PHASE is refused for external-media route $SKU ($BOARD_TARGET); use $PACKAGE and a witnessed manual temporary launch"
        exit 1
        ;;
esac

case "$PHASE" in
    install-hint) IP=${IP:-<miner_ip>}; cmd_install_hint; exit $? ;;
    bootlog) cmd_bootlog; exit $? ;;
    ota) cmd_ota; exit $? ;;
esac
[ -z "$IP" ] && { err "missing miner IP"; exit 2; }
validate_live_transport_args || exit $?

if [ "$BOOT_CHAIN" = external-media ]; then
    validate_case_dir || exit $?
fi

case "$PHASE" in
    detect|shares|soak|all) : ;;
    *) verify_live_unit_mac || exit $? ;;
esac

info "$SKU  [$RELEASE_STATE]  $NOTE"
case "$PHASE" in
    detect)     cmd_detect ;;
    backup)     cmd_backup ;;
    firstlight) cmd_firstlight ;;
    enum)       cmd_enum ;;
    shares)     cmd_shares ;;
    soak)       cmd_soak ;;
    bench)      cmd_bench ;;
    all)        cmd_all ;;
    *) err "unknown phase '$PHASE'"; usage; exit 2 ;;
esac
exit $?
