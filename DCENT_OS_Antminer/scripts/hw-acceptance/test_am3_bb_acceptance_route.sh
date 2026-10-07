#!/bin/sh
# Hardware-free regression for the distinct AM335x S19j Pro route. Generic
# deployment/update paths must refuse before transport, while observer phases
# require exact current-run evidence and never promote configured totals to
# measured population.
set -u

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
harness="$here/dcent-accept.sh"
conf="$here/skus.conf"
fails=0

bad() { printf 'FAIL: %s\n' "$*" >&2; fails=$((fails + 1)); }

expected='S19jProBB|am3-bb-s19jpro|armv7|BM1362|0x1362|378|am335x|external-media|EXPERIMENTAL|BP-AM3-BB-PSU65-WATCHDOG|3x126 BM1362; historical .79 runtime shares, current runtime-bound-PSU65/watchdog bench pending; NAND blocked'
count=$(awk -v row="$expected" '{ sub(/\r$/, "") } /^[[:space:]]*#/ || /^[[:space:]]*$/ { next } $0 == row { n++ } END { print n+0 }' "$conf")
[ "$count" -eq 1 ] || bad "exact non-comment S19jProBB manifest row count is $count, expected 1"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '# %s\n' "$expected" > "$tmp/comment-decoy.conf"
count=$(awk -v row="$expected" '{ sub(/\r$/, "") } /^[[:space:]]*#/ || /^[[:space:]]*$/ { next } $0 == row { n++ } END { print n+0 }' "$tmp/comment-decoy.conf")
[ "$count" -eq 0 ] || bad 'a commented manifest decoy was accepted as a route row'

list=$("$harness" list 2>&1)
printf '%s' "$list" | grep -F 'S19jProBB' >/dev/null 2>&1 || bad 'list omits S19jProBB'
printf '%s' "$list" | grep -F 'am3-bb-s19jpro' >/dev/null 2>&1 || bad 'list omits the exact AM3-BB board target'

hint=$(cd / && "$harness" install-hint S19jProBB 192.0.2.1 2>&1)
printf '%s' "$hint" | grep -F 'PERSISTENT INSTALL REFUSED' >/dev/null 2>&1 || bad 'install hint does not refuse persistence'
printf '%s' "$hint" | grep -F 'runtime/SD lab-only' >/dev/null 2>&1 || bad 'install hint omits external-media-only posture'
procedure=$(printf '%s\n' "$hint" | sed -n '/BP-AM3-BB-PSU65-WATCHDOG\.md$/ { s/^[[:space:]]*//; p; }' | tail -n 1)
[ -n "$procedure" ] && [ "${procedure#/}" != "$procedure" ] && [ -r "$procedure" ] \
    || bad "install hint did not emit a readable absolute procedure path: ${procedure:-<missing>}"
procedure_blocks="$tmp/procedure-sh"
mkdir "$procedure_blocks"
awk -v out="$procedure_blocks" '
    /^```sh$/ { active=1; block++; file=out "/block-" block ".sh"; next }
    active && /^```$/ { close(file); active=0; next }
    active { print >file }
' "$procedure"
for block in "$procedure_blocks"/*.sh; do
    sed 's/<ip>/192.0.2.1/g' "$block" | sh -n \
        || bad "procedure shell block is not parseable: ${block##*/}"
done
grep -F 'operator-known_hosts' "$procedure" >/dev/null 2>&1 \
    || bad 'procedure does not preserve the exact pinned host-key bytes'
grep -F 'GPIO59 role remains' "$procedure" >/dev/null 2>&1 \
    || bad 'procedure does not retire the guessed GPIO59 cutoff role'
grep -F 'Class4/key1' "$procedure" >/dev/null 2>&1 \
    || bad 'procedure omits full decoded EEPROM admission before supply ON'
grep -F 'schema=v3' "$procedure" >/dev/null 2>&1 \
    || bad 'procedure names a retired route diagnostic schema'
if grep -Eq 'watchdog disabled|physical GPIO59|cold_boot_profile=15000_13800' "$procedure"; then
    bad 'procedure restored obsolete actuation/default guidance'
fi
grep -F 'if "$@" >"$host_evidence_dir/$phase.transcript" 2>&1; then' "$procedure" >/dev/null 2>&1 \
    || bad 'procedure phase status capture is not safe under shell errexit'
printf '%s' "$hint" | grep -E 'dcent install|output/dcentos-sysupgrade|--revert-to-stock' >/dev/null 2>&1 \
    && bad 'install hint leaked executable persistent-update instructions'

printf '%s\n' '{"schema":"dcent-accept-v2","authority":"diagnostic-observer","policy_id":"dcent-accept-policy-v2","result":"PASS","sku":"S19jProBB","board_target":"am3-bb-s19jpro","mode":"capstone"}' > "$tmp/matrix.jsonl"
if "$harness" matrix "$tmp/matrix.jsonl" >"$tmp/matrix-no-scope.out" 2>&1; then
    bad 'matrix unexpectedly accepted an implicit/incomplete scope'
fi
grep -F -- '--require=SKU:mode' "$tmp/matrix-no-scope.out" >/dev/null 2>&1 \
    || bad 'matrix missing-scope failure is not actionable'
if ! "$harness" matrix "$tmp/matrix.jsonl" --require=S19jProBB:capstone >"$tmp/matrix-am3.out" 2>&1; then
    bad 'matrix did not complete AM3 diagnostic scope'
fi
grep -F 'ACCEPTANCE_SCOPE_PASS' "$tmp/matrix-am3.out" >/dev/null 2>&1 \
    || bad 'matrix omitted its diagnostic-only scope verdict'
grep -F 'RELEASE_GO' "$tmp/matrix-am3.out" >/dev/null 2>&1 \
    && bad 'matrix claimed release authority from local observer JSON'

marker="$tmp/transport-contacted"
for command_name in ssh scp dcent bash curl nc; do
    command_path="$tmp/$command_name"
    printf '#!/bin/sh\nprintf contacted > "%s"\nexit 99\n' "$marker" > "$command_path"
    chmod +x "$command_path"
done

# Refusal is evaluated before IP validation, transcript file access, SSH, REST,
# deployment, or update tooling. The OTA path deliberately names no real file.
for phase in all backup firstlight ota; do
    rm -f "$marker"
    arg=192.0.2.1
    [ "$phase" = ota ] && arg="$tmp/does-not-exist.transcript"
    if PATH="$tmp:$PATH" "$harness" "$phase" S19jProBB "$arg" \
        --artifact-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
        --expected-version=2026.7.19 >"$tmp/$phase.out" 2>&1; then
        bad "$phase unexpectedly succeeded"
    fi
    [ ! -e "$marker" ] || bad "$phase contacted transport/deployment before refusal"
    grep -F 'refused for external-media route' "$tmp/$phase.out" >/dev/null 2>&1 \
        || bad "$phase did not emit the route-specific refusal"
    [ "$phase" != ota ] || ! grep -F 'pass a captured OTA-capstone transcript' "$tmp/$phase.out" >/dev/null 2>&1 \
        || bad 'OTA inspected the nonexistent transcript before route refusal'
done

# Replace only the transport mocks used by read-only observer phases.
cat > "$tmp/ssh" <<'MOCK_SSH'
#!/bin/sh
printf '%s\n' "$*" >> "${MOCK_COMMAND_LOG:?}"
case_dir=/tmp/dcentos-am3-bb.A1b2c3
receipt='AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v3 run_pid=4242 board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence=exact_device_tree'
case "$*" in
    */sys/class/net/eth0/address*) printf '%s\n' "${MOCK_MAC:-02:11:22:33:44:55}" ;;
    *date\ -u*) printf '%s\n' '20260719T120000Z' ;;
    */proc/mtd*)
        printf '%s\n' \
            'mtd0: 00100000 00020000 "boot"' \
            'mtd1: 02000000 00020000 "firmware"'
        ;;
    */api/system/info*)
        case "${MOCK_REST_CASE:-pass}" in
            pass) printf '%s\n' '{"status":"ok","board_target":"am3-bb-s19jpro","chip_type":"BM1362","soc":"AM335x"}' ;;
            wrong_identity) printf '%s\n' '{"status":"ok","board_target":"am2-s19jpro-zynq","chip_type":"BM1362","soc":"AM335x"}' ;;
        esac
        ;;
    */api/status*)
        [ "${MOCK_REST_CASE:-pass}" = pass ] && printf '%s\n' '{"status":"ok","temp_c":55}'
        ;;
    */proc/net/tcp*)
        printf '%s\n' \
            'producer_pid=4242' \
            'producer_start_ticks=98765' \
            'producer_exe=/tmp/dcentos-am3-bb.A1b2c3/dcentrald' \
            'listener_pair=4028,8080'
        ;;
    *command*version*)
        printf '%s\n' '{"STATUS":[{"STATUS":"S"}],"VERSION":[{"Miner":"dcentrald/0.6.0","Firmware":"DCENTOS","DCENTOS":"0.6.0"}]}'
        ;;
    *AM3_BB_ENUMERATION_RECEIPT*)
        case "${MOCK_ENUM_CASE:-assigned}" in
            exact)
                printf '%s\n' \
                    'current_pid=4242' \
                    'AM3_BB_ENUMERATION_RECEIPT schema=v1 run_pid=4242 chains=3 chain0=126 chain1=126 chain2=126 total=378 evidence=post_assignment_unique'
                ;;
            generic)
                printf '%s\n' 'current_pid=4242' 'enumerated 378 chips' 'total_chips=378'
                ;;
            *)
                printf '%s\n' 'current_pid=4242' 'configured BM1362 address assignment assigned_chips_total=378'
                ;;
        esac
        ;;
    *)
        case "${MOCK_SSH_CASE:-pass}" in
            empty) : ;;
            wrong_soc)
                printf '%s\n' \
                    'marker_state=absent' \
                    'compatible=vendor,ti,am335x-bone-black-lookalike' \
                    'model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0' \
                    'current_pid=4242' \
                    "cmdline=$case_dir/dcentrald --am3-bb-mining" \
                    "$receipt"
                ;;
            stale|legacy_supply)
                printf '%s\n' \
                    'marker_state=absent' \
                    'compatible=ti,am335x-bone-black' \
                    'model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0' \
                    'current_pid=4242' \
                    "cmdline=$case_dir/dcentrald --am3-bb-mining"
                if [ "$MOCK_SSH_CASE" = stale ]; then
                    printf '%s\n' "$receipt" | sed 's/run_pid=4242/run_pid=99/'
                else
                    printf '%s\n' "$receipt" | sed 's/schema=v3/schema=v2/; s/fixed_apw15120_runtime_owner_required/15000_13800/'
                fi
                ;;
            duplicate)
                printf '%s\n' \
                    'marker_state=absent' \
                    'compatible=ti,am335x-bone-black' \
                    'model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0' \
                    'current_pid=4242' \
                    "cmdline=$case_dir/dcentrald --am3-bb-mining" \
                    "$receipt" "$receipt"
                ;;
            *)
                printf '%s\n' \
                    'marker_state=absent' \
                    'compatible=ti,am335x-bone-black' \
                    'compatible=ti,am33xx' \
                    'model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0' \
                    'current_pid=4242' \
                    "cmdline=$case_dir/dcentrald --am3-bb-mining --config $case_dir/am3.toml" \
                    "$receipt"
                ;;
        esac
        ;;
esac
MOCK_SSH
chmod +x "$tmp/ssh"
: > "$tmp/commands.log"
case_dir=/tmp/dcentos-am3-bb.A1b2c3
printf '%s\n' '192.0.2.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyPinnedKey' > "$tmp/known_hosts"
auth_args="--ssh-known-hosts=$tmp/known_hosts --expected-mac=02:11:22:33:44:55"

# A zero-exit toolbox NAND inventory must never be promoted to a verified
# backup. The harness owns a pinned SSH transport and refuses to call this
# historically misleading compatibility command at all.
cat > "$tmp/dcent" <<'MOCK_DCENT'
#!/bin/sh
printf 'invoked\n' > "${MOCK_DCENT_MARKER:?}"
exit 0
MOCK_DCENT
chmod +x "$tmp/dcent"
rm -f "$tmp/dcent-invoked"
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_DCENT_MARKER="$tmp/dcent-invoked" \
    "$harness" backup S19jPro 192.0.2.1 $auth_args >"$tmp/backup-inventory.out" 2>&1; then
    bad 'backup gate accepted partition inventory as a verified backup'
fi
[ ! -e "$tmp/dcent-invoked" ] || bad 'backup gate delegated identity-sensitive work to the unpinned toolbox transport'
grep -F 'only lists /proc/mtd; it is not a backup producer' "$tmp/backup-inventory.out" >/dev/null 2>&1 \
    || bad 'backup refusal did not explain the toolbox NAND inventory semantics'
grep -F 'partition inventory cannot satisfy this gate' "$tmp/backup-inventory.out" >/dev/null 2>&1 \
    || bad 'backup refusal did not fail closed on missing verified evidence'

: > "$tmp/commands.log"
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_MAC=02:11:22:33:44:99 \
    "$harness" all S19jPro 192.0.2.1 $auth_args >"$tmp/all-wrong-identity.out" 2>&1; then
    bad 'aggregate flow accepted a physical-MAC identity mismatch'
fi
grep -F '/proc/mtd' "$tmp/commands.log" >/dev/null 2>&1 \
    && bad 'aggregate flow reached the backup prerequisite after identity failure'
grep -F 'eth0 identity mismatch' "$tmp/all-wrong-identity.out" >/dev/null 2>&1 \
    || bad 'aggregate identity refusal was not actionable'

if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" \
    "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" >"$tmp/detect-no-auth.out" 2>&1; then
    bad 'live detect accepted missing pinned transport identity'
fi
grep -F 'requires a readable operator-pinned --ssh-known-hosts' "$tmp/detect-no-auth.out" >/dev/null 2>&1 \
    || bad 'missing pinned transport failure is not actionable'

if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" \
    "$harness" detect S19jProBB 192.0.2.1 $auth_args >"$tmp/detect-no-case.out" 2>&1; then
    bad 'external-media detect accepted no case directory'
fi
grep -F -- '--case-dir=/tmp/dcentos-am3-bb.<mktemp-suffix>' "$tmp/detect-no-case.out" >/dev/null 2>&1 \
    || bad 'missing case-directory refusal is not actionable'
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" \
    "$harness" soak S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args --minutes=1 >"$tmp/weak-policy.out" 2>&1; then
    bad 'soak accepted a duration below the fixed policy minimum'
fi
grep -F 'cannot weaken the 10-minute minimum' "$tmp/weak-policy.out" >/dev/null 2>&1 \
    || bad 'weakened soak policy did not fail with an actionable error'
if grep -Eq 'DCENT_ACCEPT_(API_PORT|REST_PORT|FIRSTLIGHT_N|FIRSTLIGHT_T|CAPSTONE_N|CAPSTONE_T|POLL|TEMP_CEILING)' "$harness"; then
    bad 'ambient environment can still override an acceptance scoring constant'
fi
deploy="$here/../dev_deploy.sh"
grep -F -- '--runtime-only --verify' "$harness" >/dev/null 2>&1 \
    || bad 'acceptance first-light does not force the deploy helper onto /tmp'
grep -F 'FORCE_RUNTIME_ONLY' "$deploy" >/dev/null 2>&1 \
    || bad 'deploy helper has no explicit forced-runtime-only authority'
grep -F 'DCENTOS_EPHEMERAL_RUNTIME=1' "$deploy" >/dev/null 2>&1 \
    || bad 'runtime-only launch does not assert the daemon ephemeral-runtime policy'
grep -F 'DCENT_EXPECTED_MAC="$EXPECTED_MAC"' "$harness" >/dev/null 2>&1 \
    || bad 'acceptance does not bind the deploy helper to the independently recorded MAC'
grep -F 'DCENT_EXPECTED_MAC' "$deploy" >/dev/null 2>&1 \
    || bad 'deploy helper does not enforce its physical-unit identity input'
grep -F 'DCENTRALD_UNVERIFIABLE' "$deploy" >/dev/null 2>&1 \
    || bad 'deploy helper can silently skip a recognized but uninspectable daemon owner'
grep -F 'stop_exact_launched_process' "$deploy" >/dev/null 2>&1 \
    || bad 'deploy helper has no reusable PID/start/executable-bound launch stop'
grep -F 'RUNTIME_CONFIG_DIR="/tmp/dcentrald-runtime.${CONFIG_BIND_SHA256}.${DEPLOY_START}.$$"' "$deploy" >/dev/null 2>&1 \
    || bad 'runtime config is not deployed to a fresh content-addressed private directory'
grep -F 'START_ERROR=explicit_config_metadata_changed' "$deploy" >/dev/null 2>&1 \
    || bad 'runtime config metadata is not revalidated at the final launch boundary'
grep -F 'START_ERROR=explicit_config_hash_changed' "$deploy" >/dev/null 2>&1 \
    || bad 'runtime config is not re-hashed at the final launch boundary'
grep -F 'process_evidence_before=$(producer_process_evidence)' "$harness" >/dev/null 2>&1 \
    || bad 'acceptance does not sample producer evidence before API identity'
grep -F 'process_evidence_after=$(producer_process_evidence)' "$harness" >/dev/null 2>&1 \
    || bad 'acceptance does not sample producer evidence after API identity'
grep -F 'json_exit false "$NEW_PID" "$BINARY_SIZE" false "API health check failed"' "$deploy" >/dev/null 2>&1 \
    || bad 'deploy verification can still report success after API health failure'
grep -F 'touch /data/.dcent_stage_check' "$deploy" >/dev/null 2>&1 \
    && bad 'runtime deploy preflight still writes a persistent /data probe'
grep -F 'first-light requires exactly one numeric [thermal].fan_max_pwm<=30' "$harness" >/dev/null 2>&1 \
    || bad 'first-light does not fail closed on an unproven quiet fan ceiling'
grep -F -- '--output="$deploy_receipt"' "$harness" >/dev/null 2>&1 \
    || bad 'first-light does not consume the exact launched process receipt'
grep -F 'ACCEPT_PRODUCER_PID=' "$harness" >/dev/null 2>&1 \
    || bad 'first-light does not clear the pre-launch producer before rebinding'
grep -F 'first-light producer transition was not exactly bound to the launched runtime' "$harness" >/dev/null 2>&1 \
    || bad 'first-light does not reject stale or mismatched producer evidence'
grep -F 'stop_exact_runtime_launch "$launch_pid" "$launch_start" "$launch_exe"' "$harness" >/dev/null 2>&1 \
    || bad 'first-light post-launch failure cannot reclaim its exact runtime'
if grep -Eq 'RELEASE_(GO|NOGO)' "$harness" "$here/lib/accept_parse.sh"; then
    bad 'diagnostic matrix still exposes a release-authority verdict token'
fi

if ! PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_SSH_CASE=pass MOCK_REST_CASE=pass \
    "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/detect-pass.out" 2>&1; then
    bad 'exact AM3-BB identity evidence did not pass detect'
fi
grep -F 'IDENTITY_PASS' "$tmp/detect-pass.out" >/dev/null 2>&1 || bad 'detect PASS omitted the strict identity verdict'

for identity_case in empty wrong_soc stale duplicate legacy_supply; do
    if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_SSH_CASE="$identity_case" MOCK_REST_CASE=pass \
        "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/detect-$identity_case.out" 2>&1; then
        bad "detect unexpectedly passed $identity_case identity evidence"
    fi
done
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_SSH_CASE=pass MOCK_MAC=02:11:22:33:44:99 \
    "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/detect-wrong-mac.out" 2>&1; then
    bad 'detect unexpectedly passed a different physical MAC identity'
fi
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_SSH_CASE=pass MOCK_REST_CASE=empty \
    "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/detect-no-rest.out" 2>&1; then
    bad 'detect unexpectedly passed with REST unreachable'
fi
if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_SSH_CASE=pass MOCK_REST_CASE=wrong_identity \
    "$harness" detect S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/detect-wrong-rest-identity.out" 2>&1; then
    bad 'detect unexpectedly accepted a reachable REST endpoint bound to another board target'
fi

for enum_case in assigned generic; do
    if PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_ENUM_CASE="$enum_case" \
        "$harness" enum S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/enum-$enum_case.out" 2>&1; then
        bad "enum unexpectedly promoted $enum_case evidence"
    fi
    grep -F 'AM3_ENUM_PENDING:no_unique_population_receipt' "$tmp/enum-$enum_case.out" >/dev/null 2>&1 \
        || bad "enum $enum_case did not report missing unique-population proof"
done
if ! PATH="$tmp:$PATH" MOCK_COMMAND_LOG="$tmp/commands.log" MOCK_ENUM_CASE=exact \
    "$harness" enum S19jProBB 192.0.2.1 --case-dir="$case_dir" $auth_args >"$tmp/enum-exact.out" 2>&1; then
    bad 'exact current-run unique-population receipt did not pass enum'
fi

if grep -Ei '(^|[[:space:]])(dd|flash_erase|nandwrite|fw_setenv|sysupgrade|reboot|poweroff|halt|rm|mv)([[:space:]]|$)' "$tmp/commands.log" >/dev/null 2>&1; then
    bad 'observer transport command included a mutating operation'
fi
grep -F -- '-o StrictHostKeyChecking=yes' "$tmp/commands.log" >/dev/null 2>&1 \
    || bad 'observer SSH did not require strict host-key checking'
grep -F -- "UserKnownHostsFile=$tmp/known_hosts" "$tmp/commands.log" >/dev/null 2>&1 \
    || bad 'observer SSH did not use the operator-pinned known_hosts file'
[ ! -e "$marker" ] || bad 'observer phase used a direct local curl/nc transport instead of SSH loopback'

if [ "$fails" -eq 0 ]; then
    echo 'PASS: AM3-BB acceptance is route-bound, read-only, fail-closed, and assignment totals cannot prove enumeration'
    exit 0
fi
echo "FAIL: $fails AM3-BB acceptance-route regression(s)"
exit 1
