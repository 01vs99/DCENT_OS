#!/bin/sh
#
# test_accept_parse.sh — hardware-free unit tests for lib/accept_parse.sh.
#
# Feeds captured CGMiner/REST/log fixtures through the pure parsers and asserts
# the accepted-share counter, hashrate, elapsed, enumeration, and PASS/FAIL
# verdict logic. Contacts NO miner. Runs standalone AND inside the offline CI
# gate (ci_offline_gates.sh -> accept_parse_selftest) so the load-bearing
# accept-gate math can never silently regress.
#
# Exit 0 = all asserts pass; exit 1 = at least one failed.

# NOTE: no `set -e` — accept_verdict/accept_enum_verdict return non-zero BY DESIGN
# (that is the FAIL signal under test). `set -e` would abort at the first expected
# failure before we can capture its rc. The harness does its own assertion tally.
set -u

DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FIX="$DIR/fixtures"
CONF="$DIR/skus.conf"

# shellcheck source=lib/accept_parse.sh
. "$DIR/lib/accept_parse.sh"

# Every fixture this suite reads must exist BEFORE any assertion runs.
#
# Without this, a missing fixture does not fail the suite -- it makes the
# assertion vacuous. The parsers are fed by redirect (`parser < "$FIX/x"`), so a
# missing file yields EMPTY input, and for the negative cases empty produces the
# very FAIL/rc=1 the assertion was written to expect. Reproduced: deleting
# fixtures/log_am3_bb_enumerated_378.txt leaves this script printing
# "accept_parse tests passed." and exiting 0 while proving nothing about AM3-BB.
#
# That is the exact fail-open shape this suite exists to catch in the acceptance
# math, so it must not be present in the suite itself. A fixture that is missing
# is a broken checkout, not a skipped case.
missing_fixture=0
for required_fixture in \
    log_am3_bb_enumerated_378.txt \
    log_enumerated_189.txt \
    log_s17_enumerated_144.txt \
    log_t17plus_enumerated_132.txt \
    status_enumerated_342.json \
    status_s15_held_guide_60.json \
    status_s17plus_enumerated_195.json \
    status_t17_enumerated_90.json \
    summary_accepted7.json \
    summary_malformed.txt \
    summary_no_accepted.json \
    summary_spaced.json \
    summary_zero.json
do
    if [ ! -r "$FIX/$required_fixture" ]; then
        printf 'FAIL - required fixture missing or unreadable: fixtures/%s\n' \
            "$required_fixture" >&2
        missing_fixture=$((missing_fixture + 1))
    fi
done
if [ "$missing_fixture" -ne 0 ]; then
    printf 'accept_parse tests ABORTED: %s required fixture(s) absent. These are\n' \
        "$missing_fixture" >&2
    printf 'tracked files; a missing one means an incomplete checkout or a commit\n' >&2
    printf 'that landed this suite without its fixtures. Do not "fix" this by\n' >&2
    printf 'deleting the assertions that use them.\n' >&2
    exit 1
fi

fails=0
ok() { printf 'ok   - %s\n' "$*"; }
no() { printf 'FAIL - %s\n' "$*" >&2; fails=$((fails + 1)); }

# assert_eq <label> <expected> <actual>
assert_eq() {
    if [ "$2" = "$3" ]; then
        ok "$1 (= '$3')"
    else
        no "$1: expected '$2' got '$3'"
    fi
}

# assert_rc <label> <expected_rc> <actual_rc>
assert_rc() {
    if [ "$2" -eq "$3" ]; then
        ok "$1 (rc=$3)"
    else
        no "$1: expected rc $2 got $3"
    fi
}

# --- accept_parse_accepted --------------------------------------------------
# The decoy: summary_accepted7 also carries "Difficulty Accepted":1792.0 — a
# naive '"Accepted"' substring match would return 1792. Must return 7.
assert_eq "accepted: 7 (not the Difficulty Accepted 1792 decoy)" \
    "7" "$(accept_parse_accepted < "$FIX/summary_accepted7.json")"
assert_eq "accepted: 0 (fresh miner, zero shares)" \
    "0" "$(accept_parse_accepted < "$FIX/summary_zero.json")"
assert_eq "accepted: 42 (whitespace/pretty-printed body)" \
    "42" "$(accept_parse_accepted < "$FIX/summary_spaced.json")"
assert_eq "accepted: empty (error response, no SUMMARY)" \
    "" "$(accept_parse_accepted < "$FIX/summary_no_accepted.json")"
assert_eq "accepted: empty (connection-refused garbage)" \
    "" "$(accept_parse_accepted < "$FIX/summary_malformed.txt")"
assert_eq "accepted: REST system-info fallback" \
    "9" "$(printf '%s' '{"sharesAccepted":9}' | accept_parse_accepted)"

# --- accept_parse_mhs_av / elapsed -----------------------------------------
assert_eq "mhs av: 13500.42" \
    "13500.42" "$(accept_parse_mhs_av < "$FIX/summary_accepted7.json")"
assert_eq "elapsed: 615" \
    "615" "$(accept_parse_elapsed < "$FIX/summary_accepted7.json")"
assert_eq "mhs av: 95000.7 (spaced body)" \
    "95000.7" "$(accept_parse_mhs_av < "$FIX/summary_spaced.json")"
assert_eq "mhs av: REST GH/s fallback normalized to MH/s" \
    "12500" "$(printf '%s' '{"hashRate":12.5}' | accept_parse_mhs_av)"
assert_eq "elapsed: REST uptime fallback" \
    "321" "$(printf '%s' '{"uptime_s":321}' | accept_parse_elapsed)"

# --- accept_parse_enumerated (REST body + log line) ------------------------
assert_eq "enumerated: 342 (REST chips_enumerated)" \
    "342" "$(accept_parse_enumerated < "$FIX/status_enumerated_342.json")"
assert_eq "enumerated: 189 (dcentrald log line)" \
    "189" "$(accept_parse_enumerated < "$FIX/log_enumerated_189.txt")"
assert_eq "enumerated: 60 (S15 held-guide host fixture)" \
    "60" "$(accept_parse_enumerated < "$FIX/status_s15_held_guide_60.json")"
assert_eq "enumerated: 144 (S17 fixture)" \
    "144" "$(accept_parse_enumerated < "$FIX/log_s17_enumerated_144.txt")"
assert_eq "enumerated: 195 (S17+ BM1397 fixture)" \
    "195" "$(accept_parse_enumerated < "$FIX/status_s17plus_enumerated_195.json")"
assert_eq "enumerated: 90 (T17 fixture)" \
    "90" "$(accept_parse_enumerated < "$FIX/status_t17_enumerated_90.json")"
assert_eq "enumerated: 132 (T17+ BM1397 fixture)" \
    "132" "$(accept_parse_enumerated < "$FIX/log_t17plus_enumerated_132.txt")"
assert_eq "enumerated: assignment-only AM3-BB total is not an observation" \
    "" "$(accept_parse_enumerated < "$FIX/log_am3_bb_enumerated_378.txt")"

# --- accept_verdict (the accept gate decision) -----------------------------
# PASS when count >= threshold; FAIL otherwise; junk coerces safely.
v=$(accept_verdict 7 3); rc=$?; assert_eq "verdict 7>=3 text" "PASS" "$v"; assert_rc "verdict 7>=3 rc" 0 "$rc"
v=$(accept_verdict 3 3); rc=$?; assert_eq "verdict 3>=3 text (boundary)" "PASS" "$v"; assert_rc "verdict 3>=3 rc" 0 "$rc"
v=$(accept_verdict 2 3); rc=$?; assert_eq "verdict 2<3 text" "FAIL" "$v"; assert_rc "verdict 2<3 rc" 1 "$rc"
v=$(accept_verdict 0 1); rc=$?; assert_eq "verdict 0<1 text (dead miner)" "FAIL" "$v"; assert_rc "verdict 0<1 rc" 1 "$rc"
v=$(accept_verdict "" 3); rc=$?; assert_eq "verdict empty->0 text" "FAIL" "$v"; assert_rc "verdict empty->0 rc" 1 "$rc"
v=$(accept_verdict "xx" 1); rc=$?; assert_eq "verdict junk->0 text" "FAIL" "$v"; assert_rc "verdict junk->0 rc" 1 "$rc"

# End-to-end: parse a live-shaped body then gate on it.
n=$(accept_parse_accepted < "$FIX/summary_accepted7.json")
v=$(accept_verdict "$n" 5); rc=$?
assert_eq "e2e parse+gate (7 shares, N=5) text" "PASS" "$v"
assert_rc "e2e parse+gate (7 shares, N=5) rc" 0 "$rc"

# --- accepted-share observation window ------------------------------------
v=$(accept_share_window_verdict 100 105 5 600 600 64 75); rc=$?
assert_eq "share window: five new shares over full capstone passes" "SHARE_PASS" "$v"; assert_rc "share capstone pass rc" 0 "$rc"
v=$(accept_share_window_verdict 100 105 5 590 600 64 75); rc=$?
assert_eq "share window: lifetime count cannot bypass duration" "SHARE_PENDING:duration" "$v"; assert_rc "share duration pending rc" 1 "$rc"
v=$(accept_share_window_verdict 100 104 5 600 600 64 75); rc=$?
assert_eq "share window: cumulative count is scored as a delta" "SHARE_PENDING:shares" "$v"; assert_rc "share delta pending rc" 1 "$rc"
v=$(accept_share_window_verdict 100 99 1 10 0 64 75); rc=$?
assert_eq "share window: counter rollback is a producer fault" "SHARE_FAIL:counter_reset" "$v"; assert_rc "share reset rc" 1 "$rc"
v=$(accept_share_window_verdict 100 101 1 10 0 64 75 103); rc=$?
assert_eq "share window: adjacent rollback above baseline is a producer fault" "SHARE_FAIL:counter_reset" "$v"; assert_rc "share adjacent reset rc" 1 "$rc"
v=$(accept_share_window_verdict 100 0 1 10 0 64 75 103); rc=$?
assert_eq "share window: reset to zero cannot regrow invisibly" "SHARE_FAIL:counter_reset" "$v"; assert_rc "share zero reset rc" 1 "$rc"
v=$(accept_share_window_verdict 100 105 5 600 600 '' 75); rc=$?
assert_eq "share window: thermal blindness fails closed" "SHARE_FAIL:thermal_unknown" "$v"; assert_rc "share thermal blind rc" 1 "$rc"
v=$(accept_share_window_verdict 100 105 5 600 600 76 75); rc=$?
assert_eq "share window: overtemperature fails closed" "SHARE_FAIL:overtemp" "$v"; assert_rc "share overtemp rc" 1 "$rc"

# --- same-process REST/CGMiner producer identity --------------------------
producer_version='{"STATUS":[{"STATUS":"S"}],"VERSION":[{"Miner":"dcentrald/0.6.0","Firmware":"DCENTOS","DCENTOS":"0.6.0"}]}'
producer_evidence() {
    printf '%s\n' 'producer_pid=4242' 'producer_start_ticks=98765' \
        'producer_exe=/tmp/dcentrald_runtime' 'listener_pair=4028,8080' "$producer_version"
}
v=$(producer_evidence | accept_dcentrald_producer_verdict 4242); rc=$?
assert_eq "producer: same admitted dcentrald owns both endpoints" "PRODUCER_PASS" "$v"; assert_rc "producer pass rc" 0 "$rc"
v=$(producer_evidence | accept_dcentrald_producer_verdict 9999); rc=$?
assert_eq "producer: AM3 route PID mismatch fails" "PRODUCER_FAIL:route_pid" "$v"; assert_rc "producer route pid rc" 1 "$rc"
v=$({ producer_evidence; printf '%s\n' 'producer_pid=4243'; } | accept_dcentrald_producer_verdict); rc=$?
assert_eq "producer: multiple candidate processes fail" "PRODUCER_FAIL:listener_ownership" "$v"; assert_rc "producer ambiguity rc" 1 "$rc"
v=$(producer_evidence | sed 's/"Firmware":"DCENTOS"/"Firmware":"stock"/' | accept_dcentrald_producer_verdict 4242); rc=$?
assert_eq "producer: stock CGMiner cannot supply scored shares" "PRODUCER_FAIL:firmware_identity" "$v"; assert_rc "producer firmware rc" 1 "$rc"

# --- accept_enum_verdict (enumeration sanity) ------------------------------
v=$(accept_enum_verdict 342 342); rc=$?; assert_eq "enum 342==342" "PASS" "$v"; assert_rc "enum 342==342 rc" 0 "$rc"
v=$(accept_enum_verdict 340 342); rc=$?; assert_eq "enum 340~342 (in band)" "PASS" "$v"; assert_rc "enum 340~342 rc" 0 "$rc"
v=$(accept_enum_verdict 28 342); rc=$?; assert_eq "enum 28<<342 (partial chain, FAIL)" "FAIL" "$v"; assert_rc "enum 28 rc" 1 "$rc"
v=$(accept_enum_verdict 96 0); rc=$?; assert_eq "enum 96 vs UNCONFIRMED->CAPTURE" "CAPTURE" "$v"; assert_rc "enum capture rc" 0 "$rc"
v=$(accept_enum_verdict 0 0); rc=$?; assert_eq "enum 0 vs UNCONFIRMED->FAIL" "FAIL" "$v"; assert_rc "enum 0/0 rc" 1 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/status_s15_held_guide_60.json")" 0); rc=$?; assert_eq "enum S15 held-guide fixture" "CAPTURE" "$v"; assert_rc "enum S15 held-guide rc" 0 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/log_s17_enumerated_144.txt")" 144); rc=$?; assert_eq "enum S17 144 fixture" "PASS" "$v"; assert_rc "enum S17 fixture rc" 0 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/status_s17plus_enumerated_195.json")" 195); rc=$?; assert_eq "enum S17+ 195 fixture" "PASS" "$v"; assert_rc "enum S17+ fixture rc" 0 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/status_t17_enumerated_90.json")" 90); rc=$?; assert_eq "enum T17 90 fixture" "PASS" "$v"; assert_rc "enum T17 fixture rc" 0 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/log_t17plus_enumerated_132.txt")" 132); rc=$?; assert_eq "enum T17+ 132 fixture" "PASS" "$v"; assert_rc "enum T17+ fixture rc" 0 "$rc"
v=$(accept_enum_verdict "$(accept_parse_enumerated < "$FIX/log_am3_bb_enumerated_378.txt")" 378); rc=$?; assert_eq "enum AM3-BB assignment-only fixture fails" "FAIL" "$v"; assert_rc "enum AM3-BB assignment-only fixture rc" 1 "$rc"

# --- exact AM3-BB route identity and unique-population receipts ------------
am3_pid=4242
am3_case=/tmp/dcentos-am3-bb.A1b2c3
am3_route_receipt="AM3_BB_ROUTE_ADMISSION_RECEIPT schema=v3 run_pid=$am3_pid board_target=am3-bb-s19jpro soc=am335x carrier=S19J_IO_BOARD_V2_0 asic=BM1362 asic_evidence=declared_runtime_composition topology_profile=s19j_io_board_v2_0_exact_v1 gpio_profile=legacy59_metadata-psu65_high-rst49_60_27_22-plug51_48_47_46-fantach7_20_110_112-led23_45 uart_profile=ttyS1_48022000-ttyS2_48024000-ttyS4_481a8000-3000000 i2c_profile=eeprom0_50_51_52-deny-psu1_10 cold_boot_profile=fixed_apw15120_runtime_owner_required-reset10_1100_retry1x2_200_100-fan10_30 identity_evidence=exact_device_tree"
am3_enum_receipt="AM3_BB_ENUMERATION_RECEIPT schema=v1 run_pid=$am3_pid chains=3 chain0=126 chain1=126 chain2=126 total=378 evidence=post_assignment_unique"
am3_identity() {
    printf '%s\n' \
        'marker_state=absent' \
        'compatible=ti,am335x-bone-black' \
        'compatible=ti,am33xx' \
        'model=BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0' \
        "current_pid=$am3_pid" \
        "cmdline=$am3_case/dcentrald --am3-bb-mining --config $am3_case/am3.toml" \
        "$am3_route_receipt" \
        'rest_reachable=1' \
        'rest_board_target=am3-bb-s19jpro'
}

v=$(am3_identity | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: exact LuxOS DT/current process/receipt/REST" "IDENTITY_PASS" "$v"; assert_rc "AM3 identity pass rc" 0 "$rc"
v=$(am3_identity | sed 's/marker_state=absent/marker_state=present\nmarker=am3-bb-s19jpro/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: exact explicit marker is admitted" "IDENTITY_PASS" "$v"; assert_rc "AM3 marker identity rc" 0 "$rc"
v=$(am3_identity | sed 's/ti,am335x-bone-black/vendor,lookalike/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: compatible substring/lookalike fails" "IDENTITY_FAIL:soc" "$v"; assert_rc "AM3 bad SoC rc" 1 "$rc"
v=$(am3_identity | sed 's/rest_reachable=1/rest_reachable=0/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: unreachable REST fails" "IDENTITY_FAIL:rest" "$v"; assert_rc "AM3 REST fail rc" 1 "$rc"
v=$(am3_identity | sed 's/run_pid=4242/run_pid=99/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: stale route receipt PID fails" "IDENTITY_FAIL:runtime_receipt" "$v"; assert_rc "AM3 stale receipt rc" 1 "$rc"
v=$(am3_identity | sed 's/schema=v3/schema=v2/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: retired supply recipe schema fails" "IDENTITY_FAIL:runtime_receipt" "$v"; assert_rc "AM3 retired supply schema rc" 1 "$rc"
v=$(am3_identity | sed 's/fixed_apw15120_runtime_owner_required/15000_13800/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: guessed APW operating targets fail" "IDENTITY_FAIL:runtime_receipt" "$v"; assert_rc "AM3 guessed APW target rc" 1 "$rc"
v=$(am3_identity | sed '/^cmdline=/p' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: duplicate process evidence fails" "IDENTITY_FAIL:process" "$v"; assert_rc "AM3 duplicate cmdline rc" 1 "$rc"
v=$(am3_identity | sed "s#cmdline=$am3_case/dcentrald #cmdline=$am3_case/dcentrald-evil #" | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: executable path lookalike fails" "IDENTITY_FAIL:process" "$v"; assert_rc "AM3 path lookalike rc" 1 "$rc"
v=$(am3_identity | sed "s#cmdline=/tmp/dcentos-am3-bb\.A1b2c3/#cmdline=/tmp/dcentos-am3-bbXA1b2c3/#" | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: case-dir regex lookalike fails" "IDENTITY_FAIL:process" "$v"; assert_rc "AM3 case-dir lookalike rc" 1 "$rc"
v=$(am3_identity | sed 's/--am3-bb-mining/--am3-bb-mining-evil/' | accept_am3_bb_identity_verdict "$am3_case"); rc=$?
assert_eq "AM3 identity: mode-flag lookalike fails" "IDENTITY_FAIL:process" "$v"; assert_rc "AM3 flag lookalike rc" 1 "$rc"

v=$(printf '%s\n' "$am3_enum_receipt" | accept_am3_bb_enumeration_verdict "$am3_pid"); rc=$?
assert_eq "AM3 enum: exact current-run unique population" "AM3_ENUM_PASS" "$v"; assert_rc "AM3 enum pass rc" 0 "$rc"
v=$(printf '%s\n' 'configured BM1362 address assignment assigned_chips_total=378' | accept_am3_bb_enumeration_verdict "$am3_pid"); rc=$?
assert_eq "AM3 enum: aggregate assignment remains pending" "AM3_ENUM_PENDING:no_unique_population_receipt" "$v"; assert_rc "AM3 aggregate pending rc" 1 "$rc"
v=$(printf '%s\n' "$am3_enum_receipt" | accept_am3_bb_enumeration_verdict 99); rc=$?
assert_eq "AM3 enum: stale PID receipt fails" "AM3_ENUM_FAIL:receipt_mismatch" "$v"; assert_rc "AM3 stale enum rc" 1 "$rc"
v=$(printf '%s\n%s\n' "$am3_enum_receipt" "$am3_enum_receipt" | accept_am3_bb_enumeration_verdict "$am3_pid"); rc=$?
assert_eq "AM3 enum: duplicate receipts are ambiguous" "AM3_ENUM_FAIL:ambiguous_receipts" "$v"; assert_rc "AM3 duplicate enum rc" 1 "$rc"

# --- accept_parse_temp_c + accept_temp_safe (soak thermal guard) -----------
assert_eq "temp: 49.3 (REST temp_c)" \
    "49.3" "$(accept_parse_temp_c < "$FIX/status_enumerated_342.json")"
assert_eq "temp: max across multiple readings (never mask a hot board)" \
    "71" "$(printf '{"temp_c":55,"chip_temp_c":71,"board_temp_c":60}' | accept_parse_temp_c)"
assert_eq "temp: empty when absent" \
    "" "$(printf '{"hashrate_ghs":100}' | accept_parse_temp_c)"

v=$(accept_temp_safe 49.3 75); rc=$?; assert_eq "temp 49.3<=75 SAFE" "SAFE" "$v"; assert_rc "temp safe rc" 0 "$rc"
v=$(accept_temp_safe 75 75); rc=$?; assert_eq "temp 75<=75 boundary SAFE" "SAFE" "$v"; assert_rc "temp boundary rc" 0 "$rc"
v=$(accept_temp_safe 80 75); rc=$?; assert_eq "temp 80>75 HOT" "HOT" "$v"; assert_rc "temp hot rc" 1 "$rc"
v=$(accept_temp_safe 91.5 75); rc=$?; assert_eq "temp 91.5>75 HOT (fractional)" "HOT" "$v"; assert_rc "temp hot frac rc" 1 "$rc"
v=$(accept_temp_safe 75.9 75); rc=$?; assert_eq "temp 75.9>75 HOT (no truncation)" "HOT" "$v"; assert_rc "temp fractional boundary rc" 1 "$rc"
v=$(accept_temp_safe -273 75); rc=$?; assert_eq "impossible negative temperature fails closed" "UNKNOWN" "$v"; assert_rc "temp sentinel rc" 1 "$rc"
v=$(accept_temp_safe "" 75); rc=$?; assert_eq "temp missing fails closed" "UNKNOWN" "$v"; assert_rc "temp missing rc" 1 "$rc"
v=$(accept_temp_safe "junk" 75); rc=$?; assert_eq "temp junk fails closed" "UNKNOWN" "$v"; assert_rc "temp junk rc" 1 "$rc"

# --- accept_soak_verdict (sustained-mining stability gate) ------------------
# Catches what the single-point accept gate cannot: first-shares-then-die-spiral,
# thermal throttle, or stall. Each soak() arg is one "elapsed acc mhs temp" line.
soak() { printf '%s\n' "$@"; }

v=$(soak "60 5 13000000 62" "120 8 12950000 64" "180 12 13010000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: stable run PASS" "SOAK_PASS" "$v"; assert_rc "soak stable rc" 0 "$rc"

v=$(soak "60 5 13000000 62" "120 8 5000000 64" "180 9 4800000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: hashrate collapse FAIL" "SOAK_FAIL:hashrate_collapse(min=4800000<floor=9100000)" "$v"
assert_rc "soak collapse rc" 1 "$rc"

v=$(soak "60 5 13000000 62" "120 5 13000000 64" "180 5 13000000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: shares stalled FAIL" "SOAK_FAIL:share_delta(0<1)" "$v"
assert_rc "soak stalled rc" 1 "$rc"

v=$(soak "0 100 13000000 62" "300 102 13000000 64" "600 104 13000000 63" | accept_soak_verdict 75 70 3 5 600); rc=$?
assert_eq "soak policy: fewer than five new shares fails" "SOAK_FAIL:share_delta(4<5)" "$v"; assert_rc "soak policy share delta rc" 1 "$rc"
v=$(soak "0 100 13000000 62" "290 103 13000000 64" "590 105 13000000 63" | accept_soak_verdict 75 70 3 5 600); rc=$?
assert_eq "soak policy: short observation fails" "SOAK_FAIL:duration(590<600)" "$v"; assert_rc "soak policy duration rc" 1 "$rc"
v=$(soak "0 100 13000000 62" "300 0 13000000 64" "600 105 13000000 63" | accept_soak_verdict 75 70 3 5 600); rc=$?
assert_eq "soak: mid-window counter reset cannot be hidden by endpoints" "SOAK_FAIL:counter_reset(100->0)" "$v"; assert_rc "soak mid-reset rc" 1 "$rc"
v=$(soak "0 100 13000000 62" "60 105 13000000 64" "600 105 13000000 63" | accept_soak_verdict 75 70 3 5 600 300); rc=$?
assert_eq "soak: early shares followed by prolonged stall fails" "SOAK_FAIL:share_progress_stalled" "$v"; assert_rc "soak progress freshness rc" 1 "$rc"
v=$(soak "0 100 0 62" "300 103 0 64" "600 105 0 63" | accept_soak_verdict 75 70 3 5 600 300); rc=$?
assert_eq "soak: all-zero hashrate is unavailable, not retained" "SOAK_FAIL:hashrate_unavailable" "$v"; assert_rc "soak zero hashrate rc" 1 "$rc"

v=$(soak "60 5 13000000 62" "120 8 13000000 80" "180 12 13000000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: thermal excursion FAIL" "SOAK_FAIL:thermal_excursion" "$v"; assert_rc "soak hot rc" 1 "$rc"

v=$(soak "60 5 13000000 62" "120 8 13000000 " "180 12 13000000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: thermal blind fails closed" "SOAK_FAIL:thermal_blind" "$v"; assert_rc "soak blind rc" 1 "$rc"

v=$(soak "60 5 13000000 62" | accept_soak_verdict 75); rc=$?
assert_eq "soak: too few samples FAIL" "SOAK_FAIL:too_few_samples(1<3)" "$v"; assert_rc "soak short rc" 1 "$rc"

v=$(soak "60 5 13000000 62" "120 8 xx 64" "180 12 13000000 63" | accept_soak_verdict 75); rc=$?
assert_eq "soak: nonnumeric mhs fails closed" "SOAK_FAIL:nonnumeric_mhs" "$v"; assert_rc "soak junk mhs rc" 1 "$rc"

# Retention boundary: min == exactly 70% of max -> PASS (floor is inclusive).
v=$(soak "60 5 10000000 62" "120 8 7000000 63" "180 12 9000000 63" | accept_soak_verdict 75 70); rc=$?
assert_eq "soak: min==70% of max PASS" "SOAK_PASS" "$v"; assert_rc "soak retention boundary rc" 0 "$rc"

# Redirected (not piped) stdin must accumulate identically (no subshell loss).
v=$(accept_soak_verdict 75 <<SOAK_TEST_EOF
60 5 13000000 62
120 8 12900000 64
180 12 13000000 63
SOAK_TEST_EOF
); rc=$?
assert_eq "soak: redirected stdin PASS" "SOAK_PASS" "$v"; assert_rc "soak redirect rc" 0 "$rc"

# --- accept_boot_verdict (serial/boot-log stall-stage diagnosis) ------------
# Turns a captured UART cold-boot log into an actionable stall-point verdict —
# the missing analysis step for the deferred SD-first cold-boot blockers.
bl() { printf '%s\n' "$@"; }

v=$(bl "U-Boot 2019.01" "Starting kernel" "Freeing unused kernel memory" "dcentrald v0.6" "enumerated 189 chips" "ACCEPT GATE PASS: 5 accepted shares" | accept_boot_verdict); rc=$?
assert_eq "boot: full boot to mining -> PASS" "BOOT_PASS" "$v"; assert_rc "boot pass rc" 0 "$rc"

v=$(bl "U-Boot 2019.01" "Starting kernel" "Kernel panic - not syncing" | accept_boot_verdict); rc=$?
assert_eq "boot: kernel panic diagnosed at kernel" "BOOT_FAIL:kernel" "$v"; assert_rc "boot kernel rc" 1 "$rc"

v=$(bl "U-Boot 2019.01" "Booting Linux" "BusyBox v1.31" "Starting S40network" | accept_boot_verdict); rc=$?
assert_eq "boot: userspace stall diagnosed at init" "BOOT_FAIL:init" "$v"; assert_rc "boot init rc" 1 "$rc"

v=$(bl "U-Boot SPL 2019" "Run /sbin/init" "dcentrald v0.6" "enumerated 126 chips" | accept_boot_verdict); rc=$?
assert_eq "boot: enum-no-shares diagnosed at enum" "BOOT_FAIL:enum" "$v"; assert_rc "boot enum rc" 1 "$rc"

v=$(bl "U-Boot 2019.01" "Hit any key to stop autoboot" | accept_boot_verdict); rc=$?
assert_eq "boot: bootloader hang diagnosed at uboot" "BOOT_FAIL:uboot" "$v"; assert_rc "boot uboot rc" 1 "$rc"

v=$(bl "random noise with no boot markers" | accept_boot_verdict); rc=$?
assert_eq "boot: markerless log fails closed at none" "BOOT_FAIL:none" "$v"; assert_rc "boot none rc" 1 "$rc"

# --- accept_matrix_verdict (diagnostic-only, target-bound scope roll-up) -----
# stderr grid discarded (2>/dev/null); stdout carries only the machine verdict.
mj() { printf '%s\n' "$@"; }
jr() { printf '{"schema":"dcent-accept-v2","authority":"diagnostic-observer","policy_id":"dcent-accept-policy-v2","result":"%s","sku":"%s","board_target":"%s","mode":"%s"}\n' "$1" "$2" "$3" "$4"; }

v=$({ jr PASS S9 am1-s9 capstone; jr PASS S19jPro am2-s19jpro-zynq soak; } | accept_matrix_verdict "$CONF" 'S9:capstone,S19jPro:soak' 2>/dev/null); rc=$?
assert_eq "matrix: all diagnostic results pass scope" "ACCEPTANCE_SCOPE_PASS" "$v"; assert_rc "matrix pass rc" 0 "$rc"

v=$({ jr PASS S9 am1-s9 capstone; jr FAIL S21 am3-s21 soak; echo 'log noise line'; } | accept_matrix_verdict "$CONF" 'S9:capstone,S21:soak' 2>/dev/null); rc=$?
assert_eq "matrix: a FAIL lists sku:phase" "ACCEPTANCE_SCOPE_NOGO:S21:soak" "$v"; assert_rc "matrix nogo rc" 1 "$rc"

v=$(printf '' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: no results fails closed" "ACCEPTANCE_SCOPE_NOGO:no_results" "$v"; assert_rc "matrix empty rc" 1 "$rc"
v=$(mj 'just a log line' 'another non-json' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: non-JSON only fails closed" "ACCEPTANCE_SCOPE_NOGO:no_results" "$v"; assert_rc "matrix nonjson rc" 1 "$rc"

v=$(jr PASS S9 am1-s9 capstone | accept_matrix_verdict "$CONF" 'S9:capstone,S21:soak' 2>/dev/null); rc=$?
assert_eq "matrix: incomplete declared scope fails" "ACCEPTANCE_SCOPE_NOGO:S21:soak:missing" "$v"; assert_rc "matrix missing scope rc" 1 "$rc"
v=$(jr PASS Ghost ghost-target capstone | accept_matrix_verdict "$CONF" 'Ghost:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: unknown manifest SKU fails" "ACCEPTANCE_SCOPE_NOGO:Ghost:unknown_sku" "$v"; assert_rc "matrix unknown SKU rc" 1 "$rc"
bad_manifest="${TMPDIR:-/tmp}/dcent-accept-bad-manifest-$$"
sed -n '/^S9|/p' "$CONF" > "$bad_manifest"
sed -n '/^S9|/p' "$CONF" >> "$bad_manifest"
v=$(jr PASS S9 am1-s9 capstone | accept_matrix_verdict "$bad_manifest" 'S9:capstone' 2>/dev/null); rc=$?
rm -f "$bad_manifest"
assert_eq "matrix: duplicate manifest SKU fails" "ACCEPTANCE_SCOPE_NOGO:manifest_invalid" "$v"; assert_rc "matrix bad manifest rc" 1 "$rc"
# The negative control follows an actual held route, not a SKU since promoted.
capture_row=$(awk -F '|' '$9 == "NOT-IMPLEMENTED" { print $1 "|" $2; exit }' "$CONF")
[ -n "$capture_row" ] || { no "required NOT-IMPLEMENTED control is absent from skus.conf"; exit 1; }
capture_sku=${capture_row%%|*}
capture_target=${capture_row#*|}
v=$(jr PASS "$capture_sku" "$capture_target" capstone | accept_matrix_verdict "$CONF" "$capture_sku:capstone" 2>/dev/null); rc=$?
assert_eq "matrix: NOT-IMPLEMENTED cannot pass" "ACCEPTANCE_SCOPE_NOGO:$capture_sku:not_implemented" "$v"; assert_rc "matrix not implemented rc" 1 "$rc"
v=$(jr PASS S19jProBB am3-bb-s19jpro capstone | accept_matrix_verdict "$CONF" 'S19jProBB:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: external-media evidence can complete diagnostic scope" "ACCEPTANCE_SCOPE_PASS" "$v"; assert_rc "matrix external diagnostic rc" 0 "$rc"
v=$(jr PASS S19jProBB am3-bb-s19jpro ota | accept_matrix_verdict "$CONF" 'S19jProBB:ota' 2>/dev/null); rc=$?
assert_eq "matrix: external-media OTA route is forbidden" "ACCEPTANCE_SCOPE_NOGO:S19jProBB:route_forbidden" "$v"; assert_rc "matrix external OTA rc" 1 "$rc"
v=$(jr PASS S17 am2-s17p bootlog | accept_matrix_verdict "$CONF" 'S17:bootlog' 2>/dev/null); rc=$?
assert_eq "matrix: bootlog cannot satisfy acceptance scope" "ACCEPTANCE_SCOPE_NOGO:S17:diagnostic_only" "$v"; assert_rc "matrix bootlog rc" 1 "$rc"
v=$(mj '{"result":"PASS","sku":"S9","mode":"capstone"}' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: legacy unbound row fails" "ACCEPTANCE_SCOPE_NOGO:unbound_result" "$v"; assert_rc "matrix legacy row rc" 1 "$rc"
v=$(jr PASS S9 am1-s9 capstone | sed 's/"policy_id":"dcent-accept-policy-v2",//' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: missing fixed policy fails" "ACCEPTANCE_SCOPE_NOGO:unbound_result" "$v"; assert_rc "matrix missing policy rc" 1 "$rc"
v=$(jr PASS S9 am1-s9 capstone | sed 's/dcent-accept-policy-v2/weaker-local-policy/' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: wrong policy fails" "ACCEPTANCE_SCOPE_NOGO:unbound_result" "$v"; assert_rc "matrix wrong policy rc" 1 "$rc"
v=$(jr PASS S9 am1-s9 capstone | sed 's/"policy_id"/"policy_id":"dcent-accept-policy-v2","policy_id"/' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: duplicate policy is ambiguous" "ACCEPTANCE_SCOPE_NOGO:unbound_result" "$v"; assert_rc "matrix duplicate policy rc" 1 "$rc"
v=$(jr PASS S19jPro am3-bb-s19jpro soak | accept_matrix_verdict "$CONF" 'S19jPro:soak' 2>/dev/null); rc=$?
assert_eq "matrix: relabelled board target fails" "ACCEPTANCE_SCOPE_NOGO:S19jPro:board_target_mismatch" "$v"; assert_rc "matrix target bind rc" 1 "$rc"
v=$({ jr PASS S9 am1-s9 capstone; jr PASS S9 am1-s9 capstone; } | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: duplicate result fails" "ACCEPTANCE_SCOPE_NOGO:S9:capstone:duplicate" "$v"; assert_rc "matrix duplicate rc" 1 "$rc"
v=$(mj '{"schema":"dcent-accept-v2","authority":"diagnostic-observer","policy_id":"dcent-accept-policy-v2","result":"PASS","result":"UNKNOWN","sku":"S9","board_target":"am1-s9","mode":"capstone"}' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: duplicate JSON field is unbound" "ACCEPTANCE_SCOPE_NOGO:unbound_result" "$v"; assert_rc "matrix malformed rc" 1 "$rc"
v=$(mj '{"schema":"dcent-accept-v2" "authority":"diagnostic-observer","result":"PASS","sku":"S9","board_target":"am1-s9","mode":"capstone"}' | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: syntactically malformed JSON fails" "ACCEPTANCE_SCOPE_NOGO:malformed_result" "$v"; assert_rc "matrix invalid JSON rc" 1 "$rc"
v=$(printf '%s trailing\n' "$(jr PASS S9 am1-s9 capstone)" | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: trailing garbage fails" "ACCEPTANCE_SCOPE_NOGO:malformed_result" "$v"; assert_rc "matrix trailing garbage rc" 1 "$rc"
v=$(jr PASS S21 am3-s21 soak | accept_matrix_verdict "$CONF" 'S9:capstone' 2>/dev/null); rc=$?
assert_eq "matrix: out-of-scope result fails" "ACCEPTANCE_SCOPE_NOGO:S21:soak:outside_scope" "$v"; assert_rc "matrix outside scope rc" 1 "$rc"

# --- accept_ota_verdict (witnessed-OTA-capstone stage diagnosis) -------------
# Encodes the  OTA truth contracts: uploaded != scheduled != flashed !=
# mining, so a weaker signal can never score as a capstone pass.
ol() { printf '%s\n' "$@"; }
ota_sha=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ota_version=2026.7.19
ota_begin="DCENT_OTA_CAPSTONE_BEGIN sku=S9 board_target=am1-s9 artifact_sha256=$ota_sha expected_version=$ota_version"
ota_end="DCENT_OTA_CAPSTONE_END sku=S9 board_target=am1-s9 artifact_sha256=$ota_sha observed_version=$ota_version"
ota_pass() {
    ol "$ota_begin" \
        "upload accepted" \
        "artifact sha256 verified: $ota_sha" \
        "OTA signature verified" \
        "sysupgrade scheduled" \
        "reboot observed" \
        "version matches expected: $ota_version" \
        "ACCEPT GATE PASS: 5 accepted shares" \
        "$ota_end"
}

v=$(ota_pass | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: full capstone -> PASS" "OTA_PASS" "$v"; assert_rc "ota pass rc" 0 "$rc"

v=$(ol "$ota_begin" "upload accepted" "artifact sha256 verified: $ota_sha" "signature check: BAD" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: unsigned image stalls at artifact verification" "OTA_FAIL:artifact_verified" "$v"; assert_rc "ota unsigned rc" 1 "$rc"

v=$(ol "$ota_begin" "upload accepted" "artifact sha256 verified: $ota_sha" "OTA signature verified" "sysupgrade scheduled" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: scheduled != flashed" "OTA_FAIL:scheduled" "$v"; assert_rc "ota scheduled rc" 1 "$rc"

v=$(ol "$ota_begin" "upload accepted" "artifact sha256 verified: $ota_sha" "OTA signature verified" "sysupgrade scheduled" "reboot observed" "version matches expected: $ota_version" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: version-ok-no-shares stalls at version_confirmed" "OTA_FAIL:version_confirmed" "$v"; assert_rc "ota version rc" 1 "$rc"

v=$(ol "random noise no markers" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: markerless transcript fails closed" "OTA_FAIL:none" "$v"; assert_rc "ota none rc" 1 "$rc"

v=$(ol "ACCEPT GATE PASS: 5 accepted shares" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: accepted shares alone cannot pass" "OTA_FAIL:none" "$v"; assert_rc "ota shares-only rc" 1 "$rc"
v=$(ol "$ota_begin" "upload failed: not uploaded" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: negative upload prose is not a milestone" "OTA_FAIL:bound" "$v"; assert_rc "ota negative upload rc" 1 "$rc"
v=$(ol "$ota_begin" "upload accepted" "artifact sha256 verified: $ota_sha" "signature verified: false" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: negative signature prose is not a milestone" "OTA_FAIL:artifact_verified" "$v"; assert_rc "ota negative signature rc" 1 "$rc"
v=$(ol "$ota_begin" "artifact sha256 verified: $ota_sha" "upload accepted" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: reversed milestones fail ordering" "OTA_FAIL:order" "$v"; assert_rc "ota reversed rc" 1 "$rc"
v=$(ol "$ota_begin" "upload accepted" "OTA signature verified" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: omitted artifact proof fails ordering" "OTA_FAIL:order" "$v"; assert_rc "ota missing artifact rc" 1 "$rc"
bad_sha=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
v=$(ol "$ota_begin" "upload accepted" "artifact sha256 verified: $bad_sha" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: wrong artifact hash fails binding" "OTA_FAIL:artifact_mismatch" "$v"; assert_rc "ota bad hash rc" 1 "$rc"
v=$(ota_pass | accept_ota_verdict S9 am1-s9 "$bad_sha" "$ota_version"); rc=$?
assert_eq "ota: envelope bound to another expected hash fails" "OTA_FAIL:unbound" "$v"; assert_rc "ota expectation hash rc" 1 "$rc"
v=$(ota_pass | sed "s/version matches expected: $ota_version/version matches expected: wrong/" | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: wrong observed version fails binding" "OTA_FAIL:version_mismatch" "$v"; assert_rc "ota bad version rc" 1 "$rc"
v=$(ota_pass | sed '$d' | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: missing END envelope fails" "OTA_FAIL:end_missing" "$v"; assert_rc "ota missing end rc" 1 "$rc"
v=$({ ota_pass; printf '%s\n' "$ota_end"; } | accept_ota_verdict S9 am1-s9 "$ota_sha" "$ota_version"); rc=$?
assert_eq "ota: duplicate END envelope fails" "OTA_FAIL:envelope" "$v"; assert_rc "ota duplicate end rc" 1 "$rc"
v=$(ota_pass | accept_ota_verdict S9 am1-s9 '' "$ota_version"); rc=$?
assert_eq "ota: missing expected hash is a setup error" "OTA_FAIL:invalid_expectation" "$v"; assert_rc "ota missing expectation rc" 2 "$rc"

if [ "$fails" -ne 0 ]; then
    printf '\naccept_parse tests FAILED: %s assertion(s)\n' "$fails" >&2
    exit 1
fi
printf '\naccept_parse tests passed.\n'
