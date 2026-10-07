#!/bin/sh
# Real native startup has stock delays; keep it outside the ten-minute fast tier.
# All tests are host-only. Their pools bind loopback and verify real submissions.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$#:${1:-}" in
    0:)
        # --close prevents a surviving test child from retaining the build lock.
        # timeout covers compilation and execution, after lock acquisition.
        mkdir -p "$HOME/.cache/dcent-beta"
        exec flock --close "$HOME/.cache/dcent-beta/heavy.lock" \
            timeout --signal=TERM --kill-after=30s 2400s sh "$0" --under-lock
        ;;
    1:--under-lock) ;;
    *) echo "Usage: run_native_spine_tests.sh" >&2; exit 2 ;;
esac
cd "$SCRIPT_DIR/../dcentrald"
export RUSTUP_TOOLCHAIN=1.90.0
export CARGO_NET_OFFLINE=true

suite() {
    expected=$1
    shift
    inventory=$(cargo test --message-format=short --locked -j2 --features sim-hal "$@" -- --list)
    found=$(printf '%s\n' "$inventory" | awk '/: test$/ { n++ } END { print n+0 }')
    if [ "$found" -ne "$expected" ]; then
        printf 'ERROR: expected %s tests, found %s: %s\n' "$expected" "$found" "$*" >&2
        exit 1
    fi
    cargo test --message-format=short --locked -j2 --features sim-hal "$@" -- --include-ignored --test-threads=1
}

# These generic transport and host-tool tests are not counted as row owners.
suite 8 -p dcentrald-hal --lib platform::sim::chain::tests
suite 2 -p dcentrald --test beta_spine_inventory
suite 4 -p dcentrald --test host_sim_cli
suite 4 -p dcentrald --test host_sim_refusals
suite 11 -p dcentrald --test sim_s19pro_t2
bash "$SCRIPT_DIR/run_filtered_cargo_test.sh" --message-format=short --locked -j2 -p dcentrald-hal \
    --features sim-hal --lib -- platform::stock_bm1391 --include-ignored --test-threads=1

# The exact runner inventories each name before executing it, including ignored
# tests. Deleting/renaming any one row's test must fail this mandatory job.
# Scope names distinguish a full coordinator from the narrower real chain owner.
while read -r target scope exact; do
    printf 'NATIVE ROW: %s (%s)\n' "$target" "$scope"
    sh "$SCRIPT_DIR/run_exact_cargo_test.sh" "$exact" --message-format=short --locked -j2 \
        -p dcentrald --features sim-hal --bin dcentrald
done <<'ROWS'
am1-s9 chain-owner work_dispatcher::native_pool_tests::s9_native_chain_dispatcher_init_work_nonce_independent_pool
am1-s9i chain-owner work_dispatcher::native_pool_tests::s9i_native_chain_dispatcher_init_work_nonce_independent_pool
am1-s9j chain-owner work_dispatcher::native_pool_tests::s9j_native_chain_dispatcher_init_work_nonce_independent_pool
am1-s9se chain-owner c43_bm1393_mining::work::feeder_tests::s9se_c43_chain_init_work_nonce_independent_pool
am1-s9k chain-owner c43_bm1393_mining::work::feeder_tests::s9k_c43_chain_init_work_nonce_independent_pool
am1-s15 full-coordinator bm1391_mining::integration_tests::s15_full_native_init_work_nonce_independent_pool_submit_and_closeout
am1-t15 full-coordinator bm1391_mining::integration_tests::t15_full_native_init_work_nonce_independent_pool_submit_and_fan_fault_cutoff
am2-s17e full-coordinator bm1396_mining_work::runtime::integration_tests::s17e_actual_factory_startup_probes_pool_share_and_fixed_epoch_thermal_cutoff
am2-t17e full-coordinator bm1396_mining_work::runtime::integration_tests::actual_full_startup_worker_registry_pool_share_and_shared_terminal_receipt
am2-s17p chain-owner s17_hybrid_mining::native::chain_integration::s17_native_s17p_three_chains_init_and_independent_pool
am2-s17plus chain-owner s17_hybrid_mining::native::chain_integration::s17_native_s17plus_three_chains_init_and_independent_pool
am2-t17 chain-owner s17_hybrid_mining::native::chain_integration::s17_native_t17_three_chains_init_and_independent_pool
am2-t17plus chain-owner s17_hybrid_mining::native::chain_integration::s17_native_t17plus_three_chains_init_and_independent_pool
am2-s19pro adapter-owner s19_bm1398_native_mining::tests::s19pro_actual_adapter_init_fifo_nonce_independent_pool
am2-s19 adapter-owner s19_bm1398_native_mining::tests::s19_actual_adapter_init_fifo_nonce_independent_pool
am2-t19 adapter-owner s19_bm1398_native_mining::tests::t19_actual_adapter_init_fifo_nonce_independent_pool
am2-s19a adapter-owner s19_bm1398_native_mining::tests::s19a_actual_adapter_init_fifo_nonce_independent_pool
am2-s19plus adapter-owner s19_bm1398_native_mining::tests::s19plus_actual_adapter_init_fifo_nonce_independent_pool
am2-s19j chain-owner serial_mining::tests::modern_native_population_tests::am2_s19j_distinct_native_init_work_nonce_independent_pool
am3-bb-s19jpro chain-owner am3_bb_mining::tests::bb_s19jpro_factory_kernel_init_transport_nonce_independent_pool
am3-s19jpro-aml chain-owner serial_mining::classic_aml_runtime::tests::classic_aml_each_retained_route_init_work_nonce_independent_pool
am3-s19jproa chain-owner serial_mining::tests::modern_native_population_tests::am3_s19jproa_native_init_work_nonce_independent_pool
am3-s19jproplus chain-owner serial_mining::tests::modern_native_population_tests::am3_s19jproplus_native_init_work_nonce_independent_pool
am3-s19k chain-owner serial_mining::tests::modern_native_population_tests::s19k_exact_typed77_init_work_nonce_independent_pool
am3-s19xp chain-owner serial_mining::tests::modern_native_population_tests::am3_s19xp_native_init_work_nonce_independent_pool
am3-s19jxp chain-owner serial_mining::tests::modern_native_population_tests::am3_s19jxp_native_init_work_nonce_independent_pool
am3-s21 chain-owner serial_mining::tests::modern_native_population_tests::am3_s21_native_init_work_nonce_independent_pool
am3-s21pro chain-owner serial_mining::tests::modern_native_population_tests::am3_s21pro_native_init_work_nonce_independent_pool
am3-s21xp chain-owner serial_mining::tests::modern_native_population_tests::am3_s21xp_native_init_work_nonce_independent_pool
ROWS

# Refusal controls exercise the same owners without repeating long positive runs.
for selector in malformed_observed_eeprom_refuses_before_source_enable_or_work \
    modeled_transport_cannot_open_the_physical_gpio_boundary \
    s17_native_cold_chain_refuses_fifo_and_pll_faults_before_work \
    classic_aml_missing_assigned_chip_refuses_work_publication \
    s9_dispatcher_missing_or_mismatched_observed_population_refuses_before_work \
    c43_factory_pic_population_sensor_faults_refuse_normal_work_and_cut \
    am2_s19j_missing_assigned_chip_refuses_native_work \
    s19k_missing_assigned_population_refuses_typed77_work_transport \
    s19k_native_work_transport_refuses_reordered_routes \
    bb_bad_factory_crc_refuses_before_native_uart_initialization \
    actual_bm1398_adapter_factory_pic_and_population_faults_cut_before_work \
    injected_marker_requires_exact_image_fabric_slots_and_same_simulated_command_owner \
    bm1391_mining::custody::thermal_health_tests \
    bm1396_independent_pool_oracle_checks_both_complete_retained_headers \
    difficulty_one_oracle_refuses_hash_just_above_consensus_target; do
    bash "$SCRIPT_DIR/run_filtered_cargo_test.sh" --message-format=short --locked -j2 -p dcentrald \
        --features sim-hal --bin dcentrald -- "$selector" --include-ignored --test-threads=1
done
printf '%s\n' 'Every registered Beta row passed its native positive-path test.'
