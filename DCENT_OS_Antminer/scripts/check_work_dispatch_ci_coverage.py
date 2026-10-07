#!/usr/bin/env python3
"""Inventory + pin: WorkDispatchLifecycle engine tests must be CI-exact-wired.

Continuous-audit residual (2026-07-29): serial_mining (and hybrid/stock)
`work_dispatch_admission_tests` modules shipped pure lifecycle contracts for the
NO-SHIP work-dispatch admission wire, but none appeared under
`run_exact_cargo_test.sh` in the offline workflow / static inventory. Cargo
`--exact` with a missing selector can exit 0 with zero tests — only explicit
wiring + this pin keep the contracts on the commit path.

Also pins serial + hybrid `tests::` zero-orphan exact-wire ratchets (2026-07-29):
every unit under those modules must appear under `run_exact_cargo_test.sh`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PROJECT = REPO_ROOT / "projects" / "dcentos"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dcentos-offline-gates.yml"
STATIC_GATE = PROJECT / "scripts" / "ci_offline_gates.sh"
SERIAL_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "serial_mining.rs"
HYBRID_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "s19j_hybrid_mining.rs"
STOCK_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "stock_mining.rs"
DAEMON_SRC = PROJECT / "dcentrald" / "dcentrald" / "src" / "daemon.rs"

ENGINE_MODULES = (
    ("serial_mining", SERIAL_SRC),
    ("s19j_hybrid_mining", HYBRID_SRC),
    ("stock_mining", STOCK_SRC),
    # Standard FPGA daemon path (2026-07-29 constitution cycle): same pure
    # WorkDispatchLifecycle contract as stock/serial/hybrid.
    ("daemon", DAEMON_SRC),
)

# Extra serial_mining::tests contracts that must stay CI-wired (orphaned
# inventory 2026-07-29). Full orphan list is larger; these are safety/protocol
# tiers expanded in residual waves.
SERIAL_MUST_WIRE_UNDER_TESTS = (
    # L08 production job-ID selector, cursor and response decoder.
    "serial_job_id_steps_and_wrap_match_each_supported_family",
    "serial_job_id_rejects_unknown_chips_and_mismatched_xp_dialect",
    "bm1370_job_id_dispatch_cycle_round_trips_all_small_cores",
    # Protocol honesty (tier-1)
    "serial_rolled_version_reconstructs_when_pool_did_not_negotiate_mask",
    "serial_rolled_version_retains_full_field_for_later_pool_admission",
    # Native/PTY and complete-field BIP320 contracts are offline exact tests.
    "bm1362_aml_cold_parser_keeps_short_identity_separate_from_assigned_coverage",
    "bm1362_aml_native_actual_init_work_and_known_nonce_on_a_and_plus_ptys",
    "bm1362_aml_runtime_clock_and_hcn_share_all_three_uart_fences",
    "bm1366_xp_native_actual_init_work_and_known_nonce_on_xp_and_jxp_ptys",
    "bm1370_native_actual_init_work_and_known_nonce_on_pro_and_xp_ptys",
    "s21_native_selected_uart_work_and_genesis_nonce_round_trip",
    "serial_pool_version_checks_both_set_and_cleared_base_bits",
    "serial_pool_version_genesis_matches_the_actual_v1_wire_header",
    "serial_pool_version_leaves_bm1398_and_s19k_reconstruction_unchanged",
    "exact_am2_source_clears_stale_work_when_hash_on_disconnect_is_false",
    # Heartbeat / watchdog / terminal (tier-2, 2026-07-29)
    "bm1362_heartbeat_terminal_limit_precedes_short_watchdog_reset_windows",
    "bm1362_heartbeat_requires_supported_observed_dspic_firmware",
    "bm1362_heartbeat_failure_budget_is_bounded_and_success_resets_it",
    "nopic_fan_loop_disposition_is_terminal_for_every_revoked_state",
    "terminal_barrier_failure_consumes_no_safe_off_leg_before_retry",
    "s19k_rearm_write_failure_is_terminal_not_best_effort",
    "am2_never_energized_closeout_is_not_terminal_safe_off_evidence",
    # Admission / identity fail-closed (tier-2)
    "exact_am2_bm1362_refuses_unmonitored_uart_trans_routes",
    "validated_serial_admission_binds_exact_route_family_and_separate_geometry",
    "ambiguous_nopic_count_refuses_instead_of_guessing_a_pic_driver",
    "native_serial_voltage_identity_rejects_impossible_model_chip_pairs",
    # Airflow / actor / nonce / experimental admit (tier-3, 2026-07-29)
    "preenergize_airflow_envelope_reports_low_point_and_restore_failures_together",
    "preenergize_airflow_envelope_refuses_low_point_and_restores_maximum",
    "preenergize_airflow_envelope_proves_max_then_min_then_restores_max",
    "bm1362_nonce_safety_distinguishes_startup_midrun_and_disabled",
    "serial_actor_receiver_loss_and_three_read_errors_are_terminal",
    "native_serial_identity_never_comes_from_default_or_explicit_geometry",
    "am2_apw_stabilization_requires_live_actor_and_successful_progress",
    "serial_execution_terminal_rejects_late_physical_commit",
    "retained_single_owner_safe_off_legs_execute_all_pending_work_and_never_replay_success",
    "exact_serial_actor_freshness_rejects_queued_or_disconnected_required_exits",
    # Cancellation / bring-up / geometry / admission refuse (tier-4, 2026-07-29)
    "am2_bringup_wait_is_immediately_cancellation_aware",
    "am2_cancellation_refuses_every_subsequent_validated_serial_commit",
    "exact_am2_bringup_validates_before_consuming_power_boundary_authority",
    "bm1362_pool_disconnect_requires_announced_authority_and_uart_commit",
    "s19k_pool_disconnect_requires_prior_authority_and_physical_commit",
    "validated_serial_admission_rejects_family_cross_use_and_impossible_frame_envelope",
    "assigned_serial_geometry_requires_exact_unique_configured_address_coverage",
    "native_serial_geometry_requires_catalog_evidence_or_explicit_override",
    "native_serial_difficulty_requires_a_registered_profile",
    "serial_runtime_has_no_unbrokered_kernel_i2c_fd_or_ioctl_path",
    "unique_owner_installation_never_replaces_live_or_completed_custody",
    # Final offline-admissible residual batch (tier-5, 2026-07-29): fixtures,
    # identity classifiers, chip-family pins, AM3-BB parsers, actor/APW edges.
    # Inventory classified all 25 remaining orphans as offline unit tests —
    # none live-gated / evidence-exhausted.
    "am3_bb_uart_trans_chain_parser_accepts_deduped_ttyo_list",
    "am3_bb_uart_trans_chain_parser_accepts_single_ttyo_path",
    "am3_bb_uart_trans_chain_parser_rejects_unknown_or_empty_paths",
    "apw_bypass_and_unclassified_state_transitions_are_explicit",
    "bm1368_fixture_interval_agrees_with_the_general_ladder",
    "bm1370_and_bm1368_chip_ids_are_distinct_in_discriminator",
    "bm1370_serial_execution_requires_exact_experimental_chip_authority",
    "bm1398_fixture_validates_full_header_with_rolled_midstate",
    "bm1398_rejects_out_of_range_midstate_even_without_rolling",
    "bm1398_work_id_wraps_on_seven_bit_job_ring",
    "exact_am2_apw_applicability_is_explicit_and_unclassified_state_cannot_close",
    "exact_am2_bm1362_init_uses_constructor_plan_and_retained_observations",
    "exact_am2_power_boundary_remains_crossed_when_gpio_assertion_is_unknown",
    "exact_route_api_lifecycle_distinguishes_never_opened_from_opened_and_closed",
    "native_amlogic_serial_source_has_one_validated_write_and_shutdown_path",
    "nopic_family_classifier_matches_profile_table",
    "pic_enable_cmd_vnish_byte_exact",
    "pic_family_default_path_is_unchanged_for_non_nopic_units",
    "pinned_bm1370_model_wins_over_misleading_chip_count",
    "retired_bhb56_dspic_route_has_no_runtime_capability_surface",
    "s21pro_family_models_resolve_to_bm1370_not_bm1368",
    "serial_actor_distinguishes_empty_poll_liveness_from_committed_work",
    "serial_actor_mints_commit_evidence_only_after_successful_tx",
    "serial_address_ladder_is_unchanged_for_shipped_populations_and_safe_at_one_chip",
    "serial_share_fixture_keeps_target_and_achieved_difficulty_separate",
    # S19k Track-1 2026-08-15/16: industrial PLL policy + Braiins passthrough.
    "industrial_serial_pll_policy_is_exact_route_bound_and_fail_closed",
    "industrial_serial_pll_searches_enforce_vendor_vco_envelope",
    "s19k_braiins_bm1366_passthrough_opens_both_ttys",
    "s19k_braiins_bm1366_passthrough_uses_closed_21_36_builder",
    "live407_uart_vbits_hash_is_ticket_valid_not_434faee1",
    "wave425_post_clean_chain_inactive_sentinel_dispatches_before_work",
    #  (2026-08-19): live serial night-mode fan/frequency contracts.
    "serial_night_fan_apply_caps_home_and_safety",
    "serial_night_fan_path_publishes_watch_and_applies_helper",
    "serial_night_frequency_init_uses_shared_helper",
    "serial_night_frequency_midrun_enqueues_pll0_write",
    "active_capacity_frequency_requires_completed_serial_pll_write",
    #  aggregate drift: S19k actor publication/ordering contracts.
    "s19k_actor_publishes_ownership_only_after_physical_send",
    "s19k_actor_orders_physical_commit_before_following_rx",
    "s19k_actor_does_not_publish_failed_tx_and_receipts_partial_commit",
    "s19k_job_attribution_variants_preserve_retry_order_and_identity",
    "track1_watchdog_liveness_requires_fresh_complete_thermal_and_tach_proof",
    "track1_watchdog_sla_requires_exact_30_30_5",
    "nopic_panic_fans_coast_only_after_checked_cut",
    "s19k_clean_gate_uses_header_resolved_attribution",
    "s19k_partial_receipt_cannot_publish_global_ownership",
    "s19k_runtime_drains_actor_events_before_terminal_exit",
    "track1_closeout_source_fences_panic_planned_stop_and_question_mark_exits",
    "track1_watchdog_accepts_only_positive_armed_admission",
    "track1_bosminer_identity_binds_pid_start_comm_and_executable",
    # Post- S19k exact execution, attribution, watchdog, and live
    # identity contracts. Keep every new serial_mining::tests unit exact-wired.
    "s19k_endpoint_observability_keeps_raw_frame_and_valid_nonce_clocks_distinct",
    "s19k_multi_uart_actor_io_is_bound_to_exact_execution_fence",
    "s19k_share_result_sidecar_bounds_history_and_counts_eviction",
    "s19k_share_result_sidecar_consumes_exact_payload_once",
    "s19k_track1_route_is_distinct_fenced_and_api_denied",
    "s19k_watchdog_requires_recent_history_admitted_nonce_on_every_active_tx_path",
    "s19k_wrap_epoch_advances_only_in_physical_commit_consumer",
    "s19k_stale_epoch_commit_retires_under_present_authority",
    "track1_live_identity_command_is_bounded_and_reaps_a_hung_probe",
    "track1_live_identity_parsers_pin_cpu_mtd_and_profile_aware_v2_transcripts",
    "track1_live_identity_reader_refuses_symlink_and_oversize_file",
    "track1_live_model_accepts_902_903_mix_and_refuses_invalid_shapes",
    "track1_live_profiles_refuse_all_non_exact_eeprom_populations",
    # Native S19k production-owner route: exact population subset, cold-init
    # ownership, evidence freshness, cooling, and panic-closeout isolation.
    "bm1366_native_cold_executor_is_exact_multi_uart_and_owner_gated",
    "bm1366_native_post_baud_admission_requires_exact_host_pair_and_fresh_geometry",
    "bm1366_native_route_requires_configured_request_then_evidence_joined",
    "s19k_native_cold_start_opt_in_is_strict_and_never_the_token_issuer",
    "s19k_native_cooling_pins_all_four_channels_at_2000_rpm",
    "s19k_native_mapping_and_panic_closeout_are_not_generic_nopic",
    "s19k_native_owner_timeline_rejects_stale_pre_and_post_evidence",
    "s19k_native_route_requires_an_exact_ordered_population_subset",
    # S19k office Gauntlet: every newly added authority, no-work, bounded-work,
    # endurance, custody, and inherited-rail contract stays exact-wired.
    "s19k_bounded_work_cli_must_match_the_immutable_runtime_binding",
    "s19k_bounded_work_completion_requires_every_required_uart",
    "s19k_bounded_work_incomplete_closeout_is_a_terminal_error",
    "s19k_bounded_work_rx_evidence_reconstructs_the_complete_wire_frame",
    "s19k_endurance_segments_use_interval_not_lifetime_hashrate",
    "s19k_endurance_work_cli_must_match_the_immutable_runtime_binding",
    "s19k_guarded_unlink_durable_replace_is_ordered_and_crash_resumable",
    "s19k_guarded_unlink_is_inode_bound_and_crash_resumable",
    "s19k_guarded_unlink_rejects_symlink_type_mode_and_owner",
    "s19k_no_work_actor_refuses_any_queued_uart_transmit",
    "s19k_no_work_cli_must_match_the_immutable_runtime_binding",
    "s19k_production_endurance_never_grants_itself_bounded_bench_completion",
    "track1_inherited_unread_voltage_is_published_as_unknown",
    "track1_j3_is_exact_kernel_all_thread_authority",
    # S19k attempt-7..10 waves (paced ladder, coverage retry/re-enrollment,
    # salvage plan-prefix window, bounded-proof duplicate-RX credit,
    # wrap-retired no-clean session): zero-orphan ratchet repair 2026-08-29.
    "s19k_bounded_proof_credits_duplicate_rx_paths_on_pool_accept",
    "s19k_coverage_denial_detail_renders_duplicate_and_off_plan_addresses",
    "s19k_missing_plan_addresses_diffs_and_refuses_off_plan_windows",
    "s19k_salvage_plan_prefix_window_accepts_exact_plan_with_unparseable_tail",
    "s19k_salvage_plan_prefix_window_never_hides_a_parseable_tail_frame",
    "s19k_salvage_plan_prefix_window_refuses_bad_frame_inside_the_plan",
    "s19k_salvage_plan_prefix_window_refuses_non_rejected_error_kinds",
    "s19k_salvage_plan_prefix_window_replays_attempt9_tty_s1_coverage_windows",
    "s19k_track1_address_ladder_paces_each_set_address_step_like_the_stock_jig",
    "s19k_track1_coverage_retry_reenrolls_unclaimed_plan_addresses_before_next_probe",
    "s19k_track1_duplicate_rx_share_credit_requires_submitted_or_accepted_share",
    "s19k_track1_wrap_retired_no_clean_submit_allows_only_never_cleaned_sessions",
    # 2026-08-29 shared-contract rebase: the settled S19k Track-1 path now
    # delegates its re-enrollment diff and mints the shared coverage
    # certificate; these two pins keep that rebasing exact-wired.
    "track1_reenrollment_and_coverage_back_onto_the_shared_serial_chain_contract",
    "track1_ladder_cadence_is_representable_in_the_shared_paced_policy",
    # 2026-08-31 full-line-beta Phase 0: the S19k install-custody terminal
    # contracts added to serial_mining::tests must stay exact-wired under CI.
    "install_custody_is_a_pre_uart_gpio437_only_terminal_composition",
    "install_custody_panic_and_receipt_contracts_remain_cut_only",
    "install_custody_receipt_contract_rejects_both_mode_mismatches",
    "s19k_install_custody_cli_must_match_the_immutable_runtime_binding",
)

EXACT_PREFIX = "sh ../scripts/run_exact_cargo_test.sh "
_TEST_FN = re.compile(
    r"#\[(?:\w+::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)",
    re.MULTILINE,
)
_MOD_BODY = re.compile(
    r"mod work_dispatch_admission_tests\s*\{",
    re.MULTILINE,
)


def extract_brace_body(text: str, open_brace_index: int) -> str:
    """Return text inside `{...}` starting at open_brace_index (the `{`)."""
    if open_brace_index < 0 or open_brace_index >= len(text) or text[open_brace_index] != "{":
        raise ValueError("open_brace_index must point at '{'")
    depth = 0
    i = open_brace_index
    in_str: str | None = None
    in_line_comment = False
    in_block = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block:
            if c == "*" and n == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c == "/" and n == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and n == "*":
            in_block = True
            i += 2
            continue
        if c in "\"'":
            in_str = c
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_index + 1 : i]
        i += 1
    raise ValueError("unbalanced braces extracting module body")


def work_dispatch_tests_in_source(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = _MOD_BODY.search(text)
    if not match:
        raise SystemExit(f"missing work_dispatch_admission_tests in {path}")
    brace = text.find("{", match.start())
    body = extract_brace_body(text, brace)
    return _TEST_FN.findall(body)


def required_work_dispatch_selectors() -> list[str]:
    selectors: list[str] = []
    for engine, path in ENGINE_MODULES:
        if not path.is_file():
            raise SystemExit(f"missing engine source: {path}")
        for name in work_dispatch_tests_in_source(path):
            selectors.append(f"{engine}::work_dispatch_admission_tests::{name}")
    return selectors


def required_serial_must_wire_selectors() -> list[str]:
    return [
        f"serial_mining::tests::{name}" for name in SERIAL_MUST_WIRE_UNDER_TESTS
    ]


def all_required_selectors() -> list[str]:
    return required_work_dispatch_selectors() + required_serial_must_wire_selectors()


def extract_exact_commands(path: Path) -> list[str]:
    found: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        start = raw.find(EXACT_PREFIX)
        if start < 0:
            continue
        command = raw[start:].strip()
        if command.endswith("\\"):
            command = command[:-1].rstrip()
        command = command.strip("'\"")
        found.append(command)
    return found


def selectors_from_commands(commands: list[str]) -> set[str]:
    out: set[str] = set()
    for command in commands:
        # sh ../scripts/run_exact_cargo_test.sh SELECTOR --locked ...
        rest = command[len(EXACT_PREFIX) :].strip()
        selector = rest.split()[0] if rest else ""
        if selector:
            out.add(selector)
    return out


def inventory_engine_tests_under_tests_mod(src: Path) -> list[str]:
    """Test fn names inside `mod tests { ... }` only (sibling modules excluded)."""
    text = src.read_text(encoding="utf-8")
    marker = "\n#[cfg(test)]\nmod tests {"
    start = text.find(marker)
    if start < 0:
        return []
    brace = text.find("{", start)
    # Stop at sibling work_dispatch module if present (column-0 sibling after tests).
    wd = text.find("\n#[cfg(test)]\nmod work_dispatch_admission_tests {")
    if wd > brace:
        body = text[brace + 1 : wd]
    else:
        body = extract_brace_body(text, brace)
    return _TEST_FN.findall(body)


def inventory_serial_tests_under_tests_mod() -> list[str]:
    return inventory_engine_tests_under_tests_mod(SERIAL_SRC)


def inventory_hybrid_tests_under_tests_mod() -> list[str]:
    return inventory_engine_tests_under_tests_mod(HYBRID_SRC)


def check_coverage(
    workflow_path: Path = WORKFLOW,
    static_path: Path = STATIC_GATE,
) -> list[str]:
    failures: list[str] = []
    required = all_required_selectors()
    if len(required) < 30:
        failures.append(
            f"expected ≥30 work-dispatch selectors across 4 engines (+serial must-wire), got {len(required)}"
        )

    wf_cmds = extract_exact_commands(workflow_path)
    st_cmds = extract_exact_commands(static_path)
    wf_sel = selectors_from_commands(wf_cmds)
    st_sel = selectors_from_commands(st_cmds)

    for selector in required:
        cmd_fragment = f"{EXACT_PREFIX}{selector} "
        # Allow end-of-line without trailing space after selector args start
        in_wf = any(
            c.startswith(f"{EXACT_PREFIX}{selector} ")
            or c.startswith(f"{EXACT_PREFIX}{selector}\t")
            or c == f"{EXACT_PREFIX}{selector}"
            or f"{EXACT_PREFIX}{selector} --" in c
            for c in wf_cmds
        )
        in_st = any(
            c.startswith(f"{EXACT_PREFIX}{selector} ")
            or c.startswith(f"{EXACT_PREFIX}{selector}\t")
            or c == f"{EXACT_PREFIX}{selector}"
            or f"{EXACT_PREFIX}{selector} --" in c
            for c in st_cmds
        )
        if not in_wf:
            failures.append(f"workflow missing exact selector: {selector}")
        if not in_st:
            failures.append(f"static inventory missing exact selector: {selector}")
        # Prefer also present in set for messaging
        _ = cmd_fragment, wf_sel, st_sel

    # Inventory honesty: every serial_mining::tests unit must be exact-wired
    # (tier-5 closed 2026-07-29). New tests without CI wire fail closed.
    under_tests = inventory_serial_tests_under_tests_mod()
    wired_tests = {
        s.removeprefix("serial_mining::tests::")
        for s in wf_sel
        if s.startswith("serial_mining::tests::")
    }
    orphans = sorted(set(under_tests) - wired_tests)
    # Always print inventory for residual ledger consumers.
    print(
        f"serial_mining::tests inventory: total={len(under_tests)} "
        f"wired_exact={len(wired_tests & set(under_tests))} "
        f"orphans={len(orphans)}"
    )
    print(
        f"work_dispatch must-wire selectors: {len(required_work_dispatch_selectors())}"
    )
    print(
        f"serial must-wire under tests:: : {len(SERIAL_MUST_WIRE_UNDER_TESTS)}"
    )
    if orphans:
        preview = ", ".join(orphans[:8])
        more = "" if len(orphans) <= 8 else f" (+{len(orphans) - 8} more)"
        failures.append(
            f"serial_mining::tests has {len(orphans)} unwired exact-selector "
            f"orphans (add to offline-gates + SERIAL_MUST_WIRE_UNDER_TESTS): "
            f"{preview}{more}"
        )
    # SERIAL_MUST_WIRE is the tiered residual list (subset); pre-wired historical
    # contracts need not re-list here. Require the tier list ⊆ inventory ∩ CI.
    unknown_must = sorted(set(SERIAL_MUST_WIRE_UNDER_TESTS) - set(under_tests))
    if unknown_must:
        failures.append(
            f"SERIAL_MUST_WIRE_UNDER_TESTS names not in serial_mining::tests: "
            f"{', '.join(unknown_must[:8])}"
        )

    # Hybrid tests:: zero-orphan ratchet (2026-07-29 continuous-audit).
    hybrid_under = inventory_hybrid_tests_under_tests_mod()
    hybrid_wired = {
        s.removeprefix("s19j_hybrid_mining::tests::")
        for s in wf_sel
        if s.startswith("s19j_hybrid_mining::tests::")
    }
    hybrid_orphans = sorted(set(hybrid_under) - hybrid_wired)
    print(
        f"s19j_hybrid_mining::tests inventory: total={len(hybrid_under)} "
        f"wired_exact={len(hybrid_wired & set(hybrid_under))} "
        f"orphans={len(hybrid_orphans)}"
    )
    if hybrid_orphans:
        preview = ", ".join(hybrid_orphans[:8])
        more = (
            ""
            if len(hybrid_orphans) <= 8
            else f" (+{len(hybrid_orphans) - 8} more)"
        )
        failures.append(
            f"s19j_hybrid_mining::tests has {len(hybrid_orphans)} unwired "
            f"exact-selector orphans (add to offline-gates): {preview}{more}"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    _ = argv  # reserved
    try:
        failures = check_coverage()
    except SystemExit as exc:
        print(f"check_work_dispatch_ci_coverage: FAIL {exc}", file=sys.stderr)
        return 1
    if failures:
        print("check_work_dispatch_ci_coverage: FAIL", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("check_work_dispatch_ci_coverage: PASS")
    print(f"  required_selectors={len(all_required_selectors())}")
    engines = ",".join(name for name, _ in ENGINE_MODULES)
    print(f"  engines={engines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
