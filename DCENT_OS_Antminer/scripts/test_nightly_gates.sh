#!/bin/sh
# Explicit supplemental suites for the comprehensive nightly tier.
# Pytest runs both unittest and pytest-style files; direct Python execution
# would silently collect zero tests in the native_zynq_sd files.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."
FAIL_FAST=${1:-0}
case "$FAIL_FAST" in 0|1) ;; *) exit 2 ;; esac
python3 -c 'import pytest' || exit 1
failures=0
pass() { printf 'NIGHTLY PASS: %s\n' "$1"; }
fail() {
    failures=$((failures + 1))
    printf 'NIGHTLY FAIL: %s\n' "$1" >&2
    [ "$FAIL_FAST" -eq 0 ] || exit 1
}

# Full executable/process coverage belongs here; blocking keeps the fast typed
# closeout, shell restart and refusal suites without rebuilding the daemon.
if sh scripts/test_release_container_boundary.sh; then
    pass 'test_release_container_boundary.sh'
else
    fail 'test_release_container_boundary.sh'
fi
if native_assets=$(python3 scripts/held_assets.py --repo-root ../..) \
    && DCENT_HELD_ASSETS="$native_assets" python3 scripts/test_release_native_sd.py; then
    pass 'test_release_native_sd.py'
else
    fail 'test_release_native_sd.py'
fi
if native_assets=$(python3 scripts/held_assets.py --repo-root ../..) \
    && DCENT_HELD_ASSETS="$native_assets" python3 scripts/test_prepare_bm1396_sd_image.py; then
    pass 'test_prepare_bm1396_sd_image.py'
else
    fail 'test_prepare_bm1396_sd_image.py'
fi
if sh scripts/test_software_closeout_integration.sh; then
    pass 'test_software_closeout_integration.sh'
else
    fail 'test_software_closeout_integration.sh'
fi

# FIT archive checks need the held donor; blocking explicitly runs the four
# ordinary-file transaction/boot classes from the same module instead.
if python3 -m pytest -q scripts/test_am2_native_ota.py -k ExactFitTests; then
    pass 'test_am2_native_ota.py ExactFitTests'
else
    fail 'test_am2_native_ota.py ExactFitTests'
fi
# Complement the blocking module selection with its two held-input proofs.
if python3 -m pytest -q scripts/test_s19k_aml_install_safety.py -k 'test_held_78_bad_blocks_intersect_the_planned_root_window or test_held_mtd_utils_proves_padbad_nandwrite_mismatch'; then
    pass 'test_s19k_aml_install_safety.py held archive proofs'
else
    fail 'test_s19k_aml_install_safety.py held archive proofs'
fi
if python3 -m pytest -q scripts/first_install/test_build_am2_stock_recovery.py; then
    pass 'first_install/test_build_am2_stock_recovery.py'
else
    fail 'first_install/test_build_am2_stock_recovery.py'
fi
if python3 -m pytest -q scripts/test_am2_beta_image_policy.py; then
    pass 'test_am2_beta_image_policy.py'
else
    fail 'test_am2_beta_image_policy.py'
fi
if python3 -m pytest -q scripts/test_am2_fabric_boot.py; then
    pass 'test_am2_fabric_boot.py'
else
    fail 'test_am2_fabric_boot.py'
fi
if python3 -m pytest -q scripts/test_am2_s17_build_input.py; then
    pass 'test_am2_s17_build_input.py'
else
    fail 'test_am2_s17_build_input.py'
fi
if python3 -m pytest -q scripts/test_am3_bb_nand_window.py; then
    pass 'test_am3_bb_nand_window.py'
else
    fail 'test_am3_bb_nand_window.py'
fi
if python3 -m pytest -q scripts/test_amlogic_native_boot_profiles.py; then
    pass 'test_amlogic_native_boot_profiles.py'
else
    fail 'test_amlogic_native_boot_profiles.py'
fi
if python3 -m pytest -q scripts/test_bm1362_nopic_image.py; then
    pass 'test_bm1362_nopic_image.py'
else
    fail 'test_bm1362_nopic_image.py'
fi
if python3 -m pytest -q scripts/test_bm1362_nopic_storage.py; then
    pass 'test_bm1362_nopic_storage.py'
else
    fail 'test_bm1362_nopic_storage.py'
fi
if python3 -m pytest -q scripts/test_bm1396_boot_startup.py; then
    pass 'test_bm1396_boot_startup.py'
else
    fail 'test_bm1396_boot_startup.py'
fi
if python3 -m pytest -q scripts/test_bm1396_native_sd_early_init.py; then
    pass 'test_bm1396_native_sd_early_init.py'
else
    fail 'test_bm1396_native_sd_early_init.py'
fi
if python3 -m pytest -q scripts/test_bm1396_sd_ready.py; then
    pass 'test_bm1396_sd_ready.py'
else
    fail 'test_bm1396_sd_ready.py'
fi
if python3 -m pytest -q scripts/test_bm1396_sd_ssh.py; then
    pass 'test_bm1396_sd_ssh.py'
else
    fail 'test_bm1396_sd_ssh.py'
fi
if python3 -m pytest -q scripts/test_build_am2_first_install_capsule.py; then
    pass 'test_build_am2_first_install_capsule.py'
else
    fail 'test_build_am2_first_install_capsule.py'
fi
if python3 -m pytest -q scripts/test_build_am3_bb_nand_capsule.py; then
    pass 'test_build_am3_bb_nand_capsule.py'
else
    fail 'test_build_am3_bb_nand_capsule.py'
fi
if python3 -m pytest -q scripts/test_build_am3_bb_nand_recovery_media.py; then
    pass 'test_build_am3_bb_nand_recovery_media.py'
else
    fail 'test_build_am3_bb_nand_recovery_media.py'
fi
if python3 -m pytest -q scripts/test_build_am3_bb_recovery_kernel.py; then
    pass 'test_build_am3_bb_recovery_kernel.py'
else
    fail 'test_build_am3_bb_recovery_kernel.py'
fi
if python3 -m pytest -q scripts/test_build_am3_bb_recovery_runtime.py; then
    pass 'test_build_am3_bb_recovery_runtime.py'
else
    fail 'test_build_am3_bb_recovery_runtime.py'
fi
if python3 -m pytest -q scripts/test_build_am3_bbctrl_recovery_dtb.py; then
    pass 'test_build_am3_bbctrl_recovery_dtb.py'
else
    fail 'test_build_am3_bbctrl_recovery_dtb.py'
fi
if python3 -m pytest -q scripts/test_build_s19k_aml_transition_capsule.py; then
    pass 'test_build_s19k_aml_transition_capsule.py'
else
    fail 'test_build_s19k_aml_transition_capsule.py'
fi
if python3 -m pytest -q scripts/test_c43_boot_startup.py; then
    pass 'test_c43_boot_startup.py'
else
    fail 'test_c43_boot_startup.py'
fi
if python3 -m pytest -q scripts/test_c43_native_sd_early_init.py; then
    pass 'test_c43_native_sd_early_init.py'
else
    fail 'test_c43_native_sd_early_init.py'
fi
if python3 -m pytest -q scripts/test_c43_sd_ssh.py; then
    pass 'test_c43_sd_ssh.py'
else
    fail 'test_c43_sd_ssh.py'
fi
if python3 -m pytest -q scripts/test_check_markdown_links.py; then
    pass 'test_check_markdown_links.py'
else
    fail 'test_check_markdown_links.py'
fi
if python3 -m pytest -q scripts/test_classic_aml_application_proof.py; then
    pass 'test_classic_aml_application_proof.py'
else
    fail 'test_classic_aml_application_proof.py'
fi
if python3 -m pytest -q scripts/test_classic_aml_storage.py; then
    pass 'test_classic_aml_storage.py'
else
    fail 'test_classic_aml_storage.py'
fi
if python3 -m pytest -q scripts/test_classic_aml_upgrade_gate.py; then
    pass 'test_classic_aml_upgrade_gate.py'
else
    fail 'test_classic_aml_upgrade_gate.py'
fi
if python3 -m pytest -q scripts/test_cv1835_overlay_plan.py; then
    pass 'test_cv1835_overlay_plan.py'
else
    fail 'test_cv1835_overlay_plan.py'
fi
if python3 -m pytest -q scripts/test_daemon_supply_chain.py; then
    pass 'test_daemon_supply_chain.py'
else
    fail 'test_daemon_supply_chain.py'
fi
if python3 -m pytest -q scripts/test_dependency_age.py; then
    pass 'test_dependency_age.py'
else
    fail 'test_dependency_age.py'
fi
if python3 -m pytest -q scripts/test_extract_am2_s17_kernel.py; then
    pass 'test_extract_am2_s17_kernel.py'
else
    fail 'test_extract_am2_s17_kernel.py'
fi
if python3 -m pytest -q scripts/test_extract_s15_t15_bm1391_carrier.py; then
    pass 'test_extract_s15_t15_bm1391_carrier.py'
else
    fail 'test_extract_s15_t15_bm1391_carrier.py'
fi
if python3 -m pytest -q scripts/test_generate_sbom.py; then
    pass 'test_generate_sbom.py'
else
    fail 'test_generate_sbom.py'
fi
if python3 -m pytest -q scripts/test_mcp_token_mint.py; then
    pass 'test_mcp_token_mint.py'
else
    fail 'test_mcp_token_mint.py'
fi
if python3 -m pytest -q scripts/test_overlay_csrf_allowlist.py; then
    pass 'test_overlay_csrf_allowlist.py'
else
    fail 'test_overlay_csrf_allowlist.py'
fi
if python3 -m pytest -q scripts/test_persisted_network.py; then
    pass 'test_persisted_network.py'
else
    fail 'test_persisted_network.py'
fi
if python3 -m pytest -q scripts/test_prepare_bm1391_sd_boot.py; then
    pass 'test_prepare_bm1391_sd_boot.py'
else
    fail 'test_prepare_bm1391_sd_boot.py'
fi
if python3 -m pytest -q scripts/test_prepare_bm1391_sd_image.py; then
    pass 'test_prepare_bm1391_sd_image.py'
else
    fail 'test_prepare_bm1391_sd_image.py'
fi
if python3 -m pytest -q scripts/test_prepare_bm1396_sd_boot.py; then
    pass 'test_prepare_bm1396_sd_boot.py'
else
    fail 'test_prepare_bm1396_sd_boot.py'
fi
if python3 -m pytest -q scripts/test_prepare_c43_sd_image.py; then
    pass 'test_prepare_c43_sd_image.py'
else
    fail 'test_prepare_c43_sd_image.py'
fi
if python3 -m pytest -q scripts/test_prepare_classic_aml_install_candidate.py; then
    pass 'test_prepare_classic_aml_install_candidate.py'
else
    fail 'test_prepare_classic_aml_install_candidate.py'
fi
if python3 -m pytest -q scripts/test_prepare_classic_aml_private_beta.py; then
    pass 'test_prepare_classic_aml_private_beta.py'
else
    fail 'test_prepare_classic_aml_private_beta.py'
fi
if python3 -m pytest -q scripts/test_prepare_s9_variant_rootfs.py; then
    pass 'test_prepare_s9_variant_rootfs.py'
else
    fail 'test_prepare_s9_variant_rootfs.py'
fi
if python3 -m pytest -q scripts/test_s19jpro_enablement_workflow.py; then
    pass 'test_s19jpro_enablement_workflow.py'
else
    fail 'test_s19jpro_enablement_workflow.py'
fi
if python3 -m pytest -q scripts/test_s19jpro_lane_verify.py; then
    pass 'test_s19jpro_lane_verify.py'
else
    fail 'test_s19jpro_lane_verify.py'
fi
if python3 -m pytest -q scripts/test_s19k_aml_flash_transaction_sim.py; then
    pass 'test_s19k_aml_flash_transaction_sim.py'
else
    fail 'test_s19k_aml_flash_transaction_sim.py'
fi
if python3 -m pytest -q scripts/test_s19k_aml_stage1_audit.py; then
    pass 'test_s19k_aml_stage1_audit.py'
else
    fail 'test_s19k_aml_stage1_audit.py'
fi
if python3 -m pytest -q scripts/test_s19k_data_mount_owner.py; then
    pass 'test_s19k_data_mount_owner.py'
else
    fail 'test_s19k_data_mount_owner.py'
fi
if python3 -m pytest -q scripts/test_s19k_hermetic_host_preflight.py; then
    pass 'test_s19k_hermetic_host_preflight.py'
else
    fail 'test_s19k_hermetic_host_preflight.py'
fi
if python3 -m pytest -q scripts/test_s19k_hermetic_image_producer.py; then
    pass 'test_s19k_hermetic_image_producer.py'
else
    fail 'test_s19k_hermetic_image_producer.py'
fi
if python3 -m pytest -q scripts/test_s19k_hermetic_materialize_inner.py; then
    pass 'test_s19k_hermetic_materialize_inner.py'
else
    fail 'test_s19k_hermetic_materialize_inner.py'
fi
if python3 -m pytest -q scripts/test_s19k_hermetic_normalize_source_copy.py; then
    pass 'test_s19k_hermetic_normalize_source_copy.py'
else
    fail 'test_s19k_hermetic_normalize_source_copy.py'
fi
if python3 -m pytest -q scripts/test_s19k_hermetic_release_signer.py; then
    pass 'test_s19k_hermetic_release_signer.py'
else
    fail 'test_s19k_hermetic_release_signer.py'
fi
if python3 -m pytest -q scripts/test_s19k_install_custody_image_package.py; then
    pass 'test_s19k_install_custody_image_package.py'
else
    fail 'test_s19k_install_custody_image_package.py'
fi
if python3 -m pytest -q scripts/test_s19k_native_reproducibility_verify.py; then
    pass 'test_s19k_native_reproducibility_verify.py'
else
    fail 'test_s19k_native_reproducibility_verify.py'
fi
if python3 -m pytest -q scripts/test_s19k_postinstall_target_witness.py; then
    pass 'test_s19k_postinstall_target_witness.py'
else
    fail 'test_s19k_postinstall_target_witness.py'
fi
if python3 -m pytest -q scripts/test_s19k_release_gate.py; then
    pass 'test_s19k_release_gate.py'
else
    fail 'test_s19k_release_gate.py'
fi
if python3 -m pytest -q scripts/test_s19k_signing_ceremony.py; then
    pass 'test_s19k_signing_ceremony.py'
else
    fail 'test_s19k_signing_ceremony.py'
fi
if python3 -m pytest -q scripts/test_s19k_source_authority.py; then
    pass 'test_s19k_source_authority.py'
else
    fail 'test_s19k_source_authority.py'
fi
if python3 -m pytest -q scripts/test_s19k_tmp_deploy_safety.py; then
    pass 'test_s19k_tmp_deploy_safety.py'
else
    fail 'test_s19k_tmp_deploy_safety.py'
fi
if python3 -m pytest -q scripts/test_s19kpro_nopic_image.py; then
    pass 'test_s19kpro_nopic_image.py'
else
    fail 'test_s19kpro_nopic_image.py'
fi
if python3 -m pytest -q scripts/test_s19kpro_nopic_storage.py; then
    pass 'test_s19kpro_nopic_storage.py'
else
    fail 'test_s19kpro_nopic_storage.py'
fi
if python3 -m pytest -q scripts/test_s21_enablement_workflow.py; then
    pass 'test_s21_enablement_workflow.py'
else
    fail 'test_s21_enablement_workflow.py'
fi
if python3 -m pytest -q scripts/test_s21_lane_verify.py; then
    pass 'test_s21_lane_verify.py'
else
    fail 'test_s21_lane_verify.py'
fi
if python3 -m pytest -q scripts/test_safe_extract_am3_bb_payload.py; then
    pass 'test_safe_extract_am3_bb_payload.py'
else
    fail 'test_safe_extract_am3_bb_payload.py'
fi
if python3 -m pytest -q scripts/test_universal_onramp_workflow.py; then
    pass 'test_universal_onramp_workflow.py'
else
    fail 'test_universal_onramp_workflow.py'
fi
if python3 -m pytest -q scripts/test_update_job.py; then
    pass 'test_update_job.py'
else
    fail 'test_update_job.py'
fi
if python3 -m pytest -q scripts/test_update_observer.py; then
    pass 'test_update_observer.py'
else
    fail 'test_update_observer.py'
fi
if python3 -m pytest -q scripts/tests/test_firmware_support_registry.py; then
    pass 'tests/test_firmware_support_registry.py'
else
    fail 'tests/test_firmware_support_registry.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_assets.py; then
    pass 'tests/test_native_zynq_sd_assets.py'
else
    fail 'tests/test_native_zynq_sd_assets.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_boot.py; then
    pass 'tests/test_native_zynq_sd_boot.py'
else
    fail 'tests/test_native_zynq_sd_boot.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_data.py; then
    pass 'tests/test_native_zynq_sd_data.py'
else
    fail 'tests/test_native_zynq_sd_data.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_discovery_startup.py; then
    pass 'tests/test_native_zynq_sd_discovery_startup.py'
else
    fail 'tests/test_native_zynq_sd_discovery_startup.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_elf.py; then
    pass 'tests/test_native_zynq_sd_elf.py'
else
    fail 'tests/test_native_zynq_sd_elf.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_finalize.py; then
    pass 'tests/test_native_zynq_sd_finalize.py'
else
    fail 'tests/test_native_zynq_sd_finalize.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_prepare.py; then
    pass 'tests/test_native_zynq_sd_prepare.py'
else
    fail 'tests/test_native_zynq_sd_prepare.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_selector.py; then
    pass 'tests/test_native_zynq_sd_selector.py'
else
    fail 'tests/test_native_zynq_sd_selector.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_ssh.py; then
    pass 'tests/test_native_zynq_sd_ssh.py'
else
    fail 'tests/test_native_zynq_sd_ssh.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_startup.py; then
    pass 'tests/test_native_zynq_sd_startup.py'
else
    fail 'tests/test_native_zynq_sd_startup.py'
fi
if python3 -m pytest -q scripts/tests/test_native_zynq_sd_storage.py; then
    pass 'tests/test_native_zynq_sd_storage.py'
else
    fail 'tests/test_native_zynq_sd_storage.py'
fi

printf 'Supplemental nightly suites: %s failures.\n' "$failures"
[ "$failures" -eq 0 ]
