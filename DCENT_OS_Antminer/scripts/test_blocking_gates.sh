#!/bin/sh
# Blocking offline behavior and safety tests. Every suite has an explicit call.
# No full Cargo workspace build, restricted-input cross build, or receipt corpus.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."
FAIL_FAST=${1:-0}
case "$FAIL_FAST" in 0|1) ;; *) echo "Usage: $0 [0|1 (fail fast)]" >&2; exit 2 ;; esac
[ "$#" -le 1 ] || { echo "ERROR: unexpected blocking arguments" >&2; exit 2; }
started=$(date +%s)
passed=0
failures=0
failed_suites=''

pass() {
    # Some legacy children exit zero when a prerequisite is absent. A blocking
    # suite must execute its tests; never turn their skip/zero-test summaries
    # into a green gate just because the child returned zero.
    if printf '%s\n' "$suite_output" | grep -Eq '(^SKIP:|^OK \(skipped=[1-9]|(^|, )[1-9][0-9]* skipped|^PASS: .*\(skipped\)|^Ran 0 tests)'; then
        printf 'ERROR: blocking suite did not execute all selected tests: %s\n' "$1" >&2
        fail "$1"
        return
    fi
    passed=$((passed + 1))
    printf 'BLOCKING PASS: %s\n' "$1"
}
fail() {
    failures=$((failures + 1))
    failed_suites="$failed_suites $1"
    printf '%s\n' "$suite_output" >&2
    printf 'BLOCKING FAIL: %s\n' "$1" >&2
    [ "$FAIL_FAST" -eq 0 ] || exit 1
}

# Required behavior must execute: a missing utility is an error, never a skip.
[ "$(uname -s)" = Linux ] || { echo "ERROR: blocking gates require Linux (WSL on Windows)." >&2; exit 1; }
for prerequisite in python3 sh bash cc cargo rustup flock openssl busybox fw_setenv fw_printenv git awk sed grep tar sha256sum od tail; do
    command -v "$prerequisite" >/dev/null 2>&1 || {
        printf 'ERROR: blocking prerequisite is missing: %s\n' "$prerequisite" >&2
        exit 1
    }
done
busybox ash -c ':' || exit 1
python3 -c 'import sys, pytest; assert sys.version_info >= (3, 10)' || exit 1

# Signing and signed publication admission
if suite_output=$(python3 scripts/test_release_build_identity.py 2>&1); then
    pass 'test_release_build_identity.py'
else
    fail 'test_release_build_identity.py'
fi
if suite_output=$(python3 scripts/test_release_dashboard.py 2>&1); then
    pass 'test_release_dashboard.py'
else
    fail 'test_release_dashboard.py'
fi
if suite_output=$(python3 scripts/test_release_input_profiles.py 2>&1); then
    pass 'test_release_input_profiles.py'
else
    fail 'test_release_input_profiles.py'
fi
if suite_output=$(python3 scripts/test_release_producer.py 2>&1); then
    pass 'test_release_producer.py'
else
    fail 'test_release_producer.py'
fi
if suite_output=$(python3 scripts/test_release_runtime_exports.py 2>&1); then
    pass 'test_release_runtime_exports.py'
else
    fail 'test_release_runtime_exports.py'
fi
if suite_output=$(python3 scripts/test_prepare_release_am2_boot.py 2>&1); then
    pass 'test_prepare_release_am2_boot.py'
else
    fail 'test_prepare_release_am2_boot.py'
fi
if suite_output=$(python3 scripts/test_release_stage_boot.py 2>&1); then
    pass 'test_release_stage_boot.py'
else
    fail 'test_release_stage_boot.py'
fi
if suite_output=$(sh scripts/test_release_am2_boot_reproduction.sh 2>&1); then
    pass 'test_release_am2_boot_reproduction.sh'
else
    fail 'test_release_am2_boot_reproduction.sh'
fi
if suite_output=$(python3 scripts/test_current_bm1398_sd_profiles.py 2>&1); then
    pass 'test_current_bm1398_sd_profiles.py'
else
    fail 'test_current_bm1398_sd_profiles.py'
fi
if suite_output=$(python3 scripts/test_shared_post_image.py 2>&1); then
    pass 'test_shared_post_image.py'
else
    fail 'test_shared_post_image.py'
fi
if suite_output=$(python3 scripts/test_runtime_policy_provision.py 2>&1); then
    pass 'test_runtime_policy_provision.py'
else
    fail 'test_runtime_policy_provision.py'
fi
if suite_output=$(python3 scripts/test_runtime_image_manifest.py 2>&1); then
    pass 'test_runtime_image_manifest.py'
else
    fail 'test_runtime_image_manifest.py'
fi
if suite_output=$(sh scripts/test_sd_signing_gate_static.sh 2>&1); then
    pass 'test_sd_signing_gate_static.sh'
else
    fail 'test_sd_signing_gate_static.sh'
fi
if suite_output=$(sh scripts/test_sign_sd_image.sh 2>&1); then
    pass 'test_sign_sd_image.sh'
else
    fail 'test_sign_sd_image.sh'
fi
if suite_output=$(sh scripts/test_sign_release_artifact.sh 2>&1); then
    pass 'test_sign_release_artifact.sh'
else
    fail 'test_sign_release_artifact.sh'
fi
if suite_output=$(sh scripts/test_sign_stock_manifest.sh 2>&1); then
    pass 'test_sign_stock_manifest.sh'
else
    fail 'test_sign_stock_manifest.sh'
fi
if suite_output=$(sh scripts/test_release_signing_authority.sh 2>&1); then
    pass 'test_release_signing_authority.sh'
else
    fail 'test_release_signing_authority.sh'
fi
if suite_output=$(sh scripts/test_host_path_text.sh 2>&1); then
    pass 'test_host_path_text.sh'
else
    fail 'test_host_path_text.sh'
fi
if suite_output=$(sh scripts/test_verify_sysupgrade_signature.sh 2>&1); then
    pass 'test_verify_sysupgrade_signature.sh'
else
    fail 'test_verify_sysupgrade_signature.sh'
fi
if suite_output=$(sh scripts/test_release_image_provision.sh 2>&1); then
    pass 'test_release_image_provision.sh'
else
    fail 'test_release_image_provision.sh'
fi
if suite_output=$(sh scripts/test_release_posture_default.sh 2>&1); then
    pass 'test_release_posture_default.sh'
else
    fail 'test_release_posture_default.sh'
fi
if suite_output=$(sh scripts/test_public_artifact_release_gate.sh 2>&1); then
    pass 'test_public_artifact_release_gate.sh'
else
    fail 'test_public_artifact_release_gate.sh'
fi
if suite_output=$(bash scripts/test_release_train.sh 2>&1); then
    pass 'test_release_train.sh'
else
    fail 'test_release_train.sh'
fi
if suite_output=$(bash scripts/test_release_capsule_target_policy.sh 2>&1); then
    pass 'test_release_capsule_target_policy.sh'
else
    fail 'test_release_capsule_target_policy.sh'
fi

# Executed boot, identity, SafeOff and restart negatives
if suite_output=$(cargo +1.90.0 test --offline --locked -j2 --manifest-path dcentrald/Cargo.toml -p dcentrald-common --lib runtime_policy 2>&1); then
    pass 'dcentrald-common runtime_policy'
else
    fail 'dcentrald-common runtime_policy'
fi
if suite_output=$(cargo +1.90.0 test --offline --locked -j2 --manifest-path dcentrald/Cargo.toml -p dcentrald-common --lib mutation_disposition:: 2>&1); then
    pass 'dcentrald-common mutation_disposition'
else
    fail 'dcentrald-common mutation_disposition'
fi
if suite_output=$(sh scripts/test_amlogic_identity_guard.sh 2>&1); then
    pass 'test_amlogic_identity_guard.sh'
else
    fail 'test_amlogic_identity_guard.sh'
fi
if suite_output=$(sh scripts/test_dcentrald_crash_restart_policy.sh 2>&1); then
    pass 'test_dcentrald_crash_restart_policy.sh'
else
    fail 'test_dcentrald_crash_restart_policy.sh'
fi
if suite_output=$(sh scripts/test_amlogic_boot_safe_state.sh 2>&1); then
    pass 'test_amlogic_boot_safe_state.sh'
else
    fail 'test_amlogic_boot_safe_state.sh'
fi
if suite_output=$(python3 scripts/test_amlogic_gpio437_policy.py 2>&1); then
    pass 'test_amlogic_gpio437_policy.py'
else
    fail 'test_amlogic_gpio437_policy.py'
fi
if suite_output=$(cargo +1.90.0 test --offline --locked -j2 --manifest-path dcentrald/Cargo.toml -p dcentrald-common --lib amlogic_gpio437:: 2>&1); then
    pass 'dcentrald-common amlogic_gpio437'
else
    fail 'dcentrald-common amlogic_gpio437'
fi
if suite_output=$(python3 scripts/test_s21_boot_polarity.py 2>&1); then
    pass 'test_s21_boot_polarity.py'
else
    fail 'test_s21_boot_polarity.py'
fi
# The two held archive/captured-dmesg proofs run explicitly in nightly.
# All ordinary-file install/backup/identity/restore behavior runs here.
if suite_output=$(python3 -m pytest -q scripts/test_s19k_aml_install_safety.py -k 'not test_held_78_bad_blocks_intersect_the_planned_root_window and not test_held_mtd_utils_proves_padbad_nandwrite_mismatch' 2>&1); then
    pass 'test_s19k_aml_install_safety.py'
else
    fail 'test_s19k_aml_install_safety.py'
fi
if suite_output=$(python3 scripts/test_media_gate_delegates.py 2>&1); then
    pass 'test_media_gate_delegates.py'
else
    fail 'test_media_gate_delegates.py'
fi

# Commit health and rollback authority
if suite_output=$(sh scripts/test_s99_health_verdict.sh 2>&1); then
    pass 'test_s99_health_verdict.sh'
else
    fail 'test_s99_health_verdict.sh'
fi
if suite_output=$(sh scripts/test_s99upgrade_failed_health_no_commit.sh 2>&1); then
    pass 'test_s99upgrade_failed_health_no_commit.sh'
else
    fail 'test_s99upgrade_failed_health_no_commit.sh'
fi
if suite_output=$(sh scripts/test_s99upgrade_commit_refusals.sh 2>&1); then
    pass 'test_s99upgrade_commit_refusals.sh'
else
    fail 'test_s99upgrade_commit_refusals.sh'
fi
if suite_output=$(sh scripts/test_s99upgrade_ssh_soft_pass.sh 2>&1); then
    pass 'test_s99upgrade_ssh_soft_pass.sh'
else
    fail 'test_s99upgrade_ssh_soft_pass.sh'
fi
if suite_output=$(sh scripts/test_ota_version_monotonicity.sh 2>&1); then
    pass 'test_ota_version_monotonicity.sh'
else
    fail 'test_ota_version_monotonicity.sh'
fi
if suite_output=$(sh scripts/test_legacy_boot_env_writer_containment.sh 2>&1); then
    pass 'test_legacy_boot_env_writer_containment.sh'
else
    fail 'test_legacy_boot_env_writer_containment.sh'
fi
if suite_output=$(sh scripts/test_s9_restore_containment.sh 2>&1); then
    pass 'test_s9_restore_containment.sh'
else
    fail 'test_s9_restore_containment.sh'
fi
if suite_output=$(sh scripts/test_amlogic_uninstall_containment.sh 2>&1); then
    pass 'test_amlogic_uninstall_containment.sh'
else
    fail 'test_amlogic_uninstall_containment.sh'
fi

# Package, transaction, storage and fw_setenv boundaries
if suite_output=$(sh scripts/test_sysupgrade_packaging_static.sh --blocking 2>&1); then
    pass 'test_sysupgrade_packaging_static.sh'
else
    fail 'test_sysupgrade_packaging_static.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_resource_ledger.sh 2>&1); then
    pass 'test_sysupgrade_resource_ledger.sh'
else
    fail 'test_sysupgrade_resource_ledger.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_mount_identity.sh 2>&1); then
    pass 'test_sysupgrade_mount_identity.sh'
else
    fail 'test_sysupgrade_mount_identity.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_ubi_volume_plan.sh 2>&1); then
    pass 'test_sysupgrade_ubi_volume_plan.sh'
else
    fail 'test_sysupgrade_ubi_volume_plan.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_package_input.sh 2>&1); then
    pass 'test_sysupgrade_package_input.sh'
else
    fail 'test_sysupgrade_package_input.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_persistent_state.sh 2>&1); then
    pass 'test_sysupgrade_persistent_state.sh'
else
    fail 'test_sysupgrade_persistent_state.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_transaction_lock.sh 2>&1); then
    pass 'test_sysupgrade_transaction_lock.sh'
else
    fail 'test_sysupgrade_transaction_lock.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_transaction_workspace.sh 2>&1); then
    pass 'test_sysupgrade_transaction_workspace.sh'
else
    fail 'test_sysupgrade_transaction_workspace.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_ubi_identity.sh 2>&1); then
    pass 'test_sysupgrade_ubi_identity.sh'
else
    fail 'test_sysupgrade_ubi_identity.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_ubi_node.sh 2>&1); then
    pass 'test_sysupgrade_ubi_node.sh'
else
    fail 'test_sysupgrade_ubi_node.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_uboot_env_admission.sh 2>&1); then
    pass 'test_sysupgrade_uboot_env_admission.sh'
else
    fail 'test_sysupgrade_uboot_env_admission.sh'
fi
if suite_output=$(sh scripts/test_sysupgrade_signal_exit.sh 2>&1); then
    pass 'test_sysupgrade_signal_exit.sh'
else
    fail 'test_sysupgrade_signal_exit.sh'
fi
if suite_output=$(sh scripts/test_zynq_sysupgrade_geometry.sh 2>&1); then
    pass 'test_zynq_sysupgrade_geometry.sh'
else
    fail 'test_zynq_sysupgrade_geometry.sh'
fi
if suite_output=$(python3 scripts/test_am2_native_ota.py NativeTransactionTests PreparedJobBindingTests ExecutedEnvironmentCommitTests ExecutedNativeBootTests 2>&1); then
    pass 'test_am2_native_ota.py'
else
    fail 'test_am2_native_ota.py'
fi

# Production source guards and their negative controls
if suite_output=$(python3 scripts/test_release_channel_feed.py 2>&1); then
    pass 'test_release_channel_feed.py'
else
    fail 'test_release_channel_feed.py'
fi
if suite_output=$(python3 scripts/test_channel_build_config.py 2>&1); then
    pass 'test_channel_build_config.py'
else
    fail 'test_channel_build_config.py'
fi
if suite_output=$(sh scripts/test_channel_feed.sh 2>&1); then
    pass 'test_channel_feed.py'
else
    fail 'test_channel_feed.py'
fi

if suite_output=$(python3 scripts/test_reset_settings.py 2>&1); then
    pass 'test_reset_settings.py'
else
    fail 'test_reset_settings.py'
fi
if suite_output=$(python3 scripts/test_provision_recovery_defaults.py 2>&1); then
    pass 'test_provision_recovery_defaults.py'
else
    fail 'test_provision_recovery_defaults.py'
fi
if suite_output=$(python3 scripts/test_am3_rootfs_dhcp.py 2>&1); then
    pass 'test_am3_rootfs_dhcp.py'
else
    fail 'test_am3_rootfs_dhcp.py'
fi

if suite_output=$(python3 scripts/check_lab_env_reads.py 2>&1); then
    pass 'check_lab_env_reads.py'
else
    fail 'check_lab_env_reads.py'
fi
if suite_output=$(python3 scripts/test_lab_env_reads.py 2>&1); then
    pass 'test_lab_env_reads.py'
else
    fail 'test_lab_env_reads.py'
fi
if suite_output=$(python3 scripts/test_blocking_source_guards.py 2>&1); then
    pass 'test_blocking_source_guards.py'
else
    fail 'test_blocking_source_guards.py'
fi
if suite_output=$(python3 scripts/check_i2c_transaction_labeling.py --self-test 2>&1); then
    pass 'check_i2c_transaction_labeling.py'
else
    fail 'check_i2c_transaction_labeling.py'
fi
if suite_output=$(python3 scripts/check_no_orphan_power_backends.py 2>&1); then
    pass 'check_no_orphan_power_backends.py'
else
    fail 'check_no_orphan_power_backends.py'
fi
if suite_output=$(python3 scripts/check_no_orphan_power_backends.py --self-test 2>&1); then
    pass 'check_no_orphan_power_backends.py'
else
    fail 'check_no_orphan_power_backends.py'
fi
if suite_output=$(sh scripts/test_bip320_bangate_negative_control.sh 2>&1); then
    pass 'test_bip320_bangate_negative_control.sh'
else
    fail 'test_bip320_bangate_negative_control.sh'
fi
if suite_output=$(python3 scripts/test_blocking_gate_runner.py 2>&1); then
    pass 'test_blocking_gate_runner.py'
else
    fail 'test_blocking_gate_runner.py'
fi

elapsed=$(($(date +%s) - started))
printf 'Blocking gates: %s passed, %s failed, %ss elapsed.\n' "$passed" "$failures" "$elapsed"
if [ "$failures" -ne 0 ]; then
    printf 'Failed blocking suites:%s\n' "$failed_suites" >&2
fi
[ "$failures" -eq 0 ] || exit 1
if [ "$elapsed" -ge 600 ]; then
    echo "ERROR: blocking gates exceeded the ten-minute budget." >&2
    exit 1
fi
