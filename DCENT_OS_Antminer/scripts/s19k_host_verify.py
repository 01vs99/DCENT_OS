#!/usr/bin/env python3
"""Host-side verifier for S19k Wave-1 contracts when cargo test is Defender-blocked.

Does not replace cargo test. Checks CRC5 vectors, SafeOff polarity, dual-port
policy, and script string pins. Exit 0 only if all assertions pass.
"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import subprocess
import tempfile
import sys
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]


def resp_crc5(data: bytes, init: int) -> int:
    crc = init & 0x1F
    for byte in data:
        for bit_index in range(7, -1, -1):
            data_bit = (byte >> bit_index) & 1
            feedback = data_bit ^ ((crc >> 4) & 1)
            crc = (
                (((crc >> 3) & 1) << 4)
                | ((((crc >> 2) & 1) ^ data_bit) << 3)
                | ((((crc >> 1) & 1) ^ feedback) << 2)
                | ((crc & 1) << 1)
                | feedback
            )
    return crc


def check_ota08_exact_identity(source: str) -> None:
    """Exercise the read-only identity function; never source the OTA executor."""
    begin = source.index("require_amlogic_ota08_identity() {")
    function = source[begin:source.index("\n}", begin) + 2]
    for platform, target, expected in (
        ("am3-aml-s19k", "am3-s19k", True),
        ("am3-aml-s21", "am3-s21", True),
        ("am3-aml-s19k", "am3-s19kpro", False),
        ("am3-aml-s19kpro", "am3-aml-s19kpro", False),
        ("am3-aml-s21", "am3-s19k", False),
        ("am3-unknown", "am3-unknown", False),
        (None, "am3-s19k", False),
        ("am3-aml-s19k", None, False),
    ):
        with tempfile.TemporaryDirectory(prefix="dcent-ota08-identity-") as directory:
            root = Path(directory)
            for name, value in (("platform", platform), ("board_target", target)):
                if value is not None:
                    (root / name).write_text(value, encoding="utf-8")
            script = function + '\nPLATFORM_FILE="$1/platform"\nBOARD_TARGET_FILE="$1/board_target"\nrequire_amlogic_ota08_identity\n'
            result = subprocess.run(["sh", "-c", script, "fixture", directory], capture_output=True, text=True, timeout=5)
            assert (result.returncode == 0) == expected, (platform, target, result.stdout, result.stderr)


def main() -> int:
    frame = bytes.fromhex("AA556096394C021403048E")
    # Honest: RTL job init 0x1B does not match this comparative trailer.
    assert resp_crc5(frame[2:10], 0x1B) != frame[10] & 0x1F
    assert resp_crc5(b"", 0x03) == 0x03

    install = (ROOT / "scripts/install_amlogic_persistent.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "GPIO437_SAFE_OFF=1" in install
    assert "am3-s19k-active-low" in install
    safeoff_at = install.find("Step 7b/10: GPIO437 PWR_EN SafeOff")
    combined_writer_at = install.find(
        "    flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT || exit 1"
    )
    assert (
        safeoff_at != -1
        and combined_writer_at != -1
        and safeoff_at < combined_writer_at
    )

    lab = (ROOT / "scripts/amlogic_lab_rootfs.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "am3-s19k-active-low" in lab
    assert "drive LOW) before NAND" not in lab
    assert "refuse GPIO437 SafeOff without proven board identity" in lab
    assert (
        "CLEAR_FOR_FLASH=false - refusing gpio437 SafeOff/flash_erase/nandwrite" in lab
    )
    assert "--lab-only is not a FLASH override" in lab
    assert "admit_s19k_lab_rootfs_script_execute_refuses_nandwrite" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_install.rs"
    ).read_text(encoding="utf-8", errors="replace")
    write_at = lab.find("    write)")
    restore_at = lab.find("    restore)")
    assert write_at != -1 and restore_at != -1 and write_at < restore_at
    write_slice = lab[write_at:restore_at]
    restore_slice = lab[restore_at:]
    assert write_slice.find("refuse_clear_for_flash_nand") < write_slice.find(
        "require_gpio437_safe_off_before_mutation"
    )
    assert restore_slice.find("refuse_clear_for_flash_nand") < restore_slice.find(
        "require_gpio437_safe_off_before_mutation"
    )

    s37 = (
        ROOT
        / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
    ).read_text(encoding="utf-8", errors="replace")
    # The generated authority owns levels; S37 has no independent SKU list.
    spec = importlib.util.spec_from_file_location("gpio437_policy", ROOT / "scripts/generate_amlogic_gpio437.py")
    assert spec is not None and spec.loader is not None
    policy_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy_module)
    policy = policy_module.load_policy()
    for target in ("am3-s19k", "am3-s19kpro", "am3-aml-s19kpro"):
        row = next(row for row in policy["profiles"] if row["board_target"] == target)
        assert policy_module.decision(row, policy["sources"]) == ("qualified", 2, (0, 1))
    assert 'read_psu_recipe || return 1' in s37
    assert 'set_gpio_value_checked "$PWR_GPIO" "$PWR_OFF_VALUE"' in s37
    assert 'set_gpio_direction_checked "$PWR_GPIO" "$PWR_OFF_DIRECTION" out' in s37
    assert 'set_gpio_direction_checked "$PWR_GPIO" in in' in s37
    assert "IDENTITY_ROOT/board_target" in s37
    assert "GPIO437 refuse: missing or unsealed board_target=" in s37

    job = (ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_job.rs").read_text(
        encoding="utf-8"
    )
    assert "CLOSED_11D_PREFIX: [u8; 4] = [0x55, 0xAA, 0x21, 0x36]" in job
    assert "FPGA_ESP_JOB_LEN_FIELD: u8 = 0x56" in job
    assert "BOSMINER_55AA2136_COLLISION_OFF: u64 = 0x00EE_C448" in job
    assert "BOSMINER_PREFIX_CONST_VA: u64 = 0x012E_C448" in job
    assert "BOSMINER_PACK_FN_VA: u64 = 0x0091_BEB4" in job
    assert "admit_bosminer_ghidra_pack_prefix_21_36" in job
    assert "pack_s19k_braiins_ghidra_job_body" in job
    assert "pack_s19k_braiins_ghidra_job_body_with_vbits" in job
    assert "admit_bosminer_91beb4_pack_body_elf" in job
    assert "admit_s19k_ghidra_pack_body_matches_production" in job
    assert "refuse_91beb4_alloc_fail_packing40_as_pack_ident" in job
    assert "BOSMINER_PACK_FN_MOVZ56_INSN: u32 = 0x5280_0AC0" in job
    assert "BOSMINER_PACK_DEST_VERSION_OFF: usize = 0x52" in job
    assert "BOSMINER_PACK_FN_SUCCESS_RUSTC_LOCS: usize = 0" in job
    assert "s19k_braiins_midstate0_version" in job
    assert "BOSMINER_VERSION_ROLL_FN_VA: u64 = 0x00C4_1E5C" in job
    assert "BOSMINER_FILL_PREFIX_OFF: usize = 0x50" in job
    assert "refuse_len_field_36_as_esp_data_len_plus_4" in job
    assert "ESP_BM1366_JOB_PAYLOAD: usize = 82" in job
    assert "BOSMINER_WORK_NTIME_OFF: usize = 0x38" in job
    assert "refuse_bosminer_work_plus_0x38_as_nbits" in job
    assert "BOSMINER_FILL_NBITS_OFF: usize = 0x44" in job
    assert "BOSMINER_NTIME_ROLL_FN_VA: u64 = 0x00C4_1C48" in job
    assert "BOSMINER_JOB_NBITS_OFF: usize = 0x78" in job
    assert "BOSMINER_JOB_NBITS_GETTER_VA: u64 = 0x00C7_B380" in job
    assert "BOSMINER_JOB_NBITS_GETTER2_VA: u64 = 0x00D1_39DC" in job
    assert "BOSMINER_STRATUM_V2_JOB_VTABLE_VA: u64 = 0x01A1_21D8" in job
    assert "admit_bosminer_job_nbits_is_self_plus_0x78" in job
    assert "refuse_bosminer_pack_caller_engine_plus_0x90_as_nbits" in job
    assert "s19k_braiins_job_nbits_from_object" in job
    assert "BOSMINER_NBITS_BUG_WORK_RS_LINE: u16 = 307" in job
    assert "BOSMINER_PACK_CALLER_WORKER_RS_LINE: u16 = 482" in job
    assert "admit_bosminer_engine_midstate_log" in job
    assert "refuse_ext_work_id_to_hw_as_s19k_uart_job_id" in job
    assert "refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id" in job
    assert "s19k_braiins_midstate_count_from_log" in job
    assert "BOSMINER_ENGINE_MIDSTATE_LOG_OFF: usize = 0x70" in job
    assert "BOSMINER_REGISTRY_ASSERT_LINE: u16 = 148" in job
    assert "BOSMINER_REGISTRY_EMPTY_LINE: u16 = 119" in job
    assert "admit_bosminer_work_plus_0x40_is_registry_work_id" in job
    assert "refuse_invented_registry_size_as_uart_job_id_space" in job
    assert "BOSMINER_WORK_ID_OFF: usize = 0x40" in job
    assert "BOSMINER_WORK_ID_STP_INSN: u32 = 0xA903_DB68" in job
    assert "BOSMINER_REGISTRY_SLOT_STRIDE: usize = 0x78" in job
    assert "BOSMINER_REGISTRY_SIZE_KNOWN: bool = false" in job
    assert "s19k_braiins_uart_job_id_inputs" in job
    assert "BOSMINER_WORKER_SIZE: usize = 0x1C8" in job
    assert "BOSMINER_JOB_ID_FN_ADRP_STR_HITS: usize = 0" in job
    assert "BOSMINER_LSL3_RET_HITS: usize = 0" in job
    assert "refuse_unlocated_engine_job_id_fn_as_named_encoder" in job
    assert "refuse_worker_ctor_e0000020_as_registry_size" in job
    assert "BOSMINER_WORKER_CTOR_TRACE_MASK: u32 = 0xE000_0020" in job
    assert "BOSMINER_AND_FF_RET_VA: u64 = 0x010A_F790" in job
    assert "BOSMINER_UART_REGISTRY_SIZE_BASE: u32 = 0x100" in job
    assert "BOSMINER_AM3_FACTORY_0X100_SHR_HITS: usize = 5" in job
    assert "s19k_braiins_uart_registry_size_from_log" in job
    assert "refuse_fpga_0x10000_shr_log_as_uart_registry_size" in job
    assert "admit_bosminer_uart_registry_size_is_0x100_shr_log" in job
    assert "refuse_aml_ctrl_rs_as_uart_registry_factory" in job
    assert "BOSMINER_AM3_FACTORY_MOVZ_INSN: u32 = 0x5280_200A" in job
    assert "BOSMINER_FPGA_0X10000_MOVZ_INSN: u32 = 0x52A0_0029" in job
    assert "BOSMINER_WORKER_NEW_SAVES_X6_INSN: u32 = 0xAA06_03FA" in job
    assert "BOSMINER_AM3_COMBO_BUG_LINE: u16 = 57" in job
    assert (
        'BOSMINER_AM3_RS: &str = "open/bosminer/bosminer-am2-s17/src/hardware/am3.rs"'
        in job
    )
    assert "controlboard/aml.rs" in job
    assert "admit_bosminer_bm1366_uses_am3_uart_registry_factory" in job
    assert "refuse_bm1366_exclusive_uart_registry_size" in job
    assert "BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_INSN: u32 = 0x5282_6CCA" in job
    assert "BOSMINER_BM1366_CHIP_ID: u16 = 0x1366" in job
    assert "hashchain/bm1366.rs" in job
    assert "BOSMINER_HASHCHAIN_TICKET_LINE: u16 = 298" in job
    assert "s19k_braiins_uart_job_id" in job
    assert "s19k_braiins_uart_work_id_from_rx_job_byte" in job
    assert "admit_bosminer_uart_job_id_is_work_id_shl_log" in job
    assert "refuse_factory_clone_as_first_writer_of_job_id_fn" in job
    assert "BOSMINER_FACTORY_CLONE_FN_VA: u64 = 0x0087_5F54" in job
    assert "BOSMINER_WORK_RESP_PARSE_FN_VA: u64 = 0x0091_C0A0" in job
    assert "BOSMINER_PACK_CALLER_LSL_COUNT_INSN: u32 = 0x9ACA_2121" in job
    assert "BOSMINER_ENGINE_NONCE_FN_OFF: usize = 0x88" in job
    assert "admit_bosminer_engine88_producer_family" in job
    assert "refuse_engine88_type4_result_as_fill_identity" in job
    assert "BOSMINER_ENGINE88_PRODUCER_HITS: usize = 6" in job
    assert "BOSMINER_ENGINE88_WORK_TYPE: u32 = 4" in job
    assert "BOSMINER_ENGINE88_PRODUCER_FN_VA: u64 = 0x008D_9984" in job
    assert "admit_bosminer_fill_type1_plus88_coinstall_absent" in job
    assert "refuse_fill_type1_static_plus88_installer" in job
    assert "BOSMINER_FILL_TYPE1_COINSTALLED_88_HITS: usize = 0" in job
    assert "admit_bosminer_factory_clone_bl_family" in job
    assert "refuse_clone_q88_as_named_text_identity" in job
    assert "BOSMINER_FACTORY_CLONE_BL_HITS: usize = 5" in job
    assert "BOSMINER_CLONE_SRC_MOV_INSN: u32 = 0xAA01_03F4" in job
    assert "admit_bosminer_prep_q88_from_x1" in job
    assert "admit_bosminer_get_caller_x2_is_prep_source" in job
    assert "admit_bosminer_prod_two_templates" in job
    assert "refuse_prep_x2_as_factory_x1" in job
    assert "refuse_prep_q88_dest_as_factory_dest" in job
    assert "BOSMINER_PREP_Q88_LDUR_INSN: u32 = 0x3CC8_8285" in job
    assert "BOSMINER_PREP_Q88_STUR_INSN: u32 = 0x3C88_8165" in job
    assert "BOSMINER_PREP_Q88_DEST_ADD_INSN: u32 = 0x9108_C3EB" in job
    assert "BOSMINER_PREP_TEMPLATE_STACK_OFF: u16 = 0x2E0" in job
    assert "BOSMINER_GET_X19_FROM_X2_INSN: u32 = 0xAA02_03F3" in job
    assert "admit_bosminer_87fb4c_wraps_clone" in job
    assert "admit_bosminer_prod_prep_source_is_x22_clone" in job
    assert "refuse_prod_sp2e0_as_factory_x24_clone" in job
    assert "BOSMINER_WRAP_CLONE_BL_INSN: u32 = 0x97FF_D8F5" in job
    assert "BOSMINER_PROD_WRAP_SRC_MOV_INSN: u32 = 0xAA16_03E1" in job
    assert "BOSMINER_PROD_WRAP_BL_INSN: u32 = 0x9400_066D" in job
    assert "admit_bosminer_e02c_is_0x2a0_vtable_method" in job
    assert "refuse_e02c_vtable_as_named_plus88" in job
    assert "BOSMINER_E02C_VTABLE_HITS: usize = 2" in job
    assert "BOSMINER_E02C_TYPE_SIZE: usize = 0x2A0" in job
    assert "BOSMINER_E02C_FIXTURE_LINE: u16 = 258" in job
    assert "BOSMINER_E02C_HARDWARE_LINE: u16 = 352" in job
    assert "admit_bosminer_ctx_290_then_88" in job
    assert "refuse_ctx_self_plus88_as_method0_load" in job
    assert "BOSMINER_CTX_290_THEN_88_INSN: u32 = 0xF940_4529" in job
    assert "BOSMINER_CTX_X22_PLUS88_HITS: usize = 0" in job
    assert "admit_bosminer_ctx_290_is_hashmap_get_self" in job
    assert "refuse_ctx_290_as_hashchain_engine" in job
    assert "refuse_hashmap_plus88_as_engine_nonce_fn" in job
    assert "BOSMINER_PROD_MAP_LDR_INSN: u32 = 0xF941_4AC0" in job
    assert "BOSMINER_PROD_GET_BL_INSN: u32 = 0x97FF_E9C8" in job
    assert "BOSMINER_HASHMAP_GET_ADD_C0_INSN: u32 = 0x9103_0000" in job
    assert "BOSMINER_HASHMAP_INNER_OFF: usize = 0xC0" in job
    assert "admit_bosminer_am3_str88_census" in job
    assert "admit_bosminer_am3_str88_result_family" in job
    assert "admit_bosminer_am3_str88_add18_family" in job
    assert "refuse_am3_str88_as_hashmap_plus88" in job
    assert "refuse_am3_str88_as_engine_nonce_text" in job
    assert "BOSMINER_AM3_STR88_HITS: usize = 10" in job
    assert "BOSMINER_AM3_STR88_RESULT_HITS: usize = 3" in job
    assert "BOSMINER_AM3_STR88_ADD18_INSN: u32 = 0x9100_6148" in job
    assert "BOSMINER_AM3_STR88_DEST_A8_HITS: usize = 0" in job
    assert "admit_bosminer_hashmap_str88_census" in job
    assert "admit_bosminer_hashmap_str88_family" in job
    assert "refuse_hashmap_str88_as_engine_nonce_text" in job
    assert "BOSMINER_HASHMAP_STR88_HITS: usize = 11" in job
    assert "BOSMINER_HASHMAP_STR88_FAMILY_STRIDE: u64 = 0x8B8" in job
    assert "BOSMINER_HASHMAP_STR88_ADD_A8_INSN: u32 = 0x9102_A260" in job
    assert "admit_bosminer_hashmap_x20_is_result_ok" in job
    assert "refuse_hashmap_x20_as_dest_plus88_addr" in job
    assert "refuse_hashmap_x20_as_dest_plus90_addr" in job
    assert "BOSMINER_HASHMAP_STR88_HELPER_VA: u64 = 0x0086_1090" in job
    assert "BOSMINER_HASHMAP_STR88_LDP_INSN: u32 = 0xA951_DFF4" in job
    assert "BOSMINER_HASHMAP_STR88_OK_SP: u16 = 0x118" in job
    assert "admit_bosminer_hashmap_helper_ok_is_b8_clone" in job
    assert "admit_bosminer_hashmap_str88_rest_census" in job
    assert "refuse_hashmap_helper_ok_as_engine_nonce" in job
    assert "BOSMINER_HASHMAP_STR88_REST_HITS: usize = 8" in job
    assert "BOSMINER_HASHMAP_HELPER_OK_STR_INSN: u32 = 0xF900_0660" in job
    assert "BOSMINER_HASHMAP_CLONE_ALLOC_SIZE: u16 = 0x18" in job
    assert "BOSMINER_HASHMAP_HELPER_CLONE_FN_VA: u64 = 0x008B_60AC" in job
    assert "admit_bosminer_hashmap_18_is_dealloc_node" in job
    assert "refuse_hashmap_18_as_alloc" in job
    assert "admit_bosminer_hashmap_5de708_is_result_x0" in job
    assert "admit_bosminer_hashmap_115c698_is_field_rewrite" in job
    assert "BOSMINER_HASHMAP_18_DEALLOC_BL_INSN: u32 = 0x97F4_FA55" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK0_VA: u64 = 0x005F_4A7C" in job
    assert "BOSMINER_HASHMAP_5DE708_BL_TGT: u64 = 0x0058_6CD8" in job
    assert "BOSMINER_HASHMAP_115C698_STR_INSN: u32 = 0xF900_46A8" in job
    assert "admit_bosminer_heap_thunk0_is_tail_trampoline" in job
    assert "refuse_heap_thunk0_as_realloc" in job
    assert "admit_bosminer_hashmap_str88_rest_named" in job
    assert "admit_bosminer_hashmap_626aac_is_x0_from_x23" in job
    assert "refuse_hashmap_626aac_as_panic_4538b0_return" in job
    assert "admit_bosminer_hashmap_654c10_is_x24_from_plus90" in job
    assert "admit_bosminer_hashmap_9f3f00_is_stack_x8" in job
    assert "admit_bosminer_hashmap_b824c8_is_x8_plus8" in job
    assert "refuse_hashmap_b824c8_as_panic_4538b0_return" in job
    assert "admit_bosminer_hashmap_115c788_is_field_rewrite" in job
    assert "refuse_hashmap_rest_dests_as_engine_nonce_text" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA: u64 = 0x0129_B128" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK0_B_INSN: u32 = 0x17E4_BB77" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK0_B_TGT: u64 = 0x00BC_9F10" in job
    assert "BOSMINER_RUSTC_HEAP_DEALLOC_CBZ_INSN: u32 = 0xB400_12A0" in job
    assert "BOSMINER_HASHMAP_626AAC_STR_INSN: u32 = 0xF900_4660" in job
    assert "BOSMINER_HASHMAP_654C10_STR_INSN: u32 = 0xF900_4678" in job
    assert "BOSMINER_HASHMAP_9F3ED8_SP_OFF: u16 = 0x58" in job
    assert "BOSMINER_HASHMAP_B824C0_ADD8_INSN: u32 = 0x9100_2109" in job
    assert "BOSMINER_PANIC_DTOR_MSG_LEN: u16 = 0x24" in job
    assert "admit_bosminer_heap_thunk2_is_size_product" in job
    assert "refuse_heap_thunk2_as_dummy_trampoline" in job
    assert "refuse_heap_thunk2_as_dealloc" in job
    assert "admit_bosminer_hashmap_626aac_second_arm_is_x8_plus20" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK2_BODY_VA: u64 = 0x0129_B1E4" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK2_B_TGT: u64 = 0x00BC_9E18" in job
    assert "BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_INSN: u32 = 0x9BC1_7C02" in job
    assert "BOSMINER_HASHMAP_626FB0_ADD20_INSN: u32 = 0x9100_8100" in job
    assert "admit_bosminer_fill_plus88_template_is_spawn_x24" in job
    assert "refuse_fill_type1_adrp_identity_installer" in job
    assert "BOSMINER_SPAWN_X23_LDR_INSN: u32 = 0xF940_0037" in job
    assert "BOSMINER_SPAWN_OK_SP: u16 = 0x78" in job
    assert "BOSMINER_ADRP_ADD_STR88_HITS: usize = 0" in job
    assert "BOSMINER_ADRP_LDR_TEXT_STR88_NONSP_HITS: usize = 0" in job
    assert "BOSMINER_E02C_METHODS_STR88_HITS: usize = 0" in job
    assert "admit_bosminer_hashmap_get_returns_tag_payload" in job
    assert "admit_bosminer_spawn_x23_is_payload_qword0" in job
    assert "refuse_spawn_x23_as_first_load_identity_text" in job
    assert "BOSMINER_HASHMAP_GET_MISS_TAG_INSN: u32 = 0x5280_0033" in job
    assert "BOSMINER_SPAWN_TBZ_INSN: u32 = 0x3700_0F60" in job
    assert "BOSMINER_SPAWN_DEFAULT_SIZE: u16 = 0x50" in job
    assert "BOSMINER_SPAWN_DEFAULT_ALLOC_BL_TGT: u64 = 0x005F_4A78" in job
    assert "BOSMINER_SPAWN_MISS_PAYLOAD0_VA: u64 = 0x019B_DE50" in job
    assert "admit_bosminer_hashmap_insert_copies_18_from_entry8" in job
    assert "refuse_hashmap_insert_as_plus88_identity" in job
    assert "BOSMINER_HASHMAP_INSERT_FN_VA: u64 = 0x008D_A510" in job
    assert "BOSMINER_HASHMAP_INSERT_VALUE_SIZE: u16 = 0x18" in job
    assert "BOSMINER_HASHMAP_INSERT_SRC_MOV_INSN: u32 = 0xAA03_03F5" in job
    assert "BOSMINER_HASHMAP_INSERT_STUR_Q_INSN: u32 = 0x3C9E_8221" in job
    assert "BOSMINER_HASHMAP_INSERT_NONSP_STR88_HITS: usize = 0" in job
    assert "admit_bosminer_entry8_qword0_is_factory4" in job
    assert "refuse_entry8_qword0_as_identity_text" in job
    assert "BOSMINER_ENTRY8_QWORD0_FN_VA: u64 = 0x0087_7D40" in job
    assert "BOSMINER_ENTRY8_QWORD0_STP_INSN: u32 = 0xA903_A3E9" in job
    assert "BOSMINER_ENTRY8_1366_STP_INSN: u32 = 0xA905_ABE9" in job
    assert "BOSMINER_VT0_250_NONSP_STR88_HITS: usize = 0" in job
    assert "admit_bosminer_1366_uses_two_factory_monomorphs" in job
    assert "refuse_factory4_as_876ca8" in job
    assert "BOSMINER_FACTORY4_FN_VA: u64 = 0x0087_7D40" in job
    assert "BOSMINER_FACTORY4_FRAME_INSN: u32 = 0xD11B_03FF" in job
    assert "BOSMINER_FACTORY_876_FRAME_INSN: u32 = 0xD11A_43FF" in job
    assert "BOSMINER_FACTORY4_SNAP_SIZE_INSN: u32 = 0x5282_C102" in job
    assert "BOSMINER_FACTORY4_WORKER_NEW_VA: u64 = 0x0090_4434" in job
    assert "BOSMINER_FACTORY_CLONE_TGT: u64 = 0x0087_5F54" in job
    assert "admit_bosminer_worker_new_monomorphs_split" in job
    assert "refuse_worker_new_factory4_as_876" in job
    assert "BOSMINER_WORKER_NEW_876_FRAME_INSN: u32 = 0xD13B_83FF" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_FRAME_INSN: u32 = 0xD13C_03FF" in job
    assert "BOSMINER_FACTORY_876_COPY1600_INSN: u32 = 0x5282_C002" in job
    assert "BOSMINER_FACTORY4_ALLOC18A0_INSN: u32 = 0x5283_1402" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_CA00_INSN: u32 = 0x5299_4009" in job
    assert "admit_bosminer_factory4_ca00_is_1e9" in job
    assert "refuse_ca00_as_factory4_type_tag" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_1E9: u32 = 1_000_000_000" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_MOVK_INSN: u32 = 0x72A7_7349" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_CMP_INSN: u32 = 0x6B09_011F" in job
    assert "BOSMINER_CA00_MOVZ_W9_HITS: usize = 230" in job
    assert "admit_bosminer_worker_new_copy1a8_shared" in job
    assert "refuse_copy1a8_as_factory_type_param" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA: u64 = 0x0090_4690" in job
    assert "BOSMINER_WORKER_NEW_876_MEMCPY_BL_INSN: u32 = 0x940B_1645" in job
    assert "BOSMINER_WORKER_NEW_1A8_MOVZ_HITS: usize = 64" in job
    assert "admit_bosminer_factory4_snap_extra_is_tail_16" in job
    assert "refuse_entry8_plus10_as_snap_extra16" in job
    assert "BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_INSN: u32 = 0x9119_4108" in job
    assert "BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN: u32 = 0x9140_07E8" in job
    assert "BOSMINER_ENTRY8_PLUS10_STR_INSN: u32 = 0xF900_27E8" in job
    assert "BOSMINER_ENTRY8_PLUS10_VALUE: u32 = 0x002F_AF08" in job
    assert "admit_bosminer_snap_extra16_is_worker_new_tail" in job
    assert "refuse_tail16_as_entry8_plus10" in job
    assert "BOSMINER_WORKER_NEW_876_STR_15F8_INSN: u32 = 0xF90A_FEC9" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_STR_1600_INSN: u32 = 0xF90B_02A9" in job
    assert "BOSMINER_WORKER_NEW_TAIL_Q0_OFF: u16 = 0x15F8" in job
    assert "admit_bosminer_876_tail_15f8_is_arg0" in job
    assert "refuse_2faf08_as_worker_new_tail" in job
    assert "refuse_factory4_1600_as_876_arg0" in job
    assert "BOSMINER_WORKER_NEW_876_MOV_X24_X0_INSN: u32 = 0xAA00_03F8" in job
    assert "BOSMINER_WORKER_NEW_876_CALL_BL_INSN: u32 = 0x940B_BF12" in job
    assert "BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN: u32 = 0x5282_4129" in job
    assert "BOSMINER_AF08_MOVZ_W8_HITS: usize = 4" in job
    assert "admit_bosminer_factory_x23_is_self_and_bf33a4_is_70_box" in job
    assert "refuse_bf33a4_as_identity" in job
    assert "BOSMINER_FACTORY_MOV_X23_X0_INSN: u32 = 0xAA00_03F7" in job
    assert "BOSMINER_BF33A4_SIZE_INSN: u32 = 0x5280_0E00" in job
    assert "BOSMINER_BF33A4_ALLOC_BL_INSN: u32 = 0x97E8_059E" in job
    assert "BOSMINER_WORKER_NEW_COPY1208_INSN: u32 = 0x5282_4108" in job
    assert "admit_bosminer_bf33a4_box_fields_and_1208_header" in job
    assert "refuse_1208_as_object_base_memcpy" in job
    assert "refuse_factory_self_as_hashchain_ldr" in job
    assert "BOSMINER_BF33A4_STR10_INSN: u32 = 0xF900_0816" in job
    assert "BOSMINER_WORKER_NEW_COPY1AF_INSN: u32 = 0x5280_35E2" in job
    assert "BOSMINER_BF33A4_BL_HITS: usize = 6" in job
    assert "BOSMINER_FACTORY_SELF_X23_LDR_HITS: usize = 0" in job
    assert "admit_bosminer_11f26f8_zeros_tag2_and_1af_is_7_plus_1a8" in job
    assert "refuse_q0q1_as_identity_text" in job
    assert "refuse_1af_as_asic_frame" in job
    assert "BOSMINER_F11F26F8_LSR_INSN: u32 = 0xD37D_FC09" in job
    assert "BOSMINER_BF33A4_LDURQ0_INSN: u32 = 0x3CC2_83E0" in job
    assert "BOSMINER_WORKER_NEW_BLOB_PLUS7_INSN: u32 = 0x9100_1D00" in job
    assert "BOSMINER_FACTORY4_610_DROP_BL_INSN: u32 = 0x9408_F2EF" in job
    assert "admit_bosminer_b41d80_is_70_drop_and_q2_from_sp" in job
    assert "refuse_7byte_prefix_as_55aa_header" in job
    assert "refuse_q2_as_identity_text" in job
    assert "BOSMINER_B41D80_LDR_SLOT_INSN: u32 = 0xF940_0013" in job
    assert "BOSMINER_B41D80_SIZE_INSN: u32 = 0x5280_0E01" in job
    assert "BOSMINER_BF33A4_LDP_Q12_INSN: u32 = 0xAD40_0BE1" in job
    assert "BOSMINER_FACTORY4_PREFIX_STR_INSN: u32 = 0xF904_23E9" in job
    assert "BOSMINER_B41D80_BL_HITS: usize = 54" in job
    assert "admit_bosminer_887c34_is_98_box_and_q2_is_zero_shuffle" in job
    assert "refuse_factory4_prefix_as_bbd3dc_pair" in job
    assert "refuse_876_ec8_as_840_prefix" in job
    assert "BOSMINER_887C34_SIZE_INSN: u32 = 0x5280_1300" in job
    assert "BOSMINER_BBD3DC_ADD48_INSN: u32 = 0x9101_2008" in job
    assert "BOSMINER_887C34_BL_HITS: usize = 5" in job
    assert "BOSMINER_BBD3DC_BL_HITS: usize = 11" in job
    assert "admit_bosminer_887c34_arcinner_fields" in job
    assert "refuse_98_arg58_as_7byte_prefix" in job
    assert "BOSMINER_887C34_STP58_INSN: u32 = 0xA905_FFE0" in job
    assert "BOSMINER_887C34_LDAXR_INSN: u32 = 0xC85F_7C08" in job
    assert "admit_bosminer_1af_prefix_unwritten_and_8_is_layout_align" in job
    assert "refuse_factory4_prefix_as_887c34_arc" in job
    assert "refuse_8_as_vec_capacity" in job
    assert "BOSMINER_FACTORY4_1AF_SRC_INSN: u32 = 0x9121_83E1" in job
    assert "BOSMINER_FACTORY4_BLOB860_STR_HITS: usize = 0" in job
    assert "BOSMINER_887C34_LAYOUT_ALIGN: u16 = 8" in job
    assert "admit_bosminer_1af_is_pad7_then_aligned_1a8" in job
    assert "refuse_1af_as_wire_header_or_vec_len" in job
    assert "BOSMINER_FACTORY4_STR_13B8_INSN: u32 = 0xF909_DEA9" in job
    assert "BOSMINER_WORKER_NEW_1AF_ALIGNED: u16 = 0x1210" in job
    assert "admit_bosminer_1208_is_arg1_c8_and_1a8_is_local" in job
    assert "refuse_1208_u8_as_midstate_or_55aa" in job
    assert "BOSMINER_876_LDRB_ARG1_C8_INSN: u32 = 0x3943_233A" in job
    assert "BOSMINER_876_LDRB_BOX18_INSN: u32 = 0x3940_6113" in job
    assert "BOSMINER_WORKER_NEW_ARG1_C8: u16 = 0xC8" in job
    assert "admit_bosminer_c8_is_state_tag_and_1a8_is_registry" in job
    assert "refuse_c8_as_bool" in job
    assert "BOSMINER_HASHCHAIN_C8_CMP3_INSN: u32 = 0x7100_0D1F" in job
    assert "BOSMINER_HASHCHAIN_C8_CMP3_HITS: usize = 77" in job
    assert "BOSMINER_876_REGISTRY_WRAP_BL_INSN: u32 = 0x940B_D047" in job
    assert "admit_bosminer_c8_tags_are_command_rs_async_poll" in job
    assert "refuse_c8_as_hashchain_running_or_starting" in job
    assert "bosminer_c8_async_tag_name" in job
    assert "BOSMINER_C8_ASYNC_FN_LINE: u16 = 700" in job
    assert "BOSMINER_C8_NESTED_ASYNC_LINE: u16 = 719" in job
    assert "BOSMINER_C8_TAG1_CBNZ_INSN: u32 = 0x3500_0C68" in job
    assert "BOSMINER_C8_ASYNC_DONE_BL_INSN: u32 = 0x97ED_F490" in job
    assert "BOSMINER_ASYNC_DONE_HELPER_ADD_INSN: u32 = 0x9111_C108" in job
    assert (
        'BOSMINER_ASYNC_DONE_MSG: &str = "`async fn` resumed after completion"' in job
    )
    assert (
        'BOSMINER_ASYNC_PANIC_MSG: &str = "`async fn` resumed after panicking"' in job
    )
    assert "BOSMINER_C8_TAG_COMPLETED: u8 = 1" in job
    assert "BOSMINER_C8_TAG_PANICKED: u8 = 2" in job
    assert "BOSMINER_C8_TAG_SUSPENDED: u8 = 3" in job
    assert "admit_bosminer_c8_async_polled_from_hashchain_drivers" in job
    assert "refuse_c8_async_as_named_write_register" in job
    assert "BOSMINER_C8_POLL_BL_HITS: usize = 6" in job
    assert "BOSMINER_C8_POLL_BM1366_LINE: u16 = 127" in job
    assert "BOSMINER_C8_POLL_BM136X_LINE: u16 = 107" in job
    assert "BOSMINER_C8_POLL_BM1397_LINE: u16 = 147" in job
    assert "BOSMINER_C8_POLL_VT230_LDR_INSN: u32 = 0xF941_1908" in job
    assert "BOSMINER_C8_POLL_ADD30_INSN: u32 = 0x9100_C260" in job
    assert (
        'BOSMINER_BM136X_FIELDSET_MSG: &str = "FieldSet corrupted (this is a bug)"'
        in job
    )
    assert "admit_bosminer_plus230_is_ctx_ptr_and_1a8_wrap_fields" in job
    assert "refuse_plus230_as_vtable_or_1a8_end_as_interior" in job
    assert "BOSMINER_C8_STATE_ZERO_F8_INSN: u32 = 0x3903_E27F" in job
    assert "BOSMINER_C8_FUT10_STR_INSN: u32 = 0xF900_2268" in job
    assert "BOSMINER_REGISTRY_WRAP_LINE: u16 = 109" in job
    assert "BOSMINER_REGISTRY_WRAP_STR110_INSN: u32 = 0xF900_8AE8" in job
    assert "BOSMINER_REGISTRY_WRAP_STR1A8_INSN: u32 = 0xF900_D6E8" in job
    assert "BOSMINER_REGISTRY_1E9_MOVK_INSN: u32 = 0x72A7_7348" in job
    assert "admit_bosminer_plus230_init_usize10_and_wrap_simd" in job
    assert "refuse_plus230_as_named_io_ptr_or_168_as_registry_new" in job
    assert "BOSMINER_HC_PLUS230_INIT_LINE: u16 = 323" in job
    assert "BOSMINER_HC_PLUS230_MOVZ10_INSN: u32 = 0x5280_0208" in job
    assert "BOSMINER_HC_PLUS230_STR_INSN: u32 = 0xF901_1948" in job
    assert "BOSMINER_WRAP_SIMD_168_STP_INSN: u32 = 0xAD00_0920" in job
    assert "BOSMINER_WRAP_STP158_INSN: u32 = 0xA915_D2F5" in job
    assert "BOSMINER_HC_PLUS240_1E8: u32 = 0x05F5_E100" in job
    assert "admit_bosminer_poll_230_is_hc_usize10_and_188_unwritten" in job
    assert "refuse_poll_230_as_heap_ptr_projection" in job
    assert "BOSMINER_POLL_FUT0_LDR_INSN: u32 = 0xF940_0269" in job
    assert "BOSMINER_POLL_FUT8_STR_INSN: u32 = 0xF900_0669" in job
    assert "BOSMINER_POLL_STATE_LDRB_INSN: u32 = 0x3940_A808" in job
    assert "BOSMINER_WRAP_1A8_UNWRITTEN_OFF: u16 = 0x188" in job
    assert "BOSMINER_POLL_230_PLUS10_SUM: u16 = 0x20" in job
    assert "admit_bosminer_230_usize_not_time_and_168_is_now_scale_prefix" in job
    assert "refuse_230_or_168_as_instant_or_duration" in job
    assert "BOSMINER_NANOS_PER_SEC: u32 = 1_000_000_000" in job
    assert "BOSMINER_CLOCK_REALTIME: u32 = 0" in job
    assert "BOSMINER_C0D4AC_NOW_BL_INSN: u32 = 0x941A_3315" in job
    assert "BOSMINER_C0D4AC_STR8_INSN: u32 = 0xB900_0A68" in job
    assert "BOSMINER_SYSNOW_W0_INSN: u32 = 0x2A1F_03E0" in job
    assert "BOSMINER_DURATION_NEW_LINE: u16 = 201" in job
    assert "BOSMINER_TIMESPEC_NOW_LINE_137: u16 = 137" in job
    assert "BOSMINER_DURATION_NEW_STR10_INSN: u32 = 0xB900_1268" in job
    assert "BOSMINER_HC_PLUS260_MOVZ_INSN: u32 = 0x5280_0020" in job
    assert 'BOSMINER_INVALID_TIMESTAMP_MSG: &str = "invalid timestamp"' in job
    assert "admit_bosminer_c0d4ac_is_48_and_37_split_fpga_uart_wrap" in job
    assert "refuse_168_as_full_c0d4ac_or_fpga_as_uart_only" in job
    assert "BOSMINER_C0D4AC_SIZE: u16 = 0x48" in job
    assert "BOSMINER_C0D4AC_BL_HITS: usize = 37" in job
    assert "BOSMINER_C0D4AC_FPGA_HITS: usize = 6" in job
    assert "BOSMINER_C0D4AC_UART_HITS: usize = 25" in job
    assert "BOSMINER_C0D4AC_FPGA_ADD_C8_INSN: u32 = 0x9103_23E8" in job
    assert "BOSMINER_C0D4AC_FPGA_BL0_INSN: u32 = 0x940D_76E6" in job
    assert "BOSMINER_C0D4AC_WRAP_BL0_INSN: u32 = 0x9400_5701" in job
    assert "admit_bosminer_c0d4ac_is_now_scale_cell_not_timespec" in job
    assert "refuse_c0d4ac_or_plus230_as_timespec_size" in job
    assert "BOSMINER_TIMESPEC_SIZE: u16 = 16" in job
    assert "BOSMINER_C0D4AC_UART_WORKER_LINE: u16 = 68" in job
    assert "BOSMINER_C0D4AC_FPGA_HOST_STP_INSN: u32 = 0xA9BA_7BFD" in job
    assert "BOSMINER_C0D4AC_FPGA_HOST_SUB_INSN: u32 = 0xD10E_03FF" in job
    assert "BOSMINER_C0D4AC_UART_WORKER_RS" in job
    assert "/build/source/open/bosminer/bosminer-backend/src/worker.rs" in job
    assert "admit_bosminer_230_owner_nests_command_647_and_48_not_stop_watch" in job
    assert "refuse_c0d4ac_as_metrics_stop_watch_or_hashes_time_mean" in job
    assert "BOSMINER_HC_PLUS230_NESTED_CMD_LINE: u16 = 647" in job
    assert "BOSMINER_HC_PLUS230_NESTED_CMD_BL_INSN: u32 = 0x97F0_73D7" in job
    assert "BOSMINER_METRICS_223_LINE: u16 = 223" in job
    assert "BOSMINER_METRICS_223_BL_INSN: u32 = 0x942C_2E2B" in job
    assert 'BOSMINER_METRICS_STOP_WATCH: &str = "stop_watch"' in job
    assert "BOSMINER_HASHES_TIME_MEAN_ELEMENTS: u8 = 2" in job
    assert "admit_bosminer_c0d4ac_is_copy_and_workpair_is_wrap_sibling" in job
    assert "refuse_c0d4ac_as_workpair_or_named_from_drop_glue" in job
    assert "BOSMINER_C0D4AC_IS_COPY: bool = true" in job
    assert "BOSMINER_DROP_IN_PLACE_HITS: usize = 0" in job
    assert "BOSMINER_WORKPAIR_LINE_110: u16 = 110" in job
    assert "BOSMINER_WORKPAIR_110_ADRP_INSN: u32 = 0xD000_7084" in job
    assert "BOSMINER_C0D4E0_BL_HITS: usize = 1" in job
    assert (
        'BOSMINER_WORKPAIR_RS: &str = "open/bosminer/bosminer-hal/src/workpair.rs"'
        in job
    )
    assert "admit_bosminer_230_is_vt40_x0_and_poll_stores_fut40" in job
    assert "refuse_230_as_ticket_mask_or_work_time_or_poll_mutating_hc" in job
    assert "BOSMINER_HASHCHAIN_TICKET_LINE: u16 = 298" in job
    assert "BOSMINER_HASHCHAIN_TICKET_COL: u16 = 9" in job
    assert "BOSMINER_POLL_FUT40_OFF: u16 = 0x40" in job
    assert "BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN: u32 = 0xF941_1900" in job
    assert "BOSMINER_HASHCHAIN_TICKET_ADRP_INSN: u32 = 0xF000_8C02" in job
    assert (
        'BOSMINER_HASHCHAIN_TICKET_LOG: &str = "Setting ticket mask register for difficulty"'
        in job
        or 'BOSMINER_HASHCHAIN_TICKET_LOG: &str =\n    "Setting ticket mask register for difficulty"'
        in job
    )
    assert "admit_bosminer_238_is_fat_vtable_and_clone_installs_pair" in job
    assert "refuse_238_as_single_callback_or_x0_as_construct_usize10" in job
    assert "BOSMINER_FAT_VT_SLOT_HITS: usize = 7" in job
    assert "BOSMINER_CLONE_MEMCPY_SIZE: u16 = 0x230" in job
    assert "BOSMINER_CMD_472_LINE: u16 = 472" in job
    assert "BOSMINER_CLONE_MEMCPY_MOVZ_INSN: u32 = 0x5280_4602" in job
    assert "BOSMINER_FAT_PAIR_STR238_INSN: u32 = 0xF901_1E97" in job
    assert "BOSMINER_CMD_472_ADRP_INSN: u32 = 0xD000_8C21" in job
    assert "admit_bosminer_fat_slots_pair_sret_and_cmd119_is_div" in job
    assert "refuse_fat_slots_as_named_hashchip_methods" in job
    assert "BOSMINER_FAT_PAIR_RETURN_HITS: usize = 6" in job
    assert "BOSMINER_FAT_SRET_HITS: usize = 1" in job
    assert "BOSMINER_CMD_119_LINE: u16 = 119" in job
    assert "BOSMINER_HASHCHAIN_336_LINE: u16 = 336" in job
    assert "BOSMINER_FAT_SLOT30_X1_LDR_INSN: u32 = 0xF940_0A61" in job
    assert 'BOSMINER_HAL_COMMAND_MODULE: &str = "bosminer_hal::command"' in job
    assert 'BOSMINER_HASHCHIP_LABEL: &str = "Hashchip:"' in job
    assert "admit_bosminer_fat_pairs_are_dyn_future_poll18_not_cmd700" in job
    assert "refuse_fat_pairs_as_result_or_cmd700_poll" in job
    assert "BOSMINER_JUMP_TABLE_CMD700_BL_HITS: usize = 0" in job
    assert "BOSMINER_DYN_FUT_POLL_HITS: usize = 6" in job
    assert "BOSMINER_DYN_FUT_POLL18_OFF: u16 = 0x18" in job
    assert "BOSMINER_DYN_FUT_POLL18_INSN: u32 = 0xF940_0C29" in job
    assert "BOSMINER_FAT_PAIR_RELOAD28_INSN: u32 = 0xF940_1660" in job
    assert "BOSMINER_FAT_SLOT28_JOIN_B_INSN: u32 = 0x17FF_F957" in job
    assert "admit_bosminer_poll_sret20_pending9_t_at_168" in job
    assert "refuse_poll_unit_or_pending0_or_named_slot_methods" in job
    assert "BOSMINER_POLL_PENDING_TAG: u16 = 9" in job
    assert "BOSMINER_POLL_SRET_SIZE: u16 = 0x20" in job
    assert "BOSMINER_POLL_T_LEN: u16 = 0x18" in job
    assert "BOSMINER_POLL_CMP9_HITS: usize = 6" in job
    assert "BOSMINER_POLL_CMP9_X27_INSN: u32 = 0xF100_277F" in job
    assert "BOSMINER_POLL_T168_LDR_INSN: u32 = 0xF940_B7F9" in job
    assert "BOSMINER_FAT_SLOT_PRE_BLR_LOC_HITS: usize = 0" in job
    assert "admit_bosminer_poll_tag8_ok_tag9_pending_ret" in job
    assert "refuse_pending9_as_unknown_or_named_slot_methods" in job
    assert "s19k_bosminer_poll_word0_arm" in job
    assert "BOSMINER_POLL_READY_OK_TAG: u16 = 8" in job
    assert "BOSMINER_POLL_SUSPEND_STATE_OFF: u16 = 0x21" in job
    assert "BOSMINER_POLL_CMP8_HITS: usize = 7" in job
    assert "BOSMINER_POLL_PENDING_STR_X28_INSN: u32 = 0xF900_0388" in job
    assert "BOSMINER_POLL_SUSPEND_STRB_INSN: u32 = 0x3900_8668" in job
    assert "BOSMINER_POLL_ERR_PACK_STP_INSN: u32 = 0xA900_679B" in job
    assert "BOSMINER_CMD_LOC_LINE_HITS: usize = 27" in job
    assert "BOSMINER_CMD_EVENT_LINES: [u16; 4] = [594, 621, 656, 675]" in job
    assert "admit_bosminer_cmp8_six_post_poll_one_slot28_prelude" in job
    assert "refuse_seventh_cmp8_as_seventh_poll_or_named_slot28" in job
    assert "BOSMINER_POLL_CMP8_POST_POLL_HITS: usize = 6" in job
    assert "BOSMINER_POLL_CMP8_PRELUDE_HITS: usize = 1" in job
    assert "BOSMINER_SLOT28_PRELUDE_MOVZ8_INSN: u32 = 0x5280_011B" in job
    assert "BOSMINER_SLOT28_PRELUDE_BL_INSN: u32 = 0x97FF_E24D" in job
    assert "BOSMINER_CMD_PANIC_PAD_LINES: [u16; 4] = [418, 514, 693, 719]" in job
    assert "admit_bosminer_831314_is_tag10_drop_dispatcher" in job
    assert "refuse_831314_as_slot28_method_or_named_maybedone" in job
    assert "s19k_bosminer_831314_tag_arm" in job
    assert "BOSMINER_FN831314_VA: u64 = 0x0083_1314" in job
    assert "BOSMINER_FN831314_TAG_OFF: u16 = 0x10" in job
    assert "BOSMINER_FN831314_BL_HITS: usize = 2" in job
    assert "BOSMINER_FN831314_LDRB10_INSN: u32 = 0x3940_4008" in job
    assert "BOSMINER_FN831314_TAG46_TARGET: u64 = 0x0083_1D18" in job
    assert "BOSMINER_FN831314_BODY_LOC_HITS: usize = 0" in job
    assert "admit_bosminer_831d18_831668_are_drop_siblings" in job
    assert "refuse_drop_sibs_as_one_fn_or_named_slot_or_arc" in job
    assert "s19k_bosminer_drop_sib_tag_off" in job
    assert "BOSMINER_FN831D18_VA: u64 = 0x0083_1D18" in job
    assert "BOSMINER_FN831668_VA: u64 = 0x0083_1668" in job
    assert "BOSMINER_FN831D18_TAG_OFF: u16 = 0x19" in job
    assert "BOSMINER_FN831668_TAG_OFF: u16 = 0x70" in job
    assert "BOSMINER_FN831D18_BL_HITS: usize = 12" in job
    assert "BOSMINER_FN831668_BL_HITS: usize = 6" in job
    assert "BOSMINER_DROP_SIB_HELPER_VA: u64 = 0x011F_2764" in job
    assert "BOSMINER_FN831D18_HC68_HITS: usize = 4" in job
    assert "BOSMINER_DROP_SIB_BODY_LOC_HITS: usize = 0" in job
    assert "admit_bosminer_11f2764_is_refcount_helper_jt68_from_240" in job
    assert "refuse_11f2764_as_named_arc_or_jt68_as_hashchain" in job
    assert "s19k_bosminer_refcount_overflow_cap" in job
    assert "BOSMINER_FN11F2764_VA: u64 = 0x011F_2764" in job
    assert "BOSMINER_FN11F2764_BL_HITS: usize = 557" in job
    assert "BOSMINER_FN11F2764_MOVZ1_PREV_HITS: usize = 537" in job
    assert "BOSMINER_FN11F2764_LDXR_INSN: u32 = 0x085F_FC08" in job
    assert 'BOSMINER_REFCOUNT_OVERFLOW_MSG: &str = "reference count overflow!"' in job
    assert "BOSMINER_JT_PLUS68_STR_INSN: u32 = 0xF900_3660" in job
    assert "BOSMINER_JT_PLUS108_OFF: u16 = 0x108" in job
    assert "BOSMINER_FN11F26F8_TO_764_DELTA: u16 = 0x6C" in job
    assert "admit_bosminer_121e588_is_parking_lot_tls" in job
    assert "refuse_121e588_as_arc_inc_or_drop" in job
    assert "s19k_bosminer_121e588_tls_off" in job
    assert "BOSMINER_FN121E588_VA: u64 = 0x0121_E588" in job
    assert "BOSMINER_FN121E588_TLS_OFF: u16 = 0x280" in job
    assert "BOSMINER_FN121E588_BL_HITS: usize = 681" in job
    assert "BOSMINER_FN121E588_MRS_INSN: u32 = 0xD53B_D048" in job
    assert "BOSMINER_PARK_1226_LINE: u16 = 1226" in job
    assert "BOSMINER_PARK_1226_COL: u16 = 58" in job
    assert "BOSMINER_FN11F2764_TLS_BL_INSN: u32 = 0x9400_AF7E" in job
    assert (
        'BOSMINER_PARK_RS_SUFFIX: &str = "parking_lot_core-0.9.10/src/parking_lot.rs"'
        in job
        or 'BOSMINER_PARK_RS_SUFFIX: &str =\n    "parking_lot_core-0.9.10/src/parking_lot.rs"'
        in job
    )
    assert "admit_bosminer_slot28_is_zero_arg_fat_future" in job
    assert "refuse_slot28_as_named_command_or_packing" in job
    assert "s19k_bosminer_slot28_extra_x1" in job
    assert "BOSMINER_FAT_SLOT28_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT28_X1_WRITES: usize = 0" in job
    assert "BOSMINER_FAT_SLOT28_BLR_INSN: u32 = 0xD63F_0100" in job
    assert "BOSMINER_FAT_SLOT28_DATA_LDR_INSN: u32 = 0xF941_1900" in job
    assert "BOSMINER_FAT_SLOT28_JOIN_TARGET: u64 = 0x0083_6F60" in job
    assert "admit_bosminer_slot30_is_x1_arg_fat_future" in job
    assert "refuse_slot30_as_named_send_work_or_other_ldr30" in job
    assert "s19k_bosminer_slot30_extra_x1" in job
    assert "BOSMINER_FAT_SLOT30_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT30_X1_WRITES: usize = 1" in job
    assert "BOSMINER_FAT_SLOT30_BLR_INSN: u32 = 0xD63F_0100" in job
    assert "BOSMINER_FAT_SLOT30_DATA_LDR_INSN: u32 = 0xF941_1900" in job
    assert "BOSMINER_FAT_SLOT30_JOIN_TARGET: u64 = 0x0083_7054" in job
    assert "BOSMINER_FAT_SLOT30_JOIN_B_INSN: u32 = 0x17FF_FD20" in job
    assert "BOSMINER_FAT_SLOT30_OTHER_LDR30_INSN: u32 = 0xF940_1AC8" in job
    assert "admit_bosminer_slot30_x1_is_poll_self_frame10" in job
    assert "refuse_frame10_as_cmd700_future10_or_hashchain10" in job
    assert "s19k_bosminer_frame10_str_hits" in job
    assert "BOSMINER_FRAME10_STR_HITS: usize = 0" in job
    assert "BOSMINER_JT_POLL_X19_MOV_INSN: u32 = 0xAA00_03F3" in job
    assert "BOSMINER_JT_POLL_CX_MOV_INSN: u32 = 0xAA01_03F5" in job
    assert "BOSMINER_FRAME10_ERR_LDR_INSN: u32 = 0xF940_0A79" in job
    assert "BOSMINER_FRAME10_ERR_B_INSN: u32 = 0x1400_06C7" in job
    assert "BOSMINER_FRAME10_ERR_TARGET: u64 = 0x0083_8CD8" in job
    assert "BOSMINER_HC_OBJ_STP10_INSN: u32 = 0xA901_6289" in job
    assert "admit_bosminer_slot38_is_zero_arg_family_b_fat_future" in job
    assert "refuse_slot38_as_x1_sibling_or_named_command" in job
    assert "s19k_bosminer_slot38_extra_x1" in job
    assert "BOSMINER_FAT_SLOT38_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT38_X1_WRITES: usize = 0" in job
    assert "BOSMINER_FAT_SLOT38_BLR_INSN: u32 = 0xD63F_0100" in job
    assert "BOSMINER_FAT_SLOT38_POLL_VA: u64 = 0x0083_7674" in job
    assert "BOSMINER_FAT_SLOT38_PRE_X1_LDR_INSN: u32 = 0xF940_0829" in job
    assert "admit_bosminer_slot40_is_zero_arg_copy18_fat_future" in job
    assert "refuse_slot40_as_sret50_or_x1_or_named_command" in job
    assert "s19k_bosminer_slot40_extra_x1" in job
    assert "BOSMINER_FAT_SLOT40_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT48_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT50_PATTERN_HITS: usize = 0" in job
    assert "BOSMINER_FAT_SLOT78_PATTERN_HITS: usize = 1" in job
    assert "BOSMINER_FAT_SLOT40_X1_WRITES: usize = 0" in job
    assert "BOSMINER_FAT_SLOT40_SRC18_LDR_INSN: u32 = 0xF940_0E68" in job
    assert "BOSMINER_FAT_SLOT40_COPY0_STR_INSN: u32 = 0xF900_0268" in job
    assert "BOSMINER_FAT_SLOT40_JOIN_TARGET: u64 = 0x0083_6FE4" in job
    assert "admit_bosminer_slot48_is_zero_arg_immediate_fat_future" in job
    assert "refuse_slot48_as_copy18_or_named_command" in job
    assert "s19k_bosminer_slot48_extra_x1" in job
    assert "BOSMINER_FAT_SLOT48_X1_WRITES: usize = 0" in job
    assert "BOSMINER_FAT_SLOT48_POLL_VA: u64 = 0x0083_8638" in job
    assert "BOSMINER_FAT_SLOT48_COPY30_STR_INSN: u32 = 0xF900_1A68" in job
    assert "admit_bosminer_slot78_is_ldp_family_b_fat_future" in job
    assert "refuse_slot78_as_slot30_or_named_hashchain_336" in job
    assert "s19k_bosminer_slot78_extra_x1" in job
    assert "BOSMINER_FAT_SLOT78_LDP_INSN: u32 = 0xA943_0668" in job
    assert "BOSMINER_FAT_SLOT78_JOIN_B_INSN: u32 = 0x17FF_FDE5" in job
    assert "BOSMINER_FAT_SLOT78_JOIN_TARGET: u64 = 0x0083_757C" in job
    assert "BOSMINER_FAT_SLOT78_X1_FROM_LDP: bool = true" in job
    assert "admit_bosminer_future18_is_construct_time_fat_host" in job
    assert "refuse_future18_as_cmd700_or_named_hashchain_field" in job
    assert "s19k_bosminer_future18_jt_str_hits" in job
    assert "BOSMINER_FUTURE18_JT_STR_HITS: usize = 0" in job
    assert "BOSMINER_HC_INIT_PLUS18_LDR_INSN: u32 = 0xF940_0E68" in job
    assert "admit_bosminer_future_clone_copies_sp8_and_returns_vtable" in job
    assert "refuse_future_clone_as_91000c_or_named_stack_filler" in job
    assert "s19k_bosminer_future_clone_bl_hits" in job
    assert "BOSMINER_FUTURE_VT_VA: u64 = 0x019B_BAE8" in job
    assert "BOSMINER_FUTURE_VT_SIZE: u64 = 0x188" in job
    assert "BOSMINER_FUTURE_VT_POLL: u64 = 0x0083_6E2C" in job
    assert "BOSMINER_FUTURE_VT_DROP: u64 = 0x0083_1814" in job
    assert "BOSMINER_FUTURE_CLONE_VA: u64 = 0x0083_6DA4" in job
    assert "BOSMINER_FUTURE_CLONE_BL_HITS: usize = 0" in job
    assert "BOSMINER_FUTURE_CLONE_VT_ADD_INSN: u32 = 0x912B_A021" in job
    assert "BOSMINER_FUTURE_VT_ADD_IMM: u16 = 0xAE8" in job
    assert "admit_bosminer_clone_fills_sp8_x0_as_future18" in job
    assert "refuse_sp8_filler_as_separate_fn_or_sib188" in job
    assert "s19k_bosminer_clone_x0_is_future18" in job
    assert "s19k_bosminer_clone_writes_future10" in job
    assert "BOSMINER_FUTURE_TMPL_X0_STR_INSN: u32 = 0xF900_13E0" in job
    assert "BOSMINER_FUTURE_TMPL_ST21_INSN: u32 = 0x3900_A7FF" in job
    assert "BOSMINER_FUTURE_TMPL_ST22_INSN: u32 = 0x3900_ABE1" in job
    assert "BOSMINER_FUTURE_TMPL_X0_SP_OFF: u16 = 0x20" in job
    assert "BOSMINER_OWNER260_SIZE: u16 = 0x260" in job
    assert "BOSMINER_SIB188_X0_STR_INSN: u32 = 0xF900_07E0" in job
    assert "BOSMINER_SIB188_VT_ADD_IMM: u16 = 0x1A8" in job
    assert "admit_bosminer_slot50_is_sret_host30_x1_38" in job
    assert "refuse_slot50_as_poll9_or_zero_arg_fat" in job
    assert "s19k_bosminer_slot50_extra_x1" in job
    assert "s19k_bosminer_slot50_is_poll_tag9" in job
    assert "BOSMINER_FAT_SLOT50_LDR_PRE38_INSN: u32 = 0xF843_8F81" in job
    assert "BOSMINER_FAT_SLOT50_LDUR_M8_INSN: u32 = 0xF85F_8388" in job
    assert "BOSMINER_FAT_SLOT50_LDP_INSN: u32 = 0xA956_53EA" in job
    assert "BOSMINER_FAT_SLOT50_SRET_SIZE: u16 = 0x28" in job
    assert "BOSMINER_FAT_SLOT50_X1_WRITES: usize = 1" in job
    assert "admit_bosminer_owner260_drop_has_fat230" in job
    assert "refuse_owner260_as_hashchain_or_named_hashboard" in job
    assert "s19k_bosminer_owner260_is_hashchain" in job
    assert "BOSMINER_OWNER260_DROP_FN_VA: u64 = 0x0087_3D10" in job
    assert "BOSMINER_OWNER260_BOXER_ADD_IMM: u16 = 0x798" in job
    assert "BOSMINER_OWNER260_BOXER_MOVZ260_INSN: u32 = 0x5280_4C00" in job
    assert "BOSMINER_HW200_LINE: u16 = 200" in job
    assert "admit_bosminer_40c2c4_has_4_bls_three_jt160" in job
    assert "refuse_40c2c4_as_named_from_backtrace" in job
    assert "s19k_bosminer_40c2c4_bl_hits" in job
    assert "BOSMINER_SLOT50_CONV_BL_HITS: usize = 4" in job
    assert "BOSMINER_SLOT50_CONV_JT160_HITS: usize = 3" in job
    assert "BOSMINER_SLOT50_CONV_ADD0_INSN: u32 = 0x9105_83E0" in job
    assert "BOSMINER_SLOT50_CONV_OTHER_ADD_INSN: u32 = 0x9100_C3E0" in job
    assert "BOSMINER_BACKTRACE_HELPER_BL_HITS: usize = 171" in job
    assert "admit_bosminer_future10_writer_is_poll_copy48" in job
    assert "refuse_future10_as_context_or_clone_template" in job
    assert "s19k_bosminer_future10_jt_str_x19_hits" in job
    assert "s19k_bosminer_future10_is_context" in job
    assert "BOSMINER_FUTURE10_STR_INSN: u32 = 0xF900_0988" in job
    assert "BOSMINER_FUTURE10_ALIAS_MOV_INSN: u32 = 0xAA13_03EC" in job
    assert "BOSMINER_FUTURE10_SRC48_LDR_INSN: u32 = 0xF940_2668" in job
    assert "BOSMINER_FUTURE10_SRC48_OFF: u16 = 0x48" in job
    assert "BOSMINER_FUTURE10_JT_STR_X19_HITS: usize = 0" in job
    assert "BOSMINER_FUTURE10_JT_STR_X21_HITS: usize = 0" in job
    assert "BOSMINER_FUTURE10_JOIN_TARGET: u64 = 0x0083_72E8" in job
    assert "admit_bosminer_future48_is_tokio_mutex_lock" in job
    assert "refuse_future48_as_fat_slot_or_c0d4ac_or_lock_owned" in job
    assert "s19k_bosminer_mutex_lock_poll_bl_hits" in job
    assert "BOSMINER_MUTEX_LOCK_POLL_BL_HITS: usize = 9" in job
    assert "BOSMINER_MUTEX_LOCK_LINE: u16 = 434" in job
    assert "BOSMINER_MUTEX_UNREACHABLE_LINE: u16 = 657" in job
    assert "BOSMINER_MUTEX_LOCK_TAG70_OFF: u16 = 0x70" in job
    assert "BOSMINER_MUTEX_RS_PATH_LEN: u16 = 157" in job
    assert "BOSMINER_FUTURE48_STR_INSN: u32 = 0xF900_2668" in job
    assert "BOSMINER_MUTEX_LOCK_TAG70_LDRB_INSN: u32 = 0x3941_C008" in job
    assert "admit_bosminer_host240_is_70_ptr_mutex_at_28" in job
    assert "refuse_host240_as_hashchain_1e8_or_as_mutex" in job
    assert "s19k_bosminer_host240_is_mutex" in job
    assert "s19k_bosminer_host240_is_hashchain" in job
    assert "s19k_bosminer_host240_jt_ldr_hits" in job
    assert "BOSMINER_HOST240_JT_LDR_HITS: usize = 12" in job
    assert "BOSMINER_HOST240_CTOR70_STR_HITS: usize = 1" in job
    assert "BOSMINER_HOST240_BOX_SIZE: u16 = 0x70" in job
    assert "BOSMINER_HOST240_MUTEX_OFF: u16 = 0x28" in job
    assert "BOSMINER_HOST240_LDR_HOST_INSN: u32 = 0xF940_0268" in job
    assert "BOSMINER_HOST240_DROP_ADD_INSN: u32 = 0x9109_0260" in job
    assert "BOSMINER_HOST240_NULL_STR_INSN: u32 = 0xF901_227F" in job
    assert "admit_bosminer_host240_plus10_is_common_proj" in job
    assert "refuse_mutex_start_as_plus28_or_named_arc" in job
    assert "s19k_bosminer_host240_add10_hits" in job
    assert "BOSMINER_HOST240_ADD10_HITS: usize = 12" in job
    assert "BOSMINER_HOST240_ADD18_HITS: usize = 1" in job
    assert "BOSMINER_HOST248_OFF: u16 = 0x248" in job
    assert "BOSMINER_HOST248_DROP_TGT_VA: u64 = 0x0092_462C" in job
    assert "BOSMINER_HOST240_ALT48_STR_INSN: u32 = 0xF900_2668" in job
    assert "BOSMINER_HOST248_WEAK_LDAXR_INSN: u32 = 0xC85F_7D09" in job
    assert "admit_bosminer_9247b0_is_counted_fat_drop" in job
    assert "refuse_9247b0_as_mutex_or_named_vec" in job
    assert "s19k_bosminer_9247b0_bl_hits" in job
    assert "BOSMINER_9247B0_BL_HITS: usize = 4" in job
    assert "BOSMINER_9247B0_ADD10_CALLERS: usize = 3" in job
    assert "BOSMINER_9247B0_LEN_OFF: u16 = 0x10" in job
    assert "BOSMINER_9247B0_PTR_OFF: u16 = 0x08" in job
    assert "BOSMINER_9247B0_STRIDE: u16 = 0x10" in job
    assert "BOSMINER_9247B0_LEN_LDR_INSN: u32 = 0xF940_0815" in job
    assert "BOSMINER_9247B0_LDP_INSN: u32 = 0xA97E_CED4" in job
    assert "BOSMINER_9247B0_DEALLOC_BL_INSN: u32 = 0x97F3_409F" in job
    assert "admit_bosminer_host248_inner_is_30_not_70" in job
    assert "refuse_9247b0_elem_as_mutex_or_248_as_240" in job
    assert "s19k_bosminer_92462c_bl_hits" in job
    assert "BOSMINER_92462C_BL_HITS: usize = 81" in job
    assert "BOSMINER_HOST248_INNER_SIZE: u16 = 0x30" in job
    assert "BOSMINER_92462C_JT_BL_HITS: usize = 1" in job
    assert "BOSMINER_92462C_JT_ADD_OFF: u16 = 0x270" in job
    assert "BOSMINER_HOST248_INNER_SIZE_INSN: u32 = 0x5280_0601" in job
    assert "BOSMINER_92462C_JT_BL_INSN: u32 = 0x9403_B815" in job
    assert "BOSMINER_92462C_EXTRA18_LDR_INSN: u32 = 0xF940_0E60" in job
    assert "admit_bosminer_mutex_starts_at_data18_and_248_t_is_20" in job
    assert "refuse_mutex_at_data0_or_named_248_t" in job
    assert "s19k_bosminer_mutex_self_is_stored_ptr" in job
    assert "BOSMINER_HOST240_DATA_PREFIX: u16 = 0x18" in job
    assert "BOSMINER_HOST248_T_SIZE: u16 = 0x20" in job
    assert "BOSMINER_HOST248_T_BUF_OFF: u16 = 0x08" in job
    assert "BOSMINER_HOST248_T_LEN_OFF: u16 = 0x10" in job
    assert "BOSMINER_HOST248_T_EXTRA_OFF: u16 = 0x18" in job
    assert "BOSMINER_LOCK_POLL_SELF_LDR_INSN: u32 = 0xF940_0268" in job
    assert "BOSMINER_LOCK_POLL_ACQ_ADD_INSN: u32 = 0x9100_A260" in job
    assert "BOSMINER_LOCK_POLL_ACQ_FN_VA: u64 = 0x011F_2DE4" in job
    assert "admit_bosminer_prefix_opaque_and_elem_box_shaped" in job
    assert "refuse_prefix_as_named_vec_or_586cd8_as_jt_walker" in job
    assert "s19k_bosminer_prefix_jt_field_ldr_hits" in job
    assert "BOSMINER_PREFIX_JT_FIELD_LDR_HITS: usize = 0" in job
    assert "BOSMINER_586CD8_BL_HITS: usize = 66" in job
    assert "BOSMINER_586CD8_JT_BL_HITS: usize = 0" in job
    assert "BOSMINER_586CD8_STRIDE: u16 = 0x18" in job
    assert "BOSMINER_586CD8_STRIDE_MOVZ_INSN: u32 = 0x5280_0309" in job
    assert "BOSMINER_586CD8_MADD_INSN: u32 = 0x9B09_2908" in job
    assert "BOSMINER_9247B0_ELEM_IS_BOX_SHAPED: bool = true" in job
    assert "admit_bosminer_host240_clone_str_x25" in job
    assert "refuse_cec094_or_51a8c8_as_host240_ctor" in job
    assert "BOSMINER_HOST240_CLONE_STR240_INSN: u32 = 0xF901_2299" in job
    assert "BOSMINER_HOST240_CLONE_BL_HITS: usize = 0" in job
    assert "BOSMINER_HOST240_CLONE_STR240_UNIQUE: usize = 1" in job
    assert "BOSMINER_HOST240_NONSP_NONNULL_STR_HITS: usize = 54" in job
    assert "BOSMINER_HOST240_CLONE_MEMCPY_LEN: u16 = 0x230" in job
    assert "BOSMINER_HOST240_CLONE_X25_LDR_INSN: u32 = 0xF940_07F9" in job
    assert "admit_bosminer_clone_real_entry_is_835220" in job
    assert "refuse_835234_as_fn_entry_or_70_first_alloc" in job
    assert "BOSMINER_HOST240_CLONE_REAL_ENTRY_VA: u64 = 0x0083_5220" in job
    assert "BOSMINER_HOST240_CLONE_REAL_ENTRY_INSN: u32 = 0xF81B_0FFD" in job
    assert "BOSMINER_HOST240_CLONE_REAL_BL_HITS: usize = 1" in job
    assert "BOSMINER_HOST240_CLONE_VT_QWORD_HITS: usize = 0" in job
    assert "BOSMINER_HOST240_CLONE_CALLER_VA: u64 = 0x0087_E1CC" in job
    assert "BOSMINER_HOST240_CLONE_CALLER_INSN: u32 = 0x97FE_DC15" in job
    assert "BOSMINER_HOST240_CLONE_CALLER_X1_MOV_INSN: u32 = 0xAA18_03E1" in job
    assert "BOSMINER_60B0FC_BL_HITS: usize = 27" in job
    assert "BOSMINER_681768_BL_HITS: usize = 99" in job
    assert "BOSMINER_749C58_ALLOC_SIZE: u16 = 0x228" in job
    assert "BOSMINER_749C58_STR240_INSN: u32 = 0xF901_2276" in job
    assert "s19k_bosminer_clone_real_entry_bl_hits" in job
    assert "admit_bosminer_sp78_is_sret10_of_blr23" in job
    assert "refuse_sp78_as_field_or_87deb4_as_named_x24" in job
    assert "BOSMINER_SP78_SRET_ADD_INSN: u32 = 0x9101_A3E8" in job
    assert "BOSMINER_SP78_BLR23_INSN: u32 = 0xD63F_02E0" in job
    assert "BOSMINER_SP78_LDR78_INSN: u32 = 0xF940_3FE8" in job
    assert "BOSMINER_SP78_STR78_HITS: usize = 0" in job
    assert "BOSMINER_87DEB4_BL_HITS: usize = 0" in job
    assert "BOSMINER_87DEB4_IS_X24_MINT: bool = false" in job
    assert "BOSMINER_87DEB4_MOVZ70_INSN: u32 = 0x5280_0E00" in job
    assert "s19k_bosminer_87e02c_str78_hits" in job
    assert "admit_bosminer_hashmap_v_is_18_spawn0_factory8" in job
    assert "refuse_sret18_as_hashmap_v_or_named_result" in job
    assert "BOSMINER_HASHMAP_GET_BL_HITS: usize = 3" in job
    assert "BOSMINER_HASHMAP_GET_BL_B_INSN: u32 = 0x9401_056C" in job
    assert "BOSMINER_CLONE_GET_TBZ_INSN: u32 = 0x3600_03A0" in job
    assert "BOSMINER_SRET18_Q0_CBZ_INSN: u32 = 0xB400_1073" in job
    assert "BOSMINER_SRET18_Q2_LDAXR_INSN: u32 = 0xC85F_7D09" in job
    assert "BOSMINER_SRET18_IS_HASHMAP_V: bool = false" in job
    assert "BOSMINER_HASHMAP_V0_IS_FACTORY4: bool = false" in job
    assert "BOSMINER_HASHMAP_V8_IS_VT0: bool = false" in job
    assert "BOSMINER_SPAWN_W0_TEST_IS_TBNZ: bool = true" in job
    assert "s19k_bosminer_hashmap_get_bl_hits" in job
    assert "admit_bosminer_hashmap_v_is_chipid_factory_tuple" in job
    assert "refuse_hashmap_v_as_occupied_entry_or_named_type" in job
    assert "BOSMINER_HASHMAP_V_CTOR_VA: u64 = 0x0086_2458" in job
    assert "BOSMINER_HASHMAP_V_CTOR_PROLOGUE_INSN: u32 = 0xD104_C3FF" in job
    assert "BOSMINER_HASHMAP_V_INSERT_UNROLL: usize = 7" in job
    assert "BOSMINER_HASHMAP_V_SLOT_STRIDE: u16 = 0x20" in job
    assert "BOSMINER_HASHMAP_V_1366_STRH_INSN: u32 = 0x7900_A3EA" in job
    assert "BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_INSN: u32 = 0x9400_1683" in job
    assert "BOSMINER_HASHMAP_V_TYPE_NAMED: bool = false" in job
    assert "BOSMINER_HASHMAP_V_IS_OCCUPIED_ENTRY: bool = false" in job
    assert "BOSMINER_HASHBROWN_0145_MOD86_XREF_VA: u64 = 0x0040_3294" in job
    assert "s19k_bosminer_hashmap_v_key_count" in job
    rx = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_bm1366_uart_resp_body_len" in rx
    assert "refuse_bm139x_default_body7_as_bm1366_uart" in rx
    assert "refuse_response_bytes_11_as_set_response_len" in rx
    assert "BM1366_UART_RESP_BODY_LEN: usize = 9" in rx
    assert "BM139X_HAL_DEFAULT_RESP_BODY_LEN: usize = 7" in rx
    assert "SET_RESPONSE_LEN_11_AS_BODY_WIRE: usize = 2 + UART_RESP_LEN" in rx
    assert "classify_s19k_dual_uart_rx_after" in rx
    assert "refuse_one_port_work_as_dual_chain_proof" in rx
    share = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_s19k_constructed_fill_hunts_and_headers" in share
    assert "admit_s19k_fill_header_uses_workentry_prev_not_wire" in share
    assert "s19k_workentry_prev_from_stratum" in share
    assert "S19K_STRATUM_PREV_ASYM" in share
    assert "admit_s19k_production_header_uses_workentry_prev" in share
    assert "s19k_bm1366_fill_header80" in share
    assert "S19K_CONSTRUCTED_FILL_BASE_VERSION: u32 = 0x2000_2000" in share
    assert "refuse_constructed_fill_header_as_bip320_strip" in share
    discover = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8")
    assert "S19kDualWorkRxJoin" in discover
    assert "admit_s19k_production_joins_dual_uart_after_fill" in discover
    serial = (ROOT / "dcentrald/dcentrald/src/serial_mining.rs").read_text(
        encoding="utf-8"
    )
    assert "dual_work_rx.record(" in serial
    assert "S19k dual-UART WorkDispatch join (does not drop this nonce)" in serial
    assert "SinglePortNotDualProof" in rx
    assert "admit_s19k_production_set_response_len_is_bm1366_body" in rx
    install_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_install.rs"
    ).read_text(encoding="utf-8")
    assert "refuse_s19k_backup_ledger_without_nandrecovery_sidecar" in install_rs
    assert "backup ledger missing nandrecovery_env sidecar" in install_rs
    restore = (ROOT / "scripts/restore_amlogic_mtd5_from_backup.sh").read_text(
        encoding="utf-8"
    )
    assert "nandrecovery_env.bin" in restore
    assert "nand_env.bak is not recover_env" in restore
    assert "s19k_nand_env_crc.py" in restore
    assert "nandrecovery_env.bin CRC32 mismatch" in restore
    assert "cannot CRC-admit nandrecovery_env.bin" in restore
    assert "nandrecovery_env_crc_ok=true" in restore
    assert "nand_env_crc_ok=true" in restore
    assert "recover_env_source=nandrecovery_env.bin" in restore
    assert "recover_env_source=nand_env.bak" not in restore
    assert "admit_s19k_restore_sidecar_crc" in install_rs
    assert "format_s19k_restore_crc_admit" in install_rs
    assert "admit_s19k_restore_script_crc_admits_sidecar" in install_rs
    assert "admit_s19k_restore_script_sidecar_matches_mtd5_slice" in install_rs
    assert "dcent_am3_extract_nandrecovery_env" in restore
    assert "nandrecovery_env.bin does not match mtd5 slice" in restore
    assert "nandrecovery_env_matches_mtd5_slice=true" in restore
    assert restore.find("dcent_am3_extract_nandrecovery_env") < restore.find(
        "VERIFY_OK hashes match ledger"
    )
    assert "admit_s19k_restore_script_sidecar_sha256" in install_rs
    assert "refuse_s19k_hashless_ledger_formatter_as_restore_complete" in install_rs
    assert "admit_s19k_hashed_ledger_formatter_emits_sidecar_sha" in install_rs
    job_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_job.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_s19k_bosminer_scan_scripts" in job_rs
    memcpy_scan = (ROOT / "scripts/s19k_scan_bosminer_memcpy_sizes.py").read_text(
        encoding="utf-8"
    )
    assert "Does not close T1" in memcpy_scan
    assert "0x36" in memcpy_scan
    assert "0x56" in memcpy_scan
    assert "U86_AT_0xe80871" in (
        ROOT / "scripts/s19k_scan_bosminer_genericarray.py"
    ).read_text(encoding="utf-8")
    assert "55AA2136" in (ROOT / "scripts/s19k_scan_bosminer_job_bytes.py").read_text(
        encoding="utf-8"
    )
    assert "missing nandrecovery_env_sha256" in restore
    assert "nandrecovery_env.bin sha256 drift" in restore
    assert "nandrecovery_env_sha256_ok=true" in restore
    assert restore.find("nandrecovery_env.bin sha256 drift") < restore.find(
        "VERIFY_OK hashes match ledger"
    )
    discover = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8")
    assert "do not invent `AA 55` + HAL body-7" in discover
    assert "refuse_hal_body7_observe_as_silence" in discover
    assert "note_empty_if_unseen" in discover
    assert "admit_s19k_production_records_empty_work_polls" in discover
    assert "classify_s19k_bm1366_rx_after" in (
        ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "S19kRxExpectedAfter::InitRearm" in (
        ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
    ).read_text(encoding="utf-8", errors="replace")
    rx_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs").read_text(
        encoding="utf-8"
    )
    assert "RearmRegOk" in rx_rs
    assert "SetAddressEcho" in rx_rs
    assert "bm1366_rearm_ticket_reply_uart" in rx_rs
    assert "bm1366_rearm_hcn_reply_uart" in rx_rs
    assert "refuse_esp_a4_reply_as_fill_rearm_ok" in rx_rs
    assert "admit_s19k_production_classifies_init_rearm_rx" in rx_rs
    assert "note_empty_if_unseen" in (
        ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
    ).read_text(encoding="utf-8", errors="replace")
    hal = (ROOT / "dcentrald/dcentrald-hal/src/serial_chain.rs").read_text(
        encoding="utf-8"
    )
    assert "pub const BM1366_UART_RESP_BODY_LEN: usize = 9" in hal
    assert "const DEFAULT_RESP_BODY_LEN: usize = 7" in hal
    assert "admit_bosminer_11f2de4_is_acquire_poll" in job
    assert "refuse_11f2de4_as_raw_mutex_or_standalone_poll_acquire" in job
    assert "s19k_bosminer_acquire_poll_bl_hits" in job
    assert "BOSMINER_ACQUIRE_POLL_BL_HITS: usize = 34" in job
    assert "BOSMINER_ACQUIRE_POLL_JT_BL_HITS: usize = 0" in job
    assert "BOSMINER_ACQUIRE_POLL_TLS_OFF: u16 = 0x40" in job
    assert "BOSMINER_ACQUIRE_POLL_X1_MOV_INSN: u32 = 0xAA01_03F5" in job
    assert "BOSMINER_ACQUIRE_POLL_MRS_INSN: u32 = 0xD53B_D058" in job
    assert "BOSMINER_ACQUIRE_POLL_LOC425_LINE: u32 = 425" in job
    assert "BOSMINER_ACQUIRE_POLL_LOC493_LINE: u32 = 493" in job
    assert "BOSMINER_ACQUIRE_POLL_COOP_LINE: u32 = 345" in job
    assert "BOSMINER_BATCH_SEMAPHORE_RS" in job
    assert "BOSMINER_COOP_MOD_RS" in job
    assert "s19k_braiins_uart_nonce_arg_from_payload8" in job
    assert "s19k_braiins_midstate_log_from_count" in job
    assert "admit_bosminer_work_resp_rev_then_nonce_fn" in job
    assert "refuse_rev_w0_ret_as_engine_nonce_fn" in job
    assert "refuse_mul_lslv_ret_as_named_job_id_encoder" in job
    assert "BOSMINER_WORK_RESP_REV_INSN: u32 = 0x5AC0_0B00" in job
    assert "BOSMINER_WORK_RESP_LDR88_INSN: u32 = 0xF940_4428" in job
    assert "BOSMINER_WORK_RESP_BLR_INSN: u32 = 0xD63F_0100" in job
    assert "BOSMINER_BM1366_FACTORY_FN_VA: u64 = 0x0087_6CA8" in job
    assert "admit_bosminer_1366_factory_is_876ca8" in job
    assert "admit_bosminer_clone_copies_plus88_qword" in job
    assert "BOSMINER_CLONE_LDUR_Q88_INSN: u32 = 0x3CC8_8285" in job
    assert "admit_bosminer_work_resp_blr_return_is_nonce" in job
    assert "refuse_plus80_ne1_as_alt_nonce_transform" in job
    assert "refuse_ret_only_as_named_plus88" in job
    assert "admit_bosminer_plus80_is_work_type_tag" in job
    assert "refuse_midstates_work_type_on_braiins_fill_rx" in job
    assert "refuse_pic0x88_as_engine_plus88" in job
    assert "refuse_am3_future_plus80_as_work_type" in job
    assert "admit_bosminer_plus80_is_verwidth_tag" in job
    assert "refuse_verwidth_else_as_uart_fill_path" in job
    assert "refuse_verwidth_mid_entry_as_parse_bl_target" in job
    assert "BOSMINER_ENGINE_WORK_TYPE_OFF: usize = 0x80" in job
    assert "BOSMINER_WORK_TYPE_VERSION_ROLLING: u8 = 1" in job
    assert "BOSMINER_WORK_RESP_PLUS80_LINE: u16 = 344" in job
    assert "BOSMINER_ENGINE_VERWIDTH_SELF_OFF: usize = 0x60" in job
    assert "BOSMINER_VERWIDTH_PARSE_BL_TARGET_VA: u64 = 0x00BF_2478" in job
    assert "BOSMINER_VERWIDTH_CMP_VA: u64 = 0x00BF_247C" in job
    assert "refuse_factory_data_as_named_plus88" in job
    assert "admit_bosminer_factory_x1_is_runtime_x24" in job
    assert "refuse_bm1366_str88_result_as_engine_nonce_fn" in job
    assert "refuse_rustc_metadata_as_named_plus88" in job
    assert "BOSMINER_FACTORY_DATA_PTR_HITS: usize = 0" in job
    assert "BOSMINER_FACTORY_X1_FROM_X24_INSN: u32 = 0xAA18_03E1" in job
    assert "BOSMINER_RUSTC_VERSION" in job
    assert "BOSMINER_RUSTC_SECTION_PRESENT: bool = false" in job
    assert "BOSMINER_WORK_RESP_SAVE_X0_INSN: u32 = 0xAA00_03F6" in job
    assert "BOSMINER_RET_ONLY_SITES: usize = 269" in job
    assert "s19k_braiins_fill_nonce_word" in job
    assert "refuse_work_resp_low8_div_as_pool_nonce" in job
    assert "BOSMINER_MIDSTATE_COUNT_FN_VA: u64 = 0x0125_FC94" in job
    assert "BOSMINER_REV_W0_RET_HITS: usize = 0" in job
    assert "s19k_braiins_fill_job_id" in job
    assert "s19k_braiins_fill_midstate_log" in job
    assert "admit_bosminer_fill_path_job_id_is_work_id_shl_log" in job
    assert "refuse_am3_factory_as_first_writer_of_engine_fn_ptrs" in job
    assert "refuse_bf3264_as_engine_nonce_fn" in job
    assert "BOSMINER_FILL_MIDSTATE_LOG: u32 = 0" in job
    assert "BOSMINER_WORK_RESP_DIV_FN_VA: u64 = 0x00BF_3264" in job
    assert "BOSMINER_WORK_RESP_DIV_LDR_INSN: u32 = 0xF940_0008" in job
    assert "s19k_braiins_work_resp_index" in job
    assert "admit_bosminer_uart_work_resp_div_is_worker_plus_0x11c0" in job
    assert "refuse_fpga_0x340_as_uart_work_resp_div" in job
    assert "refuse_worker_ctor_str88_sp_as_engine_nonce_fn" in job
    assert "refuse_unnamed_0x11c0_value_as_chip_count" in job
    assert "refuse_asic_index_from_nonce_be_as_bf3264" in job
    assert "admit_bosminer_rx_object_is_wrapper_plus_0x10_copy" in job
    assert "refuse_serde_str_11c0_as_uart_div_writer" in job
    assert "refuse_hashchain_str88_self_plus_90_as_engine_nonce_fn" in job
    assert "BOSMINER_RX_WRAPPER_COPY_OFF: usize = 0x10" in job
    assert "BOSMINER_RX_WRAPPER_COPY_LEN: usize = 0x1390" in job
    assert "BOSMINER_WRAPPER_DIV_OFF: usize = 0x11D0" in job
    assert "BOSMINER_RX_WRAPPER_ADD_SRC_INSN: u32 = 0x9100_4261" in job
    assert "BOSMINER_RX_WRAPPER_SIZE_INSN: u32 = 0x5282_7202" in job
    assert "BOSMINER_HASHCHAIN_STR88_SELF_PTR_INSN: u32 = 0xF900_4674" in job
    assert "BOSMINER_HASHCHAIN_ADD90_INSN: u32 = 0x9102_4274" in job
    assert "admit_bosminer_hashchain_div_is_self_plus_0x11f0" in job
    assert "admit_bosminer_div_is_single_deref_udiv" in job
    assert "refuse_86e3d0_as_hashchain_spawn" in job
    assert "refuse_749200_halt_box_as_uart_div_writer" in job
    assert "BOSMINER_HASHCHAIN_DIV_OFF: usize = 0x11F0" in job
    assert "BOSMINER_HASHCHAIN_RX_COPY_OFF: usize = 0x30" in job
    assert "BOSMINER_HASHCHAIN_COPY_ADD_INSN: u32 = 0x9100_C261" in job
    assert "BOSMINER_TLS_DROP_MRS_INSN: u32 = 0xD53B_D056" in job
    assert "BOSMINER_WORK_RESP_DIV_UDIV_INSN: u32 = 0x9AC8_0920" in job
    assert "BOSMINER_HALT_BOX_STR_11F0_INSN: u32 = 0xF908_FA75" in job
    assert "refuse_ldr_11f0_as_uart_div_reader" in job
    assert "refuse_movz_11f0_as_field_addend" in job
    assert "BOSMINER_LDR_11F0_INSN: u32 = 0xF948_FA75" in job
    assert "BOSMINER_LDR_11F8_INSN: u32 = 0xF948_FE76" in job
    assert "BOSMINER_MOVZ_11F0_MEMCPY_INSN: u32 = 0x5282_3E02" in job
    assert "BOSMINER_ANTMINER_DRIVER_INIT_XREF_VA: u64 = 0x0083_7200" in job
    assert "refuse_1270_future_memcpy_as_div_writer" in job
    assert "refuse_ubfx_17_8_as_engine_nonce_fn" in job
    assert "refuse_add90_str88_sp_as_engine_nonce_fn" in job
    assert "BOSMINER_FUTURE_SNAP_SIZE_INSN: u32 = 0x5282_4E02" in job
    assert "BOSMINER_FUTURE_TAG2_INSN: u32 = 0xB900_3289" in job
    assert "BOSMINER_UBFX_17_8_INSN: u32 = 0x5311_60C6" in job
    assert "BOSMINER_ADD90_STR88_SP_INSN: u32 = 0xF900_47E8" in job
    assert "BOSMINER_OBJECT_30_1270_MEMCPY_HITS: usize = 54" in job
    assert "admit_bosminer_factory_x1_is_engine_template" in job
    assert "admit_bosminer_dispatch_1366_baud_is_3125k" in job
    assert "refuse_876398_str88_as_engine_nonce_fn" in job
    assert "refuse_str118_and_strw_11c0_as_named_writers" in job
    assert "BOSMINER_CLONE_SRC_MOV_INSN: u32 = 0xAA01_03F4" in job
    assert "BOSMINER_FACTORY_X1_LDR70_INSN: u32 = 0xF940_3B08" in job
    assert "BOSMINER_DISPATCH_BAUD_MOVZ_INSN: u32 = 0x5295_E109" in job
    assert "BOSMINER_AM3_FACTORY_BL_HITS: usize = 0" in job
    assert "admit_bosminer_factory_addr_only_dispatch_store" in job
    assert "refuse_factory_15f8_as_heap_div_writer" in job
    assert "refuse_slice10_str88_as_engine_nonce_fn" in job
    assert "BOSMINER_FACTORY_ADDR_ADD_INSN: u32 = 0x9132_A108" in job
    assert "BOSMINER_FACTORY_SNAP_SIZE_INSN: u32 = 0x5282_BF02" in job
    assert "BOSMINER_SLICE10_STR88_HITS: usize = 7" in job
    assert "admit_bosminer_factory_blr_is_get_value_plus_8" in job
    assert "refuse_sp1640_clone_as_named_div_integer" in job
    assert "BOSMINER_HASHMAP_GET_KEY_OFF: usize = 0x19C" in job
    assert "BOSMINER_FACTORY_LDR8_INSN: u32 = 0xF940_0437" in job
    assert "BOSMINER_FACTORY_BLR_INSN: u32 = 0xD63F_02E0" in job
    assert "BOSMINER_SP1640_CLONE_BL_INSN: u32 = 0x9400_2342" in job
    assert "refuse_83b3a0_as_engine_88_copy" in job
    assert "admit_bosminer_factory_x1_is_spawn_local738" in job
    assert "refuse_93cc3c_as_factory_x1" in job
    assert "admit_bosminer_value_plus8_is_bm1366_vt0" in job
    assert "BOSMINER_PREP_ADD_F0_INSN: u32 = 0x9103_C020" in job
    assert "BOSMINER_PREP_STR88_HITS: usize = 0" in job
    assert "BOSMINER_FACTORY_X1_LDR_SP78_INSN: u32 = 0xF940_3FE8" in job
    assert "BOSMINER_BM1366_VT0_FN_VA: u64 = 0x008D_BDF4" in job
    assert "admit_bosminer_vt0_is_prep_boxer" in job
    assert "refuse_dbdf4_as_engine_88_writer" in job
    assert "BOSMINER_VT0_LDRB_228_INSN: u32 = 0x3948_A008" in job
    assert "BOSMINER_VT0_COPY_230_INSN: u32 = 0x5280_4602" in job
    assert "BOSMINER_VT0_STR88_HITS: usize = 0" in job
    assert "admit_bosminer_tag228_ones_are_two_strb" in job
    assert "refuse_5f5a20_7c_as_vt0_tag" in job
    assert "refuse_prep_22c_as_vt0_tag" in job
    assert "BOSMINER_TAG1_STRB_HITS: usize = 2" in job
    assert "BOSMINER_TAG1_A_STRB_INSN: u32 = 0x3908_A26A" in job
    assert "refuse_7493e4_as_hashchain_tag228" in job
    assert "refuse_6079d4_as_hashchain_tag228" in job
    assert "admit_bosminer_prep_copies_hashchain_w228" in job
    assert "BOSMINER_HALT_SPLIT_ADD_INSN: u32 = 0x9140_0417" in job
    assert "BOSMINER_PREP_LDRW_228_INSN: u32 = 0xB942_2A9C" in job
    assert "BOSMINER_PREP_STRW_228_INSN: u32 = 0xB902_2A7C" in job
    assert "refuse_825568_2a0_as_first_228_writer" in job
    assert "refuse_878950_230_as_first_228_writer" in job
    assert "refuse_609a60_01000000_as_hashchain_tag" in job
    assert "BOSMINER_INSTANTIATE_SNAP_INSN: u32 = 0x5280_5402" in job
    assert "BOSMINER_INSTANTIATE_BUILD_230_INSN: u32 = 0x5280_4602" in job
    assert "BOSMINER_TAG228_W1000000_STR_INSN: u32 = 0xB902_2A68" in job
    assert "admit_am3_hashchain_init_has_no_228_store" in job
    assert "refuse_movz1_strw_as_hashchain_228" in job
    assert "BOSMINER_AM3_HC_INIT_STR228_HITS: usize = 0" in job
    assert "BOSMINER_TAG1_STRW_NONSP_HITS: usize = 0" in job
    assert "refuse_split_200_strb28_as_hashchain_228" in job
    assert "refuse_add228_strb0_as_hashchain_228" in job
    assert "admit_am3_hashchain_add228_is_panic_ptr" in job
    assert "BOSMINER_SPLIT_200_STRB28_HITS: usize = 0" in job
    assert "BOSMINER_AM3_HC_INIT_ADD228_INSN: u32 = 0x9108_A042" in job
    assert "BOSMINER_AM3_HC_INIT_ADD228_PANIC_HITS: usize = 10" in job
    assert "refuse_movz228_strb_regoff_as_hashchain_228" in job
    assert "refuse_add228_bl_strb_x0_as_hashchain_228" in job
    assert "refuse_9514c8_memcpy200_as_hashchain_228" in job
    assert "admit_dest228_memcpy_is_five_non_hashchain" in job
    assert "BOSMINER_MOVZ228_STRB_REGOFF_HITS: usize = 0" in job
    assert "BOSMINER_DEST228_MEMCPY_ADD_INSN: u32 = 0x9108_A2A0" in job
    assert "BOSMINER_DEST228_MEMCPY_SIZE_INSN: u32 = 0x5280_4002" in job
    assert "refuse_stp_xzr_as_hashchain_228_default" in job
    assert "refuse_1200524_as_memset" in job
    assert "refuse_wzr_228_stores_as_hashchain" in job
    assert "refuse_ticket_mask_836c20_as_hashchain_228" in job
    assert "BOSMINER_STP_XZR_220_228_NONSP_HITS: usize = 0" in job
    assert "BOSMINER_STR_XZR_228_NONSP_HITS: usize = 7" in job
    assert "BOSMINER_STR_XZR_228_INSN: u32 = 0xF901_167F" in job
    assert "BOSMINER_SLOT_SET_BL_HITS: usize = 358" in job
    assert "refuse_post_alloc_str228_as_hashchain" in job
    assert "admit_bosminer_btree_str228_is_child_slot" in job
    assert "refuse_mov_dest_memcpy_ge229_as_hashchain" in job
    assert "refuse_c6c594_2b0_as_hashchain" in job
    assert "BOSMINER_POST_ALLOC_STR228_NONSP_HITS: usize = 3" in job
    assert "BOSMINER_POST_ALLOC_STR228_INSN: u32 = 0xF901_1728" in job
    assert "BOSMINER_BTREE_STR220_228_HITS: usize = 17" in job
    assert "BOSMINER_BTREE_STR228_INSN: u32 = 0xF901_1419" in job
    assert "BOSMINER_MOV_DEST_228WIN_HITS: usize = 7" in job
    assert "BOSMINER_BASE_ADD0_MEMCPY_GE229_HITS: usize = 0" in job
    assert "BOSMINER_C6C594_MEMCPY_2B0_INSN: u32 = 0x5280_5602" in job
    assert "admit_bosminer_prep_has_three_bl_callers" in job
    assert "refuse_8258c0_as_first_228_writer" in job
    assert "admit_am3_hashchain_wrapper_is_future_poll" in job
    assert "refuse_stur_228_as_hashchain" in job
    assert "BOSMINER_PREP_BL_HITS: usize = 3" in job
    assert "BOSMINER_PREP_BL_A_INSN: u32 = 0x9400_5771" in job
    assert "BOSMINER_AM3_WRAP_HITS: usize = 5" in job
    assert "BOSMINER_AM3_WRAP_ADD18_INSN: u32 = 0x9100_6260" in job
    assert "BOSMINER_STUR_228_ANY_HITS: usize = 0" in job
    assert "admit_am3_wrap_has_ten_bl_callers" in job
    assert "admit_am3_wrap_caller_is_outer_future" in job
    assert "refuse_8e7454_as_hashchain_228" in job
    assert "BOSMINER_AM3_WRAP_BL_HITS: usize = 10" in job
    assert "BOSMINER_AM3_WRAP_CALLER_ADD20_INSN: u32 = 0x9100_8260" in job
    assert "BOSMINER_AM3_WRAP_CALLER_BL_INSN: u32 = 0x97FF_965E" in job
    assert "admit_bosminer_outer_future_box_is_180" in job
    assert "admit_bosminer_vtable_19c6b50_is_thunk_e7454" in job
    assert "refuse_8cb778_180_as_hashchain_228" in job
    assert "BOSMINER_OUTER_BOX_SIZE: usize = 0x180" in job
    assert "BOSMINER_OUTER_BOX_SIZE_INSN: u32 = 0x5280_3000" in job
    assert "BOSMINER_OUTER_VT_THUNK: u64 = 0x0084_CA74" in job
    assert "BOSMINER_OUTER_BOX_180_HITS: usize = 4" in job
    assert "admit_bosminer_8ce99c_boxes_and_schedules" in job
    assert "admit_bosminer_8b9504_is_runqueue_insert" in job
    assert "admit_am3_init_dest_is_box_plus_38" in job
    assert "refuse_8ce99c_as_hashchain_228" in job
    assert "BOSMINER_BOX_SCHED_TAG_INSN: u32 = 0x5280_1982" in job
    assert "BOSMINER_BOX_SCHED_ADD160_INSN: u32 = 0x9105_82C0" in job
    assert "BOSMINER_RUNQ_STR18_INSN: u32 = 0xF900_0C29" in job
    assert "BOSMINER_AM3_INIT_DEST_BOX_OFF: usize = 0x38" in job
    assert "admit_bosminer_8518d0_assembles_108_stack_image" in job
    assert "refuse_8518d0_param2_as_hashchain_pointer" in job
    assert "admit_bosminer_8518d0_bit0_selects_alt_boxer" in job
    assert "refuse_8518d0_as_hashchain_228" in job
    assert "BOSMINER_PARENT_IMAGE_ADD_INSN: u32 = 0x9106_83E1" in job
    assert "BOSMINER_PARENT_CE99C_BL_INSN: u32 = 0x9401_F3F9" in job
    assert "BOSMINER_PARENT_IMAGE_SIZE: usize = 0x108" in job
    assert "BOSMINER_ALT_BOX_FN_VA: u64 = 0x008C_C148" in job
    assert "admit_bosminer_8790dc_is_am2_s17_hashchain_msg_event" in job
    assert "admit_bosminer_8790dc_stages_108_at_sp_2cc0" in job
    assert "refuse_8790dc_2c70_as_hashchain_228_object" in job
    assert "refuse_8790dc_as_hashchain_228" in job
    assert "BOSMINER_MSG_EVT_SRC_LDR_INSN: u32 = 0xF956_3A6A" in job
    assert "BOSMINER_MSG_EVT_P2_ADD_LO_INSN: u32 = 0x9133_0021" in job
    assert "BOSMINER_MSG_EVT_STAGE_SP_OFF: usize = 0x2CC0" in job
    assert "BOSMINER_MSG_EVT_BL_HITS: usize = 0" in job
    assert "admit_bosminer_am3_add228_is_panic_loc" in job
    assert "refuse_am3_add228_as_hashchain_field" in job
    assert "admit_bosminer_am3_init_poll_tag_is_80" in job
    assert "BOSMINER_AM3_ADD228_ADRP_HITS: usize = 10" in job
    assert "BOSMINER_AM3_ADD228_ADRP_INSN: u32 = 0xD000_87A2" in job
    assert "BOSMINER_AM3_ADD228_LOC_VA: u64 = 0x019C_6228" in job
    assert "BOSMINER_AM3_INIT_TAG80_INSN: u32 = 0x3942_0008" in job
    assert "admit_bosminer_instantiate_x1_is_slot_deref" in job
    assert "admit_bosminer_5c78c_loads_hc_from_plus_260" in job
    assert "refuse_42bb8_as_hashchain_allocator" in job
    assert "refuse_682090_str228_as_hashchain" in job
    assert "BOSMINER_INST_X1_LDR_INSN: u32 = 0xF940_0341" in job
    assert "BOSMINER_SRC5C_LDR260_INSN: u32 = 0xF941_32A9" in job
    assert "BOSMINER_VEC228_INSN: u32 = 0xF901_1677" in job
    assert "BOSMINER_FAC_X1_MOV_INSN: u32 = 0xAA13_03E1" in job
    assert "admit_bosminer_5c78c_self_is_300" in job
    assert "admit_bosminer_705800_boxes_300_from_parent_3b0" in job
    assert "refuse_836c34_str260_as_hashchain" in job
    assert "refuse_705800_as_hashchain_228_mint" in job
    assert "BOSMINER_SRC5C_VT_ADRP_INSN: u32 = 0xF000_9521" in job
    assert "BOSMINER_BOX300_SRC_LDR_INSN: u32 = 0xF941_3298" in job
    assert "BOSMINER_BOX300_MOVZ_INSN: u32 = 0x5280_6000" in job
    assert "BOSMINER_STR260_HITS: usize = 52" in job
    assert "BOSMINER_TICKET_MASK260_INSN: u32 = 0xF901_3148" in job
    assert "admit_bosminer_705464_stores_src_at_3b0" in job
    assert "admit_bosminer_705464_copies_hc_to_2e0" in job
    assert "refuse_3b0_as_hashchain_pointer" in job
    assert "refuse_705464_as_hashchain_228" in job
    assert "BOSMINER_PARENT3C0_STR3B0_INSN: u32 = 0xF901_DAD7" in job
    assert "BOSMINER_PARENT3C0_LDR260_INSN: u32 = 0xF941_32FB" in job
    assert "BOSMINER_PARENT3C0_TYPE_SIZE: usize = 0x3C0" in job
    assert "admit_bosminer_705464_callers_load_elf_statics" in job
    assert "admit_bosminer_call3c0_elf_objs_have_vptr" in job
    assert "refuse_call3c0_as_hashchain_260_mint" in job
    assert "refuse_call3c0_vptr_as_hashchain_260" in job
    assert "BOSMINER_CALL3C0_A_LDR_INSN: u32 = 0xF947_6800" in job
    assert "BOSMINER_CALL3C0_OBJ_A_VA: u64 = 0x01AE_01C0" in job
    assert "BOSMINER_CALL3C0_VPTR_A: u64 = 0x0086_33A0" in job
    assert "admit_bosminer_867740_inits_static_obj" in job
    assert "admit_bosminer_867740_simd_covers_260" in job
    assert "refuse_867740_strx_260" in job
    assert "refuse_867740_strh228_as_hashchain_tag" in job
    assert "BOSMINER_INIT677_SIMD260_INSN: u32 = 0xAD12_8660" in job
    assert "BOSMINER_INIT677_STRH228_INSN: u32 = 0x7904_5268" in job
    assert "admit_bosminer_x9_is_local120" in job
    assert "admit_bosminer_260_from_adfb28_plus_10" in job
    assert "refuse_adfb28_plus10_as_hashchain" in job
    assert "refuse_beee00_as_static_260_source" in job
    assert "BOSMINER_X9_LDR_SP_B8_INSN: u32 = 0xF940_5FE9" in job
    assert "BOSMINER_X9_OBJ_VA: u64 = 0x01AD_FB28" in job
    assert "admit_bosminer_true_slot_loads_are_six" in job
    assert "admit_bosminer_633a0_returns_after_67740" in job
    assert "refuse_later_overwrite_1ae0420" in job
    assert "refuse_a25760_as_slot_a" in job
    assert "BOSMINER_TRUE_SLOT_LDR_HITS: usize = 6" in job
    assert "BOSMINER_TRUE_SLOT_A_ONCE_INSN: u32 = 0xF947_6AB5" in job
    assert "admit_bosminer_8631f0_is_x8_sret_default" in job
    assert "admit_bosminer_adfb28_size_is_98" in job
    assert "refuse_8631f0_as_hashchain_ctor" in job
    assert "refuse_adfb28_plus228_as_hashchain_field" in job
    assert "BOSMINER_INIT631_STR88_INSN: u32 = 0xB900_891F" in job
    assert "BOSMINER_INIT631_STR10_INSN: u32 = 0xF900_090A" in job
    assert "BOSMINER_SIBLING_SIZE: usize = 0x98" in job
    assert "BOSMINER_PSU_F64_0_BITS: u64 = 0x3FB9_9999_9999_999A" in job
    assert "admit_bosminer_bf2478_is_midstate_log_helper" in job
    assert "admit_bosminer_uart_version_width_is_midstate_log" in job
    assert "refuse_bip320_16_as_bosminer_uart_version_width" in job
    assert "refuse_bf2478_as_bip320_mask" in job
    assert "s19k_braiins_uart_version_bits" in job
    assert "BOSMINER_VERWIDTH_B_LOG_INSN: u32 = 0x1419_B603" in job
    assert "BOSMINER_ENGINE_MIDSTATE_COUNT_OFF: usize = 0x78" in job
    assert "admit_bosminer_five_uart_parse_callers" in job
    assert "admit_bosminer_bf6c2c_is_registry_submit" in job
    assert "refuse_bf6c2c_as_bip320_reexpand" in job
    assert "refuse_uart_wrappers_as_bip320_reexpand" in job
    assert "BOSMINER_UART_CONS_MOVZ11D0_INSN: u32 = 0x5282_3A08" in job
    assert "BOSMINER_RESP_CONSUMER_MOVZ78_INSN: u32 = 0x5280_0F08" in job
    assert "BOSMINER_UART_WRAP_LSL13_HITS: usize = 0" in job
    assert "admit_bosminer_strb228_census_is_24" in job
    assert "admit_bosminer_bf26d0_is_engine_abs_log" in job
    assert "BOSMINER_STRB228_NONSP_HITS: usize = 24" in job
    assert "BOSMINER_LOG_ABS_FN_VA: u64 = 0x00BF_26D0" in job
    assert "admit_bosminer_bf26d0_has_seven_bl_callers" in job
    assert "admit_bosminer_workers_pass_abs_log_to_registry" in job
    assert "admit_bosminer_fpga_factory_calls_abs_log" in job
    assert "admit_bosminer_b2639c_is_one_shr_log" in job
    assert "refuse_one_shr_log_as_uart_registry_size" in job
    assert "s19k_braiins_one_shr_log" in job
    assert "BOSMINER_LOG_ABS_BL_CALLERS: usize = 7" in job
    assert "BOSMINER_ONESHR_LSRV_INSN: u32 = 0x9AC0_2100" in job
    assert "BOSMINER_ONESHR_FN_VA: u64 = 0x00B2_6398" in job
    assert "BOSMINER_ONESHR_BL_CALLERS: usize = 9" in job
    assert "admit_bosminer_oneshr_six_store_three_discard" in job
    assert "admit_bosminer_oneshr_no_x0_cond_branch" in job
    assert "refuse_oneshr_flag2_toggle_as_one_shr_result" in job
    assert "refuse_3280_ldr_as_oneshr_consumer" in job
    assert "refuse_2a70_early_ldr_as_oneshr_consumer" in job
    assert "s19k_braiins_oneshr_is_fill_log" in job
    assert "BOSMINER_ONESHR_STACK_STORE_HITS: usize = 6" in job
    assert "BOSMINER_ONESHR_SIB_FN_VA: u64 = 0x00B2_63F4" in job
    assert "BOSMINER_ONESHR_CALLER_VAS: [u64; 9]" in job
    assert "BOSMINER_ONESHR_X0_COND_HITS: usize = 0" in job
    assert "BOSMINER_ONESHR_3280_LDR_INSN: u32 = 0xF959_43E0" in job
    assert "BOSMINER_ONESHR_3280_LDR_NEXT_INSN: u32 = 0xF959_63E1" in job
    assert "BOSMINER_ONESHR_2A70_EARLY_LDR_INSN: u32 = 0xF955_3BE6" in job
    assert "admit_s19k_bosminer_layouts" in job
    assert "refuse_3280_oneshr_str_as_live_consumer" in job
    assert "refuse_2a70_ldxr_as_oneshr_consumer" in job
    assert "S19kBosminerJobLayout" in job
    assert "BOSMINER_UART_WORK_RESP_DIV_OFF: usize = 0x11C0" in job
    assert "BOSMINER_FPGA_WORK_RESP_DIV_OFF: usize = 0x340" in job
    assert "BOSMINER_WORK_RESP_DIV_MOVZ_INSN: u32 = 0x5282_3819" in job
    assert "BOSMINER_WORK_RESP_ADD_X2_INSN: u32 = 0x8B19_0262" in job
    assert "BOSMINER_FPGA_DIV_ADD_INSN: u32 = 0x910D_0260" in job
    assert "BOSMINER_WORKER_CTOR_STR88_SP_INSN: u32 = 0xF900_47F3" in job
    assert "BOSMINER_AM3_FACTORY_STR_88_90_HITS: usize = 0" in job
    assert "closed_job_id_is_slot_shl_3: false" in job
    assert "admit_bosminer_ghidra_crc_is_itu_t" in job
    wire_b = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_wire_b.rs").read_text(
        encoding="utf-8"
    )
    assert "pack_uart_relay_braiins" in wire_b
    assert "CMD_GET_ADDRESS: u8 = 0x52" in wire_b
    assert "CMD_CHAIN_INACTIVE: u8 = 0x53" in wire_b
    assert "cmd_get_address_bcast" in wire_b
    assert "S19K_JIG_VOLTAGE_DOMAIN: u8 = 11" in wire_b
    assert "admit_bosminer_uart_relay_pack_matches_public_chip0" in wire_b
    assert "BOSMINER_UART_RELAY_PACK_FN_VA: u64 = 0x0083_CA30" in wire_b
    assert "BOSMINER_UART_RELAY_REV16_INSN: u32 = 0x5AC0_094A" in wire_b
    assert "BOSMINER_UART_RELAY_NONCE_GAP_BIT: u32 = 2" in wire_b
    assert "BOSMINER_CRC_INIT_RAW: u16 = 0x84CF" in job
    assert "BOSMINER_CRC_TABLE_VA: u64 = 0x0132_8F60" in job
    assert "refuse_bosminer_55aa2136_collision_as_job_template" in job
    assert "BOSMINER_BM136X_PACKED_STRUCT_OFF: u64 = 0x00F2_56E0" in job
    assert "refuse_packed_struct_string_as_job_length_fact" in job
    assert "BOSMINER_BM136X_XREF_VA: u64 = 0x0092_08CC" in job
    assert "refuse_bm136x_xref_as_job_length_fact" in job
    assert "BOSMINER_BM136X_LOC_LINE: u16 = 36" in job
    assert "BOSMINER_BM13XX_BROADCAST_ASSERT_LEN: u16 = 0x2E" in job
    assert "refuse_9208f8_movz2e_as_bm136x_line46" in job
    assert "admit_bosminer_91beb4_unique_alloc56" in job
    assert "BOSMINER_PACK_ALLOC56_SITES: usize = 1" in job
    assert "admit_bosminer_pack56_type_unnamed_in_rustc_metadata" in job
    assert "refuse_hashmap_v_as_pack56_type" in job
    assert "refuse_factory4_as_pack56_type" in job
    assert "refuse_workpair_as_pack56_type" in job
    assert "BOSMINER_TYPEINFO_SIZE56_HITS: usize = 0" in job
    assert 'BOSMINER_HAL_WORKPAIR_TYPE: &str = "bosminer_hal::workpair"' in job
    assert "refuse_bm136x_panic_site_as_job_packer" in job
    assert "BOSMINER_BM136X_PANIC_BL_CALLERS: usize = 0" in job
    assert "refuse_zero_bl_callers_as_packer_entry" in job
    assert "reconstruct_s19k_send_work_wire" in job
    assert "refuse_sibling_braiins_binaries_as_job_template" in job
    assert "refuse_s19k_packed_bosminer_as_job_template" in job
    assert "S19K_PACKED_BOSMINER_55AA2136_HITS: usize = 0" in job
    assert "refuse_failed_send_work_xrefs_as_job_length" in job
    assert "BOSMINER_FAILED_SEND_WORK_JOB_IMM_XREFS: usize = 0" in job
    assert "refuse_missing_getaddress_literal_as_job_length" in job
    assert "BOSMINER_55AA5205_HITS: usize = 0" in job
    assert "BOSMINER_PACK_CANDIDATE_21_36_STRB: usize = 0" in job
    assert "refuse_movz_strb_false_positives_as_pack_body" in job
    assert "BOSMINER_MOVZ36_ASCII6_VA: u64 = 0x00ED_E73C" in job
    assert "refuse_genericarray_u86_as_job_length_fact" in job
    assert "BOSMINER_GENERICARRAY_STR_HITS: usize = 0" in job
    serial = (ROOT / "dcentrald/dcentrald/src/serial_mining.rs").read_text(
        encoding="utf-8"
    )
    production_serial = serial.split("\n#[cfg(test)]\nmod tests {", 1)[0]
    assert "plan_s19k_braiins_mining_on_ports" in serial
    assert "passthrough && is_bm1366" in serial
    assert "SerialWorkTransport::Multi" in serial
    assert "let serial = if braiins_bm1366_passthrough_handoff" in production_serial
    assert "let serial = if passthrough && is_bm1366" not in production_serial
    assert "parse_bm1366_share_from_body" not in serial
    assert "hunt_s19k_bm1366_fill_from_admitted_tx_path" in serial
    assert "S19kOutstandingFillTx" in serial
    assert "insert_wire" in serial
    assert "insert_wire_retiring" in serial
    assert "refuse_s19k_wrap7_same_id_drop_without_retire" in serial
    assert "outstanding_s19k_tx.len() >= 32" not in serial
    assert (
        "qualify_bm1366_braiins_fill_from_body(&resp[..9], share.job_id" not in serial
    )
    assert "SerialMiningEngineBookkeeping::s19k_braiins_fill" in serial
    assert "admit_s19k_braiins_fill_share_job_id_in_history" in serial
    assert "reconstruct_s19k_send_work_wire" in serial
    transport_tail = production_serial.split(
        "let serial = if braiins_bm1366_passthrough_handoff", 1
    )[1]
    bm1366_arm, generic_tail = transport_tail.split("} else if passthrough {", 1)
    assert "open_passthrough(0, &serial_device)" not in bm1366_arm
    assert "open_passthrough_bm1366(i as u8, path)" in bm1366_arm
    generic_arm = generic_tail.split("} else if is_bm1398 {", 1)[0]
    bm1366_refusal = generic_arm.find("if is_bm1366 {")
    generic_open = generic_arm.find("open_passthrough(0, &serial_device)")
    assert 0 <= bm1366_refusal < generic_open
    assert "S19k BM1366 must use Track-1 multi-tty" in generic_arm
    nonce_arm = serial.split("Wave 246: tagged tty", 1)[1]
    nonce_arm = nonce_arm.split("if flags & 0x80 == 0", 1)[0]
    assert "nonce = share.nonce_le" in nonce_arm
    assert "hunt_s19k_bm1366_fill_from_admitted_tx_path" in nonce_arm
    assert "hit.path" in nonce_arm
    assert "0u16, // fill log 0: not ESP BIP320 body[6:7]" not in nonce_arm
    assert "share.version_bits as u16" in nonce_arm
    assert "0u8, // fill midstates=1" in nonce_arm
    assert "0x80, // fill hunt" in nonce_arm
    assert "share.midstate_num" not in nonce_arm
    fill_ok = nonce_arm.split("Ok(share) =>", 1)[1].split("Err(error)", 1)[0]
    assert "0x80, // fill hunt" in fill_ok
    assert "resp[8]" not in fill_ok
    assert "(share.version_bits >> 13) as u16" not in nonce_arm
    assert "(share.version_bits >> 13) as u16" not in serial
    install_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_install.rs"
    ).read_text(encoding="utf-8")
    assert "gpio437_safe_off_for_identity" in install_rs
    assert "s19k_board_target_is_live_alias" in install_rs
    assert "CLEAR_FOR_FLASH: bool = false" in install_rs
    deploy_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_tmp_deploy.rs"
    ).read_text(encoding="utf-8")
    assert "NativeMiningOnForbidden" in deploy_rs
    assert "passthrough" in deploy_rs
    deploy_sh = (ROOT / "scripts/dcentrald_s19k_tmp_deploy.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "import tomllib" in deploy_sh
    assert 'platform = document.get("platform")' in deploy_sh
    assert 'mining = document.get("mining")' in deploy_sh
    assert "requires the operator's explicit --allow-loud authority" in deploy_sh
    assert "NativeMiningOn" in deploy_sh
    assert "admit_s19k_armhf_elf" in deploy_sh
    assert "e_machine" in deploy_sh
    assert "--expected-artifact-sha256)" in deploy_sh
    assert "--expected-artifact-bytes)" in deploy_sh
    assert "operator_artifact_pin=$ARTIFACT_OPERATOR_PIN" in deploy_sh
    assert "expected_artifact_sha256=$EXPECTED_ARTIFACT_SHA256" in deploy_sh
    assert "expected_artifact_bytes=$EXPECTED_ARTIFACT_BYTES" in deploy_sh
    assert (
        "selected artifact does not match exact sealed operator authority" in deploy_sh
    )
    deploy_rs_text = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_tmp_deploy.rs"
    ).read_text(encoding="utf-8")
    assert "pub fn admit_s19k_armhf_elf" in deploy_rs_text
    assert "ELF_MACHINE_ARM: u16 = 40" in deploy_rs_text
    assert "admit_s19k_armhf_musl_static" in deploy_rs_text
    assert "parse_s19k_armhf_elf" in deploy_rs_text
    assert "EF_ARM_ABI_FLOAT_HARD: u32 = 0x0000_0400" in deploy_rs_text
    assert "format_s19k_tmp_deploy_launch_plan" in deploy_rs_text
    assert "admit_s19k_tmp_deploy_script_musl_static" in deploy_rs_text
    assert "admit_s19k_tmp_deploy_board_target" in deploy_rs_text
    assert "admit_s19k_tmp_deploy_post_scp" in deploy_rs_text
    assert "dcentos.s19k-tmp-deploy/v12" in deploy_rs_text
    assert "operator_artifact_pin=required-and-matched" in deploy_rs_text
    assert "expected_artifact_sha256={sha256_hex}" in deploy_rs_text
    assert "expected_artifact_bytes={bytes}" in deploy_rs_text
    assert "runtime_receipt_schema=dcentos.s19k-tmp-runtime/v5" in deploy_rs_text
    assert (
        "runtime_lock=board-global-atomic-mkdir+v6-artifact-bound-owner+"
        "typed-pending-retention" in deploy_rs_text
    )
    assert "custody_observer_sha256" in deploy_rs_text
    assert "custody_observer_bytes" in deploy_rs_text
    assert "stock_restart_helper_sha256" in deploy_rs_text
    assert "stock_restart_helper_bytes" in deploy_rs_text
    assert (
        "live_identity_schema=dcentos.s19k-braiins-live-identity/v2" in deploy_rs_text
    )
    assert (
        "live_identity_profile_rule=mutually-exclusive-complete-tuple" in deploy_rs_text
    )
    assert (
        "live_identity_profile_live88_two_bhb56903_slots_2_3="
        "2xBHB56903@2,3+addr1-undetected-placeholder+"
        "eeprom-0x50-absent-0x51-0x52-0511" in deploy_rs_text
    )
    # 2026-08-30 runner binds the Track-1 reset set through EXPECTED_SAFEOFF_RESETS;
    # the contract pins that exact else-branch block.
    assert "EXPECTED_SAFEOFF_RESETS=454:0,455:0,456:0" in deploy_rs_text
    assert "resets=$EXPECTED_SAFEOFF_RESETS psu=437:1" in deploy_rs_text
    assert "resets=472:0,473:0,474:0 psu=437:1" not in deploy_rs_text
    assert (
        "live_identity_profile_held78_three_bhb56902_slots_1_2_3="
        "3xBHB56902@1,2,3+eeprom-0x50-0x51-0x52-0511" in deploy_rs_text
    )
    assert "entry_in_executable_load" in deploy_sh
    assert "phnum in (0, 0xffff)" in deploy_sh
    assert "p_offset + p_filesz > len(blob)" in deploy_sh
    assert "sha256=" in deploy_sh
    assert "bytes=" in deploy_sh
    assert "post_scp=sha256sum" in deploy_sh
    assert "admit_s19k_tmp_deploy_post_scp" in deploy_sh
    assert deploy_sh.find("scp -O") < deploy_sh.find("admit_s19k_tmp_deploy_post_scp")
    assert deploy_sh.find("admit_s19k_tmp_deploy_post_scp") < deploy_sh.find(
        "chmod 755"
    )
    assert "WrongBoardTarget" in deploy_rs_text
    assert "am3-s19kpro" in deploy_sh
    assert "am3-aml-s19kpro" in deploy_sh

    discover = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8")
    assert "observe_s19k_dual_port_topology" in discover
    assert "observe_s19k_triple_port_topology" in discover
    assert "format_s19k_topology_observe" in discover
    assert "physical_bound: None" in discover
    assert "s19k_port_answer_from_rx" in discover
    assert "observe_s19k_board_tty_discover" in discover
    assert "board_on_s1" in discover
    assert "board_on_s2" in discover
    assert "board_on_s3" in discover
    assert "boards=s1:" in discover
    assert "HELD_78_CHASSIS" in discover
    assert "JYZZYR6BCJHCA0JRG" in discover
    assert "bind_s19k_board_tty" in discover
    assert "AsicEepromSerialOnTty" in discover
    assert "refuse_s19k_held_corpus_as_serial_tty_map" in discover
    assert "refuse_s19k_106_irq_as_physical_1_ttys1" in discover
    assert "refuse_s19k_xilinx_s19j_as_aml_tty_map" in discover
    assert "observe_s19k_host_i2c_chassis" in discover
    assert "parse_s19k_i2cdetect_at24" in discover
    assert "S19K_78_I2CDETECT_FIXTURE" in discover
    assert "HostI2cChassis" in discover
    assert "tty=unbound" in discover
    assert "refuse_s19k_host_i2c_as_tty_bind" in discover
    assert "admit_s19k_host_i2c_chassis_script" in discover
    assert "observe_s19k_host_i2c_chassis" in serial
    assert "DCENT_S19K_I2CDETECT" in serial
    assert "tty stays unbound" in serial
    assert "parse_s19k_uart_eeprom_named_tty" in discover
    assert "S19K_UART_EEPROM_TTYS2_JRG_FIXTURE" in discover
    assert "refuse_s19k_host_i2c_file_as_uart_eeprom" in discover
    assert "DCENT_S19K_UART_EEPROM" in serial
    assert "parse_s19k_uart_eeprom_named_tty" in serial
    assert "admit_s19k_production_uses_uart_eeprom_fixture" in discover
    chassis_sh = (ROOT / "scripts/s19k_host_i2c_chassis.sh").read_text(encoding="utf-8")
    assert "i2cset=false" in chassis_sh
    assert "tty=unbound" in chassis_sh
    assert "DCENT_S19K_HOST_I2C_LIVE=1" in chassis_sh
    assert "i2cset -y" not in chassis_sh
    assert "S19K_HOST_I2C" in chassis_sh
    assert 'path: "/dev/ttyS3"' in discover
    assert "physical_1→ttyS3" in discover
    assert "observe_s19k_board_tty_discover" in serial
    assert "S19kBoardTtyEvidenceKind::DescendingAml" not in serial
    model_json = (
        ROOT.parents[1]
        / ""
        / "03-bosminer/bosminer_model.json"
    )
    if model_json.is_file():
        model = model_json.read_text(encoding="utf-8")
        assert '"physical_address": 1' in model
        assert '"serial_number": "JYZZYR6BCJHCA0JRG"' in model
        assert '"serial_number": "JYZZYR6BCJHCA0KRG"' in model
        assert '"serial_number": "JYZZYR6BCJHCA0HNX"' in model
        assert "/dev/ttyS" not in model
        assert "ttyS3" not in model
    assert "s19k_port_open_is_optional" in serial
    assert "BRAIINS_TTYS_THIRD" in serial
    assert "BRAIINS_TTYS_DISCOVER" in discover
    assert "classify_s19k_78_dmesg_hash_uart_wakes" in discover
    assert "refuse_wave26_two_uart_three_board_mux" in discover
    assert "parse_s19k_dmesg_uart_controller" in discover
    assert "admit_s19k_78_kernel_ttys_mmio" in discover
    assert "admit_s19k_78_dmesg_wakes_match_kernel_mmio" in discover
    assert "admit_s19k_dtb_serials_match_78_kernel_mmio" in discover
    assert "refuse_console_mmio_as_hash_uart" in discover
    assert "S19K_78_TTYS3_MMIO: u32 = 0xFF80_4000" in discover
    ckpool = (ROOT / "dcentrald/dcentrald_s19k_braiins_ckpool.toml").read_text(
        encoding="utf-8"
    )
    assert "passthrough = true" in ckpool
    assert "enabled = true" in ckpool
    assert "CLEAR_FOR_FLASH=false - refusing flash_erase/nandwrite/fw_setenv" in install
    assert "admit_s19k_78_daemonc_elf" in install_rs
    assert "admit_s19k_stock_upgrade_cgi" in install_rs
    assert "S19K_78_DAEMONC_PORC_STR_OFF: u64 = 0xF54" in install_rs
    assert "admit_s19k_78_daemonc_is_update_daemon" in install_rs
    assert "admit_s19k_daemonc_listen_is_localhost_22322" in install_rs
    assert "admit_s19k_daemonc_argv0_roles" in install_rs
    assert "admit_s19k_daemons_system_prefix" in install_rs
    assert "admit_s19k_daemonc_client_cmp_http_200" in install_rs
    assert "refuse_s19k_daemonc_as_direct_nand_writer" in install_rs
    assert "refuse_s19k_mtd2_as_updateporc_source" in install_rs
    assert "admit_s19k_78_mtd3_is_ubi_stock_config" in install_rs
    assert "refuse_s19k_mtd3_as_updateporc_source" in install_rs
    assert "refuse_s19k_mtd3_as_fileparser_source" in install_rs
    assert "refuse_s19k_mtd3_as_uart_trans_source" in install_rs
    assert "refuse_s19k_mtd3_as_android_system" in install_rs
    assert "refuse_s19k_mtd3_miner_conf_as_separate_dent" in install_rs
    assert "S19K_78_MTD3_BYTES: usize = 5_242_880" in install_rs
    assert "S19K_78_MTD3_CGMINER_CONF_OFF: usize = 3_283_000" in install_rs
    assert "S19K_78_MTD3_NETWORK_CONF_OFF: usize = 3_283_392" in install_rs
    assert "S19K_78_MTD3_UPDATEPORC_HITS: usize = 0" in install_rs
    assert "admit_s19k_s97_promotes_first_boot_to_successful" in install_rs
    assert "admit_s19k_s97_nanddump_02_before_write_03" in install_rs
    assert "refuse_s19k_s97_as_unconditional_03" in install_rs
    assert "refuse_s19k_s97_as_promote_01_to_03" in install_rs
    assert "admit_s19k_s99_header_names_recover_to_stock" in install_rs
    assert "refuse_s19k_s99_leftover_02_as_mtd2_boot" in install_rs
    assert "admit_s19k_s99_wal_block_leaves_flag_02" in install_rs
    assert "refuse_s19k_s99_firstboot0_as_recover_disarm" in install_rs
    assert "admit_s19k_s99_identity_wal_does_not_block_03" in install_rs
    assert "admit_s21_s97_identical_to_78" in install_rs
    assert "refuse_s21_androidboot_firstboot_as_uboot_firstboot" in install_rs
    assert "refuse_s21_held_s97_as_firstboot_bootcmd" in install_rs
    s99 = (
        ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade"
    ).read_text(encoding="utf-8", errors="replace")
    assert "U-Boot reverts to mtd2" not in s99
    assert "Two parallel U-Boot revert mechanisms" not in s99
    assert "U-Boot will revert on next reboot" not in s99
    assert "recover_to_stock" in s99
    assert "bootcmd never reads firstboot" in s99
    assert "firstboot=0 is not the revert disarm" in s99
    assert "next reboot is recover_to_stock" in s99
    assert "s19k_firstboot_is_wal_companion_only" in s99
    assert "proceeding to 0x02->0x03" in s99
    assert "recover_to_stock is already disarmed by flag 0x03" in s99
    assert (
        'S19K_STOCK_UPDATEPORC_PREFIX: &str = "/usr/sbin/updateporc.sh "' in install_rs
    )
    assert "S19K_STOCK_DAEMONC_LISTEN_PORT: u16 = 22322" in install_rs
    assert "S19K_78_DAEMONC_CMP_C8_INSN: u32 = 0xE350_00C8" in install_rs
    daemonc = (
        ROOT.parents[1]
        / ""
        / "09-stock-bitmain-current/usr_sbin_daemonc"
    )
    update_daemon = daemonc.parent / "usr_sbin_update-daemon"
    if daemonc.is_file():
        db = daemonc.read_bytes()
        assert len(db) == 7240
        assert (
            hashlib.sha256(db).hexdigest()
            == "a8f3c4c3e505dbee636c1f4919029470ef77fa3590fe6cbf462a49eae07b8e8e"
        )
        assert db[:4] == b"\x7fELF"
        assert db[4] == 1
        assert int.from_bytes(db[18:20], "little") == 40
        assert db[0xF54 : 0xF54 + 24] == b"/usr/sbin/updateporc.sh "
        assert db[0x1414 : 0x1414 + 9] == b"127.0.0.1"
        assert db[0x1420 : 0x1420 + 5] == b"22322"
        assert db[0x1444 : 0x1444 + 7] == b"daemonc"
        assert db[0x144C : 0x144C + 7] == b"daemons"
        assert struct.unpack_from("<I", db, 0x8DC)[0] == 0xE3011444
        assert struct.unpack_from("<I", db, 0x8F8)[0] == 0xE5940004
        assert struct.unpack_from("<I", db, 0x908)[0] == 0xE301144C
        assert struct.unpack_from("<I", db, 0x94C)[0] == 0xE3010414
        assert struct.unpack_from("<I", db, 0x964)[0] == 0xE3010420
        assert struct.unpack_from("<I", db, 0xC9C)[0] == 0xE300EF54
        assert struct.unpack_from("<I", db, 0xEBC)[0] == 0xE35000C8
        if update_daemon.is_file():
            assert update_daemon.read_bytes() == db
    mtd2 = ROOT.parents[1] / ""
    if mtd2.is_file():
        mb = mtd2.read_bytes()
        assert len(mb) == 52_428_800
        assert mb.find(b"updateporc") < 0
        assert mb[2_097_152 : 2_097_152 + 8] == b"ANDROID!"
    mtd3 = ROOT.parents[1] / ""
    if mtd3.is_file():
        m3 = mtd3.read_bytes()
        assert len(m3) == 5_242_880
        assert m3[:4] == b"UBI#"
        assert m3[4] == 1
        assert int.from_bytes(m3[16:20], "big") == 2048
        assert int.from_bytes(m3[20:24], "big") == 4096
        assert len(m3) // 131072 == 40
        assert m3.count(b"UBI#") == 40
        assert m3.find(b"updateporc") < 0
        assert m3.find(b"FileParser") < 0
        assert m3.find(b"uart_trans") < 0
        assert m3.find(b"4cc0") < 0
        assert m3.find(b"ANDROID!") < 0
        assert m3[3_283_000:3_283_012] == b"cgminer.conf"
        assert m3[3_283_392:3_283_404] == b"network.conf"
        assert m3[3_283_002:3_283_012] == b"miner.conf"
        assert m3[3_412_368:3_412_385] == b"hostname=Antminer"
        assert m3[395_264:395_268] == b"UBI!"
    s97 = (
        ROOT.parents[1]
        / ""
        / "00-system/etc/init.d/S97recovery-flag"
    )
    if s97.is_file():
        s97t = s97.read_text(encoding="utf-8", errors="replace")
        assert "RECOVERY_FLAG_FIRST_BOOT" in s97t
        assert "RECOVERY_FLAG_SUCCESSFUL" in s97t
        assert "nandwrite -p -s" in s97t
        assert 'BOS_MODE" = "nand"' in s97t
        assert "nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1" in s97t
        assert s97t.find(
            "nanddump -s $LOCAL_RECOVERY_FLAGS_OFFSET_BOS_LAYOUT -l 1"
        ) < s97t.find("flash_erase")
        assert "RECOVERY_FLAG_INSTALLED" not in s97t
    cgi = (
        ROOT.parents[1]
        / ""
        / "09-stock-bitmain-current/www_pages_cgi-bin_upgrade.cgi"
    )
    if cgi.is_file():
        cgi_text = cgi.read_text(encoding="utf-8", errors="replace")
        assert "/usr/sbin/daemonc" in cgi_text
        assert "echo 2 > /tmp/miner_act" in cgi_text
    assert install.find("CLEAR_FOR_FLASH=false") < install.find(
        "flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT"
    )
    preflight = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs"
    ).read_text(encoding="utf-8")
    assert "S19kSilenceClass" in preflight
    assert "RailsDisabled" in preflight
    enum_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_bosminer_enum.rs").read_text(
        encoding="utf-8"
    )
    assert "S19K_BHB56902_CHIP_COUNT: u32 = 77" in enum_rs
    assert "parse_s19k_bosminer_enum_fault" in enum_rs
    assert "refuse_s19k_78_bosminer_log_as_fastuart_proof" in enum_rs
    bos_log = (
        ROOT.parents[1]
        / ""
        / "00-system/cap_init/bosminer.log.before"
    )
    if bos_log.is_file():
        log_text = bos_log.read_text(encoding="utf-8", errors="replace")
        assert "read_register(reg=0x0) doesn't match chip count 77" in log_text
        assert "reply 0x2 missing" in log_text
        assert "control board platform:am3-aml" in log_text
        assert "BHB56902" in log_text
        assert log_text.count("Set baud rate") == 0
    departure_log = (
        ROOT.parents[1] / "tmp/s19k-departure-capture-20260821/logs/bosminer.log"
    )
    if departure_log.is_file():
        departure_bytes = departure_log.read_bytes()
        assert len(departure_bytes) == 182_833
        assert hashlib.sha256(departure_bytes).hexdigest() == (
            "98453e18d012e18adf726d7276f7d1d4a53c3546696a2b5950248138f6668b93"
        )
        departure_text = departure_bytes.decode("utf-8", errors="replace")
        cycles = departure_text.split("PSU: Enable")
        assert len(cycles) == 9, "eight complete captured rail-enable cycles"
        for cycle in cycles[1:]:
            for chain in (2, 3):
                assert (
                    cycle.count(
                        f"CHAIN/{chain}: Discovered 77 chips (expected 77 chips)"
                    )
                    == 1
                )
                assert (
                    cycle.count(
                        f"CHAIN/{chain}: Set baud rate @ requested: 3125000, actual: 3125000"
                    )
                    == 1
                )
                assert (
                    cycle.count(
                        f"CHAIN/{chain}: Monitor watchdog temperature task started"
                    )
                    == 1
                )
        final_cycle = cycles[-1]
        assert (
            final_cycle.find("CHAIN/2: Initializing hashchain")
            < final_cycle.find("CHAIN/2: Discovered 77 chips (expected 77 chips)")
            < final_cycle.find(
                "CHAIN/2: Set baud rate @ requested: 3125000, actual: 3125000"
            )
            < final_cycle.find("CHAIN/2: Monitor watchdog temperature task started")
        )
        assert (
            final_cycle.find("CHAIN/3: Initializing hashchain")
            < final_cycle.find("CHAIN/3: Discovered 77 chips (expected 77 chips)")
            < final_cycle.find(
                "CHAIN/3: Set baud rate @ requested: 3125000, actual: 3125000"
            )
            < final_cycle.find("CHAIN/3: Monitor watchdog temperature task started")
        )
    assert "classify_s19k_passthrough_silence" in serial
    assert "s19k_passthrough_rearm_writes" in serial
    assert "native_program.address_interval" in serial
    assert "if is_bm1366" in serial
    assert "is_bm1366," in serial
    assert "if is_bm1366 {" in serial
    assert "return Some(rolled_version);" in serial
    # : BM1366 packed ver0 is midstate0 OR before BIP320 strip.
    rolled = serial.split("fn serial_rolled_version(", 1)[1]
    rolled = rolled.split("fn serial_build_header(", 1)[0]
    assert "is_bm1366: bool" in rolled
    assert "s19k_braiins_midstate0_version" in rolled
    assert "entry.version" in rolled
    assert "version_bits_raw" in rolled
    assert rolled.find("s19k_braiins_midstate0_version") < rolled.find(
        "bip320_reconstruct_rolled_version"
    )
    job = (ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_job.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_s19k_production_rolled_version_is_midstate0_or" in job
    assert "refuse_bip320_strip_as_braiins_fill_ver0" in job
    flag_sh = (ROOT / "scripts/s19k_write_recovery_flag.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "intent=UbootStockRevert" in flag_sh
    assert "DCENT_S19K_RECOVERY_FLAG_EXECUTE" in flag_sh
    assert "eraseblock_start=" in flag_sh
    assert "rewriter=eraseblock_rewrite" in flag_sh
    assert "--fixture-in" in flag_sh
    assert "byte_in_block=$EB_OFF_HEX" in flag_sh
    assert flag_sh.count("candidate_required=full-0x20000-byte-eraseblock") == 3
    assert flag_sh.count("candidate_source=host-fixture-only") == 3
    assert flag_sh.count("write_command=false") == 3
    assert (
        flag_sh.count("readback_required=full-0x20000-byte-sha256-and-byte-compare")
        == 3
    )
    assert "mode=execute-eraseblock-rewrite" not in flag_sh
    assert "byte_in_block must be 0" not in flag_sh
    assert "planned_not_executed" not in flag_sh
    assert "proc_mtd=" in install
    assert "recovery_flag_local=" in install
    geom = (ROOT / "scripts/lib/am3_geometry.sh").read_text(encoding="utf-8")
    assert "DCENT_AM3_NANDROOTFS_GLOBAL" in geom
    init_seq = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "s19k_passthrough_rearm_writes" in init_seq
    assert "refuse_esp_9000ffff_as_braiins_fill_rearm" in init_seq
    assert "admit_s19k_passthrough_rearm_omits_version_roll" in init_seq
    assert "admit_s19k_midrun_rearm_includes_analog_mux" in init_seq
    assert (
        '"ticket_mask_diff256" | "hash_counting_s19k" | "version_roll"' not in init_seq
    )
    assert '"ticket_mask_diff256" | "hash_counting_s19k" | "analog_mux"' in init_seq
    assert "ESP_BM1366_VERSION_ROLL_MASK: u32 = 0x9000_FFFF" in init_seq
    assert "steps.push(step_from_write(*VERSION_ROLL_BCAST_WRITE))" not in init_seq
    engine = (ROOT / "dcentrald/dcentrald-common/src/serial_work_engine.rs").read_text(
        encoding="utf-8"
    )
    assert "S19K_AML_ADDR_INTERVAL" in engine
    assert "fn s19k_braiins_fill()" in engine
    assert "admit_s19k_passthrough_work_tx" in serial
    assert "admit_s19k_backup" in install_rs
    assert "admit_s19k_nandwrite_preflight" in install_rs
    assert "format_s19k_backup_ledger_with_hashes" in install_rs
    assert "nandrecovery_env_local_offset" in install_rs
    assert "admit_s19k_mtd5_backup_covers_recovery" in install_rs
    assert "refuse_nand_env_bak_as_nandrecovery_env" in install_rs
    assert "NANDRECOVERY_ENV_GLOBAL: u64 = 0x0B00_0000" in install_rs
    assert "format_s19k_recovery_flag_write_plan" in install_rs
    assert "plan_s19k_recovery_flag_eraseblock" in install_rs
    assert "refuse_s19k_recovery_flag_raw_byte_poke" in install_rs
    assert "INIT_CTRL_A8_UNICAST" in init_seq
    assert "BOSMINER_115A_BE_FILE_OFF: u64 = 0x0159_20A6" in init_seq
    assert "BOSMINER_115A_BE_VA: u64 = 0x019A_20A6" in init_seq
    assert "refuse_bosminer_115a_file_pin_as_hcn_writer" in init_seq
    assert "LIVE_78_20251204_POPULATION" in discover
    assert "refuse_wave26_two_uart_three_board_mux" in discover
    assert "refuse_s19k_axg_ttys4_as_third_hash_uart" in discover
    assert "fn lifts_hold" in discover
    assert "self.getaddress_rx" in discover
    assert "refuse_bosminer_hcn_divider_log_as_reg10_writer" in init_seq
    assert "BOSMINER_HCN_DIVIDER_LOG_FN_VA: u64 = 0x0084_34E0" in init_seq
    assert "refuse_bosminer_hash_counting_number_string_as_hcn_writer" in init_seq
    assert "BOSMINER_HASH_COUNTING_NUMBER_STR_VA: u64 = 0x0139_DB65" in init_seq
    assert "classify_s19k_78_irq_delta" in discover
    assert "refuse_bosminer_movz51_as_set_config_packer" in init_seq
    assert "BOSMINER_MOVZ51_HITS: usize = 33" in init_seq
    assert "admit_s19k_fastuart_with_host_baud" in init_seq
    assert "s19k_native_pll0_start_write" in init_seq
    assert "pll0_50mhz" in init_seq
    assert "ESP_FASTUART_HOST_BAUD: u32 = 1_000_000" in init_seq
    assert "classify_s19k_uart_baud_dialect" in init_seq
    assert "refuse_esp_fastuart_as_s19k_braiins_3m" in init_seq
    assert "refuse_pll0_50mhz_as_s19k_stock_mining_freq" in init_seq
    assert "S19K_78_DMESG_HOLD_BAUD: u32 = 115_200" in init_seq
    assert "BOSMINER_HAL_COMMAND_RS_VA: u64 = 0x0130_3F89" in init_seq
    assert "ext_baud_enable" in init_seq
    assert "BOSMINER_FASTUART_FIELDS_STR_VA: u64 = 0x0132_0C4B" in init_seq
    assert "refuse_bm1366_3001_as_s19k_braiins_3m" in init_seq
    assert "refuse_bm1362_3011_as_s19k_braiins_3m" in init_seq
    assert "refuse_bosminer_movz_3001_as_fastuart" in init_seq
    assert "refuse_bosminer_ticket_mask_future_as_fastuart" in init_seq
    assert "BOSMINER_COMMAND_RS_READ_REGISTER_FN_VA: u64 = 0x008A_9044" in init_seq
    assert "BOSMINER_UART_BE4_SEND_FN_VA: u64 = 0x008A_200C" in init_seq
    assert "BOSMINER_TICKET_MASK_FUTURE_FN_VA: u64 = 0x0083_6934" in init_seq
    assert "admit_bosminer_bm1366_stock_baud_static" in init_seq
    assert "BOSMINER_BM1366_FASTUART_3M125: u32 = 0x0000_3011" in init_seq
    assert "BOSMINER_SETCFG_51_09_00_28_HITS: usize = 0" in init_seq
    assert "refuse_bosminer_file_setcfg_28_as_s19k_fastuart" in init_seq
    assert "refuse_uart_be4_send_callers_as_s19k_aml_fastuart" in init_seq
    assert "BOSMINER_HOST_TERMIOS_FN_VA: u64 = 0x00BB_E3D4" in init_seq
    assert "s19k_native_fastuart_bible_3125k_write" in init_seq
    assert "refuse_bosminer_be4_send_as_s19k_set_config" in init_seq
    assert "s19k_generic_set_config_uart" in init_seq
    assert "refuse_bm1397_9byte_as_bm1366_getaddress_rx" in init_seq
    assert "BOSMINER_PACKED_STRUCT_PACKING_RS_VA: u64 = 0x0131_BE45" in init_seq
    assert "admit_bosminer_write_loc_is_bm1398_rs" in init_seq
    assert "refuse_command_rs_write_as_s19k_aml_set_config" in init_seq
    assert "refuse_pack_fn_as_s19k_exclusive_set_config" in init_seq
    assert "BOSMINER_PACK_BL_HITS: usize = 3" in init_seq
    assert "admit_bosminer_bm1366_packed_dispatch" in init_seq
    assert "refuse_bm1366_packed_dispatch_as_named_fastuart" in init_seq
    assert "BOSMINER_BM1366_PACKED_DISPATCH_FN_VA: u64 = 0x008D_823C" in init_seq
    assert "BOSMINER_BM1366_DISPATCH_BL_HITS: usize = 48" in init_seq
    assert "BOSMINER_BM1366_DISPATCH_BL_IN_LOC_CLUSTER: usize = 31" in init_seq
    assert "admit_bosminer_blr_x8_is_fat_ptr_vtable0" in init_seq
    assert "refuse_blr_x8_as_named_text_write_reg" in init_seq
    assert "refuse_dispatch_arc_like_as_uart_write" in init_seq
    assert "BOSMINER_BM1366_DISPATCH_LDP_INSN: u32 = 0xA947_D275" in init_seq
    assert "admit_bosminer_fat_ptr_vtable_layout" in init_seq
    assert "refuse_vtable_method_as_uart_write_reg" in init_seq
    assert "BOSMINER_FAT_PTR_VTABLE_VA: u64 = 0x019C_7900" in init_seq
    assert "psu_protocol.rs" in init_seq
    assert "admit_bosminer_plus78_fn_loc_is_hashchain_rs" in init_seq
    assert "admit_bosminer_hashchain_plus78_operands" in init_seq
    assert "admit_bosminer_sibling_pack_tag_dispatch" in init_seq
    assert "refuse_hashchain_plus78_as_psu_rodata_vtable" in init_seq
    assert "refuse_hashchain_plus78_second_as_text_fastuart" in init_seq
    assert "BOSMINER_HASHCHAIN_PLUS78_STP_VA: u64 = 0x008D_FF48" in init_seq
    assert "BOSMINER_HASHCHAIN_SIBLING_PACK_FN_VA: u64 = 0x008D_5F9C" in init_seq
    assert "BOSMINER_HASHCHAIN_PLUS78_LOC_LINE: u32 = 112" in init_seq
    assert "admit_bosminer_legacy_fastuart_fail_str" in init_seq
    assert "refuse_legacy_fastuart_panic_as_uart_write" in init_seq
    assert "refuse_legacy_fastuart_as_s19k_host_3m" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_PANIC_FN_VA: u64 = 0x0091_AFE8" in init_seq
    assert "admit_bosminer_legacy_fastuart_divisor_path" in init_seq
    assert "admit_bosminer_legacy_fastuart_fields_layout" in init_seq
    assert "refuse_reg28_3001_as_legacy_fastuart_pack" in init_seq
    assert "refuse_legacy_fastuart_divisor_as_3001" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA: u64 = 0x0091_AF6C" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_PACKED_LEN: usize = 0x0E" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0: u32 = 6" in init_seq
    assert "admit_bosminer_legacy_fastuart_div_fptr" in init_seq
    assert "admit_bosminer_hashchain_dup78_88_copy" in init_seq
    assert "refuse_hashchain_dup88_as_engine_nonce_fn" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF: u64 = 0x016B_E820" in init_seq
    assert "BOSMINER_HASHCHAIN_DUP88_STP_VA: u64 = 0x008D_3A80" in init_seq
    assert "admit_bosminer_hashchain_blr78_family" in init_seq
    assert "refuse_blr78_family_as_engine_plus88" in init_seq
    assert "BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS: usize = 7" in init_seq
    assert "bosminer_legacy_fastuart_w13" in init_seq
    assert "pack_bosminer_legacy_fastuart_fields" in init_seq
    assert "pack_bosminer_legacy_fastuart_bm1398_write_instance" in init_seq
    assert "admit_bosminer_legacy_fastuart_w13_map" in init_seq
    assert "admit_bosminer_legacy_fastuart_w1_ldrb_sub1" in init_seq
    assert "admit_bosminer_nested88_plus18_family" in init_seq
    assert "refuse_legacy_fastuart_dest5_as_bible_3001" in init_seq
    assert "refuse_fastuart_field_names_as_dest_byte_map" in init_seq
    assert "refuse_nested88_plus18_as_engine_nonce_fn" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2: u32 = 0x80" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3: u32 = 0x0F" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA: u64 = 0x0091_AF84" in init_seq
    assert "BOSMINER_NESTED88_HITS: usize = 2" in init_seq
    assert "BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF: u16 = 0x22C" in init_seq
    assert "decode_bosminer_fastuart_reg_named" in init_seq
    assert "admit_bosminer_fastuart_named_bit_blob" in init_seq
    assert "refuse_bible_3001_as_ext_baud_enable" in init_seq
    assert "refuse_rfs_tfs_width_as_named" in init_seq
    assert "BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT: u32 = 16" in init_seq
    assert "unknown_bit_7_reserved_bit_6" in init_seq
    assert "admit_bosminer_fastuart_22c_xtal25" in init_seq
    assert "bosminer_xtal25_divisor_baud" in init_seq
    assert "refuse_xtal25_div8_as_s19k_host_3m" in init_seq
    assert "refuse_plus22c_as_engine_nonce_fn" in init_seq
    assert "BOSMINER_FASTUART_22C_XTAL_HZ: u32 = 25_000_000" in init_seq
    assert "BOSMINER_FASTUART_22C_LDRB_HITS: usize = 12" in init_seq
    assert "admit_bosminer_host_3m_movz_sites" in init_seq
    assert "admit_bosminer_host_3m_termios_b3000000" in init_seq
    assert "admit_bosminer_aml_open_host_3m" in init_seq
    assert "refuse_host_3m_termios_as_chip_fastuart_28" in init_seq
    assert "refuse_legacy_pack_and_xtal25_as_host_3m_writer" in init_seq
    assert "linux_b3000000_speed_t" in init_seq
    assert "BOSMINER_HOST_3M_MOVZ_HITS: usize = 4" in init_seq
    assert "BOSMINER_B3000000_SPEED_T: u32 = 0x100D" in init_seq
    assert "admit_bosminer_bm1397_reg28_0600000f" in init_seq
    assert "admit_bosminer_bm1396_reg28_0600000f" in init_seq
    assert "pack_legacy_s17_reg28_uart" in init_seq
    assert "refuse_legacy_s17_reg28_0600000f_as_bm1366" in init_seq
    assert "BOSMINER_LEGACY_S17_REG28_VALUE: u32 = 0x0600_000F" in init_seq
    assert "BOSMINER_BM1397_REG28_LOC_LINE: u32 = 103" in init_seq
    assert "BOSMINER_BM1396_REG28_LOC_LINE: u32 = 101" in init_seq
    assert "format_s19k_install_commit_plan" in install_rs
    assert "refuse_s19k_firstboot_only_as_install_commit" in install_rs
    assert "InstallArm" in install_rs
    assert "S99_WAL_companion_only" in install_rs
    assert "admit_s19k_install_commit_plan" in install_rs
    assert "admit_s19k_recovery_flag_script_plans_install_arm" in install_rs
    assert "admit_s19k_install_script_writes_install_commit_geometry" in install_rs
    install_sh_w285 = (ROOT / "scripts/install_amlogic_persistent.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "write_install_commit_plan()" in install_sh_w285
    assert "uboot_action=FirstBosThenSetFlag2" in install_sh_w285
    assert "eraseblock_index=" in install_sh_w285
    assert "eraseblock_start=" in install_sh_w285
    assert "byte_in_block=" in install_sh_w285
    assert 'write_install_commit_plan "dry_run=true"' in install_sh_w285
    assert install_sh_w285.find("write_install_commit_plan()") < install_sh_w285.find(
        'write_install_commit_plan "dry_run=true"'
    )
    assert install_sh_w285.find(
        'write_install_commit_plan "dry_run=true"'
    ) < install_sh_w285.find(
        "CLEAR_FOR_FLASH=false - refusing flash_erase/nandwrite/fw_setenv"
    )
    assert "bootm_mtd2=false" in install_rs
    flag_sh_w284 = (ROOT / "scripts/s19k_write_recovery_flag.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "schema=dcentos.amlogic-install-commit/v1" in flag_sh_w284
    assert "intent=InstallArm" in flag_sh_w284
    assert "uboot_action=FirstBosThenSetFlag2" in flag_sh_w284
    assert "printf '\\001'" in flag_sh_w284
    assert "recovery flag 0x01 execute is FLASH NOT_YET" in flag_sh_w284
    assert (
        "recovery flag 0x01 is FLASH NOT_YET here (use INSTALL_COMMIT_PLAN)"
        not in flag_sh_w284
    )
    assert flag_sh_w284.find(
        "recovery flag 0x01 execute is FLASH NOT_YET"
    ) < flag_sh_w284.find("intent=InstallArm")
    assert "rewrite_recovery_flag_fixture()" in flag_sh_w284
    assert flag_sh_w284.find("rewrite_recovery_flag_fixture()") < flag_sh_w284.find(
        "intent=InstallArm"
    )
    assert 'flash_erase /dev/mtd5 "$EB_START_HEX" 1' not in flag_sh_w284
    assert "format_s19k_recover_to_stock_plan" in install_rs
    assert "plan_s19k_recover_to_stock" in install_rs
    assert "admit_s19k_install_script_writes_recover_to_stock_plan" in install_rs
    assert "S19kRecoverToStockStep" in install_rs
    assert "format_s19k_recover_walk_ledger" in install_rs
    assert "admit_s19k_recover_walk_ledger" in install_rs
    assert "admit_s19k_recover_script_dry_run_walks_plan" in install_rs
    assert "admit_s19k_recover_script_execute_refuses_nandwrite" in install_rs
    assert "S19K_RECOVER_WALK_SCHEMA" in install_rs
    assert "S19K_RECOVER_DRY_STEP0" in install_rs
    recover_sh = (ROOT / "scripts/recover_amlogic_to_stock.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "--dry-run" in recover_sh
    assert "--verify-only" in recover_sh
    assert "RECOVER_TO_STOCK_PLAN.txt" in recover_sh
    assert "RECOVER_WALK.txt" in recover_sh
    assert "s19k_nand_env_crc.py" in recover_sh
    assert "nandrecovery_env.bin CRC32 mismatch" in recover_sh
    assert "nand_env.bak is not recover_env" in recover_sh
    assert (
        "[DRY RUN] walking RECOVER_TO_STOCK_PLAN before GPIO/nandwrite/fw_setenv/env import"
        in recover_sh
    )
    assert "schema=dcentos.amlogic-recover-walk/v1" in recover_sh
    assert (
        "dry_step0=nand read 01060000 ${nandrecovery_env_offset} ${env_size}; env default -a; env import -d -c 01060000 0x10000; env save"
        in recover_sh
    )
    assert "dry_step1=nand erase.part nvdata" in recover_sh
    assert "dry_step2=reset" in recover_sh
    assert "nandwrite=false" in recover_sh
    assert "fw_setenv=false" in recover_sh
    assert "env_import=false" in recover_sh
    assert (
        "CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite"
        in recover_sh
    )
    assert "Type 'RECOVER'" in recover_sh
    assert "missing live canonical platform/board_target pair" in recover_sh
    assert "is not exact am3-aml-s19k:am3-s19k" in recover_sh
    assert "gpio437 SafeOff (am3-s19k-active-low, value=1)" in recover_sh
    assert (
        "missing live /proc/mtd; refuse geometry-blind recover-to-stock" in recover_sh
    )
    assert "if [ -r /proc/mtd ]; then" not in recover_sh
    assert "\nfw_setenv firstboot 1\n" not in recover_sh
    recover_execute = recover_sh.split(
        'if [ "${DCENT_S19K_RECOVER_EXECUTE:-0}" != 1 ]', 1
    )[1]
    assert recover_execute.find("Type 'RECOVER'") < recover_execute.find(
        "CLEAR_FOR_FLASH=false — refusing"
    )
    assert recover_execute.find(
        "CLEAR_FOR_FLASH=false — refusing"
    ) < recover_execute.find("require_exact_live_s19k_identity /etc/dcentos")
    assert recover_execute.find(
        "require_exact_live_s19k_identity /etc/dcentos"
    ) < recover_execute.find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
    assert recover_execute.find(
        "gpio437 SafeOff (am3-s19k-active-low, value=1)"
    ) < recover_execute.find(
        "missing live /proc/mtd; refuse geometry-blind recover-to-stock"
    )
    assert recover_execute.find(
        "missing live /proc/mtd; refuse geometry-blind recover-to-stock"
    ) < recover_execute.find("nandwrite -p /dev/mtd5")
    assert "recover_amlogic_to_stock.sh" in (
        ROOT / "scripts/install_amlogic_persistent.sh"
    ).read_text(encoding="utf-8", errors="replace")
    assert "admit_s19k_install_script_runs_recover_dry_run" in install_rs
    install_sh_w288 = (ROOT / "scripts/install_amlogic_persistent.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert (
        'sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run'
        in install_sh_w288
    )
    assert (
        "recover-to-stock --dry-run failed; refusing successful backup"
        in install_sh_w288
    )
    assert "RECOVER_WALK.txt" in install_sh_w288
    assert install_sh_w288.find(
        "RECOVER_TO_STOCK_PLAN.txt written"
    ) < install_sh_w288.find(
        'sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run'
    )
    assert install_sh_w288.find(
        'sh "$RECOVER_RUNNER" --artifact-dir "$ARTIFACT_DIR" --dry-run'
    ) < install_sh_w288.find("[BACKUP-ONLY]")
    assert "admit_s19k_install_script_runs_flag_01_fixture" in install_rs
    assert "extract_s19k_recovery_flag_eraseblock_from_mtd5_backup" in install_rs
    assert "dcent_am3_extract_recovery_flag_eraseblock" in (
        ROOT / "scripts/lib/am3_geometry.sh"
    ).read_text(encoding="utf-8", errors="replace")
    assert "dcent_am3_extract_recovery_flag_eraseblock" in install_sh_w288
    assert 'sh "$FLAG_HELPER" --value 0x01' in install_sh_w288
    assert "--fixture-in" in install_sh_w288
    assert "recovery_flag_eb.0x01.bin" in install_sh_w288
    assert "INSTALL_COMMIT_WALK.txt" in install_sh_w288
    assert (
        "recovery-flag 0x01 fixture walk failed; refusing successful backup"
        in install_sh_w288
    )
    assert "admit_s19k_install_script_admits_flag_01_bytes" in install_rs
    assert "admit_s19k_walked_flag_01_fixture" in install_rs
    assert "0x01 fixture-out length" in install_sh_w288
    assert "0x01 fixture-out byte0=" in install_sh_w288
    assert "(want 01)" in install_sh_w288
    assert install_sh_w288.find(
        "0x01 fixture-out missing after walk"
    ) < install_sh_w288.find("0x01 fixture-out length")
    assert install_sh_w288.find("0x01 fixture-out length") < install_sh_w288.find(
        "0x01 fixture-out byte0="
    )
    assert install_sh_w288.find("0x01 fixture-out byte0=") < install_sh_w288.find(
        "[BACKUP-ONLY]"
    )
    flag_invoke = install_sh_w288.find('sh "$FLAG_HELPER" --value 0x01')
    backup_only = install_sh_w288.find("[BACKUP-ONLY]")
    assert flag_invoke != -1 and backup_only != -1 and flag_invoke < backup_only
    assert "--execute" not in install_sh_w288[flag_invoke:backup_only]
    assert (
        install_sh_w288.find("dcent_am3_extract_recovery_flag_eraseblock") < flag_invoke
    )
    assert "walk_s19k_recover_to_stock_artifact" in install_rs
    assert "construct_s19k_nandrecovery_env_fixture" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_nand_env.rs"
    ).read_text(encoding="utf-8")
    assert "encode_s19k_nand_env" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_nand_env.rs"
    ).read_text(encoding="utf-8")
    crc_emit = (ROOT / "scripts/s19k_nand_env_crc.py").read_text(encoding="utf-8")
    assert "emit_nandrecovery_env_fixture" in crc_emit
    assert "--emit" in crc_emit
    crc_spec = importlib.util.spec_from_file_location(
        "s19k_nand_env_crc_w282", ROOT / "scripts/s19k_nand_env_crc.py"
    )
    crc_mod = importlib.util.module_from_spec(crc_spec)
    assert crc_spec.loader is not None
    crc_spec.loader.exec_module(crc_mod)
    fixture = crc_mod.emit_nandrecovery_env_fixture()
    crc_mod.admit_nand_env_crc(fixture)
    assert len(fixture) == crc_mod.S19K_NAND_ENV_LEN
    flag_sh = (ROOT / "scripts/s19k_write_recovery_flag.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "recover_env_source=nandrecovery_env.bin" in flag_sh
    assert "nand_erase_part=nvdata" in flag_sh
    assert "bootm_mtd2=false" in flag_sh
    assert "recover_execute=refused" in flag_sh
    assert "pass=admit_s19k_recover_execute_returns_ClearForFlashNotYet" in flag_sh
    assert "admit_s19k_recover_execute" in install_rs
    assert "recover_execute=refused reason=CLEAR_FOR_FLASH" in (
        ROOT / "scripts/install_amlogic_persistent.sh"
    ).read_text(encoding="utf-8", errors="replace")
    assert "format_s19k_recover_execute_refuse" in install_rs
    assert "admit_s19k_recover_execute_refuse_names_78_ram" in install_rs
    assert "admit_s19k_recover_execute_refuse_names_78_nand_src" in install_rs
    assert "nandrecovery_env_offset=0x{nandenv:08X}" in install_rs
    assert "recover_env_ram=0x{ram:08X}" in install_rs
    assert "S19kRecoverExecuteError" in install_rs
    assert "extract_s19k_nandrecovery_env_from_mtd5_backup" in install_rs
    assert "admit_s19k_nandrecovery_env_slice" in install_rs
    assert "refuse_s19k_nand_env_bak_as_recover_env_import" in install_rs
    assert "S19K_BACKUP_NANDRECOVERY_ENV_NAME" in install_rs
    assert "dcent_am3_extract_nandrecovery_env" in (
        ROOT / "scripts/lib/am3_geometry.sh"
    ).read_text(encoding="utf-8")
    assert "nandrecovery_env.bin" in (
        ROOT / "scripts/install_amlogic_persistent.sh"
    ).read_text(encoding="utf-8")
    assert "BOSMINER_WRITE_VERIFY_STR_FILE_OFF: u64 = 0x00F2_0197" in init_seq
    assert "refuse_reply_0x2_missing_as_interval_proof" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bosminer_enum.rs"
    ).read_text(encoding="utf-8")
    assert "S19K_AML_UPDATEPORC_IN_HELD_CORPUS: bool = false" in install_rs
    assert "format_s19k_aml_factory_sd_plan" in install_rs
    assert "parse_s19k_aml_upgrade_header" in install_rs
    assert "S19K_AML_UPGRADE_CRC: u32 = 0x1CCB_07DA" in install_rs
    assert "S19K_AML_UPGRADE_ITEM_STRIDE: usize = 0x240" in install_rs
    assert "refuse_s19k_aml_img_as_updateporc" in install_rs
    assert "refuse_s19k_aml_img_as_4cc0_or_uart_trans" in install_rs
    assert "refuse_s19k_aml_crc_as_decrypt_key" in install_rs
    assert "S19K_AML_UPGRADE_UBOOT_IDENTITY" in install_rs
    assert "admit_s19k_aml_upgrade_usb_uboot_item" in install_rs
    assert "admit_s19k_aml_upgrade_meson1_item" in install_rs
    assert "admit_s19k_aml_upgrade_usb_ddr_item" in install_rs
    assert "admit_s19k_aml_upgrade_usb_ddr_enc_item" in install_rs
    assert "admit_s19k_aml_upgrade_usb_uboot_enc_item" in install_rs
    assert "admit_s19k_aml_upgrade_ini_item" in install_rs
    assert "admit_s19k_aml_upgrade_keys_item" in install_rs
    assert "admit_s19k_aml_upgrade_platform_item" in install_rs
    assert "refuse_s19k_usb_ddr_enc_as_decrypt_key" in install_rs
    assert "refuse_s19k_conf_keys_as_aes_key" in install_rs
    assert "refuse_s19k_encrypt_reg_as_otp_decrypt_key" in install_rs
    assert "refuse_s19k_ini_erase_bootloader_as_execute" in install_rs
    assert "S19K_AML_UPGRADE_ITEM0_USB_DDR_OFF: u64 = 11_008" in install_rs
    assert "S19K_AML_UPGRADE_ITEM1_USB_DDR_ENC_OFF: u64 = 60_160" in install_rs
    assert "S19K_AML_UPGRADE_ITEM3_USB_UBOOT_ENC_OFF: u64 = 878_336" in install_rs
    assert "S19K_AML_UPGRADE_ITEM8_INI_OFF: u64 = 3_314_512" in install_rs
    assert "S19K_AML_UPGRADE_ITEM13_KEYS_OFF: u64 = 17_040_912" in install_rs
    assert "S19K_AML_UPGRADE_ITEM16_PLATFORM_OFF: u64 = 17_069_496" in install_rs
    assert "S19K_AML_UPGRADE_ENCRYPT_REG: u32 = 0xFF80_0228" in install_rs
    assert "S19K_AML_UPGRADE_ITEM2_USB_UBOOT_OFF: u64 = 109_312" in install_rs
    assert "S19K_AML_UPGRADE_ITEM14_MESON1_OFF: u64 = 17_040_928" in install_rs
    assert "refuse_s19k_aml_dtb_partition_as_gzip_meson1" in install_rs
    assert "admit_s19k_aml_upgrade_aml_dtb_item" in install_rs
    assert "admit_s19k_aml_upgrade_meson1_enc_item" in install_rs
    assert "admit_s19k_aml_dtb_alias_meson1_enc" in install_rs
    assert "parse_s19k_aml_verify_item" in install_rs
    assert "S19K_AML_UPGRADE_ITEM4_AML_DTB_OFF: u64 = 1_647_360" in install_rs
    assert (
        'S19K_AML_DTB_ENC_SHA1_HEX: &[u8; 40] = b"8e1890fd2c43f6e7e10cc04b23c2073e88d7ab1b"'
        in install_rs
    )
    assert (
        'S19K_AML_BOOT_SHA1_HEX: &[u8; 40] = b"97107df8e67ce465c3d71a7816d32b7b86f71d8e"'
        in install_rs
    )
    assert (
        'S19K_AML_BOOTLOADER_SHA1_HEX: &[u8; 40] = b"377d37642c69b9b7665cac669361693755bec457"'
        in install_rs
    )
    assert (
        'S19K_AML_RECOVERY_SHA1_HEX: &[u8; 40] = b"b6441d919a9e3c2ad6e503fe21b6ca0e361ac4c3"'
        in install_rs
    )
    assert "classify_s19k_aml_verify_hex" in install_rs
    assert "admit_s19k_aml_verify_pair" in install_rs
    assert "admit_s19k_aml_upgrade_verify_item" in install_rs
    assert "admit_s19k_aml_upgrade_bootloader_item" in install_rs
    assert "refuse_s19k_aml_verify_as_decrypt" in install_rs
    assert "S19K_AML_UPGRADE_ITEM10_VERIFY_BOOT_OFF: u64 = 16_222_128" in install_rs
    assert "S19K_AML_UPGRADE_ITEM11_BOOTLOADER_OFF: u64 = 16_222_176" in install_rs
    assert "S19K_AML_UPGRADE_ITEM6_UBOOT_OFF: u64 = 1_677_136" in install_rs
    assert "admit_s19k_aml_upgrade_sdc_uboot_item" in install_rs
    assert "admit_s19k_bootloader_uboot_enc_same_size" in install_rs
    assert "refuse_s19k_bootloader_as_uboot_enc" in install_rs
    assert "refuse_s19k_bootloader_as_plaintext_uboot" in install_rs
    assert "S19K_SDC_USB_UBOOT_PREFIX_BYTES: usize = 49_664" in install_rs
    assert "admit_s19k_sdc_usb_uboot_suffix" in install_rs
    assert "admit_s19k_sdc_uboot_prefix_bl2" in install_rs
    assert "refuse_s19k_sdc_uboot_prefix_as_gpio437" in install_rs
    assert "refuse_s19k_sdc_usb_uboot_as_same_image" in install_rs
    assert "Built : 10:38:43, Apr 14 2020. axg gf27ed33" in install_rs
    assert "parse_s19k_bl2_storage_classes" in install_rs
    assert "admit_s19k_bl2_storage_init" in install_rs
    assert "refuse_s19k_bl2_storage_as_78_mtd" in install_rs
    assert "refuse_s19k_bl2_storage_as_s30v_nand" in install_rs
    assert "refuse_s19k_bl2_emmc_boot_as_s19k_nand_map" in install_rs
    assert 'S19K_BL2_NAND_INIT: &[u8] = b"NAND init\\n"' in install_rs
    assert 'S19K_BL2_EMMC_BOOT: &[u8] = b"eMMC boot @ "' in install_rs
    assert "admit_s19k_bl2_rpmb_emmc_errors" in install_rs
    assert "refuse_s19k_bl2_rpmb_as_nandrecovery" in install_rs
    assert "refuse_s19k_bl2_rpmb_as_78_nand" in install_rs
    assert "refuse_s19k_bl2_rpmb_as_s30v_nand" in install_rs
    assert 'S19K_BL2_RPMB_COUNTER: &[u8] = b"BL2: rpmb counter: 0x"' in install_rs
    assert 'S19K_BL2_RPMB_SET_KEY: &[u8] = b"BL2: rpmb set key: 0x"' in install_rs
    assert "admit_s19k_bl2_scan_bbt_ecc" in install_rs
    assert "refuse_s19k_bl2_bbt_as_78_nand_ecc" in install_rs
    assert "refuse_s19k_bl2_bbt_as_s30v_nand" in install_rs
    assert "refuse_s19k_bl2_bbt_as_nandrecovery" in install_rs
    assert 'S19K_BL2_SCAN_BBT_ECC: &[u8] = b"scan bbt ecc error happen:"' in install_rs
    assert "S19K_BL2_SCAN_BBT_OFF: usize = 42_161" in install_rs
    assert 'S19K_BL2_NBBT: &[u8] = b"nbbt"' in install_rs
    assert 'S19K_BL2_READ_PAGE_ADDR: &[u8] = b"read page_addr:"' in install_rs
    assert "admit_s19k_bl2_ddr_saved_page" in install_rs
    assert "admit_s19k_bl2_lock_check" in install_rs
    assert "refuse_s19k_bl2_ddr_page_as_nandrecovery" in install_rs
    assert "refuse_s19k_bl2_lock_as_gpio437" in install_rs
    assert "refuse_s19k_bl2_lock_as_nandrecovery" in install_rs
    assert 'S19K_BL2_DDR_SAVED_PAGE: &[u8] = b"ddr saved page: "' in install_rs
    assert "S19K_BL2_DDR_SAVED_PAGE_OFF: usize = 42_139" in install_rs
    assert 'S19K_BL2_LOCK_FAILED: &[u8] = b"lock failed! reset...\\n"' in install_rs
    assert "admit_s19k_bl2_cpu_clk_24mhz" in install_rs
    assert "admit_s19k_bl2_sys_fix_pll" in install_rs
    assert "refuse_s19k_bl2_24mhz_as_hash_clock" in install_rs
    assert "refuse_s19k_bl2_24mhz_as_uart_baud" in install_rs
    assert "refuse_s19k_bl2_pll_as_asic_pll" in install_rs
    assert 'S19K_BL2_CPU_CLK_24MHZ: &[u8] = b"CPU clk: 24MHz\\n"' in install_rs
    assert "S19K_BL2_CPU_CLK_OFF: usize = 42_242" in install_rs
    assert 'S19K_BL2_SYS_PLL: &[u8] = b"SYS PLL"' in install_rs
    assert 'S19K_BL2_FIX_PLL: &[u8] = b"FIX PLL"' in install_rs
    assert "admit_s19k_bl2_saradc_sample_error" in install_rs
    assert "admit_s19k_bl2_saradc_cnt" in install_rs
    assert "refuse_s19k_bl2_saradc_as_miner_voltage_adc" in install_rs
    assert "refuse_s19k_bl2_saradc_as_miner_temp_adc" in install_rs
    assert "refuse_s19k_bl2_saradc_as_gpio437" in install_rs
    assert 'S19K_BL2_SARADC_ERR: &[u8] = b"Get saradc sample Error. Cnt_"' in install_rs
    assert "S19K_BL2_SARADC_ERR_OFF: usize = 42_285" in install_rs
    assert 'S19K_BL2_SARADC_CNT: &[u8] = b"Cnt_"' in install_rs
    assert "S19K_BL2_SARADC_CNT_OFF: usize = 42_310" in install_rs
    assert "admit_s19k_bl2_board_id" in install_rs
    assert "refuse_s19k_bl2_board_id_as_78_chassis" in install_rs
    assert "refuse_s19k_bl2_board_id_as_bhb56" in install_rs
    assert 'S19K_BL2_BOARD_ID: &[u8] = b"Board ID = "' in install_rs
    assert "S19K_BL2_BOARD_ID_OFF: usize = 42_315" in install_rs
    assert "parse_s19k_bl2_ddr_types" in install_rs
    assert "admit_s19k_bl2_ddr_table" in install_rs
    assert "refuse_s19k_bl2_ddr_as_78_nand" in install_rs
    assert "refuse_s19k_bl2_ddr_as_s30v_nand" in install_rs
    assert "refuse_s19k_bl2_ddr_init_as_nandrecovery" in install_rs
    assert 'S19K_BL2_RANK: &[u8] = b"rank: "' in install_rs
    assert "S19K_BL2_RANK_OFF: usize = 42_384" in install_rs
    assert "S19K_BL2_DDR_TYPE_TABLE_OFF: usize = 42_560" in install_rs
    assert 'S19K_BL2_DDR_INIT_FAIL: &[u8] = b"DDR init fail, reset..."' in install_rs
    assert "S19K_BL2_DDR_INIT_FAIL_OFF: usize = 42_924" in install_rs
    assert "admit_s19k_bl2_ddr_ssc_pll" in install_rs
    assert "refuse_s19k_bl2_ddr_ssc_as_hash_pll" in install_rs
    assert "refuse_s19k_bl2_ddr_pll_bypass_as_asic_pll" in install_rs
    assert "refuse_s19k_bl2_ddr_clk_err_as_uart_baud" in install_rs
    assert 'S19K_BL2_DDR_SSC: &[u8] = b"Set ddr ssc: ppm"' in install_rs
    assert "S19K_BL2_DDR_SSC_OFF: usize = 42_664" in install_rs
    assert 'S19K_BL2_DDR_PLL_BYPASS: &[u8] = b"DDR pll bypass enabled\\n"' in install_rs
    assert "S19K_BL2_DDR_PLL_BYPASS_OFF: usize = 42_710" in install_rs
    assert 'S19K_BL2_DDR_PLL: &[u8] = b"DDR PLL"' in install_rs
    assert "S19K_BL2_DDR_CLK_ERR_OFF: usize = 42_961" in install_rs
    assert "admit_s19k_bl2_bist_test" in install_rs
    assert "refuse_s19k_bl2_bist_as_nand_bist" in install_rs
    assert "refuse_s19k_bl2_bist_as_nandrecovery" in install_rs
    assert 'S19K_BL2_BIST_TEST: &[u8] = b"bist_test "' in install_rs
    assert "S19K_BL2_BIST_TEST_OFF: usize = 42_950" in install_rs
    assert 'S19K_BL2_DDR_INIT_FAILED: &[u8] = b"DDR init failed"' in install_rs
    assert "admit_s19k_bl2_dram_chl_mhz" in install_rs
    assert "refuse_s19k_bl2_chl_as_hash_chain" in install_rs
    assert "refuse_s19k_bl2_chl_mhz_as_hash_clock" in install_rs
    assert 'S19K_BL2_CHL: &[u8] = b" chl: "' in install_rs
    assert "S19K_BL2_CHL_OFF: usize = 42_996" in install_rs
    assert "S19K_BL2_CHL_MHZ_OFF: usize = 43_003" in install_rs
    assert "admit_s19k_bl2_ddr_reset" in install_rs
    assert "refuse_s19k_bl2_reset_as_gpio437" in install_rs
    assert "refuse_s19k_bl2_reset_as_hb_reset" in install_rs
    assert 'S19K_BL2_DDR_RESET: &[u8] = b"Reset..."' in install_rs
    assert "S19K_BL2_DDR_RESET_OFF: usize = 43_044" in install_rs
    assert 'S19K_BL2_ADDRBUS_FAIL: &[u8] = b"AddrBus test failed!!!"' in install_rs
    assert "admit_s19k_bl2_sdio_customer_id" in install_rs
    assert "refuse_s19k_bl2_sdio_as_miner_identity" in install_rs
    assert "refuse_s19k_bl2_customer_id_as_78_chassis" in install_rs
    assert 'S19K_BL2_SDIO_DEBUG: &[u8] = b"sdio debug board detected"' in install_rs
    assert "S19K_BL2_SDIO_DEBUG_OFF: usize = 43_177" in install_rs
    assert (
        'S19K_BL2_CUSTOMER_ID: &[u8] = b"ERROR! Customer ID not match!"' in install_rs
    )
    assert "S19K_BL2_CUSTOMER_ID_OFF: usize = 43_236" in install_rs
    assert "admit_s19k_bl2_memdump_bl2z" in install_rs
    assert "refuse_s19k_bl2_memdump_as_nandrecovery" in install_rs
    assert "refuse_s19k_bl2_bl2z_as_78_nand" in install_rs
    assert 'S19K_BL2_MEMDUMP: &[u8] = b"@MEMDUMP"' in install_rs
    assert "S19K_BL2_MEMDUMP_OFF: usize = 43_267" in install_rs
    assert 'S19K_BL2_JUMP_BL2Z: &[u8] = b"jump to BL2z:"' in install_rs
    assert "S19K_BL2_JUMP_BL2Z_OFF: usize = 43_307" in install_rs
    assert "admit_s19k_bl2_fip_usb_mode" in install_rs
    assert "refuse_s19k_bl2_usb_mode_as_aml_install" in install_rs
    assert "refuse_s19k_bl2_fip_chk_as_nandrecovery" in install_rs
    assert 'S19K_BL2_RETURN_BL2: &[u8] = b"return to BL2"' in install_rs
    assert "S19K_BL2_RETURN_BL2_OFF: usize = 43_321" in install_rs
    assert 'S19K_BL2_USB_MODE: &[u8] = b"USB mode!"' in install_rs
    assert 'S19K_BL2_FIP_HDR_CHK: &[u8] = b"FIP HDR CHK:"' in install_rs
    assert "admit_s19k_bl2_fip_tmp_bl31" in install_rs
    assert "refuse_s19k_bl2_fip_tmp_as_aml_install" in install_rs
    assert "refuse_s19k_bl2_bl31_as_nandrecovery" in install_rs
    assert "refuse_s19k_bl2_never_here_as_operator_install" in install_rs
    assert 'S19K_BL2_FIP_TMP_HDR: &[u8] = b"FIP TMP HDR"' in install_rs
    assert "S19K_BL2_FIP_TMP_HDR_OFF: usize = 43_381" in install_rs
    assert 'S19K_BL2_BL31: &[u8] = b"BL31"' in install_rs
    assert "S19K_BL2_BL31_OFF: usize = 43_393" in install_rs
    assert 'S19K_BL2_NEVER_HERE: &[u8] = b"Never should be here!"' in install_rs
    assert "S19K_BL2_NEVER_HERE_OFF: usize = 43_406" in install_rs
    assert "admit_s19k_bl2_err_sha_table" in install_rs
    assert "parse_s19k_bl2_err_sha_labels" in install_rs
    assert "refuse_s19k_bl2_err_sha_as_verify_sha1" in install_rs
    assert "refuse_s19k_bl2_err_sha_as_decrypt_key" in install_rs
    assert "S19K_BL2_ERR_SHA_TABLE: &[u8] =" in install_rs
    assert "S19K_BL2_ERR_SHA_TABLE_OFF: usize = 43_464" in install_rs
    assert (
        'b"Err:sha5\\n\\x00Err:sha4\\n\\x00Err:sha3\\n\\x00Err:sha1\\n\\x00Err:sha2\\n\\x00"'
        in install_rs
    )
    assert "admit_s19k_bl2_never_be_here_skip_usb" in install_rs
    assert "refuse_s19k_bl2_never_be_here_as_operator_install" in install_rs
    assert "refuse_s19k_bl2_skip_usb_as_aml_install" in install_rs
    assert 'S19K_BL2_NEVER_BE_HERE: &[u8] = b"NEVER BE HERE"' in install_rs
    assert "S19K_BL2_NEVER_BE_HERE_OFF: usize = 43_530" in install_rs
    assert 'S19K_BL2_USB_LABEL: &[u8] = b"BL2 USB "' in install_rs
    assert "S19K_BL2_USB_LABEL_OFF: usize = 43_552" in install_rs
    assert 'S19K_BL2_SKIP_USB: &[u8] = b"Skip usb!"' in install_rs
    assert "S19K_BL2_SKIP_USB_OFF: usize = 43_562" in install_rs
    assert "admit_s19k_bl2_reg_dump" in install_rs
    assert "parse_s19k_bl2_dump_labels" in install_rs
    assert "refuse_s19k_bl2_reg_dump_as_hash_uart" in install_rs
    assert "refuse_s19k_bl2_reg_dump_as_nandrecovery" in install_rs
    assert "S19K_BL2_DUMP_TABLE_OFF: usize = 43_577" in install_rs
    assert (
        'b"-W[0x\\x00]:0x\\x00,R:0x\\x00DATA\\x00ADDR\\x00ADDR2\\x00ADDR3\\x00\\nTotal Size 0x\\x00FULL\\x00FULL2"'
        in install_rs
    )
    assert "S19K_AML_UPGRADE_ITEM18_VERIFY_REC_OFF: u64 = 23_134_344" in install_rs
    assert "refuse_s19k_aml_dtb_as_plaintext_fdt" in install_rs
    assert "refuse_s19k_aml_dtb_as_gpio437" in install_rs
    assert "admit_s19k_aml_upgrade_boot_item" in install_rs
    assert "admit_s19k_aml_upgrade_recovery_item" in install_rs
    assert "S19K_AML_UPGRADE_ITEM9_BOOT_OFF: u64 = 3_315_120" in install_rs
    assert "S19K_AML_UPGRADE_ITEM17_RECOVERY_OFF: u64 = 17_069_704" in install_rs
    assert "parse_s19k_android_amlsecu_stamp_raw" in install_rs
    assert "classify_s19k_amlsecu_time" in install_rs
    assert (
        'S19K_FACTORY_AMLSECU_BOOT_TIME: &[u8; 16] = b"2023111515304766"' in install_rs
    )
    assert (
        'S19K_FACTORY_AMLSECU_RECOVERY_TIME: &[u8; 16] = b"2023111515304721"'
        in install_rs
    )
    assert "admit_s19k_factory_android_boot_header" in install_rs
    assert "S19K_FACTORY_BOOT_RAMDISK_SIZE: u32 = 0x0068_6800" in install_rs
    assert "S19K_FACTORY_BOOT_RAMDISK_OFF: usize = 0x5C_1000" in install_rs
    assert "S19K_FACTORY_BOOT_SECOND_OFF: usize = 12_875_776" in install_rs
    assert "admit_s19k_factory_android_second_layout" in install_rs
    assert "refuse_s19k_20231108_ramdisk_as_factory_boot" in install_rs
    assert "refuse_s19k_factory_second_as_plaintext_android" in install_rs
    assert "refuse_s19k_4k_ramdisk_off_as_factory_page2048" in install_rs
    assert "admit_s19k_factory_android_recovery_header" in install_rs
    assert "refuse_s19k_factory_recovery_as_boot_ramdisk" in install_rs
    assert "refuse_s19k_factory_boot_as_20231108_datafile" in install_rs
    assert "admit_s19k_factory_android_ramdisk_not_gzip" in install_rs
    assert "refuse_s19k_factory_android_page0_as_gpio437" in install_rs
    assert "refuse_s19k_factory_android_as_s30v_full_slot" in install_rs
    assert "S19K_FACTORY_ANDROID_RAMDISK_OFF: usize = 0x5C_1800" in install_rs
    assert "S19K_20231108_RAMDISK_ADDR: u32 = 0x0100_0000" in install_rs
    assert "S19K_20231108_SECOND_ADDR: u32 = 0x00F0_0000" in install_rs
    assert "S19K_20231108_TAGS_ADDR: u32 = 0x0000_0100" in install_rs
    assert "S19K_AML_FACTORY_SD_IMG_BYTES: usize = 23_134_392" in install_rs
    assert "S19K_AML_FACTORY_SD_UBOOT_BYTES: usize = 818_688" in install_rs
    assert "VNISH_AML_SD_UBOOT_POINTER_BYTES: usize = 131" in install_rs
    assert "refuse_s19k_aml_factory_sd_as_nandrecovery_env" in install_rs
    assert "refuse_s19k_xil_sd_recover_as_aml_nand" in install_rs
    assert "XilSdRecoverFactory" in install_rs
    assert "admit_s19k_aml_factory_sd_execute" in install_rs
    aml_sd = (
        ROOT.parents[1]
        / ""
        / "AML-19k-Pro-202311151447-sd-card.zip"
    )
    if aml_sd.is_file():
        import zipfile

        with zipfile.ZipFile(aml_sd) as z:
            names = set(z.namelist())
            assert names == {
                "aml_sdc_burn.ini",
                "aml_sdc_burn.UBOOT.ENC",
                "aml_upgrade_package_enc.img",
            }
            assert z.getinfo("aml_sdc_burn.ini").file_size == 602
            assert z.getinfo("aml_sdc_burn.UBOOT.ENC").file_size == 818688
            assert z.getinfo("aml_upgrade_package_enc.img").file_size == 23134392
            ini = z.read("aml_sdc_burn.ini").decode("latin1")
            assert "erase_bootloader    =1" in ini
            assert "erase_flash         =1" in ini
            assert "reboot              =1" in ini
            assert "package     =aml_upgrade_package_enc.img" in ini
            img = z.read("aml_upgrade_package_enc.img")
            assert img[:4] == (0x1CCB07DA).to_bytes(4, "little")
            assert img[8:12] == (0x27B51956).to_bytes(4, "little")
            assert int.from_bytes(img[12:20], "little") == 23134392
            assert int.from_bytes(img[24:28], "little") == 19
            assert b"updateporc" not in img
            assert b"uart_trans" not in img
            assert b"bmminer_4cc0" not in img
            item7 = img[0x40 + 7 * 0x240 : 0x40 + 8 * 0x240]
            assert item7[0x20:0x29] == b"UBOOT.ENC"
            assert item7[0x120:0x12C] == b"aml_sdc_burn"
            assert int.from_bytes(item7[0x10:0x18], "little") == 2495824
            assert int.from_bytes(item7[0x18:0x20], "little") == 818688
            assert img[2495824 : 2495824 + 818688] == z.read("aml_sdc_burn.UBOOT.ENC")
            item11 = img[16222176 : 16222176 + 818688]
            item7 = img[2495824 : 2495824 + 818688]
            assert len(item11) == len(item7) == 818688
            assert item11 != item7
            assert item11[:2] != item7[:2]
            assert b"S19k-Pro_BHB56XXX" not in item11
            assert b"GPIOAO_3" not in item11
            item0 = img[0x40 + 0 * 0x240 : 0x40 + 1 * 0x240]
            assert item0[0x20:0x23] == b"USB"
            assert item0[0x120:0x123] == b"DDR"
            assert int.from_bytes(item0[0x10:0x18], "little") == 11008
            assert int.from_bytes(item0[0x18:0x20], "little") == 49152
            assert img[11008 + 16 : 11008 + 20] == b"@AML"
            item1 = img[0x40 + 1 * 0x240 : 0x40 + 2 * 0x240]
            assert item1[0x20:0x23] == b"USB"
            assert item1[0x120:0x127] == b"DDR_ENC"
            assert int.from_bytes(item1[0x10:0x18], "little") == 60160
            assert int.from_bytes(item1[0x18:0x20], "little") == 49152
            assert img[11008 : 11008 + 49152] != img[60160 : 60160 + 49152]
            item3 = img[0x40 + 3 * 0x240 : 0x40 + 4 * 0x240]
            assert item3[0x20:0x23] == b"USB"
            assert item3[0x120:0x129] == b"UBOOT_ENC"
            assert int.from_bytes(item3[0x10:0x18], "little") == 878336
            assert int.from_bytes(item3[0x18:0x20], "little") == 769024
            assert img[109312 : 109312 + 32] != img[878336 : 878336 + 32]
            item8 = img[0x40 + 8 * 0x240 : 0x40 + 9 * 0x240]
            assert item8[0x20:0x23] == b"ini"
            assert item8[0x120:0x12C] == b"aml_sdc_burn"
            assert int.from_bytes(item8[0x10:0x18], "little") == 3314512
            assert int.from_bytes(item8[0x18:0x20], "little") == 602
            ini = img[3314512 : 3314512 + 602]
            assert b"aml_upgrade_package.img" in ini
            assert b"erase_bootloader    = 1" in ini
            item13 = img[0x40 + 13 * 0x240 : 0x40 + 14 * 0x240]
            assert item13[0x20:0x24] == b"conf"
            assert item13[0x120:0x124] == b"keys"
            assert img[17040912:17040928] == b"secure_boot_set\n"
            item16 = img[0x40 + 16 * 0x240 : 0x40 + 17 * 0x240]
            assert item16[0x20:0x24] == b"conf"
            assert item16[0x120:0x128] == b"platform"
            plat = img[17069496 : 17069496 + 202]
            assert plat.startswith(b"Platform:0x0811")
            assert b"Encrypt_reg:0xff800228" in plat
            usb = img[109312 : 109312 + 769024]
            sdc = img[1677136 : 1677136 + 818688]
            assert sdc[725584 : 725584 + 8] == b"GPIOAO_3"
            assert sdc[725575:725592] == b"gpio \xf0\x38\x98 GPIOAO_3"
            assert 818688 - 725584 == 93104
            assert 769024 - 675920 == 93104
            assert len(sdc) - len(usb) == 49664
            assert sdc[49664:] == usb
            pref = sdc[:49664]
            assert (
                b"Built : 10:38:43, Apr 14 2020. axg gf27ed33 - jenkins@walle02-sh"
                in pref
            )
            assert b"BL2" in pref
            assert b"NAND init" in pref
            assert b"Rsv\x00eMMC\x00NAND\x00SPI\x00SD\x00USB\x00UNKNOWN" in pref
            assert b"eMMC boot @ " in pref
            assert b"!!!ERROR, No storage device init!" in pref
            assert b"get rpmb counter error 0x" in pref
            assert b"BL2: rpmb counter: 0x" in pref
            assert b"BL2: rpmb set key: 0x" in pref
            assert b"Cannot read RPMB write counter" in pref
            assert b"stock_system" not in pref
            assert b"nandnormal" not in pref
            assert b"twoplane" not in pref
            assert b"nvdata" not in pref
            assert b"GPIOAO_3" not in pref
            assert b"gpio437" not in pref
            assert b"PWR_CONTROL" not in pref
            assert usb[674340:674357] == b"i2c mw 1f 3.1 0 2"
            assert sdc[724004:724021] == b"i2c mw 1f 3.1 0 2"
            assert usb[674967:674977] == b"setenv boo"
            assert b"setenv bootcmd" not in usb
            assert b"setenv firstboot" not in usb
            assert b"bootcmd" not in usb
            assert b"firstboot" not in usb
            assert b"'mtdids'" in usb
            assert b"mtdparts" not in usb
            assert usb[674989:675010] == b"logo=${display_layer}"
            assert usb[675016:675024] == b"android9"
            assert b"logo=${display_layer}" not in pref
            assert usb[675071:675079] == b"hardware"
            assert usb[675081:675086] == b"Iogic"
            assert usb[675118:675130] == b"baseband=N/A"
            assert b"hardware=" not in usb
            assert b"amlogic" not in usb[674800:676000]
            assert b"plat/amlogic/common/bl31_plat_setup.c" in usb
            assert b"plat/amlogic/common/sip_svc.c" in usb
            assert b"plat/amlogic/common/plat_pm.c" in usb
            assert b"plat/amlogic/board/axg/secureboot/secureboot.c" in usb
            assert b"Amlogic-secure-boot-module-v0.4" in usb
            assert usb.count(b"plat/amlogic/") == 4
            assert b"plat/amlogic" not in pref
            assert pref[42156:42160] == b"nbbt"
            assert pref[42161:42187] == b"scan bbt ecc error happen:"
            assert pref[42189:42204] == b"read page_addr:"
            assert b"scan bbt" not in usb
            assert b"nandnormal" not in pref
            assert b"twoplane" not in pref
            assert b"nandrecovery" not in pref
            assert usb[675106:675117] == b"uild.expect"
            assert usb[675132:675139] == b"acmdlin"
            assert b"build.expect" not in usb
            assert b"androidboot" not in usb
            assert pref[42139:42155] == b"ddr saved page: "
            assert pref[42206:42217] == b"lock check "
            assert pref[42219:42241] == b"lock failed! reset...\n"
            assert b"ddr saved page" not in usb
            assert b"recover_env" not in pref
            assert b"gpio437" not in pref
            assert pref[42242:42257] == b"CPU clk: 24MHz\n"
            assert pref[42258:42265] == b"SYS PLL"
            assert pref[42276:42283] == b"FIX PLL"
            assert b"CPU clk: 24MHz" not in usb
            assert b"SYS PLL" not in usb
            assert b"FIX PLL" not in usb
            assert pref[42285:42314] == b"Get saradc sample Error. Cnt_"
            assert pref[42310:42314] == b"Cnt_"
            assert b"Get saradc sample Error. Cnt_" not in usb
            assert b"Cnt_" not in usb
            assert b"ina260" not in pref
            assert b"XADC" not in pref
            assert b"gpio437" not in pref
            assert b"SARADC channel2" in usb
            assert pref[42315:42326] == b"Board ID = "
            assert b"Board ID = " not in usb
            assert b"JYZZ" not in pref
            assert b"BHB56" not in pref
            assert usb[686158:686164] == b"saradc"
            assert usb[686169:686184] == b"SARADC channel2"
            assert b"Get saradc sample Error. Cnt_" not in usb
            assert pref[42384:42390] == b"rank: "
            assert pref[42560:42586] == b"DDR3\x00\x00DDR4\x00\x00LPDDR3\x00\x00LPDDR2"
            assert (
                pref[42588:42629]
                == b"Rank0 16bit\x00\x00Rank0\x00\x00Rank0+1\x00\x00Rank01 16bit"
            )
            assert pref[42924:42947] == b"DDR init fail, reset..."
            assert b"rank: " not in usb
            assert b"DDR3" not in usb
            assert b"LPDDR3" not in usb
            assert b"nandnormal" not in pref
            assert b"twoplane" not in pref
            assert b"nvdata" not in pref
            assert pref[42664:42680] == b"Set ddr ssc: ppm"
            assert pref[42681:42698] == b"1000\n\x002000\n\x003000\n"
            assert pref[42710:42733] == b"DDR pll bypass enabled\n"
            assert pref[42786:42793] == b"DDR PLL"
            assert pref[42961:42976] == b"DDR clk err...\n"
            assert pref[42977:42995] == b"DDR Timing err...\n"
            assert b"Set ddr ssc: ppm" not in usb
            assert b"DDR pll bypass enabled" not in usb
            assert b"DDR PLL" not in usb
            assert pref[42950:42960] == b"bist_test "
            assert pref[43007:43015] == b" - PASS\n"
            assert pref[43016:43024] == b" - FAIL\n"
            assert pref[43025:43040] == b"DDR init failed"
            assert b"bist_test" not in usb
            assert b"NAND BIST" not in pref
            assert b"nand bist" not in pref
            assert pref[42996:43002] == b" chl: "
            assert pref[43003:43006] == b"MHz"
            assert b" chl: " not in usb
            assert b"hashboard" not in pref
            assert b"ttyS" not in pref
            assert b"BM1366" not in pref
            assert pref[43044:43052] == b"Reset..."
            assert pref[43025:43043] == b"DDR init failed..."
            assert pref[43054:43076] == b"AddrBus test failed!!!"
            assert pref[43098:43119] == b"Device test failed!!!"
            assert b"Reset..." not in usb
            assert b"gpio437" not in pref
            assert b"HB0_RESET" not in pref
            assert b"PWR_CONTROL" not in pref
            assert pref[43177:43202] == b"sdio debug board detected"
            assert pref[43205:43233] == b"no sdio debug board detected"
            assert pref[43236:43265] == b"ERROR! Customer ID not match!"
            assert b"sdio debug board" not in usb
            assert b"Customer ID" not in usb
            assert b"JYZZ" not in pref
            assert b"board_target" not in pref
            assert pref[43267:43275] == b"@MEMDUMP"
            assert pref[43276:43286] == b"bl2z: ptr:"
            assert pref[43297:43305] == b"NO BL2z!"
            assert pref[43307:43320] == b"jump to BL2z:"
            assert b"jump to BL2z" not in usb
            assert b"NO BL2z" not in usb
            assert b"nandrecovery" not in pref
            assert b"recover_env" not in pref
            assert pref[43321:43334] == b"return to BL2"
            assert pref[43336:43345] == b"USB mode!"
            assert pref[43347:43359] == b"FIP HDR CHK:"
            assert pref[43370:43379] == b"BL3x CHK:"
            assert b"return to BL2" not in usb
            assert b"USB mode!" not in usb
            assert b"FIP HDR CHK" not in usb
            assert b"updateporc" not in pref
            assert b"aml_sdc_burn" not in pref
            assert pref[43381:43392] == b"FIP TMP HDR"
            assert pref[43393:43397] == b"BL31"
            assert pref[43406:43427] == b"Never should be here!"
            assert pref[43464:43514] == (
                b"Err:sha5\n\x00Err:sha4\n\x00Err:sha3\n\x00Err:sha1\n\x00Err:sha2\n\x00"
            )
            assert b"sha1sum" not in pref
            assert b"sha1sum" not in usb
            assert usb[245984:245992] == b"Err:sha\n"
            assert usb[245984:245993] != b"Err:sha5\n"
            assert usb[246088:246128] == (
                b"Err:sha5\n\x00Err:sha3\n\x00Err:sha1\n\x00Err:sha2\n\x00"
            )
            assert (
                b"Err:sha5\n\x00Err:sha4\n\x00Err:sha3\n\x00Err:sha1\n\x00Err:sha2\n\x00"
                not in usb
            )
            assert usb[246227:246236] == b"Err:sha4\n"
            assert pref[43530:43543] == b"NEVER BE HERE"
            assert pref[43552:43560] == b"BL2 USB "
            assert pref[43562:43571] == b"Skip usb!"
            assert b"NEVER BE HERE" not in usb
            assert b"BL2 USB " not in usb
            assert b"Skip usb!" not in usb
            assert pref[43406:43427] == b"Never should be here!"
            assert b"NEVER BE HERE" != b"Never should be here!"
            assert pref[43577:43641] == (
                b"-W[0x\x00]:0x\x00,R:0x\x00DATA\x00ADDR\x00ADDR2\x00ADDR3\x00"
                b"\nTotal Size 0x\x00FULL\x00FULL2"
            )
            assert b"-W[0x" not in usb
            assert b"ADDR2" not in usb
            assert b"ADDR3" not in usb
            assert b"Total Size 0x" not in usb
            assert b"FULL2" not in usb
            assert b"ttyS" not in pref
            assert b"BM1366" not in pref
            assert b"55 AA" not in pref
            assert usb[729904:729915] == b"TxFIFO FULL"
            assert usb[729940:729950] == b"SPEED ENUM"
            assert usb[257284:257302] == b"ADDR_MASK_48_TO_63"
            assert usb[674787:674794] == b"ramoops"
            assert b"TxFIFO FULL" not in pref
            assert b"SPEED ENUM" not in pref
            assert b"ADDR_MASK_48_TO_63" not in pref
            assert b"ramoops" not in pref
            assert b"ttyS1" not in usb
            assert b"ttyS2" not in usb
            assert b"ttyS3" not in usb
            assert usb[41822:41839] == b"=== %s EXCEPTION:"
            assert usb[41995:42041] == b"=========== Process Stack Contents ==========="
            assert usb[42807:42827] == b"core/cortex-m/task.c"
            assert b"=== %s EXCEPTION:" not in pref
            assert b"core/cortex-m/task.c" not in pref
            assert b"Process Stack Contents" not in pref
            assert usb[42640:42650] == b"__wait_evt"
            assert usb[42692:42707] == b"Task Ready Name"
            assert b"__wait_evt" not in pref
            assert b"Task Ready Name" not in pref
            assert usb[42652:42662] == b"mutex_lock"
            assert usb[42680:42691] == b"svc_handler"
            assert usb[42868:42888] == b"Task %d (%s) exited!"
            assert b"mutex_lock" not in pref
            assert b"svc_handler" not in pref
            assert b"Task %d (%s) exited!" not in pref
            assert usb[42664:42678] == b"task_set_event"
            assert usb[42900:42926] == b"Stack overflow in %s task!"
            assert b"task_set_event" not in pref
            assert b"Stack overflow in %s task!" not in pref
            assert usb[42928:42939] == b"tasks_ready"
            assert usb[42940:42950] == b"<< idle >>"
            assert b"tasks_ready" not in pref
            assert b"<< idle >>" not in pref
            assert usb[42951:42956] == b"HOOKS"
            assert usb[42957:42966] == b"TIMERTASK"
            assert b"HOOKS" not in pref
            assert b"TIMERTASK" not in pref
            assert usb[42967:42977] == b"LOWMAILBOX"
            assert usb[42978:42989] == b"HIGHMAILBOX"
            assert b"LOWMAILBOX" not in pref
            assert b"HIGHMAILBOX" not in pref
            assert usb[42990:43000] == b"SECMAILBOX"
            assert usb[43001:43012] == b"USERLOWTASK"
            assert b"SECMAILBOX" not in pref
            assert b"USERLOWTASK" not in pref
            assert usb[43013:43025] == b"USERHIGHTASK"
            assert usb[43026:43040] == b"USERSECURETASK"
            assert b"USERHIGHTASK" not in pref
            assert b"USERSECURETASK" not in pref
            assert usb[43041:43056] == b"TIMERFORADCTASK"
            assert usb[43064:43093] == b"empty chip, efuse not burned."
            assert b"TIMERFORADCTASK" not in pref
            assert b"empty chip, efuse not burned." not in pref
            assert usb[43096:43111] == b"This is ES chip"
            assert usb[43120:43141] == b"is_set_dvfs_vol_first"
            assert b"This is ES chip" not in pref
            assert b"is_set_dvfs_vol_first" not in pref
            assert usb[43144:43157] == b"get_init_dvfs"
            assert usb[43160:43168] == b"get_dvfs"
            assert usb[43172:43183] == b"freq_to_idx"
            assert b"get_init_dvfs" not in pref
            assert b"freq_to_idx" not in pref
            assert usb[43184:43197] == b"set_dvfs_info"
            assert usb[43200:43211] == b"use_sys_pll"
            assert b"set_dvfs_info" not in pref
            assert b"use_sys_pll" not in pref
            assert usb[43380:43391] == b"use_fix_clk"
            assert usb[43595:43612] == b"sys pll lock done"
            assert b"use_fix_clk" not in pref
            assert b"sys pll lock done" not in pref
            assert usb[43392:43400] == b"set_dvfs"
            assert usb[43400] == 0
            assert usb[43392:43405] != b"set_dvfs_info"
            assert usb[43710:43730] == b"cpu clk suspend rate"
            assert usb[43852:43865] == b"set_dvfs_busy"
            assert usb[43868:43886] == b"high_task_set_dvfs"
            assert usb[44476:44487] == b"aml_thermal"
            assert b"cpu clk suspend rate" not in pref
            assert b"set_dvfs_busy" not in pref
            assert b"high_task_set_dvfs" not in pref
            assert b"aml_thermal" not in pref
            assert usb[43735:43754] == b"cpu clk resume rate"
            assert usb[43888:43907] == b"high_task_init_dvfs"
            assert usb[44496:44508] == b"bl30:thermal"
            assert usb[43932:43950] == b"JTAG force diasble"
            assert usb[43985:44002] == b"efuse_pw_en: 0x%x"
            assert b"cpu clk resume rate" not in pref
            assert b"high_task_init_dvfs" not in pref
            assert b"bl30:thermal" not in pref
            assert b"JTAG force diasble" not in pref
            assert b"efuse_pw_en: 0x%x" not in pref
            assert usb[43908:43930] == b"high_task_init_dvfstbl"
            assert usb[43952:43967] == b"disable M3 JTAG"
            assert usb[44004:44035] == b"WARNING! efuse bits is disabled"
            assert usb[44496:44521] == b"bl30:thermal disable trim"
            assert b"high_task_init_dvfstbl" not in pref
            assert b"disable M3 JTAG" not in pref
            assert b"WARNING! efuse bits is disabled" not in pref
            assert b"bl30:thermal disable trim" not in pref
            assert usb[43968:43984] == b"disable A53 JTAG"
            assert usb[44037:44051] == b"Enable M3 JTAG"
            assert usb[44540:44558] == b"bl30:thermal_calib"
            assert usb[44949:44982] == b"bl30: GXL ES chip disable thermal"
            assert b"disable A53 JTAG" not in pref
            assert b"Enable M3 JTAG" not in pref
            assert b"bl30:thermal_calib" not in pref
            assert b"bl30: GXL ES chip disable thermal" not in pref
            assert usb[44068:44083] == b"Enable A53 JTAG"
            assert usb[44052:44058] == b" to AO"
            assert usb[44578:44603] == b"bl30:ERROR: thermal_calib"
            assert usb[44695:44733] == b"bl30:This chip has not trimmed thermal"
            assert b"Enable A53 JTAG" not in pref
            assert b" to AO" not in pref
            assert b"bl30:ERROR: thermal_calib" not in pref
            assert b"bl30:This chip has not trimmed thermal" not in pref
            assert usb[44060:44066] == b" to EE"
            assert usb[44118:44143] == b"Error: Incorrect password"
            assert usb[44807:44836] == b"bl30:thermal_calibration_data"
            assert usb[44738:44750] == b"bl30:axg ver"
            assert b" to EE" not in pref
            assert b"Error: Incorrect password" not in pref
            assert b"bl30:thermal_calibration_data" not in pref
            assert b"bl30:axg ver" not in pref
            assert usb[44096:44116] == b"Error: Invalid input"
            assert usb[44145:44161] == b"Please try again"
            assert usb[44765:44782] == b"bl30:axg thermal0"
            assert usb[44784:44805] == b"bl30:thermal init err"
            assert b"Error: Invalid input" not in pref
            assert b"Please try again" not in pref
            assert b"bl30:axg thermal0" not in pref
            assert b"bl30:thermal init err" not in pref
            assert b"updateporc" not in pref
            assert b"aml_sdc_burn" not in pref
            assert b"nandrecovery" not in pref
            assert b"FIP TMP HDR" not in usb
            assert b"Never should be here!" not in usb
            assert b"PARAM_BL31" in usb
            assert b"S19k-Pro_BHB56XXX" in img
            assert b"GPIOAO_3" in usb
            assert usb[675920:675928] == b"GPIOAO_3"
            assert usb[675911:675916] == b"gpio "
            assert usb[675916:675920] != b"GPIO"
            assert usb[675911:675928] == b"gpio \xf0\x38\x98 GPIOAO_3"
            assert b"gpio GPIOAO_3" not in usb
            assert b"console=ttyS0" in usb
            assert b"uart,0xff803000" in usb
            assert b"recover_env=" not in usb
            assert usb.count(b"GPIOAO_3") == 1
            assert b"GPIOAO_0" not in usb
            assert b"GPIOAO_1" not in usb
            assert b"GPIOAO_2" not in usb
            assert b"gpio437" not in usb
            assert b"PWR_CONTROL" not in usb
            assert b"recover_env" not in usb
            assert b"nandrecovery" not in usb
            aml_dtb = img[1647360 : 1647360 + 29728]
            assert aml_dtb[:2] != b"\x1f\x8b"
            assert aml_dtb[:4] != b"AML_"
            assert aml_dtb[:4] != bytes.fromhex("d00dfeed")
            assert (
                hashlib.sha1(aml_dtb).hexdigest()
                == "8e1890fd2c43f6e7e10cc04b23c2073e88d7ab1b"
            )
            item15 = img[0x40 + 15 * 0x240 : 0x40 + 16 * 0x240]
            assert item15[0x20:0x23] == b"dtb"
            assert item15[0x120:0x12A] == b"meson1_ENC"
            assert int.from_bytes(item15[0x10:0x18], "little") == 1647360
            assert int.from_bytes(item15[0x18:0x20], "little") == 29728
            verify5 = img[1677088 : 1677088 + 48]
            assert verify5 == b"sha1sum 8e1890fd2c43f6e7e10cc04b23c2073e88d7ab1b"
            boot_blob = img[3315120 : 3315120 + 12907008]
            rec_blob = img[17069704 : 17069704 + 6064640]
            bl_blob = img[16222176 : 16222176 + 818688]
            assert (
                hashlib.sha1(boot_blob).hexdigest()
                == "97107df8e67ce465c3d71a7816d32b7b86f71d8e"
            )
            assert (
                hashlib.sha1(bl_blob).hexdigest()
                == "377d37642c69b9b7665cac669361693755bec457"
            )
            assert (
                hashlib.sha1(rec_blob).hexdigest()
                == "b6441d919a9e3c2ad6e503fe21b6ca0e361ac4c3"
            )
            assert (
                img[16222128 : 16222128 + 48]
                == b"sha1sum 97107df8e67ce465c3d71a7816d32b7b86f71d8e"
            )
            assert (
                img[17040864 : 17040864 + 48]
                == b"sha1sum 377d37642c69b9b7665cac669361693755bec457"
            )
            assert (
                img[23134344 : 23134344 + 48]
                == b"sha1sum b6441d919a9e3c2ad6e503fe21b6ca0e361ac4c3"
            )
            assert b"gpio437" not in aml_dtb
            assert b"PWR_CONTROL" not in aml_dtb
            meson_gz = img[17040928 : 17040928 + 28568]
            assert meson_gz[:2] == b"\x1f\x8b"
            import gzip

            meson = gzip.decompress(meson_gz)
            assert len(meson) == 114688
            assert meson[:4] == b"AML_"
            assert int.from_bytes(meson[4:8], "little") == 2
            assert int.from_bytes(meson[8:12], "little") == 2
            assert int.from_bytes(meson[12 + 48 : 12 + 52], "little") == 0x800
            assert (
                int.from_bytes(meson[12 + 56 + 48 : 12 + 56 + 52], "little") == 0x10800
            )
            assert b"PWR_CONTROL" not in meson
            assert b"gpio437" not in meson
            assert b"gpio-line-names" not in meson
            s30v = meson[0x10800 : 0x10800 + 0xB800]
            assert s30v[:4] == bytes.fromhex("d00dfeed")
            assert b"mcu6350" in s30v
            assert b"tas5782m" in s30v
            assert b"aml_pca9557@0x1f" in s30v
            assert b"aml, ledring" in s30v
            assert b"nvdata" in s30v
            assert b"amlogic,meson-axg-periphs-pinctrl" in s30v
            assert b"amlogic,meson-axg-aobus-pinctrl" in s30v
            assert b"pinctrl@ff634480" in s30v
            assert b"pinctrl@ff800014" in s30v
            assert b"gpio-controller" in s30v
            assert b"linux,gpio-base" not in s30v
            assert b"gpio-ranges" not in s30v
            assert b"gpio-line-names" not in s30v
            assert b"gpio437" not in s30v
            assert b"PWR_CONTROL" not in s30v
            assert b"GPIOA_0" not in s30v
            g1 = meson[0x800 : 0x800 + 0x10000]
            assert b"tas5707" in g1
            assert b"mcu6350" not in g1
            item4 = img[1647360 : 1647360 + 4]
            assert item4[:2] != b"\x1f\x8b"
            boot = img[3315120 : 3315120 + 12907008]
            rec = img[17069704 : 17069704 + 6064640]
            assert boot[:8] == b"ANDROID!"
            assert rec[:8] == b"ANDROID!"
            assert int.from_bytes(boot[8:12], "little") == 6031360
            assert int.from_bytes(boot[12:16], "little") == 0x01080000
            assert int.from_bytes(boot[16:20], "little") == 6842368
            assert int.from_bytes(boot[16:20], "little") != 0x66A000
            assert int.from_bytes(boot[20:24], "little") == 0x01000000
            assert int.from_bytes(boot[24:28], "little") == 30720
            assert int.from_bytes(boot[28:32], "little") == 0x00F00000
            assert int.from_bytes(boot[32:36], "little") == 0x00000100
            assert int.from_bytes(boot[36:40], "little") == 2048
            assert boot[48:64] == b"\x00" * 16
            assert boot[64:79] == b"init=/sbin/init"
            assert 2048 + 6031360 == 0x5C1000
            assert 2048 + 6031360 + 6842368 == 12875776
            assert boot[0x5C1000:0x5C1002] != b"\x1f\x8b"
            second = boot[12875776 : 12875776 + 30720]
            assert len(second) == 30720
            assert second[:4] == bytes.fromhex("27847e00")
            assert not second.startswith(b"ANDROID!")
            assert b"updateporc" not in second
            assert b"uart_trans" not in second
            assert b"nandrecovery" not in second
            assert boot[0x5C1800:0x5C1802] != b"\x1f\x8b"
            assert boot[0x5C1800:0x5C1804] != bytes.fromhex("04224d18")
            assert int.from_bytes(rec[12:16], "little") == 0x01080000
            assert int.from_bytes(rec[24:28], "little") == 30720
            assert int.from_bytes(rec[36:40], "little") == 2048
            assert rec[64:79] == b"init=/sbin/init"
            assert int.from_bytes(rec[8:12], "little") == 6031360
            assert int.from_bytes(rec[16:20], "little") == 0
            assert rec[0x400:0x408] == b"AMLSECU!"
            assert rec[0x410:0x420] == b"2023111515304721"
            assert boot[0x400:0x408] == b"AMLSECU!"
            assert boot[0x410:0x420] == b"2023111515304766"
            assert b"updateporc" not in boot
            assert b"updateporc" not in rec
            assert boot[2048 : 2048 + 64] == rec[2048 : 2048 + 64]
    assert "refuse_s19k_20231108_bmu_as_plaintext_porc" in install_rs
    assert "parse_s19k_single_bmu_toc" in install_rs
    assert "parse_s19k_android_boot_header" in install_rs
    assert "admit_s19k_20231108_single_bmu" in install_rs
    assert "S19K_ANDROID_BOOT_MAGIC" in install_rs
    assert "BOSMINER_PACKED_STRUCT_PACK_FN_VA: u64 = 0x008A_8D28" in init_seq
    assert "BOSMINER_COMMAND_RS_WRITE_FN_VA: u64 = 0x008B_1B98" in init_seq
    assert "BOSMINER_ANTMINER_AML_OPEN_FN_VA: u64 = 0x00BC_1F28" in init_seq
    assert "extract_s19k_single_bmu_datafile" in install_rs
    assert "refuse_held_fileparser_as_s19k_android_decoder" in install_rs
    assert "S19K_FILEPARSER_IN_78_EXTRACT: bool = false" in install_rs
    assert "HELD_CVITEK_FILEPARSER_DATAFILE_OFF: usize = 15460" in install_rs
    assert "parse_s19k_android_amlsecu_stamp" in install_rs
    assert "refuse_s19k_amlsecu_stamp_as_s21_decrypt_container" in install_rs
    assert "admit_s19k_uart_rescue_console" in install_rs
    assert "S19K_78_CONSOLE_MMIO: u32 = 0xFF80_3000" in install_rs
    assert "refuse_s19k_android_boot_as_mtd5_uimage" in install_rs
    assert "parse_s19k_uimage_header" in install_rs
    assert "refuse_xilinx_arm32_uimage_as_s19k_aml" in install_rs
    assert "UIMAGE_ARCH_ARM64: u8 = 22" in install_rs
    assert 'name: "stock_config"' in install_rs
    assert (
        'name: "reserved"'
        not in install_rs.split("pub const S19K_NAND_MAP", 1)[1].split(
            "pub enum S19kInstallCarrier", 1
        )[0]
    )
    nand_env_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_nand_env.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_s21_held_proc_mtd_matches_78" in nand_env_rs
    assert "classify_s19k_uboot_interrupt" in nand_env_rs
    assert "classify_s19k_uboot_flag_action" in nand_env_rs
    assert "refuse_s19k_flag_02_as_direct_mtd2_boot" in nand_env_rs
    assert "refuse_recover_to_stock_as_mtd5_uimage_write" in nand_env_rs
    assert "classify_s19k_stock_return_path" in nand_env_rs
    assert "firstboot-only is not an S19k stock-return path" in nand_env_rs
    assert "refuse_s19k_firstboot_env_flip_as_stock_return" in nand_env_rs
    assert "(true, _) => Ok(S19kStockReturnPath::FirstbootEnvFlip)" not in nand_env_rs
    assert "refuse_firstboot_as_recover_to_stock" in nand_env_rs
    assert "format_s19k_uboot_bootcmd_plan" in nand_env_rs
    assert "admit_s19k_uboot_bootcmd_plan" in nand_env_rs
    assert "S19kUbootBootcmdArm" in nand_env_rs
    assert "S19K_UBOOT_BOOTCMD_ARMS" in nand_env_rs
    assert "refuse_firstboot_as_mtd2_boot" in nand_env_rs
    assert "admit_s19k_78_bootcmd_has_no_firstboot" in nand_env_rs
    assert "admit_s19k_78_firstboot_unused_by_bootcmd" in nand_env_rs
    assert "S19K_DCENT_FIRSTBOOT_ENV_KEY" in nand_env_rs
    assert "S19K_78_FIRSTBOOT_ENV_VALUE" in nand_env_rs
    assert "admit_s19k_78_recover_env_ram" in nand_env_rs
    assert "S19K_78_RECOVER_ENV_RAM: u32 = 0x0106_0000" in nand_env_rs
    assert "S19K_78_ENV_IMPORT_SIZE: u32 = 0x1_0000" in nand_env_rs
    assert "admit_s19k_78_recover_env_nand_src" in nand_env_rs
    assert "admit_s19k_78_recover_erases_nvdata_after_recover_env" in nand_env_rs
    assert "admit_s19k_78_nand_env_has_no_mtdparts" in nand_env_rs
    assert "refuse_s19k_erase_nvdata_before_recover_env" in nand_env_rs
    assert "refuse_s19k_78_bos_overlay_as_uboot_nvdata" in nand_env_rs
    assert "admit_s19k_78_recover_env_default_before_import" in nand_env_rs
    assert "refuse_s19k_env_default_a_as_recover_env" in nand_env_rs
    assert "refuse_s19k_env_import_without_default_a" in nand_env_rs
    assert "refuse_s19k_uboot_compiled_defaults_as_nandrecovery_env" in nand_env_rs
    assert "admit_s19k_78_recover_env_import_flags" in nand_env_rs
    assert "refuse_s19k_dry_run_as_env_import_dash_d" in nand_env_rs
    assert "refuse_s19k_env_import_dash_c_as_continue" in nand_env_rs
    assert "refuse_s19k_zynq_do_env_import_as_78_recover_env" in nand_env_rs
    assert "S19K_78_NANDRECOVERY_ENV: u64 = 0x0B00_0000" in nand_env_rs
    assert "S19K_78_ENV_SIZE: u64 = 0x1_0000" in nand_env_rs
    revert_sh = (ROOT / "scripts/revert_to_stock_am3_aml_s19k.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "does NOT boot mtd2" in revert_sh
    assert "NOT recover_to_stock" in revert_sh
    assert "Reboot now to start stock firmware" not in revert_sh
    assert "refusing firstboot-only" in revert_sh
    assert "REVERT_COMMIT_PLAN" in revert_sh
    assert "recover_env_source=nandrecovery_env.bin" in revert_sh
    assert "does NOT arm flag 0x02" in revert_sh
    assert "schema=dcentos.amlogic-stock-image-revert/v1" in revert_sh
    assert "\nfw_setenv firstboot 1\n" not in revert_sh
    assert "refuse_s19k_firstboot_only_as_revert_commit" in install_rs
    assert "format_s19k_stock_image_revert_plan" in install_rs
    assert "admit_s19k_revert_script_refuses_firstboot_only" in install_rs
    assert "admit_s19k_revert_script_dry_run_before_nandwrite" in install_rs
    assert "refuse_s19k_revert_nandwrite_without_recover_commit" in install_rs
    assert "admit_s19k_revert_script_execute_refuses_nandwrite" in install_rs
    assert "admit_s19k_restore_script_execute_refuses_nandwrite" in install_rs
    assert "admit_s19k_restore_script_execute_requires_proc_mtd" in install_rs
    assert "admit_s19k_restore_execute_live_proc_mtd" in install_rs
    assert "admit_s19k_recovery_flag_script_execute_refuses_nandwrite" in install_rs
    assert "admit_s19k_restore_execute" in install_rs
    restore_sh = (ROOT / "scripts/restore_amlogic_mtd5_from_backup.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert (
        "CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite"
        in restore_sh
    )
    assert restore_sh.find("Type 'RESTORE'") < restore_sh.find(
        "CLEAR_FOR_FLASH=false — refusing"
    )
    assert restore_sh.find("CLEAR_FOR_FLASH=false — refusing") < restore_sh.find(
        "gpio437 SafeOff (am3-s19k-active-low, value=1)"
    )
    assert "missing live /proc/mtd; refuse geometry-blind restore" in restore_sh
    assert "if [ -r /proc/mtd ]; then" not in restore_sh
    assert restore_sh.find("CLEAR_FOR_FLASH=false — refusing") < restore_sh.find(
        "missing live /proc/mtd; refuse geometry-blind restore"
    )
    assert restore_sh.find(
        "missing live /proc/mtd; refuse geometry-blind restore"
    ) < restore_sh.find("gpio437 SafeOff (am3-s19k-active-low, value=1)")
    assert "--dry-run" in revert_sh
    assert "[DRY RUN] writing REVERT_COMMIT_PLAN before GPIO/nandwrite" in revert_sh
    assert "dry_run=true" in revert_sh
    assert revert_sh.find("[DRY RUN]") < revert_sh.find("nandwrite -p -s")
    assert revert_sh.find("[DRY RUN]") < revert_sh.find("gpio437 SafeOff")
    assert (
        "CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/nandwrite/fw_setenv"
        in revert_sh
    )
    assert "write_revert_commit_plan false false" in revert_sh
    assert revert_sh.find("Type 'REVERT'") < revert_sh.find(
        "CLEAR_FOR_FLASH=false — refusing"
    )
    assert revert_sh.find("CLEAR_FOR_FLASH=false — refusing") < revert_sh.find(
        "nandwrite -p -s"
    )
    assert revert_sh.find("CLEAR_FOR_FLASH=false — refusing") < revert_sh.find(
        "gpio437 SafeOff"
    )
    flag_sh = (ROOT / "scripts/s19k_write_recovery_flag.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "NOT a direct bootm of mtd2" in flag_sh
    assert "NOT fw_setenv firstboot" in flag_sh
    assert (
        "CLEAR_FOR_FLASH=false — refusing gpio437 SafeOff/flash_erase/nandwrite"
        in flag_sh
    )
    assert flag_sh.find(
        'if [ "${DCENT_S19K_RECOVERY_FLAG_EXECUTE:-0}" != 1 ]'
    ) < flag_sh.find("missing exact live platform:target identity")
    assert flag_sh.find("missing exact live platform:target identity") < flag_sh.find(
        "CLEAR_FOR_FLASH=false — refusing"
    )
    assert "is not exact am3-aml-s19k:am3-s19k" in flag_sh
    assert "one_byte_execute_retired=true" in flag_sh
    assert "full_eraseblock_candidate_required=true" in flag_sh
    assert 'flash_erase /dev/mtd5 "$EB_START_HEX" 1' not in flag_sh
    assert 'nandwrite -p -s "$EB_START_HEX" /dev/mtd5' not in flag_sh
    install_sh = (ROOT / "scripts/install_amlogic_persistent.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert (
        "U-Boot will revert to mtd2 stock_system if first boot fails" not in install_sh
    )
    assert "RECOVER_TO_STOCK_PLAN.txt" in install_sh
    assert "schema=dcentos.amlogic-recover-to-stock/v1" in install_sh
    assert "RECOVER_EXECUTE_REFUSE.txt" in install_sh
    assert install_sh.find("BACKUP_LEDGER.txt written") < install_sh.find(
        "RECOVER_TO_STOCK_PLAN.txt"
    )
    assert install_sh.find("RECOVER_TO_STOCK_PLAN.txt") < install_sh.find(
        "[BACKUP-ONLY]"
    )
    assert "recover_to_stock" in install_sh
    assert "refuse_boot_bos_as_mtd5_uimage_write" in nand_env_rs
    assert "refuse_s19k_78_mtd3_as_reserved" in nand_env_rs
    assert "S19K_78_NAND_ENV_CRC: u32 = 0x471D_6B1A" in nand_env_rs
    assert "S19K_78_NANDRECOVERY_ENV: u64 = 0x0B00_0000" in nand_env_rs
    assert "S19K_78_RECOVERY_SET_FLAG:" in nand_env_rs
    assert "S19K_78_RECOVERY_SET_FLAG_2:" in nand_env_rs
    assert "nand erase ${nandrecovery_flag_offset} 0x20000" in nand_env_rs
    assert "admit_s19k_78_recovery_set_flag" in nand_env_rs
    nand_env_bin = (
        ROOT.parents[1]
        / ""
        / "00-system/nand_env.bin"
    )
    if nand_env_bin.is_file():
        envb = nand_env_bin.read_bytes()
        assert b"recovery_set_flag_2=" in envb
        assert b"mw.b ${flagcmpaddr} ${recovery_flag_first_boot}" in envb
        assert b"nand erase ${nandrecovery_flag_offset} 0x20000" in envb
        assert b"recover_to_stock=" in envb
        assert b"run recover_to_stock" in envb
        assert b"firstboot=1" in envb
        assert b"${firstboot}" not in envb
        assert b"androidboot.firstboot=1" in envb
    dtb_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_aml_dtb.rs").read_text(
        encoding="utf-8"
    )
    assert "classify_s19k_uboot_nand_device" in dtb_rs
    assert "refuse_s19k_78_linux_mtd_as_uboot_nvdata" in dtb_rs
    assert "refuse_s19k_20231115_emmc_nvdata_as_aml_nand" in dtb_rs
    assert "S19K_UBOOT_NANDNORMAL_DEVICE: u8 = 1" in dtb_rs
    assert "S19K_DTB_NVDATA_FILL_REST" in dtb_rs
    assert "admit_vnish_s19k_aml_soc_dtb" in dtb_rs
    assert "refuse_vnish_s19k_dtb_as_gpio437_polarity" in dtb_rs
    assert "VNISH_S19K_AML_DTB_BYTES: usize = 20_945" in dtb_rs
    assert "VNISH_S19K_AML_AO_UART1_MMIO: u32 = 0xFF80_4000" in dtb_rs
    assert "parse_s19k_aml_multi_dtb" in dtb_rs
    assert 'S19K_AML_MULTI_DTB_MAGIC: &[u8; 4] = b"AML_"' in dtb_rs
    assert "S19K_FACTORY_MESON1_ENTRY1_OFF: u32 = 0x1_0800" in dtb_rs
    assert "admit_s19k_factory_meson1_header" in dtb_rs
    assert "admit_s19k_factory_s30v_nand_sizes" in dtb_rs
    assert "classify_s19k_factory_meson1_i2c" in dtb_rs
    assert "refuse_s19k_factory_meson1_as_gpio437" in dtb_rs
    assert "refuse_s19k_usb_uboot_gpioao3_as_gpio437" in dtb_rs
    assert "refuse_s19k_usb_uboot_as_recover_env" in dtb_rs
    assert 'S19K_USB_UBOOT_GPIOAO3: &str = "GPIOAO_3"' in dtb_rs
    assert "s19k_aml_multi_dtb_inner" in dtb_rs
    assert "refuse_s19k_meson1_gzip_as_raw_fdt" in dtb_rs
    assert 'S19K_FACTORY_S30V_MCU: &str = "mcu6350"' in dtb_rs
    assert "parse_s19k_aml_dtb_gpio_controllers" in dtb_rs
    assert "admit_s19k_s30v_axg_gpio_controllers" in dtb_rs
    assert "refuse_s19k_dt_math_as_gpio437" in dtb_rs
    assert "refuse_s19k_vendor_gpiochip_base_as_dt_cell" in dtb_rs
    assert "refuse_s19k_gpioao3_local_as_gpio437" in dtb_rs
    assert "S19K_AXG_PERIPHS_MUX: u32 = 0xFF63_4480" in dtb_rs
    assert "S19K_AXG_AOBUS_MUX: u32 = 0xFF80_0014" in dtb_rs
    assert "S19K_AXG_VENDOR_GPIOCHIP_BASE: u32 = 411" in dtb_rs
    assert "S19K_AXG_GPIOA0_LOCAL: u32 = 26" in dtb_rs
    assert "S19K_USB_UBOOT_GPIOAO3_OFF: usize = 675_925" in dtb_rs
    assert "S19K_USB_UBOOT_GPIO_WORD_OFF: usize = 675_916" in dtb_rs
    assert "admit_s19k_usb_uboot_gpioao3_offset" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_gpio_word" in dtb_rs
    assert "refuse_s19k_usb_uboot_contiguous_gpio_cmd" in dtb_rs
    assert "refuse_s19k_usb_uboot_gpioao_as_pin_table" in dtb_rs
    assert "S19K_SDC_UBOOT_GPIOAO3_OFF: usize = 725_589" in dtb_rs
    assert "S19K_UBOOT_GPIOAO3_FROM_END: usize = 93_099" in dtb_rs
    assert "admit_s19k_uboot_packed_gpioao3_seq" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_console" in dtb_rs
    assert "refuse_s19k_usb_uboot_packed_as_nand_env" in dtb_rs
    assert 'S19K_FACTORY_PCA9557_NODE: &str = "aml_pca9557@0x1f"' in dtb_rs
    assert 'S19K_FACTORY_LEDRING: &str = "aml, ledring"' in dtb_rs
    assert 'S19K_USB_UBOOT_I2C_MW_1F: &[u8] = b"i2c mw 1f 3.1 0 2"' in dtb_rs
    assert "S19K_USB_UBOOT_I2C_MW_1F_OFF: usize = 674_340" in dtb_rs
    assert "admit_s19k_factory_pca9557_ledring" in dtb_rs
    assert "admit_s19k_usb_uboot_i2c_mw_1f" in dtb_rs
    assert "refuse_s19k_i2c_mw_1f_as_gpio437" in dtb_rs
    assert "S19K_USB_UBOOT_SETENV_OFF: usize = 674_967" in dtb_rs
    assert 'S19K_USB_UBOOT_SETENV_PREFIX: &[u8] = b"setenv boo"' in dtb_rs
    assert "admit_s19k_usb_uboot_packed_setenv" in dtb_rs
    assert "refuse_s19k_usb_setenv_as_bootcmd" in dtb_rs
    assert "refuse_s19k_usb_setenv_as_firstboot" in dtb_rs
    assert "refuse_s19k_usb_quoted_mtdids_as_mtdparts" in dtb_rs
    assert "S19K_USB_UBOOT_LOGO_OFF: usize = 674_989" in dtb_rs
    assert 'S19K_USB_UBOOT_LOGO: &[u8] = b"logo=${display_layer}"' in dtb_rs
    assert "S19K_USB_UBOOT_ANDROID9_OFF: usize = 675_016" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_logo" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_android9" in dtb_rs
    assert "refuse_s19k_usb_logo_as_nand_bootargs" in dtb_rs
    assert "refuse_s19k_usb_android9_as_s19k_rootfs" in dtb_rs
    assert "S19K_USB_UBOOT_HARDWARE_OFF: usize = 675_071" in dtb_rs
    assert 'S19K_USB_UBOOT_HARDWARE: &[u8] = b"hardware"' in dtb_rs
    assert "S19K_USB_UBOOT_IOGIC_OFF: usize = 675_081" in dtb_rs
    assert 'S19K_USB_UBOOT_IOGIC: &[u8] = b"Iogic"' in dtb_rs
    assert "S19K_USB_UBOOT_BASEBAND_OFF: usize = 675_118" in dtb_rs
    assert 'S19K_USB_UBOOT_BASEBAND: &[u8] = b"baseband=N/A"' in dtb_rs
    assert "admit_s19k_usb_uboot_packed_hardware" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_iogic" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_baseband" in dtb_rs
    assert "refuse_s19k_usb_hardware_as_board_id" in dtb_rs
    assert "refuse_s19k_usb_iogic_as_amlogic" in dtb_rs
    assert "admit_s19k_usb_uboot_atf_plat_amlogic" in dtb_rs
    assert "refuse_s19k_usb_plat_amlogic_as_miner_nand" in dtb_rs
    assert "plat/amlogic/common/bl31_plat_setup.c" in dtb_rs
    assert "Amlogic-secure-boot-module-v0.4" in dtb_rs
    assert "S19K_USB_UBOOT_UILD_EXPECT_OFF: usize = 675_106" in dtb_rs
    assert 'S19K_USB_UBOOT_UILD_EXPECT: &[u8] = b"uild.expect"' in dtb_rs
    assert "S19K_USB_UBOOT_ACMDLIN_OFF: usize = 675_132" in dtb_rs
    assert 'S19K_USB_UBOOT_ACMDLIN: &[u8] = b"acmdlin"' in dtb_rs
    assert "admit_s19k_usb_uboot_packed_uild_expect" in dtb_rs
    assert "S19K_USB_UBOOT_SARADC_CH2_OFF: usize = 686_169" in dtb_rs
    assert 'S19K_USB_UBOOT_SARADC_CH2: &[u8] = b"SARADC channel2"' in dtb_rs
    assert "S19K_USB_UBOOT_SARADC_WORD_OFF: usize = 686_158" in dtb_rs
    assert "admit_s19k_usb_uboot_saradc_channel2" in dtb_rs
    assert "admit_s19k_usb_uboot_txfifo_speed_enum" in dtb_rs
    assert "refuse_s19k_usb_txfifo_as_hash_fifo" in dtb_rs
    assert "refuse_s19k_usb_speed_enum_as_chip_enum" in dtb_rs
    assert "admit_s19k_usb_uboot_addr_mask" in dtb_rs
    assert "refuse_s19k_usb_addr_mask_as_nandrecovery" in dtb_rs
    assert "admit_s19k_usb_uboot_ramoops" in dtb_rs
    assert "refuse_s19k_usb_ramoops_as_recover_env" in dtb_rs
    assert 'S19K_USB_UBOOT_TXFIFO_FULL: &[u8] = b"TxFIFO FULL"' in dtb_rs
    assert "S19K_USB_UBOOT_TXFIFO_FULL_OFF: usize = 729_904" in dtb_rs
    assert 'S19K_USB_UBOOT_SPEED_ENUM: &[u8] = b"SPEED ENUM"' in dtb_rs
    assert "S19K_USB_UBOOT_SPEED_ENUM_OFF: usize = 729_940" in dtb_rs
    assert 'S19K_USB_UBOOT_ADDR_MASK: &[u8] = b"ADDR_MASK_48_TO_63"' in dtb_rs
    assert "S19K_USB_UBOOT_ADDR_MASK_OFF: usize = 257_284" in dtb_rs
    assert 'S19K_USB_UBOOT_RAMOOPS: &[u8] = b"ramoops"' in dtb_rs
    assert "S19K_USB_UBOOT_RAMOOPS_OFF: usize = 674_787" in dtb_rs
    assert "admit_s19k_usb_uboot_cortex_exception" in dtb_rs
    assert "refuse_s19k_usb_cortex_exception_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_cortex_task_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_EXCEPTION: &[u8] = b"=== %s EXCEPTION:"' in dtb_rs
    assert "S19K_USB_UBOOT_EXCEPTION_OFF: usize = 41_822" in dtb_rs
    assert (
        'S19K_USB_UBOOT_PSTACK: &[u8] = b"=========== Process Stack Contents ==========="'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_PSTACK_OFF: usize = 41_995" in dtb_rs
    assert 'S19K_USB_UBOOT_CORTEX_TASK: &[u8] = b"core/cortex-m/task.c"' in dtb_rs
    assert "S19K_USB_UBOOT_CORTEX_TASK_OFF: usize = 42_807" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_task_table" in dtb_rs
    assert "refuse_s19k_usb_ec_task_table_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_task_table_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_WAIT_EVT: &[u8] = b"__wait_evt"' in dtb_rs
    assert "S19K_USB_UBOOT_WAIT_EVT_OFF: usize = 42_640" in dtb_rs
    assert 'S19K_USB_UBOOT_TASK_READY: &[u8] = b"Task Ready Name"' in dtb_rs
    assert "S19K_USB_UBOOT_TASK_READY_OFF: usize = 42_692" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_mutex_svc" in dtb_rs
    assert "refuse_s19k_usb_ec_mutex_svc_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_mutex_svc_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_MUTEX_LOCK: &[u8] = b"mutex_lock"' in dtb_rs
    assert "S19K_USB_UBOOT_MUTEX_LOCK_OFF: usize = 42_652" in dtb_rs
    assert 'S19K_USB_UBOOT_SVC_HANDLER: &[u8] = b"svc_handler"' in dtb_rs
    assert "S19K_USB_UBOOT_SVC_HANDLER_OFF: usize = 42_680" in dtb_rs
    assert 'S19K_USB_UBOOT_TASK_EXIT: &[u8] = b"Task %d (%s) exited!"' in dtb_rs
    assert "S19K_USB_UBOOT_TASK_EXIT_OFF: usize = 42_868" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_task_set_stack" in dtb_rs
    assert "refuse_s19k_usb_ec_task_set_stack_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_stack_ov_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_TASK_SET_EVENT: &[u8] = b"task_set_event"' in dtb_rs
    assert "S19K_USB_UBOOT_TASK_SET_EVENT_OFF: usize = 42_664" in dtb_rs
    assert 'S19K_USB_UBOOT_STACK_OV: &[u8] = b"Stack overflow in %s task!"' in dtb_rs
    assert "S19K_USB_UBOOT_STACK_OV_OFF: usize = 42_900" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_idle" in dtb_rs
    assert "refuse_s19k_usb_ec_idle_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_idle_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_TASKS_READY: &[u8] = b"tasks_ready"' in dtb_rs
    assert "S19K_USB_UBOOT_TASKS_READY_OFF: usize = 42_928" in dtb_rs
    assert 'S19K_USB_UBOOT_IDLE: &[u8] = b"<< idle >>"' in dtb_rs
    assert "S19K_USB_UBOOT_IDLE_OFF: usize = 42_940" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_hooks_timer" in dtb_rs
    assert "refuse_s19k_usb_ec_hooks_timer_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_hooks_timer_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_HOOKS: &[u8] = b"HOOKS"' in dtb_rs
    assert "S19K_USB_UBOOT_HOOKS_OFF: usize = 42_951" in dtb_rs
    assert 'S19K_USB_UBOOT_TIMERTASK: &[u8] = b"TIMERTASK"' in dtb_rs
    assert "S19K_USB_UBOOT_TIMERTASK_OFF: usize = 42_957" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_mailbox" in dtb_rs
    assert "refuse_s19k_usb_ec_mailbox_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_mailbox_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_LOWMAILBOX: &[u8] = b"LOWMAILBOX"' in dtb_rs
    assert "S19K_USB_UBOOT_LOWMAILBOX_OFF: usize = 42_967" in dtb_rs
    assert 'S19K_USB_UBOOT_HIGHMAILBOX: &[u8] = b"HIGHMAILBOX"' in dtb_rs
    assert "S19K_USB_UBOOT_HIGHMAILBOX_OFF: usize = 42_978" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_sec_userlow" in dtb_rs
    assert "refuse_s19k_usb_ec_sec_userlow_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_sec_userlow_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_SECMAILBOX: &[u8] = b"SECMAILBOX"' in dtb_rs
    assert "S19K_USB_UBOOT_SECMAILBOX_OFF: usize = 42_990" in dtb_rs
    assert 'S19K_USB_UBOOT_USERLOWTASK: &[u8] = b"USERLOWTASK"' in dtb_rs
    assert "S19K_USB_UBOOT_USERLOWTASK_OFF: usize = 43_001" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_user_high_secure" in dtb_rs
    assert "refuse_s19k_usb_ec_user_high_secure_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_user_high_secure_as_nandrecovery" in dtb_rs
    assert 'S19K_USB_UBOOT_USERHIGHTASK: &[u8] = b"USERHIGHTASK"' in dtb_rs
    assert "S19K_USB_UBOOT_USERHIGHTASK_OFF: usize = 43_013" in dtb_rs
    assert 'S19K_USB_UBOOT_USERSECURETASK: &[u8] = b"USERSECURETASK"' in dtb_rs
    assert "S19K_USB_UBOOT_USERSECURETASK_OFF: usize = 43_026" in dtb_rs
    assert "admit_s19k_usb_uboot_ec_timer_efuse" in dtb_rs
    assert "refuse_s19k_usb_ec_timer_efuse_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ec_timer_efuse_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_empty_efuse_as_otp_decrypt" in dtb_rs
    assert 'S19K_USB_UBOOT_TIMERFORADC: &[u8] = b"TIMERFORADCTASK"' in dtb_rs
    assert "S19K_USB_UBOOT_TIMERFORADC_OFF: usize = 43_041" in dtb_rs
    assert (
        'S19K_USB_UBOOT_EMPTY_EFUSE: &[u8] = b"empty chip, efuse not burned."' in dtb_rs
    )
    assert "S19K_USB_UBOOT_EMPTY_EFUSE_OFF: usize = 43_064" in dtb_rs
    assert "admit_s19k_usb_uboot_es_chip_dvfs" in dtb_rs
    assert "refuse_s19k_usb_es_chip_dvfs_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_es_chip_dvfs_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_dvfs_as_hash_pll" in dtb_rs
    assert "refuse_s19k_usb_es_chip_as_miner_identity" in dtb_rs
    assert 'S19K_USB_UBOOT_ES_CHIP: &[u8] = b"This is ES chip"' in dtb_rs
    assert "S19K_USB_UBOOT_ES_CHIP_OFF: usize = 43_096" in dtb_rs
    assert 'S19K_USB_UBOOT_DVFS_VOL: &[u8] = b"is_set_dvfs_vol_first"' in dtb_rs
    assert "S19K_USB_UBOOT_DVFS_VOL_OFF: usize = 43_120" in dtb_rs
    assert "admit_s19k_usb_uboot_dvfs_freq" in dtb_rs
    assert "refuse_s19k_usb_dvfs_freq_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_dvfs_freq_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_freq_to_idx_as_hash_pll" in dtb_rs
    assert 'S19K_USB_UBOOT_GET_INIT_DVFS: &[u8] = b"get_init_dvfs"' in dtb_rs
    assert "S19K_USB_UBOOT_GET_INIT_DVFS_OFF: usize = 43_144" in dtb_rs
    assert 'S19K_USB_UBOOT_GET_DVFS: &[u8] = b"get_dvfs"' in dtb_rs
    assert "S19K_USB_UBOOT_GET_DVFS_OFF: usize = 43_160" in dtb_rs
    assert 'S19K_USB_UBOOT_FREQ_TO_IDX: &[u8] = b"freq_to_idx"' in dtb_rs
    assert "S19K_USB_UBOOT_FREQ_TO_IDX_OFF: usize = 43_172" in dtb_rs
    assert "admit_s19k_usb_uboot_dvfs_sys_pll" in dtb_rs
    assert "refuse_s19k_usb_dvfs_sys_pll_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_dvfs_sys_pll_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_use_sys_pll_as_hash_pll" in dtb_rs
    assert 'S19K_USB_UBOOT_SET_DVFS_INFO: &[u8] = b"set_dvfs_info"' in dtb_rs
    assert "S19K_USB_UBOOT_SET_DVFS_INFO_OFF: usize = 43_184" in dtb_rs
    assert 'S19K_USB_UBOOT_USE_SYS_PLL: &[u8] = b"use_sys_pll"' in dtb_rs
    assert "S19K_USB_UBOOT_USE_SYS_PLL_OFF: usize = 43_200" in dtb_rs
    assert "admit_s19k_usb_uboot_fix_clk_pll_lock" in dtb_rs
    assert "refuse_s19k_usb_fix_clk_pll_lock_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_fix_clk_pll_lock_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_sys_pll_lock_as_hash_pll" in dtb_rs
    assert 'S19K_USB_UBOOT_USE_FIX_CLK: &[u8] = b"use_fix_clk"' in dtb_rs
    assert "S19K_USB_UBOOT_USE_FIX_CLK_OFF: usize = 43_380" in dtb_rs
    assert 'S19K_USB_UBOOT_SYS_PLL_LOCK: &[u8] = b"sys pll lock done"' in dtb_rs
    assert "S19K_USB_UBOOT_SYS_PLL_LOCK_OFF: usize = 43_595" in dtb_rs
    assert "admit_s19k_usb_uboot_dvfs_thermal" in dtb_rs
    assert "refuse_s19k_usb_dvfs_thermal_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_dvfs_thermal_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_cpu_clk_suspend_as_hash_pll" in dtb_rs
    assert "refuse_s19k_usb_aml_thermal_as_hash_thermal" in dtb_rs
    assert 'S19K_USB_UBOOT_SET_DVFS: &[u8] = b"set_dvfs"' in dtb_rs
    assert "S19K_USB_UBOOT_SET_DVFS_OFF: usize = 43_392" in dtb_rs
    assert 'S19K_USB_UBOOT_CPU_CLK_SUSPEND: &[u8] = b"cpu clk suspend rate"' in dtb_rs
    assert "S19K_USB_UBOOT_CPU_CLK_SUSPEND_OFF: usize = 43_710" in dtb_rs
    assert 'S19K_USB_UBOOT_SET_DVFS_BUSY: &[u8] = b"set_dvfs_busy"' in dtb_rs
    assert "S19K_USB_UBOOT_SET_DVFS_BUSY_OFF: usize = 43_852" in dtb_rs
    assert 'S19K_USB_UBOOT_HIGH_TASK_SET_DVFS: &[u8] = b"high_task_set_dvfs"' in dtb_rs
    assert "S19K_USB_UBOOT_HIGH_TASK_SET_DVFS_OFF: usize = 43_868" in dtb_rs
    assert 'S19K_USB_UBOOT_AML_THERMAL: &[u8] = b"aml_thermal"' in dtb_rs
    assert "S19K_USB_UBOOT_AML_THERMAL_OFF: usize = 44_476" in dtb_rs
    assert "admit_s19k_usb_uboot_bl30_jtag_efuse" in dtb_rs
    assert "refuse_s19k_usb_bl30_jtag_efuse_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_bl30_jtag_efuse_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_cpu_clk_resume_as_hash_pll" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_as_hash_thermal" in dtb_rs
    assert "refuse_s19k_usb_efuse_pw_en_as_otp_decrypt" in dtb_rs
    assert 'S19K_USB_UBOOT_CPU_CLK_RESUME: &[u8] = b"cpu clk resume rate"' in dtb_rs
    assert "S19K_USB_UBOOT_CPU_CLK_RESUME_OFF: usize = 43_735" in dtb_rs
    assert (
        'S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS: &[u8] = b"high_task_init_dvfs"' in dtb_rs
    )
    assert "S19K_USB_UBOOT_HIGH_TASK_INIT_DVFS_OFF: usize = 43_888" in dtb_rs
    assert 'S19K_USB_UBOOT_BL30_THERMAL: &[u8] = b"bl30:thermal"' in dtb_rs
    assert "S19K_USB_UBOOT_BL30_THERMAL_OFF: usize = 44_496" in dtb_rs
    assert 'S19K_USB_UBOOT_JTAG_FORCE: &[u8] = b"JTAG force diasble"' in dtb_rs
    assert "S19K_USB_UBOOT_JTAG_FORCE_OFF: usize = 43_932" in dtb_rs
    assert 'S19K_USB_UBOOT_EFUSE_PW_EN: &[u8] = b"efuse_pw_en: 0x%x"' in dtb_rs
    assert "S19K_USB_UBOOT_EFUSE_PW_EN_OFF: usize = 43_985" in dtb_rs
    assert "admit_s19k_usb_uboot_dvfstbl_jtag_trim" in dtb_rs
    assert "refuse_s19k_usb_dvfstbl_jtag_trim_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_dvfstbl_jtag_trim_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_efuse_bits_disabled_as_otp_decrypt" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_trim_as_hash_thermal" in dtb_rs
    assert (
        'S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL: &[u8] = b"high_task_init_dvfstbl"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_HIGH_TASK_INIT_DVFSTBL_OFF: usize = 43_908" in dtb_rs
    assert 'S19K_USB_UBOOT_DISABLE_M3_JTAG: &[u8] = b"disable M3 JTAG"' in dtb_rs
    assert "S19K_USB_UBOOT_DISABLE_M3_JTAG_OFF: usize = 43_952" in dtb_rs
    assert (
        'S19K_USB_UBOOT_EFUSE_BITS_DISABLED: &[u8] = b"WARNING! efuse bits is disabled"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_EFUSE_BITS_DISABLED_OFF: usize = 44_004" in dtb_rs
    assert (
        'S19K_USB_UBOOT_BL30_THERMAL_TRIM: &[u8] = b"bl30:thermal disable trim"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_BL30_THERMAL_TRIM_OFF: usize = 44_496" in dtb_rs
    assert "admit_s19k_usb_uboot_a53_gxl_thermal" in dtb_rs
    assert "refuse_s19k_usb_a53_gxl_thermal_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_a53_gxl_thermal_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_calib_as_hash_thermal" in dtb_rs
    assert "refuse_s19k_usb_gxl_es_thermal_as_miner_identity" in dtb_rs
    assert 'S19K_USB_UBOOT_DISABLE_A53_JTAG: &[u8] = b"disable A53 JTAG"' in dtb_rs
    assert "S19K_USB_UBOOT_DISABLE_A53_JTAG_OFF: usize = 43_968" in dtb_rs
    assert 'S19K_USB_UBOOT_ENABLE_M3_JTAG: &[u8] = b"Enable M3 JTAG"' in dtb_rs
    assert "S19K_USB_UBOOT_ENABLE_M3_JTAG_OFF: usize = 44_037" in dtb_rs
    assert 'S19K_USB_UBOOT_BL30_THERMAL_CALIB: &[u8] = b"bl30:thermal_calib"' in dtb_rs
    assert "S19K_USB_UBOOT_BL30_THERMAL_CALIB_OFF: usize = 44_540" in dtb_rs
    assert (
        'S19K_USB_UBOOT_GXL_ES_THERMAL: &[u8] = b"bl30: GXL ES chip disable thermal"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_GXL_ES_THERMAL_OFF: usize = 44_949" in dtb_rs
    assert "admit_s19k_usb_uboot_a53_ao_untrimmed" in dtb_rs
    assert "refuse_s19k_usb_a53_ao_untrimmed_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_a53_ao_untrimmed_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_calib_err_as_hash_thermal" in dtb_rs
    assert "refuse_s19k_usb_bl30_untrimmed_as_hash_thermal" in dtb_rs
    assert 'S19K_USB_UBOOT_ENABLE_A53_JTAG: &[u8] = b"Enable A53 JTAG"' in dtb_rs
    assert "S19K_USB_UBOOT_ENABLE_A53_JTAG_OFF: usize = 44_068" in dtb_rs
    assert 'S19K_USB_UBOOT_JTAG_TO_AO: &[u8] = b" to AO"' in dtb_rs
    assert "S19K_USB_UBOOT_JTAG_TO_AO_OFF: usize = 44_052" in dtb_rs
    assert (
        'S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR: &[u8] = b"bl30:ERROR: thermal_calib"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_BL30_THERMAL_CALIB_ERR_OFF: usize = 44_578" in dtb_rs
    assert (
        'S19K_USB_UBOOT_BL30_UNTRIMMED: &[u8] = b"bl30:This chip has not trimmed thermal"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_BL30_UNTRIMMED_OFF: usize = 44_695" in dtb_rs
    assert "admit_s19k_usb_uboot_ee_pw_axg" in dtb_rs
    assert "refuse_s19k_usb_ee_pw_axg_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ee_pw_axg_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_incorrect_password_as_miner_auth" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_cal_data_as_hash_thermal" in dtb_rs
    assert "refuse_s19k_usb_bl30_axg_ver_as_miner_identity" in dtb_rs
    assert 'S19K_USB_UBOOT_JTAG_TO_EE: &[u8] = b" to EE"' in dtb_rs
    assert "S19K_USB_UBOOT_JTAG_TO_EE_OFF: usize = 44_060" in dtb_rs
    assert (
        'S19K_USB_UBOOT_INCORRECT_PASSWORD: &[u8] = b"Error: Incorrect password"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_INCORRECT_PASSWORD_OFF: usize = 44_118" in dtb_rs
    assert (
        'S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA: &[u8] = b"bl30:thermal_calibration_data"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_BL30_THERMAL_CAL_DATA_OFF: usize = 44_807" in dtb_rs
    assert 'S19K_USB_UBOOT_BL30_AXG_VER: &[u8] = b"bl30:axg ver"' in dtb_rs
    assert "S19K_USB_UBOOT_BL30_AXG_VER_OFF: usize = 44_738" in dtb_rs
    assert "admit_s19k_usb_uboot_invalid_try_thermal0" in dtb_rs
    assert "refuse_s19k_usb_invalid_try_thermal0_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_invalid_try_thermal0_as_nandrecovery" in dtb_rs
    assert "refuse_s19k_usb_invalid_input_as_miner_auth" in dtb_rs
    assert "refuse_s19k_usb_bl30_axg_thermal0_as_hash_thermal" in dtb_rs
    assert "refuse_s19k_usb_bl30_thermal_init_err_as_hash_thermal" in dtb_rs
    assert 'S19K_USB_UBOOT_INVALID_INPUT: &[u8] = b"Error: Invalid input"' in dtb_rs
    assert "S19K_USB_UBOOT_INVALID_INPUT_OFF: usize = 44_096" in dtb_rs
    assert 'S19K_USB_UBOOT_PLEASE_TRY_AGAIN: &[u8] = b"Please try again"' in dtb_rs
    assert "S19K_USB_UBOOT_PLEASE_TRY_AGAIN_OFF: usize = 44_145" in dtb_rs
    assert 'S19K_USB_UBOOT_BL30_AXG_THERMAL0: &[u8] = b"bl30:axg thermal0"' in dtb_rs
    assert "S19K_USB_UBOOT_BL30_AXG_THERMAL0_OFF: usize = 44_765" in dtb_rs
    assert (
        'S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR: &[u8] = b"bl30:thermal init err"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_BL30_THERMAL_INIT_ERR_OFF: usize = 44_784" in dtb_rs
    assert "admit_s19k_usb_uboot_scpi_ddr_gcm" in dtb_rs
    assert "refuse_s19k_usb_gcm_tag_as_android_decrypt" in dtb_rs
    assert "refuse_s19k_usb_scpi_as_hash_uart" in dtb_rs
    assert "refuse_s19k_usb_ddr_suspend_as_hashboard_rail" in dtb_rs
    assert "refuse_s19k_usb_otp_block_as_gpio437" in dtb_rs
    assert "admit_s19k_usb_uboot_bl30_axg_stamp" in dtb_rs
    assert 'S19K_USB_UBOOT_GCM_TAG: &[u8] = b"GCM: Tag mismatch"' in dtb_rs
    assert "S19K_USB_UBOOT_GCM_TAG_OFF: usize = 45_797" in dtb_rs
    assert 'S19K_USB_UBOOT_SCPI_CSS: &[u8] = b"scpi_set_css_power_state"' in dtb_rs
    assert "S19K_USB_UBOOT_SCPI_CSS_OFF: usize = 45_328" in dtb_rs
    assert 'S19K_USB_UBOOT_DDR_SUSPEND: &[u8] = b"Enter ddr suspend"' in dtb_rs
    assert "S19K_USB_UBOOT_DDR_SUSPEND_OFF: usize = 45_483" in dtb_rs
    assert (
        'S19K_USB_UBOOT_OTP_BLOCK11: &[u8] = b"--> UPDATE MVN in OTP BLOCK_11"'
        in dtb_rs
    )
    assert "S19K_USB_UBOOT_OTP_BLOCK11_OFF: usize = 45_261" in dtb_rs
    assert 'S19K_USB_UBOOT_BL30_AXG_STAMP: &[u8] = b"axg_v1.1.3494-9ec8345"' in dtb_rs
    assert "S19K_USB_UBOOT_BL30_AXG_STAMP_OFF: usize = 46_256" in dtb_rs
    assert "refuse_s19k_usb_saradc_ch2_as_bl2_error" in dtb_rs
    assert "refuse_s19k_usb_saradc_ch2_as_miner_adc" in dtb_rs
    assert "admit_s19k_usb_uboot_packed_acmdlin" in dtb_rs
    assert "refuse_s19k_usb_uild_expect_as_build_prop" in dtb_rs
    assert "refuse_s19k_usb_acmdlin_as_nand_bootargs" in dtb_rs
    vnish_tar = (
        ROOT.parents[1]
        / ""
        / "awesome-s19kpro-aml-nand-v1.2.6-install.tar.gz"
    )
    if vnish_tar.is_file():
        import tarfile

        with tarfile.open(vnish_tar, "r:gz") as tf:
            names = tf.getnames()
            assert "devicetree.dtb" in names
            assert "uramdisk.image.gz" in names
            assert "vmlinux.bin" in names
            dtb_m = tf.extractfile("devicetree.dtb")
            assert dtb_m is not None
            vdb = dtb_m.read()
            uram = tf.extractfile("uramdisk.image.gz")
            assert uram is not None
            uimg = uram.read(64)
        assert len(vdb) == 20_945
        assert vdb[:4] == bytes.fromhex("d00dfeed")
        assert b"PWR_CONTROL" not in vdb
        assert b"gpio437" not in vdb
        assert b"serial0" in vdb
        assert b"serial3" in vdb
        assert b"serial@3000" in vdb
        assert b"serial@4000" in vdb
        assert b"serial@ffd24000" in vdb
        assert b"serial@ffd23000" in vdb
        assert uimg[:4] == bytes.fromhex("27051956")
        assert uimg[29] == 2
        assert "admit_s19k_stock_revert_uimage" in install_rs
    dtb = (
        ROOT.parents[1]
        / ""
        / "08-luxos-capture/axg_s400_antminer.dtb"
    )
    if dtb.is_file():
        db = dtb.read_bytes()
        assert len(db) == 45_596
        assert db[:4] == bytes.fromhex("d00dfeed")
        assert b"bootloader\x00nandnormal\x00" in db
        assert b"nvdata" in db
        assert b"plat-names" in db
        off_struct = int.from_bytes(db[8:12], "big")
        off_strings = int.from_bytes(db[12:16], "big")
        size_strings = int.from_bytes(db[32:36], "big")
        size_struct = int.from_bytes(db[36:40], "big")
        strings = db[off_strings : off_strings + size_strings]

        def fdt_str(o: int) -> str:
            end = strings.find(b"\x00", o)
            return strings[o:end].decode("ascii")

        off = off_struct
        end = off_struct + size_struct
        path: list[str] = []
        nv_off = None
        nv_sz = None
        plats = None
        chips: dict[str, int] = {}
        while off + 4 <= end:
            tag = int.from_bytes(db[off : off + 4], "big")
            off += 4
            if tag == 1:
                start = off
                while db[off] != 0:
                    off += 1
                path.append(db[start:off].decode("ascii"))
                off = (off + 4) & ~3
            elif tag == 2:
                path.pop()
            elif tag == 3:
                plen = int.from_bytes(db[off : off + 4], "big")
                nameoff = int.from_bytes(db[off + 4 : off + 8], "big")
                off += 8
                val = db[off : off + plen]
                off = (off + plen + 3) & ~3
                pname = fdt_str(nameoff)
                pth = "/".join(x for x in path if x)
                if pth == "mtd_nand" and pname == "plat-names":
                    plats = [x.decode("ascii") for x in val.split(b"\x00") if x]
                elif (
                    pth in ("mtd_nand/bootloader", "mtd_nand/nandnormal")
                    and pname == "chip_num"
                ):
                    chips[pth.rsplit("/", 1)[-1]] = int.from_bytes(val[:4], "big")
                elif pth == "mtd_nand/nand_partition/nvdata" and pname == "offset":
                    nv_off = int.from_bytes(val[:8], "big")
                elif pth == "mtd_nand/nand_partition/nvdata" and pname == "size":
                    nv_sz = int.from_bytes(val[:8], "big")
            elif tag == 9:
                break
        assert plats == ["bootloader", "nandnormal"], plats
        assert chips.get("bootloader") == 1, chips
        assert chips.get("nandnormal") == 2, chips
        assert nv_off == 0xFFFFFFFFFFFFFFFF, nv_off
        assert nv_sz == 0, nv_sz
        assert b"twoplane" in db
        xml_emmc = (
            ROOT.parents[1]
            / ""
            / "partition_emmc_miner.xml"
        )
        if xml_emmc.is_file():
            xt = xml_emmc.read_text(encoding="utf-8", errors="replace")
            assert 'type="emmc"' in xt
            assert 'label="nvdata"' in xt
    uart_doc = (ROOT / "docs/UART_CONSOLE_RECOVERY.md").read_text(encoding="utf-8")
    assert "AnyKeyDuringBootdelay" in uart_doc
    assert "recover_to_stock" in uart_doc
    assert "U-Boot interrupt **not held**" not in uart_doc
    nand_env_bin = (
        ROOT.parents[1]
        / ""
        / "00-system/nand_env.bin"
    )
    if nand_env_bin.is_file():
        neb = nand_env_bin.read_bytes()
        assert len(neb) == 65536
        crc = int.from_bytes(neb[:4], "little")
        assert crc == 0x471D6B1A
        assert (zlib.crc32(neb[4:]) & 0xFFFFFFFF) == crc
        env_txt = (
            neb[4:].split(b"\x00\x00", 1)[0].replace(b"\x00", b"\n").decode("ascii")
        )
        assert "bootdelay=1" in env_txt
        assert (
            "bootcmd=run try_to_boot_bos_normally; run try_to_boot_bos_after_install; run recover_to_stock"
            in env_txt
        )
        assert "nand erase.part nvdata" in env_txt
        assert "nand device 1" in env_txt
        assert "nandrecovery_env_offset=0x00000B000000" in env_txt
        assert "nandrecovery_flag_offset=0x00000B400000" in env_txt
        assert "nandrootfs=0x00000B800000" in env_txt
        assert "recovery_flag_first_boot=0x2" in env_txt
        assert "recovery_flag_successful=0x3" in env_txt
        assert "bootstopkey=" not in env_txt
        assert "Hit any key to stop autoboot" not in env_txt
        assert "console=ttyS0,115200" in env_txt
        assert "earlycon=aml_uart,0xff803000" in env_txt
    recon_78 = (
        ROOT.parents[1]
        / ""
        / "00-system/recon.txt"
    )
    if recon_78.is_file():
        recon_text = recon_78.read_bytes().decode("utf-8", errors="replace")
        assert 'mtd3: 00500000 00020000 "stock_config"' in recon_text
        assert 'mtd5: 09900000 00020000 "system"' in recon_text
        assert '"reserved"' not in recon_text
    s19k_readme = (
        ROOT / "br2_external_dcentos/board/amlogic/am3-s19kpro/README.md"
    ).read_text(encoding="utf-8")
    assert "stock_config" in s19k_readme
    assert "not** a direct `bootm` of mtd2" in s19k_readme
    assert "0x00200000" in s19k_readme
    assert "0x00800000" in s19k_readme
    assert "2 MiB" in s19k_readme
    assert "8 MiB" in s19k_readme
    assert "S19K_78_PROC_MTD_SIZES" in s19k_readme
    assert "admit_s19k_board_readme_mtd_sizes" in nand_env_rs
    wire_try = (ROOT / "scripts/s19k_braiins_wire_try.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "legacy S19k wire-try is retired" in wire_try
    assert "dcentrald_s19k_tmp_deploy.sh" in wire_try
    assert "exit 64" in wire_try
    for forbidden in (
        "ssh",
        "scp",
        "stty",
        "/dev/tty",
        "/sys/class/gpio",
        "\\x55\\xAA",
    ):
        assert forbidden not in wire_try
    deploy = (ROOT / "scripts/dcentrald_s19k_tmp_deploy.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert (
        "Refuse mining-on; exact handoff requires stock-held engaged rails." in deploy
    )
    assert "--dry-run" in deploy
    assert "TMP_DEPLOY_PLAN" in deploy
    assert "hard_float=true" in deploy
    assert "pt_interp=none" in deploy
    assert "musl_static=true" in deploy
    assert "ld-linux" in deploy
    assert deploy.find("[DRY RUN]") < deploy.find("ssh_trial()")
    assert "StrictHostKeyChecking=yes" in deploy
    assert "UserKnownHostsFile=$KNOWN_HOSTS" in deploy
    assert "StrictHostKeyChecking=no" not in deploy
    assert "GPIO437=1 means PSU OFF" in deploy
    assert "DCENT_S19K_LIVE_IDENTITY" in deploy
    assert "content-bound helper returned no exact live S19k identity receipt" in deploy
    assert "refuse single-port /tmp deploy" in deploy
    assert "exact daemon-owned handoff requires one live bosminer" in deploy
    assert (
        "handoff_identity=supervisor+child-pid+start+ppid+pgrp+session+comm+exe+argv-sha256"
        in deploy
    )
    held_s37_cap = (
        ROOT.parents[1]
        / ""
        / "03-bosminer/init_capture.txt"
    )
    if held_s37_cap.is_file():
        cap = held_s37_cap.read_text(encoding="utf-8", errors="replace")
        start = cap.find("=== /etc/init.d/S37board_setup ===")
        end = cap.find("=== /etc/init.d/S99bosminer ===")
        assert start >= 0 and end > start
        held_s37 = cap[start:end]
        assert "echo 446" in held_s37
        assert "CH0_PLUG" in held_s37
        assert "echo 437" not in held_s37
        assert "echo 439" in held_s37
        assert "echo 454" in held_s37
    dmesg_78 = (
        ROOT.parents[1]
        / ""
        / "00-system/cap_init/dmesg.before"
    )
    if dmesg_78.is_file():
        dmesg_text = dmesg_78.read_text(encoding="utf-8", errors="replace")
        assert "ttyS1 use xtal" in dmesg_text
        assert "ttyS2 use xtal" in dmesg_text
        assert "ttyS3 use xtal" in dmesg_text
        assert "change 0 to 9600" in dmesg_text
        assert "change 9600 to 115200" in dmesg_text
        assert "ff804000.serial: ttyS3 at MMIO 0xff804000 (irq = 14" in dmesg_text
        assert "ffd24000.serial: ttyS1 at MMIO 0xffd24000 (irq = 25" in dmesg_text
        assert "ffd23000.serial: ttyS2 at MMIO 0xffd23000 (irq = 26" in dmesg_text
        assert "console=ttyS0,115200" in dmesg_text
        assert "earlycon=aml_uart,0xff803000" in dmesg_text
        assert "console [ttyS0] enabled" in dmesg_text
    nopic_beta = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_nopic_beta.rs"
    ).read_text(encoding="utf-8")
    assert "S19K_AM3_GPIO437_VALUE_OFF" in nopic_beta
    assert "refuse_re4c_safe_off_as_am3_s19k_cut(gpio_safe_off_value)" in nopic_beta
    assert (
        "S19K_BM1366_BAUD_HZ: u32 = BOSMINER_BM1366_REQUESTED_FAST_BAUD"
        in nopic_beta
    )
    assert (
        "S19K_BM1366_HOST_BAUD_HZ: u32 = BOSMINER_BM1366_AML_HOST_BAUD"
        in nopic_beta
    )
    assert (
        "S19K_BM1366_FASTUART_VALUE: u32 = BOSMINER_BM1366_FASTUART_3M125"
        in nopic_beta
    )
    assert "S19K_BM1366_JIG_BAUD_HZ: u32 = 12_000_000" in nopic_beta
    assert "admit_s19k_bm1366_stock_baud_pair" in nopic_beta
    daemon_rs = (ROOT / "dcentrald/dcentrald/src/daemon.rs").read_text(
        encoding="utf-8"
    )
    assert "admit_s19k_bm1366_stock_baud_pair(" in daemon_rs
    assert "S19K_BM1366_HOST_BAUD_HZ" in daemon_rs
    assert "S19K_BM1366_FASTUART_VALUE" in daemon_rs
    gpio = (ROOT / "dcentrald/dcentrald-common/src/s19k_am3_gpio437.rs").read_text(
        encoding="utf-8"
    )
    assert "parse_s19k_gpio_timeline_line" in gpio
    assert "passthrough_must_not_pulse_hb_reset" in gpio
    assert "admit_s19k_78_gpio_timeline_hb_reset_ganged_after_psu" in gpio
    assert "refuse_s19k_78_first_psu_engage_as_hb_reset_released" in gpio
    assert "refuse_s19k_78_per_chain_reset_as_bosminer_observed" in gpio
    assert "refuse_s19k_78_gpio_timeline_as_dmm_rail" in gpio
    assert "refuse_s21_s37_437_high_export_as_78_s37" in gpio
    assert "admit_bosminer_psu_gpio_is_gpiod_label" in gpio
    assert "refuse_held_braiins_s37_as_gpio437_exporter" in gpio
    assert "refuse_sysfs_export_437_as_bosminer_open" in gpio
    assert 'BOSMINER_PWR_CONTROL_LABEL: &[u8] = b"PWR_CONTROL"' in gpio
    assert 'BOSMINER_GPIOD_RS: &str = "gpiod-0.2.3/src/lib.rs"' in gpio
    bos = (
        ROOT.parents[1]
        / ""
    )
    if bos.is_file():
        bb = bos.read_bytes()
        assert hashlib.sha256(bb).hexdigest() == (
            "5a49dcbe2e2d9f4fb047eca856e71440bd73fc020a817e808b5af3b45a7c8707"
        )
        # Exact S19k/BM1366 stock baud identity chain. Chip-id 0x1366 selects
        # the factory/vtable whose +0x50 method builds FastUartReg. The common
        # selector admits 1M and 3.125M; BM1366 mode=2 packs 3.125M as 0x3011.
        assert struct.unpack_from("<Q", bb, 0x016BDAE8)[0] == 0x8DBDF4
        assert struct.unpack_from("<Q", bb, 0x015B7B00 + 0x50)[0] == 0x8DD3B8
        assert struct.unpack_from("<QQ", bb, 0x00EE8010) == (4, 0x28)
        assert struct.unpack_from("<I", bb, 0x004DD3D8)[0] == 0x9400F713
        assert struct.unpack_from("<I", bb, 0x004DD414)[0] == 0x5280004A
        assert struct.unpack_from("<I", bb, 0x004DD418)[0] == 0x390053EA
        assert struct.unpack_from("<I", bb, 0x004DD468)[0] == 0x97FDC649
        assert struct.unpack_from("<I", bb, 0x0051B034)[0] == 0xF109013F
        assert struct.unpack_from("<I", bb, 0x0051B03C)[0] == 0x5295E109
        assert struct.unpack_from("<I", bb, 0x0051B040)[0] == 0x72A005E9
        assert struct.unpack_from("<I", bb, 0x004376FC)[0] == 0xF9402929
        assert struct.unpack_from("<I", bb, 0x00437704)[0] == 0xD63F0120
        assert struct.unpack_from("<I", bb, 0x00437BC8)[0] == 0xF9401928
        assert struct.unpack_from("<QQQQQQ", bb, 0x015AB508) == (
            0x0131B8D5,
            6,
            0x0131B8DB,
            29,
            0x0131B8F8,
            10,
        )
        assert (
            bb[0x00F1B8D5 : 0x00F1B8D5 + 45]
            == b"CHAIN/: Set baud rate @ requested: , actual: "
        )
        # FUN_00836934 was previously mislabeled as set-baud. Its descriptor
        # is len=4/reg=0x14 and its log text is the ticket-mask message.
        assert struct.unpack_from("<QQ", bb, 0x00EE7E20) == (4, 0x14)
        assert b"Setting ticket mask register for difficulty " in bb
        off = 0x015920A6
        assert bb[off : off + 4] == bytes.fromhex("0000115A")
        assert bb[0x013B0A28 : 0x013B0A28 + 6] == bytes.fromhex("280000003011")
        assert bb[0x0141FA28 : 0x0141FA28 + 6] == bytes.fromhex("280000003001")
        assert bb.find(bytes.fromhex("51090028")) < 0
        assert struct.unpack_from("<Q", bb, 0x015B4590)[0] == 0x8B1B98
        assert struct.unpack_from("<Q", bb, 0x015B4598)[0] == 0x01321135
        assert struct.unpack_from("<Q", bb, 0x015B45A0)[0] == 0x36
        assert (
            bb[0x00F21135 : 0x00F21135 + 54]
            == b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1398.rs"
        )
        assert struct.unpack_from("<Q", bb, 0x015B46A8)[0] == 0x8B2B34
        assert struct.unpack_from("<Q", bb, 0x015B46B0)[0] == 0x01321135
        assert (
            bb[0x00F232F5 : 0x00F232F5 + 54]
            == b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1366.rs"
        )
        assert struct.unpack_from("<Q", bb, 0x015B7EA8)[0] == 0x8DC828
        assert struct.unpack_from("<Q", bb, 0x015B7EB0)[0] == 0x013232F5
        assert struct.unpack_from("<Q", bb, 0x015B7EB8)[0] == 54
        assert struct.unpack_from("<Q", bb, 0x015B7EC0)[0] == 0x000000400000005D
        assert struct.unpack_from("<QQQQ", bb, 0x015B7EC8) == (
            0x8D87F8,
            0x128,
            8,
            0x8DCFBC,
        )
        bm1366_poll_ranges = (
            (0x8DCFBC, 0x8DD3B8),
            (0x8DD4C8, 0x8DD5B8),
            (0x8DD63C, 0x8DE218),
            (0x8DE274, 0x8DE3E8),
            (0x8DE430, 0x8DE93C),
            (0x8DE984, 0x8DED90),
        )
        dispatch_target = 0x8D823C
        dispatch_bl_count = 0
        for start, end in bm1366_poll_ranges:
            for pc in range(start, end, 4):
                insn = struct.unpack_from("<I", bb, pc - 0x400000)[0]
                if insn & 0xFC000000 != 0x94000000:
                    continue
                imm26 = insn & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                if pc + (imm26 << 2) == dispatch_target:
                    dispatch_bl_count += 1
        assert dispatch_bl_count == 31
        assert struct.unpack_from("<QQQQ", bb, 0x015B80A8) == (
            0x013234D2,
            54,
            0x0000004000000067,
            0x8D85A0,
        )
        assert struct.unpack_from("<QQQQ", bb, 0x015B80C0) == (
            0x8D85A0,
            0x148,
            8,
            0x8DF138,
        )
        assert struct.unpack_from("<I", bb, 0x004DF2A8)[0] == 0x528001E1
        assert struct.unpack_from("<I", bb, 0x004DF2B0)[0] == 0x52800500
        assert struct.unpack_from("<I", bb, 0x004DF2B4)[0] == 0x72A0C001
        assert struct.unpack_from("<I", bb, 0x004DF2B8)[0] == 0x940C4FF5
        assert struct.unpack_from("<QQQQ", bb, 0x015AC768) == (
            0x0131C3B8,
            54,
            0x0000004000000065,
            0x83EAF0,
        )
        assert struct.unpack_from("<QQQQ", bb, 0x015AC780) == (
            0x83EAF0,
            0x148,
            8,
            0x846384,
        )
        assert struct.unpack_from("<I", bb, 0x004464F4)[0] == 0x528001E1
        assert struct.unpack_from("<I", bb, 0x004464FC)[0] == 0x52800500
        assert struct.unpack_from("<I", bb, 0x00446500)[0] == 0x72A0C001
        assert struct.unpack_from("<I", bb, 0x00446504)[0] == 0x940EB362
        assert 0x0F | (0x600 << 16) == 0x0600000F
        assert bb[0x011FD4AE:0x011FD4B4] == bytes.fromhex("80009000ffff")
        assert struct.unpack_from("<I", bb, 0x00A7A568)[0] == 0x52801488
        assert struct.unpack_from("<I", bb, 0x00A7A56C)[0] == 0xB8686808
        assert struct.unpack_from("<I", bb, 0x0051BEB4)[0] == 0xD10103FF
        assert struct.unpack_from("<I", bb, 0x0051BEC8)[0] == 0x52800AC0
        assert struct.unpack_from("<I", bb, 0x0051BEE4)[0] == 0x910152A8
        assert struct.unpack_from("<I", bb, 0x0051BF00)[0] == 0x910142A8
        assert struct.unpack_from("<I", bb, 0x0051BF14)[0] == 0x3D800000
        assert struct.unpack_from("<I", bb, 0x0051BF50)[0] == 0xB8052009
        assert struct.unpack_from("<I", bb, 0x0051BF54)[0] == 0x940073FF
        assert struct.unpack_from("<I", bb, 0x0051BF58)[0] == 0x91000A81
        assert struct.unpack_from("<I", bb, 0x0051BF5C)[0] == 0x52800A82
        assert struct.unpack_from("<I", bb, 0x0051BF60)[0] == 0x940073FE
        assert struct.unpack_from("<I", bb, 0x0051BF64)[0] == 0x94007408
        assert struct.unpack_from("<I", bb, 0x0051BFB0)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x0051BEDC)[0] == 0x97F362EA
        assert b"bosminer_hal::workpair" in bb
        assert b"bosminer_hal::command" in bb
        assert b"ChipParams" in bb
        assert b"nonceversion_idxsolution_idxtarget" in bb
        ti56 = 0
        e_phoff = struct.unpack_from("<Q", bb, 32)[0]
        e_phentsize = struct.unpack_from("<H", bb, 54)[0]
        e_phnum = struct.unpack_from("<H", bb, 56)[0]
        for phi in range(e_phnum):
            poff = e_phoff + phi * e_phentsize
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                "<IIQQQQQQ", bb, poff
            )
            if p_type != 1 or p_vaddr < 0x17800000 or p_filesz < 24:
                continue
            for qi in range(0, p_filesz - 24, 8):
                drop, sz, align = struct.unpack_from("<QQQ", bb, p_offset + qi)
                if (
                    sz == 0x56
                    and align in (1, 2, 4, 8, 16)
                    and 0x400000 <= drop < 0x1775388
                ):
                    ti56 += 1
        assert ti56 == 0
        # : HashMap V constructor paints 7 chip-id keys; type unnamed.
        assert struct.unpack_from("<I", bb, 0x00462458)[0] == 0xD104C3FF
        assert struct.unpack_from("<I", bb, 0x00462498)[0] == 0x52826CCA
        assert struct.unpack_from("<I", bb, 0x004624B4)[0] == 0x7900A3EA
        assert struct.unpack_from("<I", bb, 0x0046248C)[0] == 0x790063E9
        assert struct.unpack_from("<I", bb, 0x00462570)[0] == 0x9401C928
        assert struct.unpack_from("<I", bb, 0x004D4A5C)[0] == 0x940016AD
        assert struct.unpack_from("<I", bb, 0x004D4B04)[0] == 0x94001683
        assert bb.find(b"OccupiedEntry") < 0
        assert bb.find(b"VacantEntry") < 0
        assert bb.find(b"HashMap<") < 0
        assert struct.unpack_from("<I", bb, 0x004D823C)[0] == 0xA9BE57FE
        assert struct.unpack_from("<I", bb, 0x004D8244)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x004D826C)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x004A8D34)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x004D824C)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x004D8250)[0] == 0x54000220
        assert struct.unpack_from("<I", bb, 0x004D8254)[0] == 0x7100111F
        assert struct.unpack_from("<I", bb, 0x004D825C)[0] == 0xA947D275
        assert struct.unpack_from("<I", bb, 0x004D8260)[0] == 0xF9400288
        assert struct.unpack_from("<I", bb, 0x004D82CC)[0] == 0xF9400D08
        assert struct.unpack_from("<I", bb, 0x004D82D0)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00DF2764)[0] == 0xB4000241
        assert struct.unpack_from("<Q", bb, 0x015B7900)[0] == 0
        assert struct.unpack_from("<Q", bb, 0x015B7908)[0] == 0x30
        assert struct.unpack_from("<Q", bb, 0x015B7910)[0] == 8
        assert struct.unpack_from("<Q", bb, 0x015B7918)[0] == 0x11DE81C
        assert bb[0x00F231EE : 0x00F231EE + 68].startswith(
            b"open/bosminer/bosminer-am2-s17/src/hardware/antminer/psu_protocol.rs"
        )
        assert struct.unpack_from("<I", bb, 0x004DDB10)[0] == 0x91240129
        assert struct.unpack_from("<I", bb, 0x004DDB58)[0] == 0xA907A67F
        assert struct.unpack_from("<I", bb, 0x00DDE81C)[0] == 0xAA0003E8
        assert struct.unpack_from("<I", bb, 0x00DDE834)[0] == 0xD61F0080
        assert (
            bb[0x00F23527 : 0x00F23527 + 47]
            == b"open/bosminer/bosminer-am2-s17/src/hashchain.rs"
        )
        assert struct.unpack_from("<Q", bb, 0x015B83C8)[0] == 0x8DFE6C
        assert struct.unpack_from("<Q", bb, 0x015B83D0)[0] == 0x01323527
        assert struct.unpack_from("<Q", bb, 0x015B83D8)[0] == 0x2F
        assert struct.unpack_from("<Q", bb, 0x015B83E0)[0] == 0x0000002000000070
        assert struct.unpack_from("<I", bb, 0x004DFF24)[0] == 0xF940126C
        assert struct.unpack_from("<I", bb, 0x004DFF34)[0] == 0xF940018A
        assert struct.unpack_from("<I", bb, 0x004DFF3C)[0] == 0x91056269
        assert struct.unpack_from("<I", bb, 0x004DFF44)[0] == 0x91004148
        assert struct.unpack_from("<I", bb, 0x004DFF48)[0] == 0xA907A668
        assert struct.unpack_from("<I", bb, 0x004DFF4C)[0] == 0x9101A260
        assert struct.unpack_from("<I", bb, 0x004DFF54)[0] == 0x97FFD812
        assert struct.unpack_from("<I", bb, 0x004DFF64)[0] == 0x97FFE0B6
        assert struct.unpack_from("<I", bb, 0x004D5FAC)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x004D5FA8)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x004D5FB4)[0] == 0x7100091F
        assert struct.unpack_from("<I", bb, 0x004D5FBC)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x004D5FD0)[0] == 0xA9415A68
        assert struct.unpack_from("<I", bb, 0x004DF004)[0] == 0xA9042668
        assert (
            bb[0x00F251D0 : 0x00F251D0 + 39]
            == b"BUG: Failed to build legacy FastUartReg"
        )
        assert (
            bb[0x00F251A3 : 0x00F251A3 + 45]
            == b"open/bosminer/bosminer-antminer/src/bm139x.rs"
        )
        assert struct.unpack_from("<Q", bb, 0x015BA080)[0] == 0x013251A3
        assert struct.unpack_from("<Q", bb, 0x015BA088)[0] == 0x2D
        assert struct.unpack_from("<Q", bb, 0x015BA090)[0] == 0x0000001A00000293
        assert struct.unpack_from("<I", bb, 0x0051AFF8)[0] == 0x91074000
        assert struct.unpack_from("<I", bb, 0x0051AF74)[0] == 0x540003A0
        assert struct.unpack_from("<I", bb, 0x0051AFE4)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x0051AF18)[0] == 0x39401C08
        assert struct.unpack_from("<I", bb, 0x0051AF30)[0] == 0x53187C2B
        assert struct.unpack_from("<I", bb, 0x0051AF34)[0] == 0x7103FD7F
        assert struct.unpack_from("<I", bb, 0x0051AF54)[0] == 0x9AC90900
        assert struct.unpack_from("<I", bb, 0x0051AF6C)[0] == 0x53031009
        assert struct.unpack_from("<I", bb, 0x0051AF70)[0] == 0x7100053F
        assert struct.unpack_from("<I", bb, 0x0051AF8C)[0] == 0x39003109
        assert struct.unpack_from("<I", bb, 0x0051AFD0)[0] == 0x7900010E
        assert struct.unpack_from("<I", bb, 0x0051AFE0)[0] == 0x3900350B
        assert struct.unpack_from("<I", bb, 0x004B20F0)[0] == 0x528000C0
        assert struct.unpack_from("<I", bb, 0x004B20FC)[0] == 0x9401A39C
        assert struct.unpack_from("<Q", bb, 0x016BE820)[0] == 0x91AF14
        assert struct.unpack_from("<Q", bb, 0x016BE818)[0] == 0x1AE5350
        assert struct.unpack_from("<Q", bb, 0x016BE828)[0] == 0x1AE4948
        assert struct.unpack_from("<I", bb, 0x004D3A78)[0] == 0xA9402100
        assert struct.unpack_from("<I", bb, 0x004D3A7C)[0] == 0xA907A260
        assert struct.unpack_from("<I", bb, 0x004D3A80)[0] == 0xA908A260
        assert struct.unpack_from("<I", bb, 0x004D54F4)[0] == 0xA9078660
        for va in (
            0x008D54F4,
            0x008D57D8,
            0x008D5AD8,
            0x008D5DEC,
            0x008D60E8,
            0x008D641C,
            0x008D66B4,
        ):
            off = va - 0x400000
            assert struct.unpack_from("<I", bb, off - 8)[0] == 0xAA1503E0, hex(va)
            assert struct.unpack_from("<I", bb, off - 4)[0] == 0xD63F0100, hex(va)
            assert struct.unpack_from("<I", bb, off)[0] == 0xA9078660, hex(va)
        assert struct.unpack_from("<I", bb, 0x0051AF84)[0] == 0x531C040D
        assert struct.unpack_from("<I", bb, 0x0051AFA4)[0] == 0x33041C2D
        assert struct.unpack_from("<I", bb, 0x0051AFD4)[0] == 0x3900150D
        assert struct.unpack_from("<I", bb, 0x004B20F4)[0] == 0x52801002
        assert struct.unpack_from("<I", bb, 0x004B20F8)[0] == 0x528001E3
        assert struct.unpack_from("<I", bb, 0x004B20E0)[0] == 0xF9400668
        assert struct.unpack_from("<I", bb, 0x004B20E4)[0] == 0x3948B108
        assert struct.unpack_from("<I", bb, 0x004B20E8)[0] == 0x51000501
        assert struct.unpack_from("<I", bb, 0x004B27D0)[0] == 0xF9401A6A
        assert struct.unpack_from("<I", bb, 0x004B27E0)[0] == 0x9100614A
        assert struct.unpack_from("<I", bb, 0x004B27EC)[0] == 0xF900466A
        assert struct.unpack_from("<I", bb, 0x004DEA3C)[0] == 0xF9401A6A
        assert struct.unpack_from("<I", bb, 0x004DEA54)[0] == 0x91006148
        assert struct.unpack_from("<I", bb, 0x004DEA60)[0] == 0xF9004668
        assert bb[0x00F20C4B : 0x00F20C4B + 18] == b"unknown_bits_31_28"
        assert b"ext_baud_enable" in bb[0x00F20C4B : 0x00F20C4B + 0x80]
        assert bb[0x00F20C4B : 0x00F20C4B + 148].startswith(
            b"unknown_bits_31_28unknown_bits_27_23unknown_bit_22unknown_bits_21_17"
            b"ext_baud_enableunknown_bit_15rfsunknown_bit_13unknown_bit_7_reserved_bit_6tfs"
        )
        assert struct.unpack_from("<I", bb, 0x004B24DC)[0] == 0x3948B009
        assert struct.unpack_from("<I", bb, 0x004B24F0)[0] == 0x528F0801
        assert struct.unpack_from("<I", bb, 0x004B24F4)[0] == 0x72A02FA1
        assert struct.unpack_from("<I", bb, 0x007BE5BC)[0] == 0x5298D808
        assert struct.unpack_from("<I", bb, 0x007BE5C0)[0] == 0x72A005A8
        assert struct.unpack_from("<I", bb, 0x007BE5CC)[0] == 0x528201A1
        assert struct.unpack_from("<I", bb, 0x007C1F94)[0] == 0x5298D802
        assert struct.unpack_from("<I", bb, 0x007C1FB4)[0] == 0x72A005A2
        assert struct.unpack_from("<I", bb, 0x007C00EC)[0] == 0x5298D802
        assert struct.unpack_from("<I", bb, 0x007C7020)[0] == 0x5298D808
        assert struct.unpack_from("<I", bb, 0x007C2918)[0] == 0x528201A2
        assert struct.unpack_from("<I", bb, 0x007C7130)[0] == 0x528201A1
        assert bb[0x00F92558:].startswith(
            b"open/utils-rs/serial-driver/src/antminer_aml.rs"
        )
        assert bb[0x00F9B584:].startswith(b"nix-0.26.4/src/sys/termios.rs")
        assert struct.unpack_from("<I", bb, 0x004DF2B0)[0] == 0x52800500
        assert struct.unpack_from("<I", bb, 0x004DF2A8)[0] == 0x528001E1
        assert struct.unpack_from("<I", bb, 0x004DF2B4)[0] == 0x72A0C001
        assert struct.unpack_from("<I", bb, 0x004DF2B8)[0] == 0x940C4FF5
        assert struct.unpack_from("<I", bb, 0x007F32C0)[0] == 0x5AC00AA8
        assert struct.unpack_from("<I", bb, 0x004464FC)[0] == 0x52800500
        assert struct.unpack_from("<I", bb, 0x00446500)[0] == 0x72A0C001
        assert struct.unpack_from("<I", bb, 0x00446504)[0] == 0x940EB362
        assert struct.unpack_from("<Q", bb, 0x015B7FF8)[0] == 0x8DE984
        assert (struct.unpack_from("<Q", bb, 0x015B7FF8 + 24)[0] & 0xFFFFFFFF) == 241
        assert bb[0x0141FA28 : 0x0141FA28 + 6] == bytes.fromhex("280000003001")
        assert bb[0x013B0A28 : 0x013B0A28 + 6] == bytes.fromhex("280000003011")
        # MOVZ X1,#0x3001 (LE 0xd2860021); later MOVK completes a pointer.
        assert struct.unpack_from("<I", bb, 0x00CBA39C)[0] == 0xD2860021
        assert struct.unpack_from("<I", bb, 0x00CC49D8)[0] == 0xD2860021
        assert b"Hashchip: no response for read_register" in bb
        assert b"Modifying MiscCtrl for chip" in bb
        assert b"open/utils-rs/serial-driver/src/antminer_aml.rs" in bb
        assert (
            bb[0x00F20197 : 0x00F20197 + 45]
            == b"values were not written correctly to register"
        )
        assert bb[0x00EEC448 : 0x00EEC448 + 4] == bytes.fromhex("55AA2136")
        assert b"BUG: asking for non-existing version index" in bb
        assert b"packed_struct-0.10.1/src/packing.rs" in bb
        assert b"set_config" not in bb
        # : nbits getter is ldr w0,[x0,#0x78]; ret on both stratum_v2 vtables.
        assert bb[0x0087B380 : 0x0087B380 + 8] == bytes.fromhex("007840b9c0035fd6")
        assert bb[0x009139DC : 0x009139DC + 8] == bytes.fromhex("007840b9c0035fd6")
        assert bb[0x0087B368 : 0x0087B368 + 8] == bytes.fromhex("00200091c0035fd6")
        assert struct.unpack_from("<Q", bb, 0x016021D8 + 8)[0] == 0x80
        assert struct.unpack_from("<Q", bb, 0x016021D8 + 0x10)[0] == 8
        assert struct.unpack_from("<Q", bb, 0x016021D8 + 0x90)[0] == 0x00C7B380
        assert struct.unpack_from("<Q", bb, 0x0160DC10 + 0x90)[0] == 0x00D139DC
        assert b"open/bosminer/bosminer/src/client/stratum_v2.rs" in bb
        assert b"BUG: Stratum: incorrect size of prev hash" in bb
        assert b"BUG: job has incorrect nbits" in bb
        assert b"open/bosminer/bosminer/src/work.rs" in bb
        assert b"/build/source/open/bosminer/bosminer-backend/src/worker.rs" in bb
        assert b"open/bosminer/bosminer-antminer/src/io/ext_work_id.rs" in bb
        assert b"PWR_CONTROL" in bb
        assert b"/dev/gpiochip" in bb
        assert b"gpiod-0.2.3/src/lib.rs" in bb
        assert b"open/utils-rs/gpio/src/lib.rs" in bb
        assert b"open pin out" in bb
        assert b"BUG: pin name  not found!" in bb
        assert b"HB0_RESET" in bb
        assert b"HB1_RESET" in bb
        assert b"HB2_RESET" in bb
        assert b"HB3_RESET" in bb
        assert b"invalid midstate count logarithm" in bb
        assert (
            b"assertion failed: self.work_id < Self::get_work_id_count(midstate_count)"
            in bb
        )
        assert b"assertion failed: work_id < self.registry_size" in bb
        assert b"open/bosminer/bosminer-hal/src/registry.rs" in bb
        # FUN_0092f200 VA 0x0092f200 is first-LOAD file 0x52f200.
        assert bb[0x0052F200 : 0x0052F200 + 8] != b"\x00" * 8
        # : FUN_00bf5414 stp x8,x22,[x27,#0x38] at VA 0x00bf6454.
        assert struct.unpack_from("<I", bb, 0x007F6454)[0] == 0xA903DB68
        assert bb[0x007E7084 : 0x007E7084 + 4] != b"\x00" * 4
        # : Worker memcpy size 0x1c8; AND#0xFF;RET exists; ctor mask 0xE0000020.
        assert (
            struct.unpack_from("<I", bb, 0x004F2550)[0] == 0x52803902
        )  # MOVZ W2,#0x1C8
        assert bb[0x00CAF790 : 0x00CAF790 + 8] == bytes.fromhex("001c0012c0035fd6")
        assert (
            struct.unpack_from("<I", bb, 0x00503810)[0] == 0x72BC0009
        )  # MOVK W9,#0xE000,LSL#16
        # : five AM3 factories MOVZ W10,#0x100; LSRV X6,X10,X8.
        for off in (0x004767E8, 0x00476D70, 0x004772F8, 0x00477880, 0x00477E08):
            assert struct.unpack_from("<I", bb, off)[0] == 0x5280200A
            assert struct.unpack_from("<I", bb, off + 4)[0] == 0x9AC82546
        # FPGA factory MOVZ W9,#1,LSL#16 then LSRV W7,W9,W8 at +7 insns.
        assert struct.unpack_from("<I", bb, 0x004AEE2C)[0] == 0x52A00029
        assert struct.unpack_from("<I", bb, 0x004AEE48)[0] == 0x1AC82527
        # Worker::new FUN_00903534+0x20 mov x26,x6 (count).
        assert struct.unpack_from("<I", bb, 0x00503554)[0] == 0xAA0603FA
        assert b"open/bosminer/bosminer-am2-s17/src/hardware/am3.rs" in bb
        assert (
            b"open/bosminer/bosminer-am2-s17/src/hardware/antminer/controlboard/aml.rs"
            in bb
        )
        assert b"BUG: Combination architecture-control board not supported" in bb
        # : FUN_008d6cf0 MOVZ W10,#0x1366; same factory as 1362/1368/1370.
        assert struct.unpack_from("<I", bb, 0x004D6D00)[0] == 0x52826C48  # #0x1362
        assert struct.unpack_from("<I", bb, 0x004D6D14)[0] == 0x52826CCA  # #0x1366
        assert struct.unpack_from("<I", bb, 0x004D6D40)[0] == 0x52826D0A  # #0x1368
        assert struct.unpack_from("<I", bb, 0x004D6D58)[0] == 0x52826E0A  # #0x1370
        assert b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1366.rs" in bb
        assert b"Bm1366 HashChain driver" in bb
        assert b"Setting ticket mask register for difficulty" in bb
        # : FUN_0083ca30 REV16 W10,W10 then STR packed UartRelayReg.
        assert struct.unpack_from("<I", bb, 0x0043CAB0)[0] == 0x5AC0094A
        assert struct.unpack_from("<I", bb, 0x0043CAF4)[0] == 0xB9000008
        assert (
            struct.unpack_from("<I", bb, 0x0043CA98)[0] == 0x39400AC8
        )  # LDRB W8,[X22,#2]
        assert b"UartRelayReg" in bb
        assert b"nonce_gap_en" in bb
        assert b"ro_relay_en" in bb
        assert b"co_relay_en" in bb
        assert b"Enabling UART relay chip:" in bb
        # : pack-caller LSL X1,X9,X10; work-response parse; clone fn.
        assert struct.unpack_from("<I", bb, 0x0051C00C)[0] == 0x9ACA2121
        assert (
            struct.unpack_from("<I", bb, 0x0051C000)[0] == 0xF940482B
        )  # LDR X11,[X1,#0x90]
        assert (
            struct.unpack_from("<I", bb, 0x0051C0DC)[0] == 0xF9404428
        )  # LDR X8,[X1,#0x88]
        for va in (
            0x00843B80,
            0x00845FA0,
            0x008689E8,
            0x00868ECC,
            0x0088B5FC,
            0x008DC920,
        ):
            off = va - 0x400000
            assert struct.unpack_from("<I", bb, off)[0] == 0x52800089, hex(va)
            assert struct.unpack_from("<I", bb, off + 0x1C)[0] == 0xF9004269, hex(va)
            assert struct.unpack_from("<I", bb, off + 0x3C)[0] == 0xF9004660, hex(va)
        assert struct.unpack_from("<I", bb, 0x004D9998)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x00475F74)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00475F80)[0] == 0xAA0103F4
        assert struct.unpack_from("<I", bb, 0x00475FAC)[0] == 0x3CC88285
        assert struct.unpack_from("<I", bb, 0x004761D4)[0] == 0x3C888265
        for va, insn in (
            (0x0087679C, 0x97FFFDEE),
            (0x00876D24, 0x97FFFC8C),
            (0x008772AC, 0x97FFFB2A),
            (0x00877834, 0x97FFF9C8),
            (0x00877DBC, 0x97FFF866),
        ):
            off = va - 0x400000
            assert struct.unpack_from("<I", bb, off)[0] == insn, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x20)[0] == 0xAA0103F8, hex(va)
        # : prep Q5 from X1 onto SP+0x230; get X2 is prep source; prod two templates.
        assert struct.unpack_from("<I", bb, 0x0043B3D4)[0] == 0xAA0103F4
        assert struct.unpack_from("<I", bb, 0x0043B400)[0] == 0x3CC88285
        assert struct.unpack_from("<I", bb, 0x0043B578)[0] == 0x9108C3EB
        assert struct.unpack_from("<I", bb, 0x0043B630)[0] == 0x3C888165
        assert struct.unpack_from("<I", bb, 0x00435240)[0] == 0xAA0203F3
        assert struct.unpack_from("<I", bb, 0x004352DC)[0] == 0xAA1303E1
        assert struct.unpack_from("<I", bb, 0x004352E0)[0] == 0x94001830
        assert struct.unpack_from("<I", bb, 0x0047E190)[0] == 0x910B83E0
        assert struct.unpack_from("<I", bb, 0x0047E1C0)[0] == 0x910B83E2
        # : FUN_0087fb4c wraps clone; prod clones X22 onto SP+0x2e0.
        assert struct.unpack_from("<I", bb, 0x0047FB70)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x0047FB78)[0] == 0xAA0103F4
        assert struct.unpack_from("<I", bb, 0x0047FB80)[0] == 0x97FFD8F5
        assert struct.unpack_from("<I", bb, 0x0047E044)[0] == 0xAA0003F6
        assert struct.unpack_from("<I", bb, 0x0047E194)[0] == 0xAA1603E1
        assert struct.unpack_from("<I", bb, 0x0047E198)[0] == 0x9400066D
        # : two 0x2a0 vtables; method 0 = FUN_0087e02c.
        assert struct.unpack_from("<Q", bb, 0x015AB778)[0] == 0x87E02C
        assert struct.unpack_from("<Q", bb, 0x015AB768)[0] == 0x2A0
        assert struct.unpack_from("<Q", bb, 0x015AB770)[0] == 0x10
        assert struct.unpack_from("<I", bb, 0x015AB758)[0] == 258
        assert struct.unpack_from("<I", bb, 0x015AB75C)[0] == 22
        assert struct.unpack_from("<Q", bb, 0x015B1920)[0] == 0x87E02C
        assert struct.unpack_from("<Q", bb, 0x015B1910)[0] == 0x2A0
        assert struct.unpack_from("<Q", bb, 0x015B1918)[0] == 0x10
        assert struct.unpack_from("<I", bb, 0x015B1900)[0] == 352
        assert struct.unpack_from("<I", bb, 0x015B1904)[0] == 18
        assert (
            bb[0x00F1B9BC : 0x00F1B9BC + 0x43]
            == b"open/bosminer/bosminer-am2-s17/src/hardware/braiinsminer/fixture.rs"
        )
        assert (
            bb[0x00F1F03A : 0x00F1F03A + 0x2E]
            == b"open/bosminer/bosminer-am2-s17/src/hardware.rs"
        )
        # : *(X22+0x290)+0x88; not X22+0x88; SP+#0x88 is a stack slot.
        assert struct.unpack_from("<I", bb, 0x0047E11C)[0] == 0xF9414AC9
        assert struct.unpack_from("<I", bb, 0x0047E128)[0] == 0xF9404529
        assert struct.unpack_from("<I", bb, 0x0047E070)[0] == 0xF94047E1
        # : *(X22+0x290) is HashMap-get self, not HashChain engine.
        assert struct.unpack_from("<I", bb, 0x0047E080)[0] == 0xF9414AC0
        assert struct.unpack_from("<I", bb, 0x0047E084)[0] == 0xAA1603E1
        assert struct.unpack_from("<I", bb, 0x0047E088)[0] == 0x97FFE9C8
        assert struct.unpack_from("<I", bb, 0x004787B8)[0] == 0x91030000
        assert struct.unpack_from("<I", bb, 0x004787C8)[0] == 0xF9405688
        assert struct.unpack_from("<I", bb, 0x004787CC)[0] == 0x91067033
        assert struct.unpack_from("<I", bb, 0x00478C98)[0] == 0xF9014AFA
        assert struct.unpack_from("<I", bb, 0x00478C9C)[0] == 0xF9014EF9
        # : AM3 STR#0x88 census — Result/slice/future/zero/field, not map+0x88.
        for va, insn in (
            (0x008683B8, 0xF9004669),
            (0x00868A24, 0xF9004660),
            (0x00868F08, 0xF9004660),
            (0x0086C42C, 0xF9004668),
            (0x0086CADC, 0xF9004668),
            (0x0086DDE8, 0xF900467F),
            (0x008764BC, 0xF9004668),
            (0x0088B638, 0xF9004660),
            (0x0088D984, 0xF9004668),
            (0x0088E0B8, 0xF9004668),
        ):
            assert struct.unpack_from("<I", bb, va - 0x400000)[0] == insn, hex(va)
        assert struct.unpack_from("<I", bb, 0x00465F04)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x00487D24)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x0046C420)[0] == 0x91006148
        assert struct.unpack_from("<I", bb, 0x0048D978)[0] == 0x91006148
        assert struct.unpack_from("<I", bb, 0x0048E0AC)[0] == 0x91004108
        # : HashMap dest STR#0x88 (both +0xA8 and +0xC0); 3-site family.
        for va, insn in (
            (0x005DE708, 0xF9004660),
            (0x00626AAC, 0xF9004660),
            (0x00654C10, 0xF9004678),
            (0x00655098, 0xF9004668),
            (0x008D1340, 0xF9004674),
            (0x008D1BF8, 0xF9004674),
            (0x008D24B0, 0xF9004674),
            (0x009F3F00, 0xF9004668),
            (0x00B824C8, 0xF9004669),
            (0x0115C698, 0xF90046A8),
            (0x0115C788, 0xF90046A8),
        ):
            assert struct.unpack_from("<I", bb, va - 0x400000)[0] == insn, hex(va)
        assert struct.unpack_from("<I", bb, 0x004D1180)[0] == 0x9102A260
        assert struct.unpack_from("<I", bb, 0x004D1190)[0] == 0x91030260
        assert struct.unpack_from("<I", bb, 0x004D1A38)[0] == 0x9102A260
        assert struct.unpack_from("<I", bb, 0x004D1A48)[0] == 0x91030260
        # : X20 is Result-Ok [SP,#0x118] after BL FUN_00861090.
        for va, bl in (
            (0x008D1340, 0x97FE3F68),
            (0x008D1BF8, 0x97FE3D3A),
            (0x008D24B0, 0x97FE3B0C),
        ):
            off = va - 0x400000
            assert struct.unpack_from("<I", bb, off - 0x50)[0] == bl, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x4C)[0] == 0xB94113E8, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x48)[0] == 0x360000A8, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x34)[0] == 0xA951DFF4, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x58)[0] == 0x910443E8, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x5C)[0] == 0xF9405E60, hex(va)
            assert struct.unpack_from("<I", bb, off - 0xCC)[0] == 0x91022274, hex(va)
            assert struct.unpack_from("<I", bb, off - 0x7C)[0] == 0x91024274, hex(va)
        assert struct.unpack_from("<I", bb, 0x00461090)[0] != 0
        # : FUN_00861090 Ok = clone of *(self+0xB8); 8 rest dests.
        assert struct.unpack_from("<I", bb, 0x0046109C)[0] == 0xF9400016
        assert struct.unpack_from("<I", bb, 0x004610A0)[0] == 0xAA0003F4
        assert struct.unpack_from("<I", bb, 0x004610A4)[0] == 0xAA0803F3
        assert struct.unpack_from("<I", bb, 0x004610B0)[0] == 0x910042C0
        assert struct.unpack_from("<I", bb, 0x004610B4)[0] == 0x940153FE
        assert struct.unpack_from("<I", bb, 0x00461148)[0] == 0xF9000660
        assert struct.unpack_from("<I", bb, 0x0046114C)[0] == 0xF9000A61
        assert struct.unpack_from("<I", bb, 0x00461150)[0] == 0xF900027F
        assert struct.unpack_from("<I", bb, 0x004B60AC)[0] != 0
        assert struct.unpack_from("<I", bb, 0x004B6120)[0] == 0x52800301
        assert struct.unpack_from("<I", bb, 0x004B6124)[0] == 0x52800102
        assert struct.unpack_from("<I", bb, 0x00255088)[0] == 0x91004108
        # : 0x18 node is dealloc-shaped; 0x5de708 Result X0; 0x115c698 field rewrite.
        assert struct.unpack_from("<I", bb, 0x004B60B8)[0] == 0xF9400413
        assert struct.unpack_from("<I", bb, 0x004B60C0)[0] == 0x91004268
        assert struct.unpack_from("<I", bb, 0x004B60F8)[0] == 0xF9400514
        assert struct.unpack_from("<I", bb, 0x004B6100)[0] == 0xF9400115
        assert struct.unpack_from("<I", bb, 0x004B611C)[0] == 0xAA1303E0
        assert struct.unpack_from("<I", bb, 0x004B6128)[0] == 0x97F4FA55
        assert struct.unpack_from("<I", bb, 0x004B612C)[0] == 0xAA1503E0
        assert struct.unpack_from("<I", bb, 0x004B6130)[0] == 0xAA1403E1
        assert struct.unpack_from("<I", bb, 0x001F4A7C)[0] == 0x143299AB
        assert struct.unpack_from("<I", bb, 0x001DE6FC)[0] == 0x97FEA177
        assert struct.unpack_from("<I", bb, 0x001DE704)[0] == 0xF9405268
        assert struct.unpack_from("<I", bb, 0x00D5C680)[0] == 0xF94046B4
        assert struct.unpack_from("<I", bb, 0x00D5C694)[0] == 0xF94056B4
        assert struct.unpack_from("<I", bb, 0x00D5C698)[0] == 0xF90046A8
        assert struct.unpack_from("<I", bb, 0x00D5C6B0)[0] == 0xF90056A8
        # : thunk0 body is dummy-frame B 0xbc9f10; six rest dests classified.
        assert struct.unpack_from("<I", bb, 0x00E9B128)[0] == 0xA9BF7BFD
        assert struct.unpack_from("<I", bb, 0x00E9B12C)[0] == 0x910003FD
        assert struct.unpack_from("<I", bb, 0x00E9B130)[0] == 0xA8C17BFD
        assert struct.unpack_from("<I", bb, 0x00E9B134)[0] == 0x17E4BB77
        assert struct.unpack_from("<I", bb, 0x00E9B138)[0] == 0xD10103FF
        assert struct.unpack_from("<I", bb, 0x007C9F10)[0] == 0x1400012F
        assert struct.unpack_from("<I", bb, 0x007CA3CC)[0] == 0xB40012A0
        assert struct.unpack_from("<I", bb, 0x0022672C)[0] == 0xF94002E0
        assert struct.unpack_from("<I", bb, 0x00226730)[0] == 0x140000DF
        assert struct.unpack_from("<I", bb, 0x00226AA8)[0] == 0x97F8B382
        assert struct.unpack_from("<I", bb, 0x00226AAC)[0] == 0xF9004660
        assert struct.unpack_from("<I", bb, 0x000538C0)[0] == 0x52800481
        assert struct.unpack_from("<I", bb, 0x00254690)[0] == 0xF9404A78
        assert struct.unpack_from("<I", bb, 0x00254698)[0] == 0x1400015E
        assert struct.unpack_from("<I", bb, 0x00254C10)[0] == 0xF9004678
        assert struct.unpack_from("<I", bb, 0x005F3ED8)[0] == 0xF9400BE8
        assert struct.unpack_from("<I", bb, 0x005F3F00)[0] == 0xF9004668
        assert struct.unpack_from("<I", bb, 0x007824BC)[0] == 0x97E344FD
        assert struct.unpack_from("<I", bb, 0x007824C0)[0] == 0x91002109
        assert struct.unpack_from("<I", bb, 0x007824C8)[0] == 0xF9004669
        assert struct.unpack_from("<I", bb, 0x00D5C784)[0] == 0xF94056B4
        assert struct.unpack_from("<I", bb, 0x00D5C788)[0] == 0xF90046A8
        assert (
            bb[0x0120B3A6 : 0x0120B3A6 + 36] == b"panic in a destructor during cleanup"
        )
        # : thunk2 is size-product tail to 0xbc9e18; 0x626aac second arm X8+0x20.
        assert struct.unpack_from("<I", bb, 0x00E9B1E4)[0] == 0xD100C3FF
        assert struct.unpack_from("<I", bb, 0x00E9B1F4)[0] == 0xF100403F
        assert struct.unpack_from("<I", bb, 0x00E9B1F8)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00E9B21C)[0] == 0x17E4BAFF
        assert struct.unpack_from("<I", bb, 0x007C9E18)[0] == 0xA9BD7BFD
        assert struct.unpack_from("<I", bb, 0x007C9E24)[0] == 0xB4000061
        assert struct.unpack_from("<I", bb, 0x007C9E28)[0] == 0x9BC17C02
        assert struct.unpack_from("<I", bb, 0x007C9E30)[0] == 0x9B007C33
        assert struct.unpack_from("<I", bb, 0x00226FB0)[0] == 0x91008100
        assert struct.unpack_from("<I", bb, 0x00226FC0)[0] == 0x17FFFEBB
        # : fill +0x88 template is spawn X24; no ADRP identity installer.
        assert struct.unpack_from("<I", bb, 0x0047E094)[0] == 0xF9400037
        assert struct.unpack_from("<I", bb, 0x0047E144)[0] == 0x9101A3E8
        assert struct.unpack_from("<I", bb, 0x0047E15C)[0] == 0xD63F02E0
        assert struct.unpack_from("<I", bb, 0x0047E168)[0] == 0xF9403FE8
        assert struct.unpack_from("<I", bb, 0x0047E170)[0] == 0xF90033E8
        assert struct.unpack_from("<I", bb, 0x0047E188)[0] == 0xF94033F8
        assert struct.unpack_from("<I", bb, 0x0047E1C8)[0] == 0xAA1803E1
        # : get (tag,payload); spawn X23=[X1]; miss default 0x50.
        assert struct.unpack_from("<I", bb, 0x004788E4)[0] == 0x52800033
        assert struct.unpack_from("<I", bb, 0x00478910)[0] == 0x910022B4
        assert struct.unpack_from("<I", bb, 0x00478918)[0] == 0xAA1F03F3
        assert struct.unpack_from("<I", bb, 0x0047891C)[0] == 0xAA1303E0
        assert struct.unpack_from("<I", bb, 0x00478920)[0] == 0xAA1403E1
        assert struct.unpack_from("<I", bb, 0x00478930)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00478938)[0] == 0xAA1303E0
        assert struct.unpack_from("<I", bb, 0x0047893C)[0] == 0xAA1403E1
        assert struct.unpack_from("<I", bb, 0x0047894C)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x0047E08C)[0] == 0x37000F60
        assert struct.unpack_from("<I", bb, 0x0000BE80)[0] == 0x52800101
        assert struct.unpack_from("<I", bb, 0x0000BE90)[0] == 0x52800A00
        assert struct.unpack_from("<I", bb, 0x0000BEA4)[0] == 0x9407A2F5
        assert struct.unpack_from("<I", bb, 0x0000BE64)[0] == 0xD000AD88
        assert struct.unpack_from("<I", bb, 0x0000BE68)[0] == 0x91394108
        assert struct.unpack_from("<I", bb, 0x0000BE70)[0] == 0xF90003E8
        assert struct.unpack_from("<I", bb, 0x001F4A78)[0] == 0x14329996
        # : insert HIT copies 0x18 from entry|8; not +0x88 identity.
        assert struct.unpack_from("<I", bb, 0x004DA530)[0] == 0xAA0303F5
        assert struct.unpack_from("<I", bb, 0x004DA53C)[0] == 0x97FF79D2
        assert struct.unpack_from("<I", bb, 0x004787DC)[0] == 0x9401012A
        assert struct.unpack_from("<I", bb, 0x004DA610)[0] == 0x3DC002A1
        assert struct.unpack_from("<I", bb, 0x004DA614)[0] == 0xF9400AA9
        assert struct.unpack_from("<I", bb, 0x004DA620)[0] == 0x3C9E8221
        assert struct.unpack_from("<I", bb, 0x004DA624)[0] == 0xF81F8229
        assert struct.unpack_from("<I", bb, 0x004D4A4C)[0] == 0xB27D02A3
        assert struct.unpack_from("<I", bb, 0x004D4A5C)[0] == 0x940016AD
        # : entry|8 qword0 is factory4 FUN_00877d40; 0x250 has no extra +0x88.
        assert struct.unpack_from("<I", bb, 0x004624A0)[0] == 0xB00000A9
        assert struct.unpack_from("<I", bb, 0x004624A4)[0] == 0x91350129
        assert struct.unpack_from("<I", bb, 0x004624BC)[0] == 0xA903A3E9
        assert struct.unpack_from("<I", bb, 0x004624D4)[0] == 0xA905ABE9
        assert struct.unpack_from("<I", bb, 0x0046256C)[0] == 0x9100C3E1
        assert struct.unpack_from("<I", bb, 0x00462570)[0] == 0x9401C928
        assert struct.unpack_from("<I", bb, 0x004D4A40)[0] == 0xAD400680
        assert struct.unpack_from("<I", bb, 0x004D4A44)[0] == 0x910003F5
        assert struct.unpack_from("<I", bb, 0x004D4A54)[0] == 0xAD0007E0
        assert struct.unpack_from("<I", bb, 0x00477D40)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x00477DBC)[0] == 0x97FFF866
        assert struct.unpack_from("<I", bb, 0x00475F54)[0] != 0
        # : factory4 vs FUN_00876ca8 are sibling monomorphs; 1366 uses both.
        assert struct.unpack_from("<I", bb, 0x00477D78)[0] == 0xD11B03FF
        assert struct.unpack_from("<I", bb, 0x00476CE0)[0] == 0xD11A43FF
        assert struct.unpack_from("<I", bb, 0x00477E50)[0] == 0x5282C102
        assert struct.unpack_from("<I", bb, 0x00476DB8)[0] == 0x5282BF02
        assert struct.unpack_from("<I", bb, 0x00477E38)[0] == 0x9402317F
        assert struct.unpack_from("<I", bb, 0x00476DA0)[0] == 0x940231E5
        assert struct.unpack_from("<I", bb, 0x00476D24)[0] == 0x97FFFC8C
        assert struct.unpack_from("<I", bb, 0x004D6D14)[0] == 0x52826CCA
        assert struct.unpack_from("<I", bb, 0x00504434)[0] == 0xFC190FE8
        assert struct.unpack_from("<I", bb, 0x00503534)[0] == 0xFC190FE8
        # : worker_new frames 0xEE0 vs 0xF00; factory extra sizes +0x10; 0x230 shared.
        assert struct.unpack_from("<I", bb, 0x00503550)[0] == 0xD13B83FF
        assert struct.unpack_from("<I", bb, 0x00504450)[0] == 0xD13C03FF
        assert struct.unpack_from("<I", bb, 0x00476E58)[0] == 0x5282C002
        assert struct.unpack_from("<I", bb, 0x00477EF0)[0] == 0x5282C202
        assert struct.unpack_from("<I", bb, 0x00476E80)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x00477F18)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x00476EC4)[0] == 0x52831202
        assert struct.unpack_from("<I", bb, 0x00477F5C)[0] == 0x52831402
        assert struct.unpack_from("<I", bb, 0x00503690)[0] == 0x52803502
        assert struct.unpack_from("<I", bb, 0x005044D8)[0] == 0x52994009
        # : #0xca00 is 1e9 MOVZ+MOVK, then CMP W8,W9; 230 first-LOAD hits.
        assert struct.unpack_from("<I", bb, 0x005044D4)[0] == 0xB94383E8
        assert struct.unpack_from("<I", bb, 0x005044E0)[0] == 0x72A77349
        assert struct.unpack_from("<I", bb, 0x005044E4)[0] == 0x6B09011F
        assert struct.unpack_from("<I", bb, 0x005044E8)[0] == 0x540006E1
        ca00_w9 = 0
        off = 0
        while off + 4 <= 0x01375388:
            if struct.unpack_from("<I", bb, off)[0] == 0x52994009:
                ca00_w9 += 1
            off += 4
        assert ca00_w9 == 230
        # : both worker_new memcpy #0x1a8 via 0xbc8fe0; not the +16 field.
        assert struct.unpack_from("<I", bb, 0x00503690)[0] == 0x52803502
        assert struct.unpack_from("<I", bb, 0x00504690)[0] == 0x52803502
        assert struct.unpack_from("<I", bb, 0x005036CC)[0] == 0x940B1645
        assert struct.unpack_from("<I", bb, 0x005046CC)[0] == 0x940B1245
        copy1a8 = 0
        off = 0
        while off + 4 <= 0x01375388:
            if struct.unpack_from("<I", bb, off)[0] == 0x52803502:
                copy1a8 += 1
            off += 4
        assert copy1a8 == 64
        # : extra 16 B is snap tail; dest SP+#0x40 shared; src #0x640 vs #0x650.
        assert struct.unpack_from("<I", bb, 0x00476DB0)[0] == 0x914007E8
        assert struct.unpack_from("<I", bb, 0x00476DB4)[0] == 0x910103E9
        assert struct.unpack_from("<I", bb, 0x00476DBC)[0] == 0x91190108
        assert struct.unpack_from("<I", bb, 0x00477E48)[0] == 0x914007E8
        assert struct.unpack_from("<I", bb, 0x00477E4C)[0] == 0x910103E9
        assert struct.unpack_from("<I", bb, 0x00477E54)[0] == 0x91194108
        assert struct.unpack_from("<I", bb, 0x004624C0)[0] == 0x5295E108
        assert struct.unpack_from("<I", bb, 0x004624C4)[0] == 0x72A005E8
        assert struct.unpack_from("<I", bb, 0x004624C8)[0] == 0xF90027E8
        # : extra 16 B is worker_new STR +0x15F8 / +0x1600.
        assert struct.unpack_from("<I", bb, 0x00503F90)[0] == 0xF90AFEC9
        assert struct.unpack_from("<I", bb, 0x00503FC4)[0] == 0xF90B02D5
        assert struct.unpack_from("<I", bb, 0x00504ED4)[0] == 0xF90AFEB3
        assert struct.unpack_from("<I", bb, 0x00504EC0)[0] == 0xF90B02A9
        # : 876 +0x15F8 is arg0; +0x1600 is call return; 0x2faf08 is rustc size-class.
        assert struct.unpack_from("<I", bb, 0x00503560)[0] == 0xAA0003F8
        assert struct.unpack_from("<I", bb, 0x00503564)[0] == 0xAA0803F6
        assert struct.unpack_from("<I", bb, 0x00503E30)[0] == 0xF9001BF8
        assert struct.unpack_from("<I", bb, 0x00503F64)[0] == 0xF9401BE9
        assert struct.unpack_from("<I", bb, 0x00503F78)[0] == 0xF909DEC9
        assert struct.unpack_from("<I", bb, 0x00503754)[0] == 0xAA1803E0
        assert struct.unpack_from("<I", bb, 0x0050375C)[0] == 0x940BBF12
        assert struct.unpack_from("<I", bb, 0x00503768)[0] == 0xF902FBE0
        assert struct.unpack_from("<I", bb, 0x00503F00)[0] == 0xF942FBF5
        assert struct.unpack_from("<I", bb, 0x00504E6C)[0] == 0x52824129
        assert struct.unpack_from("<I", bb, 0x007C00B4)[0] == 0xEB08003F
        assert struct.unpack_from("<I", bb, 0x007C00BC)[0] == 0x52800174
        assert struct.unpack_from("<I", bb, 0x007C00C4)[0] == 0x52800154
        af08 = 0
        off = 0
        while off + 4 <= 0x01375388:
            if struct.unpack_from("<I", bb, off)[0] == 0x5295E108:
                af08 += 1
            off += 4
        assert af08 == 4
        # : factory X23 is self; FUN_00bf33a4 is 0x70 box; #0x1209 is end offset.
        assert struct.unpack_from("<I", bb, 0x00476D08)[0] == 0xAA0003F7
        assert struct.unpack_from("<I", bb, 0x00477DA0)[0] == 0xAA0003F7
        assert struct.unpack_from("<I", bb, 0x00476D8C)[0] == 0xAA1703E0
        assert struct.unpack_from("<I", bb, 0x00477E24)[0] == 0xAA1703E0
        assert struct.unpack_from("<I", bb, 0x007F33A4)[0] == 0xD10203FF
        assert struct.unpack_from("<I", bb, 0x007F33E4)[0] == 0x52800E00
        assert struct.unpack_from("<I", bb, 0x007F33E8)[0] == 0x52800101
        assert struct.unpack_from("<I", bb, 0x007F3400)[0] == 0x97E8059E
        assert struct.unpack_from("<I", bb, 0x007F3424)[0] == 0xF9001017
        assert struct.unpack_from("<I", bb, 0x007F3448)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00503F2C)[0] == 0x52824129
        assert struct.unpack_from("<I", bb, 0x00503F34)[0] == 0x8B0902C0
        assert struct.unpack_from("<I", bb, 0x00503F44)[0] == 0x52824108
        assert struct.unpack_from("<I", bb, 0x00504E74)[0] == 0x52824108
        assert struct.unpack_from("<I", bb, 0x00504E78)[0] == 0x8B0902A0
        # : 0x70 box fields; 0x1af copy to obj+0x1209; 0 factory-self LDR.
        assert struct.unpack_from("<I", bb, 0x007F3414)[0] == 0xF9000816
        assert struct.unpack_from("<I", bb, 0x007F341C)[0] == 0x39006015
        assert struct.unpack_from("<I", bb, 0x007F342C)[0] == 0xA9064C14
        assert struct.unpack_from("<I", bb, 0x007F3440)[0] == 0xA904FC08
        assert struct.unpack_from("<I", bb, 0x007F3438)[0] == 0x3D800000
        assert struct.unpack_from("<I", bb, 0x00504758)[0] == 0x940BBB13
        assert struct.unpack_from("<I", bb, 0x00504764)[0] == 0xF9030BE0
        assert struct.unpack_from("<I", bb, 0x00503F38)[0] == 0x528035E2
        assert struct.unpack_from("<I", bb, 0x00504E5C)[0] == 0x528035E2
        assert struct.unpack_from("<I", bb, 0x00503F30)[0] == 0x912103E1
        assert struct.unpack_from("<I", bb, 0x00504E58)[0] == 0x912183E1
        assert struct.unpack_from("<I", bb, 0x00503F48)[0] == 0xF908F2DF
        assert struct.unpack_from("<I", bb, 0x00503F54)[0] == 0xF90902D9
        assert struct.unpack_from("<I", bb, 0x00503F58)[0] == 0x38286AD3
        copy1af = 0
        off = 0
        while off + 4 <= 0x01375388:
            if struct.unpack_from("<I", bb, off)[0] == 0x528035E2:
                copy1af += 1
            off += 4
        assert copy1af == 6
        # : FUN_011f26f8 zeros+tag2; 0x1af=7+0x1a8; factory4 SP+#0x610 drop.
        assert struct.unpack_from("<I", bb, 0x00DF26F8)[0] == 0xD37DFC09
        assert struct.unpack_from("<I", bb, 0x00DF2700)[0] == 0xD37FF809
        assert struct.unpack_from("<I", bb, 0x00DF2704)[0] == 0xA9007D1F
        assert struct.unpack_from("<I", bb, 0x00DF2710)[0] == 0xF9001109
        assert struct.unpack_from("<I", bb, 0x00DF2714)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x007F33C8)[0] == 0x9100A3E8
        assert struct.unpack_from("<I", bb, 0x007F33CC)[0] == 0x52800020
        assert struct.unpack_from("<I", bb, 0x007F33D4)[0] == 0x3CC283E0
        assert struct.unpack_from("<I", bb, 0x007F33D8)[0] == 0x3CC383E1
        assert struct.unpack_from("<I", bb, 0x00503E60)[0] == 0x912103E8
        assert struct.unpack_from("<I", bb, 0x00503E64)[0] == 0x91001D00
        assert struct.unpack_from("<I", bb, 0x00504D7C)[0] == 0x912183E8
        assert struct.unpack_from("<I", bb, 0x005051C0)[0] == 0x911843E0
        assert struct.unpack_from("<I", bb, 0x005051C4)[0] == 0x9408F2EF
        # : 7-byte prefix; FUN_00b41d80 is 0x70/8 drop; Q2 from LDP [SP].
        assert struct.unpack_from("<I", bb, 0x00741D88)[0] == 0xF9400013
        assert struct.unpack_from("<I", bb, 0x00741DDC)[0] == 0x52800E01
        assert struct.unpack_from("<I", bb, 0x00741DE4)[0] == 0x52800102
        assert struct.unpack_from("<I", bb, 0x00741DEC)[0] == 0x17EACB24
        assert struct.unpack_from("<I", bb, 0x007F340C)[0] == 0xAD400BE1
        assert struct.unpack_from("<I", bb, 0x007F343C)[0] == 0x3C838002
        assert struct.unpack_from("<I", bb, 0x00504C98)[0] == 0xF94767E9
        assert struct.unpack_from("<I", bb, 0x00504CA8)[0] == 0xF90423E9
        assert struct.unpack_from("<I", bb, 0x00503E24)[0] == 0xF90767E1
        # : FUN_00887c34 0x98 box is factory4 prefix; Q2 is helper zeros.
        assert struct.unpack_from("<I", bb, 0x00487C34)[0] == 0xD102C3FF
        assert struct.unpack_from("<I", bb, 0x00487C70)[0] == 0x52801300
        assert struct.unpack_from("<I", bb, 0x00487C44)[0] == 0x52800101
        assert struct.unpack_from("<I", bb, 0x00487C8C)[0] == 0x97F5B37B
        assert struct.unpack_from("<I", bb, 0x00487CDC)[0] == 0xAA0003E1
        assert struct.unpack_from("<I", bb, 0x005046D0)[0] == 0xAA1F03E0
        assert struct.unpack_from("<I", bb, 0x005046D4)[0] == 0x97FE0D58
        assert struct.unpack_from("<I", bb, 0x005046E4)[0] == 0xF90303E0
        assert struct.unpack_from("<I", bb, 0x00504AA8)[0] == 0xF94303E8
        assert struct.unpack_from("<I", bb, 0x00504AB0)[0] == 0xF90767E8
        assert struct.unpack_from("<I", bb, 0x005036D0)[0] == 0xAA1F03E0
        assert struct.unpack_from("<I", bb, 0x005036E8)[0] == 0xF902F3E0
        assert struct.unpack_from("<I", bb, 0x007BD3DC)[0] == 0xF9400000
        assert struct.unpack_from("<I", bb, 0x007BD3F4)[0] == 0x91012008
        assert struct.unpack_from("<I", bb, 0x007BD3F8)[0] == 0xC85FFD01
        assert struct.unpack_from("<I", bb, 0x00503E14)[0] == 0x940AE572
        assert struct.unpack_from("<I", bb, 0x00504D30)[0] == 0x940AE1AB
        assert struct.unpack_from("<I", bb, 0x00504D38)[0] == 0xF90773E0
        assert struct.unpack_from("<I", bb, 0x00504D40)[0] == 0xF90777E1
        assert struct.unpack_from("<I", bb, 0x007F33EC)[0] == 0x3D8003E0
        assert struct.unpack_from("<I", bb, 0x007F33F4)[0] == 0x3D8007E1
        assert struct.unpack_from("<I", bb, 0x007F3434)[0] == 0x3C828001
        # : 0x98 ArcInner field map.
        assert struct.unpack_from("<I", bb, 0x00487C4C)[0] == 0x52800108
        assert struct.unpack_from("<I", bb, 0x00487C5C)[0] == 0x3D8003E0
        assert struct.unpack_from("<I", bb, 0x00487C64)[0] == 0xA901A3FF
        assert struct.unpack_from("<I", bb, 0x00487C68)[0] == 0xA903A3FF
        assert struct.unpack_from("<I", bb, 0x00487C6C)[0] == 0xA905FFE0
        assert struct.unpack_from("<I", bb, 0x00487C74)[0] == 0xF90037E8
        assert struct.unpack_from("<I", bb, 0x00487CC4)[0] == 0xC85F7C08
        assert struct.unpack_from("<I", bb, 0x00487CAC)[0] == 0xF9004808
        # : 0x1af prefix unwritten; Arc #0x840 != blob #0x860; Layout.align=8.
        assert struct.unpack_from("<I", bb, 0x00504D80)[0] == 0x91001D00
        assert struct.unpack_from("<I", bb, 0x00504E58)[0] == 0x912183E1
        assert struct.unpack_from("<I", bb, 0x00504D7C)[0] == 0x912183E8
        assert struct.unpack_from("<I", bb, 0x00504CA8)[0] == 0xF90423E9
        f4_str860 = 0
        off = 0x00504434
        end = 0x00505400
        while off + 4 <= end:
            w = struct.unpack_from("<I", bb, off)[0]
            if ((w >> 22) & 0x3FF) == 0x3E4:
                rn = (w >> 5) & 0x1F
                imm = ((w >> 10) & 0xFFF) * 8
                if rn == 31 and imm == 0x860:
                    f4_str860 += 1
            off += 4
        assert f4_str860 == 0
        # : 0x1af = pad7 after +0x1208 plus 0x1a8 at +0x1210; next STR #0x13b8.
        assert struct.unpack_from("<I", bb, 0x00504E6C)[0] == 0x52824129
        assert struct.unpack_from("<I", bb, 0x00504E74)[0] == 0x52824108
        assert struct.unpack_from("<I", bb, 0x00504E78)[0] == 0x8B0902A0
        assert struct.unpack_from("<I", bb, 0x00504E84)[0] == 0x38286AB4
        assert struct.unpack_from("<I", bb, 0x00504EA4)[0] == 0xF909DEA9
        assert struct.unpack_from("<I", bb, 0x00503F78)[0] == 0xF909DEC9
        assert struct.unpack_from("<I", bb, 0x00504E5C)[0] == 0x528035E2
        # : +0x1208 = *(arg1+0xC8) via box+0x18; 0x1a8 src is Worker::new local.
        assert struct.unpack_from("<I", bb, 0x0050373C)[0] == 0x3943233A
        assert struct.unpack_from("<I", bb, 0x00503758)[0] == 0x2A1A03E4
        assert struct.unpack_from("<I", bb, 0x00504740)[0] == 0x39432304
        assert struct.unpack_from("<I", bb, 0x00503768)[0] == 0xF902FBE0
        assert struct.unpack_from("<I", bb, 0x00503DE0)[0] == 0xF942FBE8
        assert struct.unpack_from("<I", bb, 0x00503E04)[0] == 0x39406113
        assert struct.unpack_from("<I", bb, 0x00504D28)[0] == 0x39406116
        assert struct.unpack_from("<I", bb, 0x00504DE4)[0] == 0x2A1603F4
        assert struct.unpack_from("<I", bb, 0x00503E50)[0] == 0x910D43E1
        assert struct.unpack_from("<I", bb, 0x00504D68)[0] == 0x910DC3E1
        # : HashChain+0xC8 state tag; 0x1a8 is Registry wrap output.
        assert struct.unpack_from("<I", bb, 0x004D6858)[0] == 0x39432008
        assert struct.unpack_from("<I", bb, 0x004D6864)[0] == 0x7100051F
        assert struct.unpack_from("<I", bb, 0x004D689C)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x004D68B0)[0] == 0x7100091F
        assert struct.unpack_from("<I", bb, 0x004D69BC)[0] == 0x52800028
        assert struct.unpack_from("<I", bb, 0x004D69C0)[0] == 0x39032268
        assert struct.unpack_from("<I", bb, 0x004D69DC)[0] == 0x52800068
        assert struct.unpack_from("<I", bb, 0x004D6A84)[0] == 0x52800048
        assert struct.unpack_from("<I", bb, 0x00503678)[0] == 0x910D43F3
        assert struct.unpack_from("<I", bb, 0x0050367C)[0] == 0x940BD047
        assert struct.unpack_from("<I", bb, 0x00504674)[0] == 0x910DC3F3
        # : +0xC8 tags 1/2/3 are command.rs:700 async poll states.
        assert struct.unpack_from("<I", bb, 0x004D686C)[0] == 0x35000C68
        assert struct.unpack_from("<I", bb, 0x004D68A0)[0] == 0x54000B21
        assert struct.unpack_from("<I", bb, 0x004D69F8)[0] == 0xB0008780
        assert struct.unpack_from("<I", bb, 0x004D69FC)[0] == 0x91064000
        assert struct.unpack_from("<I", bb, 0x004D6A00)[0] == 0x97EDF490
        assert struct.unpack_from("<I", bb, 0x004D6A0C)[0] == 0x97EDF49A
        assert struct.unpack_from("<I", bb, 0x004D6A1C)[0] == 0x91058000
        assert struct.unpack_from("<I", bb, 0x00053C50)[0] == 0x9111C108
        assert struct.unpack_from("<I", bb, 0x00053C84)[0] == 0x91120108
        assert struct.unpack_from("<I", bb, 0x004D69B8)[0] == 0x2A1F03E0
        assert struct.unpack_from("<I", bb, 0x004D69E0)[0] == 0x52800020
        assert (
            bb[0x0120EAAA : 0x0120EAAA + 35] == b"`async fn` resumed after completion"
        )
        assert bb[0x0120EACD : 0x0120EACD + 34] == b"`async fn` resumed after panicking"
        assert (
            bb[0x00F229BE : 0x00F229BE + 55]
            == b"/build/source/open/bosminer/bosminer-hal/src/command.rs"
        )
        assert struct.unpack_from("<I", bb, 0x015B71A0)[0] == 700
        assert struct.unpack_from("<I", bb, 0x015B71A4)[0] == 51
        assert struct.unpack_from("<I", bb, 0x015B7170)[0] == 719
        assert struct.unpack_from("<I", bb, 0x015B7174)[0] == 12
        cmp3 = 0
        off = 0
        while off + 16 <= 0x01375388:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 22) == 0xE5 and ((w >> 10) & 0xFFF) == 0xC8:
                rt = w & 0x1F
                k = 1
                while k < 5:
                    w2 = struct.unpack_from("<I", bb, off + 4 * k)[0]
                    if (
                        (w2 >> 22) == 0x1C4
                        and ((w2 >> 5) & 0x1F) == rt
                        and (w2 & 0x1F) == 31
                    ):
                        if ((w2 >> 10) & 0xFFF) == 3:
                            cmp3 += 1
                        break
                    k += 1
            off += 4
        assert cmp3 == 77
        drop_bls = 0
        box98_bls = 0
        clone48_bls = 0
        poll_bls = 0
        off = 0
        while off + 4 <= 0x01375388:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                dest = (off + 0x400000) + (imm26 << 2)
                if dest == 0xB41D80:
                    drop_bls += 1
                elif dest == 0x887C34:
                    box98_bls += 1
                elif dest == 0xBBD3DC:
                    clone48_bls += 1
                elif dest == 0x8D684C:
                    poll_bls += 1
            off += 4
        assert drop_bls == 54
        assert box98_bls == 5
        assert clone48_bls == 11
        assert poll_bls == 6
        # : command.rs:700 Future polled from hashchain drivers.
        assert struct.unpack_from("<I", bb, 0x004DD098)[0] == 0xF9411908
        assert struct.unpack_from("<I", bb, 0x004DD0A4)[0] == 0x91004108
        assert struct.unpack_from("<I", bb, 0x004DD0B0)[0] == 0x9100C260
        assert struct.unpack_from("<I", bb, 0x004DD0B8)[0] == 0x97FFE5E5
        assert struct.unpack_from("<I", bb, 0x004DD194)[0] == 0x97FFE5AE
        assert struct.unpack_from("<I", bb, 0x004DD2BC)[0] == 0x97FFE564
        assert struct.unpack_from("<I", bb, 0x004DDC48)[0] == 0x97FFE301
        assert struct.unpack_from("<I", bb, 0x004DDCFC)[0] == 0x97FFE2D4
        assert struct.unpack_from("<I", bb, 0x004DF6B8)[0] == 0x97FFDC65
        assert struct.unpack_from("<I", bb, 0x004DD040)[0] == 0x913BA000
        assert struct.unpack_from("<I", bb, 0x004DDD38)[0] == 0x91316000
        assert struct.unpack_from("<I", bb, 0x004DF798)[0] == 0x91054000
        assert struct.unpack_from("<I", bb, 0x004DDCF4)[0] == 0x9101C260
        assert struct.unpack_from("<I", bb, 0x004DF6B0)[0] == 0x91006260
        assert struct.unpack_from("<I", bb, 0x015B7EF8)[0] == 127
        assert struct.unpack_from("<I", bb, 0x015B7EFC)[0] == 66
        assert struct.unpack_from("<I", bb, 0x015B7C68)[0] == 107
        assert struct.unpack_from("<I", bb, 0x015B7C6C)[0] == 18
        assert struct.unpack_from("<I", bb, 0x015B8160)[0] == 147
        assert struct.unpack_from("<I", bb, 0x015B8164)[0] == 72
        assert bb[0x00F23243 : 0x00F23243 + 34] == b"FieldSet corrupted (this is a bug)"
        # : +0x230 is ctx pointer; wrap 0x1a8 interior + exclusive end.
        assert struct.unpack_from("<I", bb, 0x004DD094)[0] == 0xF9400668
        assert struct.unpack_from("<I", bb, 0x004DD09C)[0] == 0xF9001A7F
        assert struct.unpack_from("<I", bb, 0x004DD0A0)[0] == 0xB9003A77
        assert struct.unpack_from("<I", bb, 0x004DD0A8)[0] == 0x3903E27F
        assert struct.unpack_from("<I", bb, 0x004DD0AC)[0] == 0xF9002268
        assert struct.unpack_from("<I", bb, 0x004DDC34)[0] == 0x3904E27F
        assert struct.unpack_from("<I", bb, 0x004DF6A8)[0] == 0x3903827F
        assert struct.unpack_from("<I", bb, 0x007F77E4)[0] == 0xB0007082
        assert struct.unpack_from("<I", bb, 0x007F77E8)[0] == 0x91078042
        assert struct.unpack_from("<I", bb, 0x007F77F8)[0] == 0x97FFBA93
        assert struct.unpack_from("<I", bb, 0x007F796C)[0] == 0xF9008AE8
        assert struct.unpack_from("<I", bb, 0x007F7958)[0] == 0x910462E9
        assert struct.unpack_from("<I", bb, 0x007F797C)[0] == 0x9105A2E9
        assert struct.unpack_from("<I", bb, 0x007F7980)[0] == 0xF900D6E8
        assert struct.unpack_from("<I", bb, 0x0080D4B8)[0] == 0x52994008
        assert struct.unpack_from("<I", bb, 0x0080D4C0)[0] == 0x72A77348
        assert struct.unpack_from("<I", bb, 0x015F81F0)[0] == 109
        assert struct.unpack_from("<I", bb, 0x015F81F4)[0] == 32
        assert (
            bb[0x00FA47C5 : 0x00FA47C5 + 42]
            == b"open/bosminer/bosminer-hal/src/registry.rs"
        )
        # : HashChain+0x230 init usize 0x10; wrap SIMD +0x118/+0x168.
        assert struct.unpack_from("<I", bb, 0x00436BEC)[0] == 0x52800208
        assert struct.unpack_from("<I", bb, 0x00436BF8)[0] == 0xF9011948
        assert struct.unpack_from("<I", bb, 0x00436BFC)[0] == 0x529C2008
        assert struct.unpack_from("<I", bb, 0x00436C04)[0] == 0x72A0BEA8
        assert struct.unpack_from("<I", bb, 0x00436C0C)[0] == 0xB9024148
        assert struct.unpack_from("<I", bb, 0x00436C24)[0] == 0xF9011D5F
        assert struct.unpack_from("<I", bb, 0x00436C30)[0] == 0xF9012D4A
        assert struct.unpack_from("<I", bb, 0x00436CB0)[0] == 0x912B4000
        assert struct.unpack_from("<I", bb, 0x007F7960)[0] == 0xA915D2F5
        assert struct.unpack_from("<I", bb, 0x007F7968)[0] == 0xAD4006C0
        assert struct.unpack_from("<I", bb, 0x007F7974)[0] == 0xAD000520
        assert struct.unpack_from("<I", bb, 0x007F798C)[0] == 0xAD518BE0
        assert struct.unpack_from("<I", bb, 0x007F7998)[0] == 0xAD000920
        assert struct.unpack_from("<I", bb, 0x015ABAE0)[0] == 323
        assert struct.unpack_from("<I", bb, 0x015ABAE4)[0] == 73
        assert (
            bb[0x00F1B7EA : 0x00F1B7EA + 47]
            == b"open/bosminer/bosminer-am2-s17/src/hashchain.rs"
        )
        # : Future+0 copied to +8; poll +0x230 is usize 0x10; wrap +0x188 unwritten.
        assert struct.unpack_from("<I", bb, 0x004DD020)[0] == 0xF9400269
        assert struct.unpack_from("<I", bb, 0x004DD02C)[0] == 0xF9000669
        assert struct.unpack_from("<I", bb, 0x004DCFCC)[0] == 0x3940A808
        wrap_188 = 0
        off = 0x007F7798
        end = 0x007F7A48
        while off + 4 <= end:
            w = struct.unpack_from("<I", bb, off)[0]
            rn = (w >> 5) & 0x1F
            if (w >> 22) == 0x3E4 and rn == 23:
                imm = ((w >> 10) & 0xFFF) * 8
                if 0x188 <= imm < 0x1A8:
                    wrap_188 += 1
            if (w >> 22) in (0x2A4, 0x2A6) and rn == 23:
                imm7 = (w >> 15) & 0x7F
                dest = imm7 * 8
                if dest < 0x1A8 and dest + 16 > 0x188:
                    wrap_188 += 1
            off += 4
        assert wrap_188 == 0
        # : dest+0x168 is NANOS_PER_SEC prefix of SystemTime::now object;
        # HashChain+0x230 is not Instant/Duration.
        assert struct.unpack_from("<I", bb, 0x0080D4B4)[0] == 0x941A3315
        assert struct.unpack_from("<I", bb, 0x0080D4CC)[0] == 0xB9000A68
        assert struct.unpack_from("<I", bb, 0x0080D4D0)[0] == 0xB9001A68
        assert struct.unpack_from("<I", bb, 0x0080D4C4)[0] == 0xB9003261
        assert struct.unpack_from("<I", bb, 0x0080D4D4)[0] == 0xA902027F
        assert struct.unpack_from("<I", bb, 0x0080D4BC)[0] == 0xF9001E7F
        assert struct.unpack_from("<I", bb, 0x0080D4C8)[0] == 0xB900427F
        assert struct.unpack_from("<I", bb, 0x00E9A110)[0] == 0x2A1F03E0
        assert struct.unpack_from("<I", bb, 0x00E9A118)[0] == 0x1400137D
        assert struct.unpack_from("<I", bb, 0x00E9EF30)[0] == 0x52994008
        assert struct.unpack_from("<I", bb, 0x00E9EF34)[0] == 0x72A77348
        assert struct.unpack_from("<I", bb, 0x00E9F02C)[0] == 0x5299400D
        assert struct.unpack_from("<I", bb, 0x00E9F034)[0] == 0x72A7734D
        assert struct.unpack_from("<I", bb, 0x00E9F070)[0] == 0xB9001268
        assert struct.unpack_from("<I", bb, 0x0049B720)[0] == 0x52800020
        assert struct.unpack_from("<I", bb, 0x0049B724)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00436C34)[0] == 0xF9013148
        assert struct.unpack_from("<I", bb, 0x016B9218)[0] == 201
        assert struct.unpack_from("<I", bb, 0x016B921C)[0] == 18
        assert struct.unpack_from("<I", bb, 0x016BAEB0)[0] == 137
        assert struct.unpack_from("<I", bb, 0x016BAEB4)[0] == 68
        assert struct.unpack_from("<I", bb, 0x016BAEC8)[0] == 139
        assert struct.unpack_from("<I", bb, 0x016BAECC)[0] == 58
        assert (
            bb[0x0120545E : 0x0120545E + 72]
            == b"/rustc/17067e9ac6d7ecb70e50f92c1944e545188d2359/library/core/src/time.rs"
        )
        assert (
            bb[0x01206E6E : 0x01206E6E + 36] == b"library/std/src/sys/pal/unix/time.rs"
        )
        assert bb[0x01206E5D : 0x01206E5D + 17] == b"invalid timestamp"
        # : c0d4ac is 0x48; 37 BLs = 6 FPGA + 25 UART + 6 wrap.
        assert struct.unpack_from("<I", bb, 0x004AF910)[0] == 0x910323E8
        assert struct.unpack_from("<I", bb, 0x004AF914)[0] == 0x940D76E6
        assert struct.unpack_from("<I", bb, 0x004AF938)[0] == 0x9108C3E8
        assert struct.unpack_from("<I", bb, 0x004AF90C)[0] == 0x940D76DB
        assert struct.unpack_from("<I", bb, 0x004F836C)[0] == 0x940C5450
        assert struct.unpack_from("<I", bb, 0x007F78A4)[0] == 0x9108C3E8
        assert struct.unpack_from("<I", bb, 0x007F78A8)[0] == 0x94005701
        off = 0
        c0d = 0
        fpga_n = 0
        uart_n = 0
        wrap_n = 0
        text_end = 0x1375388
        while off + 4 <= text_end:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0x25:
                dest = (off + 0x400000) + (
                    ((w & 0x3FFFFFF) - 0x4000000 if w & 0x2000000 else w & 0x3FFFFFF)
                    << 2
                )
                if dest == 0xC0D4AC:
                    va = off + 0x400000
                    c0d += 1
                    if 0x8AF000 <= va < 0x8B0000:
                        fpga_n += 1
                    elif 0x8F0000 <= va < 0x900000:
                        uart_n += 1
                    elif 0xBF0000 <= va < 0xC00000:
                        wrap_n += 1
            off += 4
        assert c0d == 37
        assert fpga_n == 6
        assert uart_n == 25
        assert wrap_n == 6
        # : 0x48 cell in FPGA FUN_008af670 / UART worker.rs:68; not Timespec.
        assert struct.unpack_from("<I", bb, 0x004AF670)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x004AF688)[0] == 0xD10E03FF
        assert struct.unpack_from("<I", bb, 0x015B8888)[0] == 68
        assert struct.unpack_from("<I", bb, 0x015B888C)[0] == 18
        assert (
            bb[0x00F23690 : 0x00F23690 + 58]
            == b"/build/source/open/bosminer/bosminer-backend/src/worker.rs"
        )
        assert b"Timespec" not in bb
        # : +0x230 owner nests command.rs:647; 0x48 is not Metrics.stop_watch.
        assert struct.unpack_from("<I", bb, 0x00436CDC)[0] == 0xB0008C20
        assert struct.unpack_from("<I", bb, 0x00436CE0)[0] == 0x91010000
        assert struct.unpack_from("<I", bb, 0x00436CE4)[0] == 0x97F073D7
        assert struct.unpack_from("<I", bb, 0x015AB050)[0] == 647
        assert struct.unpack_from("<I", bb, 0x015AB054)[0] == 21
        assert (
            bb[0x00F1B3E2 : 0x00F1B3E2 + 55]
            == b"/build/source/open/bosminer/bosminer-hal/src/command.rs"
        )
        assert struct.unpack_from("<I", bb, 0x0001EAA4)[0] == 0xB000AF21
        assert struct.unpack_from("<I", bb, 0x0001EAA8)[0] == 0x91060021
        assert struct.unpack_from("<I", bb, 0x0001EAB0)[0] == 0x942C2E2B
        assert struct.unpack_from("<I", bb, 0x015F3190)[0] == 223
        assert struct.unpack_from("<I", bb, 0x015F3194)[0] == 43
        assert (
            bb[0x00F9D7EE : 0x00F9D7EE + 41]
            == b"open/bosminer/bosminer-hal/src/metrics.rs"
        )
        assert bb[0x00F9E85B : 0x00F9E85B + 10] == b"stop_watch"
        assert bb[0x00F9E865 : 0x00F9E865 + 9] == b"perf_time"
        assert b"struct HashesTimeMean with 2 elements" in bb
        # : 0x48 is Copy; workpair.rs is wrap sibling; not WorkPair.
        assert struct.unpack_from("<I", bb, 0x007F65D0)[0] == 0xD0007084
        assert struct.unpack_from("<I", bb, 0x007F65D4)[0] == 0x91036084
        assert struct.unpack_from("<I", bb, 0x007F7568)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x007F7798)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x0080D4E0)[0] == 0x39400028
        assert struct.unpack_from("<I", bb, 0x000238A0)[0] == 0x941FA710
        assert struct.unpack_from("<I", bb, 0x015F80E8)[0] == 110
        assert struct.unpack_from("<I", bb, 0x015F80EC)[0] == 22
        assert (
            bb[0x00FA46F7 : 0x00FA46F7 + 42]
            == b"open/bosminer/bosminer-hal/src/workpair.rs"
        )
        assert b"bosminer_hal::workpair" in bb
        assert b"drop_in_place" not in bb
        assert b"_RNv" not in bb
        # : +0x230 is X0 to (+0x238).vt[+0x40]; poll ADD stores Future+0x40;
        # ticket-mask log is hashchain.rs:298 at 0x838008, after FUN_00836934 RET.
        assert struct.unpack_from("<I", bb, 0x00436BD8)[0] == 0xAA1303EA
        assert struct.unpack_from("<I", bb, 0x00436CA8)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00436E78)[0] == 0xD61F0140
        assert struct.unpack_from("<I", bb, 0x00436E8C)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00436E90)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x00436E94)[0] == 0xF9402128
        assert struct.unpack_from("<I", bb, 0x00436E98)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x004DD098)[0] == 0xF9411908
        assert struct.unpack_from("<I", bb, 0x004DD0A4)[0] == 0x91004108
        assert struct.unpack_from("<I", bb, 0x004DD0AC)[0] == 0xF9002268
        assert struct.unpack_from("<I", bb, 0x00438008)[0] == 0xF0008C02
        assert struct.unpack_from("<I", bb, 0x0043800C)[0] == 0x9113C042
        assert struct.unpack_from("<I", bb, 0x00438014)[0] == 0x97F06DA7
        assert struct.unpack_from("<I", bb, 0x015AB500)[0] == 298
        assert struct.unpack_from("<I", bb, 0x015AB504)[0] == 9
        assert b"Setting ticket mask register for difficulty" in bb
        # : +0x230/+0x238 fat pointer; memcpy 0x230 then STR pair; 7 vt slots.
        assert struct.unpack_from("<I", bb, 0x00435308)[0] == 0xD63F02E0
        assert struct.unpack_from("<I", bb, 0x0043530C)[0] == 0xAA0003F8
        assert struct.unpack_from("<I", bb, 0x00435310)[0] == 0xAA0103F7
        assert struct.unpack_from("<I", bb, 0x00435320)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x00435324)[0] == 0x940E4F2F
        assert struct.unpack_from("<I", bb, 0x0043532C)[0] == 0xF9011A98
        assert struct.unpack_from("<I", bb, 0x00435330)[0] == 0xF9011E97
        assert struct.unpack_from("<I", bb, 0x007C8FE0)[0] == 0x8B020024
        assert struct.unpack_from("<I", bb, 0x00437668)[0] == 0xF9401D28
        assert struct.unpack_from("<I", bb, 0x004376FC)[0] == 0xF9402929
        assert struct.unpack_from("<I", bb, 0x00437BC8)[0] == 0xF9401928
        assert struct.unpack_from("<I", bb, 0x00437DD8)[0] == 0xF9403D28
        assert struct.unpack_from("<I", bb, 0x0043862C)[0] == 0xF9402528
        assert struct.unpack_from("<I", bb, 0x004389F8)[0] == 0xF9401528
        assert struct.unpack_from("<I", bb, 0x00434ED4)[0] == 0xD0008C21
        assert struct.unpack_from("<I", bb, 0x00434ED8)[0] == 0x913FA021
        assert struct.unpack_from("<I", bb, 0x015AAFF8)[0] == 472
        assert struct.unpack_from("<I", bb, 0x015AAFFC)[0] == 36
        assert struct.unpack_from("<I", bb, 0x004DC5A4)[0] == 0xF9011E6A
        assert (
            bb[0x00F03F89 : 0x00F03F89 + 55]
            == b"/build/source/open/bosminer/bosminer-hal/src/command.rs"
        )
        # : 6 STP pair + 1 sret; cmd.rs:119 is divider; Hashchip label.
        assert struct.unpack_from("<I", bb, 0x00437BBC)[0] == 0xF9400A61
        assert struct.unpack_from("<I", bb, 0x00437700)[0] == 0x910583E8
        assert struct.unpack_from("<I", bb, 0x00438A00)[0] == 0xA9028660
        assert struct.unpack_from("<I", bb, 0x00436E9C)[0] == 0xA9028660
        assert struct.unpack_from("<I", bb, 0x00438634)[0] == 0xA9040660
        assert struct.unpack_from("<I", bb, 0x00438A10)[0] == 0x90008C22
        assert struct.unpack_from("<I", bb, 0x00438A14)[0] == 0x9131A042
        assert struct.unpack_from("<I", bb, 0x00437E04)[0] == 0x90008C20
        assert struct.unpack_from("<I", bb, 0x00437E08)[0] == 0x912C2000
        assert struct.unpack_from("<I", bb, 0x007F320C)[0] == 0x900070A4
        assert struct.unpack_from("<I", bb, 0x007F3210)[0] == 0x91238084
        assert struct.unpack_from("<I", bb, 0x007F3264)[0] == 0xF9400008
        assert struct.unpack_from("<I", bb, 0x015F78F0)[0] == 119
        assert struct.unpack_from("<I", bb, 0x015F78F4)[0] == 22
        assert struct.unpack_from("<I", bb, 0x015ABB18)[0] == 336
        assert struct.unpack_from("<I", bb, 0x015ABB1C)[0] == 84
        assert struct.unpack_from("<Q", bb, 0x0158FEB0)[0] == 0x1303FC0
        assert bb[0x00F03FC0 : 0x00F03FC0 + 8] == b"Hashchip"
        assert bb[0x00F03FDA : 0x00F03FDA + 13] == b"read_register"
        assert b"bosminer_hal::command" in bb
        # : 6 pairs polled via [X1,#0x18]; 0 command.rs:700 BLs in jump table.
        assert struct.unpack_from("<I", bb, 0x00436F64)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00436F6C)[0] == 0x910583E8
        assert struct.unpack_from("<I", bb, 0x00436F70)[0] == 0xAA1503E1
        assert struct.unpack_from("<I", bb, 0x00436F74)[0] == 0xD63F0120
        assert struct.unpack_from("<I", bb, 0x00436FE4)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00436FE8)[0] == 0x910583E8
        assert struct.unpack_from("<I", bb, 0x00437054)[0] == 0xF9401660
        assert struct.unpack_from("<I", bb, 0x00437058)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x0043757C)[0] == 0xF9402E60
        assert struct.unpack_from("<I", bb, 0x00437580)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00437674)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00438638)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00438A04)[0] == 0x17FFF957
        assert struct.unpack_from("<I", bb, 0x00436EA0)[0] == 0x14000051
        assert struct.unpack_from("<I", bb, 0x004DD0B8)[0] == 0x97FFE5E5
        # : Poll sret word0==9 is Pending; Ready T at +0x168/+0x170.
        assert struct.unpack_from("<I", bb, 0x00436F78)[0] == 0xF940B3FB
        assert struct.unpack_from("<I", bb, 0x00436F7C)[0] == 0xF100277F
        assert struct.unpack_from("<I", bb, 0x00436FF4)[0] == 0xF940B3FB
        assert struct.unpack_from("<I", bb, 0x00436FF8)[0] == 0xF100277F
        assert struct.unpack_from("<I", bb, 0x00437068)[0] == 0xF940B3FB
        assert struct.unpack_from("<I", bb, 0x0043706C)[0] == 0xF100277F
        assert struct.unpack_from("<I", bb, 0x00437590)[0] == 0xF940B3F8
        assert struct.unpack_from("<I", bb, 0x00437594)[0] == 0xF100271F
        assert struct.unpack_from("<I", bb, 0x00437684)[0] == 0xF940B3F8
        assert struct.unpack_from("<I", bb, 0x00437688)[0] == 0xF100271F
        assert struct.unpack_from("<I", bb, 0x00438648)[0] == 0xF940B3FB
        assert struct.unpack_from("<I", bb, 0x0043864C)[0] == 0xF100277F
        assert struct.unpack_from("<I", bb, 0x00437108)[0] == 0xF940B7F9
        assert struct.unpack_from("<I", bb, 0x0043710C)[0] == 0x3DC05FE0
        assert struct.unpack_from("<I", bb, 0x00436F84)[0] == 0x52800128
        # : tag 8 Ready-continue; tag 9 Pending writes *X28 and RETs.
        assert struct.unpack_from("<I", bb, 0x00436F88)[0] == 0xF9000388
        assert struct.unpack_from("<I", bb, 0x00436F8C)[0] == 0x52800108
        assert struct.unpack_from("<I", bb, 0x00436F90)[0] == 0x14000716
        assert struct.unpack_from("<I", bb, 0x00438BE8)[0] == 0x39008668
        assert struct.unpack_from("<I", bb, 0x00438BEC)[0] == 0x910D03FF
        assert struct.unpack_from("<I", bb, 0x00438C08)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x004370B8)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x00437138)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x0043713C)[0] == 0x5400C661
        assert struct.unpack_from("<I", bb, 0x004371B0)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x00437600)[0] == 0xF100231F
        assert struct.unpack_from("<I", bb, 0x004376DC)[0] == 0xF100231F
        assert struct.unpack_from("<I", bb, 0x004386A8)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x004389E4)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x00438A08)[0] == 0x3DC00FE0
        assert struct.unpack_from("<I", bb, 0x00438A0C)[0] == 0x140000B3
        assert struct.unpack_from("<I", bb, 0x00438CD8)[0] == 0xA900679B
        assert struct.unpack_from("<I", bb, 0x00438CDC)[0] == 0x52800028
        assert struct.unpack_from("<I", bb, 0x00438CE0)[0] == 0x3D800780
        assert struct.unpack_from("<I", bb, 0x00438CE4)[0] == 0x17FFFFC1
        assert b"rust-1.87.0" in bb
        # : 7th CMP #8 is slot-+0x28 prelude after MOVZ W27,#8.
        assert struct.unpack_from("<I", bb, 0x004389D0)[0] == 0x5280011B
        assert struct.unpack_from("<I", bb, 0x004389E0)[0] == 0x97FFE24D
        assert struct.unpack_from("<I", bb, 0x004389E4)[0] == 0xF100237F
        assert struct.unpack_from("<I", bb, 0x004389F8)[0] == 0xF9401528
        # : FUN_00831314 is a +0x10-tag drop dispatcher; 2 X22 BLs.
        assert struct.unpack_from("<I", bb, 0x00431314)[0] == 0xF81E0FFE
        assert struct.unpack_from("<I", bb, 0x00431318)[0] == 0xA9014FF4
        assert struct.unpack_from("<I", bb, 0x0043131C)[0] == 0x39404008
        assert struct.unpack_from("<I", bb, 0x00431320)[0] == 0x7100111F
        assert struct.unpack_from("<I", bb, 0x00431328)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x0043135C)[0] == 0x91010000
        assert struct.unpack_from("<I", bb, 0x00431364)[0] == 0x1400026D
        assert struct.unpack_from("<I", bb, 0x004313A0)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x004313A8)[0] == 0x91006000
        assert struct.unpack_from("<I", bb, 0x00438B8C)[0] == 0xAA1603E0
        assert struct.unpack_from("<I", bb, 0x00438B90)[0] == 0x97FFE1E1
        # : 831d18 / 831668 isomorphic drop siblings; shared 0x11f2764.
        assert struct.unpack_from("<I", bb, 0x00431D18)[0] == 0xA9BE57FE
        assert struct.unpack_from("<I", bb, 0x00431D20)[0] == 0x39406408
        assert struct.unpack_from("<I", bb, 0x00431D28)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x00431D30)[0] == 0x7100111F
        assert struct.unpack_from("<I", bb, 0x00431D38)[0] == 0xA9425275
        assert struct.unpack_from("<I", bb, 0x00431D60)[0] == 0xF9400260
        assert struct.unpack_from("<I", bb, 0x00431D64)[0] == 0x52800021
        assert struct.unpack_from("<I", bb, 0x00431D68)[0] == 0x9427027F
        assert struct.unpack_from("<I", bb, 0x00431668)[0] == 0xA9BE57FE
        assert struct.unpack_from("<I", bb, 0x00431670)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x00431678)[0] == 0x71000D1F
        assert struct.unpack_from("<I", bb, 0x00431680)[0] == 0x7100111F
        assert struct.unpack_from("<I", bb, 0x00431688)[0] == 0xA947D275
        assert struct.unpack_from("<I", bb, 0x004316B0)[0] == 0xF9403660
        assert struct.unpack_from("<I", bb, 0x004316B4)[0] == 0x52800021
        assert struct.unpack_from("<I", bb, 0x004316B8)[0] == 0x9427042B
        assert struct.unpack_from("<I", bb, 0x004386FC)[0] == 0x9101A260
        assert struct.unpack_from("<I", bb, 0x004389C8)[0] == 0x9101A260
        assert struct.unpack_from("<I", bb, 0x00DF2764)[0] == 0xB4000241
        # : 11f2764 refcount helper; JT +0x68 from +0x240+0x10.
        assert struct.unpack_from("<I", bb, 0x00DF2770)[0] == 0x085FFC08
        assert struct.unpack_from("<I", bb, 0x00DF277C)[0] == 0x350001A8
        assert struct.unpack_from("<I", bb, 0x00DF2780)[0] == 0x52800028
        assert struct.unpack_from("<I", bb, 0x00DF2784)[0] == 0x08097E68
        assert struct.unpack_from("<I", bb, 0x00DF27AC)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00DF27B4)[0] == 0x52994002
        assert struct.unpack_from("<I", bb, 0x00DF27BC)[0] == 0x72A77342
        assert struct.unpack_from("<I", bb, 0x00DF27C0)[0] == 0x97C96F38
        assert struct.unpack_from("<I", bb, 0x004385F4)[0] == 0xF9412108
        assert struct.unpack_from("<I", bb, 0x00438600)[0] == 0x91004100
        assert struct.unpack_from("<I", bb, 0x00438604)[0] == 0xF9003660
        assert struct.unpack_from("<I", bb, 0x004386F0)[0] == 0x39442268
        assert b"reference count overflow!" in bb
        # : 121e588 is parking_lot TLS get (TPIDR+0x280), not Arc.
        assert struct.unpack_from("<I", bb, 0x00E1E588)[0] == 0xD103C3FF
        assert struct.unpack_from("<I", bb, 0x00E1E594)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00E1E59C)[0] == 0xD2A00000
        assert struct.unpack_from("<I", bb, 0x00E1E5A0)[0] == 0xF2805000
        assert struct.unpack_from("<I", bb, 0x00E1E5AC)[0] == 0xD53BD048
        assert struct.unpack_from("<I", bb, 0x00E1E5B0)[0] == 0x8B000114
        assert struct.unpack_from("<I", bb, 0x00E1E5B4)[0] == 0xF8408689
        assert struct.unpack_from("<I", bb, 0x00E1E5B8)[0] == 0xF100053F
        assert struct.unpack_from("<I", bb, 0x00E1E5C0)[0] == 0xF100093F
        assert struct.unpack_from("<I", bb, 0x00E1E610)[0] == 0xD0004521
        assert struct.unpack_from("<I", bb, 0x00E1E614)[0] == 0x9131C021
        assert struct.unpack_from("<I", bb, 0x00E1E688)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00DF2790)[0] == 0x9400AF7E
        assert struct.unpack_from("<I", bb, 0x016B4C80)[0] == 1226
        assert struct.unpack_from("<I", bb, 0x016B4C84)[0] == 58
        assert b"parking_lot_core-0.9.10/src/parking_lot.rs" in bb
        # : unique fat-slot +0x28 BLR; X0 from +0x230; STP pair; join poll.
        assert struct.unpack_from("<I", bb, 0x004389EC)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x004389F0)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x004389F4)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x004389F8)[0] == 0xF9401528
        assert struct.unpack_from("<I", bb, 0x004389FC)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00438A00)[0] == 0xA9028660
        assert struct.unpack_from("<I", bb, 0x00438A04)[0] == 0x17FFF957
        assert struct.unpack_from("<I", bb, 0x00436F60)[0] == 0xAA1303E8
        assert struct.unpack_from("<I", bb, 0x00436F64)[0] == 0xF9400C29
        # : unique fat-slot +0x30 BLR; X1 from Future+0x10; STP pair; join 0x837054.
        assert struct.unpack_from("<I", bb, 0x00437BB8)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x00437BBC)[0] == 0xF9400A61
        assert struct.unpack_from("<I", bb, 0x00437BC0)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00437BC4)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x00437BC8)[0] == 0xF9401928
        assert struct.unpack_from("<I", bb, 0x00437BCC)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00437BD0)[0] == 0xA9028660
        assert struct.unpack_from("<I", bb, 0x00437BD4)[0] == 0x17FFFD20
        assert struct.unpack_from("<I", bb, 0x00437054)[0] == 0xF9401660
        assert struct.unpack_from("<I", bb, 0x00437058)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00439D9C)[0] == 0xF9401AC8
        assert b"send_work" not in bb
        assert b"set_baud" not in bb
        assert b"write_register" not in bb
        # : slot+0x30 X1 is poll-self frame+0x10, not cmd700 Future+0x10.
        assert struct.unpack_from("<I", bb, 0x00436E70)[0] == 0xAA0103F5
        assert struct.unpack_from("<I", bb, 0x00436E74)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00436E78)[0] == 0xD61F0140
        assert struct.unpack_from("<I", bb, 0x004371B8)[0] == 0xF9400A79
        assert struct.unpack_from("<I", bb, 0x004371BC)[0] == 0x140006C7
        assert struct.unpack_from("<I", bb, 0x00438CD8)[0] == 0xA900679B
        assert struct.unpack_from("<I", bb, 0x00436B94)[0] == 0xA9016289
        assert struct.unpack_from("<I", bb, 0x00436CA8)[0] == 0xD65F03C0
        # : unique fat-slot +0x38 BLR; 0 extra X1; STP +0x58; immediate poll.
        assert struct.unpack_from("<I", bb, 0x00437638)[0] == 0xF9400829
        assert struct.unpack_from("<I", bb, 0x0043763C)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x00437660)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00437664)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x00437668)[0] == 0xF9401D28
        assert struct.unpack_from("<I", bb, 0x0043766C)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00437670)[0] == 0xA9058660
        assert struct.unpack_from("<I", bb, 0x00437674)[0] == 0xF9400C29
        # : unique fat-slot +0x40; copy +0x18→+0; STP +0x28; join 0x836fe4.
        assert struct.unpack_from("<I", bb, 0x00436E7C)[0] == 0xF9400E68
        assert struct.unpack_from("<I", bb, 0x00436E84)[0] == 0xF9000268
        assert struct.unpack_from("<I", bb, 0x00436E8C)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00436E90)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x00436E94)[0] == 0xF9402128
        assert struct.unpack_from("<I", bb, 0x00436E98)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00436E9C)[0] == 0xA9028660
        assert struct.unpack_from("<I", bb, 0x00436EA0)[0] == 0x14000051
        assert struct.unpack_from("<I", bb, 0x00436FE4)[0] == 0xF9400C29
        # : +0x48 immediate poll; +0x78 LDP Family-B; Future+0x18 fat host.
        assert struct.unpack_from("<I", bb, 0x0043860C)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x0043861C)[0] == 0xF9001668
        assert struct.unpack_from("<I", bb, 0x00438620)[0] == 0xF9001A68
        assert struct.unpack_from("<I", bb, 0x00438624)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00438628)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x0043862C)[0] == 0xF9402528
        assert struct.unpack_from("<I", bb, 0x00438630)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00438634)[0] == 0xA9040660
        assert struct.unpack_from("<I", bb, 0x00438638)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x00437DCC)[0] == 0xA9430668
        assert struct.unpack_from("<I", bb, 0x00437DD0)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x00437DD4)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x00437DD8)[0] == 0xF9403D28
        assert struct.unpack_from("<I", bb, 0x00437DDC)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00437DE0)[0] == 0xA9058660
        assert struct.unpack_from("<I", bb, 0x00437DE8)[0] == 0x17FFFDE5
        assert struct.unpack_from("<I", bb, 0x0043757C)[0] == 0xF9402E60
        assert struct.unpack_from("<I", bb, 0x00437580)[0] == 0xF9400C29
        assert struct.unpack_from("<I", bb, 0x004369B4)[0] == 0xF9400E68
        # : 0x188 Future clone from SP+#8; vtable 0x19bbae8; poll 0x836e2c.
        assert struct.unpack_from("<I", bb, 0x00436DA4)[0] == 0xD106C3FF
        assert struct.unpack_from("<I", bb, 0x00436DC0)[0] == 0x52803100
        assert struct.unpack_from("<I", bb, 0x00436DD8)[0] == 0x910023E1
        assert struct.unpack_from("<I", bb, 0x00436DDC)[0] == 0x52803102
        assert struct.unpack_from("<I", bb, 0x00436DE4)[0] == 0x940E487F
        assert struct.unpack_from("<I", bb, 0x00436DF8)[0] == 0x912BA021
        assert struct.unpack_from("<Q", bb, 0x015ABAE8)[0] == 0x831814
        assert struct.unpack_from("<Q", bb, 0x015ABAF0)[0] == 0x188
        assert struct.unpack_from("<Q", bb, 0x015ABAF8)[0] == 8
        assert struct.unpack_from("<Q", bb, 0x015ABB00)[0] == 0x836E2C
        # : clone fills SP+#8 itself; X0 at +0x20 = Future+0x18; 0x260 owner vtable.
        assert struct.unpack_from("<I", bb, 0x00436DBC)[0] == 0xF90013E0
        assert struct.unpack_from("<I", bb, 0x00436DB0)[0] == 0x3900A7FF
        assert struct.unpack_from("<I", bb, 0x00436DC4)[0] == 0x3900ABE1
        assert struct.unpack_from("<Q", bb, 0x015B17A0)[0] == 0x260
        assert struct.unpack_from("<Q", bb, 0x015B17A8)[0] == 0x10
        assert struct.unpack_from("<Q", bb, 0x015B17B0)[0] == 0x836DA4
        assert struct.unpack_from("<I", bb, 0x0045A02C)[0] == 0xF90007E0
        assert struct.unpack_from("<I", bb, 0x0045A064)[0] == 0x9106A021
        # : +0x50 sret host frame+0x30 / X1 +0x38; owner drop 0x873d10 + boxer.
        assert struct.unpack_from("<I", bb, 0x004376E8)[0] == 0xAA1303FC
        assert struct.unpack_from("<I", bb, 0x004376EC)[0] == 0xF8438F81
        assert struct.unpack_from("<I", bb, 0x004376F0)[0] == 0xF85F8388
        assert struct.unpack_from("<I", bb, 0x004376F4)[0] == 0xF9411D09
        assert struct.unpack_from("<I", bb, 0x004376F8)[0] == 0xF9411900
        assert struct.unpack_from("<I", bb, 0x004376FC)[0] == 0xF9402929
        assert struct.unpack_from("<I", bb, 0x00437700)[0] == 0x910583E8
        assert struct.unpack_from("<I", bb, 0x00437704)[0] == 0xD63F0120
        assert struct.unpack_from("<I", bb, 0x00437708)[0] == 0xA95653EA
        assert struct.unpack_from("<I", bb, 0x00437718)[0] == 0xEB09015F
        assert struct.unpack_from("<I", bb, 0x00437688)[0] == 0xF100271F
        assert struct.unpack_from("<I", bb, 0x00437740)[0] == 0x97EF52E1
        assert struct.unpack_from("<Q", bb, 0x015B1798)[0] == 0x873D10
        assert struct.unpack_from("<I", bb, 0x00473D18)[0] == 0xF9412008
        assert struct.unpack_from("<I", bb, 0x00473D40)[0] == 0xF9411E74
        assert struct.unpack_from("<I", bb, 0x00473D44)[0] == 0xF9411A75
        assert struct.unpack_from("<I", bb, 0x0047E394)[0] == 0x52804C00
        assert struct.unpack_from("<I", bb, 0x0047E398)[0] == 0x52800201
        assert struct.unpack_from("<I", bb, 0x0047E3C4)[0] == 0xF0008A08
        assert struct.unpack_from("<I", bb, 0x0047E3C8)[0] == 0x911E6108
        assert struct.unpack_from("<I", bb, 0x0047E3D0)[0] == 0xA9012296
        # : FUN_0040c2c4 has 4 BLs; 3 JT pass SP+#0x160; 4th SP+#0x30.
        assert struct.unpack_from("<I", bb, 0x0043773C)[0] == 0x910583E0
        assert struct.unpack_from("<I", bb, 0x00437740)[0] == 0x97EF52E1
        assert struct.unpack_from("<I", bb, 0x00437764)[0] == 0x910583E0
        assert struct.unpack_from("<I", bb, 0x00437768)[0] == 0x97EF52D7
        assert struct.unpack_from("<I", bb, 0x004378B0)[0] == 0x910583E0
        assert struct.unpack_from("<I", bb, 0x004378B4)[0] == 0x97EF5284
        assert struct.unpack_from("<I", bb, 0x0043A768)[0] == 0x9100C3E0
        assert struct.unpack_from("<I", bb, 0x0043A770)[0] == 0x97EF46D5
        assert bb[0x01205ECF : 0x01205ECF + 18] == b"RUST_LIB_BACKTRACE"
        # : Future+0x10 first writer is poll copy of +0x48 via X12=X19.
        assert struct.unpack_from("<I", bb, 0x004372E0)[0] == 0xF9402668
        assert struct.unpack_from("<I", bb, 0x004372F0)[0] == 0xAA1303EC
        assert struct.unpack_from("<I", bb, 0x00437300)[0] == 0xF9000988
        assert struct.unpack_from("<I", bb, 0x00437238)[0] == 0x91012260
        assert struct.unpack_from("<I", bb, 0x0043723C)[0] == 0xAA1503E1
        assert struct.unpack_from("<I", bb, 0x00437240)[0] == 0x97FFF73D
        assert struct.unpack_from("<I", bb, 0x00437178)[0] == 0x1400005C
        assert struct.unpack_from("<I", bb, 0x00436DB0)[0] == 0x3900A7FF
        assert struct.unpack_from("<I", bb, 0x00434F34)[0] == 0xD10183FF
        # : Future+0x48 is tokio-1.45.1 Mutex::lock future; poll 0x834f34.
        assert struct.unpack_from("<I", bb, 0x00434F48)[0] == 0x3941C008
        assert struct.unpack_from("<I", bb, 0x0043502C)[0] == 0x3901C268
        assert struct.unpack_from("<I", bb, 0x0043507C)[0] == 0xD0008C20
        assert struct.unpack_from("<I", bb, 0x00435080)[0] == 0x910BC000
        assert struct.unpack_from("<I", bb, 0x00435084)[0] == 0x97F07AEF
        assert struct.unpack_from("<I", bb, 0x004370FC)[0] == 0xF9002668
        assert struct.unpack_from("<I", bb, 0x004370D4)[0] == 0xF9412108
        assert struct.unpack_from("<I", bb, 0x004370E4)[0] == 0x91004108
        assert struct.unpack_from("<I", bb, 0x004370F0)[0] == 0x91006108
        assert struct.unpack_from("<Q", bb, 0x015AB2F0)[0] == 0x131B62A
        assert struct.unpack_from("<Q", bb, 0x015AB2F8)[0] == 157
        assert struct.unpack_from("<I", bb, 0x015AB300)[0] == 434
        assert struct.unpack_from("<I", bb, 0x015AB304)[0] == 51
        assert bb[0x00F1B62A : 0x00F1B62A + 157].endswith(
            b"tokio-1.45.1/src/sync/mutex.rs"
        )
        assert (
            bb[0x00F1B6C7 : 0x00F1B6C7 + 40]
            == b"internal error: entered unreachable code"
        )
        # : fat-host +0x240 is 0x70-ptr; Mutex at +0x28; not HashChain 1e8.
        assert struct.unpack_from("<I", bb, 0x004370C0)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x004370C8)[0] == 0xF940A509
        assert struct.unpack_from("<I", bb, 0x004370CC)[0] == 0xF9000669
        assert struct.unpack_from("<I", bb, 0x004370D4)[0] == 0xF9412108
        assert struct.unpack_from("<I", bb, 0x004370E4)[0] == 0x91004108
        assert struct.unpack_from("<I", bb, 0x004370F0)[0] == 0x91006108
        assert struct.unpack_from("<I", bb, 0x004370FC)[0] == 0xF9002668
        assert struct.unpack_from("<I", bb, 0x00436C0C)[0] == 0xB9024148
        assert struct.unpack_from("<I", bb, 0x00473D18)[0] == 0xF9412008
        assert struct.unpack_from("<I", bb, 0x00473D20)[0] == 0xC85F7D09
        assert struct.unpack_from("<I", bb, 0x00473D38)[0] == 0x91090260
        assert struct.unpack_from("<I", bb, 0x00473D3C)[0] == 0x940B3811
        assert struct.unpack_from("<I", bb, 0x008EC010)[0] == 0x52800E01
        assert struct.unpack_from("<I", bb, 0x008EC094)[0] == 0xF901227F
        # : +0x10 common projection; alt Future+0x48; +0x248 sibling drop.
        assert struct.unpack_from("<I", bb, 0x00437160)[0] == 0xF9412108
        assert struct.unpack_from("<I", bb, 0x0043716C)[0] == 0x91004108
        assert struct.unpack_from("<I", bb, 0x00437174)[0] == 0xF9002668
        assert struct.unpack_from("<I", bb, 0x00437178)[0] == 0x1400005C
        assert struct.unpack_from("<I", bb, 0x00438600)[0] == 0x91004100
        assert struct.unpack_from("<I", bb, 0x00438604)[0] == 0xF9003660
        assert struct.unpack_from("<I", bb, 0x00438C2C)[0] == 0x91004128
        assert struct.unpack_from("<I", bb, 0x00473DA8)[0] == 0x91092260
        assert struct.unpack_from("<I", bb, 0x00473DB4)[0] == 0x1402C21E
        assert struct.unpack_from("<I", bb, 0x00524634)[0] == 0xF9400013
        assert struct.unpack_from("<I", bb, 0x00524638)[0] == 0x91004260
        assert struct.unpack_from("<I", bb, 0x0052463C)[0] == 0x9400005D
        assert struct.unpack_from("<I", bb, 0x00524660)[0] == 0x91002268
        assert struct.unpack_from("<I", bb, 0x00524664)[0] == 0xC85F7D09
        # : FUN_009247b0 counted fat-ptr drop; 4 BLs; 3 ADD #0x10.
        assert struct.unpack_from("<I", bb, 0x005247B0)[0] == 0xF81D0FFE
        assert struct.unpack_from("<I", bb, 0x005247BC)[0] == 0xF9400815
        assert struct.unpack_from("<I", bb, 0x005247C4)[0] == 0xF9400408
        assert struct.unpack_from("<I", bb, 0x005247C8)[0] == 0x91006116
        assert struct.unpack_from("<I", bb, 0x005247D0)[0] == 0xF10006B5
        assert struct.unpack_from("<I", bb, 0x005247D4)[0] == 0x910042D6
        assert struct.unpack_from("<I", bb, 0x005247DC)[0] == 0xA97ECED4
        assert struct.unpack_from("<I", bb, 0x005247EC)[0] == 0xD63F0100
        assert struct.unpack_from("<I", bb, 0x00524800)[0] == 0x97F3409F
        assert struct.unpack_from("<I", bb, 0x00524814)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00524320)[0] == 0x94000124
        assert struct.unpack_from("<I", bb, 0x0052456C)[0] == 0x91004000
        assert struct.unpack_from("<I", bb, 0x00524570)[0] == 0x94000090
        assert struct.unpack_from("<I", bb, 0x00524638)[0] == 0x91004260
        assert struct.unpack_from("<I", bb, 0x0052463C)[0] == 0x9400005D
        assert struct.unpack_from("<I", bb, 0x00526030)[0] == 0x91004000
        assert struct.unpack_from("<I", bb, 0x00526034)[0] == 0x97FFF9DF
        # : *248 inner is 0x30; 81 BLs to 0x92462c; JT SP+#0x270.
        assert struct.unpack_from("<I", bb, 0x00524680)[0] == 0x52800601
        assert struct.unpack_from("<I", bb, 0x00524688)[0] == 0x52800102
        assert struct.unpack_from("<I", bb, 0x00524640)[0] == 0xF8410268
        assert struct.unpack_from("<I", bb, 0x00524648)[0] == 0xF9400E60
        assert struct.unpack_from("<I", bb, 0x0052462C)[0] == 0xF81E0FFE
        assert struct.unpack_from("<I", bb, 0x004365D4)[0] == 0x9109C3E0
        assert struct.unpack_from("<I", bb, 0x004365D8)[0] == 0x9403B815
        # : lock() &self is stored ptr (Mutex at data+0x18); *248 T is 0x20.
        assert struct.unpack_from("<I", bb, 0x00434F5C)[0] == 0xF9400268
        assert struct.unpack_from("<I", bb, 0x00434FA8)[0] == 0xF9000E68
        assert struct.unpack_from("<I", bb, 0x00434FD0)[0] == 0x9100A260
        assert struct.unpack_from("<I", bb, 0x00434FD4)[0] == 0x9426F784
        assert struct.unpack_from("<I", bb, 0x00434FF8)[0] == 0x9100A260
        assert struct.unpack_from("<I", bb, 0x00DF2DE4)[0] == 0xD102C3FF
        # : 0x586cd8 stride-0x18 index; Box-shaped 0x9247b0 elems.
        assert struct.unpack_from("<I", bb, 0x00186CD8)[0] == 0xD10143FF
        assert struct.unpack_from("<I", bb, 0x00186D68)[0] == 0xF9400E69
        assert struct.unpack_from("<I", bb, 0x00186D74)[0] == 0x52800309
        assert struct.unpack_from("<I", bb, 0x00186D78)[0] == 0xF9400A6A
        assert struct.unpack_from("<I", bb, 0x00186D7C)[0] == 0x9B092908
        assert struct.unpack_from("<I", bb, 0x00186DA8)[0] == 0xF9401676
        assert struct.unpack_from("<I", bb, 0x00186DC0)[0] == 0xF9401268
        assert struct.unpack_from("<I", bb, 0x005247F0)[0] == 0xF9400661
        assert struct.unpack_from("<I", bb, 0x00524800)[0] == 0x97F3409F
        # : FUN_011f2de4 is Acquire::poll; coop TLS+0x40; pads 425/493.
        assert struct.unpack_from("<I", bb, 0x00DF2DE4)[0] == 0xD102C3FF
        assert struct.unpack_from("<I", bb, 0x00DF2E0C)[0] == 0xAA0103F5
        assert struct.unpack_from("<I", bb, 0x00DF2E10)[0] == 0xD2A00000
        assert struct.unpack_from("<I", bb, 0x00DF2E14)[0] == 0xF2800800
        assert struct.unpack_from("<I", bb, 0x00DF2E20)[0] == 0xD53BD058
        assert struct.unpack_from("<I", bb, 0x00DF3024)[0] == 0x91184021
        assert struct.unpack_from("<I", bb, 0x00DF332C)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x00DF333C)[0] == 0x91166042
        assert struct.unpack_from("<I", bb, 0x00DF335C)[0] == 0x9116C084
        assert struct.unpack_from("<I", bb, 0x016B2598 + 16)[0] == 425
        assert struct.unpack_from("<I", bb, 0x016B2598 + 20)[0] == 18
        assert struct.unpack_from("<I", bb, 0x016B25B0 + 16)[0] == 493
        assert struct.unpack_from("<I", bb, 0x016B25B0 + 20)[0] == 9
        assert struct.unpack_from("<I", bb, 0x016B3610 + 16)[0] == 345
        assert struct.unpack_from("<I", bb, 0x016B3610 + 20)[0] == 13
        assert bb[0x011F39EE : 0x011F39EE + 167].endswith(b"batch_semaphore.rs")
        assert bb[0x011F5989 : 0x011F5989 + 160].endswith(b"task/coop/mod.rs")
        # : HashChain clone unique STR X25,[X20,#0x240]; X1 via SP+#8.
        assert struct.unpack_from("<I", bb, 0x00435234)[0] == 0xD10903FF
        assert struct.unpack_from("<I", bb, 0x0043524C)[0] == 0xF90007E1
        assert struct.unpack_from("<I", bb, 0x004352E8)[0] == 0xC85F7D09
        assert struct.unpack_from("<I", bb, 0x00435314)[0] == 0xF94007F9
        assert struct.unpack_from("<I", bb, 0x00435320)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x00435324)[0] == 0x940E4F2F
        assert struct.unpack_from("<I", bb, 0x0043532C)[0] == 0xF9011A98
        assert struct.unpack_from("<I", bb, 0x00435330)[0] == 0xF9011E97
        assert struct.unpack_from("<I", bb, 0x00435334)[0] == 0xF9012299
        assert struct.unpack_from("<I", bb, 0x00435338)[0] == 0xF9012688
        assert struct.unpack_from("<I", bb, 0x0011A8C8)[0] == 0xF9012260
        assert struct.unpack_from("<I", bb, 0x008EC094)[0] == 0xF901227F
        # : real clone entry 0x835220; unique BL 0x87e1cc; 0x228/index refuses.
        assert struct.unpack_from("<I", bb, 0x00435220)[0] == 0xF81B0FFD
        assert struct.unpack_from("<I", bb, 0x00435224)[0] == 0xA90167FE
        assert struct.unpack_from("<I", bb, 0x00435230)[0] == 0xA9044FF4
        assert struct.unpack_from("<I", bb, 0x0047E1C4)[0] == 0xAA1703E0
        assert struct.unpack_from("<I", bb, 0x0047E1C8)[0] == 0xAA1803E1
        assert struct.unpack_from("<I", bb, 0x0047E1CC)[0] == 0x97FEDC15
        assert struct.unpack_from("<I", bb, 0x0047E02C)[0] == 0xA9BC7BFD
        assert struct.unpack_from("<I", bb, 0x0020B0FC)[0] == 0xD10143FF
        assert struct.unpack_from("<I", bb, 0x0020B198)[0] == 0x52800309
        assert struct.unpack_from("<I", bb, 0x00281768)[0] == 0xD10143FF
        assert struct.unpack_from("<I", bb, 0x00281804)[0] == 0x52800309
        assert struct.unpack_from("<I", bb, 0x001FE12C)[0] == 0xF9012260
        assert struct.unpack_from("<I", bb, 0x003B4D48)[0] == 0xF9012260
        assert struct.unpack_from("<I", bb, 0x00349BF8)[0] == 0x52804500
        assert struct.unpack_from("<I", bb, 0x00349C18)[0] == 0xAA0003F6
        assert struct.unpack_from("<I", bb, 0x00349C58)[0] == 0xF9012276
        assert struct.unpack_from("<I", bb, 0x00436C0C)[0] == 0xB9024148
        # : SP+#0x78 is sret+0x10 of BLR X23; 0x87deb4 is 0x70 boxer.
        assert struct.unpack_from("<I", bb, 0x0047E144)[0] == 0x9101A3E8
        assert struct.unpack_from("<I", bb, 0x0047E15C)[0] == 0xD63F02E0
        assert struct.unpack_from("<I", bb, 0x0047E160)[0] == 0xA946D7F3
        assert struct.unpack_from("<I", bb, 0x0047E168)[0] == 0xF9403FE8
        assert struct.unpack_from("<I", bb, 0x0047E088)[0] == 0x97FFE9C8
        assert struct.unpack_from("<I", bb, 0x0047E094)[0] == 0xF9400037
        assert struct.unpack_from("<I", bb, 0x0047DEB4)[0] == 0xD10203FF
        assert struct.unpack_from("<I", bb, 0x0047DECC)[0] == 0x52800E00
        assert struct.unpack_from("<I", bb, 0x0047DEC0)[0] == 0x52800101
        assert struct.unpack_from("<I", bb, 0x0047DED8)[0] == 0x97F5DAE8
        assert struct.unpack_from("<I", bb, 0x0047DF10)[0] == 0xD65F03C0
        assert struct.unpack_from("<Q", bb, 0x015B8838)[0] == 0x87DEB4
        # : HashMap V +0/+8 split; sret 0x18 != V; TBNZ miss vs TBZ hit.
        assert struct.unpack_from("<I", bb, 0x0047E08C)[0] == 0x37000F60
        assert struct.unpack_from("<I", bb, 0x00435260)[0] == 0x360003A0
        assert struct.unpack_from("<I", bb, 0x004352D4)[0] == 0xF9400437
        assert struct.unpack_from("<I", bb, 0x004371F8)[0] == 0x9401056C
        assert struct.unpack_from("<I", bb, 0x004371FC)[0] == 0x360021E0
        assert struct.unpack_from("<I", bb, 0x0047E164)[0] == 0xB4001073
        assert struct.unpack_from("<I", bb, 0x0047E174)[0] == 0xC85F7D09
        assert struct.unpack_from("<I", bb, 0x004788E4)[0] == 0x52800033
        get_bls = []
        for off in range(0, 0x1375388, 4):
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) != 0x25:
                continue
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            if off + 0x400000 + (imm << 2) == 0x8787A8:
                get_bls.append(off + 0x400000)
        assert get_bls == [0x83525C, 0x8371F8, 0x87E088]
        assert b"BUG: Not a work response" in bb
        assert b"BUG: Midstates work type in version-rolling mode" in bb
        # : REV W0,W24 @ FUN_0091c0a0; MidstateCount count→log.
        assert struct.unpack_from("<I", bb, 0x0051C0E0)[0] == 0x5AC00B00
        assert struct.unpack_from("<I", bb, 0x0051C0DC)[0] == 0xF9404428
        assert struct.unpack_from("<I", bb, 0x0051C0E4)[0] == 0xD63F0100
        assert (
            struct.unpack_from("<I", bb, 0x0051C0E8)[0] == 0x394202A8
        )  # LDRB [X21,#0x80]
        assert struct.unpack_from("<I", bb, 0x0051C0EC)[0] == 0x7100051F  # CMP #1
        assert struct.unpack_from("<I", bb, 0x0051C0F4)[0] == 0xAA0003F6  # MOV X22,X0
        assert struct.unpack_from("<I", bb, 0x0051C120)[0] == 0xAA1603E1  # MOV X1,X22
        # : +0x80!=1 cold path is bm1398_6x.rs:344 work-type panic.
        assert struct.unpack_from("<I", bb, 0x0051C1B0)[0] == 0xB0005040  # ADRP X0
        assert (
            struct.unpack_from("<I", bb, 0x0051C1B4)[0] == 0x91123C00
        )  # ADD X0,#0x48F
        assert (
            struct.unpack_from("<I", bb, 0x0051C1C0)[0] == 0x52800601
        )  # MOVZ W1,#0x30
        assert (
            bb[0x00F2548F : 0x00F2548F + 48]
            == b"BUG: Midstates work type in version-rolling mode"
        )
        assert (
            bb[0x00F25433 : 0x00F25433 + 48]
            == b"open/bosminer/bosminer-antminer/src/bm1398_6x.rs"
        )
        assert bb[0x00F25477 : 0x00F25477 + 24] == b"BUG: Not a work response"
        assert struct.unpack_from("<Q", bb, 0x015BA220)[0] == 0x1325433
        assert struct.unpack_from("<Q", bb, 0x015BA228)[0] == 48
        assert struct.unpack_from("<I", bb, 0x015BA230)[0] == 344
        assert struct.unpack_from("<I", bb, 0x015BA234)[0] == 21
        assert struct.unpack_from("<Q", bb, 0x015BA208)[0] == 0x1325433
        assert struct.unpack_from("<I", bb, 0x015BA218)[0] == 319
        assert struct.unpack_from("<I", bb, 0x015BA21C)[0] == 9
        assert b"pic0x88.rs" in bb
        # : X21=X1; ADD #0x60; verwidth mid-entry CMP (same tag).
        assert struct.unpack_from("<I", bb, 0x0051C0D4)[0] == 0xAA0103F5
        assert struct.unpack_from("<I", bb, 0x0051C0F8)[0] == 0x910182A0
        assert struct.unpack_from("<I", bb, 0x007F2478)[0] == 0x39408008
        assert struct.unpack_from("<I", bb, 0x007F247C)[0] == 0x7100051F
        assert struct.unpack_from("<I", bb, 0x007F2484)[0] == 0xF9400C00
        assert struct.unpack_from("<I", bb, 0x007F248C)[0] == 0xF9400800
        # : factory X1 is runtime X24; no DATA u64 of 0x876ca8.
        assert struct.unpack_from("<I", bb, 0x0047E1C8)[0] == 0xAA1803E1
        assert struct.unpack_from("<I", bb, 0x00478C98)[0] == 0xF9014AFA
        assert struct.unpack_from("<I", bb, 0x004DC95C)[0] == 0xF9004660
        assert bb.find(struct.pack("<Q", 0x876CA8)) < 0
        assert b"rustc version 1.87.0 (17067e9ac 2025-05-09)" in bb
        assert b"core::convert::identity" not in bb
        assert struct.unpack_from("<I", bb, 0x004D6D14)[0] == 0x52826CCA
        assert struct.unpack_from("<I", bb, 0x004D6D10)[0] == 0x9132A108
        assert struct.unpack_from("<I", bb, 0x00476CA8)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x00475FAC)[0] == 0x3CC88285
        assert struct.unpack_from("<I", bb, 0x004761D4)[0] == 0x3C888265
        assert struct.unpack_from("<I", bb, 0x00E5FC94)[0] != 0
        assert b"open/bosminer/bosminer-units/src/midstate_count.rs" in bb
        assert b"BUG: number of midstates not a power of 2" in bb
        assert b"BUG: zero midstates" in bb
        # : FUN_00bf3264 at VA 0x00bf3264 (file 0x7f3264).
        assert struct.unpack_from("<I", bb, 0x007F3264)[0] == 0xF9400008
        # : five UART parse callers MOVZ W25,#0x11c0; ADD X2,X19,X25.
        for off in (0x004F2950, 0x004F3A1C, 0x004F4AE8, 0x004F5BB4, 0x004F6C80):
            assert struct.unpack_from("<I", bb, off)[0] == 0x52823819
        for off in (0x004F29E8, 0x004F3AB4, 0x004F4B80, 0x004F5C4C, 0x004F6D18):
            assert struct.unpack_from("<I", bb, off)[0] == 0x8B190262
        assert struct.unpack_from("<I", bb, 0x004AFA64)[0] == 0x910D0260
        assert struct.unpack_from("<I", bb, 0x0050086C)[0] == 0xF90047F3
        # : RX memcpy wrapper+0x10 / 0x1390; five HashChain STR &self+0x90.
        assert struct.unpack_from("<I", bb, 0x0046E420)[0] == 0x91004261
        assert struct.unpack_from("<I", bb, 0x0046E424)[0] == 0x52827202
        assert struct.unpack_from("<I", bb, 0x004CFC14)[0] == 0xF9004674
        assert struct.unpack_from("<I", bb, 0x004CFC14 - 0x7C)[0] == 0x91024274
        for off in (0x004CFC14, 0x004D0A88, 0x004D1340, 0x004D1BF8, 0x004D24B0):
            assert struct.unpack_from("<I", bb, off)[0] == 0xF9004674
        # : HashChain+0x30 copy; TLS drop MRS; single-deref UDIV; Halt Box STR.
        assert struct.unpack_from("<I", bb, 0x004927A8)[0] == 0x9100C261
        assert struct.unpack_from("<I", bb, 0x004927AC)[0] == 0x52827202
        assert struct.unpack_from("<I", bb, 0x00492814)[0] == 0x97FF6EEF
        assert struct.unpack_from("<I", bb, 0x0046E3E4)[0] == 0x942879B0
        assert struct.unpack_from("<I", bb, 0x00E8CAE0)[0] == 0xD53BD056
        assert struct.unpack_from("<I", bb, 0x007F3268)[0] == 0xB40000A8
        assert struct.unpack_from("<I", bb, 0x007F326C)[0] == 0x92401C29
        assert struct.unpack_from("<I", bb, 0x007F3274)[0] == 0x9AC80920
        assert struct.unpack_from("<I", bb, 0x003492B8)[0] == 0xF908FA75
        assert struct.unpack_from("<I", bb, 0x00501248)[0] == 0xF908FABF
        assert b"open/bosminer/bosminer/src/halt.rs" in bb
        # : six LDR #0x11f0 pair #0x11f8 (Box); MOVZ #0x11f0 is memcpy size.
        assert struct.unpack_from("<I", bb, 0x0012BEF4)[0] == 0xF948FA75
        assert struct.unpack_from("<I", bb, 0x0012BEF0)[0] == 0xF948FE76
        for off, w_11f0, w_11f8 in (
            (0x0012BEF4, 0xF948FA75, 0xF948FE76),
            (0x0012E130, 0xF948FA68, 0xF948FE61),
            (0x0015D52C, 0xF948FA75, 0xF948FE76),
            (0x0015F6D0, 0xF948FA68, 0xF948FE61),
            (0x001C3EB0, 0xF948FA75, 0xF948FE76),
            (0x001C60D8, 0xF948FA68, 0xF948FE61),
        ):
            assert struct.unpack_from("<I", bb, off)[0] == w_11f0
            assert struct.unpack_from("<I", bb, off - 4)[0] == w_11f8
        assert struct.unpack_from("<I", bb, 0x002A9208)[0] == 0x52823E02
        assert struct.unpack_from("<I", bb, 0x004F4B88)[0] == 0x94009D46
        assert b"AntminerDriver::init" in bb
        assert b"Empty PLL table" in bb
        # : Future 0x1270 snapshot; tag 2 at +0x30; UBFX>>17; SP ADD#0x90.
        assert struct.unpack_from("<I", bb, 0x00090D5C)[0] == 0x52824E02
        assert struct.unpack_from("<I", bb, 0x0008E7B8)[0] == 0xB9003289
        assert struct.unpack_from("<I", bb, 0x00090D3C)[0] == 0x52800048
        assert struct.unpack_from("<I", bb, 0x0010B9D0)[0] == 0xF81E0FFE
        assert struct.unpack_from("<I", bb, 0x00182B30)[0] == 0x531160C6
        for off in (0x00182B30, 0x0038D490, 0x0038D78C, 0x00536D48, 0x00537064):
            w = struct.unpack_from("<I", bb, off)[0]
            assert (w & 0xFFC00000) == 0x53000000
            assert ((w >> 16) & 0x3F) == 17
            assert ((w >> 10) & 0x3F) == 24
        assert struct.unpack_from("<I", bb, 0x0061E8BC)[0] == 0xF90047E8
        assert struct.unpack_from("<I", bb, 0x0061E89C)[0] == 0x910243FF
        # : clone MOV X20,X1; factory MOV X24,X1 + LDR #0x70; dispatch 3.125M.
        assert struct.unpack_from("<I", bb, 0x00475F74)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00475F80)[0] == 0xAA0103F4
        assert struct.unpack_from("<I", bb, 0x00476D04)[0] == 0xAA0103F8
        assert struct.unpack_from("<I", bb, 0x00476D4C)[0] == 0xF9403B08
        assert struct.unpack_from("<I", bb, 0x004764BC)[0] == 0xF9004668
        assert struct.unpack_from("<I", bb, 0x004D6D20)[0] == 0x5295E109
        assert struct.unpack_from("<I", bb, 0x004D6D24)[0] == 0x72A005E9
        assert struct.unpack_from("<I", bb, 0x004D6D14)[0] == 0x52826CCA
        # : factory addr ADRP+ADD; Worker::new BL; 0x15f8 stack snap; slice+0x10.
        assert struct.unpack_from("<I", bb, 0x004D6D0C)[0] == 0x90FFFD08
        assert struct.unpack_from("<I", bb, 0x004D6D10)[0] == 0x9132A108
        assert struct.unpack_from("<I", bb, 0x00476D8C)[0] == 0xAA1703E0
        assert struct.unpack_from("<I", bb, 0x00476DA0)[0] == 0x940231E5
        assert struct.unpack_from("<I", bb, 0x00476DB8)[0] == 0x5282BF02
        assert struct.unpack_from("<I", bb, 0x00476DB4)[0] == 0x910103E9
        assert struct.unpack_from("<I", bb, 0x00476DC0)[0] == 0xB27D0120
        assert struct.unpack_from("<I", bb, 0x00476DC4)[0] == 0xB27D0101
        assert struct.unpack_from("<I", bb, 0x0046CADC)[0] == 0xF9004668
        assert struct.unpack_from("<I", bb, 0x0046CAC4)[0] == 0xF9400148
        assert struct.unpack_from("<I", bb, 0x0046CAD0)[0] == 0x91004108
        # : HashMap get; LDR [entry,#8]; BLR factory; SP+0x1640 clone.
        assert struct.unpack_from("<I", bb, 0x0043525C)[0] == 0x94010D53
        assert struct.unpack_from("<I", bb, 0x004352D4)[0] == 0xF9400437
        assert struct.unpack_from("<I", bb, 0x00435308)[0] == 0xD63F02E0
        assert struct.unpack_from("<I", bb, 0x004352E0)[0] == 0x94001830
        assert struct.unpack_from("<I", bb, 0x004787DC)[0] == 0x9401012A
        assert struct.unpack_from("<I", bb, 0x0047E1CC)[0] == 0x97FEDC15
        assert struct.unpack_from("<I", bb, 0x00476E44)[0] == 0x94002342
        assert struct.unpack_from("<I", bb, 0x00476E3C)[0] == 0xAA1803E1
        assert struct.unpack_from("<I", bb, 0x00476E40)[0] == 0x91190000
        # : prep ADD #0xf0/#0x10; Vec clone LDRs; X1=[SP,#0x78]; vt0 LDR+STP.
        assert struct.unpack_from("<I", bb, 0x0043B3CC)[0] == 0x9103C020
        assert struct.unpack_from("<I", bb, 0x0043B3D4)[0] == 0xAA0103F4
        assert struct.unpack_from("<I", bb, 0x0043B3F0)[0] == 0x91004280
        assert struct.unpack_from("<I", bb, 0x00ED2780)[0] == 0xF9400813
        assert struct.unpack_from("<I", bb, 0x00ED2788)[0] == 0xF9400415
        assert struct.unpack_from("<I", bb, 0x0047E044)[0] == 0xAA0003F6
        assert struct.unpack_from("<I", bb, 0x0047E168)[0] == 0xF9403FE8
        assert struct.unpack_from("<I", bb, 0x0047E16C)[0] == 0xF9414ED7
        assert struct.unpack_from("<I", bb, 0x0047E1C4)[0] == 0xAA1703E0
        assert struct.unpack_from("<I", bb, 0x0047E1C8)[0] == 0xAA1803E1
        assert struct.unpack_from("<I", bb, 0x0047E15C)[0] == 0xD63F02E0
        assert struct.unpack_from("<I", bb, 0x0047E144)[0] == 0x9101A3E8
        assert struct.unpack_from("<I", bb, 0x0047E05C)[0] == 0x9108C000
        assert struct.unpack_from("<I", bb, 0x0047E060)[0] == 0x9402FAF7
        assert struct.unpack_from("<I", bb, 0x004352DC)[0] == 0xAA1303E1
        assert struct.unpack_from("<I", bb, 0x00435258)[0] == 0xAA0203E1
        assert struct.unpack_from("<I", bb, 0x004D6D34)[0] == 0xF945754A
        assert struct.unpack_from("<I", bb, 0x004D6D3C)[0] == 0xA902ABE8
        assert struct.unpack_from("<I", bb, 0x004D4B6C)[0] == 0xB27D02A3
        assert struct.unpack_from("<Q", bb, 0x016BDAE8)[0] == 0x008DBDF4
        # : FUN_008dbdf4 LDRB +0x228; memcpy 0x230; box 0x250.
        assert struct.unpack_from("<I", bb, 0x004DBE04)[0] == 0x3948A008
        assert struct.unpack_from("<I", bb, 0x004DBE14)[0] == 0x7100051F
        assert struct.unpack_from("<I", bb, 0x004DBE1C)[0] == 0x9108A668
        assert struct.unpack_from("<I", bb, 0x004DBE30)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x004DBE34)[0] == 0x940BB46B
        assert struct.unpack_from("<I", bb, 0x004DBE40)[0] == 0x52804A00
        assert struct.unpack_from("<I", bb, 0x004DBE64)[0] == 0x52804A02
        assert struct.unpack_from("<I", bb, 0x004DBEA0)[0] == 0x52800461
        # : two MOVZ#1+STRB #0x228; 0x7c refuse; prep STRB #0x22c.
        assert struct.unpack_from("<I", bb, 0x00209E9C)[0] == 0x5280002A
        assert struct.unpack_from("<I", bb, 0x00209EA4)[0] == 0x3908A26A
        assert struct.unpack_from("<I", bb, 0x003493DC)[0] == 0x52800028
        assert struct.unpack_from("<I", bb, 0x003493E4)[0] == 0x3908A2E8
        assert struct.unpack_from("<I", bb, 0x001F5A1C)[0] == 0x52800F88
        assert struct.unpack_from("<I", bb, 0x001F5A20)[0] == 0x3908A268
        assert struct.unpack_from("<I", bb, 0x0043B788)[0] == 0x3908B275
        # : Halt split +0x1228; prep LDR W/STR W #0x228; A ADD #0x250.
        assert struct.unpack_from("<I", bb, 0x00349220)[0] == 0x91400417
        assert struct.unpack_from("<I", bb, 0x003492B8)[0] == 0xF908FA75
        assert struct.unpack_from("<I", bb, 0x0043B76C)[0] == 0xB9422A9C
        assert struct.unpack_from("<I", bb, 0x0043B7A8)[0] == 0xB9022A7C
        assert struct.unpack_from("<I", bb, 0x00207A04)[0] == 0xAA0003F3
        assert struct.unpack_from("<I", bb, 0x00209EBC)[0] == 0x91094276
        # : instantiate 0x2a0; FUN_00878950 0x230; STR W 0x01000000.
        assert struct.unpack_from("<I", bb, 0x00425694)[0] == 0x52805402
        assert struct.unpack_from("<I", bb, 0x00425698)[0] == 0x940E8E52
        assert struct.unpack_from("<I", bb, 0x00478C64)[0] == 0x52804602
        assert struct.unpack_from("<I", bb, 0x00478C68)[0] == 0x940D40DE
        assert struct.unpack_from("<I", bb, 0x00478C78)[0] == 0xF9011AFC
        assert struct.unpack_from("<I", bb, 0x00209A54)[0] == 0x52A02008
        assert struct.unpack_from("<I", bb, 0x00209A60)[0] == 0xB9022A68
        assert struct.unpack_from("<I", bb, 0x00435320)[0] == 0x52804602
        assert b"BUG: failed to instantiate hashchain" in bb
        # : five AM3 HashChain inits have 0 STR #0x228 and 0 large memcpy.
        am3_inits = (
            (0x004CFAD0, 0x004D0188),
            (0x004D0944, 0x004D0FFC),
            (0x004D11FC, 0x004D18B4),
            (0x004D1AB4, 0x004D216C),
            (0x004D236C, 0x004D2A24),
        )
        str228 = 0
        memcpy_ge80 = 0
        for lo, hi in am3_inits:
            off = lo
            while off + 4 <= hi:
                w = struct.unpack_from("<I", bb, off)[0]
                if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                    str228 += 1
                if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                    str228 += 1
                if (w & 0xFF800000) == 0x52800000 and (w & 0x1F) == 2:
                    imm = (w >> 5) & 0xFFFF
                    if imm >= 0x80 and off + 8 <= hi:
                        nxt = struct.unpack_from("<I", bb, off + 4)[0]
                        if (nxt >> 26) == 0b100101:
                            imm26 = nxt & 0x3FFFFFF
                            if imm26 & (1 << 25):
                                imm26 -= 1 << 26
                            if (off + 0x400000 + 4 + (imm26 << 2)) == 0xBC8FE0:
                                memcpy_ge80 += 1
                off += 4
        assert str228 == 0
        assert memcpy_ge80 == 0
        assert struct.unpack_from("<I", bb, 0x004D0160)[0] == 0x9108A042
        assert struct.unpack_from("<I", bb, 0x004D0164)[0] == 0x52800441
        assert struct.unpack_from("<I", bb, 0x004D0168)[0] == 0x97EE0D52
        split = 0
        add_strb0 = 0
        add228_panic = 0
        off = 0
        first = 0x01375388
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFF800000) == 0x91000000:
                imm = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                rd = w & 0x1F
                if rd != 31 and imm == 0x200:
                    k = 1
                    while k < 33 and off + 4 * k + 4 <= first:
                        sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                        if (
                            (sw & 0xFFC00000) == 0x39000000
                            and ((sw >> 10) & 0xFFF) == 0x28
                            and ((sw >> 5) & 0x1F) == rd
                        ):
                            split += 1
                            break
                        k += 1
                if rd != 31 and imm == 0x228:
                    k = 1
                    while k < 9 and off + 4 * k + 4 <= first:
                        sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                        if (
                            (sw & 0xFFC00000) == 0x39000000
                            and ((sw >> 10) & 0xFFF) == 0
                            and ((sw >> 5) & 0x1F) == rd
                        ):
                            add_strb0 += 1
                            break
                        k += 1
            off += 4
        for lo, hi in am3_inits:
            off = lo
            while off + 4 <= hi:
                w = struct.unpack_from("<I", bb, off)[0]
                if (w & 0xFF800000) == 0x91000000:
                    imm = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                    if imm == 0x228 and (w & 0x1F) != 31:
                        add228_panic += 1
                off += 4
        assert split == 0
        assert add_strb0 == 0
        assert add228_panic == 10
        # : dest=+0x228 memcpy; 0 MOVZ#0x228+STRB-reg.
        assert struct.unpack_from("<I", bb, 0x005514C8)[0] == 0x9108A2A0
        assert struct.unpack_from("<I", bb, 0x005514D0)[0] == 0x52804002
        assert struct.unpack_from("<I", bb, 0x005514D4)[0] == 0x9409DEC3
        assert struct.unpack_from("<I", bb, 0x006D9F50)[0] == 0x9108A3A0
        assert struct.unpack_from("<I", bb, 0x006D9F58)[0] == 0x52803E02
        assert struct.unpack_from("<I", bb, 0x007267D0)[0] == 0x9108A3E0
        movz228_regoff = 0
        dest228 = 0
        off = 0
        while off + 8 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFF800000) in (0x52800000, 0xD2800000) and ((w >> 21) & 3) == 0:
                if ((w >> 5) & 0xFFFF) == 0x228:
                    rd = w & 0x1F
                    k = 1
                    while k < 12 and off + 4 * k + 4 <= first:
                        sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                        if ((sw >> 21) & 0x7FF) == 0x1C1 and ((sw >> 16) & 0x1F) == rd:
                            movz228_regoff += 1
                            break
                        k += 1
            if (w & 0xFF800000) == 0x91000000:
                imm = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                if imm == 0x228 and (w & 0x1F) == 0:
                    k = 1
                    while k < 8 and off + 4 * k + 4 <= first:
                        sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                        if (sw >> 26) == 0b100101:
                            imm26 = sw & 0x3FFFFFF
                            if imm26 & (1 << 25):
                                imm26 -= 1 << 26
                            tgt = (off + 4 * k + 0x400000) + (imm26 << 2)
                            if tgt == 0xBC8FE0:
                                dest228 += 1
                            break
                        k += 1
            off += 4
        assert movz228_regoff == 0
        assert dest228 == 5
        # : STP XZR Default empty; STR XZR/WZR pins; slot setter; AM2 baud.
        stp_xzr = 0
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0xA9000000:
                rt = w & 0x1F
                rt2 = (w >> 10) & 0x1F
                rn = (w >> 5) & 0x1F
                imm = ((w >> 15) & 0x7F) * 8
                if rt == 31 and rt2 == 31 and rn != 31 and imm in (0x210, 0x220, 0x228):
                    stp_xzr += 1
            off += 4
        assert stp_xzr == 0
        assert struct.unpack_from("<I", bb, 0x0024C9BC)[0] == 0xF901167F
        assert struct.unpack_from("<I", bb, 0x00587604)[0] == 0xB9022ADF
        assert struct.unpack_from("<I", bb, 0x00E00524)[0] == 0xA9BE57FE
        assert struct.unpack_from("<I", bb, 0x00436C20)[0] == 0x3908A15F
        slot_bl = 0
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) == 0x1200524:
                    slot_bl += 1
            off += 4
        assert slot_bl == 358
        # : post-alloc STR #0x228 before RET; BTree +0x220/+0x228; dest=MOV/ADD#0 memcpy.
        assert struct.unpack_from("<I", bb, 0x00181A00)[0] == 0xF9011728
        assert struct.unpack_from("<I", bb, 0x00414A44)[0] == 0xF9011015
        assert struct.unpack_from("<I", bb, 0x00414A78)[0] == 0xF9011419
        assert struct.unpack_from("<I", bb, 0x00E7CA2C)[0] == 0xF9011418
        assert struct.unpack_from("<I", bb, 0x00342FB0)[0] == 0x52810C02
        assert struct.unpack_from("<I", bb, 0x0086C9AC)[0] == 0x52805602
        post_alloc = 0
        btree_pair = 0
        mov_hc = 0
        mov_228 = 0
        add0 = 0
        memcpy_va = 0xBC8FE0
        alloc_va = 0x5F4A78

        def decode_add_imm(word):
            if (word & 0xFF800000) != 0x91000000:
                return None
            return (
                word & 0x1F,
                (word >> 5) & 0x1F,
                ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0),
            )

        def bl_tgt(pc, word):
            if (word >> 26) != 0b100101:
                return None
            imm26 = word & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            return pc + (imm26 << 2)

        def movz_w2_size(word):
            if (word & 0xFF800000) not in (0x52800000, 0xD2800000):
                return None
            if (word & 0x1F) != 2:
                return None
            hw = (word >> 21) & 3
            return ((word >> 5) & 0xFFFF) << (hw * 16)

        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if bl_tgt(off + 0x400000, w) == alloc_va:
                k = 1
                while k < 32 and off + 4 * k + 4 <= first:
                    sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                    if sw == 0xD65F03C0:
                        break
                    xn = (sw >> 5) & 0x1F
                    if xn != 31:
                        is_strb = (sw & 0xFFC00000) == 0x39000000 and (
                            (sw >> 10) & 0xFFF
                        ) == 0x228
                        is_strw = (sw & 0xFFC00000) == 0xB9000000 and (
                            (sw >> 10) & 0xFFF
                        ) * 4 == 0x228
                        is_strx = (sw >> 22) == 0x3E4 and (
                            (sw >> 10) & 0xFFF
                        ) * 8 == 0x228
                        if is_strb or is_strw or is_strx:
                            post_alloc += 1
                            break
                    k += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x220:
                rn = (w >> 5) & 0x1F
                rt = w & 0x1F
                if rn != 31 and rt != 31:
                    k = 1
                    while k < 8 and off + 4 * k + 4 <= first:
                        sw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                        if (
                            (sw >> 22) == 0x3E4
                            and ((sw >> 10) & 0xFFF) * 8 == 0x228
                            and ((sw >> 5) & 0x1F) == rn
                        ):
                            btree_pair += 1
                            break
                        k += 1
            sz = movz_w2_size(w)
            if sz is not None and 0x229 <= sz <= 0x4000 and off + 8 <= first:
                nxt = struct.unpack_from("<I", bb, off + 4)[0]
                if bl_tgt(off + 4 + 0x400000, nxt) == memcpy_va:
                    dest_kind = None
                    dest_rn = None
                    dest_add = None
                    b = 1
                    while b < 12 and off >= 4 * b:
                        pw = struct.unpack_from("<I", bb, off - 4 * b)[0]
                        a = decode_add_imm(pw)
                        if a and a[0] == 0:
                            dest_kind = "ADD"
                            dest_rn = a[1]
                            dest_add = a[2]
                            break
                        if (pw & 0xFFE0FFE0) == 0xAA0003E0 and (pw & 0x1F) == 0:
                            dest_kind = "MOV"
                            dest_rn = (pw >> 16) & 0x1F
                            dest_add = 0
                            break
                        b += 1
                    if dest_kind == "ADD" and dest_add == 0 and dest_rn != 31:
                        add0 += 1
                    if dest_kind == "MOV" and dest_rn != 31:
                        neigh = set()
                        lo = max(0, off - 4 * 48)
                        hi = min(first, off + 4 * 48)
                        j = lo
                        while j + 4 <= hi:
                            a = decode_add_imm(struct.unpack_from("<I", bb, j)[0])
                            if a:
                                if a[2] == 0x19C:
                                    neigh.add("19c")
                                elif a[2] == 0x11F0:
                                    neigh.add("11f0")
                                elif a[2] == 0x228:
                                    neigh.add("228")
                            j += 4
                        if "19c" in neigh or "11f0" in neigh:
                            mov_hc += 1
                        if "228" in neigh:
                            mov_228 += 1
            off += 4
        assert post_alloc == 3
        assert btree_pair == 17
        assert mov_hc == 0
        assert mov_228 == 7
        assert add0 == 0
        # : 3 prep BL; 5 AM3 Future wrappers ADD#0x18; 0 STUR #0x228.
        assert struct.unpack_from("<I", bb, 0x004255DC)[0] == 0x94005771
        assert struct.unpack_from("<I", bb, 0x00425934)[0] == 0x9400569B
        assert struct.unpack_from("<I", bb, 0x004352E0)[0] == 0x94001830
        assert struct.unpack_from("<I", bb, 0x004CCE3C)[0] == 0x91006260
        assert struct.unpack_from("<I", bb, 0x004CCE20)[0] == 0xB9401008
        assert struct.unpack_from("<I", bb, 0x004CCE44)[0] == 0x94000B23
        prep_bl = 0
        wrap_add18 = 0
        stur228 = 0
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) == 0x83B3A0:
                    prep_bl += 1
            if (w & 0x3B200C00) == 0x38000000:
                imm9 = (w >> 12) & 0x1FF
                if imm9 & 0x100:
                    imm9 -= 0x200
                if imm9 == 0x228 or imm9 == -0x228:
                    stur228 += 1
            off += 4
        for lo, init in (
            (0x004CCE14, 0x008CFAD0),
            (0x004CC92C, 0x008D0944),
            (0x004CCEC4, 0x008D11FC),
            (0x004CCF74, 0x008D1AB4),
            (0x004CCC3C, 0x008D236C),
        ):
            v = lo
            while v + 4 <= lo + 0xA0:
                w = struct.unpack_from("<I", bb, v)[0]
                if (w & 0xFF800000) == 0x91000000:
                    imm = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                    if imm == 0x18 and (w & 0x1F) == 0:
                        wrap_add18 += 1
                v += 4
        assert prep_bl == 3
        assert wrap_add18 == 5
        assert stur228 == 0
        # : 10 BL to AM3 wrappers; ADD#0x20; 0 STR#0x228 in FUN_008e7454.
        assert struct.unpack_from("<I", bb, 0x004E7494)[0] == 0x91008260
        assert struct.unpack_from("<I", bb, 0x004E749C)[0] == 0x97FF965E
        wrap_bl = 0
        wrap_tgts = {0x8CCE14, 0x8CC92C, 0x8CCEC4, 0x8CCF74, 0x8CCC3C}
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) in wrap_tgts:
                    wrap_bl += 1
            off += 4
        assert wrap_bl == 10
        wrap_caller_str228 = 0
        off = 0x004E7454
        while off + 4 <= 0x004E7593:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                wrap_caller_str228 += 1
            if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                wrap_caller_str228 += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                wrap_caller_str228 += 1
            off += 4
        assert wrap_caller_str228 == 0
        # : FUN_008cb778 boxes outer Future 0x180; vtable 0x19c6b50 -> 0x84ca74.
        assert struct.unpack_from("<I", bb, 0x004CB808)[0] == 0x52803000
        assert struct.unpack_from("<I", bb, 0x004CB820)[0] == 0x97F4A496
        assert struct.unpack_from("<I", bb, 0x004CB82C)[0] == 0x52803002
        assert struct.unpack_from("<I", bb, 0x004CB7D4)[0] == 0x912D4108
        assert struct.unpack_from("<Q", bb, 0x015B6B50)[0] == 0x84CA74
        box_str228 = 0
        off = 0x004CB778
        while off + 4 <= 0x004CB863:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                box_str228 += 1
            if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                box_str228 += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                box_str228 += 1
            off += 4
        assert box_str228 == 0
        vt_adrp = 0
        off = 0
        while off + 8 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                immlo = (w >> 29) & 3
                immhi = (w >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = ((off + 0x400000) & ~0xFFF) + (imm << 12)
                k = 1
                while k < 6 and off + 4 * k + 4 <= first:
                    aw = struct.unpack_from("<I", bb, off + 4 * k)[0]
                    if (aw & 0xFF800000) == 0x91000000:
                        ard = aw & 0x1F
                        arn = (aw >> 5) & 0x1F
                        aimm = ((aw >> 10) & 0xFFF) << (12 if (aw >> 22) & 1 else 0)
                        if ard == rd and arn == rd:
                            formed = page + aimm
                            if 0x19C6B00 <= formed <= 0x19C6C80:
                                vt_adrp += 1
                            break
                    k += 1
            off += 4
        assert vt_adrp == 5
        # : FUN_008ce99c boxes tag 0xcc, schedules at Arc+0x160; runq STR +0x18.
        assert struct.unpack_from("<I", bb, 0x004CE99C)[0] == 0xD10103FF
        assert struct.unpack_from("<I", bb, 0x004CE9D4)[0] == 0x52801982
        assert struct.unpack_from("<I", bb, 0x004CE9DC)[0] == 0x97FFF367
        assert struct.unpack_from("<I", bb, 0x004CE9E4)[0] == 0x910582C0
        assert struct.unpack_from("<I", bb, 0x004CE9F0)[0] == 0x97FFAAC5
        assert struct.unpack_from("<I", bb, 0x004B952C)[0] == 0xF9000C29
        assert struct.unpack_from("<I", bb, 0x004CE9FC)[0] == 0x910802C0
        boxer_bl = 0
        boxer_tgts = {0x8CB778, 0x8CB8B4, 0x8CB9F0, 0x8CBB2C}
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) in boxer_tgts:
                    boxer_bl += 1
            off += 4
        assert boxer_bl == 4
        # : FUN_008518d0 assembles 0x108 at SP+#0x1a0; bit0 alt boxer.
        assert struct.unpack_from("<I", bb, 0x004518D0)[0] == 0xA9BE7BFD
        assert struct.unpack_from("<I", bb, 0x004518DC)[0] == 0xB9400009
        assert struct.unpack_from("<I", bb, 0x00451920)[0] == 0xF9402829
        assert struct.unpack_from("<I", bb, 0x004519B4)[0] == 0x910683E1
        assert struct.unpack_from("<I", bb, 0x004519B8)[0] == 0x9401F3F9
        assert struct.unpack_from("<I", bb, 0x004519A8)[0] == 0x94011B48
        assert struct.unpack_from("<I", bb, 0x0047965C)[0] == 0x97FF609D
        parent_bl = 0
        parent_str228 = 0
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) == 0x8518D0:
                    parent_bl += 1
            off += 4
        off = 0x004518D0
        while off + 4 <= 0x00451A43:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                parent_str228 += 1
            if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                parent_str228 += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                parent_str228 += 1
            off += 4
        assert parent_bl == 1
        assert parent_str228 == 0
        # : FUN_008790dc stages 0x108 at SP+#0x2cc0 from self+#0x2c70.
        assert struct.unpack_from("<I", bb, 0x004790DC)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x0047964C)[0] == 0x914013E0
        assert struct.unpack_from("<I", bb, 0x00479650)[0] == 0x91400BE1
        assert struct.unpack_from("<I", bb, 0x00479654)[0] == 0x910E0000
        assert struct.unpack_from("<I", bb, 0x00479658)[0] == 0x91330021
        assert struct.unpack_from("<I", bb, 0x00479618)[0] == 0xF9563A6A
        assert struct.unpack_from("<I", bb, 0x00479608)[0] == 0xF9565E69
        assert struct.unpack_from("<I", bb, 0x00479418)[0] == 0x9401E449
        assert struct.unpack_from("<Q", bb, 0x015B0F90)[0] == 0x8790DC
        assert b"bosminer_am2_s17::hashchainmessageevent" in bb
        msg_bl = 0
        msg_str228 = 0
        off = 0
        while off + 4 < first:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) == 0x8790DC:
                    msg_bl += 1
            off += 4
        off = 0x004790DC
        while off + 4 <= 0x004797C7:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                msg_str228 += 1
            if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                msg_str228 += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                msg_str228 += 1
            off += 4
        assert msg_bl == 0
        assert msg_str228 == 0
        # : AM3 ADD#0x228 is ADRP loc 0x19c6228; init tag LDRB +0x80.
        assert struct.unpack_from("<I", bb, 0x004D015C)[0] == 0xD00087A2
        assert struct.unpack_from("<I", bb, 0x004D0160)[0] == 0x9108A042
        assert struct.unpack_from("<I", bb, 0x004CFAEC)[0] == 0x39420008
        am3_adrp228 = 0
        am3_tag80 = 0
        am3_inits_w78 = (
            (0x004CFAD0, 0x004D0188),
            (0x004D0944, 0x004D0FFC),
            (0x004D11FC, 0x004D18B4),
            (0x004D1AB4, 0x004D216C),
            (0x004D236C, 0x004D2A24),
        )
        for lo, hi in am3_inits_w78:
            off = lo
            while off + 4 <= hi:
                w = struct.unpack_from("<I", bb, off)[0]
                if (w & 0xFFC00000) == 0x39400000 and ((w >> 10) & 0xFFF) == 0x80:
                    am3_tag80 += 1
                if (w & 0xFF800000) == 0x91000000:
                    imm = ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)
                    if imm == 0x228 and (w & 0x1F) == 2:
                        prev = struct.unpack_from("<I", bb, off - 4)[0]
                        if (prev & 0x9F00001F) == 0x90000002:
                            am3_adrp228 += 1
                off += 4
        assert am3_adrp228 == 10
        assert am3_tag80 == 5
        # : instantiate X1=*slot; FUN_0085c78c LDR +0x260; Vec STR +0x228.
        assert struct.unpack_from("<I", bb, 0x004255C8)[0] == 0xF9400341
        assert struct.unpack_from("<I", bb, 0x004255E4)[0] == 0xF9417909
        assert struct.unpack_from("<I", bb, 0x00442C5C)[0] == 0x97FF8A43
        assert struct.unpack_from("<I", bb, 0x0045C828)[0] == 0xF94132A9
        assert struct.unpack_from("<I", bb, 0x0045CAC0)[0] == 0x97FF983E
        assert struct.unpack_from("<I", bb, 0x004352DC)[0] == 0xAA1303E1
        assert struct.unpack_from("<I", bb, 0x00282090)[0] == 0xF9011677
        assert struct.unpack_from("<I", bb, 0x00282088)[0] == 0xF9010E60
        src_str228 = 0
        off = 0x0045C78C
        while off + 4 <= 0x0045CBCC:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                src_str228 += 1
            if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                src_str228 += 1
            if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                src_str228 += 1
            off += 4
        assert src_str228 == 0
        # : FUN_0085c78c self is 0x300; boxer copies parent+0x3b0; baud STR is fn-ptr.
        assert struct.unpack_from("<Q", bb, 0x0159CE70)[0] == 0x6F4F2C
        assert struct.unpack_from("<Q", bb, 0x0159CE78)[0] == 0x300
        assert struct.unpack_from("<Q", bb, 0x0159CE80)[0] == 0x10
        assert struct.unpack_from("<Q", bb, 0x0159CE88)[0] == 0x85C78C
        assert struct.unpack_from("<I", bb, 0x00305824)[0] == 0xF941D814
        assert struct.unpack_from("<I", bb, 0x00305890)[0] == 0xF9413298
        assert struct.unpack_from("<I", bb, 0x003058DC)[0] == 0x52806000
        assert struct.unpack_from("<I", bb, 0x00305960)[0] == 0x52806002
        assert struct.unpack_from("<I", bb, 0x0030596C)[0] == 0xF0009521
        assert struct.unpack_from("<I", bb, 0x00305970)[0] == 0x9139C021
        assert struct.unpack_from("<I", bb, 0x003055C0)[0] == 0x940588FB
        assert struct.unpack_from("<I", bb, 0x00436C10)[0] == 0xB0000328
        assert struct.unpack_from("<I", bb, 0x00436C14)[0] == 0x911C8108
        assert struct.unpack_from("<I", bb, 0x00436C34)[0] == 0xF9013148
        assert struct.unpack_from("<I", bb, 0x00305484)[0] == 0xAA0003F7
        assert struct.unpack_from("<I", bb, 0x00305488)[0] == 0xAA0803F6
        assert struct.unpack_from("<I", bb, 0x003054B8)[0] == 0xF94132FB
        assert struct.unpack_from("<I", bb, 0x00305668)[0] == 0xF90152D7
        assert struct.unpack_from("<I", bb, 0x0030566C)[0] == 0xF90172DB
        assert struct.unpack_from("<I", bb, 0x0030567C)[0] == 0xF901DAD7
        assert struct.unpack_from("<I", bb, 0x003056C0)[0] == 0xF901DED4
        assert struct.unpack_from("<Q", bb, 0x0159C9C0)[0] == 0x3C0
        assert struct.unpack_from("<Q", bb, 0x0159C9D8)[0] == 0x705800
        str260 = 0
        str260_xzr = 0
        str260_clone = 0
        box300_bl = 0
        clone300_bl = 0
        movz300_near = 0
        parent3c0_bl = 0
        parent3c0_str228 = 0
        str3b0 = 0
        off = 0
        while off + 4 <= 0x01375388:
            w = struct.unpack_from("<I", bb, off)[0]
            pc = off + 0x400000
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                tgt = pc + (imm26 << 2)
                if tgt == 0x705800:
                    box300_bl += 1
                if tgt == 0x8679AC:
                    clone300_bl += 1
                if tgt == 0x705464:
                    parent3c0_bl += 1
            xn = (w >> 5) & 0x1F
            is_str260 = False
            xt = w & 0x1F
            if xn != 31:
                if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x260:
                    is_str260 = True
                if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x260:
                    is_str260 = True
            if xn != 31:
                if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x3B0:
                    str3b0 += 1
                if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x3B0:
                    str3b0 += 1
            if 0x00305464 <= off < 0x0030573C:
                if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                    parent3c0_str228 += 1
                if (w & 0xFFC00000) == 0xB9000000 and ((w >> 10) & 0xFFF) * 4 == 0x228:
                    parent3c0_str228 += 1
                if (w & 0xFFC00000) == 0x39000000 and ((w >> 10) & 0xFFF) == 0x228:
                    parent3c0_str228 += 1
            if is_str260:
                str260 += 1
                if xt == 31:
                    str260_xzr += 1
                else:
                    saw = False
                    look = off - 4
                    while look >= 0 and off - look <= 64:
                        lw = struct.unpack_from("<I", bb, look)[0]
                        if (
                            (lw >> 22) == 0x3E5
                            and ((lw >> 10) & 0xFFF) * 8 == 0x260
                            and (lw & 0x1F) == xt
                        ):
                            saw = True
                            break
                        look -= 4
                    if saw:
                        str260_clone += 1
            if (w & 0xFF800000) in (0x52800000, 0xD2800000):
                hw = (w >> 21) & 3
                imm = ((w >> 5) & 0xFFFF) << (hw * 16)
                if imm == 0x300:
                    look = off + 4
                    while look + 4 <= 0x01375388 and look - off <= 0x80:
                        sw = struct.unpack_from("<I", bb, look)[0]
                        sxn = (sw >> 5) & 0x1F
                        if sxn != 31:
                            if (sw >> 22) == 0x3E4 and (
                                (sw >> 10) & 0xFFF
                            ) * 8 == 0x260:
                                movz300_near += 1
                            if (sw & 0xFFC00000) == 0xB9000000 and (
                                (sw >> 10) & 0xFFF
                            ) * 4 == 0x260:
                                movz300_near += 1
                        look += 4
            off += 4
        assert str260 == 52
        assert str260_xzr == 8
        assert str260_clone == 9
        assert box300_bl == 0
        assert clone300_bl == 1
        assert movz300_near == 0
        assert parent3c0_bl == 3
        assert parent3c0_str228 == 0
        assert str3b0 == 20
        # : three callers load ELF statics; +0x260 on those objects is 0.
        assert struct.unpack_from("<I", bb, 0x002F23BC)[0] == 0xAA0803F3
        assert struct.unpack_from("<I", bb, 0x002F24E0)[0] == 0x90009EE0
        assert struct.unpack_from("<I", bb, 0x002F24F0)[0] == 0xF9476800
        assert struct.unpack_from("<I", bb, 0x002F2500)[0] == 0xAA1303E8
        assert struct.unpack_from("<I", bb, 0x002F2504)[0] == 0x52800026
        assert struct.unpack_from("<I", bb, 0x002F2508)[0] == 0x94004BD7
        assert struct.unpack_from("<I", bb, 0x002F2844)[0] == 0xB0009EE0
        assert struct.unpack_from("<I", bb, 0x002F2854)[0] == 0xF9469C00
        assert struct.unpack_from("<I", bb, 0x002F286C)[0] == 0x94004AFE
        assert struct.unpack_from("<I", bb, 0x002F2D4C)[0] == 0xF0009EC0
        assert struct.unpack_from("<I", bb, 0x002F2D5C)[0] == 0xF9450400
        assert struct.unpack_from("<I", bb, 0x002F2D74)[0] == 0x940049BC
        assert struct.unpack_from("<Q", bb, 0x016BEED0)[0] == 0x1AE01C0
        assert struct.unpack_from("<Q", bb, 0x016BFD38)[0] == 0x1ADFBC0
        assert struct.unpack_from("<Q", bb, 0x016BDA08)[0] == 0x1ADFEC0
        assert struct.unpack_from("<Q", bb, 0x016D01C0)[0] == 0x8633A0
        assert struct.unpack_from("<Q", bb, 0x016CFBC0)[0] == 0x862C84
        assert struct.unpack_from("<Q", bb, 0x016CFEC0)[0] == 0x8626A8
        assert struct.unpack_from("<Q", bb, 0x016D0420)[0] == 0
        assert struct.unpack_from("<Q", bb, 0x016CFE20)[0] == 0
        assert struct.unpack_from("<Q", bb, 0x016D0120)[0] == 0
        call3_str260 = 0
        call3_str228 = 0
        call3_bl = 0
        vptr_str260 = 0
        vptr_bl = 0
        for lo, hi in (
            (0x002F23A8, 0x002F260C),
            (0x002F270C, 0x002F2970),
            (0x002F2C14, 0x002F2E78),
        ):
            off = lo
            while off + 4 <= hi:
                w = struct.unpack_from("<I", bb, off)[0]
                xn = (w >> 5) & 0x1F
                if xn != 31:
                    if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x260:
                        call3_str260 += 1
                    if (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x228:
                        call3_str228 += 1
                    if (w & 0xFFC00000) == 0xB9000000 and (
                        (w >> 10) & 0xFFF
                    ) * 4 == 0x228:
                        call3_str228 += 1
                off += 4
        off = 0
        while off + 4 <= 0x01375388:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                tgt = (off + 0x400000) + (imm26 << 2)
                if tgt in (0x6F23A8, 0x6F270C, 0x6F2C14):
                    call3_bl += 1
                if tgt in (0x8633A0, 0x862C84, 0x8626A8):
                    vptr_bl += 1
            off += 4
        for lo, hi in (
            (0x004633A0, 0x00463874),
            (0x00462C84, 0x00463140),
            (0x004626A8, 0x00462B64),
        ):
            off = lo
            while off + 4 <= hi:
                w = struct.unpack_from("<I", bb, off)[0]
                xn = (w >> 5) & 0x1F
                if xn != 31 and (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x260:
                    vptr_str260 += 1
                off += 4
        assert call3_str260 == 0
        assert call3_str228 == 0
        assert call3_bl == 0
        assert vptr_str260 == 0
        assert vptr_bl == 0
        # : FUN_00867740 SIMD covers +0x260; STRH +0x228 is param_16.
        assert struct.unpack_from("<I", bb, 0x00467740)[0] == 0xD10243FF
        assert struct.unpack_from("<I", bb, 0x00467758)[0] == 0xAA0803F3
        assert struct.unpack_from("<I", bb, 0x004678DC)[0] == 0x79045268
        assert struct.unpack_from("<I", bb, 0x0046790C)[0] == 0xAD400520
        assert struct.unpack_from("<I", bb, 0x00467910)[0] == 0xF901726B
        assert struct.unpack_from("<I", bb, 0x00467914)[0] == 0xAD128660
        assert struct.unpack_from("<I", bb, 0x00463780)[0] == 0x94000FF0
        assert struct.unpack_from("<I", bb, 0x0046304C)[0] == 0x940011BD
        assert struct.unpack_from("<I", bb, 0x00462A70)[0] == 0x94001334
        init677_str260 = 0
        off = 0x00467740
        while off + 4 <= 0x00467950:
            w = struct.unpack_from("<I", bb, off)[0]
            xn = (w >> 5) & 0x1F
            if xn != 31 and (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x260:
                init677_str260 += 1
            off += 4
        assert init677_str260 == 0
        # : X9=&local_120; +0x260 from *(0x1adfb28+0x10)==0.
        assert struct.unpack_from("<I", bb, 0x004678C0)[0] == 0xF9405FE9
        assert struct.unpack_from("<I", bb, 0x00463698)[0] == 0xD0009355
        assert struct.unpack_from("<I", bb, 0x0046369C)[0] == 0xF94792B5
        assert struct.unpack_from("<I", bb, 0x004636E0)[0] == 0xF9400AA9
        assert struct.unpack_from("<I", bb, 0x004636FC)[0] == 0xF900C3E9
        assert struct.unpack_from("<I", bb, 0x00463748)[0] == 0x9105C3E8
        assert struct.unpack_from("<I", bb, 0x00463750)[0] == 0x910583E9
        assert struct.unpack_from("<I", bb, 0x00463760)[0] == 0xA90223E9
        assert struct.unpack_from("<I", bb, 0x00462F54)[0] == 0xF94792B5
        assert struct.unpack_from("<I", bb, 0x00462978)[0] == 0xF94792B5
        assert struct.unpack_from("<Q", bb, 0x016BDF20)[0] == 0x1ADFB28
        assert struct.unpack_from("<Q", bb, 0x016CFB28)[0] == 0x8631F0
        assert struct.unpack_from("<Q", bb, 0x016CFB38)[0] == 0
        # : no later overwrite of 0x1ae01c0+0x260; 6 true slot LDRs; 633a0 RETs.
        assert struct.unpack_from("<I", bb, 0x002F2434)[0] == 0xF9476AB5
        assert struct.unpack_from("<I", bb, 0x002F2798)[0] == 0xF9469EB5
        assert struct.unpack_from("<I", bb, 0x002F2CA0)[0] == 0xF94506B5
        assert struct.unpack_from("<I", bb, 0x00463784)[0] == 0x910883FF
        assert struct.unpack_from("<I", bb, 0x004637A4)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x0062575C)[0] == 0x9000854A
        post_str260 = 0
        off = 0x00463784
        while off + 4 <= 0x004637A8:
            w = struct.unpack_from("<I", bb, off)[0]
            xn = (w >> 5) & 0x1F
            if xn != 31 and (w >> 22) == 0x3E4 and ((w >> 10) & 0xFFF) * 8 == 0x260:
                post_str260 += 1
            off += 4
        assert post_str260 == 0
        # : FUN_008631f0 is X8-sret PSU Default; sibling is 0x98; +0x228 is not a field.
        assert struct.unpack_from("<I", bb, 0x004631F0)[0] == 0xB0005429
        assert struct.unpack_from("<I", bb, 0x004631F4)[0] == 0x5280004A
        assert struct.unpack_from("<I", bb, 0x00463224)[0] == 0x5280002A
        assert struct.unpack_from("<I", bb, 0x00463228)[0] == 0xB900891F
        assert struct.unpack_from("<I", bb, 0x00463244)[0] == 0xF900090A
        assert struct.unpack_from("<I", bb, 0x0046325C)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x004636C4)[0] == 0x3DC002A0
        assert struct.unpack_from("<Q", bb, 0x00EE80F0)[0] == 0x3FB999999999999A
        assert struct.unpack_from("<Q", bb, 0x016CFB28)[0] == 0x8631F0
        assert struct.unpack_from("<Q", bb, 0x016CFBC0)[0] == 0x862C84
        init631_bl = 0
        init631_str228 = 0
        init631_max = 0
        off = 0x004631F0
        while off + 4 <= 0x00463260:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                init631_bl += 1
            xn = (w >> 5) & 0x1F
            if xn != 31:
                if (w >> 22) == 0x3E4:
                    so = ((w >> 10) & 0xFFF) * 8
                    if so > init631_max:
                        init631_max = so
                    if so == 0x228:
                        init631_str228 += 1
                if (w & 0xFFC00000) == 0xB9000000:
                    so = ((w >> 10) & 0xFFF) * 4
                    if so > init631_max:
                        init631_max = so
                    if so == 0x228:
                        init631_str228 += 1
            off += 4
        callers_631 = 0
        off = 0
        while off + 4 <= 0x01375388:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                if (off + 0x400000) + (imm26 << 2) == 0x8631F0:
                    callers_631 += 1
            off += 4
        assert init631_bl == 0
        assert init631_str228 == 0
        assert init631_max == 0x88
        assert callers_631 == 0
        # : FUN_00bf2478 MidstateCount→log; UART version width is that log.
        assert struct.unpack_from("<I", bb, 0x007F2478)[0] == 0x39408008
        assert struct.unpack_from("<I", bb, 0x007F2484)[0] == 0xF9400C00
        assert struct.unpack_from("<I", bb, 0x007F2488)[0] == 0x1419B603
        assert struct.unpack_from("<I", bb, 0x007F248C)[0] == 0xF9400800
        assert struct.unpack_from("<I", bb, 0x007F2490)[0] == 0xD65F03C0
        # : five UART wrappers parse→Ok→FUN_00bf6c2c; no LSL#13 BIP320 re-expand.
        assert struct.unpack_from("<I", bb, 0x004F262C)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x004F29F0)[0] == 0x9400A5AC
        assert struct.unpack_from("<I", bb, 0x004F29F4)[0] == 0xB941A3E8
        assert struct.unpack_from("<I", bb, 0x004F29F8)[0] == 0x36001088
        assert struct.unpack_from("<I", bb, 0x004F2C1C)[0] == 0x52823A08
        assert struct.unpack_from("<I", bb, 0x004F2C24)[0] == 0x8B080260
        assert struct.unpack_from("<I", bb, 0x004F2C28)[0] == 0x940C1001
        assert struct.unpack_from("<I", bb, 0x004F3ABC)[0] == 0x9400A179
        assert struct.unpack_from("<I", bb, 0x004F4B88)[0] == 0x94009D46
        assert struct.unpack_from("<I", bb, 0x004F5C54)[0] == 0x94009913
        assert struct.unpack_from("<I", bb, 0x004F6D20)[0] == 0x940094E0
        assert struct.unpack_from("<I", bb, 0x007F6C2C)[0] == 0xA9BA7BFD
        assert struct.unpack_from("<I", bb, 0x007F6C48)[0] == 0xAA0103FA
        assert struct.unpack_from("<I", bb, 0x007F6C4C)[0] == 0xF9403409
        assert struct.unpack_from("<I", bb, 0x007F6FA0)[0] == 0x52800F08
        assert struct.unpack_from("<I", bb, 0x004AFA8C)[0] == 0x940D1C68
        wrap_lsl13 = 0
        for base in (0x004F262C, 0x004F36F8, 0x004F47C4, 0x004F5890, 0x004F695C):
            off = base
            while off < base + 0x101C:
                w = struct.unpack_from("<I", bb, off)[0]
                if (w & 0xFF800000) == 0x53000000:
                    immr = (w >> 16) & 0x3F
                    imms = (w >> 10) & 0x3F
                    if immr == 19 and imms == 18:
                        wrap_lsl13 += 1
                if (w & 0xFF800000) == 0xD3400000:
                    immr = (w >> 16) & 0x3F
                    imms = (w >> 10) & 0x3F
                    if immr == 51 and imms == 50:
                        wrap_lsl13 += 1
                off += 4
        bf6c_lsl13 = 0
        off = 0x007F6C2C
        while off < 0x007F76F4:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w & 0xFF800000) == 0x53000000:
                immr = (w >> 16) & 0x3F
                imms = (w >> 10) & 0x3F
                if immr == 19 and imms == 18:
                    bf6c_lsl13 += 1
            if (w & 0xFF800000) == 0xD3400000:
                immr = (w >> 16) & 0x3F
                imms = (w >> 10) & 0x3F
                if immr == 51 and imms == 50:
                    bf6c_lsl13 += 1
            off += 4
        assert wrap_lsl13 == 0
        assert bf6c_lsl13 == 0
        # : engine-absolute log helper; STRB #0x228 0x7c Default.
        assert struct.unpack_from("<I", bb, 0x007F26D0)[0] == 0x39420008
        assert struct.unpack_from("<I", bb, 0x007F26DC)[0] == 0xF9403C00
        assert struct.unpack_from("<I", bb, 0x007F26E0)[0] == 0x1419B56D
        assert struct.unpack_from("<I", bb, 0x007F26E4)[0] == 0xF9403800
        assert struct.unpack_from("<I", bb, 0x007F26E8)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x001F5A1C)[0] == 0x52800F88
        assert struct.unpack_from("<I", bb, 0x001F5A20)[0] == 0x3908A268
        # : 7 BL FUN_00bf26d0; Worker MOV/BL/X3; 1>>log tail.
        assert struct.unpack_from("<I", bb, 0x004AEA78)[0] == 0xAA0103E0
        assert struct.unpack_from("<I", bb, 0x004AEA7C)[0] == 0x940D0F15
        assert struct.unpack_from("<I", bb, 0x004AEA94)[0] == 0x940201EB
        assert struct.unpack_from("<I", bb, 0x005009FC)[0] == 0xAA1803E0
        assert struct.unpack_from("<I", bb, 0x00500A00)[0] == 0x940BC734
        assert struct.unpack_from("<I", bb, 0x00500A14)[0] == 0xAA0003E3
        assert struct.unpack_from("<I", bb, 0x00503630)[0] == 0xAA1903E0
        assert struct.unpack_from("<I", bb, 0x00503634)[0] == 0x940BBC27
        assert struct.unpack_from("<I", bb, 0x00503640)[0] == 0xAA0003E3
        assert struct.unpack_from("<I", bb, 0x0050367C)[0] == 0x940BD047
        assert struct.unpack_from("<I", bb, 0x00726398)[0] == 0xF81F0FFE
        assert struct.unpack_from("<I", bb, 0x0072639C)[0] == 0x940330CD
        assert struct.unpack_from("<I", bb, 0x007263A0)[0] == 0x52800028
        assert struct.unpack_from("<I", bb, 0x007263A4)[0] == 0x9AC02100
        assert struct.unpack_from("<I", bb, 0x007263A8)[0] == 0xF84107FE
        assert struct.unpack_from("<I", bb, 0x007263AC)[0] == 0xD65F03C0
        assert struct.unpack_from("<I", bb, 0x0007C294)[0] == 0x941AA841
        assert struct.unpack_from("<I", bb, 0x0051C104)[0] == 0x940B58DD
        abs_log_bl = 0
        rel_log_bl = 0
        oneshr_bl = 0
        off = 0
        first_load = 0x1375388
        while off + 4 <= first_load:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                tgt = (off + 0x400000) + (imm26 << 2)
                if tgt == 0xBF26D0:
                    abs_log_bl += 1
                elif tgt == 0xBF2478:
                    rel_log_bl += 1
                elif tgt == 0xB26398:
                    oneshr_bl += 1
            off += 4
        assert abs_log_bl == 7
        assert rel_log_bl == 1
        assert oneshr_bl == 9
        # : each named caller BL targets FUN_00b26398; +0x80 has no
        # CBZ/CBNZ/TBZ/TBNZ on W0/X0. LDR refuse sites are real ELF words.
        caller_vas = (
            0x0047C294,
            0x0047C44C,
            0x0047C528,
            0x004CCA04,
            0x004CCBBC,
            0x004CCC8C,
            0x004FA250,
            0x004FA408,
            0x004FA4D8,
        )
        for va in caller_vas:
            off_va = va - 0x400000
            w = struct.unpack_from("<I", bb, off_va)[0]
            assert (w >> 26) == 0b100101, hex(w)
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            tgt = va + (imm26 << 2)
            assert tgt == 0xB26398, (hex(va), hex(tgt))
            for delta in range(4, 0x80, 4):
                insn = struct.unpack_from("<I", bb, off_va + delta)[0]
                top = insn >> 24
                if top in (0x34, 0x35, 0xB4, 0xB5, 0xB6, 0xB7) and (insn & 0x1F) == 0:
                    raise AssertionError(f"W0/X0 cond {insn:#x} at {va + delta:#x}")
        assert struct.unpack_from("<I", bb, 0x0007C76C)[0] == 0xF95943E0
        assert struct.unpack_from("<I", bb, 0x0007C770)[0] == 0xF95963E1
        assert struct.unpack_from("<I", bb, 0x0007B8DC)[0] == 0xF9553BE6
        assert struct.unpack_from("<I", bb, 0x0007C68C)[0] == 0xF91943E8
        # : 6 STR X0 of 1>>log; 3 discard + sibling ADD#0x400; dest+2 toggle.
        assert struct.unpack_from("<I", bb, 0x0007C290)[0] == 0x8B140320
        assert struct.unpack_from("<I", bb, 0x0007C29C)[0] == 0xF91943E0
        assert struct.unpack_from("<I", bb, 0x0007C454)[0] == 0xF9153BE0
        assert struct.unpack_from("<I", bb, 0x0007C52C)[0] == 0x3DC74BE0
        assert struct.unpack_from("<I", bb, 0x0007C520)[0] == 0x39000AC8
        assert struct.unpack_from("<I", bb, 0x0007C538)[0] == 0x39000ADF
        assert struct.unpack_from("<I", bb, 0x007263F4)[0] == 0x91100001
        sib_bl = 0
        store3280 = 0
        store2a70 = 0
        off = 0
        while off + 4 <= first_load:
            w = struct.unpack_from("<I", bb, off)[0]
            if (w >> 26) == 0b100101:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                tgt = (off + 0x400000) + (imm26 << 2)
                if tgt == 0xB263F4:
                    sib_bl += 1
                if tgt == 0xB26398 and off + 12 <= first_load:
                    sw = struct.unpack_from("<I", bb, off + 8)[0]
                    if sw == 0xF91943E0:
                        store3280 += 1
                    elif sw == 0xF9153BE0:
                        store2a70 += 1
            off += 4
        assert sib_bl == 3
        assert store3280 == 3
        assert store2a70 == 3
        # : #0x3280 oneshr STR overwritten; #0x2a70 LDR is LDXR after RET.
        assert struct.unpack_from("<I", bb, 0x0007C68C)[0] == 0xF91943E8
        assert struct.unpack_from("<I", bb, 0x0007DE88)[0] == 0xF9553BE8
        assert struct.unpack_from("<I", bb, 0x0007DE8C)[0] == 0xC85F7D09
        share_rs = (
            ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs"
        ).read_text(encoding="utf-8")
        assert "parse_bm1366_braiins_fill_share_from_body" in share_rs
        assert "s19k_braiins_fill_nonce_word" in share_rs
        assert "refuse_esp_f8_mask_as_braiins_fill_job_id" in share_rs
        assert "refuse_esp_step8_as_braiins_fill_registry" in share_rs
        assert "s19k_braiins_uart_version_bits" in share_rs
        assert "FUN_00bf2478" in share_rs
    bmu = (
        ROOT.parents[1]
        / ""
    )
    if bmu.is_file():
        bmu_b = bmu.read_bytes()
        assert b"updateporc" not in bmu_b
        assert len(bmu_b) == 12_792_832
        assert bmu_b[0] == 0x26
        assert int.from_bytes(bmu_b[0x16:0x18], "big") == 451
        assert bmu_b[0x18 : 0x18 + 26] == b"-----BEGIN PUBLIC KEY-----"
        assert bmu_b[0x418:0x41C] == bytes.fromhex("022e5ae0")
        assert hashlib.sha256(bmu_b[0x18 : 0x18 + 451]).hexdigest() == (
            "f03c6e8345cb3cfec6792b3ef545cc2e2166661492683c20e8f0166aba8c8ad0"
        )
        cv_pub = (
            ROOT.parents[1]
            / ""
            / "unpacked/inner/CVCtrl_extracted/etc/bitmain.pub"
        )
        if cv_pub.is_file():
            cvb = cv_pub.read_bytes()
            assert len(cvb) == 451
            assert cvb != bmu_b[0x18 : 0x18 + 451]
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding

                key = serialization.load_pem_public_key(cvb)
                try:
                    key.verify(
                        bmu_b[0x418 : 0x418 + 256],
                        bmu_b[0x18 : 0x18 + 451],
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                    raise AssertionError(
                        "held CVCtrl bitmain.pub must not verify 20231108 miner.pem.sig"
                    )
                except Exception as exc:
                    assert type(exc).__name__ == "InvalidSignature"
            except ImportError:
                pass
        assert bmu_b[0x800:0x808] == b"ANDROID!"
        assert int.from_bytes(bmu_b[0x808:0x80C], "little") == 0x005C0800
        assert int.from_bytes(bmu_b[0x80C:0x810], "little") == 0x01080000
        assert int.from_bytes(bmu_b[0x810:0x814], "little") == 0x0066A000
        assert int.from_bytes(bmu_b[0x824:0x828], "little") == 2048
        assert b"init=/sbin/init" in bmu_b[0x800 : 0x800 + 80]
        assert bmu_b[1304] == 1
        assert bmu_b[1309] == 9
        assert int.from_bytes(bmu_b[1310:1314], "big") == 12_790_272
        # 0x4000 remains mid-kernel ciphertext, not the component start.
        assert bmu_b[0x4000:0x4004] == bytes.fromhex("CA78C944")
        ramdisk_off = 0x800 + 0x5C1000
        assert bmu_b[ramdisk_off : ramdisk_off + 2] != b"\x1f\x8b"
        assert bmu_b[0x800 : 0x800 + 12_790_272][:8] == b"ANDROID!"
        assert bmu_b[0x800 + 0x400 : 0x800 + 0x408] == b"AMLSECU!"
        assert bmu_b[0x800 + 0x410 : 0x800 + 0x420] == b"2023110817065673"
        assert int.from_bytes(bmu_b[0x800 + 0x40C : 0x800 + 0x410], "little") == 3
    fp_cv = (
        ROOT.parents[1]
        / ""
        / "unpacked/inner/CVCtrl_extracted/usr/bin/FileParser"
    )
    if fp_cv.is_file():
        fpb = fp_cv.read_bytes()
        assert len(fpb) == 20184
        assert fpb[15460 : 15460 + 8] == b"datafile"
        assert b"ANDROID" not in fpb
        assert b"SHA256_Init" in fpb
        assert b"RSA_verify" in fpb
        assert b"PEM_read_bio_RSA_PUBKEY" in fpb
    fp_sd = (
        ROOT.parents[1]
        / ""
        / "antminer_sd_fw/update_no_header/usr/bin/FileParser"
    )
    if fp_sd.is_file():
        assert b"datafile" not in fp_sd.read_bytes()
    zynq_uimage = (
        ROOT.parents[1]
        / ""
        / "Antminer_S19_Pro_zynq7007_BHB42XXX/uImage"
    )
    if zynq_uimage.is_file():
        uh = zynq_uimage.read_bytes()[:64]
        assert uh[0:4] == bytes.fromhex("27051956")
        assert uh[29] == 2
        assert b"Linux-4.6.0-xilinx" in uh[32:64]
        assert int.from_bytes(uh[12:16], "big") == 4_057_256
    assert "s19k_native_per_chip_core_writes" in init_seq
    assert "refuse_firmware_internals_a8_as_s19k_per_chip" in init_seq
    assert "init_ctrl_a8_unicast" in init_seq
    assert "format_s19k_backup_geometry_lines" in install_rs
    assert "classify_s19k_nand_layout" in install_rs
    assert "CLEAR_FOR_FLASH: bool = false" in install_rs
    assert "admit_s19k_backup_filenames" in install_rs
    assert "admit_s19k_backup_artifact_dir" in install_rs
    assert "admit_s19k_install_script_refuses_firstboot_only_commit" in install_rs
    assert "admit_s19k_install_rootfs_window_only" in install_rs
    assert "refuse_s19k_package_kernel_as_rootfs_nandwrite" in install_rs
    assert "format_s19k_install_payload_plan" in install_rs
    assert "format_s19k_successful_flag_plan" in install_rs
    assert "admit_s19k_successful_flag_plan" in install_rs
    assert "admit_s19k_recovery_flag_script_plans_successful_keep_bos" in install_rs
    assert "admit_s19k_recovery_flag_script_shares_fixture_rewrite" in install_rs
    assert "rewrite_recovery_flag_fixture()" in (
        ROOT / "scripts/s19k_write_recovery_flag.sh"
    ).read_text(encoding="utf-8", errors="replace")
    flag_sh_w286 = (ROOT / "scripts/s19k_write_recovery_flag.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "printf '\\003'" in flag_sh_w286
    assert "fixture_value=0x03" in flag_sh_w286
    assert "SuccessfulKeepBos plan/fixture only" in flag_sh_w286
    assert "eraseblock_index=" in flag_sh_w286
    assert "recovery flag 0x03 execute is FLASH NOT_YET" in flag_sh_w286
    assert 'flash_erase /dev/mtd5 "$EB_START_HEX" 1' not in flag_sh_w286
    assert 'nandwrite -p -s "$EB_START_HEX" /dev/mtd5' not in flag_sh_w286
    assert flag_sh_w286.find("rewrite_recovery_flag_fixture()") < flag_sh_w286.find(
        "intent=SuccessfulKeepBos"
    )
    assert flag_sh_w286.find("rewrite_recovery_flag_fixture()") < flag_sh_w286.find(
        "printf '\\003'"
    )
    assert "admit_s19k_s99_promotes_02_to_03" in install_rs
    assert "admit_s19k_s99_ota08_identity_and_readback" in install_rs
    assert "admit_s19k_s99_leftover_01_is_error" in install_rs
    assert "S99_AMLOGIC_OTA08_IDENTITIES" in install_rs
    s99 = (
        ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S99upgrade"
    ).read_text(encoding="utf-8", errors="replace")
    assert "AMLOGIC_RAW_NAND_RECOVERY_FLAG_EXCEPTION" in s99
    assert "require_amlogic_ota08_identity" in s99
    assert "missing live $BOARD_TARGET_FILE" in s99
    check_ota08_exact_identity(s99)
    assert "am3-aml-s19k:am3-s19k" in s99
    assert "am3-aml-s19jpro:am3-s19jpro-aml" in s99
    assert "am3-aml-s21:am3-s21" in s99
    assert "am3-aml-s21pro:am3-s21pro" in s99
    assert "OLD=$(read_recovery_flag)" in s99
    assert "ERROR: recovery flag readback = $NEW (expected 0x03)" in s99
    assert "WARN: recovery flag readback" not in s99
    assert "ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace" in s99
    assert "[WARN] recovery flag = 0x01" not in s99
    leftover01 = s99.find("            0x01)")
    leftover_err = s99.find(
        "ERROR: recovery flag = 0x01 (INSTALLED) leftover in userspace"
    )
    err_star = s99.find("            ERR_*)")
    assert leftover01 != -1 and leftover_err != -1 and err_star != -1
    assert leftover01 < leftover_err < err_star
    leftover_slice = s99[leftover01:err_star]
    assert "exit 1" in leftover_slice
    assert "exit 0" not in leftover_slice
    assert "commit_recovery_flag" not in leftover_slice
    assert "printf '\\x3'" not in leftover_slice
    assert "admit_s19k_s99_unread_or_unexpected_flag_is_error" in install_rs
    assert "ERROR: could not read recovery flag ($FLAG); refuse OTA-08" in s99
    assert "ERROR: unexpected recovery flag value: $FLAG; refuse OTA-08" in s99
    assert "[WARN] could not read recovery flag" not in s99
    assert "[WARN] unexpected recovery flag value:" not in s99
    unexpected_case = s99.find("            *)", err_star)
    assert unexpected_case != -1 and err_star < unexpected_case
    err_slice = s99[err_star:unexpected_case]
    unexpected_esac = s99.find("esac", unexpected_case)
    unexpected_slice = s99[unexpected_case:unexpected_esac]
    assert "exit 1" in err_slice and "exit 0" not in err_slice
    assert "exit 1" in unexpected_slice and "exit 0" not in unexpected_slice
    assert "commit_recovery_flag" not in err_slice
    assert "printf '\\x3'" not in err_slice
    assert s99.find("require_amlogic_ota08_identity") < s99.find(
        'flash_erase "$RECOVERY_MTD"'
    )
    assert s99.find("OLD=$(read_recovery_flag)") < s99.find(
        'flash_erase "$RECOVERY_MTD"'
    )
    assert s99.find('nandwrite -p -s "$RECOVERY_FLAG_OFFSET"') < s99.find(
        "NEW=$(read_recovery_flag)"
    )
    assert "refuse_s19k_flag_03_as_recover_to_stock" in install_rs
    assert "refuse_s19k_flag_03_as_mtd2_boot" in install_rs
    assert "SuccessfulKeepBos" in install_rs
    assert "admit_s19k_install_script_nandwrites_root_only" in install_rs
    assert "S19K_INSTALL_ROOTFS_LOCAL: u64 = 0x0510_0000" in install_rs
    assert "S19K_INSTALL_ROOTFS_WINDOW: u64 = 0x0280_0000" in install_rs
    assert "admit_s19k_backup_requires_nandrecovery_sidecar" in install_rs
    assert "refuse_s19k_backup_without_nandrecovery_sidecar" in install_rs
    assert "S19kBackupArtifactAdmit" in install_rs
    crc_py = (ROOT / "scripts/s19k_nand_env_crc.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "def crc32_iso_hdlc" in crc_py
    assert "S19K_NAND_ENV_CRC_OK" in crc_py
    assert "POLY = 0xEDB88320" in crc_py
    install_sh_crc = (ROOT / "scripts/install_amlogic_persistent.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "s19k_nand_env_crc.py" in install_sh_crc
    assert "nandrecovery_env_crc_ok=" in install_sh_crc
    assert "nand_env_crc_ok=" in install_sh_crc
    assert "INSTALL_PAYLOAD_PLAN.txt" in install_sh_crc
    assert "package_kernel_nandwrite=false" in install_sh_crc
    crc_spec = importlib.util.spec_from_file_location(
        "s19k_nand_env_crc", ROOT / "scripts/s19k_nand_env_crc.py"
    )
    crc_mod = importlib.util.module_from_spec(crc_spec)
    assert crc_spec.loader is not None
    crc_spec.loader.exec_module(crc_mod)
    crc_body = b"bootcmd=run recover_to_stock\0"
    crc_body = crc_body + b"\0" * (crc_mod.S19K_NAND_ENV_LEN - 4 - len(crc_body))
    crc_word = crc_mod.crc32_iso_hdlc(crc_body)
    crc_blob = crc_word.to_bytes(4, "little") + crc_body
    crc_mod.admit_nand_env_crc(crc_blob)
    try:
        crc_mod.admit_nand_env_crc(crc_blob[:4] + b"\xff" + crc_blob[5:])
        raise AssertionError("corrupt nand_env CRC must fail")
    except SystemExit:
        pass
    assert "parse_s19k_backup_ledger" in install_rs
    assert "admit_s19k_backup_hashes" in install_rs
    assert "admit_s19k_restore_preinstall_window" in install_rs
    assert "admit_s19k_recovery_flag_write" in install_rs
    assert "refuse_stock_bmu_as_dcent_sysupgrade" in install_rs
    assert "refuse_cvitek_updateporc_as_s19k_nand_writer" in install_rs
    assert "refuse_held_updateporc_as_s19k_nand_writer" in install_rs
    assert "ZynqUbiMtd6Comparative" in install_rs
    assert "refuse_s19k_mtd6_update_volume" in install_rs
    assert "refuse_s19k_zynq_mtd0_update_marker" in install_rs
    assert "HELD_CVITEK_UPDATEPORC_BANNER" in install_rs
    assert "refuse_s19k_stock_flash_via_mmcblk0" in install_rs
    assert "parse_s19k_bmu_header" in install_rs
    assert "S19K_BTMU_MAGIC: u8 = 0x26" in install_rs
    assert "refuse_s19k_bmu_as_raw_nand_image" in install_rs
    assert "s19k_bmu_offset_24_is_pem_not_toc" in install_rs
    assert "S19K_BMU_DATA_START: usize = 0x4000" in install_rs
    assert "classify_s19k_bmu_payload_head" in install_rs
    assert "S19K_STOCK_20231108_PAYLOAD_HEAD" in install_rs
    assert "refuse_s19k_bmu_payload_as_rootfs_uimage" in install_rs
    assert "S19K_BMU_PEM_SIG_OFF: usize = 0x418" in install_rs
    assert "admit_s19k_20231108_miner_pem" in install_rs
    assert "admit_s19k_20231108_pem_sig_head" in install_rs
    assert "admit_s19k_held_root_does_not_verify_pem_sig" in install_rs
    assert "refuse_s19k_unverified_pem_sig_as_nand_grant" in install_rs
    assert 'HELD_FILEPARSER_SHA256_INIT: &str = "SHA256_Init"' in install_rs
    assert "S19K_MINER_PEM_SIG_HELD_ROOT_VERIFIED: bool = false" in install_rs
    assert "S19K_20231108_MINER_PEM_LEN: usize = 451" in install_rs
    assert "refuse_aml_sdc_burn_as_dcent" in install_rs
    assert "refuse_s19k_cvctrl_sd2nand_as_aml_nand" in install_rs
    assert "CvitekSd2NandFactory" in install_rs
    nand_layout = (
        ROOT.parents[1] / "projects/dcent-toolbox/src/dcent_toolbox/core/nand_layout.py"
    ).read_text(encoding="utf-8")
    assert "AMLOGIC_ROOTFS_OFFSET = 0x05100000" in nand_layout
    assert "AMLOGIC_RECOVERY_FLAG_OFFSET = 0x04D00000" in nand_layout
    assert "AMLOGIC_MTD5_SIZE_SUM_REFUSED = 0x06100000" in nand_layout
    assert "S19K_78_MTD5_BASE: u64 = 0x0670_0000" in install_rs
    assert "S19K_78_MTD5_SIZE_SUM: u64 = 0x0610_0000" in install_rs
    assert "OFFSET_FROM_END_MTD0_TO_MTD1: u64 = 0x60_0000" in install_rs
    assert "mtd5_base_from_proc_mtd" in install_rs
    assert "compute_s19k_geometry_from_proc_mtd" in install_rs
    assert "admit_s19k_planned_locals_match_computed" in install_rs
    assert "rewrite_s19k_recovery_flag_eraseblock" in install_rs
    assert "dcent_am3_mtd5_base_from_proc_mtd" in geom
    assert "dcent_am3_mtd5_covers_recovery" in geom
    assert "computed_mtd5_base=" in install
    assert "admit_s19k_physical_mtd5_base" in install_rs
    assert "RECOVERY_FLAG_FIRST_BOOT: u8 = 0x02" in install_rs
    assert "S19K_RESTORE_MTD5_USES_WINDOW_OFFSET: bool = false" in install_rs
    assert "refuse_s19k_restore_mtd5_at_rootfs_window_offset" in install_rs
    restore = (ROOT / "scripts/restore_amlogic_mtd5_from_backup.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert restore.find("gpio437 SafeOff") < restore.find('nandwrite -p "$ROOTFS_MTD"')
    assert "nandwrite -p -s" not in restore
    assert "backup ledger geometry is not exact S19k .78" in restore
    assert "admit ledger board_target=" in restore
    assert "BACKUP_LEDGER missing mtd5_len" in restore
    assert "missing live canonical platform/board_target pair" in restore
    assert "tmp_deploy leftover" in restore
    assert "admit_s19k_restore_live_board_target" in install_rs
    assert "refuse_s19k_restore_tmp_deploy_stamp" in install_rs
    deploy_sh = (ROOT / "scripts/dcentrald_s19k_tmp_deploy.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "/etc/dcentos/tmp_deploy" not in deploy_sh
    assert "dcentrald_s19k_tmp_remote_run.sh" in deploy_sh
    trial_sh = (ROOT / "scripts/dcentrald_s19k_tmp_trial.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert 'exec "$SCRIPT_DIR/dcentrald_s19k_tmp_deploy.sh"' in trial_sh
    remote_trial = (ROOT / "scripts/dcentrald_s19k_tmp_remote_run.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "/etc/dcentos" not in remote_trial
    assert "runtime_active" in remote_trial
    assert "persistent_mutation=false" in remote_trial
    assert "trap 'stop_child 130' 2" in remote_trial
    assert (
        '"$TRIAL_BIN" --config "$TRIAL_CFG" --serial-mining --allow-loud \\'
        in remote_trial
    )
    for custody_arg in (
        '--s19k-bos-tools-pid "$BOUND_SUPERVISOR_PID"',
        '--s19k-bos-tools-start "$BOUND_SUPERVISOR_START"',
        '--s19k-bos-tools-ppid "$BOUND_SUPERVISOR_PPID"',
        '--s19k-bos-tools-pgrp "$BOUND_SUPERVISOR_PGRP"',
        '--s19k-bos-tools-session "$BOUND_SUPERVISOR_SESSION"',
        '--s19k-bos-tools-exe "$BOUND_SUPERVISOR_EXE"',
        '--s19k-bos-tools-cmdline-sha256 "$BOUND_SUPERVISOR_CMDLINE_SHA"',
        '--s19k-bos-tools-cmdline-bytes "$BOUND_SUPERVISOR_CMDLINE_BYTES"',
        '--s19k-bosminer-pid "$BOUND_BOSMINER_PID"',
        '--s19k-bosminer-start "$BOUND_BOSMINER_START"',
        '--s19k-bosminer-ppid "$BOUND_BOSMINER_PPID"',
        '--s19k-bosminer-pgrp "$BOUND_BOSMINER_PGRP"',
        '--s19k-bosminer-session "$BOUND_BOSMINER_SESSION"',
        '--s19k-bosminer-exe "$BOUND_BOSMINER_EXE"',
        '--s19k-bosminer-cmdline-sha256 "$BOUND_BOSMINER_CMDLINE_SHA"',
        '--s19k-bosminer-cmdline-bytes "$BOUND_BOSMINER_CMDLINE_BYTES"',
    ):
        assert custody_arg in remote_trial
    assert "DCENTOS_EPHEMERAL_RUNTIME=1" in remote_trial
    assert "DCENT_S19K_TRACK1_STOP_SAFEOFF=1" in remote_trial
    assert "verify_bound_file" in remote_trial
    # Attempt-10 hard-ceiling backstop (2026-08-28 lifecycle audit): the
    # historical blanket "never SIGKILL" invariant is superseded by an exact
    # one — the ONLY kill -KILL anywhere in the remote trial is the trial
    # ceiling's identity-fenced SIGKILL of the exact daemon child inside
    # enforce_trial_ceiling_exit, and it can never name stock supervisor
    # processes. Mirrors scripts/test_s19k_tmp_deploy_safety.py's pin.
    assert remote_trial.count("kill -KILL") == 1
    _ceiling_fn = remote_trial[
        remote_trial.index("enforce_trial_ceiling_exit() {"): remote_trial.index(
            "set_expected_safeoff_receipt()"
        )
    ]
    assert 'kill -KILL "$CHILD_PID" 2>/dev/null' in _ceiling_fn
    assert "exact_dcentrald_child_matches" in _ceiling_fn
    assert "stale temporary runtime receipt" in remote_trial
    assert (
        'BOUNDED_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_bounded_work_transcript"'
        in remote_trial
    )
    assert "dcentos.s19k-bounded-work-transcript/v1" in remote_trial
    assert "semantic_verification=host-required" in remote_trial
    assert (
        'NO_WORK_TRANSCRIPT_RECEIPT="$TRIAL_DIR/runtime_handoff_no_work_transcript"'
        in remote_trial
    )
    assert "dcentos.s19k-handoff-no-work-transcript/v1" in remote_trial
    assert (
        "semantic_verification=host-plus-independent-instruments-required"
        in remote_trial
    )
    assert 'exec 6< "$STARTUP_DAEMON_TRANSCRIPT"' in remote_trial
    assert '"$@" 6>&- 9>&-' in remote_trial
    assert remote_trial.count("clear_runtime_obligation_after_safeoff ||") >= 2
    # 2026-08-30 closure (f2d3b9bc6) consolidated the two per-mode inline receipt
    # publishes into one fail-closed publish_mode_specific_receipts_after_safeoff()
    # that publishes install-custody + handoff-no-work + bounded-work receipts and is
    # invoked on every checked-SafeOff exit path (stronger coverage than the two old
    # inline sites). Re-anchored 2026-09-01 to the consolidated structure — the
    # handoff-no-work receipt still publishes fail-closed on every no-work exit.
    assert remote_trial.count("publish_handoff_no_work_transcript_receipt") >= 2
    assert remote_trial.count("publish_bounded_work_transcript_receipt") >= 2
    assert remote_trial.count("publish_install_custody_transcript_receipt") >= 2
    assert remote_trial.count("publish_mode_specific_receipts_after_safeoff") >= 4
    for receipt in (
        'publish_install_custody_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS"',
        'publish_handoff_no_work_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS"',
        'publish_bounded_work_transcript_receipt "$MODE_WRAPPER_EXIT_STATUS"',
    ):
        assert receipt in remote_trial
    for closeout in (
        "clear_runtime_obligation_after_safeoff || exit 1\n"
        '        publish_mode_specific_receipts_after_safeoff "$EXIT_CODE"',
        "clear_runtime_obligation_after_safeoff || exit 1\n"
        '    publish_mode_specific_receipts_after_safeoff "$CHILD_STATUS"',
    ):
        assert closeout in remote_trial
    assert 'ENDURANCE_EVIDENCE_DIR="$TRIAL_DIR/endurance_evidence"' in remote_trial
    assert "endurance-work-proof" in remote_trial
    assert "S19K_ENDURANCE_ACK_OK" in remote_trial
    assert "publish_endurance_work_receipt" in remote_trial
    assert "publish_endurance_failure_receipt" in remote_trial
    assert "dcentos.s19k-endurance-work-receipt/v1" in remote_trial
    assert "dcentos.s19k-endurance-daemon-terminal/v1" in remote_trial
    assert "dcentos.s19k-endurance-failure-receipt/v1" in remote_trial
    assert "dcentos.s19k-endurance-daemon-failure/v1" in remote_trial
    endurance_rs = (ROOT / "dcentrald/dcentrald/src/s19k_endurance.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "pub(crate) const S19K_ENDURANCE_MIN_S: u64 = 24 * 60 * 60" in endurance_rs
    assert "pub(crate) const S19K_ENDURANCE_MAX_S: u64 = 26 * 60 * 60" in endurance_rs
    assert "S19K_ENDURANCE_ACK_TIMEOUT_S: u64 = 5 * 60" in endurance_rs
    assert "hash_bound_field" in endurance_rs
    assert "no-clobber-hard-link-after-fsync" in endurance_rs
    assert "publish_failure_terminal" in endurance_rs
    assert "fail-after-checked-safeoff" in endurance_rs
    endurance_collect = (ROOT / "scripts/s19k_endurance_collect.py").read_text(
        encoding="utf-8", errors="replace"
    )
    endurance_verify = (ROOT / "scripts/s19k_endurance_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    endurance_baseline = (ROOT / "scripts/s19k_endurance_baseline.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "StrictHostKeyChecking=yes" in endurance_collect
    assert "GlobalKnownHostsFile=/dev/null" in endurance_collect
    assert "host-create-new-fsync" in endurance_collect
    assert "S19K_ENDURANCE_COLLECTION_OK" in endurance_collect
    assert "S19K_ENDURANCE_CONTROLLED_FAILURE_EVIDENCE_OK" in endurance_collect
    assert "--resume-failure" in endurance_collect
    assert "resume_failure" in endurance_collect
    assert "manifest-first transaction" in endurance_collect
    assert "clean_stale_publication_scratch" in endurance_collect
    assert "POSIX directory fsync" in endurance_collect
    assert "verify_against_baseline" in endurance_collect
    assert "phase3_provenance" in endurance_collect
    assert '"dry_run": "false"' in endurance_verify
    assert 'BASELINE_SCHEMA = "dcentos.s19k-endurance-baseline/v4"' in endurance_verify
    assert "verify_phase3_provenance" in endurance_verify
    assert "phase3_baseline_builder_sha256" in endurance_verify
    assert (
        'FINAL_RECEIPT_SCHEMA = "dcentos.s19k-endurance-host-verification/v1"'
        in endurance_verify
    )
    assert "TARGET_RECEIPT_KEYS" in endurance_verify
    assert "TARGET_FAILURE_RECEIPT_KEYS" in endurance_verify
    assert "verify_failure_final" in endurance_verify
    assert (
        "first endurance segment does not begin at the admitted observation origin"
        in endurance_verify
    )
    assert "accepted-share evidence is incomplete" in endurance_verify
    assert (
        "SafeOff receipt does not prove reset-low / PSU-off terminal state"
        in endurance_verify
    )
    assert "gather_phase3_provenance" in endurance_baseline
    assert "bounded.verify" in endurance_baseline
    assert "physical.verify_evidence" in endurance_baseline
    assert "phase3_physical_verification_id" in endurance_baseline
    assert "no-clobber-hard-link-after-fsync" in endurance_baseline
    stock_restart = (
        ROOT / "scripts/dcentrald_s19k_stock_restart_from_safeoff.sh"
    ).read_text(encoding="utf-8", errors="replace")
    for census_source in (remote_trial, stock_restart):
        assert '[ -L "$FD" ] || [ -e "$FD" ] || continue' in census_source
        assert '[ -e "$FD" ] || [ -L "$FD" ] || continue' not in census_source
        census_start = census_source.index("collect_all_task_effect_snapshot() {")
        census_end = census_source.index("\n}\n", census_start)
        census = census_source[census_start:census_end]
        argv_loop = census.index("for PROC_ARG in $CMDLINE; do")
        assert census.index("set -f", 0, argv_loop) < argv_loop
        assert census.index("set +f", argv_loop) > argv_loop
    assert "filter_custody_relevant_task_effects() (\n    set -f" in remote_trial
    assert "filter_relevant_task_effects() (\n    set -f" in stock_restart
    watchdog_namespace_gate = (
        'case "$FD_TARGET" in\n'
        '                    "$WATCHDOG_NODE_ROOT"/*) ;;\n'
        "                    *) continue ;;\n"
        "                esac"
    )
    assert watchdog_namespace_gate in stock_restart
    assert stock_restart.index(watchdog_namespace_gate) < stock_restart.index(
        'if fd_watchdog_rdev "$FD"; then'
    )
    bounded_verify = (ROOT / "scripts/s19k_bounded_transcript_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert (
        'RECEIPT_SCHEMA = "dcentos.s19k-bounded-work-transcript/v1"' in bounded_verify
    )
    assert 'PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"' in bounded_verify
    no_work_verify = (ROOT / "scripts/s19k_no_work_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    no_work_tests = (ROOT / "scripts/test_s19k_no_work_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    no_work_prepare = (ROOT / "scripts/s19k_no_work_prepare.py").read_text(
        encoding="utf-8", errors="replace"
    )
    no_work_prepare_tests = (ROOT / "scripts/test_s19k_no_work_prepare.py").read_text(
        encoding="utf-8", errors="replace"
    )
    phase3_physical = (ROOT / "scripts/s19k_phase3_physical_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    phase3_physical_tests = (
        ROOT / "scripts/test_s19k_phase3_physical_verify.py"
    ).read_text(encoding="utf-8", errors="replace")
    phase12_normalize = (ROOT / "scripts/s19k_phase12_normalize.py").read_text(
        encoding="utf-8", errors="replace"
    )
    phase12_normalize_tests = (
        ROOT / "scripts/test_s19k_phase12_normalize.py"
    ).read_text(encoding="utf-8", errors="replace")
    phase12_capture = (
        ROOT / "scripts/s19k_phase12_capture_verify.py"
    ).read_text(encoding="utf-8", errors="replace")
    phase12_capture_tests = (
        ROOT / "scripts/test_s19k_phase12_capture_verify.py"
    ).read_text(encoding="utf-8", errors="replace")
    assert 'PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"' in no_work_verify
    assert (
        'RECEIPT_SCHEMA = "dcentos.s19k-handoff-no-work-transcript/v1"'
        in no_work_verify
    )
    assert (
        'MANIFEST_SCHEMA = "dcentos.s19k-phase12-instrument-manifest/v2"'
        in no_work_verify
    )
    assert 'BUNDLE_SCHEMA = "dcentos.s19k-phase12-evidence-bundle/v2"' in no_work_verify
    assert (
        'VERIFICATION_SCHEMA = "dcentos.s19k-phase12-raw-capture-verification/v2"'
        in phase12_capture
    )
    assert "rates_and_gaps_computed_from_raw_blocks" in phase12_capture
    assert "rail_composite_at_times(" in phase12_capture
    assert "test_missing_second_rail_is_rejected" in phase12_capture_tests
    assert "test_unmeasured_gap_between_blocks_is_rejected" in phase12_capture_tests
    assert (
        'CONFIG_SCHEMA = "dcentos.s19k-phase12-normalization-config/v1"'
        in phase12_normalize
    )
    assert (
        'RECEIPT_SCHEMA = "dcentos.s19k-phase12-normalization/v1"' in phase12_normalize
    )
    assert "host-plus-independent-instruments-required" in no_work_verify
    assert "S19K_PHASE12_NO_WORK_OK" in no_work_verify
    assert '"verifier_sha256"' in no_work_verify
    assert '"verifier_bytes"' in no_work_verify
    assert '"preparer_sha256"' in no_work_verify
    assert '"preparer_bytes"' in no_work_verify
    assert '"normalizer_sha256"' in no_work_verify
    assert '"normalizer_bytes"' in no_work_verify
    assert "normalizer.verify_normalization(" in no_work_verify
    assert 'BUNDLE_RECEIPT_FILENAME = "phase12_bundle_complete"' in no_work_verify
    assert "require_bundle_complete: bool = True" in no_work_verify
    assert (
        "embedded host verification differs from fresh semantic verification"
        in no_work_verify
    )
    assert "member must have exactly one hard link" in no_work_verify
    assert "os.read(descriptor, 1024 * 1024)" in no_work_verify
    assert '"--output"' in no_work_verify
    assert "os.O_EXCL" in no_work_verify
    assert "os.fsync(directory_descriptor)" in no_work_verify
    assert "MAX_SAMPLE_GAP_MS = 1_000" in no_work_verify
    assert "MIN_POST_DECAY_CONFIRM_MS = 5_000" in no_work_verify
    assert "MAX_DECAY_PERCENT_OF_BASELINE = 5" in no_work_verify
    assert "MAX_CANONICAL_BYTES = 64 * 1024 * 1024" in no_work_verify
    assert "MIN_SPINNING_FAN_RPM = 2_000" in no_work_verify
    assert "MIN_SPINNING_FANS = 2" in no_work_verify
    assert "_stable_regular_bytes_bounded" in no_work_verify
    assert 'bytes.fromhex("55AA2136")' in no_work_verify
    assert (
        "test_rejects_work_frame_even_when_uart_manifest_is_rehashed" in no_work_tests
    )
    assert "test_rejects_work_signature_split_across_adjacent_tx_rows" in no_work_tests
    assert (
        "test_rejects_manual_canonical_edit_even_when_manifest_is_rehashed"
        in no_work_tests
    )
    assert (
        "test_rejects_raw_export_edit_even_when_manifest_is_rehashed" in no_work_tests
    )
    assert "test_rejects_manifest_bound_to_another_normalizer" in no_work_tests
    assert "test_rejects_reset_low_only_after_gpio437_cut" in no_work_tests
    assert "test_rejects_missing_independent_rail_decay" in no_work_tests
    assert "test_rejects_cooling_loss_before_decay_confirmation" in no_work_tests
    assert "test_rejects_rail_rebound_after_decay_confirmation" in no_work_tests
    assert "test_rejects_sampling_gap_after_decay_confirmation" in no_work_tests
    assert "test_rejects_cooling_loss_after_decay_confirmation" in no_work_tests
    assert "test_rejects_stale_instrumentation_preflight" in no_work_tests
    assert "test_rejects_missing_bundle_completion_receipt" in no_work_tests
    assert "test_rejects_tampered_embedded_semantic_result" in no_work_tests
    assert "test_rejects_bundle_member_with_external_hard_link" in no_work_tests
    assert "test_rejects_canonical_capture_over_size_limit" in no_work_tests
    assert "test_cli_publishes_external_result_and_success_sentinel" in no_work_tests
    assert (
        "evidence preparation requires Linux/WSL publication semantics"
        in no_work_prepare
    )
    assert (
        "preflight, normalization, raw, and canonical inputs must be ten distinct inodes"
        in no_work_prepare
    )
    assert "host-staged-hard-link-bundle-and-directory-fsync" in no_work_prepare
    assert 'getattr(os, "O_NOFOLLOW", 0)' in no_work_prepare
    assert "os.link(" in no_work_prepare
    assert "_fsync_directory(output)" in no_work_prepare
    assert "S19K_PHASE12_BUNDLE_OK" in no_work_prepare
    assert (
        "test_prepares_exact_self_verifying_v2_bundle" in no_work_prepare_tests
    )
    assert (
        "test_refuses_semantically_unsafe_uart_capture_before_publication"
        in no_work_prepare_tests
    )
    assert "test_refuses_source_inode_alias" in no_work_prepare_tests
    assert "test_refuses_canonical_capture_over_size_limit" in no_work_prepare_tests
    assert "test_cli_publishes_both_required_success_sentinels" in no_work_prepare_tests
    assert (
        "test_refuses_manifest_clock_that_disagrees_with_normalization"
        in no_work_prepare_tests
    )
    assert 'SCHEMA = "dcentos.s19k-phase3-physical-manifest/v2"' in phase3_physical
    assert "phase12._parse_instrument" in phase3_physical
    assert "S19K_PHASE3_PHYSICAL_OK" in phase3_physical
    assert "test_rejects_tail_rebound" in phase3_physical_tests
    assert "def verify_normalization(" in phase12_normalize
    assert "S19K_PHASE12_NORMALIZATION_OK" in phase12_normalize
    assert "test_derives_and_replays_byte_identical_outputs" in phase12_normalize_tests
    assert (
        "test_rejects_rehashed_but_semantically_forged_receipt"
        in phase12_normalize_tests
    )
    assert (
        "test_publishes_exact_three_file_directory_and_cli_sentinel"
        in phase12_normalize_tests
    )
    runbook_convergence_tests = (
        ROOT / "scripts/test_s19k_gauntlet_runbook_convergence.py"
    ).read_text(encoding="utf-8", errors="replace")
    assert (
        "test_current_card_has_exactly_three_pinned_deploy_commands"
        in runbook_convergence_tests
    )
    assert (
        "test_historical_bench_plan_is_non_executable_and_points_forward"
        in runbook_convergence_tests
    )
    assert (
        "test_legacy_bench_pack_is_non_executable_and_points_forward"
        in runbook_convergence_tests
    )
    assert (
        "test_all_legacy_s19k_operator_docs_are_superseded_and_non_executable"
        in runbook_convergence_tests
    )
    assert "test_phase12_tool_pins_match_current_files" in runbook_convergence_tests
    assert (
        "test_obsolete_artifacts_never_appear_in_executable_blocks"
        in runbook_convergence_tests
    )
    assert "socket" not in no_work_verify
    assert "subprocess" not in no_work_verify
    assert "socket" not in phase12_normalize
    assert "subprocess" not in phase12_normalize
    endurance_verify = (ROOT / "scripts/s19k_endurance_verify.py").read_text(
        encoding="utf-8", errors="replace"
    )
    assert 'PLAN_SCHEMA = "dcentos.s19k-tmp-deploy/v12"' in endurance_verify
    assert 'wire[:4] != bytes.fromhex("55AA2136")' in bounded_verify
    assert "def _crc16_itu_t" in bounded_verify
    assert "def _crc5" in bounded_verify
    assert "S19K_BOUNDED_TRANSCRIPT_OK" in bounded_verify
    assert "socket" not in bounded_verify
    assert "subprocess" not in bounded_verify
    assert "admit_s19k_restore_nand_layout" in install_rs
    assert "admit_s19k_restore_ledger_vs_live" in install_rs
    assert "admit_s19k_restore_ledger_identity" in install_rs
    assert "refuse geometry-blind restore" in restore
    assert "covers_recovery=true" in restore
    assert "dcent_am3_mtd5_covers_recovery" in restore
    assert "refuse geometry-blind backup" in install
    assert "board_target_source=$BOARD_TARGET_SOURCE" in install
    assert "record_s19k_backup_board_target" in install
    assert "|| echo $BOARD_PKG_NAME" not in install
    assert (
        "package-sourced backup must not relabel a package target as a live board_target"
        in restore
    )
    assert "exact tuple proof independently re-admitted" in restore
    assert "board_target_source=package" in restore
    assert "refuse_s19k_restore_execute_package_identity" in install_rs
    assert "record_s19k_backup_board_target" in install_rs
    assert "refuse window-offset" in restore
    assert "fw_setenv not required" in restore
    assert "clear_for_flash=false" in restore
    assert "--verify-only" in restore
    assert "nand_env.bak" in install
    assert "BACKUP_LEDGER.txt" in install
    assert "nand_env_sha256=" in install
    assert "mtd5_sha256=" in install
    assert "ABSENT_BRAIINS_L3" in install
    assert "--backup-only" in install

    hal = (ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs").read_text(
        encoding="utf-8"
    )
    # GPIO437 drive parameters now come from the qualified common table.
    # Track-1 retains its exact row for cutoff; a mutable marker cannot change it.
    assert "boot_safe_handoff_s19k_requires_commanded_value_1" in hal
    track1_cut = hal.split("pub fn disable_s19k_track1_psu_checked()", 1)[1].split("\n}", 1)[0]
    assert 'amlogic_gpio437::resolve_drive_recipe("am3-s19k")' in track1_cut
    assert "disable_psu_checked_for_recipe(recipe)" in track1_cut
    assert "read_to_string" not in track1_cut
    standalone_recipe = hal.split("fn amlogic_marker_drive_recipe()", 1)[1].split("\n}", 1)[0]
    assert 'fs::read_to_string("/etc/dcentos/board_target")' in standalone_recipe
    assert "amlogic_gpio437::resolve_drive_recipe(target.trim())" in standalone_recipe
    assert "GPIO437 standalone polarity refused" in standalone_recipe
    gpio437_driver = hal.split("fn drive_psu_checked_at(", 1)[1].split("\n}", 1)[0]
    assert gpio437_driver.index('write(&base.join("direction"), recipe.off_direction())') < gpio437_driver.index('write(&base.join("value"), &raw.to_string())')
    assert "read_psu_active_low_disabled_checked_at(gpio_root, n)?" in gpio437_driver
    assert "read_psu_enabled_on_with_recipe_at(gpio_root, n, recipe)? != on" in gpio437_driver
    assert "gpio437_population_recipe_is_required_and_cannot_be_rebound" in hal
    cfg_rs = (ROOT / "dcentrald/dcentrald-hal/src/platform/config.rs").read_text(
        encoding="utf-8"
    )
    assert "S19K_AMLOGIC_CHAIN2_TTY_CANDIDATES" in cfg_rs
    assert (
        'pub const S19K_AMLOGIC_CHAIN2_TTY_CANDIDATES: [&str; 1] = ["/dev/ttyS3"];'
        in cfg_rs
    )
    s19k_fn = cfg_rs.split("pub fn s19k_amlogic()", 1)[1].split("pub fn ", 1)[0]
    assert 'device: "/dev/ttyS3".to_string()' in s19k_fn
    assert 'device: "/dev/ttyS4".to_string()' not in s19k_fn

    revert = (ROOT / "scripts/revert_to_stock_am3_aml_s19k.sh").read_text(
        encoding="utf-8", errors="replace"
    )
    assert revert.find("gpio437 SafeOff") < revert.find("nandwrite -p -s")
    assert "am3-s19k-active-low" in revert
    assert 'echo 1 > "$SYS/gpio$PWR_GPIO/value"' in revert
    assert "fw_setenv missing" in revert
    assert revert.find("Step 1c: NAND/env tool preflight") < revert.find(
        "nandwrite -p -s"
    )
    assert (
        0
        <= revert.find("missing exact live platform:target identity")
        < revert.find("Type 'REVERT'")
    )
    assert revert.find("IH_ARCH") < revert.find("Type 'REVERT'")
    assert "stock revert requires expected SHA-256" in revert
    assert "ANDROID! boot.img" in revert
    assert "not ARM64 (16)" in revert
    assert "admit_s19k_stock_revert_uimage" in install_rs
    assert "admit_s19k_stock_revert_sha256_required" in install_rs
    assert "tmp_deploy leftover" in revert
    assert "0x05700000/0x05300000" in revert
    assert "admitted local 0x05100000" in revert
    assert "admit_s19k_stock_revert_live_board_target" in install_rs
    assert "refuse_s19k_stock_revert_tmp_deploy_stamp" in install_rs
    assert "admit_s19k_stock_revert_rootfs_offset" in install_rs
    assert "S19K_REVERT_SIZE_SUM_WINDOW" in install_rs
    assert "S19K_LIVE_IDENTITY_ALIASES" in install_rs
    assert "s19k_board_target_is_live_alias" in install_rs
    assert "am3-aml-s19k:am3-s19k" in revert
    assert "am3-aml-s19kpro" not in revert
    assert "am3-s19k|am3-s19kpro|am3-aml-s19kpro" in restore

    stock_cgi = (
        ROOT.parents[1]
        / ""
        / "09-stock-bitmain-current/www_pages_cgi-bin_upgrade.cgi"
    )
    if stock_cgi.is_file():
        cgi = stock_cgi.read_text(encoding="utf-8", errors="replace")
        assert "update.bmu" in cgi
        assert "/usr/sbin/daemonc" in cgi
    daemonc = (
        ROOT.parents[1]
        / ""
        / "09-stock-bitmain-current/usr_sbin_daemonc"
    )
    if daemonc.is_file():
        blob = daemonc.read_bytes()
        assert len(blob) == 7240
        assert blob[:4] == b"\x7fELF"
        assert blob[4] == 1
        assert int.from_bytes(blob[18:20], "little") == 40
        assert b"updateporc.sh" in blob
    cvitek_porc = (
        ROOT.parents[1]
        / ""
        / "unpacked/inner/CVCtrl_extracted/usr/sbin/updateporc.sh"
    )
    if cvitek_porc.is_file():
        porc = cvitek_porc.read_text(encoding="utf-8", errors="replace")
        assert "for CV183X platform update" in porc
        assert "/dev/mmcblk0p1" in porc
        assert "/dev/mmcblk0p3" in porc
        assert "/dev/mmcblk0p4" in porc
        assert "nandwrite" not in porc
        assert cvitek_porc.stat().st_size == 3920
    fileparser = (
        ROOT.parents[1]
        / ""
        / "unpacked/inner/CVCtrl_extracted/usr/bin/FileParser"
    )
    if fileparser.is_file():
        fp = fileparser.read_bytes()
        assert len(fp) == 20184
        assert fp[:4] == b"\x7fELF"
        assert fp[4] == 1
        assert int.from_bytes(fp[18:20], "little") == 40
        assert b"RSA_verify" in fp
        assert b"Not A Btmu File!" in fp
        assert b"input miner_type and bmu miner type donot match!" in fp
    zynq_porc = (
        ROOT.parents[1]
        / ""
        / "Antminer_S19_Pro_zynq7007_BHB42XXX/minerfs_no_header/usr/sbin/updateporc.sh"
    )
    if zynq_porc.is_file():
        zp = zynq_porc.read_text(encoding="utf-8", errors="replace")
        assert "ubiattach" in zp
        assert "/dev/mtd6" in zp
        assert "flash_erase /dev/mtd0 0x1B00000" in zp
        assert "mmcblk" not in zp
        assert zynq_porc.stat().st_size == 2627
    s19k_bmu = (
        ROOT.parents[1]
        / ""
    )
    if s19k_bmu.is_file():
        hdr = s19k_bmu.read_bytes()[:64]
        assert hdr[0] == 0x26
        assert b"-----BEGIN PUBLIC KEY-----" in hdr
        h = int.from_bytes(hdr[2:10], "little")
        assert h == 0xB0909B8BD8F36BFB, hex(h)
        assert s19k_bmu.stat().st_size == 12_792_832
        assert hdr[0x24:0x2E] == b"UBLIC KEY-"
        pay = s19k_bmu.read_bytes()[0x4000:0x4004]
        assert pay == bytes([0xCA, 0x78, 0xC9, 0x44]), pay.hex()
        assert pay != bytes.fromhex("27051956")
        sig4 = s19k_bmu.read_bytes()[0x418:0x41C]
        assert any(x != 0 for x in sig4)
    burn = (
        ROOT.parents[1]
        / ""
    )
    if burn.is_file():
        ini = burn.read_text(encoding="utf-8", errors="replace")
        assert "erase_bootloader" in ini
        assert "=1" in ini
        assert "aml_upgrade_package_enc.img" in ini

    def crc16_itu_t(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    # desk 11d: body 0x54 bytes of type=0x21,len=0x36,job=8,rsvd=1,sno=0,zeros
    body = bytearray(0x54)
    body[0] = 0x21
    body[1] = 0x36
    body[2] = 0x08
    body[3] = 0x01
    crc = crc16_itu_t(bytes(body))
    assert crc == 0x796D, hex(crc)
    # send_work / first-frame log uses the same CCITT-FALSE / ITU-T algorithm.
    hal_crc = (ROOT / "dcentrald/dcentrald-hal/src/serial_chain.rs").read_text(
        encoding="utf-8"
    )
    assert "fn crc16(data: &[u8]) -> u16" in hal_crc
    assert "let mut crc: u16 = 0xFFFF" in hal_crc
    assert "crc = (crc << 1) ^ 0x1021" in hal_crc
    share = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs").read_text(
        encoding="utf-8"
    )
    assert "parse_bm1366_share_from_body" in share
    assert "admit_s19k_share_job_id_in_history" in share
    assert "admit_s19k_share_job_id_in_history" not in serial
    work_frame = serial.split("let work_frame = if is_bm1398", 1)[1][:3500]
    assert "} else if is_bm1366 {" in work_frame
    assert "else if is_bm1366 && passthrough" not in work_frame
    assert "build_s19k_braiins_mining_on_work_body" in work_frame
    assert "qualify_bm1366_braiins_fill_from_body" in share
    assert "hunt_s19k_bm1366_fill_from_admitted_tx_path" in serial
    assert "S19kOutstandingFillTx" in share
    assert "S19K_FILL_TX_SLOTS: usize = 256" in share
    assert "refuse_s19k_fifo32_wrap_as_outstanding_table" in share
    assert "admit_s19k_production_uses_tagged_fill_hunt" in share
    assert "refuse_esp_bip320_as_braiins_fill_version" in share
    assert "refuse_esp_midstate_as_braiins_fill_index" in share
    assert "refuse_esp_flags_redrop_after_fill_hunt" in share
    assert "share.midstate_num = 0" in share
    assert "share.rolled_version =" in share
    assert "s19k_braiins_midstate0_version(base_version, version_be)" in share
    assert "s19k_braiins_uart_version_bits" in share
    assert "refuse_esp_qualify_as_braiins_fill" in share
    assert "SYNTHETIC_BM1366_FILL_WORK2_BODY" in share
    assert "refuse_constructed_fill_hal_body7_wire_as_share" in share
    assert "refuse_constructed_fill_hal_body7_extract_as_share" in share
    assert "admit_constructed_fill_hal_body9_extract_hunts" in share
    assert "refuse_s19k_body7_two_frame_extract_as_shares" in share
    assert "admit_s19k_body7_then_body9_next_frame_hunts" in share
    assert "admit_s19k_body7_residue_then_body9_recovers_next" in rx
    assert "extract_s19k_aa55_bodies_and_residue" in rx
    assert "refuse_s19k_body7_residue_as_frame" in rx
    assert "admit_s19k_body7_two_frame_leaves_residue" in rx
    assert "admit_s19k_body9_two_frame_no_residue" in rx
    assert "hunt_s19k_bm1366_fill_from_tagged_slot" in share
    assert "admit_s19k_production_hunt_uses_body9" in share
    assert "refuse_s19k_production_bm1366_hunt_as_hal_body7" in share
    assert "admit_s19k_production_sets_body_before_first_read" in share
    assert "refuse_hal_default_body7_as_bm1366_first_read" in share
    assert "refuse_s19k_skip_bm1366_open_first_read_at_7" in share
    assert "admit_s19k_production_requires_body9_before_first_read" in share
    assert "admit_s19k_init_bm1366_requires_body9_before_flush" in share
    assert "admit_s19k_init_bm1366_requires_fresh_switched_baud_response" in share
    assert "admit_s19k_init_bm1366_omits_esp_a4" in share
    assert "s19k_fill_job_byte_or_small_core" in share
    assert "s19k_fill_lookup_tx" in share
    assert "S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY" in share
    assert "s19k_fill_lookup_tx_esp_overlay_experimental" in share
    assert "refuse_s19k_fill_overlay_f8_as_fun_0091c0a0" in share
    assert "admit_s19k_production_fill_lookup_is_raw" in share
    assert "no outstanding 21 36 TX in that raw fill job-id slot" in share
    assert "admit_s19k_uart_queue_covers_fill_slots" in share
    assert "refuse_s19k_uart_queue16_as_fill_depth" in share
    assert "admit_s19k_production_bm1366_queue_covers_fill_slots" in share
    assert "S19K_BM1366_HOLD_QUEUE_DEPTH: usize = 4" in share
    assert "admit_s19k_bm1366_hold_queue_uart_paced" in share
    assert "refuse_s19k_live408_256_drop_oldest_as_hold" in share
    assert "admit_s19k_production_bm1366_holds_before_take_dispatch" in share
    assert "admit_s19k_track1_thermal_handoff_unowned" in share
    assert "refuse_s19k_track1_handoff_as_thermal_ready" in share
    assert "admit_s19k_production_bm1366_tx_before_rx" in share
    assert "admit_s19k_init_bm1366_requires_private_owner" in share
    assert "s19k_multi_send_work_tx_required" in discover
    assert "refuse_s3_tx_as_required_send_work" in discover
    assert "admit_s19k_production_multi_send_skips_discover" in discover
    preflight = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs"
    ).read_text(encoding="utf-8")
    assert "refuse_chip_heard_at_115200_as_restored_3m_work_tx" in preflight
    assert "ChipHeardAt115200 is diagnostic; refuse restored-3M work TX" in preflight
    assert (
        "S19kDualBaudSilence::ChipHeardAt115200 | S19kDualBaudSilence::FastUartHeardAt115200"
        in preflight
    )
    assert "admit_s19k_dual_baud_work_tx_for_path" in preflight
    assert "admit_s19k_dual_baud_work_tx_for_path" in serial
    assert "admit_s19k_production_dual_baud_admit_skips_discover" in preflight
    assert "refuse_silence_at_both_bauds_as_chip_proof_3m_tx" in preflight
    assert "refuse_silence_at_both_bauds_as_chip_proof_3m_tx" in serial
    assert "S19kDualBaudWorkTxKind" in preflight
    assert "HandoffProbe is not ChipProofAt3M" in serial
    assert "admit_s19k_production_labels_silence_handoff_probe" in preflight
    assert "refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx" in preflight
    assert "refuse_retry_not_run_or_inconclusive_as_chip_proof_3m_tx" in serial
    assert "refuse_inconclusive_probe_as_chip_proof_3m_tx" in preflight
    assert "InconclusiveProbe is not ChipProofAt3M" in serial
    assert "admit_s19k_production_labels_inconclusive_probe" in preflight
    install_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_install.rs"
    ).read_text(encoding="utf-8")
    assert "S19K_78_MTD2_ANDROID2_OFF: usize = 0x0120_0000" in install_rs
    assert "S19K_78_MTD2_ANDROID2_RAMDISK_SIZE: u32 = 0x0066_2000" in install_rs
    assert "refuse_s19k_mtd2_as_fileparser_source" in install_rs
    assert "refuse_s19k_mtd2_as_uart_trans_source" in install_rs
    assert "admit_s19k_78_mtd2_android_pair" in install_rs
    assert "S19K_AML_UPDATEPORC_IN_HELD_CORPUS: bool = false" in install_rs
    assert "S19K_78_MTD2_AMLSECU_A1_TIME" in install_rs
    assert "S19K_78_MTD2_AMLSECU_A2_TIME" in install_rs
    assert "Mtd2Android1" in install_rs
    assert "admit_s19k_78_mtd2_kernels_identical" in install_rs
    assert "admit_s19k_78_mtd2_a1_second_layout" in install_rs
    assert "2021111922403912" in install_rs
    assert "2021111922403917" in install_rs
    assert "S19K_AMLSECU_KIND_RECOVERY: u32 = 2" in install_rs
    assert "S19K_AMLSECU_KIND_BOOT: u32 = 3" in install_rs
    assert "admit_s19k_amlsecu_kind_matches_ramdisk" in install_rs
    assert "refuse_s19k_factory_recovery_as_mtd2_a1" in install_rs
    assert "refuse_s19k_factory_boot_as_mtd2_a2" in install_rs
    assert "refuse_s19k_20231108_as_mtd2_a2" in install_rs
    assert "admit_s19k_factory_recovery_overflows_78_mtd3" in install_rs
    assert "refuse_s19k_factory_recovery_item_as_78_bos_mtd3" in install_rs
    assert "refuse_s19k_s30v_mtd3_name_as_78_bos" in install_rs
    assert "admit_s19k_factory_recovery_second_layout" in install_rs
    assert "S19K_FACTORY_RECOVERY_OVERFLOW_VS_78_MTD3: u64 = 821_760" in install_rs
    assert 'S19K_78_MTD3_NAME: &str = "stock_config"' in install_rs
    assert "S19K_FACTORY_RECOVERY_SECOND_OFF: usize = 0x5C_1000" in install_rs
    assert "S19K_FACTORY_PARTITION_SUBS" in install_rs
    assert "S19K_FACTORY_RESTOCK_MISSING" in install_rs
    assert "admit_s19k_factory_partition_subs" in install_rs
    assert "admit_s19k_factory_pack_has_no_restock_partitions" in install_rs
    assert "refuse_s19k_factory_pack_as_s30v_restock" in install_rs
    assert "refuse_s19k_factory_conf_as_partition_config" in install_rs
    assert "refuse_s19k_factory_partition_sub_as_restock_slot" in install_rs
    assert "admit_s19k_factory_boot_size_fits_78_mtd2" in install_rs
    assert "refuse_s19k_factory_boot_item_as_78_mtd2_nandwrite" in install_rs
    assert "refuse_s19k_s30v_boot_as_78_mtd2" in install_rs
    assert "admit_s19k_android_name_empty" in install_rs
    assert "admit_s19k_factory_boot_recovery_kernels_identical" in install_rs
    assert "refuse_s19k_factory_recovery_second_as_boot_second" in install_rs
    assert "refuse_s19k_factory_recovery_second_as_meson1_enc" in install_rs
    assert (
        "S19K_FACTORY_RECOVERY_SECOND_HEAD: [u8; 4] = [0x68, 0xCA, 0xF5, 0xA1]"
        in install_rs
    )
    assert (
        "S19K_FACTORY_BOOT_KERNEL_HEAD: [u8; 4] = [0x30, 0x9C, 0xFC, 0x10]"
        in install_rs
    )
    assert 'S19K_78_MTD3_UBI_VOL_NAME: &[u8] = b"config_data"' in install_rs
    assert "S19K_78_MTD3_VTBL_NAME_OFF: usize = 397_328" in install_rs
    assert "admit_s19k_78_mtd3_ubi_volume_name" in install_rs
    assert "refuse_s19k_78_mtd3_ubi_vol_as_proc_mtd_name" in install_rs
    assert "refuse_s19k_78_nand_env_as_updateporc" in install_rs
    assert "refuse_s19k_upgrade_cgi_as_updateporc_script" in install_rs
    assert "S19K_78_MTD3_VTBL_PEB4_OFF: usize = 528_384" in install_rs
    assert "S19K_78_MTD3_VTBL_PEB4_NAME_OFF: usize = 528_400" in install_rs
    assert "admit_s19k_78_mtd3_vtbl_peb4_name" in install_rs
    assert "admit_s19k_78_mtd3_vtbl_copies_identical" in install_rs
    assert "refuse_s19k_78_mtd3_single_vtbl_peb_as_complete" in install_rs
    assert "refuse_s19k_upgrade_clear_as_updateporc_script" in install_rs
    init_seq = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "admit_s19k_stock_fastuart_28_write_as_leave_115200" in init_seq
    assert "refuse_esp_miscctrl_default_baud_as_fastuart_28" in init_seq
    assert "ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE: u32 = 0x0000_7A31" in init_seq
    assert "admit_s19k_production_track1_reads_not_writes_fastuart_28" in init_seq
    assert "BosminerBm1366StockInitEvidenceStage" in init_seq
    assert "BOSMINER_BM1366_STOCK_INIT_DISPATCH" in init_seq
    assert "admit_bosminer_bm1366_stock_init_order_static" in init_seq
    assert "refuse_bosminer_bm1366_stock_init_manifest_as_executable" in init_seq
    assert "[0x8000_8540, 0x8000_8020, 0x8000_82AA]" in init_seq
    assert "bosminer_bm1366_stock_reg0c_plan" in init_seq
    assert "bosminer_bm1366_stock_finalize_plan" in init_seq
    assert "bosminer_bm1366_stock_set_address_plan" in init_seq
    assert "bosminer_bm1366_stock_generic_core3c_value" in init_seq
    assert "BOSMINER_BM1366_STOCK_INIT_EXECUTION_SLOT_ORDER" in init_seq
    assert "[0x40, 0x48, 0x28, 0x38, 0x50, 0x78, 0x30]" in init_seq
    assert "BOSMINER_BM1366_STOCK_UART_RELAY_DESCRIPTOR_FILE_OFF" in init_seq
    assert "AnalogMuxIoDriverAndDomainRelay" in init_seq
    assert "BOSMINER_HASHCHAIN_START_WRAPPER_FN_VA: u64 = 0x0071_78F4" in init_seq
    assert "BOSMINER_HASHCHAIN_START_POLL_FN_VA: u64 = 0x0071_9868" in init_seq
    assert "BOSMINER_HASHCHAIN_START_RETRY_BUDGET: u8 = 4" in init_seq
    assert "BOSMINER_HASHCHAIN_START_RETRY_DELAY_NS: u64 = 10_000_000_000" in init_seq
    assert "BOSMINER_HASHCHAIN_INIT_TIMEOUT_NS: u64 = 10_000_000_000" in init_seq
    assert "BOSMINER_BM1366_STOCK_POST_BAUD_PATH" in init_seq
    assert "refuse_bosminer_post_baud_path_as_fresh_validation" in init_seq
    assert "classify_s19k_post_baud_observation" in init_seq
    assert "s19k_post_baud_work_tx_disposition" in init_seq
    assert "admit_s19k_native_work_tx_after_post_baud" in init_seq
    assert "FailClosedRollbackBeforeWorkTx" in init_seq
    assert "FreshSwitchedBaudResponseAdmitted" in init_seq
    assert "refuse_native_post_baud_pass_as_production" in init_seq
    assert "admit_s19k_native_init_program_lacks_post_baud_response_barrier" in init_seq
    assert "admit_s19k_production_native_transport_requires_joined_owner" in init_seq
    assert "BOSMINER_HASHCHAIN_TERMINAL_FAILURE_CALLS" in init_seq
    assert "BOSMINER_HASHCHAIN_START_FAILURE_POLICY" in init_seq
    assert "BOSMINER_S19K_DEPARTURE_LIFECYCLE_CAPTURE" in init_seq
    assert "BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_FN_VA" in init_seq
    assert "BOSMINER_HASHCHAIN_FAN_READY_SNAPSHOT_STATUS_BYTE_OFFSET: u16 = 0x016C" in init_seq
    assert "BOSMINER_HASHCHAIN_FAN_PENDING_WAIT_NS: u64 = 1_000_000_000" in init_seq
    assert "BOSMINER_HASHCHAIN_PLATFORM_ORDER" in init_seq
    assert "FanReadinessGateOneSecondPendingCadence" in init_seq
    assert "BOSMINER_AM3_AML_PLATFORM_CODE: u8 = 3" in init_seq
    assert "BOSMINER_AM3_AML_FILTERED_BUILDERS" in init_seq
    assert "BOSMINER_S19K_NOPIC_CANDIDATE_INDEX: u8 = 8" in init_seq
    assert "Antminer S19K Pro NoPic" in init_seq
    assert "BHB56902" in init_seq
    assert "admit_bosminer_s19k_platform_resolution_static" in init_seq
    assert "BOSMINER_CHAIN_DESCRIPTOR_ARC_EVIDENCE" in init_seq
    assert "BOSMINER_CHAIN_DESCRIPTOR_ARC_LINEAGE_PINS" in init_seq
    assert "BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_PINS" in init_seq
    assert "RawRecordOwnsLiveHashchainManagerDispatchPairIsPrestaged" in init_seq
    assert 'BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_NAME: &str = "HashchainManager"' in init_seq
    assert "BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_VTABLE_VA: u64 = 0x019F_B178" in init_seq
    assert "tuner_object_bytes: BOSMINER_TUNER_OBJECT_BYTES" in init_seq
    assert "descriptor_arc_offset: BOSMINER_CHAIN_DESCRIPTOR_ARC_OFFSET" in init_seq
    assert "source_owner_offset: BOSMINER_TUNER_SOURCE_OWNER_OFFSET" in init_seq
    assert "source_arc_vec_data_offset: BOSMINER_SOURCE_ARC_VEC_DATA_OFFSET" in init_seq
    assert "source_arc_companion_offset: BOSMINER_SOURCE_ARC_COMPANION_OFFSET" in init_seq
    assert "descriptor_build_fn_va: BOSMINER_CHAIN_DESCRIPTOR_BUILD_FN_VA" in init_seq
    assert "derived_vec_data_offset: BOSMINER_TUNER_DERIVED_DESCRIPTOR_VEC_DATA_OFFSET" in init_seq
    assert "callback_fn_va: BOSMINER_TUNER_CHAIN_CALLBACK_FN_VA" in init_seq
    assert "concrete_arc_allocation_bytes: Some(BOSMINER_LIVE_CHAIN_ARC_ALLOCATION_BYTES)" in init_seq
    assert "concrete_arc_payload_bytes: Some(BOSMINER_LIVE_CHAIN_ARC_PAYLOAD_BYTES)" in init_seq
    assert "concrete_arc_payload_type_name: Some(BOSMINER_LIVE_CHAIN_PAYLOAD_TYPE_NAME)" in init_seq
    assert "admit_bosminer_chain_descriptor_arc_lineage_static" in init_seq
    assert "BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_EVIDENCE" in init_seq
    assert "BOSMINER_HASHCHAIN_LIFECYCLE_RECEIVER_LINEAGE_PINS" in init_seq
    assert (
        "PayloadPrestageProviderCandidatesLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic"
        in init_seq
    )
    assert "raw_record_arc_offset: 0x0510" in init_seq
    assert "arc_allocation_bytes: 0x0570" in init_seq
    assert "arc_payload_bytes: 0x0560" in init_seq
    assert 'arc_payload_type_name: "HashchainManager"' in init_seq
    assert "item_triggered_listener_offset: 0x30" in init_seq
    assert "item_payload_offset: 0x0060" in init_seq
    assert 'listener_type_name: "triggered::Listener"' in init_seq
    assert "listener_clone_fn_va: 0x00BB_D3DC" in init_seq
    assert "listener_next_id_offset: 0x48" in init_seq
    assert "outer_cloned_listener_offset: 0x03D0" in init_seq
    assert "state_listener_input_offset: 0x0360" in init_seq
    assert "state_payload_input_offset: 0x0388" in init_seq
    assert "state_reused_listener_self_slot_offset: 0x03A0" in init_seq
    assert "state_dispatch_self_slot_offset: 0x03B8" in init_seq
    assert "stack_listener_inner_offset: 0x48" in init_seq
    assert "payload_hook_trait_data_offset: 0x0230" in init_seq
    assert "payload_hook_trait_vtable_offset: 0x0238" in init_seq
    assert "payload_hook_method_slot: 0x18" in init_seq
    assert "payload_hook_dispatch_va: 0x0071_A51C" in init_seq
    assert "payload_hook_method_vas: [0x0070_539C, 0x0070_57FC]" in init_seq
    assert "payload_hook_is_noop: true" in init_seq
    assert "prestage_vec_source_offset: 0x10" in init_seq
    assert "prestage_vec_clone_fn_va: 0x012D_276C" in init_seq
    assert "prestaged_data_offset: 0x0538" in init_seq
    assert "stack_prestaged_data_offset: 0x0B10" in init_seq
    assert "stack_prestaged_dispatch_table_offset: 0x0B18" in init_seq
    assert "stack_listener_inner_overwrite_va: 0x0071_A528" in init_seq
    assert "local_object_prefix_copy_bytes: 0x01E0" in init_seq
    assert "local_object_trait_data_offset: 0x0210" in init_seq
    assert "local_object_dispatch_table_offset: 0x0218" in init_seq
    assert "concrete_dispatch_data: None" in init_seq
    assert "concrete_dispatch_table_va: None" in init_seq
    assert "concrete_method_va: None" in init_seq
    assert "admit_bosminer_hashchain_lifecycle_receiver_lineage_static" in init_seq
    assert "BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_EVIDENCE" in init_seq
    assert "BOSMINER_CLONED_TABLE_TWO_SLOT_SEQUENCE_PINS" in init_seq
    assert "admit_bosminer_cloned_table_two_slot_sequence_static" in init_seq
    assert "refuse_bosminer_cloned_table_slot_0x28_as_terminal_dispatch" in init_seq
    assert "refuse_bosminer_cloned_table_slot_0x50_as_same_pair" in init_seq
    assert "refuse_bosminer_cloned_table_slot_0x20_as_cloned_p10_table" in init_seq
    assert "slot: 0x48" in init_seq
    assert "fail_imm: 5" in init_seq
    assert "refused_slot_0x50_source_offset: 0x03C0" in init_seq
    assert "distinct_pair_table_offset: 0x0228" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_PRODUCER_EVIDENCE" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_PRODUCER_LINEAGE_PINS" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_CODE3_CANDIDATE_PINS" in init_seq
    assert "BOSMINER_PRESTAGE_VEC_BOUNDARY_PINS" in init_seq
    assert (
        "Code3FirstSuccessProviderCandidatesAndPrestageLineageResolvedRuntimeSelectionBytesAndFinalMethodRemainDynamic"
        in init_seq
    )
    assert "NoOpRetainsPrestagedPair" in init_seq
    assert "BOSMINER_ANTMINER_BUILDER_VTABLE_VA: u64 = 0x019A_C828" in init_seq
    assert "BOSMINER_ANTMINER_PROVIDER_VTABLE_VA: u64 = 0x019A_C978" in init_seq
    assert "BOSMINER_BRAIINS_FIXTURE_PROVIDER_VTABLE_VA: u64 = 0x019A_C9B8" in init_seq
    assert "BOSMINER_ANTMINER_LIFECYCLE_HOOK_METHOD_VA: u64 = 0x0070_539C" in init_seq
    assert "BOSMINER_BRAIINS_FIXTURE_LIFECYCLE_HOOK_METHOD_VA: u64 = 0x0070_57FC" in init_seq
    assert "BOSMINER_ANTMINER_CANDIDATE_VALIDATE_METHOD_VA: u64 = 0x0070_A82C" in init_seq
    assert "BOSMINER_BRAIINS_FIXTURE_CANDIDATE_VALIDATE_METHOD_VA: u64 = 0x0070_A824" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_REGISTRY_SELECT_FN_VA: u64 = 0x0079_4C48" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_REGISTRY_ENTRY_METHOD_SLOT: u8 = 0x30" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_SELECTED_PAIR_OFFSETS: [u16; 2] = [0x0450, 0x0458]" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_CHILD_METHOD_SLOT: u8 = 0x20" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_MATERIALIZE_FN_VA: u64 = 0x00B2_58B8" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_PREFIX_COPY_BYTES: u16 = 0x0660" in init_seq
    assert (
        "BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_STATE_OFFSET: u16 = 0x2940"
        in init_seq
    )
    assert (
        "BOSMINER_PRESTAGE_REFUTED_RUNTIME_OBJECT_TAIL_OFFSETS: [u8; 2] = [0x50, 0x58]"
        in init_seq
    )
    assert "BOSMINER_PRESTAGE_REFUTED_ROTATED_TAIL_OFFSET: u8 = 0x50" in init_seq
    assert "BOSMINER_PRESTAGE_B90C_ENTRY_PREFIX_OFFSET: u8 = 0x60" in init_seq
    assert "BOSMINER_PRESTAGE_B90C_ENTRY_VEC_OFFSET: u8 = 0x70" in init_seq
    assert (
        "BOSMINER_PRESTAGE_B90C_SNAPSHOT_PREFIX_OFFSET: u16 = 0x0730"
        in init_seq
    )
    assert "BOSMINER_PRESTAGE_B90C_OWNED_PREFIX_OFFSET: u16 = 0x0E10" in init_seq
    assert "BOSMINER_PRESTAGE_B879_INPUT_PREFIX_OFFSET: u8 = 0x00" in init_seq
    assert (
        "BOSMINER_PRESTAGE_B879_SNAPSHOT_PREFIX_OFFSET: u16 = 0x06E0"
        in init_seq
    )
    assert (
        "BOSMINER_PRESTAGE_B879_CLONE_STACK_OFFSET: u16 = 0x0BF0"
        in init_seq
    )
    assert (
        "BOSMINER_PRESTAGE_B879_CLONE_FORWARD_CAP_DATA_STACK_OFFSET: u16 = 0x0BD0"
        in init_seq
    )
    assert (
        "BOSMINER_PRESTAGE_B879_CLONE_FORWARD_LEN_STACK_OFFSET: u16 = 0x0BE0"
        in init_seq
    )
    assert (
        "BOSMINER_PRESTAGE_B879_CLONE_LATER_OVERWRITE_FN_VA: u64 = 0x00B6_00A4"
        in init_seq
    )
    assert "BOSMINER_PRESTAGE_PAYLOAD_PREFIX_SOURCE_STACK_OFFSET: u16 = 0x0A20" in init_seq
    assert (
        "BOSMINER_PRESTAGE_PAYLOAD_VEC_STACK_OFFSETS: [u16; 3] = [0x0A30, 0x0A38, 0x0A40]"
        in init_seq
    )
    assert "BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_STACK_OFFSET: u16 = 0x0C10" in init_seq
    assert "BOSMINER_PRESTAGE_PAYLOAD_PREFIX_STAGING_BYTES: u16 = 0x0190" in init_seq
    assert "BOSMINER_PRESTAGE_PAYLOAD_PREFIX_CONSTRUCTOR_ARG_INDEX: u8 = 7" in init_seq
    assert "BOSMINER_PRESTAGE_B90C_CLONE_REACHES_PAYLOAD_PREFIX: bool = true" in init_seq
    assert (
        "BOSMINER_PRESTAGE_PROVIDER_PAIR_STATE_OFFSETS: [u16; 2] = [0x04B0, 0x04B8]"
        in init_seq
    )
    assert "BOSMINER_PRESTAGE_PROVIDER_METHOD_SLOT: u8 = 0x18" in init_seq
    assert "BOSMINER_PRESTAGE_PROVIDER_PRESERVED_DATA_STATE_OFFSET: u16 = 0x0EA8" in init_seq
    assert "BOSMINER_PRESTAGE_PROVIDER_DATA_CLONE_FN_VA: u64 = 0x0046_8B24" in init_seq
    assert "BOSMINER_PRESTAGE_PROVIDER_PREFIX_CLONE_FN_VA: u64 = 0x0046_85AC" in init_seq
    assert "BOSMINER_PRESTAGE_PROVIDER_VEC_OFFSET: u8 = 0x10" in init_seq
    assert "BOSMINER_PRESTAGE_MATERIALIZER_INPUT_PREFIX_BYTES: u16 = 0x02A0" in init_seq
    assert "BOSMINER_PRESTAGE_MATERIALIZED_PREFIX_BYTES: u16 = 0x0660" in init_seq
    assert "BOSMINER_HASHCHAIN_MANAGER_VEC_OFFSETS: [u8; 3] = [0x10, 0x18, 0x20]" in init_seq
    assert "BOSMINER_HASHCHAIN_MANAGER_DROP_FN_VA: u64 = 0x00B7_5924" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_LISTENER_DISPATCH_VA: u64 = 0x00B8_7AE4" in init_seq
    assert "BOSMINER_PAYLOAD_HOOK_CANDIDATE_VALIDATE_DISPATCH_VA: u64 = 0x00B8_96F4" in init_seq
    assert "admit_bosminer_payload_hook_producer_lineage_static" in init_seq
    assert (
        "refuse_bosminer_hashchain_lifecycle_receiver_as_concrete_gpio_authority"
        in init_seq
    )
    assert "BOSMINER_FAN_STATUS_FIELDS" in init_seq
    assert "required_fans_above_min_speed" in init_seq
    assert "BOSMINER_FAN_STATUS_SERIALIZER_PINS" in init_seq
    assert "BOSMINER_S19K_DEPARTURE_FAN_POLICY" in init_seq
    assert "resolved_config_observations: 8" in init_seq
    assert "min_fans: 0" in init_seq
    assert "min_fan_rpm: 2_000" in init_seq
    assert "power_enable_to_reset" in init_seq
    assert "admit_bosminer_hashchain_lifecycle_static" in init_seq
    assert "admit_bosminer_fan_status_schema_static" in init_seq
    assert "refuse_bosminer_stock_lifecycle_as_safeoff_proof" in init_seq
    assert "refuse_bosminer_s19k_fan_gate_as_positive_cooling_proof" in init_seq
    assert "refuse_bosminer_telemetry_cadence_as_retry_delay" in init_seq
    init_order_tool = ROOT / "scripts/s19k_verify_bosminer_bm1366_init_order.py"
    init_order_source = init_order_tool.read_text(encoding="utf-8")
    assert "EXPECTED_SHA256" in init_order_source
    assert "native cold-init execution remains refused" in init_order_source
    init_order_spec = importlib.util.spec_from_file_location(
        "s19k_verify_bosminer_bm1366_init_order", init_order_tool
    )
    assert init_order_spec is not None and init_order_spec.loader is not None
    init_order_mod = importlib.util.module_from_spec(init_order_spec)
    sys.modules[init_order_spec.name] = init_order_mod
    init_order_spec.loader.exec_module(init_order_mod)
    held_bosminer = (
        ROOT.parent.parent
        / ""
    )
    if held_bosminer.is_file():
        init_order_lines = init_order_mod.verify(held_bosminer)
        assert any("slot=0x40" in line for line in init_order_lines)
        assert any("slot=0x28" in line for line in init_order_lines)
        assert any("reg0c=index0:0x80000000" in line for line in init_order_lines)
        assert any("UartRelay:pairs-domain10..0" in line for line in init_order_lines)
        assert any(
            "EXECUTION_ORDER +0x40->+0x48->+0x28->+0x38->+0x50->+0x78->+0x30" in line
            for line in init_order_lines
        )
        assert any("inactive=3x/300000000ns" in line for line in init_order_lines)
        assert any(
            "ASIC FastUART broadcast -> host baud switch" in line
            for line in init_order_lines
        )
        assert any(
            "POST_BAUD_VALIDATION stock=none-dedicated" in line
            and "DCENT=fresh-response-required" in line
            for line in init_order_lines
        )
        assert any(
            "LIFECYCLE retry-budget=4 inter-attempt=10000000000ns init-timeout=10000000000ns"
            in line
            and "fan-pending-cadence=1000000000ns" in line
            for line in init_order_lines
        )
        assert any(
            "PLATFORM_ORDER observed-PSU-enable -> exact-reset-dispatch" in line
            and "exact-fan-ready-gate/1s-pending-recheck -> Fans-OK" in line
            and "exact-init-dispatch/10s-timeout" in line
            for line in init_order_lines
        )
        assert any(
            "PLATFORM_RESOLUTION runtime=am3-aml/code3" in line
            and "builders=[Antminer@vtable0x019ac828,Braiins Fixture@vtable0x019ac880]" in line
            and "first-success-runtime-dependent" in line
            and "Antminer-inventory-candidate[8]=Antminer S19K Pro NoPic/BHB56902" in line
            and "Fixture-provider-vtable0x019ac9b8" in line
            for line in init_order_lines
        )
        assert any(
            "CHAIN_DESCRIPTOR_ARC source=owner@tuner+0x950" in line
            and "Arc-Vec@+0x6a8/+0x6b0" in line
            and "builder=FUN_007e9c24" in line
            and "A+0x568-enabled/A+0x558-companion" in line
            and "descriptor=0x38/Arc@+0x20/+0x28" in line
            and "primary-Vec@+0x7b8/+0x7c0/+0x7c8" in line
            and "derived-Vec@+0x7d0/+0x7d8/+0x7e0" in line
            and "callback=+0x978/FUN_0070a168@0x00662554/x0-Vec" in line
            and "raw+0x510/+0x518=A/+0x558" in line
            and "live-Arc=0x570/align0x10/header0x10/payload0x560" in line
            and "payload-type=HashchainManager/vtable0x019fb178" in line
            and "constructor=FUN_00b5c168/prefix-copy=0x1f0" in line
            and "lifecycle-provider-candidates=[Antminer@0x019ac978,Braiins Fixture@0x019ac9b8]" in line
            and "hook+0x18=[FUN_0070539c,FUN_007057fc]-both-no-op" in line
            and "runtime-winner/prestaged-dispatch-table=dynamic" in line
            for line in init_order_lines
        )
        assert any(
            "LIFECYCLE_RECEIVER raw-record=0x570/separate-Arc@+0x510" in line
            and "live-Arc=0x570/align0x10/payload=P=A+0x10" in line
            and "item-lanes=triggered::Listener@+0x30/P@+0x60" in line
            and "Listener clone=FUN_00bbd3dc" in line
            and "Listener.inner saved@sp+0x48/consumed@0x0071a2d8" in line
            and "prestage=FUN_012d276c(clone-P+0x10-Vec)/data=P+0x538" in line
            and "B90c lane=entry+0x70/prefix+0x60/snapshot+0x730/owned+0xe10" in line
            and "b879-input+0x00/snapshot+0x6e0/clone+0x10" in line
            and "forward-cap/data@sp+0xbd0,len@sp+0xbe0" in line
            and "manager-prefix-Vec@sp+0xa30/+0xa38/+0xa40-before-later-overwrite" in line
            and "prefix=sp+0xa20 -> sp+0xc10/0x190 -> constructor-x7" in line
            and "P+0x10/+0x18/+0x20" in line
            and "pair@sp+0xb10/+0xb18" in line
            and "provider-vtables=[0x019ac978,0x019ac9b8] slot+0x18@0x0071a51c" in line
            and "[FUN_0070539c,FUN_007057fc](both-no-op)" in line
            and "sp+0x48-overwrite@0x0071a528 -> local+0x210/+0x218" in line
            and "+0x3a0 overwritten with local self@0x0071ab58" in line
            and "prestaged-table slot+0x28@0x0071b098 then same-pair slot+0x48@0x0071b128" in line
            and "slot+0x50=LDP-from-overwritten+0x3c0-not-cloned-pair" in line
            and "slot+0x20=distinct-local+0x220/+0x228" in line
            and "P lane=outer+0x50/+0x3f8/nested+0x388/+0x370" in line
            and "P+0x1c0-dispatch-join=refuted" in line
            and "builder-vtables=[0x019ac828,0x019ac880]/runtime-winner=dynamic" in line
            and "P+0x10-provider-lineage=resolved/runtime-bytes+final-method=dynamic" in line
            and "initial-payload+0x200=Vec-metadata" in line
            for line in init_order_lines
        )
        assert any(
            "PAYLOAD_HOOK_PRODUCER registry=FUN_00794c48" in line
            and "entry0x10/slot+0x30" in line
            and "calls=[0x00471804,0x004c1fc8,0x004ef814]" in line
            and "selected@parent+0x450/+0x458 -> FUN_005614c0" in line
            and "child=parent+0xd40/capture+0x4b0/+0x4b8" in line
            and "slot+0x20@[0x0047ab50,0x004cb318,0x004f8b64]" in line
            and "provider-pair+0x4b0/+0x4b8 slot+0x18" in line
            and "provider-data@state+0xea8" in line
            and "FUN_00468b24/FUN_004685ac clone-provider-data-Vec+0x10" in line
            and "FUN_00b258b8 input-prefix0x2a0 -> materialized-prefix0x660" in line
            and "state+0xf10/+0x1570/+0x1be0/+0x2240" in line
            and "runtime-object-footer-separate" in line
            and "B90c entry+0x70/prefix+0x60" in line
            and "snapshot+0x730/owned+0xe10" in line
            and "FUN_00b87980 input+0x00/snapshot+0x6e0/clone+0x10" in line
            and "sp+0xbf0 -> forwarded-to-prefix-Vec" in line
            and "constructor-x7 -> HashchainManager-P+0x10" in line
            and "materialized+0x4c0/+0x4c8" in line
            and "working+0xba0/+0xba8 slot+0x18@0x00b87ae4" in line
            and "selected+0xe20/+0xe28 slot+0x28@0x00b896f4" in line
            and "HashchainManager-P+0x230/+0x238" in line
            and "code3-builder-vtables=[0x019ac828,0x019ac880]" in line
            and "provider-vtables=[0x019ac978,0x019ac9b8]" in line
            and "validators=[FUN_0070a82c,FUN_0070a824]" in line
            and "child-methods=[FUN_007053a0,FUN_00705800]" in line
            and "child-results=[0x340@0x019ace50,0x300@0x019ace70]" in line
            and "hook+0x18=[FUN_0070539c,FUN_007057fc](both-no-op)/runtime-winner=dynamic" in line
            and "prestaged={data:P+0x538,table:clone(P+0x10).data}" in line
            and "P+0x10-provider-lineage=resolved/runtime-table+concrete-slot-methods=dynamic" in line
            for line in init_order_lines
        )
        assert any(
            "CLONED_TABLE_DISPATCH pair=+0x210/+0x218 slot+0x28@0x0071b098" in line
            and "slot+0x48@0x0071b128" in line
            and "fail-imm=4 then" in line
            and "fail-imm=5" in line
            and "slot+0x50=LDP-from-overwritten+0x3c0-refused" in line
            and "slot+0x20=distinct-+0x220/+0x228-refused-as-P+0x10" in line
            and "concrete-method=None" in line
            for line in init_order_lines
        )
        assert any(
            "FAN_STATUS schema=num_fans_at_ok_speed:u64@0x00" in line
            and "required_fans_above_min_speed:bool@0x11" in line
            and "gate-watch-byte=+0x16c/unjoined" in line
            for line in init_order_lines
        )
        assert any(
            "FAN_POLICY observed-configs=8 fixed-speed=100 min-fans=0" in line
            and "min-rpm=2000 rpm-epsilon=600" in line
            and "max-fans=4 start-cooldown=100" in line
            for line in init_order_lines
        )
        assert any(
            "FAN_GATE_AUTHORITY refused=min-fans-zero/no-positive-fan-proof" in line
            and "independent-positive-count+fresh-per-channel-RPM/tach-required" in line
            and "tach-motion-is-not-physical-airflow-rate-proof" in line
            for line in init_order_lines
        )
        assert any(
            "CAPTURE_OBSERVED complete-dual-cycles=8 chain3-partial=1 per-chain-success=17"
            in line
            and "power-enable-to-reset=2060449..2071063us" in line
            for line in init_order_lines
        )
        assert any(
            "FAILURE_POLICY retry=wait10s->new-inner-reset" in line
            and "terminal-wrapper=retained-error/no-BLR/no-local-reset-or-APW" in line
            for line in init_order_lines
        )
        assert any("telemetry-1s-is-not-retry" in line for line in init_order_lines)
        assert any(
            "reset lineage is not GPIO/electrical authority" in line
            for line in init_order_lines
        )
        assert any(
            "stock lifecycle is not SafeOff proof" in line for line in init_order_lines
        )
        assert init_order_lines[-1].endswith(
            "native cold-init execution remains refused"
        )
    apw_stock = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_apw121215f_stock.rs"
    ).read_text(encoding="utf-8")
    assert (
        "S19K_APW121215F_REPORTED_VERSION_BYTES: [u8; 3] = [0x75, 0x76, 0x77]"
        in apw_stock
    )
    assert "S19K_APW121215F_TRAIT_ALLOC_FN_VA" in apw_stock
    assert "BOSMINER_PSU_SERVICE_ASYNC_STATE_MACHINE_FN_VA" in apw_stock
    assert "S19K_STOCK_PSU_ENABLE_DISPATCH" in apw_stock
    assert "StockPsuEnableDispatchStep::InvokePsuTraitSlot(0x20)" in apw_stock
    assert "refuse_stock_psu_enable_dispatch_as_electrical_rail_proof" in apw_stock
    assert (
        "refuse_stock_psu_enable_and_hashboard_reset_as_one_static_transaction"
        in apw_stock
    )
    assert "S19K_STOCK_APW_DISABLE_SEQUENCE" in apw_stock
    assert "StockApwLifecycleStep::AwaitI2cWorkerBarrier" in apw_stock
    assert "StockApwDisableWorkerStep::AcknowledgeWithoutApwBackendCall" in apw_stock
    assert "S19K_STOCK_APW_DISABLE_WORKER_MESSAGE_TAG: u8 = 3" in apw_stock
    assert "S19K_STOCK_APW_I2C_WORKER_TAG3_HANDLER_VA" in apw_stock
    assert "StockApwLifecycleStep::WritePsuControlOutput(true)" in apw_stock
    assert "S19K_STOCK_PSU_CONTROL_INITIAL_STATE: bool = true" in apw_stock
    assert "S19K_STOCK_SYSFS_PIN_OUT_WRITE_FN_VA" in apw_stock
    assert "S19K_STOCK_APW_WORD_CHECKSUM_MODE: u8 = 1" in apw_stock
    assert "s19k_stock_apw_wire_checksum" in apw_stock
    assert "S19K_STOCK_APW_SET_VOLTAGE_POLICY" in apw_stock
    assert "write_to_read_delay_ms: 350" in apw_stock
    assert "retry_count: 3" in apw_stock
    assert "retry_delay_s: 2" in apw_stock
    assert "classify_s19k_rail_cut" in apw_stock
    assert "admit_s19k_terminal_safeoff_evidence" in apw_stock
    assert "MissingIndependentRailOrCurrentDecay" in apw_stock
    assert "pub mod s19k_apw121215f_stock;" in (
        ROOT / "dcentrald/dcentrald-common/src/lib.rs"
    ).read_text(encoding="utf-8")
    apw_tool = ROOT / "scripts/s19k_verify_bosminer_apw121215f.py"
    apw_tool_source = apw_tool.read_text(encoding="utf-8")
    assert "EXPECTED_SHA256" in apw_tool_source
    assert "stock disable is not VerifiedRailCut" in apw_tool_source
    apw_spec = importlib.util.spec_from_file_location(
        "s19k_verify_bosminer_apw121215f", apw_tool
    )
    assert apw_spec is not None and apw_spec.loader is not None
    apw_mod = importlib.util.module_from_spec(apw_spec)
    sys.modules[apw_spec.name] = apw_mod
    apw_spec.loader.exec_module(apw_mod)
    if held_bosminer.is_file():
        apw_lines = apw_mod.verify(held_bosminer)
        assert any("reported-versions=0x75,0x76,0x77" in line for line in apw_lines)
        assert len(apw_mod.INSTRUCTION_PINS) == 114
        assert any("compatibility-discriminator=4" in line for line in apw_lines)
        assert any(
            "PSU_ENABLE_DISPATCH state-machine=0x00b8be50" in line
            and "trait-slot=+0x20" in line
            for line in apw_lines
        )
        assert any(
            "allocator=0x0090dfc0 -> vtable=0x019c8e78" in line
            and "slot+0x20=0x0090fcc8/poll=0x0090fd70" in line
            for line in apw_lines
        )
        assert any("PSU_CONTROL open-PinOut(initial=1)" in line for line in apw_lines)
        assert any("enqueue-worker-tag=3" in line for line in apw_lines)
        assert any("await-worker-ack" in line for line in apw_lines)
        assert any("no-APW-backend-call" in line for line in apw_lines)
        assert any("worker-continues" in line for line in apw_lines)
        assert any("write-logical-1" in line for line in apw_lines)
        assert any("mode=1 little-endian-word-additive" in line for line in apw_lines)
        assert any("other-modes byte-additive" in line for line in apw_lines)
        assert any("write-to-read=350ms" in line for line in apw_lines)
        assert any("maximum-attempts=4" in line for line in apw_lines)
        assert any(
            "static=separate-exact-futures/no-single-recovered-transaction" in line
            for line in apw_lines
        )
        assert any(
            "controller-dispatch+logical-GPIO-write-is-not-voltage-rise" in line
            for line in apw_lines
        )
        assert apw_lines[-1].endswith("stock disable is not VerifiedRailCut")
    assert (
        "send_write_reg_broadcast_bm1397plus(PUBLIC_FASTUART_REG"
        not in serial.split("PASSTHROUGH BM1366", 1)[1].split(
            "} else if passthrough", 1
        )[0]
    )
    assert "s19k_work_tx_required_after_enum" in serial
    send_i = serial.find("impl SerialWorkTransport")
    assert send_i != -1
    send_win = serial[send_i : send_i + 1800]
    assert "multi.tx_required.iter()" in send_win
    assert "admit_s19k_multi_send_work" in send_win
    assert "admit_s19k_fill_hunt_on_tx_path" in serial
    assert "did not receive work" in serial
    discover_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8")
    assert "refuse_s3_rx_as_fill_hunt" in discover_rs
    assert "admit_s19k_production_fill_hunt_skips_discover" in discover_rs
    assert "ThermalSafetyState::HandoffUnowned" in serial
    assert "thermal HandoffUnowned (not Ready)" in serial
    assert "s19k_track1_thermal" in serial
    assert "GPIO437 not written" in serial
    assert "spawn_track1_temps" in serial
    assert "hold_track1_leftover_fans_pwm100" in serial
    assert "admit_s19k_track1_thermal_ready" in share
    assert "admit_s19k_production_construction_serial_work" in share
    assert "S19K_TRACK1_LEFTOVER_FAN_PWM" in share
    board_desc_rs = (ROOT / "dcentrald/dcentrald-common/src/board_desc.rs").read_text(
        encoding="utf-8"
    )
    s19k_fn = board_desc_rs.find("pub const fn am3_s19kpro()")
    assert s19k_fn != -1
    s19k_win = board_desc_rs[s19k_fn : s19k_fn + 900]
    assert "WorkEngineKind::SerialWork" in s19k_win
    assert "LifecycleLane::AmlogicNativeSerial" in s19k_win
    assert (
        "native BM1366 transport is absent and production construction refuses"
        not in s19k_win
    )
    proof_i = serial.find("let thermal_proof_present =")
    assert proof_i != -1
    proof_win = serial[proof_i : serial.find(";", proof_i) + 1]
    assert "braiins_bm1366_passthrough_handoff" not in proof_win
    assert "let tx_before_rx = is_bm1362 || is_bm1366" in serial
    assert "DCENT_S19K_NATIVE_COLD_START" in serial
    assert 'matches!(raw, Some("1"))' in serial
    assert "BM1366_SERIAL_WORK_QUEUE_DEPTH" in serial
    depth_i = serial.find("let work_queue_depth = if is_bm1362")
    assert depth_i != -1
    depth_win = serial[depth_i : depth_i + 500]
    assert "} else if is_bm1366 {" in depth_win
    assert "BM1366_SERIAL_WORK_QUEUE_DEPTH" in depth_win
    assert "admit_s19k_production_run_skips_init_bm1366_chain" in share
    assert "admit_s19k_nopic_observation_refuses_bm1366" in share
    assert "admit_s19k_native_multi_uart_route_is_fenced" in share
    assert "admit_s19k_native_aggregate_platform_admission" in share
    aggregate_hal = (
        ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
    ).read_text(encoding="utf-8")
    assert "S19K_NATIVE_LOGICAL_CHAIN_ROUTES" in aggregate_hal
    assert 'uart: "/dev/ttyS3"' in aggregate_hal
    assert "logical_chain: 0" in aggregate_hal
    assert "reset_gpio: 454" in aggregate_hal
    aggregate_i = aggregate_hal.find("impl S19kNativeAggregateAdmission")
    aggregate_end = aggregate_hal.find("impl S19kNativePopulationAdmission", aggregate_i)
    assert aggregate_i != -1 and aggregate_end > aggregate_i
    aggregate = aggregate_hal[aggregate_i:aggregate_end]
    assert "validate_amlogic_boot_safe_handoff(AmlogicNoPicProfile::S19k)" in aggregate
    assert "let populated_slots = read_plug_topology_checked()?" in aggregate
    assert "populated_slots[*index] && !uart_available[*index]" in aggregate
    assert "let routes = self.logical_chain_routes()" in aggregate
    assert "service.psu_enable_operation_available = false" in aggregate
    assert "service.psu_enable_operation_available = true" not in aggregate
    assert "take_psu_enable_operation" not in aggregate
    assert "Result<Arc<S19kNativeFanObservation>>" in aggregate
    assert "Result<Arc<dyn FanAccess>>" not in aggregate
    observer_i = aggregate_hal.find("impl S19kNativeFanObservation")
    observer_end = aggregate_hal.find("pub struct S19kNativeAggregateAdmission", observer_i)
    assert observer_i != -1 and observer_end > observer_i
    observer = aggregate_hal[observer_i:observer_end]
    assert "pub fn get_per_fan_rpm" in observer
    assert "pub fn get_speed_pwm" in observer
    assert "pub fn set_speed" not in observer
    assert "impl FanAccess" not in observer
    assert "set_amlogic_board_reset_checked" not in aggregate
    mapped_i = aggregate_end
    mapped_end = aggregate_hal.find("fn amlogic_slot_from_serial_device", mapped_i)
    assert mapped_i != -1 and mapped_end > mapped_i
    mapped = aggregate_hal[mapped_i:mapped_end]
    assert "service.psu_enable_operation_available = true" in mapped
    assert "Result<Arc<dyn FanAccess>>" in mapped
    assert "Arc::ptr_eq(power_generation, &self.generation)" in mapped
    assert "assert_s19k_native_all_resets_checked()" in mapped
    assert "release_mapped_resets_checked" in mapped
    native_shape = serial[
        serial.find("fn admit_s19k_native_multi_uart_shape") : serial.find(
            "mod serial_route_domains",
            serial.find("fn admit_s19k_native_multi_uart_shape"),
        )
    ]
    assert "S19K_NATIVE_LOGICAL_CHAIN_ROUTES.as_slice()" in native_shape
    assert "refuse_s19k_nopic_probe_as_track1_first_read" in share
    assert "admit_s19k_am2_hybrid_reset_is_not_bm1366" in share
    assert "refuse_s19k_am2_hybrid_open_as_track1_first_read" in share
    assert "admit_s19k_am2_reset_baseline_is_not_bm1366" in share
    assert "refuse_s19k_am2_reset_baseline_as_track1_first_read" in share
    assert "admit_s19k_am3_bb_open_is_not_bm1366" in share
    assert "refuse_s19k_am3_bb_open_as_track1_first_read" in share
    assert "admit_s19k_init_bm1398_is_not_bm1366" in share
    assert "refuse_s19k_init_bm1398_as_track1_first_read" in share
    assert "admit_s19k_init_bm1368_is_not_bm1366" in share
    assert "refuse_s19k_init_bm1368_as_track1_first_read" in share
    assert "admit_s19k_init_bm1370_is_not_bm1366" in share
    assert "refuse_s19k_init_bm1370_as_track1_first_read" in share
    assert "admit_s19k_init_bm1362_is_not_bm1366" in share
    assert "refuse_s19k_init_bm1362_as_track1_first_read" in share
    assert "admit_s19k_am2_companion_open_is_not_bm1366" in share
    assert "refuse_s19k_am2_companion_open_as_track1_first_read" in share
    assert "admit_s19k_am2_phase3b1_relay_is_not_bm1366" in share
    assert "refuse_s19k_am2_phase3b1_relay_as_track1_first_read" in share
    assert "admit_s19k_am2_probe_uart_is_not_bm1366" in share
    assert "refuse_s19k_am2_probe_uart_as_track1_first_read" in share
    assert "admit_s19k_am2_init_asic_open_is_not_bm1366" in share
    assert "refuse_s19k_am2_init_asic_open_as_track1_first_read" in share
    assert "admit_s19k_am2_passthrough0_is_not_bm1366" in share
    assert "refuse_s19k_am2_passthrough0_as_track1_first_read" in share
    bm1398_i = serial.find("fn init_bm1398_chain(")
    assert bm1398_i != -1
    bm1398_win = serial[bm1398_i : bm1398_i + 4000]
    assert "SerialBringUpPluginKind::SerialBm1398" in bm1398_win
    assert "send_get_address_bm1397plus" in bm1398_win
    assert "require_bm1366_response_body" not in bm1398_win
    assert "open_passthrough_bm1366" not in bm1398_win
    assert "BM1366_UART_RESP_BODY_LEN" not in bm1398_win
    init66_i = serial.find("fn init_bm1366_chain(")
    init70_i = serial.find("fn init_bm1370_chain(")
    assert init66_i != -1 and init70_i != -1 and init70_i > init66_i
    init66_win = serial[init66_i:init70_i]
    assert "serial: &ValidatedSerialBackend" in init66_win
    assert "native_program: &S19kBm1366NativeExecutionProgram" in init66_win
    assert "SerialChainBackend::open(" not in init66_win
    assert "reset_asic_baud(" not in init66_win
    assert "Bm1366EnumerationAdmission" not in init66_win
    assert "rambo" not in init66_win
    assert "BM1366_VERSION_MASK_VALUE" not in init66_win
    assert "send_write_reg_broadcast_bm1397plus(0xA4" not in init66_win
    assert "s19k_bm1366_native_execution_program" in init66_win
    assert "native_program.pre_baud_commands" in init66_win
    assert "native_program.fast_uart_command" in init66_win
    assert "set_baud(native_program.fast_host_baud)" in init66_win
    assert "native BM1366 post-baud anti-staleness flush failed" in init66_win
    assert "Bm1366NativePostBaudAdmission::from_response_window" in init66_win
    assert "native_program.post_baud_commands" in init66_win
    assert "native_program.final_commands" in init66_win
    assert "terminal rollback required before per-chip mutation or work TX" in init66_win
    assert "fn init_bm1366_chains(" in init66_win
    assert "ValidatedS19kBm1366NativeMultiBackend" in init66_win
    assert "serial.expected_chips_per_uart() == 77" in init66_win
    assert "for (path, backend) in serial.iter()" in init66_win
    assert "Self::init_bm1366_chain(backend, path, &native_program)" in init66_win
    assert "PUBLIC_FASTUART_VALUE" not in init66_win
    asic_switch_i = init66_win.find("native_program.fast_uart_command")
    host_switch_i = init66_win.find("set_baud(native_program.fast_host_baud)")
    fresh_gate_i = init66_win.find("Bm1366NativePostBaudAdmission::from_response_window")
    per_chip_i = init66_win.find("native_program.post_baud_commands")
    assert asic_switch_i < host_switch_i < fresh_gate_i < per_chip_i
    pre_ladder_i = init66_win.find("native_program.pre_baud_commands")
    assert pre_ladder_i != -1
    assert "send_get_address_bm1397plus" not in init66_win[:pre_ladder_i]
    assert "pub struct S19kBm1366NativeExecutionProgram" in init_seq
    assert "fastuart_stock_3m125" in init_seq
    assert "BOSMINER_BM1366_FASTUART_3M125" in init_seq
    assert "post_host_baud_settle_ms: 50" in init_seq
    assert "post_baud_tail_settle_ms: 50" in init_seq
    assert "const BM1366_REG_A8_PER_CHIP" not in serial
    assert "const BM1366_HASH_COUNTING_S19K" not in serial
    bm1368_i = serial.find("fn init_bm1368_chain(")
    assert bm1368_i != -1
    bm1368_win = serial[bm1368_i : bm1368_i + 4000]
    assert "ValidatedSerialBackend" in bm1368_win
    assert "SerialBringUpPluginKind::AmlogicBm1368" in bm1368_win
    assert "=== BM1368 ASIC INIT" in bm1368_win
    assert "SerialChainBackend::open" not in bm1368_win
    assert "require_bm1366_response_body" not in bm1368_win
    assert "open_passthrough_bm1366" not in bm1368_win
    assert "BM1366_UART_RESP_BODY_LEN" not in bm1368_win
    bm1370_i = serial.find("fn init_bm1370_chain(")
    assert bm1370_i != -1
    bm1370_win = serial[bm1370_i : bm1370_i + 4000]
    assert "ValidatedSerialBackend" in bm1370_win
    assert "SerialBringUpPluginKind::AmlogicBm1370" in bm1370_win
    assert "=== BM1370 ASIC INIT" in bm1370_win
    assert "send_get_address_bm1397plus" in bm1370_win
    assert "SerialChainBackend::open" not in bm1370_win
    assert "require_bm1366_response_body" not in bm1370_win
    assert "open_passthrough_bm1366" not in bm1370_win
    assert "BM1366_UART_RESP_BODY_LEN" not in bm1370_win
    bm1362_i = serial.find("fn init_bm1362_chain(")
    assert bm1362_i != -1
    bm1362_win = serial[bm1362_i : bm1362_i + 2500]
    assert "ValidatedSerialBackend" in bm1362_win
    assert "=== BM1362 ASIC INIT" in bm1362_win
    assert "BM1362 init requires the checked reset-baseline 115200" in bm1362_win
    assert "SerialChainBackend::open" not in bm1362_win
    assert "require_bm1366_response_body" not in bm1362_win
    assert "open_passthrough_bm1366" not in bm1362_win
    assert "BM1366_UART_RESP_BODY_LEN" not in bm1362_win
    hybrid = (ROOT / "dcentrald/dcentrald/src/s19j_hybrid_mining.rs").read_text(
        encoding="utf-8"
    )
    hybrid_i = hybrid.find("fn reset_asic_baud(serial_device: &str, uart_preference: SerialBackendPreference)")
    assert hybrid_i != -1
    hybrid_win = hybrid[hybrid_i : hybrid_i + 1800]
    assert "HotStartHostClass::Zynq" in hybrid_win
    assert "plan_hot_start_hybrid_wake_ops" in hybrid_win
    assert "require_bm1366_response_body" not in hybrid_win
    assert "BM1366_UART_RESP_BODY_LEN" not in hybrid_win
    companion_i = hybrid.find("let companion_dev = am2_dual_chain_second_uart()")
    assert companion_i != -1
    companion_win = hybrid[companion_i : companion_i + 2500]
    assert "SerialChainBackend::open_with_preference(0, &companion_dev, 115_200, uart_preference)" in companion_win
    assert "assert_mcr_out2" in companion_win
    assert "require_bm1366_response_body" not in companion_win
    assert "open_passthrough_bm1366" not in companion_win
    assert "BM1366_UART_RESP_BODY_LEN" not in companion_win
    relay_i = hybrid.find("match SerialChainBackend::open_with_preference(\n")
    assert relay_i != -1
    relay_win = hybrid[relay_i : relay_i + 1800]
    assert "maybe_write_bm1362_uart_relay" in relay_win
    assert "bm1362_phase3b1_pre_gate" in relay_win
    assert "require_bm1366_response_body" not in relay_win
    assert "open_passthrough_bm1366" not in relay_win
    assert "BM1366_UART_RESP_BODY_LEN" not in relay_win
    probe_i = hybrid.find("fn probe_uart_for_chips(")
    init_asic_i = hybrid.find("fn init_asic_chain(")
    assert init_asic_i != -1
    init_head = hybrid[init_asic_i : init_asic_i + 800]
    assert "=== BM1362 ASIC INIT" in init_head
    init_open_i = hybrid.find(
        "let mut serial = SerialChainBackend::open_with_preference(0, serial_device, 115_200, uart_preference)",
        init_asic_i,
    )
    assert init_open_i != -1
    init_open_win = hybrid[init_open_i : init_open_i + 1500]
    assert "am2_post_reset_settle_ms" in init_open_win
    assert "Failed to open serial port at 115200" in init_open_win
    assert "require_bm1366_response_body" not in init_open_win
    assert "open_passthrough_bm1366" not in init_open_win
    assert "BM1366_UART_RESP_BODY_LEN" not in init_open_win
    assert probe_i != -1
    probe_win = hybrid[probe_i : probe_i + 2500]
    assert "BM1362_RESP_BODY_LEN" in probe_win
    assert "hybrid_send_get_address" in probe_win
    assert "read_bm1362_serial_drain_summary" in probe_win
    assert "require_bm1366_response_body" not in probe_win
    assert "open_passthrough_bm1366" not in probe_win
    assert "BM1366_UART_RESP_BODY_LEN" not in probe_win
    pt_i = hybrid.find("PASSTHROUGH: skipping Phase 1-7 (bosminer owns PIC+chain init)")
    assert pt_i != -1
    pt_win = hybrid[pt_i : pt_i + 800]
    assert "open_passthrough_with_preference(0, &serial_device, uart_preference)" in pt_win
    assert "BM1362_RESP_BODY_LEN" in pt_win
    assert "require_bm1366_response_body" not in pt_win
    assert "open_passthrough_bm1366" not in pt_win
    assert "BM1366_UART_RESP_BODY_LEN" not in pt_win
    base_i = serial.find("fn observe_reset_baseline(")
    assert base_i != -1
    base_win = serial[base_i : base_i + 1800]
    assert "BM1362_UNASSIGNED_RESP_BODY_LEN" in base_win
    assert "AM2 BM1362 reset-baseline" in base_win
    assert "require_bm1366_response_body" not in base_win
    assert "BM1366_UART_RESP_BODY_LEN" not in base_win
    am3_bb = (ROOT / "dcentrald/dcentrald/src/am3_bb_mining.rs").read_text(
        encoding="utf-8"
    )
    bb_i = am3_bb.find("impl Am3BbChainUart")
    assert bb_i != -1
    bb_win = am3_bb[bb_i : bb_i + 2500]
    assert "am3-bb: SerialChainBackend::open" in bb_win
    assert "require_bm1366_response_body" not in bb_win
    assert "open_passthrough_bm1366" not in bb_win
    assert "init_bm1366_chain first-read must be body 9" in serial
    assert "require_bm1366_response_body" in serial
    assert "fn require_bm1366_response_body" in hal_crc
    assert "admit_s19k_hal_open_passthrough_bm1366" in share
    assert "admit_s19k_hal_extracts_bm1366_body9" in rx
    assert "admit_s19k_hal_midstream_body7_then_body9" in rx
    assert "fn rx_buffer_body7_then_body9_recovers_next" in hal_crc
    assert "extract_s19k_hal_bm1366_bodies" in rx
    assert "admit_s19k_hal_bodies_77_complete" in rx
    assert "rx_buffer_extracts_complete_bm1366_frame" in hal_crc
    assert "rx_buffer_body7_on_bm1366_wire_leaves_trailer" in hal_crc
    assert "try_extract_frame(BM1366_UART_RESP_BODY_LEN" in hal_crc
    assert "admit_s19k_production_uses_bm1366_passthrough_open" in share
    assert "admit_s19k_production_refuses_generic_passthrough_for_bm1366" in share
    assert "refuse_s19k_generic_passthrough0_as_track1" in share
    assert (
        "S19k BM1366 must use Track-1 multi-tty open_passthrough_bm1366, not generic open_passthrough(0)"
        in serial
    )
    assert "Some(&resp[..9])" in serial
    assert "Some(&resp[..7])" not in serial
    assert "s.set_response_len(resp_body_len)" in serial
    assert "open_passthrough_bm1366(i as u8, path)" in serial
    assert "SerialChainBackend::open_passthrough(i as u8, path)" not in serial
    open_i = serial.find("SerialChainBackend::open_passthrough_bm1366(i as u8, path)")
    assert open_i != -1
    win = serial[open_i : open_i + 2800]
    assert win.find("s.set_response_len(resp_body_len)") < win.find("send_get_address")
    assert win.find(
        "s19k_discover_skip_rx_when_leftover_baud_not_track1_3m"
    ) < win.find("send_get_address")
    hal = (ROOT / "dcentrald/dcentrald-hal/src/serial_chain.rs").read_text(
        encoding="utf-8"
    )
    assert "fn open_passthrough_bm1366" in hal
    assert "set_response_len(BM1366_UART_RESP_BODY_LEN)" in hal
    discover = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8")
    assert "S19kPortRxMatrix" in discover
    assert "classify_port_rx_hex" in discover
    assert "refuse_one_required_port_as_dual_chain_proof" in discover
    assert "refuse_zero_required_ports_as_dual_chain_proof" in discover
    assert "refuse_s3_only_as_required_pair_proof" in discover
    assert "admit_s19k_multi_rx_path" in discover
    assert "admit_s19k_multi_rx_tables" in discover
    assert "refuse_same_tty_as_dual_uart_proof" in discover
    assert "admit_s19k_required_dual_uart_paths" in discover
    assert "classify_s19k_tagged_dual_uart_rx_after" in discover
    assert "observe_s19k_tagged_rx_body" in discover
    assert "refuse_held_78_cap_serial_as_bm1366_golden" in discover
    assert "HELD_78_CAP_SERIAL_S3: &[u8] = &[0x00, 0x00, 0xAA]" in discover
    assert "observe_bm1366_uart_rx" in discover
    cap_serial = (
        ROOT.parents[1]
        / ""
    )
    assert (cap_serial / "ttyS1.rx.bin").read_bytes() == b""
    assert (cap_serial / "ttyS2.rx.bin").read_bytes() == b""
    assert (cap_serial / "ttyS3.rx.bin").read_bytes() == bytes([0x00, 0x00, 0xAA])
    assert "format_s19k_port_rx_matrix" in serial
    assert "refuse_one_required_port_as_dual_chain_proof" in serial
    assert "refuse_zero_required_ports_as_dual_chain_proof" in serial
    assert "refuse_s3_only_as_required_pair_proof" in serial
    assert "admit_s19k_production_getaddress_tx_fail_is_framing" in discover
    tx_fail = serial.find("S19k GetAddress TX failed")
    assert tx_fail != -1
    tx_window = serial[tx_fail : tx_fail + 240]
    assert "S19kPortAnswer::FramingOrEcho" in tx_window
    assert "S19kPortAnswer::Silence" not in tx_window
    assert "BM1366_VERSION_ROLL_SHIFT" in share
    assert (
        "pub const BM1366_VERSION_ROLL_MASK: u32 = crate::VERSION_ROLLING_STRATUM_BIP320_MASK;"
        in share
    )
    # Independent BIP320 reconstruction: 0x0304 << 13 must keep bit 15.
    version_bits = (0x0304 << 13) & 0x1FFFE000
    assert version_bits == 0x00608000, hex(version_bits)
    assert "admit_s19k_multi_send_work" in serial
    assert "s19k_work_tx_required_after_enum" in serial
    assert "s19k_multi_send_work_tx_required" in discover
    assert "refuse_s3_tx_as_required_send_work" in discover
    assert "s19k_multi_rx_start" in serial
    assert "admit_s19k_multi_rx_path" in serial
    assert "admit_s19k_multi_rx_tables" in serial
    assert "S19K_MULTI_RX" in serial
    assert "pending_rx" in serial
    assert "BM1366_SERIAL_TX_BURST" in serial
    assert "s19k_multi_rx_ready_indices" in discover
    assert "refuse_s19k_first_hit_as_dual_port_drain" in discover
    assert "admit_s19k_live401_stall_is_sequential_s1_then_s2" in discover
    assert "refuse_s19k_live401_stall_as_simultaneous_dual_death" in discover
    assert "admit_s19k_live403_s1_survived_past_live401_s1" in discover
    assert "refuse_s19k_live403_as_stall_closed" in discover
    assert "admit_s19k_live403_multi_rx_counts_balanced" in discover
    assert "admit_s19k_live403_actor_tx_starved_during_rx" in discover
    assert "refuse_s19k_live403_as_passthrough_never_rearmed" in discover
    assert "admit_s19k_live404_actor_tx_kept_up_with_rx" in discover
    assert "admit_s19k_live404_oneshot_rearm_then_cliff" in discover
    assert "refuse_s19k_live404_as_jobid_wrap" in discover
    assert "refuse_s19k_live404_as_stall_closed" in discover
    assert "admit_s19k_production_bm1366_skips_rx_followup_drain" in discover
    assert "admit_s19k_production_bm1366_midrun_rearm" in discover
    assert "admit_s19k_live405_survived_past_live404_cliff" in discover
    assert "admit_s19k_live405_s1_died_at_wrap5" in discover
    assert "refuse_s19k_live405_as_failed_midrun_rearm" in discover
    assert "refuse_s19k_live405_as_stall_closed" in discover
    assert "admit_s19k_production_bm1366_tx_min_interval" in discover
    assert "admit_s19k_tx_pace_puts_wrap5_after_t90" in discover
    assert "admit_s19k_fill_registry_is_256" in discover
    assert "admit_s19k_live406_hung_on_ttys3_9600" in discover
    assert "refuse_s19k_live406_as_stall_closed" in discover
    assert "s19k_discover_skip_rx_when_leftover_baud_not_track1_3m" in discover
    assert "admit_s19k_production_skips_discover_rx_when_leftover_not_3m" in discover
    assert "admit_s19k_live407_dual_port_past_t90" in discover
    assert "admit_s19k_live407_survived_paced_wrap5" in discover
    assert "admit_s19k_live407_zero_shares" in discover
    assert "refuse_s19k_live407_as_share_closed" in discover
    assert "refuse_s19k_t90_only_as_production_ready" in discover
    assert "refuse_s19k_t90_only_as_customer_writable" in discover
    assert "admit_s19k_live408_pool_accepted_one_share" in discover
    assert "refuse_s19k_live408_as_t90_dual_port" in discover
    assert "refuse_s19k_live408_as_share_and_t90" in discover
    assert "admit_s19k_live408_died_at_wrap3" in discover
    assert "admit_s19k_tx_pace_puts_wrap3_after_t90" in discover
    assert "S19K_LIVE408_WRAP3_TX: u32 = 768" in discover
    assert "S19K_LIVE407_TX_MIN_INTERVAL_MS: u32 = 80" in discover
    assert "S19K_BM1366_TX_MIN_INTERVAL_MS: u32 = 120" in discover
    assert "admit_s19k_live409_parked_boarddesc_management_only" in discover
    assert "refuse_s19k_live409_as_share_and_t90" in discover
    assert "admit_s19k_production_track1_serial_not_native" in discover
    assert "admit_s19k_live410_share_and_t90" in discover
    assert "refuse_s19k_live410_as_production_ready" in discover
    assert "refuse_s19k_live410_as_multi_share_closed" in discover
    assert "refuse_s19k_live410_as_customer_writable" in discover
    assert "admit_s19k_live411_multi_share_and_t90" in discover
    assert "refuse_s19k_live411_as_production_ready" in discover
    assert "refuse_s19k_live411_as_t180_soak" in discover
    assert "refuse_s19k_t90_multi_share_as_soak" in discover
    assert "refuse_s19k_live411_as_customer_writable" in discover
    assert "S19K_LIVE411_SHARE1_NONCE: u32 = 0xC15A_724A" in discover
    assert "S19K_LIVE411_S1_LAST_RX_MS: u32 = 118_283" in discover
    assert "admit_s19k_live412_multi_share_and_t180" in discover
    assert "admit_s19k_live412_survived_paced_wrap5" in discover
    assert "refuse_s19k_live412_as_production_ready" in discover
    assert "refuse_s19k_t180_tmp_as_production_ready" in discover
    assert "refuse_s19k_live412_as_customer_writable" in discover
    assert "S19K_LIVE412_SHARE1_NONCE: u32 = 0x4E3E_900D" in discover
    assert "S19K_LIVE412_S1_LAST_RX_MS: u32 = 187_186" in discover
    assert "S19K_LIVE412_S2_LAST_RX_MS: u32 = 188_012" in discover
    assert "admit_s19k_live414_thermal_ready_and_t180" in discover
    assert "admit_s19k_live414_died_at_wrap7" in discover
    assert "refuse_s19k_live414_as_t600_soak" in discover
    assert "refuse_s19k_live414_as_production_ready" in discover
    assert "refuse_s19k_live414_as_customer_writable" in discover
    assert "S19K_LIVE414_SHARE1_NONCE: u32 = 0xEEAB_1C38" in discover
    assert "S19K_LIVE414_S1_LAST_RX_MS: u32 = 228_031" in discover
    assert "S19K_LIVE414_S2_LAST_RX_MS: u32 = 213_744" in discover
    assert "S19K_LIVE414_WRAP7_TX: u32 = 1_792" in discover
    assert "s19k_track1_wrap_barrier_due" in discover
    assert "admit_s19k_production_wrap_barrier" in discover
    assert "admit_s19k_live414_wrap7_trips_barrier" in discover
    assert "refuse_s19k_slower_tx_as_wrap7_survival" in discover
    assert "admit_s19k_live415_died_before_wrap1" in discover
    assert "refuse_s19k_live415_as_t600_soak" in discover
    assert "admit_s19k_live416_died_after_wrap2_drain_rearm" in discover
    assert "refuse_s19k_live416_as_t600_soak" in discover
    assert "refuse_s19k_live415_416_drain_rearm_as_wrap_survival" in discover
    assert "S19K_LIVE415_S1_LAST_RX_MS: u32 = 26_517" in discover
    assert "S19K_LIVE416_S1_LAST_RX_MS: u32 = 73_609" in discover
    assert "S19K_LIVE416_SHARE1_NONCE: u32 = 0xADFE_CA91" in discover
    assert "admit_s19k_live417_died_at_wrap6" in discover
    assert "refuse_s19k_live417_as_t600_soak" in discover
    assert "admit_s19k_production_rearm_skips_tx" in discover
    assert "live417: ticket+HCN then immediate work TX" in serial
    assert "S19K_LIVE417_S1_LAST_RX_MS: u32 = 169_044" in discover
    assert "S19K_LIVE417_SHARE1_NONCE: u32 = 0xD081_C53B" in discover
    assert "admit_s19k_live418_died_at_wrap6" in discover
    assert "refuse_s19k_live418_as_t600_soak" in discover
    assert "S19K_LIVE418_S1_LAST_RX_MS: u32 = 184_926" in discover
    assert "S19K_LIVE418_SHARE1_NONCE: u32 = 0xD272_543F" in discover
    assert "admit_s19k_live419_died_after_wrap1_cold_leftover" in discover
    assert "refuse_s19k_live419_as_t600_soak" in discover
    assert "S19K_LIVE419_S1_LAST_RX_MS: u32 = 38_374" in discover
    assert "admit_s19k_live420_died_after_wrap4" in discover
    assert "refuse_s19k_live420_as_t600_soak" in discover
    assert "S19K_LIVE420_S1_LAST_RX_MS: u32 = 136_902" in discover
    assert "admit_s19k_midrun_rearm_includes_analog_mux" in discover
    assert "refuse_s19k_analog_mux_rearm_as_t600_soak" in discover
    assert "admit_s19k_live414_shares_stopped_after_midrun_clean" in discover
    assert "refuse_s19k_midrun_clean_as_chip_reload" in discover
    assert "refuse_s19k_live412_8bd1_as_same_slot_replace" in discover
    assert "admit_s19k_live412_8bd1_is_first_fill" in discover
    assert "refuse_s19k_session_start_shares_as_occupied_slot_replace" in discover
    assert "S19K_LIVE412_8BD1_TX_EST: u32 = 65" in discover
    assert "classify_s19k_post_clean_nonce" in serial
    assert "leftover_hit" in serial
    assert "retired_s19k_history" in serial
    assert "let midrun_clean = is_bm1366 && total_work > 0" in serial
    assert "s19k_post_clean_submit_allowed" in serial
    assert "S19k leftover/ambiguous post-clean nonce refused at submit" in serial
    assert "unpack_s19k_braiins_ghidra_job_wire" in job
    assert "parse_s19k_compact_hex" in job
    assert "s19k_live412_captured_first_frame_is_8bd0_job0" in job
    assert "b.is_ascii_whitespace()" in job
    assert "admit_s19k_esp_bm1366_has_no_work_abort_opcode" in job
    assert "s19k_track1_fill_job_id" in job
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP" in job
    assert "s19k_track1_fill_job_id" in serial
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP" in serial
    assert "s19k_experimental_post_clean_flip_enabled_from_env" in serial
    assert "s19k_plan_post_clean_uart_replace" in serial
    assert "post_clean_uart.chain_inactive" in serial
    assert "s19k_compact_tx_meets_share_target" in serial
    assert "new_tx_meets" in serial
    assert "retired_tx_meets" in serial
    assert "admit_s19k_jig_has_no_closed11d_job" in job
    assert "retired_s19k_tx" in serial
    assert "retired_tx_wire" in serial
    assert "s19k_should_log_full_work_frame" in serial
    assert "s19k_first_occupied_tx_hex" in serial
    assert "refuse_s19k_fill_cursor_reset_as_t600_soak" in discover
    assert "admit_s19k_live414_resent_full_registry_after_clean" in discover
    assert "refuse_s19k_fill_cursor_reset_as_chip_work_replace" in discover
    assert "S19K_LIVE414_POST_CLEAN_TX_EST: u32 = 1_228" in discover
    assert "s19k_track1_pause_rearm_until_tx" in discover
    assert "admit_s19k_production_pauses_rearm_one_wrap_after_clean" in discover
    assert "refuse_s19k_hcn_pause_as_t600_soak" in discover
    assert "refuse_s19k_hcn_pause_as_chip_work_replace" in discover
    assert "refuse_s19k_getaddress_as_midrun_invalidate" in discover
    assert "s19k_track1_pause_rearm_until_tx" in serial
    assert "pause mid-run re-arm after clean" in serial
    assert "total_tx < pause_until" in serial
    assert "refuse_s19k_analog_mux_as_wrap7_survival" in discover
    assert "admit_s19k_production_clean_resets_fill_cursor" in discover
    assert "admit_s19k_live424_session_start_paused_rearm" in discover
    assert "refuse_s19k_live424_as_leftover_hit_soak" in discover
    assert "refuse_s19k_session_start_hcn_pause" in discover
    assert "S19K_LIVE424_S1_LAST_RX_MS: u32 = 102_054" in discover
    assert "S19K_LIVE424_SESSION_START_PAUSE_TX: u32 = 37" in discover
    assert "admit_s19k_live425_leftover_hit_and_wrap7" in discover
    assert "refuse_s19k_live425_as_t600_soak" in discover
    assert "S19K_LIVE425_LEFTOVER_HIT: u32 = 6" in discover
    assert "S19K_LIVE425_S1_LAST_RX_MS: u32 = 225_447" in discover
    assert "S19K_LIVE414_LAST_SHARE_MS: u32 = 50_683" in discover
    assert "S19K_LIVE414_MIDRUN_CLEAN_MS: u32 = 66_296" in discover
    assert "reset_s19k_braiins_fill" in serial
    assert "live414/417/418: mid-run clean left fill cursor running" in serial
    assert "admit_s19k_live414_rx_died_while_tx_crossed_wrap7" in discover
    assert "skip_tx_this_loop" in serial
    assert "s19k_track1_wrap_barrier_due" in serial
    assert "S19k passthrough wrap-barrier" in serial
    assert "S19K_LIVE410_SHARE_NONCE: u32 = 0x9AEA_565C" in discover
    assert "s19k_track1_job_id_retry_slots" in share
    assert "admit_s19k_production_retries_track1_job_id_slots" in share
    assert "s19k_track1_job_id_retry_slots" in serial
    assert "live410: also try ESP 0xF8 and >>3" in serial
    assert "S19K_LIVE410_S1_LAST_RX_MS: u32 = 116_990" in discover
    assert "S19K_LIVE410_S2_LAST_RX_MS: u32 = 117_231" in discover
    main_rs = (ROOT / "dcentrald/dcentrald/src/main.rs").read_text(encoding="utf-8")
    # Current dispatch authority joins the exact BM1366 profile and ASIC
    # protocol; Track-1 custody remains a separate, explicitly bound CLI route.
    assert "bm1366_dispatch_admitted_serial_platform(" in main_rs
    assert "let asic_protocol_admission = board_desc.admit_asic_protocol(" in main_rs
    assert "asic_protocol: Some(asic_protocol_admission)" in main_rs
    bm1366_profiles = (ROOT / "dcentrald/dcentrald-common/src/bm1366_serial_platform.rs").read_text(
        encoding="utf-8"
    )
    assert "Some(profile) if profile.dispatch_admitted => Ok(profile)" in bm1366_profiles
    assert 'None => Err("board target has no BM1366 serial platform profile")' in bm1366_profiles
    assert "fn am3_s19k_serial_bm1366_is_track1_leftover_not_native()" in main_rs
    assert "s19k_stock_handoff_identity.is_some() == s19k_track1_receipt_authority.is_some()" in main_rs
    assert "s19k_stock_handoff_identity.is_some() == s19k_track1_j3_lease.is_some()" in main_rs
    assert "lease.require_context(authority, identity)?" in main_rs
    assert "lease.require_install_custody_safeoff_policy(s19k_install_custody_safeoff)?" in main_rs
    assert "!s19k_install_custody_safeoff || s19k_stock_handoff_identity.is_some()" in main_rs
    assert "s19k_discover_skip_rx_when_leftover_baud_not_track1_3m" in serial
    assert "skip drain/GetAddress" in serial
    assert "BM1366_PASSTHROUGH_REARM_EVERY_S" in serial
    assert "S19k passthrough mid-run re-arm" in serial
    assert "BM1366_SERIAL_TX_MIN_INTERVAL_MS" in serial
    assert "let min_tx_interval = if is_bm1366" in serial
    assert "const BM1366_SERIAL_TX_MIN_INTERVAL_MS: u64 = 120" in serial
    assert "S19k Track-1 hold" in serial
    assert "refuse live408 drop-oldest" in serial
    assert "S19K_BM1366_HOLD_QUEUE_DEPTH" in serial
    assert "BM1366_SERIAL_RX_FOLLOWUP_DRAIN" in serial
    assert "let rx_followup_drain = if is_bm1366" in serial
    assert "for _ in 0..rx_followup_drain" in serial
    assert "paths: opened" in serial
    assert "else if is_bm1366 {" in serial.split("let resp_body_len", 1)[1][:500]
    assert "BM1366_UART_RESP_BODY_LEN" in serial.split("let resp_body_len", 1)[1][:500]
    assert "S19k tagged RX is not a correlated BM1366 fill nonce; not counted" in serial
    rx = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs").read_text(
        encoding="utf-8"
    )
    assert "job_crc5_inits_matching" in rx
    assert "esp_asic_crc5" in rx
    assert "admit_esp_rx_crc5_remainder" in rx
    assert "refuse_rtl_1b_payload_as_job_crc_drop" in rx
    assert "HELD_BM1362_JOB_FRAMES" in rx
    assert "admit_s19k_no_held_bm1366_job_nonce" in rx
    assert "admit_s19k_live88_held_bm1366_job_nonce" in rx
    assert "S19K_LIVE88_S1_LEFTOVER_JOB_NONCE" in rx
    assert "refuse_held_s21_job_as_s19k_bm1366_nonce" in rx
    assert "refuse_held_bm1362_frames_as_s19k_bm1366_nonce" in rx
    assert "S19K_HELD_BM1366_JOB_NONCE: Option<&[u8]> =" in rx
    assert "Some(&S19K_LIVE88_S1_LEFTOVER_JOB_NONCE)" in rx
    assert "Option<&[u8]> = None" not in rx
    assert "ESP_ASIC_CRC5_INIT: u8 = 0x1F" in rx
    assert "ESP_BM1366_CHIP_ID_RX_LEN: usize = 11" in rx
    assert "command_reply_from_frame" in rx
    assert "enum_asic_addrs_from_rx" in rx
    assert "first_missing_enum_addr" in rx
    assert "classify_s19k_chip_enum_complete" in rx
    assert "refuse_one_chipaddress_as_77_chip_complete" in rx
    assert "bm1366_constructed_77_chip_enum" in rx
    assert "not 77-chip complete" in serial
    assert "refuse_rx_byte5_as_register_address" in rx
    assert "ESP_RX_REG_OR_JOB_ID_OFF: usize = 7" in rx
    assert "S19kUartRxKind::CommandReply" in rx
    assert "raw job byte" in rx
    assert "not ESP id&0xF8" in rx
    assert "work-type must be 1" in rx
    assert "job_id = id & 0xF8 after CLOSED" not in rx
    assert "raw_job_byte" in rx
    assert "braiins_fill_work_id_from_kind" in rx
    assert "refuse_esp_masked_job_id_as_braiins_fill_work_id" in rx
    assert "bm1366_chip_address_uart" in rx
    assert "admit_expected_chip_address_rx" in rx
    assert "refuse_bm1362_core03_as_bm1366_chip_address" in rx
    assert "classify_s19k_bm1366_rx_after" in rx
    assert "admit_s19k_production_types_getaddress_baud" in rx
    assert "s19k_track1_classify_rx_baud" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "s19k_track1_classify_rx_baud" in serial
    assert "s19k_track1_classify_rx_baud_with_reg28" in serial
    assert "S19kRxExpectedAfter::FastUart28" in serial
    assert "send_read_reg_broadcast_bm1397plus" in serial
    assert "s19k_track1_should_retry_115200" in serial
    assert "S19K_TRACK1_RETRY_115200_ENV" in serial
    assert 'S19K_TRACK1_RETRY_115200_ENV: &str = "DCENT_S19K_TRACK1_RETRY_115200"' in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "GetAddress115200Retry" in serial
    assert "s19k_track1_retry_restore_baud" in serial
    assert "impl Drop for Track1HostBaudRestore" in serial
    assert "Track1HostBaudRestore::arm" in serial
    drop_impl = serial.find("impl Drop for Track1HostBaudRestore")
    drop_end = serial.find("\n}", drop_impl)
    assert drop_impl != -1 and drop_end != -1
    assert "set_baud" in serial[drop_impl:drop_end]
    assert "restore_to" in serial[drop_impl:drop_end]
    assert serial[drop_impl:drop_end].count("set_baud") >= 2
    assert "refuse_work_tx_if_host_not_3m_after_restore" in serial
    assert "classify_s19k_dual_baud_silence" in serial
    assert "admit_s19k_dual_baud_work_tx" in serial
    assert "S19kDualBaudObserve" in serial
    preflight_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_passthrough_preflight.rs"
    ).read_text(encoding="utf-8")
    assert "classify_s19k_dual_baud_silence" in preflight_rs
    assert "ChipHeardWhileRailsDisabled" in preflight_rs
    assert "SilenceAtBothBauds" in preflight_rs
    assert "refuse_silence_at_both_bauds_as_chip_115200" in preflight_rs
    assert "refuse_work_tx_if_host_not_3m_after_restore" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "s19k_track1_restore_baud_attempt" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    arm_at = serial.find("Track1HostBaudRestore::arm(&s)")
    set115 = serial.find("set_baud(S19K_78_DMESG_HOLD_BAUD)")
    assert set115 != -1 and arm_at != -1 and set115 < arm_at
    assert "S19K_78_DMESG_HOLD_BAUD" in serial
    assert "refuse_chip_heard_at_115200_as_3m_work_proof" in serial
    t1_retry = serial.find("s19k_track1_should_retry_115200")
    t1_answer = serial.find("s19k_port_answer_from_rx(&obs)", t1_retry)
    assert t1_retry != -1 and t1_answer != -1 and t1_retry < t1_answer
    set115 = serial.find("S19K_78_DMESG_HOLD_BAUD", t1_retry)
    restore = serial.find("s19k_track1_retry_restore_baud()", t1_retry)
    assert set115 != -1 and restore != -1 and set115 < restore
    assert "PUBLIC_FASTUART_REG" in serial
    assert "classify_s19k_chip_fastuart_word" in serial
    assert "send_read_reg_bm1397plus(0, 0x28)" not in serial
    uart_rx_src = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs"
    ).read_text(encoding="utf-8")
    assert "ChipFastUartUnread" in uart_rx_src
    assert "GetAddressSilenceAt115200" in uart_rx_src
    ga115 = uart_rx_src.find("S19kRxExpectedAfter::GetAddress115200Retry => match obs")
    fu28 = uart_rx_src.find("S19kRxExpectedAfter::FastUart28 => match obs", ga115)
    assert ga115 != -1 and fu28 != -1
    assert "GetAddressSilenceAt115200" in uart_rx_src[ga115:fu28]
    assert "ChipFastUartUnread" not in uart_rx_src[ga115:fu28]
    assert "GetAddressSilenceAt115200" in serial
    assert "FastUart28At115200" in serial
    assert "s19k_track1_should_probe_fastuart_28_at_115200" in serial
    assert "FastUart28HeardAt115200" in uart_rx_src
    assert "FastUart28SilenceAt115200" in uart_rx_src
    fu115 = uart_rx_src.find("S19kRxExpectedAfter::FastUart28At115200 => match obs")
    assert fu115 != -1
    assert "FastUart28HeardAt115200" in uart_rx_src[fu115 : fu115 + 600]
    assert "ChipFastUartUnread" not in uart_rx_src[fu115 : fu115 + 400]
    ga_retry = serial.find("S19kRxExpectedAfter::GetAddress115200Retry")
    fu115_serial = serial.find("S19kRxExpectedAfter::FastUart28At115200")
    arm_at = serial.find("Track1HostBaudRestore::arm(&s)")
    assert ga_retry != -1 and fu115_serial != -1 and arm_at != -1
    assert arm_at < ga_retry < fu115_serial
    assert "FastUartHeardAt115200" in serial
    assert "pack_read_register_bcast_uart" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_wire_b.rs"
    ).read_text(encoding="utf-8")
    assert "admit_s19k_production_reads_fastuart_28" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_uart_rx.rs"
    ).read_text(encoding="utf-8")
    assert "send_read_reg_broadcast_bm1397plus" in (
        ROOT / "dcentrald/dcentrald-hal/src/serial_chain.rs"
    ).read_text(encoding="utf-8")
    ga = serial.find("S19kRxExpectedAfter::GetAddress")
    ga_obs = serial.find("S19k GetAddress observe", ga)
    assert ga != -1 and ga_obs != -1 and ga < ga_obs
    assert "Ok(())" not in serial[ga:ga_obs]
    assert "track1_baud" in serial[ga:ga_obs]
    assert "admit_s19k_rx_after" in rx
    assert "refuse_silence_after_getaddress_as_parser_fault" in rx
    assert "refuse_zero_nonce_after_2156_as_parser_proof" in rx
    assert "admit_fill_work_id_tx_rx_correlate" in rx
    assert "s19k_hal_body7_wire_cut" in rx
    assert "admit_constructed_fill_nonce_correlates" in rx
    assert "refuse_constructed_fill_body7_as_job_nonce" in rx
    assert "refuse_constructed_fill_body7_observe_as_job_or_silence" in rx
    assert "S19K_HAL_BODY7_WIRE_CUT: usize = 2 + BM139X_HAL_DEFAULT_RESP_BODY_LEN" in rx
    assert "S19kRxDiag" in rx
    assert "WorkDispatch2156" in rx
    assert "BM1366_CHIP_ADDRESS_CORE: u8 = 0x00" in rx
    assert "BM1362_CHIP_ADDRESS_CORE: u8 = 0x03" in rx
    assert "HELD_78_CAP_SERIAL_S3: [u8; 3] = [0x00, 0x00, 0xAA]" in rx
    assert "admit_s21_held_uart_chip_id_is_1368_not_1366" in rx
    assert "refuse_s21_held_uart_capture_as_s19k_jobnonce" in rx
    assert "S21_HELD_UART_CA1368_COUNT: usize = 108" in rx
    assert "S21_HELD_UART_CA1366_COUNT: usize = 0" in rx
    assert "refuse_s19k_rxbuf_leftover_aa_plus_tx55_as_jobnonce" in rx
    assert "refuse_s19k_held_s3_aa_as_preamble_seed" in rx
    assert "admit_s19k_production_flush_rx_after_getaddress_nopreamble" in rx
    assert "admit_s19k_production_flush_rx_after_fastuart_empty" in rx
    assert "admit_s19k_production_flush_rx_after_115200_retry_empty" in rx
    assert "admit_s19k_production_flush_rx_after_fastuart_115200_empty" in rx
    serial = (ROOT / "dcentrald/dcentrald/src/serial_mining.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "flush leftover RX after empty GetAddress" in serial
    assert "flush leftover RX after empty FastUART" in serial
    assert "flush leftover RX after empty 115200-retry GetAddress" in serial
    assert "flush leftover RX after empty FastUART-at-115200" in serial
    assert "HAL last-byte AA" in serial
    assert "expected_rx_fixtures_and_diag_are_not_parser_proof" in rx
    # Independent CRC5 sweep: RTL 0x1B does not match S21 comparative trailer 0x0E.
    matching = [i for i in range(32) if resp_crc5(frame[2:10], i) == frame[10] & 0x1F]
    assert 0x1B not in matching, matching
    assert matching, "comparative trailer must match some init (desk-only)"

    jig = (
        ROOT.parents[1]
        / ""
    )
    if jig.is_file():
        blob = jig.read_bytes()
        assert blob.find(bytes.fromhex("55AA2136")) < 0
        assert blob.find(bytes.fromhex("55AA2156")) < 0
        i = blob.find(bytes.fromhex("2136"))
        assert i > 0
        # First 21 36 adjacency is Thumb `movs r1,#0x30; add r0,sp,#imm`, not a job prefix.
        assert blob[i - 1 : i + 3] == bytes.fromhex("302136a8"), blob[
            i - 2 : i + 4
        ].hex()

    uart_trans = (ROOT / "dcentrald/dcentrald-asic/src/uart_trans/mod.rs").read_text(
        encoding="utf-8"
    )
    assert "JOB_LEN_FIELD" in uart_trans
    assert "UART_TRANS_BM1362_LEN_FIELD" in uart_trans
    assert "S19k 21 36" in uart_trans
    assert "work_frame_from_s19k_21_36_command_is_admitted" in uart_trans
    init_seq = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8")
    assert "refuse_esp_s19xp_hcn_as_s19k_rearm" in init_seq
    assert "ESP_BM1366_HASH_COUNTING_S19XP: u32 = 0x0000_151C" in init_seq
    uart_job = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_uart_trans_job.rs"
    ).read_text(encoding="utf-8")
    assert "admit_uart_trans_command_len_field" in uart_job
    assert "BM1362_UART_TRANS_LEN_FIELD: u8 = 0x56" in uart_job
    assert "admit_uart_trans_mmap_layout" in uart_job
    assert "admit_uart_trans_history_layout" in uart_job
    assert "UART_TRANS_MMAP_LEN: usize = 0x20_D0C" in uart_job
    assert "UART_TRANS_HISTORY_OFF: usize = 0x1F_80C" in uart_job
    assert "UART_TRANS_IOCTL_SET_WQ: u32 = 0x4004_7502" in uart_job
    assert "UART_TRANS_IOCTL_START_TIMER: u32 = 0x7505" in uart_job
    assert "UART_TRANS_IOCTL_CLEAN_WORK: u32 = 0x7507" in uart_job
    assert "UART_TRANS_IOCTL_SEND_ONCE: u32 = 0x4004_750A" in uart_job
    assert "pack_uart_trans_ring_element" in uart_job
    assert "pack_uart_trans_ring_from_header_chunk" in uart_job
    assert "uart_trans_next_write_idx" in uart_job
    assert "pack_s19k_closed_uart_trans_ring" in job
    assert "refuse_braiins_uart_trans_mmap" in uart_job
    assert "refuse_work_base_plus8_given_history" in uart_job
    assert "admit_uart_trans_work_base_from_history" in uart_job
    assert "admit_uart_trans_host_bind_plan" in uart_job
    assert "refuse_uart_trans_host_bind_execution" in uart_job
    assert "UART_TRANS_CAPSTONE_WORK_BASE" in uart_job
    assert "refuse_uart_trans_work_base_sot_without_4cc0" in uart_job
    assert "refuse_bm1362_ioctl_as_s19k_aml" in uart_job
    assert "UART_TRANS_4CC0_SEARCHED_HINTS" in uart_job
    assert "refuse_held_cvctrl_uart_trans_as_s19k_aml_4cc0" in uart_job
    assert "format_uart_trans_host_bind_plan" in uart_job
    assert "refuse_uart_trans_set_baud_as_bind_step" in uart_job
    assert "" in uart_job
    live_bins = (
        ROOT.parents[1]
        / ""
        / "04-binaries"
    )
    if live_bins.is_dir():
        named = [p.name for p in live_bins.iterdir()]
        assert not any("4cc0" in n.lower() for n in named)
        assert not any(n.startswith("bmminer") for n in named)
    cv_ko = (
        ROOT.parents[1]
        / ""
        / "unpacked/inner/CVCtrl_extracted/lib/modules/uart_trans.ko"
    )
    if cv_ko.is_file():
        ko = cv_ko.read_bytes()
        assert b"0x20d0c" not in ko
        assert b"1F80C" not in ko
    s11 = ROOT / ""
    s11t = s11.read_text(encoding="utf-8", errors="replace")
    assert "# pwr_en 437" in s11t
    assert "echo 1 > /sys/class/gpio/gpio437/value" in s11t
    gpio437_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_gpio437.rs"
    ).read_text(encoding="utf-8")
    assert "admit_vnish_s19k_s11_pwr_en_boot_is_safeoff" in gpio437_rs
    assert "refuse_checked_low_as_am3_s19k_safeoff_wording" in gpio437_rs
    assert "admit_s19k_production_safeoff_wording" in gpio437_rs
    assert "admit_s19k_crash_teardown_safeoff_value" in gpio437_rs
    assert "admit_s19k_disable_psu_checked_exports_before_write" in gpio437_rs
    assert "admit_s19k_hal_resolves_pwr_control_before_sysfs" in gpio437_rs
    assert "admit_s19k_hal_resolves_plug_reset_by_name" in gpio437_rs
    assert "admit_s19k_track1_does_not_pulse_hb_reset" in gpio437_rs
    assert "admit_s19k_track1_preflight_resolves_plug_psu" in gpio437_rs
    assert "admit_s19k_hal_resolves_fan_tach_by_name" in gpio437_rs
    assert "admit_s19k_hal_resolves_led_and_pinmux_by_name" in gpio437_rs
    assert "S19K_AM3_FAN_TACH_DT_NAMES" in gpio437_rs
    assert "S19K_AM3_LED_RED_DT_NAME" in gpio437_rs
    assert "S19K_AM3_I2C_SCL_DT_NAME" in gpio437_rs
    assert "s19k_am3_fan_tach_sysfs_n" in gpio437_rs
    assert "s19k_am3_led_sysfs_n" in gpio437_rs
    assert "s19k_am3_pinmux_sysfs_n" in gpio437_rs
    assert "S19K_AM3_PWR_CONTROL_DT_NAME" in gpio437_rs
    assert "S19K_AM3_PLUG_DT_NAMES" in gpio437_rs
    assert "S19K_AM3_RESET_DT_NAMES" in gpio437_rs
    assert "s19k_am3_pwr_control_sysfs_n" in gpio437_rs
    assert "s19k_am3_plug_sysfs_n" in gpio437_rs
    assert "s19k_am3_reset_sysfs_n" in gpio437_rs
    assert "refuse_hb0_plug_as_amlogic_primary" in gpio437_rs
    assert "refuse_hb3_reset_as_s19k_fourth_board" in gpio437_rs
    assert "resolve_name_or_legacy" in (
        ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
    ).read_text(encoding="utf-8")
    assert '"PWR_CONTROL"' in (
        ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs"
    ).read_text(encoding="utf-8")
    assert "admit_s19k_track1_mining_on_does_not_write_gpio437" in gpio437_rs
    hal_aml = (ROOT / "dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs").read_text(
        encoding="utf-8"
    )
    assert (
        '"CH0_PLUG"' in hal_aml and '"CH1_PLUG"' in hal_aml and '"CH2_PLUG"' in hal_aml
    )
    assert (
        '"HB0_RESET"' in hal_aml
        and '"HB1_RESET"' in hal_aml
        and '"HB2_RESET"' in hal_aml
    )
    assert "resolve_plug_gpio_global" in hal_aml
    assert "resolve_reset_gpio_global" in hal_aml
    plug_fn = hal_aml.find("fn resolve_plug_gpio_global")
    plug_fn_end = hal_aml.find("fn resolve_reset_gpio_global", plug_fn)
    assert plug_fn != -1 and plug_fn_end != -1
    assert '"HB0_PLUG"' not in hal_aml[plug_fn:plug_fn_end]
    topo = hal_aml.find("fn read_plug_topology_checked")
    topo_end = hal_aml.find("Ok(populated)", topo)
    assert topo != -1 and topo_end != -1
    assert "resolve_plug_gpio_global" in hal_aml[topo:topo_end]
    assert "GPIO_PLUG_BASE +" not in hal_aml[topo:topo_end]
    rst = hal_aml.find("fn set_board_reset(&self")
    rst_end = hal_aml.find("// PSU enable for cold boot", rst)
    assert rst != -1 and rst_end != -1
    assert "set_amlogic_board_reset_checked" in hal_aml[rst:rst_end]
    assert "checked write failed" in hal_aml[rst:rst_end]
    assert "let _ = fs::write" not in hal_aml[rst:rst_end]
    assert "GPIO_RESET_BASE +" not in hal_aml[rst:rst_end]
    t1_win = serial.find("PASSTHROUGH BM1366")
    t1_seam = serial.find("} else if passthrough {", t1_win)
    assert t1_win != -1 and t1_seam != -1
    assert "set_board_reset" not in serial[t1_win:t1_seam]
    assert "s19k_plug_sysfs_paths()" not in serial[t1_win:t1_seam]
    assert "/sys/class/gpio/gpio437/value" not in serial[t1_win:t1_seam]
    assert "resolve_psu_gpio_global" in serial[t1_win:t1_seam]
    assert "resolve_plug_gpio_global" in serial[t1_win:t1_seam]
    assert '"FAN_FRONT_SPEED0"' in hal_aml
    assert '"FAN_REAR_SPEED1"' in hal_aml
    assert "resolve_fan_tach_gpio_global" in hal_aml
    fan_arm = hal_aml.find("Bring up gpio447-450 as one complete cooling-observation")
    fan_end = hal_aml.find("complete GPIO falling-edge counter set armed", fan_arm)
    assert fan_arm != -1 and fan_end != -1
    assert "resolve_fan_tach_gpio_global" in hal_aml[fan_arm:fan_end]
    assert "GPIO_FAN_TACH_BASE +" not in hal_aml[fan_arm:fan_end]
    assert '"LED_RED"' in hal_aml and '"LED_GREEN"' in hal_aml
    assert '"I2C_SCL"' in hal_aml and '"I2C_SDA"' in hal_aml
    assert "resolve_led_gpio_global" in hal_aml
    assert "resolve_pinmux_gpio_global" in hal_aml
    assert "write_amlogic_status_led" in hal_aml
    pinmux = hal_aml.find("fn prepare_management_i2c_pinmux")
    pinmux_end = hal_aml.find("Ok(())", pinmux)
    assert pinmux != -1 and pinmux_end != -1
    assert "resolve_pinmux_gpio_global" in hal_aml[pinmux:pinmux_end]
    assert "for gpio in GPIO_PINMUX_FIX" not in hal_aml[pinmux:pinmux_end]
    assert "write_amlogic_status_led" not in serial[t1_win:t1_seam]
    s37t = (
        ROOT
        / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
    ).read_text(encoding="utf-8", errors="replace")
    assert "LED_GREEN=453" in s37t and "LED_RED=438" in s37t
    assert "I2C_SCL=476" in s37t and "I2C_SDA=477" in s37t
    assert "for GPIO in 453 438" in s37t
    assert "for GPIO in 476 477" in s37t
    dis = hal_aml.find("fn drive_psu_checked_at(")
    dis_end = hal_aml.find("fn read_psu_active_low_disabled_checked_at(", dis)
    assert dis != -1 and dis_end != -1 and dis < dis_end
    dis_body = hal_aml[dis:dis_end]
    assert 'gpio_root.join("export")' in dis_body
    assert 'write(&base.join("direction"), recipe.off_direction())' in dis_body
    assert 'write(&base.join("value"), &raw.to_string())' in dis_body
    assert "read_psu_enabled_on_with_recipe_at(gpio_root, n, recipe)? != on" in dis_body
    assert "enable_psu_gpio()?;" not in dis_body
    assert "let _ = enable_psu_gpio" not in dis_body
    assert dis_body.index('gpio_root.join("export")') < dis_body.index(
        'write(&base.join("direction"), recipe.off_direction())'
    ) < dis_body.index('write(&base.join("value"), &raw.to_string())')
    profile = hal_aml[hal_aml.find("impl AmlogicNoPicProfile") : hal_aml.find(
        "pub struct AmlogicNoPicAdmission"
    )]
    assert "fn board_target(self) -> &'static str" in profile
    assert "fn psu_is_active_low" not in profile
    authority = hal_aml[hal_aml.find("struct AmlogicPsuCommitAuthority") : hal_aml.find(
        "fn amlogic_psu_enable_superseded"
    )]
    assert "board_target: profile.board_target()" in authority
    assert "recipe: OnceLock<Gpio437DriveRecipe>" in authority
    assert "amlogic_gpio437::resolve_population_recipe(self.board_target, &names)" in authority
    assert "self.recipe().and_then(disable_psu_checked_for_recipe)" in authority
    assert "disable_psu_checked()" not in authority
    assert "amlogic_board_target_is_s19k" not in authority
    lifecycle = hal_aml[
        hal_aml.find("impl AmlogicPowerThermalLifecycleOwner") : hal_aml.find(
            "pub struct AmlogicPsuEnableOperation"
        )
    ]
    assert (
        "disable_psu_checked_for_recipe(self.psu_commit.recipe()?)?"
        in lifecycle
    )
    assert "disable_psu_checked()" not in lifecycle
    power_operation = hal_aml[
        hal_aml.find("struct AmlogicPsuGpioRollback") : hal_aml.find(
            "impl AmlogicThermalPort"
        )
    ]
    assert "AmlogicPsuGpioRollback::armed(recipe)" in power_operation
    assert "enable_psu_gpio_for_recipe(recipe)" in power_operation
    assert "fn enable_psu_gpio() -> Result<()>" not in hal_aml
    assert "disable_psu_checked_for_recipe(self.recipe)" in power_operation
    assert "disable_psu_checked()" not in power_operation
    assert "if amlogic_board_target_is_s19k" not in power_operation
    assert (
        "Self::spawn_with_required_slots_and_generation( admission.populated_slots(), "
        "admission.profile(), Some(Arc::clone(&admission.generation)), )?"
    ) in " ".join(hal_aml.split())
    assert "AmlogicPsuCommitAuthority::new(profile, native_generation)" in hal_aml
    assert "native_generation: self.psu_commit.native_generation.clone()" in hal_aml
    assert "admit_amlogic_retained_power_owner_freezes_profile_polarity" in gpio437_rs
    assert "admit_s19k_track1_arms_teardown_without_enable" in gpio437_rs
    assert "admit_s19k_track1_arms_watchdog_without_enable" in gpio437_rs
    assert "s19k_track1_mark_watchdog_liveness" in serial
    assert (
        "Track-1 SoC watchdog/route positively admitted at terminal stock-process boundary"
        in serial
    )
    t1_arm = serial.find(
        "let watchdog_start = SafetyWatchdogOwner::start_before_energizing"
    )
    t1_seam = serial.find("let serial = if braiins_bm1366_passthrough_handoff", t1_arm)
    assert t1_arm != -1 and t1_seam != -1 and t1_arm < t1_seam
    t1_wd = serial[t1_arm:t1_seam]
    assert "start_before_energizing" in t1_wd
    assert "prepare_enable(" not in t1_wd
    assert "enable_psu(" not in t1_wd
    assert "admit_s19k_track1_watchdog_sla(&receipt)" in t1_wd
    assert "SerialRouteDomains::claim_s19k_track1(" in t1_wd
    assert "nopic_watchdog = Some(watchdog_owner)" in t1_wd
    assert (
        0
        <= t1_wd.find("expected.require_exact_tree_at")
        < t1_wd.find(".assume_inherited_rails();")
        < t1_wd.find(".sigkill_and_wait(")
    )
    assert "arm_s19k_track1_teardown" in serial
    assert "s19k_track1_maybe_planned_stop_safeoff" in serial
    assert "DCENT_S19K_TRACK1_STOP_SAFEOFF" in gpio437_rs
    assert "admit_s19k_production_planned_stop_is_fail_closed" in gpio437_rs
    assert "GPIO437 is checked low" not in serial
    assert "power is checked low" not in serial
    assert "checked SafeOff" in serial
    assert "refuse_vnish_s11_empty_stop_as_dcent_shutdown" in gpio437_rs
    assert "refuse_vnish_s11_uninitialized_hb_reset_as_dcent" in gpio437_rs
    assert "admit_dcent_s37_asserts_hb_reset_at_boot" in gpio437_rs
    assert "refuse_vnish_s11_start_as_electrical_safeoff" in gpio437_rs
    s37 = (
        ROOT
        / "br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup"
    ).read_text(encoding="utf-8", errors="replace")
    assert "for GPIO in 454 455 456" in s37
    assert "configure_output_low_gpio" in s37
    assert "Hold hashboards in reset" in s37

    # --- : post-clean share-funnel discriminator (live414/417/418
    # cliff: correlated ticket nonces never pass the pool target after the
    # first mid-run clean; live412 proves non-clean updates replace work) ---
    engine = (ROOT / "dcentrald/dcentrald-common/src/serial_work_engine.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "pub struct S19kCleanFunnel" in engine
    assert "DUMPS_PER_CLEAN" in engine
    assert "admit_s19k_production_clean_funnel_instrumented" in engine
    assert "clean_funnel.on_clean()" in serial
    assert "clean_funnel.take_dump_for(" in serial
    assert "s19k_track1_alive_gpio437_field" in serial
    assert "s19k_first_tx_hex_where" in serial
    assert "s19k_leftover_hit_from_retired_store" in serial
    assert "s19k_leftover_class_matches_retired_tx" in serial
    assert "leftover_header" in serial
    assert "nonce_silent_s" in serial
    install_rs = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_am3_install.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "s19k_track1_tmpfs_stage_allowed" in install_rs
    assert "s19k_track1_soak_should_stop" in install_rs
    assert "fn s19k_track1_parse_wrap_rx" in install_rs
    assert "fn s19k_track1_alive_line_wrap7" in install_rs
    assert "fn admit_s19k_live432_tx_wrap_does_not_stop_wrap7_t600" in install_rs
    assert "fn s19k_track1_production_endurance_requires_stop(" in serial
    assert (
        "s19k_track1_soak_decision(elapsed_s, nonce_silent_s, wrap_rx, false)" in serial
    )
    assert "s19k_track1_soak_should_stop(" not in serial
    assert (
        "s19k_production_endurance_never_grants_itself_bounded_bench_completion"
        in serial
    )
    assert "S19k Track-1 RX-death stop predicate reached; revoking work" in serial
    assert "DispatchRevocationCause::HeartbeatFailure" in serial
    assert "S19K_TRACK1_SOAK_MAX_S: u64 = 1500" in install_rs
    assert (
        "fn s19k_track1_tmpfs_refuses_live426_enospc_copy_and_admits_hardlink"
        in install_rs
    )
    assert (
        "fn s19k_track1_soak_does_not_stop_at_live427_620s_without_clean" in install_rs
    )
    assert "S19K_TRACK1_SOAK_T600_S: u64 = 600" in install_rs
    assert "S19K_TRACK1_SOAK_WRAP7: u64 = 7" in install_rs
    assert "fn refuse_s19k_live431_220s_as_wrap7_t600" in install_rs
    assert "fn admit_s19k_track1_restore_never_writes_gpio437" in install_rs
    assert "fn s19k_track1_launch_may_kill" in install_rs
    assert "fn admit_s19k_track1_launch_kills_owned_pid_only" in install_rs
    assert "fn refuse_s19k_live429_sigterm_as_leftover_or_wrap" in install_rs
    uart_job = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_uart_trans_job.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "fn refuse_s19k_stock_uart_job_id_as_slot_shift" in uart_job
    assert "stock pack_asic_work job_id is work_id&0xff" in uart_job
    live430_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert not any(
        "kill $(pidof dcentrald)" in line
        for line in live430_launch.splitlines()
        if not line.lstrip().startswith("#")
    )
    assert 'kill "$OWNED"' in live430_launch
    assert "dcentrald.pid" in live430_launch
    assert "nonce_silent_s=90" in live430_launch
    live431_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert not any(
        "kill $(pidof dcentrald)" in line
        for line in live431_launch.splitlines()
        if not line.lstrip().startswith("#")
    )
    assert 'kill "$OWNED"' in live431_launch
    assert "dcentrald.pid" in live431_launch
    assert "nonce_silent_s=90" in live431_launch
    assert "s1_silent_s" in live431_launch
    assert "wrap_idx" in live431_launch
    live431_toml = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "passthrough = true" in live431_toml
    assert "CLEAR_FOR_FLASH" not in live431_toml
    discover = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_chain_discover.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "S19K_LIVE427_S1_LAST_RX_MS: u32 = 187_676" in discover
    assert "fn refuse_s19k_live427_as_chain_inactive_result" in discover
    assert "fn s19k_track1_wrap_index" in discover
    assert "fn refuse_s19k_wrap_tx_skip_as_survival" in discover
    assert "fn s19k_track1_soak_rx_dead" in install_rs
    assert "S19K_TRACK1_SOAK_RX_DEAD_S: u64 = 90" in install_rs
    assert "fn s19k_track1_tracing_ansi_enabled" in install_rs
    assert "fn admit_s19k_production_honors_rust_log_style_never" in install_rs
    logging_rs = (ROOT / "dcentrald/dcentrald/src/logging.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "s19k_track1_tracing_ansi_enabled" in logging_rs
    assert "with_ansi(ansi)" in logging_rs
    assert "fn refuse_s19k_restore_plan_as_execute_grant" in install_rs
    assert "s19k_track1_wrap_index" in serial
    assert "wrap_idx" in serial
    assert "fn s19k_esp_bm1366_job_slot_count" in discover
    assert "fn refuse_s19k_esp_plus8_mod128_as_track1_fill" in discover
    assert "fn refuse_s19k_bosminer_registry_wrap_as_chip_uart_abort" in discover
    assert "fn s19k_leftover_hit_from_retired_store" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs"
    ).read_text(encoding="utf-8", errors="replace")
    share_rs = (ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "fn insert_wire_retiring" in share_rs
    assert "fn refuse_s19k_wrap7_same_id_drop_without_retire" in share_rs
    assert "fn admit_s19k_production_retires_wrap_overwrite" in share_rs
    assert "fn s19k_track1_hunt_retired_without_funnel" in share_rs
    assert "fn s19k_track1_count_wrap_retire_leftover" in share_rs
    assert "fn s19k_track1_refuse_wrap_retired_submit" in share_rs
    assert "s19k_track1_hunt_retired_without_funnel" in serial
    assert "s19k_track1_count_wrap_retire_leftover" in serial
    assert "s19k_track1_refuse_wrap_retired_submit" in serial
    assert "s19k_restore_wrap_retire_leftover_after_clean_snapshot" in serial
    assert "S19k wrap-retire leftover" in serial
    assert "s19k_track1_count_wrap_retire_leftover" in serial
    assert "s19k_track1_refuse_wrap_retired_submit" in serial
    assert "fn admit_s19k_install_backup_reads_gpio437_before_safeoff" in install_rs
    assert "fn s19k_track1_note_port_rx" in discover
    assert "fn s19k_track1_port_silent_s" in discover
    assert "s1_silent_s" in serial
    assert "s2_silent_s" in serial
    assert "S19K_TRACK1_RX_CHANNEL" in serial
    assert "mpsc::channel::<S19kSerialRxHit>(256)" not in serial
    assert "fn admit_s19k_live430_wrap4_gpio_on_no_clean" in discover
    assert "fn refuse_s19k_live430_as_leftover_or_sigterm" in discover
    assert "fn admit_s19k_live431_wrap6_after_live_clean" in discover
    assert "fn refuse_s19k_live431_as_wrap7_t600" in discover
    braiins_job_live = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_job.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "fn s19k_leftover_hit_admits_experimental_inactive" in braiins_job_live
    assert (
        "fn admit_s19k_live436_wrap_retire_leftover_admits_first_clean_inactive"
        in braiins_job_live
    )
    assert "S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT: u32 = 3" in braiins_job_live
    assert "fn s19k_leftover_hit_vs_meets_replace_proven" in braiins_job_live
    assert "fn s19k_plan_wrap4_early_leftover_safe" in braiins_job_live
    assert "fn s19k_wrap4_early_leftover_safe_due" in braiins_job_live
    assert "fn admit_s19k_live434_wrap4_early_clean_was_due" in braiins_job_live
    assert (
        "fn admit_s19k_live436_leftover3_wrap4_early_admits_inactive"
        in braiins_job_live
    )
    assert (
        "fn admit_s19k_live437_wrap4_same_tick_admits_before_header_climb"
        in braiins_job_live
    )
    assert "fn admit_s19k_production_wrap4_logs_snapshot_leftover" in braiins_job_live
    assert "let admit_hit = clean_funnel.leftover_hit" in serial
    assert (
        "fn admit_s19k_live437_launch_wrap4_early_is_experimental" in braiins_job_live
    )
    assert "Same-tick admit uses the" in braiins_job_live
    live437_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1" in live437_launch
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1" in live437_launch
    assert 'kill "$OWNED"' in live437_launch
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live437_launch
    live437_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live437_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live437_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live437_restore
    live438_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1" in live438_launch
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1" in live438_launch
    assert "wrap-4 leftover-admitted chain-inactive" in live438_launch
    assert 'kill "$OWNED"' in live438_launch
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live438_launch
    live438_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live438_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live438_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live438_restore
    live439_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1" in live439_launch
    assert "flush_measured" in (
        ROOT / "dcentrald/dcentrald/src/serial_mining.rs"
    ).read_text(encoding="utf-8")
    live439_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live439_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live439_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live439_restore
    assert "fn admit_s19k_live435_dual_port_wrap7" in discover
    assert "fn refuse_s19k_live435_as_wrap7_t600" in discover
    assert "S19K_LIVE435_WRAP_RX: u32 = 8" in discover
    assert "fn admit_s19k_live436_wrap4_death_with_wrap_retire_leftover" in discover
    assert "fn refuse_s19k_live436_as_wrap7_t600_or_replace" in discover
    assert "S19K_LIVE436_WRAP_RX: u32 = 4" in discover
    assert "fn admit_s19k_live437_wrap4_snapshot_without_inactive" in discover
    assert "fn refuse_s19k_live437_as_leftover_admit_or_t600" in discover
    assert "S19K_LIVE437_WRAP_RX: u32 = 6" in discover
    assert "S19K_LIVE437_WRAP4_SNAPSHOT_LEFTOVER_HIT: u32 = 4" in discover
    assert "fn admit_s19k_live438_wrap4_same_tick_queued_cmd3" in discover
    assert "fn refuse_s19k_live438_admit_as_replace" in discover
    assert "S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 6" in discover
    assert "fn admit_s19k_live439_wrap7_after_leftover_admit" in discover
    assert "fn refuse_s19k_live439_as_replace_or_t600" in discover
    assert "fn admit_s19k_live440_wrap7_header_only_does_not_readmit" in discover
    assert "fn admit_s19k_live441_wrap6_death_before_wrap7_snapshot" in discover
    assert "S19K_LIVE441_WRAP_RX: u32 = 6" in discover
    assert "S19K_LIVE441_WRAP7_SNAP_QUEUED: u32 = 0" in discover
    assert "fn refuse_s19k_live440_as_replace_or_t600" in discover
    assert "S19K_LIVE440_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 1" in discover
    assert "S19K_LIVE440_WRAP7_READMIT_QUEUED: u32 = 0" in discover
    assert "S19K_LIVE440_WRAP_RX: u32 = 7" in discover
    assert "S19K_LIVE439_WRAP4_ADMIT_LEFTOVER_HIT: u32 = 2" in discover
    assert "S19K_LIVE439_SECOND_CLEAN_LEFTOVER_HIT: u32 = 216" in discover
    assert "S19K_LIVE439_WRAP_RX_ALIVE: u32 = 7" in discover
    assert "fn s19k_wrap7_leftover_readmit_due" in braiins_job_live
    assert "fn s19k_wrap7_leftover_snapshot_due" in braiins_job_live
    assert "fn admit_s19k_live440_wrap7_snapshots_post_admit_store" in braiins_job_live
    assert "fn admit_s19k_live439_wrap7_leftover_readmit" in braiins_job_live
    assert "s19k_wrap7_leftover_snapshot_due(" in serial
    assert "S19k wrap-7 leftover snapshot (experimental)" in serial
    assert (
        "fn refuse_s19k_bosminer_53050000_as_chain_inactive_template"
        in braiins_job_live
    )
    assert "fn refuse_s19k_jig_chain_inactive_log_as_midrun_abort" in braiins_job_live
    assert "s19k_track1_rx_death_parser_note" in serial
    assert "rx_parser" in serial
    assert "Serial RX wire observation" in (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    bosminer_bin = (
        ROOT.parent.parent
        / ""
    )
    if bosminer_bin.is_file():
        bos = bosminer_bin.read_bytes()
        assert bos.find(bytes.fromhex("55aa5305")) < 0
        first_5305 = bos.find(bytes.fromhex("53050000"))
        assert first_5305 > 4
        assert bos[first_5305 - 4 : first_5305] == bytes.fromhex("52050000")
    jig_bin = (
        ROOT.parent.parent
        / ""
    )
    if jig_bin.is_file():
        jig = jig_bin.read_bytes()
        assert b"Set chain inactive" in jig
        assert jig.find(b"Set chain inactive") < jig.find(b"Set asic address")
        assert jig.find(bytes.fromhex("55aa5305")) < 0
        assert jig.find(bytes.fromhex("55aa2136")) < 0
    assert "fn s19k_live439_planner_numbers_drive_shipped_helpers" in braiins_job_live
    assert "leftover_hit > 0 && meets == 0" in braiins_job_live
    assert "s19k_wrap7_leftover_readmit_due(" in serial
    assert "wrap7_leftover_readmitted" in serial
    assert "S19k wrap-7 leftover-readmit chain-inactive (experimental)" in serial
    live440_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1" in live440_launch
    assert "wrap-7 leftover-readmit" in live440_launch
    live441_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1" in live441_launch
    assert "wrap-7 leftover snapshot" in live441_launch
    live441_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live441_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live441_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live441_restore
    live440_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live440_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live440_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live440_restore
    assert "fn s19k_post_inactive_flush_measured_not_replace" in braiins_job_live
    assert "fn refuse_s19k_live438_post_flush_leftover0_as_replace" in braiins_job_live
    assert "fn s19k_leftover_header_is_not_tx_leftover" in braiins_job_live
    assert "fn refuse_s19k_live438_header_leftover_as_second_cmd3" in braiins_job_live
    assert "s19k_leftover_header_is_not_tx_leftover" in serial
    assert "s19k_post_inactive_flush_measured_not_replace" in serial
    assert "flush_measured" in serial
    assert "CLEAR_FOR_FLASH: bool = false" in install_rs
    assert "S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HEADER: u32 = 0" in discover
    assert "S19K_LIVE438_S1_LAST_RX_MS: u32 = 151_822" in discover
    assert "fn admit_s19k_job_flip_is_leftover_admitted" in braiins_job_live
    assert "fn s19k_post_inactive_replace_proven" in braiins_job_live
    assert "s19k_post_inactive_replace_proven(" in serial
    assert "replace_proven" in serial
    assert (
        "fn admit_s19k_second_clean_plans_from_pre_reset_leftover" in braiins_job_live
    )
    assert "snapshot_for_post_clean_plan" in serial
    assert "on_leftover_admitted_inactive" in serial
    assert "fn s19k_experimental_wrap4_early_clean_enabled_from_env" in braiins_job_live
    assert "s19k_plan_wrap4_early_leftover_safe(" in serial
    assert "s19k_track1_clean_after_rx_death_silent" in serial
    assert "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN" in serial
    assert "fn admit_s19k_live431_leftover_vs_meets_unproven" in braiins_job_live
    assert "fn admit_s19k_live433_leftover_vs_meets_unproven" in braiins_job_live
    assert (
        "fn admit_s19k_live431_leftover_admits_experimental_inactive"
        in braiins_job_live
    )
    assert "clean_funnel.leftover_hit" in serial
    assert "leftover_header" in serial
    assert "fn s19k_track1_leftover_handoff_gpio437_ok" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8", errors="replace")
    init_seq_gpio = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "fn s19k_track1_refuse_work_tx_if_gpio437_not_on" in init_seq_gpio
    assert "fn admit_s19k_production_refuses_tx_when_gpio437_off" in init_seq_gpio
    assert "s19k_track1_refuse_work_tx_if_gpio437_not_on" in serial
    assert "S19k leftover handoff gpio437 not ON" in serial
    assert "fn refuse_s19k_s21_pwr_en_polarity_as_am3_s19k" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "fn refuse_s19k_dcent_sysupgrade_execute_while_flash_false" in install_rs
    assert "fn s19k_track1_note_wrap_at_rx" in discover
    assert "wrap_rx" in serial
    assert "fn s19k_track1_alive_line_rx_dead" in install_rs
    assert "fn admit_s19k_track1_launch_rx_dead_is_ge_90" in install_rs
    assert "fn admit_s19k_live432_rx_died_after_first_clean_inactive" in discover
    assert "fn classify_s19k_track1_rx_death" in discover
    assert "fn s19k_track1_tx_wrap_after_rx_death" in discover
    assert "fn admit_s19k_live433_wrap6_identity_death" in discover
    assert "fn classify_s19k_held_uart_wrap6" in discover
    assert "fn admit_s19k_wrap6_death_not_held_uart_abort" in discover
    assert "fn admit_s19k_live434_wrap4_identity_death" in discover
    assert "fn s19k_track1_clean_after_rx_death_ms" in discover
    assert "fn s19k_track1_clean_after_rx_death_silent" in discover
    assert "CleanAfterRxDeath" in discover
    assert "fn s19k_held_uart_prefix_is_wrap6_abort" in discover
    assert "S19K_TRACK1_WRAP6_TX" in discover
    assert (
        "TxWrapAfterRxDeath"
        not in discover.split("pub enum S19kTrack1RxDeathClass", 1)[-1].split("}", 1)[0]
    )
    assert "fn admit_s19k_aml_mutation" in install_rs
    assert "fn refuse_s19k_leftover_admitted_inactive_as_flash_grant" in install_rs
    assert "fn leftover_admit_is_refused_as_flash_grant" in install_rs
    assert "fn s19k_aml_intent_from_artifact" in install_rs
    assert "fn admit_s19k_aml_artifact" in install_rs
    assert "fn refuse_s19k_rescue_console_as_nandwrite_grant" in install_rs
    assert "fn refuse_s19k_rollback_plan_as_execute_grant" in install_rs
    assert "fn admit_s19k_recover_script_refuses_execute_before_gpio" in install_rs
    assert "fn refuse_s19k_backup_as_nandwrite_grant" in install_rs
    assert "enum S19kAmlMutationIntent" in install_rs
    assert "fn s19k_track1_parse_nonce_silent_s" in install_rs
    assert "fn admit_s19k_track1_launch_rx_dead_ignores_ansi" in install_rs
    assert "fn s19k_hunt_retired_after_outstanding_miss" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "live433: outstanding miss hunts retired 21 36" in serial
    assert "S19k leftover 21 36 via retired store" in serial
    assert "S19k track1 RX death class" in serial
    live433_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "nonce_silent_s=(9[0-9]" in live433_launch
    assert "wrap_rx=" in live433_launch
    assert 'kill "$OWNED"' in live433_launch
    assert "RUST_LOG_STYLE=never" not in live433_launch
    live434_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "RUST_LOG_STYLE=never" in live434_launch
    assert "nonce_silent_s.{0,40}" in live434_launch
    assert "wrap_rx=" in live434_launch
    assert 'kill "$OWNED"' in live434_launch
    live434_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live434_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live434_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live434_restore
    live435_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "RUST_LOG_STYLE=never" in live435_launch
    assert "nonce_silent_s.{0,40}" in live435_launch
    assert "wrap_rx=" in live435_launch
    assert 'kill "$OWNED"' in live435_launch
    assert "S19k wrap-retire leftover" in live435_launch
    live435_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live435_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live435_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live435_restore
    assert "CLEAR_FOR_FLASH" not in (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    live432_launch = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert not any(
        "kill $(pidof dcentrald)" in line
        for line in live432_launch.splitlines()
        if not line.lstrip().startswith("#")
    )
    assert 'kill "$OWNED"' in live432_launch
    assert "nonce_silent_s=90" in live432_launch
    assert "wrap7_and_t600" in live432_launch
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1" in live432_launch
    live432_restore = (
        ROOT.parent.parent
        / ""
    ).read_text(encoding="utf-8", errors="replace")
    assert "S99bosminer start" in live432_restore
    assert "echo 1 > /sys/class/gpio/gpio437/value" not in live432_restore
    assert "echo 0 > /sys/class/gpio/gpio437/value" not in live432_restore
    assert "fn refuse_s19k_rx_channel_as_wrap7_survival" in (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_share.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "S19k post-clean funnel" in serial
    assert "S19k post-clean nonce dump" in serial
    assert "s19k_clean_funnel_armed(&clean_funnel)" in serial
    # : VNish v1.3.3 S11board production GPIO map pinned in rust.
    init_seq = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_bm1366_init_seq.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert "S19K_AML_CHAIN_RESET_GPIOS: [u32; 3] = [454, 455, 456]" in init_seq
    assert "S19K_AML_PWR_EN_GPIO: u32 = 437" in init_seq
    assert "admit_s19k_aml_chain_reset_gpios" in init_seq

    # --- : post-clean chain-inactive broadcast (experimental).
    # BM1366 protocol CMD=3 chain inactive (55 AA 53 05 00 00 CRC5) is the
    # only documented chip-side work flush; shipped env-gated as the live
    # follow-up when leftover_hit dominates the funnel. ---
    braiins_job = (
        ROOT / "dcentrald/dcentrald-common/src/s19k_braiins_job.rs"
    ).read_text(encoding="utf-8", errors="replace")
    assert (
        "S19K_BM1366_CHAIN_INACTIVE_BODY: [u8; 4] = [0x53, 0x05, 0x00, 0x00]"
        in braiins_job
    )
    assert "S19K_BM1366_CHAIN_INACTIVE_WIRE: [u8; 7]" in braiins_job
    assert "refuse_s19k_post_clean_chain_inactive_as_production" in braiins_job
    assert "admit_s19k_production_post_clean_chain_inactive_is_env_gated" in braiins_job
    assert "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE" in serial
    assert "actor_send_chain_inactive_bm1366" in serial
    assert "S19k post-clean chain-inactive broadcast queued" in serial
    assert "if frame.as_slice() == S19K_BM1366_CHAIN_INACTIVE_BODY" in serial

    # --- : FR-1.28 (251010) stock S19k Pro .bmu 3-variant TOC
    # parser (RE only). AMLCtrl/zynq7007/CVCtrl blobs tile the container;
    # never nandwrite a BMU. ---
    bmu_toc = (ROOT / "dcentrald/dcentrald-common/src/s19k_stock_bmu_toc.rs").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "pub mod" not in bmu_toc
    assert "S19K_BMU_TOC_MAGIC: u32 = 0xABAB_ABAB" in bmu_toc
    assert "AMLCtrl_BHB56XXX" in bmu_toc
    assert "zynq7007_BHB56XXX" in bmu_toc
    assert "CVCtrl_BHB56XXX" in bmu_toc
    assert "refuse_s19k_bmu_nand_write" in bmu_toc
    assert "refuse_s19k_bmu_fr128_as_legacy_single_image" in bmu_toc
    assert "pub mod s19k_stock_bmu_toc;" in (
        ROOT / "dcentrald/dcentrald-common/src/lib.rs"
    ).read_text(encoding="utf-8", errors="replace")

    # --- : parser-boundary UART telemetry. A future authorized run
    # must distinguish host-observed wire silence from bytes that reach the
    # UART but fail to assemble into complete BM1366 responses. ---
    assert "pub fn classify_serial_rx_interval(" in engine
    assert "SerialRxIntervalState::WireOnlyProgress" in engine
    assert "SerialRxIntervalState::CounterReset" in engine
    assert "pub struct SerialRxObservation" in hal
    assert "rx_wire_bytes: AtomicU64" in hal
    assert "rx_framed_responses: AtomicU64" in hal
    assert "pub fn rx_observation(&self) -> SerialRxObservation" in hal
    assert "fn actor_rx_observations(&self)" in serial
    assert "classify_serial_rx_interval(" in serial
    assert '"Serial RX wire observation"' in serial

    print("S19K_HOST_VERIFY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
