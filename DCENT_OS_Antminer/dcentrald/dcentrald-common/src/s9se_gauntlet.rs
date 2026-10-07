//! S9 SE gauntlet + — host-testable admit/refuse owner.
//!
//! Same shape as the S19k gauntlet (`DCENT_OS_Antminer/):
//! one claim, one evidence pin, one rust admit/refuse, FLASH/mining remain
//! refused. This module does **not** open UART, mmap FPGA, or energize rails.
//!
//! Evidence:
//! - GitHub DCENT_OS#2 (live Ctrl_C43 / XC7Z007S, BM1393, 3×60)
//! - HiveOS S9 SE stock+client ramdisk `usr/bin/cgminer` (`cgminer_1393`)
//! - Held S9k `cgminer.dec` of the same driver-btm-soc / asic / zynq / power tree
//!
//! Ledger: .

use crate::asic_protocol;
use crate::board_desc::{AsicProtocolIdentity, BoardDesc, ChainTransportKind, WorkEngineKind};
use crate::pll_model::pll_family_for_protocol;
use crate::s9se_boot::{admit_boot_header, refuse_boot_bitstream_abi, BOOT_BIN_SIZE};
use crate::s9se_cooling::{
    admit_s9se_fan_sample, decide_s9se_cooling_action, hash_cut_dhash_word, pack_fan_control_word,
    S9SeCoolingAction, S9SeCoolingDecision, S9SeFanAdmission, CTRL_C43_S9SE_COOLING,
    FAN_CONTROL_OFFSET, FAN_SPEED_OFFSET,
};
use crate::s9se_eeprom::{
    admit_eeprom_crc, admit_major_is_1393, chip_minor_from_byte, eeprom_payload_crc16,
    refuse_s9se_eeprom_write, EEPROM_CRC_LEN,
};
use crate::s9se_enum::{
    admit_s9se_geometry, admit_s9se_production_interval, plan_s9se_address_program,
    refuse_am1_s9_chip_count,
};
use crate::s9se_fpga::{
    admit_hardware_version_low16, admit_s9se_fpga_mem_is_256mib_path, admit_three_populated_chains,
    apply_all_hashboard_reset, apply_hashboard_reset, block_header_version_1_word,
    decode_fan_speed_word, fpga_ticket_mask_word, merkle_bin_number_word, nonce2_jobid_store_phy,
    pack_bc_write_command, pack_zynq_iic, refuse_s9se_fpga_io, AXI_MMAP_BYTES, BC_WRITE_TRIGGER,
    BLOCK_HEADER_VERSION_2, BLOCK_HEADER_VERSION_3, BT8D_CONTROL, FPGA_MEM_OFFSET_256MIB,
    HARDWARE_VERSION_VALUE, HASH_COUNTING_OPEN_CORE, JOB_LENGTH, NONCE2_AND_JOBID_STORE,
    PRE_HEADER_HASH0, QN_WRITE_DATA_INIT,
};
use crate::s9se_identity::{
    admit_factory_conf, admit_uimage_header, refuse_factory_freq_token_as_mhz, ANT_VERSION,
    GPIO_LCD_CS, UIMAGE_SIZE,
};
use crate::s9se_init::{
    admit_expected_asic_count, admit_stock_bringup_order, plan_s9se_open_core,
    refuse_s9se_init_execute,
};
use crate::s9se_job::{
    coinbase_nonce2_word, decode_s9se_job, dhash_soc_init_word, dhash_start_no_ab_word,
    job_length_bytes, pack_pre_header_hash_words, pack_s9se_job, refuse_s9se_job_dispatch,
    S9SeJobPacket, DEFAULT_ASIC_DIFF, DHASH_NO_AB_OR, FLAG_TICKET_UPDATE, JOB_TYPE,
};
use crate::s9se_nand::{admit_nand_table, refuse_classic_s9_image, refuse_s9se_flash};
use crate::s9se_nonce::{
    classify_return_record, classify_s9se_nonce, refuse_s9se_nonce_fifo_io, S9SeFifoRecord,
};
use crate::s9se_pic::{
    crab_na_values, decode_an_voltage_v10, pack_crab_circuit, pack_get_an_voltage2,
    pack_get_crab_voltage, pack_get_pdcx, pack_get_software_version, pdcx_values, pic_iic_dev_addr,
    refuse_s9se_pic_flash, refuse_t11a_chain_swap_on_s9se, s9se_init_pic_order,
};
use crate::s9se_pic::{pack_enable_dc_dc, pack_reset, refuse_s9se_pic_io};
use crate::s9se_pll::{
    admit_s9se_chip_address, freq_climb_mhz, freq_high_pll_1393_row, freq_pll_1393_row,
    operational_pll_plan, pack_frequency_with_addr, pll_output_mhz, refuse_s9se_frequency_program,
    FREQ_PLL_1393, PLL_FALLBACK_DIVIDER, PLL_FALLBACK_WORD,
};
use crate::s9se_regs::{clock_delay_byte, pack_clock_delay_control};
use crate::s9se_regs::{
    core_reg_name, hash_clock_freq_mhz, pack_baud_one_chain, pack_baud_with_addr, pack_core_number,
    pack_core_reg_read_one, pack_core_reg_write_all, pack_misc_broadcast, pack_read_vil,
    pack_ticket_mask_broadcast, CORE_REG_HASH_CLOCK_COUNTER, MISC_CONTROL_DEFAULT,
    REG_CORE_RESPONSE, REG_MISC_CONTROL, REG_TICKET_MASK,
};
use crate::s9se_temp::{
    calc_offset_simple, local_temp_c, pack_read_temp_vil, refuse_s9se_temp_io, remote_temp_c,
    target_chip_temp_ce_economic, TEMP_DEVICE_DEFAULT,
};
use crate::s9se_timeout::{
    refuse_s9se_timeout_io, stock_timeout_s9se, timeout_control_word, DEFAULT_BAUDDIV,
    DEFAULT_TICKET_MASK, WORKING_BAUDDIV,
};
use crate::s9se_vil::{crc5_bits, refuse_fpga_offset_as_uart_opcode as vil_refuse_fpga_offset};
use crate::s9se_voltage::{
    power_iic_from_voltage, refuse_s9se_voltage_write, voltage_climb_kind, S9SeVoltageClimbKind,
    FACTORY_CONF_VOLTAGE_V, ISSUE2_EEPROM_VOLTAGE_V,
};
use crate::s9se_work::{
    admit_send_job_type_is_not_tw_length, refuse_12_word_send_job_as_ssot,
    refuse_s9se_work_dispatch, vil_tw_register_offsets, SEND_JOB_TYPE,
};
use crate::voltage_rail::{voltage_ownership_for_asic, VoltageOwnership};
use dcent_schema::hardware::InstallAuthorization;

/// Board-target string. Own row — must not alias `am1-s9` or `am1-s15`.
pub const S9SE_BOARD_TARGET: &str = "am1-s9se";

pub const S9SE_CHIP_ID: u16 = 0x1393;
pub const S9SE_CHAINS: u8 = 3;
pub use crate::s9se_enum::{S9SE_ADDR_INTERVAL, S9SE_CHIPS_PER_CHAIN, S9SE_LAST_CHIP_ADDR};
pub const S9SE_CORES_PER_CHIP: u16 = 208;
pub const S9SE_OPEN_CORE_BANK: u16 = 52;
pub const S9SE_OPEN_CORE_BANKS: u16 = 4;
pub const S9SE_SOC: &str = "XC7Z007S";
pub const S9SE_CONTROLLER: &str = "Ctrl_C43";
pub const S9SE_CONTROLLER_REV_REPORTED: &str = "V1.0";
pub const S9SE_DRAM_MIB: u16 = 256;

/// UART headers (S9k asic.c VIL). Same numbers as `dcentrald-asic::bm1393::uart`.
pub const HDR_SET_ADDR: u8 = 0x40;
pub const HDR_WRITE_SINGLE: u8 = 0x41;
pub const HDR_READ_SINGLE: u8 = 0x42;
pub const HDR_WRITE_ALL: u8 = 0x51;
pub const HDR_READ_ALL: u8 = 0x52;
pub const HDR_INACTIVE_ALL: u8 = 0x53;
pub const VIL_LEN_SHORT: u8 = 5;
pub const CRC5_POLY: u8 = 0x05;
pub const CRC5_INIT: u8 = 0x1F;
pub const CRC5_SHORT_BITS: u32 = 27;
pub const ISSUE2_BC_WORD0: u32 = 0x4205_781C;

pub const FPGA_BC_WRITE: u32 = 0x0C0;
pub const FPGA_BC_BUF0: u32 = 0x0C4;
pub const FPGA_TW0: u32 = 0x40;
pub const FPGA_DHASH: u32 = 0x100;
pub const VIL_TW_WORDS: usize = 13;
pub const DHASH_RAW_TW: u32 = 0x8100;
pub const EEPROM_MAJOR_1393: u8 = 0;

pub const CGMINER_OPKG_SOURCE_NEEDLE: &str = "cgminer_1393";
pub const CGMINER_SHA256: &str = "e113eab6d2480ec1596f23992ce013b855196821b276760441c2bc060d9bc9fb";
pub const UIMAGE_SHA256: &str = "85f7da5f8205a684acb057ce7268d2e395bc4f39e5ae4c088bbf4ede1fcb638f";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S9SeGauntletError {
    WrongBoardTarget { observed: String },
    AliasedToAm1S9,
    AliasedToAm1S15,
    ChipIdNot1393 { observed: u16 },
    TreatedAsBm1387,
    MiningDefaultOn,
    InstallNotDenied,
    ActiveTransport { observed: String },
    WorkEngineNotManagementOnly,
    LastChipAddrMismatch { observed: u8 },
    GeometryMismatch,
    Crc5Mismatch,
    FpgaOffsetIsNotUartOpcode,
    PwmTreatedAsActuator,
    TachZeroTreatedAsFanFailure,
    ChipRegistryMustStayUndriveable,
    VoltageWriteNotRefused,
    WorkDispatchNotRefused,
    PllFamilyMustStayNone,
    VoltageOwnerMustStayRuntimeDiscovered,
    FlashNotRefused,
    InitExecuteNotRefused,
    PicIoNotRefused,
    FpgaIoNotRefused,
    NandTableMismatch,
    JobDispatchNotRefused,
    TempIoNotRefused,
    BitstreamAbiMustStayUnknown,
    TimeoutIoNotRefused,
    NonceFifoNotRefused,
}

/// Bit-serial CRC5 matching stock `CRC5@1AE70` / `dcentrald-asic::bm1393`.
pub fn s9se_crc5_bits(data: &[u8], nbits: u32) -> u8 {
    crc5_bits(data, nbits)
}

pub fn admit_s9se_last_chip_addr(addr: u8) -> Result<(), S9SeGauntletError> {
    if addr != S9SE_LAST_CHIP_ADDR {
        return Err(S9SeGauntletError::LastChipAddrMismatch { observed: addr });
    }
    Ok(())
}

pub fn admit_s9se_issue2_crc5_capture() -> Result<(), S9SeGauntletError> {
    let frame = [
        (ISSUE2_BC_WORD0 >> 24) as u8,
        (ISSUE2_BC_WORD0 >> 16) as u8,
        (ISSUE2_BC_WORD0 >> 8) as u8,
        ISSUE2_BC_WORD0 as u8,
    ];
    if frame[0] != HDR_READ_SINGLE || frame[1] != VIL_LEN_SHORT {
        return Err(S9SeGauntletError::Crc5Mismatch);
    }
    // Preserve the historical short-frame CRC capture at address 0x78. It
    // does not identify the last populated ASIC in the production address plan.
    if frame[2] != crate::s9se_enum::S9SE_LAST_CHIP_ADDR_CAPTURED {
        return Err(S9SeGauntletError::Crc5Mismatch);
    }
    if s9se_crc5_bits(&frame[..3], CRC5_SHORT_BITS) != frame[3] {
        return Err(S9SeGauntletError::Crc5Mismatch);
    }
    Ok(())
}

pub fn refuse_fpga_offset_as_uart_opcode(byte: u8) -> Result<(), S9SeGauntletError> {
    vil_refuse_fpga_offset(byte).map_err(|_| S9SeGauntletError::FpgaOffsetIsNotUartOpcode)
}

pub fn admit_s9se_open_core_geometry() -> Result<(), S9SeGauntletError> {
    if S9SE_OPEN_CORE_BANK * S9SE_OPEN_CORE_BANKS != S9SE_CORES_PER_CHIP {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

pub fn admit_s9se_cooling_is_not_a_loop(
    commanded_pwm: u8,
    tach_low8: u8,
) -> Result<(), S9SeGauntletError> {
    if CTRL_C43_S9SE_COOLING.pwm_affects_airflow
        || CTRL_C43_S9SE_COOLING.treat_tach_zero_as_fan_failure
        || CTRL_C43_S9SE_COOLING.tach_available_for_supervisor
    {
        return Err(S9SeGauntletError::PwmTreatedAsActuator);
    }
    match admit_s9se_fan_sample(commanded_pwm, tach_low8) {
        S9SeFanAdmission::EvidenceUnavailable { .. } => {}
    }
    if decide_s9se_cooling_action(S9SeCoolingAction::RaisePwm)
        != S9SeCoolingDecision::RefusePwmNotAnActuator
    {
        return Err(S9SeGauntletError::PwmTreatedAsActuator);
    }
    if tach_low8 == 0 && CTRL_C43_S9SE_COOLING.treat_tach_zero_as_fan_failure {
        return Err(S9SeGauntletError::TachZeroTreatedAsFanFailure);
    }
    let _ = (FAN_CONTROL_OFFSET, FAN_SPEED_OFFSET);
    Ok(())
}

pub fn refuse_s9se_as_am1_s9(target: &str) -> Result<(), S9SeGauntletError> {
    if target == "am1-s9" {
        return Err(S9SeGauntletError::AliasedToAm1S9);
    }
    Ok(())
}

pub fn refuse_s9se_as_am1_s15(target: &str) -> Result<(), S9SeGauntletError> {
    if target == "am1-s15" {
        return Err(S9SeGauntletError::AliasedToAm1S15);
    }
    Ok(())
}

/// BoardDesc row must stay its own fail-closed C43 row. Mining/install stay
/// non-public and the generic protocol admit stays refused.
pub fn admit_s9se_board_desc_fail_closed(d: &BoardDesc) -> Result<(), S9SeGauntletError> {
    if d.board_target != S9SE_BOARD_TARGET {
        return Err(S9SeGauntletError::WrongBoardTarget {
            observed: d.board_target.to_string(),
        });
    }
    refuse_s9se_as_am1_s9(d.board_target)?;
    if d.asic_protocol == AsicProtocolIdentity::Bm1387 {
        return Err(S9SeGauntletError::TreatedAsBm1387);
    }
    if d.asic_protocol.to_chip_id() != Some(S9SE_CHIP_ID) {
        return Err(S9SeGauntletError::ChipIdNot1393 {
            observed: d.asic_protocol.to_chip_id().unwrap_or(0),
        });
    }
    if d.mining_default_enabled {
        return Err(S9SeGauntletError::MiningDefaultOn);
    }
    // C43-native refresh (2026-09): the row owns the exact stock-FPGA BM1393
    // composition (its independently pinned C43 fabric), so the old
    // transport-None / management-only park is stale. Fail-closed now means:
    // the exact C43 lane, install authorization still Denied (only the
    // removable-media facet is LabOnly), and the generic protocol admit must
    // still refuse the fabric.
    if d.public_beta_install()
        || d.enablement.install_authorization != InstallAuthorization::Denied
    {
        return Err(S9SeGauntletError::InstallNotDenied);
    }
    if d.chain_transport != ChainTransportKind::StockFpga {
        return Err(S9SeGauntletError::ActiveTransport {
            observed: format!("{:?}", d.chain_transport),
        });
    }
    if d.work_engine != WorkEngineKind::FpgaWorkFifo {
        return Err(S9SeGauntletError::WorkEngineNotManagementOnly);
    }
    if asic_protocol::admit_protocol_over_transport(d.asic_protocol, ChainTransportKind::StockFpga)
        .is_ok()
    {
        return Err(S9SeGauntletError::ActiveTransport {
            observed: "StockFpga admitted".into(),
        });
    }
    Ok(())
}

/// Production ChipRegistry must not drive 0x1393 (no am1-s9se executor yet).
pub fn refuse_s9se_chip_registry_drive(detects_1393: bool) -> Result<(), S9SeGauntletError> {
    if detects_1393 {
        return Err(S9SeGauntletError::ChipRegistryMustStayUndriveable);
    }
    Ok(())
}

/// : IIC map is pinned; write path stays refused.
pub fn admit_s9se_voltage_map_write_refused() -> Result<(), S9SeGauntletError> {
    let _ = power_iic_from_voltage(FACTORY_CONF_VOLTAGE_V)
        .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    let _ = power_iic_from_voltage(ISSUE2_EEPROM_VOLTAGE_V)
        .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_voltage_write().is_ok() {
        return Err(S9SeGauntletError::VoltageWriteNotRefused);
    }
    if voltage_ownership_for_asic(AsicProtocolIdentity::Bm1393)
        != VoltageOwnership::RuntimeDiscovered
    {
        return Err(S9SeGauntletError::VoltageOwnerMustStayRuntimeDiscovered);
    }
    Ok(())
}

/// : 13-word VIL TW planner; work TX refused.
pub fn admit_s9se_work_planner_dispatch_refused() -> Result<(), S9SeGauntletError> {
    refuse_12_word_send_job_as_ssot(VIL_TW_WORDS)
        .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_work_dispatch().is_ok() {
        return Err(S9SeGauntletError::WorkDispatchNotRefused);
    }
    let offs = vil_tw_register_offsets();
    if offs.len() != 13 || offs[0] != FPGA_TW0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

/// : PLL formula is known; production PLL family stays None.
pub fn admit_s9se_pll_formula_family_none() -> Result<(), S9SeGauntletError> {
    let mhz: f64 = 25.0 * 120.0 / (1.0 * 1.0 * 1.0);
    if (mhz - 3000.0).abs() > f64::EPSILON {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pll_family_for_protocol(AsicProtocolIdentity::Bm1393).is_some() {
        return Err(S9SeGauntletError::PllFamilyMustStayNone);
    }
    Ok(())
}

/// Production address plan: 60 populated addresses at stride four. Not a live enum.
pub fn admit_s9se_enum_program_desk_only() -> Result<(), S9SeGauntletError> {
    admit_s9se_geometry(
        S9SE_CHIPS_PER_CHAIN,
        S9SE_ADDR_INTERVAL,
        S9SE_LAST_CHIP_ADDR,
    )
    .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if admit_s9se_production_interval(4).is_err() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_am1_s9_chip_count(63).is_ok() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let plan = plan_s9se_address_program().map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if plan.set_address.len() != 60
        || plan.set_address[0][2] != 0
        || plan.set_address[59][2] != 0xec
    {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

/// : DTB 256 MiB + `cgminer.sh` DMA `0x0F000000`; FPGA I/O refused.
pub fn admit_s9se_fpga_and_dma_desk_only() -> Result<(), S9SeGauntletError> {
    admit_s9se_fpga_mem_is_256mib_path().map_err(|_| S9SeGauntletError::NandTableMismatch)?;
    if FPGA_MEM_OFFSET_256MIB != 0x0F00_0000 {
        return Err(S9SeGauntletError::NandTableMismatch);
    }
    let bc = pack_bc_write_command(0, 0).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if bc & BC_WRITE_TRIGGER == 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_fpga_io().is_ok() {
        return Err(S9SeGauntletError::FpgaIoNotRefused);
    }
    Ok(())
}

/// : DTB NAND table + FLASH refuse + classic S9 image refuse.
pub fn admit_s9se_nand_flash_refused() -> Result<(), S9SeGauntletError> {
    admit_nand_table().map_err(|_| S9SeGauntletError::NandTableMismatch)?;
    if refuse_s9se_flash().is_ok() {
        return Err(S9SeGauntletError::FlashNotRefused);
    }
    if refuse_classic_s9_image("am1-s9").is_ok() {
        return Err(S9SeGauntletError::AliasedToAm1S9);
    }
    Ok(())
}

/// : PIC frames pack; I/O refused.
pub fn admit_s9se_pic_frames_io_refused() -> Result<(), S9SeGauntletError> {
    if pack_reset().first() != Some(&0x55) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_enable_dc_dc(1).get(3) != Some(&0x15) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_pic_io().is_ok() {
        return Err(S9SeGauntletError::PicIoNotRefused);
    }
    if refuse_s9se_eeprom_write().is_ok() {
        return Err(S9SeGauntletError::VoltageWriteNotRefused);
    }
    admit_major_is_1393(0).map_err(|_| S9SeGauntletError::ChipIdNot1393 { observed: 0 })?;
    Ok(())
}

/// : PLL fallback 200 MHz + operational spine; program refused.
pub fn admit_s9se_pll_fallback_program_refused() -> Result<(), S9SeGauntletError> {
    let mhz = pll_output_mhz(PLL_FALLBACK_WORD, PLL_FALLBACK_DIVIDER)
        .ok_or(S9SeGauntletError::GeometryMismatch)?;
    if (mhz - 200.0).abs() > 0.01 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let _ = operational_pll_plan(PLL_FALLBACK_WORD, PLL_FALLBACK_DIVIDER)
        .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_frequency_program().is_ok() {
        return Err(S9SeGauntletError::PllFamilyMustStayNone);
    }
    if FREQ_PLL_1393.len() != 179 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let row200 = freq_pll_1393_row(14).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if row200.0 != 200 || row200.1 == PLL_FALLBACK_WORD {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

/// : chip regs + 208-core open-core plan; init execute refused.
pub fn admit_s9se_regs_and_init_desk_only() -> Result<(), S9SeGauntletError> {
    admit_expected_asic_count(60).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    let misc = pack_misc_broadcast(MISC_CONTROL_DEFAULT);
    if misc[3] != REG_MISC_CONTROL {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let tm = pack_ticket_mask_broadcast(0x3F);
    if tm[3] != REG_TICKET_MASK {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let core = pack_core_number(0x78);
    if core[7] != 0x78 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let rd = pack_read_vil(0x78, 0, false);
    if rd[0] != HDR_READ_SINGLE {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let oc = plan_s9se_open_core().map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if oc.core_enable_frames.len() != 208 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_init_execute().is_ok() {
        return Err(S9SeGauntletError::InitExecuteNotRefused);
    }
    Ok(())
}

/// : factory conf + `send_job` type `0x52` is not TW length.
pub fn admit_s9se_identity_and_send_job_type() -> Result<(), S9SeGauntletError> {
    admit_factory_conf().map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_factory_freq_token_as_mhz("O").is_ok() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if !admit_send_job_type_is_not_tw_length(SEND_JOB_TYPE) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

///  desk: stock `send_job` packet packs/decodes; dispatch refused.
pub fn admit_s9se_job_packet_dispatch_refused() -> Result<(), S9SeGauntletError> {
    let job = S9SeJobPacket {
        flags: FLAG_TICKET_UPDATE,
        asic_diff: DEFAULT_ASIC_DIFF,
        job_id: 1,
        version: 0x2000_0000,
        previous_hash: [0; 32],
        ntime: 1,
        nbits: 2,
        coinbase_len: 80,
        nonce2_offset: 0,
        nonce2_size: 4,
        merkle_count: 0,
        nonce2: 0,
        support_ab: false,
        version_num: 1,
    };
    let bytes =
        pack_s9se_job(&job, &[0u8; 80], &[]).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if bytes.first() != Some(&JOB_TYPE) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let back = decode_s9se_job(&bytes).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if back.asic_diff != DEFAULT_ASIC_DIFF {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_job_dispatch().is_ok() {
        return Err(S9SeGauntletError::JobDispatchNotRefused);
    }
    Ok(())
}

///  desk: `bring_up_chain` / `bitmain_soc_init` order; execute refused.
pub fn admit_s9se_stock_bringup_execute_refused() -> Result<(), S9SeGauntletError> {
    admit_stock_bringup_order().map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_init_execute().is_ok() {
        return Err(S9SeGauntletError::InitExecuteNotRefused);
    }
    Ok(())
}

///  desk: temp I²C-through-chip frame; I/O refused.
pub fn admit_s9se_temp_path_io_refused() -> Result<(), S9SeGauntletError> {
    let frame = pack_read_temp_vil(0x02, TEMP_DEVICE_DEFAULT, 0, 0, false);
    if frame[3] != 0x1C || frame[5] != TEMP_DEVICE_DEFAULT {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_temp_io().is_ok() {
        return Err(S9SeGauntletError::TempIoNotRefused);
    }
    Ok(())
}

/// Header-only identity cannot attest the loaded fabric. The actual donor
/// PL partition is now decoded by s9se_boot::fpga_configuration_partition.
pub fn admit_s9se_boot_identity_no_fabric_abi() -> Result<(), S9SeGauntletError> {
    let mut header = vec![0u8; BOOT_BIN_SIZE];
    header[0x20..0x24].copy_from_slice(&0xAA99_5566u32.to_le_bytes());
    header[0x24..0x28].copy_from_slice(b"XNLX");
    admit_boot_header(&header).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_boot_bitstream_abi(false).is_ok() {
        return Err(S9SeGauntletError::BitstreamAbiMustStayUnknown);
    }
    Ok(())
}

///  desk: timeout formula, working bauddiv 1, default ticket 0x3F.
pub fn admit_s9se_timeout_baud_ticket_desk_only() -> Result<(), S9SeGauntletError> {
    let t = stock_timeout_s9se(400).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if t != 327 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if timeout_control_word(t, 1) & 0x8000_0000 == 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if WORKING_BAUDDIV != 1 || DEFAULT_TICKET_MASK != 0x3F {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_timeout_io().is_ok() {
        return Err(S9SeGauntletError::TimeoutIoNotRefused);
    }
    Ok(())
}

///  desk: nonce HIBYTE/interval classify; FIFO I/O refused.
pub fn admit_s9se_nonce_classify_fifo_refused() -> Result<(), S9SeGauntletError> {
    let buf = (u32::from(10 * S9SE_ADDR_INTERVAL) << 24) | 7;
    let place = classify_s9se_nonce(0, buf, S9SE_ADDR_INTERVAL)
        .map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if place.chip != 10 || place.core != 7 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_nonce_fifo_io().is_ok() {
        return Err(S9SeGauntletError::NonceFifoNotRefused);
    }
    Ok(())
}

///  desk: clock-delay CORE_CMD + PIC 0x17/0x31 packers.
pub fn admit_s9se_clock_delay_and_extra_pic() -> Result<(), S9SeGauntletError> {
    if clock_delay_byte(false) != 4 || clock_delay_byte(true) != 6 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_clock_delay_control(false)[7] != 4 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_get_software_version().get(3) != Some(&0x17) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_crab_circuit(1).get(3) != Some(&0x31) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

///  desk: stock PWM word exists; it is still not an actuator.
pub fn admit_s9se_pwm_encode_not_actuator() -> Result<(), S9SeGauntletError> {
    if pack_fan_control_word(100) != 0x0032_0000 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if hash_cut_dhash_word(0xFFFF_FFFF) & 0x40 != 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if decide_s9se_cooling_action(S9SeCoolingAction::RaisePwm)
        != S9SeCoolingDecision::RefusePwmNotAnActuator
    {
        return Err(S9SeGauntletError::PwmTreatedAsActuator);
    }
    Ok(())
}

///  desk: FPGA IIC / reset / HW version / QN / plug. I/O refused.
pub fn admit_s9se_fpga_iic_reset_plug_desk_only() -> Result<(), S9SeGauntletError> {
    let iic = pack_zynq_iic(0x20, 0, true, false, 0, 0);
    if iic & 0x0200_0000 == 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if apply_hashboard_reset(0, 2, true).map_err(|_| S9SeGauntletError::GeometryMismatch)? != 4 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if !admit_hardware_version_low16(u32::from(HARDWARE_VERSION_VALUE)) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if QN_WRITE_DATA_INIT != 0x8080_800F || AXI_MMAP_BYTES != 352 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    admit_three_populated_chains(0b0111).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_fpga_io().is_ok() {
        return Err(S9SeGauntletError::FpgaIoNotRefused);
    }
    Ok(())
}

///  desk: PIC AN 0x29 + EEPROM CRC-16 + byte-248 minor.
pub fn admit_s9se_pic_an_and_eeprom_crc() -> Result<(), S9SeGauntletError> {
    if pack_get_an_voltage2().get(3) != Some(&0x29) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if decode_an_voltage_v10(0) != 0.0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let payload = [0u8; EEPROM_CRC_LEN];
    if !admit_eeprom_crc(&payload, eeprom_payload_crc16(&payload)) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if chip_minor_from_byte(0b00_101_000) != 5 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

///  desk: FIFO record + nonce classify stay I/O-refused.
pub fn admit_s9se_fifo_record_desk_only() -> Result<(), S9SeGauntletError> {
    match classify_return_record(0x8000_0082, 7) {
        Some(S9SeFifoRecord::Nonce { chain, nonce3, .. }) if chain == 2 && nonce3 == 7 => {}
        _ => return Err(S9SeGauntletError::GeometryMismatch),
    }
    if refuse_s9se_nonce_fifo_io().is_ok() {
        return Err(S9SeGauntletError::NonceFifoNotRefused);
    }
    Ok(())
}

///  desk: voltage/freq climb planners; writes still refused.
pub fn admit_s9se_climbs_and_identity_desk_only() -> Result<(), S9SeGauntletError> {
    if voltage_climb_kind(9.0, 9.6) != S9SeVoltageClimbKind::ImmediateRaise {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_voltage_write().is_ok() {
        return Err(S9SeGauntletError::VoltageWriteNotRefused);
    }
    let climb = freq_climb_mhz(100, 200, 50).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if climb != [150, 200] {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_frequency_program().is_ok() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if local_temp_c(80) != 16 || ANT_VERSION != "3172" || GPIO_LCD_CS != 954 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if DEFAULT_BAUDDIV != 26 || WORKING_BAUDDIV != 1 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if coinbase_nonce2_word(128, 32, 4) != (4u32 << 8) | (32u32 << 16) | 2 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

///  desk: S9 SE-native PIC crab/PDCx, IIC addr, init-pic, CE temp.
pub fn admit_s9se_pic_iic_and_ce_temp_desk_only() -> Result<(), S9SeGauntletError> {
    if pack_get_crab_voltage().get(3) != Some(&0x28) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_get_pdcx().get(3) != Some(&0x2B) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pic_iic_dev_addr(0) != 0x20 || pic_iic_dev_addr(2) != 0x22 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    refuse_t11a_chain_swap_on_s9se(false).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if refuse_s9se_pic_flash().is_ok() {
        return Err(S9SeGauntletError::PicIoNotRefused);
    }
    if s9se_init_pic_order() != [0x07, 0x06, 0x15] {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if calc_offset_simple(64, 80) != 16 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if target_chip_temp_ce_economic(16) != 75 || HASH_COUNTING_OPEN_CORE != 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

///  desk leftover: CORE_REG map, all-reset, crab/PDC values, remote temp.
pub fn admit_s9se_core_reg_and_all_reset_desk_only() -> Result<(), S9SeGauntletError> {
    if core_reg_name(0) != Some("Clock Delay Ctrl") || REG_CORE_RESPONSE != 0x40 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let read = pack_core_reg_read_one(0x02, 7, CORE_REG_HASH_CLOCK_COUNTER);
    if read[6] != CORE_REG_HASH_CLOCK_COUNTER || read[7] != 0xFF {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let write = pack_core_reg_write_all(0x02, 5, 1);
    if write[6] != 0x85 || write[4] != 0x80 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if (hash_clock_freq_mhz(8) - 100.0).abs() > 1e-9 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if apply_all_hashboard_reset(0, true) != 0xFFFF {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if crab_na_values(&[13, 0x28, 1, 0, 1, 0, 2, 0, 3, 0, 4]) != Some([1, 2, 3, 4]) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pdcx_values(&[9, 0x2B, 1, 0, 9, 0, 8, 0, 7]) != Some([9, 8, 7]) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if remote_temp_c(64) != 0 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let baud = pack_baud_with_addr(0x02, 1).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if baud[..8] != [0x41, 0x09, 0x02, 0x18, 0x40, 0x21, 0x01, 0x00] {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if BT8D_CONTROL.axi_word != 15 || BT8D_CONTROL.byte_offset != 0x3C {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_fpga_io().is_ok() {
        return Err(S9SeGauntletError::FpgaIoNotRefused);
    }
    Ok(())
}

///  desk leftover: high-PLL table, PLL0-only freq-with-addr, AXI job
/// slots, send_job DHASH/version words. I/O still refused.
pub fn admit_s9se_wave9_desk_leftover() -> Result<(), S9SeGauntletError> {
    if freq_high_pll_1393_row(4).map_err(|_| S9SeGauntletError::GeometryMismatch)?
        != (200, 15, 3000)
    {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let freq = pack_frequency_with_addr(false, 0x02, 0x0040_0241);
    if freq[3] != 0x08 || freq[0] != 0x41 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    admit_s9se_chip_address(1, 4).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if admit_s9se_chip_address(1, 2).is_ok() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if JOB_LENGTH.axi_word != 71 || PRE_HEADER_HASH0.axi_word != 80 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if decode_fan_speed_word(0x0318) != (3, 0x18) {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if merkle_bin_number_word(2) != 2 || fpga_ticket_mask_word(15) != 15 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if block_header_version_1_word(0x2000_0000) != 0x2000_4000 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if job_length_bytes(128, 1) != 160 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if dhash_start_no_ab_word(0) != DHASH_NO_AB_OR {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if dhash_soc_init_word(0) != 0x8100 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_pre_header_hash_words(&[0x11; 32])[7] != 0x1111_1111 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if pack_baud_with_addr(0x02, 1).map_err(|_| S9SeGauntletError::GeometryMismatch)?[..8]
        != [0x41, 0x09, 0x02, 0x18, 0x40, 0x21, 0x01, 0x00]
    {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_frequency_program().is_ok() {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_fpga_io().is_ok() {
        return Err(S9SeGauntletError::FpgaIoNotRefused);
    }
    Ok(())
}

///  desk leftover: nonce2/jobid store axi[68] + PHY, version_2/3
/// slots, chain-wide MISC baud vs per-chip 40 21. I/O still refused.
pub fn admit_s9se_wave10_desk_leftover() -> Result<(), S9SeGauntletError> {
    if NONCE2_AND_JOBID_STORE.axi_word != 68 || NONCE2_AND_JOBID_STORE.byte_offset != 0x110 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if nonce2_jobid_store_phy() != FPGA_MEM_OFFSET_256MIB {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if BLOCK_HEADER_VERSION_2.axi_word != 90 || BLOCK_HEADER_VERSION_3.byte_offset != 0x16C {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    let chain = pack_baud_one_chain(1).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    let per_chip = pack_baud_with_addr(0x02, 1).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if chain[0] != 0x51 || chain[3] != 0x18 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if per_chip[..8] != [0x41, 0x09, 0x02, 0x18, 0x40, 0x21, 0x01, 0x00] {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if chain[4..8] == per_chip[4..8] {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    if refuse_s9se_fpga_io().is_ok() {
        return Err(S9SeGauntletError::FpgaIoNotRefused);
    }
    Ok(())
}

///  desk: held uImage magic/name. Not a flash admit.
pub fn admit_s9se_uimage_identity() -> Result<(), S9SeGauntletError> {
    let mut hdr = vec![0u8; 64];
    hdr[0..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    hdr[16..20].copy_from_slice(&0x0000_8000u32.to_be_bytes());
    admit_uimage_header(&hdr).map_err(|_| S9SeGauntletError::GeometryMismatch)?;
    if UIMAGE_SIZE != 4_006_832 {
        return Err(S9SeGauntletError::GeometryMismatch);
    }
    Ok(())
}

/// Re-export so gauntlet tests can name the board without a circular board_desc
/// module split. `BoardDesc::am1_s9se` is the single constructor.
pub fn s9se_board() -> BoardDesc {
    BoardDesc::am1_s9se()
}

/// Keep a compile-visible use of the asic-side CRC helper module docs.
pub fn cgminer_evidence_needles() -> [&'static str; 3] {
    [CGMINER_OPKG_SOURCE_NEEDLE, CGMINER_SHA256, UIMAGE_SHA256]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_desc::BoardDesc;
    use crate::s9se_cooling::supervisor_tach_available_for_target;
    use crate::s9se_vil::{
        admit_issue2_captured_short_frame, pack_chain_inactive_vil, pack_read_single_nonvil,
    };

    #[test]
    fn wave0_issue2_crc5_and_geometry() {
        admit_s9se_issue2_crc5_capture().unwrap();
        admit_s9se_last_chip_addr(0xec).unwrap();
        assert!(admit_s9se_last_chip_addr(0x7A).is_err());
        admit_s9se_open_core_geometry().unwrap();
        assert_eq!(S9SE_CORES_PER_CHIP, 208);
        assert_eq!(s9se_crc5_bits(&[0x42, 0x05, 0x78], 24), 0x11);
    }

    #[test]
    fn wave0_fpga_offsets_are_not_uart_opcodes() {
        assert!(refuse_fpga_offset_as_uart_opcode(0xC0).is_err());
        assert!(refuse_fpga_offset_as_uart_opcode(0xC4).is_err());
        assert!(refuse_fpga_offset_as_uart_opcode(0x30).is_err());
        refuse_fpga_offset_as_uart_opcode(HDR_READ_SINGLE).unwrap();
        refuse_fpga_offset_as_uart_opcode(HDR_SET_ADDR).unwrap();
        assert_eq!(FPGA_BC_WRITE, 48 * 4);
        assert_eq!(FPGA_BC_BUF0, 49 * 4);
        assert_eq!(FPGA_TW0, 16 * 4);
        assert_eq!(FPGA_DHASH, 64 * 4);
        assert_eq!(VIL_TW_WORDS, 13);
        assert_eq!(DHASH_RAW_TW, 0x8100);
        assert_eq!(EEPROM_MAJOR_1393, 0);
    }

    #[test]
    fn wave0_cooling_pwm_is_not_an_actuator() {
        admit_s9se_cooling_is_not_a_loop(30, 0).unwrap();
        assert_eq!(FAN_CONTROL_OFFSET, 0x084);
        assert_eq!(FAN_SPEED_OFFSET, 0x004);
    }

    #[test]
    fn wave1_board_desc_is_own_fail_closed_row() {
        let d = s9se_board();
        admit_s9se_board_desc_fail_closed(&d).unwrap();
        assert_eq!(d.board_target, S9SE_BOARD_TARGET);
        assert_ne!(d.board_target, BoardDesc::am1_s9().board_target);
        assert_ne!(d.board_target, BoardDesc::am1_s15().board_target);
        assert!(BoardDesc::lookup("am1-s9se").is_some());
        refuse_s9se_as_am1_s9("am1-s9").unwrap_err();
        refuse_s9se_as_am1_s15("am1-s15").unwrap_err();
    }

    #[test]
    fn wave1_protocol_identity_is_1393_not_1387() {
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1393),
            Some(AsicProtocolIdentity::Bm1393)
        );
        assert_eq!(AsicProtocolIdentity::Bm1393.to_chip_id(), Some(0x1393));
        assert_eq!(
            AsicProtocolIdentity::from_chip_label("BM1393"),
            Some(AsicProtocolIdentity::Bm1393)
        );
        let d = s9se_board();
        assert_eq!(d.asic_protocol, AsicProtocolIdentity::Bm1393);
        assert_ne!(d.asic_protocol, AsicProtocolIdentity::Bm1387);
        assert_ne!(d.asic_protocol, AsicProtocolIdentity::Bm1391);
    }

    #[test]
    fn wave1_chip_registry_stays_undriveable() {
        refuse_s9se_chip_registry_drive(false).unwrap();
        assert!(refuse_s9se_chip_registry_drive(true).is_err());
    }

    #[test]
    fn evidence_needles_are_pinned() {
        let n = cgminer_evidence_needles();
        assert!(n[0].contains("1393"));
        assert_eq!(n[1].len(), 64);
        assert_eq!(n[2].len(), 64);
    }

    #[test]
    fn wave2_vil_frames_match_issue2_and_stock() {
        admit_issue2_captured_short_frame().unwrap();
        assert_eq!(pack_read_single_nonvil(0x78), [0x42, 0x05, 0x78, 0x1C]);
        assert_eq!(pack_chain_inactive_vil()[0], 0x53);
        assert_eq!(s9se_crc5_bits(&[0x42, 0x05, 0x78], CRC5_SHORT_BITS), 0x1C);
    }

    #[test]
    fn wave2_voltage_map_is_pinned_write_refused() {
        admit_s9se_voltage_map_write_refused().unwrap();
    }

    #[test]
    fn wave2_work_planner_is_13_words_dispatch_refused() {
        admit_s9se_work_planner_dispatch_refused().unwrap();
        let caps = asic_protocol::protocol_capabilities(AsicProtocolIdentity::Bm1393);
        assert!(caps.get_address_enumerate);
        assert!(caps.assign_chip_addresses);
        assert!(!caps.work_submit);
        assert!(!caps.frequency_program);
        assert!(!caps.version_rolling_work);
    }

    #[test]
    fn wave2_pll_formula_family_stays_none() {
        admit_s9se_pll_formula_family_none().unwrap();
    }

    #[test]
    fn wave2_enum_program_is_60_stride_four_from_both_production_models() {
        admit_s9se_enum_program_desk_only().unwrap();
    }

    #[test]
    fn wave2_supervisor_has_no_tach_on_am1_s9se() {
        assert_eq!(
            supervisor_tach_available_for_target(S9SE_BOARD_TARGET),
            Some(false)
        );
    }

    #[test]
    fn wave3_fpga_dma_is_256mib_io_refused() {
        admit_s9se_fpga_and_dma_desk_only().unwrap();
    }

    #[test]
    fn wave3_nand_flash_stays_refused() {
        admit_s9se_nand_flash_refused().unwrap();
    }

    #[test]
    fn wave3_pic_and_eeprom_io_refused() {
        admit_s9se_pic_frames_io_refused().unwrap();
    }

    #[test]
    fn wave3_pll_fallback_is_200mhz_program_refused() {
        admit_s9se_pll_fallback_program_refused().unwrap();
    }

    #[test]
    fn wave3_regs_open_core_init_execute_refused() {
        admit_s9se_regs_and_init_desk_only().unwrap();
    }

    #[test]
    fn wave3_identity_and_send_job_type() {
        admit_s9se_identity_and_send_job_type().unwrap();
    }

    #[test]
    fn wave4_job_packet_dispatch_refused() {
        admit_s9se_job_packet_dispatch_refused().unwrap();
    }

    #[test]
    fn wave4_stock_bringup_execute_refused() {
        admit_s9se_stock_bringup_execute_refused().unwrap();
    }

    #[test]
    fn wave4_temp_path_io_refused() {
        admit_s9se_temp_path_io_refused().unwrap();
    }

    #[test]
    fn wave4_boot_identity_no_fabric_abi() {
        admit_s9se_boot_identity_no_fabric_abi().unwrap();
    }

    #[test]
    fn wave5_timeout_baud_ticket_io_refused() {
        admit_s9se_timeout_baud_ticket_desk_only().unwrap();
    }

    #[test]
    fn wave5_nonce_classify_fifo_refused() {
        admit_s9se_nonce_classify_fifo_refused().unwrap();
    }

    #[test]
    fn wave5_clock_delay_and_extra_pic() {
        admit_s9se_clock_delay_and_extra_pic().unwrap();
    }

    #[test]
    fn wave5_uimage_identity() {
        admit_s9se_uimage_identity().unwrap();
    }

    #[test]
    fn wave6_pwm_encode_not_actuator() {
        admit_s9se_pwm_encode_not_actuator().unwrap();
    }

    #[test]
    fn wave6_fpga_iic_reset_plug() {
        admit_s9se_fpga_iic_reset_plug_desk_only().unwrap();
    }

    #[test]
    fn wave6_pic_an_and_eeprom_crc() {
        admit_s9se_pic_an_and_eeprom_crc().unwrap();
    }

    #[test]
    fn wave6_fifo_record_io_refused() {
        admit_s9se_fifo_record_desk_only().unwrap();
    }

    #[test]
    fn wave6_climbs_and_identity() {
        admit_s9se_climbs_and_identity_desk_only().unwrap();
    }

    #[test]
    fn wave7_pic_iic_and_ce_temp() {
        admit_s9se_pic_iic_and_ce_temp_desk_only().unwrap();
    }

    #[test]
    fn wave8_core_reg_and_all_reset() {
        admit_s9se_core_reg_and_all_reset_desk_only().unwrap();
    }

    #[test]
    fn wave9_high_pll_job_axi_leftover() {
        admit_s9se_wave9_desk_leftover().unwrap();
    }

    #[test]
    fn wave10_nonce2_store_and_chain_baud() {
        admit_s9se_wave10_desk_leftover().unwrap();
    }
}
