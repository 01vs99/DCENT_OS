//! S19k BM1366 native wire parameters and read-only UART ownership probe.
//!
//! Native execution uses the kernel device/driver join under the fabric lease,
//! fresh response coverage after every baud transition, and the retained
//! cooling, watchdog and power owners. Historical Bench GO and desk-pending
//! policy is archived under `office-bench/s19k/`; it is not compiled.
//!
//! This module constructs command plans only; it never opens a UART or enables
//! power. The native executor retains the response barriers and terminal cut.

use crate::chain_transport::{
    bitmain_jig_addr_interval, bm1397plus_addr_interval, linear_chip_addresses,
};
use crate::stock_fpga_policy::stock_bitmain_crc5;

/// Native AML uses the kernel's Meson UART owner. This read-only probe binds
/// each configured endpoint to its actual platform device and driver; a
/// `/dev/uart_trans` name or a loaded module is not transport identity.
///
/// The caller must already hold the fabric lease, and must retain the existing
/// exclusive UART executor for I/O. This observation grants no power or work
/// capability. A ttyS2 endpoint still needs fresh complete RX evidence after
/// every initialization/baud transition; an owner match cannot prove live RX.
pub fn probe_native_amlogic_uart_owner(serial_devices: &str) -> Result<(), String> {
    probe_native_amlogic_uart_owner_at(std::path::Path::new("/sys"), serial_devices)
}

fn probe_native_amlogic_uart_owner_at(
    sysfs: &std::path::Path,
    serial_devices: &str,
) -> Result<(), String> {
    use std::{collections::BTreeSet, fs};
    let platform_devices = fs::canonicalize(sysfs.join("devices"))
        .map_err(|error| format!("native AML UART sysfs devices unavailable: {error}"))?;
    let expected_driver = fs::canonicalize(sysfs.join("bus/platform/drivers/meson_uart"))
        .map_err(|error| format!("native AML UART kernel meson_uart owner unavailable: {error}"))?;
    let mut seen = BTreeSet::new();
    for path in serial_devices.split(',') {
        // These are the source-pinned native Meson endpoint/register pairs,
        // not logical hashboard mappings. Physical population admission owns
        // the separate tty-to-EEPROM/plug/reset join.
        let (tty, controller) = match path {
            "/dev/ttyS1" => ("ttyS1", "ffd24000.serial"),
            "/dev/ttyS2" => ("ttyS2", "ffd23000.serial"),
            "/dev/ttyS3" => ("ttyS3", "ff804000.serial"),
            _ => {
                return Err(format!(
                    "native AML UART refuses non-native endpoint {path:?}"
                ))
            }
        };
        if !seen.insert(tty) {
            return Err(format!("native AML UART duplicate endpoint {path}"));
        }
        let device =
            fs::canonicalize(sysfs.join(format!("class/tty/{tty}/device"))).map_err(|error| {
                format!("native AML UART {path} has no kernel device owner: {error}")
            })?;
        if !device.starts_with(&platform_devices)
            || device.file_name().and_then(|name| name.to_str()) != Some(controller)
        {
            return Err(format!(
                "native AML UART {path} controller differs from {controller}: {}",
                device.display()
            ));
        }
        let driver = fs::canonicalize(device.join("driver"))
            .map_err(|error| format!("native AML UART {path} driver is unavailable: {error}"))?;
        if driver != expected_driver {
            return Err(format!(
                "native AML UART {path} is owned by {}, expected meson_uart",
                driver.display()
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod native_uart_owner_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct SysfsFixture(PathBuf);
    impl SysfsFixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "dcent-native-uart-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            for driver in ["meson_uart", "uart_trans", "of_serial"] {
                fs::create_dir_all(root.join(format!("bus/platform/drivers/{driver}"))).unwrap();
            }
            for (tty, controller) in [
                ("ttyS1", "ffd24000.serial"),
                ("ttyS2", "ffd23000.serial"),
                ("ttyS3", "ff804000.serial"),
            ] {
                let device = root.join(format!("devices/platform/{controller}"));
                let class = root.join(format!("class/tty/{tty}"));
                fs::create_dir_all(&device).unwrap();
                fs::create_dir_all(&class).unwrap();
                symlink(&device, class.join("device")).unwrap();
                symlink(
                    root.join("bus/platform/drivers/meson_uart"),
                    device.join("driver"),
                )
                .unwrap();
            }
            Self(root)
        }
    }
    impl Drop for SysfsFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn exact_live_kernel_bindings_admit_without_module_or_process_names() {
        let fixture = SysfsFixture::new();
        // An unrelated loaded uart_trans module cannot reclassify AML as CV.
        fs::create_dir_all(fixture.0.join("module/uart_trans")).unwrap();
        for paths in [
            "/dev/ttyS2",
            "/dev/ttyS1,/dev/ttyS2",
            "/dev/ttyS3,/dev/ttyS2,/dev/ttyS1",
        ] {
            probe_native_amlogic_uart_owner_at(&fixture.0, paths).unwrap();
        }
    }

    #[test]
    fn wrong_missing_and_rebound_kernel_owners_refuse() {
        let fixture = SysfsFixture::new();
        for path in [
            "",
            "/dev/uart_trans",
            "/dev/ttyS0",
            "/dev/ttyS4",
            "/dev/ttyS2,/dev/ttyS2",
            " /dev/ttyS2",
            "/dev/ttyS2,",
        ] {
            assert!(
                probe_native_amlogic_uart_owner_at(&fixture.0, path).is_err(),
                "{path:?}"
            );
        }
        let driver = fixture.0.join("devices/platform/ffd23000.serial/driver");
        fs::remove_file(&driver).unwrap();
        assert!(probe_native_amlogic_uart_owner_at(&fixture.0, "/dev/ttyS2").is_err());
        for wrong in ["uart_trans", "of_serial"] {
            symlink(
                fixture.0.join(format!("bus/platform/drivers/{wrong}")),
                &driver,
            )
            .unwrap();
            assert!(probe_native_amlogic_uart_owner_at(&fixture.0, "/dev/ttyS2").is_err());
            fs::remove_file(&driver).unwrap();
        }
        symlink(fixture.0.join("bus/platform/drivers/meson_uart"), &driver).unwrap();
        let class = fixture.0.join("class/tty/ttyS2/device");
        fs::remove_file(&class).unwrap();
        symlink(fixture.0.join("devices/platform/ffd24000.serial"), &class).unwrap();
        assert!(probe_native_amlogic_uart_owner_at(&fixture.0, "/dev/ttyS2").is_err());
    }
}

/// HashSource / Lead geometry for S19k BM1366 (same as checklist A).
pub const S19K_WIRE_ASIC_NUM: u8 = 77;
/// Jig `Config.ini` `Voltage_Domain` for BHB56902. Not a UART register.
pub const S19K_JIG_VOLTAGE_DOMAIN: u8 = 11;
/// Jig `Asic_Num_Per_Voltage_Domain`. 11×7 = 77.
pub const S19K_JIG_ASICS_PER_DOMAIN: u8 = 7;
pub const S19K_WIRE_CHIP_ID: u16 = 0x1366;
pub const S19K_WIRE_MIDSTATE_NUMBER: u8 = 8;
pub const S19K_WIRE_RESPONSE_BYTES: usize = 11;
pub const S19K_WIRE_HASH_COUNTING: u32 = 0x0000_115A;
pub const S19K_WIRE_JOB_ID_STEP: u8 = 8;
pub const S19K_WIRE_JOB_ID_MOD: u8 = 128;

// --- B1 CMD opcodes / templates (jig FPGA CMD builders; CRC5 via stock_bitmain_crc5) ---
/// UART GetAddress header (`55 AA 52 05 …`). Was misnamed `CMD_CHAIN_INACTIVE`.
pub const CMD_GET_ADDRESS: u8 = 0x52;
/// Real UART chain-inactive (`55 AA 53 05 00 00 03`). ESP `_send_chain_inactive`.
pub const CMD_CHAIN_INACTIVE: u8 = 0x53;
pub const CMD_SET_ADDRESS: u8 = 0x40;
pub const CMD_SET_CONFIG_BCAST: u8 = 0x51;
pub const CMD_SET_CONFIG_UNICAST: u8 = 0x41;

/// Public floor SSOT for 77 chips: floor(256/77) = 3.
/// **Refused** as S19k AML / BHB5690x SoT — see `refuse_s19k_public_floor_as_aml_interval`
/// (`BM1366_WIRE_BRINGUP.md` § Desk 2026-08-11g).
pub const S19K_PUBLIC_ADDR_INTERVAL: u8 = 3;
/// AML Track 1 / BHB5690x preferred `asic_addr_interval` (bmminer_4cc0 conf+0x34).
/// Desk 11g CLOSED: use **2**, not public floor=3. Slot count hint: 256/2 = 128.
pub const S19K_AML_ADDR_INTERVAL: u8 = 2;
/// Jig bucket for 65–128 chips = 2 (same dialect as AML preferred; desk 11b/11g).
pub const S19K_JIG_ADDR_INTERVAL: u8 = S19K_AML_ADDR_INTERVAL;
/// AML set-addr slot count when step=2: `256 / addr_interval` (4cc0 `__aeabi_uidiv`).
pub const S19K_AML_ADDR_SLOT_COUNT: u16 = 128;

// Open-core / stage_2 core-regs (EVIDENCED)
pub const CORE_REG_HASH_CLOCK: u32 = 0x8000_8540;
pub const CORE_REG_CLOCK_DELAY: u32 = 0x8000_8020; // Pwth_Sel=4, CCdly=0, Swpf=0
pub const CORE_REG_ASICBOOST: u32 = 0x8000_82AA;
pub const REG_ANALOG_MUX: u8 = 0x54;
pub const REG_CORE: u8 = 0x3C;
pub const ANALOG_MUX_DIODE_VDD_SEL: u32 = 0x0000_0003;

// --- B2 PLL ---
pub const REG_PLL0: u8 = 0x08;
pub const REG_PLL1: u8 = 0x60;
pub const PLL_RAMP_START_MHZ: u32 = 50;
pub const PUBLIC_FASTUART_REG: u8 = 0x28;
pub const PUBLIC_FASTUART_VALUE: u32 = 0x1130_0200; // 1 Mbps class
pub const JIG_CONFIG_BAUD_HZ: u32 = 12_000_000;

/// Minimum dwell after EACH native SetAddress, including the final address.
/// The held BM1366 jig chain-init sequence also uses 10 ms per ladder entry.
/// Grouping 16 writes behind a 2 ms pause does not meet this wire requirement.
pub const S19K_ADDRESS_DWELL_MS: u64 = 10;

/// BHB56902/03 maximum in held Bitmain s19k-pro-merge-20240409
/// `01_Antminer_S19k_Pro_zynq7007_BHB56XXX/components/minerfs.image.gz.tree/etc/levels.json`.
/// BHB56901's 695 MHz row is a different board/PSU combination.
pub const S19K_NATIVE_MAX_FREQUENCY_MHZ: u16 = 670;

/// Resolve with the shared BM1366 solver, then check the actual divider ratio
/// against the envelope (rounded integer MHz can hide an overshoot). If the
/// nearest result crosses the ceiling, try lower requests within the native
/// executor's existing 2 MHz error allowance. No register formula is forked.
pub fn bm1366_pll_in_envelope(
    target_mhz: u16,
    minimum_mhz: u16,
    maximum_mhz: u16,
) -> Result<(u32, u16), &'static str> {
    if minimum_mhz == 0 || !(minimum_mhz..=maximum_mhz).contains(&target_mhz) {
        return Err("BM1366 PLL request lies outside the frequency envelope");
    }
    let lowest_request = target_mhz.saturating_sub(2).max(minimum_mhz);
    for request in (lowest_request..=target_mhz).rev() {
        let (register, actual) = crate::bm1366_pll_reg_and_actual(request);
        let div = crate::pll_model::crystal25_pll_decode_dividers(register);
        let numerator = 25 * u64::from(div.fb_div);
        let denominator =
            u64::from(div.ref_div) * u64::from(div.post_div1) * u64::from(div.post_div2);
        if denominator != 0
            && numerator >= u64::from(minimum_mhz) * denominator
            && numerator <= u64::from(maximum_mhz) * denominator
            && numerator.abs_diff(u64::from(target_mhz) * denominator) <= 2 * denominator
        {
            return Ok((register, actual));
        }
    }
    Err("BM1366 PLL has no solution within the envelope and 2 MHz error allowance")
}

/// Native command plan for the existing BHB56902/03 owner. Underclocking is
/// allowed from 100 MHz (native driver policy); 50 MHz is only a ramp start.
/// This is not a voltage or cooling grant. The executor must still acquire
/// fresh post-baud coverage before touching the post-baud or final sections.
pub fn s19k_bm1366_native_execution_program(
    expected_chip_count: u8,
    target_frequency_mhz: u16,
) -> Result<crate::s19k_bm1366_init_seq::S19kBm1366NativeExecutionProgram, &'static str> {
    use crate::s19k_bm1366_init_seq::S19kBm1366NativeCommandOp;
    if !(100..=S19K_NATIVE_MAX_FREQUENCY_MHZ).contains(&target_frequency_mhz) {
        return Err("native BHB56902/03 PLL target must be within 100..=670 MHz");
    }
    let (pll_register, actual_frequency_mhz) =
        bm1366_pll_in_envelope(target_frequency_mhz, 100, S19K_NATIVE_MAX_FREQUENCY_MHZ)?;
    let mut program = crate::s19k_bm1366_init_seq::s19k_bm1366_native_execution_program(
        expected_chip_count,
        target_frequency_mhz,
    )?;
    let pll_command = program.final_commands.iter_mut().find(|command| {
        matches!(command.op, S19kBm1366NativeCommandOp::WriteRegister(write) if write.reg == REG_PLL0)
    }).ok_or("native S19k plan lost its final PLL0 command")?;
    if let S19kBm1366NativeCommandOp::WriteRegister(write) = &mut pll_command.op {
        write.value = pll_register;
    }
    program.actual_frequency_mhz = actual_frequency_mhz;
    for command in &mut program.pre_baud_commands {
        if matches!(command.op, S19kBm1366NativeCommandOp::SetAddress { .. }) {
            command.dwell_after_ms = command.dwell_after_ms.max(S19K_ADDRESS_DWELL_MS);
        }
    }
    Ok(program)
}

/// Physical mtd5 geometry; preceding partition sizes omit a 6 MiB gap.
/// `/proc/mtd` supplies lengths, so summing it incorrectly gives 0x06100000.
pub const S19K_MTD5_BASE: u32 = 0x0670_0000;
pub const S19K_MTD5_SIZE: u32 = 0x0990_0000;

/// Translate a nonempty physical span using observed partition geometry.
/// This is address arithmetic only. Persistent writes additionally require
/// the installer's full backup/readback, signature and write/readback checks.
pub fn s19k_mtd5_local_span(
    observed_base: u32,
    observed_size: u32,
    physical_offset: u32,
    length: u32,
) -> Result<std::ops::Range<u32>, &'static str> {
    if observed_base != S19K_MTD5_BASE || observed_size != S19K_MTD5_SIZE {
        return Err("S19k mtd5 requires physical base 0x06700000 and size 0x09900000");
    }
    let start = physical_offset
        .checked_sub(observed_base)
        .ok_or("physical span starts before S19k mtd5")?;
    let end = start.checked_add(length).ok_or("S19k mtd5 span overflow")?;
    if length == 0 || end > observed_size {
        return Err("physical span lies outside S19k mtd5");
    }
    Ok(start..end)
}

// --- B3 ticket / hw_error ---
pub const REG_TICKET_MASK: u8 = 0x14;
pub const TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256: u32 = 0x0000_00FF;
pub const MOST_HW_NUM: u16 = 128;

// --- B4 public FPGA job header (AML uart_trans job ABI CLOSED 11d/11e/11f) ---
pub const PUBLIC_FPGA_JOB_HDR: u8 = 0x21;
pub const PUBLIC_FPGA_JOB_LEN: u8 = 0x56;
pub const REG_VERSION_ROLL: u8 = 0xA4;

// --- B5 UART_RELAY packing (public chip0) ---
pub const REG_UART_RELAY: u8 = 0x2C;
pub const REG_HASH_COUNTING: u8 = 0x10;
/// Public chip0 UART_RELAY value: CO=1, RO=1, dist=0x7C → `CO|(RO<<1)|(dist<<16)`.
pub const UART_RELAY_CHIP0_PUBLIC: u32 = 0x007C_0003;
pub const UART_RELAY_CHIP0_DIST: u16 = 0x007C;

/// Pack UART_RELAY per wire B5 / `sub_78448`: `CO | (RO << 1) | (dist << 16)`.
/// `nonce_gap_en` is 0 (Braiins `FUN_0083ca30` flags bit 2).
pub const fn pack_uart_relay(co_en: bool, ro_en: bool, dist: u16) -> u32 {
    pack_uart_relay_braiins(co_en, ro_en, false, dist)
}

/// Braiins `UartRelayReg` (`FUN_0083ca30`).
///
/// In-memory: `gap_cnt` u16 @0, `nonce_gap_en` @2, `ro_relay_en` @3,
/// `co_relay_en` @4. Packed LE word is `REV16(gap) | flags<<24` with
/// flags = `CO | RO<<1 | nonce_gap<<2`. `cmd_set_config` BE of the
/// logical u32 below emits the same wire bytes `[gap_hi, gap_lo, 0, flags]`.
pub const BOSMINER_UART_RELAY_PACK_FN_VA: u64 = 0x0083_CA30;
pub const BOSMINER_UART_RELAY_REV16_VA: u64 = 0x0083_CAB0;
pub const BOSMINER_UART_RELAY_REV16_INSN: u32 = 0x5AC0_094A;
pub const BOSMINER_UART_RELAY_STR_VA: u64 = 0x0083_CAF4;
pub const BOSMINER_UART_RELAY_CO_BIT: u32 = 0;
pub const BOSMINER_UART_RELAY_RO_BIT: u32 = 1;
pub const BOSMINER_UART_RELAY_NONCE_GAP_BIT: u32 = 2;

pub const fn pack_uart_relay_braiins(
    co_en: bool,
    ro_en: bool,
    nonce_gap_en: bool,
    dist: u16,
) -> u32 {
    let co = if co_en { 1u32 } else { 0 };
    let ro = if ro_en {
        1u32 << BOSMINER_UART_RELAY_RO_BIT
    } else {
        0
    };
    let ng = if nonce_gap_en {
        1u32 << BOSMINER_UART_RELAY_NONCE_GAP_BIT
    } else {
        0
    };
    ((dist as u32) << 16) | co | ro | ng
}

pub fn admit_bosminer_uart_relay_pack_matches_public_chip0() -> Result<(), &'static str> {
    if pack_uart_relay_braiins(true, true, false, UART_RELAY_CHIP0_DIST) != UART_RELAY_CHIP0_PUBLIC
    {
        return Err("chip0 public 0x007C0003 is CO+RO, nonce_gap=0, gap=0x7C");
    }
    if pack_uart_relay_braiins(true, true, true, UART_RELAY_CHIP0_DIST)
        != (UART_RELAY_CHIP0_PUBLIC | (1 << BOSMINER_UART_RELAY_NONCE_GAP_BIT))
    {
        return Err("nonce_gap_en is flags bit 2 (logical 0x007C0007)");
    }
    if BOSMINER_UART_RELAY_REV16_INSN != 0x5AC0_094A {
        return Err("FUN_0083ca30 REV16 W10,W10 pin drifted");
    }
    Ok(())
}

pub fn refuse_uart_relay_without_nonce_gap_field() -> Result<(), &'static str> {
    Err("Braiins UartRelayReg has nonce_gap_en at +2 → flags bit 2; pack_uart_relay leaves it 0")
}

/// Broadcast set_config for S19k stock hash counting (`0x0000115A` @ reg `0x10`).
pub fn cmd_hash_counting_s19k_bcast() -> [u8; 9] {
    cmd_set_config(true, 0, REG_HASH_COUNTING, S19K_WIRE_HASH_COUNTING)
}

/// Unicast UART_RELAY write for chip0 (public value).
pub fn cmd_uart_relay_chip0() -> [u8; 9] {
    cmd_set_config(false, 0, REG_UART_RELAY, UART_RELAY_CHIP0_PUBLIC)
}

/// B1 stage_2 ordered steps (EVIDENCED `set_asic_register_stage_2` / `sub_5F848`).
/// Host-testable order only — does not claim am3 ttyS framing closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum S19kWireStage2Step {
    AnalogMux = 0,
    ChainInactive = 1,
    SetAddress = 2,
    CoreHashClock = 3,
    CoreClockDelay = 4,
    UartRelayIfDomainsGt9 = 5,
}

#[derive(Debug, Default)]
pub struct S19kWireStage2Latch {
    highest: Option<S19kWireStage2Step>,
}

impl S19kWireStage2Latch {
    pub fn advance(&mut self, next: S19kWireStage2Step) -> Result<(), String> {
        let required = match next {
            S19kWireStage2Step::AnalogMux => None,
            S19kWireStage2Step::ChainInactive => Some(S19kWireStage2Step::AnalogMux),
            S19kWireStage2Step::SetAddress => Some(S19kWireStage2Step::ChainInactive),
            S19kWireStage2Step::CoreHashClock => Some(S19kWireStage2Step::SetAddress),
            S19kWireStage2Step::CoreClockDelay => Some(S19kWireStage2Step::CoreHashClock),
            S19kWireStage2Step::UartRelayIfDomainsGt9 => Some(S19kWireStage2Step::CoreClockDelay),
        };
        if let Some(prev) = required {
            match self.highest {
                Some(h) if h >= prev => {}
                _ => {
                    return Err(format!(
                        "S19k Wire stage_2 refused: cannot enter {next:?} before {prev:?}"
                    ));
                }
            }
        }
        self.highest = Some(match self.highest {
            Some(h) if h > next => h,
            _ => next,
        });
        Ok(())
    }
}

/// S19k has 11 voltage domains → UART relay path is required after stage_2 core regs.
pub const S19K_VOLTAGE_DOMAINS: u8 = 11;
pub const fn s19k_requires_uart_relay() -> bool {
    S19K_VOLTAGE_DOMAINS > 9
}

/// Generic public address interval; do not bind it as the S19k AML interval.
/// Call [`refuse_s19k_public_floor_as_aml_interval`] before using an input interval.
pub fn s19k_public_floor_addr_interval() -> u8 {
    let public = bm1397plus_addr_interval(S19K_WIRE_ASIC_NUM);
    debug_assert_eq!(public, S19K_PUBLIC_ADDR_INTERVAL);
    public
}

/// Prefer AML / BHB5690x interval **2** (desk 11g). Public floor=3 is refused for this family.
pub fn s19k_preferred_addr_interval() -> u8 {
    // Assert preferred is 2, not public floor(256/77)=3.
    debug_assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
    debug_assert_ne!(S19K_AML_ADDR_INTERVAL, S19K_PUBLIC_ADDR_INTERVAL);
    let _ = refuse_s19k_public_floor_as_aml_interval(S19K_AML_ADDR_INTERVAL);
    S19K_AML_ADDR_INTERVAL
}

/// Jig bucket interval for the same population (equals AML preferred; desk 11b/11g).
pub fn s19k_jig_addr_interval() -> u8 {
    bitmain_jig_addr_interval(S19K_WIRE_ASIC_NUM).unwrap_or(0)
}

/// Refuse inventing public `bm1397plus_addr_interval(77)=3` as S19k AML SoT
/// (`BM1366_WIRE_BRINGUP.md` § Desk 2026-08-11g). Preferred interval is **2**, not 3.
pub fn refuse_s19k_public_floor_as_aml_interval(interval: u8) -> Result<(), &'static str> {
    if interval == S19K_PUBLIC_ADDR_INTERVAL {
        return Err(
            "S19k BHB5690x / am3-s19kpro AML: refuse public floor(256/77)=3; preferred asic_addr_interval=2 (desk 11g)",
        );
    }
    if interval != S19K_AML_ADDR_INTERVAL {
        return Err(
            "S19k BHB5690x / am3-s19kpro AML: preferred asic_addr_interval is 2 (BM1366_WIRE_BRINGUP.md § Desk 2026-08-11g)",
        );
    }
    Ok(())
}

/// Enum / set_address addresses for S19k AML: `linear_chip_addresses(77, 2)`.
/// ASIC count remains [`S19K_WIRE_ASIC_NUM`] (77). Slot count hint: 256/2 = 128.
pub fn s19k_aml_linear_addresses() -> Vec<u8> {
    linear_chip_addresses(S19K_WIRE_ASIC_NUM, S19K_AML_ADDR_INTERVAL)
}

/// Alias: preferred linear map is AML step-2 (desk 11g). Not public floor step-3.
pub fn s19k_public_linear_addresses() -> Vec<u8> {
    s19k_aml_linear_addresses()
}

fn crc5_cmd(body: &[u8]) -> u8 {
    stock_bitmain_crc5(body, body.len() * 8)
}

/// 5-byte GetAddress broadcast: `52 05 00 00 CRC5` (`0x0A`).
pub fn cmd_get_address_bcast() -> [u8; 5] {
    cmd_read_register_bcast(0x00)
}

/// Broadcast `read_register(reg)`: `52 05 00 RR CRC5`.
/// GetAddress is `reg=0x00`. FastUART is `reg=0x28`.
/// Not single-chip `42 05 AA RR`.
pub fn cmd_read_register_bcast(reg: u8) -> [u8; 5] {
    let mut f = [CMD_GET_ADDRESS, 0x05, 0x00, reg, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Full UART TX: `55 AA` + [`cmd_read_register_bcast`].
pub fn pack_read_register_bcast_uart(reg: u8) -> [u8; 7] {
    let body = cmd_read_register_bcast(reg);
    [0x55, 0xAA, body[0], body[1], body[2], body[3], body[4]]
}

/// 5-byte chain-inactive broadcast: `53 05 00 00 CRC5` (`0x03`).
pub fn cmd_chain_inactive_bcast() -> [u8; 5] {
    let mut f = [CMD_CHAIN_INACTIVE, 0x05, 0x00, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// Pre- `cmd_chain_inactive_bcast` emitted GetAddress `0x52`.
pub fn refuse_get_address_bytes_as_chain_inactive(body: &[u8]) -> Result<(), &'static str> {
    if body == [0x52u8, 0x05, 0x00, 0x00, 0x0A] {
        return Err("52 05 00 00 0A is GetAddress; chain-inactive is 53 05 00 00 03");
    }
    Ok(())
}

/// 5-byte set_address: `40 05 AA 00 CRC5`.
pub fn cmd_set_address(addr: u8) -> [u8; 5] {
    let mut f = [CMD_SET_ADDRESS, 0x05, addr, 0x00, 0];
    f[4] = crc5_cmd(&f[..4]);
    f
}

/// On-wire set_address for uart_trans / Braiins raw ttyS (desk 11g deepen): TX prepends `55 AA`.
///
/// CLOSED template: `55 AA 40 05 <addr> 00 <crc5>`. Live am3 capture still DESK_PENDING —
/// templates only; Braiins userspace writes this full frame under CLEAR_BRAIINS_TTY.
pub fn pack_set_address_uart_trans(addr: u8) -> [u8; 7] {
    let body = cmd_set_address(addr);
    [0x55, 0xAA, body[0], body[1], body[2], body[3], body[4]]
}

/// 9-byte set_config: `51/41 09 AA RR VV VV VV VV CRC5`.
pub fn cmd_set_config(broadcast: bool, chip_addr: u8, reg: u8, value: u32) -> [u8; 9] {
    let mut f = [
        if broadcast {
            CMD_SET_CONFIG_BCAST
        } else {
            CMD_SET_CONFIG_UNICAST
        },
        0x09,
        chip_addr,
        reg,
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
        0,
    ];
    f[8] = crc5_cmd(&f[..8]);
    f
}

pub fn next_job_id(prev: u8) -> u8 {
    prev.wrapping_add(S19K_WIRE_JOB_ID_STEP) % S19K_WIRE_JOB_ID_MOD
}

pub fn pattern_number_ok_for_midstate8(pattern_number: u8) -> bool {
    pattern_number == S19K_WIRE_MIDSTATE_NUMBER && pattern_number % 2 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ladder_paces_every_address_and_retains_baud_barriers() {
        use crate::s19k_bm1366_init_seq::S19kBm1366NativeCommandOp;
        let program = s19k_bm1366_native_execution_program(77, 400).unwrap();
        let legacy =
            crate::s19k_bm1366_init_seq::s19k_bm1366_native_execution_program(77, 400).unwrap();
        let mut addresses = Vec::new();
        for (command, old) in program
            .pre_baud_commands
            .iter()
            .zip(&legacy.pre_baud_commands)
        {
            assert_eq!(command.op, old.op);
            if let S19kBm1366NativeCommandOp::SetAddress { address } = command.op {
                assert_eq!(command.dwell_after_ms, 10, "address {address}");
                addresses.push(address);
            } else {
                assert_eq!(command, old);
            }
        }
        assert_eq!(addresses, (0..77).map(|i| i * 2).collect::<Vec<u8>>());
        assert_eq!(program.fast_uart_command, legacy.fast_uart_command);
        assert_eq!(program.fast_host_baud, 3_000_000);
        assert_eq!(program.post_baud_commands, legacy.post_baud_commands);
        assert_eq!(program.final_commands, legacy.final_commands);
    }

    #[test]
    fn native_pll_refuses_sibling_ceiling_ramp_start_and_invalid_geometry() {
        for frequency in [0, 50, 99, 671, 695, u16::MAX] {
            assert!(
                s19k_bm1366_native_execution_program(77, frequency).is_err(),
                "{frequency}"
            );
        }
        for frequency in [100, 200, 400, 540, 669, 670] {
            let program = s19k_bm1366_native_execution_program(77, frequency).unwrap();
            assert!((100..=670).contains(&program.actual_frequency_mhz));
        }
        for count in [0, 76, 78, 110, 128] {
            assert!(s19k_bm1366_native_execution_program(count, 400).is_err());
        }
    }

    #[test]
    fn pll_ceiling_checks_fractional_wire_frequency_and_updates_the_command() {
        use crate::s19k_bm1366_init_seq::S19kBm1366NativeCommandOp;
        for (target, minimum, maximum) in [(670, 100, 670), (485, 400, 485), (515, 300, 515)] {
            let (register, actual) = bm1366_pll_in_envelope(target, minimum, maximum).unwrap();
            let div = crate::pll_model::crystal25_pll_decode_dividers(register);
            let denominator =
                u32::from(div.ref_div) * u32::from(div.post_div1) * u32::from(div.post_div2);
            assert!(25 * u32::from(div.fb_div) <= u32::from(maximum) * denominator);
            assert!(25 * u32::from(div.fb_div) >= u32::from(minimum) * denominator);
            assert!(actual.abs_diff(target) <= 2);
        }
        let program = s19k_bm1366_native_execution_program(77, 670).unwrap();
        assert_eq!(program.actual_frequency_mhz, 669);
        let safe = bm1366_pll_in_envelope(670, 100, 670).unwrap();
        assert!(program.final_commands.iter().any(
            |command| matches!(command.op, S19kBm1366NativeCommandOp::WriteRegister(write)
                if write.reg == REG_PLL0 && write.value == safe.0)
        ));
        // 670 MHz has no exact divider solution; rounded labels must not admit it.
        assert!(bm1366_pll_in_envelope(485, 485, 485).is_ok());
        for (target, minimum, maximum) in [
            (670, 670, 670),
            (0, 0, 670),
            (671, 100, 670),
            (99, 100, 670),
            (400, 500, 100),
        ] {
            assert!(bm1366_pll_in_envelope(target, minimum, maximum).is_err());
        }
    }

    #[test]
    fn physical_mtd5_translation_refuses_the_size_sum_trap_and_overflow() {
        let local = |base, offset, length| s19k_mtd5_local_span(base, 0x0990_0000, offset, length);
        assert_eq!(
            local(0x0670_0000, 0x0B80_0000, 0x0010_0000),
            Ok(0x0510_0000..0x0520_0000)
        );
        assert_eq!(
            local(0x0670_0000, 0x0B40_0000, 1),
            Ok(0x04D0_0000..0x04D0_0001)
        );
        assert!(local(0x0610_0000, 0x0B80_0000, 0x0010_0000).is_err());
        assert!(s19k_mtd5_local_span(0x0670_0000, 0x09F0_0000, 0x0B80_0000, 1).is_err());
        assert!(local(0x0670_0000, 0x066F_FFFF, 1).is_err());
        assert!(local(0x0670_0000, 0x1000_0000, 1).is_err());
        assert!(local(0x0670_0000, 0x0670_0000, 0).is_err());
        assert!(local(0x0670_0000, u32::MAX, u32::MAX).is_err());
        assert_eq!(
            local(0x0670_0000, 0x0FFF_FFFF, 1),
            Ok(0x098F_FFFF..0x0990_0000)
        );
    }

    #[test]
    fn b1_cmd_templates_match_wire_desk_crc5() {
        assert_eq!(cmd_get_address_bcast(), [0x52, 0x05, 0x00, 0x00, 0x0a]);
        assert_eq!(cmd_read_register_bcast(0x00), cmd_get_address_bcast());
        assert_eq!(
            pack_read_register_bcast_uart(0x00),
            [0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, 0x0A]
        );
        let r28 = cmd_read_register_bcast(PUBLIC_FASTUART_REG);
        assert_eq!(&r28[..4], &[0x52, 0x05, 0x00, 0x28]);
        assert_ne!(r28[4], 0);
        assert_ne!(r28, cmd_get_address_bcast());
        assert_eq!(
            pack_read_register_bcast_uart(PUBLIC_FASTUART_REG)[2],
            0x52,
            "broadcast read is 0x52, not single-chip 0x42"
        );
        assert_eq!(cmd_chain_inactive_bcast(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert!(
            refuse_get_address_bytes_as_chain_inactive(&[0x52, 0x05, 0x00, 0x00, 0x0A]).is_err()
        );
        assert_eq!(CMD_GET_ADDRESS, 0x52);
        assert_eq!(CMD_CHAIN_INACTIVE, 0x53);
        assert_eq!(
            S19K_JIG_VOLTAGE_DOMAIN * S19K_JIG_ASICS_PER_DOMAIN,
            S19K_WIRE_ASIC_NUM
        );
        assert_eq!(cmd_set_address(0), [0x40, 0x05, 0x00, 0x00, 0x1c]);
        assert_eq!(cmd_set_address(2), [0x40, 0x05, 0x02, 0x00, 0x01]);
        assert_eq!(cmd_set_address(3), [0x40, 0x05, 0x03, 0x00, 0x1d]);
    }

    #[test]
    fn b1_interval_aml_pinned_step2_refuse_public_floor3() {
        // Public floor helper still reports 3 — but S19k AML must not bind it (desk 11g).
        assert_eq!(bm1397plus_addr_interval(77), S19K_PUBLIC_ADDR_INTERVAL);
        assert_eq!(bitmain_jig_addr_interval(77), Some(S19K_AML_ADDR_INTERVAL));
        assert_eq!(S19K_AML_ADDR_INTERVAL, 2);
        assert_eq!(S19K_AML_ADDR_SLOT_COUNT, 128);
        assert_eq!(s19k_preferred_addr_interval(), 2);
        assert_eq!(s19k_jig_addr_interval(), 2);
        assert_eq!(s19k_preferred_addr_interval(), s19k_jig_addr_interval());
        assert_ne!(s19k_preferred_addr_interval(), S19K_PUBLIC_ADDR_INTERVAL);
        assert!(refuse_s19k_public_floor_as_aml_interval(3).is_err());
        assert!(refuse_s19k_public_floor_as_aml_interval(2).is_ok());
        let addrs = s19k_aml_linear_addresses();
        assert_eq!(addrs.len(), usize::from(S19K_WIRE_ASIC_NUM));
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 2);
        assert_eq!(addrs[76], 152); // (77-1)*2
    }

    #[test]
    fn b1_open_core_regs_and_stage2_set_config_frames() {
        assert_eq!(CORE_REG_HASH_CLOCK, 0x8000_8540);
        assert_eq!(CORE_REG_CLOCK_DELAY, 0x8000_8020);
        assert_eq!(CORE_REG_ASICBOOST, 0x8000_82AA);
        assert_eq!(
            cmd_set_config(true, 0, REG_ANALOG_MUX, ANALOG_MUX_DIODE_VDD_SEL),
            [0x51, 0x09, 0x00, 0x54, 0x00, 0x00, 0x00, 0x03, 0x1d]
        );
        assert_eq!(
            cmd_set_config(true, 0, REG_CORE, CORE_REG_HASH_CLOCK),
            [0x51, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x85, 0x40, 0x0c]
        );
        assert_eq!(
            cmd_set_config(true, 0, REG_CORE, CORE_REG_CLOCK_DELAY),
            [0x51, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x80, 0x20, 0x19]
        );
        assert_eq!(
            cmd_set_config(false, 0, REG_CORE, CORE_REG_ASICBOOST),
            [0x41, 0x09, 0x00, 0x3c, 0x80, 0x00, 0x82, 0xaa, 0x05]
        );
    }

    #[test]
    fn b2_pll_and_baud_dialects_not_merged() {
        assert_eq!(REG_PLL0, 0x08);
        assert_eq!(REG_PLL1, 0x60);
        assert_eq!(PLL_RAMP_START_MHZ, 50);
        assert_eq!(PUBLIC_FASTUART_VALUE, 0x1130_0200);
        assert_eq!(JIG_CONFIG_BAUD_HZ, 12_000_000);
    }

    #[test]
    fn b3_ticket_mask_frame_and_most_hw_num() {
        assert_eq!(MOST_HW_NUM, 128);
        assert_eq!(
            cmd_set_config(
                true,
                0,
                REG_TICKET_MASK,
                TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256
            ),
            [0x51, 0x09, 0x00, 0x14, 0x00, 0x00, 0x00, 0xff, 0x08]
        );
    }

    #[test]
    fn b4_midstate8_abi_pins_and_refuses_s21_sixteen() {
        assert_eq!(S19K_WIRE_MIDSTATE_NUMBER, 8);
        assert!(pattern_number_ok_for_midstate8(8));
        assert!(!pattern_number_ok_for_midstate8(16));
        assert_eq!(PUBLIC_FPGA_JOB_HDR, 0x21);
        assert_eq!(PUBLIC_FPGA_JOB_LEN, 0x56);
        assert_eq!(S19K_WIRE_RESPONSE_BYTES, 11);
        assert_eq!(S19K_WIRE_HASH_COUNTING, 0x0000_115A);
        assert_eq!(next_job_id(0), 8);
        assert_eq!(next_job_id(120), 0);
    }

    #[test]
    fn b5_asic_register_config_knobs() {
        // Config.ini: CCdly=0 Pwth=4 Swpf=0 Clk_Sel=0 Diode_Vdd_Mux_Sel=3
        assert_eq!(CORE_REG_CLOCK_DELAY, 0x8000_8020);
        assert_eq!(CORE_REG_HASH_CLOCK, 0x8000_8540); // Clk_Sel=0
        assert_eq!(ANALOG_MUX_DIODE_VDD_SEL, 3);
        // Pulse_Mode=1 bit placement remains DESK_PENDING — we do not invent packing here.
    }

    #[test]
    fn b5_uart_relay_packing_matches_public_chip0() {
        assert_eq!(
            pack_uart_relay(true, true, UART_RELAY_CHIP0_DIST),
            UART_RELAY_CHIP0_PUBLIC
        );
        assert_eq!(UART_RELAY_CHIP0_PUBLIC, 0x007C_0003);
        assert_eq!(REG_UART_RELAY, 0x2C);
        assert!(admit_bosminer_uart_relay_pack_matches_public_chip0().is_ok());
        assert!(refuse_uart_relay_without_nonce_gap_field().is_err());
        assert_eq!(
            pack_uart_relay_braiins(true, true, true, UART_RELAY_CHIP0_DIST),
            0x007C_0007
        );
        assert_eq!(BOSMINER_UART_RELAY_PACK_FN_VA, 0x0083_CA30);
        let f = cmd_uart_relay_chip0();
        assert_eq!(f[0], CMD_SET_CONFIG_UNICAST);
        assert_eq!(f[2], 0x00);
        assert_eq!(f[3], REG_UART_RELAY);
        assert_eq!(&f[4..8], &[0x00, 0x7c, 0x00, 0x03]);
        assert_eq!(f[8], stock_bitmain_crc5(&f[..8], 64));
    }

    #[test]
    fn b4_hash_counting_set_config_frame() {
        assert_eq!(REG_HASH_COUNTING, 0x10);
        let body = [0x51u8, 0x09, 0x00, 0x10, 0x00, 0x00, 0x11, 0x5a];
        let mut expect = [0u8; 9];
        expect[..8].copy_from_slice(&body);
        expect[8] = stock_bitmain_crc5(&body, 64);
        assert_eq!(cmd_hash_counting_s19k_bcast(), expect);
    }

    #[test]
    fn b1_stage2_order_latch_and_uart_relay_required() {
        assert!(s19k_requires_uart_relay());
        let mut latch = S19kWireStage2Latch::default();
        assert!(latch.advance(S19kWireStage2Step::SetAddress).is_err());
        latch.advance(S19kWireStage2Step::AnalogMux).unwrap();
        latch.advance(S19kWireStage2Step::ChainInactive).unwrap();
        latch.advance(S19kWireStage2Step::SetAddress).unwrap();
        latch.advance(S19kWireStage2Step::CoreHashClock).unwrap();
        latch.advance(S19kWireStage2Step::CoreClockDelay).unwrap();
        latch
            .advance(S19kWireStage2Step::UartRelayIfDomainsGt9)
            .unwrap();
    }

    #[test]
    fn desk_11g_set_address_uart_trans_preamble() {
        assert_eq!(
            pack_set_address_uart_trans(0),
            [0x55, 0xAA, 0x40, 0x05, 0x00, 0x00, 0x1c]
        );
        assert_eq!(
            pack_set_address_uart_trans(2),
            [0x55, 0xAA, 0x40, 0x05, 0x02, 0x00, 0x01]
        );
        let addrs = s19k_aml_linear_addresses();
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 2); // interval=2
        assert_eq!(
            pack_set_address_uart_trans(addrs[1]),
            [0x55, 0xAA, 0x40, 0x05, 0x02, 0x00, 0x01]
        );
    }

    #[test]
    fn clear_braiins_ttys_pins_baud_3m_never_ttys0() {
        use crate::s19k_uart_trans_job::{
            admit_braiins_job_tx_path, admit_job_tx_path, admit_job_tx_path_for_transport,
            BRAIINS_RAW_TTYS_PINS, BRAIINS_TTYS_BAUD, BRAIINS_TTYS_CANDIDATES,
            BRAIINS_TTYS_FORBIDDEN,
        };
        assert_eq!(BRAIINS_TTYS_BAUD, 3_000_000);
        assert_eq!(BRAIINS_RAW_TTYS_PINS.baud, 3_000_000);
        assert_eq!(BRAIINS_TTYS_CANDIDATES, &["/dev/ttyS1", "/dev/ttyS2"]);
        assert_eq!(BRAIINS_TTYS_FORBIDDEN, &["/dev/ttyS0"]);
        assert!(!BRAIINS_TTYS_CANDIDATES.contains(&"/dev/ttyS0"));
        assert!(!BRAIINS_TTYS_CANDIDATES.contains(&"/dev/ttyS3"));
        assert!(admit_braiins_job_tx_path("/dev/ttyS1").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS2").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS3").is_ok());
        assert!(admit_braiins_job_tx_path("/dev/ttyS0").is_err());
        assert!(admit_job_tx_path("/dev/ttyS1").is_err()); // stock unchanged
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS1").is_ok());
        assert!(admit_job_tx_path_for_transport(false, "/dev/ttyS3").is_ok());
    }
}
