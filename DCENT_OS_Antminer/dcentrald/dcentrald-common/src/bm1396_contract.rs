//! Clean-room BM1396 identity and per-present-chain enumeration contract.
//!
//! Exact signed S17e/T17e production binaries prove the wire identity,
//! per-present-chain geometry, baud behavior, voltage-endpoint framing, and
//! lifecycle facts recorded here. The module performs no I/O and deliberately
//! does not admit carrier energization or promote vendor software limits into
//! bench-certified electrical safety envelopes.

/// BM1396 register-zero high word required by the exact signed S17e/T17e
/// production miners.
pub const BM1396_WIRE_CHIP_ID: u16 = 0x1396;

/// S17e ASIC responses required for each caller-selected present chain.
///
/// `bmminer` SHA-256
/// `819bd5ee790f3ce74f61a45546856e0cd7b37a62e7ec2263ebb83e35220c8243`:
/// enumeration function `0x82958`, register-zero response high-word compare
/// at `0x82a70`, count compare against 135 at `0x82ad4`.
pub const BM1396_S17E_CHIPS_PER_PRESENT_CHAIN: u16 = 135;

/// T17e ASIC responses required for each caller-selected present chain.
///
/// `bmminer` SHA-256
/// `d0f14d843e35b15ffdf73d3523fa637ac318ade6c1a660764ceab5a48e135ffe`:
/// enumeration function `0x83800`, register-zero response high-word compare
/// at `0x83918`, count compare against 78 at `0x8397c`.
pub const BM1396_T17E_CHIPS_PER_PRESENT_CHAIN: u16 = 78;

/// S17e hardware-address interval written by the exact production startup path
/// (`0x80e8c` stores 1 at `0x80ea0`).
pub const BM1396_S17E_ADDRESS_INTERVAL: u8 = 1;

/// T17e hardware-address interval written by the exact production startup path
/// (`0x81d34` stores 3 at `0x81d48`).
pub const BM1396_T17E_ADDRESS_INTERVAL: u8 = 3;

/// FPGA chain slots examined by both exact production startup paths. Runtime
/// presence flags, not this upper bound, decide which slots are acted on.
pub const BM1396_FPGA_CHAIN_SLOT_COUNT: u8 = 16;

/// Address-reset broadcasts sent before address assignment.
pub const BM1396_ADDRESS_RESET_BURST_COUNT: u8 = 3;

/// Inter-command delay used for both reset-address and set-address commands.
pub const BM1396_ADDRESS_COMMAND_SPACING_MS: u32 = 30;

/// Lower clamp in the recovered vendor board-voltage setter, in centivolts.
/// This is a vendor software envelope, not a bench-certified absolute rating.
pub const BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV: u16 = 1800;

/// Upper clamp in the recovered vendor board-voltage setter, in centivolts.
/// This is a vendor software envelope, not a bench-certified absolute rating.
pub const BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV: u16 = 2100;

/// T17e short-count retry increment, in centivolts.
pub const BM1396_T17E_RETRY_VOLTAGE_STEP_CV: u16 = 100;

/// Seven-bit I2C address used by the recovered BM1396 board-voltage transport.
/// This identifies the software endpoint, not the controller silicon.
pub const BM1396_VOLTAGE_I2C_ADDRESS: u8 = 0x11;

/// Delay between an eight-byte voltage request and its eight-byte response.
pub const BM1396_VOLTAGE_RESPONSE_WAIT_US: u32 = 500_000;

/// Total request/read attempts made when a voltage response is invalid.
pub const BM1396_VOLTAGE_TRANSPORT_MAX_ATTEMPTS: u8 = 3;

/// Fixed-point value returned by the recovered ramp-step helper. The caller
/// interprets it with one fractional bit, producing 17.5 DAC counts.
pub const BM1396_VOLTAGE_DAC_RAMP_STEP_FIXED_X2: u8 = 35;

/// Effective integer DAC-code step used by the recovered stepped setter.
/// ARM `VCVT.F64.S32 #1` creates 17.5 and `VCVT.S32.F64` truncates it to 17.
/// The final write is shorter when needed so every emitted transition is at
/// most 17 counts.
pub const BM1396_VOLTAGE_DAC_RAMP_STEP: u8 = 17;

pub const BM1396_STARTUP_BAUD: u32 = 115_200;
pub const BM1396_BAUD_HIGH_CLOCK_THRESHOLD: u32 = 3_000_000;
pub const BM1396_BAUD_LOW_CLOCK_HZ: u32 = 25_000_000;
pub const BM1396_BAUD_HIGH_CLOCK_HZ: u32 = 400_000_000;
pub const BM1396_FPGA_BAUD_REGISTER_OFFSET: u32 = 0x3c;
pub const BM1396_FPGA_BAUD_PRESERVE_MASK: u32 = 0xc0c0_c0c0;
pub const BM1396_ASIC_MISC_CONTROL_REGISTER: u8 = 0x18;
/// Exact integer passed to the recovered monotonic-delay wrapper before the
/// FPGA selector change. The call is semantically a 50 ms settle.
pub const BM1396_BAUD_SWITCH_DELAY_CALL_VALUE: u32 = 50_000;
/// Register prelude emitted before divisor programming above 3 Mbaud.
pub const BM1396_HIGH_BAUD_CLOCK_PRELUDE: [(u8, u32); 3] = [
    (0x68, 0x4070_0111),
    (0x68, 0x4070_0111),
    (0x28, 0x0600_000f),
];

pub const BM1396_DCDC_CONTROL_OPCODE: u8 = 0x15;
pub const BM1396_DCDC_DISABLE_PAYLOAD: u8 = 0x00;
pub const BM1396_SHUTDOWN_GPIO: u16 = 907;
pub const BM1396_SHUTDOWN_GPIO_SETTLE_MS: u32 = 1_000;
pub const BM1396_FPGA_MAIN_CONTROL_OFFSET: u32 = 0x100;
pub const BM1396_FPGA_MAIN_CONTROL_RUN_BIT: u32 = 0x40;
pub const BM1396_CHAIN_WATCHDOG_DISABLE_AFTER_MISMATCHES: u8 = 30;
pub const BM1396_CHAIN_WATCHDOG_TRIGGER_DELAY_CALL_VALUES: [u32; 2] = [100, 300];
pub const BM1396_CHAIN_WATCHDOG_INTER_PHASE_DELAY_CALL_VALUES: [u32; 2] = [100, 1_500];

/// Both production binaries require at least four fans at startup and runtime.
pub const BM1396_REQUIRED_FAN_COUNT: u8 = 4;
pub const BM1396_FAN_VALIDATION_MAX_SAMPLES: u8 = 10;
pub const BM1396_FAN_TACH_MAX_READINGS: u8 = 8;
pub const BM1396_FAN_TACH_DEFAULT_RPM_PER_COUNT: u32 = 120;
pub const BM1396_FAN_TACH_SPECIAL_RPM_PER_COUNT: u32 = 240;
/// Low-16-bit hardware selector that doubles the tach conversion. The exact
/// code truncates FPGA offset 0 to signed i16 before comparing, so upper bits
/// are intentionally ignored.
pub const BM1396_FAN_TACH_DOUBLE_RATE_HW_ID_LOW16: u16 = 0xb025;
/// Exact signed-2020 T17e startup sets 100% at 0x18b50/0x18b54
/// (`set_fan_pwm` 0x4a3d0), before calling validation(4000, 1) at
/// 0x194d4..0x194dc. This threshold belongs to that high-PWM startup.
pub const BM1396_STOCK_STARTUP_FAN_PWM_PERCENT: u8 = 100;
pub const BM1396_STARTUP_FAN_MIN_RPM: u32 = 4_000;
pub const BM1396_QUIET_FAN_PWM_PERCENT: u8 = 30;
pub const BM1396_RUNTIME_FAN_MIN_RPM: u32 = 400;
/// Exact integer passed to the recovered delay wrapper after a bad sample.
pub const BM1396_STARTUP_FAN_BAD_SAMPLE_DELAY_CALL_VALUE: u32 = 2_000;
/// Exact integer passed to the recovered delay wrapper after a bad sample.
pub const BM1396_RUNTIME_FAN_BAD_SAMPLE_DELAY_CALL_VALUE: u32 = 50;
/// The recovered core-reopen predicate treats PCB minima below this as
/// invalid/too-low sensor data, not as a cool board.
pub const BM1396_VENDOR_MIN_VALID_PCB_TEMP_C: i16 = 16;
/// Exact hard-monitor limits while the shared runtime state byte is clear.
/// Comparisons are strict greater-than, so equality remains admitted.
pub const BM1396_HARD_THERMAL_FLAG_CLEAR_PCB_MAX_C: i16 = 85;
pub const BM1396_HARD_THERMAL_FLAG_CLEAR_CHIP_MAX_C: i16 = 98;
/// Exact tightened limits while the shared runtime state byte is set. The byte
/// also participates in core close/reopen handling; it is not a monotonic timer.
pub const BM1396_HARD_THERMAL_FLAG_SET_PCB_MAX_C: i16 = 80;
pub const BM1396_HARD_THERMAL_FLAG_SET_CHIP_MAX_C: i16 = 95;
/// A separate runtime loop sets the shared phase byte when its counter reaches
/// this value after repeated one-second delays. Reopen can later clear it.
pub const BM1396_RUNTIME_PHASE_SET_COUNTER_VALUE: u16 = 120;
pub const BM1396_HARD_THERMAL_FATAL_ERROR_CODE: u8 = 15;
/// Exact 2019-only positive temperature-delta limits. These sample-to-sample
/// deltas are not time-normalized °C/s values. Equality remains admitted.
pub const BM1396_LEGACY_2019_FLAG_CLEAR_PCB_DELTA_MAX_C: i32 = 13;
pub const BM1396_LEGACY_2019_FLAG_CLEAR_CHIP_DELTA_MAX_C: i32 = 15;
pub const BM1396_LEGACY_2019_FLAG_SET_PCB_DELTA_MAX_C: i32 = 8;
pub const BM1396_LEGACY_2019_FLAG_SET_CHIP_DELTA_MAX_C: i32 = 10;
pub const BM1396_LEGACY_2019_THERMAL_FATAL_ERROR_CODE: u8 = 14;
pub const BM1396_SENSOR_POSITIONS_PER_CHAIN: usize = 4;
pub const BM1396_SENSOR_INVALID_FATAL_ERROR_CODE: u8 = 14;
pub const BM1396_SENSOR_MODE0_SLOPE_F64_BITS: u64 = 0x3fef_0e56_0418_9375;
pub const BM1396_SENSOR_MODE0_OFFSET_F64_BITS: u64 = 0x4026_7c6a_7ef9_db23;
pub const BM1396_SENSOR_MODE1_SLOPE_F64_BITS: u64 = 0x3fec_0418_9374_bc6a;
pub const BM1396_SENSOR_MODE1_OFFSET_F64_BITS: u64 = 0x4020_9724_7453_8ef3;
pub const BM1396_SENSOR_OUTLIER_VARIANCE_THRESHOLD: i16 = 100;
pub const BM1396_SENSOR_OUTLIER_MULTIPLIER_F32_BITS: u32 = 0x402c_cccd;

/// Compute the exact host-command CRC5 used by both signed BM1396 binaries.
///
/// Polynomial `x^5 + x^2 + 1` (`0x05` feedback), initial state `0x1f`, MSB
/// first. This is not the modified CRC carried by some ASIC response trailers.
pub fn bm1396_command_crc5(data: &[u8]) -> u8 {
    let mut crc = 0x1f;
    for &byte in data {
        for bit_index in (0..8).rev() {
            let input_bit = (byte >> bit_index) & 1;
            let crc_top = (crc >> 4) & 1;
            crc = (crc << 1) & 0x1f;
            if input_bit ^ crc_top != 0 {
                crc ^= 0x05;
            }
        }
    }
    crc
}

/// Build the exact BM1396 register-read body including its CRC5 trailer.
pub fn bm1396_read_register_frame(broadcast: bool, chip_addr: u8, reg_addr: u8) -> [u8; 5] {
    let mut frame = [
        if broadcast { 0x52 } else { 0x42 },
        0x05,
        chip_addr,
        reg_addr,
        0,
    ];
    frame[4] = bm1396_command_crc5(&frame[..4]);
    frame
}

/// Build the address-reset/chain-inactive command sent three times before
/// address assignment.
pub fn bm1396_reset_address_frame() -> [u8; 5] {
    let mut frame = [0x53, 0x05, 0x00, 0x00, 0];
    frame[4] = bm1396_command_crc5(&frame[..4]);
    frame
}

/// Build one exact set-address command.
pub fn bm1396_set_address_frame(address: u8) -> [u8; 5] {
    let mut frame = [0x40, 0x05, address, 0x00, 0];
    frame[4] = bm1396_command_crc5(&frame[..4]);
    frame
}

/// Build the exact BM1396 register-write body including its CRC5 trailer.
pub fn bm1396_write_register_frame(
    broadcast: bool,
    chip_addr: u8,
    reg_addr: u8,
    value: u32,
) -> [u8; 9] {
    let value = value.to_be_bytes();
    let mut frame = [
        if broadcast { 0x51 } else { 0x41 },
        0x09,
        chip_addr,
        reg_addr,
        value[0],
        value[1],
        value[2],
        value[3],
        0,
    ];
    frame[8] = bm1396_command_crc5(&frame[..8]);
    frame
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396BaudPlan {
    pub baud: u32,
    pub bt8d: u16,
    pub high_speed_clock: bool,
    pub fpga_selector: u8,
    pub fpga_register_value: u32,
    pub misc_control_register_value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396UnsupportedBaud {
    pub baud: u32,
}

impl std::fmt::Display for Bm1396UnsupportedBaud {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BM1396 baud {} has no exact signed-firmware FPGA selector admission",
            self.baud
        )
    }
}

impl std::error::Error for Bm1396UnsupportedBaud {}

/// Build the exact ASIC-divisor/FPGA-selector plan for a baud explicitly
/// supported by both signed BM1396 miners.
///
/// The stock function maps every unrecognized configured baud to FPGA selector
/// `0x1a` even after computing a different ASIC divisor. This independent
/// contract refuses that desynchronizing fallback.
pub const fn bm1396_baud_plan(
    baud: u32,
    old_misc_control_register_value: u32,
    old_fpga_register_value: u32,
) -> Result<Bm1396BaudPlan, Bm1396UnsupportedBaud> {
    let fpga_selector = match baud {
        115_200 => 0x1a,
        1_500_000 => 0x01,
        3_000_000 => 0x00,
        6_000_000 => 0x03,
        12_000_000 => 0x04,
        25_000_000 => 0x05,
        _ => return Err(Bm1396UnsupportedBaud { baud }),
    };
    let high_speed_clock = baud > BM1396_BAUD_HIGH_CLOCK_THRESHOLD;
    let clock_hz = if high_speed_clock {
        BM1396_BAUD_HIGH_CLOCK_HZ
    } else {
        BM1396_BAUD_LOW_CLOCK_HZ
    };
    let bt8d = clock_hz / (baud * 8) - 1;
    let bt8d_low = (bt8d & 0x1f) << 8;
    let bt8d_high = ((bt8d >> 5) & 0x0f) << 24;
    let misc_control_register_value = if high_speed_clock {
        (old_misc_control_register_value & 0xf0ff_e0ff) | bt8d_low | bt8d_high | 0x0001_0000
    } else {
        (old_misc_control_register_value & 0xf0fe_e0ff) | bt8d_low | bt8d_high
    };
    let repeated = fpga_selector as u32
        | ((fpga_selector as u32) << 8)
        | ((fpga_selector as u32) << 16)
        | ((fpga_selector as u32) << 24);
    Ok(Bm1396BaudPlan {
        baud,
        bt8d: bt8d as u16,
        high_speed_clock,
        fpga_selector,
        fpga_register_value: (old_fpga_register_value & BM1396_FPGA_BAUD_PRESERVE_MASK) | repeated,
        misc_control_register_value,
    })
}

/// Build the exact eight-byte board-voltage request sent to I2C address 0x11.
///
/// The checksum is the wrapping `u16` sum of bytes 2 through 5 and is encoded
/// little-endian. For this fixed frame it is `0x0089 + dac`.
pub const fn bm1396_voltage_request_frame(dac: u8) -> [u8; 8] {
    let checksum = 0x0089u16 + dac as u16;
    [
        0x55,
        0xaa,
        0x06,
        0x83,
        dac,
        0x00,
        checksum as u8,
        (checksum >> 8) as u8,
    ]
}

/// Why an eight-byte response from the recovered voltage endpoint was invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396VoltageResponseError {
    WrongLength { observed: usize },
    WrongEnvelope,
    ChecksumMismatch { expected: u16, observed: u16 },
}

impl std::fmt::Display for Bm1396VoltageResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { observed } => {
                write!(f, "BM1396 voltage response expected 8 bytes, observed {observed}")
            }
            Self::WrongEnvelope => write!(
                f,
                "BM1396 voltage response expected envelope 55 aa 06 83"
            ),
            Self::ChecksumMismatch { expected, observed } => write!(
                f,
                "BM1396 voltage response checksum expected 0x{expected:04x}, observed 0x{observed:04x}"
            ),
        }
    }
}

impl std::error::Error for Bm1396VoltageResponseError {}

/// Validate one recovered board-voltage response and return its two opaque,
/// checksum-covered payload bytes.
///
/// Exact S17e/T17e code tests no separate status bit: bytes 4 and 5 are opaque.
/// A caller must not invent success semantics for either byte.
pub fn bm1396_validate_voltage_response(
    response: &[u8],
) -> Result<[u8; 2], Bm1396VoltageResponseError> {
    if response.len() != 8 {
        return Err(Bm1396VoltageResponseError::WrongLength {
            observed: response.len(),
        });
    }
    if response[..4] != [0x55, 0xaa, 0x06, 0x83] {
        return Err(Bm1396VoltageResponseError::WrongEnvelope);
    }
    let expected =
        response[2] as u16 + response[3] as u16 + response[4] as u16 + response[5] as u16;
    let observed = response[6] as u16 | ((response[7] as u16) << 8);
    if observed != expected {
        return Err(Bm1396VoltageResponseError::ChecksumMismatch { expected, observed });
    }
    Ok([response[4], response[5]])
}

/// Why a requested centivolt value could not enter the recovered vendor DAC
/// conversion without first being explicitly clamped by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396VoltageOutsideVendorEnvelope {
    pub requested_cv: u16,
}

impl std::fmt::Display for Bm1396VoltageOutsideVendorEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BM1396 voltage request {} cV is outside recovered vendor envelope {}..={} cV",
            self.requested_cv,
            BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV,
            BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV
        )
    }
}

impl std::error::Error for Bm1396VoltageOutsideVendorEnvelope {}

/// Convert a request already inside the recovered 1800-2100 cV vendor
/// envelope to its exact DAC code.
///
/// Ghidra recovered semantically equivalent IEEE-754 implementations in the
/// signed S17e and T17e miners. Exhaustive comparison over all 301 admitted integer
/// centivolt values proves this integer form equivalent to those binaries:
/// `floor((91849 - 43 * raw_cV) / 120)`.
///
/// This function refuses values outside the recovered software envelope. A
/// caller that wants vendor clamping must invoke
/// [`bm1396_vendor_working_voltage_clamp_cv`] explicitly first.
pub const fn bm1396_voltage_dac_in_vendor_envelope(
    raw_cv: u16,
) -> Result<u8, Bm1396VoltageOutsideVendorEnvelope> {
    if raw_cv < BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV
        || raw_cv > BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV
    {
        return Err(Bm1396VoltageOutsideVendorEnvelope {
            requested_cv: raw_cv,
        });
    }
    let numerator = 91_849u32 - 43u32 * raw_cv as u32;
    Ok((numerator / 120) as u8)
}

/// Plan the exact DAC-code sequence emitted by the recovered stepped setter.
///
/// Both inputs are software-shadow centivolts; the current value is not a
/// controller readback. Increasing voltage lowers the DAC code. Exact
/// multiples of 17 do not duplicate the target, a remainder produces one
/// shorter final step, and an unchanged target is still written once.
pub fn plan_bm1396_vendor_voltage_dac_ramp(
    current_cv: u16,
    target_cv: u16,
) -> Result<Vec<u8>, Bm1396VoltageOutsideVendorEnvelope> {
    let current = i16::from(bm1396_voltage_dac_in_vendor_envelope(current_cv)?);
    let target = i16::from(bm1396_voltage_dac_in_vendor_envelope(target_cv)?);
    let difference = target - current;
    let direction = difference.signum();
    let full_steps = difference.unsigned_abs() / u16::from(BM1396_VOLTAGE_DAC_RAMP_STEP);
    let mut emitted = Vec::with_capacity(usize::from(full_steps) + 1);

    for step in 1..=full_steps {
        let code = current
            + direction
                * i16::try_from(step * u16::from(BM1396_VOLTAGE_DAC_RAMP_STEP))
                    .expect("BM1396 vendor DAC ramp is bounded to u8 codes");
        emitted.push(code as u8);
    }
    if emitted.last().copied() != Some(target as u8) {
        emitted.push(target as u8);
    }
    Ok(emitted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396FanValidationPhase {
    Startup,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396FanValidationPolicy {
    pub minimum_rpm: u32,
    pub required_fan_count: u8,
    pub maximum_samples: u8,
    pub bad_sample_delay_call_value: u32,
    /// Exhausting validation is fatal and enters the deterministic global
    /// shutdown sequence recovered from the same signed binary.
    pub fatal_on_exhaustion: bool,
}

pub const fn bm1396_fan_validation_policy(
    phase: Bm1396FanValidationPhase,
) -> Bm1396FanValidationPolicy {
    match phase {
        Bm1396FanValidationPhase::Startup => Bm1396FanValidationPolicy {
            minimum_rpm: BM1396_STARTUP_FAN_MIN_RPM,
            required_fan_count: BM1396_REQUIRED_FAN_COUNT,
            maximum_samples: BM1396_FAN_VALIDATION_MAX_SAMPLES,
            bad_sample_delay_call_value: BM1396_STARTUP_FAN_BAD_SAMPLE_DELAY_CALL_VALUE,
            fatal_on_exhaustion: true,
        },
        Bm1396FanValidationPhase::Runtime => Bm1396FanValidationPolicy {
            minimum_rpm: BM1396_RUNTIME_FAN_MIN_RPM,
            required_fan_count: BM1396_REQUIRED_FAN_COUNT,
            maximum_samples: BM1396_FAN_VALIDATION_MAX_SAMPLES,
            bad_sample_delay_call_value: BM1396_RUNTIME_FAN_BAD_SAMPLE_DELAY_CALL_VALUE,
            fatal_on_exhaustion: true,
        },
    }
}

/// Quiet30 uses the recovered running-fan predicate in every powered phase.
/// Signed-2020 T17e calls validation(400, 0) at 0x4f418..0x4f420 and
/// 0x4f4b0..0x4f4b8. The stock 100%-PWM/4000-RPM startup test cannot be
/// transplanted beneath the home PWM30 cap, and no linear PWM/RPM law is
/// established by those bytes. This policy checks four spinning fans; actual
/// quiet-profile airflow remains a physical qualification, with independent
/// temperature limits and immediate source cutoff retained.
pub const fn bm1396_quiet_fan_validation_policy() -> Bm1396FanValidationPolicy {
    bm1396_fan_validation_policy(Bm1396FanValidationPhase::Runtime)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396FanTachReading {
    pub fan_id: u8,
    pub raw_count: u8,
    pub rpm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bm1396FanState {
    passing: [bool; BM1396_FAN_TACH_MAX_READINGS as usize],
}

impl Bm1396FanState {
    pub const fn passing(self) -> [bool; BM1396_FAN_TACH_MAX_READINGS as usize] {
        self.passing
    }

    pub fn passing_count(self) -> u8 {
        self.passing.iter().filter(|&&passing| passing).count() as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396FanSampleError {
    TooManyReadings { observed: usize },
    InvalidFanId { observed: u8 },
}

/// Apply one production fan sample to persistent per-ID good/bad state.
/// Observations are sequential, so the last value for a repeated ID wins;
/// unobserved IDs retain their previous state.
pub fn bm1396_update_fan_state(
    mut previous: Bm1396FanState,
    minimum_rpm: u32,
    readings: &[Bm1396FanTachReading],
) -> Result<Bm1396FanState, Bm1396FanSampleError> {
    if readings.len() > usize::from(BM1396_FAN_TACH_MAX_READINGS) {
        return Err(Bm1396FanSampleError::TooManyReadings {
            observed: readings.len(),
        });
    }
    for reading in readings {
        let fan_id = usize::from(reading.fan_id);
        if fan_id >= previous.passing.len() {
            return Err(Bm1396FanSampleError::InvalidFanId {
                observed: reading.fan_id,
            });
        }
        previous.passing[fan_id] = reading.rpm >= minimum_rpm;
    }
    Ok(previous)
}

/// Test one sampled fan population against the exact production threshold.
/// This convenience evaluates one sample from an all-bad initial state. The
/// production validator must carry [`Bm1396FanState`] across samples via
/// [`bm1396_update_fan_state`].
pub fn bm1396_fan_sample_passes(
    policy: Bm1396FanValidationPolicy,
    readings: &[Bm1396FanTachReading],
) -> bool {
    bm1396_update_fan_state(Bm1396FanState::default(), policy.minimum_rpm, readings)
        .map(|state| state.passing_count() >= policy.required_fan_count)
        .unwrap_or(false)
}

/// Decode one exact production tach register observation.
///
/// `tach_register` comes from FPGA offset `0x04`: count is low 8 bits and fan
/// id is bits 8..10. The low 16 bits of FPGA offset `0x00` select 120x or 240x
/// RPM scaling.
pub const fn bm1396_decode_fan_tach(
    fpga_hw_selector: u32,
    tach_register: u32,
) -> Bm1396FanTachReading {
    let raw_count = (tach_register & 0xff) as u8;
    let fan_id = ((tach_register >> 8) & 0x07) as u8;
    let scale = if fpga_hw_selector as u16 == BM1396_FAN_TACH_DOUBLE_RATE_HW_ID_LOW16 {
        BM1396_FAN_TACH_SPECIAL_RPM_PER_COUNT
    } else {
        BM1396_FAN_TACH_DEFAULT_RPM_PER_COUNT
    };
    Bm1396FanTachReading {
        fan_id,
        raw_count,
        rpm: raw_count as u32 * scale,
    }
}

/// Exact input classification used by the recovered production core-reopen
/// predicate. DCENT safety code must retain the distinct invalid state rather
/// than silently treating it as cool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396VendorThermalObservation {
    SensorInvalidTooLow,
    BelowConfiguredAlarm,
    AtOrAboveConfiguredAlarm,
}

pub const fn bm1396_vendor_thermal_observation(
    live_pcb_min_c: i16,
    live_chip_max_c: i16,
    configured_alarm_c: i16,
) -> Bm1396VendorThermalObservation {
    if live_pcb_min_c < BM1396_VENDOR_MIN_VALID_PCB_TEMP_C {
        Bm1396VendorThermalObservation::SensorInvalidTooLow
    } else if live_chip_max_c >= configured_alarm_c {
        Bm1396VendorThermalObservation::AtOrAboveConfiguredAlarm
    } else {
        Bm1396VendorThermalObservation::BelowConfiguredAlarm
    }
}

/// Exact boolean result of the signed-firmware `is_temp_reopen_core` function.
///
/// This establishes only reopen eligibility: PCB minimum must be valid and
/// chip maximum must be strictly below configured `Alarm_Temp`. It does not by
/// itself prove a shutdown action or immutable thermal limit.
pub const fn bm1396_vendor_can_reopen_core(
    live_pcb_min_c: i16,
    live_chip_max_c: i16,
    configured_alarm_c: i16,
) -> bool {
    live_pcb_min_c >= BM1396_VENDOR_MIN_VALID_PCB_TEMP_C && live_chip_max_c < configured_alarm_c
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396HardThermalMode {
    RuntimeStateFlagClear,
    RuntimeStateFlagSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396HardThermalLimits {
    pub pcb_max_c: i16,
    pub chip_max_c: i16,
}

pub const fn bm1396_hard_thermal_limits(mode: Bm1396HardThermalMode) -> Bm1396HardThermalLimits {
    match mode {
        Bm1396HardThermalMode::RuntimeStateFlagClear => Bm1396HardThermalLimits {
            pcb_max_c: BM1396_HARD_THERMAL_FLAG_CLEAR_PCB_MAX_C,
            chip_max_c: BM1396_HARD_THERMAL_FLAG_CLEAR_CHIP_MAX_C,
        },
        Bm1396HardThermalMode::RuntimeStateFlagSet => Bm1396HardThermalLimits {
            pcb_max_c: BM1396_HARD_THERMAL_FLAG_SET_PCB_MAX_C,
            chip_max_c: BM1396_HARD_THERMAL_FLAG_SET_CHIP_MAX_C,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396HardThermalDecision {
    Continue,
    FatalError(u8),
}

/// Exact 2020 signed S17e/T17e hard-temperature decision. The monitor loop
/// performs work and then ends with a 1000-ms tail delay; this helper therefore
/// does not claim a precise 1 Hz sampling interval. It is separate from
/// configured `Alarm_Temp` and the core-reopen predicate.
pub const fn bm1396_hard_thermal_decision(
    mode: Bm1396HardThermalMode,
    pcb_max_c: i16,
    chip_max_c: i16,
) -> Bm1396HardThermalDecision {
    let limits = bm1396_hard_thermal_limits(mode);
    if pcb_max_c > limits.pcb_max_c || chip_max_c > limits.chip_max_c {
        Bm1396HardThermalDecision::FatalError(BM1396_HARD_THERMAL_FATAL_ERROR_CODE)
    } else {
        Bm1396HardThermalDecision::Continue
    }
}

/// Exact 2019 S17e/T17e hard-thermal limits. The 2020 signed binaries retain
/// the absolute limits but no longer perform these positive-delta checks in
/// their hard monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396Legacy2019ThermalLimits {
    pub pcb_max_c: i16,
    pub chip_max_c: i16,
    pub pcb_positive_delta_max_c: i32,
    pub chip_positive_delta_max_c: i32,
}

pub const fn bm1396_legacy_2019_thermal_limits(
    mode: Bm1396HardThermalMode,
) -> Bm1396Legacy2019ThermalLimits {
    let absolute = bm1396_hard_thermal_limits(mode);
    match mode {
        Bm1396HardThermalMode::RuntimeStateFlagClear => Bm1396Legacy2019ThermalLimits {
            pcb_max_c: absolute.pcb_max_c,
            chip_max_c: absolute.chip_max_c,
            pcb_positive_delta_max_c: BM1396_LEGACY_2019_FLAG_CLEAR_PCB_DELTA_MAX_C,
            chip_positive_delta_max_c: BM1396_LEGACY_2019_FLAG_CLEAR_CHIP_DELTA_MAX_C,
        },
        Bm1396HardThermalMode::RuntimeStateFlagSet => Bm1396Legacy2019ThermalLimits {
            pcb_max_c: absolute.pcb_max_c,
            chip_max_c: absolute.chip_max_c,
            pcb_positive_delta_max_c: BM1396_LEGACY_2019_FLAG_SET_PCB_DELTA_MAX_C,
            chip_positive_delta_max_c: BM1396_LEGACY_2019_FLAG_SET_CHIP_DELTA_MAX_C,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396Legacy2019ThermalSample {
    pub pcb_c: i16,
    pub chip_c: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396Legacy2019ThermalStep {
    pub history: [Option<Bm1396Legacy2019ThermalSample>; BM1396_FPGA_CHAIN_SLOT_COUNT as usize],
    pub pcb_positive_delta_max_c: i32,
    pub chip_positive_delta_max_c: i32,
    pub decision: Bm1396HardThermalDecision,
}

/// Pure 2019 S17e/T17e thermal-monitor step (`CONFIRMED_MULTI_FIRMWARE`).
///
/// Active slots are `Some(sample)`. Inactive slots preserve their history.
/// First observations have zero rise. Cooling is ignored for the maximum
/// positive delta, while every active observation updates history even when
/// this step becomes fatal. Absolute maxima are supplied separately because
/// stock evaluates its global maxima even when no chain slot is active.
pub fn bm1396_legacy_2019_thermal_step(
    mode: Bm1396HardThermalMode,
    previous: [Option<Bm1396Legacy2019ThermalSample>; BM1396_FPGA_CHAIN_SLOT_COUNT as usize],
    current: [Option<Bm1396Legacy2019ThermalSample>; BM1396_FPGA_CHAIN_SLOT_COUNT as usize],
    observed_pcb_max_c: i16,
    observed_chip_max_c: i16,
) -> Bm1396Legacy2019ThermalStep {
    let mut history = previous;
    let mut pcb_positive_delta_max_c = 0i32;
    let mut chip_positive_delta_max_c = 0i32;

    for ((previous_slot, history_slot), current_slot) in
        previous.iter().zip(history.iter_mut()).zip(current.iter())
    {
        let Some(sample) = current_slot else {
            continue;
        };
        if let Some(previous_sample) = previous_slot {
            pcb_positive_delta_max_c = pcb_positive_delta_max_c
                .max((i32::from(sample.pcb_c) - i32::from(previous_sample.pcb_c)).max(0));
            chip_positive_delta_max_c = chip_positive_delta_max_c
                .max((i32::from(sample.chip_c) - i32::from(previous_sample.chip_c)).max(0));
        }
        *history_slot = Some(*sample);
    }

    let limits = bm1396_legacy_2019_thermal_limits(mode);
    let decision = if observed_pcb_max_c > limits.pcb_max_c
        || observed_chip_max_c > limits.chip_max_c
        || pcb_positive_delta_max_c > limits.pcb_positive_delta_max_c
        || chip_positive_delta_max_c > limits.chip_positive_delta_max_c
    {
        Bm1396HardThermalDecision::FatalError(BM1396_LEGACY_2019_THERMAL_FATAL_ERROR_CODE)
    } else {
        Bm1396HardThermalDecision::Continue
    };

    Bm1396Legacy2019ThermalStep {
        history,
        pcb_positive_delta_max_c,
        chip_positive_delta_max_c,
        decision,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396SensorInvalidAction {
    Continue,
    IsolateChainAndContinue,
    IsolateChainAndFatalError(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bm1396NoActiveChainForSensorDecision;

/// Recover the exact per-chain reaction when all four readings in either of
/// the two sensor channels are invalid. `true` means invalid. Normal runtime
/// escalates error 14 after isolation; the observed special mode continues
/// unless isolating the chain leaves no active chains.
pub fn bm1396_sensor_invalid_action(
    channel0_invalid: [bool; BM1396_SENSOR_POSITIONS_PER_CHAIN],
    channel1_invalid: [bool; BM1396_SENSOR_POSITIONS_PER_CHAIN],
    special_mode: bool,
    active_chain_count_before: u8,
) -> Result<Bm1396SensorInvalidAction, Bm1396NoActiveChainForSensorDecision> {
    if active_chain_count_before == 0 {
        return Err(Bm1396NoActiveChainForSensorDecision);
    }
    if !channel0_invalid.into_iter().all(|invalid| invalid)
        && !channel1_invalid.into_iter().all(|invalid| invalid)
    {
        return Ok(Bm1396SensorInvalidAction::Continue);
    }
    if special_mode && active_chain_count_before > 1 {
        Ok(Bm1396SensorInvalidAction::IsolateChainAndContinue)
    } else {
        Ok(Bm1396SensorInvalidAction::IsolateChainAndFatalError(
            BM1396_SENSOR_INVALID_FATAL_ERROR_CODE,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396SensorSamplingMode {
    Mode0,
    Mode1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396SensorAggregationFamily {
    FamilyA,
    Other,
}

/// Model-specific sensor chip-ordinal grouping used only for aggregation bins.
/// Exact signed topology constructors 4bb74/4c764 populate this discriminator;
/// it is not the sensor manufacturer ID read from register FE. It does not
/// select the channel-1 transform; that is the caller sampling mode.
pub const fn bm1396_sensor_aggregation_family(
    model: Bm1396Model,
    sensor_chip_ordinal: u8,
) -> Bm1396SensorAggregationFamily {
    let family_a = match model {
        Bm1396Model::S17e => sensor_chip_ordinal == 0x1b || sensor_chip_ordinal == 0x63,
        Bm1396Model::T17e => sensor_chip_ordinal == 0x11 || sensor_chip_ordinal == 0x41,
    };
    if family_a {
        Bm1396SensorAggregationFamily::FamilyA
    } else {
        Bm1396SensorAggregationFamily::Other
    }
}

/// Channel zero is the exact signed mathematical subtraction `raw - 0x40`.
pub const fn bm1396_sensor_channel0_temperature(raw: u8) -> i16 {
    raw as i16 - 0x40
}

/// Exact channel-one transform selected by the explicit caller sampling mode.
/// Both channels first subtract `0x40`; the ARM conversion then truncates
/// toward zero before the value is stored as i16.
pub fn bm1396_sensor_channel1_temperature(raw: u8, mode: Bm1396SensorSamplingMode) -> i16 {
    let x = f64::from(bm1396_sensor_channel0_temperature(raw));
    let (slope, offset) = match mode {
        Bm1396SensorSamplingMode::Mode0 => (
            f64::from_bits(BM1396_SENSOR_MODE0_SLOPE_F64_BITS),
            f64::from_bits(BM1396_SENSOR_MODE0_OFFSET_F64_BITS),
        ),
        Bm1396SensorSamplingMode::Mode1 => (
            f64::from_bits(BM1396_SENSOR_MODE1_SLOPE_F64_BITS),
            f64::from_bits(BM1396_SENSOR_MODE1_OFFSET_F64_BITS),
        ),
    };
    (x * slope - offset).trunc() as i16
}

/// Exact post-aggregation outlier predicate. Mean/variance are supplied because
/// stock computes them independently per sensor-family × channel bin, using
/// integer population variance, and does not recompute after marking outliers.
pub fn bm1396_sensor_sample_is_outlier(sample: i16, mean: i16, variance: i16) -> bool {
    if variance <= BM1396_SENSOR_OUTLIER_VARIANCE_THRESHOLD {
        return false;
    }
    let difference = i64::from(sample) - i64::from(mean);
    let squared_difference = difference * difference;
    (variance as f32) * f32::from_bits(BM1396_SENSOR_OUTLIER_MULTIPLIER_F32_BITS)
        < squared_difference as f32
}

/// Deterministic shutdown actions recovered from both exact signed miners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396ShutdownStep {
    DisableChainDcDc { slot: u8, opcode: u8, payload: u8 },
    EnsureGpioExported { gpio: u16 },
    SetGpioDirectionHigh { gpio: u16 },
    WriteGpioHigh { gpio: u16 },
    DelayMs(u32),
    ClearFpgaMainControlBits { offset: u32, clear_mask: u32 },
}

/// Plan exact shutdown order from the runtime active-slot bitmap.
pub fn plan_bm1396_shutdown(
    active_slots: &[bool; BM1396_FPGA_CHAIN_SLOT_COUNT as usize],
) -> Vec<Bm1396ShutdownStep> {
    let mut steps = Vec::new();
    for (slot, active) in active_slots.iter().copied().enumerate() {
        if active {
            steps.push(Bm1396ShutdownStep::DisableChainDcDc {
                slot: slot as u8,
                opcode: BM1396_DCDC_CONTROL_OPCODE,
                payload: BM1396_DCDC_DISABLE_PAYLOAD,
            });
        }
    }
    steps.extend([
        Bm1396ShutdownStep::EnsureGpioExported {
            gpio: BM1396_SHUTDOWN_GPIO,
        },
        Bm1396ShutdownStep::SetGpioDirectionHigh {
            gpio: BM1396_SHUTDOWN_GPIO,
        },
        Bm1396ShutdownStep::WriteGpioHigh {
            gpio: BM1396_SHUTDOWN_GPIO,
        },
        Bm1396ShutdownStep::DelayMs(BM1396_SHUTDOWN_GPIO_SETTLE_MS),
        Bm1396ShutdownStep::ClearFpgaMainControlBits {
            offset: BM1396_FPGA_MAIN_CONTROL_OFFSET,
            clear_mask: BM1396_FPGA_MAIN_CONTROL_RUN_BIT,
        },
    ]);
    steps
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396ChainWatchdogDecision {
    pub expected_responses: u16,
    pub observed_responses: u16,
    pub next_consecutive_mismatches: u8,
    pub disable_chain: bool,
}

/// Exact terminal behavior selected by the recovered stock error router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396VendorErrorAction {
    ReturnImmediately,
    LogAndReturn,
    GlobalPowerOffThenSleepForever,
    GlobalPowerOffThenAssert,
}

pub const fn bm1396_vendor_error_action(code: u8) -> Bm1396VendorErrorAction {
    match code {
        0..=2 => Bm1396VendorErrorAction::ReturnImmediately,
        3 | 4 | 5 | 6 | 8 | 10 | 12 | 14 | 15 | 16 | 18 => {
            Bm1396VendorErrorAction::GlobalPowerOffThenSleepForever
        }
        11 | 13 => Bm1396VendorErrorAction::GlobalPowerOffThenAssert,
        _ => Bm1396VendorErrorAction::LogAndReturn,
    }
}

/// Evaluate one active chain's recurring register-watchdog response count.
///
/// A match clears the counter. The 30th consecutive mismatch disables the
/// chain; the exact runtime does not attempt recovery or re-enumeration here.
pub const fn bm1396_chain_watchdog_decision(
    model: Bm1396Model,
    observed_responses: u16,
    previous_consecutive_mismatches: u8,
) -> Bm1396ChainWatchdogDecision {
    let expected_responses = model.expected_chips_per_present_chain();
    if observed_responses == expected_responses {
        return Bm1396ChainWatchdogDecision {
            expected_responses,
            observed_responses,
            next_consecutive_mismatches: 0,
            disable_chain: false,
        };
    }
    let next = previous_consecutive_mismatches.saturating_add(1);
    Bm1396ChainWatchdogDecision {
        expected_responses,
        observed_responses,
        next_consecutive_mismatches: next,
        disable_chain: next >= BM1396_CHAIN_WATCHDOG_DISABLE_AFTER_MISMATCHES,
    }
}

/// Apply the exact vendor software clamp to a requested board voltage.
///
/// This helper is deliberately named `vendor`, not `safety`: it records the
/// production firmware policy but does not promote 18–21 V to a certified
/// absolute hardware envelope.
pub const fn bm1396_vendor_working_voltage_clamp_cv(request_cv: u16) -> u16 {
    if request_cv < BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV {
        BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV
    } else if request_cv > BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV {
        BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV
    } else {
        request_cv
    }
}

/// T17e voltage request for the next short-count retry.
///
/// The exact production path adds 100 cV, wraps values above 2100 cV to
/// 1800 cV, and then passes the result through the same vendor clamp. S17e does
/// not apply this voltage change on a short-count retry.
pub const fn bm1396_t17e_next_retry_voltage_cv(current_cv: u16) -> u16 {
    let incremented = current_cv.saturating_add(BM1396_T17E_RETRY_VOLTAGE_STEP_CV);
    let wrapped = if incremented > BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV {
        BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV
    } else {
        incremented
    };
    bm1396_vendor_working_voltage_clamp_cv(wrapped)
}

/// Exact model binding for the two signed BM1396 production miners held in the
/// offline corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396Model {
    S17e,
    T17e,
}

impl Bm1396Model {
    /// Resolve only canonical board targets. Aliases belong at the BoardDesc
    /// boundary and must not silently enter the silicon contract.
    pub const fn from_board_target(board_target: &str) -> Option<Self> {
        match board_target.as_bytes() {
            b"am2-s17e" => Some(Self::S17e),
            b"am2-t17e" => Some(Self::T17e),
            _ => None,
        }
    }

    pub const fn expected_chips_per_present_chain(self) -> u16 {
        match self {
            Self::S17e => BM1396_S17E_CHIPS_PER_PRESENT_CHAIN,
            Self::T17e => BM1396_T17E_CHIPS_PER_PRESENT_CHAIN,
        }
    }

    pub const fn address_interval(self) -> u8 {
        match self {
            Self::S17e => BM1396_S17E_ADDRESS_INTERVAL,
            Self::T17e => BM1396_T17E_ADDRESS_INTERVAL,
        }
    }

    /// Resolve a dense runtime ordinal to the exact model-specific 8-bit wire
    /// address. Out-of-geometry ordinals are refused.
    pub const fn hardware_address(self, chip_ordinal: u16) -> Option<u8> {
        if chip_ordinal >= self.expected_chips_per_present_chain() {
            return None;
        }
        let address = chip_ordinal * self.address_interval() as u16;
        if address > u8::MAX as u16 {
            return None;
        }
        Some(address as u8)
    }

    /// Number of set-address commands emitted by the exact initializer:
    /// `floor(256 / interval)`. This can exceed the responding ASIC count and
    /// must not be confused with model geometry.
    pub const fn address_assignment_count(self) -> u16 {
        256 / self.address_interval() as u16
    }

    /// Address used by one initializer assignment command.
    pub const fn assignment_address(self, assignment_ordinal: u16) -> Option<u8> {
        if assignment_ordinal >= self.address_assignment_count() {
            return None;
        }
        Some((assignment_ordinal * self.address_interval() as u16) as u8)
    }
}

/// Why a signed-firmware BM1396 enumeration contract was not satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396EnumerationError {
    WrongChipId { observed: u16 },
    WrongPresentChainCount { expected: u16, observed: u16 },
}

impl std::fmt::Display for Bm1396EnumerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongChipId { observed } => write!(
                f,
                "BM1396 enumeration expected ChipID 0x{BM1396_WIRE_CHIP_ID:04x}, observed 0x{observed:04x}"
            ),
            Self::WrongPresentChainCount { expected, observed } => write!(
                f,
                "BM1396 present-chain enumeration expected {expected} ASICs, observed {observed}"
            ),
        }
    }
}

impl std::error::Error for Bm1396EnumerationError {}

/// Validated-value token showing that supplied enumeration values matched the
/// exact signed model contract. It is not bound to an observation issuer and
/// authorizes neither power nor work dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396EnumerationAdmission {
    model: Bm1396Model,
    chip_count: u16,
}

impl Bm1396EnumerationAdmission {
    pub const fn model(self) -> Bm1396Model {
        self.model
    }

    pub const fn chip_count(self) -> u16 {
        self.chip_count
    }
}

/// Validate the runtime values the exact signed production miners enforce for
/// one caller-selected present chain.
pub const fn admit_bm1396_present_chain_enumeration(
    model: Bm1396Model,
    observed_chip_id: u16,
    observed_chip_count: u16,
) -> Result<Bm1396EnumerationAdmission, Bm1396EnumerationError> {
    if observed_chip_id != BM1396_WIRE_CHIP_ID {
        return Err(Bm1396EnumerationError::WrongChipId {
            observed: observed_chip_id,
        });
    }
    let expected = model.expected_chips_per_present_chain();
    if observed_chip_count != expected {
        return Err(Bm1396EnumerationError::WrongPresentChainCount {
            expected,
            observed: observed_chip_count,
        });
    }
    Ok(Bm1396EnumerationAdmission {
        model,
        chip_count: observed_chip_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_routes_pin_exact_signed_model_geometry() {
        assert_eq!(
            Bm1396Model::from_board_target("am2-s17e"),
            Some(Bm1396Model::S17e)
        );
        assert_eq!(
            Bm1396Model::from_board_target("am2-t17e"),
            Some(Bm1396Model::T17e)
        );
        assert_eq!(Bm1396Model::S17e.expected_chips_per_present_chain(), 135);
        assert_eq!(Bm1396Model::T17e.expected_chips_per_present_chain(), 78);
        assert_eq!(Bm1396Model::S17e.address_interval(), 1);
        assert_eq!(Bm1396Model::T17e.address_interval(), 3);
        assert_eq!(Bm1396Model::S17e.hardware_address(134), Some(134));
        assert_eq!(Bm1396Model::S17e.hardware_address(135), None);
        assert_eq!(Bm1396Model::T17e.hardware_address(77), Some(231));
        assert_eq!(Bm1396Model::T17e.hardware_address(78), None);
        assert_eq!(Bm1396Model::S17e.address_assignment_count(), 256);
        assert_eq!(Bm1396Model::S17e.assignment_address(255), Some(255));
        assert_eq!(Bm1396Model::S17e.assignment_address(256), None);
        assert_eq!(Bm1396Model::T17e.address_assignment_count(), 85);
        assert_eq!(Bm1396Model::T17e.assignment_address(84), Some(252));
        assert_eq!(Bm1396Model::T17e.assignment_address(85), None);
        assert_eq!(Bm1396Model::from_board_target("s17e"), None);
        assert_eq!(Bm1396Model::from_board_target("am2-s17plus"), None);
    }

    #[test]
    fn enumeration_admission_is_exact_and_fail_closed() {
        let s17e = admit_bm1396_present_chain_enumeration(Bm1396Model::S17e, 0x1396, 135)
            .expect("exact signed S17e contract");
        assert_eq!(s17e.model(), Bm1396Model::S17e);
        assert_eq!(s17e.chip_count(), 135);

        let t17e = admit_bm1396_present_chain_enumeration(Bm1396Model::T17e, 0x1396, 78)
            .expect("exact signed T17e contract");
        assert_eq!(t17e.chip_count(), 78);

        assert_eq!(
            admit_bm1396_present_chain_enumeration(Bm1396Model::S17e, 0x1397, 135),
            Err(Bm1396EnumerationError::WrongChipId { observed: 0x1397 })
        );
        assert_eq!(
            admit_bm1396_present_chain_enumeration(Bm1396Model::S17e, 0x1396, 134),
            Err(Bm1396EnumerationError::WrongPresentChainCount {
                expected: 135,
                observed: 134,
            })
        );
        assert_eq!(
            admit_bm1396_present_chain_enumeration(Bm1396Model::T17e, 0x1396, 79),
            Err(Bm1396EnumerationError::WrongPresentChainCount {
                expected: 78,
                observed: 79,
            })
        );
    }

    #[test]
    fn vendor_retry_voltage_policy_is_exact() {
        assert_eq!(BM1396_FPGA_CHAIN_SLOT_COUNT, 16);
        assert_eq!(BM1396_ADDRESS_RESET_BURST_COUNT, 3);
        assert_eq!(BM1396_ADDRESS_COMMAND_SPACING_MS, 30);
        assert_eq!(bm1396_vendor_working_voltage_clamp_cv(1700), 1800);
        assert_eq!(bm1396_vendor_working_voltage_clamp_cv(1950), 1950);
        assert_eq!(bm1396_vendor_working_voltage_clamp_cv(2200), 2100);
        assert_eq!(bm1396_t17e_next_retry_voltage_cv(1800), 1900);
        assert_eq!(bm1396_t17e_next_retry_voltage_cv(2000), 2100);
        assert_eq!(bm1396_t17e_next_retry_voltage_cv(2100), 1800);
        assert_eq!(bm1396_t17e_next_retry_voltage_cv(u16::MAX), 1800);
    }

    #[test]
    fn exact_signed_command_frames_have_fixed_non_tautological_goldens() {
        assert_eq!(
            bm1396_read_register_frame(true, 0x00, 0x00),
            [0x52, 0x05, 0x00, 0x00, 0x0a]
        );
        assert_eq!(
            bm1396_read_register_frame(false, 0x2a, 0x18),
            [0x42, 0x05, 0x2a, 0x18, 0x1c]
        );
        assert_eq!(
            bm1396_write_register_frame(true, 0x00, 0x18, 0x1234_5678),
            [0x51, 0x09, 0x00, 0x18, 0x12, 0x34, 0x56, 0x78, 0x0a]
        );
        assert_eq!(
            bm1396_write_register_frame(false, 0x2a, 0x08, 0x4068_0221),
            [0x41, 0x09, 0x2a, 0x08, 0x40, 0x68, 0x02, 0x21, 0x03]
        );
        assert_eq!(bm1396_reset_address_frame(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(
            bm1396_set_address_frame(134),
            [0x40, 0x05, 0x86, 0x00, 0x12]
        );
        assert_eq!(
            bm1396_set_address_frame(231),
            [0x40, 0x05, 0xe7, 0x00, 0x0b]
        );
        assert_eq!(
            bm1396_set_address_frame(252),
            [0x40, 0x05, 0xfc, 0x00, 0x02]
        );
    }

    #[test]
    fn exact_signed_voltage_transport_frames_and_response_validation_are_pinned() {
        assert_eq!(BM1396_VOLTAGE_I2C_ADDRESS, 0x11);
        assert_eq!(BM1396_VOLTAGE_RESPONSE_WAIT_US, 500_000);
        assert_eq!(BM1396_VOLTAGE_TRANSPORT_MAX_ATTEMPTS, 3);
        assert_eq!(BM1396_VOLTAGE_DAC_RAMP_STEP_FIXED_X2, 35);
        assert_eq!(BM1396_VOLTAGE_DAC_RAMP_STEP, 17);
        assert_eq!(
            bm1396_voltage_request_frame(120),
            [0x55, 0xaa, 0x06, 0x83, 0x78, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            bm1396_voltage_request_frame(12),
            [0x55, 0xaa, 0x06, 0x83, 0x0c, 0x00, 0x95, 0x00]
        );
        assert_eq!(
            bm1396_validate_voltage_response(&[0x55, 0xaa, 0x06, 0x83, 0x78, 0x00, 0x01, 0x01]),
            Ok([0x78, 0x00])
        );
        assert_eq!(
            bm1396_validate_voltage_response(&[0x55, 0xaa, 0x06]),
            Err(Bm1396VoltageResponseError::WrongLength { observed: 3 })
        );
        assert_eq!(
            bm1396_validate_voltage_response(&[0x54, 0xaa, 0x06, 0x83, 0x78, 0x00, 0x01, 0x01]),
            Err(Bm1396VoltageResponseError::WrongEnvelope)
        );
        assert_eq!(
            bm1396_validate_voltage_response(&[0x55, 0xaa, 0x06, 0x83, 0x78, 0x00, 0x00, 0x01]),
            Err(Bm1396VoltageResponseError::ChecksumMismatch {
                expected: 0x0101,
                observed: 0x0100,
            })
        );
    }

    #[test]
    fn exact_signed_voltage_dac_conversion_is_exhaustively_equivalent_and_fail_closed() {
        let goldens = [
            (1800, 120),
            (1825, 111),
            (1850, 102),
            (1875, 93),
            (1900, 84),
            (1925, 75),
            (1950, 66),
            (1975, 57),
            (2000, 48),
            (2025, 39),
            (2050, 30),
            (2075, 21),
            (2100, 12),
        ];
        for (raw_cv, expected_dac) in goldens {
            assert_eq!(
                bm1396_voltage_dac_in_vendor_envelope(raw_cv),
                Ok(expected_dac),
                "raw voltage {raw_cv} cV"
            );
        }
        assert_eq!(
            bm1396_voltage_dac_in_vendor_envelope(1799),
            Err(Bm1396VoltageOutsideVendorEnvelope { requested_cv: 1799 })
        );
        assert_eq!(
            bm1396_voltage_dac_in_vendor_envelope(2101),
            Err(Bm1396VoltageOutsideVendorEnvelope { requested_cv: 2101 })
        );

        // Pin all admitted integer inputs against the exact IEEE-754 constants
        // recovered from both signed binaries, not against the integer helper's
        // own formula.
        let divisor = f64::from_bits(0x4059_0000_0000_0000);
        let slope = f64::from_bits(0x4041_eaaa_a7de_d6bb);
        let intercept = f64::from_bits(0x4087_eb4b_4aec_8d5c);
        for raw_cv in 1800u16..=2100 {
            let exact_binary_double = intercept - (raw_cv as f64 / divisor) * slope;
            let expected = exact_binary_double.trunc() as u8;
            assert_eq!(bm1396_voltage_dac_in_vendor_envelope(raw_cv), Ok(expected));
        }
    }

    #[test]
    fn exact_signed_voltage_dac_ramp_preserves_direction_remainder_and_single_write() {
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(1800, 2100),
            Ok(vec![103, 86, 69, 52, 35, 18, 12])
        );
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(2100, 1800),
            Ok(vec![29, 46, 63, 80, 97, 114, 120])
        );
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(1800, 1900),
            Ok(vec![103, 86, 84])
        );
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(1950, 1950),
            Ok(vec![66])
        );
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(1700, 1900),
            Err(Bm1396VoltageOutsideVendorEnvelope { requested_cv: 1700 })
        );
        assert_eq!(
            plan_bm1396_vendor_voltage_dac_ramp(1900, 2200),
            Err(Bm1396VoltageOutsideVendorEnvelope { requested_cv: 2200 })
        );
    }

    #[test]
    fn quiet30_uses_four_spinning_fans_without_importing_stock_full_pwm_startup() {
        let policy = bm1396_quiet_fan_validation_policy();
        assert_eq!(BM1396_STOCK_STARTUP_FAN_PWM_PERCENT, 100);
        assert_eq!(BM1396_QUIET_FAN_PWM_PERCENT, 30);
        assert_eq!(
            policy,
            bm1396_fan_validation_policy(Bm1396FanValidationPhase::Runtime)
        );
        assert_eq!(policy.minimum_rpm, 400);
        let readings: Vec<_> = (0..8)
            .map(|index| bm1396_decode_fan_tach(0, ((index % 4) << 8) | 4))
            .collect();
        assert!(readings.iter().all(|reading| reading.rpm == 480));
        assert!(bm1396_fan_sample_passes(policy, &readings));
        assert!(!bm1396_fan_sample_passes(
            bm1396_fan_validation_policy(Bm1396FanValidationPhase::Startup),
            &readings
        ));
        let stopped: Vec<_> = (0..8)
            .map(|index| bm1396_decode_fan_tach(0, ((index % 4) << 8) | 3))
            .collect();
        assert!(!bm1396_fan_sample_passes(policy, &stopped));
        let repeated = vec![bm1396_decode_fan_tach(0, 40); 8];
        assert!(!bm1396_fan_sample_passes(policy, &repeated));
    }

    #[test]
    fn exact_signed_fan_policies_keep_startup_and_runtime_thresholds_distinct() {
        let startup = bm1396_fan_validation_policy(Bm1396FanValidationPhase::Startup);
        assert_eq!(startup.minimum_rpm, 4_000);
        assert_eq!(startup.required_fan_count, 4);
        assert_eq!(startup.maximum_samples, 10);
        assert_eq!(startup.bad_sample_delay_call_value, 2_000);
        assert!(startup.fatal_on_exhaustion);
        let reading = |fan_id, rpm| Bm1396FanTachReading {
            fan_id,
            raw_count: 0,
            rpm,
        };
        assert!(bm1396_fan_sample_passes(
            startup,
            &[
                reading(0, 4_000),
                reading(1, 4_100),
                reading(2, 4_200),
                reading(3, 4_300),
            ]
        ));
        assert!(!bm1396_fan_sample_passes(
            startup,
            &[
                reading(0, 4_000),
                reading(1, 4_100),
                reading(2, 4_200),
                reading(3, 3_999),
            ]
        ));
        let runtime = bm1396_fan_validation_policy(Bm1396FanValidationPhase::Runtime);
        let high_then_low = bm1396_update_fan_state(
            Bm1396FanState::default(),
            runtime.minimum_rpm,
            &[reading(0, 500), reading(0, 399)],
        )
        .unwrap();
        assert_eq!(high_then_low.passing_count(), 0);
        let low_then_high = bm1396_update_fan_state(
            Bm1396FanState::default(),
            runtime.minimum_rpm,
            &[reading(0, 399), reading(0, 500)],
        )
        .unwrap();
        assert_eq!(low_then_high.passing_count(), 1);
        let persistent =
            bm1396_update_fan_state(low_then_high, runtime.minimum_rpm, &[reading(1, 500)])
                .unwrap();
        assert_eq!(
            persistent.passing(),
            [true, true, false, false, false, false, false, false]
        );
        assert!(matches!(
            bm1396_update_fan_state(
                Bm1396FanState::default(),
                runtime.minimum_rpm,
                &[reading(8, 500)]
            ),
            Err(Bm1396FanSampleError::InvalidFanId { observed: 8 })
        ));
        assert!(matches!(
            bm1396_update_fan_state(
                Bm1396FanState::default(),
                runtime.minimum_rpm,
                &[reading(0, 500); 9]
            ),
            Err(Bm1396FanSampleError::TooManyReadings { observed: 9 })
        ));
        assert_eq!(runtime.minimum_rpm, 400);
        assert_eq!(runtime.bad_sample_delay_call_value, 50);
        assert!(bm1396_fan_sample_passes(
            runtime,
            &[
                reading(0, 400),
                reading(1, 401),
                reading(2, 402),
                reading(3, 403),
            ]
        ));
        assert!(!bm1396_fan_sample_passes(
            runtime,
            &[
                reading(0, 400),
                reading(0, 401),
                reading(0, 402),
                reading(0, 403),
            ]
        ));
        assert_eq!(BM1396_FAN_TACH_MAX_READINGS, 8);

        assert_eq!(
            bm1396_decode_fan_tach(0x0000_0000, 0xffff_0520),
            Bm1396FanTachReading {
                fan_id: 5,
                raw_count: 0x20,
                rpm: 0x20 * 120,
            }
        );
        assert_eq!(
            bm1396_decode_fan_tach(0x1234_b025, 0x0000_07ff),
            Bm1396FanTachReading {
                fan_id: 7,
                raw_count: 0xff,
                rpm: 0xff * 240,
            }
        );
        assert_eq!(
            bm1396_decode_fan_tach(0xffff_b025, 0x0000_0001).rpm,
            240,
            "upper selector bits are ignored by the signed-i16 compare"
        );
    }

    #[test]
    fn exact_signed_thermal_predicate_preserves_invalid_sensor_state() {
        assert_eq!(
            bm1396_vendor_thermal_observation(15, 80, 90),
            Bm1396VendorThermalObservation::SensorInvalidTooLow
        );
        assert_eq!(
            bm1396_vendor_thermal_observation(16, 89, 90),
            Bm1396VendorThermalObservation::BelowConfiguredAlarm
        );
        assert_eq!(
            bm1396_vendor_thermal_observation(16, 90, 90),
            Bm1396VendorThermalObservation::AtOrAboveConfiguredAlarm
        );
        assert_eq!(
            bm1396_vendor_thermal_observation(100, 91, 90),
            Bm1396VendorThermalObservation::AtOrAboveConfiguredAlarm
        );
        assert_eq!(
            bm1396_vendor_thermal_observation(15, 100, 90),
            Bm1396VendorThermalObservation::SensorInvalidTooLow,
            "invalid PCB minimum dominates a hot chip observation in the exact predicate"
        );
        assert!(!bm1396_vendor_can_reopen_core(15, 80, 90));
        assert!(bm1396_vendor_can_reopen_core(16, 89, 90));
        assert!(!bm1396_vendor_can_reopen_core(16, 90, 90));
        assert!(!bm1396_vendor_can_reopen_core(16, 91, 90));
    }

    #[test]
    fn hard_thermal_monitor_and_all_position_sensor_failure_are_exact() {
        assert_eq!(
            bm1396_hard_thermal_limits(Bm1396HardThermalMode::RuntimeStateFlagClear),
            Bm1396HardThermalLimits {
                pcb_max_c: 85,
                chip_max_c: 98,
            }
        );
        assert_eq!(
            bm1396_hard_thermal_decision(Bm1396HardThermalMode::RuntimeStateFlagClear, 85, 98,),
            Bm1396HardThermalDecision::Continue,
            "the exact comparisons are strict greater-than"
        );
        assert_eq!(
            bm1396_hard_thermal_decision(Bm1396HardThermalMode::RuntimeStateFlagClear, 86, 0,),
            Bm1396HardThermalDecision::FatalError(15)
        );
        assert_eq!(
            bm1396_hard_thermal_decision(Bm1396HardThermalMode::RuntimeStateFlagSet, 80, 96,),
            Bm1396HardThermalDecision::FatalError(15)
        );

        let all_invalid = [true; BM1396_SENSOR_POSITIONS_PER_CHAIN];
        let one_valid = [true, true, true, false];
        assert_eq!(
            bm1396_sensor_invalid_action(all_invalid, one_valid, false, 3),
            Ok(Bm1396SensorInvalidAction::IsolateChainAndFatalError(14))
        );
        assert_eq!(
            bm1396_sensor_invalid_action(one_valid, one_valid, false, 3),
            Ok(Bm1396SensorInvalidAction::Continue)
        );
        assert_eq!(
            bm1396_sensor_invalid_action(all_invalid, one_valid, true, 3),
            Ok(Bm1396SensorInvalidAction::IsolateChainAndContinue)
        );
        assert_eq!(
            bm1396_sensor_invalid_action(all_invalid, one_valid, true, 1),
            Ok(Bm1396SensorInvalidAction::IsolateChainAndFatalError(14))
        );
        assert_eq!(
            bm1396_sensor_invalid_action(all_invalid, one_valid, true, 0),
            Err(Bm1396NoActiveChainForSensorDecision)
        );

        let transform_goldens = [
            (0, -64, -73, -64),
            (64, 0, -11, -8),
            (128, 64, 50, 47),
            (255, 191, 174, 158),
        ];
        for (raw, channel0, mode0, mode1) in transform_goldens {
            assert_eq!(bm1396_sensor_channel0_temperature(raw), channel0);
            assert_eq!(
                bm1396_sensor_channel1_temperature(raw, Bm1396SensorSamplingMode::Mode0),
                mode0
            );
            assert_eq!(
                bm1396_sensor_channel1_temperature(raw, Bm1396SensorSamplingMode::Mode1),
                mode1
            );
        }
        assert_eq!(
            bm1396_sensor_aggregation_family(Bm1396Model::S17e, 0x1b),
            Bm1396SensorAggregationFamily::FamilyA
        );
        assert_eq!(
            bm1396_sensor_aggregation_family(Bm1396Model::T17e, 0x1b),
            Bm1396SensorAggregationFamily::Other
        );
        assert!(!bm1396_sensor_sample_is_outlier(100, 0, 100));
        assert!(bm1396_sensor_sample_is_outlier(100, 0, 101));
    }

    #[test]
    fn legacy_2019_rate_of_rise_limits_keep_release_scope_and_boundaries_exact() {
        assert_eq!(
            bm1396_legacy_2019_thermal_limits(Bm1396HardThermalMode::RuntimeStateFlagClear),
            Bm1396Legacy2019ThermalLimits {
                pcb_max_c: 85,
                chip_max_c: 98,
                pcb_positive_delta_max_c: 13,
                chip_positive_delta_max_c: 15,
            }
        );
        assert_eq!(
            bm1396_legacy_2019_thermal_limits(Bm1396HardThermalMode::RuntimeStateFlagSet),
            Bm1396Legacy2019ThermalLimits {
                pcb_max_c: 80,
                chip_max_c: 95,
                pcb_positive_delta_max_c: 8,
                chip_positive_delta_max_c: 10,
            }
        );

        for (mode, pcb_delta, chip_delta, pcb_max, chip_max) in [
            (Bm1396HardThermalMode::RuntimeStateFlagClear, 13, 15, 85, 98),
            (Bm1396HardThermalMode::RuntimeStateFlagSet, 8, 10, 80, 95),
        ] {
            let mut previous = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
            let mut current = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
            previous[0] = Some(Bm1396Legacy2019ThermalSample {
                pcb_c: 0,
                chip_c: 0,
            });
            current[0] = Some(Bm1396Legacy2019ThermalSample {
                pcb_c: pcb_delta,
                chip_c: chip_delta,
            });
            assert_eq!(
                bm1396_legacy_2019_thermal_step(mode, previous, current, pcb_max, chip_max)
                    .decision,
                Bm1396HardThermalDecision::Continue,
                "all four equality boundaries remain admitted"
            );
        }
    }

    #[test]
    fn legacy_2019_rate_of_rise_step_is_positive_only_stateful_and_fatal14() {
        let mut previous = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
        let mut current = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
        previous[0] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 70,
            chip_c: 80,
        });
        current[0] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 60,
            chip_c: 70,
        });
        previous[1] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 40,
            chip_c: 50,
        });
        current[1] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 50,
            chip_c: 55,
        });
        previous[2] = None;
        current[2] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 120,
            chip_c: 120,
        });
        previous[3] = Some(Bm1396Legacy2019ThermalSample {
            pcb_c: 33,
            chip_c: 44,
        });

        let step = bm1396_legacy_2019_thermal_step(
            Bm1396HardThermalMode::RuntimeStateFlagClear,
            previous,
            current,
            80,
            90,
        );
        assert_eq!(step.pcb_positive_delta_max_c, 10);
        assert_eq!(step.chip_positive_delta_max_c, 5);
        assert_eq!(step.decision, Bm1396HardThermalDecision::Continue);
        assert_eq!(step.history[0], current[0], "cooling still updates history");
        assert_eq!(
            step.history[2], current[2],
            "first observation has zero rise"
        );
        assert_eq!(
            step.history[3], previous[3],
            "inactive history is preserved"
        );

        for (pcb_delta, chip_delta) in [(14, 0), (0, 16)] {
            let mut before = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
            let mut after = [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
            before[0] = Some(Bm1396Legacy2019ThermalSample {
                pcb_c: 0,
                chip_c: 0,
            });
            after[0] = Some(Bm1396Legacy2019ThermalSample {
                pcb_c: pcb_delta,
                chip_c: chip_delta,
            });
            let fatal = bm1396_legacy_2019_thermal_step(
                Bm1396HardThermalMode::RuntimeStateFlagClear,
                before,
                after,
                0,
                0,
            );
            assert_eq!(fatal.decision, Bm1396HardThermalDecision::FatalError(14));
            assert_eq!(
                fatal.history[0], after[0],
                "fatal pass still updates history"
            );
        }

        let no_active = bm1396_legacy_2019_thermal_step(
            Bm1396HardThermalMode::RuntimeStateFlagClear,
            previous,
            [None; BM1396_FPGA_CHAIN_SLOT_COUNT as usize],
            86,
            0,
        );
        assert_eq!(no_active.pcb_positive_delta_max_c, 0);
        assert_eq!(
            no_active.decision,
            Bm1396HardThermalDecision::FatalError(14),
            "global absolute maxima are still evaluated with no active samples"
        );
    }

    #[test]
    fn exact_signed_baud_selector_and_divisor_plans_are_pinned_and_fail_closed() {
        let goldens = [
            (115_200, 26, false, 0x1a, 0x1a1a_1a1a),
            (1_500_000, 1, false, 0x01, 0x0101_0101),
            (3_000_000, 0, false, 0x00, 0x0000_0000),
            (6_000_000, 7, true, 0x03, 0x0303_0303),
            (12_000_000, 3, true, 0x04, 0x0404_0404),
            (25_000_000, 1, true, 0x05, 0x0505_0505),
        ];
        for (baud, bt8d, high_speed_clock, selector, fpga_register) in goldens {
            let plan = bm1396_baud_plan(baud, 0, 0).expect("exact signed baud mapping");
            assert_eq!(plan.baud, baud);
            assert_eq!(plan.bt8d, bt8d);
            assert_eq!(plan.high_speed_clock, high_speed_clock);
            assert_eq!(plan.fpga_selector, selector);
            assert_eq!(plan.fpga_register_value, fpga_register);
        }
        assert_eq!(
            bm1396_baud_plan(115_200, 0, 0)
                .expect("low-clock misc control")
                .misc_control_register_value,
            0x0000_1a00
        );
        assert_eq!(
            bm1396_baud_plan(6_000_000, 0, 0)
                .expect("high-clock misc control")
                .misc_control_register_value,
            0x0001_0700
        );
        assert_eq!(
            bm1396_baud_plan(3_000_000, u32::MAX, 0)
                .expect("low-clock exact preserve mask")
                .misc_control_register_value,
            0xf0fe_e0ff
        );
        assert_eq!(
            bm1396_baud_plan(6_000_000, u32::MAX, 0)
                .expect("high-clock exact preserve mask")
                .misc_control_register_value,
            0xf0ff_e7ff
        );
        assert_eq!(BM1396_ASIC_MISC_CONTROL_REGISTER, 0x18);
        assert_eq!(BM1396_FPGA_BAUD_REGISTER_OFFSET, 0x3c);
        assert_eq!(BM1396_BAUD_SWITCH_DELAY_CALL_VALUE, 50_000);
        assert_eq!(
            BM1396_HIGH_BAUD_CLOCK_PRELUDE,
            [
                (0x68, 0x4070_0111),
                (0x68, 0x4070_0111),
                (0x28, 0x0600_000f),
            ]
        );
        assert_eq!(
            bm1396_baud_plan(3_000_000, 0, u32::MAX)
                .expect("preserved FPGA lanes")
                .fpga_register_value,
            BM1396_FPGA_BAUD_PRESERVE_MASK
        );
        for baud in [0, 115_201, 3_125_000, 10_000_000, u32::MAX] {
            assert_eq!(
                bm1396_baud_plan(baud, 0, 0),
                Err(Bm1396UnsupportedBaud { baud })
            );
        }
    }

    #[test]
    fn deterministic_shutdown_disables_active_chains_before_board_and_fpga_off() {
        let mut active = [false; BM1396_FPGA_CHAIN_SLOT_COUNT as usize];
        active[0] = true;
        active[3] = true;
        assert_eq!(
            plan_bm1396_shutdown(&active),
            vec![
                Bm1396ShutdownStep::DisableChainDcDc {
                    slot: 0,
                    opcode: 0x15,
                    payload: 0,
                },
                Bm1396ShutdownStep::DisableChainDcDc {
                    slot: 3,
                    opcode: 0x15,
                    payload: 0,
                },
                Bm1396ShutdownStep::EnsureGpioExported { gpio: 907 },
                Bm1396ShutdownStep::SetGpioDirectionHigh { gpio: 907 },
                Bm1396ShutdownStep::WriteGpioHigh { gpio: 907 },
                Bm1396ShutdownStep::DelayMs(1_000),
                Bm1396ShutdownStep::ClearFpgaMainControlBits {
                    offset: 0x100,
                    clear_mask: 0x40,
                },
            ]
        );
    }

    #[test]
    fn runtime_chain_watchdog_resets_on_match_and_disables_on_thirtieth_mismatch() {
        assert_eq!(
            bm1396_chain_watchdog_decision(Bm1396Model::S17e, 135, 29),
            Bm1396ChainWatchdogDecision {
                expected_responses: 135,
                observed_responses: 135,
                next_consecutive_mismatches: 0,
                disable_chain: false,
            }
        );
        assert_eq!(
            bm1396_chain_watchdog_decision(Bm1396Model::T17e, 77, 28),
            Bm1396ChainWatchdogDecision {
                expected_responses: 78,
                observed_responses: 77,
                next_consecutive_mismatches: 29,
                disable_chain: false,
            }
        );
        assert_eq!(
            bm1396_chain_watchdog_decision(Bm1396Model::T17e, 77, 29),
            Bm1396ChainWatchdogDecision {
                expected_responses: 78,
                observed_responses: 77,
                next_consecutive_mismatches: 30,
                disable_chain: true,
            }
        );
        assert_eq!(BM1396_CHAIN_WATCHDOG_TRIGGER_DELAY_CALL_VALUES, [100, 300]);
        assert_eq!(
            BM1396_CHAIN_WATCHDOG_INTER_PHASE_DELAY_CALL_VALUES,
            [100, 1_500]
        );
    }

    #[test]
    fn exact_stock_error_router_keeps_pic_lost_nonfatal_and_pins_terminal_masks() {
        for code in 0..=2 {
            assert_eq!(
                bm1396_vendor_error_action(code),
                Bm1396VendorErrorAction::ReturnImmediately
            );
        }
        for code in [3, 4, 5, 6, 8, 10, 12, 14, 15, 16, 18] {
            assert_eq!(
                bm1396_vendor_error_action(code),
                Bm1396VendorErrorAction::GlobalPowerOffThenSleepForever,
                "code {code}"
            );
        }
        for code in [11, 13] {
            assert_eq!(
                bm1396_vendor_error_action(code),
                Bm1396VendorErrorAction::GlobalPowerOffThenAssert
            );
        }
        assert_eq!(
            bm1396_vendor_error_action(7),
            Bm1396VendorErrorAction::LogAndReturn,
            "PIC_LOST is handled by per-chain caller state, not global power-off"
        );
    }
}
