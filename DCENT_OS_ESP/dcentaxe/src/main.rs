#![recursion_limit = "512"]
#[cfg(all(
    feature = "lora",
    any(feature = "pins-hammer-bc", feature = "pins-hammer-dc")
))]
compile_error!(
    "Hammer SKUs cannot enable LoRa: GPIO6/7/8/15 collide with the ST7789/panel-power nets"
);
#[cfg(all(
    feature = "eth-w5500",
    any(feature = "pins-hammer-bc", feature = "pins-hammer-dc")
))]
compile_error!(
    "Hammer SKUs cannot enable the BAP W5500 add-on: GPIO39/40/41/42 are ST7789 data lines"
);
// The BitForge Nano's status LED is GPIO9, which is also the LoRa SX1262 RXEN.
// Unlike the two guards above — which describe boards that merely SHOULD NOT
// enable a radio — this one is what makes the `cfg(not(lora))` on the
// `(1, -1, 9)` GPIO-binder arm safe. That arm is gated out of LoRa builds
// because the binder `match` is on runtime values and therefore compiles every
// arm into every image, so an ungated arm moved `gpio9` a second time and broke
// the build of every `--features lora` image on every board. Without this
// guard, gating the arm would instead let a `bitforge-nano,lora` image compile
// and then fall through to the binder's `panic!` at boot (panic=abort => boot
// loop). Refuse the pairing at build time instead: on this board the collision
// is real hardware, not a compilation artifact.
#[cfg(all(feature = "bitforge-nano", feature = "lora"))]
compile_error!(
    "bitforge-nano cannot enable LoRa: its status LED is GPIO9, which is the \
     SX1262 RXEN line — the two cannot share the pin"
);
// A board whose thermal sensor sits behind an I2C bus multiplexer has NO
// reachable temperature source without the mux driver, so
// `select_thermal_mux_channel` falls back to a hard refusal and the board can
// never mine. That is the correct fail-closed behaviour, but it would be a
// silent, image-only regression — nothing in the host gate can observe which
// side of the cfg was compiled. Catch it at build time instead.
#[cfg(all(feature = "bitforge-nano", not(feature = "i2c-mux-pca9544")))]
compile_error!(
    "bitforge-nano must enable i2c-mux-pca9544: its two EMC2101s are reachable \
     only through the PCA9544A, so without the driver the board has no trusted \
     temperature and mining stays disabled"
);
// The TMP451 diode mux claims TWO GPIOs for its select lines, and on the Nerd
// boards that declare one, A0 is GPIO2 — the SX1262 TXEN line. The LoRa bus
// takes `gpio2` unconditionally near the top of `main`, so enabling both would
// move it twice. This is the same trap that broke every `--features lora`
// image (see the `bitforge-nano` guard above), and it is caught here rather
// than as a bare E0382 hundreds of lines away.
//
// Unlike the LED collision above there is no cfg-gated fallback arm to write:
// a board cannot read half its dies. The pairing is simply refused.
#[cfg(all(feature = "temp-tmp451", feature = "lora"))]
compile_error!(
    "temp-tmp451 cannot be combined with lora: the TMP451 mux select line A0 is \
     GPIO2, which is the SX1262 TXEN line — the two cannot share the pin"
);
// The plug-sense binder moves `gpio12` inside a RUNTIME match arm, which
// compiles into every `pins-bitaxe` image regardless of which board is running.
// GPIO12 is also the TMP451 mux A1 line, so the two feature sets cannot
// coexist. No board in the registry selects both (every muxed board is
// `pins-nerd`), and this guard is what keeps that true.
#[cfg(all(feature = "temp-tmp451", feature = "pins-bitaxe"))]
compile_error!(
    "temp-tmp451 cannot be combined with pins-bitaxe: the TMP451 mux select \
     line A1 is GPIO12, which the pins-bitaxe plug-sense binder already claims"
);
// Hammer DC02 binds ASIC reset on GPIO3. NerdQX TMP451 mux A1 is also GPIO3.
// The GPIO binder `match` compiles every arm into every image, so a combined
// image would move gpio3 twice (E0382). Refuse the pairing: no SKU is both.
#[cfg(all(feature = "temp-tmp451", feature = "pins-hammer-dc"))]
compile_error!(
    "temp-tmp451 cannot be combined with pins-hammer-dc: NerdQX mux A1 is \
     GPIO3, which Hammer DC02 already binds as ASIC reset"
);
// NerdQX mux A1 is GPIO3; NerdOCTAXE-γ mux A1 is GPIO12. Both also take GPIO2
// as A0, so two mux arms in one image is a static gpio2 double-move.
#[cfg(all(feature = "nerdqx", feature = "nerdoctaxe-gamma"))]
compile_error!(
    "nerdqx and nerdoctaxe-gamma cannot share an image: TMP451 mux A1 is \
     GPIO3 vs GPIO12 (and both arms would move GPIO2)"
);
// DCENT_axe — Clean-room BitAxe mining firmware
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
// Boot flow:
//   1. Check NVS for saved config
//   2. If no config → start WiFi AP captive portal (setup mode)
//   3. If config exists → connect to WiFi → init hardware → start HTTP server → mine
//   4. If WiFi fails → reboot + retry (3x max, then clear config → setup mode)

mod api;
mod api_system_info;
mod auth;
mod autotuner;
mod bridge;
mod capabilities;
mod cgminer_tcp;
mod chip_profiles_bitaxe;
mod config;
mod dashboard;
mod derived_metrics;
// W5500 SPI-Ethernet "DCENT LAN Mod" (PLAN-E Phase 1). DEFAULT-OFF — compiled
// only when a board opts into the `eth-w5500` feature (byte-identical image
// otherwise). `eth_w5500` is the esp-idf `esp_eth` bring-up seam; `net` is the
// pure Wi-Fi⇄Ethernet failover FSM (host-tested via the dcentaxe-core
// re-include). Activation is fail-closed through the existing
// `AccessoryMode::W5500Lan` guard (LAN xor BAP-Touch — shared GPIO39/40).
#[cfg(feature = "eth-w5500")]
mod eth_w5500;
#[cfg(feature = "eth-w5500")]
mod net;
// On-board SX1262 LoRa radio task + $DCM mesh integration. DEFAULT-OFF — compiled
// only when a board opts into the `lora` feature (byte-identical image otherwise).
#[cfg(feature = "lora")]
mod lora_task;
mod mcp;
#[cfg(feature = "lora")]
mod mesh_solo_runtime;
mod metrics_render;
mod mqtt;
mod mqtt_ha;
mod notifications;
mod nvs_config;
mod ota_signature;
mod power_measurement;
mod provisioning;
mod self_test;
mod shared;
mod swarm;
mod thermal_safety;
mod wifi;

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::gpio;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::uart::{config::Config as UartConfig, UartDriver};
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpServer};
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::sys;
use log::*;

use dcentaxe_asic::{AsicResult, SerialPort};
use dcentaxe_hal::display::Ssd1306Display;
// P1-O4: `fit_line`, `resolve_rung` and `TEXT_COLUMNS` are consumed only by
// the carousel, which is `display-ssd1306`-gated; `MiningRung` still feeds
// the four boot/init screens on every board. Both `use` lines below are
// pinned VERBATIM by `oled_truth_ladder_guards` / `oled_truth_ladder_r2_guards`,
// so the headless-unused half is silenced here rather than split out.
#[cfg_attr(feature = "display-none", allow(unused_imports))]
use dcentaxe_hal::display_convert::{fit_line, resolve_rung, MiningRung, TEXT_COLUMNS};
// P1-O2 round 2: a SECOND use line on purpose. The dcentaxe-core source
// contract pins the line above verbatim (it is how the host gate proves this
// espidf-only file imports the shared resolver at all), so round 2's two
// bounded composers arrive beside it rather than inside it.
#[cfg_attr(feature = "display-none", allow(unused_imports))]
use dcentaxe_hal::display_convert::{rung_decoration, rung_status_line};
#[cfg(feature = "display-ssd1306")]
use dcentaxe_hal::display_convert::halving_progress;
// P1-O1: the fail-closed reason CODES and the bounded rows that carry
// them. Same host-pure split, and pinned by a dcentaxe-core source
// contract for the same reason: this file can never be host-compiled, so
// a sentence composed here could not be measured against the panel.
use dcentaxe_hal::block_reason::{blocked_screen, code_line, ip_row, BlockReason};
use dcentaxe_hal::emc2103::Emc2103;
use dcentaxe_hal::emc2302::Emc2302;
use dcentaxe_hal::gpio::GpioController;
use dcentaxe_hal::i2c::I2cBus;
use dcentaxe_hal::power::{PowerError, PowerManager};
// HALPWR-2 / COMP-6: gate each per-field power telemetry read so a NaN sub-read
// (power.rs get_telemetry now returns f32::NAN per failed field) HOLDS the
// last-good value instead of poisoning mean_power_w in the autotuner window.
use dcentaxe_hal::safety::{
    ina260_oc_over_envelope, ina260_oc_should_cut, ina260_oc_strike_next, power_field_available,
};
use dcentaxe_hal::temp::{Emc2101, Tmp1075};
use dcentaxe_mining::dispatcher::{DispatcherConfig, MiningDispatcher, PoolSlot};
use dcentaxe_stratum::client::StratumClient;
#[cfg(feature = "display-ssd1306")]
use dcentaxe_stratum::solo::ChainId;
use dcentaxe_stratum::types::{MiningEvent, StratumEvent, StratumProtocol};

use autotuner::Autotuner;
use config::{ControlSurface, DcentAxeConfig};
use shared::{stratum_status_snapshots, SharedState};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Columns available to the companion page's activity word.
///
/// P1-O2: the pet-room layout draws it with `draw_text(22, 25, ...)` and
/// puts the wattage at x = 90, so (90 - 22) / 6 = 11 characters. The
/// full-pet layout starts at x = 36 and has 15, but one budget for both
/// slots means the word cannot change width when the layout flips.
#[cfg(feature = "display-ssd1306")]
const PET_ACTIVITY_COLUMNS: usize = 11;

const EMERGENCY_TEMP_C: f32 = 105.0;
const WARNING_TEMP_C: f32 = 90.0;

// ── ES-2: die-sensor-blindness confirm window (fail-closed) ─────────────────
// When a die-equipped board loses EVERY ASIC-die reading while only cooler
// proxies remain (`thermal_safety::evaluate_thermal` → `die_reading_blind`),
// `max_temp` is proxy-derived and understates the true die temp, so the
// overtemp cut could fire late or never. The supervisor forces the fan to 100%
// immediately (immediate airflow is the only safe response when the die is
// unmeasurable) and cuts ASIC power after this many CONSECUTIVE die-blind ticks.
// The debounce (~3 × 5 s = 15 s) rejects a single transient I2C read glitch,
// matching the fan-stall (3-tick) and I2C-dead (3-tick) guards; the proxy-based
// thermal ladder still runs each of those ticks. Fail-safe direction only.
const DIE_BLIND_CONFIRM_TICKS: u32 = 3;

// ── INA260 over-current/over-power backstop (DS4432U boards) ────────────────
// DS4432U boards (Max / Ultra / Supra) have no PMBus
// STATUS_WORD over-current detection — `PowerManager::check_fault` is a no-op
// (R-10 note: DCENT_axe BM1397 is NOT a DS4432U board — it carries a TPS546
// PMBus VRM, EN on GPIO10 active-high, and no INA260 — so it takes the TPS546
// fault path, not this backstop.)
// for them — so the INA260 input-rail monitor is the only software OC guard.
// When measured input power/current stays above the board's rated PowerLimits
// envelope (× a margin) for several consecutive supervisor ticks, run the SAME
// fail-closed power-off the TPS546 fault path uses. The margin sits just above
// the rated PSU envelope (e.g. 25 W board → 31.25 W) and the debounce spans
// ~4 × 5 s ticks so a transient load-step / measurement spike cannot
// nuisance-trip. Fail-safe direction only: this can only ADD a hard-kill.
const INA260_OC_MARGIN: f32 = 1.25;
const INA260_OC_DEBOUNCE_TICKS: u8 = 4;

// ── XPSAFE-5: cut-hash-before-fan-noise thermal policy (home/space-heater) ──
// DCENT's load-bearing posture is "cut hash power before raising fan noise".
// At the WARNING tier (>90 C) we shed a modest amount of hash FIRST, then raise
// the fan only to a home-friendly cap (NOT 100%). These named consts are the
// one-line policy lever: a datacenter/loud profile would raise the cap, but the
// home default stays quiet. The 95 C tier still goes to 100% and the 105 C
// EMERGENCY tier still cuts hash entirely — those hard backstops are never
// lowered. NEVER lower a threshold or the fan floor.
const THERMAL_WARN_FREQ_SHED_MHZ: f32 = 50.0;
const THERMAL_WARN_FAN_CAP_PCT: u8 = 70;

// ── HALT-10: always-on gentle proportional fan curve (home-quiet) ──
// With the default fan_target_temp_c == 0 the PID never runs, so without this
// the fan would sit at boot duty until 90 C then step. This gives a continuous
// ramp between a comfort floor and the WARNING band while mining, keeping the
// board quiet at steady state. It only ever RAISES the fan above a user's manual
// setting (never reduces it, never below the 20% floor) and the 90 C -> cap /
// 105 C -> cut backstops still apply. All thresholds are named consts.
const PROP_FAN_LOW_TEMP_C: f32 = 55.0;
const PROP_FAN_HIGH_TEMP_C: f32 = 85.0;
const PROP_FAN_MIN_PCT: u8 = 30;
const PROP_FAN_MAX_PCT: u8 = 70;
#[cfg(feature = "stratum-v2")]
const STRATUM_STATUS_EVENT_LIMIT: usize = 64;

/// Connect the channel carrying this board's thermal sensor, and verify it.
///
/// Fails closed. A board that declares a [`ThermalI2cMux`] has NO reachable
/// temperature source until this succeeds, so the caller disables mining on
/// any error rather than proceeding to read whatever the bus happens to
/// expose.
///
/// [`ThermalI2cMux`]: dcentaxe_hal::board::ThermalI2cMux
#[cfg(feature = "i2c-mux-pca9544")]
fn select_thermal_mux_channel(
    i2c: &mut I2cBus,
    cfg: dcentaxe_hal::board::ThermalI2cMux,
) -> Result<(), String> {
    use dcentaxe_hal::pca9544::Pca9544;
    let mut mux = Pca9544::new(i2c, cfg.addr).map_err(|e| e.to_string())?;
    // `select` writes, settles, reads the control register back and compares
    // it against what was asked for — a write that the part did not latch, or
    // a different channel being live, is an error here rather than a wrong
    // temperature later.
    mux.select(i2c, cfg.channel).map_err(|e| e.to_string())
}

/// Fallback for images built without the multiplexer driver.
///
/// A board declaring a mux in a build that cannot drive one is a build
/// misconfiguration, not a runtime condition to work around — refuse, so the
/// caller disables mining instead of reading an unselected bus.
#[cfg(not(feature = "i2c-mux-pca9544"))]
fn select_thermal_mux_channel(
    _i2c: &mut I2cBus,
    cfg: dcentaxe_hal::board::ThermalI2cMux,
) -> Result<(), String> {
    Err(format!(
        "board declares a thermal I2C mux at 0x{:02X} channel {} but this image \
         was built without the i2c-mux-pca9544 driver",
        cfg.addr, cfg.channel
    ))
}

/// One board's TMP451 diode mux, resolved from the board row into live hardware.
///
/// Holds the shared select lines plus every sensor hanging off them. The
/// NerdOCTAXE-γ's two TMP451s share ONE pair of GPIOs, which is why the select
/// is owned here rather than by each sensor: two sensors cannot each own the
/// same pin.
#[cfg(feature = "temp-tmp451")]
struct DiodeMuxSweep<'d> {
    select: dcentaxe_hal::tmp451::MuxSelect<'d>,
    /// `(sensor, first_asic, channels)` — the row's channel→ASIC map, already
    /// validated as a bijection by `board.rs`'s declaration tests.
    sensors: Vec<(dcentaxe_hal::tmp451::Tmp451, u8, u8)>,
    /// ASIC count from the board row. Coverage is counted against THIS.
    expected_asics: u8,
}

#[cfg(feature = "temp-tmp451")]
impl DiodeMuxSweep<'_> {
    /// Read every declared die once, and report how many actually answered.
    ///
    /// Iterates channel-outer / sensor-inner on purpose: the analog path is
    /// shared, so selecting a channel once and reading both sensors through it
    /// pays the 50 ms mux settle and the discarded conversion ONCE per channel
    /// instead of once per sensor.
    ///
    /// Never returns early on an error. A dead sensor must not hide the dies
    /// that are still readable — and, more importantly, a partial sweep is
    /// reported as partial rather than as a smaller complete one.
    fn sweep(&mut self, i2c: &mut I2cBus) -> thermal_safety::MuxedDieFold {
        // Split the borrow: `read_muxed_channel` takes `&self` on the sensor and
        // `&mut` on the select, which a single `self` borrow cannot provide.
        let Self {
            select,
            sensors,
            expected_asics,
        } = self;

        let mut readings: Vec<Option<f32>> = vec![None; *expected_asics as usize];
        let channels = sensors.iter().map(|(_, _, c)| *c).max().unwrap_or(0);

        for channel in 0..channels {
            for (sensor, first_asic, sensor_channels) in sensors.iter() {
                if channel >= *sensor_channels {
                    continue;
                }
                let asic = usize::from(*first_asic) + usize::from(channel);
                let Some(slot) = readings.get_mut(asic) else {
                    // The row's map points past the declared ASIC count. The
                    // fold treats the missing die as uncovered and the board
                    // goes blind, which is the right answer for a board whose
                    // own description is inconsistent.
                    warn!(
                        "TMP451 0x{:02X} channel {} maps to ASIC {} but the board declares only {} \
                         — reading discarded",
                        sensor.addr(),
                        channel,
                        asic,
                        expected_asics
                    );
                    continue;
                };
                match sensor.read_muxed_channel(i2c, select, channel) {
                    // `conservative_c` (not `corrected_c`): a safety cut must not
                    // be fooled by a downward per-board correction.
                    Ok(Some(reading)) => *slot = Some(reading.conservative_c()),
                    Ok(None) => warn!(
                        "TMP451 0x{:02X} channel {} (ASIC {}): diode reads open-circuit",
                        sensor.addr(),
                        channel,
                        asic
                    ),
                    Err(e) => warn!(
                        "TMP451 0x{:02X} channel {} (ASIC {}) read failed: {}",
                        sensor.addr(),
                        channel,
                        asic,
                        e
                    ),
                }
            }
        }

        thermal_safety::fold_muxed_die_readings(&readings, *expected_asics)
    }
}

fn unsafe_lab_safety_bypass_enabled() -> bool {
    // XPSAFE-4: the lab-safety bypass is COMPILE-TIME ONLY. The prior runtime
    // process-environment arm was dead on ESP32 (no process env at runtime) and
    // falsely implied a runtime toggle. Removing it makes the activation surface
    // honest and unambiguous: the bypass can ONLY be set by building with the
    // build-time env var. main() reads the result ONCE at boot into the local
    // `unsafe_lab_safety_bypass` and reuses it at every gate, so there is nothing
    // for a late env change to flip mid-run.
    option_env!("DCENTAXE_UNSAFE_LAB_SAFETY_BYPASS") == Some("1")
}

// ══════════════════════════════════════════════════════════════════════════
// XPSAFE-1 — Fail-closed panic hook
// ══════════════════════════════════════════════════════════════════════════
//
// A panicked/wedged supervisor must not leave the ASIC energized while the
// ~hundreds-of-ms coredump-write + reboot runs (the task-WDT is only a ~15 s
// last-resort backstop). `install_fail_closed_panic_hook()` registers a
// `std::panic::set_hook` closure that, on ANY panic, cuts the buck rail and
// commands max cooling BEFORE the runtime aborts (the xtensa-esp32s3-espidf
// target defaults to panic=abort; see the workspace `Cargo.toml`
// `[profile.release]`). The closure is `Fn + Send + Sync + 'static` and captures
// no HAL handles, so the raw bits it needs are published through these atomics.
// Sentinels (-1 GPIO / 0 fan addr / 0 PMBus addr) keep the hook a SAFE NO-OP
// until the HAL arms it in three phases — buck right after the enable GPIO is
// built (still OFF), fan inside each controller boot block, and (XPSAFE-5) the
// PMBus rail cut right after the regulator is probed on boards that have no
// enable GPIO — all well before the rail is raised.
static PANIC_BUCK_GPIO: AtomicI32 = AtomicI32::new(-1);
static PANIC_BUCK_ACTIVE_LOW: AtomicBool = AtomicBool::new(false);
static PANIC_FAN_PORT: AtomicI32 = AtomicI32::new(-1);
static PANIC_FAN_ADDR: AtomicU8 = AtomicU8::new(0);
static PANIC_FAN_REG0: AtomicU8 = AtomicU8::new(0);
static PANIC_FAN_REG1: AtomicU8 = AtomicU8::new(0);
static PANIC_FAN_REG_COUNT: AtomicU8 = AtomicU8::new(0);
static PANIC_FAN_VAL: AtomicU8 = AtomicU8::new(0);

/// XPSAFE-1 I2C budget for the hook, in FreeRTOS ticks (~20 ms at
/// `FREERTOS_HZ=1000`). Every I2C write the hook performs is bounded by this so
/// a driver mutex held by the panicking task can never stall the abort path.
const PANIC_I2C_TICKS: u32 = 20;

/// Settle time after raising the ASIC LDO bank, before the core rail is
/// configured. Upstream `NerdQaxePlus::initAsics` waits exactly this long
/// between `LDO_enable()` and `m_tps->init()`.
const LDO_SETTLE_MS: u64 = 100;


/// Settle time between cutting the core rail and dropping the ASIC LDO on the
/// normal fail-closed path. Upstream `NerdQaxePlus::shutdown` waits this long
/// after `setVoltage(0.0)` before `LDO_disable()`.
///
/// This is also the reason the XPSAFE-1 panic hook does NOT drop the LDO: it
/// has no budget to wait, and dropping the IO supply on top of a still-
/// collapsing core rail inverts the sequence upstream deliberately observes.
/// Leaving the LDO up while the buck is cut is precisely the state upstream
/// holds for this window, so the hook's omission is the correct action rather
/// than a missing one.
const LDO_SHUTDOWN_SETTLE_MS: u64 = 500;

// XPSAFE-5 — panic-time rail cut for boards with NO enable GPIO.
//
// The GPIO cut above is the guaranteed action, but it only exists on
// `RailBringup::EnableGpio` boards. A `RailBringup::RegulatorOnly` board has no
// discrete enable at all: its rail is raised by a PMBus `OPERATION_ON` and cut
// by `OPERATION_OFF`, so `PANIC_BUCK_GPIO` stays at the -1 sentinel and the hook
// had NO actuator for it. That gap is why letting those boards mine used to
// read as a trade ("mining at the cost of the panic cut") — it is not one, and
// this closes it with the mechanism the fan write already proves out: one
// bounded, alloc-free `i2c_master_write_to_device`.
//
// Honest about the difference: a GPIO cut is a lock-free register write and
// cannot fail; a PMBus cut needs the I2C peripheral and can time out. It is
// best-effort-but-bounded, which is strictly more than nothing and strictly
// less than the GPIO path. It is armed ONLY where the GPIO cut is absent, so
// the panic path of every field-proven enable-GPIO board stays byte-identical.
static PANIC_PMBUS_PORT: AtomicI32 = AtomicI32::new(-1);
static PANIC_PMBUS_ADDR: AtomicU8 = AtomicU8::new(0);

// XPSAFE-5d — panic-time rail cut for boards whose enable is an I2C EXPANDER
// pin (Q1370/Q1373, FXL6408 at 0x43). Neither of the two arms above reaches
// them: `PANIC_BUCK_GPIO` stays at its sentinel because there is no ESP pin, and
// the PMBus arm is useless because their TPS5364x ignores `OPERATION`.
//
// Deliberately a SECOND NAMED ARM rather than folding both into one generic
// (addr, reg, value) write. The generic shape is tidier and strictly more
// dangerous: it would let the hook be armed to write any byte to any register
// at any address, and the comment on `arm_panic_pmbus_rail_cut` already warns
// what a guessed address costs. Two arms with fixed, test-pinned registers
// cannot be aimed somewhere unintended.
static PANIC_EXPANDER_PORT: AtomicI32 = AtomicI32::new(-1);
static PANIC_EXPANDER_ADDR: AtomicU8 = AtomicU8::new(0);

/// FXL6408 `OUTPUT_STATE` register. Mirrors `fxl6408_convert::reg::OUTPUT_STATE`
/// and is pinned equal to it by `expander_panic_constants_match_the_hal`.
const PANIC_EXPANDER_OUTPUT_STATE: u8 = 0x05;
/// Every expander output LOW: ASIC reset asserted, VREG off, LDO off.
///
/// One byte, and it needs no knowledge of the driver's shadow registers — which
/// matters because the hook cannot read them. It is also exactly the state
/// `Q1370B::initBoard` establishes before anything is allowed to energize, so
/// it is a known-good target rather than a computed one.
const PANIC_EXPANDER_ALL_LOW: u8 = 0x00;

/// PMBus `OPERATION` command. Mirrors the private `power::pmbus::OPERATION`;
/// pinned equal to it by `pmbus_panic_constants_match_the_hal` so the hook and
/// the driver can never disagree about which register turns the rail off.
const PANIC_PMBUS_OPERATION: u8 = 0x01;
/// PMBus `OPERATION` payload that turns the output OFF. Mirrors the private
/// `power::pmbus::OPERATION_OFF`; pinned by the same test.
const PANIC_PMBUS_OPERATION_OFF: u8 = 0x00;

/// Arm the panic hook's best-effort fan-cooling write for a confirmed fan
/// controller. `addr` is published LAST (it is the hook's "fan armed" gate) so
/// the hook never observes a half-written register set. `val` is always the
/// controller's full-scale duty (see `safety::fan_safe_panic_duty` /
/// `safety::emc2101_panic_duty`); the panic path never reduces a fan limit.
fn arm_panic_fan(port: i32, addr: u8, reg0: u8, reg1: u8, reg_count: u8, val: u8) {
    PANIC_FAN_PORT.store(port, Ordering::Release);
    PANIC_FAN_REG0.store(reg0, Ordering::Release);
    PANIC_FAN_REG1.store(reg1, Ordering::Release);
    PANIC_FAN_REG_COUNT.store(reg_count, Ordering::Release);
    PANIC_FAN_VAL.store(val, Ordering::Release);
    PANIC_FAN_ADDR.store(addr, Ordering::Release);
}

/// XPSAFE-5: arm the panic hook's PMBus rail cut for a board whose rail has no
/// enable GPIO. `addr` is published LAST (it is the hook's "armed" gate) so the
/// hook never observes a half-written pair, exactly as `arm_panic_fan` does.
///
/// Call this ONLY after the regulator has been probed and confirmed, and ONLY
/// for `RailBringup::RegulatorOnly` boards — arming it with a guessed address
/// would make the hook write `OPERATION_OFF` at whatever device answers 0x24.
fn arm_panic_pmbus_rail_cut(port: i32, addr: u8) {
    PANIC_PMBUS_PORT.store(port, Ordering::Release);
    PANIC_PMBUS_ADDR.store(addr, Ordering::Release);
}

/// XPSAFE-5d: arm the panic hook's expander rail cut. `addr` is published LAST
/// (the hook's "armed" gate), exactly as the two arms above do.
///
/// Call this ONLY after the expander has answered its device code and its
/// outputs are configured — arming it earlier would have the hook write
/// `OUTPUT_STATE` into a part that is still in high-Z, or into whatever else
/// happens to answer 0x43.
fn arm_panic_expander_rail_cut(port: i32, addr: u8) {
    PANIC_EXPANDER_PORT.store(port, Ordering::Release);
    PANIC_EXPANDER_ADDR.store(addr, Ordering::Release);
}

/// XPSAFE-1: install the fail-closed panic hook (see banner above).
///
/// The `Box` allocation happens HERE at install time, never inside the hook. The
/// hook body is ALLOC-FREE (no `format!`/`String`) per
/// . It deliberately does NOT call
/// `esp_restart()`: under panic=abort the runtime already reboots, and an
/// explicit restart here would SKIP the coredump that `/api/system/coredump`
/// depends on. The buck-cut (a lock-free atomic register write) is the
/// guaranteed-safe action and runs FIRST; the XPSAFE-5 PMBus rail cut (armed
/// only where no enable GPIO exists) and the fan write are best-effort, each
/// with a short I2C timeout so a held driver mutex can never wedge the abort
/// path. Power removal is ordered ahead of cooling: a rail that is off needs no
/// airflow, but airflow cannot save a rail that stays on.
fn install_fail_closed_panic_hook() {
    std::panic::set_hook(Box::new(|_panic_info| {
        // 1. LOAD-BEARING: cut the buck rail. `gpio_set_level` is a lock-free
        //    atomic register write — always safe from panic context.
        let buck_gpio = PANIC_BUCK_GPIO.load(Ordering::Acquire);
        if buck_gpio >= 0 {
            let active_low = PANIC_BUCK_ACTIVE_LOW.load(Ordering::Acquire);
            let off_level = dcentaxe_hal::safety::buck_off_level(active_low);
            unsafe {
                sys::gpio_set_level(buck_gpio, off_level);
            }
        }
        // 2. XPSAFE-5: cut the rail over PMBus for boards that have no enable
        //    GPIO to drive. Armed only when step 1 has no actuator, so this is
        //    a no-op on every enable-GPIO board. Runs BEFORE the fan write
        //    because removing power outranks adding airflow, and both share the
        //    same bounded I2C budget.
        let pmbus_addr = PANIC_PMBUS_ADDR.load(Ordering::Acquire);
        if pmbus_addr != 0 {
            let pmbus_port = PANIC_PMBUS_PORT.load(Ordering::Acquire);
            if pmbus_port >= 0 {
                let buf = [PANIC_PMBUS_OPERATION, PANIC_PMBUS_OPERATION_OFF];
                unsafe {
                    sys::i2c_master_write_to_device(
                        pmbus_port as u32,
                        pmbus_addr,
                        buf.as_ptr(),
                        buf.len(),
                        PANIC_I2C_TICKS,
                    );
                }
            }
        }
        // 3. XPSAFE-5d: cut the rail at the I2C port expander, for boards whose
        //    enable is neither an ESP GPIO nor a PMBus-switchable regulator.
        //    One write of 0x00 to OUTPUT_STATE drops ASIC reset, VREG and LDO
        //    together — the state `Q1370B::initBoard` establishes before
        //    anything may energize. Armed only where the two arms above have no
        //    actuator, so every other board's panic path stays byte-identical.
        //
        //    Still ahead of the fan: removing power outranks adding airflow.
        let exp_addr = PANIC_EXPANDER_ADDR.load(Ordering::Acquire);
        if exp_addr != 0 {
            let exp_port = PANIC_EXPANDER_PORT.load(Ordering::Acquire);
            if exp_port >= 0 {
                let buf = [PANIC_EXPANDER_OUTPUT_STATE, PANIC_EXPANDER_ALL_LOW];
                unsafe {
                    sys::i2c_master_write_to_device(
                        exp_port as u32,
                        exp_addr,
                        buf.as_ptr(),
                        buf.len(),
                        PANIC_I2C_TICKS,
                    );
                }
            }
        }
        // 4. BEST-EFFORT: command max cooling. Short timeout (~20 ms at
        //    FREERTOS_HZ=1000) so a held I2C driver mutex cannot stall the abort.
        let fan_addr = PANIC_FAN_ADDR.load(Ordering::Acquire);
        if fan_addr != 0 {
            let port = PANIC_FAN_PORT.load(Ordering::Acquire);
            if port < 0 {
                return;
            }
            let port = port as u32;
            let val = PANIC_FAN_VAL.load(Ordering::Acquire);
            let reg_count = PANIC_FAN_REG_COUNT.load(Ordering::Acquire);
            if reg_count >= 1 {
                let buf = [PANIC_FAN_REG0.load(Ordering::Acquire), val];
                unsafe {
                    sys::i2c_master_write_to_device(
                        port,
                        fan_addr,
                        buf.as_ptr(),
                        buf.len(),
                        PANIC_I2C_TICKS,
                    );
                }
            }
            if reg_count >= 2 {
                let buf = [PANIC_FAN_REG1.load(Ordering::Acquire), val];
                unsafe {
                    sys::i2c_master_write_to_device(
                        port,
                        fan_addr,
                        buf.as_ptr(),
                        buf.len(),
                        PANIC_I2C_TICKS,
                    );
                }
            }
        }
    }));
}

fn fail_closed_power_off(
    reason: &str,
    state: &SharedState,
    mining_kill: Option<&Arc<AtomicBool>>,
    power_mgr: Option<&mut PowerManager>,
    i2c: &mut I2cBus,
    gpio_ctrl: &mut GpioController<'_>,
) {
    error!("FAIL-CLOSED POWER OFF: {}", reason);
    if let Some(kill) = mining_kill {
        kill.store(true, Ordering::Relaxed);
    }
    {
        let mut telem = state
            .telemetry
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        telem.mining_enabled = false;
        telem.pool_connected = false;
    }
    if let Some(power_mgr) = power_mgr {
        match power_mgr.disable(i2c) {
            Ok(()) => {}
            Err(PowerError::RequiresBuckCut(msg)) => {
                warn!("Regulator disable requires GPIO cut: {}", msg);
            }
            Err(e) => {
                error!(
                    "Regulator disable failed during fail-closed shutdown: {}",
                    e
                );
            }
        }
    }
    if let Err(e) = gpio_ctrl.enable_buck(false) {
        error!(
            "Buck GPIO disable failed during fail-closed shutdown: {}",
            e
        );
    }
    // XPSAFE-5d: cut an EXPANDER rail. Without this a Q-series board would
    // survive a POWER FAULT with its rail up: `enable_buck(false)` errors (no
    // ESP pin) and `PowerManager::disable` returns `RequiresBuckCut` because a
    // TPS5364x cannot switch its own output. Neither of the two steps above
    // touches the only actuator the board has.
    //
    // The address comes from the panic-arm atomic rather than a driver handle,
    // for two reasons. It is the same verified value — published only after the
    // part answered its device code and its outputs were configured — and it
    // needs no `Fxl6408` in this signature, which would not compile when the
    // feature is off since the module would not exist.
    //
    // The write goes through `I2cBus`, NOT the raw `sys::` call the panic hook
    // uses, so it takes the driver mutex and cannot corrupt an in-flight
    // transaction. Writing all-zero also makes the driver's shadow drift
    // harmless: 0x00 is exactly the output byte `PortState::after_reset()`
    // holds, and no rail write happens after this point in any case — the
    // expander is only driven during bring-up.
    let expander_addr = PANIC_EXPANDER_ADDR.load(Ordering::Acquire);
    if expander_addr != 0 {
        match i2c.write_reg_u8(
            expander_addr,
            PANIC_EXPANDER_OUTPUT_STATE,
            PANIC_EXPANDER_ALL_LOW,
        ) {
            Ok(()) => info!(
                "Expander rail cut: 0x{:02X} OUTPUT_STATE=0x00 (ASIC reset + VREG + LDO low)",
                expander_addr
            ),
            Err(e) => error!(
                "Expander rail cut FAILED during fail-closed shutdown (0x{:02X}): {}",
                expander_addr, e
            ),
        }
    }
    // The ASIC LDO bank comes down LAST, and only after the core rail has had
    // time to collapse — upstream `NerdQaxePlus::shutdown` sequences
    // `setVoltage(0.0)` -> 500 ms -> `LDO_disable()`. Dropping the IO supply
    // first, or simultaneously, would leave the dies' IO rail below their core
    // rail while the core is still discharging.
    //
    // Guarded on `ldo_is_enabled()`, not merely `has_ldo()`, and the difference
    // is the settle. This helper is reachable from the supervisor LOOP (POWER
    // FAULT, INA260 over-current), so an unconditional 500 ms here would be
    // re-spent every tick against the task-WDT budget on a rail that is already
    // down. Reading the pin's real output state makes the drop idempotent: the
    // first fail-closed pays the settle, every later one is a no-op. It also
    // covers the board-has-no-LDO case, so `enable_ldo`'s topology `Err` is
    // never reached from here.
    if gpio_ctrl.ldo_is_enabled() {
        std::thread::sleep(std::time::Duration::from_millis(LDO_SHUTDOWN_SETTLE_MS));
        if let Err(e) = gpio_ctrl.enable_ldo(false) {
            error!("ASIC LDO disable failed during fail-closed shutdown: {}", e);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// OLED NOTIFICATION EMITTER (P1-O4)
// ══════════════════════════════════════════════════════════════════════════
// `Ssd1306Display::notify` is a NO-OP stub in the `display-none` variant of
// `dcentaxe-hal::display`, so on the 21 headless build targets these calls did
// nothing at runtime — but the compiler still built every `format!` and every
// string literal behind them and linked them into the image. Routing the ~70
// gamification call sites through this macro moves the whole ARGUMENT LIST
// behind the `display-ssd1306` cfg.
//
// What deliberately stays OUTSIDE the gate at every call site: the achievement
// bitmask updates, the `nvs_save_*` dirty flags, `lifetime_shares`,
// `share_flash_tick` / `achievement_flash_tick`, the state-edge trackers
// `prev_accepted` / `prev_streak` / `prev_block_height` and the telemetry
// publish. A headless board must unlock, persist and report exactly what a
// panelled board does. Display-only by construction and therefore INSIDE the
// gate: the `pending_flash` strobe machine and the notification-edge trackers
// `prev_rejected` / `prev_best_diff` / `prev_clean_jobs`, whose only readers are
// notification arms (blind critic + DCENT_CE/EE review, P1-O4 round 1).
//
// The urgent safety notifications (`display.notify_urgent`) in the power /
// thermal / fan handlers are NOT routed through this macro: they sit inside
// safety code and are out of this lane's footprint.
#[cfg(feature = "display-ssd1306")]
macro_rules! oled_notify {
    ($display:expr, $($arg:expr),+ $(,)?) => {
        $display.notify($($arg),+)
    };
}
#[cfg(feature = "display-none")]
macro_rules! oled_notify {
    ($display:expr, $($arg:expr),+ $(,)?) => {
        ()
    };
}

// ══════════════════════════════════════════════════════════════════════════
// PIXEL ART — 8x8 1-bit sprites stored as const byte arrays
// Each sprite is 8 bytes: one byte per column, LSB = top pixel.
// ══════════════════════════════════════════════════════════════════════════

/// Pickaxe swinging frame 1 (mining)
#[cfg(feature = "display-ssd1306")]
const SPRITE_PICKAXE_1: [u8; 8] = [
    0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00111000, 0b01001000, 0b10001000, 0b00001000,
];
/// Pickaxe swinging frame 2
#[cfg(feature = "display-ssd1306")]
const SPRITE_PICKAXE_2: [u8; 8] = [
    0b00000000, 0b00000001, 0b00000010, 0b00000100, 0b00011100, 0b00100100, 0b01000100, 0b00000100,
];
/// Bitcoin coin frame 1 (front)
#[cfg(feature = "display-ssd1306")]
const SPRITE_COIN_1: [u8; 8] = [
    0b00111100, 0b01000010, 0b10011001, 0b10100101, 0b10100101, 0b10011001, 0b01000010, 0b00111100,
];
/// Bitcoin coin frame 2 (turning)
#[cfg(feature = "display-ssd1306")]
const SPRITE_COIN_2: [u8; 8] = [
    0b00011000, 0b00100100, 0b01001001, 0b01010101, 0b01010101, 0b01001001, 0b00100100, 0b00011000,
];
/// Bitcoin coin frame 3 (edge)
#[cfg(feature = "display-ssd1306")]
const SPRITE_COIN_3: [u8; 8] = [
    0b00001000, 0b00010100, 0b00100010, 0b00101010, 0b00101010, 0b00100010, 0b00010100, 0b00001000,
];
/// Lightning bolt (share accepted flash)
#[cfg(feature = "display-ssd1306")]
const SPRITE_LIGHTNING: [u8; 8] = [
    0b00000000, 0b00001100, 0b00010100, 0b00111100, 0b00011110, 0b00010100, 0b00011000, 0b00000000,
];
/// Campfire (space heater vibes)
#[cfg(feature = "display-ssd1306")]
const SPRITE_CAMPFIRE: [u8; 8] = [
    0b00000000, 0b00010000, 0b00101000, 0b00010000, 0b01111110, 0b11111111, 0b01111110, 0b00111100,
];
/// Rocket (milestone/achievement)
#[cfg(feature = "display-ssd1306")]
const SPRITE_ROCKET: [u8; 8] = [
    0b00010000, 0b00111000, 0b01111100, 0b01111100, 0b01111100, 0b00111000, 0b01000100, 0b10000010,
];

// ══════════════════════════════════════════════════════════════════════════
// 16x16 CREATURE SPRITES — Full-screen companion page
// Column-major 1-bit, 16 columns x 2 pages (16 bytes per page = 32 bytes)
// ══════════════════════════════════════════════════════════════════════════

/// Happy miner creature — wide eyes, smile, pickaxe hat (16x16, eyes open)
#[cfg(feature = "display-ssd1306")]
const CREATURE_HAPPY: [u8; 32] = [
    0x00, 0x00, 0x1C, 0x22, 0x49, 0x45, 0x41, 0x45, 0x49, 0x22, 0x1C, 0x00, 0x00, 0x00, 0x00,
    0x00, // top 8 rows
    0x00, 0x3C, 0x42, 0x81, 0xA5, 0x81, 0x81, 0x42, 0x3C, 0x18, 0x24, 0x24, 0x18, 0x00, 0x00,
    0x00, // bottom 8 rows (body+legs)
];

/// Happy miner blink frame — eyes closed (16x16)
#[cfg(feature = "display-ssd1306")]
const CREATURE_BLINK: [u8; 32] = [
    0x00, 0x00, 0x1C, 0x22, 0x41, 0x4D, 0x41, 0x4D, 0x41, 0x22, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x3C, 0x42, 0x81, 0xA5, 0x81, 0x81, 0x42, 0x3C, 0x18, 0x24, 0x24, 0x18, 0x00, 0x00, 0x00,
];

/// Sad creature — droopy eyes, frown (16x16)
#[cfg(feature = "display-ssd1306")]
const CREATURE_SAD: [u8; 32] = [
    0x00, 0x00, 0x1C, 0x22, 0x41, 0x49, 0x41, 0x49, 0x41, 0x22, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x3C, 0x42, 0x81, 0x99, 0x81, 0xA5, 0x42, 0x3C, 0x18, 0x24, 0x24, 0x18, 0x00, 0x00, 0x00,
];

/// Sleeping creature — closed eyes, Zzz (16x16)
#[cfg(feature = "display-ssd1306")]
const CREATURE_SLEEP: [u8; 32] = [
    0x00, 0x00, 0x1C, 0x22, 0x41, 0x4D, 0x41, 0x4D, 0x41, 0x22, 0x1C, 0x0E, 0x04, 0x0E, 0x02,
    0x06, // Zzz pattern top-right
    0x00, 0x3C, 0x42, 0x81, 0x81, 0x81, 0x81, 0x42, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00, 0x00,
    0x00, // legs together (resting)
];

/// Heart filled (5x7 column-major)
#[cfg(feature = "display-ssd1306")]
const HEART_FILLED: [u8; 5] = [0x0C, 0x1E, 0x3C, 0x1E, 0x0C];
/// Heart empty (5x7 column-major)
#[cfg(feature = "display-ssd1306")]
const HEART_EMPTY: [u8; 5] = [0x0C, 0x12, 0x24, 0x12, 0x0C];

/// Brightness breathing LUT (6 steps, hardware contrast register)
#[cfg(feature = "display-ssd1306")]
const BREATH_LUT: [u8; 6] = [0x60, 0x90, 0xCF, 0xFF, 0xCF, 0x90];

// ══════════════════════════════════════════════════════════════════════════
// HASHRATE FUN COMPARISONS
// ══════════════════════════════════════════════════════════════════════════
#[cfg(feature = "display-ssd1306")]
const HASHRATE_COMPARISONS: &[&str] = &[
    "Game Boys mining!",
    "x Satoshi's 2009 HR",
    "hashes per eye blink",
    "of network. YOU MATTER",
    "billion SHA256/heartbt",
    "Nintendo 64s hashing!",
    "dial-up modems worth!",
    "pocket calculators!",
];

// ══════════════════════════════════════════════════════════════════════════
// MINING FORTUNE COOKIES
// ══════════════════════════════════════════════════════════════════════════
#[cfg(feature = "display-ssd1306")]
const FORTUNE_COOKIES: &[&str] = &[
    "A golden nonce awaits",
    "Trust the math. Mine.",
    "Lucky: 21, 2100, 210k",
    "Diff drop incoming...",
    "Your hash, your rules!",
    "Patience mines blocks.",
    "The chain remembers.",
    "Tick tock, next block.",
];

/// Check if a block height is "special" (palindrome, round, repeating, sequential).
#[cfg(feature = "display-ssd1306")]
fn is_special_block(h: u32) -> Option<&'static str> {
    if h == 0 {
        return None;
    }
    let s = format!("{}", h);
    let bytes = s.as_bytes();

    // Palindrome check
    let is_palindrome = bytes.iter().zip(bytes.iter().rev()).all(|(a, b)| a == b);
    if is_palindrome && s.len() >= 5 {
        return Some("PALINDROME!");
    }

    // Round number (divisible by 100000)
    if h % 1_000_000 == 0 {
        return Some("MILLION BLOCK!");
    }
    if h % 100_000 == 0 {
        return Some("ROUND BLOCK!");
    }

    // Repeating digits (all same)
    if s.len() >= 5 && bytes.iter().all(|&b| b == bytes[0]) {
        return Some("JACKPOT!");
    }

    // Sequential ascending (123456)
    if s.len() >= 5 {
        let mut is_seq = true;
        for i in 1..bytes.len() {
            if bytes[i] != bytes[i - 1] + 1 {
                is_seq = false;
                break;
            }
        }
        if is_seq {
            return Some("SEQUENCE BLOCK!");
        }
    }

    None
}

fn expected_hashrate_ghs(
    asic_model: dcentaxe_asic::AsicModel,
    frequency_mhz: f32,
    asic_count: u8,
) -> f32 {
    let small_cores_per_chip = match asic_model {
        dcentaxe_asic::AsicModel::BM1397 => 672,
        dcentaxe_asic::AsicModel::BM1366 => 894,
        dcentaxe_asic::AsicModel::BM1368 => 1276,
        dcentaxe_asic::AsicModel::BM1370 | dcentaxe_asic::AsicModel::BM1373 => 2040,
        // MSBT0501 is a SCRYPT chip: a "small core" runs ~10^4 clocks per hash
        // because of the 128 KiB ROMix, so the SHA-256 `freq x cores` model is
        // ~4 orders of magnitude wrong for it (150-450 MH/s, not GH/s). There
        // is no honest small-core figure to put here, and the caller returns
        // GH/s, so report 0 rather than a number that is off by 10^4.
        // A unit-aware hashrate estimator is a follow-up (design §4.6).
        dcentaxe_asic::AsicModel::Lt0051 => 0,
    };
    frequency_mhz * small_cores_per_chip as f32 * asic_count.max(1) as f32 / 1000.0
}

#[cfg(feature = "stratum-v2")]
fn push_stratum_status_event(
    status: &dcentaxe_stratum::SharedStratumStatus,
    kind: dcentaxe_stratum::StratumEventKind,
    detail: impl Into<String>,
) {
    let now = shared::unix_time_ms();
    if let Ok(mut status) = status.lock() {
        status
            .recent_events
            .push(dcentaxe_stratum::StratumEventRecord {
                ts_unix_ms: now,
                kind,
                detail: detail.into(),
            });
        if status.recent_events.len() > STRATUM_STATUS_EVENT_LIMIT {
            status.recent_events.remove(0);
        }
    }
}

#[cfg(feature = "stratum-v2")]
fn fill_sv2_rng_seed() -> [u8; 64] {
    let mut rng_seed = [0u8; 64];
    for chunk in rng_seed.chunks_exact_mut(4) {
        let r = unsafe { sys::esp_random() };
        chunk.copy_from_slice(&r.to_le_bytes());
    }
    rng_seed
}

#[cfg(feature = "stratum-v2")]
#[derive(Debug, Clone)]
struct Sv2PendingSubmit {
    sequence_number: u32,
    difficulty: f64,
    submitted_at: Instant,
}

#[cfg(feature = "stratum-v2")]
fn parse_sv2_job_id(job_id: &str) -> Result<u32, String> {
    job_id
        .parse::<u32>()
        .or_else(|_| u32::from_str_radix(job_id.trim_start_matches("0x"), 16))
        .map_err(|e| format!("invalid SV2 job_id {}: {}", job_id, e))
}

#[cfg(feature = "stratum-v2")]
fn parse_hex_u32(name: &str, value: &str) -> Result<u32, String> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|e| format!("invalid {} {}: {}", name, value, e))
}

#[cfg(feature = "stratum-v2")]
fn update_sv2_pending_status(
    status: &dcentaxe_stratum::SharedStratumStatus,
    pending: &[Sv2PendingSubmit],
) {
    let oldest_pending_submit_age_ms = pending
        .iter()
        .map(|submit| submit.submitted_at.elapsed().as_millis() as u64)
        .max()
        .unwrap_or(0);
    if let Ok(mut status) = status.lock() {
        status.shares_pending = pending.len() as u32;
        status.oldest_pending_submit_age_ms = oldest_pending_submit_age_ms;
    }
}

#[cfg(feature = "stratum-v2")]
fn record_sv2_share_accepted(
    status: &dcentaxe_stratum::SharedStratumStatus,
    pending: &mut Vec<Sv2PendingSubmit>,
    sequence_number: u32,
    accepted_count: u32,
) {
    let mut accepted = Vec::new();
    let mut remaining = Vec::with_capacity(pending.len());
    let max_accept = accepted_count.max(1) as usize;
    for submit in pending.drain(..) {
        if submit.sequence_number <= sequence_number && accepted.len() < max_accept {
            accepted.push(submit);
        } else {
            remaining.push(submit);
        }
    }
    *pending = remaining;
    if accepted.is_empty() {
        update_sv2_pending_status(status, pending);
        return;
    }
    let now_ms = shared::unix_time_ms();
    let accepted_len = accepted.len() as u64;
    let difficulty_sum: f64 = accepted.iter().map(|submit| submit.difficulty).sum();
    let response_ms = accepted
        .iter()
        .map(|submit| submit.submitted_at.elapsed().as_millis() as f64)
        .fold(0.0, f64::max);
    if let Ok(mut status) = status.lock() {
        status.shares_accepted = status.shares_accepted.saturating_add(accepted_len);
        status.shares_pending = pending.len() as u32;
        status.difficulty_accepted += difficulty_sum;
        status.last_share_response_ms = response_ms;
        status.last_share_response_unix_ms = now_ms;
        status.last_share_accepted_unix_ms = now_ms;
    }
    push_stratum_status_event(
        status,
        dcentaxe_stratum::StratumEventKind::ShareAccepted,
        format!("seq={} count={}", sequence_number, accepted_len),
    );
    update_sv2_pending_status(status, pending);
}

#[cfg(feature = "stratum-v2")]
fn record_sv2_share_rejected(
    status: &dcentaxe_stratum::SharedStratumStatus,
    pending: &mut Vec<Sv2PendingSubmit>,
    sequence_number: u32,
    reason: &str,
) {
    let mut rejected: Option<Sv2PendingSubmit> = None;
    pending.retain(|submit| {
        if submit.sequence_number == sequence_number && rejected.is_none() {
            rejected = Some(submit.clone());
            false
        } else {
            true
        }
    });
    let now_ms = shared::unix_time_ms();
    if let Ok(mut status) = status.lock() {
        status.shares_rejected = status.shares_rejected.saturating_add(1);
        status.shares_pending = pending.len() as u32;
        status.last_reject_reason = reason.to_string();
        status.last_share_response_unix_ms = now_ms;
        status.last_share_rejected_unix_ms = now_ms;
        if let Some(submit) = rejected {
            status.difficulty_rejected += submit.difficulty;
            status.last_share_response_ms = submit.submitted_at.elapsed().as_millis() as f64;
        }
    }
    push_stratum_status_event(
        status,
        dcentaxe_stratum::StratumEventKind::ShareRejected,
        format!("seq={} {}", sequence_number, reason),
    );
    update_sv2_pending_status(status, pending);
}

/// SV2-3: after this many CONSECUTIVE connect failures, fail over to the
/// configured fallback pool (if any) instead of retrying the same dead endpoint
/// forever. An SV2 pool/network outage previously meant total mining loss because
/// the V2 arm DROPPED the fallback and only ever retried the primary.
#[cfg(feature = "stratum-v2")]
const SV2_FAILOVER_AFTER_N: u32 = 5;

#[cfg(feature = "stratum-v2")]
fn run_sv2_client_thread(
    mut config: dcentaxe_stratum::StratumConfig,
    event_tx: mpsc::Sender<StratumEvent>,
    share_rx: mpsc::Receiver<MiningEvent>,
    status: dcentaxe_stratum::SharedStratumStatus,
    expected_hashrate_ghs: f32,
    sv2_authority_pubkey: Option<String>,
    fallback_pool: Option<dcentaxe_stratum::StratumConfig>,
) {
    use dcentaxe_stratum_v2::channel::Sv2Event;
    use dcentaxe_stratum_v2::client::{Sv2Client, Sv2Config};

    // SV2-3: track consecutive connect failures locally so we can fail over to the
    // fallback pool once they cross SV2_FAILOVER_AFTER_N. `failed_over` ensures we
    // only switch once (the fallback then gets its own retry/backoff).
    let mut sv2_consecutive_failures = 0u32;
    let mut failed_over = false;
    let mut backoff_secs = 1u64;
    loop {
        let host = config.endpoint_host();
        if let Ok(mut s) = status.lock() {
            s.configured_url = config.url.clone();
            s.configured_port = config.port;
            s.active_url = host.clone();
            s.active_port = config.port;
            s.connected = false;
            s.authorized = false;
            s.backoff_secs = backoff_secs;
        }

        let sv2_config = Sv2Config {
            host: host.clone(),
            port: config.port,
            worker: config.worker_name.clone(),
            hashrate_ghs: expected_hashrate_ghs.max(1.0),
            timeout_secs: 15,
            pool_authority_pubkey: sv2_authority_pubkey.clone(),
        };
        let mut client = Sv2Client::new(sv2_config);
        client.set_rng_seed(fill_sv2_rng_seed());

        match client.connect() {
            Ok(()) => {
                backoff_secs = 1;
                sv2_consecutive_failures = 0;
                if let Ok(mut s) = status.lock() {
                    s.consecutive_failures = 0;
                    s.backoff_secs = 0;
                    s.last_connect_cause = "sv2 noise handshake complete".to_string();
                    s.last_connect_unix_ms = shared::unix_time_ms();
                }
                push_stratum_status_event(
                    &status,
                    dcentaxe_stratum::StratumEventKind::Connect,
                    format!("sv2 noise handshake {}:{}", host, config.port),
                );
            }
            Err(e) => {
                warn!("SV2: connection failed: {}", e);
                let now_ms = shared::unix_time_ms();
                sv2_consecutive_failures = sv2_consecutive_failures.saturating_add(1);
                if let Ok(mut s) = status.lock() {
                    s.connected = false;
                    s.authorized = false;
                    s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                    s.last_disconnect_cause = e.clone();
                    s.last_disconnect_unix_ms = now_ms;
                    s.backoff_secs = backoff_secs;
                }
                push_stratum_status_event(
                    &status,
                    dcentaxe_stratum::StratumEventKind::Disconnect,
                    e,
                );
                let _ = event_tx.send(StratumEvent::Disconnected);

                // SV2-3: an SV2 outage must not mean total mining loss. After
                // SV2_FAILOVER_AFTER_N consecutive failures, switch to the
                // configured fallback pool (once). If the fallback is itself SV2,
                // we keep this loop and retry the new endpoint; if it is V1, we hand
                // off to the V1 client path (matching the V1 arm in
                // spawn_stratum_thread) since this thread only speaks SV2.
                if !failed_over
                    && sv2_consecutive_failures >= SV2_FAILOVER_AFTER_N
                    && fallback_pool.is_some()
                {
                    let fb = fallback_pool.clone().expect("checked is_some");
                    failed_over = true;
                    warn!(
                        "SV2: {} consecutive failures — failing over to fallback pool {}:{}",
                        sv2_consecutive_failures,
                        crate::shared::sanitize_pool_url(&fb.url),
                        fb.port
                    );
                    if let Ok(mut s) = status.lock() {
                        s.last_disconnect_cause = "sv2 failover to fallback".to_string();
                        s.last_reconnect_cause = format!(
                            "sv2 failover to fallback {}:{}",
                            crate::shared::sanitize_pool_url(&fb.url),
                            fb.port
                        );
                    }
                    push_stratum_status_event(
                        &status,
                        dcentaxe_stratum::StratumEventKind::FailoverEntered,
                        format!(
                            "sv2 failover to fallback {}:{}",
                            crate::shared::sanitize_pool_url(&fb.url),
                            fb.port
                        ),
                    );
                    if fb.protocol() == StratumProtocol::V2 {
                        // Fallback is SV2 too — retry it with this loop's machinery.
                        config = fb;
                        backoff_secs = 1;
                        sv2_consecutive_failures = 0;
                        continue;
                    } else {
                        // Fallback is V1 — hand off to the V1 client path. `status`
                        // is an Arc, so clone the handle (cheap) to avoid moving it
                        // out of the retry loop; this path runs the V1 client to
                        // completion and returns.
                        let mut v1 = StratumClient::new(fb, event_tx, share_rx);
                        v1.set_status_handle(status.clone());
                        v1.run();
                        return;
                    }
                }

                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(30);
                continue;
            }
        }

        let mut pending_submits: Vec<Sv2PendingSubmit> = Vec::new();
        let mut reconnect_config: Option<dcentaxe_stratum::StratumConfig> = None;

        'connected: loop {
            for event in client.poll() {
                match event {
                    Sv2Event::Connected => {
                        if let Ok(mut s) = status.lock() {
                            s.connected = true;
                            s.authorized = true;
                            s.last_reconnect_cause = "sv2 setup accepted".to_string();
                        }
                        push_stratum_status_event(
                            &status,
                            dcentaxe_stratum::StratumEventKind::PoolMessage,
                            "sv2 setup accepted; opening mining channel",
                        );
                        let _ = event_tx.send(StratumEvent::Reconnected);
                    }
                    Sv2Event::DifficultyChanged(diff) => {
                        let safe_diff = if diff.is_finite() && diff > 0.0 {
                            diff
                        } else {
                            1.0
                        };
                        if let Ok(mut s) = status.lock() {
                            s.difficulty = safe_diff;
                        }
                        push_stratum_status_event(
                            &status,
                            dcentaxe_stratum::StratumEventKind::DifficultyChanged,
                            format!("sv2 difficulty {:.4}", safe_diff),
                        );
                        let _ = event_tx.send(StratumEvent::DifficultyChanged(safe_diff));
                    }
                    Sv2Event::NewJob {
                        job_id,
                        version,
                        prev_hash,
                        merkle_root,
                        nbits,
                        ntime,
                        target,
                        clean_jobs,
                    } => {
                        let work = bridge::sv2_job_to_mining_work(
                            job_id,
                            version,
                            prev_hash,
                            merkle_root,
                            nbits,
                            ntime,
                            // SV2 standard channels carry no negotiated version_mask;
                            // bridge upgrades 0 -> the BIP320 canonical mask so BM1397
                            // rolls 4 midstates (ASICBoost) under SV2, matching V1.
                            0,
                            target,
                        );
                        if let Ok(mut s) = status.lock() {
                            s.connected = true;
                            s.authorized = true;
                            s.jobs_received = s.jobs_received.saturating_add(1);
                        }
                        let _ = event_tx.send(StratumEvent::PrebuiltWork { work, clean_jobs });
                    }
                    Sv2Event::ShareAccepted {
                        sequence_number,
                        accepted_count,
                    } => record_sv2_share_accepted(
                        &status,
                        &mut pending_submits,
                        sequence_number,
                        accepted_count,
                    ),
                    Sv2Event::ShareRejected {
                        sequence_number,
                        reason,
                    } => {
                        record_sv2_share_rejected(
                            &status,
                            &mut pending_submits,
                            sequence_number,
                            &reason,
                        );
                    }
                    Sv2Event::Disconnected(reason) => {
                        warn!("SV2: disconnected: {}", reason);
                        if let Ok(mut s) = status.lock() {
                            s.connected = false;
                            s.authorized = false;
                            s.last_disconnect_cause = reason.clone();
                            s.last_disconnect_unix_ms = shared::unix_time_ms();
                        }
                        push_stratum_status_event(
                            &status,
                            dcentaxe_stratum::StratumEventKind::Disconnect,
                            reason,
                        );
                        let _ = event_tx.send(StratumEvent::Disconnected);
                        break 'connected;
                    }
                    Sv2Event::Reconnect { host, port } => {
                        let mut next = config.clone();
                        if !host.trim().is_empty() {
                            next.url = host;
                        }
                        if port != 0 {
                            next.port = port;
                        }
                        reconnect_config = Some(next);
                        break 'connected;
                    }
                }
            }

            while let Ok(MiningEvent::SubmitShare(share)) = share_rx.try_recv() {
                let submit_result = parse_sv2_job_id(&share.job_id)
                    .and_then(|job_id| {
                        let nonce = parse_hex_u32("nonce", &share.nonce)?;
                        let ntime = parse_hex_u32("ntime", &share.ntime)?;
                        Ok((job_id, nonce, ntime))
                    })
                    .and_then(|(job_id, nonce, ntime)| {
                        client.submit_share(job_id, nonce, ntime, share.version)
                    });
                match submit_result {
                    Ok(sequence_number) => {
                        let now_ms = shared::unix_time_ms();
                        pending_submits.push(Sv2PendingSubmit {
                            sequence_number,
                            difficulty: share.difficulty,
                            submitted_at: Instant::now(),
                        });
                        if pending_submits.len() > 64 {
                            pending_submits.remove(0);
                        }
                        if let Ok(mut s) = status.lock() {
                            s.shares_submitted = s.shares_submitted.saturating_add(1);
                            s.shares_pending = pending_submits.len() as u32;
                            s.last_share_submit_unix_ms = now_ms;
                            s.last_share_difficulty = share.difficulty;
                        }
                        push_stratum_status_event(
                            &status,
                            dcentaxe_stratum::StratumEventKind::ShareSubmitted,
                            format!("seq={} diff={:.1}", sequence_number, share.difficulty),
                        );
                    }
                    Err(e) => {
                        warn!("SV2: failed to submit share: {}", e);
                        if let Ok(mut s) = status.lock() {
                            s.last_reject_reason = e.clone();
                        }
                    }
                }
            }

            update_sv2_pending_status(&status, &pending_submits);
            std::thread::sleep(Duration::from_millis(20));
        }

        client.disconnect();
        if let Some(next) = reconnect_config.take() {
            config = next;
        } else {
            std::thread::sleep(Duration::from_secs(backoff_secs));
            backoff_secs = (backoff_secs * 2).min(30);
        }
    }
}

#[cfg(not(feature = "stratum-v2"))]
fn run_sv2_client_thread(
    config: dcentaxe_stratum::StratumConfig,
    event_tx: mpsc::Sender<StratumEvent>,
    share_rx: mpsc::Receiver<MiningEvent>,
    status: dcentaxe_stratum::SharedStratumStatus,
    _expected_hashrate_ghs: f32,
    _sv2_authority_pubkey: Option<String>,
    fallback_pool: Option<dcentaxe_stratum::StratumConfig>,
) {
    error!(
        "Stratum V2 configured for {}:{}, but firmware was built without the stratum-v2 feature",
        crate::shared::sanitize_pool_url(&config.url),
        config.port
    );
    // H4/SV2-AVAIL: instead of sleeping forever (total mining loss with no
    // failover), fail OVER to a configured V1 fallback pool when one is set —
    // e.g. a unit reflashed from a V2 build whose persisted primary is still V2.
    // A V2 fallback can't be honored on this build either, so only a V1 fallback
    // is taken; this reuses the exact proven V1 StratumClient path.
    if let Some(fb) = fallback_pool {
        if fb.protocol() == StratumProtocol::V1 {
            warn!(
                "SV2 unavailable in this build — failing over to V1 fallback pool {}:{}",
                crate::shared::sanitize_pool_url(&fb.url),
                fb.port
            );
            if let Ok(mut s) = status.lock() {
                s.last_disconnect_cause = "stratum-v2 not compiled; using V1 fallback".to_string();
            }
            let mut client = StratumClient::new(fb, event_tx, share_rx);
            client.set_status_handle(status);
            client.run();
            return;
        }
        warn!("SV2 unavailable and configured fallback is also V2 — cannot fail over");
    }
    if let Ok(mut s) = status.lock() {
        s.connected = false;
        s.authorized = false;
        s.last_disconnect_cause = "stratum-v2 feature not compiled".to_string();
    }
    let _ = event_tx.send(StratumEvent::Disconnected);
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_stratum_thread(
    name: &str,
    config: dcentaxe_stratum::StratumConfig,
    fallback_pool: Option<dcentaxe_stratum::StratumConfig>,
    donation: Option<dcentaxe_stratum::DonationDirective>,
    event_tx: mpsc::Sender<StratumEvent>,
    share_rx: mpsc::Receiver<MiningEvent>,
    status: dcentaxe_stratum::SharedStratumStatus,
    expected_hashrate_ghs: f32,
    sv2_authority_pubkey: Option<String>,
) -> std::thread::JoinHandle<()> {
    let protocol = config.protocol();
    let thread_name = name.to_string();
    std::thread::Builder::new()
        .name(thread_name)
        .stack_size(if protocol == StratumProtocol::V2 {
            32 * 1024
        } else {
            24 * 1024
        })
        .spawn(move || match protocol {
            StratumProtocol::V1 => {
                let mut client = StratumClient::new(config, event_tx, share_rx);
                client.set_status_handle(status);
                if let Some(fb) = fallback_pool {
                    client.set_fallback(fb.clone());
                    // B-ESP-10: sanitize the pool URL (strip any user:pass@) in logs.
                    info!(
                        "Stratum: fallback pool configured - {}:{}",
                        crate::shared::sanitize_pool_url(&fb.url),
                        fb.port
                    );
                }
                if let Some(directive) = donation {
                    client.set_donation(directive);
                }
                client.run();
            }
            StratumProtocol::V2 => {
                // SV2-3: thread the fallback pool through instead of dropping it.
                // run_sv2_client_thread now fails over to it after
                // SV2_FAILOVER_AFTER_N consecutive failures, so an SV2 outage no
                // longer means total mining loss.
                if let Some(ref fb) = fallback_pool {
                    info!(
                        "SV2: fallback pool configured for failover - {}:{}",
                        crate::shared::sanitize_pool_url(&fb.url),
                        fb.port
                    );
                }
                run_sv2_client_thread(
                    config,
                    event_tx,
                    share_rx,
                    status,
                    expected_hashrate_ghs,
                    sv2_authority_pubkey,
                    fallback_pool,
                );
            }
        })
        .expect("Stratum thread spawn failed")
}

/// Format a large number with K/M/G suffix to fit on 21-char OLED lines.
#[cfg(feature = "display-ssd1306")]
fn fmt_num(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{}G", n / 1_000_000_000)
    } else if n >= 1_000_000 {
        format!("{}M", n / 1_000_000)
    } else if n >= 10_000 {
        format!("{}k", n / 1_000)
    } else {
        format!("{}", n)
    }
}

/// Compact GH/s display for 21-character OLED rows.
#[cfg(feature = "display-ssd1306")]
fn fmt_hashrate(hr_ghs: f64) -> String {
    if hr_ghs >= 1000.0 {
        format!("{:.2}T", hr_ghs / 1000.0)
    } else if hr_ghs >= 100.0 {
        format!("{:.0}G", hr_ghs)
    } else if hr_ghs >= 10.0 {
        format!("{:.1}G", hr_ghs)
    } else {
        format!("{:.2}G", hr_ghs)
    }
}

fn main() {
    // ======================================================================
    // Step 1: ESP-IDF init
    // ======================================================================
    sys::link_patches();
    EspLogger::initialize_default();

    // XPSAFE-1: register the fail-closed panic hook BEFORE any rail is enabled.
    // Until the HAL arms it (buck GPIO + fan controller, in Step 6), the hook is
    // a safe no-op; arming completes well before `enable_buck(true)`.
    install_fail_closed_panic_hook();

    let reset_reason = unsafe { sys::esp_reset_reason() };
    info!("========================================");
    info!("  DCENT_axe v{} — First Hash Edition", VERSION);
    info!("  D-Central Technologies");
    info!(
        "  Reset reason: {} (code {})",
        match reset_reason {
            sys::esp_reset_reason_t_ESP_RST_POWERON => "Power-on",
            sys::esp_reset_reason_t_ESP_RST_SW => "Software",
            sys::esp_reset_reason_t_ESP_RST_PANIC => "Panic",
            sys::esp_reset_reason_t_ESP_RST_INT_WDT => "Interrupt watchdog",
            sys::esp_reset_reason_t_ESP_RST_TASK_WDT => "Task watchdog",
            sys::esp_reset_reason_t_ESP_RST_WDT => "Other watchdog",
            sys::esp_reset_reason_t_ESP_RST_DEEPSLEEP => "Deep sleep",
            sys::esp_reset_reason_t_ESP_RST_BROWNOUT => "Brownout",
            sys::esp_reset_reason_t_ESP_RST_SDIO => "SDIO",
            _ => "Unknown",
        },
        reset_reason
    );
    info!("========================================");

    // Surface any stored panic coredump (ESP-IDF coredump partition) so the
    // user/dev knows to retrieve it via /api/system/coredump before a fresh
    // panic overwrites it.
    {
        let mut out_addr: usize = 0;
        let mut out_size: usize = 0;
        let rc = unsafe { sys::esp_core_dump_image_get(&mut out_addr, &mut out_size) };
        if rc == 0 && out_size > 0 {
            warn!(
                "Panic coredump present: {} bytes @ 0x{:08x} — retrieve via GET /api/system/coredump?download=1",
                out_size, out_addr
            );
        }
    }

    // ======================================================================
    // Step 2: NVS + peripherals
    // ======================================================================
    let nvs_partition =
        esp_idf_svc::nvs::EspDefaultNvsPartition::take().expect("Failed to initialize NVS flash");

    // Task-WDT safe-mode recovery.
    // If the device has rebooted ≥3 times from `ESP_RST_TASK_WDT` inside a
    // 300 s window, we refuse to start mining on the next boot and surface
    // the device in "safe mode" so the user can reach the dashboard / API
    // without the wedged code path tripping the WDT again. Cleared by
    // `POST /api/system/clear-safe-mode` or by any successful mining loop.
    const WDT_WINDOW_MS: u64 = 300_000;
    const WDT_SAFE_MODE_THRESHOLD: u8 = 3;
    let (mut wdt_count, mut wdt_since_ms) = (0u8, 0u64);
    let mut safe_mode = false;
    {
        let p = nvs_partition.clone();
        if let Ok(mut nvs) =
            esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(p, "dcentaxe", true)
        {
            let (count, since) = nvs_config::load_wdt_counters(&nvs);
            let now_ms = shared::unix_time_ms();
            if reset_reason == sys::esp_reset_reason_t_ESP_RST_TASK_WDT
                || reset_reason == sys::esp_reset_reason_t_ESP_RST_INT_WDT
            {
                if since == 0 || now_ms.saturating_sub(since) > WDT_WINDOW_MS {
                    // New window.
                    wdt_count = 1;
                    wdt_since_ms = now_ms;
                } else {
                    wdt_count = count.saturating_add(1);
                    wdt_since_ms = since;
                }
                warn!(
                    "Task-WDT reset detected: count={} in {} ms window",
                    wdt_count,
                    now_ms.saturating_sub(wdt_since_ms)
                );
                nvs_config::save_wdt_counters(&mut nvs, wdt_count, wdt_since_ms);
                if wdt_count >= WDT_SAFE_MODE_THRESHOLD {
                    safe_mode = true;
                    warn!(
                        "SAFE MODE: {} WDT resets in {} ms — mining suppressed. \
                         POST /api/system/clear-safe-mode to recover.",
                        wdt_count,
                        now_ms.saturating_sub(wdt_since_ms)
                    );
                }
            } else if reset_reason == sys::esp_reset_reason_t_ESP_RST_POWERON
                || reset_reason == sys::esp_reset_reason_t_ESP_RST_SW
            {
                // Clean boot — reset the window if it's stale.
                if since != 0 && now_ms.saturating_sub(since) > WDT_WINDOW_MS {
                    nvs_config::save_wdt_counters(&mut nvs, 0, 0);
                    wdt_count = 0;
                    wdt_since_ms = 0;
                } else {
                    wdt_count = count;
                    wdt_since_ms = since;
                }
            }
        }
    }

    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let sysloop = EspSystemEventLoop::take().expect("Failed to take event loop");

    // On-board SX1262 LoRa radio bus (DEFAULT-OFF `lora` feature). Acquire the
    // dedicated SPI3/HSPI host + the 9 control GPIOs (netlist-locked 9/9 on
    // DCENT_axe BM1397: 5/6/7/15/16/21/8 + TXEN=2/RXEN=9) up front, before the
    // rest of main consumes `peripherals`. Fail-soft: a bus-init error leaves
    // `lora_bus=None`, the task never spawns, mining is unaffected.
    // ⚠️ Integration seam — SPI transport NEEDS-VERIFY on silicon (esp-idf-hal);
    // pin map is LOCKED vs the BM1397 netlist (FULL_PREFAB_REVIEW 2026-07-11).
    #[cfg(feature = "lora")]
    let lora_bus = match dcentaxe_hal::lora_pins::open_lora_bus(
        peripherals.spi3,
        peripherals.pins.gpio5.into(),
        peripherals.pins.gpio6.into(),
        peripherals.pins.gpio7.into(),
        peripherals.pins.gpio15.into(),
        peripherals.pins.gpio16.into(),
        peripherals.pins.gpio21.into(),
        peripherals.pins.gpio8.into(),
        Some(peripherals.pins.gpio2.into()),
        Some(peripherals.pins.gpio9.into()),
    ) {
        Ok(bus) => Some(bus),
        Err(e) => {
            warn!("LoRa: SPI3 bus init failed ({e:?}) — mesh disabled, mining continues");
            None
        }
    };

    // ======================================================================
    // Step 3: Early I2C + display init
    // ======================================================================
    // I2C pins selected at compile time by board feature.
    // BitAxe=47/48, Nerd=18/17, Hammer=44/43 (SDA/SCL).
    #[cfg(feature = "pins-bitaxe")]
    let mut i2c = I2cBus::new_default(
        peripherals.i2c0,
        peripherals.pins.gpio47,
        peripherals.pins.gpio48,
    )
    .expect("I2C init failed");
    #[cfg(feature = "pins-nerd")]
    let mut i2c = I2cBus::new_default(
        peripherals.i2c0,
        peripherals.pins.gpio18,
        peripherals.pins.gpio17,
    )
    .expect("I2C init failed");
    #[cfg(any(feature = "pins-hammer-bc", feature = "pins-hammer-dc"))]
    let mut i2c = I2cBus::new_default(
        peripherals.i2c0,
        peripherals.pins.gpio44,
        peripherals.pins.gpio43,
    )
    .expect("I2C init failed");

    // Display init (SSD1306 OLED for BitAxe, no-op stub for headless boards)
    let mut display = Ssd1306Display::new();
    if let Err(e) = display.init(&mut i2c) {
        warn!("OLED display not available: {} — continuing without it", e);
    } else {
        // ── Startup Animation: Mining creature wakes up! ──
        let boot_frames = [
            ("(-.-)zzZ", "Waking up..."),
            ("(o_o)", "Hmm?"),
            ("(^_^)", "Time to mine!"),
            ("[>_]#", "Let's hash!"),
        ];
        for (face, msg) in &boot_frames {
            display.show_status(
                &mut i2c,
                &format!("DCENT_axe v{}", VERSION),
                face,
                msg,
                "D-Central Tech.",
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        // Brief flash effect on boot
        display.invert_display(&mut i2c, true);
        std::thread::sleep(Duration::from_millis(80));
        display.invert_display(&mut i2c, false);

        display.show_status(
            &mut i2c,
            &format!("DCENT_axe v{}", VERSION),
            "D-Central Tech.",
            // P1-O2: the panel speaks the dashboard's truth ladder from its
            // very first frame. The web pill first-paints PENDING for the same
            // reason: no telemetry yet is UNKNOWN, not "off".
            //
            // Round 2 (critic finding 1): RUNG first, detail second, like the
            // other three init screens. The first word on the very first frame
            // an operator ever sees is now the state, not the label "Mining:".
            // 21 of 21 columns exactly - rung_status_line degrades to a bare
            // PENDING if that ever stops fitting, it never clips.
            &rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry"),
            "Booting...",
        );
    }

    // ======================================================================
    // Step 4: Load config from NVS — or enter provisioning
    // ======================================================================
    let nvs_for_prov = nvs_partition.clone();
    let (saved_config, mut nvs_handle) = nvs_config::load_config(nvs_partition.clone());
    let saved_configured = saved_config
        .as_ref()
        .map(|cfg| cfg.is_configured())
        .unwrap_or(false);
    let force_setup_mode = nvs_handle.get_u8("force_setup").ok().flatten().unwrap_or(0) != 0;
    // Owner claim is a first-run gate — it forces a just-powered-on miner with
    // an empty NVS into captive-portal mode so a random passerby can't hit
    // "Save" on a device that has no password. Once the user has saved WiFi
    // credentials (saved_configured), the device is physically claimed and
    // the password stays genuinely optional.
    //
    // AOTA-4: `claim_skip` is a reserved opt-out flag that NO handler currently
    // writes (it always reads back 0). In particular /api/auth/owner-reset
    // deliberately preserves WiFi/pool config and does NOT force re-claim
    // (api.rs owner-reset clears only the password), so a reset device stays
    // passwordless-but-writable for ordinary settings. That is intentional and
    // safe because OTA flashing and the unsigned-OTA toggle are independently
    // fail-closed while passwordless: the OTA handler and shared-config gate go
    // through `ota_signature::ota_signature_enforced` /
    // `ota_signature::owner_action_authorized`, which never let an
    // unauthenticated caller waive signature verification or flip
    // `allow_unsigned_ota`. So a reset (passwordless) device cannot be coerced
    // into an unsigned-OTA RCE. The read below stays for forward compatibility
    // if a future handler ever sets the flag.
    let owner_claim_skipped = nvs_handle.get_u8("claim_skip").ok().flatten().unwrap_or(0) != 0;
    let owner_claim_required = !saved_configured
        && !crate::auth::password_is_set_in_nvs(&mut nvs_handle)
        && !owner_claim_skipped;

    let (mut config, mut nvs_handle): (DcentAxeConfig, _) = match saved_config {
        Some(cfg) if cfg.is_configured() && !force_setup_mode && !owner_claim_required => {
            info!(
                "NVS config loaded: SSID='{}', pool={}:{}",
                cfg.wifi_ssid,
                crate::shared::sanitize_pool_url(&cfg.stratum.url),
                cfg.stratum.port
            );
            (cfg, nvs_handle)
        }
        _ => {
            if force_setup_mode {
                info!("Forced setup mode requested — entering WiFi setup mode (AP captive portal)");
            } else if owner_claim_required && saved_configured {
                warn!("Saved config found without owner claim — entering setup mode to secure the miner");
            } else {
                info!("No saved config (or empty SSID) — entering WiFi setup mode (AP captive portal)");
            }
            display.show_status(
                &mut i2c,
                &format!("DCENT_axe v{}", VERSION),
                if force_setup_mode {
                    "Setup mode requested"
                } else if owner_claim_required && saved_configured {
                    "Owner claim required"
                } else {
                    "No config found"
                },
                "Starting setup...",
                "",
            );
            let config = provisioning::run_provisioning(
                peripherals.modem,
                sysloop.clone(),
                nvs_for_prov,
                nvs_handle,
                &mut display,
                &mut i2c,
            );
            // run_provisioning reboots after saving — unreachable, but just in case:
            unreachable!("Provisioning should have rebooted");
        }
    };

    config.canonicalize_identity();

    // ══ Lucky-enablement SPEC §3 — fail-closed boot identity gate ═══════════
    // Runs HERE because this is the earliest point with everything it needs
    // and the latest point that is still provably safe:
    //  * AFTER config load + canonicalize_identity (the stored identity tuple
    //    — board_version / board_model / miner_model — is final), and after
    //    I2C init (Step 3), so the AMBIGUOUS branch can run the READ-ONLY
    //    PMBus 0x7F/0x14 LV08 probe;
    //  * BEFORE `validate_safety` (which checks `identity_refusal` FIRST) and
    //    therefore before `mining_permitted` is computed, before
    //    `gpio_ctrl.enable_buck(true)`, before `PowerManager::new`, and before
    //    any `set_voltage` — the core rail is still OFF, so a refusal here
    //    means the rail is NEVER energized under a misidentified profile
    //    (the 302→Hex-Ultra 3.6 V trap).
    // The probe closure is only invoked from the gate's AMBIGUOUS branch
    // (structural contract in `config::resolve_identity_gate`); a genuine
    // BitAxe Hex Ultra with a missing/garbled devicemodel reaches that branch
    // and is SAVED by the probe answering NoSecondaryRegulators — never
    // refused on strings alone.
    match config.run_identity_gate(|| {
        Some(dcentaxe_hal::power::probe_lucky_lv08_secondary_regulators(&mut i2c).verdict)
    }) {
        crate::config::IdentityGateOutcome::Proceed => {}
        crate::config::IdentityGateOutcome::AdoptProfile(row) => {
            info!(
                "Identity gate: stored identity (bv='{}', dm='{}', mm='{}') resolves to \
                 canonical board {} ({}) — adopting and persisting",
                config.board_version,
                config.board_model,
                config.miner_model,
                row.board_version,
                row.device_model,
            );
            config.apply_identity_profile(row);
            if let Err(e) = nvs_config::save_config(&mut nvs_handle, &config) {
                // Non-fatal: the gate re-resolves identically on every boot.
                warn!("Identity gate: failed to persist adopted identity: {e}");
            }
        }
        crate::config::IdentityGateOutcome::RefuseToEnergize { reason } => {
            error!("Identity gate REFUSED TO ENERGIZE: {reason}");
            config.identity_refusal = Some(reason);
        }
    }

    // Hammer DC rows are already resolved by the string gate above, so their
    // TMP75 address strap is a separate verification step. The config layer
    // model-gates the closure before any address is touched: 0x48/0x4C are not
    // globally unique. The HAL primitive performs only zero-byte ACK probes.
    match config.run_identity_strap_gate(|expected_addr| {
        Some(
            dcentaxe_hal::hammer_strap_probe::probe_hammer_identity_strap(&mut i2c, expected_addr)
                .verdict,
        )
    }) {
        crate::config::IdentityStrapGateOutcome::Proceed => {}
        crate::config::IdentityStrapGateOutcome::RefuseToEnergize { reason } => {
            error!("Hammer identity-strap gate REFUSED TO ENERGIZE: {reason}");
            if config.identity_refusal.is_none() {
                config.identity_refusal = Some(reason);
            }
        }
    }

    let unsafe_lab_safety_bypass = unsafe_lab_safety_bypass_enabled();
    if unsafe_lab_safety_bypass {
        warn!("UNSAFE LAB SAFETY BYPASS ENABLED: thermal/custom-board safety gates may be relaxed");
    }
    let mut config_safety_error = config.validate_safety(unsafe_lab_safety_bypass).err();
    if let Err(e) = nvs_config::update_ota_floor_if_newer(&mut nvs_handle, VERSION) {
        warn!("Failed to seed OTA rollback floor: {}", e);
    }
    let qualified_boot_point = config.qualify_operating_point(
        config.target_frequency,
        config.target_voltage_mv,
        crate::config::ControlSurface::BootRestore,
    );
    if qualified_boot_point.refused {
        let reason = format!(
            "boot-restored voltage {}mV is outside the registered board envelope; \
             preserving stored evidence and refusing mining",
            config.target_voltage_mv
        );
        error!("{reason}");
        if config_safety_error.is_none() {
            config_safety_error = Some(reason);
        }
    } else if qualified_boot_point.clamped {
        warn!(
            "Boot config clamped to qualified envelope: {:.2}MHz/{}mV -> {:.2}MHz/{}mV",
            config.target_frequency,
            config.target_voltage_mv,
            qualified_boot_point.frequency_mhz,
            qualified_boot_point.voltage_mv
        );
        config.target_frequency = qualified_boot_point.frequency_mhz;
        config.target_voltage_mv = qualified_boot_point.voltage_mv;
        if let Err(e) = nvs_config::save_config(&mut nvs_handle, &config) {
            warn!("Failed to persist qualified boot config: {}", e);
        }
    }
    if let Some(ref e) = config_safety_error {
        error!("Config safety validation failed: {}", e);
    }

    let mut board_config = config.board_config();
    let asic_model = config.asic_model();
    let asic_count = if config.asic_count > 0 {
        config.asic_count
    } else {
        config.expected_asic_count()
    };
    let power_limits = config.power_limits();

    // Hardware-relative Speed Demon threshold (~80% of rated peak GH/s)
    // Scale by ASIC count for multi-chip boards (Hex = 6x, GT = 2x, etc.)
    let speed_demon_threshold: f64 = {
        let per_chip = match asic_model {
            dcentaxe_asic::AsicModel::BM1370 | dcentaxe_asic::AsicModel::BM1373 => 1000.0,
            dcentaxe_asic::AsicModel::BM1368 => 500.0,
            dcentaxe_asic::AsicModel::BM1366 => 400.0,
            dcentaxe_asic::AsicModel::BM1397 => 300.0,
            // Scrypt achievement thresholds are on a different scale entirely
            // (MH/s, and a different diff-1 constant). f64::INFINITY keeps the
            // badge unreachable rather than trivially granted by a SHA-256
            // threshold applied to Scrypt difficulty numbers.
            dcentaxe_asic::AsicModel::Lt0051 => f64::INFINITY,
        };
        per_chip * asic_count as f64
    };

    // Apply display orientation from config
    if config.display_inverted {
        let _ = display.set_flip(&mut i2c, true);
    }

    if config.overclock_enabled {
        info!(
            "OVERCLOCK MODE ENABLED — max {:.0}W, {:.0}A, {:.0}MHz",
            power_limits.max_power_w, power_limits.max_current_a, power_limits.max_frequency
        );
    } else {
        info!(
            "Safe mode — max {:.0}W, {:.0}A, {:.0}MHz (5V/6A PSU)",
            power_limits.max_power_w, power_limits.max_current_a, power_limits.max_frequency
        );
    }

    // ======================================================================
    // Step 4: WiFi connect (with NVS-backed retry counter)
    // ======================================================================
    let wifi_retries = {
        let p = nvs_partition.clone();
        if let Ok(nvs) =
            esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(p, "dcentaxe", true)
        {
            nvs.get_u8("wifi_retries").ok().flatten().unwrap_or(0)
        } else {
            0
        }
    };

    display.show_status(
        &mut i2c,
        &format!("DCENT_axe v{}", VERSION),
        &format!("WiFi: {}", config.wifi_ssid),
        "Connecting...",
        "",
    );

    let wifi_handle = match wifi::connect_wifi(
        peripherals.modem,
        sysloop.clone(),
        nvs_partition.clone(),
        &config.wifi_ssid,
        &config.wifi_password,
    ) {
        Ok(wifi) => {
            info!("WiFi connected to '{}'", config.wifi_ssid);
            // Reset recovery flags on success.
            if wifi_retries > 0 || force_setup_mode {
                let p = nvs_partition.clone();
                if let Ok(mut nvs) = esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(
                    p, "dcentaxe", true,
                ) {
                    let _ = nvs.set_u8("wifi_retries", 0u8);
                    let _ = nvs.remove("force_setup");
                }
            }
            wifi
        }
        Err(e) => {
            error!("WiFi failed: {}", e);

            // Show failure reason on OLED before switching to recovery setup mode.
            let reason = if format!("{}", e).contains("timeout") {
                "Timeout"
            } else if format!("{}", e).contains("auth") || format!("{}", e).contains("password") {
                "Auth failed"
            } else {
                "Connection error"
            };
            display.show_status(
                &mut i2c,
                &format!("DCENT_axe v{}", VERSION),
                "WiFi failed",
                reason,
                "Starting setup mode",
            );

            let nvs_p = nvs_partition.clone();
            if let Ok(mut nvs) = esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(
                nvs_p, "dcentaxe", true,
            ) {
                let _ = nvs.set_u8("wifi_retries", wifi_retries.saturating_add(1));
                let _ = nvs.set_u8("force_setup", 1u8);
                info!("Marked forced setup mode for next boot");
            }

            std::thread::sleep(Duration::from_secs(2));
            unsafe {
                sys::esp_restart();
            }
            unreachable!();
        }
    };

    // Extract IP address from WiFi netif for OLED display and logging
    let device_ip: String = wifi_handle
        .sta_netif()
        .get_ip_info()
        .map(|info| format!("{}", info.ip))
        .unwrap_or_else(|_| "?.?.?.?".into());
    info!("Device IP: {}", device_ip);

    let _sntp = match esp_idf_svc::sntp::EspSntp::new_default() {
        Ok(service) => {
            info!("SNTP: started for wall-clock schedule support");
            Some(service)
        }
        Err(e) => {
            warn!("SNTP: unavailable ({:?}) — schedules will use uptime fallback until clock is valid", e);
            None
        }
    };

    // ======================================================================
    // W5500 SPI-Ethernet bring-up — "DCENT LAN Mod" (PLAN-E Phase 1)
    // ======================================================================
    // DEFAULT-OFF twice over: requires the `eth-w5500` build feature AND the
    // operator's `config.network.eth_enabled` opt-in. Activation is
    // fail-closed through the existing AccessoryMode guard (W5500 SPI rides
    // the BAP-UART pins GPIO39/40 — LAN xor BAP-Touch), and consumes ONLY
    // the 4 BAP/J4 SPI pins + the free SPI2 host (LoRa keeps SPI3; RST is an
    // on-board RC POR; INT is unwired → polling). Fail-soft like LoRa: any
    // bring-up error leaves Ethernet dark and mining unaffected.
    // ⚠️ Integration seam — NEEDS-VERIFY on silicon; live link + accepted
    // share over Ethernet are bench-gated (PLAN-E Phase 3).
    #[cfg(feature = "eth-w5500")]
    let eth_net_mode = config.network.mode;
    #[cfg(feature = "eth-w5500")]
    let eth_link = match config.eth_lan_activation() {
        Ok(false) => {
            info!(
                "ETH: eth-w5500 firmware but network.eth_enabled=false (or mode=wifi-only) — \
                 Ethernet stays dark"
            );
            None
        }
        Err(guard) => {
            warn!(
                "ETH: W5500 LAN refused by accessory guard: {guard} — Wi-Fi only, \
                 mining unaffected"
            );
            None
        }
        Ok(true) => {
            if eth_net_mode == config::NetworkMode::EthOnly {
                warn!(
                    "ETH: mode=eth-only — Wi-Fi STA stays up as management fallback in this \
                     build (Wi-Fi teardown under eth-only is a documented follow-up)"
                );
            }
            match eth_w5500::EthLink::bring_up(
                peripherals.spi2,
                peripherals.pins.gpio41.into(), // SCLK (J4 pin 5) — dcentaxe_hal::eth::W5500_SCLK_GPIO
                peripherals.pins.gpio40.into(), // MOSI (J4 pin 4) — W5500_MOSI_GPIO
                peripherals.pins.gpio39.into(), // MISO (J4 pin 3) — W5500_MISO_GPIO
                peripherals.pins.gpio42.into(), // CS   (J4 pin 6) — W5500_CS_GPIO
                sysloop.clone(),
                eth_net_mode,
            ) {
                Ok(link) => Some(link),
                Err(e) => {
                    warn!("ETH: W5500 bring-up failed ({e}) — Wi-Fi only, mining unaffected");
                    None
                }
            }
        }
    };

    display.show_status(
        &mut i2c,
        &format!("DCENT_axe v{}", VERSION),
        "WiFi connected!",
        &format!("IP: {}", device_ip),
        "Connecting to pool...",
    );

    // mDNS: requires esp-idf-sys to compile with mDNS component
    // TODO: Add ESP_IDF_COMPONENTS="mdns" to .cargo/config.toml [env] section
    {
        let hostname = if config.hostname.is_empty() {
            format!("dcentaxe-{}", board_config.device_model)
        } else {
            config.hostname.clone()
        };
        info!(
            "mDNS: {}.local (component not yet linked — access via IP: {})",
            hostname, device_ip
        );
    }
    // Allow OLED to display IP for 2 seconds so user can note it down
    std::thread::sleep(Duration::from_millis(2000));

    // ======================================================================
    // Step 5: Shared state (for API, dashboard, MCP, autotuner)
    // ======================================================================
    let state = SharedState::new(config.clone(), &board_config, nvs_handle);
    {
        let mut wifi = state.wifi.lock().unwrap_or_else(|e| e.into_inner());
        *wifi = Some(wifi_handle);
    }
    {
        let live_config = state.config.lock().unwrap_or_else(|e| e.into_inner());
        let local_id = {
            let mut mac = [0u8; 6];
            unsafe {
                esp_idf_svc::sys::esp_wifi_get_mac(
                    esp_idf_svc::sys::wifi_interface_t_WIFI_IF_STA,
                    mac.as_mut_ptr(),
                );
            }
            format!(
                "bitaxe-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )
        };
        let mut swarm = state.swarm.lock().unwrap_or_else(|e| e.into_inner());
        swarm.local.id = local_id;
        swarm.local.hostname = if live_config.hostname.is_empty() {
            format!("dcentaxe-{}", board_config.device_model)
        } else {
            live_config.hostname.clone()
        };
        swarm.local.display_name = board_config.model.name().to_string();
        swarm.local.board_model = board_config.device_model.clone();
        swarm.local.board_version = board_config.board_version.clone();
        swarm.local.board_target = board_config.model.board_target().to_string();
        swarm.local.asic_model = board_config.asic_model.clone();
        swarm.local.ip = device_ip.clone();
        swarm.discovery.mdns_hostname = Some(format!("{}.local", swarm.local.hostname));
        swarm.discovery.api_url = Some(format!("http://{}/api/swarm", device_ip));
        swarm.discovery.mcp_url = Some(format!("http://{}/mcp", device_ip));
        swarm.discovery.mdns_enabled = true;
        swarm.discovery.discovery_hint = "mDNS advertising _dcentaxe._tcp".to_string();
    }

    // Seed peers + queen_id from NVS so we rejoin the cluster quickly after
    // a reboot. The mDNS thread (spawned later) refreshes on its first tick.
    swarm::load_persisted(&state);
    // Kick the background swarm worker: mDNS advertise + query + election
    // + NVS persistence. Non-blocking; failures log but don't panic.
    swarm::start(state.clone());

    // Last-known pool difficulty (primes ASIC TicketMask at boot, ESP-Miner PR #1594).
    let mut cached_pool_difficulty: f64 = 0.0;
    // Load all-time best share difficulty + achievements + streak + lifetime shares from NVS
    let (
        mut achievements,
        mut best_streak_ever,
        mut lifetime_shares,
        mut best_nonce_val,
        mut best_nonce_diff,
    ) = {
        let nvs_for_load = nvs_partition.clone();
        if let Ok(nvs) = esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(
            nvs_for_load,
            "dcentaxe",
            true,
        ) {
            let best_diff_ever = nvs_config::load_best_diff(&nvs);
            if let Some(lkg) = nvs_config::load_last_known_good(&nvs) {
                let mut at = state.autotuner.lock().unwrap_or_else(|e| e.into_inner());
                at.last_good_frequency = lkg.frequency_mhz;
                at.last_good_voltage_mv = lkg.voltage_mv;
                at.last_good_jth = lkg.jth;
                at.last_good_error_rate = lkg.delta_error_rate;
                at.silicon_grade = if lkg.delta_error_rate <= 0.002 && lkg.jth <= 16.5 {
                    "gold"
                } else if lkg.delta_error_rate <= 0.01 && lkg.jth <= 18.5 {
                    "strong"
                } else if lkg.delta_error_rate <= 0.02 {
                    "normal"
                } else {
                    "spicy"
                }
                .to_string();
            }
            let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.best_diff_ever = best_diff_ever;
            let ach = nvs_config::load_achievements(&nvs);
            let streak = nvs_config::load_best_streak(&nvs);
            let lt_shares = nvs_config::load_lifetime_shares(&nvs);
            let (bn_val, bn_diff) = nvs_config::load_best_nonce(&nvs);
            cached_pool_difficulty = nvs_config::load_cached_pool_difficulty(&nvs);
            let (stage_name, _) = nvs_config::evolution_stage(lt_shares);
            info!("NVS: achievements=0x{:08X} ({} unlocked), best_streak={}, lifetime_shares={} ({}), best_nonce=0x{:08X}, cached_diff={:.3}",
                ach, nvs_config::achievement_count(ach), streak, lt_shares, stage_name, bn_val, cached_pool_difficulty);
            (ach, streak, lt_shares, bn_val, bn_diff)
        } else {
            let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.best_diff_ever = 0.0;
            (0u32, 0u32, 0u32, 0u32, 0.0f64)
        }
    };
    // Set reset reason + safe-mode + coredump presence in telemetry.
    {
        let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
        telem.reset_reason = match reset_reason {
            sys::esp_reset_reason_t_ESP_RST_POWERON => "Power-on",
            sys::esp_reset_reason_t_ESP_RST_SW => "Software",
            sys::esp_reset_reason_t_ESP_RST_PANIC => "Panic",
            sys::esp_reset_reason_t_ESP_RST_INT_WDT => "Interrupt watchdog",
            sys::esp_reset_reason_t_ESP_RST_TASK_WDT => "Task watchdog",
            sys::esp_reset_reason_t_ESP_RST_WDT => "Other watchdog",
            sys::esp_reset_reason_t_ESP_RST_DEEPSLEEP => "Deep sleep",
            sys::esp_reset_reason_t_ESP_RST_BROWNOUT => "Brownout",
            sys::esp_reset_reason_t_ESP_RST_SDIO => "SDIO",
            _ => "Unknown",
        }
        .to_string();
        telem.safe_mode = safe_mode;
        telem.wdt_reset_count = wdt_count;
        let mut out_addr: usize = 0;
        let mut out_size: usize = 0;
        let rc = unsafe { sys::esp_core_dump_image_get(&mut out_addr, &mut out_size) };
        telem.coredump_present = rc == 0 && out_size > 0;
    }
    let shared_mining_stats = state.stats.clone();

    // ======================================================================
    // Step 6: HAL init
    // ======================================================================

    // GPIO — buck enable pin depends on board model.
    //
    // The LDO enable is part of the KEY, not an afterthought applied to a
    // matched controller. A board that declares one and reaches an arm that
    // does not bind it would boot with a perfectly configured core rail and a
    // chain that never answers — the exact silent failure `LdoEnable` was
    // written to make impossible. Keeping it in the tuple means such a board
    // hits the `pins` fallback instead.
    let mut gpio_ctrl = match (
        board_config.asic_reset_pin,
        board_config.buck_enable_pin,
        board_config.led_pin,
        board_config.ldo_enable_pin,
    ) {
        // The multi-phase Nerd line: TPS5364x EN on GPIO10 plus the LDO bank on
        // GPIO13. Both rails feed the dies; see `board::LdoEnable`.
        (1, 10, 4, 13) => GpioController::new_with_ldo(
            peripherals.pins.gpio1,
            peripherals.pins.gpio10,
            peripherals.pins.gpio4,
            peripherals.pins.gpio13,
            board_config.buck_enable_active_low,
        ),
        (1, 10, 4, -1) => GpioController::new(
            peripherals.pins.gpio1,
            peripherals.pins.gpio10,
            peripherals.pins.gpio4,
            board_config.buck_enable_active_low,
        ),
        (1, 46, 4, -1) => GpioController::new(
            peripherals.pins.gpio1,
            peripherals.pins.gpio46,
            peripherals.pins.gpio4,
            board_config.buck_enable_active_low,
        ),
        // Hammer BC01/BC01-Pro/BC02/BC04 + DC04/DC06. GPIO46 is ST7789 D5,
        // so these models deliberately bind no discrete buck-enable output.
        (1, -1, 4, -1) => {
            GpioController::new_without_buck(peripherals.pins.gpio1, peripherals.pins.gpio4)
        }
        // Hammer DC02: reset is GPIO3 and no discrete buck-enable is verified.
        // GPIO 1 is its fan TACH input; GPIO46 is ST7789 panel D5.
        //
        // Gated off `temp-tmp451` images: that feature binds GPIO3 as NerdQX
        // TMP451 mux A1, and a runtime match cannot make the two moves exclusive.
        // The compile_error above refuses `pins-hammer-dc` + `temp-tmp451`.
        #[cfg(not(feature = "temp-tmp451"))]
        (3, -1, 4, -1) => {
            GpioController::new_without_buck(peripherals.pins.gpio3, peripherals.pins.gpio4)
        }
        // BitForge Nano: the LED is GPIO9, NOT the stock BitAxe GPIO4 — GPIO4
        // on this board is `/TMP_10K_A2`, the ASIC-2 NTC divider node, so
        // binding it as an LED output would drive a thermistor divider. Both
        // the netlist and forge-os (`self_test.c:49` `BLINK_GPIO_1 9`) agree.
        // No discrete buck-enable: `GPIO_ASIC_ENABLE` is defined in three
        // vendor files and never driven; the rail is TPS546A24 PMBus only.
        //
        // ⚠ `cfg(not(lora))` is LOAD-BEARING, and not because this board has an
        // opinion about LoRa. This `match` is on RUNTIME values, so every arm is
        // compiled into every image — a runtime match cannot make two pin moves
        // mutually exclusive the way `#[cfg]` can. The LoRa bus takes
        // `gpio9` (RXEN) unconditionally near the top of `main`, so leaving this
        // arm ungated made `peripherals.pins.gpio9` move twice and broke the
        // build of EVERY `--features lora` image, on every board, not just this
        // one. The paired `compile_error!` at the top of this file is what keeps
        // gating the arm honest: it forbids `bitforge-nano` + `lora` outright, so
        // the arm can never be missing in a build that would actually need it
        // (a missing arm falls to the `panic!` below = panic=abort = boot loop).
        #[cfg(not(feature = "lora"))]
        (1, -1, 9, -1) => {
            GpioController::new_without_buck(peripherals.pins.gpio1, peripherals.pins.gpio9)
        }
        pins => panic!("Unsupported board GPIO mapping: {:?}", pins),
    }
    .expect("GPIO init failed");

    // XPSAFE-1: arm the panic hook's buck-cut now that the enable GPIO is a
    // configured output. Buck is still OFF here, so a hook firing before
    // `enable_buck(true)` is a harmless no-op; from this point on, ANY panic
    // drives the rail OFF before the abort / coredump / reboot.
    PANIC_BUCK_GPIO.store(board_config.buck_enable_pin, Ordering::Release);
    PANIC_BUCK_ACTIVE_LOW.store(board_config.buck_enable_active_low, Ordering::Release);

    let mut mining_permitted = true;
    let mut mining_block_reason: Option<BlockReason> = None;

    if let Some(_e) = config_safety_error.clone() {
        mining_permitted = false;
        mining_block_reason = Some(BlockReason::ConfigUnsafe);
    }

    if safe_mode {
        mining_permitted = false;
        mining_block_reason = Some(BlockReason::SafeModeWdt);
    }

    let power_gate_permitted = if board_config.plug_sense {
        match board_config.plug_sense_pin {
            #[cfg(feature = "pins-bitaxe")]
            12 => match gpio::PinDriver::input(peripherals.pins.gpio12, gpio::Pull::Down) {
                Ok(plug_sense) => {
                    if plug_sense.is_high() {
                        info!("Plug sense HIGH on GPIO12 — external power present");
                        true
                    } else {
                        warn!("Plug sense LOW on GPIO12 — gating power {}", "closed");
                        false
                    }
                }
                Err(e) => {
                    warn!("Plug sense GPIO init failed: {:?}", e);
                    false
                }
            },
            _ => false,
        }
    } else {
        true
    };

    if !power_gate_permitted {
        mining_permitted = false;
        mining_block_reason = Some(BlockReason::NoPlugSense);
        error!("Power input not detected by plug-sense gate — mining disabled");
    }

    // Temperature sensor + Fan controller
    // Hex boards: EMC2302 (0x2F) dual fan + TMP1075 for temp
    // Single-ASIC boards: EMC2101 (0x4C) fan+temp or EMC2103 (0x2E)
    let boot_fan_pct = config.fan_speed_pct.clamp(20, 100);
    let mut temp_emc = None;
    let mut fan_is_emc2103 = false;
    let mut emc2103: Option<Emc2103> = None;
    let mut fan_emc2302: Option<Emc2302> = None;

    // Boards whose thermal sensor sits behind an I2C BUS multiplexer cannot be
    // read at all until a channel is connected, so this runs BEFORE any sensor
    // or fan-controller transaction below. Declared per board by
    // `BitAxeModel::thermal_i2c_mux`, not branched on model here.
    //
    // The channel is selected once and left connected: nothing else on these
    // boards lives downstream of the mux, and our model drives ONE controller
    // at one duty (which is what the vendor firmware does too). A mux that
    // later drops its selection makes subsequent reads NAK — a loud failure
    // that the existing fail-closed thermal path already handles — rather than
    // silently returning the other ASIC's die temperature.
    if let Some(mux_cfg) = board_config.model.thermal_i2c_mux() {
        match select_thermal_mux_channel(&mut i2c, mux_cfg) {
            Ok(()) => info!(
                "Thermal I2C mux 0x{:02X}: channel {} connected",
                mux_cfg.addr, mux_cfg.channel
            ),
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::ThermalMux);
                error!(
                    "Thermal I2C mux 0x{:02X} channel {} select failed: {} — mining disabled \
                     (no trusted temperature is reachable on this board without it)",
                    mux_cfg.addr, mux_cfg.channel, e
                );
            }
        }
    }

    // ── TMP451 per-ASIC diode mux ──────────────────────────────────────────
    // Declared by `BitAxeModel::tmp451_diode_mux()`. On a board that declares
    // one, these ARE the die sensors: the row's own `temp_sensor` (a TMP1075)
    // measures airflow, ~10-20 C below a junction. So a failure to bring the
    // mux up is not a degraded mode, it is thermal blindness, and it disables
    // mining exactly like the bus-mux failure above.
    #[cfg(feature = "temp-tmp451")]
    let mut diode_mux: Option<DiodeMuxSweep> = None;
    #[cfg(feature = "temp-tmp451")]
    if let Some(decl) = board_config.model.tmp451_diode_mux() {
        use dcentaxe_hal::board::Tmp451SelectLines;
        use dcentaxe_hal::tmp451::{MuxSelect, Tmp451};

        // The declared pin NUMBERS are data; the pin MOVE is a compile-time
        // fact. A `match` cannot make two moves exclusive (every arm compiles
        // into every image), so exactly one arm here binds pins and the rest
        // refuse. A board declaring different select lines therefore fails
        // closed and loudly, instead of being silently driven on the wrong two
        // GPIOs. Wiring such a board means adding its arm AND proving the pins
        // are free in every feature combination — see the `compile_error!`
        // pair at the top of this file.
        // `evaluate_thermal_muxed` carries no `gt_temp2` slot, because the die
        // readings arrive as a counted sweep rather than as two fixed sensors.
        // On a board that had BOTH, that second die reading would be silently
        // dropped from the fold — a hot die vanishing from `max_temp`. No board
        // in the registry pairs them; this refuses the pairing loudly instead of
        // letting a future row discover it as a missing overtemp cut.
        let selected =
            if board_config.fan_controller == dcentaxe_hal::board::FanControllerKind::Emc2103 {
                Err(
                "board declares a TMP451 diode mux AND an EMC2103, whose second die reading has \
                 no slot in the muxed thermal fold"
                    .to_string(),
            )
            } else {
                match decl.select {
                    #[cfg(feature = "nerdqx")]
                    Tmp451SelectLines::Gpio { a0: 2, a1: 3 } => MuxSelect::new(
                        peripherals.pins.gpio2.into(),
                        peripherals.pins.gpio3.into(),
                        decl.active_high,
                    )
                    .map_err(|e| e.to_string()),
                    #[cfg(not(feature = "nerdqx"))]
                    Tmp451SelectLines::Gpio { a0: 2, a1: 12 } => MuxSelect::new(
                        peripherals.pins.gpio2.into(),
                        peripherals.pins.gpio12.into(),
                        decl.active_high,
                    )
                    .map_err(|e| e.to_string()),
                    Tmp451SelectLines::Gpio { a0, a1 } => Err(format!(
                "board declares TMP451 mux select lines GPIO{}/GPIO{}, which this image has no \
                 binding for",
                a0, a1
            )),
                    Tmp451SelectLines::Expander { addr, a0, a1 } => Err(format!(
                "board declares TMP451 mux select lines on an FXL6408 expander at 0x{:02X} \
                 (pins {}/{}), and the expander transport is not implemented",
                addr, a0, a1
            )),
                }
            };

        match selected {
            Ok(select) => {
                let mut sensors = Vec::new();
                let mut failed: Vec<String> = Vec::new();
                for declared in decl.sensors {
                    match Tmp451::new(&mut i2c, declared.addr, decl.calibration) {
                        Ok(sensor) => {
                            info!(
                                "TMP451 0x{:02X}: {} channels covering ASICs {}..{}",
                                declared.addr,
                                declared.channels,
                                declared.first_asic,
                                declared.first_asic + declared.channels - 1
                            );
                            sensors.push((sensor, declared.first_asic, declared.channels));
                        }
                        Err(e) => failed.push(format!("0x{:02X}: {}", declared.addr, e)),
                    }
                }

                // Partial sensor bring-up is refused for the same reason a
                // partial sweep is blind: the dies behind the missing sensor
                // are unmeasured, and they share this board's rail and fan.
                if failed.is_empty() {
                    diode_mux = Some(DiodeMuxSweep {
                        select,
                        sensors,
                        expected_asics: board_config.asic_count,
                    });
                    // NerdQX: the mux answering IS the identity check. Raise
                    // the static clamped envelope to upstream nominal only
                    // after a positive bring-up — never from the row alone.
                    board_config.apply_nerdqx_tmp451_identity(true);
                } else {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::ThermalDieSensor);
                    error!(
                        "TMP451 diode mux: {} of {} sensors failed to initialize ({}) — mining \
                         disabled (these ARE this board's die sensors; the TMP1075 is an airflow \
                         proxy and cannot stand in for a junction temperature)",
                        failed.len(),
                        decl.sensors.len(),
                        failed.join("; ")
                    );
                }
            }
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::ThermalDieSensor);
                error!("TMP451 diode mux unavailable: {} — mining disabled", e);
            }
        }
    }

    match board_config.fan_controller {
        dcentaxe_hal::board::FanControllerKind::Emc2302 => match Emc2302::new_default(&mut i2c) {
            Ok(emc) => {
                let mut rpm1 = 0;
                let mut rpm2 = 0;
                if let Err(e) = emc.set_fan_speed(&mut i2c, boot_fan_pct) {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::FanSet);
                    error!("EMC2302 fan set failed: {} - mining disabled", e);
                } else {
                    std::thread::sleep(Duration::from_millis(500));
                    for _ in 0..5 {
                        rpm1 = emc.get_fan1_rpm(&mut i2c).unwrap_or(0);
                        rpm2 = emc.get_fan2_rpm(&mut i2c).unwrap_or(0);
                        // XPSAFE-8: stop as soon as every DECLARED fan has
                        // proven tach. With the default both-headers population
                        // this is the previous `rpm1 > 0 && rpm2 > 0`; with one
                        // header declared it avoids spending the full retry
                        // window waiting on a connector that is not populated.
                        if board_config.declared_fan_tach_proven(rpm1, rpm2) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(250));
                    }
                }
                info!(
                    "Fan at {}% (via EMC2302 dual fan) — RPM: fan1={}, fan2={}",
                    boot_fan_pct, rpm1, rpm2
                );
                emc.dump_diagnostics(&mut i2c);
                if let Ok(status) = emc.read_status(&mut i2c) {
                    let fan1_connected = rpm1 > 0;
                    let fan2_connected = rpm2 > 0;
                    let has_real_fault = (fan1_connected
                        && (status.fan1_stall || status.fan1_spin_fail || status.fan1_drive_fail))
                        || (fan2_connected
                            && (status.fan2_stall
                                || status.fan2_spin_fail
                                || status.fan2_drive_fail));
                    if has_real_fault {
                        warn!(
                            "EMC2302 fan fault: stall={}/{}, spin={}/{}, drive={}/{}",
                            status.fan1_stall,
                            status.fan2_stall,
                            status.fan1_spin_fail,
                            status.fan2_spin_fail,
                            status.fan1_drive_fail,
                            status.fan2_drive_fail
                        );
                    }
                }
                // XPSAFE-8: the tach requirement itself is UNCHANGED — this
                // board still must prove a tachometer. What is scoped is which
                // headers the proof is demanded from, so a unit running one fan
                // fails closed on the fan it actually has instead of failing
                // closed forever on a header that was never populated. With the
                // default both-headers population this is byte-for-byte the old
                // `rpm1 == 0 || rpm2 == 0`.
                if board_config.requires_fan_tach()
                    && !unsafe_lab_safety_bypass
                    && board_config.declared_fan_tach_missing(rpm1, rpm2)
                {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::FanNoTach);
                    error!(
                        "EMC2302 required tach absent at boot: fan1={}, fan2={} (declared \
                         population {:?}) - mining disabled",
                        rpm1, rpm2, board_config.fans_populated
                    );
                } else if board_config.requires_fan_tach()
                    && board_config.fans_populated != dcentaxe_hal::board::FanPopulation::Both
                {
                    // Surface the reduced redundancy explicitly: proof passed,
                    // but this unit has no second fan to fall back on.
                    warn!(
                        "EMC2302 tach proof OK on declared population {:?} (fan1={}, fan2={}) - \
                         mining permitted with NO fan redundancy; a single stall now relies on \
                         the thermal ladder",
                        board_config.fans_populated, rpm1, rpm2
                    );
                }
                fan_emc2302 = Some(emc);
                // XPSAFE-1: arm panic-hook cooling. EMC2302 dual fan on I2C0,
                // FAN1_SETTING=0x30 + FAN2_SETTING=0x40 (emc2302.rs), full-scale
                // 8-bit duty.
                arm_panic_fan(
                    0,
                    dcentaxe_hal::emc2302::EMC2302_ADDR,
                    0x30,
                    0x40,
                    2,
                    dcentaxe_hal::safety::fan_safe_panic_duty(),
                );
            }
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::FanInit);
                error!(
                    "EMC2302 init failed: {} — mining disabled until fan control is available",
                    e
                );
            }
        },
        dcentaxe_hal::board::FanControllerKind::Emc2101 => match Emc2101::new(&mut i2c, 0x4C) {
            Ok(emc) => {
                if let Err(e) = emc.init_fan(&mut i2c) {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::FanInit);
                    error!("EMC2101 fan init failed: {} — mining disabled", e);
                } else if let Err(e) = emc.set_fan_speed(&mut i2c, boot_fan_pct) {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::FanSet);
                    error!("EMC2101 fan set failed: {} — mining disabled", e);
                } else {
                    if board_config.emc_ideality_factor != 0 {
                        if let Err(e) =
                            emc.set_ideality_factor(&mut i2c, board_config.emc_ideality_factor)
                        {
                            warn!("EMC2101 ideality configuration failed: {}", e);
                        }
                        if let Err(e) =
                            emc.set_beta_compensation(&mut i2c, board_config.emc_beta_compensation)
                        {
                            warn!("EMC2101 beta compensation failed: {}", e);
                        }
                    }
                    // HALT-6 / XPSAFE-7: boot-time tach proof for opted-in EMC2101
                    // single-fan boards. The EMC2101 boot path previously had NO
                    // RPM readback (unlike the EMC2103/EMC2302 paths). When the
                    // operator has opted in (fan_tach_present=true ->
                    // tach_proof_required()), require a >0 RPM at boot so a
                    // never-spinning fan fails closed; genuinely tachless boards
                    // keep the lenient heuristic (no boot assert) and surface
                    // "no fan proof (heuristic only)" telemetry below.
                    if board_config.tach_proof_required()
                        && !unsafe_lab_safety_bypass
                        && boot_fan_pct > 0
                    {
                        let mut boot_rpm = 0u32;
                        std::thread::sleep(Duration::from_millis(350));
                        for _ in 0..3 {
                            boot_rpm = emc.read_fan_rpm(&mut i2c).unwrap_or(0);
                            if boot_rpm > 0 {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(150));
                        }
                        if boot_rpm == 0 {
                            mining_permitted = false;
                            mining_block_reason = Some(BlockReason::FanNoTach);
                            error!("EMC2101 tach stayed at 0 RPM during boot — mining disabled");
                        } else {
                            info!(
                                "EMC2101 boot tach proof OK ({} RPM at {}%)",
                                boot_rpm, boot_fan_pct
                            );
                        }
                    } else if !board_config.tach_proof_required() {
                        // No tach proof available/required on this board — the fan
                        // STALL kill is heuristic-only and the thermal ladder is the
                        // backstop. Surfaced in telemetry/self-test below.
                        info!(
                            "EMC2101 fan: no fan proof (heuristic only); thermal ladder is the backstop"
                        );
                    }
                    info!("Fan at {}% (via EMC2101)", boot_fan_pct);
                    temp_emc = Some(emc);
                    // XPSAFE-1: arm panic-hook cooling. EMC2101 on I2C0,
                    // FAN_SETTING=0x4C (temp.rs), 6-bit full-scale duty (63).
                    arm_panic_fan(
                        0,
                        dcentaxe_hal::temp::EMC2101_ADDR,
                        0x4C,
                        0,
                        1,
                        dcentaxe_hal::safety::emc2101_panic_duty(),
                    );
                }
            }
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::FanMissing);
                error!(
                    "Expected EMC2101 fan controller missing: {} — mining disabled",
                    e
                );
            }
        },
        dcentaxe_hal::board::FanControllerKind::Emc2103 => {
            if i2c.probe(0x2E) {
                info!("EMC2103 detected at 0x2E — GT/Gamma Turbo fan controller");
                let duty = (255u16 * boot_fan_pct as u16 / 100) as u8;
                let mut driver = Emc2103::new(0x2E, board_config.temp_flip);
                match driver.init(
                    &mut i2c,
                    duty,
                    board_config.emc_ideality_factor,
                    board_config.emc_beta_compensation,
                ) {
                    Ok(()) => {
                        let mut boot_rpm = 0;
                        if boot_fan_pct > 0 {
                            std::thread::sleep(Duration::from_millis(350));
                            for _ in 0..3 {
                                boot_rpm = driver.read_rpm(&mut i2c);
                                if boot_rpm > 0 {
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(150));
                            }
                        }
                        if boot_fan_pct > 0 && boot_rpm == 0 {
                            mining_permitted = false;
                            mining_block_reason = Some(BlockReason::FanNoTach);
                            error!("EMC2103 tach stayed at 0 RPM during boot — mining disabled");
                        } else {
                            info!(
                                "Fan at {}% (via EMC2103, duty={}, rpm={})",
                                boot_fan_pct, duty, boot_rpm
                            );
                            fan_is_emc2103 = true;
                            emc2103 = Some(driver);
                            // XPSAFE-1: arm panic-hook cooling. EMC2103 (GT) on
                            // I2C0 at 0x2E, FAN_SETTING=0x40 (emc2103.rs),
                            // full-scale 8-bit duty.
                            arm_panic_fan(
                                0,
                                0x2E,
                                dcentaxe_hal::emc2103::decode::REG_FAN_SETTING,
                                0,
                                1,
                                dcentaxe_hal::safety::fan_safe_panic_duty(),
                            );
                        }
                    }
                    Err(_) => {
                        mining_permitted = false;
                        mining_block_reason = Some(BlockReason::FanInit);
                        error!("EMC2103 init failed — mining disabled");
                    }
                }
            } else {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::FanMissing);
                error!("Expected EMC2103 fan controller missing — mining disabled");
            }
        }
        dcentaxe_hal::board::FanControllerKind::None => {}
    }

    // Fan state tracker + hardware write helper
    struct FanState {
        speed_pct: u8,
        rpm: u32,
    }
    let mut fan_ctrl = FanState {
        speed_pct: boot_fan_pct,
        rpm: 0,
    };
    // PID + EMA fan controller (ESP-Miner PR #1640 parity — see dcentaxe-hal::fan_pid).
    let mut fan_pid = dcentaxe_hal::fan_pid::FanPid::default();
    impl FanState {
        fn current_speed(&self) -> u8 {
            self.speed_pct
        }
        fn last_rpm(&self) -> u32 {
            self.rpm
        }
        fn set_speed(&mut self, pct: u8) -> Result<(), ()> {
            // Safety floor: never go below 20% while mining (fan_ever_seen guard
            // handles stall detection, but 0% fan while hashing = thermal runaway)
            self.speed_pct = pct.max(20).min(100);
            Ok(())
        }
    }
    /// Write fan speed to the actual hardware (EMC2302, EMC2101, or EMC2103).
    /// Call after fan_ctrl.set_speed() to apply the change.
    fn apply_fan_speed(
        i2c: &mut I2cBus,
        pct: u8,
        emc2302: &Option<Emc2302>,
        emc2101: &Option<Emc2101>,
        emc2103: &Option<Emc2103>,
    ) -> Result<(), String> {
        if let Some(ref emc) = emc2302 {
            emc.set_fan_speed(i2c, pct)
                .map_err(|e| format!("EMC2302 fan set failed: {}", e))?;
        } else if let Some(ref emc) = emc2101 {
            emc.set_fan_speed(i2c, pct)
                .map_err(|e| format!("EMC2101 fan set failed: {}", e))?;
        } else if let Some(ref emc) = emc2103 {
            emc.set_fan_speed(i2c, pct)
                .map_err(|e| format!("EMC2103 fan set failed: {}", e))?;
        }
        Ok(())
    }

    fn apply_fan_speed_or_fail_closed(
        i2c: &mut I2cBus,
        pct: u8,
        emc2302: &Option<Emc2302>,
        emc2101: &Option<Emc2101>,
        emc2103: &Option<Emc2103>,
        runtime_mining_active: bool,
        state: &SharedState,
        mining_kill: &Arc<AtomicBool>,
        power_mgr: &mut PowerManager,
        gpio_ctrl: &mut GpioController<'_>,
        reason: &str,
    ) -> bool {
        match apply_fan_speed(i2c, pct, emc2302, emc2101, emc2103) {
            Ok(()) => true,
            Err(e) => {
                error!("{}: {} - fan command not confirmed", reason, e);
                if runtime_mining_active {
                    fail_closed_power_off(
                        &format!("{} fan write failed: {}", reason, e),
                        state,
                        Some(mining_kill),
                        Some(power_mgr),
                        i2c,
                        gpio_ctrl,
                    );
                }
                false
            }
        }
    }

    fn apply_automatic_operating_point(
        state: &SharedState,
        power_mgr: &mut PowerManager,
        i2c: &mut I2cBus,
        freq_cmd_tx: &mpsc::Sender<f32>,
        last_applied_voltage: &mut u16,
        last_applied_freq: &mut f32,
        requested_frequency: f32,
        requested_voltage: u16,
        surface: ControlSurface,
        reason: &str,
    ) {
        let qualified = {
            let mut cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
            let qualified =
                cfg.qualify_operating_point(requested_frequency, requested_voltage, surface);
            if qualified.clamped {
                warn!(
                    "{} clamped operating point {:.0}MHz/{}mV -> {:.0}MHz/{}mV",
                    reason,
                    requested_frequency,
                    requested_voltage,
                    qualified.frequency_mhz,
                    qualified.voltage_mv
                );
            }
            cfg.target_frequency = qualified.frequency_mhz;
            cfg.target_voltage_mv = qualified.voltage_mv;
            qualified
        };

        let mut voltage_apply_ok = true;
        if qualified.voltage_mv != *last_applied_voltage {
            match power_mgr.set_voltage(i2c, qualified.voltage_mv) {
                Ok(()) => *last_applied_voltage = qualified.voltage_mv,
                Err(e) => {
                    voltage_apply_ok = false;
                    error!("{} voltage apply failed: {}", reason, e);
                }
            }
        }
        if (qualified.frequency_mhz - *last_applied_freq).abs() > 0.1 {
            let raises_frequency = qualified.frequency_mhz > *last_applied_freq;
            if raises_frequency && !voltage_apply_ok {
                warn!(
                    "{} frequency increase to {:.0} MHz skipped after voltage apply failure",
                    reason, qualified.frequency_mhz
                );
            } else {
                match freq_cmd_tx.send(qualified.frequency_mhz) {
                    Ok(()) => *last_applied_freq = qualified.frequency_mhz,
                    Err(e) => error!("{} frequency apply failed: {}", reason, e),
                }
            }
        }
    }

    // XPSAFE-5 — energize the rail the way THIS board's topology allows.
    //
    // The previous shape called `enable_buck(true)` unconditionally and treated
    // its `Err` as a failure. On a board with no enable GPIO that `Err` is not a
    // failure at all, it is the board reporting its own topology — and because
    // `mining_permitted` only ever ratchets false, the conflation left
    // NerdAxe-gamma, the BitForge Nano and the BitAxe Naja booting, identifying,
    // serving the dashboard, and permanently unable to mine. `RailBringup` was
    // written to name that distinction; this is the consumer it never had.
    // XPSAFE-5e — bring up the I2C port expander, for boards whose rail lives
    // on one. This must happen BEFORE the LDO step below, because on these
    // boards the LDO enable is an expander pin too.
    //
    // Order inside this block is the safety property: probe and reset the part,
    // drive ASIC reset / VREG / LDO to output-LOW (upstream `Q1370B::initBoard`),
    // and only THEN arm the panic cut. Arming earlier would point the hook at a
    // part still in high-Z; arming later would leave a window where the rail
    // could be raised with no panic actuator behind it.
    #[cfg(feature = "io-expander-fxl6408")]
    let mut rail_expander: Option<dcentaxe_hal::fxl6408::Fxl6408> = None;
    #[cfg(feature = "io-expander-fxl6408")]
    if mining_permitted {
        if let dcentaxe_hal::board::RailBringup::ExpanderGpio { addr, .. } =
            board_config.rail_bringup()
        {
            match dcentaxe_hal::fxl6408::Fxl6408::new(&mut i2c, addr) {
                Ok(mut exp) => match exp.configure_power_sequence_outputs(&mut i2c) {
                    Ok(()) => {
                        arm_panic_expander_rail_cut(0, addr);
                        info!(
                            "XPSAFE-5d: panic-hook expander rail cut armed (I2C0 0x{:02X}) — \
                             this board's enable is neither an ESP GPIO nor a switchable \
                             regulator",
                            addr
                        );
                        rail_expander = Some(exp);
                    }
                    Err(e) => {
                        mining_permitted = false;
                        mining_block_reason = Some(BlockReason::RailExpander);
                        error!("Expander power-sequence setup failed: {}", e);
                        fail_closed_power_off(
                            "Expander power-sequence setup failed",
                            &state,
                            None,
                            None,
                            &mut i2c,
                            &mut gpio_ctrl,
                        );
                    }
                },
                Err(e) => {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::RailExpander);
                    error!("Rail expander not found at 0x{:02X}: {}", addr, e);
                    fail_closed_power_off(
                        "Rail expander not found",
                        &state,
                        None,
                        None,
                        &mut i2c,
                        &mut gpio_ctrl,
                    );
                }
            }
        }
    }

    // XPSAFE-5c — raise the ASIC LDO bank BEFORE the core rail is configured.
    //
    // On the multi-phase Nerd line the dies are fed by two supplies, and
    // upstream's `initAsics` is explicit about the order: LDO_enable(), 100 ms,
    // then the TPS init, then VOUT. Doing it the other way round leaves the
    // chain silent on a rail that looks perfect from the regulator's side —
    // which is how this shipped, with GPIO13 referenced nowhere in the tree.
    //
    // `has_ldo()` is asked FIRST rather than calling `enable_ldo` and reading
    // its Err, because that Err means "this board has no LDO", not "the LDO
    // failed" — the distinction that cost three boards their ability to mine
    // in Wave 21. A board that HAS one and cannot raise it fails closed.
    // The LDO is asked for by ROLE, not by pin — `asic_ldo_enable()` carries
    // the transport, so a board whose LDO is an expander pin runs the same
    // sequence at the same point with the same settle. Adding the second
    // transport added no second sequence, which is the whole reason the
    // declaration is typed rather than an `i32`.
    #[cfg(feature = "io-expander-fxl6408")]
    if mining_permitted {
        if let Some(dcentaxe_hal::board::LdoEnable::Expander { pin, .. }) =
            board_config.model.asic_ldo_enable()
        {
            let raised = match rail_expander.as_mut() {
                Some(exp) => exp
                    .write_pin(&mut i2c, pin, true)
                    .map_err(|e| e.to_string()),
                // Unreachable in practice: the same `ExpanderGpio` classification
                // gates both this and the construction above. Stated as a hard
                // refusal anyway, because "the handle is missing" must never
                // degrade into "skip raising the LDO and mine anyway".
                None => Err("rail expander was never constructed".to_string()),
            };
            match raised {
                Ok(()) => {
                    info!(
                        "Rail bring-up: ASIC LDO enabled on expander pin {} — settling {} ms \
                         before the core rail is configured",
                        pin, LDO_SETTLE_MS
                    );
                    std::thread::sleep(std::time::Duration::from_millis(LDO_SETTLE_MS));
                }
                Err(e) => {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::RailLdo);
                    error!("Expander ASIC LDO enable failed: {}", e);
                    fail_closed_power_off(
                        "Expander ASIC LDO enable failed",
                        &state,
                        None,
                        None,
                        &mut i2c,
                        &mut gpio_ctrl,
                    );
                }
            }
        }
    }
    if mining_permitted && gpio_ctrl.has_ldo() {
        match gpio_ctrl.enable_ldo(true) {
            Ok(()) => {
                info!(
                    "Rail bring-up: ASIC LDO enabled on GPIO{} — settling {} ms before the \
                     core rail is configured",
                    board_config.ldo_enable_pin, LDO_SETTLE_MS
                );
                std::thread::sleep(std::time::Duration::from_millis(LDO_SETTLE_MS));
            }
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::RailLdo);
                error!("ASIC LDO enable failed: {}", e);
                fail_closed_power_off(
                    "ASIC LDO enable failed",
                    &state,
                    None,
                    None,
                    &mut i2c,
                    &mut gpio_ctrl,
                );
            }
        }
    }
    if mining_permitted {
        match board_config.rail_bringup() {
            // A discrete GPIO asserts the enable. Unchanged, byte for byte:
            // an Err here really is a failure to actuate a pin that exists.
            dcentaxe_hal::board::RailBringup::EnableGpio
                if board_config.rail_enable_order()
                    == dcentaxe_hal::board::RailEnableOrder::RegulatorBeforeGpio =>
            {
                // Deferred on purpose — see `RailEnableOrder`. Asserting EN here
                // would energize a TPS5364x at whatever VOUT its NVM holds,
                // because that part ignores OPERATION and follows EN alone.
                // The assertion happens after `PowerManager::new` below.
                info!(
                    "Rail bring-up: {} defers its enable GPIO until the regulator is configured",
                    board_config.model.name()
                );
            }
            dcentaxe_hal::board::RailBringup::EnableGpio => {
                if let Err(e) = gpio_ctrl.enable_buck(true) {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::RailBuck);
                    error!("Buck enable failed: {}", e);
                    fail_closed_power_off(
                        "Buck enable failed",
                        &state,
                        None,
                        None,
                        &mut i2c,
                        &mut gpio_ctrl,
                    );
                }
            }
            // EXPERIMENTAL: no enable pin exists; the regulator IS the rail
            // actuator. `PowerManager::new` leaves the TPS546 at OPERATION_OFF,
            // and the `set_voltage` below sends VOUT_COMMAND + OPERATION_ON —
            // so the rail comes up there, in order (rail -> reset -> UART), not
            // here. Nothing to drive at this step is the correct outcome, not a
            // fault. The regulator's identity is verified after probing, below.
            dcentaxe_hal::board::RailBringup::RegulatorOnly => {
                info!(
                    "Rail bring-up: {} has no enable GPIO — the regulator commands the rail \
                     (EXPERIMENTAL). Rail rises at set_voltage(); cuts run over PMBus.",
                    board_config.model.name()
                );
            }
            // EXPERIMENTAL: the enable is an expander pin. Like the
            // `RegulatorBeforeGpio` case above this is deliberately deferred —
            // the part behind it is a TPS5364x, whose EN must not be asserted
            // until `VOUT_COMMAND` has been written. The expander itself was
            // already brought up and its panic cut armed (XPSAFE-5e), so the
            // rail has an actuator before it can possibly rise.
            dcentaxe_hal::board::RailBringup::ExpanderGpio { addr, pin } => {
                info!(
                    "Rail bring-up: {} drives its enable through an I2C expander at \
                     0x{:02X} pin {} (EXPERIMENTAL) — deferred until the regulator is \
                     configured",
                    board_config.model.name(),
                    addr,
                    pin
                );
            }
            // Neither an enable pin nor commandable voltage. Nothing in firmware
            // can raise or lower this rail, so nothing can cut it either.
            dcentaxe_hal::board::RailBringup::NoActuator => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::RailNoActuator);
                fail_closed_power_off(
                    "No rail actuator (no enable GPIO, no commandable regulator)",
                    &state,
                    None,
                    None,
                    &mut i2c,
                    &mut gpio_ctrl,
                );
            }
        }
    }

    // I2C already initialized in Step 3 (for OLED display)

    // Power — boards with fixed voltage (NerdNOS) skip regulator init
    // Retry up to 3 times with I2C recovery delay (rapid reboots can leave bus in bad state)
    let mut power_mgr = if mining_permitted {
        let mut result = None;
        for attempt in 1..=3 {
            match PowerManager::new(&mut i2c, &board_config) {
                Ok(mgr) => {
                    result = Some(mgr);
                    break;
                }
                Err(e) => {
                    if attempt < 3 {
                        warn!("PowerManager init attempt {}/3 failed: {:?} — retrying after I2C recovery", attempt, e);
                        std::thread::sleep(Duration::from_millis(500));
                        // HALPWR-8: probe the board-appropriate regulator address as
                        // the bus-recovery poke. The old hardcoded 0x24 only matches
                        // TPS546 boards; on a DS4432U (0x48) board it probed an absent
                        // device so only the sleeps helped recovery.
                        let recovery_addr = match board_config.power_controller {
                            dcentaxe_hal::board::PowerControllerKind::Tps546 => {
                                dcentaxe_hal::power::TPS546_ADDR
                            }
                            dcentaxe_hal::board::PowerControllerKind::Ds4432u => {
                                dcentaxe_hal::power::DS4432U_ADDR
                            }
                            _ => dcentaxe_hal::power::TPS546_ADDR,
                        };
                        let _ = i2c.probe(recovery_addr);
                        std::thread::sleep(Duration::from_millis(100));
                    } else if board_config.model.has_voltage_control() {
                        mining_permitted = false;
                        mining_block_reason = Some(BlockReason::PowerInit);
                        error!(
                            "PowerManager init failed after 3 attempts: {:?} — mining disabled",
                            e
                        );
                        fail_closed_power_off(
                            "Power init failed after rails may have been enabled",
                            &state,
                            None,
                            None,
                            &mut i2c,
                            &mut gpio_ctrl,
                        );
                        result = Some(PowerManager::null());
                    } else {
                        warn!(
                            "No voltage regulator found — board has fixed voltage ({} mV)",
                            board_config.default_voltage_mv
                        );
                        result = Some(PowerManager::null());
                    }
                }
            }
        }
        result.unwrap_or_else(PowerManager::null)
    } else {
        PowerManager::null()
    };
    // XPSAFE-5b: the deferred enable. A board whose regulator must be configured
    // before EN is asserted gets its GPIO driven HERE, after `PowerManager::new`
    // has identified the part and programmed its phase count, current-sense full
    // scale and over-temperature limits — and before `set_voltage` below.
    if mining_permitted
        && board_config.rail_enable_order()
            == dcentaxe_hal::board::RailEnableOrder::RegulatorBeforeGpio
        && board_config.rail_bringup() == dcentaxe_hal::board::RailBringup::EnableGpio
    {
        match gpio_ctrl.enable_buck(true) {
            Ok(()) => info!(
                "Rail bring-up: enable GPIO asserted after regulator configuration ({:?})",
                power_mgr.regulator_type()
            ),
            Err(e) => {
                mining_permitted = false;
                mining_block_reason = Some(BlockReason::RailBuck);
                error!("Deferred buck enable failed: {}", e);
                fail_closed_power_off(
                    "Deferred buck enable failed",
                    &state,
                    None,
                    Some(&mut power_mgr),
                    &mut i2c,
                    &mut gpio_ctrl,
                );
            }
        }
    }
    // XPSAFE-5b (expander) — the deferred enable for a board whose EN is an
    // expander pin. Same window, same reason as the GPIO case directly above:
    // after `PowerManager::new` has identified the TPS5364x and programmed its
    // phase count, current-sense full scale and over-temperature limits, and
    // before `set_voltage` raises the output.
    #[cfg(feature = "io-expander-fxl6408")]
    if mining_permitted {
        if let dcentaxe_hal::board::RailBringup::ExpanderGpio { addr, pin } =
            board_config.rail_bringup()
        {
            let asserted = match rail_expander.as_mut() {
                Some(exp) => exp
                    .write_pin(&mut i2c, pin, true)
                    .map_err(|e| e.to_string()),
                None => Err("rail expander was never constructed".to_string()),
            };
            match asserted {
                Ok(()) => info!(
                    "Rail bring-up: expander VREG enable asserted at 0x{:02X} pin {} after \
                     regulator configuration ({:?})",
                    addr,
                    pin,
                    power_mgr.regulator_type()
                ),
                Err(e) => {
                    mining_permitted = false;
                    mining_block_reason = Some(BlockReason::RailExpander);
                    error!("Deferred expander enable failed: {}", e);
                    fail_closed_power_off(
                        "Deferred expander enable failed",
                        &state,
                        None,
                        Some(&mut power_mgr),
                        &mut i2c,
                        &mut gpio_ctrl,
                    );
                }
            }
        }
    }
    // XPSAFE-5 — a board with no enable GPIO may only mine if its regulator can
    // actually CUT the rail, and the panic hook must be armed before the rail
    // is ever raised (the `set_voltage` below is what raises it).
    //
    // The capability check is not ceremony, and it is deliberately not a
    // part-name comparison. `PowerManager::new` PROBES: a board whose 0x24
    // stays silent while a DS4432U answers 0x48 resolves to `Ds4432u`, whose
    // `disable()` returns `RequiresBuckCut`. A TPS5364x is the subtler case —
    // it speaks PMBus fluently but ignores OPERATION, so it cannot switch its
    // own output either. Both are rails nothing could bring down. Refuse them.
    if mining_permitted
        && board_config.rail_bringup() == dcentaxe_hal::board::RailBringup::RegulatorOnly
    {
        if power_mgr.regulator_type().can_cut_rail_over_i2c() {
            // Single regulator at 0x24. Multi-regulator stacks (the Lucky LV08's
            // [0x24, 0x7F, 0x14]) are NOT RegulatorOnly boards — they carry an
            // enable GPIO — so one address is the whole set here. If a
            // multi-regulator board ever classifies RegulatorOnly, this must
            // arm every address or it would cut one phase and leave the others.
            arm_panic_pmbus_rail_cut(0, dcentaxe_hal::power::TPS546_ADDR);
            info!(
                "XPSAFE-5: panic-hook PMBus rail cut armed (I2C0 0x{:02x}) — this board has \
                 no enable GPIO for the hook to drive",
                dcentaxe_hal::power::TPS546_ADDR
            );
        } else {
            mining_permitted = false;
            mining_block_reason = Some(BlockReason::RailNoI2cCut);
            error!(
                "Board has no enable GPIO and its regulator ({:?}) cannot cut the rail over I2C",
                power_mgr.regulator_type()
            );
            fail_closed_power_off(
                "No enable GPIO and no I2C-cuttable regulator",
                &state,
                None,
                Some(&mut power_mgr),
                &mut i2c,
                &mut gpio_ctrl,
            );
        }
    }
    if mining_permitted && board_config.model.has_voltage_control() {
        if let Err(e) = power_mgr.set_voltage(&mut i2c, config.target_voltage_mv) {
            mining_permitted = false;
            mining_block_reason = Some(BlockReason::PowerSetVoltage);
            error!("Set voltage failed: {} — mining disabled", e);
            fail_closed_power_off(
                "Set voltage failed after rail enable",
                &state,
                None,
                Some(&mut power_mgr),
                &mut i2c,
                &mut gpio_ctrl,
            );
        } else {
            info!("Voltage: {} mV", config.target_voltage_mv);
        }
    } else if !board_config.model.has_voltage_control() {
        info!(
            "Fixed voltage: {} mV (not adjustable)",
            board_config.default_voltage_mv
        );
    }
    // Wait for power rails to stabilize before probing temp sensors
    std::thread::sleep(Duration::from_millis(100));

    // I2C bus scan for diagnostics (helps identify what's on the bus)
    {
        let mut found = Vec::new();
        for addr in 0x08..=0x77 {
            if i2c.probe(addr) {
                found.push(addr);
            }
        }
        info!(
            "I2C scan: {} devices found: {}",
            found.len(),
            found
                .iter()
                .map(|a| format!("0x{:02X}", a))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // ── XPSAFE-12: this diagnostic scan POKES the regulator ────────────
        //
        // `I2cBus::probe` is a ZERO-BYTE write — fine for an EEPROM or a fan
        // controller, but to a PMBus part a write that carries no command byte
        // is malformed, and the TPS546 records it as `STATUS_CML = 0x40`
        // ("invalid or unsupported data received"). The scan runs AFTER
        // `PowerManager::new`, so it re-dirtied a status word that init had just
        // cleared.
        //
        // Nothing noticed for seventeen seconds, and then the supervisor's first
        // fault check read `STATUS_WORD = 0x0202` and executed the unconditional
        // POWER FAULT hard-kill — on a rail measuring 3.646 V / 11.7 V in /
        // 20.1 A / 48 C, while the board was mining and submitting accepted
        // shares. Diagnosed live on a Hex Supra, 2026-09-03.
        //
        // The flag is cleared here, immediately, by the code that caused it.
        // This is not a relaxation of the power-fault posture: the kill stays
        // unconditional, and any CML the supervisor sees from now on was raised
        // by something other than our own bus scan.
        {
            match power_mgr.clear_faults(&mut i2c) {
                Ok(status) => info!(
                    "I2C scan: cleared the regulator CML the zero-byte probe just set                      (STATUS_WORD now 0x{:04x})",
                    status
                ),
                Err(e) => warn!(
                    "I2C scan: could not clear regulator faults after probing: {:?} — a \
                     self-inflicted CML may trip the power-fault kill",
                    e
                ),
            }
        }
    }

    let (mut tmp_primary, tmp_secondary) = if board_config.temp_sensor
        == dcentaxe_hal::board::TempSensorKind::Tmp1075
    {
        // Which two devices to open depends on the board family. BitAxe Hex
        // straps its pair at 0x4A/0x4B; the Nerd multi-ASIC boards strap
        // from 0x48 and reserve 0x49 for the VOLTAGE REGULATOR, so the Hex
        // pair addresses the wrong devices there — it would miss the first
        // ASIC sensor entirely. `new_nerd_asic` maps logical ASIC sensors
        // past the VR device (0 -> 0x48, 1 -> 0x4A); see
        // `dcentaxe_hal::tmp1075_convert` for the topology.
        //
        // The question here is about the HARDWARE, not the brand: the Q-series
        // carries the same TPS53647 rail and the same TMP1075 strapping as the
        // Nerd multi-ASIC boards (`Q1370B::initBoard` calls the very same
        // `detectNumTempSensors`), so it must take the same branch.
        // `has_multiphase_vrm` is the predicate that says so.
        let nerd = board_config.model.has_multiphase_vrm();
        let (primary_addr, secondary_addr) = if nerd {
            ("0x48", "0x4A")
        } else {
            ("0x4A", "0x4B")
        };
        let open_primary = |i2c: &mut _| {
            if nerd {
                Tmp1075::new_nerd_asic(i2c, 0, "asic0").ok()
            } else {
                Tmp1075::new_primary(i2c).ok()
            }
        };

        // TMP1075 init with retry — the primary may need extra time after power-up
        let mut primary = open_primary(&mut i2c);
        if primary.is_none() {
            std::thread::sleep(Duration::from_millis(200));
            primary = open_primary(&mut i2c);
            if primary.is_some() {
                info!("TMP1075 primary ({primary_addr}) detected on retry");
            }
        }
        let secondary = if nerd {
            Tmp1075::new_nerd_asic(&mut i2c, 1, "asic1").ok()
        } else {
            Tmp1075::new_secondary(&mut i2c).ok()
        };
        if primary.is_some() {
            info!("TMP1075 primary ({primary_addr}) detected");
        } else {
            error!("TMP1075 primary ({primary_addr}) missing on TMP1075 board — mining disabled");
        }
        if secondary.is_some() {
            info!("TMP1075 secondary ({secondary_addr}) detected");
        } else {
            error!(
                "TMP1075 secondary ({secondary_addr}) missing on TMP1075 board — mining disabled"
            );
        }
        if primary.is_none() || secondary.is_none() {
            mining_permitted = false;
            mining_block_reason = Some(BlockReason::ThermalBoardSensor);
        }
        (primary, secondary)
    } else {
        (None, None)
    };

    if board_config.temp_sensor != dcentaxe_hal::board::TempSensorKind::Tmp1075 {
        tmp_primary = None;
    }

    if mining_permitted && !unsafe_lab_safety_bypass {
        let boot_trusted_temp = temp_emc
            .as_mut()
            .and_then(|s| {
                s.read_external_temp(&mut i2c)
                    .ok()
                    .flatten()
                    .or_else(|| s.read_internal_temp(&mut i2c).ok())
            })
            .or_else(|| {
                emc2103.as_ref().and_then(|e| {
                    e.read_chip_temp(&mut i2c)
                        .or_else(|| e.read_secondary_temp(&mut i2c))
                })
            })
            .or_else(|| {
                tmp_primary
                    .as_ref()
                    .and_then(|s| s.read_temp(&mut i2c).ok())
                    .or_else(|| {
                        tmp_secondary
                            .as_ref()
                            .and_then(|s| s.read_temp(&mut i2c).ok())
                    })
            })
            .or_else(|| {
                if power_mgr.has_vreg_temp_sensor() {
                    power_mgr.get_vreg_temp(&mut i2c).ok()
                } else {
                    None
                }
            });
        if boot_trusted_temp.is_none() {
            mining_permitted = false;
            mining_block_reason = Some(BlockReason::ThermalNoSource);
            fail_closed_power_off(
                "No trusted thermal source returned data at boot",
                &state,
                None,
                Some(&mut power_mgr),
                &mut i2c,
                &mut gpio_ctrl,
            );
        }
    } else if mining_permitted {
        warn!("UNSAFE LAB: mining may start without boot-time thermal proof");
    }

    if mining_permitted {
        gpio_ctrl.reset_asic().expect("ASIC reset failed");
        std::thread::sleep(Duration::from_millis(200));
    }

    // ======================================================================
    // Step 7: UART + ASIC driver
    // ======================================================================
    let uart_config = UartConfig::new().baudrate(esp_idf_svc::hal::units::Hertz(115200));
    // UART pins: BitAxe=17/18, Nerd=43/44. Hammer polarity is SKU-specific.
    #[cfg(feature = "pins-bitaxe")]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio17,
        peripherals.pins.gpio18,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");
    #[cfg(all(
        feature = "pins-hammer-bc",
        any(
            feature = "hammer-bc01",
            feature = "hammer-bc01-pro",
            feature = "hammer-bc02"
        )
    ))]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio18,
        peripherals.pins.gpio17,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");
    #[cfg(all(feature = "pins-hammer-bc", feature = "hammer-bc04"))]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio17,
        peripherals.pins.gpio18,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");
    #[cfg(all(feature = "pins-hammer-dc", feature = "hammer-dc02"))]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio18,
        peripherals.pins.gpio17,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");
    #[cfg(all(
        feature = "pins-hammer-dc",
        any(feature = "hammer-dc04", feature = "hammer-dc06")
    ))]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio17,
        peripherals.pins.gpio18,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");
    #[cfg(feature = "pins-nerd")]
    let uart_driver = UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio43,
        peripherals.pins.gpio44,
        Option::<gpio::AnyIOPin<'_>>::None,
        Option::<gpio::AnyIOPin<'_>>::None,
        &uart_config,
    )
    .expect("UART init failed");

    let serial_port = SerialPort::from_uart(uart_driver);
    let mut driver = dcentaxe_asic::create_driver(asic_model, serial_port);
    // Use the last pool-suggested difficulty from NVS (ESP-Miner PR #1594 parity).
    // Fall back to 256.0 on first boot or when the cached value is zero/invalid.
    let initial_diff = if cached_pool_difficulty.is_finite() && cached_pool_difficulty >= 1.0 {
        cached_pool_difficulty
    } else {
        256.0
    };
    let chips = if mining_permitted {
        match driver.init(config.target_frequency, asic_count, initial_diff) {
            Ok(n) => {
                info!("ASIC: {} chip(s), model={}", n, asic_model);
                match driver.set_max_baud() {
                    Ok(baud) => info!("ASIC UART switched to {} baud", baud),
                    Err(e) => error!("Failed to set max baud: {} — mining at reduced speed", e),
                }
                display.show_status(
                    &mut i2c,
                    &format!("DCENT_axe v{}", VERSION),
                    // P1-O2: permitted, chips found, no hashrate yet = READY,
                    // the same rung the dashboard shows for this state.
                    // Round 2 (critic finding 2): composed by rung_status_line,
                    // which cannot exceed 21 columns for ANY chip count - the
                    // raw format! this replaced was clipped by draw_text from
                    // the right, silently, with no ellipsis.
                    &rung_status_line(MiningRung::Ready.panel_word(), &format!("{} chips OK", n)),
                    &ip_row(&device_ip),
                    "Connecting to pool...",
                );
                n
            }
            Err(e) => {
                error!("ASIC init failed: {} — continuing without mining", e);
                display.show_status(
                    &mut i2c,
                    &format!("DCENT_axe v{}", VERSION),
                    // P1-O2: chips == 0 means mining is not permitted = STANDBY.
                    // Round 2: 20 of 21 columns - the tightest rung line on the
                    // panel, and the reason the composer is bounded rather than
                    // trusted.
                    &rung_status_line(MiningRung::Standby.panel_word(), "ASIC FAILED"),
                    &ip_row(&device_ip),
                    "Dashboard active",
                );
                0
            }
        }
    } else {
        let reason = mining_block_reason.unwrap_or(BlockReason::SafetyGate);
        // P1-O2: the fail-closed screen names the shared rung, so "the panel
        // says STANDBY" and "the dashboard says STANDBY" are the same
        // sentence.
        //
        // P1-O1: and the other three rows now say something an operator can
        // USE. They used to be the firmware version, a 30-80 character
        // sentence that draw_text clipped mid-word at column 21 with no
        // ellipsis, and the IP. All four rows are composed by the bounded
        // helpers, so no row on this screen can be clipped for any reason,
        // any watchdog count or any address. The version leaves THIS screen
        // only - every other boot frame still carries it - because a version
        // an operator cannot act on is worth less, here, than the action
        // they can.
        let blocked = blocked_screen(
            &rung_status_line(MiningRung::Standby.panel_word(), "disabled"),
            reason,
            wdt_count,
            &device_ip,
        );
        display.show_status(&mut i2c, &blocked[0], &blocked[1], &blocked[2], &blocked[3]);
        // The full sentence is not lost, it is just not on the glass: the
        // log keeps it, beside the exact code the panel is showing.
        warn!(
            "Mining disabled before ASIC init: {} [{}] -> {}",
            reason.summary(),
            code_line(reason, wdt_count),
            reason.action()
        );
        0
    };
    let mining_enabled = mining_permitted && chips > 0;
    {
        let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
        telem.mining_enabled = mining_enabled;
    }

    // ======================================================================
    // Step 8: HTTP server — dashboard + REST API + MCP
    // ======================================================================
    // XPH-4 / MAINAPI-7: name the URI-handler cap and the registered-handler
    // estimate as consts, and pin the headroom invariant at compile time so the
    // human-maintained count can never silently exceed the cap (the class of bug
    // that boot-looped against the previous 64 cap). Do NOT lower MAX_URI_HANDLERS.
    //
    // Registered-handler accounting — counted by INVOCATION, not by text
    // (re-verified 2026-09-03 by `tools/count_handlers.py`, lane P1-I3).
    //
    // WHY THE OLD NUMBER WAS WRONG: a `.fn_handler(` written inside a helper —
    // a `fn` like `dashboard::register_static`, or a
    // `let name = |path: &str, …| { … }` closure — is written ONCE in the source
    // but EXECUTED once per call site. Counting occurrences of the *text*
    // `.fn_handler(` therefore reports FEWER handlers than the firmware actually
    // registers, which is the dangerous direction for a cap that fails at boot.
    // The table below counts registrations, and names every helper that makes the
    // two columns differ:
    //
    //   file             text sites   registrations   why they differ
    //   api.rs                   54              57   3 closures invoked twice:
    //                                                 `register` → /api/system/
    //                                                 statistics{,/dashboard};
    //                                                 `register_ota_get` →
    //                                                 /api/system/OTA{,WWW} (GET);
    //                                                 `register_manifest` →
    //                                                 /api/system/update/
    //                                                 {package-,}manifest
    //   auth.rs                   5               5   all literal URIs
    //   mcp.rs                    2               2   /mcp GET + /mcp POST
    //   dashboard.rs              3              12   `register_static()` is ONE
    //                                                 site invoked 10× for the
    //                                                 /dashboard/* assets, plus
    //                                                 / and /index.html
    //   ───────────────  ──────────  ──────────────
    //   TOTAL                    64              76   text-only under-counts by 12
    //
    // Not counted here, deliberately: `cgminer_tcp` is a raw TCP listener, not a
    // URI handler; and `provisioning.rs` registers 10 URIs (1 + an 8-path
    // captive-portal `for` loop + 1) on its OWN short-lived `EspHttpServer`, whose
    // cap is `Configuration::default().max_uri_handlers` (32) — it never consumes
    // a slot from MAX_URI_HANDLERS.
    //
    // Re-run `python tools/count_handlers.py` after ANY route change. The
    // `dcentaxe-core` guard `registered_handler_count_under_cap` recomputes this
    // total from the sources and fails if the const drifts from reality.
    const MAX_URI_HANDLERS: usize = 96;
    const REGISTERED_HANDLER_ESTIMATE: usize = 76;
    // Compile-time floor guard: the estimate must always stay under the cap.
    const _: () = assert!(REGISTERED_HANDLER_ESTIMATE < MAX_URI_HANDLERS);
    // Runtime tripwire if a future edit pushes the count near the cap.
    debug_assert!(
        REGISTERED_HANDLER_ESTIMATE + 8 < MAX_URI_HANDLERS,
        "registered HTTP handlers approaching max_uri_handlers cap — re-count and \
         bump MAX_URI_HANDLERS (do not silently exceed it)"
    );
    let http_config = HttpConfig {
        stack_size: 10240,
        max_uri_handlers: MAX_URI_HANDLERS,
        ..Default::default()
    };
    let mut http_server = EspHttpServer::new(&http_config).expect("HTTP server start failed");

    dashboard::register_dashboard(&mut http_server);
    api::register_api(&mut http_server, state.clone());
    mcp::register_mcp(&mut http_server, state.clone());
    cgminer_tcp::start_cgminer_tcp(state.clone());
    info!("HTTP server started: dashboard + REST API + MCP");

    // ======================================================================
    // Step 9: Channels + threads (only if ASIC init succeeded)
    // ======================================================================
    // Frequency command channel: main loop -> mining thread
    let (freq_cmd_tx, freq_cmd_rx) = mpsc::channel::<f32>();

    // Thermal kill switch: set true to stop the mining thread
    let mining_kill = Arc::new(AtomicBool::new(false));

    if mining_enabled {
        let (event_tx, event_rx) = mpsc::channel::<StratumEvent>();
        let (share_tx, share_rx) = mpsc::channel::<MiningEvent>();
        let nominal_hashrate_ghs =
            expected_hashrate_ghs(asic_model, config.target_frequency, asic_count);

        // Solo mesh empty-block path: park a NewJob sender for the LoRa task
        // (fail-closed until mesh config enables solo_mesh_empty).
        #[cfg(feature = "lora")]
        mesh_solo_runtime::park_event_tx(event_tx.clone());

        // Primary stratum thread
        let stratum_config = config.stratum.clone();
        let fallback_pool = config.fallback_pool.clone();
        let donation_directive = match config.donation.to_directive(config.stratum.version_rolling)
        {
            Ok(directive) => Some(directive),
            Err(error) => {
                warn!(
                    "Donation configuration rejected; donation disabled: {}",
                    error
                );
                None
            }
        };
        let primary_status = dcentaxe_stratum::new_shared_stratum_status(&stratum_config, 0);
        {
            let mut statuses = state
                .stratum_status
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            statuses.push(primary_status.clone());
        }
        let _stratum = spawn_stratum_thread(
            "stratum",
            stratum_config,
            fallback_pool,
            donation_directive,
            event_tx,
            share_rx,
            primary_status,
            nominal_hashrate_ghs,
            // Pinned SV2 authority key applies to the PRIMARY pool only. When
            // unset (default), the SV2 client uses TOFU exactly as before.
            config.sv2_authority_pubkey.clone(),
        );

        // Secondary stratum thread + pool slots (if split_pool configured)
        let split_pool_cfg = config.split_pool.clone();
        let pool_slots: Vec<PoolSlot>;

        if let Some(ref split) = split_pool_cfg {
            let secondary_pct = split.hashrate_pct.clamp(1, 99);
            let primary_pct = 100 - secondary_pct;

            let (event_tx_b, event_rx_b) = mpsc::channel::<StratumEvent>();
            let (share_tx_b, share_rx_b) = mpsc::channel::<MiningEvent>();

            let split_config = split.pool.clone();
            let secondary_status = dcentaxe_stratum::new_shared_stratum_status(&split_config, 1);
            {
                let mut statuses = state
                    .stratum_status
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                statuses.push(secondary_status.clone());
            }
            let _stratum_b = spawn_stratum_thread(
                "stratum-b",
                split_config,
                None,
                None,
                event_tx_b,
                share_rx_b,
                secondary_status,
                nominal_hashrate_ghs * secondary_pct as f32 / 100.0,
                // Split/secondary pool: per-pool authority keys are a follow-up.
                None,
            );

            info!(
                "Split mining: {}% to {}:{}, {}% to {}:{}",
                primary_pct,
                crate::shared::sanitize_pool_url(&config.stratum.url),
                config.stratum.port,
                secondary_pct,
                crate::shared::sanitize_pool_url(&split.pool.url),
                split.pool.port
            );

            pool_slots = vec![
                PoolSlot::new(0, primary_pct, event_rx, share_tx),
                PoolSlot::new(1, secondary_pct, event_rx_b, share_tx_b),
            ];
        } else {
            pool_slots = vec![PoolSlot::new(0, 100, event_rx, share_tx)];
        }

        // Shared pool stats handle — dispatcher writes, API reads
        let pool_stats_for_mining = state.pool_stats.clone();

        // Mining thread
        let asic_model_copy = asic_model;
        let stats_for_mining = shared_mining_stats.clone();
        let mining_kill_flag = mining_kill.clone();
        let _mining = std::thread::Builder::new()
            .name("mining".into())
            .stack_size(24 * 1024)
            .spawn(move || {
                // RefCell created INSIDE the thread — never crosses thread boundaries
                let driver_cell = std::cell::RefCell::new(driver);

                // Poll for frequency change commands from main loop
                let freq_rx = freq_cmd_rx;

                let target_freq = config.target_frequency;
                let dispatcher_config = match asic_model {
                    dcentaxe_asic::AsicModel::BM1397 => {
                        DispatcherConfig::for_bm1397(target_freq, asic_count)
                    }
                    dcentaxe_asic::AsicModel::BM1366 => {
                        DispatcherConfig::for_bm1366(target_freq, asic_count)
                    }
                    dcentaxe_asic::AsicModel::BM1368 => {
                        DispatcherConfig::for_bm1368(target_freq, asic_count)
                    }
                    dcentaxe_asic::AsicModel::BM1370 => {
                        DispatcherConfig::for_bm1370(target_freq, asic_count)
                    }
                    dcentaxe_asic::AsicModel::BM1373 => {
                        DispatcherConfig::for_bm1370(target_freq, asic_count)
                    }
                    // MSBT0501 (Scrypt): cadence from MEASURED MH/s, never the
                    // SHA-256 core-count formula. Until live telemetry exists we
                    // seed it with the model's rated aggregate rate
                    // (DC02 150 / DC04 300 / DC06 450 MH/s). The driver refuses
                    // to init, so this config is not reachable in production —
                    // it exists so bring-up starts from the right model.
                    dcentaxe_asic::AsicModel::Lt0051 => {
                        let rated_mhs = 75.0 * asic_count.max(1) as f32;
                        DispatcherConfig::for_lt0051(rated_mhs, asic_count)
                    }
                    #[cfg(feature = "asic-kf1950")]
                    dcentaxe_asic::AsicModel::KF1950 => {
                        DispatcherConfig::for_kf1950(target_freq, asic_count)
                    }
                };
                let mut dispatcher = MiningDispatcher::with_pools(pool_slots, dispatcher_config);
                dispatcher.set_shared_stats(stats_for_mining);
                dispatcher.set_shared_pool_stats(pool_stats_for_mining);

                let mut send_work_fn =
                    |work: &dcentaxe_stratum::MiningWork, job_id: u8| -> Result<(), String> {
                        let job = bridge::mining_work_to_job(work, job_id, asic_model_copy);
                        driver_cell
                            .borrow_mut()
                            .send_work(&job)
                            .map_err(|e| format!("{}", e))
                    };

                let mut process_work_fn = || -> Vec<(u8, u32, u32, u32, u8)> {
                    match driver_cell.borrow_mut().read_responses(10) {
                        Ok(results) => results
                            .into_iter()
                            .filter_map(|r| {
                                if let AsicResult::Nonce {
                                    job_id,
                                    nonce,
                                    rolled_version,
                                    rolled_ntime,
                                    asic_nr,
                                    timestamp_us: _,
                                } = r
                                {
                                    // For BM1397: rolled_version = midstate_index (0-3)
                                    // For BM1366/68/70: rolled_version = actual rolled version from ASIC
                                    // For ntime-rolling chains: rolled_ntime = absolute hashed ntime (0 = none)
                                    // The dispatcher's handle_nonce will convert midstate_index
                                    // to actual version for BM1397 using increment_bitmask.
                                    Some((job_id, nonce, rolled_version, rolled_ntime, asic_nr))
                                } else {
                                    None
                                }
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    }
                };

                // Run dispatcher with frequency command polling
                let mut apply_driver_config = |new_diff: Option<f64>, new_mask: Option<u32>| {
                    if let Some(mask) = new_mask {
                        if let Err(e) = driver_cell.borrow_mut().set_version_mask(mask) {
                            error!("Failed to update ASIC version mask: {}", e);
                        }
                    }
                    if let Some(diff) = new_diff {
                        if let Err(e) = driver_cell.borrow_mut().set_difficulty(diff) {
                            error!("Failed to update ASIC difficulty: {}", e);
                        }
                    }
                };

                loop {
                    // Check thermal kill switch
                    if mining_kill_flag.load(Ordering::Relaxed) {
                        warn!("Mining thread: thermal kill signal received — stopping");
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(10));
                            if !mining_kill_flag.load(Ordering::Relaxed) {
                                break; // resume if cleared (future: reboot path)
                            }
                        }
                    }

                    // Check for frequency change commands from main loop/autotuner
                    while let Ok(new_freq) = freq_rx.try_recv() {
                        info!("Mining thread: frequency change to {:.0} MHz", new_freq);
                        if let Err(e) = driver_cell.borrow_mut().set_frequency(new_freq) {
                            error!("Frequency change failed: {}", e);
                        }
                    }
                    // Run one iteration of the dispatcher
                    dispatcher.run_once(
                        &mut send_work_fn,
                        &mut process_work_fn,
                        &mut apply_driver_config,
                    );

                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
            .expect("Mining thread spawn failed");
    } else {
        warn!("Mining disabled — ASIC init failed. Dashboard/API still accessible.");
    }

    // ======================================================================
    // Step 10: Main loop — telemetry, autotuner, thermal protection
    // ======================================================================
    info!("Mining active! Dashboard at http://{}/", device_ip);
    gpio_ctrl.set_led(true).ok();

    let mut autotuner = Autotuner::new(
        state.board_limits.min_frequency,
        state.board_limits.max_frequency,
        state.board_limits.min_voltage_mv,
        state.board_limits.max_voltage_mv,
    );
    autotuner.set_power_limits(&power_limits);
    let start_time = Instant::now();

    // Track last-applied voltage/freq so API changes are detected correctly
    let mut last_applied_voltage = config.target_voltage_mv;
    let mut last_applied_freq = config.target_frequency;

    let mut consecutive_i2c_failures: u32 = 0;
    let mut consecutive_temp_failures: u32 = 0;
    let mut consecutive_fan_stall: u32 = 0;
    // ES-2: consecutive supervisor ticks where a die-equipped board could read
    // NO ASIC-die sensor while a cooler proxy remained (see DIE_BLIND_CONFIRM_TICKS).
    let mut consecutive_die_blind: u32 = 0;
    // INA260 over-current backstop debounce (DS4432U boards). Counts consecutive
    // supervisor ticks measured over the rated PowerLimits envelope × margin.
    let mut ina_oc_strikes: u8 = 0;
    let mut fan1_ever_seen: bool = false; // Track if fan1 ever reported RPM > 0
    #[cfg(feature = "display-ssd1306")]
    let mut display_page: u8 = 0;
    #[cfg(feature = "display-ssd1306")]
    let mut notification_cooldown: u8 = 0; // Force carousel pages between notifications
    let mut identify_notification_cooldown: u8 = 0; // Avoid swarm-locate OLED storms
                                                    // B-ESP-10: the OLED is a read surface — strip any user:pass@ creds from the
                                                    // pool URL (host stays visible for at-the-miner diagnostics).
    #[cfg(feature = "display-ssd1306")]
    let pool_display = format!(
        "{}:{}",
        crate::shared::sanitize_pool_url(&config.stratum.url),
        config.stratum.port
    );

    // Gamification: track previous values to detect events for OLED notifications
    let mut prev_accepted: u64 = 0;
    #[cfg(feature = "display-ssd1306")]
    let mut prev_rejected: u64 = 0;
    #[cfg(feature = "display-ssd1306")]
    let mut prev_best_diff: f64 = 0.0;
    #[cfg(feature = "display-ssd1306")]
    let mut prev_clean_jobs: u64 = 0;
    let mut prev_streak: u32 = 0;
    let mut last_notified_share_milestone: u64 = 0;
    let mut previous_failover_active = false;
    let mut thermal_notification_active = false;
    #[cfg(feature = "display-ssd1306")]
    let mut diary_tick: u32 = 0; // counts up for mining diary rotation
    #[cfg(feature = "display-ssd1306")]
    let mut last_transition_flash: bool = false; // alternate to trigger flash on page change

    // v3 state variables
    let mut led_heartbeat_phase: u8 = 0; // 0-3 for heartbeat pattern
    let mut prev_heartbeat_speed: u8 = 2; // track speed changes for phase reset
    let mut prev_block_height: u32 = 0; // for special block detection
    #[cfg(feature = "display-ssd1306")]
    let mut comparison_idx: usize = 0; // hashrate comparison rotation
    #[cfg(feature = "display-ssd1306")]
    let mut fortune_idx: usize = 0; // fortune cookie rotation
    #[cfg(feature = "display-ssd1306")]
    let mut pixel_art_frame: u8 = 0; // animation frame counter
    #[cfg(feature = "display-ssd1306")]
    let mut companion_visit: u8 = 0; // rotates companion room/full-screen variants
    // Display-only strobe state: on headless boards there is nothing to strobe, so the whole
    // machine (declaration, consumer, both producers) lives behind the panel feature (P1-O4 fix).
    #[cfg(feature = "display-ssd1306")]
    let mut pending_flash: u8 = 0; // non-blocking flash state machine (decrements each tick)
    let mut share_flash_tick: u8 = 0; // lightning sprite after share accepted
    let mut achievement_flash_tick: u8 = 0; // rocket sprite after achievement
    let mut chill_miner_secs: u64 = 0; // consecutive seconds under 65C for Chill Miner achievement
    let mut low_power_secs: u64 = 0; // consecutive seconds under 10W for Power Miser achievement
    let mut daily_summary_shown: bool = false; // daily mining summary (show once after 24h)
    let mut last_history_sample_ms: u64 = 0;
    let mut last_schedule_key: Option<String> = None;
    let mut schedule_base_point: Option<(f32, u16)> = None;

    // WiFi reconnect: poll-based, called once per main-loop tick. Replaces
    // the old "one-shot connect, hope for the best" behaviour. Without this
    // a flaky AP would starve the device until the WDT tripped (3 trips →
    // safe-mode), forcing the user to reboot to recover.
    let mut wifi_reconnect_state = wifi::ReconnectState::new();

    // Wi-Fi⇄Ethernet failover observer (PLAN-E Phase 1). Pure FSM — the
    // outbound steering itself is lwIP route-priority (see eth_w5500.rs);
    // this reports/logs the active link and counts flaps.
    #[cfg(feature = "eth-w5500")]
    let mut eth_failover = net::FailoverState::new();

    // Subscribe the main task to the task watchdog. With
    // CONFIG_ESP_TASK_WDT_PANIC=n this turns a wedged main loop into a reset
    // that the boot-time WDT counter + safe-mode flow recovers from.
    unsafe {
        let rc = sys::esp_task_wdt_add(std::ptr::null_mut());
        if rc != 0 {
            warn!("esp_task_wdt_add returned {}", rc);
        }
    }
    let mut wdt_cleared_this_run = false;

    // MQTT + Home Assistant auto-discovery publisher (default-OFF, opt-in via
    // config.mqtt.enabled). Outbound + fail-soft on its own thread — never blocks
    // mining/safety, adds no HTTP handler. Returns immediately when MQTT is off.
    mqtt::spawn_publisher(state.clone());

    // On-board SX1262 LoRa radio task (default-OFF). Owns the radio on its own
    // thread — never blocks mining/safety; fail-soft if the bus never came up.
    #[cfg(feature = "lora")]
    if let Some(bus) = lora_bus {
        lora_task::spawn(state.clone(), bus);
    }

    loop {
        // Feed the WDT. Happens every iteration; 5 s loop is well under the
        // 15 s CONFIG_ESP_TASK_WDT_TIMEOUT_S budget.
        unsafe {
            let _ = sys::esp_task_wdt_reset();
        }
        std::thread::sleep(Duration::from_secs(5));
        let uptime = start_time.elapsed().as_secs();

        // After 5 minutes of stable uptime, clear the WDT reset counter so
        // future transient wedges don't accumulate into a false safe-mode trip.
        if !wdt_cleared_this_run && uptime >= 300 && (wdt_count > 0 || wdt_since_ms > 0) {
            let p = nvs_partition.clone();
            if let Ok(mut nvs) =
                esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(p, "dcentaxe", true)
            {
                nvs_config::save_wdt_counters(&mut nvs, 0, 0);
                info!("WDT window cleared after 5 min stable uptime");
            }
            wdt_count = 0;
            wdt_since_ms = 0;
            wdt_cleared_this_run = true;
        }

        // ── Non-blocking flash state machine (evolution/special block effects) ──
        #[cfg(feature = "display-ssd1306")]
        if pending_flash > 0 {
            display.invert_display(&mut i2c, true);
            std::thread::sleep(Duration::from_millis(30));
            display.invert_display(&mut i2c, false);
            pending_flash -= 1;
        }

        // Decrement sprite flash timers
        if share_flash_tick > 0 {
            share_flash_tick -= 1;
        }
        if achievement_flash_tick > 0 {
            achievement_flash_tick -= 1;
        }
        if identify_notification_cooldown > 0 {
            identify_notification_cooldown -= 1;
        }

        let identify_active = {
            let mut swarm = state.swarm.lock().unwrap_or_else(|e| e.into_inner());
            let now = shared::unix_time_ms() / 1000;
            if swarm.identify_until_epoch_s > 0 && swarm.identify_until_epoch_s <= now {
                swarm.identify_until_epoch_s = 0;
                false
            } else {
                swarm.identify_until_epoch_s > now
            }
        };
        if identify_active && identify_notification_cooldown == 0 {
            let live_config = state.config.lock().unwrap_or_else(|e| e.into_inner());
            let identify_name = if live_config.hostname.is_empty() {
                format!("dcentaxe-{}", board_config.device_model)
            } else {
                live_config.hostname.clone()
            };
            display.notify_urgent(
                "(^_^) HI!",
                &identify_name,
                &format!("IP {}", device_ip),
                "Swarm locate active",
            );
            identify_notification_cooldown = 6; // show locate text at most every 30s
        }
        if identify_active {
            gpio_ctrl.toggle_led().ok();
        }

        // ── Collect telemetry ──────────────────────────────────────────
        let power = power_mgr.get_telemetry(&mut i2c).ok();
        // Hex boards: chip_temp from TMP1075 (prefer primary 0x4A, fallback to secondary 0x4B)
        // Single-ASIC: chip_temp from EMC2101 external diode
        // GT (EMC2103): sensors are physically wired so that what ESP-Miner calls
        // "external_temp" is on EMC2103 sensor 2 and vice-versa. Matches upstream
        // `temp_flip = true` for board "801" (PR #1616 / commit 33d7210). `chip_temp`
        // below reads the primary chip sensor (registers 0x04/0x05 = TEMP2), and
        // `gt_temp2` reads the secondary (registers 0x02/0x03 = TEMP1).
        // GT secondary die temp on the EMC2103 secondary sensor (honors temp_flip).
        let gt_temp2 = emc2103
            .as_ref()
            .and_then(|e| e.read_secondary_temp(&mut i2c));
        // Per-ASIC die sweep on boards that declare a TMP451 diode mux. Costs
        // one mux settle + one discarded conversion per CHANNEL (not per
        // sensor) — worst case ~3.7 s for the OCTAXE-γ's 4 channels x 2
        // sensors, inside a 5 s loop whose WDT was fed at the top and has a
        // 15 s budget. Duration is logged so a slow bus is visible rather than
        // inferred from a reset.
        #[cfg(feature = "temp-tmp451")]
        let die_fold = diode_mux.as_mut().map(|mux| {
            let started = std::time::Instant::now();
            let fold = mux.sweep(&mut i2c);
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(2) {
                warn!(
                    "TMP451 die sweep took {} ms ({} of {} dies covered) — check the I2C bus",
                    elapsed.as_millis(),
                    fold.covered,
                    fold.expected
                );
            }
            fold
        });
        #[cfg(not(feature = "temp-tmp451"))]
        let die_fold: Option<thermal_safety::MuxedDieFold> = None;

        let apply_temp_offset =
            |temp: Option<f32>| temp.map(|t| t + board_config.temp_offset_c as f32);
        let chip_temp = if let Some(ref mut emc) = temp_emc {
            if board_config.emc_internal_temp {
                apply_temp_offset(emc.read_internal_temp(&mut i2c).ok())
            } else {
                apply_temp_offset(emc.read_external_temp(&mut i2c).ok().flatten())
            }
        } else if fan_is_emc2103 {
            // GT: primary chip temp on the EMC2103 chip sensor (honors temp_flip).
            // See `gt_temp2` block above for the upstream reference.
            apply_temp_offset(emc2103.as_ref().and_then(|e| e.read_chip_temp(&mut i2c)))
        } else {
            // Hex boards: use max of both TMP1075s for safety (hotter sensor = closer to ASIC)
            let t1 = tmp_primary
                .as_ref()
                .and_then(|s| s.read_temp(&mut i2c).ok());
            let t2 = tmp_secondary
                .as_ref()
                .and_then(|s| s.read_temp(&mut i2c).ok());
            apply_temp_offset(match (t1, t2) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            })
        };
        // On a muxed board the TMP451 sweep IS the die reading. The branch above
        // fell through to this board's TMP1075s, which measure AIRFLOW — they
        // stay in the fold as inlet/outlet proxies below, but they must not
        // masquerade as a junction temperature once real diodes are readable.
        //
        // No `apply_temp_offset` here on purpose: the die readings already
        // carry the board's declared TMP451 `Calibration`, and stacking the
        // row's proxy offset on top would correct them twice.
        let chip_temp = match die_fold {
            Some(fold) => fold.hottest,
            None => chip_temp,
        };
        // board_temp: EMC2101 internal on single-chip, or TMP1075 secondary on Hex (for temp2)
        let board_temp = apply_temp_offset(
            temp_emc
                .as_ref()
                .and_then(|s| s.read_internal_temp(&mut i2c).ok())
                .or_else(|| {
                    tmp_secondary
                        .as_ref()
                        .and_then(|s| s.read_temp(&mut i2c).ok())
                }),
        );
        let inlet_temp = apply_temp_offset(
            tmp_primary
                .as_ref()
                .and_then(|s| s.read_temp(&mut i2c).ok()),
        );
        let outlet_temp = apply_temp_offset(
            tmp_secondary
                .as_ref()
                .and_then(|s| s.read_temp(&mut i2c).ok()),
        );
        let gt_temp2 = apply_temp_offset(gt_temp2);
        let vreg_temp = if power_mgr.has_vreg_temp_sensor() {
            power_mgr.get_vreg_temp(&mut i2c).ok()
        } else {
            None
        };

        // ── Thermal fold + sensor-adequacy decision (host-pure) ────────
        // `evaluate_thermal` folds every sensor into `max_temp`, reports
        // `any_temp_valid` (the all-None BLIND trigger + I2C-dead watchdog),
        // AND flags `die_reading_blind`: a board EXPECTED to carry an ASIC-die
        // sensor has lost every die reading while only cooler proxies remain,
        // so `max_temp` understates the true die temp (ES-2 fail-open fix).
        // Extracted to `crate::thermal_safety` so the decision is host-tested
        // under `cargo test -p dcentaxe-core`.
        //
        // `chip_die_expected`: true for every board that physically carries an
        // ASIC-die sensor (EMC2101 external diode, EMC2103 chip sensor, or Hex
        // TMP1075s — i.e. `temp_sensor != None`, or any EMC2103 board). False
        // only for a board whose sole thermal source is a cooler proxy (custom
        // `temp_sensor == None` on TPS546 vreg temp), where a missing chip_temp
        // is NORMAL and must never be treated as blind.
        let chip_die_expected =
            board_config.temp_sensor != dcentaxe_hal::board::TempSensorKind::None || fan_is_emc2103;
        //
        // On a muxed board the same decision runs through
        // `evaluate_thermal_muxed`, which adds one rule: INCOMPLETE COVERAGE IS
        // BLINDNESS. Seven of eight dies reading a comfortable 65 C is not a
        // sighted board — the eighth shares the rail and the fan and could be
        // anywhere. (Upstream folds the same sweep with a bare `max` and reports
        // it as healthy; see `MuxedDieFold`.)
        let thermal = match die_fold {
            Some(fold) => thermal_safety::evaluate_thermal_muxed(
                fold,
                board_temp,
                inlet_temp,
                outlet_temp,
                vreg_temp,
                chip_die_expected,
            ),
            None => thermal_safety::evaluate_thermal(
                chip_temp,
                gt_temp2,
                board_temp,
                inlet_temp,
                outlet_temp,
                vreg_temp,
                chip_die_expected,
            ),
        };
        let max_temp = thermal.max_temp;
        let runtime_mining_active = mining_enabled && !mining_kill.load(Ordering::Relaxed);
        let thermal_clamp_active = max_temp > WARNING_TEMP_C;

        // ── Sensor failure detection ───────────────────────────────────
        // If ALL sensors return None, we have no thermal data — assume danger
        let any_temp_valid = thermal.any_temp_valid;

        if runtime_mining_active {
            // DELIBERATE CONSERVATIVE POSTURE: ANY regulator fault is treated as
            // an immediate, unconditional fail-closed power-off. There is no
            // recoverable-vs-hard `status_word` inspection, no cooldown, and no
            // auto re-enable here — a hardware-validated recovery FSM is future
            // work (see docs/PUBLIC_BETA_READINESS_REPORT.md and the RESERVED
            // helpers in dcentaxe-hal::power). For a beta the known-working
            // hard-kill is the correct fail-safe; do not soften this path.
            if let Err(e) = power_mgr.check_fault(&mut i2c) {
                error!("POWER FAULT: {} — disabling ASIC for safety", e);
                fan_ctrl.set_speed(100).ok();
                apply_fan_speed_or_fail_closed(
                    &mut i2c,
                    100,
                    &fan_emc2302,
                    &temp_emc,
                    &emc2103,
                    runtime_mining_active,
                    &state,
                    &mining_kill,
                    &mut power_mgr,
                    &mut gpio_ctrl,
                    "POWER FAULT fan pin",
                );
                fail_closed_power_off(
                    &format!("POWER FAULT: {}", e),
                    &state,
                    Some(&mining_kill),
                    Some(&mut power_mgr),
                    &mut i2c,
                    &mut gpio_ctrl,
                );
                display.notify_urgent(
                    "!! POWER FAULT !!",
                    "ASIC disabled",
                    &format!("IP {}", device_ip),
                    "Check PSU/cabling",
                );
            }

            // INA260 over-current/over-power backstop for DS4432U boards, which
            // get no PMBus STATUS_WORD OC detection from check_fault above. If
            // the measured INA260 input power/current stays above the board's
            // rated PowerLimits envelope × INA260_OC_MARGIN for
            // INA260_OC_DEBOUNCE_TICKS consecutive ticks, run the SAME
            // fail-closed power-off the TPS546 fault path uses. Debounced + a
            // margin above the rated envelope so a transient cannot nuisance-trip.
            if power_mgr.has_ina260() {
                let (max_power_w, max_current_a) = {
                    let limits = state
                        .config
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .power_limits();
                    (limits.max_power_w, limits.max_current_a)
                };
                let measured = power.as_ref();
                let meas_w = measured.map(|p| p.power_w).unwrap_or(f32::NAN);
                let meas_a = measured.map(|p| p.current_ma / 1000.0).unwrap_or(f32::NAN);
                // NaN (no snapshot / a failed per-field sub-read) is benign:
                // `ina260_oc_over_envelope` rejects non-finite fields, byte-matching
                // the prior `.unwrap_or(false)` + per-field `power_field_available`
                // guards (`power_over || current_over`).
                let over = ina260_oc_over_envelope(
                    meas_w,
                    meas_a,
                    max_power_w,
                    max_current_a,
                    INA260_OC_MARGIN,
                );
                if over {
                    ina_oc_strikes = ina260_oc_strike_next(true, ina_oc_strikes);
                    warn!(
                        "INA260 OC backstop: {:.1}W / {:.2}A over {:.0}% of rated [{:.1}W, {:.2}A] — strike {}/{}",
                        meas_w,
                        meas_a,
                        INA260_OC_MARGIN * 100.0,
                        max_power_w,
                        max_current_a,
                        ina_oc_strikes,
                        INA260_OC_DEBOUNCE_TICKS
                    );
                    if ina260_oc_should_cut(ina_oc_strikes, INA260_OC_DEBOUNCE_TICKS) {
                        error!(
                            "INA260 OVER-CURRENT: {:.1}W / {:.2}A sustained over rated envelope — cutting ASIC power",
                            meas_w, meas_a
                        );
                        // Cut hash power FIRST (: cut hash before raising
                        // fan noise), then pin the fan to cool. Power is already
                        // off here, so a failed fan write needs no further kill.
                        fail_closed_power_off(
                            &format!(
                                "INA260 over-current: {:.1}W / {:.2}A sustained",
                                meas_w, meas_a
                            ),
                            &state,
                            Some(&mining_kill),
                            Some(&mut power_mgr),
                            &mut i2c,
                            &mut gpio_ctrl,
                        );
                        fan_ctrl.set_speed(100).ok();
                        if let Err(e) =
                            apply_fan_speed(&mut i2c, 100, &fan_emc2302, &temp_emc, &emc2103)
                        {
                            warn!("INA260 OC: fan pin after power-cut failed: {}", e);
                        }
                        display.notify_urgent(
                            "!! OVER-CURRENT !!",
                            "ASIC disabled",
                            &format!("IP {}", device_ip),
                            "Check PSU/load",
                        );
                    }
                } else {
                    ina_oc_strikes = ina260_oc_strike_next(false, ina_oc_strikes);
                }
            }
        }

        if !any_temp_valid {
            consecutive_temp_failures += 1;
            warn!(
                "All temperature sensors failed ({}/10) — forcing fan to 100%",
                consecutive_temp_failures
            );
            fan_ctrl.set_speed(100).ok();
            apply_fan_speed_or_fail_closed(
                &mut i2c,
                100,
                &fan_emc2302,
                &temp_emc,
                &emc2103,
                runtime_mining_active,
                &state,
                &mining_kill,
                &mut power_mgr,
                &mut gpio_ctrl,
                "THERMAL BLIND fan pin",
            );
            // Sustained temp sensor loss while mining → kill mining (especially critical on Hex)
            if runtime_mining_active && !unsafe_lab_safety_bypass {
                error!("THERMAL BLIND: {} consecutive temp sensor failures — killing mining for safety", consecutive_temp_failures);
                mining_kill.store(true, Ordering::Relaxed);
                {
                    let mut telem = state
                        .telemetry
                        .lock()
                        .unwrap_or_else(|err| err.into_inner());
                    telem.mining_enabled = false;
                    telem.pool_connected = false;
                }
                power_mgr.disable(&mut i2c).ok();
                gpio_ctrl.enable_buck(false).ok();
                display.notify_urgent(
                    "THERMAL BLIND",
                    "Sensors offline",
                    "ASIC disabled",
                    "Fan forced 100%",
                );
            }
        } else {
            consecutive_temp_failures = 0;
        }

        // ── ES-2: die-sensor blindness (fail-closed) ───────────────────
        // A board EXPECTED to carry an ASIC-die sensor has lost EVERY die
        // reading while only cooler proxies (board/inlet/outlet/vreg, ~10-20 C
        // below the die) remain, so `max_temp` understates the true die temp
        // and the overtemp cut could fire late or never. This is distinct from
        // the all-None case above (there a proxy is still valid, so
        // `any_temp_valid` is true and that branch does NOT fire).
        //
        // Force the fan to 100% immediately (immediate airflow is the only safe
        // response when the die is unmeasurable — the documented exception to
        // cut-hash-before-fan-noise), then cut ASIC power after
        // DIE_BLIND_CONFIRM_TICKS consecutive ticks to reject a single transient
        // I2C read glitch. Gated on active mining (no die heat otherwise) and,
        // for the kill, on the lab-safety bypass like the all-None BLIND path.
        if thermal.die_reading_blind && runtime_mining_active {
            consecutive_die_blind += 1;
            warn!(
                "DIE SENSOR BLIND ({}/{}) — no ASIC-die reading, only cooler proxies left; \
                 proxy max_temp {:.0}C UNDERSTATES the die — forcing fan 100%",
                consecutive_die_blind, DIE_BLIND_CONFIRM_TICKS, max_temp
            );
            fan_ctrl.set_speed(100).ok();
            apply_fan_speed_or_fail_closed(
                &mut i2c,
                100,
                &fan_emc2302,
                &temp_emc,
                &emc2103,
                runtime_mining_active,
                &state,
                &mining_kill,
                &mut power_mgr,
                &mut gpio_ctrl,
                "DIE BLIND fan pin",
            );
            if consecutive_die_blind >= DIE_BLIND_CONFIRM_TICKS && !unsafe_lab_safety_bypass {
                error!(
                    "DIE SENSOR BLIND: {} consecutive ticks with no ASIC-die reading — \
                     killing mining for safety (proxy max_temp {:.0}C cannot protect the die)",
                    consecutive_die_blind, max_temp
                );
                mining_kill.store(true, Ordering::Relaxed);
                {
                    let mut telem = state
                        .telemetry
                        .lock()
                        .unwrap_or_else(|err| err.into_inner());
                    telem.mining_enabled = false;
                    telem.pool_connected = false;
                }
                power_mgr.disable(&mut i2c).ok();
                gpio_ctrl.enable_buck(false).ok();
                display.notify_urgent(
                    "DIE SENSOR BLIND",
                    "ASIC temp lost",
                    "ASIC disabled",
                    "Fan forced 100%",
                );
            }
        } else {
            consecutive_die_blind = 0;
        }

        // ── I2C health watchdog (only relevant when mining) ────────────
        if runtime_mining_active {
            if power.is_none() && !any_temp_valid {
                consecutive_i2c_failures += 1;
                if consecutive_i2c_failures >= 3 {
                    error!(
                        "I2C bus dead — killing mining thread ({} consecutive failures)",
                        consecutive_i2c_failures
                    );
                    mining_kill.store(true, Ordering::Relaxed);
                    {
                        let mut telem = state
                            .telemetry
                            .lock()
                            .unwrap_or_else(|err| err.into_inner());
                        telem.mining_enabled = false;
                        telem.pool_connected = false;
                    }
                    fan_ctrl.set_speed(100).ok();
                    apply_fan_speed_or_fail_closed(
                        &mut i2c,
                        100,
                        &fan_emc2302,
                        &temp_emc,
                        &emc2103,
                        runtime_mining_active,
                        &state,
                        &mining_kill,
                        &mut power_mgr,
                        &mut gpio_ctrl,
                        "I2C BUS DEAD fan pin",
                    );
                    power_mgr.disable(&mut i2c).ok();
                    gpio_ctrl.enable_buck(false).ok();
                    display.notify_urgent(
                        "I2C BUS DEAD",
                        "ASIC disabled",
                        "Fan forced 100%",
                        &format!("IP {}", device_ip),
                    );
                    // Continue loop — HTTP server stays alive
                }
            } else {
                consecutive_i2c_failures = 0;
            }
        }

        // ── Fan stall detection (safety critical) ─────────────────────
        let fan_speed = fan_ctrl.current_speed();
        // Read actual fan RPM from EMC2302, EMC2101, or EMC2103 TACH registers
        let mut fan2_rpm_val: u32 = 0;
        let (fan_rpm, any_fan_dead) = if let Some(ref emc) = fan_emc2302 {
            // EMC2302 (Hex boards): read both fans independently
            let rpm1 = emc.get_fan1_rpm(&mut i2c).unwrap_or(0);
            let rpm2 = emc.get_fan2_rpm(&mut i2c).unwrap_or(0);
            fan2_rpm_val = rpm2;
            // Track which fans have ever been seen (distinguishes unconnected from stalled)
            if rpm1 > 0 {
                fan1_ever_seen = true;
            }
            // Expose fan 1 and fan 2 independently through telemetry.
            // XPSAFE-8: the primary reading follows the DECLARED population, so
            // a unit with only header 2 fitted reports its real fan here instead
            // of a hardcoded 0 that would both mis-render and poison the stall
            // kill. Per-header telemetry (fan1/fan2) stays literal.
            let rpm = board_config.primary_tach_rpm(rpm1, rpm2);
            // Hex-class boards require tach on every fan the operator declared
            // present. Treat 0 RPM on a declared fan as a fault after the
            // existing multi-loop confirmation window below. An undeclared
            // header's permanent 0 is not a stall.
            let dead = fan_speed > 0 && board_config.declared_fan_tach_missing(rpm1, rpm2);
            (rpm, dead)
        } else if let Some(ref emc) = temp_emc {
            let rpm = emc.read_fan_rpm(&mut i2c).unwrap_or(0);
            if rpm > 0 {
                fan1_ever_seen = true;
            }
            // Single-fan board: only flag stall if tach previously reported RPM
            // (BitAxe Max and similar boards may not have tach wire connected).
            // HALT-6 / XPSAFE-7: a fan that NEVER spins keeps fan1_ever_seen=false,
            // so the lenient heuristic could never fire the FAN STALL kill. When the
            // operator has opted in (fan_tach_present=true -> tach_proof_required()),
            // fail closed on a never-spinning fan; genuinely tachless boards keep the
            // lenient heuristic.
            (
                rpm,
                (board_config.tach_proof_required() || fan1_ever_seen) && rpm == 0 && fan_speed > 0,
            )
        } else if fan_is_emc2103 {
            let rpm = emc2103.as_ref().map(|e| e.read_rpm(&mut i2c)).unwrap_or(0);
            if rpm > 0 {
                fan1_ever_seen = true;
            }
            // GT-class boards require a working tach path.
            (rpm, rpm == 0 && fan_speed > 0)
        } else {
            (0, false)
        };
        fan_ctrl.rpm = fan_rpm;
        if runtime_mining_active && fan_speed > 0 && any_fan_dead {
            consecutive_fan_stall += 1;
            if consecutive_fan_stall >= 3 {
                // 15 seconds of fan stall while commanded on — stall confirmed
                error!(
                    "FAN STALL DETECTED — no RPM for 15s while fan at {}%",
                    fan_speed
                );
                mining_kill.store(true, Ordering::Relaxed);
                {
                    let mut telem = state
                        .telemetry
                        .lock()
                        .unwrap_or_else(|err| err.into_inner());
                    telem.mining_enabled = false;
                    telem.pool_connected = false;
                }
                power_mgr.disable(&mut i2c).ok();
                gpio_ctrl.enable_buck(false).ok();
                display.notify_urgent(
                    "!! FAN STALL !!",
                    "RPM = 0",
                    "ASIC disabled",
                    "Check fan connector",
                );
                display.show_status(
                    &mut i2c,
                    "FAN STALL DETECTED!",
                    &format!("RPM=0 fan={}%", fan_speed),
                    "ASIC shutting down",
                    "Check fan connection",
                );
            } else if consecutive_fan_stall >= 2 {
                // 10 seconds — warning
                warn!(
                    "Fan stall warning — RPM=0 for {}s",
                    consecutive_fan_stall * 5
                );
                display.notify_urgent(
                    "FAN WARNING",
                    "RPM = 0",
                    &format!("Fan at {}%", fan_speed),
                    "Check fan!",
                );
            }
        } else {
            consecutive_fan_stall = 0;
        }

        // ── Update shared telemetry ────────────────────────────────────
        {
            let status_snapshots = stratum_status_snapshots(&state);
            let (pool_connected, pool_difficulty) = status_snapshots
                .iter()
                .find(|status| status.connected)
                .map(|status| (true, status.difficulty))
                .unwrap_or_else(|| {
                    state
                        .pool_stats
                        .lock()
                        .map(|stats| {
                            let connected = stats.iter().any(|pool| pool.connected);
                            let difficulty = stats
                                .iter()
                                .find(|pool| pool.connected)
                                .map(|pool| pool.difficulty)
                                .unwrap_or(0.0);
                            (connected, difficulty)
                        })
                        .unwrap_or((false, 0.0))
                });
            let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref p) = power {
                // HALPWR-2 / COMP-6: per-field NaN guard. power.rs get_telemetry now
                // returns f32::NAN for a failed sub-read (e.g. a transient INA260 /
                // TPS546 NACK on one field). Writing a NaN into telem.power_w would
                // poison mean_power_w in the autotuner's PowerWindow and the
                // heartbeat/history log. Guard each field independently so a single
                // blanked field HOLDS its last-good telem value rather than
                // overwriting it, and one blanked field never blanks the others.
                if power_field_available(p.voltage_mv) {
                    telem.voltage_mv = p.voltage_mv;
                }
                if power_field_available(p.current_ma) {
                    telem.current_ma = p.current_ma;
                }
                if power_field_available(p.power_w) {
                    telem.power_w = p.power_w;
                }
                if power_field_available(p.input_voltage_mv) {
                    telem.input_voltage_mv = p.input_voltage_mv;
                }
            }
            telem.chip_temp_c = chip_temp.unwrap_or(0.0);
            telem.board_temp_c = board_temp.unwrap_or(0.0);
            telem.vreg_temp_c = vreg_temp.unwrap_or(0.0);
            telem.inlet_temp_c = inlet_temp.unwrap_or(0.0);
            telem.outlet_temp_c = outlet_temp.unwrap_or(0.0);
            telem.sensors_ok = any_temp_valid;
            // HALT-6 / XPSAFE-7: surface "no fan proof (heuristic only)" so the
            // dashboard/self-test does not present a tachless board's fan as proven
            // healthy. True when the board has no tach proof available.
            telem.fan_proof_heuristic_only = !board_config.tach_proof_required();
            // HALT-5: on emc_internal_temp boards chip_temp is a board-ambient
            // proxy (EMC2101 internal die + offset), not a true junction reading.
            // Label it so the dashboard does not present it as junction temp. The
            // thermal cuts and the +offset are UNCHANGED.
            telem.chip_temp_is_ambient_proxy = board_config.emc_internal_temp;
            telem.fan_speed_pct = fan_ctrl.current_speed();
            telem.fan_rpm = fan_ctrl.last_rpm();
            telem.fan2_rpm = fan2_rpm_val;
            telem.uptime_secs = uptime;
            telem.pool_connected = pool_connected;
            telem.pool_difficulty = pool_difficulty;

            // Populate per-chip data for any board with at least one ASIC.
            // Single-chip boards (Gamma/Ultra/Supra/Max) get one entry so the
            // dashboard ASIC Chips card always appears with live telemetry.
            if asic_count >= 1 {
                // MAINAPI-1: per_chip is a fixed [PerChipStats; MAX_CHIPS] (=16
                // since the Lucky LV08 9-chip scaling wave — 9×28=252 keeps raw
                // nonce bytes 252-255 decoding to asic_nr 9, one past a 9-element
                // array, so the array is oversized to 16). An asic_count >
                // MAX_CHIPS would panic on an unchecked index = miner down. Bound
                // the loop to MAX_CHIPS and use .get() as a belt-and-suspenders
                // degrade so a bad asic_count can never index out of bounds.
                // The `.min(MAX_CHIPS)` clamp is pinned by a dcentaxe-core
                // source contract — do NOT remove it.
                let chip_count = (asic_count as usize).min(dcentaxe_mining::stats::MAX_CHIPS);
                let mut chips = Vec::with_capacity(chip_count);
                for i in 0..chip_count {
                    let chip_t = if fan_is_emc2103 {
                        if i == 0 {
                            chip_temp
                        } else if i == 1 {
                            gt_temp2
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    // Get per-chip nonce/error counts from mining stats
                    let (chip_nonces, chip_errs) = if let Ok(stats) = state.stats.lock() {
                        stats
                            .per_chip
                            .get(i)
                            .map(|c| (c.nonces, c.errors))
                            .unwrap_or((0, 0))
                    } else {
                        (0, 0)
                    };
                    chips.push(shared::ChipData {
                        temp_c: chip_t,
                        status: shared::ChipStatus::Unknown,
                        hw_errors: chip_errs,
                        shares: chip_nonces,
                        hashrate_ghs: None,
                    });
                }
                telem.chip_data = chips;
            } else {
                telem.chip_data.clear();
            }
            telem.free_heap = unsafe { sys::esp_get_free_heap_size() };
            telem.wifi_rssi = unsafe {
                let mut rssi: i32 = 0;
                esp_idf_svc::sys::esp_wifi_sta_get_rssi(&mut rssi);
                rssi as i8
            };
            telem.device_ip = device_ip.clone();
        }

        // ── WiFi link health + auto-reconnect ──────────────────────────
        // Poll once per tick (~5 s). On disconnect, calls `wifi.connect()`
        // with linear backoff (1 → 2 → 5 → 10 → 30 s, cap 30 s) until link
        // returns. See wifi::tick_reconnect for design rationale.
        {
            let mut wifi_guard = state.wifi.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref mut w) = *wifi_guard {
                let now_ms = shared::unix_time_ms();
                wifi::tick_reconnect(w.as_mut(), &mut wifi_reconnect_state, now_ms);
            }
        }

        // ── W5500 LAN link health + Wi-Fi⇄Ethernet failover observer ───
        // Poll once per tick (~5 s), same cadence as the Wi-Fi reconnect.
        // lwIP already steers outbound traffic by netif route priority; this
        // block derives the honest "active link" label (Ethernet only with
        // link + IP) and logs every transition with the raw link state.
        #[cfg(feature = "eth-w5500")]
        if let Some(ref eth) = eth_link {
            let wifi_up = {
                let wifi_guard = state.wifi.lock().unwrap_or_else(|e| e.into_inner());
                wifi_guard
                    .as_ref()
                    .map(|w| w.is_connected().unwrap_or(false))
                    .unwrap_or(false)
            };
            let snap = eth.snapshot(wifi_up);
            if let Some((from, to)) = eth_failover.tick(eth_net_mode, snap) {
                let ip = eth
                    .ip()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "none".into());
                info!(
                    "NET: active link {} -> {} (wifi_up={} eth_link={} eth_ip={} transitions={})",
                    from.as_str(),
                    to.as_str(),
                    snap.wifi_up,
                    snap.eth_link_up,
                    ip,
                    eth_failover.transitions(),
                );
            }
        }

        {
            let snap = state
                .stats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot();
            let live_config = state.config.lock().unwrap_or_else(|e| e.into_inner());
            let local_id = {
                let mut mac = [0u8; 6];
                unsafe {
                    esp_idf_svc::sys::esp_wifi_get_mac(
                        esp_idf_svc::sys::wifi_interface_t_WIFI_IF_STA,
                        mac.as_mut_ptr(),
                    );
                }
                format!(
                    "bitaxe-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )
            };
            let mut swarm = state.swarm.lock().unwrap_or_else(|e| e.into_inner());
            swarm.local.id = local_id;
            swarm.local.ip = device_ip.clone();
            swarm.local.hostname = if live_config.hostname.is_empty() {
                format!("dcentaxe-{}", board_config.device_model)
            } else {
                live_config.hostname.clone()
            };
            let telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            swarm.local.mining_enabled = telem.mining_enabled;
            swarm.local.pool_connected = telem.pool_connected;
            swarm.local.hashrate_ghs = snap.hashrate_5m_ghs;
            swarm.local.last_seen_unix_ms = shared::unix_time_ms();
            swarm.discovery.api_url = Some(format!("http://{}/api/swarm", device_ip));
            swarm.discovery.mcp_url = Some(format!("http://{}/mcp", device_ip));
        }

        let history_now_ms = shared::unix_time_ms();
        if history_now_ms.saturating_sub(last_history_sample_ms) >= 60_000 {
            let snap = state
                .stats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot();
            let telem = state
                .telemetry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let statuses = shared::stratum_status_snapshots(&state);
            let active_status = statuses
                .iter()
                .find(|status| status.connected)
                .or(statuses.first());
            let (submitted, pool_accepted, pool_rejected) =
                statuses.iter().fold((0_u64, 0_u64, 0_u64), |acc, status| {
                    (
                        acc.0 + status.shares_submitted,
                        acc.1 + status.shares_accepted,
                        acc.2 + status.shares_rejected,
                    )
                });
            let mut history = state.history.lock().unwrap_or_else(|e| e.into_inner());
            history.samples.push(crate::shared::MinerHistorySample {
                ts_unix_ms: history_now_ms,
                hashrate_ghs: snap.hashrate_5m_ghs,
                hashrate_15s_ghs: snap.hashrate_15s_ghs,
                hashrate_30s_ghs: snap.hashrate_30s_ghs,
                power_w: telem.power_w,
                temp_c: telem.chip_temp_c,
                local_accepted_shares: snap.accepted_shares,
                local_rejected_shares: snap.rejected_shares,
                submitted_shares: submitted,
                pool_accepted_shares: pool_accepted,
                pool_rejected_shares: pool_rejected,
                response_time_ms: active_status
                    .map(|status| status.last_share_response_ms)
                    .unwrap_or(0.0),
                failover_active: active_status
                    .map(|status| status.failover_active)
                    .unwrap_or(false),
                connected: active_status
                    .map(|status| status.connected)
                    .unwrap_or(telem.pool_connected),
            });
            if history.samples.len() > 60 {
                let excess = history.samples.len() - 60;
                history.samples.drain(0..excess);
            }
            let mut events: Vec<dcentaxe_stratum::StratumEventRecord> = statuses
                .iter()
                .flat_map(|status| status.recent_events.clone())
                .collect();
            events.sort_by_key(|event| event.ts_unix_ms);
            if events.len() > 64 {
                events = events.split_off(events.len() - 64);
            }
            history.events = events;
            last_history_sample_ms = history_now_ms;
        }

        // ── Thermal protection (only when mining — bogus readings when ASIC off) ──
        if runtime_mining_active && max_temp > EMERGENCY_TEMP_C {
            error!("THERMAL EMERGENCY {:.0}C — ASIC OFF", max_temp);
            mining_kill.store(true, Ordering::Relaxed);
            {
                let mut telem = state
                    .telemetry
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                telem.mining_enabled = false;
                telem.pool_connected = false;
            }
            fan_ctrl.set_speed(100).ok();
            apply_fan_speed_or_fail_closed(
                &mut i2c,
                100,
                &fan_emc2302,
                &temp_emc,
                &emc2103,
                runtime_mining_active,
                &state,
                &mining_kill,
                &mut power_mgr,
                &mut gpio_ctrl,
                "THERMAL EMERGENCY fan pin",
            );
            power_mgr.disable(&mut i2c).ok();
            gpio_ctrl.enable_buck(false).ok();
            display.show_status(
                &mut i2c,
                "THERMAL EMERGENCY!",
                &format!("{:.0}C - ASIC OFF", max_temp),
                &format!("IP: {}", device_ip),
                "Reboot to resume",
            );
            // Thermal auto-recovery: monitor temp and reboot when safe
            let mut thermal_cooldown = 0u32;
            loop {
                // This recovery loop intentionally bypasses the normal main-loop
                // WDT feed while fans stay pinned and ASIC power is off.
                unsafe {
                    let _ = sys::esp_task_wdt_reset();
                }
                std::thread::sleep(Duration::from_secs(5));
                unsafe {
                    let _ = sys::esp_task_wdt_reset();
                }
                // Re-assert fan 100% every cooldown tick. The fan duty was
                // commanded once before this loop; if a transient I2C glitch
                // reset the EMC fan register mid-cooldown, the fan could quietly
                // drop on a still-warm board until reboot. Re-issuing the write
                // self-heals a glitched register while the board cools. ASIC
                // power is already cut here, so a failed re-write needs no
                // further kill action — log and retry next tick.
                fan_ctrl.set_speed(100).ok();
                if let Err(e) = apply_fan_speed(&mut i2c, 100, &fan_emc2302, &temp_emc, &emc2103) {
                    warn!(
                        "Thermal recovery: fan 100% re-assert failed: {} (retry next tick)",
                        e
                    );
                }
                // Re-read current temperatures from live sensors on every recovery tick.
                let cool_temp = [
                    temp_emc
                        .as_mut()
                        .and_then(|s| s.read_external_temp(&mut i2c).ok().flatten())
                        .and_then(|t| apply_temp_offset(Some(t))),
                    apply_temp_offset(
                        emc2103
                            .as_ref()
                            .and_then(|e| e.read_secondary_temp(&mut i2c)),
                    ),
                    apply_temp_offset(emc2103.as_ref().and_then(|e| e.read_chip_temp(&mut i2c))),
                    tmp_primary
                        .as_ref()
                        .and_then(|s| s.read_temp(&mut i2c).ok())
                        .and_then(|t| apply_temp_offset(Some(t))),
                    tmp_secondary
                        .as_ref()
                        .and_then(|s| s.read_temp(&mut i2c).ok())
                        .and_then(|t| apply_temp_offset(Some(t))),
                    temp_emc
                        .as_ref()
                        .and_then(|s| s.read_internal_temp(&mut i2c).ok())
                        .and_then(|t| apply_temp_offset(Some(t))),
                    if power_mgr.has_vreg_temp_sensor() {
                        power_mgr.get_vreg_temp(&mut i2c).ok()
                    } else {
                        None
                    },
                ]
                .into_iter()
                .flatten()
                .fold(None, |acc: Option<f32>, temp| {
                    Some(acc.map_or(temp, |current| current.max(temp)))
                });

                if let Some(cool_temp) = cool_temp {
                    if cool_temp < 75.0 {
                        thermal_cooldown += 1;
                        info!(
                            "Thermal recovery: {:.0}C — cooldown {}/12 (60s needed)",
                            cool_temp, thermal_cooldown
                        );
                        display.show_status(
                            &mut i2c,
                            "COOLING DOWN...",
                            &format!("{:.0}C (need <75C)", cool_temp),
                            &format!("Recovery in {}s", (12 - thermal_cooldown) * 5),
                            &format!("IP: {}", device_ip),
                        );
                        if thermal_cooldown >= 12 {
                            info!("Thermal recovery complete — rebooting to resume mining");
                            display.show_status(
                                &mut i2c,
                                "TEMP OK - REBOOTING",
                                &format!("{:.0}C - safe", cool_temp),
                                "Resuming mining...",
                                "",
                            );
                            std::thread::sleep(Duration::from_secs(2));
                            unsafe {
                                sys::esp_restart();
                            }
                        }
                    } else {
                        thermal_cooldown = 0;
                        error!("Still too hot: {:.0}C — waiting...", cool_temp);
                        display.show_status(
                            &mut i2c,
                            "THERMAL EMERGENCY!",
                            &format!("{:.0}C - TOO HOT", cool_temp),
                            "Waiting to cool...",
                            &format!("IP: {}", device_ip),
                        );
                    }
                } else {
                    thermal_cooldown = 0;
                    display.show_status(
                        &mut i2c,
                        "THERMAL EMERGENCY!",
                        "Sensor data unavailable",
                        "Fan pinned at 100%",
                        &format!("Waiting: {}", device_ip),
                    );
                }
            }
        } else if runtime_mining_active && max_temp > 95.0 {
            // Progressive thermal throttle: reduce frequency to shed heat
            // before reaching the 105°C emergency shutdown.
            // XPSAFE-5: CUT HASH FIRST, then pin the fan. fan=100% is correct and
            // reserved for this 95 C+ band, but the frequency reduction is applied
            // BEFORE the fan bump so heat generation drops first.
            let degrees_over = (max_temp - 95.0).min(10.0);
            let reduction_mhz = degrees_over * 25.0; // 25 MHz per degree above 95
            let configured_target_freq = state
                .config
                .lock()
                .map(|cfg| cfg.target_frequency)
                .unwrap_or(last_applied_freq);
            let throttled_freq = (configured_target_freq - reduction_mhz).max(100.0);
            warn!(
                "Thermal throttle: {:.0}C — reducing freq to {:.0} MHz",
                max_temp, throttled_freq
            );
            if (throttled_freq - last_applied_freq).abs() > 0.1 {
                match freq_cmd_tx.send(throttled_freq) {
                    Ok(()) => last_applied_freq = throttled_freq,
                    Err(e) => error!("Thermal throttle frequency apply failed: {}", e),
                }
            }
            fan_ctrl.set_speed(100).ok();
            apply_fan_speed_or_fail_closed(
                &mut i2c,
                100,
                &fan_emc2302,
                &temp_emc,
                &emc2103,
                runtime_mining_active,
                &state,
                &mining_kill,
                &mut power_mgr,
                &mut gpio_ctrl,
                "THERMAL THROTTLE fan pin",
            );
        } else if runtime_mining_active && max_temp > WARNING_TEMP_C {
            // XPSAFE-5 WARNING tier (>90 C): cut-hash-before-fan-noise (home posture).
            // Shed a modest amount of hash FIRST, then raise the fan only to a
            // home-friendly cap (THERMAL_WARN_FAN_CAP_PCT, NOT 100%). The 95 C tier
            // above escalates to 100% if the temperature keeps climbing.
            let warn_freq = {
                let configured_target_freq = state
                    .config
                    .lock()
                    .map(|cfg| cfg.target_frequency)
                    .unwrap_or(last_applied_freq);
                (configured_target_freq - THERMAL_WARN_FREQ_SHED_MHZ).max(100.0)
            };
            warn!(
                "Thermal warning: {:.0}C — shedding hash to {:.0} MHz then fan to {}%",
                max_temp, warn_freq, THERMAL_WARN_FAN_CAP_PCT
            );
            if (warn_freq - last_applied_freq).abs() > 0.1 {
                match freq_cmd_tx.send(warn_freq) {
                    Ok(()) => last_applied_freq = warn_freq,
                    Err(e) => error!("Thermal warning frequency apply failed: {}", e),
                }
            }
            fan_ctrl.set_speed(THERMAL_WARN_FAN_CAP_PCT).ok();
            apply_fan_speed_or_fail_closed(
                &mut i2c,
                THERMAL_WARN_FAN_CAP_PCT,
                &fan_emc2302,
                &temp_emc,
                &emc2103,
                runtime_mining_active,
                &state,
                &mining_kill,
                &mut power_mgr,
                &mut gpio_ctrl,
                "THERMAL WARNING fan pin",
            );
        }

        // ── Apply config changes from API/MCP ──────────────────────────
        // Note: config lock is acquired multiple times this iteration (~7 times).
        // Each lock costs ~1µs. Total: ~7µs per 5s iteration = negligible.
        // If profiling shows contention, consolidate into a single snapshot here.
        {
            let cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
            let mut voltage_apply_ok = true;
            // Fan speed changes (skip if auto-control is active)
            // ES-2: never let a user/config fan setpoint undo the die-blind
            // fan-100 override — while die-blind we cannot trust `max_temp` to
            // clear the WARNING gate below, so guard on the flag explicitly.
            if cfg.fan_target_temp_c == 0
                && cfg.fan_speed_pct != fan_ctrl.current_speed()
                && !mining_kill.load(Ordering::Relaxed)
                && any_temp_valid
                && !thermal.die_reading_blind
                && max_temp < WARNING_TEMP_C
            {
                let _ = fan_ctrl.set_speed(cfg.fan_speed_pct);
                apply_fan_speed_or_fail_closed(
                    &mut i2c,
                    fan_ctrl.current_speed(),
                    &fan_emc2302,
                    &temp_emc,
                    &emc2103,
                    runtime_mining_active,
                    &state,
                    &mining_kill,
                    &mut power_mgr,
                    &mut gpio_ctrl,
                    "CONFIG fan pin",
                );
            }
            // Voltage changes (compare against last applied, not immutable boot config)
            if !thermal_clamp_active && cfg.target_voltage_mv != last_applied_voltage {
                match power_mgr.set_voltage(&mut i2c, cfg.target_voltage_mv) {
                    Ok(()) => last_applied_voltage = cfg.target_voltage_mv,
                    Err(e) => {
                        voltage_apply_ok = false;
                        error!(
                            "Config voltage apply failed: {} mV: {}",
                            cfg.target_voltage_mv, e
                        );
                    }
                }
            }
            // Display flip changes
            if cfg.display_inverted != display.inverted {
                let _ = display.set_flip(&mut i2c, cfg.display_inverted);
            }
            // Frequency changes (compare against last applied, not immutable boot config)
            if !thermal_clamp_active && cfg.target_frequency != last_applied_freq {
                let raises_frequency = cfg.target_frequency > last_applied_freq;
                if raises_frequency && !voltage_apply_ok {
                    warn!(
                        "Config frequency increase to {:.0} MHz skipped after voltage apply failure",
                        cfg.target_frequency
                    );
                } else {
                    let _ = freq_cmd_tx.send(cfg.target_frequency);
                    last_applied_freq = cfg.target_frequency;
                }
            }
        }

        // ── Mining toggle from API ──────────────────────────────────────
        // MAINAPI-5: `mining_kill` is ONE-WAY at runtime. Every site in the main
        // loop only ever stores `true` into it (API stop, fan stall, thermal
        // emergency, etc.); nothing ever clears it back to false in the runtime
        // loop. Once the ASIC has been powered off (power_mgr.disable +
        // enable_buck(false)) the ONLY safe re-init path is a full reboot
        // (esp_restart below), which re-runs ASIC bring-up from scratch. Do NOT add
        // a runtime `store(false)` here: resuming the dispatcher against a
        // powered-off ASIC would dispatch work to a dead chip. Recovery is
        // reboot-only by design (this mirrors the thermal-recovery esp_restart).
        let api_mining_enabled = {
            let telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.mining_enabled
        };
        if !api_mining_enabled && !mining_kill.load(Ordering::Relaxed) {
            info!("Mining stopped by user via API");
            mining_kill.store(true, Ordering::Relaxed);
            power_mgr.disable(&mut i2c).ok();
            gpio_ctrl.enable_buck(false).ok();
        } else if api_mining_enabled && mining_kill.load(Ordering::Relaxed) {
            // Resume is reboot-only: never clear mining_kill in place.
            info!("Mining resume requested by user — rebooting to reinit ASIC");
            unsafe {
                esp_idf_svc::sys::esp_restart();
            }
        }

        // ── Daily schedule check (profile + autotuner policy switching) ──
        let active_schedule = {
            let cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
            if cfg.schedule_enabled && !cfg.power_schedule.is_empty() {
                let (minute_of_day, time_source) = crate::config::schedule_minute_of_day(
                    cfg.schedule_timezone_offset_minutes,
                    uptime,
                );
                crate::config::active_power_schedule(&cfg.power_schedule, minute_of_day)
                    .map(|(idx, entry)| (idx, minute_of_day, time_source, entry.clone()))
            } else {
                None
            }
        };

        if let Some((idx, minute_of_day, time_source, entry)) = active_schedule {
            let schedule_key = format!(
                "{}:{}:{:.1}:{}:{:?}:{:?}:{:?}",
                idx,
                entry.start_minute_of_day(),
                entry.frequency,
                entry.voltage_mv,
                entry.autotune_enabled,
                entry.autotune_mode,
                entry.autotune_target
            );
            let needs_schedule_apply = last_schedule_key.as_deref() != Some(schedule_key.as_str())
                || (entry.frequency - last_applied_freq).abs() > 0.1
                || entry.voltage_mv != last_applied_voltage;
            if needs_schedule_apply && !thermal_clamp_active {
                if schedule_base_point.is_none() {
                    let cfg = state.config.lock().unwrap_or_else(|e| e.into_inner());
                    schedule_base_point = Some((cfg.target_frequency, cfg.target_voltage_mv));
                }
                let label = if entry.label.trim().is_empty() {
                    "scheduled profile"
                } else {
                    entry.label.as_str()
                };

                if let Some(enabled) = entry.autotune_enabled {
                    let mut autotune = state.autotuner.lock().unwrap_or_else(|e| e.into_inner());
                    autotune.enabled = enabled;
                    if enabled {
                        autotune.mode = entry
                            .autotune_mode
                            .as_deref()
                            .and_then(crate::shared::AutotuneMode::from_api_str)
                            .unwrap_or(crate::shared::AutotuneMode::BestEfficiency);
                    }
                    if let Some(target) = entry.autotune_target {
                        autotune.target_value = target;
                    }
                    autotune.status = if enabled {
                        format!("scheduled: {}", label)
                    } else {
                        "scheduled fixed profile".to_string()
                    };
                    info!(
                        "Schedule: autotuner {} for '{}' (mode={:?}, target={:.1})",
                        if enabled { "enabled" } else { "disabled" },
                        label,
                        autotune.mode,
                        autotune.target_value
                    );
                }

                info!(
                    "Schedule: applying '{}' at {:02}:{:02} via {} ({:.0}MHz, {}mV)",
                    label,
                    minute_of_day / 60,
                    minute_of_day % 60,
                    time_source,
                    entry.frequency,
                    entry.voltage_mv
                );
                apply_automatic_operating_point(
                    &state,
                    &mut power_mgr,
                    &mut i2c,
                    &freq_cmd_tx,
                    &mut last_applied_voltage,
                    &mut last_applied_freq,
                    entry.frequency,
                    entry.voltage_mv,
                    ControlSurface::Schedule,
                    "Schedule",
                );
                last_schedule_key = Some(schedule_key);
            }
        } else if last_schedule_key.is_some() && !thermal_clamp_active {
            if let Some((base_freq, base_voltage)) = schedule_base_point.take() {
                info!(
                    "Schedule: inactive — restoring base profile ({:.0}MHz, {}mV)",
                    base_freq, base_voltage
                );
                apply_automatic_operating_point(
                    &state,
                    &mut power_mgr,
                    &mut i2c,
                    &freq_cmd_tx,
                    &mut last_applied_voltage,
                    &mut last_applied_freq,
                    base_freq,
                    base_voltage,
                    ControlSurface::Schedule,
                    "Schedule",
                );
            }
            last_schedule_key = None;
        }

        // ── Autotuner tick ─────────────────────────────────────────────
        if runtime_mining_active && any_temp_valid && !thermal_clamp_active {
            if let Some((new_freq, new_voltage)) = autotuner.tick(&state) {
                apply_automatic_operating_point(
                    &state,
                    &mut power_mgr,
                    &mut i2c,
                    &freq_cmd_tx,
                    &mut last_applied_voltage,
                    &mut last_applied_freq,
                    new_freq,
                    new_voltage,
                    ControlSurface::Autotuner,
                    "Autotuner",
                );
            }
        }

        // ── Fan auto-control (PID + EMA) ──────────────────────────────
        // Always ingest the current max temp into the EMA filter so we can
        // fall through to `current_output()` for dashboard smoothing even
        // when auto-control is off.
        if any_temp_valid {
            fan_pid.ingest(max_temp);
        }
        let live_fan_target = state
            .config
            .lock()
            .map(|c| c.fan_target_temp_c)
            .unwrap_or(0);
        if live_fan_target > 0
            && runtime_mining_active
            && any_temp_valid
            && max_temp <= WARNING_TEMP_C
        {
            // Tick interval matches the main loop (5 s). ESP-Miner PR #1640 uses
            // 100 ms; our loop is locked to 5 s so the controller is driven with
            // dt_ms=5000 and the integrator clamp prevents windup at this cadence.
            if let Some(pct) = fan_pid.update(live_fan_target as f32, 5_000, 30.0, 100.0) {
                let _ = fan_ctrl.set_speed(pct.round() as u8);
                apply_fan_speed_or_fail_closed(
                    &mut i2c,
                    fan_ctrl.current_speed(),
                    &fan_emc2302,
                    &temp_emc,
                    &emc2103,
                    runtime_mining_active,
                    &state,
                    &mining_kill,
                    &mut power_mgr,
                    &mut gpio_ctrl,
                    "AUTO FAN fan pin",
                );
            }
        } else if live_fan_target == 0
            && runtime_mining_active
            && any_temp_valid
            && max_temp <= WARNING_TEMP_C
        {
            // HALT-10: always-on gentle proportional fan curve for manual/unset
            // (fan_target_temp_c == 0). The explicit PID path above is unchanged;
            // this only runs when the PID is NOT driving the fan. It maps max_temp
            // linearly into [PROP_FAN_MIN_PCT, PROP_FAN_MAX_PCT] between the comfort
            // floor and the WARNING band, giving a continuous ramp instead of a
            // step. It only ever RAISES the fan above the current (possibly manual)
            // setting — never reduces a user's higher command, never below the 20%
            // floor — and the 90 C -> cap / 105 C -> cut backstops still apply
            // (this branch is gated `max_temp <= WARNING_TEMP_C`).
            let span = (PROP_FAN_HIGH_TEMP_C - PROP_FAN_LOW_TEMP_C).max(1.0);
            let frac = ((max_temp - PROP_FAN_LOW_TEMP_C) / span).clamp(0.0, 1.0);
            let prop_pct = (PROP_FAN_MIN_PCT as f32
                + frac * (PROP_FAN_MAX_PCT as f32 - PROP_FAN_MIN_PCT as f32))
                .round() as u8;
            // Respect the 20% mining floor and never reduce a higher manual command.
            let desired = prop_pct.max(20);
            if desired > fan_ctrl.current_speed() {
                let _ = fan_ctrl.set_speed(desired);
                apply_fan_speed_or_fail_closed(
                    &mut i2c,
                    fan_ctrl.current_speed(),
                    &fan_emc2302,
                    &temp_emc,
                    &emc2103,
                    runtime_mining_active,
                    &state,
                    &mining_kill,
                    &mut power_mgr,
                    &mut gpio_ctrl,
                    "PROP FAN fan pin",
                );
            }
        }

        // ── Heartbeat log ──────────────────────────────────────────────
        let watts = power.as_ref().map(|p| p.power_w).unwrap_or(0.0);
        let pwr = power
            .map(|p| {
                format!(
                    "{:.0}mV {:.1}A {:.1}W",
                    p.voltage_mv,
                    p.current_ma / 1000.0,
                    p.power_w
                )
            })
            .unwrap_or_else(|| "N/A".into());
        #[cfg_attr(feature = "display-none", allow(unused_variables))]
        let (
            hr,
            accepted,
            rejected,
            best_diff,
            clean_jobs,
            block_height,
            streak,
            streak_best,
            sparkline,
            mood_now,
        ) = {
            let mut s = state.stats.lock().unwrap_or_else(|e| e.into_inner());
            s.push_hashrate_sample(); // record hashrate for sparkline
            s.push_temp_sample(max_temp); // record temp for thermal sparkline
            let fan_target = state
                .config
                .lock()
                .map(|c| c.fan_target_temp_c as f32)
                .unwrap_or(65.0);
            let mood = s.mood_score(max_temp, fan_target);
            s.push_mood_sample(mood);
            let snap = s.snapshot();
            (
                snap.hashrate_5m_ghs,
                snap.accepted_shares,
                snap.rejected_shares,
                snap.best_difficulty,
                snap.clean_jobs_count,
                snap.block_height,
                snap.accept_streak,
                snap.best_streak,
                snap.hashrate_sparkline,
                mood,
            )
        };
        // Check for new all-time best share difficulty
        let best_ever = {
            let telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.best_diff_ever
        };
        let notification_config = state
            .config
            .lock()
            .map(|config| config.notifications.clone())
            .unwrap_or_default();
        if notification_config.enabled {
            let failover_active = shared::stratum_status_snapshots(&state)
                .first()
                .map(|status| status.failover_active)
                .unwrap_or(false);
            if failover_active != previous_failover_active {
                notifications::spawn_event(
                    notification_config.clone(),
                    notifications::NotificationKind::Failover,
                    if failover_active {
                        "Pool failover active"
                    } else {
                        "Primary pool restored"
                    },
                    format!("Miner: {}", device_ip),
                );
                previous_failover_active = failover_active;
            }

            let thermal_now = max_temp > WARNING_TEMP_C;
            if thermal_now && !thermal_notification_active {
                notifications::spawn_event(
                    notification_config.clone(),
                    notifications::NotificationKind::Thermal,
                    "Thermal warning",
                    format!("Maximum reported temperature: {:.1} C", max_temp),
                );
            }
            thermal_notification_active = thermal_now;

            let milestone = notification_config.share_milestone;
            if milestone > 0 {
                let reached = accepted / milestone * milestone;
                if reached > last_notified_share_milestone {
                    notifications::spawn_event(
                        notification_config,
                        notifications::NotificationKind::ShareMilestone,
                        "Share milestone",
                        format!("{} accepted shares", reached),
                    );
                    last_notified_share_milestone = reached;
                }
            }
        }
        // ── NVS dirty flags for batched writes (1 open per tick max) ──
        let mut nvs_save_best_diff = false;
        let mut nvs_save_achievements = false;
        let mut nvs_save_streak = false;
        let mut nvs_save_lifetime = false;
        let mut nvs_save_cached_diff = false;

        // Flag a cached-diff save whenever the live pool diff drifts meaningfully
        // from the last value we persisted (10 % hysteresis prevents flash wear
        // on vardiff wobble). ESP-Miner PR #1594 parity.
        {
            let live_pool_diff = state
                .telemetry
                .lock()
                .map(|t| t.pool_difficulty)
                .unwrap_or(0.0);
            let pool_connected = state
                .telemetry
                .lock()
                .map(|t| t.pool_connected)
                .unwrap_or(false);
            if pool_connected && live_pool_diff >= 1.0 {
                let drift = (live_pool_diff - cached_pool_difficulty).abs();
                if drift > (cached_pool_difficulty * 0.1).max(1.0) {
                    cached_pool_difficulty = live_pool_diff;
                    nvs_save_cached_diff = true;
                }
            }
        }

        if best_diff > best_ever && best_diff > 0.0 {
            info!(
                "NEW ALL-TIME BEST SHARE: {:.2} (was {:.2})",
                best_diff, best_ever
            );
            let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.best_diff_ever = best_diff;
            best_nonce_diff = best_diff;
            best_nonce_val = (best_diff as u32).wrapping_mul(0x1337);
            nvs_save_best_diff = true;
            // Achievement: Best Day Ever
            if achievements & nvs_config::ACH_BEST_DAY == 0 {
                achievements |= nvs_config::ACH_BEST_DAY;
                oled_notify!(display,
                    "** ACHIEVEMENT! **",
                    "Best Day Ever!",
                    "New all-time best!",
                    &format!(
                        "{}/{} unlocked",
                        nvs_config::achievement_count(achievements),
                        nvs_config::ACHIEVEMENT_TOTAL
                    ),
                );
                achievement_flash_tick = 1;
                nvs_save_achievements = true;
            }
        }

        let config_freq = state
            .config
            .lock()
            .map(|c| c.target_frequency)
            .unwrap_or(0.0);
        let telem_heap = state.telemetry.lock().map(|t| t.free_heap).unwrap_or(0);

        info!("up={}s hr={:.1}GH/s pwr=[{}] t={:.0}C fan={}% shares={}/{} freq={:.0} best={:.0} heap={}",
            uptime, hr, pwr, max_temp, fan_ctrl.current_speed(),
            accepted, accepted + rejected,
            config_freq, best_diff, telem_heap);

        // ══════════════════════════════════════════════════════════════
        // BITCOIN MINING HACKER TAMAGOTCHI
        // Your BitAxe is a tiny living mining creature!
        // It eats SHA256 hashes, celebrates shares, learns Bitcoin,
        // and tells its own story on the OLED.
        // ══════════════════════════════════════════════════════════════

        #[cfg(feature = "display-ssd1306")]
        {
            diary_tick += 1;
        }
        let efficiency = if hr > 0.001 {
            watts as f64 / (hr / 1000.0)
        } else {
            0.0
        };

        // ── Chill Miner tracking (consecutive time under 65C) ──
        if max_temp < 65.0 && any_temp_valid {
            chill_miner_secs += 5; // main loop ticks every 5s
        } else {
            chill_miner_secs = 0;
        }

        // ── Power Miser tracking (consecutive time under 10W) ──
        if watts > 0.1 && watts < 10.0 {
            low_power_secs += 5; // main loop ticks every 5s
        } else {
            low_power_secs = 0;
        }

        // ── Streak break detection ──
        #[cfg(feature = "display-ssd1306")]
        if rejected > prev_rejected && prev_rejected > 0 && prev_streak > 5 {
            oled_notify!(display,
                "(T_T) STREAK BROKEN!",
                &format!("Was {} in a row!", prev_streak),
                &format!("Record: {}", best_streak_ever.max(streak_best)),
                "Build it back up!",
            );
        }
        #[cfg(feature = "display-ssd1306")]
        {
            prev_rejected = rejected;
        }

        // ── Streak milestones ──
        if streak > prev_streak && streak > 0 {
            if streak == 25 {
                oled_notify!(display,
                    "(^_^) 25 STREAK!",
                    "No errors! Smooth!",
                    "Keep it going...",
                    &format!("Record: {}", best_streak_ever.max(streak_best)),
                );
            } else if streak == 50 {
                oled_notify!(display,
                    "\\(^o^)/ 50 STREAK!",
                    "FLAWLESS mining!",
                    "Half a century!",
                    "You're unstoppable!",
                );
                // Achievement: Streak Master
                if achievements & nvs_config::ACH_STREAK_50 == 0 {
                    achievements |= nvs_config::ACH_STREAK_50;
                    oled_notify!(display,
                        "** ACHIEVEMENT! **",
                        "Streak Master!",
                        "50 shares, 0 errors",
                        &format!(
                            "{}/{} unlocked",
                            nvs_config::achievement_count(achievements),
                            nvs_config::ACHIEVEMENT_TOTAL
                        ),
                    );
                    achievement_flash_tick = 1;
                    nvs_save_achievements = true;
                }
            } else if streak == 100 {
                oled_notify!(display,
                    "*** 100 STREAK! ***",
                    "(!!!!) LEGENDARY!",
                    "Triple digits baby!",
                    "Screenshot this!",
                );
            }
            // Update best streak in NVS if beaten
            if streak_best > best_streak_ever {
                best_streak_ever = streak_best;
                nvs_save_streak = true;
            }
        }
        prev_streak = streak;

        // ── Achievement checks ──
        // First Share
        if accepted >= 1 && (achievements & nvs_config::ACH_FIRST_SHARE == 0) {
            achievements |= nvs_config::ACH_FIRST_SHARE;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "First Share!",
                "Your mining journey",
                "has begun!",
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Centurion
        if accepted >= 100 && (achievements & nvs_config::ACH_CENTURION == 0) {
            achievements |= nvs_config::ACH_CENTURION;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Centurion!",
                "100 shares accepted!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Kilohash
        if accepted >= 1000 && (achievements & nvs_config::ACH_KILOHASH == 0) {
            achievements |= nvs_config::ACH_KILOHASH;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "KILOHASH!",
                "1000 shares!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Marathon (24 hours)
        if uptime >= 86400 && (achievements & nvs_config::ACH_MARATHON == 0) {
            achievements |= nvs_config::ACH_MARATHON;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Marathon Runner!",
                "24 hours non-stop!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Hot Stuff (survived thermal warning)
        if max_temp > WARNING_TEMP_C && (achievements & nvs_config::ACH_HOT_STUFF == 0) {
            achievements |= nvs_config::ACH_HOT_STUFF;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Hot Stuff!",
                "Survived a thermal!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Block Witness (100 blocks)
        if clean_jobs >= 100 && (achievements & nvs_config::ACH_BLOCK_WITNESS == 0) {
            achievements |= nvs_config::ACH_BLOCK_WITNESS;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Block Witness!",
                "100 blocks witnessed!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Best Day Ever (checked above in best_diff section)

        // ── New v4 achievements ──
        // Speed Demon (hardware-relative threshold: ~80% of rated peak GH/s)
        if hr > speed_demon_threshold && (achievements & nvs_config::ACH_SPEED_DEMON == 0) {
            achievements |= nvs_config::ACH_SPEED_DEMON;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "TERAHASH CLUB!",
                "Over 1 TH/s!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Hash King (10% above speed demon threshold = ~90% of rated peak)
        let hash_king_threshold: f64 = speed_demon_threshold * 1.1;
        if hr > hash_king_threshold && (achievements & nvs_config::ACH_HASH_KING == 0) {
            achievements |= nvs_config::ACH_HASH_KING;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Hash King!",
                "Peak performance!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Chill Miner (1 hour under 65C)
        if chill_miner_secs >= 3600 && (achievements & nvs_config::ACH_CHILL_MINER == 0) {
            achievements |= nvs_config::ACH_CHILL_MINER;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Cool & Collected!",
                "1 hour under 65C!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Diff Hunter (share diff > 1M)
        if best_diff > 1_000_000.0 && (achievements & nvs_config::ACH_DIFF_HUNTER == 0) {
            achievements |= nvs_config::ACH_DIFF_HUNTER;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Million Diff Club!",
                "Diff > 1,000,000!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Night Owl (16+ hours uptime)
        if uptime >= 57600 && (achievements & nvs_config::ACH_NIGHT_OWL == 0) {
            achievements |= nvs_config::ACH_NIGHT_OWL;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Night Owl!",
                "16h+ night shift!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Half-K (500 shares)
        if accepted >= 500 && (achievements & nvs_config::ACH_HALF_K == 0) {
            achievements |= nvs_config::ACH_HALF_K;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Half-K!",
                "500 shares accepted!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Warm Day (8 hours continuous mining)
        if uptime >= 28800 && (achievements & nvs_config::ACH_WARM_DAY == 0) {
            achievements |= nvs_config::ACH_WARM_DAY;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Warm Day!",
                "8 hours non-stop!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Streak 100 (100 shares without rejection)
        if streak >= 100 && (achievements & nvs_config::ACH_STREAK_100 == 0) {
            achievements |= nvs_config::ACH_STREAK_100;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Perfect Century!",
                "100 in a row!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }

        // ── v5 achievements (bits 16-23) ──
        // Early Adopter (auto-grant ~30s after first boot)
        if uptime > 30 && (achievements & nvs_config::ACH_EARLY_ADOPTER == 0) {
            achievements |= nvs_config::ACH_EARLY_ADOPTER;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Early Adopter!",
                "DCENT_axe pioneer!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Efficiency Expert (< 20 J/TH sustained for 10 minutes)
        if efficiency > 0.1
            && efficiency < 20.0
            && uptime > 600
            && (achievements & nvs_config::ACH_EFFICIENCY == 0)
        {
            achievements |= nvs_config::ACH_EFFICIENCY;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Efficiency Expert!",
                "Under 20 J/TH!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Diamond Hands (7 days = 604800s continuous uptime)
        if uptime >= 604800 && (achievements & nvs_config::ACH_DIAMOND_HANDS == 0) {
            achievements |= nvs_config::ACH_DIAMOND_HANDS;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Diamond Hands!",
                "7 days straight!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Lucky Strike (share diff > 10M)
        if best_diff > 10_000_000.0 && (achievements & nvs_config::ACH_LUCKY_STRIKE == 0) {
            achievements |= nvs_config::ACH_LUCKY_STRIKE;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Lucky Strike!",
                "10M diff nonce!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Power Miser (under 10W for 1 hour)
        if low_power_secs >= 3600 && (achievements & nvs_config::ACH_POWER_MISER == 0) {
            achievements |= nvs_config::ACH_POWER_MISER;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Power Miser!",
                "1hr under 10W!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Block Party (1000 blocks witnessed)
        if clean_jobs >= 1000 && (achievements & nvs_config::ACH_BLOCK_PARTY == 0) {
            achievements |= nvs_config::ACH_BLOCK_PARTY;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Block Party!",
                "1000 blocks seen!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Creature Legend (10K+ lifetime shares = Legend evolution tier)
        if lifetime_shares >= 10000 && (achievements & nvs_config::ACH_CREATURE_LEGEND == 0) {
            achievements |= nvs_config::ACH_CREATURE_LEGEND;
            oled_notify!(display,
                "** ACHIEVEMENT! **",
                "Creature Legend!",
                "10K lifetime!",
                &format!(
                    "{}/{} unlocked",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }
        // Completionist (all other 23 achievements unlocked)
        let all_others: u32 = 0x007F_FFFFu32; // bits 0-22
        if (achievements & all_others) == all_others
            && (achievements & nvs_config::ACH_COMPLETIONIST == 0)
        {
            achievements |= nvs_config::ACH_COMPLETIONIST;
            oled_notify!(display,
                "*** COMPLETIONIST ***",
                "ALL achievements!",
                "You are LEGENDARY!",
                &format!(
                    "{}/{} COMPLETE!",
                    nvs_config::achievement_count(achievements),
                    nvs_config::ACHIEVEMENT_TOTAL
                ),
            );
            achievement_flash_tick = 1;
            nvs_save_achievements = true;
        }

        // ── Daily Mining Summary (once after 24h) ──
        if uptime >= 86400 && !daily_summary_shown && accepted > 0 {
            daily_summary_shown = true;
            #[cfg(feature = "display-ssd1306")]
            let eff_grade = if efficiency < 20.0 {
                "S+"
            } else if efficiency < 30.0 {
                "A"
            } else if efficiency < 50.0 {
                "B"
            } else if efficiency < 80.0 {
                "C"
            } else {
                "D"
            };
            oled_notify!(display,
                "DAY 1 COMPLETE!",
                &format!("{} shares mined", accepted),
                &format!("Best diff: {}", fmt_num(best_diff as u64)),
                &format!("Grade: {} ({:.0}J/TH)", eff_grade, efficiency),
            );
        }

        // ── Mining Diary: rare companion flavor (every ~144 ticks = ~12 min) ──
        #[cfg(feature = "display-ssd1306")]
        if diary_tick % 144 == 0 && uptime > 60 && accepted > 0 {
            let energy_wh = watts as f64 * (uptime as f64 / 3600.0);
            let cups_of_coffee = (energy_wh / 100.0) as u64; // ~100 Wh per cup
            let eff_grade = if efficiency < 20.0 {
                "S+"
            } else if efficiency < 30.0 {
                "A"
            } else if efficiency < 50.0 {
                "B"
            } else if efficiency < 80.0 {
                "C"
            } else {
                "D"
            };
            let uptime_hrs = uptime / 3600;
            let uptime_mins = (uptime % 3600) / 60;

            match (diary_tick / 144) % 16 {
                0 => oled_notify!(display,
                    "(^_~) MINING DIARY",
                    &format!("{} shares today!", accepted),
                    &format!("{:.1} Wh consumed", energy_wh),
                    &format!("= {} cups of coffee", cups_of_coffee.max(1)),
                ),
                1 => oled_notify!(display,
                    "(^_^) FUN FACT!",
                    &format!("{:.1} J/TH efficiency", efficiency),
                    &format!("Grade: {} silicon!", eff_grade),
                    "How's your chip?",
                ),
                2 => oled_notify!(display,
                    "(*_*) SHARE WORK",
                    &format!("{} accepted", fmt_num(accepted)),
                    &format!("Best: {}", fmt_num(best_diff as u64)),
                    "Proof, not guesses",
                ),
                3 => oled_notify!(display,
                    "(^v^) UPTIME!",
                    &format!("{}h {}m so far!", uptime_hrs, uptime_mins),
                    "That's dedication!",
                    "Your miner thanks u",
                ),
                4 => oled_notify!(display,
                    "(o_o) NONCE REPORT",
                    &format!("Best: {}", fmt_num(best_diff as u64)),
                    &format!("ATH: {}", fmt_num(best_ever as u64)),
                    "Keep hunting!",
                ),
                5 => oled_notify!(display,
                    "(B) SHARE COUNTER",
                    &format!("OK:{} ER:{}", fmt_num(accepted), rejected),
                    &format!("Streak:{}", streak),
                    "Pool-confirmed work",
                ),
                6 => oled_notify!(display,
                    "[>_]# HACKER LOG",
                    &format!("PID:{} temp:{:.0}C", accepted, max_temp),
                    &format!("fan:{}% pwr:{:.1}W", fan_ctrl.current_speed(), watts),
                    "All systems nominal",
                ),
                7 => {
                    // Hashrate fun comparison
                    let comp = HASHRATE_COMPARISONS[comparison_idx % HASHRATE_COMPARISONS.len()];
                    let val: u64 = match comparison_idx % HASHRATE_COMPARISONS.len() {
                        0 => (hr * 1_000_000_000.0 / 4_194_304.0) as u64, // Game Boy = ~4 MH/s
                        1 => (hr * 1_000_000_000.0 / 5_000_000.0) as u64, // Satoshi ~5 MH/s
                        2 => (hr * 1_000_000_000.0 * 0.3) as u64,         // 300ms blink
                        3 => 0,                                           // special
                        4 => (hr * 1_000_000_000.0 * 0.8) as u64,         // 800ms heartbeat
                        5 => (hr * 1_000_000_000.0 / 93_750_000.0) as u64, // N64 ~93 MIPS
                        6 => (hr * 1_000_000_000.0 / 56_000.0) as u64,    // 56k modem
                        _ => (hr * 1_000_000_000.0 / 10.0) as u64,        // pocket calc
                    };
                    if comparison_idx % HASHRATE_COMPARISONS.len() == 3 {
                        oled_notify!(display,
                            "(*_*) YOUR HASHRATE",
                            &fmt_hashrate(hr),
                            &format!("Best diff {}", fmt_num(best_diff as u64)),
                            "Local telemetry",
                        );
                    } else {
                        oled_notify!(display,
                            "(*_*) YOUR HASHRATE",
                            &format!("= {} {}", fmt_num(val), comp),
                            "Think about THAT!",
                            "Mind = blown!",
                        );
                    }
                    comparison_idx += 1;
                }
                8 => {
                    // Fortune cookie
                    let fortune = FORTUNE_COOKIES[fortune_idx % FORTUNE_COOKIES.len()];
                    oled_notify!(display,
                        "(^_~) FORTUNE COOKIE",
                        &format!("\"{}\"", fortune),
                        "",
                        "Mine on, friend!",
                    );
                    fortune_idx += 1;
                }
                9 => {
                    // Evolution status
                    let (stage, face) = nvs_config::evolution_stage(lifetime_shares);
                    let next_threshold: u32 = match lifetime_shares {
                        0 => 1,
                        1..=99 => 100,
                        100..=999 => 1000,
                        1000..=4999 => 5000,
                        5000..=9999 => 10000,
                        _ => 0, // maxed
                    };
                    if next_threshold > 0 {
                        let need = next_threshold.saturating_sub(lifetime_shares);
                        oled_notify!(display,
                            &format!("{} {}", face, stage),
                            &format!("Lifetime: {}", fmt_num(lifetime_shares as u64)),
                            &format!("Next: {}sh to evolve", fmt_num(need as u64)),
                            &format!(
                                "{:.0}% there!",
                                (lifetime_shares as f32 / next_threshold as f32) * 100.0
                            ),
                        );
                    } else {
                        oled_notify!(display,
                            &format!("{} LEGEND!", face),
                            &format!("{} lifetime!", fmt_num(lifetime_shares as u64)),
                            "MAX EVOLUTION!",
                            "Absolute unit!",
                        );
                    }
                }
                10 => oled_notify!(display,
                    "(^_^) YOUR BITAXE",
                    "is the cutest miner",
                    "on the network!",
                    "No one else is close",
                ),
                11 => {
                    // Hall of fame peek
                    if best_nonce_diff > 0.0 {
                        oled_notify!(display,
                            "HALL OF FAME",
                            &format!("Best: 0x{:08X}", best_nonce_val),
                            &format!("Diff: {}", fmt_num(best_nonce_diff as u64)),
                            "Your proof of work!",
                        );
                    } else {
                        oled_notify!(display,
                            "HALL OF FAME",
                            "No best nonce yet!",
                            "Keep mining to find",
                            "your personal best!",
                        );
                    }
                }
                // New v4 creature idle chatter
                12 => oled_notify!(display,
                    "(^_^) CREATURE CHAT",
                    "I love warm hashes",
                    "*purrs in SHA256*",
                    "Feed me more nonces!",
                ),
                13 => oled_notify!(display,
                    "(^v^) CREATURE CHAT",
                    "Tick tock next block!",
                    "Is that a new block?",
                    "I dream in hex...",
                ),
                14 => oled_notify!(display,
                    "(o_o) CREATURE CHAT",
                    "My bits are tingling!",
                    "Something big is",
                    "coming... I feel it!",
                ),
                _ => oled_notify!(display,
                    "(*_*) CREATURE CHAT",
                    "01001000 01001001",
                    "(thats HI in binary)",
                    "Nerd life best life!",
                ),
            };
        }

        // ── Share accepted: the creature is FED! ──
        if accepted > prev_accepted && prev_accepted > 0 {
            share_flash_tick = 4; // companion lightning/eating animation, no popup spam
            if accepted % 25 == 0 {
                oled_notify!(display,
                    "SHARE MILESTONE",
                    &format!("{} accepted", accepted),
                    &format!("Streak:{} Best:{}", streak, fmt_num(best_diff as u64)),
                    "Pet fed. Still mining.",
                );
            }
        }
        // ── Lifetime shares + creature evolution ──
        if accepted > prev_accepted && prev_accepted > 0 {
            let new_shares = (accepted - prev_accepted) as u32;
            let old_lifetime = lifetime_shares;
            lifetime_shares = lifetime_shares.saturating_add(new_shares);

            // Check if evolution stage changed
            let (old_stage, _) = nvs_config::evolution_stage(old_lifetime);
            #[cfg_attr(feature = "display-none", allow(unused_variables))]
            let (new_stage, new_face) = nvs_config::evolution_stage(lifetime_shares);
            if old_stage != new_stage {
                oled_notify!(display,
                    "*** EVOLUTION! ***",
                    &format!("{} -> {}", old_stage, new_stage),
                    &format!("{}", new_face),
                    &format!("{} lifetime!", fmt_num(lifetime_shares as u64)),
                );
                // Non-blocking double flash for evolution (compound if already flashing)
                #[cfg(feature = "display-ssd1306")]
                {
                    pending_flash = pending_flash.saturating_add(4);
                }
            }

            // Save lifetime shares every 10 new shares (reduce flash wear)
            if lifetime_shares / 10 > old_lifetime / 10 {
                nvs_save_lifetime = true;
            }
        }

        // ── Special block easter eggs ──
        if block_height > 0 && block_height != prev_block_height {
            #[cfg(feature = "display-ssd1306")]
            if let Some(special_msg) = is_special_block(block_height) {
                oled_notify!(display,
                    &format!("** {} **", special_msg),
                    &format!("Block #{}", block_height),
                    "RARE BLOCK EVENT!",
                    "Screenshot this!",
                );
                // Non-blocking strobe effect for special blocks (compound)
                pending_flash = pending_flash.saturating_add(3);
            }
            prev_block_height = block_height;
        }

        // ── New best difficulty: creature is ECSTATIC! ──
        #[cfg(feature = "display-ssd1306")]
        if best_diff > prev_best_diff && prev_best_diff > 0.0 && best_diff > 1000.0 {
            match (best_diff as u64) % 3 {
                0 => oled_notify!(display,
                    "(!!!) NEW RECORD!!!",
                    &format!("(*o*) Diff: {:.0}", best_diff),
                    &format!("Was: {:.0}", prev_best_diff),
                    "Im the GOAT miner!!",
                ),
                1 => oled_notify!(display,
                    "\\(!!!!)/ RECORD!",
                    &format!("Diff: {:.0}!", best_diff),
                    "Thats my best EVER!",
                    "Screenshot this!",
                ),
                _ => oled_notify!(display,
                    "(!!!!) HOLY NONCE!",
                    &format!("{:.0} difficulty!", best_diff),
                    "New personal best!",
                    "Chad miner energy!",
                ),
            };
        }
        #[cfg(feature = "display-ssd1306")]
        {
            prev_best_diff = best_diff;
        }

        // ── Milestone celebrations ──
        #[cfg(feature = "display-ssd1306")]
        if accepted > 0 && accepted % 100 == 0 && accepted > prev_accepted {
            match (accepted / 100) % 4 {
                0 => oled_notify!(display,
                    &format!("*** {} SHARES! ***", accepted),
                    "\\(^o^)/ LEVEL UP!",
                    "Achievement unlocked!",
                    "Stack sats. Stay humb",
                ),
                1 => oled_notify!(display,
                    &format!("*** {} SHARES! ***", accepted),
                    "(^_^)b CENTURY!",
                    "100 more shares done!",
                    "WAGMI!",
                ),
                2 => oled_notify!(display,
                    &format!("*** {} SHARES! ***", accepted),
                    "(*_*) MILESTONE!",
                    "Mining is a marathon",
                    "not a sprint!",
                ),
                _ => oled_notify!(display,
                    &format!("*** {} SHARES! ***", accepted),
                    "(/^o^)/ LEGEND!",
                    "Still hashing!",
                    "Tick tock next block!",
                ),
            };
        }

        prev_accepted = accepted;

        // ── Batched NVS write (1 open max per tick instead of 6) ──
        if nvs_save_best_diff
            || nvs_save_achievements
            || nvs_save_streak
            || nvs_save_lifetime
            || nvs_save_cached_diff
        {
            let nvs_p = nvs_partition.clone();
            if let Ok(mut nvs) = esp_idf_svc::nvs::EspNvs::<esp_idf_svc::nvs::NvsDefault>::new(
                nvs_p, "dcentaxe", true,
            ) {
                if nvs_save_best_diff {
                    nvs_config::save_best_diff(&mut nvs, best_diff);
                    nvs_config::save_best_nonce(&mut nvs, best_nonce_val, best_nonce_diff);
                }
                if nvs_save_achievements {
                    nvs_config::save_achievements(&mut nvs, achievements);
                }
                if nvs_save_streak {
                    nvs_config::save_best_streak(&mut nvs, best_streak_ever);
                }
                if nvs_save_lifetime {
                    nvs_config::save_lifetime_shares(&mut nvs, lifetime_shares);
                }
                if nvs_save_cached_diff {
                    nvs_config::save_cached_pool_difficulty(&mut nvs, cached_pool_difficulty);
                }
            }
        }

        // ── Update achievement/creature telemetry for API ──
        {
            let mut telem = state.telemetry.lock().unwrap_or_else(|e| e.into_inner());
            telem.achievements = achievements;
            telem.achievement_count = nvs_config::achievement_count(achievements);
            telem.lifetime_shares = lifetime_shares;
            let (stage_name, _) = nvs_config::evolution_stage(lifetime_shares);
            telem.creature_stage = stage_name.to_string();
            telem.creature_mood = mood_now;
        }

        // ── New block on the network! ──
        #[cfg(feature = "display-ssd1306")]
        if clean_jobs > prev_clean_jobs && prev_clean_jobs > 0 {
            let blk = if block_height > 1 {
                format!("Block #{}", block_height - 1)
            } else {
                "New block found!".to_string()
            };
            oled_notify!(display,
                "NEW BLOCK",
                &blk,
                "Fresh work from pool",
                &format!("HR {}", fmt_hashrate(hr)),
            );
        }
        #[cfg(feature = "display-ssd1306")]
        {
            prev_clean_jobs = clean_jobs;
        }

        // ── Uptime milestones — you're part of something bigger! ──
        #[cfg(feature = "display-ssd1306")]
        let uptime_mins = uptime / 60;
        #[cfg(feature = "display-ssd1306")]
        if uptime_mins > 0 && uptime_mins % 60 == 0 && uptime % 60 < 5 {
            // Every hour celebration
            let hours = uptime_mins / 60;
            match hours {
                1 => oled_notify!(display,
                    "(^_^) 1 HOUR!",
                    "You've been mining",
                    "for a whole hour!",
                    "Legend in the making",
                ),
                _ => oled_notify!(display,
                    &format!("(^_^) {} HOURS!", hours),
                    "Still hashing strong!",
                    &format!("{} shares this run", accepted),
                    "Dedication!",
                ),
            };
        }

        // ── Random Bitcoin wisdom (rare: about every 10 minutes) ──
        #[cfg(feature = "display-ssd1306")]
        if uptime > 120 && (uptime * 7 + accepted) % 120 == 0 {
            match (uptime / 5) % 10 {
                0 => oled_notify!(display,
                    "(^_~) BITCOIN WISDOM",
                    "\"Running Bitcoin\"",
                    "- Hal Finney, 2009",
                    "And so are you!",
                ),
                1 => oled_notify!(display,
                    "(^_^) YOU MATTER!",
                    "Every hash you mine",
                    "makes Bitcoin more",
                    "decentralized!",
                ),
                2 => oled_notify!(display,
                    "(*_*) FUN FACT:",
                    "Your BitAxe does 1T",
                    "hashes per second!",
                    "Thats 1 TRILLION/s!",
                ),
                3 => oled_notify!(display,
                    "(o_o) THINK ABOUT IT",
                    "You are literally",
                    "writing history in",
                    "the blockchain!",
                ),
                4 => oled_notify!(display,
                    "{^_^} CYPHERPUNK!",
                    "Your miner. Your",
                    "rules. Your hashes.",
                    "Thats sovereignty!",
                ),
                5 => oled_notify!(display,
                    "(^v^) DID YOU KNOW?",
                    "Home miners like you",
                    "are Bitcoin's immune",
                    "system! Stay strong!",
                ),
                6 => oled_notify!(display,
                    "(^_^) WARM & HASHING",
                    "Your BitAxe is also",
                    "a space heater!",
                    "Free heat + sats!",
                ),
                7 => oled_notify!(display,
                    "(*o*) SOLO MINING:",
                    "Low odds, but if you",
                    "find a block = 3.125",
                    "BTC! Dream big!",
                ),
                8 => oled_notify!(display,
                    "(^_~) REMEMBER:",
                    "Not your node,",
                    "not your rules.",
                    "Run your own hash!",
                ),
                _ => oled_notify!(display,
                    "(@_@) NERD ALERT:",
                    "SHA256 was designed",
                    "by the NSA in 2001!",
                    "Now WE use it!",
                ),
            };
        }

        // ── OLED display carousel (notifications interleaved, not blocking) ──
        // Urgent safety notifications preempt immediately. Normal notifications are
        // sparse so hashrate/IP/block/companion pages remain the main OLED experience.
        #[cfg(feature = "display-ssd1306")]
        if notification_cooldown > 0 {
            notification_cooldown -= 1;
        }
        #[cfg(feature = "display-ssd1306")]
        let urgent_notification = display.has_urgent_notification();
        #[cfg(feature = "display-ssd1306")]
        if (urgent_notification || notification_cooldown == 0)
            && display.show_notification_if_pending(&mut i2c)
        {
            display.set_contrast(&mut i2c, 0xFF);
            display.invert_display(&mut i2c, true);
            std::thread::sleep(Duration::from_millis(60));
            display.invert_display(&mut i2c, false);
            display.set_contrast(&mut i2c, 0xCF);
            gpio_ctrl.toggle_led().ok();
            notification_cooldown = if urgent_notification { 2 } else { 5 };
            continue;
        }
        #[cfg(feature = "display-ssd1306")]
        let autotuner_enabled = state.autotuner.lock().map(|at| at.enabled).unwrap_or(false);
        // Carousel uses an anchor pattern: hashrate, IP, block, and companion repeat
        // frequently. Trivia/education pages are demoted so the OLED stays useful.
        // Logical pages: 0=mining, 1=device/IP, 2=weather, 3=halving, 4=autotuner,
        //                5=sats, 6=hall of fame, 7=companion (full-screen)
        #[cfg(feature = "display-ssd1306")]
        let carousel: &[u8] = if autotuner_enabled {
            &[0, 7, 1, 0, 4, 7, 0, 2, 1, 7, 0, 2]
        } else {
            &[0, 7, 1, 0, 2, 7, 0, 1, 7, 5, 2, 6]
        };
        #[cfg(feature = "display-ssd1306")]
        let page_count = carousel.len() as u8;
        #[cfg(feature = "display-ssd1306")]
        let logical_page = carousel[display_page as usize % carousel.len()];
        // Standard Stratum jobs do not carry a network id; Bitcoin mainnet and
        // testnet share the same 210,000-block subsidy interval, so the height
        // of the last job is unambiguous on either. A solo-mesh job carries its
        // configured chain, but mesh jobs share the pool's event channel, so
        // `block_height` may belong to EITHER source: on a regtest mesh (150
        // blocks) the interval is therefore unknowable and no bar is drawn
        // (blind critic P1-O5, finding 2). The chain is read from the LIVE
        // config like its two sibling readers, not the boot snapshot (finding 3).
        #[cfg(feature = "display-ssd1306")]
        let halving_interval: Option<u32> = {
            #[cfg(feature = "lora")]
            let chain = {
                let live = state.config.lock().unwrap_or_else(|e| e.into_inner());
                if live.mesh.solo_mesh_empty_active() {
                    let configured = live.mesh.solo_chain.trim();
                    if configured.eq_ignore_ascii_case("mainnet")
                        || configured.eq_ignore_ascii_case("main")
                    {
                        ChainId::Mainnet
                    } else if configured.eq_ignore_ascii_case("testnet")
                        || configured.eq_ignore_ascii_case("test")
                    {
                        ChainId::Testnet
                    } else {
                        ChainId::Regtest
                    }
                } else {
                    ChainId::Mainnet
                }
            };
            #[cfg(not(feature = "lora"))]
            let chain = ChainId::Mainnet;
            if matches!(chain, ChainId::Regtest) {
                None
            } else {
                Some(chain.subsidy_halving_interval())
            }
        };
        #[cfg(feature = "display-ssd1306")]
        let halving = halving_interval.and_then(|interval| halving_progress(block_height, interval));

        // ── Mining Creature: the evolution stage name (companion page) ──
        // P1-O2: the ASCII face that used to be composed here was drawn on page
        // 0 row 3, where the shared rung word now lives. It duplicated the 8x8
        // pixel-art sprite already in that frame's top-left corner and the
        // 16x16 companion that owns page 7 — and, the actual defect, it gated
        // on the BOOT-TIME `mining_enabled` while the word beside it gated on
        // the runtime state, so a board killed at runtime rendered a live face
        // next to `OFF`. The sprites keep the companion; the word is now true.
        #[cfg(feature = "display-ssd1306")]
        let (evo_stage_name, _evo_face) = nvs_config::evolution_stage(lifetime_shares);

        // Select pixel art sprite based on mining state (lightning/rocket override)
        #[cfg(feature = "display-ssd1306")]
        let active_sprite = if share_flash_tick > 0 {
            &SPRITE_LIGHTNING // flash after share accepted
        } else if achievement_flash_tick > 0 {
            &SPRITE_ROCKET // flash after achievement unlock
        } else if streak > 10 && (uptime % 4) < 2 {
            // Good streak — spinning coin celebration
            if (uptime / 2) % 2 == 0 {
                &SPRITE_COIN_1
            } else {
                &SPRITE_COIN_2
            }
        } else if hr > 10.0 {
            if pixel_art_frame % 2 == 0 {
                &SPRITE_PICKAXE_1
            } else {
                &SPRITE_PICKAXE_2
            }
        } else if max_temp > 70.0 {
            &SPRITE_CAMPFIRE
        } else {
            if (uptime / 3) % 3 == 0 {
                &SPRITE_COIN_1
            } else if (uptime / 3) % 3 == 1 {
                &SPRITE_COIN_2
            } else {
                &SPRITE_COIN_3
            }
        };
        #[cfg(feature = "display-ssd1306")]
        {
            pixel_art_frame = pixel_art_frame.wrapping_add(1);
        }

        // ── Day/Night cycle (based on uptime) ──
        let day_phase = match uptime / 3600 {
            0..=1 => "morning",   // boot to 2h
            2..=9 => "day",       // 2h-10h
            10..=15 => "evening", // 10h-16h
            _ => "night",         // 16h+
        };

        // Screen transition flash effect (only on actual page change)
        #[cfg(feature = "display-ssd1306")]
        if last_transition_flash {
            display.invert_display(&mut i2c, true);
            std::thread::sleep(Duration::from_millis(30));
            display.invert_display(&mut i2c, false);
            last_transition_flash = false;
        }
        #[cfg(feature = "display-ssd1306")]
        if logical_page != 7 {
            display.set_contrast(&mut i2c, 0xCF);
        }

        #[cfg(feature = "display-ssd1306")]
        match logical_page {
            0 => {
                // Page 0: Mining HUD. Keep this dense enough to be useful, but not noisy.
                let temp_str = if any_temp_valid {
                    format!("{:.0}C", max_temp)
                } else {
                    "--C".to_string()
                };
                let hr_str = fmt_hashrate(hr);

                display.clear();
                // Draw pixel art sprite in top-left corner (8x8)
                display.draw_bitmap(0, 0, active_sprite, 8, 8);
                // Pickaxe debris particles — pseudo-random sparkle near sprite when mining
                if hr > 10.0 {
                    let seed = uptime as usize;
                    display.set_pixel(9 + (seed * 7) % 5, (seed * 13) % 6, true);
                    display.set_pixel(10 + (seed * 11) % 4, 2 + (seed * 3) % 5, true);
                    if seed % 3 == 0 {
                        display.set_pixel(8 + (seed * 5) % 6, 1 + (seed * 9) % 5, true);
                    }
                }
                // Line 0: hashrate + temp. Full stage/lifetime lives on companion pages.
                display.draw_text(10, 0, &format!("{} {}", hr_str, temp_str));

                // Line 1: Hashrate sparkline (16 samples, 2px wide each = 32px)
                let max_hr = sparkline.iter().cloned().fold(0.0_f32, f32::max).max(1.0);
                let mut norm = [0.0f32; 16];
                for i in 0..16 {
                    norm[i] = sparkline[i] / max_hr;
                }
                display.draw_sparkline(0, 8, &norm, 2);
                display.draw_text(36, 8, &format!("{:.1}W {:.0}J/T", watts, efficiency));

                // Line 2: shares + streak/errors + best diff (21 chars max)
                let diff_s = fmt_num(best_diff as u64);
                if streak > 5 {
                    display.draw_text(
                        0,
                        16,
                        &format!("OK:{} stk:{} d:{}", fmt_num(accepted), streak, diff_s),
                    );
                } else {
                    display.draw_text(
                        0,
                        16,
                        &format!("OK:{} ER:{} d:{}", fmt_num(accepted), rejected, diff_s),
                    );
                }

                // Line 3: the SHARED mining rung, the block anchor, then any
                // companion flavour that still fits.
                //
                // P1-O2: `MINING` / `READY` / `STANDBY` / `PENDING` are the web
                // dashboard's own pill words, resolved by the one shared
                // `resolve_rung`, so the panel can no longer contradict the
                // browser (CRITIC_RUBRIC.md H7) and a permitted-but-idle board
                // is finally distinguishable from a stopped one — both used to
                // read `SLEEP`. `runtime_mining_active` is the discriminator on
                // BOTH pages now; `true` is the first-data gate, which the
                // carousel has already satisfied (it drew this tick's snapshot),
                // so PENDING belongs to the boot screens. The old flavour words
                // survive as DECORATIONS that `fit_line` drops first when the
                // 21-column line is full — the truth is never what gets clipped.
                //
                // Round 2 (critic finding 6): the decoration comes from the ONE
                // shared table, with the same four inputs the companion page
                // passes. Two chains used to diverge here - this page knew
                // about nightfall and the companion page did not, so the same
                // tick could decorate one and leave the other bare.
                let rung = resolve_rung(true, runtime_mining_active, hr > 0.0);
                let deco = rung_decoration(
                    max_temp > 85.0,
                    share_flash_tick > 0,
                    achievement_flash_tick > 0,
                    day_phase == "night",
                );
                let block_short = if block_height > 0 {
                    format!("B:{}", block_height)
                } else {
                    "B:---".to_string()
                };
                display.draw_text(
                    0,
                    24,
                    &fit_line(&[rung.panel_word(), &block_short], deco, TEXT_COLUMNS),
                );

                let _ = display.flush(&mut i2c);
            }
            1 => {
                // Page 1: Device/IP. Prioritize fields needed at the physical miner.
                let uptime_str = if uptime >= 3600 {
                    format!("up:{}h{}m", uptime / 3600, (uptime % 3600) / 60)
                } else {
                    format!("up:{}m", uptime / 60)
                };
                let wifi_rssi = state.telemetry.lock().map(|t| t.wifi_rssi).unwrap_or(0);
                let pool_short: String = pool_display.chars().take(21).collect();
                let block_line = if block_height > 0 {
                    format!("v{} BLK:{}", VERSION, block_height)
                } else {
                    format!("v{} BLK:---", VERSION)
                };
                display.show_status(
                    &mut i2c,
                    &device_ip,
                    &pool_short,
                    &format!("WiFi:{}dB {}", wifi_rssi, uptime_str),
                    &block_line,
                );
            }
            2 => {
                // Page 2: height-derived halving progress + temperature weather.
                // Unknown height means no bar: an empty bar would still look
                // like a measured zero and recreate the lie this lane removes.
                let halving_line = if let Some((_, blocks_to_halving)) = halving {
                    format!("HALVING: {} LEFT", blocks_to_halving)
                } else {
                    "HALVING: ---".to_string()
                };

                let weather = if max_temp > 85.0 {
                    "SCORCHING!"
                } else if max_temp > 70.0 {
                    "Warm & Toasty"
                } else if max_temp > 55.0 {
                    "Perfect Weather"
                } else if max_temp > 40.0 {
                    "Cool Breeze"
                } else {
                    "Freezing!"
                };
                let forecast = if max_temp > 70.0 { "Fan:MAX" } else { "Stable" };

                display.clear();
                display.draw_centered(0, &halving_line);
                if let Some((progress, _)) = halving {
                    display.draw_progress_bar(2, 9, 80, progress);
                    // Floor, never round: 209,999/210,000 must not read "100%" beside "1 LEFT".
                    display.draw_text(86, 8, &format!("{}%", (progress * 100.0).floor() as u32));
                }
                display.draw_centered(16, &format!("{} {:.0}C", weather, max_temp));
                display.draw_text(
                    0,
                    24,
                    &format!("Fan:{}% {}", fan_ctrl.current_speed(), forecast),
                );
                let _ = display.flush(&mut i2c);
            }
            4 if autotuner_enabled => {
                // Page 4: Autotuner (only when enabled)
                let at = state
                    .autotuner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let at_phase = at.status.chars().take(21).collect::<String>();
                let best_freq = if at.current_frequency > 0.0 {
                    format!(
                        "Best:{:.0}MHz {:.1}J/TH",
                        at.current_frequency, at.best_efficiency
                    )
                } else {
                    "Best: measuring...".to_string()
                };
                let pwr_limit = autotuner.power_limit_display();
                display.show_status(
                    &mut i2c,
                    &format!("AUTOTUNER: {}", at_phase),
                    &format!("Testing {:.0} MHz", config_freq),
                    &best_freq,
                    &format!("Power: {:.1}W / {}", watts, pwr_limit),
                );
            }
            5 => {
                // Share tracker + streak + achievements. Keep this grounded in
                // local pool-confirmed data; no hardcoded network estimates.
                let ach_count = nvs_config::achievement_count(achievements);
                let share_rate = if uptime > 60 {
                    accepted as f64 / (uptime as f64 / 3600.0)
                } else {
                    0.0
                };
                display.show_status(
                    &mut i2c,
                    "SHARE TRACKER",
                    &format!("OK:{} ER:{}", fmt_num(accepted), rejected),
                    &format!("{:.1}/hr best:{}", share_rate, fmt_num(best_diff as u64)),
                    &format!(
                        "Stk:{} rec:{} ach:{}/{}",
                        streak,
                        best_streak_ever.max(streak_best),
                        ach_count,
                        nvs_config::ACHIEVEMENT_TOTAL
                    ),
                );
            }
            6 => {
                // Hall of Fame: the operator's own best-ever share, honestly.
                //
                // P1-O5: this page used to alternate every 5s with two
                // fabricated sub-pages — a Bitcoin-supply-schedule progress
                // bar driven by a hardcoded constant with no data behind it,
                // and a network-hashrate comparison line (no such field
                // exists anywhere in this firmware; confirmed by a
                // workspace-wide grep). Both are removed rather than
                // replaced: the honest reachable form of the same
                // halving/epoch math already lives on page 2 (P1-O4's dead
                // page-3 arm), so this page does not need a second,
                // redundant copy of it.
                display.clear();
                display.draw_centered(0, "-- HALL OF FAME --");
                if best_nonce_diff > 0.0 {
                    display.draw_text(0, 8, &format!("Best: 0x{:08X}", best_nonce_val));
                    display.draw_text(
                        0,
                        16,
                        &format!("Diff: {}", fmt_num(best_nonce_diff as u64)),
                    );
                } else {
                    display.draw_text(0, 8, "No trophy yet!");
                    display.draw_text(0, 16, "Mine to earn one!");
                }
                let _ = display.flush(&mut i2c);
            }
            7 => {
                // Companion page: mostly Tamagotchi pet room, with periodic full-height moments.
                display.clear();

                // Select creature sprite based on mood and blink cycle
                let mood_score = {
                    let fan_target = state
                        .config
                        .lock()
                        .map(|c| c.fan_target_temp_c as f32)
                        .unwrap_or(65.0);
                    let s = state.stats.lock().unwrap_or_else(|e| e.into_inner());
                    s.mood_score(max_temp, fan_target)
                };
                let creature_sprite = if !runtime_mining_active || hr < 1.0 {
                    &CREATURE_SLEEP
                } else if mood_score < 4 || max_temp > 85.0 {
                    &CREATURE_SAD
                } else if share_flash_tick > 0 || uptime % 4 == 0 {
                    &CREATURE_BLINK // blink every 4th tick (~20s)
                } else {
                    &CREATURE_HAPPY
                };

                // Breathing brightness effect (zero CPU — hardware contrast)
                display.set_contrast(
                    &mut i2c,
                    BREATH_LUT[(uptime as usize / 2) % BREATH_LUT.len()],
                );

                // Name and stage (right side)
                let creature_name =
                    nvs_config::creature_name(device_ip.as_bytes().last().copied().unwrap_or(0));
                let hr_str = fmt_hashrate(hr);
                let temp_str = if any_temp_valid {
                    format!("{:.0}C", max_temp)
                } else {
                    "--C".to_string()
                };
                let block_str = if block_height > 0 {
                    format!("BLK:{}", block_height)
                } else {
                    "BLK:---".to_string()
                };
                // P1-O2: the companion page reads the SAME rung as page 0 and
                // as the dashboard — one resolver, one vocabulary, one
                // discriminator. This string lands in two slots of different
                // widths (15 columns in the full-pet layout at x=36, 11 in the
                // pet room at x=22 with the wattage at x=90), so it is fitted
                // against the TIGHTER of the two and the rung word is never the
                // part that gets clipped.
                //
                // Round 2 (critic finding 6): one table, same four inputs as
                // page 0 - byte-identical argument list, pinned by a
                // dcentaxe-core source contract, so the two pages can no longer
                // describe the same tick differently.
                let pet_rung = resolve_rung(true, runtime_mining_active, hr > 0.0);
                let pet_deco = rung_decoration(
                    max_temp > 85.0,
                    share_flash_tick > 0,
                    achievement_flash_tick > 0,
                    day_phase == "night",
                );
                let activity = fit_line(&[pet_rung.panel_word()], pet_deco, PET_ACTIVITY_COLUMNS);

                let full_pet = share_flash_tick > 0
                    || achievement_flash_tick > 0
                    || !runtime_mining_active
                    || max_temp > 85.0
                    || companion_visit % 3 == 2;
                companion_visit = companion_visit.wrapping_add(1);

                if full_pet {
                    // 32px-tall creature owns the screen; right side keeps key status.
                    display.draw_bitmap_2x(0, 0, creature_sprite, 16, 16);
                    display.draw_text(36, 0, creature_name);
                    display.draw_text(36, 8, &activity);
                    display.draw_text(36, 16, &format!("{} {}", hr_str, temp_str));
                    display.draw_text(36, 24, &block_str);
                } else {
                    // Pet room: companion is central, but mining stats remain readable.
                    display.draw_bitmap(2, 0, creature_sprite, 16, 16);
                    display.draw_text(22, 0, creature_name);
                    display.draw_text(82, 0, &hr_str);
                    display.draw_text(22, 8, evo_stage_name);
                    display.draw_text(94, 8, &temp_str);

                    // Mood hearts (5 hearts, filled based on mood 0-10)
                    let hearts_filled = (mood_score / 2).min(5);
                    for h in 0..5u8 {
                        let hx = 22 + h as usize * 7;
                        if h < hearts_filled {
                            display.draw_bitmap(hx, 17, &HEART_FILLED, 5, 8);
                        } else {
                            display.draw_bitmap(hx, 17, &HEART_EMPTY, 5, 8);
                        }
                    }
                    display.draw_text(64, 16, &format!("OK:{}", fmt_num(accepted)));
                    display.draw_text(22, 25, &activity);
                    display.draw_text(90, 24, &format!("{:.0}W", watts));
                }

                let _ = display.flush(&mut i2c);
            }
            // Unreachable by construction, and kept only because `match` on a
            // `u8` must be exhaustive. `logical_page` is read out of one of the
            // two `carousel` arrays above; between them they hold only
            // 0,1,2,4,5,6,7, and `4` appears only in the array chosen when
            // `autotuner_enabled` is true — the same local the guarded arm
            // tests — so the guard above can never fall through to here.
            //
            // P1-O4 deleted the two bodies that used to sit behind this fact:
            // page 3 (halving/difficulty-epoch countdown) and the bouncing
            // Bitcoin / mood-sparkline screensaver. Neither page id was in
            // either array, so neither had ever been drawn on a panel; both
            // were compiled into every SSD1306 image and, before this lane's
            // cfg gate, into every headless image too. `dcentaxe-core`'s
            // `p1_o4_headless_carousel_guards` pins the arrays against the arms
            // so a dead page cannot come back unnoticed.
            _ => {}
        }
        #[cfg(feature = "display-ssd1306")]
        let next_page = (display_page + 1) % page_count;
        // Only flash on full-rotation wrap (return to page 0), not every page change
        #[cfg(feature = "display-ssd1306")]
        if next_page == 0 && display_page != 0 {
            last_transition_flash = true;
        }
        #[cfg(feature = "display-ssd1306")]
        {
            display_page = next_page;
        }

        // ── LED heartbeat pattern (replaces simple toggle) ──
        // Pattern: ON(100ms) OFF(100ms) ON(100ms) OFF(700ms) — like a real heartbeat
        // Rate scales: faster when hashing well, slower at night phase
        let heartbeat_speed: u8 = if hr > 100.0 {
            1
        } else if day_phase == "night" {
            3
        } else {
            2
        };
        // Reset phase on speed change to prevent double-blink
        if heartbeat_speed != prev_heartbeat_speed {
            led_heartbeat_phase = 0;
            prev_heartbeat_speed = heartbeat_speed;
        }
        led_heartbeat_phase = (led_heartbeat_phase + 1) % (4 * heartbeat_speed);
        let phase_in_cycle = led_heartbeat_phase / heartbeat_speed;
        match phase_in_cycle {
            0 => gpio_ctrl.set_led(true).ok(),  // first beat ON
            1 => gpio_ctrl.set_led(false).ok(), // first beat OFF
            2 => gpio_ctrl.set_led(true).ok(),  // second beat ON
            _ => gpio_ctrl.set_led(false).ok(), // rest (longer pause)
        };
    }
}
