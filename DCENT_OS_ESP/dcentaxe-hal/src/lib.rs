//! DCENT_axe Hardware Abstraction Layer
//!
//! Provides platform-specific hardware access for BitAxe boards:
//! - **board** — Board model detection and configuration (pin maps, voltage limits)
//! - **uart** — UART driver for ASIC chain communication (115200 -> 1M/3.125M baud)
//! - **i2c** — I2C bus driver for power ICs and temperature sensors (400 kHz)
//! - **gpio** — Discrete GPIO control (ASIC reset, buck enable, LED)
//! - **fan** — Fan PWM control (25 kHz LEDC) and tachometer RPM reading
//! - **power** — Voltage regulation (TPS546/DS4432U) and power monitoring (INA260)
//! - **temp** — Temperature sensing (EMC2101 internal + external diode, TPS546 fallback)
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                      Application Layer                           |
//! |  (mining daemon, thermal control, API server)                    |
//! +------------------------------------------------------------------+
//!           |           |           |          |           |
//!     +-----+---+ +----+----+ +----+----+ +---+---+ +----+----+
//!     | AsicUart| | I2cBus  | | GpioCtl | | Fan   | | PowerMgr|
//!     | (uart)  | | (i2c)   | | (gpio)  | | (fan) | | (power) |
//!     +----+----+ +----+----+ +----+----+ +---+---+ +----+----+
//!          |           |           |          |           |
//!     +----+----+ +----+----+ +----+----+ +---+---+ +----+----+
//!     | UART1   | | I2C0    | | GPIOs   | | LEDC  | | TPS546  |
//!     | TX:17   | | SDA:47  | | RST:1   | | PWM:11| | DS4432U |
//!     | RX:18   | | SCL:48  | | EN:46   | | TCH:14| | INA260  |
//!     +---------+ +---------+ | LED:4   | +-------+ | EMC2101 |
//!                             +---------+            +---------+
//! ```
//!
//! # Safety
//!
//! - Voltage settings are clamped to board-specific limits (cannot exceed max_voltage_mv);
//!   a `DRIVER_VOLTAGE_CEILING_MV` backstop in `safety` also caps the raw DAC/regulator
//!   drivers (HALPWR-3).
//! - The 20% mining fan-floor is enforced on the shipping path by `FanState::set_speed`
//!   (`pct.max(20)`) in the `dcentaxe` binary, not by the `fan::FanController` type (a
//!   reference implementation currently not on the shipping path — HALT-2). The `fan_pid`
//!   acoustic `min_pct` (30%) sits *above* the 20% floor and never undercuts it.
//! - `GpioController::power_on_sequence()` performs buck-enable → settle → reset in one
//!   fail-closed call (HALT-8); callers that drive `enable_buck`/`reset_asic` separately are
//!   responsible for that ordering.
//! - I2C operations have timeouts to prevent bus lockup.

// `board` is pure logic (pin-map tables, voltage limits, board-version
// profiles) with no ESP-IDF dependency, so it compiles on the host. The
// remaining peripheral driver modules link against esp-idf-hal/svc and are
// therefore gated to the ESP-IDF target. Host unit tests of the pure config /
// OTA logic (via the dcentaxe-core crate) need only `board`.
pub mod board;
// Pure CML fault-escalation window logic (no ESP-IDF dep) — host-testable and
// consumed by the espidf-only `power` module.
pub mod cml_escalation;
// Pure Hammer DC TMP75 address-strap classifier. The bus-touching ACK probe is
// isolated below and compiled only for ESP-IDF.
pub mod hammer_strap;
// Pure TPS546 write-protect policy (XPSAFE-2, cross-pollinated from DCENT_OS's
// HAL EEPROM write-denylist). No ESP-IDF dep — host-testable; consumed by the
// espidf-only `i2c` module's write path. Default-OFF (disarmed) so field-proven
// boards keep their exact prior behavior.
#[cfg(target_os = "espidf")]
pub mod display;
// Pure SSD1306 framebuffer + 5x7 glyph core + notification-queue policy (no
// ESP-IDF dep) — split out of the espidf-only `display` module so the ONE
// user-facing surface that had no executable contract at all becomes
// host-renderable. `display.rs` keeps the I2C transport and delegates every
// pixel decision here, so a host test can render any panel state to PNG and
// check it against the panel's real 21-column x 4-row budget. Always compiled
// (like `tmp451_convert` / `pca9544_convert`) so it reaches the host gate on a
// board that selects `display-none`.
pub mod display_convert;
// P1-O1: the fail-closed reason CODES the panel shows when a board refuses to
// mine, plus the bounded rows that carry them. Same always-compiled, host-pure
// split as `display_convert` and re-included into `dcentaxe-core` the same way:
// `main.rs` is espidf-only, so a sentence it composed inline could never be
// measured against the panel's 21 columns — and all 29 of them were clipped.
pub mod block_reason;
pub mod tps546_guard;
// Alloc-free fail-closed safety primitives (XPSAFE-1): buck-enable polarity +
// max-cooling fan-duty bytes. No ESP-IDF dep — host-testable and the single
// source of truth shared by the espidf-only panic hook and `gpio::enable_buck`.
pub mod safety;
// Hammer's ST7789 i80 panel GPIO map is pure metadata plus host-run collision
// tests. The panel driver stays absent until GPIO15 is characterized on bench.
pub mod st7789_pins;
// DCENT_axe on-board SX1262 LoRa radio pin map (LOCKED 9/9 vs BM1397 netlist)
// + the esp-idf SPI3/HSPI bus builder. The pure pin map (const table + table
// test) is host-testable; the `open_lora_bus` builder inside is esp-idf-gated
// (integration seam — NEEDS-VERIFY on silicon). Default-OFF via the `pins-lora`
// feature — a non-LoRa SKU never compiles this module.
#[cfg(feature = "pins-lora")]
pub mod lora_pins;
// W5500 SPI-Ethernet (DCENT LAN Mod, PLAN-E Phase 1) pin map + MAC-derivation
// rule + clock/poll constants. PURE (no esp-idf dep) and host-testable — the
// esp-idf `esp_eth` bring-up seam lives in the `dcentaxe` binary
// (`eth_w5500.rs`), which is the only crate that propagates the required
// `esp_idf_eth_spi_ethernet_w5500` sdkconfig cfg via its build.rs. Default-OFF
// via the `eth-w5500` feature — a non-LAN SKU never compiles this module.
#[cfg(feature = "eth-w5500")]
pub mod eth;
// The pure decode/register-map layer of the EMC2103 driver is host-testable via
// the `dcentaxe-core` `#[path]` re-include (see emc2103.rs); the whole module is
// gated here because its I2C-backed `Emc2103` struct links esp-idf-hal.
#[cfg(target_os = "espidf")]
pub mod emc2103;
#[cfg(target_os = "espidf")]
pub mod emc2302;
#[cfg(target_os = "espidf")]
pub mod fan;
#[cfg(target_os = "espidf")]
pub mod fan_pid;
#[cfg(target_os = "espidf")]
pub mod gpio;
#[cfg(target_os = "espidf")]
pub mod hammer_strap_probe;
#[cfg(target_os = "espidf")]
pub mod i2c;
#[cfg(target_os = "espidf")]
pub mod power;
// Pure PMBus + DS4432U voltage/telemetry math (no ESP-IDF / log / serde) — split
// out of the espidf-only `power` module so the regulator-write/decode math is
// host-testable. `power.rs` re-exports the PMBus fns and calls `ds4432u_dac_code`
// so the regulator code path stays byte-identical.
pub mod power_convert;
// Pure TPS53647/TPS53667 multi-phase VRM math (VID ladder, part identity, phase
// and over-current encoding) — the Nerd family's multi-ASIC boards carry one of
// these instead of the TPS546 every BitAxe-class board uses. Same host-pure
// split as `power_convert`: no ESP-IDF dep, so the part-identity gate and the
// fail-closed voltage window are exercised by the host test gate with no
// hardware. The SMBus shim lives in `tps5364x` (espidf-only).
#[cfg(target_os = "espidf")]
pub mod temp;
#[cfg(all(target_os = "espidf", feature = "power-tps5364x"))]
pub mod tps5364x;
pub mod tps5364x_convert;
// Pure EMC2101 external-diode temperature decode (no ESP-IDF dep) — split out of
// the espidf-only `temp` module so the sensor-availability decision (HALT-3) is
// host-testable; consumed by `temp::Emc2101::read_external_temp`.
pub mod temp_decode;
// Pure TMP451 / ADT7461-family remote-diode decode + analog-mux channel encoding
// (no ESP-IDF dep) — the per-ASIC thermal source on the muxed Nerd boards, whose
// register map is confirmed by BOTH the upstream Nerd firmware and Bitmain's own
// S21xp factory jig. Host-testable so the fail-closed availability rule and the
// per-board calibration bounds run in the host gate. Transport shim: `tmp451`.
#[cfg(all(target_os = "espidf", feature = "temp-tmp451"))]
pub mod tmp451;
pub mod tmp451_convert;
// Pure TMP1075 addressing/topology/decode (no ESP-IDF dep) — the decode half of
// `temp::Tmp1075`, plus the `0x48 + n` multi-device addressing the Nerd boards
// need and the rule that device 1 is the VOLTAGE-REGULATOR sensor, not an ASIC
// sensor. Host-testable so that rule (and the two decode defects the upstream C
// carries) are pinned by the host gate.
pub mod tmp1075_convert;
// Pure FXL6408 I2C port-expander register/bit core (no ESP-IDF dep) — the
// Q-series is the first family whose ASIC reset, VREG enable and LDO enable are
// I2C transactions rather than GPIO writes, so each one can FAIL. The shadow
// registers this part requires are split into compute (`with_pin`) and record
// (`commit`) so a write the bus rejected can never leak into the next mask.
pub mod fxl6408_convert;
// ESP-IDF transport for the above. Split out because the pure core shipped a
// full register model with NO driver and no caller behind it, which is what
// kept the Q1370/Q1373 classified as having no rail actuator at all: their
// enable is real, it is just an I2C write nothing could issue.
#[cfg(all(target_os = "espidf", feature = "io-expander-fxl6408"))]
pub mod fxl6408;
// Pure PCA9544A I2C bus-multiplexer channel core (no ESP-IDF dep) — the
// BitForge Nano is the first board whose two thermal sensors share one
// hard-wired address and are reachable only by selecting a mux channel first.
// That makes the channel select part of the THERMAL path: a select that fails
// silently returns the other ASIC's die temperature under this ASIC's name.
// Select and confirm are therefore bound together here, and "no channel
// connected" is a state rather than upstream's underflowed integer.
#[cfg(all(target_os = "espidf", feature = "i2c-mux-pca9544"))]
pub mod pca9544;
pub mod pca9544_convert;
// Pure NTC-thermistor-on-ADC conversion (no ESP-IDF dep) — the first
// temperature sensor in the registry that is NOT an I2C part. The BitForge Nano
// carries a 10 k NTC per ASIC in a divider on two ESP32 ADC inputs, reads them
// exactly once at init, and throws the value away; this makes them a real
// runtime source. Host-pure so the divider algebra and the fail-closed input
// validation (upstream returns -273.15 as an in-band error value, and divides
// by zero on an open circuit) run in the host gate. Transport shim: `ntc`.
pub mod ntc_convert;
#[cfg(target_os = "espidf")]
pub mod uart;

// Re-export key types for convenience
pub use board::{BitAxeModel, BoardConfig};
#[cfg(target_os = "espidf")]
pub use display::Ssd1306Display;
#[cfg(target_os = "espidf")]
pub use emc2103::Emc2103;
#[cfg(target_os = "espidf")]
pub use emc2302::Emc2302;
#[cfg(target_os = "espidf")]
pub use fan::FanController;
#[cfg(target_os = "espidf")]
pub use gpio::GpioController;
#[cfg(target_os = "espidf")]
pub use i2c::I2cBus;
#[cfg(target_os = "espidf")]
pub use power::{PowerManager, PowerTelemetry};
#[cfg(target_os = "espidf")]
pub use temp::{Emc2101, TempSensor, TemperatureReading, Tmp1075};
#[cfg(target_os = "espidf")]
pub use uart::AsicUart;
