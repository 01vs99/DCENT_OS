//! Host-testable pure-logic core for DCENT_axe.
//!
//! `config.rs` and `ota_signature.rs` physically live in the `dcentaxe` binary
//! crate and are compiled there for firmware via `mod config;` /
//! `mod ota_signature;`. This crate re-includes the SAME source files via
//! `#[path]` purely so the pure logic can be host-compiled and unit-tested in
//! CI without the ESP-IDF toolchain.
//!
//! There is exactly ONE source of truth for each module — do NOT fork the
//! logic. Edits belong in `dcentaxe/src/{config,ota_signature}.rs`; this crate
//! merely exposes them for `cargo test` on a host target. The `#[cfg(test)]`
//! modules inside those files run here and are excluded from every firmware
//! build (where `cfg(test)` is never set).
//!
//! `temp_decode` follows the same convention but physically lives in
//! `dcentaxe-hal/src/temp_decode.rs` (it is consumed by the esp-idf-gated
//! `temp` module, not the `dcentaxe` binary). It is re-included here only so
//! its `#[cfg(test)]` unit tests host-run under `cargo test -p dcentaxe-core`.
//! This `#[path]` copy is a distinct crate root from the `dcentaxe_hal::temp_decode`
//! reachable through the `dcentaxe-hal` dependency; the copy is the one that
//! gets `cfg(test)`.

// ─────────────────────────────────────────────────────────────────────────────
// Test-harness lint posture (do NOT copy this into the real firmware build).
//
// `dcentaxe-core` is a TEST-HARNESS crate: it re-includes partial source files
// from the `dcentaxe` binary and `dcentaxe-hal` via `#[path]` ONLY so their
// `#[cfg(test)]` unit tests host-run in CI without the ESP-IDF toolchain. Because
// each file is compiled here OUT of its real crate context, several lints fire
// here that are FALSE POSITIVES for this harness:
//
//   * `dead_code` / `unused_imports` / `unused_variables` — items that the
//     `dcentaxe` BINARY (main.rs) uses but this harness does not reach read as
//     unused HERE only.
//   * `unexpected_cfgs` — the board-variant features (`bitaxe-gamma`, `nerdnos`,
//     …) that `config.rs` branches on are declared in the `dcentaxe` crate's
//     Cargo.toml, not in this harness crate's, so each `cfg!(feature = …)` looks
//     "unexpected" here.
//   * `unused_mut` — a `mut` binding that the firmware path reassigns but the
//     host-reachable branch does not.
//
// We allow them at the CRATE ROOT so the clippy `-D warnings` CI gate stays green
// for this harness WITHOUT editing the single-source-of-truth files (whose real
// firmware build, where the code IS used, is unaffected — this allow does not
// follow the source into the `dcentaxe`/`dcentaxe-hal` builds).
#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    unexpected_cfgs
)]

#[path = "../../dcentaxe/src/config.rs"]
pub mod config;

// PLAN-E W5500 LAN: the pure Wi-Fi⇄Ethernet failover FSM. Single source of
// truth is `dcentaxe/src/net.rs` (feature-gated `eth-w5500` in the binary);
// re-included here UNCONDITIONALLY so its decision-matrix / flap-telemetry
// tests always host-run in the default gate (it only needs `crate::config`,
// which is re-included above).
#[path = "../../dcentaxe/src/net.rs"]
pub mod net;

#[path = "../../dcentaxe/src/notifications.rs"]
pub mod notifications;

// Same single-source-of-truth pattern: capabilities.rs physically lives in the
// `dcentaxe` binary crate and builds the additive `/api/v1/capabilities`
// descriptor from host-pure config/board metadata plus runtime bounds. Re-include
// it here so its shared-contract pin tests run under `cargo test -p dcentaxe-core`
// without an ESP-IDF toolchain.
#[path = "../../dcentaxe/src/capabilities.rs"]
pub mod capabilities;

#[cfg(test)]
mod capability_api_route_guards {
    const API_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/api.rs"
    ));
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    #[test]
    fn capability_endpoint_is_additive_and_registered_after_system_info() {
        let system_info = API_RS
            .find("register_system_info(server, state.clone());")
            .expect("register_api must keep the AxeOS /api/system/info route");
        let capabilities = API_RS
            .find("register_capabilities(server, state.clone());")
            .expect("register_api must add the shared capability endpoint");
        let system_asic = API_RS
            .find("register_system_asic(server, state.clone());")
            .expect("register_api must keep /api/system/asic");

        assert!(
            system_info < capabilities && capabilities < system_asic,
            "/api/v1/capabilities must be additive beside system info, not folded into it"
        );
        assert!(API_RS.contains("\"/api/v1/capabilities\""));
        assert!(API_RS.contains("build_esp_capability_descriptor("));
        assert!(API_RS.contains("authorize_rest_read(&req, &state)"));
        assert!(API_RS.contains("Do not fold this into `/api/system/info`"));
    }

    #[test]
    fn handler_count_includes_capability_endpoint() {
        // P1-I3: the accounting table in main.rs is counted by INVOCATION, not by
        // text. Three api.rs helper closures each register two URIs, so the 54
        // text occurrences of `.fn_handler(` are 57 real registrations, and the
        // whole-server total is 76, not 64. The columns are matched on a
        // whitespace-collapsed copy (re-indenting the comment must not break the
        // guard) but the NUMBERS are exact: a route change must re-run
        // `python tools/count_handlers.py` and update them.
        // `split_whitespace` also makes this newline-agnostic, which matters:
        // `core.autocrlf = true` means a fresh worktree is CRLF while the main
        // tree is LF, and a guard that matches a bare `\n` passes on one and
        // fails on the other.
        let main_flat = MAIN_RS.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            main_flat.contains("api.rs 54 57"),
            "main.rs handler accounting must show api.rs as 54 text sites -> 57 \
             registrations (which includes /api/v1/capabilities)"
        );
        assert!(
            main_flat.contains("TOTAL 64 76"),
            "main.rs handler accounting must total the invocation-aware 76 \
             registrations (64 text sites)"
        );
        assert!(
            MAIN_RS.contains("const REGISTERED_HANDLER_ESTIMATE: usize = 76;"),
            "REGISTERED_HANDLER_ESTIMATE must be the invocation-aware total (76), \
             which includes /api/v1/capabilities"
        );
    }
}

#[path = "../../dcentaxe/src/ota_signature.rs"]
pub mod ota_signature;

#[path = "../../dcentaxe-hal/src/temp_decode.rs"]
pub mod temp_decode;

// Same single-source-of-truth pattern: display_convert.rs physically lives in
// `dcentaxe-hal` (consumed by the espidf-only `display` transport, which keeps
// only the I2C half). It is dependency-free pure logic — the SSD1306
// framebuffer, the 5x7 font and glyph blitter, the text/centred-text layout and
// the notification queue's ordering rules — so it is re-included here to
// host-run its `#[cfg(test)]` tests under `cargo test -p dcentaxe-core`.
//
// This closes a real hole: before the split the OLED had ZERO tests anywhere in
// the workspace and the only evidence it rendered anything was a bench
// photograph. The re-included tests differentially pin every drawing routine
// byte-for-byte against the pre-split implementation, pin the font table by
// digest, and render arbitrary 4-line panel states to PNG while asserting the
// panel's real 21-column x 4-row budget
// (`cargo test -p dcentaxe-core oled_render_`). The PNGs land under the cargo
// TARGET directory (`<target>/<triple>/<profile>/oled-evidence/`) so an ordinary
// `cargo test` never writes into the working tree; set
// `DCENTAXE_OLED_EVIDENCE_DIR` to collect them into a campaign evidence folder.
#[path = "../../dcentaxe-hal/src/display_convert.rs"]
pub mod display_convert;

// P1-O1, same pattern one file over: block_reason.rs physically lives in
// `dcentaxe-hal` and is re-included here so its `#[cfg(test)]` tests run in the
// host gate. It owns the fail-closed reason CODES the 128x32 panel shows when a
// board refuses to mine, the imperative ACTION beside each one, and the full
// sentence each code stands in for. `main.rs` used to build that sentence
// inline and hand it to `draw_text`, which clips at column 21 from the right
// with no ellipsis: all 29 of them were clipped, the longest losing 50 of its
// 71 characters. A module the host gate can execute is the only way that stays
// measured — `main.rs` is espidf-only and can never be host-compiled.
#[path = "../../dcentaxe-hal/src/block_reason.rs"]
pub mod block_reason;

// Same single-source-of-truth pattern: tps546_guard.rs physically lives in
// `dcentaxe-hal` (consumed by the espidf-only `i2c` write path). Re-included here
// only so its `#[cfg(test)]` host tests run under `cargo test -p dcentaxe-core`
// without the ESP-IDF toolchain. The module is dependency-free pure logic
// (XPSAFE-2 write-protect policy), so it host-compiles unchanged. This `#[path]`
// copy is a distinct crate root from `dcentaxe_hal::tps546_guard`; the copy is
// the one that gets `cfg(test)`.
#[path = "../../dcentaxe-hal/src/tps546_guard.rs"]
pub mod tps546_guard;

// Same single-source-of-truth pattern: emc2103.rs physically lives in
// `dcentaxe-hal` (its I2C-backed `Emc2103` struct is consumed by the espidf-only
// firmware build). Re-included here only so the pure `decode` submodule's
// `#[cfg(test)]` host tests run under `cargo test -p dcentaxe-core`. On host the
// `espidf_impl` module (and its `crate::i2c` / `log` deps) is cfg-gated out, so
// only the dependency-free decode math compiles.
#[path = "../../dcentaxe-hal/src/emc2103.rs"]
pub mod emc2103;

// Same single-source-of-truth pattern: fan_pid.rs physically lives in
// `dcentaxe-hal` (its control loop is consumed by the espidf-only firmware
// build, so the module is `#[cfg(target_os = "espidf")]`-gated there). It is
// dependency-free pure PID math (HALT-9: derivative EMA filter + retuned gains),
// so it is re-included here only to host-run its `#[cfg(test)]` unit tests under
// `cargo test -p dcentaxe-core`.
#[path = "../../dcentaxe-hal/src/fan_pid.rs"]
pub mod fan_pid;

// Same single-source-of-truth pattern: chip_profiles_bitaxe.rs physically lives
// in the `dcentaxe` binary crate (consumed by the espidf-only autotuner). It is
// dependency-free pure datasheet/V-F-envelope tables, so it is re-included here
// only to host-run its `#[cfg(test)]` tests under `cargo test -p dcentaxe-core`.
// This pins the per-chip V/F caps the autotuner clamps against (AUTOTUNE-4) so a
// future band-filter/dead-band regression is caught in CI.
#[path = "../../dcentaxe/src/chip_profiles_bitaxe.rs"]
pub mod chip_profiles_bitaxe;

// Same single-source-of-truth pattern: mqtt_ha.rs physically lives in the
// `dcentaxe` binary crate (compiled into firmware via `mod mqtt_ha;`, consumed by
// the esp-idf-only `mqtt` transport module). It is dependency-light pure logic
// (the host-pure Home Assistant MQTT auto-discovery + state-payload builder), so
// it is re-included here only to host-run its `#[cfg(test)]` unit tests under
// `cargo test -p dcentaxe-core`. This pins the discovery topic/payload schema +
// the state-key contract so the firmware transport can never publish a payload
// that drifts from the templates HA consumes.
#[path = "../../dcentaxe/src/mqtt_ha.rs"]
pub mod mqtt_ha;

// Same single-source-of-truth pattern: metrics_render.rs physically lives in the
// `dcentaxe` binary crate (declared `mod metrics_render;` in api.rs, consumed by
// the esp-idf-only `register_prometheus` HTTP handler). It is dependency-free pure
// logic (the host-pure Prometheus `/metrics` body builder + label escaper), so it
// is re-included here only to host-run its `#[cfg(test)]` unit tests under
// `cargo test -p dcentaxe-core`. This pins the exposition contract: every existing
// metric family renders byte-identical, the new per-reason reject + share-freshness
// families are well-formed, and every label value is escaped (no broken lines / no
// worker/URL leak).
#[path = "../../dcentaxe/src/metrics_render.rs"]
pub mod metrics_render;

// Same single-source-of-truth pattern: derived_metrics.rs physically lives in the
// `dcentaxe` binary crate (declared `mod derived_metrics;` in main.rs, consumed by
// the esp-idf-only `register_system_info` HTTP handler). It is dependency-free pure
// math (the `/api/system/info` derivations: acceptance-rate, J/TH efficiency,
// expected hashrate), so it is re-included here only to host-run its `#[cfg(test)]`
// unit tests under `cargo test -p dcentaxe-core`. This pins the data-honesty
// contract: `acceptance_rate_pct` returns None at zero confirmed shares so the
// handler can never re-fabricate a 100.0 accept rate on a freshly-booted miner.
#[path = "../../dcentaxe/src/derived_metrics.rs"]
pub mod derived_metrics;

// Same single-source-of-truth pattern: thermal_safety.rs physically lives in the
// `dcentaxe` binary crate (declared `mod thermal_safety;` in main.rs, consumed by
// the esp-idf-only supervisor loop). It is dependency-free pure logic (the
// temperature fold + sensor-adequacy decision), so it is re-included here only to
// host-run its `#[cfg(test)]` unit tests under `cargo test -p dcentaxe-core`. This
// pins the ES-2 fail-closed contract: a die-equipped board that loses every
// ASIC-die reading while only cooler proxies remain is flagged `die_reading_blind`
// (must escalate to THERMAL-BLIND), while a board with no chip diode by design is
// never false-killed, and the all-None case stays handled by `any_temp_valid`.
#[path = "../../dcentaxe/src/thermal_safety.rs"]
pub mod thermal_safety;

/// XPSAFE-1 / COMP-1 host guards.
///
/// These run under the existing CI line
/// `cargo test -p dcentaxe-core --lib --locked` (no ESP-IDF toolchain needed).
/// The espidf-only panic hook + arming code in `dcentaxe/src/main.rs` cannot be
/// host-built on this target, so these pin (a) the pure decision logic the hook
/// depends on (`dcentaxe_hal::safety`), and (b) structural invariants over the
/// `main.rs` / `shared.rs` / workspace `Cargo.toml` source text.
#[cfg(test)]
mod safety_guards {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const SHARED_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/shared.rs"
    ));
    const WORKSPACE_CARGO_TOML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"));
    const AUTOTUNER_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/autotuner.rs"
    ));

    // ── XPSAFE-1: pure buck-cut polarity (load-bearing) ──────────────────────
    // Guards against an inversion that would make the panic hook ENERGIZE the
    // rail instead of cutting it.
    #[test]
    fn panic_hook_buck_off_level_cuts_rail_both_polarities() {
        use dcentaxe_hal::safety::{buck_level_high, buck_off_level};
        // active-low board: OFF == drive HIGH(1); active-high: OFF == drive LOW(0).
        assert_eq!(buck_off_level(true), 1);
        assert_eq!(buck_off_level(false), 0);
        // Full (active_low, on) truth table.
        assert!(buck_level_high(true, false));
        assert!(!buck_level_high(true, true));
        assert!(!buck_level_high(false, false));
        assert!(buck_level_high(false, true));
    }

    // ── XPSAFE-1: panic fan duty is full-scale, never reduced ────────────────
    #[test]
    fn panic_fan_duty_is_full_scale() {
        use dcentaxe_hal::safety::{emc2101_panic_duty, fan_safe_panic_duty, pwm_byte_for_pct};
        assert_eq!(pwm_byte_for_pct(0), 0);
        assert_eq!(pwm_byte_for_pct(100), 255);
        // Above 100 clamps to full scale.
        assert_eq!(pwm_byte_for_pct(200), 255);
        assert_eq!(fan_safe_panic_duty(), 255);
        assert_eq!(fan_safe_panic_duty(), pwm_byte_for_pct(100));
        // EMC2101 uses a 6-bit duty; 63 == 100% full scale.
        assert_eq!(emc2101_panic_duty(), 63);
        // The panic duty must exceed any mining-floor (20%) command.
        assert!(fan_safe_panic_duty() > pwm_byte_for_pct(20));
    }

    // ── XPSAFE-1: hook installed BEFORE any rail enable ──────────────────────
    // Substitute for the un-host-runnable main(): assert the install CALL's byte
    // offset precedes the real `enable_buck(true)` call. We match the call
    // sites, not the banner comments — and `.enable_buck(true)` is NOT specific
    // enough for that, because a doc comment writes `` `gpio_ctrl.enable_buck(true)` ``
    // WITH the leading dot, ~1000 lines earlier. Anchor on the full statement:
    // the install call is the only `install_fail_closed_panic_hook();` (the fn
    // def ends `() {`), and the rail enable is the sole `if let Err(e) =
    // gpio_ctrl.enable_buck(true) {`, which `rail_bringup_wiring` pins as unique.
    #[test]
    fn panic_hook_installed_before_buck_enable() {
        let install = MAIN_RS
            .find("install_fail_closed_panic_hook();")
            .expect("main.rs must CALL install_fail_closed_panic_hook() (XPSAFE-1)");
        let enable = MAIN_RS
            .find("if let Err(e) = gpio_ctrl.enable_buck(true) {")
            .expect("main.rs must call enable_buck(true) to bring up the rail");
        assert!(
            install < enable,
            "panic hook install (byte {install}) must precede the first \
             enable_buck(true) call (byte {enable})"
        );
    }

    // ── COMP-1: no poison-prone `.lock().unwrap()` in shared runtime paths ────
    #[test]
    fn no_lock_unwrap_in_main_or_shared() {
        assert_eq!(
            MAIN_RS.matches(".lock().unwrap()").count(),
            0,
            "main.rs must use .lock().unwrap_or_else(|e| e.into_inner()) — a panic \
             must not poison a Mutex another thread then unwraps (COMP-1)"
        );
        assert_eq!(
            SHARED_RS.matches(".lock().unwrap()").count(),
            0,
            "shared.rs must not use .lock().unwrap() (COMP-1)"
        );
    }

    // ── COMP-1: panic=abort pinned at the workspace root ─────────────────────
    #[test]
    fn release_profile_pins_panic_abort() {
        let profile_idx = WORKSPACE_CARGO_TOML
            .find("[profile.release]")
            .expect("workspace Cargo.toml must declare [profile.release]");
        assert!(
            WORKSPACE_CARGO_TOML[profile_idx..].contains("panic = \"abort\""),
            "[profile.release] must set panic = \"abort\" (COMP-1)"
        );
    }

    // ── XPAUTO-2: chip-health backoff decision logic (host-tested) ───────────
    // The retreat condition lives ONLY in `dcentaxe_hal::safety` so the
    // espidf-only autotuner wiring (which can't host-compile) can never disagree
    // with the host-tested decision. Pin the load-bearing semantics here too.
    #[test]
    fn hw_error_backoff_only_retreats_after_consecutive_debounce() {
        use dcentaxe_hal::safety::{hw_error_backoff_should_retreat, hw_error_streak_next};
        const CEIL: f64 = 0.02; // == MAX_ERROR_RATE in the autotuner
        const REQ: u8 = 3; // the call-site debounce

        // Healthy telemetry never retreats.
        assert!(!hw_error_backoff_should_retreat(0.0, CEIL, 0, REQ));
        assert!(!hw_error_backoff_should_retreat(0.01, CEIL, 9, REQ));
        // A single bad tick is debounced (no instant trip on a share-reject burst).
        assert!(!hw_error_backoff_should_retreat(0.10, CEIL, 0, REQ));
        // Three consecutive bad ticks trip exactly once the streak reaches REQ.
        let mut streak = 0u8;
        let mut tripped_on = None;
        for tick in 1u8..=4 {
            streak = hw_error_streak_next(0.10, CEIL, streak);
            if hw_error_backoff_should_retreat(0.10, CEIL, streak.saturating_sub(1), REQ) {
                tripped_on = Some(tick);
                break;
            }
        }
        assert_eq!(tripped_on, Some(3));
        // Garbage telemetry never retreats and resets the streak (fail-benign).
        assert!(!hw_error_backoff_should_retreat(f64::NAN, CEIL, 9, REQ));
        assert_eq!(hw_error_streak_next(f64::INFINITY, CEIL, 7), 0);
    }

    // ── XPAUTO-2: the autotuner wiring is structurally correct + default-OFF ──
    // autotuner.rs is espidf-only and cannot host-compile, so pin the
    // cross-pollination invariants against the source TEXT: the backoff is
    // gated (default-OFF), it RETREATS to last-known-good (never a higher
    // freq/voltage), and it routes through the same pure decision fn that the
    // tests above exercise. A mis-wire (e.g. a backoff that returns a HIGHER
    // freq, or that loses precedence) would not be caught by host compilation.
    #[test]
    fn autotuner_health_backoff_is_gated_and_retreats_to_last_known_good() {
        // The opt-in gate exists and the new branch reads it (default-OFF flag).
        assert!(
            AUTOTUNER_RS.contains("health_backoff_enabled"),
            "autotuner.rs must gate the XPAUTO-2 backoff behind health_backoff_enabled (default-OFF)"
        );
        // The retreat is computed by the host-tested pure fn, never re-derived.
        assert!(
            AUTOTUNER_RS.contains("hw_error_backoff_should_retreat"),
            "autotuner.rs must call the host-tested hw_error_backoff_should_retreat decision fn"
        );
        assert!(
            AUTOTUNER_RS.contains("hw_error_streak_next"),
            "autotuner.rs must advance the streak via hw_error_streak_next"
        );
        // On retreat it returns the existing last-known-good pair — proven down,
        // never a speculative higher point.
        assert!(
            AUTOTUNER_RS.contains("last_good_frequency")
                && AUTOTUNER_RS.contains("last_good_voltage_mv"),
            "the backoff must retreat to the existing last_good_frequency/last_good_voltage_mv"
        );
        // The retreat counter is part of the autotuner struct state.
        assert!(
            AUTOTUNER_RS.contains("hw_err_over_ceiling_streak"),
            "autotuner.rs must persist the consecutive-over-ceiling streak across ticks"
        );
    }
}

/// XPSAFE-5: structural guards over the rail bring-up dispatch and the panic
/// hook's PMBus rail cut.
///
/// `BoardConfig::rail_bringup()` is host-tested in `dcentaxe-hal`, but a
/// classifier that nothing consumes changes no behaviour — that is exactly how
/// three fully-registered boards stayed unable to mine while the whole test
/// suite was green. `main.rs` is espidf-only and cannot be host-built, so these
/// pin the CONSUMER against its source text: that the rail step dispatches on
/// the classification instead of on a bare `enable_buck` error, that a board
/// with no enable GPIO is refused unless its regulator can cut the rail, and
/// that the panic hook removes power before it adds airflow.
#[cfg(test)]
mod rail_bringup_wiring {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const POWER_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/power.rs"
    ));

    const FXL6408_CONVERT_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/fxl6408_convert.rs"
    ));

    /// The hook's expander constants match the driver's register map.
    ///
    /// The hook cannot call the driver — it is alloc-free and captures no
    /// handles — so it carries its own copies of `OUTPUT_STATE` and the all-low
    /// payload. This pins them equal to the source of truth, exactly as
    /// `pmbus_panic_constants_match_the_hal` does for `OPERATION`. A hook that
    /// writes the wrong register does not fail loudly; it silently does nothing
    /// while reporting a rail cut.
    #[test]
    fn expander_panic_constants_match_the_hal() {
        assert!(
            FXL6408_CONVERT_RS.contains("pub const OUTPUT_STATE: u8 = 0x05;"),
            "fxl6408_convert::reg::OUTPUT_STATE moved — the panic hook's copy is now wrong"
        );
        assert!(
            MAIN_RS.contains("const PANIC_EXPANDER_OUTPUT_STATE: u8 = 0x05;"),
            "the hook's OUTPUT_STATE copy must equal the driver's"
        );
        assert!(
            MAIN_RS.contains("const PANIC_EXPANDER_ALL_LOW: u8 = 0x00;"),
            "the panic payload must drive every expander output LOW — ASIC reset \
             asserted, VREG off, LDO off"
        );
    }

    /// The expander arm publishes its address LAST, like the other two.
    #[test]
    fn the_expander_arm_publishes_its_address_last() {
        let body = MAIN_RS
            .split("fn arm_panic_expander_rail_cut(port: i32, addr: u8) {")
            .nth(1)
            .expect("arm_panic_expander_rail_cut must exist");
        let port = body.find("PANIC_EXPANDER_PORT.store").expect("port store");
        let addr = body.find("PANIC_EXPANDER_ADDR.store").expect("addr store");
        assert!(
            port < addr,
            "the address is the hook's armed-gate and must be stored last"
        );
    }

    /// The expander cut runs BEFORE the fan write, like every other rail cut.
    ///
    /// Power removal outranks airflow: a rail that is off needs no cooling, but
    /// cooling cannot save a rail that stays on.
    #[test]
    fn the_hook_cuts_the_expander_rail_before_it_adds_airflow() {
        let hook = MAIN_RS
            .find("std::panic::set_hook(Box::new(|_panic_info| {")
            .expect("panic hook must exist");
        let body = &MAIN_RS[hook..];
        let expander = body
            .find("PANIC_EXPANDER_ADDR.load(Ordering::Acquire)")
            .expect("hook must read the expander arm");
        let fan = body
            .find("PANIC_FAN_ADDR.load(Ordering::Acquire)")
            .expect("hook must read the fan arm");
        assert!(
            expander < fan,
            "the expander rail cut must precede the fan write"
        );
    }

    /// The panic cut is armed BEFORE the expander rail can be raised.
    ///
    /// The arm is the only actuator these boards have. Raising VREG first would
    /// leave a window in which a panic energizes the chain with nothing able to
    /// bring it down — the precise gap XPSAFE-5 was written to close for the
    /// PMBus boards.
    #[test]
    fn the_expander_cut_is_armed_before_its_rail_can_rise() {
        let arm = MAIN_RS
            .find("arm_panic_expander_rail_cut(0, addr);")
            .expect("main.rs must arm the expander rail cut");
        let assertion = MAIN_RS
            .find("Rail bring-up: expander VREG enable asserted")
            .expect("main.rs must assert the expander VREG enable");
        assert!(
            arm < assertion,
            "the panic cut must be armed before the expander VREG enable is asserted"
        );
    }

    /// The normal fail-closed path cuts an expander rail too.
    ///
    /// Without this a Q-series board survives a POWER FAULT with its rail up:
    /// `enable_buck(false)` errors (no ESP pin) and `PowerManager::disable`
    /// returns `RequiresBuckCut` because a TPS5364x cannot switch its own
    /// output. Neither step touches the only actuator the board has.
    #[test]
    fn the_fail_closed_path_cuts_an_expander_rail() {
        let body = MAIN_RS
            .split("fn fail_closed_power_off(")
            .nth(1)
            .expect("fail_closed_power_off must exist");
        assert!(
            body.contains("PANIC_EXPANDER_ADDR.load(Ordering::Acquire)"),
            "fail_closed_power_off must cut an expander rail when one is armed"
        );
        assert!(
            body.contains("PANIC_EXPANDER_ALL_LOW"),
            "the fail-closed expander cut must drive every output LOW"
        );
    }

    /// A TPS5364x reports that it cannot power itself off.
    ///
    /// `PowerManager::disable` used to fall through to `Ok(())` for this part —
    /// reporting a successful power-off to the fail-closed path while doing
    /// nothing, because its `ON_OFF_CONFIG` leaves `OPERATION` inert. On a board
    /// with an enable GPIO the rail still came down and only the log lied; on a
    /// board without one, nothing cut the rail at all.
    #[test]
    fn a_tps5364x_admits_it_cannot_switch_its_own_output() {
        let body = POWER_RS
            .split("    pub fn disable(&self, i2c: &mut I2cBus) -> Result<(), PowerError> {")
            .nth(2)
            .expect("PowerManager::disable must exist (second `disable` in the file)");
        let head = &body[..body.find("\n    }").unwrap_or(body.len())];
        assert!(
            head.contains("self.tps5364x.is_some()"),
            "PowerManager::disable must branch on a TPS5364x rather than falling \
             through to Ok(())"
        );
        assert!(
            head.contains("RequiresBuckCut"),
            "a TPS5364x disable must return RequiresBuckCut — the caller already \
             handles it by proceeding to the real actuator"
        );
    }

    /// Every GPIO tuple `board.rs` calls bindable is really an arm in `main.rs`.
    ///
    /// `board_gpio_tuple_is_bindable_for_every_model` checks each board against
    /// a hardcoded `SUPPORTED` list, which is only as good as its agreement
    /// with the binder. Nothing previously compared the two, so `SUPPORTED`
    /// could gain an entry the binder never grew — and a board matching only
    /// that phantom entry would reach the `pins => panic!` fallback, which is
    /// `panic = abort`, which is a boot loop.
    ///
    /// This checks the direction that matters: every tuple `board.rs` promises
    /// is bindable must literally appear in the binder.
    #[test]
    fn every_supported_gpio_tuple_is_a_real_binder_arm() {
        const BOARD_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe-hal/src/board.rs"
        ));
        let list_start = BOARD_RS
            .find("const SUPPORTED: [(i32, i32, i32, i32); ")
            .expect("board.rs must declare the bindable-tuple list");
        let list_end = BOARD_RS[list_start..]
            .find("];")
            .map(|o| list_start + o)
            .expect("SUPPORTED list must terminate");
        let list = &BOARD_RS[list_start..list_end];

        let tuples: Vec<&str> = list
            .match_indices('(')
            .skip(1) // the `[(i32, i32, i32, i32); N]` type itself
            .filter_map(|(i, _)| list[i..].find(')').map(|e| &list[i..=i + e]))
            .collect();
        assert!(
            tuples.len() >= 6,
            "parsed only {} tuples out of SUPPORTED — the parse is wrong, so the \
             assertions below would be vacuous",
            tuples.len()
        );
        for tuple in tuples {
            assert!(
                MAIN_RS.contains(&format!("{tuple} =>")),
                "board.rs lists {tuple} as bindable, but main.rs has no such \
                 binder arm — a board with that tuple would hit `pins => panic!`"
            );
        }
    }

    /// The ASIC LDO must be raised BEFORE the core regulator is configured.
    ///
    /// Upstream `NerdQaxePlus::initAsics` is explicit: `LDO_enable()`, 100 ms,
    /// then `m_tps->init()`. Our equivalent of that init is
    /// `PowerManager::new`, so the LDO step has to appear earlier in the file.
    /// Inverting the order leaves the dies without their IO supply while the
    /// core rail is programmed — a chain that never answers on a rail that
    /// looks perfect from the regulator's side.
    #[test]
    fn the_ldo_comes_up_before_the_core_regulator_is_configured() {
        let ldo = MAIN_RS
            .find("match gpio_ctrl.enable_ldo(true) {")
            .expect("main.rs must raise the ASIC LDO during bring-up");
        let regulator = MAIN_RS
            .find("PowerManager::new(")
            .expect("main.rs must construct a PowerManager");
        assert!(
            ldo < regulator,
            "the ASIC LDO enable must precede PowerManager::new — upstream's own \
             order is LDO_enable() then m_tps->init()"
        );
    }

    /// The LDO step asks `has_ldo()` instead of reading `enable_ldo`'s `Err`.
    ///
    /// `enable_ldo` returns `Err` on a board that HAS no LDO pin, which is a
    /// topology report and not an actuation failure. Reading it as a failure is
    /// the exact defect that left three boards permanently unable to mine in
    /// Wave 21; this pins the shape that cannot repeat it.
    #[test]
    fn an_absent_ldo_is_asked_about_rather_than_failed_into() {
        assert!(
            MAIN_RS.contains("if mining_permitted && gpio_ctrl.has_ldo() {"),
            "the LDO bring-up must be guarded on has_ldo(), so a board with no \
             LDO rail is skipped rather than blocked"
        );
    }

    /// The LDO comes down AFTER the core rail, with upstream's settle.
    ///
    /// `NerdQaxePlus::shutdown` is `setVoltage(0.0)` -> 500 ms ->
    /// `LDO_disable()`. Dropping the IO supply first would leave it below a
    /// still-discharging core rail.
    #[test]
    fn the_fail_closed_path_drops_the_ldo_after_the_core_rail() {
        let buck = MAIN_RS
            .find("if let Err(e) = gpio_ctrl.enable_buck(false) {")
            .expect("fail_closed_power_off must cut the buck");
        let ldo = MAIN_RS
            .find("if let Err(e) = gpio_ctrl.enable_ldo(false) {")
            .expect("fail_closed_power_off must drop the ASIC LDO");
        assert!(
            buck < ldo,
            "the ASIC LDO must be dropped after the core rail is cut"
        );
        assert!(
            MAIN_RS.contains("const LDO_SHUTDOWN_SETTLE_MS: u64 = 500;"),
            "the core-rail-to-LDO settle must match upstream's 500 ms"
        );
    }

    /// The panic hook does NOT drop the ASIC LDO, and that is deliberate.
    ///
    /// The hook has no budget for the 500 ms settle upstream observes between
    /// cutting the core rail and dropping the LDO, and an IO rail left up over
    /// a collapsing core rail is exactly the state that settle holds. Adding an
    /// LDO write to the hook would invert a sequence the vendor is explicit
    /// about, so this pins the omission as a decision rather than a gap.
    #[test]
    fn the_panic_hook_leaves_the_ldo_alone() {
        let hook = MAIN_RS
            .find("std::panic::set_hook(Box::new(|_panic_info| {")
            .expect("main.rs must install the fail-closed panic hook");
        let hook_end = MAIN_RS[hook..]
            .find("\nfn ")
            .map(|o| hook + o)
            .unwrap_or(MAIN_RS.len());
        let body = &MAIN_RS[hook..hook_end];
        // Positive anchors FIRST. A negative assertion over a computed slice
        // passes for two reasons — the thing is absent, or the slice is empty —
        // and only one of them is the invariant. These make an empty or
        // mis-cut body fail loudly instead of silently satisfying the test.
        assert!(
            body.contains("PANIC_BUCK_GPIO.load(Ordering::Acquire)"),
            "hook body slice did not capture the buck cut — the slice is wrong, \
             so the negative assertion below would be vacuous"
        );
        assert!(
            body.contains("PANIC_FAN_ADDR.load(Ordering::Acquire)"),
            "hook body slice did not capture the fan write — slice is too short"
        );
        assert!(
            !body.contains("PANIC_LDO"),
            "the panic hook must not act on the ASIC LDO — see LDO_SHUTDOWN_SETTLE_MS"
        );
    }

    /// The rail step must ask WHY there is no enable pin, not just that there
    /// isn't one. Reverting to a single unconditional `enable_buck(true)` — the
    /// shape that blocked NerdAxe-gamma, BitForge Nano and BitAxe Naja — fails
    /// here.
    #[test]
    fn rail_enable_dispatches_on_the_classification() {
        assert!(
            MAIN_RS.contains("match board_config.rail_bringup() {"),
            "main.rs must dispatch the rail step on RailBringup, not on the \
             bare Err from an absent buck-enable pin"
        );
        for arm in [
            "dcentaxe_hal::board::RailBringup::EnableGpio =>",
            "dcentaxe_hal::board::RailBringup::RegulatorOnly =>",
            "dcentaxe_hal::board::RailBringup::NoActuator =>",
        ] {
            assert!(MAIN_RS.contains(arm), "main.rs is missing the `{arm}` arm");
        }
    }

    /// `enable_buck(true)` must live INSIDE the `EnableGpio` arm — the only
    /// class of board that has a pin to drive.
    #[test]
    fn the_rail_is_only_driven_by_gpio_on_boards_that_have_one() {
        // Anchor on the STATEMENT, not on `.enable_buck(true)`: that substring
        // also occurs in four doc/banner comments, so a bare `find` for it
        // lands ~1000 lines above the real call site.
        const CALL_SITE: &str = "if let Err(e) = gpio_ctrl.enable_buck(true) {";
        assert_eq!(
            MAIN_RS.matches(CALL_SITE).count(),
            1,
            "there must be exactly ONE rail-enable call site to reason about"
        );
        let enable_gpio_arm = MAIN_RS
            .find("dcentaxe_hal::board::RailBringup::EnableGpio =>")
            .expect("EnableGpio arm");
        let regulator_arm = MAIN_RS
            .find("dcentaxe_hal::board::RailBringup::RegulatorOnly =>")
            .expect("RegulatorOnly arm");
        let enable_call = MAIN_RS.find(CALL_SITE).expect("enable_buck");
        assert!(
            enable_gpio_arm < enable_call && enable_call < regulator_arm,
            "enable_buck(true) (byte {enable_call}) must sit between the \
             EnableGpio arm (byte {enable_gpio_arm}) and the RegulatorOnly arm \
             (byte {regulator_arm}) — driving a pin a board does not have is \
             what this whole dispatch exists to stop"
        );
    }

    /// Skipping the GPIO step is only safe while something else can cut the
    /// rail. A probed DS4432U cannot (`disable()` returns `RequiresBuckCut`),
    /// nor can a TPS5364x (it ignores `OPERATION`), and on these boards there is
    /// no buck GPIO to fall back on. See
    /// `the_rail_cut_check_asks_for_a_capability_not_a_part` for why this is
    /// phrased as a capability rather than the part name it started as.
    #[test]
    fn a_board_with_no_enable_gpio_is_refused_unless_its_regulator_can_cut() {
        assert!(
            MAIN_RS.contains("power_mgr.regulator_type().can_cut_rail_over_i2c()"),
            "main.rs must verify the PROBED regulator can cut the rail before \
             letting a board with no enable GPIO energize"
        );
        let check = MAIN_RS
            .find("power_mgr.regulator_type().can_cut_rail_over_i2c()")
            .expect("regulator capability check");
        let raise = MAIN_RS
            .find("power_mgr.set_voltage(&mut i2c, config.target_voltage_mv)")
            .expect("main.rs must raise the rail with set_voltage");
        assert!(
            check < raise,
            "the regulator identity check (byte {check}) must run BEFORE the \
             rail is raised (byte {raise})"
        );
    }

    /// The hook's PMBus command bytes must be the driver's, not a guess.
    #[test]
    fn pmbus_panic_constants_match_the_hal() {
        assert!(
            POWER_RS.contains("pub const OPERATION: u8 = 0x01;"),
            "power::pmbus::OPERATION moved — the panic hook's mirror is stale"
        );
        assert!(
            POWER_RS.contains("pub const OPERATION_OFF: u8 = 0x00;"),
            "power::pmbus::OPERATION_OFF moved — the panic hook's mirror is stale"
        );
        assert!(
            MAIN_RS.contains("const PANIC_PMBUS_OPERATION: u8 = 0x01;"),
            "the hook must write the same OPERATION register the driver does"
        );
        assert!(
            MAIN_RS.contains("const PANIC_PMBUS_OPERATION_OFF: u8 = 0x00;"),
            "the hook must write the same OFF payload the driver does"
        );
        // OPERATION_ON is 0x80; writing it from the hook would ENERGIZE the rail
        // during a panic. The mirrored OFF payload must never drift to it.
        assert!(
            POWER_RS.contains("pub const OPERATION_ON: u8 = 0x80;"),
            "OPERATION_ON moved; re-check that the hook's payload is still OFF"
        );
        assert!(
            !MAIN_RS.contains("const PANIC_PMBUS_OPERATION_OFF: u8 = 0x80;"),
            "the hook's payload is OPERATION_ON — a panic would energize the rail"
        );
    }

    /// Power off outranks cooling: a rail that is off needs no airflow, but
    /// airflow cannot save a rail that stays on. Both are bounded by the same
    /// I2C tick budget so neither can wedge the abort path.
    #[test]
    fn the_panic_hook_removes_power_before_it_adds_airflow() {
        let pmbus = MAIN_RS
            .find("let pmbus_addr = PANIC_PMBUS_ADDR.load(Ordering::Acquire);")
            .expect("hook must read the armed PMBus address");
        let fan = MAIN_RS
            .find("let fan_addr = PANIC_FAN_ADDR.load(Ordering::Acquire);")
            .expect("hook must read the armed fan address");
        assert!(
            pmbus < fan,
            "the PMBus rail cut (byte {pmbus}) must run before the fan write \
             (byte {fan})"
        );
        assert!(
            MAIN_RS.contains("const PANIC_I2C_TICKS: u32 = 20;"),
            "both hook I2C writes must share one bounded tick budget"
        );
        // The count is the point: it is what noticed XPSAFE-5d adding a fourth
        // write. Any new actuator in the hook must arrive WITH its bounded
        // timeout, or this fails rather than letting an unbounded I2C call
        // reach the abort path.
        assert_eq!(
            MAIN_RS.matches("PANIC_I2C_TICKS,").count(),
            4,
            "every i2c_master_write_to_device in the hook (1 PMBus + 1 expander \
             + 2 fan registers) must pass the bounded timeout"
        );
    }

    /// The rail-cut test must be a CAPABILITY, not a part name.
    ///
    /// A TPS5364x speaks PMBus fluently and still cannot switch its own output
    /// (its `ON_OFF_CONFIG` leaves the CMD bit clear), so `== Tps546` and "can
    /// cut the rail" stopped being the same question the moment that part was
    /// wired up. Naming the part again would silently let a TPS5364x board with
    /// no enable GPIO energize a rail nothing can bring down.
    #[test]
    fn the_rail_cut_check_asks_for_a_capability_not_a_part() {
        assert!(
            MAIN_RS.contains("power_mgr.regulator_type().can_cut_rail_over_i2c()"),
            "main.rs must gate on the capability, not on a regulator part name"
        );
        assert!(
            !MAIN_RS.contains("regulator_type() == dcentaxe_hal::power::PowerIcType::Tps546"),
            "the part-name comparison must be gone, not merely supplemented"
        );
        assert!(
            POWER_RS.contains("Self::Ds4432u | Self::Tps5364x => false,"),
            "neither the DS4432U nor the TPS5364x can cut a rail over I2C"
        );
        assert!(
            POWER_RS.contains("Self::Tps546 => true,"),
            "the TPS546 is the one regulator whose OPERATION_OFF switches the stage"
        );
    }

    /// A regulator that must be configured before EN is asserted, is.
    ///
    /// The deferred assertion has to land in the window between
    /// `PowerManager::new` (which programs phases, current-sense full scale and
    /// the OT limits) and `set_voltage` (which commands the rail). Outside that
    /// window it is either the bug it replaced or a rail commanded before it is
    /// enabled.
    #[test]
    fn the_deferred_enable_lands_between_regulator_init_and_the_first_setpoint() {
        let deferred = MAIN_RS
            .find("XPSAFE-5b: the deferred enable")
            .expect("main.rs must defer the enable for RegulatorBeforeGpio boards");
        let init = MAIN_RS
            .find("PowerManager::new(&mut i2c, &board_config)")
            .expect("PowerManager::new call site");
        let setpoint = MAIN_RS
            .find("power_mgr.set_voltage(&mut i2c, config.target_voltage_mv)")
            .expect("first setpoint");
        assert!(
            init < deferred && deferred < setpoint,
            "deferred enable (byte {deferred}) must sit between PowerManager::new \
             (byte {init}) and the first set_voltage (byte {setpoint})"
        );
        assert!(
            MAIN_RS.contains("RailEnableOrder::RegulatorBeforeGpio"),
            "main.rs must dispatch on the declared order, not on a board list"
        );
    }

    /// Arming publishes the address LAST, so the hook can never fire on a
    /// half-written pair and write OPERATION_OFF to whatever port 0 happens to
    /// be. Same discipline as `arm_panic_fan`.
    #[test]
    fn the_pmbus_arm_publishes_its_address_last() {
        let body = MAIN_RS
            .split("fn arm_panic_pmbus_rail_cut(port: i32, addr: u8) {")
            .nth(1)
            .expect("arm_panic_pmbus_rail_cut must exist");
        let port = body.find("PANIC_PMBUS_PORT.store").expect("port store");
        let addr = body.find("PANIC_PMBUS_ADDR.store").expect("addr store");
        assert!(
            port < addr,
            "the address is the hook's armed-gate and must be stored last"
        );
    }
}

/// XPSAFE-2: structural guards over the TPS546 fault-limit write-protect wiring.
///
/// `power.rs` / `i2c.rs` are espidf-only and cannot be host-built, so (like the
/// XPSAFE-1 `safety_guards`) these pin the cross-pollination invariants against
/// the source TEXT: the guard is default-OFF (a Cargo feature, not in `default`),
/// the protected register set stays in sync with `power::pmbus`, and the
/// arm-before-/latch-after-`configure_limits` ordering is intact so a future edit
/// can't silently strip the guard or block normal voltage control.
#[cfg(test)]
mod tps546_guard_wiring {
    use crate::tps546_guard::{is_protected_register, PROTECTED_REGISTERS, TPS546_ADDR};

    const POWER_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/power.rs"
    ));
    const I2C_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/i2c.rs"
    ));
    const HAL_CARGO_TOML: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/Cargo.toml"
    ));

    // ── XPSAFE-2: the guard is DEFAULT-OFF (opt-in Cargo feature) ────────────
    #[test]
    fn guard_feature_is_declared_and_not_in_default() {
        assert!(
            HAL_CARGO_TOML.contains("tps546-fault-limit-guard = []"),
            "dcentaxe-hal must declare the `tps546-fault-limit-guard` feature"
        );
        // It must NOT be enabled by default — find the `default = [...]` line and
        // assert the feature name does not appear inside it.
        let default_line = HAL_CARGO_TOML
            .lines()
            .find(|l| l.trim_start().starts_with("default ="))
            .expect("HAL Cargo.toml must declare a `default` feature list");
        assert!(
            !default_line.contains("tps546-fault-limit-guard"),
            "the fault-limit guard must stay DEFAULT-OFF (not in `default`): {default_line}"
        );
    }

    // ── XPSAFE-2: power init arms before, and latches after, configure_limits ─
    #[test]
    fn power_init_arms_before_and_latches_after_configure_limits() {
        let arm = POWER_RS
            .find("arm_tps546_fault_limit_guard()")
            .expect("Tps546::new must ARM the guard (XPSAFE-2)");
        let configure = POWER_RS
            .find("tps.configure_limits(i2c, config)")
            .expect("Tps546::new must call configure_limits");
        let latch = POWER_RS
            .find("latch_tps546_fault_limit_guard()")
            .expect("Tps546::new must LATCH the guard after init (XPSAFE-2)");
        assert!(
            arm < configure,
            "guard must be ARMED (byte {arm}) before configure_limits (byte {configure}) \
             so init's legitimate fault-limit writes still go through"
        );
        assert!(
            configure < latch,
            "guard must be LATCHED (byte {latch}) AFTER configure_limits (byte {configure}) \
             so the protection registers are only locked once init's writes are done"
        );
        // Both wiring calls are feature-gated (default-off).
        assert!(
            POWER_RS.contains("#[cfg(feature = \"tps546-fault-limit-guard\")]"),
            "guard arm/latch calls in power.rs must be feature-gated default-off"
        );
    }

    // ── XPSAFE-2: the i2c write path consults the guard ──────────────────────
    #[test]
    fn i2c_write_path_consults_the_guard() {
        assert!(
            I2C_RS.contains("is_write_blocked(addr, register)"),
            "i2c.rs write() must consult GuardState::is_write_blocked (XPSAFE-2)"
        );
        assert!(
            I2C_RS.contains("fn refuse_tps546_write"),
            "i2c.rs must refuse guarded writes via refuse_tps546_write"
        );
        // The guard state must default to disarmed in the constructor.
        assert!(
            I2C_RS.contains("tps546_guard: GuardState::default()"),
            "I2cBus must initialize the guard to the disarmed default"
        );
    }

    // ── XPSAFE-2: protected set stays in sync with the power::pmbus codes ─────
    // The pure module duplicates the PMBus register codes by value (it is
    // dependency-free on purpose). Pin that every protected code is actually the
    // PMBus command code power.rs declares, so the two can never silently drift.
    #[test]
    fn protected_registers_match_power_pmbus_declarations() {
        // (protected register code, the `pub const NAME: u8 =` it must equal)
        let pairs: &[(u8, &str)] = &[
            (0x40, "VOUT_OV_FAULT_LIMIT: u8 = 0x40"),
            (0x42, "VOUT_OV_WARN_LIMIT: u8 = 0x42"),
            (0x43, "VOUT_UV_WARN_LIMIT: u8 = 0x43"),
            (0x44, "VOUT_UV_FAULT_LIMIT: u8 = 0x44"),
            (0x2B, "VOUT_MIN: u8 = 0x2B"),
            (0x24, "VOUT_MAX: u8 = 0x24"),
            (0x55, "VIN_OV_FAULT_LIMIT: u8 = 0x55"),
            (0x58, "VIN_UV_WARN_LIMIT: u8 = 0x58"),
            (0x35, "VIN_ON: u8 = 0x35"),
            (0x36, "VIN_OFF: u8 = 0x36"),
            (0x46, "IOUT_OC_FAULT_LIMIT: u8 = 0x46"),
            (0x4A, "IOUT_OC_WARN_LIMIT: u8 = 0x4A"),
            (0x4F, "OT_FAULT_LIMIT: u8 = 0x4F"),
            (0x51, "OT_WARN_LIMIT: u8 = 0x51"),
            (0x5F, "VIN_OV_FAULT_RESPONSE: u8 = 0x5F"),
            (0x47, "IOUT_OC_FAULT_RESPONSE: u8 = 0x47"),
            (0x50, "OT_FAULT_RESPONSE: u8 = 0x50"),
        ];
        for (code, decl) in pairs {
            assert!(
                is_protected_register(TPS546_ADDR, *code),
                "0x{code:02x} must be in the protected set"
            );
            assert!(
                POWER_RS.contains(decl),
                "power::pmbus must still declare `{decl}` — protected set drifted from power.rs"
            );
        }
        // Every pair above accounts for exactly the protected set (no orphan code
        // in PROTECTED_REGISTERS that power.rs doesn't back).
        assert_eq!(
            PROTECTED_REGISTERS.len(),
            pairs.len(),
            "PROTECTED_REGISTERS changed — update the power::pmbus cross-check table too"
        );
    }
}

/// SV2-activate: the `sv2_authority_pubkey` config field round-trips through the
/// NVS JSON serializer and is `serde(default)` (legacy blobs load `None`), so a
/// firmware that gains this field can still read an old saved config. Lives in
/// the host-only crate root so the `serde_json` dev-dependency never touches a
/// firmware image.
#[cfg(test)]
mod config_sv2_authority {
    use crate::config::DcentAxeConfig;

    #[test]
    fn default_sv2_authority_pubkey_is_none() {
        let cfg = DcentAxeConfig::default();
        assert!(cfg.sv2_authority_pubkey.is_none());
    }

    #[test]
    fn sv2_authority_pubkey_round_trips_none_and_some() {
        // None survives a full serialize → deserialize cycle.
        let mut cfg = DcentAxeConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DcentAxeConfig = serde_json::from_str(&json).unwrap();
        assert!(back.sv2_authority_pubkey.is_none());

        // Some(token) survives too.
        cfg.sv2_authority_pubkey = Some("some-base58-token".to_string());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DcentAxeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.sv2_authority_pubkey.as_deref(),
            Some("some-base58-token")
        );
    }

    #[test]
    fn legacy_config_without_field_loads_none() {
        // A pre-feature config blob (no sv2_authority_pubkey key) must still load
        // via #[serde(default)], yielding None — no schema bump, no load failure.
        let full = DcentAxeConfig::default();
        let mut value: serde_json::Value = serde_json::to_value(&full).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("sv2_authority_pubkey");
        let legacy_json = serde_json::to_string(&value).unwrap();
        assert!(
            !legacy_json.contains("sv2_authority_pubkey"),
            "legacy blob must omit the field for this test to be meaningful"
        );
        let loaded: DcentAxeConfig = serde_json::from_str(&legacy_json).unwrap();
        assert!(loaded.sv2_authority_pubkey.is_none());
    }
}

/// MQTT/HA config: default-OFF, safe defaults, and legacy NVS blobs (no `mqtt`
/// key) round-trip via `#[serde(default)]` — so a unit that gains the MQTT
/// feature still reads an old saved config. Same host-only harness as
/// `config_sv2_authority`.
#[cfg(test)]
mod config_mqtt {
    use crate::config::{DcentAxeConfig, MqttConfig};

    #[test]
    fn mqtt_default_is_off_with_safe_defaults() {
        let cfg = DcentAxeConfig::default();
        assert!(!cfg.mqtt.enabled, "MQTT must default OFF");
        assert!(cfg.mqtt.broker_host.is_empty());
        assert_eq!(cfg.mqtt.broker_port, 1883);
        assert!(cfg.mqtt.username.is_empty());
        assert!(cfg.mqtt.password.is_empty());
        assert!(!cfg.mqtt.tls);
        assert_eq!(cfg.mqtt.publish_interval_s, 30);
        // The operator-CONTROL surface must default OFF (no remote write surface
        // unless explicitly enabled).
        assert!(
            !cfg.mqtt.commands_enabled,
            "MQTT command entities must default OFF"
        );
    }

    #[test]
    fn mqtt_config_round_trips() {
        let mut cfg = DcentAxeConfig::default();
        cfg.mqtt = MqttConfig {
            enabled: true,
            broker_host: "203.0.113.10".to_string(),
            broker_port: 1883,
            username: "ha".to_string(),
            password: "secret".to_string(),
            tls: false,
            publish_interval_s: 15,
            commands_enabled: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DcentAxeConfig = serde_json::from_str(&json).unwrap();
        assert!(back.mqtt.enabled);
        assert_eq!(back.mqtt.broker_host, "203.0.113.10");
        assert_eq!(back.mqtt.username, "ha");
        assert_eq!(back.mqtt.password, "secret");
        assert_eq!(back.mqtt.publish_interval_s, 15);
        assert!(
            back.mqtt.commands_enabled,
            "commands_enabled must round-trip"
        );
    }

    #[test]
    fn legacy_config_without_mqtt_loads_default() {
        // A pre-feature blob (no `mqtt` key) must still load via #[serde(default)].
        let full = DcentAxeConfig::default();
        let mut value: serde_json::Value = serde_json::to_value(&full).unwrap();
        value.as_object_mut().unwrap().remove("mqtt");
        let legacy_json = serde_json::to_string(&value).unwrap();
        assert!(
            !legacy_json.contains("\"mqtt\""),
            "legacy blob must omit the field for this test to be meaningful"
        );
        let loaded: DcentAxeConfig = serde_json::from_str(&legacy_json).unwrap();
        assert!(!loaded.mqtt.enabled, "missing mqtt key must default OFF");
        assert_eq!(loaded.mqtt.broker_port, 1883);
    }

    #[test]
    fn legacy_mqtt_blob_without_commands_enabled_loads_off() {
        // A blob that predates the command surface (has `mqtt` but no
        // `commands_enabled` key) must load with the control surface OFF.
        let full = DcentAxeConfig::default();
        let mut value: serde_json::Value = serde_json::to_value(&full).unwrap();
        value
            .get_mut("mqtt")
            .and_then(|m| m.as_object_mut())
            .unwrap()
            .remove("commands_enabled");
        let legacy_json = serde_json::to_string(&value).unwrap();
        let loaded: DcentAxeConfig = serde_json::from_str(&legacy_json).unwrap();
        assert!(
            !loaded.mqtt.commands_enabled,
            "a legacy mqtt blob without commands_enabled must default OFF"
        );
    }
}

/// MQTT/HA command-surface clamp contract: the HA command envelope constants in
/// `mqtt_ha` MUST stay equal to the `chip_profiles_bitaxe::validate_autotune_target`
/// limits the local autotuner enforces, so the advertised HA slider/box range can
/// never drift outside the validated safety envelope. Both modules are re-included
/// in this host crate, so this is a real compile-linked equality (not a text pin).
#[cfg(test)]
mod mqtt_command_clamp_contract {
    use crate::chip_profiles_bitaxe::{
        MAX_AUTOTUNE_TARGET_TEMP_C, MAX_AUTOTUNE_TARGET_WATTS, MIN_AUTOTUNE_TARGET_TEMP_C,
    };
    use crate::mqtt_ha::{
        parse_autotune_mode, AUTOTUNE_MODES, CMD_TARGET_TEMP_MAX_C, CMD_TARGET_TEMP_MIN_C,
        CMD_TARGET_WATTS_MAX,
    };

    #[test]
    fn ha_command_envelope_equals_validator_envelope() {
        // Target-watts ceiling advertised to HA == the validator's board budget.
        assert_eq!(
            CMD_TARGET_WATTS_MAX, MAX_AUTOTUNE_TARGET_WATTS,
            "HA target-watts ceiling must equal validate_autotune_target's max"
        );
        // Target-temp band advertised to HA == the validator's accepted band.
        assert_eq!(CMD_TARGET_TEMP_MIN_C, MIN_AUTOTUNE_TARGET_TEMP_C);
        assert_eq!(CMD_TARGET_TEMP_MAX_C, MAX_AUTOTUNE_TARGET_TEMP_C);
    }

    #[test]
    fn ha_autotune_modes_match_shared_from_api_str() {
        // shared::AutotuneMode is esp-idf-gated and not host-compiled here, so pin
        // the 4 canonical strings against shared.rs source text (the single other
        // source of these strings) + prove parse_autotune_mode round-trips them.
        const SHARED_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/shared.rs"
        ));
        for m in AUTOTUNE_MODES {
            assert_eq!(parse_autotune_mode(m), Some(m), "mode must round-trip");
            assert!(
                SHARED_RS.contains(&format!("=> \"{m}\"")),
                "shared::AutotuneMode::as_api_str must still emit \"{m}\""
            );
        }
    }
}

/// WF-F main-api lane structural guards.
///
/// `main.rs` / `api.rs` live in the `dcentaxe` BINARY crate and cannot
/// host-compile (esp-idf at module scope), so — exactly like `safety_guards` and
/// `tps546_guard_wiring` — these pin the behavioral invariants of each fix against
/// the source TEXT via `include_str!`. The pure DECISION logic each fix consumes
/// (`power_field_available`, `tach_proof_required`, the fan floor) is already
/// host-tested in `dcentaxe-hal::safety` / `board.rs`; these only pin the
/// main.rs/api.rs WIRING that a host compile cannot reach.
/// Char-boundary-safe slice from `start` for up to `len` bytes (source contains
/// multi-byte chars, so a naive `&s[start..start+len]` can split a UTF-8 code
/// point). Returns the substring from `start` to the largest char boundary at or
/// before `start + len`.
#[cfg(test)]
fn safe_window(s: &str, start: usize, len: usize) -> &str {
    let mut end = (start + len).min(s.len());
    while end > start && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[start..end]
}

#[cfg(test)]
mod thermal_ladder_guards {
    use super::safe_window;

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    fn byte_of(hay: &str, needle: &str) -> usize {
        hay.find(needle)
            .unwrap_or_else(|| panic!("main.rs must contain `{needle}`"))
    }

    // ── XPSAFE-5: cut-hash-before-fan-noise ordering at the WARNING tier ──────
    #[test]
    fn warning_tier_sheds_hash_before_raising_fan() {
        // The WARNING tier (>90 C) must send the hash-shed frequency BEFORE the
        // fan bump (THERMAL_WARN_FAN_CAP_PCT). Find the WARNING comment anchor and
        // assert the freq send precedes the set_speed inside that region.
        let region_start = byte_of(MAIN_RS, "XPSAFE-5 WARNING tier");
        let region = &MAIN_RS[region_start..];
        let freq_send = region
            .find("freq_cmd_tx.send(warn_freq)")
            .expect("WARNING tier must shed hash via freq_cmd_tx.send(warn_freq)");
        let fan_bump = region
            .find("fan_ctrl.set_speed(THERMAL_WARN_FAN_CAP_PCT)")
            .expect("WARNING tier must raise fan to THERMAL_WARN_FAN_CAP_PCT");
        assert!(
            freq_send < fan_bump,
            "XPSAFE-5: WARNING tier must cut hash (byte {freq_send}) BEFORE raising the fan (byte {fan_bump})"
        );
    }

    // ── XPSAFE-5: 95 C tier reduces frequency before pinning fan to 100% ──────
    #[test]
    fn ninety_five_tier_throttles_freq_before_fan_100() {
        let region_start = byte_of(MAIN_RS, "max_temp > 95.0");
        let region = &MAIN_RS[region_start..];
        let freq_send = region
            .find("freq_cmd_tx.send(throttled_freq)")
            .expect("95C tier must throttle via freq_cmd_tx.send(throttled_freq)");
        let fan_100 = region
            .find("fan_ctrl.set_speed(100)")
            .expect("95C tier must still pin fan to 100%");
        assert!(
            freq_send < fan_100,
            "XPSAFE-5: 95C tier must reduce frequency (byte {freq_send}) BEFORE fan=100% (byte {fan_100})"
        );
    }

    // ── XPSAFE-5: the home-cap consts exist and the cap is < 100 ──────────────
    #[test]
    fn warn_fan_cap_is_below_full_scale() {
        assert!(MAIN_RS.contains("const THERMAL_WARN_FREQ_SHED_MHZ: f32 = 50.0;"));
        assert!(MAIN_RS.contains("const THERMAL_WARN_FAN_CAP_PCT: u8 = 70;"));
        // 70 < 100 — the WARNING tier is home-capped, not full blast.
        assert!(
            MAIN_RS.contains("THERMAL_WARN_FAN_CAP_PCT: u8 = 70"),
            "the WARNING-tier fan cap must stay below 100 (home/quiet posture)"
        );
    }

    // ── XPSAFE-5: EMERGENCY tier still cuts hash AND power together ────────────
    #[test]
    fn emergency_tier_still_cuts_hash_and_buck() {
        let region_start = byte_of(MAIN_RS, "max_temp > EMERGENCY_TEMP_C");
        let region = safe_window(MAIN_RS, region_start, 2000);
        assert!(
            region.contains("mining_kill.store(true"),
            "EMERGENCY tier must still set mining_kill"
        );
        assert!(
            region.contains("enable_buck(false)"),
            "EMERGENCY tier must still cut the buck rail"
        );
    }

    // ── XPSAFE-5: thresholds are NEVER lowered (regression guard) ─────────────
    #[test]
    fn thermal_thresholds_unchanged() {
        assert!(MAIN_RS.contains("const EMERGENCY_TEMP_C: f32 = 105.0;"));
        assert!(MAIN_RS.contains("const WARNING_TEMP_C: f32 = 90.0;"));
        assert!(
            MAIN_RS.contains("max_temp > 95.0"),
            "the 95C throttle tier must remain"
        );
    }

    // ── HALT-10: always-on proportional curve, gated + floor-respecting ───────
    #[test]
    fn prop_fan_curve_is_gated_and_respects_floor() {
        assert!(MAIN_RS.contains("const PROP_FAN_LOW_TEMP_C: f32 = 55.0;"));
        assert!(MAIN_RS.contains("const PROP_FAN_HIGH_TEMP_C: f32 = 85.0;"));
        assert!(MAIN_RS.contains("const PROP_FAN_MIN_PCT: u8 = 30;"));
        assert!(MAIN_RS.contains("const PROP_FAN_MAX_PCT: u8 = 70;"));
        // cap < 100 and floor >= 20.
        assert!(MAIN_RS.contains("PROP_FAN_MAX_PCT: u8 = 70"));
        assert!(MAIN_RS.contains("PROP_FAN_MIN_PCT: u8 = 30"));
        // The branch is gated live_fan_target == 0 and max_temp <= WARNING
        // (backstops kept). Anchor on the runtime branch's floor comment, which is
        // unique to the executable curve (the const block above uses a different
        // wording), so we inspect the real branch body and not the doc block.
        let region_start = byte_of(MAIN_RS, "Respect the 20% mining floor");
        let region = safe_window(MAIN_RS, region_start, 600);
        assert!(
            region.contains("prop_pct.max(20)"),
            "HALT-10 curve must clamp to the 20% mining floor"
        );
        assert!(
            region.contains("> fan_ctrl.current_speed()"),
            "HALT-10 curve must only RAISE the fan, never reduce a higher manual command"
        );
        // And the branch is gated on live_fan_target == 0 + max_temp <= WARNING.
        assert!(
            MAIN_RS.contains("} else if live_fan_target == 0"),
            "HALT-10 curve must be gated on live_fan_target == 0 (manual/unset)"
        );
    }
}

#[cfg(test)]
mod fan_tach_guards {
    use super::safe_window;

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    // ── HALT-6 / XPSAFE-7: runtime EMC2101 stall gate consumes tach_proof_required ──
    #[test]
    fn runtime_stall_gate_uses_tach_proof_required() {
        assert!(
            MAIN_RS.contains("board_config.tach_proof_required() || fan1_ever_seen"),
            "the EMC2101 runtime stall gate must OR-gate on tach_proof_required() so an \
             opted-in board fails closed on a never-spinning fan (HALT-6/XPSAFE-7)"
        );
    }

    // ── HALT-6 / XPSAFE-7: EMC2101 boot path adds a tach_proof_required-gated proof ──
    #[test]
    fn emc2101_boot_tach_proof_is_present_and_gated() {
        let start = MAIN_RS
            .find("boot-time tach proof for opted-in EMC2101")
            .expect("EMC2101 boot path must add a tach proof (HALT-6/XPSAFE-7)");
        let region = safe_window(MAIN_RS, start, 1400);
        assert!(
            region.contains("board_config.tach_proof_required()"),
            "boot tach proof must be gated on tach_proof_required()"
        );
        assert!(
            region.contains("read_fan_rpm"),
            "boot tach proof must read RPM via read_fan_rpm"
        );
        assert!(
            region.contains("mining_permitted = false"),
            "a never-spinning opted-in fan must set mining_permitted = false at boot"
        );
    }

    // ── HALT-6 / XPSAFE-7: heuristic-only telemetry is surfaced ───────────────
    #[test]
    fn heuristic_only_fan_proof_is_surfaced() {
        assert!(
            MAIN_RS.contains("no fan proof (heuristic only)"),
            "tachless boards must surface a 'no fan proof (heuristic only)' note"
        );
        assert!(
            MAIN_RS
                .contains("telem.fan_proof_heuristic_only = !board_config.tach_proof_required()"),
            "telemetry must carry fan_proof_heuristic_only derived from tach_proof_required()"
        );
    }
}

#[cfg(test)]
mod mainapi_guards {
    use super::safe_window;

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const API_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/api.rs"
    ));
    const SHARED_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/shared.rs"
    ));

    // ── XPSAFE-4: lab bypass is compile-time only (no dead std::env arm) ───────
    #[test]
    fn unsafe_lab_bypass_is_compile_time_only() {
        let start = MAIN_RS
            .find("fn unsafe_lab_safety_bypass_enabled")
            .expect("main.rs must define unsafe_lab_safety_bypass_enabled");
        // The fn body ends at the next `}` line after the option_env! check.
        let body = safe_window(MAIN_RS, start, 700);
        assert!(
            body.contains("option_env!(\"DCENTAXE_UNSAFE_LAB_SAFETY_BYPASS\")"),
            "bypass must still read the compile-time env var"
        );
        assert!(
            !body.contains("std::env::var"),
            "XPSAFE-4: the dead runtime std::env::var arm must be gone"
        );
        // Read once at boot + loud warn.
        assert!(
            MAIN_RS.contains("let unsafe_lab_safety_bypass = unsafe_lab_safety_bypass_enabled();")
        );
        assert!(MAIN_RS.contains("UNSAFE LAB SAFETY BYPASS ENABLED"));
    }

    // ── HALPWR-2-wire / COMP-6-wire: per-field NaN guard on power telemetry ───
    #[test]
    fn power_telemetry_is_nan_guarded_per_field() {
        assert!(
            MAIN_RS.contains("if power_field_available(p.power_w)"),
            "telem.power_w must be guarded with power_field_available before assignment"
        );
        // All four power fields are independently guarded.
        for field in ["voltage_mv", "current_ma", "power_w", "input_voltage_mv"] {
            let guard = format!("power_field_available(p.{field})");
            assert!(
                MAIN_RS.contains(&guard),
                "power.{field} must be guarded by {guard} (one blanked field must not blank the others)"
            );
        }
    }

    // ── MAINAPI-1: per-chip loop is bounded (no unchecked index) ──────────────
    #[test]
    fn per_chip_loop_is_bounded() {
        assert!(
            !MAIN_RS.contains("stats.per_chip[i as usize]"),
            "MAINAPI-1: the per-chip telemetry loop must not index per_chip[i as usize] (panic risk)"
        );
        assert!(
            MAIN_RS.contains(".min(dcentaxe_mining::stats::MAX_CHIPS)"),
            "MAINAPI-1: the loop must clamp the chip count to MAX_CHIPS"
        );
        // Belt-and-suspenders: the per_chip read goes through .get(i) (whitespace
        // between `per_chip` and `.get(i)` is collapsed for a robust match).
        let collapsed: String = MAIN_RS.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            collapsed.contains("per_chip .get(i)") || collapsed.contains("per_chip.get(i)"),
            "MAINAPI-1: the loop must use per_chip.get(i) as a degrade"
        );
    }

    // ── LV08 9-chip scaling (SPEC §5) ─────────────────────────────────────────
    //
    // The `.min(MAX_CHIPS)` clamp above is still required — but on its own it is
    // no longer sufficient, and on a 9-chip board it used to be the thing that
    // TRUNCATED telemetry. The clamp is only safe while `MAX_CHIPS` is at least
    // as wide as the widest board. These contracts pin the capacity side of that
    // pair against the real production sources.
    //
    // `dcentaxe-core` cannot depend on `dcentaxe-mining` (it is a host test
    // harness for the `dcentaxe`/`dcentaxe-hal` sources), so `MAX_CHIPS` is read
    // out of the `stats.rs` TEXT. Note this deliberately reads OTHER files —
    // never this one — so the assertions cannot be self-satisfied by their own
    // needle strings. The compile-linked counterpart lives in
    // `dcentaxe-mining` (`stats::tests::max_chips_covers_the_largest_supported_board`).

    const STATS_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-mining/src/stats.rs"
    ));
    const SELF_TEST_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/self_test.rs"
    ));

    /// Parse the integer literal `stats.rs` declares for `MAX_CHIPS`.
    fn declared_max_chips() -> usize {
        let needle = "pub const MAX_CHIPS: usize = ";
        let at = STATS_RS
            .find(needle)
            .expect("stats.rs must declare `pub const MAX_CHIPS: usize`");
        let rest = &STATS_RS[at + needle.len()..];
        let end = rest
            .find(';')
            .expect("the MAX_CHIPS declaration must terminate with ';'");
        rest[..end]
            .trim()
            .parse::<usize>()
            .expect("MAX_CHIPS must be a plain integer literal")
    }

    /// SPEC §5: `MAX_CHIPS` is a CAPACITY that must exceed the widest supported
    /// chain. The Lucky LV08 is 9× BM1366, and the BM1366 `asic_nr` decode at a
    /// 9-chip address interval (28) yields 9 — one past the last real chip — for
    /// raw nonce bytes 252..=255. So the array must be strictly wider than 9.
    #[test]
    fn max_chips_capacity_covers_the_widest_supported_chain() {
        let max_chips = declared_max_chips();
        assert!(
            max_chips > 9,
            "MAX_CHIPS is {max_chips}: it must be STRICTLY greater than the 9-chip \
             LV08 chain so the one-past `asic_nr = 9` decode has a slot. At 9 or \
             fewer, `main.rs`'s `.min(MAX_CHIPS)` clamp silently truncates live \
             chips out of telemetry and the self-test can never see a full chain."
        );
        assert_ne!(
            max_chips, 6,
            "MAX_CHIPS regressed to the pre-LV08 6-slot array — chips 6..8 would \
             be silently dropped while hashrate still counted them"
        );
    }

    /// `LARGEST_SUPPORTED_ASIC_COUNT` must be the ACTUAL largest chain in the
    /// board registry, not a number someone remembered to bump.
    ///
    /// `dcentaxe-mining` pins `MAX_CHIPS > LARGEST_SUPPORTED_ASIC_COUNT`, but it
    /// cannot see `dcentaxe-hal` — so if a new board landed with more chips than
    /// the constant claims, that check would compare `MAX_CHIPS` against a stale
    /// figure and pass while the real chain overflowed. This is the only place
    /// that can compare the constant to the registry it is supposed to describe.
    /// It is what caught nothing when the LV08 was 9 and everything went to 12
    /// with the NerdEKO.
    #[test]
    fn the_largest_supported_chain_constant_matches_the_board_registry() {
        let needle = "pub const LARGEST_SUPPORTED_ASIC_COUNT: usize = ";
        let at = STATS_RS
            .find(needle)
            .expect("stats.rs must declare `pub const LARGEST_SUPPORTED_ASIC_COUNT`");
        let rest = &STATS_RS[at + needle.len()..];
        let end = rest
            .find(';')
            .expect("the LARGEST_SUPPORTED_ASIC_COUNT declaration must terminate with ';'");
        let declared: u8 = rest[..end]
            .trim()
            .parse()
            .expect("LARGEST_SUPPORTED_ASIC_COUNT must be a plain integer literal");

        let actual = dcentaxe_hal::board::BoardVersionProfile::ALL
            .iter()
            .map(|p| p.model.asic_count())
            .max()
            .expect("the board registry is never empty");

        assert_eq!(
            declared, actual,
            "LARGEST_SUPPORTED_ASIC_COUNT says {declared} but the widest board in \
             the registry has {actual} chips. Bump the constant in stats.rs — and \
             check MAX_CHIPS still exceeds it, because the per-chip telemetry \
             arrays are that wide and nothing else notices when a chain outgrows \
             them."
        );
        assert!(
            declared_max_chips() > actual as usize,
            "MAX_CHIPS ({}) must stay strictly wider than the widest real chain \
             ({actual}) so the one-past `asic_nr` decode has a slot",
            declared_max_chips()
        );
    }

    /// The clamp in `main.rs` must keep clamping against the SHARED constant, not
    /// a locally re-declared number that could drift away from `stats.rs`.
    #[test]
    fn main_clamps_against_the_shared_max_chips_constant() {
        assert!(
            MAIN_RS.contains("dcentaxe_mining::stats::MAX_CHIPS"),
            "main.rs must reference the shared stats::MAX_CHIPS, never a local copy"
        );
        assert!(
            !MAIN_RS.contains("const MAX_CHIPS"),
            "main.rs must not re-declare its own MAX_CHIPS (drift from stats.rs)"
        );
    }

    /// SPEC §5 / H-4: the self-test ASIC-chain step must bound its `per_chip`
    /// scan to the board's declared chip count.
    ///
    /// `self_test.rs` is compiled only in the esp-idf `dcentaxe` binary, so its
    /// own `#[cfg(test)]` module never runs in the host gate — this text contract
    /// is the host-verifiable proof. Two directions are pinned:
    ///  * it must NOT scan the whole fixed array (a phantom one-past slot would
    ///    stand in for a dark chip ⇒ false PASS), and
    ///  * the width helper must exist and be fed the expected count (an unbounded
    ///    or hardcoded width is what made a healthy 9-chip board fail forever).
    #[test]
    fn self_test_asic_chain_scan_is_bounded_to_expected_chips() {
        // Slice to the PRODUCTION region: everything before the file's first
        // `#[cfg(test)]`. Without this, `self_test.rs`'s own unit tests (which
        // legitimately mention `.take(scan)`) would satisfy these assertions and
        // the contract would silently self-pass after the production bound was
        // deleted.
        let prod = &SELF_TEST_RS[..SELF_TEST_RS
            .find("#[cfg(test)]")
            .expect("self_test.rs must still have a #[cfg(test)] module boundary")];
        assert!(
            prod.contains("fn asic_chain_scan_width("),
            "self_test.rs must define the pure asic_chain_scan_width() bound"
        );
        assert!(
            prod.contains("let scan = asic_chain_scan_width(expected);"),
            "the asic_chain step must derive its scan width from `expected`"
        );
        // The scan-width helper must clamp against the shared capacity constant.
        assert!(
            prod.contains("dcentaxe_mining::stats::MAX_CHIPS"),
            "asic_chain_scan_width must clamp against the shared stats::MAX_CHIPS"
        );
        // Both counters (healthy and error-only) go through the bound.
        assert_eq!(
            prod.matches(".take(scan)").count(),
            2,
            "both the healthy and the error-only per_chip scans must be bounded \
             by .take(scan) — an unbounded one re-opens the phantom-slot false PASS"
        );
        // The old unbounded whole-array scan must be gone. Compare with ALL
        // whitespace removed so a reformat cannot make this vacuously true.
        let despaced: String = prod.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            despaced.contains(".take(scan).filter(|c|c.nonces>0)"),
            "the healthy-chip scan must be bounded BEFORE it filters"
        );
        assert!(
            !despaced.contains("s.per_chip.iter().filter(|c|c.nonces>0).count()"),
            "the unbounded whole-array healthy-chip scan must not come back"
        );
    }

    // ── HALPWR-8: power-init recovery probe is board-appropriate ──────────────
    #[test]
    fn power_init_recovery_probe_is_board_aware() {
        assert!(
            !MAIN_RS.contains("let _ = i2c.probe(0x24);"),
            "HALPWR-8: the power-init recovery poke must not hardcode i2c.probe(0x24)"
        );
        assert!(
            MAIN_RS.contains("TPS546_ADDR") && MAIN_RS.contains("DS4432U_ADDR"),
            "HALPWR-8: recovery probe must branch on the board regulator address"
        );
        assert!(
            MAIN_RS.contains("board_config.power_controller"),
            "HALPWR-8: recovery probe must branch on board_config.power_controller"
        );
    }

    // ── MAINAPI-5: mining_kill is one-way at runtime (reboot-only recovery) ────
    #[test]
    fn mining_kill_is_one_way_at_runtime() {
        assert_eq!(
            MAIN_RS.matches("mining_kill.store(false").count(),
            0,
            "MAINAPI-5: nothing in the runtime loop may clear mining_kill — recovery is reboot-only"
        );
        let start = MAIN_RS
            .find("Mining resume requested by user")
            .expect("resume branch must exist");
        let region = safe_window(MAIN_RS, start, 200);
        assert!(
            region.contains("esp_restart"),
            "MAINAPI-5: the API resume branch must reboot via esp_restart"
        );
    }

    // ── XPH-4 / MAINAPI-7: named handler cap + compile-time headroom guard ─────
    #[test]
    fn uri_handler_cap_is_named_and_asserted() {
        assert!(MAIN_RS.contains("const MAX_URI_HANDLERS: usize = 96;"));
        assert!(MAIN_RS.contains("const REGISTERED_HANDLER_ESTIMATE: usize ="));
        assert!(
            MAIN_RS
                .contains("const _: () = assert!(REGISTERED_HANDLER_ESTIMATE < MAX_URI_HANDLERS);"),
            "XPH-4: a compile-time floor guard must pin the estimate under the cap"
        );
        assert!(
            MAIN_RS.contains("max_uri_handlers: MAX_URI_HANDLERS,"),
            "HttpConfig must use the named const, not a bare 96"
        );
    }

    // ── XPH-4 / P1-I3: the registered-handler count is INVOCATION-aware ───────
    //
    // The predecessor of this test counted occurrences of the *text*
    // `.fn_handler(` in api.rs and added documented constants for the other
    // files. That UNDER-COUNTED. A registration written inside a helper — a `fn`
    // like `dashboard::register_static`, or a `let name = |path: &str, …| { … }`
    // closure — is written ONCE but EXECUTED once per call site. Four such
    // helpers exist (three closures in api.rs, `register_static` in
    // dashboard.rs); between them 4 text sites produce 16 registrations, so the
    // old text count reported 64 where the firmware registers 76.
    //
    // Replacing the text count with this one is STRICTLY STRICTER: it removes a
    // blind spot in the direction that fails at boot (httpd refuses the handler
    // past `max_uri_handlers`), it never relaxes the cap. Cross-checked by
    // `tools/count_handlers.py`, which resolves the same sites with a Rust-aware
    // parser and prints the per-file table and the full URI list.
    #[test]
    fn registered_handler_count_under_cap() {
        const DASHBOARD_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/dashboard.rs"
        ));
        const AUTH_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/auth.rs"
        ));
        const MCP_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/mcp.rs"
        ));

        // (sites whose first argument is a URI literal, sites whose first
        // argument is an identifier — i.e. a helper parameter or loop variable).
        fn fn_handler_sites(src: &str) -> (usize, usize) {
            let (mut literal, mut indirect) = (0usize, 0usize);
            let mut rest = src;
            while let Some(pos) = rest.find(".fn_handler(") {
                rest = &rest[pos + ".fn_handler(".len()..];
                if rest.trim_start().starts_with('"') {
                    literal += 1;
                } else {
                    indirect += 1;
                }
            }
            (literal, indirect)
        }

        // Call sites of a URI-registering helper: a statement whose callee name
        // starts with `register` and which either carries a `"/…"` URI literal or
        // opens a multi-line argument list. Each such call is one registration.
        fn registrar_call_sites(src: &str) -> usize {
            src.lines()
                .map(str::trim_start)
                .filter(|line| {
                    line.starts_with("register") && (line.contains("\"/") || line.ends_with('('))
                })
                .count()
        }

        // `core.autocrlf = true` in this repo, so a freshly created worktree
        // checks these sources out with CRLF while the long-lived main tree
        // holds LF. Normalise ONCE here so this guard can never pass on one
        // checkout and fail on the other. Two pre-existing guards in this crate
        // (`sv2_fallback_failover_is_wired` and
        // `config::identity_gate_tests::default_model_for_build_has_lucky_arms`)
        // match bare `\n` literals and fail in a CRLF worktree for exactly that
        // reason — do not copy their shape.
        let api = API_RS.replace("\r\n", "\n");
        let dashboard = DASHBOARD_RS.replace("\r\n", "\n");
        let auth = AUTH_RS.replace("\r\n", "\n");
        let mcp = MCP_RS.replace("\r\n", "\n");

        let (api_lit, api_ind) = fn_handler_sites(&api);
        let (dash_lit, dash_ind) = fn_handler_sites(&dashboard);
        let (auth_lit, auth_ind) = fn_handler_sites(&auth);
        let (mcp_lit, mcp_ind) = fn_handler_sites(&mcp);

        let api_calls = registrar_call_sites(&api);
        let dash_calls = registrar_call_sites(&dashboard);
        let auth_calls = registrar_call_sites(&auth);
        let mcp_calls = registrar_call_sites(&mcp);

        // The shape must hold, or the arithmetic below is not a census: every
        // indirect site is backed by helper call sites, and a file with no
        // indirection has no registrar calls either.
        assert_eq!(
            (auth_ind, auth_calls, mcp_ind, mcp_calls),
            (0, 0, 0, 0),
            "auth.rs/mcp.rs must register only literal URIs — re-run \
             `python tools/count_handlers.py`"
        );
        assert_eq!(
            (api_ind, api_calls),
            (3, 6),
            "api.rs must have exactly 3 indirect `.fn_handler(` sites, each a \
             helper closure invoked twice (statistics, OTA GET, update manifest) \
             — re-run `python tools/count_handlers.py`"
        );
        assert_eq!(
            (dash_ind, dash_calls),
            (1, 10),
            "dashboard.rs must have exactly 1 indirect `.fn_handler(` site \
             (register_static) invoked once per /dashboard/* asset — re-run \
             `python tools/count_handlers.py`"
        );

        let registered = (api_lit + api_calls)
            + (dash_lit + dash_calls)
            + (auth_lit + auth_calls)
            + (mcp_lit + mcp_calls);
        let text_only = api.matches(".fn_handler(").count()
            + dashboard.matches(".fn_handler(").count()
            + auth.matches(".fn_handler(").count()
            + mcp.matches(".fn_handler(").count();

        assert!(
            registered > text_only,
            "the invocation-aware count ({registered}) must exceed the old text \
             count ({text_only}); if they are equal, helper resolution broke and \
             the blind spot is back"
        );
        assert_eq!(
            registered, 76,
            "measured HTTP URI registrations changed — re-run \
             `python tools/count_handlers.py`, then update \
             REGISTERED_HANDLER_ESTIMATE and the accounting table in main.rs"
        );
        assert!(
            registered < 96,
            "registered handlers {registered} must stay under the 96 cap"
        );
        assert!(
            registered + 8 < 96,
            "registered handlers {registered} must keep the 8-slot runtime \
             tripwire headroom under the 96 cap"
        );
        assert!(
            MAIN_RS.contains("const REGISTERED_HANDLER_ESTIMATE: usize = 76;"),
            "REGISTERED_HANDLER_ESTIMATE must equal the measured invocation-aware \
             total (76)"
        );
    }

    // ── P1-I3 (round 2): the SET of files that register URI handlers is pinned ─
    //
    // ADOPTED from the round-1 blind critic's held-out test, which lived at
    // `dcentaxe-core/tests/critic_heldout_p1i3.rs` under this same name.  It is
    // moved into the guard set (this module) so it is maintained with the census
    // it protects instead of sitting beside it, and so `-p dcentaxe-core --lib`
    // alone is sufficient to catch the hole.
    //
    // WHY IT EXISTS.  `registered_handler_count_under_cap` above reads exactly
    // FOUR hardcoded sources (api / auth / dashboard / mcp), and
    // `tools/count_handlers.py` attributes a `.fn_handler(` site to a server only
    // when its enclosing `fn` is reachable from a wiring needle it already knows.
    // Neither of them sees a registration in a FIFTH file wired into
    // `http_server` from a new `main.rs` line.  The round-1 critic proved this by
    // wiring two handlers out of `swarm.rs`: the script printed them as `dead`,
    // still reported `measured = 76 OK`, and still exited 0, while every guard in
    // this crate stayed green.  The census then UNDER-counts, and under-counting
    // is the direction that makes `httpd_register_uri_handler()` fail at boot —
    // the class of bug that boot-looped this firmware against the old 64 cap.
    //
    // Round 2 closes the same hole on the script side (a dead site is now a
    // problem, and the script exits non-zero).  This guard closes it on the Rust
    // side, where no Python is in the loop.
    //
    // Comments are stripped before matching, because `main.rs` legitimately names
    // `.fn_handler(` inside its accounting comment, and this module's own prose
    // does too.
    #[test]
    fn only_the_five_known_files_register_uri_handlers() {
        use std::collections::BTreeSet;
        use std::fs;
        use std::path::{Path, PathBuf};

        /// Blank out `//` line comments and `/* */` block comments (Rust nests
        /// them), preserving length so nothing else shifts.
        fn strip_comments(src: &str) -> String {
            let b: Vec<char> = src.chars().collect();
            let mut out = b.clone();
            let n = b.len();
            let mut i = 0;
            while i < n {
                if b[i] == '/' && i + 1 < n && b[i + 1] == '/' {
                    let mut j = i;
                    while j < n && b[j] != '\n' {
                        out[j] = ' ';
                        j += 1;
                    }
                    i = j;
                } else if b[i] == '/' && i + 1 < n && b[i + 1] == '*' {
                    let mut depth = 1usize;
                    let mut j = i + 2;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    while j < n && depth > 0 {
                        if b[j] == '/' && j + 1 < n && b[j + 1] == '*' {
                            depth += 1;
                            out[j] = ' ';
                            out[j + 1] = ' ';
                            j += 2;
                        } else if b[j] == '*' && j + 1 < n && b[j + 1] == '/' {
                            depth -= 1;
                            out[j] = ' ';
                            out[j + 1] = ' ';
                            j += 2;
                        } else {
                            if b[j] != '\n' {
                                out[j] = ' ';
                            }
                            j += 1;
                        }
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            out.into_iter().collect()
        }

        // RECURSIVE, unlike the critic's original `read_dir`: `dcentaxe/src` is
        // flat today, but a `src/http/routes.rs` added tomorrow must not be able
        // to register handlers the census cannot see. Strictly stricter.
        fn rust_sources(dir: &Path, into: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).expect("dcentaxe/src must be readable") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    rust_sources(&path, into);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    into.push(path);
                }
            }
        }

        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dcentaxe/src");
        let mut paths: Vec<PathBuf> = Vec::new();
        rust_sources(&src_dir, &mut paths);
        paths.sort();

        let mut found: BTreeSet<String> = BTreeSet::new();
        let mut counts: Vec<(String, usize)> = Vec::new();
        for path in &paths {
            let rel = path
                .strip_prefix(&src_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let raw = fs::read_to_string(path).unwrap_or_default();
            let code = strip_comments(&raw.replace("\r\n", "\n"));
            let n = code.matches(".fn_handler(").count();
            if n > 0 {
                found.insert(rel.clone());
                counts.push((rel, n));
            }
        }

        // Four of these are the files `registered_handler_count_under_cap` reads;
        // the fifth (`provisioning.rs`) owns the captive-portal server, which has
        // its own `Configuration::default()` cap of 32 and never spends a slot of
        // MAX_URI_HANDLERS. `tools/count_handlers.py` censuses all five.
        let expected: BTreeSet<String> = [
            "api.rs",
            "auth.rs",
            "dashboard.rs",
            "mcp.rs",
            "provisioning.rs",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        assert_eq!(
            found, expected,
            "a source file outside the censused set registers URI handlers \
             (per-file code-level `.fn_handler(` counts: {counts:?}). The \
             invocation-aware guard above reads only api/auth/dashboard/mcp, and \
             `tools/count_handlers.py` cannot attribute a site whose enclosing fn \
             is unreachable from a wiring root it knows — so the census would \
             silently UNDER-count. Extend BOTH censuses (add the main.rs wiring \
             needle to SERVERS in count_handlers.py), re-run \
             `python tools/count_handlers.py`, then update \
             REGISTERED_HANDLER_ESTIMATE and the accounting table in main.rs."
        );

        // The census this lane pins must also stay self-consistent on the text
        // side: main.rs must contain NO code-level `.fn_handler(` (its
        // occurrences are documentation), or the accounting table's "text sites"
        // column is wrong.
        let main_raw =
            fs::read_to_string(src_dir.join("main.rs")).expect("main.rs must be readable");
        let main_code = strip_comments(&main_raw.replace("\r\n", "\n"));
        assert_eq!(
            main_code.matches(".fn_handler(").count(),
            0,
            "main.rs must not register URI handlers directly; its `.fn_handler(` \
             occurrences are comment text only"
        );
    }

    // ── CRITIC HELD-OUT (P1-I3 round 2): no two registrations share a (method,
    //    URI) pair on the main server — a gap neither guard above closes ───────
    //
    // `registered_handler_count_under_cap` and `only_the_five_known_files_
    // register_uri_handlers` both guard COUNTS and the SET OF FILES that
    // register handlers. Neither guards URI UNIQUENESS. `tools/count_handlers.py`
    // actually computes this (the `dup` map in its `render()`, printed as
    // "Duplicate (server, method, URI) registrations - the second one FAILS at
    // boot") but that check is DISPLAY-ONLY: it is built in `render()`, never
    // added to `result["problems"]`, so it does not affect `--json`, does not
    // affect the exit code, and is invisible to `measure_image.{sh,ps1}` and to
    // every host-side gate in this crate.
    //
    // A lane could swap one literal URI for a duplicate of an existing one
    // (e.g. change the "/api/achievements" GET at api.rs to "/api/presets", the
    // same method+path already registered at api.rs) and:
    //   - `registered_handler_count_under_cap` stays green: the TOTAL is still
    //     76, because a literal-for-literal swap changes no count.
    //   - `only_the_five_known_files_register_uri_handlers` stays green: the
    //     FILE SET is unchanged.
    //   - `tools/count_handlers.py --quiet` exits 0: the "Duplicate ..." line
    //     is printed but is not a `problems` entry.
    // `httpd_register_uri_handler()` fails on the SECOND registration of an
    // identical (method, path) pair, which panics the `.expect(...)`/
    // `.unwrap_or_else(...)` at every call site in this codebase — a boot-loop
    // class defect none of the existing backpressure would catch.
    //
    // This positively pins TODAY'S real state (no duplicates exist), so it is a
    // held-out regression guard, not a demonstration. Verified live during
    // round-2 critique: duplicating a literal api.rs URI made THIS test fail
    // while `registered_handler_count_under_cap` and
    // `only_the_five_known_files_register_uri_handlers` both stayed green.
    //
    // Method-aware, not just URI-aware: this codebase legitimately reuses a
    // path across methods (GET/OPTIONS/PATCH/POST all serve `/api/system`), so
    // only an EXACT (method, uri) collision is a defect. The four registration
    // shapes on the main server are:
    //   - direct literal `.fn_handler("...", Method::X, ...)` sites — the
    //     method is read from the site itself.
    //   - the 3 api.rs helper closures (`register`, `register_ota_get`,
    //     `register_manifest`) and dashboard.rs's `register_static` helper fn —
    //     all four ALWAYS use `Method::Get` internally (source-verified), and
    //     each call site's URI is the first (or, for `register_static`, only
    //     literal) argument to the call.
    #[test]
    fn no_two_registrations_share_the_same_method_and_uri() {
        use std::collections::BTreeMap;

        const DASHBOARD_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/dashboard.rs"
        ));
        const AUTH_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/auth.rs"
        ));
        const MCP_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/mcp.rs"
        ));

        /// Blank out `//` and `/* */` comments so a URI mentioned only in prose
        /// (e.g. this very test's doc-comment, or main.rs's accounting table)
        /// can never be mistaken for a live registration. Byte-for-byte the same
        /// algorithm `only_the_five_known_files_register_uri_handlers` uses
        /// above, duplicated locally so this test has no dependency on that
        /// one's internals.
        fn strip_comments(src: &str) -> String {
            let b: Vec<char> = src.chars().collect();
            let mut out = b.clone();
            let n = b.len();
            let mut i = 0;
            while i < n {
                if b[i] == '/' && i + 1 < n && b[i + 1] == '/' {
                    let mut j = i;
                    while j < n && b[j] != '\n' {
                        out[j] = ' ';
                        j += 1;
                    }
                    i = j;
                } else if b[i] == '/' && i + 1 < n && b[i + 1] == '*' {
                    let mut depth = 1usize;
                    let mut j = i + 2;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    while j < n && depth > 0 {
                        if b[j] == '/' && j + 1 < n && b[j + 1] == '*' {
                            depth += 1;
                            out[j] = ' ';
                            out[j + 1] = ' ';
                            j += 2;
                        } else if b[j] == '*' && j + 1 < n && b[j + 1] == '/' {
                            depth -= 1;
                            out[j] = ' ';
                            out[j + 1] = ' ';
                            j += 2;
                        } else {
                            if b[j] != '\n' {
                                out[j] = ' ';
                            }
                            j += 1;
                        }
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            out.into_iter().collect()
        }

        /// (method, uri) for every direct `.fn_handler("...", Method::X, ...)`
        /// site. A site whose first argument is NOT a `"` literal (a helper's
        /// internal definition, e.g. `register_static`'s own body) is skipped —
        /// its call sites are covered by `helper_call_uris` below.
        fn direct_pairs(src: &str) -> Vec<(String, String)> {
            let mut out = Vec::new();
            let needle = ".fn_handler(";
            let mut idx = 0usize;
            while let Some(pos) = src[idx..].find(needle) {
                let abs = idx + pos;
                let after = &src[abs + needle.len()..];
                let trimmed = after.trim_start();
                if let Some(rest) = trimmed.strip_prefix('"') {
                    if let Some(endq) = rest.find('"') {
                        let uri = rest[..endq].to_string();
                        let after_uri = &rest[endq + 1..];
                        if let Some(mpos) = after_uri.find("Method::") {
                            let mrest = &after_uri[mpos + "Method::".len()..];
                            let mend = mrest
                                .find(|c: char| !c.is_ascii_alphanumeric())
                                .unwrap_or(mrest.len());
                            out.push((mrest[..mend].to_string(), uri));
                        }
                    }
                }
                idx = abs + needle.len();
            }
            out
        }

        /// The first `"..."` literal found within `window` bytes after `pos` —
        /// correct for every helper call shape in this codebase because exactly
        /// ONE argument in each call (the URI) is ever a bare string literal,
        /// regardless of argument position or whether the call spans multiple
        /// lines (`register_static`'s calls do, when rustfmt wraps them).
        fn first_literal_after(src: &str, pos: usize, window: usize) -> Option<String> {
            let end = (pos + window).min(src.len());
            let slice = &src[pos..end];
            let sq = slice.find('"')?;
            let rest = &slice[sq + 1..];
            let eq = rest.find('"')?;
            Some(rest[..eq].to_string())
        }

        /// Every call-site URI for `helper_name(`, excluding its OWN `fn
        /// helper_name(` definition line (a call is never line-prefixed `fn `).
        /// `let helper_name = |` closure definitions do not contain the
        /// substring `helper_name(` at all (there is a ` = |` between the name
        /// and the args), so they need no separate exclusion.
        fn helper_call_uris(src: &str, helper_name: &str) -> Vec<String> {
            let mut out = Vec::new();
            let needle = format!("{helper_name}(");
            let mut idx = 0usize;
            while let Some(pos) = src[idx..].find(&needle) {
                let abs = idx + pos;
                let line_start = src[..abs].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let prefix = src[line_start..abs].trim_start();
                let is_def = prefix.starts_with("fn ") || prefix.starts_with("pub fn ");
                if !is_def {
                    if let Some(u) = first_literal_after(src, abs + needle.len(), 400) {
                        out.push(u);
                    }
                }
                idx = abs + needle.len();
            }
            out
        }

        let api = strip_comments(&API_RS.replace("\r\n", "\n"));
        let dashboard = strip_comments(&DASHBOARD_RS.replace("\r\n", "\n"));
        let auth = strip_comments(&AUTH_RS.replace("\r\n", "\n"));
        let mcp = strip_comments(&MCP_RS.replace("\r\n", "\n"));

        let mut pairs: Vec<(&'static str, String, String)> = Vec::new();
        for (m, u) in direct_pairs(&api) {
            pairs.push(("api.rs", m, u));
        }
        for (m, u) in direct_pairs(&auth) {
            pairs.push(("auth.rs", m, u));
        }
        for (m, u) in direct_pairs(&dashboard) {
            pairs.push(("dashboard.rs", m, u));
        }
        for (m, u) in direct_pairs(&mcp) {
            pairs.push(("mcp.rs", m, u));
        }
        // All four helpers register with a hardcoded Method::Get internally
        // (source-verified: `register`, `register_ota_get`, `register_manifest`
        // in api.rs; `register_static` in dashboard.rs).
        for u in helper_call_uris(&api, "register") {
            pairs.push(("api.rs", "Get".to_string(), u));
        }
        for u in helper_call_uris(&api, "register_ota_get") {
            pairs.push(("api.rs", "Get".to_string(), u));
        }
        for u in helper_call_uris(&api, "register_manifest") {
            pairs.push(("api.rs", "Get".to_string(), u));
        }
        for u in helper_call_uris(&dashboard, "register_static") {
            pairs.push(("dashboard.rs", "Get".to_string(), u));
        }

        // This reconstruction must land on the same total the invocation-aware
        // guard above measures, or the two disagree about what "76" counts.
        assert_eq!(
            pairs.len(),
            76,
            "held-out (method, uri) reconstruction found {} registrations, not \
             76 — it has drifted from `registered_handler_count_under_cap`'s \
             count and must be re-synced, not silently trusted",
            pairs.len()
        );

        let mut seen: BTreeMap<(String, String), Vec<&'static str>> = BTreeMap::new();
        for (file, method, uri) in &pairs {
            seen.entry((method.clone(), uri.clone()))
                .or_default()
                .push(file);
        }
        let dups: Vec<_> = seen.iter().filter(|(_, files)| files.len() > 1).collect();
        assert!(
            dups.is_empty(),
            "duplicate (method, URI) registration(s) on the main server - the \
             SECOND `httpd_register_uri_handler()` call for an identical \
             (method, path) pair panics its `.expect(...)`/`.unwrap_or_else(...)` \
             at boot, and NEITHER `registered_handler_count_under_cap` (counts \
             are unaffected by a literal-for-literal URI swap) NOR \
             `only_the_five_known_files_register_uri_handlers` (the file set is \
             unaffected) would catch it: {dups:?}. \
             `tools/count_handlers.py`'s own \"Duplicate (server, method, URI)\" \
             line does not fail its exit code either - this is Rust-side \
             backpressure for a gap that exists on both sides of the counter."
        );
    }

    // ── P1-I3 (round 2): ONE number for the handler budget, everywhere ────────
    //
    // Round 1 shipped FOUR different values for a single budget — 71, 72, 73 and
    // 76 — spread across this file's comments/assert messages and
    // `DCENT_OS_ESP/. Three of them were stale by more than the
    // 8-slot tripwire margin, and a reader who trusted the wrong one would size a
    // new feature against headroom that does not exist.
    //
    // This guard is written WITHOUT any stale literal in its own source, because
    // it reads its own file: spelling a stale figure out here (as the first
    // draft of this very comment did) makes the guard match ITSELF and it can
    // never go green — the `include_str!` self-match trap. Every needle is BUILT
    // with `format!`, and the scan reads whole numbers rather than substrings so
    // `6` can never be found inside `76`.
    #[test]
    fn handler_budget_is_stated_as_one_number_everywhere() {
        const LIB_RS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        const CLAUDE_MD: &str =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../"));

        // The one true number, and the only other value this file may mention:
        // `+1 handler would push it to 77`, which is a cost statement, not a claim
        // about today.
        const MEASURED: usize = 76;
        const PLUS_ONE: usize = MEASURED + 1;
        const CAP: usize = 96;
        const EST: &str = "REGISTERED_HANDLER_ESTIMATE";

        assert!(
            MAIN_RS.contains(&format!("const {EST}: usize = {MEASURED};")),
            "the measured total must be the const in main.rs"
        );

        // Every `<n>/<cap>` in this file must be a WHOLE number equal to the
        // measured total (or that total plus one, when the sentence is costing a
        // hypothetical extra handler). Reading the run of digits that ends at the
        // slash is what keeps `6` from being "found" inside `76`.
        let of_cap = format!("/{CAP}");
        let bytes = LIB_RS.as_bytes();
        let mut at = 0usize;
        while let Some(hit) = LIB_RS[at..].find(&of_cap) {
            let slash = at + hit;
            let mut start = slash;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < slash {
                let found = &LIB_RS[start..slash];
                let value: usize = found.parse().expect("run of ascii digits");
                assert!(
                    value == MEASURED || value == PLUS_ONE,
                    "stale handler-budget figure `{found}/{CAP}` in \
                     dcentaxe-core/src/lib.rs — the measured total is {MEASURED}/{CAP} \
                     (and {PLUS_ONE}/{CAP} when costing one more handler). Re-run \
                     `python tools/count_handlers.py` and state ONE number."
                );
            }
            at = slash + of_cap.len();
        }

        // Same for prose of the form `REGISTERED_HANDLER_ESTIMATE <n>`. The const
        // declaration itself is `REGISTERED_HANDLER_ESTIMATE: usize = <n>;`, which
        // has a colon after the name and so is not matched here; it is pinned
        // exactly by the assertion above and by
        // `registered_handler_count_under_cap`.
        let est_space = format!("{EST} ");
        let mut at = 0usize;
        while let Some(hit) = LIB_RS[at..].find(&est_space) {
            let after = at + hit + est_space.len();
            let digits: String = LIB_RS[after..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                let value: usize = digits.parse().expect("run of ascii digits");
                assert!(
                    value == MEASURED || value == PLUS_ONE,
                    "stale handler-budget figure `{EST} {digits}` in \
                     dcentaxe-core/src/lib.rs — the measured total is {MEASURED}. \
                     Re-run `python tools/count_handlers.py` and state ONE number."
                );
            }
            at = after;
        }

        // DCENT_OS_ESP/ states the same budget in prose. Read the
        // number back out of the bullet rather than pattern-matching a phrase, so
        // a reworded bullet still has to carry the right figure.
        let marker = format!("MAX_URI_HANDLERS={CAP}");
        let at = CLAUDE_MD.find(&marker).unwrap_or_else(|| {
            panic!(" must state the embedded-route budget as `{marker}`")
        });
        let window = safe_window(CLAUDE_MD, at, 240);
        let cur = "(currently ";
        let start = window
            .find(cur)
            .expect("'s embedded-route bullet must say `(currently <n>`");
        let digits: String = window[start + cur.len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        assert_eq!(
            digits,
            MEASURED.to_string(),
            "'s embedded-route budget bullet says `(currently {digits})` but the \
             measured invocation-aware total is {MEASURED} — `python tools/count_handlers.py` \
             is the source of that number"
        );
    }

    // ── MAINAPI-6: the dead asic_model_name duplicate is gone ─────────────────
    #[test]
    fn dead_asic_model_name_removed() {
        assert!(
            !API_RS.contains("fn asic_model_name"),
            "MAINAPI-6: the dead board->ASIC duplicate fn asic_model_name must be removed"
        );
    }

    // ── MAINAPI-3: every JSON handler accumulates the full body ───────────────
    #[test]
    fn no_single_read_truncation_in_api() {
        assert_eq!(
            API_RS.matches("req.read(&mut body).unwrap_or(0)").count(),
            0,
            "MAINAPI-3: no handler may single-read a body (truncation on multi-segment POST)"
        );
        // read_full_body fn def + >= 8 call sites = >= 9 occurrences.
        assert!(
            API_RS.matches("read_full_body(").count() >= 9,
            "MAINAPI-3: read_full_body must back at least 8 body-reading handlers"
        );
    }

    // ── MAINAPI-4: explicit target_temp=0 is rejected, manual selectors kept ──
    #[test]
    fn ambiguous_zero_target_temp_is_rejected() {
        assert!(
            API_RS.contains("target_temp=0 is ambiguous"),
            "MAINAPI-4: an explicit target_temp=0 must be rejected with a clear 400 message"
        );
        // The unambiguous manual selectors still set fan_target_temp_c = 0.
        assert!(API_RS.contains("\"manual\" => config.fan_target_temp_c = 0"));
        assert!(API_RS.contains("config.fan_target_temp_c = 0; // manual mode"));
        // apply_config_updates now returns a Result so the 400 can propagate.
        assert!(API_RS.contains(
            "fn apply_config_updates(state: &SharedState, body: &[u8]) -> Result<(), String>"
        ));
    }

    // ── AOTA-6: unsigned OTA surfaces + optionally pins the payload SHA-256 ────
    #[test]
    fn unsigned_ota_surfaces_and_pins_sha() {
        assert!(
            API_RS.contains("X-DCENT-Unsigned-SHA256"),
            "AOTA-6: an optional out-of-band unsigned-SHA pin header must be read"
        );
        assert!(
            API_RS.contains("Unsigned OTA SHA256 mismatch"),
            "AOTA-6: an unsigned-SHA mismatch must abort the OTA"
        );
        // mismatch routes through esp_ota_abort.
        let m = API_RS
            .find("Unsigned OTA SHA256 mismatch")
            .expect("mismatch message present");
        let mut win_start = m.saturating_sub(400);
        while win_start < m && !API_RS.is_char_boundary(win_start) {
            win_start += 1;
        }
        let region = &API_RS[win_start..m];
        assert!(
            region.contains("esp_ota_abort"),
            "AOTA-6: unsigned-SHA mismatch must call esp_ota_abort"
        );
        assert!(
            API_RS.contains("\"payloadSha256\": payload_sha256"),
            "AOTA-6: the success JSON must surface payloadSha256"
        );
        assert!(
            API_RS.contains("OTA accepted in UNSIGNED mode"),
            "AOTA-6: unsigned mode must emit a loud audit warning"
        );
    }

    // ── SV2-3: V2 arm threads a fallback + defines a failover threshold ───────
    #[test]
    fn sv2_fallback_failover_is_wired() {
        assert!(
            MAIN_RS.contains("const SV2_FAILOVER_AFTER_N: u32 = 5;"),
            "SV2-3: a named failover threshold must exist"
        );
        // The V2 arm passes a fallback into run_sv2_client_thread (no longer warn-and-drop).
        // Match the V2 arm in spawn_stratum_thread specifically (the one whose
        // body runs run_sv2_client_thread), not the earlier protocol == V2 checks.
        // Checkout-invariant: this literal spans a line break, so normalise CRLF first
        // (the guard failed on every CRLF worktree and on main after a merge rewrote main.rs).
        let main_rs = MAIN_RS.replace("\r\n", "\n");
        let arm = main_rs
            .find("run_sv2_client_thread(\n                    config,")
            .expect("spawn_stratum_thread V2 arm must call run_sv2_client_thread");
        let region = safe_window(&main_rs, arm, 400);
        assert!(
            region.contains("fallback_pool,"),
            "SV2-3: the V2 arm must thread fallback_pool into run_sv2_client_thread"
        );
        assert!(
            MAIN_RS.contains("fallback_pool: Option<dcentaxe_stratum::StratumConfig>,"),
            "SV2-3: run_sv2_client_thread must accept a fallback_pool param"
        );
        // The failover branch references both the threshold and the fallback.
        assert!(
            MAIN_RS.contains("sv2_consecutive_failures >= SV2_FAILOVER_AFTER_N"),
            "SV2-3: failover must trigger after SV2_FAILOVER_AFTER_N failures"
        );
        assert!(
            MAIN_RS.contains("sv2 failover to fallback"),
            "SV2-3: the failover must surface a status string"
        );
    }

    // ESP-5: SV2 is not live-proven; every API surface that advertises it must
    // also expose the experimental maturity flag.
    #[test]
    fn sv2_experimental_maturity_is_surfaced() {
        assert!(
            API_RS.contains("\"stratumV2Available\": cfg!(feature = \"stratum-v2\")"),
            "/api/system must keep the build-time SV2 availability flag"
        );
        assert!(
            API_RS.contains("\"stratumV2Experimental\": true"),
            "ESP-5: /api/system must surface that SV2 remains experimental"
        );
        assert!(
            API_RS.contains("stratum_v2_experimental: true"),
            "ESP-5: /api/system/info must populate stratumV2Experimental"
        );
    }

    // ── HALT-5: emc_internal_temp boards label chip_temp as ambient proxy ─────
    #[test]
    fn emc_internal_temp_labeled_as_ambient_proxy() {
        assert!(
            MAIN_RS.contains("telem.chip_temp_is_ambient_proxy = board_config.emc_internal_temp"),
            "HALT-5: chip_temp must be labeled a board-ambient proxy on emc_internal_temp boards"
        );
        assert!(
            SHARED_RS.contains("pub chip_temp_is_ambient_proxy: bool"),
            "HALT-5: telemetry must carry the ambient-proxy label field"
        );
        // No threshold was lowered (regression guard).
        assert!(MAIN_RS.contains("const EMERGENCY_TEMP_C: f32 = 105.0;"));
        assert!(MAIN_RS.contains("const WARNING_TEMP_C: f32 = 90.0;"));
    }

    // ── MAINAPI-8: the canonical lock order is documented in shared.rs ─────────
    #[test]
    fn canonical_lock_order_is_documented() {
        assert!(
            SHARED_RS.contains("CANONICAL LOCK ORDER"),
            "MAINAPI-8: shared.rs must document the canonical lock acquisition order"
        );
    }
}

/// DCENT design-language (Phase-2 axe contract) structural guards.
///
/// `dashboard.rs` lives in the `dcentaxe` BINARY crate and embeds the served
/// dashboard as one giant inline HTML/CSS/JS string — it pulls in esp-idf at
/// module scope and CANNOT host-compile, so (exactly like `safety_guards`,
/// `tps546_guard_wiring`, and `mainapi_guards`) these pin the Phase-2 axe
/// design-language CONTRACT against the source TEXT via `include_str!`. This is
/// the host-testable verification + durability mechanism for the
/// un-host-compilable `dashboard.rs`: it is the only place CI can prove the
/// accent / autotuner-mode / truth-ladder / token contract has not regressed.
///
/// Assertions are deliberately whitespace-robust: HTML/CSS/JS minification or a
/// reformat must not flip a guard. Multi-token display strings are matched after
/// collapsing internal whitespace; single-token swatches are matched
/// case-insensitively where the contract is color-value (not label) oriented.
#[cfg(test)]
mod dcent_design_language_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const TOKENS_CSS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/tokens.css"
    ));
    // The TERM-7 glossary string-table is hosted inline in framework.js (the
    // already-served, handler-free <script src> #1). Pin it from source TEXT —
    // framework.js, like dashboard.rs, embeds in the esp-idf binary crate and
    // cannot host-compile, so this include_str! is the only place CI proves the
    // glossary-equivalent + its canonical spellings + handler-free host have not
    // regressed.
    const FRAMEWORK_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/framework.js"
    ));
    // The served (register_static'd + <script src>'d) label-bearing components
    // that the emission wired to pull labels from window.GLOSSARY. stats.js is
    // intentionally EXCLUDED — it is an orphan (not served), so its dormant
    // glossary edit is source-consistency only and is not a contract surface.
    const CORE_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/core.js"
    ));
    const ASIC_CHIPS_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/asic-chips.js"
    ));
    const BLOCK_TILE_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/block-tile.js"
    ));

    /// Collapse every run of ASCII whitespace to a single space so a reflow /
    /// minify of the embedded HTML/CSS/JS cannot break a multi-token match.
    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── (1) accent = DCENT amber #FAA500; #F7931A is opt-in ONLY ──────────────
    // The DCENT primary accent is amber #FAA500. Bitcoin-orange #F7931A is the
    // OPT-IN `--orange-bitcoin` alias / theme-picker swatch ONLY; it must never
    // be the DEFAULT value of `--accent` / `--orange`. A regression that re-set
    // the inline accent slots to #F7931A would not be caught by host compilation.
    #[test]
    fn accent_is_dcent_amber_not_bitcoin_orange_default() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The amber accent is present (case-insensitive: the hex may be authored
        // upper- or lower-case; the contract is the color value, not its casing).
        assert!(
            flat.to_ascii_uppercase().contains("#FAA500"),
            "dashboard.rs must define the DCENT amber accent #FAA500"
        );
        // The inline `--accent` and `--orange` slots default to amber, NOT to
        // Bitcoin-orange. Match the assignment with collapsed whitespace so a
        // reflow of the `:root{...}` block can't dodge the guard.
        let flat_up = flat.to_ascii_uppercase();
        assert!(
            flat_up.contains("--ACCENT:#FAA500") || flat_up.contains("--ACCENT: #FAA500"),
            "the inline --accent slot must default to amber #FAA500"
        );
        assert!(
            flat_up.contains("--ORANGE:#FAA500") || flat_up.contains("--ORANGE: #FAA500"),
            "the inline --orange slot must default to amber #FAA500"
        );
        assert!(
            !flat_up.contains("--ACCENT:#F7931A") && !flat_up.contains("--ACCENT: #F7931A"),
            "regression: the default --accent must NOT be Bitcoin-orange #F7931A"
        );
        assert!(
            !flat_up.contains("--ORANGE:#F7931A") && !flat_up.contains("--ORANGE: #F7931A"),
            "regression: the default --orange must NOT be Bitcoin-orange #F7931A"
        );
        // Every #F7931A occurrence must be the OPT-IN path: either the
        // `--orange-bitcoin` alias or a theme-picker swatch wired to setAccent().
        // Pin that the only legitimate alias exists and that #F7931A is never the
        // accent default (above). We count occurrences case-insensitively and
        // assert each is opt-in by requiring the alias declaration to be present.
        assert!(
            flat_up.contains("--ORANGE-BITCOIN:#F7931A")
                || flat_up.contains("--ORANGE-BITCOIN: #F7931A"),
            "#F7931A must survive only as the opt-in --orange-bitcoin alias"
        );
    }

    // ── (2) the 4 canonical autotuner mode display names are present ──────────
    // The autotuner exposes exactly four user-selectable modes. Their DISPLAY
    // names (the <option> labels) are the contract surface; a rename to a
    // non-canonical label would silently break parity with the OS lane.
    #[test]
    fn four_canonical_autotuner_mode_names_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        for name in [
            "Max Hashrate",
            "Best Efficiency",
            "Target Watts",
            "Target Temp",
        ] {
            assert!(
                flat.contains(name),
                "autotuner mode display name `{name}` missing from dashboard.rs"
            );
        }
        // And the JS mode-description map keys (the machine values behind those
        // labels) stay in lock-step so the labels are not orphaned.
        for key in [
            "max_hashrate",
            "best_efficiency",
            "target_watts",
            "target_temp",
        ] {
            assert!(
                flat.contains(key),
                "autotuner mode value `{key}` missing — display label/value pair drifted"
            );
        }
    }

    // ── (3) truth-ladder: Ready / Standby present, overloaded `Enabled` gone ──
    // The mining state truth-ladder rung-2 was renamed from the OVERLOADED
    // `Enabled` (which RALPH Wave 9D9 used for "permitted but zero hashrate") to
    // the unambiguous `Ready` (mining permitted, awaiting hashrate) /
    // `Standby` (mining disabled) split. Pin that the new state-labels exist and
    // that the old overloaded DISPLAY label is gone. NOTE: we target the
    // displayed state-LABEL strings, not the legacy `data-state="enabled"` CSS
    // class alias (which is a styling hook, not a label) and not the unrelated
    // `Enable Autotuner` checkbox text.
    #[test]
    fn truth_ladder_ready_standby_present_old_enabled_label_gone() {
        let flat = collapse_ws(DASHBOARD_RS);
        // Both casings of the new rung-2 labels appear (hero badge `Ready`/`Standby`
        // + topbar/log pill `READY`/`STANDBY`).
        assert!(
            flat.contains("'Ready'") || flat.contains("\"Ready\"") || flat.contains(">Ready<"),
            "truth-ladder must surface the `Ready` state-label"
        );
        assert!(
            flat.contains("'READY'") || flat.contains("\"READY\"") || flat.contains(">READY<"),
            "truth-ladder must surface the uppercase `READY` pill label"
        );
        assert!(
            flat.contains("'Standby'")
                || flat.contains("\"Standby\"")
                || flat.contains(">Standby<"),
            "truth-ladder must surface the `Standby` state-label"
        );
        assert!(
            flat.contains("'STANDBY'")
                || flat.contains("\"STANDBY\"")
                || flat.contains(">STANDBY<"),
            "truth-ladder must surface the uppercase `STANDBY` pill label"
        );
        // The OLD overloaded rung-2 DISPLAY label must be gone. The state-label is
        // emitted as a quoted JS string literal (e.g. `'ENABLED'`) or rendered
        // text (`>Enabled<`); assert none of those forms survive. The legacy
        // `data-state="enabled"` CSS selector (a class alias) and the
        // `Enable Autotuner` checkbox are intentionally NOT matched by these forms.
        for forbidden in [
            "'ENABLED'",
            "\"ENABLED\"",
            ">ENABLED<",
            "'Enabled'",
            "\"Enabled\"",
            ">Enabled<",
        ] {
            assert!(
                !flat.contains(forbidden),
                "the old overloaded rung-2 state-label `{forbidden}` must be gone (use Ready/Standby)"
            );
        }
    }

    // ── (4) tokens.css: canonical accent + void surface ───────────────────────
    // The design-token source-of-truth must declare the canonical `--accent`
    // amber and the `--bg-void` deepest surface. Robust to whitespace around the
    // `:` and to the alias `var(--s-void)` form (the void value lives on
    // `--s-void: #070710`, with `--bg-void` aliasing it).
    #[test]
    fn tokens_css_has_canonical_accent_and_void() {
        let flat = collapse_ws(TOKENS_CSS);
        let flat_up = flat.to_ascii_uppercase();
        // --accent: #FAA500  (whitespace-robust, case-insensitive on the hex).
        assert!(
            flat_up.contains("--ACCENT:#FAA500") || flat_up.contains("--ACCENT: #FAA500"),
            "tokens.css must declare --accent #FAA500"
        );
        // --bg-void must exist and resolve to #070710 — either declared directly
        // or aliased onto --s-void (whose value is #070710). Accept both forms.
        assert!(
            flat.contains("--bg-void:"),
            "tokens.css must declare the --bg-void surface token"
        );
        let bg_void_direct =
            flat_up.contains("--BG-VOID:#070710") || flat_up.contains("--BG-VOID: #070710");
        let bg_void_aliased = (flat.contains("--bg-void: var(--s-void)")
            || flat.contains("--bg-void:var(--s-void)"))
            && (flat_up.contains("--S-VOID:#070710") || flat_up.contains("--S-VOID: #070710"));
        assert!(
            bg_void_direct || bg_void_aliased,
            "tokens.css --bg-void must resolve to #070710 (direct or via --s-void alias)"
        );
    }

    // ── (5) tokens.css: EVERY [shared] role resolves to its canonical value ────
    // The drift VALIDATOR half of the contract's "author-once / emit-twice /
    // validate" mechanism (token-contract.md §0 / UIVIS-RENDER-1). This parses
    // the axe tokens.css emission and asserts every [shared]-VALUE-converged role
    // equals the canonical value from the contract. It generalizes the by-hand
    // alias-resolution the void test above does into a reusable 1-level resolver.
    //
    // SOURCE OF TRUTH: docs/design-system/DCENT_DESIGN_LANGUAGE/token-contract.md
    // §2/§3/§5/§8. The canonical [shared]-VALUE-converged table on the axe side is:
    //     --accent        #FAA500   (§2 primary brand)
    //     --accent-deep   #FA6700   (§2 ember companion; via --ember alias)
    //     --accent-hover  #FFC94D   (§2 amber lift; via --amber alias)
    //     --orange-bitcoin#F7931A   (§2 opt-in legacy BTC alias — NEVER the default)
    //     --bg-void       #070710   (§3 deepest floor / family glue; via --s-void)
    //     --tgreen        #00FF41   (§5/§8 reserved terminal-green; byte-identical)
    //
    // DELIBERATELY NOT value-validated on axe (the contract-faithful asymmetry):
    // the STATUS hues (--green #34d399 / --yellow #fbbf24 / --red #f87171 /
    // --cyan #22d3ee) are `[shared]-ROLE / per-project-VALUE` (§5 — axe's softer
    // Tailwind-400 family vs OS's saturated table-tuned set), and axe has NO
    // --sphere-mid (§9 forbids it here). Value-asserting those would falsely fail.
    // OS owns the canonical status/sphere VALUES, so the OS validator checks them.

    /// Resolve a `--<role>` value from the whitespace-collapsed UPPERCASED CSS,
    /// following EXACTLY ONE level of `VAR(--OTHER)` indirection (the only depth
    /// present in the axe emission: --accent-deep→--ember, --accent-hover→--amber,
    /// --bg-void→--s-void; --accent/--orange-bitcoin/--tgreen are direct).
    ///
    /// Returns the value token (up to `;`), whitespace already collapsed and
    /// uppercased. 1-LEVEL LIMIT (fail-closed): a future 2-level alias returns the
    /// `VAR(--X)` literal and the equality assert fails loudly — not a silent pass.
    fn css_role_value(flat_up: &str, role_up: &str) -> Option<String> {
        let raw = read_role(flat_up, role_up)?;
        // `VAR(--OTHER)` → resolve one level.
        if let Some(rest) = raw.strip_prefix("VAR(") {
            if let Some(inner) = rest.strip_suffix(')') {
                let inner = inner.trim();
                if inner.starts_with("--") {
                    if let Some(v) = read_role(flat_up, inner) {
                        return Some(v);
                    }
                }
            }
        }
        Some(raw)
    }

    /// Read a single `--ROLE:VALUE;` declaration from the collapsed-uppercase CSS.
    /// `flat_up` has internal whitespace collapsed to single spaces (collapse_ws)
    /// then uppercased; we additionally strip spaces around the value so
    /// `--ACCENT: #FAA500` and `--ACCENT:#FAA500` compare identically.
    fn read_role(flat_up: &str, role_up: &str) -> Option<String> {
        // Find `--ROLE` followed (after optional space) by ':'.
        let needle = role_up;
        let mut search_from = 0usize;
        while let Some(idx) = flat_up[search_from..].find(needle) {
            let start = search_from + idx;
            let after = &flat_up[start + needle.len()..];
            // The char immediately after the role name must be ':' or a space then
            // ':', AND the char BEFORE must not be a `-`/alnum (so `--ACCENT` does
            // not also match inside `--ACCENT-DEEP`). collapse_ws guarantees single
            // spaces; role names use only [A-Z0-9-].
            let prev_ok = start == 0
                || !flat_up.as_bytes()[start - 1].is_ascii_alphanumeric()
                    && flat_up.as_bytes()[start - 1] != b'-';
            let after_trim = after.trim_start();
            if prev_ok && after_trim.starts_with(':') {
                let val = after_trim[1..].trim_start();
                if let Some(end) = val.find(';') {
                    return Some(val[..end].replace(' ', ""));
                }
            }
            search_from = start + needle.len();
        }
        None
    }

    #[test]
    fn tokens_css_shared_roles_match_contract() {
        let flat_up = collapse_ws(TOKENS_CSS).to_ascii_uppercase();
        // Each tuple: (role, canonical value, contract section) — all UPPERCASE.
        let shared: &[(&str, &str, &str)] = &[
            ("--ACCENT", "#FAA500", "§2 primary brand"),
            (
                "--ACCENT-DEEP",
                "#FA6700",
                "§2 ember companion (via --ember)",
            ),
            ("--ACCENT-HOVER", "#FFC94D", "§2 amber lift (via --amber)"),
            (
                "--ORANGE-BITCOIN",
                "#F7931A",
                "§2 opt-in BTC alias (never default)",
            ),
            (
                "--BG-VOID",
                "#070710",
                "§3 floor / family glue (via --s-void)",
            ),
            ("--TGREEN", "#00FF41", "§5/§8 reserved terminal-green"),
        ];
        for (role, want, section) in shared {
            let got = css_role_value(&flat_up, role).unwrap_or_else(|| {
                panic!("tokens.css is missing the [shared] role {role} ({section})")
            });
            assert_eq!(
                &got, want,
                "tokens.css {role} must equal canonical {want} ({section}, \
                 token-contract.md §0/§2/§3/§5/§8)"
            );
        }
        // And the contract-faithful asymmetry holds: the per-project STATUS hues
        // are PRESENT (role names exist) but are NOT the OS-canonical values — so
        // they are correctly [shared]-ROLE / per-project-VALUE, never cross-checked.
        // (Pin the axe Tailwind-400 family stays distinct from OS's saturated set.)
        assert_eq!(
            css_role_value(&flat_up, "--GREEN").as_deref(),
            Some("#34D399"),
            "axe --green stays the per-project Tailwind-400 value (§5 shared-role/per-project-value)"
        );
        assert!(
            css_role_value(&flat_up, "--SPHERE-MID").is_none(),
            "axe must NOT declare --sphere-mid (§9 forbids it; it is OS-only)"
        );
    }

    // ── (6) TERM-7: window.GLOSSARY string-table present + handler-free host ───
    // The axe glossary-equivalent (terminology-lexicon §0/§11) is hosted INLINE
    // in framework.js (the already-served <script src> #1), exposed as
    // `window.GLOSSARY`, so the ~scattered canonical labels are single-sourced
    // and every component IIFE + the inline dashboard.rs JS can resolve them.
    // The host MUST stay handler-free: framework.js is loaded via the existing
    // `register_static(server, "/dashboard/framework.js", ...)` — a regression
    // that split the table into a NEW dashboard/glossary.js would cost +1
    // register_static (76/96 today) and force bumping REGISTERED_HANDLER_ESTIMATE.
    #[test]
    fn term7_glossary_table_present_and_handler_free() {
        let fw = collapse_ws(FRAMEWORK_JS);
        // The table + resolver are defined and exposed on window.
        assert!(
            fw.contains("const GLOSSARY ="),
            "framework.js must define the inline GLOSSARY string-table (TERM-7)"
        );
        assert!(
            fw.contains("window.GLOSSARY = GLOSSARY"),
            "framework.js must expose GLOSSARY on window so components can resolve labels"
        );
        assert!(
            fw.contains("window.gloss = gloss"),
            "framework.js must expose the gloss() resolver on window"
        );
        // Handler-free host: framework.js is register_static'd in dashboard.rs;
        // a NEW glossary.js handler must NOT have been introduced.
        let dash = collapse_ws(DASHBOARD_RS);
        assert!(
            dash.contains("register_static(server, \"/dashboard/framework.js\""),
            "framework.js must stay the served (register_static) glossary host"
        );
        assert!(
            !dash.contains("/dashboard/glossary.js"),
            "regression: glossary must stay inline in framework.js — no new glossary.js \
             handler (would push REGISTERED_HANDLER_ESTIMATE 76 -> 77/96)"
        );
    }

    // ── (7) TERM-7: GLOSSARY carries the canonical [shared] keys + spellings ───
    // The keys are the stable cross-firmware ids (they must match the OS
    // glossary.ts keys); the strings must be byte-identical to the contract
    // spellings (terminology-lexicon §3.1/§4.x/§5.3/§6.1) or the S1 token+label
    // drift-validators and the truth-ladder guard would diverge from the table.
    #[test]
    fn term7_glossary_has_canonical_shared_keys_and_strings() {
        let fw = collapse_ws(FRAMEWORK_JS);
        // Stable [shared] glossary KEYS (cross-firmware contract surface, §11).
        for key in [
            "window_headline_10m",
            "efficiency_jth",
            "unit_power",
            "btu_per_hour",
            "state_telemetry_pending",
            "state_mining",
            "state_ready",
            "state_standby",
            "state_stopped",
            "telemetry_stale",
            "telemetry_absent",
            "empty_value",
            "share_accepted",
            "best_diff_session",
            "best_diff_all_time",
            "pool_target_difficulty",
            "achieved_difficulty",
            // UINAV-4 shared disclosure-run vocabulary.
            "disclosure_basic",
            "disclosure_standard",
            "advanced_axe_disclosure",
        ] {
            assert!(
                fw.contains(key),
                "GLOSSARY must carry the canonical [shared] key `{key}` (terminology-lexicon §11)"
            );
        }
        // Canonical STRINGS that the served components pull (byte-identical to the
        // contract). 'Hashrate · 10m' is matched in two parts so the central-dot
        // codepoint is not an encoding hazard in the assertion source.
        for s in [
            "Telemetry stale",             // §6.1 telemetry_stale
            "Telemetry pending",           // §6.1 state_telemetry_pending
            "pool accepted",               // §4.4 share_accepted (count-row phrasing)
            "Best Diff (session)",         // §4.2 best_diff_session
            "Best Ever (all-time)",        // §4.2 best_diff_all_time
            "Pool Target Difficulty",      // §4.1 pool_target_difficulty
            "Achieved Difficulty",         // §4.1 achieved_difficulty
            "Lower J/TH = more efficient", // §3.2 efficiency_jth help
        ] {
            assert!(
                fw.contains(s),
                "GLOSSARY must carry the canonical [shared] string `{s}` byte-identical"
            );
        }
        // The 'Hashrate · 10m' headline label (window_headline_10m): match the
        // two literal halves around the middot so the test source stays ASCII.
        assert!(
            fw.contains("Hashrate") && fw.contains("10m") && fw.contains("10m Average"),
            "GLOSSARY window_headline_10m must carry the 'Hashrate · 10m' label + '10m Average' caption"
        );
    }

    // ── (8) TERM-6: 'Telemetry stale' surfaced distinct from 'Offline' ─────────
    // axe was binary online/offline; the canonical lexicon (§6.1) splits
    // held-but-stale telemetry ('Telemetry stale') from nothing-arriving
    // ('Offline'). dashboard.rs's offline path must surface the stale label on
    // the held-_lastInfo branch (truth-contract: label only, never extrapolated).
    #[test]
    fn term6_telemetry_stale_label_surfaced() {
        let dash = collapse_ws(DASHBOARD_RS);
        // The canonical label text and its glossary key are both present.
        assert!(
            dash.contains("Telemetry stale"),
            "dashboard.rs must surface the canonical 'Telemetry stale' label (TERM-6 §6.1)"
        );
        assert!(
            dash.contains("telemetry_stale"),
            "dashboard.rs must reference the telemetry_stale glossary key"
        );
        // The held-vs-absent split is implemented: the banner chooses the stale
        // label only when prior telemetry is held in _lastInfo.
        assert!(
            dash.contains("_telemetryBanner") && dash.contains("_lastInfo?"),
            "the offline banner must split held telemetry (stale) from absent (offline) via _lastInfo"
        );
        // The pre-first-data rung word stays distinct (never collapsed into stale).
        assert!(
            dash.contains("Telemetry pending"),
            "rung-0 'Telemetry pending' must stay distinct from 'Telemetry stale'"
        );
    }

    // ── (9) the served components pull labels from window.GLOSSARY ─────────────
    // core.js / asic-chips.js / block-tile.js were wired to resolve labels via
    // the shared table (with a per-key literal fallback). Pin that they reference
    // it so a future edit cannot silently re-hardcode a scattered label.
    #[test]
    fn served_components_reference_glossary() {
        let core = collapse_ws(CORE_JS);
        assert!(
            core.contains("window.gloss") && core.contains("window_headline_10m"),
            "core.js must resolve its headline/meta labels from window.GLOSSARY"
        );
        for (name, src) in [
            ("asic-chips.js", collapse_ws(ASIC_CHIPS_JS)),
            ("block-tile.js", collapse_ws(BLOCK_TILE_JS)),
        ] {
            assert!(
                src.contains("window.gloss") && src.contains("empty_value"),
                "{name} must resolve the canonical empty-value glyph from window.GLOSSARY"
            );
        }
    }

    // ── (10) M-dash-2: the headline temp tile respects sensor provenance ───────
    // A dead/absent sensor (sensorsOk=false, temp 0) must NOT render as a real
    // "0C / Cool", and an EMC2101 ambient PROXY must be qualified, not shown as the
    // true ASIC die temp. dashboard.rs JS cannot host-execute, so pin from TEXT
    // that the headline `tempQuick` tile is gated on `sensorsOk` and that the
    // `tempSource` ambient-proxy provenance is consulted near the temp rendering.
    #[test]
    fn headline_temp_tile_respects_sensors_ok_and_temp_source() {
        let flat = collapse_ws(DASHBOARD_RS);
        // (a) tempKnown derives from sensorsOk (+ a finite-check mirroring
        //     asic-chips.js) — the sensor-provenance gate.
        assert!(
            flat.contains("tempKnown=(d.sensorsOk!==false)"),
            "the headline temp gate `tempKnown` must derive from d.sensorsOk"
        );
        // (b) the ambient-proxy provenance token is consulted.
        assert!(
            flat.contains("d.dcentaxe.tempSource==='ambient_proxy'"),
            "the temp tile must consult dcentaxe.tempSource for the ambient-proxy qualifier"
        );
        // (c) the headline tempQuick tile renders '--' (not 0C/Cool) when unknown.
        assert!(
            flat.contains("if(!tempKnown){ S('tempQuick','--')"),
            "the headline tempQuick tile must render '--' when the sensor is unknown, \
             not a fabricated 0C/Cool"
        );
        // (d) PROXIMITY: the sensorsOk / tempSource provenance refs sit NEAR the
        //     headline temp rendering (co-located wiring, not an unrelated mention).
        let temp_idx = DASHBOARD_RS
            .find("S('tempQuick'")
            .expect("dashboard.rs must render the headline tempQuick tile");
        let sensor_idx = DASHBOARD_RS
            .find("d.sensorsOk")
            .expect("dashboard.rs must reference d.sensorsOk");
        let source_idx = DASHBOARD_RS
            .find("d.dcentaxe.tempSource")
            .expect("dashboard.rs must reference d.dcentaxe.tempSource");
        let dist = |a: usize, b: usize| if a > b { a - b } else { b - a };
        assert!(
            dist(temp_idx, sensor_idx) < 2000 && dist(temp_idx, source_idx) < 2000,
            "the sensorsOk/tempSource provenance refs must sit NEAR the headline temp \
             rendering (co-located wiring), not an unrelated mention"
        );
    }
}

/// MCP / AUTH CONTRACT structural guards (Phase-3 `mcp-align` lane).
///
/// `mcp.rs` lives in the `dcentaxe` BINARY crate (esp-idf at module scope) and
/// CANNOT host-compile, so — exactly like `safety_guards` and
/// `dcent_design_language_guards` — this pins the cross-firmware MCP/auth
/// contract (`docs/design-system/DCENT_DESIGN_LANGUAGE/mcp-auth-contract.md`)
/// against the `mcp.rs` source TEXT via `include_str!`. It is the only place CI
/// can prove axe's tool-name vocabulary + the read/control auth split has not
/// drifted from the shared `dcent-schema::mcp` registry.
///
/// Matches are deliberately whitespace-robust (substring on a whitespace-
/// collapsed copy), never byte-exact blocks, so a benign reformat of `mcp.rs`
/// cannot flip a guard.
#[cfg(test)]
mod mcp_auth_contract_guards {
    const MCP_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/mcp.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── (1) the 6 cross-firmware-kernel canonical names are present ───────────
    // These are the dcent-schema minimal_profile() names (mcp-auth-contract.md
    // §5.1). axe MUST emit/accept each canonical name. A rename here is a
    // breaking change that host compilation alone cannot catch (binary crate).
    #[test]
    fn kernel_canonical_tool_names_present() {
        let flat = collapse_ws(MCP_RS);
        for name in [
            "get_status",
            "get_device_info",
            "get_swarm_status",
            "identify_device",
            "restart_mining",
            "set_pool",
        ] {
            assert!(
                flat.contains(&format!("\"{name}\"")),
                "mcp.rs must reference the canonical kernel tool name `{name}`"
            );
        }
    }

    // ── (2) legacy aliases are ACCEPTED inbound but NOT emitted standalone ────
    // Contract §2.1 hard rule: "the canonical tool name is the only name a
    // surface EMITS"; a surface MAY still ACCEPT a legacy_alias inbound. axe's
    // dispatch keeps the `get_asic_info`/`get_swarm` match arms (back-compat),
    // but handle_tools_list must no longer list them as standalone tools.
    #[test]
    fn legacy_aliases_accepted_inbound_not_emitted() {
        let flat = collapse_ws(MCP_RS);
        // Inbound dispatch arms for the two aliases MUST stay (back-compat for
        // old AI agents / toolbox callers still using the pre-canonical name).
        assert!(
            flat.contains("\"get_asic_info\" => tool_get_asic_info(state)"),
            "mcp.rs must keep ACCEPTING get_asic_info inbound (legacy alias of get_device_info)"
        );
        assert!(
            flat.contains("\"get_swarm\" => tool_get_swarm(state)"),
            "mcp.rs must keep ACCEPTING get_swarm inbound (legacy alias of get_swarm_status)"
        );
        // …but the two aliases must NOT be emitted as their own tools/list
        // descriptor entries. The emitted form is `"name": "<canonical>"`; an
        // emitted alias would appear as `"name": "get_asic_info"` /
        // `"name": "get_swarm"`. Assert those emission lines are absent.
        assert!(
            !flat.contains("\"name\": \"get_asic_info\""),
            "contract §2.1: get_asic_info is a legacy alias — must NOT be emitted as a standalone \
             tools/list entry (accept inbound only)"
        );
        assert!(
            !flat.contains("\"name\": \"get_swarm\""),
            "contract §2.1: get_swarm is a legacy alias — must NOT be emitted as a standalone \
             tools/list entry (accept inbound only)"
        );
    }

    // ── (3) the 7 CONTROL tools == the shared write semantics ─────────────────
    // The read/control auth split (contract §3) is enforced by
    // mcp_tool_requires_control(). The CONTROL set is the 3 shared-kernel write
    // tools (identify_device/restart_mining/set_pool) + the 4 axe-led tuning
    // tools (set_frequency/set_core_voltage/set_fan_speed/run_autotune). A tool
    // silently dropping out of this matches!() would make it callable on an
    // unauthorized read session — exactly the auth-surface drift this pins.
    #[test]
    fn control_gate_lists_exactly_the_seven_write_tools() {
        let flat = collapse_ws(MCP_RS);
        // The control gate is a matches!(name, ... ) over the 7 CONTROL names.
        for name in [
            "set_frequency",
            "set_core_voltage",
            "set_fan_speed",
            "set_pool",
            "restart_mining",
            "identify_device",
            "run_autotune",
        ] {
            assert!(
                flat.contains(&format!("\"{name}\"")),
                "CONTROL tool `{name}` must appear in mcp.rs (mcp_tool_requires_control gate)"
            );
        }
        // The 3 READ kernel tools must NOT be control-gated. Guard that the
        // control gate function does not list a read tool by checking the
        // matches! arm region around mcp_tool_requires_control.
        let gate = flat
            .find("fn mcp_tool_requires_control")
            .expect("mcp.rs must define the read/control split gate mcp_tool_requires_control");
        // Bound the window at the NEXT sibling `fn ` (not a fixed +400 slice) so a
        // future edit that shrinks the inter-fn doc comment can't let the window
        // spill into `fn mcp_tool_writes_hardware` — whose matches! lists the SAME
        // control names — and mask a mis-class / fail-open regression (the exact
        // AOTA-class defect this guard exists to prevent; completeness-critic L1).
        let end = flat[gate..]
            .match_indices("fn ")
            .nth(1)
            .map(|(i, _)| gate + i)
            .unwrap_or_else(|| (gate + 400).min(flat.len()));
        let region = &flat[gate..end];
        for read_only in [
            "\"get_status\"",
            "\"get_device_info\"",
            "\"get_swarm_status\"",
        ] {
            assert!(
                !region.contains(read_only),
                "READ tool {read_only} must NOT be inside the CONTROL gate (would force owner-auth \
                 on a read tool / mis-class the auth split)"
            );
        }
    }

    // ── (4) the fail-closed-on-OPEN control posture is intact ─────────────────
    // Contract §3.2 + §6: axe's signature posture is CONTROL fail-closed on an
    // OPEN (passwordless) device. The dispatch must refuse a CONTROL tool when
    // !control_authorized regardless of read access. This is the AOTA-class RCE
    // the axe hardening closed; the structure must not regress. (The posture
    // DEFAULT is deliberately the inverse of the OS :3000 server — that
    // asymmetry is the documented, unresolved operator decision; this guard
    // pins only that axe's own fail-closed structure survives, not the cross-
    // product policy.)
    #[test]
    fn control_dispatch_is_fail_closed_on_unauthorized() {
        let flat = collapse_ws(MCP_RS);
        assert!(
            flat.contains("if mcp_tool_requires_control(name) { if !auth.control_authorized {"),
            "handle_tool_call must refuse a CONTROL tool when !control_authorized (fail-closed)"
        );
        // The McpAuth split (read_authorized / control_authorized) is the
        // reference 2-predicate decision (contract §3.1). Pin both predicates.
        assert!(
            flat.contains("read_authorized") && flat.contains("control_authorized"),
            "mcp.rs must keep the two-predicate auth split (read_authorized + control_authorized)"
        );
    }

    // ── (5) cross-firmware byte-alignment: axe mcp.rs ↔ OS :3000 overlay ──────
    // The OS Python `:3000` control server hand-mirrors the SAME dcent-schema
    // minimal_profile() kernel (board/zynq/.../web/mcp_server.py). axe's own
    // mcp.rs and that OS overlay are two independent emissions of the one shared
    // registry — they MUST expose the identical 6 canonical kernel names and the
    // identical 3 shared WRITE names. This is the cross-firmware leg of the
    // author-once / emit-twice / VALIDATE mechanism (token-contract §0,
    // UIVIS-RENDER-1): the dcent-schema Rust drift test
    // (projects/dcent-schema/tests/python_overlay_drift.rs) pins the OS overlay
    // to the registry; THIS test pins axe to the same names the OS overlay
    // emits, so a desync on EITHER firmware surfaces as a red test runnable under
    // `cargo +stable test -p dcentaxe-core --lib`. Text-substring + additive;
    // the OS overlay is read read-only via include_str! (never compiled).
    // Path note: relative to this crate's manifest dir
    // (DCENT_OS_ESP/dcentaxe-core). Two `..` segments reach `projects/`,
    // then into the sibling `dcentos` project.
    const OS_MCP_OVERLAY_PY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dcentos/br2_external_dcentos/board/zynq/rootfs-overlay/root/web/mcp_server.py"
    ));

    #[test]
    fn axe_and_os_overlay_share_the_same_kernel_vocabulary() {
        let axe = collapse_ws(MCP_RS);
        let os = collapse_ws(OS_MCP_OVERLAY_PY);

        // The 6 shared-kernel canonical names must be referenced by axe's mcp.rs
        // AND emitted by the OS overlay as the `"name": "<canonical>"` descriptor.
        for name in [
            "get_status",
            "get_device_info",
            "get_swarm_status",
            "identify_device",
            "restart_mining",
            "set_pool",
        ] {
            assert!(
                axe.contains(&format!("\"{name}\"")),
                "axe mcp.rs must reference shared-kernel tool `{name}`"
            );
            assert!(
                os.contains(&format!("\"name\": \"{name}\"")),
                "OS :3000 overlay must EMIT shared-kernel tool `{name}` — cross-firmware desync"
            );
        }

        // The 3 SHARED write tools must be in axe's CONTROL gate AND the OS
        // overlay's WRITE_TOOLS set (both firmwares fail-closed the same names on
        // a release image). axe's own 4 tuning write tools (set_frequency etc.)
        // are axe-only and intentionally NOT asserted against the OS overlay.
        for shared_write in ["identify_device", "restart_mining", "set_pool"] {
            assert!(
                axe.contains(&format!("\"{shared_write}\"")),
                "axe mcp.rs must carry shared write tool `{shared_write}` in its CONTROL gate"
            );
            // The OS WRITE_TOOLS set is a `{ ... }` literal; assert membership by
            // the bare quoted entry appearing after the WRITE_TOOLS marker.
            let wt = os
                .find("WRITE_TOOLS =")
                .expect("OS overlay must define WRITE_TOOLS");
            let region = &os[wt..];
            assert!(
                region.contains(&format!("\"{shared_write}\"")),
                "OS overlay WRITE_TOOLS must contain shared write tool `{shared_write}` — \
                 cross-firmware auth desync (axe gates it, OS must too)"
            );
        }
    }

    // ── MCP-SEC: bitaxe://config masks EVERY pool password, not just primary ──
    // The read resource clones the live config and masks secrets before
    // serializing. The fallback (`fallback_pool`) and split (`split_pool`) pools
    // each carry their OWN StratumConfig.password; a regression that masks only
    // the primary `stratum.password` would leak the backup-pool credentials in
    // cleartext to any read-authorized MCP client. mcp.rs is the espidf-only
    // binary-crate source (cannot host-compile), so pin the masking against the
    // source TEXT (whitespace-robust, additive — same pattern as the other
    // mcp_auth_contract_guards).
    #[test]
    fn config_resource_masks_all_pool_passwords() {
        let flat = collapse_ws(MCP_RS);
        assert!(
            flat.contains("\"bitaxe://config\" =>"),
            "mcp.rs must serve the bitaxe://config read resource"
        );
        // Primary (pre-existing) masking must stay.
        assert!(
            flat.contains("safe_config.stratum.password = \"***\""),
            "bitaxe://config must mask the PRIMARY stratum password"
        );
        // FALLBACK pool password masking (FIX 2).
        assert!(
            flat.contains("safe_config.fallback_pool.as_mut()")
                && flat.contains("fb.password = \"***\""),
            "MCP-SEC: bitaxe://config must mask the FALLBACK pool password"
        );
        // SPLIT (secondary) pool password masking (FIX 2).
        assert!(
            flat.contains("safe_config.split_pool.as_mut()")
                && flat.contains("sp.pool.password = \"***\""),
            "MCP-SEC: bitaxe://config must mask the SPLIT pool password"
        );
    }

    // ── B-ESP-10: pool worker + URL masked on EVERY read surface ─────────────
    // The pool `worker` is the operator's FULL BTC payout address on V1 solo and
    // a pool URL can embed `user:pass@` creds. This mirrors the Antminer
    // load-bearing rule
    // with byte-identical shapes (`mask_wallet` → <first6>…<last4>;
    // `sanitize_pool_url` → strip the authority). api.rs + mcp.rs are the
    // espidf-only binary-crate sources (cannot host-compile), so pin the masking
    // against the source TEXT — additive + whitespace-robust, exactly like
    // `config_resource_masks_all_pool_passwords` above.
    #[test]
    fn pool_worker_and_url_masked_on_read_surfaces() {
        const API_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/api.rs"
        ));
        let api = collapse_ws(API_RS);
        let mcp = collapse_ws(MCP_RS);

        // /api/system/info struct: primary worker masked + URL sanitized via the
        // owned pre-bound locals (the struct holds &str borrows).
        assert!(
            api.contains(
                "let stratum_user_masked = crate::shared::mask_wallet(&config.stratum.worker_name)"
            ) && api.contains("stratum_user: stratum_user_masked.as_str()"),
            "/api/system/info must mask the primary worker (stratum_user)"
        );
        assert!(
            api.contains(
                "let stratum_url_masked = crate::shared::sanitize_pool_url(&config.stratum.url)"
            ) && api.contains("stratum_url: stratum_url_masked.as_str()"),
            "/api/system/info must sanitize the primary pool URL (stratum_url)"
        );
        assert!(
            api.contains("fallback_user_masked")
                && api.contains("crate::shared::mask_wallet(&fb.worker_name)"),
            "/api/system/info must mask the fallback worker"
        );

        // /api/system GET: the split-pool worker is masked (only split surface).
        assert!(
            api.contains("crate::shared::mask_wallet(&s.pool.worker_name)"),
            "/api/system GET must mask the split-pool worker"
        );

        // /api/pools: both workers masked.
        assert!(
            api.contains("\"worker\": crate::shared::mask_wallet(&config.stratum.worker_name)")
                && api.contains("\"worker\": crate::shared::mask_wallet(&split.pool.worker_name)"),
            "/api/pools must mask the primary + split workers"
        );

        // CGMiner TCP API (pyasic-compat, port 4028): worker masked like Antminer.
        const CGMINER_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/cgminer_tcp.rs"
        ));
        let cg = collapse_ws(CGMINER_RS);
        assert!(
            cg.contains("\"User\": crate::shared::mask_wallet(&pool.worker_name)")
                && cg.contains("\"User\": crate::shared::mask_wallet(&fallback.worker_name)"),
            "CGMiner API must mask the worker in the `User` field"
        );

        // Whole-file floor: every worker/url read site routes through a helper.
        assert!(
            api.matches("crate::shared::mask_wallet(").count() >= 6,
            "api.rs lost a worker-mask call site (read-surface regression)"
        );
        assert!(
            api.matches("crate::shared::sanitize_pool_url(").count() >= 6,
            "api.rs lost a pool-URL-sanitize call site (read-surface regression)"
        );

        // mcp.rs bitaxe://config masks the worker + URL (not just passwords).
        assert!(
            mcp.contains(
                "safe_config.stratum.worker_name = crate::shared::mask_wallet(&safe_config.stratum.worker_name)"
            ),
            "mcp.rs bitaxe://config must mask the primary worker"
        );
        assert!(
            mcp.contains(
                "safe_config.stratum.url = crate::shared::sanitize_pool_url(&safe_config.stratum.url)"
            ),
            "mcp.rs bitaxe://config must sanitize the primary pool URL"
        );
        assert!(
            mcp.contains("fb.worker_name = crate::shared::mask_wallet(&fb.worker_name)")
                && mcp.contains(
                    "sp.pool.worker_name = crate::shared::mask_wallet(&sp.pool.worker_name)"
                ),
            "mcp.rs bitaxe://config must mask the fallback + split workers"
        );

        // Round-trip WRITE guard exists: a masked read echo must not clobber the
        // stored full worker/url (the dashboard form re-POSTs what it rendered).
        assert!(
            api.contains("crate::shared::is_masked_worker_echo(")
                && api.contains("crate::shared::is_sanitized_url_echo("),
            "apply_config_updates must keep the stored worker/url on a masked echo"
        );

        // ── Newly-closed leaks (this pass) — PINNED so they cannot re-open ───────
        // The original >=6 whole-file floors above gave false confidence: they
        // passed DESPITE these three sites leaking, because OTHER call sites met
        // the count. Pin each newly-fixed site EXACTLY.

        // FIX 1: shared_pool_config (GET + POST /api/config/shared, primary AND
        // fallback) routes the pool URL + worker through the canonical sanitizers.
        assert!(
            api.contains("url: crate::shared::sanitize_pool_url(&pool.url)")
                && api.contains("worker: crate::shared::mask_wallet(&pool.worker_name)"),
            "shared_pool_config (/api/config/shared) must sanitize the URL + mask \
             the worker for the primary AND fallback pool (B-ESP-10 FIX 1)"
        );

        // FIX 2 companion: because GET /api/config/shared now masks, the
        // apply_shared_config_patch WRITE path must guard against a masked re-POST
        // clobbering the stored full worker/url (primary + fallback, url + worker).
        assert!(
            api.matches("crate::shared::is_sanitized_url_echo(").count() >= 2
                && api.matches("crate::shared::is_masked_worker_echo(").count() >= 2,
            "apply_shared_config_patch + apply_config_updates must BOTH echo-guard \
             the worker/url WRITE path (B-ESP-10 FIX 2)"
        );

        // FIX 3: the MCP pool_truth active-pool format string sanitizes the URL.
        // Both the pools[] entry and pool_truth use the identical sanitized form;
        // also assert the raw `format!("{}:{}", status.active_url` is gone.
        assert!(
            mcp.matches(
                "\"active_pool\": format!(\"{}:{}\", crate::shared::sanitize_pool_url(&status.active_url), status.active_port)"
            )
            .count()
                >= 2,
            "mcp pool_truth + pools[] active_pool must BOTH sanitize the active \
             pool URL (B-ESP-10 FIX 3)"
        );
        assert!(
            !mcp.contains("format!(\"{}:{}\", status.active_url"),
            "mcp active_pool must not format the RAW active_url (B-ESP-10 FIX 3 leak)"
        );

        // FIX 4: the CGMiner fallback "Stratum URL" uses the already-sanitized
        // fb_display_url, not the raw fallback.url.
        assert!(
            cg.contains("let fb_display_url = crate::shared::sanitize_pool_url(&fallback.url)")
                && cg.contains("\"Stratum URL\": fb_display_url"),
            "CGMiner fallback \"Stratum URL\" must use the sanitized fb_display_url \
             (B-ESP-10 FIX 4)"
        );
        assert!(
            !cg.contains("\"Stratum URL\": fallback.url"),
            "CGMiner fallback \"Stratum URL\" must not emit the raw fallback.url \
             (B-ESP-10 FIX 4 leak)"
        );
    }

    // ── B-ESP-10 iteration 2: events + console logs + OLED masked at the SOURCE ──
    // The DEEPER channel the iteration-1 HTTP-field masking missed: the stratum
    // EVENT details (`StratumEventRecord.detail`), the client/SV2 console LOGS, and
    // the physical OLED embed the RAW pool URL (and one log printed the RAW worker
    // = BTC payout address). Those event details flow verbatim onto the HTTP/MCP
    // read surfaces (`recent_events`, `primary_failback_detail`,
    // `last_reconnect_cause`). They are now sanitized/masked AT THE SOURCE in
    // `dcentaxe-stratum/src/client.rs` + the binary `main.rs` (+ provisioning.rs),
    // so the api.rs/mcp.rs emission points stay clean automatically. client.rs +
    // main.rs are espidf/foreign-crate sources a host compile cannot reach, so pin
    // the masking against the source TEXT (whitespace-robust, additive). Each fixed
    // site is asserted POSITIVE (uses the helper) AND NEGATIVE (the raw form is gone)
    // so the leak cannot silently re-open.
    #[test]
    fn pool_worker_and_url_masked_in_events_logs_oled() {
        const CLIENT_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe-stratum/src/client.rs"
        ));
        const MAIN_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/main.rs"
        ));
        const PROVISIONING_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/provisioning.rs"
        ));
        let client = collapse_ws(CLIENT_RS);
        let main = collapse_ws(MAIN_RS);
        let prov = collapse_ws(PROVISIONING_RS);

        // dcentaxe-stratum imports the canonical helpers (its own byte-identical
        // copy, since the binary's crate::shared is not reachable from this crate).
        assert!(
            client.contains("use crate::mask::{mask_wallet, sanitize_pool_url}"),
            "client.rs must import the sanitize/mask helpers from crate::mask"
        );

        // ── client.rs event details + logs sanitize the pool URL ────────────────
        for needle in [
            // Connect event detail
            "\"connected to {}:{}\", sanitize_pool_url(&self.config.url)",
            // FailoverSkipped / FailoverEntered event details
            "\"fallback unreachable {}:{}\", sanitize_pool_url(&fb.url)",
            "\"switched to fallback {}:{}\", sanitize_pool_url(&self.config.url)",
            // Primary reprobe / failback event details
            "\"probing primary {}:{}\", sanitize_pool_url(&self.primary_config.url)",
            "\"primary {}:{} authorized with job proof\", sanitize_pool_url(&self.primary_config.url)",
            "\"switching back to primary {}:{}\", sanitize_pool_url(&self.config.url)",
            "\"primary {}:{} failed: {}\", sanitize_pool_url(&self.primary_config.url)",
            // PoolRedirect: last_reconnect_cause + ReconnectRequested event detail
            "\"pool redirect {}:{}\", sanitize_pool_url(&self.config.url)",
            "\"redirect to {}:{} in {}s\", sanitize_pool_url(&self.config.url)",
        ] {
            assert!(
                client.contains(needle),
                "client.rs event/log site lost its sanitize_pool_url wrapper: {needle}"
            );
        }
        // The authorize LOG masks the worker (BTC payout address).
        assert!(
            client
                .contains("\"Stratum: authorized as '{}'\", mask_wallet(&self.config.worker_name)"),
            "client.rs authorized log must mask the worker (mask_wallet)"
        );

        // ── client.rs: the RAW forms must be GONE (negative pins) ───────────────
        for raw in [
            "\"connected to {}:{}\", self.config.url",
            "\"switched to fallback {}:{}\", self.config.url",
            "\"fallback unreachable {}:{}\", fb.url",
            "\"pool redirect {}:{}\", self.config.url",
            "\"redirect to {}:{} in {}s\", self.config.url",
            "\"Stratum: authorized as '{}'\", self.config.worker_name",
            "\"primary {}:{} authorized with job proof\", self.primary_config.url",
        ] {
            assert!(
                !client.contains(raw),
                "client.rs still emits a RAW pool URL/worker in an event/log: {raw}"
            );
        }
        // The wire protocol (mining.authorize / mining.submit params) MUST keep the
        // real worker — masking there would break auth. Pin it stays raw.
        assert!(
            client.contains("self.config.worker_name, self.config.password"),
            "client.rs mining.authorize params must keep the REAL worker (write path)"
        );

        // ── main.rs SV2 failover event + OLED sanitize the pool URL ─────────────
        assert!(
            main.contains(
                "\"sv2 failover to fallback {}:{}\", crate::shared::sanitize_pool_url(&fb.url)"
            ),
            "main.rs SV2 failover event/log must sanitize the fallback URL"
        );
        assert!(
            main.contains(
                "let pool_display = format!( \"{}:{}\", crate::shared::sanitize_pool_url(&config.stratum.url)"
            ),
            "main.rs OLED pool_display must sanitize the pool URL"
        );
        // Negative pins: the raw SV2-failover + raw OLED forms are gone.
        assert!(
            !main.contains("\"sv2 failover to fallback {}:{}\", fb.url"),
            "main.rs SV2 failover event still leaks the raw fallback.url"
        );
        assert!(
            !main.contains("format!(\"{}:{}\", config.stratum.url, config.stratum.port)"),
            "main.rs OLED pool_display still leaks the raw config.stratum.url"
        );
        // SV2 wire worker stays raw (handshake auth).
        assert!(
            main.contains("worker: config.worker_name.clone()"),
            "main.rs Sv2Config must keep the REAL worker (write/handshake path)"
        );

        // ── provisioning.rs worker-validation warn masks the BTC payout prefix ──
        assert!(
            prov.contains("crate::shared::mask_wallet(addr_part)"),
            "provisioning.rs worker-validation warn must mask the worker prefix"
        );
        assert!(
            !prov.contains("pool worker format.\", addr_part"),
            "provisioning.rs worker-validation warn still logs the raw worker prefix"
        );
    }
}

/// CAP-OS2AXE-1 / CAP-OS2AXE-3 Phase-3 capability-port structural guards
/// (`axe-ports` lane).
///
/// Phase 3 ported two OS→axe READ-ONLY capability surfaces INLINE into
/// `dashboard.rs` (the autotuner evidence tiles + the Network card's halving
/// countdown + mempool fee radial). `dashboard.rs` is espidf-only and CANNOT
/// host-compile, so — exactly like `dcent_design_language_guards` — these pin
/// the load-bearing invariants of the new inline surfaces against the source
/// TEXT via `include_str!`. This is the host-testable durability mechanism that
/// keeps a future edit from (a) silently stripping the truth-contract honesty
/// copy, or (b) converting the deliberately handler-FREE inline widgets into
/// register_static-spending modular files (the embedded OTA-slot/handler-budget
/// rule from the nav contract).
#[cfg(test)]
mod dashboard_evidence_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── CAP-OS2AXE-1: last_good_* tiles carry the "persisted, not live-proven"
    //    honesty label (data-model-fields §7.2). Softening this to imply a live
    //    setpoint would breach the truth-contract. ──────────────────────────────
    #[test]
    fn autotuner_last_good_tiles_are_labeled_persisted_not_live_proven() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains("persisted, not live-proven"),
            "CAP-OS2AXE-1: the last_good_* evidence tiles MUST carry the \
             'persisted, not live-proven' honesty label (data-model-fields §7.2)"
        );
        // The render reads the persisted last-known-good fields (presentation of
        // existing AutotunerView data — no new wire field).
        for field in [
            "lastGoodFrequency",
            "lastGoodVoltageMv",
            "lastGoodJth",
            "lastGoodErrorRate",
        ] {
            assert!(
                flat.contains(field),
                "CAP-OS2AXE-1: the evidence render must read at.{field} (existing AutotunerView field)"
            );
        }
    }

    // ── CAP-OS2AXE-1: the Best Efficiency evidence row is a MEASURED receipt,
    //    distinct from the DERIVED grade and the PERSISTED last_good_* point. It
    //    reads the existing AutotunerView.bestEfficiency field and carries the
    //    "measured … J/TH, lower is better" honesty label so it can't be confused
    //    with a derived/persisted value (data-model-fields §7.x truth split). A
    //    regression dropping this row or its label would not be caught by host
    //    compilation (dashboard.rs is espidf-only). ──────────────────────────────
    #[test]
    fn best_efficiency_row_reads_measured_field_and_is_labeled_measured() {
        let flat = collapse_ws(DASHBOARD_RS);
        // Reads the existing AutotunerView.bestEfficiency wire field (camelCase
        // serde of best_efficiency) — no new field invented.
        assert!(
            flat.contains("at.bestEfficiency"),
            "CAP-OS2AXE-1: the evidence render must read at.bestEfficiency \
             (existing AutotunerView field), not a fabricated one"
        );
        // Carries the MEASURED honesty label — distinct from the DERIVED grade and
        // the PERSISTED last_good_* point — so the three truth classes don't blur.
        assert!(
            flat.contains("measured &mdash; J/TH, lower is better")
                || flat.contains("measured — J/TH, lower is better"),
            "CAP-OS2AXE-1: the Best Efficiency row MUST carry the \
             'measured — J/TH, lower is better' honesty label"
        );
        // The render is wired through the uniquely-named evidence fn (so it can't
        // shadow a dashboard/*.js window.* global per the wiring contract).
        assert!(
            flat.contains("function renderAutotunerEvidence(at)"),
            "CAP-OS2AXE-1: the evidence rows must render through renderAutotunerEvidence(at)"
        );
    }

    // ── CAP-OS2AXE-1: silicon_grade is labeled DERIVED (not a factory bin) and
    //    has an honest "unknown"/em-dash empty state (data-model-fields §7.1). ──
    #[test]
    fn silicon_grade_is_labeled_derived_with_honest_unknown() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains("derived (measured error-rate/nonce), not factory bin"),
            "CAP-OS2AXE-1: silicon_grade MUST be labeled derived (measured \
             error-rate/nonce), NOT a factory bin (data-model-fields §7.1)"
        );
        assert!(
            flat.contains("siliconGrade"),
            "CAP-OS2AXE-1: the evidence render must read at.siliconGrade"
        );
        // Honest empty state: the 'unknown'/'?' grade renders as the em-dash, it
        // is NOT fabricated into a letter.
        assert!(
            flat.contains("g!=='unknown'"),
            "CAP-OS2AXE-1: an 'unknown' silicon_grade must fall back to the honest \
             em-dash empty state, never a fabricated grade"
        );
    }

    // ── CAP-OS2AXE-3: the mempool fee radial uses the mempool.space cross-origin
    //    browser fetch (NOT a new local /api handler) — handler-FREE by contract. ─
    #[test]
    fn mempool_radial_uses_cross_origin_fetch_not_a_local_handler() {
        assert!(
            DASHBOARD_RS.contains("https://mempool.space/api/v1/fees/recommended"),
            "CAP-OS2AXE-3: the mempool radial MUST use the mempool.space cross-origin \
             browser fetch (the block-tile.js pattern), costing NO firmware handler"
        );
        // It must NOT introduce a new local /api fee route (which would imply a
        // firmware register_static/fn_handler cost).
        assert!(
            !DASHBOARD_RS.contains("/api/network/fees") && !DASHBOARD_RS.contains("/api/mempool"),
            "CAP-OS2AXE-3: the mempool radial must NOT add a new local /api fee handler"
        );
        // Fail-silent empty-state honesty: the em-dash render is the default.
        assert!(
            DASHBOARD_RS.contains("fail-silent"),
            "CAP-OS2AXE-3: the mempool fetch must fail SILENTLY to the em-dash empty state"
        );
    }

    // ── CAP-OS2AXE-3: the halving bar reads the ALREADY-CLIENT-SIDE block height
    //    (d.blockHeight) — no fetch, no new wire field, no handler. ─────────────
    #[test]
    fn halving_bar_reads_block_height_no_new_wire_field() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The countdown is driven by the existing client-side block height passed
        // into renderHalvingCountdown(bh) where bh = d.blockHeight.
        assert!(
            flat.contains("renderHalvingCountdown(bh)"),
            "CAP-OS2AXE-3: the halving countdown must be driven by the existing \
             client-side block height (renderHalvingCountdown(bh))"
        );
        assert!(
            flat.contains("var bh=d.blockHeight"),
            "CAP-OS2AXE-3: bh must come from the already-client-side d.blockHeight \
             (no new wire field)"
        );
        // The OS HalvingTimelineBar math is ported faithfully (210000-block epoch).
        assert!(
            flat.contains("_HALVING_INTERVAL=210000"),
            "CAP-OS2AXE-3: the halving math must use the 210000-block interval"
        );
    }

    // ── Budget guardrail: the Phase-3 inline ports add NO new register_static
    //    handler and NO new modular dashboard file. The two landed widgets are
    //    handler-FREE; a regression that introduces a new dashboard/network.js
    //    (the rejected alternative) would bump the handler count toward the cap. ─
    #[test]
    fn phase3_ports_add_no_new_register_static_handler() {
        // No network.js asset was baked + served (the deferred/rejected
        // alternative). The handler-spending forms are an `include_str!` of the
        // file and a `register_static`/served route for it — NOT a mention of the
        // filename in a comment. Match the concrete handler-cost forms only so the
        // explanatory comment ("no new dashboard/network.js") doesn't self-trip.
        assert!(
            !DASHBOARD_RS.contains("include_str!(\"dashboard/network.js\")")
                && !DASHBOARD_RS.contains("include_str!(\"dashboard/network.css\")"),
            "BUDGET: Phase-3 must NOT include_str! a new network dashboard asset \
             (a register_static handler cost) — the network widgets are INLINE"
        );
        assert!(
            !DASHBOARD_RS.contains("register_static(server, \"/dashboard/network.js\"")
                && !DASHBOARD_RS.contains("register_static(server, \"/dashboard/network.css\""),
            "BUDGET: Phase-3 must NOT register_static a /dashboard/network.* route \
             (a new URI handler) — the network widgets are handler-free inline"
        );
        assert!(
            !DASHBOARD_RS.contains("DASH_JS_NETWORK") && !DASHBOARD_RS.contains("DASH_CSS_NETWORK"),
            "BUDGET: Phase-3 must NOT bake a new network dashboard asset const (handler cost)"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // P1-W6 — the Performance chart seeds from the DEVICE's own history.
    //
    // Before this lane the chart was a purely client-side ring: one point per
    // 15 s poll, drawn only once two points existed, thrown away on every
    // reload — while the firmware had kept a real ~60-minute history all along
    // and registered TWO routes for it that the dashboard never called. These
    // are source contracts because `dashboard.rs` is `target_os = "espidf"`
    // only and cannot host-compile; the last test binds the CLIENT to the
    // SERVER shape it reads, so a renamed label or a changed cap fails here
    // instead of silently emptying the chart on a device.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn chart_seeds_from_the_device_statistics_endpoint_on_load_and_on_reconnect() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains("function seedChart()")
                && flat.contains("'/api/system/statistics?columns="),
            "P1-W6: the chart must seed from GET /api/system/statistics \
             (api.rs::register_system_statistics)"
        );
        // Boot: the seed runs in the same start-up chain as the first poll.
        assert!(
            flat.contains("renderAuthUi();poll();seedChart();"),
            "P1-W6: seedChart() must run in the boot chain next to poll()"
        );
        // Reconnect: the re-seed sits inside update()'s offline->online branch,
        // so the offline gap is filled with what the device really sampled
        // rather than a straight line drawn across it.
        assert!(
            flat.contains(
                "if(_offline){_offline=0;clearInterval(_retryT);_retryDelay=10;\
                 E('offlineBanner').style.display='none';seedChart()}"
            ),
            "P1-W6: update()'s reconnect branch must re-seed the chart"
        );
        // Columns are resolved BY NAME off the response's own `labels`, never by
        // a hard-coded index: the handler's ?columns= filter returns a SUBSET in
        // the same fixed order, so an index would silently read the wrong column.
        for name in [
            "indexOf('hashrate')",
            "indexOf('power')",
            "indexOf('asicTemp')",
            "indexOf('timestamp')",
        ] {
            assert!(
                flat.contains(name),
                "P1-W6: seedChart must resolve the {name} column by name, not by index"
            );
        }
    }

    #[test]
    fn chart_window_label_is_derived_from_the_samples_and_never_a_constant() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains("id=\"chartWin\"") && flat.contains("function chartWindow()"),
            "P1-W6: the chart must carry a window label element rendered by chartWindow()"
        );
        // Window LENGTH is the span of the timestamps actually held and the
        // COUNT is the ring length — both read off the data.
        assert!(
            flat.contains("var n=TSH.length") && flat.contains("TSH[n-1]-TSH[0]"),
            "P1-W6: the window length and sample count must be derived from TSH"
        );
        // A label may never assert a window the held data does not prove (the
        // old ring was 120 points at 15 s and nothing said so).
        for fake in [
            "last 30 min",
            "Last 30 min",
            "last 30 minutes",
            "last hour",
            "Last hour",
            "120 samples",
            "60 minutes of history",
        ] {
            assert!(
                !flat.contains(fake),
                "P1-W6/D2: '{fake}' is a constant window claim — derive it from TSH"
            );
        }
        // Provenance is stated, not implied: how many points came from the
        // device vs. from this browser session.
        assert!(
            flat.contains("' from device'") && flat.contains("'this session'"),
            "P1-W6/D2: the label must say whether the points came from the device \
             or only from this session"
        );
    }

    #[test]
    fn chart_falls_back_to_the_client_ring_without_fabricating_points() {
        let flat = collapse_ws(DASHBOARD_RS);
        // A failed history fetch marks the provenance and re-renders the label.
        // It never invents samples (rubric H14).
        assert!(
            flat.contains(".catch(function(){_histSrc=-1;chartWindow();return 0})"),
            "P1-W6/H14: a failed history fetch must fall back to the client-only \
             ring and say so, never fabricate points"
        );
        assert!(
            flat.contains("'device history unavailable'"),
            "P1-W6/D2: the fallback label must state that the device history was \
             unavailable"
        );
        // Every column the seed plots must be PRESENT. Zero-filling a missing
        // column would draw a flat 0 series that looks like a measurement.
        assert!(
            flat.contains("if(ih<0||ip<0||it<0||is<0||!R.length)throw 0;"),
            "P1-W6/H14: a missing statistics column must abort the seed, never be \
             zero-filled into a false flat series"
        );
        assert!(
            !flat.contains("Math.random()"),
            "H14: the dashboard must never fabricate data with Math.random()"
        );
    }

    #[test]
    fn chart_history_seed_spends_no_new_uri_handler() {
        // /api/system/statistics is already registered by api.rs; the chart just
        // calls it. dashboard.rs keeps exactly its three fn_handler call sites
        // (`/`, `/index.html`, and the one inside register_static).
        assert_eq!(
            DASHBOARD_RS.matches("fn_handler(").count(),
            3,
            "P1-W6/H2: the chart history seed must spend ZERO new URI handlers \
             (MAX_URI_HANDLERS budget) — it reuses a route api.rs already serves"
        );
    }

    #[test]
    fn statistics_endpoint_contract_the_chart_seed_depends_on_still_holds() {
        const API_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/api.rs"
        ));
        const MAIN_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/main.rs"
        ));
        let api = collapse_ws(API_RS);
        assert!(
            api.contains("register(\"/api/system/statistics\", state.clone(), server);"),
            "P1-W6: GET /api/system/statistics must stay registered — the dashboard \
             chart seeds from it"
        );
        // The four column names the dashboard resolves by name.
        for label in ["\"hashrate\"", "\"power\"", "\"asicTemp\"", "\"timestamp\""] {
            assert!(
                api.contains(label),
                "P1-W6: statistics column {label} is part of the chart-seed contract"
            );
        }
        let main = collapse_ws(MAIN_RS);
        // Cadence + cap are what make the reported window ~60 minutes.
        assert!(
            main.contains("history_now_ms.saturating_sub(last_history_sample_ms) >= 60_000"),
            "P1-W6: the 60 s history sample cadence is part of the chart-seed contract"
        );
        assert!(
            main.contains("if history.samples.len() > 60 {"),
            "P1-W6: the 60-sample history cap is part of the chart-seed contract"
        );
        // Oldest-first ordering: the cap drains the FRONT, which is why the rows
        // can be plotted left-to-right without sorting them client-side.
        assert!(
            main.contains("history.samples.drain(0..excess);"),
            "P1-W6: history rows must stay oldest-first (the cap drains the front) \
             — the chart plots them in the order received"
        );
    }
    // ══════════════════════════════════════════════════════════════════════
    // HELD-OUT TEST (blind critic, P1-W6 r1, 2026-09-03) — added by the critic,
    // never seen by the builder. Rationale: the critic crossed `TH` and `PH` in
    // seedChart()'s assignment (`HRH=h;TH=p;PH=t;TSH=s;`) so the device's WATTS
    // were plotted on the cyan temperature line against the temperature scale
    // and its DEGREES on the yellow power line — and all 513 dcentaxe-core tests
    // still passed. The seed is the only place a column index is bound to a
    // series, and nothing pinned that binding: a one-character transposition
    // there silently mislabels two of the three seeded quantities, which is a
    // truth breach the moment it ships. This binds the column -> series map at
    // both hops (the per-row push, and the staged array -> global assignment).
    // ══════════════════════════════════════════════════════════════════════
    #[test]
    fn chart_seed_binds_every_statistics_column_to_the_series_named_by_that_column() {
        let flat = collapse_ws(DASHBOARD_RS);
        // Hop 1 — each resolved column index pushes into the staging array for
        // THAT quantity: ih->h (hashrate), it->t (asicTemp), ip->p (power),
        // is->s (timestamp).
        for (idx, arr, what) in [
            ("ih", "h", "hashrate"),
            ("it", "t", "asicTemp"),
            ("ip", "p", "power"),
            ("is", "s", "timestamp"),
        ] {
            assert!(
                flat.contains(&format!("{arr}.push(+r[{idx}]||0)")),
                "P1-W6/D2 held-out: the {what} column (index `{idx}`) must be pushed                  into the `{arr}` staging array — a crossed index plots one quantity                  under another's name and scale"
            );
        }
        // Hop 2 — the staged arrays land on the globals the chart draws with the
        // matching colour and scale: HRH (accent, hashrate axis), TH (cyan,
        // temperature scale), PH (yellow, power scale), TSH (time axis).
        assert!(
            flat.contains("HRH=h;TH=t;PH=p;TSH=s;"),
            "P1-W6/D2 held-out: the seed must assign hashrate->HRH, asicTemp->TH,              power->PH, timestamp->TSH; any transposition mislabels a series"
        );
        for crossed in ["HRH=h;TH=p;PH=t;", "HRH=t;", "HRH=p;", "TSH=h;", "TSH=t;", "TSH=p;"] {
            assert!(
                !flat.contains(crossed),
                "P1-W6/D2 held-out: `{crossed}` crosses a statistics column onto the                  wrong chart series"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // P1-W6 ROUND 2 — presentation truth for the seeded chart.
    //
    // Round 1 made the chart read the device's own history. Round 2 fixes what
    // that history then LOOKED like: two sample cadences (60 s device, 15 s
    // live) drawn at a uniform index pitch, two different hashrate averages on
    // one line, a re-seed that a 5xx recovery skipped, and a hero-trend window
    // whose length depended on the ring's mix. Every test below is a source
    // contract over `dashboard.rs` (which is `target_os = "espidf"` only), and
    // several of them cross-check the server file the client is reading.
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn chart_x_position_is_proportional_to_time_not_to_sample_index() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The seeded rows are 60 s apart and the live pushes are 15 s apart, so
        // an index-uniform axis draws 60 minutes and 15 minutes at the same
        // width. x must come off the TIMESTAMP.
        assert!(
            flat.contains("var t0=TSH[0],tsp=(TSH[TSH.length-1]-t0)||1;")
                && flat.contains("_CX=[];for(var i=0;i<TSH.length;i++)_CX[i]=pad.l+(TSH[i]-t0)/tsp*cw;"),
            "P1-W6 r2: the chart's x positions must be computed from TSH \
             (time-proportional), not from the sample index"
        );
        // Every consumer reads that one mapping: the hashrate polyline, the
        // secondary series, the hover crosshair.
        assert!(
            flat.contains("pts.push([_CX[i],pad.t+ch-(HRH[i]/hrMax)*ch])")
                && flat.contains("i?ctx.lineTo(_CX[i],y):ctx.moveTo(_CX[i],y)")
                && flat.contains("var x=_CX[idx];"),
            "P1-W6 r2: every series and the hover crosshair must place points \
             through the shared time-proportional _CX map"
        );
        // The index-pitch forms that produced the 4x time-scale break.
        for banned in [
            "i/(HRH.length-1)*cw",
            "i/(TH.length-1)*cw",
            "i/(PH.length-1)*cw",
            "i/(a.length-1)*cw",
            "idx/(HRH.length-1)*cw",
            "idx/(TSH.length-1)*cw",
        ] {
            assert!(
                !flat.contains(banned),
                "P1-W6 r2: `{banned}` spaces points by sample INDEX — the ring \
                 mixes 60 s and 15 s samples, so that misdraws the time scale"
            );
        }
    }

    #[test]
    fn chart_time_ticks_are_uniform_in_time_and_clock_aligned() {
        let flat = collapse_ws(DASHBOARD_RS);
        // A ladder of round intervals (1/5/15/30/60/180 min): the smallest step
        // that yields at most five ticks. Equal step => equal Δt between ticks.
        assert!(
            flat.contains("var TS=[6e4,3e5,9e5,18e5,36e5,108e5],st=216e5,k;for(k=0;k<6;k++)if(tsp/TS[k]<=5){st=TS[k];break}"),
            "P1-W6 r2: time ticks must step by a fixed interval chosen from a \
             round-number ladder, so the spacing is uniform in TIME"
        );
        // Ticks land on round LOCAL clock minutes (AxeOS shows 30-minute ticks);
        // the timezone offset is what makes ':00/:15/:30/:45' rather than
        // 'whatever t0 happened to be'.
        assert!(
            flat.contains("var tz=new Date().getTimezoneOffset()*6e4;")
                && flat.contains("for(var tk=Math.ceil((t0-tz)/st)*st+tz;tk<=t0+tsp;tk+=st)"),
            "P1-W6 r2: tick times must be clock-aligned multiples of the step"
        );
        // And the label is placed at that tick's TIME, not at a sample.
        assert!(
            flat.contains("pad.l+(tk-t0)/tsp*cw,pad.t+ch+18"),
            "P1-W6 r2: a tick label must be drawn at its own timestamp's x"
        );
        // The round-1 form: five labels at evenly spaced sample INDICES.
        assert!(
            !flat.contains("Math.round(ti/4*(TSH.length-1))"),
            "P1-W6 r2: ticks must not be picked by sample index"
        );
    }

    #[test]
    fn chart_line_carries_one_hashrate_statistic_matching_the_seeded_column() {
        const API_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/api.rs"
        ));
        const MAIN_RS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentaxe/src/main.rs"
        ));
        let flat = collapse_ws(DASHBOARD_RS);
        // Client: the value appended to the chart ring is the 5-minute average,
        // named so it cannot be confused with the 1m value the mining booleans
        // and the "1m:" readout use.
        assert!(
            flat.contains("var hr=d.hashRate_1m||d.hashRate||0,hr5=d.hashRate_5m||hr;"),
            "P1-W6 r2/D2: the chart's hashrate must be resolved as its own \
             5-minute statistic, not reuse the 1-minute value"
        );
        assert!(
            flat.contains("HRH.push(hr5);"),
            "P1-W6 r2/D2: the live chart push must be the 5-minute statistic"
        );
        assert!(
            !flat.contains("HRH.push(hr);"),
            "P1-W6 r2/D2: pushing hashRate_1m onto a line seeded with the \
             5-minute average puts TWO different averages on ONE line"
        );
        // Server, both hops: the wire field the client pushes and the history
        // column the client seeds from must be the SAME snapshot statistic.
        let api = collapse_ws(API_RS);
        assert!(
            api.contains("hash_rate_5m: snap.hashrate_5m_ghs,"),
            "P1-W6 r2: /api/system/info `hashRate_5m` must stay \
             `snap.hashrate_5m_ghs` — the chart's live push reads it"
        );
        assert!(
            api.contains("\"hashrate\" => snap.hashrate_5m_ghs,"),
            "P1-W6 r2: the statistics `hashrate` column must stay \
             `snap.hashrate_5m_ghs` — the chart seeds the same line from it"
        );
        assert!(
            collapse_ws(MAIN_RS).contains("hashrate_ghs: snap.hashrate_5m_ghs,"),
            "P1-W6 r2: the retained history sample's `hashrate_ghs` must stay \
             `snap.hashrate_5m_ghs`"
        );
    }

    #[test]
    fn chart_reconnect_reseed_requires_a_response_the_client_accepted() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The re-seed hook lives in update()'s offline->online branch, so the
        // retry must not clear `_offline` itself and must not hand update() a
        // body it never validated. Round 1's retry did both, so a 5xx->200
        // recovery cleared the flag first and silently skipped the re-seed.
        assert!(
            flat.contains(
                "fetch('/api/system/info',{headers:authHeaders({})})\
                 .then(handleReadAuthFailure)\
                 .then(function(r){if(!r.ok)throw 0;return r.json()})\
                 .then(update)"
            ),
            "P1-W6 r2: schedRetry must reject a non-ok response and let update() \
             own the offline->online transition (that is where the re-seed is)"
        );
        assert!(
            !flat.contains(
                "function(d){_offline=0;_retryDelay=10;\
                 E('offlineBanner').style.display='none';update(d)}"
            ),
            "P1-W6 r2: schedRetry must not clear _offline before update() — that \
             skips the reconnect re-seed"
        );
    }

    #[test]
    fn chart_provenance_distinguishes_stale_device_points_from_none_at_all() {
        let flat = collapse_ws(DASHBOARD_RS);
        // A failed re-seed while device rows are still on the canvas is not the
        // same as having no device history: the points are real, just old.
        assert!(
            flat.contains("_histSrc<0?(_histRows?_histRows+fd+', stale':'device history unavailable')"),
            "P1-W6 r2/D2: after a failed re-seed the label must say the device \
             points are STALE while they are still drawn, and only claim \
             'device history unavailable' when none are held"
        );
        // The empty-history branch of the handler answers with ONE row built
        // from the live snapshot (its timestamp == currentTimestamp). That is a
        // live reading, so it must not be counted as a history sample.
        assert!(
            flat.contains("_histRows=s.length-(s.length==1&&s[0]==c0);"),
            "P1-W6 r2/D2: the empty-history branch's synthetic row is a live \
             reading and must not be counted as device history"
        );
        assert!(
            flat.contains("'live reading, no history'"),
            "P1-W6 r2/D2: the label must name the empty-history branch for what \
             it is instead of reporting '1 from device'"
        );
    }

    #[test]
    fn chart_seed_skips_a_short_row_instead_of_zero_filling_it() {
        let flat = collapse_ws(DASHBOARD_RS);
        // `+undefined||0` is 0: a row shorter than the largest resolved column
        // index would be plotted as a real 0 GH/s, 0 W, 0 degC sample.
        assert!(
            flat.contains("mi=Math.max(ih,ip,it,is)")
                && flat.contains("if(!r||r.length<=mi)continue;"),
            "P1-W6 r2/H14: a statistics row shorter than the resolved columns \
             must be skipped, never zero-filled into a false sample"
        );
        // And if that leaves nothing, the seed fails honestly rather than
        // reporting an empty window as device history.
        assert!(
            flat.contains("if(!s.length)throw 0;"),
            "P1-W6 r2/H14: a response whose every row was skipped must take the \
             honest failure path, not report an empty device history"
        );
    }

    #[test]
    fn hero_trend_window_is_a_fixed_ninety_second_span_read_off_the_timestamps() {
        let flat = collapse_ws(DASHBOARD_RS);
        // "six samples back" was 90 s in an all-live ring and up to five minutes
        // once 60 s device samples were mixed in — the arrow silently changed
        // meaning. Walk TSH back to the first point at least 90 s older.
        assert!(
            flat.contains("var j2=n2-1,tb=TSH[j2]-9e4;while(j2>0&&TSH[j2]>tb)j2--;"),
            "P1-W6 r2/D2: the hero trend baseline must be a fixed 90-second TIME \
             window found by walking TSH"
        );
        assert!(
            !flat.contains("HRH[Math.max(0,HRH.length-6)]") && !flat.contains("_hHist"),
            "P1-W6 r2/D2: a fixed sample COUNT is not a fixed window once the \
             ring mixes two cadences"
        );
    }

    #[test]
    fn chart_secondary_series_has_a_labelled_axis_and_the_canvas_has_a_name() {
        let flat = collapse_ws(DASHBOARD_RS);
        // Hashrate keeps the labelled left axis; temperature gains a labelled
        // right axis (AxeOS's two-axis layout is the bar). The padding has to
        // make room for it or the labels are clipped.
        assert!(
            flat.contains("var pad={l:45,r:34,t:10,b:25},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;"),
            "P1-W6 r2/D1: the plot must reserve right-hand padding for the \
             temperature axis"
        );
        assert!(
            flat.contains("if(showT&&TH.length>1){ctx.fillStyle='#22d3ee';ctx.textAlign='left';ctx.fillText((tMax*(1-i/4)).toFixed(0),pad.l+cw+5,y+4)}"),
            "P1-W6 r2/D1: the temperature series must carry a labelled right-hand \
             axis on the same gridlines as the hashrate axis"
        );
        // Each series names its unit and its axis in the legend, so a reader can
        // tell which scale a line belongs to without hovering.
        for label in [
            ">Hashrate 5m (left)<",
            ">Temp °C (right)<",
            ">Power W<",
        ] {
            assert!(
                flat.contains(label),
                "P1-W6 r2/D1: the chart legend must carry `{label}` so every \
                 series names its unit"
            );
        }
        // D4: the canvas is not a decoration — it gets a role and a name, and
        // the name is the same derived window/provenance sentence a sighted
        // reader sees, announced when it changes.
        assert!(
            flat.contains("<canvas id=\"perfChart\" role=img aria-labelledby=chartWin>"),
            "P1-W6 r2/D4: the chart canvas needs role=img and an accessible name \
             taken from the window label"
        );
        assert!(
            flat.contains("<div class=\"chart-win\" id=\"chartWin\" aria-live=polite>"),
            "P1-W6 r2/D4: the window label must announce its own changes"
        );
    }
}

/// FUND-LINK guards (`P1-G1`, DCENT_axe UI Gauntlet 2026-09-03).
///
/// Root  (2026-07-10) makes a visible Fund / Donate / Support
/// affordance pointing at `https://d-central.tech/fund/` a HARD RULE for every
/// DCENT_ open-source project, and a missing one a public-release GATE FAILURE.
/// Until this module existed nothing in the tree referenced that URL - no test,
/// no ban gate, no workflow - so a scrub/claims pass could have deleted the
/// dashboard's only instance with every gate still green.
///
/// `dashboard.rs` is `target_os = "espidf"`-only and cannot host-compile, so -
/// exactly like `dcent_design_language_guards` and `dashboard_evidence_guards` -
/// these pin the invariant against the source TEXT via `include_str!`.
///
/// TWO instances are required, not one. The sidebar-footer instance
/// (`.sb-foot`, `placement=dashboard`) is `display:none` in the collapsed
/// sidebar (`body.col .sb-foot`, dashboard.rs ~:292) and is off-canvas whenever
/// the mobile drawer is closed at <= 768 px. Measured on the mock 2026-09-03:
/// height 0 / `offsetParent` null in `body.col`, and `rect.left = -244` at both
/// 390x844 and 768x1024. A single instance is therefore only CONDITIONALLY
/// visible. The second instance lives in a PAGE card (System page
/// "Integrations"), which is painted in both of those states.
///
/// The matching source-text ban gates are `scripts/ci_ban_gates.sh` [12]-[14]:
/// [12] counts anchors, [13]/[14] require each placement tag distinctly (a
/// copy-paste of one anchor twice passed [12] alone — blind critic P1-G1, probe
/// A). Guard and gates are deliberately redundant: deleting an anchor fails
/// both, and `fund_link_is_pinned_by_the_ci_ban_gate_too` notices if the gate
/// itself is removed. Neither pins PAINT — the adopted held-out guard
/// `a_fund_anchor_is_inside_the_system_page_container_and_not_inline_hidden`
/// bounds the System-page instance to its page container and rejects an
/// inline-hidden anchor.
#[cfg(test)]
mod fund_link_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const CI_BAN_GATES_SH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scripts/ci_ban_gates.sh"
    ));

    /// The exact href prefix the HARD RULE names.
    const FUND_HREF_PREFIX: &str = "https://d-central.tech/fund/";
    /// The anchor form, so a bare mention in a comment cannot satisfy the guard.
    const FUND_HREF: &str = "href=\"https://d-central.tech/fund/";

    #[test]
    fn fund_link_present_on_dashboard() {
        let anchors = DASHBOARD_RS.matches(FUND_HREF).count();
        assert!(
            anchors >= 2,
            "FUND (root  2026-07-10, public-release gate): dashboard.rs \
             must render at least TWO anchors whose href starts with {} - the \
             sidebar footer is display:none in the collapsed sidebar and \
             off-canvas with the mobile drawer closed, so one instance is only \
             conditionally visible. Found {}.",
            FUND_HREF_PREFIX, anchors
        );
        assert!(
            !DASHBOARD_RS.contains("http://d-central.tech/fund"),
            "FUND: the fund link must stay https:// (an http:// form appeared)"
        );
        let tagged = DASHBOARD_RS
            .matches("/fund/go?source=dcent_axe&placement=")
            .count();
        assert_eq!(
            tagged, anchors,
            "FUND: every fund anchor keeps the ?source=dcent_axe&placement=... \
             attribution convention ({} tagged of {} anchors)",
            tagged, anchors
        );
        assert!(
            DASHBOARD_RS.contains("&placement=dashboard"),
            "FUND: the sidebar-footer instance (placement=dashboard) was removed"
        );
        // Distinct placement tags: the two instances stay separately
        // attributable, and a copy-paste of one cannot satisfy the count.
        let placements: std::collections::BTreeSet<&str> = DASHBOARD_RS
            .match_indices("&placement=")
            .map(|(i, m)| {
                let rest = &DASHBOARD_RS[i + m.len()..];
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        assert!(
            placements.len() >= 2,
            "FUND: the fund anchors must carry DISTINCT placement tags; saw {:?}",
            placements
        );
    }

    #[test]
    fn fund_link_has_an_instance_outside_the_collapsible_sidebar_footer() {
        let foot = DASHBOARD_RS
            .find("<div class=\"sb-foot\">")
            .expect("FUND: the sidebar footer block moved - re-point this guard");
        let main = DASHBOARD_RS[foot..]
            .find("<div class=\"main\"")
            .map(|i| foot + i)
            .expect("FUND: the main region marker moved - re-point this guard");
        let in_footer = DASHBOARD_RS[foot..main].matches(FUND_HREF).count();
        let outside = DASHBOARD_RS.matches(FUND_HREF).count() - in_footer;
        assert!(
            outside >= 1,
            "FUND: at least one fund anchor must live OUTSIDE the sidebar footer \
             (`body.col .sb-foot` is display:none and the drawer is off-canvas \
             below 769 px), so the affordance survives the collapsed-sidebar and \
             drawer-closed states. Found {} in the footer, {} outside.",
            in_footer, outside
        );
        let integrations = DASHBOARD_RS
            .find("<div class=\"card-title\">Integrations</div>")
            .expect("FUND: the System page Integrations card moved");
        assert!(
            DASHBOARD_RS[integrations..].contains(FUND_HREF),
            "FUND: the second instance belongs in a PAGE card - the System page \
             Integrations card (dashboard.rs ~:1395) - not in the sidebar chrome"
        );
    }

    #[test]
    fn fund_link_is_pinned_by_the_ci_ban_gate_too() {
        assert!(
            CI_BAN_GATES_SH.contains("require_pattern"),
            "FUND: scripts/ci_ban_gates.sh must keep the require_pattern helper \
             (the mirror of a ban gate: it fires when something REQUIRED is gone)"
        );
        assert!(
            CI_BAN_GATES_SH.contains(FUND_HREF_PREFIX),
            "FUND: scripts/ci_ban_gates.sh must keep the [12] gate requiring {} \
             in dashboard.rs - guard and gate are deliberately redundant",
            FUND_HREF_PREFIX
        );
    }
}

/// Phase-4 UX-FLOW VOCABULARY structural guards (`axe-flows` lane).
///
/// Phase 4 made axe's flow SURFACES speak the shared flow vocabulary
/// (`flows-and-patterns.md`, `terminology-lexicon.md`, `component-contract.md §7`).
/// Every edit was an additive, INLINE label/string touch-up inside an existing
/// `dashboard.rs` element — NO new register_static handler, NO new modular file,
/// NO new function that could shadow a `dashboard/*.js` window.* global, NO Rust
/// control-flow change (the HTML/JS lives inside Rust raw-string literals, so the
/// edits are syntax-safe by construction). `dashboard.rs` is espidf-only and
/// CANNOT host-compile, so — exactly like `dcent_design_language_guards` and
/// `dashboard_evidence_guards` — these pin the load-bearing flow-vocabulary
/// invariants against the source TEXT via `include_str!`. This is the only CI
/// mechanism that proves the Phase-4 flow vocabulary (and the keep-DISTINCT /
/// keep-axe-floor identity guardrails) has not regressed.
///
/// Matches are deliberately whitespace-robust (substring on a whitespace-
/// collapsed copy), never byte-exact blocks, so a benign HTML/JS reflow or
/// minify cannot flip a guard.
#[cfg(test)]
mod dcent_flow_vocab_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── (a) UXFLOW-SAFETY-1: the fan-safety honesty vocabulary is present ──────
    // The "No tach" / "Unproved" RPM-proof readout + the three canonical PWM zone
    // labels + the cut-hash-before-noise posture phrasing (glossary key
    // cut_hash_before_noise). These are LABEL-only — the cut-hash-before-fan
    // BEHAVIOR lives in main.rs (XPSAFE-5 / HALT thermal tiers, host-pinned in
    // `thermal_ladder_guards`), NOT here. A regression that strips the honesty
    // labels (e.g. faking a 0 RPM instead of "No tach") would not be caught by
    // host compilation (dashboard.rs is espidf-only).
    #[test]
    fn fan_safety_honesty_vocabulary_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        // rpm==0 ⇒ literal "No tach" (never a fake 0), and the speed-proof token.
        assert!(
            flat.contains("'No tach'")
                || flat.contains("\"No tach\"")
                || flat.contains(">No tach<"),
            "UXFLOW-SAFETY-1: rpm==0 must render the literal 'No tach' (never a fake 0 RPM)"
        );
        assert!(
            flat.contains("'Unproved'")
                || flat.contains("\"Unproved\"")
                || flat.contains(">Unproved<"),
            "UXFLOW-SAFETY-1: the fan speed-proof token 'Unproved' (rpm==0) must be present"
        );
        // The three canonical PWM zone labels (component-contract §7).
        for zone in ["Home cap", "Loud override", "Thermal override"] {
            assert!(
                flat.contains(zone),
                "UXFLOW-SAFETY-1: the canonical PWM zone label `{zone}` must be present"
            );
        }
        // The cut-hash-before-noise posture phrasing (glossary cut_hash_before_noise).
        assert!(
            flat.contains("cut hash before noise"),
            "UXFLOW-SAFETY-1: the 'cut hash before noise' posture phrasing must surface \
             (LABEL only — the behavior lives in main.rs)"
        );
    }

    // ── (b) UXFLOW-SAFETY-1 identity guard: axe keeps its OWN fan floor (20) ───
    // The shared vocabulary is adopted at axe's floor, NOT OS's 10-30 home clamp.
    // The manual fan slider must stay min=20 max=100; importing OS's numeric clamp
    // is an explicit keep-unique violation (keep-unique-guardrails §8).
    #[test]
    fn fan_slider_keeps_axe_floor_not_os_clamp() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The slider keeps its axe floor (min=20) and ceiling (max=100).
        assert!(
            flat.contains("id=\"fanSlider\" min=20 max=100")
                || flat.contains("type=range id=\"fanSlider\" min=20 max=100"),
            "UXFLOW-SAFETY-1: the manual fan slider must keep axe's own floor (min=20 max=100), \
             NOT be re-clamped to OS's 10-30 home range"
        );
        // The derived zone label is wired through the uniquely-named inline helper
        // (fanZoneLabel) — a NEW name that does NOT collide with any dashboard/*.js
        // window.* global, preserving the wiring contract.
        assert!(
            flat.contains("function fanZoneLabel("),
            "UXFLOW-SAFETY-1: the PWM zone label must render through the uniquely-named \
             fanZoneLabel() helper (wiring-contract-safe)"
        );
        // a11y: the zone is mirrored into aria-valuetext (component-contract §7).
        assert!(
            flat.contains("aria-valuetext"),
            "UXFLOW-SAFETY-1: the fan slider must expose the zone via aria-valuetext (a11y parity)"
        );
    }

    // ── (c) UXFLOW-POOL-1: the 3 canonical pool ROUTING labels are present ─────
    // axe's failbackStatusText already emits the shared routing vocabulary
    // (Primary ready (job proof) / Primary route entered / Fallback active). Pin
    // them so a relabel can't silently break cross-firmware pool-vocabulary
    // parity. Difficulty honesty: the Pool-Target-vs-Achieved phrasing is on the
    // Share Target tooltips.
    #[test]
    fn pool_routing_and_difficulty_vocabulary_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        for label in [
            "Primary ready (job proof)",
            "Primary route entered",
            "Fallback active",
        ] {
            assert!(
                flat.contains(label),
                "UXFLOW-POOL-1: the canonical pool routing label `{label}` must survive \
                 in failbackStatusText"
            );
        }
        // Pool-Target-vs-Achieved difficulty honesty (lexicon §4.1): the Share
        // Target rows carry the 'pool-required minimum, not ... Achieved' tooltip.
        assert!(
            flat.contains("Pool Target Difficulty") && flat.contains("Achieved Difficulty"),
            "UXFLOW-POOL-1: the Share Target honesty tooltip must distinguish Pool Target \
             Difficulty (vardiff minimum) from Achieved Difficulty"
        );
    }

    // ── (d) UXFLOW-OTA-1 (ratify): the Upload≠boot≠rollback proof ladder + the
    //    manifest-preflight vocabulary survive (RALPH 9D8 OTA-UX contract). ─────
    #[test]
    fn ota_proof_ladder_vocabulary_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        // Upload-not-Flash framing + the boot-proof-pending success copy.
        assert!(
            flat.contains("Upload accepted; boot proof pending."),
            "UXFLOW-OTA-1: the OTA success copy must be 'Upload accepted; boot proof pending.'"
        );
        // The operator is told to refresh device status, never to assume reboot.
        assert!(
            flat.contains("refresh device status"),
            "UXFLOW-OTA-1: an unparseable OTA response must tell the operator to \
             'refresh device status' (not infer reboot/success)"
        );
        // The compact manifest-preflight tokens (RALPH 9D8).
        for token in ["slot_fit", "sha_status", "target preflight required"] {
            assert!(
                flat.contains(token),
                "UXFLOW-OTA-1: the OTA manifest-preflight token `{token}` must survive"
            );
        }
    }

    // ── (e) UXFLOW-RESET-1 (keep DISTINCT): the owner-reset keeps-X disclosure
    //    copy survives. axe owner-reset KEEPS WiFi + pool config and is session-
    //    gated; it must NOT converge with OS restore-to-stock (which wipes to
    //    stock). Pin the keeps-X disclosure so the keep-distinct boundary holds. ─
    #[test]
    fn owner_reset_keeps_distinct_disclosure_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains("Keeps WiFi + pool config") || flat.contains("keeps WiFi + pool config"),
            "UXFLOW-RESET-1: the owner-reset disclosure must state it KEEPS WiFi + pool config \
             (keep-DISTINCT from OS restore-to-stock, which wipes to stock)"
        );
        // It is session-gated (an active owner session), not a physical-access
        // bypass — the keep-unique auth posture (do not regress).
        assert!(
            flat.contains("Requires an active owner session"),
            "UXFLOW-RESET-1: owner-reset must remain session-gated (active owner session), \
             not a claim_skip-style bypass"
        );
    }

    // ── (f) UXFLOW-TUNE-1: an absent tuner status renders the canonical
    //    'Unavailable' honesty word, never the old bare 'idle' (the OS
    //    valueOrUnavailable convention). The 4 mode names stay canonical (already
    //    pinned in `dcent_design_language_guards`); this pins the run-status
    //    honesty fallback only. ──────────────────────────────────────────────────
    #[test]
    fn tuner_null_status_renders_unavailable_not_bare_idle() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The null/empty fallback is the canonical 'Unavailable'.
        assert!(
            flat.contains("at.status||'Unavailable'")
                || flat.contains("at.status || 'Unavailable'"),
            "UXFLOW-TUNE-1: an absent tuner status must fall back to the canonical \
             'Unavailable', not a bare 'idle'"
        );
        // The default markup span is also 'Unavailable', not the old 'idle'.
        assert!(
            flat.contains("id=\"atStatus\">Unavailable<"),
            "UXFLOW-TUNE-1: the tuner Status span must default to 'Unavailable'"
        );
        // The old bare 'idle' fallback must be gone from the tuner status path
        // (the '||\\'idle\\'' fallback specifically — unrelated 'idle' words in
        // other contexts are not matched by this exact form).
        assert!(
            !flat.contains("at.status||'idle'") && !flat.contains("at.status || 'idle'"),
            "UXFLOW-TUNE-1: the old bare 'idle' tuner-status fallback must be gone"
        );
    }
}

/// S4 `axe-ports` capability-port guards (`axe-ports` lane).
///
/// The S4 second pass ported two DCENT_OS capabilities to axe as ADDITIVE,
/// identity-preserving, handler-free inline surfaces in `dashboard.rs`:
///   • CAP-OS2AXE-2 — a LITE vanilla-SVG fan-curve editor (3-point temp->PWM)
///     over axe's two-scalar fan model, and
///   • CAP-OS2AXE-6 — a LITE 3-4 step first-run wizard overlay.
///
/// Because `dashboard.rs` is espidf-only and CANNOT host-compile, these — exactly
/// like `dcent_flow_vocab_guards` — pin the load-bearing port invariants against
/// the source TEXT via `include_str!`. They are the only CI mechanism that proves:
///   (G-FANCURVE-1)     the fan-curve surface exists, clamps PWM to axe's OWN floor
///                      20..100, and does NOT import OS's 10-30 home clamp (keep-unique);
///   (G-FANCURVE-AUTH)  the fan-curve WRITE is owner-auth-gated — it routes through the
///                      CSRF+Bearer `post('/api/system'…)` helper (which itself routes
///                      `ensureWriteAuth()`+`authHeaders()` -> `authorize_rest_write`),
///                      with NO new bare/unauth mutation route. axe is
///                      FAIL-CLOSED-CONTROL-ON-OPEN on EVERY build, so a CONTROL write
///                      MUST never be an unauthenticated POST;
///   (G-WIZARD-1)       the first-run overlay carries the 4 canonical step labels +
///                      the freedom-first "recommended, not required" / opt-out copy;
///   (G-WIZARD-SAFETY-ACK) the Welcome (step 0) screen carries the explicit
///                      safety-acknowledgement checkbox (id=frSafetyAck) stating the
///                      cut-hash-before-fan-noise home-heater posture, surfaced BEFORE
///                      the pool/mode steps;
///   (G-WIZARD-KEEPUNIQUE) the overlay DROPS the OS-only industrial steps
///                      (Circuit / PSU / Calibration / Power source) — scoped to the
///                      WIZ-FR-START..WIZ-FR-END region so the descriptive comment that
///                      *names* the dropped steps doesn't false-positive;
///   (G-S4-BUDGET)      BOTH ports are handler-FREE: no new register_static route, no
///                      new modular dashboard/*.{js,css} file, and the named handler-
///                      count constants (REGISTERED_HANDLER_ESTIMATE 76 / MAX_URI_
///                      HANDLERS 96) stay untouched — they reuse the existing auth-gated
///                      post('/api/system') write (the embedded-route budget HARD rule).
///
/// Matches are whitespace-robust (substring on a whitespace-collapsed copy), never
/// byte-exact blocks, so a benign HTML/JS reflow cannot flip a guard.
#[cfg(test)]
mod s4_axe_capability_port_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    // main.rs owns the embedded-route budget constants (MAX_URI_HANDLERS /
    // REGISTERED_HANDLER_ESTIMATE). It is espidf-only and cannot host-compile, so
    // the budget guard pins those constants against the source TEXT to prove the
    // S4 ports added ZERO handlers (the embedded-route budget is a HARD rule).
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Scope helper: the wizard markup between the WIZ-FR-START..WIZ-FR-END markers
    /// (collapse_ws keeps the comment markers intact — no internal whitespace).
    fn wizard_region(flat: &str) -> &str {
        let start = flat
            .find("WIZ-FR-START")
            .expect("CAP-OS2AXE-6: WIZ-FR-START marker must be present");
        let end = flat
            .find("WIZ-FR-END")
            .expect("CAP-OS2AXE-6: WIZ-FR-END marker must be present");
        assert!(
            end > start,
            "CAP-OS2AXE-6: WIZ-FR markers must be ordered (START before END)"
        );
        &flat[start..end]
    }

    // ── (G-FANCURVE-1) the fan-curve surface exists + keeps axe's OWN 20..100 floor ──
    #[test]
    fn fan_curve_surface_clamps_to_axe_floor_not_os_clamp() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The inline vanilla-SVG editor surface (unique marker) is present.
        assert!(
            flat.contains("id=\"fanCurveSvg\""),
            "CAP-OS2AXE-2: the inline fan-curve SVG surface (id=\"fanCurveSvg\") must be present"
        );
        assert!(
            flat.contains("function fanCurveApply(") && flat.contains("function fanCurveRender("),
            "CAP-OS2AXE-2: the fan-curve apply/render helpers must be present"
        );
        // PWM axis clamps to axe's OWN floor (20) and ceiling (100) — the drag/load
        // clamp `Math.max(20,Math.min(100,…))`.
        assert!(
            flat.contains("Math.max(20,Math.min(100,"),
            "CAP-OS2AXE-2: the fan-curve PWM axis must clamp to axe's OWN floor 20..100"
        );
        // KEEP-UNIQUE (component-contract §7 / keep-unique §8): OS's 10-30 home clamp
        // must NOT be pushed onto axe, and the OS multi-point editor's identifiers
        // (PWM_MAX=30) must not appear.
        assert!(
            !flat.contains("Math.min(30,"),
            "CAP-OS2AXE-2: axe must NOT re-clamp the curve to OS's 10-30 home range"
        );
        assert!(
            !flat.contains("PWM_MAX"),
            "CAP-OS2AXE-2: the OS FanCurveEditor's PWM_MAX (0-30 cap) identifier must NOT leak \
             into axe — axe keeps its own floor (20)"
        );
        // Honesty: the lite editor must label itself as NOT a per-point firmware curve
        // (that stays OS-only), so it never implies per-point firmware control.
        assert!(
            flat.contains("per-point firmware curve"),
            "CAP-OS2AXE-2: the lite editor must be labelled honestly (NOT a per-point firmware \
             curve — that stays DCENT_OS-only per component-contract §7)"
        );
    }

    // ── (G-FANCURVE-AUTH) the fan-curve WRITE is owner-auth-gated (structural) ──────
    // axe is FAIL-CLOSED-CONTROL-ON-OPEN on EVERY build. The fan-curve apply is a
    // CONTROL surface, so its WRITE MUST route through the CSRF+Bearer `post()` helper
    // (-> ensureWriteAuth + authHeaders -> authorize_rest_write), never a bare/unauth
    // mutation and never a NEW route.
    #[test]
    fn fan_curve_write_requires_owner_auth() {
        let flat = collapse_ws(DASHBOARD_RS);
        // The apply writes through the auth-gated helper on the EXISTING /api/system
        // route (the same gate setFanAuto uses), carrying the derived knee + floor.
        assert!(
            flat.contains("post('/api/system',{fanMode:'auto',autofanspeed:1,fanTargetTemp:"),
            "CAP-OS2AXE-2: the fan-curve apply must write the derived knee/floor through the \
             auth-gated post('/api/system',…) helper (NOT a bare/unauth mutation)"
        );
        // The post() helper itself ALWAYS routes ensureWriteAuth() + authHeaders()
        // (CSRF X-Requested-With + Bearer) before the POST — this is the structural
        // proof that every post() write (incl. the fan curve) requires owner-auth.
        assert!(
            flat.contains(
                "ensureWriteAuth().then(function(){return fetch(u,{method:'POST',headers:authHeaders("
            ),
            "CAP-OS2AXE-2: post() must gate every write through ensureWriteAuth()+authHeaders() \
             (authorize_rest_write) — the fan-curve CONTROL write inherits this owner-auth gate"
        );
        // No NEW unauthenticated fan/curve mutation route was introduced (+0 handlers).
        assert!(
            !flat.contains("/api/fan-curve") && !flat.contains("/api/fancurve"),
            "CAP-OS2AXE-2: the fan-curve must introduce NO new (unauth) route — it reuses the \
             existing auth-gated /api/system route (+0 URI handlers)"
        );
    }

    // ── (G-WIZARD-1) the first-run overlay carries the canonical steps + opt-out ────
    #[test]
    fn first_run_wizard_steps_and_freedom_copy_present() {
        let flat = collapse_ws(DASHBOARD_RS);
        let region = wizard_region(&flat);
        // The 3-4 step overlay surface + nav wiring.
        assert!(
            flat.contains("id=\"frOverlay\"") && flat.contains("function firstRunApply("),
            "CAP-OS2AXE-6: the first-run overlay (#frOverlay) + apply path must be present"
        );
        // The 4 canonical step labels in OS step ORDERING (Welcome+safety-ack ->
        // Pool/worker -> Mode/heater-target -> Review).
        for label in ["Welcome", "Pool / Worker", "Heater Target", "Review"] {
            assert!(
                region.contains(label),
                "CAP-OS2AXE-6: the canonical first-run step label `{label}` must be present"
            );
        }
        // The freedom-first opt-out copy ("recommended, not required") + a dismiss path.
        assert!(
            region.contains("recommended, not required"),
            "CAP-OS2AXE-6: the freedom-first 'recommended, not required' opt-out copy must survive"
        );
        assert!(
            region.contains("Skip for now") && flat.contains("function firstRunSkip("),
            "CAP-OS2AXE-6: the wizard must stay dismissible ('Skip for now' / firstRunSkip)"
        );
        // Final Apply reuses the EXISTING auth-gated post('/api/system') write (+0 handlers).
        assert!(
            flat.contains("function firstRunApply(") && flat.contains("post('/api/system',b,"),
            "CAP-OS2AXE-6: the wizard Apply must reuse the auth-gated post('/api/system') write"
        );
    }

    // ── (G-WIZARD-KEEPUNIQUE) the overlay DROPS the OS-only industrial steps ────────
    // Scoped to the WIZ-FR-START..WIZ-FR-END region: axe stays a home device — the
    // industrial commissioning steps (Circuit NEC-derate / PSU override / Calibration
    // / Power source) must NOT appear inside the overlay (keep-unique §4.7). The
    // descriptive comment that *names* them lives OUTSIDE the markers on purpose.
    #[test]
    fn first_run_wizard_drops_os_industrial_steps() {
        let flat = collapse_ws(DASHBOARD_RS);
        let region = wizard_region(&flat);
        for banned in ["Circuit", "Calibration", "PSU", "Power source"] {
            assert!(
                !region.contains(banned),
                "CAP-OS2AXE-6 keep-unique §4.7: the OS-only industrial step `{banned}` must NOT \
                 appear in the axe first-run overlay (a 14-step commissioning rail is wrong UX \
                 for a home BitAxe)"
            );
        }
    }

    // ── (G-WIZARD-SAFETY-ACK) the wizard's Welcome step carries the safety-ack ──────
    // The first-run overlay's Welcome screen (step 0) MUST present the explicit
    // safety acknowledgement — the cut-hash-before-fan-noise home-heater posture
    // checkbox (id=frSafetyAck) — surfaced BEFORE the pool/mode steps so the safety
    // contract is shown first. A regression that dropped the ack (or softened its
    // posture phrasing) would not be caught by host compilation (dashboard.rs is
    // espidf-only). Scoped to the WIZ-FR region so it is unambiguously the wizard.
    #[test]
    fn first_run_wizard_has_safety_ack_step() {
        let flat = collapse_ws(DASHBOARD_RS);
        let region = wizard_region(&flat);
        // The safety-acknowledgement checkbox lives inside the wizard region.
        assert!(
            region.contains("id=\"frSafetyAck\""),
            "CAP-OS2AXE-6: the first-run wizard must carry the safety-ack checkbox \
             (id=\"frSafetyAck\")"
        );
        // It states the load-bearing cut-hash-before-fan-noise home-heater posture
        // (LABEL only — the behavior lives in main.rs XPSAFE-5 thermal tiers).
        assert!(
            region.contains("cuts hash before raising fan noise"),
            "CAP-OS2AXE-6: the safety-ack step must state the 'cuts hash before raising fan \
             noise' home-heater posture"
        );
        // The ack sits on the Welcome step (data-fr-step=0), BEFORE the Pool/Worker
        // step (data-fr-step=1) — the safety contract is surfaced first.
        let step0 = region
            .find("data-fr-step=\"0\"")
            .expect("CAP-OS2AXE-6: the wizard must have a Welcome step (data-fr-step=0)");
        let step1 = region
            .find("data-fr-step=\"1\"")
            .expect("CAP-OS2AXE-6: the wizard must have a Pool/Worker step (data-fr-step=1)");
        let ack = region
            .find("id=\"frSafetyAck\"")
            .expect("safety-ack present (checked above)");
        assert!(
            step0 < ack && ack < step1,
            "CAP-OS2AXE-6: the safety-ack must sit on the Welcome step (between step 0 and \
             step 1), surfaced before pool/mode setup"
        );
    }

    // ── (G-S4-BUDGET) the fan-curve editor + wizard stay within the wiring/handler
    //    budget. BOTH are handler-FREE inline surfaces: NO new register_static route,
    //    NO new modular dashboard/*.{js,css} file, and the named handler-count
    //    constants are UNTOUCHED (proof S4 added 0 handlers). The embedded-route
    //    budget is a HARD rule (nav-IA contract); a regression that broke either
    //    surface into a served asset would bump the count toward the 96 cap and is
    //    invisible to host compilation (main.rs/dashboard.rs are espidf-only). ────────
    #[test]
    fn s4_ports_stay_within_wiring_and_handler_budget() {
        let flat = collapse_ws(DASHBOARD_RS);
        // No served route for a fan-curve OR wizard asset (the handler-spending form).
        for route in [
            "/dashboard/fan-curve.js",
            "/dashboard/fancurve.js",
            "/dashboard/fan-curve.css",
            "/dashboard/wizard.js",
            "/dashboard/wizard.css",
            "/dashboard/first-run.js",
        ] {
            assert!(
                !DASHBOARD_RS.contains(route),
                "G-S4-BUDGET: the S4 ports must NOT serve a `{route}` asset (a register_static / \
                 fn_handler cost) — the fan-curve + wizard are handler-free INLINE surfaces"
            );
        }
        // No new include_str! of a fan-curve/wizard module file (baking a served asset).
        for asset in [
            "include_str!(\"dashboard/fan-curve.js\")",
            "include_str!(\"dashboard/fancurve.js\")",
            "include_str!(\"dashboard/wizard.js\")",
            "include_str!(\"dashboard/first-run.js\")",
        ] {
            assert!(
                !flat.contains(asset),
                "G-S4-BUDGET: the S4 ports must NOT include_str! a new dashboard module `{asset}` \
                 (a register_static handler cost)"
            );
        }
        // Both surfaces reuse the EXISTING auth-gated /api/system write (+0 routes):
        // the fan-curve apply and the wizard Apply both post('/api/system', …).
        assert!(
            flat.contains("post('/api/system',{fanMode:'auto',autofanspeed:1,fanTargetTemp:"),
            "G-S4-BUDGET: the fan-curve apply must reuse the existing auth-gated \
             post('/api/system') write (+0 handlers)"
        );
        assert!(
            flat.contains("post('/api/system',b,"),
            "G-S4-BUDGET: the wizard Apply must reuse the existing auth-gated \
             post('/api/system') write (+0 handlers)"
        );
        // The named handler-count constants are UNCHANGED — proof S4 added 0 handlers
        // and the embedded-route budget is intact (REGISTERED_HANDLER_ESTIMATE < cap).
        assert!(
            MAIN_RS.contains("const MAX_URI_HANDLERS: usize = 96;"),
            "G-S4-BUDGET: MAX_URI_HANDLERS must stay 96 (S4 ports add no handler)"
        );
        assert!(
            MAIN_RS.contains("const REGISTERED_HANDLER_ESTIMATE: usize = 76;"),
            "G-S4-BUDGET: REGISTERED_HANDLER_ESTIMATE must stay at the measured \
             invocation-aware total 76 (S4 fan-curve + wizard are handler-free \
             inline surfaces, +0 routes; 76 was 73 only because the old count was \
             by text — see lane P1-I3)"
        );
    }
}

/// S5 `axe-superset` cross-firmware MCP tool-name alignment guards (convergence
/// Phase S5, `axe-superset` lane).
///
/// S5 unifies the MCP control vocabulary across DCENT_axe and DCENT_OS on the
/// `dcent.cross-firmware.tuning.v1` superset (dcent-schema `tuning_profile()`):
/// the 6-tool minimal kernel PLUS 6 richer tuning EXTENSIONS — READS
/// `get_network`/`get_history`; CONTROL `set_frequency`/`set_core_voltage`/
/// `set_fan_speed`/`run_autotune`. axe is the RICH control side and was ALREADY
/// fully superset-conformant before S5: `tools_list_descriptor()` emits all 12
/// canonical names, the dispatch ACCEPTS the 2 kernel legacy aliases inbound-only
/// (`get_asic_info`->`get_device_info`, `get_swarm`->`get_swarm_status`), and
/// `mcp_tool_requires_control` already gates exactly the 7 CONTROL names. So S5
/// applied ZERO renames and ZERO new URI handlers on axe — its deliverable is
/// THIS durability pin.
///
/// `dcentaxe/src/mcp.rs` (and `main.rs`) are the espidf-only binary-crate sources
/// and CANNOT host-compile, so — exactly like `mcp_auth_contract_guards` /
/// `s4_axe_capability_port_guards` — these guards pin the load-bearing facts
/// against the source TEXT via `include_str!` (whitespace-robust substring on a
/// collapsed copy; additive, never byte-exact blocks). They make a future edit
/// that (a) drops a canonical superset name, (b) mis-classes a tuning CONTROL
/// tool OUT of the owner-auth gate (the AOTA-class fail-open regression), (c)
/// wrongly write-gates a READ tool, or (d) spends a URI handler to add a tool,
/// a RED test runnable under `cargo +stable test -p dcentaxe-core --lib`.
///
/// This is a NEW module (S5) added ALONGSIDE `s4_axe_capability_port_guards`; it
/// touches neither S4 nor `mcp_auth_contract_guards`.
#[cfg(test)]
mod s5_axe_mcp_superset_guards {
    const MCP_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/mcp.rs"
    ));
    // main.rs owns the embedded-route budget constants; it is espidf-only and
    // cannot host-compile, so the budget guard pins them against the source TEXT
    // to prove the S5 name alignment added ZERO handlers (HARD route-budget rule).
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The 12-row FROZEN `tuning_profile()` superset (kernel 6 first, then the 6
    /// extensions in reads-then-writes tail order) — the EXACT order/contents the
    /// dcent-schema source of truth pins (`tuning_profile_tool_names_are_locked`).
    const SUPERSET_NAMES: [&str; 12] = [
        "get_status",
        "get_device_info",
        "get_swarm_status",
        "identify_device",
        "restart_mining",
        "set_pool",
        "get_network",
        "get_history",
        "set_frequency",
        "set_core_voltage",
        "set_fan_speed",
        "run_autotune",
    ];
    /// The 6 superset EXTENSIONS (rows 7-12) split by auth class — what S5 layers
    /// on top of the minimal kernel.
    const EXTENSION_READS: [&str; 2] = ["get_network", "get_history"];
    const EXTENSION_CONTROLS: [&str; 4] = [
        "set_frequency",
        "set_core_voltage",
        "set_fan_speed",
        "run_autotune",
    ];

    /// Window the `mcp_tool_requires_control` matches!() body (generous 400-char
    /// bound; the gate is a short fn) — the same scoping the sibling
    /// `mcp_auth_contract_guards::control_gate_lists_exactly_the_seven_write_tools`
    /// guard uses. `find("fn mcp_tool_requires_control")` matches the DEFINITION
    /// (the call sites have no `fn ` prefix), so the window is the gate body.
    fn control_gate_region(flat: &str) -> String {
        let gate = flat
            .find("fn mcp_tool_requires_control")
            .expect("mcp.rs must define the read/control split gate mcp_tool_requires_control");
        // Bound at the NEXT sibling `fn ` rather than a fixed +400 slice: the
        // sibling `fn mcp_tool_writes_hardware` lists the SAME control names, so a
        // future edit that shrinks the inter-fn doc comment could let a fixed
        // window spill into it and FALSE-PASS the auth-class assertions even with
        // a tuning control removed from the real gate (completeness-critic L1).
        let end = flat[gate..]
            .match_indices("fn ")
            .nth(1)
            .map(|(i, _)| gate + i)
            .unwrap_or_else(|| (gate + 400).min(flat.len()));
        flat[gate..end].to_string()
    }

    // ── (3a/3b/3c) the 12 canonical superset names are present AND each extension
    //    is in its CORRECT auth class: the 4 tuning CONTROL tools inside the
    //    owner-auth gate, the 2 tuning READ tools outside it. ─────────────────────
    #[test]
    fn tuning_superset_present_and_correctly_classed() {
        let flat = collapse_ws(MCP_RS);
        let region = control_gate_region(&flat);

        // (a) every canonical superset name is referenced by axe's mcp.rs.
        for name in SUPERSET_NAMES {
            assert!(
                flat.contains(&format!("\"{name}\"")),
                "S5: axe mcp.rs must reference canonical superset tool `{name}`"
            );
        }
        // (b) the 4 tuning CONTROL extensions sit INSIDE the owner-auth control
        //     gate — so an unauthorized read session (and an OPEN/passwordless
        //     device) is REFUSED them (the AOTA-class fail-closed posture).
        for name in EXTENSION_CONTROLS {
            assert!(
                region.contains(&format!("\"{name}\"")),
                "S5: tuning CONTROL tool `{name}` MUST be inside mcp_tool_requires_control \
                 (owner-auth gate) — else it is callable on an unauthorized/open session"
            );
        }
        // (c) the 2 tuning READ extensions are NOT control-gated (correct auth
        //     class — write-gating a read tool would force owner-auth on telemetry).
        for name in EXTENSION_READS {
            assert!(
                !region.contains(&format!("\"{name}\"")),
                "S5: READ tool `{name}` must NOT be inside the CONTROL gate (mis-classed \
                 auth — would force owner-auth on a read tool)"
            );
        }
    }

    // ── each of the 12 canonical names is EMITTED exactly once (tools/list) and
    //    DISPATCHED exactly once (inbound) — wiring integrity: no missing tool, no
    //    double-registration, no dangling alias. ──────────────────────────────────
    #[test]
    fn superset_tools_registered_exactly_once_no_dangling_alias() {
        let flat = collapse_ws(MCP_RS);
        for name in SUPERSET_NAMES {
            let emitted = flat.matches(&format!("\"name\": \"{name}\"")).count();
            assert_eq!(
                emitted, 1,
                "S5: superset tool `{name}` must be EMITTED exactly once in tools/list \
                 (found {emitted}) — no missing/duplicate descriptor"
            );
            let dispatched = flat.matches(&format!("\"{name}\" =>")).count();
            assert_eq!(
                dispatched, 1,
                "S5: superset tool `{name}` must be DISPATCHED exactly once inbound \
                 (found {dispatched}) — no dangling/duplicate match arm"
            );
        }
        // The 2 kernel legacy aliases are ACCEPTED inbound (one arm each) but NEVER
        // EMITTED — back-compat without surfacing a non-canonical name (contract §2.1).
        for alias in ["get_asic_info", "get_swarm"] {
            assert_eq!(
                flat.matches(&format!("\"{alias}\" =>")).count(),
                1,
                "S5: legacy alias `{alias}` must keep exactly one inbound dispatch arm (back-compat)"
            );
            assert!(
                !flat.contains(&format!("\"name\": \"{alias}\"")),
                "S5: legacy alias `{alias}` must NOT be emitted as a tools/list entry \
                 (accept inbound only — contract §2.1)"
            );
        }
    }

    // ── the tuning name alignment spends ZERO URI handlers: all 12 tools dispatch
    //    inside the single POST /mcp JSON-RPC handler via the `name` match, and the
    //    named handler-count constants are UNCHANGED (HARD embedded-route budget). ──
    #[test]
    fn superset_alignment_adds_zero_uri_handlers() {
        // The named budget constants are untouched (S5 = name alignment, +0 routes).
        assert!(
            MAIN_RS.contains("const MAX_URI_HANDLERS: usize = 96;"),
            "S5: MAX_URI_HANDLERS must stay 96 (MCP name alignment adds no handler)"
        );
        assert!(
            MAIN_RS.contains("const REGISTERED_HANDLER_ESTIMATE: usize = 76;"),
            "S5: REGISTERED_HANDLER_ESTIMATE must stay at the measured \
             invocation-aware total 76 (all 12 MCP tools share the single \
             POST /mcp handler — name alignment is handler-free; 76 was 73 only \
             because the old count was by text — see lane P1-I3)"
        );
        let flat = collapse_ws(MCP_RS);
        // No per-tool route was introduced for any tuning tool (would be a handler cost).
        for name in SUPERSET_NAMES {
            assert!(
                !flat.contains(&format!("/mcp/{name}")),
                "S5: tuning tool `{name}` must NOT get its own /mcp/{name} route — all tools \
                 dispatch inside the single POST /mcp handler (+0 URI handlers)"
            );
        }
        // The single POST /mcp registration remains the one and only MCP control route.
        assert!(
            flat.contains("\"/mcp\", Method::Post,"),
            "S5: the single POST /mcp JSON-RPC handler must remain the sole MCP control route"
        );
    }

    // ── fail-closed-control-on-OPEN holds for all 4 new tuning controls: the
    //    dispatch refuses a CONTROL tool when !control_authorized regardless of read
    //    access, the 4 tuning writes are real actuators, and freq/voltage keep the
    //    per-board hardware clamp. ─────────────────────────────────────────────────
    #[test]
    fn tuning_controls_inherit_fail_closed_open_posture() {
        let flat = collapse_ws(MCP_RS);
        // The fail-closed control dispatch structure (same pin as the sibling
        // mcp_auth_contract_guards::control_dispatch_is_fail_closed_on_unauthorized).
        assert!(
            flat.contains("if mcp_tool_requires_control(name) { if !auth.control_authorized {"),
            "S5: handle_tool_call must refuse a CONTROL tool when !control_authorized — the 4 \
             tuning writes inherit this fail-closed-on-open posture"
        );
        // Each tuning CONTROL extension actually performs a hardware/config write
        // through its tool fn (so gating it is load-bearing, not cosmetic).
        for (name, tool_fn) in [
            ("set_frequency", "fn tool_set_frequency("),
            ("set_core_voltage", "fn tool_set_core_voltage("),
            ("set_fan_speed", "fn tool_set_fan_speed("),
            ("run_autotune", "fn tool_run_autotune("),
        ] {
            assert!(
                flat.contains(tool_fn),
                "S5: tuning CONTROL tool `{name}` must have its actuating handler `{tool_fn}…`"
            );
        }
        // The two hardware-actuating writes (freq/voltage) route through the
        // per-board hardware clamp (qualify_operating_point) on the Mcp surface —
        // mcp-auth-contract §2 hard rule (do not weaken the clamp).
        assert!(
            flat.contains("config.qualify_operating_point(")
                && flat.contains("crate::config::ControlSurface::Mcp"),
            "S5: set_frequency/set_core_voltage must keep routing through \
             qualify_operating_point(..., ControlSurface::Mcp) (per-board hardware clamp)"
        );
    }
}

/// S2 `axe-conform` MODULAR-DASHBOARD-JS conformance guards (`axe-conform` lane).
///
/// The S2 second pass of the DCENT convergence conformed the two shared
/// components the component-contract named but left unspecced against their axe
/// emissions: `COMP-CHIPSTRIP` (`ChipGrid`, `asic-chips.js`) and
/// `COMP-BLOCKTILE` (`BlockCard`, `block-tile.js`). Both files were already
/// ship-grade — the only genuine divergence was the BlockCard LIVE/STALE pill
/// (axe dimmed opacity but never flipped the pill LABEL the way OS
/// `CurrentBlockCard.liveStatus()` does). These guards pin the now-conformed
/// facts against the JS source TEXT via `include_str!`.
///
/// These two `dashboard/*.js` files are NOT `include_str!`'d by any other guard
/// (the espidf-only `dashboard.rs` guards above can't see them), so without this
/// module a future edit could silently regress the freshness-honesty swap, the
/// closed `ChipState` enum, the honest-null temp path, or trim the
/// `[axe-only-solo]` coinbase user-reward verification (an identity guardrail per
/// terminology-lexicon §3 and keep-unique §4.6). Unlike `dashboard.rs`, these are
/// plain text host-readable, so the asserts run under `cargo test -p
/// dcentaxe-core --lib` on any host.
#[cfg(test)]
mod axe_conform_modular_js_guards {
    const ASIC_CHIPS_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/asic-chips.js"
    ));
    const BLOCK_TILE_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/block-tile.js"
    ));
    const API_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/api.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── COMP-BLOCKTILE: the BlockCard freshness rule (component-contract §5,
    //    "live=true ⇒ LIVE pill; else STALE pill") is byte-identical across both
    //    products — LIVE_THRESHOLD_MS = 120_000. axe pins the literal 120000 in
    //    block-tile.js so the shared 120s gate can't silently drift. ───────────
    #[test]
    fn block_card_freshness_threshold_is_120s_shared_with_os() {
        let flat = collapse_ws(BLOCK_TILE_JS);
        // The 120s stale gate (block-tile.js:360) — the same magnitude OS pins as
        // LIVE_THRESHOLD_MS=120_000 (CurrentBlockCard.tsx:9).
        assert!(
            flat.contains("120000"),
            "COMP-BLOCKTILE: block-tile.js MUST keep the 120000 ms (120 s) \
             staleness threshold — byte-identical to OS LIVE_THRESHOLD_MS=120_000"
        );
        // It is applied as a Date.now()-since-receivedUnixMs comparison, not a
        // fabricated 'always live'.
        assert!(
            flat.contains("Date.now()-d.receivedUnixMs")
                || flat.contains("Date.now() - d.receivedUnixMs"),
            "COMP-BLOCKTILE: the stale gate must be a real Date.now()-receivedUnixMs age check"
        );
    }

    // ── COMP-BLOCKTILE: the S2 genuine divergence closed — the block hero LIVE
    //    pill flips its LABEL to STALE when the block age exceeds the threshold
    //    (matching OS liveStatus()), not just an opacity dim. A regression back
    //    to opacity-only would not be caught by host compilation. ───────────────
    #[test]
    fn block_hero_pill_swaps_live_label_to_stale_when_stale() {
        let flat = collapse_ws(BLOCK_TILE_JS);
        // The pill text node is swapped between the two reused vocabulary strings
        // (no new glossary key invented in S2 — 'STALE'/'LIVE' already exist in
        // the axe surface vocabulary).
        assert!(
            flat.contains("var lpLabel = stale ? 'STALE' : 'LIVE'")
                || flat.contains("var lpLabel=stale?'STALE':'LIVE'"),
            "COMP-BLOCKTILE: the block hero pill MUST flip its LABEL to 'STALE' \
             (else 'LIVE') when stale, matching OS CurrentBlockCard.liveStatus() — \
             opacity-dim alone is the regressed pre-S2 behavior"
        );
        // The text-swap mutates the pill's text node only (preserving the leading
        // <span class="live-dot"> affordance) — NOT a wholesale innerHTML rebuild
        // that would drop the dot.
        assert!(
            flat.contains("lp.lastChild"),
            "COMP-BLOCKTILE: the STALE swap must target the pill text node \
             (lp.lastChild) so the leading <span class=\"live-dot\"> survives"
        );
        // A 'stale' class is toggled and the stale tint references the token ROLE
        // var(--yellow) — never a literal hex (S1 token drift-validators stay
        // green; components reference roles, not values).
        assert!(
            flat.contains("lp.classList.add('stale')"),
            "COMP-BLOCKTILE: the stale pill must toggle a 'stale' class"
        );
        assert!(
            flat.contains("var(--yellow)"),
            "COMP-BLOCKTILE: the stale tint must reference the token ROLE \
             var(--yellow), never a literal hex"
        );
    }

    // ── COMP-CHIPSTRIP: the ChipGrid per-chip state is the CLOSED shared enum
    //    idle | active | warm | hot | error (component-contract §4 Level B,
    //    asic-chips.js chipState()). Pin every member + the absence of any other
    //    state token, so a future edit can't widen/rename the closed vocab. ─────
    #[test]
    fn chip_state_emits_only_the_closed_shared_enum() {
        let flat = collapse_ws(ASIC_CHIPS_JS);
        // chipState() is the closed-enum derivation function.
        assert!(
            flat.contains("function chipState(c)"),
            "COMP-CHIPSTRIP: asic-chips.js must keep chipState(c) as the closed \
             per-chip state derivation"
        );
        // Every member of the closed enum is returned.
        for member in [
            "return 'error'",
            "return 'idle'",
            "return 'hot'",
            "return 'warm'",
            "return 'active'",
        ] {
            assert!(
                flat.contains(member),
                "COMP-CHIPSTRIP: chipState() must emit the closed enum member \
                 `{member}` (idle|active|warm|hot|error)"
            );
        }
        // The temperature ladder thresholds are the contracted ones
        // (t>=70 hot, t>=55 warm, t>=40 active) — not arbitrary values.
        assert!(
            flat.contains("t >= 70") || flat.contains("t>=70"),
            "COMP-CHIPSTRIP: the 'hot' threshold must be t>=70 (contract §4)"
        );
        assert!(
            flat.contains("t >= 55") || flat.contains("t>=55"),
            "COMP-CHIPSTRIP: the 'warm' threshold must be t>=55 (contract §4)"
        );
    }

    // ── COMP-CHIPSTRIP: honest-null temp. An unknown/absent temperature renders
    //    the em-dash '--', never a fabricated 0 — the no-data honesty contract
    //    (terminology TERM-6). The hasTemp guard + chipState's t==null→idle path
    //    enforce it. ────────────────────────────────────────────────────────────
    #[test]
    fn chip_temp_honest_null_renders_em_dash_not_fabricated_zero() {
        let flat = collapse_ws(ASIC_CHIPS_JS);
        // The hasTemp honest-null guard.
        assert!(
            flat.contains("isFinite(c.temp)"),
            "COMP-CHIPSTRIP: the temp render must guard on isFinite(c.temp) \
             (honest-null), not assume a number"
        );
        // The tile renders the em-dash '--' when temp is absent, never a fake 0.
        assert!(
            flat.contains("c.temp.toFixed(0) : '--'") || flat.contains("c.temp.toFixed(0):'--'"),
            "COMP-CHIPSTRIP: an absent temp must render the em-dash '--', \
             never a fabricated 0"
        );
        // In chipState(), a null temp on a non-error chip resolves to 'idle'
        // (not a fabricated active/warm state).
        assert!(
            flat.contains("t == null) return 'idle'") || flat.contains("t==null)return'idle'"),
            "COMP-CHIPSTRIP: a null temp on a live chip must resolve to 'idle', \
             never a fabricated thermal state"
        );
    }

    // ── ANTI-TRIM identity pin: the [axe-only-solo] coinbase user-reward
    //    VERIFICATION (terminology-lexicon §3, keep-unique §4.6) is axe-led and
    //    must NEVER be trimmed toward the OS shell by a 'conformance' edit. Pin
    //    the renderer + the verified/heuristic source tags so a future
    //    simplification can't silently strip the solo-verification block. ───────
    #[test]
    fn coinbase_user_reward_verification_survives_as_axe_only_identity() {
        let flat = collapse_ws(BLOCK_TILE_JS);
        // The coinbase payout renderer is preserved.
        assert!(
            flat.contains("function renderCoinbasePayout(inf)"),
            "ANTI-TRIM (terminology §3 [axe-only-solo]): renderCoinbasePayout(inf) \
             — the coinbase user-reward verification block — must SURVIVE; it is \
             axe-led identity, never trimmed toward the OS shell"
        );
        // The verified-vs-heuristic provenance tags (the ✓ glyph form is matched
        // loosely so the exact glyph byte-form can't false-fail).
        assert!(
            flat.contains("[verified"),
            "ANTI-TRIM: the coinbase block must keep the '[verified …]' \
             source tag (real coinbase-derived reward %)"
        );
        assert!(
            flat.contains("[url heuristic]"),
            "ANTI-TRIM: the coinbase block must keep the '[url heuristic]' \
             source tag (pool-name inference when outputs aren't decoded)"
        );
        // The verifier derives the user's scripthex client-side — the mechanism
        // that makes the verification real, not cosmetic.
        assert!(
            flat.contains("addressToScriptHex"),
            "ANTI-TRIM: the verifier must keep deriving the user scripthex \
             (addressToScriptHex) so the reward % is verified, not asserted"
        );
    }

    #[test]
    fn ota_e2e_factory_flash_uses_raw_write_bin() {
        let script = include_str!("../../scripts/test_ota_e2e.sh");
        assert!(
            script.contains("espflash write-bin --port \"$COM_PORT\" 0x0 \"$FACTORY_PATH\""),
            "merged factory.bin images must be flashed as raw binaries at 0x0"
        );
        assert!(
            !script.contains("espflash flash --port \"$COM_PORT\"")
                || !script.contains("\"$FACTORY_PATH\""),
            "test_ota_e2e.sh must not use espflash flash for merged factory.bin payloads"
        );
    }

    #[test]
    fn package_verifier_and_factory_flash_map_are_wired() {
        let e2e = include_str!("../../scripts/test_ota_e2e.sh");
        let sh_packager = include_str!("../../scripts/package-firmware.sh");
        let ps_packager = include_str!("../../scripts/package-firmware.ps1");
        let verifier = include_str!("../../scripts/verify_ota_package.py");

        assert!(
            e2e.contains("verify_ota_package.py"),
            "the e2e gate must run the offline package verifier before live planning"
        );
        assert!(sh_packager.contains("\"factoryFlashMap\""));
        assert!(ps_packager.contains("factoryFlashMap = @("));
        for token in ["promotionReceiptId", "hardwareEvidenceIndexSha256"] {
            assert!(
                sh_packager.contains(token) && ps_packager.contains(token),
                "both packagers must retain production-evidence trace field {token}"
            );
        }
        for token in [
            "bootloader",
            "partition-table",
            "ota-data-initial",
            "update",
            "0x20000",
            "canonical_ota_message",
            "canonical_bundle_message",
            "verify_ed25519",
            "PUBLIC_TARGET_DEVICE_MODELS",
            "allow_internal_targets",
            "otaSignatureAlgorithm",
            "signatureAlgorithm",
            "promotionReceiptId",
            "hardwareEvidenceIndexSha256",
            "production_claim_errors",
        ] {
            assert!(
                verifier.contains(token),
                "verify_ota_package.py must retain flash-map/signature token {token}"
            );
        }
    }

    #[test]
    fn release_build_stamp_can_be_reproduced_from_source_date_epoch() {
        let build_rs = include_str!("../../dcentaxe/build.rs");
        let gauntlet = include_str!("../../scripts/production_gauntlet.py");
        assert!(build_rs.contains("std::env::var(\"SOURCE_DATE_EPOCH\")"));
        assert!(build_rs.contains("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH"));
        assert!(gauntlet.contains("env.setdefault(\"SOURCE_DATE_EPOCH\", source_date_epoch())"));
    }

    #[test]
    fn public_release_build_matrix_defaults_to_toolbox_install_targets() {
        let registry: serde_json::Value =
            serde_json::from_str(include_str!("../../esp-targets.json"))
                .expect("esp-targets.json must be valid JSON");
        let sh_matrix = include_str!("../../scripts/build-matrix.sh");
        let ps_matrix = include_str!("../../scripts/build-matrix.ps1");
        let release_workflow =
            include_str!("../../../../.github/workflows/dcentos-esp-release.yml");
        let ci_matrix_workflow =
            include_str!("../../../../.github/workflows/bitaxe-build-matrix.yml");
        let expected_public = [
            "bitaxe-max",
            "bitaxe-ultra",
            "bitaxe-supra",
            "bitaxe-gamma",
            "bitaxe-hex-ultra",
            "bitaxe-hex-supra",
        ];
        let targets = registry["targets"]
            .as_array()
            .expect("target registry must contain an array");
        assert_eq!(
            targets.len(),
            37,
            "every compiled board needs one registry row"
        );
        let public_targets: Vec<&str> = targets
            .iter()
            .filter(|target| target["release_scope"] == "public")
            .map(|target| {
                target["board_target"]
                    .as_str()
                    .expect("board_target must be a string")
            })
            .collect();
        assert_eq!(public_targets, expected_public);

        assert!(
            sh_matrix.contains("target_matrix.py") && sh_matrix.contains("build_scope public"),
            "POSIX matrix must derive the default public slice from the registry"
        );
        assert!(
            sh_matrix.contains("INCLUDE_INTERNAL_TARGETS")
                && ps_matrix.contains("[switch]$IncludeInternalTargets"),
            "internal targets must remain opt-in in both local matrix runners"
        );
        assert!(
            ps_matrix.contains("esp-targets.json") && ps_matrix.contains("release_scope"),
            "PowerShell matrix must derive its ownership slices from the registry"
        );
        assert!(
            release_workflow.contains("target_matrix.py list --scope public --format github"),
            "signed release workflow must plan a dynamic public matrix"
        );
        assert!(
            release_workflow.contains("target['package_policy'] == 'public'")
                && ci_matrix_workflow.contains("target['package_policy'] == 'public'"),
            "both public package validators must derive exact device bindings from the registry"
        );
        assert!(
            ci_matrix_workflow.contains("found_boards == set(expected_models)"),
            "root build-matrix workflow must exact-check the public package set"
        );
    }

    #[test]
    fn ota_partition_size_matches_api_upload_limit() {
        let partitions = include_str!("../../partitions.csv");
        let ota0 = partitions
            .lines()
            .find(|line| line.trim_start().starts_with("ota_0,"))
            .expect("partitions.csv must define ota_0");
        let cols: Vec<&str> = ota0.split(',').map(str::trim).collect();
        assert_eq!(
            cols.get(3),
            Some(&"0x20000"),
            "ota_0 offset is the factory update offset"
        );
        assert_eq!(cols.get(4), Some(&"0x300000"), "ota_0 size must stay 3 MB");
        assert!(
            API_RS.contains("const MAX_FIRMWARE_SIZE: usize = 3 * 1024 * 1024"),
            "OTA upload max must match partitions.csv ota_0 size"
        );
    }
}

/// The release/evidence registry is not only packaging metadata: its
/// `runtime_mode` and `install_policy` must agree with the compiled board
/// safety gate, and the selected row must reach both operator-facing APIs.
#[cfg(test)]
mod deployment_policy_guards {
    use dcentaxe_hal::board::{BitAxeModel, BoardConfig};

    const REGISTRY: &str = include_str!("../../esp-targets.json");
    const BUILD_RS: &str = include_str!("../../dcentaxe/build.rs");
    const API_RS: &str = include_str!("../../dcentaxe/src/api.rs");
    const AUTH_RS: &str = include_str!("../../dcentaxe/src/auth.rs");
    const MQTT_RS: &str = include_str!("../../dcentaxe/src/mqtt.rs");
    const GAUNTLET_PY: &str = include_str!("../../scripts/production_gauntlet.py");
    const HARDWARE_EVIDENCE_PY: &str = include_str!("../../scripts/hardware_evidence.py");
    const PROMOTION_CANDIDATE_PY: &str = include_str!("../../scripts/promotion_candidate.py");
    const HARDWARE_SESSION_PY: &str = include_str!("../../scripts/hardware_session.py");
    const HARDWARE_EVIDENCE_INDEX: &str = include_str!("../../hardware-evidence/index.json");
    const API_SYSTEM_INFO_RS: &str = include_str!("../../dcentaxe/src/api_system_info.rs");
    const DASHBOARD_RS: &str = include_str!("../../dcentaxe/src/dashboard.rs");

    #[test]
    fn registry_runtime_mode_matches_the_real_board_safety_gate() {
        let registry: serde_json::Value =
            serde_json::from_str(REGISTRY).expect("esp-targets.json must parse");
        let targets = registry["targets"]
            .as_array()
            .expect("registry targets must be an array");

        for target in targets {
            let board_target = target["board_target"]
                .as_str()
                .expect("board_target must be a string");
            let device_model = target["device_model"]
                .as_str()
                .expect("device_model must be a string");
            let runtime_mode = target["runtime_mode"]
                .as_str()
                .expect("runtime_mode must be a string");
            let install_policy = target["install_policy"]
                .as_str()
                .expect("install_policy must be a string");
            let package_policy = target["package_policy"]
                .as_str()
                .expect("package_policy must be a string");
            let model = BitAxeModel::from_device_model(device_model)
                .unwrap_or_else(|| panic!("{board_target}: device model is not registered"));
            assert_eq!(model.board_target(), board_target);
            let board = BoardConfig::for_model(model);

            match runtime_mode {
                "mining" => {
                    assert!(
                        board.validate().is_ok() && board.mining_capable(),
                        "{board_target}: registry says mining but BoardConfig refuses it"
                    );
                    assert_ne!(install_policy, "blocked", "{board_target}");
                }
                "identity-only" => {
                    assert!(
                        board.mining_capable() && board.validate().is_err(),
                        "{board_target}: identity-only registry row must fail the real mining gate"
                    );
                    assert_eq!(install_policy, "blocked", "{board_target}");
                    assert_eq!(package_policy, "diagnostic", "{board_target}");
                }
                other => panic!("{board_target}: unsupported runtime_mode {other}"),
            }
        }
    }

    #[test]
    fn build_policy_reaches_capabilities_system_info_and_dashboard() {
        for token in [
            "DCENTAXE_HARDWARE_FAMILY",
            "DCENTAXE_SUPPORT_TIER",
            "DCENTAXE_EVIDENCE_LEVEL",
            "DCENTAXE_RUNTIME_MODE",
            "DCENTAXE_INSTALL_POLICY",
            "DCENTAXE_PACKAGE_POLICY",
            "DCENTAXE_FLASH_LAYOUT",
            "DCENTAXE_PRODUCTION_BLOCKERS_JSON",
        ] {
            assert!(BUILD_RS.contains(token), "build.rs must emit {token}");
            assert!(
                API_RS.contains(token),
                "operator API construction must consume {token}"
            );
        }
        assert!(BUILD_RS.contains("../esp-targets.json"));
        assert!(BUILD_RS.contains("emit_registry_metadata("));
        assert!(BUILD_RS.contains("git_dirty"));
        assert!(BUILD_RS.contains("DCENTAXE_PROMOTION_RECEIPT_ID"));
        assert!(API_RS.contains("option_env!(\"DCENTAXE_PROMOTION_RECEIPT_ID\")"));
        assert!(API_SYSTEM_INFO_RS.contains("pub promotion_receipt_id: Option<&'static str>"));
        assert!(API_SYSTEM_INFO_RS.contains("pub deployment: DeploymentView<'a>"));
        assert!(DASHBOARD_RS.contains("id=\"deploymentBanner\""));
        assert!(DASHBOARD_RS.contains("d.dcentaxe.deployment"));
        assert!(DASHBOARD_RS.contains("sysProductionBlockers"));
        assert!(
            AUTH_RS.contains("pub(crate) fn deployment_mutations_allowed(state: &SharedState)")
                && AUTH_RS.contains("fn authorize_deployment_mutation(state: &SharedState)")
                && AUTH_RS.contains("DCENTAXE_RUNTIME_MODE")
                && AUTH_RS.contains("DCENTAXE_INSTALL_POLICY")
                && AUTH_RS.contains("mining_allowed_without_lab_bypass"),
            "REST/MCP writes must enforce both compiled policy and runtime board safety"
        );
        assert!(
            AUTH_RS
                .matches("authorize_deployment_mutation(state)?;")
                .count()
                >= 2,
            "both REST writes and MCP controls must pass the deployment gate"
        );
        assert!(
            MQTT_RS.contains("sync_channel(MQTT_COMMAND_QUEUE_CAPACITY)")
                && MQTT_RS.contains("details != Details::Complete")
                && MQTT_RS.contains("command_tx.try_send(inbound)")
                && MQTT_RS.contains(".subscribe(&topic, QoS::AtLeastOnce)")
                && MQTT_RS.contains("fn apply_inbound_command(")
                && MQTT_RS.contains("validate_autotune_target(")
                && MQTT_RS.contains("deployment_allows_operational_mutations(")
                && MQTT_RS.contains("command_discovery_tombstones(device_id)"),
            "real esp-idf MQTT transport must bound, subscribe, policy-check, validate, apply, and tombstone controls"
        );
        assert!(
            API_RS.contains("commands_enabled: crate::mqtt_ha::command_surface_enabled(")
                && API_RS.contains("deployment_allows_operational_mutations("),
            "system info must report the effective policy-gated MQTT command surface"
        );
        assert!(
            !MQTT_RS.contains("EspMqttClient::new_cb(&url, &conf, |_event| {})"),
            "the ESP MQTT callback must never silently drop every inbound event"
        );
    }

    #[test]
    fn production_promotion_requires_a_hashed_exact_sku_receipt() {
        let registry: serde_json::Value = serde_json::from_str(REGISTRY).unwrap();
        let contract = &registry["production_gate_contract"];
        assert_eq!(contract["minimum_soak_seconds"], 259_200);
        assert_eq!(contract["artifact_schema"], 1);
        assert_eq!(
            contract["artifact_authority"],
            "observed-exact-sku-hardware-gate"
        );
        for gate in [
            "exact-sku-identity",
            "safe-boot",
            "fail-safe-power-cut",
            "trusted-thermal",
            "accepted-share",
            "ota-rollback",
            "sustained-soak",
            "mqtt-command-roundtrip",
        ] {
            assert!(
                contract["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| item == gate),
                "production gate contract must retain {gate}"
            );
        }
        assert!(GAUNTLET_PY.contains("and target[\"support_tier\"] == \"production\""));
        assert!(GAUNTLET_PY.contains("and target[\"install_policy\"] == \"production\""));
        assert!(GAUNTLET_PY.contains("and promotion[\"qualified\"]"));
        assert!(GAUNTLET_PY.contains("and receipt_firmware_matches_package"));
        assert!(GAUNTLET_PY.contains("package_version == promotion.get(\"firmware_version\")"));
        assert!(GAUNTLET_PY.contains("and production_signatures_verified"));
        assert!(HARDWARE_EVIDENCE_PY.contains("unit_fingerprint_sha256"));
        assert!(HARDWARE_EVIDENCE_PY.contains("gate {gate_name} artifact sha256 mismatch"));
        assert!(HARDWARE_EVIDENCE_PY.contains("operator and witness must be distinct"));
        assert!(PROMOTION_CANDIDATE_PY.contains("qualification-only-not-publishable"));
        assert!(PROMOTION_CANDIDATE_PY.contains("candidate_id"));
        assert!(PROMOTION_CANDIDATE_PY.contains("source_date_epoch"));
        assert!(PROMOTION_CANDIDATE_PY.contains("candidate_source_is_clean"));
        assert!(PROMOTION_CANDIDATE_PY.contains("git_head"));
        assert!(PROMOTION_CANDIDATE_PY.contains("admit-package"));
        assert!(PROMOTION_CANDIDATE_PY.contains("without rebuilding payloads"));
        assert!(HARDWARE_EVIDENCE_PY.contains("promotion_candidate.candidate_id"));
        assert!(HARDWARE_EVIDENCE_PY.contains("reported_promotion_receipt_id"));
        assert!(HARDWARE_SESSION_PY.contains("authorization-gated-exact-sku-hardware-session"));
        assert!(HARDWARE_SESSION_PY.contains("authorize-live-"));
        assert!(HARDWARE_SESSION_PY.contains("finalize-"));
        assert!(HARDWARE_SESSION_PY.contains("Registry production admission remains a separate"));
        let index: serde_json::Value = serde_json::from_str(HARDWARE_EVIDENCE_INDEX).unwrap();
        assert_eq!(index["authority"], "retained-exact-sku-hardware-receipts");
    }
}

/// H1 — AxeOS-compat `/api/system/info` WIRE CONTRACT guard.
///
/// `api_system_info.rs` builds the `/api/system/info` response with
/// `#[serde(rename_all = "camelCase")]` plus a set of explicit `#[serde(rename =
/// "...")]` per-field renames that keep the JSON byte-identical to AxeOS so
/// BitAxeHQ / Swarm / pyasic consume it unchanged. That module's doc declares this
/// a CRITICAL contract, but NOTHING enforced it: it is NOT in the `#[path]` set
/// and has no `#[cfg(test)]`, so a dropped rename or a `rename_all` flip would
/// silently break every AxeOS-compat consumer with zero CI signal.
///
/// `api_system_info.rs` is a pure serde-derive module that DOES host-compile
/// (no esp-idf deps), but pinning the contract against the source TEXT via
/// `include_str!` — exactly like `dcent_design_language_guards` /
/// `mcp_auth_contract_guards` — catches a rename drift regardless of whether the
/// struct still compiles (a renamed-but-still-valid field compiles fine yet breaks
/// the wire). This is the host-testable durability mechanism for the wire format.
///
/// Assertions are whitespace-robust (collapse runs of ASCII whitespace) so a
/// rustfmt reflow of an attribute cannot flip a guard.
#[cfg(test)]
mod api_wire_contract_guards {
    const API_SYSTEM_INFO_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/api_system_info.rs"
    ));

    /// Collapse every run of ASCII whitespace to a single space so a reflow of an
    /// attribute / struct line cannot dodge a substring match.
    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── (1) the response struct uses camelCase, and the flag is ON the struct ──
    // A flip of `rename_all` (e.g. to snake_case) — or moving it off the response
    // struct — would silently rename ~140 keys and break every AxeOS consumer.
    #[test]
    fn response_struct_is_camel_case() {
        let flat = collapse_ws(API_SYSTEM_INFO_RS);
        assert!(
            flat.contains("#[serde(rename_all = \"camelCase\")] pub struct SystemInfoResponse"),
            "the SystemInfoResponse struct MUST keep `#[serde(rename_all = \"camelCase\")]` \
             immediately above it — a flip renames every AxeOS-compat key"
        );
    }

    // ── (2) every load-bearing explicit per-field rename literal is present ─────
    // These are the EXACT renames found in api_system_info.rs (the camelCase
    // derive cannot produce `hashRate`/`ASICModel`/`stratumURL`-style mixed-case or
    // the snake_case `overheat_mode` AxeOS keys, so each is pinned explicitly). The
    // closing quote in the match disambiguates `hashRate` from `hashRate_1m`, etc.
    #[test]
    fn axeos_field_renames_are_pinned() {
        let flat = collapse_ws(API_SYSTEM_INFO_RS);
        for key in [
            "vrTemp",
            "hashRate",
            "hashRate_1m",
            "hashRate_5m",
            "hashRate_10m",
            "hashRate_15m",
            "hashRate_1h",
            "isPSRAMAvailable",
            "wifiRSSI",
            "ASICModel",
            "stratumURL",
            "stratumTLS",
            "fallbackStratumURL",
            "fallbackStratumTLS",
            "axeOSVersion",
            // NOTE: snake_case override of the camelCase derive — AxeOS emits
            // `overheat_mode`, NOT `overheatMode`; this rename is load-bearing.
            "overheat_mode",
        ] {
            assert!(
                flat.contains(&format!("#[serde(rename = \"{key}\")]")),
                "AxeOS-compat wire key `{key}` lost its `#[serde(rename = \"{key}\")]` — \
                 this breaks BitAxeHQ/Swarm/pyasic consumption"
            );
        }
    }

    // ── (3) the load-bearing Option / skip_serializing_if fields stay typed ─────
    // `hash_rate_1h` is `Option<f64>` (always None) so it serializes as JSON null
    // to match the legacy `hashRate_1h: null`. `last_panic` / `last_restart_reason`
    // / `temp_source` are `skip_serializing_if = "Option::is_none"` so they are
    // OMITTED when absent — dropping the skip would emit an unexpected key, and
    // dropping the Option would emit a value the legacy wire never had.
    #[test]
    fn optional_and_skipped_fields_stay_honest() {
        let flat = collapse_ws(API_SYSTEM_INFO_RS);
        assert!(
            flat.contains("pub hash_rate_1h: Option"),
            "hashRate_1h must stay `Option<f64>` so it serializes as null (legacy wire)"
        );
        for field in ["last_panic", "last_restart_reason", "temp_source"] {
            assert!(
                flat.contains(&format!(
                    "#[serde(skip_serializing_if = \"Option::is_none\")] pub {field}: Option"
                )),
                "`{field}` must keep `skip_serializing_if = \"Option::is_none\"` over an Option \
                 so it is OMITTED (not emitted) when absent — preserving the legacy wire shape"
            );
        }
    }

    // ── (4) M-dash-1 additive honesty companion stays on the wire ──────────────
    // `acceptanceRate` is a DCENT-original field (NOT AxeOS). The M-dash-1 honesty
    // fix added the additive `acceptanceRateKnown: bool` companion so a freshly-
    // booted miner (zero confirmed shares) is not read as a real 100% accept rate.
    // Pin both fields so the honesty wiring cannot be silently dropped.
    #[test]
    fn acceptance_rate_known_companion_present() {
        let flat = collapse_ws(API_SYSTEM_INFO_RS);
        assert!(
            flat.contains("pub acceptance_rate: f64"),
            "acceptance_rate (DCENT-original) must stay on the wire"
        );
        assert!(
            flat.contains("pub acceptance_rate_known: bool"),
            "M-dash-1: the additive `acceptanceRateKnown` honesty companion must stay on the wire \
             so zero-share `acceptanceRate` cannot read as a real 100% accept rate"
        );
    }

    #[test]
    fn stratum_v2_experimental_companion_present() {
        let flat = collapse_ws(API_SYSTEM_INFO_RS);
        assert!(
            flat.contains("pub stratum_v2_available: bool"),
            "/api/system/info must keep the additive stratumV2Available flag"
        );
        assert!(
            flat.contains("pub stratum_v2_experimental: bool"),
            "ESP-5: /api/system/info must keep stratumV2Experimental so SV2 maturity is honest"
        );
    }
}

/// LoRa `/mcp` registry contract guards (Track C W2.6).
///
/// Two legs, exactly as the brief specifies:
///   * a REAL compile-linked test of `dcentaxe_lora::mcp` proving that with `lora`
///     ON, exactly ONE lora tool is mutating and it is `OwnerControl`; and
///   * a structural guard over the `dcentaxe/src/mcp.rs` source TEXT proving that
///     with `lora` OFF the `/mcp` tools/list + dispatch are BYTE-IDENTICAL — i.e.
///     every lora tool-name string lives ONLY inside the single
///     `#[cfg(feature = "lora")]` `LORA-MCP-REGION`, and both call sites are
///     cfg-gated. `mcp.rs` is the espidf-only binary-crate source (cannot
///     host-compile), so the byte-identical proof is text-based (whitespace-robust,
///     additive) — the same pattern as `mcp_auth_contract_guards`.
#[cfg(test)]
mod mcp_lora_contract_guards {
    use dcentaxe_lora::mcp::{tools, McpAccess};

    const MCP_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/mcp.rs"
    ));
    const LORA_TASK_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/lora_task.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ── (1) with lora ON, EXACTLY ONE lora tool is mutating + it is OwnerControl ─
    // Real compile-linked check against the shared crate — not a text pin. A future
    // edit that adds a second mutating tool, or downgrades `lora_send_beacon` to a
    // passwordless read, fails HERE (the BAP-2 / 2026-06-12 passwordless-mutate ban).
    #[test]
    fn lora_mcp_exactly_one_owner_control_tool() {
        let t = tools();
        assert_eq!(t.len(), 3, "the LoRa MCP surface is exactly 3 tools");
        let mutating: Vec<&str> = t
            .iter()
            .filter(|x| x.requires_auth())
            .map(|x| x.name)
            .collect();
        assert_eq!(
            mutating,
            ["lora_send_beacon"],
            "exactly one lora tool is mutating and it MUST be lora_send_beacon"
        );
        for tool in t.iter() {
            match tool.name {
                "lora_send_beacon" => assert_eq!(
                    tool.access,
                    McpAccess::OwnerControl,
                    "lora_send_beacon must be OwnerControl (owner-gated)"
                ),
                "lora_status" | "get_mesh_peers" => assert_eq!(
                    tool.access,
                    McpAccess::Read,
                    "{} must be a read tool",
                    tool.name
                ),
                other => panic!("unexpected lora tool name `{other}`"),
            }
        }
    }

    // ── (2) with lora OFF, the /mcp tools/list + dispatch are BYTE-IDENTICAL ──────
    // All lora tool-NAME strings must live ONLY inside the single cfg-gated
    // LORA-MCP-REGION. The two call sites reference `lora_mcp::*` helpers (never a
    // quoted tool name), so with the feature OFF the region + call sites compile out
    // and nothing lora reaches tools/list or dispatch.
    #[test]
    fn lora_mcp_names_only_in_cfg_region() {
        let begin = MCP_RS
            .find("LORA-MCP-REGION BEGIN")
            .expect("mcp.rs must delimit the lora region (LORA-MCP-REGION BEGIN)");
        let end = MCP_RS
            .find("LORA-MCP-REGION END")
            .expect("mcp.rs must close the lora region (LORA-MCP-REGION END)");
        assert!(begin < end, "region markers out of order");
        let region = &MCP_RS[begin..end];
        // The region's module is cfg(feature="lora")-gated.
        assert!(
            region.contains("#[cfg(feature = \"lora\")]"),
            "the lora_mcp module must be #[cfg(feature = \"lora\")]-gated"
        );
        // Every raw lora tool-name string appears ONLY inside the region.
        let outside = format!("{}{}", &MCP_RS[..begin], &MCP_RS[end..]);
        for quoted in [
            "\"lora_status\"",
            "\"lora_send_beacon\"",
            "\"get_mesh_peers\"",
        ] {
            assert!(
                region.contains(quoted),
                "{quoted} must appear inside the lora region (the dispatch/schema wiring)"
            );
            assert!(
                !outside.contains(quoted),
                "{quoted} must NOT appear outside the cfg-gated lora region — the /mcp tools/list \
                 + dispatch must be byte-identical when `lora` is OFF"
            );
        }
    }

    // ── (3) both call sites are cfg-gated + send_beacon is owner-control fail-closed ─
    #[test]
    fn lora_mcp_call_sites_gated_and_beacon_owner_controlled() {
        let flat = collapse_ws(MCP_RS);
        // tools/list injection is feature-gated.
        assert!(
            flat.contains("#[cfg(feature = \"lora\")] lora_mcp::append_tools(tools);"),
            "the tools/list lora append must be #[cfg(feature = \"lora\")]-gated"
        );
        // dispatch arm is feature-gated + routes to the gated region helper.
        assert!(
            flat.contains(
                "#[cfg(feature = \"lora\")] n if lora_mcp::is_lora_tool(n) => return lora_mcp::dispatch(state, n, &args, auth),"
            ),
            "the tools/call lora dispatch arm must be #[cfg(feature = \"lora\")]-gated"
        );
        // lora_send_beacon is fail-closed on !control_authorized (owner control) and
        // routes through the duty-governed request_beacon (never a raw radio poke).
        let region_flat = {
            let begin = flat.find("LORA-MCP-REGION BEGIN").unwrap();
            let end = flat.find("LORA-MCP-REGION END").unwrap();
            flat[begin..end].to_string()
        };
        assert!(
            region_flat.contains("if !auth.control_authorized"),
            "lora_send_beacon must be refused fail-closed unless authorize_mcp_control() passed"
        );
        assert!(
            region_flat.contains("crate::lora_task::request_beacon(state"),
            "lora_send_beacon must route through the duty-governed lora_task::request_beacon"
        );
    }

    // ── (4) the duty governor + honest refusal + fail-soft init are wired ─────────
    // lora_task.rs is espidf-only (cannot host-compile), so pin its load-bearing
    // honesty invariants against the source TEXT: a duty-clamped beacon returns the
    // honest `"duty_budget"` reason (never a fake "sent"), and a radio-init failure
    // is fail-soft (mining continues).
    #[test]
    fn lora_task_is_duty_governed_honest_and_fail_soft() {
        let flat = collapse_ws(LORA_TASK_RS);
        assert!(
            flat.contains("fn request_beacon"),
            "lora_task must expose request_beacon for the MCP owner-control tool"
        );
        assert!(
            flat.contains("duty.try_acquire"),
            "request_beacon (and the task beacons) must gate transmits on the duty governor"
        );
        assert!(
            flat.contains("\"duty_budget\""),
            "a duty-clamped beacon must return the honest reason \"duty_budget\" (not a fake sent)"
        );
        assert!(
            flat.contains("mining continues"),
            "a radio cold-boot failure must be fail-soft (log once, mining continues)"
        );
    }
}

// ── XPSAFE-8: single-fan Hex declaration is WIRED, not merely available ──────
//
// `BoardConfig::declared_fan_tach_missing` is a classifier. A classifier with
// no production consumer changes no behavior — the exact failure shape this
// workspace has hit repeatedly (`RailBringup` shipped with zero callers for a
// day while the whole suite stayed green). `main.rs` is `target_os = "espidf"`
// only and is never host-compiled, so no host test can call these gates.
// These source contracts pin the wiring instead.
#[cfg(test)]
mod xpsafe8_fan_population_wiring {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const BOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/board.rs"
    ));
    const CONFIG_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/config.rs"
    ));

    /// The HAL still exposes the predicate the gates are supposed to consume.
    #[test]
    fn hal_exposes_the_declared_fan_predicate() {
        assert!(
            BOARD_RS.contains("pub fn declared_fan_tach_missing"),
            "BoardConfig::declared_fan_tach_missing was renamed or removed — the \
             main.rs boot and runtime fan gates consume it by name"
        );
        assert!(
            BOARD_RS.contains("pub fn primary_tach_rpm"),
            "BoardConfig::primary_tach_rpm was renamed or removed"
        );
    }

    /// The operator's declaration actually reaches the BoardConfig the gates read.
    ///
    /// Without this call the config field would round-trip through NVS and be
    /// silently ignored, leaving a single-fan unit permanently blocked while the
    /// dashboard cheerfully reported the declaration as saved.
    #[test]
    fn config_applies_the_declared_population_to_the_board() {
        assert!(
            CONFIG_RS.contains("pub fans_populated: FanPopulation"),
            "DcentAxeConfig::fans_populated was renamed or removed"
        );
        assert!(
            CONFIG_RS.contains("board.set_fans_populated(self.fans_populated)"),
            "DcentAxeConfig::board_config no longer applies fans_populated — the \
             operator declaration would be persisted and then ignored"
        );
    }

    /// The BOOT gate consumes the predicate, and the bare both-fans expression
    /// it replaced has not crept back in.
    #[test]
    fn boot_gate_consumes_the_declared_predicate() {
        assert!(
            MAIN_RS.contains("board_config.declared_fan_tach_missing(rpm1, rpm2)"),
            "the EMC2302 boot tach gate no longer consumes declared_fan_tach_missing"
        );
        assert!(
            MAIN_RS.contains("board_config.declared_fan_tach_proven(rpm1, rpm2)"),
            "the EMC2302 boot retry loop no longer exits on the declared population"
        );
        // The gate must still be scoped by the mandatory-tach predicate: this
        // change was never allowed to make tach proof optional for a Hex.
        assert!(
            MAIN_RS.contains("board_config.requires_fan_tach()"),
            "the EMC2302 boot gate dropped requires_fan_tach() — a Hex must still \
             prove a tachometer; fan population only scopes WHICH fans"
        );
    }

    /// The RUNTIME stall kill consumes it too.
    ///
    /// Boot-only wiring would let a declared fan stall mid-soak without tripping
    /// — the exact failure the mandatory-tach posture exists to prevent.
    #[test]
    fn runtime_stall_kill_consumes_the_declared_predicate() {
        let marker = "let dead = fan_speed > 0 && board_config.declared_fan_tach_missing";
        assert!(
            MAIN_RS.contains(marker),
            "the EMC2302 runtime stall kill no longer consumes the declared \
             predicate — a stalled fan on a declared header would not trip"
        );
        assert!(
            MAIN_RS.contains("let rpm = board_config.primary_tach_rpm(rpm1, rpm2);"),
            "the runtime primary RPM no longer follows the declared population — a \
             fan2-only unit would feed a hardcoded 0 into the stall kill"
        );
    }

    /// The bare `rpm1 == 0 || rpm2 == 0` form must not return to the EMC2302
    /// gates. Split so this assertion never matches its own source text.
    #[test]
    fn the_unscoped_both_fans_expression_is_gone_from_the_emc2302_gates() {
        let bare = concat!("(rpm1 == 0", " || rpm2 == 0)");
        assert!(
            !MAIN_RS.contains(bare),
            "the unscoped both-fans expression is back in main.rs — it ignores the \
             operator's declared fan population and permanently blocks a \
             legitimately single-fan unit"
        );
    }
}

/// OLED panel-budget backpressure (lane P1-I2).
///
/// `display_convert` makes the panel's real capacity measurable — 21 columns by
/// 4 rows on the 128x32 SSD1306 — but a metric with no consumer changes nothing
///. This
/// module is that consumer: it measures every fail-closed `mining_block_reason`
/// in `main.rs`, the strings the panel shows an operator when the board refuses
/// to mine, against the budget.
///
/// Today **every one of them overflows** and is silently clipped mid-word by
/// `draw_centered` (`display_convert::centered_is_clipped`). This lane does NOT
/// fix that — the fix is a wrap, or a short code plus a dashboard pointer, and
/// it belongs to an O lane. What this module does is stop the number getting
/// worse: the assertion is a **ratchet**, not a pin. Adding a 30th over-budget
/// reason fails; shortening reasons is welcome and the constant comes down with
/// the fix.
#[cfg(test)]
mod oled_panel_budget_guards {
    use crate::display_convert::{centered_is_clipped, line_fits, TEXT_COLUMNS};

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    /// Every `mining_block_reason = Some(...)` assignment, reduced to the
    /// static text of its string literals (runtime `{}` args only make the
    /// rendered line longer, never shorter).
    ///
    /// The source is normalised to LF first: this repository sets
    /// `core.autocrlf = true`, so a fresh Windows worktree checks `main.rs` out
    /// with CRLF and any matcher that assumes bare `\n` silently stops matching
    /// there. Two existing guards in this crate have that defect today.
    fn block_reason_literals() -> Vec<String> {
        let src = MAIN_RS.replace("\r\n", "\n");
        let bytes = src.as_bytes();
        let mut found = Vec::new();
        let needle = "mining_block_reason";
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(needle) {
            let mut i = at + rel + needle.len();
            // Advance the cursor first so a non-matching hit (the `let mut
            // mining_block_reason: Option<String>` declaration) cannot loop.
            at = i;
            // Tolerate any wrapping rustfmt chose around `= Some(`.
            while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'=' {
                continue;
            }
            i += 1;
            while i < bytes.len() && (bytes[i] as char).is_whitespace() {
                i += 1;
            }
            if !src[i..].starts_with("Some(") {
                continue;
            }
            i += "Some(".len();
            let mut depth = 1i32;
            let mut in_str = false;
            let mut escaped = false;
            let mut text = String::new();
            while i < bytes.len() && depth > 0 {
                let c = bytes[i] as char;
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                        text.push(' ');
                    } else {
                        text.push(c);
                    }
                } else {
                    match c {
                        '"' => in_str = true,
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                }
                i += 1;
            }
            found.push(text.trim().to_string());
            at = i;
        }
        found
    }

    /// The parser must keep finding the reasons; a silent zero would make the
    /// ratchet below vacuously green.
    #[test]
    fn the_fail_closed_reason_set_is_still_locatable_in_main_rs() {
        let reasons = block_reason_literals();
        assert!(
            reasons.len() >= 25,
            "only {} mining_block_reason assignments were parsed out of main.rs — \
             the matcher has drifted and the panel-budget ratchet below is vacuous",
            reasons.len()
        );
        // P1-O1 RE-BOUND this half; it was not dropped and it was not loosened.
        // `main.rs` no longer holds the sentences at all: every assignment site
        // now names a `BlockReason` and the sentence moved to
        // `block_reason.rs`'s `summary()`, where the host gate can EXECUTE it
        // instead of grepping for it. The canonical over-budget reason must
        // still exist somewhere, so the check follows it to its new home rather
        // than going quiet — and it now also proves the sentence is no longer
        // reachable as a raw panel string, which the old form could not.
        assert!(
            crate::block_reason::BlockReason::ALL
                .iter()
                .any(|r| r.summary().contains("Board has no rail actuator")),
            "the canonical over-budget reason is missing from block_reason.rs — \
             it is the reason this ratchet exists and it may not simply vanish"
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("Board has no rail actuator")),
            "the sentence is back inside a `mining_block_reason = Some(...)` \
             assignment, where draw_text clips it at column 21 mid-word. It \
             belongs in block_reason.rs::summary() (log) with a code on the panel"
        );
    }

    /// RATCHET: the number of fail-closed reasons that do not fit the panel may
    /// only go DOWN, **and the constant must come down with it**.
    ///
    /// Measured 2026-09-03 at commit b3071167c: 29 of 29. Every reason an
    /// operator can be shown when their board refuses to mine is clipped at
    /// column 21 — the longest, `main.rs:3115`, loses 50 of its 71 characters
    /// and reads "Board has no rail act".
    ///
    /// # Why this is `assert_eq!` and not a one-sided `<=`
    ///
    /// Round 1 of lane P1-I2 shipped `assert!(over.len() <= 29)` plus a
    /// downward check of `over.len() >= 1`, and the P1-I2 critic pointed out
    /// that the second one is effectively vacuous: the count could drift
    /// 29 -> 28 -> ... -> 1 while the test stayed green, so the doc comment's
    /// promise that "the constant comes down with the fix" was a convention
    /// nothing enforced. A ratchet that only ratchets in one direction is a
    /// ceiling, not a ratchet. Exact equality against the named constant makes
    /// the promise executable: shortening a reason is welcome, and it fails
    /// this test until [`OVER_BUDGET_AT_P1_I2`] is lowered in the same change,
    /// which is exactly the moment the new ceiling should be recorded.
    ///
    /// The `<=` assertion is KEPT ahead of the equality so growth still reports
    /// the newly over-budget set rather than a bare count mismatch.
    #[test]
    fn no_new_fail_closed_reason_may_overflow_the_oled_panel() {
        /// The measured over-budget count this tree is pinned to. Lower it in
        /// the same change that shortens a reason; never raise it.
        ///
        /// **P1-O1 lowered it 29 -> 0**, which is the move this constant's own
        /// doc comment above prescribes ("set OVER_BUDGET_AT_P1_I2 to {} in
        /// this same change so the ratchet keeps its grip"). Every assignment
        /// site now names a `BlockReason`; the sentence lives in
        /// `block_reason.rs::summary()` and reaches the log, while the panel
        /// gets a code of at most `CODE_COLUMNS` characters and an action row.
        /// At zero the ratchet stops being a record of damage and becomes a
        /// prohibition: re-introducing ANY sentence at a
        /// `mining_block_reason = Some(...)` site fails this test.
        const OVER_BUDGET_AT_P1_I2: usize = 0;

        let reasons = block_reason_literals();
        let over: Vec<&String> = reasons
            .iter()
            .filter(|r| !line_fits(r) || centered_is_clipped(r))
            .collect();

        assert!(
            over.len() <= OVER_BUDGET_AT_P1_I2,
            "{} fail-closed reasons now exceed the {TEXT_COLUMNS}-column OLED \
             budget, up from {OVER_BUDGET_AT_P1_I2}. A reason the panel clips \
             mid-word is a reason the operator cannot act on. Wrap it over lines \
             2-3, or use a short code plus a dashboard pointer. Newly over-budget \
             set:\n{:#?}",
            over.len(),
            over
        );

        // The downward half, enforced rather than promised: a fix that shortens
        // a reason MUST lower the constant in the same change, or the pin stops
        // describing the tree it is pinning.
        assert_eq!(
            over.len(),
            OVER_BUDGET_AT_P1_I2,
            "{} fail-closed reasons exceed the {TEXT_COLUMNS}-column OLED budget, \
             but this ratchet is pinned at {OVER_BUDGET_AT_P1_I2}. If you just \
             shortened a reason: good — set OVER_BUDGET_AT_P1_I2 to {} in this \
             same change so the ratchet keeps its grip. Still over budget:\n{:#?}",
            over.len(),
            over.len(),
            over
        );
    }
}
/// ════════════════════════════════════════════════════════════════════════════
/// P1-I1 (DCENT_axe UI Gauntlet) — the PC mock server's fidelity pin.
///
/// `tools/axe_mock_server.mjs` serves the dashboard on a workstation by PARSING
/// this firmware's own `dashboard.rs` at startup: the `DASHBOARD_HTML` literal,
/// the `register_static()` asset set, and both response-header tuples. That
/// derivation was proven faithful once, by hand, on 2026-09-03 — and a proof by
/// inspection expires the moment somebody edits `dashboard.rs`.
///
/// Every screenshot, click-through and blind A/B verdict in the campaign is
/// taken against that mock, so a silent drift does not merely break a tool: it
/// turns every downstream verdict into fiction while all of them stay green.
///
/// These tests are the join. They pin the exact shapes the mock reads — the
/// asset set, both header tuples, the registration mechanism, and the accepted
/// write-route set — so any edit fails HERE with a message naming the tool to
/// update. They are a source contract only: `dashboard.rs`, `api.rs`, `auth.rs`
/// and `mcp.rs` are `target_os = "espidf"` and cannot be host-compiled, so
/// nothing else would catch it.
///
/// `axe_mock_server.mjs` is `include_str!`d deliberately: moving or deleting
/// the tool must break this gate rather than silently unbind it.
///
/// CRLF: `core.autocrlf = true` gives fresh worktrees CRLF working copies while
/// git stores LF, and two neighbouring guards in this crate already fail that
/// way (they search for an embedded "\n"). Every source read here goes through
/// `lf()` first, so this guard cannot be a false green on one checkout and a
/// false red on another.
#[cfg(test)]
mod axe_mock_server_fidelity_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const API_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/api.rs"
    ));
    const AUTH_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/auth.rs"
    ));
    const MCP_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/mcp.rs"
    ));
    const MOCK_MJS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tools/axe_mock_server.mjs"
    ));

    /// The one tool every failure message must name.
    const TOOL: &str = "DCENT_OS_ESP/tools/axe_mock_server.mjs";

    /// Normalize line endings. See the CRLF note in the module header — without
    /// this the guard is checkout-dependent, which is the same class of defect
    /// it exists to prevent.
    fn lf(s: &str) -> String {
        s.replace("\r\n", "\n")
    }

    fn skip_ws(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b'\n' || b[i] == b'\r') {
            i += 1;
        }
        i
    }

    /// Read a `"…"` literal starting at `i` (which must be the opening quote).
    /// Returns the contents and the index one past the closing quote.
    fn read_str(src: &str, i: usize) -> Option<(&str, usize)> {
        if src.as_bytes().get(i) != Some(&b'"') {
            return None;
        }
        let s = i + 1;
        let rel = src[s..].find('"')?;
        Some((&src[s..s + rel], s + rel + 1))
    }

    /// Every `("Name", "value")` header tuple literal in `block`, in source
    /// order. `("Content-Type", content_type)` — `register_static`'s per-asset
    /// variable — yields `None`, exactly as the mock records it.
    fn header_tuples(block: &str) -> Vec<(String, Option<String>)> {
        let b = block.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < b.len() {
            if b[i] != b'(' {
                i += 1;
                continue;
            }
            let j = skip_ws(b, i + 1);
            let Some((name, after_name)) = read_str(block, j) else {
                i += 1;
                continue;
            };
            // A header name is tokens and dashes only; this rejects
            // `panic!("Failed to register GET {}", path)` and friends.
            if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                i += 1;
                continue;
            }
            let k = skip_ws(b, after_name);
            if b.get(k) != Some(&b',') {
                i += 1;
                continue;
            }
            let k = skip_ws(b, k + 1);
            if let Some((value, after_value)) = read_str(block, k) {
                let m = skip_ws(b, after_value);
                if b.get(m) == Some(&b')') {
                    out.push((name.to_string(), Some(value.to_string())));
                    i = m + 1;
                    continue;
                }
            } else if block[k..].starts_with("content_type") {
                let m = skip_ws(b, k + "content_type".len());
                if b.get(m) == Some(&b')') {
                    out.push((name.to_string(), None));
                    i = m + 1;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// Slice `[from .. to)`, panicking with a mock-naming message if either
    /// anchor is gone (the mock exits 3 on the same condition).
    fn between<'a>(src: &'a str, from: &str, to: &str) -> &'a str {
        let a = src.find(from).unwrap_or_else(|| {
            panic!(
                "MOCK-FIDELITY: dashboard.rs no longer contains the anchor `{from}`. \
                 {TOOL} isolates its header block with exactly this marker and will \
                 refuse to start (PARSE FAILURE). Update the tool and this pin together."
            )
        });
        let b = src[a..].find(to).map(|off| a + off).unwrap_or_else(|| {
            panic!(
                "MOCK-FIDELITY: dashboard.rs no longer contains the anchor `{to}` after \
                 `{from}`. {TOOL} isolates its header block with exactly these markers. \
                 Update the tool and this pin together."
            )
        });
        &src[a..b]
    }

    /// Every `(METHOD, uri)` pair registered by a `fn_handler("<literal>", Method::X, …)`
    /// site in `src`. Handlers whose URI is a variable (the `register_static`
    /// helper) have no literal and are deliberately not returned here.
    fn handler_routes(src: &str) -> Vec<(String, String)> {
        let b = src.as_bytes();
        let needle = "fn_handler(";
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(needle) {
            let start = at + rel + needle.len();
            at = start;
            let i = skip_ws(b, start);
            let Some((uri, after_uri)) = read_str(src, i) else {
                continue; // URI is a variable (register_static's `path`)
            };
            let k = skip_ws(b, after_uri);
            if b.get(k) != Some(&b',') {
                continue;
            }
            let k = skip_ws(b, k + 1);
            if !src[k..].starts_with("Method::") {
                continue;
            }
            let ms = k + "Method::".len();
            let me = ms
                + src[ms..]
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(0);
            out.push((src[ms..me].to_string(), uri.to_string()));
        }
        out
    }

    /// Every `register_static(server, "<uri>", CONST, css|js)` call site, in
    /// registration order — parsed the way the mock parses it, formatting-agnostic.
    fn baked_assets(src: &str) -> Vec<(String, String)> {
        let b = src.as_bytes();
        let needle = "register_static(";
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(needle) {
            let start = at + rel + needle.len();
            at = start;
            let i = skip_ws(b, start);
            if !src[i..].starts_with("server") {
                continue; // the `fn register_static(` definition, or a doc mention
            }
            let i = skip_ws(b, i + "server".len());
            if b.get(i) != Some(&b',') {
                continue;
            }
            let i = skip_ws(b, i + 1);
            let Some((uri, after_uri)) = read_str(src, i) else { continue };
            // , CONST_NAME
            let i = skip_ws(b, after_uri);
            if b.get(i) != Some(&b',') {
                continue;
            }
            let i = skip_ws(b, i + 1);
            let ce = i + src[i..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(0);
            // , css|js
            let i = skip_ws(b, ce);
            if b.get(i) != Some(&b',') {
                continue;
            }
            let i = skip_ws(b, i + 1);
            let te = i + src[i..]
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(0);
            out.push((uri.to_string(), src[i..te].to_string()));
        }
        out
    }

    // ── MOCK-FIDELITY-1: the served asset set. ───────────────────────────────
    // The mock reads `register_static(server, "<uri>", CONST, css|js)` and
    // serves exactly that set, 404ing everything else under /dashboard/ —
    // including the four files that sit on disk but are deliberately not baked.
    // If this list moves and the mock is not updated, every screenshot in the
    // campaign is taken against a page loading the wrong asset set.
    #[test]
    fn baked_dashboard_asset_set_is_exactly_what_the_mock_serves() {
        const EXPECTED: [(&str, &str); 10] = [
            ("/dashboard/tokens.css", "css"),
            ("/dashboard/core.css", "css"),
            ("/dashboard/components.css", "css"),
            ("/dashboard/block-tile.css", "css"),
            ("/dashboard/asic-chips.css", "css"),
            ("/dashboard/framework.js", "js"),
            ("/dashboard/api.js", "js"),
            ("/dashboard/core.js", "js"),
            ("/dashboard/block-tile.js", "js"),
            ("/dashboard/asic-chips.js", "js"),
        ];
        let rs = lf(DASHBOARD_RS);
        let found = baked_assets(&rs);
        let expected: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(u, c)| (u.to_string(), c.to_string()))
            .collect();
        assert_eq!(
            found, expected,
            "MOCK-FIDELITY-1: the register_static() asset set in dashboard.rs changed.\n\
             {TOOL} derives the files it serves from exactly this list, so until it is \
             re-checked it serves a set the firmware does not.\n\
             Update {TOOL} (and its Fidelity section in tools/README.md), re-run the lane's \
             click-through, then update this pin.\n\
             found:    {found:#?}\n\
             expected: {expected:#?}"
        );

        // The four deliberately-unbaked components must stay unbaked: the
        // mock's 404-parity evidence rests on it (dashboard.rs:59-62, :69-72).
        for orphan in ["stats.css", "flow.css", "stats.js", "flow.js"] {
            assert!(
                !found.iter().any(|(u, _)| u.ends_with(orphan)),
                "MOCK-FIDELITY-1: `{orphan}` became a baked asset. {TOOL} 404s it today as \
                 firmware-accurate behaviour; that evidence is now wrong."
            );
        }
    }

    // ── MOCK-FIDELITY-2: the `/` and `/index.html` header tuple. ─────────────
    // The mock replays these headers verbatim. A cache-header change the mock
    // does not follow makes every cache/reload observation on the mock a claim
    // about a page the device does not serve.
    #[test]
    fn html_response_headers_are_exactly_what_the_mock_replays() {
        const EXPECTED: [(&str, &str); 4] = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-cache"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
        ];
        let rs = lf(DASHBOARD_RS);
        let want: Vec<(String, Option<String>)> = EXPECTED
            .iter()
            .map(|(k, v)| (k.to_string(), Some(v.to_string())))
            .collect();

        for (anchor, end) in [
            ("\"/\",", ".expect(\"Failed to register GET /\")"),
            (
                "\"/index.html\",",
                ".expect(\"Failed to register GET /index.html\")",
            ),
        ] {
            let block = between(&rs, anchor, end);
            let got = header_tuples(block);
            assert_eq!(
                got, want,
                "MOCK-FIDELITY-2: the response headers for the `{anchor}` dashboard handler \
                 changed.\n{TOOL} parses this exact tuple list out of dashboard.rs and \
                 replays it; a header it does not know about makes every cache, framing and \
                 sniffing observation taken on the mock false.\n\
                 Update {TOOL} and this pin together.\n\
                 found:    {got:#?}\n\
                 expected: {want:#?}"
            );
        }
    }

    // ── MOCK-FIDELITY-3: the `/dashboard/*` header tuple. ────────────────────
    // Content-Type is the per-asset argument (`None` here); the other two are
    // literals the mock copies. `public, max-age=300` is the value the critic's
    // round-1 mutation flipped to prove the mock derives rather than hard-codes.
    #[test]
    fn static_asset_headers_are_exactly_what_the_mock_replays() {
        let rs = lf(DASHBOARD_RS);
        let block = between(&rs, "fn register_static(", "pub fn register_dashboard(");
        let got = header_tuples(block);
        let want: Vec<(String, Option<String>)> = vec![
            ("Content-Type".to_string(), None),
            (
                "Cache-Control".to_string(),
                Some("public, max-age=300".to_string()),
            ),
            (
                "X-Content-Type-Options".to_string(),
                Some("nosniff".to_string()),
            ),
        ];
        assert_eq!(
            got, want,
            "MOCK-FIDELITY-3: register_static()'s response headers changed.\n\
             {TOOL} reads this tuple list and serves /dashboard/* with it (taking \
             Content-Type from the per-asset argument, which is why it is None here).\n\
             Update {TOOL} and this pin together.\n\
             found:    {got:#?}\n\
             expected: {want:#?}"
        );

        // The per-asset content types themselves (dashboard.rs:157-158): the
        // mock resolves each asset's Content-Type from these two locals by name.
        for want_ct in [
            "let css = \"text/css; charset=utf-8\";",
            "let js = \"application/javascript; charset=utf-8\";",
        ] {
            assert!(
                rs.contains(want_ct),
                "MOCK-FIDELITY-3: the content-type local `{want_ct}` is gone. {TOOL} resolves \
                 each asset's Content-Type from these two locals by name and exits 3 without \
                 them."
            );
        }
    }

    // ── MOCK-FIDELITY-4: the registration MECHANISM. ─────────────────────────
    // The mock knows exactly one way an asset gets baked. A second mechanism (a
    // loop, a macro, a differently-named helper, a #[cfg]-gated call) would be
    // invisible to it: it would keep serving a stale set and never say so.
    #[test]
    fn dashboard_registers_assets_only_through_register_static() {
        let rs = lf(DASHBOARD_RS);

        // Exactly one helper definition, and every baked const is consumed by it.
        assert_eq!(
            rs.matches("fn register_static(").count(),
            1,
            "MOCK-FIDELITY-4: dashboard.rs no longer has exactly one `fn register_static(` \
             definition. {TOOL} enumerates the baked asset set from calls to that one \
             helper. Update {TOOL} and this pin together."
        );
        assert_eq!(
            rs.matches("include_str!(\"dashboard/").count(),
            baked_assets(&rs).len(),
            "MOCK-FIDELITY-4: dashboard.rs bakes a different number of `dashboard/` assets \
             with include_str! than it registers through register_static(). Either an asset \
             is compiled into the image and never served, or it is served by some mechanism \
             {TOOL} cannot see. Update {TOOL} and this pin together."
        );

        // The only literal routes are the two HTML ones the mock knows.
        let routes = handler_routes(&rs);
        let uris: Vec<&str> = routes.iter().map(|(_, u)| u.as_str()).collect();
        assert_eq!(
            uris,
            vec!["/", "/index.html"],
            "MOCK-FIDELITY-4: dashboard.rs registers literal URIs {uris:?}. {TOOL} knows only \
             `/` and `/index.html` (plus the register_static() helper, whose URI is a \
             parameter). A third literal route would 404 on the mock while the firmware \
             answers it. Update {TOOL} and this pin together."
        );
        assert_eq!(
            rs.matches("fn_handler(").count(),
            3,
            "MOCK-FIDELITY-4: dashboard.rs has a different number of fn_handler( sites than \
             the 3 the mock accounts for (GET /, GET /index.html, and the register_static \
             helper). Update {TOOL} and this pin together."
        );
    }

    // ── MOCK-FIDELITY-5: the write-route set. ────────────────────────────────
    // Round 1's mock answered EVERY non-GET with 200 {"status":"ok"} from a
    // default arm, so `POST /api/definitely/not/a/route` came back green and a
    // builder shipping a typo'd POST target would never learn. The mock now
    // derives the accepted (method, uri) pairs from these three files and 404s
    // the rest, as esp_http_server does for an unregistered URI. This pin is
    // what keeps that derivation honest.
    #[test]
    fn firmware_write_route_set_is_exactly_what_the_mock_accepts() {
        const EXPECTED: [(&str, &str); 32] = [
            ("Delete", "/api/auth/session/current"),
            ("Delete", "/api/system/coredump"),
            // CORS preflight registrations. They are real (uri, method) pairs on the
            // device, so a mock that 404s them is not firmware-accurate.
            ("Options", "/api/swarm/room-temp"),
            ("Options", "/api/system"),
            ("Options", "/api/system/identify"),
            ("Options", "/api/system/restart"),
            ("Patch", "/api/system"),
            ("Post", "/api/auth/owner-reset"),
            ("Post", "/api/auth/password"),
            ("Post", "/api/auth/session"),
            ("Post", "/api/auth/setup"),
            ("Post", "/api/config/shared"),
            ("Post", "/api/mining/autotune"),
            ("Post", "/api/mining/start"),
            ("Post", "/api/mining/stop"),
            ("Post", "/api/schedule"),
            ("Post", "/api/swarm/config"),
            ("Post", "/api/swarm/report"),
            ("Post", "/api/swarm/room-temp"),
            ("Post", "/api/system"),
            ("Post", "/api/system/OTA"),
            ("Post", "/api/system/OTAWWW"),
            ("Post", "/api/system/blockFound/dismiss"),
            ("Post", "/api/system/clear-safe-mode"),
            ("Post", "/api/system/identify"),
            ("Post", "/api/system/restart"),
            ("Post", "/api/system/self-test/cancel"),
            ("Post", "/api/system/self-test/run"),
            ("Post", "/api/system/setup"),
            ("Post", "/cgi-bin/blink.cgi"),
            ("Post", "/cgi-bin/reboot.cgi"),
            ("Post", "/mcp"),
        ];

        let mut found: Vec<(String, String)> = Vec::new();
        for src in [API_RS, AUTH_RS, MCP_RS] {
            for (method, uri) in handler_routes(&lf(src)) {
                if method != "Get" && method != "Head" {
                    found.push((method, uri));
                }
            }
        }
        found.sort();
        found.dedup();

        let expected: Vec<(String, String)> = EXPECTED
            .iter()
            .map(|(m, u)| (m.to_string(), u.to_string()))
            .collect();
        assert_eq!(
            found, expected,
            "MOCK-FIDELITY-5: the firmware's non-GET route set changed.\n\
             {TOOL} derives the writes it accepts from api.rs + auth.rs + mcp.rs and 404s \
             everything else, so an unpinned change here either (a) makes the mock 404 a \
             route the device answers, or (b) leaves the mock accepting a route the device \
             removed. Both make a click-through green against a page the device would fail.\n\
             Update {TOOL} (WRITE_RESPONSES) and this pin together.\n\
             found:    {found:#?}\n\
             expected: {expected:#?}"
        );
    }

    // ── MOCK-FIDELITY-6: the mock must still DERIVE, not hard-code. ──────────
    // A well-meaning "just make it work" edit that pastes the asset list into
    // the tool would pass every test above while destroying the property those
    // tests exist to protect. None of the ten baked filenames may appear in the
    // tool's own source.
    #[test]
    fn the_mock_hardcodes_none_of_the_baked_asset_names() {
        let mock = lf(MOCK_MJS);
        for name in [
            "tokens.css",
            "core.css",
            "components.css",
            "block-tile.css",
            "asic-chips.css",
            "framework.js",
            "api.js",
            "core.js",
            "block-tile.js",
            "asic-chips.js",
        ] {
            assert!(
                !mock.contains(name),
                "MOCK-FIDELITY-6: {TOOL} now contains the literal `{name}`. The mock's whole \
                 value is that it DERIVES the baked asset set from dashboard.rs at startup; \
                 a hard-coded filename is a copy that silently stops tracking the firmware. \
                 Parse it, do not paste it."
            );
        }
        // And it must still refuse to start rather than invent bytes.
        assert!(
            mock.contains("PARSE FAILURE"),
            "MOCK-FIDELITY-6: {TOOL} lost its fail-closed PARSE FAILURE path. A mock that \
             falls back to invented headers when dashboard.rs stops matching is worse than \
             no mock: it is green and wrong."
        );
    }

    // ── HELD-OUT (round-2 critic, not seen by the builder): the fail-closed
    // `fail()` helper must actually terminate the process, not merely log a
    // string. MOCK-FIDELITY-6 above pins only the substring "PARSE FAILURE";
    // a refactor that keeps that string in the log line but drops (or
    // downgrades) `process.exit(3)` inside `fail()` would pass every
    // fidelity test in this module while the mock kept running past a
    // dashboard.rs it admits it cannot parse — precisely the "green and
    // wrong" failure mode MOCK-FIDELITY-6 exists to prevent. This slices out
    // `fail()`'s own `{ ... }` body (matching braces, not a whole-file
    // substring search) so it cannot pass by matching an unrelated exit
    // call elsewhere in a 560-line file.
    #[test]
    fn mock_fail_closed_path_hard_exits_nonzero() {
        let mock = lf(MOCK_MJS);
        let start = mock.find("function fail(what)").unwrap_or_else(|| {
            panic!(
                "HELD-OUT: {TOOL} no longer defines `function fail(what)`. The mock's \
                 fail-closed helper moved or was renamed; find the new one and re-pin its \
                 exit behaviour here."
            )
        });
        let body_start = mock[start..]
            .find('{')
            .map(|o| start + o)
            .expect("HELD-OUT: `function fail(what)` has no `{` body");
        let mut depth = 0i32;
        let mut end = body_start;
        for (i, c) in mock[body_start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &mock[body_start..end];
        assert!(
            body.contains("PARSE FAILURE"),
            "HELD-OUT: {TOOL}'s fail() body no longer logs PARSE FAILURE."
        );
        assert!(
            body.contains("process.exit(3)"),
            "HELD-OUT: {TOOL}'s fail() helper no longer calls process.exit(3). A caller of \
             fail() that does not hard-exit lets the mock keep running past a dashboard.rs it \
             admits it cannot parse, so every later screenshot in the campaign would be taken \
             against undefined behaviour rather than the documented PARSE FAILURE refusal."
        );
    }

    // ── HELD-OUT (round-2 critic, not seen by the builder): every baked
    // asset URI is registered exactly once. The mock's served-asset table is
    // presumably keyed by URI (`GET /dashboard/<file>`); a second
    // `register_static()` call for a URI already registered would silently
    // shadow one of the two assets rather than erroring anywhere. Today
    // MOCK-FIDELITY-1's exact-list comparison happens to also catch a
    // duplicate (it changes the list), but that is a side effect of the
    // fixture being 10 specific names, not a check of the invariant itself.
    // This pins the invariant directly.
    #[test]
    fn baked_asset_uris_are_registered_exactly_once() {
        let rs = lf(DASHBOARD_RS);
        let found = baked_assets(&rs);
        let mut uris: Vec<&str> = found.iter().map(|(u, _)| u.as_str()).collect();
        let n = uris.len();
        uris.sort();
        uris.dedup();
        assert_eq!(
            uris.len(),
            n,
            "HELD-OUT: dashboard.rs calls register_static() twice for the same URI \
             ({found:#?}). {TOOL} builds its served-asset table keyed by URI, so a duplicate \
             registration silently shadows one of the two assets instead of erroring."
        );
    }
}

/// ── P1-W1 (DCENT_axe UI Gauntlet, 2026-09-03) ─────────────────────────────
/// The dashboard's PRIMARY NAVIGATION must be operable from the keyboard, and
/// it must be impossible for a keypress to leave the content area with no
/// active `.page`. Two real defects motivated these guards:
///
///   1. the digit shortcut mapped `1`–`8` to `go(k-1)` while `PAGE_NAMES` has
///      seven entries, so pressing `8` set `_curPage = 7`, removed the current
///      page's `.ac`, and then threw on `E('n7').classList` — a blank content
///      area, and (because `_curPage` was left at 7) every later `go()` threw
///      too, bricking the whole navigation until a reload;
///   2. the sidebar links were `<a onclick="go(n)">` with no `href`, `tabindex`
///      or `role`, so they could not receive focus at all and the
///      `:focus-visible` rule in the same file was dead code.
///
/// `dashboard.rs` is espidf-only and CANNOT host-compile, so — exactly like
/// `dcent_design_language_guards`, `dashboard_evidence_guards` and
/// `dcent_flow_vocab_guards` — these pin the invariants against the source
/// TEXT via `include_str!`. Matches are made on a whitespace-collapsed copy so
/// a benign HTML/JS reflow cannot flip a guard. These are ADDITIVE: no existing
/// guard is touched.
#[cfg(test)]
mod dashboard_a11y_nav_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn flat() -> String {
        DASHBOARD_RS.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The page roster, read out of the ONE literal the UI derives it from.
    fn page_names() -> Vec<String> {
        let f = flat();
        const HEAD: &str = "var PAGE_NAMES=[";
        let start = f.find(HEAD).expect("A11Y-NAV: PAGE_NAMES literal must exist") + HEAD.len();
        let end = start + f[start..].find(']').expect("A11Y-NAV: PAGE_NAMES must be closed");
        f[start..end]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect()
    }

    /// The body of one CSS rule, selected by its `<selector>{` opener.
    fn css_rule(selector_open: &str) -> String {
        let f = flat();
        let at = f
            .find(selector_open)
            .unwrap_or_else(|| panic!("A11Y-NAV: CSS rule `{selector_open}` must exist"));
        let rest = &f[at + selector_open.len()..];
        let end = rest.find('}').expect("A11Y-NAV: CSS rule must be closed");
        rest[..end].to_string()
    }

    // ── A11Y-NAV-0: PAGE_NAMES is the single source of the page count, and the
    //    nav/page element ids it implies all exist (and stop there). ──────────
    #[test]
    fn page_names_is_the_single_source_of_the_page_roster() {
        let names = page_names();
        let f = flat();
        assert_eq!(
            names.len(),
            7,
            "A11Y-NAV-0: the flat IA is seven pages (nav-ia-spine caps axe at 8); \
             PAGE_NAMES declares {names:?}. If a page is added, every guard below \
             follows PAGE_NAMES automatically — but the nav/page markup must too."
        );
        for i in 0..names.len() {
            assert!(
                f.contains(&format!("id=\"n{i}\"")),
                "A11Y-NAV-0: PAGE_NAMES[{i}] has no sidebar link `id=\"n{i}\"`"
            );
            assert!(
                f.contains(&format!("id=\"p{i}\"")),
                "A11Y-NAV-0: PAGE_NAMES[{i}] has no page container `id=\"p{i}\"`"
            );
        }
        assert!(
            !f.contains(&format!("id=\"n{}\"", names.len())),
            "A11Y-NAV-0: there is a sidebar link past the end of PAGE_NAMES"
        );
    }

    // ── A11Y-NAV-1: the digit shortcut's upper bound IS PAGE_NAMES.length. A
    //    hard-coded `8` is the exact defect this lane fixed. ─────────────────
    #[test]
    fn the_digit_shortcut_upper_bound_is_page_names_length() {
        let f = flat();
        assert!(
            f.contains("var k=parseInt(e.key);if(k>=1&&k<=PAGE_NAMES.length)go(k-1)"),
            "A11Y-NAV-1: the digit shortcut MUST bound itself with PAGE_NAMES.length so \
             the roster and the shortcut can never disagree."
        );
        let literal_bound = format!("if(k>=1&&k<={})go(k-1)", page_names().len() + 1);
        assert!(
            !f.contains(&literal_bound),
            "A11Y-NAV-1: the shortcut is bounded by a LITERAL one past the roster \
             ({literal_bound}). Pressing that digit leaves zero `.page.ac` (rubric H8)."
        );
    }

    // ── A11Y-NAV-2: go() rejects an out-of-range index BEFORE it mutates the
    //    DOM, so no input can leave the content area with no active page. ────
    #[test]
    fn go_refuses_an_out_of_range_index_before_it_mutates_the_dom() {
        let f = flat();
        let at = f.find("function go(n){").expect("A11Y-NAV-2: go() must exist");
        let body = &f[at..];
        assert!(
            body.starts_with("function go(n){n=+n;if(!(n>=0&&n<PAGE_NAMES.length)||n===_curPage)return;"),
            "A11Y-NAV-2: go() MUST coerce and bounds-check `n` against PAGE_NAMES.length \
             as its first statement. Without it `go(7)` removes the active page's `.ac` \
             and then throws, leaving a blank content area and a poisoned `_curPage`."
        );
        let guard_at = body
            .find("n<PAGE_NAMES.length")
            .expect("A11Y-NAV-2: bounds check missing");
        let mutate_at = body
            .find("classList.remove('ac')")
            .expect("A11Y-NAV-2: go() must still deactivate the previous page");
        assert!(
            guard_at < mutate_at,
            "A11Y-NAV-2: the bounds check must run BEFORE the first classList mutation"
        );
        assert!(
            body[..mutate_at + 200.min(body.len() - mutate_at)].contains("var o=E('n'+_curPage);if(o){"),
            "A11Y-NAV-2: the previous link lookup must be null-guarded — a poisoned \
             `_curPage` must degrade to a no-op, never to a thrown TypeError."
        );
    }

    // ── A11Y-NAV-3: every sidebar link is focusable and carries a role. ─────
    #[test]
    fn every_sidebar_nav_anchor_carries_tabindex_and_role() {
        let f = flat();
        for i in 0..page_names().len() {
            let needle = format!("<a onclick=\"go({i})\"");
            let at = f
                .find(&needle)
                .unwrap_or_else(|| panic!("A11Y-NAV-3: sidebar link {i} (`{needle}`) is missing"));
            let end = at + f[at..].find('>').expect("A11Y-NAV-3: unterminated <a> tag");
            let tag = &f[at..end];
            assert!(
                tag.contains(&format!("id=\"n{i}\"")),
                "A11Y-NAV-3: sidebar link {i} lost its id: {tag}"
            );
            assert!(
                tag.contains("tabindex=0"),
                "A11Y-NAV-3: `{tag}` has no href and no tabindex, so the PRIMARY \
                 navigation cannot receive keyboard focus at all."
            );
            assert!(
                tag.contains("role=button"),
                "A11Y-NAV-3: `{tag}` is focusable but has no role, so assistive tech \
                 announces a bare text run instead of a control."
            );
        }
    }

    // ── A11Y-NAV-4: role=button means Enter AND Space must activate it. ─────
    #[test]
    fn enter_and_space_activate_a_focused_sidebar_nav_link() {
        assert!(
            flat().contains(
                "if(e.key==='Enter'||e.key===' '){var a=e.target.closest&&e.target.closest('.sb-nav a');if(a){e.preventDefault();a.click();return}}"
            ),
            "A11Y-NAV-4: a focusable role=button link that does nothing on Enter/Space \
             is worse than an unfocusable one — it is a keyboard trap with no exit. The \
             handler is DELEGATED onto the existing keydown listener (zero new listeners, \
             zero new handlers)."
        );
    }

    // ── A11Y-NAV-5: the active link is announced, not just coloured. ────────
    #[test]
    fn the_active_nav_link_is_announced_with_aria_current_page() {
        let f = flat();
        assert!(
            f.contains("id=\"n0\" tabindex=0 role=button aria-current=page"),
            "A11Y-NAV-5: the initially-active link must ship with aria-current=page"
        );
        assert!(
            f.contains("o.removeAttribute('aria-current')")
                && f.contains("t.setAttribute('aria-current','page')"),
            "A11Y-NAV-5: go() must move aria-current with the `.ac` class, or a screen \
             reader reports the wrong page after every navigation."
        );
    }

    // ── A11Y-NAV-6: language, landmarks, and one h1 per page. ───────────────
    #[test]
    fn the_document_declares_its_language() {
        assert!(
            flat().contains("<html lang=en>"),
            "A11Y-NAV-6: <html> must declare a language or a screen reader picks the \
             wrong voice for every string on the page."
        );
    }

    #[test]
    fn the_nav_and_main_landmarks_exist() {
        let f = flat();
        assert!(
            f.contains("<nav class=\"sb-nav\" id=\"nav\">"),
            "A11Y-NAV-6: the sidebar must stay a <nav> landmark"
        );
        assert!(
            f.contains("<main class=\"content\">") && f.contains("</main>"),
            "A11Y-NAV-6: the page container must be a <main> landmark so 'skip to \
             content' works. It replaced a <div class=\"content\"> and is cheaper \
             in bytes than the comment it removed."
        );
    }

    #[test]
    fn every_page_has_exactly_one_h1() {
        let f = flat();
        let pages = page_names().len();
        assert_eq!(
            f.matches("<h1 ").count(),
            pages,
            "A11Y-NAV-6: expected exactly one <h1> per page ({pages})"
        );
        assert_eq!(
            f.matches("</h1>").count(),
            pages,
            "A11Y-NAV-6: unbalanced <h1> tags"
        );
        assert!(
            !f.contains("<div class=\"page-title\">"),
            "A11Y-NAV-6: a page title must be an <h1>, not a styled <div> — the heading \
             outline is how a screen-reader user knows which page they are on."
        );
        for (id, title) in [("p0", "Dashboard"), ("p2", "Logs")] {
            assert!(
                f.contains(&format!("<h1 class=vh>{title}</h1>")),
                "A11Y-NAV-6: page {id} carries its title in other chrome, so it needs a \
                 visually-hidden <h1>{title}</h1> to keep the outline complete."
            );
        }
        assert!(
            f.contains(".vh{position:absolute;"),
            "A11Y-NAV-6: the .vh visually-hidden utility backing those headings is gone"
        );
        // The h1s must keep the exact box the divs had: an h1's UA margin-top
        // would otherwise push every titled page down by ~15px.
        let rule = css_rule(".page-title{");
        assert!(
            rule.contains("margin:0 0 20px"),
            "A11Y-NAV-6: .page-title must zero the UA h1 margin explicitly (found `{rule}`)"
        );
    }

    #[test]
    fn the_icon_only_controls_have_accessible_names() {
        let f = flat();
        assert!(
            f.contains("class=\"hamburger\" onclick=\"toggleSB()\" aria-label=\"Open navigation\""),
            "A11Y-NAV-6: the hamburger's only content is the glyph &#9776;, which is what \
             a screen reader would read out without an aria-label."
        );
        assert!(
            f.contains("onclick=\"toggleCol()\" title=\"Collapse sidebar\" aria-label=\"Collapse sidebar\""),
            "A11Y-NAV-6: the collapse control's content glyph &#9664; wins over its \
             title attribute for the accessible name, so it needs an aria-label."
        );
    }

    // ── A11Y-NAV-7: the pause control's announced state follows its label. ──
    #[test]
    // Lead fix at merge (blind critic P1-W1, MF1): a toggle whose accessible name changes must NOT
    // also carry aria-pressed (APG) — "Resume mining, pressed" would read as resume-is-active.
    fn the_pause_button_aria_state_follows_its_visible_label() {
        let f = flat();
        assert!(
            f.contains("aria-label=\"Pause mining\">") && !f.contains("aria-label=\"Pause mining\" aria-pressed"),
            "A11Y-NAV-7: the pause button must ship a pressed state, not just a label"
        );
        assert!(
            f.contains("pl.textContent=miningEnabled?'PAUSE':'RESUME'"),
            "A11Y-NAV-7: the visible label flip is the behaviour the aria state must track"
        );
        assert!(
            f.contains("tbpb.setAttribute('aria-label',miningEnabled?'Pause mining':'Resume mining');")
                && !f.contains("tbpb.setAttribute('aria-pressed'"),
            "A11Y-NAV-7: update() flips the button's LABEL to RESUME but used to leave \
             aria-label=\"Pause mining\" behind — a screen reader then offers to pause a \
             miner that is already stopped. Both must read the SAME `miningEnabled` \
             predicate as the label."
        );
    }

    // ── A11Y-NAV-8: the additions above are PAID FOR by dead CSS/JS, and the
    //    LIVE hero-* rules are not collateral damage. ────────────────────────
    #[test]
    fn the_dead_hero_rules_stay_deleted_and_the_live_ones_stay() {
        let f = flat();
        for dead in [
            ".hero{",
            ".hero-head{",
            ".hero-meta{",
            ".hero::before{",
            ".hero::after{",
            ".hero-hr{",
            ".hero-unit{",
            ".hero-sub{",
            ".hero-pills{",
            ".hero-inner{",
            ".hero-left{",
            ".hero-divider-v{",
            ".hero-footer{",
        ] {
            assert!(
                !f.contains(dead),
                "A11Y-NAV-8: `{dead}` is legacy dead CSS (the `<div class=\"hero\">` it \
                 styled was deleted in loop 13, 2026-04-28) and paid for this lane's \
                 a11y additions. Re-adding it grows the image for nothing."
            );
        }
        assert!(
            !f.contains("document.querySelector('.hero')"),
            "A11Y-NAV-8: the block-found glow queried `.hero`, an element that no longer \
             exists, so it always resolved to null. It also carried two of the file's \
             raw rgba(247,147,26,…) literals."
        );
        for live in [
            ".hero-kpi{",
            ".hero-pill{",
            ".hero-pool-pill{",
            ".hero-core-caption{",
            ".hero-trend{",
        ] {
            assert!(
                f.contains(live),
                "A11Y-NAV-8: `{live}` IS used by the merged hero row and must survive the \
                 dead-CSS sweep."
            );
        }
    }

    // ── A11Y-NAV-9: the focus ring the lane made reachable is actually
    //    visible — `.sb-nav` clips horizontally, so an OUTSET ring loses its
    //    left/right edges on a nav link. ─────────────────────────────────────
    #[test]
    // Lead fix at merge (blind critic P1-W1, MF2): the shared outset ring's box-shadow erased the
    // active link's inset glow while focused; nav links draw an inset OUTLINE and leave the shadow alone.
    fn the_sidebar_focus_ring_is_drawn_inside_the_clipping_nav() {
        let f = flat();
        assert!(
            css_rule(".sb-nav{").contains("overflow-y:auto"),
            "A11Y-NAV-9: this guard exists because .sb-nav scrolls (and therefore clips \
             on BOTH axes). If that stops being true, revisit the inset ring below."
        );
        assert!(
            f.contains(".sb-nav a:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}")
                && !f.contains(".sb-nav a:focus-visible,.btn:focus-visible"),
            "A11Y-NAV-9: the shared :focus-visible rule uses outline-offset:2px and an \
             outset glow; inside the clipping .sb-nav that renders as two horizontal \
             bars instead of a ring. The nav link must draw its ring INSET."
        );
    }
}

/// ── HELD-OUT (blind critic, lane P1-W1 round 1, 2026-09-03) ───────────────
/// Written by the critic AFTER the lane was built; the builder never saw it.
/// It binds the two things the lane's own guards leave free:
///
///  1. `dashboard_a11y_nav_guards::every_page_has_exactly_one_h1` counts `<h1 `
///     and `</h1>` over the WHOLE document. Seven `<h1>` on one page and none
///     on the other six passes it — and that is the regression a future
///     "tidy the headings" edit actually produces. The outline must be one
///     `h1` per PAGE CONTAINER, which is what a screen-reader user navigates.
///  2. `…::every_page_has_exactly_one_h1` also only asserts that `.vh{position:
///     absolute;` exists. Adding `display:none` to that rule keeps the assert
///     green and removes both visually-hidden headings from the accessibility
///     tree entirely — i.e. it silently undoes the lane while every guard the
///     lane shipped stays green. A visually-hidden heading must CLIP, never
///     remove.
#[cfg(test)]
mod critic_p1_w1_held_out {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn flat() -> String {
        DASHBOARD_RS.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn visually_hidden_headings_stay_in_the_a11y_tree_and_are_one_per_page() {
        let f = flat();

        // (1) `.vh` must CLIP, not REMOVE.
        const OPEN: &str = ".vh{";
        let at = f.find(OPEN).expect("HELD-OUT: the .vh utility must exist");
        let rest = &f[at + OPEN.len()..];
        let rule = &rest[..rest.find('}').expect("HELD-OUT: .vh rule unterminated")];
        for killer in ["display:none", "visibility:hidden", "content-visibility:hidden"] {
            assert!(
                !rule.contains(killer),
                "HELD-OUT: `.vh{{{rule}}}` uses `{killer}`, which removes the node from \
                 the ACCESSIBILITY TREE. A visually-hidden <h1> that no screen reader \
                 can read is strictly worse than no <h1>: the outline claims to exist \
                 and does not. Clip it (position:absolute + 1px box + overflow:hidden) \
                 instead."
            );
        }
        assert!(
            rule.contains("position:absolute") && rule.contains("overflow:hidden"),
            "HELD-OUT: `.vh` must clip via position:absolute + overflow:hidden (found `{rule}`)"
        );

        // (2) exactly one <h1 per PAGE CONTAINER, not merely 7 in the document.
        const PAGE: &str = "<div class=\"page";
        let starts: Vec<usize> = f.match_indices(PAGE).map(|(i, _)| i).collect();
        assert_eq!(
            starts.len(),
            7,
            "HELD-OUT: expected 7 `.page` containers, found {}",
            starts.len()
        );
        let end_of_pages = f
            .find("</main>")
            .expect("HELD-OUT: the <main> landmark must close after the pages");
        assert!(
            *starts.last().unwrap() < end_of_pages,
            "HELD-OUT: a `.page` container escaped the <main> landmark"
        );
        let mut seen_ids: Vec<String> = Vec::new();
        for (k, &s) in starts.iter().enumerate() {
            let e = if k + 1 < starts.len() { starts[k + 1] } else { end_of_pages };
            let region = &f[s..e];
            let head = &region[..region.find('>').expect("HELD-OUT: unterminated page div")];
            let id = head
                .find("id=\"")
                .map(|i| {
                    let r = &head[i + 4..];
                    r[..r.find('"').unwrap_or(0)].to_string()
                })
                .unwrap_or_default();
            assert!(!id.is_empty(), "HELD-OUT: page container `{head}` has no id");
            let n = region.matches("<h1").count();
            assert_eq!(
                n, 1,
                "HELD-OUT: page `{id}` contains {n} <h1> elements, expected exactly 1. \
                 The document-wide count the lane pins cannot see this: seven headings \
                 stacked on one page satisfies it while six pages announce nothing."
            );
            assert_eq!(
                region.matches("</h1>").count(),
                1,
                "HELD-OUT: page `{id}` has an unbalanced <h1>"
            );
            seen_ids.push(id);
        }
        seen_ids.sort();
        assert_eq!(
            seen_ids,
            vec!["p0", "p1", "p2", "p3", "p4", "p5", "p6"],
            "HELD-OUT: the page-container ids are not the seven the nav can reach"
        );
    }
}

/// HELD-OUT (blind critic, lane `P1-G1`, round 1, 2026-09-03).
///
/// The lane's own `fund_link_has_an_instance_outside_the_collapsible_sidebar_footer`
/// proves the second Fund anchor exists SOMEWHERE AFTER the Integrations
/// card-title offset (`DASHBOARD_RS[integrations..].contains(...)`). That slice is
/// open-ended: it is satisfied just as well by an anchor in the Swarm page, in a
/// modal, or inside the trailing `<script>` block - none of which is painted on
/// the System page. It is also satisfied by an anchor the author wrapped in an
/// inline `display:none`, which the critic reproduced: wrapping the anchor in
/// `<div style="display:none">` left all three lane guards green and the ban gate
/// at exit 0, while the affordance was invisible at every width.
///
/// This test BOUNDS the containment instead of leaving it open: the anchor must
/// fall inside the `<div class="page" id="p4">` System-page container (bounded
/// above by the next page container in source order), and its own source line
/// must not carry an inline `display:none` / `hidden`. Source text cannot prove
/// painted visibility - only the probe can - but this removes the two cheapest
/// ways to satisfy the rule without shipping a visible affordance.
#[cfg(test)]
mod critic_held_out_fund_anchor_is_inside_the_system_page_container {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const FUND_ANCHOR: &str = "href=\"https://d-central.tech/fund/";

    #[test]
    fn a_fund_anchor_is_inside_the_system_page_container_and_not_inline_hidden() {
        let p4 = DASHBOARD_RS
            .find("<div class=\"page\" id=\"p4\">")
            .expect("HELD-OUT: the System page container `id=\"p4\"` moved - re-point this test");
        // Bound the slice above by the NEXT page container after p4, so "inside
        // the System page" cannot decay into "anywhere later in the file".
        let end = DASHBOARD_RS[p4 + 1..]
            .find("<div class=\"page\" id=\"p")
            .map(|i| p4 + 1 + i)
            .unwrap_or(DASHBOARD_RS.len());
        let page = &DASHBOARD_RS[p4..end];
        let anchor_at = page.find(FUND_ANCHOR).unwrap_or_else(|| {
            panic!(
                "HELD-OUT (root  2026-07-10 Fund HARD RULE): no anchor whose href \
                 starts with https://d-central.tech/fund/ lives INSIDE the System page \
                 container (`<div class=\"page\" id=\"p4\">` .. next page container, {} bytes). \
                 An anchor merely placed after the Integrations card-title offset can sit in \
                 the Swarm page, a modal or the trailing <script> block and is never painted \
                 on the System page.",
                page.len()
            )
        });

        // The anchor's own source line must not be inline-hidden. The critic
        // proved that wrapping it in `<div style="display:none">` on this line
        // leaves every lane guard and the ban gate green.
        let line_start = page[..anchor_at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = page[anchor_at..]
            .find('\n')
            .map(|i| anchor_at + i)
            .unwrap_or(page.len());
        let line = &page[line_start..line_end];
        let squashed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            !squashed.contains("display:none"),
            "HELD-OUT: the System-page Fund anchor's own source line carries an inline \
             `display:none`, so the affordance is present in the HTML and invisible on \
             screen. Line: {}",
            line.trim()
        );
        assert!(
            !line.contains(" hidden>") && !line.contains(" hidden "),
            "HELD-OUT: the System-page Fund anchor's own source line carries the `hidden` \
             attribute. Line: {}",
            line.trim()
        );
    }
}
/// ============================================================================
/// P1-O2 (DCENT_axe UI Gauntlet) - the OLED and the web share ONE truth ladder.
///
/// `CRITIC_RUBRIC.md` H7 is an automatic REJECT: "for the same scenario the
/// panel's state word and the dashboard's state id disagree". Before this lane
/// they could not agree, because the panel had no rung vocabulary at all - page
/// 0 printed `OFF/HOT/SLEEP/FED/NITE/HASH`, the companion page printed
/// `Offline/TOO HOT/Zzz.../Nom nonce/Proud!/Mining hard`, and the two arms gated
/// on DIFFERENT discriminators (`mining_enabled` at boot vs.
/// `runtime_mining_active` at runtime). `ready` and `standby` both rendered as
/// `SLEEP`/`Zzz...`, so the one distinction an operator most needs at a glance
/// was the one the panel could not make.
///
/// The fix is one host-pure resolver
/// ([`crate::display_convert::resolve_rung`]) plus one mapping table
/// ([`crate::display_convert::MiningRung::panel_word`]). These tests are the
/// JOIN: the behaviour is unit-tested where it lives, and the two consumers -
/// `main.rs` (espidf-only, never host-compiled) and `dashboard.rs` (a string
/// literal of JavaScript) - are pinned here as source contracts, which is the
/// only place either can be checked at all.
///
/// CRLF: `core.autocrlf = true` means a fresh Windows worktree checks these
/// files out with CRLF while git stores LF, so every read goes through `lf()`
/// first. A neighbouring guard in this crate fails exactly that way today
/// (`config::identity_gate_tests::default_model_for_build_has_lucky_arms`
/// searches for a bare "\n}\n"), which is why this one does not.
#[cfg(test)]
mod oled_truth_ladder_guards {
    use crate::display_convert::{fit_line, resolve_rung, MiningRung, TEXT_COLUMNS};

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn lf(s: &str) -> String {
        s.replace("\r\n", "\n")
    }

    /// The panel words ARE the dashboard's pill words - not a lookalike set.
    ///
    /// `dashboard.rs` renders the ladder three times in `update()` (the topbar
    /// pill, the `tbMiningPill` element and the Logs crumb) as the literal
    /// ternary matched below, and first-paints `PENDING` before any telemetry.
    /// If somebody re-words the browser, this fails and names the panel table
    /// that has to move with it.
    #[test]
    fn panel_words_are_the_dashboard_pill_words() {
        let dash = lf(DASHBOARD_RS);
        let ternary = "mining?'MINING':miningEnabled?'READY':'STANDBY'";
        assert!(
            dash.contains(ternary),
            "dashboard.rs no longer renders the {ternary:?} ladder; the OLED's \
             MiningRung::panel_word() table in dcentaxe-hal/src/display_convert.rs \
             must be re-pinned to whatever replaced it"
        );
        assert!(
            dash.contains("data-state=\"pending\"") && dash.contains(">PENDING<"),
            "dashboard.rs must still first-paint the PENDING rung"
        );

        assert_eq!(MiningRung::Mining.panel_word(), "MINING");
        assert_eq!(MiningRung::Ready.panel_word(), "READY");
        assert_eq!(MiningRung::Standby.panel_word(), "STANDBY");
        assert_eq!(MiningRung::TelemetryPending.panel_word(), "PENDING");

        // …and the state ids the dashboard stamps on `tbMiningPill.dataset`.
        // Lane P1-W3 (merged after this guard was written) hoisted the rung into one shared
        // definition and stamps the pill's state id as `_rung.toLowerCase()`, so the lowercase ids
        // are no longer literals. Same contract, pinned at the derivation: the mixed-case labels
        // checked below, lower-cased, ARE the state ids the resolver names.
        assert!(
            dash.contains("tbp.dataset.state=_rung.toLowerCase()"),
            "dashboard.rs must stamp tbMiningPill's state id from the shared rung label"
        );
        for (label, id) in [("Mining", "mining"), ("Ready", "ready"), ("Standby", "standby")] {
            assert_eq!(label.to_lowercase(), id, "state id must be the lower-cased rung label");
        }
        assert_eq!(MiningRung::Mining.web_state_id(), "mining");
        assert_eq!(MiningRung::Ready.web_state_id(), "ready");
        assert_eq!(MiningRung::Standby.web_state_id(), "standby");
        assert_eq!(MiningRung::TelemetryPending.web_state_id(), "pending");

        // The hero badge's mixed-case labels.
        for label in [
            "'Mining'",
            "'Ready'",
            "'Standby'",
            "Telemetry pending",
        ] {
            assert!(
                dash.contains(label),
                "dashboard.rs must still render the {label} hero label"
            );
        }
    }

    /// `main.rs` must DERIVE its panel words from the shared resolver.
    ///
    /// A mapping table with no consumer changes nothing - the exact shape of
    /// , which
    /// this project has been bitten by four times (`RailBringup`,
    /// `tps5364x_convert`, `fxl6408_convert`, `tmp451_convert` all shipped
    /// callerless). So: the resolver is called, the mapping is used, and the
    /// two ad-hoc ternaries are gone.
    #[test]
    fn main_rs_derives_the_panel_word_from_the_shared_resolver() {
        let src = lf(MAIN_RS);

        assert!(
            src.contains("use dcentaxe_hal::display_convert::{fit_line, resolve_rung, MiningRung, TEXT_COLUMNS};"),
            "main.rs must import the shared truth-ladder resolver"
        );
        assert_eq!(
            src.matches("resolve_rung(true, runtime_mining_active, hr > 0.0)")
                .count(),
            2,
            "both carousel arms that print a state word (page 0 row 3 and the \
             companion page) must resolve the rung from the SAME inputs; the \
             original defect was two arms gating on two different flags"
        );
        assert!(
            src.contains("fit_line(&[rung.panel_word(), &block_short], deco, TEXT_COLUMNS)"),
            "page 0 row 3 must render the rung word verbatim, ahead of the block \
             anchor, inside the 21-column budget"
        );
        assert!(
            src.contains("fit_line(&[pet_rung.panel_word()], pet_deco, PET_ACTIVITY_COLUMNS)"),
            "the companion page must render the same rung word"
        );

        // The boot / ASIC-init screens speak the ladder too.
        for call in [
            "MiningRung::TelemetryPending.panel_word()",
            "MiningRung::Ready.panel_word()",
            "MiningRung::Standby.panel_word()",
        ] {
            assert!(
                src.contains(call),
                "the boot/init screens must name the rung: missing {call}"
            );
        }
        assert_eq!(
            src.matches("MiningRung::Standby.panel_word()").count(),
            2,
            "both fail-closed init screens (ASIC init failure and \
             mining-not-permitted) must say STANDBY"
        );
    }

    /// The retired vocabulary must not come back.
    ///
    /// These are the exact literals that produced H7. `SLEEP`/`Zzz...` are the
    /// load-bearing pair: they were what made `ready` and `standby` look
    /// identical on the panel.
    #[test]
    fn the_ad_hoc_panel_vocabulary_is_gone() {
        let src = lf(MAIN_RS);
        for dead in [
            "\"SLEEP\"",
            "\"HASH\"",
            "\"Offline\"",
            "\"TOO HOT\"",
            "\"Zzz...\"",
            "\"Nom nonce\"",
            "\"Proud!\"",
            "\"Mining hard\"",
        ] {
            assert!(
                !src.contains(dead),
                "the retired panel word {dead} is back in main.rs. State words \
                 come from MiningRung::panel_word(); flavour words are \
                 DECORATIONS passed to fit_line() and are dropped first when the \
                 line is full."
            );
        }
        // "OFF" as a state word is gone; the pet_state ternary that produced it
        // is gone with it.
        assert!(
            !src.contains("let pet_state = if !runtime_mining_active {"),
            "the page-0 pet_state ternary must not return"
        );
        assert!(
            !src.contains("let activity = if !runtime_mining_active {"),
            "the companion-page activity ternary must not return"
        );
    }

    /// The panel must never gate a state word on the BOOT-TIME flag again.
    ///
    /// `mining_enabled` is decided once, at `main.rs`'s ASIC-init step, and
    /// never updated; `runtime_mining_active` is `mining_enabled && !kill`. The
    /// old page-0 face read the former while the word beside it read the
    /// latter, which is how one frame could show a live creature next to `OFF`.
    #[test]
    fn the_carousel_state_words_read_the_runtime_flag_only() {
        let src = lf(MAIN_RS);
        let carousel = src
            .find("// ── OLED display carousel")
            .expect("the carousel block must still be locatable");
        // Comments are stripped first: this file's own explanation of the
        // defect NAMES the flag, and a guard that its own rationale would trip
        // is a guard nobody can keep.
        let body: String = src[carousel..]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // `runtime_mining_active` does not contain `mining_enabled` as a
        // substring, so a bare occurrence really is the boot-time flag.
        assert!(
            !body.contains("mining_enabled"),
            "the carousel reads the boot-time `mining_enabled` again. It is \
             decided once, at ASIC init, and never updated; the runtime kill \
             paths only move `runtime_mining_active`. Mixing the two is exactly \
             how one frame showed a live creature next to `OFF`. Every state \
             word must come from resolve_rung(.., runtime_mining_active, ..)."
        );
        assert!(
            body.contains("runtime_mining_active"),
            "the carousel must still read the runtime flag - a vacuous pass \
             here would mean the block moved and this guard lost its subject"
        );
    }

    /// Whatever the firmware can compose for those two lines fits the panel.
    ///
    /// This is the behavioural half: the source contract above proves `main.rs`
    /// calls `fit_line`, and this proves `fit_line` cannot overflow for any
    /// rung / decoration / block-height combination the firmware can produce.
    /// `draw_text` clips from the right with no ellipsis, so an overflow is a
    /// silent lie, not a visible error.
    #[test]
    fn every_composable_panel_line_fits_twenty_one_columns() {
        const PET_ACTIVITY_COLUMNS: usize = 11;
        let decos: [&[&str]; 5] = [&[], &["HOT"], &["FED"], &["NITE"], &["WOW"]];
        for &enabled in &[false, true] {
            for &hashing in &[false, true] {
                let rung = resolve_rung(true, enabled, hashing);
                for height in [0u64, 1, 868_123, 9_999_999, 21_000_000] {
                    let block = if height > 0 {
                        format!("B:{height}")
                    } else {
                        "B:---".to_string()
                    };
                    for deco in decos {
                        let row3 =
                            fit_line(&[rung.panel_word(), &block], deco, TEXT_COLUMNS);
                        assert!(
                            row3.chars().count() <= TEXT_COLUMNS,
                            "page-0 row 3 overflows: {row3:?}"
                        );
                        assert!(row3.starts_with(rung.panel_word()));

                        let pet =
                            fit_line(&[rung.panel_word()], deco, PET_ACTIVITY_COLUMNS);
                        assert!(
                            pet.chars().count() <= PET_ACTIVITY_COLUMNS,
                            "companion activity overflows: {pet:?}"
                        );
                        assert!(pet.starts_with(rung.panel_word()));
                    }
                }
            }
        }
    }

    /// The named companion budget in `main.rs` matches the geometry around it.
    ///
    /// The activity string is drawn at x = 22 with the wattage at x = 90, and
    /// the glyph pitch is 6 px, so the slot is exactly (90 - 22) / 6 = 11
    /// columns. If either coordinate moves, this fails instead of the panel
    /// quietly overprinting.
    #[test]
    fn the_companion_activity_budget_matches_its_geometry() {
        let src = lf(MAIN_RS);
        assert!(
            src.contains("const PET_ACTIVITY_COLUMNS: usize = 11;"),
            "the companion activity budget must stay a named constant"
        );
        assert!(
            src.contains("display.draw_text(22, 25, &activity);"),
            "the pet-room activity origin (x = 22) is what makes the budget 11"
        );
        assert!(
            src.contains("display.draw_text(90, 24, &format!(\"{:.0}W\", watts));"),
            "the wattage at x = 90 is the right edge of the activity slot"
        );
        assert_eq!((90 - 22) / 6, 11);
    }

    /// A `ready` device must be tellable from a `standby` one ON THE PANEL.
    ///
    /// The lane exists for this sentence. It is asserted on the composed lines,
    /// not just the enum, because the enum being distinct is worth nothing if
    /// both render the same string in the 21 columns the operator can see.
    #[test]
    fn ready_and_standby_render_differently_on_both_pages() {
        const PET_ACTIVITY_COLUMNS: usize = 11;
        let ready = resolve_rung(true, true, false);
        let standby = resolve_rung(true, false, false);
        let block = "B:868123";

        let r3 = fit_line(&[ready.panel_word(), block], &[], TEXT_COLUMNS);
        let s3 = fit_line(&[standby.panel_word(), block], &[], TEXT_COLUMNS);
        assert_ne!(r3, s3, "page 0 row 3 collapses ready and standby: {r3:?}");

        let rp = fit_line(&[ready.panel_word()], &[], PET_ACTIVITY_COLUMNS);
        let sp = fit_line(&[standby.panel_word()], &[], PET_ACTIVITY_COLUMNS);
        assert_ne!(rp, sp, "the companion page collapses ready and standby");

        // And a decoration must never be able to erase the difference.
        for deco in [&["HOT"][..], &["FED"][..], &["NITE"][..]] {
            assert_ne!(
                fit_line(&[ready.panel_word(), block], deco, TEXT_COLUMNS),
                fit_line(&[standby.panel_word(), block], deco, TEXT_COLUMNS)
            );
        }
    }
}

/// ============================================================================
/// HELD-OUT guard written by the blind critic for P1-O2 round 1 (not adopted by
/// the lead yet — delete it or keep it, but do not silently loosen it).
///
/// The lane routed page 0 row 3 and the companion activity word through
/// `fit_line`, which is a budget guarantee BY CONSTRUCTION. The four
/// `show_status` boot/init screens it also re-worded do **not** go through
/// `fit_line`: they are raw `format!` calls whose result reaches
/// `Ssd1306Display::show_status` → `draw_text`, which clips at column 21 from
/// the RIGHT, silently, with no ellipsis. Today every one of them fits — the
/// tightest is `STANDBY: ASIC FAILED` at 20 of 21 columns, one character of
/// headroom. That headroom is currently protected by nothing at all: renaming
/// a rung, or turning `disabled` into `disabled by safety`, would push the
/// operator-facing half of the line off the panel and no test would notice.
///
/// So this pins BOTH halves: the four call sites still exist verbatim (a
/// reword lands here), and every string they can compose fits 21 columns for
/// every chip count a `u8` detection can report.
///
/// **ROUND 2 NOTE (builder, adopting this guard).** The guard fired, exactly as
/// designed. Critic findings 1 and 2 ordered the reword of these same four
/// sites - boot frame to RUNG-first, and all four off raw `format!` and onto a
/// composer that cannot overflow. The four pinned literals below are therefore
/// re-pinned to the new call sites and the composed-width half now builds its
/// strings with `rung_status_line`, i.e. with the real composition rather than
/// a copy of it. Nothing was loosened: still four verbatim pins, still every
/// `u8` chip count, still `line_fits`. The headroom this guard was written to
/// protect is now structural as well as measured - `rung_status_line` drops an
/// over-long detail whole rather than letting `draw_text` clip it - and the
/// behavioural proof of that lives in
/// `display_convert::tests::rung_status_line_can_never_overflow_or_lose_the_rung`.
#[cfg(test)]
mod critic_p1_o2_init_screen_budget {
    use crate::display_convert::{line_fits, rung_status_line, MiningRung, TEXT_COLUMNS};

    const MAIN_SRC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    #[test]
    fn every_rung_bearing_init_screen_line_fits_the_panel() {
        let src = MAIN_SRC.replace("\r\n", "\n");

        for site in [
            "&rung_status_line(MiningRung::TelemetryPending.panel_word(), \"no telemetry\")",
            "&rung_status_line(MiningRung::Ready.panel_word(), &format!(\"{} chips OK\", n))",
            "&rung_status_line(MiningRung::Standby.panel_word(), \"ASIC FAILED\")",
            "&rung_status_line(MiningRung::Standby.panel_word(), \"disabled\")",
        ] {
            assert!(
                src.contains(site),
                "the rung-bearing init screen {site} was reworded. draw_text \
                 clips at column 21 with no ellipsis, so re-check the composed \
                 width here - and keep the line RUNG-first: the first word on \
                 the frame is the one an operator reads."
            );
        }
        // The label-first shape the blind critic rejected must not come back.
        assert!(
            !src.contains("format!(\"Mining: {}\""),
            "the boot frame is back to LABEL:RUNG; it must lead with the rung"
        );

        let mut composed = vec![
            rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry"),
            rung_status_line(MiningRung::Standby.panel_word(), "ASIC FAILED"),
            rung_status_line(MiningRung::Standby.panel_word(), "disabled"),
        ];
        // `n` is the detected chip count, a u8 straight off the wire.
        for n in 0u16..=255 {
            composed.push(rung_status_line(
                MiningRung::Ready.panel_word(),
                &format!("{n} chips OK"),
            ));
        }

        for line in &composed {
            assert!(
                line_fits(line),
                "init-screen line needs {} of {TEXT_COLUMNS} columns and will be \
                 clipped: {line:?}",
                line.chars().count()
            );
        }

        // Lead fix at merge (blind critic P1-O2 round 2, LOW): the width half above had become
        // circular - it composes with `rung_status_line`, the function under test. This block
        // states the expectation INDEPENDENTLY: when rung + ": " + detail fits the panel the
        // composer must return exactly that; otherwise it must return the bare rung word.
        let mut expected: Vec<(&str, String)> = vec![
            (MiningRung::TelemetryPending.panel_word(), "no telemetry".to_string()),
            (MiningRung::Standby.panel_word(), "ASIC FAILED".to_string()),
            (MiningRung::Standby.panel_word(), "disabled".to_string()),
        ];
        for n in 0u16..=255 {
            expected.push((MiningRung::Ready.panel_word(), format!("{n} chips OK")));
        }
        assert_eq!(expected.len(), composed.len());
        for ((w, d), line) in expected.iter().zip(composed.iter()) {
            let w: &str = w;
            let d: &str = d;
            let full = w.chars().count() + 2 + d.chars().count();
            let want = if full <= TEXT_COLUMNS { format!("{w}: {d}") } else { w.to_string() };
            assert_eq!(
                line, &want,
                "composer output is neither the full `RUNG: detail` ({full} cols) nor the bare rung"
            );
        }
    }
}

/// ============================================================================
/// P1-O2 ROUND 2 (DCENT_axe UI Gauntlet) - the boot/init screens lead with the
/// rung, inside a budget that is structural, and BOTH carousel pages decorate a
/// tick the same way.
///
/// Round 1 gave the panel the rung vocabulary. The blind critic then found
/// three things wrong with how it was used:
///
/// 1. the boot frame read `Mining: PENDING` - LABEL first, rung second - while
///    the other three init screens read `RUNG: detail`. The first word on the
///    first frame an operator ever sees was not the state;
/// 2. all four bypassed `fit_line`: raw `format!` into `draw_text`, which clips
///    at column 21 from the RIGHT, silently, with no ellipsis. The tightest was
///    20 of 21 columns and the one remaining column was guarded by nothing;
/// 3. page 0 chose decorations from `HOT/FED/NITE` and the companion page from
///    `HOT/FED/WOW`, so a night tick decorated one page and left the other bare.
///
/// The fixes are two host-pure functions in `dcentaxe-hal`:
/// [`crate::display_convert::rung_status_line`] (rung word unconditional,
/// detail appended only if the whole of it fits) and
/// [`crate::display_convert::rung_decoration`] (one table, four inputs, at most
/// one answer). Their BEHAVIOUR is unit-tested where they live. What cannot be
/// tested there is that `main.rs` - espidf-only, never host-compiled - actually
/// calls them, and calls the decoration table with the SAME inputs on both
/// pages. That join is what this module pins, and it is the join that four
/// previous callerless drivers in this project (`RailBringup`,
/// `tps5364x_convert`, `fxl6408_convert`, `tmp451_convert`) taught us to pin.
#[cfg(test)]
mod oled_truth_ladder_r2_guards {
    use crate::display_convert::{
        fit_line, rung_decoration, rung_status_line, MiningRung, TEXT_COLUMNS,
    };

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    fn lf(s: &str) -> String {
        s.replace("\r\n", "\n")
    }

    /// Every `rung_decoration(...)` call in `main.rs`, with its argument list
    /// normalised to single spaces so indentation is not part of the claim.
    fn decoration_call_args(src: &str) -> Vec<String> {
        const NEEDLE: &str = "rung_decoration(";
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find(NEEDLE) {
            let after = &rest[i + NEEDLE.len()..];
            let mut depth = 1usize;
            let mut end = None;
            for (j, c) in after.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.expect("unbalanced rung_decoration( call");
            out.push(after[..end].split_whitespace().collect::<Vec<_>>().join(" "));
            rest = &after[end..];
        }
        out
    }

    /// Critic finding 1: the boot frame leads with the RUNG, not with a label.
    #[test]
    fn the_boot_frame_leads_with_the_rung_not_a_label() {
        let src = lf(MAIN_RS);
        assert!(
            src.contains(
                "&rung_status_line(MiningRung::TelemetryPending.panel_word(), \"no telemetry\")"
            ),
            "the boot frame must compose its line rung-first through the \
             bounded composer"
        );
        assert!(
            !src.contains("format!(\"Mining: {}\""),
            "the LABEL-first boot line is back; the first word an operator \
             reads on the first frame must be the state"
        );

        let line = rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry");
        assert!(
            line.starts_with(MiningRung::TelemetryPending.panel_word()),
            "the rung leads: {line:?}"
        );
        assert_eq!(line, "PENDING: no telemetry");
        assert_eq!(
            line.chars().count(),
            TEXT_COLUMNS,
            "exactly on the budget; the composer degrades to a bare PENDING \
             rather than clipping if this ever stops fitting"
        );
    }

    /// Critic finding 2: none of the four rung-bearing init screens is a raw
    /// `format!` into `draw_text` any more.
    #[test]
    fn every_rung_bearing_init_screen_goes_through_the_bounded_composer() {
        let src = lf(MAIN_RS);
        assert!(
            src.contains("use dcentaxe_hal::display_convert::{rung_decoration, rung_status_line};"),
            "main.rs must import the bounded composers"
        );
        assert_eq!(
            src.matches("&rung_status_line(").count(),
            4,
            "exactly the four boot/init show_status lines are composed this \
             way; a fifth caller (or a lost one) means the evidence set and the \
             adopted critic guard no longer describe the panel"
        );
        // ...and no `show_status` argument is a bare state format! again. The
        // three shapes below are the ones the critic found bypassing fit_line.
        for banned in [
            "format!(\"Mining: {}\"",
            "format!(\"{}: {} chips OK\"",
            "format!(\"{}: ASIC FAILED\"",
            "format!(\"{}: disabled\"",
        ] {
            assert!(
                !src.contains(banned),
                "{banned} is back: it reaches draw_text unbounded and is \
                 clipped at column 21 with no ellipsis"
            );
        }
    }

    /// Critic finding 6: ONE decoration table, and both pages ask it the same
    /// question. The argument lists must be byte-identical after whitespace
    /// normalisation - a page that stopped passing `day_phase` would be the
    /// original divergence rebuilt.
    #[test]
    fn both_carousel_pages_read_one_decoration_table_with_identical_inputs() {
        let src = lf(MAIN_RS);
        let calls = decoration_call_args(&src);
        assert_eq!(
            calls.len(),
            2,
            "exactly two decoration sites - page 0 row 3 and the companion \
             page's activity word: {calls:?}"
        );
        assert_eq!(
            calls[0], calls[1],
            "the two pages decorate the same tick from different inputs again: \
             {calls:?}"
        );
        for input in [
            "max_temp > 85.0",
            "share_flash_tick > 0",
            "achievement_flash_tick > 0",
            "day_phase == \"night\"",
        ] {
            assert!(
                calls[0].contains(input),
                "the shared decoration inputs must still include {input}: {:?}",
                calls[0]
            );
        }
        // The two ad-hoc chains must not return.
        assert!(
            !src.contains("let deco: &[&str] = if max_temp > 85.0 {"),
            "the page-0 decoration chain must not return"
        );
        assert!(
            !src.contains("let pet_deco: &[&str] = if max_temp > 85.0 {"),
            "the companion-page decoration chain must not return"
        );
    }

    /// A decoration is flavour and must never be able to displace the rung, in
    /// either slot width, for any tick the firmware can produce.
    #[test]
    fn a_decoration_can_never_displace_the_rung_word() {
        const PET_ACTIVITY_COLUMNS: usize = 11;
        for hot in [false, true] {
            for fed in [false, true] {
                for wow in [false, true] {
                    for night in [false, true] {
                        let deco = rung_decoration(hot, fed, wow, night);
                        assert!(deco.len() <= 1, "at most one decoration: {deco:?}");
                        for rung in MiningRung::ALL {
                            for height in [0u64, 1, 868_123, 12_345_678, 21_000_000] {
                                let block = if height > 0 {
                                    format!("B:{height}")
                                } else {
                                    "B:---".to_string()
                                };
                                let row3 =
                                    fit_line(&[rung.panel_word(), &block], deco, TEXT_COLUMNS);
                                assert!(row3.starts_with(rung.panel_word()));
                                assert!(row3.contains(&block), "the block anchor survives");
                                assert!(row3.chars().count() <= TEXT_COLUMNS, "{row3:?}");

                                let pet =
                                    fit_line(&[rung.panel_word()], deco, PET_ACTIVITY_COLUMNS);
                                assert!(pet.starts_with(rung.panel_word()));
                                assert!(pet.chars().count() <= PET_ACTIVITY_COLUMNS, "{pet:?}");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// ============================================================================
/// HELD-OUT guard written by the blind critic for P1-O2 ROUND 2 (not adopted by
/// the lead yet - keep it or delete it, but do not silently loosen it).
///
/// Round 2's budget claims are GEOMETRY claims, and only some of the geometry
/// is pinned. `rung_status_line` is safe at any origin because the four
/// boot/init rows go through `show_status` -> `draw_status` -> `draw_centered`,
/// which centres them: 21 columns really is the budget there. Page 0 row 3 is
/// NOT centred. `main.rs` composes it with `fit_line(.., TEXT_COLUMNS)` = 21
/// and hands the result to `display.draw_text(0, 24, ..)`, and that budget is
/// correct ONLY because the origin is x = 0. `FrameBuffer::draw_text` clips
/// from the RIGHT, silently, with no ellipsis, so moving that origin to (say)
/// x = 36 would amputate the block anchor - and every existing P1-O2 guard
/// would stay green, because the lane pins the page-7 origins
/// (`the_companion_activity_budget_matches_its_geometry`) and pins the page-0
/// `fit_line` CALL, but nothing pins WHERE page 0 row 3 is drawn.
///
/// So this pins the origin, and DERIVES the budget from it rather than
/// asserting the same constant twice.
#[cfg(test)]
mod critic_p1_o2_r2_page0_row3_geometry {
    use crate::display_convert::{TEXT_COLUMNS, WIDTH};

    const MAIN_SRC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    /// The compose-and-draw pair for page 0 row 3, whitespace-normalised.
    const PAGE0_ROW3_SITE: &str = concat!(
        "display.draw_text( 0, 24, ",
        "&fit_line(&[rung.panel_word(), &block_short], deco, TEXT_COLUMNS), );"
    );

    /// Glyph pitch of the built-in 5x7 font: five columns plus one of spacing.
    const GLYPH_PITCH: usize = 6;
    /// Where `main.rs` draws page 0's rung row.
    const PAGE0_ROW3_ORIGIN_X: usize = 0;
    /// The right edge of the pet-room activity slot (the wattage origin).
    const PET_ROOM_RIGHT_EDGE_X: usize = 90;
    /// The left edge of the pet-room activity slot.
    const PET_ROOM_ORIGIN_X: usize = 22;
    /// The left edge of the full-pet activity slot.
    const FULL_PET_ORIGIN_X: usize = 36;

    /// Whitespace-normalised, so indentation and line breaks are not the claim
    /// and a reformat cannot fail this test.
    fn flat(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn page0_rung_row_is_drawn_at_x0_so_its_twenty_one_column_budget_is_real() {
        assert!(
            flat(MAIN_SRC).contains(PAGE0_ROW3_SITE),
            "page 0 row 3 no longer composes to TEXT_COLUMNS at origin x = 0. fit_line's budget is only honest if that row starts at the left edge: draw_text clips from the RIGHT with no ellipsis, so a non-zero origin silently amputates the block anchor (and then the rung word) while every other P1-O2 guard stays green. Expected to find: {PAGE0_ROW3_SITE}"
        );

        assert_eq!(
            (WIDTH - PAGE0_ROW3_ORIGIN_X) / GLYPH_PITCH,
            TEXT_COLUMNS,
            "TEXT_COLUMNS no longer describes a row drawn at x = {PAGE0_ROW3_ORIGIN_X} on a {WIDTH}px panel"
        );
    }

    /// The companion word is fitted against the TIGHTER of its two slots (11).
    /// If the full-pet origin ever moves right, that slot becomes the tighter
    /// one and the shared 11-column constant stops being conservative.
    #[test]
    fn the_companion_word_is_fitted_against_the_tighter_of_its_two_slots() {
        let src = flat(MAIN_SRC);
        assert!(
            src.contains("display.draw_text(36, 8, &activity);"),
            "the full-pet activity origin moved"
        );
        assert!(
            src.contains("display.draw_text(22, 25, &activity);"),
            "the pet-room activity origin moved"
        );
        let full_pet_columns = (WIDTH - FULL_PET_ORIGIN_X) / GLYPH_PITCH;
        let pet_room_columns = (PET_ROOM_RIGHT_EDGE_X - PET_ROOM_ORIGIN_X) / GLYPH_PITCH;
        assert!(
            pet_room_columns <= full_pet_columns,
            "main.rs fits the companion word to {pet_room_columns} columns assuming that is the tighter slot, but the full-pet layout now offers only {full_pet_columns}"
        );
        assert_eq!(pet_room_columns, 11);
    }
}

/// FUND-LINK guards, follow-up lane `P1-G1b` (DCENT_axe UI Gauntlet 2026-09-03).
///
/// Lane `P1-G1` made the Fund affordance reachable in every NAV STATE. A blind
/// critic then measured it per PAGE and found the hole this module closes: on
/// the Dashboard (`id="p0"`), where a first-time owner lands, there was **no
/// visible Fund instance in 8 of the 10 width x nav-state cells** (re-measured
/// on the mock 2026-09-03 before this lane: the sidebar footer is `height 0` /
/// `offsetParent null` in `body.col`, and `rect.left = -244` with the drawer
/// closed at 768/390/360; the System-page instance lives on `p4`, which is
/// `display:none` while the Dashboard is active, so it measured `height 0`).
/// Two further defects came from the same round: the sidebar-footer anchor
/// rendered browser-default link blue at **2.08:1** on `rgb(10,14,20)` because
/// the inline stylesheet had no `a { }` rule at all, and the System-page anchor
/// was a **320x15** tap target at 390.
///
/// These tests are ADDITIVE siblings. They never edit `fund_link_guards` or the
/// adopted held-out `critic_held_out_fund_anchor_is_inside_the_system_page_container`;
/// they add the `p0` half of the same containment idea plus the two
/// presentation invariants that source text CAN prove. Source text still cannot
/// prove PAINT - only the CDP probe can - but every cheap way to satisfy the
/// rule without shipping a visible, legible, tappable affordance is now refused.
#[cfg(test)]
mod fund_link_landing_page_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const CI_BAN_GATES_SH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scripts/ci_ban_gates.sh"
    ));
    const FUND_ANCHOR: &str = "href=\"https://d-central.tech/fund/";

    /// Every `<div class="page..." id="pN">` container start, in source order.
    /// `<div class="page-title">` is excluded by requiring the next byte after
    /// `page` to close the class (`"`) or start another class (` `).
    fn page_starts() -> Vec<usize> {
        DASHBOARD_RS
            .match_indices("<div class=\"page")
            .filter(|(i, m)| {
                let rest = &DASHBOARD_RS[i + m.len()..];
                rest.starts_with('"') || rest.starts_with(' ')
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Slice `DASHBOARD_RS` to ONE page container, bounded above by the next
    /// page container, so "inside the page" cannot decay into "anywhere later
    /// in the file" (the failure mode the round-1 held-out test named).
    fn page_slice(id: &str) -> &'static str {
        let marker = format!("\" id=\"{}\">", id);
        let starts = page_starts();
        let pos = starts
            .iter()
            .position(|&s| {
                let tag_end = DASHBOARD_RS[s..]
                    .find('>')
                    .map(|j| s + j + 1)
                    .unwrap_or(DASHBOARD_RS.len());
                DASHBOARD_RS[s..tag_end].contains(&marker)
            })
            .unwrap_or_else(|| {
                panic!(
                    "FUND/P1-G1b: the `{}` page container moved - re-point this guard",
                    id
                )
            });
        let start = starts[pos];
        let end = starts.get(pos + 1).copied().unwrap_or(DASHBOARD_RS.len());
        &DASHBOARD_RS[start..end]
    }

    /// The `p0` half of the held-out containment guard.
    ///
    /// The Dashboard is the landing page and the only page painted before the
    /// operator navigates anywhere. An instance that lives only in the sidebar
    /// chrome disappears in `body.col` and off-canvas below 769 px; an instance
    /// that lives only on `p4` is `display:none` until the operator already went
    /// looking. So one anchor must be inside `id="p0"` itself.
    #[test]
    fn a_fund_anchor_is_inside_the_dashboard_page_container_and_not_inline_hidden() {
        let page = page_slice("p0");
        let at = page.find(FUND_ANCHOR).unwrap_or_else(|| {
            panic!(
                "FUND/P1-G1b (root  2026-07-10 HARD RULE): no anchor whose href \
                 starts with https://d-central.tech/fund/ lives INSIDE the Dashboard page \
                 container (`id=\"p0\"` .. next page container, {} bytes). Measured on the \
                 mock: without it the affordance is invisible on the LANDING page in 8 of \
                 10 width x nav-state cells (sidebar footer height 0 in `body.col`, \
                 left=-244 with the drawer closed at <= 768; the System instance sits on \
                 p4, which is display:none while the Dashboard is active).",
                page.len()
            )
        });
        let line_start = page[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = page[at..].find('\n').map(|i| at + i).unwrap_or(page.len());
        let line = &page[line_start..line_end];
        let squashed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            !squashed.contains("display:none"),
            "FUND/P1-G1b: the Dashboard Fund anchor's own source line carries an inline \
             `display:none`, so the affordance is in the HTML and off the screen. Line: {}",
            line.trim()
        );
        assert!(
            !line.contains(" hidden>") && !line.contains(" hidden "),
            "FUND/P1-G1b: the Dashboard Fund anchor's own source line carries the `hidden` \
             attribute. Line: {}",
            line.trim()
        );
        assert!(
            line.contains("target=_blank") || line.contains("target=\"_blank\""),
            "FUND/P1-G1b: the Dashboard Fund anchor must open in a new tab. Line: {}",
            line.trim()
        );
        assert!(
            line.contains("rel=noopener") || line.contains("rel=\"noopener\""),
            "FUND/P1-G1b: the Dashboard Fund anchor must carry rel=noopener. Line: {}",
            line.trim()
        );
    }

    /// Both PAGE instances carry the shared `.fund` class, and that class is a
    /// >= 44 px touch target with a footer rule.
    ///
    /// The blind critic measured the System-page anchor at **320x15** on a 390
    /// viewport - a third of the 44 px floor the rubric applies outside dense
    /// data tables. `display:block` + `padding:16px 0` on a ~15 px line box
    /// yields ~47 px, and the same class gives the anchor a card/page FOOTER
    /// rule (`border-top`) so a donation link no longer reads as one more row of
    /// the Integrations list it was sitting inside.
    #[test]
    fn the_page_fund_anchors_use_the_fund_class_and_it_is_a_44px_touch_target() {
        for tag in ["placement=p0", "placement=sys"] {
            let at = DASHBOARD_RS
                .find(tag)
                .unwrap_or_else(|| panic!("FUND/P1-G1b: the `{}` anchor is gone", tag));
            let line_start = DASHBOARD_RS[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let head = &DASHBOARD_RS[line_start..at];
            assert!(
                head.contains("class=fund") || head.contains("class=\"fund\""),
                "FUND/P1-G1b: the `{}` anchor must carry the shared `fund` class \
                 (>= 44 px touch target + footer rule). Line head: {}",
                tag,
                head.trim()
            );
        }
        let rule_at = DASHBOARD_RS
            .find(".fund{")
            .expect("FUND/P1-G1b: the `.fund` utility rule was deleted from the inline CSS");
        let rule_end = DASHBOARD_RS[rule_at..]
            .find('}')
            .map(|j| rule_at + j)
            .unwrap_or(DASHBOARD_RS.len());
        let rule = &DASHBOARD_RS[rule_at..rule_end];
        assert!(
            rule.contains("display:block"),
            "FUND/P1-G1b: `.fund` must be display:block - vertical padding on an INLINE \
             anchor gives the row no layout height of its own. Rule: {}",
            rule
        );
        assert!(
            rule.contains("border-top"),
            "FUND/P1-G1b: `.fund` must keep its `border-top` footer rule - without it the \
             amber link reads as a stray row of the Integrations list rather than the \
             card/page footer it is. Rule: {}",
            rule
        );
        let pad = rule
            .find("padding:")
            .map(|i| &rule[i + "padding:".len()..])
            .expect("FUND/P1-G1b: `.fund` must keep its padding (that IS the touch target)");
        let px: u32 = pad
            .split(|c: char| !c.is_ascii_digit())
            .find(|s| !s.is_empty())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        assert!(
            px >= 15,
            "FUND/P1-G1b: `.fund` vertical padding is {}px; with a ~15px line box the anchor \
             needs >= 15px top and bottom to clear the 44px touch floor the rubric applies \
             at 390 (measured baseline: 320x15). Rule: {}",
            px,
            rule
        );
    }

    /// The inline stylesheet must keep a bare `a { color: ... }` rule.
    ///
    /// Before this lane the file had NO `a` rule, so every anchor without an
    /// explicit colour rendered browser-default `rgb(0,0,238)`: measured
    /// **2.08:1** against the sidebar's `rgb(10,14,20)`, far under the 4.5:1
    /// floor, on the Fund link the HARD RULE exists to protect. Three inline
    /// `color:var(--accent)` overrides were deleted in the same change because
    /// this rule makes them dead, so deleting the rule now regresses FOUR
    /// anchors at once.
    #[test]
    fn bare_anchors_paint_from_the_accent_token_not_browser_default_blue() {
        let at = DASHBOARD_RS.find("\na,.text-accent{").unwrap_or_else(|| {
            panic!(
                "FUND/P1-G1b: the inline CSS lost its bare `a` colour rule. Without it the \
                 sidebar-footer Fund anchor (dashboard.rs ~:768), the on-chain payout link, \
                 the block-modal mempool link and the coredump link all fall back to \
                 browser-default blue - measured 2.08:1 on rgb(10,14,20)."
            )
        });
        let end = DASHBOARD_RS[at..]
            .find('}')
            .map(|j| at + j)
            .unwrap_or(DASHBOARD_RS.len());
        let decl = DASHBOARD_RS[at..end].trim();
        assert!(
            decl.contains("var(--accent)"),
            "FUND/P1-G1b: the bare `a` rule must paint from the --accent TOKEN, never a raw \
             hex (rubric H5). Rule: {}",
            decl
        );
        assert!(
            !DASHBOARD_RS.contains("style=\"color:var(--accent)\">verify on-chain"),
            "FUND/P1-G1b: the on-chain payout link re-grew the inline colour the bare `a` \
             rule replaced - the two must not drift apart again"
        );
    }

    /// The ban gate mirrors the landing-page instance too.
    ///
    /// Gates [13]/[14] pin the `dashboard` and `sys` placement tags; the
    /// landing-page instance needs its own, or a scrub that deletes exactly the
    /// `p0` anchor leaves the anchor COUNT at 2 and every gate green.
    #[test]
    fn the_landing_page_placement_tag_is_pinned_by_the_ci_ban_gate_too() {
        assert!(
            CI_BAN_GATES_SH.contains("source=dcent_axe&placement=p0\""),
            "FUND/P1-G1b: scripts/ci_ban_gates.sh must require the landing-page placement \
             tag (`placement=p0`) distinctly, the way [13]/[14] require `dashboard` and \
             `sys` - otherwise deleting the p0 anchor keeps the count at 2 and the gate \
             stays green."
        );
    }
}

/// HELD-OUT (blind critic, lane `P1-G1b`, round 1, 2026-09-03).
///
/// The lane's `a_fund_anchor_is_inside_the_dashboard_page_container_and_not_inline_hidden`
/// and the adopted round-1 held-out both inspect **the anchor's own source line**
/// for `display:none` / `hidden`. The critic falsified the lane's claim that
/// "every cheap way to satisfy the rule without shipping a visible, legible,
/// tappable affordance is now refused": opening the wrapper on the PREVIOUS line
///
/// ```text
///  <div style="display:none">
///  <a class=fund href="https://d-central.tech/fund/go?...&placement=p0" ...>Fund open firmware</a>
///  </div>
/// ```
///
/// left the anchor's own line spotless. Measured on the mock at 1440x900 with
/// that mutation in place: `p0 0x0 op=false | sys 0x0 op=false` - the affordance
/// was invisible - while `cargo test -p dcentaxe-core` reported **440 passed, 0
/// failed** and `scripts/ci_ban_gates.sh` exited 0. Line-local inspection cannot
/// see an ancestor.
///
/// This test walks the enclosing `<div>` ancestry INSIDE the page container and
/// fails if any wrapper that is still open at the anchor carries an inline
/// `display:none` / `visibility:hidden` / the `hidden` attribute. It is bounded
/// to the same page slice as the guards it strengthens, so it cannot decay into
/// "anywhere in the file", and it covers BOTH page instances (`p0` and `p4`).
///
/// Source text still cannot prove PAINT - only the CDP probe can. It can prove
/// that no ancestor in the anchor's own page container declares it away.
#[cfg(test)]
mod critic_held_out_no_hidden_ancestor_wraps_a_page_fund_anchor {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const FUND_ANCHOR: &str = "href=\"https://d-central.tech/fund/";

    /// Start offsets of every `<div class="page...` page container, in source order.
    fn page_starts() -> Vec<usize> {
        DASHBOARD_RS
            .match_indices("<div class=\"page")
            .filter(|(i, m)| {
                let rest = &DASHBOARD_RS[i + m.len()..];
                rest.starts_with('"') || rest.starts_with(' ')
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn page_slice(id: &str) -> &'static str {
        let marker = format!("\" id=\"{}\">", id);
        let starts = page_starts();
        let pos = starts
            .iter()
            .position(|&s| {
                let tag_end = DASHBOARD_RS[s..]
                    .find('>')
                    .map(|j| s + j + 1)
                    .unwrap_or(DASHBOARD_RS.len());
                DASHBOARD_RS[s..tag_end].contains(&marker)
            })
            .unwrap_or_else(|| panic!("HELD-OUT/P1-G1b: page container `{}` moved", id));
        let start = starts[pos];
        let end = starts.get(pos + 1).copied().unwrap_or(DASHBOARD_RS.len());
        &DASHBOARD_RS[start..end]
    }

    /// True if the opening tag between `lt` and its `>` declares the element away.
    fn tag_is_hidden(tag: &str) -> bool {
        let squashed: String = tag.chars().filter(|c| !c.is_whitespace()).collect();
        squashed.contains("display:none")
            || squashed.contains("visibility:hidden")
            || tag.contains(" hidden>")
            || tag.contains(" hidden ")
    }

    /// Walk `<div ...>` / `</div>` from the start of `page` up to `upto`, keeping
    /// a stack of open divs, and return the opening tags still open at `upto`.
    fn open_ancestors(page: &str, upto: usize) -> Vec<String> {
        let mut stack: Vec<String> = Vec::new();
        let bytes = page.as_bytes();
        let mut i = 0usize;
        while i < upto {
            if bytes[i] != b'<' {
                i += 1;
                continue;
            }
            let rest = &page[i..];
            if rest.starts_with("</div") {
                stack.pop();
                i += 5;
            } else if rest.starts_with("<div") {
                let end = rest.find('>').map(|j| i + j + 1).unwrap_or(upto);
                let tag = &page[i..end.min(page.len())];
                // A self-closed `<div/>` never opens a scope; the file has none,
                // but be explicit rather than silently wrong if one appears.
                if !tag.trim_end().ends_with("/>") {
                    stack.push(tag.to_string());
                }
                i = end;
            } else {
                i += 1;
            }
        }
        stack
    }

    #[test]
    fn no_hidden_ancestor_wraps_the_dashboard_or_system_page_fund_anchor() {
        for id in ["p0", "p4"] {
            let page = page_slice(id);
            let at = page.find(FUND_ANCHOR).unwrap_or_else(|| {
                panic!(
                    "HELD-OUT/P1-G1b: no fund anchor inside page container `{}` \
                     ({} bytes) - the containment guards should have caught this first",
                    id,
                    page.len()
                )
            });
            let hidden: Vec<String> = open_ancestors(page, at)
                .into_iter()
                .filter(|t| tag_is_hidden(t))
                .collect();
            assert!(
                hidden.is_empty(),
                "HELD-OUT/P1-G1b (root  2026-07-10 Fund HARD RULE): the fund \
                 anchor inside page `{}` is wrapped by {} still-open element(s) that \
                 declare it away, so the affordance is in the HTML and off the screen. \
                 The lane's line-local `display:none` checks cannot see an ancestor: \
                 measured on the mock, a wrapper opened one line above left the anchor \
                 at 0x0 / offsetParent=null while all 440 dcentaxe-core tests and the \
                 ban gate stayed green. Offending open tag(s): {:?}",
                id,
                hidden.len(),
                hidden
            );
        }
    }

    /// The `p0` instance must be the LAST element of the Dashboard container.
    ///
    /// The lane appended it after the final card, which is why the page footer
    /// costs the first viewport nothing (measured: `scrollWidth` at 390/360 is
    /// byte-identical to the base tree, and page height grows by 50 px at the
    /// BOTTOM). Move it up between two cards and it starts pushing telemetry the
    /// operator came for; no lane guard would notice.
    #[test]
    fn the_dashboard_fund_anchor_is_the_last_element_of_the_landing_page() {
        let page = page_slice("p0");
        let at = page
            .find(FUND_ANCHOR)
            .expect("HELD-OUT/P1-G1b: no fund anchor inside `p0`");
        let close = page[at..]
            .find("</a>")
            .map(|j| at + j + 4)
            .expect("HELD-OUT/P1-G1b: the p0 fund anchor is unterminated");
        let tail = &page[close..];
        // Everything after the anchor must be whitespace, the container's own
        // closing tag, and HTML comments - no further content elements.
        let mut rest = tail.trim();
        while let Some(s) = rest.strip_prefix("</div>") {
            rest = s.trim();
        }
        while rest.starts_with("<!--") {
            match rest.find("-->") {
                Some(j) => rest = rest[j + 3..].trim(),
                None => break,
            }
        }
        assert!(
            rest.is_empty(),
            "HELD-OUT/P1-G1b: the Dashboard fund anchor is no longer the last element \
             of the `p0` container - {} bytes of content follow it inside the page, so \
             the footer line now sits between cards and pushes telemetry down. \
             Next content: {:?}",
            rest.len(),
            &rest[..rest.len().min(120)]
        );
    }
}

/// TRUTH-COPY guards (`P1-W3`, DCENT_axe UI Gauntlet 2026-09-03).
///
/// Four separate copy defects on the served dashboard, all invisible to the
/// compiler because `dashboard.rs` is `target_os = "espidf"`-only:
///
/// 1. **The Health tile contradicted every other state surface.** The tile read
///    `health = !mining ? 'Stopped' : ...`, and `mining` means *permitted AND
///    hashing*. In the `ready` rung (permitted, zero hashrate) the topbar pill,
///    the hero badge and the Logs pill all printed `READY` while the Health tile
///    printed `Stopped` - measured on the mock 2026-09-03, scenario `ready`.
///    Four surfaces each re-derived the rung from `mining`/`miningEnabled` with
///    their own ternary, so they could drift; now ONE `_rung` variable feeds all
///    four and the drift is inexpressible. That single-source property is the
///    load-bearing part of these guards, not the individual strings.
/// 2. **A fifth vocabulary for the four autotuner modes.** The Schedule policy
///    `<select>` labelled them `Autotune efficiency / watts / temp / max` while
///    `#atMode` and `#frMode` use the canonical Max Hashrate / Best Efficiency /
///    Target Watts / Target Temp (`DCENT_OS_ESP/, DCENT Design
///    Language; terminology-lexicon contract).
/// 3. **`LOG STREAM - LIVE` claimed a device log stream that does not exist.**
///    Every line on the Logs page is synthesized client-side from 15 s
///    `/api/system/info` deltas (`mlog(...)` call sites). There is no ring
///    buffer and no `/api/system/logs` endpoint; adding one is a separate,
///    handler-spending lane. The header now states its provenance.
/// 4. **`mempool.space` was polled every 60 s by default**, disclosing the
///    operator's IP to a third party with no consent step. It is now behind a
///    one-tap opt-in persisted in `localStorage`, default OFF; the em-dash empty
///    state is what a fresh install shows. The MECHANISM is unchanged - it is
///    still the handler-free cross-origin browser fetch that
///    `dashboard_evidence_guards::mempool_radial_uses_cross_origin_fetch_not_a_local_handler`
///    pins - only the DEFAULT moved.
///
/// These are source-TEXT contracts in the same shape as
/// `dcent_design_language_guards` / `dashboard_evidence_guards`. They only ADD;
/// no existing guard is touched.
#[cfg(test)]
mod dashboard_truth_copy_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn count(hay: &str, needle: &str) -> usize {
        hay.match_indices(needle).count()
    }

    // ── (a) ONE rung word, four surfaces. ────────────────────────────────────
    #[test]
    fn one_rung_variable_feeds_topbar_hero_logs_pill_and_health_tile() {
        // The single definition. `mining` = permitted AND hashing; `miningEnabled`
        // = permitted. Telemetry-pending is handled before first data arrives.
        assert!(
            DASHBOARD_RS.contains(
                "var _rung=mining?'Mining':miningEnabled?'Ready':'Standby',_RUNG=mining?'MINING':miningEnabled?'READY':'STANDBY';"
            ),
            "P1-W3: the truth-ladder rung must be derived ONCE into `_rung`/`_RUNG`; \
             every state surface reads those variables so they cannot disagree"
        );
        // The four consumers.
        for (consumer, needle) in [
            ("topbar legacy pill #tbMining", "id=\"tbMiningDot\"></span>'+_RUNG}"),
            ("hero badge #heroMiningState", "ms.textContent=_rung;"),
            ("topbar pill #tbMiningPill", "'<span class=\"tb-mining-dot\"></span>'+_RUNG}"),
            ("Logs crumb pill #logStatePill", "setLogMiningState(_RUNG,mining);"),
            ("Health stat tile #healthQuick", "var health=!mining?_rung:"),
        ] {
            assert!(
                DASHBOARD_RS.contains(needle),
                "P1-W3: {consumer} must read the shared rung variable (`{needle}` missing)"
            );
        }
        // Each ladder is written ONCE, on the shared `_rung`/`_RUNG` definition
        // line. BOTH literal families are kept, deliberately: the pre-existing
        // `dcent_design_language_guards::truth_ladder_ready_standby_present_old_enabled_label_gone`
        // pins the uppercase pill labels as SOURCE literals, so a `.toUpperCase()`
        // derivation would erase them from the text and fail that guard (observed,
        // 2026-09-03). A SECOND occurrence of either ternary means a surface has
        // gone back to deriving its own copy.
        for (ternary, family) in [
            ("miningEnabled?'READY':'STANDBY'", "uppercase pill"),
            ("miningEnabled?'Ready':'Standby'", "mixed-case badge"),
        ] {
            assert_eq!(
                count(DASHBOARD_RS, ternary),
                1,
                "P1-W3: the {family} rung ternary `{ternary}` must appear exactly ONCE (on \
                 the shared definition line). A second occurrence is a surface re-deriving \
                 the rung - that is exactly how the Health tile came to print `Stopped` \
                 under a READY topbar"
            );
        }
    }

    // ── (a) the Health tile never renders the contradicting word again. ──────
    #[test]
    fn health_tile_does_not_print_stopped_while_the_rung_is_ready() {
        assert!(
            !DASHBOARD_RS.contains("var health=!mining?'Stopped'"),
            "P1-W3: the Health tile must use the rung word (`Ready`/`Standby`), not the \
             literal 'Stopped' - in the `ready` rung the tile contradicted the topbar pill, \
             the hero badge and the Logs pill on the same screen"
        );
        // The existing sub-line (glyph + state + accepted-share provenance) is kept:
        // the tile still says WHY, it just no longer lies about WHAT.
        assert!(
            DASHBOARD_RS.contains("var acceptedProof=acceptedFresh?")
                && DASHBOARD_RS.contains("S('healthQuickLabel',hSubGlyph+' '+hSubText+"),
            "P1-W3: the Health tile's honest sub-line (accepted-share proof / `pool offline`) \
             must survive the rung-word change"
        );
    }

    // ── (b) one vocabulary for the four autotuner modes. ─────────────────────
    #[test]
    fn schedule_policy_select_uses_the_four_canonical_autotuner_mode_names() {
        // The Schedule row builder's <select id="sPolicy...">.
        assert!(
            DASHBOARD_RS.contains("<select id=\"sPolicy'+i+'\">"),
            "P1-W3: the Schedule policy select moved - re-point this guard"
        );
        for label in [
            ">Best Efficiency</option>",
            ">Target Watts</option>",
            ">Target Temp</option>",
            ">Max Hashrate</option>",
        ] {
            assert!(
                DASHBOARD_RS.contains(label),
                "P1-W3: the Schedule policy select must use the canonical autotuner mode \
                 name `{label}` (DCENT Design Language: Max Hashrate / Best Efficiency / \
                 Target Watts / Target Temp)"
            );
        }
        for banned in [
            "Autotune efficiency",
            "Autotune watts",
            "Autotune temp",
            "Autotune max",
        ] {
            assert!(
                !DASHBOARD_RS.contains(banned),
                "P1-W3: `{banned}` is a fifth vocabulary for a mode that already has a \
                 canonical name - the same mode must read the same everywhere"
            );
        }
    }

    // ── (c) the Logs header states its provenance instead of claiming LIVE. ──
    #[test]
    fn logs_header_says_event_feed_derived_from_telemetry_not_live_stream() {
        assert!(
            !DASHBOARD_RS.contains("LOG STREAM &middot; LIVE")
                && !DASHBOARD_RS.contains("LOG STREAM · LIVE"),
            "P1-W3: the Logs page has no device log stream - every line is synthesized \
             client-side from 15 s /api/system/info deltas - so it must not advertise \
             `LOG STREAM · LIVE`. A real stream is a separate handler-spending lane"
        );
        assert!(
            DASHBOARD_RS.contains(">EVENT FEED</span>"),
            "P1-W3: the Logs stream header must be titled `EVENT FEED`"
        );
        assert!(
            DASHBOARD_RS.contains("&middot; derived from telemetry every 15 s"),
            "P1-W3: the Logs stream header must state its provenance verbatim \
             (`· derived from telemetry every 15 s`) next to the title"
        );
        // The poll it names is the real one: 15 s while visible.
        assert!(
            DASHBOARD_RS.contains("var rate=document.hidden?30000:15000;"),
            "P1-W3: the Logs header names a 15 s cadence - keep it joined to the actual \
             foreground poll rate, or change both together"
        );
    }

    // ── (d) no third-party request before the operator opts in. ──────────────
    #[test]
    fn mempool_space_fee_poll_is_opt_in_and_default_off() {
        // The consent record is browser-local, and reading it is fail-closed:
        // a throwing/absent localStorage means NOT opted in.
        assert!(
            DASHBOARD_RS.contains("var _MPOPT='dcentaxe-mempool-optin';"),
            "P1-W3: the mempool opt-in must be persisted under a stable localStorage key"
        );
        assert!(
            DASHBOARD_RS.contains(
                "function mempoolOptedIn(){try{return localStorage.getItem(_MPOPT)==='1'}catch(e){return false}}"
            ),
            "P1-W3: the opt-in predicate must be fail-CLOSED - an absent or throwing \
             localStorage (private mode, blocked storage) means NOT opted in"
        );
        // The poll starter refuses to fetch before consent. This is the whole lane:
        // the `if(!on)return;` must sit BEFORE the first fetch and before the timer.
        let start = DASHBOARD_RS
            .find("function startMempoolPoll(){")
            .expect("P1-W3: startMempoolPoll() moved - re-point this guard");
        let body_end = DASHBOARD_RS[start..]
            .find('\n')
            .map(|i| start + i)
            .unwrap_or(DASHBOARD_RS.len());
        let body = &DASHBOARD_RS[start..body_end];
        let gate = body
            .find("if(!on)return;")
            .expect("P1-W3: startMempoolPoll() must return early when not opted in");
        let fetch_at = body
            .find("fetchMempoolFees()")
            .expect("P1-W3: startMempoolPoll() must still be the thing that starts the poll");
        let timer_at = body
            .find("setInterval(fetchMempoolFees")
            .expect("P1-W3: the 60 s mempool timer must live inside startMempoolPoll()");
        assert!(
            gate < fetch_at && gate < timer_at,
            "P1-W3: the consent gate must precede BOTH the first mempool.space fetch and \
             the 60 s timer. Body: {body}"
        );
        // Nothing else may start the poll behind the operator's back: the only
        // fetch/timer call sites are inside startMempoolPoll (plus the interval).
        assert_eq!(
            count(DASHBOARD_RS, "fetchMempoolFees"),
            3,
            "P1-W3: `fetchMempoolFees` may be mentioned exactly 3 times - its definition, \
             the consent-gated call, and the consent-gated 60 s timer. A fourth mention is \
             a call site outside the gate, i.e. a default-on third-party request"
        );
        // The disclosure names what is sent and to whom, in the control itself.
        assert!(
            DASHBOARD_RS.contains("mempool.space fees (sends this device's IP to mempool.space)"),
            "P1-W3: the opt-in control must disclose WHAT is sent and TO WHOM in its own \
             accessible name, not in a tooltip"
        );
        // It is a real <button>: keyboard-reachable and named, with no new handler.
        assert!(
            DASHBOARD_RS.contains("<button type=\"button\" id=\"mpOptIn\"")
                && DASHBOARD_RS.contains("onclick=\"mempoolToggle()\""),
            "P1-W3: the opt-in must be a native <button> (tabbable, Enter/Space) - not a \
             div with a click handler"
        );
        // The em-dash empty state is what an un-opted-in install shows.
        assert!(
            DASHBOARD_RS.contains("renderMempoolRadial(null);"),
            "P1-W3: the default (un-opted-in) render must be the honest em-dash empty state"
        );
    }

    // ── (d) the browser makes no OTHER third-party request by default. ───────
    #[test]
    fn mempool_space_is_the_only_absolute_url_the_dashboard_fetches() {
        let absolute: Vec<&str> = DASHBOARD_RS
            .match_indices("fetch('http")
            .chain(DASHBOARD_RS.match_indices("fetch(\"http"))
            .map(|(i, _)| {
                let rest = &DASHBOARD_RS[i..];
                &rest[..rest.find(')').map(|j| j + 1).unwrap_or(rest.len().min(120))]
            })
            .collect();
        assert_eq!(
            absolute,
            vec!["fetch('https://mempool.space/api/v1/fees/recommended')"],
            "P1-W3 (rubric H11): the dashboard may make exactly ONE absolute-URL browser \
             fetch, the opt-in mempool.space fee poll. Found: {absolute:?}"
        );
    }
}

/// CRITIC HELD-OUT TEST (`P1-W3`, round 1, blind critic — the builder never saw this).
///
/// The lane's own guards prove ONE `_rung` variable now feeds the four state
/// surfaces **inside `dashboard.rs`**. Measured on the mock 2026-09-03 they all
/// agree in `mining` / `ready` / `standby` / `first-run` / `pool-offline`.
///
/// But the served product has a **fifth** state surface the lane's footprint never
/// touched: the `mining-core` component in `dcentaxe/src/dashboard/core.js`, which
/// re-derives the same ladder from `window.state` with its own ternary
/// (`core.js:99-112`) and paints its own `MINING` / `READY` / `STANDBY` pill one
/// card above the Health tile the lane just fixed. Nothing joins the two files, so
/// `count(ternary) == 1` inside `dashboard.rs` cannot see a drift introduced in
/// `core.js` — and a drift there reproduces exactly the defect this lane closed
/// (two state words for one state, on one screen).
///
/// This guard binds the fifth surface to the same vocabulary and the same
/// predicate: `mining` = permitted AND positive hashrate, and the badge words are
/// the shared rungs, nothing else.
#[cfg(test)]
mod critic_held_out_core_js_rung_ladder_cannot_drift_from_dashboard_rs {
    const CORE_JS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/core.js"
    ));
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    #[test]
    fn mining_core_pill_uses_the_same_predicate_and_the_same_rung_words() {
        // Same predicate as dashboard.rs: permitted AND hashing. If core.js ever
        // pills on `miningEnabled` alone it prints MINING at zero hashrate.
        assert!(
            CORE_JS.contains("var mining = miningEnabled && hrGH > 0;"),
            "P1-W3 held-out: the mining-core component must derive `mining` as \
             permitted AND positive hashrate, the same predicate dashboard.rs uses \
             for `_rung`; anything looser prints MINING while the Health tile says Ready"
        );
        // Same words, all four rungs, as badge text.
        for rung in ["PENDING", "MINING", "READY", "STANDBY"] {
            assert!(
                CORE_JS.contains(&format!("</span>{rung}</span>")),
                "P1-W3 held-out: the mining-core pill must render the shared rung word \
                 `{rung}`"
            );
        }
        // No sixth vocabulary on that badge - these are the words the campaign has
        // already had to remove from other surfaces.
        for banned in ["ENABLED", "STOPPED", "DISABLED", ">OFF<", "HASHING"] {
            assert!(
                !CORE_JS.contains(banned),
                "P1-W3 held-out: `{banned}` is not a truth-ladder rung; the mining-core \
                 badge sits one card above the Health tile and must not introduce a \
                 second word for the same state"
            );
        }
        // The screen-reader ladder must match the visible one, rung for rung.
        assert!(
            CORE_JS.contains(
                "(mining ? ', mining' : miningEnabled ? ', ready' : telemetryReady ? ', standby' : ', telemetry pending')"
            ),
            "P1-W3 held-out: the mining-core aria-label must announce the same four \
             rungs as the visible pill, in the same order"
        );
        // Cross-file: every uppercase rung dashboard.rs can emit is a rung core.js
        // can emit. This is the join the lane's in-file `count(...) == 1` cannot make.
        assert!(
            DASHBOARD_RS.contains("_RUNG=mining?'MINING':miningEnabled?'READY':'STANDBY'"),
            "P1-W3 held-out: dashboard.rs's shared uppercase rung ternary moved - \
             re-point this guard before trusting it"
        );
        for rung in ["MINING", "READY", "STANDBY"] {
            assert!(
                DASHBOARD_RS.contains(rung) && CORE_JS.contains(rung),
                "P1-W3 held-out: rung `{rung}` must exist on BOTH the inline surfaces \
                 and the mining-core component - one file may not retire a rung alone"
            );
        }
    }
}

/// ── P1-W5 (DCENT_axe UI Gauntlet, 2026-09-03) ─────────────────────────────
/// The MOBILE SHELL. Three defects motivated these guards, all measured on the
/// mock at 390x844 and 360x780 before the lane touched anything:
///
///   1. **Every page scrolled horizontally.** `document.documentElement`
///      reported `scrollWidth` 667..705 against a `clientWidth` of 390 on all
///      seven pages, because `.topbar-left` (crumbs + three status pills) and
///      `.topbar-right` (six controls) neither shrank nor wrapped. At 768 the
///      same cluster measured 374x112 at `y = -32` — a 112 px block hanging out
///      of a 56 px bar. Rubric H9 calls that an automatic REJECT.
///   2. **The drawer was not a modal surface.** The slide-in sidebar had no
///      scrim, no outside-tap close, no focus containment and no Escape, and
///      `closeSBMobile()` unconditionally cleared `.open` — so nothing told a
///      keyboard or screen-reader user that the page behind it was inert.
///   3. **Three of seven pages were only behind an unlabelled hamburger** and
///      the four tabs that existed announced nothing (`aria-current` absent).
///
/// `dashboard.rs` is `target_os = "espidf"`-only and cannot host-compile, so —
/// exactly like `dcent_design_language_guards`, `dashboard_evidence_guards`,
/// `dashboard_a11y_nav_guards` and `fund_link_guards` — these pin the invariants
/// against the source TEXT via `include_str!`, on a whitespace-collapsed copy so
/// a benign reflow cannot flip a guard. They are ADDITIVE: no existing guard is
/// touched, renamed, weakened or ignored.
///
/// NOTE ON THE TAB SET. The bar surfaces five of the seven pages
/// (Dash/Pool/Logs/System/Settings) and the drawer keeps all seven. That is NOT
/// a new top-level nav item under rubric H10 — H10 bounds the PAGE ROSTER
/// ("a new top-level nav item beyond 8"), and `PAGE_NAMES` still declares seven,
/// which `A11Y-NAV-0` already pins. `MOBILE-2` below binds the tab set to that
/// same roster so a tab can never point at a page that does not exist.
#[cfg(test)]
mod dashboard_mobile_shell_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn flat() -> String {
        DASHBOARD_RS.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The body of one CSS rule, selected by its `<selector>{` opener.
    fn css_rule(selector_open: &str) -> String {
        let f = flat();
        let at = f
            .find(selector_open)
            .unwrap_or_else(|| panic!("MOBILE: CSS rule `{selector_open}` must exist"));
        let rest = &f[at + selector_open.len()..];
        let end = rest.find('}').expect("MOBILE: CSS rule must be closed");
        rest[..end].to_string()
    }

    /// The `go(n)` indices the bottom tab bar links to, in bar order.
    fn tab_targets() -> Vec<usize> {
        let f = flat();
        let at = f
            .find("<nav class=\"mobile-tabs\" aria-label=\"Primary\">")
            .expect("MOBILE: the bottom tab bar container moved");
        let end = at + f[at..].find("</div>").expect("MOBILE: tab bar unterminated");
        let bar = f[at..end].to_string();
        bar.match_indices("<button onclick=\"go(")
            .map(|(i, m)| {
                let rest = &bar[i + m.len()..];
                let stop = rest.find(')').expect("MOBILE: unterminated go( in the tab bar");
                rest[..stop]
                    .parse::<usize>()
                    .expect("MOBILE: non-numeric tab target")
            })
            .collect()
    }

    // ── MOBILE-1: the bar's column count IS its button count. A 5th button
    //    under a `repeat(4,1fr)` grid silently drops off the row. ────────────
    #[test]
    fn the_tab_bar_grid_declares_one_column_per_tab() {
        let n = tab_targets().len();
        assert!(
            n >= 5,
            "MOBILE-1: the bar must surface at least five pages, found {n}"
        );
        let rule = css_rule(".mobile-tabs{display:grid;");
        assert!(
            rule.contains(&format!("grid-template-columns:repeat({n},1fr)")),
            "MOBILE-1: the tab bar has {n} buttons but its grid is `{rule}`. A column \
             count that disagrees with the button count pushes the last tab out of the \
             row instead of erroring."
        );
    }

    // ── MOBILE-2: every tab points at a page that exists AND has a drawer
    //    link, and no page is in the bar twice. ──────────────────────────────
    #[test]
    fn every_tab_targets_a_real_page_that_also_lives_in_the_drawer() {
        let f = flat();
        let names = {
            const HEAD: &str = "var PAGE_NAMES=[";
            let s = f.find(HEAD).expect("MOBILE-2: PAGE_NAMES must exist") + HEAD.len();
            let e = s + f[s..].find(']').expect("MOBILE-2: PAGE_NAMES unterminated");
            f[s..e].split(',').count()
        };
        let mut seen = std::collections::BTreeSet::new();
        for t in tab_targets() {
            assert!(
                t < names,
                "MOBILE-2: tab go({t}) is past the end of PAGE_NAMES ({names} pages). \
                 go() bounds-checks and returns, so the tab would be a dead control."
            );
            assert!(
                f.contains(&format!("id=\"mn{t}\"")),
                "MOBILE-2: the tab for page {t} must carry id=mn{t} - go() syncs the \
                 active tab through E('mn'+n)."
            );
            assert!(
                f.contains(&format!("id=\"n{t}\"")),
                "MOBILE-2: page {t} is in the tab bar but has no drawer link n{t}; the \
                 drawer must stay the complete roster."
            );
            assert!(
                seen.insert(t),
                "MOBILE-2: page {t} appears in the tab bar twice"
            );
        }
    }

    // ── MOBILE-3: the active tab is ANNOUNCED, not just coloured, and the
    //    attribute moves with the `.ac` class. (Blind critic note on P1-W1.) ─
    #[test]
    fn the_active_tab_carries_aria_current_and_go_moves_it() {
        let f = flat();
        assert!(
            f.contains("class=\"ac\" id=\"mn0\" aria-current=page"),
            "MOBILE-3: the initially-active tab must ship aria-current=page, or the first \
             paint announces no current page in the bottom bar."
        );
        assert!(
            f.contains("b.classList.remove('ac');b.removeAttribute('aria-current')"),
            "MOBILE-3: go() must CLEAR aria-current from every tab before setting it, or \
             two tabs claim to be current."
        );
        assert!(
            f.contains("mb.classList.add('ac');mb.setAttribute('aria-current','page')"),
            "MOBILE-3: go() must set aria-current on the newly active tab in the same \
             statement that sets `.ac`, so colour and announcement cannot drift."
        );
    }

    // ── MOBILE-4: the drawer is a real modal surface — scrim element, scrim
    //    CSS, and both the open and the close path toggle it. ───────────────
    #[test]
    fn the_drawer_has_a_scrim_that_closes_it_on_an_outside_tap() {
        let f = flat();
        assert!(
            f.contains(
                "<div class=\"sb-scrim\" id=\"sbScrim\" onclick=\"closeSBMobile()\" hidden>"
            ),
            "MOBILE-4: the drawer needs a real scrim element whose click closes it. A \
             pseudo-element cannot carry a handler, and without it the only way out of \
             the drawer is to hit the 26 px hamburger again."
        );
        let rule = css_rule(".sb-scrim{");
        for need in ["position:fixed", "inset:0", "z-index:50"] {
            assert!(
                rule.contains(need),
                "MOBILE-4: the scrim rule must contain `{need}` (found `{rule}`). The \
                 z-index sits BELOW the sidebar's 100 and above `.main`'s 1, so the \
                 scrim dims and blocks the page without covering the drawer."
            );
        }
        assert!(
            rule.contains("var(--s-void)"),
            "MOBILE-4: the scrim paints the surface-floor TOKEN, not a new raw rgba \
             (rubric H5/D3). Found `{rule}`."
        );
        assert!(
            f.contains("E('sbScrim').hidden=!o") && f.contains("E('sbScrim').hidden=1"),
            "MOBILE-4: both the open path (toggleSB) and the close path (closeSBMobile) \
             must move the scrim, or it strands over an already-closed drawer."
        );
    }

    // ── MOBILE-5: focus goes INTO the drawer and comes BACK to the opener,
    //    and the close path is a no-op when the drawer is already closed. ───
    #[test]
    fn the_drawer_moves_focus_in_and_returns_it_to_the_opener() {
        let f = flat();
        assert!(
            f.contains("_sbR=document.activeElement;E('n0').focus()"),
            "MOBILE-5: opening the drawer must record the opener and move focus to the \
             first nav link, or a keyboard user's focus stays behind the scrim."
        );
        assert!(
            f.contains("if(_sbR){_sbR.focus();_sbR=0}"),
            "MOBILE-5: closing the drawer must return focus to the element that opened it \
             and clear the reference, so a later close cannot re-steal focus."
        );
        assert!(
            f.contains(
                "function closeSBMobile(){var s=E('sidebar');if(!s.classList.contains('open'))return;"
            ),
            "MOBILE-5: closeSBMobile() runs on EVERY go() - including at 1440 px, where \
             there is no drawer. It must return immediately when the drawer is not open, \
             or every desktop navigation yanks focus to _sbR."
        );
    }

    // ── MOBILE-6: Escape closes the drawer and Tab is trapped inside it —
    //    delegated onto the ONE existing keydown listener (no new listeners,
    //    no new handlers). ──────────────────────────────────────────────────
    #[test]
    fn escape_closes_the_drawer_and_tab_is_trapped_inside_it() {
        let f = flat();
        assert!(
            f.contains("if(e.key==='Escape'){closeSBMobile();return}"),
            "MOBILE-6: a modal surface with no Escape is a keyboard trap (rubric D4/H8)."
        );
        let needle = "if(e.key==='Tab'&&E('sidebar').classList.contains('open')){";
        assert!(
            f.contains(needle),
            "MOBILE-6: the Tab trap must be gated on the drawer being OPEN, so it costs \
             nothing on desktop and cannot capture Tab on a normal page."
        );
        let at = f.find(needle).expect("MOBILE-6: the Tab trap is gone");
        let stop = (at + 300).min(f.len());
        let body = &f[at..stop];
        assert!(
            body.contains("q[0]") && body.contains("q[q.length-1]") && body.contains("e.shiftKey"),
            "MOBILE-6: the trap must wrap BOTH ways - forward off the last focusable and \
             backward off the first. A forward-only trap leaves Shift+Tab escaping into \
             the inert page behind the scrim. Found: {body}"
        );
        assert!(
            body.contains("e.preventDefault()"),
            "MOBILE-6: the wrap must cancel the browser's own focus move, or focus lands \
             outside the drawer and is only pulled back one element late."
        );
        assert_eq!(
            f.matches("document.addEventListener('keydown'").count(),
            1,
            "MOBILE-6: the drawer keys ride the ONE existing keydown listener. A second \
             document listener is weight this 96-slot firmware does not need."
        );
    }

    // ── MOBILE-7: no page scrolls horizontally at 360/390 (rubric H9). The
    //    three source causes measured at baseline are all closed here. ──────
    #[test]
    fn the_topbar_clusters_can_no_longer_push_the_page_sideways() {
        let f = flat();
        assert!(
            f.contains(
                ".topbar .crumbs,.status-pills,.tb-icon+.tb-icon,.tb-icon+.tb-icon+.tb-btn{display:none}"
            ),
            "MOBILE-7: at <=768 the topbar must drop the breadcrumb (every page carries \
             its own h1 since P1-W1, and the tab bar marks the active page), the three \
             status pills (pool/IP/wifi each have their own page) and the two controls \
             that follow the notification bell - `.tb-icon+.tb-icon` is the account \
             shortcut, which IS the Settings tab now, and `+.tb-btn` after it is the \
             sidebar-collapse control, which is inert below 769 px because `.main` \
             forces margin-left:0 there. Measured: .topbar-left 374x112 at y=-32 -> \
             26x35 at y=6 on the 768 viewport, and the right cluster 354 -> 271 px, \
             which is what stops the Reboot button being clipped at 360. \
             NOTE the `.topbar ` prefix is load-bearing: \
             `.crumbs` is re-declared display:flex AFTER this media block, so a bare \
             `.crumbs` selector loses the cascade and the rule silently does nothing."
        );
        // NOTE: `.topbar-right` is declared twice (the base rule, then the
        // mobile override), so a first-match rule lookup would read the wrong
        // one. Match the override's exact declaration instead.
        assert!(
            f.contains(".topbar-right{min-width:0;overflow-x:auto}"),
            "MOBILE-7: the right cluster must be allowed to SHRINK (min-width:0 defeats \
             the flex auto minimum) and absorb its own overflow, so a narrower phone \
             scrolls inside the cluster instead of scrolling the document."
        );
        assert!(
            css_rule(".content{padding:14px 14px").contains("overflow-x:clip"),
            "MOBILE-7: `.chip-pop` (asic-chips.css, an opacity:0 hover popover) is 180 px \
             wide and centred on a ~120 px chip tile, so the rightmost tile still pushed \
             the document to 399 px at a 390 px viewport after the topbar was fixed. \
             `clip` - not `hidden` - because `hidden` would make .content a scroll \
             container and drag overflow-y:auto along with it."
        );
    }

    // ── MOBILE-8: safe area + touch targets + readable labels. ─────────────
    #[test]
    fn the_bar_respects_the_safe_area_and_the_44px_touch_target() {
        let bar = css_rule(".mobile-tabs{display:grid;");
        assert!(
            bar.contains("env(safe-area-inset-bottom)"),
            "MOBILE-8: `viewport-fit=cover` is declared, so a fixed bottom bar without \
             the safe-area inset sits under the home indicator. Found `{bar}`."
        );
        let content = css_rule(".content{padding:14px 14px");
        assert!(
            content.contains("env(safe-area-inset-bottom)"),
            "MOBILE-8: the content's bottom padding clears the BAR, so it must grow by \
             the same inset or the last card hides behind it. Found `{content}`."
        );
        let btn = css_rule(".mobile-tabs button{");
        assert!(
            btn.contains("min-height:44px"),
            "MOBILE-8: tab targets must be >= 44 px (rubric D4). Found `{btn}`."
        );
        let size = btn
            .split("font-size:")
            .nth(1)
            .and_then(|s| s.split("px").next())
            .and_then(|s| s.parse::<u32>().ok())
            .expect("MOBILE-8: the tab label font-size must be a px literal");
        assert!(
            size >= 10,
            "MOBILE-8: tab labels were 9 px; rubric D5 wants >= 11 px for anything that \
             must be read, and this bar is the primary navigation. Found {size} px."
        );
    }

    // ── MOBILE-9: the first viewport at <=480 answers "is it mining, how
    //    fast, how hot" without scrolling. ─────────────────────────────────
    #[test]
    fn the_first_mobile_viewport_leads_with_the_state_badge_and_the_stats() {
        let f = flat();
        assert!(
            f.contains("<div class=mstrip style=\"display:flex;"),
            "MOBILE-9: the meta strip that carries the rung badge (#heroMiningState) needs \
             a class so it can be ordered; it had none."
        );
        let m = f
            .find("@media(max-width:480px){")
            .expect("MOBILE-9: the <=480 block is gone");
        let end = m + f[m..].find("}}").expect("MOBILE-9: the <=480 block is unterminated") + 2;
        let block = f[m..end].to_string();
        for need in [
            // Lead fix at the P1-W4 merge: scoped to the ACTIVE page. The unscoped `#p0` rule
            // (1,0,0) outranked `.page{display:none}` (0,1,0), so below 480 px the Dashboard stayed
            // rendered above every other page (found by P1-W4, verified by its critic on the base).
            "#p0.ac{display:flex;flex-direction:column}",
            ".mstrip{order:-2}",
            ".grid4{order:-1}",
        ] {
            assert!(
                block.contains(need),
                "MOBILE-9: `{need}` is missing from the <=480 block. Measured at 390x844: \
                 the badge used to sit at y=779 and the temperature at y=1131, i.e. one \
                 and two viewports down. Ordered, they land at 91 and 268 with the \
                 hashrate sphere ending at 769 - all three inside the first 780 px. \
                 Found: {block}"
            );
        }
        assert!(
            block.contains(".stat-label{font-size:12px}"),
            "MOBILE-9: the stat labels are 10 px everywhere else; at <=480 they carry the \
             temperature and health readouts and must be 12 px. Found: {block}"
        );
        assert!(
            !block.contains(".grid4{grid-template-columns:1fr}"),
            "MOBILE-9: the <=480 override that forced the stat grid to ONE column is what \
             pushed Temperature below the fold. The <=768 rule's 2x2 grid must survive."
        );
    }

    // ── MOBILE-10: the additions are PAID FOR, and the dead rules that paid
    //    for them stay dead. ───────────────────────────────────────────────
    #[test]
    fn the_dead_body_grid_rule_and_the_orphan_bar_id_stay_deleted() {
        let f = flat();
        assert!(
            !f.contains("body{grid-template-columns:1fr}"),
            "MOBILE-10: `body` is never display:grid in this stylesheet (it is a block box \
             with a fixed .sb and a margin-left .main), so the <=768 body grid-template \
             rule never applied to anything. It is one of this lane's payers; re-adding it \
             grows the image for nothing."
        );
        assert!(
            !f.contains("id=\"mobileNav\""),
            "MOBILE-10: id=mobileNav had no reader anywhere in dashboard.rs, \
             dashboard/*.js, dcentaxe-core or the ban gates - a second payer."
        );
    }
}

/// ── BLIND-CRITIC HELD-OUT TEST for lane P1-W5 (round 1, 2026-09-03) ────────
/// The builder never saw this one. It binds the fact the ten `MOBILE-*` guards
/// leave completely unpinned: **WHERE the scrim lives in the DOM**, which is the
/// only reason its `z-index:50` means anything at all.
///
/// `.main{position:relative;z-index:1}` (`dashboard.rs:301`) is a STACKING
/// CONTEXT. Every z-index inside it — including the bottom tab bar's `z-index:120`
/// — is scoped to it, so an element inside `.main` can never paint above a
/// body-level sibling with a higher z-index. Measured on the mock at 390x844
/// with the drawer open: `elementFromPoint(300,820)` (inside the tab bar) returns
/// `sbScrim`, i.e. the z-120 bar is already under the z-50 scrim, exactly because
/// of that scoping.
///
/// So if a later edit tidies the scrim `<div>` into `.main` — a natural-looking
/// move, since that is where the rest of the page chrome lives — the element
/// still exists, still has its rule, still carries its `onclick`, and every one
/// of MOBILE-4/5/6 still passes on the source text. What breaks is only visible
/// on a device: the scrim renders BELOW the fixed sidebar's own layer, the
/// outside tap lands on page content instead, and the drawer stops being a modal
/// surface. This test refuses that move, and it pins the three z-indices as an
/// ORDER (main < scrim < sidebar) rather than as literals, so a future re-layer
/// has to stay coherent instead of merely matching a number.
#[cfg(test)]
mod critic_p1_w5_held_out {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn flat() -> String {
        DASHBOARD_RS.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// `z-index:` out of the FIRST rule body opened by `selector_open`.
    fn z_of(f: &str, selector_open: &str) -> i32 {
        let at = f
            .find(selector_open)
            .unwrap_or_else(|| panic!("HELD-OUT: CSS rule `{selector_open}` must exist"));
        let rest = &f[at + selector_open.len()..];
        let end = rest.find('}').expect("HELD-OUT: unterminated CSS rule");
        let body = &rest[..end];
        let zi = body
            .find("z-index:")
            .unwrap_or_else(|| panic!("HELD-OUT: `{selector_open}` must declare a z-index"));
        let tail = &body[zi + "z-index:".len()..];
        let stop = tail
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(tail.len());
        tail[..stop]
            .parse::<i32>()
            .expect("HELD-OUT: z-index must be an integer literal")
    }

    #[test]
    fn the_scrim_is_a_body_level_sibling_outside_the_main_stacking_context() {
        let f = flat();

        let sidebar = f
            .find("<div class=\"sb\" id=\"sidebar\">")
            .expect("HELD-OUT: the sidebar container moved");
        let scrim = f
            .find("<div class=\"sb-scrim\" id=\"sbScrim\"")
            .expect("HELD-OUT: the drawer scrim element is gone");
        let main = f
            .find("<div class=\"main\" id=\"mainArea\">")
            .expect("HELD-OUT: the main container moved");

        assert!(
            sidebar < scrim && scrim < main,
            "HELD-OUT: the scrim must be a BODY-LEVEL sibling emitted after the sidebar \
             and before `.main` (offsets sidebar={sidebar} scrim={scrim} main={main}). \
             `.main` is position:relative;z-index:1 — a stacking context — so a scrim \
             moved inside it can never paint above the fixed sidebar, and the \
             outside-tap close silently stops working while every source-text guard \
             still passes."
        );

        let z_main = z_of(&f, ".main{margin-left:var(--sidebar-w);");
        let z_scrim = z_of(&f, ".sb-scrim{");
        let z_sb = z_of(&f, ".sb{position:fixed;");
        assert!(
            z_main < z_scrim && z_scrim < z_sb,
            "HELD-OUT: the layer ORDER is the contract, not the numbers: \
             .main({z_main}) < .sb-scrim({z_scrim}) < .sb({z_sb}). Below `.main` the \
             scrim dims nothing; at or above `.sb` it covers the drawer it is supposed \
             to sit behind, so the nav links stop being tappable."
        );
    }
}

/// ============================================================================
/// P1-O1 (DCENT_axe UI Gauntlet) — the fail-closed screen says something an
/// operator can act on, and every row of it fits the glass.
///
/// The defect: `main.rs` built a 30–80 character SENTENCE for
/// `mining_block_reason` at 29 sites and handed it to
/// [`crate::display_convert::FrameBuffer::draw_text`], which clips at column 21
/// **from the right, silently, with no ellipsis**. `oled_panel_budget_guards`
/// (lane P1-I2) measured the damage: 29 of 29 clipped, the longest losing 50 of
/// its 71 characters and reading `Board has no rail act`. The screen also spent
/// a row on the firmware version and offered no next step at all.
///
/// The fix is the shape that ratchet's own doc comment named — a short code
/// plus a pointer — implemented in [`crate::block_reason`], whose behaviour is
/// unit-tested where it lives. What cannot be tested there is that `main.rs`
/// (espidf-only, never host-compiled) actually USES it: that every site names a
/// code, that the screen is composed by the bounded helpers, that the sentence
/// still reaches the log, and that the interpolated detail each sentence used
/// to carry is still logged too. That join is what this module pins — the same
/// join five callerless drivers in this project
/// (`RailBringup`, `tps5364x_convert`, `fxl6408_convert`, `tmp451_convert`,
/// `display_convert`) taught us to pin.
#[cfg(test)]
mod p1_o1_fail_closed_reason_guards {
    use crate::block_reason::{
        blocked_screen, code_row, ip_row, BlockReason, CODE_COLUMNS, MARKER,
    };
    use crate::display_convert::{
        centered_is_clipped, line_fits, rung_status_line, MiningRung, TEXT_COLUMNS,
    };

    const MAIN_SRC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));
    const BLOCK_REASON_SRC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe-hal/src/block_reason.rs"
    ));

    /// `core.autocrlf = true` gives fresh Windows worktrees CRLF working copies
    /// while git stores LF; two guards in this crate have been false-green that
    /// way. Every source read here is normalised first.
    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// The `BlockReason::` variant named by every `mining_block_reason = Some(`
    /// assignment, in source order.
    fn assigned_variants(src: &str) -> Vec<String> {
        const NEEDLE: &str = "mining_block_reason = Some(BlockReason::";
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(NEEDLE) {
            let start = at + rel + NEEDLE.len();
            let end = src[start..]
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|n| start + n)
                .unwrap_or(src.len());
            out.push(src[start..end].to_string());
            at = end;
        }
        out
    }

    /// Every refusal site names a code. None of them builds a sentence.
    ///
    /// The count is exact, not a floor: a 30th site that forgot the code would
    /// otherwise pass while the panel showed an operator nothing at all.
    #[test]
    fn every_fail_closed_site_names_a_block_reason_code() {
        let src = lf(MAIN_SRC);
        let assignments = src.matches("mining_block_reason = Some(").count();
        let coded = assigned_variants(&src);
        assert_eq!(
            assignments,
            coded.len(),
            "{} of {assignments} `mining_block_reason = Some(...)` sites do not \
             name a BlockReason. A site that assigns anything else is assigning \
             a string, and draw_text clips a string at column 21 mid-word.",
            assignments - coded.len()
        );
        assert_eq!(
            coded.len(),
            29,
            "the fail-closed refusal set changed size (was 29). That is allowed \
             — but the new site must name a BlockReason and this number must \
             move with it, or the guard stops describing the tree it pins."
        );
        let known: Vec<String> = BlockReason::ALL
            .iter()
            .map(|r| format!("{r:?}"))
            .collect();
        for name in &coded {
            assert!(
                known.contains(name),
                "main.rs names BlockReason::{name}, which is not in \
                 BlockReason::ALL — ALL is what every budget test iterates, so \
                 an unlisted variant is an unmeasured panel row"
            );
        }
    }

    /// No code is dead, and the fallback is the only one no site selects.
    ///
    /// A code nothing can produce is a code nobody tested against a real
    /// refusal; a refusal with no code is a blank row.
    #[test]
    fn every_code_is_reachable_and_the_fallback_is_the_only_exception() {
        let src = lf(MAIN_SRC);
        let coded = assigned_variants(&src);
        for reason in BlockReason::ALL {
            let name = format!("{reason:?}");
            let used = coded.iter().any(|n| *n == name);
            if reason == BlockReason::SafetyGate {
                assert!(
                    !used,
                    "SafetyGate is the unwrap_or fallback for a refusal that \
                     named no reason; a site selecting it directly should name \
                     its own code instead"
                );
                assert!(
                    src.contains("mining_block_reason.unwrap_or(BlockReason::SafetyGate)"),
                    "the fallback code is no longer wired; a refusal with no \
                     reason would render an empty panel row"
                );
            } else {
                assert!(
                    used,
                    "BlockReason::{name} is never assigned in main.rs — a code \
                     no refusal produces has never been seen on a panel"
                );
            }
        }
    }

    /// The screen is composed by the bounded helpers, and it still names the
    /// rung the dashboard names.
    #[test]
    fn the_fail_closed_screen_is_composed_by_the_bounded_helpers() {
        let src = lf(MAIN_SRC);
        for needle in [
            "let blocked = blocked_screen(",
            "&rung_status_line(MiningRung::Standby.panel_word(), \"disabled\"),",
            "            wdt_count,",
            "            &device_ip,",
            "display.show_status(&mut i2c, &blocked[0], &blocked[1], &blocked[2], &blocked[3]);",
        ] {
            assert!(
                src.contains(needle),
                "the fail-closed screen no longer composes through \
                 blocked_screen: missing {needle:?}. Composed inline it is \
                 unmeasurable — main.rs is espidf-only."
            );
        }
        // The raw reason must never go back on the glass. The needle is the
        // exact pre-lane shape — rung row, then the sentence — rather than a
        // bare `&reason`, which also matches an unrelated SV2 reject handler.
        assert!(
            !src.contains(
                "&rung_status_line(MiningRung::Standby.panel_word(), \"disabled\"),\n            &reason,"
            ),
            "a raw reason value is being handed to show_status again; that is \
             exactly the string draw_text clipped at column 21"
        );
    }

    /// The sentence is not lost — it moved to the log, beside the code.
    #[test]
    fn the_full_sentence_and_the_code_both_reach_the_log() {
        let src = lf(MAIN_SRC);
        for needle in [
            "\"Mining disabled before ASIC init: {} [{}] -> {}\",",
            "reason.summary(),",
            "code_line(reason, wdt_count),",
            "reason.action()",
        ] {
            assert!(
                src.contains(needle),
                "the fail-closed log line no longer carries {needle:?}. The \
                 panel deliberately shows only a code; if the log stops \
                 carrying the sentence, the sentence is gone."
            );
        }
    }

    /// The interpolated detail that used to ride inside the reason string is
    /// still logged at every site that would otherwise have lost it.
    ///
    /// Eight sites passed a driver error (or an address, or a regulator
    /// identity) into the sentence and had no other log carrying it —
    /// `fail_closed_power_off` logs its own literal reason, never the `e`. Each
    /// one keeps its exact former text as an `error!`.
    #[test]
    fn the_detail_the_sentence_used_to_carry_is_still_logged() {
        let src = lf(MAIN_SRC);
        for needle in [
            "error!(\"Expander power-sequence setup failed: {}\", e);",
            "error!(\"Rail expander not found at 0x{:02X}: {}\", addr, e);",
            "error!(\"Expander ASIC LDO enable failed: {}\", e);",
            "error!(\"ASIC LDO enable failed: {}\", e);",
            "error!(\"Buck enable failed: {}\", e);",
            "error!(\"Deferred buck enable failed: {}\", e);",
            "error!(\"Deferred expander enable failed: {}\", e);",
            "\"Board has no enable GPIO and its regulator ({:?}) cannot cut the rail over I2C\",",
            "error!(\"Power input not detected by plug-sense gate — mining disabled\");",
        ] {
            assert!(
                src.contains(needle),
                "a fail-closed site stopped logging its own detail: {needle:?}. \
                 The panel now shows a CODE, so the log is the only place the \
                 underlying driver error survives."
            );
        }
    }

    /// The two other boot screens' address rows are bounded too.
    #[test]
    fn the_boot_screens_address_row_is_bounded() {
        let src = lf(MAIN_SRC);
        for anchor in [
            "&rung_status_line(MiningRung::Ready.panel_word(), &format!(\"{} chips OK\", n)),\n                    &ip_row(&device_ip),",
            "&rung_status_line(MiningRung::Standby.panel_word(), \"ASIC FAILED\"),\n                    &ip_row(&device_ip),",
        ] {
            assert!(
                src.contains(anchor),
                "a boot screen's address row went back to a raw format!; a \
                 clipped address is worse than none, because a truncated IPv4 \
                 address still looks like an address"
            );
        }
    }

    /// The panel's REAL geometry, not just a character count.
    ///
    /// `show_status` CENTRES every row (`draw_status` -> `draw_centered`), and
    /// `draw_centered` measures width in UTF-8 BYTES while `draw_text` clips on
    /// pixels. `line_fits` counts characters and would miss a row that centres
    /// badly, so this walks the actual centred layout for every reason, every
    /// watchdog count and a spread of addresses.
    #[test]
    fn no_fail_closed_row_is_clipped_by_the_centred_layout_show_status_uses() {
        let rung = rung_status_line(MiningRung::Standby.panel_word(), "disabled");
        for reason in BlockReason::ALL {
            for count in [0u8, 1, 3, 9, 10, 99, 100, 254, 255] {
                for ip in ["", "203.0.113.1", "203.0.113.42", "255.255.255.255"] {
                    let rows = blocked_screen(&rung, reason, count, ip);
                    for (i, row) in rows.iter().enumerate() {
                        assert!(
                            !centered_is_clipped(row),
                            "{reason:?} count {count} ip {ip:?}: row {i} {row:?} \
                             is clipped by the centred layout show_status uses"
                        );
                        assert!(line_fits(row), "{reason:?}: row {i} {row:?} overflows");
                    }
                }
            }
        }
    }

    /// The error marker survives on every code row, at every count.
    ///
    /// `CRITIC_RUBRIC.md` §4.2 asks that an error screen be distinguishable
    /// from a status screen at arm's length. `!!` is what the runtime urgent
    /// notifications already use, so the marker costs three columns — and
    /// [`CODE_COLUMNS`] is exactly what is left. A code one character wider
    /// would silently push the marker off, which is the same class of defect
    /// one row down.
    #[test]
    fn the_error_marker_is_never_the_thing_that_gets_dropped() {
        for reason in BlockReason::ALL {
            assert!(
                reason.code().chars().count() <= CODE_COLUMNS,
                "{reason:?} code is wider than the marker leaves room for"
            );
            for count in [0u8, 3, 255] {
                let row = code_row(reason, count);
                assert!(
                    row.starts_with(MARKER),
                    "{reason:?} count {count}: {row:?} lost the error marker"
                );
                assert!(
                    row.contains(reason.code()),
                    "{reason:?} count {count}: {row:?} lost the code itself"
                );
                assert!(row.chars().count() <= TEXT_COLUMNS);
            }
        }
        assert!(line_fits(&ip_row("255.255.255.255")));
    }

    /// The reason module owns TEXT and nothing else.
    ///
    /// This lane's class is `ui-only` strings inside safety code paths. The
    /// honest way to keep that true over time is to make it impossible for a
    /// gate to migrate here: a module that mentions no permission flag, no
    /// power-off path and no bus cannot be deciding anything.
    #[test]
    fn the_reason_module_holds_no_gate_no_actuator_and_no_bus() {
        let src = lf(BLOCK_REASON_SRC);
        // Ignore the module's own prose, which necessarily discusses them.
        let code_only: String = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
            })
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "mining_permitted",
            "fail_closed_power_off",
            "I2cBus",
            "i2c",
            "gpio",
            "unsafe",
            "power_mgr",
        ] {
            assert!(
                !code_only.contains(forbidden),
                "block_reason.rs mentions {forbidden:?} in code. It is a text \
                 table: the moment it can touch a gate, an actuator or a bus, \
                 `ui-only` stops being true of this lane."
            );
        }
    }
}


/// ============================================================================
/// CRITIC HELD-OUT (lane P1-O1, round 1) — a reason row must belong to the
/// variant that indexes it.
///
/// `BlockReason::row()` is `&REASONS[self as usize]`: the discriminant is a
/// bare index into a hand-ordered array. The lane's own guards check that
/// `REASONS.len() == COUNT`, that `ALL` is in discriminant order, that no two
/// codes collide, and that every code and action fits the panel — but NOTHING
/// binds a variant to the row it lands on. Insert a `ReasonRow` one position
/// early, or transpose two rows, and every existing test stays green while the
/// panel prints another fault's code and, worse, another fault's ACTION.
///
/// That is not a cosmetic slip on this screen. The actions name *different
/// physical interventions*: `Check fans; reboot` sends the operator to the
/// fans, `Check power input` to the PSU, `Clear in dashboard` to a REST call,
/// `Fix in dashboard` to their own config. A transposed row is a panel that
/// confidently sends someone to the wrong place — which is exactly the failure
/// this lane exists to end, one step further down the same road.
///
/// Two halves, neither of which restates the table:
///  * the code's SUBSYSTEM prefix is derived from the variant's own name, so a
///    cross-family shift fails;
///  * the four actions that mean four different interventions are each bound to
///    exactly one variant, so a WITHIN-family transposition fails too.
///
/// Plus one semantic assertion the lane does not make: the two structural
/// refusals may never say "Power-cycle to retry". A board with no rail actuator
/// does not grow one over a power cycle, and an action that cannot work is a
/// promise, which `block_reason.rs`'s own doc forbids.
#[cfg(test)]
mod critic_p1_o1_reason_rows_belong_to_their_variants {
    use crate::block_reason::{
        BlockReason, CHECK_FANS, CHECK_POWER_INPUT, CLEAR_IN_DASHBOARD, FIX_IN_DASHBOARD,
        RETRY_POWER_CYCLE,
    };

    /// The subsystem prefix a variant's code must carry, derived from the
    /// variant's OWN name rather than from a second copy of the table.
    fn expected_prefix(name: &str) -> &'static str {
        if name.starts_with("Fan") {
            "FAN:"
        } else if name.starts_with("Rail") {
            "RAIL:"
        } else if name.starts_with("Thermal") {
            "THERMAL:"
        } else if name.starts_with("Power") || name == "NoPlugSense" {
            "POWER:"
        } else if name == "ConfigUnsafe" {
            "CONFIG:"
        } else if name == "SafeModeWdt" {
            "SAFE-MODE"
        } else if name == "SafetyGate" {
            "SAFETY:"
        } else {
            panic!(
                "BlockReason::{name} is new and this held-out test does not know \
                 which subsystem its code must name. Add it here in the same \
                 change — an unclassified variant is one whose row nothing binds."
            )
        }
    }

    #[test]
    fn every_code_names_the_subsystem_its_variant_names() {
        for reason in BlockReason::ALL {
            let name = format!("{reason:?}");
            let want = expected_prefix(&name);
            assert!(
                reason.code().starts_with(want),
                "BlockReason::{name} resolves to code {:?}, which does not start \
                 with {want:?}. `row()` indexes REASONS by the discriminant, so \
                 this is a row inserted or transposed in the table: the panel is \
                 showing one fault under another fault's name.",
                reason.code()
            );
        }
    }

    #[test]
    fn each_distinct_physical_intervention_belongs_to_exactly_one_variant() {
        // action -> the single variant that may carry it, and why it is that
        // variant's alone.
        let bound: [(&str, BlockReason, &str); 4] = [
            (
                CHECK_FANS,
                BlockReason::FanNoTach,
                "only a missing tach sends the operator to the fans themselves",
            ),
            (
                CHECK_POWER_INPUT,
                BlockReason::NoPlugSense,
                "only the plug-sense gate is about input power",
            ),
            (
                CLEAR_IN_DASHBOARD,
                BlockReason::SafeModeWdt,
                "only safe mode has a clear-and-reboot control to press",
            ),
            (
                FIX_IN_DASHBOARD,
                BlockReason::ConfigUnsafe,
                "only a refused configuration is the operator's own to change",
            ),
        ];
        for (action, owner, why) in bound {
            assert_eq!(
                owner.action(),
                action,
                "BlockReason::{owner:?} no longer carries {action:?} — {why}"
            );
            let carriers: Vec<String> = BlockReason::ALL
                .iter()
                .filter(|r| r.action() == action)
                .map(|r| format!("{r:?}"))
                .collect();
            assert_eq!(
                carriers,
                vec![format!("{owner:?}")],
                "{action:?} is carried by {carriers:?}. It names ONE physical \
                 intervention, so a second variant pointing at it sends that \
                 operator somewhere the fault is not."
            );
        }
    }

    #[test]
    fn a_structural_refusal_never_tells_the_operator_to_power_cycle() {
        for reason in [BlockReason::RailNoActuator, BlockReason::RailNoI2cCut] {
            assert_ne!(
                reason.action(),
                RETRY_POWER_CYCLE,
                "{reason:?} is a property of the BOARD, not a transient failure: \
                 no power cycle adds an enable GPIO or makes a regulator \
                 I2C-cuttable. Telling the operator to retry is the promise \
                 block_reason.rs's own doc says an action must never make."
            );
        }
    }
}

/// ============================================================================
/// P1-O4 (DCENT_axe UI Gauntlet 2026-09-03) — the panel is not free, and two of
/// its pages were never on it.
///
/// Two facts this module pins, both measured before it was written:
///
/// 1. **Two carousel arms were unreachable.** `main.rs` selects a page with
///    `logical_page = carousel[display_page % carousel.len()]`, and the two
///    `carousel` arrays between them contain only `0,1,2,4,5,6,7`. The page-3
///    (halving / difficulty-epoch countdown) arm and the `_` screensaver arm
///    (bouncing Bitcoin + mood/thermal sparklines) were therefore compiled into
///    every SSD1306 image and drawn on no panel, ever. Both bodies are deleted;
///    the `_` arm survives as `_ => {}` only because `match` on a `u8` must be
///    exhaustive.
///
/// 2. **The 21 `display-none` targets paid for the panel.** Every
///    `display.notify(...)` and the whole carousel ran against the no-op
///    headless stub in `dcentaxe-hal::display`, but the compiler still built
///    every `format!` and every literal behind them. Measured on `nerdaxe`
///    after P1-O2: **+624 B of `.text` for that one lane alone**. The
///    notification sites now go through `oled_notify!`, whose `display-none`
///    arm expands to `()`, and the carousel statements carry
///    `#[cfg(feature = "display-ssd1306")]`.
///
/// The load-bearing half of (2) is what did NOT move behind the gate: a
/// headless board must still unlock achievements, set the `nvs_save_*` dirty
/// flags, advance `lifetime_shares` and publish the same telemetry as a
/// panelled one, and NO safety, fail-closed or boot/init code may end up inside
/// a display gate. `main.rs` is `target_os = "espidf"`-only and can never be
/// host-compiled, so — like every other `main.rs` contract in this crate — that
/// is proved against the source TEXT.
#[cfg(test)]
mod p1_o4_headless_carousel_guards {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    const GATE: &str = "#[cfg(feature = \"display-ssd1306\")]";

    /// `core.autocrlf = true` gives fresh Windows worktrees CRLF working copies
    /// while git stores LF. Every read here is normalised first.
    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    fn indent_of(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    /// Byte ranges of every statement/item introduced by a
    /// `#[cfg(feature = "display-ssd1306")]` attribute.
    ///
    /// `main.rs` is uniformly indented, so the extent of a gated statement is
    /// found by indentation: it runs from the line after the attribute until
    /// the first line that is neither blank, nor more deeply indented, nor a
    /// continuation token (`}` / `]` / `)` / `{` / `else`) at the attribute's
    /// own indent. `the_gate_scanner_finds_the_blocks_it_claims_to_find`
    /// asserts the scanner really brackets the carousel, so a parser drift
    /// fails loudly instead of making every "is not gated" check vacuous.
    fn display_gated_spans(src: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut offsets = Vec::new();
        let mut at = 0usize;
        for line in src.split_inclusive('\n') {
            offsets.push((at, line));
            at += line.len();
        }
        for (i, (_, line)) in offsets.iter().enumerate() {
            if line.trim() != GATE {
                continue;
            }
            let n = indent_of(line);
            let mut j = i + 1;
            if j >= offsets.len() {
                break;
            }
            let start = offsets[j].0;
            let mut end = offsets[j].0 + offsets[j].1.len();
            j += 1;
            while j < offsets.len() {
                let (off, l) = offsets[j];
                let t = l.trim_start();
                let cont = t.is_empty()
                    || indent_of(l) > n
                    || (indent_of(l) == n
                        && (t.starts_with('}')
                            || t.starts_with(']')
                            || t.starts_with(')')
                            || t.starts_with('{')
                            || t.starts_with("else")));
                if !cont {
                    break;
                }
                end = off + l.len();
                j += 1;
            }
            spans.push((start, end));
        }
        spans
    }

    fn is_gated(spans: &[(usize, usize)], at: usize) -> bool {
        spans.iter().any(|&(s, e)| at >= s && at < e)
    }

    fn offsets_of(src: &str, needle: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(needle) {
            out.push(at + rel);
            at += rel + needle.len();
        }
        out
    }

    /// The scanner is only worth what it can be shown to bracket.
    #[test]
    fn the_gate_scanner_finds_the_blocks_it_claims_to_find() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);
        assert!(
            spans.len() >= 30,
            "the display gate all but vanished from main.rs ({} spans); the \
             headless boards are paying for the panel again",
            spans.len()
        );

        // The carousel `match` is one span, and it really does run from the
        // first page to the last.
        let carousel_spans: Vec<&(usize, usize)> = spans
            .iter()
            .filter(|&&(s, e)| src[s..e].contains("-- HALL OF FAME --"))
            .collect();
        assert_eq!(
            carousel_spans.len(),
            1,
            "exactly one gated span may contain the carousel's hall-of-fame page"
        );
        let (cs, ce) = *carousel_spans[0];
        for marker in [
            "match logical_page {",
            "let rung = resolve_rung(true, runtime_mining_active, hr > 0.0);",
            "let pet_rung = resolve_rung(true, runtime_mining_active, hr > 0.0);",
            "_ => {}",
        ] {
            assert!(
                src[cs..ce].contains(marker),
                "the carousel span stops short: it does not contain {marker:?}"
            );
        }

        // The emitter macro is gated in both directions.
        assert!(
            src.contains(&format!("{GATE}\nmacro_rules! oled_notify {{")),
            "the SSD1306 arm of oled_notify! must be the gated one"
        );
        assert!(
            src.contains("#[cfg(feature = \"display-none\")]\nmacro_rules! oled_notify {"),
            "the headless arm of oled_notify! must exist, or a display-none \
             build stops compiling"
        );
    }

    /// The page ids a tick can select, and the arms that exist to draw them,
    /// are the same set.
    ///
    /// This is the regression that lane P1-O4 exists for: page 3 sat in the
    /// `match` for months with no array entry pointing at it, so it cost image
    /// bytes on every board and rendered on none.
    #[test]
    fn every_carousel_arm_is_a_page_the_arrays_can_select() {
        let src = lf(MAIN_RS);
        const DECL: &str = "let carousel: &[u8] = if autotuner_enabled {";
        // Start AFTER the declaration: its own `&[u8]` type annotation would
        // otherwise be parsed as a third (empty) page table.
        let anchor = src.find(DECL).expect("the carousel arrays must stay locatable") + DECL.len();
        let arrays_end = src[anchor..]
            .find("let page_count")
            .expect("page_count follows the arrays")
            + anchor;
        let mut selectable: Vec<u8> = Vec::new();
        for lit in src[anchor..arrays_end].split("&[").skip(1) {
            let body = &lit[..lit.find(']').expect("unterminated carousel array")];
            for tok in body.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                selectable.push(tok.parse::<u8>().unwrap_or_else(|_| {
                    panic!("carousel array holds a non-literal page id: {tok:?}")
                }));
            }
        }
        assert!(
            selectable.len() >= 24,
            "both carousel arrays must still be literal page-id tables: {selectable:?}"
        );
        selectable.sort_unstable();
        selectable.dedup();

        let match_at = src
            .find("match logical_page {")
            .expect("the carousel match must stay locatable");
        let mut armed: Vec<u8> = Vec::new();
        let mut wildcard = false;
        for line in src[match_at..].lines().skip(1) {
            if line.starts_with("        }") {
                break;
            }
            let t = line.trim_start();
            if indent_of(line) != 12 || !t.contains("=> ") && !t.contains("=> {") {
                continue;
            }
            let head = t.split("=>").next().unwrap_or("").trim();
            if head == "_" {
                wildcard = true;
                continue;
            }
            let id = head.split_whitespace().next().unwrap_or("");
            if let Ok(n) = id.parse::<u8>() {
                armed.push(n);
            }
        }
        armed.sort_unstable();
        armed.dedup();
        assert!(wildcard, "the `_` arm is what keeps the match exhaustive");
        assert_eq!(
            armed, selectable,
            "the carousel arms and the page ids the arrays can select have \
             diverged. An arm with no array entry is a page that costs image \
             bytes and is never drawn (that was page 3, the halving \
             countdown); an array entry with no arm falls through to `_ => {{}}` \
             and blanks that slot of the rotation."
        );

        // The wildcard carries no body: it is unreachable by construction.
        assert!(
            src[match_at..].contains("            _ => {}\n"),
            "the `_` arm must stay an empty, unreachable placeholder — it is \
             the only reason the match compiles at all"
        );
    }

    /// The two deleted bodies must not come back by copy-paste.
    #[test]
    fn the_two_unreachable_carousel_arms_are_gone() {
        let src = lf(MAIN_RS);
        for dead in [
            "\"HALVING #{} in {}d\"",
            "\"EPOCH #{} ~{}d left\"",
            "screensaver_x",
            "screensaver_dy",
            "\"MOOD:{} {}/10\"",
            "\"ECSTATIC\"",
        ] {
            assert!(
                !src.contains(dead),
                "{dead} is back in main.rs. It belonged to a carousel arm no \
                 tick could select. If the halving page is wanted, it needs an \
                 entry in a `carousel` array (and P1-O5 owns making its numbers \
                 honest), not an arm nothing points at."
            );
        }
        // The dead arms were the ONLY consumers of these two snapshot reads.
        for gone in ["s.temp_sparkline()", "s.mood_sparkline()"] {
            assert!(
                !src.contains(gone),
                "{gone} is read again in main.rs, but the only page that ever \
                 drew it (the screensaver arm) is deleted"
            );
        }
        // The samples themselves are still PUSHED: `mood_now` feeds
        // `telem.creature_mood` on every board, and the rings stay warm for a
        // future consumer.
        for kept in [
            "s.push_temp_sample(max_temp);",
            "s.push_mood_sample(mood);",
            "telem.creature_mood = mood_now;",
        ] {
            assert!(
                src.contains(kept),
                "{kept} was collateral damage of the dead-arm deletion; the \
                 sampling and the telemetry it feeds are not display code"
            );
        }
    }

    /// Every gamification notification goes through the emitter macro, so the
    /// `format!` arguments behind it are not compiled on a headless board.
    #[test]
    fn the_notification_emitter_is_the_only_notify_call_site() {
        let src = lf(MAIN_RS);
        assert_eq!(
            src.matches("$display.notify(").count(),
            1,
            "the macro body is the one place `notify(` may be named"
        );
        assert_eq!(
            src.matches("display.notify(").count(),
            1,
            "a raw `display.notify(...)` call is back in main.rs: its argument \
             list — every `format!` and every literal — would be compiled into \
             all 21 display-none images to feed a no-op stub"
        );
        let sites = src.matches("oled_notify!(display,").count();
        assert!(
            sites >= 60,
            "only {sites} notification sites route through oled_notify!; the \
             lane moved 71"
        );

        // The urgent SAFETY notifications are deliberately NOT routed through
        // the macro: they sit inside the power / thermal / fan handlers, which
        // are out of this lane's footprint. If that ever changes it must be a
        // reviewed decision, not a silent one.
        assert!(
            src.contains("display.notify_urgent("),
            "the urgent safety notifications must still be direct calls"
        );
    }

    /// A `display-none` board unlocks, persists and reports exactly what a
    /// panelled board does.
    ///
    /// This is the whole safety argument for the cfg gate. Every site below is
    /// asserted to sit OUTSIDE every gated span, so no amount of future
    /// gate-widening can quietly make headless boards stop saving an
    /// achievement or advancing a lifetime counter.
    #[test]
    fn a_headless_board_keeps_every_achievement_and_persistence_side_effect() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);

        let mut checked = 0usize;
        for needle in [
            "achievements |= nvs_config::ACH_",
            "nvs_save_achievements = true;",
            "nvs_save_best_diff = true;",
            "nvs_save_streak = true;",
            "nvs_save_lifetime = true;",
            "nvs_save_cached_diff = true;",
            "achievement_flash_tick = 1;",
            "share_flash_tick = 4;",
            "lifetime_shares = lifetime_shares.saturating_add(new_shares);",
            "nvs_config::save_best_nonce(",
            "nvs_config::save_achievements(",
            "nvs_config::save_lifetime_shares(",
            "telem.achievements = achievements;",
            "telem.lifetime_shares = lifetime_shares;",
            "telem.creature_stage = stage_name.to_string();",
            "best_nonce_diff = best_diff;",
            "daily_summary_shown = true;",
            "prev_accepted = accepted;",
            "prev_streak = streak;",
            "prev_block_height = block_height;",
            "chill_miner_secs += 5;",
            "low_power_secs += 5;",
        ] {
            let hits = offsets_of(&src, needle);
            assert!(
                !hits.is_empty(),
                "the state site {needle:?} vanished from main.rs — a headless \
                 board can no longer be compared against a panelled one"
            );
            for at in hits {
                assert!(
                    !is_gated(&spans, at),
                    "{needle:?} at byte {at} is inside a \
                     `display-ssd1306` block. That is achievement / persistence \
                     / telemetry state, not pixels: gating it means a Nerd, \
                     Hammer, BitForge or Naja board silently stops unlocking, \
                     saving or reporting it."
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 80,
            "only {checked} state sites were checked; the achievement table \
             cannot have shrunk that far"
        );
        assert_eq!(
            src.matches("achievements |= nvs_config::ACH_").count(),
            24,
            "the achievement unlock set changed size (was 24). That is allowed \
             — but the new one must be outside the display gate and this number \
             must move with it."
        );
    }

    /// No safety, fail-closed or boot/init code may sit inside a display gate.
    ///
    /// H12 in the campaign rubric, asserted structurally: this lane is
    /// `ui-only`, and a `#[cfg]` that swallowed a rail cut, a fan write or the
    /// refusal screen would be a firmware-behaviour change hiding in a UI lane
    /// — and it would only ever be observable on the boards nobody has on a
    /// bench.
    #[test]
    fn no_safety_or_fail_closed_code_is_inside_a_display_gate() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);
        for needle in [
            "fail_closed_power_off(",
            "install_fail_closed_panic_hook(",
            "mining_block_reason = Some(",
            "blocked_screen(",
            // The DRAW call, not just the composition: gating this one line
            // survived the first pass of this guard (found by mutation, lane
            // P1-O4). `show_status` is a no-op on a headless board either way,
            // but P1-O1's refusal screen is pinned to stay exactly as merged
            // and a `#[cfg]` around it is not a display-only edit — it is the
            // shape a real regression would take.
            "display.show_status(&mut i2c, &blocked[0]",
            "&rung_status_line(",
            "display.notify_urgent(",
            "power_mgr.disable(",
            "enable_buck(",
            "set_fan_speed",
            "mining_permitted",
            "runtime_mining_active =",
            "consecutive_fan_stall",
            "ina_oc_strikes",
        ] {
            for at in offsets_of(&src, needle) {
                assert!(
                    !is_gated(&spans, at),
                    "{needle:?} at byte {at} is inside a `display-ssd1306` \
                     block. Safety, fail-closed and boot/init code runs on \
                     every board; only pixels may be gated."
                );
            }
        }
    }

    /// Lead fix at merge (blind critic P1-O4 must-fix 1): the strobe machine is pure
    /// display, so EVERY `pending_flash` occurrence — declaration, consumer, both
    /// producers — must sit inside a `display-ssd1306` span. Round 1 had one producer
    /// inside a gate and the rest outside (the lane's own doc said the opposite) and
    /// the hand-maintained needle list did not notice.
    #[test]
    fn the_pending_flash_strobe_machine_is_entirely_display_gated() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);
        let sites: Vec<usize> = offsets_of(&src, "pending_flash")
            .into_iter()
            .filter(|&at| {
                let line_start = src[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
                !src[line_start..at].trim_start().starts_with("//")
            })
            .collect();
        assert!(sites.len() >= 4, "expected the declaration, consumer and producers, found {}", sites.len());
        for at in sites {
            assert!(
                is_gated(&spans, at),
                "`pending_flash` at byte {at} is outside every display gate: {:?}",
                &src[at..(at + 60).min(src.len())]
            );
        }
    }

}

/// ============================================================================
/// HELD-OUT (critic, lane P1-O4 round 1, 2026-09-03) — an `oled_notify!`
/// argument is EVALUATED on a panelled board and DROPPED UNEVALUATED on a
/// headless one.
///
/// The lane's emitter has two arms:
///
/// ```ignore
/// #[cfg(feature = "display-ssd1306")]
/// macro_rules! oled_notify { ($display:expr, $($arg:expr),+ $()?) => { $display.notify($($arg),+) }; }
/// #[cfg(feature = "display-none")]
/// macro_rules! oled_notify { ($display:expr, $($arg:expr),+ $()?) => { () }; }
/// ```
///
/// The headless arm expands to `()` and never names `$arg`, so a Rust macro
/// never expands it: every expression in the argument list simply does not
/// exist in a `display-none` image. That is the whole point — it is how 71
/// `format!` argument lists stop being compiled onto the 21 headless targets —
/// and it is also the one hazard the design creates. An argument that DOES
/// something (`counter += 1`, `queue.pop()`, `slot.take()`, `.lock()`) would
/// run on a panelled board and silently stop running on every headless one, and
/// nothing would fail: both images compile, both pass the host gate, and the
/// only symptom is a Nerd / Hammer / BitForge / Naja board whose counter never
/// moves.
///
/// The lane's own `a_headless_board_keeps_every_achievement_and_persistence_side_effect`
/// checks a NAMED list of state sites against the gate spans. This test is the
/// complementary shape: it is a CLOSED check over the argument lists
/// themselves, so a *new* side-effecting argument is refused without anyone
/// having to remember to add it to a list.
///
/// Written by the round-1 critic against the merged lane state; the builder
/// never saw it. It passes on the lane as submitted (71 sites, 0 violations).
#[cfg(test)]
mod critic_p1_o4_notify_arguments_are_pure {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    /// Tokens that make an argument DO something rather than describe something.
    /// Note `+=`/`-=`/… and a bare `=` that is not part of a comparison.
    const MUTATING: &[&str] = &[
        ".take()",
        ".pop()",
        ".remove(",
        ".insert(",
        ".push(",
        ".push_str(",
        ".clear()",
        ".drain(",
        ".lock()",
        "+=",
        "-=",
        "*=",
        "/=",
        "|=",
        "&=",
        "^=",
    ];

    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// Balanced-paren extent of the invocation starting at `open` (index of the
    /// `(`), skipping over string and char literals so a `"("` inside a
    /// `format!` template cannot unbalance the scan.
    fn call_body(src: &str, open: usize) -> &str {
        let b = src.as_bytes();
        let mut depth = 0usize;
        let mut i = open;
        let mut in_str = false;
        let mut in_chr = false;
        while i < b.len() {
            let c = b[i];
            if in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    in_str = false;
                }
            } else if in_chr {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'\'' {
                    in_chr = false;
                }
            } else {
                match c {
                    b'"' => in_str = true,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return &src[open + 1..i];
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        panic!("unterminated oled_notify! invocation at byte {open}");
    }

    /// Blank every string literal and every line comment, so the scan sees only
    /// code. `format!("A += B")` must not read as an assignment.
    fn code_only(body: &str) -> String {
        let b = body.as_bytes();
        let mut out = String::with_capacity(body.len());
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'"' => {
                    out.push('"');
                    i += 1;
                    while i < b.len() {
                        if b[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if b[i] == b'"' {
                            break;
                        }
                        i += 1;
                    }
                    out.push('"');
                    i += 1;
                }
                b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                c => {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
        out
    }

    fn is_bare_assignment(code: &str) -> Option<usize> {
        let b = code.as_bytes();
        for i in 0..b.len() {
            if b[i] != b'=' {
                continue;
            }
            let prev = if i == 0 { b' ' } else { b[i - 1] };
            let next = if i + 1 < b.len() { b[i + 1] } else { b' ' };
            if next == b'=' || prev == b'=' {
                continue; // ==
            }
            if matches!(prev, b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'|' | b'&' | b'^') {
                continue; // != <= >= += … (compound ops handled by MUTATING)
            }
            return Some(i);
        }
        None
    }

    #[test]
    fn every_oled_notify_argument_is_free_of_side_effects() {
        let src = lf(MAIN_RS);
        let needle = "oled_notify!(";
        let mut at = 0usize;
        let mut sites = 0usize;
        let mut offenders: Vec<String> = Vec::new();

        while let Some(rel) = src[at..].find(needle) {
            let start = at + rel;
            // Skip the two `macro_rules! oled_notify {` definitions.
            if src[..start].trim_end().ends_with("macro_rules!") {
                at = start + needle.len();
                continue;
            }
            let open = start + needle.len() - 1;
            let body = call_body(&src, open);
            sites += 1;
            let code = code_only(body);
            for bad in MUTATING {
                if code.contains(bad) {
                    offenders.push(format!(
                        "byte {start}: argument list contains {bad:?} — {:?}",
                        &body[..body.len().min(90)]
                    ));
                }
            }
            if let Some(off) = is_bare_assignment(&code) {
                offenders.push(format!(
                    "byte {start}: argument list contains an assignment at +{off} — {:?}",
                    &code[..code.len().min(90)]
                ));
            }
            at = open + body.len() + 2;
        }

        assert!(
            sites >= 60,
            "only {sites} `oled_notify!` invocations found; the emitter that this \
             test exists to constrain has gone missing from main.rs"
        );
        assert!(
            offenders.is_empty(),
            "an `oled_notify!` argument list DOES something instead of just \
             describing something. The `display-none` arm of the macro expands \
             to `()` and never names its arguments, so on all 21 headless build \
             targets these expressions are NEVER EVALUATED — the effect happens \
             on a panelled board and silently does not happen on a Nerd, Hammer, \
             BitForge or Naja. Move the effect to its own statement outside the \
             macro call.\n{}",
            offenders.join("\n")
        );
    }
}

/// ── P1-W9: the Pool page's share-rejection reasons list ──────────────────────
///
/// `/api/system/info` already carries a real per-reason histogram at
/// `dcentaxe.poolTruth.rejectReasonCounts` (`api_system_info.rs` `PoolTruthView`,
/// filled from `dcentaxe_stratum::StratumStatus::reject_reason_counts`, itself
/// maintained by `record_reject_reason` and bounded at `MAX_REJECT_REASONS = 8`
/// distinct keys). The dashboard never read it.
///
/// The top-level `sharesRejectedReasons` is a different thing: an ARRAY of at
/// most one string (`api.rs` wraps `status.last_reject_reason`). The old Logs
/// counters indexed that array with STRING keys
/// (`sharesRejectedReasons['Job not found']`), which is always `undefined` on an
/// array, so both the "HW Err" and "Stale" counters were pinned at zero for
/// every device that ever ran this firmware.
///
/// `dashboard.rs` is espidf-only and cannot host-compile, so — exactly like
/// `dashboard_evidence_guards` — these pin the invariants against the source
/// TEXT via `include_str!`:
///
///  * the reasons list is mounted on the Pool page and rendered from the real
///    histogram, not from the one-element array;
///  * the classifier's key fragments and its plain-English lines stay the same
///    length and in the same order, and a table of 30 real reject strings (the
///    AxeOS v2.15.1 `share-rejection-explanations.json` vocabulary plus this
///    firmware's own `pool rejected share` fallback) each land in the class the
///    lane intends — a reordering or a dropped fragment fails here, not in the
///    field;
///  * pool-supplied keys are HTML-escaped before insertion;
///  * the empty state is honest and the lane spends no handler slot.
#[cfg(test)]
mod p1_w9_share_rejection_reason_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    /// Pull a `var <name>='<payload>'.split('|');` table out of the dashboard
    /// source and return its `|`-separated entries.
    fn table(name: &str) -> Vec<String> {
        let head = format!("var {name}='");
        let start = DASHBOARD_RS
            .find(&head)
            .unwrap_or_else(|| panic!("P1-W9: `var {name}=' ...` table is gone from dashboard.rs"))
            + head.len();
        let rest = &DASHBOARD_RS[start..];
        let end = rest
            .find("'.split('|');")
            .unwrap_or_else(|| panic!("P1-W9: {name} is no longer a '|'-split literal"));
        rest[..end].split('|').map(|s| s.to_string()).collect()
    }

    fn normalize(key: &str) -> String {
        key.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    /// The exact algorithm `rjCat()` runs in the browser: first class whose
    /// comma-separated fragments contain a substring of the normalized key.
    fn classify(key: &str) -> Option<usize> {
        let n = normalize(key);
        table("RJK")
            .iter()
            .position(|frags| frags.split(',').any(|f| n.contains(f)))
    }

    /// Reject strings a real pool can send, with the class each must land in.
    /// Sources:
    /// src/assets/share-rejection-explanations.json` (the bar's own vocabulary)
    /// and `dcentaxe-stratum/src/client.rs` `result_false_reject_reason`.
    const VOCABULARY: &[(&str, usize)] = &[
        // 0 — the share was fine, the job was not current any more.
        ("Stale", 0),
        ("stale", 0),
        ("stale-share", 0),
        ("Job not found", 0),
        // Lead fix at merge (blind critic P1-W9, F4): a job-id rejection is NOT staleness — this
        // project's documented BM1368/BM1370 job-id-mask defects emit exactly this string, and
        // "arrived after a new job started" would explain a firmware bug away. Class 5 instead.
        ("Invalid JobID", 5),
        ("invalid-job-id", 5),
        // 1 — the share did not reach the pool's target.
        ("Above target", 1),
        ("Difficulty too low", 1),
        ("difficulty-too-low", 1),
        ("low difficulty share", 1),
        // 2 — already seen.
        ("Duplicate", 2),
        ("Duplicate share", 2),
        // 3 — the session, not the share, is the problem.
        ("Unauthorized worker", 3),
        ("Not subscribed", 3),
        ("Authorization validation error", 3),
        ("Invalid authorization message", 3),
        ("Invalid Bitcoin address", 3),
        ("Worker mismatch", 3),
        // 4 — version rolling.
        ("Invalid version mask", 4),
        // 5 — the pool could not parse what we sent.
        ("No nonce", 5),
        ("No ntime", 5),
        ("No nonce2", 5),
        ("No username", 5),
        ("No job_id", 5),
        ("Params not array", 5),
        ("Invalid array size", 5),
        ("Invalid nonce2 length", 5),
        ("Ntime out of range", 5),
        ("Mining Submit validation error", 5),
        ("invalid-channel-id", 5),
        // 6 — our own fallback when the pool answers `false` with no payload.
        ("pool rejected share", 6),
    ];

    /// Strings that must stay UNCLASSIFIED. The lane's rule is that an
    /// unrecognised key is shown in the pool's own wording with NO explanation
    /// line, because inventing one is the failure mode this list exists to
    /// prevent. `Valid` is in the bar's file but is not a rejection at all.
    const DELIBERATELY_UNMAPPED: &[&str] = &[
        "Valid",
        "Suggest difficulty is disabled for this connection",
        "Server busy, retry",
    ];

    #[test]
    fn the_reasons_list_is_mounted_on_the_pool_page_under_the_shares_block() {
        let src = DASHBOARD_RS;
        let pool_page = {
            let start = src
                .find("<div class=\"page\" id=\"p1\">")
                .expect("P1-W9: the Pool page (#p1) is gone");
            let rest = &src[start..];
            let end = rest.find("<!-- ").map(|i| i + 1).unwrap_or(rest.len());
            &rest[..end]
        };
        assert!(
            pool_page.contains("id=\"rejList\""),
            "P1-W9: the rejection-reasons mount must live on the POOL page, next \
             to the share counters it explains"
        );
        assert!(
            pool_page.contains("Rejections by Reason"),
            "P1-W9: the reasons block must be titled, not an unlabelled list"
        );
        // It sits after the share rows, not above the pool form.
        let shares = pool_page
            .find("id=\"sharesPerHr\"")
            .expect("P1-W9: the Pool Status share rows are gone");
        let list = pool_page.find("id=\"rejList\"").unwrap();
        assert!(
            list > shares,
            "P1-W9: the reasons list belongs UNDER the shares block"
        );
    }

    #[test]
    fn the_list_renders_from_the_real_histogram_not_the_one_element_array() {
        assert!(
            DASHBOARD_RS.contains("renderRej(pt.rejectReasonCounts,r)"),
            "P1-W9: the list must be fed from dcentaxe.poolTruth.rejectReasonCounts \
             (the counted histogram), not from sharesRejectedReasons"
        );
        assert!(
            !DASHBOARD_RS.contains("sharesRejectedReasons["),
            "P1-W9: sharesRejectedReasons is an ARRAY of at most one string \
             (api.rs wraps last_reject_reason). Indexing it with a STRING key is \
             always undefined — that is the bug this lane removed; it must not \
             come back"
        );
    }

    #[test]
    fn pool_supplied_keys_are_escaped_before_insertion() {
        assert!(
            DASHBOARD_RS.contains("hEsc(cs[i].key)"),
            "P1-W9: a reject reason is a string the POOL chose. It reaches the DOM \
             through innerHTML, so it must pass through hEsc()"
        );
    }

    #[test]
    fn every_class_has_exactly_one_plain_english_line() {
        let keys = table("RJK");
        let words = table("RJW");
        assert_eq!(
            keys.len(),
            words.len(),
            "P1-W9: RJK and RJW are index-parallel; a length mismatch silently \
             shifts every explanation onto the wrong reason"
        );
        assert_eq!(keys.len(), 7, "P1-W9: the lane ships 7 reason classes");
        for (i, w) in words.iter().enumerate() {
            assert!(!w.is_empty(), "P1-W9: class {i} has an empty explanation");
            assert!(
                w.len() <= 40,
                "P1-W9: '{w}' is {} chars; the line has to read on a 390 px \
                 viewport under a two-column key/count row",
                w.len()
            );
            assert!(
                !w.contains('<') && !w.contains('&'),
                "P1-W9: explanations are injected as HTML; keep them plain text"
            );
        }
        for (i, k) in keys.iter().enumerate() {
            assert!(
                !k.is_empty(),
                "P1-W9: class {i} has no key fragments, so it can never match"
            );
            assert!(
                k.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ','),
                "P1-W9: fragment list '{k}' must be lowercase alphanumeric — it is \
                 matched against a key normalized by the same rule"
            );
        }
    }

    #[test]
    fn every_real_reject_string_lands_in_the_class_the_lane_intends() {
        for (key, want) in VOCABULARY {
            let got = classify(key);
            assert_eq!(
                got,
                Some(*want),
                "P1-W9: the pool string {key:?} classified as {got:?}, not \
                 class {want}. Reordering RJK/RJW or dropping a fragment moves \
                 real reject reasons under the wrong explanation, which is worse \
                 than showing none"
            );
        }
    }

    #[test]
    fn an_unrecognised_reason_gets_no_invented_explanation() {
        for key in DELIBERATELY_UNMAPPED {
            assert_eq!(
                classify(key),
                None,
                "P1-W9: {key:?} must stay unclassified. The render shows the \
                 pool's own wording with no explanation line rather than \
                 guessing, and the mining fixture carries one such key so the \
                 path is visible in evidence"
            );
        }
        // And the render really does branch on "no class" rather than defaulting.
        assert!(
            DASHBOARD_RS.contains("c=rjCat(cs[i].key);"),
            "P1-W9: the render must ask rjCat() per row"
        );
        assert!(
            DASHBOARD_RS.contains("(c<0?'':"),
            "P1-W9: an unclassified reason (c<0) must render NO explanation line"
        );
    }

    #[test]
    fn the_empty_state_is_honest_about_which_emptiness_it_means() {
        assert!(
            DASHBOARD_RS.contains("No rejected shares yet."),
            "P1-W9: with zero rejects the list must say so, not render blank"
        );
        assert!(
            DASHBOARD_RS.contains("The pool sent no reason for "),
            "P1-W9: rejects with an empty histogram is a DIFFERENT state from no \
             rejects at all, and the operator has to be able to tell them apart"
        );
    }

    #[test]
    fn the_stale_and_bad_share_counters_read_the_histogram() {
        assert!(
            DASHBOARD_RS.contains("_rc=pt.rejectReasonCounts||[]"),
            "P1-W9: the Logs stale/bad-share counters must read the histogram; \
             the previous source was an array indexed by string and was always 0"
        );
        // Class 0 is stale-by-nature; classes 1 and 4 are the share itself
        // being unacceptable. Anything else is a session/parse problem and is
        // not a share-quality counter.
        assert!(
            DASHBOARD_RS.contains("if(qk===0)stTot+=qn;else if(qk===1||qk===4)hwTot+=qn"),
            "P1-W9: the counter split must stay bound to the classifier's class \
             indices, or the Logs page starts counting auth failures as bad shares"
        );
    }

    #[test]
    fn the_render_only_uses_classes_the_inline_stylesheet_defines() {
        // The list is built as an innerHTML string, so no CSS-coverage tool can
        // see these classes in the markup. Deleting one during a dead-byte sweep
        // would leave the list unstyled with nothing failing.
        for class in ["kv-row", "kv-key", "kv-val", "help-small", "card-title"] {
            assert!(
                DASHBOARD_RS.contains(&format!(".{class}{{"))
                    || DASHBOARD_RS.contains(&format!(".{class} ")),
                "P1-W9: renderRej emits class '{class}', which the inline \
                 stylesheet must still define"
            );
        }
    }

    #[test]
    fn the_breakdown_is_anchored_to_a_denominator() {
        // "11 stale" is not information until the reader knows 11 out of what.
        // The Pool Status list carries the rejected total against SUBMITTED (not
        // against accepted, which would hide unresolved/pending shares).
        assert!(
            DASHBOARD_RS.contains("id=\"poolRejN\""),
            "P1-W9: the reasons breakdown needs a rejected total above it"
        );
        assert!(
            DASHBOARD_RS.contains("S('poolRejN',r+' of '+submitted+' submitted')"),
            "P1-W9: the total must read `<rejected> of <submitted> submitted`. \
             Against accepted+rejected it would silently drop pending and \
             unresolved submits and overstate the rejection rate"
        );
    }

    #[test]
    fn the_lane_spends_no_handler_slot() {
        // Embedded-route budget: MAX_URI_HANDLERS = 96, 76 real registrations
        // today, of which dashboard.rs owns 12 (`/`, `/index.html`, 10 assets).
        assert_eq!(
            DASHBOARD_RS.matches("fn_handler(").count(),
            3,
            "P1-W9: dashboard.rs registers `/` and `/index.html` directly plus one \
             inside register_static(). A new fn_handler( spends a slot the axe IA \
             budget has to approve"
        );
        assert_eq!(
            DASHBOARD_RS.matches("register_static(").count(),
            12,
            "P1-W9: the baked asset set is 10 files (definition + declaration + 10 \
             call sites). The reasons list is inline for exactly this reason"
        );
    }
}

/// ── P1-W9 critic held-out guard ─────────────────────────────────────────────
///
/// The lane's `rjCat()` classifier scans its seven fragment classes IN ORDER and
/// returns the FIRST class holding a substring of the normalized key. That makes
/// the ordering load-bearing in a way the lane's own vocabulary table cannot see:
/// a broad fragment added to an early class silently swallows every key a later
/// class was written for, and the later class's explanation line becomes dead
/// code that no test notices (the vocabulary table only pins the 32 strings it
/// happens to list).
///
/// This binds the property directly: **every fragment must classify to its own
/// class**. If `class[i]` contains a fragment that some `class[j<i]` already
/// matches, the fragment is unreachable and the reasons it exists for are
/// explained by the wrong line — the exact failure mode the lane's comment says
/// is "worse than showing none".
///
/// Written blind by the round-1 critic; the builder never saw it. It is
/// deliberately independent of `p1_w9_share_rejection_reason_guards` (it
/// re-derives the tables from the dashboard source itself) so a future edit that
/// loosens that module cannot loosen this one at the same time.
#[cfg(test)]
mod critic_p1_w9_reject_class_fragments_are_reachable {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn split_table(name: &str) -> Vec<String> {
        let head = format!("var {name}='");
        let start = DASHBOARD_RS
            .find(&head)
            .unwrap_or_else(|| panic!("P1-W9 critic: `var {name}=' ...` is gone from dashboard.rs"))
            + head.len();
        let rest = &DASHBOARD_RS[start..];
        let end = rest
            .find("'.split('|');")
            .unwrap_or_else(|| panic!("P1-W9 critic: {name} is no longer a '|'-split literal"));
        rest[..end].split('|').map(str::to_string).collect()
    }

    /// `rjCat()`: first class with a fragment that is a substring of the key,
    /// after the key is lowercased and stripped to `[a-z0-9]`.
    fn classify(classes: &[String], key: &str) -> Option<usize> {
        let n: String = key
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        classes
            .iter()
            .position(|frags| frags.split(',').any(|f| n.contains(f)))
    }

    #[test]
    fn no_reject_class_fragment_is_shadowed_by_an_earlier_class() {
        let classes = split_table("RJK");
        let words = split_table("RJW");
        assert_eq!(classes.len(), words.len(), "RJK/RJW must stay parallel");

        for (i, class) in classes.iter().enumerate() {
            for frag in class.split(',') {
                assert!(
                    !frag.is_empty(),
                    "P1-W9 critic: class {i} has an empty fragment; every key contains \
                     the empty string, so it would swallow every later class"
                );
                let landed = classify(&classes, frag);
                assert_eq!(
                    landed,
                    Some(i),
                    "P1-W9 critic: fragment {frag:?} belongs to class {i} ({:?}) but a key \
                     containing it is claimed by class {landed:?}. rjCat() takes the FIRST \
                     matching class, so this fragment can never fire and every reject reason \
                     it was written for is explained by the wrong line.",
                    words[i]
                );
            }
        }
    }
}

/// ── Lane P1-W4: motion, contrast and target-size floors ───────────────────
///
/// Measured on the mock with a CDP probe before anything was changed
/// (`projects/.axe-gauntlet/pass1/P1-W4/before/audit_rm_*.json`):
///
/// | counter (7 pages, reduced-motion emulated) | 1440 | 390 |
/// |---|---|---|
/// | CSS animations `playState==='running'`     |   37 |  38 |
/// | text nodes below 4.5:1 on their painted bg |  416 | 1002 |
/// | text nodes below 10 px                     |  115 |  379 |
/// | controls below 44x44                       |  159 |  176 |
///
/// The three roots were: no `@media (prefers-reduced-motion: reduce)` rule
/// anywhere; `--dim:#6b7a8d` (3.51:1 at worst) and `--muted:#3a4555` (1.89:1)
/// used as TEXT colours; and no minimum target size below 768 px.
///
/// `dashboard.rs` is `target_os = "espidf"`-only and cannot host-compile, so —
/// exactly like `dcent_design_language_guards`, `dashboard_a11y_nav_guards`,
/// `fund_link_guards` and `dashboard_mobile_shell_guards` — these pin the
/// invariants against the source TEXT via `include_str!`, on a
/// whitespace-collapsed copy so a benign reflow cannot flip a guard. They are
/// ADDITIVE: no existing guard is touched, renamed, weakened or ignored.
///
/// NOTE ON `html:root`. `dashboard/tokens.css` is `<link>`ed AFTER the inline
/// `<style>` and its `:root` would restore the two failing values. The lane's
/// footprint is `dashboard.rs`, so the corrected pair is declared with the
/// higher-specificity `html:root` (0,1,1). W4-4 pins BOTH the escalation and
/// the measured ratio, so a future lane that fixes `tokens.css` properly can
/// delete the escalation only by keeping the ratio.
#[cfg(test)]
mod dashboard_motion_contrast_target_guards {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn flat() -> String {
        DASHBOARD_RS.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Byte offsets of the served inline stylesheet inside `flat()`. The first
    /// `</style>` in the file is a mention inside a Rust doc comment, so the
    /// close is searched for AFTER the open — never from the start.
    fn css_span(f: &str) -> (usize, usize) {
        // `<style>` also appears in two comments above the markup, so the real
        // opener is matched by the first rule that follows it.
        const OPEN: &str = "<style> :root{";
        let open = f.find(OPEN).expect("W4: the inline <style> must exist") + OPEN.len();
        let close = open
            + f[open..]
                .find("</style>")
                .expect("W4: the inline <style> must be closed");
        (open, close)
    }

    /// The served inline stylesheet, whitespace-collapsed.
    fn css() -> String {
        let f = flat();
        let (a, b) = css_span(&f);
        f[a..b].to_string()
    }

    /// Everything the browser gets AFTER the stylesheet: markup plus inline JS.
    fn body() -> String {
        let f = flat();
        let (_, b) = css_span(&f);
        f[b..].to_string()
    }

    /// The body of the balanced `{...}` that starts at `at`.
    fn balanced(src: &str, at: usize) -> String {
        let bytes = src.as_bytes();
        let start = src[at..].find('{').expect("W4: rule must open") + at;
        let mut depth = 0i32;
        for i in start..bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return src[start + 1..i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("W4: unterminated rule at {at}")
    }

    fn reduced_motion_block() -> String {
        let c = css();
        let at = c.find("@media(prefers-reduced-motion:reduce)").unwrap_or_else(|| {
            panic!(
                "W4-1: the served stylesheet declares infinite animations and a \
                 24 px backdrop blur, and the probe measured 37 running animations \
                 on the dashboard alone. Without an \
                 `@media(prefers-reduced-motion:reduce)` block an operator who has \
                 asked their OS to reduce motion is given no way to stop them."
            )
        });
        balanced(&c, at)
    }

    /// The selector that owns the rule containing byte `at`: everything between
    /// the previous `{` or `}` and this rule's own `{`. Works for top-level and
    /// `@media`-nested rules alike.
    fn selector_owning(src: &str, at: usize) -> String {
        let open = src[..at].rfind('{').expect("W4: declaration outside a rule");
        let start = src[..open]
            .rfind(['{', '}'])
            .map(|i| i + 1)
            .unwrap_or(0);
        // Strip any CSS comment that sits between the previous rule and this
        // selector (`/* -- Sidebar -- */ .sb` is one selector, not two).
        let mut sel = src[start..open].to_string();
        while let Some(a) = sel.find("/*") {
            match sel[a..].find("*/") {
                Some(rel) => {
                    let b = a + rel + 2;
                    sel.replace_range(a..b, "");
                }
                None => {
                    sel.truncate(a);
                    break;
                }
            }
        }
        sel.trim().to_string()
    }

    fn hex_rgb(h: &str) -> (f64, f64, f64) {
        let h = h.trim_start_matches('#');
        assert_eq!(h.len(), 6, "W4: expected a 6-digit hex, got {h:?}");
        let p = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).expect("W4: bad hex") as f64;
        (p(0), p(2), p(4))
    }

    fn lin(c: f64) -> f64 {
        let c = c / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }

    fn luminance(c: (f64, f64, f64)) -> f64 {
        0.2126 * lin(c.0) + 0.7152 * lin(c.1) + 0.0722 * lin(c.2)
    }

    /// WCAG 2.x contrast ratio.
    fn ratio(a: (f64, f64, f64), b: (f64, f64, f64)) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    }

    /// The value of one custom property declared inside `html:root{...}`.
    fn html_root_token(name: &str) -> String {
        let c = css();
        let at = c.find("html:root{").unwrap_or_else(|| {
            panic!(
                "W4-4: `dashboard/tokens.css` is linked AFTER this stylesheet and its \
                 `:root` re-declares --dim and --muted. Only a higher-specificity \
                 selector (`html:root`, 0,1,1) inside this file keeps the corrected \
                 pair; a plain `:root` here loses the cascade and the contrast \
                 regression comes back invisibly."
            )
        });
        let body = balanced(&c, at);
        let key = format!("{name}:");
        let s = body
            .find(&key)
            .unwrap_or_else(|| panic!("W4-4: html:root must declare {name}, body was {body:?}"))
            + key.len();
        let rest = &body[s..];
        let e = rest.find([';', '}']).unwrap_or(rest.len());
        rest[..e].trim().to_string()
    }

    // The lightest background any of this text was measured on: a `.pill`
    // (rgba(255,255,255,0.04)) painted over `--s-overlay` #1a1c2a, which
    // composites to rgb(35,36,48). Every other painted surface in the served UI
    // is darker, so clearing 4.5:1 here clears it everywhere.
    const LIGHTEST_PAINTED_SURFACE: (f64, f64, f64) = (35.0, 36.0, 48.0);

    // ── W4-1: reduced motion actually stops the motion. ─────────────────────
    #[test]
    fn reduced_motion_disables_every_animation_and_transition() {
        let b = reduced_motion_block();
        for needle in [
            "*,*::before,*::after{",
            "animation:none!important",
            "transition:none!important",
        ] {
            assert!(
                b.contains(needle),
                "W4-1: the reduced-motion block must contain {needle:?}. It has to be \
                 universal and !important because five modular stylesheets \
                 (core.css's ringRot/linkPulse/nodeBreathe, asic-chips.css's \
                 chipBeam/hotPulse, ...) are linked AFTER this block and declare \
                 their own infinite animations. Block body was: {b:?}"
            );
        }
    }

    // ── W4-2: every blur the stylesheet paints is turned off with it. A 24 px
    //    backdrop-filter over scrolling content is the most expensive repaint
    //    on the page and reads as motion to the same users. ──────────────────
    #[test]
    fn reduced_motion_also_drops_every_backdrop_blur() {
        let c = css();
        let block = reduced_motion_block();
        let off = {
            let at = block
                .find("backdrop-filter:none")
                .expect("W4-2: the reduced-motion block must declare backdrop-filter:none");
            selector_owning(&block, at)
        };
        assert!(
            block.contains("-webkit-backdrop-filter:none"),
            "W4-2: the prefixed property must be cleared too; Safari and every \
             WebKit-based mobile browser only honour the prefixed one."
        );
        let mut blurred: Vec<String> = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = c[from..].find("backdrop-filter:blur(") {
            let at = from + rel;
            let sel = selector_owning(&c, at);
            if !sel.starts_with('@') && !blurred.contains(&sel) {
                blurred.push(sel);
            }
            from = at + 1;
        }
        assert!(
            !blurred.is_empty(),
            "W4-2: no backdrop blur found at all - if the blur was removed, this \
             guard is stale and should be re-derived, not deleted."
        );
        for sel in blurred {
            // A grouped selector like `.a,.b` is covered when each part is.
            for part in sel.split(',') {
                let part = part.trim();
                assert!(
                    off.split(',').any(|o| o.trim() == part),
                    "W4-2: `{part}` paints a backdrop blur but is not in the \
                     reduced-motion `backdrop-filter:none` list ({off:?})."
                );
            }
        }
        assert!(
            off.contains("#frOverlay"),
            "W4-2: the first-run overlay carries its blur in an inline style \
             attribute, which only an !important author rule can override; it must \
             stay in the list ({off:?})."
        );
    }

    // ── W4-3: --muted is a surface/edge token, never a text colour. ─────────
    #[test]
    fn muted_is_never_used_as_a_text_colour_in_this_stylesheet() {
        let c = css();
        let mut hits: Vec<String> = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = c[from..].find("color:var(--muted)") {
            let at = from + rel;
            let prev = c.as_bytes()[at.saturating_sub(1)];
            // `border-color:` / `scrollbar-color:` are edge uses and stay.
            if prev == b'{' || prev == b';' || prev == b' ' {
                hits.push(selector_owning(&c, at));
            }
            from = at + 1;
        }
        assert!(
            hits.is_empty(),
            "W4-3: --muted measured 1.89:1 against --s-raised as text. These rules \
             set it with a bare `color:`: {hits:?}. Secondary text uses --dim; \
             --muted stays for borders, the scrollbar thumb and idle dots."
        );
    }

    // ── W4-4: the two secondary-text tokens clear 4.5:1 by measurement, not by
    //    assertion, and they keep their order (muted quieter than dim). ──────
    #[test]
    fn the_secondary_text_tokens_clear_four_and_a_half_to_one() {
        let dim = html_root_token("--dim");
        let muted = html_root_token("--muted");
        for (name, hex) in [("--dim", &dim), ("--muted", &muted)] {
            let r = ratio(hex_rgb(hex), LIGHTEST_PAINTED_SURFACE);
            assert!(
                r >= 4.5,
                "W4-4: {name}:{hex} measures {r:.2}:1 against the lightest painted \
                 surface in the served UI (rgb(35,36,48) - a .pill over \
                 --s-overlay). WCAG 1.4.3 asks 4.5:1 for body text and this token \
                 is a body-text token."
            );
        }
        let (rd, rm) = (
            ratio(hex_rgb(&dim), LIGHTEST_PAINTED_SURFACE),
            ratio(hex_rgb(&muted), LIGHTEST_PAINTED_SURFACE),
        );
        assert!(
            rd > rm,
            "W4-4: --dim ({rd:.2}:1) must stay the LOUDER of the two secondary \
             tiers and --muted ({rm:.2}:1) the quieter, or the two tokens have \
             swapped meaning and every call site now says the opposite of what \
             its author intended."
        );
    }

    // ── W4-5: nothing readable below 10 px in this stylesheet. ──────────────
    #[test]
    fn no_readable_text_is_declared_below_ten_pixels() {
        let c = css();
        let mut small: Vec<(String, String)> = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = c[from..].find("font-size:") {
            let at = from + rel;
            from = at + 1;
            // The floor rule matches inline style= attributes by substring; its
            // own selector text necessarily contains the sizes it is fixing.
            if c[..at].ends_with("[style*=\"") {
                continue;
            }
            let rest = &c[at + "font-size:".len()..];
            let end = rest.find("px").unwrap_or(0);
            if end == 0 || end > 4 {
                continue;
            }
            if let Ok(px) = rest[..end].parse::<f64>() {
                if px < 10.0 {
                    small.push((selector_owning(&c, at), rest[..end].to_string()));
                }
            }
            from = at + 1;
        }
        assert!(
            small.is_empty(),
            "W4-5: 10 px is the readable floor for this UI (the probe found 379 \
             sub-10 px text nodes at 390 px before this lane). These declare less: \
             {small:?}"
        );
    }

    // ── W4-6: the educational copy is reachable without a mouse. ────────────
    #[test]
    fn every_tooltip_is_focusable_and_openable_by_tap() {
        let b = body();
        let hosts = b.matches("data-tip=\"").count();
        assert!(
            hosts >= 20,
            "W4-6: expected the 20 measured [data-tip] hosts, found {hosts} - if \
             tooltips moved, re-derive this guard rather than lowering it."
        );
        let mut from = 0usize;
        let mut unfocusable = 0usize;
        while let Some(rel) = b[from..].find("data-tip=\"") {
            let at = from + rel + "data-tip=\"".len();
            let end = at + b[at..].find('"').expect("W4-6: unterminated data-tip");
            // the attribute that follows the closing quote
            let tail = &b[end + 1..(end + 24).min(b.len())];
            if !tail.trim_start().starts_with("tabindex=0") {
                unfocusable += 1;
            }
            from = end;
        }
        assert_eq!(
            unfocusable, 0,
            "W4-6: {unfocusable} [data-tip] hosts carry no `tabindex=0`. The tip is \
             a ::after on :hover only, so a host that cannot take focus hides its \
             copy from every keyboard and touch user."
        );
        let c = css();
        for needle in [
            "[data-tip]:focus::after",
            "[data-tip]:focus-within::after",
            "[data-tip].tip-on::after",
        ] {
            assert!(
                c.contains(needle),
                "W4-6: the tooltip must open on {needle:?}, not on :hover alone."
            );
        }
        assert!(
            b.contains("addEventListener('touchstart'") && b.contains("'tip-on'"),
            "W4-6: a touch device has no hover, so the tap toggle that adds \
             `.tip-on` is the only way the copy is reachable there."
        );
    }

    // ── W4-7: 44x44 controls on the phone viewport. ─────────────────────────
    #[test]
    fn controls_declare_a_forty_four_pixel_floor_below_seven_sixty_eight() {
        let c = css();
        let at = c
            .rfind("@media(max-width:768px)")
            .expect("W4-7: the phone breakpoint must exist");
        let block = balanced(&c, at);
        assert!(
            block.matches("min-height:44px").count() >= 2,
            "W4-7: the phone block must set a 44 px minimum height; the probe \
             measured .tb-btn at 24 px, .log-filter-pill at 21 px and the sidebar \
             links at 37 px. Block: {block:?}"
        );
        for sel in [
            ".tb-btn", ".btn", ".hamburger", ".modal-close", ".pw-toggle",
            ".log-filter-pill", ".log-crumb-pill", ".sb-nav a", "details summary",
            ".field input", ".field select",
        ] {
            assert!(
                block.contains(sel),
                "W4-7: `{sel}` was measured below 44 px at 390 and is not in the \
                 phone-viewport floor."
            );
        }
        assert!(
            block.contains("input[type=checkbox]") && block.contains("input[type=radio]"),
            "W4-7: a checkbox/radio is tapped through its <label>; the chart legend \
             and the room-temp radio group were 13-17 px tall until their labels \
             took the floor."
        );
    }
}

/// ── HELD-OUT guard, written by the P1-W4 BLIND CRITIC (round 1, 2026-09-03) ──
///
/// The builder never saw this test. It binds the one thing the lane's own
/// guards do not: the **cascade bet**.
///
/// `dashboard/tokens.css` is `<link>`ed AFTER the inline `<style>` (dashboard.rs
/// `:707`), so for any custom property both files declare, tokens.css wins at
/// equal specificity. The lane accepted that for the surface ladder (inline
/// `--s-void:#050709` deliberately loses to tokens.css `#070710` — verified
/// live: `getComputedStyle(document.documentElement).getPropertyValue('--s-void')`
/// returns `#070710` on the served page) and escalated ONLY the secondary text
/// pair through `html:root` (0,1,1).
///
/// That escalation is invisible at review time and silent at runtime: delete one
/// entry, or let a future tokens.css edit diverge one more *text* token, and the
/// page reverts to the measured 1.89:1 / 3.51:1 with every existing W4 guard
/// still green (they only read `dashboard.rs`). This guard reads BOTH files and
/// closes the loop in both directions:
///
///   (a) every property in `html:root{}` is really contested — tokens.css
///       declares it with a different value — so the override is never dead
///       weight someone "cleans up";
///   (b) every property the inline stylesheet uses as a `color:` value and that
///       tokens.css re-declares divergently IS carried by the override; and
///   (c) each carried value clears 4.5:1 on the lightest painted surface the
///       critic measured (a `.pill`, rgba(255,255,255,0.04) over `--s-overlay`,
///       compositing to rgb(35,36,48)).
///
/// Critic measurement this rests on (CDP contrast walk, 5 widths x 7 pages x
/// {mining, ready, standby}): text nodes below 4.5:1 = **0** after, **487** at
/// 1440 / **1351** at 390 before.
#[cfg(test)]
mod critic_p1_w4_heldout_token_override_cascade {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));
    const TOKENS_CSS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard/tokens.css"
    ));

    /// rgb(35,36,48): a `.pill` background (rgba(255,255,255,0.04)) composited
    /// over `--s-overlay` #1a1c2a. Measured by the critic as the lightest
    /// painted background any secondary text sits on; every other surface in
    /// the served UI is darker, so clearing here clears everywhere.
    const LIGHTEST_PAINTED_SURFACE: (f64, f64, f64) = (35.0, 36.0, 48.0);

    fn strip_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut rest = src;
        while let Some(a) = rest.find("/*") {
            out.push_str(&rest[..a]);
            match rest[a + 2..].find("*/") {
                Some(rel) => rest = &rest[a + 2 + rel + 2..],
                None => return out,
            }
        }
        out.push_str(rest);
        out
    }

    /// Whitespace-collapsed, comment-free copy: a benign reflow of the source
    /// must not be able to flip this guard.
    fn flat(src: &str) -> String {
        strip_comments(src)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn flat_keep_comments(src: &str) -> String {
        src.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// True when `--name` is used as the value of a real `color:` property —
    /// `border-color:var(--muted)` must NOT count as text.
    fn used_as_text_colour(css: &str, name: &str) -> bool {
        let needle = format!("color:var({name})");
        let b = css.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = css[from..].find(&needle) {
            let at = from + rel;
            let prev = if at == 0 { b'{' } else { b[at - 1] };
            if !(prev == b'-' || prev.is_ascii_alphanumeric()) {
                return true;
            }
            from = at + 1;
        }
        false
    }

    /// Body of the balanced `{...}` that opens at or after `at`.
    fn balanced(src: &str, at: usize) -> String {
        let b = src.as_bytes();
        let start = at + src[at..].find('{').expect("heldout: rule must open");
        let mut depth = 0i32;
        for i in start..b.len() {
            match b[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return src[start + 1..i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("heldout: unterminated rule");
    }

    /// `--name: value` pairs declared directly in a rule body.
    fn decls(body: &str) -> Vec<(String, String)> {
        let mut v = Vec::new();
        for chunk in body.split(';') {
            let chunk = chunk.trim();
            if !chunk.starts_with("--") {
                continue;
            }
            if let Some(c) = chunk.find(':') {
                let name = chunk[..c].trim().to_string();
                let val = chunk[c + 1..].trim().to_string();
                if !name.is_empty() && !val.is_empty() {
                    v.push((name, val));
                }
            }
        }
        v
    }

    fn find_rule(src: &str, selector: &str) -> Option<String> {
        src.find(selector).map(|at| balanced(src, at))
    }

    /// The served inline stylesheet only (never the doc comments above it).
    /// NOTE: comments are NOT stripped from `dashboard.rs` — a Rust `//` line
    /// at :19 contains the glob `dashboard/*.{js,css}`, whose `/*` would open a
    /// phantom comment that swallows the `<style>` opener.
    fn inline_css() -> String {
        let f = flat_keep_comments(DASHBOARD_RS);
        const OPEN: &str = "<style> :root{";
        let open = f.find(OPEN).expect("heldout: inline <style> must exist");
        let close = open
            + f[open..]
                .find("</style>")
                .expect("heldout: inline <style> must be closed");
        f[open..close].to_string()
    }

    fn hex_rgb(h: &str) -> Option<(f64, f64, f64)> {
        let h = h.trim().trim_start_matches('#');
        if h.len() != 6 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let p = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).unwrap() as f64;
        Some((p(0), p(2), p(4)))
    }

    fn lin(c: f64) -> f64 {
        let c = c / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }

    fn luminance(c: (f64, f64, f64)) -> f64 {
        0.2126 * lin(c.0) + 0.7152 * lin(c.1) + 0.0722 * lin(c.2)
    }

    fn ratio(a: (f64, f64, f64), b: (f64, f64, f64)) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    }

    #[test]
    fn every_text_token_the_later_sheet_contests_is_escalated_and_still_clears_four_and_a_half() {
        let css = inline_css();
        let inline_root = decls(&find_rule(&css, ":root{").expect(
            "heldout: the inline stylesheet must open with a :root token block",
        ));
        let escalated = decls(&find_rule(&css, "html:root{").unwrap_or_else(|| {
            panic!(
                "HELDOUT-W4: `dashboard/tokens.css` is linked AFTER this stylesheet \
                 (dashboard.rs :707) and its :root re-declares the secondary text \
                 tokens. Without an `html:root{{...}}` escalation inside dashboard.rs \
                 the later sheet wins and the contrast regression the lane measured \
                 (--muted 1.89:1, --dim 3.51:1) returns with no test going red."
            )
        }));
        let tokens_root = decls(
            &find_rule(&flat(TOKENS_CSS), ":root{")
                .expect("heldout: tokens.css must declare a :root block"),
        );

        let val = |set: &[(String, String)], name: &str| -> Option<String> {
            set.iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };

        // (a) nothing in the escalation is dead weight.
        assert!(
            !escalated.is_empty(),
            "HELDOUT-W4a: html:root{{}} exists but declares nothing."
        );
        for (name, v) in &escalated {
            let t = val(&tokens_root, name).unwrap_or_else(|| {
                panic!(
                    "HELDOUT-W4a: html:root escalates {name}, but dashboard/tokens.css \
                     does not declare it — nothing contests it, so the escalation is \
                     dead weight that invites a future 'cleanup' to delete the whole \
                     rule (and with it the tokens that DO need it)."
                )
            });
            assert_ne!(
                &t, v,
                "HELDOUT-W4a: html:root escalates {name} to the same value \
                 tokens.css already has — the rule is inert here."
            );
        }

        // (b) every contested TEXT token is escalated, and (c) still clears 4.5:1.
        for (name, inline_v) in &inline_root {
            if !used_as_text_colour(&css, name) {
                continue; // not used as a text colour in the served stylesheet
            }
            let Some(tokens_v) = val(&tokens_root, name) else {
                continue; // the later sheet does not contest it
            };
            if &tokens_v == inline_v {
                continue; // contested but identical — the cascade is harmless
            }
            let esc = val(&escalated, name).unwrap_or_else(|| {
                panic!(
                    "HELDOUT-W4b: `{name}` is used as a TEXT colour in the inline \
                     stylesheet, the inline :root sets it to {inline_v} and \
                     dashboard/tokens.css re-declares it as {tokens_v}. tokens.css is \
                     linked AFTER the inline <style>, so {tokens_v} is what the \
                     browser paints. Escalate it in the html:root{{}} block (or fix \
                     tokens.css) — the critic measured 487 text nodes below 4.5:1 at \
                     1440 px and 1351 at 390 px when this cascade was left to win."
                )
            });
            assert_eq!(
                &esc, inline_v,
                "HELDOUT-W4b: html:root escalates {name} to {esc} while the inline \
                 :root says {inline_v} — two sources of truth for one token."
            );
            let rgb = hex_rgb(&esc).unwrap_or_else(|| {
                panic!("HELDOUT-W4c: {name} escalated to {esc}, which is not a 6-digit hex; \
                        this guard can only prove the ratio for a literal colour.")
            });
            let r = ratio(rgb, LIGHTEST_PAINTED_SURFACE);
            assert!(
                r >= 4.5,
                "HELDOUT-W4c: {name}={esc} measures {r:.2}:1 on the lightest painted \
                 surface the critic found (rgb(35,36,48) — a .pill over --s-overlay). \
                 WCAG AA body text needs 4.5:1."
            );
        }
    }
}

/// HELD-OUT (blind critic, round 2, P1-W6) — the round-2 tests prove the tick
/// ladder FORMULA is present in the shipped source (string match), but none of
/// them prove the formula's OUTPUT stays within a readable tick count across a
/// span shape the builder didn't screenshot. A ladder that is present but
/// mis-tuned (e.g. one entry shifted) would pass every existing test here while
/// drawing an unreadable axis (too many ticks on a long span, or too few on a
/// short one) for a scenario nobody happened to capture.
///
/// This mirrors `dashboard.rs`'s exact step-selection and tick-walk arithmetic
/// in Rust (cross-checked against the literal source string so the mirror
/// cannot silently drift from what ships) and asserts the bound AxeOS-class
/// readability requires: a 3-hour span must not spam more than 5 ticks, and a
/// 3-minute span must still show at least 2 (a single tick cannot convey
/// elapsed time). The local clock-offset term is fixed at 0 for determinism
/// across CI hosts in different timezones — it only shifts tick PHASE, never
/// the ladder step or the tick COUNT the two assertions below check.
#[cfg(test)]
mod critic_p1_w6_r2_tick_ladder_bounds {
    const DASHBOARD_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/dashboard.rs"
    ));

    fn collapse_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Faithful mirror of `dashboard.rs`'s `for(k=0;k<6;k++)if(tsp/TS[k]<=5){st=TS[k];break}`.
    fn ladder_step_ms(tsp: f64) -> f64 {
        const TS: [f64; 6] = [6e4, 3e5, 9e5, 18e5, 36e5, 108e5];
        for step in TS {
            if tsp / step <= 5.0 {
                return step;
            }
        }
        216e5
    }

    /// Faithful mirror of the tick-walk
    /// `for(var tk=Math.ceil((t0-tz)/st)*st+tz;tk<=t0+tsp;tk+=st)`, with the
    /// timezone term fixed at 0 (see module doc).
    fn tick_count(t0: f64, tsp: f64) -> usize {
        let st = ladder_step_ms(tsp);
        let mut tk = (t0 / st).ceil() * st;
        let end = t0 + tsp;
        let mut n = 0usize;
        while tk <= end {
            n += 1;
            tk += st;
        }
        n
    }

    #[test]
    fn tick_ladder_formula_matches_the_shipped_source() {
        let flat = collapse_ws(DASHBOARD_RS);
        assert!(
            flat.contains(
                "var TS=[6e4,3e5,9e5,18e5,36e5,108e5],st=216e5,k;for(k=0;k<6;k++)if(tsp/TS[k]<=5){st=TS[k];break}"
            ),
            "the mirrored ladder constants in this held-out test no longer match \
             dashboard.rs's shipped tick-step formula — update the mirror before \
             trusting the bounds below"
        );
    }

    #[test]
    fn a_three_hour_span_never_exceeds_five_ticks() {
        let n = tick_count(0.0, 3.0 * 3_600_000.0);
        assert!(
            n <= 5,
            "a 3-hour window produced {n} ticks — the ladder must pick a coarser \
             step before the axis turns into a comb of labels"
        );
    }

    #[test]
    fn a_three_minute_span_still_shows_at_least_two_ticks() {
        let n = tick_count(0.0, 3.0 * 60_000.0);
        assert!(
            n >= 2,
            "a 3-minute window produced {n} tick(s) — a single tick cannot show \
             elapsed time, the reader needs at least two to see a direction"
        );
    }
}

/// P1-O5: the panel used to show three fabricated numbers — a "block
/// progress" bar that was really `uptime % 600` (device uptime, nothing to do
/// with a block), a "BTC Timeline: 13%" bar driven by a hardcoded
/// `0.13_f32`, and a "^600EH/s" network-hashrate line with no backing field
/// anywhere in this firmware (a workspace-wide `grep -rn network_hashrate`
/// is empty).
///
/// The fix: a pure, host-tested composer —
/// [`crate::display_convert::halving_progress`] — turns a real coinbase
/// `block_height` and a network-aware subsidy-halving interval into
/// `Option<(f32 progress, u32 blocks_to_halving)>`, `None` for height 0 (no
/// decoded height yet) so the bar is *absent* rather than drawn at a lying
/// 0%. `main.rs` page 2 is the one remaining consumer; the BTC-Timeline and
/// "you vs the world" sub-pages of page 6 (Hall of Fame) are deleted rather
/// than given a second, redundant copy of the same math.
///
/// This module is a source contract over `main.rs` (which cannot be
/// host-compiled) plus a direct re-exercise of the composer through the
/// `#[path]`-shared `display_convert` module, so both halves of the fix —
/// "the old lies are gone" and "the new math is honest at its edges" — are
/// checked from dcentaxe-core.
#[cfg(test)]
mod p1_o5_fabricated_panel_numbers_guards {
    use crate::display_convert::halving_progress;

    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    /// `core.autocrlf = true` gives fresh Windows worktrees CRLF working
    /// copies while git stores LF. Every read here is normalised first.
    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// None of the three fabricated sites, nor the sub-page framing built
    /// around them, may return — as code, not merely as an unused string
    /// sitting in a doc comment somewhere.
    #[test]
    fn none_of_the_three_fabricated_literals_survive_in_main_rs() {
        let src = lf(MAIN_RS);
        for dead in [
            "uptime % 600",           // the fake "block progress" divisor
            "timeline_pct",           // the fake BTC-Timeline local
            "0.13_f32",               // its hardcoded constant
            "BTC Timeline",           // its on-glass label
            "^600EH/s",               // the fake network-hashrate line
            "YOU vs THE WORLD",       // its page framing
            "- YOU vs THE WORLD -",
        ] {
            assert!(
                !src.contains(dead),
                "{dead:?} is back in main.rs. P1-O5 removed it as a \
                 fabricated number (or the framing built around one); if a \
                 real data source justifies bringing the concept back, it \
                 must go through halving_progress() or an equally honest, \
                 host-tested composer, never a bare constant."
            );
        }
    }

    /// The one remaining progress bar on the panel is fed by the composer,
    /// gated so an unknown height draws no bar at all, and nothing else in
    /// `main.rs` calls `draw_progress_bar` a second time (that second call
    /// was the BTC-Timeline bar this lane deleted).
    #[test]
    fn the_one_remaining_progress_bar_is_composer_fed_and_height_gated() {
        let src = lf(MAIN_RS);
        assert_eq!(
            src.matches("draw_progress_bar(").count(),
            1,
            "expected exactly one draw_progress_bar call (the honest \
             halving bar on page 2); a second call means a fabricated bar \
             came back, or the honest one was duplicated without review"
        );
        assert_eq!(
            src.matches("halving_progress(block_height, interval)").count(),
            1,
            "the panel's block-height-derived progress must be sourced from \
             exactly one call to the shared composer"
        );
        // Lead fix at merge (blind critic P1-O5, finding 2): the interval is an
        // `Option` now (a regtest mesh, whose job height may belong to the pool
        // instead, selects none), so the composer is reached through `and_then`.
        assert_eq!(
            src.matches("halving_interval.and_then(").count(),
            1,
            "the composer must be fed through the Option interval, so a chain              the panel cannot know draws no bar rather than the wrong one"
        );
        // The bar draw must be reachable only through the `Some` arm of a
        // match/if-let on the composer's output — i.e. it is textually
        // inside the `if let Some((progress, _)) = halving` guard, not
        // drawn unconditionally (which would still show an empty bar as a
        // lying "0%" when the height is unknown, the exact bug this lane
        // fixes for height 0).
        let bar_at = src
            .find("draw_progress_bar(")
            .expect("checked above: exactly one call exists");
        let preceding = &src[..bar_at];
        let guard_at = preceding
            .rfind("if let Some((progress, _)) = halving")
            .expect("the progress-bar draw must be preceded by the height-gate");
        // Nothing may close that `if let` block between the guard and the
        // draw call (a stray `}` at the guard's own indentation would mean
        // the draw moved outside the gate). The guard line and its closing
        // brace sit at the same indentation as one another.
        let guard_line_start = preceding[..guard_at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let indent = &preceding[guard_line_start..guard_at];
        let close_needle = format!("\n{indent}}}\n");
        assert!(
            !preceding[guard_at..].contains(&close_needle),
            "the height gate appears to close before the progress-bar draw; \
             the bar must stay inside `if let Some(...) = halving`"
        );
    }

    /// `halving_progress` at the exact edges the lane brief named: unknown
    /// height, an exact halving boundary, a large real mainnet height, and a
    /// different (network-aware) interval. Duplicates the hal-crate unit
    /// tests deliberately — this crate is where a source contract can also
    /// see `main.rs`, so both the composer's honesty and its call site are
    /// checked from one place.
    #[test]
    fn halving_progress_edges_render_the_brief_named_cases() {
        assert_eq!(
            halving_progress(0, 210_000),
            None,
            "height 0 (no decoded height yet) must draw no bar, not a lying 0%"
        );
        assert_eq!(
            halving_progress(840_000, 210_000),
            Some((0.0, 210_000)),
            "an exact mainnet halving boundary is 0% into the new epoch, \
             with a full interval left to the next one"
        );
        let (mainnet_pct, mainnet_left) =
            halving_progress(868_123, 210_000).expect("a real mainnet height");
        assert_eq!(mainnet_left, 181_877);
        assert!((mainnet_pct - 28_123.0 / 210_000.0).abs() < f32::EPSILON);
        // Network-aware interval: the same composer, a different (regtest)
        // interval, proves the site's `ChainId::subsidy_halving_interval()`
        // wiring is meaningful and not a dead parameter always fed 210_000.
        let (regtest_pct, regtest_left) =
            halving_progress(151, 150).expect("a regtest height");
        assert_eq!(regtest_left, 149);
        assert!((regtest_pct - 1.0 / 150.0).abs() < f32::EPSILON);
    }

    /// The network-aware interval selection itself: mainnet is the default
    /// for ordinary pool mining (Stratum jobs carry no chain id), and an
    /// active solo-mesh job's configured chain is consulted when the `lora`
    /// feature is built in. Both arms must still name the real halving
    /// intervals, not an invented constant.
    #[test]
    fn the_interval_selection_names_both_real_network_constants() {
        let src = lf(MAIN_RS);
        assert!(
            src.contains("ChainId::Mainnet"),
            "the default (no solo-mesh job) path must resolve to Mainnet"
        );
        assert!(
            src.contains("chain.subsidy_halving_interval()"),
            "the interval must come from ChainId's own network-aware method, \
             not a bare 210_000 duplicated into main.rs"
        );
    }
}

/// P1-O5 **critic held-out** (round 1). The lane's own guards refuse the three
/// fabricated sites by NAME — the literal `"uptime % 600"`, the local
/// `timeline_pct`, the strings `"BTC Timeline"` / `"^600EH/s"` — plus one
/// structural check that the single `draw_progress_bar` call sits inside
/// `if let Some((progress, _)) = halving`.
///
/// That is a hand-maintained needle list, and the critic falsified it: writing
/// the SAME lie with different arithmetic —
/// `let fake = (uptime as f32 % 600.0) / 600.0;` fed to the bar and to the
/// percent, *inside* the height gate so the structural check still passes —
/// left all 536 host tests GREEN while the panel again showed a wall-clock
/// progress bar under an honest title. The panel would be lying and the gate
/// would say it was not.
///
/// This module binds the property instead of the spelling: the carousel page
/// that draws the halving bar may not read the wall clock at all, and the value
/// it draws must be the identifier the composer's `Option` binds. It also pins
/// the on-glass label to 21 columns for every value the two REAL network
/// intervals can produce, reading the format string out of `main.rs` itself so
/// widening the label goes RED rather than silently clipping.
#[cfg(test)]
mod critic_p1_o5_the_halving_page_reads_no_wall_clock {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    /// Fresh Windows worktrees check out CRLF while git stores LF.
    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// The body of the carousel arm that owns the halving bar, delimited by the
    /// arm headers on either side of it. Both delimiters are asserted so a
    /// reshuffle of the carousel fails loudly instead of silently scoping this
    /// guard to nothing.
    fn halving_page_arm(src: &str) -> &str {
        const OPEN: &str = "\n            2 => {\n";
        const NEXT: &str = "\n            4 if ";
        let start = src
            .find(OPEN)
            .expect("carousel arm `2 => {` not found — the halving page moved");
        let end = src[start..]
            .find(NEXT)
            .map(|i| start + i)
            .expect("carousel arm `4 if …` not found — re-anchor this guard");
        let body = &src[start + OPEN.len()..end];
        assert!(
            body.len() > 400,
            "the extracted page-2 arm is implausibly short ({} bytes) — the \
             delimiters no longer bracket the real body",
            body.len()
        );
        body
    }

    /// The halving page draws a progress bar and a percentage. Neither may be
    /// derived from device uptime, in ANY spelling: the page must not mention
    /// the wall clock at all, and the drawn value must be the identifier the
    /// composer's `Option` destructures.
    #[test]
    fn the_halving_bar_and_percent_carry_no_uptime_in_any_spelling() {
        let src = lf(MAIN_RS);
        let arm = halving_page_arm(&src);

        assert!(
            !arm.contains("uptime"),
            "the halving carousel page reads `uptime`. A block/epoch progress \
             bar derived from device uptime is the exact fabrication P1-O5 \
             removed; the lane's literal-string guard only refuses the ONE \
             spelling `uptime % 600`, so this page is held wall-clock-free by \
             construction instead. Page body:\n{arm}"
        );

        // Exactly one bar, and its value is the composer-bound identifier.
        let bar_calls: Vec<&str> = arm.match_indices("draw_progress_bar(").map(|(i, _)| &arm[i..]).collect();
        assert_eq!(
            bar_calls.len(),
            1,
            "expected exactly one progress bar on the halving page"
        );
        let args = {
            let rest = &bar_calls[0]["draw_progress_bar(".len()..];
            let close = rest.find(')').expect("unterminated draw_progress_bar call");
            &rest[..close]
        };
        let value = args
            .rsplit(',')
            .next()
            .expect("draw_progress_bar takes arguments")
            .trim();
        let bound = format!("if let Some(({value}, _)) = halving");
        assert!(
            arm.contains(&bound),
            "the progress-bar value `{value}` is not the identifier bound by \
             the composer's Option (expected the page to contain `{bound}`). \
             A bar drawn from any other local can be a fabricated quantity \
             even while the enclosing `if let` gate is present."
        );
        // The percentage must render the same identifier, not a second source.
        assert!(
            arm.contains(&format!("{value} * 100.0")),
            "the on-glass percentage must be computed from the same \
             composer-bound value `{value}` as the bar"
        );
    }

    /// The label the page writes above the bar, taken from `main.rs` itself,
    /// must fit the panel's 21 columns for EVERY blocks-to-halving value the
    /// real `ChainId` intervals can produce (mainnet/testnet 210,000 and
    /// regtest 150 — the only values `subsidy_halving_interval()` returns), and
    /// so must the unknown-height placeholder.
    #[test]
    fn the_halving_label_fits_21_columns_for_every_real_interval() {
        const TEXT_COLUMNS: usize = 21;
        // The two intervals `ChainId::subsidy_halving_interval()` can return.
        const REAL_INTERVALS: [u32; 2] = [210_000, 150];

        let src = lf(MAIN_RS);
        let arm = halving_page_arm(&src);

        // Pull the two literals out of the page rather than restating them.
        let fmt_at = arm
            .find("format!(\"")
            .expect("the halving page must format its title");
        let fmt_rest = &arm[fmt_at + "format!(\"".len()..];
        let fmt = &fmt_rest[..fmt_rest.find('"').expect("unterminated format literal")];
        let (prefix, suffix) = fmt
            .split_once("{}")
            .expect("the halving title must interpolate the blocks-to-halving count");

        for interval in REAL_INTERVALS {
            // `halving_progress` returns `interval - (height % interval)`, so
            // blocks-to-halving ranges over 1..=interval. Sweep all of it.
            for blocks_left in 1..=interval {
                let line = format!("{prefix}{blocks_left}{suffix}");
                assert!(
                    line.chars().count() <= TEXT_COLUMNS,
                    "halving title {line:?} is {} columns on a {TEXT_COLUMNS}-column \
                     panel (interval {interval}, blocks left {blocks_left}) — it \
                     would be silently clipped by draw_text",
                    line.chars().count()
                );
            }
        }

        // The unknown-height placeholder is a bare literal on the same row.
        let placeholder_at = arm
            .find("\"HALVING")
            .expect("the unknown-height placeholder must stay a plain literal");
        let placeholder_rest = &arm[placeholder_at + 1..];
        let placeholder =
            &placeholder_rest[..placeholder_rest.find('"').expect("unterminated placeholder")];
        assert!(
            placeholder.chars().count() <= TEXT_COLUMNS,
            "the unknown-height placeholder {placeholder:?} is {} columns",
            placeholder.chars().count()
        );
    }
}

/// Lead guard at merge (blind critic P1-O5, finding 1 — "the H14 guards are a
/// needle list; the same lie re-spelled passes"). The critic's held-out pins the
/// halving page; this module closes the class for EVERY progress bar `main.rs`
/// draws now or later: the value a bar draws must be bound either by a composer
/// `if let Some((value, ..)) = …` or by a `let value = …;` whose expression never
/// mentions the wall clock (`uptime`). A bar fed from device uptime is exactly the
/// fabrication P1-O5 removed, whatever it is called.
mod p1_o5_lead_no_progress_bar_reads_the_wall_clock {
    const MAIN_RS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../dcentaxe/src/main.rs"));

    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// The identifier passed as the LAST argument of a `draw_progress_bar(` call.
    fn bar_value(call_tail: &str) -> &str {
        let close = call_tail.find(')').expect("unterminated draw_progress_bar call");
        call_tail[..close].rsplit(',').next().expect("draw_progress_bar takes arguments").trim()
    }

    /// The nearest binding of `value` above `at`: a composer destructure or a `let`.
    /// Returns the binding line (for the wall-clock check) and how it was bound.
    fn binding_line(src: &str, at: usize, value: &str) -> (String, &'static str) {
        let before = &src[..at];
        let some = format!("Some(({value},");
        let some_first = format!("Some(({value} ");
        let let_ = format!("let {value} ");
        let let_mut = format!("let mut {value} ");
        let candidates = [
            (before.rfind(&some), "composer"),
            (before.rfind(&some_first), "composer"),
            (before.rfind(&let_), "let"),
            (before.rfind(&let_mut), "let"),
        ];
        let (pos, kind) = candidates
            .iter()
            .filter_map(|(p, k)| p.map(|p| (p, *k)))
            .max_by_key(|(p, _)| *p)
            .unwrap_or_else(|| panic!("no binding found for progress-bar value `{value}`"));
        let line_start = before[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = src[pos..].find('\n').map(|i| pos + i).unwrap_or(src.len());
        (src[line_start..line_end].to_string(), kind)
    }

    #[test]
    fn every_progress_bar_value_is_bound_without_the_wall_clock() {
        let src = lf(MAIN_RS);
        let sites: Vec<usize> = src.match_indices("draw_progress_bar(").map(|(i, _)| i).collect();
        assert!(!sites.is_empty(), "main.rs draws no progress bar at all — re-anchor this guard");
        for at in sites {
            let value = bar_value(&src[at + "draw_progress_bar(".len()..]).to_string();
            assert!(
                !value.contains("uptime"),
                "a progress bar is fed directly from the wall clock: `{value}`"
            );
            let (line, kind) = binding_line(&src, at, &value);
            assert!(
                !line.contains("uptime"),
                "progress-bar value `{value}` is bound ({kind}) from the wall clock: {line:?}"
            );
            // Between the binding and the draw, the value must not be reassigned from uptime.
            let between = &src[..at];
            let bind_pos = between.rfind(line.trim_start()).unwrap_or(0);
            let span = &between[bind_pos..];
            assert!(
                !span.contains(&format!("{value} = ")) || !span.contains("uptime"),
                "progress-bar value `{value}` is reassigned from the wall clock before it is drawn"
            );
        }
    }

    /// The regtest-mesh ambiguity fix (finding 2): a regtest chain selects NO
    /// interval, so the height of a job whose chain is unknowable never feeds a bar.
    #[test]
    fn a_regtest_mesh_selects_no_halving_interval() {
        let src = lf(MAIN_RS);
        assert!(
            src.contains("if matches!(chain, ChainId::Regtest) {\n                None\n            }"),
            "the interval selection must map a Regtest mesh to `None`"
        );
        assert!(
            src.contains("halving_interval.and_then(|interval| halving_progress(block_height, interval))"),
            "the composer must be fed through the Option interval"
        );
        assert!(
            !src.contains("config.mesh.solo_chain"),
            "the chain must be read from the live `state.config`, not the boot snapshot (finding 3)"
        );
    }
}

/// ============================================================================
/// P1-I6 (DCENT_axe UI Gauntlet 2026-09-03) — the CLOSED gated-write check the
/// P1-O4-r1 critic asked for.
///
/// `EVIDENCE_LEDGER.md` `P1-O4-r1`, "Largest remaining gap": "the panel-absence
/// contract is asserted against a HAND-MAINTAINED needle list —
/// `pending_flash` slipped behind a gate in this very lane with the guard
/// green." `p1_o4_headless_carousel_guards`'s
/// `a_headless_board_keeps_every_achievement_and_persistence_side_effect`
/// above is exactly that needle list: it is only as good as the names someone
/// remembered to add to it. This module is the CLOSED complement: instead of
/// asking "is this NAMED tracker outside every gate", it asks "is EVERY
/// identifier a gate writes also DECLARED inside a gate", over every
/// identifier the file has, with no list to fall out of date.
///
/// **What it checks.** Over `lf(MAIN_RS)`: every
/// `#[cfg(feature = "display-ssd1306")]` span (the same statement-extent
/// finder `p1_o4_headless_carousel_guards` uses — copied here privately,
/// three small pure functions, per this lane's additive-only footprint rather
/// than importing across module internals); inside each span, every
/// assignment target (`ident = `, `ident += /-= /*= /\= /|= /&= /^= `,
/// `ident.push(` / `.insert(` / `.clear(` / `.pop(`) and, over the WHOLE
/// file, every `let`/`let mut` declaration. For every identifier assigned
/// inside a gated span, its nearest PRECEDING declaration in the file must
/// ALSO be inside a (possibly different) gated span — or be that identifier's
/// own `let` inside the very span it is assigned in. A violation — an
/// identifier declared outside every gate but written inside one — fails the
/// test naming the identifier, the byte offset, and the `main.rs` line, per
/// the brief: a real hit is a FINDING to report, not something to allowlist
/// quiet.
///
/// **The allowlist is EMPTY.** On the base tree the scan sees 17
/// gated-write sites; every one resolves to a declaration that is ALSO
/// gated, so `VIOLATIONS` (below) stays empty and the test passes on real
/// content, not on a vacuous scan (`the_scan_still_finds_the_expected_number_
/// of_gated_write_sites` pins the count so a parser regression that silently
/// stops matching cannot look identical to "no violations"). The full
/// identifier-by-identifier list this scan produces on the base tree —
/// including the ones it correctly declines to flag and why — is
/// reproduced by `cargo test … -- --nocapture` and logged verbatim in this
/// lane's `scan-findings.md`.
///
/// **What it deliberately does NOT flag** (each exclusion is exercised by
/// `false_positive_exclusions_do_not_trip_the_scanner` below against a
/// synthetic snippet, not merely asserted against the one real base tree):
/// - A field/method target preceded by `.` (`display.x = ...`,
///   `telem.chip_data.clear()`, `telem.creature_mood = mood_now;`) — the
///   RECEIVER, not a bare local, is what would need checking, and this
///   scanner does no struct-layout analysis. A struct field slipping behind
///   a gate is invisible to it; it only ever covers bare local identifiers.
/// - A type ascription (`let x: u8 = 0;`) — the token immediately before the
///   `=`, skipping only horizontal whitespace, is `:`, which never
///   legitimately precedes a real assignment target. Without this exclusion
///   the scanner flagged its own type names (`u8`, `u64`, `usize`, `f64`,
///   `bool`, `u32`, `String`) as "assigned" identifiers on the base tree.
/// - The `_` discard pattern (`_ = expr;`) — never binds a name.
/// - A match-arm `=>` — the character after `=` is checked for both `=`
///   (comparison) and `>` (arrow). Dropping the `>` half of that check
///   false-fired on `4 if autotuner_enabled => {` (`main.rs:6938`) while this
///   lane was being built; kept here as a named exclusion rather than a
///   silent fix so a future editor does not "simplify" it back.
/// - `display.clear(...)` / a future `display.push_...(...)` — `display` is
///   the one shared hardware handle whose method surface exists, by
///   construction, identically in both the `display-ssd1306` and
///   `display-none` builds (the whole reason `oled_notify!` exists,
///   `main.rs:736-770`); calling one of its methods from inside a gate costs
///   nothing on headless and is not a scalar state tracker. This is a named,
///   single-identifier exclusion (`KNOWN_HANDLES`), not a general allowlist —
///   a second handle with the same shape needs the same explicit, documented
///   treatment, not a silent addition here.
/// - A shadowing `let` INSIDE the span itself — "nearest preceding
///   declaration" naturally resolves to that inner `let`, which is exactly
///   "the span's own let" the brief asks to accept, without needing a special
///   case.
///
/// **What the scanner genuinely cannot see** (documented, not silently
/// patched over): full lexical scoping. "Nearest preceding `let` by byte
/// offset" is a linear-scan heuristic, not a parser — a shadowing `let`
/// inside a block that has already CLOSED before the assignment site would
/// still be picked as the governing declaration if no closer one exists.
/// `main.rs`'s mining loop is one long, mostly-flat function body with almost
/// no re-shadowing of these tracker names, so this has not produced a wrong
/// answer on the real file (every site the scan sees is listed in
/// `scan-findings.md`), but it is a real limitation of a textual check over a
/// file `dcentaxe-core` can never host-parse (`main.rs` is
/// `target_os = "espidf"`-only). It also cannot see a mutation reached only
/// through a function call (`some_local_setter(&mut x)`), only a textual
/// `=`/`OP=`/`.push(`-shaped site. After the merge fix the mutating-method
/// list is nine long (`.push( .push_str( .insert( .clear( .pop( .retain(
/// .extend( .truncate( .swap(`) and a newline between an identifier and its
/// `=` no longer hides the assignment; what stays unseen is a mutation through
/// a method NOT on that list, a field target (`x.y = `), a `&mut` handed to a
/// function, and full lexical scoping. The list is a documented enumeration,
/// not a claim of completeness: the closed check is a tripwire for the shapes
/// this codebase actually writes, and the critic-authored held-out
/// `critic_p1_i6_unscanned_mutation_shapes` is what pins the class.
#[cfg(test)]
mod p1_i6_closed_gated_write_guards {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    const GATE: &str = "#[cfg(feature = \"display-ssd1306\")]";

    /// `core.autocrlf = true` gives fresh Windows worktrees CRLF working
    /// copies while git stores LF. Every read here is normalised first.
    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    fn indent_of(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    // ------------------------------------------------------------------
    // Copied privately from `p1_o4_headless_carousel_guards` above (this
    // lane's footprint is one additive EOF module; duplicating three small
    // pure functions keeps this module independent of that one's internals
    // rather than reaching into a `#[cfg(test)]` sibling module).
    // ------------------------------------------------------------------

    /// Byte ranges of every statement/item introduced by a
    /// `#[cfg(feature = "display-ssd1306")]` attribute. See the identical
    /// function in `p1_o4_headless_carousel_guards` for the extent-finding
    /// rule; `the_gate_scanner_still_finds_the_expected_span_count` below
    /// re-proves this copy really brackets the carousel on the current file.
    fn display_gated_spans(src: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut offsets = Vec::new();
        let mut at = 0usize;
        for line in src.split_inclusive('\n') {
            offsets.push((at, line));
            at += line.len();
        }
        for (i, (_, line)) in offsets.iter().enumerate() {
            if line.trim() != GATE {
                continue;
            }
            let n = indent_of(line);
            let mut j = i + 1;
            if j >= offsets.len() {
                break;
            }
            let start = offsets[j].0;
            let mut end = offsets[j].0 + offsets[j].1.len();
            j += 1;
            while j < offsets.len() {
                let (off, l) = offsets[j];
                let t = l.trim_start();
                let cont = t.is_empty()
                    || indent_of(l) > n
                    || (indent_of(l) == n
                        && (t.starts_with('}')
                            || t.starts_with(']')
                            || t.starts_with(')')
                            || t.starts_with('{')
                            || t.starts_with("else")));
                if !cont {
                    break;
                }
                end = off + l.len();
                j += 1;
            }
            spans.push((start, end));
        }
        spans
    }

    fn is_gated(spans: &[(usize, usize)], at: usize) -> bool {
        spans.iter().any(|&(s, e)| at >= s && at < e)
    }

    fn offsets_of(src: &str, needle: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = src[at..].find(needle) {
            out.push(at + rel);
            at += rel + needle.len();
        }
        out
    }

    // ------------------------------------------------------------------
    // This lane's own scanner.
    // ------------------------------------------------------------------

    fn is_ident_start(c: u8) -> bool {
        c == b'_' || c.is_ascii_alphabetic()
    }
    fn is_ident_char(c: u8) -> bool {
        c == b'_' || c.is_ascii_alphanumeric()
    }

    /// Marks every byte inside a string literal, a char literal, or a `//`
    /// line comment as `false` ("not code"), so the assignment/declaration
    /// scan can never match text inside a `format!("... = ...")` template or
    /// a comment. `main.rs`'s banner dividers and doc comments are all `//`
    /// line comments; the file uses no `/* */` block comments in the scanned
    /// region, so those are not handled here — a limitation, not a silent
    /// gap: if one is ever introduced, its contents would be scanned as real
    /// code rather than skipped.
    fn code_mask(src: &str) -> Vec<bool> {
        let b = src.as_bytes();
        let mut mask = vec![true; b.len()];
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'"' => {
                    let start = i;
                    i += 1;
                    while i < b.len() {
                        if b[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if b[i] == b'"' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    for m in mask.iter_mut().take(i.min(b.len())).skip(start) {
                        *m = false;
                    }
                }
                b'\'' => {
                    // Distinguish a char literal (`'a'`, `'\\'`, `'\''`) from
                    // a lifetime (`'static`, `'a`, `'de`): a char literal
                    // closes with a second `'` within 1-2 bytes; a lifetime
                    // does not.
                    let start = i;
                    let mut j = i + 1;
                    if j < b.len() && b[j] == b'\\' {
                        j += 2;
                    } else if j < b.len() {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'\'' {
                        j += 1;
                        for m in mask.iter_mut().take(j).skip(start) {
                            *m = false;
                        }
                        i = j;
                        continue;
                    }
                    i += 1;
                }
                b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                    let start = i;
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                    for m in mask.iter_mut().take(i).skip(start) {
                        *m = false;
                    }
                }
                _ => i += 1,
            }
        }
        mask
    }

    #[derive(Clone, Debug)]
    struct Decl {
        ident: String,
        offset: usize,
    }

    /// Every `let`/`let mut IDENT` binding in `src`, in file order. Only a
    /// simple identifier binding is recognised — a destructuring pattern
    /// (`let (a, b) = ..`, `let Foo { x, .. } = ..`) is not a shape any of
    /// the tracked carousel state uses and is skipped rather than
    /// misparsed.
    fn let_declarations(src: &str, mask: &[bool]) -> Vec<Decl> {
        let b = src.as_bytes();
        let n = b.len();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < n {
            let Some(rel) = src[i..].find("let ") else {
                break;
            };
            let idx = i + rel;
            if idx >= mask.len() || !mask[idx] {
                i = idx + 1;
                continue;
            }
            if idx > 0 && is_ident_char(b[idx - 1]) {
                i = idx + 1;
                continue;
            }
            let mut j = idx + 4;
            while j < n && (b[j] == b' ' || b[j] == b'\t') {
                j += 1;
            }
            if src[j..].starts_with("mut ") || src[j..].starts_with("mut\t") {
                j += 3;
                while j < n && (b[j] == b' ' || b[j] == b'\t') {
                    j += 1;
                }
            }
            if j < n && is_ident_start(b[j]) {
                let start = j;
                let mut k = j;
                while k < n && is_ident_char(b[k]) {
                    k += 1;
                }
                out.push(Decl {
                    ident: src[start..k].to_string(),
                    offset: start,
                });
            }
            i = idx + 1;
        }
        out
    }

    const BARE_OPS: [&str; 7] = ["+=", "-=", "*=", "/=", "|=", "&=", "^="];
    /// Lead fix at merge (blind critic P1-I6, must-fix 2): round 1 listed four
    /// methods and silently missed five more of the same shape — the critic put
    /// `.push_str(` into a gated span and all six lane tests stayed green. The
    /// sharpest case is `.push_str(`, which LOOKS covered because it starts with
    /// `.push` but `starts_with(".push(")` is false for it.
    const MUTATING_METHODS: [&str; 9] = [
        ".push(",
        ".push_str(",
        ".insert(",
        ".clear(",
        ".pop(",
        ".retain(",
        ".extend(",
        ".truncate(",
        ".swap(",
    ];

    /// A shared hardware handle whose method surface is, by construction,
    /// identical in both build variants (see the module doc comment above) —
    /// not a per-board scalar state tracker. Named and singular on purpose:
    /// a second handle with the same shape must be added here explicitly and
    /// documented, never inferred.
    const KNOWN_HANDLES: [&str; 1] = ["display"];

    #[derive(Clone, Debug)]
    struct Assignment {
        ident: String,
        offset: usize,
        kind: &'static str,
    }

    /// Every assignment-like site in `src`: a bare `ident = ` / `ident OP= `
    /// / `ident.push(...)`-shaped mutation. Excludes a `let` declaration's
    /// own initializer, a type ascription, the `_` discard, a match arm's
    /// `=>`, and the `KNOWN_HANDLES` exclusion — see the module doc comment
    /// for why each of those is not a real write this check cares about.
    fn assignment_sites(src: &str, mask: &[bool], decls: &[Decl]) -> Vec<Assignment> {
        let decl_offsets: std::collections::HashSet<usize> =
            decls.iter().map(|d| d.offset).collect();
        let b = src.as_bytes();
        let n = b.len();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < n {
            if !mask[i] || !is_ident_start(b[i]) || (i > 0 && is_ident_char(b[i - 1])) {
                i += 1;
                continue;
            }
            let start = i;
            let mut k = i;
            while k < n && is_ident_char(b[k]) {
                k += 1;
            }
            let ident = &src[start..k];

            let preceded_by_dot = start > 0 && b[start - 1] == b'.';
            let mut p = start;
            while p > 0 && (b[p - 1] == b' ' || b[p - 1] == b'\t') {
                p -= 1;
            }
            let preceded_by_colon = p > 0 && b[p - 1] == b':';
            let is_underscore = ident == "_";
            let is_decl_site = decl_offsets.contains(&start);
            let is_known_handle = KNOWN_HANDLES.contains(&ident);

            // Lead fix at merge (critic must-fix 2): an assignment whose `=` wraps
            // to the next line was invisible to round 1, which skipped only spaces
            // and tabs. Newlines are skipped too; an attribute line is not code and
            // is stepped over entirely (it also removes the `#[cfg(feature = "…")]`
            // false positive the critic recorded as a LOW).
            let mut m = k;
            while m < n && (b[m] == b' ' || b[m] == b'\t' || b[m] == b'\n' || b[m] == b'\r') {
                m += 1;
            }
            let mut kind: Option<&'static str> = None;
            if !preceded_by_dot && !preceded_by_colon && !is_decl_site && !is_underscore {
                if m < n && b[m] == b'=' {
                    let nxt = if m + 1 < n { b[m + 1] } else { 0 };
                    if nxt != b'=' && nxt != b'>' {
                        kind = Some("=");
                    }
                }
                if kind.is_none() {
                    for op in BARE_OPS {
                        if src[m..].starts_with(op) {
                            kind = Some(op);
                            break;
                        }
                    }
                }
            }
            if !preceded_by_dot && !is_underscore && !is_known_handle {
                for meth in MUTATING_METHODS {
                    if src[k..].starts_with(meth) {
                        kind = Some(meth);
                        break;
                    }
                }
            }
            if let Some(kind) = kind {
                out.push(Assignment {
                    ident: ident.to_string(),
                    offset: start,
                    kind,
                });
            }
            i = k;
        }
        out
    }

    fn nearest_decl(decls: &[Decl], ident: &str, before: usize) -> Option<usize> {
        decls
            .iter()
            .filter(|d| d.ident == ident && d.offset < before)
            .map(|d| d.offset)
            .max()
    }

    #[derive(Debug)]
    struct ScanRow {
        ident: String,
        offset: usize,
        kind: &'static str,
        decl_offset: Option<usize>,
        decl_gated: Option<bool>,
    }

    /// Runs the full closed check over `src`: one row per assignment found
    /// inside a gated span, in file order, with its resolved declaration
    /// (if any) and whether that declaration is itself gated.
    fn scan(src: &str) -> Vec<ScanRow> {
        let spans = display_gated_spans(src);
        let mask = code_mask(src);
        let decls = let_declarations(src, &mask);
        let sites = assignment_sites(src, &mask, &decls);
        sites
            .into_iter()
            .filter(|a| is_gated(&spans, a.offset))
            .map(|a| {
                let decl_offset = nearest_decl(&decls, &a.ident, a.offset);
                let decl_gated = decl_offset.map(|d| is_gated(&spans, d));
                ScanRow {
                    ident: a.ident,
                    offset: a.offset,
                    kind: a.kind,
                    decl_offset,
                    decl_gated,
                }
            })
            .collect()
    }

    fn line_of(src: &str, offset: usize) -> usize {
        src[..offset].matches('\n').count() + 1
    }

    /// The scan is only worth what it can be shown to bracket: re-proves this
    /// module's private copy of `display_gated_spans` still finds a
    /// realistic number of gated spans on the current file, so a parser
    /// drift here fails loudly instead of silently emptying `scan()`.
    #[test]
    fn the_gate_scanner_still_finds_the_expected_span_count() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);
        assert!(
            spans.len() >= 30,
            "the display gate all but vanished from main.rs ({} spans) — this \
             module's private copy of the extent-finder may have drifted from \
             the file's shape",
            spans.len()
        );
    }

    #[test]
    fn every_identifier_written_inside_a_display_gate_is_declared_inside_one() {
        let src = lf(MAIN_RS);
        let rows = scan(&src);
        assert!(
            rows.len() >= 15,
            "the scanner found only {} gated-write sites; it may have stopped \
             matching the carousel's shape (17 were found when this module was \
             written — see scan-findings.md)",
            rows.len()
        );

        eprintln!("P1-I6 closed gated-write scan — {} site(s)", rows.len());
        let mut violations: Vec<String> = Vec::new();
        for row in &rows {
            let line = line_of(&src, row.offset);
            match (row.decl_offset, row.decl_gated) {
                (Some(decl_off), Some(true)) => {
                    let decl_line = line_of(&src, decl_off);
                    eprintln!(
                        "  {} @byte {} (main.rs:{}, `{}`) — declared @byte {} (main.rs:{}), \
                         GATED — ok",
                        row.ident, row.offset, line, row.kind, decl_off, decl_line
                    );
                }
                (Some(decl_off), Some(false)) => {
                    let decl_line = line_of(&src, decl_off);
                    eprintln!(
                        "  {} @byte {} (main.rs:{}, `{}`) — declared @byte {} (main.rs:{}), \
                         UNGATED — VIOLATION",
                        row.ident, row.offset, line, row.kind, decl_off, decl_line
                    );
                    violations.push(format!(
                        "`{}` written at byte {} (main.rs:{}) inside a display-ssd1306 span, \
                         but its declaration at byte {} (main.rs:{}) sits outside every gate",
                        row.ident, row.offset, line, decl_off, decl_line
                    ));
                }
                _ => {
                    eprintln!(
                        "  {} @byte {} (main.rs:{}, `{}`) — no let-declaration found in the \
                         file; scanner miss, not asserted",
                        row.ident, row.offset, line, row.kind
                    );
                }
            }
        }
        assert!(
            violations.is_empty(),
            "closed gated-write check found {} violation(s) — a real ungated identifier is \
             assigned inside a display-ssd1306 span:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }

    /// Self-test (brief-required): inject a gated write of `prev_accepted` —
    /// a tracker that stays ungated BY CONTRACT (`main.rs:746-753`) — into an
    /// in-memory copy of the source, and prove the scan above goes RED on
    /// it. No file on disk is touched here; the manual byte-copy mutation
    /// check against the real `main.rs` is recorded separately in this
    /// lane's `mutation-check.log`.
    #[test]
    fn the_scanner_catches_an_injected_ungated_tracker_written_inside_a_gate() {
        let src = lf(MAIN_RS);
        const ANCHOR: &str = "let mut pending_flash: u8 = 0; // non-blocking flash state machine (decrements each tick)\n";
        let at = src
            .find(ANCHOR)
            .expect("the pending_flash declaration must stay locatable for this self-test");
        let line_start = src[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let indent = &src[line_start..at];
        let insertion = format!(
            "{indent}#[cfg(feature = \"display-ssd1306\")]\n{indent}prev_accepted = 0; // P1-I6 self-test injection\n"
        );
        let insert_at = at + ANCHOR.len();
        let mut mutated = String::with_capacity(src.len() + insertion.len());
        mutated.push_str(&src[..insert_at]);
        mutated.push_str(&insertion);
        mutated.push_str(&src[insert_at..]);

        let rows = scan(&mutated);
        let hit = rows
            .iter()
            .find(|r| r.ident == "prev_accepted" && r.decl_gated == Some(false));
        assert!(
            hit.is_some(),
            "injecting a gated write of the ungated-by-contract `prev_accepted` tracker did \
             not turn the scan red; the checker is not doing the job this lane exists for"
        );
    }

    /// Every exclusion documented in the module doc comment, proven against
    /// a small synthetic snippet rather than merely asserted by the base
    /// tree happening to pass. Each snippet embeds its own gate so `scan()`
    /// runs unmodified.
    #[test]
    fn false_positive_exclusions_do_not_trip_the_scanner() {
        let cases: [(&str, &str); 6] = [
            (
                "struct field assignment on the display object",
                "#[cfg(feature = \"display-ssd1306\")]\ndisplay.some_field = 1;\n",
            ),
            (
                "mutating method call on the display handle",
                "#[cfg(feature = \"display-ssd1306\")]\ndisplay.push(1);\n",
            ),
            (
                "field assignment on an unrelated struct (telem)",
                "#[cfg(feature = \"display-ssd1306\")]\ntelem.creature_mood = mood_now;\n",
            ),
            (
                "type ascription in a gated let",
                "#[cfg(feature = \"display-ssd1306\")]\nlet mut x: u8 = 0;\n",
            ),
            (
                "the `_` discard pattern",
                "#[cfg(feature = \"display-ssd1306\")]\n_ = something();\n",
            ),
            (
                "a match arm's `=>`, not an assignment",
                "#[cfg(feature = \"display-ssd1306\")]\nmatch n { autotuner_enabled => {} }\n",
            ),
        ];
        for (label, snippet) in cases {
            let rows = scan(snippet);
            assert!(
                rows.is_empty(),
                "{label} falsely tripped the scanner: {rows:?}"
            );
        }
    }

    /// The complementary positive case: a shadowing `let` INSIDE the gated
    /// span it is later assigned in must resolve to itself and never be
    /// reported, even though a same-named identifier is also declared
    /// (ungated) earlier in the same snippet.
    #[test]
    fn a_let_that_shadows_inside_the_span_resolves_to_its_own_declaration() {
        let snippet = "let z: u8 = 1;\n#[cfg(feature = \"display-ssd1306\")]\n{\n    let mut z: u8 = 2;\n    z += 1;\n}\n";
        let rows = scan(snippet);
        assert_eq!(
            rows.len(),
            1,
            "expected exactly one gated-write site (the inner `z += 1`): {rows:?}"
        );
        assert_eq!(rows[0].ident, "z");
        assert_eq!(
            rows[0].decl_gated,
            Some(true),
            "the shadowing `let mut z` inside the span must be the resolved declaration, not \
             the outer ungated one: {rows:?}"
        );
    }

    /// The negative case this whole module exists for, proven directly
    /// against the corpus in addition to the injected self-test above: an
    /// identifier declared OUTSIDE every gate (`prev_accepted`,
    /// `prev_streak`, `prev_block_height`, `share_flash_tick`,
    /// `achievement_flash_tick` — the contract's own ungated-by-design list,
    /// `main.rs:746-753`) has NO assignment site inside any gated span on
    /// the base tree. If one of these five is ever moved behind a gate, the
    /// contract comment and this assertion both need to change together —
    /// not just the code.
    #[test]
    fn the_five_contractually_ungated_trackers_have_no_gated_write_today() {
        let src = lf(MAIN_RS);
        let rows = scan(&src);
        for tracker in [
            "prev_accepted",
            "prev_streak",
            "prev_block_height",
            "share_flash_tick",
            "achievement_flash_tick",
        ] {
            assert!(
                !rows.iter().any(|r| r.ident == tracker),
                "{tracker:?} is written inside a display-ssd1306 span today. The contract \
                 comment at main.rs:746-753 says it stays ungated by design; either the \
                 contract or this assertion is now wrong, and it must be a reviewed decision"
            );
        }
    }
}

/// ============================================================================
/// CRITIC HELD-OUT (P1-I6 round 1, blind critic) — the mutation shapes the
/// closed gated-write check above cannot see.
///
/// `p1_i6_closed_gated_write_guards` recognises a write only as `ident = `,
/// `ident OP= `, or one of four mutating methods (`.push(` `.insert(`
/// `.clear(` `.pop(`). This critic measured its behaviour against adversarial
/// snippets and confirmed that each of the following goes through it UNSEEN —
/// `scan()` returns zero rows, so a gated write to an ungated tracker in any
/// of these shapes passes the closed check silently:
///
/// - `.retain(` `.extend(` `.truncate(` `.swap(` `.push_str(` `.drain(`
///   `.remove(` `.append(` `.resize(` `.insert_str(` `.swap_remove(`
///   `.retain_mut(` `.dedup(` `.reverse(` `.rotate_left(` `.rotate_right(`
///   `.fill(` `.clone_from(` `.split_off(` — every one of these mutates its
///   receiver exactly as `.push(` does, and `.push_str(` is the sharpest case
///   because it LOOKS covered (`starts_with(".push(")` is false for it).
/// - an assignment whose `=` is wrapped onto the next source line
///   (`ident\n    = value;`) — the scanner skips only spaces and tabs when
///   looking for the operator, so a rustfmt line break hides the write.
///
/// The opposite failure is a `/* */` block comment inside a gated span: the
/// scanner's `code_mask` masks `//` line comments only, so `/* tick = 1; */`
/// inside a span is reported as a REAL gated write. That direction fails
/// loudly rather than silently, but it is still a wrong answer.
///
/// A textual check cannot adjudicate these shapes, so this guard FORBIDS them
/// inside a `display-ssd1306` span instead. It is green on the current tree
/// (0 hits of all three kinds, measured) and goes red the moment one appears —
/// which routes the author to the closed check's owner rather than letting the
/// write past. Removing this module without extending
/// `p1_i6_closed_gated_write_guards::MUTATING_METHODS` re-opens the hole.
#[cfg(test)]
mod critic_p1_i6_unscanned_mutation_shapes {
    const MAIN_RS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentaxe/src/main.rs"
    ));

    const GATE: &str = "#[cfg(feature = \"display-ssd1306\")]";

    /// Mutating receivers that the closed check's four-method list misses.
    /// Every one of these takes `&mut self` in std.
    const UNSCANNED_MUTATORS: [&str; 19] = [
        ".retain(",
        ".retain_mut(",
        ".extend(",
        ".truncate(",
        ".swap(",
        ".swap_remove(",
        ".push_str(",
        ".insert_str(",
        ".drain(",
        ".remove(",
        ".append(",
        ".resize(",
        ".dedup(",
        ".reverse(",
        ".rotate_left(",
        ".rotate_right(",
        ".fill(",
        ".clone_from(",
        ".split_off(",
    ];

    fn lf(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    fn indent_of(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    /// Same extent rule as the closed check's own span finder (copied, since
    /// that module's helpers are private to it): the attribute applies to the
    /// following statement/item, whose extent runs while the indent is
    /// greater, or equal and the line opens/closes a block.
    fn display_gated_spans(src: &str) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut offsets = Vec::new();
        let mut at = 0usize;
        for line in src.split_inclusive('\n') {
            offsets.push((at, line));
            at += line.len();
        }
        for (i, (_, line)) in offsets.iter().enumerate() {
            if line.trim() != GATE {
                continue;
            }
            let n = indent_of(line);
            let mut j = i + 1;
            if j >= offsets.len() {
                break;
            }
            let start = offsets[j].0;
            let mut end = offsets[j].0 + offsets[j].1.len();
            j += 1;
            while j < offsets.len() {
                let (off, l) = offsets[j];
                let t = l.trim_start();
                let cont = t.is_empty()
                    || indent_of(l) > n
                    || (indent_of(l) == n
                        && (t.starts_with('}')
                            || t.starts_with(']')
                            || t.starts_with(')')
                            || t.starts_with('{')
                            || t.starts_with("else")));
                if !cont {
                    break;
                }
                end = off + l.len();
                j += 1;
            }
            spans.push((start, end));
        }
        spans
    }

    /// `false` for every byte inside a string literal, a char literal or a
    /// `//` comment, so a mutator named in a doc comment or a format string
    /// is not mistaken for code.
    fn code_mask(src: &str) -> Vec<bool> {
        let b = src.as_bytes();
        let mut mask = vec![true; b.len()];
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'"' => {
                    let start = i;
                    i += 1;
                    while i < b.len() {
                        if b[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if b[i] == b'"' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    for m in mask.iter_mut().take(i.min(b.len())).skip(start) {
                        *m = false;
                    }
                }
                b'\'' => {
                    let start = i;
                    let mut j = i + 1;
                    if j < b.len() && b[j] == b'\\' {
                        j += 2;
                    } else if j < b.len() {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'\'' {
                        j += 1;
                        for m in mask.iter_mut().take(j).skip(start) {
                            *m = false;
                        }
                        i = j;
                        continue;
                    }
                    i += 1;
                }
                b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                    let start = i;
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                    for m in mask.iter_mut().take(i).skip(start) {
                        *m = false;
                    }
                }
                _ => i += 1,
            }
        }
        mask
    }

    fn is_gated(spans: &[(usize, usize)], at: usize) -> bool {
        spans.iter().any(|&(s, e)| at >= s && at < e)
    }

    fn line_of(src: &str, offset: usize) -> usize {
        src[..offset].matches('\n').count() + 1
    }

    #[test]
    fn no_display_gated_span_mutates_through_a_shape_the_closed_check_cannot_see() {
        let src = lf(MAIN_RS);
        let spans = display_gated_spans(&src);
        assert!(
            spans.len() >= 30,
            "the display gate all but vanished ({} spans); this guard would be vacuous",
            spans.len()
        );
        let mask = code_mask(&src);
        let mut findings: Vec<String> = Vec::new();

        // 1. mutating receivers outside the closed check's four-method list
        for meth in UNSCANNED_MUTATORS {
            let mut at = 0usize;
            while let Some(rel) = src[at..].find(meth) {
                let off = at + rel;
                at = off + meth.len();
                if !mask[off] || !is_gated(&spans, off) {
                    continue;
                }
                findings.push(format!(
                    "`{}` inside a display-ssd1306 span at main.rs:{} — the closed check's \
                     MUTATING_METHODS list does not contain it, so a gated mutation of an \
                     ungated tracker through it would pass silently",
                    meth,
                    line_of(&src, off)
                ));
            }
        }

        // 2. an assignment operator wrapped onto its own line: the closed
        //    check skips only spaces/tabs between the identifier and the `=`.
        let mut at = 0usize;
        for line in src.split_inclusive('\n') {
            let off = at;
            at += line.len();
            let t = line.trim_start();
            let wrapped = t.starts_with("+=")
                || t.starts_with("-=")
                || t.starts_with("*=")
                || t.starts_with("/=")
                || t.starts_with("|=")
                || t.starts_with("&=")
                || t.starts_with("^=")
                || (t.starts_with('=') && !t.starts_with("==") && !t.starts_with("=>"));
            if !wrapped {
                continue;
            }
            let tok = off + indent_of(line);
            if !mask[tok] || !is_gated(&spans, tok) {
                continue;
            }
            findings.push(format!(
                "an assignment operator starts main.rs:{} — with the `=` on its own line the \
                 closed check cannot see the write",
                line_of(&src, tok)
            ));
        }

        // 3. a `/* */` block comment inside a span: the closed check's mask
        //    handles `//` only, so text inside one is scanned as real code.
        let mut at = 0usize;
        while let Some(rel) = src[at..].find("/*") {
            let off = at + rel;
            at = off + 2;
            if !mask[off] || !is_gated(&spans, off) {
                continue;
            }
            findings.push(format!(
                "a `/* */` block comment opens inside a display-ssd1306 span at main.rs:{} — \
                 the closed check's code mask handles `//` only and would scan its contents \
                 as real code",
                line_of(&src, off)
            ));
        }

        assert!(
            findings.is_empty(),
            "{} mutation shape(s) the closed gated-write check cannot adjudicate now appear \
             inside a display-ssd1306 span. Either move the mutation out of the gate, or \
             extend `p1_i6_closed_gated_write_guards` to cover the shape and update this \
             guard in the same change:\n{}",
            findings.len(),
            findings.join("\n")
        );
    }
}
