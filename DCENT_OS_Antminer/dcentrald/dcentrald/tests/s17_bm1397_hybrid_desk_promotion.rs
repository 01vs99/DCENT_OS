//! S17-family (BM1397) hybrid desk-promotion contract.
//!
//! Campaign `2026-08-27-antminer17-unlock-armada`, agent B1 (2026-08-27).
//! DESK-ONLY promotion: this pins the registry/admission/recipe surfaces that
//! replace the management-only wall for `am2-s17p`, `am2-s17plus`, `am2-t17`,
//! `am2-t17plus`. LIVE bring-up (first energized S17 under DCENT_OS) is the
//! bench milestone and is NOT claimed here — see
//!
//! for the live-bring-up risk list.
//!
//! ## What this test pins
//!
//! 1. BoardDesc snapshot: exact facet tuples for the four promoted targets
//!    (work engine, controller class per the stock-RE adjudication, supervisor
//!    lane, no install / no auto-mine).
//! 2. Geometry: 3×48 / 3×65 / 3×30 / 3×44 with `floor(256/N)` strides — 44,
//!    not 45, for T17+ (stock `07702_pattern_44.txt`, A1 §V2).
//! 3. The canonical MiscCtrl / baud / FastUART constants agree with the
//!    silicon-profiles SSOT.
//! 4. Source contracts over the new engine module: EEPROM 0x50–0x57
//!    write-deny reference at the wire boundary, no BIP320 reconstruction,
//!    no PSU-watchdog (0x84) executor, unconditional native degraded-firmware
//!    refusal, and energize admission BEFORE the watchdog is armed.
//! 5. Launcher honesty with the am2-s17pro init script: exact-token S17
//!    selector (B2 landed 2026-08-27), `--s17-hybrid` appended only, and no
//!    image ever exports a `DCENT_AM2_S17_*` knob (contract below).
//!
//! ## B2 launcher contract (do not weaken) — LANDED
//!
//! The selector is an exact-target case (never an `am2-*` prefix —
//! ADR-0013 §6):
//!
//! ```sh
//! am2-s17p|am2-s17pro) IS_S17_HYBRID_TARGET=1 ;;
//! am2-s17plus|am2-t17|am2-t17plus) IS_S17_HYBRID_TARGET=1 ;;
//! ```
//!
//! and the S17 arm appends `--s17-hybrid` plus (initially) ONLY:
//! `DCENT_AM2_S17_SKIP_PER_CHIP_INIT` unset, `DCENT_AM2_S17_SERIAL_WORK_DISPATCH`
//! unset, `DCENT_AM2_S17_FAST_UART_PLL3` unset, `DCENT_AM2_S17_TRUST_DEGRADED_FW`
//! unset, `DCENT_AM2_S17_ALLOW_ENERGIZE` unset (the bench gate is set by hand on
//! the bench unit, NEVER by an image). The non-S17 arms must add the
//! `DCENT_AM2_S17_*` names to their unset hygiene.

use dcentrald_common::{
    AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind, SlotPolicy,
    VoltageControllerClass, WorkEngineKind,
};
use dcentrald_silicon_profiles::bm1397::{
    BM1397_CHIP_ID_REPLY, BM1397_CORES_PER_CHIP, BM1397_FAST_UART_REG28, BM1397_FAST_UART_REG68,
    BM1397_MISCCTRL_BAUD_VALUE, BM1397_OPERATIONAL_BAUD,
};

const S17_MINING_RS: &str = include_str!("../src/s17_hybrid_mining.rs");
const S17_WIRE_RS: &str = include_str!("../src/s17_wire.rs");
const S17_NATIVE_RS: &str = include_str!("../src/s17_native_runtime.rs");
const S17_ADMISSION_RS: &str = include_str!("../src/s17_hybrid_admission.rs");
const MAIN_RS: &str = include_str!("../src/main.rs");
const S17_LAUNCHER: &str = include_str!(
    "../../../br2_external_dcentos/board/zynq/am2-s17pro/rootfs-overlay/etc/init.d/S82dcentrald"
);

fn snapshot(target: &str) -> BoardDesc {
    BoardDesc::lookup(target)
        .unwrap_or_else(|| panic!("{target} must be registered"))
        .clone()
}

fn production_source(source: &str) -> &str {
    // A cfg(test) import precedes the engine body. Only the actual test
    // module ends production; this delimiter also accepts CRLF checkouts.
    source
        .split_once("\nmod tests {")
        .expect("production source must precede its test module")
        .0
}

#[test]
fn s17_board_desc_snapshot_pins_the_promoted_facet_tuples() {
    for (target, controller) in [
        ("am2-s17p", VoltageControllerClass::DsPic33Ep),
        ("am2-t17", VoltageControllerClass::DsPic33Ep),
        ("am2-s17plus", VoltageControllerClass::Pic16F1704),
        ("am2-t17plus", VoltageControllerClass::Pic16F1704),
    ] {
        let d = snapshot(target);
        assert_eq!(d.family, BoardFamily::Zynq, "{target}");
        assert_eq!(d.chain_transport, ChainTransportKind::StockFpga, "{target}");
        assert_eq!(d.work_engine, WorkEngineKind::FpgaWorkFifo, "{target}");
        assert_eq!(d.asic_protocol, AsicProtocolIdentity::Bm1397, "{target}");
        assert_eq!(d.voltage_controller, controller, "{target}");
        assert_eq!(d.slot_policy, SlotPolicy::ZynqAbFwSetenv, "{target}");
        assert!(
            d.runtime_status.permits_mining_lane(),
            "{target}: the promotion must name an executable lane"
        );
        // Promotion is a runtime lane, never an install affordance.
        assert!(!d.public_beta_install(), "{target}");
        assert!(!d.mining_default_enabled, "{target}");
        let authorization = format!("{:?}", d.enablement.install_authorization);
        assert!(
            !authorization.contains("PublicBeta"),
            "{target}: enablement unchanged by the runtime promotion (got {authorization})"
        );
    }
}

#[test]
fn s17_geometry_and_strides_match_the_stock_re() {
    use dcentrald_common::bm1397plus_addr_interval;
    use dcentrald_silicon_profiles::bm1397::{
        BM1397_CHIPS_PER_CHAIN_S17_PLUS, BM1397_CHIPS_PER_CHAIN_S17_PRO,
    };
    let production = production_source(S17_MINING_RS);

    // Held constants: S17 Pro 48 and S17+ 65 from silicon-profiles; T17 30 and
    // T17+ 44 from the stock pattern files (A1 §V1/§V2).
    assert_eq!(BM1397_CHIPS_PER_CHAIN_S17_PRO, 48);
    assert_eq!(BM1397_CHIPS_PER_CHAIN_S17_PLUS, 65);
    assert_eq!(BM1397_CORES_PER_CHIP, 672);
    assert_eq!(BM1397_CHIP_ID_REPLY, [0x13, 0x97]);

    let expected = [
        ("am2-s17p", 48u8, 5u8, "BHB07601"),
        ("am2-s17plus", 65, 3, "BHB07602"),
        ("am2-t17", 30, 8, "BHB07701"),
        ("am2-t17plus", 44, 5, "BHB07702"),
    ];
    for (target, chips, stride, hashboard) in expected {
        // Owner-module unit tests call these private geometry functions.
        // This integration pin keeps their exact target composition linked
        // to the common stride API and held silicon constants.
        assert!(
            production.contains(&format!("{target:?} => Some({chips})")),
            "{target}: engine geometry pin drifted"
        );
        assert!(
            production.contains(&format!("{target:?} => Some(\"{hashboard}\")")),
            "{target}: hashboard identity drifted"
        );
        assert_eq!(bm1397plus_addr_interval(chips), stride);
    }

    // T17+ is 44, never 45 (retired operator note) — in production code.
    assert!(!production.contains("Some(45)"));
}

#[test]
fn s17_uart_constants_agree_with_silicon_profiles() {
    assert_eq!(BM1397_OPERATIONAL_BAUD, 6_250_000);
    assert_eq!(BM1397_MISCCTRL_BAUD_VALUE, 0x0000_6031);
    assert_eq!(BM1397_FAST_UART_REG68, 0xC070_0111);
    assert_eq!(BM1397_FAST_UART_REG28, 0x0600_000F);
    assert!(S17_MINING_RS.contains("S17_MISCCTRL_RESET_BAUD: u32 = 0x0000_7A31"));
    assert!(S17_MINING_RS.contains("S17_DEFAULT_BAUD: u32 = 115_740"));
}

#[test]
fn s17_engine_source_contract_safety_invariants() {
    // Production prefix only — the module's own inline tests reference the
    // same identifiers when pinning their absence.
    let production = production_source(S17_MINING_RS);
    // EEPROM write-deny reference stays at the wire boundary (rule #28).
    assert!(production.contains("S17_EEPROM_WRITE_DENYLIST"));
    // 4-midstate AsicBoost, never BIP320 reconstruction (G.3 #7).
    assert!(!production.contains("bip320_reconstruct"));
    assert!(!production.contains("BIP320_VERSION_ROLLING_MASK"));
    // No PSU-watchdog executor for the APW9 generation (A1 §V3).
    assert!(!production.contains("apw9_watchdog"));
    // R05: the constant definitions live in the wire leaf (src/s17_wire.rs).
    assert!(S17_WIRE_RS.contains("S17_PSU_WATCHDOG_CMD_ABSENT: u8 = 0x84"));
    // Destructive PIC ops stay out of the runtime binary (rule #29).
    assert!(!production.contains("jump_to_app"));
    assert!(!production.contains("pic_reset"));
    // 5-stable-heartbeat voltage deferral (rule #24).
    assert!(S17_WIRE_RS.contains("S17_STABLE_HEARTBEATS_BEFORE_VOLTAGE: u32 = 5"));
    // dsPIC fw=0x86 refusal (rule #30) belongs to the native profile and
    // observed application boundaries; no environment opt-in can waive it.
    assert!(S17_WIRE_RS.contains("S17_DEGRADED_DSPIC_FW: u8 = 0x86"));
    let native = production_source(S17_NATIVE_RS);
    assert!(native.contains("!matches!(chain.pic_application, Some(0 | 0x86 | 0xCC | 0xFF))"));
    let initialize = native
        .split_once("async fn initialize(&mut self, shutdown: &CancellationToken)")
        .expect("native S17 initialization boundary")
        .1;
    let energize = initialize
        .find("I2cMutationLabel::Energize")
        .expect("first native rail energize transaction");
    let before_energize = &initialize[..energize];
    let live_read = before_energize
        .find("let application = framed_reply(&version, 0x17)?;")
        .expect("observed PIC application before voltage");
    let refusal = before_energize
        .find("application.len() == 1 && !matches!(application[0], 0 | 0x86 | 0xcc | 0xff)")
        .expect("unconditional invalid/degraded application refusal before voltage");
    assert!(live_read < refusal);
    assert!(!before_energize.contains("trust_degraded_fw"));
    assert!(!before_energize.contains("DCENT_AM2_S17_TRUST_DEGRADED_FW"));
    assert!(production.contains("dcentrald_common::lab_env::var(name)"));
    // The BM1362 env family must NOT appear in the S17 engine.
    for bm1362_env in ["DCENT_AM2_SERIAL_WORK_DISPATCH", "DCENT_AM2_SKIP_FAST_UART"] {
        assert!(
            !production.contains(bm1362_env),
            "{bm1362_env} is BM1362-scoped and must not leak into the S17 engine"
        );
    }
}

#[test]
fn s17_admission_binds_the_exact_target_set() {
    assert!(
        S17_ADMISSION_RS.contains("[\"am2-s17p\", \"am2-s17plus\", \"am2-t17\", \"am2-t17plus\"]")
    );
    // Exact set, never a prefix.
    assert!(!S17_ADMISSION_RS.contains("starts_with(\"am2-"));
    // Observed carrier + configured protocol checks stay in the admission.
    assert!(S17_ADMISSION_RS.contains("OBSERVED_CONTROL_BOARD_ZYNQ_AM2"));
    assert!(S17_ADMISSION_RS.contains("AsicProtocolIdentity::Bm1397"));
}

#[test]
fn s17_main_construction_orders_gate_watchdog_then_engine() {
    // Scope to the run_main body: the inline main.rs tests also mention the
    // constructor names (source-contract pins), and they appear earlier in the
    // file than the production branch.
    let run_signature = ["async fn run_", "main("].concat();
    let run_start = MAIN_RS.find(&run_signature).expect("run_main body");
    let run_body = &MAIN_RS[run_start..];

    // The pre-bench energize gate is adjudicated BEFORE the safety admission
    // arms the watchdog (no armed-watchdog reboot loop on refusal).
    let gate_pos = run_body
        .find("adjudicate_s17_energize_gate(")
        .expect("energize gate call");
    let admission_pos = run_body
        .find("S17HybridSafetyAdmission::start(")
        .expect("S17 safety admission");
    let miner_pos = run_body
        .find("S17HybridMiner::new(")
        .expect("S17 miner constructor");
    assert!(
        gate_pos < admission_pos,
        "gate must precede watchdog arming"
    );
    assert!(
        admission_pos < miner_pos,
        "watchdog must precede engine construction"
    );
    // Exactly one dispatch-admission consumer still covers the new engine.
    assert_eq!(
        run_body
            .matches("admit_board_desc_runtime_dispatch(")
            .count(),
        1,
        "main runtime must keep exactly one typed BoardDesc dispatch consumer"
    );

    // CLI + auto-route exist.
    assert!(MAIN_RS.contains("\"--s17-hybrid\""));
    assert!(MAIN_RS.contains("fn classify_s17_hybrid_auto"));
}

#[test]
fn s17_launcher_exact_selector_appends_flag_only_and_never_exports_knobs() {
    // B2's selector landed (2026-08-27 unlock armada): the am2-s17pro init
    // script now admits the four promoted BoardDesc targets through an
    // EXACT-token case (ADR-0013 §6 — never an `am2-*` prefix) and appends
    // `--s17-hybrid` ONLY. Every `DCENT_AM2_S17_*` recipe knob — including
    // the bench energize gate — stays unset in images; the engine's
    // conservative defaults hold until the operator hand-sets a knob in
    // /data/dcentrald-env (sourced after the scrub, per B1 §3).
    let selector_pos = S17_LAUNCHER
        .find("IS_S17_HYBRID_TARGET=0")
        .expect("S17 selector block");
    // Exact-token arms: the four promoted targets, no wildcard.
    assert!(
        S17_LAUNCHER.contains("am2-s17p|am2-s17pro) IS_S17_HYBRID_TARGET=1 ;;"),
        "exact-token selector arm for am2-s17p/am2-s17pro"
    );
    assert!(
        S17_LAUNCHER.contains("am2-s17plus|am2-t17|am2-t17plus) IS_S17_HYBRID_TARGET=1 ;;"),
        "exact-token selector arm for the plus/t17 targets"
    );
    let selector_region = &S17_LAUNCHER[selector_pos..selector_pos + 600];
    assert!(
        !selector_region.contains("am2-s17*)") && !selector_region.contains("am2-*)"),
        "the S17 selector must never be a family prefix (ADR-0013 §6)"
    );
    // The BM1362 selector keeps refusing 17-series targets (still pinned by
    // the inline main.rs launcher test as well).
    assert!(
        S17_LAUNCHER.contains("am2-s19j|am2-s19jpro|am2-s19jpro-zynq) IS_BM1362_HYBRID_TARGET=1")
    );
    // The S17 arm appends the dispatch flag and NOTHING else.
    let append_arm = S17_LAUNCHER
        .split_once("if [ \"$IS_S17_HYBRID_TARGET\" = \"1\" ]; then")
        .expect("S17 append arm")
        .1;
    let append_arm = &append_arm[..append_arm.find("fi").expect("arm end")];
    assert_eq!(
        append_arm.trim(),
        "EXTRA_ARGS=\"$EXTRA_ARGS --s17-hybrid\"",
        "the S17 arm must append --s17-hybrid and export no recipe knob"
    );
    // All five knobs (incl. ALLOW_ENERGIZE) are unset by the image hygiene.
    for knob in [
        "DCENT_AM2_S17_FAST_UART_PLL3",
        "DCENT_AM2_S17_SERIAL_WORK_DISPATCH",
        "DCENT_AM2_S17_SKIP_PER_CHIP_INIT",
        "DCENT_AM2_S17_TRUST_DEGRADED_FW",
        "DCENT_AM2_S17_ALLOW_ENERGIZE",
    ] {
        assert!(
            S17_LAUNCHER.contains(&format!("unset {knob}")),
            "image hygiene must unset {knob}"
        );
        assert!(
            !S17_LAUNCHER.contains(&format!("export {knob}")),
            "images must NEVER export {knob} (bench gates are hand-set in /data)"
        );
    }
}
