#![forbid(unsafe_code)]

//! Shared no-HAL contract utilities for dcentrald.
//!
//! This crate is intentionally HAL-free, network-free, subprocess-free, and
//! async-runtime-free, in the same spirit as `dcentrald-api-types`. It is the
//! host-safe boundary for utilities that must be reachable from both the API
//! surface (`dcentrald-api`) and the protocol clients (`dcentrald-stratum`)
//! without pulling in a hardware dependency. Filesystem effects are restricted
//! to [`atomic_file`], [`mutation_disposition`], [`thermal_lockout`], and the
//! regular-file-only S19k Bench-GO marker. New no-HAL helpers
//! (config-validation, ID redaction, units conversion) belong here.
//!
//! Modules:
//! - [`wallet_mask`] — Bitcoin/Litecoin wallet-address masking for log and
//!   UI emission. Provides `mask_wallet()`, `mask_in_string()`, and
//!   `is_likely_wallet()`. See module docs for the threat model and which
//!   addresses are recognized (bech32, bech32m, base58 P2PKH/P2SH, hex).
//! - [`chain_voltage`] — AT-1 measured-vs-commanded per-chain rail-voltage
//!   resolver. Reuses [`dspic_decode`]'s 0x3A `MEASURE_VOLTAGE` decode to feed
//!   the autotuner/telemetry a provenance-tagged rail voltage (read-back only).
//! - [`at3_rail`] — AT-3 process-global publish/consume slot. The am2 hybrid
//!   loop's gated, default-OFF quiet-window 0x3A read publishes a fresh measured
//!   rail here; the API per-chain telemetry projection reads it back so a
//!   plausible reading is tagged `measured`. Read-only/measure-only.
//! - [`atomic_file`] — bounded same-filesystem state replacement and durable
//!   deletion with directory fsync plus explicit publication/failure evidence.

/// AM1 framed dsPIC33EP16GS202 controller adapter (T9+ class) — pure wire
/// codec + admission law cited to held stock bytes. The S9/S9i/S9j PIC16
/// bare law is a refused negative fixture here, never a reuse.
pub mod am1_dspic_adapter;
pub mod am2_topology;
/// Canonical build target and published filename for each artifact claim.
pub mod artifact_producer;
/// Transport-neutral ASIC protocol pure admission + init program seed (ADR-0010 / P1-3).
pub mod asic_protocol;
pub mod at3_rail;
pub mod atomic_file;
pub mod release_channel;
pub mod amlogic_gpio437;
pub mod lab_env;
pub mod runtime_hardware_recipe;
pub mod runtime_policy;
pub use release_channel::ReleaseChannel;
/// Per-platform parameters for the BM1366 direct-serial runtime (Gauntlet B8):
/// dispatch-admitted rows for am3-s19k (77) and the XP pair (110 each).
pub mod bm1366_serial_platform;
/// Exact per-bin BM1366 XP-pair profiles (S19 XP / S19j XP, 110 exact per
/// chain), per-model measured-PSU dialect law (APW12 75..77 vs APW17 c1),
/// population admission, init sequencing, session cancel/stale composition
/// and all-chain distribution planning; pure and no-I/O.
pub mod bm1366_xp_board_profiles;
/// Exact base-S21 (am3-s21, BM1368) full-unit profile, 3x108 population
/// admission, all-chain distribution planning and per-route nonce
/// accounting; pure and no-I/O (campaign lane R13).
pub mod bm1368_s21_board_profiles;
/// Exact per-bin BM1370 board profiles (Pro65/Plus55/XP91), population
/// admission and all-chain distribution planning; pure and no-I/O.
pub mod bm1370_board_profiles;
pub mod bm1370_work_geometry;
pub mod bm1396_s17e_factory;
/// Exact BM1360 S19i (NBS2003) + BM1398S S19a (BHB28611) legacy four-chain
/// Zynq admission profiles from held first-party topol.conf bytes; pure and
/// no-I/O (campaign lane R17).
pub mod s19_legacy_zynq_profiles;
/// Exact framed-dsPIC33EP16GS202 "S9 plus plus" AM1 generation evidence (S9
/// Hydro + S11 builds): analog-voltage telemetry wire law, compile-time
/// predicate table, S11 payload-selection law and inference-freedom pin;
/// pure and no-I/O (campaign lane R17).
pub mod s9_plus_plus_pic_generation;
/// Exact S7-45/S7-54 factory profiles and BM1385 FIL response contract; pure and no-I/O.
pub mod bm1385_s7_offline;
/// Exact S15/T15 APW8-adjacent software/guide evidence; pure and no-I/O.
pub mod bm1391_apw8_evidence;
/// Offline exact-release facts and fail-closed S15/T15 BM1391 carrier gaps.
pub mod bm1391_carrier_profile;
/// Exact-release S15/T15 BM1391 thermal/PIC safety evidence; pure and no-I/O.
pub mod bm1391_safety_contract;
/// Exact S15/T15 stock nonce-consumer duplicate/age/digest gates; pure replay only.
pub mod bm1391_share_qualification;
/// Exact S15/T15 stock BM1391 FPGA return-record and work-binding codec.
pub mod bm1391_stock_return;
/// Exact-release S15/T15 BM1391 PLL/voltage startup facts; pure and no-I/O.
pub mod bm1391_stock_startup;
/// Exact-release S15/T15 stock job decoder and pure FPGA publication planner.
pub mod bm1391_stock_work;
pub mod bm1393_native;
pub mod bm1396_auto_adapt_voltage;
/// Exact stock-module and userspace-mapping BM1396 carrier preflight facts.
pub mod bm1396_carrier_preflight;
/// Exact signed-firmware BM1396 identity and per-present-chain geometry contract.
pub mod bm1396_contract;
pub mod bm1396_domain_voltage;
/// Exact signed-firmware BM1396 userspace-to-FPGA register ABI facts.
pub mod bm1396_fpga_abi;
/// Release/model-scoped BM1396 startup and enumeration retry state machine.
pub mod bm1396_lifecycle;
pub mod bm1396_pic;
pub mod bm1396_submit_receiver;
pub mod bm1396_work;
/// Exact BM1396 outstanding-work expansion and host nonce-ring consumer.
pub mod bm1396_work_binding;
/// BM1397 / S17 BHB07601 bring-up skeleton (IMPLEMENT items 1-12; host-testable).
pub mod bm1397_s17_bhb07601;
/// Legacy BM1398 / NBP1901 identity+geometry compatibility (protocol recovered; native admission false).
pub mod bm1398_nbp1901_stub;
/// Exact held L3+ PIC application and dormant updater replay; no authority.
pub mod bm1485_l3plus_pic_firmware;
/// Exact 2017 stock L3+ BM1485 UART/address/MISC facts; pure and no-I/O.
pub mod bm1485_l3plus_stock;
/// Exact held L3+ BeagleBone software-carrier tuple; offline evidence only.
pub mod bm1485_l3plus_stock_carrier;
/// Exact 2017 stock L3+ fan tach, sensor calibration, and PWM replay.
pub mod bm1485_l3plus_stock_cooling;
/// Exact 2017 stock L3+ presence, enumeration, and startup-failure replay.
pub mod bm1485_l3plus_stock_lifecycle;
/// Exact 2017 stock L3+ PIC/heartbeat/thermal rail-off replay; pure and no-I/O.
pub mod bm1485_l3plus_stock_pic;
/// Exact 2017 stock L3+ BM1485 PLL table and write spine; pure and no-I/O.
pub mod bm1485_l3plus_stock_pll;
/// Exact 2017 stock L3+ process-exit weakness and shutdown assessment.
pub mod bm1485_l3plus_stock_shutdown;
/// Exact 2017 stock L3+ Stratum request, pending, and response replay.
pub mod bm1485_l3plus_stock_submit;
/// Exact 2017 stock L3+ work frame, return queue, and binding limits.
pub mod bm1485_l3plus_stock_work;
/// Exact L7 VNish serial return and bounded snapshot binding; pure and no-I/O.
pub mod bm1489_l7_return;
/// Exact L7 VNish thermal/fan/shutdown replay; pure and no-I/O.
pub mod bm1489_l7_safety;
/// Exact L7 VNish sensor transport words/frames/templates; pure and no-I/O.
pub mod bm1489_l7_sensor_transport;
/// Exact L7 VNish post-queue snapshot/duplicate/target gates; pure replay only.
pub mod bm1489_l7_share_qualification;
/// Exact L7 VNish Stratum send/pending/response lifecycle; pure replay only.
pub mod bm1489_l7_submission;
/// Exact third-party L7 VNish BM1489 selector-six register protocol; pure and no-I/O.
pub mod bm1489_l7_vnish;
/// Exact L7 VNish outbound work frame and Merkle planner; pure and no-I/O.
pub mod bm1489_l7_work;
/// Exact held-release L9 BM1491 carrier/pinmux preflight; pure and no-I/O.
pub mod bm1491_l9_carrier_preflight;
/// Exact held-release L9 BM1491 heartbeat/watchdog replay; pure and no-I/O.
pub mod bm1491_l9_heartbeat;
/// Exact held-release L9 BM1491 APW17/EEPROM/sensor IIC routing; pure and no-I/O.
pub mod bm1491_l9_iic_routes;
/// Exact held-release L9 BM1491 top-init and setup-all-chip plan.
pub mod bm1491_l9_init;
/// Exact held-release L9 BM1491 operating frequency/voltage policy replay.
pub mod bm1491_l9_operating;
/// Exact held-release L9 BM1491 adjustable-power voltage-wrapper replay.
pub mod bm1491_l9_power;
/// Exact held-release L9 BM1491 temperature/shutdown pure contract.
pub mod bm1491_l9_safety;
/// Exact held-release L9 BM1491 sensor-backend transport/result replay.
pub mod bm1491_l9_sensor_transport;
/// Exact held-release L9 BM1491 nonce-to-Stratum submission replay.
pub mod bm1491_l9_submission;
/// Exact held-release L9 BM1491 work-frame and nonce-return pure contract.
pub mod bm1491_l9_work;
/// Declarative control-board composition identity (ADR-0011). Scaffold registry.
pub mod board_desc;
/// Pure chain-transport op language + host recorder (ADR-0010 / P1-3 I/O seed).
pub mod chain_transport;
pub mod chain_voltage;
/// C52 cooling custody policy for home AM2 profiles (P1-7).
pub mod cooling_custody;
/// Cooling-medium axis (Air/Hydro/Immersion) + cut-ladder validation
/// (Round-15 A3, hardware-enablement axis 4). Fanless boards get NO
/// fan-raise rung — absent, not zero.
pub mod cooling_medium;
pub mod dspic_decode;
pub mod dspic_heartbeat;
/// In-miner factory aging / frequency-scan planner. Execute refused.
pub mod factory_aging;
/// Night-hour watt reduction (home night mode → Power-mode setpoint).
pub mod night_power;
/// Pure PLL frequency model + TransportOp expansion (decade P1-4 seed).
pub mod pll_model;
pub mod s19_bm1398_runtime;
/// am3-s19k GPIO437 PWR_CONTROL polarity pin (active LOW). Do not apply to S21.
pub mod s19k_am3_gpio437;
/// Amlogic NAND install architecture + SKU-scoped GPIO437 SafeOff. FLASH NOT_YET.
pub mod s19k_am3_install;
/// LuxOS-captured `axg_s400_antminer.dtb` NAND plats (`nand device 1` / nvdata).
pub mod s19k_aml_dtb;
/// Exact held-stock APW121215f lifecycle/profile facts and SafeOff evidence boundary.
pub mod s19k_apw121215f_stock;
/// Exact AMTC BM1366 golden-pattern record layout and physical core geometry.
pub mod s19k_bm1366_amtc_pattern;
/// Exact Bosminer BM1366 nonce attribution; separate from ESP/AMTC decoding.
pub mod s19k_bm1366_braiins_nonce;
/// BM1366 EXPERIMENTAL init program (GetAddress / 0x53 inactive / set_address).
pub mod s19k_bm1366_init_seq;
pub mod s19k_bm1366_nopic_beta;
/// BM1366 UART nonce → share reconstruction (ESP-Miner process_work).
pub mod s19k_bm1366_share;
/// BM1366 raw-UART GetAddress + 11-byte RX classify (T4/T5). No dispatch hook.
pub mod s19k_bm1366_uart_rx;
pub mod s19k_bm1366_wire_b;
/// FR-1.28 `.bmu` payload-protection scheme evidence (Gap-3 Track-2;
/// signature-only BMU layer, AML inner bodies stay opaque; zero install authority).
pub mod s19k_bmu_payload_evidence;
/// `a lab unit` bosminer `read_register(reg=0x0)` enum shortfall (77 expected).
pub mod s19k_bosminer_enum;
/// Gap-4 desk RE: bosminer TYPE_JOB pack chain, work-id math, HCN divider
/// (first-hand capstone/Ghidra pins; evidence only, no dispatch hook).
pub mod s19k_bosminer_t1_pack;
/// Braiins Track-1 board#↔ttyS discover policy (T8). No hardcoded map.
pub mod s19k_braiins_chain_discover;
/// Braiins Track-1 CLOSED 21 36 mining-on work TX (desk 11d/11f).
pub mod s19k_braiins_job;
/// Braiins `/tmp` deploy policy (ELF32 armhf, dual tty, rails held).
pub mod s19k_braiins_tmp_deploy;
/// Retired Braiins raw-UART probe; admission is permanently fail-closed.
pub mod s19k_braiins_wire_try;
/// Gap-1 desk RE: no held firmware emits a chip-side work-invalidate mid-run
/// (VNish gateway census, stock flush-api flag chain, AMTC jig vocabulary).
pub mod s19k_midrun_flush_evidence;
/// `a lab unit` `/dev/nand_env` U-Boot env (interrupt window + BOS/stock sequencer).
pub mod s19k_nand_env;
/// Track-1 GetAddress silence vs GPIO437 / plug-detect (not a job-shape proof).
pub mod s19k_passthrough_preflight;
/// FR-1.28 (251010) stock S19k Pro `.bmu` 3-variant TOC parser (RE only; never flash).
pub mod s19k_stock_bmu_toc;
/// Amlogic /dev/uart_trans job pack (desk 11d/11e) — host-testable.
pub mod s19k_uart_trans_job;
pub mod s21_domain_adc;
/// Fail-closed S21-generation carrier/controller admission contracts.
pub mod s21_generation_admission;
/// S21 VCO / domain climb HOLD pin (jig_clamp; autotune enabled=false).
pub mod s21_vco_hold;
pub mod s21xp_aml_evidence;
/// S9 SE `BOOT.bin` identity. No fabric ABI.
pub mod s9se_boot;
/// Ctrl_C43 / S9 SE: FPGA PWM is not an actuator; tach 0x04 is not evidence.
pub mod s9se_cooling;
/// S9 SE EEPROM major-type pin. Write refused.
pub mod s9se_eeprom;
/// S9 SE address-assignment program (60 × stride 2). Desk-only.
pub mod s9se_enum;
/// S9 SE stock-FPGA AXI map + DMA base. No mmap.
pub mod s9se_fpga;
/// S9 SE gauntlet + admit/refuse owner (GitHub DCENT_OS#2).
pub mod s9se_gauntlet;
/// S9 SE factory / DTB / firmware identity pins.
pub mod s9se_identity;
/// S9 SE desk bring-up planner. Execute refused.
pub mod s9se_init;
/// S9 SE FPGA `send_job` packet. Dispatch refused.
pub mod s9se_job;
/// S9 SE NAND / FLASH refuse (DTB + runme.sh).
pub mod s9se_nand;
/// S9 SE stock nonce classify. FIFO I/O refused.
pub mod s9se_nonce;
/// S9 SE dsPIC33EP16GS202 command catalog. I/O refused.
pub mod s9se_pic;
/// S9 SE / BM1393 PLL facts. Frequency program refused.
pub mod s9se_pll;
/// S9 SE BM1393 chip-register packers. Desk-only.
pub mod s9se_regs;
/// S9 SE on-chip I²C temperature path. I/O refused.
pub mod s9se_temp;
/// S9 SE stock timeout / working baud. FPGA write refused.
pub mod s9se_timeout;
/// S9 SE BM1393 VIL + CRC5 frame packers. Desk-only.
pub mod s9se_vil;
/// S9 SE dsPIC IIC voltage map. Conversion only — no I²C write.
pub mod s9se_voltage;
/// S9 SE VIL TW 13-word planner. Work dispatch refused.
pub mod s9se_work;
/// Pure serial enumeration, coverage, path-health, and bounded-work contracts.
pub mod serial_chain_proof;
/// Offline declared-route and passive carrier-preflight policy for stock S9 FPGA.
pub mod stock_fpga_carrier_preflight;
/// Pure stock FPGA AsicBoost / version-slot packing (G17).
pub mod stock_fpga_policy;
/// Exact held T21 Amlogic direct-UART/GPIO/PWM route; evidence only, no I/O.
pub mod t21_aml_production_route;
/// Exact evidence-scoped T21 (am3-t21, BM1368) stock profile: controller,
/// PSU and geometry pinned only to held T21 bytes; pure and no-I/O
/// (campaign lane R13 deliverable 2).
pub mod t21_bm1368_profile;
/// Pure ASIC ticket-mask encode (G24).
pub mod ticket_mask;
/// Exact offline S17/T17+ AMTC factory profiles; no production or I/O authority.
pub mod x17_amtc_factory_evidence;
/// Exact X17 recovery-script and T17e archive evidence; pure and no-I/O.
pub mod x17_amtc_recovery_evidence;
/// Exact S19 XP/S19j XP AML production routes; evidence only, no I/O authority.
pub mod x19_aml_production_route;
/// Desk-only XIL dual-chain CMD slot map for missing-SKU bring-up (RE-4A).
pub mod xil_dual_chain_desk;
// Re-export map builder used by standard-mining heartbeat temp publication.
pub use dspic_heartbeat::{build_pic_temp_chain_map, heartbeat_extra_addrs};
/// Honest diagnostic snapshot vs active-stim labels (P2-5).
pub mod diagnostic_mode;
/// Hydro coolant-loop feedback composition + external cutoff gate (R15):
/// monitored inlet/outlet/flow laws from the held hydro stock bytes, the
/// stock water-permit analog, and a one-way latched, fail-closed,
/// operator-reset-only cutoff the mining path can never bypass; pure and
/// no-I/O (campaign lane R15).
pub mod hydro_cooling_feedback;
/// Exact hydro/immersion board-PSU-cooling runtime profiles (R15): the 27
/// held topol.conf machine tuples (S19 Hydro → S21 XP Hydro), ZYNQ7007
/// transport facts (PIC1704 @0x20, AT24C02D @0x50, PSU 0x10/GPIO907),
/// population admission and fail-closed transport/startup composition;
/// pure and no-I/O. Hydro rows are excluded from beta kits — runtime
/// profiles only, no install/registration claim (campaign lane R15).
pub mod hydro_immersion_profiles;
/// Pure hashrate-from-geometry math (P2-9).
pub mod hashrate_geometry;
/// Install/packaging matrix from BoardDesc (toolbox/CI/docs generators).
pub mod install_matrix;
/// Corpus-backed hashboard↔control-board connector/pinout/plug-detect data
/// (Round 17 B4, Bitmain maintenance-guide corpus). Pure data, no I/O.
pub mod interconnect;
/// Universal measurement provenance (P2-3).
pub mod measurement;
/// Composed multi-chain energize + dispatch admission (strangler glue).
pub mod mining_lifecycle;
/// Durable, typed, fail-closed hardware mutation-disposition journal +
/// startup adjudication (crash-surviving quarantine tombstones).
pub mod mutation_disposition;
/// Multi-chain power-up stagger policy (P1-5 companion).
pub mod powerup_schedule;
/// Exact ordinary-S9 stock carrier/fan identity matcher; offline data only.
pub mod s9_ordinary_stock_profile;
/// Exact-release S9j stock thermal/fan pure contract; no live I/O authority.
pub mod s9_stock_thermal;
/// PowerCut + FanCommand policy (cut-hash-before-noise; home PWM cap).
pub mod safety_command;
/// Pure serial work-engine bookkeeping (history ring, dedup, job-id cursor).
pub mod serial_work_engine;
/// Shared serial work-history / job-id / dedup policy (mining strangler).
pub mod serial_work_policy;
pub mod sha256_padding;
/// Crash-durable source-aware thermal generation lockout.
pub mod thermal_lockout;
pub mod time;
pub mod units;
/// VoltageRail facet trait + errors (ADR-0010). Adapters live in asic/hal.
pub mod voltage_rail;
pub mod wallet_mask;
/// Work-dispatch safety admission (watchdog + heartbeat + thermal NO-SHIP).
pub mod work_dispatch_safety;

pub use asic_protocol::{
    admit_protocol_over_transport, admit_work_engine_over_transport, plan_pure_init_program,
    protocol_capabilities, InitProgram, InitStep, ProtocolCapabilities, ProtocolTransportAdmission,
    ProtocolTransportError,
};
pub use bm1391_share_qualification::{
    bm1391_stock_digest_disposition, bm1391_stock_double_sha256_from_midstate,
    bm1391_stock_normalize_share_difficulty, bm1391_stock_pre_hash_step,
    bm1391_stock_sha_context_words, decode_bm1391_stock_consumer_record,
    pop_bm1391_stock_consumer_ring, Bm1391StockConsumerRecord, Bm1391StockConsumerRecordError,
    Bm1391StockConsumerRingError, Bm1391StockConsumerRingState,
    Bm1391StockDifficultyNormalizationError, Bm1391StockDigestDisposition, Bm1391StockDuplicateKey,
    Bm1391StockPreHashDisposition, Bm1391StockPreHashStep, Bm1391StockPrecomputedHashInput,
    Bm1391StockRingPop, Bm1391StockSnapshotAge, BM1391_STOCK_CURRENT_SNAPSHOT_OFFSET,
    BM1391_STOCK_HEADER_BYTE_LEN, BM1391_STOCK_LOW_DIFFICULTY_COUNTER_INCREMENT,
    BM1391_STOCK_LOW_DIFFICULTY_WORD_MAX, BM1391_STOCK_PREVIOUS_ONE_SNAPSHOT_OFFSET,
    BM1391_STOCK_PREVIOUS_TWO_SNAPSHOT_OFFSET, BM1391_STOCK_RETURN_RING_HEADER_LEN,
    BM1391_STOCK_SHA_CONTEXT_WORDS, BM1391_STOCK_SNAPSHOT_MIDSTATE_OFFSET,
    BM1391_STOCK_SNAPSHOT_TAIL_OFFSET, BM1391_STOCK_TWO_NEGATIVE_32_F64_BITS,
    BM1391_STOCK_TWO_POSITIVE_32_F64_BITS,
};
pub use bm1391_stock_return::{
    advance_bm1391_stock_ring, bind_bm1391_stock_nonce, decode_bm1391_stock_fpga_return,
    Bm1391StockBoundNonce, Bm1391StockFpgaReturn, Bm1391StockNonceReturn,
    Bm1391StockRegisterReturn, Bm1391StockReturnDecodeError, Bm1391StockRingError,
    Bm1391StockRingState, Bm1391StockWorkBindError, BM1391_STOCK_BOUND_NONCE_RECORD_LEN,
    BM1391_STOCK_FPGA_RETURN_RECORD_LEN, BM1391_STOCK_NONCE_VALID_BIT,
    BM1391_STOCK_OUTSTANDING_WORK_RECORD_LEN, BM1391_STOCK_REGISTER_CRC5_MASK,
    BM1391_STOCK_REGISTER_CRC_ERROR_BIT, BM1391_STOCK_REGISTER_TYPE_MASK,
    BM1391_STOCK_RETURN_CHAIN_MASK, BM1391_STOCK_RETURN_NONCE_BIT,
    BM1391_STOCK_RETURN_RING_CAPACITY, BM1391_STOCK_WORK_ID_MASK,
};
pub use bm1396_auto_adapt_voltage::{
    bm1396_auto_adapt_target_voltage_cv, plan_bm1396_auto_adapt_voltage, Bm1396AutoAdaptProfile,
    Bm1396AutoAdaptVoltageError, Bm1396AutoAdaptVoltagePlan,
    BM1396_AUTO_ADAPT_POST_PLL_ADC_THRESHOLD_MHZ, BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C,
    BM1396_S17E_SIGNED_2020_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
    BM1396_S17E_SIGNED_2020_AUTO_ADAPT_MATRIX_CV, BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
    BM1396_T17E_AUTO_ADAPT_LOWER_MATRIX_CV, BM1396_T17E_AUTO_ADAPT_UPPER_MATRIX_CV,
    BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV, BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV,
};
pub use bm1396_carrier_preflight::{
    assess_bm1396_static_carrier, bm1396_stock_dma_base_for_memtotal_kib,
    Bm1396CarrierArtifactObservation, Bm1396CarrierPreflightError, Bm1396CarrierPreflightStep,
    Bm1396CarrierStaticAssessment, Bm1396CarrierStaticObservation, Bm1396MappedAddressObservation,
    Bm1396StockCarrierAccessMode, Bm1396StockCarrierNotificationMode, BM1396_AXI_DEVICE_PATH,
    BM1396_AXI_MODULE_SHA256, BM1396_AXI_MODULE_SIZE, BM1396_AXI_PHYSICAL_BASE,
    BM1396_AXI_RESERVED_LEN, BM1396_AXI_USER_MAP_LEN, BM1396_CARRIER_PREFLIGHT_PLAN,
    BM1396_FPGA_MEM_ALLOWED_BASES, BM1396_FPGA_MEM_DEFAULT_BASE, BM1396_FPGA_MEM_DEVICE_PATH,
    BM1396_FPGA_MEM_LARGE_RAM_THRESHOLD_KIB, BM1396_FPGA_MEM_MAP_LEN,
    BM1396_FPGA_MEM_MEDIUM_RAM_THRESHOLD_KIB, BM1396_FPGA_MEM_MODULE_SHA256,
    BM1396_FPGA_MEM_MODULE_SIZE, BM1396_STOCK_CARRIER_ACCESS_MODE,
    BM1396_STOCK_CARRIER_NOTIFICATION_MODE, BM1396_STOCK_MODULE_VERMAGIC,
};
pub use bm1396_contract::{
    admit_bm1396_present_chain_enumeration, bm1396_baud_plan, bm1396_chain_watchdog_decision,
    bm1396_command_crc5, bm1396_decode_fan_tach, bm1396_fan_sample_passes,
    bm1396_fan_validation_policy, bm1396_hard_thermal_decision, bm1396_hard_thermal_limits,
    bm1396_legacy_2019_thermal_limits, bm1396_legacy_2019_thermal_step, bm1396_read_register_frame,
    bm1396_reset_address_frame, bm1396_sensor_aggregation_family,
    bm1396_sensor_channel0_temperature, bm1396_sensor_channel1_temperature,
    bm1396_sensor_invalid_action, bm1396_sensor_sample_is_outlier, bm1396_set_address_frame,
    bm1396_t17e_next_retry_voltage_cv, bm1396_update_fan_state, bm1396_validate_voltage_response,
    bm1396_vendor_can_reopen_core, bm1396_vendor_error_action, bm1396_vendor_thermal_observation,
    bm1396_vendor_working_voltage_clamp_cv, bm1396_voltage_dac_in_vendor_envelope,
    bm1396_voltage_request_frame, bm1396_write_register_frame, plan_bm1396_shutdown,
    plan_bm1396_vendor_voltage_dac_ramp, Bm1396BaudPlan, Bm1396ChainWatchdogDecision,
    Bm1396EnumerationAdmission, Bm1396EnumerationError, Bm1396FanSampleError, Bm1396FanState,
    Bm1396FanTachReading, Bm1396FanValidationPhase, Bm1396FanValidationPolicy,
    Bm1396HardThermalDecision, Bm1396HardThermalLimits, Bm1396HardThermalMode,
    Bm1396Legacy2019ThermalLimits, Bm1396Legacy2019ThermalSample, Bm1396Legacy2019ThermalStep,
    Bm1396Model, Bm1396NoActiveChainForSensorDecision, Bm1396SensorAggregationFamily,
    Bm1396SensorInvalidAction, Bm1396SensorSamplingMode, Bm1396ShutdownStep, Bm1396UnsupportedBaud,
    Bm1396VendorErrorAction, Bm1396VendorThermalObservation, Bm1396VoltageOutsideVendorEnvelope,
    Bm1396VoltageResponseError, BM1396_ADDRESS_COMMAND_SPACING_MS,
    BM1396_ADDRESS_RESET_BURST_COUNT, BM1396_ASIC_MISC_CONTROL_REGISTER, BM1396_BAUD_HIGH_CLOCK_HZ,
    BM1396_BAUD_HIGH_CLOCK_THRESHOLD, BM1396_BAUD_LOW_CLOCK_HZ,
    BM1396_BAUD_SWITCH_DELAY_CALL_VALUE, BM1396_CHAIN_WATCHDOG_DISABLE_AFTER_MISMATCHES,
    BM1396_CHAIN_WATCHDOG_INTER_PHASE_DELAY_CALL_VALUES,
    BM1396_CHAIN_WATCHDOG_TRIGGER_DELAY_CALL_VALUES, BM1396_DCDC_CONTROL_OPCODE,
    BM1396_DCDC_DISABLE_PAYLOAD, BM1396_FAN_TACH_DEFAULT_RPM_PER_COUNT,
    BM1396_FAN_TACH_DOUBLE_RATE_HW_ID_LOW16, BM1396_FAN_TACH_MAX_READINGS,
    BM1396_FAN_TACH_SPECIAL_RPM_PER_COUNT, BM1396_FAN_VALIDATION_MAX_SAMPLES,
    BM1396_FPGA_BAUD_PRESERVE_MASK, BM1396_FPGA_BAUD_REGISTER_OFFSET, BM1396_FPGA_CHAIN_SLOT_COUNT,
    BM1396_FPGA_MAIN_CONTROL_OFFSET, BM1396_FPGA_MAIN_CONTROL_RUN_BIT,
    BM1396_HARD_THERMAL_FATAL_ERROR_CODE, BM1396_HARD_THERMAL_FLAG_CLEAR_CHIP_MAX_C,
    BM1396_HARD_THERMAL_FLAG_CLEAR_PCB_MAX_C, BM1396_HARD_THERMAL_FLAG_SET_CHIP_MAX_C,
    BM1396_HARD_THERMAL_FLAG_SET_PCB_MAX_C, BM1396_HIGH_BAUD_CLOCK_PRELUDE,
    BM1396_LEGACY_2019_FLAG_CLEAR_CHIP_DELTA_MAX_C, BM1396_LEGACY_2019_FLAG_CLEAR_PCB_DELTA_MAX_C,
    BM1396_LEGACY_2019_FLAG_SET_CHIP_DELTA_MAX_C, BM1396_LEGACY_2019_FLAG_SET_PCB_DELTA_MAX_C,
    BM1396_LEGACY_2019_THERMAL_FATAL_ERROR_CODE, BM1396_REQUIRED_FAN_COUNT,
    BM1396_RUNTIME_FAN_BAD_SAMPLE_DELAY_CALL_VALUE, BM1396_RUNTIME_FAN_MIN_RPM,
    BM1396_RUNTIME_PHASE_SET_COUNTER_VALUE, BM1396_S17E_ADDRESS_INTERVAL,
    BM1396_S17E_CHIPS_PER_PRESENT_CHAIN, BM1396_SENSOR_INVALID_FATAL_ERROR_CODE,
    BM1396_SENSOR_MODE0_OFFSET_F64_BITS, BM1396_SENSOR_MODE0_SLOPE_F64_BITS,
    BM1396_SENSOR_MODE1_OFFSET_F64_BITS, BM1396_SENSOR_MODE1_SLOPE_F64_BITS,
    BM1396_SENSOR_OUTLIER_MULTIPLIER_F32_BITS, BM1396_SENSOR_OUTLIER_VARIANCE_THRESHOLD,
    BM1396_SENSOR_POSITIONS_PER_CHAIN, BM1396_SHUTDOWN_GPIO, BM1396_SHUTDOWN_GPIO_SETTLE_MS,
    BM1396_STARTUP_BAUD, BM1396_STARTUP_FAN_BAD_SAMPLE_DELAY_CALL_VALUE,
    BM1396_STARTUP_FAN_MIN_RPM, BM1396_T17E_ADDRESS_INTERVAL, BM1396_T17E_CHIPS_PER_PRESENT_CHAIN,
    BM1396_T17E_RETRY_VOLTAGE_STEP_CV, BM1396_VENDOR_MIN_VALID_PCB_TEMP_C,
    BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV, BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV,
    BM1396_VOLTAGE_DAC_RAMP_STEP, BM1396_VOLTAGE_DAC_RAMP_STEP_FIXED_X2,
    BM1396_VOLTAGE_I2C_ADDRESS, BM1396_VOLTAGE_RESPONSE_WAIT_US,
    BM1396_VOLTAGE_TRANSPORT_MAX_ATTEMPTS, BM1396_WIRE_CHIP_ID,
};
pub use bm1396_domain_voltage::{
    bm1396_decode_domain_adc_registers, bm1396_domain_adc_raw_to_volts,
    bm1396_domain_adc_sample_index, bm1396_domain_voltage_acquisition_error,
    bm1396_domain_voltage_mode_from_vendor_param, bm1396_domain_voltage_policy,
    bm1396_evaluate_domain_voltages, bm1396_next_domain_voltage_level, bm1396_summarize_domain_adc,
    Bm1396DomainAdcIndexError, Bm1396DomainAdcRawLanes, Bm1396DomainAdcSummary,
    Bm1396DomainAdcSummaryError, Bm1396DomainVoltageAdaptiveLevel, Bm1396DomainVoltageDecision,
    Bm1396DomainVoltageInputError, Bm1396DomainVoltageMode, Bm1396DomainVoltagePolicy,
    Bm1396DomainVoltagePolicyError, BM1396_DOMAIN_ADC_LANE_COUNT,
    BM1396_DOMAIN_ADC_LANE_SPREAD_F64_BITS, BM1396_DOMAIN_ADC_MULTIPLIER,
    BM1396_DOMAIN_ADC_RAW_MASK, BM1396_DOMAIN_ADC_SCALE_2_NEG_12_F64_BITS,
    BM1396_DOMAIN_MIN_0_8_F32_BITS, BM1396_DOMAIN_MIN_1_0_F32_BITS, BM1396_DOMAIN_MIN_1_1_F32_BITS,
    BM1396_DOMAIN_MIN_1_2_F32_BITS, BM1396_DOMAIN_MIN_1_3_F32_BITS,
    BM1396_DOMAIN_SPREAD_0_05_F32_BITS, BM1396_DOMAIN_SPREAD_0_1_F32_BITS,
    BM1396_DOMAIN_SPREAD_0_2_F32_BITS, BM1396_DOMAIN_VOLTAGE_ACQUISITION_ERROR_BASE,
    BM1396_S17E_CHIPS_PER_DOMAIN, BM1396_S17E_DOMAIN_COUNT, BM1396_T17E_CHIPS_PER_DOMAIN,
    BM1396_T17E_DOMAIN_COUNT,
};
pub use bm1396_fpga_abi::{
    bm1396_bc_command_requires_completion_poll, bm1396_return_control_enable,
    bm1396_return_dispatch, bm1396_return_fifo_status, bm1396_return_record_word_count,
    bm1396_should_reassert_return_enable, bm1396_version_lane_writes, bm1396_work_fifo_ready,
    Bm1396FpgaRegisterWrite, Bm1396ReturnDispatch, Bm1396ReturnFifoStatus, Bm1396VersionLaneMode,
    BM1396_FPGA_BC_COMMAND_MAX_POLLS, BM1396_FPGA_BC_COMMAND_OFFSET,
    BM1396_FPGA_BC_COMMAND_POLL_SLEEP_US, BM1396_FPGA_JOB_BLOCK_VERSION_OFFSET,
    BM1396_FPGA_JOB_BUFFER_A_OFFSET, BM1396_FPGA_JOB_BUFFER_B_OFFSET,
    BM1396_FPGA_JOB_BUFFER_SELECT_OFFSET, BM1396_FPGA_JOB_COINBASE_LAYOUT_OFFSET,
    BM1396_FPGA_JOB_ID_OFFSET, BM1396_FPGA_JOB_MAIN_CONTROL_OFFSET,
    BM1396_FPGA_JOB_MERKLE_COUNT_OFFSET, BM1396_FPGA_JOB_NBITS_OFFSET,
    BM1396_FPGA_JOB_NONCE2_HIGH_OFFSET, BM1396_FPGA_JOB_NONCE2_LOW_OFFSET,
    BM1396_FPGA_JOB_NTIME_OFFSET, BM1396_FPGA_JOB_PAYLOAD_END_OFFSET,
    BM1396_FPGA_JOB_PREVIOUS_HASH_BASE_OFFSET, BM1396_FPGA_JOB_PREVIOUS_HASH_WORDS,
    BM1396_FPGA_RETURN_CONTROL_OFFSET, BM1396_FPGA_RETURN_COUNT_MASK,
    BM1396_FPGA_RETURN_COUNT_OFFSET, BM1396_FPGA_RETURN_ENABLE_BIT,
    BM1396_FPGA_RETURN_WORD1_DISPATCH_BIT, BM1396_FPGA_RETURN_WORD1_OFFSET,
    BM1396_FPGA_RETURN_WORD2_OFFSET, BM1396_FPGA_SINGLE_COUNT_REASSERT_OBSERVATIONS,
    BM1396_FPGA_TICKET_DIFFICULTY_OFFSET, BM1396_FPGA_TWO_WORD_RECORD_MARKER,
    BM1396_FPGA_VERSION_LANE_1_OFFSET, BM1396_FPGA_VERSION_LANE_2_OFFSET,
    BM1396_FPGA_VERSION_LANE_3_OFFSET, BM1396_FPGA_VERSION_LANE_4_OFFSET,
    BM1396_FPGA_VERSION_LANE_5_OFFSET, BM1396_FPGA_VERSION_LANE_6_OFFSET,
    BM1396_FPGA_VERSION_LANE_7_OFFSET, BM1396_FPGA_WORK_READY_DELAY_CALL_VALUE,
    BM1396_FPGA_WORK_READY_MAX_POLLS, BM1396_FPGA_WORK_READY_OFFSET,
};
pub use bm1396_lifecycle::{
    bm1396_enumeration_pass_start, bm1396_enumeration_profile, bm1396_inter_pass_transition,
    plan_bm1396_enumeration_attempt, plan_bm1396_post_exhaustion, Bm1396EnumerationAttemptOutcome,
    Bm1396EnumerationAttemptPlan, Bm1396EnumerationAttemptStep, Bm1396EnumerationPassStep,
    Bm1396EnumerationProfile, Bm1396FirmwareRelease, Bm1396InterPassVoltageTargetSource,
    Bm1396LifecyclePlanError, Bm1396PassCompletionDisposition, Bm1396PllBankSelectorSource,
    Bm1396PostExhaustionDisposition, Bm1396PostExhaustionPlan, Bm1396PostExhaustionStep,
    Bm1396RuntimeModeClass, Bm1396T17e2020InterPassStep,
    BM1396_LEGACY_2019_ENUMERATION_MAXIMUM_PASSES, BM1396_LEGACY_2019_ENUMERATION_MAX_ATTEMPTS,
    BM1396_LEGACY_2019_SHORT_COUNT_MAX_RETRIES, BM1396_S17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES,
    BM1396_SIGNED_2020_ENUMERATION_MAX_ATTEMPTS, BM1396_SIGNED_2020_ENUMERATION_PASS_START,
    BM1396_SIGNED_2020_SHORT_COUNT_MAX_RETRIES, BM1396_T17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES,
    BM1396_T17E_SIGNED_2020_INTER_PASS_TRANSITION,
};
#[cfg(feature = "recovery-tool")]
pub use bm1396_pic::{
    bm1396_pic_application_reset_frame, bm1396_pic_jump_to_app_frame,
    BM1396_PIC_APPLICATION_RESET_OPCODE, BM1396_PIC_JUMP_TO_APP_OPCODE,
};
pub use bm1396_pic::{
    bm1396_pic_endpoint, bm1396_pic_heartbeat_frame, bm1396_pic_implementation_route,
    bm1396_pic_implementation_route_for_model, bm1396_pic_physical_part_for_model,
    bm1396_pic_rail_disable_frame, bm1396_pic_rail_enable_frame, bm1396_pic_response_accepted,
    bm1396_pic_version_frame, bm1396_pic_voltage_sample_passes,
    bm1396_pic_voltage_verification_iteration, bm1396_safe_heartbeat_failure_count,
    Bm1396PicEndpoint, Bm1396PicFrameError, Bm1396PicImplementationRoute, Bm1396PicPhysicalPart,
    Bm1396PicVoltageCheckError, Bm1396PicVoltageIterationDecision, Bm1396PicVoltageIterationError,
    BM1396_PIC_CHAIN_SLOT_COUNT, BM1396_PIC_HEARTBEAT_OPCODE,
    BM1396_PIC_HEARTBEAT_PER_CHAIN_DELAY_CALL_VALUE, BM1396_PIC_HEARTBEAT_RESPONSE_LEN,
    BM1396_PIC_HEARTBEAT_SCAN_SLEEP_MS, BM1396_PIC_I2C_BASE_ADDRESS,
    BM1396_PIC_INVALID_REPLY_SLEEP_MS, BM1396_PIC_MAX_ATTEMPTS, BM1396_PIC_MAX_REQUEST_PAYLOAD_LEN,
    BM1396_PIC_POST_READ_WAIT_MS, BM1396_PIC_PREAMBLE, BM1396_PIC_RAIL_OPCODE,
    BM1396_PIC_VERSION_OPCODE, BM1396_PIC_VERSION_RESPONSE_LEN,
    BM1396_PIC_VOLTAGE_DIRECT_SET_SETTLE_MS, BM1396_PIC_VOLTAGE_FAILURE_ERROR_CODE,
    BM1396_PIC_VOLTAGE_INTERCHECK_SLEEP_MS, BM1396_PIC_VOLTAGE_MAX_OUTER_ITERATIONS,
    BM1396_PIC_VOLTAGE_TOLERANCE_V_F64_BITS, BM1396_PIC_WRITE_TO_READ_WAIT_MS,
};
pub use bm1396_work::{
    bm1396_decode_nonce_record, bm1396_decode_register_record, bm1396_job_scalar_writes,
    bm1396_job_timeout_control_value, bm1396_job_version_mode, bm1396_parse_job_packet,
    bm1396_plan_job_fpga, bm1396_plan_ordered_job_dispatch, bm1396_previous_hash_fpga_words,
    bm1396_sha256_pad_coinbase, Bm1396JobDispatchPlanError, Bm1396JobFpgaPlan, Bm1396JobPacket,
    Bm1396JobParseError, Bm1396JobPlanError, Bm1396NonceDecodeError, Bm1396NonceRecord,
    Bm1396OrderedJobOp, Bm1396OrderedJobPlan, Bm1396RegisterDecodeError, Bm1396RegisterRecord,
    BM1396_JOB_DELAY_CALL_VALUE, BM1396_JOB_FINAL_MAIN_PRESERVE_MASK,
    BM1396_JOB_FIRST_RETURN_ENABLE_MASK, BM1396_JOB_FIXED_LEN, BM1396_JOB_HEADER,
    BM1396_JOB_MAIN_CONTROL_BIT7_FLAG, BM1396_JOB_MAIN_CONTROL_BIT7_MASK,
    BM1396_JOB_MAIN_CONTROL_CLEAR_MASK, BM1396_JOB_MAIN_CONTROL_CLEAR_MAX_POLLS,
    BM1396_JOB_MULTIVERSION_MODE_BASE, BM1396_JOB_SINGLE_MODE_WORD,
    BM1396_JOB_TICKET_DIFFICULTY_FLAG, BM1396_JOB_TIMEOUT_CONTROL_OFFSET, BM1396_MERKLE_BRANCH_LEN,
    BM1396_NONCE_CHIP_ADDRESS_SHIFT, BM1396_NONCE_CORE_SHIFT, BM1396_NONCE_QUEUE_CAPACITY,
    BM1396_NONCE_VALID_BIT, BM1396_OUTSTANDING_WORK_RECORD_SIZE, BM1396_RETURN_CHAIN_MASK,
    BM1396_RETURN_CRC_ERROR_BIT, BM1396_RETURN_RECORD_LEN, BM1396_WORK_ID_MASK,
};
pub use board_desc::{
    AsicCatalogIdentity, AsicProtocolAdmission, AsicProtocolIdentity, BoardDesc, BoardFamily,
    ChainTransportKind, SlotPolicy, VoltageControllerClass, WorkEngineKind,
};
pub use chain_transport::{
    admit_transport_op, am2_misc_ctrl_pre_baud_from_bosminer_cold_opt_in,
    am2_misc_ctrl_pre_baud_policy_from_bosminer_cold_opt_in, am2_misc_ctrl_pre_baud_value,
    bm1397plus_addr_interval, bm1397plus_full_population_chip_addresses,
    hot_start_dual_spray_bm1397plus_transport_ops, init_program_to_transport_ops,
    init_step_to_transport_ops, linear_chip_addresses, plan_admitted_transport_ops,
    plan_bm1387_misc_ctrl_i2c_off_chip0, plan_bm1387_misc_ctrl_triple_write_chip,
    plan_bm1397_fast_uart_pll3_then_config, plan_bm1397_fast_uart_pll3_then_config_chip,
    plan_bm1397plus_chain_inactive_burst, plan_bm1397plus_full_population_address_ladder,
    plan_bm1397plus_set_address_ladder, plan_hot_start_baud_wake_ladder,
    plan_hot_start_baud_wake_ladder_from_fast_baud, plan_hot_start_baud_wake_ops,
    plan_hot_start_dual_spray_ops, plan_hot_start_hybrid_wake_ops,
    plan_misc_ctrl_single_write_broadcast, plan_misc_ctrl_single_write_broadcast_reg,
    plan_misc_ctrl_single_write_chip, plan_misc_ctrl_single_write_chip_reg,
    plan_misc_ctrl_triple_write_broadcast, plan_misc_ctrl_triple_write_broadcast_reg,
    plan_misc_ctrl_triple_write_chip, plan_misc_ctrl_triple_write_chip_reg,
    plan_version_rolling_broadcast_writes, plan_version_rolling_quad_write_broadcast,
    plan_version_rolling_single_write_broadcast, plan_version_rolling_triple_write_broadcast,
    protocol_speaks_bm1397plus_commands, transport_backend_class, version_rolling_reg_value,
    Am2MiscCtrlPreBaudPolicy, Bm1387MiscCtrlCadenceOp, Bm1387RegWriteIntent, ChainTransport,
    HotStartBaudStage, HotStartCommandFamily, HotStartHostClass, HotStartSprayOp,
    RecordingChainTransport, TransportBackendClass, TransportOp, TransportOpError,
    AM2_MISC_CTRL_PRE_BAUD_BOSMINER_COLD, AM2_MISC_CTRL_PRE_BAUD_DEFAULT_109,
    BM1387_MISC_CTRL_I2C_OFF_MINING, BM1397_FAST_UART_CONFIG_REG, BM1397_FAST_UART_CONFIG_VALUE,
    BM1397_FAST_UART_PLL3_VALUE, BM1397_PLL3_PARAMETER_REG, HOT_START_AMLOGIC_FAST_BAUD,
    HOT_START_MISC_CTRL_BAUD_RESET, HOT_START_POST_LADDER_SETTLE_MS, HOT_START_SPRAY_DWELL_MS,
    HOT_START_TARGET_BAUD, HOT_START_ZYNQ_FAST_BAUD, HOT_START_ZYNQ_MID_BAUD, MISC_CTRL_REG_BM1387,
    MISC_CTRL_REG_BM1397PLUS, MISC_CTRL_SINGLE_WRITE_COUNT, MISC_CTRL_TRIPLE_WRITE_COUNT,
    MISC_CTRL_TRIPLE_WRITE_SPACING_MS, VERSION_ROLLING_MASK_SHIFT, VERSION_ROLLING_QUAD_COUNT,
    VERSION_ROLLING_REG_BIP320_DEFAULT, VERSION_ROLLING_REG_BM1397PLUS, VERSION_ROLLING_REG_PREFIX,
    VERSION_ROLLING_SINGLE_COUNT, VERSION_ROLLING_STRATUM_BIP320_MASK,
    VERSION_ROLLING_TRIPLE_COUNT,
};
pub use cooling_custody::{
    admit_c52_custody, admit_home_am2_s19_c52, c52_custody_decision, is_c52_mode_low_byte,
    C52AdmissionError, C52CustodyDecision, CoolingBoardClass, CoolingProfileKind,
    C49_MODE_LOW_BYTE, C52_MODE_LOW_BYTE,
};
pub use dcent_schema::hardware::{
    ArtifactKind, ArtifactMaturity, ExternalMediaMaturity, ExternalMediaMode, GenericConstruction,
    HardwareEnablementPolicy, ImplementationMaturity, InstallAuthorization, LifecycleLane,
    RecoveryMaturity, RuntimeStatus, StorageTopology, UpdateMechanism,
    HARDWARE_ENABLEMENT_SCHEMA_VERSION,
};
pub use diagnostic_mode::{
    admit_report_kind, parse_report_kind, DiagnosticModeError, DiagnosticRunMode,
};
pub use hashrate_geometry::{
    chip_hashrate_ghs, nominal_hashrate_ghs_from_geometry, total_chips_from_per_chain,
    total_chips_from_profile_geometry,
};
pub use install_matrix::{
    ab_sysupgrade_board_targets, install_matrix, install_matrix_json, install_matrix_tsv,
    public_beta_board_targets, InstallMatrixRow,
};
pub use measurement::{prefer_measured, Measurement, MeasurementProvenance};
pub use mining_lifecycle::{
    plan_multi_chain_enable, plan_production_multi_chain_enable,
    plan_production_multi_chain_energize, plan_production_multi_chain_energize_for_targets,
    MiningLifecycleError, MultiChainEnableAuthority, MultiChainEnablePlan,
    ProductionMultiChainEnergizePlan,
};
pub use pll_model::{
    admit_pll_register, bm1362_pll_frequencies, bm1362_pll_reg_and_actual,
    bm1366_pll_reg_and_actual, bm1368_pll_reg_and_actual, bm1368_pll_table_lookup,
    bm1368_vco_in_jig_range, bm1370_pll_reg_and_actual, bm1370_vco_in_jig_range,
    bm1387_pll_frequencies, bm1391_pll_fallback_200m, bm1391_pll_pack, bm1391_pll_search,
    bm1396_pll_program_register_value, bm1396_production_pure_pll_admitted,
    bm1396_production_pure_pll_status, bm1397_pll0_lock_bit_set, bm1397_pll0_readback_matches,
    bm1397_pll0_verify_rewrite_admitted, bm1397_pll_decode_dividers, bm1397_pll_frequencies,
    bm1397_pll_register_value, bm1398_pll_frequencies, bm1398_pll_register_value,
    crystal25_pll_decode_dividers, crystal25_pll_encode_reg, plan_all_pll_broadcast_writes,
    plan_bm1368_pll_ramp, plan_bm1391_frequency_program_ops,
    plan_bm1391_frequency_program_ops_chip, plan_bm1396_frequency_program_ops,
    plan_bm1396_frequency_program_ops_experimental, plan_bm1396_pll_program_ops,
    plan_bm1397_frequency_program_ops, plan_bm1397_frequency_program_ops_chip,
    plan_bm1397_pll0_verify_read, plan_bm1397_pll0_verify_retry_rewrite,
    plan_frequency_program_ops, plan_pll0_broadcast_write, plan_pll_broadcast_write, pll_count,
    pll_family_for_protocol, pll_register_addrs, resolve_bm1362_pll, resolve_bm1366_pll,
    resolve_bm1368_pll, resolve_bm1368_pll_fallback_mhz, resolve_bm1368_pll_mhz,
    resolve_bm1368_pll_with_policy, resolve_bm1370_pll, resolve_bm1370_pll_mhz,
    resolve_bm1370_pll_with_policy, resolve_bm1387_pll, resolve_bm1391_pll, resolve_bm1396_pll,
    resolve_bm1396_pll_experimental_family_hypothesis, resolve_bm1397_pll, resolve_bm1398_pll,
    resolve_bm1398_pll_nearest_admitted, resolve_pll, resolve_pll_for_protocol, Bm1368VcoPolicy,
    Bm1370VcoPolicy, Bm1391PllSolution, Bm1396PllDividers, Bm1396PllSolution, Bm1396PurePllStatus,
    Bm1397PllDividers, Bm1398PllDividers, Crystal25PllDividers, PllFamily, PllPlanError,
    PllSolution, BM1362_PLL_FREQUENCIES, BM1362_PLL_TABLE, BM1368_CLKI_MHZ, BM1368_FB_DIV_MAX,
    BM1368_FB_DIV_MIN, BM1368_PLL_RAMP_MAX_X100, BM1368_PLL_TABLE, BM1368_PLL_TABLE_MAX_X100,
    BM1370_CLKI_MHZ, BM1370_FB_DIV_MAX, BM1370_FB_DIV_MIN, BM1370_JIG_VCO_MAX_MHZ,
    BM1370_JIG_VCO_MAX_REFDIV1_MHZ, BM1370_JIG_VCO_MIN_MHZ, BM1370_PLL_COUNT,
    BM1370_PLL_REGISTER_ADDRS, BM1387_PLL_PARAMETER_REG, BM1387_PLL_TABLE, BM1391_PLL0_DIVIDER_REG,
    BM1391_PLL0_REG, BM1391_S17_JIG_PLL_AUTHORIZES_S15_T15_PROGRAMMING,
    BM1391_S17_JIG_PLL_FALLBACK_200M, BM1391_S17_JIG_PLL_FALLBACK_EXTERNAL_DIV,
    BM1391_S17_JIG_PLL_PROGRAM_SPACING_MS, BM1396_PLL_CLKI_MHZ, BM1396_PLL_FAILURE_REGISTER,
    BM1396_PLL_FAILURE_SELECTOR, BM1396_PLL_FB_DIV_MAX, BM1396_PLL_FB_DIV_MIN,
    BM1396_PLL_MAX_ERROR_MHZ_EXCLUSIVE, BM1396_PLL_PRESERVE_MASK, BM1396_PLL_PROGRAM_WRITE_COUNT,
    BM1396_PLL_REFDIV_ONE_VCO_MAX_MHZ, BM1396_PLL_REGISTER_ADDRS, BM1396_PLL_SUCCESS_SELECTOR,
    BM1396_PLL_VCO_MAX_MHZ, BM1396_PLL_VCO_MIN_MHZ, BM1397_CLKI_MHZ, BM1397_FB_DIV_MAX,
    BM1397_FB_DIV_MIN, BM1397_FREQ_MAX_MHZ, BM1397_FREQ_MIN_MHZ, BM1397_PLL0_DIVIDER_PRECONFIG,
    BM1397_PLL0_DIVIDER_REG, BM1397_PLL0_LOCK_BIT, BM1397_PLL0_VERIFY_MAX_ATTEMPTS,
    BM1397_PLL0_VERIFY_READ_SETTLE_MS, BM1397_PLL0_VERIFY_REWRITE_SETTLE_MS,
    BM1397_PLL_PROGRAM_SPACING_MS, BM1398_CLKI_MHZ, BM1398_FB_DIV_MAX, BM1398_FB_DIV_MIN,
    BM1398_MAX_ERROR_MILLIMHZ_EXCLUSIVE, BM1398_REFDIV_ONE_VCO_MAX_MHZ, BM1398_VCO_MAX_MHZ,
    BM1398_VCO_MIN_MHZ, PLL0_PARAMETER_REG,
};
pub use powerup_schedule::{
    inter_step_delays_ms, plan_powerup, plan_production_enable_sequence, plan_production_powerup,
    require_nonempty, schedule_duration_ms, validate_production_stagger, validate_schedule_gaps,
    PowerUpPolicyError, PowerUpStep, StaggerConfig, DEFAULT_CHAIN_STAGGER_MS,
    MIN_PRODUCTION_STAGGER_MS,
};
pub use s9_stock_thermal::{
    decode_s9j_e531_local_pcb_c, decode_s9j_e531_remote_c, s9j_e531_fan_control_value,
    summarize_s9j_e531_fan_reads, S9StockCutReason, S9StockFanTachRead, S9StockFanTachState,
    S9StockFanTachSummary, S9StockHardCutStep, S9StockThermalObservation, S9StockThermalPlan,
    S9StockThermalPlanner, S9StockThermalProfile, S9J_E531_BMMINER_SHA256,
    S9J_E531_FAN_CURVE_HYSTERESIS_C, S9J_E531_FAN_CURVE_ORIGIN_C, S9J_E531_FAN_CURVE_PCT_PER_C,
    S9J_E531_FAN_FLOOR_MAX_PCB_C, S9J_E531_FAN_SLOT_COUNT, S9J_E531_FAN_SWEEPS_PER_CYCLE,
    S9J_E531_FAN_TACH_RPM_PER_UNIT, S9J_E531_FULL_FAN_PCB_C, S9J_E531_HARD_PCB_CUTOFF_C,
    S9J_E531_HARD_PROTECT_CUT_STEPS, S9J_E531_HARD_PROTECT_LOOP_SLEEP_SECS,
    S9J_E531_LOCAL_DECODE_MAX_C, S9J_E531_LOCAL_DECODE_MIN_C, S9J_E531_MAX_PWM_PERCENT,
    S9J_E531_MIN_PWM_PERCENT, S9J_E531_MIN_WORKING_FANS, S9J_E531_SUPERVISORY_CUT_STEPS,
    S9J_E531_SUPERVISORY_FAULT_CYCLES_TO_CUT, S9J_E531_SUPERVISORY_LOOP_SLEEP_SECS,
    S9J_E531_TEMP_LAST_ACCEPTED_ATTEMPT, S9J_E531_TEMP_READ_ATTEMPTS,
};
pub use safety_command::{
    apply_safety_action, power_precedes_fan_raise, violates_home_fan_cap, FanCommand, PowerCut,
    PowerCutReason, SafetyAction, SafetyApplyReport, SafetyStep, FAN_PWM_ABSOLUTE_MAX,
    HOME_FAN_PWM_SAFETY_MAX,
};
pub use serial_work_engine::{
    admit_s19k_production_clean_funnel_instrumented,
    admit_s19k_wrap4_snapshot_preserves_wrap_retire_leftover, admit_serial_bring_up_plugin,
    classify_s19k_post_clean_nonce, classify_serial_rx_interval, execute_serial_bring_up_plan,
    plan_serial_bring_up, plan_serial_bring_up_for_board, refine_bm1362_bring_up_for_board_family,
    s19k_clean_funnel_armed, s19k_post_clean_submit_allowed,
    s19k_restore_wrap_retire_leftover_after_clean_snapshot, s19k_should_log_full_work_frame,
    s19k_track1_rx_death_parser_note, serial_work_min_interval_ms, AsicJobIdCursor,
    GenerationSeenShareSet, S19kCleanFunnel, S19kPostCleanNonceClass, SeenShareSet,
    SerialBringUpAdmitError, SerialBringUpPhases, SerialBringUpPlan, SerialBringUpPlanError,
    SerialBringUpPlanParams, SerialBringUpPlugin, SerialBringUpPluginKind, SerialDispatchTicket,
    SerialMiningEngineBookkeeping, SerialRxInterval, SerialRxIntervalState, SerialWorkBookkeeping,
    WorkHistoryEntry, WorkHistoryRing, SERIAL_WORK_MAX_FRAMES_PER_SEC,
}; // WorkHistoryRing is generic over entry type (P1-1)
pub use serial_work_policy::{
    generation_dedup_cutoff, generation_share_dedup_key, next_asic_job_id, serial_share_dedup_key,
    should_clear_seen_shares, should_prune_generation_seen, work_history_depth_for_chip_id,
    AM3_BB_WORK_HISTORY_PER_ID, BM1362_SERIAL_NONCE_LEN, BM1398_WORK_HISTORY_PER_ID,
    DEFAULT_SEEN_SHARES_CAP, DEFAULT_SERIAL_JOB_ID_STEP, DEFAULT_WORK_HISTORY_PER_ID,
    GENERATION_SEEN_RETAIN_WINDOW, GENERATION_SEEN_SOFT_CAP_DISPATCHER,
    GENERATION_SEEN_SOFT_CAP_SERIAL,
};
pub use sha256_padding::sha256_pad_message;
pub use stock_fpga_policy::{
    plan_stock_bc_chain_inactive_vil, plan_stock_bc_set_address_vil, plan_stock_bc_set_config,
    plan_stock_bm1387_set_freq, plan_stock_cold_boot_library_inventory, plan_stock_dma_job,
    plan_stock_init_ticket_mask_and_hcnt_vil, plan_stock_open_core_one_chain_vil,
    plan_stock_set_asic_ticket_mask_chains_vil, plan_stock_set_asic_ticket_mask_vil,
    plan_stock_set_baud_chains_vil, plan_stock_set_baud_one_chain_vil, plan_stock_set_baud_vil,
    plan_stock_set_hcnt_chains_vil, plan_stock_set_hcnt_vil, plan_stock_software_set_address,
    stock_asicboost_admitted, stock_asicboost_slot_from_solution_idx,
    stock_asicboost_version_for_solution, stock_asicboost_version_reg,
    stock_asicboost_version_words, stock_bc_busy_wait_step, stock_bc_post_trigger_wait_budget,
    stock_bc_pre_ready_step, stock_bc_ready, stock_bc_set_config_buffer_writes,
    stock_bc_set_config_trigger_write, stock_bc_set_config_write_sequence,
    stock_bc_vil_cmd_buffer_writes, stock_bc_vil_cmd_trigger_write, stock_bc_write_command,
    stock_bc_write_merge_host_baud, stock_bc_write_requires_busy_wait, stock_bitmain_crc5,
    stock_buffer_space_ready, stock_buffer_space_wait_step, stock_calculate_core_number,
    stock_cold_boot_composition_is_phase4b_admitted, stock_cold_boot_inventory_counts,
    stock_dev_timeout_auto, stock_dhash_midstate_count, stock_dhash_with_midstate_mode,
    stock_fan_control_full, stock_fan_control_value, stock_fpga_header_scalar_word,
    stock_init_uart_bauddiv, stock_open_core_bc_nullwork_enable,
    stock_open_core_bc_nullwork_prelude, stock_open_core_buffer_timeout_continues_to_dhash_exit,
    stock_open_core_buffer_timeout_skips_nullwork_enable,
    stock_open_core_buffer_timeout_skips_remaining_tw, stock_open_core_dhash_entry,
    stock_open_core_dhash_exit, stock_open_core_dummy_tw_words, stock_open_core_gateblk_misc_value,
    stock_open_core_sim_write_trace, stock_sensor_calc_offset, stock_sensor_get_local,
    stock_sensor_get_remote_c, stock_set_baud_misc_value, stock_set_pwm_percent_clamped,
    stock_shutdown_bc_disable_nullwork, stock_time_out_control_reg, StockBcBusyWaitStep,
    StockBcPreReadyStep, StockBcSetConfigPlan, StockBcVilCmdPlan, StockBufferSpaceWaitStep,
    StockColdBootCompositionParams, StockColdBootLibraryStep, StockDhashMidstateMode,
    StockDmaJobPlan, StockDmaJobPlanError, StockOpenCoreOp, StockOpenCoreSimReport,
    StockOpenCoreSimState, StockSetBaudOp, StockSoftwareSetAddressOp, StockTimeOutControlScale,
    STOCK_ASICBOOST_BIP320_MASK, STOCK_ASICBOOST_SLOT_BIT_SHIFT, STOCK_ASICBOOST_SLOT_COUNT,
    STOCK_ASICBOOST_VERSION_REGS, STOCK_ASIC_TICKET_MASK_REG, STOCK_BC_BUSY_BIT,
    STOCK_BC_CHAIN_FIELD_CLEAR, STOCK_BC_POST_TRIGGER_POLL_MS,
    STOCK_BC_POST_TRIGGER_WAIT_MAX_ATTEMPTS, STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS,
    STOCK_BC_SET_CONFIG_SETTLE_US, STOCK_BC_WRITE_TRIGGER_OR, STOCK_BM1387_MISC_CTRL_REG,
    STOCK_BM1387_SET_CONFIG_PLL_REG, STOCK_COLD_BOOT_INTER_STAGE_MS,
    STOCK_COLD_BOOT_OPEN_CORE_SETTLE_MS, STOCK_DHASH_MIDSTATE_COUNT_MASK,
    STOCK_DHASH_MIDSTATE_COUNT_SHIFT, STOCK_DMA_JOB_SLOT_SIZE, STOCK_DMA_MERKLE_BRANCH_LEN,
    STOCK_HCNT_REG, STOCK_INIT_ASIC_TICKET_MASK, STOCK_INIT_UART_BAUDDIV_MAX,
    STOCK_INIT_UART_BAUD_NUMER_A, STOCK_INIT_UART_BAUD_NUMER_B, STOCK_INIT_UART_BAUD_SCALE,
    STOCK_OPEN_CORE_BC_NULLWORK_ENABLE_BIT, STOCK_OPEN_CORE_BC_NULLWORK_PRELUDE_BIT,
    STOCK_OPEN_CORE_BC_PRELUDE_AND, STOCK_OPEN_CORE_BC_PRELUDE_SETTLE_US,
    STOCK_OPEN_CORE_BUFFER_POLL_US, STOCK_OPEN_CORE_BUFFER_WAIT_MAX_ATTEMPTS,
    STOCK_OPEN_CORE_DEFAULT_BAUD_DIV_LOW5, STOCK_OPEN_CORE_DEFAULT_MULTI_VERSION,
    STOCK_OPEN_CORE_DHASH_CLEAR_MASK, STOCK_OPEN_CORE_DHASH_VIL_BIT,
    STOCK_OPEN_CORE_DUMMY_WORK_COUNT, STOCK_OPEN_CORE_FIRST_WORK_TYPE,
    STOCK_OPEN_CORE_GATEBLK_SETTLE_US, STOCK_OPEN_CORE_GATEBLK_VALUE_BASE,
    STOCK_OPEN_CORE_REST_WORK_TYPE, STOCK_REG_BC_COMMAND_BUFFER, STOCK_REG_BC_COMMAND_BUFFER_W1,
    STOCK_REG_BC_COMMAND_BUFFER_W2, STOCK_REG_BC_WRITE_COMMAND, STOCK_REG_BUFFER_SPACE,
    STOCK_REG_DHASH_ACC_CONTROL, STOCK_REG_FAN_CONTROL, STOCK_REG_HASH_COUNTING_NUMBER,
    STOCK_REG_TIME_OUT_CONTROL, STOCK_REG_TW_WRITE_COMMAND, STOCK_SENSOR_KELVIN_C,
    STOCK_SENSOR_OFFSET_COEF, STOCK_SENSOR_RAW_BIAS, STOCK_SENSOR_REMOTE_BIAS,
    STOCK_SENSOR_REMOTE_DIV, STOCK_SENSOR_REMOTE_SCALE, STOCK_SET_BAUD_MISC_FIXED,
    STOCK_SET_BAUD_POST_ALL_CHAINS_SETTLE_US, STOCK_SET_CONFIG_HDR_BCAST,
    STOCK_SET_CONFIG_HDR_UNICAST, STOCK_SET_CONFIG_LEN, STOCK_SOFTWARE_SET_ADDRESS_DWELL_MS,
    STOCK_SOFTWARE_SET_ADDRESS_INACTIVE_REPEATS, STOCK_SOFTWARE_SET_ADDRESS_INTERVAL,
    STOCK_TIMEOUT_CORE_TICKS, STOCK_TIMEOUT_MAX, STOCK_TIMEOUT_SCALE_DEN, STOCK_TIMEOUT_SCALE_NUM,
    STOCK_TIME_OUT_CONTROL_ENABLE, STOCK_TIME_OUT_CONTROL_MASK, STOCK_VIL_CHAIN_INACTIVE_HDR,
    STOCK_VIL_SET_ADDRESS_HDR, STOCK_VIL_SHORT_CMD_LEN,
};
pub use ticket_mask::{
    bit_reverse_u32_bytewise, compute_ticket_mask_policy, largest_power_of_two_le,
    resolve_ticket_mask, ticket_mask_encoding_for_chip_id, ticket_mask_esp_miner_pow2_floor,
    ticket_mask_from_difficulty, ticket_mask_register_for_chip_id,
    try_ticket_mask_encoding_for_chip_id, TicketMaskEncoding, TicketMaskPolicy,
    TicketMaskPolicyError, TICKET_MASK_REG_BM1387, TICKET_MASK_REG_BM1397PLUS,
};
pub use voltage_rail::{
    admit_dspic_firmware_for_energize, admit_pic1704_short_form_set_mv,
    admit_voltage_rail_mutation, admit_voltage_rail_op, chip_driver_set_voltage_admission,
    energize_voltage_rail, host_adapter_rail, is_hard_refuse, is_tas5782m_i2c_addr,
    pic16_dac_to_mv, pic16_mv_to_dac, pic1704_short_form_has_writable_voltage_setpoint,
    refuse_degraded_firmware, refuse_wrong_mode, resolve_voltage_rail_adapter,
    safe_off_voltage_rail, stock_pic16_init_dac, stock_pic16_operating_dac,
    unsupported_voltage_path, voltage_ownership_for_asic, voltage_rail_adapter_for_controller,
    voltage_rail_io_error, walk_down_and_safe_off_voltage_rail, BackendVoltageRail,
    RecordingVoltageRail, Tas5782mVoltageRail, UnsupportedExternalDacRail, VoltageOwnership,
    VoltageRail, VoltageRailAdapterKind, VoltageRailError, VoltageRailOp, VoltageRefuseReason,
    DSPIC_DEGRADED_FW, DSPIC_PROVEN_APP_FW, PIC16_MIN_SAFE_DAC, PIC16_VOLTAGE_DIVISOR,
    PIC16_VOLTAGE_OFFSET, PIC1704_REG_CONTROL, PIC1704_REG_VOLTAGE_H, PIC1704_REG_VOLTAGE_L,
    STOCK_PIC16_INIT_MV, STOCK_PIC16_OPERATING_MV, TAS5782M_I2C_ADDRS,
};
pub use work_dispatch_safety::{
    admit_work_dispatch, build_work_dispatch_inputs, map_watchdog_safety_state,
    measured_startup_thermal_state, revocation_stops_watchdog_feed, revoke_work_dispatch,
    should_revoke_work_dispatch_for_controller_health, ControllerHeartbeatObservation,
    DispatchRevocationCause, HeartbeatRequirement, ThermalSafetyState, WatchdogSafetyState,
    WorkDispatchAdmissionPublication, WorkDispatchAdmissionReceipt, WorkDispatchLifecycle,
    WorkDispatchSafetyError, WorkDispatchSafetyInputs,
};

use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide gate for the log-tail passthrough sanitizer.
///
/// W1.4: when `true` (the default), the `/api/debug/log` endpoint masks
/// any wallet-shaped substrings before serializing the response. Setting
/// this to `false` is an opt-out for operators with structured-log
/// collectors that need raw addresses.
///
/// Per-call masking on `worker=` / `username=` / `wallet=` log fields is
/// independent of this flag and cannot be disabled via the config. To see
/// raw addresses on the wire, use `RUST_LOG=trace` (TRACE-level only,
/// gated by EnvFilter, off by default in production).
static MASK_LOGS_ENABLED: AtomicBool = AtomicBool::new(true);

/// Set the process-wide log-tail mask flag. Called once at daemon startup
/// from the [logging] section of dcentrald.toml.
pub fn set_mask_logs(enabled: bool) {
    MASK_LOGS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Read the process-wide log-tail mask flag.
pub fn mask_logs_enabled() -> bool {
    MASK_LOGS_ENABLED.load(Ordering::Relaxed)
}
