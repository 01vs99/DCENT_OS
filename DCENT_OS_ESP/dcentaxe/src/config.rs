// DCENT_axe Configuration
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0

use dcentaxe_hal::board::{
    AccessoryMode, BitAxeModel, BoardConfig, BoardHardwareConfig, BoardVersionProfile,
    FanControllerKind, FanPopulation, PowerControllerKind, TempSensorKind,
};
use dcentaxe_stratum::StratumConfig;

#[cfg(feature = "lora")]
use dcentaxe_lora::config::MeshConfig;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_schedule_entry_enabled() -> bool {
    true
}

pub(crate) fn default_model_for_build() -> BitAxeModel {
    if cfg!(feature = "bitaxe-gt-touch") {
        BitAxeModel::GtTouch
    } else if cfg!(feature = "bitaxe-touch") {
        BitAxeModel::Touch
    } else if cfg!(feature = "bitaxe-max") {
        BitAxeModel::Max
    } else if cfg!(feature = "bitaxe-ultra") {
        BitAxeModel::Ultra
    } else if cfg!(feature = "bitaxe-supra") {
        BitAxeModel::Supra
    } else if cfg!(feature = "bitaxe-gamma-duo") {
        BitAxeModel::GammaDuo
    } else if cfg!(feature = "bitaxe-gamma") {
        BitAxeModel::Gamma
    } else if cfg!(feature = "bitaxe-gt") {
        BitAxeModel::GammaTurbo
    } else if cfg!(feature = "bitaxe-hex-ultra") {
        BitAxeModel::HexUltra
    } else if cfg!(feature = "bitaxe-hex-supra") {
        BitAxeModel::HexSupra
    } else if cfg!(feature = "nerdnos") {
        BitAxeModel::NerdNOS
    } else if cfg!(feature = "nerdaxe-gamma") {
        BitAxeModel::NerdAxeGamma
    } else if cfg!(feature = "nerdaxe") {
        BitAxeModel::NerdAxe
    } else if cfg!(feature = "nerdqaxe-plus") {
        BitAxeModel::NerdQaxePlus
    } else if cfg!(feature = "nerdqaxe-pp") {
        BitAxeModel::NerdQaxePP
    } else if cfg!(feature = "nerdoctaxe-plus") {
        BitAxeModel::NerdOctaxePlus
    } else if cfg!(feature = "nerdoctaxe-gamma") {
        BitAxeModel::NerdOctaxeGamma
    } else if cfg!(feature = "nerdqx") {
        BitAxeModel::NerdQX
    } else if cfg!(feature = "nerdhaxe-gamma") {
        BitAxeModel::NerdHaxeGamma
    } else if cfg!(feature = "nerdeko") {
        BitAxeModel::NerdEko
    } else if cfg!(feature = "q1370") {
        BitAxeModel::Q1370
    } else if cfg!(feature = "q1373") {
        BitAxeModel::Q1373
    } else if cfg!(feature = "dcent-axe-bm1397") {
        BitAxeModel::DcentAxeBm1397
    } else if cfg!(feature = "dcent-axe-quad-bm1397") {
        BitAxeModel::DcentAxeQuadBm1397
    } else if cfg!(feature = "dcent-axe-hex-bm1397") {
        BitAxeModel::DcentAxeHexBm1397
    } else if cfg!(feature = "hammer-bc01") {
        BitAxeModel::HammerBc01
    } else if cfg!(feature = "hammer-bc01-pro") {
        BitAxeModel::HammerBc01Pro
    } else if cfg!(feature = "hammer-bc02") {
        BitAxeModel::HammerBc02
    } else if cfg!(feature = "hammer-bc04") {
        BitAxeModel::HammerBc04
    } else if cfg!(feature = "hammer-dc02") {
        BitAxeModel::HammerDc02
    } else if cfg!(feature = "hammer-dc04") {
        BitAxeModel::HammerDc04
    } else if cfg!(feature = "hammer-dc06") {
        BitAxeModel::HammerDc06
    } else if cfg!(feature = "lucky-lv06") {
        BitAxeModel::LuckyLv06
    } else if cfg!(feature = "lucky-lv07") {
        BitAxeModel::LuckyLv07
    } else if cfg!(feature = "lucky-lv08") {
        // A missing arm here makes a lucky-lv08 image silently build as the
        // final `Gamma` fallback (wrong chip, wrong count, wrong envelope) —
        // the exact defect R2 flagged for every new SKU family.
        BitAxeModel::LuckyLv08
    } else if cfg!(feature = "bitforge-nano") {
        // Same reason as the Lucky arm above: without this, a bitforge-nano
        // image builds as the `Gamma` fallback — one ASIC instead of two, and
        // an envelope that is not this board's.
        BitAxeModel::BitForgeNano
    } else if cfg!(feature = "bitaxe-naja") {
        // Same reason again, and the consequence is worse here: the `Gamma`
        // fallback is BM1370 silicon at 1150 mV, and this board carries BM1373
        // dies whose ceiling is 1200 mV with a 1010 mV default.
        BitAxeModel::BitaxeNaja
    } else {
        BitAxeModel::Gamma
    }
}

pub(crate) fn default_profile_for_build() -> &'static BoardVersionProfile {
    BoardVersionProfile::default_for_model(default_model_for_build())
}

// ── CFG-7 — single source of truth for the fan auto-control default ──────────
//
// Three sites used to hardcode the fan target temp independently
// (`DcentAxeConfig::default`, `migrate_axeos_config`, and the provisioning
// `build_submission`). The value `0` means MANUAL fan mode (runtime checks
// `cfg.fan_target_temp_c == 0` and falls back to `fan_speed_pct`); any non-zero
// value enables the auto curve at that target °C. `0` is the maximally
// default-preserving reconciliation: factory-default and AxeOS migration already
// used `0`, so centralizing on `0` changes only the provisioning outlier (which
// previously diverged at 65) and never alters the persisted factory default.
//
// Operator policy lever: flipping this to ~60-65 adopts the  home-unit
// "quiet-first" auto-curve posture fleet-wide in ONE line — and because all three
// paths now reference this const, they move together and can never drift again.
pub const DEFAULT_FAN_TARGET_TEMP_C: u8 = 0;

// ── CFG-5 — single classifier for BIP320/ASICBoost version-rolling ───────────
//
// The BM1397 (BitAxe Max) does NOT support BIP320 version rolling; every other
// supported chip (BM1366/1368/1370) does. This used to be re-derived at two
// sites with divergent sources of truth (`migrate_axeos_config` keyed off the
// RESOLVED profile while persisting the STORED asic_model string;
// `build_submission` hardcoded `true`). Centralize the decision so both compute
// it from the SAME final asic_model string they persist, eliminating the case
// where a stored asicmodel and a board_version-resolved profile disagree. The
// magic string "BM1397" is preserved verbatim.
pub fn chip_rolls_versions(asic_model: &str) -> bool {
    asic_model.trim() != "BM1397"
}

// ── Lucky-enablement SPEC §1.2 / §3 — inbound identity helpers ───────────────

/// SPEC §1.2: true iff this raw inbound boardversion is one of the vendor
/// `A`-suffixed spellings (`300A`/`301A`/`302A`, case-insensitive) that request
/// an anonymous `mining.subscribe` (empty params, no user-agent). The suffix is
/// NOT hardware — it maps onto the same board rows — so it is modeled as the
/// `anonymous_subscribe` config flag, latched before canonicalization erases it.
pub fn board_version_requests_anonymous_subscribe(board_version: &str) -> bool {
    matches!(
        board_version.trim().to_ascii_lowercase().as_str(),
        "300a" | "301a" | "302a"
    )
}

/// Outcome of the boot-time fail-closed identity gate (SPEC §3 steps 4–5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityGateOutcome {
    /// The stored identity already resolves through the normal ladder exactly
    /// as `resolve_identity` would — nothing to change, boot proceeds.
    Proceed,
    /// The tuple resolution CORRECTS the naive `board_version`-first lookup
    /// (e.g. stored vendor identity `302`/`lv08` → Lucky LV08 `2008`, or the
    /// probe proved the three-regulator LV08 signature). The caller must adopt
    /// this canonical profile into the config and persist it.
    AdoptProfile(&'static BoardVersionProfile),
    /// SPEC §3 step 5: the identity is ambiguous and the probe could not
    /// settle it. The device must still boot, identify, serve the dashboard
    /// and report WHY — but mining stays disabled and the core rail is never
    /// brought up (the caller routes this through the existing
    /// `mining_permitted`/`mining_block_reason` refusal mechanism, the same
    /// path the Hammer fail-closed rows use).
    RefuseToEnergize { reason: String },
}

/// Outcome of the separate, post-resolution Hammer DC address-strap gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityStrapGateOutcome {
    Proceed,
    RefuseToEnergize { reason: String },
}

/// Verify an already-resolved Hammer DC row against its read-only TMP75
/// address strap.
///
/// This is intentionally separate from [`resolve_identity_gate`]: that gate
/// probes only its Ambiguous arm, while this one verifies a Resolved row. The
/// model check precedes the closure call because 0x48 and 0x4C are unrelated
/// peripherals on non-Hammer boards.
pub fn verify_identity_strap_gate(
    model: BitAxeModel,
    expected_addr: Option<u8>,
    probe: impl FnOnce(u8) -> Option<dcentaxe_hal::hammer_strap::HammerStrapProbeVerdict>,
) -> IdentityStrapGateOutcome {
    use dcentaxe_hal::hammer_strap::HammerStrapProbeVerdict;

    if !model.is_hammer_dc() {
        return IdentityStrapGateOutcome::Proceed;
    }

    let Some(expected_addr) = expected_addr else {
        return IdentityStrapGateOutcome::RefuseToEnergize {
            reason: format!(
                "resolved Hammer DC model {model:?} has no registered identity strap; \
                 refusing to energize"
            ),
        };
    };

    match probe(expected_addr) {
        Some(HammerStrapProbeVerdict::Match) => IdentityStrapGateOutcome::Proceed,
        Some(HammerStrapProbeVerdict::Absent) => IdentityStrapGateOutcome::RefuseToEnergize {
            reason: format!(
                "Hammer DC identity strap 0x{expected_addr:02X} did not ACK; \
                 refusing to energize"
            ),
        },
        Some(HammerStrapProbeVerdict::Mismatch { observed_mask }) => {
            IdentityStrapGateOutcome::RefuseToEnergize {
                reason: format!(
                    "Hammer DC identity strap mismatch: expected 0x{expected_addr:02X}, \
                     observed candidate mask 0x{observed_mask:02X}; refusing to energize"
                ),
            }
        }
        None => IdentityStrapGateOutcome::RefuseToEnergize {
            reason: format!(
                "Hammer DC identity strap 0x{expected_addr:02X} could not be probed; \
                 refusing to energize"
            ),
        },
    }
}

/// Boot-time fail-closed identity gate (SPEC §3).
///
/// Pure decision logic over `board::resolve_identity` plus an injected probe:
/// * `Resolved` → [`IdentityGateOutcome::Proceed`] when the naive
///   `BoardVersionProfile::find(board_version)` already lands on the same row;
///   otherwise [`IdentityGateOutcome::AdoptProfile`] (the resolver corrected a
///   colliding/vendor identity).
/// * `Ambiguous { probe_lv08: true }` → run `probe` (the ONLY branch that may
///   touch the read-only PMBus 0x7F/0x14 probe — `power.rs` documents that
///   caller contract, and taking the probe as a closure enforces it
///   structurally: no other branch can invoke it):
///     - `TripleRegulatorLv08` ⇒ adopt the LV08 row (`2008`),
///     - `NoSecondaryRegulators` ⇒ genuine BitAxe ⇒ keep the legacy profile,
///     - `Inconclusive` (or probe unavailable, `None`) ⇒ REFUSE TO ENERGIZE.
/// * `Ambiguous { probe_lv08: false }` → refuse (no disambiguation available).
/// * `Unknown` → `Proceed`; the existing unrecognized-identity refusal in
///   `validate_safety` already fails that closed.
///
/// Host-tested in `identity_gate_tests` below (compiled via `dcentaxe-core`).
pub fn resolve_identity_gate(
    board_version: &str,
    device_model: &str,
    miner_model: &str,
    probe: impl FnOnce() -> Option<dcentaxe_hal::tps546_guard::LuckyProbeVerdict>,
) -> IdentityGateOutcome {
    use dcentaxe_hal::board::{resolve_identity, IdentityVerdict};
    use dcentaxe_hal::tps546_guard::LuckyProbeVerdict;

    match resolve_identity(board_version, device_model, miner_model) {
        IdentityVerdict::Resolved(profile) => {
            let naive = BoardVersionProfile::find(board_version);
            if naive.map(|row| row.board_version) == Some(profile.board_version) {
                IdentityGateOutcome::Proceed
            } else {
                // The tuple resolution disagrees with (or supplements) the
                // naive board_version lookup — re-anchor to the &'static row.
                match BoardVersionProfile::find(profile.board_version) {
                    Some(row) => IdentityGateOutcome::AdoptProfile(row),
                    // Unreachable for any row resolve_identity can return, but
                    // never fall back to the naive (possibly colliding) row.
                    None => IdentityGateOutcome::RefuseToEnergize {
                        reason: format!(
                            "board identity resolved to unregistered board_version '{}' — \
                             refusing to energize (fail-closed)",
                            profile.board_version
                        ),
                    },
                }
            }
        }
        IdentityVerdict::Ambiguous { reason, probe_lv08 } => {
            if !probe_lv08 {
                return IdentityGateOutcome::RefuseToEnergize {
                    reason: format!(
                        "board identity ambiguous ({reason}); no disambiguation probe \
                         available — refusing to energize (SPEC §3 fail-closed)"
                    ),
                };
            }
            match probe() {
                Some(LuckyProbeVerdict::TripleRegulatorLv08) => {
                    match BoardVersionProfile::find("2008") {
                        Some(row) => IdentityGateOutcome::AdoptProfile(row),
                        None => IdentityGateOutcome::RefuseToEnergize {
                            reason: "LV08 probe matched but board_version 2008 is not \
                                     registered — refusing to energize"
                                .to_string(),
                        },
                    }
                }
                Some(LuckyProbeVerdict::NoSecondaryRegulators) => {
                    // Neither LV08-only address answered ⇒ genuine BitAxe ⇒
                    // the legacy board_version resolution stands unchanged.
                    IdentityGateOutcome::Proceed
                }
                Some(LuckyProbeVerdict::Inconclusive) | None => {
                    IdentityGateOutcome::RefuseToEnergize {
                        reason: format!(
                            "board identity ambiguous ({reason}); LV08 secondary-regulator \
                             probe inconclusive — refusing to energize (SPEC §3 step 5 \
                             fail-closed; dashboard stays up, mining disabled)"
                        ),
                    }
                }
            }
        }
        IdentityVerdict::Unknown => IdentityGateOutcome::Proceed,
    }
}

// ── CFG-2 — bounded body-accumulation decision helpers ───────────────────────
//
// The provisioning POST handler must accumulate a possibly-multi-segment request
// body up to a hard cap (`nvs_config::MAX_CONFIG_SIZE`) instead of doing a single
// fixed-size `req.read`, which embedded-io can truncate. The req I/O loop itself
// is esp-idf and review-only, but the accept/overflow DECISION is pure and pinned
// here so the cap boundary is host-tested.

/// True iff `incoming` more bytes can be appended to a buffer that already holds
/// `received` bytes without exceeding `max`. Used to REJECT (not silently
/// truncate) an over-cap body.
pub fn body_read_capacity_ok(received: usize, incoming: usize, max: usize) -> bool {
    received.saturating_add(incoming) <= max
}

/// Clamp the next per-read request length so it never overshoots the remaining
/// capacity (`max - received`). Returns 0 once the cap is reached, which the
/// loop treats as "stop reading / reject if more data is pending".
pub fn next_take(received: usize, max: usize) -> usize {
    max.saturating_sub(received)
}

// ── CFG-3 — NVS blob read-back-verify decision ───────────────────────────────
//
// `save_config` writes the config blob then reads it straight back and compares
// byte-for-byte, surfacing a torn/short write as an error rather than a silent
// "saved OK". The byte-compare is pure and pinned here.

/// True iff the bytes read back from NVS exactly equal the bytes written
/// (length + content). A short/truncated or mutated read-back verifies false.
pub fn blob_write_verified(written: &[u8], read_back: &[u8]) -> bool {
    written == read_back
}

// ── CFG-10 — config-schema forward/backward version decision ─────────────────
//
// `migrate_config` must make an explicit decision when a stored blob's
// `schema_version` differs from the firmware's `SCHEMA_VERSION`, including the
// downgrade case where a FUTURE blob (stored > current) is read by older
// firmware. The decision is pure and pinned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaAction {
    /// Stored version equals firmware version — nothing to do.
    Current,
    /// Stored version is OLDER than firmware — run additive upgrade arms.
    MigrateForward(u8),
    /// Stored version is NEWER than firmware (a downgrade) — refuse to trust the
    /// future shape; clamp the marker and rely on serde to have dropped unknown
    /// fields.
    RefuseFuture,
}

/// Classify a stored schema version against the firmware's current version.
pub fn schema_action(stored: u8, current: u8) -> SchemaAction {
    use std::cmp::Ordering;
    match stored.cmp(&current) {
        Ordering::Equal => SchemaAction::Current,
        Ordering::Less => SchemaAction::MigrateForward(stored),
        Ordering::Greater => SchemaAction::RefuseFuture,
    }
}

/// Bring a just-loaded config up to the current schema version.
///
/// Per-version steps go here. The function is a no-op when the stored blob
/// already matches `SCHEMA_VERSION`. Keep the arms additive — old firmware
/// may still be running in the field, so migrations must stay idempotent.
///
/// CFG-10 (moved here 2026-06-29): the real forward-migration MUTATION now lives
/// in this host-compiled `config` module (the single-source `#[path]` pattern)
/// so it is unit-tested on the host gate, not only string-matched. The NVS
/// loader (`nvs_config::load_config`, which pulls in `esp-idf-svc` and so cannot
/// host-compile) calls `crate::config::migrate_config` on every loaded blob.
pub fn migrate_config(config: &mut DcentAxeConfig) {
    let from = config.schema_version;
    // CFG-10: make the forward/backward decision explicit, including the
    // downgrade case (a FUTURE blob whose schema_version > SCHEMA_VERSION read
    // by older firmware) which the old code loaded as-is.
    match schema_action(from, SCHEMA_VERSION) {
        SchemaAction::Current => {}
        SchemaAction::MigrateForward(_) => {
            // Schema 0 → 1 — introduce the `schema_version` field itself.
            // Any config written by a pre-schema build deserialises with
            // schema_version = 0 (serde default), so we just stamp the current
            // version. No data shape changes required.
            if from < 1 {
                log::info!("NVS: migrating config schema {} → 1", from);
                config.schema_version = 1;
            }
            // Future additive upgrade arms: if from < 2 { ... }

            // Defensive: if a future arm forgets to advance the marker, stamp it
            // so the loader never believes it round-tripped an older shape.
            if config.schema_version < SCHEMA_VERSION {
                config.schema_version = SCHEMA_VERSION;
            }
        }
        SchemaAction::RefuseFuture => {
            // A blob written by NEWER firmware. We cannot know its added fields;
            // serde has already dropped any keys our struct doesn't declare
            // during deserialize. Clamp the stored marker DOWN to our current
            // version so the loader never claims to round-trip the future shape
            // (least-destructive: known fields — WiFi creds, stratum — survive).
            // The stricter escalation, when a real field-MEANING change lands, is
            // to treat the affected subset as first-boot / re-provision.
            log::warn!(
                "NVS: config schema_version={} is NEWER than firmware {} — refusing \
                 future shape, clamping marker (known fields preserved)",
                from,
                SCHEMA_VERSION
            );
            config.schema_version = SCHEMA_VERSION;
        }
    }
}

// ── CFG-12 — reject an unconnectable pool endpoint at provisioning time ───────
//
// `build_submission` validated `wifi_ssid` and `worker` but did NO check on the
// pool endpoint. The JSON path defaults an absent `pool_url` to "" and BOTH
// paths accept `pool_port == 0` (form `"0".parse().unwrap_or(...)` → 0; JSON
// `get_u16` → 0 when absent). Those raw values were saved to NVS and the captive
// portal rendered "Configuration Saved!" even though the miner can NEVER connect
// (`StratumClient::check_pool_reachable` builds "host:port" and `TcpStream`
// connects). That is a silent-failure + dishonest-success defect.
//
// Reject the two unconnectable shapes at SUBMIT time so the caller surfaces the
// error (HTTP 400) instead of a false success. Conservative on purpose: it
// accepts every shape the live endpoint parser
// (`dcentaxe_stratum::endpoint_host_from_url`) resolves to a non-empty host —
// bare `host`, `host:port`, `stratum+tcp://host`, `sv2://host`, `user:pass@host`,
// `host/path`, etc. — and ONLY adds three rejects:
//   * empty / whitespace-only url               → reject
//   * port == 0                                 → reject
//   * a scheme with no host (e.g. "stratum+tcp://") → reject
// It deliberately does NOT reject a url merely containing a space or other
// "looks odd" shapes: DNS / `connect` is the real authority and over-rejection
// would lock a legitimate operator value out of provisioning.
pub fn validate_pool_endpoint(url: &str, port: u16) -> Result<(), String> {
    if url.trim().is_empty() {
        return Err("Pool URL is required".to_string());
    }
    if port == 0 {
        return Err("Pool port must be non-zero".to_string());
    }
    if dcentaxe_stratum::endpoint_host_from_url(url).is_empty() {
        return Err("Pool URL has no host (scheme without a hostname)".to_string());
    }
    Ok(())
}

// ── CFG-8 — UTF-8-correct percent/`+` URL decoder ────────────────────────────
//
// The provisioning form path (`application/x-www-form-urlencoded`) decodes SSIDs
// / passwords / pool URLs. The old decoder pushed each percent-decoded byte as a
// Unicode scalar (`byte as char`, Latin-1), corrupting any multi-byte UTF-8
// value encoded as several `%XX`. Decode into a byte buffer and reassemble UTF-8
// at the end via `from_utf8_lossy`, so multi-byte sequences round-trip and a
// malformed sequence yields the replacement char instead of mojibake. ASCII
// input is byte-identical to the old behavior. Pure logic, host-tested.
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                // Need exactly two hex digits following '%'.
                if i + 2 < bytes.len() {
                    let hi = (bytes[i + 1] as char).to_digit(16);
                    let lo = (bytes[i + 2] as char).to_digit(16);
                    if let (Some(hi), Some(lo)) = (hi, lo) {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                }
                // Malformed or truncated `%XX` — emit the literal bytes we saw so
                // the value is not silently lost (mirrors the old fallback).
                out.push(b'%');
                if i + 1 < bytes.len() {
                    out.push(bytes[i + 1]);
                    if i + 2 < bytes.len() {
                        out.push(bytes[i + 2]);
                        i += 3;
                    } else {
                        i += 2;
                    }
                } else {
                    i += 1;
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone, Copy)]
pub struct StockAsicSettings {
    pub default_frequency: u16,
    pub frequency_options: &'static [u16],
    pub default_voltage_mv: u16,
    pub voltage_options: &'static [u16],
}

const BM1397_FREQUENCIES: &[u16] = &[400, 425, 450, 475, 485, 500, 525, 550, 575, 600];
const BM1397_VOLTAGES: &[u16] = &[1100, 1150, 1200, 1250, 1300, 1350, 1400, 1450, 1500];
const BM1366_FREQUENCIES: &[u16] = &[400, 425, 450, 475, 485, 500, 525, 550, 575];
const BM1366_VOLTAGES: &[u16] = &[1100, 1150, 1200, 1250, 1300];
const BM1368_FREQUENCIES: &[u16] = &[400, 425, 450, 475, 485, 490, 500, 525, 550, 575];
const BM1368_VOLTAGES: &[u16] = &[1100, 1150, 1166, 1200, 1250, 1300];
const BM1370_FREQUENCIES: &[u16] = &[400, 490, 525, 550, 600, 625];
const BM1370XP_FREQUENCIES: &[u16] = &[350, 375, 380, 400, 410];
const BM1370_VOLTAGES: &[u16] = &[1000, 1060, 1100, 1150, 1200, 1250];
// BM1373 (Hammer BC01 Pro): vendor ceiling is 500 MHz and 1.15 V per chip —
// deliberately narrow, conservative option lists (driver is a fail-closed
// scaffold; these only bound the UI until hardware bring-up).
const BM1373_FREQUENCIES: &[u16] = &[300, 350, 400, 450, 500];
const BM1373_VOLTAGES: &[u16] = &[1000, 1050, 1100, 1150];
// MSBT0501 (Hammer DC0x, Scrypt). PER-ASIC millivolts — the rail is
// per-ASIC x chip_count (DC02 x2, DC04 x4, DC06 x6). The vendor per-chip
// window is identical on all three models: 500 / 635 (stock) / 750 mV.
// Frequencies never exceed the vendor STOCK default of 2300 MHz; the firmware
// clamp's 2600 MHz top and the web UI's 2400 are policy numbers, not proven
// safe operating points, and the driver refuses to run either way.
// Q1373 (BM1373 on the Q1370 board). Upstream's own tables, which are tighter
// than the generic BM1373 lists: 250-550 MHz and 980-1080 mV, against an
// absMax of 700 MHz / 1200 mV. The option list stops at the vendor table's top,
// not at the absolute ceiling.
const Q1373_FREQUENCIES: &[u16] = &[250, 300, 350, 400, 475, 550];
const Q1373_VOLTAGES: &[u16] = &[980, 1000, 1010, 1030, 1050, 1080];
// NerdQX (BM1370). Upstream's table starts at 495 MHz / 1085 mV (its eco point)
// and reaches 1000 MHz / 1350 mV — but ONLY on a board whose TMP451 mux
// answered. With no mux probe wired yet, the options stop at the clamped
// 495 MHz / 1150 mV that upstream itself falls back to. Widening this list is
// gated on the probe, not on a config edit.
const NERDQX_FREQUENCIES: &[u16] = &[495];
const NERDQX_VOLTAGES: &[u16] = &[1085, 1120, 1130, 1140, 1150];
// NerdAxe-γ carries its own tables rather than the shared BM1370 pair.
// `m_asicVoltages` is 1120..=1200 in 10 mV steps, so the shared
// BM1370_VOLTAGES would offer this board both 1000 mV (below its
// characterized floor — the under-volt direction the multiphase floor test
// exists to prevent) and 1250 mV (above its ceiling). Upstream
// `nerdaxegamma.cpp`, verbatim.
const NERDAXE_GAMMA_FREQUENCIES: &[u16] = &[500, 515, 525, 550, 575];
const NERDAXE_GAMMA_VOLTAGES: &[u16] = &[1120, 1130, 1140, 1150, 1160, 1170, 1180, 1190, 1200];
const MSBT0501_FREQUENCIES: &[u16] = &[700, 1200, 1600, 2000, 2300];
const MSBT0501_VOLTAGES: &[u16] = &[500, 550, 600, 635, 700, 750];

pub fn stock_asic_settings(model: BitAxeModel) -> StockAsicSettings {
    match model {
        BitAxeModel::Max
        | BitAxeModel::DcentAxeBm1397
        | BitAxeModel::DcentAxeQuadBm1397
        | BitAxeModel::DcentAxeHexBm1397 => StockAsicSettings {
            default_frequency: 425,
            frequency_options: BM1397_FREQUENCIES,
            default_voltage_mv: 1400,
            voltage_options: BM1397_VOLTAGES,
        },
        // NerdAxe needs NO tables of its own: upstream `nerdaxe.cpp` declares
        // `m_asicFrequencies = {400,425,450,475,485,500,525,550,575}` and
        // `m_asicVoltages = {1100,1150,1200,1250,1300}` — byte-identical to
        // BM1366_FREQUENCIES / BM1366_VOLTAGES — with `m_defaultAsicFrequency
        // = 485` and `m_defaultAsicVoltageMillis = 1200`, which is this arm
        // exactly. It only looked like a special case while it was mislabelled
        // BM1370.
        BitAxeModel::Ultra | BitAxeModel::HexUltra | BitAxeModel::NerdAxe => StockAsicSettings {
            default_frequency: 485,
            frequency_options: BM1366_FREQUENCIES,
            default_voltage_mv: 1200,
            voltage_options: BM1366_VOLTAGES,
        },
        BitAxeModel::Supra
        | BitAxeModel::HexSupra
        | BitAxeModel::NerdQaxePlus
        // NerdOCTAXE+ is 8x BM1368 and inherits the NerdQAxe+ tables upstream.
        | BitAxeModel::NerdOctaxePlus => {
            StockAsicSettings {
                default_frequency: 490,
                frequency_options: BM1368_FREQUENCIES,
                default_voltage_mv: 1166,
                voltage_options: BM1368_VOLTAGES,
            }
        }
        BitAxeModel::Gamma
        | BitAxeModel::GammaTurbo
        | BitAxeModel::Touch
        | BitAxeModel::GtTouch
        | BitAxeModel::NerdQaxePP
        // NerdOCTAXE-γ is 8x BM1370 and inherits the NerdQAxe++ tables, as do
        // NerdHaxe-γ (6x), NerdEKO (12x) and the Q1370 (4x). NerdQX is BM1370
        // too but is NOT here: it carries its own frequency/voltage tables
        // starting at 1085 mV, and its unproven-board ceiling is 495 MHz /
        // 1150 mV — see the arm below.
        | BitAxeModel::NerdOctaxeGamma
        | BitAxeModel::NerdHaxeGamma
        | BitAxeModel::NerdEko
        | BitAxeModel::Q1370 => StockAsicSettings {
            default_frequency: 525,
            frequency_options: BM1370_FREQUENCIES,
            default_voltage_mv: 1150,
            voltage_options: BM1370_VOLTAGES,
        },
        // BitForge Nano needs NO tables of its own: 2x BM1370 in parallel on
        // one rail is the same shape as the Gamma Duo, and the shared BM1370
        // options already top out at 1250 mV — below this board's 1350 mV
        // ceiling and far below the 1400 mV its vendor Kconfig defaults to
        // (see `BoardConfig::for_model`). Zero new constants.
        BitAxeModel::GammaDuo | BitAxeModel::BitForgeNano => StockAsicSettings {
            default_frequency: 400,
            frequency_options: BM1370XP_FREQUENCIES,
            default_voltage_mv: 1150,
            voltage_options: BM1370_VOLTAGES,
        },
        BitAxeModel::NerdNOS => StockAsicSettings {
            default_frequency: 400,
            frequency_options: &[300, 400],
            default_voltage_mv: 1200,
            voltage_options: &[1200],
        },
        // ── Hammer BC0x (EXPERIMENTAL): per-chip values — the series rail is
        // derived via BoardConfig.voltage_domains, never encoded here. ──
        BitAxeModel::HammerBc01 | BitAxeModel::HammerBc04 => StockAsicSettings {
            default_frequency: 525,
            frequency_options: BM1370_FREQUENCIES,
            default_voltage_mv: 1200,
            voltage_options: BM1370_VOLTAGES,
        },
        BitAxeModel::HammerBc02 => StockAsicSettings {
            default_frequency: 525,
            frequency_options: BM1370_FREQUENCIES,
            default_voltage_mv: 1225,
            voltage_options: BM1370_VOLTAGES,
        },
        BitAxeModel::HammerBc01Pro => StockAsicSettings {
            default_frequency: 400,
            frequency_options: BM1373_FREQUENCIES,
            default_voltage_mv: 1000,
            voltage_options: BM1373_VOLTAGES,
        },
        // Q1373 — BM1373 on the Q1370 board. Its own upstream tables run
        // 250-550 MHz / 980-1080 mV, tighter than the generic BM1373 lists, so
        // it gets its own options rather than borrowing the Hammer ones.
        // BitAxe Naja is the same BM1373 silicon on a 2-die board, so it takes
        // the same vendor tables and the same defaults — the ASIC sets these,
        // not the board. Zero new constants: a Naja-specific table here would
        // be an invented number, since bitaxeorg ships no firmware at all.
        BitAxeModel::Q1373 | BitAxeModel::BitaxeNaja => StockAsicSettings {
            default_frequency: 350,
            frequency_options: Q1373_FREQUENCIES,
            default_voltage_mv: 1010,
            voltage_options: Q1373_VOLTAGES,
        },
        // NerdQX — BM1370, but its own tables and, until its TMP451 mux proves
        // the board is really a QX, upstream's clamped 495 MHz / 1150 mV
        // ceiling. Defaults are the clamped values, not the nominal 777/1200.
        BitAxeModel::NerdQX => StockAsicSettings {
            default_frequency: 495,
            frequency_options: NERDQX_FREQUENCIES,
            default_voltage_mv: 1150,
            voltage_options: NERDQX_VOLTAGES,
        },
        // NerdAxe-γ — BM1370 on a narrower window than the shared BM1370
        // tables. `m_defaultAsicFrequency = 515`, `m_defaultAsicVoltageMillis
        // = 1150` (upstream `nerdaxegamma.cpp`).
        BitAxeModel::NerdAxeGamma => StockAsicSettings {
            default_frequency: 515,
            frequency_options: NERDAXE_GAMMA_FREQUENCIES,
            default_voltage_mv: 1150,
            voltage_options: NERDAXE_GAMMA_VOLTAGES,
        },
        // ── Hammer DC0x (MSBT0501, Scrypt) ──
        // 🔴 `default_voltage_mv` / `voltage_options` here are PER-ASIC, like
        // every other row. The RAIL is derived as per-ASIC x voltage_domains
        // (2/4/6), so 635 mV means 1.27 V on a DC02 and 3.81 V on a DC06.
        // Never substitute a rail figure into this table.
        // Frequency options stop AT the vendor stock default (2300 MHz): the
        // firmware clamp reaches 2600 and the web UI shows 2400, but neither is
        // bench-proven, so the list only ever goes DOWN from stock.
        BitAxeModel::HammerDc02 | BitAxeModel::HammerDc04 | BitAxeModel::HammerDc06 => {
            StockAsicSettings {
                default_frequency: 2300,
                frequency_options: MSBT0501_FREQUENCIES,
                default_voltage_mv: 635,
                voltage_options: MSBT0501_VOLTAGES,
            }
        }
        // ── Lucky Miner LVxx (BM1366) ──
        // Envelope mirrored from the already-registered board rows
        // (485 MHz / 1200 mV, options 1100-1300) — see board.rs.
        BitAxeModel::LuckyLv06 | BitAxeModel::LuckyLv07 | BitAxeModel::LuckyLv08 => {
            StockAsicSettings {
                default_frequency: 485,
                frequency_options: BM1366_FREQUENCIES,
                default_voltage_mv: 1200,
                voltage_options: BM1366_VOLTAGES,
            }
        }
    }
}

/// First-boot mining-mode intent shared with the DCENT_OS onboarding contract.
/// Pool and solo-pool both use the configured Stratum endpoint. The mesh modes
/// additionally configure the LoRa solo relay when that firmware feature is
/// present; non-LoRa builds reject those choices at provisioning time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MiningMode {
    Pool,
    Solo,
    GatewaySolo,
    MeshSolo,
}

impl Default for MiningMode {
    fn default() -> Self {
        Self::Pool
    }
}

impl MiningMode {
    pub fn from_token(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "pool" => Ok(Self::Pool),
            "solo" => Ok(Self::Solo),
            "gateway-solo" | "gateway_solo" => Ok(Self::GatewaySolo),
            "mesh-solo" | "mesh_solo" => Ok(Self::MeshSolo),
            other => Err(format!("Unsupported mining mode: {other}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pool => "pool",
            Self::Solo => "solo",
            Self::GatewaySolo => "gateway-solo",
            Self::MeshSolo => "mesh-solo",
        }
    }

    pub const fn requires_lora(self) -> bool {
        matches!(self, Self::GatewaySolo | Self::MeshSolo)
    }
}

/// Full DCENT_axe configuration.
///
/// Persisted to NVS as JSON. On first boot (no NVS config), the captive
/// portal collects this from the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcentAxeConfig {
    /// WiFi SSID
    pub wifi_ssid: String,
    /// WiFi password.
    ///
    /// CFG-4 at-rest threat-model note: this PSK is persisted in cleartext in
    /// the default (unencrypted) NVS partition, alongside `stratum.password`.
    /// True at-rest protection is `CONFIG_NVS_ENCRYPTION` + ESP-IDF flash
    /// encryption / secure-boot configured in `sdkconfig.defaults` + eFuse —
    /// that is operator-gated hardware provisioning, NOT something these source
    /// files can deliver, so we do not claim it here. The mitigation that IS in
    /// effect: GET surfaces must keep redacting (e.g. `api.rs` exposes
    /// `password_set: bool` and logs "redacted", never the value), and the
    /// provisioning path must never log the user PSK/pool password.
    pub wifi_password: String,
    /// Pool/Stratum configuration
    pub stratum: StratumConfig,
    /// Operator-selected onboarding mode. Missing legacy fields default to
    /// ordinary pool mining without a schema-version bump.
    #[serde(default)]
    pub mining_mode: MiningMode,
    /// Board model (e.g., "gamma", "ultra", "max", "hexultra")
    pub board_model: String,
    /// Runtime board version read from AxeOS/ESP-Miner NVS when available.
    #[serde(default)]
    pub board_version: String,
    /// Runtime ASIC model read from AxeOS/ESP-Miner NVS when available.
    #[serde(default)]
    pub asic_model: String,
    /// Vendor `minermodel` NVS key (Lucky-enablement SPEC §3). Only Lucky
    /// factory firmware writes this key ("LV06"/"LV07"/"LV08"); a genuine
    /// BitAxe never does, which makes it the most reliable inbound identity
    /// signal. Persisted verbatim so `board::resolve_identity` can re-run the
    /// fail-closed disambiguation on every boot. `#[serde(default)]` ⇒ legacy
    /// NVS blobs round-trip as "" (absent).
    #[serde(default)]
    pub miner_model: String,
    /// SPEC §1.2: vendor boardversions `300A`/`301A`/`302A` are electrically
    /// identical to `300`/`301`/`302`; the sole difference is that they send
    /// `mining.subscribe` with EMPTY params (no `bitaxe/BM1366/<ver>`-style
    /// user-agent). Modeled as this config flag — never as separate board
    /// rows. Latched (never auto-cleared) by `canonicalize_identity` when a
    /// raw A-suffixed boardversion is seen, BEFORE the canonical rewrite
    /// erases the suffix. `#[serde(default)]` ⇒ legacy NVS blobs round-trip
    /// as `false` (identified subscribe, today's behavior).
    ///
    /// HONESTY/HOOKUP NOTE: the actual `mining.subscribe` request is built in
    /// `dcentaxe-stratum` (`client.rs` `send_subscribe`/`build_subscribe_params`
    /// with the crate-level `USER_AGENT`); `StratumConfig` carries no such
    /// flag yet, so this field is plumbed as far as this crate owns and the
    /// stratum-side hookup is a documented remaining step.
    #[serde(default)]
    pub anonymous_subscribe: bool,
    /// RUNTIME-ONLY fail-closed identity refusal (Lucky-enablement SPEC §3
    /// step 5). Set by the boot identity gate in `main.rs` when the inbound
    /// identity is ambiguous and the read-only LV08 regulator probe could not
    /// settle it; checked FIRST by [`Self::validate_safety`], which is the
    /// existing master mining-permission gate — so the refusal rides the same
    /// `mining_permitted`/`mining_block_reason` path as every other refusal
    /// (Hammer precedent) and the rail is never brought up.
    ///
    /// `#[serde(skip)]`: never serialized, never deserialized — recomputed
    /// every boot, so a stale NVS blob can never suppress (or fabricate) a
    /// refusal.
    #[serde(skip)]
    pub identity_refusal: Option<String>,
    /// User-configurable hostname (persisted to NVS)
    #[serde(default)]
    pub hostname: String,
    /// Target hash frequency (MHz)
    pub target_frequency: f32,
    /// Target core voltage (mV)
    pub target_voltage_mv: u16,
    /// Fan speed (0-100%)
    pub fan_speed_pct: u8,
    /// ASIC chip count (auto-detect if 0)
    pub asic_count: u8,
    /// Overclocking mode enabled (assumes 5V 10A PSU instead of 5V 6A)
    #[serde(default)]
    pub overclock_enabled: bool,
    /// Display flipped 180 degrees
    #[serde(default)]
    pub display_inverted: bool,
    /// Fan auto-control target temperature (0 = manual mode, use fan_speed_pct)
    #[serde(default)]
    pub fan_target_temp_c: u8,
    /// Backup/fallback pool configuration
    #[serde(default)]
    pub fallback_pool: Option<dcentaxe_stratum::StratumConfig>,
    /// Optional secondary pool with hashrate splitting.
    /// If present, hashrate is split between primary (stratum) and this pool.
    /// Primary gets (100 - hashrate_pct)%, secondary gets hashrate_pct%.
    #[serde(default)]
    pub split_pool: Option<SplitPoolConfig>,
    /// SV2 own-template proxy hint. DCENT_axe still mines via a standard SV2
    /// endpoint; DCENT_OS or another proxy owns Template Distribution/JD.
    #[serde(default)]
    pub sv2_own_templates: Sv2OwnTemplateConfig,
    /// Optional pinned SV2 pool authority public key for the PRIMARY pool.
    ///
    /// Accepts a base58check token (`base58check([0x01,0x00] || pubkey32)`) or a
    /// full SV2 URL whose path carries it. When set, the SV2 Noise handshake
    /// verifies the server's certificate fail-closed (BIP340 Schnorr) — the
    /// MITM defense. Default `None` keeps trust-on-first-use (TOFU), so existing
    /// behavior is byte-identical when the operator does not pin a key. A
    /// malformed value logs a warning and falls back to TOFU (never bricks the
    /// connection). `#[serde(default)]` ⇒ legacy NVS blobs round-trip with no
    /// schema bump (same pattern as `fallback_pool`).
    #[serde(default)]
    pub sv2_authority_pubkey: Option<String>,
    /// Voluntary, time-sliced D-Central donation configuration. Default ON at
    /// 2%, matching DCENT_OS. A missing field in a legacy blob adopts this
    /// disclosed default without a schema-version bump.
    #[serde(default)]
    pub donation: DonationConfig,
    /// MQTT + Home Assistant auto-discovery config (default-OFF, opt-in).
    /// `#[serde(default)]` ⇒ legacy NVS blobs round-trip with no schema bump.
    #[serde(default)]
    pub mqtt: MqttConfig,
    /// Outbound-only Telegram/Discord/Slack notifications (default OFF).
    #[serde(default)]
    pub notifications: NotificationsConfig,
    /// Wired-Ethernet (W5500 "DCENT LAN Mod" accessory) + Wi-Fi failover
    /// config — PLAN-E Phase 1. `eth_enabled` DEFAULT-OFF: a fresh/legacy unit
    /// never touches the BAP/J4 SPI pins. Only meaningful when the firmware is
    /// built with `--features eth-w5500`; still stored unconditionally so NVS
    /// blobs round-trip across feature-differing images. `#[serde(default)]`
    /// ⇒ legacy blobs load the disabled default with no schema bump.
    #[serde(default)]
    pub network: NetworkConfig,
    /// On-board LoRa / mesh config (default-OFF solo mesh). Only meaningful when
    /// the firmware is built with `--features lora`; still stored so NVS blobs
    /// round-trip. Fail-closed: `solo_relay_enabled=false`, mining_source=off.
    #[cfg(feature = "lora")]
    #[serde(default)]
    pub mesh: MeshConfig,
    /// Enable the daily power/autotune schedule.
    #[serde(default = "default_true")]
    pub schedule_enabled: bool,
    /// Local timezone offset in minutes from UTC for schedule matching.
    /// The dashboard seeds this from the browser; firmware falls back to uptime
    /// if SNTP has not set a valid wall clock yet.
    #[serde(default)]
    pub schedule_timezone_offset_minutes: i16,
    /// Scheduled power profiles (e.g., low power at night)
    #[serde(default)]
    pub power_schedule: Vec<PowerSchedule>,
    /// Explicit ESP-Miner custom-board hardware override set.
    #[serde(default)]
    pub hardware: Option<BoardHardwareConfig>,
    /// Require bearer authentication for /metrics once the owner password is set.
    #[serde(default = "default_true")]
    pub metrics_require_auth: bool,
    /// Allow unsigned OTA uploads even when a signing key is compiled in.
    #[serde(default)]
    pub allow_unsigned_ota: bool,
    /// Which temperature input drives the Space Heater autotuner.
    /// `Local` — firmware reads its own chip temperature (default).
    /// `SwarmAverage` — average of peer-reported room temps (Queen decides).
    /// `External` — only the value last POSTed to `/api/swarm/room-temp`.
    #[serde(default)]
    pub room_temp_source: RoomTempSource,
    /// Config blob schema version. Bumped whenever we change the shape in a
    /// way that `#[serde(default)]` alone can't round-trip. Load path in
    /// `nvs_config::load_config` runs per-version migration steps; `0` or
    /// the current `SCHEMA_VERSION` both round-trip cleanly.
    #[serde(default)]
    pub schema_version: u8,
    /// XPSAFE-8: which dual-fan headers the operator declares PHYSICALLY
    /// POPULATED on this unit.
    ///
    /// Default [`FanPopulation::Both`] — the reference build for every dual-fan
    /// row — so `#[serde(default)]` makes every existing NVS blob round-trip
    /// with byte-identical gate behavior.
    ///
    /// This is deliberately a FIRST-CLASS config field and NOT part of
    /// [`BoardHardwareConfig`]: `apply_hardware_override_if_unrecognized`
    /// refuses hardware overrides for a recognized row, because a registered
    /// row's fan/thermal/power topology is the firmware's safety authority.
    /// Fan POPULATION is not topology — it is a fact about one physical unit
    /// that the row cannot know — so it travels on its own field and never
    /// touches the refused path.
    ///
    /// It does not relax the mandatory-tach requirement. A Hex still must prove
    /// a tachometer; this only scopes WHICH headers the proof is demanded from.
    #[serde(default)]
    pub fans_populated: FanPopulation,
}

fn default_mqtt_port() -> u16 {
    1883
}

fn default_mqtt_publish_interval_s() -> u16 {
    30
}

/// MQTT + Home Assistant auto-discovery config (default-OFF, opt-in).
///
/// When `enabled`, the firmware connects (outbound) to the configured broker and
/// publishes HA MQTT discovery configs + periodic telemetry (see `mqtt_ha.rs` for
/// the payload schema and `mqtt.rs` for the transport). Telemetry is publish-only
/// and fail-soft. The separately opt-in command surface is bounded, clamped, and
/// deployment-policy-gated before it can update autotuner intent; board/thermal
/// safety remains authoritative.
///
/// `password` at-rest threat-model note mirrors `wifi_password`/`stratum.password`:
/// it is persisted in cleartext in the default (unencrypted) NVS partition. The
/// mitigation in effect is the same — GET surfaces redact it (`/api/system/info`
/// exposes `password_set: bool`, `bitaxe://config` masks it to `***`, the apply
/// path logs "redacted"). True at-rest protection is operator-gated NVS/flash
/// encryption, not something this struct can deliver, so we do not claim it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    /// Master toggle. DEFAULT-OFF: a fresh/legacy unit publishes nothing.
    #[serde(default)]
    pub enabled: bool,
    /// Broker hostname or IP (no scheme; scheme is derived from `tls`).
    #[serde(default)]
    pub broker_host: String,
    /// Broker port (1883 plaintext / 8883 typical TLS).
    #[serde(default = "default_mqtt_port")]
    pub broker_port: u16,
    /// Optional broker username (empty = anonymous).
    #[serde(default)]
    pub username: String,
    /// Optional broker password (empty = none). Redacted on every read surface.
    #[serde(default)]
    pub password: String,
    /// Use TLS (`mqtts://`). Cert provisioning is operator/sdkconfig-gated; the
    /// proven path is a plaintext LAN broker. Default false.
    #[serde(default)]
    pub tls: bool,
    /// Telemetry publish cadence in seconds (clamped to a sane floor at runtime).
    #[serde(default = "default_mqtt_publish_interval_s")]
    pub publish_interval_s: u16,
    /// Opt-in operator-CONTROL surface. When true (default FALSE), the publisher
    /// ALSO advertises + subscribes the HA `number`/`select`/`climate` command
    /// entities (target watts / autotuner mode / target chip temperature) and
    /// applies inbound setpoints through the SAME clamped autotuner path the REST
    /// API uses (`mqtt_ha::parse_command` clamps every value to the safety
    /// envelope; the autotuner re-clamps freq/voltage). DEFAULT-OFF so a remote
    /// write surface is never exposed unless the operator explicitly enables it.
    /// `#[serde(default)]` ⇒ legacy NVS blobs load `false`.
    #[serde(default)]
    pub commands_enabled: bool,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            broker_host: String::new(),
            broker_port: default_mqtt_port(),
            username: String::new(),
            password: String::new(),
            tls: false,
            publish_interval_s: default_mqtt_publish_interval_s(),
            commands_enabled: false,
        }
    }
}

/// Which network link the firmware should prefer when the W5500 LAN accessory
/// is enabled (PLAN-E §4.2). Pure data — the runtime failover FSM consuming it
/// lives in `net.rs` (compiled only under the `eth-w5500` feature).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Wi-Fi STA only — Ethernet is never brought up even when `eth_enabled`.
    WifiOnly,
    /// Ethernet is the ONLY desired link. Honesty note (this increment):
    /// Wi-Fi STA still boots for provisioning/management fallback — full Wi-Fi
    /// teardown under EthOnly is a follow-up; the FSM reports `ActiveLink::None`
    /// (not Wi-Fi) when the cable is down so the label never over-claims.
    EthOnly,
    /// LAN-first with Wi-Fi fallback — mirrors TNA's "auto-use Ethernet when
    /// link + IP" behavior. The default whenever Ethernet is enabled.
    #[default]
    EthPreferred,
}

/// Wired-Ethernet (W5500 "DCENT LAN Mod") + Wi-Fi failover configuration —
/// PLAN-E Phase 1. DEFAULT-OFF (`eth_enabled: false`): even an `eth-w5500`
/// build ships Ethernet-dark until the operator opts in (the same
/// runtime-opt-in discipline as `mqtt.enabled` and the LoRa `MeshConfig`).
/// DHCP-only this increment; a static-IP block is a documented follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Master toggle for the W5500 SPI-Ethernet accessory. DEFAULT-OFF.
    /// Activation is additionally fail-closed by the accessory guard:
    /// [`DcentAxeConfig::eth_lan_activation`] refuses LAN on a board whose
    /// accessory mode is BAP-Touch (shared GPIO39/40).
    #[serde(default)]
    pub eth_enabled: bool,
    /// Link preference / failover policy. Default [`NetworkMode::EthPreferred`].
    #[serde(default)]
    pub mode: NetworkMode,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            eth_enabled: false,
            mode: NetworkMode::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub discord_webhook_url: String,
    #[serde(default)]
    pub slack_webhook_url: String,
    #[serde(default)]
    pub share_milestone: u64,
    #[serde(default = "default_true")]
    pub thermal_alerts: bool,
    #[serde(default = "default_true")]
    pub failover_alerts: bool,
    #[serde(default = "default_true")]
    pub ota_alerts: bool,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            discord_webhook_url: String::new(),
            slack_webhook_url: String::new(),
            share_milestone: 0,
            thermal_alerts: true,
            failover_alerts: true,
            ota_alerts: true,
        }
    }
}

impl NotificationsConfig {
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        if !redacted.telegram_bot_token.is_empty() {
            redacted.telegram_bot_token = "***".to_string();
        }
        if !redacted.discord_webhook_url.is_empty() {
            redacted.discord_webhook_url = "***".to_string();
        }
        if !redacted.slack_webhook_url.is_empty() {
            redacted.slack_webhook_url = "***".to_string();
        }
        redacted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sv2OwnTemplateConfig {
    /// Whether the primary SV2 endpoint is intended to be a local template/JD proxy.
    #[serde(default)]
    pub enabled: bool,
    /// Standard SV2 mining endpoint exposed by the local proxy/DCENT_OS.
    #[serde(default)]
    pub mining_proxy_url: String,
    /// Optional Template Provider endpoint for operator visibility.
    #[serde(default)]
    pub template_provider_url: String,
    /// Optional Job Declarator Server endpoint for operator visibility.
    #[serde(default)]
    pub job_declarator_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoomTempSource {
    #[default]
    Local,
    SwarmAverage,
    External,
}

/// Bump this (and add a migration arm in `nvs_config::migrate_config`) every
/// time the saved config shape changes in a way older firmware can't read.
pub const SCHEMA_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Donation configuration — voluntary 2% default, fully transparent
// ---------------------------------------------------------------------------

pub const DONATION_PAYOUT_ADDRESS: &str = "bc1q04lzwddzgmtjex6jlsv2fwhe4se4jxje6rhzp6";
const _: [(); 42] = [(); DONATION_PAYOUT_ADDRESS.len()];

fn default_donation_enabled() -> bool {
    true
}

fn default_donation_percent() -> f32 {
    2.0
}

fn default_donation_pool() -> String {
    "stratum+tcp://pool.d-central.tech:3333".to_string()
}

fn default_donation_worker() -> String {
    "DungeonMaster".to_string()
}

fn default_donation_password() -> String {
    "x".to_string()
}

fn default_donation_fallback_pool() -> String {
    "stratum+tcp://stratum.braiins.com:3333".to_string()
}

fn default_donation_cycle() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationConfig {
    #[serde(default = "default_donation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_donation_percent")]
    pub percent: f32,
    #[serde(default = "default_donation_pool")]
    pub pool_url: String,
    #[serde(default = "default_donation_worker")]
    pub worker: String,
    #[serde(default = "default_donation_password")]
    pub password: String,
    #[serde(default = "default_true")]
    pub fallback_enabled: bool,
    #[serde(default = "default_donation_fallback_pool")]
    pub fallback_pool_url: String,
    #[serde(default = "default_donation_worker")]
    pub fallback_worker: String,
    #[serde(default = "default_donation_password")]
    pub fallback_password: String,
    #[serde(default = "default_donation_cycle")]
    pub cycle_duration_s: u64,
}

impl DonationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.percent.is_finite() || !(0.0..=5.0).contains(&self.percent) {
            return Err("Donation percent must be between 0 and 5".to_string());
        }
        if !(60..=86_400).contains(&self.cycle_duration_s) {
            return Err("Donation cycle must be between 60 and 86400 seconds".to_string());
        }
        if self.enabled && self.percent > 0.0 {
            if self.pool_url.trim().is_empty() {
                return Err("Donation pool URL is required when donation is enabled".to_string());
            }
            if self.worker.trim().is_empty() {
                return Err("Donation worker is required when donation is enabled".to_string());
            }
            if self.fallback_enabled
                && (self.fallback_pool_url.trim().is_empty()
                    || self.fallback_worker.trim().is_empty())
            {
                return Err(
                    "Donation fallback pool and worker are required when fallback is enabled"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    pub fn donation_window_secs(&self) -> u64 {
        if !self.enabled || !self.percent.is_finite() || self.percent <= 0.0 {
            return 0;
        }
        ((self.cycle_duration_s as f64 * self.percent as f64 / 100.0).round() as u64)
            .min(self.cycle_duration_s)
    }

    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        if !redacted.password.is_empty() {
            redacted.password = "***".to_string();
        }
        if !redacted.fallback_password.is_empty() {
            redacted.fallback_password = "***".to_string();
        }
        redacted
    }

    pub fn to_directive(
        &self,
        version_rolling: bool,
    ) -> Result<dcentaxe_stratum::DonationDirective, String> {
        self.validate()?;
        let primary = donation_pool_config(
            &self.pool_url,
            &self.worker,
            &self.password,
            version_rolling,
        )?;
        let fallback = if self.fallback_enabled {
            Some(donation_pool_config(
                &self.fallback_pool_url,
                &self.fallback_worker,
                &self.fallback_password,
                version_rolling,
            )?)
        } else {
            None
        };
        Ok(dcentaxe_stratum::DonationDirective {
            enabled: self.enabled,
            percent: self.percent,
            primary,
            fallback,
            cycle_duration_s: self.cycle_duration_s,
        })
    }
}

fn donation_pool_config(
    url: &str,
    worker: &str,
    password: &str,
    version_rolling: bool,
) -> Result<StratumConfig, String> {
    let host = dcentaxe_stratum::endpoint_host_from_url(url);
    if host.is_empty() {
        return Err("Donation pool URL has no host".to_string());
    }
    let without_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .split('@')
        .next_back()
        .unwrap_or(url);
    let port = without_scheme
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(3333);
    if port == 0 {
        return Err("Donation pool port must be non-zero".to_string());
    }
    Ok(StratumConfig {
        url: url.to_string(),
        port,
        worker_name: worker.to_string(),
        password: password.to_string(),
        suggest_difficulty: 0,
        version_rolling,
    })
}

impl Default for DonationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            percent: default_donation_percent(),
            pool_url: default_donation_pool(),
            worker: default_donation_worker(),
            password: default_donation_password(),
            fallback_enabled: true,
            fallback_pool_url: default_donation_fallback_pool(),
            fallback_worker: default_donation_worker(),
            fallback_password: default_donation_password(),
            cycle_duration_s: default_donation_cycle(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardProfileSource {
    BoardVersion,
    DeviceModelDefault,
    AsicModelFallback,
    BuildDefault,
}

#[derive(Debug, Clone, Copy)]
pub struct BoardProfileResolution {
    pub profile: &'static BoardVersionProfile,
    pub source: BoardProfileSource,
    pub identity_recognized: bool,
    pub family_consistent: bool,
    pub mining_allowed_without_lab_bypass: bool,
}

impl DcentAxeConfig {
    /// Returns true if this config has WiFi credentials set.
    pub fn is_configured(&self) -> bool {
        !self.wifi_ssid.is_empty()
    }

    /// Parse the board model string into a BitAxeModel.
    pub fn bitaxe_model(&self) -> BitAxeModel {
        self.exact_model()
    }

    pub fn exact_model(&self) -> BitAxeModel {
        BitAxeModel::from_device_model(&self.board_model)
            .unwrap_or_else(|| self.board_profile().model)
    }

    pub fn board_profile_resolution(&self) -> BoardProfileResolution {
        let (profile, source) =
            if let Some(profile) = BoardVersionProfile::find(&self.board_version) {
                (profile, BoardProfileSource::BoardVersion)
            } else if let Some(model) = BitAxeModel::from_device_model(&self.board_model) {
                (
                    BoardVersionProfile::default_for_model(model),
                    BoardProfileSource::DeviceModelDefault,
                )
            } else if !self.asic_model.trim().is_empty() {
                (
                    BoardVersionProfile::infer("", "", self.asic_model.trim()),
                    BoardProfileSource::AsicModelFallback,
                )
            } else {
                (
                    default_profile_for_build(),
                    BoardProfileSource::BuildDefault,
                )
            };

        let identity_recognized = self.board_identity_recognized();
        let family_consistent = self.board_identity_family_consistent();
        let resolved_model =
            BitAxeModel::from_device_model(&self.board_model).unwrap_or(profile.model);
        let mut board = BoardConfig::for_profile_with_model(profile, resolved_model);
        if !self.asic_model.trim().is_empty() {
            board.asic_model = self.asic_model.trim().to_string();
        }
        if self.asic_count > 0 {
            board.asic_count = self.asic_count;
        }
        self.apply_hardware_override_if_unrecognized(&mut board, "board_profile_resolution");
        let board_safe = board.validate().is_ok()
            && board
                .validate_accessory_mode(board.accessory_mode())
                .is_ok();
        let custom_board_requires_bypass = self.hardware.is_some()
            && !self.board_version.trim().is_empty()
            && BoardVersionProfile::find(&self.board_version).is_none()
            && board.mining_capable();
        BoardProfileResolution {
            profile,
            source,
            identity_recognized,
            family_consistent,
            mining_allowed_without_lab_bypass: identity_recognized
                && family_consistent
                && board_safe
                && !custom_board_requires_bypass,
        }
    }

    pub fn board_profile(&self) -> &'static BoardVersionProfile {
        self.board_profile_resolution().profile
    }

    pub fn board_version_recognized(&self) -> bool {
        let board_version = self.board_version.trim();
        board_version.is_empty() || BoardVersionProfile::find(board_version).is_some()
    }

    pub fn board_identity_recognized(&self) -> bool {
        let board_version = self.board_version.trim();
        if !board_version.is_empty() {
            return BoardVersionProfile::find(board_version).is_some();
        }

        BitAxeModel::from_device_model(&self.board_model).is_some()
    }

    pub fn board_identity_family_consistent(&self) -> bool {
        let board_version = self.board_version.trim();
        let Some(profile) = BoardVersionProfile::find(board_version) else {
            return true;
        };

        let Some(model) = BitAxeModel::from_device_model(&self.board_model) else {
            return true;
        };

        model == profile.model
            || BoardVersionProfile::default_for_model(model).model == profile.model
    }

    pub fn support_status(&self) -> &'static str {
        if self.board_identity_recognized() {
            self.board_config().model.support_status()
        } else {
            "unknown"
        }
    }

    pub fn asic_model_name(&self) -> &str {
        if self.asic_model.trim().is_empty() {
            self.board_profile().asic_model
        } else {
            self.asic_model.trim()
        }
    }

    pub fn board_config(&self) -> BoardConfig {
        let profile = self.board_profile();
        let mut board = BoardConfig::for_profile_with_model(profile, self.exact_model());

        if !self.board_version.trim().is_empty() {
            board.board_version = self.board_version.trim().to_string();
        }
        if !self.asic_model.trim().is_empty() {
            board.asic_model = self.asic_model.trim().to_string();
        }
        if self.asic_count > 0 {
            board.asic_count = self.asic_count;
        }
        self.apply_hardware_override_if_unrecognized(&mut board, "board_config");
        // XPSAFE-8: fan POPULATION is per-unit physical truth, not row topology,
        // so it is applied unconditionally — after the hardware-override guard
        // above, and deliberately outside it. It cannot widen the board's
        // capabilities: `requires_fan_tach()` is untouched, so a Hex still must
        // prove a tachometer either way.
        board.set_fans_populated(self.fans_populated);

        board
    }

    /// Apply NVS hardware metadata only on the explicit custom-board path.
    ///
    /// Registered rows are the firmware's safety authority. A successfully
    /// deserialized legacy blob may still carry `hardware`, but it must never
    /// replace a recognized row's fan, thermal, or power-controller topology.
    /// Keeping deserialization permissive avoids bricking existing units while
    /// this resolution-time guard refuses the unsafe interpretation.
    fn apply_hardware_override_if_unrecognized(
        &self,
        board: &mut BoardConfig,
        resolution_path: &str,
    ) {
        let Some(hw) = &self.hardware else {
            return;
        };
        if self.board_identity_recognized() {
            log::error!(
                "REFUSING persisted hardware override in {resolution_path}: recognized board \
                 identity board_version='{}' board_model='{}' must use its registered topology",
                self.board_version.trim(),
                self.board_model.trim(),
            );
            return;
        }
        board.apply_hardware_config(hw);
    }

    /// W5500 LAN activation gate — PLAN-E Phase 1 (host-pure, unit-tested).
    ///
    /// Answers "should this boot bring up the W5500 Ethernet link?" in one
    /// fail-closed decision:
    /// - `Ok(false)` — LAN not requested (`network.eth_enabled == false`, or
    ///   `mode == WifiOnly` which makes an enabled toggle inert by definition).
    /// - `Ok(true)`  — LAN requested AND legal for this board's accessory mode.
    /// - `Err(msg)`  — LAN requested but ILLEGAL: the board's accessory mode is
    ///   BAP-Touch and the existing `validate_accessory_mode` guard refuses the
    ///   pair (W5500 SPI rides the BAP-UART pins GPIO39/40). Callers must log
    ///   and keep Ethernet dark — mining is unaffected (fail-soft for mining,
    ///   fail-closed for the pins).
    ///
    /// NOTE: picking LAN *over* Touch on a BAP-populated board (the PLAN-E
    /// Risk-#6 "choose one" UX) is a follow-up increment — this gate only ever
    /// refuses; it never flips a BAP board's accessory mode to LAN.
    pub fn eth_lan_activation(&self) -> Result<bool, &'static str> {
        if !self.network.eth_enabled || self.network.mode == NetworkMode::WifiOnly {
            return Ok(false);
        }
        let board = self.board_config();
        board.validate_accessory_mode(AccessoryMode::W5500Lan)?;
        Ok(true)
    }

    pub fn validate_safety(&self, unsafe_lab_bypass: bool) -> Result<(), String> {
        // SPEC §3 step 5 — the fail-closed identity refusal is checked FIRST,
        // before any board-shape validation: a misidentified board makes every
        // downstream conclusion (voltage domains, chip count, controllers)
        // untrustworthy. Set only at runtime by the boot identity gate
        // (`#[serde(skip)]` — a persisted blob can never carry it).
        if let Some(reason) = &self.identity_refusal {
            if !unsafe_lab_bypass {
                return Err(format!("board identity gate: {reason}"));
            }
            log::warn!(
                "UNSAFE LAB BYPASS is overriding a FAIL-CLOSED BOARD-IDENTITY REFUSAL: \
                 {reason}. The board may be MISIDENTIFIED — a wrong voltage-domain \
                 profile can drive a multiple of the per-die voltage onto the core \
                 rail (the 3.6 V Lucky LV08 trap). Lab hardware only."
            );
        }
        let board = self.board_config();
        board.validate().map_err(|e| e.to_string())?;
        board
            .validate_accessory_mode(board.accessory_mode())
            .map_err(|e| e.to_string())?;

        if !self.board_identity_recognized() && !unsafe_lab_bypass {
            return Err(
                "unrecognized board identity requires explicit unsafe lab safety bypass"
                    .to_string(),
            );
        }
        if !self.board_identity_family_consistent() {
            return Err(format!(
                "board_version '{}' is inconsistent with device_model '{}'",
                self.board_version.trim(),
                self.board_model.trim()
            ));
        }

        let custom_board = self.hardware.is_some()
            && !self.board_version.trim().is_empty()
            && BoardVersionProfile::find(&self.board_version).is_none();
        if custom_board && board.mining_capable() && !unsafe_lab_bypass {
            if board.fan_controller == FanControllerKind::None {
                return Err(
                    "custom mining-capable board requires an explicit fan controller".to_string(),
                );
            }
            if board.temp_sensor == TempSensorKind::None {
                return Err(
                    "custom mining-capable board requires an explicit temperature sensor"
                        .to_string(),
                );
            }
            if board.power_controller == PowerControllerKind::None {
                return Err(
                    "custom mining-capable board requires an explicit power controller".to_string(),
                );
            }
        }

        // Fail closed on a power-schedule slot whose autotuner target is outside
        // the safe envelope. The interactive control paths route every target
        // through `validate_autotune_target`, but a schedule slot's target is only
        // loosely clamped on API save (and a slot loaded from a legacy NVS blob
        // could carry any value); when such a slot activates it would drive the
        // autotuner past the board's safe power/thermal budget. Validate each
        // enabled slot's (mode, target) through the SAME envelope function.
        for (idx, slot) in self.power_schedule.iter().enumerate() {
            if slot.autotune_enabled != Some(true) {
                continue;
            }
            if let (Some(mode_str), Some(target)) =
                (slot.autotune_mode.as_deref(), slot.autotune_target)
            {
                if let Some(mode) =
                    crate::chip_profiles_bitaxe::BestPointMode::from_api_str(mode_str)
                {
                    crate::chip_profiles_bitaxe::validate_autotune_target(mode, target).map_err(
                        |e| format!("power_schedule slot {idx} autotune target invalid: {e}"),
                    )?;
                }
            }
        }

        Ok(())
    }

    pub fn canonicalize_identity(&mut self) {
        // SPEC §1.2: latch the anonymous-subscribe request from a raw
        // A-suffixed vendor boardversion BEFORE any canonical rewrite (below,
        // or the boot identity gate) erases the suffix. Latch-only: a later
        // canonical "2008" never clears an already-set flag.
        if board_version_requests_anonymous_subscribe(&self.board_version) {
            self.anonymous_subscribe = true;
        }
        if !self.board_version.trim().is_empty()
            && BoardVersionProfile::find(&self.board_version).is_none()
        {
            return;
        }

        let exact_model = self.exact_model();
        let profile = self.board_profile();
        self.board_model = exact_model.canonical_key().to_string();
        self.board_version = profile.board_version.to_string();
        self.asic_model = profile.asic_model.to_string();
    }

    /// The exact argument tuple the boot identity gate feeds to
    /// [`resolve_identity_gate`]: `(board_version, device_model, miner_model)`.
    ///
    /// Extracted as a pure function so the WIRING (not just the resolver) is
    /// host-testable — the failure mode this guards against is a correct
    /// resolver that production never calls, or calls with the wrong fields
    /// (e.g. dropping `miner_model`, the vendor's most reliable signal).
    pub fn identity_gate_inputs(&self) -> (&str, &str, &str) {
        (&self.board_version, &self.board_model, &self.miner_model)
    }

    /// Run the SPEC §3 boot identity gate over THIS config's stored identity.
    /// `probe` is invoked only from the AMBIGUOUS branch (see
    /// [`resolve_identity_gate`]); `main.rs` passes the real read-only
    /// PMBus 0x7F/0x14 probe, tests inject verdicts.
    pub fn run_identity_gate(
        &self,
        probe: impl FnOnce() -> Option<dcentaxe_hal::tps546_guard::LuckyProbeVerdict>,
    ) -> IdentityGateOutcome {
        let (board_version, device_model, miner_model) = self.identity_gate_inputs();
        resolve_identity_gate(board_version, device_model, miner_model, probe)
    }

    /// Run the post-resolution Hammer DC identity-strap verification. The
    /// injected probe is structurally unreachable for every non-Hammer model.
    pub fn run_identity_strap_gate(
        &self,
        probe: impl FnOnce(u8) -> Option<dcentaxe_hal::hammer_strap::HammerStrapProbeVerdict>,
    ) -> IdentityStrapGateOutcome {
        let board = self.board_config();
        verify_identity_strap_gate(board.model, board.identity_strap_addr, probe)
    }

    /// Adopt a gate-resolved canonical profile ([`IdentityGateOutcome::AdoptProfile`])
    /// into this config: canonical board_version/board_model/asic_model plus the
    /// row's chip count, clearing any prior runtime refusal and stale custom
    /// hardware metadata. Latches the SPEC §1.2 anonymous-subscribe request
    /// from the raw pre-rewrite boardversion before the canonical rewrite
    /// erases the `A` suffix.
    pub fn apply_identity_profile(&mut self, row: &'static BoardVersionProfile) {
        if board_version_requests_anonymous_subscribe(&self.board_version) {
            self.anonymous_subscribe = true;
        }
        self.board_version = row.board_version.to_string();
        self.board_model = row.model.canonical_key().to_string();
        self.asic_model = row.asic_model.to_string();
        self.asic_count = BoardConfig::for_profile(row).asic_count;
        // An ambiguous AxeOS identity can arrive with a custom hardware blob.
        // Once the gate adopts a registered row, that blob is no longer
        // authoritative and must not survive the identity rewrite/persist.
        self.hardware = None;
        self.identity_refusal = None;
    }

    pub fn board_target(&self) -> &'static str {
        self.board_config().model.board_target()
    }

    /// Get the ASIC model for driver creation.
    pub fn asic_model(&self) -> dcentaxe_asic::AsicModel {
        match self.asic_model_name() {
            "BM1397" => dcentaxe_asic::AsicModel::BM1397,
            "BM1368" => dcentaxe_asic::AsicModel::BM1368,
            "BM1370" => dcentaxe_asic::AsicModel::BM1370,
            // BM1373 (Hammer BC01 Pro) MUST resolve to its own fail-closed
            // scaffold driver — falling through to the BM1366 fallback would
            // run a WRONG chip's init sequence against live BM1373 silicon.
            "BM1373" => dcentaxe_asic::AsicModel::BM1373,
            // MSBT0501 (Hammer DC0x, Scrypt) MUST resolve to its own driver.
            // Falling through to the BM1366 fallback would run a Bitmain
            // SHA-256 init sequence — 0x55AA framing, CRC-5 command frames, a
            // TicketMask write with the LOW-bits convention — against live
            // Scrypt silicon that speaks 0xCDAB/CRC-16-CMS and uses a HIGH-bits
            // ticket mask. This is the same latent trap that was found and
            // fixed for "BM1373" in the BC0x lane. `LT0051` is accepted too
            // because that is the vendor's DRIVER name and may appear in a
            // hand-set NVS field.
            "MSBT0501" | "LT0051" => dcentaxe_asic::AsicModel::Lt0051,
            _ => dcentaxe_asic::AsicModel::BM1366,
        }
    }

    /// Get expected ASIC count for this board model.
    pub fn expected_asic_count(&self) -> u8 {
        self.board_config().asic_count
    }

    /// Get safe power limits based on overclock mode.
    pub fn power_limits(&self) -> PowerLimits {
        let model = self.board_config().model;
        if self.overclock_enabled {
            PowerLimits::overclock(model)
        } else {
            PowerLimits::safe(model)
        }
    }

    pub fn qualify_operating_point(
        &self,
        frequency_mhz: f32,
        voltage_mv: u16,
        surface: ControlSurface,
    ) -> QualifiedOperatingPoint {
        let board = self.board_config();
        let stock = stock_asic_settings(board.model);
        let limits = self.power_limits();
        let mut min_frequency = stock.frequency_options.iter().copied().min().unwrap_or(50) as f32;
        let mut max_frequency = limits.max_frequency.min(
            stock
                .frequency_options
                .iter()
                .copied()
                .max()
                .unwrap_or(limits.max_frequency.round() as u16) as f32,
        );
        let mut min_voltage_mv = board.min_voltage_mv.max(
            stock
                .voltage_options
                .iter()
                .copied()
                .min()
                .unwrap_or(board.min_voltage_mv),
        );
        let mut max_voltage_mv = limits.max_voltage_mv.min(
            stock
                .voltage_options
                .iter()
                .copied()
                .max()
                .unwrap_or(limits.max_voltage_mv),
        );

        // Gamma Turbo is qualified in live testing at 625 MHz / 1150 mV in
        // safe mode. Keep higher voltages behind explicit overclock mode.
        if board.model == BitAxeModel::GammaTurbo && !self.overclock_enabled {
            max_voltage_mv = max_voltage_mv.min(board.default_voltage_mv);
        }

        if max_frequency < min_frequency {
            min_frequency = max_frequency;
        }

        // Fail closed on a non-finite frequency. `f32::clamp(NaN)` returns NaN, and
        // `(NaN - NaN).abs() > EPSILON` is false, so a NaN `frequency_mhz` would exit
        // THE central V/F safety clamp UNCLAMPED and be reported `clamped: false`.
        // Substitute the lowest safe frequency and force the `clamped` flag so no
        // caller ever applies (or trusts) a non-finite operating point.
        let (frequency_mhz, frequency_was_invalid) = if frequency_mhz.is_finite() {
            (frequency_mhz, false)
        } else {
            (min_frequency, true)
        };

        let qualified_frequency = frequency_mhz.clamp(min_frequency, max_frequency);
        // Mirror the frequency guard above: `u16::clamp` PANICS when min > max (reboot under
        // panic=abort). max_voltage_mv is narrowed AFTER min_voltage_mv is fixed — e.g. the
        // GammaTurbo non-overclock cap toward default_voltage_mv — so a future board table whose
        // min floor sat above that cap would panic in THE central V/F safety clamp. Unreachable
        // with today's tables (pinned by voltage_clamp_never_panics_across_all_models), but the
        // sibling frequency clamp is guarded and this one must be too; collapse toward the
        // lower (safer) voltage cap.
        if max_voltage_mv < min_voltage_mv {
            min_voltage_mv = max_voltage_mv;
        }
        // A boot-restored vendor/NVS value outside the board driver's absolute
        // voltage window is evidence of a foreign or corrupt profile. Preserve
        // that evidence and refuse mining instead of silently replacing it
        // with a boundary value and persisting the replacement. Runtime control
        // surfaces retain their load-bearing clamp behavior. Voltage zero is
        // the HAL's explicit "disable output" command and is not rejected here.
        let refused = surface == ControlSurface::BootRestore
            && voltage_mv != 0
            && (voltage_mv < board.min_voltage_mv || voltage_mv > board.max_voltage_mv);
        let qualified_voltage = voltage_mv.clamp(min_voltage_mv, max_voltage_mv);
        QualifiedOperatingPoint {
            frequency_mhz: qualified_frequency,
            voltage_mv: qualified_voltage,
            refused,
            clamped: frequency_was_invalid
                || (qualified_frequency - frequency_mhz).abs() > f32::EPSILON
                || qualified_voltage != voltage_mv,
        }
    }

    pub fn qualified_frequency_options(&self) -> Vec<u16> {
        let board = self.board_config();
        stock_asic_settings(board.model)
            .frequency_options
            .iter()
            .copied()
            .filter(|frequency| {
                let point = self.qualify_operating_point(
                    *frequency as f32,
                    board.default_voltage_mv,
                    ControlSurface::RestPatch,
                );
                point.frequency_mhz.round() as u16 == *frequency
            })
            .collect()
    }

    pub fn qualified_voltage_options(&self) -> Vec<u16> {
        let board = self.board_config();
        let base_frequency = self
            .qualify_operating_point(
                self.target_frequency,
                self.target_voltage_mv,
                ControlSurface::RestPatch,
            )
            .frequency_mhz;
        stock_asic_settings(board.model)
            .voltage_options
            .iter()
            .copied()
            .filter(|voltage_mv| {
                let point = self.qualify_operating_point(
                    base_frequency,
                    *voltage_mv,
                    ControlSurface::RestPatch,
                );
                point.voltage_mv == *voltage_mv
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlSurface {
    Provisioning,
    RestPatch,
    LegacyRest,
    Mcp,
    Autotuner,
    Schedule,
    BootRestore,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct QualifiedOperatingPoint {
    pub frequency_mhz: f32,
    pub voltage_mv: u16,
    /// BootRestore only: the stored voltage is outside the HAL's absolute
    /// board envelope and must not be applied or persisted.
    pub refused: bool,
    pub clamped: bool,
}

/// Default config used by the provisioning portal form.
impl Default for DcentAxeConfig {
    fn default() -> Self {
        let profile = default_profile_for_build();
        let board = BoardConfig::for_profile_with_model(profile, default_model_for_build());
        Self {
            wifi_ssid: String::new(),
            wifi_password: String::new(),
            stratum: StratumConfig::default(),
            mining_mode: MiningMode::default(),
            board_model: default_model_for_build().canonical_key().into(),
            board_version: profile.board_version.into(),
            asic_model: profile.asic_model.into(),
            miner_model: String::new(),
            anonymous_subscribe: false,
            identity_refusal: None,
            hostname: String::new(),
            target_frequency: board.default_frequency,
            target_voltage_mv: board.default_voltage_mv,
            fan_speed_pct: 100,
            asic_count: board.asic_count,
            overclock_enabled: false,
            display_inverted: false,
            fan_target_temp_c: DEFAULT_FAN_TARGET_TEMP_C, // 0 = manual mode (CFG-7)
            fallback_pool: None,
            split_pool: None,
            sv2_own_templates: Sv2OwnTemplateConfig::default(),
            sv2_authority_pubkey: None,
            donation: DonationConfig::default(),
            mqtt: MqttConfig::default(),
            notifications: NotificationsConfig::default(),
            network: NetworkConfig::default(),
            #[cfg(feature = "lora")]
            mesh: MeshConfig::default(),
            schedule_enabled: true,
            schedule_timezone_offset_minutes: 0,
            power_schedule: Vec::new(),
            hardware: None,
            metrics_require_auth: true,
            allow_unsigned_ota: false,
            room_temp_source: RoomTempSource::Local,
            schema_version: SCHEMA_VERSION,
            // XPSAFE-8: the reference build populates both headers.
            fans_populated: FanPopulation::Both,
        }
    }
}

/// Power limits based on PSU rating.
///
/// Safe mode: assumes 5V 6A PSU (30W max, ~25W usable after losses)
/// Overclock mode: assumes 5V 10A PSU (50W max, ~45W usable)
#[derive(Debug, Clone)]
pub struct PowerLimits {
    /// Maximum power draw in watts
    pub max_power_w: f32,
    /// Maximum current in amps
    pub max_current_a: f32,
    /// Maximum safe frequency for this power envelope (MHz)
    pub max_frequency: f32,
    /// Recommended default frequency (MHz)
    pub default_frequency: f32,
    /// Maximum safe voltage (mV)
    pub max_voltage_mv: u16,
}

impl PowerLimits {
    /// Safe limits for 5V 6A PSU (standard USB-C, most common)
    pub fn safe(model: BitAxeModel) -> Self {
        match model {
            BitAxeModel::GammaDuo => Self {
                max_power_w: 40.0,
                max_current_a: 8.0,
                max_frequency: 410.0,
                default_frequency: 400.0,
                max_voltage_mv: 1250,
            },
            BitAxeModel::GammaTurbo => Self {
                max_power_w: 60.0,
                max_current_a: 5.0,
                max_frequency: 625.0,
                default_frequency: 525.0,
                max_voltage_mv: 1350,
            },
            BitAxeModel::Gamma => Self {
                max_power_w: 25.0,
                max_current_a: 5.5,
                max_frequency: 475.0,
                default_frequency: 525.0,
                max_voltage_mv: 1200,
            },
            BitAxeModel::Supra => Self {
                max_power_w: 25.0,
                max_current_a: 5.5,
                max_frequency: 450.0,
                default_frequency: 490.0,
                max_voltage_mv: 1250,
            },
            BitAxeModel::Ultra => Self {
                max_power_w: 25.0,
                max_current_a: 5.5,
                max_frequency: 450.0,
                default_frequency: 400.0,
                max_voltage_mv: 1250,
            },
            BitAxeModel::Max => Self {
                max_power_w: 25.0,
                max_current_a: 5.5,
                max_frequency: 400.0,
                default_frequency: 425.0,
                max_voltage_mv: 1400,
            },
            BitAxeModel::HexUltra => Self {
                // ESP-Miner: FAMILY_HEX.max_power = 90W, 12V input
                max_power_w: 90.0,
                max_current_a: 8.0,
                max_frequency: 500.0,
                default_frequency: 485.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::HexSupra => Self {
                // ESP-Miner: FAMILY_SUPRA_HEX.max_power = 120W, 12V input
                max_power_w: 120.0,
                max_current_a: 10.0,
                max_frequency: 525.0,
                default_frequency: 490.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::NerdNOS => Self {
                max_power_w: 8.0,
                max_current_a: 1.6,
                max_frequency: 400.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // NerdAxe: 1x BM1366 off USB-C 5 V. `max_current_a` is upstream's
            // `m_maxCurrentA = 5.0`, not the 5.5 the mislabelled BM1370 row
            // guessed; `max_power_w` is its `m_maxPin = 15.0`.
            BitAxeModel::NerdAxe => Self {
                max_power_w: 15.0,
                max_current_a: 5.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // NerdAxe-γ: 1x BM1370, `m_maxPin = 25.0`, `m_maxCurrentA = 6.0`.
            // Ceiling is the top of `m_asicVoltages` (1200), which is also the
            // board row's `max_voltage_mv` — this board has no headroom above
            // its characterized window, so `overclock` returns `safe`.
            BitAxeModel::NerdAxeGamma => Self {
                max_power_w: 25.0,
                max_current_a: 6.0,
                max_frequency: 575.0,
                default_frequency: 515.0,
                max_voltage_mv: 1200,
            },
            BitAxeModel::NerdQaxePlus => Self {
                max_power_w: 55.0,
                max_current_a: 12.0,
                max_frequency: 450.0,
                default_frequency: 400.0,
                max_voltage_mv: 1250,
            },
            BitAxeModel::NerdQaxePP => Self {
                max_power_w: 80.0,
                max_current_a: 16.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // ── NerdOCTAXE pair: 8 ASICs on a 12 V multi-phase rail ──
            // Envelopes derived from the upstream board constructors' own
            // m_maxPin ceilings, kept BELOW them: OCTAXE+ m_maxPin 130 W,
            // OCTAXE-γ m_maxPin 250 W on the 4-phase part (300 W only on the
            // 6-phase TPS53667, which this row does not assume). These are
            // "safe" limits, so they sit under the vendor ceiling deliberately.
            BitAxeModel::NerdOctaxePlus => Self {
                max_power_w: 110.0,
                max_current_a: 10.0,
                max_frequency: 450.0,
                default_frequency: 400.0,
                max_voltage_mv: 1250,
            },
            BitAxeModel::NerdOctaxeGamma => Self {
                max_power_w: 200.0,
                max_current_a: 18.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // ── The rest of the Nerd multi-ASIC line + the Q-series ──
            // Same derivation as the OCTAXE pair: sit UNDER the upstream
            // constructor's own m_maxPin, and under the vendor current ceiling
            // (m_maxCurrentA) rather than at it.
            // NerdHaxe-γ: 6x BM1370, m_maxPin 250 W, m_maxCurrentA 15 A.
            BitAxeModel::NerdHaxeGamma => Self {
                max_power_w: 200.0,
                max_current_a: 13.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // NerdEKO: 12x BM1370, m_maxPin 350 W, m_maxCurrentA 25 A. The
            // largest envelope in the registry, and still held below vendor.
            BitAxeModel::NerdEko => Self {
                max_power_w: 300.0,
                max_current_a: 22.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // NerdQX: 4x BM1370, m_maxPin 240 W. The frequency/voltage ceiling
            // is the CLAMPED one (495 MHz / 1150 mV) — see `stock_asic_settings`.
            // Its own over-current trip is refused as unreachable, so nothing
            // here may lean on the regulator catching an overload.
            BitAxeModel::NerdQX => Self {
                max_power_w: 200.0,
                max_current_a: 17.0,
                max_frequency: 495.0,
                default_frequency: 495.0,
                max_voltage_mv: 1150,
            },
            // Q1370: 4x BM1370, m_maxPin 150 W, m_maxCurrentA 20 A.
            BitAxeModel::Q1370 => Self {
                max_power_w: 130.0,
                max_current_a: 12.0,
                max_frequency: 475.0,
                default_frequency: 400.0,
                max_voltage_mv: 1200,
            },
            // Q1373: 4x BM1373, m_maxPin 180 W, m_maxCurrentA 15 A. The BM1373
            // envelope is much lower than the BM1370's — 550 MHz vendor table
            // top and a 1080 mV ceiling — so this row is not a scaled Q1370.
            BitAxeModel::Q1373 => Self {
                max_power_w: 150.0,
                max_current_a: 13.0,
                max_frequency: 400.0,
                default_frequency: 350.0,
                max_voltage_mv: 1050,
            },
            // BitAxe Naja: the same BM1373 dies, two of them instead of four.
            // Frequency and voltage are per-die properties and so are IDENTICAL
            // to the Q1373 row above; only the power and current envelopes
            // halve with the die count. Its 2-phase TPS546D24A rail and 90 W
            // row target both agree with that.
            BitAxeModel::BitaxeNaja => Self {
                max_power_w: 75.0,
                max_current_a: 6.5,
                max_frequency: 400.0,
                default_frequency: 350.0,
                max_voltage_mv: 1050,
            },
            // Touch variants share limits with their mining-board base.
            BitAxeModel::Touch => Self::safe(BitAxeModel::Gamma),
            BitAxeModel::GtTouch => Self::safe(BitAxeModel::GammaTurbo),
            // ── DCENT_axe BM1397 family ──
            // Single shares the BitAxe Max BM1397 envelope.
            BitAxeModel::DcentAxeBm1397 => Self::safe(BitAxeModel::Max),
            // Quad/Hex: same BM1397 chip envelope, scaled wall power for the chain.
            BitAxeModel::DcentAxeQuadBm1397 => Self {
                max_power_w: 90.0,
                max_current_a: 8.0,
                max_frequency: 400.0,
                default_frequency: 425.0,
                max_voltage_mv: 1400,
            },
            BitAxeModel::DcentAxeHexBm1397 => Self {
                max_power_w: 130.0,
                max_current_a: 11.0,
                max_frequency: 400.0,
                default_frequency: 425.0,
                max_voltage_mv: 1400,
            },
            // ── Hammer BC0x (EXPERIMENTAL) — vendor wall-power maxima; all
            // voltages are PER-CHIP (the series rail is derived elsewhere).
            // Mining is refused on these boards until peripheral drivers
            // exist; these envelopes only bound config plumbing/UI. ──
            BitAxeModel::HammerBc01 => Self {
                max_power_w: 45.0,
                max_current_a: 9.0,
                max_frequency: 600.0,
                default_frequency: 525.0,
                max_voltage_mv: 1300,
            },
            // BC01 Pro: 1.15 V per-chip HARD cap and 500 MHz vendor ceiling
            // (lower-confidence web-UI data — keep conservative).
            BitAxeModel::HammerBc01Pro => Self {
                max_power_w: 45.0,
                max_current_a: 9.0,
                max_frequency: 500.0,
                default_frequency: 400.0,
                max_voltage_mv: 1150,
            },
            BitAxeModel::HammerBc02 => Self {
                max_power_w: 60.0,
                max_current_a: 12.0,
                max_frequency: 600.0,
                default_frequency: 525.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::HammerBc04 => Self {
                max_power_w: 120.0,
                max_current_a: 10.0,
                max_frequency: 600.0,
                default_frequency: 525.0,
                max_voltage_mv: 1250,
            },
            // ── Hammer DC0x (EXPERIMENTAL, Scrypt) — vendor wall-power
            // maxima. `max_voltage_mv` is PER-CHIP (750 mV); the series rail is
            // derived as per-chip x 2/4/6 by the regulator layer, so this
            // number must NEVER be read as a rail. `max_frequency` is pinned to
            // the vendor STOCK default, i.e. zero headroom.
            // Mining is refused on these boards (no trusted thermal source);
            // these envelopes only bound config plumbing/UI. ──
            BitAxeModel::HammerDc02 => Self {
                max_power_w: 50.0,
                max_current_a: 5.0,
                max_frequency: 2300.0,
                default_frequency: 2300.0,
                max_voltage_mv: 750,
            },
            BitAxeModel::HammerDc04 => Self {
                max_power_w: 100.0,
                max_current_a: 9.0,
                max_frequency: 2300.0,
                default_frequency: 2300.0,
                max_voltage_mv: 750,
            },
            BitAxeModel::HammerDc06 => Self {
                max_power_w: 100.0,
                max_current_a: 9.0,
                max_frequency: 2300.0,
                default_frequency: 2300.0,
                max_voltage_mv: 750,
            },
            // ── Lucky Miner LVxx — 12 V input, one parallel domain (SPEC §1).
            // Safe envelopes sit AT (LV06/LV07, 40 W vendor rating) or just
            // UNDER (LV08: 135 W vs the 140 W rating) the vendor maxima —
            // no Lucky hardware is on any bench (SPEC §8), so no headroom is
            // granted anywhere. 485 MHz / 1200 mV stock, 1300 mV option cap. ──
            BitAxeModel::LuckyLv06 => Self {
                max_power_w: 40.0,
                max_current_a: 4.0,
                max_frequency: 500.0,
                default_frequency: 485.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::LuckyLv07 => Self {
                // Same 40 W family rating as LV06 (SPEC §1 table) — the second
                // die does not raise the vendor ceiling.
                max_power_w: 40.0,
                max_current_a: 4.0,
                max_frequency: 500.0,
                default_frequency: 485.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::LuckyLv08 => Self {
                // 135 W safe envelope under the 140 W vendor rating; ~11.5 A
                // at the 12 V input.
                max_power_w: 135.0,
                max_current_a: 11.5,
                max_frequency: 500.0,
                default_frequency: 485.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::BitForgeNano => Self {
                // `BITFORGE_NANO_MAX_POWER 60` (forge-os `power.c:15`) is the
                // vendor's own ceiling; the README asks for a >=70 W supply, so
                // 60 W sits inside the recommended headroom. 5 A at the 12 V
                // barrel jack.
                max_power_w: 60.0,
                max_current_a: 5.0,
                // 2x BM1370 in parallel — the Gamma Duo's frequency envelope.
                max_frequency: 410.0,
                default_frequency: 400.0,
                // Refuses the vendor's 1400 mV Kconfig default outright. See
                // the `BoardConfig::for_model` note: nothing upstream clamps it
                // (`VCORE_set_voltage` passes the float straight through, and
                // `TPS546_INIT_VOUT_MAX = 2` is a 2.0 V ceiling on a 1.2 V
                // rail).
                max_voltage_mv: 1250,
            },
        }
    }

    /// Overclock limits for 5V 10A PSU (high-power USB-C or barrel jack)
    pub fn overclock(model: BitAxeModel) -> Self {
        match model {
            BitAxeModel::GammaDuo => Self {
                max_power_w: 50.0,
                max_current_a: 10.0,
                max_frequency: 490.0,
                default_frequency: 410.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::GammaTurbo => Self {
                max_power_w: 80.0,
                max_current_a: 6.7,
                max_frequency: 650.0,
                default_frequency: 550.0,
                max_voltage_mv: 1350,
            },
            BitAxeModel::Gamma => Self {
                max_power_w: 45.0,
                max_current_a: 9.5,
                max_frequency: 600.0,
                default_frequency: 525.0,
                max_voltage_mv: 1300,
            },
            BitAxeModel::Supra => Self {
                max_power_w: 45.0,
                max_current_a: 9.5,
                max_frequency: 575.0,
                default_frequency: 490.0,
                max_voltage_mv: 1350,
            },
            BitAxeModel::Ultra => Self {
                max_power_w: 45.0,
                max_current_a: 9.5,
                max_frequency: 550.0,
                default_frequency: 485.0,
                max_voltage_mv: 1350,
            },
            BitAxeModel::Max => Self {
                max_power_w: 45.0,
                max_current_a: 9.5,
                max_frequency: 500.0,
                default_frequency: 400.0,
                max_voltage_mv: 1600,
            },
            BitAxeModel::HexUltra => Self {
                max_power_w: 110.0,
                max_current_a: 10.0,
                max_frequency: 550.0,
                default_frequency: 500.0,
                max_voltage_mv: 1350,
            },
            BitAxeModel::HexSupra => Self {
                max_power_w: 150.0,
                max_current_a: 13.0,
                max_frequency: 575.0,
                default_frequency: 525.0,
                max_voltage_mv: 1350,
            },
            // Nerd boards: overclock = same as safe (USB-powered, limited headroom)
            BitAxeModel::NerdNOS => Self::safe(model),
            // The OCTAXE pair is 12 V-fed and already sized near its vendor
            // ceiling at "safe"; there is no separate USB-C overclock envelope
            // to grant, so they reuse their safe limits like NerdNOS does.
            // Same for the rest of the 12 V multi-phase line and the Q-series:
            // all are wall-fed and already sized near their vendor ceiling at
            // "safe". NerdQX especially — its regulator's own over-current trip
            // is unreachable (see `check_iout_fault_limit`), so granting it
            // extra headroom would be leaning on a protection that is not there.
            BitAxeModel::NerdOctaxePlus
            | BitAxeModel::NerdOctaxeGamma
            | BitAxeModel::NerdHaxeGamma
            | BitAxeModel::NerdEko
            | BitAxeModel::NerdQX
            | BitAxeModel::Q1370
            | BitAxeModel::Q1373
            // BitAxe Naja: no characterized headroom exists to grant. No unit
            // has ever run, and the BM1373 numbers it uses are the vendor's for
            // a different board — there is nothing to overclock ON TOP of.
            | BitAxeModel::BitaxeNaja
            // NerdAxe-γ: `max_voltage_mv` already IS the top of
            // `m_asicVoltages`, and upstream's `m_absMaxAsicVoltageMillis` is
            // commented out — there is no characterized headroom to grant.
            | BitAxeModel::NerdAxeGamma => Self::safe(model),
            BitAxeModel::NerdAxe | BitAxeModel::NerdQaxePlus | BitAxeModel::NerdQaxePP => Self {
                max_power_w: Self::safe(model).max_power_w * 1.5,
                max_current_a: Self::safe(model).max_current_a * 1.5,
                max_frequency: Self::safe(model).max_frequency + 100.0,
                default_frequency: Self::safe(model).default_frequency + 50.0,
                max_voltage_mv: Self::safe(model).max_voltage_mv + 100,
            },
            // Touch variants reuse the overclock profile of their mining-board base.
            BitAxeModel::Touch => Self::overclock(BitAxeModel::Gamma),
            BitAxeModel::GtTouch => Self::overclock(BitAxeModel::GammaTurbo),
            // ── DCENT_axe BM1397 family ──
            // Single shares the BitAxe Max BM1397 overclock envelope; Quad/Hex
            // scale their own safe envelope the same way the Nerd chains do.
            BitAxeModel::DcentAxeBm1397 => Self::overclock(BitAxeModel::Max),
            BitAxeModel::DcentAxeQuadBm1397 | BitAxeModel::DcentAxeHexBm1397 => Self {
                max_power_w: Self::safe(model).max_power_w * 1.5,
                max_current_a: Self::safe(model).max_current_a * 1.5,
                max_frequency: Self::safe(model).max_frequency + 100.0,
                default_frequency: Self::safe(model).default_frequency,
                max_voltage_mv: Self::safe(model).max_voltage_mv + 100,
            },
            // ── Hammer BC0x: NO overclock headroom is granted — we hold no
            // evidence for anything beyond the vendor envelope (BC01 Pro's
            // 1.15 V cap in particular must never be raised this way). ──
            // Hammer DC0x: same posture, and doubly so — the vendor's own
            // 700-2600 MHz clamp is explicitly NOT a proven-safe envelope, and
            // a per-chip over-volt is multiplied by 2/4/6 across the series
            // stack. No headroom without a witnessed wattmeter+thermal soak.
            // Lucky LVxx: no hardware on any bench, so no headroom either.
            BitAxeModel::HammerBc01
            | BitAxeModel::HammerBc01Pro
            | BitAxeModel::HammerBc02
            | BitAxeModel::HammerBc04
            | BitAxeModel::HammerDc02
            | BitAxeModel::HammerDc04
            | BitAxeModel::HammerDc06
            | BitAxeModel::LuckyLv06
            | BitAxeModel::LuckyLv07
            | BitAxeModel::LuckyLv08
            // BitForge Nano: no hardware on any bench, and its vendor firmware
            // ships no characterized headroom at all — its only voltage
            // "ceiling" is a 2.0 V TPS546 limit on a 1.2 V rail, which is not a
            // ceiling. Nothing to grant.
            | BitAxeModel::BitForgeNano => Self::safe(model),
        }
    }

    /// Warning message for enabling overclock mode
    pub const OVERCLOCK_WARNING: &'static str = concat!(
        "WARNING: Overclocking mode increases power draw significantly. ",
        "Ensure your PSU is rated for at least 5V 10A (50W). ",
        "Using an inadequate PSU may cause: voltage drops, USB disconnects, ",
        "ASIC damage, fire risk, or permanent device failure. ",
        "D-Central Technologies is not responsible for damage caused by overclocking. ",
        "Proceed at your own risk."
    );
}

/// Configuration for a secondary pool with hashrate splitting.
///
/// When configured, the firmware maintains two simultaneous Stratum connections
/// and alternates work dispatch between them using a deficit-based scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitPoolConfig {
    /// Pool connection details for the secondary pool.
    pub pool: dcentaxe_stratum::StratumConfig,

    /// Percentage of hashrate directed to this secondary pool (1-99).
    /// The primary pool receives (100 - hashrate_pct)% of hashrate.
    pub hashrate_pct: u8,
}

/// A scheduled power profile that activates at a specific hour of the day.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerSchedule {
    /// Whether this schedule entry is active.
    #[serde(default = "default_schedule_entry_enabled")]
    pub enabled: bool,
    /// Hour to activate this profile (0-23, local time)
    pub hour: u8,
    /// Minute within the hour to activate this profile (0-59).
    #[serde(default)]
    pub minute: u8,
    /// Target frequency (MHz)
    pub frequency: f32,
    /// Target voltage (mV)
    #[serde(alias = "voltageMv")]
    pub voltage_mv: u16,
    /// Optional autotuner override for this slot.
    /// None = leave current autotuner state alone, Some(false) = fixed freq/volt,
    /// Some(true) = enable autotuner using the optional mode/target below.
    #[serde(default, alias = "autotuneEnabled")]
    pub autotune_enabled: Option<bool>,
    /// Autotuner mode when `autotune_enabled = true`.
    /// API string values: max_hashrate, best_efficiency, target_watts, target_temp.
    #[serde(default, alias = "autotuneMode")]
    pub autotune_mode: Option<String>,
    /// Autotuner target value for target_watts / target_temp style policies.
    #[serde(default, alias = "autotuneTarget")]
    pub autotune_target: Option<f32>,
    /// Human label
    #[serde(default)]
    pub label: String,
}

impl PowerSchedule {
    pub fn start_minute_of_day(&self) -> u16 {
        self.hour.min(23) as u16 * 60 + self.minute.min(59) as u16
    }
}

/// Return the current local schedule minute and the source used to derive it.
/// SNTP-backed wall clock is preferred; uptime fallback preserves useful behavior
/// on isolated setups without NTP/DNS.
pub fn schedule_minute_of_day(
    timezone_offset_minutes: i16,
    uptime_secs: u64,
) -> (u16, &'static str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now >= 1_600_000_000 {
        let local_secs = now as i64 + timezone_offset_minutes as i64 * 60;
        let day_secs = local_secs.rem_euclid(86_400) as u64;
        return ((day_secs / 60) as u16, "wall_clock");
    }

    (((uptime_secs % 86_400) / 60) as u16, "uptime_fallback")
}

/// Pick the latest enabled schedule entry whose start time is <= current local time.
/// If all entries start later than now, wrap to the latest entry from yesterday.
pub fn active_power_schedule<'a>(
    entries: &'a [PowerSchedule],
    minute_of_day: u16,
) -> Option<(usize, &'a PowerSchedule)> {
    let mut best_before: Option<(usize, u16, &PowerSchedule)> = None;
    let mut best_wrap: Option<(usize, u16, &PowerSchedule)> = None;

    for (idx, entry) in entries.iter().enumerate() {
        if !entry.enabled {
            continue;
        }
        let start = entry.start_minute_of_day();
        if start <= minute_of_day {
            if best_before
                .map(|(_, prev, _)| start >= prev)
                .unwrap_or(true)
            {
                best_before = Some((idx, start, entry));
            }
        }
        if best_wrap.map(|(_, prev, _)| start >= prev).unwrap_or(true) {
            best_wrap = Some((idx, start, entry));
        }
    }

    best_before
        .or(best_wrap)
        .map(|(idx, _, entry)| (idx, entry))
}

pub fn next_schedule_change_minutes(entries: &[PowerSchedule], minute_of_day: u16) -> Option<u16> {
    let mut next_today: Option<u16> = None;
    let mut first_tomorrow: Option<u16> = None;

    for entry in entries.iter().filter(|entry| entry.enabled) {
        let start = entry.start_minute_of_day();
        if start > minute_of_day {
            if next_today.map(|prev| start < prev).unwrap_or(true) {
                next_today = Some(start);
            }
        }
        if first_tomorrow.map(|prev| start < prev).unwrap_or(true) {
            first_tomorrow = Some(start);
        }
    }

    next_today
        .map(|start| start - minute_of_day)
        .or_else(|| first_tomorrow.map(|start| 1_440 - minute_of_day + start))
}

/// A fixed frequency/voltage preset for a specific BitAxe model.
#[derive(Debug, Clone)]
pub struct MiningPreset {
    /// Human-readable name
    pub name: &'static str,
    /// Target frequency (MHz)
    pub frequency: f32,
    /// Target core voltage (mV)
    pub voltage_mv: u16,
    /// Expected hashrate (GH/s, approximate)
    pub expected_hashrate_ghs: f32,
    /// Expected power draw (watts, approximate)
    pub expected_power_w: f32,
    /// Requires overclock mode?
    pub requires_overclock: bool,
}

/// Get available mining presets for a board model.
/// Returns 3-5 presets from Low Power → Max Performance.
pub fn mining_presets(model: BitAxeModel) -> Vec<MiningPreset> {
    match model {
        BitAxeModel::GammaDuo => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 350.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 700.0,
                expected_power_w: 8.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 850.0,
                expected_power_w: 12.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "High Perf",
                frequency: 410.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 900.0,
                expected_power_w: 15.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 490.0,
                voltage_mv: 1250,
                expected_hashrate_ghs: 1000.0,
                expected_power_w: 20.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::Gamma => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 800.0,
                expected_power_w: 10.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 1000.0,
                expected_power_w: 15.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Efficient",
                frequency: 490.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 1100.0,
                expected_power_w: 13.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "High Perf",
                frequency: 575.0,
                voltage_mv: 1260,
                expected_hashrate_ghs: 1200.0,
                expected_power_w: 20.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 600.0,
                voltage_mv: 1300,
                expected_hashrate_ghs: 1250.0,
                expected_power_w: 24.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::GammaTurbo => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 1700.0,
                expected_power_w: 28.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Balanced",
                frequency: 525.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 2200.0,
                expected_power_w: 36.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Recommended Safe",
                frequency: 625.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 2600.0,
                expected_power_w: 42.5,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 650.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 2800.0,
                expected_power_w: 48.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::Supra => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 500.0,
                expected_power_w: 10.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 490.0,
                voltage_mv: 1166,
                expected_hashrate_ghs: 575.0,
                expected_power_w: 15.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Efficient",
                frequency: 485.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 625.0,
                expected_power_w: 13.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "High Perf",
                frequency: 550.0,
                voltage_mv: 1300,
                expected_hashrate_ghs: 700.0,
                expected_power_w: 20.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 575.0,
                voltage_mv: 1350,
                expected_hashrate_ghs: 775.0,
                expected_power_w: 24.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::Ultra => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 400.0,
                expected_power_w: 10.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 450.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 450.0,
                expected_power_w: 12.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Efficient",
                frequency: 485.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 500.0,
                expected_power_w: 14.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "High Perf",
                frequency: 525.0,
                voltage_mv: 1300,
                expected_hashrate_ghs: 550.0,
                expected_power_w: 18.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 550.0,
                voltage_mv: 1350,
                expected_hashrate_ghs: 575.0,
                expected_power_w: 22.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::Max => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 300.0,
                expected_power_w: 8.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 425.0,
                voltage_mv: 1400,
                expected_hashrate_ghs: 425.0,
                expected_power_w: 14.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "High Perf",
                frequency: 450.0,
                voltage_mv: 1400,
                expected_hashrate_ghs: 450.0,
                expected_power_w: 18.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 500.0,
                voltage_mv: 1600,
                expected_hashrate_ghs: 500.0,
                expected_power_w: 25.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::HexUltra => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 350.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 2100.0,
                expected_power_w: 30.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 485.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 3000.0,
                expected_power_w: 48.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 485.0,
                voltage_mv: 1350,
                expected_hashrate_ghs: 3000.0,
                expected_power_w: 48.0,
                requires_overclock: true,
            },
        ],
        BitAxeModel::HexSupra => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 350.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 2400.0,
                expected_power_w: 30.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 490.0,
                voltage_mv: 1166,
                expected_hashrate_ghs: 3600.0,
                expected_power_w: 48.0,
                requires_overclock: true,
            },
            MiningPreset {
                name: "Max (OC)",
                frequency: 490.0,
                voltage_mv: 1350,
                expected_hashrate_ghs: 3600.0,
                expected_power_w: 48.0,
                requires_overclock: true,
            },
        ],
        // NerdNOS: BM1397 underclocked, USB-powered ~8W
        BitAxeModel::NerdNOS => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 80.0,
                expected_power_w: 5.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 400.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 110.0,
                expected_power_w: 8.0,
                requires_overclock: false,
            },
        ],
        // NerdAxe: 1x BM1366 — the BitAxe Ultra's ASIC and, per
        // `stock_asic_settings`, its exact frequency/voltage tables. This
        // borrowed the Gamma presets while the row claimed BM1370.
        BitAxeModel::NerdAxe => mining_presets(BitAxeModel::Ultra),
        // NerdAxe-γ: 1x BM1370, electrically the BitAxe Gamma shape.
        BitAxeModel::NerdAxeGamma => mining_presets(BitAxeModel::Gamma),
        // NerdQaxe+: 4x BM1368
        BitAxeModel::NerdQaxePlus => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 2000.0,
                expected_power_w: 35.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 450.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 2400.0,
                expected_power_w: 50.0,
                requires_overclock: false,
            },
        ],
        // NerdQaxe++: 4x BM1370
        BitAxeModel::NerdQaxePP => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 3200.0,
                expected_power_w: 50.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 4800.0,
                expected_power_w: 75.0,
                requires_overclock: true,
            },
        ],
        // NerdOCTAXE+: 8x BM1368. Upstream README documents ~5 TH/s at ~100 W
        // for the whole board; these presets stay under that.
        BitAxeModel::NerdOctaxePlus => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 4000.0,
                expected_power_w: 70.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 450.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 4800.0,
                expected_power_w: 100.0,
                requires_overclock: false,
            },
        ],
        // NerdOCTAXE-γ: 8x BM1370. Figures are the 4-phase (rev ≤3.3) envelope
        // — the 6-phase rev 3.4 runs higher, but only once its TPS53667 has
        // been positively identified, which is not something a static preset
        // table can assert.
        BitAxeModel::NerdOctaxeGamma => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 6400.0,
                expected_power_w: 100.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 9600.0,
                expected_power_w: 150.0,
                requires_overclock: true,
            },
        ],
        // NerdHaxe-γ: 6x BM1370, m_maxPin 250 W. Per-chip figures are the
        // NerdOCTAXE-γ's, scaled 6/8.
        BitAxeModel::NerdHaxeGamma => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 4800.0,
                expected_power_w: 75.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 7200.0,
                expected_power_w: 115.0,
                requires_overclock: true,
            },
        ],
        // NerdEKO: 12x BM1370 on a 6-phase TPS53667, m_maxPin 350 W. Same
        // per-chip figures scaled 12/8.
        BitAxeModel::NerdEko => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 9600.0,
                expected_power_w: 150.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 14400.0,
                expected_power_w: 225.0,
                requires_overclock: true,
            },
        ],
        // NerdQX: 4x BM1370. ONE preset, because until the TMP451 mux proves
        // the board, 495 MHz / 1150 mV is the only operating point it is
        // allowed. A "Default" above the ceiling would be a preset that cannot
        // be applied.
        BitAxeModel::NerdQX => vec![MiningPreset {
            name: "Default",
            frequency: 495.0,
            voltage_mv: 1150,
            expected_hashrate_ghs: 3000.0,
            expected_power_w: 55.0,
            requires_overclock: false,
        }],
        // Q1370: 4x BM1370, m_maxPin 150 W — the NerdQAxe++ per-chip figures.
        BitAxeModel::Q1370 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 3200.0,
                expected_power_w: 50.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 4800.0,
                expected_power_w: 75.0,
                requires_overclock: true,
            },
        ],
        // Q1373: 4x BM1373. Hashrate per chip is UNMEASURED — no BM1373 board
        // has ever run here, and the Hammer BC01 Pro row is the only other
        // BM1373 figure we hold (vendor web-UI table, not a measurement).
        // Frequencies are the vendor's own table; the hashrate numbers are
        // scaled from that vendor claim and should be treated as such.
        BitAxeModel::Q1373 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1000,
                expected_hashrate_ghs: 12000.0,
                expected_power_w: 100.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 350.0,
                voltage_mv: 1010,
                expected_hashrate_ghs: 14000.0,
                expected_power_w: 130.0,
                requires_overclock: false,
            },
        ],
        // BitAxe Naja: 2x BM1373. These are the Q1373 figures above halved for
        // the die count, which makes them DOUBLY derived — that row is already
        // scaled from a vendor web-UI claim rather than a measurement, and no
        // BM1373 board of any kind has run on a bench here. Treat the hashrate
        // and power columns as order-of-magnitude only. The frequency and
        // voltage columns are the vendor's own table and are not derived.
        BitAxeModel::BitaxeNaja => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1000,
                expected_hashrate_ghs: 6000.0,
                expected_power_w: 50.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 350.0,
                voltage_mv: 1010,
                expected_hashrate_ghs: 7000.0,
                expected_power_w: 65.0,
                requires_overclock: false,
            },
        ],
        // Touch variants reuse the presets of their mining-board base.
        BitAxeModel::Touch => mining_presets(BitAxeModel::Gamma),
        BitAxeModel::GtTouch => mining_presets(BitAxeModel::GammaTurbo),
        // ── DCENT_axe BM1397 family ──
        // Single reuses the BitAxe Max BM1397 presets.
        BitAxeModel::DcentAxeBm1397 => mining_presets(BitAxeModel::Max),
        // Quad 4x BM1397: per-chip Max figures scaled to the 4-chip chain.
        BitAxeModel::DcentAxeQuadBm1397 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 1200.0,
                expected_power_w: 32.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 425.0,
                voltage_mv: 1400,
                expected_hashrate_ghs: 1700.0,
                expected_power_w: 56.0,
                requires_overclock: false,
            },
        ],
        // ── Hammer BC0x (EXPERIMENTAL — mining refused until drivers exist;
        // presets are per-chip values bounding future UI, hashrate figures are
        // conservative 525 MHz extrapolations, not vendor 820 MHz claims). ──
        BitAxeModel::HammerBc01 => mining_presets(BitAxeModel::Gamma),
        BitAxeModel::HammerBc01Pro => vec![MiningPreset {
            name: "Default",
            frequency: 400.0,
            voltage_mv: 1000,
            expected_hashrate_ghs: 3200.0,
            expected_power_w: 36.0,
            requires_overclock: false,
        }],
        BitAxeModel::HammerBc02 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 1600.0,
                expected_power_w: 25.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1225,
                expected_hashrate_ghs: 2100.0,
                expected_power_w: 40.0,
                requires_overclock: false,
            },
        ],
        BitAxeModel::HammerBc04 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 3200.0,
                expected_power_w: 55.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 525.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 4200.0,
                expected_power_w: 80.0,
                requires_overclock: false,
            },
        ],
        // ── Hammer DC0x (Scrypt) ──
        // ⚠ `expected_hashrate_ghs` is a SHA-256-era field name. Scrypt boards
        // hash in MH/s (`PowAlgorithm::hashrate_unit()`), and 150/300/450 MH/s
        // is 0.00015/0.0003/0.00045 GH/s — a number no UI should ever show as
        // "GH/s". Rather than store a misleading unit, these presets report
        // 0.0 and the DC0x rows are excluded from hashrate-bearing preset
        // surfaces until the display layer is unit-aware (design §4.6).
        // `voltage_mv` is PER-CHIP; the rail is derived x2/x4/x6.
        BitAxeModel::HammerDc02 | BitAxeModel::HammerDc04 | BitAxeModel::HammerDc06 => {
            vec![
                MiningPreset {
                    name: "Low Power",
                    frequency: 1600.0,
                    voltage_mv: 600,
                    expected_hashrate_ghs: 0.0,
                    expected_power_w: 0.0,
                    requires_overclock: false,
                },
                MiningPreset {
                    name: "Default",
                    frequency: 2300.0,
                    voltage_mv: 635,
                    expected_hashrate_ghs: 0.0,
                    expected_power_w: 0.0,
                    requires_overclock: false,
                },
            ]
        }
        // ── Lucky Miner LVxx — stock BM1366 envelope (485 MHz / 1200 mV).
        // ⚠ Expected hashrate/power are PROJECTIONS (per-chip BM1366 figures ×
        // chip count + the 18 W family input offset) — NO Lucky hardware has
        // ever been bench-proven (SPEC §8), nothing here is measured. The
        // earlier Ultra-preset delegate was wrong by 2×/9× on LV07/LV08.
        // No preset requires overclock: `PowerLimits::overclock` grants Lucky
        // zero headroom, so an overclock-gated preset would be unreachable.
        BitAxeModel::LuckyLv06 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 400.0,
                expected_power_w: 14.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 485.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 500.0,
                expected_power_w: 18.0,
                requires_overclock: false,
            },
        ],
        BitAxeModel::LuckyLv07 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 800.0,
                expected_power_w: 26.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 485.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 1000.0,
                expected_power_w: 34.0,
                requires_overclock: false,
            },
        ],
        // 2x BM1370 in parallel — the same silicon, count and topology as the
        // Gamma Duo, so it borrows that board's preset ladder rather than
        // inventing hashrate/power figures no bench has measured.
        BitAxeModel::BitForgeNano => mining_presets(BitAxeModel::GammaDuo),
        BitAxeModel::LuckyLv08 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 400.0,
                voltage_mv: 1150,
                expected_hashrate_ghs: 3600.0,
                expected_power_w: 100.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 485.0,
                voltage_mv: 1200,
                expected_hashrate_ghs: 4500.0,
                expected_power_w: 135.0,
                requires_overclock: false,
            },
        ],
        // Hex 6x BM1397: per-chip Max figures scaled to the 6-chip chain.
        BitAxeModel::DcentAxeHexBm1397 => vec![
            MiningPreset {
                name: "Low Power",
                frequency: 300.0,
                voltage_mv: 1100,
                expected_hashrate_ghs: 1800.0,
                expected_power_w: 48.0,
                requires_overclock: false,
            },
            MiningPreset {
                name: "Default",
                frequency: 425.0,
                voltage_mv: 1400,
                expected_hashrate_ghs: 2550.0,
                expected_power_w: 84.0,
                requires_overclock: false,
            },
        ],
    }
}

#[cfg(test)]
mod donation_tests {
    use super::{DcentAxeConfig, DonationConfig, MiningMode, DONATION_PAYOUT_ADDRESS};

    #[test]
    fn donation_defaults_match_dcent_os_contract() {
        let donation = DonationConfig::default();
        assert!(donation.enabled);
        assert_eq!(donation.percent, 2.0);
        assert_eq!(donation.cycle_duration_s, 3600);
        assert_eq!(donation.donation_window_secs(), 72);
        assert_eq!(donation.pool_url, "stratum+tcp://pool.d-central.tech:3333");
        assert!(DONATION_PAYOUT_ADDRESS.starts_with("bc1q"));
        assert_eq!(DONATION_PAYOUT_ADDRESS.len(), 42);
        donation.validate().expect("valid donation defaults");
        let directive = donation.to_directive(true).expect("runtime directive");
        assert_eq!(directive.primary.port, 3333);
        assert_eq!(directive.primary.worker_name, "DungeonMaster");
        assert_eq!(directive.fallback.as_ref().unwrap().port, 3333);
    }

    #[test]
    fn donation_validation_is_bounded_and_fail_closed() {
        let mut donation = DonationConfig::default();
        donation.percent = -0.1;
        assert!(donation.validate().is_err());
        donation.percent = 5.1;
        assert!(donation.validate().is_err());
        donation.percent = f32::NAN;
        assert!(donation.validate().is_err());
        donation.percent = 2.0;
        donation.cycle_duration_s = 59;
        assert!(donation.validate().is_err());
        donation.cycle_duration_s = 86_401;
        assert!(donation.validate().is_err());
    }

    #[test]
    fn donation_off_has_zero_window_and_redaction_never_leaks_passwords() {
        let mut donation = DonationConfig::default();
        donation.enabled = false;
        assert_eq!(donation.donation_window_secs(), 0);
        let redacted = donation.redacted();
        assert_eq!(redacted.password, "***");
        assert_eq!(redacted.fallback_password, "***");
        assert!(!serde_json::to_string(&redacted).unwrap().contains("\"x\""));
    }

    #[test]
    fn legacy_blob_without_donation_adopts_disclosed_default_without_schema_bump() {
        let full = DcentAxeConfig::default();
        let schema = full.schema_version;
        let mut value = serde_json::to_value(&full).unwrap();
        value.as_object_mut().unwrap().remove("donation");
        let loaded: DcentAxeConfig = serde_json::from_value(value).unwrap();
        assert!(loaded.donation.enabled);
        assert_eq!(loaded.donation.percent, 2.0);
        assert_eq!(loaded.schema_version, schema);
    }

    #[test]
    fn default_config_remains_below_nvs_blob_limit() {
        let json = serde_json::to_vec(&DcentAxeConfig::default()).unwrap();
        assert!(json.len() < 3584, "default config is {} bytes", json.len());
    }

    #[test]
    fn onboarding_mining_mode_is_bounded_and_legacy_defaults_to_pool() {
        assert_eq!(MiningMode::from_token("pool").unwrap(), MiningMode::Pool);
        assert_eq!(
            MiningMode::from_token("gateway-solo").unwrap(),
            MiningMode::GatewaySolo
        );
        assert!(MiningMode::from_token("invented").is_err());
        assert!(MiningMode::GatewaySolo.requires_lora());
        assert!(!MiningMode::Solo.requires_lora());

        let mut value = serde_json::to_value(DcentAxeConfig::default()).unwrap();
        value.as_object_mut().unwrap().remove("mining_mode");
        let loaded: DcentAxeConfig = serde_json::from_value(value).unwrap();
        assert_eq!(loaded.mining_mode, MiningMode::Pool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a custom (non-table) hardware override with the three safety
    /// controllers chosen explicitly. `BoardHardwareConfig` has no `Default`,
    /// so every field is spelled out; only the controller kinds are
    /// load-bearing for these tests.
    fn custom_hw(
        fan: FanControllerKind,
        temp: TempSensorKind,
        power: PowerControllerKind,
    ) -> BoardHardwareConfig {
        BoardHardwareConfig {
            plug_sense: false,
            asic_enable: true,
            fan_controller: fan,
            temp_sensor: temp,
            power_controller: power,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0x00,
            temp_offset_c: 0,
            power_consumption_target_w: 19,
        }
    }

    // ── XPH-1 — validate_safety() master mining-permission gate ──
    //
    // A custom mining-capable board (board_version not in the profile table +
    // an explicit hardware override) must be REFUSED when any one of the three
    // required safety controllers (fan / temperature / power) is absent, and
    // PERMITTED only under the explicit unsafe lab bypass. Each case keeps a
    // trusted thermal source present so `BoardConfig::validate()` itself passes
    // and the custom-board gate is the deciding factor.
    #[test]
    fn validate_safety_fails_closed_when_required_controller_absent() {
        // Baseline default config (host build => Gamma, a KNOWN profile) passes.
        let base = DcentAxeConfig::default();
        assert!(
            BoardVersionProfile::find(&base.board_version).is_some(),
            "default board_version should resolve to a known profile"
        );
        assert!(base.validate_safety(false).is_ok());

        // (missing fan, trusted temp + power), (missing temp, trusted fan +
        // power == Tps546), (missing power, trusted fan + temp).
        let cases = [
            custom_hw(
                FanControllerKind::None,
                TempSensorKind::Emc2101,
                PowerControllerKind::Tps546,
            ),
            custom_hw(
                FanControllerKind::Emc2101,
                TempSensorKind::None,
                PowerControllerKind::Tps546,
            ),
            custom_hw(
                FanControllerKind::Emc2101,
                TempSensorKind::Emc2101,
                PowerControllerKind::None,
            ),
        ];

        for hw in cases {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = "DCENT-NOPROFILE-TEST".to_string();
            assert!(
                BoardVersionProfile::find(&cfg.board_version).is_none(),
                "test board_version must be absent from the profile table"
            );
            cfg.hardware = Some(hw);

            // Sanity: this really is a custom, mining-capable board.
            let board = cfg.board_config();
            assert!(board.mining_capable());

            // Fail-closed: the master gate refuses without the bypass.
            assert!(
                cfg.validate_safety(false).is_err(),
                "master gate must refuse a custom mining board missing a required controller"
            );
            // Explicit lab bypass permits the bench exception.
            assert!(
                cfg.validate_safety(true).is_ok(),
                "explicit unsafe lab bypass must permit the bench exception"
            );
        }
    }

    // ── XPH-2 — qualify_operating_point() voltage/freq clamp + PowerLimits ──
    #[test]
    fn board_profile_resolution_records_provenance_and_mining_gate() {
        let cfg = DcentAxeConfig::default();
        let resolved = cfg.board_profile_resolution();
        assert_eq!(resolved.source, BoardProfileSource::BoardVersion);
        assert_eq!(resolved.profile.board_version, cfg.board_version);
        assert!(resolved.identity_recognized);
        assert!(resolved.family_consistent);
        assert!(resolved.mining_allowed_without_lab_bypass);

        let mut unknown_version = DcentAxeConfig::default();
        unknown_version.board_version = "DCENT-UNKNOWN-BOARD".to_string();
        let resolved = unknown_version.board_profile_resolution();
        assert_eq!(resolved.source, BoardProfileSource::DeviceModelDefault);
        assert_eq!(resolved.profile.model, default_model_for_build());
        assert!(!resolved.identity_recognized);
        assert!(resolved.family_consistent);
        assert!(
            !resolved.mining_allowed_without_lab_bypass,
            "unknown board_version fallback must be provenance-visible and non-mining"
        );

        let mut asic_only = DcentAxeConfig::default();
        asic_only.board_version.clear();
        asic_only.board_model = "garbage-model".to_string();
        asic_only.asic_model = "BM1370".to_string();
        let resolved = asic_only.board_profile_resolution();
        assert_eq!(resolved.source, BoardProfileSource::AsicModelFallback);
        assert_eq!(resolved.profile.model, BitAxeModel::Gamma);
        assert!(!resolved.identity_recognized);
        assert!(resolved.family_consistent);
        assert!(
            !resolved.mining_allowed_without_lab_bypass,
            "ASIC-only inference must not become an automatic mining path"
        );
    }

    // ── Hammer BC0x/DC0x (EXPERIMENTAL): recognized identity, refused mining. ──
    // Production-path pin: the full NVS→resolution ladder must (a) recognize
    // the provisional Hammer rows so the boards never fall into the
    // custom-board lab-bypass lane, and (b) still refuse mining because no
    // Hammer peripheral driver exists (board_safe=false — no trusted thermal
    // source). This drives `board_profile_resolution()` exactly as boot does.
    #[test]
    fn hammer_rows_are_recognized_but_mining_stays_refused() {
        for (ver, model_key, asic) in [
            ("hammer-bc01", "hammer_bc01", "BM1370"),
            ("hammer-bc01-pro", "hammer_bc01_pro", "BM1373"),
            ("hammer-bc02", "hammer_bc02", "BM1370"),
            ("hammer-bc04", "hammer_bc04", "BM1370"),
            ("3102", "hammer_dc02", "MSBT0501"),
            ("3104", "hammer_dc04", "MSBT0501"),
            ("3106", "hammer_dc06", "MSBT0501"),
        ] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = ver.to_string();
            cfg.board_model = model_key.to_string();
            cfg.asic_model.clear();
            cfg.canonicalize_identity();
            let resolved = cfg.board_profile_resolution();
            assert_eq!(resolved.source, BoardProfileSource::BoardVersion, "{ver}");
            assert!(resolved.identity_recognized, "{ver}: identity must resolve");
            assert!(resolved.family_consistent, "{ver}");
            assert!(
                !resolved.mining_allowed_without_lab_bypass,
                "{ver}: mining must stay refused until Hammer peripheral drivers exist"
            );
            assert_eq!(cfg.support_status(), "experimental", "{ver}");
            assert_eq!(cfg.asic_model_name(), asic, "{ver}");

            // Regression for the live porosity: a recognized row must ignore
            // deserialized hardware metadata rather than accepting Tps546 as
            // a synthetic thermal source (with no fan and no temp sensor).
            cfg.hardware = Some(custom_hw(
                FanControllerKind::None,
                TempSensorKind::None,
                PowerControllerKind::Tps546,
            ));
            assert!(cfg.hardware.is_some(), "{ver}: blob still deserializes");
            let board = cfg.board_config();
            assert_eq!(
                board.power_controller,
                PowerControllerKind::None,
                "{ver}: registered topology must beat NVS hardware"
            );
            assert_eq!(board.temp_sensor, TempSensorKind::None, "{ver}");
            assert!(
                cfg.validate_safety(false).is_err(),
                "{ver}: production safety path must refuse the porous hardware blob"
            );
        }
    }

    // ── BM1373 must resolve to its own fail-closed scaffold driver. ──
    // Production-path pin for `asic_model()`: before this arm existed, the
    // string "BM1373" fell through to the BM1366 FALLBACK — which would run a
    // wrong chip's full init sequence against live BM1373 silicon on a
    // BC01 Pro. The scaffold driver refuses init instead (fail-closed).
    #[test]
    fn bm1373_resolves_to_its_own_driver_not_the_bm1366_fallback() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "hammer-bc01-pro".to_string();
        cfg.board_model = "hammer_bc01_pro".to_string();
        cfg.asic_model.clear();
        cfg.canonicalize_identity();
        assert_eq!(cfg.asic_model_name(), "BM1373");
        assert_eq!(
            cfg.asic_model(),
            dcentaxe_asic::AsicModel::BM1373,
            "BM1373 must select the fail-closed BM1373 scaffold, never the BM1366 fallback"
        );
        // The metadata now reports the PROVEN silicon id (0x1372, not the
        // 0x1373 part number — BM1373_DOSSIER.md).
        assert_eq!(cfg.asic_model().expected_chip_id(), 0x1372);
    }

    #[test]
    fn unknown_board_version_is_mining_gated_without_lab_bypass() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "DCENT-UNKNOWN-BOARD".to_string();
        cfg.hardware = None;

        assert!(!cfg.board_version_recognized());
        assert_eq!(cfg.support_status(), "unknown");
        assert!(
            cfg.validate_safety(false).is_err(),
            "unknown board_version alone must not silently mine on a default profile"
        );
        assert!(
            cfg.validate_safety(true).is_ok(),
            "the explicit lab bypass remains available for bench-only unknown boards"
        );
    }

    #[test]
    fn recognized_model_without_board_version_stays_supported() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version.clear();
        cfg.board_model = "gamma".to_string();

        assert!(cfg.board_version_recognized());
        assert!(cfg.board_identity_recognized());
        assert_eq!(cfg.board_profile().model, BitAxeModel::Gamma);
        assert_eq!(cfg.support_status(), "supported");
        assert!(
            cfg.validate_safety(false).is_ok(),
            "older configs with a recognized device_model must remain eligible"
        );
    }

    #[test]
    fn inferred_asic_profile_without_identity_is_unknown_and_mining_gated() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version.clear();
        cfg.board_model = "garbage-model".to_string();
        cfg.asic_model = "BM1370".to_string();
        cfg.hardware = None;

        assert!(cfg.board_version_recognized());
        assert!(!cfg.board_identity_recognized());
        assert_eq!(cfg.board_profile().model, BitAxeModel::Gamma);
        assert!(cfg.board_config().mining_capable());
        assert_eq!(cfg.support_status(), "unknown");
        assert!(
            cfg.validate_safety(false).is_err(),
            "ASIC-only inference must not become a mining path"
        );
        assert!(
            cfg.validate_safety(true).is_ok(),
            "the explicit lab bypass remains available for bench-only inference"
        );
    }

    #[test]
    fn board_version_and_device_model_family_must_agree() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "801".to_string(); // Gamma Turbo / GT
        cfg.board_model = "gamma".to_string();

        assert!(cfg.board_version_recognized());
        assert!(!cfg.board_identity_family_consistent());
        assert!(
            cfg.validate_safety(false).is_err(),
            "cross-family board_version/device_model disagreement must not mine"
        );
        assert!(
            cfg.validate_safety(true).is_err(),
            "unsafe lab bypass is for unknown/custom boards, not contradictory identities"
        );
    }

    #[test]
    fn accessory_models_can_reuse_their_underlying_mining_profile() {
        let mut touch = DcentAxeConfig::default();
        touch.board_version = "601".to_string(); // Gamma mining board profile
        touch.board_model = "touch".to_string();
        assert!(touch.board_identity_family_consistent());
        assert!(touch.validate_safety(false).is_ok());

        // NerdQAxe++ USED to borrow "601" and so used to validate against it.
        // Queue rank 41 gave it canonical row "4007", and the pairing is now
        // correctly REFUSED — the same correction, for the same reason, as the
        // NerdAxe case immediately below: "601" is a BM1370 board on a single
        // TPS546 with a one-fan EMC2101, while a NerdQAxe++ is a BM1370 board
        // on a 3-phase TPS53647 at 0x71 with a two-fan EMC2302 and a 100 W
        // envelope. Accepting the pair hands it the wrong regulator driver.
        let mut stale_borrow = DcentAxeConfig::default();
        stale_borrow.board_version = "601".to_string(); // Gamma-family profile
        stale_borrow.board_model = "nerdqaxe++".to_string();
        assert!(
            !stale_borrow.board_identity_family_consistent(),
            "a Gamma profile must not validate against the TPS53647 NerdQAxe++"
        );

        // Its own row pairs, and mines.
        let mut nerd = DcentAxeConfig::default();
        nerd.board_version = "4007".to_string();
        nerd.board_model = "nerdqaxe++".to_string();
        assert!(nerd.board_identity_family_consistent());
        assert!(nerd.validate_safety(false).is_ok());

        // Same for the other three rank-41 rows, so a later edit cannot quietly
        // point one of them back at a BitAxe row.
        for (ver, model) in [
            ("4006", "nerdqaxe+"),
            ("4008", "nerdoctaxe+"),
            ("4009", "nerdoctaxe-gamma"),
        ] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = ver.to_string();
            cfg.board_model = model.to_string();
            assert!(
                cfg.board_identity_family_consistent(),
                "{model} must pair with its canonical row {ver}"
            );
        }

        // NerdAxe no longer borrows one, and this pairing is now correctly
        // REFUSED. It used to pass — which was the mislabelling in miniature:
        // "601" is a BM1370 board on a TPS546, and NerdAxe is BM1366 on a
        // DS4432U whose enable GPIO is inverted relative to it. Accepting the
        // pair would hand a real NerdAxe the wrong regulator driver and the
        // wrong panic-hook polarity.
        let mut mismatched = DcentAxeConfig::default();
        mismatched.board_version = "601".to_string();
        mismatched.board_model = "nerdaxe".to_string();
        assert!(
            !mismatched.board_identity_family_consistent(),
            "a Gamma profile must not validate against the BM1366 NerdAxe"
        );

        // Its own row does pair, and so does the γ's.
        let mut axe = DcentAxeConfig::default();
        axe.board_version = "4004".to_string();
        axe.board_model = "nerdaxe".to_string();
        assert!(axe.board_identity_family_consistent());
        assert!(axe.validate_safety(false).is_ok());

        let mut gamma = DcentAxeConfig::default();
        gamma.board_version = "4005".to_string();
        gamma.board_model = "nerdaxegamma".to_string();
        assert!(gamma.board_identity_family_consistent());
        assert!(gamma.validate_safety(false).is_ok());
    }

    #[test]
    fn support_status_is_recognized_and_conservative() {
        let mut gamma = DcentAxeConfig::default();
        gamma.board_version = "601".to_string();
        gamma.board_model = "gamma".to_string();
        assert!(gamma.board_version_recognized());
        assert_eq!(gamma.support_status(), "supported");

        let mut gt = DcentAxeConfig::default();
        gt.board_version = "801".to_string();
        gt.board_model = "gammaturbo".to_string();
        assert!(gt.board_version_recognized());
        assert_eq!(gt.support_status(), "experimental");

        let mut dcent_bm1397 = DcentAxeConfig::default();
        dcent_bm1397.board_version = "900".to_string();
        dcent_bm1397.board_model = "dcentaxe_bm1397".to_string();
        assert!(dcent_bm1397.board_version_recognized());
        assert_eq!(
            dcent_bm1397.support_status(),
            "experimental",
            "DCENT_axe 900 stays experimental until retained live proof exists"
        );
    }

    #[test]
    fn qualify_operating_point_clamps_and_powerlimits_constants_hold() {
        let cfg = DcentAxeConfig::default(); // Gamma, safe mode
        let limits = cfg.power_limits();

        // A wildly out-of-range request clamps DOWN to the per-model safe
        // envelope and reports `clamped`.
        let over = cfg.qualify_operating_point(99_999.0, u16::MAX, ControlSurface::Autotuner);
        assert!(over.clamped);
        assert!(over.frequency_mhz <= limits.max_frequency);
        assert!(over.voltage_mv <= limits.max_voltage_mv);

        // An explicitly in-range request is returned unchanged (NOT clamped).
        // Gamma safe max_frequency is 475 MHz, so 450/1100 is inside the window;
        // note the default target of 525 MHz would itself clamp.
        let inb = cfg.qualify_operating_point(450.0, 1100, ControlSurface::Autotuner);
        assert!(!inb.clamped);
        assert_eq!(inb.frequency_mhz, 450.0);
        assert_eq!(inb.voltage_mv, 1100);

        // Pin the verbatim magic safety constants — any future edit to the
        // tables breaks CI rather than silently shipping a different envelope.
        let safe_gamma = PowerLimits::safe(BitAxeModel::Gamma);
        let oc_gamma = PowerLimits::overclock(BitAxeModel::Gamma);
        assert_eq!(safe_gamma.max_voltage_mv, 1200);
        assert_eq!(safe_gamma.max_frequency, 475.0);
        assert_eq!(oc_gamma.max_voltage_mv, 1300);
        assert_eq!(oc_gamma.max_frequency, 600.0);
        // Invariant: the overclock envelope is never below the safe envelope.
        assert!(oc_gamma.max_frequency >= safe_gamma.max_frequency);
        assert!(oc_gamma.max_voltage_mv >= safe_gamma.max_voltage_mv);
    }

    #[test]
    fn boot_restore_refuses_out_of_range_voltage_while_runtime_surfaces_clamp() {
        let cfg = DcentAxeConfig::default(); // Gamma: absolute max 1400mV
        let requested = u16::MAX;

        let boot = cfg.qualify_operating_point(450.0, requested, ControlSurface::BootRestore);
        assert!(boot.refused, "foreign boot voltage must be refused");
        assert!(
            boot.clamped,
            "qualified diagnostic value still records the boundary"
        );

        for surface in [
            ControlSurface::Provisioning,
            ControlSurface::RestPatch,
            ControlSurface::LegacyRest,
            ControlSurface::Mcp,
            ControlSurface::Autotuner,
            ControlSurface::Schedule,
        ] {
            let runtime = cfg.qualify_operating_point(450.0, requested, surface);
            assert!(
                !runtime.refused,
                "{surface:?}: runtime clamp behavior is load-bearing"
            );
            assert!(runtime.clamped, "{surface:?}");
        }
    }

    #[test]
    fn qualify_operating_point_fails_closed_on_non_finite_frequency() {
        // `f32::clamp(NaN)` is NaN and `(NaN - NaN).abs() > EPSILON` is false, so a
        // non-finite frequency must NOT slip through THE central V/F clamp
        // unclamped-and-reported-unclamped. It must be forced to a safe finite
        // frequency within the envelope and flagged `clamped`.
        let cfg = DcentAxeConfig::default(); // Gamma, safe mode
        let limits = cfg.power_limits();
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let qp = cfg.qualify_operating_point(bad, 1100, ControlSurface::Autotuner);
            assert!(
                qp.frequency_mhz.is_finite(),
                "non-finite freq {bad} must be replaced with a finite value"
            );
            assert!(
                qp.frequency_mhz <= limits.max_frequency,
                "substituted frequency must stay within the safe envelope"
            );
            assert!(
                qp.clamped,
                "a non-finite frequency must be reported as clamped"
            );
        }
    }

    // ── Power-schedule time helpers (select the freq/volt/autotuner policy on
    //    every loop; previously untested). ──
    fn sched_entry(hour: u8, minute: u8, enabled: bool) -> PowerSchedule {
        PowerSchedule {
            enabled,
            hour,
            minute,
            frequency: 500.0,
            voltage_mv: 1150,
            autotune_enabled: None,
            autotune_mode: None,
            autotune_target: None,
            label: String::new(),
        }
    }

    #[test]
    fn schedule_start_minute_of_day_clamps_and_computes() {
        let mk = |h: u8, m: u8| sched_entry(h, m, true).start_minute_of_day();
        assert_eq!(mk(6, 30), 390);
        assert_eq!(mk(0, 0), 0);
        assert_eq!(mk(23, 59), 1439);
        // Out-of-range hour/minute clamp to 23:59 (no overflow / wraparound).
        assert_eq!(mk(25, 70), 1439);
    }

    #[test]
    fn active_power_schedule_selects_latest_past_entry_and_wraps() {
        let entries = vec![
            sched_entry(6, 0, true),
            sched_entry(12, 0, true),
            sched_entry(18, 0, true),
        ];
        // 13:00 -> the 12:00 entry (latest start <= now).
        assert_eq!(
            active_power_schedule(&entries, 13 * 60).map(|(i, _)| i),
            Some(1)
        );
        // 05:00 -> all entries start later -> wrap to yesterday's LATEST (18:00).
        assert_eq!(
            active_power_schedule(&entries, 5 * 60).map(|(i, _)| i),
            Some(2)
        );
        let empty: [PowerSchedule; 0] = [];
        assert_eq!(active_power_schedule(&empty, 600).map(|(i, _)| i), None);
    }

    #[test]
    fn active_power_schedule_ties_prefer_later_index_and_skip_disabled() {
        // Two entries at the SAME start: the later index wins (>= tie rule).
        let tie = vec![sched_entry(6, 0, true), sched_entry(6, 0, true)];
        assert_eq!(
            active_power_schedule(&tie, 13 * 60).map(|(i, _)| i),
            Some(1)
        );
        // A disabled earlier entry is skipped; the later enabled one is chosen.
        let mixed = vec![sched_entry(6, 0, false), sched_entry(12, 0, true)];
        assert_eq!(
            active_power_schedule(&mixed, 13 * 60).map(|(i, _)| i),
            Some(1)
        );
    }

    #[test]
    fn next_schedule_change_minutes_handles_today_and_midnight_wrap() {
        let entries = vec![sched_entry(6, 0, true), sched_entry(18, 0, true)];
        // 13:00 -> next is 18:00 today: 1080 - 780 = 300.
        assert_eq!(next_schedule_change_minutes(&entries, 13 * 60), Some(300));
        // 20:00 -> nothing later today -> tomorrow's 06:00: 1440 - 1200 + 360 = 600.
        assert_eq!(next_schedule_change_minutes(&entries, 20 * 60), Some(600));
        let empty: [PowerSchedule; 0] = [];
        assert_eq!(next_schedule_change_minutes(&empty, 600), None);
    }

    #[test]
    fn validate_safety_rejects_out_of_envelope_schedule_autotune_target() {
        let mut cfg = DcentAxeConfig::default();
        assert!(
            cfg.validate_safety(false).is_ok(),
            "baseline default config passes safety validation"
        );

        // A schedule slot with autotune enabled + an absurd target_watts must be
        // rejected: the target bypasses the interactive validate_autotune_target
        // envelope and would drive the autotuner past the board power budget when
        // the slot activates.
        cfg.power_schedule.push(PowerSchedule {
            enabled: true,
            hour: 12,
            minute: 0,
            frequency: 500.0,
            voltage_mv: 1150,
            autotune_enabled: Some(true),
            autotune_mode: Some("target_watts".to_string()),
            autotune_target: Some(1_000_000.0),
            label: String::new(),
        });
        assert!(
            cfg.validate_safety(false).is_err(),
            "an out-of-envelope schedule autotune target must be rejected"
        );

        // A target within the envelope passes.
        cfg.power_schedule.last_mut().unwrap().autotune_target = Some(15.0);
        assert!(
            cfg.validate_safety(false).is_ok(),
            "a safe schedule autotune target must be accepted"
        );

        // A non-finite target is also rejected (fail closed).
        cfg.power_schedule.last_mut().unwrap().autotune_target = Some(f32::NAN);
        assert!(
            cfg.validate_safety(false).is_err(),
            "a NaN schedule autotune target must be rejected"
        );

        // MaxHashrate ignores the target entirely, so no envelope rejection.
        let slot = cfg.power_schedule.last_mut().unwrap();
        slot.autotune_mode = Some("max_hashrate".to_string());
        slot.autotune_target = Some(1_000_000.0);
        assert!(
            cfg.validate_safety(false).is_ok(),
            "MaxHashrate ignores the target, so no envelope rejection"
        );
    }

    #[test]
    fn presets_above_safe_max_frequency_are_flagged_requires_overclock() {
        // `requires_overclock` is purely informational — the API surfaces it as
        // `requiresOverclock` so the UI can warn the user. A preset whose
        // frequency exceeds the board's SAFE envelope max but is flagged
        // `requires_overclock: false` therefore LIES to the user (it presents an
        // overclock as safe). Pin the invariant so a mislabeled preset can't ship.
        const MODELS: &[BitAxeModel] = &[
            BitAxeModel::GammaDuo,
            BitAxeModel::GammaTurbo,
            BitAxeModel::Gamma,
            BitAxeModel::Supra,
            BitAxeModel::Ultra,
            BitAxeModel::Max,
            BitAxeModel::HexUltra,
            BitAxeModel::HexSupra,
            BitAxeModel::NerdNOS,
            BitAxeModel::NerdAxe,
            BitAxeModel::NerdQaxePlus,
            BitAxeModel::NerdQaxePP,
            BitAxeModel::Touch,
            BitAxeModel::GtTouch,
        ];
        let mut violations = Vec::new();
        for &model in MODELS {
            let safe_max = PowerLimits::safe(model).max_frequency;
            for p in mining_presets(model) {
                if p.frequency > safe_max && !p.requires_overclock {
                    violations.push(format!(
                        "{:?} '{}' {}MHz > safe-max {}MHz",
                        model, p.name, p.frequency, safe_max
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "presets above safe-max frequency must be flagged requires_overclock (the UI \
             surfaces the flag as safe/unsafe): {violations:?}"
        );
    }

    // ── XPH-2 (GammaTurbo special case, config.rs:405-407) ──
    //
    // Gamma Turbo without explicit overclock must cap voltage at the board
    // default (1150 mV), even though the raw safe envelope would otherwise
    // allow more.
    #[test]
    fn qualify_operating_point_gammaturbo_caps_voltage_without_overclock() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_model = "gammaturbo".to_string();
        cfg.board_version = "801".to_string();
        cfg.overclock_enabled = false;

        let board = cfg.board_config();
        assert_eq!(board.model, BitAxeModel::GammaTurbo);
        let default_v = board.default_voltage_mv;
        assert_eq!(default_v, 1150);

        // A high voltage request is capped at default_voltage_mv in safe mode.
        let qp = cfg.qualify_operating_point(550.0, 1300, ControlSurface::Autotuner);
        assert!(qp.clamped);
        assert_eq!(qp.voltage_mv, default_v);
    }

    // Source text of the two NON-re-included lane files. `include_str!` resolves
    // relative to THIS file's physical location (dcentaxe/src/config.rs) in BOTH
    // the binary-crate build and the dcentaxe-core `#[path]`-reincluded build, so
    // these structural guards run in CI. They pin call-site wiring that lives in
    // files the host crate cannot compile (esp-idf I/O).
    const PROVISIONING_RS: &str = include_str!("provisioning.rs");
    const NVS_CONFIG_RS: &str = include_str!("nvs_config.rs");

    // The config-size cap lives in nvs_config.rs (which is NOT re-included into
    // the host crate), so the host tests pin the magic value locally and assert
    // nvs_config.rs still declares it — keeping the two from drifting.
    const MAX_CONFIG_SIZE_PIN: usize = 3584;

    #[test]
    fn cfg2_max_config_size_constant_is_pinned() {
        assert!(
            NVS_CONFIG_RS.contains("pub const MAX_CONFIG_SIZE: usize = 3584;"),
            "nvs_config.rs must declare pub const MAX_CONFIG_SIZE: usize = 3584 (CFG-2 cap)"
        );
    }

    // ── CFG-2 — bounded body-accumulation decision helpers ──
    #[test]
    fn cfg2_body_read_capacity_and_take_clamp() {
        let max = MAX_CONFIG_SIZE_PIN;
        // Room remains while received + incoming stays at or below the cap.
        assert!(body_read_capacity_ok(0, max, max));
        assert!(body_read_capacity_ok(max - 1, 1, max));
        // One byte past the cap is rejected.
        assert!(!body_read_capacity_ok(max, 1, max));
        assert!(!body_read_capacity_ok(max - 1, 2, max));
        // Saturating: a huge incoming never wraps to "fits".
        assert!(!body_read_capacity_ok(1, usize::MAX, max));

        // next_take clamps the per-read request to remaining capacity, 0 at cap.
        assert_eq!(next_take(0, max), max);
        assert_eq!(next_take(max - 10, max), 10);
        assert_eq!(next_take(max, max), 0);
        assert_eq!(next_take(max + 5, max), 0); // saturating, never underflows
    }

    /// Simulate the accumulation loop over a sequence of segments using ONLY the
    /// pure decision helpers (the real loop's req.read is esp-idf, review-only).
    /// Returns None when the total would exceed `max` (the reject path).
    fn accumulate(segments: &[&[u8]], max: usize) -> Option<Vec<u8>> {
        let mut body: Vec<u8> = Vec::new();
        for seg in segments {
            if next_take(body.len(), max) == 0 && !seg.is_empty() {
                return None;
            }
            if !body_read_capacity_ok(body.len(), seg.len(), max) {
                return None;
            }
            body.extend_from_slice(seg);
        }
        Some(body)
    }

    #[test]
    fn cfg2_chunked_reassembly_and_overflow_reject() {
        let max = MAX_CONFIG_SIZE_PIN;
        // A >1024-byte payload spread across multiple segments reassembles exactly.
        let big = vec![b'A'; 1500];
        let segs: Vec<&[u8]> = big.chunks(300).collect();
        let got = accumulate(&segs, max).expect("multi-segment body must reassemble");
        assert_eq!(got.len(), 1500);
        assert_eq!(got, big);

        // A body exceeding the cap is rejected (None), not truncated.
        let huge = vec![b'B'; max + 1];
        let huge_segs: Vec<&[u8]> = huge.chunks(512).collect();
        assert!(accumulate(&huge_segs, max).is_none());

        // Exactly at the cap fits.
        let exact = vec![b'C'; max];
        let exact_segs: Vec<&[u8]> = exact.chunks(512).collect();
        assert_eq!(accumulate(&exact_segs, max).map(|v| v.len()), Some(max));
    }

    #[test]
    fn cfg2_provisioning_uses_bounded_reader() {
        // The POST handler must call the bounded reader with the MAX_CONFIG_SIZE
        // cap and no longer do a fixed 1024-byte single read.
        assert!(
            PROVISIONING_RS.contains("read_full_body(&mut req, nvs_config::MAX_CONFIG_SIZE)"),
            "provisioning POST handler must use the bounded read_full_body with the config-size cap"
        );
        assert!(
            !PROVISIONING_RS.contains("let mut body = vec![0u8; 1024];"),
            "provisioning POST handler must not keep the fixed 1024-byte single-read footgun"
        );
        // Over-cap bodies are rejected (HTTP 413), never truncated.
        assert!(
            PROVISIONING_RS.contains("BodyReadError::TooLarge") && PROVISIONING_RS.contains("413"),
            "an over-cap body must be rejected with HTTP 413"
        );
    }

    // ── CFG-3 — NVS blob read-back-verify ──
    #[test]
    fn cfg3_blob_write_verified_byte_for_byte() {
        assert!(blob_write_verified(b"hello", b"hello"));
        // Truncated / short read-back fails.
        assert!(!blob_write_verified(b"hello", b"hell"));
        // Single-bit (here single-byte) flip fails.
        assert!(!blob_write_verified(b"hello", b"hellp"));
        // Empty read-back fails for a non-empty write.
        assert!(!blob_write_verified(b"hello", b""));
        // Two empties verify (degenerate but consistent).
        assert!(blob_write_verified(b"", b""));
    }

    #[test]
    fn cfg3_save_config_reads_back_and_verifies() {
        // save_config must read the blob back and route the compare through the
        // host-tested decision fn so a future edit can't strip the verify.
        assert!(
            NVS_CONFIG_RS.contains("blob_write_verified"),
            "save_config must call the host-tested blob_write_verified decision"
        );
        // The read-back get_blob must appear AFTER the set_blob write.
        let set_idx = NVS_CONFIG_RS
            .find("nvs.set_blob(NVS_KEY_CONFIG, &json)")
            .expect("save_config must set_blob the config");
        let verify_idx = NVS_CONFIG_RS
            .find("nvs.get_blob(NVS_KEY_CONFIG, &mut verify_buf)")
            .expect("save_config must read the blob back into verify_buf");
        assert!(
            set_idx < verify_idx,
            "the read-back-verify get_blob (byte {verify_idx}) must follow the set_blob write \
             (byte {set_idx})"
        );
    }

    // ── CFG-5 — version-rolling classifier ──
    #[test]
    fn cfg5_chip_rolls_versions_classifier() {
        assert!(!chip_rolls_versions("BM1397"));
        assert!(!chip_rolls_versions(" BM1397 ")); // trims
        assert!(chip_rolls_versions("BM1370"));
        assert!(chip_rolls_versions("BM1368"));
        assert!(chip_rolls_versions("BM1366"));
        // Empty resolves to a rolling default elsewhere; the helper is purely the
        // string test, so an empty (non-BM1397) string rolls.
        assert!(chip_rolls_versions(""));
    }

    #[test]
    fn cfg5_migrate_computes_single_final_asic_model() {
        // The migrate path must compute one final_asic_model and derive both the
        // persisted asic_model and version_rolling from it (not from the resolved
        // profile), closing the divergence.
        assert!(
            NVS_CONFIG_RS.contains("let final_asic_model ="),
            "migrate_axeos_config must compute a single final_asic_model"
        );
        assert!(
            NVS_CONFIG_RS.contains("chip_rolls_versions(&final_asic_model)"),
            "version_rolling must be derived from final_asic_model via chip_rolls_versions"
        );
        assert!(
            NVS_CONFIG_RS.contains("asic_model: final_asic_model"),
            "the persisted asic_model must BE final_asic_model"
        );
        // The old divergent source of truth is gone.
        assert!(
            !NVS_CONFIG_RS.contains("resolved_profile.asic_model != \"BM1397\""),
            "the old version_rolling = resolved_profile.asic_model != BM1397 divergence must be removed"
        );
    }

    // ── CFG-7 — single fan-default source of truth ──
    #[test]
    fn cfg7_default_fan_target_is_centralized() {
        assert_eq!(DEFAULT_FAN_TARGET_TEMP_C, 0); // 0 = manual mode, magic preserved
        assert_eq!(
            DcentAxeConfig::default().fan_target_temp_c,
            DEFAULT_FAN_TARGET_TEMP_C
        );
        // All three sites reference the const; no divergent literal remains.
        assert!(
            PROVISIONING_RS.contains("DEFAULT_FAN_TARGET_TEMP_C"),
            "provisioning build_submission must reference DEFAULT_FAN_TARGET_TEMP_C"
        );
        assert!(
            NVS_CONFIG_RS.contains("DEFAULT_FAN_TARGET_TEMP_C"),
            "migrate_axeos_config must reference DEFAULT_FAN_TARGET_TEMP_C"
        );
        assert!(
            !PROVISIONING_RS.contains("fan_target_temp_c: 65"),
            "the divergent provisioning literal fan_target_temp_c: 65 must be removed"
        );
    }

    // ── CFG-6 — submit-time safety gate wiring ──
    #[test]
    fn cfg6_provisioning_gates_before_save() {
        // The POST handler must call validate_safety with the lab bypass BEFORE
        // it calls save_config, mirroring the safety_guards install<enable order.
        let gate_idx = PROVISIONING_RS
            .find(".validate_safety(unsafe_lab_safety_bypass_enabled())")
            .expect("provisioning POST handler must call validate_safety with the lab bypass");
        let save_idx = PROVISIONING_RS
            .find("nvs_config::save_config(&mut nvs, &submission.config)")
            .expect("provisioning POST handler must save_config");
        assert!(
            gate_idx < save_idx,
            "validate_safety gate (byte {gate_idx}) must run BEFORE save_config (byte {save_idx})"
        );
        // The bypass helper mirrors the documented env flag.
        assert!(
            PROVISIONING_RS.contains("DCENTAXE_UNSAFE_LAB_SAFETY_BYPASS"),
            "the submit-time gate must honor the documented DCENTAXE_UNSAFE_LAB_SAFETY_BYPASS escape"
        );
    }

    // ── CFG-12 — reject an unconnectable pool endpoint at provisioning ──
    #[test]
    fn cfg12_validate_pool_endpoint_rejects_unconnectable() {
        // Empty / whitespace-only url → reject (the JSON path defaults an absent
        // pool_url to "").
        assert!(validate_pool_endpoint("", 21496).is_err());
        assert!(validate_pool_endpoint("   ", 21496).is_err());
        // port == 0 → reject (form `"0".parse().unwrap_or(...)` and JSON get_u16
        // both yield 0; "host:0" can never connect).
        assert!(validate_pool_endpoint("public-pool.io", 0).is_err());
        // A scheme with NO host can never resolve → reject.
        assert!(validate_pool_endpoint("stratum+tcp://", 3333).is_err());
        // Legit endpoints pass — every shape the live endpoint parser
        // (dcentaxe_stratum::endpoint_host_from_url) resolves to a non-empty host:
        // bare host, scheme://host, and host:port.
        assert!(validate_pool_endpoint("public-pool.io", 21496).is_ok());
        assert!(validate_pool_endpoint("stratum+tcp://public-pool.io", 3333).is_ok());
        assert!(validate_pool_endpoint("solo.ckpool.org:3333", 3333).is_ok());
        // Conservative (NOT rejected on purpose): a url carrying creds resolves to
        // a host, so it passes — DNS/connect is the real authority and
        // over-rejection would lock out a legitimate operator value.
        assert!(validate_pool_endpoint("user:pass@pool.example.com", 3333).is_ok());
    }

    #[test]
    fn cfg12_provisioning_validates_pool_endpoint_before_save() {
        // build_submission must reject an unconnectable pool endpoint BEFORE it
        // constructs + returns the config the POST handler saves and renders
        // "Configuration Saved!" for. Mirror cfg6's byte-ordering pin.
        let call_idx = PROVISIONING_RS
            .find("crate::config::validate_pool_endpoint(&pool_url, pool_port)")
            .expect("build_submission must call validate_pool_endpoint(&pool_url, pool_port)");
        // The config the handler saves is constructed at `let base_config = DcentAxeConfig {`.
        let build_idx = PROVISIONING_RS
            .find("let base_config = DcentAxeConfig {")
            .expect("build_submission must construct the config to save");
        assert!(
            call_idx < build_idx,
            "validate_pool_endpoint (byte {call_idx}) must run BEFORE the saved config is built (byte {build_idx})"
        );
        // …and AFTER the worker check (task: right after the worker check).
        let worker_idx = PROVISIONING_RS
            .find("Bitcoin address required as worker name")
            .expect("build_submission must keep the worker-name check");
        assert!(
            worker_idx < call_idx,
            "validate_pool_endpoint (byte {call_idx}) must run after the worker check (byte {worker_idx})"
        );
    }

    // ── CFG-8 — UTF-8-correct URL decoder ──
    #[test]
    fn cfg8_url_decode_utf8_and_fallbacks() {
        // ASCII unchanged.
        assert_eq!(url_decode("abc"), "abc");
        // '+' becomes space.
        assert_eq!(url_decode("a+b"), "a b");
        // A 2-byte UTF-8 char (é = C3 A9) reassembles, not Latin-1 mojibake.
        assert_eq!(url_decode("%C3%A9"), "é");
        // A 3-byte UTF-8 char (€ = E2 82 AC) round-trips.
        assert_eq!(url_decode("%E2%82%AC"), "€");
        // Mixed literal + multi-byte.
        assert_eq!(url_decode("caf%C3%A9+bar"), "café bar");
        // Invalid hex falls back to literal.
        assert_eq!(url_decode("%ZZ"), "%ZZ");
        // Truncated percent at end-of-string does not panic and re-emits literally.
        assert_eq!(url_decode("ab%A"), "ab%A");
        assert_eq!(url_decode("%"), "%");
        // A lone invalid byte sequence still yields a valid UTF-8 String (lossy),
        // never panics: "%FF" is a lone 0xFF -> replacement char.
        let lossy = url_decode("%FF");
        assert!(std::str::from_utf8(lossy.as_bytes()).is_ok());
    }

    #[test]
    fn cfg8_provisioning_uses_shared_url_decode() {
        assert!(
            PROVISIONING_RS.contains("crate::config::url_decode(value)"),
            "the form parser must call the host-tested crate::config::url_decode"
        );
        assert!(
            !PROVISIONING_RS.contains("fn url_decode(s: &str) -> String {"),
            "provisioning must not keep a private divergent url_decode"
        );
    }

    // ── CFG-4 — credentials are not leaked on the provisioning path ──
    // No at-rest encryption is claimed here (that is operator-gated
    // sdkconfig/eFuse work). The deliverable guard is a NEGATIVE one: ensure the
    // provisioning path never formats the user WiFi PSK / pool password into a
    // log line, so a future edit can't introduce a secret leak. The only password
    // shown by design is the ephemeral CSPRNG hotspot password on the OLED.
    #[test]
    fn cfg4_provisioning_never_logs_user_secrets() {
        for line in PROVISIONING_RS.lines() {
            let l = line.trim_start();
            let is_log = l.starts_with("info!")
                || l.starts_with("warn!")
                || l.starts_with("error!")
                || l.starts_with("log::info!")
                || l.starts_with("log::warn!")
                || l.starts_with("log::error!")
                || l.starts_with("debug!")
                || l.starts_with("log::debug!");
            if !is_log {
                continue;
            }
            // The user WiFi PSK / pool password variables must never appear in a
            // log statement. (`ap_password` — the ephemeral OLED recovery code —
            // is shown on the display, not via the log macros guarded here.)
            assert!(
                !line.contains("wifi_password"),
                "provisioning must never log the user WiFi PSK: {line}"
            );
            assert!(
                !line.contains("pool_pass") && !line.contains("stratum.password"),
                "provisioning must never log the pool password: {line}"
            );
        }
    }

    // ── CFG-10 — schema forward/backward decision ──
    #[test]
    fn cfg10_schema_action_classifies() {
        assert_eq!(schema_action(0, 1), SchemaAction::MigrateForward(0));
        assert_eq!(schema_action(1, 1), SchemaAction::Current);
        assert_eq!(schema_action(2, 1), SchemaAction::RefuseFuture);
        assert_eq!(schema_action(255, 1), SchemaAction::RefuseFuture);
    }

    #[test]
    fn cfg10_future_blob_does_not_claim_future_shape() {
        // A simulated FUTURE blob (schema_version = 2) deserialized through the
        // current loader struct, then run through the schema decision, must NOT
        // be left claiming the future shape: schema_action says RefuseFuture and
        // the marker is clamped to the current SCHEMA_VERSION. Known fields
        // (wifi_ssid, stratum) survive serde round-trip.
        let mut cfg = DcentAxeConfig::default();
        cfg.wifi_ssid = "homenet".to_string();
        cfg.schema_version = 2; // pretend a newer firmware wrote this
        let json = serde_json::to_string(&cfg).unwrap();
        let mut loaded: DcentAxeConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            schema_action(loaded.schema_version, SCHEMA_VERSION),
            SchemaAction::RefuseFuture
        );
        // Apply the clamp the migrate path performs on RefuseFuture.
        if schema_action(loaded.schema_version, SCHEMA_VERSION) == SchemaAction::RefuseFuture {
            loaded.schema_version = SCHEMA_VERSION;
        }
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert_eq!(loaded.wifi_ssid, "homenet"); // known field preserved
    }

    // CFG-10 (2026-06-29): migrate_config moved into this host-compiled module,
    // so we now behavior-test the real mutation instead of string-matching it.
    #[test]
    fn cfg10_migrate_config_stamps_legacy_schema_to_current() {
        // A legacy blob (schema_version = 0, the serde default for a pre-schema
        // config) is forward-migrated to the current schema while every known
        // field — WiFi creds, stratum endpoint — survives untouched.
        let mut cfg = DcentAxeConfig::default();
        cfg.schema_version = 0;
        cfg.wifi_ssid = "homenet".to_string();
        cfg.wifi_password = "secret".to_string();
        cfg.stratum.url = "public-pool.io".to_string();
        cfg.stratum.port = 21496;

        migrate_config(&mut cfg);

        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
        assert_eq!(cfg.wifi_ssid, "homenet");
        assert_eq!(cfg.wifi_password, "secret");
        assert_eq!(cfg.stratum.url, "public-pool.io");
        assert_eq!(cfg.stratum.port, 21496);
    }

    #[test]
    fn cfg10_migrate_config_clamps_future_blob_refusefuture() {
        // A blob written by NEWER firmware (schema_version > SCHEMA_VERSION) is
        // the RefuseFuture arm: the marker is clamped DOWN to the current version
        // so the loader never claims to round-trip the future shape, and known
        // fields survive.
        let mut cfg = DcentAxeConfig::default();
        cfg.schema_version = SCHEMA_VERSION.saturating_add(1);
        cfg.wifi_ssid = "homenet".to_string();
        assert_eq!(
            schema_action(cfg.schema_version, SCHEMA_VERSION),
            SchemaAction::RefuseFuture
        );

        migrate_config(&mut cfg);

        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
        assert_eq!(cfg.wifi_ssid, "homenet");
    }

    #[test]
    fn cfg10_migrate_config_is_idempotent() {
        // Running migrate_config twice equals running it once (additive,
        // idempotent migrations — old firmware may still be in the field).
        let mut once = DcentAxeConfig::default();
        once.schema_version = 0;
        once.wifi_ssid = "homenet".to_string();
        migrate_config(&mut once);

        let mut twice = DcentAxeConfig::default();
        twice.schema_version = 0;
        twice.wifi_ssid = "homenet".to_string();
        migrate_config(&mut twice);
        migrate_config(&mut twice);

        assert_eq!(twice.schema_version, SCHEMA_VERSION);
        assert_eq!(once.schema_version, twice.schema_version);
        assert_eq!(once.wifi_ssid, twice.wifi_ssid);
    }

    #[test]
    fn cfg10_migrate_config_still_invoked_from_nvs_loader() {
        // The mutation moved into config.rs (host-tested above). Pin that the NVS
        // loader — which cannot host-compile (esp-idf-svc) — still calls it on
        // every load, so the behavior actually runs on device.
        assert!(
            NVS_CONFIG_RS.contains("crate::config::migrate_config(&mut config)"),
            "nvs_config::load_config must call crate::config::migrate_config on the loaded blob"
        );
    }

    // ── XPSAFE-3 — extended safety-gate regression pins (beyond Phase-1 XPH-1/2) ──

    /// Build a custom (non-table) hardware override for XPSAFE-3, reusing the
    /// XPH-1 controller-kind pattern.
    fn xpsafe3_custom_hw(
        fan: FanControllerKind,
        temp: TempSensorKind,
        power: PowerControllerKind,
    ) -> BoardHardwareConfig {
        custom_hw(fan, temp, power)
    }

    #[test]
    fn xpsafe3_custom_board_each_missing_controller_fails_closed() {
        // Each of the three required controllers, individually absent on a custom
        // mining-capable board, must Err without the bypass and Ok with it.
        let cases = [
            xpsafe3_custom_hw(
                FanControllerKind::None,
                TempSensorKind::Emc2101,
                PowerControllerKind::Tps546,
            ),
            xpsafe3_custom_hw(
                FanControllerKind::Emc2101,
                TempSensorKind::None,
                PowerControllerKind::Tps546,
            ),
            xpsafe3_custom_hw(
                FanControllerKind::Emc2101,
                TempSensorKind::Emc2101,
                PowerControllerKind::None,
            ),
        ];
        for hw in cases {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = "DCENT-XPSAFE3-NOPROFILE".to_string();
            assert!(BoardVersionProfile::find(&cfg.board_version).is_none());
            cfg.hardware = Some(hw);
            assert!(cfg.board_config().mining_capable());
            assert!(
                cfg.validate_safety(false).is_err(),
                "missing required controller must fail-closed without bypass"
            );
            assert!(
                cfg.validate_safety(true).is_ok(),
                "explicit lab bypass must permit the bench exception"
            );
        }
    }

    #[test]
    fn xpsafe3_qualify_operating_point_clamp_invariants() {
        // Across several models, any input is clamped into [min, max] and the
        // clamped flag is set iff a clamp actually happened.
        for (model, ver) in [
            (BitAxeModel::Gamma, "601"),
            (BitAxeModel::GammaTurbo, "801"),
            (BitAxeModel::Max, ""),
            (BitAxeModel::HexSupra, ""),
        ] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_model = model.canonical_key().to_string();
            if !ver.is_empty() {
                cfg.board_version = ver.to_string();
            } else {
                // For models without an explicit version here, drive selection by
                // asic to land on the intended model.
                cfg.board_version = String::new();
            }
            cfg.canonicalize_identity();

            let board = cfg.board_config();
            let stock = stock_asic_settings(board.model);
            let limits = cfg.power_limits();
            let min_f = stock.frequency_options.iter().copied().min().unwrap_or(50) as f32;
            let max_f = limits.max_frequency.min(
                stock
                    .frequency_options
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(limits.max_frequency.round() as u16) as f32,
            );

            // Above-max freq AND above-max voltage clamps BOTH down + clamped.
            let over = cfg.qualify_operating_point(99_999.0, u16::MAX, ControlSurface::Autotuner);
            assert!(over.clamped, "{model:?}: out-of-range must report clamped");
            assert!(over.frequency_mhz <= max_f + f32::EPSILON);
            assert!(over.voltage_mv <= limits.max_voltage_mv);

            // Below-min freq clamps UP and is reported clamped.
            let under = cfg.qualify_operating_point(1.0, 1, ControlSurface::Autotuner);
            assert!(under.clamped, "{model:?}: below-min must report clamped");
            assert!(under.frequency_mhz >= min_f.min(max_f) - f32::EPSILON);

            // Fuzz: every output is inside the envelope.
            for f in [50.0_f32, 200.0, 400.0, 600.0, 1200.0] {
                for v in [800u16, 1100, 1300, 1600] {
                    let qp = cfg.qualify_operating_point(f, v, ControlSurface::Autotuner);
                    assert!(qp.frequency_mhz >= min_f.min(max_f) - f32::EPSILON);
                    assert!(qp.frequency_mhz <= max_f + f32::EPSILON);
                    assert!(qp.voltage_mv <= limits.max_voltage_mv);
                }
            }
        }
    }

    #[test]
    fn xpsafe3_gammaturbo_voltage_cap_holds_without_overclock() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_model = "gammaturbo".to_string();
        cfg.board_version = "801".to_string();
        cfg.overclock_enabled = false;
        let board = cfg.board_config();
        assert_eq!(board.model, BitAxeModel::GammaTurbo);
        let default_v = board.default_voltage_mv;
        // Even a request at the raw safe envelope max is capped to default in
        // non-overclock mode.
        let safe_max_v = PowerLimits::safe(BitAxeModel::GammaTurbo).max_voltage_mv;
        assert!(
            safe_max_v > default_v,
            "test premise: safe max exceeds default"
        );
        let qp = cfg.qualify_operating_point(500.0, safe_max_v, ControlSurface::Autotuner);
        assert_eq!(qp.voltage_mv, default_v);
        assert!(qp.clamped);
    }

    /// Regression guard for the voltage-clamp panic asymmetry: `u16::clamp` panics when
    /// min > max (reboot under panic=abort), and `qualify_operating_point` narrows
    /// `max_voltage_mv` (GammaTurbo non-overclock cap) AFTER the floor is fixed. Re-derive
    /// the exact bounds for EVERY shipped board version in BOTH overclock modes and assert
    /// floor <= cap (proves the panic is unreachable today), then adversarially sweep
    /// qualify itself to prove it never panics regardless.
    #[test]
    fn voltage_clamp_never_panics_across_all_models() {
        for profile in dcentaxe_hal::board::BoardVersionProfile::ALL {
            for overclock in [false, true] {
                let mut cfg = DcentAxeConfig::default();
                cfg.board_model = profile.device_model.to_string();
                cfg.board_version = profile.board_version.to_string();
                cfg.overclock_enabled = overclock;
                cfg.canonicalize_identity();
                let board = cfg.board_config();
                let stock = stock_asic_settings(board.model);
                let limits = cfg.power_limits();

                // Mirror the exact derivation in qualify_operating_point (min floor, then the
                // GammaTurbo non-overclock narrowing of max toward default_voltage_mv).
                let floor = board.min_voltage_mv.max(
                    stock
                        .voltage_options
                        .iter()
                        .copied()
                        .min()
                        .unwrap_or(board.min_voltage_mv),
                );
                let mut cap = limits.max_voltage_mv.min(
                    stock
                        .voltage_options
                        .iter()
                        .copied()
                        .max()
                        .unwrap_or(limits.max_voltage_mv),
                );
                if board.model == BitAxeModel::GammaTurbo && !overclock {
                    cap = cap.min(board.default_voltage_mv);
                }
                assert!(
                    floor <= cap,
                    "{} v{} oc={overclock}: derived voltage floor {floor} > cap {cap} — u16::clamp would panic",
                    profile.device_model,
                    profile.board_version
                );

                // Belt-and-suspenders: qualify never panics on adversarial operating points.
                for &f in &[f32::NAN, 0.0, 650.0, 99_999.0] {
                    for &v in &[0u16, 1350, u16::MAX] {
                        let qp = cfg.qualify_operating_point(f, v, ControlSurface::Autotuner);
                        assert!(qp.voltage_mv <= board.max_voltage_mv);
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PLAN-E Phase 1 — W5500 LAN config + accessory-guard activation gate.
// Host-run via the dcentaxe-core `#[path]` re-include (`cargo test -p dcentaxe-core`).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod w5500_lan_network_config_guards {
    use super::*;

    // ── DEFAULT-OFF: a fresh unit ships Ethernet-dark ────────────────────────
    #[test]
    fn network_config_defaults_off_with_eth_preferred_mode() {
        let cfg = DcentAxeConfig::default();
        assert!(
            !cfg.network.eth_enabled,
            "network.eth_enabled must default OFF (Ethernet-dark)"
        );
        assert_eq!(cfg.network.mode, NetworkMode::EthPreferred);
        assert_eq!(
            cfg.eth_lan_activation(),
            Ok(false),
            "default config must not activate the W5500 LAN"
        );
    }

    // ── Legacy NVS blobs without the field round-trip to the disabled default ─
    #[test]
    fn legacy_blob_without_network_field_loads_disabled_default() {
        let full = DcentAxeConfig::default();
        let schema = full.schema_version;
        let mut value = serde_json::to_value(&full).unwrap();
        value.as_object_mut().unwrap().remove("network");
        let loaded: DcentAxeConfig = serde_json::from_value(value).unwrap();
        assert!(!loaded.network.eth_enabled);
        assert_eq!(loaded.network.mode, NetworkMode::EthPreferred);
        assert_eq!(loaded.schema_version, schema, "no schema bump needed");
    }

    // ── Serde shape: kebab-case mode tokens are the wire contract ────────────
    #[test]
    fn network_mode_serializes_kebab_case_and_round_trips() {
        for (mode, token) in [
            (NetworkMode::WifiOnly, "\"wifi-only\""),
            (NetworkMode::EthOnly, "\"eth-only\""),
            (NetworkMode::EthPreferred, "\"eth-preferred\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), token);
            let back: NetworkMode = serde_json::from_str(token).unwrap();
            assert_eq!(back, mode);
        }
        assert!(serde_json::from_str::<NetworkMode>("\"invented\"").is_err());
    }

    // ── Activation gate matrix ───────────────────────────────────────────────
    #[test]
    fn eth_enabled_on_a_no_bap_board_activates() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_model = "gamma".into(); // stock Gamma: no BAP header populated
        cfg.board_version = String::new();
        cfg.network.eth_enabled = true;
        assert!(!cfg.board_config().model.has_bap(), "test premise");
        assert_eq!(cfg.eth_lan_activation(), Ok(true));
    }

    #[test]
    fn wifi_only_mode_makes_the_toggle_inert() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_model = "gamma".into();
        cfg.board_version = String::new();
        cfg.network.eth_enabled = true;
        cfg.network.mode = NetworkMode::WifiOnly;
        assert_eq!(cfg.eth_lan_activation(), Ok(false));
    }

    // The crux guard: W5500 SPI rides the BAP-UART pins (GPIO39/40), so a
    // BAP-Touch board must REFUSE LAN — fail-closed, mining unaffected.
    #[test]
    fn eth_enabled_on_a_bap_board_is_refused_by_the_accessory_guard() {
        for bap_model in ["touch", "dcentaxe_bm1397"] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_model = bap_model.into();
            cfg.board_version = String::new();
            cfg.network.eth_enabled = true;
            let board = cfg.board_config();
            assert!(board.model.has_bap(), "test premise for '{bap_model}'");
            assert_eq!(board.accessory_mode(), AccessoryMode::BapTouch);
            let refused = cfg.eth_lan_activation();
            assert!(
                refused.is_err(),
                "'{bap_model}' must refuse W5500 LAN while accessory mode is BAP-Touch"
            );
            // The refusal is the existing guard's message — activation must go
            // through validate_accessory_mode, not a parallel re-implementation.
            assert_eq!(
                refused,
                Err(board
                    .validate_accessory_mode(AccessoryMode::W5500Lan)
                    .unwrap_err())
            );
        }
    }

    // EthOnly requests still respect the guard (only WifiOnly is inert).
    #[test]
    fn eth_only_mode_still_goes_through_the_guard() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_model = "gamma".into();
        cfg.board_version = String::new();
        cfg.network.eth_enabled = true;
        cfg.network.mode = NetworkMode::EthOnly;
        assert_eq!(cfg.eth_lan_activation(), Ok(true));

        cfg.board_model = "touch".into();
        assert!(cfg.eth_lan_activation().is_err());
    }
}

// ── Lucky-enablement SPEC §3 / §1.2 — host tests for the fail-closed identity
// gate and the anonymous-subscribe latch (compiled on the host gate via the
// dcentaxe-core `#[path]` re-include of this file).
#[cfg(test)]
mod identity_gate_tests {
    use super::*;
    use dcentaxe_hal::hammer_strap::HammerStrapProbeVerdict;
    use dcentaxe_hal::tps546_guard::LuckyProbeVerdict;

    fn no_probe_expected() -> Option<LuckyProbeVerdict> {
        panic!(
            "the probe closure must ONLY run from the AMBIGUOUS branch \
             (power.rs caller contract — 0x7F is an I2C spec-reserved address)"
        );
    }

    fn no_strap_probe_expected(_: u8) -> Option<HammerStrapProbeVerdict> {
        panic!("identity strap probe must be model-gated to Hammer DC rows")
    }

    fn adopted_version(outcome: IdentityGateOutcome) -> &'static str {
        match outcome {
            IdentityGateOutcome::AdoptProfile(row) => row.board_version,
            other => panic!("expected AdoptProfile, got {other:?}"),
        }
    }

    // ── The 3.6 V trap itself: an unlocked LV08 (302/lv08) must NEVER stand
    // as a Hex Ultra. Resolution happens on strings alone — no probe runs. ──
    #[test]
    fn unlocked_lv08_resolves_to_lucky_2008_without_probing() {
        let outcome = resolve_identity_gate("302", "lv08", "", no_probe_expected);
        assert_eq!(adopted_version(outcome), "2008");
    }

    // Stock Lucky factory identity (402/supra/LV08): minermodel is
    // authoritative, again with no probe.
    #[test]
    fn stock_lucky_lv08_resolves_via_minermodel_without_probing() {
        let outcome = resolve_identity_gate("402", "supra", "LV08", no_probe_expected);
        assert_eq!(adopted_version(outcome), "2008");
        let outcome = resolve_identity_gate("402", "supra", "LV06", no_probe_expected);
        assert_eq!(adopted_version(outcome), "2006");
    }

    // A-suffixed vendor boardversions resolve directly (SPEC §1.2).
    #[test]
    fn a_suffixed_boardversions_adopt_lucky_rows() {
        assert_eq!(
            adopted_version(resolve_identity_gate("302A", "", "", no_probe_expected)),
            "2008"
        );
        assert_eq!(
            adopted_version(resolve_identity_gate("300A", "", "", no_probe_expected)),
            "2006"
        );
        assert_eq!(
            adopted_version(resolve_identity_gate("301A", "", "", no_probe_expected)),
            "2007"
        );
    }

    // A consistent genuine BitAxe never probes and never changes.
    #[test]
    fn canonical_identities_proceed_without_probe() {
        for (bv, dm) in [
            ("302", "hex"),
            ("402", "supra"),
            ("601", "gamma"),
            ("2008", "lucky_lv08"),
            ("2006", "lv06"),
        ] {
            assert_eq!(
                resolve_identity_gate(bv, dm, "", no_probe_expected),
                IdentityGateOutcome::Proceed,
                "({bv},{dm}) must proceed unchanged"
            );
        }
    }

    // ── SPEC §3 step 4: the ambiguous collision runs the probe. ──
    #[test]
    fn ambiguous_302_probe_decides_lv08_vs_genuine_hex() {
        // Both LV08-only addresses answered ⇒ adopt the LV08 row.
        let outcome = resolve_identity_gate("302", "", "", || {
            Some(LuckyProbeVerdict::TripleRegulatorLv08)
        });
        assert_eq!(adopted_version(outcome), "2008");

        // Neither answered ⇒ genuine BitAxe ⇒ legacy resolution stands.
        let outcome = resolve_identity_gate("302", "", "", || {
            Some(LuckyProbeVerdict::NoSecondaryRegulators)
        });
        assert_eq!(outcome, IdentityGateOutcome::Proceed);
    }

    // ── SPEC §3 step 5: inconclusive (or unavailable) probe ⇒ REFUSE. ──
    #[test]
    fn inconclusive_probe_refuses_to_energize() {
        for probe_result in [Some(LuckyProbeVerdict::Inconclusive), None] {
            let outcome = resolve_identity_gate("302", "", "", || probe_result);
            match outcome {
                IdentityGateOutcome::RefuseToEnergize { reason } => {
                    assert!(
                        reason.to_ascii_lowercase().contains("refusing to energize"),
                        "refusal must say why: {reason}"
                    );
                }
                other => panic!("probe={probe_result:?} must refuse, got {other:?}"),
            }
        }
        // 402-with-minermodel collision (unrecognized minermodel) also refuses
        // when the probe cannot settle it.
        let outcome = resolve_identity_gate("402", "supra", "LV99", || {
            Some(LuckyProbeVerdict::Inconclusive)
        });
        assert!(matches!(
            outcome,
            IdentityGateOutcome::RefuseToEnergize { .. }
        ));
    }

    // Unknown tuples proceed — validate_safety's unrecognized-identity refusal
    // already fails them closed (no probe runs).
    #[test]
    fn unknown_identity_proceeds_to_existing_refusal_path() {
        assert_eq!(
            resolve_identity_gate("999x", "", "", no_probe_expected),
            IdentityGateOutcome::Proceed
        );
    }

    // ── SPEC §1.2 — anonymous-subscribe latch. ──
    #[test]
    fn a_suffix_latches_anonymous_subscribe_before_canonical_rewrite() {
        for raw in ["300A", "301a", "302A", " 302a "] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = raw.to_string();
            cfg.canonicalize_identity();
            assert!(
                cfg.anonymous_subscribe,
                "raw boardversion '{raw}' must latch anonymous_subscribe"
            );
        }
        // Plain versions do NOT set it…
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "302".to_string();
        cfg.canonicalize_identity();
        assert!(!cfg.anonymous_subscribe);
        // …and canonicalization never CLEARS an already-latched flag.
        let mut cfg = DcentAxeConfig::default();
        cfg.anonymous_subscribe = true;
        cfg.board_version = "2008".to_string();
        cfg.board_model = "lucky_lv08".to_string();
        cfg.canonicalize_identity();
        assert!(cfg.anonymous_subscribe, "latch must never be auto-cleared");
    }

    #[test]
    fn board_version_anonymous_classifier_table() {
        for yes in ["300A", "301A", "302A", "300a", " 302a "] {
            assert!(board_version_requests_anonymous_subscribe(yes), "{yes}");
        }
        for no in ["300", "302", "2008", "402", "", "303A", "hammer-bc01"] {
            assert!(!board_version_requests_anonymous_subscribe(no), "{no}");
        }
    }

    // Legacy NVS blobs (no miner_model / anonymous_subscribe keys) round-trip
    // with the safe defaults and no schema bump.
    #[test]
    fn legacy_blob_defaults_new_identity_fields() {
        let full = DcentAxeConfig::default();
        let mut value = serde_json::to_value(&full).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("miner_model");
        obj.remove("anonymous_subscribe");
        let loaded: DcentAxeConfig = serde_json::from_value(value).unwrap();
        assert_eq!(loaded.miner_model, "");
        assert!(!loaded.anonymous_subscribe);
        assert_eq!(loaded.schema_version, full.schema_version);
    }

    // The Lucky build-default arms exist (a missing cfg! arm silently builds
    // the final Gamma fallback — R2). Host builds compile with no board
    // feature, so pin the production fn's SOURCE REGION (sliced to the fn
    // body, per the include_str! self-match trap rule) instead of runtime cfg!.
    #[test]
    fn default_model_for_build_has_lucky_arms() {
        // Checkout-invariant: the fn-end search below spans line breaks, so normalise CRLF
        // first (this guard failed on every autocrlf worktree in the 2026-09-03 UI Gauntlet).
        let src_owned = include_str!("config.rs").replace("\r\n", "\n");
        let src: &str = src_owned.as_str();
        let fn_start = src
            .find("pub(crate) fn default_model_for_build()")
            .expect("default_model_for_build must exist");
        let fn_end = src[fn_start..]
            .find("\n}\n")
            .map(|off| fn_start + off)
            .expect("fn body end");
        let body = &src[fn_start..fn_end];
        for (feature, model) in [
            ("lucky-lv06", "LuckyLv06"),
            ("lucky-lv07", "LuckyLv07"),
            ("lucky-lv08", "LuckyLv08"),
        ] {
            assert!(
                body.contains(&format!("cfg!(feature = \"{feature}\")")),
                "default_model_for_build must branch on {feature}"
            );
            assert!(
                body.contains(&format!("BitAxeModel::{model}")),
                "default_model_for_build must map {feature} to {model}"
            );
        }
    }

    // Lucky safe envelopes stay at/under the SPEC §1 vendor ratings and get
    // zero overclock headroom (SPEC §8: no hardware, no proof).
    #[test]
    fn lucky_power_envelopes_match_spec_ratings() {
        assert_eq!(PowerLimits::safe(BitAxeModel::LuckyLv06).max_power_w, 40.0);
        assert_eq!(PowerLimits::safe(BitAxeModel::LuckyLv07).max_power_w, 40.0);
        assert_eq!(PowerLimits::safe(BitAxeModel::LuckyLv08).max_power_w, 135.0);
        for model in [
            BitAxeModel::LuckyLv06,
            BitAxeModel::LuckyLv07,
            BitAxeModel::LuckyLv08,
        ] {
            let safe = PowerLimits::safe(model);
            let oc = PowerLimits::overclock(model);
            assert_eq!(oc.max_power_w, safe.max_power_w, "{model:?}: no headroom");
            assert_eq!(oc.max_voltage_mv, safe.max_voltage_mv, "{model:?}");
            assert_eq!(oc.max_frequency, safe.max_frequency, "{model:?}");
            // Presets stay inside the safe envelope and never gate on the
            // (headroom-less) overclock flag.
            for preset in mining_presets(model) {
                assert!(!preset.requires_overclock, "{model:?} '{}'", preset.name);
                assert!(preset.frequency <= safe.max_frequency);
                assert!(preset.voltage_mv <= safe.max_voltage_mv);
                assert!(preset.expected_power_w <= safe.max_power_w);
            }
        }
    }

    // ════ WIRING tests — the resolver being correct is not enough; production
    // must actually CALL it with the right stored fields (the "green tests,
    // broken product" failure mode). ════

    // The caller's argument choice, as a pure function: all three stored
    // fields flow through, in order. Mutation-checked: dropping `miner_model`
    // turns the stock-Lucky case into Proceed (Supra!) and this test fails;
    // dropping `board_model` makes the unlocked-Lucky case hit the
    // panicking probe closure and this test fails.
    #[test]
    fn run_identity_gate_wires_all_three_stored_identity_fields() {
        // miner_model is load-bearing: stock Lucky (402/supra/LV08).
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "402".into();
        cfg.board_model = "supra".into();
        cfg.miner_model = "LV08".into();
        assert_eq!(
            cfg.identity_gate_inputs(),
            ("402", "supra", "LV08"),
            "gate inputs must be (board_version, board_model, miner_model) verbatim"
        );
        match cfg.run_identity_gate(no_probe_expected) {
            IdentityGateOutcome::AdoptProfile(row) => assert_eq!(row.board_version, "2008"),
            other => panic!("stock Lucky LV08 must adopt 2008 via minermodel, got {other:?}"),
        }

        // board_model (device_model) is load-bearing: unlocked Lucky (302/lv08)
        // must resolve on strings alone — the panicking probe closure proves
        // the devicemodel actually reached the resolver.
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "302".into();
        cfg.board_model = "lv08".into();
        cfg.miner_model = String::new();
        match cfg.run_identity_gate(no_probe_expected) {
            IdentityGateOutcome::AdoptProfile(row) => assert_eq!(row.board_version, "2008"),
            other => panic!("unlocked Lucky LV08 must adopt 2008 via devicemodel, got {other:?}"),
        }
    }

    #[test]
    fn apply_identity_profile_adopts_canonical_row() {
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "302A".into();
        cfg.board_model = "lv08".into();
        cfg.asic_count = 6; // stale Hex count from a naive prior resolution
        cfg.hardware = Some(BoardHardwareConfig {
            plug_sense: false,
            asic_enable: true,
            fan_controller: FanControllerKind::Emc2101,
            temp_sensor: TempSensorKind::Emc2101,
            power_controller: PowerControllerKind::Ds4432u,
            has_ina260: false,
            emc_internal_temp: false,
            emc_ideality_factor: 0x24,
            emc_beta_compensation: 0,
            temp_offset_c: 0,
            power_consumption_target_w: 19,
        });
        cfg.identity_refusal = Some("stale".into());
        let row = BoardVersionProfile::find("2008").unwrap();
        cfg.apply_identity_profile(row);
        assert_eq!(cfg.board_version, "2008");
        // The adopted board_model is the model's canonical key ("lv08" — the
        // vendor's own devicemodel spelling) and MUST round-trip through
        // from_device_model so every later resolution lands on the same model.
        assert_eq!(cfg.board_model, row.model.canonical_key());
        assert_eq!(
            dcentaxe_hal::board::BitAxeModel::from_device_model(&cfg.board_model),
            Some(row.model),
            "adopted board_model must round-trip to the adopted model"
        );
        assert_eq!(cfg.asic_model, "BM1366");
        assert_eq!(cfg.asic_count, 9, "LV08 is nine chips, one parallel domain");
        assert!(
            cfg.hardware.is_none(),
            "adopting a registered row must clear stale custom hardware"
        );
        assert!(cfg.identity_refusal.is_none());
        assert!(
            cfg.anonymous_subscribe,
            "raw 302A must latch anonymous_subscribe before the rewrite erases the suffix"
        );
        // And the adopted identity is stable: the gate now proceeds.
        assert_eq!(
            cfg.run_identity_gate(no_probe_expected),
            IdentityGateOutcome::Proceed
        );
        // SPEC §1.1: the adopted board is ONE parallel domain — never Hex's 3.
        assert_eq!(cfg.board_config().voltage_domains, 1);
    }

    #[test]
    fn hammer_strap_gate_is_model_gated_and_all_registered_rows_match() {
        let cfg = DcentAxeConfig::default();
        assert_eq!(
            cfg.run_identity_strap_gate(no_strap_probe_expected),
            IdentityStrapGateOutcome::Proceed,
            "non-Hammer models must never touch strap candidate addresses"
        );

        for (version, model, expected) in [
            ("3102", "hammer_dc02", 0x48),
            ("3104", "hammer_dc04", 0x4C),
            ("3106", "hammer_dc06", 0x4F),
        ] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = version.into();
            cfg.board_model = model.into();
            assert_eq!(
                cfg.run_identity_strap_gate(|address| {
                    assert_eq!(address, expected, "{version}");
                    Some(HammerStrapProbeVerdict::Match)
                }),
                IdentityStrapGateOutcome::Proceed,
                "{version}"
            );
        }
    }

    #[test]
    fn hammer_strap_absent_mismatch_and_unreadable_reach_master_refusal() {
        for verdict in [
            Some(HammerStrapProbeVerdict::Absent),
            Some(HammerStrapProbeVerdict::Mismatch {
                observed_mask: dcentaxe_hal::hammer_strap::hammer_strap_addr_bit(0x4A)
                    | dcentaxe_hal::hammer_strap::hammer_strap_addr_bit(0x4E),
            }),
            None,
        ] {
            let mut cfg = DcentAxeConfig::default();
            cfg.board_version = "3104".into();
            cfg.board_model = "hammer_dc04".into();
            let reason = match cfg.run_identity_strap_gate(|expected| {
                assert_eq!(expected, 0x4C);
                verdict
            }) {
                IdentityStrapGateOutcome::RefuseToEnergize { reason } => reason,
                other => panic!("bad strap evidence must refuse, got {other:?}"),
            };
            cfg.identity_refusal = Some(reason);
            let err = cfg.validate_safety(false).unwrap_err();
            assert!(
                err.contains("identity gate") && err.contains("identity strap"),
                "strap refusal must win at the production master gate: {err}"
            );
        }
    }

    // The refusal is enforced through the EXISTING master gate
    // (validate_safety), checked before every other check, and only the
    // explicit unsafe-lab bypass can override it.
    #[test]
    fn validate_safety_checks_identity_refusal_first_and_only_lab_bypass_overrides() {
        let mut cfg = DcentAxeConfig::default();
        assert!(cfg.validate_safety(false).is_ok(), "test premise");
        cfg.identity_refusal = Some("probe inconclusive".into());
        let err = cfg.validate_safety(false).unwrap_err();
        assert!(
            err.contains("identity gate") && err.contains("probe inconclusive"),
            "refusal must surface the gate reason: {err}"
        );
        assert!(cfg.validate_safety(true).is_ok(), "lab bypass overrides");

        // Checked FIRST: even on a config that would also fail a later check
        // (unrecognized identity), the identity-gate reason wins.
        let mut cfg = DcentAxeConfig::default();
        cfg.board_version = "999x".into();
        cfg.board_model = "nonsense".into();
        cfg.identity_refusal = Some("probe inconclusive".into());
        let err = cfg.validate_safety(false).unwrap_err();
        assert!(
            err.contains("identity gate"),
            "identity refusal must be the FIRST check: {err}"
        );
    }

    // identity_refusal is runtime-only: never serialized, never accepted from
    // a stored blob (a stale blob must not be able to suppress OR fabricate a
    // refusal — it is recomputed every boot).
    #[test]
    fn identity_refusal_is_never_persisted() {
        let mut cfg = DcentAxeConfig::default();
        cfg.identity_refusal = Some("probe inconclusive".into());
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            !json.contains("identity_refusal"),
            "identity_refusal must be #[serde(skip)]"
        );
        let injected: DcentAxeConfig = serde_json::from_str(&json.replace(
            "\"miner_model\":\"\"",
            "\"miner_model\":\"\",\"identity_refusal\":\"fabricated\"",
        ))
        .unwrap();
        assert!(injected.identity_refusal.is_none());
    }

    // ── Source-pin the two production call sites (the files are esp-idf-only
    // and cannot host-compile, so pin their source text — same pattern as the
    // PROVISIONING_RS / nvs_config pins elsewhere in this test suite). ──
    #[test]
    fn nvs_migration_reads_minermodel_and_stores_it() {
        let src = include_str!("nvs_config.rs");
        assert!(
            src.contains("read_str(\"minermodel\")"),
            "migrate_axeos_config must read the vendor `minermodel` NVS key (SPEC §3 step 1)"
        );
        assert!(
            src.contains("miner_model:"),
            "migrate_axeos_config must persist miner_model into DcentAxeConfig"
        );
        assert!(
            src.contains("resolve_identity("),
            "migrate_axeos_config must route identity through board::resolve_identity, \
             never BoardVersionProfile::find(board_version) alone"
        );
    }

    #[test]
    fn main_boot_path_runs_the_identity_gate_before_energizing() {
        let src = include_str!("main.rs");
        let gate_idx = src
            .find(".run_identity_gate(")
            .expect("main.rs must invoke config.run_identity_gate on the boot path");
        let strap_idx = src
            .find(".run_identity_strap_gate(")
            .expect("main.rs must invoke the post-resolution Hammer strap gate");
        assert!(
            src.contains("probe_lucky_lv08_secondary_regulators"),
            "the gate's AMBIGUOUS branch must wire the real read-only LV08 probe"
        );
        assert!(
            src.contains(".apply_identity_profile("),
            "AdoptProfile must re-anchor the config via apply_identity_profile"
        );
        assert!(
            src.contains("probe_hammer_identity_strap"),
            "the Hammer gate must wire the real read-only address-only probe"
        );
        assert!(
            src.contains("identity_refusal = Some("),
            "RefuseToEnergize must set config.identity_refusal for validate_safety"
        );
        // Ordering: the gate must run BEFORE the master safety gate is
        // evaluated and long before any rail bring-up.
        let validate_idx = src
            .find("config.validate_safety(")
            .expect("main.rs evaluates validate_safety");
        assert!(
            gate_idx < strap_idx && strap_idx < validate_idx,
            "gate order must be identity ({gate_idx}) < strap ({strap_idx}) < \
             validate_safety ({validate_idx})"
        );
        let power_idx = src
            .find("PowerManager::new(")
            .expect("main.rs constructs PowerManager");
        assert!(
            strap_idx < power_idx,
            "strap gate (byte {strap_idx}) must run before PowerManager::new (byte {power_idx})"
        );
        // Match the real call STATEMENT, not prose — several comments (and the
        // gate's own placement rationale) quote `enable_buck(true)`.
        let buck_idx = src
            .find("if let Err(e) = gpio_ctrl.enable_buck(true)")
            .expect("main.rs enables the buck");
        assert!(
            strap_idx < buck_idx,
            "strap gate (byte {strap_idx}) must run before the buck is enabled (byte {buck_idx})"
        );
    }
}
