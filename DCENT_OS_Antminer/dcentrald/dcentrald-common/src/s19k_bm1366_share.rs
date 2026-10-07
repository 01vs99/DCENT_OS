//! BM1366 UART nonce → share reconstruction (ESP-Miner `BM1366_process_work`).
//!
//! Pure. Does **not** submit, open UART, or claim accepted shares.
//! Runtime frames require ESP/BM1366 full-frame remainder-zero CRC5. The
//! payload-only `0x1B` hypothesis remains diagnostic evidence, not admission.
//!
//! S19k address interval is AML **2**, but attribution dialects differ:
//! ESP/AMTC uses nonce bits 17..24, while Braiins fill uses the recovered
//! partition callback in `s19k_bm1366_braiins_nonce`.

use crate::s19k_bm1366_uart_rx::{
    admit_fill_work_id_tx_rx_correlate, asic_index_from_nonce_be, chip_addr_from_nonce_be,
    classify_bm1366_uart_rx_checked, core_id_from_nonce_be, S19kUartRxKind, S19kUartRxObservation,
    BM1366_JOB_ID_MASK, BM1366_SMALL_CORE_MASK, BM1366_UART_RESP_BODY_LEN, UART_RESP_LEN,
    UART_RESP_PREAMBLE,
};
use crate::s19k_uart_trans_job::BRAIINS_TTYS_THIRD;

/// BIP320 version-roll positions 13..28 (`VERSION_ROLLING_STRATUM_BIP320_MASK`).
/// Do not use the 12-bit mask that drops bits 13..16 (`version_be` low nibble);
/// that would corrupt `serial_rolled_version` after `version_bits >> 13`.
pub const BM1366_VERSION_ROLL_SHIFT: u32 = 13;
pub const BM1366_VERSION_ROLL_MASK: u32 = crate::VERSION_ROLLING_STRATUM_BIP320_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kBm1366AttributionProvenance {
    /// ESP/AMTC `(nonce>>17)&0xff`, interval-2 decoder.
    EspAmtcBits17Derived,
    /// Exact Bosminer callback arithmetic and S19k 77/2 configuration; the
    /// result also passed the independently evidenced physical ranges.
    BraiinsDerivedInPhysicalRange,
    /// Arithmetic output retained for observability only. Do not publish it
    /// as a physical ASIC/core identity or reject an otherwise valid share.
    BraiinsDerivedOutOfPhysicalRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBm1366Share {
    pub job_id: u8,
    /// ESP raw-UART dialect only. Braiins fill consumes the entire job byte
    /// as work-id and stores zero here because no small-core field is known.
    pub small_core: u8,
    pub midstate_num: u8,
    pub nonce_be: u32,
    /// Wire/submit nonce (LE interpret of the same 4 bytes).
    pub nonce_le: u32,
    pub version_bits: u32,
    pub rolled_version: u32,
    pub chip_addr: u8,
    pub asic_index: u8,
    pub core_id: u8,
    pub attribution_provenance: S19kBm1366AttributionProvenance,
}

impl S19kBm1366Share {
    /// Only exposes Braiins ASIC/core identity after the recovered arithmetic
    /// also passes S19k's independent 77-ASIC / 112-core physical ranges.
    pub fn braiins_physical_chip_core(&self) -> Option<(u8, u8, u8)> {
        matches!(
            self.attribution_provenance,
            S19kBm1366AttributionProvenance::BraiinsDerivedInPhysicalRange
        )
        .then_some((self.chip_addr, self.asic_index, self.core_id))
    }
}

pub fn s19k_braiins_attribution_provenance(
    attribution: &crate::s19k_bm1366_braiins_nonce::BraiinsBm1366Attribution,
) -> S19kBm1366AttributionProvenance {
    if crate::s19k_bm1366_braiins_nonce::s19k_braiins_bm1366_attribution_is_physical(attribution) {
        S19kBm1366AttributionProvenance::BraiinsDerivedInPhysicalRange
    } else {
        S19kBm1366AttributionProvenance::BraiinsDerivedOutOfPhysicalRange
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kShareError {
    NotJobNonce,
    JobIdMismatch { observed: u8, expected_mask: u8 },
}

/// Reconstruct rolled version: `base | (version_be << 13)`.
///
/// Braiins `FUN_0091c0a0` WorkResponse version is **not** this 16-bit BIP320
/// field: it AND-masks `version_be` to `((1<<midstate_log)-1)` via
/// `FUN_00bf2478`. Fill midstates=1 ⇒ that field is 0. : the five
/// UART callers plus `FUN_00bf6c2c` do **not** `LSL #13` / build `0x1FFFE000`.
/// Keep this ESP/BIP320 reconstruct for pool submit; see
/// `s19k_braiins_uart_version_bits`.
pub fn reconstruct_rolled_version(base_version: u32, version_be: u16) -> u32 {
    let bits = (u32::from(version_be) << BM1366_VERSION_ROLL_SHIFT) & BM1366_VERSION_ROLL_MASK;
    (base_version & !BM1366_VERSION_ROLL_MASK) | bits
}

/// Parse a job nonce without a job-id match (observe / first-look).
pub fn parse_bm1366_uart_share(
    frame: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let kind = classify_bm1366_uart_rx_checked(frame).map_err(|_| S19kShareError::NotJobNonce)?;
    let S19kUartRxKind::JobNonce { job_id, .. } = kind else {
        return Err(S19kShareError::NotJobNonce);
    };
    qualify_bm1366_job_nonce(kind, job_id, base_version)
}

/// HAL nonce path delivers the 9-byte body (preamble already stripped).
pub fn parse_bm1366_share_from_body(
    body: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    if body.len() < 9 {
        return Err(S19kShareError::NotJobNonce);
    }
    let mut frame = [0u8; 11];
    frame[0] = 0xAA;
    frame[1] = 0x55;
    frame[2..11].copy_from_slice(&body[..9]);
    parse_bm1366_uart_share(&frame, base_version)
}

/// A nonce job_id must hit an outstanding `WorkHistoryRing` slot.
/// `parse_bm1366_share_from_body` cannot do this — it only sees the frame.
pub fn admit_s19k_share_job_id_in_history(
    history_slot_occupied: bool,
    observed_job_id: u8,
) -> Result<u8, S19kShareError> {
    let id = observed_job_id & BM1366_JOB_ID_MASK;
    if !history_slot_occupied {
        return Err(S19kShareError::JobIdMismatch {
            observed: id,
            expected_mask: BM1366_JOB_ID_MASK,
        });
    }
    Ok(id)
}

/// Braiins fill RX: history key is `job_byte >> fill_log` (log 0 ⇒ raw byte).
/// ESP `id & 0xF8` is a different dialect — see [`refuse_esp_step8_as_braiins_fill_registry`].
pub fn admit_s19k_braiins_fill_share_job_id_in_history(
    history_slot_occupied: bool,
    observed_work_id: u8,
) -> Result<u8, S19kShareError> {
    if !history_slot_occupied {
        return Err(S19kShareError::JobIdMismatch {
            observed: observed_work_id,
            expected_mask: 0xFF,
        });
    }
    Ok(observed_work_id)
}

/// ESP `+8`/`%128` is 16 in-flight IDs. Braiins fill registry is `0x100>>0=256`.
pub fn refuse_esp_step8_as_braiins_fill_registry(step: u8, mask: u8) -> Result<(), &'static str> {
    if step == crate::s19k_bm1366_wire_b::S19K_WIRE_JOB_ID_STEP && mask == 0x7F {
        return Err(
            "ESP/wire step-8 mask 0x7F is 16 slots; Braiins fill UART registry is 256 (log 0)",
        );
    }
    Ok(())
}

/// ESP `id & 0xF8` drops the low 3 bits Braiins fill log=0 uses as work_id.
pub fn refuse_esp_f8_mask_as_braiins_fill_job_id(raw_job_byte: u8) -> Result<(), &'static str> {
    let masked = raw_job_byte & BM1366_JOB_ID_MASK;
    if masked != raw_job_byte {
        return Err(
            "ESP id&0xF8 drops low 3 bits; Braiins fill log=0 uses the raw job byte as work_id",
        );
    }
    Ok(())
}

/// Same 9-byte HAL body as [`parse_bm1366_share_from_body`], but job_id is
/// the Braiins fill work_id (`raw_byte >> log0`), not `id & 0xF8`.
pub fn parse_bm1366_braiins_fill_share_from_body(
    body: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let mut share = parse_bm1366_share_from_body(body, base_version)?;
    if body.len() < 6 {
        return Err(S19kShareError::NotJobNonce);
    }
    let raw = body[crate::s19k_bm1366_uart_rx::ESP_RX_REG_OR_JOB_ID_OFF - 2];
    let work_id = crate::s19k_braiins_job::s19k_braiins_uart_work_id_from_rx_job_byte(
        raw,
        crate::s19k_braiins_job::s19k_braiins_fill_midstate_log(),
    )
    .map_err(|_| S19kShareError::NotJobNonce)?;
    share.job_id = work_id as u8;
    let words = crate::s19k_bm1366_braiins_nonce::bosminer_bm1366_nonce_words(body)
        .ok_or(S19kShareError::NotJobNonce)?;
    share.nonce_be = words.callback_nonce_be;
    share.nonce_le = words.payload_low32_le;
    let attribution = crate::s19k_bm1366_braiins_nonce::decode_s19k_braiins_bm1366_attribution(
        words.callback_nonce_be,
    )
    .map_err(|_| S19kShareError::NotJobNonce)?;
    share.chip_addr = attribution.chip_address_low8;
    share.asic_index = attribution.asic_index as u8;
    share.core_id = attribution.core_id;
    share.attribution_provenance = s19k_braiins_attribution_provenance(&attribution);
    // `payload[5] >> log0` is the complete fill work-id. Its low three bits
    // are not the ESP small-core field.
    share.small_core = 0;
    // Fill midstates=1 ⇒ log 0 ⇒ FUN_0091c0a0 version mask is 0.
    // Do not keep ESP `version_be << 13` BIP320 bits from parse_bm1366_share_from_body.
    let version_be = u16::from_be_bytes([
        body.get(6).copied().unwrap_or(0),
        body.get(7).copied().unwrap_or(0),
    ]);
    // live407: fill log-0 UART *width* is 0 in bosminer, but the chip still
    // rolls body[6:7]<<13. Masking to 0 hashes 434faee1; keeping version_be
    // hashes 00000000009b6f81 (ticket-valid). Do not use the log-0 mask here.
    let _ = crate::s19k_braiins_job::s19k_braiins_uart_version_bits(
        version_be,
        crate::s19k_braiins_job::s19k_braiins_fill_midstate_log(),
    );
    share.version_bits = u32::from(version_be);
    share.rolled_version =
        crate::s19k_braiins_job::s19k_braiins_midstate0_version(base_version, version_be);
    // Fill midstates=1 ⇒ only index 0. Do not keep ESP body[4] midstate_num.
    share.midstate_num = 0;
    Ok(share)
}

/// Braiins fill UART version is mask 0. ESP BIP320 `version_be << 13` is a
/// different dialect and will fail `validate_full_header` against packed ver0.
pub fn refuse_esp_bip320_as_braiins_fill_version(src: &str) -> Result<(), &'static str> {
    if src.contains("(share.version_bits >> 13) as u16") {
        return Err(
            "Braiins fill version is mask 0; refuse ESP share.version_bits >> 13 on the fill arm",
        );
    }
    Ok(())
}

/// After a successful fill hunt, do not re-drop on ESP `resp[8] & 0x80`.
/// Hunt already required [`crate::s19k_bm1366_uart_rx::JobNonce`] (trailer bit7).
pub fn refuse_esp_flags_redrop_after_fill_hunt(src: &str) -> Result<(), &'static str> {
    if src.contains("0u16, // fill log 0") && src.contains("resp[8]") {
        // Fill Ok tuple must not pass HAL body[8] as flags after hunt.
        if !src.contains("0x80, // fill hunt") {
            return Err("fill hunt already required JobNonce; refuse ESP resp[8] flags redrop");
        }
    }
    Ok(())
}

/// Fill midstates=1 ⇒ midstate index is 0. ESP `body[4]` is a different dialect.
pub fn refuse_esp_midstate_as_braiins_fill_index(src: &str) -> Result<(), &'static str> {
    if src.contains("share.midstate_num") {
        return Err("Braiins fill midstates=1; refuse ESP share.midstate_num as midstate_idx");
    }
    Ok(())
}

/// Qualify a classified UART job nonce against an expected on-wire job_id.
pub fn qualify_bm1366_job_nonce(
    kind: S19kUartRxKind,
    expected_job_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let S19kUartRxKind::JobNonce {
        nonce_be,
        midstate_num,
        job_id,
        raw_job_byte: _,
        small_core,
        version_be,
    } = kind
    else {
        return Err(S19kShareError::NotJobNonce);
    };
    let expected = expected_job_id & BM1366_JOB_ID_MASK;
    if job_id != expected {
        return Err(S19kShareError::JobIdMismatch {
            observed: job_id,
            expected_mask: expected,
        });
    }
    Ok(S19kBm1366Share {
        job_id,
        small_core,
        midstate_num,
        nonce_be,
        nonce_le: nonce_be.swap_bytes(),
        version_bits: (u32::from(version_be) << BM1366_VERSION_ROLL_SHIFT)
            & BM1366_VERSION_ROLL_MASK,
        rolled_version: reconstruct_rolled_version(base_version, version_be),
        chip_addr: chip_addr_from_nonce_be(nonce_be),
        asic_index: asic_index_from_nonce_be(nonce_be),
        core_id: core_id_from_nonce_be(nonce_be),
        attribution_provenance: S19kBm1366AttributionProvenance::EspAmtcBits17Derived,
    })
}

/// Fill log=0: match the raw UART job byte. Do not AND-mask `0xF8` first.
pub fn qualify_bm1366_braiins_fill_from_body(
    body: &[u8],
    expected_work_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let share = parse_bm1366_braiins_fill_share_from_body(body, base_version)?;
    if share.job_id != expected_work_id {
        return Err(S19kShareError::JobIdMismatch {
            observed: share.job_id,
            expected_mask: expected_work_id,
        });
    }
    Ok(share)
}

/// ESP qualify AND-masks expected with 0xF8. Fill work_id 2 becomes 0.
pub fn refuse_esp_qualify_as_braiins_fill(expected_work_id: u8) -> Result<(), &'static str> {
    if expected_work_id & BM1366_JOB_ID_MASK != expected_work_id {
        return Err("qualify_bm1366_job_nonce masks expected with 0xF8; use fill qualify");
    }
    Ok(())
}

/// Synthetic AA55 job body (9 B) with fill work_id 2 in ESP byte 5. Not live BM1366.
pub const SYNTHETIC_BM1366_FILL_WORK2_BODY: [u8; 9] =
    [0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x00, 0x8F];
/// : constructed fill job_id. Not a live sniff.
pub const S19K_CONSTRUCTED_FILL_JOB_ID: u8 = 0x10;
/// Packed nVersion with bit 13 set so BIP320 strip is observable.
pub const S19K_CONSTRUCTED_FILL_BASE_VERSION: u32 = 0x2000_2000;
pub const S19K_CONSTRUCTED_FILL_PREV: [u8; 32] = [0x11; 32];
pub const S19K_CONSTRUCTED_FILL_MERKLE: [u8; 32] = [0x22; 32];
pub const S19K_CONSTRUCTED_FILL_NTIME: u32 = 0x5C00_0000;
pub const S19K_CONSTRUCTED_FILL_NBITS: u32 = 0x1D00_FFFF;
/// Wire nonce bytes in the constructed 9-byte body.
pub const S19K_CONSTRUCTED_FILL_BODY: [u8; 9] = [
    0x00,
    0x11,
    0x22,
    0x33,
    0x00,
    S19K_CONSTRUCTED_FILL_JOB_ID,
    0x00,
    0x00,
    0x82,
];
/// Constructed RX job byte with small_core ORed in. Not a live sniff.
pub const S19K_CONSTRUCTED_FILL_SMALL_CORE: u8 = 0x02;
pub const S19K_CONSTRUCTED_FILL_JOB_OR_CORE: u8 =
    S19K_CONSTRUCTED_FILL_JOB_ID | S19K_CONSTRUCTED_FILL_SMALL_CORE;
pub const S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY: [u8; 9] = [
    0x00,
    0x11,
    0x22,
    0x33,
    0x00,
    S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
    0x00,
    0x00,
    0x9B,
];

/// One UART nonce body plus the tty that produced it. Untagged hits
/// (AM2 / uart_trans) leave `path` None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kSerialRxHit {
    pub path: Option<&'static str>,
    pub body: Vec<u8>,
}

impl S19kSerialRxHit {
    pub fn untagged(body: Vec<u8>) -> Self {
        Self { path: None, body }
    }
}

/// Fill work_id is a `u8`. A 32-deep FIFO can drop a still-valid older slot.
pub const S19K_FILL_TX_SLOTS: usize = 256;
/// live408: UART TX hold (2–4), not the 256-slot outstanding table.
/// take_dispatch only when this queue has room so job_id matches the wire.
pub const S19K_BM1366_HOLD_QUEUE_DEPTH: usize = 4;
/// live428/430: MULTI died while TX continued. Actor `blocking_send` on a
/// 256-deep nonce channel stalls UART read (kernel FIFO overflow). Dual
/// 77-chip boards can emit more than 256 ticket hits between async
/// consumes. Deeper channel is backpressure, not wrap-7 soak proof.
pub const S19K_TRACK1_RX_CHANNEL: usize = 2048;

pub fn refuse_s19k_rx_channel_as_wrap7_survival() -> Result<(), &'static str> {
    Err("deeper RX channel is backpressure, not wrap-7 dual-port soak proof")
}

pub fn admit_s19k_production_rx_channel(src: &str) -> Result<(), &'static str> {
    if !src.contains("S19K_TRACK1_RX_CHANNEL") {
        return Err("serial_mining must size nonce channel with S19K_TRACK1_RX_CHANNEL");
    }
    if src.contains("mpsc::channel::<S19kSerialRxHit>(256)") {
        return Err("256-deep nonce channel can stall actor blocking_send");
    }
    Ok(())
}

/// Closed fill TX prefix: `55 AA 21 36` + fill job_id.
pub fn s19k_fill_tx_prefix(job_id: u8) -> [u8; 5] {
    let p = crate::s19k_braiins_job::CLOSED_11D_PREFIX;
    [
        p[0],
        p[1],
        p[2],
        p[3],
        crate::s19k_braiins_job::s19k_braiins_fill_job_id(job_id),
    ]
}

/// : tagged body + outstanding `21 36` TX. Not `qualify(parsed.job_id)`.
pub fn hunt_s19k_bm1366_fill_from_tagged_outstanding(
    path: &str,
    body: Option<&[u8]>,
    outstanding_txs: &[Vec<u8>],
) -> Result<S19kBm1366Share, &'static str> {
    let obs = crate::s19k_braiins_chain_discover::observe_s19k_tagged_rx_body(path, body, 10)?;
    match &obs {
        S19kUartRxObservation::Frames { frames, .. }
            if frames
                .iter()
                .any(|kind| matches!(kind, S19kUartRxKind::JobNonce { .. })) => {}
        S19kUartRxObservation::Silence { .. } => {
            return Err("tagged RX silence is not a BM1366 share");
        }
        _ => return Err("tagged RX is not JobNonce (framing/echo/short/chip)"),
    }
    let body = body
        .filter(|b| !b.is_empty())
        .ok_or("tagged RX body empty")?;
    if body.len() != BM1366_UART_RESP_BODY_LEN {
        return Err("BM1366 fill body must be 9");
    }
    if outstanding_txs.is_empty() {
        return Err("no outstanding 21 36 TX to correlate");
    }
    let mut rx = [0u8; UART_RESP_LEN];
    rx[0] = UART_RESP_PREAMBLE[0];
    rx[1] = UART_RESP_PREAMBLE[1];
    rx[2..].copy_from_slice(body);
    if !outstanding_txs
        .iter()
        .any(|tx| admit_fill_work_id_tx_rx_correlate(tx, &rx).is_ok())
    {
        return Err("RX job_id does not correlate with any outstanding 21 36 TX");
    }
    parse_bm1366_braiins_fill_share_from_body(body, 0)
        .map_err(|_| "fill parse failed after TX/RX correlate")
}

/// : outstanding `21 36` TX indexed by sent fill job_id.
/// Replacing a slot overwrites that job_id only. Wrap of a 32-deep FIFO
/// cannot drop a still-valid older slot.
///
/// Retired stores keep a short generation stack per job_id. live443
/// wrap-5 `clone()` replace and `insert_wire` overwrite dropped wrap-4
/// leftover 21 36 wires, so leftover_header remapped and leftover_hit
/// stayed 0 after leftover-admit. Merge + keep generations so wrap-4
/// leftover TXs still leftover_hit after leftover-admit wipe.
pub const S19K_RETIRED_TX_GENS: usize = 4;

#[derive(Clone, Debug)]
pub struct S19kOutstandingFillTx {
    slots: Vec<Vec<Vec<u8>>>,
}

impl Default for S19kOutstandingFillTx {
    fn default() -> Self {
        Self::new()
    }
}

impl S19kOutstandingFillTx {
    pub fn new() -> Self {
        Self {
            slots: vec![Vec::new(); S19K_FILL_TX_SLOTS],
        }
    }

    pub fn insert_wire(&mut self, wire: Vec<u8>) -> Result<u8, &'static str> {
        let job_id = s19k_fill_job_id_from_tx_wire(&wire)?;
        let slot = &mut self.slots[usize::from(job_id)];
        slot.clear();
        slot.push(wire);
        Ok(job_id)
    }

    /// Push a retired generation without dropping older leftover 21 36.
    pub fn push_retired_generation(&mut self, wire: Vec<u8>) -> Result<u8, &'static str> {
        let job_id = s19k_fill_job_id_from_tx_wire(&wire)?;
        let gens = &mut self.slots[usize::from(job_id)];
        if gens.last().is_some_and(|prev| prev == &wire) {
            return Ok(job_id);
        }
        gens.push(wire);
        while gens.len() > S19K_RETIRED_TX_GENS {
            gens.remove(0);
        }
        Ok(job_id)
    }

    /// Fail-closed wrap overwrite: the previous `21 36` at this job_id
    /// is occupied leftover, not a 32-FIFO drop. Retire it before the
    /// new merkle occupies the slot (wrap-7 same-id replace). Keep the
    /// prior retired generation (live443 wrap-retire overwrite wiped
    /// wrap-4 leftover TX so leftover_hit stayed 0).
    pub fn insert_wire_retiring(
        &mut self,
        wire: Vec<u8>,
        retired: &mut Self,
    ) -> Result<S19kFillInsert, &'static str> {
        let job_id = s19k_fill_job_id_from_tx_wire(&wire)?;
        let slot = &mut self.slots[usize::from(job_id)];
        let evicted = slot.pop();
        slot.clear();
        slot.push(wire);
        let retired_prev = if let Some(old) = evicted {
            retired.push_retired_generation(old)?;
            true
        } else {
            false
        };
        Ok(S19kFillInsert {
            job_id,
            retired_prev,
        })
    }

    /// live443 wrap-5 `retired = outstanding.clone()` wiped wrap-4 leftover
    /// 21 36. Merge POST-admit outstanding into retired generations.
    pub fn merge_from(&mut self, other: &Self) {
        for gens in &other.slots {
            for wire in gens {
                let _ = self.push_retired_generation(wire.clone());
            }
        }
    }

    pub fn get(&self, job_id: u8) -> Option<&[u8]> {
        self.slots[usize::from(job_id)]
            .last()
            .map(|wire| wire.as_slice())
    }

    pub fn wires_for(&self, job_id: u8) -> impl Iterator<Item = &[u8]> {
        self.slots[usize::from(job_id)]
            .iter()
            .map(|wire| wire.as_slice())
    }

    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
        }
    }

    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| !slot.is_empty()).count()
    }
}

/// Result of a fail-closed fill insert. `retired_prev` is occupied-slot
/// leftover of the previous wrap at the same job_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kFillInsert {
    pub job_id: u8,
    pub retired_prev: bool,
}

/// wrap-7 same job_id overwrite must retire the previous 21 36.
/// wrap_idx>=7 without retiring is an occupied-slot drop, not wrap-7 RX.
pub fn refuse_s19k_wrap7_same_id_drop_without_retire(
    wrap_idx: u64,
    retired_prev: bool,
) -> Result<(), &'static str> {
    if wrap_idx >= 7 && !retired_prev {
        return Err(
            "wrap-7 same job_id overwrite without retiring previous 21 36 drops occupied leftover",
        );
    }
    Ok(())
}

/// First wrap of a slot needs no retire. Later wraps must retire.
pub fn s19k_track1_wrap_overwrite_must_retire(wrap_idx: u64, slot_was_occupied: bool) -> bool {
    wrap_idx >= 1 && slot_was_occupied
}

/// Production TX path must retire wrap overwrite into retired_s19k_tx.
pub fn admit_s19k_production_retires_wrap_overwrite(src: &str) -> Result<(), &'static str> {
    if !src.contains("insert_wire_retiring") {
        return Err("BM1366 outstanding insert must retire previous 21 36 on same job_id");
    }
    if !src.contains("&mut retired_s19k_tx") && !src.contains("retired_s19k_tx") {
        return Err("wrap overwrite must retire into retired_s19k_tx");
    }
    Ok(())
}

/// Compact uppercase hex used on leftover dump `tx_wire` / `retired_tx_wire`.
pub fn s19k_compact_tx_hex(wire: &[u8]) -> String {
    wire.iter().map(|b| format!("{b:02X}")).collect()
}

/// First occupied slot among `slots` whose wire satisfies `pred`.
/// live425 leftover dumps used [`s19k_first_occupied_tx_hex`] (first
/// occupied, not the wire that actually hashed), so `LeftoverPreClean`
/// and `retired_tx_meets=false` could appear on the same line.
pub fn s19k_first_tx_hex_where(
    store: &S19kOutstandingFillTx,
    slots: &[u8],
    mut pred: impl FnMut(&[u8]) -> bool,
) -> Option<String> {
    slots.iter().find_map(|&jid| {
        store
            .wires_for(jid)
            .find_map(|wire| pred(wire).then(|| s19k_compact_tx_hex(wire)))
    })
}

/// First occupied slot among the live410 retry set. Occupancy-only —
/// not leftover proof. Leftover class/dump must use
/// [`s19k_first_tx_hex_where`] with a compact-TX meet predicate.
pub fn s19k_first_occupied_tx_hex(store: &S19kOutstandingFillTx, slots: &[u8]) -> String {
    s19k_first_tx_hex_where(store, slots, |_| true).unwrap_or_default()
}

/// leftover_hit and dump `retired_tx_meets` must describe the same wire.
pub fn s19k_leftover_class_matches_retired_tx(
    class: crate::S19kPostCleanNonceClass,
    retired_tx_meets: bool,
) -> bool {
    matches!(class, crate::S19kPostCleanNonceClass::LeftoverPreClean) == retired_tx_meets
}

/// leftover_hit is true only when a retired 21 36 wire in `store` satisfies
/// `pred` (the same compact-TX meet the dump uses).
pub fn s19k_leftover_hit_from_retired_store(
    store: &S19kOutstandingFillTx,
    slots: &[u8],
    pred: impl FnMut(&[u8]) -> bool,
) -> bool {
    s19k_first_tx_hex_where(store, slots, pred).is_some()
}

pub fn classify_s19k_post_clean_from_retired_tx_hit(
    new_meets: bool,
    retired_tx_hit: bool,
) -> crate::S19kPostCleanNonceClass {
    crate::classify_s19k_post_clean_nonce(new_meets, retired_tx_hit)
}

/// Constructed ESP-overlay hypothesis: `work_id | (small_core & 0x07)`.
/// This is not Braiins fill semantics and must not be used for production
/// encode/decode; fill log0 consumes the complete byte as work-id.
pub fn s19k_fill_job_byte_or_small_core(work_id: u8, small_core: u8) -> u8 {
    work_id | (small_core & BM1366_SMALL_CORE_MASK)
}

pub fn refuse_s19k_fill_job_byte_or_small_core_as_braiins() -> Result<(), &'static str> {
    Err("Braiins fill payload[5] is the complete work-id; ESP low3 small-core overlay is unproven")
}

/// live410: 932 ticket-256 nonces / 1 pool-8192 share. Raw fill job-id hunt
/// hits some outstanding slot (so the nonce is counted) but the chip often
/// hashed a different slot (core bits / <<3). Retry these after the raw miss.
pub fn s19k_track1_job_id_retry_slots(raw_job_byte: u8) -> [u8; 3] {
    [
        raw_job_byte,
        raw_job_byte & BM1366_JOB_ID_MASK,
        raw_job_byte >> 3,
    ]
}

pub fn admit_s19k_track1_job_id_retry_slots(raw: u8) -> Result<(), &'static str> {
    let slots = s19k_track1_job_id_retry_slots(raw);
    if slots[0] != raw {
        return Err("first retry slot must be the raw fill job byte");
    }
    if slots[1] != (raw & BM1366_JOB_ID_MASK) {
        return Err("second retry slot must be ESP id&0xF8");
    }
    if slots[2] != (raw >> 3) {
        return Err("third retry slot must be slot<<3 inverse");
    }
    Ok(())
}

/// Production submit must retry live410 wrong-slot job_ids.
pub fn admit_s19k_production_retries_track1_job_id_slots(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_job_id_retry_slots") {
        return Err("serial_mining must call s19k_track1_job_id_retry_slots");
    }
    if !src.contains("live410: also try ESP 0xF8 and >>3") {
        return Err("serial_mining must name the live410 job-id retry");
    }
    Ok(())
}

/// Braiins fill log 0: `FUN_0091c0a0` work_id is `payload[5] >> 0` = raw byte.
/// ESP `id & 0xF8` overlay is a different dialect.
pub fn s19k_fill_lookup_tx<'a>(
    raw_job_byte: u8,
    outstanding: &'a S19kOutstandingFillTx,
) -> Result<(&'a [u8], u8), &'static str> {
    if let Some(tx) = outstanding.get(raw_job_byte) {
        return Ok((tx, raw_job_byte));
    }
    Err("no outstanding 21 36 TX in that raw fill job-id slot")
}

/// ESP-Miner overlay. Not FUN_0091c0a0. Not production fill hunt.
pub fn s19k_fill_lookup_tx_esp_overlay_experimental<'a>(
    raw_job_byte: u8,
    outstanding: &'a S19kOutstandingFillTx,
) -> Result<(&'a [u8], u8), &'static str> {
    if let Some(tx) = outstanding.get(raw_job_byte) {
        return Ok((tx, raw_job_byte));
    }
    let overlay = raw_job_byte & BM1366_JOB_ID_MASK;
    if overlay != raw_job_byte {
        if let Some(tx) = outstanding.get(overlay) {
            return Ok((tx, overlay));
        }
    }
    Err("no outstanding 21 36 TX in that ESP overlay job-id slot")
}

pub fn refuse_s19k_fill_overlay_f8_as_fun_0091c0a0() -> Result<(), &'static str> {
    Err("FUN_0091c0a0 fill work_id is payload[5]>>log; log 0 is the raw byte, not id&0xF8 overlay")
}

pub fn admit_s19k_fill_lookup_uses_raw_job_byte(
    raw_job_byte: u8,
    resolved: u8,
) -> Result<(), &'static str> {
    if raw_job_byte == resolved {
        return Ok(());
    }
    Err("Braiins fill lookup must resolve the raw job byte, not an ESP 0xF8 overlay")
}

pub fn admit_s19k_production_fill_lookup_is_raw(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("pub fn s19k_fill_lookup_tx<")
        .ok_or("missing s19k_fill_lookup_tx")?;
    let win = src.get(start..start.saturating_add(450)).unwrap_or("");
    if win.contains("raw_job_byte & BM1366_JOB_ID_MASK") {
        return Err("production fill lookup must not overlay id&0xF8");
    }
    if !win.contains("outstanding.get(raw_job_byte)") {
        return Err("production fill lookup must index the raw job byte");
    }
    Ok(())
}

pub fn s19k_fill_job_id_from_tx_wire(wire: &[u8]) -> Result<u8, &'static str> {
    if wire.len() < 5 {
        return Err("TX shorter than prefix+job_id");
    }
    if wire[0..4] != crate::s19k_braiins_job::CLOSED_11D_PREFIX {
        return Err("outstanding TX must be 55 AA 21 36");
    }
    Ok(wire[4])
}

/// Hunt using the job-id slot, not a FIFO scan that can wrap away the TX.
pub fn hunt_s19k_bm1366_fill_from_tagged_slot(
    path: &str,
    body: Option<&[u8]>,
    outstanding: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    hunt_s19k_bm1366_fill_from_admitted_tx_path(
        path,
        body,
        outstanding,
        crate::s19k_uart_trans_job::BRAIINS_TTYS_CANDIDATES,
    )
}

/// Fill-hunt using the runtime's evidence-derived work-TX path set. The same
/// logical UART that received the work must own the response; ttyS3 is valid
/// only after complete CRC-valid enumeration promoted it into that set.
pub fn hunt_s19k_bm1366_fill_from_admitted_tx_path(
    path: &str,
    body: Option<&[u8]>,
    outstanding: &S19kOutstandingFillTx,
    work_tx_paths: &[&str],
) -> Result<S19kBm1366Share, &'static str> {
    crate::s19k_braiins_chain_discover::admit_s19k_fill_hunt_on_tx_path(path, work_tx_paths)?;
    let obs = crate::s19k_braiins_chain_discover::observe_s19k_tagged_rx_body(path, body, 10)?;
    match &obs {
        S19kUartRxObservation::Frames { frames, .. }
            if frames
                .iter()
                .any(|kind| matches!(kind, S19kUartRxKind::JobNonce { .. })) => {}
        S19kUartRxObservation::Silence { .. } => {
            return Err("tagged RX silence is not a BM1366 share");
        }
        _ => return Err("tagged RX is not JobNonce (framing/echo/short/chip)"),
    }
    let body = body
        .filter(|b| !b.is_empty())
        .ok_or("tagged RX body empty")?;
    if body.len() != BM1366_UART_RESP_BODY_LEN {
        return Err("BM1366 fill body must be 9");
    }
    let mut share = parse_bm1366_braiins_fill_share_from_body(body, 0)
        .map_err(|_| "fill parse failed before slot lookup")?;
    let raw = body[crate::s19k_bm1366_uart_rx::ESP_RX_REG_OR_JOB_ID_OFF - 2];
    let (tx, resolved) = s19k_fill_lookup_tx(raw, outstanding)?;
    share.job_id = resolved;
    let mut rx = [0u8; UART_RESP_LEN];
    rx[0] = UART_RESP_PREAMBLE[0];
    rx[1] = UART_RESP_PREAMBLE[1];
    rx[2..].copy_from_slice(body);
    admit_fill_work_id_tx_rx_correlate(tx, &rx)?;
    Ok(share)
}

/// live433: 199 correlate_fail never checked retired 21 36. After a
/// mid-run clean, an outstanding miss that correlates on the retired
/// store is leftover, not a framing miss.
pub fn s19k_hunt_retired_after_outstanding_miss(outstanding_miss: bool, retired_hit: bool) -> bool {
    outstanding_miss && retired_hit
}

/// Hunt retired 21 36 after an outstanding miss even when the
/// post-clean funnel is not armed. Wrap-retire leftover (same job_id
/// overwrite before the first pool clean) is occupied leftover.
pub fn s19k_track1_hunt_retired_without_funnel(funnel_armed: bool) -> bool {
    let _ = funnel_armed;
    true
}

/// leftover_hit increments on a retired 21 36 meet even when the
/// funnel is not yet armed. First-fill `meets` stay funnel-only so
/// leftover-admitted inactive is not blocked by session-start shares.
pub fn s19k_track1_count_wrap_retire_leftover(funnel_armed: bool) -> bool {
    let _ = funnel_armed;
    true
}

/// Submit of wrap-retired leftover is refused the same as post-clean
/// leftover. `true` means submit is allowed.
pub fn s19k_track1_refuse_wrap_retired_submit(retired_tx_meets: bool) -> bool {
    !retired_tx_meets
}

/// Production nonce path must hunt `retired_s19k_tx` after the
/// outstanding miss (live433 leftover_hit=0 with 199 correlate_fail)
/// and count wrap-retire leftover without waiting for a pool clean.
pub fn admit_s19k_production_hunts_retired_after_outstanding_miss(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("live433: outstanding miss hunts retired 21 36") {
        return Err("outstanding miss must hunt retired_s19k_tx (live433 leftover_hit=0 / correlate_fail=199)");
    }
    if !src.contains("S19k leftover 21 36 via retired store") {
        return Err("retired hunt must log leftover 21 36 via retired store");
    }
    if !src.contains("s19k_track1_hunt_retired_without_funnel") {
        return Err("retired hunt after outstanding miss must not wait for funnel arm");
    }
    if !src.contains("s19k_track1_count_wrap_retire_leftover") {
        return Err("wrap-retire leftover_hit must increment without funnel arm");
    }
    if !src.contains("s19k_track1_refuse_wrap_retired_submit") {
        return Err("wrap-retired leftover submit must be refused the same as post-clean leftover");
    }
    Ok(())
}

/// A 32-deep FIFO is not an S19k outstanding-TX table.
pub fn refuse_s19k_fifo32_wrap_as_outstanding_table() -> Result<(), &'static str> {
    Err(
        "32-deep FIFO wrap can drop an older still-valid fill job_id; index by sent job-id slot (256)",
    )
}

/// Outstanding TX table must stay 256. This is not the UART send-queue depth
/// (live408 256-deep drop-oldest burned job_ids at ~40 Hz).
pub fn admit_s19k_uart_queue_covers_fill_slots(depth: usize) -> Result<(), &'static str> {
    if depth < S19K_FILL_TX_SLOTS {
        return Err(
            "UART work queue shallower than 256 fill slots drops 21 36 still held in outstanding",
        );
    }
    Ok(())
}

/// UART TX hold must be 2–4 so take_dispatch is paced by the actor, not 40 Hz.
pub fn admit_s19k_bm1366_hold_queue_uart_paced(depth: usize) -> Result<(), &'static str> {
    if depth < 2 || depth > 4 {
        return Err("BM1366 UART hold queue must be 2-4 so take_dispatch is UART-paced (live408)");
    }
    Ok(())
}

pub fn refuse_s19k_live408_256_drop_oldest_as_hold() -> Result<(), &'static str> {
    Err("live408 256-deep drop-oldest UART queue is not a Track-1 hold")
}

pub fn refuse_s19k_uart_queue16_as_fill_depth(depth: usize) -> Result<(), &'static str> {
    if depth == 16 {
        return Err("16-deep UART queue is not the 256-slot fill outstanding table");
    }
    Ok(())
}

/// Production `run()` must select the 4-slot hold, not fill-256 drop-oldest.
pub fn admit_s19k_production_bm1366_queue_covers_fill_slots(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("let work_queue_depth = if is_bm1362") else {
        return Err("missing work_queue_depth selection");
    };
    let win = src.get(start..start.saturating_add(500)).unwrap_or("");
    if !win.contains("} else if is_bm1366 {") {
        return Err("BM1366 must select its own work_queue_depth");
    }
    if !win.contains("BM1366_SERIAL_WORK_QUEUE_DEPTH") {
        return Err("BM1366 work_queue_depth must be BM1366_SERIAL_WORK_QUEUE_DEPTH");
    }
    if win.contains("is_bm1366 {\n            DEFAULT_SERIAL_WORK_QUEUE_DEPTH") {
        return Err("BM1366 must not use DEFAULT_SERIAL_WORK_QUEUE_DEPTH 16");
    }
    if src.contains("s19k_bm1366_share::S19K_FILL_TX_SLOTS")
        && src.contains("const BM1366_SERIAL_WORK_QUEUE_DEPTH: usize =\n    dcentrald_common::s19k_bm1366_share::S19K_FILL_TX_SLOTS")
    {
        return Err("BM1366 UART queue must not be S19K_FILL_TX_SLOTS (live408 drop-oldest)");
    }
    if !src.contains("S19K_BM1366_HOLD_QUEUE_DEPTH") {
        return Err("BM1366 UART queue must be S19K_BM1366_HOLD_QUEUE_DEPTH");
    }
    Ok(())
}

/// live408: take_dispatch before UART send burned job_ids. Hold first.
pub fn admit_s19k_production_bm1366_holds_before_take_dispatch(
    src: &str,
) -> Result<(), &'static str> {
    let start = src
        .find("_ = dispatch_timer.tick()")
        .ok_or("missing dispatch_timer tick")?;
    let win = src.get(start..start.saturating_add(3200)).unwrap_or("");
    let hold = win
        .find("S19k Track-1 hold")
        .ok_or("dispatch_timer must hold BM1366 when UART queue is full")?;
    let take = win
        .find("take_dispatch()")
        .ok_or("dispatch_timer must take_dispatch after hold")?;
    if hold > take {
        return Err("BM1366 must hold before take_dispatch (live408 job_id burn)");
    }
    if !src.contains("refuse live408 drop-oldest") {
        return Err("BM1366 push must refuse live408 drop-oldest");
    }
    Ok(())
}

/// Leftover rails-up on `.88` must hold PWM 100 (home PWM 30 cooks boards).
pub const S19K_TRACK1_LEFTOVER_FAN_PWM: u8 = 100;
/// `.88` seated BHB56903 slots 2+3 (physical 2+3; slot 1 empty).
pub const S19K_LIVE88_SEATED_TMP75_SLOTS: [bool; 3] = [false, true, true];

/// Thermal coverage starts from the freshly bound live-hardware profile, not
/// from logical UART count. This matters for the held `a lab unit` profile: all three
/// boards remain physically populated even when only ttyS1+ttyS2 are admitted
/// for work TX, and inherited rails can leave the third board hot.
///
/// A dynamically promoted ttyS3 still escalates to all three TMP75 pairs. That
/// is a fail-closed response to serial evidence outside the `.88` two-board
/// profile, not a tty-to-physical-slot mapping claim.
pub fn s19k_track1_required_tmp75_slots(
    profile_seated_slots: [bool; 3],
    active_tx_paths: &[&str],
) -> [bool; 3] {
    if active_tx_paths.contains(&BRAIINS_TTYS_THIRD) {
        [true, true, true]
    } else {
        profile_seated_slots
    }
}

/// Track-1 must not OR the Braiins handoff into thermal_proof_present.
/// Ready requires the Track-1 TMP75+fan owner, not the leftover flag.
pub fn admit_s19k_track1_thermal_handoff_unowned(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("let thermal_proof_present =") else {
        return Err("missing thermal_proof_present");
    };
    let after = src.get(start..).unwrap_or("");
    let end = after.find(';').unwrap_or(400);
    let win = after.get(..end).unwrap_or("");
    if win.contains("braiins_bm1366_passthrough_handoff") {
        return Err("thermal_proof_present must not include Braiins handoff as Ready");
    }
    if !src.contains("s19k_track1_thermal") {
        return Err("Track-1 must own TMP75+fans (s19k_track1_thermal) for Ready");
    }
    if !src.contains("GPIO437 not written") {
        return Err("Track-1 thermal Ready must keep GPIO437 unread-for-write");
    }
    if !src.contains("ThermalSafetyState::HandoffUnowned") {
        return Err("Track-1 must keep HandoffUnowned as the no-owner fallback");
    }
    if !src.contains("thermal HandoffUnowned (not Ready)") {
        return Err("Track-1 must log HandoffUnowned is not Ready");
    }
    Ok(())
}

pub fn refuse_s19k_track1_handoff_as_thermal_ready() -> Result<(), &'static str> {
    Err("Braiins handoff flag alone is not thermal Ready")
}

pub fn refuse_s19k_track1_pwm30_as_leftover_ready() -> Result<(), &'static str> {
    Err("PWM 30 home cap is not leftover-rails-up Ready")
}

/// Classify Track-1 leftover thermal from measured seated TMP75 + commanded PWM.
/// Does not invent Ready from constants or the Braiins handoff flag.
pub fn classify_s19k_track1_thermal(
    seated_inlet_outlet_c: &[(f32, f32)],
    fan_pwm: u8,
    gpio437_written: bool,
    dangerous_temp_c: u8,
    hysteresis_c: u8,
) -> crate::work_dispatch_safety::ThermalSafetyState {
    use crate::work_dispatch_safety::{measured_startup_thermal_state, ThermalSafetyState};
    if gpio437_written {
        return ThermalSafetyState::Emergency;
    }
    if fan_pwm != S19K_TRACK1_LEFTOVER_FAN_PWM {
        return ThermalSafetyState::NotReady;
    }
    if seated_inlet_outlet_c.len() < 2 {
        return ThermalSafetyState::NotReady;
    }
    let mut hottest = f32::NEG_INFINITY;
    for (inlet, outlet) in seated_inlet_outlet_c {
        if !inlet.is_finite() || !outlet.is_finite() {
            return ThermalSafetyState::NotReady;
        }
        hottest = hottest.max(*inlet).max(*outlet);
    }
    measured_startup_thermal_state(Some(hottest), dangerous_temp_c, hysteresis_c)
}

pub fn admit_s19k_track1_thermal_ready(
    seated_inlet_outlet_c: &[(f32, f32)],
    fan_pwm: u8,
    gpio437_written: bool,
    dangerous_temp_c: u8,
    hysteresis_c: u8,
) -> Result<crate::work_dispatch_safety::ThermalSafetyState, &'static str> {
    use crate::work_dispatch_safety::ThermalSafetyState;
    if gpio437_written {
        return Err("Track-1 thermal must not write GPIO437");
    }
    if fan_pwm != S19K_TRACK1_LEFTOVER_FAN_PWM {
        return Err("Track-1 leftover rails-up must hold fan PWM 100");
    }
    if seated_inlet_outlet_c.len() < 2 {
        return Err("Track-1 .88 seated slots 2+3 need inlet/outlet pairs");
    }
    let state = classify_s19k_track1_thermal(
        seated_inlet_outlet_c,
        fan_pwm,
        gpio437_written,
        dangerous_temp_c,
        hysteresis_c,
    );
    if state != ThermalSafetyState::Ready {
        return Err("Track-1 thermal is not Ready");
    }
    Ok(state)
}

pub fn admit_s19k_production_construction_serial_work(
    desc: &crate::BoardDesc,
) -> Result<(), &'static str> {
    if desc.board_target != "am3-s19k" {
        return Err("production construction pin is am3-s19k");
    }
    if desc.work_engine != crate::WorkEngineKind::SerialWork {
        return Err("am3-s19k production construction must be SerialWork");
    }
    if !desc.runtime_status.permits_mining_lane() {
        return Err("am3-s19k production construction must permit a mining lane");
    }
    if desc.asic_protocol != crate::AsicProtocolIdentity::Bm1366 {
        return Err("am3-s19k production construction must stay BM1366");
    }
    Ok(())
}

/// BM1366 must TX-before-RX so the 256-deep queue drains before VTIME read.
pub fn admit_s19k_production_bm1366_tx_before_rx(src: &str) -> Result<(), &'static str> {
    if !src.contains("let tx_before_rx = is_bm1362 || is_bm1366") {
        return Err("BM1366 must TX-before-RX with BM1362");
    }
    Ok(())
}

/// The per-UART BM1366 initializer must accept only already-promoted custody.
pub fn admit_s19k_init_bm1366_requires_private_owner(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    for required in [
        "serial: &ValidatedSerialBackend",
        "native_program: &S19kBm1366NativeExecutionProgram",
    ] {
        if !win.contains(required) {
            return Err("BM1366 initializer must accept only typed promoted custody");
        }
    }
    for forbidden in ["ExperimentalConfig::load()", "SerialChainBackend::open("] {
        if win.contains(forbidden) {
            return Err("BM1366 initializer must not mint or bypass native custody");
        }
    }
    Ok(())
}

/// HAL body-7 *wire* cut of a constructed fill nonce (AA 55 + 7) is framing, not a share.
pub fn refuse_constructed_fill_hal_body7_wire_as_share(
    path: &str,
    raw_job: u8,
    outstanding: &[Vec<u8>],
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{bm1366_fill_job_nonce_uart, s19k_hal_body7_wire_cut};
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let cut =
        s19k_hal_body7_wire_cut(&rx).ok_or("constructed fill nonce shorter than body-7 cut")?;
    match hunt_s19k_bm1366_fill_from_tagged_outstanding(path, Some(cut), outstanding) {
        Ok(_) => Ok(()),
        Err(e)
            if e.contains("framing") || e.contains("not JobNonce") || e.contains("must be 9") =>
        {
            Err("constructed fill HAL body-7 wire cut is framing, not a share or Silence")
        }
        Err(_) => Ok(()),
    }
}

/// HAL `try_extract_frame(7)` **body** of a constructed fill nonce.
/// Distinct from W330's 9-byte *wire* cut (`AA 55`+7).
pub fn refuse_constructed_fill_hal_body7_extract_as_share(
    path: &str,
    raw_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{bm1366_fill_job_nonce_uart, extract_s19k_aa55_bodies};
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let bodies = extract_s19k_aa55_bodies(&rx, 7);
    if bodies.len() != 1 || bodies[0].len() != 7 {
        return Ok(());
    }
    match hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(bodies[0].as_slice()), slots) {
        Ok(_) => Ok(()),
        Err(e)
            if e.contains("must be 9") || e.contains("framing") || e.contains("not JobNonce") =>
        {
            Err("constructed fill HAL body-7 extract is not a share")
        }
        Err(_) => Ok(()),
    }
}

/// Same constructed nonce, HAL body-9 extract, must hunt against the job-id slot.
pub fn admit_constructed_fill_hal_body9_extract_hunts(
    path: &str,
    raw_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    use crate::s19k_bm1366_uart_rx::{bm1366_fill_job_nonce_uart, extract_s19k_hal_bm1366_bodies};
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let bodies = extract_s19k_hal_bm1366_bodies(&rx);
    if bodies.len() != 1 || bodies[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Err("HAL body-9 extract of constructed fill nonce must be one 9-byte body");
    }
    hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(bodies[0].as_slice()), slots)
}

/// Two-frame body-7 extract: neither 7-byte body is a share. Residue is not a frame.
pub fn refuse_s19k_body7_two_frame_extract_as_shares(
    path: &str,
    slots: &S19kOutstandingFillTx,
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{
        admit_s19k_body7_two_frame_leaves_residue, admit_s19k_body9_two_frame_no_residue,
        bm1366_chip_address_uart, bm1366_fill_job_nonce_uart, refuse_s19k_body7_residue_as_frame,
    };
    let mut stream = Vec::with_capacity(22);
    stream.extend_from_slice(&bm1366_fill_job_nonce_uart(2));
    stream.extend_from_slice(&bm1366_chip_address_uart(0));
    let (bodies, residue) = admit_s19k_body7_two_frame_leaves_residue(&stream)?;
    if refuse_s19k_body7_residue_as_frame(&residue).is_ok() {
        return Ok(());
    }
    for body in &bodies {
        match hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(body.as_slice()), slots) {
            Ok(_) => return Ok(()),
            Err(e)
                if e.contains("must be 9")
                    || e.contains("framing")
                    || e.contains("not JobNonce") => {}
            Err(_) => return Ok(()),
        }
    }
    let nine = admit_s19k_body9_two_frame_no_residue(&stream)?;
    if nine[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Ok(());
    }
    Err("body-7 two-frame extract is not dual shares; body-9 leaves no residue")
}

/// Body-7 cut of `first_job`, then body-9 recovery of `next_job` hunts that slot.
pub fn admit_s19k_body7_then_body9_next_frame_hunts(
    path: &str,
    first_job: u8,
    next_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    use crate::s19k_bm1366_uart_rx::{
        admit_s19k_body7_residue_then_body9_recovers_next, bm1366_fill_job_nonce_uart,
    };
    let first = bm1366_fill_job_nonce_uart(first_job);
    let next = bm1366_fill_job_nonce_uart(next_job);
    let recovered = admit_s19k_body7_residue_then_body9_recovers_next(&first, &next)?;
    hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(recovered.as_slice()), slots)
}

pub fn refuse_tautological_fill_qualify_source(src: &str) -> Result<(), &'static str> {
    if src.contains("qualify_bm1366_braiins_fill_from_body(&resp[..9], share.job_id") {
        return Err("production must not qualify fill against the just-parsed job_id");
    }
    Ok(())
}

/// Bitcoin 80-byte header the fill hunt + midstate0 OR must produce.
pub fn s19k_bm1366_fill_header80(
    rolled_version: u32,
    prev: &[u8; 32],
    merkle: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&rolled_version.to_le_bytes());
    header[4..36].copy_from_slice(prev);
    header[36..68].copy_from_slice(merkle);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&nbits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    header
}

/// : pack `21 36` → slot hunt → midstate0 OR → 80-byte header.
/// Fill log 0 leaves packed bit 13 in the header. BIP320 strip must not.
pub fn admit_s19k_constructed_fill_hunts_and_headers() -> Result<[u8; 80], &'static str> {
    let wire = crate::s19k_braiins_job::build_s19k_braiins_mining_on_work_wire(
        S19K_CONSTRUCTED_FILL_JOB_ID,
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        S19K_CONSTRUCTED_FILL_PREV,
        S19K_CONSTRUCTED_FILL_MERKLE,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
    );
    if wire[0..4] != crate::s19k_braiins_job::CLOSED_11D_PREFIX {
        return Err("constructed TX must be 55 AA 21 36");
    }
    let mut slots = S19kOutstandingFillTx::new();
    slots
        .insert_wire(wire.to_vec())
        .map_err(|_| "constructed TX insert")?;
    let share = hunt_s19k_bm1366_fill_from_tagged_slot(
        "/dev/ttyS1",
        Some(&S19K_CONSTRUCTED_FILL_BODY),
        &slots,
    )?;
    if share.job_id != S19K_CONSTRUCTED_FILL_JOB_ID {
        return Err("constructed hunt job_id");
    }
    if share.version_bits != 0 {
        return Err("fill log 0 version mask must be 0");
    }
    if share.midstate_num != 0 {
        return Err("fill midstates=1 index must be 0");
    }
    let rolled = crate::s19k_braiins_job::s19k_braiins_midstate0_version(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        share.version_bits as u16,
    );
    if rolled != S19K_CONSTRUCTED_FILL_BASE_VERSION {
        return Err("fill vbits 0 must OR packed ver0 unchanged");
    }
    let stripped = crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        0,
    );
    if stripped == rolled {
        return Err("packed bit 13 must distinguish midstate0 OR from BIP320 strip");
    }
    let header = s19k_bm1366_fill_header80(
        rolled,
        &S19K_CONSTRUCTED_FILL_PREV,
        &S19K_CONSTRUCTED_FILL_MERKLE,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
        share.nonce_le,
    );
    if header[0..4] != S19K_CONSTRUCTED_FILL_BASE_VERSION.to_le_bytes() {
        return Err("header version must be packed ver0, not BIP320-stripped");
    }
    Ok(header)
}

/// Asymmetric stratum prev. `[0x11; 32]` is invariant under both reverses.
pub const S19K_STRATUM_PREV_ASYM: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

/// WorkBuilder / `serial_build_header` prev: per-word byte swap of stratum.
pub fn s19k_workentry_prev_from_stratum(stratum: &[u8; 32]) -> [u8; 32] {
    let mut out = *stratum;
    for chunk in out.chunks_exact_mut(4) {
        chunk.reverse();
    }
    out
}

/// Fill header prev is WorkEntry format, not stratum and not 21 36 wire order.
pub fn admit_s19k_fill_header_uses_workentry_prev_not_wire() -> Result<[u8; 80], &'static str> {
    let stratum = S19K_STRATUM_PREV_ASYM;
    let workentry = s19k_workentry_prev_from_stratum(&stratum);
    let wire = crate::s19k_braiins_job::reverse_32bit_words(&workentry);
    if workentry == stratum {
        return Err("asymmetric prev must change under per-word endian");
    }
    if wire == workentry || wire == stratum {
        return Err("21 36 word-order reverse must differ from WorkEntry and stratum prev");
    }
    let merkle = S19K_STRATUM_PREV_ASYM;
    let merkle_wire = crate::s19k_braiins_job::reverse_32bit_words(&merkle);
    let header = s19k_bm1366_fill_header80(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        &workentry,
        &merkle,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
        0,
    );
    if header[4..36] != workentry {
        return Err("fill header prev must be WorkEntry / serial_build_header prev");
    }
    if header[4..36] == stratum {
        return Err("fill header must not use raw stratum prev");
    }
    if header[4..36] == wire {
        return Err("fill header must not use 21 36 wire word-order prev");
    }
    if header[36..68] != merkle {
        return Err("fill header merkle must be WorkEntry raw merkle");
    }
    if merkle == merkle_wire {
        return Err("need merkle that changes under word-order reverse");
    }
    Ok(header)
}

pub fn refuse_s19k_stratum_prev_as_fill_header() -> Result<(), &'static str> {
    Err("stratum prev is not WorkEntry header prev (reverse_endianness_per_word)")
}

pub fn refuse_s19k_wire_word_reverse_as_fill_header() -> Result<(), &'static str> {
    Err("21 36 reverse_32bit_words prev is the pack wire field, not serial_build_header")
}

/// Production `serial_build_header` copies WorkEntry prev/merkle, not wire reverse.
pub fn admit_s19k_production_header_uses_workentry_prev(src: &str) -> Result<(), &'static str> {
    let Some(fn_start) = src.find("fn serial_build_header(") else {
        return Err("serial_build_header missing");
    };
    let window = src[fn_start..]
        .split("fn serial_full_header_hash_be(")
        .next()
        .ok_or("serial_build_header window missing")?;
    if !window.contains("&entry.prev_block_hash") {
        return Err("serial_build_header must use WorkEntry prev");
    }
    if !window.contains("&entry.merkle_root") {
        return Err("serial_build_header must use WorkEntry merkle");
    }
    if window.contains("reverse_32bit_words(&entry.prev_block_hash)") {
        return Err("serial_build_header must not word-order-reverse WorkEntry prev");
    }
    Ok(())
}

pub fn refuse_constructed_fill_header_as_bip320_strip(
    header: &[u8; 80],
) -> Result<(), &'static str> {
    let stripped = crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        0,
    );
    if header[0..4] == stripped.to_le_bytes() {
        return Err("constructed header used BIP320 strip; fill packed ver0 required");
    }
    Ok(())
}

/// Production BM1366 hunt must pass the 9-byte UART body, not HAL default 7.
pub fn admit_s19k_production_hunt_uses_body9(src: &str) -> Result<(), &'static str> {
    if !src.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path") {
        return Err("production hunter must call the admitted-TX-path fill parser");
    }
    if !src.contains("Some(&resp[..9])") {
        return Err("production BM1366 hunt must pass Some(&resp[..9])");
    }
    if src.contains("Some(&resp[..7])") {
        return Err("production must not hunt HAL body-7 Some(&resp[..7])");
    }
    if !src.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("production must name BM1366_UART_RESP_BODY_LEN");
    }
    Ok(())
}

pub fn refuse_s19k_production_bm1366_hunt_as_hal_body7() -> Result<(), &'static str> {
    Err("production BM1366 must hunt resp[..9] / BM1366_UART_RESP_BODY_LEN, not HAL DEFAULT 7")
}

/// Track-1 must `set_response_len(resp_body_len)` before the first GetAddress read.
pub fn admit_s19k_production_sets_body_before_first_read(src: &str) -> Result<(), &'static str> {
    let Some(open) = src
        .find("SerialChainBackend::open_passthrough_bm1366(i as u8, path)")
        .or_else(|| src.find("SerialChainBackend::open_passthrough(i as u8, path)"))
    else {
        return Err("missing Track-1 open_passthrough");
    };
    let win = src.get(open..open.saturating_add(1800)).unwrap_or("");
    let Some(set_at) = win.find("s.set_response_len(resp_body_len)") else {
        return Err("Track-1 must set_response_len after open_passthrough");
    };
    if let Some(get_at) = win.find("send_get_address") {
        if get_at < set_at {
            return Err("Track-1 must set_response_len before send_get_address");
        }
    }
    Ok(())
}

/// HAL must expose a BM1366 passthrough open that sets body 9 before return.
pub fn admit_s19k_hal_open_passthrough_bm1366(src: &str) -> Result<(), &'static str> {
    if !src.contains("fn open_passthrough_bm1366") {
        return Err("HAL must expose open_passthrough_bm1366");
    }
    if !src.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)") {
        return Err("open_passthrough_bm1366 must set BM1366 body 9 before return");
    }
    Ok(())
}

/// Generic `else if passthrough` must refuse BM1366 before `open_passthrough(0)`.
pub fn admit_s19k_production_refuses_generic_passthrough_for_bm1366(
    src: &str,
) -> Result<(), &'static str> {
    let Some(arm) = src.find("} else if passthrough {") else {
        return Err("missing generic passthrough arm");
    };
    let win = src.get(arm..arm.saturating_add(700)).unwrap_or("");
    if !win.contains("if is_bm1366") {
        return Err("generic passthrough arm must refuse BM1366");
    }
    if !win.contains("open_passthrough_bm1366") {
        return Err("generic passthrough BM1366 refuse must name open_passthrough_bm1366");
    }
    let bail_at = win.find("anyhow::bail!");
    let open0_at = win.find("open_passthrough(0, &serial_device)");
    match (bail_at, open0_at) {
        (Some(b), Some(o)) if b < o => Ok(()),
        _ => Err("generic passthrough must bail BM1366 before open_passthrough(0)"),
    }
}

/// Generic `open_passthrough(0)` is not S19k Track-1.
pub fn refuse_s19k_generic_passthrough0_as_track1() -> Result<(), &'static str> {
    Err("generic open_passthrough(0) is not S19k Track-1; BM1366 must bail before that open")
}

/// Track-1 must not construct generic open_passthrough (DEFAULT 7) for BM1366.
pub fn admit_s19k_production_uses_bm1366_passthrough_open(src: &str) -> Result<(), &'static str> {
    if !src.contains("open_passthrough_bm1366(i as u8, path)") {
        return Err("Track-1 must open via open_passthrough_bm1366");
    }
    if src.contains("SerialChainBackend::open_passthrough(i as u8, path)") {
        return Err("Track-1 must not use generic open_passthrough for BM1366");
    }
    Ok(())
}

/// HAL constructor default 7 is not a valid BM1366 first-read body.
pub fn refuse_hal_default_body7_as_bm1366_first_read(body_len: usize) -> Result<(), &'static str> {
    if body_len == crate::s19k_bm1366_uart_rx::BM139X_HAL_DEFAULT_RESP_BODY_LEN {
        return Err(
            "BM1366 first-read still at HAL DEFAULT_RESP_BODY_LEN 7; set_response_len(9) was skipped",
        );
    }
    Ok(())
}

/// Skipping `open_passthrough_bm1366` leaves first-read at HAL DEFAULT 7.
pub fn refuse_s19k_skip_bm1366_open_first_read_at_7(
    used_bm1366_open: bool,
    body_len: usize,
) -> Result<(), &'static str> {
    if !used_bm1366_open && body_len == crate::s19k_bm1366_uart_rx::BM139X_HAL_DEFAULT_RESP_BODY_LEN
    {
        return Err("skipping open_passthrough_bm1366 leaves first-read at HAL DEFAULT 7");
    }
    Ok(())
}

/// Track-1 must `require_bm1366_response_body` before GetAddress / drain.
pub fn admit_s19k_production_requires_body9_before_first_read(
    src: &str,
) -> Result<(), &'static str> {
    let Some(open) = src.find("SerialChainBackend::open_passthrough_bm1366(i as u8, path)") else {
        return Err("missing Track-1 open_passthrough_bm1366");
    };
    let win = src.get(open..open.saturating_add(1800)).unwrap_or("");
    let Some(req_at) = win.find("require_bm1366_response_body") else {
        return Err("Track-1 must require_bm1366_response_body after open");
    };
    if let Some(get_at) = win.find("send_get_address") {
        if get_at < req_at {
            return Err("Track-1 must require_bm1366_response_body before send_get_address");
        }
    }
    if let Some(drain_at) = win.find("drain_serial_passthrough_backlog") {
        if drain_at < req_at {
            return Err("Track-1 must require_bm1366_response_body before drain");
        }
    }
    Ok(())
}

/// Native BM1366 cold init must consume a validated backend and require body 9
/// before its first flush/read. Raw UART open belongs only to the exact
/// multi-UART route promotion fence.
pub fn admit_s19k_init_bm1366_requires_body9_before_flush(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let after_start = src.get(start..).unwrap_or("");
    let end = after_start
        .get(1..)
        .and_then(|tail| tail.find("fn init_bm1370_chain(").map(|offset| offset + 1))
        .unwrap_or(after_start.len());
    let rest = after_start.get(..end).unwrap_or(after_start);
    if !rest.contains("serial: &ValidatedSerialBackend") {
        return Err("init_bm1366_chain must consume a validated serial backend");
    }
    if rest.contains("SerialChainBackend::open(") || rest.contains("reset_asic_baud(") {
        return Err("init_bm1366_chain must not reopen or hot-reset a raw UART");
    }
    let Some(req_at) = rest.find("require_bm1366_response_body") else {
        return Err("init_bm1366_chain must require_bm1366_response_body");
    };
    let Some(flush_at) = rest.find("flush_io") else {
        return Err("init_bm1366_chain must still flush_io");
    };
    if flush_at < req_at {
        return Err("init_bm1366_chain must require body 9 before flush_io");
    }
    if !rest.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)") {
        return Err("init_bm1366_chain must set BM1366_UART_RESP_BODY_LEN, not a generic 9");
    }
    Ok(())
}

/// The experimental native executor must cross the exact held-stock BM1366
/// ASIC/host baud pair and obtain a fresh admitted response before any
/// per-chip tail. This remains an offline/runtime-shape gate, not production
/// authority; `run()` must continue to refuse the executor separately.
pub fn admit_s19k_init_bm1366_requires_fresh_switched_baud_response(
    src: &str,
) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let end = src[start + 1..]
        .find("fn init_bm1370_chain(")
        .map(|offset| start + 1 + offset)
        .unwrap_or(src.len());
    let init = &src[start..end];
    for required in [
        "s19k_bm1366_native_execution_program(",
        "fn init_bm1366_chains(",
        "ValidatedS19kBm1366NativeMultiBackend",
        "for (path, backend) in serial.iter()",
        "native_program.pre_baud_commands",
        "native_program.fast_uart_command",
        "set_baud(native_program.fast_host_baud)",
        "native BM1366 post-baud anti-staleness flush failed",
        "Bm1366NativePostBaudAdmission::from_response_window",
        "native_program.post_baud_commands",
        "native_program.final_commands",
        "terminal rollback required before per-chip mutation or work TX",
    ] {
        if !init.contains(required) {
            return Err("native BM1366 executor is missing an exact switched-baud response gate");
        }
    }
    if init.contains("PUBLIC_FASTUART_VALUE") {
        return Err("native BM1366 executor must not use the ESP 1M FastUART word");
    }
    let asic_switch = init
        .find("native_program.fast_uart_command")
        .ok_or("missing typed exact BM1366 ASIC FastUART command")?;
    let host_switch = init
        .find("set_baud(native_program.fast_host_baud)")
        .ok_or("missing exact S19k host baud switch")?;
    let fresh_gate = init
        .find("Bm1366NativePostBaudAdmission::from_response_window")
        .ok_or("missing fresh post-baud admission")?;
    let per_chip = init
        .find("native_program.post_baud_commands")
        .ok_or("missing typed BM1366 per-chip tail")?;
    if !(asic_switch < host_switch && host_switch < fresh_gate && fresh_gate < per_chip) {
        return Err(
            "native BM1366 per-chip tail is not gated after the exact switched-baud response",
        );
    }
    Ok(())
}

/// Leftover `init_bm1366_chain` must not broadcast ESP VersionMask 0xA4=0x9000FFFF.
pub fn admit_s19k_init_bm1366_omits_esp_a4(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let end = src[start + 1..]
        .find("fn init_bm1370_chain(")
        .map(|i| start + 1 + i)
        .unwrap_or(src.len());
    let win = &src[start..end];
    if win.contains("BM1366_VERSION_MASK_VALUE")
        || win.contains("send_write_reg_broadcast_bm1397plus(0xA4")
    {
        return Err("init_bm1366_chain must not write ESP 0xA4=0x9000FFFF VersionMask");
    }
    Ok(())
}

/// Production `run()` must use the population-scoped native initializer and
/// must not call the leftover single-backend initializer directly.
pub fn admit_s19k_production_run_skips_init_bm1366_chain(src: &str) -> Result<(), &'static str> {
    let Some(run_start) = src.find("pub async fn run(&mut self)") else {
        return Err("missing production run()");
    };
    let run_end = src.find("\n#[cfg(test)]\nmod tests {").unwrap_or(src.len());
    if run_end <= run_start {
        return Err("cannot isolate production run()");
    }
    let run = &src[run_start..run_end];
    if run.contains("Self::init_bm1366_chain(") {
        return Err("production run() must not call init_bm1366_chain");
    }
    if !run.contains("Self::init_bm1366_chains(native_backends, target_freq)") {
        return Err("production run() must call the typed population-scoped initializer");
    }
    Ok(())
}

/// The NoPic serial observation facade is no longer BM1368/BM1370-only: the
/// landed XP-pair (am3-s19xp/am3-s19jxp BM1366) and S19j Pro A/Plus (BM1362)
/// native serial routes join it through the typed
/// `modern_s21_profile(target, identity)` table. The fence that must survive
/// is target-exactness: the facade admits only exact native model x ASIC rows
/// from that table, and the S19k BM1366 production target never appears in it
/// (its lane stays ExactSerialRoute::S19kNative).
pub fn admit_s19k_nopic_observation_refuses_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn begin_nopic_observation(") else {
        return Err("missing begin_nopic_observation");
    };
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("modern_s21_profile(dispatch.board_target(), dispatch.identity()).is_some()")
    {
        return Err("NoPic observation must gate on the exact native model/ASIC profile table");
    }
    if !win.contains("NoPic observation requires an exact native model and ASIC identity") {
        return Err("NoPic observation must refuse an unmatched model/identity pair");
    }
    let Some(table_at) = src.find("fn modern_s21_profile(") else {
        return Err("missing modern_s21_profile gate table");
    };
    let table = src.get(table_at..table_at.saturating_add(1200)).unwrap_or("");
    if table.contains(r#"("am3-s19k""#) {
        return Err("S19k BM1366 production target must not join the NoPic profile table");
    }
    Ok(())
}

/// Native BM1366 custody must be an exact selected population, single-fence
/// route whose pre-serial token has no caller-selected constructor.
pub fn admit_s19k_native_multi_uart_route_is_fenced(src: &str) -> Result<(), &'static str> {
    let production = src
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .unwrap_or(src);
    for required in [
        "ExactSerialRoute::S19kNative",
        "struct S19kNativePreSerialAdmission {",
        "fn promote_s19k_native_multi_execution(",
        "admit_s19k_native_multi_uart_shape(",
        "S19k native exact multi-UART open",
        "ValidatedSerialBackend::new(backend, execution.clone())",
        "ValidatedS19kBm1366NativeMultiBackend",
        "fn issue_pre_serial(&mut self)",
    ] {
        if !production.contains(required) {
            return Err("native S19k multi-UART route is missing exact fenced custody");
        }
    }
    if production.contains("pub struct S19kNativePreSerialAdmission") {
        return Err("native S19k pre-serial authority must remain private");
    }
    Ok(())
}

/// Native S19k platform admission selects an ordered subset of the immutable
/// controller-facing route from the fresh plug bitmap. The read-only aggregate
/// must not expose APW/reset/PWM mutation; only the opaque population promotion
/// may own those operations.
pub fn admit_s19k_native_aggregate_platform_admission(
    hal: &str,
    serial: &str,
) -> Result<(), &'static str> {
    for required in [
        "pub const S19K_NATIVE_LOGICAL_CHAIN_ROUTES:",
        "pub struct S19kNativeLogicalChainRoute",
        "uart: \"/dev/ttyS3\"",
        "logical_chain: 0",
        "reset_gpio: 454",
        "pub struct S19kNativeFanObservation",
        "pub struct S19kNativeAggregateAdmission",
        "pub struct S19kNativePopulationAdmission",
        "validate_amlogic_boot_safe_handoff(AmlogicNoPicProfile::S19k)",
        "let populated_slots = read_plug_topology_checked()?",
        "populated_slots[*index] && !uart_available[*index]",
    ] {
        if !hal.contains(required) {
            return Err("native S19k aggregate platform admission is incomplete");
        }
    }
    let start = hal
        .find("impl S19kNativeAggregateAdmission")
        .ok_or("missing native S19k aggregate admission implementation")?;
    let end = hal[start..]
        .find("impl S19kNativePopulationAdmission")
        .map(|offset| start + offset)
        .ok_or("cannot bound native S19k aggregate admission implementation")?;
    let body = &hal[start..end];
    if !body.contains("service.psu_enable_operation_available = false")
        || body.contains("service.psu_enable_operation_available = true")
        || body.contains("take_psu_enable_operation")
        || body.contains("set_amlogic_board_reset_checked")
        || !body.contains("Result<Arc<S19kNativeFanObservation>>")
        || body.contains("Result<Arc<dyn FanAccess>>")
    {
        return Err(
            "native S19k aggregate admission gained unproven power/reset/PWM/slot authority",
        );
    }
    let observer_start = hal
        .find("impl S19kNativeFanObservation")
        .ok_or("missing native S19k fan observation implementation")?;
    let observer_end = hal[observer_start..]
        .find("pub struct S19kNativeAggregateAdmission")
        .map(|offset| observer_start + offset)
        .ok_or("cannot bound native S19k fan observation implementation")?;
    let observer = &hal[observer_start..observer_end];
    if !observer.contains("pub fn get_per_fan_rpm")
        || !observer.contains("pub fn get_speed_pwm")
        || observer.contains("pub fn set_speed")
        || observer.contains("impl FanAccess")
    {
        return Err("native S19k fan observation capability gained PWM command authority");
    }
    let shape_start = serial
        .find("fn admit_s19k_native_multi_uart_shape")
        .ok_or("missing native S19k multi-UART shape gate")?;
    let shape_end = serial[shape_start..]
        .find("mod serial_route_domains")
        .map(|offset| shape_start + offset)
        .ok_or("cannot bound native S19k multi-UART shape gate")?;
    if !serial[shape_start..shape_end].contains("S19K_NATIVE_LOGICAL_CHAIN_ROUTES.as_slice()") {
        return Err("native serial route must consume the HAL logical-chain contract");
    }
    Ok(())
}

pub fn refuse_s19k_nopic_probe_as_track1_first_read() -> Result<(), &'static str> {
    Err("NoPic observe_candidate is BM1368/BM1370 only; not S19k Track-1 first-read")
}

fn am2_hybrid_source_method<'a>(
    source: &'a str,
    signature: &str,
) -> Result<&'a str, &'static str> {
    let start = source.find(signature).ok_or("missing AM2 hybrid source method")?;
    // This is an impl method. Bound the complete method at its closing
    // indentation, independently of parameter additions and body length.
    let method = &source[start..];
    let Some(end) = method.find("\n    }") else {
        return Err("missing AM2 hybrid source method boundary");
    };
    Ok(&method[..end])
}

/// AM2 hybrid baud-wake is Zynq BM1362. Do not borrow require_bm1366.
pub fn admit_s19k_am2_hybrid_reset_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let win = am2_hybrid_source_method(hybrid_src, "fn reset_asic_baud(")?;
    if !win.contains("HotStartHostClass::Zynq") {
        return Err("AM2 hybrid reset_asic_baud must use Zynq hot-start class");
    }
    if !win.contains("plan_hot_start_hybrid_wake_ops") {
        return Err("AM2 hybrid reset_asic_baud must use hybrid wake ops");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 hybrid reset_asic_baud must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_hybrid_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 hybrid reset_asic_baud is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 reset-baseline first-read is BM1362 unassigned body, not BM1366 body 9.
pub fn admit_s19k_am2_reset_baseline_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn observe_reset_baseline(") else {
        return Err("missing observe_reset_baseline");
    };
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("BM1362_UNASSIGNED_RESP_BODY_LEN") {
        return Err("AM2 reset-baseline must set BM1362 unassigned body");
    }
    if !win.contains("AM2 BM1362 reset-baseline") {
        return Err("AM2 reset-baseline must name BM1362");
    }
    if win.contains("require_bm1366_response_body") || win.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("AM2 reset-baseline must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_reset_baseline_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 observe_reset_baseline is BM1362; not S19k Track-1 first-read")
}

/// am3-bb kernel UART open is BeagleBone, not S19k Track-1.
pub fn admit_s19k_am3_bb_open_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("impl Am3BbChainUart") else {
        return Err("missing Am3BbChainUart");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("am3-bb: SerialChainBackend::open") {
        return Err("am3-bb must name SerialChainBackend::open");
    }
    if win.contains("require_bm1366_response_body") || win.contains("open_passthrough_bm1366") {
        return Err("am3-bb open must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am3_bb_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("am3-bb SerialChainBackend::open is BeagleBone; not S19k Track-1 first-read")
}

/// Leftover BM1398 init is not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1398_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1398_chain(") else {
        return Err("missing init_bm1398_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("SerialBringUpPluginKind::SerialBm1398") {
        return Err("init_bm1398_chain must use SerialBm1398 bring-up");
    }
    if !win.contains("send_get_address_bm1397plus") {
        return Err("init_bm1398_chain must use BM1397+ GetAddress");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1398_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1398_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1398_chain is BM1398; not S19k Track-1 first-read")
}

/// Leftover BM1368 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1368_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1368_chain(") else {
        return Err("missing init_bm1368_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1368_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("SerialBringUpPluginKind::AmlogicBm1368") {
        return Err("init_bm1368_chain must use AmlogicBm1368 bring-up");
    }
    if !win.contains("=== BM1368 ASIC INIT") {
        return Err("init_bm1368_chain must name BM1368 ASIC INIT");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1368_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1368_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1368_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1368_chain is BM1368 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// Leftover BM1370 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1370_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1370_chain(") else {
        return Err("missing init_bm1370_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1370_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("SerialBringUpPluginKind::AmlogicBm1370") {
        return Err("init_bm1370_chain must use AmlogicBm1370 bring-up");
    }
    if !win.contains("=== BM1370 ASIC INIT") {
        return Err("init_bm1370_chain must name BM1370 ASIC INIT");
    }
    if !win.contains("send_get_address_bm1397plus") {
        return Err("init_bm1370_chain must use BM1397+ GetAddress");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1370_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1370_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1370_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1370_chain is BM1370 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// Leftover BM1362 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1362_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1362_chain(") else {
        return Err("missing init_bm1362_chain");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1362_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("=== BM1362 ASIC INIT") {
        return Err("init_bm1362_chain must name BM1362 ASIC INIT");
    }
    if !win.contains("BM1362 init requires the checked reset-baseline 115200") {
        return Err("init_bm1362_chain must require the 115200 reset-baseline route");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1362_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1362_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1362_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1362_chain is BM1362 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// AM2 RANK-5 companion PL-UART is Zynq BM1362 dual-UART, not S19k Track-1.
pub fn admit_s19k_am2_companion_open_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let win = am2_hybrid_source_method(hybrid_src, "fn init_asic_chain(")?;
    if !win.contains("let companion_dev = am2_dual_chain_second_uart()") {
        return Err("missing AM2 companion UART open");
    }
    if !win.contains("SerialChainBackend::open_with_preference(0, &companion_dev, 115_200, uart_preference)") {
        return Err("AM2 companion must open companion_dev at 115200");
    }
    if !win.contains("assert_mcr_out2") {
        return Err("AM2 companion must assert OUT2");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 companion must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_companion_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 companion UART open is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 Phase 3b1-relay is BM1362 UART relay lab stage, not S19k Track-1.
pub fn admit_s19k_am2_phase3b1_relay_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let method = am2_hybrid_source_method(hybrid_src, "pub async fn run(")?;
    let relay = method.find("// Phase 3b1-relay: send BM1362 UART relay enable")
        .ok_or("missing Phase 3b1-relay boundary")?;
    let win = &method[relay..];
    let end = win.find("// Phase 3b2b:").ok_or("missing Phase 3b1-relay end")?;
    let relay = &win[..end];
    let compact: String = relay.chars().filter(|ch| !ch.is_whitespace()).collect();
    if !compact.contains("SerialChainBackend::open_with_preference(fpga_chain_id,&chain_uart_device,115_200,uart_preference,)") {
        return Err("Phase 3b1-relay must use the typed 115200 UART open");
    }
    if !relay.contains("maybe_write_bm1362_uart_relay") {
        return Err("Phase 3b1-relay must write BM1362 UART relay");
    }
    if !relay.contains("bm1362_phase3b1_pre_gate") {
        return Err("Phase 3b1-relay must name bm1362_phase3b1_pre_gate");
    }
    if method.contains("require_bm1366_response_body")
        || method.contains("open_passthrough_bm1366")
        || method.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("Phase 3b1-relay must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_phase3b1_relay_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 Phase 3b1-relay is BM1362 UART relay; not S19k Track-1 first-read")
}

/// AM2 PL UART probe is BM1362 fallback sweep, not S19k Track-1 first-read.
pub fn admit_s19k_am2_probe_uart_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let win = am2_hybrid_source_method(hybrid_src, "fn probe_uart_for_chips(")?;
    if !win.contains("BM1362_RESP_BODY_LEN") {
        return Err("AM2 UART probe must set BM1362 response body");
    }
    if !win.contains("hybrid_send_get_address") {
        return Err("AM2 UART probe must use hybrid GetAddress");
    }
    if !win.contains("read_bm1362_serial_drain_summary") {
        return Err("AM2 UART probe must drain BM1362 summary");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 UART probe must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_probe_uart_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 probe_uart_for_chips is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 hybrid init_asic_chain primary 115200 open is BM1362, not S19k Track-1.
pub fn admit_s19k_am2_init_asic_open_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let win = am2_hybrid_source_method(hybrid_src, "fn init_asic_chain(")?;
    if !win.contains("=== BM1362 ASIC INIT") {
        return Err("AM2 init_asic_chain must name BM1362 ASIC INIT");
    }
    if !win.contains("let mut serial = SerialChainBackend::open_with_preference(0, serial_device, 115_200, uart_preference)") {
        return Err("AM2 init_asic_chain must open primary UART at 115200");
    }
    if !win.contains("am2_post_reset_settle_ms") {
        return Err("AM2 init_asic_chain primary open must settle via am2_post_reset_settle_ms");
    }
    if !win.contains("Failed to open serial port at 115200") {
        return Err("AM2 init_asic_chain primary open must name 115200 failure");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 init_asic_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_init_asic_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 init_asic_chain primary open is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 hybrid mining-on passthrough is BM1362 DEFAULT-7 open, not S19k Track-1.
pub fn admit_s19k_am2_passthrough0_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let method = am2_hybrid_source_method(hybrid_src, "pub async fn run(")?;
    let Some(start) = method.find("PASSTHROUGH: skipping Phase 1-7 (bosminer owns PIC+chain init)") else {
        return Err("missing AM2 hybrid passthrough skip");
    };
    let win = &method[start..];
    let end = win.find("\n        } else {").ok_or("missing AM2 passthrough arm boundary")?;
    let passthrough = &win[..end];
    if !passthrough.contains("open_passthrough_with_preference(0, &serial_device, uart_preference)") {
        return Err("AM2 hybrid passthrough must use the typed chain-0 open");
    }
    if !passthrough.contains("BM1362_RESP_BODY_LEN") {
        return Err("AM2 hybrid passthrough must set BM1362 response body");
    }
    if method.contains("require_bm1366_response_body")
        || method.contains("open_passthrough_bm1366")
        || method.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 hybrid passthrough must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_passthrough0_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 hybrid open_passthrough(0) is Zynq BM1362; not S19k Track-1 first-read")
}

pub fn admit_s19k_production_uses_tagged_fill_hunt(src: &str) -> Result<(), &'static str> {
    if !src.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path") {
        return Err("production hunter must call the admitted-TX-path fill parser");
    }
    if !src.contains("admit_s19k_fill_hunt_on_tx_path") {
        return Err("production hunter must refuse RX paths that did not receive work");
    }
    if !src.contains("S19kOutstandingFillTx") {
        return Err("production must index outstanding fill TX by job-id slot");
    }
    if src.contains("outstanding_s19k_tx.len() >= 32") {
        return Err("production must not FIFO-wrap outstanding fill TX");
    }
    refuse_tautological_fill_qualify_source(src)?;
    refuse_esp_bip320_as_braiins_fill_version(src)?;
    refuse_esp_midstate_as_braiins_fill_index(src)?;
    refuse_esp_flags_redrop_after_fill_hunt(src)?;
    if src.contains("0u16, // fill log 0: not ESP BIP320 body[6:7]") {
        return Err("production fill arm must not zero UART version_be (live407)");
    }
    if !src.contains("share.version_bits as u16") {
        return Err("production fill arm must pass UART version_be into midstate0 OR");
    }
    if !src.contains("0u8, // fill midstates=1") {
        return Err("production fill arm must pass midstate_idx = 0 (fill midstates=1)");
    }
    if !src.contains("0x80, // fill hunt") {
        return Err("production fill arm must not re-drop on ESP resp[8] after hunt");
    }
    Ok(())
}

/// Classify + qualify one 11-byte UART frame.
pub fn share_from_uart_frame(
    frame: &[u8],
    expected_job_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let kind = classify_bm1366_uart_rx_checked(frame).map_err(|_| S19kShareError::NotJobNonce)?;
    qualify_bm1366_job_nonce(kind, expected_job_id, base_version)
}

pub fn refuse_bm1368_job_id_extract(id: u8) -> u8 {
    // Document the wrong extract so tests can refuse it.
    (id & 0xF0) >> 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_am2_method_rejects_bm1366_at_tail(
        source: &str,
        signature: &str,
        validate: fn(&str) -> Result<(), &'static str>,
        expected_error: &'static str,
    ) {
        let start = source.find(signature).expect("real AM2 method");
        let method = am2_hybrid_source_method(source, signature).unwrap();
        let tail = start + method.len();
        for forbidden in [
            "require_bm1366_response_body",
            "open_passthrough_bm1366",
            "BM1366_UART_RESP_BODY_LEN",
        ] {
            let mutated = format!(
                "{}\n        {forbidden};{}",
                &source[..tail],
                &source[tail..]
            );
            assert_eq!(validate(&mutated), Err(expected_error), "{signature}: {forbidden}");
        }
    }

    #[test]
    fn s21_comparative_nonce_reconstructs_after_remainder_zero_admission() {
        // Comparative BM1368 live frame decoded with **BM1366** masks.
        let frame = [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ];
        let base = 0x2000_0000u32;
        let share = share_from_uart_frame(&frame, 0x10, base).unwrap();
        assert_eq!(share.job_id, 0x10);
        assert_eq!(share.small_core, 0x04);
        assert_eq!(share.midstate_num, 0x02);
        assert_eq!(share.nonce_be, 0x6096_394C);
        assert_eq!(share.nonce_le, 0x4C39_9660);
        assert_eq!(BM1366_VERSION_ROLL_MASK, 0x1FFF_E000);
        assert_ne!(BM1366_VERSION_ROLL_MASK, 0x1FFE_0000);
        // 0x0304 << 13 = 0x0060_8000; bits 13..16 must survive the mask.
        assert_eq!(0x0304u32 << 13, 0x0060_8000);
        assert_eq!(share.version_bits, 0x0304u32 << 13);
        assert_eq!(share.version_bits & 0x0000_8000, 0x0000_8000);
        assert_eq!(
            share.rolled_version,
            reconstruct_rolled_version(base, 0x0304)
        );
    }

    #[test]
    fn live407_fill_parse_keeps_uart_version_be() {
        // live407 Nonce #1 body. Fill log-0 mask would zero 0x00A0 and
        // hash 434faee1; keeping it feeds midstate0 OR 0x20140000.
        let body = [0x87, 0xD9, 0x6C, 0x10, 0x00, 0x00, 0x00, 0xA0, 0x94];
        let share = parse_bm1366_braiins_fill_share_from_body(&body, 0x2000_0000).unwrap();
        assert_eq!(share.nonce_le, 0x106C_D987);
        assert_eq!(
            share.attribution_provenance,
            S19kBm1366AttributionProvenance::BraiinsDerivedInPhysicalRange
        );
        assert!(share.braiins_physical_chip_core().is_some());
        assert_eq!(share.version_bits, 0x00A0);
        assert_eq!(
            crate::s19k_braiins_job::s19k_braiins_midstate0_version(
                0x2000_0000,
                share.version_bits as u16
            ),
            0x2014_0000
        );
        assert_eq!(share.rolled_version, 0x2014_0000);
        assert_ne!(
            crate::s19k_braiins_job::s19k_braiins_uart_version_bits(0x00A0, 0).unwrap(),
            0x00A0
        );
    }

    #[test]
    fn braiins_rounding_tail_is_observable_but_not_physical_identity() {
        let attr = crate::s19k_bm1366_braiins_nonce::decode_s19k_braiins_bm1366_attribution(
            u32::from(u16::MAX) << 9,
        )
        .unwrap();
        assert_eq!(attr.asic_index, 77);
        assert_eq!(
            s19k_braiins_attribution_provenance(&attr),
            S19kBm1366AttributionProvenance::BraiinsDerivedOutOfPhysicalRange
        );
    }

    #[test]
    fn s21_comparative_share_follow_on_pins() {
        let frame = [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ];
        let base = 0x2000_0000u32;
        let share = share_from_uart_frame(&frame, 0x10, base).unwrap();
        assert_eq!(
            reconstruct_rolled_version(0x2000_0000, 0x0304),
            0x2000_0000 | 0x0060_8000
        );
        assert_eq!(
            share.asic_index,
            share.chip_addr / crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL
        );
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL, 2);
        // Wrong family extract must not be used.
        assert_ne!(refuse_bm1368_job_id_extract(0x14), share.job_id);
        // BM1368 `(id & 0xF0) >> 1`: 0x14 → 0x08. Not BM1366 `id & 0xF8` → 0x10.
        assert_eq!(refuse_bm1368_job_id_extract(0x14), 0x08);
        // ChipAddress must not qualify as a share.
        let chip = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            share_from_uart_frame(&chip, 0x10, base),
            Err(S19kShareError::NotJobNonce)
        ));
        assert!(share_from_uart_frame(&frame, 0x08, base).is_err());
        let body = &frame[2..];
        let from_body = parse_bm1366_share_from_body(body, base).unwrap();
        assert_eq!(from_body.job_id, share.job_id);
        assert_eq!(from_body.nonce_le, share.nonce_le);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path"),
            "production BM1366 nonce path must bind fill RX to an admitted TX path"
        );
        assert!(s19k_hunt_retired_after_outstanding_miss(true, true));
        assert!(!s19k_hunt_retired_after_outstanding_miss(true, false));
        assert!(s19k_track1_hunt_retired_without_funnel(false));
        assert!(s19k_track1_count_wrap_retire_leftover(false));
        assert!(s19k_track1_refuse_wrap_retired_submit(false));
        assert!(!s19k_track1_refuse_wrap_retired_submit(true));
        assert!(admit_s19k_production_hunts_retired_after_outstanding_miss(serial).is_ok());
        assert!(serial.contains("else if is_bm1366"));
        assert!(admit_s19k_share_job_id_in_history(true, 0x10).is_ok());
        assert!(admit_s19k_share_job_id_in_history(false, 0x10).is_err());
        assert!(
            !serial.contains("admit_s19k_share_job_id_in_history"),
            "S19k BM1366 must not use ESP 0xF8 history admit"
        );
        assert!(
            serial.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path"),
            "Braiins fill RX must bind the job-id slot to a path that received work"
        );
        assert!(
            admit_s19k_production_uses_tagged_fill_hunt(serial).is_ok(),
            "Braiins fill RX must hunt tagged body against outstanding 21 36 TX"
        );
        assert!(admit_s19k_production_hunt_uses_body9(serial).is_ok());
        assert!(admit_s19k_production_hunt_uses_body9(
            "hunt_s19k_bm1366_fill_from_admitted_tx_path\nSome(&resp[..7])\nBM1366_UART_RESP_BODY_LEN"
        )
        .is_err());
        assert!(refuse_s19k_production_bm1366_hunt_as_hal_body7().is_err());
        assert!(admit_s19k_production_sets_body_before_first_read(serial).is_ok());
        assert!(admit_s19k_production_sets_body_before_first_read(
            "SerialChainBackend::open_passthrough_bm1366(i as u8, path)\nsend_get_address\ns.set_response_len(resp_body_len)"
        )
        .is_err());
        assert!(refuse_hal_default_body7_as_bm1366_first_read(7).is_err());
        assert!(refuse_hal_default_body7_as_bm1366_first_read(9).is_ok());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(false, 7).is_err());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(true, 7).is_ok());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(false, 9).is_ok());
        assert!(admit_s19k_production_requires_body9_before_first_read(serial).is_ok());
        assert!(admit_s19k_production_requires_body9_before_first_read(
            "SerialChainBackend::open_passthrough_bm1366(i as u8, path)\nsend_get_address\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(admit_s19k_init_bm1366_requires_body9_before_flush(serial).is_ok());
        assert!(admit_s19k_init_bm1366_requires_body9_before_flush(
            "fn init_bm1366_chain(\nserial: &ValidatedSerialBackend\nflush_io\nrequire_bm1366_response_body\nfn init_bm1370_chain("
        )
        .is_err());
        assert!(admit_s19k_init_bm1366_requires_fresh_switched_baud_response(serial).is_ok());
        assert!(admit_s19k_init_bm1366_requires_fresh_switched_baud_response(
            "fn init_bm1366_chain(\nBOSMINER_BM1366_FASTUART_REG\nset_baud(BOSMINER_BM1366_AML_HOST_BAUD)\nfor i in 0..chip_count\nfn init_bm1370_chain("
        )
        .is_err());
        assert!(admit_s19k_init_bm1366_omits_esp_a4(serial).is_ok());
        assert!(admit_s19k_init_bm1366_omits_esp_a4(
            "fn init_bm1366_chain(\nBM1366_VERSION_MASK_VALUE\nfn init_bm1370_chain("
        )
        .is_err());
        assert!(admit_s19k_production_run_skips_init_bm1366_chain(serial).is_ok());
        assert!(admit_s19k_nopic_observation_refuses_bm1366(serial).is_ok());
        assert!(admit_s19k_nopic_observation_refuses_bm1366(
            "fn begin_nopic_observation(\nAsicProtocolIdentity::Bm1366\n"
        )
        .is_err());
        assert!(admit_s19k_native_multi_uart_route_is_fenced(serial).is_ok());
        const AML_HAL: &str = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");
        assert!(admit_s19k_native_aggregate_platform_admission(AML_HAL, serial).is_ok());
        let power_enabled = AML_HAL.replacen(
            "service.psu_enable_operation_available = false",
            "service.psu_enable_operation_available = true",
            1,
        );
        assert!(admit_s19k_native_aggregate_platform_admission(&power_enabled, serial).is_err());
        let remapped = AML_HAL.replacen("uart: \"/dev/ttyS3\"", "uart: \"/dev/ttyS4\"", 1);
        assert!(admit_s19k_native_aggregate_platform_admission(&remapped, serial).is_err());
        let pwm_elevated = AML_HAL.replacen(
            "Result<Arc<S19kNativeFanObservation>>",
            "Result<Arc<dyn FanAccess>>",
            1,
        );
        assert!(admit_s19k_native_aggregate_platform_admission(&pwm_elevated, serial).is_err());
        assert!(admit_s19k_native_multi_uart_route_is_fenced(
            "ExactSerialRoute::S19kNative\nstruct S19kNativePreSerialAdmission {"
        )
        .is_err());
        assert!(refuse_s19k_nopic_probe_as_track1_first_read().is_err());
        const HYBRID: &str = include_str!("../../dcentrald/src/s19j_hybrid_mining.rs");
        assert!(admit_s19k_am2_hybrid_reset_is_not_bm1366(HYBRID).is_ok());
        // Extend the real method with diagnostics before inserting either
        // BM1366 first-read form beyond the former 1800-byte window.
        for forbidden in [
            "require_bm1366_response_body",
            "open_passthrough_bm1366",
            "BM1366_UART_RESP_BODY_LEN",
        ] {
            let diagnostics = "serial wake diagnostic ".repeat(80);
            let mutated = HYBRID.replacen(
                "info!(\"Baud reset complete\");",
                &format!("/* {diagnostics} */\n        {forbidden};\n        info!(\"Baud reset complete\");"),
                1,
            );
            assert_ne!(mutated, HYBRID, "real AM2 baud-reset mutation must apply");
            assert_eq!(
                admit_s19k_am2_hybrid_reset_is_not_bm1366(&mutated),
                Err("AM2 hybrid reset_asic_baud must not borrow BM1366 first-read")
            );
        }
        assert!(refuse_s19k_am2_hybrid_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_reset_baseline_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_am2_reset_baseline_is_not_bm1366(
            "fn observe_reset_baseline(\nBM1362_UNASSIGNED_RESP_BODY_LEN\nAM2 BM1362 reset-baseline\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_reset_baseline_as_track1_first_read().is_err());
        const AM3_BB: &str = include_str!("../../dcentrald/src/am3_bb_mining.rs");
        assert!(admit_s19k_am3_bb_open_is_not_bm1366(AM3_BB).is_ok());
        assert!(admit_s19k_am3_bb_open_is_not_bm1366(
            "impl Am3BbChainUart\nam3-bb: SerialChainBackend::open\nopen_passthrough_bm1366"
        )
        .is_err());
        assert!(refuse_s19k_am3_bb_open_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1398_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1398_is_not_bm1366(
            "fn init_bm1398_chain(\nSerialBringUpPluginKind::SerialBm1398\nsend_get_address_bm1397plus\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1398_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1368_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1368_is_not_bm1366(
            "fn init_bm1368_chain(\nValidatedSerialBackend\nSerialBringUpPluginKind::AmlogicBm1368\n=== BM1368 ASIC INIT\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1368_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1370_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1370_is_not_bm1366(
            "fn init_bm1370_chain(\nValidatedSerialBackend\nSerialBringUpPluginKind::AmlogicBm1370\n=== BM1370 ASIC INIT\nsend_get_address_bm1397plus\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1370_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1362_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1362_is_not_bm1366(
            "fn init_bm1362_chain(\nValidatedSerialBackend\n=== BM1362 ASIC INIT\nBM1362 init requires the checked reset-baseline 115200\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1362_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_companion_open_is_not_bm1366(HYBRID).is_ok());
        assert_am2_method_rejects_bm1366_at_tail(
            HYBRID,
            "fn init_asic_chain(",
            admit_s19k_am2_companion_open_is_not_bm1366,
            "AM2 companion must not borrow BM1366 first-read",
        );
        assert!(refuse_s19k_am2_companion_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_phase3b1_relay_is_not_bm1366(HYBRID).is_ok());
        assert_am2_method_rejects_bm1366_at_tail(
            HYBRID,
            "pub async fn run(",
            admit_s19k_am2_phase3b1_relay_is_not_bm1366,
            "Phase 3b1-relay must not borrow BM1366 first-read",
        );
        assert!(refuse_s19k_am2_phase3b1_relay_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_probe_uart_is_not_bm1366(HYBRID).is_ok());
        assert_am2_method_rejects_bm1366_at_tail(
            HYBRID,
            "fn probe_uart_for_chips(",
            admit_s19k_am2_probe_uart_is_not_bm1366,
            "AM2 UART probe must not borrow BM1366 first-read",
        );
        assert!(refuse_s19k_am2_probe_uart_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_init_asic_open_is_not_bm1366(HYBRID).is_ok());
        assert_am2_method_rejects_bm1366_at_tail(
            HYBRID,
            "fn init_asic_chain(",
            admit_s19k_am2_init_asic_open_is_not_bm1366,
            "AM2 init_asic_chain must not borrow BM1366 first-read",
        );
        assert!(refuse_s19k_am2_init_asic_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_passthrough0_is_not_bm1366(HYBRID).is_ok());
        assert_am2_method_rejects_bm1366_at_tail(
            HYBRID,
            "pub async fn run(",
            admit_s19k_am2_passthrough0_is_not_bm1366,
            "AM2 hybrid passthrough must not borrow BM1366 first-read",
        );
        assert!(refuse_s19k_am2_passthrough0_as_track1_first_read().is_err());
        const HAL: &str = include_str!("../../dcentrald-hal/src/serial_chain.rs");
        assert!(admit_s19k_hal_open_passthrough_bm1366(HAL).is_ok());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_hal_extracts_bm1366_body9(HAL).is_ok());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_hal_midstream_body7_then_body9(HAL).is_ok());
        assert!(admit_s19k_production_uses_bm1366_passthrough_open(serial).is_ok());
        assert!(admit_s19k_production_uses_bm1366_passthrough_open(
            "SerialChainBackend::open_passthrough(i as u8, path)"
        )
        .is_err());
        assert!(admit_s19k_production_refuses_generic_passthrough_for_bm1366(serial).is_ok());
        assert!(admit_s19k_production_refuses_generic_passthrough_for_bm1366(
            "} else if passthrough {\n            let mut s = SerialChainBackend::open_passthrough(0, &serial_device)"
        )
        .is_err());
        assert!(refuse_s19k_generic_passthrough0_as_track1().is_err());
        assert!(refuse_tautological_fill_qualify_source(
            "qualify_bm1366_braiins_fill_from_body(&resp[..9], share.job_id, 0)"
        )
        .is_err());
        assert!(
            serial.contains("format_s19k_port_rx_matrix"),
            "passthrough GetAddress must log per-port RX, not a single ChipAnswered"
        );
        assert!(
            serial.contains("refuse_one_required_port_as_dual_chain_proof"),
            "one answering UART must not be dual-chain proof"
        );
        assert!(
            serial.contains("refuse_zero_required_ports_as_dual_chain_proof"),
            "zero required UART answers must not be dual-chain proof"
        );
        assert!(
            serial.contains("refuse_s3_only_as_required_pair_proof"),
            "ttyS3-only ChipAddress must not be required-pair proof"
        );
        assert!(
            serial.contains("admit_s19k_braiins_fill_share_job_id_in_history"),
            "Braiins fill history must not mask 0xF8"
        );
        let fill_frame = [
            0xAA, 0x55, 0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x00, 0x8F,
        ];
        let fill = parse_bm1366_braiins_fill_share_from_body(&fill_frame[2..], base).unwrap();
        assert_eq!(fill.job_id, 2);
        assert_ne!(fill.job_id, 2u8 << 3);
        assert_eq!(fill.nonce_be, 0x1122_3344);
        assert_eq!(
            fill.nonce_be,
            crate::s19k_braiins_job::s19k_braiins_fill_nonce_word(0x1122_3344)
        );
        assert_eq!(fill.nonce_le, 0x4433_2211);
        assert_eq!(
            crate::s19k_braiins_job::s19k_braiins_uart_version_bits(0xABCD, 0).unwrap(),
            0
        );
        assert_eq!(fill.version_bits, 0);
        assert_eq!(fill.rolled_version, base);
        assert_eq!(fill.midstate_num, 0);
        let noisy = [0x11, 0x22, 0x33, 0x44, 0x07, 0x02, 0xAB, 0xCD, 0x81];
        let noisy_fill = parse_bm1366_braiins_fill_share_from_body(&noisy, base).unwrap();
        assert_eq!(noisy_fill.version_bits, 0xABCD);
        assert_eq!(
            noisy_fill.rolled_version,
            crate::s19k_braiins_job::s19k_braiins_midstate0_version(base, 0xABCD)
        );
        assert_eq!(noisy_fill.job_id, 2);
        assert_eq!(noisy_fill.midstate_num, 0);
        let esp_noisy = parse_bm1366_share_from_body(&noisy, base).unwrap();
        assert_ne!(esp_noisy.version_bits, 0);
        assert_eq!(esp_noisy.midstate_num, 0x07);
        assert!(refuse_esp_midstate_as_braiins_fill_index("share.midstate_num").is_err());
        assert!(refuse_esp_midstate_as_braiins_fill_index("0u8, // fill midstates=1").is_ok());
        assert!(refuse_esp_flags_redrop_after_fill_hunt("0u16, // fill log 0\nresp[8],").is_err());
        assert!(
            refuse_esp_flags_redrop_after_fill_hunt("0u16, // fill log 0\n0x80, // fill hunt")
                .is_ok()
        );
        assert!(
            refuse_esp_bip320_as_braiins_fill_version("(share.version_bits >> 13) as u16").is_err()
        );
        assert!(refuse_esp_bip320_as_braiins_fill_version("0u16, // fill log 0").is_ok());
        let esp = parse_bm1366_share_from_body(&fill_frame[2..], base).unwrap();
        assert_eq!(esp.job_id, 0);
        assert!(refuse_esp_f8_mask_as_braiins_fill_job_id(0x02).is_err());
        assert!(refuse_esp_step8_as_braiins_fill_registry(8, 0x7F).is_err());
        assert!(refuse_esp_step8_as_braiins_fill_registry(1, 0xFF).is_ok());
        assert!(admit_s19k_braiins_fill_share_job_id_in_history(true, 2).is_ok());
        assert!(admit_s19k_braiins_fill_share_job_id_in_history(false, 2).is_err());
        assert!(refuse_esp_qualify_as_braiins_fill(2).is_err());
        assert!(refuse_esp_qualify_as_braiins_fill(0x10).is_ok());
        let q = qualify_bm1366_braiins_fill_from_body(&SYNTHETIC_BM1366_FILL_WORK2_BODY, 2, base)
            .unwrap();
        assert_eq!(q.job_id, 2);
        assert!(qualify_bm1366_braiins_fill_from_body(
            &SYNTHETIC_BM1366_FILL_WORK2_BODY,
            0x10,
            base
        )
        .is_err());
        let tx2 = s19k_fill_tx_prefix(2).to_vec();
        let tx3 = s19k_fill_tx_prefix(3).to_vec();
        let hit = hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx2.clone()],
        )
        .unwrap();
        assert_eq!(hit.job_id, 2);
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx3],
        )
        .is_err());
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[],
        )
        .is_err());
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS0",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx2.clone()],
        )
        .is_err());
        assert!(
            hunt_s19k_bm1366_fill_from_tagged_outstanding("/dev/ttyS1", None, &[tx2.clone()],)
                .is_err()
        );
        let cut7 = &SYNTHETIC_BM1366_FILL_WORK2_BODY[..7];
        let cut7_err =
            hunt_s19k_bm1366_fill_from_tagged_outstanding("/dev/ttyS2", Some(cut7), &[tx2.clone()])
                .expect_err("HAL body-7 must not hunt as a share");
        assert!(
            cut7_err.contains("framing") || cut7_err.contains("not JobNonce"),
            "HAL body-7 must be framing, not silence: {cut7_err}"
        );
        assert!(!cut7_err.contains("silence"));
        assert!(
            refuse_constructed_fill_hal_body7_wire_as_share("/dev/ttyS1", 2, &[tx2.clone()],)
                .is_err()
        );
        assert!(
            refuse_constructed_fill_hal_body7_wire_as_share("/dev/ttyS0", 2, &[tx2.clone()])
                .is_ok()
        );
        let taut = qualify_bm1366_braiins_fill_from_body(
            &SYNTHETIC_BM1366_FILL_WORK2_BODY,
            parse_bm1366_braiins_fill_share_from_body(&SYNTHETIC_BM1366_FILL_WORK2_BODY, base)
                .unwrap()
                .job_id,
            base,
        );
        assert!(
            taut.is_ok(),
            "self-qualify is tautological; hunt requires TX"
        );
        let mut live = S19kOutstandingFillTx::new();
        let mut retired = S19kOutstandingFillTx::new();
        let first = live
            .insert_wire_retiring(tx2.clone(), &mut retired)
            .unwrap();
        assert!(!first.retired_prev);
        assert!(retired.get(2).is_none());
        let second = live
            .insert_wire_retiring(tx2.clone(), &mut retired)
            .unwrap();
        assert!(second.retired_prev);
        assert!(retired.get(2).is_some());
        // live443: wrap-5 clone() replace dropped wrap-4 leftover TX.
        // wrap-retire leftover must keep the prior retired generation.
        let wrap4 = s19k_fill_tx_prefix(2).to_vec();
        let post_admit = {
            let mut w = s19k_fill_tx_prefix(2).to_vec();
            w.push(0xAA);
            w
        };
        let mut wrap4_store = S19kOutstandingFillTx::new();
        wrap4_store.insert_wire(wrap4.clone()).unwrap();
        let mut live_post = S19kOutstandingFillTx::new();
        live_post.insert_wire(wrap4.clone()).unwrap();
        live_post
            .insert_wire_retiring(post_admit.clone(), &mut wrap4_store)
            .unwrap();
        let slots = [2u8];
        assert!(
            s19k_leftover_hit_from_retired_store(&wrap4_store, &slots, |w| w == wrap4.as_slice()),
            "wrap-4 leftover 21 36 must leftover_hit after wrap-retire"
        );
        let replaced = live_post.clone();
        assert!(
            !s19k_leftover_hit_from_retired_store(&replaced, &slots, |w| w == wrap4.as_slice()),
            "live443 wrap-5 clone() replace drops wrap-4 leftover TX"
        );
        wrap4_store.merge_from(&live_post);
        assert!(
            s19k_leftover_hit_from_retired_store(&wrap4_store, &slots, |w| w == wrap4.as_slice()),
            "wrap-5 merge must keep wrap-4 leftover 21 36"
        );
        assert!(
            s19k_leftover_hit_from_retired_store(&wrap4_store, &slots, |w| w
                == post_admit.as_slice()),
            "wrap-5 merge must leftover_hit POST-admit 21 36"
        );
        assert_eq!(S19K_RETIRED_TX_GENS, 4);
        assert!(s19k_track1_wrap_overwrite_must_retire(1, true));
        assert!(!s19k_track1_wrap_overwrite_must_retire(0, true));
        assert!(refuse_s19k_wrap7_same_id_drop_without_retire(7, false).is_err());
        assert!(refuse_s19k_wrap7_same_id_drop_without_retire(7, true).is_ok());
        assert!(refuse_s19k_wrap7_same_id_drop_without_retire(6, false).is_ok());
        assert!(admit_s19k_production_retires_wrap_overwrite(serial).is_ok());
        assert_eq!(S19K_FILL_TX_SLOTS, 256);
        assert_eq!(S19K_BM1366_HOLD_QUEUE_DEPTH, 4);
        assert!(refuse_s19k_fifo32_wrap_as_outstanding_table().is_err());
        assert!(admit_s19k_uart_queue_covers_fill_slots(S19K_FILL_TX_SLOTS).is_ok());
        assert!(admit_s19k_uart_queue_covers_fill_slots(16).is_err());
        assert!(admit_s19k_bm1366_hold_queue_uart_paced(S19K_BM1366_HOLD_QUEUE_DEPTH).is_ok());
        assert!(admit_s19k_bm1366_hold_queue_uart_paced(S19K_FILL_TX_SLOTS).is_err());
        assert!(refuse_s19k_live408_256_drop_oldest_as_hold().is_err());
        assert!(refuse_s19k_uart_queue16_as_fill_depth(16).is_err());
        assert!(refuse_s19k_uart_queue16_as_fill_depth(256).is_ok());
        assert!(admit_s19k_production_bm1366_queue_covers_fill_slots(serial).is_ok());
        assert!(admit_s19k_production_bm1366_holds_before_take_dispatch(serial).is_ok());
        assert_eq!(s19k_track1_job_id_retry_slots(0x04), [0x04, 0x00, 0x00]);
        assert_eq!(s19k_track1_job_id_retry_slots(0x0C), [0x0C, 0x08, 0x01]);
        assert!(admit_s19k_track1_job_id_retry_slots(0x04).is_ok());
        assert!(admit_s19k_production_retries_track1_job_id_slots(serial).is_ok());
        assert!(admit_s19k_production_bm1366_queue_covers_fill_slots(
            "let work_queue_depth = if is_bm1362 {\nBM1362_SERIAL_WORK_QUEUE_DEPTH\n} else {\nDEFAULT_SERIAL_WORK_QUEUE_DEPTH\n}"
        )
        .is_err());
        assert!(admit_s19k_track1_thermal_handoff_unowned(serial).is_ok());
        assert!(admit_s19k_track1_thermal_handoff_unowned(
            "let thermal_proof_present = am2_fan.is_some() || braiins_bm1366_passthrough_handoff;"
        )
        .is_err());
        assert!(refuse_s19k_track1_handoff_as_thermal_ready().is_err());
        assert!(refuse_s19k_track1_pwm30_as_leftover_ready().is_err());
        assert_eq!(S19K_TRACK1_LEFTOVER_FAN_PWM, 100);
        assert_eq!(S19K_LIVE88_SEATED_TMP75_SLOTS, [false, true, true]);
        assert_eq!(
            s19k_track1_required_tmp75_slots(
                S19K_LIVE88_SEATED_TMP75_SLOTS,
                &["/dev/ttyS1", "/dev/ttyS2"],
            ),
            [false, true, true]
        );
        assert_eq!(
            s19k_track1_required_tmp75_slots(
                S19K_LIVE88_SEATED_TMP75_SLOTS,
                &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"],
            ),
            [true, true, true]
        );
        assert_eq!(
            s19k_track1_required_tmp75_slots([true, true, true], &["/dev/ttyS1", "/dev/ttyS2"],),
            [true, true, true],
            "held .78 three-board population must not be weakened by a two-UART TX plan"
        );
        assert!(serial.contains(
            "let s19k_track1_required_tmp75_slots = s19k_track1_required_tmp75_slots(\n            s19k_profile_seated_tmp75_slots"
        ));
        assert!(serial.contains("if !s19k_track1_required_tmp75_slots[slot as usize]"));
        let ready = admit_s19k_track1_thermal_ready(
            &[(42.0, 48.0), (41.0, 47.0)],
            S19K_TRACK1_LEFTOVER_FAN_PWM,
            false,
            80,
            5,
        );
        assert_eq!(
            ready.unwrap(),
            crate::work_dispatch_safety::ThermalSafetyState::Ready
        );
        assert!(
            admit_s19k_track1_thermal_ready(&[(42.0, 48.0), (41.0, 47.0)], 30, false, 80, 5,)
                .is_err()
        );
        assert!(admit_s19k_track1_thermal_ready(
            &[(42.0, 48.0), (41.0, 47.0)],
            S19K_TRACK1_LEFTOVER_FAN_PWM,
            true,
            80,
            5,
        )
        .is_err());
        assert!(
            admit_s19k_production_construction_serial_work(&crate::BoardDesc::am3_s19kpro())
                .is_ok()
        );
        assert!(admit_s19k_production_bm1366_tx_before_rx(serial).is_ok());
        assert!(
            admit_s19k_production_bm1366_tx_before_rx("let tx_before_rx = is_bm1362;").is_err()
        );
        assert!(admit_s19k_init_bm1366_requires_private_owner(serial).is_ok());
        assert!(admit_s19k_init_bm1366_requires_private_owner(
            "fn init_bm1366_chain(\nserial: &SerialChainBackend"
        )
        .is_err());
        assert_eq!(
            crate::work_dispatch_safety::admit_work_dispatch(
                &crate::work_dispatch_safety::WorkDispatchSafetyInputs {
                    watchdog: crate::work_dispatch_safety::WatchdogSafetyState::Armed,
                    heartbeat_requirement:
                        crate::work_dispatch_safety::HeartbeatRequirement::NoneRequired,
                    controllers: vec![],
                    thermal: crate::work_dispatch_safety::ThermalSafetyState::HandoffUnowned,
                    previously_revoked: false,
                }
            )
            .unwrap()
            .thermal,
            crate::work_dispatch_safety::ThermalSafetyState::HandoffUnowned
        );
        assert!(s19k_fill_job_id_from_tx_wire(&tx2).unwrap() == 2);
        assert!(s19k_fill_job_id_from_tx_wire(&[0x55, 0xAA, 0x21, 0x56, 2]).is_err());
        let body0 = [0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x96];
        let mut slots = S19kOutstandingFillTx::new();
        let mut fifo: Vec<Vec<u8>> = Vec::new();
        for id in 0u8..=40 {
            let tx = s19k_fill_tx_prefix(id).to_vec();
            assert_eq!(slots.insert_wire(tx.clone()).unwrap(), id);
            fifo.push(tx);
            if fifo.len() > 32 {
                fifo.remove(0);
            }
        }
        assert_eq!(slots.occupied(), 41);
        assert!(slots.get(0).is_some());
        assert!(fifo.iter().all(|tx| tx.get(4) != Some(&0)));
        assert!(
            hunt_s19k_bm1366_fill_from_tagged_outstanding("/dev/ttyS1", Some(&body0), &fifo,)
                .is_err()
        );
        let slot_hit =
            hunt_s19k_bm1366_fill_from_tagged_slot("/dev/ttyS1", Some(&body0), &slots).unwrap();
        assert_eq!(slot_hit.job_id, 0);
        let slot2 = hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &slots,
        )
        .unwrap();
        assert_eq!(slot2.job_id, 2);
        assert_eq!(
            s19k_fill_job_byte_or_small_core(
                S19K_CONSTRUCTED_FILL_JOB_ID,
                S19K_CONSTRUCTED_FILL_SMALL_CORE
            ),
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE
        );
        assert!(refuse_s19k_fill_job_byte_or_small_core_as_braiins().is_err());
        let mut overlay_slots = S19kOutstandingFillTx::new();
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .unwrap();
        assert!(hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .is_err());
        let esp_overlay = s19k_fill_lookup_tx_esp_overlay_experimental(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            &overlay_slots,
        )
        .unwrap();
        assert_eq!(esp_overlay.1, S19K_CONSTRUCTED_FILL_JOB_ID);
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_OR_CORE).to_vec())
            .unwrap();
        let identity_wins = hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .unwrap();
        assert_eq!(identity_wins.job_id, S19K_CONSTRUCTED_FILL_JOB_OR_CORE);
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            identity_wins.job_id
        )
        .is_ok());
        assert!(
            refuse_constructed_fill_hal_body7_extract_as_share("/dev/ttyS1", 2, &slots,).is_err()
        );
        assert!(
            refuse_constructed_fill_hal_body7_extract_as_share("/dev/ttyS0", 2, &slots,).is_ok()
        );
        let extracted =
            admit_constructed_fill_hal_body9_extract_hunts("/dev/ttyS1", 2, &slots).unwrap();
        assert_eq!(extracted.job_id, 2);
        assert!(refuse_s19k_body7_two_frame_extract_as_shares("/dev/ttyS1", &slots).is_err());
        assert!(refuse_s19k_body7_two_frame_extract_as_shares("/dev/ttyS0", &slots).is_ok());
        let recovered =
            admit_s19k_body7_then_body9_next_frame_hunts("/dev/ttyS1", 2, 3, &slots).unwrap();
        assert_eq!(recovered.job_id, 3);
        assert!(admit_s19k_body7_then_body9_next_frame_hunts("/dev/ttyS0", 2, 3, &slots).is_err());
        slots.clear();
        assert!(
            hunt_s19k_bm1366_fill_from_tagged_slot("/dev/ttyS1", Some(&body0), &slots,).is_err()
        );
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .ok();
        assert!(hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS3",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .is_err());
        assert!(admit_s19k_production_uses_tagged_fill_hunt(serial).is_ok());
        let header = admit_s19k_constructed_fill_hunts_and_headers().unwrap();
        assert_eq!(header.len(), 80);
        assert_eq!(
            &header[0..4],
            &S19K_CONSTRUCTED_FILL_BASE_VERSION.to_le_bytes()
        );
        assert_eq!(&header[4..36], &S19K_CONSTRUCTED_FILL_PREV);
        assert_eq!(&header[36..68], &S19K_CONSTRUCTED_FILL_MERKLE);
        assert!(refuse_constructed_fill_header_as_bip320_strip(&header).is_ok());
        let mut stripped = header;
        stripped[0..4].copy_from_slice(
            &crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
                S19K_CONSTRUCTED_FILL_BASE_VERSION,
                0,
            )
            .to_le_bytes(),
        );
        assert!(refuse_constructed_fill_header_as_bip320_strip(&stripped).is_err());
        let endian = admit_s19k_fill_header_uses_workentry_prev_not_wire().unwrap();
        assert_eq!(
            &endian[4..36],
            &s19k_workentry_prev_from_stratum(&S19K_STRATUM_PREV_ASYM)
        );
        assert_ne!(&endian[4..36], &S19K_STRATUM_PREV_ASYM);
        assert!(refuse_s19k_stratum_prev_as_fill_header().is_err());
        assert!(refuse_s19k_wire_word_reverse_as_fill_header().is_err());
        assert!(admit_s19k_production_header_uses_workentry_prev(serial).is_ok());
        assert!(
            crate::s19k_bm1366_uart_rx::admit_s19k_production_classifies_init_rearm_rx(serial)
                .is_ok()
        );
    }

    #[test]
    fn s19k_fill_lookup_is_braiins_raw_not_esp_f8() {
        let share_src = include_str!("s19k_bm1366_share.rs");
        assert!(admit_s19k_production_fill_lookup_is_raw(share_src).is_ok());
        assert!(refuse_s19k_fill_overlay_f8_as_fun_0091c0a0().is_err());
        assert!(
            refuse_esp_f8_mask_as_braiins_fill_job_id(S19K_CONSTRUCTED_FILL_JOB_OR_CORE).is_err()
        );
        assert!(
            crate::s19k_braiins_job::admit_bosminer_fill_path_job_id_is_work_id_shl_log().is_ok()
        );
        assert_eq!(
            crate::s19k_braiins_job::s19k_braiins_uart_work_id_from_rx_job_byte(
                S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
                crate::s19k_braiins_job::s19k_braiins_fill_midstate_log()
            )
            .unwrap(),
            u64::from(S19K_CONSTRUCTED_FILL_JOB_OR_CORE)
        );
        let mut slots = S19kOutstandingFillTx::new();
        slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .unwrap();
        assert!(s19k_fill_lookup_tx(S19K_CONSTRUCTED_FILL_JOB_OR_CORE, &slots).is_err());
        assert_eq!(
            s19k_fill_lookup_tx_esp_overlay_experimental(S19K_CONSTRUCTED_FILL_JOB_OR_CORE, &slots)
                .unwrap()
                .1,
            S19K_CONSTRUCTED_FILL_JOB_ID
        );
        slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_OR_CORE).to_vec())
            .unwrap();
        let hit = s19k_fill_lookup_tx(S19K_CONSTRUCTED_FILL_JOB_OR_CORE, &slots).unwrap();
        assert_eq!(hit.1, S19K_CONSTRUCTED_FILL_JOB_OR_CORE);
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(hit.1, hit.1).is_ok());
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            S19K_CONSTRUCTED_FILL_JOB_ID
        )
        .is_err());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_live88_held_bm1366_job_nonce().is_ok());
    }

    #[test]
    fn s19k_retired_tx_hex_is_empty_after_remap_clear() {
        let mut retired = S19kOutstandingFillTx::new();
        let tx = s19k_fill_tx_prefix(8).to_vec();
        assert_eq!(retired.insert_wire(tx.clone()).unwrap(), 8);
        let retry = s19k_track1_job_id_retry_slots(8);
        assert_eq!(
            s19k_first_occupied_tx_hex(&retired, &retry),
            s19k_compact_tx_hex(&tx)
        );
        let remapped = S19kOutstandingFillTx::new();
        assert!(s19k_first_occupied_tx_hex(&remapped, &retry).is_empty());
        let mut two = S19kOutstandingFillTx::new();
        let miss = s19k_fill_tx_prefix(8).to_vec();
        let hit = s19k_fill_tx_prefix(9).to_vec();
        assert_eq!(two.insert_wire(miss.clone()).unwrap(), 8);
        assert_eq!(two.insert_wire(hit.clone()).unwrap(), 9);
        let slots = [8u8, 9];
        let chosen = s19k_first_tx_hex_where(&two, &slots, |w| w == hit.as_slice()).unwrap();
        assert_eq!(chosen, s19k_compact_tx_hex(&hit));
        assert_ne!(chosen, s19k_first_occupied_tx_hex(&two, &slots));
        assert!(s19k_leftover_class_matches_retired_tx(
            crate::S19kPostCleanNonceClass::LeftoverPreClean,
            true
        ));
        assert!(!s19k_leftover_class_matches_retired_tx(
            crate::S19kPostCleanNonceClass::LeftoverPreClean,
            false
        ));
        assert!(s19k_leftover_hit_from_retired_store(&two, &slots, |w| w == hit.as_slice()));
        assert!(!s19k_leftover_hit_from_retired_store(&two, &slots, |_| {
            false
        }));
        assert_eq!(S19K_TRACK1_RX_CHANNEL, 2048);
        assert!(refuse_s19k_rx_channel_as_wrap7_survival().is_err());
        let serial = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcentrald/src/serial_mining.rs"
        ));
        assert!(admit_s19k_production_rx_channel(serial).is_ok());
        assert_eq!(
            classify_s19k_post_clean_from_retired_tx_hit(false, true),
            crate::S19kPostCleanNonceClass::LeftoverPreClean
        );
        assert_eq!(
            classify_s19k_post_clean_from_retired_tx_hit(true, false),
            crate::S19kPostCleanNonceClass::NewBlockShare
        );
        assert!(s19k_leftover_class_matches_retired_tx(
            classify_s19k_post_clean_from_retired_tx_hit(false, true),
            true
        ));
    }
}
