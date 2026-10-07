//! Exact signed-2020 S17e/T17e read-only factory-record admission.
//! Source: native-factory-calibration-vectors-v1.json (16 complete original
//! acquisition/integrity/cache/population replays). EEPROM data is never written.
use super::*;
use dcentrald_common::bm1396_auto_adapt_voltage::{
    Bm1396AutoAdaptProfile, BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV,
    BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV,
};
use dcentrald_common::bm1396_s17e_factory::{self as s17e, S17eFactoryRecord};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryCalibrationRecord {
    chain: u8,
    bytes: Vec<u8>,
    attempted_word: Option<u32>,
    completed_at: Option<Instant>,
    calibration: Option<Result<u16, String>>,
    s17e: Option<Result<S17eFactoryRecord, String>>,
}
impl FactoryCalibrationRecord {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    /// Only bytes whose actual +30 completion was observed are present.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Last attempted read command, including a store/response that failed.
    pub fn attempted_word(&self) -> Option<u32> {
        self.attempted_word
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
    /// Both source CRCs/headers, AE marker and1500..2100 source range.
    /// This does not assert factory authenticity or an independent rail value.
    pub fn calibration(&self) -> Option<&Result<u16, String>> {
        self.calibration.as_ref()
    }
    pub fn s17e_profile(&self) -> Option<&Result<S17eFactoryRecord, String>> {
        self.s17e.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryCalibrationObservation {
    records: Vec<FactoryCalibrationRecord>,
    acquired_at: Option<Instant>,
    profile: Option<Bm1396AutoAdaptProfile>,
}
impl FactoryCalibrationObservation {
    pub fn records(&self) -> &[FactoryCalibrationRecord] {
        &self.records
    }
    /// Complete raw acquisition, distinct from successful profile admission.
    pub fn acquired_at(&self) -> Option<Instant> {
        self.acquired_at
    }
    pub fn profile(&self) -> Option<Bm1396AutoAdaptProfile> {
        self.profile
    }
}

// Original T17e AFB70, independently replayed for both complete source regions.
// CRC16/Modbus, initialFFFF, reflectedA001, stored little endian.
fn record_crc(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    crc
}

fn decode_record(bytes: &[u8]) -> Result<u16, String> {
    if bytes.len() != 256 {
        return Err("T17e factory record requires256 completed bytes".into());
    }
    let word = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    // Original57fe0 checks fixture[0..26] and miner[28..fe], independently.
    if record_crc(&bytes[..0x26]) != word(0x26) || word(0) != 0x1396 {
        return Err("T17e fixture CRC/header rejected".into());
    }
    if record_crc(&bytes[0x28..0xfe]) != word(0xfe) || word(0x28) != 0x1396 {
        return Err("T17e miner CRC/header rejected".into());
    }
    // Original59c7c getter followed by180c4 complete selected-chain admission.
    if bytes[0x82] != 0xae {
        return Err("T17e factory calibration marker rejected".into());
    }
    let calibration = word(0x83);
    if !(1500..=2100).contains(&calibration) {
        return Err("T17e factory calibration outside source1500..2100 range".into());
    }
    Ok(calibration)
}

impl<H: Hardware> Transport<H> {
    /// Only this transport's complete read-only acquisition supplies per-chip
    /// targets. Public pure factory records cannot replace retained owner data.
    pub fn s17e_factory_records(&self) -> Result<Vec<(u8, S17eFactoryRecord)>, String> {
        if self.model != Model::S17e || self.is_terminal() {
            return Err("S17e factory targets require their live exact owner".into());
        }
        let retained = self
            .factory_calibration
            .lock()
            .map_err(|_| "BM1396 factory custody poisoned")?;
        let observed = retained.as_ref().ok_or("S17e factory acquisition absent")?;
        if observed.acquired_at.is_none()
            || observed.profile != Some(Bm1396AutoAdaptProfile::Signed2020S17eFixed)
            || observed
                .records
                .iter()
                .map(|record| record.chain)
                .collect::<Vec<_>>()
                != self.chains
        {
            return Err("S17e factory population was not admitted".into());
        }
        observed
            .records
            .iter()
            .map(|record| {
                Ok((
                    record.chain,
                    record
                        .s17e
                        .as_ref()
                        .ok_or("S17e factory profile absent")?
                        .as_ref()
                        .map_err(Clone::clone)?
                        .clone(),
                ))
            })
            .collect()
    }

    pub fn factory_calibration_observation(
        &self,
    ) -> Result<Option<FactoryCalibrationObservation>, String> {
        Ok(self
            .factory_calibration
            .lock()
            .map_err(|_| "BM1396 factory custody poisoned")?
            .clone())
    }

    /// Only this owner's complete fresh acquisition can supply its native
    /// profile. A software CRC is integrity evidence, not authenticity or volts.
    pub fn factory_calibration_profile(&self) -> Result<Bm1396AutoAdaptProfile, String> {
        if self.is_terminal() {
            return Err("BM1396 factory profile after terminal".into());
        }
        self.factory_calibration
            .lock()
            .map_err(|_| "BM1396 factory custody poisoned")?
            .as_ref()
            .and_then(|observation| observation.profile)
            .ok_or_else(|| "BM1396 factory profile has not been admitted".into())
    }

    /// One retained read-only acquisition before cold work. T17e interpolation
    /// stays inside1760..1840cV; S17e requires every separate frequency record,
    /// both checksums, the mode-zero flag and its complete voltage population.
    /// Schedule before energizing: this full management transaction serializes
    /// PIC traffic, while the independent source cutoff remains available.
    pub async fn acquire_factory_calibration(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Bm1396AutoAdaptProfile, String> {
        self.worker(deadline, false, move |this| {
            // Preserve the terminal lock order: ASIC then management.
            let asic = this.lock(&this.asic, deadline, false)?;
            let _lane = this.lock(&this.management, deadline, false)?;
            if asic.startup_attempted
                || !asic.publications.is_empty()
                || this.hardware.read(DHASH)? & RUN != 0
            {
                return Err("BM1396 factory read requires an unused cold engine".into());
            }
            this.query_presence(deadline)?;
            {
                let mut retained = this
                    .factory_calibration
                    .lock()
                    .map_err(|_| "BM1396 factory custody poisoned")?;
                if retained.is_some() {
                    return Err("BM1396 factory acquisition already attempted".into());
                }
                *retained = Some(FactoryCalibrationObservation {
                    records: Vec::new(),
                    acquired_at: None,
                    profile: None,
                });
            }
            for &chain in &this.chains {
                this.factory_calibration
                    .lock()
                    .map_err(|_| "BM1396 factory custody poisoned")?
                    .as_mut()
                    .ok_or("BM1396 lost factory custody")?
                    .records
                    .push(FactoryCalibrationRecord {
                        chain,
                        bytes: Vec::with_capacity(256),
                        attempted_word: None,
                        completed_at: None,
                        calibration: None,
                        s17e: None,
                    });
                for offset in 0..=255u32 {
                    this.query_presence(deadline)?;
                    if this.hardware.read(DHASH)? & RUN != 0 {
                        return Err("BM1396 engine became active during factory read".into());
                    }
                    // Original556ec -> B5C7C: device50|(chain&7), address-present,
                    // read flag, bus0. Transport admission already refuses aliases.
                    let word = 0x03a0_0000 | (u32::from(chain) << 16) | (offset << 8);
                    this.factory_calibration
                        .lock()
                        .map_err(|_| "BM1396 factory custody poisoned")?
                        .as_mut()
                        .ok_or("BM1396 lost factory custody")?
                        .records
                        .last_mut()
                        .ok_or("BM1396 missing factory record")?
                        .attempted_word = Some(word);
                    let byte = this.management_byte_locked(word, deadline, false)?;
                    // Retain actual final completion before a late deadline can
                    // fail. Unlike stock, timeout is never truncated intoFF.
                    this.factory_calibration
                        .lock()
                        .map_err(|_| "BM1396 factory custody poisoned")?
                        .as_mut()
                        .ok_or("BM1396 lost factory custody")?
                        .records
                        .last_mut()
                        .ok_or("BM1396 missing factory record")?
                        .bytes
                        .push(byte);
                }
                this.delay(Duration::from_millis(500), deadline, false)?;
                let mut retained = this
                    .factory_calibration
                    .lock()
                    .map_err(|_| "BM1396 factory custody poisoned")?;
                let record = retained
                    .as_mut()
                    .ok_or("BM1396 lost factory custody")?
                    .records
                    .last_mut()
                    .ok_or("BM1396 missing factory record")?;
                record.completed_at = Some(Instant::now());
                match this.model {
                    Model::T17e => record.calibration = Some(decode_record(&record.bytes)),
                    Model::S17e => record.s17e = Some(s17e::decode_factory_record(&record.bytes)),
                }
            }
            this.query_presence(deadline)?;
            if this.hardware.read(DHASH)? & RUN != 0 {
                return Err("BM1396 engine active at factory completion".into());
            }
            let mut retained = this
                .factory_calibration
                .lock()
                .map_err(|_| "BM1396 factory custody poisoned")?;
            let observation = retained.as_mut().ok_or("BM1396 lost factory custody")?;
            observation.acquired_at = Some(Instant::now());
            if this.model == Model::S17e {
                let profiles = observation
                    .records
                    .iter()
                    .map(|record| {
                        record
                            .s17e
                            .as_ref()
                            .ok_or_else(|| "S17e factory record incomplete".to_string())?
                            .as_ref()
                            .map_err(Clone::clone)
                            .cloned()
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                s17e::population_working_voltage(&profiles)?;
                let plan_records = observation
                    .records
                    .iter()
                    .map(|record| record.chain)
                    .zip(profiles)
                    .collect::<Vec<_>>();
                s17e::startup_plan(&plan_records)?;
                this.check(deadline, false)?;
                observation.profile = Some(Bm1396AutoAdaptProfile::Signed2020S17eFixed);
                return Ok(Bm1396AutoAdaptProfile::Signed2020S17eFixed);
            }
            let mut calibration = None;
            for record in &observation.records {
                let value = record
                    .calibration
                    .as_ref()
                    .ok_or("BM1396 factory record incomplete")?
                    .as_ref()
                    .map_err(Clone::clone)?;
                if calibration.is_some_and(|old| old != *value) {
                    return Err("T17e selected factory calibrations disagree".into());
                }
                calibration = Some(*value);
            }
            let calibration_cv = calibration.ok_or("T17e factory population is empty")?;
            if !(BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV
                ..=BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV)
                .contains(&calibration_cv)
            {
                return Err(
                    "T17e factory calibration outside recovered native interpolation anchors"
                        .into(),
                );
            }
            let profile = Bm1396AutoAdaptProfile::Signed2020T17eCalibration { calibration_cv };
            this.check(deadline, false)?;
            observation.profile = Some(profile);
            Ok(profile)
        })
        .await
    }
}
