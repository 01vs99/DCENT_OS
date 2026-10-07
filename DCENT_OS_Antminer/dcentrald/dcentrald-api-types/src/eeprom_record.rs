//!  eep-A — EEPROM record DTOs (HAL-free, post-cipher).
//!
//! Source RE evidence:
//! .
//!
//! Bosminer-plus-tuner ships four EEPROM parser variants, each keyed on
//! the first two bytes of the (decrypted) plaintext blob. This module
//! consumes a **plaintext** byte slice (caller has already run XXTEA /
//! AES-128-ECB / Braiinsminer cipher as needed) and decodes the typed
//! record fields above the cipher.
//!
//! The crypto layer lives separately:
//! - EDF v5 / XXTEA caller-key path: `dcent-toolbox::core::eeprom_decoder`
//!   (Python, already shipped as -T2 partial).
//! - x19_plain / x19_J XXTEA: the deployed key and three-region framing are
//!   closed in [`crate::deployed_eeprom`]. This module still keeps its legacy
//!   post-cipher DTO dispatcher separate; callers holding a raw 256-byte page
//!   must use that deployed decoder rather than treating ciphertext as plaintext.
//!
//! Preamble dispatch (per RE doc §2):
//!
//! | Byte 0 | Byte 1   | Variant       | Hashboard families                  |
//! |--------|----------|---------------|-------------------------------------|
//! | `0x04` | `0x11`   | x19_plain/x19_J | BHB42xxx (S19/S19j Pro/T19; BM1398/BM1362) |
//! | `0x05` | `0x11`   | edf_v5_xxtea  | BHB56xxx, BHB68xxx (BM1366/BM1368)  |
//! | `0x01` | `0x41`   | format1_plaintext_name | A3HB4xxxx / A3HB7xxxx (S21 Pro/XP; BM1370) |
//! | `'B'`  | `'r'`    | braiinsminer  | BMM100/BMM101                       |
//! | other  | other    | UnknownPreamble | rejected with parse error         |
//!
//! **Format 1 note (2026-08-02; body decode landed rank 20, 2026-08-04):**
//! A3HB-prefixed boards are format 1, NOT format 5. Their header is `0x01 0x41`,
//! where `0x41` is `board_name[0]` (`'A'`), NOT a key-version selector —
//! `board_name` sits in a 16-byte plaintext header. `dispatch()` now returns a
//! structured, IDENTITY-ONLY [`Format1PlaintextNameRecord`] read from the known
//! plaintext offset `raw[1..16]`; the enciphered body key is unrecovered, so
//! every V/F/sweep/serial/CRC field stays absent (never falls back to a sibling
//! SKU's envelope). Evidence:
//! evidence/epic-eeprom-matched-samples-20.json` (A3HB70501/70601/70701
//! `fmt=1|keyver=65`). **Dispatch is always on `raw[0]`; never map a SKU to a
//! format** (`BHB56801` appears as both format 4 and 5).
//!
//! HAL-free; pure logic. Tests cover synthetic plaintext + the JSON shape
//! verified against `a lab unit` `hb0/hb1/hb2.parsed.json` evidence in the
//! knowledge-base.

use serde::{Deserialize, Serialize};

pub const RAW_EEPROM_BLOB_LEN: usize = 256;
pub const RAW_EEPROM_DECODE_SCHEMA: &str = "dcentos.eeprom.raw_decode.v1";

/// Discriminated union of all four EEPROM parser variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "variant", rename_all = "snake_case")]
pub enum EepromRecord {
    /// BHB42xxx (early S19/S19j Pro), XXTEA-encrypted. Raw deployed-page
    /// decryption lives in [`crate::deployed_eeprom`]; this legacy record keeps
    /// the preamble + raw payload only.
    X19Plain(X19PlainRecord),
    /// Exact BHB428xx BM1362 SKUs, XXTEA-encrypted with explicit PT1/PT2;
    /// marketing-model binding unresolved, plus sensor rows. Raw deployed-page
    /// decryption lives in
    /// [`crate::deployed_eeprom`].
    X19J(X19JRecord),
    /// BHB56xxx / BHB68xxx (BM1366/BM1368), EDF v5 header with XXTEA
    /// algorithm and explicit key index. (A3HB-prefixed S21 Pro/XP boards
    /// are format 1 `0x01 0x41`, NOT this variant — see module docs.)
    EdfV5Xxtea(EdfV5XxteaRecord),
    /// Legacy structured plaintext helper retained for callers that already
    /// converted a BHB56/BHB68 blob into field-like data.
    X21Aes(X21AesRecord),
    /// Braiins BMM100/101 boards.
    Braiinsminer(BraiinsminerRecord),
    /// A3HB4xxxx / A3HB7xxxx (S21 Pro / S21 XP, BM1370) — **format 1**
    /// `0x01 0x41`. Only the plaintext `board_name` is recoverable; the
    /// enciphered body key is unrecovered, so this is an IDENTITY-ONLY partial
    /// decode. See [`Format1PlaintextNameRecord`].
    Format1PlaintextName(Format1PlaintextNameRecord),
}

/// Maturity of the host-side, read-only decoder for one [`EepromRecord`]
/// family.
///
/// This is deliberately about bytes already held by the host. It is not a
/// board-admission, tuning, runtime, or write-authority state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EepromDecodeCapabilityState {
    /// A deployed 256-byte page is decoded by [`crate::deployed_eeprom`] using
    /// the header-selected XXTEA key and exact three-region framing.
    DeployedReadOnlyDecode,
    /// Only the exact plaintext board-name field is decoded; the encrypted
    /// body and every factory tuning field remain unavailable.
    IdentityOnlyDecode,
    /// The preamble is recognized and opaque bytes are retained, but no body
    /// fields are decoded.
    PreambleOnly,
    /// A legacy helper accepts caller-prepared structured plaintext; there is
    /// no raw deployed-page decoder for this variant in this crate.
    StructuredHelperOnly,
}

/// Exact, non-authorizing capability record for one EEPROM format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EepromFormatCapability {
    pub variant: &'static str,
    pub state: EepromDecodeCapabilityState,
    pub decoder: &'static str,
    pub integrity_scope: &'static str,
    pub identity_fields_decoded: bool,
    pub factory_tuning_fields_decoded: bool,
    pub runtime_admission_authorized: bool,
    pub tuning_authorized: bool,
    pub write_authorized: bool,
}

/// Exhaustive capability ceiling for the six [`EepromRecord`] variants.
///
/// `X19J` is kept distinct because it is a public DTO variant, even though the
/// deployed decoder returns the common [`crate::deployed_eeprom::DeployedHashboardIdentity`]
/// rather than constructing `EepromRecord::X19J` directly. Format 4/5 CRC5 is
/// advisory by design and is named as such instead of being overstated as an
/// authentication or admission gate.
pub const EEPROM_FORMAT_CAPABILITIES: &[EepromFormatCapability] = &[
    EepromFormatCapability {
        variant: "X19Plain",
        state: EepromDecodeCapabilityState::DeployedReadOnlyDecode,
        decoder: "deployed_eeprom::decode_deployed_eeprom",
        integrity_scope: "header-selected XXTEA plus advisory two-region CRC5",
        identity_fields_decoded: true,
        factory_tuning_fields_decoded: true,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
    EepromFormatCapability {
        variant: "X19J",
        state: EepromDecodeCapabilityState::DeployedReadOnlyDecode,
        decoder: "deployed_eeprom::decode_deployed_eeprom (common identity DTO)",
        integrity_scope: "header-selected XXTEA plus advisory two-region CRC5",
        identity_fields_decoded: true,
        factory_tuning_fields_decoded: true,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
    EepromFormatCapability {
        variant: "EdfV5Xxtea",
        state: EepromDecodeCapabilityState::DeployedReadOnlyDecode,
        decoder: "deployed_eeprom::decode_deployed_eeprom",
        integrity_scope: "header-selected XXTEA plus advisory two-region CRC5",
        identity_fields_decoded: true,
        factory_tuning_fields_decoded: true,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
    EepromFormatCapability {
        variant: "Format1PlaintextName",
        state: EepromDecodeCapabilityState::IdentityOnlyDecode,
        decoder: "deployed_eeprom::decode_deployed_eeprom (format-1 branch)",
        integrity_scope: "exact 256-byte page and bounded plaintext-name field only",
        identity_fields_decoded: true,
        factory_tuning_fields_decoded: false,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
    EepromFormatCapability {
        variant: "Braiinsminer",
        state: EepromDecodeCapabilityState::PreambleOnly,
        decoder: "eeprom_record::dispatch",
        integrity_scope: "Br preamble and opaque-byte retention only",
        identity_fields_decoded: false,
        factory_tuning_fields_decoded: false,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
    EepromFormatCapability {
        variant: "X21Aes",
        state: EepromDecodeCapabilityState::StructuredHelperOnly,
        decoder: "eeprom_record::decode_x21_aes",
        integrity_scope: "caller-prepared structured plaintext length/ASCII checks only",
        identity_fields_decoded: true,
        factory_tuning_fields_decoded: false,
        runtime_admission_authorized: false,
        tuning_authorized: false,
        write_authorized: false,
    },
];

/// Shape of an x21_aes plaintext record (post-AES decryption).
///
/// Field set per RE doc §4 (string at `0x00f1b0d6`):
/// `S/N FCT-JOB CH-DIE CH-MARK FT CH-TECH CH-BIN PCB BOM U1 VF U2 U3 SALE-R U4`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X21AesRecord {
    /// 17-char ASCII serial number (e.g. `AS19K…`).
    pub serial_number: String,
    /// Hashboard SKU name like `BHB56902` (cross-checked vs in-binary
    /// SKU table at `0x00eec028` to derive chip family).
    pub b_name: String,
    /// PCB version word.
    pub pcb_version: u16,
    /// BOM version word.
    pub bom_version: u16,
    /// Factory job ticket id (e.g. `JYZZ20230901007-Y1`).
    pub fact_job: String,
    /// Chip die marking (`ED`, etc.).
    pub ch_die: String,
    /// Chip marking line (e.g. `S1GM23AL36`).
    pub ch_marking: String,
    /// Functional test result string (e.g. `F1V18B3C1`).
    pub ft: String,
    /// Chip technology code (`BS`, etc.).
    pub ch_tech: String,
    /// Chip bin (silicon quality grade) — small integer as string.
    pub bin: String,
    /// V/F curve descriptor (encoded; consumer plugs into the relevant
    /// silicon-profiles table to compute target voltage at frequency).
    pub vf: Vec<u8>,
    /// SALE-R rate code (Bitmain marketing tier).
    pub sale_rate: Option<String>,
}

/// Shape of an EDF v5 encrypted EEPROM record.
///
/// Header `05 11` means format version 5, algorithm nibble 1 (XXTEA),
/// key index 1. The body is still encrypted here; this HAL-free crate only
/// reports read-only metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdfV5XxteaRecord {
    pub format_version: u8,
    pub cipher: String,
    pub key_index: u8,
    pub raw_payload: Vec<u8>,
}

/// Shape of an x19_plain record. The XXTEA KDF is unknown without further
/// RE so this variant is currently `preamble-only` — full field decode
/// requires capturing a BHB42xxx plaintext dump and matching it against
/// the bosminer panic-string field list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X19PlainRecord {
    /// First byte after preamble: layout sub-version.
    pub algo_or_subver: u8,
    /// Raw encrypted payload bytes (the caller is expected to keep this
    /// for forward-compat once the KDF is documented).
    pub raw_payload: Vec<u8>,
}

/// Shape of an x19_J record. Same KDF status as x19_plain — preamble +
/// raw payload only until further RE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X19JRecord {
    pub layout_version: u8,
    pub algo_key_version: u8,
    pub raw_payload: Vec<u8>,
}

/// Shape of a Braiinsminer (`BMM100`/`BMM101`) record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BraiinsminerRecord {
    /// `Br!` magic + remaining payload (cipher unknown).
    pub raw_payload: Vec<u8>,
}

/// Shape of a **format-1** (`0x01 0x41`) A3HB-prefixed page (S21 Pro / S21 XP,
/// BM1370).
///
/// Unlike every other variant this one carries a *readable* field:
/// `board_name` sits in a 16-byte PLAINTEXT header at `raw[1..16]` (`raw[1]` is
/// `board_name[0]`, the `'A'` that aliases as `0x41` — NOT a key selector). The
/// remaining `raw[16..256]` is 240 bytes of fully-diffused ciphertext under a
/// key D-Central does not hold, so **every enciphered field — default voltage,
/// frequency, sweep curve, serial, CRC — is unrecoverable and stays absent.**
///
/// This struct deliberately has NO field that a downstream consumer could
/// mistake for a V/F value: an S21 Pro/XP identity must never seed a voltage or
/// PLL envelope from a sibling SKU (CONTEXT §1.2 — never inherit another board's
/// energization envelope). Identity is all a format-1 page can honestly yield.
///
/// Evidence:
/// (the `fmt == 1` branch) + `epic-eeprom-matched-samples-20.json`
/// (A3HB70501/70601/70701, `format_version=1`, header byte-exact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Format1PlaintextNameRecord {
    /// The plaintext board name (`A3HB70501`, …) read from the KNOWN offset
    /// `raw[1..16]`, NUL/space-trimmed. This is the ONLY field recoverable from
    /// a format-1 page without the body key.
    pub board_name: String,
}

/// Parse error returned by `dispatch()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum EepromParseError {
    /// Plaintext blob is too short to even read the preamble.
    Truncated { got: usize, need: usize },
    /// Preamble doesn't match any known parser variant.
    UnknownPreamble { byte0: u8, byte1: u8 },
    /// Variant recognized but the body decoder isn't implemented yet
    /// (waiting on further RE).
    NotImplementedYet { variant: String },
    /// Body field decode failed (e.g. CRC mismatch, malformed field).
    BodyDecode { detail: String },
}

/// Status for a host-safe raw EEPROM/BHB decode attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEepromDecodeStatus {
    /// The blob length was not the expected 256-byte EEPROM page.
    MalformedLength,
    /// The preamble was recognized and a structured record was decoded.
    Decoded,
    /// The preamble was recognized, but only metadata could be normalized.
    MetadataOnly,
    /// The preamble did not match a known EEPROM parser.
    UnknownPreamble,
}

/// Normalized, read-only board identity extracted from a raw EEPROM blob.
///
/// This DTO is intentionally lossy: it exposes identity and provenance fields
/// that are safe for API/dashboard consumers without carrying cipher material,
/// proprietary keys, or any write-capable handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedHashboardMetadata {
    pub board_sku: Option<String>,
    pub chip_family: Option<String>,
    pub model_family: Option<String>,
    pub eeprom_variant: Option<String>,
    pub eeprom_format: Option<String>,
    pub cipher: Option<String>,
    pub key_index: Option<u8>,
    pub serial_number: Option<String>,
    pub confidence: String,
    pub source: String,
    pub read_only: bool,
    pub writes_performed: bool,
    pub notes: Vec<String>,
}

impl Default for NormalizedHashboardMetadata {
    fn default() -> Self {
        Self {
            board_sku: None,
            chip_family: None,
            model_family: None,
            eeprom_variant: None,
            eeprom_format: None,
            cipher: None,
            key_index: None,
            serial_number: None,
            confidence: "none".to_string(),
            source: "no_normalized_metadata".to_string(),
            read_only: true,
            writes_performed: false,
            notes: vec!["No EEPROM writes are performed by api-types decode helpers.".to_string()],
        }
    }
}

/// Host-safe raw EEPROM decode report for one 256-byte blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawEepromDecodeReport {
    pub schema: String,
    pub raw_len: usize,
    pub status: RawEepromDecodeStatus,
    pub record: Option<EepromRecord>,
    pub metadata: NormalizedHashboardMetadata,
    pub warnings: Vec<String>,
}

/// Dispatch a plaintext EEPROM blob to the right variant.
///
/// `plaintext` MUST be the post-cipher byte sequence — the caller has
/// already run XXTEA / AES-128-ECB / etc. as appropriate. Use
/// `dcent-toolbox::core::eeprom_decoder` for the cipher pass.
pub fn dispatch(plaintext: &[u8]) -> Result<EepromRecord, EepromParseError> {
    if plaintext.len() < 2 {
        return Err(EepromParseError::Truncated {
            got: plaintext.len(),
            need: 2,
        });
    }
    match (plaintext[0], plaintext[1]) {
        (0x04, 0x11) => {
            // x19_plain or x19_J — KDF not documented; return the
            // x19_plain preamble form so the caller knows what they
            // have. Distinguishing x19_plain vs x19_J requires a SKU
            // crosscheck after decrypt, which we can't do here.
            Ok(EepromRecord::X19Plain(X19PlainRecord {
                algo_or_subver: 0,
                raw_payload: plaintext[2..].to_vec(),
            }))
        }
        (0x05, 0x11) => {
            // EDF v5 encrypted record. Byte 1 splits into algorithm nibble
            // 0x1 (XXTEA) and key index 0x1.
            Ok(EepromRecord::EdfV5Xxtea(EdfV5XxteaRecord {
                format_version: 5,
                cipher: "xxtea".to_string(),
                key_index: 1,
                raw_payload: plaintext[2..].to_vec(),
            }))
        }
        (b'B', b'r') => Ok(EepromRecord::Braiinsminer(BraiinsminerRecord {
            raw_payload: plaintext.to_vec(), // includes the magic
        })),
        (0x01, 0x41) => {
            // Format 1 (A3HB4xxxx / A3HB7xxxx, S21 Pro/XP, BM1370). The header's
            // second byte is board_name[0] = 'A' (0x41), NOT a key selector, so
            // we only accept the exact observed (0x01, 0x41); any other second
            // byte has no held evidence and falls through to UnknownPreamble.
            //
            // board_name is PLAINTEXT at raw[1..16]. Read it from that KNOWN
            // offset — never scan the enciphered body (raw[16..256]), which is
            // fully-diffused ciphertext that could spell a false catalog SKU by
            // chance. The body key is unrecovered, so this is identity-only:
            // every enciphered field is unreadable and stays absent (see
            // `Format1PlaintextNameRecord`). Queue rank 20 / H3 #6.
            let board_name = read_ascii_field(plaintext, 1, 15)?;
            Ok(EepromRecord::Format1PlaintextName(
                Format1PlaintextNameRecord { board_name },
            ))
        }
        (a, b) => Err(EepromParseError::UnknownPreamble { byte0: a, byte1: b }),
    }
}

/// Decode an x21_aes plaintext body (everything after the 2-byte preamble).
///
/// Field framing per RE doc §4 + verified against `a lab unit` `hb*.parsed.json`.
/// The plaintext blob has fixed-length sections; we read by offset rather
/// than length-prefix because that's what bosminer does.
///
/// ** status**: this implements only the JSON-key-equivalent
/// surface (serial_number, b_name, fact_job, ch_*, ft, sale_rate). Full
/// VF curve byte-level layout is left as `Vec<u8>` until live cross-check
/// against more boards lands. PCB/BOM version words read from the well-known
/// 32-bit aligned offsets when present.
pub fn decode_x21_aes(payload: &[u8]) -> Result<X21AesRecord, EepromParseError> {
    if payload.len() < 32 {
        return Err(EepromParseError::Truncated {
            got: payload.len(),
            need: 32,
        });
    }
    // The field layout is text-tagged in the actual binary; for  we
    // expect the caller to provide a structured plaintext that mirrors the
    // hb*.parsed.json shape. The runtime adapter inside dcent-toolbox
    // populates the fields; we just validate length + ASCII-cleanness.
    //
    // Constructor for testing: caller hands in a serialized form that
    // matches a synthetic-plaintext layout. Real `a lab unit`-format plaintext is
    // decoded by `dcent-toolbox::core::eeprom_decoder.decode_x21_aes` (Python).
    let serial_number = read_ascii_field(payload, 0, 17)?;
    let b_name = read_ascii_field(payload, 17, 8)?;
    Ok(X21AesRecord {
        serial_number,
        b_name,
        pcb_version: 0,
        bom_version: 0,
        fact_job: String::new(),
        ch_die: String::new(),
        ch_marking: String::new(),
        ft: String::new(),
        ch_tech: String::new(),
        bin: String::new(),
        vf: Vec::new(),
        sale_rate: None,
    })
}

/// Decode a raw 256-byte BHB EEPROM page where the bytes are already
/// fixture-like plaintext.
///
/// This function does not decrypt, derive keys, contact hardware, or write
/// EEPROM. For encrypted/opaque records it only reports what can be proven
/// from the visible preamble and ASCII SKU strings.
pub fn decode_raw_256_blob(raw: &[u8]) -> RawEepromDecodeReport {
    let mut warnings = Vec::new();
    if raw.len() != RAW_EEPROM_BLOB_LEN {
        warnings.push(format!(
            "expected {} bytes, got {}; no hardware reads or writes attempted",
            RAW_EEPROM_BLOB_LEN,
            raw.len()
        ));
        return RawEepromDecodeReport {
            schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
            raw_len: raw.len(),
            status: RawEepromDecodeStatus::MalformedLength,
            record: None,
            metadata: NormalizedHashboardMetadata::default(),
            warnings,
        };
    }

    let record = dispatch(raw);
    let mut metadata = normalize_metadata_from_raw(raw, record.as_ref().ok());
    metadata.read_only = true;
    metadata.writes_performed = false;

    match record {
        Ok(record) => {
            let status = if matches!(record, EepromRecord::X21Aes(_)) {
                RawEepromDecodeStatus::Decoded
            } else {
                RawEepromDecodeStatus::MetadataOnly
            };
            if !matches!(record, EepromRecord::X21Aes(_)) {
                warnings.push(
                    "recognized preamble but full body decode requires decrypted fixture evidence"
                        .to_string(),
                );
            }
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status,
                record: Some(record),
                metadata,
                warnings,
            }
        }
        Err(EepromParseError::UnknownPreamble { byte0, byte1 }) => {
            warnings.push(format!(
                "unknown EEPROM preamble 0x{byte0:02x} 0x{byte1:02x}; no decode guessed"
            ));
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status: RawEepromDecodeStatus::UnknownPreamble,
                record: None,
                metadata,
                warnings,
            }
        }
        Err(err) => {
            warnings.push(format!(
                "recognized preamble but body decode failed: {err:?}"
            ));
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status: RawEepromDecodeStatus::MetadataOnly,
                record: None,
                metadata,
                warnings,
            }
        }
    }
}

fn normalize_metadata_from_raw(
    raw: &[u8],
    record: Option<&EepromRecord>,
) -> NormalizedHashboardMetadata {
    let mut metadata = NormalizedHashboardMetadata::default();
    match record {
        Some(EepromRecord::X21Aes(rec)) => {
            metadata.board_sku = Some(rec.b_name.clone());
            metadata.serial_number = if rec.serial_number.is_empty() {
                None
            } else {
                Some(rec.serial_number.clone())
            };
        }
        Some(EepromRecord::EdfV5Xxtea(rec)) => {
            metadata.eeprom_variant = Some("edf_v5_xxtea_key1".to_string());
            metadata.eeprom_format = Some(format!("edf_v{}", rec.format_version));
            metadata.cipher = Some(rec.cipher.clone());
            metadata.key_index = Some(rec.key_index);
            metadata.confidence = "preamble_only".to_string();
            metadata.source = "eeprom_header_05_11".to_string();
            metadata
                .notes
                .push("Header 05 11 = EDF v5, XXTEA algorithm, key index 1.".to_string());
            metadata.board_sku = scan_known_sku(raw);
        }
        Some(EepromRecord::Format1PlaintextName(rec)) => {
            metadata.eeprom_format = Some("format1".to_string());
            metadata.cipher = None; // body key unrecovered
            metadata.confidence = "plaintext_name".to_string();
            metadata.source = "eeprom_header_01_41".to_string();
            metadata.notes.push(
                "Header 01 41 = format 1; board_name is plaintext at raw[1..16], \
                 enciphered body key unrecovered (V/F/sweep unreadable)."
                    .to_string(),
            );
            // Identity comes from the KNOWN plaintext offset, never a full-page
            // ciphertext scan — a diffused body could spell a false SKU.
            metadata.board_sku = if rec.board_name.is_empty() {
                None
            } else {
                Some(rec.board_name.clone())
            };
        }
        _ => {
            metadata.board_sku = scan_known_sku(raw);
        }
    }

    if let Some(sku) = metadata.board_sku.as_deref() {
        if let Some(entry) = catalog_entry_for_sku(sku) {
            metadata.chip_family = Some(entry.chip_family.to_string());
            metadata.model_family = Some(entry.model_family.to_string());
            metadata.eeprom_variant = Some(entry.eeprom_variant.to_string());
            metadata.confidence = entry.confidence.to_string();
            metadata.source = entry.source.to_string();
            metadata.notes.push(entry.note.to_string());
        } else {
            metadata.confidence = "unknown_sku".to_string();
            metadata
                .notes
                .push(format!("visible SKU {sku} is not in BHB_SKU_CATALOG"));
        }
    }

    metadata
}

fn scan_known_sku(raw: &[u8]) -> Option<String> {
    for len in (7..=9).rev() {
        if raw.len() < len {
            continue;
        }
        for window in raw.windows(len) {
            if !window.iter().all(|b| b.is_ascii_alphanumeric()) {
                continue;
            }
            let Ok(candidate) = std::str::from_utf8(window) else {
                continue;
            };
            if catalog_entry_for_sku(candidate).is_some() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

/// Resolve a board name to its catalog row — **first match wins**.
///
/// ⚠ ORDER IS LOAD-BEARING. [`BHB_SKU_CATALOG`] mixes exact `model_id` rows
/// with prefix patterns, and this is a linear `find`. Every exact row MUST be
/// listed **before** any prefix that would also match it, or the prefix
/// answers first and the exact row becomes dead. Pinned by
/// `exact_rows_precede_the_prefix_catch_all_they_correct`.
pub fn catalog_entry_for_sku(b_name: &str) -> Option<&'static BhbSkuCatalogEntry> {
    let sku = b_name.trim();
    BHB_SKU_CATALOG
        .iter()
        .find(|entry| sku_matches_catalog_pattern(sku, entry.pattern))
}

fn sku_matches_catalog_pattern(sku: &str, pattern: &str) -> bool {
    match pattern {
        "BHB426xx" => sku.starts_with("BHB426"),
        "BHB568xx / BHB569xx" => sku.starts_with("BHB568") || sku.starts_with("BHB569"),
        // W8 rank-9 (2026-08-03): there is deliberately NO `BHB68` prefix arm.
        // BHB68 SKUs resolve only through their 8 exact roster rows; an
        // unknown `BHB68…` is `None` (fail closed), never a guessed family.
        "A3HB4xxxx" => sku.starts_with("A3HB4"),
        "A3HB7xxxx" => sku.starts_with("A3HB7"),
        _ => sku == pattern,
    }
}

/// Read an ASCII field at `[start, start+len)` from `payload`. Trims
/// trailing NUL/spaces. Returns `BodyDecode` on non-ASCII bytes.
fn read_ascii_field(payload: &[u8], start: usize, len: usize) -> Result<String, EepromParseError> {
    // bug-hunt LOW #10 (2026-05-28): `start + len` was unchecked. With large
    // start/len it could wrap (usize overflow) and pass the bounds check, then
    // `&payload[start..start+len]` would panic. Only internal callers with small
    // fixed constants reach this today, but checked_add makes it safe if
    // read_ascii_field is ever made pub / reused on attacker-influenced offsets.
    let end = match start.checked_add(len) {
        Some(e) if e <= payload.len() => e,
        _ => {
            return Err(EepromParseError::Truncated {
                got: payload.len(),
                need: start.saturating_add(len),
            });
        }
    };
    let bytes = &payload[start..end];
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return Err(EepromParseError::BodyDecode {
            detail: format!("non-ASCII bytes in field at offset {}", start),
        });
    }
    let s = std::str::from_utf8(bytes)
        .map_err(|e| EepromParseError::BodyDecode {
            detail: e.to_string(),
        })?
        .trim_end_matches(['\0', ' '])
        .to_string();
    Ok(s)
}

/// Static hashboard-SKU catalog distilled from the local RE corpus.
///
/// This is intentionally a small catalog surface, not a live EEPROM reader.
/// Route/API consumers can render this table without linking HAL code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BhbSkuCatalogEntry {
    pub pattern: &'static str,
    pub chip_family: &'static str,
    pub model_family: &'static str,
    pub eeprom_variant: &'static str,
    pub confidence: &'static str,
    pub source: &'static str,
    pub note: &'static str,
}

/// Known BHB/A3HB SKU-to-chip-family catalog.
///
/// Source anchors for the BHB428 correction (2026-08-09):
/// - the exact ePIC v1.22.0 jig roster reports all six BHB428 SKUs as
///   `BM1362` / chip address `0x1362`;
/// - the held matched-page corpus contains exact format-4 pages for
///   `BHB42801` and `BHB42831`; both decrypt with the BM1362 lot-code letter
///   `C` and their factory V/F values agree with the BM1362 PVT tables;
/// - `dcentrald-silicon-profiles::{hashboards,hashboard_catalog,bm1362}` and
///   the exact topology JSON independently carry the same six BM1362 rows.
///
/// The former `BHB428xx -> BM1366` prefix was a stale documentation inference.
/// It is deliberately replaced by six exact rows: an unobserved future
/// `BHB428*` suffix must resolve to `None`, never inherit a chip family.
///
/// ## Prefer EXACT `model_id` rows; prefixes are the legacy shape (UB-26)
///
/// The `*xx` patterns here are **prefix** matchers. A prefix answers for SKUs
/// nobody has ever examined, which is how `BHB68xxx -> BM1370` came to give a
/// wrong-family answer for six BM1368 boards. New rows are therefore EXACT
/// `model_id` keys, and [`catalog_entry_for_sku`] is a first-match-wins linear
/// scan, so **an exact row must be listed before any prefix that would also
/// match it**.
///
/// **W8 rank-9 (2026-08-03): the `BHB68xxx -> BM1370` catch-all is RETIRED.**
/// An unknown `BHB68…` SKU now resolves to `None` — fail closed, never a
/// guessed family. Rationale: every one of the 8 `BHB68xxx` boards in the held
/// ePIC v1.22.0 roster is `asic_id BM1368`/`asic_addr 0x1368`; zero BHB68
/// boards anywhere in any held corpus are BM1370 (the roster's 13 BM1370
/// boards are all `A3HB*`, format 1); and the DCENT-held s21 `BHB68606` page
/// plus the three held format-5 BHB68 pages all carry the BM1368 lot-code
/// letter `'V'` (W5-RANK-13 §2). A catch-all in EITHER direction is a guess:
/// `-> BM1370` mis-labels the likely-BM1368 unknown, `-> BM1368` would
/// mis-label a future genuine BM1370 `BHB68…`. Neither is evidence, so an
/// unknown must be `None` (per-SKU evidence adds a new EXACT row). The
/// remaining `BHB426xx`/`BHB568xx/BHB569xx` prefixes are separate
/// adjudications with their own evidence base and are unchanged here. BHB428
/// is exact-keyed for the reason above.
///
/// The exact-keyed, roster-complete counterpart (50 SKUs, with per-row
/// provenance and no prefix matching at all) is
/// `dcentrald-silicon-profiles::hashboard_catalog`. It cannot live here —
/// this crate is HAL-free and deliberately upstream of silicon-profiles.
pub const BHB_SKU_CATALOG: &[BhbSkuCatalogEntry] = &[
    BhbSkuCatalogEntry {
        pattern: "BHB426xx",
        chip_family: "BM1362",
        model_family: "S19j Pro / S19j Pro variants",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: " secs 1.1-1.4",
        note: "BHB426xx rows cover the S19j Pro BM1362 family.",
    },
    // UB-26 (2026-08-03): EXACT row. `BHB42701` starts with `BHB427`, so no
    // pattern in this table matched it and `chip_family_for_sku("BHB42701")`
    // returned `None` — a catalogued board with no resolvable family (H3 §1.4
    // records the same refusal). Two independent sources say BM1362: our own
    // `dcentrald-silicon-profiles::hashboards` catalog row (`BHB42701`, 108
    // chips/chain, efficiency-optimised, with a per-SKU BM1362 PVT table) and
    // the ePIC jig DB (`asic_id BM1362`, `asic_addr 0x1362`, 108 chips).
    // Exact key, deliberately NOT a new `BHB427xx` prefix.
    BhbSkuCatalogEntry {
        pattern: "BHB42701",
        chip_family: "BM1362",
        model_family: "S19j",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: "silicon-profiles::hashboards BHB42701 catalog row + bm1362 PVT table; \
                 epic-jig-hashboard-db-50models.json (BM1362/0x1362, 108 chips)",
        note: "Exact row: BHB42701 matched no pattern before UB-26 and resolved to None. \
               Held page observed as format 4 (0x04 0x11); dispatch is still always on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42801",
        chip_family: "BM1362",
        model_family: "S19j Pro+ / S19j+ BM1362 high-bin family",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: "held epic-eeprom-matched-samples-20.json BHB42801 format-4 page; \
                 epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact page-backed row; no BHB428 prefix inference. Lot-code family C and \
               factory 675 MHz/16000 cV-like value corroborate the BM1362 profile.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42803",
        chip_family: "BM1362",
        model_family: "S19j Pro-A BM1362 repair-class",
        eeprom_variant: "unknown_no_held_page",
        confidence: "medium",
        source: "epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact roster/PVT row; no held deployed page for this SKU and no prefix admission.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42811",
        chip_family: "BM1362",
        model_family: "S19j+ BM1362 high-bin family",
        eeprom_variant: "unknown_no_held_page",
        confidence: "medium",
        source: "epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact roster/PVT row; no held deployed page for this SKU and no prefix admission.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42821",
        chip_family: "BM1362",
        model_family: "S19j+ BM1362 high-bin family",
        eeprom_variant: "unknown_no_held_page",
        confidence: "medium",
        source: "epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact roster/PVT row; no held deployed page for this SKU and no prefix admission.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42831",
        chip_family: "BM1362",
        model_family: "S19j+ BM1362 high-bin family",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: "held epic-eeprom-matched-samples-20.json BHB42831 format-4 page; \
                 epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact page-backed row; no BHB428 prefix inference. Lot-code family C and \
               factory 645 MHz/15300 cV-like value corroborate the BM1362 profile.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB42841",
        chip_family: "BM1362",
        model_family: "S19j+ BM1362 low-power bin",
        eeprom_variant: "unknown_no_held_page",
        confidence: "medium",
        source: "epic jig DB BM1362/0x1362; silicon-profiles BM1362 PVT/topology",
        note: "Exact roster/PVT row; no held deployed page for this SKU and no prefix admission.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB568xx / BHB569xx",
        chip_family: "BM1366",
        model_family: "S19k Pro / S19k Pro AML / S19 XP variants",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: " lines 531-538; live .78 BHB56902 EEPROM decode",
        note: "BHB56902 is live-driven from the S19k Pro .78 capture.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68603",
        chip_family: "BM1368",
        model_family: "Antminer S21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: "bosminer model-list.json SHA256 c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0; epic-eeprom-matched-samples-20.json SHA256 958a3a3ab8269dd3ebfd684b600c3e3ed9f325e3177f7fcd817ee495b1264909 page SHA256 83baae35cd70f069f55f89290ccdf25db35e3f09a04b6a6d6d31ae15a12f4bdf",
        note: "The product map assigns BHB68603 only to S21/BM1368; the separate 256-byte ePIC fixture page proves format 5 / XXTEA key slot 1 and decoded board name. It is not an authenticated live-board capture.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68603-",
        chip_family: "BM1368",
        model_family: "Antminer S21",
        eeprom_variant: "unknown_no_held_page",
        confidence: "medium",
        source: "held bosminer model-list.json SHA256 c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0",
        note: "The exact held product map assigns BHB68603- only to S21/BM1368. No held BHB68603- EEPROM page proves a cipher or record variant, so decoding remains unadmitted.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68606",
        chip_family: "BM1368",
        model_family: "Antminer S21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: "bosminer model-list.json SHA256 c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0; epic-eeprom-matched-samples-20.json SHA256 958a3a3ab8269dd3ebfd684b600c3e3ed9f325e3177f7fcd817ee495b1264909 page SHA256 4d62362c012bbd2ac1446f189b931c8bdb11d16c1512d207bf96d1bfb5cd08c5",
        note: "The product map assigns BHB68606 only to S21/BM1368; the separate 256-byte ePIC fixture page proves format 5 / XXTEA key slot 1 and decoded board name. It is not an authenticated live-board capture.",
    },
    // ------------------------------------------------------------------
    // UB-26 (2026-08-03): the six remaining EXACT `BHB68xxx` rows.
    //
    // The broad `BHB68xxx -> BM1370` row below is a **prefix catch-all** whose
    // only cited basis is a *preamble* table (`BOSMINER_EEPROM_PARSERS_RE.md`)
    // — and a preamble is a family hint that provably cannot determine an ASIC
    // generation (`0x05 0x11` spans BM1366 AND BM1368). It therefore answered
    // "BM1370" for six SKUs nobody had ever looked at. The ePIC UMC OS v1.22.0
    // jig DB declares all EIGHT `BHB68xxx` roster rows as `asic_id BM1368` /
    // `asic_addr 0x1368` / 108 chips per chain — no `BHB68xxx` board in that
    // roster is BM1370 (the BM1370 boards are the 13 `A3HB*` rows). Four of the
    // six are independently corroborated as 108-chip S21-generation boards by
    // the VNish 1.2.7 model matrix (`BHB68701`/`BHB68703` = Antminer T21,
    // `BHB68707`/`BHB68709` = Antminer S19 XP+).
    //
    // Caveat 3 stands: the ePIC DB is Bitmain-derived but ePIC-TRANSCRIBED and
    // never outranks a DCENT measurement. It is not overruling one here — the
    // value it corrects is a doc inference from a preamble table, not a
    // measurement. Confidence is therefore `medium`, not `high`.
    //
    // These are EXACT keys, never a `BHB687xx` prefix, and they change nothing
    // about admission: `hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY` has no
    // row for any of them, so `observed_protocol_for_deployed_board_name` still
    // refuses all six (pinned by `deployed_bhb68_prefix_never_mints_bm1368`
    // there and by `new_exact_rows_do_not_widen_deployed_admission` here).
    //
    // W8 rank-9 (2026-08-03): the `BHB68xxx -> BM1370` catch-all that used to
    // sit after these rows is REMOVED (see the catalog doc comment above). An
    // unknown `BHB68…` SKU resolves to `None`; only the 8 exact roster rows
    // (BHB68601/68603[-]/68606/68701/68703/68705/68707/68709) answer.
    // ------------------------------------------------------------------
    BhbSkuCatalogEntry {
        pattern: "BHB68601",
        chip_family: "BM1368",
        model_family: "S21-generation BM1368 board; no held corpus names its product",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips; ePIC-transcribed, caveat 3)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU, so the eeprom_variant is the family's observed class, \
               not an attested format — always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68701",
        chip_family: "BM1368",
        model_family: "T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer T21, 108 chips); \
                 epic-eeprom-matched-samples-20.json (held page, format 5)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68703",
        chip_family: "BM1368",
        model_family: "T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer T21, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68705",
        chip_family: "BM1368",
        model_family: "S21-generation BM1368 board; no held corpus names its product",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips; ePIC-transcribed, caveat 3)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68707",
        chip_family: "BM1368",
        model_family: "S19 XP+",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer S19 XP+, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68709",
        chip_family: "BM1368",
        model_family: "S19 XP+",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer S19 XP+, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "A3HB4xxxx",
        chip_family: "BM1370",
        model_family: "S21 Pro / S21 XP class",
        eeprom_variant: "format1_plaintext_name",
        confidence: "low",
        source: "epic-jig-hashboard-db-50models.json (A3HB40601 -> BM1370; ePIC-transcribed, caveat 3)",
        note: "A3HB40601 was silently unresolved before this row. Format 1 \
               (0x01 0x41) inferred from the A3HB7 sibling family; no held page \
               for A3HB4, so treat the format as unconfirmed and always dispatch \
               on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "A3HB7xxxx",
        chip_family: "BM1370",
        model_family: "S21 Pro / S21 XP class",
        // Format 1 (0x01 0x41), NOT edf_v5. Ground truth: three held pages
        // A3HB70501/70601/70701 decode as format_version=1, keyver=0x41 =
        // board_name[0] 'A' (plaintext), NOT a key selector.
        eeprom_variant: "format1_plaintext_name",
        confidence: "high",
        source: "epic-eeprom-matched-samples-20.json (A3HB70501/70601/70701 fmt=1|keyver=65)",
        note: "Corrects the stale A3HB7xxxx -> edf_v5_xxtea (0x05) label; A3HB7 \
               is format 1 (0x01 0x41), board_name in plaintext, enciphered body \
               key unrecovered. Dispatch on raw[0], never map SKU -> format.",
    },
    // ------------------------------------------------------------------
    // UB-26 (2026-08-03): the two non-`model_id` jig records. Neither matched
    // any pattern, so both resolved to `None`.
    //
    // These are the strongest-evidenced rows in this table: we RE'd `NBP1901`
    // from a completely different source (`bm1398_protocol.rs`'s
    // `S19_PRO_NBP1901_CHAIN_SPEC`, jig-recovered 2026-07-24: 114 chips,
    // 38 voltage domains x 3) and the ePIC DB independently reproduces it
    // exactly; `NBS1902`'s 76 = 38 x 2 likewise matches
    // `projects/dcent-hashboards/HASHBOARD_TARGET_MATRIX.md:45`.
    //
    // IDENTITY LABEL ONLY. Native BM1398 remains NOT IMPLEMENTED and refused:
    // `hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY` declares no BM1398 row,
    // a row only ever admits its OWN identity, and the `0x04`-never-admits-
    // BM1398 invariant is unchanged. Pinned by
    // `new_exact_rows_do_not_widen_deployed_admission`.
    // ------------------------------------------------------------------
    BhbSkuCatalogEntry {
        pattern: "NBP1901",
        chip_family: "BM1398",
        model_family: "S19 Pro",
        // No held page for either NB* SKU, so the on-page format is UNKNOWN.
        // Do not guess a family default here — dispatch is on raw[0] anyway.
        eeprom_variant: "unknown_no_held_page",
        confidence: "high",
        source: "bm1398_protocol.rs S19_PRO_NBP1901_CHAIN_SPEC (jig-recovered 2026-07-24: \
                 114 chips / 38 domains x 3); epic-jig-hashboard-db-50models.json (BM1398P/0x1398, \
                 114 chips, chain_domain_num 38) — two independent sources agreeing exactly",
        note: "Exact row: NBP1901 matched no pattern before UB-26 and resolved to None. \
               Identity label only; native BM1398 stays refused by the admission policy.",
    },
    BhbSkuCatalogEntry {
        pattern: "NBS1902",
        chip_family: "BM1398",
        model_family: "S19",
        eeprom_variant: "unknown_no_held_page",
        confidence: "high",
        source: "epic-jig-hashboard-db-50models.json (BM1398P/0x1398, 76 chips, 38 domains x 2); \
                 projects/dcent-hashboards/HASHBOARD_TARGET_MATRIX.md:45 (S19: 76 = 38 x 2); \
                 first-party Bitmain stock topol.conf s19-20211116 (Phase A 2026-09-01, section 3.7)",
        note: "Exact row: NBS1902 matched no pattern before UB-26 and resolved to None. \
               Identity label only; native BM1398 stays refused by the admission policy. \
               Gauntlet B6 (2026-09-02): stock topol now first-party — 76/chain, 8x10 grid, \
               38 domains x 2, interval 3, PIC1704@0x20, AWP12@0x10 gpio907 (pinned as \
               bm1398_protocol::S19_NBS1902_BOARD_GEOMETRY).",
    },
    // ------------------------------------------------------------------
    // Gauntlet B6 (2026-09-02): T19's board, promoted from unknown to a
    // catalog identity-label row by FIRST-PARTY Bitmain stock evidence
    // (Phase A asicminingsupplies mirror, section 3.7 row 9): the T19
    // stock topol.conf names machine NBT1903 = BM1398P (asic_addr 0x1398),
    // 76 ASICs/chain (8x10), 38 domains x 2, addr interval 3, PIC1704 @
    // 0x20, PSU AWP12 @ 0x10 gpio 907. Geometry is pinned as
    // bm1398_protocol::T19_NBT1903_BOARD_GEOMETRY.
    //
    // Same class as the NB* rows above: IDENTITY LABEL ONLY — no held
    // EEPROM page, and `hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY`
    // still declares no BM1398 row, so nothing here admits anything.
    // ------------------------------------------------------------------
    BhbSkuCatalogEntry {
        pattern: "NBT1903",
        chip_family: "BM1398",
        model_family: "T19",
        eeprom_variant: "unknown_no_held_page",
        confidence: "high",
        source: "first-party Bitmain stock topol.conf t19-20230320 (Phase A 2026-09-01, \
                 section 3.7 row 9: NBT1903 = BM1398P, 76/chain, 8x10, 38 domains x 2, \
                 interval 3, PIC1704@0x20, AWP12@0x10 gpio907); geometry pinned at \
                 bm1398_protocol::T19_NBT1903_BOARD_GEOMETRY",
        note: "Exact row: identity label only. No held NBT1903 EEPROM page; the \
               deployed admission policy never declares BM1398, so this row cannot \
               mint an observed identity (pinned by \
               deployed_policy_table_can_never_declare_bm1398).",
    },
];

/// Returns the chip-family string for a known hashboard SKU. Mirrors
/// bosminer's in-binary SKU table at `0x00eec028` plus the local
///  corrections above. Caller plugs the result
/// into `dcentrald-silicon-profiles` to look up a `SiliconTable`.
pub fn chip_family_for_sku(b_name: &str) -> Option<&'static str> {
    catalog_entry_for_sku(b_name).map(|entry| entry.chip_family)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_capability_registry_is_exhaustive_and_exact() {
        let variants: std::collections::BTreeSet<&str> = EEPROM_FORMAT_CAPABILITIES
            .iter()
            .map(|capability| capability.variant)
            .collect();
        assert_eq!(EEPROM_FORMAT_CAPABILITIES.len(), 6);
        assert_eq!(variants.len(), EEPROM_FORMAT_CAPABILITIES.len());
        assert_eq!(
            variants,
            [
                "Braiinsminer",
                "EdfV5Xxtea",
                "Format1PlaintextName",
                "X19J",
                "X19Plain",
                "X21Aes",
            ]
            .into_iter()
            .collect()
        );

        let state = |variant| {
            EEPROM_FORMAT_CAPABILITIES
                .iter()
                .find(|capability| capability.variant == variant)
                .expect("every public record variant has a capability row")
                .state
        };
        for variant in ["X19Plain", "X19J", "EdfV5Xxtea"] {
            assert_eq!(
                state(variant),
                EepromDecodeCapabilityState::DeployedReadOnlyDecode
            );
        }
        assert_eq!(
            state("Format1PlaintextName"),
            EepromDecodeCapabilityState::IdentityOnlyDecode
        );
        assert_eq!(
            state("Braiinsminer"),
            EepromDecodeCapabilityState::PreambleOnly
        );
        assert_eq!(
            state("X21Aes"),
            EepromDecodeCapabilityState::StructuredHelperOnly
        );
    }

    #[test]
    fn format_capability_registry_never_grants_hardware_authority() {
        for capability in EEPROM_FORMAT_CAPABILITIES {
            assert!(!capability.runtime_admission_authorized);
            assert!(!capability.tuning_authorized);
            assert!(!capability.write_authorized);
            assert!(!capability.decoder.is_empty());
            assert!(!capability.integrity_scope.is_empty());
        }

        let format1 = EEPROM_FORMAT_CAPABILITIES
            .iter()
            .find(|capability| capability.variant == "Format1PlaintextName")
            .unwrap();
        assert!(format1.identity_fields_decoded);
        assert!(!format1.factory_tuning_fields_decoded);

        let braiins = EEPROM_FORMAT_CAPABILITIES
            .iter()
            .find(|capability| capability.variant == "Braiinsminer")
            .unwrap();
        assert!(!braiins.identity_fields_decoded);
        assert!(!braiins.factory_tuning_fields_decoded);
    }

    fn synthetic_x21_payload(serial: &str, b_name: &str) -> Vec<u8> {
        let mut payload = vec![0u8; 32];
        let s = serial.as_bytes();
        let n = s.len().min(17);
        payload[..n].copy_from_slice(&s[..n]);
        let b = b_name.as_bytes();
        let bn = b.len().min(8);
        payload[17..17 + bn].copy_from_slice(&b[..bn]);
        payload
    }

    fn synthetic_raw_blob(preamble: [u8; 2], sku: &str) -> Vec<u8> {
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = preamble[0];
        raw[1] = preamble[1];
        raw[32..32 + sku.len()].copy_from_slice(sku.as_bytes());
        raw
    }

    fn synthetic_raw_x21_blob(serial: &str, sku: &str) -> Vec<u8> {
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x05;
        raw[1] = 0x11;
        let payload = synthetic_x21_payload(serial, sku);
        raw[2..2 + payload.len()].copy_from_slice(&payload);
        raw
    }

    #[test]
    fn truncated_blob_returns_truncated() {
        let r = dispatch(&[]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { got: 0, need: 2 }));
        let r = dispatch(&[0x05]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { got: 1, need: 2 }));
    }

    #[test]
    fn unknown_preamble_returns_unknown_preamble() {
        let r = dispatch(&[0xff, 0xfe, 0x00, 0x00]).unwrap_err();
        match r {
            EepromParseError::UnknownPreamble { byte0, byte1 } => {
                assert_eq!(byte0, 0xff);
                assert_eq!(byte1, 0xfe);
            }
            _ => panic!("expected UnknownPreamble, got {:?}", r),
        }
    }

    #[test]
    fn x19_preamble_dispatches_to_x19_plain_variant() {
        let mut blob = vec![0x04, 0x11];
        blob.extend_from_slice(&[0xaa; 8]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::X19Plain(rec) => {
                assert_eq!(rec.raw_payload, vec![0xaa; 8]);
            }
            _ => panic!("expected X19Plain, got {:?}", r),
        }
    }

    #[test]
    fn edf_v5_xxtea_preamble_dispatches_metadata() {
        let mut blob = vec![0x05, 0x11];
        blob.extend_from_slice(&[0xaa; 8]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::EdfV5Xxtea(rec) => {
                assert_eq!(rec.format_version, 5);
                assert_eq!(rec.cipher, "xxtea");
                assert_eq!(rec.key_index, 1);
                assert_eq!(rec.raw_payload, vec![0xaa; 8]);
            }
            _ => panic!("expected EdfV5Xxtea, got {:?}", r),
        }
    }

    #[test]
    fn x21_aes_truncated_payload_is_caught() {
        let r = decode_x21_aes(&[0x00]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { .. }));
    }

    #[test]
    fn x21_aes_non_ascii_field_fails_closed() {
        let mut payload = vec![0u8; 32];
        // Inject a non-ASCII byte (0xFE) in the serial range.
        payload[5] = 0xFE;
        let r = decode_x21_aes(&payload).unwrap_err();
        assert!(matches!(r, EepromParseError::BodyDecode { .. }));
    }

    #[test]
    fn braiinsminer_preamble_recognized() {
        let mut blob = vec![b'B', b'r'];
        blob.extend_from_slice(&[0x21, 0x00, 0xff]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::Braiinsminer(rec) => {
                // Includes the magic.
                assert_eq!(rec.raw_payload, vec![b'B', b'r', 0x21, 0x00, 0xff]);
            }
            _ => panic!("expected Braiinsminer, got {:?}", r),
        }
    }

    #[test]
    fn chip_family_lookup_known_skus() {
        assert_eq!(chip_family_for_sku("BHB56902"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42601"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42699"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42801"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42803"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42811"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42821"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42831"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42841"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB428xx"), None);
        assert_eq!(chip_family_for_sku("BHB42899"), None);
        assert_eq!(chip_family_for_sku("BHB56801"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB68603"), Some("BM1368"));
        assert_eq!(chip_family_for_sku("BHB68603-"), Some("BM1368"));
        assert_eq!(chip_family_for_sku("BHB68606"), Some("BM1368"));
        // W8 rank-9: no BHB68 catch-all — an off-roster BHB68 SKU is None.
        assert_eq!(chip_family_for_sku("BHB68123"), None);
        // A3HB40601 was silently unresolved before the A3HB4 pattern was added.
        assert_eq!(chip_family_for_sku("A3HB40601"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70501"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70601"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70701"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("UNKNOWN-XX"), None);
        assert_eq!(chip_family_for_sku(""), None);
    }

    #[test]
    fn a3hb_boards_are_format1_not_edf_v5() {
        // Ground truth: A3HB70501/70601/70701 decode as format_version=1
        // (header 0x01 0x41), NOT format 5 (0x05 0x11). The catalog must not
        // relabel them edf_v5. Evidence:
        //
        //   epic-eeprom-matched-samples-20.json
        for sku in ["A3HB40601", "A3HB70501", "A3HB70601", "A3HB70701"] {
            let entry = catalog_entry_for_sku(sku).expect("A3HB catalog entry");
            assert_eq!(entry.chip_family, "BM1370");
            assert_eq!(entry.eeprom_variant, "format1_plaintext_name");
            assert_ne!(entry.eeprom_variant, "edf_v5_xxtea_key1");
        }
    }

    #[test]
    fn a3hb40601_format1_page_resolves_identity_via_structured_partial_decode() {
        // A real format-1 page: header 0x01 0x41 then the plaintext board name
        // (0x41 = board_name[0] = 'A'). Queue rank 20: dispatch() now returns a
        // structured, IDENTITY-ONLY Format1PlaintextName record (body key
        // unrecovered), so the status is MetadataOnly, not UnknownPreamble.
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x01;
        raw[1] = 0x41;
        raw[1..1 + b"A3HB40601".len()].copy_from_slice(b"A3HB40601");

        let report = decode_raw_256_blob(&raw);
        // Recognized preamble, body enciphered ⇒ MetadataOnly (never Decoded).
        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert!(matches!(
            report.record,
            Some(EepromRecord::Format1PlaintextName(_))
        ));
        // Identity resolves from the plaintext board_name at the known offset.
        assert_eq!(report.metadata.board_sku.as_deref(), Some("A3HB40601"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1370"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    #[test]
    fn format1_dispatch_reads_plaintext_name_not_ciphertext_noise() {
        // Robustness win over scan_known_sku: the plaintext board_name at
        // raw[1..16] is authoritative; a real catalog SKU planted in the
        // enciphered body (raw[16..256]) must NOT hijack identity.
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x01;
        raw[1] = 0x41;
        raw[1..1 + b"A3HB70501".len()].copy_from_slice(b"A3HB70501");
        // Plant a *different* real SKU (a BM1366 board) in the ciphertext body.
        raw[64..64 + b"BHB56902".len()].copy_from_slice(b"BHB56902");

        let rec = dispatch(&raw).unwrap();
        match rec {
            EepromRecord::Format1PlaintextName(r) => {
                assert_eq!(r.board_name, "A3HB70501");
            }
            other => panic!("expected Format1PlaintextName, got {other:?}"),
        }
        let report = decode_raw_256_blob(&raw);
        // Identity is the plaintext name (BM1370), NOT the body-noise BM1366 SKU.
        assert_eq!(report.metadata.board_sku.as_deref(), Some("A3HB70501"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1370"));
    }

    #[test]
    fn format1_record_carries_no_encipherable_field_hard_none() {
        // The queue's core safety contract: a format-1 record may carry ONLY the
        // plaintext board_name. Nothing decodable from the (unheld-key)
        // ciphertext body — voltage, frequency, sweep, serial, CRC — may appear,
        // or a downstream consumer could seed an S21 Pro/XP energization
        // envelope from a value it cannot actually read. Enforced structurally:
        // the serialized record has exactly {variant, board_name}.
        let rec = EepromRecord::Format1PlaintextName(Format1PlaintextNameRecord {
            board_name: "A3HB70501".to_string(),
        });
        let v = serde_json::to_value(&rec).unwrap();
        let obj = v.as_object().expect("record serializes to an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["board_name", "variant"],
            "format-1 record must expose ONLY board_name (+ the variant tag); \
             any V/F/serial/CRC field is a forbidden envelope leak"
        );
        // And a decoded format-1 page never claims a full-field Decoded status.
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x01;
        raw[1] = 0x41;
        raw[1..1 + b"A3HB70501".len()].copy_from_slice(b"A3HB70501");
        let report = decode_raw_256_blob(&raw);
        assert_ne!(report.status, RawEepromDecodeStatus::Decoded);
        assert_eq!(report.metadata.serial_number, None);
        assert_eq!(report.metadata.cipher, None);
    }

    /// UB-26 + W8 rank-9. The eight `BHB68xxx` roster SKUs resolve to BM1368
    /// by EXACT key, and the broad `BHB68xxx -> BM1370` catch-all is GONE.
    ///
    /// All eight `BHB68xxx` rows in the held ePIC v1.22.0 roster declare
    /// `asic_id BM1368` / `asic_addr 0x1368` / 108 chips; no roster `BHB68xxx`
    /// board is BM1370 (the 13 BM1370 roster boards are all `A3HB*`). Four are
    /// independently corroborated by the VNish 1.2.7 matrix (T21 / S19 XP+,
    /// 108 chips), and the held format-5 BHB68 pages (ePIC BHB68603/68606/
    /// 68701 + the DCENT-held s21 `BHB68606` dump) all decode with the BM1368
    /// lot-code letter `'V'` (W5-RANK-13 §2).
    #[test]
    fn exact_bhb68_rows_replace_the_bm1370_catch_all_answer() {
        for sku in [
            "BHB68601", "BHB68603", "BHB68606", "BHB68701", "BHB68703", "BHB68705", "BHB68707",
            "BHB68709",
        ] {
            let entry = catalog_entry_for_sku(sku).expect("exact BHB68 row");
            assert_eq!(entry.pattern, sku, "{sku} must match its OWN exact row");
            assert_eq!(
                entry.chip_family, "BM1368",
                "{sku}: every roster BHB68xxx board is BM1368"
            );
        }
    }

    /// W8 rank-9 NEGATIVE pin: an unknown `BHB68…` SKU resolves to `None`.
    ///
    /// A catch-all in either direction is a guess — `-> BM1370` mis-labels the
    /// likely-BM1368 unknown, `-> BM1368` would mis-label a future genuine
    /// BM1370 `BHB68…` board. Identity resolution fails CLOSED; new evidence
    /// adds a new EXACT row, never a prefix.
    #[test]
    fn unknown_bhb68_sku_resolves_to_none_never_a_guessed_family() {
        for probe in [
            "BHB68123",
            "BHB68999",
            "BHB68602",
            "BHB68607",
            "BHB68702",
            "BHB68711",
            "BHB68",
            "BHB686",
            "BHB68xxx",
            "BHB686060",
        ] {
            assert_eq!(
                chip_family_for_sku(probe),
                None,
                "{probe}: off-roster BHB68 must fail closed, not guess a family"
            );
            assert!(catalog_entry_for_sku(probe).is_none(), "{probe}");
        }
        // ...and no row in the table is a BHB68 prefix pattern anymore.
        assert!(
            !BHB_SKU_CATALOG
                .iter()
                .any(|e| e.pattern.starts_with("BHB68") && e.pattern.contains('x')),
            "a BHB68 prefix row must never be reintroduced — exact keys only"
        );
    }

    /// UB-26. Three SKUs that previously matched NO pattern and returned
    /// `None`: `BHB42701` (BHB427, outside the `BHB426`/`BHB428` prefixes) and
    /// the two non-`model_id` jig records.
    #[test]
    fn previously_unresolvable_exact_skus_now_resolve() {
        assert_eq!(chip_family_for_sku("BHB42701"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("NBP1901"), Some("BM1398"));
        assert_eq!(chip_family_for_sku("NBS1902"), Some("BM1398"));
        // Still exact — no new prefix space was opened.
        for probe in ["BHB427", "BHB42702", "NBP", "NBP19011", "NBS", "NB"] {
            assert_eq!(
                chip_family_for_sku(probe),
                None,
                "{probe} must not resolve — the new rows are exact keys"
            );
        }
    }

    /// LOAD-BEARING order invariant: this table is a linear `find`, so an
    /// exact row placed AFTER a prefix that also matches it is dead code and
    /// the wrong family wins silently. Assert every exact row still answers
    /// for itself.
    #[test]
    fn exact_rows_precede_the_prefix_catch_all_they_correct() {
        for entry in BHB_SKU_CATALOG {
            // Only exact rows (patterns that are their own SKU) are checked;
            // the pattern strings ending in `xx`/`xxx`/`xxxx` are prefixes.
            if entry.pattern.contains('x') {
                continue;
            }
            let resolved = catalog_entry_for_sku(entry.pattern)
                .unwrap_or_else(|| panic!("{} resolves to nothing", entry.pattern));
            assert_eq!(
                resolved.pattern, entry.pattern,
                "exact row {} is shadowed by earlier pattern {} — reorder the table",
                entry.pattern, resolved.pattern
            );
        }
    }

    /// The non-page-backed new rows are IDENTITY LABELS only. BHB42701 is the
    /// deliberate exception: its exact held matched page independently admits
    /// BM1362. Every other row remains outside the deployed-page policy, and in
    /// particular native BM1398 stays refused.
    #[test]
    fn new_exact_rows_do_not_widen_deployed_admission() {
        use crate::hashboard_eeprom::observed_protocol_for_deployed_board_name;
        assert_eq!(
            observed_protocol_for_deployed_board_name("BHB42701"),
            Some(dcentrald_common::board_desc::AsicProtocolIdentity::Bm1362),
            "BHB42701 has an exact held page and may mint only BM1362"
        );
        for sku in [
            "BHB68601", "BHB68701", "BHB68703", "BHB68705", "BHB68707", "BHB68709", "NBP1901",
            "NBS1902",
        ] {
            assert!(
                catalog_entry_for_sku(sku).is_some(),
                "{sku} must be catalogued"
            );
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                None,
                "{sku}: a catalog identity label must never mint an observed identity"
            );
        }
    }

    /// No new row may claim an EEPROM format it has no held page for.
    /// `format_version` is not a function of SKU (`BHB56801` is held as both
    /// format 4 and format 5), so an unattested SKU says so.
    #[test]
    fn unattested_new_rows_do_not_claim_a_held_format() {
        for sku in ["NBP1901", "NBS1902"] {
            let e = catalog_entry_for_sku(sku).unwrap();
            assert_eq!(e.eeprom_variant, "unknown_no_held_page", "{sku}");
        }
        for sku in ["BHB68601", "BHB68703", "BHB68705", "BHB68707", "BHB68709"] {
            let e = catalog_entry_for_sku(sku).unwrap();
            assert!(
                e.note.contains("No held page for this SKU"),
                "{sku}: an unattested format must say so in the note, got {:?}",
                e.note
            );
            assert!(e.note.contains("dispatch on raw[0]"), "{sku}");
        }
    }

    #[test]
    fn bhb_sku_catalog_exact_keys_bhb428_as_bm1362() {
        for sku in [
            "BHB42801", "BHB42803", "BHB42811", "BHB42821", "BHB42831", "BHB42841",
        ] {
            let entry = catalog_entry_for_sku(sku).expect("exact BHB428 catalog entry");
            assert_eq!(entry.pattern, sku, "{sku} must match its own exact row");
            assert_eq!(entry.chip_family, "BM1362");
            assert!(entry.source.contains("silicon-profiles"));
        }
        for sku in ["BHB428", "BHB428xx", "BHB42899", "BHB4289999"] {
            assert_eq!(catalog_entry_for_sku(sku), None, "{sku} must fail closed");
        }
    }

    #[test]
    fn bhb_sku_catalog_pins_documented_bhb686_to_bm1368() {
        for sku in ["BHB68603", "BHB68603-", "BHB68606"] {
            let entry = catalog_entry_for_sku(sku).expect("BHB686 exact catalog entry");
            assert_eq!(entry.chip_family, "BM1368");
            assert_eq!(entry.model_family, "Antminer S21");
            assert!(entry
                .source
                .contains("c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0"));
        }
        assert_eq!(
            catalog_entry_for_sku("BHB68603-")
                .expect("BHB68603- exact catalog entry")
                .eeprom_variant,
            "unknown_no_held_page"
        );
        for (sku, page_sha256) in [
            (
                "BHB68603",
                "83baae35cd70f069f55f89290ccdf25db35e3f09a04b6a6d6d31ae15a12f4bdf",
            ),
            (
                "BHB68606",
                "4d62362c012bbd2ac1446f189b931c8bdb11d16c1512d207bf96d1bfb5cd08c5",
            ),
        ] {
            let entry = catalog_entry_for_sku(sku).expect("held BHB686 fixture row");
            assert_eq!(entry.eeprom_variant, "edf_v5_xxtea_key1");
            assert!(entry.source.contains(page_sha256));
            assert!(entry
                .note
                .contains("not an authenticated live-board capture"));
        }
    }

    #[test]
    fn x21_aes_record_round_trips_through_serde() {
        let r = X21AesRecord {
            serial_number: "AS19K1234567890AB".to_string(),
            b_name: "BHB56902".to_string(),
            pcb_version: 0x4242,
            bom_version: 0x5555,
            fact_job: "JYZZ20230901007-Y1".to_string(),
            ch_die: "ED".to_string(),
            ch_marking: "S1GM23AL36".to_string(),
            ft: "F1V18B3C1".to_string(),
            ch_tech: "BS".to_string(),
            bin: "4".to_string(),
            vf: vec![0xde, 0xad, 0xbe, 0xef],
            sale_rate: Some("HIGH".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: X21AesRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn eeprom_record_serde_round_trip_with_tagged_variant() {
        let r = EepromRecord::X19Plain(X19PlainRecord {
            algo_or_subver: 0xAA,
            raw_payload: vec![1, 2, 3],
        });
        let json = serde_json::to_string(&r).unwrap();
        // Per the snake_case + tag="variant" attribute.
        assert!(json.contains("\"variant\":\"x19_plain\""));
        let back: EepromRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn eeprom_parse_error_serde_round_trip() {
        let err = EepromParseError::UnknownPreamble {
            byte0: 0x77,
            byte1: 0x88,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: EepromParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
        assert!(json.contains("\"error\":\"unknown_preamble\""));
    }

    #[test]
    fn x21_payload_with_short_serial_trims_correctly() {
        let payload = synthetic_x21_payload("AS19K123", "BHB56902");
        let rec = decode_x21_aes(&payload).unwrap();
        // Serial field is 17 bytes wide; trim trailing NUL.
        assert_eq!(rec.serial_number, "AS19K123");
        assert_eq!(rec.b_name, "BHB56902");
    }

    #[test]
    fn b_name_round_trip_against_re_doc_anchor() {
        // RE doc anchor: hb0/hb1/hb2 from .78 all decode to BHB56902 (BM1366).
        let payload = synthetic_x21_payload("AS19K00000000.78a", "BHB56902");
        let rec = decode_x21_aes(&payload).unwrap();
        assert_eq!(chip_family_for_sku(&rec.b_name), Some("BM1366"));
    }

    #[test]
    fn truncated_x21_payload_short_of_b_name_field_is_caught() {
        // Payload shorter than offset+8 (b_name width) returns Truncated.
        // Only 16 bytes after preamble: too short for b_name @ offset 17.
        let r = decode_x21_aes(&[0x42; 16]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { .. }));
    }

    #[test]
    fn read_ascii_field_trims_trailing_spaces_and_nuls() {
        let mut payload = vec![0u8; 16];
        payload[..5].copy_from_slice(b"hello");
        payload[5] = b' ';
        payload[6] = b' ';
        payload[7] = 0;
        let s = read_ascii_field(&payload, 0, 16).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn raw_256_x19_bhb426_metadata_is_normalized_without_writes() {
        let raw = synthetic_raw_blob([0x04, 0x11], "BHB42601");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.schema, RAW_EEPROM_DECODE_SCHEMA);
        assert_eq!(report.raw_len, RAW_EEPROM_BLOB_LEN);
        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42601"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1362"));
        assert_eq!(
            report.metadata.model_family.as_deref(),
            Some("S19j Pro / S19j Pro variants")
        );
        assert_eq!(report.metadata.eeprom_variant.as_deref(), Some("x19_plain"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    #[test]
    fn raw_256_x19_bhb428_metadata_uses_exact_bm1362_catalog() {
        let raw = synthetic_raw_blob([0x04, 0x11], "BHB42841");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42841"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1362"));
        assert!(report
            .metadata
            .notes
            .iter()
            .any(|note| note.contains("no held deployed page")));
    }

    #[test]
    fn raw_256_edf_v5_bhb56902_reports_xxtea_metadata() {
        let raw = synthetic_raw_x21_blob("AS19K1234567890AB", "BHB56902");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB56902"));
        assert_eq!(report.metadata.serial_number.as_deref(), None);
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1366"));
        assert_eq!(
            report.metadata.eeprom_variant.as_deref(),
            Some("edf_v5_xxtea_key1")
        );
        assert_eq!(report.metadata.eeprom_format.as_deref(), Some("edf_v5"));
        assert_eq!(report.metadata.cipher.as_deref(), Some("xxtea"));
        assert_eq!(report.metadata.key_index, Some(1));
        assert!(matches!(report.record, Some(EepromRecord::EdfV5Xxtea(_))));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    #[test]
    fn raw_256_edf_v5_bhb68603_maps_to_bm1368() {
        let raw = synthetic_raw_blob([0x05, 0x11], "BHB68603");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB68603"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1368"));
        assert_eq!(
            report.metadata.model_family.as_deref(),
            Some("Antminer S21")
        );
        assert_eq!(report.metadata.eeprom_format.as_deref(), Some("edf_v5"));
        assert_eq!(report.metadata.cipher.as_deref(), Some("xxtea"));
        assert_eq!(report.metadata.key_index, Some(1));
    }

    #[test]
    fn raw_256_malformed_preamble_fails_closed() {
        let raw = synthetic_raw_blob([0xde, 0xad], "BHB42601");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::UnknownPreamble);
        assert!(report.record.is_none());
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42601"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown EEPROM preamble")));
    }

    #[test]
    fn raw_decode_rejects_non_256_byte_blob() {
        let report = decode_raw_256_blob(&[0x05, 0x11, 0x00]);

        assert_eq!(report.status, RawEepromDecodeStatus::MalformedLength);
        assert_eq!(report.raw_len, 3);
        assert!(report.record.is_none());
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }
}
