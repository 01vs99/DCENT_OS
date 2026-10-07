//! Complete factory data for the retained Classic BB BHB42601/41 profiles.
//!
//! This is a pure data contract, not a hardware admission or acquisition token.
//! It reuses the deployed EEPROM decoder and preserves that decoder's advisory
//! CRC behavior. Only this checked profile requires both reported CRCs to match.
//! The caller's endpoint labels do not establish a bus, current population,
//! freshness, CPU identity, PIC firmware, global bridge state or electrical use.
//!
//! Source: campaign R09 `bb-lux-model-factory-replay-v1.json` (held original Lux
//! ELF SHA256 386b88490154b1007ca15d0f529749664ec641743d7f132127ec078c196df1df),
//! R10 `bb-factory-profile-design-v1.json`, and the retained ePIC 20-page corpus.
//! Original decoder 0x71f730 inserts address-minus-0x50 at 0x6f1578 for addresses
//! 0x50..=0x53. That four-entry decoder range is not a physical BB chain count.
//! Both held SKUs produce model+0x80 count126 and +0x84 discriminator0x202.
//! BHB42621 has no held page in that corpus and is deliberately unsupported.

use crate::deployed_eeprom::{
    decode_deployed_eeprom, DeployedEepromError, DeployedHashboardIdentity,
    DeployedIdentityProvenance, RAW_PAGE_LEN,
};
use crate::hashboard_eeprom::observed_protocol_from_deployed_page;
use crate::zhiju_eeprom::Crc5Check;
use dcentrald_common::board_desc::AsicProtocolIdentity;

const FIRST_ADDRESS: u8 = 0x50;
const LAST_ADDRESS: u8 = 0x53;
const MAX_RECORDS: usize = 4;

/// Exact SKUs with complete retained pages and original BB decoder comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbFactorySku {
    Bhb42601,
    Bhb42641,
}

impl BbFactorySku {
    pub fn board_name(self) -> &'static str {
        match self {
            Self::Bhb42601 => "BHB42601",
            Self::Bhb42641 => "BHB42641",
        }
    }

    /// Source-profile expectation, never the result of a live ASIC census.
    pub fn expected_chip_count(self) -> u16 {
        // Actual original model+0x80 for both complete held pages.
        126
    }

    /// Source profile selection only; no physical part or firmware observation.
    pub fn pic_profile(self) -> BbFactoryPicProfile {
        BbFactoryPicProfile::ClassicBhb426
    }
}

/// A source-scoped model label, not a PIC route or a controller-ready state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbFactoryPicProfile {
    /// Both held original models set byte0x94=1. No global flag is inferred.
    ClassicBhb426,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BbFactoryPageError {
    InvalidAddress { address: u8 },
    Decode(DeployedEepromError),
    IncompleteFactoryIdentity { board_class: u8 },
    UnsupportedSku { board_name: String },
    EmptySerial,
    SiliconDisagreement,
    IdentityCrc { observed: Crc5Check },
    ParametersCrc { observed: Crc5Check },
}

impl std::fmt::Display for BbFactoryPageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress { address } => {
                write!(
                    formatter,
                    "BB factory endpoint {address:#04x} is outside 0x50..=0x53"
                )
            }
            Self::Decode(source) => write!(formatter, "BB factory page decode: {source}"),
            Self::IncompleteFactoryIdentity { board_class } => write!(
                formatter,
                "BB factory data requires a decrypted class4 identity, got class {board_class}"
            ),
            Self::UnsupportedSku { board_name } => {
                write!(
                    formatter,
                    "BB factory SKU {board_name} has no supported held-page profile"
                )
            }
            Self::EmptySerial => formatter.write_str("BB factory identity has no serial"),
            Self::SiliconDisagreement => {
                formatter.write_str("BB factory page does not corroborate BM1362")
            }
            Self::IdentityCrc { observed } => {
                write!(
                    formatter,
                    "BB factory identity CRC is not Match: {observed:?}"
                )
            }
            Self::ParametersCrc { observed } => {
                write!(
                    formatter,
                    "BB factory parameters CRC is not Match: {observed:?}"
                )
            }
        }
    }
}

impl std::error::Error for BbFactoryPageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            _ => None,
        }
    }
}

/// An immutable complete page and its checked factory data.
///
/// Constructed only from raw bytes, never from a deserialized identity DTO.
/// Retained bytes and decoded values are accessible through shared references.
/// Matching CRC5 values are weak data checks and do not authenticate a board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbFactoryPage {
    address: u8,
    raw: [u8; RAW_PAGE_LEN],
    identity: DeployedHashboardIdentity,
    sku: BbFactorySku,
}

impl BbFactoryPage {
    pub fn decode(address: u8, raw: &[u8]) -> Result<Self, BbFactoryPageError> {
        if !(FIRST_ADDRESS..=LAST_ADDRESS).contains(&address) {
            return Err(BbFactoryPageError::InvalidAddress { address });
        }
        let identity = decode_deployed_eeprom(raw).map_err(BbFactoryPageError::Decode)?;
        if identity.board_class != 4
            || identity.provenance != DeployedIdentityProvenance::DecryptedXxtea
        {
            return Err(BbFactoryPageError::IncompleteFactoryIdentity {
                board_class: identity.board_class,
            });
        }
        let sku = match identity.board_name.as_str() {
            "BHB42601" => BbFactorySku::Bhb42601,
            "BHB42641" => BbFactorySku::Bhb42641,
            _ => {
                return Err(BbFactoryPageError::UnsupportedSku {
                    board_name: identity.board_name,
                });
            }
        };
        if identity.board_serial.trim().is_empty() {
            return Err(BbFactoryPageError::EmptySerial);
        }
        if observed_protocol_from_deployed_page(raw) != Some(AsicProtocolIdentity::Bm1362) {
            return Err(BbFactoryPageError::SiliconDisagreement);
        }
        if identity.region_1_crc5 != Crc5Check::Match {
            return Err(BbFactoryPageError::IdentityCrc {
                observed: identity.region_1_crc5,
            });
        }
        if identity.region_2_crc5 != Crc5Check::Match {
            return Err(BbFactoryPageError::ParametersCrc {
                observed: identity.region_2_crc5,
            });
        }
        // The existing decoder already checked this exact length. Keep a checked
        // conversion so future decoder changes cannot introduce a slice panic.
        let raw = raw.try_into().map_err(|_| {
            BbFactoryPageError::Decode(DeployedEepromError::WrongLength { got: raw.len() })
        })?;
        Ok(Self {
            address,
            raw,
            identity,
            sku,
        })
    }

    /// Caller-supplied endpoint label; no bus or physical-slot custody is implied.
    pub fn address(&self) -> u8 {
        self.address
    }

    /// Original decoder's address-minus-0x50 index, not a probed physical slot.
    pub fn source_chain_index(&self) -> u8 {
        self.address - FIRST_ADDRESS
    }

    pub fn raw_page(&self) -> &[u8; RAW_PAGE_LEN] {
        &self.raw
    }

    pub fn identity(&self) -> &DeployedHashboardIdentity {
        &self.identity
    }

    pub fn sku(&self) -> BbFactorySku {
        self.sku
    }

    /// EEPROM factory metadata in centivolts; not a requested or measured rail.
    pub fn factory_voltage_cv(&self) -> u16 {
        self.identity.voltage_cv
    }

    /// EEPROM factory metadata; not an applied PLL result.
    pub fn factory_frequency_mhz(&self) -> u16 {
        self.identity.frequency_mhz
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BbFactoryCollectionError {
    SelectedCount {
        got: usize,
    },
    InvalidSelectedAddress {
        address: u8,
    },
    DuplicateSelectedAddress {
        address: u8,
    },
    RecordCount {
        expected: usize,
        got: usize,
    },
    UnexpectedAddress {
        address: u8,
    },
    DuplicateRecord {
        address: u8,
    },
    Page {
        address: u8,
        source: BbFactoryPageError,
    },
    MixedSku {
        first: BbFactorySku,
        other: BbFactorySku,
    },
}

impl std::fmt::Display for BbFactoryCollectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelectedCount { got } => {
                write!(
                    formatter,
                    "BB factory selected set must have 1..=4 members, got {got}"
                )
            }
            Self::InvalidSelectedAddress { address } => {
                write!(
                    formatter,
                    "BB factory selected endpoint {address:#04x} is invalid"
                )
            }
            Self::DuplicateSelectedAddress { address } => {
                write!(
                    formatter,
                    "BB factory selected endpoint {address:#04x} is duplicated"
                )
            }
            Self::RecordCount { expected, got } => {
                write!(
                    formatter,
                    "BB factory requires all {expected} selected records, got {got}"
                )
            }
            Self::UnexpectedAddress { address } => {
                write!(
                    formatter,
                    "BB factory record {address:#04x} is outside the selected set"
                )
            }
            Self::DuplicateRecord { address } => {
                write!(formatter, "BB factory record {address:#04x} is duplicated")
            }
            Self::Page { address, source } => {
                write!(
                    formatter,
                    "BB factory selected record {address:#04x}: {source}"
                )
            }
            Self::MixedSku { first, other } => write!(
                formatter,
                "BB factory collection requires one exact SKU, got {} and {}",
                first.board_name(),
                other.board_name()
            ),
        }
    }
}

impl std::error::Error for BbFactoryCollectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Page { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Complete records for every member of an explicit selected endpoint set.
///
/// This initial data contract rejects mixed exact SKUs. That is a component
/// policy, not a statement that hardware cannot operate mixed revisions.
/// It supplies neither a discovered population nor a same-run receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbFactoryCollection {
    pages: Vec<BbFactoryPage>,
}

impl BbFactoryCollection {
    /// Decode all records or return an error; never omit an invalid member.
    ///
    /// The returned order follows `selected_addresses`, regardless of record
    /// order. Both slices are bounded before decoding or allocation.
    pub fn decode(
        selected_addresses: &[u8],
        records: &[(u8, &[u8])],
    ) -> Result<Self, BbFactoryCollectionError> {
        if selected_addresses.is_empty() || selected_addresses.len() > MAX_RECORDS {
            return Err(BbFactoryCollectionError::SelectedCount {
                got: selected_addresses.len(),
            });
        }
        for (index, &address) in selected_addresses.iter().enumerate() {
            if !(FIRST_ADDRESS..=LAST_ADDRESS).contains(&address) {
                return Err(BbFactoryCollectionError::InvalidSelectedAddress { address });
            }
            if selected_addresses[..index].contains(&address) {
                return Err(BbFactoryCollectionError::DuplicateSelectedAddress { address });
            }
        }
        if records.len() != selected_addresses.len() {
            return Err(BbFactoryCollectionError::RecordCount {
                expected: selected_addresses.len(),
                got: records.len(),
            });
        }
        for (index, &(address, _)) in records.iter().enumerate() {
            if !selected_addresses.contains(&address) {
                return Err(BbFactoryCollectionError::UnexpectedAddress { address });
            }
            if records[..index].iter().any(|record| record.0 == address) {
                return Err(BbFactoryCollectionError::DuplicateRecord { address });
            }
        }
        let mut pages: Vec<BbFactoryPage> = Vec::with_capacity(selected_addresses.len());
        for &address in selected_addresses {
            // Equal counts plus checked uniqueness/membership guarantee a record
            // for each selected endpoint. Still refuse if that invariant changes.
            let Some((_, raw)) = records.iter().find(|record| record.0 == address) else {
                return Err(BbFactoryCollectionError::RecordCount {
                    expected: selected_addresses.len(),
                    got: pages.len(),
                });
            };
            let page = BbFactoryPage::decode(address, raw)
                .map_err(|source| BbFactoryCollectionError::Page { address, source })?;
            if let Some(first) = pages.first() {
                if first.sku != page.sku {
                    return Err(BbFactoryCollectionError::MixedSku {
                        first: first.sku,
                        other: page.sku,
                    });
                }
            }
            pages.push(page);
        }
        Ok(Self { pages })
    }

    /// All selected records in the requested order, with no mutable access.
    pub fn pages(&self) -> &[BbFactoryPage] {
        &self.pages
    }
}

#[cfg(test)]
#[path = "bb_factory_profile_tests.rs"]
mod tests;
