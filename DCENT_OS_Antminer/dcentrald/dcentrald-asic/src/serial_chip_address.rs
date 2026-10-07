//! CRC-verified BM136x/BM1370 serial ChipAddress response parsing.
//!
//! Direct-UART transports receive complete response bodies after the
//! `AA 55` preamble has been removed by the HAL.  This module validates the
//! retained 9-byte BM136x command-response body without turning repeated
//! response frames into a physical chip-population claim.
//!
//! The value/responder-address layout and response CRC are retained in the
//! ESP-Miner BM1366/BM1368/BM1370 `count_asic_chips()` implementation and in
//! the live S21 response capture documented at
//! .  Frame count proves a
//! CRC-clean response window; it does not prove uniqueness, topology, or
//! measured identity.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU8;

use dcentrald_common::AsicProtocolIdentity;

use crate::protocol::bm13xx_command_response_crc5;

/// Bytes after the `AA 55` preamble in a BM136x ChipAddress response.
pub const SERIAL_CHIP_ADDRESS_BODY_BYTES: usize = 9;

/// One CRC-verified command response for register `0x00`.
///
/// Fields are private so callers cannot rewrap raw serial bytes as parser
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialChipAddressObservation {
    identity: AsicProtocolIdentity,
    value_address: u8,
    responder_address: u8,
}

impl SerialChipAddressObservation {
    pub const fn identity(self) -> AsicProtocolIdentity {
        self.identity
    }

    pub const fn value_address(self) -> u8 {
        self.value_address
    }

    pub const fn responder_address(self) -> u8 {
        self.responder_address
    }
}

/// Why a response body is not exact ChipAddress command evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialChipAddressResponseError {
    Length {
        observed: usize,
    },
    JobResponseTrailer {
        trailer: u8,
    },
    UnsupportedTrailerFlags {
        trailer: u8,
    },
    CrcMismatch {
        expected: u8,
        observed: u8,
    },
    UnknownChipId {
        observed: u16,
    },
    UnsupportedIdentityLayout {
        identity: AsicProtocolIdentity,
    },
    CoreCountEncoding {
        identity: AsicProtocolIdentity,
        expected: u8,
        observed: u8,
    },
    RegisterAddress {
        observed: u8,
    },
    ReservedBytes {
        observed: [u8; 2],
    },
    AddressMismatch {
        value_address: u8,
        responder_address: u8,
    },
}

/// Parse one exact 9-byte BM136x/BM1370 ChipAddress response body.
///
/// The caller supplies bytes after the serial HAL has removed `AA 55`.  The
/// response trailer's low five bits are checked with the response-specific
/// CRC state machine. Bits 6:5 remain unsupported and are rejected; bit 7
/// identifies mining/job responses and is likewise rejected.
pub fn parse_serial_chip_address_body(
    body: &[u8],
) -> Result<SerialChipAddressObservation, SerialChipAddressResponseError> {
    if body.len() != SERIAL_CHIP_ADDRESS_BODY_BYTES {
        return Err(SerialChipAddressResponseError::Length {
            observed: body.len(),
        });
    }

    let trailer = body[8];
    if trailer & 0x80 != 0 {
        return Err(SerialChipAddressResponseError::JobResponseTrailer { trailer });
    }
    if trailer & 0x60 != 0 {
        return Err(SerialChipAddressResponseError::UnsupportedTrailerFlags { trailer });
    }
    let expected = bm13xx_command_response_crc5(&body[..8]);
    let observed = trailer & 0x1f;
    if observed != expected {
        return Err(SerialChipAddressResponseError::CrcMismatch { expected, observed });
    }

    let chip_id = u16::from_be_bytes([body[0], body[1]]);
    let identity = AsicProtocolIdentity::from_chip_id(chip_id)
        .ok_or(SerialChipAddressResponseError::UnknownChipId { observed: chip_id })?;
    let expected_core_count_encoding = match identity {
        AsicProtocolIdentity::Bm1362 => 0x03,
        AsicProtocolIdentity::Bm1366
        | AsicProtocolIdentity::Bm1368
        | AsicProtocolIdentity::Bm1370 => 0x00,
        // Exact S15/T15 miners compare register 0's high word with `0x1391`, but
        // this serial response parser has no captured BM1391 core-count layout;
        // the sibling S11 jig supplies no model-ID frame either. Registering the
        // catalog identity in `board_desc` must not become permission to invent
        // that layout — assigning it `0x03` or `0x00` would fail open.
        AsicProtocolIdentity::Bm1387
        | AsicProtocolIdentity::Bm1391
        | AsicProtocolIdentity::Bm1393
        | AsicProtocolIdentity::Bm1396
        | AsicProtocolIdentity::Bm1397
        | AsicProtocolIdentity::Bm1398 => {
            return Err(SerialChipAddressResponseError::UnsupportedIdentityLayout { identity });
        }
        AsicProtocolIdentity::RuntimeDiscovered => unreachable!("numeric chip ID is exact"),
    };
    if body[2] != expected_core_count_encoding {
        return Err(SerialChipAddressResponseError::CoreCountEncoding {
            identity,
            expected: expected_core_count_encoding,
            observed: body[2],
        });
    }
    if body[5] != 0 {
        return Err(SerialChipAddressResponseError::RegisterAddress { observed: body[5] });
    }
    if body[6..8] != [0, 0] {
        return Err(SerialChipAddressResponseError::ReservedBytes {
            observed: [body[6], body[7]],
        });
    }
    if body[3] != body[4] {
        return Err(SerialChipAddressResponseError::AddressMismatch {
            value_address: body[3],
            responder_address: body[4],
        });
    }

    Ok(SerialChipAddressObservation {
        identity,
        value_address: body[3],
        responder_address: body[4],
    })
}

/// Rejected frame plus its stable index in the supplied window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSerialChipAddressResponse {
    pub response_index: usize,
    pub reason: SerialChipAddressResponseError,
}

/// Address-shape classification for a CRC-clean response window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAddressWindowShape {
    /// Every response used address zero. Repetitions are frames, not chips.
    RepeatedUnassignedZero,
    /// Every responder address was unique and at least one was nonzero.
    UniqueAssignedAddresses,
    /// At least one assigned responder address occurred more than once.
    DuplicateAssignedAddresses,
}

/// Parser-issued exact-family evidence for one serial response window.
///
/// Deliberately not `Clone` or `Copy`: this value is consumed when a runtime
/// binds the observed window to one route generation. `observed_frames` is not
/// exposed as a chip count and no conversion to `MeasuredEnumeration` exists.
#[must_use = "validated serial response evidence must be bound to one runtime route"]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedSerialChipAddressWindow {
    identity: AsicProtocolIdentity,
    observed_frames: NonZeroU8,
    responder_addresses: Vec<u8>,
    duplicate_addresses: Vec<u8>,
    shape: SerialAddressWindowShape,
}

impl ValidatedSerialChipAddressWindow {
    /// Normalize a parser-issued short BM1362 reset reply window for exact
    /// route binding. Repeated zero replies remain frame-count evidence;
    /// only the subsequent assigned-address census can prove chip coverage.
    pub fn from_bm1362_reset_baseline(
        window: crate::bm1362::unassigned_address::ValidatedBm1362UnassignedAddressWindow,
    ) -> Self {
        Self {
            identity: AsicProtocolIdentity::Bm1362,
            observed_frames: window.observed_frames(),
            responder_addresses: vec![0],
            duplicate_addresses: Vec::new(),
            shape: SerialAddressWindowShape::RepeatedUnassignedZero,
        }
    }

    pub const fn identity(&self) -> AsicProtocolIdentity {
        self.identity
    }

    pub const fn observed_frames(&self) -> NonZeroU8 {
        self.observed_frames
    }

    pub fn responder_addresses(&self) -> &[u8] {
        &self.responder_addresses
    }

    pub fn duplicate_addresses(&self) -> &[u8] {
        &self.duplicate_addresses
    }

    pub const fn shape(&self) -> SerialAddressWindowShape {
        self.shape
    }
}

/// Why a complete response window cannot issue exact-family evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialChipAddressWindowError {
    Empty,
    TooManyResponses {
        observed: usize,
    },
    Rejected(Vec<RejectedSerialChipAddressResponse>),
    MixedFamilies {
        response_index: usize,
        first: AsicProtocolIdentity,
        observed: AsicProtocolIdentity,
    },
}

/// Validate every response in one GetAddress window.
///
/// One malformed, nonce/job, CRC-damaged, unknown/layout-incompatible, or mixed-family response
/// rejects the complete window. This prevents stale mining traffic or a noisy
/// byte stream from authorizing family-specific register writes.
pub fn validate_serial_chip_address_window<'a, I>(
    responses: I,
) -> Result<ValidatedSerialChipAddressWindow, SerialChipAddressWindowError>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let responses = responses.into_iter().collect::<Vec<_>>();
    if responses.is_empty() {
        return Err(SerialChipAddressWindowError::Empty);
    }
    let observed_frames = u8::try_from(responses.len()).map_err(|_| {
        SerialChipAddressWindowError::TooManyResponses {
            observed: responses.len(),
        }
    })?;
    let observed_frames =
        NonZeroU8::new(observed_frames).ok_or(SerialChipAddressWindowError::Empty)?;

    let mut identity = None;
    let mut addresses = Vec::with_capacity(responses.len());
    let mut rejected = Vec::new();
    for (response_index, response) in responses.into_iter().enumerate() {
        match parse_serial_chip_address_body(response) {
            Ok(observation) => {
                if let Some(first) = identity {
                    if first != observation.identity() {
                        return Err(SerialChipAddressWindowError::MixedFamilies {
                            response_index,
                            first,
                            observed: observation.identity(),
                        });
                    }
                } else {
                    identity = Some(observation.identity());
                }
                addresses.push(observation.responder_address());
            }
            Err(reason) => rejected.push(RejectedSerialChipAddressResponse {
                response_index,
                reason,
            }),
        }
    }
    if !rejected.is_empty() {
        return Err(SerialChipAddressWindowError::Rejected(rejected));
    }
    let identity = identity.ok_or(SerialChipAddressWindowError::Empty)?;

    let mut counts = BTreeMap::<u8, usize>::new();
    for address in addresses.iter().copied() {
        *counts.entry(address).or_default() += 1;
    }
    let responder_addresses = counts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let duplicate_addresses = counts
        .iter()
        .filter_map(|(&address, &count)| (address != 0 && count > 1).then_some(address))
        .collect::<Vec<_>>();
    let shape = if responder_addresses.as_slice() == [0] {
        SerialAddressWindowShape::RepeatedUnassignedZero
    } else if duplicate_addresses.is_empty() && counts.get(&0).copied().unwrap_or(0) <= 1 {
        SerialAddressWindowShape::UniqueAssignedAddresses
    } else {
        SerialAddressWindowShape::DuplicateAssignedAddresses
    };

    Ok(ValidatedSerialChipAddressWindow {
        identity,
        observed_frames,
        responder_addresses,
        duplicate_addresses,
        shape,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(chip_id: u16, address: u8) -> [u8; SERIAL_CHIP_ADDRESS_BODY_BYTES] {
        let [hi, lo] = chip_id.to_be_bytes();
        let core_count_encoding = match chip_id {
            0x1387 => 0x90,
            0x1397 | 0x1398 => 0x18,
            0x1362 => 0x03,
            _ => 0,
        };
        let mut body = [hi, lo, core_count_encoding, address, address, 0, 0, 0, 0];
        body[8] = bm13xx_command_response_crc5(&body[..8]);
        body
    }

    #[test]
    fn parses_crc_valid_bm1362_bm1368_and_bm1370_bodies() {
        for (chip_id, identity) in [
            (0x1362, AsicProtocolIdentity::Bm1362),
            (0x1368, AsicProtocolIdentity::Bm1368),
            (0x1370, AsicProtocolIdentity::Bm1370),
        ] {
            let observation = parse_serial_chip_address_body(&body(chip_id, 0x2a)).unwrap();
            assert_eq!(observation.identity(), identity);
            assert_eq!(observation.value_address(), 0x2a);
            assert_eq!(observation.responder_address(), 0x2a);
        }
    }

    #[test]
    fn parses_locked_bm1368_contract_and_retained_literal_bm1370_vector() {
        // BM1368 address-zero locks the live S21 capture layout documented in
        // S21_ASIC_COMM_TEST.md; that document redacts only the address/CRC
        // bytes. BM1370 is the literal retained mujina-miner PROTOCOL.md
        // vector. Preambles are omitted because the HAL strips `AA 55`.
        let bm1368 = [0x13, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f];
        let bm1370 = [0x13, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
        assert_eq!(
            parse_serial_chip_address_body(&bm1368).unwrap().identity(),
            AsicProtocolIdentity::Bm1368
        );
        assert_eq!(
            parse_serial_chip_address_body(&bm1370).unwrap().identity(),
            AsicProtocolIdentity::Bm1370
        );
    }

    #[test]
    fn response_parser_rejects_every_identity_adjacent_integrity_failure() {
        for length in [0usize, 8, 10, 12] {
            assert!(matches!(
                parse_serial_chip_address_body(&vec![0; length]),
                Err(SerialChipAddressResponseError::Length { observed }) if observed == length
            ));
        }

        let valid = body(0x1368, 2);
        let mut bad_crc = valid;
        bad_crc[8] ^= 1;
        assert!(matches!(
            parse_serial_chip_address_body(&bad_crc),
            Err(SerialChipAddressResponseError::CrcMismatch { .. })
        ));

        let mut job = valid;
        job[8] |= 0x80;
        assert!(matches!(
            parse_serial_chip_address_body(&job),
            Err(SerialChipAddressResponseError::JobResponseTrailer { .. })
        ));

        let mut flags = valid;
        flags[8] |= 0x20;
        assert!(matches!(
            parse_serial_chip_address_body(&flags),
            Err(SerialChipAddressResponseError::UnsupportedTrailerFlags { .. })
        ));

        let mut wrong_register = valid;
        wrong_register[5] = 0x18;
        wrong_register[8] = bm13xx_command_response_crc5(&wrong_register[..8]);
        assert!(matches!(
            parse_serial_chip_address_body(&wrong_register),
            Err(SerialChipAddressResponseError::RegisterAddress { observed: 0x18 })
        ));

        let mut wrong_core_count = valid;
        wrong_core_count[2] = 3;
        wrong_core_count[8] = bm13xx_command_response_crc5(&wrong_core_count[..8]);
        assert!(matches!(
            parse_serial_chip_address_body(&wrong_core_count),
            Err(SerialChipAddressResponseError::CoreCountEncoding {
                identity: AsicProtocolIdentity::Bm1368,
                expected: 0,
                observed: 3,
            })
        ));

        let mut reserved = valid;
        reserved[7] = 1;
        reserved[8] = bm13xx_command_response_crc5(&reserved[..8]);
        assert!(matches!(
            parse_serial_chip_address_body(&reserved),
            Err(SerialChipAddressResponseError::ReservedBytes { .. })
        ));

        let mut mismatch = valid;
        mismatch[4] = 4;
        mismatch[8] = bm13xx_command_response_crc5(&mismatch[..8]);
        assert!(matches!(
            parse_serial_chip_address_body(&mismatch),
            Err(SerialChipAddressResponseError::AddressMismatch { .. })
        ));

        let unknown = body(0x1234, 0);
        assert!(matches!(
            parse_serial_chip_address_body(&unknown),
            Err(SerialChipAddressResponseError::UnknownChipId { observed: 0x1234 })
        ));

        let known_but_different_layout = body(0x1397, 0);
        assert!(matches!(
            parse_serial_chip_address_body(&known_but_different_layout),
            Err(SerialChipAddressResponseError::UnsupportedIdentityLayout {
                identity: AsicProtocolIdentity::Bm1397,
            })
        ));
    }

    /// Registering `Bm1391` in the board catalog must not make a `0x1391`
    /// chain response decodable.
    ///
    /// Before the catalog entry existed, `from_chip_id(0x1391)` returned `None`
    /// and this body was refused as `UnknownChipId` — safe by accident. Adding
    /// the identity moves it into the layout match, so the refusal now has to be
    /// deliberate.
    ///
    /// The mutation this test actually catches is **misgrouping**, not deletion:
    /// removing the `Bm1391` arm from an exhaustive `match identity` is a
    /// compile error, not a red test, so "delete the arm" proves nothing. Move
    /// `Bm1391` into the `0x00` arm and `body()`'s zero encoding matches, so the
    /// parse succeeds and this assertion fails. Move it into the `0x03` arm and
    /// the error becomes `CoreCountEncoding`, which this assertion also rejects.
    /// Both fail-open directions are covered by the one vector.
    #[test]
    fn bm1391_stays_an_unsupported_layout_even_though_the_catalog_now_knows_it() {
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(0x1391),
            Some(AsicProtocolIdentity::Bm1391),
            "catalog identity is the precondition this test guards against"
        );
        assert!(matches!(
            parse_serial_chip_address_body(&body(0x1391, 0)),
            Err(SerialChipAddressResponseError::UnsupportedIdentityLayout {
                identity: AsicProtocolIdentity::Bm1391,
            })
        ));
    }

    #[test]
    fn window_is_exact_family_but_never_promotes_frame_count_to_population() {
        let unassigned = body(0x1368, 0);
        let window = validate_serial_chip_address_window([
            &unassigned[..],
            &unassigned[..],
            &unassigned[..],
        ])
        .unwrap();
        assert_eq!(window.identity(), AsicProtocolIdentity::Bm1368);
        assert_eq!(window.observed_frames().get(), 3);
        assert_eq!(window.responder_addresses(), &[0]);
        assert_eq!(
            window.shape(),
            SerialAddressWindowShape::RepeatedUnassignedZero
        );

        let assigned = [body(0x1370, 0), body(0x1370, 4), body(0x1370, 8)];
        let window =
            validate_serial_chip_address_window(assigned.iter().map(|body| &body[..])).unwrap();
        assert_eq!(
            window.shape(),
            SerialAddressWindowShape::UniqueAssignedAddresses
        );
        assert_eq!(window.responder_addresses(), &[0, 4, 8]);

        let duplicate = [body(0x1370, 4), body(0x1370, 4)];
        let window =
            validate_serial_chip_address_window(duplicate.iter().map(|body| &body[..])).unwrap();
        assert_eq!(
            window.shape(),
            SerialAddressWindowShape::DuplicateAssignedAddresses
        );
        assert_eq!(window.duplicate_addresses(), &[4]);
    }

    #[test]
    fn window_rejects_mixed_family_and_more_than_u8_frames() {
        let bm1368 = body(0x1368, 0);
        let bm1370 = body(0x1370, 0);
        assert!(matches!(
            validate_serial_chip_address_window([&bm1368[..], &bm1370[..]]),
            Err(SerialChipAddressWindowError::MixedFamilies { .. })
        ));

        let responses = vec![bm1368.to_vec(); usize::from(u8::MAX) + 1];
        assert!(matches!(
            validate_serial_chip_address_window(responses.iter().map(Vec::as_slice)),
            Err(SerialChipAddressWindowError::TooManyResponses { observed: 256 })
        ));
    }
}
